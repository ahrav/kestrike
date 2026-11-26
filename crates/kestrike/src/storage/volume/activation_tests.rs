use super::super::device::sim::{Media, media};
use super::super::record::Crc32c;
use super::super::recovery::session_at;
use super::activation::{Action, Activation, ActivationStep, Command, Damage, Fault, RECORD_LEN};
use crate::failover::records::VolumeId;
use crate::net::ownership::session_of;

const CAPACITY: u64 = 1 << 20;

fn volume() -> VolumeId {
    VolumeId::new("vol-0123456789abcdef0").unwrap()
}

fn own() -> Activation {
    Activation::of(volume(), &session_at(7, 2))
}

fn encoded(activation: Activation) -> Vec<u8> {
    let mut record = [0xA5; RECORD_LEN];
    activation.encode(Crc32c::detect(), &mut record);
    record.to_vec()
}

fn unit(device: &Media, unit: u64) -> Vec<u8> {
    let at = unit as usize * RECORD_LEN;
    device.borrow()[at..at + RECORD_LEN].to_vec()
}

/// The activation step's calls, so a control can drive a broken variant through the same checks.
trait Step {
    fn start(&mut self, crc: Crc32c, record: &mut [u8; RECORD_LEN]) -> Action;
    fn written(&mut self) -> Action;
    fn read(&mut self, crc: Crc32c, bytes: Option<&[u8]>) -> Action;
}

impl Step for ActivationStep {
    fn start(&mut self, crc: Crc32c, record: &mut [u8; RECORD_LEN]) -> Action {
        ActivationStep::start(self, crc, record)
    }

    fn written(&mut self) -> Action {
        ActivationStep::written(self)
    }

    fn read(&mut self, crc: Crc32c, bytes: Option<&[u8]>) -> Action {
        ActivationStep::read(self, crc, bytes)
    }
}

fn drive(
    step: &mut impl Step,
    device: &Media,
    mut read: impl FnMut(usize, Vec<u8>) -> Option<Vec<u8>>,
) -> (Action, Vec<Command>) {
    let crc = Crc32c::detect();
    let mut submitted = Vec::new();
    let mut reads = 0;
    let mut record = [0xA5; RECORD_LEN];
    let mut next = step.start(crc, &mut record);
    loop {
        match next {
            Action::Submit(command @ Command::Write { unit }) => {
                submitted.push(command);
                let at = unit as usize * RECORD_LEN;
                device.borrow_mut()[at..at + RECORD_LEN].copy_from_slice(&record);
                next = step.written();
            }
            Action::Submit(command @ Command::Read { unit: at }) => {
                submitted.push(command);
                let bytes = read(reads, unit(device, at));
                reads += 1;
                next = step.read(crc, bytes.as_deref());
            }
            ended => return (ended, submitted),
        }
    }
}

const CRC_AT: usize = 48;

/// Tail positions at the scan boundaries of `dirty` and `clear`: the first tail byte, both sides of the first 64-byte
/// boundary, the bytes before, at and after the first 128-byte boundary, the middle of the unit, the start of the
/// last 128-byte chunk, and the last byte.
const TAIL_EDGES: [usize; 9] = [52, 63, 64, 127, 128, 129, 2048, 3968, RECORD_LEN - 1];

fn resealed(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes[CRC_AT..CRC_AT + 4].fill(0);
    let sum = Crc32c::detect().checksum(&bytes);
    bytes[CRC_AT..CRC_AT + 4].copy_from_slice(&sum.to_le_bytes());
    bytes
}

fn with_tenure(mut record: Vec<u8>, generation: u32, epoch: u32) -> Vec<u8> {
    record[32..36].copy_from_slice(&generation.to_le_bytes());
    record[36..40].copy_from_slice(&epoch.to_le_bytes());
    record[40..48].copy_from_slice(&session_of(generation, epoch).to_le_bytes());
    resealed(record)
}

#[test]
fn activation_step_writes_once_and_reads_back() {
    let crc = Crc32c::detect();
    let session = session_at(7, 2);
    for name in ["vol-0123456789abcdef0", "vol-0123"] {
        let id = VolumeId::new(name).unwrap();
        let device = media(CAPACITY);
        let mut step = ActivationStep::new(id, &session);
        let (ended, submitted) = drive(&mut step, &device, |_, bytes| Some(bytes));
        assert_eq!(ended, Action::Activated, "{name}");
        assert_eq!(
            submitted,
            [Command::Write { unit: 0 }, Command::Read { unit: 0 }]
        );
        let record = unit(&device, 0);
        assert_eq!(
            Activation::decode(crc, &record),
            Ok(Activation::of(id, &session)),
            "{name}"
        );
        assert!(device.borrow()[RECORD_LEN..].iter().all(|&byte| byte == 0));
        assert_eq!(&record[..8], b"IMGCACT1");
        assert_eq!(record[8..10], 1u16.to_le_bytes());
        assert_eq!(usize::from(record[10]), name.len());
        assert_eq!(&record[11..11 + name.len()], name.as_bytes());
        assert!(record[11 + name.len()..32].iter().all(|&byte| byte == 0));
        let generation = u32::try_from(session.generation().get()).unwrap();
        assert_eq!(record[32..36], generation.to_le_bytes());
        assert_eq!(record[36..40], session.epoch().get().to_le_bytes());
        assert_eq!(record[40..48], session.get().to_le_bytes());
        assert!(record[52..].iter().all(|&byte| byte == 0));
    }
}

#[test]
fn torn_readback_retries_once_then_refuses() {
    let foreign = Activation::of(volume(), &session_at(7, 3));
    let landed = encoded(foreign);
    for (failed, ended) in [
        (1, Action::Activated),
        (2, Action::Refused(Fault::Damaged(Damage::Torn))),
    ] {
        for damage in ["flipped", "lost", "short", "long"] {
            let device = media(CAPACITY);
            let (step, submitted) = drive(
                &mut ActivationStep::new(volume(), &session_at(7, 2)),
                &device,
                |n, mut bytes| {
                    if n >= failed {
                        return Some(bytes);
                    }
                    match damage {
                        "flipped" => bytes[RECORD_LEN / 2..].fill(0xA5),
                        "short" => bytes.truncate(RECORD_LEN - 1),
                        "long" => bytes.push(0),
                        _ => return None,
                    }
                    Some(bytes)
                },
            );
            assert_eq!(step, ended, "{failed} failed, {damage}");
            assert_eq!(
                submitted,
                [
                    Command::Write { unit: 0 },
                    Command::Read { unit: 0 },
                    Command::Read { unit: 0 }
                ],
                "{failed} failed, {damage}"
            );
        }
    }
    let device = media(CAPACITY);
    let (step, submitted) = drive(
        &mut ActivationStep::new(volume(), &session_at(7, 2)),
        &device,
        |n, _| (n > 0).then(|| landed.clone()),
    );
    assert_eq!(step, Action::Refused(Fault::Foreign(foreign)));
    assert_eq!(submitted.len(), 3);
    let mut magic = encoded(own());
    magic[0] = b'X';
    let invalid = resealed(magic);
    let device = media(CAPACITY);
    let (step, submitted) = drive(
        &mut ActivationStep::new(volume(), &session_at(7, 2)),
        &device,
        |n, _| (n > 0).then(|| invalid.clone()),
    );
    assert_eq!(step, Action::Refused(Fault::Damaged(Damage::Invalid)));
    assert_eq!(submitted.len(), 3);
}

#[test]
fn the_largest_session_round_trips_and_activates() {
    let crc = Crc32c::detect();
    let session = session_at(u64::from(u32::MAX - 1), (1 << 31) - 3);
    let edge = Activation::of(volume(), &session);
    let record = encoded(edge);
    assert_eq!(record[32..36], (u32::MAX - 1).to_le_bytes());
    assert_eq!(record[36..40], 0xFFFF_FFFCu32.to_le_bytes());
    assert_eq!(Activation::decode(crc, &record), Ok(edge));
    let device = media(CAPACITY);
    let (step, _) = drive(
        &mut ActivationStep::new(volume(), &session),
        &device,
        |_, bytes| Some(bytes),
    );
    assert_eq!(step, Action::Activated);
}

#[test]
fn activation_record_refuses_torn_and_invalid_records() {
    let crc = Crc32c::detect();
    let record = encoded(own());
    assert_eq!(resealed(record.clone()), record);
    for at in [0, 9, 10, 12, 33, 37, 41, 49].into_iter().chain(TAIL_EDGES) {
        let mut bytes = record.clone();
        bytes[at] ^= 1;
        assert_eq!(
            Activation::decode(crc, &bytes),
            Err(Damage::Torn),
            "byte {at}"
        );
    }
    let edit = |at: usize, value: u8| {
        let mut bytes = record.clone();
        bytes[at] = value;
        resealed(bytes)
    };
    let short = VolumeId::new("vol-0123").unwrap();
    let mut padding = encoded(Activation::of(short, &session_at(7, 2)));
    padding[11 + short.as_str().len()] = b'0';
    let mut session = record.clone();
    session[40] ^= 1;
    let tail = TAIL_EDGES.map(|at| (format!("tail byte {at}"), edit(at, 1)));
    let named = [
        ("magic", edit(0, b'X')),
        ("version", edit(8, 2)),
        ("long name", edit(10, 22)),
        ("empty name", edit(10, 0)),
        ("non-hex name", edit(15, b'g')),
        ("padding", resealed(padding)),
        ("session", resealed(session)),
        ("generation zero", with_tenure(record.clone(), 0, 6)),
        (
            "generation exhausted",
            with_tenure(record.clone(), u32::MAX, 6),
        ),
        ("odd epoch", with_tenure(record.clone(), 7, 5)),
        ("epoch zero", with_tenure(record.clone(), 7, 0)),
        (
            "epoch above the maximum",
            with_tenure(record.clone(), 7, 0xFFFF_FFFE),
        ),
    ]
    .map(|(name, bytes)| (name.to_string(), bytes));
    for (name, bytes) in named.into_iter().chain(tail) {
        assert_eq!(
            Activation::decode(crc, &bytes),
            Err(Damage::Invalid),
            "{name}"
        );
        let device = media(CAPACITY);
        let (step, submitted) = drive(
            &mut ActivationStep::new(volume(), &session_at(7, 2)),
            &device,
            |n, own| Some(if n == 0 { bytes.clone() } else { own }),
        );
        assert_eq!(
            step,
            Action::Refused(Fault::Damaged(Damage::Invalid)),
            "{name}"
        );
        assert_eq!(
            submitted,
            [Command::Write { unit: 0 }, Command::Read { unit: 0 }],
            "{name}"
        );
    }
    assert_eq!(Activation::decode(crc, &resealed(record)), Ok(own()));
}

#[test]
fn foreign_session_refuses() {
    foreign_records_refuse(|| ActivationStep::new(volume(), &session_at(7, 2)));
}

/// A read-back that activates on any record `Activation::decode` accepts, with no check that the record is its own,
/// activates over another tenure's or volume's record, so the foreign-record check fails on the first foreign record.
#[test]
#[should_panic(expected = "assertion `left == right` failed\n  left: Activated")]
fn negative_control_a_read_back_that_accepts_a_foreign_record_activates() {
    struct AcceptsForeign(ActivationStep);
    impl Step for AcceptsForeign {
        fn start(&mut self, crc: Crc32c, record: &mut [u8; RECORD_LEN]) -> Action {
            self.0.start(crc, record)
        }

        fn written(&mut self) -> Action {
            self.0.written()
        }

        fn read(&mut self, crc: Crc32c, bytes: Option<&[u8]>) -> Action {
            match bytes.map(|bytes| Activation::decode(crc, bytes)) {
                Some(Ok(_)) => Action::Activated,
                _ => self.0.read(crc, bytes),
            }
        }
    }
    foreign_records_refuse(|| AcceptsForeign(ActivationStep::new(volume(), &session_at(7, 2))));
}

/// Drives each step `new` returns over a unit 0 that reads back a record of another tenure or volume, and asserts
/// that the step refuses it as foreign after one write and one read.
fn foreign_records_refuse<S: Step>(new: impl Fn() -> S) {
    let other = VolumeId::new("vol-0fedcba9876543210").unwrap();
    for foreign in [
        Activation::of(volume(), &session_at(7, 3)),
        Activation::of(volume(), &session_at(7, 1)),
        Activation::of(volume(), &session_at(8, 2)),
        Activation::of(volume(), &session_at(6, 2)),
        Activation::of(other, &session_at(7, 2)),
    ] {
        let landed = encoded(foreign);
        let device = media(CAPACITY);
        let (step, submitted) = drive(&mut new(), &device, |_, _| Some(landed.clone()));
        assert_eq!(step, Action::Refused(Fault::Foreign(foreign)));
        assert_eq!(
            submitted,
            [Command::Write { unit: 0 }, Command::Read { unit: 0 }]
        );
    }
}

#[test]
#[should_panic(expected = "the activation record is written once")]
fn a_second_start_panics() {
    let mut step = ActivationStep::new(volume(), &session_at(7, 2));
    let mut record = [0; RECORD_LEN];
    step.start(Crc32c::detect(), &mut record);
    step.start(Crc32c::detect(), &mut record);
}

#[test]
#[should_panic(expected = "a write precedes the read-back")]
fn written_before_start_panics() {
    ActivationStep::new(volume(), &session_at(7, 2)).written();
}

#[test]
fn a_read_outside_a_read_back_panics() {
    let crc = Crc32c::detect();
    let mut record = [0; RECORD_LEN];
    let mut writing = ActivationStep::new(volume(), &session_at(7, 2));
    writing.start(crc, &mut record);
    let early = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
        writing.read(crc, Some(&record));
    }));
    assert_eq!(panic_message(early), "a read-back follows the write");
    let mut ended = ActivationStep::new(volume(), &session_at(7, 2));
    ended.start(crc, &mut record);
    ended.written();
    assert_eq!(ended.read(crc, Some(&record)), Action::Activated);
    let late = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
        ended.read(crc, Some(&record));
    }));
    assert_eq!(panic_message(late), "a read-back follows the write");
}

fn panic_message(result: std::thread::Result<()>) -> &'static str {
    let payload = result.expect_err("the read panics");
    payload
        .downcast_ref::<&'static str>()
        .copied()
        .expect("a literal panic message")
}
