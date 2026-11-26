//! The media fault classes of the simulated device: each is admitted before any effect, applies inside one execution or one control call, and leaves the bytes and custody its class names.
//! Byte oracles are the test's own patterns, SHA-256 digests and the whole host shadow outside the command's buffer; custody oracles are the device's outstanding records.

use std::panic::{AssertUnwindSafe, catch_unwind};

use sha2::{Digest, Sha256};

use super::sim::{
    DAMAGE_XOR, Damage, Effect, Event, Fault, Injection, Mode, Omission, QuiesceMode, Report,
    SCRIPT, ScriptCapacity, ScriptKind, ScriptReason, ScriptRefusal, SimConfig, SimControl,
    SimDisk, Stage, StatusForm, sim,
};
use super::sim_tests::{
    LEN, TWO_MIB, arena, block, config, harness, modeled, pick, stop, submit, token,
};
use super::{
    Buffer, Classification, Completion, CompletionSink, DeviceStatus, Disk, Operation, PoolKind,
    QuiesceStatus,
};
use crate::sim::choice::{Chooser, Domain, Site};
use crate::sim::trace::{self, Capacity, Outcome, PAYLOAD, Recorder, Terminal, Work};

const N: usize = LEN as usize;
const BLOCK: u64 = LEN as u64;
const CAPACITY: u64 = 1 << 20;

/// A modeled device whose script reserves `damage` damage records.
fn with_damage(seed: u64, damage: u32) -> (SimDisk, SimControl) {
    sim(SimConfig {
        script: ScriptCapacity { damage, ..SCRIPT },
        ..config(
            seed,
            Mode::Modeled {
                backing_len: TWO_MIB,
            },
        )
    })
}

fn at(index: u64) -> usize {
    index as usize * N
}

fn fill(byte: u8) -> Vec<u8> {
    vec![byte; N]
}

fn success(raw: u64) -> Completion {
    Completion {
        token: token(raw),
        status: DeviceStatus::Kernel(LEN as i32),
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The whole host shadow except `buffer`'s range: every other buffer's bytes, which no command on `buffer` may change.
fn beside(control: &SimControl, buffer: &Buffer<'_>) -> Vec<u8> {
    let mut shadow = control.host(0, TWO_MIB);
    shadow.drain(buffer.offset()..buffer.offset() + N);
    shadow
}

/// Gray: a delayed command stays out of every ready set, holding its queue room, until the device clock reaches its time; it then executes and terminates as any other command, its event naming the delay it served.
/// A command takes one delay, never one in the past, and an executed command takes none, so eligibility only ever turns on.
#[test]
fn a_gray_delay_holds_the_command_until_its_time_and_then_terminates_normally() {
    let arena = arena();
    let (mut disk, control) = modeled(3);
    let (a, b) = (
        arena.acquire(PoolKind::ReceiveWrite).unwrap(),
        arena.acquire(PoolKind::ReceiveWrite).unwrap(),
    );
    control.write_device(0, &fill(0x11));
    submit(&mut disk, Operation::Read, 1, block(0), &a).unwrap();
    submit(&mut disk, Operation::Read, 2, block(1), &b).unwrap();
    control.advance_to(2);
    control.delay(token(1), 7);
    assert_eq!(
        control.try_delay(token(1), 9),
        harness(ScriptKind::Delay, ScriptReason::Delayed(token(1)))
    );
    assert_eq!(
        control.try_delay(token(2), 1),
        harness(ScriptKind::Delay, ScriptReason::Past { until: 1, now: 2 })
    );
    assert_eq!(control.next_due(), Some(7));
    control.tick(8);
    assert_eq!(pick(&mut disk, 8).0, [success(2)]);
    assert_eq!(control.ready(Stage::Execute), []);
    assert_eq!(control.ready(Stage::Post), []);
    control.advance_to(6);
    control.tick(8);
    assert_eq!(pick(&mut disk, 8).0, [], "the delay holds until time 7");
    assert_eq!(
        control.outstanding(),
        1,
        "the delayed command keeps its charge"
    );
    assert_eq!(control.host(a.offset(), N), vec![0; N], "and moves no byte");
    control.advance_to(control.next_due().unwrap());
    assert_eq!(control.ready(Stage::Execute), [token(1)]);
    control.tick(8);
    assert_eq!(pick(&mut disk, 8).0, [success(1)]);
    assert_eq!(control.host(a.offset(), N), fill(0x11));
    assert!(control.events().contains(&Event::Delayed {
        token: token(1),
        elapsed: 5
    }));
    assert_eq!(control.next_due(), None);
    assert_eq!(
        control.try_delay(token(1), 9),
        harness(ScriptKind::Delay, ScriptReason::NotPending(token(1)))
    );
    submit(&mut disk, Operation::Read, 3, block(2), &a).unwrap();
    control.execute(token(3));
    assert_eq!(
        control.try_delay(token(3), 9),
        harness(ScriptKind::Delay, ScriptReason::Executed(token(3)))
    );
    stop(&mut disk, &control);
    drop((a, b));
    assert!(arena.release().is_ok());
}

/// The next due time is the earliest delay that ends after the device clock, whatever the pending order; a delay the clock already reached is never reported, and a delay to the current time leaves its command ready.
#[test]
fn a_gray_delay_reports_its_earliest_future_time() {
    let arena = arena();
    let (mut disk, control) = modeled(16);
    let a = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    for raw in 1..=4 {
        submit(&mut disk, Operation::Read, raw, block(raw), &a).unwrap();
    }
    control.delay(token(1), 9);
    control.delay(token(2), 7);
    control.delay(token(4), 8);
    assert_eq!(
        control.next_due(),
        Some(7),
        "the earliest, not the first pending"
    );
    control.delay(token(3), control.now());
    assert!(control.ready(Stage::Execute).contains(&token(3)));
    assert_eq!(
        control.next_due(),
        Some(7),
        "a due delay is not scheduled again"
    );
    control.advance_to(8);
    assert_eq!(control.next_due(), Some(9), "nor one past its time");
    control.advance_to(12);
    assert_eq!(control.next_due(), None);
    stop(&mut disk, &control);
    drop(a);
    assert!(arena.release().is_ok());
}

/// Submits one read and delays it to time 1, for the direct-seam tests.
fn delayed(disk: &mut SimDisk, control: &SimControl, buffer: &Buffer<'_>) {
    submit(disk, Operation::Read, 1, block(0), buffer).unwrap();
    control.delay(token(1), 1);
}

/// A direct post of a command whose gray delay has not ended panics, so no seam runs a delayed command early.
#[test]
#[should_panic(expected = "is delayed")]
fn a_direct_post_of_a_delayed_command_breaks_the_delay() {
    let arena = arena();
    let (mut disk, control) = modeled(4);
    let a = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    delayed(&mut disk, &control, &a);
    control.post(token(1));
}

/// A direct execute of a command whose gray delay has not ended panics, as a direct post does.
#[test]
#[should_panic(expected = "is delayed")]
fn a_direct_execute_of_a_delayed_command_breaks_the_delay() {
    let arena = arena();
    let (mut disk, control) = modeled(4);
    let a = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    delayed(&mut disk, &control, &a);
    control.execute(token(1));
}

/// The device clock, which deadlines and delays share, never moves back.
#[test]
#[should_panic(expected = "the device clock moves only forward")]
fn the_device_clock_refuses_to_move_back() {
    let (_disk, control) = modeled(15);
    control.advance_to(5);
    control.advance_to(4);
}

/// Misdirected read: the command reads a distinct equal-length source in place of the intended range and reports success; the intended media, the source and every other host byte read as before once it posted.
#[test]
fn a_misdirected_read_delivers_the_source_and_restores_the_intended_media() {
    let arena = arena();
    let (mut disk, control) = modeled(4);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let bystander = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    control.write_host(bystander.offset(), &fill(0x77));
    control.write_device(at(0), &fill(0x11));
    control.write_device(at(2), &fill(0x22));
    let others = beside(&control, &buffer);
    submit(&mut disk, Operation::Read, 1, block(0), &buffer).unwrap();
    control.fault(token(1), Fault::MisdirectedRead { source: 2 * BLOCK });
    control.tick(1);
    assert_eq!(pick(&mut disk, 8).0, [success(1)]);
    assert_eq!(control.host(buffer.offset(), N), fill(0x22));
    assert_eq!(
        beside(&control, &buffer),
        others,
        "no other host byte moved"
    );
    assert_eq!(control.device(at(0), N), fill(0x11));
    assert_eq!(control.device(at(2), N), fill(0x22));
    assert!(control.events().contains(&Event::Misdirected {
        token: token(1),
        at: 2 * BLOCK
    }));
    assert_eq!(control.damaged(), [], "a read damages nothing");
    drop((buffer, bystander));
    assert!(arena.release().is_ok());
}

/// Misdirected write: the command reports success, the intended range keeps its preimage, no host byte moves, and the target holds the produced bytes under a damage record naming the command and the target's digest; the write attempt is recorded at the target, where its bytes lasted.
#[test]
fn a_misdirected_write_restores_the_preimage_and_attributes_the_target_damage() {
    let arena = arena();
    let (mut disk, control) = modeled(5);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    control.write_device(at(0), &fill(0x11));
    control.write_device(at(3), &fill(0x22));
    control.write_host(buffer.offset(), &fill(0x33));
    let shadow = control.host(0, TWO_MIB);
    let preimage = digest(&control.device(at(0), N));
    control.record_attempts();
    submit(&mut disk, Operation::Write, 1, block(0), &buffer).unwrap();
    let target = 3 * BLOCK;
    control.fault(token(1), Fault::MisdirectedWrite { target });
    control.tick(1);
    assert_eq!(pick(&mut disk, 8).0, [success(1)]);
    assert_eq!(digest(&control.device(at(0), N)), preimage);
    assert_eq!(
        control.host(0, TWO_MIB),
        shadow,
        "a write moves no host byte"
    );
    let produced = digest(&fill(0x33));
    assert_eq!(digest(&control.device(at(3), N)), produced);
    assert_eq!(
        control.damaged(),
        [Damage {
            start: target,
            len: BLOCK,
            token: Some(token(1)),
            digest: produced,
        }]
    );
    let attempts = control.attempts();
    let recorded: Vec<_> = (attempts.iter())
        .map(|attempt| (attempt.start, digest(&attempt.bytes)))
        .collect();
    assert_eq!(
        recorded,
        [(target, produced)],
        "the attempt record holds the bytes at the target"
    );
    drop(buffer);
    assert!(arena.release().is_ok());
}

/// An unwind inside a misdirection, after its substitution or copy and before its restoration, still restores the intended media: the read's substituted bytes and the write's own bytes never stay at the intended range, and no other host byte moves.
/// The command stays pending with its fault spent and later executes ordinarily; the write's copy at the target stays attributed.
#[test]
fn an_unwind_inside_a_misdirection_restores_the_intended_media() {
    let other = 2 * BLOCK;
    // The operation, its fault, the byte the target holds after the unwind, its damage records, and the byte both the intended range and the buffer hold after the ordinary retry.
    let cases = [
        (
            Operation::Read,
            Fault::MisdirectedRead { source: other },
            0x22,
            0,
            0x11,
        ),
        (
            Operation::Write,
            Fault::MisdirectedWrite { target: other },
            0x33,
            1,
            0x33,
        ),
    ];
    for (op, fault, target, damaged, retried) in cases {
        let arena = arena();
        let (mut disk, control) = modeled(6);
        let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
        control.write_device(at(0), &fill(0x11));
        control.write_device(at(2), &fill(0x22));
        control.write_host(buffer.offset(), &fill(0x33));
        let others = beside(&control, &buffer);
        submit(&mut disk, op, 1, block(0), &buffer).unwrap();
        control.fault(token(1), fault);
        control.delay(token(1), control.now());
        control.unwind_next_misdirection();
        let unwound = catch_unwind(AssertUnwindSafe(|| control.execute(token(1))));
        assert!(unwound.is_err(), "{op:?}");
        assert_eq!(control.device(at(0), N), fill(0x11), "{op:?}");
        assert_eq!(control.pending(), 1, "{op:?}");
        assert_eq!(control.try_delay(token(1), control.now()), Ok(()), "{op:?}");
        assert_eq!(control.device(at(2), N), fill(target), "{op:?}");
        assert_eq!(control.damaged().len(), damaged, "{op:?}");
        control.tick(1);
        assert_eq!(pick(&mut disk, 8).0, [success(1)], "{op:?}");
        assert_eq!(control.device(at(0), N), fill(retried), "{op:?}");
        assert_eq!(control.host(buffer.offset(), N), fill(retried), "{op:?}");
        assert_eq!(beside(&control, &buffer), others, "{op:?}");
        drop(buffer);
        assert!(arena.release().is_ok());
    }
}

/// Misdirection admission refuses, before any effect, another range that overlaps the intended one, passes the device, belongs to the other operation, or, for a write, finds no damage record free.
/// The ranges just below and just above the intended one and the device's last range are admitted.
#[test]
fn misdirection_admission_refuses_bad_ranges_before_any_effect() {
    let arena = arena();
    let (mut disk, control) = with_damage(7, 0);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    control.write_device(at(1), &fill(0x11));
    let media = control.device(0, at(8));
    submit(&mut disk, Operation::Read, 1, block(1), &buffer).unwrap();
    submit(&mut disk, Operation::Write, 2, block(4), &buffer).unwrap();
    let refused = |raw, fault, reason| {
        assert_eq!(
            control.try_fault(token(raw), fault),
            harness(ScriptKind::Fault, reason),
            "{fault:?}"
        );
    };
    for source in [BLOCK, BLOCK + 512, 1, 2 * BLOCK - 1] {
        refused(
            1,
            Fault::MisdirectedRead { source },
            ScriptReason::Overlap {
                start: source,
                len: BLOCK,
            },
        );
    }
    for source in [CAPACITY - BLOCK + 512, u64::MAX - 1] {
        refused(
            1,
            Fault::MisdirectedRead { source },
            ScriptReason::OutOfBounds {
                start: source,
                len: BLOCK,
            },
        );
    }
    refused(
        1,
        Fault::MisdirectedWrite { target: 0 },
        ScriptReason::Operation(token(1)),
    );
    refused(
        2,
        Fault::MisdirectedRead { source: 0 },
        ScriptReason::Operation(token(2)),
    );
    refused(
        2,
        Fault::MisdirectedWrite { target: 0 },
        ScriptReason::Full { capacity: 0 },
    );
    assert_eq!(control.device(0, at(8)), media, "no refusal moved a byte");
    control.fault(token(1), Fault::MisdirectedRead { source: 0 });
    submit(&mut disk, Operation::Read, 3, block(1), &buffer).unwrap();
    control.fault(token(3), Fault::MisdirectedRead { source: 2 * BLOCK });
    submit(&mut disk, Operation::Read, 4, block(1), &buffer).unwrap();
    control.fault(
        token(4),
        Fault::MisdirectedRead {
            source: CAPACITY - BLOCK,
        },
    );
    assert_eq!(
        control.try_fault(token(4), Fault::CorruptSuccess),
        harness(ScriptKind::Fault, ScriptReason::Faulted(token(4)))
    );
    stop(&mut disk, &control);
    drop(buffer);
    assert!(arena.release().is_ok());
}

/// Sector damage changes exactly the whole 512-byte sectors it names through the raw media, records their range and digest with no command, and refuses an empty, partial-sector, out-of-bounds or over-capacity range with the media unchanged.
#[test]
fn sector_damage_changes_whole_sectors_and_refuses_any_other_range() {
    let (_disk, control) = with_damage(8, 2);
    control.write_device(0, &[0x11; 4096]);
    let damage = control.damage(512, 1024);
    assert_eq!(
        damage,
        Damage {
            start: 512,
            len: 1024,
            token: None,
            digest: digest(&[0x11 ^ DAMAGE_XOR; 1024]),
        }
    );
    let media = control.device(0, 4096);
    assert!(media[..512].iter().all(|byte| *byte == 0x11));
    assert!(
        media[512..1536]
            .iter()
            .all(|byte| *byte == 0x11 ^ DAMAGE_XOR && *byte != 0x11)
    );
    assert!(media[1536..].iter().all(|byte| *byte == 0x11));
    for (start, len) in [(0, 0), (100, 512), (512, 700)] {
        assert_eq!(
            control.try_damage(start, len),
            harness(ScriptKind::Damage, ScriptReason::Unaligned { start, len })
        );
    }
    for (start, len) in [(CAPACITY, 512), (u64::MAX - 511, 512)] {
        assert_eq!(
            control.try_damage(start, len),
            harness(ScriptKind::Damage, ScriptReason::OutOfBounds { start, len })
        );
    }
    control.damage(CAPACITY - 512, 512);
    assert_eq!(
        control.try_damage(0, 512),
        harness(ScriptKind::Damage, ScriptReason::Full { capacity: 2 })
    );
    assert_eq!(control.device(0, 4096), media);
    assert_eq!(control.damaged().len(), 2);
}

/// Omission: the command's bytes move and its completion never posts, by tick, by direct post or by selection; it keeps its queue room, so the caller's custody holds, through a `Pending` and a `Failed` quiesce until a reset proves the stop.
/// An episode leaves nothing behind the stop; a hostile omission stays counted after it.
#[test]
fn an_omission_holds_the_command_until_a_proven_stop() {
    let arena = arena();
    let (mut disk, control) = modeled(9);
    let buffers: Vec<_> = (0..3)
        .map(|_| arena.acquire(PoolKind::ReceiveWrite).unwrap())
        .collect();
    control.write_host(buffers[0].offset(), &fill(0x44));
    submit(&mut disk, Operation::Write, 1, block(0), &buffers[0]).unwrap();
    submit(&mut disk, Operation::Read, 2, block(1), &buffers[1]).unwrap();
    submit(&mut disk, Operation::Read, 3, block(2), &buffers[2]).unwrap();
    control.fault(token(1), Fault::Omit(Omission::Episode));
    control.fault(token(2), Fault::Omit(Omission::Hostile));
    control.fault(token(3), Fault::Omit(Omission::Episode));
    let index = control
        .ready(Stage::Execute)
        .iter()
        .position(|t| *t == token(3))
        .unwrap();
    assert_eq!(
        control.select(Stage::Execute, index).unwrap().effect,
        Effect::Omitted
    );
    for _ in 0..4 {
        control.tick(8);
    }
    control.post(token(1));
    assert_eq!(control.candidates(Stage::Post), []);
    assert_eq!(control.ready(Stage::Execute), []);
    assert_eq!(
        control.select(Stage::Post, 0),
        harness(
            ScriptKind::Selection(Stage::Post),
            ScriptReason::Selection { index: 0, ready: 0 }
        )
    );
    assert_eq!(pick(&mut disk, 8).0, []);
    assert_eq!(control.device(0, N), fill(0x44));
    assert_eq!(
        control.outstanding(),
        3,
        "each omitted command keeps its charge"
    );
    assert_eq!(control.executed_unposted(), 3);
    assert_eq!(
        control.omitted(),
        [
            (token(1), Omission::Episode),
            (token(2), Omission::Hostile),
            (token(3), Omission::Episode),
        ]
    );
    assert_eq!(control.hostile(), 1);
    for (mode, status) in [
        (QuiesceMode::AllReturned, QuiesceStatus::Pending),
        (QuiesceMode::Failed(Some(5)), QuiesceStatus::Failed(Some(5))),
    ] {
        control.set_quiesce(mode);
        assert_eq!(disk.quiesce(), status);
        assert_eq!(control.outstanding(), 3, "{mode:?} keeps the charge");
    }
    stop(&mut disk, &control);
    assert_eq!(control.omitted(), []);
    assert_eq!(
        control.hostile(),
        1,
        "a stop leaves the hostile omission counted"
    );
    drop(buffers);
    assert!(arena.release().is_ok());
}

/// Generates the fixtures of [`every_fault_kind_reports_as_tagged`] from one row per `Fault` variant: the variant's name, the operations admission accepts it on, and at least one value.
/// `tagged_operations` matches every row's variant with no wildcard arm, so a new variant compiles only once it has a row, a row names one variant, and a row without an operation or a value fails to parse; `tagged_faults` checks each value against its own row's variant.
macro_rules! tagged_faults {
    ($($variant:ident => [$($operation:ident),+], [$($fault:expr),+ $(,)?];)+) => {
        fn tagged_operations(fault: Fault) -> &'static [Operation] {
            match fault {
                $(Fault::$variant { .. } => &[$(Operation::$operation),+],)+
            }
        }

        fn tagged_faults() -> Vec<Fault> {
            let mut faults = Vec::new();
            $($(
                let fault = $fault;
                assert!(
                    matches!(fault, Fault::$variant { .. }),
                    "{fault:?} sits in another variant's row"
                );
                faults.push(fault);
            )+)+
            faults
        }
    };
}

/// A short count whose 4 KiB units cover the whole command, so the device reports success over every requested byte.
const WHOLE_SHORT: Fault = Fault::Short { units: LEN / 4096 };

tagged_faults! {
    Status => [Read, Write], [
        Fault::Status(DeviceStatus::Kernel(LEN as i32)),
        Fault::Status(DeviceStatus::Kernel(LEN as i32 / 4)),
        Fault::Status(DeviceStatus::Kernel(-libc::EIO)),
        Fault::Status(DeviceStatus::Nvme(0)),
        Fault::Status(DeviceStatus::Nvme(0x0004)),
    ];
    Short => [Read, Write], [Fault::Short { units: 1 }, WHOLE_SHORT];
    CorruptSuccess => [Read, Write], [Fault::CorruptSuccess];
    TornWrite => [Read, Write], [Fault::TornWrite { sectors: 3 }];
    PartialReadFailure => [Read, Write], [Fault::PartialReadFailure { sectors: 5 }];
    DropCommand => [Read, Write], [Fault::DropCommand];
    DropCompletion => [Read, Write], [Fault::DropCompletion];
    MisdirectedRead => [Read], [Fault::MisdirectedRead { source: OTHER_BLOCK * BLOCK }];
    MisdirectedWrite => [Write], [Fault::MisdirectedWrite { target: OTHER_BLOCK * BLOCK }];
    Omit => [Read, Write], [Fault::Omit(Omission::Episode), Fault::Omit(Omission::Hostile)];
    UnqualifiedLanding => [Write], [Fault::UnqualifiedLanding { seed: 9 }];
}

/// The intended range's old media, the buffer's new bytes and the misdirection's other range, which fills block `OTHER_BLOCK`, apart from the intended block 0.
const OLD: u8 = 0x11;
const NEW: u8 = 0x33;
const OTHER: u8 = 0x22;
const OTHER_BLOCK: u64 = 2;
const _: () = assert!(OLD != NEW && NEW != OTHER && OTHER != OLD);

/// Runs one `op` of block 0 under `fault`, or ordinarily under `None`, on a modeled device, and returns the delivered completion's status, if any, with the tag derived from what the device did: lying exactly when that status classifies as success while the host shadow or the media differ from an ordinary execution's.
/// An ordinary read leaves the old media in the buffer and changes nothing else; an ordinary write leaves the new bytes at block 0 and changes nothing else.
fn observed_report(op: Operation, fault: Option<Fault>) -> (Option<DeviceStatus>, Report) {
    let arena = arena();
    let (mut disk, control) = with_damage(21, 1);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    control.write_device(at(0), &fill(OLD));
    control.write_device(at(OTHER_BLOCK), &fill(OTHER));
    control.write_host(buffer.offset(), &fill(NEW));
    let (mut host, mut media) = (
        control.host(0, TWO_MIB),
        control.device(0, CAPACITY as usize),
    );
    match op {
        Operation::Read => host[buffer.offset()..buffer.offset() + N].fill(OLD),
        Operation::Write => media[at(0)..at(0) + N].fill(NEW),
    }
    submit(&mut disk, op, 1, block(0), &buffer).unwrap();
    if let Some(fault) = fault {
        control.fault(token(1), fault);
    }
    control.tick(1);
    let delivered = match pick(&mut disk, 2).0.as_slice() {
        [] => None,
        [completion] => {
            assert_eq!(completion.token, token(1), "{op:?} {fault:?}");
            Some(completion.status)
        }
        more => panic!("{op:?} {fault:?} delivered {more:?}"),
    };
    let faithful =
        control.host(0, TWO_MIB) == host && control.device(0, CAPACITY as usize) == media;
    stop(&mut disk, &control);
    drop(buffer);
    assert!(arena.release().is_ok());
    let report = if succeeded(delivered) && !faithful {
        Report::Lying
    } else {
        Report::Honest
    };
    (delivered, report)
}

/// Whether `delivered` is a completion whose status classifies as success for the command's length.
fn succeeded(delivered: Option<DeviceStatus>) -> bool {
    delivered.is_some_and(|status| status.classify(LEN) == Classification::Success)
}

/// Submits one `op` of block 0 on a modeled device and returns admission's answer to `fault` on it, before any effect.
fn admission(op: Operation, fault: Fault) -> Result<(), ScriptRefusal> {
    let arena = arena();
    let (mut disk, control) = with_damage(21, 1);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    submit(&mut disk, op, 1, block(0), &buffer).unwrap();
    let admitted = control.try_fault(token(1), fault);
    stop(&mut disk, &control);
    drop(buffer);
    assert!(arena.release().is_ok());
    admitted
}

/// Each `Fault` variant's tag equals what the device did for one command: the tag observed from the delivered completion, the media and the host bytes equals [`Fault::report`] for the command's length, on every operation its row names, and admission refuses the variant `Operation` on every other operation.
/// An ordinary execution of each operation and a short count covering the whole command each report success and observe as honest, so the byte comparison decides a case.
/// Each `Status` fixture delivers its own status, both tags appear in each status form, and the `Status` tag and whole-landing predicate follow the command's length; every lying fault a write admits breaks whole landing, so the qualified-range guard, which refuses each fault that breaks whole landing, refuses it.
#[test]
fn every_fault_kind_reports_as_tagged() {
    for op in [Operation::Read, Operation::Write] {
        for fault in [None, Some(WHOLE_SHORT)] {
            let (delivered, observed) = observed_report(op, fault);
            assert!(
                succeeded(delivered) && observed == Report::Honest,
                "{op:?} {fault:?} reports success over the requested bytes: {delivered:?} {observed:?}"
            );
        }
    }
    let mut status_tags = Vec::new();
    for fault in tagged_faults() {
        for op in [Operation::Read, Operation::Write] {
            if !tagged_operations(fault).contains(&op) {
                assert_eq!(
                    admission(op, fault).map_err(|refusal| refusal.reason),
                    Err(ScriptReason::Operation(token(1))),
                    "{op:?} {fault:?}"
                );
                continue;
            }
            let (delivered, observed) = observed_report(op, Some(fault));
            assert_eq!(observed, fault.report(LEN), "{op:?} {fault:?}");
            if op == Operation::Write && observed == Report::Lying {
                assert!(fault.breaks_whole_landing(LEN), "{fault:?}");
            }
            if let Fault::Status(status) = fault {
                assert_eq!(delivered, Some(status), "{op:?} {fault:?}");
                let form = match status {
                    DeviceStatus::Kernel(_) => StatusForm::Kernel,
                    DeviceStatus::Nvme(_) => StatusForm::Nvme,
                };
                status_tags.push((form, observed));
            }
        }
    }
    for form in [StatusForm::Kernel, StatusForm::Nvme] {
        for tag in [Report::Lying, Report::Honest] {
            assert!(
                status_tags.contains(&(form, tag)),
                "the {form:?} status fixtures observe {tag:?}: {status_tags:?}"
            );
        }
    }
    let quarter = Fault::Status(DeviceStatus::Kernel(LEN as i32 / 4));
    assert_eq!(quarter.report(LEN / 4), Report::Lying);
    assert_eq!(quarter.report(LEN), Report::Honest);
    assert!(quarter.breaks_whole_landing(LEN / 4));
    assert!(!quarter.breaks_whole_landing(LEN));
}

/// The hostile false stop is admitted only on a modeled device, whose access after the return lands in the host shadow.
#[test]
#[should_panic(expected = "a false stop needs a modeled device")]
fn a_direct_device_refuses_the_false_stop() {
    let (_disk, control) = sim(config(13, Mode::Direct));
    control.set_quiesce(QuiesceMode::FalseStopped);
}

/// A long run of every fault class keeps the device's metadata at fixed high-water marks and its stores at their construction capacity, and its second half allocates nothing.
/// The omitted write submitted before the run keeps its queue room and buffer throughout; the first cycle's misdirected write makes the one damage record, and admission refuses every later misdirected write and sector damage.
#[test]
fn fault_classes_keep_fixed_metadata_across_a_long_run() {
    const CYCLES: u64 = 4_000;
    let arena = arena();
    let (mut disk, control) = with_damage(10, 1);
    let reserved = control.footprint().reserved;
    let buffers: Vec<_> = (0..4)
        .map(|_| arena.acquire(PoolKind::ReceiveWrite).unwrap())
        .collect();
    let full = harness(ScriptKind::Damage, ScriptReason::Full { capacity: 1 });
    submit(&mut disk, Operation::Write, 1, block(3), &buffers[3]).unwrap();
    control.fault(token(1), Fault::Omit(Omission::Episode));
    let mut out = Vec::with_capacity(8);
    let mut allocated = 0;
    for cycle in 0..CYCLES {
        let before = crate::instrument::allocations();
        let raw = 2 + 3 * cycle;
        submit(&mut disk, Operation::Read, raw, block(0), &buffers[0]).unwrap();
        submit(&mut disk, Operation::Write, raw + 1, block(1), &buffers[1]).unwrap();
        submit(&mut disk, Operation::Read, raw + 2, block(2), &buffers[2]).unwrap();
        control.fault(token(raw), Fault::MisdirectedRead { source: 4 * BLOCK });
        let misdirected = control.try_fault(
            token(raw + 1),
            Fault::MisdirectedWrite { target: 5 * BLOCK },
        );
        assert_eq!(misdirected.is_ok(), cycle == 0);
        control.delay(token(raw + 2), control.now() + 1);
        assert_eq!(control.try_damage(6 * BLOCK, 512), full);
        control.tick(8);
        control.advance_to(control.now() + 1);
        control.tick(8);
        out.clear();
        disk.pick_completions(&mut CompletionSink::new(&mut out, 8));
        assert_eq!(out.len(), 3, "{}", control.describe());
        assert_eq!(
            control.outstanding(),
            1,
            "the omitted write keeps its charge"
        );
        if cycle >= CYCLES / 2 {
            allocated += crate::instrument::allocations() - before;
        }
    }
    assert_eq!(allocated, 0, "the cycles allocate nothing");
    let footprint = control.footprint();
    assert_eq!(footprint.reserved, reserved, "no store grew");
    assert_eq!(
        (footprint.pending, footprint.device, footprint.damage),
        (4, 4, 1),
        "{footprint:?}"
    );
    assert_eq!(control.damaged().len(), 1);
    stop(&mut disk, &control);
    drop(buffers);
    assert!(arena.release().is_ok());
}

/// Every effect that records or withholds allocates nothing: after one warm cycle, each counted cycle admits and applies a misdirected write and a sector damage, each taking a fresh damage record, and an omission whose command stays pending.
#[test]
fn recording_and_withholding_effects_allocate_nothing() {
    const CYCLES: u64 = 6;
    let arena = arena();
    let (mut disk, control) = with_damage(14, 2 * CYCLES as u32);
    let reserved = control.footprint().reserved;
    let buffers: Vec<_> = (0..CYCLES + 1)
        .map(|_| arena.acquire(PoolKind::ReceiveWrite).unwrap())
        .collect();
    let writer = &buffers[CYCLES as usize];
    let mut out = Vec::with_capacity(8);
    let mut allocated = 0;
    for cycle in 0..CYCLES {
        let before = crate::instrument::allocations();
        let raw = 1 + 2 * cycle;
        submit(&mut disk, Operation::Write, raw, block(0), writer).unwrap();
        submit(
            &mut disk,
            Operation::Read,
            raw + 1,
            block(1),
            &buffers[cycle as usize],
        )
        .unwrap();
        control.fault(
            token(raw),
            Fault::MisdirectedWrite {
                target: (2 + cycle) * BLOCK,
            },
        );
        control.fault(token(raw + 1), Fault::Omit(Omission::Episode));
        control.damage((10 + cycle) * BLOCK, 512);
        control.tick(8);
        out.clear();
        disk.pick_completions(&mut CompletionSink::new(&mut out, 8));
        assert_eq!(out, [success(raw)]);
        if cycle > 0 {
            allocated += crate::instrument::allocations() - before;
        }
    }
    assert_eq!(allocated, 0, "the counted cycles allocate nothing");
    assert_eq!(control.footprint().reserved, reserved, "no store grew");
    assert_eq!(control.damaged().len(), 2 * CYCLES as usize);
    assert_eq!(control.omitted().len(), CYCLES as usize);
    stop(&mut disk, &control);
    drop(buffers);
    assert!(arena.release().is_ok());
}

const SITE: Site = Site {
    domain: Domain::Disk,
    actor: 1,
    site: 1,
};

/// What a scripted faulted run varies: the misdirected read's source block, the fifth command's omission class, and whether it injects a duplicate.
#[derive(Clone, Copy)]
struct Script {
    source: u64,
    omission: Omission,
    inject: bool,
}

const SCRIPTED: Script = Script {
    source: 4,
    omission: Omission::Hostile,
    inject: true,
};

/// Drives five commands through the selection seam, the executions, posts and admissions drawn by `chooser`: a misdirected read and write, a gray delay, an ordinary write and an omission, beside a raw sector damage.
/// It then injects a duplicate of the first command's report, ends the omitted command with a reset, and returns the bundle digest of the run.
fn faulted_bundle(chooser: &mut Chooser, script: Script) -> [u8; 32] {
    let arena = arena();
    let (mut disk, control) = modeled(11);
    let incarnation = chooser.launch(1);
    let buffers: Vec<_> = (0..5)
        .map(|_| arena.acquire(PoolKind::ReceiveWrite).unwrap())
        .collect();
    for (index, buffer) in buffers.iter().enumerate() {
        control.write_device(at(index as u64 + 5), &fill(index as u8 + 1));
        control.write_host(buffer.offset(), &fill(index as u8 + 0x10));
    }
    let ops = [
        Operation::Read,
        Operation::Write,
        Operation::Read,
        Operation::Write,
        Operation::Read,
    ];
    for (raw, (op, buffer)) in (1..).zip(ops.into_iter().zip(&buffers)) {
        submit(&mut disk, op, raw, block(raw - 1), buffer).unwrap();
    }
    control.fault(
        token(1),
        Fault::MisdirectedRead {
            source: script.source * BLOCK,
        },
    );
    control.fault(token(2), Fault::MisdirectedWrite { target: 10 * BLOCK });
    control.delay(token(3), 2);
    control.fault(token(5), Fault::Omit(script.omission));
    control.damage(11 * BLOCK, 1024);
    let mut delivered = Vec::new();
    for _ in 0..32 {
        for stage in [Stage::Execute, Stage::Post, Stage::Admit] {
            let candidates = control.candidates(stage);
            if !candidates.is_empty() {
                let index = chooser.index(SITE, incarnation, &candidates).unwrap();
                control.select(stage, index).unwrap();
            }
        }
        delivered.extend(pick(&mut disk, 8).0);
        control.advance_to(control.now() + 1);
        if control.outstanding() == control.omitted().len() {
            break;
        }
    }
    assert_eq!(delivered.len(), 4, "{}", control.describe());
    if script.inject {
        control.inject(success(1), Injection::Duplicate);
        delivered.extend(pick(&mut disk, 8).0);
    }
    let omitted = control.omitted();
    stop(&mut disk, &control);
    let hosts: Vec<_> = buffers
        .iter()
        .map(|b| control.host(b.offset(), N))
        .collect();
    drop(buffers);
    assert!(arena.release().is_ok());
    bundle_digest(chooser.recorded(), &control, &delivered, &omitted, &hosts)
}

/// Closes a bundle over the run's choices, its delivered completions, every device event, the attributed damage, the omissions and hostile count, the media and every buffer's host bytes, with the device clock as its virtual time, and returns its semantic digest.
fn bundle_digest(
    tape: &[u8],
    control: &SimControl,
    delivered: &[Completion],
    omitted: &[(super::CommandToken, Omission)],
    hosts: &[Vec<u8>],
) -> [u8; 32] {
    let mut recorder = Recorder::new(Vec::new(), Capacity::new(8, 4, 10_000, 4).unwrap());
    recorder.choices(tape);
    let mut emit = |kind, bytes: &[u8]| {
        let mut payload = [0; PAYLOAD];
        payload[..32].copy_from_slice(&digest(bytes));
        recorder.event(&trace::Event { kind, payload });
    };
    for completion in delivered {
        emit(1, format!("{completion:?}").as_bytes());
    }
    for event in control.events() {
        emit(2, format!("{event:?}").as_bytes());
    }
    for damage in control.damaged() {
        emit(3, format!("{damage:?}").as_bytes());
    }
    emit(4, format!("{omitted:?} {}", control.hostile()).as_bytes());
    emit(5, &control.device(0, at(12)));
    for host in hosts {
        emit(6, host);
    }
    let terminal = Terminal::Complete {
        outcome: Outcome::Pass,
        fired: 1,
        required: 1,
    };
    let work = Work {
        turns: 0,
        decisions: 0,
        progress: 0,
        virtual_us: control.now(),
        skipped_us: 0,
    };
    recorder.finish(terminal, work).digest
}

/// A faulted run replayed from its recorded choices closes a bundle with the same semantic digest; a run whose misdirected read names another source, whose omission takes the other class, or that injects nothing closes a different one.
#[test]
fn a_faulted_run_replays_to_an_equal_bundle_digest() {
    let mut recording = Chooser::record(12, &[SITE]);
    let recorded = faulted_bundle(&mut recording, SCRIPTED);
    let tape = recording.finish().unwrap();
    let mut replaying = Chooser::replay(&[SITE], tape.clone());
    assert_eq!(faulted_bundle(&mut replaying, SCRIPTED), recorded);
    assert!(replaying.finish().is_ok());
    let mutants = [
        Script {
            source: 9,
            ..SCRIPTED
        },
        Script {
            omission: Omission::Episode,
            ..SCRIPTED
        },
        Script {
            inject: false,
            ..SCRIPTED
        },
    ];
    for mutant in mutants {
        let mut moved = Chooser::replay(&[SITE], tape.clone());
        assert_ne!(faulted_bundle(&mut moved, mutant), recorded);
    }
}
