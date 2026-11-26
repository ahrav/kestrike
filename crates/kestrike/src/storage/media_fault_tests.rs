//! The simulated device's media fault classes through the storage read and fill paths: misdirection and sector damage end in typed rejections or an exact verified prefix, and a gray delay or an omission keeps the read's buffer and right until a terminal or a proven stop.
//! The device clock is the one clock: each poll passes the volume the device's time, so deadlines and gray delays share it.

use sha2::{Digest, Sha256};

use super::device::sim::{DAMAGE_XOR, Event, Fault, Omission, QuiesceMode, SimControl};
use super::device::{CommandToken, IO_UNIT, Operation, PoolKind, QuiesceProgress, Quiesced};
use super::grace_tests::refs;
use super::hit_tests::published;
use super::lease::ExtentLease;
use super::owner::Storage;
use super::owner_fixture::last_read;
use super::publish_tests::{TRIES, budget, key};
use super::record::HeaderMismatch;
use super::test_platform::TestPlatform;
use super::volume_fixture::{Device, arena, drive, extent, receive_all, settle};
use super::writable_tests::{bytes, reserve, wide};
use super::{ExtentLocator, ReadEvent, ReadStatus};
use crate::sim::round::{Act, Actor, round};

/// Payload bytes of every object here: three full 8,192-byte chunks and part of a fourth.
const PAYLOAD: usize = 3 * 8192 + 100;

/// The extent slot `slot` holds.
fn locator(storage: &Storage<TestPlatform>, slot: usize) -> ExtentLocator {
    storage.live_pool().unwrap().records()[slot].locator()
}

/// The first device byte of `lease`'s extent.
fn start(storage: &Storage<TestPlatform>, lease: &ExtentLease<'_, TestPlatform>) -> u64 {
    super::volume_fixture::device_byte(storage, locator(storage, lease.id().slot_index())) as u64
}

/// Tokens of the writes the device accepted after event `from` of its ring.
fn writes_after(control: &SimControl, from: usize) -> Vec<CommandToken> {
    control.events()[from..]
        .iter()
        .filter_map(|event| match event {
            Event::Submitted(token, Operation::Write) => Some(*token),
            _ => None,
        })
        .collect()
}

/// Ticks the device and polls the volume at the device clock `turns` times,
/// one controller round each, returning each read's end.
fn ends(dev: &mut Device<'_, '_>, turns: usize) -> Vec<ReadStatus> {
    let mut out = Vec::with_capacity(16);
    let mut ended = Vec::new();
    for _ in 0..turns {
        let mut tick = || dev.control.tick(64);
        let mut poll = || {
            let _ = dev.volume.poll_storage(dev.control.now(), &mut out);
        };
        round(&mut [
            Act::new(Actor::Disk(0), &mut tick),
            Act::new(Actor::Volume(0), &mut poll),
        ]);
        ended.extend(out.drain(..).filter_map(|event| match event {
            ReadEvent::Done { status, .. } => Some(status),
            ReadEvent::Chunk { .. } => None,
        }));
    }
    ended
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Witness: a read misdirected to another object's equal-length extent fails its identity check and delivers no byte, and the intended extent reads as before, so a repeat read completes.
#[test]
fn a_misdirected_read_fails_its_identity_check_with_the_intended_media_restored() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let payload = bytes(PAYLOAD, 1);
    let lease = published(&storage, &mut dev, &key(1), 0, &payload);
    let other = published(&storage, &mut dev, &key(2), 0, &bytes(PAYLOAD, 2));
    let slot = lease.id().slot_index();
    let before = extent(&storage, &dev.control, locator(&storage, slot));
    let op = dev.volume.read(lease.duplicate(), u64::MAX).unwrap();
    let token = last_read(&dev.control).unwrap();
    dev.control.fault(
        token,
        Fault::MisdirectedRead {
            source: start(&storage, &other),
        },
    );
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(
        delivered.status,
        ReadStatus::HeaderMismatch(HeaderMismatch::Key)
    );
    assert!(delivered.bytes.is_empty(), "only allowed bytes: none");
    assert_eq!(
        extent(&storage, &dev.control, locator(&storage, slot)),
        before
    );
    assert_eq!(dev.read(&lease), payload);
    assert_eq!(
        refs(&storage, slot),
        2,
        "the anchor and the lease: each read's right ended"
    );
    drop((lease, other));
    settle(&mut dev.volume, &dev.control);
}

/// A read misdirected to a copy of its own record whose second chunk carries a damaged sector passes its identity check and fails that chunk: it delivers exactly the verified first chunk, and the intended extent and the copy read as before.
#[test]
fn a_misdirected_read_of_damaged_content_delivers_only_the_verified_prefix() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let payload = bytes(PAYLOAD, 6);
    let lease = published(&storage, &mut dev, &key(1), 0, &payload);
    let slot = lease.id().slot_index();
    let intended = locator(&storage, slot);
    let before = extent(&storage, &dev.control, intended);
    let layout = storage.record.layout(0, PAYLOAD as u32);
    let second = layout.chunk(1).unwrap();
    // A device range past the volume, which the copy alone uses.
    let copy = 512 * IO_UNIT as u64;
    dev.control.write_device(copy as usize, &before);
    let damaged = copy + layout.header_bytes() as u64 + second.start + 512;
    dev.control.damage(damaged, 512);
    let copied = dev.control.device(copy as usize, before.len());
    let op = dev.volume.read(lease.duplicate(), u64::MAX).unwrap();
    let token = last_read(&dev.control).unwrap();
    dev.control
        .fault(token, Fault::MisdirectedRead { source: copy });
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(delivered.status, ReadStatus::ChunkMismatch { index: 1 });
    assert_eq!(delivered.bytes, payload[..second.start as usize]);
    assert_eq!(extent(&storage, &dev.control, intended), before);
    assert_eq!(dev.control.device(copy as usize, before.len()), copied);
    drop(lease);
    settle(&mut dev.volume, &dev.control);
}

/// A fill whose one write is misdirected to another object's extent reports success and publishes, yet its own extent keeps the preimage and the other extent's head holds the fill's record: each read ends in a typed rejection with no byte, and the target range is attributed to the write with the digest of the bytes it left.
#[test]
fn a_misdirected_fill_publishes_bytes_that_read_back_as_typed_rejections() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let other = published(&storage, &mut dev, &key(2), 0, &bytes(PAYLOAD, 2));
    let target = start(&storage, &other);
    let mut fill = reserve(&storage, &key(1), 0, 5000).unwrap();
    let slot = fill.id().slot_index();
    let preimage = extent(&storage, &dev.control, locator(&storage, slot));
    dev.control.set_halted(true);
    let from = dev.control.events().len();
    receive_all(
        &mut fill,
        &mut dev.volume,
        &dev.control,
        &bytes(5000, 1),
        4096,
    );
    let tokens = writes_after(&dev.control, from);
    assert_eq!(tokens.len(), 1, "{}", dev.control.describe());
    dev.control
        .fault(tokens[0], Fault::MisdirectedWrite { target });
    dev.control.set_halted(false);
    settle(&mut dev.volume, &dev.control);
    let lease = fill
        .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
        .unwrap();
    assert_eq!(
        extent(&storage, &dev.control, locator(&storage, slot)),
        preimage
    );
    let damaged = dev.control.damaged();
    assert_eq!(damaged.len(), 1);
    let damage = damaged[0];
    assert_eq!((damage.start, damage.token), (target, Some(tokens[0])));
    let left = dev.control.device(target as usize, damage.len as usize);
    assert_eq!(sha(&left), damage.digest);
    let expected = [
        ReadStatus::HeaderMismatch(HeaderMismatch::Magic { found: 0 }),
        ReadStatus::HeaderMismatch(HeaderMismatch::Lengths {
            metadata_len: 0,
            body_len: 5000,
        }),
    ];
    for (read, status) in [&lease, &other].into_iter().zip(expected) {
        let op = dev.volume.read(read.duplicate(), u64::MAX).unwrap();
        let delivered = drive(&mut dev.volume, &dev.control, op);
        assert_eq!(delivered.status, status);
        assert!(delivered.bytes.is_empty());
    }
    drop((lease, other));
    settle(&mut dev.volume, &dev.control);
}

/// What a read of a damaged record shows.
#[derive(Debug, Clone, Copy)]
enum Expect {
    /// A typed header rejection and no byte.
    Header,
    /// The mismatch of this chunk after exactly the chunks before it.
    Chunk(u32),
    /// Uncovered padding: the whole payload and no rejection.
    Padding,
}

/// Sector damage, applied to whole covered sectors through the raw media, ends a read of the header in a typed rejection with no byte and a read of a later payload chunk in that chunk's mismatch after exactly the verified chunks before it; damage to a sector past the payload, which no read covers, earns no rejection.
/// Each damage record names its exact range and the digest of the bytes it left.
#[test]
fn sector_damage_yields_a_typed_rejection_or_an_exact_verified_prefix() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let payload = bytes(PAYLOAD, 3);
    let lease = published(&storage, &mut dev, &key(1), 0, &payload);
    let base = start(&storage, &lease);
    let layout = storage.record.layout(0, PAYLOAD as u32);
    let header = layout.header_bytes() as u64;
    let second = layout.chunk(1).unwrap();
    let end = (header + PAYLOAD as u64).next_multiple_of(512);
    assert!(
        end + 512 <= layout.record_units() * IO_UNIT as u64,
        "a padding sector"
    );
    let cases = [
        (base, Expect::Header),
        (base + header + second.start + 512, Expect::Chunk(1)),
        (base + end, Expect::Padding),
    ];
    for (at, expect) in cases {
        let damage = dev.control.damage(at, 512);
        assert_eq!((damage.start, damage.len, damage.token), (at, 512, None));
        let left = dev.control.device(at as usize, 512);
        assert_eq!(sha(&left), damage.digest);
        let op = dev.volume.read(lease.duplicate(), u64::MAX).unwrap();
        let delivered = drive(&mut dev.volume, &dev.control, op);
        match expect {
            Expect::Header => {
                let found = u64::from_le_bytes(left[..8].try_into().unwrap());
                assert_eq!(
                    delivered.status,
                    ReadStatus::HeaderMismatch(HeaderMismatch::Magic { found })
                );
                assert_eq!(
                    (found ^ u64::from_ne_bytes([DAMAGE_XOR; 8])).to_le_bytes(),
                    *b"IMGCREC1"
                );
                assert!(delivered.bytes.is_empty());
            }
            Expect::Chunk(index) => {
                assert_eq!(delivered.status, ReadStatus::ChunkMismatch { index });
                let chunk = layout.chunk(index).unwrap();
                assert_eq!(delivered.bytes, payload[..chunk.start as usize]);
            }
            Expect::Padding => {
                assert_eq!(delivered.status, ReadStatus::Complete, "uncovered padding");
                assert_eq!(delivered.bytes, payload);
            }
        }
        // Undo the damage through the same raw control, so each case reads one damaged sector.
        let restored: Vec<u8> = left.iter().map(|byte| byte ^ DAMAGE_XOR).collect();
        dev.control.write_device(at as usize, &restored);
    }
    assert_eq!(
        dev.control.damaged().len(),
        3,
        "the records outlive the repair"
    );
    drop(lease);
    settle(&mut dev.volume, &dev.control);
}

/// Gray: a read whose command is delayed past its deadline ends `TimedOut` while the device still holds its buffer, and keeps its right and the buffer until the delayed command terminates normally at the time the device reports as next due; that terminal delivers nothing more.
#[test]
fn a_gray_delay_past_the_deadline_keeps_the_buffer_until_its_terminal() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let lease = published(&storage, &mut dev, &key(1), 0, &bytes(PAYLOAD, 4));
    let slot = lease.id().slot_index();
    let free = buffers.report(PoolKind::ReadResponse).free;
    let _op = dev.volume.read(lease.duplicate(), 10).unwrap();
    let token = last_read(&dev.control).unwrap();
    dev.control.delay(token, 50);
    dev.control.advance_to(10);
    assert_eq!(ends(&mut dev, 8), [ReadStatus::TimedOut]);
    assert_eq!(
        refs(&storage, slot),
        3,
        "the anchor, the lease and the read's right"
    );
    assert_eq!(
        buffers.report(PoolKind::ReadResponse).free,
        free - 1,
        "a deadline releases no buffer the device holds"
    );
    assert_eq!(dev.control.outstanding(), 1);
    assert_eq!(dev.control.next_due(), Some(50));
    dev.control.advance_to(50);
    assert!(ends(&mut dev, 8).is_empty(), "one Done per read");
    assert!(
        dev.control
            .events()
            .contains(&Event::Delayed { token, elapsed: 50 })
    );
    assert_eq!(refs(&storage, slot), 2, "released at the real terminal");
    assert_eq!(buffers.report(PoolKind::ReadResponse).free, free);
    drop(lease);
    settle(&mut dev.volume, &dev.control);
}

/// Omission: a read whose completion is omitted ends `TimedOut` at its deadline and keeps its right and buffer while the device answers nothing; closing waits on the omitted command through a `Pending` and a `Failed` quiesce until a reset proves the stop, which releases both.
/// A hostile omission is counted as such, and the stop leaves that count.
#[test]
fn an_omitted_read_keeps_its_custody_until_the_proven_stop() {
    for class in [Omission::Episode, Omission::Hostile] {
        let storage = wide(2, 8);
        let buffers = arena();
        let mut dev = Device::new(&storage, &buffers);
        let lease = published(&storage, &mut dev, &key(1), 0, &bytes(PAYLOAD, 5));
        let slot = lease.id().slot_index();
        let free = buffers.report(PoolKind::ReadResponse).free;
        let _op = dev.volume.read(lease.duplicate(), 10).unwrap();
        let token = last_read(&dev.control).unwrap();
        dev.control.fault(token, Fault::Omit(class));
        dev.control.advance_to(10);
        assert_eq!(ends(&mut dev, 8), [ReadStatus::TimedOut], "{class:?}");
        assert_eq!(dev.control.omitted(), [(token, class)]);
        for mode in [QuiesceMode::AllReturned, QuiesceMode::Failed(Some(5))] {
            dev.control.set_quiesce(mode);
            let progress = dev.volume.close();
            assert!(
                !matches!(progress, QuiesceProgress::Quiesced(_)),
                "{class:?} {mode:?} {progress:?}"
            );
            assert!(ends(&mut dev, 2).is_empty());
            assert_eq!(refs(&storage, slot), 3, "{class:?} {mode:?}");
            assert_eq!(buffers.report(PoolKind::ReadResponse).free, free - 1);
        }
        dev.control.set_quiesce(QuiesceMode::Reset);
        let mut progress = dev.volume.close();
        for _ in 0..4 {
            let _ = ends(&mut dev, 1);
            progress = dev.volume.close();
        }
        assert_eq!(
            progress,
            QuiesceProgress::Quiesced(Quiesced::DeviceStopped),
            "{class:?}"
        );
        assert_eq!(refs(&storage, slot), 2, "{class:?}");
        assert_eq!(buffers.report(PoolKind::ReadResponse).free, free);
        assert_eq!(dev.control.hostile(), u64::from(class == Omission::Hostile));
        drop(lease);
    }
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_gray_delay_past_the_deadline_keeps_the_buffer_until_its_terminal,
    a_misdirected_fill_publishes_bytes_that_read_back_as_typed_rejections,
    a_misdirected_read_fails_its_identity_check_with_the_intended_media_restored,
    a_misdirected_read_of_damaged_content_delivers_only_the_verified_prefix,
    an_omitted_read_keeps_its_custody_until_the_proven_stop,
    sector_damage_yields_a_typed_rejection_or_an_exact_verified_prefix,
);
