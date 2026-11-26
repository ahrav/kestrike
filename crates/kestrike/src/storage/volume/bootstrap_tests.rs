//! The attach bootstrap over shared simulated media: attach's metadata checks before its claim, the probe of both root slots, format, the RESET's slot order and its evidence, the tenure's session across relaunches, crashes between the RESET writes, retries, and the `Bootstrapping` refusal ahead of the first payload write.

use std::rc::Rc;

use super::super::budget::WorkBudget;
use super::super::device::identify_fixture::{EBS, Fields, facts_sized};
use super::super::device::sim::{
    Captured, Fault, Media, Mode, SCRIPT, SimConfig, SimControl, SimDisk, StatusForm, media, sim,
    sim_attached,
};
use super::super::device::{
    AttachFacts, BufferArena, BufferConfig, CommandToken, DeriveRefusal, DeviceStatus, IO_UNIT,
    Operation, PoolKind, PoolSpec, ProfileRefusal, RefusalReason, SubmitRefusal, TransferLimits,
};
use super::super::ledger::EngineBudget;
use super::super::os::HugepageSize;
use super::super::owner::Storage;
use super::super::placement::NodeMask;
use super::super::readiness::State;
use super::super::record::Crc32c;
use super::super::recovery::{
    AreaRefusal, FormatId, Layout, MetadataOutcome, Root, Slot, TileRefusal, decode, encode,
};
use super::super::test_platform::TestPlatform;
use super::super::volume_fixture::{
    BUFFER, DEPTH, MEDIA, TICK, TestVolume, ample_io, facts, fixture_format, record_bytes,
};
use super::super::writable::FillReserveError;
use super::super::writable::ReceiveError;
use super::volume_tests::{storage as plain, storage_changed};
use super::{AttachError, PLANT, Plant, Volume, VolumeConfig};
use crate::storage::owner_fixture::{self, reserve};

const CONFIG: SimConfig = SimConfig {
    seed: 7,
    capacity: MEDIA,
    queue_depth: DEPTH as u32,
    max_transfer: BUFFER,
    form: StatusForm::Kernel,
    mode: Mode::Direct,
    script: SCRIPT,
};
pub(super) const LAYOUT: Layout = Layout {
    unit: 4096,
    metadata_units: 16,
};

pub(super) fn over(store: &Media) -> (SimDisk, SimControl) {
    sim_attached(CONFIG, Rc::clone(store), facts(BUFFER))
}

/// An arena whose maintenance pool holds `count` buffers of `len` bytes.
pub(super) fn arena_maintaining(count: u32, len: u32) -> BufferArena<TestPlatform> {
    let pools = [
        PoolSpec {
            kind: PoolKind::ReadResponse,
            count: 4,
            buffer_len: BUFFER,
        },
        PoolSpec {
            kind: PoolKind::ReceiveWrite,
            count: 4,
            buffer_len: BUFFER,
        },
        PoolSpec {
            kind: PoolKind::Maintenance,
            count,
            buffer_len: len,
        },
    ];
    let validated = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).expect("node 0"),
        pools: &pools,
    }
    .validate()
    .expect("valid");
    BufferArena::initialize(
        &validated,
        TestPlatform::heap(4096),
        &mut EngineBudget::new(usize::MAX),
    )
    .expect("arena")
}

pub(super) fn arena() -> BufferArena<TestPlatform> {
    arena_maintaining(1, 4096)
}

pub(super) fn attach<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    disk: SimDisk,
) -> TestVolume<'s, 'a> {
    attach_with(
        storage,
        arena,
        disk,
        crate::storage::ServingAuthority::fixture(),
    )
}

/// Attaches `disk` under `authority` with the bootstrap tests' depth and tick.
pub(super) fn attach_with<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    disk: SimDisk,
    authority: crate::storage::ServingAuthority,
) -> TestVolume<'s, 'a> {
    Volume::attach(
        storage,
        arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        authority,
        DEPTH,
        TICK,
        &mut EngineBudget::new(1 << 24),
    )
    .map_err(|(error, _)| error)
    .expect("attach")
}

/// One device tick, then one volume poll with room for every event.
pub(super) fn tick(volume: &mut TestVolume<'_, '_>, control: &SimControl) {
    control.tick(64);
    let mut out = Vec::with_capacity(16);
    let _ = volume.poll_storage(0, &mut out);
}

/// Ticks until the bootstrap leaves `Bootstrapping`, and returns its outcome.
pub(super) fn run(volume: &mut TestVolume<'_, '_>, control: &SimControl) -> MetadataOutcome {
    for _ in 0..64 {
        let outcome = volume.metadata_outcome();
        if outcome != MetadataOutcome::Bootstrapping {
            return outcome;
        }
        tick(volume, control);
    }
    panic!("the bootstrap stayed in progress\n{}", control.describe());
}

/// Runs the bootstrap to `Open`, formatting under [`fixture_format`]'s ID when both slots decode invalid.
fn open(volume: &mut TestVolume<'_, '_>, control: &SimControl) {
    if run(volume, control) == MetadataOutcome::Unformatted {
        volume.format_from(fixture_format).expect("formats");
    }
    assert_eq!(run(volume, control), MetadataOutcome::Open);
}

/// The root each slot of `store` decodes to, if any.
fn roots(store: &Media) -> [Option<(FormatId, Root)>; 2] {
    super::super::volume_fixture::decoded_roots(store, LAYOUT)
}

pub(super) fn generations(store: &Media) -> [Option<u64>; 2] {
    roots(store).map(|root| root.map(|(_, root)| root.generation))
}

/// Encodes `root` of `format` into `slot` of `store` under `layout`.
pub(super) fn place(store: &Media, layout: Layout, format: FormatId, root: &Root, slot: Slot) {
    let mut block = vec![0; 4096];
    encode(Crc32c::detect(), layout, format, root, slot, &mut block);
    let at = slot.block() as usize * 4096;
    store.borrow_mut()[at..at + 4096].copy_from_slice(&block);
}

/// The device start of every write `control` captured, in acceptance order.
pub(super) fn writes(control: &SimControl) -> Vec<u64> {
    submitted(control, Operation::Write)
        .into_iter()
        .map(|(_, start)| start)
        .collect()
}

/// The device start of every read `control` captured, in acceptance order.
pub(super) fn read_starts(control: &SimControl) -> Vec<u64> {
    submitted(control, Operation::Read)
        .into_iter()
        .map(|(_, start)| start)
        .collect()
}

pub(super) fn submitted(control: &SimControl, op: Operation) -> Vec<(CommandToken, u64)> {
    control
        .capture()
        .events
        .iter()
        .filter_map(|event| match *event {
            Captured::Submitted {
                token,
                operation,
                device,
                ..
            } if operation == op => Some((token, device.start())),
            _ => None,
        })
        .collect()
}

/// The capture position of `token`'s submission and of its delivery.
pub(super) fn positions(control: &SimControl, token: CommandToken) -> (usize, Option<usize>) {
    let events = control.capture().events;
    let submitted = events
        .iter()
        .position(|event| matches!(event, Captured::Submitted { token: t, .. } if *t == token))
        .expect("submitted");
    let delivered = events
        .iter()
        .position(|event| matches!(event, Captured::Delivered { token: t, .. } if *t == token));
    (submitted, delivered)
}

pub(super) const FORMAT: FormatId = FormatId([0x42; 16]);

#[test]
fn fresh_media_waits_unformatted_and_format_writes_the_tenure_session_to_a_then_b() {
    let storage = plain(2);
    let arena = arena();
    let store = media(MEDIA);
    let (disk, control) = over(&store);
    let expected = crate::storage::upcoming_session();
    let mut volume = attach(&storage, &arena, disk);
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Unformatted);
    let reads = read_starts(&control);
    assert_eq!(reads, [0, 4096], "slot A, then slot B");
    assert!(writes(&control).is_empty(), "the probe writes nothing");
    volume
        .format_from(fixture_format)
        .expect("both slots decode invalid");
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Open);
    assert_eq!(writes(&control), [0, 4096], "slot A, then slot B");
    let [Some((a_format, a)), Some((b_format, b))] = roots(&store) else {
        panic!("both slots hold a root")
    };
    assert_eq!(a_format, b_format, "one format ID");
    assert_ne!(a_format.0, [0; 16]);
    assert_eq!(
        (a.clone(), b),
        (
            Root::reset(
                volume.session(),
                crate::storage::TEST_CLOCK.encode(),
                crate::storage::TEST_FEED.encode()
            ),
            Root::reset(
                volume.session(),
                crate::storage::TEST_CLOCK.encode(),
                crate::storage::TEST_FEED.encode()
            )
        )
    );
    assert_eq!(
        volume.session(),
        expected,
        "the format writes the tenure's session"
    );
    assert_eq!(volume.format(), Err(MetadataOutcome::Open));
    assert_eq!(writes(&control).len(), 2, "a refused format writes nothing");
}

/// A format request refuses with the bootstrap's outcome and writes nothing unless both slots decode invalid: over a valid root, an unreadable slot, an unsupported version and a foreign layout.
#[test]
fn format_refuses_and_writes_nothing_unless_both_slots_decode_invalid() {
    let arena = arena();
    // A valid root: the bootstrap RESETs over it, and format refuses.
    let store = media(MEDIA);
    place(
        &store,
        LAYOUT,
        FORMAT,
        &Root::reset(
            3,
            crate::storage::TEST_CLOCK.encode(),
            crate::storage::TEST_FEED.encode(),
        ),
        Slot::A,
    );
    let storage = plain(2);
    let (disk, control) = over(&store);
    let expected = crate::storage::upcoming_session();
    let mut volume = attach(&storage, &arena, disk);
    assert_eq!(volume.format(), Err(MetadataOutcome::Bootstrapping));
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Open);
    assert_eq!(volume.format(), Err(MetadataOutcome::Open));
    assert_eq!(generations(&store), [Some(expected); 2]);
    drop(volume);
    // An unreadable slot A.
    let store = media(MEDIA);
    let storage = plain(2);
    let (disk, control) = over(&store);
    let mut volume = attach(&storage, &arena, disk);
    let _ = volume.poll_storage(0, &mut Vec::with_capacity(16));
    let [(read, 0)] = submitted(&control, Operation::Read)[..] else {
        panic!("slot A's read")
    };
    control.fault(read, Fault::Status(DeviceStatus::Kernel(-5)));
    let unreadable = MetadataOutcome::SlotUnreadable { slot: Slot::A };
    assert_eq!(run(&mut volume, &control), unreadable);
    assert_eq!(volume.format(), Err(unreadable));
    assert!(writes(&control).is_empty());
    drop(volume);
    // An unsupported version in slot B and a foreign layout in slot A.
    let mut newer = vec![0; 4096];
    encode(
        Crc32c::detect(),
        LAYOUT,
        FORMAT,
        &Root::reset(
            2,
            crate::storage::TEST_CLOCK.encode(),
            crate::storage::TEST_FEED.encode(),
        ),
        Slot::B,
        &mut newer,
    );
    newer[8] = 0x04;
    let foreign = Layout {
        unit: 4096,
        metadata_units: 8,
    };
    for (slot, refused) in [
        (
            Slot::B,
            MetadataOutcome::Unsupported {
                slot: Slot::B,
                version: 0x8004,
            },
        ),
        (Slot::A, MetadataOutcome::FormatMismatch),
    ] {
        let store = media(MEDIA);
        if slot == Slot::B {
            store.borrow_mut()[4096..8192].copy_from_slice(&newer);
        } else {
            place(
                &store,
                foreign,
                FORMAT,
                &Root::reset(
                    2,
                    crate::storage::TEST_CLOCK.encode(),
                    crate::storage::TEST_FEED.encode(),
                ),
                Slot::A,
            );
        }
        let before = store.borrow().clone();
        let storage = plain(2);
        let (disk, control) = over(&store);
        let mut volume = attach(&storage, &arena, disk);
        assert_eq!(run(&mut volume, &control), refused);
        assert_eq!(volume.format(), Err(refused));
        assert!(writes(&control).is_empty(), "{refused:?}");
        assert!(*store.borrow() == before, "{refused:?} left the media");
    }
}

/// A failed read at each position of the probe refuses `SlotUnreadable` for the slot it read, withholds the attempt,
/// closes admission, installs and writes nothing, and a format request then refuses with that outcome: read 1 of the
/// probe reads slot A, and read 2 reads slot B once read 1 succeeded. The probe with no failed read submits those two
/// reads and waits unformatted, and the slots the refusals name across the sweep are the blocks of those reads, each
/// once.
#[test]
fn a_failed_read_at_each_probe_position_refuses_slot_unreadable_with_no_write() {
    let arena = arena();
    let probe = |fault: Option<usize>| {
        let store = media(MEDIA);
        let before = store.borrow().clone();
        let storage = plain(2);
        let (disk, control) = over(&store);
        let mut volume = attach(&storage, &arena, disk);
        let mut faulted = None;
        for _ in 0..64 {
            if volume.metadata_outcome() != MetadataOutcome::Bootstrapping {
                break;
            }
            let reads = submitted(&control, Operation::Read);
            if let Some(n) = fault
                && faulted.is_none()
                && let Some(&(token, start)) = reads.get(n - 1)
            {
                control.fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
                faulted = Some(start);
            }
            tick(&mut volume, &control);
        }
        if fault.is_some() {
            let refused = volume.metadata_outcome();
            assert_eq!(
                volume.readiness(),
                State::Withheld,
                "fault at read {fault:?}: the refusal withholds the attempt"
            );
            assert_eq!(
                volume.format_from(fixture_format),
                Err(refused),
                "fault at read {fault:?}: a format refuses with the outcome"
            );
            for _ in 0..8 {
                tick(&mut volume, &control);
            }
            assert_eq!(
                owner_fixture::residents(&storage),
                0,
                "fault at read {fault:?}: nothing installed"
            );
        }
        assert_eq!(
            storage.is_closed(),
            fault.is_some(),
            "fault at read {fault:?}: a refused probe closes admission"
        );
        assert!(
            writes(&control).is_empty(),
            "fault at read {fault:?}: no write"
        );
        assert!(
            *store.borrow() == before,
            "fault at read {fault:?}: the media are unchanged"
        );
        (volume.metadata_outcome(), read_starts(&control), faulted)
    };
    let (outcome, clean, _) = probe(None);
    assert_eq!(outcome, MetadataOutcome::Unformatted);
    assert_eq!(
        clean,
        [0, 4096],
        "the clean probe reads slot A, then slot B"
    );
    let mut refused = Vec::new();
    for (n, slot) in (1..=clean.len()).zip([Slot::A, Slot::B]) {
        let (outcome, reads, fault) = probe(Some(n));
        assert_eq!(
            fault,
            Some(clean[n - 1]),
            "slot {slot:?}: its probe alone is faulted"
        );
        assert_eq!(
            reads,
            clean[..n],
            "slot {slot:?}: no read follows the failed probe"
        );
        let MetadataOutcome::SlotUnreadable { slot: named } = outcome else {
            panic!("slot {slot:?}: the probe refuses SlotUnreadable, not {outcome:?}");
        };
        assert_eq!(named, slot, "the refusal names the probed slot");
        refused.push(named.block() * IO_UNIT as u64);
    }
    assert_eq!(
        refused, clean,
        "the refusals name the slot of each read of the clean probe once"
    );
}

/// Over two valid slots of two format IDs, tied roots of different content, or a root of generation `u64::MAX`, above every session, the bootstrap refuses and writes nothing.
#[test]
fn foreign_format_ids_tied_roots_and_a_root_above_the_session_refuse_with_no_write() {
    let arena = arena();
    let tied = Root {
        incarnation: 4,
        ..Root::reset(
            5,
            crate::storage::TEST_CLOCK.encode(),
            crate::storage::TEST_FEED.encode(),
        )
    };
    let cases: [(&Root, FormatId, &Root, MetadataOutcome); 3] = [
        (
            &Root::reset(
                5,
                crate::storage::TEST_CLOCK.encode(),
                crate::storage::TEST_FEED.encode(),
            ),
            FormatId([0x43; 16]),
            &Root::reset(
                4,
                crate::storage::TEST_CLOCK.encode(),
                crate::storage::TEST_FEED.encode(),
            ),
            MetadataOutcome::FormatMismatch,
        ),
        (
            &Root::reset(
                5,
                crate::storage::TEST_CLOCK.encode(),
                crate::storage::TEST_FEED.encode(),
            ),
            FORMAT,
            &tied,
            MetadataOutcome::TiedRoots,
        ),
        (
            &Root::reset(
                u64::MAX,
                crate::storage::TEST_CLOCK.encode(),
                crate::storage::TEST_FEED.encode(),
            ),
            FORMAT,
            &Root::reset(
                4,
                crate::storage::TEST_CLOCK.encode(),
                crate::storage::TEST_FEED.encode(),
            ),
            MetadataOutcome::StaleSession,
        ),
    ];
    for (a, b_format, b, refused) in cases {
        let store = media(MEDIA);
        place(&store, LAYOUT, FORMAT, a, Slot::A);
        place(&store, LAYOUT, b_format, b, Slot::B);
        let storage = plain(2);
        let (disk, control) = over(&store);
        let mut volume = attach(&storage, &arena, disk);
        assert_eq!(run(&mut volume, &control), refused);
        assert!(writes(&control).is_empty(), "{refused:?}");
        assert_eq!(volume.session(), 0, "{refused:?} opened no session");
        assert!(storage.is_closed(), "{refused:?} closed admission");
    }
}

/// The session each attach over `store` writes, for `attaches` attaches with a fresh storage each, checked against the authority's session and every generation the media's root slots held before the attach.
///
/// # Errors
///
/// `a generation was reissued` when an attach writes a generation at or below one the slots held.
fn relaunched(store: &Media, attaches: usize) -> Result<Vec<u64>, &'static str> {
    let arena = arena();
    let mut issued = Vec::new();
    for _ in 0..attaches {
        let before = generations(store).into_iter().flatten().max();
        let storage = plain(2);
        let (disk, control) = over(store);
        let expected = crate::storage::upcoming_session();
        let mut volume = attach(&storage, &arena, disk);
        open(&mut volume, &control);
        let reads = read_starts(&control);
        assert_eq!(
            reads,
            [0, 4096],
            "the bootstrap reads the two root slots and no other metadata block"
        );
        let generation = volume.session();
        if before.is_some_and(|before| generation <= before) {
            return Err("a generation was reissued");
        }
        assert_eq!(
            generation, expected,
            "the attach writes its tenure's session"
        );
        assert_eq!(generations(store), [Some(generation); 2]);
        issued.push(generation);
    }
    Ok(issued)
}

/// A cold attach over a valid root that names journal history RESETs both slots under the tenure's session after
/// reading only the two root slots: the history the old root names is neither read nor carried into the new roots,
/// and the volume opens and reaches `Live` over no restored binding.
#[test]
fn a_cold_attach_resets_over_a_root_that_names_history_reading_only_the_root_slots() {
    let clock = crate::storage::TEST_CLOCK.encode();
    let feed = crate::storage::TEST_FEED.encode();
    let arena = arena();
    let named = [
        Root {
            sequence: 1,
            journal: 0..2,
            ..Root::reset(5, clock, feed)
        },
        Root {
            history: 4,
            incarnation: 4,
            journal: 3..6,
            ..Root::reset(5, clock, feed)
        },
    ];
    for old in named {
        let store = media(MEDIA);
        place(&store, LAYOUT, FORMAT, &old, Slot::A);
        let storage = plain(2);
        let (disk, control) = over(&store);
        let expected = crate::storage::upcoming_session();
        let mut volume = attach(&storage, &arena, disk);
        assert_eq!(run(&mut volume, &control), MetadataOutcome::Open);
        let reads = read_starts(&control);
        assert_eq!(reads, [0, 4096], "only the root slots are read: {old:?}");
        assert_eq!(
            writes(&control),
            [4096, 0],
            "the RESET writes B, which lacks the highest root, then A"
        );
        let reset = Root::reset(expected, clock, feed);
        assert_eq!(
            roots(&store).map(|root| root.map(|(_, root)| root)),
            [Some(reset.clone()), Some(reset)],
            "both slots hold the tenure's RESET root, naming no history"
        );
        assert_eq!(
            volume.begin_replay(storage.feed_contract(), 0),
            Ok(super::super::Readiness::Live)
        );
    }
}

/// Attaches over shared media write their sessions, each above every generation the slots held.
#[test]
fn relaunches_over_shared_media_write_increasing_sessions() {
    let issued = relaunched(&media(MEDIA), 3).unwrap();
    assert!(
        issued.windows(2).all(|pair| pair[0] < pair[1]),
        "{issued:?}"
    );
}

/// Planted `GenerationReuse`: a RESET that writes the highest valid generation in place of the session fails the reissue check by name.
#[test]
fn a_reset_that_reissues_the_highest_generation_fails_the_issuance_check() {
    let store = media(MEDIA);
    assert!(relaunched(&store, 1).is_ok());
    PLANT.with(|plant| plant.set(Some(Plant::GenerationReuse)));
    let reissued = relaunched(&store, 1);
    PLANT.with(|plant| plant.set(None));
    assert_eq!(reissued, Err("a generation was reissued"));
}

/// Every record a fill writes carries the attach's tenure session as its header's session: the extent's bytes equal a record built with that session, across three incarnations over one media.
#[test]
fn every_payload_header_carries_the_tenure_session() {
    let store = media(MEDIA);
    let arena = owner_fixture::arena(4);
    for generation in 1..=3 {
        let storage = owner_fixture::storage(8);
        let expected = crate::storage::upcoming_session();
        let mut device =
            super::super::volume_fixture::Device::over(&storage, &arena, Rc::clone(&store));
        let session = device.volume.session();
        assert_eq!(
            session, expected,
            "generation {generation}: the tenure's session"
        );
        let key = [generation as u8; 32];
        let payload = vec![generation as u8; 1000];
        let mut fill = reserve(&storage, &key, 0, payload.len()).expect("a fill");
        let id = fill.id();
        device.fill(&mut fill, &payload);
        let locator = storage.live_pool().unwrap().records()[id.slot_index()].locator();
        let expected = record_bytes(&storage, key, id, session, &[], &payload);
        let written = super::super::volume_fixture::extent(&storage, &device.control, locator);
        assert_eq!(
            written[..expected.len()],
            expected[..],
            "generation {generation}"
        );
        fill.abort();
    }
}

/// Holds every write `control` captured past the first `seen`, returning the newly held tokens with their device starts.
fn hold_new(control: &SimControl, seen: &mut usize) -> Vec<(CommandToken, u64)> {
    let all = submitted(control, Operation::Write);
    let new = all[*seen..].to_vec();
    for (token, _) in &new {
        control.hold(*token);
    }
    *seen = all.len();
    new
}

/// A crash between the two RESET writes, with the highest root in either slot: the first write goes to the other slot, the highest root's slot keeps its bytes until that write is persisted, the second write follows the first's delivery, and the next attach writes its own session above the crashed attach's.
#[test]
fn a_crash_between_the_reset_writes_keeps_the_highest_root_and_the_next_attach_writes_a_higher_session()
 {
    for highest in [Slot::A, Slot::B] {
        // A dead volume's held write keeps its maintenance buffer, so each owner takes its own arena.
        let arena = arena();
        let store = media(MEDIA);
        place(
            &store,
            LAYOUT,
            FORMAT,
            &Root::reset(
                5,
                crate::storage::TEST_CLOCK.encode(),
                crate::storage::TEST_FEED.encode(),
            ),
            highest,
        );
        place(
            &store,
            LAYOUT,
            FORMAT,
            &Root::reset(
                4,
                crate::storage::TEST_CLOCK.encode(),
                crate::storage::TEST_FEED.encode(),
            ),
            highest.other(),
        );
        let kept = store.borrow()[highest.block() as usize * 4096..][..4096].to_vec();
        let storage = plain(2);
        let (disk, control) = over(&store);
        let expected = crate::storage::upcoming_session();
        let mut volume = attach(&storage, &arena, disk);
        let mut seen = 0;
        let mut held = Vec::new();
        for _ in 0..16 {
            held.extend(hold_new(&control, &mut seen));
            if !held.is_empty() {
                break;
            }
            tick(&mut volume, &control);
        }
        let [(first, start)] = held[..] else {
            panic!("one RESET write outstanding: {held:?}")
        };
        assert_eq!(start, highest.other().block() * 4096, "{highest:?}");
        for _ in 0..4 {
            tick(&mut volume, &control);
            assert!(
                hold_new(&control, &mut seen).is_empty(),
                "one root write at a time"
            );
            assert_eq!(
                store.borrow()[highest.block() as usize * 4096..][..4096],
                kept[..]
            );
        }
        control.release(first);
        let mut second = None;
        for _ in 0..16 {
            tick(&mut volume, &control);
            if let [(token, start)] = hold_new(&control, &mut seen)[..] {
                second = Some((token, start));
                break;
            }
        }
        let (second, start) = second.expect("the second RESET write");
        assert_eq!(start, highest.block() * 4096);
        assert!(positions(&control, first).1.expect("delivered") < positions(&control, second).0);
        assert_eq!(
            store.borrow()[highest.block() as usize * 4096..][..4096],
            kept[..]
        );
        assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
        // The owner dies with the second write held; it never lands.
        drop(volume);
        let got = generations(&store);
        assert_eq!(got[highest.block() as usize], Some(5), "{highest:?}");
        let crashed = got[highest.other().block() as usize].expect("the first RESET write landed");
        assert_eq!(
            crashed, expected,
            "{highest:?}: the crashed attach's session"
        );
        let next = storage_and_open(&arena_maintaining(1, 4096), &store);
        assert!(
            next > crashed,
            "{highest:?}: never the crashed attach's session"
        );
    }
}

fn storage_and_open(arena: &BufferArena<TestPlatform>, store: &Media) -> u64 {
    let storage = plain(2);
    let (disk, control) = over(store);
    let expected = crate::storage::upcoming_session();
    let mut volume = attach(&storage, arena, disk);
    open(&mut volume, &control);
    assert_eq!(
        volume.session(),
        expected,
        "the attach writes its tenure's session"
    );
    expected
}

/// After a RESET under a session, corrupting either slot leaves the other's root valid and the next attach writes its higher session; corrupting both leaves no valid root, so the bootstrap waits for a format and writes nothing.
#[test]
fn corrupting_one_slot_after_a_reset_still_admits_a_higher_session_and_corrupting_both_writes_nothing()
 {
    let arena = arena();
    let store = media(MEDIA);
    let first = storage_and_open(&arena, &store);
    let second = storage_and_open(&arena, &store);
    assert!(second > first);
    store.borrow_mut()[200] ^= 0xFF;
    assert_eq!(generations(&store), [None, Some(second)]);
    let third = storage_and_open(&arena, &store);
    assert!(third > second);
    store.borrow_mut()[4096 + 200] ^= 0xFF;
    assert_eq!(generations(&store), [Some(third), None]);
    assert!(storage_and_open(&arena, &store) > third);
    store.borrow_mut()[200] ^= 0xFF;
    store.borrow_mut()[4096 + 200] ^= 0xFF;
    let storage = plain(2);
    let (disk, control) = over(&store);
    let mut volume = attach(&storage, &arena, disk);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Unformatted);
    assert!(writes(&control).is_empty());
}

/// Fills refuse `Bootstrapping` until both RESET roots are persisted: a reservation made during the bootstrap refuses after its `Closed` check, a fill reserved before attach refuses to receive, and the first payload write is submitted only after the second RESET write was delivered, judged by capture position with that completion held.
#[test]
fn the_first_payload_write_follows_the_second_reset_write_and_fills_refuse_bootstrapping_until_then()
 {
    let storage = owner_fixture::storage(8);
    let arena = owner_fixture::arena(4);
    let payload = vec![7u8; 1000];
    let mut early = reserve(&storage, &[1; 32], 0, payload.len()).expect("before attach");
    let store = media(MEDIA);
    let (disk, control) = over(&store);
    let mut volume = attach(&storage, &arena, disk);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Unformatted);
    volume.format().unwrap();
    let mut seen = 0;
    let mut held = Vec::new();
    for _ in 0..32 {
        tick(&mut volume, &control);
        let new = hold_new(&control, &mut seen);
        for &(token, start) in &new {
            if start == 0 {
                control.release(token);
            } else {
                held.push(token);
            }
        }
        if !held.is_empty() {
            break;
        }
    }
    let [second] = held[..] else {
        panic!("slot B's RESET write is held")
    };
    for _ in 0..4 {
        tick(&mut volume, &control);
    }
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
    assert_eq!(
        reserve(&storage, &[2; 32], 0, 100).err(),
        Some(FillReserveError::Bootstrapping)
    );
    assert_eq!(
        early.receive(&mut volume, &payload, &mut ample_io()),
        Err(ReceiveError::Bootstrapping)
    );
    control.release(second);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Open);
    volume.begin_replay(storage.feed_contract(), 0).unwrap();
    assert_eq!(
        early.receive(&mut volume, &payload, &mut ample_io()),
        Ok(payload.len())
    );
    let payload_write = submitted(&control, Operation::Write)
        .into_iter()
        .find(|&(_, start)| start >= 8192)
        .expect("the fill's write")
        .0;
    let delivered = positions(&control, second).1.expect("delivered");
    assert!(delivered < positions(&control, payload_write).0);
    early.abort();
    // A closed storage refuses `Closed` before `Bootstrapping`.
    let closed = owner_fixture::storage(8);
    let (disk, _control) = super::super::volume_fixture::device_with(7, BUFFER);
    let _volume = attach(&closed, &arena, disk);
    let attempt = closed
        .begin_fill(
            &[3; 32],
            crate::storage::CacheVersion(0),
            4,
            &mut WorkBudget::new(1 << 16),
        )
        .expect("an attempt");
    let admitted = super::super::writable_tests::admit(&closed, 0, 100);
    closed.close();
    assert_eq!(
        attempt
            .reserve_storage(
                admitted,
                Some(0),
                Some(100),
                4,
                &mut WorkBudget::new(1 << 16)
            )
            .err(),
        Some(FillReserveError::Closed)
    );
}

/// A `Failed` RESET write replays the same bytes within `metadata_retries`; the write past them records `MetadataFailed`, which stays, and closes the storage's admission.
#[test]
fn a_failed_reset_write_replays_its_bytes_and_exhausted_retries_close_admission() {
    let storage = owner_fixture::storage(8);
    let arena = owner_fixture::arena(4);
    let store = media(MEDIA);
    let attempt = storage
        .begin_fill(
            &[2; 32],
            crate::storage::CacheVersion(0),
            4,
            &mut WorkBudget::new(1 << 16),
        )
        .expect("an attempt");
    let admitted = super::super::writable_tests::admit(&storage, 0, 100);
    let (disk, control) = over(&store);
    let mut volume = attach(&storage, &arena, disk);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Unformatted);
    volume.format().unwrap();
    let mut seen = 0;
    let (mut tokens, mut bytes) = (Vec::new(), Vec::new());
    for _ in 0..32 {
        let _ = volume.poll_storage(0, &mut Vec::with_capacity(16));
        for (token, _) in submitted(&control, Operation::Write).split_off(seen) {
            bytes.push(control.submitted(token).expect("pending"));
            control.fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
            tokens.push(token);
        }
        seen = tokens.len();
        control.tick(64);
        if volume.metadata_outcome() != MetadataOutcome::Bootstrapping {
            break;
        }
    }
    let _ = volume.poll_storage(0, &mut Vec::with_capacity(16));
    // The first write and its two retries, each at slot A.
    assert_eq!(tokens.len(), 3);
    assert_eq!(writes(&control), [Slot::A.block() * 4096; 3]);
    assert!(
        bytes.iter().all(|sent| *sent == bytes[0]),
        "identical bytes"
    );
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::MetadataFailed);
    assert!(storage.is_closed());
    assert_eq!(
        attempt
            .reserve_storage(
                admitted,
                Some(0),
                Some(100),
                4,
                &mut WorkBudget::new(1 << 16)
            )
            .err(),
        Some(FillReserveError::Closed)
    );
    assert_eq!(volume.format(), Err(MetadataOutcome::MetadataFailed));
    for _ in 0..4 {
        tick(&mut volume, &control);
    }
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::MetadataFailed);
    assert_eq!(volume.report().metadata_failed, 3);
}

/// A RESET write whose first terminal is `Failed` retries at its own slot with the same bytes, the other slot's write waits for the retry's `Persisted`, and the volume opens with both slots holding the tenure's RESET root.
#[test]
fn a_reset_write_that_fails_once_retries_at_its_slot_and_the_volume_opens() {
    let storage = owner_fixture::storage(8);
    let arena = owner_fixture::arena(4);
    let store = media(MEDIA);
    let (disk, control) = over(&store);
    let mut volume = attach(&storage, &arena, disk);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Unformatted);
    volume.format().unwrap();
    let mut failed = None;
    for _ in 0..32 {
        let _ = volume.poll_storage(0, &mut Vec::with_capacity(16));
        if failed.is_none()
            && let Some(&(token, _)) = submitted(&control, Operation::Write).first()
        {
            failed = Some(control.submitted(token).expect("pending"));
            control.fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
        }
        control.tick(64);
        if volume.metadata_outcome() != MetadataOutcome::Bootstrapping {
            break;
        }
    }
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
    assert_eq!(volume.report().metadata_failed, 1);
    let (a, b) = (Slot::A.block() * 4096, Slot::B.block() * 4096);
    assert_eq!(writes(&control), [a, a, b]);
    let at = a as usize;
    assert_eq!(
        Some(&store.borrow()[at..at + 4096]),
        failed.as_deref(),
        "the retry wrote the failed write's bytes"
    );
    let [x, y] = roots(&store).map(|root| root.map(|(_, root)| root));
    assert_eq!(x.as_ref().map(|root| root.generation), Some(volume.session));
    assert_eq!(x, y);
}

/// A table or device queue that refuses a metadata submit as full leaves the command staged without spending a retry, a tick with no read and no terminal still submits it, and the bootstrap completes with one retry configured.
#[test]
fn a_busy_device_queue_resubmits_free_and_a_quiet_tick_runs_the_metadata_step() {
    let storage = storage_changed(2, |volume| volume.metadata_retries = 1).expect("valid");
    let arena = arena();
    let store = media(MEDIA);
    let (disk, control) = over(&store);
    let mut volume = attach(&storage, &arena, disk);
    let full = SubmitRefusal {
        reason: RefusalReason::QueueFull,
        code: None,
    };
    for _ in 0..3 {
        control.refuse_next(full);
    }
    for refused in 1..=3 {
        let report = volume.poll_storage(0, &mut Vec::with_capacity(16));
        assert_eq!(report.submitted, 0);
        assert_eq!(volume.report().metadata_refused, refused);
    }
    let report = volume.poll_storage(0, &mut Vec::with_capacity(16));
    assert_eq!(
        (report.submitted, report.terminals),
        (1, 0),
        "a quiet tick submits"
    );
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Unformatted);
    control.refuse_next(full);
    control.refuse_next(full);
    volume.format().unwrap();
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Open);
    assert_eq!(volume.report().metadata_failed, 0);
}

/// Each metadata check attach runs refuses typed before the claim, with the driver and budget returned and no device command; the exact fit of each attaches.
#[test]
fn attach_refuses_each_metadata_input_before_its_claim_with_no_device_command() {
    let refuse = |storage: &Storage<TestPlatform>,
                  arena: &BufferArena<TestPlatform>,
                  facts: Option<AttachFacts>| {
        let (disk, control) = match facts {
            Some(facts) => sim_attached(CONFIG, media(MEDIA), facts),
            None => sim(CONFIG),
        };
        let mut budget = EngineBudget::new(1 << 24);
        let before = budget;
        let refused = Volume::attach(
            storage,
            arena,
            disk,
            crate::storage::portable::scripted::ScriptedClock::trusted(),
            crate::storage::ServingAuthority::fixture(),
            DEPTH,
            TICK,
            &mut budget,
        )
        .err()
        .map(|(error, _)| error);
        assert!(
            refused.is_none() || budget == before,
            "{refused:?} kept the budget"
        );
        assert_eq!(control.driver_calls(), 0, "{refused:?}");
        refused
    };
    let fields = |unit_sectors: u16, boundary: Option<u16>| Fields {
        awupf: 0,
        nsfeat: 0x02,
        nawupf: unit_sectors - 1,
        nabo: boundary.unwrap_or(0),
        nabspf: if boundary.is_some() { u16::MAX } else { 0 },
        vendor: None,
        limits: TransferLimits {
            namespace_max: BUFFER,
            boundary: 0,
            command: BUFFER,
        },
        ..EBS
    };
    let sized = |fields| Some(facts_sized(fields, MEDIA / 512));
    let base = plain(2);
    let fit = arena();
    assert_eq!(refuse(&base, &fit, None), Some(AttachError::NoAttachFacts));
    assert_eq!(
        refuse(
            &base,
            &fit,
            sized(Fields {
                vwc: 1,
                ..fields(8, None)
            })
        ),
        Some(AttachError::Profile(DeriveRefusal::Ineligible(
            ProfileRefusal::VolatileWriteCache
        )))
    );
    // `units` metadata units over the base's payload.
    let prefix = |units: u64| {
        storage_changed(2, move |volume| {
            volume.raw_bytes = volume.raw_bytes + units as usize * IO_UNIT - 16 * IO_UNIT;
            volume.metadata_units = units;
        })
        .expect("valid")
    };
    let one = prefix(1);
    assert_eq!(
        refuse(&one, &fit, Some(facts(BUFFER))),
        Some(AttachError::Metadata(AreaRefusal::Layout {
            refusal: TileRefusal::TooFewBlocks,
            unit: 4096
        }))
    );
    // The two root slots set the metadata prefix's minimum size to two blocks.
    assert_eq!(refuse(&prefix(2), &fit, Some(facts(BUFFER))), None);
    assert_eq!(refuse(&prefix(5), &fit, Some(facts(BUFFER))), None);
    let three = prefix(3);
    assert_eq!(
        refuse(&three, &fit, sized(fields(16, None))),
        Some(AttachError::Metadata(AreaRefusal::Layout {
            refusal: TileRefusal::NotUnitMultiple,
            unit: 8192
        }))
    );
    // A boundary at sector 132 falls inside block 16 of seventeen 4096-byte blocks, past the base's sixteen.
    assert_eq!(
        refuse(&prefix(17), &fit, sized(fields(8, Some(132)))),
        Some(AttachError::Metadata(AreaRefusal::Unqualified {
            block: 16
        }))
    );
    assert_eq!(refuse(&plain(2), &fit, sized(fields(8, Some(132)))), None);
    for edit in [
        (|volume: &mut VolumeConfig| volume.metadata_commands = 0) as fn(&mut VolumeConfig),
        |volume| volume.metadata_retries = 0,
    ] {
        let zero = storage_changed(2, edit).expect("valid");
        assert_eq!(
            refuse(&zero, &fit, Some(facts(BUFFER))),
            Some(AttachError::ZeroMetadataField)
        );
    }
    let two = storage_changed(2, |volume| volume.metadata_commands = 2).expect("valid");
    assert_eq!(
        refuse(&two, &fit, Some(facts(BUFFER))),
        Some(AttachError::MaintenanceShort {
            buffers: 1,
            buffer_len: 4096
        })
    );
    assert_eq!(
        refuse(&two, &arena_maintaining(2, 4096), Some(facts(BUFFER))),
        None
    );
    let eight = prefix(32);
    assert_eq!(
        refuse(&eight, &fit, sized(fields(16, None))),
        Some(AttachError::MaintenanceShort {
            buffers: 1,
            buffer_len: 4096
        })
    );
    assert_eq!(
        refuse(&eight, &arena_maintaining(1, 8192), sized(fields(16, None))),
        None
    );
    let crowded = storage_changed(7, |_| {}).expect("valid");
    assert_eq!(
        refuse(&crowded, &fit, Some(facts(BUFFER))),
        Some(AttachError::MetadataCommandsOutOfRange {
            read_commands: 7,
            metadata_commands: 1,
            reservation_commands: 0,
            depth: DEPTH
        })
    );
    assert_eq!(refuse(&plain(6), &fit, Some(facts(BUFFER))), None);
    // Every refusal above left the claim untaken.
    let (disk, control) = over(&media(MEDIA));
    let mut volume = attach(&base, &fit, disk);
    open(&mut volume, &control);
}

#[test]
fn the_hardware_fixtures_attach_over_the_ebs_profile() {
    let storage = owner_fixture::hardware_storage_on(512 << 10, 3 * 16384, 64);
    let arena = owner_fixture::arena_on(TestPlatform::heap(4096), 16, 5);
    let facts = facts_sized(EBS, MEDIA / 512);
    let config = SimConfig {
        max_transfer: facts.identify.transfer().command,
        ..CONFIG
    };
    let (disk, control) = sim_attached(config, media(MEDIA), facts);
    let mut volume = Volume::attach(
        &storage,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
        &mut EngineBudget::new(1 << 24),
    )
    .map_err(|(error, _)| error)
    .expect("the hardware fixtures fit the EBS profile");
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Unformatted);
    volume.format().unwrap();
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Open);
}

/// A format whose entropy draw fails or returns all zeros refuses `EntropyUnavailable`, which becomes the outcome, and writes nothing.
#[test]
fn a_format_without_entropy_refuses_and_writes_nothing() {
    let arena = arena();
    for fill in [
        (|_: &mut [u8; 16]| Err(crate::entropy::EntropyError::Unavailable { code: 5 }))
            as fn(&mut [u8; 16]) -> Result<(), crate::entropy::EntropyError>,
        |_| Ok(()),
    ] {
        let storage = plain(2);
        let (disk, control) = over(&media(MEDIA));
        let mut volume = attach(&storage, &arena, disk);
        assert_eq!(run(&mut volume, &control), MetadataOutcome::Unformatted);
        let refused = MetadataOutcome::EntropyUnavailable;
        assert_eq!(volume.format_from(fill), Err(refused));
        assert_eq!(run(&mut volume, &control), refused);
        assert!(writes(&control).is_empty());
        assert_eq!(volume.format(), Err(refused));
        assert!(storage.is_closed());
    }
}

/// Ticks `volume` until `control` captured a write at device byte `start`, holds it, and returns its token.
fn hold_write_at(
    volume: &mut TestVolume<'_, '_>,
    control: &SimControl,
    start: u64,
) -> CommandToken {
    for _ in 0..32 {
        let _ = volume.poll_storage(0, &mut Vec::with_capacity(16));
        if let Some(&(token, _)) = submitted(control, Operation::Write)
            .iter()
            .find(|&&(_, at)| at == start)
        {
            control.hold(token);
            return token;
        }
        control.tick(64);
    }
    panic!("no write at {start}\n{}", control.describe());
}

/// A close during a held probe read or a held RESET write ends the bootstrap and closes admission; the outcome stays `Bootstrapping`, slot B is never written, and nothing more is submitted.
#[test]
fn a_close_ends_the_bootstrap_during_a_probe_or_a_reset_write() {
    // The probe read of slot A, held, then stopped.
    let arena = arena();
    let storage = plain(2);
    let (disk, control) = over(&media(MEDIA));
    let mut volume = attach(&storage, &arena, disk);
    let _ = volume.poll_storage(0, &mut Vec::with_capacity(16));
    let [(read, 0)] = submitted(&control, Operation::Read)[..] else {
        panic!("slot A's read")
    };
    control.hold(read);
    control.set_quiesce(super::super::device::sim::QuiesceMode::Reset);
    let _ = volume.close();
    for _ in 0..4 {
        let _ = volume.close();
        tick(&mut volume, &control);
    }
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
    assert!(storage.is_closed());
    assert_eq!(volume.report().metadata_failed, 1);
    drop(volume);
    // RESET A's write, held, then stopped.
    let arena = arena_maintaining(1, 4096);
    let storage = plain(2);
    let store = media(MEDIA);
    let (disk, control) = over(&store);
    let mut volume = attach(&storage, &arena, disk);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Unformatted);
    volume.format().unwrap();
    hold_write_at(&mut volume, &control, 0);
    control.set_quiesce(super::super::device::sim::QuiesceMode::Reset);
    for _ in 0..4 {
        let _ = volume.close();
        tick(&mut volume, &control);
    }
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
    assert!(storage.is_closed(), "a stopped bootstrap closes admission");
    assert_eq!(volume.report().metadata_failed, 1);
    assert_eq!(writes(&control), [0], "slot B is never written");
    assert_eq!(generations(&store), [None, None]);
}

/// A submit the device refuses for good ends the bootstrap: a refused probe read as `SlotUnreadable`, a refused RESET write as `MetadataFailed`, each closing admission.
#[test]
fn a_metadata_submit_refused_for_good_ends_the_bootstrap_and_closes_admission() {
    let invalid = SubmitRefusal {
        reason: RefusalReason::InvalidRange,
        code: None,
    };
    let arena = arena();
    let storage = plain(2);
    let (disk, control) = over(&media(MEDIA));
    let mut volume = attach(&storage, &arena, disk);
    control.refuse_next(invalid);
    assert_eq!(
        run(&mut volume, &control),
        MetadataOutcome::SlotUnreadable { slot: Slot::A }
    );
    assert!(storage.is_closed());
    let storage = plain(2);
    let (disk, control) = over(&media(MEDIA));
    let mut volume = attach(&storage, &arena, disk);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Unformatted);
    control.refuse_next(invalid);
    volume.format().unwrap();
    assert_eq!(run(&mut volume, &control), MetadataOutcome::MetadataFailed);
    assert!(storage.is_closed());
    assert!(writes(&control).is_empty());
}

#[test]
fn a_metadata_submit_refused_device_gone_loses_the_volume_and_keeps_the_outcome() {
    let gone = SubmitRefusal {
        reason: RefusalReason::DeviceGone,
        code: None,
    };
    let arena = arena();
    let storage = plain(2);
    let (disk, control) = over(&media(MEDIA));
    let mut volume = attach(&storage, &arena, disk);
    control.refuse_next(gone);
    tick(&mut volume, &control);
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
    assert!(volume.is_lost());
    assert!(storage.is_closed());
    tick(&mut volume, &control);
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
    assert_eq!(volume.report().metadata_submitted, 0);
}

/// Once slot A's RESET root persisted, a full device queue refusing slot B's write leaves it staged, and the next tick with no read and no terminal resubmits it.
#[test]
fn a_full_queue_at_the_second_reset_write_resubmits_on_a_quiet_tick() {
    let storage = plain(2);
    let arena = arena();
    let (disk, control) = over(&media(MEDIA));
    let mut volume = attach(&storage, &arena, disk);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Unformatted);
    volume.format().unwrap();
    let mut out = Vec::with_capacity(16);
    for _ in 0..16 {
        if !writes(&control).is_empty() {
            break;
        }
        let _ = volume.poll_storage(0, &mut out);
    }
    assert_eq!(writes(&control), [0]);
    control.refuse_next(SubmitRefusal {
        reason: RefusalReason::QueueFull,
        code: None,
    });
    control.tick(64);
    let _ = volume.poll_storage(0, &mut out);
    assert_eq!(
        volume.report().metadata_refused,
        1,
        "slot B's write met the full queue"
    );
    let report = volume.poll_storage(0, &mut out);
    assert_eq!((report.submitted, report.terminals), (1, 0));
    assert_eq!(writes(&control), [0, 4096]);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Open);
}

/// With slot A's magic damaged and the unit changed, the new layout's slot B lands in another block and decodes invalid, so the bootstrap waits unformatted and a format writes a new format ID; the old slot B's root is never read as a root.
#[test]
fn a_changed_unit_over_a_corrupt_slot_a_waits_for_a_format_under_a_new_id() {
    let store = media(MEDIA);
    place(
        &store,
        LAYOUT,
        FORMAT,
        &Root::reset(
            4,
            crate::storage::TEST_CLOCK.encode(),
            crate::storage::TEST_FEED.encode(),
        ),
        Slot::A,
    );
    place(
        &store,
        LAYOUT,
        FORMAT,
        &Root::reset(
            4,
            crate::storage::TEST_CLOCK.encode(),
            crate::storage::TEST_FEED.encode(),
        ),
        Slot::B,
    );
    store.borrow_mut()[0] ^= 0xFF;
    let fields = Fields {
        awupf: 15,
        nsfeat: 0,
        vendor: None,
        limits: TransferLimits {
            namespace_max: BUFFER,
            boundary: 0,
            command: BUFFER,
        },
        ..EBS
    };
    let storage = storage_changed(2, |volume| {
        volume.raw_bytes += 16 * IO_UNIT;
        volume.metadata_units = 32;
    })
    .expect("valid");
    let arena = arena_maintaining(1, 8192);
    let (disk, control) = sim_attached(CONFIG, Rc::clone(&store), facts_sized(fields, MEDIA / 512));
    let expected = crate::storage::upcoming_session();
    let mut volume = attach(&storage, &arena, disk);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Unformatted);
    volume.format().expect("both slots decode invalid");
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Open);
    let issued = volume.session();
    let wide = Layout {
        unit: 8192,
        metadata_units: 32,
    };
    let media = store.borrow();
    let (format, root) =
        decode(Crc32c::detect(), wide, &media[..8192], Slot::A).expect("formatted");
    assert_ne!(format, FORMAT);
    assert_eq!(
        root,
        Root::reset(
            issued,
            crate::storage::TEST_CLOCK.encode(),
            crate::storage::TEST_FEED.encode()
        )
    );
    assert_eq!(issued, expected, "the format writes the tenure's session");
}

/// A volume lost while its bootstrap waits for a format ends the bootstrap at its next tick, though nothing else runs there, and closes admission.
#[test]
fn a_volume_lost_during_the_bootstrap_closes_admission_at_its_next_tick() {
    let arena = arena();
    let storage = plain(2);
    let (disk, control) = over(&media(MEDIA));
    let mut volume = attach(&storage, &arena, disk);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Unformatted);
    control.set_gone();
    let record = super::volume_tests::record(0, 0, 100, 1, 7);
    assert!(volume.read_raw(&record.read, u64::MAX).is_err());
    let buffer = arena
        .acquire(crate::storage::PoolKind::ReadResponse)
        .unwrap();
    assert!(
        volume
            .table
            .submit_read(buffer, crate::storage::DeviceRange::new(0, 4096).unwrap())
            .is_err()
    );
    assert!(volume.is_lost());
    assert!(!storage.is_closed());
    let _ = volume.poll_storage(0, &mut Vec::with_capacity(16));
    assert!(
        storage.is_closed(),
        "the lost volume's bootstrap closed admission"
    );
    assert_eq!(volume.format(), Err(MetadataOutcome::Unformatted));
    assert!(writes(&control).is_empty());
}

/// A RESET write that persists after its volume closed leaves the bootstrap ended: the outcome stays `Bootstrapping` and admission stays closed, though both slots now hold the RESET root.
#[test]
fn a_reset_write_persisting_after_a_close_leaves_the_bootstrap_ended() {
    let arena = arena_maintaining(1, 4096);
    let storage = plain(2);
    let store = media(MEDIA);
    let (disk, control) = over(&store);
    let mut volume = attach(&storage, &arena, disk);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Unformatted);
    volume.format_from(fixture_format).unwrap();
    let second = hold_write_at(&mut volume, &control, 4096);
    control.set_quiesce(super::super::device::sim::QuiesceMode::AllReturned);
    let _ = volume.close();
    assert!(storage.is_closed());
    control.release(second);
    for _ in 0..4 {
        let _ = volume.close();
        tick(&mut volume, &control);
    }
    let [Some(a), Some(b)] = generations(&store) else {
        panic!("both slots hold the RESET root")
    };
    assert_eq!((a, a >> 32), (b, 1));
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
    assert_eq!(
        volume.report().metadata_done,
        4,
        "two probes and two writes"
    );
    assert_eq!(volume.session(), 0);
}

/// A RESET write held by a dropped volume that lands after the next attach persisted its first RESET write lowers that one slot, so the attach after them still writes its session above every generation either attach carried.
#[test]
fn a_late_reset_write_from_a_dropped_volume_keeps_the_next_session_above_every_generation() {
    let store = media(MEDIA);
    place(
        &store,
        LAYOUT,
        FORMAT,
        &Root::reset(
            5,
            crate::storage::TEST_CLOCK.encode(),
            crate::storage::TEST_FEED.encode(),
        ),
        Slot::A,
    );
    place(
        &store,
        LAYOUT,
        FORMAT,
        &Root::reset(
            4,
            crate::storage::TEST_CLOCK.encode(),
            crate::storage::TEST_FEED.encode(),
        ),
        Slot::B,
    );
    let (old_arena, old_storage) = (arena(), plain(2));
    let (disk, old) = over(&store);
    let first = crate::storage::upcoming_session();
    let mut volume = attach(&old_storage, &old_arena, disk);
    let late = hold_write_at(&mut volume, &old, 0);
    drop(volume);
    let [Some(5), Some(dropped)] = generations(&store) else {
        panic!("the dropped volume's first RESET write landed on B")
    };
    assert_eq!(
        dropped, first,
        "the dropped volume wrote its tenure's session"
    );
    let (arena, storage) = (arena(), plain(2));
    let (disk, control) = over(&store);
    let expected = crate::storage::upcoming_session();
    let mut volume = attach(&storage, &arena, disk);
    let second = hold_write_at(&mut volume, &control, 4096);
    let [Some(next), Some(b)] = generations(&store) else {
        panic!("the next attach's first RESET write landed on A")
    };
    assert_eq!(
        next, expected,
        "the next attach writes its tenure's session"
    );
    assert!(next > dropped && b == dropped);
    old.release(late);
    old.tick(64);
    assert_eq!(
        generations(&store),
        [Some(dropped), Some(dropped)],
        "the late write lands"
    );
    control.release(second);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Open);
    assert_eq!(volume.session(), next);
    assert_eq!(generations(&store), [Some(dropped), Some(next)]);
    drop(volume);
    assert!(storage_and_open(&arena_maintaining(1, 4096), &store) > next);
}

/// A held RESET write retains the arena's sole maintenance buffer after the volume drops, so reattaching with that arena returns `MaintenanceShort { buffers: 0, buffer_len: 4096 }` before any device command; attaching with a fresh arena succeeds.
#[test]
fn attach_refuses_an_arena_whose_maintenance_buffer_a_dropped_volume_still_holds() {
    let arena = arena();
    let store = media(MEDIA);
    let clock = crate::storage::TEST_CLOCK.encode();
    let feed = crate::storage::TEST_FEED.encode();
    place(
        &store,
        LAYOUT,
        FORMAT,
        &Root::reset(5, clock, feed),
        Slot::A,
    );
    place(
        &store,
        LAYOUT,
        FORMAT,
        &Root::reset(4, clock, feed),
        Slot::B,
    );
    let old_storage = plain(2);
    let (disk, old) = over(&store);
    let mut volume = attach(&old_storage, &arena, disk);
    let _held = hold_write_at(&mut volume, &old, 0);
    drop(volume);
    let storage = plain(2);
    let (disk, control) = over(&store);
    let refused = Volume::attach(
        &storage,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
        &mut EngineBudget::new(1 << 24),
    )
    .err()
    .map(|(error, _)| error);
    assert_eq!(
        refused,
        Some(AttachError::MaintenanceShort {
            buffers: 0,
            buffer_len: 4096
        })
    );
    assert_eq!(control.driver_calls(), 0);
    let held = generations(&store)[1].expect("the dropped volume's first RESET write landed on B");
    assert!(storage_and_open(&arena_maintaining(1, 4096), &store) > held);
}
