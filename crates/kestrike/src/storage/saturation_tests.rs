//! Recovery history under full resources and stalled dependencies: an indefinite store outage, unresolved Publishes,
//! a capture side list at its cap, a suffix writer that stops, failed tenures that fill the ancestry, and the recovery
//! I/O share. Each test checks its bound against the state at every step. The outage, unresolved-Publish, side-list,
//! ancestry and slot-share tests then recover the named checkpoint from the store record and the prefix image, so a
//! bound that held by discarding retained entries fails the recovery; the suffix queue and suffix drain tests check
//! the log's own state and recover nothing.

use super::*;
use crate::failover::records::MAX_CHAIN;
use crate::failover::report::{Gauge, Pressure};
use crate::storage::recovery::checkpoint_tests::canonical;
use crate::storage::recovery::delta::{Packer, UNIT_LEN as BLOCK_LEN};
use crate::storage::recovery::io_share::{HostShare, IoShare, RESERVE};
use crate::storage::recovery::suffix::{SuffixLimits, SuffixLog, SuffixRefusal};
use crate::storage::recovery::suffix_tests::take;
use crate::storage::recovery::{CaptureError, reusable};
use crate::storage::volume::PlacementRefusal;

/// The message `run` panics with, or `None` when it returns.
fn panic_message(run: impl FnOnce()) -> Option<String> {
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).err()?;
    Some(match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => payload
            .downcast::<&str>()
            .map_or_else(|_| String::new(), |message| (*message).to_owned()),
    })
}

/// Whether `run` panics with the checkpoint module's `plant` set and a message containing `expected`, the assertion
/// the plant must fail; the plant is cleared either way.
fn fails_under(plant: Plant, expected: &str, run: impl FnOnce()) -> bool {
    PLANT.with(|cell| cell.set(Some(plant)));
    let message = panic_message(run);
    PLANT.with(|cell| cell.set(None));
    message.is_some_and(|message| message.contains(expected))
}

/// Whether `run` panics with the flag `plant` set and a message containing `expected`, the assertion the plant must
/// fail; the flag is cleared either way.
fn fails_with(
    plant: &'static std::thread::LocalKey<std::cell::Cell<bool>>,
    expected: &str,
    run: impl FnOnce(),
) -> bool {
    plant.with(|cell| cell.set(true));
    let message = panic_message(run);
    plant.with(|cell| cell.set(false));
    message.is_some_and(|message| message.contains(expected))
}

/// The delta blocks of [`wide`].
const REGION: u64 = 16;

/// Three four-unit slots and a delta region of [`REGION`] blocks.
fn wide() -> Layout {
    let layout = layout(4);
    Layout {
        units: layout.units + REGION,
        ..layout
    }
}

fn image(layout: &Layout) -> Vec<u8> {
    vec![0; layout.units as usize * IO_UNIT]
}

fn commits(store: &Shared) -> usize {
    store.0.borrow().commit_count(&Key::Shard(shard()))
}

/// The refusal of a stage of capture `capture` for 50 entries, which must reserve nothing.
fn stage_refusal(possible: &mut PossiblyNamed, capture: u32) -> StageRefusal {
    let checkpoint = Checkpoint {
        shard: shard(),
        session: SESSION,
        capture,
    };
    StagedCheckpoint::new(
        Crc32c::detect(),
        possible,
        (checkpoint, &entries(50)),
        &EngineBudget::unlimited(),
    )
    .map(|stage| stage.slot())
    .expect_err("no slot is free")
}

const NO_SLOT: StageRefusal =
    StageRefusal::Reserve(ReserveRefusal::Placement(PlacementRefusal::NoFreeSlot));

fn known(used: u64, limit: u64) -> Gauge {
    Gauge::known(used, limit)
}

/// Load limits with room for the 50 checkpoint entries of `landed` and the suffix inserts of [`fresh`].
fn recovery_limits() -> LoadLimits {
    let mut limits = load_limits(50);
    limits.slot_count = 400;
    (limits.payload_end, limits.n_max) = (8 * 400, 400);
    limits
}

/// A suffix insert of a fresh key, slot and unit past the 50 checkpoint entries.
fn fresh(serial: usize) -> CaptureEntry {
    entry(100 + serial, 3, 8 * (100 + serial) as u64)
}

/// Writes `bytes` of suffix block `lsn` into the prefix image at its delta unit.
fn land_block(layout: &Layout, image: &mut [u8], lsn: u64, bytes: &[u8; BLOCK_LEN]) {
    let region = crate::storage::recovery::delta::blocks(layout);
    let at = (layout.units - region + lsn % region) as usize * IO_UNIT;
    image[at..at + IO_UNIT].copy_from_slice(bytes);
}

/// The load of the checkpoint, cut and ancestry the store's record names over the prefix image `bytes`, read by a
/// reader of session `reader`.
fn recovered_with_suffix(store: &Shared, layout: &Layout, bytes: &[u8], reader: u64) -> SlotLoad {
    let record = stored(store).1;
    let named = record.checkpoint.expect("the record names a checkpoint");
    let mut reader = SlotReader::new(
        Crc32c::detect(),
        layout,
        shard(),
        (named, record.cut, record.ancestry.as_slice()),
        reader,
        (recovery_limits(), &EngineBudget::unlimited()),
        routing(4),
    )
    .unwrap();
    drive(&mut reader, bytes, |_| 0);
    reader.load()
}

/// A store that answers nothing for 64 rounds while the device keeps writing: every read returns no value, each
/// Publish and suffix extension ends unknown, and no write commits. The two unnamed slots fill with the unknown
/// Publishes and stay possibly named, the set holds at most one pending write per slot and one naming no checkpoint
/// however many writes end unknown, the third capture refuses before any unit, the suffix log acknowledges no
/// record at or past its recorded end, and the store record and the named slot's bytes stay as the outage found
/// them. The recovery reads the record's checkpoint and suffix from the medium and loads every checkpoint entry and
/// every acknowledged insert. Losing one written suffix block fails the load comparison, and the `AbandonUnknown`
/// plant, an unknown Publish treated as refused before sending, drops its slot from the set and fails the
/// `contains` check of round 0.
#[test]
fn an_indefinite_store_outage_refuses_new_history_and_keeps_the_named_checkpoint() {
    let run = |lose: Option<u64>| -> Result<(), String> {
        let layout = wide();
        let store = seeded();
        let mut host = client(&store);
        let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
        let mut bytes = image(&layout);
        let (first, entries, published) = published_image(
            (&store, None),
            &mut host,
            &mut possible,
            &layout,
            &mut bytes,
            1,
        );
        assert_eq!(published, Ok(()));
        let current = read(&mut host);
        let recorded = suffix(SESSION, 0, 0, 4);
        let current =
            reserve_suffix(&mut host, &mut possible, (&current, own()), recorded).unwrap();
        let floor = settled_floor(&possible, current.value()).expect("the publish settled the set");
        let mut log = SuffixLog::default();
        let limits = SuffixLimits {
            flush_ns: 100,
            queue_blocks: 4,
            oldest_ns: 1_000,
            uncertified: 1 << 40,
        };
        assert!(log.open(
            (Crc32c::detect(), shard()),
            (limits, &layout),
            recorded,
            floor
        ));
        let before = (stored(&store), commits(&store));
        let named_bytes = bytes.clone();
        let (mut unknown, mut acknowledged, mut refused) = (Vec::new(), Vec::new(), 0);
        let drain = |log: &mut SuffixLog, bytes: &mut Vec<u8>| {
            while let Some((lsn, block)) = take(log).map(|(lsn, block)| (lsn, *block)) {
                if lose != Some(lsn) {
                    land_block(&layout, bytes, lsn, &block);
                }
                log.written(lsn);
            }
        };
        for round in 0..64u32 {
            store.schedule(Arm::Unavailable);
            assert_eq!(
                host.read::<ShardRecord>(Key::Shard(shard())).map(|_| ()),
                Err(StoreError::Unavailable)
            );
            if possible.free_slot().is_some() {
                let (mut stage, _) = landed(&mut possible, &layout, &mut bytes, 2 + round);
                store.schedule(Arm::Unavailable);
                let outcome = publish(
                    &mut host,
                    &mut possible,
                    &current,
                    (own(), Some(first)),
                    (&cut(stage.named().capture), CaptureEpoch::default()),
                    &mut stage,
                );
                assert_eq!(
                    outcome.map(|_| ()),
                    Err(WriteRefused::Store(StoreError::Unknown))
                );
                unknown.push(stage.slot());
            } else {
                assert_eq!(stage_refusal(&mut possible, 2 + round), NO_SLOT);
            }
            store.schedule(Arm::Unavailable);
            let extension = suffix(SESSION, 0, 0, 5 + u64::from(round % 8));
            assert_eq!(
                reserve_suffix(&mut host, &mut possible, (&current, own()), extension).map(|_| ()),
                Err(WriteRefused::Store(StoreError::Unknown)),
                "the extension's outcome is unknown, so the log's reserved end stays"
            );
            // The device still writes: the log drains, and only the recorded end bounds it.
            let now = u64::from(round) * 50;
            log.flush_due(now);
            drain(&mut log, &mut bytes);
            let state = format!("{log:?}");
            let insert = fresh(round as usize);
            match log.append(now, &Record::Insert(insert.clone())) {
                Ok(position) => {
                    acknowledged.push(insert);
                    assert!(position >> 32 < recorded.end, "round {round}");
                }
                Err(refusal) => {
                    refused += 1;
                    assert_eq!(refusal, SuffixRefusal::Reserved, "round {round}");
                    assert_eq!(format!("{log:?}"), state, "a refusal changes nothing");
                }
            }
            assert_eq!((stored(&store), commits(&store)), before, "round {round}");
            assert!(
                possible.pending_count() <= layout.slots as usize + 1,
                "round {round}: {} pending writes pass one per slot and one naming no checkpoint",
                possible.pending_count()
            );
            assert!(possible.contains(first.slot), "round {round}");
            assert!(
                unknown.iter().all(|&slot| possible.contains(slot)),
                "round {round}: an unknown Publish keeps its slot possibly named"
            );
            assert!(possible.quarantined().is_empty(), "round {round}");
            assert!(log.head() <= recorded.end, "round {round}");
        }
        log.seal_cut();
        drain(&mut log, &mut bytes);
        assert_eq!(unknown.len(), 2, "the outage filled both unnamed slots");
        assert!(
            acknowledged.len() > 1 && refused > 0,
            "{} {refused}",
            acknowledged.len()
        );
        let slot = |slot: u32| {
            let start = (1 + slot as usize * layout.slot_units as usize) * IO_UNIT;
            start..start + layout.slot_units as usize * IO_UNIT
        };
        assert!(
            bytes[slot(first.slot)] == named_bytes[slot(first.slot)],
            "no capture of the outage wrote the named slot"
        );
        drop(host);
        let load = recovered_with_suffix(&store, &layout, &bytes, SESSION);
        let expected =
            GuardedLoad::Warm(canonical(entries.into_iter().chain(acknowledged).collect()));
        (load.load() == expected).then_some(()).ok_or_else(|| {
            "the load differs from the checkpoint and every acknowledged insert".into()
        })
    };
    assert_eq!(run(None), Ok(()));
    assert_eq!(
        run(Some(0)),
        Err("the load differs from the checkpoint and every acknowledged insert".into()),
        "control: a lost suffix block"
    );
    assert!(
        fails_under(
            Plant::AbandonUnknown,
            "an unknown Publish keeps its slot possibly named",
            || drop(run(None))
        ),
        "control: an unknown Publish abandoned as refused before sending"
    );
}

/// Two Publishes whose replies never arrive hold the two unnamed slots for as long as the tenure runs: each of 1,000
/// later attempts finds no free slot, a capture start given the set's free-slot answer refuses before its pass, no
/// floor is settled, and the store record stays as the held Publishes found it. The first held Publish then commits, and the recovery loads its checkpoint whole from the slot the
/// set kept. Placement over the named slot alone would have given that slot to the next capture.
#[test]
fn unresolved_publishes_hold_their_slots_however_long_they_stay_unresolved() {
    let layout = wide();
    let store = seeded();
    let mut host = client(&store);
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
    let mut bytes = image(&layout);
    let (first, _, published) = published_image(
        (&store, None),
        &mut host,
        &mut possible,
        &layout,
        &mut bytes,
        1,
    );
    assert_eq!(published, Ok(()));
    let mut held = Vec::new();
    for capture in [2, 3] {
        let (ck, entries, outcome) = published_image(
            (&store, Some(Arm::Hold)),
            &mut host,
            &mut possible,
            &layout,
            &mut bytes,
            capture,
        );
        assert_eq!(outcome, Err(WriteRefused::Store(StoreError::Unknown)));
        held.push((ck, entries));
    }
    assert_eq!(
        crate::storage::volume::place(&layout, &[first.slot], 50),
        Ok(held[0].0.slot),
        "control: placement over the named slot alone reuses an unresolved Publish's slot"
    );
    let before = (stored(&store), bytes.clone());
    for attempt in 0..1_000u32 {
        assert_eq!(possible.free_slot(), None, "attempt {attempt}");
        assert_eq!(stage_refusal(&mut possible, 4 + attempt), NO_SLOT);
        let mut capture = Capture::default();
        let cap = SideCap {
            entries: 4,
            words: 4,
        };
        assert_eq!(
            capture.start(
                (1, CaptureEpoch::default()),
                4,
                0,
                4,
                possible.free_slot().is_some(),
                cap
            ),
            Err(CaptureError::NoFreeCheckpointSlot)
        );
        let current = read(&mut host);
        assert_eq!(settled_floor(&possible, current.value()), None);
        assert_eq!(
            possible.slots(),
            [first.slot, held[0].0.slot, held[1].0.slot]
        );
        assert!(possible.quarantined().is_empty());
    }
    assert!((stored(&store), bytes.clone()) == before);
    drop(host);
    assert_eq!(
        store.release().len(),
        2,
        "both held Publishes reach the store after the tenure"
    );
    let (named, load) = recovered(&store, &layout, &bytes);
    let (second, entries) = held.swap_remove(0);
    assert_eq!(
        named,
        Some(second),
        "the first held Publish committed over the version it read"
    );
    assert_eq!(load, GuardedLoad::Warm(entries));
}

/// A pass whose side list holds one entry abandons at the second saved removal: every progress call and the proof
/// refuse `Abandoned`, the side list holds its one entry, no stage reserves a slot, and the store record and the
/// prefix image stay as the earlier pass published them, so the recovery loads that pass's whole cut. A side list
/// that grew past its cap, the `NO_SIDE_CAP` plant, lets the pass complete and fails the `Abandoned` checks.
#[test]
fn a_side_list_at_its_cap_abandons_the_pass_and_keeps_the_named_checkpoint() {
    a_side_list_at_its_cap_abandons_the_pass_and_keeps_the_named_checkpoint_case();
    assert!(
        fails_with(
            &crate::storage::recovery::NO_SIDE_CAP,
            "a removal past the side-list cap abandons the pass",
            a_side_list_at_its_cap_abandons_the_pass_and_keeps_the_named_checkpoint_case
        ),
        "control: a side list with no cap"
    );
}

fn a_side_list_at_its_cap_abandons_the_pass_and_keeps_the_named_checkpoint_case() {
    use crate::storage::publish_tests::{TRIES, budget, index_config, key, storage};
    let layout = wide();
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let members: Vec<_> = (1..=3)
        .map(|n| {
            let (bound, _) = observed_completed(&s, key(n));
            bound.publish(TRIES, &mut budget()).unwrap()
        })
        .collect();
    let counter = s.start_capture(4, true, 4).unwrap();
    let mut captured = drain(&s);
    captured.sort_by_key(CaptureEntry::slot);
    // The tenure's reader admits only its own generation's sessions, which the test storage's do not share.
    for entry in &mut captured {
        entry.session = SESSION;
    }
    assert_eq!(captured.len(), 3);
    let store = seeded();
    let mut host = client(&store);
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
    let mut bytes = image(&layout);
    let checkpoint = Checkpoint {
        shard: shard(),
        session: SESSION,
        capture: counter,
    };
    let mut stage = StagedCheckpoint::new(
        Crc32c::detect(),
        &mut possible,
        (checkpoint, &captured),
        &EngineBudget::unlimited(),
    )
    .unwrap();
    land(&layout, &mut stage, &mut bytes);
    let current = read(&mut host);
    let proof = s.cut_intact((shard(), SESSION), counter).unwrap();
    publish(
        &mut host,
        &mut possible,
        &current,
        (own(), None),
        (&proof, s.capture_epoch()),
        &mut stage,
    )
    .unwrap();
    drop(s.pool().capture_lock().unwrap().finish());
    // The proof made the tenure's history required, so the log opens and the clock reads before the removals below
    // record in it.
    s.platform.ticks(&[Some(1)]);
    let limits = SuffixLimits {
        flush_ns: 1 << 40,
        queue_blocks: 4,
        oldest_ns: 1 << 41,
        uncertified: 1 << 40,
    };
    let opened = s.with_suffix(|log| {
        log.open(
            (Crc32c::detect(), shard()),
            (limits, &layout),
            suffix(SESSION, 0, 0, REGION),
            0,
        )
    });
    assert_eq!(opened, Ok(true));
    let named = stage.named();
    let before = (stored(&store), commits(&store), bytes.clone());

    let counter = s.start_capture(4, true, 1).unwrap();
    s.remove(&key(1), members[0], TRIES, &mut budget()).unwrap();
    assert_eq!(s.capture_side_len(counter), Ok(1), "the side list is full");
    s.remove(&key(2), members[1], TRIES, &mut budget()).unwrap();
    assert_eq!(
        s.capture_visit(counter, 4, |_| {}),
        Err(CaptureError::Abandoned),
        "a removal past the side-list cap abandons the pass"
    );
    assert_eq!(s.capture_saved(counter), Err(CaptureError::Abandoned));
    assert_eq!(s.capture_side_len(counter), Err(CaptureError::Abandoned));
    assert_eq!(
        s.submit_capture_unit(counter, || ()),
        Err(CaptureError::Abandoned)
    );
    assert_eq!(
        s.cut_intact((shard(), SESSION), counter).map(|_| ()),
        Err(CaptureError::Abandoned),
        "an abandoned pass mints no proof, so no Publish names its cut"
    );
    let saved = s.pool().capture_lock().unwrap().finish();
    assert_eq!(saved.len(), 1, "the side list never passed its cap");
    assert_eq!(possible.slots(), [named.slot]);
    assert!(possible.quarantined().is_empty());
    assert!(possible.free_slot().is_some(), "no stage took a slot");
    assert!((stored(&store), commits(&store), bytes.clone()) == before);
    drop(host);
    let (recovered_named, load) = recovered(&store, &layout, &bytes);
    assert_eq!(recovered_named, Some(named));
    assert_eq!(load, GuardedLoad::Warm(captured));
}

/// A suffix writer that stops: the device completes no block for 5,000 steps while appends keep arriving. At every
/// step the blocks awaiting durability, the open block included, are at most `queue_blocks`, every
/// acknowledged append lies within `oldest_ns` of the oldest record still unflushed, and every refusal is `Queue` or
/// `Stalled` and leaves the log unchanged. A write that fails 100 times offers the same bytes each time. Once the
/// device writes again the queue drains in LSN order, every acknowledged record's block is durable, and appends are
/// admitted. The `NO_QUEUE` plant, an append with no queue check, fails the block bound at the first step past the
/// cap.
#[test]
fn the_suffix_queue_and_age_caps_hold_at_every_step_of_a_stalled_writer() {
    the_suffix_queue_and_age_caps_hold_at_every_step_of_a_stalled_writer_case();
    assert!(
        fails_with(
            &crate::storage::recovery::suffix::NO_QUEUE,
            "the blocks awaiting durability pass the queue bound",
            the_suffix_queue_and_age_caps_hold_at_every_step_of_a_stalled_writer_case
        ),
        "control: an append with no queue check"
    );
}

fn the_suffix_queue_and_age_caps_hold_at_every_step_of_a_stalled_writer_case() {
    let layout = wide();
    // A stalled clock with wide records reaches the queue bound; small records under a long flush interval reach
    // the age bound first.
    for (stride, extents, bound) in [
        (7, 1, SuffixRefusal::Stalled),
        (0, 200, SuffixRefusal::Queue),
    ] {
        let limits = SuffixLimits {
            flush_ns: 300,
            queue_blocks: 4,
            oldest_ns: 400,
            uncertified: 1 << 40,
        };
        let mut log = SuffixLog::default();
        assert!(log.open(
            (Crc32c::detect(), shard()),
            (limits, &layout),
            suffix(SESSION, 0, 0, REGION),
            0
        ));
        let (mut positions, mut oldest, mut last, mut refusals) = (Vec::new(), None, 0, Vec::new());
        let mut now = 0;
        for step in 0..5_000usize {
            now += stride;
            log.flush_due(now);
            let record = Record::Insert(CaptureEntry {
                extents: (0..extents)
                    .map(|at| ExtentLocator::new(8 * at, 1).unwrap().bits())
                    .collect(),
                ..entry(step, 2, 0)
            });
            let state = format!("{log:?}");
            match log.append(now, &record) {
                Ok(position) => {
                    let first = *oldest.get_or_insert(now);
                    assert!(now - first <= limits.oldest_ns, "step {step}");
                    positions.push(position);
                    last = step;
                }
                Err(refusal) => {
                    assert_eq!(format!("{log:?}"), state, "step {step}: {refusal:?}");
                    refusals.push(refusal);
                }
            }
            assert!(
                log.queued().0 <= limits.queue_blocks,
                "step {step}: the blocks awaiting durability pass the queue bound"
            );
            assert_eq!(log.durable(), 0, "the writer completed nothing");
        }
        assert!(!positions.is_empty() && last < 4_000, "{last}");
        assert!(
            refusals
                .iter()
                .all(|r| matches!(r, SuffixRefusal::Queue | SuffixRefusal::Stalled)),
            "{refusals:?}"
        );
        assert_eq!(refusals.last(), Some(&bound));
        log.seal_cut();
        let (lsn, bytes) = take(&mut log).map(|(lsn, bytes)| (lsn, *bytes)).unwrap();
        for _ in 0..100 {
            log.failed(lsn);
            let again = take(&mut log).map(|(lsn, bytes)| (lsn, *bytes)).unwrap();
            assert_eq!(again.0, lsn);
            assert!(again.1 == bytes, "a retry carries the retained bytes");
        }
        log.written(lsn);
        let mut next = lsn + 1;
        while let Some((lsn, _)) = take(&mut log) {
            assert_eq!(lsn, next, "blocks drain in LSN order");
            log.written(lsn);
            next += 1;
        }
        assert_eq!(log.durable(), log.head());
        assert!(
            positions
                .iter()
                .all(|&position| reusable(0, position, log.durable(), false)),
            "every acknowledged record's last block is durable"
        );
        log.append(now + 1, &Record::Insert(entry(5_000, 2, 0)))
            .expect("the drained log admits appends");
    }
}

/// Tenures that each record a suffix, write two inserts and then fail fill the ancestry to `MAX_CHAIN`. The next
/// tenure's takeover bump still commits and keeps the chain, and it recovers the checkpoint and every insert of the
/// four suffixes, while the same image with the oldest tenure's first block lost recovers less; its own suffix
/// refuses `Chain` before any request on each of 100 attempts, its log stays closed and acknowledges nothing, and the
/// report reads the ancestry full. A further failed tenure changes nothing. A settled Publish at the chain's end then
/// drops the suffixes its cut covers and the suffix is admitted. The `ChainDropsOldest` plant, a chain rewrite that
/// drops the oldest suffix to make room, reaches the store and fails the `Chain` check.
#[test]
fn failed_tenures_fill_the_ancestry_and_the_next_suffix_refuses_before_any_write() {
    let case = failed_tenures_fill_the_ancestry_and_the_next_suffix_refuses_before_any_write_case;
    assert!(
        case(),
        "control: a lost suffix block of the oldest tenure fails the whole-history comparison"
    );
    assert!(
        fails_under(
            Plant::ChainDropsOldest,
            "a full chain refuses before any request",
            || _ = case()
        ),
        "control: a chain rewrite that drops its oldest suffix"
    );
}

/// Runs the ancestry case and returns whether the image with the oldest tenure's first suffix block lost recovers
/// other than the whole history.
fn failed_tenures_fill_the_ancestry_and_the_next_suffix_refuses_before_any_write_case() -> bool {
    let layout = wide();
    let store = seeded();
    let session = |attempts: u32| (3 << 32) | (2 * u64::from(attempts));
    let mut bytes = image(&layout);
    let (_, mut expected, published) = published_image(
        (&store, None),
        &mut client(&store),
        &mut PossiblyNamed::new((shard(), SESSION), layout, None),
        &layout,
        &mut bytes,
        1,
    );
    assert_eq!(published, Ok(()));
    // The same image with the first tenure's first suffix block lost, for the recovery's control.
    let mut lost = bytes.clone();
    let mut chain = Vec::new();
    for attempts in 1..=MAX_CHAIN as u32 {
        let mut host = client(&store);
        let mut possible = PossiblyNamed::new((shard(), session(attempts)), layout, None);
        let own = Target { attempts, ..own() };
        let current = read(&mut host);
        let start = suffix_start(current.value());
        let own_suffix = suffix(session(attempts), start, start, start + 3);
        reserve_suffix(&mut host, &mut possible, (&current, own), own_suffix).unwrap();
        chain.push(own_suffix);
        // The tenure appends two inserts, which reach the medium before it fails.
        let limits = SuffixLimits {
            flush_ns: 1,
            queue_blocks: 4,
            oldest_ns: 1 << 40,
            uncertified: 1 << 40,
        };
        let mut log = SuffixLog::default();
        assert!(log.open(
            (Crc32c::detect(), shard()),
            (limits, &layout),
            own_suffix,
            0
        ));
        for serial in [10 * attempts as usize, 10 * attempts as usize + 1] {
            log.append(0, &Record::Insert(fresh(serial))).unwrap();
            expected.push(fresh(serial));
        }
        log.seal_cut();
        while let Some((lsn, block)) = take(&mut log).map(|(lsn, block)| (lsn, *block)) {
            land_block(&layout, &mut bytes, lsn, &block);
            if (attempts, lsn) != (1, start) {
                land_block(&layout, &mut lost, lsn, &block);
            }
            log.written(lsn);
        }
        // The tenure fails; its successor's bump consumes the next attempt and keeps the chain.
        let current = read(&mut host);
        host.bump(&current).unwrap();
        assert_eq!(stored(&store).1.ancestry.as_slice(), &chain[..]);
    }
    let pressure = Pressure::recorded(Some(&stored(&store).1), Some(&layout), false);
    assert_eq!(
        (pressure.ancestry, pressure.frontier, pressure.full),
        (known(4, 4), known(12, REGION), known(1, 3)),
        "the report reads the ancestry at its bound"
    );
    // The next tenure recovers the checkpoint and every insert of the four failed tenures from the record it holds.
    let whole = GuardedLoad::Warm(canonical(expected.clone()));
    let load = recovered_with_suffix(&store, &layout, &bytes, session(5));
    assert!(
        load.load() == whole,
        "the history at the cap recovers whole"
    );
    let lost_differs = recovered_with_suffix(&store, &layout, &lost, session(5)).load() != whole;
    for attempts in [5u32, 6] {
        let mut host = client(&store);
        let mut possible = PossiblyNamed::new((shard(), session(attempts)), layout, None);
        let own = Target { attempts, ..own() };
        let current = read(&mut host);
        assert_eq!(current.value().attempts, attempts);
        let start = suffix_start(current.value());
        assert_eq!(start, 12);
        let before = (stored(&store), commits(&store));
        let mut log = SuffixLog::default();
        for attempt in 0..100u64 {
            let fifth = suffix(session(attempts), start, start, start + 1 + attempt % 4);
            let reserved = reserve_suffix(&mut host, &mut possible, (&current, own), fifth);
            // The log opens only over a suffix the store recorded.
            if reserved.is_ok() {
                let limits = SuffixLimits {
                    flush_ns: 1,
                    queue_blocks: 4,
                    oldest_ns: 1 << 40,
                    uncertified: 1 << 40,
                };
                log.open((Crc32c::detect(), shard()), (limits, &layout), fifth, 0);
            }
            assert_eq!(
                reserved.map(|_| ()),
                Err(WriteRefused::Chain),
                "tenure {attempts} attempt {attempt}: a full chain refuses before any request"
            );
            assert_eq!(
                log.append(attempt, &Record::Insert(entry(attempt as usize, 2, 0))),
                Err(SuffixRefusal::Closed),
                "a tenure with no recorded suffix acknowledges no mutation"
            );
            assert_eq!((stored(&store), commits(&store)), before);
        }
        assert_eq!(possible.slots(), Vec::<u32>::new());
        if attempts == 5 {
            host.bump(&current).unwrap();
            assert_eq!(stored(&store).1.ancestry.as_slice(), &chain[..]);
            continue;
        }
        let mut proof = walked_at(1);
        proof.cut_at(start);
        let ck = NamedCheckpoint {
            session: session(attempts),
            ..named(1, 1)
        };
        let mut stage = staged(&mut possible, ck);
        let intact = proof
            .intact((shard(), ck.session), CaptureEpoch::default())
            .unwrap();
        let committed = publish(
            &mut host,
            &mut possible,
            &current,
            (own, current.value().checkpoint),
            (&intact, CaptureEpoch::default()),
            &mut stage,
        )
        .unwrap();
        assert_eq!(
            (committed.value().cut, committed.value().ancestry.as_slice()),
            (start, &[][..]),
            "the cut covers every predecessor suffix"
        );
        let own_suffix = suffix(session(attempts), start, start, start + 3);
        let extended =
            reserve_suffix(&mut host, &mut possible, (&committed, own), own_suffix).unwrap();
        let pressure = Pressure::recorded(Some(extended.value()), Some(&layout), false);
        assert_eq!(
            (pressure.ancestry, pressure.frontier, pressure.full),
            (known(1, 4), known(3, REGION), known(0, 3))
        );
    }
    lost_differs
}

/// A record that would spill past a partly filled open block counts its new block against `queue_blocks`: with one
/// sealed block and a partly filled open block under a bound of two, a record that spills refuses `Queue` and leaves
/// the log unchanged, and a record that fits the open block is admitted.
#[test]
fn a_record_spilling_past_the_open_block_counts_against_the_queue_bound() {
    let limits = SuffixLimits {
        flush_ns: 1 << 40,
        queue_blocks: 2,
        oldest_ns: 1 << 41,
        uncertified: 1 << 40,
    };
    let mut log = SuffixLog::default();
    assert!(log.open(
        (Crc32c::detect(), shard()),
        (limits, &wide()),
        suffix(SESSION, 0, 0, REGION),
        0
    ));
    let small = Record::Insert(entry(0, 2, 0));
    log.append(0, &small).unwrap();
    log.seal_cut();
    log.append(0, &small).unwrap();
    let (queued, open) = log.queued();
    assert_eq!(queued, 2, "one sealed block and the open block");
    let len = |record: &Record| record.body().unwrap().1.len();
    let spilling = (1..600)
        .map(|extents| {
            Record::Insert(CaptureEntry {
                extents: (0..extents)
                    .map(|at| ExtentLocator::new(8 * at, 1).unwrap().bits())
                    .collect(),
                ..entry(1, 2, 0)
            })
        })
        .find(|record| {
            let len = len(record);
            Packer::plan(open, len).unwrap().0 == 1 && Packer::plan(0, len).unwrap().0 == 0
        })
        .expect("a record that fits a block alone and spills past the open one");
    let state = format!("{log:?}");
    assert_eq!(log.append(0, &spilling), Err(SuffixRefusal::Queue));
    assert_eq!(format!("{log:?}"), state, "the refusal changes nothing");
    assert_eq!(Packer::plan(open, len(&small)).unwrap().0, 0);
    log.append(0, &small).unwrap();
    assert_eq!(
        log.queued().0,
        2,
        "the admitted record stays in the open block"
    );
}

/// A suffix log whose blocks wait for a recovery I/O share of one block per interval: each interval offers one
/// block, a refused block stays queued with its bytes, blocks drain in LSN order, and every acknowledged record's
/// block becomes durable.
#[test]
fn suffix_blocks_drain_one_per_interval_under_the_recovery_io_share() {
    let layout = wide();
    let limits = SuffixLimits {
        flush_ns: 1,
        queue_blocks: 8,
        oldest_ns: 1 << 40,
        uncertified: 1 << 40,
    };
    let opened = || {
        let mut log = SuffixLog::default();
        assert!(log.open(
            (Crc32c::detect(), shard()),
            (limits, &layout),
            suffix(SESSION, 0, 0, REGION),
            0
        ));
        let positions: Vec<_> = (0..6)
            .map(|at| {
                let position = log.append(0, &Record::Insert(entry(at, 2, 0))).unwrap();
                log.seal_cut();
                position
            })
            .collect();
        (log, positions)
    };
    let (mut log, positions) = opened();
    // An unthrottled twin of the same appends gives each block's expected bytes.
    let (mut twin, _) = opened();
    let mut share = IoShare::of(
        HostShare {
            bytes: RESERVE,
            interval: 10,
            owners: 1,
        },
        0,
    )
    .unwrap();
    let mut written = Vec::new();
    for now in 0..60 {
        let mut bytes = [0; BLOCK_LEN];
        match log.take_within(&mut share, now, &mut bytes) {
            Some(lsn) => {
                assert_eq!(now % 10, 0, "one block per interval");
                let (expected, block) = take(&mut twin).map(|(lsn, block)| (lsn, *block)).unwrap();
                assert!(
                    (lsn, bytes) == (expected, block),
                    "block {lsn} carries its sealed bytes"
                );
                twin.written(lsn);
                log.written(lsn);
                written.push(lsn);
            }
            None => assert!(now % 10 != 0 || written.len() == 6),
        }
    }
    assert_eq!(written, [0, 1, 2, 3, 4, 5]);
    assert_eq!(
        (share.peak(), share.saturated()),
        (BLOCK_LEN as u64, 5),
        "the five windows that left a block waiting each refused"
    );
    assert!(
        positions
            .iter()
            .all(|&position| reusable(0, position, log.durable(), false))
    );
}
