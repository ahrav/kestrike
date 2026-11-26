//! Range-split installs against the one-at-a-time install, the serial oracle of the same effects: over 1, 3, 4 and 16
//! lanes, each lane on its own thread, the tables after the lanes fold equal, word for word, the tables after the same
//! bindings install one at a time in lane order, policy order, free-set summaries and every counter included, in one
//! round and in two; and a planted lane defect breaks the equality or the lane's range.

use std::sync::atomic::Ordering;

use super::super::super::allocation::AllocationId;
use super::super::super::extent::ExtentLocator;
use super::super::super::owner::{Pool, Storage};
use super::super::super::owner_fixture::{Shape, storage_shaped_as};
use super::super::super::policy::PolicySlot;
use super::super::super::portable::PortableExpiry;
use super::super::super::reserve::Restored;
use super::super::super::seeded::SplitMix64;
use super::super::super::test_platform::TestPlatform;
use super::super::super::word::{self, INCARNATION, MARKER};
use super::super::{Naming, SlotState, Tables};
use super::{Folded, lane_len};

const SLOTS: usize = 1024;
const WRITER: u64 = (1 << 32) | 4;

/// A storage of `slots` slots.
fn storage(slots: usize) -> Storage<TestPlatform> {
    if slots == SLOTS {
        return storage_shaped_as(
            Shape {
                units: SLOTS + 64,
                slots: SLOTS,
            },
            8192,
        );
    }
    use super::super::super::publish_tests::{index_config, storage_config, storage_from};
    let mut config = storage_config(slots);
    config.volume.metadata_units = 1024;
    config.volume.raw_bytes = (slots + 1 + 1024) * super::super::super::IO_UNIT;
    let limits = [slots.min(1 << 12)];
    let index = index_config(&limits, (1, 1), 1);
    storage_from(
        &config,
        &index,
        TestPlatform::heap(super::super::super::publish_tests::PAGE),
    )
}

/// `count` bindings of distinct random slots, in random order, with random facts.
fn bindings(rng: &mut SplitMix64, count: usize, slots: usize) -> Vec<Restored> {
    let mut slots: Vec<usize> = (0..slots).collect();
    for at in (1..slots.len()).rev() {
        slots.swap(at, rng.below(at as u64 + 1) as usize);
    }
    slots[..count]
        .iter()
        .map(|&slot| {
            let mut key = [0; 32];
            for word in key.chunks_mut(8) {
                word.copy_from_slice(&rng.next_u64().to_le_bytes());
            }
            Restored {
                id: AllocationId::of_record_tag((slot as u64) << 32 | (1 + rng.below(3))),
                session: (1 << 32) | 2,
                version: rng.below(4),
                key,
                fingerprint: rng.next_u64(),
                expiry: PortableExpiry {
                    deadline_ns: 1 << 40 | rng.below(1 << 20),
                    lifetime_ms: 1 + rng.below(1000) as u32,
                },
                expires_at_s: 100 + rng.below(1 << 16) as u32,
                locator: ExtentLocator::new(slot as u64, 1).unwrap().ending_at(4096),
                tail: rng.below(4096) as u16,
            }
        })
        .collect()
}

/// The one-at-a-time install of `restored` the range-split core replaces, through the tables' single-slot paths.
fn serial(tables: &mut Tables<'_>, live: &Pool, restored: &Restored) {
    let slot = restored.id.slot_index();
    let record = &live.records()[slot];
    let free = record.ident.load(Ordering::Relaxed);
    assert!(tables.free_slots().contains(slot) && free & !INCARNATION == 0);
    let capture = live.capture_lock().unwrap();
    tables.free_slots().take(slot);
    record.set_locator(restored.locator);
    record.set_fingerprint(restored.fingerprint);
    record.set_expires_at_s(restored.expires_at_s);
    tables.tails[slot] = restored.tail;
    let naming = Naming {
        session: restored.session,
        version: restored.version,
    };
    tables.bind_naming(slot, restored.key, restored.expiry, naming);
    live.capture_insert(&capture, slot);
    if tables.state.note_deadline(restored.expires_at_s) {
        live.publish_deadline_bound(tables.state.earliest_deadline);
    }
    let installed =
        u64::from(restored.id.incarnation()) | SlotState::Resident.bits() | MARKER | word::REF;
    tables.queue().link_with(slot, |linked| {
        let exchanged = record.ident.compare_exchange(
            free,
            installed | linked,
            Ordering::Release,
            Ordering::Relaxed,
        );
        assert!(exchanged.is_ok());
    });
    tables.state.ledger.free -= 1;
    tables.state.ledger.resident += 1;
}

/// A planted lane defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plant {
    None,
    /// The fold skips the summary bits of the words a lane emptied.
    NoSummaries,
    /// The fold skips the policy splice of every lane but the first.
    OneSplice,
    /// The fold skips the slot ledger.
    NoLedger,
    /// Lane `k` installs the bindings of lane `k + 1`.
    Shifted,
}

/// Installs `restored` over `lanes` lanes, one thread each, and folds them.
fn parallel(
    tables: &mut Tables<'_>,
    live: &Pool,
    restored: &[Restored],
    lanes: usize,
    plant: Plant,
) {
    let slots = tables.records.len();
    let len = lane_len(slots, lanes);
    let count = slots.div_ceil(len);
    let mut work = vec![Vec::new(); count];
    for binding in restored {
        work[binding.id.slot_index() / len].push(*binding);
    }
    if plant == Plant::Shifted {
        work.rotate_left(1);
    }
    let reserve: Vec<u64> = work.iter().map(|lane| lane.len() as u64).collect();
    let capture = live.capture_lock().unwrap();
    let split = tables.lanes(live, &capture, len, &reserve);
    let mut folds: Vec<Folded> = std::thread::scope(|scope| {
        let workers: Vec<_> = (split.zip(&work))
            .map(|(mut lane, bindings)| {
                scope.spawn(move || {
                    for binding in bindings {
                        lane.install(binding, WRITER).unwrap();
                    }
                    lane.done()
                })
            })
            .collect();
        (workers.into_iter())
            .map(|worker| {
                worker
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect()
    });
    match plant {
        Plant::NoSummaries => folds
            .iter_mut()
            .for_each(|fold| fold.emptied = (None, Vec::new())),
        Plant::OneSplice => folds.iter_mut().skip(1).for_each(|fold| fold.installed = 0),
        _ => {}
    }
    let ledger = tables.state.ledger;
    if tables.fold_lanes(live, &capture, folds) {
        live.publish_deadline_bound(tables.state.earliest_deadline);
    }
    if plant == Plant::NoLedger {
        tables.state.ledger = ledger;
    }
}

/// Every word the install writes, in one vector per table, slot order.
fn snapshot(storage: &Storage<TestPlatform>) -> Vec<Vec<u64>> {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let tables = access.tables();
    let records = live.records();
    let atomics = |words: &[std::sync::atomic::AtomicU64]| {
        words
            .iter()
            .map(|word| word.load(Ordering::Relaxed))
            .collect()
    };
    let shot = vec![
        records
            .iter()
            .map(|record| record.ident.load(Ordering::Relaxed))
            .collect(),
        records
            .iter()
            .map(|record| record.locator().bits())
            .collect(),
        records.iter().map(|record| record.fingerprint()).collect(),
        records
            .iter()
            .map(|record| u64::from(record.expires_at_s()))
            .collect(),
        records
            .iter()
            .map(|record| u64::from(record.prev()))
            .collect(),
        tables
            .policy_next
            .iter()
            .map(|&next| u64::from(next))
            .collect(),
        tables.free_slots.to_vec(),
        tables.tails.iter().map(|&tail| u64::from(tail)).collect(),
        tables
            .keys
            .iter()
            .flat_map(|key| key.chunks(8))
            .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
            .collect(),
        tables.deadlines.to_vec(),
        tables
            .lifetimes
            .iter()
            .map(|&lifetime| u64::from(lifetime))
            .collect(),
        atomics(tables.generations),
        atomics(tables.versions),
        atomics(tables.steps),
        vec![
            u64::from(tables.domain.head),
            u64::from(tables.domain.tail),
            u64::from(tables.domain.members),
            tables.state.ledger.free as u64,
            tables.state.ledger.resident as u64,
            u64::from(tables.state.earliest_deadline),
            u64::from(tables.state.pass_earliest),
            live.insert_step.load(Ordering::Relaxed),
            live.eligible.load(Ordering::Relaxed) as u64,
            u64::from(live.deadline_bound.load(Ordering::Relaxed)),
        ],
    ];
    access.release();
    shot
}

/// The tables after `restored` installs over `lanes` lanes under `plant`, and after the one-at-a-time install in lane
/// order.
fn both(
    slots: usize,
    restored: &[Restored],
    lanes: usize,
    plant: Plant,
) -> (Vec<Vec<u64>>, Vec<Vec<u64>>) {
    rounds(slots, &[restored], lanes, plant)
}

/// [`both`] over consecutive install rounds on the same tables, each round folded before the next; the one-at-a-time
/// install takes each round's bindings in lane order.
fn rounds(
    slots: usize,
    rounds: &[&[Restored]],
    lanes: usize,
    plant: Plant,
) -> (Vec<Vec<u64>>, Vec<Vec<u64>>) {
    let (split, one) = (storage(slots), storage(slots));
    for (storage, parallel_install) in [(&split, true), (&one, false)] {
        let live = storage.live_pool().unwrap();
        for restored in rounds {
            let mut access = live.lock().unwrap();
            let mut tables = access.tables();
            if parallel_install {
                parallel(&mut tables, live, restored, lanes, plant);
            } else {
                let len = lane_len(slots, lanes);
                let mut ordered = restored.to_vec();
                ordered.sort_by_key(|binding| binding.id.slot_index() / len);
                for binding in &ordered {
                    serial(&mut tables, live, binding);
                }
            }
            access.release();
        }
    }
    (snapshot(&split), snapshot(&one))
}

/// Over 1, 3, 4 and 16 lanes and seeded binding sets of up to every slot, on 1,024 slots, where 3 lanes of 384 slots
/// need the 64-slot alignment, and on 5,000 slots, whose free set has three levels, the lanes' tables equal the
/// one-at-a-time install's in lane order: record words, locators, fingerprints, deadlines, policy links and domain,
/// every free-set word of every level, tails, keys, portable pairs, generations, versions, insertion steps, the slot
/// ledger, both deadline bounds, the insertion clock and the membership count.
#[test]
fn a_range_split_install_equals_the_one_at_a_time_install_in_lane_order() {
    let mut rng = SplitMix64::new(0x1446a);
    for (slots, cases) in [(SLOTS, 20), (5000, 8)] {
        for case in 0..cases {
            let count = [1, 64, 300, slots][case % 4];
            let restored = bindings(&mut rng, count, slots);
            for lanes in [1, 3, 4, 16] {
                let (split, one) = both(slots, &restored, lanes, Plant::None);
                assert_eq!(split, one, "{slots} slots case {case}, {lanes} lanes");
            }
        }
    }
}

/// Controls: a fold that skips the emptied words' summary bits, one that splices only the first lane's policy
/// sublist, and one that skips the slot ledger each leave tables the one-at-a-time install does not.
#[test]
fn a_fold_that_skips_summaries_a_splice_or_the_ledger_differs_from_the_one_at_a_time_install() {
    let restored = bindings(&mut SplitMix64::new(7), SLOTS, SLOTS);
    for plant in [Plant::NoSummaries, Plant::OneSplice, Plant::NoLedger] {
        let (split, one) = both(SLOTS, &restored, 4, plant);
        assert_ne!(split, one, "control {plant:?}");
        if plant == Plant::OneSplice {
            // The policy links and the domain's head and tail differ, not the counters alone.
            let policy = |shot: &[Vec<u64>]| {
                (
                    shot[4].clone(),
                    shot[5].clone(),
                    shot.last().unwrap()[..2].to_vec(),
                )
            };
            assert_ne!(policy(&split), policy(&one), "control {plant:?}");
        }
    }
}

/// Two install rounds on the same tables, the second over the first's folded state, equal the one-at-a-time install of
/// each round in lane order, so a fold composes with the policy list, free set and counters an earlier fold left.
#[test]
fn a_second_range_split_round_over_folded_tables_equals_the_one_at_a_time_install() {
    let mut rng = SplitMix64::new(0x1446b);
    for lanes in [1, 3, 4, 16] {
        let restored = bindings(&mut rng, 600, SLOTS);
        let (first, second) = restored.split_at(250);
        let (split, one) = rounds(SLOTS, &[first, second], lanes, Plant::None);
        assert_eq!(split, one, "{lanes} lanes");
    }
}

/// Control: a lane handed another lane's bindings refuses the first of them by panic before any write.
#[test]
#[should_panic(expected = "a restored binding outside its lane")]
fn a_lane_given_another_lanes_binding_panics_before_it_writes() {
    let restored = bindings(&mut SplitMix64::new(9), 64, SLOTS);
    let _ = both(SLOTS, &restored, 4, Plant::Shifted);
}

/// Control: a lane length off the 64-slot alignment refuses the split by panic before any lane exists.
#[test]
#[should_panic(expected = "a lane boundary off the 64-slot alignment")]
fn a_misaligned_lane_length_refuses_the_split() {
    let storage = storage(SLOTS);
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let capture = live.capture_lock().unwrap();
    let _ = tables.lanes(live, &capture, 72, &[0, 0]).count();
}
