//! At every census of a storage churn the free bytes keep the clean reserve, the six raw ledger terms equal the
//! bytes the churn derives from its own allocations and total the volume, and the allocator's free runs are the
//! maximal runs of units no live extent covers.
//!
//! The churn here is scripted. It reserves, publishes, aborts, abandons, invalidates and returns records on a
//! 64-unit volume with a two-unit clean reserve, and takes a census under one pool-gate hold after every step.
//! Every record carries a header, so every extent it returns has waste. The test keeps its own record of the live
//! allocations (slot, payload bytes, charged units, phase) and derives the expected terms from that record alone;
//! the ledgers, the free runs and each live slot's locator come from the gate hold.
//!
//! `churn_tests::Census::judge` judges each census, so the scripted churn and the seeded churn share one set of
//! rules: each extent's charged length, its place inside the volume, overlap, the slot counts per state, the
//! reserve, the raw terms, their total and the free runs. Its planted-defect test,
//! `the_census_reconciles_word_crossing_extents_and_fails_each_planted_defect`, shows each rule failing.
//!
//! Premises are asserted apart from the judgment, each under the word "premise": a slot word that disagrees with
//! the test's record is a scenario that did not form.

use std::sync::atomic::Ordering;

use super::attempt_tests::{begin, invalidate};
use super::budget::WorkBudget;
use super::churn_tests::{
    BODY_CAP, Census, CensusFault, Derived, Extent, Geometry, METADATA_CAP, RAW_FREE, Reported,
    churn_storage,
};
use super::device::IO_UNIT;
use super::owner::Storage;
use super::publish_tests::{TRIES, budget, key};
use super::tables::SlotState;
use super::test_platform::TestPlatform;
use super::volume_fixture::{Device, arena_with};
use super::writable_tests::bytes;
use super::{Decision, WritableFill};

/// The seeded churn's original shape: 64 payload units, 16 metadata units, 16 slots, 8 KiB chunks and a clean
/// reserve of two units.
const GEOMETRY: Geometry = Geometry::ORIGINAL;

/// The largest record the churn storage admits, its metadata cap and its body cap: nine units on this geometry.
const LARGEST: (usize, usize) = (METADATA_CAP, BODY_CAP);

/// Where one live allocation stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Reserved,
    Resident,
    Retired,
}

/// One allocation the scenario made and has not seen returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Live {
    slot: usize,
    incarnation: u32,
    payload: usize,
    units: usize,
    phase: Phase,
}

/// The scripted churn: the storage, its volume, and the scenario's own record of live allocations.
struct Churn {
    storage: &'static Storage<TestPlatform>,
    dev: Device<'static, 'static>,
    live: Vec<Live>,
    census: Census,
    censuses: usize,
    /// The fewest free bytes any census reported.
    least_free: usize,
}

impl Churn {
    fn new() -> Self {
        let storage = churn_storage(GEOMETRY, false);
        let arena = Box::leak(Box::new(arena_with(6, 6)));
        Self {
            storage,
            dev: Device::new(storage, arena),
            live: Vec::new(),
            census: Census::new(GEOMETRY),
            censuses: 0,
            least_free: usize::MAX,
        }
    }

    /// One census: every slot's word and locator, both ledgers and the free runs under one gate hold, then,
    /// with the gate released, the premises and the judgment.
    fn census(&mut self, step: &str) -> Result<(), CensusFault> {
        let pool = self.storage.live_pool().unwrap();
        let (slots, reported) = {
            let mut access = pool.lock().unwrap();
            let words: Vec<u64> = pool
                .records()
                .iter()
                .take(GEOMETRY.slots)
                .map(|record| record.ident.load(Ordering::Relaxed))
                .collect();
            let mut tables = access.tables();
            let slots: Vec<(SlotState, u32, u64, u64)> = words
                .iter()
                .enumerate()
                .map(|(slot, &word)| {
                    let locator = tables.held_locator(slot);
                    (
                        super::word::state(word),
                        super::word::incarnation(word),
                        locator.start_unit(),
                        u64::from(locator.len_units()),
                    )
                })
                .collect();
            let counts = tables.state.ledger;
            let extents = tables.extents();
            let raw = extents.ledger();
            let reported = Reported {
                slots: [
                    counts.free,
                    counts.filling,
                    counts.resident,
                    counts.retired,
                    counts.quarantined,
                ],
                raw: [
                    raw.free,
                    raw.reserved,
                    raw.resident,
                    raw.retired,
                    raw.waste,
                    raw.metadata,
                ],
                total: raw.total().ok(),
                free_runs: extents.free_set(),
            };
            (slots, reported)
        };
        assert_eq!(slots.len(), GEOMETRY.slots, "premise: the pool's slots");
        let mut derived = Derived::default();
        self.census.extents.clear();
        for allocation in &self.live {
            let (state, incarnation, start, len) = slots[allocation.slot];
            let expected = match allocation.phase {
                Phase::Reserved => SlotState::Filling,
                Phase::Resident => SlotState::Resident,
                Phase::Retired => SlotState::Retired,
            };
            assert_eq!(
                (state, incarnation),
                (expected, allocation.incarnation),
                "premise, {step}: slot {}'s word against the scenario's record",
                allocation.slot
            );
            derived.counts[expected as usize] += 1;
            match allocation.phase {
                Phase::Reserved => derived.reserved += allocation.payload,
                Phase::Resident => derived.resident += allocation.payload,
                Phase::Retired => derived.retired += allocation.payload,
            }
            derived.waste += allocation.units * IO_UNIT - allocation.payload;
            derived.held += allocation.units;
            self.census.extents.push(Extent {
                slot: allocation.slot,
                start,
                len,
                charged: allocation.units as u64,
            });
        }
        for (slot, &(state, ..)) in slots.iter().enumerate() {
            if self.live.iter().any(|allocation| allocation.slot == slot) {
                continue;
            }
            assert!(
                matches!(state, SlotState::Free | SlotState::Quarantined),
                "premise, {step}: slot {slot} is {state:?} and the scenario holds no allocation there"
            );
            derived.counts[state as usize] += 1;
        }
        self.censuses += 1;
        self.least_free = self.least_free.min(reported.raw[RAW_FREE]);
        self.census.judge(GEOMETRY, derived, &reported)
    }

    /// Takes a census and requires it clean.
    fn check(&mut self, step: &str) {
        assert_eq!(self.census(step), Ok(()), "census after: {step}");
    }

    /// Reserves a record of `metadata` and `body` bytes under key `n` and records it, or returns `None` when
    /// admission or the reservation refuses.
    fn reserve(
        &mut self,
        n: u8,
        (metadata, body): (usize, usize),
    ) -> Option<WritableFill<'static, 'static, TestPlatform>> {
        let storage = self.storage;
        let attempt = begin(storage, &key(n)).expect("premise: the attempt begins");
        let granted = match storage.decide_admission(Some(metadata), Some(body)) {
            Decision::Admit(admitted) => attempt
                .reserve_storage(admitted, Some(metadata), Some(body), TRIES, &mut budget())
                .ok(),
            _ => {
                attempt.abort();
                None
            }
        };
        let Some(fill) = granted else {
            self.service_fills();
            return None;
        };
        let payload = metadata + body;
        self.live.push(Live {
            slot: fill.id().slot_index(),
            incarnation: fill.id().incarnation(),
            payload,
            units: GEOMETRY.charged_units(payload),
            phase: Phase::Reserved,
        });
        Some(fill)
    }

    /// Releases the fill records of ended fills.
    fn service_fills(&self) {
        let _ = self
            .storage
            .service_fills(crate::index::ShardIndex(0), TRIES, &mut budget());
    }

    /// Writes `fill`'s whole record to the device.
    fn write(&mut self, fill: &mut WritableFill<'static, 'static, TestPlatform>, seed: u64) {
        let payload = self.recorded(fill.id().slot_index()).payload;
        self.dev.fill(fill, &bytes(payload, seed));
    }

    /// Writes and publishes `fill`, and records it resident.
    fn publish(&mut self, mut fill: WritableFill<'static, 'static, TestPlatform>, seed: u64) {
        let slot = fill.id().slot_index();
        self.write(&mut fill, seed);
        let lease = fill
            .publish(&mut self.dev.volume, u64::MAX, TRIES, &mut budget())
            .expect("premise: the written fill publishes");
        drop(lease);
        self.service_fills();
        self.recorded(slot).phase = Phase::Resident;
    }

    /// Reserves, writes and publishes one record; false when the reservation was refused.
    fn publish_new(&mut self, n: u8, sizes: (usize, usize)) -> bool {
        match self.reserve(n, sizes) {
            Some(fill) => {
                self.publish(fill, u64::from(n));
                true
            }
            None => false,
        }
    }

    fn recorded(&mut self, slot: usize) -> &mut Live {
        self.live
            .iter_mut()
            .find(|allocation| allocation.slot == slot)
            .expect("premise: the scenario recorded the slot's allocation")
    }

    /// Runs grace and service until `slot` is free again, then forgets every retired allocation whose slot the
    /// service freed: one service pass may return more than one retired extent.
    fn returned(&mut self, slot: usize) {
        let storage = self.storage;
        let pool = storage.live_pool().unwrap();
        let free = |slot: usize| {
            let word = pool.records()[slot].ident.load(Ordering::Relaxed);
            super::word::state(word) == SlotState::Free
        };
        for _ in 0..8 {
            self.service_fills();
            let _ = storage.certify(&mut WorkBudget::new(1 << 12)).unwrap();
            storage.service(&mut WorkBudget::new(1 << 12)).unwrap();
            if free(slot) {
                self.live.retain(|allocation| {
                    allocation.phase != Phase::Retired || !free(allocation.slot)
                });
                return;
            }
        }
        panic!("premise: slot {slot}'s extent never returned");
    }

    /// Invalidates key `n`, whose record lives in `slot`, and records the retirement.
    fn retire(&mut self, n: u8, slot: usize) {
        invalidate(self.storage, &key(n)).expect("premise: the invalidation is accepted");
        self.recorded(slot).phase = Phase::Retired;
    }

    fn slot_of(&self, payload: usize) -> usize {
        self.live
            .iter()
            .find(|allocation| allocation.payload == payload)
            .expect("premise: one live allocation has this payload")
            .slot
    }
}

/// The scripted churn. Each step is followed by a census; steps 5, 6, 7 and 9 return extents with waste, and
/// the censuses after them are the ones a return that credits the wrong bytes to the free term breaks.
#[test]
fn every_census_of_a_scripted_churn_reconciles_the_raw_terms_the_reserve_and_the_free_runs() {
    let mut churn = Churn::new();
    churn.check("0: the fresh volume");
    assert_eq!(
        churn.least_free,
        GEOMETRY.units * IO_UNIT,
        "premise: the fresh volume is all free"
    );

    // 1-2: a one-unit record, reserved and then published.
    let fill = churn
        .reserve(1, (4, 20))
        .expect("premise: record 1 is reserved");
    churn.check("1: record 1 reserved");
    churn.publish(fill, 1);
    churn.check("2: record 1 published");

    // 3: a two-unit record.
    assert!(
        churn.publish_new(2, (8, 5000)),
        "premise: record 2 is reserved"
    );
    churn.check("3: record 2 published");

    // 4: a five-unit record, with a census while it is reserved.
    let fill = churn
        .reserve(3, (0, 20_000))
        .expect("premise: record 3 is reserved");
    churn.check("4a: record 3 reserved");
    churn.publish(fill, 3);
    churn.check("4b: record 3 published");

    // 5: an unwritten reservation aborted. Its extent returns at once: 3004 payload bytes in one unit.
    let fill = churn
        .reserve(4, (4, 3000))
        .expect("premise: record 4 is reserved");
    let slot = fill.id().slot_index();
    churn.check("5a: record 4 reserved");
    fill.abort();
    churn.live.retain(|allocation| allocation.slot != slot);
    churn.check("5b: record 4 aborted, its extent returned");

    // 6: a written reservation dropped. Its extent is retired until service returns it.
    let mut fill = churn
        .reserve(5, (4, 9000))
        .expect("premise: record 5 is reserved");
    let slot = fill.id().slot_index();
    churn.write(&mut fill, 5);
    drop(fill);
    churn.recorded(slot).phase = Phase::Retired;
    churn.check("6a: record 5 written and dropped, retired");
    churn.returned(slot);
    churn.check("6b: record 5's extent returned");

    // 7: the published two-unit record invalidated, then returned; it leaves a hole between records 1 and 3.
    let slot = churn.slot_of(5008);
    churn.retire(2, slot);
    churn.check("7a: record 2 invalidated, retired");
    churn.returned(slot);
    churn.check("7b: record 2's extent returned");

    // 8: largest records, then one-unit records, until a reservation is refused. A reservation the storage
    // grants is recorded, so a claim that spent the clean reserve shows in the census as `ReserveSpent`.
    let mut n = 10;
    for sizes in [LARGEST, (4, 20)] {
        while churn.publish_new(n, sizes) {
            churn.check(&format!(
                "8: record {n} of {sizes:?} published on the filling volume"
            ));
            n += 1;
            assert!(n < 40, "premise: the volume fills within its slots");
        }
        churn.check(&format!("8: a record of {sizes:?} refused"));
    }
    let full = churn.least_free;

    // 9: every record invalidated and returned, a census after each return.
    let keys: Vec<(u8, usize)> = [(1, 24), (3, 20_000)]
        .into_iter()
        .map(|(n, payload)| (n, churn.slot_of(payload)))
        .collect();
    for (n, slot) in keys {
        churn.retire(n, slot);
        churn.check(&format!("9a: record {n} invalidated"));
        churn.returned(slot);
        churn.check(&format!("9b: record {n}'s extent returned"));
    }
    for n in 10..n {
        let _ = invalidate(churn.storage, &key(n));
    }
    let rest: Vec<usize> = churn
        .live
        .iter()
        .map(|allocation| allocation.slot)
        .collect();
    for allocation in &mut churn.live {
        allocation.phase = Phase::Retired;
    }
    churn.check("9c: the filling records invalidated");
    for slot in rest {
        if churn.live.iter().any(|allocation| allocation.slot == slot) {
            churn.returned(slot);
            churn.check(&format!("9d: slot {slot}'s extent returned"));
        }
    }
    let (censuses, live) = (churn.censuses, churn.live.len());
    drop(churn);

    assert_eq!(live, 0, "premise: the churn returned every extent");
    assert!(censuses >= 20, "premise: {censuses} censuses were taken");
    // The filling phase ended with exactly the reserve free, so the census after the refused reservation judged
    // the reserve clause where one more one-unit claim would have spent it.
    assert_eq!(
        full,
        GEOMETRY.reserve as usize * IO_UNIT,
        "premise: the filling phase left exactly the clean reserve free"
    );
}
