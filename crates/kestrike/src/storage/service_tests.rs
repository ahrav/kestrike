//! Cohort-bounded service: the work a call does follows the pending cohort
//! and the configured slot count, every probe and slot visit is funded
//! before it is made, both pass cursors resume across calls, and one held
//! object never keeps a pass from the members after it.
//!
//! Every history checks, after each call, an independent census of the slot
//! states and the owned extents against the ledger: the slot partition
//! counted from the records, the raw partition summing to the volume, owned
//! extents pairwise disjoint and their units equal to the bytes not free.

use std::sync::atomic::Ordering;

use super::budget::WorkBudget;
use super::claim_exit_tests::{FREE, PARKED, RETIRED, conserved_at};
use super::config::StorageConfig;
use super::layout::IO_UNIT;
use super::ledger::SlotPartition;
use super::owner::Storage;
use super::pending::GROUP_SLOTS;
use super::placement::PlacementConfig;
use super::release::{
    PARKED_PROBE, RETIRED_PROBE, SERVICE_CONTROLS, SERVICE_MINIMUM, SERVICE_PER_SLOT, ServiceReport,
};
use super::reserve::take_return_visits;
use super::tables::SlotState;
use super::test_platform::TestPlatform;
use super::word;
use super::{ExtentLease, ExtentReservation, Resident};

const PAGE: usize = 4096;
const KEY: [u8; 32] = [0x5a; 32];

fn storage(units: usize, slot_count: usize) -> Storage<TestPlatform> {
    storage_bodied(units, slot_count, 200)
}

/// [`storage`] whose objects carry up to `body_cap` body bytes.
fn storage_bodied(units: usize, slot_count: usize, body_cap: usize) -> Storage<TestPlatform> {
    let config = StorageConfig {
        page_size: PAGE,
        engine_budget: 1 << 27,
        body_cap,
        metadata_cap: Some(16),
        lease_limit: 1024,
        object_rights: 64,
        reader_limit: 4,
        volume: crate::storage::test_volume(units * IO_UNIT, slot_count),
    };
    let placement = PlacementConfig { control_home: 0 };
    Storage::initialize(
        &config.validate().unwrap(),
        &placement,
        TestPlatform::heap(PAGE),
    )
    .unwrap()
}

/// A one-unit reservation claimed at `slot`.
fn reserve_at(storage: &Storage<TestPlatform>, slot: usize) -> ExtentReservation<'_, TestPlatform> {
    storage.live_pool().unwrap().claim_next(slot);
    let owner = storage
        .reserve(Some(8), Some(100), &mut WorkBudget::new(1 << 10))
        .unwrap();
    assert_eq!(owner.id().slot_index(), slot);
    owner
}

/// A filling owner at `slot` dropped with the gate free, which retires it
/// with no anchor.
fn retire_at(storage: &Storage<TestPlatform>, slot: usize) {
    drop(reserve_at(storage, slot));
    assert_eq!(state(storage, slot), SlotState::Retired);
}

/// A filling owner at `slot` dropped while the gate is held, which parks
/// its obligation.
fn park_at(storage: &Storage<TestPlatform>, slot: usize) {
    let owner = reserve_at(storage, slot);
    let held = storage.live_pool().unwrap().lock().unwrap();
    drop(owner);
    drop(held);
    assert_eq!(state(storage, slot), SlotState::Filling);
}

/// A resident at `slot` with its lease, which holds a right on the slot.
pub(super) fn resident_at(
    storage: &Storage<TestPlatform>,
    slot: usize,
) -> (Resident<'_, TestPlatform>, ExtentLease<'_, TestPlatform>) {
    let mut owner = reserve_at(storage, slot);
    owner.mark_written();
    let completed = owner
        .complete(KEY, u64::MAX, &mut WorkBudget::new(1 << 10))
        .ok()
        .unwrap();
    completed
        .handoff(&mut WorkBudget::new(1 << 10))
        .ok()
        .unwrap()
}

pub(super) fn state(storage: &Storage<TestPlatform>, slot: usize) -> SlotState {
    let live = storage.live_pool().unwrap();
    word::state(live.records()[slot].ident.load(Ordering::Relaxed))
}

/// The retired and park pass cursors.
fn cursors(storage: &Storage<TestPlatform>) -> (usize, usize) {
    let mut access = storage.live_pool().unwrap().lock().unwrap();
    let tables = access.tables();
    (tables.state.cursor_slot, tables.state.cursor_park)
}

fn pending_marks(storage: &Storage<TestPlatform>) -> usize {
    let live = storage.live_pool().unwrap();
    live.telemetry().pending_marks.load(Ordering::Acquire)
}

/// The slot and raw censuses, counted from the records under the gate,
/// against the ledger.
fn census(storage: &Storage<TestPlatform>) {
    let report = storage.pool_report().unwrap();
    let ledger = report.ledger.unwrap();
    let raw_bytes = report.descriptor.raw_bytes;
    assert_eq!(ledger.raw.total(), Ok(raw_bytes), "{ledger:?}");
    assert_eq!(
        ledger.raw.metadata,
        crate::storage::TEST_METADATA_UNITS as usize * IO_UNIT,
        "{ledger:?}"
    );
    let payload_bytes = raw_bytes - ledger.raw.metadata;
    let live = storage.live_pool().unwrap();
    let access = live.lock().unwrap();
    let mut slots = SlotPartition::default();
    let mut owned = Vec::new();
    for record in live.records() {
        let current = record.ident.load(Ordering::Relaxed);
        match word::state(current) {
            SlotState::Free => slots.free += 1,
            SlotState::Quarantined => slots.quarantined += 1,
            held => {
                match held {
                    SlotState::Filling => slots.filling += 1,
                    SlotState::Resident => slots.resident += 1,
                    _ => slots.retired += 1,
                }
                let locator = record.locator();
                owned.push((locator.start_unit(), u64::from(locator.len_units())));
            }
        }
    }
    drop(access);
    assert_eq!(slots, ledger.slots);
    owned.sort_unstable();
    for pair in owned.windows(2) {
        assert!(
            pair[0].0 + pair[0].1 <= pair[1].0,
            "overlapping extents {pair:?}"
        );
    }
    let held: u64 = owned.iter().map(|(_, units)| units).sum();
    assert_eq!(held as usize * IO_UNIT, payload_bytes - ledger.raw.free);
}

/// One service call with `allowance`, its report, the steps it spent by
/// kind and the visits its returns counted; the censuses are checked after
/// the call.
fn serve(
    storage: &Storage<TestPlatform>,
    allowance: usize,
) -> (ServiceReport, super::budget::WorkCounters, usize) {
    let mut budget = WorkBudget::new(allowance);
    take_return_visits();
    let report = storage.service(&mut budget).unwrap();
    let counted = take_return_visits();
    census(storage);
    // Each pass's cursor rests the positions it covered past where it
    // started, and covers each position at most once.
    let count = storage.live_pool().unwrap().records().len();
    assert!(report.covered <= count && report.park_covered <= count);
    assert_eq!(
        cursors(storage),
        (
            (report.first + report.covered) % count,
            (report.park_first + report.park_covered) % count
        ),
        "{report:?}"
    );
    let charged = budget.counters();
    // Every probe and every visited slot is charged as one visit, beside
    // the visits the returns counted.
    assert_eq!(charged.visits, report.probes + report.visited + counted);
    assert_eq!(
        allowance - budget.remaining(),
        charged.coordination_attempts
            + charged.visits
            + charged.comparisons
            + charged.updates
            + charged.hashes
    );
    (report, charged, counted)
}

/// At fixed slot capacity a call's work follows the pending cohort alone:
/// the same retired and parked cohort beside zero or 1,500 residents costs
/// the same probes, slot visits and steps of every kind outside the extent
/// allocator's counted return visits, returns the same obligations, and an
/// idle call after it costs its controls alone in both.
#[test]
fn the_same_pending_cohort_costs_the_same_work_at_any_occupancy() {
    const SLOTS: usize = 2 * GROUP_SLOTS + 200;
    let retired = [3, GROUP_SLOTS + 4, 2 * GROUP_SLOTS + 108];
    let parked = [70, GROUP_SLOTS + 904];
    let cohort: Vec<usize> = retired.iter().chain(&parked).copied().collect();
    let mut runs = Vec::new();
    for residents in [0, 1_500] {
        let storage = storage(SLOTS + 1, SLOTS);
        let occupied: Vec<usize> = (0..SLOTS)
            .step_by(3)
            .filter(|slot| !cohort.contains(slot))
            .take(residents)
            .collect();
        let mut kept = Vec::new();
        for &slot in &occupied {
            let (resident, lease) = resident_at(&storage, slot);
            drop(lease);
            kept.push(resident);
        }
        retired.iter().for_each(|&slot| retire_at(&storage, slot));
        parked.iter().for_each(|&slot| park_at(&storage, slot));
        census(&storage);
        assert_eq!(pending_marks(&storage), parked.len());
        let (busy, mut busy_spent, counted) = serve(&storage, 1 << 16);
        assert_eq!((busy.visited, busy.serviced), (cohort.len(), cohort.len()));
        assert!(!busy.budget_exhausted, "{busy:?}");
        assert_eq!(pending_marks(&storage), 0);
        // The extent allocator's own visits for each return depend on the
        // free runs around the extent, which occupancy shapes; each stays
        // within the extent work bound the visit funded. Service's own work
        // is the rest.
        let bound = storage.pool_report().unwrap().extent_bound;
        assert!(counted <= busy.serviced * bound);
        busy_spent.visits -= counted;
        let (idle, idle_spent, _) = serve(&storage, 1 << 16);
        assert_eq!((idle.probes, idle.visited), (0, 0));
        assert!(!idle.pending);
        assert_eq!(
            (idle_spent.coordination_attempts, idle_spent.updates),
            (1, SERVICE_CONTROLS - 1)
        );
        let ledger = storage.pool_report().unwrap().ledger.unwrap();
        assert_eq!(ledger.slots.resident, residents);
        runs.push((busy, busy_spent, idle, idle_spent, cursors(&storage)));
        drop(kept);
    }
    assert_eq!(runs[0], runs[1]);
}

/// The number of minimum-funded calls until the eligible slot `target`
/// returns, at most `limit`, or `None`. With `restart`, the retired
/// cursor is put back on slot 0 before every call: the planted defect of a
/// pass that always starts over.
fn calls_to_return(
    storage: &Storage<TestPlatform>,
    target: usize,
    held: &[usize],
    limit: usize,
    restart: bool,
) -> Option<usize> {
    let minimum = storage.service_minimum();
    for call in 1..=limit {
        if restart {
            let mut access = storage.live_pool().unwrap().lock().unwrap();
            access.tables().state.cursor_slot = 0;
        }
        let (before, _) = cursors(storage);
        let (report, _, _) = serve(storage, minimum);
        assert_eq!(report.first, before);
        // Every held object stays counted and in place, whatever the pass
        // decided.
        for &slot in held {
            assert_eq!(state(storage, slot), SlotState::Retired);
        }
        if state(storage, target) == SlotState::Free {
            return Some(call);
        }
    }
    None
}

/// Held slots a minimum-funded retired pass decides per call when no park is
/// counted. The minimum is the controls, each pass's two probes and slot
/// bundle and one visit bound per pass; with no park counted the retired
/// pass alone spends the allowance after the controls, so it has `minimum - SERVICE_CONTROLS - 2 * RETIRED_PROBE` steps
/// after its two probes, and it decides a slot while that remainder funds
/// the slot's bundle and the largest return, spending the bundle on a held
/// slot.
fn held_per_call(storage: &Storage<TestPlatform>) -> usize {
    per_call(storage, SERVICE_PER_SLOT)
}

/// Slots a minimum-funded retired pass decides per call when each decision
/// spends `spent` steps, from the room its two probes leave, while that room
/// funds a slot's bundle and the largest return; with no park counted the
/// retired pass alone spends the allowance after the controls. The
/// fixture's tables carry no block arena, so `visit_bound` is the extent
/// bound alone, as the assertion checks.
fn per_call(storage: &Storage<TestPlatform>, spent: usize) -> usize {
    let bound = storage.pool_report().unwrap().extent_bound;
    assert_eq!(storage.service_minimum(), SERVICE_MINIMUM + 2 * bound);
    let after_probes = storage.service_minimum() - SERVICE_CONTROLS - 2 * RETIRED_PROBE;
    (after_probes - (SERVICE_PER_SLOT + bound)) / spent + 1
}

/// Retired objects at slots `0..held`, each held by a live lease, ahead of
/// an eligible one at slot `held`, served by minimum-funded calls: the
/// calls until the eligible one returns, or `None` within the bound.
///
/// Bound: each call that stays within one bitmap word decides at least
/// `held_per_call` slots from where the last stopped; the one call that
/// crosses into the next word pays its probe and may decide one fewer, which
/// one extra call covers. So the eligible slot, the `held + 1`th decision, is
/// reached within `ceil((held + 1) / held_per_call) + 1` calls while the
/// slots span at most two bitmap words.
fn eligible_return(held: usize, restart: bool) -> Option<usize> {
    let storage = storage(held + 2, held + 1);
    let mut leases = Vec::new();
    for slot in 0..held {
        let (resident, lease) = resident_at(&storage, slot);
        drop(resident);
        leases.push(lease);
    }
    retire_at(&storage, held);
    let certified = storage.certify(&mut WorkBudget::new(400)).unwrap();
    assert!(certified.certified.is_some());
    let held_slots: Vec<usize> = (0..held).collect();
    assert!(
        held < 2 * u64::BITS as usize,
        "the slots span at most two bitmap words"
    );
    let bound = (held + 1).div_ceil(held_per_call(&storage)) + 1;
    assert!(
        bound < held,
        "the bound is tighter than one held slot per call"
    );
    let calls = calls_to_return(&storage, held, &held_slots, bound, restart);
    drop(leases);
    calls
}

/// A run of held retired objects ahead of an eligible one: minimum-funded
/// calls decide a few slots each, every held object stays counted and in
/// place, and the eligible one returns once the cursor reaches it, since
/// each call resumes where the last stopped.
#[test]
fn a_held_object_beside_an_eligible_one_never_keeps_the_pass_from_it() {
    let calls = eligible_return(64, false).expect("the eligible object returned");
    assert!(calls > 1, "one call decided every held object: {calls}");
}

/// The planted control: a pass that restarts its cursor every call decides
/// the same first held objects forever, and the check that the eligible one
/// returns rejects it.
#[test]
#[should_panic(expected = "the eligible object never returned")]
fn negative_control_a_restarting_cursor_never_reaches_the_eligible_object() {
    eligible_return(64, true).expect("the eligible object never returned");
}

/// Quiet traffic: retired eligible objects and no admission while
/// minimum-funded calls service them, all within one bitmap word.
///
/// Bound: a returned member spends its bundle and at most the extent bound,
/// so each call returns at least `per_call(SERVICE_PER_SLOT + bound)`
/// members, or every member left, from where the last stopped, and
/// `members` objects return within `ceil(members / per_call)` calls.
#[test]
fn quiet_traffic_drains_every_eligible_member_within_its_bound() {
    const MEMBERS: usize = 24;
    let storage = storage(MEMBERS + 2, MEMBERS + 1);
    for slot in 0..MEMBERS {
        retire_at(&storage, slot);
    }
    assert!(
        storage
            .certify(&mut WorkBudget::new(400))
            .unwrap()
            .certified
            .is_some()
    );
    let bound = storage.pool_report().unwrap().extent_bound;
    let returns = per_call(&storage, SERVICE_PER_SLOT + bound);
    assert!(returns > 1, "each call returns more than one member");
    let limit = MEMBERS.div_ceil(returns);
    let minimum = storage.service_minimum();
    let left = || {
        (0..MEMBERS)
            .filter(|&slot| state(&storage, slot) != SlotState::Free)
            .count()
    };
    let mut calls = 0;
    while left() > 0 {
        calls += 1;
        assert!(calls <= limit, "members still retired after {limit} calls");
        let remaining = left();
        let (before, _) = cursors(&storage);
        let (report, _, _) = serve(&storage, minimum);
        assert_eq!(
            report.first, before,
            "call {calls} resumes where the last stopped"
        );
        assert!(
            report.serviced >= returns.min(remaining),
            "call {calls}: {report:?}"
        );
    }
    assert!(calls > 1, "one call returned every member");
    assert_eq!(
        storage.pool_report().unwrap().ledger.unwrap().slots.retired,
        0
    );
}

/// A fragmented layout: one-unit objects at units 0 to 3 of a five-unit
/// volume, the ones at units 0 and 2 retired. Before service a two-unit
/// admission is refused at the clean reserve, one free unit against the three
/// the two-unit layout and the one-unit reserve need, and so is a one-unit
/// admission, since the one free unit is the reserve; after service returns units 0 and 2
/// the volume holds three free units in three runs, enough for the two-unit
/// layout and the one-unit reserve, so the clean-reserve check passes and
/// the admission is refused for fragmentation. Each refusal leaves the
/// ledger, slot partition included, as it was, the census of slots and
/// owned extents matches the ledger at each refusal, after the service and
/// after each reuse, and a
/// one-unit admission, the retired objects' class, reuses a returned
/// address until the last free unit, the clean reserve, refuses the next.
#[test]
fn a_fragmented_refusal_keeps_the_accounting_exact_and_a_returned_address_is_reused() {
    let storage = storage_bodied(5, 8, 2 * IO_UNIT);
    let owners: [_; 4] = std::array::from_fn(|slot| reserve_at(&storage, slot));
    let starts = owners.each_ref().map(|owner| owner.locator().start_unit());
    assert_eq!(starts, [0, 1, 2, 3]);
    let [first, held, third, last] = owners;
    drop(first);
    drop(third);
    census(&storage);
    let ledger = || storage.pool_report().unwrap().ledger.unwrap();
    let wide = || {
        storage
            .reserve(
                Some(16),
                Some(2 * IO_UNIT - 200),
                &mut WorkBudget::new(1 << 10),
            )
            .err()
    };
    let retired = ledger();
    assert_eq!(retired.slots.retired, 2);
    assert_eq!(wide(), Some(super::ReserveError::CleanReserve));
    let narrow = || storage.reserve(Some(8), Some(100), &mut WorkBudget::new(1 << 10));
    assert_eq!(narrow().err(), Some(super::ReserveError::CleanReserve));
    assert_eq!(
        ledger(),
        retired,
        "a refusal before the return moves nothing"
    );
    census(&storage);
    assert!(
        storage
            .certify(&mut WorkBudget::new(400))
            .unwrap()
            .certified
            .is_some()
    );
    let (report, _, _) = serve(&storage, 1 << 12);
    assert_eq!(report.serviced, 2);
    let returned = ledger();
    assert_eq!(returned.slots.retired, 0);
    assert_eq!(
        returned.raw.free,
        3 * IO_UNIT,
        "three free units in three runs"
    );
    assert_eq!(returned.raw.free, retired.raw.free + 2 * IO_UNIT);
    assert_eq!(wide(), Some(super::ReserveError::PayloadFull));
    assert_eq!(
        ledger(),
        returned,
        "a refusal after the return moves nothing"
    );
    census(&storage);
    let reused: Vec<_> = (0..2)
        .map(|_| {
            let owner = narrow().unwrap();
            census(&storage);
            owner
        })
        .collect();
    let at: Vec<u64> = reused
        .iter()
        .map(|owner| owner.locator().start_unit())
        .collect();
    assert!(
        at.iter().any(|unit| [0, 2].contains(unit)),
        "the class reuses a returned address: {at:?}"
    );
    let full = ledger();
    assert_eq!(narrow().err(), Some(super::ReserveError::CleanReserve));
    assert_eq!(ledger(), full, "the last free unit is the clean reserve");
    census(&storage);
    drop((held, last, reused));
}

/// A distant retired member behind empty summary groups, with a park
/// counted so the retired pass holds back the park pass's decision: an
/// allowance one step short of the member's visit reads every summary word
/// on the way, stops in front of the member with the slot untouched and
/// the cursor on it, and the park pass still decides its slot; the exact
/// allowance visits and returns the member. A call resumed from the stopped
/// cursor reaches the member with two probes instead of four.
/// The retired and the parked slot pass the conservation judge before service,
/// and the tables pass again with both slots `Free` after the exact call.
#[test]
fn a_short_allowance_stops_in_front_and_the_exact_one_completes_the_visit() {
    const SLOTS: usize = 3 * GROUP_SLOTS + 10;
    let member = 2 * GROUP_SLOTS + 5;
    let build = || {
        let storage = storage(8, SLOTS);
        retire_at(&storage, member);
        park_at(&storage, 1);
        census(&storage);
        storage
    };
    let bound = build().pool_report().unwrap().extent_bound;
    // Summary words 0, 1 and 2, then bitmap word 128.
    let probes = 4;
    let held_back = 2 * PARKED_PROBE + SERVICE_PER_SLOT + bound;
    let exact = SERVICE_CONTROLS + probes * RETIRED_PROBE + SERVICE_PER_SLOT + bound + held_back;
    let short = exact - 1;
    let shorted = build();
    assert!(short >= shorted.service_minimum());

    let (report, _, _) = serve(&shorted, short);
    assert_eq!(state(&shorted, member), SlotState::Retired);
    assert_eq!(cursors(&shorted).0, member);
    assert_eq!(report.covered, member);
    assert!(report.budget_exhausted);
    // The park pass decided slot 1 from the steps held back for it.
    assert_eq!(state(&shorted, 1), SlotState::Free);
    assert_eq!(pending_marks(&shorted), 0);
    // Resumed: summary word 2 and bitmap word 128 reach the member, which
    // returns; the summary word already read marks no later word, so
    // summary word 3 ends the table, and summary words 0, 1 and 2 cover the
    // positions before the cursor.
    let (resumed, _, _) = serve(&shorted, shorted.service_minimum());
    assert_eq!(resumed.first, member);
    assert_eq!((resumed.probes, resumed.serviced), (2 + 1 + 3, 1));
    assert_eq!(resumed.covered, SLOTS);
    assert_eq!(state(&shorted, member), SlotState::Free);

    let exactly = build();
    conserved_at(&exactly, member, RETIRED);
    conserved_at(&exactly, 1, PARKED);
    let (report, _, _) = serve(&exactly, exact);
    conserved_at(&exactly, member, FREE);
    conserved_at(&exactly, 1, FREE);
    assert_eq!((report.visited, report.serviced), (2, 2));
    assert!(report.covered > member, "{report:?}");
    assert_eq!(pending_marks(&exactly), 0);
}

/// Members on both sides of a mid-table cursor, one in the last slot: one
/// funded call visits each once, wrapping inside the pass, and the cursor
/// comes back to where it started. The retired pass and the park pass each
/// read summary words 1 and 2 and the last member's bitmap word, then
/// summary words 0 and 1 and the early member's bitmap word.
#[test]
fn a_pass_from_a_mid_table_cursor_wraps_and_visits_each_member_once() {
    const SLOTS: usize = 3 * GROUP_SLOTS;
    let middle = SLOTS / 2;
    for park in [false, true] {
        let storage = storage(8, SLOTS);
        {
            let mut access = storage.live_pool().unwrap().lock().unwrap();
            let tables = access.tables();
            tables.state.cursor_slot = middle;
            tables.state.cursor_park = middle;
        }
        for slot in [middle - 1, SLOTS - 1] {
            if park {
                park_at(&storage, slot);
            } else {
                retire_at(&storage, slot);
            }
        }
        let (report, charged, counted) = serve(&storage, 1 << 12);
        assert_eq!(
            (
                report.first,
                report.park_first,
                report.covered,
                report.park_covered
            ),
            (middle, middle, SLOTS, SLOTS)
        );
        assert_eq!(
            (
                report.probes,
                report.visited,
                report.serviced,
                report.skipped
            ),
            (6, 2, 2, 0),
            "park {park}"
        );
        assert!(!report.budget_exhausted);
        assert_eq!(cursors(&storage), (middle, middle));
        let probe = if park { PARKED_PROBE } else { RETIRED_PROBE };
        assert_eq!(charged.visits, 6 + 2 + counted);
        assert_eq!(charged.comparisons, 2 * 3);
        assert_eq!(
            charged.updates,
            SERVICE_CONTROLS - 1 + 6 * (probe - RETIRED_PROBE) + 2 * 2
        );
        // With the cohort returned, an idle call reports the cursors where
        // the passes left them and every position covered.
        let (idle, _, _) = serve(&storage, 1 << 12);
        assert_eq!(
            (
                idle.first,
                idle.park_first,
                idle.covered,
                idle.park_covered,
                idle.pending
            ),
            (middle, middle, SLOTS, SLOTS, false)
        );
    }
}

/// A park in the last slot of a 128-group table, served by calls funded at
/// the minimum from cursor 0: each call before the one that reaches the
/// park spends its room on summary probes alone, one group each, charging
/// a read and a repair update per probe, and the next call resumes where
/// the last stopped until the park returns.
#[test]
fn a_distant_park_is_reached_with_every_summary_probe_charged() {
    let slots = 128 * GROUP_SLOTS;
    let storage = storage(4, slots);
    let member = slots - 1;
    park_at(&storage, member);
    let minimum = storage.service_minimum();
    let mut calls = 0;
    while state(&storage, member) != SlotState::Free {
        let (_, before) = cursors(&storage);
        let (report, charged, _) = serve(&storage, minimum);
        assert_eq!(report.park_first, before);
        assert!(report.probes * PARKED_PROBE <= minimum - SERVICE_CONTROLS);
        if report.visited == 0 {
            assert!(report.budget_exhausted, "{report:?}");
            assert_eq!(report.park_covered, report.probes * GROUP_SLOTS);
            assert_eq!(charged.updates, SERVICE_CONTROLS - 1 + report.probes);
        }
        calls += 1;
        assert!(calls <= 129, "no progress: {report:?}");
    }
    assert!(calls > 1, "one minimum-funded call scanned the whole table");
}

/// A stale parked bit beside a clear flag is visited, cleared and counted
/// as skipped, with the held count at zero; the summary bit it leaves
/// beside the zero word is repaired by the next call and counted as skipped
/// too; a third call reads the summary word alone.
#[test]
fn stale_parked_and_summary_bits_count_as_skipped() {
    let storage = storage(4, 64);
    let live = storage.live_pool().unwrap();
    // The counter entry a park leaves, so the park pass runs.
    live.telemetry()
        .pending_marks
        .fetch_add(1, Ordering::Relaxed);
    live.mark_parked_slot(5);
    let fields = |report: &ServiceReport| {
        (
            report.probes,
            report.visited,
            report.held,
            report.skipped,
            report.serviced,
        )
    };
    let (stale_bit, _, _) = serve(&storage, 1 << 12);
    assert_eq!(fields(&stale_bit), (2, 1, 0, 1, 0));
    assert_eq!(live.parked_slots()[0].load(Ordering::Relaxed), 0);
    let (stale_summary, _, _) = serve(&storage, 1 << 12);
    assert_eq!(fields(&stale_summary), (2, 0, 0, 1, 0));
    assert_eq!(live.parked_summary()[0].load(Ordering::Relaxed), 0);
    let (clean, _, _) = serve(&storage, 1 << 12);
    assert_eq!(fields(&clean), (1, 0, 0, 0, 0));
    live.telemetry()
        .pending_marks
        .fetch_sub(1, Ordering::Relaxed);
}

/// A retired member in the last slot of tables of 1, 16 and 128 summary
/// groups, served by calls funded at the minimum from cursor 0: every call
/// charges each probe it makes and reads at most one summary word per group
/// it covers beside its members' reads, the calls together read every
/// summary word on the way, the member returns, and the larger table takes
/// more calls, each resuming where the last stopped instead of rereading
/// its prefix.
#[test]
fn a_distant_sparse_obligation_is_reached_across_capacities_with_every_probe_charged() {
    let mut calls_by_groups = Vec::new();
    for groups in [1, 16, 128] {
        let slots = groups * GROUP_SLOTS;
        let storage = storage(4, slots);
        let member = slots - 1;
        retire_at(&storage, member);
        let minimum = storage.service_minimum();
        let (mut calls, mut probes) = (0, 0);
        while state(&storage, member) != SlotState::Free {
            let (before, _) = cursors(&storage);
            let (report, charged, _) = serve(&storage, minimum);
            assert_eq!(report.first, before);
            // Every probe is a charged visit, and no slot but the member
            // is visited.
            assert!(report.visited <= 1);
            assert!(charged.visits >= report.probes);
            // At most one summary read per group the call enters, plus a
            // summary and a word read per member visited and per member the
            // call stopped in front of.
            assert!(
                report.probes <= report.covered / GROUP_SLOTS + 3 + 2 * (report.visited + 1),
                "{groups} groups: {report:?}"
            );
            calls += 1;
            probes += report.probes;
            assert!(calls <= groups + 1, "{groups} groups: no progress");
        }
        // Each summary word up to the member's, and its bitmap word, read
        // at least once; the call that returns the member then completes
        // its lap.
        assert!(probes > groups, "{groups} groups: {probes} probes");
        calls_by_groups.push(calls);
    }
    assert_eq!(calls_by_groups[0], 1);
    assert!(
        calls_by_groups[2] > calls_by_groups[1],
        "{calls_by_groups:?}"
    );
}

/// Retired and parked cohorts served together by minimum-funded calls: the
/// retired pass never spends the park pass's decision, so every call
/// returns at least one parked obligation while retired work remains, and
/// the park cursor advances past the parks returned while the retired
/// cursor advances on its own.
#[test]
fn the_park_pass_runs_under_its_own_cursor_and_funding() {
    const RETIRED: usize = 48;
    const PARKED: usize = 4;
    let slots = 2 * GROUP_SLOTS;
    let storage = storage(RETIRED + PARKED + 2, slots);
    (0..RETIRED).for_each(|slot| retire_at(&storage, slot));
    let parked: Vec<usize> = (0..PARKED).map(|index| GROUP_SLOTS + 10 * index).collect();
    parked.iter().for_each(|&slot| park_at(&storage, slot));
    let minimum = storage.service_minimum();
    let mut previous = cursors(&storage);
    let mut returned = 0;
    while returned < PARKED {
        let (report, _, _) = serve(&storage, minimum);
        assert_eq!((report.first, report.park_first), previous);
        let now = PARKED - pending_marks(&storage);
        assert!(now > returned, "{report:?}");
        returned = now;
        assert!(
            parked[..returned]
                .iter()
                .all(|&slot| state(&storage, slot) == SlotState::Free)
        );
        let ledger = storage.pool_report().unwrap().ledger.unwrap();
        assert!(ledger.slots.retired > 0, "the retired cohort ran out first");
        previous = cursors(&storage);
        assert!(previous.0 < RETIRED && previous.0 > 0, "{previous:?}");
        if returned < PARKED {
            assert!(previous.1 > parked[returned - 1], "{previous:?}");
        }
    }
}
