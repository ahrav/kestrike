//! Close-service progress once interference stops, on a closed storage with a disabled, a healthy, a poisoned and a busy shard under an allowance one step below one shard's positions.
//!
//! The bound. A tour visits Index, Fills, Volume, Certify and Status. `W` is the largest spend of one tour on a twin of the fixture with no gate poisoned or held, drained by generous calls of one tour each, so `W` covers every shard's positions, removals, fill releases and slot returns.
//! A call stops in front of the first indivisible action its allowance cannot pay, leaving fewer than `A` steps unpaid, `A` the largest indivisible action: the slot service minimum, which the test checks against every call that stopped early; any other call ended a tour, which the test also checks.
//! A call also pays what resuming a stage costs beyond the twin's one call per tour: the close-gate attempt and at most one stage re-entry, a shard-gate attempt or the volume's service controls and probes, at most `V = SERVICE_MINIMUM` steps together; `V` is an analytic premise, which a too-small value would expose as a failed bound.
//! `W` is the twin's own spend, cross-checked against the geometry for coverage, so a per-step cost that every call pays alike, twin and history, raises `W` and `f` together; the defects of split and contended calls, a re-walked pass, a restarted sweep and a twice-decided position, stay visible.
//! So every call that stops early pays at least `b_eff = b - A - V` steps of tour work.
//! After the stop, the tour in progress ends, the next tour removes the busy shard's mappings and certifies their slots, and the tour after it returns them: at most `3 * W` steps, paid by calls that stop early, plus the two calls that end the first two tours and the call that meets the check, so `f = ceil(3 * W / b_eff) + 3`.
//!
//! The module also checks that the close pass credits only consecutive own calls across a foreign cursor move, on a one-shard storage of twelve slots.
//!
//! The check. By the bound's call, removals equal the mappings of every shard but the poisoned one, those shards' departed fill records are released, and the volume holds no retired or filling slot and exactly the poisoned shard's mappings as residents; a failure names the call.
//! After every call of a sweep that keeps its position, the positions the reports count decided equal the positions the index cursor passed, lap by lap, on every shard the sweep decides: all but the disabled shard and, when it is poisoned, the poisoned one; so each is decided exactly once per lap.

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::attempt_tests::begin;
use super::budget::WorkBudget;
use super::closing::{CloseStage, ClosingReport};
use super::gate::{Gate, GateError};
use super::lookup_tests::{body, key, lookup, publish, ticks};
use super::owner::Storage;
use super::publish_tests::{PAGE, RETRIES, index_config, storage_config, storage_from};
use super::release::SERVICE_MINIMUM;
use super::tables::SlotIndex;
use super::test_platform::TestPlatform;
use super::word::SlotState;
use crate::index::{IndexConfig, KeyHasher, PAIRS, ShardIndex};

/// Index shard limits: shard 0 is disabled, the others hold sixteen keys each.
const LIMITS: [usize; 4] = [0, 16, 16, 16];
/// Fill records per shard.
const FILLS: [usize; 4] = [0, 2, 2, 2];
const DISABLED: usize = 0;
const HEALTHY: usize = 1;
const POISONED: usize = 2;
const BUSY: usize = 3;
const SLOTS: usize = 64;
/// Mappings published on each enabled shard.
const MAPPED: usize = 3;
/// The call after which the busy shard's gate is released for good, a call after the sweep reached the busy and the poisoned shard.
const STOP: usize = 4;
/// A deadline 100 seconds into the engine's nanosecond timeline.
const DEADLINE: u64 = 100 * 1_000_000_000;
/// The index key pair, fixed so every run routes each key to the same shard and bucket.
const PAIR: (u64, u64) = (0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210);

/// A closed storage over [`LIMITS`] and [`FILLS`] with [`MAPPED`] mappings on each enabled shard and as many departed fill records as each table holds.
fn fixture() -> Storage<TestPlatform> {
    let index = IndexConfig {
        fills: &FILLS,
        ..index_config(&LIMITS, (1, 1), 1)
    };
    let mut storage = storage_from(&storage_config(SLOTS), &index, TestPlatform::heap(PAGE));
    storage.install_hasher(KeyHasher::with_key_pair(PAIR.0, PAIR.1));
    ticks(&storage, &[Some(1)]);
    let shard_of = |n: u8| storage.route(&key(n)).unwrap().shard().0;
    let mut mapped = [0; 4];
    for n in 0x10u8..0x80 {
        let shard = shard_of(n);
        if mapped[shard] < MAPPED {
            publish(&storage, key(n), DEADLINE, &body(n));
            mapped[shard] += 1;
        }
    }
    let mut departed = [0; 4];
    for n in 0x80u8..0xF0 {
        let shard = shard_of(n);
        if departed[shard] < FILLS[shard] {
            begin(&storage, &key(n)).unwrap().abort();
            departed[shard] += 1;
        }
    }
    assert_eq!(mapped, [0, MAPPED, MAPPED, MAPPED]);
    assert_eq!(departed, FILLS);
    storage.close();
    storage
}

/// Positions of `shard`: every pair of every physical bucket.
fn positions(storage: &Storage<TestPlatform>, shard: usize) -> usize {
    let geometry = storage.index_geometry().unwrap().shards()[shard];
    (geometry.base + geometry.overflow) * PAIRS
}

fn shard_gate(storage: &Storage<TestPlatform>, shard: usize) -> &Gate {
    let index = storage.index().unwrap();
    let image = index.image.shard(ShardIndex(shard)).unwrap();
    // SAFETY: the storage initialized the index image when it was built, and the index mapping is owned while the storage is live, which the shared borrow guarantees.
    unsafe { image.gate(&index.mapping) }
}

/// Poisons `shard`'s gate the way a holder that panics does.
fn poison(storage: &Storage<TestPlatform>, shard: usize) {
    let gate = shard_gate(storage, shard);
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _held = gate.try_lock().unwrap();
        panic!("a holder of shard {shard}'s gate panicked");
    }));
    assert!(unwound.is_err());
    assert!(matches!(gate.try_lock(), Err(GateError::Poisoned)));
}

/// Whether `storage` holds no eligible obligation: the reports' removals sum to `mappings` and their fill releases to `released`, and the ledger holds no retired or filling slot and `residents` residents.
fn drained(
    storage: &Storage<TestPlatform>,
    reports: &[ClosingReport],
    (mappings, released, residents): (usize, usize, usize),
) -> bool {
    let slots = storage.pool_report().unwrap().ledger.unwrap().slots;
    reports.iter().map(|r| r.removed).sum::<usize>() == mappings
        && reports.iter().map(|r| r.fills_released).sum::<usize>() == released
        && (slots.retired, slots.filling, slots.resident) == (0, 0, residents)
}

/// The allowance `b`, one step below one shard's positions, and the bound `f` it gives, from the twin's largest tour; asserts the premise `b > A + V`, without which `b_eff` is not positive and no `f` exists, and checks the twin's first tour against the geometry: every swept position decided once, every mapping removed and every fill record examined.
fn bound() -> (usize, usize) {
    let twin = fixture();
    let b = positions(&twin, HEALTHY) - 1;
    let action = twin.service_minimum();
    assert!(
        b > action + SERVICE_MINIMUM,
        "b = {b} cannot fund the action of {action} steps and a resumed stage"
    );
    let generous = 1 << 20;
    let mut reports = Vec::new();
    let mut tour = 0;
    while !drained(&twin, &reports, (3 * MAPPED, 3 * FILLS[HEALTHY], 0)) {
        assert!(reports.len() < 8, "the twin drains in a few tours");
        let mut budget = WorkBudget::new(generous);
        let report = twin.close_service(&mut budget).unwrap();
        assert!(report.complete, "one generous call is one tour: {report:?}");
        tour = tour.max(generous - budget.remaining());
        reports.push(report);
    }
    let first = &reports[0];
    let swept: usize = (0..4).map(|shard| positions(&twin, shard)).sum();
    assert_eq!(
        (first.positions_visited, first.removed, first.fills_visited),
        (swept, 3 * MAPPED, 3 * FILLS[HEALTHY]),
        "the twin's first tour against the geometry: {first:?}"
    );
    (b, (3 * tour).div_ceil(b - action - SERVICE_MINIMUM) + 3)
}

/// How the busy shard's gate behaves before each call.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Interference {
    /// Held through the call it names, then released for good.
    Stops(usize),
    /// Held on every call.
    Forever,
    /// Held on each call that starts with the index cursor off the busy shard, and free on each call that starts on it.
    OnArrival,
}

/// What the index sweep does after a call that found a gate busy.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sweep {
    /// Keeps the shard and position, as the close service does.
    Keeps,
    /// The planted defect: the test sends the index stage back to the first shard.
    RestartsOnBusy,
}

/// One close-service history on [`fixture`] with allowance `b`, run until the check holds, with a call after the stop reporting complete when no shard is poisoned and the interference stops, or call `limit` ends: the poisoned shard poisoned before the first call when `poisoned`, one ordinary service call moving the shared slot cursors after the first call, and the busy shard's gate as `interference` holds it.
/// Returns the call that met the check and every report, or every report and the shard the index stage visits next when call `limit` ended first.
fn drain(
    b: usize,
    interference: Interference,
    sweep: Sweep,
    poisoned: bool,
    limit: usize,
) -> Result<(usize, Vec<ClosingReport>), (Vec<ClosingReport>, usize)> {
    let storage = fixture();
    let action = storage.service_minimum();
    let sick = if poisoned {
        poison(&storage, POISONED);
        MAPPED
    } else {
        0
    };
    let wanted = (
        3 * MAPPED - sick,
        FILLS[HEALTHY] + FILLS[BUSY] + if poisoned { 0 } else { FILLS[POISONED] },
        sick,
    );
    // Positions one lap decides, and those it has decided before each shard.
    let swept = |shard: usize| shard != DISABLED && !(poisoned && shard == POISONED);
    let lap: usize = (0..4)
        .filter(|&s| swept(s))
        .map(|s| positions(&storage, s))
        .sum();
    let passed = |(shard, position): (usize, usize)| -> usize {
        let before: usize = (0..shard.min(4))
            .filter(|&s| swept(s))
            .map(|s| positions(&storage, s))
            .sum();
        before
            + if shard < 4 && swept(shard) {
                position
            } else {
                0
            }
    };
    let gate = shard_gate(&storage, BUSY);
    let cursor = &storage.close;
    let (mut laps, mut last) = (0, cursor.index_position());
    let mut held = None;
    let mut reports: Vec<ClosingReport> = Vec::new();
    for call in 1..=limit {
        let hold = match interference {
            Interference::Stops(stop) => call <= stop,
            Interference::Forever => true,
            Interference::OnArrival => cursor.index_position().0 != BUSY,
        };
        match (hold, held.is_some()) {
            (true, false) => held = Some(gate.try_lock().unwrap()),
            (false, true) => held.take().unwrap().release(),
            _ => {}
        }
        let mut budget = WorkBudget::new(b);
        let report = storage.close_service(&mut budget).unwrap();
        if report.budget_exhausted {
            assert!(
                budget.remaining() < action,
                "call {call} left {} steps unpaid, at or above the largest action",
                budget.remaining()
            );
        }
        if let Some(previous) = reports.last()
            && !previous.budget_exhausted
        {
            assert_eq!(
                report.started_in,
                CloseStage::Index,
                "call {call} follows a call that ended a tour"
            );
        }
        if sweep == Sweep::RestartsOnBusy && report.shards_busy > 0 {
            cursor.plant_index_restart();
        }
        if call == 1 {
            assert!(
                cursor.index_position().0 > DISABLED,
                "the disabled shard is one paid step to pass"
            );
            let outside = storage
                .service(&mut WorkBudget::new(storage.service_minimum()))
                .unwrap();
            assert!(outside.pending && outside.visited > 0, "{outside:?}");
        }
        reports.push(report);
        if sweep == Sweep::Keeps {
            let now = cursor.index_position();
            laps += usize::from(now < last);
            last = now;
            assert_eq!(
                reports.iter().map(|r| r.positions_visited).sum::<usize>(),
                laps * lap + passed(now),
                "call {call}: every position decided once per lap"
            );
        }
        // Without a poisoned shard, a history whose interference stops also needs a call after the stop that completes the stages it starts in.
        let settled = match interference {
            Interference::Stops(stop) if !poisoned => reports.iter().skip(stop).any(|r| r.complete),
            _ => true,
        };
        if settled && drained(&storage, &reports, wanted) {
            if let Some(guard) = held {
                guard.release();
            }
            return Ok((call, reports));
        }
    }
    Err((reports, cursor.index_position().0))
}

/// [`drain`], which must meet the check by call `limit`; `bound` names the bound in the failure, and `missed` inspects the history before the failure panics.
fn drain_by(
    b: usize,
    interference: Interference,
    sweep: Sweep,
    poisoned: bool,
    (limit, bound): (usize, &str),
    missed: impl FnOnce(&[ClosingReport], usize),
) -> (usize, Vec<ClosingReport>) {
    drain(b, interference, sweep, poisoned, limit).unwrap_or_else(|(reports, shard)| {
        missed(&reports, shard);
        panic!(
            "not drained by the bound's call {limit}, {bound}: removed {}",
            reports.iter().map(|r| r.removed).sum::<usize>()
        )
    })
}

/// With the busy shard released after call [`STOP`], every eligible obligation drains by call `STOP + f`; before the stop the history witnessed a busy gate, a poisoned gate and the disabled shard passed.
/// The poisoned shard stays a blocker after the stop, and a call that counts it never reports complete.
#[test]
fn every_eligible_obligation_drains_within_the_bound_once_interference_stops() {
    let (b, f) = bound();
    let (met, reports) = drain_by(
        b,
        Interference::Stops(STOP),
        Sweep::Keeps,
        true,
        (STOP + f, "STOP + f"),
        |_, _| {},
    );
    assert!(
        STOP < met && met <= STOP + f,
        "drained at call {met}, after the stop at call {STOP}, within STOP + f = {}",
        STOP + f
    );
    let before = &reports[..STOP];
    assert!(before.iter().any(|r| r.shards_busy > 0), "{before:?}");
    assert!(
        before.iter().any(|r| r.blockers.poisoned_gates > 0),
        "{before:?}"
    );
    assert!(
        reports[STOP..]
            .iter()
            .any(|r| r.blockers.poisoned_gates > 0)
    );
    for report in &reports {
        assert!(
            !(report.complete && report.blockers.poisoned_gates > 0),
            "{report:?}"
        );
    }
}

/// The same history with no shard poisoned drains by call `STOP + f` with a call after the stop that completes the stages it starts in.
#[test]
fn without_a_poisoned_shard_a_call_after_the_stop_completes_within_the_bound() {
    let (b, f) = bound();
    let (_, reports) = drain_by(
        b,
        Interference::Stops(STOP),
        Sweep::Keeps,
        false,
        (STOP + f, "STOP + f"),
        |_, _| {},
    );
    assert!(reports[..STOP].iter().any(|r| r.shards_busy > 0));
    assert!(reports.iter().all(|r| r.blockers.poisoned_gates == 0));
}

/// The bound holds wherever the stop falls: for every stop call from the first through `f`, the history drains by `stop + f`, and the stops fall in more than one stage.
#[test]
fn the_bound_holds_for_every_stop_through_f() {
    let (b, f) = bound();
    let mut stages = Vec::new();
    for stop in 1..=f {
        let (met, reports) = drain_by(
            b,
            Interference::Stops(stop),
            Sweep::Keeps,
            true,
            (stop + f, "stop + f"),
            |_, _| {},
        );
        assert!(met <= stop + f, "stop {stop}: drained at call {met}");
        if let Some(next) = reports.get(stop) {
            stages.push(next.started_in);
        }
    }
    assert!(stages.contains(&CloseStage::Index));
    assert!(
        stages.iter().any(|stage| *stage != CloseStage::Index),
        "{stages:?}"
    );
}

/// A gate held forever, with no shard poisoned: the index stage stays at the busy shard, every shard's mappings but the busy one's are removed, every call that finds the gate busy is incomplete, the fills, volume, certification and status stages keep running, and the check fails at the bound's call.
#[test]
#[should_panic(expected = "not drained by the bound's call")]
fn negative_control_a_gate_held_forever_leaves_the_index_stage_uncredited() {
    let (b, f) = bound();
    let missed = |reports: &[ClosingReport], shard: usize| {
        let sum = |field: fn(&ClosingReport) -> usize| -> usize { reports.iter().map(field).sum() };
        assert_eq!(shard, BUSY, "the index stage stays at the busy shard");
        assert_eq!(
            sum(|r| r.removed),
            2 * MAPPED,
            "every shard but the busy one"
        );
        assert!(sum(|r| r.shards_busy) > 0);
        assert!(reports.iter().all(|r| r.shards_busy == 0 || !r.complete));
        assert!(sum(|r| r.fill_calls) > 0);
        assert!(sum(|r| r.service_calls) > 0);
        assert!(sum(|r| r.records_visited) > 0);
        assert!(reports.iter().any(|r| r.certified.is_some()));
    };
    drain_by(
        b,
        Interference::Forever,
        Sweep::Keeps,
        false,
        (STOP + f, "STOP + f"),
        missed,
    );
}

/// A gate busy whenever the sweep arrives at its shard and free whenever a call starts on it: the sweep keeps the busy shard's position, so the call after each busy observation starts on the shard and sweeps it.
///
/// Bound: a call that finds the gate busy keeps the busy position, pays the gate attempt and moves on to later stages that the tours would also pay, so the next tour's index stage starts at the kept position with the gate free and each tour takes at most one busy observation; at most twice the work of the uninterfered tours, the history drains within `2 * f` calls.
/// The busy shard's fill table is serviced only in a call that started on the busy shard with its gate free; the drain check, which counts its fill records, witnesses that such a call reached it.
#[test]
fn a_shard_busy_on_each_arrival_is_still_swept_within_twice_the_bound() {
    let (b, f) = bound();
    let (_, reports) = drain_by(
        b,
        Interference::OnArrival,
        Sweep::Keeps,
        true,
        (2 * f, "2 * f"),
        |_, _| {},
    );
    assert!(reports.iter().any(|r| r.shards_busy > 0));
}

/// The planted sweep that restarts on a busy gate: each busy observation sends the index stage back to the first shard, the next call starts off the busy shard with its gate held, and the obligations on the busy shard are never reached.
#[test]
#[should_panic(expected = "not drained by the bound's call")]
fn negative_control_a_sweep_restarting_on_a_busy_gate_never_reaches_the_busy_shard() {
    let (b, f) = bound();
    drain_by(
        b,
        Interference::OnArrival,
        Sweep::RestartsOnBusy,
        true,
        (2 * f, "2 * f"),
        |reports, shard| {
            let removed: usize = reports.iter().map(|r| r.removed).sum();
            assert_eq!(removed, MAPPED, "the healthy shard's mappings only");
            assert_ne!(shard, BUSY, "each restart leaves the busy shard");
        },
    );
}

/// Credit across a foreign move: an ordinary service call between two budget-split close calls moves the shared slot cursor past a leased slot, so the close pass's own calls must examine that slot again before the volume stage completes.
/// With `plant`, the test makes the ordinary call's end the cursor position that resumes the pass's count, which credits the ordinary call's positions to the pass.
///
/// Geometry: twelve retired slots, the lease on slot 4. The pass's first call returns slots 0 to 2 and stops in front of slot 3; the ordinary call returns slot 3, finds slot 4 held and returns slot 5; each later close call returns two slots until slot 11, so the planted credit reaches twelve positions on the call that returns slots 10 and 11 and stops in front of slot 4, which the restarted count reaches one call later.
///
/// Bound: each close call the service minimum funds decides at least the slot at its cursor, the guaranteed floor `c_min = 1`, so the pass completes within `ceil(slots / c_min) = slots` of its own calls after the foreign move; the check asserts that it does and that it counts the leased slot held.
/// Once the lease ends, the rest of the tour in progress certifies the slot's grace and the next tour's volume stage returns it, so two generous calls, each ending at a tour's end, return it.
fn credit_after_a_foreign_move(plant: bool) {
    const LEASED: usize = 4;
    const TOURS_TO_RETURN: usize = 2;
    let mut storage = super::publish_tests::storage(12, &index_config(&[12], (1, 1), 1));
    storage.install_hasher(KeyHasher::with_key_pair(PAIR.0, PAIR.1));
    ticks(&storage, &[Some(1)]);
    let ids: Vec<_> = (0x41u8..0x4D)
        .map(|n| publish(&storage, key(n), DEADLINE, &body(n)))
        .collect();
    let leased = ids.iter().position(|id| id.slot_index() == LEASED).unwrap();
    let mut reader = storage.register().unwrap();
    let lease = lookup(&mut reader, &key(0x41 + leased as u8), RETRIES).unwrap();
    storage.close();
    let generous = || WorkBudget::new(4096);
    // One tour removes every mapping and certifies.
    while !storage.close_service(&mut generous()).unwrap().complete {}
    // The close-gate attempt, the shard's gate attempt and every position: the index stage exactly.
    let index_stage = 1 + 1 + positions(&storage, 0);
    let report = storage
        .close_service(&mut WorkBudget::new(index_stage))
        .unwrap();
    assert!(report.budget_exhausted, "{report:?}");
    let split = 1 + storage.service_minimum();
    let report = storage.close_service(&mut WorkBudget::new(split)).unwrap();
    assert_eq!(report.started_in, CloseStage::Volume, "{report:?}");
    assert_eq!((report.slots_visited, report.blockers.held_slots), (3, 0));
    let slots = storage.pool_report().unwrap().descriptor.slot_count;
    let outside = storage
        .service(&mut WorkBudget::new(storage.service_minimum()))
        .unwrap();
    assert_eq!(
        (outside.first, outside.covered, outside.held),
        (3, 3, 1),
        "{outside:?}"
    );
    if plant {
        storage
            .close
            .plant_retired_resume((outside.first + outside.covered) % slots);
    }
    let mut held = 0;
    let mut own = 0;
    loop {
        let report = storage.close_service(&mut WorkBudget::new(split)).unwrap();
        if report.started_in != CloseStage::Volume {
            break;
        }
        own += 1;
        assert!(
            own <= slots,
            "the pass took more than {slots} of its own calls"
        );
        held += report.blockers.held_slots;
    }
    assert!(
        held != 0,
        "held 0: the volume stage completed after {own} own calls with leased slot {LEASED} unexamined"
    );
    assert_eq!(held, 1, "the pass counts the leased slot once");
    let state = |storage: &Storage<TestPlatform>| {
        storage
            .slot_state(SlotIndex(LEASED))
            .map(|(state, _)| state)
    };
    assert_eq!(state(&storage), Some(SlotState::Retired));
    drop(lease);
    drop(reader);
    for _ in 0..TOURS_TO_RETURN {
        assert!(storage.close_service(&mut generous()).unwrap().complete);
    }
    assert_eq!(state(&storage), Some(SlotState::Free));
}

#[test]
fn a_slot_a_foreign_move_skipped_is_examined_before_the_stage_completes_and_released_later() {
    credit_after_a_foreign_move(false);
}

#[test]
#[should_panic(expected = "held 0: the volume stage completed")]
fn negative_control_credit_across_a_foreign_move_completes_the_stage_with_the_slot_unexamined() {
    credit_after_a_foreign_move(true);
}
