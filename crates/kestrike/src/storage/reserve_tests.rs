//! Tests of the readiness check a fill reservation makes after its early
//! cutoff read.
//!
//! A withdrawal that lands after a reservation's early cutoff read and
//! before its gate try leaves the cutoff open, so the readiness read that
//! follows the withdrawal is the one check that refuses the reservation.
//! The refused reservation is charged its gate try and no update, and
//! leaves the ledger, every slot, the free-slot set and the extent bitmap
//! as they were. The interposed step runs the withdrawal between the
//! early cutoff read and the gate try: the tests assert that readiness
//! is read after that step and that the refusal follows the take of the
//! gate. A control test admits the same reservation with no withdrawal.

use std::cell::Cell;
use std::sync::atomic::AtomicBool;

use super::boundary_tests::free_runs;
use super::readiness::{Event, State};
use super::reserve::INTERPOSE_AFTER_OPEN_READ;
use super::test_platform::TestPlatform;
use super::{ReserveError, SlotIndex, Storage, WorkBudget};

thread_local! {
    /// The storage whose readiness the interposed step withdraws.
    static PAUSED: Cell<Option<&'static Storage<TestPlatform>>> = const { Cell::new(None) };
}

/// Withdraws the paused storage's readiness, leaving its admission cutoff
/// open, and zeroes the probe's counts for the steps that follow.
fn withdraw(_cutoff: &AtomicBool) {
    let storage = PAUSED.take().expect("a test planted its storage");
    assert_eq!(storage.withdraw(), State::Withheld);
    super::probe::arm();
}

/// The ledger, every slot's state and incarnation, which slots the
/// free-slot set holds, and the free runs of the extent bitmap.
fn tables(storage: &Storage<TestPlatform>) -> impl PartialEq + std::fmt::Debug {
    let report = storage.pool_report().unwrap();
    let count = report.descriptor.slot_count;
    let slots: Vec<_> = (0..count)
        .map(|slot| storage.slot_state(SlotIndex(slot)))
        .collect();
    let free_slots: Vec<bool> = {
        let mut access = storage.live_pool().unwrap().lock().unwrap();
        let mut tables = access.tables();
        let free = tables.free_slots();
        (0..count).map(|slot| free.contains(slot)).collect()
    };
    (
        report.ledger.expect("the gate is not poisoned"),
        slots,
        free_slots,
        free_runs(storage),
    )
}

/// A withdrawal that lands after the reservation's early cutoff read and
/// before its gate try leaves the cutoff open, so a readiness read made
/// after it is the one check that refuses: the reservation takes the pool
/// gate once, refuses `Closed`, is charged its gate try and no update, and
/// leaves the ledger, every slot, the free set and the extent bitmap intact.
#[test]
fn a_withdrawal_between_the_open_read_and_the_gate_try_refuses_the_reservation_and_writes_nothing()
{
    let storage: &'static Storage<TestPlatform> =
        Box::leak(Box::new(super::owner_fixture::storage(8)));
    storage.readiness.apply(Event::Attach).unwrap();
    storage.readiness.apply(Event::LoadComplete).unwrap();
    let begin = Event::BeginReplay {
        matches: true,
        rows: 0,
    };
    storage.readiness.apply(begin).unwrap();
    assert_eq!(storage.readiness.state(), State::Live);
    let before = tables(storage);

    PAUSED.set(Some(storage));
    INTERPOSE_AFTER_OPEN_READ.with(|hook| hook.set(Some(withdraw)));
    let mut budget = WorkBudget::new(1 << 20);
    let reserved = storage.reserve(Some(0), Some(100), &mut budget);
    assert!(
        INTERPOSE_AFTER_OPEN_READ.with(|hook| hook.get().is_none()) && PAUSED.get().is_none(),
        "the withdrawal ran inside the reservation, after its open read"
    );
    assert_eq!(storage.readiness.state(), State::Withheld);
    assert!(
        !storage.is_closed(),
        "the cutoff stays open, so only the readiness read can refuse"
    );
    assert_eq!(
        reserved.err(),
        Some(ReserveError::Closed),
        "the readiness read that follows the withdrawal refuses"
    );
    assert_eq!(
        super::probe::counts().gate_taken,
        1,
        "the refusal follows the take of the pool gate"
    );
    assert_eq!(
        tables(storage),
        before,
        "the refusal precedes every slot, free-set and ledger write"
    );
    assert_eq!(
        (
            budget.counters().coordination_attempts,
            budget.counters().updates
        ),
        (1, 0),
        "the gate try is the only step the refused reservation is charged"
    );
}

/// The control: with no withdrawal in between, the same reservation at
/// `Live` is admitted and claims a slot.
#[test]
fn the_same_reservation_at_live_with_no_withdrawal_claims_a_slot() {
    let storage = super::owner_fixture::storage(8);
    storage.readiness.apply(Event::Attach).unwrap();
    storage.readiness.apply(Event::LoadComplete).unwrap();
    let begin = Event::BeginReplay {
        matches: true,
        rows: 0,
    };
    storage.readiness.apply(begin).unwrap();
    let before = tables(&storage);
    let mut budget = WorkBudget::new(1 << 20);
    let reserved = storage.reserve(Some(0), Some(100), &mut budget).unwrap();
    assert!(tables(&storage) != before, "an admitted reservation claims");
    drop(reserved);
}
