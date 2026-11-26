//! A budget that runs out after a paid attempt lost its exchange to another writer is `Contended`;
//! a budget that could not pay the first attempt is `BudgetExhausted`. The caller is
//! `lease::reserve_credit` with `Credit::Shared`, which returns `CreditError` and so keeps the two
//! refusals apart. The lost attempt is made deterministic with the thread-local hook
//! `lease::INTERPOSE_BEFORE_CAS`, which moves the engine-wide credit count between the
//! reservation's load and its compare-exchange.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::budget::WorkBudget;
use super::lease::{
    Credit, CreditError, INTERPOSE_BEFORE_CAS, LeaseReport, reserve_credit, return_credit,
};
use super::owner::Storage;
use super::owner_fixture::storage_leasing;
use super::test_platform::TestPlatform;

/// The lease limit of the scenario's storage; every reservation here runs below it.
const LIMIT: usize = 4;

/// Another writer's reservation: one credit added to the engine-wide count.
fn steal(counter: &AtomicUsize) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// What one reservation did, read from what production reports.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    result: Result<(), CreditError>,
    /// Coordination attempts the reservation's budget was charged.
    attempts: usize,
    /// Steps the budget has left.
    remaining: usize,
    /// The engine's lease figures after the reservation.
    report: LeaseReport,
    /// Whether the hook ran: it is taken when a compare-exchange is about to run.
    interposed: bool,
}

fn report(storage: &Storage<TestPlatform>) -> LeaseReport {
    storage.lease_report().unwrap()
}

/// One `Shared` credit reservation with `steps` budget steps while another writer's reservation
/// is armed to land between the reservation's load and its first compare-exchange.
fn reserve_against_a_writer(storage: &Storage<TestPlatform>, steps: usize) -> Outcome {
    INTERPOSE_BEFORE_CAS.with(|hook| hook.set(Some(steal)));
    let mut budget = WorkBudget::new(steps);
    let result = reserve_credit(storage, LIMIT, Credit::Shared, &mut budget);
    let interposed = INTERPOSE_BEFORE_CAS.with(|hook| hook.take().is_none());
    Outcome {
        result,
        attempts: budget.counters().coordination_attempts,
        remaining: budget.remaining(),
        report: report(storage),
        interposed,
    }
}

/// Premise of every test: a fresh storage with no credit reserved and no failed attempt counted.
fn fresh() -> Storage<TestPlatform> {
    let storage = storage_leasing(LIMIT);
    assert_eq!(
        report(&storage),
        LeaseReport {
            reserved: 0,
            cas_failed: 0,
            cas_spurious: 0,
        },
        "premise: a fresh storage reports no reserved credit and no failed attempt"
    );
    storage
}

/// The paid attempt loses its exchange to another writer and the budget of one is spent: the
/// reservation refuses `Contended`, with one attempt charged, the lost attempt counted once in
/// `cas_failed`, and no credit reserved beyond the other writer's.
#[test]
fn a_paid_attempt_that_lost_refuses_contended() {
    let storage = fresh();

    let outcome = reserve_against_a_writer(&storage, 1);

    // Premise: the other writer moved the count before the exchange, so the attempt was made
    // and lost; it did not fail with the expected value in place.
    assert!(
        outcome.interposed,
        "premise: the hook ran before the exchange"
    );
    assert_eq!(
        (outcome.attempts, outcome.remaining),
        (1, 0),
        "premise: the one attempt was paid and the budget is spent"
    );
    assert_eq!(
        outcome.report,
        LeaseReport {
            // The other writer's credit only: the reservation reserved none.
            reserved: 1,
            cas_failed: 1,
            cas_spurious: 0,
        },
        "the lost attempt adds to cas_failed once and reserves nothing"
    );
    // The judgment: the budget ran out while the lost count was nonzero.
    assert_eq!(
        outcome.result,
        Err(CreditError::Contended),
        "a budget that runs out after a lost attempt is Contended"
    );

    storage.leases().reserved.fetch_sub(1, Ordering::Relaxed);
    assert_eq!(report(&storage).reserved, 0);
}

/// A budget of zero cannot pay the first attempt: the reservation refuses `BudgetExhausted`,
/// nothing is charged, no exchange is tried (the armed hook never runs) and no figure moves.
#[test]
fn an_unpaid_first_attempt_refuses_budget_exhausted() {
    let storage = fresh();

    let outcome = reserve_against_a_writer(&storage, 0);

    assert!(
        !outcome.interposed,
        "no exchange was tried, so the hook never ran"
    );
    assert_eq!((outcome.attempts, outcome.remaining), (0, 0));
    assert_eq!(
        outcome.report,
        LeaseReport {
            reserved: 0,
            cas_failed: 0,
            cas_spurious: 0,
        }
    );
    assert_eq!(
        outcome.result,
        Err(CreditError::BudgetExhausted),
        "with neither count nonzero an exhausted budget is BudgetExhausted"
    );
}

/// The sibling: the same storage, the same writer and the same lost first attempt, with a
/// budget that pays for the retry. The reservation succeeds on the second attempt, and the
/// lost attempt is still counted once.
#[test]
fn a_lost_attempt_with_a_paid_retry_reserves_the_credit() {
    let storage = fresh();
    // The two-step budget assumes the retry succeeds. Each spurious failure under Miri consumes one extra step.
    let steps = if cfg!(miri) { 1 << 10 } else { 2 };

    let outcome = reserve_against_a_writer(&storage, steps);
    let spurious = outcome.report.cas_spurious;

    assert!(
        outcome.interposed,
        "premise: the hook ran before the first exchange"
    );
    assert!(
        cfg!(miri) || spurious == 0,
        "outside Miri the retry's exchange succeeds at once"
    );
    assert_eq!(outcome.result, Ok(()));
    assert_eq!(
        (outcome.attempts, outcome.remaining),
        (2 + spurious, steps - 2 - spurious)
    );
    assert_eq!(
        outcome.report,
        LeaseReport {
            // The other writer's credit and the reservation's own.
            reserved: 2,
            cas_failed: 1,
            cas_spurious: spurious,
        }
    );

    return_credit(&storage, Credit::Shared);
    storage.leases().reserved.fetch_sub(1, Ordering::Relaxed);
    assert_eq!(report(&storage).reserved, 0);
}
