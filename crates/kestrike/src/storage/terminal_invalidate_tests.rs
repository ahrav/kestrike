//! A hold that ends with nothing stored keeps the found resident, so a transition made
//! in this call counts it.
//!
//! Both tests run one shard of capacity N = 8 with V = 2 residents, its sequence set to `TERMINAL - 2`, so
//! the next invalidation's step is the one that makes the shard terminal. The invalidation names a
//! resident's key, finds it, makes the transition, and then ends with nothing stored:
//!
//! - `Closed`: the admission cutoff closes inside the inhibition, through `remove::INTERPOSE_BEFORE_CUTOFF`,
//!   after the terminal store and before the cutoff read.
//! - `History`: the suffix is required and its log is unopened, so the removal's record is refused.
//!
//! After each, the shard reads terminal with both residents visible and a lost capacity of N - V = 6. The
//! transition itself prices the removal it expects, N - (V - 1) = 7; only the hold's end, which keeps the
//! resident, sets the count back, so 7 is what a hold that forgot the kept resident leaves. The resident
//! is then shown still mapped: an exact removal, permitted after close, finds and removes it in the
//! `Closed` case, and in the `History` case finds it and is refused its record like the invalidation.
//!
//! Each test reads its observations into a value, lets the attempt and the storage go, and then asserts,
//! so a failure ends in the test's own result line.

use std::sync::atomic::Ordering;

use super::InvalidateError;
use super::attempt_tests::{begin, invalidate, ready, shard_control};
use super::publish_tests::{TRIES, budget, completed, key, report};
use super::remove::{INTERPOSE_BEFORE_CUTOFF, RemoveError};
use crate::index::TERMINAL;

/// The shard's capacity under `attempt_tests::ready`.
const CAPACITY: usize = 8;
/// The residents each test publishes.
const RESIDENTS: usize = 2;

/// What one case observed: the invalidation's refusal, then the shard's terminal flag, visible count
/// and lost capacity after it, then the exact removal's refusal, `None` for a removal that succeeded.
#[derive(Debug, PartialEq, Eq)]
struct Observed {
    refusal: Option<InvalidateError>,
    terminal: bool,
    visible: usize,
    lost_capacity: usize,
    exact_removal: Option<RemoveError>,
}

/// Runs one case: two residents, a fill attempt on the first one's key, the sequence one step short of
/// terminal, then `fault` and the invalidation of the first resident's key.
fn observe(fault: impl FnOnce(&super::Storage<super::test_platform::TestPlatform>)) -> Observed {
    let storage = ready(2);
    let named = key(5);
    let resident = completed(&storage, named)
        .publish(TRIES, &mut budget())
        .unwrap();
    completed(&storage, key(6))
        .publish(TRIES, &mut budget())
        .unwrap();
    let attempt = begin(&storage, &named).unwrap();
    shard_control(&storage)
        .sequence
        .store(TERMINAL - 2, Ordering::SeqCst);
    fault(&storage);
    let refusal = invalidate(&storage, &named).err();
    let after = report(&storage, 0);
    let exact_removal = storage.remove(&named, resident, TRIES, &mut budget()).err();
    // A hook the invalidation did not take would close the next test's storage on this thread.
    INTERPOSE_BEFORE_CUTOFF.with(|hook| hook.set(None));
    drop(attempt);
    drop(storage);
    Observed {
        refusal,
        terminal: after.terminal,
        visible: after.visible,
        lost_capacity: after.lost_capacity,
        exact_removal,
    }
}

#[test]
fn a_terminal_transition_closed_inside_counts_the_kept_resident() {
    let observed = observe(|_| {
        INTERPOSE_BEFORE_CUTOFF.with(|hook| {
            hook.set(Some(|cutoff| cutoff.store(true, Ordering::SeqCst)));
        });
    });
    assert_eq!(
        observed,
        Observed {
            refusal: Some(InvalidateError::Closed),
            terminal: true,
            visible: RESIDENTS,
            lost_capacity: CAPACITY - RESIDENTS,
            exact_removal: None,
        }
    );
}

#[test]
fn a_terminal_transition_refused_its_record_counts_the_kept_resident() {
    let observed = observe(|storage| {
        storage.with_suffix(|log| log.require()).unwrap();
    });
    assert_eq!(
        observed,
        Observed {
            refusal: Some(InvalidateError::History),
            terminal: true,
            visible: RESIDENTS,
            lost_capacity: CAPACITY - RESIDENTS,
            exact_removal: Some(RemoveError::History),
        }
    );
}
