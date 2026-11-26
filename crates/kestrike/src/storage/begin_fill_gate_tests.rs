//! A panic inside `begin_fill`'s grant must poison the shard gate.
//! The panic runs under the hold, before the grant's cutoff read, on an ordinary call and during an unrelated unwind.

use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind, panic_any};

use super::attempt::{BeginError, INTERPOSE_BEFORE_GRANT_CUTOFF};
use super::attempt_tests::{begin, gate, ready};
use super::owner::Storage;
use super::publish_tests::key;
use super::test_platform::TestPlatform;

struct GrantPanic;

fn caught_grant_panic(storage: &Storage<TestPlatform>) -> bool {
    INTERPOSE_BEFORE_GRANT_CUTOFF.with(|hook| hook.set(Some(|_| panic_any(GrantPanic))));
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = begin(storage, &key(2));
    }));
    // Disarm even if the call returned before it reached the grant.
    INTERPOSE_BEFORE_GRANT_CUTOFF.with(|hook| hook.set(None));
    result.is_err_and(|payload| payload.is::<GrantPanic>())
}

fn assert_shard_refuses_next_grant(storage: &Storage<TestPlatform>) {
    let poisoned = gate(storage).is_poisoned();
    let refusal = begin(storage, &key(3)).err();
    assert_eq!((poisoned, refusal), (true, Some(BeginError::Contended)));
}

#[test]
fn a_grant_that_panics_under_the_shard_gate_poisons_it() {
    let storage = ready(2);
    assert!(caught_grant_panic(&storage));
    assert_shard_refuses_next_grant(&storage);
}

struct BeginOnDrop<'a> {
    storage: &'a Storage<TestPlatform>,
    caught: &'a Cell<bool>,
}

impl Drop for BeginOnDrop<'_> {
    fn drop(&mut self) {
        self.caught
            .set(std::thread::panicking() && caught_grant_panic(self.storage));
    }
}

#[test]
fn a_grant_that_panics_under_the_shard_gate_poisons_it_also_during_unwinding() {
    let storage = ready(2);
    let caught = Cell::new(false);
    let outer = catch_unwind(AssertUnwindSafe(|| {
        let _on_drop = BeginOnDrop {
            storage: &storage,
            caught: &caught,
        };
        panic!("an unrelated panic");
    }));
    assert!(outer.is_err());
    assert!(caught.get());
    assert_shard_refuses_next_grant(&storage);
}
