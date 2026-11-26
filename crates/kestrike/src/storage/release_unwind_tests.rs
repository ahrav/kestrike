//! A return whose extent return panics under the pool gate, on a thread that is and is not already unwinding.
//!
//! `return_extent` promises of its held walk that "an extent whose units are not all held is corrupt, and the panic poisons the gate the caller holds", and the gate's module documentation that "a holder that panics poisons the gate on release". `Storage::return_allocation` reaches that walk for a resident outside every capture pass with no journal active.

use super::blocks::Block;
use super::gate::GateError;
use super::held::Held;
use super::owner::Storage;
use super::publish_tests::{budget, completed, index_config, key, storage};
use super::release::ReturnTransfer;
use super::test_platform::TestPlatform;

/// The transfer of a resident outside every capture pass whose locator was rewritten into a sequence handle it does not own, so its return's held walk panics under the pool gate.
fn corrupt_return(s: &Storage<TestPlatform>) -> ReturnTransfer<'_, TestPlatform> {
    let bound = completed(s, key(1));
    let handle = Held::Sequence {
        block: Block(0),
        count: 2,
    };
    s.pool().records()[bound.id().slot_index()].set_locator(handle.locator());
    bound.release()
}

/// The passing sibling: the return on a thread that is not unwinding panics and leaves the pool gate poisoned.
#[test]
fn a_return_whose_extent_return_panics_poisons_the_gate() {
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let transfer = corrupt_return(&s);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.return_allocation(transfer, &mut budget())
    }));
    assert!(caught.is_err(), "premise: the corrupt return panics");
    assert_eq!(s.pool().try_lock_quiet().err(), Some(GateError::Poisoned));
}

/// The same return made by a destructor of a thread that is already unwinding, its panic caught there: the pool gate is poisoned afterwards, as on a thread that is not unwinding.
#[test]
fn a_return_whose_extent_return_panics_during_unwinding_poisons_the_gate() {
    struct ReturnsOnDrop<'s>(
        &'s Storage<TestPlatform>,
        Option<ReturnTransfer<'s, TestPlatform>>,
    );
    impl Drop for ReturnsOnDrop<'_> {
        fn drop(&mut self) {
            let (s, transfer) = (self.0, self.1.take().unwrap());
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                s.return_allocation(transfer, &mut budget())
            }));
            assert!(caught.is_err(), "premise: the corrupt return panics");
        }
    }
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let transfer = corrupt_return(&s);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _returner = ReturnsOnDrop(&s, Some(transfer));
        panic!("an unrelated panic with a live returner");
    }));
    assert!(outcome.is_err());
    assert_eq!(s.pool().try_lock_quiet().err(), Some(GateError::Poisoned));
}
