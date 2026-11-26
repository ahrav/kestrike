//! Tests of the panics of `Tables::publish_payload`,
//! `Tables::retire_payload` and `Tables::held`: the raw-byte ledger's
//! refusal and a locator of neither form panic under the pool gate, which
//! poisons it.
//!
//! Each test first runs its operation on an untouched slot, which succeeds,
//! as the control. It then plants the corruption, a ledger byte moved under
//! its own gate hold, which it releases, or a locator stored in the record's
//! atomic word, and runs the same operation on a second slot: the
//! operation's hold reaches `Tables::publish_payload`,
//! `Tables::retire_payload` or `Tables::held`, which panics, and the gate is
//! left poisoned.

use super::held::{DIRECT_UNITS, Held};
use super::lookup_tests::{key, ready};
use super::publish_tests::{RETRIES, budget, completed};
use super::slot_tests::poisons;
use super::test_platform::TestPlatform;
use super::{ExtentLocator, RetireOutcome, ReturnOutcome, SlotIndex, SlotState, Storage};

/// The payload bytes of each fixture reservation: 4 of metadata and 20 of
/// body, which the ledger counts together.
const PAYLOAD: usize = 24;

/// The ledger's reserved and resident terms.
fn terms(storage: &Storage<TestPlatform>) -> (usize, usize) {
    let raw = storage.pool_report().unwrap().ledger.unwrap().raw;
    (raw.reserved, raw.resident)
}

/// Completing a filling slot moves its payload from reserved to resident.
/// With one reserved byte moved away first, the reserved term is below the
/// filling slot's payload: the ledger refuses, and the completion panics
/// under its pool-gate hold, which poisons the gate.
#[test]
fn a_reserved_term_below_a_filling_slots_payload_poisons_its_publication() {
    let storage = ready(8);
    let live = storage.live_pool().unwrap();

    drop(completed(&storage, key(1)).release());
    assert_eq!(terms(&storage), (0, PAYLOAD));

    let mut owner = storage.reserve(Some(4), Some(20), &mut budget()).unwrap();
    owner.mark_written();
    assert_eq!(terms(&storage), (PAYLOAD, PAYLOAD));

    let mut access = live.lock().unwrap();
    assert_eq!(access.tables().extents().publish(1), Ok(()));
    access.release();
    assert_eq!(terms(&storage), (PAYLOAD - 1, PAYLOAD + 1));

    poisons(
        &storage,
        "the raw-byte ledger holds fewer reserved bytes than a filling slot names",
        || {
            let _ = owner.complete(key(2), u64::MAX, &mut budget());
        },
    );
    assert!(storage.pool_report().unwrap().ledger.is_none());
}

/// Removing a resident object moves its payload from resident to retired.
/// With one resident byte moved away first, the resident term is below the
/// resident slot's payload: the ledger refuses, and the removal panics and
/// poisons the gate.
#[test]
fn a_resident_term_below_a_resident_slots_payload_poisons_its_retirement() {
    let storage = ready(8);
    let live = storage.live_pool().unwrap();

    let control = completed(&storage, key(1))
        .publish(RETRIES, &mut budget())
        .unwrap();
    assert_eq!(terms(&storage), (0, PAYLOAD));
    assert_eq!(
        storage.remove(&key(1), control, RETRIES, &mut budget()),
        Ok(RetireOutcome::Recorded)
    );
    assert_eq!(terms(&storage), (0, 0));

    let id = completed(&storage, key(2))
        .publish(RETRIES, &mut budget())
        .unwrap();
    assert_eq!(
        storage.slot_state(id.slot()).unwrap().0,
        SlotState::Resident
    );
    assert_eq!(terms(&storage), (0, PAYLOAD));

    let mut access = live.lock().unwrap();
    assert_eq!(access.tables().extents().retire(1), Ok(()));
    access.release();
    assert_eq!(terms(&storage), (0, PAYLOAD - 1));

    poisons(
        &storage,
        "the raw-byte ledger holds fewer resident bytes than a resident slot names",
        || {
            let _ = storage.remove(&key(2), id, RETRIES, &mut budget());
        },
    );
    assert!(storage.pool_report().unwrap().ledger.is_none());
}

/// A released reservation's return decodes what its slot holds. A length
/// of `DIRECT_UNITS + 1` is past a direct extent and tags a sequence of one
/// extent, which no sequence handle names: the return panics and poisons
/// the gate, and the record keeps the planted locator.
#[test]
fn a_locator_tag_outside_both_forms_poisons_the_return_that_decodes_it() {
    let storage = ready(8);
    let live = storage.live_pool().unwrap();

    let control = storage.reserve(Some(4), Some(20), &mut budget()).unwrap();
    let freed = control.id().slot_index();
    assert!(matches!(
        Held::decode(live.records()[freed].locator()),
        Some(Held::Direct(_))
    ));
    assert_eq!(
        storage.return_allocation(control.release(), &mut budget()),
        Ok(ReturnOutcome::Returned)
    );
    assert_eq!(
        storage.slot_state(SlotIndex(freed)).unwrap().0,
        SlotState::Free
    );

    let owner = storage.reserve(Some(4), Some(20), &mut budget()).unwrap();
    let slot = owner.id().slot_index();
    let record = &live.records()[slot];
    let neither = ExtentLocator::new(record.locator().start_unit(), DIRECT_UNITS + 1).unwrap();
    assert_eq!(Held::decode(neither), None);
    record.set_locator(neither);

    let transfer = owner.release();
    poisons(
        &storage,
        "a slot's locator names neither an extent nor a sequence",
        || {
            let _ = storage.return_allocation(transfer, &mut budget());
        },
    );
    assert_eq!(record.locator(), neither);
}
