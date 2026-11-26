//! Conservation checks at the storage interface's early exits.
//!
//! An early exit returns an error, or drops its owner, after the call
//! claimed a slot, an extent, a sequence block or an index place.
//! [`judged`] checks that the storage's holdings agree with each other and
//! with its index bindings, and [`ended`] reads the slot's state and its
//! `ABANDONED` flag. The judge fails an exit whose return leaves the tables
//! disagreeing, as a slot freed while its extent stays allocated does. The
//! slot's state fails an exit that returns nothing of a claim that wrote the
//! slot's word. A claim that took a slot from the free-slot set and never
//! wrote its word leaves the word `Free` whether or not the slot goes back,
//! so only the judge, which compares the free-slot set with the words, fails
//! such an exit that keeps the slot. A lease credit, a pending index pair, a
//! fill's place word, the escrow and a sequence block that holds no placed
//! extent are outside both checks.
//! A return the tables agree on passes the judge, so a test of an exit that
//! keeps holdings asserts which ones remain.
//!
//! The tests in this file cover the return of an owner to another storage
//! and a refused cancel of an extent reservation.

use super::SlotState;
use super::allocation::Retained;
use super::budget::WorkBudget;
use super::conservation::{Fault, Holdings};
use super::lenses::NotLive;
use super::os::Platform;
use super::owner::Storage;
use super::owner_fixture::storage;
use super::publish_tests::budget;
use super::release::ReturnError;
use super::word::{self, ABANDONED};

/// The word of a `Free` slot, without `ABANDONED`.
pub(super) const FREE: (SlotState, bool) = (SlotState::Free, false);
/// A `Filling` slot its owner still holds.
pub(super) const FILLING: (SlotState, bool) = (SlotState::Filling, false);
/// A `Filling` slot parked for service with `ABANDONED`.
pub(super) const PARKED: (SlotState, bool) = (SlotState::Filling, true);
/// A `Retired` slot with `ABANDONED`, whose extent service returns.
pub(super) const RETIRED: (SlotState, bool) = (SlotState::Retired, true);
/// A `Resident` slot parked for service with `ABANDONED`.
pub(super) const PARKED_RESIDENT: (SlotState, bool) = (SlotState::Resident, true);

/// Judges `storage`'s holdings against its index bindings and returns the
/// judge's verdict. The snapshot needs a free pool gate: a busy or poisoned
/// gate yields `Fault::Unreadable`. The binding lens refuses `NotLive` when
/// `index()` returns no index, which holds for a storage built without an
/// index and for one past `Live`, and leaves an empty binding list; past
/// `Live` the snapshot yields `Fault::Unreadable`.
pub(super) fn judged<P: Platform>(storage: &Storage<P>) -> Result<(), Fault> {
    let mut bindings = Vec::new();
    match storage.bindings_into(&mut bindings) {
        Ok(()) | Err(NotLive) => {}
    }
    let mut holdings = Holdings::default();
    storage.holdings_into(&mut holdings);
    holdings.judge(&bindings)
}

/// Derives slot `slot`'s state and its `ABANDONED` flag from one acquire
/// load of its word, without the pool gate.
///
/// # Panics
///
/// If `live_pool()` returns `None`, `slot` is out of bounds, or
/// `word::state` finds a malformed word.
fn ended<P: Platform>(storage: &Storage<P>, slot: usize) -> (SlotState, bool) {
    let held = storage.live_pool().expect("a live storage").word(slot);
    (word::state(held), held & ABANDONED != 0)
}

/// Asserts that `storage`'s holdings pass [`judged`] and that slot `slot`
/// holds `state`, its state and whether it carries `ABANDONED`.
///
/// # Panics
///
/// If either assertion fails.
#[track_caller]
pub(super) fn conserved_at<P: Platform>(
    storage: &Storage<P>,
    slot: usize,
    state: (SlotState, bool),
) {
    checked(storage, slot, state, "");
}

/// Runs one service pass over `storage` with a budget of 1024 steps, then
/// asserts what [`conserved_at`] asserts.
///
/// # Panics
///
/// If the service pass returns an error, or either assertion fails.
#[track_caller]
pub(super) fn conserved_after_service<P: Platform>(
    storage: &Storage<P>,
    slot: usize,
    state: (SlotState, bool),
) {
    storage
        .service(&mut WorkBudget::new(1 << 10))
        .expect("one service pass");
    checked(storage, slot, state, " after one service pass");
}

/// The assertions of [`conserved_at`], whose failure messages end in `when`.
#[track_caller]
fn checked<P: Platform>(storage: &Storage<P>, slot: usize, state: (SlotState, bool), when: &str) {
    assert_eq!(judged(storage), Ok(()), "the holdings{when}");
    assert_eq!(ended(storage, slot), state, "slot {slot}{when}");
}

/// A return handed to a storage other than the one that issued the owner
/// refuses `ForeignStorage` and drops the transfer, which parks the slot on
/// its own storage: the slot stays `Filling` with `ABANDONED` and its extent
/// held, both storages pass the conservation judge, and one service pass of
/// the issuing storage returns the extent and frees the slot.
#[test]
fn a_return_to_another_storage_parks_the_slot_on_its_own_storage() {
    let (issuer, other) = (storage(8), storage(8));
    let owner = issuer.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let slot = owner.id().slot_index();
    assert_eq!(
        other.return_allocation(owner.release(), &mut budget()),
        Err(ReturnError::ForeignStorage)
    );
    conserved_at(&issuer, slot, PARKED);
    assert_eq!(judged(&other), Ok(()));
    conserved_after_service(&issuer, slot, FREE);
}

/// A cancel that cannot roll its reservation back refuses `Retained` and
/// drops the owner, which abandons the extent: a written reservation under a
/// free pool gate retires its slot with `ABANDONED`, and an unwritten one
/// under a busy pool gate parks it as `Filling` with `ABANDONED`. Both pass
/// the conservation judge at the refusal, and one service pass returns the
/// extent and frees the slot.
#[test]
fn a_refused_cancel_abandons_its_extent_to_service() {
    for written in [true, false] {
        let storage = storage(8);
        let mut owner = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
        let slot = owner.id().slot_index();
        let held = if written {
            owner.mark_written();
            None
        } else {
            Some(storage.live_pool().unwrap().lock().unwrap())
        };
        assert_eq!(owner.cancel(), Err(Retained), "written {written}");
        drop(held);
        conserved_at(&storage, slot, if written { RETIRED } else { PARKED });
        conserved_after_service(&storage, slot, FREE);
    }
}
