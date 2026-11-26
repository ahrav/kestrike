//! Service returns at most one extent per visit: a slot that holds a
//! sequence keeps its incarnation, its pending membership and its block
//! while its extents return one per visit from the last, and its final
//! return frees the last extent, the block and the slot once. Cases: every
//! prefix of two- and three-extent objects from the retired and the park
//! pass, each visit funded at the call minimum; a held large object beside
//! an eligible small one; the anchor, a lease's right and device access
//! each withheld alone, the device's access standing as a right;
//! in-flight units; maintenance; close; finalization; a planted cancel that
//! frees a device-held extent, which a free-set check of that extent
//! detects; and the return's guard against an outstanding right.
//! Every visit is checked against the sequence census of `sequence_tests`.

use std::sync::atomic::Ordering;

use super::ExtentReservation;
use super::extent::HeldPhase;
use super::geometry::EXTENT_PAYLOAD;
use super::owner::Storage;
use super::probe::{self, Event};
use super::release::ServiceReport;
use super::sequence_tests::{Object, budget, built, census, storage, whole};
use super::tables::SlotState;
use super::test_platform::TestPlatform;
use super::word;

/// The domain's retired charge.
fn retired_units(storage: &Storage<TestPlatform>) -> u64 {
    let mut access = storage.live_pool().unwrap().lock().unwrap();
    access.tables().domain.retired_units
}

/// The slot's state and incarnation.
fn identity(storage: &Storage<TestPlatform>, slot: usize) -> (SlotState, u32) {
    let current = storage.live_pool().unwrap().records()[slot]
        .ident
        .load(Ordering::Relaxed);
    (word::state(current), word::incarnation(current))
}

/// One service call funded at the call minimum, with its events.
fn visit(storage: &Storage<TestPlatform>) -> (ServiceReport, Vec<Event>) {
    let mut minimum = super::budget::WorkBudget::new(storage.service_minimum());
    probe::arm();
    let report = storage.service(&mut minimum).unwrap();
    probe::disarm();
    let log = probe::events();
    assert!(!log.overflowed);
    (report, log.events)
}

/// Takes the last extent off `object`, as a visit returns it.
fn pop(object: &mut Object) -> u32 {
    let index = object.extents.len() - 1;
    object.extents.pop();
    object.payload -= if index as u32 + 1 == object.count {
        object.payload - index * EXTENT_PAYLOAD as usize
    } else {
        EXTENT_PAYLOAD as usize
    };
    index as u32
}

/// Ends `reservation` with the gate free, which retires it, or with the
/// gate held, which parks it.
fn end(
    storage: &Storage<TestPlatform>,
    reservation: ExtentReservation<'_, TestPlatform>,
    parked: bool,
) {
    if parked {
        let held = storage.live_pool().unwrap().lock().unwrap();
        drop(reservation);
        drop(held);
    } else {
        drop(reservation);
    }
}

/// Visits `object`'s slot until its final return: each visit before the
/// last returns the last held extent and leaves the slot's identity, and
/// the final one frees the slot. Returns the visits it took.
fn drain(storage: &Storage<TestPlatform>, mut object: Object, phase: HeldPhase) -> usize {
    let slot = object.owner.slot_index();
    let before = identity(storage, slot);
    for visits in 1.. {
        let (report, mut events) = visit(storage);
        // A visit may release the anchor before it returns an extent.
        events.retain(|event| !matches!(event, Event::AnchorRelease { .. }));
        if object.extents.len() >= 2 {
            let extent = pop(&mut object);
            assert_eq!((report.partial, report.serviced), (1, 0), "{report:?}");
            assert_eq!(
                events,
                [Event::ExtentReturn {
                    slot,
                    incarnation: object.owner.incarnation(),
                    extent,
                    phase,
                }]
            );
            assert_eq!(identity(storage, slot), before, "the slot persists");
            census(storage, &[&object], 0).unwrap();
            if phase == HeldPhase::Retired {
                let held: u64 = object
                    .extents
                    .iter()
                    .map(|e| u64::from(e.len_units()))
                    .sum();
                assert_eq!(retired_units(storage), held, "the retired charge");
            }
        } else {
            assert_eq!(report.serviced, 1, "{report:?}");
            assert_eq!(report.partial, 0);
            assert_eq!(events, [Event::Return { slot }]);
            assert_eq!(identity(storage, slot).0, SlotState::Free);
            assert_eq!(retired_units(storage), 0, "the retired charge");
            census(storage, &[], 0).unwrap();
            assert!(whole(storage));
            return visits;
        }
    }
    unreachable!()
}

/// Every prefix of a two- or three-extent object, retired or parked,
/// returns one extent per minimum-funded visit from its last, keeps its
/// slot, incarnation and block until the final visit, and frees them
/// there once: a prefix of `h` extents takes `max(h, 1)` visits.
#[test]
fn every_prefix_returns_one_extent_per_visit_and_the_slot_at_the_last() {
    for parked in [false, true] {
        for count in [2, 3] {
            for held in 0..=count {
                let storage = storage();
                let reservation = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
                let object = built(&storage, &reservation, count, held);
                end(&storage, reservation, parked);
                let phase = if parked {
                    HeldPhase::Reserved
                } else {
                    HeldPhase::Retired
                };
                let state = if parked {
                    SlotState::Filling
                } else {
                    SlotState::Retired
                };
                assert_eq!(identity(&storage, object.owner.slot_index()).0, state);
                census(&storage, &[&object], 0).unwrap();
                let visits = drain(&storage, object, phase);
                assert_eq!(visits, (held as usize).max(1), "{parked} {count} {held}");
            }
        }
    }
}

/// Stands for one right on `slot`'s word, as a fill's write in flight or
/// a volume read holds one, or gives it back.
fn right(storage: &Storage<TestPlatform>, slot: usize, held: bool) {
    let ident = &storage.live_pool().unwrap().records()[slot].ident;
    if held {
        ident.fetch_add(word::REF, Ordering::AcqRel);
    } else {
        ident.fetch_sub(word::REF, Ordering::AcqRel);
    }
}

/// One minimum-funded visit that returns nothing: the object, its slot and
/// the census stay as they were. Returns the visit's events.
fn held(storage: &Storage<TestPlatform>, object: &Object) -> Vec<Event> {
    let slot = object.owner.slot_index();
    let before = identity(storage, slot);
    let (report, events) = visit(storage);
    assert_eq!(
        (report.partial, report.serviced, report.held),
        (0, 0, 1),
        "{report:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::ExtentReturn { .. } | Event::Return { .. })),
        "{events:?}"
    );
    assert_eq!(identity(storage, slot), before);
    census(storage, &[object], 0).unwrap();
    events
}

/// A retired three-extent object held by a right beside an eligible small
/// one: each minimum-funded call returns the small one and leaves every
/// extent of the large one in place; once the right ends, the large one
/// returns one extent per call. A call one step short of the minimum
/// refuses with nothing done.
#[test]
fn a_held_large_object_stays_whole_while_a_small_one_returns() {
    let storage = storage();
    let large = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let object = super::sequence_tests::sequence(&storage, &large, 3);
    let slot = object.owner.slot_index();
    drop(large);
    right(&storage, slot, true);
    for _ in 0..2 {
        let small = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
        let small_slot = small.id().slot_index();
        drop(small);
        let (report, _) = visit(&storage);
        assert_eq!((report.serviced, report.held), (1, 1), "{report:?}");
        assert_eq!(identity(&storage, small_slot).0, SlotState::Free);
        census(&storage, &[&object], 0).unwrap();
    }
    let cursors = {
        let mut access = storage.live_pool().unwrap().lock().unwrap();
        let tables = access.tables();
        (tables.state.cursor_slot, tables.state.cursor_park)
    };
    let mut short = super::budget::WorkBudget::new(storage.service_minimum() - 1);
    assert_eq!(
        storage.service(&mut short).err(),
        Some(super::release::ServiceError::BudgetExhausted)
    );
    {
        let mut access = storage.live_pool().unwrap().lock().unwrap();
        let tables = access.tables();
        assert_eq!(
            (tables.state.cursor_slot, tables.state.cursor_park),
            cursors
        );
    }
    census(&storage, &[&object], 0).unwrap();
    right(&storage, slot, false);
    assert_eq!(drain(&storage, object, HeldPhase::Retired), 3);
}

/// A published three-extent object retired with its anchor and a lease:
/// each blocker withheld alone holds every extent, the anchor until grace
/// certifies the retirement and the lease's right until it ends, and once
/// both end the object returns one extent per visit.
#[test]
fn each_blocker_withheld_alone_holds_a_published_sequence() {
    for lease_held in [false, true] {
        let storage = storage();
        let mut owner = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
        owner.mark_written();
        let id = owner.id();
        let completed = owner
            .complete([0x5a; 32], u64::MAX, &mut budget())
            .ok()
            .unwrap();
        let (resident, lease) = completed.handoff(&mut budget()).ok().unwrap();
        let object = super::sequence_tests::published_sequence(&storage, id, 3);
        drop(resident);
        let lease = if lease_held {
            Some(lease)
        } else {
            drop(lease);
            None
        };
        // The anchor withheld: grace has not certified the retirement.
        let events = held(&storage, &object);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::AnchorRelease { .. }))
        );
        assert!(storage.certify(&mut budget()).unwrap().certified.is_some());
        if let Some(lease) = lease {
            // The right withheld: this visit releases the anchor and the
            // lease's right remains.
            let events = held(&storage, &object);
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event, Event::AnchorRelease { .. })),
                "{events:?}"
            );
            drop(lease);
        }
        assert_eq!(drain(&storage, object, HeldPhase::Retired), 3);
    }
}

/// A completed sequence object parked while linked in the eviction domain
/// leaves the domain at the park pass's first sighting, the visit that
/// returns its first extent, and stays detached until the final return
/// uncounts it: the domain never counts a member whose extents are
/// returning.
#[test]
fn a_parked_linked_sequence_leaves_the_domain_at_its_first_partial_return() {
    let storage = storage();
    let mut owner = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    owner.mark_written();
    let id = owner.id();
    let slot = id.slot_index();
    let completed = owner
        .complete([0x5a; 32], u64::MAX, &mut budget())
        .ok()
        .unwrap();
    let object = super::sequence_tests::published_sequence(&storage, id, 3);
    let members = |storage: &Storage<TestPlatform>| {
        let live = storage.live_pool().unwrap();
        let mut access = live.lock().unwrap();
        let mut tables = access.tables();
        (tables.queue().members(), tables.domain.detached)
    };
    assert_eq!(members(&storage), (vec![slot], 0), "completed and linked");
    // The gate held while the owner drops parks the slot, resident and
    // linked, for the park pass.
    let gate = storage.live_pool().unwrap().lock().unwrap();
    drop(completed);
    drop(gate);
    assert_eq!(identity(&storage, slot).0, SlotState::Resident);
    let (report, events) = visit(&storage);
    assert_eq!((report.partial, report.serviced), (1, 0), "{report:?}");
    assert!(
        events.contains(&Event::Detached { slot }),
        "the first sighting detaches the slot: {events:?}"
    );
    assert_eq!(
        members(&storage),
        (vec![], 1),
        "detached at the first visit"
    );
    let mut object = object;
    pop(&mut object);
    census(&storage, &[&object], 0).unwrap();
    assert_eq!(drain(&storage, object, HeldPhase::Resident), 2);
    assert_eq!(
        members(&storage),
        (vec![], 0),
        "the final return uncounts it"
    );
}

/// A right withheld alone holds a sequence at every prefix cut of three
/// extents: a visit before any return, after one returned and after two,
/// with the final return next, each leave the object as it was.
#[test]
fn a_right_withheld_alone_holds_the_sequence_at_every_cut() {
    for returned in 0..3 {
        let storage = storage();
        let reservation = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
        let mut object = super::sequence_tests::sequence(&storage, &reservation, 3);
        let slot = object.owner.slot_index();
        drop(reservation);
        for _ in 0..returned {
            let (report, _) = visit(&storage);
            assert_eq!(report.partial, 1);
            pop(&mut object);
            census(&storage, &[&object], 0).unwrap();
        }
        right(&storage, slot, true);
        held(&storage, &object);
        right(&storage, slot, false);
        drain(&storage, object, HeldPhase::Retired);
    }
}

/// Visits a retired three-extent object whose last extent the device
/// holds, judged by a free-set check of that extent: every returned
/// extent lies outside the device's. A right on the slot stands for the
/// device's access. With `cancel_frees`, the planted defect: the history
/// ends that right, as a cancel alone would, while the device still holds
/// the extent.
fn device_held(cancel_frees: bool) {
    let storage = storage();
    let reservation = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let object = super::sequence_tests::sequence(&storage, &reservation, 3);
    let slot = object.owner.slot_index();
    let device = *object.extents.last().unwrap();
    drop(reservation);
    right(&storage, slot, true);
    if cancel_frees {
        right(&storage, slot, false);
    }
    for _ in 0..3 {
        visit(&storage);
        let live = storage.live_pool().unwrap();
        let mut access = live.lock().unwrap();
        let free = access.tables().extents().free_set();
        let start = device.start_unit();
        let overlaps = free
            .iter()
            .any(|&(at, len)| at < start + u64::from(device.len_units()) && start < at + len);
        assert!(!overlaps, "a device-held extent returned to the free set");
    }
    right(&storage, slot, false);
    drain(&storage, object, HeldPhase::Retired);
}

/// The right standing for the device's access holds the object while the
/// device holds its extent, and the free-set check passes.
#[test]
fn a_device_held_extent_stays_owned_until_its_access_ends() {
    device_held(false);
}

/// The planted control: the history ends the access while the device
/// still holds the extent, the visit returns it, and the free-set check
/// detects the planted defect.
#[test]
#[should_panic(expected = "a device-held extent returned to the free set")]
fn negative_control_a_cancel_that_frees_a_device_held_extent_fails() {
    device_held(true);
}

/// The return a visit makes fails closed at its guard when called while a
/// right still holds the object.
#[test]
#[should_panic(expected = "an extent returned while a right or the anchor is outstanding")]
fn a_return_under_an_outstanding_right_fails_closed() {
    let storage = storage();
    let reservation = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let object = super::sequence_tests::sequence(&storage, &reservation, 3);
    let slot = object.owner.slot_index();
    drop(reservation);
    right(&storage, slot, true);
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let (block, count, _) = tables.sequence(slot).unwrap();
    let _ =
        super::reserve::return_last(&mut tables, live, slot, (block, count), HeldPhase::Retired);
}

/// A sequence marked in flight shrinks the domain's in-flight units by
/// each extent a visit returns, and its final return clears the in-flight
/// count with the last extent's units.
#[test]
fn in_flight_units_shrink_with_each_returned_extent() {
    let storage = storage();
    let reservation = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let mut object = super::sequence_tests::sequence(&storage, &reservation, 3);
    let slot = object.owner.slot_index();
    drop(reservation);
    let live = storage.live_pool().unwrap();
    let in_flight = || {
        let mut access = live.lock().unwrap();
        let domain = *access.tables().domain;
        (domain.in_flight, domain.in_flight_units)
    };
    let units = |object: &Object| -> u64 {
        object
            .extents
            .iter()
            .map(|e| u64::from(e.len_units()))
            .sum()
    };
    {
        let mut access = live.lock().unwrap();
        let mut tables = access.tables();
        let held = tables.held_units(slot);
        tables.queue().mark_evicted(slot, held);
    }
    assert_eq!(in_flight(), (1, units(&object)));
    while object.extents.len() >= 2 {
        assert_eq!(visit(&storage).0.partial, 1);
        pop(&mut object);
        census(&storage, &[&object], 0).unwrap();
        assert_eq!(in_flight(), (1, units(&object)));
    }
    visit(&storage);
    assert_eq!(in_flight(), (0, 0));
    assert!(whole(&storage));
}

/// Close and finalization wait for a sequence's last visit: after close,
/// every visit before the final one leaves the object pending and
/// finalization blocked, and the final one lets finalization drain.
#[test]
fn finalization_drains_a_sequence_only_after_its_final_visit() {
    let mut storage = storage();
    let reservation = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let mut object = super::sequence_tests::sequence(&storage, &reservation, 3);
    drop(reservation);
    storage.close();
    while object.extents.len() >= 2 {
        assert_eq!(storage.outstanding().pending, 1);
        assert_eq!(visit(&storage).0.partial, 1);
        pop(&mut object);
        census(&storage, &[&object], 0).unwrap();
        let blockers = super::test_platform::blocked(&mut storage);
        assert_ne!(blockers, Default::default());
    }
    visit(&storage);
    assert!(storage.outstanding().is_clear());
    let drained = (0..8).any(|_| {
        matches!(
            super::test_platform::finalize(&mut storage),
            Ok(super::finalize::Finalization::Drained)
        )
    });
    assert!(drained, "finalization drains once the sequence returned");
}

/// Maintenance reports more work while a sequence still holds extents:
/// every call whose Reclaim stage returned an extent ahead of the final
/// return says so, and calls continue until the object is whole.
#[test]
fn maintenance_reports_more_work_until_the_final_visit() {
    let storage = super::sequence_tests::storage_with(
        4,
        Some(super::volume::VolumeWatermarks {
            low_units: 200,
            min_free_slots: 1,
            retired_units: u64::MAX,
        }),
    );
    let reservation = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let mut object = super::sequence_tests::sequence(&storage, &reservation, 3);
    drop(reservation);
    let mut partial = 0;
    for _ in 0..64 {
        if whole(&storage) {
            assert_eq!(partial, 2, "two extents returned ahead of the final one");
            return;
        }
        let Ok(super::Maintained::Open(report)) = storage.maintain(&mut budget()) else {
            panic!("an open storage's maintenance refused");
        };
        if report.reclaim.ran && object.extents.len() >= 2 && report.reclaimed_bytes != 0 {
            assert!(report.more_work && !report.reclaim.done, "{report:?}");
            partial += 1;
            pop(&mut object);
            census(&storage, &[&object], 0).unwrap();
        }
    }
    panic!("maintenance never returned the whole sequence");
}

/// A close-service call that returns one extent of a retired sequence
/// counts the slot as held, so no close call reports a complete pass with
/// no held slot until the final visit.
#[test]
fn a_close_pass_counts_a_partly_returned_sequence_as_held() {
    let storage = super::sequence_tests::storage_with(
        4,
        Some(super::volume::VolumeWatermarks {
            low_units: 200,
            min_free_slots: 1,
            retired_units: u64::MAX,
        }),
    );
    let reservation = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    super::sequence_tests::sequence(&storage, &reservation, 3);
    drop(reservation);
    storage.close();
    let mut held = 0;
    for _ in 0..64 {
        let Ok(super::Maintained::Closed(report)) = storage.maintain(&mut budget()) else {
            panic!("a closed storage's maintenance did not close");
        };
        held += report.blockers.held_slots;
        if whole(&storage) {
            assert!(held >= 2, "each partial visit counts the slot held: {held}");
            return;
        }
        assert!(
            !(report.complete && report.blockers.held_slots == 0),
            "a pass reported complete with extents left: {report:?}"
        );
    }
    panic!("the close passes never returned the whole sequence");
}
