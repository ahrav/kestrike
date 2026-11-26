//! The readiness machine over a RESET attach: the word moves from `Detached` to `Loading` only when the attach gate passes, fills open only at `Live`, a mismatched subscription withholds, withdrawal closes fill admission while a granted lease keeps its right, and close drains to `Closed`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::Ordering;

use super::super::device::BufferArena;
use super::super::device::sim::{SimControl, Unwind};
use super::super::ledger::EngineBudget;
use super::super::maintain::Maintained;
use super::super::owner::Storage;
use super::super::publication_tests::{DEADLINE, filled, publish};
use super::super::publish_tests::{TRIES, key};
use super::super::readiness::{ReadinessError, State};
use super::super::test_platform::TestPlatform;
use super::super::volume_fixture::{
    BUFFER, DEPTH, Device, TICK, TestVolume, arena_with, device_with,
};
use super::super::writable::FillReserveError;
use super::super::{FeedContract, MetadataOutcome, budget::WorkBudget};
use super::Volume;
use super::journal_tests::storage_with;
use super::volume_tests::{CHUNK, SESSION, arena, attach, place, record, storage};

/// The attached volume starts on fresh media.
fn attach_unpolled<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    buffers: &'a BufferArena<TestPlatform>,
) -> (TestVolume<'s, 'a>, SimControl) {
    let (disk, control) = device_with(7, BUFFER);
    let volume = Volume::attach(
        storage,
        buffers,
        disk,
        super::super::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
        &mut EngineBudget::new(1 << 25),
    )
    .map_err(|(error, _)| error)
    .unwrap();
    (volume, control)
}

/// Formatting leaves fill admission gated on `begin_replay`.
fn poll_unsubscribed(volume: &mut TestVolume<'_, '_>, control: &SimControl) {
    let mut out = Vec::with_capacity(16);
    for _ in 0..64 {
        if volume.metadata_outcome() == MetadataOutcome::Unformatted {
            let _ = volume.format_from(super::super::volume_fixture::fixture_format);
        }
        control.tick(64);
        let _ = volume.poll_storage(0, &mut out);
    }
}

/// A RESET attach stays below `Live` after both RESET roots persist, refusing fills `Bootstrapping`, and a subscription to the storage's own feed from position zero reaches `Live`; a second begin rejects `AlreadyLive`.
#[test]
fn a_reset_attach_opens_fills_only_at_begin_replay() {
    let storage = storage_with(|volume| {
        volume.maintenance = Some(super::super::VolumeWatermarks {
            low_units: 2,
            min_free_slots: 1,
            retired_units: 2,
        });
    });
    let buffers = arena_with(4, 5);
    let (mut volume, control) = attach_unpolled(&storage, &buffers);
    assert_eq!(
        volume.readiness(),
        State::Detached,
        "the word waits for the gate"
    );
    poll_unsubscribed(&mut volume, &control);
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
    assert_eq!(volume.readiness(), State::Loaded);
    assert_eq!(
        super::super::publication_tests::reserved(&storage, &key(1), &[1; 8]).err(),
        Some(FillReserveError::Bootstrapping)
    );
    let mut calls = 0;
    loop {
        let Ok(Maintained::Open(report)) = storage.maintain(&mut WorkBudget::new(1 << 20)) else {
            panic!("an open storage below Live maintains");
        };
        calls += 1;
        assert!(
            !(report.reclaim.ran || report.expiry.ran || report.headroom.ran),
            "{report:?}"
        );
        assert_eq!((report.evicted, report.expired), (0, 0));
        if !report.more_work {
            break;
        }
        assert!(calls < 4, "maintenance below Live settles: {report:?}");
    }
    assert_eq!(volume.complete_replay(), Err(ReadinessError::NotReady));
    assert_eq!(
        volume.begin_replay(storage.feed_contract(), 0),
        Ok(State::Live)
    );
    assert_eq!(
        volume.begin_replay(storage.feed_contract(), 0),
        Err(ReadinessError::AlreadyLive)
    );
    assert!(super::super::publication_tests::reserved(&storage, &key(2), &[1; 8]).is_ok());
}

/// A subscription of another feed contract, or one starting past zero, withholds the attempt for good: fills refuse and no later begin reopens it.
#[test]
fn a_mismatched_subscription_withholds_for_the_attempt() {
    let buffers = arena_with(4, 5);
    for (feed, from) in [
        (
            FeedContract {
                authority: [1; 16],
                contract: 9,
            },
            0,
        ),
        (crate::storage::TEST_FEED, 5),
    ] {
        let storage = storage_with(|_| {});
        let (mut volume, control) = attach_unpolled(&storage, &buffers);
        poll_unsubscribed(&mut volume, &control);
        assert_eq!(volume.begin_replay(feed, from), Ok(State::Withheld));
        let report = volume.recovery_report();
        assert_eq!(
            report.phase(super::report::RecoveryPhase::Replay).start,
            None
        );
        assert_eq!(
            (report.transitions.iter().flatten().last()).map(|transition| transition.to),
            Some(State::Withheld)
        );
        assert_eq!(
            volume.begin_replay(storage.feed_contract(), 0),
            Err(ReadinessError::Ended(State::Withheld))
        );
        assert_eq!(
            super::super::publication_tests::reserved(&storage, &key(1), &[1; 8]).err(),
            Some(FillReserveError::Closed)
        );
    }
}

/// Withdrawal at `Live` closes fill admission before it returns, while a published lease keeps its right and an in-flight fill keeps its reservation; close then moves the word to `Closed`.
#[test]
fn withdrawal_closes_fills_and_keeps_granted_rights() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let lease = publish(&storage, &mut dev, &key(1), &[1; 20]).unwrap();
    storage
        .service_fills(
            crate::index::ShardIndex(0),
            4,
            &mut super::super::publish_tests::budget(),
        )
        .unwrap();
    let in_flight = filled(&storage, &mut dev, &key(2), &[2; 20]);
    let refs = storage.live_pool().unwrap().word(lease.id().slot_index());
    assert_eq!(storage.withdraw(), State::Withheld);
    assert_eq!(
        storage.live_pool().unwrap().word(lease.id().slot_index()),
        refs
    );
    assert_eq!(
        super::super::publication_tests::reserved(&storage, &key(3), &[3; 8]).err(),
        Some(FillReserveError::Closed)
    );
    assert_eq!(dev.read(&lease), [&key(1)[..4], &[1; 20]].concat());
    let second = in_flight
        .publish(
            &mut dev.volume,
            DEADLINE,
            TRIES,
            &mut super::super::publish_tests::budget(),
        )
        .expect("an in-flight fill keeps its reservation across withdrawal");
    assert_eq!(dev.read(&second), [&key(2)[..4], &[2; 20]].concat());
    let submitted = dev.volume.report().metadata_submitted;
    let _ = storage.invalidate(&key(1), TRIES, &mut super::super::publish_tests::budget());
    let mut out = Vec::with_capacity(16);
    for _ in 0..8 {
        dev.control.tick(64);
        let _ = dev.volume.poll_storage(0, &mut out);
    }
    assert_eq!(dev.volume.report().metadata_submitted, submitted);
    drop((lease, second));
    let _ = dev.volume.close();
    assert_eq!(dev.volume.readiness(), State::Closed);
    assert_eq!(storage.withdraw(), State::Closed);
}

/// Withdrawal on an idle open volume halts its metadata: later ticks publish `halted`, and a retirement parked behind a
/// held gate afterwards is retired by the next `service` call, which reports `awaiting_journal == 0`.
#[test]
fn withdrawal_on_an_idle_open_volume_halts_its_metadata() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let lease = publish(&storage, &mut dev, &key(1), &[1; 20]).unwrap();
    let id = lease.id();
    drop(lease);
    storage
        .service_fills(
            crate::index::ShardIndex(0),
            4,
            &mut super::super::publish_tests::budget(),
        )
        .unwrap();
    assert_eq!(storage.withdraw(), State::Withheld);
    let mut out = Vec::with_capacity(16);
    for _ in 0..8 {
        dev.control.tick(64);
        let _ = dev.volume.poll_storage(0, &mut out);
    }
    let live = storage.live_pool().unwrap();
    assert!(
        live.journal_words().halted.load(Ordering::Relaxed),
        "the withdrawn volume's tick publishes `halted`"
    );
    let access = live.try_lock().unwrap();
    storage
        .invalidate(&key(1), TRIES, &mut super::super::publish_tests::budget())
        .unwrap();
    drop(access);
    let parked = super::journal_tests::position(&storage, id.slot_index());
    assert_eq!(
        parked,
        crate::storage::recovery::PARKED_EPOCH[0],
        "the retirement parked behind the held gate"
    );
    let first = storage.service(&mut WorkBudget::new(1 << 10)).unwrap();
    assert_eq!(
        (
            super::journal_tests::state(&storage, id),
            first.awaiting_journal
        ),
        (Some(crate::storage::tables::SlotState::Retired), 0),
        "the halted call retires the park and reports no slot awaiting"
    );
    let _ = dev.volume.close();
}

/// A volume lost by an unwound tick refuses `begin_replay` with `Ended(Withheld)`, so fills stay closed before the next tick publishes the loss.
#[test]
fn a_lost_volume_refuses_begin_replay() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let (mut volume, control) = attach_unpolled(&storage, &buffers);
    poll_unsubscribed(&mut volume, &control);
    assert_eq!(volume.readiness(), State::Loaded);
    control.unwind_next(Some(Unwind::Pick));
    let mut out = Vec::with_capacity(16);
    let unwound = catch_unwind(AssertUnwindSafe(|| volume.poll_storage(0, &mut out)));
    assert!(unwound.is_err(), "the scripted pick unwound the tick");
    assert_eq!(
        volume.begin_replay(storage.feed_contract(), 0),
        Err(ReadinessError::Ended(State::Withheld))
    );
    assert!(volume.is_lost());
    assert_eq!(
        super::super::publication_tests::reserved(&storage, &key(1), &[1; 8]).err(),
        Some(FillReserveError::Closed)
    );
}

/// A tick that unwinds on a `Live` volume withdraws the attempt as it unwinds, so a reservation after the unwind refuses `Closed`.
#[test]
fn a_tick_that_unwinds_on_a_live_volume_withdraws_the_attempt() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let lease = publish(&storage, &mut dev, &key(1), &[1; 20]).unwrap();
    assert_eq!(dev.volume.readiness(), State::Live);
    dev.control.unwind_next(Some(Unwind::Pick));
    let mut out = Vec::with_capacity(16);
    let unwound = catch_unwind(AssertUnwindSafe(|| dev.volume.poll_storage(0, &mut out)));
    assert!(unwound.is_err(), "the scripted pick unwound the tick");
    assert_eq!(dev.volume.readiness(), State::Withheld);
    assert!(dev.volume.is_lost());
    assert_eq!(
        super::super::publication_tests::reserved(&storage, &key(2), &[2; 8]).err(),
        Some(FillReserveError::Closed)
    );
    drop(lease);
}

/// A direct read whose submit meets a gone device loses the volume and withdraws the attempt in the same call, so a reservation before the next poll refuses `Closed`.
/// The reservation is made once after the test's `is_lost` call and once before it; the second order observes the withdrawal the read call made.
#[test]
fn a_direct_submit_that_loses_the_volume_withdraws_the_attempt() {
    for reserve_first in [false, true] {
        let storage = storage_with(|_| {});
        let buffers = arena_with(4, 5);
        let mut dev = Device::new(&storage, &buffers);
        let lease = publish(&storage, &mut dev, &key(1), &[1; 20]).unwrap();
        assert_eq!(dev.volume.readiness(), State::Live);
        dev.control.set_gone();
        let refusal = dev
            .volume
            .read(lease.duplicate(), u64::MAX)
            .map(|_| ())
            .expect_err("the submit met the gone device")
            .refusal;
        assert_eq!(refusal, super::ReadRefusal::Lost);
        assert_eq!(dev.volume.readiness(), State::Withheld);
        if !reserve_first {
            assert!(dev.volume.is_lost());
        }
        assert_eq!(
            super::super::publication_tests::reserved(&storage, &key(2), &[2; 8]).err(),
            Some(FillReserveError::Closed),
            "reserve_first: {reserve_first}"
        );
        assert!(dev.volume.is_lost());
        drop(lease);
    }
}

/// The present-device case controls for device loss in `a_direct_submit_that_loses_the_volume_withdraws_the_attempt`.
#[test]
fn a_direct_read_on_a_present_device_leaves_the_attempt_live() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let lease = publish(&storage, &mut dev, &key(1), &[1; 20]).unwrap();
    assert_eq!(dev.volume.readiness(), State::Live);
    let op = dev
        .volume
        .read(lease.duplicate(), u64::MAX)
        .map_err(|refused| refused.refusal)
        .expect("the read is admitted");
    assert_eq!(dev.volume.readiness(), State::Live);
    assert_eq!(
        super::super::publication_tests::reserved(&storage, &key(2), &[2; 8]).err(),
        None
    );
    assert!(!dev.volume.is_lost());
    let delivered = super::super::volume_fixture::drive(&mut dev.volume, &dev.control, op);
    assert_eq!(delivered.status, super::ReadStatus::Complete);
    assert_eq!(dev.volume.readiness(), State::Live);
    drop(lease);
}

/// A direct read whose submit unwinds withdraws the attempt as it unwinds, so a reservation before the next poll refuses `Closed`.
#[test]
fn a_direct_submit_that_unwinds_withdraws_the_attempt() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let lease = publish(&storage, &mut dev, &key(1), &[1; 20]).unwrap();
    assert_eq!(dev.volume.readiness(), State::Live);
    dev.control.unwind_next(Some(Unwind::Submit));
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        dev.volume.read(lease.duplicate(), u64::MAX).map(|_| ())
    }));
    assert!(unwound.is_err(), "the scripted submit unwound the read");
    assert_eq!(dev.volume.readiness(), State::Withheld);
    assert_eq!(
        super::super::publication_tests::reserved(&storage, &key(2), &[2; 8]).err(),
        Some(FillReserveError::Closed)
    );
    drop(lease);
}

/// A grant whose submit meets a gone device loses the volume and withdraws the attempt in the same call, so a reservation before the next poll refuses `Closed`.
#[test]
fn a_grant_whose_submit_loses_the_volume_withdraws_the_attempt() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    assert_eq!(volume.readiness(), State::Live);
    let long = record(16, 0, 4 * CHUNK, SESSION, 34);
    place(&storage, &control, &long);
    let op = volume.read_raw(&long.read, u64::MAX).expect("admitted");
    let mut out = Vec::with_capacity(8);
    for _ in 0..8 {
        control.tick(8);
        let _ = volume.poll_storage(0, &mut out);
        if out
            .iter()
            .any(|event| matches!(event, super::ReadEvent::Chunk { .. }))
        {
            break;
        }
    }
    assert!(
        out.iter()
            .any(|event| matches!(event, super::ReadEvent::Chunk { .. })),
        "the first chunk arrived and the read awaits its grant"
    );
    control.set_gone();
    let _ = volume.grant_read(op);
    assert_eq!(volume.readiness(), State::Withheld);
    assert_eq!(
        storage.readiness.state().fill_refusal(),
        Some(super::super::reserve::ReserveError::Closed)
    );
}

/// A withdrawal before the attach binds the storage's one attach: fills refuse `Closed` at once, and the volume that attaches later starts `Withheld`, submits no probe or RESET and closes.
#[test]
fn a_withdrawal_before_the_attach_ends_the_attempt_it_precedes() {
    let storage = storage_with(|_| {});
    assert_eq!(storage.readiness.state(), State::Detached);
    assert_eq!(storage.withdraw(), State::Withheld);
    assert_eq!(
        super::super::publication_tests::reserved(&storage, &key(1), &[1; 8]).err(),
        Some(FillReserveError::Closed)
    );
    let buffers = arena_with(4, 5);
    let (mut volume, control) = attach_unpolled(&storage, &buffers);
    assert_eq!(volume.readiness(), State::Withheld);
    poll_unsubscribed(&mut volume, &control);
    assert_eq!(volume.readiness(), State::Withheld);
    assert_eq!(
        volume.report().metadata_submitted,
        0,
        "no probe or RESET submitted"
    );
    assert_eq!(storage.withdraw(), State::Withheld);
    let _ = volume.close();
    assert_eq!(volume.readiness(), State::Closed);
}

/// A withdrawal before the attach gate passes ends the attempt `Withheld`: fills refuse throughout and no probe or RESET root is submitted.
#[test]
fn a_withdrawal_before_the_gate_writes_nothing() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let (mut volume, control) = attach_unpolled(&storage, &buffers);
    assert_eq!(volume.readiness(), State::Detached);
    assert_eq!(
        super::super::publication_tests::reserved(&storage, &key(1), &[1; 8]).err(),
        Some(FillReserveError::Bootstrapping)
    );
    assert_eq!(storage.withdraw(), State::Withheld);
    poll_unsubscribed(&mut volume, &control);
    assert_eq!(volume.readiness(), State::Withheld);
    assert_eq!(
        super::super::publication_tests::reserved(&storage, &key(2), &[1; 8]).err(),
        Some(FillReserveError::Closed)
    );
    assert_eq!(
        volume.report().metadata_submitted,
        0,
        "no probe or RESET submitted"
    );
    let _ = volume.close();
    assert_eq!(volume.readiness(), State::Closed);
}

#[test]
fn a_withdrawal_after_the_probes_refuses_format() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let (mut volume, control) = attach_unpolled(&storage, &buffers);
    let mut out = Vec::with_capacity(16);
    for _ in 0..64 {
        if volume.metadata_outcome() == MetadataOutcome::Unformatted {
            break;
        }
        control.tick(64);
        let _ = volume.poll_storage(0, &mut out);
    }
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Unformatted);
    assert_eq!(storage.withdraw(), State::Withheld);
    assert_eq!(
        volume.format_from(super::super::volume_fixture::fixture_format),
        Err(MetadataOutcome::Unformatted),
        "a withheld attempt accepts no format"
    );
    let submitted = volume.report().metadata_submitted;
    for _ in 0..8 {
        control.tick(64);
        let _ = volume.poll_storage(0, &mut out);
    }
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Unformatted);
    assert_eq!(volume.report().metadata_submitted, submitted);
    let _ = volume.close();
}

/// The readiness word leaves `Detached` for `Loading` only when the gate's Report passes: while the driver withholds that Report the word stays `Detached`, fills refuse `Bootstrapping` and maintenance runs no Reclaim, Expiry or Headroom stage, and the tick that applies the passing Report moves it to `Loading`.
#[test]
fn loading_only_after_gate() {
    use super::gate_fixture::{arena as reserving_arena, attach_reserving};
    let storage = storage_with(|volume| {
        volume.maintenance = Some(super::super::VolumeWatermarks {
            low_units: 2,
            min_free_slots: 1,
            retired_units: 2,
        });
    });
    let buffers = reserving_arena();
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &buffers,
        crate::storage::ServingAuthority::fixture(),
    );
    registry.borrow_mut().budget = Some(2);
    let mut out = Vec::with_capacity(16);
    for _ in 0..32 {
        control.tick(64);
        let _ = volume.poll_storage(0, &mut out);
        assert_eq!(volume.readiness(), State::Detached);
    }
    assert_eq!(
        super::super::publication_tests::reserved(&storage, &key(1), &[1; 8]).err(),
        Some(FillReserveError::Bootstrapping)
    );
    let Ok(Maintained::Open(report)) = storage.maintain(&mut WorkBudget::new(1 << 20)) else {
        panic!("an attached storage waiting at its gate maintains");
    };
    assert!(
        !(report.reclaim.ran || report.expiry.ran || report.headroom.ran),
        "{report:?}"
    );
    assert_eq!((report.evicted, report.expired), (0, 0));
    assert_eq!(volume.readiness(), State::Detached);
    registry.borrow_mut().budget = None;
    control.tick(64);
    let _ = volume.poll_storage(0, &mut out);
    assert_eq!(volume.readiness(), State::Loading);
}

/// A periodic Report whose submit meets a gone device loses the volume and withdraws the attempt in that tick, so the word reads `Withheld` and a reservation before the next poll refuses `Closed`.
#[test]
fn a_periodic_report_that_loses_the_volume_withdraws_the_attempt() {
    use super::super::device::RefusalReason;
    use super::authority_tests::Clock;
    use super::gate_fixture::{arena as reserving_arena, attach_reserving, ticks};
    let storage = storage_with(|_| {});
    let arena = reserving_arena();
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture(),
    );
    let time = std::rc::Rc::new(std::cell::Cell::new(10));
    volume.set_serving_clock(Box::new(Clock(std::rc::Rc::clone(&time))));
    for _ in 0..64 {
        if volume.metadata_outcome() == MetadataOutcome::Unformatted {
            volume
                .format_from(super::super::volume_fixture::fixture_format)
                .expect("fresh media formats");
        }
        if volume.metadata_outcome() == MetadataOutcome::Open {
            break;
        }
        ticks(&mut volume, &control, 1);
    }
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
    assert_eq!(
        volume.begin_replay(storage.feed_contract(), 0),
        Ok(State::Live)
    );
    let submitted = registry.borrow().log.len();
    registry.borrow_mut().refuse = Some(RefusalReason::DeviceGone);
    time.set(volume.authority.next_report);
    let mut out = Vec::with_capacity(16);
    control.tick(64);
    let _ = volume.poll_storage(0, &mut out);
    assert_eq!(
        registry.borrow().log.len(),
        submitted,
        "the driver refused the Report"
    );
    assert_eq!(
        volume.table.report().admission,
        super::super::device::Admission::Lost,
        "the refused Report lost the table"
    );
    assert_eq!(volume.readiness(), State::Withheld);
    assert_eq!(
        super::super::publication_tests::reserved(&storage, &key(2), &[2; 8]).err(),
        Some(FillReserveError::Closed)
    );
    assert!(volume.is_lost());
    let _ = volume.close();
}
