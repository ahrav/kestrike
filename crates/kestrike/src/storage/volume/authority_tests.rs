//! Serving windows over the volume's metadata prefix, fill custody and reuse gate.
//! Within its deadline, a pending periodic Report holds back the next one until its terminal applies.

use super::super::claim_exit_tests::{FREE, RETIRED, conserved_after_service, conserved_at};
use super::super::volume_fixture::{Device, arena_with};
use super::authority::{AuthorityRefusal, ServingClock};
use super::journal_tests::{poll, storage_with};
use crate::failover::serving::{Cause, Event, State};
use std::cell::Cell;
use std::rc::Rc;

/// A serving clock the test sets.
pub(super) struct Clock(pub(super) Rc<Cell<u64>>);
impl ServingClock for Clock {
    fn now_us(&self) -> Option<u64> {
        Some(self.0.get())
    }
}

/// Counts every serving-clock reading; time stays at zero.
struct Counted(Rc<Cell<u32>>);
impl ServingClock for Counted {
    fn now_us(&self) -> Option<u64> {
        self.0.set(self.0.get() + 1);
        Some(0)
    }
}

/// A reading fails the test: the code under it must decide without the clock.
struct PanicClock;
impl ServingClock for PanicClock {
    fn now_us(&self) -> Option<u64> {
        panic!("clock callback");
    }
}

fn clock(dev: &mut Device<'_, '_>) -> Rc<Cell<u64>> {
    let time = Rc::new(Cell::new(0));
    dev.volume.authority.clock = Box::new(Clock(Rc::clone(&time)));
    time
}

fn expire(dev: &mut Device<'_, '_>) {
    dev.volume.authority_event(Event::Expire { now: 0 });
    assert_eq!(dev.volume.authority_report().state, State::Serving);
    assert_eq!(
        dev.volume.admit_authority(
            crate::failover::serving::Operation::Read,
            dev.volume.serving_token()
        ),
        Err(crate::failover::serving::Denial::WindowExpired)
    );
    assert!(
        !dev.volume.closed,
        "EXCLUSION-BEFORE-REUSE: expiry preserves the close waiver"
    );
}

/// A fill whose window expires before its writes complete fails, and its publication refuses as `Closed` with the
/// key still missing from the index.
#[test]
fn completing_fill_outside_the_window_refuses_publication_as_closed() {
    let storage = storage_with(|_| {});
    let arena = arena_with(4, 5);
    let mut dev = Device::new(&storage, &arena);
    let _time = clock(&mut dev);
    let mut fill = super::super::writable_tests::reserve(&storage, &[3; 32], 0, 20).unwrap();
    fill.receive(
        &mut dev.volume,
        &[3; 20],
        &mut super::super::volume_fixture::ample_io(),
    )
    .unwrap();
    fill.receive(
        &mut dev.volume,
        &[],
        &mut super::super::volume_fixture::ample_io(),
    )
    .unwrap();
    assert!(fill.progress(&dev.volume).outstanding_commands > 0);
    expire(&mut dev);
    dev.control.tick(64);
    poll(&mut dev);
    assert!(fill.progress(&dev.volume).failed);
    assert_eq!(dev.volume.report().writes_done, 0);
    assert_eq!(dev.volume.report().writes_failed, 1);
    assert_eq!(
        fill.publish(
            &mut dev.volume,
            100,
            4,
            &mut super::super::volume_fixture::ample_io()
        )
        .err(),
        Some(crate::storage::FillPublishError::Closed)
    );
    assert!(matches!(
        storage
            .register()
            .unwrap()
            .lookup(&[3; 32], 4, &mut super::super::publish_tests::budget()),
        Err(crate::storage::LookupError::Missing)
    ));
    dev.volume.close();
}

/// `Lost` is judged before the serving authority. A ready fill whose serving
/// window expired refuses publication `Closed` on a live volume and `Lost`
/// once the volume is lost.
/// Each refusal retires the fill's slot with `ABANDONED`, the tables pass the
/// conservation judge, and one service pass frees the slot.
#[test]
fn a_lost_volume_outside_the_window_refuses_publication_as_lost() {
    use crate::storage::FillPublishError;
    for lost in [false, true] {
        let storage = storage_with(|_| {});
        let arena = arena_with(4, 5);
        let mut dev = Device::new(&storage, &arena);
        let _time = clock(&mut dev);
        let mut fill = super::super::writable_tests::reserve(&storage, &[3; 32], 0, 20).unwrap();
        dev.fill(&mut fill, &[3; 20]);
        assert!(fill.is_ready(&dev.volume));
        if lost {
            dev.lose();
        }
        assert_eq!(dev.volume.is_lost(), lost);
        expire(&mut dev);
        let slot = fill.id().slot_index();
        assert_eq!(
            fill.publish(
                &mut dev.volume,
                100,
                4,
                &mut super::super::volume_fixture::ample_io()
            )
            .err(),
            Some(if lost {
                FillPublishError::Lost
            } else {
                FillPublishError::Closed
            })
        );
        conserved_at(&storage, slot, RETIRED);
        conserved_after_service(&storage, slot, FREE);
    }
}

/// The authority report takes one serving-clock reading and judges its ages, its admission refusal and its
/// withhold at that reading. Under a clock whose first reading succeeds and whose later readings fail, the report
/// reads the first reading's ages with no refusal, as it reads under a steady clock at the same time; a report that
/// took another reading for an admission would refuse `WindowExpired` beside ages of the first.
#[test]
fn the_authority_report_judges_every_field_at_one_clock_reading() {
    /// The first reading is `at`; every later reading fails.
    struct Once(Cell<bool>, u64);
    impl ServingClock for Once {
        fn now_us(&self) -> Option<u64> {
            (!self.0.replace(true)).then_some(self.1)
        }
    }
    let storage = storage_with(|_| {});
    let arena = arena_with(4, 5);
    let mut dev = Device::new(&storage, &arena);
    let time = clock(&mut dev);
    dev.volume.authority_event(Event::Refresh { at: 20 });
    time.set(50);
    let steady = dev.volume.authority_report();
    assert_eq!(
        (steady.refusal, steady.withheld, steady.freshness_age_us),
        (None, false, Some(30)),
        "the fixture's tenure serves at 50"
    );
    let count = Rc::new(Cell::new(0));
    dev.volume.authority.clock = Box::new(Counted(Rc::clone(&count)));
    dev.volume.authority_report();
    assert_eq!(count.get(), 1, "one reading per report");
    dev.volume.authority.clock = Box::new(Once(Cell::new(false), 50));
    assert_eq!(dev.volume.authority_report(), steady);
    assert_eq!(
        dev.volume.authority_report().refusal,
        Some(AuthorityRefusal::Admission(
            crate::failover::serving::Denial::WindowExpired
        )),
        "a failed reading refuses"
    );
    dev.volume.authority.clock = Box::new(Clock(Rc::new(Cell::new(0))));
    dev.volume.close();
}

#[test]
fn authority_report_carries_the_freshness_age() {
    let storage = storage_with(|_| {});
    let arena = arena_with(4, 5);
    let mut dev = Device::new(&storage, &arena);
    let time = clock(&mut dev);
    time.set(50);
    assert_eq!(dev.volume.authority_report().freshness_age_us, None);
    dev.volume.authority_event(Event::Refresh { at: 20 });
    assert_eq!(dev.volume.authority_report().freshness_age_us, Some(30));
    time.set(80);
    assert_eq!(dev.volume.authority_report().freshness_age_us, Some(60));
    dev.volume.close();
}

#[test]
fn expiry_withholds_hits_reads_fills_and_replies_and_rtype_zero_withdraws() {
    use crate::failover::{
        bounds::Bounds,
        evidence::NotSole,
        serving::{Denial, Machine, Operation, Readiness},
    };
    let storage = storage_with(|_| {});
    let arena = arena_with(4, 5);
    let mut dev = Device::new(&storage, &arena);
    let time = clock(&mut dev);
    let bounds = Bounds::new(8, 1, 100, 10, 10, 0).unwrap();
    let session = crate::storage::next_session();
    let own = dev.volume.serving_token().unwrap();
    let pair = crate::failover::evidence::Pair {
        key: own.key,
        exhid: own.exhid,
    };
    let mut machine = Machine::issued(bounds, &session, pair);
    machine.cross_boundary(&crate::storage::Fenced::assumed());
    let token = machine.token().unwrap();
    machine.step(Event::Readiness(Readiness::ReadReady { token }));
    machine.step(Event::Readiness(Readiness::AllocationReady { token }));
    dev.volume.authority = super::authority::ServingAuthority::new(
        bounds,
        machine,
        Box::new(Clock(Rc::clone(&time))),
        session,
    );
    time.set(99);
    for op in [
        Operation::Get,
        Operation::Read,
        Operation::Fill,
        Operation::Reply {
            lineage: token.lineage,
        },
    ] {
        assert_eq!(dev.volume.admit_authority(op, Some(token)), Ok(token));
        time.set(100);
        assert_eq!(
            dev.volume.admit_authority(op, Some(token)),
            Err(Denial::WindowExpired)
        );
        time.set(99);
    }
    time.set(100);
    poll(&mut dev);
    assert_eq!(dev.volume.authority_report().state, State::Serving);
    let count = dev.volume.report.metadata_submitted;
    dev.volume.authority_event(Event::Withdraw(Cause::Report(
        crate::failover::serving::ReportTrigger::new(NotSole::ReservationType).unwrap(),
    )));
    assert_eq!(dev.volume.authority_report().state, State::Withdrawn);
    for _ in 0..4 {
        poll(&mut dev);
    }
    assert_eq!(dev.volume.report.metadata_submitted, count);
    assert_eq!(dev.volume.authority_report().report_age_us, None);
    dev.volume.close();
}

thread_local! {
    static PUBLISH_TIME: std::cell::RefCell<Option<Rc<Cell<u64>>>> = const { std::cell::RefCell::new(None) };
}

#[test]
fn publication_rechecks_the_window_inside_the_visibility_bracket() {
    let storage = storage_with(|_| {});
    let arena = arena_with(4, 5);
    let mut dev = Device::new(&storage, &arena);
    let time = clock(&mut dev);
    let fill = super::super::publication_tests::filled(&storage, &mut dev, &[3; 32], &[3; 20]);
    PUBLISH_TIME.with(|slot| *slot.borrow_mut() = Some(time));
    super::super::publication::INTERPOSE_BEFORE_INHIBITION.with(|hook| {
        hook.set(Some(|_| {
            PUBLISH_TIME.with(|slot| slot.borrow().as_ref().unwrap().set(u64::MAX));
        }))
    });
    assert_eq!(
        fill.publish(
            &mut dev.volume,
            100,
            4,
            &mut super::super::publish_tests::budget()
        )
        .err(),
        Some(crate::storage::FillPublishError::Closed)
    );
    assert!(
        storage
            .register()
            .unwrap()
            .lookup(&[3; 32], 4, &mut super::super::publish_tests::budget())
            .is_err()
    );
    PUBLISH_TIME.with(|slot| slot.borrow_mut().take());
    dev.volume.close();
}

#[test]
fn a_fill_reserved_before_withdrawal_refuses_after_it() {
    let storage = storage_with(|_| {});
    let arena = arena_with(4, 5);
    let mut dev = Device::new(&storage, &arena);
    let _time = clock(&mut dev);
    let mut fill = super::super::publication_tests::filled(&storage, &mut dev, &[3; 32], &[3; 20]);
    dev.volume
        .authority_event(Event::Withdraw(Cause::NewerFence { page: 0, fence: 9 }));
    let writes = dev.volume.report().writes_submitted;
    assert_eq!(
        fill.receive(
            &mut dev.volume,
            &[],
            &mut super::super::volume_fixture::ample_io()
        ),
        Err(crate::storage::ReceiveError::Closed)
    );
    assert_eq!(
        fill.publish(
            &mut dev.volume,
            100,
            4,
            &mut super::super::publish_tests::budget()
        )
        .err(),
        Some(crate::storage::FillPublishError::Closed)
    );
    assert_eq!(dev.volume.report().writes_submitted, writes);
    dev.volume.close();
}

#[test]
fn withdrawn_refuses_reads_fills_and_payload_submission() {
    let storage = storage_with(|_| {});
    let arena = arena_with(4, 5);
    let mut dev = Device::new(&storage, &arena);
    let mut fill = super::super::writable_tests::reserve(&storage, &[3; 32], 0, 20).unwrap();
    dev.volume.authority_event(Event::Withdraw(Cause::Report(
        crate::failover::serving::ReportTrigger::new(
            crate::failover::evidence::NotSole::ReservationType,
        )
        .unwrap(),
    )));
    let record =
        super::volume_tests::record(0, 0, super::volume_tests::CHUNK, dev.volume.session, 35);
    assert_eq!(
        dev.volume.read_raw(&record.read, u64::MAX),
        Err(super::ReadRefusal::Closed)
    );
    assert_eq!(
        super::super::writable_tests::reserve(&storage, &[4; 32], 0, 20).err(),
        Some(crate::storage::FillReserveError::Withdrawn)
    );
    assert_eq!(
        fill.receive(
            &mut dev.volume,
            &[3; 20],
            &mut super::super::volume_fixture::ample_io()
        ),
        Err(crate::storage::ReceiveError::Closed)
    );
    dev.volume.close();
}

#[test]
fn invalidations_stay_refused_after_a_withdrawn_machine_or_volume_closes() {
    for close_volume in [false, true] {
        let storage = storage_with(|_| {});
        let arena = arena_with(4, 5);
        let mut dev = Device::new(&storage, &arena);
        let mut budget = crate::storage::WorkBudget::new(1 << 16);
        assert!(storage.invalidate(&[7; 32], 4, &mut budget).is_ok());
        dev.volume.authority_event(Event::Withdraw(Cause::Planned));
        dev.volume.authority_event(Event::Close);
        assert_eq!(dev.volume.authority_report().state, State::Closed);
        if close_volume {
            dev.volume.close();
        }
        assert_eq!(
            storage.invalidate(&[7; 32], 4, &mut budget).err(),
            Some(crate::storage::InvalidateError::Withdrawn),
            "close of the volume: {close_volume}"
        );
        if !close_volume {
            dev.volume.close();
        }
    }
}

#[test]
fn an_expired_window_fences_read_submission_and_arrived_bytes() {
    use super::volume_tests::{CHUNK, SESSION, TICK, arena, attach, place, record, storage};
    for cut in 0..3 {
        let storage = storage(1);
        let arena = arena();
        let (mut volume, control) = attach(&storage, &arena, TICK);
        let time = Rc::new(Cell::new(0));
        volume.authority.clock = Box::new(Clock(Rc::clone(&time)));
        let record = record(0, 0, CHUNK, SESSION, 35);
        place(&storage, &control, &record);
        let op = volume.read_raw(&record.read, u64::MAX).unwrap();
        if cut != 0 {
            volume.grant_read(op).unwrap();
        }
        let mut out = Vec::with_capacity(8);
        if cut >= 2 {
            control.tick(64);
            volume.poll_terminals(0, &out);
        }
        volume.authority_event(Event::Expire { now: 0 });
        assert_eq!(
            volume.read_raw(&record.read, u64::MAX),
            Err(super::ReadRefusal::Closed)
        );
        if cut == 0 {
            volume.grant_read(op).unwrap();
        }
        control.tick(64);
        volume.poll_storage(0, &mut out);
        assert_eq!(out.len(), 1, "ResponseInIncarnation: no Chunk at cut {cut}");
        assert!(
            matches!(out.as_slice(), [super::ReadEvent::Done { op: done, status: super::ReadStatus::Quiesced, .. }] if *done == op)
        );
        assert_eq!(volume.reads.live(), 0);
        assert_eq!(volume.table_report().pending, 0);
        volume.close();
    }
}

/// The fencing events of the late-terminal table: three withdrawal causes,
/// and a withdrawal followed by a close.
fn fencing_events() -> [Vec<Event>; 4] {
    use crate::failover::serving::Deposing;
    [
        vec![Event::Withdraw(Cause::Flipped)],
        vec![Event::Withdraw(Cause::NewerFence { page: 0, fence: 9 })],
        vec![Event::Withdraw(Cause::Status(Deposing::Conflict))],
        vec![Event::Withdraw(Cause::Flipped), Event::Close],
    ]
}

/// Applies `events` to `volume`'s serving machine and requires the state
/// each one reaches: `Withdrawn` with its cause after a withdrawal, `Closed`
/// after a close, and `Serving` when there is no event.
fn fence(volume: &mut super::super::volume_fixture::TestVolume<'_, '_>, events: &[Event]) {
    for event in events {
        volume.authority_event(*event);
        match event {
            Event::Withdraw(cause) => {
                assert_eq!(volume.authority_state(), State::Withdrawn, "{event:?}");
                assert_eq!(volume.authority_withdrawal(), Some(*cause), "{event:?}");
            }
            Event::Close => assert_eq!(volume.authority_state(), State::Closed, "{event:?}"),
            _ => unreachable!("{event:?} is no fencing event"),
        }
    }
    if events.is_empty() {
        assert_eq!(volume.authority_state(), State::Serving);
    }
}

/// What a fill's write terminal delivered after `events` left: the write
/// and failed counts the events and one storage poll added, the counts the
/// terminal then added, the custody check's count and held tokens after
/// that poll and before the device runs beside the write's token, the
/// publication's result, the index lookup's result, and the table's
/// pending commands at the end.
#[derive(Debug)]
struct LateWrite {
    fenced: (u64, u64),
    counted: (u64, u64),
    custody: (usize, Vec<crate::storage::CommandToken>),
    write: crate::storage::CommandToken,
    /// The device delivered the write's full-length success completion after the events.
    delivered: bool,
    published: Result<(), crate::storage::FillPublishError>,
    found: Result<(), crate::storage::LookupError>,
    pending: u32,
}

/// A fill's write is outstanding on the device when `events` land; the
/// device then completes it with success, and the test then calls
/// `publish` on the fill.
fn late_write(events: &[Event]) -> LateWrite {
    use super::super::device::custody_witness::judged;
    use super::super::device::sim::Captured;
    use super::super::volume_fixture::ample_io;
    use crate::storage::{Classification, Operation};
    let storage = storage_with(|_| {});
    let arena = arena_with(4, 5);
    let mut dev = Device::new(&storage, &arena);
    let mut fill = super::super::writable_tests::reserve(&storage, &[3; 32], 0, 20).unwrap();
    fill.receive(&mut dev.volume, &[3; 20], &mut ample_io())
        .unwrap();
    fill.receive(&mut dev.volume, &[], &mut ample_io()).unwrap();
    assert_eq!(fill.progress(&dev.volume).outstanding_commands, 1);
    let write = super::volume_tests::last_submitted(&dev.control);
    let held = dev.control.held();
    let len = held
        .iter()
        .find(|entry| entry.token == write && entry.operation == Operation::Write)
        .map(|entry| entry.len)
        .expect("the device holds the fill's write");
    let before = dev.volume.report();
    fence(&mut dev.volume, events);
    poll(&mut dev);
    let custody = judged(&dev.control, &arena);
    let fenced = dev.volume.report();
    dev.control.clear_capture();
    dev.control.tick(64);
    poll(&mut dev);
    let delivered = dev.control.capture().events.iter().any(|event| {
        matches!(event, Captured::Delivered { token, status }
            if *token == write && status.classify(len) == Classification::Success)
    });
    let after = dev.volume.report();
    let published = fill
        .publish(
            &mut dev.volume,
            super::super::publication_tests::DEADLINE,
            4,
            &mut super::super::publish_tests::budget(),
        )
        .map(|_| ());
    let found = storage
        .register()
        .unwrap()
        .lookup(&[3; 32], 4, &mut super::super::publish_tests::budget())
        .map(|_| ());
    let pending = dev.volume.table_report().pending;
    dev.volume.close();
    LateWrite {
        fenced: (
            fenced.writes_done - before.writes_done,
            fenced.writes_failed - before.writes_failed,
        ),
        counted: (
            after.writes_done - fenced.writes_done,
            after.writes_failed - fenced.writes_failed,
        ),
        custody,
        write,
        delivered,
        published,
        found,
        pending,
    }
}

/// `NoStaleEpochWriteLands`, WITHDRAWN-EXITS-ONLY-TO-CLOSED: a fill's write
/// outstanding when its serving machine withdraws, for each listed cause or
/// with a close after the withdrawal, completes on the device with success
/// and counts nothing as written: the events count nothing, the terminal
/// fails the write set, publication refuses as `Closed` and the key stays
/// missing. The withdrawn volume keeps the command's custody, so after the
/// event and one storage poll the custody check judges the device-held
/// write in storage custody, and after the terminal the table holds no
/// command. With no event the same steps count the write as written and
/// publish the fill.
#[test]
fn a_write_terminal_after_a_withdrawal_counts_nothing_written_and_publishes_nothing() {
    for events in fencing_events() {
        let run = late_write(&events);
        assert!(run.delivered, "{events:?}");
        assert_eq!(run.fenced, (0, 0), "{events:?}");
        assert_eq!(run.counted, (0, 1), "{events:?}");
        assert_eq!(run.custody, (1, vec![run.write]), "{events:?}");
        assert_eq!(
            run.published,
            Err(crate::storage::FillPublishError::Closed),
            "{events:?}"
        );
        assert_eq!(
            run.found,
            Err(crate::storage::LookupError::Missing),
            "{events:?}"
        );
        assert_eq!(run.pending, 0, "{events:?}");
    }
    let sound = late_write(&[]);
    assert!(sound.delivered);
    assert_eq!(sound.pending, 0);
    assert_eq!(sound.fenced, (0, 0));
    assert_eq!(sound.counted, (1, 0));
    assert_eq!(sound.custody, (1, vec![sound.write]));
    assert_eq!(sound.published, Ok(()));
    assert_eq!(sound.found, Ok(()));
}

/// What a read delivered when `events` landed at `cut`. The read submits
/// its one command at admission, before the events, and a grant call
/// admits no further command; at cut 0 that call follows the events, at
/// cut 1 it precedes them, and at cut 2 the read's terminal is also applied
/// before the events, its bytes awaiting verification. The row holds the
/// custody check's count and held tokens after the events and before the
/// next device tick, the read terminals counted arrived and failed across
/// that tick and its storage poll, the read's operation and command token,
/// the chunks and every `Done` event the volume then delivered, and the
/// live reads and the table's pending commands at the end.
#[derive(Debug)]
struct LateRead {
    custody: (usize, Vec<crate::storage::CommandToken>),
    terminals: (u64, u64),
    op: super::ReadOp,
    read: crate::storage::CommandToken,
    chunks: usize,
    dones: Vec<(super::ReadOp, super::ReadStatus)>,
    live: u32,
    pending: u32,
}

fn late_read(events: &[Event], cut: u8) -> LateRead {
    use super::super::device::custody_witness::judged;
    use super::lifecycle_tests::dones;
    use super::volume_tests::{
        CHUNK, SESSION, TICK, arena, attach, last_submitted, place, record, storage, submits,
    };
    let storage = storage(1);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(0, 0, CHUNK, SESSION, 35);
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).unwrap();
    let read = last_submitted(&control);
    let submitted = submits(&control);
    if cut != 0 {
        assert_eq!(volume.grant_read(op), Ok(super::Grant::Exhausted));
    }
    let mut out = Vec::with_capacity(8);
    if cut >= 2 {
        control.tick(64);
        volume.poll_terminals(0, &out);
        let stage = &volume
            .reads
            .get(op.slot, op.generation)
            .expect("live")
            .stage;
        assert!(
            matches!(stage, super::read::Stage::Verifying(_)),
            "the read's terminal is applied before the events"
        );
    }
    fence(&mut volume, events);
    if cut == 0 {
        assert_eq!(volume.grant_read(op), Ok(super::Grant::Exhausted));
    }
    assert_eq!(
        submits(&control),
        submitted,
        "neither the events nor a grant submit a command"
    );
    let custody = judged(&control, &arena);
    let before = volume.report();
    control.tick(64);
    volume.poll_storage(0, &mut out);
    let after = volume.report();
    let chunks = out
        .iter()
        .filter(|event| matches!(event, super::ReadEvent::Chunk { .. }))
        .count();
    let dones = dones(&mut out);
    let (live, pending) = (volume.reads.live(), volume.table_report().pending);
    volume.close();
    LateRead {
        custody,
        terminals: (
            after.reads_done - before.reads_done,
            after.reads_failed - before.reads_failed,
        ),
        op,
        read,
        chunks,
        dones,
        live,
        pending,
    }
}

/// `ResponseInIncarnation`, WITHDRAWN-EXITS-ONLY-TO-CLOSED: a read whose
/// serving machine withdraws, for each listed cause or with a close after
/// the withdrawal, hands out no `Chunk` and ends with one `Done` of status
/// `Quiesced`, with no read live and no command pending. The read submits
/// its command at admission, before the event, and a grant call admits no
/// further command; the command is in flight across the event whether that
/// call follows the event (cut 0) or precedes it (cut 1), and at cut 2 its
/// terminal is applied before the event, with its bytes awaiting
/// verification. The withdrawn volume keeps command custody: in cuts 0 and
/// 1 the custody check judges the read's command in storage custody after
/// the event and before the next device tick, and that tick delivers the
/// read's successful terminal. With no event the same steps deliver the
/// chunk and complete.
#[test]
fn a_read_terminal_after_a_withdrawal_delivers_no_chunk() {
    use super::ReadStatus;
    let held = |cut: u8| usize::from(cut < 2);
    for events in fencing_events() {
        for cut in 0..3 {
            let run = late_read(&events, cut);
            assert_eq!(
                run.custody,
                (held(cut), vec![run.read; held(cut)]),
                "{events:?} cut {cut}"
            );
            assert_eq!(run.terminals, (held(cut) as u64, 0), "{events:?} cut {cut}");
            assert_eq!(run.chunks, 0, "{events:?} cut {cut}");
            assert_eq!(
                run.dones,
                [(run.op, ReadStatus::Quiesced)],
                "{events:?} cut {cut}"
            );
            assert_eq!((run.live, run.pending), (0, 0), "{events:?} cut {cut}");
        }
    }
    for cut in 0..3 {
        let sound = late_read(&[], cut);
        assert_eq!(
            sound.custody,
            (held(cut), vec![sound.read; held(cut)]),
            "cut {cut}"
        );
        assert_eq!(sound.terminals, (held(cut) as u64, 0), "cut {cut}");
        assert_eq!(sound.chunks, 1, "cut {cut}");
        assert_eq!(sound.dones, [(sound.op, ReadStatus::Complete)], "cut {cut}");
        assert_eq!((sound.live, sound.pending), (0, 0), "cut {cut}");
    }
}

#[test]
fn applying_a_popped_terminal_keeps_custody_independent_of_clock_callbacks() {
    use super::volume_tests::{CHUNK, SESSION, TICK, arena, attach, place, record, storage};
    let storage = storage(1);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(0, 0, CHUNK, SESSION, 35);
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).unwrap();
    volume.grant_read(op).unwrap();
    control.tick(64);
    volume.table.poll(&mut volume.scratch);
    assert_eq!(volume.scratch.len(), 1);
    volume.authority.clock = Box::new(PanicClock);
    let terminal = volume.scratch.pop().unwrap();
    volume.apply(terminal, 0);
    volume.authority.clock = Box::new(Clock(Rc::new(Cell::new(0))));
    let mut out = Vec::with_capacity(8);
    volume.poll_storage(0, &mut out);
    assert!(
        matches!(out.last(), Some(super::ReadEvent::Done { op: done, status: super::ReadStatus::Complete, .. }) if *done == op)
    );
    assert_eq!(volume.reads.live(), 0);
    volume.close();
}

#[test]
fn unavailable_or_backward_clock_closes_the_window_and_publishes_refusal_before_admission() {
    struct Source(Rc<Cell<Option<u64>>>);
    impl ServingClock for Source {
        fn now_us(&self) -> Option<u64> {
            self.0.get()
        }
    }
    for next in [None, Some(9)] {
        let storage = storage_with(|_| {});
        let arena = arena_with(4, 5);
        let mut dev = Device::new(&storage, &arena);
        let time = Rc::new(Cell::new(Some(10)));
        dev.volume.authority.clock = Box::new(Source(Rc::clone(&time)));
        dev.volume.authority_deadlines();
        time.set(next);
        assert!(
            dev.volume
                .admit_authority(
                    crate::failover::serving::Operation::Fill,
                    dev.volume.serving_token()
                )
                .is_err()
        );
        dev.volume.authority_deadlines();
        assert_eq!(dev.volume.authority_report().state, State::Serving);
        assert_eq!(
            dev.volume.authority_report().refusal,
            Some(AuthorityRefusal::Clock)
        );
        time.set(Some(10));
        assert_eq!(
            dev.volume.admit_authority(
                crate::failover::serving::Operation::Fill,
                dev.volume.serving_token()
            ),
            Err(crate::failover::serving::Denial::WindowExpired)
        );
        dev.volume.close();
    }
}

/// The serving machine's `BeforeExpiry` rule ("The Report was submitted at or before the window last closed"): a Report in flight when a clock fault closes the window does not renew it. `observed` is whether the authority read the clock between the Report's submission and the fault; the fault is a missing reading or one behind the last.
#[test]
fn a_report_in_flight_across_a_clock_fault_does_not_renew_the_window() {
    use super::gate_fixture::{arena, attach_reserving, ticks};
    /// Each reading is one microsecond after the last.
    struct Stepping(Rc<Cell<Option<u64>>>);
    impl ServingClock for Stepping {
        fn now_us(&self) -> Option<u64> {
            let now = self.0.get()?;
            self.0.set(Some(now + 1));
            Some(now)
        }
    }
    let mut reopened: Vec<(bool, Option<u64>, u64, u64)> = Vec::new();
    for (observed, fault) in [
        (true, None),
        (true, Some(0)),
        (false, None),
        (false, Some(0)),
    ] {
        let arena = arena();
        let storage = super::gate_fixture::storage();
        let authority = super::ServingAuthority::fixture();
        let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
        let time = Rc::new(Cell::new(Some(0)));
        volume.set_serving_clock(Box::new(Stepping(Rc::clone(&time))));
        ticks(&mut volume, &control, 16);
        assert!(volume.authority.report.is_none(), "no Report outstanding");
        registry.borrow_mut().budget = Some(0);
        time.set(Some(200));
        let mut rounds = 0;
        while volume.authority.report.is_none() {
            ticks(&mut volume, &control, 1);
            rounds += 1;
            assert!(rounds < 8, "a periodic Report is submitted");
        }
        let submitted = volume.authority.report.expect("outstanding").2;
        if observed {
            volume.authority_deadlines();
            assert!(volume.authority.now > submitted);
        }
        time.set(fault);
        volume.authority_deadlines();
        assert_eq!(
            volume.authority_report().refusal,
            Some(AuthorityRefusal::Clock)
        );
        assert!(
            volume.authority.report.is_some(),
            "the Report stays in flight"
        );
        let machine = &volume.authority.machine;
        assert!(machine.window_end() <= machine.expired_at());
        time.set(Some(submitted + 2));
        registry.borrow_mut().budget = None;
        let mut rounds = 0;
        while volume.authority.report.is_some() {
            ticks(&mut volume, &control, 1);
            rounds += 1;
            assert!(rounds < 8, "the Report reaches its terminal");
        }
        let machine = &volume.authority.machine;
        let closed = machine.expired_at().expect("the fault closed the window");
        if machine.window_end().expect("a window") > closed {
            reopened.push((observed, fault, submitted, closed));
        }
        volume.close();
    }
    assert_eq!(
        reopened,
        [],
        "(observed, fault reading, Report submitted at, window closed at) of each Report that reopened the window"
    );
}

/// A deadline sweep visits every live read, but only exposing verified bytes
/// needs a fresh serving reading, so reads still in `Reading` add none.
#[test]
fn a_sweep_reads_the_serving_clock_only_for_reads_it_verifies() {
    use super::volume_tests::{CHUNK, SESSION, TICK, arena, attach, place, record, storage};
    let readings = |reading: u64| {
        let storage = storage(4);
        let arena = arena();
        let (mut volume, control) = attach(&storage, &arena, TICK);
        let mut timed = None;
        for read in 0..=reading {
            let record = record(read * 16, 0, CHUNK, SESSION, 35 + read);
            place(&storage, &control, &record);
            let deadline = if read == 0 { 1 } else { u64::MAX };
            let op = volume.read_raw(&record.read, deadline).unwrap();
            volume.grant_read(op).unwrap();
            timed.get_or_insert(op);
        }
        let count = Rc::new(Cell::new(0));
        volume.authority.clock = Box::new(Counted(Rc::clone(&count)));
        let mut out = Vec::with_capacity(8);
        volume.poll_storage(1, &mut out);
        let swept = count.get();
        assert!(
            matches!(out.as_slice(), [super::ReadEvent::Done { op, status: super::ReadStatus::TimedOut, .. }] if Some(*op) == timed)
        );
        for _ in 0..8 {
            control.tick(64);
            out.clear();
            volume.poll_storage(1, &mut out);
        }
        assert_eq!(volume.reads.live(), 0);
        volume.close();
        swept
    };
    assert_eq!(readings(3), readings(0));
}

/// The metadata gate's fresh reading belongs to each device submission; a
/// step with nothing staged submits nothing and reads no serving clock.
#[test]
fn an_idle_metadata_step_reads_no_serving_clock() {
    let storage = storage_with(|_| {});
    let arena = arena_with(4, 5);
    let mut dev = Device::new(&storage, &arena);
    for _ in 0..4 {
        dev.control.tick(64);
        poll(&mut dev);
    }
    assert!(
        dev.volume
            .metadata
            .commands
            .iter()
            .flatten()
            .all(|command| command.buffer.is_none()),
        "nothing staged"
    );
    dev.volume.authority.clock = Box::new(PanicClock);
    assert_eq!(dev.volume.metadata_step(1), 0);
    dev.volume.authority.clock = Box::new(Clock(Rc::new(Cell::new(0))));
    dev.volume.close();
}

/// Custody accounting counts a fill's outstanding commands without judging
/// its authority, so it reads no serving clock.
#[test]
fn a_fill_s_outstanding_commands_read_no_serving_clock() {
    let storage = storage_with(|_| {});
    let arena = arena_with(4, 5);
    let mut dev = Device::new(&storage, &arena);
    let _time = clock(&mut dev);
    let mut fill = super::super::writable_tests::reserve(&storage, &[3; 32], 0, 20).unwrap();
    for input in [&[3; 20][..], &[]] {
        fill.receive(
            &mut dev.volume,
            input,
            &mut super::super::volume_fixture::ample_io(),
        )
        .unwrap();
    }
    let outstanding = fill.progress(&dev.volume).outstanding_commands;
    assert!(outstanding > 0);
    dev.volume.authority.clock = Box::new(PanicClock);
    assert_eq!(fill.outstanding_commands(&dev.volume), outstanding);
    let _time = clock(&mut dev);
    dev.control.tick(64);
    poll(&mut dev);
    assert_eq!(fill.outstanding_commands(&dev.volume), 0);
    drop(fill);
    dev.volume.close();
}

/// FRESH-AT-EFFECT: a prepared owner turn with no terminal to apply and no
/// Report due takes one deadline sample, in `poll_terminals`.
#[test]
fn a_prepared_turn_with_nothing_to_apply_takes_one_deadline_sample() {
    let storage = storage_with(|_| {});
    let arena = arena_with(4, 5);
    let mut dev = Device::new(&storage, &arena);
    let count = Rc::new(Cell::new(0));
    dev.volume.authority.clock = Box::new(Counted(Rc::clone(&count)));
    let mut out = Vec::with_capacity(8);
    dev.volume.poll_terminals(0, &out);
    assert_eq!(
        count.get(),
        1,
        "the turn's first poll samples the deadlines"
    );
    dev.volume.poll_storage_prepared(0, &mut out);
    assert_eq!(count.get(), 1, "the prepared poll keeps that sample");
    dev.volume.authority.clock = Box::new(Clock(Rc::new(Cell::new(0))));
    dev.volume.close();
}

/// A write that completes after the turn's `poll_terminals` applies in that
/// turn's prepared poll, so its fill advances in the turn the write ended.
#[test]
fn a_write_that_ends_after_the_turns_first_poll_applies_in_the_same_turn() {
    let storage = storage_with(|_| {});
    let arena = arena_with(4, 5);
    let mut dev = Device::new(&storage, &arena);
    let _time = clock(&mut dev);
    let mut fill = super::super::writable_tests::reserve(&storage, &[3; 32], 0, 20).unwrap();
    for input in [&[3; 20][..], &[]] {
        fill.receive(
            &mut dev.volume,
            input,
            &mut super::super::volume_fixture::ample_io(),
        )
        .unwrap();
    }
    let outstanding = fill.outstanding_commands(&dev.volume);
    assert!(outstanding > 0, "the fill's writes are in flight");
    let mut out = Vec::with_capacity(8);
    dev.volume.poll_terminals(0, &out);
    assert_eq!(
        fill.outstanding_commands(&dev.volume),
        outstanding,
        "no write ended before the turn's first poll"
    );
    dev.control.tick(64);
    dev.volume.poll_storage_prepared(0, &mut out);
    assert_eq!(
        fill.outstanding_commands(&dev.volume),
        0,
        "the prepared poll applied the writes that ended after the first"
    );
    drop(fill);
    dev.volume.close();
}

/// FRESH-AT-EFFECT: a fill's progress and the precheck of a receive read no
/// serving clock, and each write command a receive submits takes one reading.
#[test]
fn a_fill_reads_the_serving_clock_once_for_each_write_it_submits() {
    let storage = storage_with(|_| {});
    let arena = arena_with(4, 5);
    let mut dev = Device::new(&storage, &arena);
    let count = Rc::new(Cell::new(0));
    dev.volume.authority.clock = Box::new(Counted(Rc::clone(&count)));
    let mut fill = super::super::writable_tests::reserve(&storage, &[3; 32], 0, 20).unwrap();
    let start = dev.volume.report().writes_submitted;
    let mut submitted = start;
    for input in [&[3; 10][..], &[3; 10], &[]] {
        let before = count.get();
        fill.receive(
            &mut dev.volume,
            input,
            &mut super::super::volume_fixture::ample_io(),
        )
        .unwrap();
        let writes = dev.volume.report().writes_submitted - submitted;
        submitted += writes;
        assert_eq!(
            u64::from(count.get() - before),
            writes,
            "one reading for each write a receive of {} bytes submitted",
            input.len()
        );
    }
    assert!(submitted > start, "the fill submitted its record");
    let before = count.get();
    assert!(fill.progress(&dev.volume).outstanding_commands > 0);
    assert_eq!(count.get(), before, "progress reads no serving clock");
    dev.volume.authority.clock = Box::new(Clock(Rc::new(Cell::new(0))));
    dev.control.tick(64);
    poll(&mut dev);
    drop(fill);
    dev.volume.close();
}

/// FRESH-AT-EFFECT: a serving clock that steps backward between two deadline
/// samples refuses the write a receive submits, on that write's own reading,
/// so nothing reaches the device, while the fill's progress still passes at
/// the latest sample; the next deadline sample fails the progress and
/// refuses a receive at its precheck.
#[test]
fn a_clock_fault_between_deadline_samples_refuses_the_write_before_the_checks_that_read_state() {
    use crate::storage::ReceiveError;
    let storage = storage_with(|_| {});
    let arena = arena_with(4, 5);
    let mut dev = Device::new(&storage, &arena);
    let time = clock(&mut dev);
    time.set(10);
    dev.volume.authority_deadlines();
    let mut fill = super::super::writable_tests::reserve(&storage, &[3; 32], 0, 20).unwrap();
    let mut io = super::super::volume_fixture::ample_io();
    assert_eq!(fill.receive(&mut dev.volume, &[3; 10], &mut io), Ok(10));
    assert_eq!(
        dev.volume.report().writes_submitted,
        0,
        "the first half stays staged"
    );
    time.set(9);
    assert!(
        !fill.progress(&dev.volume).failed,
        "progress passes at the latest deadline sample"
    );
    assert_eq!(
        fill.receive(&mut dev.volume, &[3; 10], &mut io),
        Ok(10),
        "the precheck passes at the latest deadline sample"
    );
    assert_eq!(
        fill.receive(&mut dev.volume, &[], &mut io),
        Err(ReceiveError::Closed),
        "the write is refused on its own reading"
    );
    assert_eq!(dev.volume.report().writes_submitted, 0);
    dev.volume.authority_deadlines();
    assert!(fill.progress(&dev.volume).failed);
    assert_eq!(
        fill.receive(&mut dev.volume, &[], &mut io),
        Err(ReceiveError::Closed),
        "the next deadline sample refuses at the precheck"
    );
    drop(fill);
    dev.volume.close();
}

/// A periodic Report after the fencing boundary with a foreign holder withdraws the tenure. A holder the authority's last volume-record read records withdraws with no flip request (RECORDED-HOLDER-HOLD), beside an unrecorded registrant inside its deferral window as well, which stays pending for the owner poll; an unrecorded holder triggers a flip request naming the tenure's own `(g, owner, E)`. A non-holding registrant outside the pairs of the authority's volume-record read keeps the tenure `Recovering` or `Serving`, renews the window and marks the authority pending for the next owner poll; a recorded one, or the own holder alone, renews the window and leaves nothing pending. An authority with no volume-record read judges by the own pair alone, so the same registrant withdraws it.
#[test]
fn a_foreign_holder_withdraws_and_an_unrecorded_registrant_waits_for_the_poll() {
    use super::gate_fixture::{arena, attach_reserving, foreign};
    use crate::failover::evidence::{NotSole, Registrant};
    use crate::failover::serving::ReportTrigger;
    // `stranger` adds an unrecorded non-holding registrant beside the foreign one.
    let unknown = crate::failover::evidence::Pair {
        exhid: crate::failover::identity::Exhid::new([0x44; 16]).unwrap(),
        key: crate::failover::identity::Key::decode((9 << 32) | 9).unwrap(),
    };
    for (registered, recorded, holds, stranger) in [
        (false, Some(false), false, false),
        (true, None, false, false),
        (true, Some(false), false, false),
        (true, Some(true), false, false),
        (true, Some(true), true, false),
        (true, Some(true), true, true),
        (true, Some(false), true, false),
    ] {
        let arena = arena();
        let storage = super::gate_fixture::storage();
        let mut authority = super::ServingAuthority::fixture();
        authority.recorded = recorded.map(|recorded| {
            if recorded {
                Box::new([foreign()]) as Box<[_]>
            } else {
                Box::new([])
            }
        });
        let target = authority.session().target();
        let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
        let time = Rc::new(Cell::new(0));
        volume.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
        super::gate_fixture::ticks(&mut volume, &control, 64);
        assert!(
            matches!(volume.authority_state(), State::Recovering | State::Serving),
            "the gate passed"
        );
        let reports = registry.borrow().log.len();
        if registered {
            let mut registry = registry.borrow_mut();
            // A type-2 reservation has one holder: a foreign holder took it from the own pair.
            for entry in &mut registry.entries {
                entry.holder &= !holds;
            }
            registry.entries.push(Registrant {
                cntlid: 20,
                holder: holds,
                pair: foreign(),
            });
            if stranger {
                registry.entries.push(Registrant {
                    cntlid: 21,
                    holder: false,
                    pair: unknown,
                });
            }
        }
        time.set(1_000);
        super::gate_fixture::ticks(&mut volume, &control, 8);
        assert!(
            registry.borrow().log.len() > reports,
            "a periodic Report went out"
        );
        let report = volume.authority_report();
        assert_eq!(
            report.own_records,
            Some(1),
            "{registered} {recorded:?} {holds} {stranger}: one record carries the own host ID"
        );
        // RECORDED-HOLDER-HOLD: a recorded holder withdraws with no flip request; an unrecorded holder or an
        // unrecorded registrant without a volume record retires with the flip.
        let withdrawal = match (registered, recorded, holds) {
            (true, Some(true), true) => Some((Cause::RecordedHolder, None)),
            (true, _, true) => Some((
                Cause::Report(ReportTrigger::new(NotSole::ForeignHolder).unwrap()),
                Some(target),
            )),
            (true, None, false) => Some((
                Cause::Report(ReportTrigger::new(NotSole::ForeignRegistrant).unwrap()),
                Some(target),
            )),
            _ => None,
        };
        let pending = registered && (recorded == Some(false) && !holds || stranger);
        assert_eq!(
            report.pending, pending,
            "{registered} {recorded:?} {holds} {stranger}"
        );
        // The judgment names the verdict, a deferred registrant included, and the hold reads the recorded holder.
        let judgment = match (registered, recorded, holds) {
            (false, ..) => super::RegistrantJudgment::Sole,
            (true, _, true) => super::RegistrantJudgment::Refused(NotSole::ForeignHolder),
            (true, Some(true), false) => super::RegistrantJudgment::Recorded,
            (true, _, false) => super::RegistrantJudgment::Refused(NotSole::ForeignRegistrant),
        };
        let held = matches!(withdrawal, Some((Cause::RecordedHolder, _)));
        assert_eq!(
            (report.registrants, report.hold),
            (
                Some(judgment),
                if held {
                    super::HoldState::Held
                } else {
                    super::HoldState::Clear
                }
            ),
            "{registered} {recorded:?} {holds} {stranger}"
        );
        use crate::failover::report::alarm_tests::controls;
        use crate::failover::report::{Registrants, Withdrawal};
        let labels = (
            report.registrants.map(Registrants::from),
            report.withdrawal.map(Withdrawal::from),
        );
        match (registered, recorded, holds) {
            (false, ..) => assert_eq!(labels, controls::registrant_foreign().clean),
            (true, None | Some(false), true) => {
                assert_eq!(labels, controls::registrant_foreign().fault)
            }
            (true, Some(false), false) => assert_eq!(labels, controls::registrant_deferred()),
            _ => {}
        }
        if let Some((cause, flip)) = withdrawal {
            assert_eq!(
                (report.state, report.withdrawal, report.flip),
                (State::Withdrawn, Some(cause), flip),
                "{registered} {recorded:?} {holds} {stranger}"
            );
        } else {
            assert!(matches!(report.state, State::Recovering | State::Serving));
            assert_eq!((report.withdrawal, report.flip), (None, None));
            assert!(
                volume.metadata_authorized(crate::failover::serving::MetadataKind::CheckpointRoot),
                "{registered} {recorded:?} {holds} {stranger}: the Report renews the window"
            );
            assert_eq!(volume.authority.machine.window_start(), Some(1_000));
            assert_eq!(volume.authority.machine.expired_at(), None);
        }
    }
}

/// NO-HOLDER-HOLD: a periodic Report after the fencing boundary that shows nobody holding, the own pair registered
/// without holding or no reservation, beside the own pair and the pairs of the authority's last volume-record read,
/// withdraws the tenure with `Cause::Unheld` and no flip request: a registration that ended without a preempt shows
/// no volume loss. An unrecorded registrant the cached set omits, a standby enrolled after the last owner poll,
/// withdraws the same way inside its deferral window and stays pending for the owner's poll. A second record of the
/// own pair fails the Report's identity check at parse, before either hold is judged, and withdraws with the
/// `DuplicateOwnRecord` trigger and the flip naming the tenure's own `(g, owner, E)`. An authority with no recorded set
/// judges the hold over the own pair alone after the boundary: an own-only Report withdraws with `Cause::Unheld`, and a
/// non-holding registrant beside it keeps the Report trigger with the flip and nothing pending.
#[test]
fn nobody_holding_beside_recorded_registrants_withdraws_with_no_flip() {
    use super::gate_fixture::{arena, attach_reserving, foreign};
    use crate::failover::evidence::{NotSole, Registrant};
    use crate::failover::serving::ReportTrigger;
    let unknown = crate::failover::evidence::Pair {
        exhid: crate::failover::identity::Exhid::new([0x44; 16]).unwrap(),
        key: crate::failover::identity::Key::decode((9 << 32) | 9).unwrap(),
    };
    // (rtype, extra registrant: 0 foreign(), 1 unknown, 2 a second own record, 3 none; the authority's recorded set
    // holds foreign(), or the authority has none)
    let rows = [(2, 0), (0, 0), (2, 1), (0, 1), (0, 2), (2, 3), (0, 3)]
        .map(|(rtype, extra)| (rtype, extra, true))
        .into_iter()
        .chain([(2, 3, false), (0, 3, false), (2, 0, false), (0, 0, false)]);
    for (rtype, extra, recorded) in rows {
        let arena = arena();
        let storage = super::gate_fixture::storage();
        let mut authority = super::ServingAuthority::fixture();
        authority.recorded = recorded.then(|| Box::new([foreign()]) as Box<[_]>);
        let target = authority.session().target();
        let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
        let time = Rc::new(Cell::new(0));
        volume.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
        super::gate_fixture::ticks(&mut volume, &control, 64);
        assert!(
            matches!(volume.authority_state(), State::Recovering | State::Serving),
            "the gate passed"
        );
        let reports = registry.borrow().log.len();
        {
            let mut registry = registry.borrow_mut();
            registry.rtype = rtype;
            for entry in &mut registry.entries {
                entry.holder = false;
            }
            let own = registry.entries[0].pair;
            if extra < 3 {
                registry.entries.push(Registrant {
                    cntlid: 20,
                    holder: false,
                    pair: [foreign(), unknown, own][extra],
                });
            }
        }
        time.set(1_000);
        super::gate_fixture::ticks(&mut volume, &control, 8);
        assert!(
            registry.borrow().log.len() > reports,
            "a periodic Report went out"
        );
        let trigger = |refusal| Cause::Report(ReportTrigger::new(refusal).unwrap());
        let expected = match (extra, recorded, rtype) {
            (2, ..) => (trigger(NotSole::DuplicateOwnRecord), Some(target)),
            (0, false, 2) => (trigger(NotSole::ForeignRegistrant), Some(target)),
            (0, false, _) => (trigger(NotSole::ReservationType), Some(target)),
            _ => (Cause::Unheld, None),
        };
        let report = volume.authority_report();
        assert_eq!(
            (report.state, report.withdrawal, report.flip),
            (State::Withdrawn, Some(expected.0), expected.1),
            "rtype {rtype}, extra registrant {extra}, recorded set {recorded}"
        );
        assert_eq!(
            report.pending,
            extra == 1,
            "rtype {rtype}, extra registrant {extra}, recorded set {recorded}"
        );
        assert_eq!(
            report.own_records,
            Some(if extra == 2 { 2 } else { 1 }),
            "rtype {rtype}, extra registrant {extra}, recorded set {recorded}"
        );
        let unheld = expected.0 == Cause::Unheld;
        assert_eq!(
            report.hold,
            if unheld {
                super::HoldState::Held
            } else {
                super::HoldState::Clear
            },
            "rtype {rtype}, extra registrant {extra}, recorded set {recorded}"
        );
        // Nobody holding refuses the judgment: a second own record first, then a type other than 2, then a
        // registrant outside the recorded pairs, and otherwise the missing holder.
        let judgment = match (extra, rtype, recorded) {
            (2, ..) => NotSole::DuplicateOwnRecord,
            (_, 0, _) => NotSole::ReservationType,
            (1, ..) | (0, _, false) => NotSole::ForeignRegistrant,
            _ => NotSole::NotHolder,
        };
        assert_eq!(
            report.registrants,
            Some(super::RegistrantJudgment::Refused(judgment)),
            "rtype {rtype}, extra registrant {extra}, recorded set {recorded}"
        );
    }
}

/// A pair outside the recorded pairs that two controllers register fills two adjacent Report entries and takes one
/// deferral, anchored at the first Report that listed it; the next Report finds that deferral and adds none.
#[test]
fn a_pair_listed_under_two_controllers_takes_one_deferral() {
    use super::gate_fixture::{arena, attach_reserving, foreign, own};
    use crate::failover::evidence::Registrant;
    let arena = arena();
    let storage = super::gate_fixture::storage();
    let mut authority = super::ServingAuthority::fixture();
    authority.recorded = Some(Box::new([own()]));
    let (mut dev, control, registry) = attach_reserving(&storage, &arena, authority);
    let time = Rc::new(Cell::new(0));
    dev.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
    super::gate_fixture::ticks(&mut dev, &control, 64);
    for cntlid in [20, 21] {
        registry.borrow_mut().entries.push(Registrant {
            cntlid,
            holder: false,
            pair: foreign(),
        });
    }
    for now in [1_000, 2_000] {
        let reports = registry.borrow().log.len();
        time.set(now);
        super::gate_fixture::ticks(&mut dev, &control, 8);
        assert!(registry.borrow().log.len() > reports, "at {now}");
        assert_eq!(dev.authority.pending, [(foreign(), 1_000)], "at {now}");
        let report = dev.authority_report();
        assert_eq!(
            (report.withdrawal, report.flip, report.pending),
            (None, None, true),
            "at {now}"
        );
    }
}

/// Deferrals that two Reports anchor are kept in key order, each with the submission time of the first Report that
/// listed its pair. A pair's window runs from its own anchor: the Report submitted one window after the earlier
/// anchor withdraws with `Cause::Unverified` and no flip request while the later pair is inside its window
/// (LAPSE-UNVERIFIED); every pair stays deferred, and a pair that Report lists first takes its anchor there.
#[test]
fn deferrals_from_two_reports_keep_key_order_and_their_own_anchors() {
    use super::gate_fixture::{ZeroClock, arena, attach_reserving, limits, own};
    use crate::failover::bounds::Bounds;
    use crate::failover::evidence::{Pair, Registrant};
    use crate::failover::identity::{Exhid, Key};
    use crate::failover::serving::Machine;
    let unrecorded = |tag: u8, key: u64| Pair {
        exhid: Exhid::new([tag; 16]).unwrap(),
        key: Key::decode(key).unwrap(),
    };
    let (low, high) = (
        unrecorded(0x31, (2 << 32) | 1),
        unrecorded(0x32, (3 << 32) | 1),
    );
    let registrant = |cntlid, pair| Registrant {
        cntlid,
        holder: false,
        pair,
    };
    let bounds = Bounds::new(limits().registrants(), 1, 1_000, 100, 100, 0).unwrap();
    let session = crate::storage::next_session();
    let mut authority = super::ServingAuthority::new(
        bounds,
        Machine::issued(bounds, &session, own()),
        Box::new(ZeroClock),
        session,
    );
    authority.recorded = Some(Box::new([own()]));
    let arena = arena();
    let storage = super::gate_fixture::storage();
    let (mut dev, control, registry) = attach_reserving(&storage, &arena, authority);
    let time = Rc::new(Cell::new(0));
    dev.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
    super::gate_fixture::ticks(&mut dev, &control, 64);
    let mut report_at = |now: u64, added: Option<Registrant>| {
        registry.borrow_mut().entries.extend(added);
        let reports = registry.borrow().log.len();
        time.set(now);
        super::gate_fixture::ticks(&mut dev, &control, 8);
        assert!(registry.borrow().log.len() > reports, "at {now}");
        let report = dev.authority_report();
        (
            dev.authority.pending.clone(),
            report.withdrawal,
            report.flip,
        )
    };
    assert_eq!(
        report_at(1_000, Some(registrant(20, high))),
        (vec![(high, 1_000)], None, None)
    );
    assert_eq!(
        report_at(1_500, Some(registrant(21, low))),
        (vec![(low, 1_500), (high, 1_000)], None, None)
    );
    let mid = unrecorded(0x33, (2 << 32) | 5);
    assert_eq!(
        report_at(2_000, Some(registrant(22, mid))),
        (
            vec![(low, 1_500), (mid, 2_000), (high, 1_000)],
            Some(Cause::Unverified),
            None
        ),
        "the lapsing Report keeps the newcomer it anchors, in key order"
    );
}

/// A standby that enrolls and registers after the tenure's activation keeps the owner serving: each periodic Report
/// before any owner poll certifies, renews the serving window and marks the authority pending. An owner poll replaces
/// the recorded pairs from its volume record and drops the deferral of each pair that record enrolls. Listing both instances with the standby unbound
/// retires `Attachment(Foreign)`; with the standby bound as a peer, a record that enrolls the standby's pair
/// continues and the next Report admits the registrant with nothing pending, and a record without that pair retires
/// with the Report trigger.
#[test]
fn an_owner_poll_admits_a_standby_enrolled_after_activation() {
    use super::gate_fixture::{arena, attach_reserving, foreign, own};
    use crate::failover::attachments::{InstanceId, Mismatch, Peer};
    use crate::failover::evidence::{NotSole, Registrant};
    use crate::failover::poll::{Reads, Verdict};
    use crate::failover::poll_tests::{enrolled, listed, owner, report_of, serving, volume};
    use crate::failover::records::{EventKind, Host, VolumeState};
    use crate::failover::retire::{Target, Trigger};
    use crate::failover::serving::MetadataKind;
    let holder = owner();
    let standby = Host::new(holder.host.get() + 100).unwrap();
    let standby_instance = InstanceId::new("i-0bbbbbbbbbbbbbbb0").unwrap();
    let peers = [Peer {
        host: standby,
        instance: standby_instance,
    }];
    let mut attached = volume(VolumeState::Active, holder.host);
    attached.push(EventKind::Attach, standby, 2);
    let admitted = enrolled(
        &attached,
        &[(holder.host, own(), 0), (standby, foreign(), 1)],
    );
    let unenrolled = enrolled(&attached, &[(holder.host, own(), 0)]);
    let registrant = Registrant {
        cntlid: 20,
        holder: false,
        pair: foreign(),
    };
    for record in [&admitted, &unenrolled] {
        let arena = arena();
        let storage = super::gate_fixture::storage();
        let mut authority = super::ServingAuthority::fixture();
        authority.recorded = Some(Box::new([own()]));
        let (mut dev, control, registry) = attach_reserving(&storage, &arena, authority);
        let time = Rc::new(Cell::new(0));
        dev.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
        super::gate_fixture::ticks(&mut dev, &control, 64);
        assert!(matches!(
            dev.authority_state(),
            State::Recovering | State::Serving
        ));
        registry.borrow_mut().entries.push(registrant);
        for (round, now) in [1_000, 2_000].into_iter().enumerate() {
            let reports = registry.borrow().log.len();
            time.set(now);
            super::gate_fixture::ticks(&mut dev, &control, 8);
            assert!(registry.borrow().log.len() > reports, "round {round}");
            let report = dev.authority_report();
            assert!(matches!(report.state, State::Recovering | State::Serving));
            assert_eq!(
                (report.withdrawal, report.flip, report.pending),
                (None, None, true),
                "round {round}"
            );
            assert!(
                dev.metadata_authorized(MetadataKind::CheckpointRoot),
                "round {round}: the pending Report renews the window"
            );
            assert_eq!(
                dev.authority.machine.window_start(),
                Some(now),
                "round {round}"
            );
            assert_eq!(dev.authority.machine.expired_at(), None, "round {round}");
        }
        let shard = serving();
        let both = listed(&[holder.instance.as_str(), standby_instance.as_str()]);
        let entries = [
            Registrant {
                cntlid: 1,
                holder: true,
                pair: own(),
            },
            registrant,
        ];
        let reads = Reads {
            shard: Some(&shard),
            volume: Some(record),
            listed: Some(&both),
            peers: &[],
        };
        let target = Target::of(&shard);
        let Verdict::Retire(unbound) = dev.owner_poll(
            &holder,
            target,
            own(),
            Ok(&report_of(&entries)),
            &reads,
            dev.serving_sample(),
        ) else {
            panic!("an unbound standby's listing retires");
        };
        assert_eq!(
            unbound.trigger(),
            &Trigger::Attachment(Mismatch::Foreign(standby_instance.as_str().to_owned()))
        );
        let reads = Reads {
            peers: &peers,
            ..reads
        };
        let verdict = dev.owner_poll(
            &holder,
            target,
            own(),
            Ok(&report_of(&entries)),
            &reads,
            dev.serving_sample(),
        );
        assert_eq!(
            dev.authority_report().pending,
            !std::ptr::eq(record, &admitted),
            "the poll drops the deferral of a pair its record enrolls and keeps the others"
        );
        if std::ptr::eq(record, &admitted) {
            assert_eq!(verdict, Verdict::Continue);
            time.set(3_000);
            super::gate_fixture::ticks(&mut dev, &control, 8);
            let report = dev.authority_report();
            assert!(matches!(report.state, State::Recovering | State::Serving));
            assert_eq!(
                (report.withdrawal, report.flip, report.pending),
                (None, None, false)
            );
            assert!(dev.metadata_authorized(MetadataKind::CheckpointRoot));
            assert_eq!(dev.authority.machine.expired_at(), None);
            // The standby the poll enrolled becomes the sole holder: the next Report holds on the recorded pairs the
            // poll refreshed and requests no flip.
            for entry in &mut registry.borrow_mut().entries {
                entry.holder = entry.pair == foreign();
            }
            time.set(4_000);
            super::gate_fixture::ticks(&mut dev, &control, 8);
            let report = dev.authority_report();
            assert_eq!(
                (report.state, report.withdrawal, report.flip),
                (
                    State::Withdrawn,
                    Some(crate::failover::serving::Cause::RecordedHolder),
                    None
                ),
                "the refreshed recorded pairs admit the hold"
            );
        } else {
            let Verdict::Retire(retirement) = verdict else {
                panic!("a record without the standby's pair retires: {verdict:?}");
            };
            assert_eq!(
                retirement.trigger(),
                &Trigger::Report(NotSole::ForeignRegistrant)
            );
        }
    }
}

/// ROLE-BOUND after a successor observation: an owner poll without a shard read retires on a listing with an
/// attachment outside the desired state after a deposing status, and is `Deposed` once the authority has observed a
/// later tenure, so the poll requests no retirement naming the deposed `(g, owner, E)`.
#[test]
fn an_owner_poll_after_a_successor_observation_is_deposed() {
    use super::gate_fixture::{arena, attach_reserving, own};
    use crate::failover::evidence::Registrant;
    use crate::failover::poll::{Reads, Verdict};
    use crate::failover::poll_tests::{listed, owner, report_of, serving, volume};
    use crate::failover::records::VolumeState;
    use crate::failover::retire::Target;
    use crate::failover::serving::Deposing;
    let holder = owner();
    let arena = arena();
    let storage = super::gate_fixture::storage();
    let (mut dev, control, _registry) =
        attach_reserving(&storage, &arena, super::ServingAuthority::fixture());
    super::gate_fixture::ticks(&mut dev, &control, 64);
    let target = Target::of(&serving());
    let sole = [Registrant {
        cntlid: 1,
        holder: true,
        pair: own(),
    }];
    let report = report_of(&sole);
    let record = volume(VolumeState::Active, holder.host);
    let stray = listed(&[holder.instance.as_str(), "i-0ccccccccccccccc0"]);
    let reads = Reads {
        shard: None,
        volume: Some(&record),
        listed: Some(&stray),
        peers: &[],
    };
    dev.authority_event(Event::Withdraw(Cause::Status(Deposing::Conflict)));
    let verdict = dev.owner_poll(
        &holder,
        target,
        own(),
        Ok(&report),
        &reads,
        dev.serving_sample(),
    );
    assert!(
        matches!(verdict, Verdict::Retire(_)),
        "before any successor observation the listing retires: {verdict:?}"
    );
    dev.authority_event(Event::Withdraw(Cause::Flipped));
    assert_eq!(
        dev.owner_poll(
            &holder,
            target,
            own(),
            Ok(&report),
            &reads,
            dev.serving_sample()
        ),
        Verdict::Deposed,
        "after the successor observation the poll is deposed"
    );
    assert_eq!(dev.authority_report().flip, None);
}

/// TransferRetainsVolume: if `Cause::Planned` withdrew the machine first, an owner poll over a listing with an
/// attachment outside the desired state returns `Withdraw`, and the authority reports no flip. The same poll retires
/// after `Cause::Status(Deposing::Conflict)`, also when `Cause::Planned` follows it. A successor observation after
/// the planned exit deposes the poll.
#[test]
fn an_owner_poll_after_a_planned_withdrawal_requests_no_retirement() {
    use super::gate_fixture::{arena, attach_reserving, own};
    use crate::failover::evidence::Registrant;
    use crate::failover::poll::{Reads, Verdict};
    use crate::failover::poll_tests::{listed, owner, report_of, volume};
    use crate::failover::records::VolumeState;
    use crate::failover::serving::Deposing;
    let holder = owner();
    let sole = [Registrant {
        cntlid: 1,
        holder: true,
        pair: own(),
    }];
    let report = report_of(&sole);
    let record = volume(VolumeState::Active, holder.host);
    let retired = volume(VolumeState::Retired, holder.host);
    let stray = listed(&[holder.instance.as_str(), "i-0ccccccccccccccc0"]);
    let alone = listed(&[holder.instance.as_str()]);
    let reads = Reads {
        shard: None,
        volume: Some(&record),
        listed: Some(&stray),
        peers: &[],
    };
    let status = Cause::Status(Deposing::Conflict);
    for (withdrawals, retires) in [
        (&[Cause::Planned][..], false),
        (&[status][..], true),
        (&[status, Cause::Planned][..], true),
    ] {
        let arena = arena();
        let storage = super::gate_fixture::storage();
        let authority = super::ServingAuthority::fixture();
        let target = authority.session().target();
        let (mut dev, control, _registry) = attach_reserving(&storage, &arena, authority);
        super::gate_fixture::ticks(&mut dev, &control, 64);
        for cause in withdrawals {
            dev.authority_event(Event::Withdraw(*cause));
        }
        assert_eq!(
            dev.authority_report().withdrawal,
            withdrawals.first().copied()
        );
        let verdict = dev.owner_poll(
            &holder,
            target,
            own(),
            Ok(&report),
            &reads,
            dev.serving_sample(),
        );
        if retires {
            let Verdict::Retire(retirement) = verdict else {
                panic!("{withdrawals:?}: the listing retires: {verdict:?}");
            };
            assert_eq!(retirement.target, target, "{withdrawals:?}");
        } else {
            assert_eq!(
                verdict,
                Verdict::Withdraw,
                "{withdrawals:?}: the planned exit keeps the volume"
            );
            assert_eq!(dev.authority_report().flip, None);
            assert!(!dev.authority.machine.superseded());
            let clean = Reads {
                listed: Some(&alone),
                ..reads
            };
            assert_eq!(
                dev.owner_poll(
                    &holder,
                    target,
                    own(),
                    Ok(&report),
                    &clean,
                    dev.serving_sample()
                ),
                Verdict::Unobserved,
                "a clean poll without the shard read passes through"
            );
            let deposing = Reads {
                volume: Some(&retired),
                ..reads
            };
            assert_eq!(
                dev.owner_poll(
                    &holder,
                    target,
                    own(),
                    Ok(&report),
                    &deposing,
                    dev.serving_sample()
                ),
                Verdict::Deposed,
                "a retired volume record deposes the planned tenure"
            );
            dev.authority_event(Event::Withdraw(Cause::Flipped));
            assert_eq!(
                dev.owner_poll(
                    &holder,
                    target,
                    own(),
                    Ok(&report),
                    &reads,
                    dev.serving_sample()
                ),
                Verdict::Deposed,
                "after the successor observation the poll is deposed"
            );
        }
    }
}

/// RECORDED-PAIRS-FOLLOW-READS without allocation: an owner poll whose volume record holds the authority's recorded
/// pairs keeps them and allocates nothing, a record that ends the standby's attach keeps its pair recorded, and the
/// standby's pair holding at the next serving Report then withdraws with `RecordedHolder` and no flip request.
#[test]
fn an_owner_poll_replaces_the_recorded_pairs_only_when_its_volume_record_changes_them() {
    use super::gate_fixture::{arena, attach_reserving, foreign, own};
    use crate::failover::attachments::{InstanceId, Peer};
    use crate::failover::evidence::Registrant;
    use crate::failover::poll::{Reads, Verdict};
    use crate::failover::poll_tests::{enrolled, listed, owner, report_of, serving, volume};
    use crate::failover::records::{EventKind, Host, VolumeState};
    use crate::failover::retire::Target;
    let holder = owner();
    let standby = Host::new(holder.host.get() + 100).unwrap();
    let peers = [Peer {
        host: standby,
        instance: InstanceId::new("i-0bbbbbbbbbbbbbbb0").unwrap(),
    }];
    let mut attached = volume(VolumeState::Active, holder.host);
    attached.push(EventKind::Attach, standby, 2);
    let record = enrolled(
        &attached,
        &[(holder.host, own(), 0), (standby, foreign(), 1)],
    );
    let mut detached = record.clone();
    detached.push(EventKind::Detach, standby, 2);
    let arena = arena();
    let storage = super::gate_fixture::storage();
    let mut authority = super::ServingAuthority::fixture();
    authority.recorded = Some(Box::new([own()]));
    let (mut dev, control, registry) = attach_reserving(&storage, &arena, authority);
    let time = Rc::new(Cell::new(0));
    dev.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
    super::gate_fixture::ticks(&mut dev, &control, 64);
    let shard = serving();
    let target = Target::of(&shard);
    let own_entry = Registrant {
        cntlid: 1,
        holder: true,
        pair: own(),
    };
    let entries = [
        own_entry,
        Registrant {
            cntlid: 20,
            holder: false,
            pair: foreign(),
        },
    ];
    let both = listed(&[holder.instance.as_str(), peers[0].instance.as_str()]);
    let reads = Reads {
        shard: Some(&shard),
        volume: Some(&record),
        listed: Some(&both),
        peers: &peers,
    };
    let report = report_of(&entries);
    assert_eq!(
        dev.owner_poll(
            &holder,
            target,
            own(),
            Ok(&report),
            &reads,
            dev.serving_sample()
        ),
        Verdict::Continue
    );
    let pairs =
        |dev: &super::Volume<'_, '_, _, _>| dev.authority.recorded.as_deref().map(<[_]>::to_vec);
    assert_eq!(pairs(&dev), Some(record.recorded_pairs()));
    let allocations = crate::instrument::allocations();
    assert_eq!(
        dev.owner_poll(
            &holder,
            target,
            own(),
            Ok(&report),
            &reads,
            dev.serving_sample()
        ),
        Verdict::Continue
    );
    assert_eq!(
        crate::instrument::allocations(),
        allocations,
        "a poll whose record matches the held pairs allocates nothing"
    );
    let alone = listed(&[holder.instance.as_str()]);
    let sole = [own_entry];
    let report = report_of(&sole);
    let reads = Reads {
        volume: Some(&detached),
        listed: Some(&alone),
        ..reads
    };
    assert_eq!(
        dev.owner_poll(
            &holder,
            target,
            own(),
            Ok(&report),
            &reads,
            dev.serving_sample()
        ),
        Verdict::Continue
    );
    assert_eq!(
        pairs(&dev),
        Some(record.recorded_pairs()),
        "the detached standby stays recorded"
    );
    registry.borrow_mut().entries.push(Registrant {
        cntlid: 20,
        holder: true,
        pair: foreign(),
    });
    for entry in &mut registry.borrow_mut().entries {
        entry.holder = entry.pair == foreign();
    }
    time.set(1_000);
    super::gate_fixture::ticks(&mut dev, &control, 8);
    let report = dev.authority_report();
    assert_eq!(
        (report.state, report.withdrawal, report.flip),
        (
            State::Withdrawn,
            Some(crate::failover::serving::Cause::RecordedHolder),
            None
        ),
        "a holder recorded for an ended attach holds with no flip request"
    );
}

/// A non-holding registrant whose recorded pair pins its host's live attach reads `Recorded`. Once the owner poll's
/// volume record ends that attach, by a detach event or by the entry's ended mark, the next Report reads `Ended`.
/// Every Report also lists a second standby's recorded pair under its own derived key, which sorts between the own
/// pair's key and the first standby's legacy key: the label reads `Ended` when either standby's attach ends, with the
/// other one live, and `Recorded` while both are live.
#[test]
fn a_registrant_recorded_for_an_ended_attach_reads_ended() {
    use super::gate_fixture::{arena, attach_reserving, foreign, own};
    use crate::failover::evidence::{Pair, Registrant};
    use crate::failover::identity::Exhid;
    use crate::failover::poll::{Reads, Verdict};
    use crate::failover::poll_tests::{enrolled, listed, owner, report_of, serving, volume};
    use crate::failover::records::{EventKind, Host, VolumeState};
    use crate::failover::retire::Target;
    let holder = owner();
    let standby = Host::new(holder.host.get() + 100).unwrap();
    let kept_host = Host::new(holder.host.get() + 101).unwrap();
    let mut attached = volume(VolumeState::Active, holder.host);
    attached.push(EventKind::Attach, standby, 2);
    let kept_seq = attached.push(EventKind::Attach, kept_host, 2).unwrap();
    let kept = Pair {
        exhid: Exhid::new([3; 16]).unwrap(),
        key: crate::failover::records::attachment_key(kept_seq).unwrap(),
    };
    assert!(own().key < kept.key && kept.key < foreign().key);
    let live = enrolled(
        &attached,
        &[
            (holder.host, own(), 0),
            (standby, foreign(), 1),
            (kept_host, kept, 2),
        ],
    );
    let mut detached = live.clone();
    detached.push(EventKind::Detach, standby, 2);
    let mut marked = live.clone();
    marked.events[1].kind = EventKind::Ended;
    let mut kept_ended = live.clone();
    kept_ended.events[2].kind = EventKind::Ended;
    let arena = arena();
    let storage = super::gate_fixture::storage();
    let mut authority = super::ServingAuthority::fixture();
    authority.recorded = Some(Box::new([own()]));
    let (mut dev, control, registry) = attach_reserving(&storage, &arena, authority);
    let time = Rc::new(Cell::new(0));
    dev.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
    super::gate_fixture::ticks(&mut dev, &control, 64);
    registry.borrow_mut().entries.extend([
        Registrant {
            cntlid: 20,
            holder: false,
            pair: foreign(),
        },
        Registrant {
            cntlid: 21,
            holder: false,
            pair: kept,
        },
    ]);
    let shard = serving();
    let target = Target::of(&shard);
    let sole = [Registrant {
        cntlid: 1,
        holder: true,
        pair: own(),
    }];
    let alone = listed(&[holder.instance.as_str()]);
    for (round, (record, judgment)) in [
        (&live, super::RegistrantJudgment::Recorded),
        (&detached, super::RegistrantJudgment::Ended),
        (&live, super::RegistrantJudgment::Recorded),
        (&marked, super::RegistrantJudgment::Ended),
        (&live, super::RegistrantJudgment::Recorded),
        (&kept_ended, super::RegistrantJudgment::Ended),
    ]
    .into_iter()
    .enumerate()
    {
        let reads = Reads {
            shard: Some(&shard),
            volume: Some(record),
            listed: Some(&alone),
            peers: &[],
        };
        let poll = |dev: &mut super::Volume<'_, '_, _, _>| {
            dev.owner_poll(
                &holder,
                target,
                own(),
                Ok(&report_of(&sole)),
                &reads,
                dev.serving_sample(),
            )
        };
        assert_eq!(poll(&mut dev), Verdict::Continue, "round {round}");
        let allocations = crate::instrument::allocations();
        assert_eq!(poll(&mut dev), Verdict::Continue, "round {round}");
        assert_eq!(
            crate::instrument::allocations(),
            allocations,
            "round {round}: a poll whose record matches the held pairs allocates nothing"
        );
        time.set(1_000 * (round as u64 + 1));
        super::gate_fixture::ticks(&mut dev, &control, 8);
        let report = dev.authority_report();
        assert_eq!(report.registrants, Some(judgment), "round {round}");
        assert!(
            matches!(report.state, State::Recovering | State::Serving),
            "round {round}"
        );
        assert_eq!(
            (report.withdrawal, report.flip, report.pending),
            (None, None, false),
            "round {round}"
        );
    }
}

/// The label's second case: a non-holding registrant whose pair the volume record no longer holds, under the key of
/// an ended entry, reads `Ended` once an owner poll admits it (`VolumeRecord::admitted`), as a recorded pair of an
/// ended attach does. With the entry still live the record admits no such pair: the poll retires on the foreign
/// registrant's Report and no Report reads `Ended`. The label is an observation of each Report: two Reports, each
/// a new Report command that completes and renews the authority, list the pair and read `Ended` twice from one
/// Register.
#[test]
fn an_unrecorded_registrant_under_an_ended_entry_key_reads_ended() {
    use super::gate_fixture::{arena, attach_reserving, foreign, own};
    use crate::failover::evidence::{NotSole, Pair, Registrant};
    use crate::failover::identity::{Epoch, Incarnation, Key};
    use crate::failover::poll::{Reads, Verdict};
    use crate::failover::poll_tests::{enrolled, listed, owner, report_of, serving, volume};
    use crate::failover::records::{EventKind, Host, VolumeState, attachment_key};
    use crate::failover::retire::{Target, Trigger};
    let holder = owner();
    let standby = Host::new(holder.host.get() + 100).unwrap();
    let mut attached = volume(VolumeState::Active, holder.host);
    let seq = attached.push(EventKind::Attach, standby, 2).unwrap();
    let late = Pair {
        key: attachment_key(seq).unwrap(),
        ..foreign()
    };
    let live = enrolled(&attached, &[(holder.host, own(), 0)]);
    let mut ended = live.clone();
    ended.events[1].kind = EventKind::Ended;
    for (record, reads_ended) in [(&live, false), (&ended, true)] {
        let arena = arena();
        let storage = super::gate_fixture::storage();
        let mut authority = super::ServingAuthority::fixture();
        authority.recorded = Some(Box::new([own()]));
        let (mut dev, control, registry) = attach_reserving(&storage, &arena, authority);
        let time = Rc::new(Cell::new(0));
        dev.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
        super::gate_fixture::ticks(&mut dev, &control, 64);
        let listing = [
            Registrant {
                cntlid: 1,
                holder: true,
                pair: own(),
            },
            Registrant {
                cntlid: 20,
                holder: false,
                pair: late,
            },
        ];
        registry.borrow_mut().entries.push(listing[1]);
        let shard = serving();
        let alone = listed(&[holder.instance.as_str()]);
        let reads = Reads {
            shard: Some(&shard),
            volume: Some(record),
            listed: Some(&alone),
            peers: &[],
        };
        let verdict = dev.owner_poll(
            &holder,
            Target::of(&shard),
            own(),
            Ok(&report_of(&listing)),
            &reads,
            dev.serving_sample(),
        );
        if reads_ended {
            assert_eq!(
                verdict,
                Verdict::Continue,
                "an ended entry's key admits the pair"
            );
        } else {
            let Verdict::Retire(retirement) = verdict else {
                panic!("a live entry's key admits no unrecorded pair: {verdict:?}");
            };
            assert_eq!(
                *retirement.trigger(),
                Trigger::Report(NotSole::ForeignRegistrant),
                "the poll retires on the foreign registrant"
            );
        }
        let expected = if reads_ended {
            super::RegistrantJudgment::Ended
        } else {
            super::RegistrantJudgment::Refused(NotSole::ForeignRegistrant)
        };
        for report in 1..=2 {
            let before = registry.borrow().reports();
            time.set(1_000 * report);
            super::gate_fixture::ticks(&mut dev, &control, 8);
            assert!(
                registry.borrow().reports() > before,
                "Report {report} is a new Report command"
            );
            let judged = dev.authority_report();
            assert_eq!(
                judged.report_age_us,
                Some(0),
                "Report {report} completed and was judged at its own submission"
            );
            assert_eq!(judged.registrants, Some(expected), "Report {report}");
        }
        if reads_ended {
            // A refusal takes precedence over the label: a second non-holding pair that no read admitted, listed
            // beside the admitted ended pair, reads foreign-registrant on the next Report.
            let stranger = Pair {
                key: Key::new(Epoch::new(3).unwrap(), Incarnation::new(1).unwrap()),
                ..late
            };
            registry.borrow_mut().entries.push(Registrant {
                cntlid: 21,
                holder: false,
                pair: stranger,
            });
            let before = registry.borrow().reports();
            time.set(3_000);
            super::gate_fixture::ticks(&mut dev, &control, 8);
            assert!(registry.borrow().reports() > before);
            let judged = dev.authority_report();
            assert_eq!(judged.report_age_us, Some(0));
            assert_eq!(
                judged.registrants,
                Some(super::RegistrantJudgment::Refused(
                    NotSole::ForeignRegistrant
                )),
                "an unadmitted registrant beside the admitted ended one"
            );
        }
    }
}

/// SERVING-DEFERS-UNRECORDED is bounded per pair by one serving window from the first Report that listed it: Reports
/// submitted before it ends certify, each renewing the window from its own submission, a Report without the pair
/// keeps its start, and an owner poll without a volume record, or with a record of another volume, keeps it too. A
/// second unrecorded pair first listed later takes its own window, so the first Report at or past the first pair's
/// end that lists it withdraws with `Cause::Unverified` and no flip request (LAPSE-UNVERIFIED). A Report on which
/// nobody holds beside an unrecorded registrant inside its window withdraws at once under NO-HOLDER-HOLD with
/// `Cause::Unheld`, no flip request and the pair kept pending for the owner's poll to judge. The deferral holds at
/// most `N_reg` pairs: a Report whose new pair would be the ninth under `N_reg = 8` withdraws at once with
/// `ForeignRegistrant` and the tenure's flip, inside every window, and each tick allocates nothing throughout.
#[test]
fn an_unrecorded_registrant_withdraws_after_one_window_or_without_the_own_holding() {
    use super::gate_fixture::{arena, attach_reserving, foreign, limits, own};
    use crate::failover::evidence::{NotSole, Pair, Registrant};
    use crate::failover::poll::Reads;
    use crate::failover::poll_tests::{owner, serving, volume};
    use crate::failover::records::{VolumeId, VolumeState};
    use crate::failover::retire::Target;
    use crate::failover::serving::{Machine, MetadataKind, ReportTrigger};
    const WINDOW: u64 = 10_000;
    let second = Pair {
        exhid: crate::failover::identity::Exhid::new([3; 16]).unwrap(),
        ..foreign()
    };
    let second = Pair {
        key: crate::failover::identity::Key::decode((2 << 32) | 9).unwrap(),
        ..second
    };
    // Nine distinct unrecorded pairs, one more than the fixture's `N_reg`.
    let crowd: Vec<Pair> = (0..9u8)
        .map(|at| Pair {
            exhid: crate::failover::identity::Exhid::new([10 + at; 16]).unwrap(),
            key: crate::failover::identity::Key::decode((2 << 32) | (10 + u64::from(at))).unwrap(),
        })
        .collect();
    assert_eq!(limits().registrants(), 8);
    // (time, listed pairs, poll without a record before the Report, the Report certifies)
    type Round<'r> = (u64, &'r [Pair], bool, bool);
    let holding: &[Round<'_>] = &[
        (1_000, &[foreign()], false, true),
        (5_000, &[], true, true),
        (9_000, &[foreign(), second], false, true),
        (10_900, &[second], true, true),
        (11_000, &[second], false, true),
        (11_100, &[foreign(), second], false, false),
    ];
    let unheld: &[Round<'_>] = &[(1_000, &[foreign()], false, false)];
    let capped: &[Round<'_>] = &[
        (1_000, &crowd[..7], false, true),
        (2_000, &crowd[7..8], false, true),
        (3_000, &crowd[8..9], false, false),
    ];
    // A Report at the first anchors' window end relists one of them beside a ninth pair: the list overflows and
    // keeps its trigger and flip, lapse or not.
    let relisted = [crowd[0], crowd[8]];
    let overflowing: &[Round<'_>] = &[
        (1_000, &crowd[..7], false, true),
        (2_000, &crowd[7..8], false, true),
        (1_000 + WINDOW, &relisted, false, false),
    ];
    // (the own pair holds, the withdrawing Report lapses a deferral rather than overflowing the list, rounds)
    for (own_holds, lapses, rounds) in [
        (true, true, holding),
        (false, false, unheld),
        (true, false, capped),
        (true, false, overflowing),
    ] {
        let fixture = super::ServingAuthority::fixture();
        let bounds = crate::failover::bounds::Bounds::new(
            limits().registrants(),
            1,
            WINDOW,
            limits().report_timeout(),
            100,
            0,
        )
        .unwrap();
        let session = fixture.session;
        let mut authority = super::ServingAuthority::new(
            bounds,
            Machine::issued(bounds, &session, own()),
            Box::new(super::gate_fixture::ZeroClock),
            session,
        );
        authority.recorded = Some(Box::new([own()]));
        let target = authority.session().target();
        let arena = arena();
        let storage = super::gate_fixture::storage();
        let (mut dev, control, registry) = attach_reserving(&storage, &arena, authority);
        let time = Rc::new(Cell::new(0));
        dev.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
        super::gate_fixture::ticks(&mut dev, &control, 64);
        assert!(matches!(
            dev.authority_state(),
            State::Recovering | State::Serving
        ));
        registry.borrow_mut().entries[0].holder = own_holds;
        let other = crate::failover::records::VolumeRecord {
            volume: VolumeId::new("vol-0b").unwrap(),
            ..volume(VolumeState::Active, owner().host)
        };
        for (round, &(now, listed, poll, certifies)) in rounds.iter().enumerate() {
            {
                let mut registry = registry.borrow_mut();
                registry.entries.truncate(1);
                for (at, pair) in listed.iter().enumerate() {
                    registry.entries.push(Registrant {
                        cntlid: 20 + at as u16,
                        holder: false,
                        pair: *pair,
                    });
                }
            }
            if poll {
                let shard = serving();
                for volume in [None, Some(&other)] {
                    let reads = Reads {
                        shard: Some(&shard),
                        volume,
                        listed: None,
                        peers: &[],
                    };
                    let verdict = dev.owner_poll(
                        &owner(),
                        Target::of(&shard),
                        own(),
                        Err(NotSole::Unreadable),
                        &reads,
                        dev.serving_sample(),
                    );
                    assert_eq!(
                        verdict,
                        crate::failover::poll::Verdict::Unobserved,
                        "round {round}"
                    );
                    assert!(
                        dev.authority_report().pending,
                        "round {round}: an unread poll keeps the deferral"
                    );
                }
            }
            time.set(now);
            let mut out = Vec::with_capacity(16);
            for _ in 0..8 {
                control.tick(64);
                let allocations = crate::instrument::allocations();
                let _ = dev.poll_storage(0, &mut out);
                assert_eq!(
                    crate::instrument::allocations(),
                    allocations,
                    "round {round}: the tick allocates nothing while a pair is deferred"
                );
                out.clear();
            }
            let report = dev.authority_report();
            if certifies {
                assert_eq!(
                    (report.withdrawal, report.flip, report.pending),
                    (None, None, true),
                    "round {round}"
                );
                assert!(dev.metadata_authorized(MetadataKind::CheckpointRoot));
                let machine = &dev.authority.machine;
                assert_eq!(
                    (machine.window_start(), machine.window_end()),
                    (Some(now), Some(now + WINDOW)),
                    "round {round}: the Report renews the window from its own submission"
                );
                continue;
            }
            assert_eq!(report.state, State::Withdrawn, "round {round}");
            let expected = match (own_holds, lapses) {
                (true, true) => (Some(Cause::Unverified), None),
                (true, false) => (
                    ReportTrigger::new(NotSole::ForeignRegistrant).map(Cause::Report),
                    Some(target),
                ),
                (false, _) => (Some(Cause::Unheld), None),
            };
            assert_eq!((report.withdrawal, report.flip), expected, "round {round}");
            assert!(report.pending, "round {round}");
        }
    }
}

/// SERVING-DEFERS-UNRECORDED bounds the deferral of an unrecorded pair first listed while the own pair held by one
/// serving window, beside the own holder and in both serving holds. Inside the window the own holder certifies, a
/// Report with nobody holding withdraws with `Cause::Unheld`, and one with the recorded foreign pair holding with
/// `Cause::RecordedHolder`. The same Reports at the window's end withdraw with `Cause::Unverified` and no flip request
/// (LAPSE-UNVERIFIED): no rtype 2 holder, rtype 0 and the recorded holder alike. The pair stays pending until an owner
/// poll enrolls it, and the withdrawn authority keeps its periodic Report, whose later Reports over the same lapsed
/// pair request nothing. A lapsed pair that then holds, an unrecorded holder, requests the flip naming the tenure's
/// own `(g, owner, E)` at once. Control: with `FLIP_AT_LAPSE` planted at the lapse's Report, each lapsed row
/// refuses with its Report trigger and requests the flip.
#[test]
fn a_lapsed_deferral_withdraws_each_serving_hold_unverified_with_no_flip() {
    use super::gate_fixture::{arena, attach_reserving, foreign, limits, own};
    use crate::failover::evidence::{NotSole, Pair, Registrant};
    use crate::failover::serving::{Machine, ReportTrigger};
    const WINDOW: u64 = 10_000;
    let second = Pair {
        exhid: crate::failover::identity::Exhid::new([3; 16]).unwrap(),
        key: crate::failover::identity::Key::decode((2 << 32) | 9).unwrap(),
    };
    // (rtype, the own pair holds, the recorded foreign pair holds, the withdrawal inside the window)
    let rows = [
        (2, true, false, None),
        (2, false, false, Some(Cause::Unheld)),
        (0, false, false, Some(Cause::Unheld)),
        (2, false, true, Some(Cause::RecordedHolder)),
    ];
    // The control plants `FLIP_AT_LAPSE` at the lapse's Report.
    let cases = [
        (5_000, true, false),
        (1_000 + WINDOW, false, false),
        (1_000 + WINDOW, false, true),
    ];
    for (rtype, own_holds, foreign_holds, hold) in rows {
        for (now, inside, control) in cases {
            let row = format!("{hold:?} rtype {rtype} own {own_holds} at {now} control {control}");
            let fixture = super::ServingAuthority::fixture();
            let bounds = crate::failover::bounds::Bounds::new(
                limits().registrants(),
                1,
                WINDOW,
                limits().report_timeout(),
                100,
                0,
            )
            .unwrap();
            let session = fixture.session;
            let mut authority = super::ServingAuthority::new(
                bounds,
                Machine::issued(bounds, &session, own()),
                Box::new(super::gate_fixture::ZeroClock),
                session,
            );
            authority.recorded = Some(Box::new([own(), foreign()]));
            let target = authority.session().target();
            let arena = arena();
            let storage = super::gate_fixture::storage();
            let (mut dev, device, registry) = attach_reserving(&storage, &arena, authority);
            let time = Rc::new(Cell::new(0));
            dev.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
            super::gate_fixture::ticks(&mut dev, &device, 64);
            registry.borrow_mut().entries.push(Registrant {
                cntlid: 20,
                holder: false,
                pair: second,
            });
            time.set(1_000);
            super::gate_fixture::ticks(&mut dev, &device, 8);
            let report = dev.authority_report();
            assert_eq!(
                (report.withdrawal, report.flip, report.pending),
                (None, None, true),
                "{row}: the own pair holds: the pair is deferred"
            );
            {
                let mut registry = registry.borrow_mut();
                registry.rtype = rtype;
                registry.entries[0].holder = own_holds;
                registry.entries.push(Registrant {
                    cntlid: 21,
                    holder: foreign_holds,
                    pair: foreign(),
                });
            }
            time.set(now);
            crate::storage::lapse_plant::FLIP_AT_LAPSE.set(control);
            super::gate_fixture::ticks(&mut dev, &device, 8);
            crate::storage::lapse_plant::FLIP_AT_LAPSE.set(false);
            let report = dev.authority_report();
            if control {
                assert_eq!(
                    report.flip,
                    Some(target),
                    "{row}: control: a flip requested at the lapse fails the no-flip check"
                );
                continue;
            }
            if inside && hold.is_none() {
                assert!(
                    matches!(report.state, State::Recovering | State::Serving),
                    "{row}"
                );
                assert_eq!((report.withdrawal, report.flip), (None, None), "{row}");
                continue;
            }
            let expected = if inside {
                hold
            } else {
                Some(Cause::Unverified)
            };
            assert_eq!(report.state, State::Withdrawn, "{row}");
            assert_eq!((report.withdrawal, report.flip), (expected, None), "{row}");
            let label = if inside {
                super::HoldState::Held
            } else {
                super::HoldState::Clear
            };
            assert_eq!(report.hold, label, "{row}: the hold label");
            assert!(
                report.pending,
                "{row}: the pair stays pending for the owner poll"
            );
            if inside {
                continue;
            }
            for later in [2 * WINDOW, 3 * WINDOW] {
                let reports = registry.borrow().log.len();
                time.set(later);
                super::gate_fixture::ticks(&mut dev, &device, 8);
                assert!(
                    registry.borrow().log.len() > reports,
                    "{row}: the unverified withdrawal keeps its periodic Report at {later}"
                );
                let report = dev.authority_report();
                assert_eq!(
                    (report.withdrawal, report.flip, report.hold),
                    (Some(Cause::Unverified), None, super::HoldState::Clear),
                    "{row}: a later Report over the same lapsed pair requests nothing at {later}"
                );
            }
            {
                let mut registry = registry.borrow_mut();
                registry.rtype = 2;
                for entry in &mut registry.entries {
                    entry.holder = entry.pair == second;
                }
            }
            time.set(4 * WINDOW);
            super::gate_fixture::ticks(&mut dev, &device, 8);
            let report = dev.authority_report();
            assert_eq!(
                (report.withdrawal, report.flip),
                (
                    ReportTrigger::new(NotSole::ForeignHolder).map(Cause::Report),
                    Some(target)
                ),
                "{row}: the lapsed pair preempted: an unrecorded holder flips at once"
            );
        }
    }
}

/// The rows that keep the immediate flip at a lapsed deferral: past the window of a non-holding unrecorded pair
/// first listed while the own pair held, a Report in which that pair holds (an unrecorded holder, `ForeignHolder`)
/// or in which a second record carries the own host ID (`DuplicateOwnRecord`) withdraws with the Report trigger and
/// the flip naming the tenure's own `(g, owner, E)`, as it does inside the window.
#[test]
fn a_lapsed_deferral_keeps_the_immediate_flip_of_a_foreign_holder_and_a_duplicate_own_record() {
    use super::gate_fixture::{arena, attach_reserving, limits, own};
    use crate::failover::evidence::{NotSole, Pair, Registrant};
    use crate::failover::serving::{Machine, ReportTrigger};
    const WINDOW: u64 = 10_000;
    let second = Pair {
        exhid: crate::failover::identity::Exhid::new([3; 16]).unwrap(),
        key: crate::failover::identity::Key::decode((2 << 32) | 9).unwrap(),
    };
    let alias = Pair {
        key: crate::failover::identity::Key::decode((2 << 32) | 11).unwrap(),
        ..own()
    };
    // (the deferred pair holds, an alias of the own host ID registers, the trigger)
    let rows = [
        (true, false, NotSole::ForeignHolder),
        (false, true, NotSole::DuplicateOwnRecord),
    ];
    for (preempts, aliased, trigger) in rows {
        for now in [5_000, 1_000 + WINDOW] {
            let row = format!("{trigger:?} at {now}");
            let fixture = super::ServingAuthority::fixture();
            let bounds = crate::failover::bounds::Bounds::new(
                limits().registrants(),
                1,
                WINDOW,
                limits().report_timeout(),
                100,
                0,
            )
            .unwrap();
            let session = fixture.session;
            let mut authority = super::ServingAuthority::new(
                bounds,
                Machine::issued(bounds, &session, own()),
                Box::new(super::gate_fixture::ZeroClock),
                session,
            );
            authority.recorded = Some(Box::new([own()]));
            let target = authority.session().target();
            let arena = arena();
            let storage = super::gate_fixture::storage();
            let (mut dev, control, registry) = attach_reserving(&storage, &arena, authority);
            let time = Rc::new(Cell::new(0));
            dev.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
            super::gate_fixture::ticks(&mut dev, &control, 64);
            registry.borrow_mut().entries.push(Registrant {
                cntlid: 20,
                holder: false,
                pair: second,
            });
            time.set(1_000);
            super::gate_fixture::ticks(&mut dev, &control, 8);
            assert_eq!(dev.authority_report().withdrawal, None, "{row}");
            {
                let mut registry = registry.borrow_mut();
                if preempts {
                    registry.entries[0].holder = false;
                    registry.entries[1].holder = true;
                }
                if aliased {
                    registry.entries.push(Registrant {
                        cntlid: 22,
                        holder: false,
                        pair: alias,
                    });
                }
            }
            time.set(now);
            super::gate_fixture::ticks(&mut dev, &control, 8);
            let report = dev.authority_report();
            assert_eq!(report.state, State::Withdrawn, "{row}");
            assert_eq!(
                (report.withdrawal, report.flip),
                (ReportTrigger::new(trigger).map(Cause::Report), Some(target)),
                "{row}"
            );
        }
    }
}

/// A Report with an unrecorded holder follows a deposition observation that requested no flip. After a store
/// regression, which shows no later tenure, the Report's retirement evidence requests the flip. An observation of a
/// later tenure sets the machine's `superseded` flag, so the withdrawal keeps its cause and the Report requests
/// nothing (SupersededRequestsNoFlip).
#[test]
fn a_retiring_report_after_a_deposition_observation_requests_the_flip_only_for_a_live_target() {
    use super::gate_fixture::{arena, attach_reserving, foreign};
    use crate::failover::evidence::{NotSole, Registrant};
    use crate::failover::serving::ReportTrigger;
    for observed in [
        Cause::Regression,
        Cause::Flipped,
        Cause::NewerFence { page: 0, fence: 9 },
        Cause::LaterTenure,
        Cause::Planned,
    ] {
        let arena = arena();
        let storage = super::gate_fixture::storage();
        let authority = super::ServingAuthority::fixture();
        let target = authority.session().target();
        let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
        let time = Rc::new(Cell::new(0));
        volume.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
        super::gate_fixture::ticks(&mut volume, &control, 64);
        assert!(matches!(
            volume.authority_state(),
            State::Recovering | State::Serving
        ));
        {
            let mut registry = registry.borrow_mut();
            registry.entries.push(Registrant {
                cntlid: 20,
                holder: true,
                pair: foreign(),
            });
            registry.budget = Some(0);
        }
        let reports = registry.borrow().log.len();
        time.set(1_000);
        super::gate_fixture::ticks(&mut volume, &control, 2);
        assert!(
            registry.borrow().log.len() > reports,
            "a Report is outstanding"
        );
        volume.authority_event(Event::Withdraw(observed));
        let report = volume.authority_report();
        assert_eq!(
            (report.state, report.withdrawal, report.flip),
            (State::Withdrawn, Some(observed), None)
        );
        let polled = volume.poll_report();
        let judged = (report.registrants, report.own_records);
        assert!(
            volume.authority.report.is_some(),
            "{observed:?}: the Report is outstanding across the withdrawal"
        );
        let delivered = registry.borrow().log.len();
        registry.borrow_mut().budget = None;
        super::gate_fixture::ticks(&mut volume, &control, 8);
        assert!(
            volume.authority.report.is_none() && volume.authority.expired.is_none(),
            "{observed:?}: the held terminal was delivered and consumed"
        );
        time.set(2_000);
        super::gate_fixture::ticks(&mut volume, &control, 8);
        let report = volume.authority_report();
        let expected = if !matches!(observed, Cause::Regression) {
            assert_eq!(
                (
                    volume.poll_report(),
                    (report.registrants, report.own_records)
                ),
                (polled.clone(), judged),
                "{observed:?}: the late Report leaves the polled Report and the judgment unchanged"
            );
            assert_eq!(
                registry.borrow().log.len(),
                delivered,
                "{observed:?}: no Report follows at the next period"
            );
            (Some(observed), None)
        } else {
            (
                ReportTrigger::new(NotSole::ForeignHolder).map(Cause::Report),
                Some(target),
            )
        };
        assert_eq!(
            (report.state, report.withdrawal, report.flip),
            (State::Withdrawn, expected.0, expected.1),
            "{observed:?}: the retirement evidence requests the flip only after the store regression; a later tenure \
             (SupersededRequestsNoFlip) and a planned exit (TransferRetainsVolume) keep it closed"
        );
    }
}

#[test]
fn a_report_refused_at_parse_after_the_boundary_withdraws_with_the_flip_request() {
    use super::gate_fixture::{arena, attach_reserving};
    use crate::failover::evidence::NotSole;
    use crate::failover::serving::ReportTrigger;
    use crate::storage::device::ReportError;
    assert_eq!(ReportTrigger::new(NotSole::Unreadable), None);
    for (rtype, check, refusal, own_records) in [
        (1, None, NotSole::ReservationType, None),
        (
            2,
            Some(ReportError::Inconclusive { regctl: 9 }),
            NotSole::Excess,
            None,
        ),
        (
            2,
            Some(ReportError::DuplicateKey),
            NotSole::ForeignRegistrant,
            None,
        ),
        (
            2,
            Some(ReportError::OwnHostIdKey),
            NotSole::DuplicateOwnRecord,
            Some(1),
        ),
        (2, Some(ReportError::Truncated), NotSole::Unreadable, None),
    ] {
        let arena = arena();
        let storage = super::gate_fixture::storage();
        let authority = super::ServingAuthority::fixture();
        let target = authority.session().target();
        let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
        let time = Rc::new(Cell::new(0));
        volume.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
        super::gate_fixture::ticks(&mut volume, &control, 64);
        assert!(matches!(
            volume.authority_state(),
            State::Recovering | State::Serving
        ));
        assert_eq!(volume.authority_report().own_records, Some(1));
        {
            let mut registry = registry.borrow_mut();
            registry.acquired_rtype = rtype;
            registry.rtype = rtype;
            registry.report_check = check;
        }
        assert!(volume.metadata_authorized(crate::failover::serving::MetadataKind::CheckpointRoot));
        time.set(1_000);
        super::gate_fixture::ticks(&mut volume, &control, 8);
        let report = volume.authority_report();
        assert_eq!(report.own_records, own_records, "{refusal:?}");
        if refusal == NotSole::Unreadable {
            assert!(
                matches!(report.state, State::Recovering | State::Serving),
                "an unreadable Report keeps the state: {:?}",
                report.state
            );
            assert_eq!(
                (report.withdrawal, report.flip, report.refusal),
                (None, None, Some(AuthorityRefusal::ReportMalformed))
            );
            assert!(
                !volume.metadata_authorized(crate::failover::serving::MetadataKind::CheckpointRoot),
                "an unreadable Report closes the window"
            );
            assert_eq!(
                (
                    volume.authority.machine.expired_at(),
                    volume.authority.machine.window_end()
                ),
                (Some(1_000), Some(1_000))
            );
            continue;
        }
        assert_eq!(
            (report.state, report.withdrawal, report.flip),
            (
                State::Withdrawn,
                ReportTrigger::new(refusal).map(Cause::Report),
                Some(target)
            ),
            "{refusal:?}"
        );
    }
}

/// `poll_report` copies the last Report the authority parsed: `Unreadable` before the first, the header and entries
/// of a parsed Report, the refusal of a Report refused at parse, and `Unreadable` once an uncollected Report passes
/// its deadline. A copy taken earlier keeps its contents.
#[test]
fn poll_report_copies_the_last_parsed_report_or_its_refusal() {
    use super::gate_fixture::{arena, attach_reserving};
    use crate::failover::evidence::{NotSole, ReservationType};
    use crate::storage::device::ReportError;
    for check in [
        None,
        Some(ReportError::DuplicateKey),
        Some(ReportError::Truncated),
    ] {
        let arena = arena();
        let storage = super::gate_fixture::storage();
        let authority = super::ServingAuthority::fixture();
        let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
        assert_eq!(volume.poll_report(), Err(NotSole::Unreadable));
        let time = Rc::new(Cell::new(0));
        volume.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
        super::gate_fixture::ticks(&mut volume, &control, 64);
        let gate = volume.poll_report().expect("the gate's Report parsed");
        let entries = registry.borrow().entries.clone();
        assert_eq!(gate.report().entries, &entries[..]);
        assert_eq!(gate.report().rtype, ReservationType::ExclusiveAccess);
        let changed = {
            let mut registry = registry.borrow_mut();
            registry.report_check = check;
            let last = registry.entries.len() - 1;
            registry.entries[last].cntlid += 10;
            registry.entries.clone()
        };
        assert_ne!(changed, entries);
        time.set(1_000);
        super::gate_fixture::ticks(&mut volume, &control, 8);
        let polled = volume.poll_report();
        match check {
            None => {
                let polled = polled.expect("the periodic Report parsed");
                assert_eq!(polled.report().submitted_at, 1_000);
                assert_eq!(polled.report().entries, &changed[..]);
            }
            Some(ReportError::DuplicateKey) => {
                assert_eq!(polled, Err(NotSole::ForeignRegistrant));
            }
            Some(_) => assert_eq!(polled, Err(NotSole::Unreadable)),
        }
        assert_eq!(gate.report().entries, &entries[..], "the copy is owned");
        assert_ne!(gate.report().submitted_at, 1_000);
        if check.is_some() {
            continue;
        }
        registry.borrow_mut().budget = Some(0);
        let due = 1_000 + volume.authority.bounds.report_period();
        time.set(due);
        super::gate_fixture::ticks(&mut volume, &control, 8);
        assert!(
            volume.poll_report().is_ok(),
            "the held Report is within its deadline"
        );
        time.set(due + volume.authority.bounds.report_deadline() + 1);
        super::gate_fixture::ticks(&mut volume, &control, 1);
        assert_eq!(
            volume.poll_report(),
            Err(NotSole::Unreadable),
            "an uncollected Report past its deadline leaves no Report to judge"
        );
    }
}

/// After `Cause::Unheld`, `poll_report` returns the last parsed Report while its age at the latest deadline sample
/// is less than one serving window. At one window, it returns `Err(NotSole::Unreadable)`.
#[test]
fn poll_report_returns_no_report_a_serving_window_old() {
    use super::gate_fixture::{arena, attach_reserving, bounds_with, foreign, limits, own};
    use crate::failover::evidence::NotSole;
    use crate::failover::serving::Machine;
    const WINDOW: u64 = 1_000;
    let bounds = bounds_with(limits(), WINDOW, 0);
    let session = crate::storage::next_session();
    let time = Rc::new(Cell::new(0));
    let mut authority = super::ServingAuthority::new(
        bounds,
        Machine::issued(bounds, &session, own()),
        Box::new(Clock(Rc::clone(&time))),
        session,
    );
    authority.recorded = Some(Box::new([foreign()]));
    let arena = arena();
    let storage = super::gate_fixture::storage();
    let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
    super::gate_fixture::ticks(&mut volume, &control, 64);
    assert!(
        matches!(volume.authority_state(), State::Recovering | State::Serving),
        "the gate passed"
    );
    for entry in &mut registry.borrow_mut().entries {
        entry.holder = false;
    }
    time.set(300);
    super::gate_fixture::ticks(&mut volume, &control, 8);
    assert_eq!(volume.authority_report().withdrawal, Some(Cause::Unheld));
    let submitted_at = volume
        .poll_report()
        .expect("the withdrawing Report")
        .report()
        .submitted_at;
    let reports = registry.borrow().log.len();
    time.set(submitted_at + WINDOW - 1);
    super::gate_fixture::ticks(&mut volume, &control, 8);
    assert!(
        volume.poll_report().is_ok(),
        "the Report is younger than one window"
    );
    time.set(submitted_at + WINDOW);
    super::gate_fixture::ticks(&mut volume, &control, 8);
    assert_eq!(
        registry.borrow().log.len(),
        reports,
        "the withdrawn tenure submitted no Report"
    );
    assert_eq!(volume.poll_report(), Err(NotSole::Unreadable));
}

/// STATUS-IS-DEPOSITION over the reused-key schedule: a recorded attachment's stale preempt aborts the owner's
/// in-flight read (`0x1B`) and its later write fails with `0x83`. Each status withdraws the owner with no flip
/// request, and the Report outstanding at the status then decides: a recorded holder beside recorded registrants
/// holds with no request (`Cause::RecordedHolder`), while an unrecorded holder retires through the Report trigger,
/// emitted once. A Report showing nobody holding beside the recorded pair holds the same way under NO-HOLDER-HOLD.
/// STATUS-REJUDGE: after a hold, one more Report, submitted after the status, judges the holder again and holds;
/// after the flip request no Report follows.
#[test]
fn a_deposing_status_withdraws_without_a_flip_and_the_report_decides_hold_or_retirement() {
    use super::bootstrap_tests::submitted;
    use super::gate_fixture::{arena, attach_reserving, foreign};
    use crate::failover::evidence::{NotSole, PREEMPT_ABORTED, RESERVATION_CONFLICT, Registrant};
    use crate::failover::serving::{Deposing, ReportTrigger};
    use crate::storage::device::sim::Fault;
    use crate::storage::device::{DeviceStatus, Operation};
    for (recorded, holds, status, deposing) in [
        (true, true, PREEMPT_ABORTED, Deposing::PreemptAborted),
        (true, true, RESERVATION_CONFLICT, Deposing::Conflict),
        (false, true, PREEMPT_ABORTED, Deposing::PreemptAborted),
        (false, true, RESERVATION_CONFLICT, Deposing::Conflict),
        (true, false, PREEMPT_ABORTED, Deposing::PreemptAborted),
        (true, false, RESERVATION_CONFLICT, Deposing::Conflict),
    ] {
        let arena = arena();
        let storage = super::gate_fixture::storage();
        let mut authority = super::ServingAuthority::fixture();
        authority.recorded = Some(if recorded {
            Box::new([foreign()]) as Box<[_]>
        } else {
            Box::new([])
        });
        let target = authority.session().target();
        let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
        let time = Rc::new(Cell::new(0));
        volume.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
        // A halted device executes nothing: the gate passes through the reservation double, and the bootstrap's
        // first read stays pending for the fault while the owner's periodic Report goes out and is held.
        control.set_halted(true);
        let mut out = Vec::with_capacity(16);
        let mut rounds = 0;
        while submitted(&control, Operation::Read).is_empty() {
            volume.poll_storage(0, &mut out);
            rounds += 1;
            assert!(
                rounds < 64,
                "the gate passes and the bootstrap submits a read"
            );
        }
        assert!(
            matches!(volume.authority_state(), State::Recovering | State::Serving),
            "{recorded} {holds} {status:#x}: the gate passed"
        );
        // The stale preempt took the reservation while a Report of the owner is outstanding.
        {
            let mut registry = registry.borrow_mut();
            for entry in &mut registry.entries {
                entry.holder = false;
            }
            registry.entries.push(Registrant {
                cntlid: 20,
                holder: holds,
                pair: foreign(),
            });
            registry.budget = Some(0);
        }
        time.set(1_000);
        super::gate_fixture::ticks(&mut volume, &control, 2);
        let reports = registry.borrow().log.len();
        assert!(reports > 0, "a Report is outstanding");
        let read = submitted(&control, Operation::Read)[0].0;
        control.fault(read, Fault::Status(DeviceStatus::Nvme(status << 1)));
        control.set_halted(false);
        super::gate_fixture::ticks(&mut volume, &control, 2);
        let report = volume.authority_report();
        assert_eq!(
            (report.state, report.withdrawal, report.flip),
            (State::Withdrawn, Some(Cause::Status(deposing)), None),
            "{recorded} {holds} {status:#x}: the status withdraws and requests nothing"
        );
        registry.borrow_mut().budget = None;
        super::gate_fixture::ticks(&mut volume, &control, 8);
        let report = volume.authority_report();
        // Withdrawn keeps the first cause unless a later cause requests the flip: a recorded holder's Report keeps
        // the status as the cause and requests nothing; an unrecorded holder's Report records its trigger and emits
        // the flip request once.
        let expected = if recorded {
            (Some(Cause::Status(deposing)), None)
        } else {
            (
                ReportTrigger::new(NotSole::ForeignHolder).map(Cause::Report),
                Some(target),
            )
        };
        assert_eq!(
            (report.state, report.withdrawal, report.flip),
            (State::Withdrawn, expected.0, expected.1),
            "{recorded} {holds} {status:#x}: the Report decides"
        );
        // A held tenure awaits the rejudge the status asks; the flip request ends the rejudge and the hold.
        assert_eq!(
            report.hold,
            if recorded {
                super::HoldState::Pending
            } else {
                super::HoldState::Clear
            },
            "{recorded} {holds} {status:#x}: the hold after the Report outstanding at the status"
        );
        assert_eq!(registry.borrow().log.len(), reports);
        if recorded && status == PREEMPT_ABORTED {
            assert_eq!(
                volume.authority_event(Event::Withdraw(Cause::Planned)),
                crate::failover::serving::Outcome::Stayed(
                    crate::failover::serving::Reason::Withdrawn
                )
            );
            let report = volume.authority_report();
            assert_eq!(
                (report.withdrawal, report.flip, report.hold),
                (
                    Some(Cause::Status(deposing)),
                    None,
                    super::HoldState::Pending
                ),
                "{holds} {status:#x}: the planned exit leaves the pending rejudge running"
            );
            assert_eq!(registry.borrow().log.len(), reports);
        }
        for now in [1_200, 1_400] {
            time.set(now);
            super::gate_fixture::ticks(&mut volume, &control, 4);
        }
        let report = volume.authority_report();
        assert_eq!(
            (report.withdrawal, report.flip),
            expected,
            "{recorded} {holds} {status:#x}: the Report after the status judges the holder alike"
        );
        assert_eq!(
            report.hold,
            if recorded {
                super::HoldState::Held
            } else {
                super::HoldState::Clear
            },
            "{recorded} {holds} {status:#x}: the rejudge holds the recorded holder"
        );
        if recorded {
            assert_eq!(
                volume.authority_event(Event::Withdraw(Cause::Planned)),
                crate::failover::serving::Outcome::Stayed(
                    crate::failover::serving::Reason::Withdrawn
                )
            );
            time.set(1_600);
            super::gate_fixture::ticks(&mut volume, &control, 4);
            let report = volume.authority_report();
            assert_eq!(
                (report.withdrawal, report.flip, report.hold),
                (Some(Cause::Status(deposing)), None, super::HoldState::Held),
                "{holds} {status:#x}: the planned exit leaves the held status withdrawal as it is"
            );
            assert_eq!(registry.borrow().log.len(), reports + 1);
        }
        if recorded && status == PREEMPT_ABORTED {
            // With the rejudge done, the status cause alone makes a successor observation supersede the hold.
            volume.authority_event(Event::Withdraw(Cause::Flipped));
            let report = volume.authority_report();
            assert_eq!(
                (report.withdrawal, report.hold),
                (Some(Cause::Status(deposing)), super::HoldState::Superseded),
                "{holds} {status:#x}: the successor observation supersedes the held status withdrawal"
            );
        } else {
            // A flip request ends the hold, and a successor observation after it supersedes nothing.
            if recorded {
                volume.authority_event(Event::Withdraw(Cause::Attachment));
                let report = volume.authority_report();
                assert_eq!(
                    (report.flip, report.hold),
                    (Some(target), super::HoldState::Clear),
                    "{holds} {status:#x}: a retirement trigger's flip ends the held judgment"
                );
            }
            volume.authority_event(Event::Withdraw(Cause::Flipped));
            let report = volume.authority_report();
            assert_eq!(
                (report.flip, report.hold),
                (Some(target), super::HoldState::Clear),
                "{recorded} {holds} {status:#x}: a successor after the flip request supersedes no hold"
            );
        }
        assert_eq!(
            registry.borrow().log.len(),
            reports + usize::from(recorded),
            "{recorded} {holds} {status:#x}: one Report after the status, and none after the flip request"
        );
    }
}

/// STATUS-REJUDGE keeps the periodic Report through a post-status Report that gives no observation: the first
/// Report after the status has its bytes withheld and decides nothing, and the next one judges the unrecorded holder
/// and requests the flip once, after which no Report follows.
#[test]
fn a_post_status_report_without_an_observation_keeps_the_rejudge() {
    use super::bootstrap_tests::submitted;
    use super::gate_fixture::{arena, attach_reserving, foreign};
    use crate::failover::evidence::{NotSole, PREEMPT_ABORTED, Registrant};
    use crate::failover::serving::{Deposing, ReportTrigger};
    use crate::storage::device::sim::Fault;
    use crate::storage::device::{DeviceStatus, Operation, ReportError};
    let arena = arena();
    let storage = super::gate_fixture::storage();
    let mut authority = super::ServingAuthority::fixture();
    authority.recorded = Some(Box::new([]));
    let target = authority.session().target();
    let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
    let time = Rc::new(Cell::new(0));
    volume.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
    control.set_halted(true);
    let mut out = Vec::with_capacity(16);
    while submitted(&control, Operation::Read).is_empty() {
        volume.poll_storage(0, &mut out);
    }
    let read = submitted(&control, Operation::Read)[0].0;
    control.fault(
        read,
        Fault::Status(DeviceStatus::Nvme(PREEMPT_ABORTED << 1)),
    );
    control.set_halted(false);
    super::gate_fixture::ticks(&mut volume, &control, 2);
    {
        let mut registry = registry.borrow_mut();
        for entry in &mut registry.entries {
            entry.holder = false;
        }
        registry.entries.push(Registrant {
            cntlid: 20,
            holder: true,
            pair: foreign(),
        });
        registry.report_check = Some(ReportError::Truncated);
    }
    let status = Some(Cause::Status(Deposing::PreemptAborted));
    let reports = registry.borrow().log.len();
    time.set(200);
    super::gate_fixture::ticks(&mut volume, &control, 4);
    let report = volume.authority_report();
    assert_eq!(
        (report.state, report.withdrawal, report.flip),
        (State::Withdrawn, status, None),
        "a Report with withheld bytes decides nothing"
    );
    assert_eq!(
        report.hold,
        super::HoldState::Pending,
        "the deposing status awaits its rejudge"
    );
    assert_eq!(
        report.registrants,
        Some(super::RegistrantJudgment::Refused(NotSole::Unreadable)),
        "the parser's refusal of the withheld bytes is the last judgment"
    );
    assert_eq!(registry.borrow().log.len(), reports + 1);
    registry.borrow_mut().report_check = None;
    time.set(400);
    super::gate_fixture::ticks(&mut volume, &control, 4);
    let report = volume.authority_report();
    assert_eq!(
        (report.withdrawal, report.flip),
        (
            ReportTrigger::new(NotSole::ForeignHolder).map(Cause::Report),
            Some(target)
        ),
        "the next Report judges the unrecorded holder"
    );
    assert_eq!(registry.borrow().log.len(), reports + 2);
    for now in [600, 800] {
        time.set(now);
        super::gate_fixture::ticks(&mut volume, &control, 4);
    }
    assert_eq!(
        registry.borrow().log.len(),
        reports + 2,
        "no Report follows the judgment"
    );
}

/// STATUS-REJUDGE: a preempt deposes the serving owner while no Report is outstanding, or while the outstanding
/// Report shows the own pair holding, as it does when that Report ran before the preempt. The deposing status
/// withdraws the owner with no flip request, and Withdrawn keeps the periodic Report until one submitted after the
/// status is judged: an unrecorded holder requests the flip once within the next period, a recorded holder
/// holds with no request, and no Report follows that judgment.
#[test]
fn a_deposing_status_with_no_judging_report_outstanding_takes_one_more_report() {
    use super::bootstrap_tests::submitted;
    use super::gate_fixture::{arena, attach_reserving, foreign};
    use crate::failover::evidence::{NotSole, PREEMPT_ABORTED, Registrant};
    use crate::failover::serving::{Deposing, ReportTrigger};
    use crate::storage::device::sim::Fault;
    use crate::storage::device::{DeviceStatus, Operation};
    for (recorded, outstanding) in [(true, false), (false, false), (true, true), (false, true)] {
        let arena = arena();
        let storage = super::gate_fixture::storage();
        let mut authority = super::ServingAuthority::fixture();
        authority.recorded = Some(if recorded {
            Box::new([foreign()]) as Box<[_]>
        } else {
            Box::new([])
        });
        let target = authority.session().target();
        let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
        let time = Rc::new(Cell::new(0));
        volume.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
        control.set_halted(true);
        let mut out = Vec::with_capacity(16);
        let mut rounds = 0;
        while submitted(&control, Operation::Read).is_empty() {
            volume.poll_storage(0, &mut out);
            rounds += 1;
            assert!(
                rounds < 64,
                "the gate passes and the bootstrap submits a read"
            );
        }
        assert!(
            volume.authority.report.is_none(),
            "no Report is outstanding"
        );
        if outstanding {
            registry.borrow_mut().budget = Some(0);
            time.set(200);
            super::gate_fixture::ticks(&mut volume, &control, 2);
            assert!(volume.authority.report.is_some(), "a Report is outstanding");
        }
        let read = submitted(&control, Operation::Read)[0].0;
        control.fault(
            read,
            Fault::Status(DeviceStatus::Nvme(PREEMPT_ABORTED << 1)),
        );
        control.set_halted(false);
        super::gate_fixture::ticks(&mut volume, &control, 2);
        if outstanding {
            assert!(
                volume.authority.report.is_some(),
                "the status precedes the Report's terminal"
            );
            registry.borrow_mut().budget = None;
            super::gate_fixture::ticks(&mut volume, &control, 2);
        }
        // The preempt's effect on the reservation, after the outstanding Report showed the own pair holding.
        {
            let mut registry = registry.borrow_mut();
            for entry in &mut registry.entries {
                entry.holder = false;
            }
            registry.entries.push(Registrant {
                cntlid: 20,
                holder: true,
                pair: foreign(),
            });
        }
        let report = volume.authority_report();
        let status = Some(Cause::Status(Deposing::PreemptAborted));
        assert_eq!(
            (report.state, report.withdrawal, report.flip),
            (State::Withdrawn, status, None),
            "{recorded} {outstanding}: the status withdraws and requests nothing"
        );
        assert!(volume.authority.report.is_none());
        let reports = registry.borrow().log.len();
        time.set(time.get() + 200);
        super::gate_fixture::ticks(&mut volume, &control, 4);
        let expected = if recorded {
            (status, None)
        } else {
            (
                ReportTrigger::new(NotSole::ForeignHolder).map(Cause::Report),
                Some(target),
            )
        };
        let report = volume.authority_report();
        assert_eq!(
            (report.state, report.withdrawal, report.flip),
            (State::Withdrawn, expected.0, expected.1),
            "{recorded} {outstanding}: a recorded holder holds, and an unrecorded holder requests the flip once"
        );
        assert_eq!(registry.borrow().log.len(), reports + 1);
        for _ in 0..2 {
            time.set(time.get() + 200);
            super::gate_fixture::ticks(&mut volume, &control, 4);
        }
        assert_eq!(
            registry.borrow().log.len(),
            reports + 1,
            "{recorded} {outstanding}: no Report follows the judgment"
        );
    }
}

/// SupersededRequestsNoFlip at the driver: a command of the tenure completes with a deposing status, and the
/// reservation then shows a holder outside the recorded pairs. The owner observes a shard record naming a successor
/// before that terminal or after it. Either way the tenure's `(g, owner, E)` is stale, so the withdrawal keeps its
/// first cause, requests no flip, and submits no Report to judge the holder. Without the observation the same
/// terminal is followed by one Report, which requests the flip: the request this rule withholds.
#[test]
fn a_late_driver_terminal_after_a_successor_observation_requests_no_flip() {
    use super::bootstrap_tests::submitted;
    use super::gate_fixture::{arena, attach_reserving, foreign};
    use crate::failover::evidence::{NotSole, PREEMPT_ABORTED, Registrant};
    use crate::failover::serving::{Deposing, ReportTrigger};
    use crate::storage::device::sim::Fault;
    use crate::storage::device::{DeviceStatus, Operation};
    for (observed, planned) in [
        (Some(true), false),
        (Some(false), false),
        (None, false),
        (None, true),
    ] {
        let flip_closed = observed.is_some() || planned;
        let arena = arena();
        let storage = super::gate_fixture::storage();
        let mut authority = super::ServingAuthority::fixture();
        authority.recorded = Some(Box::new([]));
        let target = authority.session().target();
        let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
        let time = Rc::new(Cell::new(0));
        volume.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
        control.set_halted(true);
        let mut out = Vec::with_capacity(16);
        let mut rounds = 0;
        while submitted(&control, Operation::Read).is_empty() {
            volume.poll_storage(0, &mut out);
            rounds += 1;
            assert!(rounds < 64, "the bootstrap submits a read");
        }
        if observed == Some(true) {
            volume.authority_event(Event::Withdraw(Cause::Flipped));
        }
        if planned {
            volume.authority_event(Event::Withdraw(Cause::Planned));
        }
        let before = registry.borrow().log.len();
        let read = submitted(&control, Operation::Read)[0].0;
        control.fault(
            read,
            Fault::Status(DeviceStatus::Nvme(PREEMPT_ABORTED << 1)),
        );
        control.set_halted(false);
        super::gate_fixture::ticks(&mut volume, &control, 2);
        {
            let mut registry = registry.borrow_mut();
            for entry in &mut registry.entries {
                entry.holder = false;
            }
            registry.entries.push(Registrant {
                cntlid: 20,
                holder: true,
                pair: foreign(),
            });
        }
        let first = if observed == Some(true) {
            Cause::Flipped
        } else if planned {
            Cause::Planned
        } else {
            Cause::Status(Deposing::PreemptAborted)
        };
        assert_eq!(
            volume.authority.refusal,
            Some(super::AuthorityRefusal::PreemptAborted),
            "{observed:?} {planned}: the late terminal reached the authority"
        );
        let report = volume.authority_report();
        assert_eq!(
            (report.state, report.withdrawal, report.flip),
            (State::Withdrawn, Some(first), None),
            "{observed:?} {planned}: the late terminal requests nothing"
        );
        let status_first = observed != Some(true) && !planned;
        assert_eq!(
            report.hold,
            if status_first {
                super::HoldState::Pending
            } else {
                super::HoldState::Clear
            },
            "{observed:?} {planned}: a deposing status that withdrew the tenure awaits its rejudge"
        );
        if observed == Some(false) {
            volume.authority_event(Event::Withdraw(Cause::Flipped));
            assert_eq!(
                volume.authority_report().withdrawal,
                Some(first),
                "the withdrawal keeps the status as its cause"
            );
            assert_eq!(
                volume.authority_report().hold,
                super::HoldState::Superseded,
                "the successor observation superseded the status withdrawal"
            );
        }
        let reports = registry.borrow().log.len();
        time.set(time.get() + 200);
        super::gate_fixture::ticks(&mut volume, &control, 4);
        let judged = usize::from(!flip_closed);
        assert_eq!(
            registry.borrow().log.len(),
            reports + judged,
            "{observed:?} {planned}: a Report judges the holder only while the flip is open, which a successor \
             observation (SupersededRequestsNoFlip) and a planned withdrawal (TransferRetainsVolume) end"
        );
        let expected = if flip_closed {
            (Some(first), None)
        } else {
            (
                ReportTrigger::new(NotSole::ForeignHolder).map(Cause::Report),
                Some(target),
            )
        };
        let report = volume.authority_report();
        assert_eq!(
            (report.withdrawal, report.flip),
            expected,
            "{observed:?} {planned}: the Report requests the flip only with no successor observation and no planned \
             withdrawal before it"
        );
        for _ in 0..2 {
            time.set(time.get() + 200);
            super::gate_fixture::ticks(&mut volume, &control, 4);
        }
        assert_eq!(
            registry.borrow().log.len(),
            reports + judged,
            "{observed:?} {planned}: no Report follows the judgment"
        );
        if planned {
            assert_eq!(
                registry.borrow().log.len(),
                before,
                "a deposing status after a planned withdrawal submits no Report"
            );
        }
    }
}

/// WINDOW-IS-AVAILABILITY (`failover/serving.rs` module doc): "a clock fault closes the window without moving the state".
/// The serving clock is the caller's callback, so its second reading inside a deadline sample, the one that follows `clear_suspend`, can unwind. The window closes before the fault is acknowledged, so a caller that survives the unwind is refused `WindowExpired` on its next healthy reading and after its next poll, unless the tick that unwound left the volume lost.
/// `authority_event` runs the sample outside every tick, so there the closed window is the only fence.
#[test]
fn a_clock_fault_whose_second_reading_unwinds_does_not_leave_the_window_open() {
    use crate::failover::serving::{Denial, Operation};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    /// The first reading is a fault, the second unwinds, and every later one reads 10.
    struct Script(Cell<usize>);
    impl ServingClock for Script {
        fn now_us(&self) -> Option<u64> {
            let at = self.0.get();
            self.0.set(at + 1);
            assert_ne!(at, 1, "clock callback");
            (at != 0).then_some(10)
        }
    }
    #[derive(Debug, Clone, Copy)]
    enum Entry {
        Terminals,
        Storage,
        Event,
    }
    let mut open = Vec::new();
    for entry in [Entry::Terminals, Entry::Storage, Entry::Event] {
        let storage = storage_with(|_| {});
        let arena = arena_with(4, 5);
        let mut dev = Device::new(&storage, &arena);
        let mut out = Vec::with_capacity(8);
        let time = clock(&mut dev);
        time.set(10);
        dev.volume.poll_storage(0, &mut out);
        assert_eq!(
            dev.volume
                .admit_authority(Operation::Fill, dev.volume.serving_token())
                .err(),
            None,
            "premise: the window is open before the fault"
        );
        dev.volume.authority.clock = Box::new(Script(Cell::new(0)));
        let unwound = catch_unwind(AssertUnwindSafe(|| match entry {
            Entry::Terminals => dev.volume.poll_terminals(0, &out),
            Entry::Storage => {
                dev.volume.poll_storage(0, &mut out);
            }
            Entry::Event => {
                dev.volume.authority_event(Event::Readiness(
                    crate::failover::serving::Readiness::ReadReady {
                        token: dev.volume.serving_token().unwrap(),
                    },
                ));
            }
        }));
        assert!(
            unwound.is_err(),
            "premise: the second reading unwound {entry:?}"
        );
        let lost = dev.volume.is_lost();
        let admitted = dev
            .volume
            .admit_authority(Operation::Fill, dev.volume.serving_token());
        dev.volume.poll_storage(0, &mut out);
        let after = dev
            .volume
            .admit_authority(Operation::Fill, dev.volume.serving_token());
        assert_eq!(
            dev.volume.authority_report().refusal,
            Some(AuthorityRefusal::Clock),
            "{entry:?}"
        );
        if !lost && (admitted, after) != (Err(Denial::WindowExpired), Err(Denial::WindowExpired)) {
            open.push((entry, admitted.is_ok(), after.is_ok()));
        }
    }
    assert!(
        open.is_empty(),
        "a clock fault leaves the volume lost or its window closed; live and admitted as (entry, at once, after the next poll): {open:?}"
    );
}

/// The read side of the same fault, against the fence [`an_expired_window_fences_read_submission_and_arrived_bytes`] asserts for a window closed without an unwind: after a clock fault whose second reading unwound `poll_storage`, a new read is refused or the volume is lost, and no `Chunk` is handed off.
#[test]
fn a_clock_fault_whose_second_reading_unwinds_hands_off_no_chunk() {
    use super::volume_tests::{CHUNK, SESSION, TICK, arena, attach, place, record, storage};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    /// The first reading is a fault, the second unwinds, and every later one reads 10.
    struct Script(Cell<usize>);
    impl ServingClock for Script {
        fn now_us(&self) -> Option<u64> {
            let at = self.0.get();
            self.0.set(at + 1);
            assert_ne!(at, 1, "clock callback");
            (at != 0).then_some(10)
        }
    }
    let storage = storage(1);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let time = Rc::new(Cell::new(10));
    volume.authority.clock = Box::new(Clock(Rc::clone(&time)));
    let record = record(0, 0, CHUNK, SESSION, 35);
    place(&storage, &control, &record);
    let mut out = Vec::with_capacity(8);
    volume.poll_storage(0, &mut out);
    volume.authority.clock = Box::new(Script(Cell::new(0)));
    let unwound = catch_unwind(AssertUnwindSafe(|| volume.poll_storage(0, &mut out)));
    assert!(
        unwound.is_err(),
        "premise: the second reading unwound the poll"
    );
    let lost = volume.is_lost();
    let read = volume.read_raw(&record.read, u64::MAX);
    if let Ok(op) = read {
        let _ = volume.grant_read(op);
        for _ in 0..4 {
            control.tick(64);
            volume.poll_storage(0, &mut out);
        }
    }
    let chunks = out
        .iter()
        .filter(|event| matches!(event, super::ReadEvent::Chunk { .. }))
        .count();
    assert!(
        lost || (read.is_err() && chunks == 0),
        "after the fault the volume is lost or reads stay fenced: lost {lost}, read admitted {}, chunks handed off {chunks}",
        read.is_ok()
    );
}

/// The count of Reports in the driver's log of reservation commands.
fn reports(log: &[super::super::device::ReservationCommand]) -> usize {
    use super::super::device::ReservationCommand;
    log.iter()
        .filter(|command| matches!(command, ReservationCommand::Report { .. }))
        .count()
}

/// Passes the attach gate on the reserving fixture, moves the machine to `state`, lets one periodic Report out with
/// its terminal withheld and sets the serving clock exactly to `next_report`, where the Report's age equals its
/// deadline and so has not expired. Two polls there leave the pending Report as it was and submit nothing; the
/// released terminal then clears it, and the next Report is out within two more polls.
fn one_report_at_a_time(state: State) {
    use super::gate_fixture::{arena, attach_reserving, storage, ticks};
    use crate::failover::serving::Readiness;
    let arena = arena();
    let storage = storage();
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture(),
    );
    let time = Rc::new(Cell::new(10));
    volume.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
    ticks(&mut volume, &control, 8);
    assert_eq!(registry.borrow().log.len(), 3, "Register, Acquire, Report");
    assert_eq!(reports(&registry.borrow().log), 1, "the gate's Report");
    assert!(
        volume.authority.report.is_none(),
        "the gate's Report applied"
    );
    if state == State::Serving {
        let token = volume.serving_token().expect("the fixture holds a token");
        volume
            .authority
            .machine
            .step(Event::Readiness(Readiness::ReadReady { token }));
        volume.authority_effects();
    }
    assert_eq!(volume.authority_state(), state);

    let period = volume.authority.bounds.report_period();
    let deadline = volume.authority.bounds.report_deadline();
    assert_eq!((period, deadline), (100, 100), "the fixture's bounds");
    registry.borrow_mut().budget = Some(0);
    let submitted = 10 + period;
    time.set(submitted);
    ticks(&mut volume, &control, 1);
    assert_eq!(
        reports(&registry.borrow().log),
        2,
        "{state:?}: the periodic Report"
    );
    let pending = volume.authority.report;
    let (_, triple, at) = pending.expect("the periodic Report is pending");
    assert_eq!((triple, at), (volume.serving_token(), submitted));
    assert_eq!(volume.authority.next_report, submitted + period);

    time.set(volume.authority.next_report);
    assert_eq!(
        time.get() - at,
        deadline,
        "{state:?}: at its deadline, not past it"
    );
    for poll in 0..2 {
        ticks(&mut volume, &control, 1);
        assert_eq!(
            volume.authority.now,
            submitted + period,
            "{state:?}: the clock was read"
        );
        assert!(
            !volume.authority_report_due(),
            "{state:?} poll {poll}: no Report is due while one is pending"
        );
        assert_eq!(
            volume.authority.report, pending,
            "{state:?} poll {poll}: the pending Report keeps its token, triple and time"
        );
        assert_eq!(
            (reports(&registry.borrow().log), registry.borrow().log.len()),
            (2, 4),
            "{state:?} poll {poll}: the driver took one periodic Report"
        );
        assert_eq!(volume.authority_state(), state, "{state:?} poll {poll}");
        assert!(volume.authority.expired.is_none(), "{state:?} poll {poll}");
    }

    registry.borrow_mut().budget = None;
    ticks(&mut volume, &control, 2);
    assert_eq!(volume.authority_state(), state);
    assert_eq!(
        (reports(&registry.borrow().log), registry.borrow().log.len()),
        (3, 5),
        "{state:?}: once the terminal applied, the Report due since `next_report` went out"
    );
    assert_ne!(
        volume.authority.report, pending,
        "{state:?}: the withheld Report is no longer the pending one"
    );
}

/// While a recovering volume's periodic Report is pending, a tick at the next Report's time submits none: `authority_report_due` is false, the pending Report keeps its command token, serving token and submit time, and the driver has taken one periodic Report. Once the terminal applies, the next Report goes out.
#[test]
fn a_recovering_volume_submits_no_report_while_one_is_pending() {
    one_report_at_a_time(State::Recovering);
}

/// A serving volume likewise submits no Report while its periodic Report is pending, and submits the next one once the terminal applies.
#[test]
fn a_serving_volume_submits_no_report_while_one_is_pending() {
    one_report_at_a_time(State::Serving);
}

/// A Report of the own pair that completes with no bytes to judge is the last evaluated Report: after a sole own
/// Report, a failed Report reads `Unreadable` with no own-record count, so the judgment, the hold and the count
/// describe the same Report.
#[test]
fn a_failed_report_after_a_sole_one_reads_unreadable() {
    use super::gate_fixture::{arena, attach_reserving};
    use super::{HoldState, RegistrantJudgment};
    use crate::failover::evidence::NotSole;
    use crate::storage::device::DeviceStatus;
    let arena = arena();
    let storage = super::gate_fixture::storage();
    let (mut volume, control, registry) =
        attach_reserving(&storage, &arena, super::ServingAuthority::fixture());
    let time = Rc::new(Cell::new(0));
    volume.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
    super::gate_fixture::ticks(&mut volume, &control, 64);
    let report = volume.authority_report();
    assert_eq!(
        (report.registrants, report.hold, report.own_records),
        (Some(RegistrantJudgment::Sole), HoldState::Clear, Some(1)),
        "the gate's Report shows the own pair alone"
    );
    registry.borrow_mut().report_status = Some(DeviceStatus::Nvme(0x6 << 1));
    let reports = registry.borrow().log.len();
    time.set(1_000);
    super::gate_fixture::ticks(&mut volume, &control, 8);
    assert!(
        registry.borrow().log.len() > reports,
        "a periodic Report went out"
    );
    let report = volume.authority_report();
    assert_eq!(
        (report.registrants, report.hold, report.own_records),
        (
            Some(RegistrantJudgment::Refused(NotSole::Unreadable)),
            HoldState::Clear,
            None
        ),
        "the failed Report replaces the sole judgment"
    );
}

/// A closed machine keeps the snapshot it closed with: a periodic Report outstanding when the volume closes reaches
/// its terminal afterwards, and that Report, here a failed one that an open machine reads `Unreadable` with no
/// own-record count, leaves the judgment, the hold and the count as the last Report before the close set them.
#[test]
fn a_report_that_ends_after_the_close_leaves_the_closed_snapshot() {
    use super::gate_fixture::{arena, attach_reserving, ticks};
    use super::{HoldState, RegistrantJudgment};
    use crate::storage::device::DeviceStatus;
    let arena = arena();
    let storage = super::gate_fixture::storage();
    let (mut volume, control, registry) =
        attach_reserving(&storage, &arena, super::ServingAuthority::fixture());
    let time = Rc::new(Cell::new(0));
    volume.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
    ticks(&mut volume, &control, 64);
    let sole = (Some(RegistrantJudgment::Sole), HoldState::Clear, Some(1));
    let report = volume.authority_report();
    assert_eq!(
        (report.registrants, report.hold, report.own_records),
        sole,
        "the gate's Report"
    );
    registry.borrow_mut().budget = Some(0);
    registry.borrow_mut().report_status = Some(DeviceStatus::Nvme(0x6 << 1));
    time.set(1_000);
    let mut rounds = 0;
    while volume.authority.report.is_none() {
        ticks(&mut volume, &control, 1);
        rounds += 1;
        assert!(rounds < 8, "a periodic Report is submitted");
    }
    volume.authority_event(Event::Close);
    assert_eq!(volume.authority_state(), State::Closed);
    registry.borrow_mut().budget = None;
    let mut rounds = 0;
    while volume.authority.report.is_some() {
        ticks(&mut volume, &control, 1);
        rounds += 1;
        assert!(rounds < 8, "the Report reaches its terminal");
    }
    assert_eq!(volume.authority_state(), State::Closed);
    let report = volume.authority_report();
    assert_eq!(
        (report.registrants, report.hold, report.own_records),
        sole,
        "the failed Report changes nothing"
    );
}

/// ENDED-NEVER-RETIRES between owner polls: a serving Report that lists a registrant under an ended attach's key
/// defers it, and the next `owner_poll`, whose volume record ends that attach, admits it among the authority's
/// recorded pairs, so no Report past the deferral window withdraws. An unreadable Report carries the admitted pair
/// only while the poll's volume record still classes it ended. Control: with no such poll, the first Report past
/// the window withdraws with `Cause::Unverified` and no flip request.
#[test]
fn a_registrant_under_an_ended_key_is_deferred_then_admitted_by_the_owner_poll() {
    use super::gate_fixture::{arena, attach_reserving, limits, own};
    use crate::failover::attachments::InstanceId;
    use crate::failover::evidence::{Pair, Registrant};
    use crate::failover::poll::{Reads, Verdict};
    use crate::failover::poll_tests::{listed, owner, report_of, serving, volume};
    use crate::failover::records::{
        AttachmentEvent, ERA, EventKind, Host, RecordedPair, VolumeState,
    };
    use crate::failover::retire::Target;
    use crate::failover::serving::Machine;
    const WINDOW: u64 = 10_000;
    let holder = owner();
    let mut record = volume(VolumeState::Active, holder.host);
    record.pairs = vec![RecordedPair {
        host: holder.host,
        pair: own(),
        attach: 0,
    }];
    record.next = 3;
    record.events.push(AttachmentEvent {
        seq: 2,
        kind: EventKind::Ended,
        host: Host::new(holder.host.get() + 100).unwrap(),
        era: ERA,
        instance: Some(InstanceId::new("i-0eeeeeeeeeeeeeee0").unwrap()),
    });
    let late = Pair {
        exhid: crate::failover::identity::Exhid::new([0x77; 16]).unwrap(),
        key: crate::failover::records::attachment_key(2).unwrap(),
    };
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Arm {
        /// The owner poll's Report lists the late pair.
        Polled,
        /// The owner poll's Report lists the own pair alone.
        Unlisted,
        /// The owner poll lists the late pair, which then holds alone.
        Holds,
        /// No owner poll.
        Unpolled,
    }
    for arm in [Arm::Polled, Arm::Unlisted, Arm::Holds, Arm::Unpolled] {
        let fixture = super::ServingAuthority::fixture();
        let bounds = crate::failover::bounds::Bounds::new(
            limits().registrants(),
            1,
            WINDOW,
            limits().report_timeout(),
            100,
            0,
        )
        .unwrap();
        let session = fixture.session;
        let mut authority = super::ServingAuthority::new(
            bounds,
            Machine::issued(bounds, &session, own()),
            Box::new(super::gate_fixture::ZeroClock),
            session,
        );
        authority.recorded = Some(Box::new([own()]));
        let arena = arena();
        let storage = super::gate_fixture::storage();
        let (mut dev, control, registry) = attach_reserving(&storage, &arena, authority);
        let time = Rc::new(Cell::new(0));
        dev.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
        super::gate_fixture::ticks(&mut dev, &control, 64);
        let own_entry = registry.borrow().entries[0];
        let late_entry = Registrant {
            cntlid: 20,
            holder: false,
            pair: late,
        };
        registry.borrow_mut().entries.push(late_entry);
        time.set(1_000);
        super::gate_fixture::ticks(&mut dev, &control, 8);
        let report = dev.authority_report();
        assert_eq!(
            (report.withdrawal, report.flip, report.pending),
            (None, None, true),
            "{arm:?}: the late registrant is deferred inside its window"
        );
        let shard = serving();
        let target = Target::of(&shard);
        let alone = listed(&[holder.instance.as_str()]);
        let reads = Reads {
            shard: Some(&shard),
            volume: Some(&record),
            listed: Some(&alone),
            peers: &[],
        };
        let entries = [own_entry, late_entry];
        let sole = [own_entry];
        let polled = report_of(&entries);
        let unlisted = report_of(&sole);
        match arm {
            Arm::Polled | Arm::Holds => {
                assert_eq!(
                    dev.owner_poll(
                        &holder,
                        target,
                        own(),
                        Ok(&polled),
                        &reads,
                        dev.serving_sample()
                    ),
                    Verdict::Continue
                );
                assert_eq!(
                    dev.authority.recorded.as_deref(),
                    Some(&[own(), late][..]),
                    "the poll admits the ended attach's registrant"
                );
                assert!(!dev.authority_report().pending);
            }
            Arm::Unlisted => {
                assert_eq!(
                    dev.owner_poll(
                        &holder,
                        target,
                        own(),
                        Ok(&unlisted),
                        &reads,
                        dev.serving_sample()
                    ),
                    Verdict::Continue
                );
                assert_eq!(
                    dev.authority.recorded.as_deref(),
                    Some(&[own()][..]),
                    "a Report that omits the late pair admits only the recorded pairs"
                );
                assert!(
                    !dev.authority_report().pending,
                    "the record classes the deferred pair ended, so its deferral drops"
                );
            }
            Arm::Unpolled => {}
        }
        if arm == Arm::Polled {
            let allocations = crate::instrument::allocations();
            assert_eq!(
                dev.owner_poll(
                    &holder,
                    target,
                    own(),
                    Ok(&polled),
                    &reads,
                    dev.serving_sample()
                ),
                Verdict::Continue
            );
            assert_eq!(
                dev.owner_poll(
                    &holder,
                    target,
                    own(),
                    Err(crate::failover::evidence::NotSole::Unreadable),
                    &reads,
                    dev.serving_sample()
                ),
                Verdict::Unobserved
            );
            assert_eq!(
                crate::instrument::allocations(),
                allocations,
                "an unchanged admitted sequence allocates nothing, an unreadable Report included"
            );
            assert_eq!(
                dev.authority.recorded.as_deref(),
                Some(&[own(), late][..]),
                "an unreadable Report keeps the ended attach's registrant the record still classes ended"
            );
            let inconclusive = crate::failover::evidence::Report {
                regctl: 2,
                ..report_of(&sole)
            };
            let _ = dev.owner_poll(
                &holder,
                target,
                own(),
                Ok(&inconclusive),
                &reads,
                dev.serving_sample(),
            );
            assert_eq!(
                dev.authority.recorded.as_deref(),
                Some(&[own(), late][..]),
                "a Report whose count differs from its entries lends no rows, so the cached pair stays"
            );
        }
        if arm == Arm::Holds {
            {
                let mut registry = registry.borrow_mut();
                registry.entries[0].holder = false;
                registry.entries[1].holder = true;
            }
            time.set(2_000);
            super::gate_fixture::ticks(&mut dev, &control, 8);
            let report = dev.authority_report();
            assert_eq!(
                (report.withdrawal, report.flip.is_some()),
                (
                    Some(Cause::Report(
                        crate::failover::serving::ReportTrigger::new(
                            crate::failover::evidence::NotSole::ForeignHolder
                        )
                        .unwrap()
                    )),
                    true
                ),
                "an admitted ended-key pair that holds retires with the flip, as an unrecorded holder does"
            );
            continue;
        }
        time.set(3 * WINDOW);
        super::gate_fixture::ticks(&mut dev, &control, 8);
        let report = dev.authority_report();
        match arm {
            Arm::Polled | Arm::Unlisted => {
                assert!(
                    matches!(report.state, State::Recovering | State::Serving),
                    "{arm:?}"
                );
                assert_eq!(
                    (report.withdrawal, report.flip),
                    (None, None),
                    "{arm:?}: no withdrawal past the window"
                );
                if arm == Arm::Polled {
                    assert_eq!(
                        report.registrants,
                        Some(super::RegistrantJudgment::Ended),
                        "the admitted late pair reads as an ended registrant"
                    );
                }
                assert_eq!(
                    report.pending,
                    arm == Arm::Unlisted,
                    "{arm:?}: an unadmitted late pair takes a fresh deferral"
                );
                assert!(
                    dev.metadata_authorized(crate::failover::serving::MetadataKind::CheckpointRoot),
                    "{arm:?}: the Report renews the window"
                );
                assert_eq!(dev.authority.machine.window_start(), Some(3 * WINDOW));
            }
            Arm::Unpolled => assert_eq!(
                (report.withdrawal, report.flip),
                (Some(Cause::Unverified), None),
                "control: without the poll the deferral lapses"
            ),
            Arm::Holds => unreachable!(),
        }
        if arm == Arm::Polled {
            let rekeyed = Pair {
                exhid: crate::failover::identity::Exhid::new([0x78; 16]).unwrap(),
                key: late.key,
            };
            // Entry 2 live again with a recorded pair of its own under the late key: another host ID under a key a
            // live recorded pair carries is unknown, while under an ended entry's recorded key it would stay ended.
            let mut held = record.clone();
            for event in held.events.iter_mut().filter(|event| event.seq == 2) {
                event.kind = EventKind::Attach;
            }
            held.pairs.push(RecordedPair {
                host: Host::new(holder.host.get() + 100).unwrap(),
                pair: rekeyed,
                attach: 2,
            });
            assert_eq!(
                held.registrant(&late),
                crate::failover::records::Registration::Unknown
            );
            let reads = Reads {
                volume: Some(&held),
                ..reads
            };
            let _ = dev.owner_poll(
                &holder,
                target,
                own(),
                Err(crate::failover::evidence::NotSole::Unreadable),
                &reads,
                dev.serving_sample(),
            );
            assert_eq!(
                dev.authority.recorded.as_deref(),
                Some(&[own(), rekeyed][..]),
                "an unreadable Report carries no cached pair the record no longer classes ended"
            );
        }
    }
}

/// A serving clock whose reading a test can withhold.
struct Withheld(Rc<Cell<Option<u64>>>);
impl ServingClock for Withheld {
    fn now_us(&self) -> Option<u64> {
        self.0.get()
    }
}

/// LAPSE-UNVERIFIED at `owner_poll`, over a tenure withdrawn with `Cause::Unverified` for a non-holding pair outside
/// its recorded set. A Report listing the pair, with a shard read naming the tenure and a volume record that does not
/// admit the pair, retires one microsecond inside the Report's window and counts as unread at the window and when
/// the reads were sent before the Report's submission. The window is measured at the send sample of the reads,
/// whatever the clock reads at the poll, a clock with no reading included. A Report whose count does not match its
/// entries, and a conclusive Report
/// submitted no later than the lapse's last Report, show nothing absent. A poll without a shard read, and a poll
/// whose volume record was read by an earlier poll alone, verify nothing; a poll whose shard read names the tenure
/// beside a volume record that admits the pair verifies.
#[test]
fn an_unverified_owner_poll_takes_reports_inside_their_window_and_verifies_on_full_evidence() {
    use super::HoldState;
    use super::gate_fixture::{arena, attach_reserving, limits, own};
    use crate::failover::evidence::{Pair, Registrant, Report, ReservationType};
    use crate::failover::poll::{Reads, Verdict};
    use crate::failover::poll_tests::{owner, serving, volume};
    use crate::failover::records::{
        AttachmentEvent, ERA, EventKind, Host, RecordedPair, VolumeState,
    };
    use crate::failover::retire::Target;
    use crate::failover::serving::Machine;
    const WINDOW: u64 = 10_000;
    let second = Pair {
        exhid: crate::failover::identity::Exhid::new([3; 16]).unwrap(),
        key: crate::failover::identity::Key::decode((2 << 32) | 9).unwrap(),
    };
    let bounds = crate::storage::gate_fixture::bounds_with(limits(), WINDOW, 0);
    let session = super::ServingAuthority::fixture().session;
    let mut authority = super::ServingAuthority::new(
        bounds,
        Machine::issued(bounds, &session, own()),
        Box::new(super::gate_fixture::ZeroClock),
        session,
    );
    authority.recorded = Some(Box::new([own()]));
    let arena = arena();
    let storage = super::gate_fixture::storage();
    let (mut dev, device, registry) = attach_reserving(&storage, &arena, authority);
    let time = Rc::new(Cell::new(Some(0)));
    dev.set_serving_clock(Box::new(Withheld(Rc::clone(&time))));
    super::gate_fixture::ticks(&mut dev, &device, 64);
    let entries = [
        registry.borrow().entries[0],
        Registrant {
            cntlid: 20,
            holder: false,
            pair: second,
        },
    ];
    registry.borrow_mut().entries.push(entries[1]);
    time.set(Some(1_000));
    super::gate_fixture::ticks(&mut dev, &device, 8);
    time.set(Some(1_000 + WINDOW));
    super::gate_fixture::ticks(&mut dev, &device, 8);
    let report = dev.authority_report();
    assert_eq!(
        (report.withdrawal, report.flip, report.hold),
        (Some(Cause::Unverified), None, HoldState::Clear)
    );
    let lapsed = 1_000 + WINDOW;
    let holder = owner();
    let shard = serving();
    let target = Target::of(&shard);
    let mut record = volume(VolumeState::Active, holder.host);
    record.pairs = vec![RecordedPair {
        host: holder.host,
        pair: own(),
        attach: 0,
    }];
    let mut admitting = record.clone();
    let host = Host::new(holder.host.get() + 77).unwrap();
    let seq = admitting.next;
    admitting.next += 1;
    admitting.events.push(AttachmentEvent {
        seq,
        kind: EventKind::Attach,
        host,
        era: ERA,
        instance: Some(
            crate::failover::attachments::InstanceId::new("i-0777777777777777a").unwrap(),
        ),
    });
    admitting.pairs.push(RecordedPair {
        host,
        pair: second,
        attach: seq,
    });
    let report_at = |submitted_at: u64, regctl: u32, entries| Report {
        submitted_at,
        rtype: ReservationType::ExclusiveAccess,
        regctl,
        entries,
    };
    let mut poll_sent = |sent: u64, now: Option<u64>, report: &Report<'_>, shard, volume| {
        time.set(now);
        let reads = Reads {
            shard,
            volume,
            listed: None,
            peers: &[],
        };
        let verdict = dev.owner_poll(&holder, target, own(), Ok(report), &reads, sent);
        (matches!(verdict, Verdict::Retire(_)), dev.lapse_verified())
    };
    let now = lapsed + 3_000;
    let both = &entries[..];
    // The age is measured at the reads' send sample, whatever the clock reads when the poll runs.
    for (row, at, sent, reading, retires) in [
        (
            "one microsecond inside the window at the send",
            now - WINDOW + 1,
            now,
            Some(now),
            true,
        ),
        (
            "at the window at the send",
            now - WINDOW,
            now,
            Some(now),
            false,
        ),
        (
            "sent before the Report's submission",
            now,
            now - 1,
            Some(now),
            false,
        ),
        (
            "inside the window at the send and two windows past it at the poll",
            now - 1,
            now,
            Some(now + 2 * WINDOW),
            true,
        ),
        (
            "inside the window at the send with no reading at the poll",
            now - WINDOW + 1,
            now,
            None,
            true,
        ),
    ] {
        assert_eq!(
            poll_sent(
                sent,
                reading,
                &report_at(at, 2, both),
                Some(&shard),
                Some(&record)
            ),
            (retires, false),
            "{row}"
        );
    }
    let alone = &entries[..1];
    assert_eq!(
        poll_sent(
            now,
            Some(now),
            &report_at(now - 1, 2, alone),
            Some(&shard),
            None
        ),
        (false, false),
        "a count that does not match the entries shows nothing absent"
    );
    assert_eq!(
        poll_sent(
            now,
            Some(now),
            &report_at(lapsed, 1, alone),
            Some(&shard),
            None
        ),
        (false, false),
        "a Report submitted no later than the lapse's last Report shows nothing absent"
    );
    assert_eq!(
        poll_sent(
            now,
            Some(now),
            &report_at(now - 1, 2, both),
            None,
            Some(&admitting)
        ),
        (false, false),
        "no shard read verifies nothing, though the volume record admits the pair"
    );
    assert_eq!(
        poll_sent(
            now,
            Some(now),
            &report_at(now - 1, 2, both),
            Some(&shard),
            None
        ),
        (false, false),
        "a shard read beside no volume record of this poll verifies nothing"
    );
    assert_eq!(
        poll_sent(
            now,
            Some(now),
            &report_at(now - 1, 2, both),
            Some(&shard),
            Some(&admitting)
        ),
        (false, true),
        "a shard read naming the tenure beside a volume record that admits the pair verifies"
    );
}
