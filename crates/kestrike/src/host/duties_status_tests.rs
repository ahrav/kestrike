use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::Ordering;

use super::capture_tests::{capture_duties_under, policy_every};
use super::tests::{TEST_VIEW_US as VIEW_US, periods, records};
use super::{Duties, Linked, Open, STATUS_US};
use crate::failover::report::{Observed, Phase, RecoveryStatus, VolumeEntry};
use crate::failover::retire::Target;
use crate::failover::serving::{Cause, Event, State};
use crate::host::lane::Lane;
use crate::host::lane::tests::bounds;
use crate::host::link::{Inbound, Link, Message, Request, Status, decode, encode_status};
use crate::host::serve::loop_tests::{ROUND_US, Stage, read_held, staged, staged_over};
use crate::host::serve::tests::warm_volume_certified;
use crate::host::{Exit, HostGate, Rerun};
use crate::net::Outcome as Fetched;
use crate::storage::store::Client;
use crate::storage::store::sim::{MemLog, Shared};
use crate::storage::test_platform::TestPlatform;

type LinkedDuties<'w> = Duties<'w, Shared, MemLog, TestPlatform>;

const PID: u32 = 42;

fn leaked() -> &'static Link {
    Box::leak(Box::default())
}

fn linked<'w>(link: &'w Link) -> Linked<'w> {
    Linked {
        link,
        pid: PID,
        status_us: VIEW_US,
        recovery: Some(RecoveryStatus::NO_ATTEMPT),
    }
}

/// Duties with no link, no control plane and no capture policy.
fn unlinked_duties<'w>(stage: &Stage<'w>) -> LinkedDuties<'w> {
    let client = Client::open(stage.store.clone(), MemLog::default()).unwrap();
    Duties::new(
        (
            &HostGate::qualified(),
            crate::failover::reconcile::StandbyGate::qualified(),
        ),
        Lane::inline(client, stage.storage),
        records(),
        None,
        bounds(),
        periods(),
    )
}

fn linked_duties<'w>(stage: &Stage<'w>, link: &'w Link) -> LinkedDuties<'w> {
    unlinked_duties(stage).linked(linked(link))
}

fn received(status: &Status) -> Status {
    let mut bytes = vec![0; crate::host::link::STATUS_LEN];
    let len = encode_status(status, &mut bytes).unwrap();
    match decode(&bytes[..len]) {
        Ok(Message::Status(status)) => *status,
        other => panic!("a status decodes to a status: {other:?}"),
    }
}

#[test]
fn a_serving_status_carries_the_entry_the_owner_builds_over_the_duties_values() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let link = leaked();
        let mut duties = linked_duties(&stage, link);
        let published = RefCell::new(Vec::new());
        let before = Cell::new(None);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                let stepped = published
                    .borrow()
                    .iter()
                    .any(|(status, _, _): &(Status, _, u64)| {
                        status
                            .entry
                            .is_some_and(|entry| entry.publication_due.is_some())
                    });
                if stepped {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                if before.get().is_none() {
                    before.set(Some(duties.observed()));
                }
                let exit = duties.turn(owner, now);
                if let Some(status) = link.status.take() {
                    let entry = owner.report_entry(now, &duties.observed());
                    published.borrow_mut().push((status, entry, now));
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(duties.open(), Open::Opened);
        let published = published.into_inner();
        let (status, entry, _) = published.last().copied().unwrap();
        for pair in published.windows(2) {
            let (earlier, later) = (&pair[0], &pair[1]);
            if earlier.0.phase == later.0.phase {
                assert!(
                    later.2 >= earlier.2 + VIEW_US,
                    "one status a period: {} then {}",
                    earlier.2,
                    later.2
                );
            }
        }
        assert_eq!(status.phase, Phase::Serving);
        assert_eq!(
            (status.pid, status.shard),
            (PID, crate::storage::store_tests::shard())
        );
        assert_eq!(status.volume, records().holder.volume);
        assert!(status.tenure.is_some() && status.target.is_some());
        assert_eq!(status.entry, entry, "the status entry is the owner's entry");
        let entry: VolumeEntry = entry.unwrap();
        let wire = VolumeEntry::decode(&entry.encode().unwrap()).unwrap();
        assert_eq!(wire, entry);
        assert_eq!(received(&status), status);
        assert_eq!(
            entry.roll_due,
            Some(false),
            "a sampled step reads roll_due known clear"
        );
        assert_eq!(
            before.get().map(|observed: Observed| observed.roll_due),
            Some(None),
            "before any suffix step sampled it, roll_due reads unavailable"
        );
        assert_eq!(entry.roll_active, Some(false));
        assert_eq!(
            entry.publication_due,
            duties.suffix_due().map(|due| due.publication)
        );
        assert_eq!(entry.exit, None, "the exit field is the owner's tracker's");
        assert_eq!(entry.recovery.attempts, Some(0));
        assert_eq!(
            entry.captures,
            crate::failover::report::Captures {
                refused: None,
                abandoned: None
            },
            "duties with no capture policy read the counts unavailable"
        );
        assert_eq!(entry.pressure.quarantine, duties.quarantine());
        assert!(
            matches!(
                duties.quarantine(),
                crate::failover::report::Gauge::Known { .. }
            ),
            "the opened tenure's set gives the gauge"
        );
        assert_eq!(
            before.get().map(|observed: Observed| observed.suffix_due),
            Some(None),
            "before the first step the suffix signal reads unavailable"
        );
        assert_eq!(
            before.get().map(|observed: Observed| observed.roll_due),
            Some(None),
            "before the first step the roll flag reads unavailable"
        );
        let periods = published.len();
        assert!(periods >= 2, "one status per period: {periods}");
    });
}

#[test]
fn a_tenure_with_no_free_checkpoint_slot_publishes_roll_due_with_no_handoff() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let link = leaked();
        let mut duties = capture_duties_under(&stage, policy_every(1_000_000)).linked(linked(link));
        let last = Cell::new(None);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                let rolled = last
                    .get()
                    .and_then(|status: Status| status.entry)
                    .is_some_and(|entry| entry.roll_due == Some(true));
                if rolled {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                if let Some(status) = link.status.take() {
                    last.set(Some(status));
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(duties.roll_due());
        assert!(
            !duties.suffix_due().is_some_and(|due| due.handoff),
            "no suffix handoff signal"
        );
        assert!(duties.captures().refused >= Some(1));
        let status = last.get().unwrap();
        assert_eq!(status.phase, Phase::Serving, "the tenure keeps serving");
        assert_eq!(status.entry.unwrap().roll_due, Some(true));
        assert_eq!(
            status.entry.unwrap().captures,
            duties.captures(),
            "the capture counts"
        );
        assert_eq!(
            status.entry.unwrap().pressure.quarantine,
            duties.quarantine(),
            "the quarantine gauge"
        );
        assert_eq!(received(&status).entry.unwrap().roll_due, Some(true));
    });
}

/// A capture pass whose encode panicked ends the tenure on the turn that takes its terminal, and that turn
/// publishes the tenure's last status before it returns: with the cell held on every turn, the duties keep the
/// status of the exit turn for the caller.
#[test]
fn a_turn_that_ends_on_a_panicked_encode_publishes_the_last_status() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let link = leaked();
        let mut duties = capture_duties_under(&stage, policy_every(1_000_000)).linked(linked(link));
        // The parked pool runs the encode on this thread, where the planted panic is set.
        crate::storage::PARK_RECOVERY.with(|park| park.set(true));
        crate::storage::ENCODE_PANIC.with(|panic| panic.set(true));
        let (served, _) = stage.serve_until(
            |_, turn, stop| {
                if turn >= 20_000 {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                owner.release_parked();
                let held = link.status.hold();
                let exit = duties.turn(owner, now);
                assert!(held.is_none(), "the held cell took no status");
                drop(held);
                exit
            },
        );
        crate::storage::ENCODE_PANIC.with(|panic| panic.set(false));
        crate::storage::PARK_RECOVERY.with(|park| park.set(false));
        assert_eq!(served.exit, Exit::Rerun(Rerun::Unwound));
        let last = duties
            .take_unpublished()
            .expect("the exit turn's status stays with the duties");
        assert_eq!(last.pid, PID);
    });
}

/// FINAL-STATUS-KEPT for an exit the serving loop names while the duties return none. A lost device leaves the phase
/// at `Serving`, so the turn that first reads the loss ends the tenure inside a status period. That turn publishes
/// its status whatever the period, and with the cell held from the first status on, the duties keep it for the
/// caller.
#[test]
fn the_turn_that_reads_a_lost_device_publishes_the_last_status_inside_a_period() {
    for held in [false, true] {
        staged_over(warm_volume_certified(0), |mut stage| {
            let link = leaked();
            let mut duties = unlinked_duties(&stage).linked(Linked {
                status_us: STATUS_US,
                ..linked(link)
            });
            let registry = stage.registry.clone();
            let taken = RefCell::new(Vec::new());
            let turn = Cell::new(0);
            let mut gone = false;
            let (served, _) = stage.serve_until(
                |rounds, _, _| {
                    if !gone && !taken.borrow().is_empty() {
                        rounds.control.set_gone();
                        registry.borrow_mut().refuse =
                            Some(crate::storage::RefusalReason::DeviceGone);
                        gone = true;
                    }
                },
                |owner, now| {
                    let hold = (held && !taken.borrow().is_empty()).then(|| link.status.hold());
                    let exit = duties.turn(owner, now);
                    drop(hold);
                    if let Some(status) = link.status.take() {
                        taken.borrow_mut().push((now, status));
                    }
                    turn.set(now);
                    exit
                },
            );
            stage.registry.borrow_mut().refuse = None;
            assert_eq!(served.exit, Exit::Rerun(Rerun::ControllerEvent), "{held}");
            let (taken, ended_at) = (taken.into_inner(), turn.get());
            let first = taken[0].0;
            assert!(
                first < ended_at && ended_at < first + STATUS_US,
                "{held}: the loss ends the tenure inside the first status period: {first}, {ended_at}"
            );
            let last = match held {
                true => {
                    assert_eq!(taken.len(), 1, "the held cell took no later status");
                    duties
                        .take_unpublished()
                        .expect("the exit turn's status stays with the duties")
                }
                false => {
                    assert_eq!(duties.take_unpublished(), None, "the cell took it");
                    let (at, last) = taken.last().copied().unwrap();
                    assert_eq!(at, ended_at, "the exit turn published its status");
                    last
                }
            };
            assert_eq!((last.pid, last.phase), (PID, Phase::Serving), "{held}");
        });
    }
}

/// FINAL-STATUS-KEPT for a withdrawal the duties did not make: the caller withdraws the authority on a recorded
/// force detach before the duties' turn, so the serving loop ends the tenure with `Exit::Retire`, which parks, while
/// the duties return none. With the cell held on that turn the duties keep the withdrawn status, and the parked
/// status built from it carries the entry with the flip flag.
#[test]
fn a_cell_held_on_the_turn_a_force_detach_retires_keeps_the_withdrawn_status() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let link = leaked();
        let mut duties = linked_duties(&stage, link);
        let mut entered = false;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if !entered {
                    let exit = duties.turn(owner, now);
                    entered = (link.status.take()).is_some_and(|status| status.entry.is_some());
                    return exit;
                }
                owner.authority_event(Event::Withdraw(Cause::ForceDetach), now);
                let held = link.status.hold();
                let exit = duties.turn(owner, now);
                assert_eq!(
                    exit, None,
                    "the duties name no exit for the caller's withdrawal"
                );
                assert!(held.is_none(), "the held cell took no status");
                drop(held);
                exit
            },
        );
        assert!(matches!(served.exit, Exit::Retire(_)), "{:?}", served.exit);
        assert_eq!(link.status.take(), None);
        let last = duties
            .take_unpublished()
            .expect("the exit turn's status stays with the duties");
        assert_eq!(last.phase, Phase::Withdrawn);
        let entry = last.entry.expect("the withdrawn status carries the entry");
        assert_eq!((entry.serving, entry.flip), (Some(State::Withdrawn), true));
        let parked = last.parked(&served.exit);
        assert_eq!((parked.phase, parked.entry), (Phase::Parked, Some(entry)));
    });
}

#[test]
fn a_held_status_cell_leaves_the_turn_unblocked_and_the_next_period_writes() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let link = leaked();
        let mut duties = linked_duties(&stage, link);
        let turns = Cell::new(0);
        let (skipped, written) = (Cell::new(None), Cell::new(None));
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if written.get().is_some() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                turns.set(turns.get() + 1);
                if turns.get() == 1 {
                    let held = link.status.hold();
                    let exit = duties.turn(owner, now);
                    assert!(held.is_none(), "the held cell took no status");
                    drop(held);
                    skipped.set(Some(now));
                    return exit;
                }
                let exit = duties.turn(owner, now);
                if written.get().is_none()
                    && let Some(status) = link.status.take()
                {
                    written.set(Some((now, status)));
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let (at, status) = written.get().unwrap();
        assert!(at > skipped.get().unwrap());
        assert_eq!(status.pid, PID);
        assert_eq!(
            duties.take_unpublished(),
            None,
            "a turn with a successor keeps no status"
        );
    });
}

#[test]
fn a_queued_peer_raises_the_peer_event_on_the_next_turn_and_a_request_is_kept() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let link = leaked();
        let mut duties = linked_duties(&stage, link);
        let request = Request::new(&[9; 95]).unwrap();
        let (before, after) = (Cell::new(None), Cell::new(None));
        let turns = Cell::new(0);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if after.get().is_some() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                turns.set(turns.get() + 1);
                if turns.get() == 3 {
                    before.set(Some(owner.withhold().peer_read_at()));
                    let read_at = Some(now.saturating_sub(1));
                    assert!(link.inbox.deliver(Inbound::Peer { read_at }));
                    assert!(link.inbox.deliver(Inbound::Request(request)));
                    let witness = crate::failover::detect::host::Revalidated {
                        shard: crate::storage::store_tests::shard(),
                        target: Target::of(&crate::failover::restart::tests::shard_record(1)),
                        until_us: now,
                    };
                    assert!(link.inbox.deliver(Inbound::Nominate(witness)));
                }
                let exit = duties.turn(owner, now);
                if turns.get() == 3 {
                    after.set(Some((now, owner.withhold().peer_read_at())));
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(before.get(), Some(None));
        let (at, read_at) = after.get().unwrap();
        assert_eq!(read_at, Some(at - 1), "the turn applied the peer read time");
        assert_eq!(duties.take_request(), Some(request));
        assert_eq!(duties.take_request(), None);
        let mut left = 0;
        link.inbox.drain(|_| left += 1);
        assert_eq!(left, 0, "the turn drained the nomination");
    });
}

/// The turns [`readings`] records.
const TURNS: usize = 200;

/// The serving-clock readings each of a tenure's first duty turns takes, with whether the turn published a status.
/// `link` links the duties; the tenure, its duties' periods and its rounds are the same with and without it.
fn readings(link: Option<&'static Link>) -> Vec<(u32, bool)> {
    staged_over(warm_volume_certified(0), |mut stage| {
        let reads = Rc::clone(&stage.rounds.clock_reads);
        let mut duties = unlinked_duties(&stage);
        if let Some(link) = link {
            duties = duties.linked(linked(link));
        }
        let turns = RefCell::new(Vec::new());
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if turns.borrow().len() >= TURNS {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let before = reads.get();
                let exit = duties.turn(owner, now);
                let published = link.is_some_and(|link| link.status.take().is_some());
                turns.borrow_mut().push((reads.get() - before, published));
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        turns.into_inner()
    })
}

/// The status costs the owner thread one serving-clock reading on a turn that publishes and none on a turn between
/// statuses: turn for turn, linked duties read the clock as often as the same duties with no link, plus once on each
/// turn that published. The one reading dates the status's ages and its entry, so both describe one instant.
#[test]
fn a_linked_turn_reads_the_serving_clock_once_for_a_status_and_never_between_statuses() {
    let (plain, linked) = (readings(None), readings(Some(leaked())));
    assert_eq!(plain.len(), linked.len());
    let published = linked.iter().filter(|(_, published)| *published).count();
    assert!(
        (3..TURNS / 2).contains(&published),
        "statuses a period apart: {published}"
    );
    for (turn, (plain, linked)) in plain.iter().zip(&linked).enumerate() {
        assert_eq!(
            linked.0,
            plain.0 + u32::from(linked.1),
            "turn {turn}, published {}",
            linked.1
        );
    }
}

/// The status's request counts carry the heartbeat's meaning: `completions` counts answered requests and `pending`
/// the device commands and the requests in flight. While the device holds a GET's read, the request is unanswered:
/// `completions` reads zero, though the owner handled the session's datagrams and the GET's, and `pending` counts
/// the request beside the commands the owner's table holds, which the owner's retained census gives at the same
/// turn. Once the client holds the complete object, `completions` reads one.
#[test]
fn a_status_counts_an_answered_request_once_and_a_held_one_in_flight() {
    staged(|mut stage| {
        let link = leaked();
        let mut duties = unlinked_duties(&stage).linked(Linked {
            status_us: 2 * ROUND_US,
            ..linked(link)
        });
        let control = stage.rounds.control.clone();
        let sent = Cell::new(None);
        let held = Cell::new(None::<(Status, u32)>);
        let fetched = Cell::new(false);
        let answered = Cell::new(None::<Status>);
        let (served, _) = stage.serve_until(
            |rounds, _, stop| {
                if held.get().is_none() {
                    let mut id = sent.get();
                    read_held(rounds, &mut id);
                    sent.set(id);
                    return;
                }
                rounds.frozen.set(false);
                if !fetched.get() {
                    let id = sent.get().expect("the GET was sent");
                    let outcome = rounds.fetched(id, &mut Vec::new());
                    fetched.set(outcome == Some(Fetched::Complete));
                }
                if answered.get().is_some() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let Some(status) = link.status.take() else {
                    return exit;
                };
                if held.get().is_none() {
                    if sent.get().is_some() && control.pending() > 0 {
                        held.set(Some((status, owner.report().retained.commands)));
                    }
                } else if fetched.get() && answered.get().is_none() {
                    answered.set(Some(status));
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let (held, commands) = held.get().expect("a status with the read at the device");
        assert_eq!(held.completions, 0, "no request is answered yet");
        assert_eq!(
            held.pending,
            u64::from(commands) + 1,
            "the commands the owner's table holds and the one GET"
        );
        let answered = answered
            .get()
            .expect("a status after the client's COMPLETE");
        assert_eq!(answered.completions, 1, "the one GET, answered once");
    });
}
