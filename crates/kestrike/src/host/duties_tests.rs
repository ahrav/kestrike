use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use super::{Duties, Open, Periods, Records};
use crate::failover::attachments::InstanceId;
use crate::failover::fresh::tests::holder;
use crate::failover::records::Host;
use crate::failover::records::{
    Ancestry, Namespace, Record, ShardRecord, VolumeId, VolumeRecord, VolumeState,
};
use crate::failover::restart::tests::{shard_now, volume_id};
use crate::failover::serving::{Cause, Event};
use crate::failover::takeover::tests::instance_of;
use crate::host::lane::tests::{Locked, SharedLog, bounds, locked_client};
use crate::host::lane::{Job, Lane};
use crate::host::serve::loop_tests::{ROUND_US, Rounds, Stage, TestOwner, staged, staged_over};
use crate::host::serve::tests::{content, warm_volume_certified};
use crate::host::{Exit, HostGate, Rerun};
use crate::net::{Outcome as Fetched, RequestId};
use crate::storage::checkpoint::{SuffixBounds, required_history};
use crate::storage::device::sim::Media;
use crate::storage::gate_fixture::{bounds_of, limits};
use crate::storage::owner_fixture::reserve_at;
use crate::storage::store::sim::{Arm, MemLog, Point, Recorder, Shared, hooked};
use crate::storage::store::{Client, Item, Key, Outcome, Store, Unavailable, WatermarkLog, Write};
use crate::storage::store_tests::{client as store_client, shard};
use crate::storage::test_platform::TestPlatform;
use crate::storage::warm_sim::{object_key, storage as test_storage};
use crate::storage::{
    CacheVersion, CaptureError, CpuSet, FillPublishError, Storage, WorkBudget, WritableFill,
};

const VIEW_US: u64 = TEST_VIEW_US;

pub(crate) const TEST_VIEW_US: u64 = 2_500;

pub(crate) fn periods() -> Periods {
    let bounds = bounds_of(limits());
    Periods::new(&bounds, TEST_VIEW_US, 50 * TEST_VIEW_US, (500, 1_000)).unwrap()
}

fn instance(host: Host) -> Option<InstanceId> {
    Some(instance_of(host))
}

pub(crate) fn records() -> Records<'static> {
    records_of(volume_id())
}

/// The records of `host`'s duties over the restart fixtures' volume.
pub(crate) fn records_for(host: Host) -> Records<'static> {
    Records {
        holder: crate::failover::takeover::tests::holder_of(host),
        instance: &instance,
    }
}

fn records_of(volume: VolumeId) -> Records<'static> {
    Records {
        holder: crate::failover::poll::Holder { volume, ..holder() },
        instance: &instance,
    }
}

/// Every store request a duties' recorder issued, in issue order as `(write, key)`.
#[derive(Clone)]
struct Calls {
    recorder: Recorder,
    issued: Rc<RefCell<Vec<(bool, Key)>>>,
}

impl Calls {
    fn over(store: &Shared) -> Self {
        Self {
            recorder: Recorder::new(store),
            issued: Rc::default(),
        }
    }

    /// The requests issued so far: those an earlier call collected and those the recorder holds.
    fn borrow(&self) -> std::cell::Ref<'_, Vec<(bool, Key)>> {
        let recorded = crate::host::wait_tests::keyed(&self.recorder);
        self.issued.borrow_mut().extend(recorded);
        self.issued.borrow()
    }
}

type InlineDuties<'w> = Duties<'w, Recorder, MemLog, TestPlatform>;

fn duties_over<'w, S: Store, L: WatermarkLog>(
    lane: Lane<'w, S, L, TestPlatform>,
) -> Duties<'w, S, L, TestPlatform> {
    Duties::new(
        (
            &HostGate::qualified(),
            crate::failover::reconcile::StandbyGate::qualified(),
        ),
        lane,
        records(),
        None,
        bounds(),
        periods(),
    )
}

fn duties_with<'w>(
    stage: &Stage<'w>,
    log: MemLog,
    volume: VolumeId,
    bounds: SuffixBounds,
) -> (InlineDuties<'w>, Calls) {
    let calls = Calls::over(&stage.store);
    let lane = Lane::inline(
        Client::open(calls.recorder.clone(), log).unwrap(),
        stage.storage,
    );
    let duties = Duties::new(
        (
            &HostGate::qualified(),
            crate::failover::reconcile::StandbyGate::qualified(),
        ),
        lane,
        records_of(volume),
        None,
        bounds,
        periods(),
    );
    (duties, calls)
}

fn inline_duties<'w>(stage: &Stage<'w>) -> (InlineDuties<'w>, Calls) {
    let (mut duties, calls) = duties_with(stage, MemLog::default(), volume_id(), bounds());
    duties.lane.inline_mut().hold();
    (duties, calls)
}

fn writes(calls: &Calls) -> Vec<Key> {
    (calls.borrow().iter())
        .filter(|(write, _)| *write)
        .map(|(_, key)| *key)
        .collect()
}

fn shard_commits(store: &Shared) -> usize {
    store.0.borrow().commit_count(&Key::Shard(shard()))
}

fn serve_turns<'w>(
    stage: &mut Stage<'w>,
    turns: u64,
    duties: impl FnMut(&mut TestOwner<'w>, u64) -> Option<Exit>,
) -> Exit {
    let mut first = None;
    let (served, _) = stage.serve_until(
        |_, turn, stop| {
            if turn >= *first.get_or_insert(turn) + turns {
                stop.store(true, Ordering::Release);
            }
        },
        duties,
    );
    served.exit
}

fn rewrite<R: Record>(store: &Shared, key: Key, edit: impl FnOnce(R) -> R) {
    let item = store.0.borrow().current(&key).cloned().unwrap();
    let write = Write::Exact {
        expect: item.version,
        value: edit(R::decode(&item.value).unwrap()).encode(),
    };
    let mut raw = store.clone();
    assert!(matches!(
        Store::write(&mut raw, &key, &write),
        Outcome::Committed(_)
    ));
}

fn delta_blocks(store: &Shared) -> u64 {
    let mut reader = store_client(store);
    let volume = reader
        .read::<VolumeRecord>(Key::Volume(volume_id()))
        .unwrap();
    required_history(&shard_now(store), &volume.value().layout).1
}

fn unnamed_volume() -> (Shared, Media) {
    let (store, media) = warm_volume_certified(1);
    rewrite::<ShardRecord>(&store, Key::Shard(shard()), |record| ShardRecord {
        checkpoint: None,
        cut: 0,
        ancestry: Ancestry::new(&[]).unwrap(),
        ..record
    });
    (store, media)
}

#[derive(Default)]
struct Gets {
    pending: Option<(RequestId, Vec<u8>)>,
    done: usize,
}

impl Gets {
    /// Sends the next GET when none is pending and reports whether the pending one completed.
    fn pump(&mut self, rounds: &Rounds<'_>, stop: &AtomicBool) -> bool {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        let active = rounds.client.borrow().state() == crate::net::SessionState::Active;
        if active && self.pending.is_none() {
            let n = 1 + (self.done % 4) as u8;
            self.pending = Some((rounds.get(n), Vec::new()));
        }
        let Some((id, bytes)) = self.pending.as_mut() else {
            return false;
        };
        let Some(outcome) = rounds.fetched(*id, bytes) else {
            return false;
        };
        assert_eq!(outcome, Fetched::Complete);
        self.pending = None;
        self.done += 1;
        true
    }
}

pub(super) type Filling<'w> = Option<(WritableFill<'w, 'w, TestPlatform>, usize)>;

pub(super) fn fill_step<'w>(
    owner: &mut TestOwner<'w>,
    storage: &'w Storage<TestPlatform>,
    filling: &mut Filling<'w>,
    n: u8,
) -> Option<Result<(), FillPublishError>> {
    fill_bytes(owner, storage, filling, n, &content(n, n))
}

/// One turn of a local FILL of object `n` with `payload`, four metadata bytes and the body after them, as
/// [`fill_step`] runs it.
pub(super) fn fill_bytes<'w>(
    owner: &mut TestOwner<'w>,
    storage: &'w Storage<TestPlatform>,
    filling: &mut Filling<'w>,
    n: u8,
    payload: &[u8],
) -> Option<Result<(), FillPublishError>> {
    if filling.is_none() {
        let fill = reserve_at(
            storage,
            &object_key(n),
            CacheVersion(0),
            4,
            payload.len() - 4,
        )
        .expect("a FILL reserves while the log is closed");
        *filling = Some((fill, 0));
    }
    let (fill, taken) = filling.as_mut()?;
    let progress = owner.fill_progress(fill);
    if !progress.is_ready() {
        // Once the payload is taken, a receive with no input submits a segment a refused submit left staged.
        let staged = progress.submitted_units < progress.len_units;
        let mut budget = WorkBudget::with_io(0, usize::MAX, usize::MAX);
        if (*taken < payload.len() || staged)
            && let Ok(more) = owner.receive_fill(fill, &payload[*taken..], &mut budget)
        {
            *taken += more;
        }
        return None;
    }
    let (fill, _) = filling.take()?;
    let mut budget = WorkBudget::new(1024);
    Some(owner.publish_fill(fill, u64::MAX, 2, &mut budget).map(drop))
}

pub(super) fn log_open(storage: &Storage<TestPlatform>) -> bool {
    storage.with_suffix(|log| log.is_open()).unwrap_or(false)
}

#[test]
fn the_tenure_open_confirms_certifies_and_reserves_before_a_fill_publishes() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let (mut duties, calls) = inline_duties(&stage);
        let (store, storage) = (stage.store.clone(), stage.storage);
        let before = shard_commits(&store);
        let recorded = shard_now(&store).ancestry.as_slice()[0];
        assert_eq!(recorded.certified, recorded.start);
        let mut viewed = None;
        let mut commits = Vec::new();
        let mut filling: Filling<'_> = None;
        let (mut closed, opened) = (None, Cell::new(None));
        let mut session = 0;
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if opened.get().is_some() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                session = owner.tenure().get();
                let inline = duties.lane.inline_mut();
                if viewed.is_none() && duties.open == Open::Viewing && inline.held() == 1 {
                    viewed = Some(calls.borrow().clone());
                }
                match duties.open {
                    Open::Confirming if inline.held() == 1 && closed.is_none() => {
                        assert!(!log_open(storage));
                        closed = fill_step(owner, storage, &mut filling, 9);
                    }
                    Open::Opened if opened.get().is_none() => {
                        assert!(log_open(storage));
                        opened.set(fill_step(owner, storage, &mut filling, 10));
                    }
                    _ => {
                        if inline.release() {
                            commits.push((duties.open, shard_commits(&store) - before));
                        }
                    }
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(
            viewed,
            Some(vec![
                (false, Key::Volume(volume_id())),
                (false, Key::Shard(shard()))
            ]),
            "READ-ORDER: the View reads the volume record first"
        );
        assert_eq!(
            duties.ends,
            [(recorded.session, recorded.end)],
            "the warm load read the predecessor's one block whole"
        );
        assert_eq!(
            closed,
            Some(Err(FillPublishError::History)),
            "a fill before the log opens"
        );
        assert_eq!(opened.get(), Some(Ok(())), "a fill after the log opens");
        assert_eq!(
            commits,
            [
                (Open::Viewing, 0),
                (Open::Confirming, 1),
                (Open::Opening, 3),
                (Open::Opened, 3)
            ],
            "the first suffix step after the open has nothing to record"
        );
        let record = shard_now(&store);
        let chain = record.ancestry.as_slice();
        let predecessor = chain
            .iter()
            .find(|suffix| suffix.session == recorded.session)
            .unwrap();
        assert_eq!(predecessor.certified, recorded.end);
        let last = chain.last().copied().unwrap();
        assert_eq!(last.session, session, "the tenure recorded its own suffix");
    });
}

#[test]
fn a_held_open_completion_issues_no_store_request_and_gets_are_served() {
    staged(|mut stage| {
        let (mut duties, calls) = inline_duties(&stage);
        let held = Cell::new(None::<(u64, usize)>);
        let mut gets = Gets::default();
        let (served, _) = stage.serve_until(
            |rounds, turn, stop| {
                let Some((from, _)) = held.get() else {
                    return;
                };
                if turn >= from + 1_000 {
                    stop.store(true, Ordering::Release);
                }
                gets.pump(rounds, stop);
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let open_held = duties.open == Open::Opening && duties.lane.outstanding() == 1;
                let inline = duties.lane.inline_mut();
                match held.get() {
                    None if open_held && inline.held() == 1 => {
                        held.set(Some((now / ROUND_US, calls.borrow().len())));
                    }
                    None => {
                        inline.release();
                    }
                    Some((_, at)) => {
                        assert_eq!(
                            calls.borrow().len(),
                            at,
                            "no store request while the Open completion is held"
                        );
                        assert_eq!(duties.lane.outstanding(), 1, "no second shard-record job");
                    }
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(held.get().is_some(), "the Open completion was held");
        assert!(gets.done >= 10, "GETs were served: {}", gets.done);
        assert_eq!(duties.open, Open::Opening);
    });
}

#[test]
fn a_panicking_lane_job_ends_the_tenure_with_a_rerun() {
    staged(|mut stage| {
        let hook = hooked(&stage.store, Key::Shard(shard()), Point::AfterRead, || {
            panic!("a planted lane panic")
        });
        let lane = Lane::inline(
            Client::open(hook, MemLog::default()).unwrap(),
            stage.storage,
        );
        let mut duties = duties_over(lane);
        let returned = RefCell::new(None);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let exit = duties.turn(owner, now);
                if exit.is_some() {
                    *returned.borrow_mut() = exit.clone();
                }
                exit
            },
        );
        assert_eq!(*returned.borrow(), Some(Exit::Rerun(Rerun::Unwound)));
        assert_eq!(served.exit, Exit::Rerun(Rerun::Unwound));
        assert_eq!(duties.open, Open::Stopped);
        assert_eq!(duties.lane.outstanding(), 0);
        assert!(served.teardown.is_ok(), "the owner still tears down");
    });
}

#[test]
#[should_panic(expected = "the duties start over an idle lane")]
fn duties_over_a_lane_with_an_outstanding_job_panic() {
    staged(|stage| {
        let mut lane = Lane::inline(store_client(&stage.store), stage.storage);
        lane.submit(Job::Mark).unwrap();
        duties_over(lane);
    });
}

#[test]
fn a_second_shard_record_job_while_open_is_outstanding_fails_the_single_holder_check() {
    staged(|mut stage| {
        let (mut duties, _) = inline_duties(&stage);
        let mut failure = None;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let exit = duties.turn(owner, now);
                if duties.open != Open::Opening || !duties.writing {
                    duties.lane.inline_mut().release();
                    return exit;
                }
                let planted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    duties.take_set();
                }));
                failure = planted
                    .err()
                    .and_then(|panic| panic.downcast::<&str>().ok());
                Some(Exit::Stopped)
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let failure = failure.expect("the planted second job fails");
        assert!(failure.starts_with("PossNamedCoversStore"), "{failure}");
    });
}

#[test]
fn a_failed_view_retries_one_view_period_after_its_submit() {
    staged(|mut stage| {
        let (mut duties, calls) = duties_with(&stage, MemLog::default(), volume_id(), bounds());
        stage.store.schedule(Arm::Unavailable);
        let mut views = Vec::new();
        let opened = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if opened.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let from = calls.borrow().len();
                let exit = duties.turn(owner, now);
                let volume = (false, Key::Volume(volume_id()));
                if calls.borrow()[from..].contains(&volume) {
                    views.push(now);
                }
                opened.set(duties.open == Open::Opened);
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(views.len(), 2, "{views:?}");
        let gap = views[1] - views[0];
        assert!(
            (VIEW_US..VIEW_US + ROUND_US).contains(&gap),
            "the retry waits one view period: {gap}"
        );
    });
}

/// The open's View passes its reads to the owner, so a record of a later tenure deposes the tenure: one bumped on
/// the own volume, which the open's own checks admit as far as the Confirm, and one flipped to another volume.
#[test]
fn a_view_of_a_later_tenure_stops_the_open_before_any_write() {
    for case in ["bumped", "flipped"] {
        staged(|mut stage| {
            match case {
                "bumped" => {
                    let mut bumper = store_client(&stage.store);
                    let read = bumper.read::<ShardRecord>(Key::Shard(shard())).unwrap();
                    bumper.bump(&read).unwrap();
                }
                _ => rewrite::<ShardRecord>(&stage.store, Key::Shard(shard()), |record| {
                    ShardRecord {
                        attempts: record.attempts + 1,
                        active: VolumeId::new("vol-ff").unwrap(),
                        ..record
                    }
                }),
            }
            let commits = shard_commits(&stage.store);
            let (mut duties, calls) = duties_with(&stage, MemLog::default(), volume_id(), bounds());
            let cause = Cell::new(None);
            assert_eq!(
                serve_turns(&mut stage, 300, |owner, now| {
                    let exit = duties.turn(owner, now);
                    cause.set(owner.authority_report().withdrawal);
                    exit
                }),
                Exit::Deposed,
                "{case}: the view's record names a later tenure"
            );
            assert_eq!(cause.get(), Some(Cause::Flipped), "{case}");
            assert_eq!(duties.open, Open::Stopped, "{case}");
            assert_eq!(shard_commits(&stage.store), commits, "{case}");
            assert_eq!(
                calls.borrow().len(),
                2,
                "{case}: the View's two reads alone"
            );
        });
    }
}

/// A Confirm that loses its exact-version write to a bump retries from a View, and that View's record of the later
/// tenure deposes the tenure with no further write.
#[test]
fn a_retry_view_of_a_later_tenure_deposes_the_tenure() {
    staged(|mut stage| {
        let (mut duties, calls) = inline_duties(&stage);
        let store = stage.store.clone();
        let mut commits = None;
        let exit = serve_turns(&mut stage, 300, |owner, now| {
            let exit = duties.turn(owner, now);
            if commits.is_none() && duties.lane.inline_mut().held() == 1 {
                let mut bumper = store_client(&store);
                let read = bumper.read::<ShardRecord>(Key::Shard(shard())).unwrap();
                bumper.bump(&read).unwrap();
                commits = Some(shard_commits(&store));
            }
            duties.lane.inline_mut().release();
            exit
        });
        assert_eq!(exit, Exit::Deposed);
        assert_eq!(Some(shard_commits(&store)), commits, "the bump alone");
        let writes = calls.borrow().iter().filter(|(write, _)| *write).count();
        assert_eq!(writes, 1, "the Confirm the bump refused");
        assert_eq!(calls.borrow().len(), 5, "two Views and that Confirm");
    });
}

/// Control for the deposition: a record below the tenure's `(g, E)` names no later tenure. The owner withdraws on it
/// as a regression, which reruns.
#[test]
fn a_view_of_an_earlier_tenure_withdraws_the_tenure_as_a_regression() {
    staged(|mut stage| {
        rewrite::<ShardRecord>(&stage.store, Key::Shard(shard()), |record| ShardRecord {
            attempts: record.attempts - 1,
            ..record
        });
        let commits = shard_commits(&stage.store);
        let (mut duties, calls) = duties_with(&stage, MemLog::default(), volume_id(), bounds());
        let cause = Cell::new(None);
        assert_eq!(
            serve_turns(&mut stage, 300, |owner, now| {
                let exit = duties.turn(owner, now);
                cause.set(owner.authority_report().withdrawal);
                exit
            }),
            Exit::Rerun(Rerun::Withdrawn)
        );
        assert_eq!(cause.get(), Some(Cause::Regression));
        assert_eq!(duties.open, Open::Stopped);
        assert_eq!(shard_commits(&stage.store), commits);
        assert_eq!(calls.borrow().len(), 2, "the View's two reads alone");
    });
}

#[test]
fn a_view_that_contradicts_the_tenure_stops_the_open_with_no_write() {
    let other = VolumeId::new("vol-ff").unwrap();
    for case in ["other volume", "retired"] {
        staged(|mut stage| {
            let mut writer = store_client(&stage.store);
            let own = writer
                .read::<VolumeRecord>(Key::Volume(volume_id()))
                .unwrap();
            let target = match case {
                "other volume" => {
                    let record = VolumeRecord {
                        volume: other,
                        ..own.value().clone()
                    };
                    writer.create(Key::Volume(other), record).unwrap();
                    other
                }
                _ => {
                    let record = VolumeRecord {
                        state: VolumeState::Retired,
                        ..own.value().clone()
                    };
                    writer.replace(&own, record).unwrap();
                    volume_id()
                }
            };
            let commits = shard_commits(&stage.store);
            let (mut duties, calls) = duties_with(&stage, MemLog::default(), target, bounds());
            assert_eq!(
                serve_turns(&mut stage, 300, |owner, now| duties.turn(owner, now)),
                Exit::Deposed,
                "{case}: the view's records show another tenure"
            );
            assert_eq!(shard_commits(&stage.store), commits, "{case}");
            assert!(calls.borrow().iter().all(|(write, _)| !write), "{case}");
        });
    }
}

#[test]
fn unbounded_suffix_limits_stop_the_open_before_any_request() {
    for case in ["no queue", "no step"] {
        staged(|mut stage| {
            let mut unbounded = bounds();
            match case {
                "no queue" => unbounded.limits.queue_blocks = 0,
                _ => unbounded.step = 0,
            }
            let (mut duties, calls) =
                duties_with(&stage, MemLog::default(), volume_id(), unbounded);
            let exit = serve_turns(&mut stage, 100, |owner, now| duties.turn(owner, now));
            assert_eq!(exit, Exit::Stopped);
            assert_eq!(duties.open, Open::Stopped, "{case}");
            assert!(writes(&calls).is_empty(), "{case}: {:?}", calls.borrow());
        });
    }
}

#[test]
fn a_reservation_the_chain_refuses_stops_the_open() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut past = bounds();
        past.step = delta_blocks(&stage.store);
        let before = shard_commits(&stage.store);
        let (mut duties, calls) = duties_with(&stage, MemLog::default(), volume_id(), past);
        assert_eq!(
            serve_turns(&mut stage, 300, |owner, now| duties.turn(owner, now)),
            Exit::Stopped
        );
        assert_eq!(duties.open, Open::Stopped);
        assert_eq!(shard_commits(&stage.store) - before, 2);
        let writes = calls.borrow().iter().filter(|(write, _)| *write).count();
        assert_eq!(writes, 2, "the Confirm and the certification alone");
        assert!(!log_open(stage.storage));
    });
}

#[test]
fn an_open_over_a_busy_capture_mutex_repeats_over_its_reservation() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let before = shard_commits(&stage.store);
        let (mut duties, calls) = duties_with(&stage, MemLog::default(), volume_id(), bounds());
        let storage = stage.storage;
        let (mut busy, mut opens) = (false, Vec::new());
        let opened = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if opened.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let from = writes(&calls).len();
                let due = (duties.open == Open::Confirming && duties.writing)
                    || (duties.open == Open::Opening && !duties.writing);
                let exit = if due && !busy {
                    busy = true;
                    storage
                        .with_suffix(|_| duties.turn(owner, now))
                        .expect("the capture mutex")
                } else {
                    duties.turn(owner, now)
                };
                if due && duties.open == Open::Opening && duties.writing {
                    opens.push((now, writes(&calls).len() - from));
                }
                opened.set(duties.open == Open::Opened && log_open(storage));
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(opens.len(), 2, "{opens:?}");
        assert!(opens[1].0 >= opens[0].0 + VIEW_US, "{opens:?}");
        assert_eq!(opens[1].1, 0, "the repeat issues no store request");
        assert_eq!(shard_commits(&stage.store) - before, 3);
        let own = shard_now(&stage.store).ancestry.as_slice().len();
        assert_eq!(own, 2, "the predecessor and one suffix of the tenure");
    });
}

#[test]
fn an_owner_withdrawal_stops_the_open_before_its_next_write() {
    for (held, late) in [
        (Open::Viewing, false),
        (Open::Confirming, false),
        (Open::Viewing, true),
        (Open::Confirming, true),
    ] {
        staged(|mut stage| {
            let (mut duties, _) = inline_duties(&stage);
            let store = stage.store.clone();
            let mut commits = None;
            let mut first = None;
            let (served, _) = stage.serve_until(
                |_, turn, stop| {
                    if turn >= *first.get_or_insert(turn) + 300 {
                        stop.store(true, Ordering::Release);
                    }
                },
                |owner, now| {
                    let exit = duties.turn(owner, now);
                    if commits.is_none() && duties.open == held && duties.lane.outstanding() == 1 {
                        owner.authority_event(Event::Withdraw(Cause::Unheld), now);
                        commits = Some(shard_commits(&store));
                    } else if late && commits.is_some() && duties.lane.outstanding() == 1 {
                        assert_eq!(
                            duties.open,
                            Open::Stopped,
                            "stopped before the completion lands"
                        );
                    }
                    if !late || commits.is_none() || duties.open == Open::Stopped {
                        duties.lane.inline_mut().release();
                    }
                    exit
                },
            );
            assert_eq!(served.exit, Exit::Stopped, "{held:?}");
            assert_eq!(duties.open, Open::Stopped, "{held:?} {late}");
            assert_eq!(Some(shard_commits(&store)), commits, "{held:?}");
            assert!(!duties.writing, "{held:?}: no shard-record job outstanding");
            let returned = matches!(duties.possible, super::Set::Here(_));
            assert_eq!(
                returned,
                held == Open::Confirming || !late,
                "{held:?} {late}"
            );
        });
    }
}

#[test]
fn a_regressed_view_withdraws_the_tenure() {
    staged(|mut stage| {
        let log = MemLog::default();
        let mut reader = Client::open(stage.store.clone(), log.clone()).unwrap();
        reader.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        let commits = shard_commits(&stage.store);
        let (mut duties, calls) = duties_with(&stage, log, volume_id(), bounds());
        stage.store.schedule(Arm::Pass);
        stage.store.schedule(Arm::StaleCurrentRead);
        let cause = Cell::new(None);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let exit = duties.turn(owner, now);
                cause.set(owner.authority_report().withdrawal);
                exit
            },
        );
        assert_eq!(served.exit, Exit::Rerun(Rerun::Withdrawn));
        assert_eq!(cause.get(), Some(Cause::Regression));
        assert_eq!(duties.open, Open::Stopped);
        assert_eq!(shard_commits(&stage.store), commits);
        assert_eq!(calls.borrow().len(), 2);
    });
}

/// A shard record of another store instance withdraws the lane's client at the View, and the tenure ends with the
/// record unwritten.
#[test]
fn a_view_of_another_namespace_ends_the_tenure() {
    staged(|mut stage| {
        rewrite::<ShardRecord>(&stage.store, Key::Shard(shard()), |record| ShardRecord {
            namespace: Namespace::new([0xee; 16]).unwrap(),
            ..record
        });
        let commits = shard_commits(&stage.store);
        let (mut duties, calls) = duties_with(&stage, MemLog::default(), volume_id(), bounds());
        assert_eq!(
            serve_turns(&mut stage, 300, |owner, now| duties.turn(owner, now)),
            Exit::Rerun(Rerun::Withdrawn),
            "the withdrawn client ends the tenure"
        );
        assert_eq!(duties.open, Open::Stopped);
        assert_eq!(shard_commits(&stage.store), commits);
        assert_eq!(calls.borrow().len(), 2, "the View's two reads alone");
    });
}

/// A completion that shows the client withdrawn ends the tenure when the open stopped while its job ran. The owner
/// withdraws with nobody holding, which keeps the tenure polling, before the completion lands: a View of another
/// namespace, then a Confirm whose watermark record fails.
#[test]
fn a_withdrawn_client_ends_the_tenure_after_the_open_stopped() {
    for held in [Open::Viewing, Open::Confirming] {
        staged(|mut stage| {
            if held == Open::Viewing {
                rewrite::<ShardRecord>(&stage.store, Key::Shard(shard()), |record| ShardRecord {
                    namespace: Namespace::new([0xee; 16]).unwrap(),
                    ..record
                });
            }
            let log = MemLog::default();
            let (mut duties, _) = duties_with(&stage, log.clone(), volume_id(), bounds());
            duties.lane.inline_mut().hold();
            let (mut withdrawn, cause) = (false, Cell::new(None));
            let exit = serve_turns(&mut stage, 300, |owner, now| {
                let exit = duties.turn(owner, now);
                if !withdrawn && duties.open == held && duties.lane.outstanding() == 1 {
                    owner.authority_event(Event::Withdraw(Cause::Unheld), now);
                    withdrawn = true;
                } else if (!withdrawn || duties.open == Open::Stopped)
                    && duties.lane.inline_mut().release()
                {
                    // The turn that adopts the View submits the Confirm.
                    log.fail.set(held == Open::Confirming);
                }
                cause.set(owner.authority_report().withdrawal);
                exit
            });
            assert!(withdrawn, "{held:?}");
            assert_eq!(exit, Exit::Rerun(Rerun::Withdrawn), "{held:?}");
            assert_eq!(cause.get(), Some(Cause::Unheld), "{held:?}");
            assert_eq!(duties.open, Open::Stopped, "{held:?}");
            assert_eq!(duties.lane.outstanding(), 0, "{held:?}");
        });
    }
}

#[test]
fn a_failed_watermark_record_stops_the_open() {
    staged(|mut stage| {
        let log = MemLog::default();
        let (mut duties, calls) = duties_with(&stage, log.clone(), volume_id(), bounds());
        duties.lane.inline_mut().hold();
        let before = shard_commits(&stage.store);
        let (mut first, mut jobs) = (None, 0);
        let (served, _) = stage.serve_until(
            |_, turn, stop| {
                if turn >= *first.get_or_insert(turn) + 300 {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                log.fail.set(duties.open == Open::Confirming);
                let exit = duties.turn(owner, now);
                jobs += usize::from(duties.lane.inline_mut().release());
                exit
            },
        );
        assert_eq!(
            served.exit,
            Exit::Rerun(Rerun::Withdrawn),
            "the withdrawn client ends the tenure"
        );
        assert_eq!(duties.open, Open::Stopped);
        assert_eq!(shard_commits(&stage.store) - before, 2);
        let writes: Vec<_> = (calls.borrow().iter())
            .filter(|(write, _)| *write)
            .cloned()
            .collect();
        assert_eq!(
            writes.len(),
            2,
            "the Confirm and the reservation: {writes:?}"
        );
        assert!(jobs >= 3, "the View, the Confirm and the Open");
    });
}

#[test]
fn a_lane_over_other_storage_stops_the_open_before_any_request() {
    staged(|mut stage| {
        let other = test_storage(1);
        let calls = Calls::over(&stage.store);
        let traced = Client::open(calls.recorder.clone(), MemLog::default()).unwrap();
        let lane = Lane::inline(traced, &other);
        let mut duties = duties_over(lane);
        let exit = serve_turns(&mut stage, 100, |owner, now| duties.turn(owner, now));
        assert_eq!(exit, Exit::Stopped);
        assert_eq!(duties.open, Open::Stopped);
        assert!(writes(&calls).is_empty(), "{:?}", calls.borrow());
        assert!(!log_open(stage.storage) && !log_open(&other));
    });
}

#[test]
fn a_stopped_open_leaves_the_certified_ends_with_the_owner() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut unbounded = bounds();
        unbounded.limits.queue_blocks = 0;
        let (mut duties, calls) = duties_with(&stage, MemLog::default(), volume_id(), unbounded);
        let mut ends = None;
        let exit = serve_turns(&mut stage, 50, |owner, now| {
            let exit = duties.turn(owner, now);
            if duties.open == Open::Stopped && ends.is_none() {
                ends = Some(owner.certified());
            }
            exit
        });
        assert_eq!(exit, Exit::Stopped);
        assert!(writes(&calls).is_empty());
        let ends = ends
            .flatten()
            .expect("the owner keeps the warm load's ends");
        assert_eq!(ends.len(), 1);
    });
}

#[test]
fn a_closed_owner_stops_the_open_before_its_next_write() {
    staged(|mut stage| {
        let (mut duties, calls) = inline_duties(&stage);
        let commits = shard_commits(&stage.store);
        let mut closed = false;
        let exit = serve_turns(&mut stage, 200, |owner, now| {
            let exit = duties.turn(owner, now);
            if !closed && duties.open == Open::Viewing && duties.lane.outstanding() == 1 {
                owner.close(now);
                closed = true;
            }
            duties.lane.inline_mut().release();
            exit
        });
        assert!(closed);
        assert_eq!(duties.open, Open::Stopped, "{exit:?}");
        assert!(writes(&calls).is_empty(), "no write");
        assert_eq!(shard_commits(&stage.store), commits);
    });
}

#[test]
fn a_lost_device_stops_the_open_before_its_next_write() {
    staged(|mut stage| {
        let (mut duties, calls) = inline_duties(&stage);
        let commits = shard_commits(&stage.store);
        let registry = stage.registry.clone();
        let (gone, mut set) = (Cell::new(false), false);
        let (mut released, mut authority) = (false, None);
        let (served, _) = stage.serve_until(
            |rounds, _, _| {
                if gone.get() && !set {
                    rounds.control.set_gone();
                    set = true;
                }
            },
            |owner, now| {
                if gone.get() && owner.lost() && !released {
                    authority = Some(owner.authority_report().state);
                    released = duties.lane.inline_mut().release();
                }
                let exit = duties.turn(owner, now);
                if !gone.get()
                    && duties.open == Open::Viewing
                    && duties.lane.inline_mut().held() == 1
                {
                    registry.borrow_mut().refuse = Some(crate::storage::RefusalReason::DeviceGone);
                    gone.set(true);
                }
                exit
            },
        );
        stage.registry.borrow_mut().refuse = None;
        assert_eq!(served.exit, Exit::Rerun(Rerun::ControllerEvent));
        assert!(released, "the View landed once the device was lost");
        assert_ne!(authority, Some(crate::failover::serving::State::Withdrawn));
        assert_eq!(duties.open, Open::Stopped);
        assert!(writes(&calls).is_empty(), "no write");
        assert_eq!(shard_commits(&stage.store), commits);
    });
}

/// The layout cases run on a cold tenure, where the floor and the delta region determine whether the View's layout
/// can open a log.
#[test]
fn a_view_with_an_unopenable_layout_or_manifest_stops_the_open_with_no_write() {
    for case in [
        "no delta block",
        "below the floor",
        "suffix without checkpoint",
    ] {
        let volume = match case {
            "suffix without checkpoint" => warm_volume_certified(1),
            _ => unnamed_volume(),
        };
        staged_over(volume, |mut stage| {
            let store = stage.store.clone();
            match case {
                "no delta block" => {
                    rewrite::<VolumeRecord>(&store, Key::Volume(volume_id()), |mut volume| {
                        volume.layout.units = 1 + u64::from(volume.layout.slots)
                            * u64::from(volume.layout.slot_units);
                        assert!(volume.layout.check_floor().is_ok());
                        volume
                    });
                }
                "below the floor" => {
                    rewrite::<VolumeRecord>(&store, Key::Volume(volume_id()), |mut volume| {
                        volume.layout.slots = 1;
                        assert!(volume.layout.check_floor().is_err());
                        volume
                    });
                }
                _ => rewrite::<ShardRecord>(&store, Key::Shard(shard()), |record| ShardRecord {
                    checkpoint: None,
                    cut: 0,
                    ..record
                }),
            }
            let commits = shard_commits(&store);
            let (mut duties, calls) = duties_with(&stage, MemLog::default(), volume_id(), bounds());
            let exit = serve_turns(&mut stage, 100, |owner, now| duties.turn(owner, now));
            match case {
                "below the floor" => {
                    assert!(matches!(exit, Exit::Retire(_)), "{case}: the poll retires")
                }
                _ => {
                    assert_eq!(exit, Exit::Stopped, "{case}");
                    assert_eq!(duties.open, Open::Stopped, "{case}");
                }
            }
            assert!(writes(&calls).is_empty(), "{case}");
            assert_eq!(shard_commits(&store), commits, "{case}");
        });
    }
}

#[test]
fn a_retry_view_with_another_layout_stops_the_open() {
    staged(|mut stage| {
        let store = stage.store.clone();
        let (mut duties, calls) = duties_with(&stage, MemLog::default(), volume_id(), bounds());
        store.schedule(Arm::Pass);
        store.schedule(Arm::Pass);
        store.schedule(Arm::Unavailable);
        let commits = shard_commits(&store);
        let mut changed = false;
        let mut was = Open::Due;
        let exit = serve_turns(&mut stage, 300, |owner, now| {
            let exit = duties.turn(owner, now);
            let returned = was == Open::Confirming && duties.open == Open::Viewing;
            was = duties.open;
            if !changed && returned {
                rewrite::<VolumeRecord>(&store, Key::Volume(volume_id()), |mut volume| {
                    volume.layout.units += 8;
                    volume
                });
                changed = true;
            }
            exit
        });
        assert_eq!(exit, Exit::Stopped);
        assert!(
            changed,
            "the Confirm failed and the open returned to its View"
        );
        assert_eq!(duties.open, Open::Stopped);
        assert_eq!(
            writes(&calls),
            [Key::Shard(shard())],
            "the failed Confirm alone"
        );
        assert_eq!(shard_commits(&store), commits);
    });
}

#[test]
fn a_first_view_with_another_layout_than_the_warm_load_read_stops_the_open() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let store = stage.store.clone();
        let storage = stage.storage;
        rewrite::<VolumeRecord>(&store, Key::Volume(volume_id()), |mut volume| {
            volume.layout.units += 8;
            assert!(volume.layout.check_floor().is_ok());
            volume
        });
        let commits = shard_commits(&store);
        let (mut duties, calls) = duties_with(&stage, MemLog::default(), volume_id(), bounds());
        let mut ends = None;
        let exit = serve_turns(&mut stage, 100, |owner, now| {
            let exit = duties.turn(owner, now);
            if duties.open == Open::Stopped && ends.is_none() {
                ends = Some(owner.certified());
            }
            exit
        });
        assert_eq!(exit, Exit::Stopped);
        assert_eq!(duties.open, Open::Stopped);
        assert_eq!(writes(&calls), [], "the View's reads alone");
        assert_eq!(shard_commits(&store), commits);
        assert!(!log_open(storage), "no log opens over the other layout");
        assert!(
            ends.flatten().is_some(),
            "the owner keeps the warm load's ends"
        );
    });
}

#[test]
fn a_write_of_unknown_outcome_retries_from_a_view_and_the_open_completes() {
    for (write, commit) in [(2, true), (2, false), (4, true), (4, false)] {
        staged_over(warm_volume_certified(0), |mut stage| {
            let store = stage.store.clone();
            let recorded = shard_now(&store).ancestry.as_slice()[0];
            for _ in 0..write {
                store.schedule(Arm::Pass);
            }
            store.schedule(Arm::Timeout { commit });
            let (mut duties, calls) = duties_with(&stage, MemLog::default(), volume_id(), bounds());
            let (mut views, mut failed) = (Vec::new(), None);
            let opened = Cell::new(false);
            let mut session = 0;
            let (served, _) = stage.serve_until(
                |_, _, stop| {
                    if opened.get() {
                        stop.store(true, Ordering::Release);
                    }
                },
                |owner, now| {
                    session = owner.tenure().get();
                    let from = calls.borrow().len();
                    let exit = duties.turn(owner, now);
                    if calls.borrow()[from..].contains(&(false, Key::Volume(volume_id()))) {
                        views.push(now);
                    }
                    if failed.is_none() && calls.borrow().len() > write {
                        failed = Some(now);
                    }
                    opened.set(duties.open == Open::Opened && log_open(stage.storage));
                    exit
                },
            );
            assert_eq!(served.exit, Exit::Stopped, "{write} {commit}");
            let failed = failed.unwrap();
            let retry = views.iter().find(|&&view| view > failed);
            assert!(
                retry.is_some(),
                "{write} {commit}: a later view retried the open: {views:?}"
            );
            let record = shard_now(&store);
            let chain = record.ancestry.as_slice();
            let own = chain
                .iter()
                .filter(|suffix| suffix.session == session)
                .count();
            assert_eq!(own, 1, "{write} {commit}: {chain:?}");
            let predecessor = chain
                .iter()
                .find(|suffix| suffix.session == recorded.session);
            assert_eq!(
                predecessor.unwrap().certified,
                recorded.end,
                "{write} {commit}"
            );
        });
    }
}

#[test]
fn a_record_that_names_no_checkpoint_ends_opened_with_the_log_closed() {
    staged_over(unnamed_volume(), |mut stage| {
        let before = shard_commits(&stage.store);
        let (mut duties, calls) = duties_with(&stage, MemLog::default(), volume_id(), bounds());
        let storage = stage.storage;
        let mut closed = None;
        let exit = serve_turns(&mut stage, 300, |owner, now| {
            let exit = duties.turn(owner, now);
            if duties.open == Open::Opened {
                closed = Some(storage.with_suffix(|log| log.is_open()));
            }
            exit
        });
        assert_eq!(exit, Exit::Stopped);
        assert_eq!(duties.open, Open::Opened);
        assert_eq!(
            closed,
            Some(Ok(false)),
            "the log stays closed while the owner serves"
        );
        assert_eq!(shard_commits(&stage.store) - before, 1, "the Confirm alone");
        assert_eq!(writes(&calls), [Key::Shard(shard())]);
    });
}

pub(super) fn on_the_lane_thread(store: &Locked) -> Result<usize, String> {
    let threads = store.threads();
    match threads
        .iter()
        .all(|thread| thread.as_deref() == Some("store-lane"))
    {
        true if !threads.is_empty() => Ok(threads.len()),
        _ => Err(format!("{threads:?}")),
    }
}

/// A store that sends on `entered` from the thread that issues a request, then holds the request until `release`
/// receives `()` or the last sender of `release` drops. The issuing thread panics if `release` stays connected and
/// receives no signal for `limit`.
struct Gated {
    inner: Locked,
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    limit: Duration,
}

impl Gated {
    fn hold(&self) {
        let _ = self.entered.send(());
        let held = self.release.recv_timeout(self.limit);
        assert_ne!(held, Err(mpsc::RecvTimeoutError::Timeout), "a held request");
    }
}

/// Serves GETs over `duties`, whose store is a [`Gated`] one that reports each request on `entries`, and stops once
/// `GETS` of them completed after the store's first request entered, dropping `release` to free the store. Returns
/// the tenure's exit, whether a store request entered, and the count of those GETs.
fn gets_while_held(
    stage: &mut Stage<'_>,
    (entries, release): (mpsc::Receiver<()>, mpsc::Sender<()>),
    duties: impl FnMut(&mut TestOwner<'_>, u64) -> Option<Exit>,
) -> (Exit, bool, usize) {
    let mut pump = Gets::default();
    let mut release = Some(release);
    let (mut holding, mut during) = (false, 0);
    let (served, _) = stage.serve_until(
        |rounds, _, stop| {
            holding = holding || entries.try_recv().is_ok();
            if pump.pump(rounds, stop) && holding {
                during += 1;
            }
            if during == GETS {
                release = None;
                stop.store(true, Ordering::Release);
            }
        },
        duties,
    );
    (served.exit, holding, during)
}

const GETS: usize = 6;

impl Store for Gated {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.hold();
        self.inner.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.hold();
        self.inner.write(key, write)
    }

    fn namespace(&self) -> Namespace {
        self.inner.namespace()
    }
}

/// STORE-OFF-POLL: the owner completes six GETs while the lane thread waits for release on its first store request.
/// Every recorded store request runs on a thread named `store-lane`.
#[test]
fn gets_are_answered_while_the_lane_holds_a_store_request() {
    staged(|mut stage| {
        let store = Locked::of(&stage.store);
        let storage = stage.storage;
        let (entered, entries) = mpsc::channel();
        let (release, held) = mpsc::channel();
        let gated = Gated {
            inner: store.clone(),
            entered,
            release: held,
            limit: Duration::from_secs(60),
        };
        std::thread::scope(|scope| {
            let lane = Lane::start(
                &HostGate::qualified(),
                scope,
                Client::open(gated, SharedLog::default()).unwrap(),
                storage,
                CpuSet::current().unwrap(),
            )
            .unwrap();
            let mut duties = duties_over(lane);
            let served = gets_while_held(&mut stage, (entries, release), |owner, now| {
                duties.turn(owner, now)
            });
            assert_eq!(served, (Exit::Stopped, true, GETS));
            drop(duties.end());
        });
        on_the_lane_thread(&store).unwrap();
    });
}

#[test]
fn a_threaded_lane_runs_the_whole_open_on_the_lane_thread() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let store = Locked::of(&stage.store);
        let storage = stage.storage;
        let opened = Cell::new(false);
        std::thread::scope(|scope| {
            let lane = Lane::start(
                &HostGate::qualified(),
                scope,
                locked_client(&store),
                storage,
                CpuSet::current().unwrap(),
            )
            .unwrap();
            let mut duties = duties_over(lane);
            let (served, _) = stage.serve_until(
                |_, _, stop| {
                    if opened.get() {
                        stop.store(true, Ordering::Release);
                    }
                },
                |owner, now| {
                    let exit = duties.turn(owner, now);
                    opened.set(
                        duties.open == Open::Opened
                            && match storage.with_suffix(|log| log.is_open()) {
                                Ok(open) => open,
                                Err(CaptureError::Unavailable) => opened.get(),
                                Err(error) => panic!("cannot observe suffix: {error:?}"),
                            },
                    );
                    exit
                },
            );
            assert_eq!(served.exit, Exit::Stopped);
            drop(duties.end());
        });
        assert!(opened.get(), "the log opened");
        let writes = (store.requests().into_iter())
            .filter(|request| request.write && request.key == Key::Shard(shard()))
            .count();
        assert_eq!(
            writes, 3,
            "the Confirm, the certification and the reservation"
        );
        on_the_lane_thread(&store).unwrap();
    });
}

/// Control for STORE-OFF-POLL: the run of `gets_are_answered_while_the_lane_holds_a_store_request` with the store
/// request issued on the owner thread. The request enters the store and stalls the owner's turn, so no GET completes
/// while the store holds it, and the turn unwinds at the hold limit in place of the stop the six GETs give.
#[test]
fn a_store_call_on_the_owner_thread_answers_no_get_while_the_store_holds_it() {
    staged(|mut stage| {
        let store = Locked::of(&stage.store);
        let (entered, entries) = mpsc::channel();
        let (release, held) = mpsc::channel();
        let gated = Gated {
            inner: store.clone(),
            entered,
            release: held,
            limit: Duration::from_millis(50),
        };
        let mut client = Client::open(gated, SharedLog::default()).unwrap();
        let served = gets_while_held(&mut stage, (entries, release), |_, _| {
            let _ = client.read::<ShardRecord>(Key::Shard(shard()));
            None
        });
        assert_eq!(served, (Exit::Rerun(Rerun::Unwound), true, 0));
        assert!(
            store.requests().is_empty(),
            "the hold limit ended the request"
        );
    });
}

thread_local! {
    pub(super) static SNAPSHOT_AFTER_READS: Cell<bool> = const { Cell::new(false) };
    /// The planted control of READ-ORDER's bound on the last binding: a view whose volume read fails judges every
    /// listing, a later one included, against the binding of the last volume record.
    pub(super) static UNBOUNDED_BINDING: Cell<bool> = const { Cell::new(false) };
}

pub(super) fn planted() -> bool {
    SNAPSHOT_AFTER_READS.with(Cell::get)
}

pub(super) fn unbounded() -> bool {
    UNBOUNDED_BINDING.with(Cell::get)
}

/// Whether a planted control that a turn of the serving duties reaches with no capture policy and no planned exit
/// is set on this thread: the view's snapshot after its reads, the unbounded last binding, a zeroed observation of
/// the duties' status, the default signal of a step that sampled none, the unguarded drop of ended pairs, or the
/// open that stops on a refused suffix reservation.
pub(crate) fn armed() -> bool {
    planted()
        || unbounded()
        || super::status::ZEROED.with(Cell::get).is_some()
        || super::step_tests::default_signal()
        || super::reclaim_tests::unguarded()
        || super::roll_tests::stopped_open()
}

/// [`armed`] reads each planted control a [`Duties::turn`] reaches with no capture policy: this module's two, a
/// zeroed status, the default signal of a step that sampled none, the unguarded drop and the stopped open.
#[test]
fn armed_reads_each_planted_control_a_turn_with_no_capture_policy_reaches() {
    use super::status::{ZEROED, Zeroed};
    /// A plant's name and its switch.
    type Switch = (&'static str, fn(bool));
    let plants: [Switch; 6] = [
        ("the snapshot after the reads", |on| {
            SNAPSHOT_AFTER_READS.with(|plant| plant.set(on));
        }),
        ("the unbounded binding", |on| {
            UNBOUNDED_BINDING.with(|plant| plant.set(on));
        }),
        ("a zeroed status", |on| {
            ZEROED.with(|plant| plant.set(on.then_some(Zeroed::Store)));
        }),
        ("the default signal", |on| {
            super::step_tests::DEFAULT_SIGNAL.with(|plant| plant.set(on));
        }),
        ("the unguarded drop", |on| {
            super::reclaim_tests::UNGUARDED.with(|plant| plant.set(on));
        }),
        ("the stopped open", |on| {
            super::roll_tests::STOPPED_OPEN.with(|plant| plant.set(on));
        }),
    ];
    assert!(!armed(), "no plant is set");
    for (name, set) in plants {
        set(true);
        let read = armed();
        set(false);
        assert!(read, "{name}");
        assert!(!armed(), "{name} cleared");
    }
}
