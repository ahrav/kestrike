use std::cell::{Cell, RefCell};
use std::collections::btree_map::Entry;
use std::num::NonZeroU64;
use std::rc::Rc;
use std::sync::atomic::Ordering;

use super::capture::{Pass, Unit, nanos};
use super::capture_tests::{
    CaptureDuties, Unanswered, capture_duties_under, policy_bounded, policy_every, published,
    replaced, shard_record,
};
use super::tests::{Filling, records};
use super::view_tests::{Events, Listing};
use super::{Duties, Open};
use crate::failover::records::NamedCheckpoint;
use crate::failover::records::ShardRecord;
use crate::failover::report::Observed;
use crate::failover::serving::{Cause, Event, State};
use crate::host::duties::tests::TEST_VIEW_US as VIEW_US;
use crate::host::lane::tests::bounds;
use crate::host::lane::{Lane, Plane};
use crate::host::serve::loop_tests::{
    ROUND_US, Rounds, Stage, TestOwner, staged_fresh, staged_over,
};
use crate::host::serve::tests::content;
use crate::host::serve::tests::warm_volume_certified;
use crate::host::{Exit, HostGate, Rerun};
use crate::net::{Outcome as Fetched, RequestId, SessionState};
use crate::storage::checkpoint::{
    PlacementRefusal, ReserveRefusal, StageRefusal, SuffixBounds, SuffixDue, WriteRefused,
};
use crate::storage::device::sim::Media;
use crate::storage::owner_fixture::{set_clock, try_reserve_at};
use crate::storage::page_coverage::Interval;
use crate::storage::store::sim::Arm;
use crate::storage::store::sim::{MemLog, Shared};
use crate::storage::store::{Client, Key, StoreError, Version};
use crate::storage::store_tests::shard;
use crate::storage::test_platform::TestPlatform;
use crate::storage::warm_sim::{layout, object_key, region};
use crate::storage::{
    CacheVersion, CapturePolicy, EngineBudget, FillPublishError, InvalidateError, Storage,
    SuffixRefusal, WorkBudget,
};

/// `NEVER` puts the time ceiling beyond the test duration, so only a due publication starts a capture pass.
pub(super) const NEVER: u64 = 1 << 60;

/// The fixture's step period, half the view period.
pub(super) const STEP_US: u64 = VIEW_US / 2;

/// Feeds and publishes one FILL of object `n` with `payload`. `None` while the fill is pending, and `None` with
/// `filling` left empty when the storage refused the fill's begin or its reservation.
pub(super) fn fill<'w>(
    owner: &mut TestOwner<'w>,
    storage: &'w Storage<TestPlatform>,
    filling: &mut Filling<'w>,
    (n, payload): (u8, &[u8]),
) -> Option<Result<(), FillPublishError>> {
    if filling.is_none() {
        let fill = try_reserve_at(storage, &object_key(n), 4, 40)?;
        *filling = Some((fill, 0));
    }
    let (fill, taken) = filling.as_mut()?;
    if !owner.fill_progress(fill).is_ready() {
        let mut budget = WorkBudget::with_io(0, usize::MAX, usize::MAX);
        if *taken < payload.len()
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

/// `Churn` appends a FILL and an INVALIDATE to the suffix for each key before advancing to the next key. A FILL
/// whose publish the storage refuses moves to the next key too; `refused` counts those refusals and `refusing` the
/// run of them since the last FILL that published. A refused begin or reservation moves to the next key uncounted.
pub(super) struct Churn<'w> {
    key: u8,
    filling: Filling<'w>,
    pub(super) refused: Vec<FillPublishError>,
    pub(super) refusing: u32,
    /// The key of the last FILL whose publish the storage refused.
    pub(super) refused_key: Option<u8>,
}

impl<'w> Churn<'w> {
    pub(super) fn new() -> Self {
        Self {
            key: 11,
            filling: None,
            refused: Vec::new(),
            refusing: 0,
            refused_key: None,
        }
    }

    fn next(&mut self) {
        self.key = if self.key == 60 { 11 } else { self.key + 1 };
    }

    /// Runs one step at turn time `now`, whose nanoseconds the storage's clock reads, so the suffix's open block
    /// seals once its flush interval passed.
    pub(super) fn step(
        &mut self,
        owner: &mut TestOwner<'w>,
        storage: &'w Storage<TestPlatform>,
        now: u64,
    ) {
        set_clock(storage, &[Some(nanos(now))]);
        // The fixture's owner runs no fill service, so the churn returns departed fill records to Free itself.
        for shard in 0..2 {
            let mut budget = WorkBudget::new(1 << 12);
            let _ = storage.service_fills(crate::index::ShardIndex(shard), 2, &mut budget);
        }
        match fill(
            owner,
            storage,
            &mut self.filling,
            (self.key, &content(self.key, self.key)),
        ) {
            None if self.filling.is_none() => self.next(),
            None => {}
            Some(Ok(())) => {
                let mut budget = WorkBudget::new(1 << 20);
                let removed = owner.invalidate(&object_key(self.key), 4, &mut budget);
                assert!(removed.is_ok(), "{removed:?}");
                self.refusing = 0;
                self.next();
            }
            Some(Err(refused)) => {
                self.refused.push(refused);
                self.refused_key = Some(self.key);
                self.refusing += 1;
                self.next();
            }
        }
    }
}

/// The fixture's suffix bounds: once the head lies within 3 blocks of the reserved end, a step records a reserved
/// end up to 8 blocks past the head, at most the capacity.
pub(super) fn wide() -> SuffixBounds {
    SuffixBounds {
        step: 8,
        margin: 3,
        ..bounds()
    }
}

fn step_duties_every<'w>(
    stage: &Stage<'w>,
    policy: Option<CapturePolicy>,
    step_us: u64,
) -> CaptureDuties<'w> {
    step_duties_on(stage, stage.store.clone(), policy, step_us)
}

/// [`step_duties`] whose lane reaches the stage's store through `store`, with a step period of `step_us`.
pub(super) fn step_duties_on<'w, S: crate::storage::store::Store>(
    stage: &Stage<'w>,
    store: S,
    policy: Option<CapturePolicy>,
    step_us: u64,
) -> Duties<'w, S, MemLog, TestPlatform> {
    let client = Client::open(store, MemLog::default()).unwrap();
    let duties = Duties::new(
        (
            &HostGate::qualified(),
            crate::failover::reconcile::StandbyGate::qualified(),
        ),
        Lane::inline(client, stage.storage),
        records(),
        None,
        wide(),
        super::tests::periods().with_step(NonZeroU64::new(step_us).unwrap()),
    );
    match policy {
        Some(policy) => duties.capturing(policy, EngineBudget::unlimited()).unwrap(),
        None => duties,
    }
}

pub(super) fn step_duties<'w>(
    stage: &Stage<'w>,
    policy: Option<CapturePolicy>,
) -> CaptureDuties<'w> {
    step_duties_every(stage, policy, STEP_US)
}

/// [`step_duties`] of `host`'s owner process.
pub(super) fn step_duties_for<'w>(
    stage: &Stage<'w>,
    policy: Option<CapturePolicy>,
    host: crate::failover::records::Host,
) -> CaptureDuties<'w> {
    let mut duties = step_duties(stage, policy);
    duties.records = super::tests::records_for(host);
    duties
}

/// The capture counter and slot of the pass's stage while it writes or proves.
fn pass_stage(duties: &CaptureDuties<'_>) -> Option<(u32, u32)> {
    match &duties.capture.as_ref()?.pass {
        Pass::Writing {
            counter, staged, ..
        }
        | Pass::Proving { counter, staged } => Some((*counter, staged.slot())),
        _ => None,
    }
}

fn idle(duties: &CaptureDuties<'_>) -> bool {
    matches!(duties.capture.as_ref().unwrap().pass, Pass::Idle)
}

#[derive(Default)]
struct Gets {
    pending: Option<(RequestId, Vec<u8>)>,
    served: u64,
}

impl Gets {
    fn step(&mut self, rounds: &Rounds<'_>, from: bool) {
        let active = rounds.client.borrow().state() == SessionState::Active;
        if from && active && self.pending.is_none() {
            self.pending = Some((rounds.get(1), Vec::new()));
        }
        if let Some((id, bytes)) = self.pending.as_mut()
            && let Some(outcome) = rounds.fetched(*id, bytes)
        {
            assert_eq!(outcome, Fetched::Complete);
            self.served += 1;
            self.pending = None;
        }
    }
}

/// Each step period submits one suffix step: on the fixture's 100 µs turns a 1,250 µs period submits one every
/// 1,300 µs. After every turn the log's reserved and certified ends lie at or below the ends the store committed
/// for the tenure's suffix, and the tenure's mutations moved both ends up.
#[test]
fn one_step_a_period_records_the_ends_in_the_store_before_the_log_admits_past_them() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, None);
        let storage = stage.storage;
        let store = stage.store.clone();
        let mut churn = Churn::new();
        let mut submitted = Vec::new();
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let at = duties.step_at;
                let exit = duties.turn(owner, now);
                if duties.open != Open::Opened {
                    return exit;
                }
                if duties.step_at != at {
                    submitted.push(now);
                }
                churn.step(owner, storage, now);
                let session = owner.tenure().get();
                let recorded = *shard_record(&store)
                    .ancestry
                    .as_slice()
                    .iter()
                    .rfind(|suffix| suffix.session == session)
                    .expect("the tenure recorded its suffix");
                let log = storage.with_suffix(|log| log.recorded()).unwrap();
                assert!(log.end <= recorded.end, "{log:?} past {recorded:?}");
                assert!(
                    log.certified <= recorded.certified,
                    "{log:?} past {recorded:?}"
                );
                ended.set(recorded.certified > recorded.start + 8 && submitted.len() >= 8);
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(
            (churn.refused.iter()).all(|refused| *refused == FillPublishError::History),
            "{:?}",
            churn.refused
        );
        let realized = STEP_US.next_multiple_of(ROUND_US);
        assert!(submitted.len() >= 8, "{submitted:?}");
        for pair in submitted.windows(2) {
            assert_eq!(
                pair[1] - pair[0],
                realized,
                "one step each step period: {submitted:?}"
            );
        }
    });
}

/// A due step waits while the lane holds a page job: an INVALIDATE held on the turn a step is due sends its page job
/// first, and the step goes out on a later turn, so a page job stays the lane's one outstanding job.
#[test]
fn a_due_step_waits_for_the_adoption_of_a_page_job() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, None);
        let mut invalidated = None;
        let mut paged_while_due = false;
        let mut stepped_after = false;
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let due =
                    duties.open == Open::Opened && now >= duties.step_at && duties.read.is_some();
                if invalidated.is_none() && due && duties.lane.outstanding() == 0 {
                    let mut budget = WorkBudget::new(1 << 20);
                    let interval = Interval::new(CacheVersion(3), CacheVersion(5)).unwrap();
                    let held = owner.invalidate_interval(&object_key(4), interval, 2, &mut budget);
                    invalidated = Some(held.is_ok());
                }
                let at = duties.step_at;
                let exit = duties.turn(owner, now);
                assert!(
                    !duties.paging || duties.lane.outstanding() == 1,
                    "a page job beside another unadopted job"
                );
                paged_while_due |= duties.paging && invalidated.is_some() && duties.step_at == at;
                stepped_after |= paged_while_due && duties.step_at != at;
                ended.set(stepped_after);
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(invalidated, Some(true));
        assert!(paged_while_due, "the page job went out before the step");
    });
}

/// A due step waits for an idle lane: a listing due on the turn a step is due goes out first, and the step stays
/// unsubmitted while the listing's completion is unadopted, so a step is the lane's one outstanding job at its
/// submit. The step goes out once the listing is adopted.
#[test]
fn a_due_step_waits_for_the_adoption_of_a_listing() {
    const WINDOW_US: u64 = 8 * ROUND_US;
    staged_over(warm_volume_certified(0), |mut stage| {
        let client = Client::open(stage.store.clone(), MemLog::default()).unwrap();
        let mut duties = Duties::new(
            (
                &HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            Lane::inline(client, stage.storage),
            records(),
            Some(Plane(Box::new(Listing::new(&Events::default())))),
            wide(),
            super::tests::periods().with_step(NonZeroU64::new(STEP_US).unwrap()),
        );
        let mut listing = None;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let named =
                    (duties.read.as_ref()).is_some_and(|read| read.value().checkpoint.is_some());
                let due = duties.open == Open::Opened
                    && named
                    && duties.plane.is_some()
                    && duties.lane.outstanding() == 0
                    && now >= duties.step_at
                    && now + 2 * WINDOW_US < duties.view_at;
                if listing.is_none() && due {
                    duties.listing_at = now;
                    duties.lane.inline_mut().hold();
                    listing = Some((now, duties.step_at));
                }
                let exit = duties.turn(owner, now);
                assert!(
                    !duties.stepping || duties.lane.outstanding() == 1,
                    "a step beside another unadopted job"
                );
                let Some((at, step_at)) = listing else {
                    return exit;
                };
                if now >= at + WINDOW_US {
                    while duties.lane.inline_mut().release() {}
                }
                if duties.plane.is_none() {
                    assert_eq!(
                        duties.step_at, step_at,
                        "a step went out beside an unadopted listing"
                    );
                } else if duties.step_at != step_at {
                    assert!(duties.stepping, "the step went out after the listing");
                    return Some(Exit::Stopped);
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(
            listing.is_some(),
            "a listing and a step fell due on one turn"
        );
    });
}

/// A step that signals a due publication starts a capture pass by the next turn under a policy that is not due, and
/// every later start follows a step adopted since the last Publish that signalled one. The tenure's mutations then
/// reach the handoff margin, which sets `roll_due` with no exit; hits keep being served, and the log refuses a FILL
/// at the tenure's bound.
#[test]
fn a_due_publication_starts_a_pass_and_the_handoff_sets_roll_due_while_hits_are_served() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, Some(policy_every(NEVER)));
        let storage = stage.storage;
        let mut churn = Churn::new();
        let mut gets = Gets::default();
        let (mut due_at, mut started_at, mut rolled) = (None, None, None::<u64>);
        let (mut was_idle, mut fresh_due, mut seen_published, mut starts) = (true, false, 0, 0);
        let ended = Cell::new(false);
        let mut turn = 0;
        let mut bound = None;
        let mut at_bound = None;
        let (served, _) = stage.serve_until(
            |rounds, _, stop| {
                gets.step(rounds, ended.get());
                if ended.get() && gets.served >= 3 {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                turn += 1;
                let (was_stepping, at) = (duties.stepping, duties.step_at);
                let exit = duties.turn(owner, now);
                assert_eq!(exit, None, "the bound raises no exit");
                if duties.open != Open::Opened {
                    return exit;
                }
                churn.step(owner, storage, now);
                // A turn adopts at most one completion: a Publish, or the step that held the set.
                let adopted = was_stepping && (!duties.stepping || duties.step_at != at);
                if published(&duties) != seen_published {
                    (seen_published, fresh_due) = (published(&duties), false);
                } else if adopted {
                    fresh_due |= duties.suffix_due().is_some_and(|due| due.publication);
                }
                if duties.suffix_due().is_some_and(|due| due.publication) && due_at.is_none() {
                    due_at = Some(turn);
                }
                let idle = idle(&duties);
                if was_idle && !idle {
                    starts += 1;
                    assert!(
                        fresh_due,
                        "a pass starts only on a publication due since the last Publish"
                    );
                }
                was_idle = idle;
                if due_at.is_some() && !idle && started_at.is_none() {
                    started_at = Some(turn);
                }
                if duties.roll_due() && rolled.is_none() {
                    assert!(duties.suffix_due().is_some_and(|due| due.handoff));
                    rolled = Some(turn);
                }
                let recorded = storage.with_suffix(|log| log.recorded()).unwrap();
                let head = storage.with_suffix(|log| log.head()).unwrap();
                bound = Some((head, recorded.start));
                let bounded = rolled.is_some() && churn.refusing >= 4;
                if bounded && head == recorded.start + region() && at_bound.is_none() {
                    let mut budget = WorkBudget::new(1 << 20);
                    let removal = owner.invalidate(&object_key(1), 4, &mut budget);
                    at_bound = Some((storage.probe_append(nanos(now)), removal.err()));
                }
                ended.set(at_bound.is_some());
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let (due_at, started_at) = (due_at.unwrap(), started_at.unwrap());
        assert!(starts >= 1);
        assert!(
            started_at <= due_at + 1,
            "the pass started by the next turn"
        );
        assert!(rolled.is_some(), "the handoff set roll_due");
        assert_eq!(churn.refused.last(), Some(&FillPublishError::History));
        let (appended, removal) = at_bound.expect("the log reached the bound");
        assert_eq!(
            appended,
            Some(Err(SuffixRefusal::Exhausted)),
            "the log refuses at the bound"
        );
        assert_eq!(
            removal,
            Some(InvalidateError::History),
            "an INVALIDATE refuses at the bound"
        );
        let (head, start) = bound.unwrap();
        assert!(
            published(&duties) >= 1,
            "a settled Publish raised the capacity"
        );
        assert_eq!(
            head,
            start + region(),
            "the log stopped at the tenure's bound of J blocks"
        );
        assert!(gets.served >= 3, "hits are served at the bound");
    });
}

/// QuarantineUntilBarrier: the tenure's passes publish into every checkpoint slot in turn. The start that follows
/// is refused with `roll_due` set, the tenure keeps serving, and each capture staged a slot no other capture of the
/// tenure staged.
#[test]
fn a_tenure_that_used_every_checkpoint_slot_sets_roll_due_and_reuses_no_slot() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = capture_duties_under(&stage, policy_every(1_000_000));
        let mut slots = Vec::new();
        let mut stagers = std::collections::BTreeMap::new();
        let mut gets = Gets::default();
        let rolled = Cell::new(false);
        let (served, _) = stage.serve_until(
            |rounds, _, stop| {
                gets.step(rounds, rolled.get());
                if gets.served >= 3 {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                assert_eq!(exit, None);
                if let Some((counter, slot)) = pass_stage(&duties) {
                    match stagers.entry(slot) {
                        Entry::Vacant(stager) => {
                            stager.insert(counter);
                            slots.push(slot);
                        }
                        Entry::Occupied(stager) => {
                            assert_eq!(*stager.get(), counter, "slot {slot} staged by two captures")
                        }
                    }
                }
                rolled.set(duties.roll_due());
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(duties.roll_due());
        assert!(!duties.suffix_due().is_some_and(|due| due.handoff));
        assert!(duties.captures().refused >= Some(1));
        assert_eq!(
            slots.len(),
            layout().slots as usize,
            "the passes used every slot: {slots:?}"
        );
        assert_eq!(
            published(&duties),
            slots.len() as u64,
            "each staged slot took a committed Publish"
        );
    });
}

/// What a planted stage refusal left: `roll_due` and the refused count on the turn of the plant, the turn time the
/// refused pass ended, and the turn time the next pass started.
struct Planted {
    roll_due: bool,
    refused: Option<u64>,
    ended_at: u64,
    restarted_at: u64,
}

/// Plants `refusal` as a pass's refused stage on an opened tenure under a policy that is never due, then
/// serves until the next pass starts and three GETs completed. With `serving`, the refused pass served a publication
/// due at its start; otherwise the publication comes due on the turn of the plant, while the pass ends.
fn planted_stage(refusal: StageRefusal, serving: bool) -> Planted {
    let mut planted = None;
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, Some(policy_every(NEVER)));
        let mut gets = Gets::default();
        let (mut plant, mut ended_at, mut restarted_at) = (None, None, None);
        let refused = Cell::new(false);
        let (served, _) = stage.serve_until(
            |rounds, _, stop| {
                gets.step(rounds, refused.get());
                if gets.served >= 3 && refused.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let idle = idle(&duties);
                if plant.is_some() {
                    match (ended_at, idle) {
                        (None, true) => ended_at = Some(now),
                        (Some(_), false) if restarted_at.is_none() => restarted_at = Some(now),
                        _ => {}
                    }
                    refused.set(restarted_at.is_some());
                    return exit;
                }
                if duties.open == Open::Opened && !duties.writing && idle {
                    assert!(
                        !duties.roll_due(),
                        "the tenure is inside its bounds before the plant"
                    );
                    let capture = duties.capture.as_mut().unwrap();
                    (capture.publish_due, capture.serving_due) = (serving, serving);
                    let next = duties.stage_refused(1, refusal);
                    let capture = duties.capture.as_mut().unwrap();
                    (capture.pass, capture.publish_due) = (next, true);
                    plant = Some((duties.roll_due(), duties.captures().refused));
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let (roll_due, refused) = plant.unwrap();
        planted = Some(Planted {
            roll_due,
            refused,
            ended_at: ended_at.unwrap(),
            restarted_at: restarted_at.unwrap(),
        });
    });
    planted.unwrap()
}

/// A stage refused for placement, planted as the pass's refused stage, sets `roll_due` and counts a refused
/// stage; the tenure keeps serving, and the publication still due starts the next pass one view period after the
/// refused one ended.
#[test]
fn a_stage_refused_for_placement_sets_roll_due_and_the_tenure_keeps_serving() {
    let placement = PlacementRefusal::Entries {
        entries: 100,
        cap: 82,
    };
    let planted = planted_stage(
        StageRefusal::Reserve(ReserveRefusal::Placement(placement)),
        true,
    );
    assert!(planted.roll_due);
    assert_eq!(planted.refused, Some(1));
    assert!(
        planted.restarted_at >= planted.ended_at + VIEW_US,
        "the next pass waited one view period"
    );
}

/// A stage refused for memory counts a refused stage and does not set `roll_due`.
#[test]
fn a_stage_refused_for_memory_leaves_roll_due_clear() {
    let planted = planted_stage(StageRefusal::Memory, true);
    assert!(!planted.roll_due);
    assert_eq!(planted.refused, Some(1));
    assert!(
        planted.restarted_at >= planted.ended_at + VIEW_US,
        "the next pass waited one view period"
    );
}

/// A publication that comes due while a refused pass ends was not served by that pass, so the next pass starts on
/// the turn after it ended.
#[test]
fn a_publication_due_during_a_refused_pass_starts_the_next_pass_at_once() {
    let planted = planted_stage(StageRefusal::Memory, false);
    assert_eq!(
        planted.restarted_at,
        planted.ended_at + ROUND_US,
        "the next pass started on the next turn"
    );
}

/// A capture start refused for a reason other than a full slot pool counts a refused start and does not set
/// `roll_due`.
#[test]
fn a_start_refused_past_the_slot_bound_leaves_roll_due_clear() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = capture_duties_under(&stage, policy_bounded(1_000, 1));
        let (mut turns, mut free) = (0, false);
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                assert!(!duties.roll_due(), "roll_due is clear before the refusal");
                let exit = duties.turn(owner, now);
                free |= matches!(duties.possible, super::Set::Here(ref set) if set.free_slot().is_some());
                turns += 1;
                ended.set(duties.captures().refused >= Some(1) || turns > 3_000);
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(free, "a checkpoint slot was free");
        assert!(duties.captures().refused >= Some(1), "a start was refused");
        assert!(idle(&duties));
        assert!(!duties.roll_due());
    });
}

/// What a due step left when `writing` was planted clear beside a job that holds the set on the lane: whether the
/// step went out, the lane's outstanding jobs, and whether the set is on the owner thread.
type Beside = (bool, usize, bool);

/// Calls `step` on duties whose lane holds a job's completion, with `writing` planted clear.
fn step_beside(duties: &mut CaptureDuties<'_>, owner: &TestOwner<'_>, now: u64) -> Beside {
    let at = duties.step_at;
    duties.writing = false;
    duties.step(owner, now + VIEW_US);
    let submitted = duties.stepping || duties.step_at != at;
    (submitted, duties.lane.outstanding(), duties.set_here())
}

/// With `writing` planted clear while a Publish holds the set on the lane, a due step waits for the idle lane: it
/// submits nothing and leaves the set with the Publish.
#[test]
fn a_step_due_beside_an_outstanding_publish_waits_for_the_idle_lane() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = capture_duties_under(&stage, policy_every(1_000_000));
        duties.lane.inline_mut().hold();
        let mut left = None;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let exit = duties.turn(owner, now);
                let publishing = matches!(
                    duties.capture.as_ref().unwrap().pass,
                    Pass::Publishing { .. }
                );
                if !publishing {
                    duties.lane.inline_mut().release();
                    return exit;
                }
                left = Some(step_beside(&mut duties, owner, now));
                Some(Exit::Stopped)
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(left, Some((false, 1, false)));
    });
}

/// Control for PossNamedCoversStore, planted: a step that goes out on an idle lane while the set is away fails the
/// single-holder check.
#[test]
fn a_step_over_a_set_that_is_away_fails_the_single_holder_check() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, None);
        let mut failure = None;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let exit = duties.turn(owner, now);
                let named =
                    (duties.read.as_ref()).is_some_and(|read| read.value().checkpoint.is_some());
                let idle = duties.lane.outstanding() == 0 && duties.set_here();
                if !(duties.open == Open::Opened && named && idle) {
                    return exit;
                }
                let away = duties.take_set();
                let planted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    duties.step(owner, now + VIEW_US);
                }));
                duties.returned(away);
                failure = planted
                    .err()
                    .and_then(|panic| panic.downcast::<&str>().ok());
                Some(Exit::Stopped)
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let failure = failure.expect("the planted step fails");
        assert!(failure.starts_with("PossNamedCoversStore"), "{failure}");
    });
}

/// The seeded cycles' choices: the state starts at `m ^ (m >> 31)` with its low bit set, for the wrapping product
/// `m = (seed ^ 0x9e37_79b9_7f4a_7c15) * 0xbf58_476d_1ce4_e5b9`; each draw advances an xorshift64 step (shifts 13, 7,
/// 17) and returns `state % below`. A change to the constants or the draw sites remaps every seed, and the identity
/// each seed line prints changes with it.
pub(super) struct Choices(u64);

impl Choices {
    pub(super) fn of(seed: u64) -> Self {
        let mixed = (seed ^ 0x9e37_79b9_7f4a_7c15).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        Self((mixed ^ (mixed >> 31)) | 1)
    }

    pub(super) fn next(&mut self, below: u64) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x % below
    }
}

/// The object keys the seeded cycles check, fill and invalidate: the warm volume's objects 1 to 4 and 5 to 12.
const KEYS: std::ops::RangeInclusive<u8> = 1..=12;

/// The turns one cycle may take before it reports a stall, below the stage's round bound.
const CYCLE_TURNS: u64 = 15_000;

pub(super) type Held = std::collections::BTreeMap<u8, Vec<u8>>;

/// The counts one seed's cycles reach, and an FNV-1a digest of the objects every cycle held at its end.
pub(super) struct Reached {
    pub(super) publications: u64,
    pub(super) fills: u64,
    pub(super) removals: u64,
    pub(super) checks: u64,
    /// The cycles whose stop left the record a certified suffix block above its cut that the next cycle loaded.
    pub(super) suffix_loads: u64,
    pub(super) identity: u64,
}

impl Default for Reached {
    fn default() -> Self {
        Self {
            publications: 0,
            fills: 0,
            removals: 0,
            checks: 0,
            suffix_loads: 0,
            identity: 0xcbf2_9ce4_8422_2325,
        }
    }
}

impl Reached {
    fn fold(&mut self, held: &Held) {
        for (key, bytes) in held {
            for byte in std::iter::once(key).chain(bytes) {
                self.identity = (self.identity ^ u64::from(*byte)).wrapping_mul(0x100_0000_01b3);
            }
        }
    }
}

/// The bytes the `fill`th FILL of the seed writes for object `n`: the key's metadata prefix, then a body that opens
/// with `0xa5`, a byte no warm object's body holds, and carries the fill number, so a refill differs from the warm
/// object and from the key's earlier fills.
fn versioned(n: u8, fill: u64) -> Vec<u8> {
    let mut body = [0xa5; 40];
    body[1..9].copy_from_slice(&fill.to_le_bytes());
    [&object_key(n)[..4], &body[..]].concat()
}

/// What one cycle left: the volume, the checkpoint the record names at the end, and whether the record holds a
/// certified suffix block above its cut.
pub(super) type Cycled = ((Shared, Media), Option<NamedCheckpoint>, bool);

/// One restart cycle over `volume`: the tenure first checks that every object of `held` serves exactly its bytes and
/// every other key of [`KEYS`] answers missing, then fills and invalidates under the seed's choices, publishes,
/// mutates again into the suffix, and stops once its suffix is durable. A FILL whose begin or reservation the
/// storage refuses, of any kind, and a FILL publish or an INVALIDATE the suffix refuses `History` draw the next
/// mutation uncounted; any other publish or INVALIDATE refusal, and an INVALIDATE of a held object that removes
/// nothing, fails the cycle; in a rolling cycle a FILL publish or an INVALIDATE the owner's drain refuses `Closed`
/// also draws the next mutation uncounted. `held` then holds the objects the tenure's published FILLs wrote and its
/// INVALIDATEs left, as the owner's index removed them.
pub(super) fn cycle(
    volume: (Shared, Media),
    held: &mut Held,
    choices: &mut Choices,
    reached: &mut Reached,
) -> Result<Cycled, String> {
    run_cycle(volume, held, choices, reached, None)
}

/// [`cycle`] whose tenure, with `roll` set, rolls instead: it mutates until the roll that `roll` raises ends the
/// tenure with [`Rerun::Planned`](crate::host::Rerun::Planned).
pub(super) fn run_cycle(
    volume: (Shared, Media),
    held: &mut Held,
    choices: &mut Choices,
    reached: &mut Reached,
    roll: Option<super::roll_tests::Trigger>,
) -> Result<Cycled, String> {
    let as_owner = crate::host::recover_tests::Identity::owner();
    let registry = crate::host::recover_tests::own_holds();
    run_cycle_as((as_owner, registry), volume, (held, choices, reached), roll)
}

/// [`run_cycle`] by the host `identity` names, over the reservation table `registry`, which the cycle leaves as its
/// tenure left it.
pub(super) fn run_cycle_as(
    (identity, registry): (
        crate::host::recover_tests::Identity,
        crate::storage::gate_fixture::Control,
    ),
    volume: (Shared, Media),
    (held, choices, reached): (&mut Held, &mut Choices, &mut Reached),
    roll: Option<super::roll_tests::Trigger>,
) -> Result<Cycled, String> {
    use super::roll_tests::Trigger;
    let requested = matches!(
        roll,
        Some(Trigger::Transfer | Trigger::Requested | Trigger::RequestedClosed)
    );
    crate::host::serve::loop_tests::staged_restart_as(identity, (volume, registry), |mut stage| {
        let policy = roll.map_or(1_000_000, Trigger::period);
        let mut duties = step_duties_for(&stage, Some(policy_every(policy)), identity.host);
        if roll.is_some_and(|roll| roll != Trigger::Abrupt && roll != Trigger::RequestedClosed) {
            duties = duties.rolling(super::roll_tests::deadline());
        }
        if requested {
            duties = duties.requesting(super::transfer_tests::key(), super::roll_tests::deadline());
        }
        let mut planted = false;
        let storage = stage.storage;
        let keys: Vec<u8> = KEYS.collect();
        let mut checked = 0;
        let mut pending: Option<(u8, RequestId, Vec<u8>)> = None;
        let mut failure = None;
        let refused = RefCell::new(None::<String>);
        let (mut mutations, mut published_at) = (0, None);
        let mut filling: Filling<'_> = None;
        let mut target = None::<(u8, Vec<u8>)>;
        let (checks_done, ended, stalled) = (Cell::new(false), Cell::new(false), Cell::new(false));
        let exited = Cell::new(None::<(String, u64, Option<u64>)>);
        let expected = held.clone();
        let mut turns = 0;
        let (served, _) = stage.serve_until(
            |rounds, _, stop| {
                if !checks_done.get() {
                    let active = rounds.client.borrow().state() == SessionState::Active;
                    if active && pending.is_none() && checked < keys.len() {
                        let n = keys[checked];
                        pending = Some((n, rounds.get(n), Vec::new()));
                    }
                    if let Some((n, id, bytes)) = pending.as_mut()
                        && let Some(outcome) = rounds.fetched(*id, bytes)
                    {
                        let wanted = expected.get(n);
                        let served = match outcome {
                            Fetched::Complete => Ok(Some(std::mem::take(bytes))),
                            Fetched::Missing => Ok(None),
                            other => Err(other),
                        };
                        match served {
                            Ok(got) if got.as_ref() == wanted => {}
                            Ok(got) => {
                                failure.get_or_insert(format!(
                                    "object {n}: served {got:?}, held {wanted:?}"
                                ));
                            }
                            Err(outcome) => {
                                failure.get_or_insert(format!(
                                    "object {n}: the GET ended {outcome:?}"
                                ));
                            }
                        }
                        checked += 1;
                        pending = None;
                        checks_done.set(checked == keys.len());
                    }
                }
                if let Some(refusal) = refused.borrow_mut().take() {
                    failure.get_or_insert(refusal);
                }
                if stalled.get() {
                    failure.get_or_insert(format!("the cycle stalled past {CYCLE_TURNS} turns"));
                }
                if ended.get() || failure.is_some() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let planned = exit == Some(Exit::Rerun(crate::host::Rerun::Planned));
                let transferred = roll == Some(Trigger::Transfer) && exit == Some(Exit::Stopped);
                if planned || transferred {
                    let report = owner.authority_report();
                    let withdrawn = (report.state, report.withdrawal, report.flip);
                    let position =
                        storage.with_suffix(|log| (log.idle(), log.head(), log.durable()));
                    let durable = match position {
                        Ok((true, head, durable)) if head == durable => Some(durable),
                        _ => None,
                    };
                    exited.set(Some((
                        format!("{withdrawn:?} at {position:?}"),
                        owner.tenure().get(),
                        durable,
                    )));
                }
                turns += 1;
                stalled.set(turns > CYCLE_TURNS);
                set_clock(storage, &[Some(nanos(now))]);
                for shard in 0..2 {
                    let mut budget = WorkBudget::new(1 << 12);
                    let _ = storage.service_fills(crate::index::ShardIndex(shard), 2, &mut budget);
                }
                // A closed log never opens, so its request arrives once a capture start found no free slot.
                if roll == Some(Trigger::RequestedClosed)
                    && checks_done.get()
                    && duties.roll_due()
                    && !planted
                {
                    planted = Trigger::RequestedClosed.plant(&mut duties);
                }
                if !checks_done.get() || duties.open != Open::Opened || ended.get() {
                    return exit;
                }
                if let Some(trigger) = roll
                    && mutations >= 4
                    && !planted
                {
                    planted = trigger.plant(&mut duties);
                }
                if published_at.is_none() && mutations >= 4 && published(&duties) > 0 {
                    published_at = Some(mutations);
                }
                let mutating = roll.is_some() || published_at.is_none_or(|at| mutations < at + 3);
                let before = held.len();
                // A rolling tenure's drain refuses FILLs and then INVALIDATEs `Closed`.
                let draining = |owner: &TestOwner<'_>| {
                    let withdrawn = owner.authority_report().state != State::Serving;
                    roll.is_some() && (owner.draining().is_some() || withdrawn)
                };
                if mutating {
                    let (n, payload) = target.get_or_insert_with(|| {
                        let n = keys[choices.next(keys.len() as u64) as usize];
                        (n, versioned(n, reached.fills))
                    });
                    let n = *n;
                    match held.entry(n) {
                        Entry::Occupied(object) => {
                            let mut budget = WorkBudget::new(1 << 20);
                            match owner.invalidate(&object_key(n), 4, &mut budget) {
                                Ok(removal) if removal.removed.is_some() => {
                                    object.remove();
                                    reached.removals += 1;
                                    mutations += 1;
                                }
                                Ok(_) => {
                                    refused.replace(Some(format!(
                                        "object {n}: the INVALIDATE of a held object removed nothing"
                                    )));
                                }
                                Err(InvalidateError::History) => {}
                                Err(InvalidateError::Closed) if draining(owner) => {}
                                Err(other) => {
                                    refused.replace(Some(format!(
                                        "object {n}: the INVALIDATE refused {other:?}"
                                    )));
                                }
                            }
                            target = None;
                        }
                        Entry::Vacant(object) => {
                            match fill(owner, storage, &mut filling, (n, payload)) {
                                None if filling.is_none() => target = None,
                                None => {}
                                Some(Ok(())) => {
                                    object.insert(payload.clone());
                                    reached.fills += 1;
                                    mutations += 1;
                                    target = None;
                                }
                                Some(Err(FillPublishError::History)) => target = None,
                                Some(Err(FillPublishError::Closed)) if draining(owner) => {
                                    target = None;
                                }
                                Some(Err(other)) => {
                                    refused.replace(Some(format!(
                                        "object {n}: the FILL refused {other:?}"
                                    )));
                                    target = None;
                                }
                            }
                        }
                    }
                }
                let abrupt = roll == Some(super::roll_tests::Trigger::Abrupt);
                if abrupt && duties.roll_due() && held.len() != before {
                    // The planted abrupt roll withdraws in the turn of an acknowledged mutation, before its block seals.
                    owner.authority_event(Event::Withdraw(Cause::Planned), now);
                    return Some(Exit::Rerun(crate::host::Rerun::Planned));
                }
                let idle = storage.with_suffix(|log| log.idle()).unwrap_or(false);
                ended.set(!mutating && idle);
                exit
            },
        );
        reached.checks += checked as u64;
        if let Some(failure) = failure {
            return Err(failure);
        }
        let ending = match roll {
            Some(Trigger::Transfer) | None => Exit::Stopped,
            Some(_) => Exit::Rerun(crate::host::Rerun::Planned),
        };
        if served.exit != ending {
            return Err(format!("the tenure ended {:?}", served.exit));
        }
        if roll.is_some_and(|roll| roll != super::roll_tests::Trigger::Abrupt) {
            let Some((withdrawn, session, durable)) = exited.take() else {
                return Err("the roll ended with no planned exit turn".to_owned());
            };
            let planned = format!("{:?}", (State::Withdrawn, Some(Cause::Planned), None::<()>));
            let Some(durable) = durable.filter(|_| withdrawn.starts_with(&planned)) else {
                return Err(format!("the roll exited under {withdrawn}"));
            };
            let record = shard_record(&stage.store);
            let own = (record.ancestry.as_slice().iter()).find(|suffix| suffix.session == session);
            let certified = own.map_or(record.cut, |own| own.certified);
            if matches!(roll, Some(Trigger::Closed | Trigger::RequestedClosed)) {
                // A tenure whose log stayed closed appended nothing, so the record holds no suffix of its session.
                if own.is_some() {
                    return Err(format!("the closed-log roll left an own suffix {own:?}"));
                }
            } else if certified != durable {
                return Err(format!(
                    "the roll withdrew at durable end {durable} over a record certifying {certified}"
                ));
            }
        }
        reached.publications += published(&duties);
        reached.fold(held);
        let record = shard_record(&stage.store);
        let suffixed = (record.ancestry.as_slice().iter())
            .any(|suffix| suffix.certified > suffix.start.max(record.cut));
        Ok((
            (stage.store.clone(), stage.media.clone()),
            record.checkpoint,
            suffixed,
        ))
    })
}

/// The objects the warm volume holds: 1 to 4, object 2 as the predecessor's suffix replaced it.
pub(super) fn warm_objects() -> Held {
    (1..=4).map(|n| (n, replaced(n))).collect()
}

/// Runs cycle `at` of seed `seed`, and tags its failure, a returned mismatch or a panic with the panic's location
/// and text, with the seed and the cycle.
fn contained<T>(
    (seed, at): (u64, usize),
    run: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    crate::sim::unwind::caught(run)
        .unwrap_or_else(|panic| Err(format!("panicked at {panic}")))
        .map_err(|failure| format!("seed {seed} cycle {at}: {failure}"))
}

/// Seeds `seeds`, each `cycles` same-host restarts through `recover`, `bring_up`, `serve` and `Duties` with a
/// publishing owner: every cycle's warm load must serve exactly the objects the earlier tenures held, from
/// the published cut and the suffix over it, and every cycle must end with the record naming a checkpoint later
/// than the one it loaded. Returns one line per seed and a summary line, or the first mismatch or panic with its
/// seed and cycle.
pub(crate) fn publishing_cycles(
    seeds: std::ops::RangeInclusive<u64>,
    cycles: usize,
) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let (mut publications, mut fills, mut removals, mut checks) = (0, 0, 0, 0);
    for seed in seeds.clone() {
        let mut choices = Choices::of(seed);
        let mut held = warm_objects();
        let mut reached = Reached::default();
        let mut volume = warm_volume_certified(0);
        let mut loaded = shard_record(&volume.0).checkpoint;
        for at in 0..cycles {
            let (next, named, suffixed) = contained((seed, at), || {
                cycle(volume, &mut held, &mut choices, &mut reached)
            })?;
            let later = |named: NamedCheckpoint| {
                loaded.is_none_or(|loaded| {
                    (named.session, named.capture) > (loaded.session, loaded.capture)
                })
            };
            if !named.is_some_and(later) {
                return Err(format!(
                    "seed {seed} cycle {at}: the record names {named:?} after {loaded:?}"
                ));
            }
            if suffixed && at + 1 < cycles {
                reached.suffix_loads += 1;
            }
            (volume, loaded) = (next, named);
        }
        lines.push(format!(
            "publishing: seed {seed} cycles {cycles}: every warm load held the published cut plus the suffix; \
             publications {}; fills {}; removals {}; checks {}; suffix loads {}; identity {:016x}",
            reached.publications,
            reached.fills,
            reached.removals,
            reached.checks,
            reached.suffix_loads,
            reached.identity
        ));
        publications += reached.publications;
        fills += reached.fills;
        removals += reached.removals;
        checks += reached.checks;
    }
    lines.push(format!(
        "publishing: {} seeds of {cycles} restarts; publications {publications}; fills {fills}; removals {removals}; \
         checks {checks}",
        seeds.count(),
    ));
    Ok(lines)
}

/// Two seeds of two restart cycles each pass with their pinned lines, with the recovery helpers inline as the
/// worker runs them, so the nightly family's driver and its schedule run in the workspace lane.
#[test]
fn two_seeded_restart_cycles_load_the_published_cut_plus_the_suffix() {
    let lines = crate::host::serve::tests::inline(|| publishing_cycles(1..=2, 2))
        .unwrap_or_else(|failure| panic!("{failure}"));
    assert_eq!(lines, PINNED, "{lines:#?}");
}

/// Control for the seeded cycles' check: after a cycle that published and mutated into its suffix, an expectation
/// that flips one object the cycle changed, kept although invalidated or dropped although filled, fails the next
/// cycle's check on that object.
#[test]
fn a_cycle_expecting_other_than_the_tenures_acknowledged_fails_its_check() {
    crate::host::serve::tests::inline(|| {
        let mut choices = Choices::of(1);
        let mut reached = Reached::default();
        let mut held = warm_objects();
        let (volume, ..) = cycle(
            warm_volume_certified(0),
            &mut held,
            &mut choices,
            &mut reached,
        )
        .unwrap_or_else(|failure| panic!("{failure}"));
        let before = warm_objects();
        let changed = (KEYS.clone())
            .find(|n| held.get(n) != before.get(n))
            .expect("the cycle changed an object");
        match held.remove(&changed) {
            Some(_) => {}
            None => {
                held.insert(changed, before[&changed].clone());
            }
        }
        let failed = cycle(volume, &mut held, &mut choices, &mut reached);
        let failure = failed.err().expect("the check fails");
        assert!(
            failure.starts_with(&format!("object {changed}:")),
            "{failure}"
        );
    });
}

/// A panic in a cycle reaches the driver as a failure tagged with its seed and cycle that keeps the panic's text.
#[test]
fn a_panic_in_a_cycle_fails_with_its_seed_and_cycle() {
    let failed = contained((3, 5), || -> Result<(), String> {
        panic!("bring-up ended {}", 7)
    });
    let failure = failed.expect_err("the panic fails the cycle");
    assert!(
        failure.starts_with("seed 3 cycle 5: panicked at "),
        "{failure}"
    );
    assert!(failure.ends_with("bring-up ended 7"), "{failure}");
}

const PINNED: [&str; 3] = [
    "publishing: seed 1 cycles 2: every warm load held the published cut plus the suffix; publications 4; fills 7; \
     removals 7; checks 24; suffix loads 1; identity ba766a5eec6969ce",
    "publishing: seed 2 cycles 2: every warm load held the published cut plus the suffix; publications 4; fills 7; \
     removals 7; checks 24; suffix loads 1; identity 932e82358997f56a",
    "publishing: 2 seeds of 2 restarts; publications 8; fills 14; removals 14; checks 48",
];

/// The shard record's version in `store`.
fn shard_version(store: &Shared) -> Version {
    Client::open(store.clone(), MemLog::default())
        .unwrap()
        .read::<ShardRecord>(Key::Shard(shard()))
        .unwrap()
        .version()
}

/// A step whose shard-record write commits with a lost reply drops the duties' read: with a step due every turn, no
/// step is submitted until the next view of the tenure replaces the read with the record the lost write committed,
/// and the steps after that commit over the new read.
#[test]
fn a_step_with_a_lost_reply_waits_for_the_next_view_before_stepping_again() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let store = Unanswered::over(&stage.store, Arm::Timeout { commit: true });
        let armed = Rc::clone(&store.armed);
        let client = Client::open(store, MemLog::default()).unwrap();
        let mut duties = Duties::new(
            (
                &HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            Lane::inline(client, stage.storage),
            records(),
            None,
            wide(),
            super::tests::periods().with_step(NonZeroU64::new(ROUND_US).unwrap()),
        );
        let storage = stage.storage;
        let shared = stage.store.clone();
        let commits = || shared.0.borrow().commit_count(&Key::Shard(shard()));
        let mut churn = Churn::new();
        let (mut fired, mut lost, mut restored, mut waited, mut after) =
            (None, None, None, 0, None);
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let at = duties.step_at;
                let exit = duties.turn(owner, now);
                if duties.open != Open::Opened && lost.is_none() {
                    return exit;
                }
                churn.step(owner, storage, now);
                if commits() >= 5 && fired.is_none() {
                    fired = Some(commits());
                    armed.set(true);
                }
                if let (Some(fired), None, Some(refusal)) = (fired, lost, duties.step_refusal) {
                    assert_eq!(refusal, WriteRefused::Store(StoreError::Unknown));
                    assert_eq!(commits(), fired + 1, "the step's write committed");
                    assert!(duties.read.is_none());
                    lost = Some((commits(), shard_version(&shared)));
                }
                if lost.is_some() && restored.is_none() {
                    match &duties.read {
                        None if now >= at => {
                            waited += 1;
                            assert_eq!(duties.step_at, at, "no step goes out without a read");
                        }
                        None => {}
                        Some(read) => restored = Some(read.version()),
                    }
                }
                if let Some((lost, _)) = lost
                    && restored.is_some()
                    && duties.step_refusal.is_none()
                    && commits() > lost
                {
                    after = Some(commits());
                }
                ended.set(after.is_some());
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let (_, version) = lost.expect("a step's reply was lost");
        assert!(waited >= 1, "a step came due while the duties held no read");
        assert_eq!(
            restored,
            Some(version),
            "the view restored the record the lost write committed"
        );
        assert!(
            after.is_some(),
            "a later step committed over the view's read"
        );
    });
}

/// The test withdraws authority with `Cause::Unheld` when the lane is idle, so any later shard-record commit would
/// come from a step submitted after the withdrawal. The owner stops submitting suffix steps while it keeps polling.
#[test]
fn a_withdrawn_owner_ends_its_suffix_steps() {
    use crate::failover::serving::{Cause, Event};
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, None);
        let storage = stage.storage;
        let shared = stage.store.clone();
        let commits = || shared.0.borrow().commit_count(&Key::Shard(shard()));
        let mut churn = Churn::new();
        let (mut before, mut withdrawn, mut after) = (0u32, None, 0u32);
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let at = duties.step_at;
                let exit = duties.turn(owner, now);
                if duties.open != Open::Opened {
                    return exit;
                }
                let submitted = duties.stepping && duties.step_at != at;
                match withdrawn {
                    None => {
                        churn.step(owner, storage, now);
                        before += u32::from(submitted);
                        if before >= 4 && duties.lane.outstanding() == 0 {
                            owner.authority_event(Event::Withdraw(Cause::Unheld), now);
                            withdrawn = Some((now, commits()));
                        }
                    }
                    Some((at, _)) => {
                        after += u32::from(submitted);
                        ended.set(now >= at + 3 * VIEW_US);
                    }
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let (_, at_withdrawal) = withdrawn.expect("steps went out before the withdrawal");
        assert_eq!(after, 0, "steps submitted after the withdrawal");
        assert_eq!(
            commits(),
            at_withdrawal,
            "the shard record's commits after the withdrawal"
        );
    });
}

/// How a step's write withdraws the store client.
#[derive(Clone, Copy)]
enum Withdrawing {
    /// The write commits and the watermark log fails to record the raised mark.
    Unlogged,
    /// A writer outside the host moved the record past the duties' read, and the store applies the step's stale
    /// write two versions past its condition.
    Regressed,
}

/// `Withdrew` records how the serve loop exited, how many turns elapsed between adopting the withdrawing step's
/// completion and exiting, and the authority's withdrawal cause at exit.
struct Withdrew {
    exit: Exit,
    turns_after_adoption: u64,
    cause: Option<crate::failover::serving::Cause>,
}

/// Runs a tenure under mutations and arms `how` on each turn whose sole lane job is a step, until a step write
/// triggers the withdrawal. The inline lane runs the step at its submission, so the shard record's commit count
/// shows whether that step wrote.
fn step_that_withdraws_the_client(how: Withdrawing) -> Withdrew {
    use crate::failover::takeover::tests::rewrite;
    let mut result = None;
    staged_over(warm_volume_certified(0), |mut stage| {
        let store = Unanswered::over(&stage.store, Arm::DoubleWin);
        let armed = Rc::clone(&store.armed);
        let log = MemLog::default();
        let fails = log.fail.clone();
        let client = Client::open(store, log).unwrap();
        let mut duties = Duties::new(
            (
                &HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            Lane::inline(client, stage.storage),
            records(),
            None,
            wide(),
            super::tests::periods().with_step(NonZeroU64::new(STEP_US).unwrap()),
        );
        let storage = stage.storage;
        let shared = stage.store.clone();
        let commits = || shared.0.borrow().commit_count(&Key::Shard(shard()));
        let mut churn = Churn::new();
        let (mut steps, mut planted, mut adopted, mut exited) = (0u32, false, None, None);
        let mut turn = 0u64;
        let cause = Cell::new(None);
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                turn += 1;
                let named =
                    (duties.read.as_ref()).is_some_and(|read| read.value().checkpoint.is_some());
                let idle = !duties.writing && !duties.paging && duties.viewing.is_none();
                let covers = duties.page_next.is_some()
                    || duties.page_after.is_some()
                    || owner.cover_waits();
                let due = duties.open == Open::Opened
                    && !planted
                    && steps >= 2
                    && named
                    && idle
                    && !covers
                    && now >= duties.step_at
                    && now < duties.view_at;
                if due {
                    match how {
                        Withdrawing::Unlogged => fails.set(true),
                        Withdrawing::Regressed => {
                            rewrite(&shared, |record| record);
                            armed.set(true);
                        }
                    }
                }
                let (at, before) = (duties.step_at, commits());
                let exit = duties.turn(owner, now);
                let submitted = duties.stepping && duties.step_at != at;
                steps += u32::from(submitted);
                if due {
                    planted = submitted && commits() > before;
                    fails.set(planted && matches!(how, Withdrawing::Unlogged));
                }
                if duties.open == Open::Opened && !planted {
                    churn.step(owner, storage, now);
                }
                let refused = matches!(duties.step_refusal, Some(WriteRefused::Store(_)));
                if planted && refused && adopted.is_none() {
                    adopted = Some(turn);
                }
                if exit.is_some() && exited.is_none() {
                    exited = Some(turn);
                    cause.set(owner.authority_report().withdrawal);
                }
                ended.set(turn >= 20_000);
                exit
            },
        );
        let adopted = adopted.expect("a step's write met the plant and its completion was adopted");
        result = Some(Withdrew {
            exit: served.exit,
            turns_after_adoption: exited.expect("the tenure ended with an exit") - adopted,
            cause: cause.get(),
        });
    });
    result.expect("the tenure ran")
}

#[test]
fn a_step_whose_raised_watermark_the_log_fails_to_record_ends_the_incarnation_at_its_adoption() {
    let left = step_that_withdraws_the_client(Withdrawing::Unlogged);
    assert_eq!(left.exit, Exit::Rerun(Rerun::Withdrawn));
    assert_eq!(
        left.turns_after_adoption, 0,
        "the adopting turn ends the incarnation"
    );
}

#[test]
fn a_step_whose_write_regresses_withdraws_the_tenure_under_regression_at_its_adoption() {
    use crate::failover::serving::Cause;
    let left = step_that_withdraws_the_client(Withdrawing::Regressed);
    assert_eq!(left.exit, Exit::Rerun(Rerun::Withdrawn));
    assert_eq!(left.cause, Some(Cause::Regression));
    assert_eq!(
        left.turns_after_adoption, 0,
        "the adopting turn ends the incarnation"
    );
}

/// A step that lands while the pass is in its unit commands holds the pass in place, whatever its unit: no unit
/// command is staged and no device result is taken while the lane holds the step's completion, so a result that ends
/// the stage meets the set on the owner thread. The pass goes on once that completion returns the set. A hold that
/// covered no unit awaiting its device result is released and taken again.
#[test]
fn a_step_outstanding_during_the_unit_commands_holds_the_pass() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, Some(policy_every(1_000_000)));
        let (mut holding, mut window, mut witnessed, mut moved) = (false, None, None, false);
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let at = duties.step_at;
                let exit = duties.turn(owner, now);
                let writing = match &duties.capture.as_ref().unwrap().pass {
                    Pass::Writing { unit, .. } => Some(*unit),
                    _ => None,
                };
                // A step submitted on this turn, after the hold was armed, has its completion held.
                let submitted = duties.stepping && duties.step_at != at;
                let inline = duties.lane.inline_mut();
                if !holding {
                    if writing.is_some() {
                        inline.hold();
                        holding = true;
                    }
                    return exit;
                }
                if let Some(unit) = witnessed {
                    while inline.release() {}
                    moved |= writing != Some(unit);
                    ended.set(moved);
                    return exit;
                }
                match window {
                    None if submitted && writing.is_some() => window = Some((writing.unwrap(), 0)),
                    None => while inline.release() {},
                    Some((unit, turns)) if turns < 20 => {
                        assert_eq!(
                            writing,
                            Some(unit),
                            "the pass holds its unit while a step holds the set"
                        );
                        window = Some((unit, turns + 1));
                    }
                    Some((unit, _)) => {
                        while inline.release() {}
                        window = None;
                        if matches!(unit, Unit::Written(_) | Unit::Reading(_)) {
                            witnessed = Some(unit);
                        }
                    }
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(
            witnessed.is_some(),
            "a step held the set over a unit awaiting its device result"
        );
        assert!(moved, "the pass went on after the step returned the set");
    });
}

/// With `writing` planted clear while the open's `holder` job, Confirm or Open, holds the set on the lane, a due
/// step waits for the idle lane: it submits nothing and leaves the set with the job.
fn a_step_due_beside_an_outstanding(holder: Open) {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, None);
        duties.lane.inline_mut().hold();
        let store = stage.store.clone();
        let mut left = None;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let exit = duties.turn(owner, now);
                if !(duties.open == holder && duties.writing) {
                    duties.lane.inline_mut().release();
                    return exit;
                }
                duties.open = Open::Opened;
                let read = Client::open(store.clone(), MemLog::default())
                    .unwrap()
                    .read::<ShardRecord>(Key::Shard(shard()))
                    .unwrap();
                duties.read = Some(read);
                left = Some(step_beside(&mut duties, owner, now));
                Some(Exit::Stopped)
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(left, Some((false, 1, false)));
    });
}

#[test]
fn a_step_due_beside_an_outstanding_confirm_waits_for_the_idle_lane() {
    a_step_due_beside_an_outstanding(Open::Confirming);
}

#[test]
fn a_step_due_beside_an_outstanding_open_waits_for_the_idle_lane() {
    a_step_due_beside_an_outstanding(Open::Opening);
}

/// Duties with no capture policy cannot publish, so a due publication sets `roll_due`: the tenure's capacity is its
/// bound.
#[test]
fn a_due_publication_with_no_capture_policy_sets_roll_due() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let client = Client::open(stage.store.clone(), MemLog::default()).unwrap();
        let mut duties = Duties::new(
            (
                &HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            Lane::inline(client, stage.storage),
            records(),
            None,
            SuffixBounds {
                margin: 1,
                ..wide()
            },
            super::tests::periods().with_step(NonZeroU64::new(ROUND_US).unwrap()),
        );
        let storage = stage.storage;
        let mut churn = Churn::new();
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                assert_eq!(exit, None, "the bound raises no exit");
                if duties.open != Open::Opened {
                    return exit;
                }
                if duties.roll_due() && !ended.get() {
                    let due = duties.suffix_due().expect("a step sampled the signals");
                    assert!(
                        due.publication && !due.handoff,
                        "the due publication set roll_due: {due:?}"
                    );
                    ended.set(true);
                }
                churn.step(owner, storage, now);
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(
            !duties.suffix_due().is_some_and(|due| due.handoff),
            "the publication came due before the handoff"
        );
    });
}

/// With a step due on every turn, the pass still takes the set on the turns the steps leave it and publishes: the
/// capture pass runs before the step in a turn.
#[test]
fn a_step_due_every_turn_leaves_the_pass_its_turns_to_publish() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties_every(&stage, Some(policy_every(1_000_000)), ROUND_US);
        let (mut steps, mut turns) = (0, 0);
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let at = duties.step_at;
                let exit = duties.turn(owner, now);
                turns += 1;
                steps += u32::from(duties.step_at != at);
                ended.set(published(&duties) >= 1 || turns > 3_000);
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(steps >= 10, "steps went out: {steps}");
        assert!(published(&duties) >= 1, "a pass published within the turns");
    });
}

/// A proved pass waits for one outstanding step at most. With a step due on every turn, a step goes out on the turn
/// the pass proves. The turn that adopts that step runs the pass before the next step, on an idle lane, so the
/// Publish goes out there, or one turn later when a due view took the lane first: a pass ends at most two turns
/// `Proving`.
#[test]
fn a_proved_pass_publishes_on_the_turn_that_adopts_an_outstanding_step() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties_every(&stage, Some(policy_every(1_000_000)), ROUND_US);
        let (mut beside, mut run, mut longest, mut turns) = (0u32, 0u32, 0u32, 0u32);
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                turns += 1;
                let pass = &duties.capture.as_ref().unwrap().pass;
                if matches!(pass, Pass::Proving { .. }) {
                    run += 1;
                    beside += u32::from(duties.stepping);
                    assert!(
                        duties.stepping || duties.viewing.is_some(),
                        "a proved pass waits beside a step or a view"
                    );
                } else {
                    run = 0;
                }
                longest = longest.max(run);
                ended.set(published(&duties) >= 3 || turns > 6_000);
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(published(&duties) >= 3, "three passes published");
        assert!(beside >= 1, "a step was outstanding beside a proved pass");
        assert!(
            longest <= 2,
            "a pass ended {longest} turns in a row proving"
        );
    });
}

/// What a planted step refusal left.
struct Refused {
    open: Open,
    refusal: Option<WriteRefused>,
    read: Option<Version>,
    /// The read's version before the plant.
    before: Version,
    /// Steps submitted and passes started after the plant, and whether a later step cleared the refusal.
    steps: u32,
    starts: u32,
    cleared: bool,
}

/// Adopts `refused` as a step's completion on an opened tenure with no job outstanding, then runs four step periods.
fn planted_step_refusal(refused: WriteRefused, policy: Option<CapturePolicy>) -> Refused {
    let mut result = None;
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, policy);
        let mut planted: Option<(u64, Refused)> = None;
        let mut was_idle = true;
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let at = duties.step_at;
                let exit = duties.turn(owner, now);
                let idle = duties
                    .capture
                    .as_ref()
                    .is_none_or(|capture| matches!(capture.pass, Pass::Idle));
                match planted.as_mut() {
                    None => {
                        let ready = duties.open == Open::Opened && !duties.writing && idle;
                        if let Some(read) = duties.read.as_ref().filter(|_| ready) {
                            let before = read.version();
                            let possible = duties.take_set();
                            (duties.writing, duties.stepping) = (true, true);
                            duties.stepped(possible, Err(refused), Some(SuffixDue::default()));
                            let left = Refused {
                                open: duties.open,
                                refusal: duties.step_refusal,
                                read: duties.read.as_ref().map(|read| read.version()),
                                before,
                                steps: 0,
                                starts: 0,
                                cleared: false,
                            };
                            planted = Some((now, left));
                        }
                    }
                    Some((at_plant, left)) => {
                        left.steps += u32::from(duties.step_at != at);
                        left.starts += u32::from(was_idle && !idle);
                        left.cleared |= duties.step_refusal.is_none();
                        ended.set(now > *at_plant + 4 * STEP_US);
                    }
                }
                was_idle = idle;
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        result = planted.map(|(_, left)| left);
    });
    result.expect("the refusal was planted")
}

/// A step refused for a tenure mismatch stops the duties' shard-record writes: no later step goes out and no capture
/// pass starts under a policy that is due.
#[test]
fn a_step_refused_for_its_tenure_stops_the_steps_and_the_passes() {
    let left = planted_step_refusal(WriteRefused::Tenure, Some(policy_every(1_000)));
    assert_eq!(left.open, Open::Stopped);
    assert_eq!(left.refusal, Some(WriteRefused::Tenure));
    assert_eq!((left.steps, left.starts), (0, 0));
}

/// A step refused before any request for its chain keeps the duties' read, so the next step goes out over it with no
/// view between, and a later step clears the refusal.
#[test]
fn a_step_refused_for_its_chain_keeps_the_read_and_steps_again() {
    let left = planted_step_refusal(WriteRefused::Chain, None);
    assert_eq!(left.open, Open::Opened);
    assert_eq!(left.refusal, Some(WriteRefused::Chain));
    assert_eq!(left.read, Some(left.before), "the read is kept");
    assert!(left.steps >= 1);
    assert!(left.cleared, "a later step cleared the refusal");
}

/// What a Publish over a named checkpoint with a lost reply left: its slot, the slot the record names once the
/// Confirm settled the set, the set's slots then, the capacity the log admits at the refusal and at the end,
/// whether a later pass started, and the abandoned count at the end, which read 1 at the refusal.
struct Lost {
    slot: u32,
    named: Option<u32>,
    settled: Vec<u32>,
    capacity: (u64, u64),
    restarted: bool,
    abandoned: u64,
}

/// Runs a tenure whose due publication starts a pass under a policy that is never due and loses the reply of that
/// pass's Publish, whose write commits when `commit`; then serves 300 turns past the settling Confirm.
fn lost_publish(commit: bool) -> Lost {
    let mut result = None;
    staged_over(warm_volume_certified(0), |mut stage| {
        let store = Unanswered::over(&stage.store, Arm::Timeout { commit });
        let armed = Rc::clone(&store.armed);
        let client = Client::open(store, MemLog::default()).unwrap();
        let mut duties = Duties::new(
            (
                &HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            Lane::inline(client, stage.storage),
            records(),
            None,
            wide(),
            super::tests::periods().with_step(NonZeroU64::new(STEP_US).unwrap()),
        )
        .capturing(policy_every(NEVER), EngineBudget::unlimited())
        .unwrap();
        let storage = stage.storage;
        let shared = stage.store.clone();
        let mut churn = Churn::new();
        let commits = || shared.0.borrow().commit_count(&Key::Shard(shard()));
        let (mut slot, mut refused, mut confirmed, mut settled) = (None, None, false, None);
        let (mut turns, mut restarted) = (0, false);
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                if duties.open != Open::Opened {
                    return exit;
                }
                churn.step(owner, storage, now);
                let capture = duties.capture.as_ref().unwrap();
                let idle = matches!(capture.pass, Pass::Idle);
                let capacity = storage.with_suffix(|log| log.capacity()).unwrap();
                match (slot, refused, settled.as_ref()) {
                    (None, ..) => {
                        if let Pass::Proving { staged, .. } = &capture.pass {
                            slot = Some(staged.slot());
                            armed.set(true);
                        }
                    }
                    (Some(slot), None, _) => {
                        if capture.refusal.is_some() {
                            assert_eq!(
                                capture.refusal,
                                Some(WriteRefused::Store(StoreError::Unknown))
                            );
                            assert_eq!(duties.settling, Some(slot));
                            assert!(duties.read.is_none(), "no step can raise the capacity");
                            assert_eq!(capture.abandoned, 1, "the refused Publish counts");
                            refused = Some((commits(), capacity));
                        }
                    }
                    (Some(slot), Some((at_refusal, before)), None) => {
                        assert!(
                            matches!(capture.pass, Pass::Idle | Pass::Finishing { .. }),
                            "no pass starts before the Confirm settles the set"
                        );
                        if duties.settling.is_some() && duties.writing {
                            // The inline lane ran the settling Confirm at its submission.
                            assert_eq!(commits(), at_refusal + 1, "the settling Confirm committed");
                            confirmed = true;
                        }
                        if duties.settling.is_none() && !duties.writing {
                            assert!(confirmed, "an acknowledged Confirm settled the set");
                            let named = shard_record(&shared).checkpoint.map(|named| named.slot);
                            settled = Some((slot, named, duties.here().slots(), before));
                        }
                    }
                    (Some(_), Some(_), Some(_)) => {
                        turns += 1;
                        restarted |= !idle;
                        ended.set(restarted || turns >= 300);
                    }
                }
                if ended.get() {
                    let (slot, named, set, at_refusal) = settled.clone().unwrap();
                    result = Some(Lost {
                        slot,
                        named,
                        settled: set,
                        capacity: (at_refusal, capacity),
                        restarted,
                        abandoned: capture.abandoned,
                    });
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
    });
    result.expect("the Confirm settled the set")
}

/// PossNamedCoversStore: a Publish over a named checkpoint whose write commits with a lost reply holds the next
/// capture start until a Confirm over the next view's read settles the set to the published checkpoint. The
/// publication it served is no longer due: the log's capacity rises over the settled floor and no second pass
/// starts.
#[test]
fn a_warm_publish_that_commits_with_a_lost_reply_settles_the_set_before_another_pass() {
    let lost = lost_publish(true);
    assert_eq!(lost.named, Some(lost.slot), "the Publish committed");
    assert_eq!(lost.settled, [lost.slot], "the Confirm settled the set");
    assert!(!lost.restarted, "no second pass started");
    assert_eq!(
        lost.abandoned, 1,
        "the count of abandoned passes keeps the Publish whose reply was lost"
    );
    assert!(
        lost.capacity.1 > lost.capacity.0,
        "a step raised the capacity over the settled floor: {:?}",
        lost.capacity
    );
}

/// A Publish over a named checkpoint whose write did not commit, with a lost reply, leaves its publication due once
/// the Confirm settled the set, so a later pass starts.
#[test]
fn a_warm_publish_lost_before_its_commit_starts_another_pass_once_the_set_settled() {
    let lost = lost_publish(false);
    assert_ne!(lost.named, Some(lost.slot), "the Publish did not commit");
    assert!(!lost.settled.contains(&lost.slot));
    assert!(lost.restarted, "the publication still due started a pass");
}

/// What a planted settling Confirm refusal left: the open and the settling slot on the turn of the plant, whether
/// the read was dropped, the steps submitted and passes started while the set stayed unsettled, and whether a later
/// Confirm settled it.
struct Unsettled {
    open: Open,
    settling: Option<u32>,
    dropped: bool,
    steps: u32,
    starts: u32,
    settled: bool,
}

/// Adopts `refused` as the completion of a settling Confirm on an opened tenure with no job outstanding, under a
/// policy that is always due, then runs three view periods.
fn planted_settling_refusal(refused: WriteRefused) -> Unsettled {
    let mut result = None;
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, Some(policy_every(1_000)));
        let mut planted: Option<(u64, Unsettled)> = None;
        let mut was_idle = true;
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let at = duties.step_at;
                let exit = duties.turn(owner, now);
                let idle = idle(&duties);
                match planted.as_mut() {
                    None => {
                        if duties.open == Open::Opened
                            && !duties.writing
                            && idle
                            && duties.read.is_some()
                        {
                            // A slot the record never names, as a lost Publish's that did not commit.
                            duties.settling = Some(u32::MAX);
                            let possible = duties.take_set();
                            duties.read = None;
                            duties.writing = true;
                            duties.resettled(possible, Err(refused));
                            let left = Unsettled {
                                open: duties.open,
                                settling: duties.settling,
                                dropped: duties.read.is_none(),
                                steps: 0,
                                starts: 0,
                                settled: false,
                            };
                            planted = Some((now, left));
                        }
                    }
                    Some((at_plant, left)) => {
                        if duties.settling.is_some() {
                            left.steps += u32::from(duties.step_at != at);
                            left.starts += u32::from(was_idle && !idle);
                        } else {
                            left.settled = true;
                        }
                        ended.set(now > *at_plant + 3 * VIEW_US);
                    }
                }
                was_idle = idle;
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        result = planted.map(|(_, left)| left);
    });
    result.expect("the refusal was planted")
}

/// A settling Confirm that ends with a store error keeps the set unsettled and drops the read: no step goes out and
/// no pass starts until a Confirm over a later view's read commits.
#[test]
fn a_settling_confirm_with_a_store_error_confirms_again_before_any_step_or_pass() {
    let left = planted_settling_refusal(WriteRefused::Store(StoreError::Unknown));
    assert_eq!(left.open, Open::Opened);
    assert_eq!(left.settling, Some(u32::MAX));
    assert!(left.dropped, "the read is dropped");
    assert_eq!((left.steps, left.starts), (0, 0));
    assert!(left.settled, "a later Confirm settled the set");
}

/// A settling Confirm refused for a tenure mismatch stops the duties' shard-record writes: no step goes out, no pass
/// starts and no later Confirm settles the set.
#[test]
fn a_settling_confirm_refused_for_its_tenure_stops_the_writes() {
    let left = planted_settling_refusal(WriteRefused::Tenure);
    assert_eq!(left.open, Open::Stopped);
    assert_eq!((left.steps, left.starts), (0, 0));
    assert!(!left.settled);
}

/// A tenure whose record names no checkpoint submits no suffix step, with a step due every turn, until its first
/// Publish reopens it over the published checkpoint; steps go out after that.
#[test]
fn steps_wait_for_a_record_that_names_a_checkpoint() {
    let store = super::capture_tests::fresh_store();
    staged_fresh(store, |mut stage| {
        let mut duties = step_duties_every(&stage, Some(policy_every(5_000_000)), ROUND_US);
        let (mut eligible, mut early, mut later, mut turns) = (0, 0, 0, 0);
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let (at, opened) = (duties.step_at, duties.open == Open::Opened);
                let unnamed =
                    (duties.read.as_ref()).is_some_and(|read| read.value().checkpoint.is_none());
                let ready = opened && !duties.writing && duties.set_here();
                let exit = duties.turn(owner, now);
                turns += 1;
                let stepped = u32::from(duties.step_at != at);
                if published(&duties) == 0 {
                    eligible += u32::from(ready && unnamed && now >= at);
                    early += stepped;
                } else if duties.open == Open::Opened {
                    later += stepped;
                }
                ended.set(later >= 3 || turns > 5_000);
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(
            eligible >= 1,
            "a step came due over a record naming no checkpoint"
        );
        assert_eq!(early, 0, "no step before the first Publish");
        assert!(later >= 3, "steps went out after the reopen: {later}");
    });
}

/// PossNamedCoversStore: the encode carries the stage's slot reservation and leaves the set on the owner thread, so
/// suffix steps go out while the helpers hold the encode's terminal. A terminal that lands while the lane holds a
/// step's completion waits: the pass stays in its encode until the set returned, then stages its units and
/// publishes.
#[test]
fn steps_go_out_while_the_helpers_encode_and_the_terminal_waits_for_the_set() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, Some(policy_every(1_000_000)));
        crate::storage::PARK_RECOVERY.with(|park| park.set(true));
        let (mut steps, mut landed, mut waited) = (0u32, false, 0u32);
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let at = duties.step_at;
                let exit = duties.turn(owner, now);
                let encoding =
                    matches!(duties.capture.as_ref().unwrap().pass, Pass::Encoding { .. });
                let submitted = duties.stepping && duties.step_at != at;
                if encoding && !landed {
                    steps += u32::from(submitted);
                    if steps == 2 {
                        // Later completions stay on the lane, the next step's among them.
                        duties.lane.inline_mut().hold();
                    }
                    if steps >= 3 && submitted {
                        owner.release_parked();
                        landed = true;
                    }
                } else if landed && waited < 20 {
                    assert!(duties.stepping, "the lane holds the step's completion");
                    assert!(
                        encoding,
                        "the encode's terminal waits while a step holds the set"
                    );
                    waited += 1;
                } else if landed {
                    while duties.lane.inline_mut().release() {}
                }
                ended.set(published(&duties) == 1);
                exit
            },
        );
        crate::storage::PARK_RECOVERY.with(|park| park.set(false));
        assert_eq!(served.exit, Exit::Stopped);
        assert!(steps >= 3, "steps went out during the encode: {steps}");
        assert_eq!(waited, 20);
        let capture = duties.capture.as_ref().unwrap();
        assert_eq!((capture.refused, capture.abandoned), (0, 0));
    });
}

/// A panicked encode ends the tenure on the turn that takes its terminal, and that turn submits no lane job: with a
/// suffix step due, the set on the owner thread and the lane idle, the turn returns `Rerun(Unwound)` and leaves the
/// step unsubmitted, so the exit starts no store write.
#[test]
fn a_turn_that_ends_on_a_panicked_encode_submits_no_step() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, Some(policy_every(1_000_000)));
        crate::storage::PARK_RECOVERY.with(|park| park.set(true));
        crate::storage::ENCODE_PANIC.with(|panic| panic.set(true));
        let mut ended = None;
        let (served, _) = stage.serve_until(
            |_, turn, stop| {
                if turn >= 20_000 {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let encoding = (duties.capture.as_ref())
                    .is_some_and(|capture| matches!(capture.pass, Pass::Encoding { .. }));
                let named =
                    (duties.read.as_ref()).is_some_and(|read| read.value().checkpoint.is_some());
                // The turn adopts nothing and submits no view, so only the step can take the lane.
                let due = encoding
                    && named
                    && duties.open == Open::Opened
                    && duties.set_here()
                    && duties.lane.outstanding() == 0
                    && now >= duties.step_at
                    && now < duties.view_at;
                if due {
                    owner.release_parked();
                }
                let at = duties.step_at;
                let exit = duties.turn(owner, now);
                if due {
                    let submitted = duties.stepping || duties.step_at != at;
                    ended = Some((exit.clone(), submitted, duties.lane.outstanding()));
                }
                exit
            },
        );
        crate::storage::ENCODE_PANIC.with(|panic| panic.set(false));
        crate::storage::PARK_RECOVERY.with(|park| park.set(false));
        assert_eq!(served.exit, Exit::Rerun(Rerun::Unwound));
        assert_eq!(
            ended,
            Some((Some(Exit::Rerun(Rerun::Unwound)), false, 0)),
            "the turn that took the panicked terminal submitted a step"
        );
    });
}

thread_local! {
    /// The planted control of a step that sampled no signal: the duties store a default signal for it.
    pub(super) static DEFAULT_SIGNAL: Cell<bool> = const { Cell::new(false) };
}

pub(super) fn default_signal() -> bool {
    DEFAULT_SIGNAL.with(Cell::get)
}

/// Drives [`Duties::stepped`] with a committed read and no signal, the completion of a step whose one try of the
/// capture mutex failed, over duties whose last step sampled a due handoff and a due publication: once with
/// `roll_due` and the capture's `publish_due` clear and once with both set. Returns the first mismatch with: the
/// read adopted, the set back on the owner thread, both flags as they were, no signal stored, and a report entry
/// over [`Duties::suffix_due`] whose `publication_due` reads unavailable.
fn step_without_a_signal() -> Result<(), String> {
    let mut result = None;
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, Some(policy_every(NEVER)));
        let store = stage.store.clone();
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let exit = duties.turn(owner, now);
                let ready = duties.open == Open::Opened
                    && duties.set_here()
                    && duties.lane.outstanding() == 0
                    && duties.read.is_some()
                    && idle(&duties);
                if !ready {
                    return exit;
                }
                result = Some([false, true].into_iter().try_for_each(|flags| {
                    let read = Client::open(store.clone(), MemLog::default())
                        .unwrap()
                        .read::<ShardRecord>(Key::Shard(shard()))
                        .unwrap();
                    let version = read.version();
                    duties.read = None;
                    duties.due = Some(SuffixDue {
                        handoff: true,
                        publication: true,
                    });
                    duties.roll_due = flags;
                    duties.capture.as_mut().unwrap().publish_due = flags;
                    let possible = duties.take_set();
                    (duties.writing, duties.stepping) = (true, true);
                    duties.stepped(possible, Ok(read), None);
                    let observed = Observed {
                        suffix_due: duties.suffix_due(),
                        ..Observed::UNAVAILABLE
                    };
                    let entry = owner.report_entry(now, &observed);
                    let adopted = duties.read.as_ref().map(|read| read.version());
                    let returned = (duties.set_here(), duties.writing, duties.stepping);
                    let publish_due = duties.capture.as_ref().unwrap().publish_due;
                    let checks = [
                        ("the read", adopted == Some(version), format!("{adopted:?}")),
                        (
                            "the set, writing, stepping",
                            returned == (true, false, false),
                            format!("{returned:?}"),
                        ),
                        (
                            "roll_due",
                            duties.roll_due() == flags,
                            format!("{}", duties.roll_due()),
                        ),
                        (
                            "publish_due",
                            publish_due == flags,
                            format!("{publish_due}"),
                        ),
                        (
                            "the stored signal",
                            duties.suffix_due().is_none(),
                            format!("{:?}", duties.suffix_due()),
                        ),
                        (
                            "the entry's publication_due",
                            entry.as_ref().map(|entry| entry.publication_due) == Some(None),
                            format!("{:?}", entry.map(|entry| entry.publication_due)),
                        ),
                    ];
                    (checks.into_iter()).try_for_each(|(field, held, left)| match held {
                        true => Ok(()),
                        false => Err(format!("{field}: {left} with the flags {flags}")),
                    })
                }));
                Some(Exit::Stopped)
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
    });
    result.expect("the tenure opened")
}

/// A step that sampled no signal, as `suffix_step` returns when its one try of the capture mutex fails, still
/// returns its read and the set, and reports its signal as unavailable: `roll_due` and the capture's `publish_due`
/// keep their values, [`Duties::suffix_due`] reads `None`, and the report entry's `publication_due` reads
/// unavailable.
#[test]
fn a_step_that_sampled_no_signal_adopts_its_read_and_reads_its_signal_unavailable() {
    step_without_a_signal().unwrap_or_else(|failure| panic!("{failure}"));
}

/// Control for the absent signal, planted: duties that store a default signal for a step that sampled none read a
/// known signal with neither a handoff nor a publication due, and the check fails on the stored signal.
#[test]
fn duties_that_store_a_default_signal_for_a_step_that_sampled_none_fail_the_check() {
    DEFAULT_SIGNAL.with(|plant| plant.set(true));
    let failed = step_without_a_signal();
    DEFAULT_SIGNAL.with(|plant| plant.set(false));
    let failure = failed.expect_err("the check fails");
    assert_eq!(
        failure,
        "the stored signal: Some(SuffixDue { handoff: false, publication: false }) with the flags false"
    );
}
