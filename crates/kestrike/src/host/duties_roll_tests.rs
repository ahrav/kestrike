use std::cell::Cell;

use super::capture::{Pass, nanos};
use super::capture_tests::{CaptureDuties, shard_record};
use std::sync::atomic::Ordering;

use super::capture_tests::policy_every;
use super::step_tests::{
    Choices, Held, NEVER, Reached, cycle, run_cycle, step_duties, warm_objects,
};
use crate::failover::planned::{Deadline, ExitKind};
use crate::failover::records::ShardRecord;
use crate::failover::report::Resume;
use crate::failover::serving::{Cause, State};
use crate::host::Exit;
use crate::host::serve::loop_tests::staged_over;
use crate::host::serve::tests::warm_volume_certified;
use crate::net::PeerId;
use crate::storage::checkpoint::{PlacementRefusal, ReserveRefusal, StageRefusal};
use crate::storage::owner_fixture::set_clock;
use crate::storage::store::sim::{Arm, Shared};

thread_local! {
    static STARTED: Cell<Option<ExitKind>> = const { Cell::new(None) };
    static STARTS: Cell<u32> = const { Cell::new(0) };
}

thread_local! {
    pub(super) static STOPPED_OPEN: Cell<bool> = const { Cell::new(false) };
}

/// Whether the planted open stops on a `Chain` refusal of the suffix reservation, as a Confirm's refusal does.
pub(super) fn stopped_open() -> bool {
    STOPPED_OPEN.with(Cell::get)
}

thread_local! {
    static RESUMED: Cell<Option<Resume>> = const { Cell::new(None) };
}

pub(super) fn resumed(reason: Resume) {
    RESUMED.with(|cell| cell.set(Some(reason)));
}

pub(super) fn started(kind: ExitKind) {
    STARTED.with(|cell| cell.set(Some(kind)));
    STARTS.with(|cell| cell.set(cell.get() + 1));
}

/// Clears the started kind, the count of starts and the resume reason a test reads.
pub(super) fn reset() {
    STARTED.with(|cell| cell.set(None));
    STARTS.with(|cell| cell.set(0));
    RESUMED.with(|cell| cell.set(None));
}

/// The machines that started since the last [`reset`].
pub(super) fn starts() -> u32 {
    STARTS.with(Cell::get)
}

/// The kind of the last exit a machine started.
pub(super) fn started_kind() -> Option<ExitKind> {
    STARTED.with(Cell::get)
}

/// The reason of the last resume.
pub(super) fn resumed_reason() -> Option<Resume> {
    RESUMED.with(Cell::get)
}

/// A planted defect of the roll driver that a control runs a roll test against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Plant {
    /// The driver reads no queued PUT RESULT, so the roll leaves its stage 1 beside one.
    ResultsUnwaited,
    /// The driver withdraws where the machine resumes for the deadline.
    DeadlineWithdraws,
    /// The driver reads no queued result in stage 1 and withholds an acknowledged certify in `Sealed` while one is
    /// queued.
    SealedGate,
    /// The driver drops a seal whose one try of the capture mutex found it held, with no retry.
    SealDroppedWhenBusy,
    /// The driver feeds the closed log's evidence only at its own slot after the turn's clock reading, so a stop of
    /// mutations a later input of the turn returns reaches the next clock reading without it.
    UnopenedAtItsSlot,
    /// The driver holds every Publish outcome while a first PUT RESULT waits, one that resumes the tenure included.
    PublishOutcomesHeld,
    /// The driver's resume ends every session of the tenure in the turn it resumes.
    ResumeEndsSessions,
}

/// A capture mutex held across the first duties turn that a planned exit starts in `Sealed` (FP-HAND-06), and what
/// that turn and the turns after it showed. That turn's clock reading issues the machine's `Step::Seal`, and the
/// driver's one try of the mutex in the same turn finds it held.
#[derive(Debug, Default)]
pub(super) struct BusySeal {
    /// A turn that started in `Sealed` ran with the mutex held.
    held: bool,
    /// The seal stayed asked at the end of that turn.
    kept: bool,
    /// A later turn, with the mutex free, admitted the seal.
    retried: bool,
}

impl BusySeal {
    /// Whether the next turn runs with the capture mutex held: the drain is sealed and no earlier turn held it.
    pub(super) fn holds(&self, sealed: bool) -> bool {
        !self.held && sealed
    }

    /// Records a turn that ran with the mutex `held` and ended with the seal `asked`.
    pub(super) fn after(&mut self, held: bool, asked: bool) {
        if held {
            (self.held, self.kept) = (true, asked);
        } else if self.held && self.kept && !asked {
            self.retried = true;
        }
    }

    /// Each check that failed.
    pub(super) fn failures(&self) -> Vec<String> {
        [
            (
                self.held,
                "no turn started in Sealed with the capture mutex held",
            ),
            (
                self.kept,
                "the seal was dropped when the capture mutex was held",
            ),
            (self.retried, "no later turn admitted the seal"),
        ]
        .into_iter()
        .filter(|&(passed, _)| !passed)
        .map(|(_, failure)| failure.to_owned())
        .collect()
    }
}

thread_local! {
    static PLANTED: Cell<Option<Plant>> = const { Cell::new(None) };
}

/// Whether the running test planted `plant`.
pub(super) fn planted(plant: Plant) -> bool {
    PLANTED.with(Cell::get) == Some(plant)
}

pub(super) fn with_plant<T>(plant: Plant, f: impl FnOnce() -> T) -> T {
    PLANTED.with(|cell| cell.set(Some(plant)));
    let out = f();
    PLANTED.with(|cell| cell.set(None));
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trigger {
    Handoff,
    Slot,
    /// A placement refusal planted after the tenure's first Publish.
    Placement,
    /// A placement refusal planted before any Publish of the tenure, so the roll leaves the delta region to the next
    /// tenure as the earlier tenures left it.
    Early,
    /// No plant: the tenure's own failed capture passes exhaust the checkpoint slots.
    Closed,
    /// The planted abrupt roll: the tenure withdraws in the turn of an acknowledged mutation, before its block seals
    /// and with no certify.
    Abrupt,
    /// An authenticated request to transfer the shard to the standby the tenure's record names.
    Transfer,
    /// An authenticated request for a same-host restart.
    Requested,
    /// An authenticated request for a same-host restart, delivered to duties that hold no bound roll once the
    /// tenure's log has stayed closed and a capture start found no free checkpoint slot.
    RequestedClosed,
}

impl Trigger {
    pub(super) fn period(self) -> u64 {
        match self {
            Self::Slot => 1,
            Self::Placement => 1_000_000,
            Self::Handoff
            | Self::Early
            | Self::Closed
            | Self::Abrupt
            | Self::Transfer
            | Self::Requested
            | Self::RequestedClosed => NEVER,
        }
    }

    pub(super) fn plant(self, duties: &mut CaptureDuties<'_>) -> bool {
        match self {
            Self::Handoff | Self::Slot | Self::Closed | Self::Abrupt => true,
            Self::Transfer | Self::Requested | Self::RequestedClosed => {
                let Some(record) = duties.read.as_ref().map(|read| *read.value()) else {
                    return false;
                };
                let kind = match (self, record.standby) {
                    (Self::Transfer, Some(target)) => {
                        crate::failover::planned::Kind::Transfer { target }
                    }
                    (Self::Transfer, None) => return false,
                    _ => crate::failover::planned::Kind::Restart,
                };
                let bytes = super::transfer_tests::sealed(&record, kind, 1);
                duties.deliver(&bytes);
                true
            }
            Self::Placement | Self::Early => {
                let capture = duties.capture.as_ref().unwrap();
                let idle = matches!(capture.pass, Pass::Idle);
                let early = self == Self::Early || capture.published > 0;
                if !early || duties.writing || !idle || !duties.set_here() {
                    return false;
                }
                let placement = PlacementRefusal::Entries {
                    entries: 100,
                    cap: 82,
                };
                let refusal = StageRefusal::Reserve(ReserveRefusal::Placement(placement));
                let next = duties.stage_refused(1, refusal);
                duties.capture.as_mut().unwrap().pass = next;
                true
            }
        }
    }
}

pub(super) fn deadline() -> Deadline {
    Deadline::new(1 << 50).unwrap()
}

struct Rolled {
    kind: Option<ExitKind>,
    before: ShardRecord,
    rolled: ShardRecord,
    after: ShardRecord,
}

fn roll_then_restart(trigger: Trigger, seed: u64) -> Result<Rolled, String> {
    let volume = warm_volume_certified(0);
    let before = shard_record(&volume.0);
    let mut held: Held = warm_objects();
    let (mut choices, mut reached) = (Choices::of(seed), Reached::default());
    STARTED.with(|cell| cell.set(None));
    crate::host::serve::tests::inline(|| {
        let (volume, _, _) =
            run_cycle(volume, &mut held, &mut choices, &mut reached, Some(trigger))?;
        let kind = STARTED.with(Cell::get);
        let rolled = shard_record(&volume.0);
        let (volume, _, _) = cycle(volume, &mut held, &mut choices, &mut reached)?;
        let after = shard_record(&volume.0);
        Ok(Rolled {
            kind,
            before,
            rolled,
            after,
        })
    })
}

fn assert_rolled(trigger: Trigger) {
    let Rolled {
        kind,
        before,
        rolled,
        after,
    } = roll_then_restart(trigger, 7).unwrap_or_else(|failure| panic!("{trigger:?}: {failure}"));
    let publish = trigger == Trigger::Handoff;
    assert_eq!(
        kind,
        Some(ExitKind::Roll { publish }),
        "{trigger:?}: the roll's kind"
    );
    let kept = |record: &ShardRecord| (record.generation, record.active, record.owner);
    assert_eq!(
        kept(&rolled),
        kept(&before),
        "{trigger:?}: the roll keeps g, the volume and the owner"
    );
    assert_eq!(kept(&after), kept(&before), "{trigger:?}");
    assert_eq!(
        rolled.attempts,
        before.attempts + 1,
        "{trigger:?}: the rolled tenure's own restart is its one attempt"
    );
    assert_eq!(
        after.attempts,
        rolled.attempts + 1,
        "{trigger:?}: the restart runs at E + 1"
    );
    assert_eq!(
        rolled.standby, before.standby,
        "{trigger:?}: the roll names no other host"
    );
}

#[test]
fn a_roll_at_the_suffix_bound_restarts_at_e_plus_one_with_every_acknowledged_mutation() {
    assert_rolled(Trigger::Handoff);
}

#[test]
fn a_roll_with_no_free_slot_restarts_on_the_named_checkpoint_and_the_certified_suffix() {
    assert_rolled(Trigger::Slot);
}

#[test]
fn a_stage_refused_for_placement_rolls_to_a_restart_at_e_plus_one() {
    assert_rolled(Trigger::Placement);
}

#[test]
fn control_an_abrupt_roll_before_the_seal_loses_an_acknowledged_mutation() {
    let rolled = roll_then_restart(Trigger::Abrupt, 7);
    let failure = rolled
        .err()
        .expect("FP-HAND-09: the abrupt roll retained every acknowledged mutation");
    assert!(failure.contains(": served "), "{failure}");
}

/// Runs a tenure whose roll is due from its first turn, with `act` called after each turn, and returns its exit.
fn rolled_tenure(
    mut act: impl FnMut(
        &mut CaptureDuties<'_>,
        &mut crate::host::serve::loop_tests::TestOwner<'_>,
        &Shared,
        u64,
    ),
) -> Exit {
    staged_over(warm_volume_certified(0), |mut stage| {
        let store = stage.store.clone();
        let mut duties = step_duties(&stage, Some(policy_every(NEVER))).rolling(deadline());
        let storage = stage.storage;
        let (turns, mut raised) = (Cell::new(0), false);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                turns.set(turns.get() + 1);
                let turn = turns.get();
                if duties.open() == super::Open::Opened && !raised {
                    (duties.roll_due, raised) = (true, true);
                }
                let exit = duties.turn(owner, now);
                if exit == Some(Exit::Rerun(crate::host::Rerun::Planned)) {
                    let report = owner.authority_report();
                    assert_eq!(
                        (report.state, report.withdrawal, report.flip),
                        (State::Withdrawn, Some(Cause::Planned), None),
                        "the roll withdrew for Cause::Planned with no flip"
                    );
                }
                set_clock(storage, &[Some(nanos(now))]);
                act(&mut duties, owner, &store, turn);
                exit
            },
        );
        served.exit
    })
}

/// A tenure whose stored shard record names no standby: its handoff raises `roll_due` and no roll starts, no drain
/// stage begins and no attempt is consumed while the record stays unnamed. At the bound of J blocks the log refuses
/// an append `Exhausted`, a FILL is refused `History` before its acknowledgment and its key answers missing, an
/// INVALIDATE is refused, and GET hits return the warm object's bytes. The standby is then named by a raw store
/// write, and the roll starts only after that write, from a later view, and ends the tenure with `Rerun::Planned`.
/// Returns each check that failed.
fn unnamed_until_the_bound() -> Vec<String> {
    use super::step_tests::Churn;
    use crate::failover::takeover::tests::designate;
    use crate::net::{Outcome as Fetched, SessionState};
    use crate::storage::warm_sim::{object_key, region};
    use crate::storage::{FillPublishError, InvalidateError, SuffixRefusal, WorkBudget};
    use std::cell::RefCell;

    let volume = warm_volume_certified(0);
    let standby = shard_record(&volume.0).standby;
    assert!(standby.is_some(), "the fixture names a standby");
    designate(&volume.0, None);
    STARTED.with(|cell| cell.set(None));
    let failures = RefCell::new(Vec::new());
    let failed = |failure: String| {
        let mut failures = failures.borrow_mut();
        if !failures.contains(&failure) {
            failures.push(failure);
        }
    };
    staged_over(volume, |mut stage| {
        let store = stage.store.clone();
        let attempts = shard_record(&store).attempts;
        let mut duties = step_duties(&stage, Some(policy_every(NEVER))).rolling(deadline());
        let storage = stage.storage;
        let mut churn = Churn::new();
        // The keys the GETs at the bound read: a warm object, then the key of the last refused FILL.
        let reads = RefCell::new(Vec::<(u8, Option<Vec<u8>>)>::new());
        let pending = RefCell::new(None);
        let served = Cell::new(0_usize);
        let (named_at, started) = (Cell::new(None::<u64>), Cell::new(None::<u64>));
        let (mut turn, mut raised, mut at_bound) = (0_u64, false, None);
        let (ended, _) = stage.serve_until(
            |rounds, _, _| {
                let reads = reads.borrow();
                let Some((n, wanted)) = reads.get(served.get()) else {
                    return;
                };
                let mut pending = pending.borrow_mut();
                let active = rounds.client.borrow().state() == SessionState::Active;
                if active && pending.is_none() {
                    *pending = Some((rounds.get(*n), Vec::new()));
                }
                if let Some((id, bytes)) = pending.as_mut()
                    && let Some(outcome) = rounds.fetched(*id, bytes)
                {
                    let answered = match (outcome, wanted) {
                        (Fetched::Complete, Some(wanted)) => bytes == wanted,
                        (Fetched::Missing, None) => true,
                        _ => false,
                    };
                    if !answered {
                        failed(format!("object {n} at the bound: {outcome:?}, {bytes:?}"));
                    }
                    served.set(served.get() + 1);
                    *pending = None;
                }
            },
            |owner, now| {
                turn += 1;
                let exit = duties.turn(owner, now);
                let unnamed = named_at.get().is_none();
                let rolled = duties.roll_active() || owner.draining().is_some();
                if unnamed && (rolled || STARTED.with(Cell::get).is_some()) {
                    failed("FP-HAND-09: a roll started with no named standby (O-9)".to_owned());
                }
                if unnamed && shard_record(&store).attempts != attempts {
                    failed("the unnamed tenure consumed an attempt".to_owned());
                }
                if unnamed && exit.is_some() {
                    failed(format!("the unnamed tenure ended {exit:?}"));
                }
                if raised && unnamed && !duties.roll_due() {
                    failed("roll_due cleared with no roll".to_owned());
                }
                if !raised && duties.roll_due() {
                    raised = true;
                    if !duties.suffix_due().is_some_and(|due| due.handoff) {
                        failed("roll_due rose without the handoff".to_owned());
                    }
                }
                if !unnamed && duties.roll_active() && started.get().is_none() {
                    started.set(Some(turn));
                }
                if duties.open() != super::Open::Opened || !unnamed {
                    return exit;
                }
                if at_bound.is_none() {
                    churn.step(owner, storage, now);
                    let recorded = storage.with_suffix(|log| log.recorded()).unwrap();
                    let head = storage.with_suffix(|log| log.head()).unwrap();
                    if raised && churn.refusing >= 4 && head == recorded.start + region() {
                        let mut budget = WorkBudget::new(1 << 20);
                        let removal = owner.invalidate(&object_key(1), 4, &mut budget);
                        let refused = churn.refused.last().copied();
                        at_bound = Some((storage.probe_append(nanos(now)), removal.err(), refused));
                        let warm = (1, Some(super::capture_tests::replaced(1)));
                        let key = churn.refused_key.expect("a refused FILL");
                        reads.replace(vec![warm, (key, None)]);
                    }
                } else if served.get() == reads.borrow().len() {
                    designate(&store, standby);
                    named_at.set(Some(turn));
                }
                exit
            },
        );
        let Some((appended, removal, refused)) = at_bound else {
            failed("the log never reached the bound".to_owned());
            return;
        };
        if appended != Some(Err(SuffixRefusal::Exhausted)) {
            failed(format!("an append at the bound returned {appended:?}"));
        }
        if refused != Some(FillPublishError::History) || removal != Some(InvalidateError::History) {
            failed(format!(
                "at the bound a FILL refused {refused:?}, an INVALIDATE {removal:?}"
            ));
        }
        let (named_at, started) = (named_at.get(), started.get());
        if named_at.is_none() || started <= named_at {
            failed(format!(
                "named at turn {named_at:?}, the roll started at {started:?}"
            ));
        }
        if ended.exit != Exit::Rerun(crate::host::Rerun::Planned) {
            failed(format!("the tenure ended {:?}", ended.exit));
        }
    });
    failures.into_inner()
}

#[test]
fn a_tenure_with_no_named_standby_starts_no_roll_until_a_read_names_one() {
    let failures = unnamed_until_the_bound();
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn control_a_roll_without_a_named_standby_fails_the_no_standby_test() {
    use crate::failover::planned::machine::tests::{Plant, with_plant};
    let failures = with_plant(Plant::StandbyIgnored, unnamed_until_the_bound);
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("FP-HAND-09:")),
        "{failures:#?}"
    );
}

/// The Publish that drops the tenure's suffix from the record at the log's bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dropped {
    /// The time ceiling triggers the capture pass that drops the tenure's suffix.
    Ceiling,
    /// The roll's own Publish cuts at the bound, and a store outage then fails the roll's certify.
    Outage,
}

/// Both cases wait until the log's head reaches its bound before naming the standby. `Dropped::Ceiling` also waits
/// until the stored record shows the cut at that bound with the tenure's suffix dropped. While the roll is sealed and
/// the test awaits resumption, `Dropped::Outage` schedules three unavailable store responses per turn to cover two
/// view reads and the certify write.
fn rolled_after_a_cut_at_the_bound(dropped: Dropped) -> Vec<String> {
    use super::step_tests::Churn;
    use crate::failover::takeover::tests::designate;

    /// The wait budget in turns. It restarts when the test observes the bound and again when it names the standby.
    const PATIENCE: u64 = 4_000;
    let volume = warm_volume_certified(0);
    let standby = shard_record(&volume.0).standby;
    assert!(standby.is_some(), "the fixture names a standby");
    designate(&volume.0, None);
    RESUMED.with(|cell| cell.set(None));
    let stalled = Cell::new(false);
    staged_over(volume, |mut stage| {
        let store = stage.store.clone();
        let ceiling = match dropped {
            Dropped::Ceiling => 20_000_000,
            Dropped::Outage => NEVER,
        };
        let mut duties = step_duties(&stage, Some(policy_every(ceiling))).rolling(deadline());
        let storage = stage.storage;
        let mut churn = Churn::new();
        let (mut turn, mut waiting_from) = (0_u64, 0_u64);
        let (mut bound, mut named, mut resumed) = (None::<u64>, false, None::<bool>);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if stalled.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                turn += 1;
                let outage = dropped == Dropped::Outage && resumed.is_none();
                if outage && duties.roll_sealed() {
                    store.0.borrow_mut().unschedule();
                    for _ in 0..3 {
                        store.schedule(Arm::Unavailable);
                    }
                }
                let exit = duties.turn(owner, now);
                store.0.borrow_mut().unschedule();
                let session = owner.tenure().get();
                let record = shard_record(&store);
                let own =
                    (record.ancestry.as_slice().iter()).any(|suffix| suffix.session == session);
                if outage && RESUMED.with(Cell::get).is_some() {
                    resumed = Some(!own);
                }
                if duties.open() != super::Open::Opened {
                    return exit;
                }
                let Some(bound) = bound else {
                    churn.step(owner, storage, now);
                    let reached = storage.with_suffix(|log| (log.head(), log.bound()));
                    if let Ok((head, end)) = reached
                        && churn.refusing >= 4
                        && head == end
                    {
                        (bound, waiting_from) = (Some(end), turn);
                    }
                    return exit;
                };
                let cut = !own && record.cut == bound;
                if !named && (dropped == Dropped::Outage || cut) {
                    designate(&store, standby);
                    (named, waiting_from) = (true, turn);
                }
                stalled.set(turn > waiting_from + PATIENCE);
                exit
            },
        );
        let mut failures = Vec::new();
        if bound.is_none() {
            failures.push("the log stayed below the bound".to_owned());
        }
        if !named {
            failures.push("the record kept the tenure's suffix at the bound".to_owned());
        }
        if dropped == Dropped::Outage && resumed != Some(true) {
            failures.push(format!(
                "the outage resumed the roll over a record that dropped the tenure's suffix: {resumed:?}"
            ));
        }
        if served.exit != Exit::Rerun(crate::host::Rerun::Planned) {
            failures.push(format!("the tenure at its bound ended {:?}", served.exit));
        }
        failures
    })
}

#[test]
fn a_tenure_whose_publish_cut_at_the_bound_rolls_once_a_read_names_a_standby() {
    let failures = rolled_after_a_cut_at_the_bound(Dropped::Ceiling);
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_roll_whose_publish_cut_at_the_bound_runs_again_after_a_lost_certify() {
    let failures = rolled_after_a_cut_at_the_bound(Dropped::Outage);
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_roll_s_certify_waits_for_the_page_completion_in_flight() {
    use super::cover_tests::{entry, exclusive, hold, key_on, pages};

    const SEALED_TURNS_HELD: u32 = 4;
    let (mut in_flight, mut sealed) = (false, 0_u32);
    let exit = staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, Some(policy_every(NEVER))).rolling(deadline());
        let storage = stage.storage;
        let (mut turn, mut held, mut planted) = (0_u32, false, false);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                turn += 1;
                assert!(turn < 20_000, "the roll stalled");
                set_clock(storage, &[Some(nanos(now))]);
                let session = owner.tenure().get();
                let viewed = duties.rolling.as_ref().and_then(|roll| roll.viewed);
                let own = viewed.is_some_and(|record| {
                    (record.ancestry.as_slice().iter()).any(|suffix| suffix.session == session)
                });
                if own && !held {
                    let pages = pages(owner);
                    hold(owner, entry(key_on(0, pages, 0)));
                    duties.lane.inline_mut().hold();
                    held = true;
                }
                let exit = duties.turn(owner, now);
                exclusive(&duties);
                in_flight |= held && duties.paging && duties.lane.inline_mut().held() > 0;
                if in_flight && !planted {
                    planted = Trigger::Early.plant(&mut duties);
                }
                sealed += u32::from(duties.roll_sealed());
                if sealed == 1 {
                    assert!(
                        duties.paging,
                        "the page write is in flight at the stop of mutations"
                    );
                }
                if !in_flight || sealed >= SEALED_TURNS_HELD {
                    while duties.lane.inline_mut().release() {}
                }
                exit
            },
        );
        served.exit
    });
    assert!(in_flight, "a page write was in flight before the roll");
    assert!(
        sealed >= SEALED_TURNS_HELD,
        "the roll sealed {sealed} turns"
    );
    assert_eq!(exit, Exit::Rerun(crate::host::Rerun::Planned));
}

/// A roll's certify waits for an idle lane: a view that falls due after the roll's start goes out first and its
/// completion stays on the lane, and the sealed roll submits no certify while that view is unadopted, so a certify
/// is the lane's one outstanding job at its submit. The certify goes out once the view is adopted, and the roll
/// ends the tenure with `Rerun::Planned`.
#[test]
fn a_roll_s_certify_waits_for_the_adoption_of_a_view() {
    const SEALED_TURNS_HELD: u32 = 4;
    let (mut beside, mut sealed) = (false, 0_u32);
    let exit = staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, Some(policy_every(NEVER))).rolling(deadline());
        let storage = stage.storage;
        let (mut turn, mut planted, mut held) = (0_u32, false, false);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                turn += 1;
                assert!(turn < 20_000, "the roll stalled");
                set_clock(storage, &[Some(nanos(now))]);
                if duties.open() == super::Open::Opened && !planted {
                    planted = Trigger::Early.plant(&mut duties);
                }
                if duties.roll_active() && !held && duties.lane.outstanding() == 0 {
                    duties.view_at = now;
                    duties.lane.inline_mut().hold();
                    held = true;
                }
                let exit = duties.turn(owner, now);
                // From `Sealed` the suffix step pauses, so `stepping` marks the certify.
                let certifying = duties.roll_sealed() && duties.stepping;
                beside |= certifying && duties.lane.outstanding() > 1;
                if held && duties.viewing.is_some() {
                    sealed += u32::from(duties.roll_sealed());
                }
                if sealed >= SEALED_TURNS_HELD {
                    while duties.lane.inline_mut().release() {}
                }
                exit
            },
        );
        served.exit
    });
    assert!(
        sealed >= SEALED_TURNS_HELD,
        "the roll sealed {sealed} turns beside the unadopted view"
    );
    assert!(!beside, "a certify beside another unadopted job");
    assert_eq!(exit, Exit::Rerun(crate::host::Rerun::Planned));
}

/// When the link toward the client admits sends again in a roll beside a queued PUT RESULT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opens {
    /// After the roll held its stage 1 for this many turns.
    InStageOne(u32),
    /// On the turn after the roll resumed.
    AfterTheResume,
}

/// A roll beside a published wire fill whose first PUT RESULT waits behind blocked sends: the client uploads an
/// empty object, sends toward it block once it holds the owner's READY, the fill publishes, and the tenure then
/// raises a roll with or without a capture (`publish`) under a deadline of `cap_us`. The link opens as `opens` says.
/// Checks RESULT-BEFORE-WITHDRAWAL: the roll holds stage 1 while the result waits, leaves it only after a send took
/// the result, and resumes for the deadline with `E`, the sessions and the authority unchanged when the link stays
/// blocked that long. The client's upload ends `Published` and the tenure `Rerun::Planned`. Returns each check that
/// failed.
fn roll_beside_a_queued_result(publish: bool, opens: Opens, cap_us: u64) -> Vec<String> {
    roll_beside_a_queued_result_left(publish, opens, cap_us).0
}

/// The first turn after a roll started on which the authority left `Serving`: that turn's clock reading less the
/// roll's deadline, whether a first PUT RESULT waited before that turn's duties ran, and the withdrawal's cause.
type LeftServing = (i128, bool, Option<Cause>);

/// [`roll_beside_a_queued_result`] with the first turn after the roll started on which the authority left `Serving`:
/// that turn's clock reading less the roll's deadline, whether a first PUT RESULT waited before that turn's duties
/// ran, and the withdrawal's cause.
fn roll_beside_a_queued_result_left(
    publish: bool,
    opens: Opens,
    cap_us: u64,
) -> (Vec<String>, Option<LeftServing>) {
    use crate::net::link::Faults;
    use crate::net::{DrainStage, SessionState, UploadOutcome};
    use crate::storage::CacheVersion;
    use std::cell::RefCell;

    const FILLED: u8 = 200;
    RESUMED.with(|cell| cell.set(None));
    STARTED.with(|cell| cell.set(None));
    let failures = RefCell::new(Vec::<String>::new());
    let fail = |failure: String| failures.borrow_mut().push(failure);
    let upload = Cell::new(None);
    let (prepared, open, outcome) = (Cell::new(false), Cell::new(false), Cell::new(None));
    let blocked = Faults {
        would_block: 100,
        ..Faults::default()
    };
    let exit = staged_over(warm_volume_certified(0), |mut stage| {
        let deadline = Deadline::new(cap_us).unwrap();
        let mut duties = step_duties(&stage, Some(policy_every(NEVER))).rolling(deadline);
        let storage = stage.storage;
        let (mut raised, mut held, mut left, mut resumed) = (false, 0_u32, false, false);
        let (mut before, mut started_at) = (None, None::<u64>);
        let mut left_serving = None;
        let (served, _) = stage.serve_until(
            |rounds, turn, _| {
                let now = turn * crate::host::serve::loop_tests::ROUND_US;
                let mut client = rounds.client.borrow_mut();
                if upload.get().is_none() && client.state() == SessionState::Active {
                    let key = crate::storage::warm_sim::object_key(FILLED);
                    upload.set(client.put(key, CacheVersion(0), now, 30_000_000).ok());
                }
                if let Some(id) = upload.get() {
                    if !prepared.get() && client.prepare(id, 0, 0, 60_000).is_ok() {
                        prepared.set(true);
                        rounds.fault_toward_client(blocked);
                    }
                    if outcome.get().is_none() {
                        outcome.set(client.put_outcome(id));
                    }
                }
                if open.replace(false) {
                    rounds.fault_toward_client(Faults::default());
                }
            },
            |owner, now| {
                set_clock(storage, &[Some(nanos(now))]);
                let epochs = [0, 1].map(|peer| owner.session_epoch(PeerId(peer)));
                if owner.put_results_queued() && !raised {
                    raised = match publish {
                        true => {
                            duties.roll_due = duties.open() == super::Open::Opened;
                            duties.roll_due
                        }
                        false => Trigger::Early.plant(&mut duties),
                    };
                    before = raised.then(|| (owner.tenure().target(), epochs));
                }
                let owed_before = owner.put_results_queued();
                let exit = duties.turn(owner, now);
                if duties.roll_active() {
                    started_at.get_or_insert(now);
                }
                let report = owner.authority_report();
                if raised && left_serving.is_none() && report.state != State::Serving {
                    let due = started_at.map_or(0, |at| at + cap_us);
                    left_serving = Some((
                        i128::from(now) - i128::from(due),
                        owed_before,
                        report.withdrawal,
                    ));
                }
                let owed = owner.put_results_queued();
                let stage = owner.draining();
                if raised && !left && (stage == Some(DrainStage::Mutations) || exit.is_some()) {
                    left = true;
                    if owed {
                        fail("RESULT-BEFORE-WITHDRAWAL: the roll left stage 1 beside a queued result".into());
                    }
                }
                if stage == Some(DrainStage::Fills) && owed {
                    held += 1;
                    if opens == Opens::InStageOne(held) {
                        open.set(true);
                    }
                }
                if let Some(reason) = RESUMED.with(Cell::take)
                    && !resumed
                {
                    resumed = true;
                    let report = owner.authority_report();
                    // The sessions are sampled after the turn that resumed.
                    let after = [0, 1].map(|peer| owner.session_epoch(PeerId(peer)));
                    let kept = after[0].is_some() && Some((owner.tenure().target(), after)) == before;
                    if reason != Resume::Deadline
                        || report.state != State::Serving
                        || stage.is_some()
                        || !kept
                        || !owed
                    {
                        fail(format!(
                            "the resume: {reason:?}, {:?}, stage {stage:?}, tenure and sessions kept {kept}, \
                             result queued {owed}",
                            report.state
                        ));
                    }
                    // The machine's deadline is the roll's start plus the cap; the resume comes on the first turn
                    // at or past it.
                    let due = started_at.map(|at| at + cap_us);
                    let round = crate::host::serve::loop_tests::ROUND_US;
                    if !due.is_some_and(|due| (due..due + round).contains(&now)) {
                        fail(format!("the resume came at {now}; the deadline is {due:?}"));
                    }
                    started_at = None;
                    open.set(opens == Opens::AfterTheResume);
                }
                exit
            },
        );
        if (opens == Opens::AfterTheResume) != resumed {
            fail(format!(
                "RESULT-BEFORE-WITHDRAWAL: the roll resumed: {resumed}, after holding stage 1 for {held} turns"
            ));
        }
        if held == 0 {
            fail("the roll never held stage 1 beside the queued result".into());
        }
        (served.exit, left_serving)
    });
    let (exit, left_serving) = exit;
    let started = STARTED.with(Cell::get);
    if started != Some(ExitKind::Roll { publish }) {
        fail(format!("the roll started as {started:?}"));
    }
    if outcome.get() != Some(UploadOutcome::Published) {
        fail(format!("the client's upload ended {:?}", outcome.get()));
    }
    if exit != Exit::Rerun(crate::host::Rerun::Planned) {
        fail(format!("the tenure ended {exit:?}"));
    }
    (failures.into_inner(), left_serving)
}

/// A roll, with and without a capture, holds its stage 1 while a published fill's first PUT RESULT waits behind
/// blocked sends, leaves it once a send took the result, and ends the tenure with the client's upload `Published`.
#[test]
fn a_roll_holds_stage_one_until_a_queued_put_result_is_sent() {
    for publish in [true, false] {
        let failures = roll_beside_a_queued_result(publish, Opens::InStageOne(40), 1 << 50);
        assert!(failures.is_empty(), "publish {publish}: {failures:#?}");
    }
}

/// The control: a driver that reads no queued result leaves stage 1 beside one and withdraws with it unsent, so the
/// client's upload never reads `Published`.
#[test]
fn control_a_roll_that_reads_no_queued_result_leaves_stage_one_beside_it() {
    for publish in [true, false] {
        let failures = with_plant(Plant::ResultsUnwaited, || {
            roll_beside_a_queued_result(publish, Opens::InStageOne(40), 1 << 50)
        });
        let left = "RESULT-BEFORE-WITHDRAWAL: the roll left stage 1 beside a queued result";
        assert!(
            failures.iter().any(|failure| failure == left),
            "publish {publish}: {failures:#?}"
        );
    }
}

/// The deadline of a roll's stage 1 beside a queued result.
const STAGE_ONE_CAP_US: u64 = 400 * crate::host::serve::loop_tests::ROUND_US;

/// A link that stays blocked to the roll's deadline resumes the tenure in place: the reason is `deadline`,
/// admission reopens, the authority stays `Serving`, and `E` and the sessions are unchanged. The result is sent
/// once the link opens, and the due roll then runs again and ends the tenure.
#[test]
fn a_roll_whose_queued_put_result_outlasts_the_deadline_resumes_in_place() {
    for publish in [true, false] {
        let failures =
            roll_beside_a_queued_result(publish, Opens::AfterTheResume, STAGE_ONE_CAP_US);
        assert!(failures.is_empty(), "publish {publish}: {failures:#?}");
    }
}

/// The control: a driver that withdraws where the machine resumes for the deadline ends the tenure with the result
/// unsent and no resume. The authority leaves `Serving` for `Cause::Planned` on the first turn at or past the roll's
/// deadline, with the result queued before that turn's duties ran, and the tenure ends `Rerun::Planned`.
#[test]
fn control_a_roll_that_withdraws_at_the_deadline_abandons_the_queued_result() {
    let round = i128::from(crate::host::serve::loop_tests::ROUND_US);
    for publish in [true, false] {
        let (failures, left) = with_plant(Plant::DeadlineWithdraws, || {
            roll_beside_a_queued_result_left(publish, Opens::AfterTheResume, STAGE_ONE_CAP_US)
        });
        let (late, owed, cause) = left.expect("the authority left Serving");
        assert!(
            (0..round).contains(&late),
            "publish {publish}: withdrew {late} us past the deadline"
        );
        assert!(
            owed,
            "publish {publish}: no result waited at the withdrawal"
        );
        assert_eq!(cause, Some(Cause::Planned), "publish {publish}");
        assert!(
            !failures
                .iter()
                .any(|failure| failure.starts_with("the roll never held stage 1")
                    || failure.starts_with("the tenure ended")),
            "publish {publish}: {failures:#?}"
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure
                    .starts_with("RESULT-BEFORE-WITHDRAWAL: the roll resumed: false")),
            "publish {publish}: {failures:#?}"
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.starts_with("the client's upload ended")),
            "publish {publish}: {failures:#?}"
        );
    }
}

/// A certify the store refuses as unavailable resumes the tenure in place: admission reopens, `E` and the sessions
/// are unchanged, and the due roll starts again and ends the tenure.
#[test]
fn a_certify_lost_to_a_store_outage_resumes_in_place_and_the_roll_runs_again() {
    RESUMED.with(|cell| cell.set(None));
    let (armed, resumed) = (Cell::new(false), Cell::new(false));
    let (attempts, sessions) = (Cell::new(None), Cell::new(None));
    let exit = rolled_tenure(|duties, owner, store, _| {
        let epochs = [0, 1].map(|peer| owner.session_epoch(PeerId(peer)));
        if !duties.roll_active() && !armed.get() {
            attempts.set(Some(shard_record(store).attempts));
            sessions.set(Some(epochs));
        }
        if !armed.get() && duties.roll_sealed() {
            store.schedule(Arm::Unavailable);
            armed.set(true);
        }
        if armed.get() && !resumed.get() && !duties.roll_active() {
            resumed.set(true);
            assert_eq!(owner.draining(), None, "admission reopened");
            assert_eq!(
                Some(shard_record(store).attempts),
                attempts.get(),
                "E is unchanged"
            );
            assert!(epochs.iter().any(Option::is_some), "a session is active");
            assert_eq!(Some(epochs), sessions.get(), "every session kept its epoch");
        }
    });
    assert!(resumed.get(), "the outage resumed the roll");
    assert_eq!(RESUMED.with(Cell::get), Some(Resume::Store));
    assert_eq!(exit, Exit::Rerun(crate::host::Rerun::Planned));
}

/// A suffix step whose one try of the capture mutex finds it held samples no signal, and the duties store none: such
/// a step leaves `roll_due` as it was. Before the roll is due, steps run with the mutex held start no roll; once the
/// roll is active, a step run with the mutex held before the seal leaves the roll and `roll_due` in place, and the
/// roll ends the tenure with `Rerun::Planned`.
#[test]
fn a_step_that_finds_the_capture_mutex_held_starts_no_roll_and_cancels_none() {
    STARTED.with(|cell| cell.set(None));
    let (unsampled, during_roll) = staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, Some(policy_every(NEVER))).rolling(deadline());
        let storage = stage.storage;
        let (mut unsampled, mut during_roll, mut submitted) = (0_u32, 0_u32, false);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let opened = duties.open() == super::Open::Opened && duties.due.is_some();
                // Each turn of a window runs with the capture mutex held, so a step it submits finds it held.
                let window = opened
                    && match duties.roll_active() {
                        false => unsampled < 2,
                        true => during_roll == 0 && !duties.roll_sealed(),
                    };
                let stepping = duties.stepping;
                let exit = match window {
                    true => storage
                        .with_suffix(|_| duties.turn(owner, now))
                        .expect("the capture mutex"),
                    false => duties.turn(owner, now),
                };
                if submitted && stepping && !duties.stepping {
                    submitted = false;
                    assert_eq!(
                        duties.due, None,
                        "a step that found the mutex held stores no signal"
                    );
                    match duties.roll_active() {
                        false => {
                            unsampled += 1;
                            assert!(!duties.roll_due(), "an unsampled step raised roll_due");
                            assert_eq!(
                                STARTED.with(Cell::get),
                                None,
                                "an unsampled step started a roll"
                            );
                            if unsampled == 2 {
                                duties.roll_due = true;
                            }
                        }
                        true => {
                            during_roll += 1;
                            assert!(duties.roll_due(), "an unsampled step cleared roll_due");
                        }
                    }
                }
                submitted |= window && !stepping && duties.stepping;
                set_clock(storage, &[Some(nanos(now))]);
                exit
            },
        );
        assert_eq!(served.exit, Exit::Rerun(crate::host::Rerun::Planned));
        (unsampled, during_roll)
    });
    assert_eq!(
        unsampled, 2,
        "two steps ran with the mutex held before the roll was due"
    );
    assert_eq!(
        during_roll, 1,
        "a step ran with the mutex held during the roll"
    );
    assert!(STARTED.with(Cell::get).is_some(), "the roll started");
}

/// A bound roll, raised by a placement refusal planted before the tenure's first Publish, whose first turn in `Sealed`
/// runs with the capture mutex held: returns each check
/// of [`BusySeal`] that failed, and a failure when the tenure ends otherwise than `Rerun::Planned`.
fn roll_under_a_busy_seal() -> Vec<String> {
    let mut busy = BusySeal::default();
    let exit = staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, Some(policy_every(NEVER))).rolling(deadline());
        let storage = stage.storage;
        let (mut turn, mut planted) = (0_u32, false);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                turn += 1;
                assert!(turn < 20_000, "the roll stalled");
                set_clock(storage, &[Some(nanos(now))]);
                if duties.open() == super::Open::Opened && !planted {
                    planted = Trigger::Early.plant(&mut duties);
                }
                let held = busy.holds(duties.roll_sealed());
                let exit = match held {
                    true => storage
                        .with_suffix(|_| duties.turn(owner, now))
                        .expect("the capture mutex"),
                    false => duties.turn(owner, now),
                };
                busy.after(held, duties.roll_seal_asked());
                exit
            },
        );
        served.exit
    });
    let mut failures = busy.failures();
    if exit != Exit::Rerun(crate::host::Rerun::Planned) {
        failures.push(format!("the roll ended {exit:?}"));
    }
    failures
}

/// FP-HAND-06 under a busy capture mutex: a bound roll whose seal, asked on its first turn in `Sealed`, finds the
/// capture mutex held keeps that seal asked, a later turn admits it, and the roll ends the tenure with
/// `Rerun::Planned`.
#[test]
fn a_roll_s_seal_that_finds_the_capture_mutex_held_is_admitted_on_a_later_turn() {
    let failures = roll_under_a_busy_seal();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The control: a driver that drops a seal whose try of the capture mutex found it held fails the check.
#[test]
fn control_a_dropped_seal_under_a_busy_capture_mutex_fails_the_roll_s_check() {
    let failures = with_plant(Plant::SealDroppedWhenBusy, roll_under_a_busy_seal);
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("the seal was dropped")),
        "{failures:#?}"
    );
}

/// A roll's certify that commits while the watermark log fails to record the raised mark withdraws the store client,
/// and the turn that adopts the certify's completion ends the incarnation with `Rerun::Withdrawn`, as a suffix
/// step's adoption does.
#[test]
fn a_certify_that_withdraws_the_client_ends_the_incarnation_at_its_adoption() {
    use crate::host::lane::Lane;
    use crate::host::{HostGate, Rerun};
    use crate::storage::EngineBudget;
    use crate::storage::store::Client;
    use crate::storage::store::sim::MemLog;
    use std::num::NonZeroU64;
    let (exit, adopted, exited) = staged_over(warm_volume_certified(0), |mut stage| {
        let log = MemLog::default();
        let fails = log.fail.clone();
        let client = Client::open(stage.store.clone(), log).unwrap();
        let periods =
            super::tests::periods().with_step(NonZeroU64::new(super::step_tests::STEP_US).unwrap());
        let duties = super::Duties::new(
            (
                &HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            Lane::inline(client, stage.storage),
            super::tests::records(),
            None,
            super::step_tests::wide(),
            periods,
        );
        let mut duties = (duties.capturing(policy_every(NEVER), EngineBudget::unlimited()))
            .unwrap()
            .rolling(deadline());
        let storage = stage.storage;
        let (mut raised, mut armed, mut submitted) = (false, false, false);
        let (mut turn, mut adopted, mut exited) = (0_u64, None, None);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                turn += 1;
                if duties.open() == super::Open::Opened && !raised {
                    (duties.roll_due, raised) = (true, true);
                }
                // From `Sealed` the next shard-record write is the certify; the log fails to record its mark.
                if !armed && duties.roll_sealed() && !duties.stepping {
                    fails.set(true);
                    armed = true;
                }
                let stepping = duties.stepping;
                let exit = duties.turn(owner, now);
                set_clock(storage, &[Some(nanos(now))]);
                if armed && !stepping && duties.stepping {
                    submitted = true;
                }
                if submitted && stepping && !duties.stepping && adopted.is_none() {
                    adopted = Some(turn);
                }
                if exit.is_some() && exited.is_none() {
                    exited = Some(turn);
                }
                exit
            },
        );
        (served.exit, adopted, exited)
    });
    assert_eq!(exit, Exit::Rerun(Rerun::Withdrawn));
    let adopted = adopted.expect("the certify went out and its completion was adopted");
    assert_eq!(
        exited,
        Some(adopted),
        "the adopting turn ends the incarnation"
    );
}

/// A roll whose owner withdraws with `Cause::Unheld` after the roll stopped mutations and before its certify went out
/// submits no certify: the shard record takes no commit after the withdrawal while the owner keeps polling for three
/// view periods.
#[test]
fn a_roll_whose_owner_withdrew_submits_no_certify() {
    use crate::failover::serving::Event;
    use crate::host::duties::tests::TEST_VIEW_US as VIEW_US;
    use crate::storage::store::Key;
    use crate::storage::store_tests::shard;
    let (withdrawn, after) = staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, Some(policy_every(NEVER))).rolling(deadline());
        let storage = stage.storage;
        let shared = stage.store.clone();
        let commits = || shared.0.borrow().commit_count(&Key::Shard(shard()));
        let (mut raised, mut withdrawn, mut certifies) = (false, None, 0_u32);
        let ended = Cell::new(false);
        stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                if duties.open() == super::Open::Opened && !raised {
                    (duties.roll_due, raised) = (true, true);
                }
                let stepping = duties.stepping;
                let exit = duties.turn(owner, now);
                set_clock(storage, &[Some(nanos(now))]);
                match withdrawn {
                    None => {
                        let stopped = owner.draining() == Some(crate::net::DrainStage::Mutations);
                        if duties.roll_active() && stopped && duties.lane.outstanding() == 0 {
                            owner.authority_event(Event::Withdraw(Cause::Unheld), now);
                            withdrawn = Some((now, commits()));
                        }
                    }
                    Some((at, _)) => {
                        certifies += u32::from(!stepping && duties.stepping);
                        ended.set(now >= at + 3 * VIEW_US);
                    }
                }
                exit
            },
        );
        let (_, at_withdrawal) = withdrawn.expect("the roll stopped mutations");
        (certifies, commits() - at_withdrawal)
    });
    assert_eq!(withdrawn, 0, "certifies submitted after the withdrawal");
    assert_eq!(after, 0, "the shard record's commits after the withdrawal");
}

/// A roll whose tenure answers one GET of a warm object in each drain stage: once the owner reports a stage, the
/// client sends the GET, and the duties' turns wait until the client has its answer, so the roll stays in that
/// stage. Each GET returns the warm object's bytes, the stage holds until the answer arrives, and the roll then
/// ends the tenure with `Rerun::Planned`. Returns each check that failed.
fn hits_through_the_roll() -> Vec<String> {
    use crate::net::{DrainStage, Outcome as Fetched, RequestId, SessionState};
    use std::cell::RefCell;
    use std::sync::atomic::Ordering;

    let failures = RefCell::new(Vec::<String>::new());
    let reported = Cell::new(None::<DrainStage>);
    let pending = RefCell::new(None::<(DrainStage, RequestId, Vec<u8>)>);
    let witnessed = RefCell::new(Vec::<DrainStage>::new());
    let exit = staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, Some(policy_every(NEVER))).rolling(deadline());
        let storage = stage.storage;
        let mut raised = false;
        let (served, _) = stage.serve_until(
            |rounds, _, stop| {
                let mut pending = pending.borrow_mut();
                let active = rounds.client.borrow().state() == SessionState::Active;
                if let Some(drained) = reported.get()
                    && active
                    && pending.is_none()
                    && !witnessed.borrow().contains(&drained)
                {
                    *pending = Some((drained, rounds.get(1), Vec::new()));
                }
                if let Some((drained, id, bytes)) = pending.as_mut()
                    && let Some(outcome) = rounds.fetched(*id, bytes)
                {
                    let warm = super::capture_tests::replaced(1);
                    if outcome != Fetched::Complete || *bytes != warm {
                        let failure = format!(
                            "FP-HAND-05: {drained:?}: the GET ended {outcome:?}, {bytes:?}"
                        );
                        failures.borrow_mut().push(failure);
                        stop.store(true, Ordering::Release);
                    }
                    if reported.get() != Some(*drained) {
                        let failure = format!("{drained:?}: answered in {:?}", reported.get());
                        failures.borrow_mut().push(failure);
                    }
                    witnessed.borrow_mut().push(*drained);
                    *pending = None;
                }
            },
            |owner, now| {
                set_clock(storage, &[Some(nanos(now))]);
                if pending.borrow().is_some() {
                    return None;
                }
                if duties.open() == super::Open::Opened && !raised {
                    (duties.roll_due, raised) = (true, true);
                }
                let exit = duties.turn(owner, now);
                reported.set(owner.draining());
                exit
            },
        );
        served.exit
    });
    let mut failures = failures.into_inner();
    let witnessed = witnessed.into_inner();
    if witnessed != [DrainStage::Fills, DrainStage::Mutations] {
        failures.push(format!("GETs answered in {witnessed:?}"));
    }
    if exit != Exit::Rerun(crate::host::Rerun::Planned) {
        failures.push(format!("the tenure ended {exit:?}"));
    }
    failures
}

#[test]
fn a_roll_serves_a_get_in_each_drain_stage() {
    let failures = hits_through_the_roll();
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn control_a_drain_that_refuses_hits_fails_the_roll_s_get_test() {
    use crate::net::owner_drain_tests::{Plant, with_plant};
    let failures = with_plant(Plant::HitsRefused, hits_through_the_roll);
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("FP-HAND-05: Fills: the GET ended")),
        "{failures:#?}"
    );
}

/// A roll whose workload holds wire-style INVALIDATEs: before the roll and in its stage 1 the tenure holds one
/// interval entry every other turn, alternating between two coverage pages. Each entry the duties acknowledge is
/// acknowledged on a turn after a page commit later than its hold, with the stored page covering it, and no entry is
/// acknowledged once mutations stopped. Some entry is acknowledged in stage 1, some entry is still held when
/// mutations stop and stays unacknowledged, and the roll ends the tenure with `Rerun::Planned`. After the restart the
/// next tenure's coverage refuses a FILL of every acknowledged entry's versions. With `lost`, the first page write of
/// stage 1 is acknowledged by the store and never applied. Returns each check that failed.
fn held_invalidates_through_the_roll(lost: bool) -> Vec<String> {
    use super::cover_tests::{
        On, Paged, commits, entry, hold, key_on, pages, refused, stored_covers,
    };
    use super::step_tests::{STEP_US, step_duties_on};
    use crate::net::DrainStage;
    use crate::storage::page_coverage::Entry;
    use std::sync::atomic::Ordering;

    let mut failures = Vec::new();
    let mut acked = Vec::<Entry>::new();
    let (mut dropped, mut in_fills) = (0_usize, 0_usize);
    let (exit, volume) = staged_over(warm_volume_certified(0), |mut stage| {
        let store = stage.store.clone();
        let paged = Paged::over(&store);
        let policy = Some(policy_every(NEVER));
        let mut duties = step_duties_on(&stage, paged.clone(), policy, STEP_US).rolling(deadline());
        let storage = stage.storage;
        let mut held: Vec<(u16, Entry, usize)> = Vec::new();
        let (mut turn, mut raised, mut armed) = (0_u64, false, false);
        let mut reported = None::<DrainStage>;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                turn += 1;
                set_clock(storage, &[Some(nanos(now))]);
                let opened = duties.open() == super::Open::Opened;
                if opened && !raised {
                    (duties.roll_due, raised) = (true, true);
                }
                if opened && reported != Some(DrainStage::Mutations) && turn % 2 == 0 {
                    let pages = pages(owner);
                    let page = [0, pages.get() - 1][held.len() % 2];
                    let entry = entry(key_on(page, pages, held.len()));
                    hold(owner, entry);
                    held.push((page, entry, commits(&store, page)));
                    if lost && !armed && reported == Some(DrainStage::Fills) {
                        paged.fault(On::PageWrite, Arm::LostWrite);
                        armed = true;
                    }
                }
                let before = owner.held_invalidations();
                let exit = duties.turn(owner, now);
                let drained = owner.draining();
                if reported != Some(DrainStage::Mutations) && drained == Some(DrainStage::Mutations) {
                    dropped = before - duties.acknowledged().len();
                }
                for acknowledged in duties.acknowledged() {
                    let Some((page, _, was)) = held.iter().find(|(_, entry, _)| entry == acknowledged)
                    else {
                        failures.push(format!("an entry never held was acknowledged: {acknowledged:?}"));
                        continue;
                    };
                    if commits(&store, *page) <= *was || !stored_covers(&store, *page, *acknowledged) {
                        failures.push(format!(
                            "ACK-ON-COMMIT: an entry on page {page} was acknowledged with no durable coverage"
                        ));
                    }
                    if reported == Some(DrainStage::Mutations) {
                        failures.push(format!("an entry on page {page} was acknowledged after the stop of mutations"));
                    }
                    in_fills += usize::from(reported == Some(DrainStage::Fills));
                    acked.push(*acknowledged);
                }
                reported = drained;
                exit
            },
        );
        (served.exit, (store, stage.media.clone()))
    });
    if in_fills == 0 || dropped == 0 {
        failures.push(format!(
            "{in_fills} entries acknowledged in stage 1, {dropped} held at the stop of mutations"
        ));
    }
    if exit != Exit::Rerun(crate::host::Rerun::Planned) {
        failures.push(format!("the tenure ended {exit:?}"));
    }
    let covered = staged_over(volume, |mut stage| {
        let covered = Cell::new(None);
        let _ = stage.serve_until(
            |_, _, stop| {
                if covered.get().is_some() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, _| {
                if covered.get().is_none() && owner.coverage_mut().is_some() {
                    let refusing = acked.iter().filter(|(key, _)| refused(owner, key));
                    covered.set(Some(refusing.count()));
                }
                None
            },
        );
        covered.get()
    });
    if covered != Some(acked.len()) {
        failures.push(format!(
            "the next tenure refuses {covered:?} of {} acknowledged entries",
            acked.len()
        ));
    }
    failures
}

#[test]
fn a_held_invalidate_in_a_roll_is_acknowledged_only_after_its_page_commit() {
    let failures = held_invalidates_through_the_roll(false);
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn control_a_lost_page_write_acknowledges_a_held_invalidate_with_no_coverage() {
    let failures = held_invalidates_through_the_roll(true);
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("ACK-ON-COMMIT:")),
        "{failures:#?}"
    );
}

/// ROLL-START, one condition at a time. On a turn at which a due roll starts, the start check holds; it fails while
/// `roll_due` is clear, while the latest view read no volume record or no shard record of the tenure, while the
/// viewed record names no standby, leaves `E` or `g` no room for the restart's bump or holds no suffix of the
/// tenure, while the open stands before `Opened`, while the duties hold no capture policy or their pass is not
/// idle, one microsecond before the roll's retry time and not at it, and once the authority has left `Serving`;
/// with each condition restored it holds again.
#[test]
fn a_due_roll_starts_only_while_every_start_condition_holds() {
    use crate::failover::records::{ATTEMPTS_MAX, Ancestry};
    use crate::failover::serving::Event;
    use crate::net::ownership::ShardGeneration;

    let checked = Cell::new(false);
    let exit = staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, Some(policy_every(NEVER))).rolling(deadline());
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                // The first turn at which a due roll would start: the view shows the suffix the open reserved.
                let mut roll = duties.rolling.take().expect("rolling duties");
                duties.roll_due = true;
                let viewed = roll.viewed;
                let Some(viewed) = viewed.filter(|_| duties.roll_starts(&roll, owner, now)) else {
                    duties.roll_due = false;
                    duties.rolling = Some(roll);
                    return duties.turn(owner, now);
                };
                checked.set(true);
                assert!(roll.volume_read && duties.open() == super::Open::Opened);

                duties.roll_due = false;
                assert!(!duties.roll_starts(&roll, owner, now), "roll_due is clear");
                duties.roll_due = true;

                roll.volume_read = false;
                assert!(
                    !duties.roll_starts(&roll, owner, now),
                    "no volume record read"
                );
                roll.volume_read = true;

                let last_generation = ShardGeneration::new(u64::from(u32::MAX)).unwrap();
                let records = [
                    (
                        "no standby",
                        ShardRecord {
                            standby: None,
                            ..viewed
                        },
                    ),
                    (
                        "E at its last value",
                        ShardRecord {
                            attempts: ATTEMPTS_MAX,
                            ..viewed
                        },
                    ),
                    (
                        "g at its last value",
                        ShardRecord {
                            generation: last_generation,
                            ..viewed
                        },
                    ),
                    (
                        "no suffix of the tenure",
                        ShardRecord {
                            ancestry: Ancestry::default(),
                            ..viewed
                        },
                    ),
                ];
                for (case, record) in records {
                    roll.viewed = Some(record);
                    assert!(!duties.roll_starts(&roll, owner, now), "{case}");
                }
                roll.viewed = None;
                assert!(
                    !duties.roll_starts(&roll, owner, now),
                    "no view of the tenure"
                );
                roll.viewed = Some(viewed);

                duties.open = super::Open::Opening;
                assert!(
                    !duties.roll_starts(&roll, owner, now),
                    "the open stands before Opened"
                );
                duties.open = super::Open::Opened;

                let capture = duties.capture.take();
                assert!(!duties.roll_starts(&roll, owner, now), "no capture policy");
                duties.capture = capture;

                let counts = duties.capture.as_mut().expect("a capture policy");
                let idle = std::mem::replace(&mut counts.pass, Pass::Finishing { counter: 1 });
                assert!(matches!(idle, Pass::Idle), "the fixture's pass is idle");
                assert!(!duties.roll_starts(&roll, owner, now), "a pass is running");
                duties.capture.as_mut().expect("a capture policy").pass = idle;

                assert!(
                    duties.roll_starts(&roll, owner, now),
                    "every condition is restored"
                );
                let retry = std::mem::replace(&mut roll.start_at, now + 1);
                assert!(
                    !duties.roll_starts(&roll, owner, now),
                    "before the retry time"
                );
                roll.start_at = now;
                assert!(duties.roll_starts(&roll, owner, now), "at the retry time");
                roll.start_at = retry;

                owner.authority_event(Event::Withdraw(Cause::Planned), now);
                assert_ne!(owner.authority_report().state, State::Serving);
                assert!(
                    !duties.roll_starts(&roll, owner, now),
                    "the authority left Serving"
                );
                duties.rolling = Some(roll);
                duties.turn(owner, now)
            },
        );
        served.exit
    });
    assert!(
        checked.get(),
        "the tenure reached a turn at which a due roll starts"
    );
    assert_eq!(exit, Exit::Rerun(crate::host::Rerun::Planned));
}

/// Duties with no capture policy start no roll: no Publish can raise their floor, so the tenure keeps serving at its
/// bound and consumes no attempt.
#[test]
fn rolling_duties_without_a_capture_policy_start_no_roll() {
    STARTED.with(|cell| cell.set(None));
    let exit = staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = step_duties(&stage, None).rolling(deadline());
        let attempts = shard_record(&stage.store).attempts;
        let (turns, opened) = (Cell::new(0_u32), Cell::new(false));
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if turns.get() > 2_000 {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                turns.set(turns.get() + 1);
                if duties.open() == super::Open::Opened {
                    duties.roll_due = true;
                    opened.set(true);
                }
                let exit = duties.turn(owner, now);
                assert!(
                    !duties.roll_active(),
                    "no roll starts without a capture policy"
                );
                exit
            },
        );
        assert!(opened.get(), "the open reached Opened with the roll due");
        assert_eq!(
            shard_record(&stage.store).attempts,
            attempts,
            "the tenure consumes no attempt"
        );
        served.exit
    });
    assert_eq!(STARTED.with(Cell::get), None);
    assert_eq!(exit, Exit::Stopped);
}

/// Seeds `seeds`, each `cycles` tenures that each roll on a bound the seed draws (the suffix bound, no free slot or a
/// placement refusal), followed by one restart. Every tenure after a roll first serves exactly the objects the
/// earlier tenures acknowledged and answers missing for every other key, and every roll keeps the generation, the
/// volume and the owner and leaves the next tenure at `E + 1`. Returns one line per seed and a summary line, or the
/// first mismatch with its seed and cycle.
pub(crate) fn rolling_cycles(
    seeds: std::ops::RangeInclusive<u64>,
    cycles: usize,
) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let mut totals = [0_u64; 4];
    let (mut fills, mut removals, mut checks) = (0, 0, 0);
    for seed in seeds.clone() {
        let mut choices = Choices::of(seed);
        let mut held: Held = warm_objects();
        let mut reached = Reached::default();
        let mut volume = warm_volume_certified(0);
        let mut drawn = [0_u64; 4];
        for at in 0..=cycles {
            let failed = |failure: String| format!("seed {seed} cycle {at}: {failure}");
            let before = shard_record(&volume.0);
            let trigger = (at < cycles).then(|| {
                let at = choices.next(4) as usize;
                drawn[at] += 1;
                [
                    Trigger::Handoff,
                    Trigger::Slot,
                    Trigger::Placement,
                    Trigger::Early,
                ][at]
            });
            STARTED.with(|cell| cell.set(None));
            let (next, _, _) = run_cycle(volume, &mut held, &mut choices, &mut reached, trigger)
                .map_err(failed)?;
            let started = STARTED.with(Cell::get);
            let unpublished = trigger.is_some_and(|trigger| trigger != Trigger::Handoff);
            if trigger.is_some()
                && (started.is_none()
                    || unpublished && started != Some(ExitKind::Roll { publish: false }))
            {
                return Err(failed(format!("{trigger:?} started the roll {started:?}")));
            }
            let after = shard_record(&next.0);
            let kept = |record: &ShardRecord| (record.generation, record.active, record.owner);
            if kept(&after) != kept(&before) || after.attempts != before.attempts + 1 {
                return Err(failed(format!(
                    "the record moved from {before:?} to {after:?}"
                )));
            }
            volume = next;
        }
        lines.push(format!(
            "rolling: seed {seed} cycles {cycles}: every tenure after a roll held every acknowledged mutation; \
             handoff {}; slot {}; placement {}; early {}; fills {}; removals {}; checks {}; identity {:016x}",
            drawn[0], drawn[1], drawn[2], drawn[3], reached.fills, reached.removals, reached.checks, reached.identity
        ));
        for (total, count) in totals.iter_mut().zip(drawn) {
            *total += count;
        }
        fills += reached.fills;
        removals += reached.removals;
        checks += reached.checks;
    }
    lines.push(format!(
        "rolling: {} seeds of {cycles} rolls; handoff {}; slot {}; placement {}; early {}; fills {fills}; \
         removals {removals}; checks {checks}",
        seeds.count(),
        totals[0],
        totals[1],
        totals[2],
        totals[3],
    ));
    Ok(lines)
}

#[test]
fn two_seeded_roll_cycles_restart_at_e_plus_one_with_every_acknowledged_mutation() {
    let lines = crate::host::serve::tests::inline(|| rolling_cycles(1..=2, 2))
        .unwrap_or_else(|failure| panic!("{failure}"));
    assert_eq!(lines, PINNED, "{lines:#?}");
}

const PINNED: [&str; 3] = [
    "rolling: seed 1 cycles 2: every tenure after a roll held every acknowledged mutation; handoff 0; slot 0; \
     placement 1; early 1; fills 22; removals 19; checks 36; identity cd17b8c9e26fbce0",
    "rolling: seed 2 cycles 2: every tenure after a roll held every acknowledged mutation; handoff 0; slot 1; \
     placement 1; early 0; fills 36; removals 37; checks 36; identity 66d0213f2cdab9e6",
    "rolling: 2 seeds of 2 rolls; handoff 0; slot 1; placement 2; early 1; fills 58; removals 56; checks 72",
];

/// Two tenures that roll on a placement refusal before any Publish leave the third tenure a delta region its required
/// history fills; that tenure's open settles with the log closed, its due Publish raises the floor, the open reserves
/// its suffix, and the tenure acknowledges mutations and serves every earlier acknowledged one.
fn two_unpublished_rolls_then_a_restart() -> Result<(u32, u64), String> {
    crate::host::serve::tests::inline(|| {
        let mut volume = warm_volume_certified(0);
        let mut held: Held = warm_objects();
        let (mut choices, mut reached) = (Choices::of(3), Reached::default());
        for _ in 0..2 {
            let start = shard_record(&volume.0).checkpoint;
            let (next, named, _) = run_cycle(
                volume,
                &mut held,
                &mut choices,
                &mut reached,
                Some(Trigger::Early),
            )?;
            if named != start {
                return Err(format!("an early roll published {named:?}"));
            }
            volume = next;
        }
        let ancestry = shard_record(&volume.0).ancestry.as_slice().len() as u32;
        let acknowledged = reached.fills + reached.removals;
        let (volume, _, _) = cycle(volume, &mut held, &mut choices, &mut reached)?;
        cycle(volume, &mut held, &mut choices, &mut reached)?;
        Ok((ancestry, reached.fills + reached.removals - acknowledged))
    })
}

#[test]
fn a_tenure_after_two_unpublished_rolls_publishes_reopens_and_admits_mutations() {
    let (ancestry, mutations) =
        two_unpublished_rolls_then_a_restart().unwrap_or_else(|failure| panic!("{failure}"));
    assert!(
        ancestry >= 2,
        "two unpublished tenures left their suffixes: {ancestry}"
    );
    assert!(
        mutations > 0,
        "the tenures after them acknowledged mutations"
    );
}

#[test]
fn control_an_open_that_stops_on_a_full_region_stalls_the_next_tenure() {
    STOPPED_OPEN.with(|cell| cell.set(true));
    let stalled = two_unpublished_rolls_then_a_restart();
    STOPPED_OPEN.with(|cell| cell.set(false));
    let failure = stalled.expect_err("FP-HAND-09: the planted open passed");
    assert!(failure.contains("stalled"), "{failure}");
}

/// After two unpublished rolls the third tenure's log stays closed, and every Publish of its capture passes is
/// refused (a planted stale epoch), which quarantines each free checkpoint slot. The tenure reaches the slot bound
/// with no suffix of its own and exits by `trigger` on its confirmed record: the bound roll for
/// [`Trigger::Closed`], an authenticated restart request for [`Trigger::RequestedClosed`]. The next tenure then
/// publishes, reopens its log and acknowledges mutations, with every earlier acknowledged object served.
fn a_closed_log_tenure_out_of_slots(trigger: Trigger) -> Result<u64, String> {
    use super::capture::STALE_EPOCH;
    crate::host::serve::tests::inline(|| {
        let mut volume = warm_volume_certified(0);
        let mut held: Held = warm_objects();
        let (mut choices, mut reached) = (Choices::of(3), Reached::default());
        for _ in 0..2 {
            let early = Some(Trigger::Early);
            (volume, _, _) = run_cycle(volume, &mut held, &mut choices, &mut reached, early)?;
        }
        let before = shard_record(&volume.0);
        let acknowledged = reached.fills + reached.removals;
        reset();
        STALE_EPOCH.with(|stale| stale.set(true));
        let rolled = run_cycle(volume, &mut held, &mut choices, &mut reached, Some(trigger));
        STALE_EPOCH.with(|stale| stale.set(false));
        let (volume, _, _) = rolled.map_err(|failure| match resumed_reason() {
            Some(reason) => format!("{failure}; the exit resumed {reason:?}"),
            None => failure,
        })?;
        if reached.fills + reached.removals != acknowledged {
            return Err("the closed-log tenure acknowledged a mutation".into());
        }
        let kind = STARTED.with(Cell::get);
        let expected = match trigger {
            Trigger::RequestedClosed => ExitKind::Restart,
            _ => ExitKind::Roll { publish: false },
        };
        if kind != Some(expected) {
            return Err(format!("the closed-log tenure started {kind:?}"));
        }
        let after = shard_record(&volume.0);
        if (after.checkpoint, after.cut, after.attempts)
            != (before.checkpoint, before.cut, before.attempts + 1)
            || (after.owner, after.standby) != (before.owner, before.standby)
        {
            return Err(format!(
                "the roll moved the record: {before:?} to {after:?}"
            ));
        }
        let (volume, named, _) = cycle(volume, &mut held, &mut choices, &mut reached)?;
        if named == before.checkpoint {
            return Err("the tenure after the roll published nothing".into());
        }
        cycle(volume, &mut held, &mut choices, &mut reached)?;
        Ok(reached.fills + reached.removals - acknowledged)
    })
}

#[test]
fn a_closed_log_tenure_out_of_slots_rolls_and_the_next_tenure_reopens() {
    let mutations = a_closed_log_tenure_out_of_slots(Trigger::Closed)
        .unwrap_or_else(|failure| panic!("{failure}"));
    assert!(mutations > 0, "the next tenure acknowledged mutations");
}

/// FP-HAND-09: a requested restart whose capture start finds no free slot stops mutations on its Publish outcome,
/// and the closed log's evidence reaches the machine before the next clock reading, so the restart confirms the
/// record and restarts where it would otherwise seal, certify the predecessors' end against the cut and resume `cut`.
#[test]
fn a_requested_restart_on_a_closed_log_out_of_slots_confirms_and_restarts() {
    let mutations = a_closed_log_tenure_out_of_slots(Trigger::RequestedClosed)
        .unwrap_or_else(|failure| panic!("{failure}"));
    assert!(mutations > 0, "the next tenure acknowledged mutations");
}

#[test]
fn control_closed_log_evidence_fed_only_at_its_slot_resumes_the_requested_restart_cut() {
    let stalled = with_plant(Plant::UnopenedAtItsSlot, || {
        a_closed_log_tenure_out_of_slots(Trigger::RequestedClosed)
    });
    let failure = stalled.expect_err("FP-HAND-09: the planted driver restarted");
    assert!(
        failure.contains("stalled") && failure.contains("resumed Cut"),
        "{failure}"
    );
}

#[test]
fn control_a_machine_requiring_an_own_suffix_stalls_the_closed_log_tenure() {
    use crate::failover::planned::machine::tests::{Plant, with_plant};
    let stalled = with_plant(Plant::OwnSuffixRequired, || {
        a_closed_log_tenure_out_of_slots(Trigger::Closed)
    });
    let failure = stalled.expect_err("FP-HAND-09: the planted machine passed");
    assert!(failure.contains("stalled"), "{failure}");
}
