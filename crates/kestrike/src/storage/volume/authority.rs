//! Owner-thread admission binds work to the tenure's token and its Report window.
//! FRESH-AT-EFFECT: every device command, publication and reply is admitted by [`ServingAuthority::admit`] on a serving-clock reading taken for it.
//! A check that reads state and issues none of these, a fill's progress or the precheck of a receive, a publication or a turn's replies, is admitted at the owner's latest deadline sample; after the window ends it passes at most until the next deadline sample, and the effect it leads to is refused on that effect's own reading.
//! An owner turn takes a deadline sample in `poll_terminals` and another in its work step before it applies a terminal or submits a Report.
//! Serving outside the window and Withdrawn keep metadata state and command custody; Withdrawn issues no medium
//! command and, after a deposing status or a lapsed deferral's withdrawal, only periodic Reports.

use super::super::device::{CommandToken, Disk, Refusal, ReservationCommand, Terminal};
use super::super::os::Platform;
use super::super::recovery::Session;
use super::attach::Volume;
use super::tick::lost;
use crate::failover::bounds::Bounds;
use crate::failover::evidence::{
    Census, Holding, NotSole, Pair, Registrant, Report, ReservationType, find_from,
};
use crate::failover::poll::{self, Holder, Reads, Verdict};
use crate::failover::reconcile::StandbyGate;
use crate::failover::records::{RecordedPair, Registration, VolumeRecord};
use crate::failover::retire::Target;
use crate::failover::serving::{self, Cause, Event, Machine, Operation, Outcome, State, Token};
use crate::net::ownership::{ActivatedEpoch, ShardGeneration};
use crate::storage::EndedPreempt;

/// Nondecreasing elapsed microseconds, including suspended time.
/// Bounds and Report timestamps use these units. A detected suspend or clock
/// failure returns `None` until the owner acknowledges it with `clear_suspend`.
/// Providers must account for platform pauses in their elapsed-time guarantee.
pub trait ServingClock {
    fn now_us(&self) -> Option<u64>;
    fn clear_suspend(&mut self) {}
}

/// Linux boot time includes suspended time; cooldown uses its separate clock.
///
/// The offset of boot time over monotonic time is signed: a time namespace may set boot time behind monotonic time.
///
/// While the recorded offset bound lies within 1 µs of the latest reading's lower bound, a reading takes only boot time and then monotonic time. Zero stands in for the monotonic read before boot time; its upper bound, boot time itself, is looser than the recorded one, so the recorded bound stays, and every suspend longer than 1 µs plus the gap between the two reads is detected.
#[derive(Default)]
pub struct BootClock {
    offset_upper: std::cell::Cell<Option<i128>>,
    suspended: std::cell::Cell<bool>,
    tight: std::cell::Cell<bool>,
}
impl ServingClock for BootClock {
    fn now_us(&self) -> Option<u64> {
        self.read(super::super::os::clock_ticks)
    }
    fn clear_suspend(&mut self) {
        self.suspended.set(false);
    }
}

impl BootClock {
    /// One reading over `ticks`, which reads a clock in nanoseconds.
    fn read(&self, mut ticks: impl FnMut(libc::clockid_t) -> Option<u64>) -> Option<u64> {
        let monotonic = if self.tight.get() {
            0
        } else {
            ticks(libc::CLOCK_MONOTONIC)?
        };
        let boot = ticks(libc::CLOCK_BOOTTIME)?;
        let after = ticks(libc::CLOCK_MONOTONIC)?;
        self.observe(monotonic, boot, after)
    }

    // The bracket bounds the BOOTTIME minus MONOTONIC offset despite scheduling delays.
    fn observe(&self, monotonic: u64, boot: u64, after: u64) -> Option<u64> {
        let lower = i128::from(boot) - i128::from(after);
        let upper = i128::from(boot) - i128::from(monotonic);
        let previous = self.offset_upper.get();
        let detected = previous.is_some_and(|previous| lower > previous);
        self.suspended.set(self.suspended.get() || detected);
        let bound = if detected {
            upper
        } else {
            previous.map_or(upper, |previous| previous.min(upper))
        };
        self.offset_upper.set(Some(bound));
        self.tight.set(bound.saturating_sub(lower) < 1_000);
        (!self.suspended.get()).then_some(boot / 1_000)
    }
}

/// The command identity, submission token and submission time in microseconds of one authority Report.
pub(super) type ReportSubmission = (CommandToken, Option<Token>, u64);

/// The attach inputs: the bounds, a machine built from the tenure's session, one clock and that session, or, for a restart, the [`Restarted`](crate::failover::restart::Restarted) value whose session and FB value move in together. No input carries a recovery proof; the machine enters `Recovering` only on the attach gate's value.
///
/// ```
/// use kestrike::failover::bounds::Bounds;
/// use kestrike::failover::serving::Machine;
/// use kestrike::storage::{ServingAuthority, ServingClock, Session};
///
/// fn build(bounds: Bounds, machine: Machine, clock: Box<dyn ServingClock>, session: Session) -> ServingAuthority {
///     ServingAuthority::new(bounds, machine, clock, session)
/// }
/// ```
///
/// A recovery proof has no place among the inputs:
///
/// ```compile_fail,E0061
/// use kestrike::failover::bounds::Bounds;
/// use kestrike::failover::serving::Machine;
/// use kestrike::storage::{ServingAuthority, ServingClock, Session};
///
/// fn build(bounds: Bounds, machine: Machine, proof: [bool; 4], clock: Box<dyn ServingClock>, session: Session) -> ServingAuthority {
///     ServingAuthority::new(bounds, machine, proof, clock, session)
/// }
/// ```
///
/// The crossing into `Recovering` that takes the gate's value is crate-private:
///
/// ```compile_fail,E0624
/// use kestrike::failover::serving::Machine;
///
/// fn cross(machine: &mut Machine) {
///     machine.cross_boundary(todo!());
/// }
/// ```
pub struct ServingAuthority {
    /// The tenure's session, from its acknowledged `E` bump or takeover.
    pub(super) session: Session,
    pub(super) bounds: Bounds,
    pub(super) machine: Machine,
    pub(super) clock: Box<dyn ServingClock>,
    pub(super) now: u64,
    pub(super) report: Option<ReportSubmission>,
    /// The authority Report whose deadline passed after the table collected its terminal, and whether the attach
    /// gate still awaited it at that deadline.
    pub(super) expired: Option<(ReportSubmission, bool)>,
    pub(super) next_report: u64,
    pub(super) ordinal: u64,
    pub(super) entries: Box<[Registrant]>,
    pub(super) refusal: Option<AuthorityRefusal>,
    pub(super) own_records: Option<u32>,
    /// The registrant judgment of the last Report the authority evaluated.
    pub(super) registrants: Option<RegistrantJudgment>,
    /// Whether the last Report the authority evaluated held the tenure under RECORDED-HOLDER-HOLD or NO-HOLDER-HOLD.
    pub(super) held: bool,
    /// The fencing-boundary value of a restart, which the attach gate passes on its first step.
    pub(super) pending_fence: Option<super::fence::Fenced>,
    /// The warm source a restart's or takeover's record names, which the attach moves into its metadata owner.
    pub(super) warm: Option<Box<super::warm::WarmSource>>,
    /// The activation's recorded pairs, which each [`Volume::owner_poll`] volume-record read replaces.
    pub(super) recorded: Option<Box<[Pair]>>,
    /// The count of trailing pairs of `recorded` that a Report listed under an ended attach's key; the pairs before
    /// them are the volume record's, the holders RECORDED-HOLDER-HOLD validates.
    pub(super) ended_admitted: usize,
    /// The subset of `recorded` that the volume-record read associated with an ended attach.
    pub(super) ended_pairs: Box<[Pair]>,
    /// Each pair outside `recorded` that a deferred Report, a Report withdrawn under RECORDED-HOLDER-HOLD or
    /// NO-HOLDER-HOLD, or a Report that withdrew or kept withdrawn the machine under LAPSE-UNVERIFIED, the periodic
    /// Reports of a machine withdrawn with `Cause::Unverified` included, listed as a registrant, with the submission
    /// time of the first such Report. A pair absent from a later Report keeps its time; [`Volume::owner_poll`] drops
    /// the pairs its volume record admits. At most `N_reg` pairs, in key order.
    pub(super) pending: Vec<(Pair, u64)>,
    /// `Some` marks a deposing status that withdrew the tenure with `Cause::Status`, pending an observation from a
    /// Report submitted after that status. The inner value holds the Report outstanding at the latest deposing
    /// status. That Report may have run before the preempt that caused the status. While `rejudge` is `Some` and the
    /// tenure holds its token, Withdrawn keeps the periodic Report, a reservation read, until a flip is requested, a
    /// cause observes a later tenure (`Machine::superseded`), whose withdrawal no Report can change, or
    /// a Report submitted after the deposing status observes the reservation holder. After a gate Register's status
    /// that Report shows the own host ID under another key, no retirement evidence before the boundary, and the
    /// withdrawal keeps `Cause::Status`.
    pub(super) rejudge: Option<Option<CommandToken>>,
    /// The header of the last Report `authority_terminal` parsed, whose entries stay in `entries[..count]` until
    /// the next parse, or that parse's refusal. An uncollected Report past its deadline sets
    /// `NotSole::Unreadable`.
    pub(super) polled: Result<(u64, ReservationType, u32, usize), NotSole>,
    /// The outstanding ended-attach preempt that [`Volume::owner_reclaim`] submitted, at most one. Its terminal
    /// makes the next Report due. A poll that judges a Report submitted before that terminal can submit the preempt
    /// again. While `authority.preempt` holds a token, `owner_reclaim` skips ended-key preemption.
    pub(super) preempt: Option<CommandToken>,
    /// Each recorded pair of an ended entry that [`Volume::owner_reclaim`] saw in a poll's volume record, with the
    /// serving-clock reading that step took after the volume read. EndOrder: the step returns a pair only when this
    /// reading precedes the submission of the poll's Report. The volume record's ended pairs bound the list.
    pub(super) ended: Vec<(RecordedPair, u64)>,
    /// LAPSE-UNVERIFIED: an owner poll of the machine withdrawn with `Cause::Unverified` read a shard record naming
    /// the tenure beside a volume record that admits every deferred pair, or a Report inside its window that lists
    /// none of the pairs still deferred ([`Volume::lapse_verified`]).
    pub(super) verified: bool,
    /// LAPSE-UNVERIFIED: the submission time of the last Report that withdrew, or kept withdrawn, the machine with
    /// `Cause::Unverified`, zero before one. A Report counts as showing the deferred pairs absent only when submitted
    /// after it.
    pub(super) lapsed_at: u64,
}

/// An owned copy of a Report the serving authority evaluated, for the owner's poll ([`Volume::poll_report`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolledReport {
    submitted_at: u64,
    rtype: ReservationType,
    regctl: u32,
    entries: Vec<Registrant>,
}

impl PolledReport {
    pub fn report(&self) -> Report<'_> {
        Report {
            submitted_at: self.submitted_at,
            rtype: self.rtype,
            regctl: self.regctl,
            entries: &self.entries,
        }
    }
}

/// Why a reservation command was not submitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unsent {
    /// The clock gave no sample at or past the last one, the sample is at or before the machine's last window expiry, or the ordinals are exhausted.
    Deferred,
    /// The table refused the submit.
    Refused(Refusal),
}

/// Closed authority telemetry causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityRefusal {
    /// The current operation's serving gate refused it.
    Admission(serving::Denial),
    /// Report bytes or certification could not establish holder evidence.
    ReportMalformed,
    /// Certification exceeded the Report deadline.
    ReportTimeout,
    /// The foreign holder's key epoch is below this token's.
    ForeignLower,
    /// The foreign holder's key epoch equals this token's.
    ForeignEqual,
    /// The foreign holder's key epoch is above this token's.
    ForeignHigher,
    /// Certified reservation conflict ended authority.
    Conflict,
    /// Certified preempt-abort status ended authority.
    PreemptAborted,
    /// A Report after the fencing boundary held more than one record with the own host ID, or the own host ID
    /// under another key; the volume retires.
    OwnHostId,
    /// The elapsed source failed, moved backward, or detected suspend.
    Clock,
    /// The attach gate passed but the serving machine refused to enter `Recovering`, a broken gate invariant.
    Boundary,
}

/// State, tenure, Report age and the withdrawal or refusal cause; the report carries no key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityReport {
    pub state: State,
    /// The `(g, a)` of the tenure's session.
    pub tenure: (ShardGeneration, ActivatedEpoch),
    /// Report age uses the serving clock; a missing Report window, a missing clock reading, or a reading below the last deadline sample yields `None`.
    pub report_age_us: Option<u64>,
    /// The heartbeat read age: the time since the tenure's freshness clock last refreshed, on the serving clock, with `None` under the same clock conditions as `report_age_us` or before the first refresh. A sender samples it when it builds each heartbeat, after receiving the heartbeat that heartbeat acknowledges.
    pub freshness_age_us: Option<u64>,
    /// The withdrawal cause [`Machine::cause`](crate::failover::serving::Machine::cause) reports.
    pub withdrawal: Option<Cause>,
    /// The flip request a retirement trigger made, naming the own `(g, owner, E)`.
    pub flip: Option<Target>,
    /// The last recorded authority cause, retained across successful renewal;
    /// otherwise the current read gate's refusal.
    pub refusal: Option<AuthorityRefusal>,
    pub withheld: bool,
    /// The own host ID's record count among the inspected rows of the last Report the authority evaluated, current
    /// or expired, `None` when that Report gave no count. A Report completing while the machine has no serving token,
    /// or while it is closed, or while it is withdrawn with `Machine::flip_open` false after a flip request, a
    /// successor observation or a withdrawal by a planned exit, leaves the count, `registrants` and the held judgment
    /// unchanged. The inspected rows stop at the registrant
    /// bound, so a count above one, an alias attachment, is a lower bound, and a count of one also covers one row
    /// under a wrong key.
    pub own_records: Option<u32>,
    /// A deferral is held: the serving judgment certified a Report over a non-holding registrant outside the
    /// authority's recorded pairs, or withdrew under a hold beside one inside its window, and no owner poll has since
    /// admitted every such pair. The flag stays set after a lapsed deferral's withdrawal (`Cause::Unverified`) until
    /// such a poll, and a pair a later Report of that withdrawn machine lists first joins it.
    pub pending: bool,
    /// The registrant judgment of the last Report the authority evaluated, `None` before one.
    pub registrants: Option<RegistrantJudgment>,
    pub hold: HoldState,
}

/// One parsed Report of the own pair, judged against the own pair and the recorded pairs.
struct Judged {
    /// The serving refusal, which a deferred registrant leaves `None`.
    refusal: Option<NotSole>,
    /// The epoch of a foreign holder's key.
    foreign: Option<crate::failover::identity::Epoch>,
    /// The cause under which RECORDED-HOLDER-HOLD, NO-HOLDER-HOLD or LAPSE-UNVERIFIED withdraws the tenure with no
    /// flip request.
    hold: Option<Cause>,
    /// The entries that carry the own host ID.
    own_host: u32,
    judgment: RegistrantJudgment,
}

/// A Report's registrants judged against the own pair and the recorded pairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrantJudgment {
    /// The own pair holds and is the only registrant.
    Sole,
    /// The own pair holds and every other registrant is a recorded pair.
    Recorded,
    /// The own pair holds, no check refuses, and another registrant is a recorded pair that pins no live attach, or a
    /// non-holding pair an activation or owner-poll read admitted unrecorded: no recorded pair carries its key, and its
    /// key derives an entry number below `next` that no live attach holds. It takes precedence over `Recorded`
    /// (ENDED-NEVER-RETIRES).
    Ended,
    /// The judgment refused: the verdict over the Report; `DuplicateOwnRecord` for a second record of the own host
    /// ID or for one own-host record under another key; the parser's refusal of the Report's bytes; or `Unreadable`
    /// for a Report of the own pair that gave no bytes to judge. A registrant that SERVING-DEFERS-UNRECORDED defers
    /// reads `ForeignRegistrant`.
    Refused(NotSole),
}

/// How the serving machine holds the tenure, in precedence order: a status withdrawal, or a rejudge a deposing
/// status awaits, that a successor observation superseded before any flip request, after which no rejudge runs
/// (SupersededRequestsNoFlip); a deposing status awaiting its rejudge while a later trigger can still request the flip,
/// on an open volume or on a closed one whose Report is still outstanding or collected; a hold on the last evaluated
/// Report while the machine requests no flip; or none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldState {
    Superseded,
    Pending,
    Held,
    Clear,
}

impl ServingAuthority {
    /// Admits `operation` under `token` on a serving-clock reading taken now; a reading that fails or lies before the latest deadline sample refuses `WindowExpired`.
    pub(crate) fn admit(
        &self,
        operation: Operation,
        token: Option<Token>,
    ) -> Result<Token, serving::Denial> {
        let token = token.ok_or(serving::Denial::NotServing(self.machine.state()))?;
        self.admit_on(operation, Some(token), self.reading())
    }

    /// One serving-clock reading, `None` when it fails or lies before the latest deadline sample.
    fn reading(&self) -> Option<u64> {
        self.clock.now_us().filter(|now| *now >= self.now)
    }

    /// [`Self::admit`] on `reading`, a value [`Self::reading`] returned, for a caller that judges several operations
    /// at one instant: a `None` reading refuses `WindowExpired`.
    fn admit_on(
        &self,
        operation: Operation,
        token: Option<Token>,
        reading: Option<u64>,
    ) -> Result<Token, serving::Denial> {
        let token = token.ok_or(serving::Denial::NotServing(self.machine.state()))?;
        let now = reading.ok_or(serving::Denial::WindowExpired)?;
        self.machine.admit_at(operation, token, now)
    }

    /// Admits `operation` under `token` at the owner's latest deadline sample, reading no clock: for a check that reads state and issues no device command, publication or reply (FRESH-AT-EFFECT).
    pub(crate) fn admit_at_sample(
        &self,
        operation: Operation,
        token: Option<Token>,
    ) -> Result<Token, serving::Denial> {
        let token = token.ok_or(serving::Denial::NotServing(self.machine.state()))?;
        self.machine.admit_at(operation, token, self.now)
    }

    /// Attach validates matching machine and driver bounds. All times use
    /// microseconds. Every root and record header the attach writes carries `session`.
    pub fn new(
        bounds: Bounds,
        machine: Machine,
        clock: Box<dyn ServingClock>,
        session: Session,
    ) -> Self {
        Self {
            session,
            bounds,
            machine,
            clock,
            now: 0,
            report: None,
            expired: None,
            next_report: 0,
            ordinal: 0,
            entries: Box::new([]),
            refusal: None,
            own_records: None,
            registrants: None,
            held: false,
            pending_fence: None,
            warm: None,
            recorded: None,
            ended_admitted: 0,
            ended_pairs: Box::new([]),
            pending: Vec::new(),
            rejudge: None,
            polled: Err(NotSole::Unreadable),
            preempt: None,
            ended: Vec::new(),
            verified: false,
            lapsed_at: 0,
        }
    }

    /// The authority of a restart that reached the fencing boundary, or a takeover that reached its admission capability, with its coverage fencing: its machine starts before the boundary without a token, and the attach gate passes on the restart's FB value with no gate command, issuing the token for the pair Report #2 confirmed. The warm source the record named moves in, so the attach reads the named slot in place of the probes. The source checks restored entries against a copy of the returned fencing's coverage, so the caller keeps that fencing's coverage unchanged until the warm load's `LoadComplete` and hands it to the owner with no `hold`, `cover_begin` or `cover_page` before then; an INVALIDATE the owner receives while the readiness reads `Detached` or `Loading` refuses `Contended`, which keeps the two equal.
    pub fn restarted(
        bounds: Bounds,
        clock: Box<dyn ServingClock>,
        restarted: crate::failover::restart::Restarted,
    ) -> (Self, crate::storage::page_coverage::Fencing) {
        let (session, fenced, (recorded, ended), fencing, warm, ended_pairs) =
            restarted.into_parts();
        let mut authority = Self::crossed(bounds, clock, session, fenced, (recorded, ended_pairs));
        authority.ended_admitted = ended;
        authority.warm = warm.map(Box::new);
        (authority, fencing)
    }

    /// Creates the authority for a fresh activation that reached the fencing boundary and returns its coverage
    /// fencing.
    pub fn activated(
        bounds: Bounds,
        clock: Box<dyn ServingClock>,
        activated: crate::failover::fresh::Activated,
    ) -> (Self, crate::storage::page_coverage::Fencing) {
        let (session, fenced, fencing, recorded, ended) = activated.into_parts();
        (
            Self::crossed(bounds, clock, session, fenced, (recorded, ended)),
            fencing,
        )
    }

    /// Takes the warm source a restart or takeover named, so the attach starts cold.
    #[cfg(test)]
    pub(crate) fn take_warm(&mut self) -> Option<Box<super::warm::WarmSource>> {
        self.warm.take()
    }

    fn crossed(
        bounds: Bounds,
        clock: Box<dyn ServingClock>,
        session: Session,
        fenced: super::fence::Fenced,
        (recorded, ended_pairs): (Vec<Pair>, Vec<Pair>),
    ) -> Self {
        let machine = Machine::new(bounds, &session);
        Self {
            pending_fence: Some(fenced),
            recorded: Some(recorded.into()),
            ended_pairs: ended_pairs.into(),
            ..Self::new(bounds, machine, clock, session)
        }
    }

    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        Self::fixture_under(super::super::recovery::next_session())
    }

    /// The fixture authority of [`fixture`](Self::fixture) under `session`.
    #[cfg(test)]
    pub(crate) fn fixture_under(session: Session) -> Self {
        Self::fixture_limits_under(super::gate_fixture::limits(), session)
    }

    /// A standby's authority: its machine starts before the fencing boundary and holds no token.
    #[cfg(test)]
    pub(crate) fn fixture_standby() -> Self {
        let fixture = Self::fixture();
        Self::new(
            fixture.bounds,
            Machine::new(fixture.bounds, &fixture.session),
            fixture.clock,
            fixture.session,
        )
    }

    #[cfg(test)]
    pub(crate) fn fixture_pre_boundary() -> Self {
        Self {
            pending_fence: Some(super::fence::Fenced::assumed()),
            ..Self::fixture_standby()
        }
    }

    #[cfg(test)]
    pub(crate) fn fixture_limits(limits: super::super::device::ReservationLimits) -> Self {
        Self::fixture_limits_under(limits, super::super::recovery::next_session())
    }

    /// A serving authority over `limits` whose machine holds the token for the fixture's own pair before the fencing boundary, under `session`.
    #[cfg(test)]
    pub(crate) fn fixture_limits_under(
        limits: super::super::device::ReservationLimits,
        session: Session,
    ) -> Self {
        Self::fixture_pair_under(limits, session, super::gate_fixture::own())
    }

    /// A serving authority over `limits` whose machine holds the token for `pair` before the fencing boundary, under `session`; a volume
    /// attached under a persisted local record takes that record's pair, which the gate's Report shows as holder.
    #[cfg(test)]
    pub(crate) fn fixture_pair_under(
        limits: super::super::device::ReservationLimits,
        session: Session,
        pair: crate::failover::evidence::Pair,
    ) -> Self {
        let bounds = super::gate_fixture::bounds_of(limits);
        let machine = Machine::issued(bounds, &session, pair);
        Self::new(
            bounds,
            machine,
            Box::new(super::gate_fixture::ZeroClock),
            session,
        )
    }
}

impl ServingAuthority {
    /// The tenure's session, which every root and record header the attach writes carries.
    pub fn session(&self) -> &Session {
        &self.session
    }

    pub(super) fn publish(&self, readiness: &super::super::readiness::Word) {
        let state = match self.machine.state() {
            State::Closed if self.machine.cause().is_some() => State::Withdrawn,
            state => state,
        };
        readiness.set_authority(state, self.machine.token().map_or(0, |token| token.lineage));
    }
}

impl<P: Platform, D: Disk> Volume<'_, '_, P, D> {
    #[cfg(test)]
    pub(crate) fn serve_later_tenure(&mut self) {
        self.serve_tenure(super::super::recovery::next_session());
    }

    #[cfg(test)]
    pub(crate) fn serve_tenure(&mut self, session: super::super::recovery::Session) {
        use crate::failover::serving::Readiness;
        let mut machine =
            Machine::issued(self.authority.bounds, &session, super::gate_fixture::own());
        let token = machine.token().expect("the fixture machine holds a token");
        machine.cross_boundary(&super::fence::Fenced::assumed());
        machine.step(Event::Readiness(Readiness::ReadReady { token }));
        machine.step(Event::Readiness(Readiness::AllocationReady { token }));
        self.authority.machine = machine;
        self.authority.session = session;
        self.authority_effects();
    }

    #[cfg(test)]
    pub(crate) fn set_serving_clock(&mut self, clock: Box<dyn ServingClock>) {
        self.authority.clock = clock;
    }

    /// Sets the serving window the authority's deferrals and its lapse judgment use to `window`, keeping the
    /// machine's bounds, so a fixture whose bounds never end a window can lapse a deferral.
    #[cfg(test)]
    pub(crate) fn set_deferral_window(&mut self, window: u64) {
        let bounds = self.authority.bounds;
        self.authority.bounds = crate::failover::bounds::Bounds::new(
            bounds.registrant_max(),
            bounds.retry_max(),
            window,
            bounds.report_deadline(),
            bounds.report_period(),
            0,
        )
        .expect("a deferral window above the Report period and deadline");
    }

    /// The session the attach's authority holds, which a cold bootstrap writes in its RESET roots and a warm bootstrap opens under at its readiness commit, which writes no root.
    pub(crate) fn tenure_session(&self) -> u64 {
        self.authority.session().get()
    }

    pub(crate) fn tenure(&self) -> &Session {
        self.authority.session()
    }

    /// Whether a withdrawal cause named a later tenure of the shard (`Machine::has_successor`).
    pub fn has_successor(&self) -> bool {
        self.authority.machine.has_successor()
    }

    /// The authority's report at one serving-clock reading: the two ages, the admission refusal and the withhold
    /// are all judged at that reading, so the report describes one instant and costs one clock reading.
    pub fn authority_report(&self) -> AuthorityReport {
        let a = &self.authority;
        let now = a.reading();
        AuthorityReport {
            state: a.machine.state(),
            tenure: a.machine.tenure(),
            report_age_us: a
                .machine
                .window_start()
                .and_then(|start| now.map(|now| now.saturating_sub(start))),
            freshness_age_us: now.and_then(|now| a.machine.read_age(now)),
            withdrawal: a.machine.cause(),
            flip: a.machine.flip_request(),
            refusal: a.refusal.or_else(|| {
                a.admit_on(Operation::Read, a.machine.token(), now)
                    .err()
                    .map(AuthorityRefusal::Admission)
            }),
            withheld: a.admit_on(Operation::Get, a.machine.token(), now)
                == Err(serving::Denial::Withheld),
            own_records: a.own_records,
            pending: !a.pending.is_empty(),
            registrants: a.registrants,
            hold: if a.machine.superseded()
                && a.machine.flip_request().is_none()
                && (a.rejudge.is_some() || matches!(a.machine.cause(), Some(Cause::Status(_))))
            {
                HoldState::Superseded
            } else if a.rejudge.is_some()
                && a.machine.flip_open()
                && !self.lost
                && (!self.closed || a.report.is_some() || a.expired.is_some())
            {
                HoldState::Pending
            } else if a.held && a.machine.flip_request().is_none() {
                HoldState::Held
            } else {
                HoldState::Clear
            },
        }
    }

    pub(super) fn authority_effects(&mut self) {
        self.authority.publish(&self.storage.readiness);
        // A withdrawn or closed tenure never submits a staged unit, so the capture learns the command's end here.
        if matches!(self.authority_state(), State::Withdrawn | State::Closed)
            && self.metadata.is_open()
        {
            self.fail_unmapped_unit();
        }
    }

    /// The serving state; [`authority_report`](Self::authority_report) also samples the clock when no refusal is recorded.
    pub(crate) fn authority_state(&self) -> State {
        self.authority.machine.state()
    }

    pub(crate) fn authority_withdrawal(&self) -> Option<Cause> {
        self.authority.machine.cause()
    }

    pub(crate) fn authority_flip(&self) -> Option<Target> {
        self.authority.machine.flip_request()
    }

    pub(crate) fn serving_token(&self) -> Option<Token> {
        self.authority.machine.token()
    }

    pub(crate) fn admit_authority(
        &self,
        operation: Operation,
        token: Option<Token>,
    ) -> Result<Token, serving::Denial> {
        self.authority.admit(operation, token)
    }

    /// [`ServingAuthority::admit_at_sample`] for this volume's authority.
    pub(crate) fn admit_authority_at_sample(
        &self,
        operation: Operation,
        token: Option<Token>,
    ) -> Result<Token, serving::Denial> {
        self.authority.admit_at_sample(operation, token)
    }

    /// A clock fault or a Report past its deadline expires the authority window.
    pub(crate) fn authority_deadlines(&mut self) {
        let a = &mut self.authority;
        let now = a.clock.now_us();
        if now.is_none_or(|now| now < a.now) {
            a.refusal = Some(AuthorityRefusal::Clock);
            // The window closes at the latest sample before the fault is acknowledged, so a reading that unwinds below leaves it closed.
            a.machine.step(Event::Expire { now: a.now });
            a.clock.clear_suspend();
            a.now = a.clock.now_us().map_or(a.now, |now| now.max(a.now));
            a.machine.step(Event::Expire { now: a.now });
        } else {
            a.now = now.unwrap();
        }
        if let Some((command, _, submitted)) = self.authority.report
            && self.authority.now.saturating_sub(submitted)
                > self.authority.bounds.report_deadline()
        {
            let gate = self.gate_awaits(command);
            let collected = !self.table.timeout_report(command);
            let a = &mut self.authority;
            if !collected {
                a.polled = Err(NotSole::Unreadable);
            }
            a.expired = a
                .report
                .take()
                .filter(|_| collected)
                .map(|report| (report, gate));
            a.refusal = Some(AuthorityRefusal::ReportTimeout);
            a.machine.step(Event::Expire { now: a.now });
        }
    }

    pub(super) fn authority_ready(&mut self) {
        if self.authority.machine.awaits_readiness()
            && self.readiness() == super::super::readiness::State::Live
        {
            let a = &mut self.authority;
            if let Some(token) = a.machine.token() {
                a.machine
                    .step(Event::Readiness(serving::Readiness::ReadReady { token }));
                a.machine
                    .step(Event::Readiness(serving::Readiness::AllocationReady {
                        token,
                    }));
            }
        }
        self.authority_effects();
    }

    pub(crate) fn metadata_staging_admitted(&self) -> bool {
        self.metadata_admitted(serving::MetadataKind::CheckpointRoot, self.authority.now)
    }

    pub(crate) fn metadata_authorized(&self, kind: serving::MetadataKind) -> bool {
        self.authority
            .clock
            .now_us()
            .filter(|now| *now >= self.authority.now)
            .is_some_and(|now| self.metadata_admitted(kind, now))
    }

    fn metadata_admitted(&self, kind: serving::MetadataKind, now: u64) -> bool {
        let Some(token) = self.serving_token() else {
            return false;
        };
        self.metadata.fenced.is_some()
            && matches!(
                self.authority.machine.metadata(&token, now, kind),
                Outcome::Admitted(_)
            )
    }

    /// An expired collected Report holds the next Report until its terminal applies, so one expired Report exists
    /// at a time and a later deadline pass keeps its retiring refusal.
    pub(super) fn authority_report_due(&self) -> bool {
        let a = &self.authority;
        !self.closed
            && !self.lost
            && self.table.reservation_limits().is_some()
            && a.report.is_none()
            && a.expired.is_none()
            && a.machine.token().is_some()
            && a.now >= a.next_report
            && match a.machine.state() {
                State::Recovering | State::Serving => self.metadata.fenced.is_some(),
                State::Withdrawn => {
                    (a.rejudge.is_some() || a.machine.cause() == Some(Cause::Unverified))
                        && a.machine.flip_open()
                }
                State::PreBoundary | State::Closed => false,
            }
    }

    /// Submits the periodic Report when one is due and returns the number submitted.
    /// A submit refused for the device's loss loses the volume and withdraws the readiness attempt in this call.
    pub(super) fn authority_reports(&mut self) -> u32 {
        if !self.authority_report_due() {
            return 0;
        }
        let submitted = self.submit_report();
        u32::from(self.sent(submitted).is_some())
    }

    /// The token of an accepted submit. A refusal for the device's loss sets `lost` and halts the metadata.
    fn sent(&mut self, submitted: Result<CommandToken, Unsent>) -> Option<CommandToken> {
        if let Err(Unsent::Refused(refusal)) = submitted
            && lost(refusal)
        {
            self.lost = true;
            self.halt_metadata();
        }
        submitted.ok()
    }

    /// Requires that no Report is pending: the periodic path checks [`authority_report_due`](Self::authority_report_due), and the gate submits its Report only while no gate command is outstanding, before any periodic Report.
    pub(super) fn submit_report(&mut self) -> Result<CommandToken, Unsent> {
        let a = &mut self.authority;
        debug_assert!(a.report.is_none(), "one Report at a time");
        let now = a
            .clock
            .now_us()
            .filter(|now| *now >= a.now)
            .ok_or(Unsent::Deferred)?;
        if a.machine.expired_at().is_some_and(|at| now <= at) {
            return Err(Unsent::Deferred);
        }
        let token = self.submit_ordered(|ordinal| ReservationCommand::Report {
            not_before: ordinal,
        })?;
        let a = &mut self.authority;
        // The submission's reading becomes the last sample, so a clock fault seen after it closes the window at or after this Report's submission and the Report renews nothing.
        a.now = now;
        a.report = Some((token, a.machine.token(), now));
        a.next_report = now.saturating_add(a.bounds.report_period());
        Ok(token)
    }

    pub(super) fn submit_ordered(
        &mut self,
        command: impl FnOnce(u64) -> ReservationCommand,
    ) -> Result<CommandToken, Unsent> {
        let ordinal = self
            .authority
            .ordinal
            .checked_add(1)
            .ok_or(Unsent::Deferred)?;
        let token = self
            .table
            .submit_reservation(command(ordinal), ordinal)
            .map_err(Unsent::Refused)?;
        self.authority.ordinal = ordinal;
        Ok(token)
    }

    pub(super) fn authority_terminal(&mut self, terminal: &Terminal<'_>) -> bool {
        // ENDED-PREEMPT: the preempt's completion status carries no verdict, a Reservation Conflict for a key that
        // no registrant carries or a deposing status included. The next Report is due at once and judges the
        // reservation the preempt left, and the volume record a later poll reads decides the pair.
        if self.authority.preempt == Some(terminal.token()) {
            #[cfg(test)]
            if status(terminal).and_then(|status| status.generic_code()) == Some(0) {
                reclaim_plant::completed();
            }
            let a = &mut self.authority;
            a.preempt = None;
            a.next_report = a.next_report.min(a.now);
            return true;
        }
        if let Some(code) = status(terminal)
            .filter(|s| s.deposes())
            .and_then(|s| s.generic_code())
        {
            let (refusal, status) = if code == crate::failover::evidence::RESERVATION_CONFLICT {
                (AuthorityRefusal::Conflict, serving::Deposing::Conflict)
            } else {
                (
                    AuthorityRefusal::PreemptAborted,
                    serving::Deposing::PreemptAborted,
                )
            };
            self.authority.refusal = Some(refusal);
            self.authority_apply(Event::Withdraw(Cause::Status(status)));
            let a = &mut self.authority;
            if a.machine.flip_open() {
                let outstanding = a.report.or(a.expired.map(|(report, _)| report));
                a.rejudge = Some(outstanding.map(|report| report.0));
            }
        }
        let report = match self.authority.report {
            Some(report) if report.0 == terminal.token() => {
                self.authority.report = None;
                Some((report, true, self.gate_awaits(report.0)))
            }
            _ => self
                .authority
                .expired
                .take_if(|(expired, _)| expired.0 == terminal.token())
                .map(|(expired, gate)| (expired, false, gate)),
        };
        let Some(((command, token, submitted_at), current, gate)) = report else {
            return false;
        };
        let authority_lost = current && gate && self.gate_authority_lost();
        if authority_lost {
            self.gate_judged(Err(super::fence::GateRefusal::AuthorityLost));
        }
        let machine = &self.authority.machine;
        if machine.state() == State::Withdrawn && !machine.flip_open() {
            return true;
        }
        let refused = match terminal {
            Terminal::Reservation { report_error, .. } => *report_error,
            _ => None,
        };
        let lineage = token.map_or(0, |t| t.lineage);
        let limits = self.table.reservation_limits();
        let parsed = match (limits, self.table.reservation_report(command)) {
            (Some(limits), Some(bytes)) => super::super::device::parse_extended_report(
                bytes,
                limits,
                submitted_at,
                &mut self.authority.entries,
            )
            .map_err(Some),
            _ => Err(refused),
        };
        self.authority.polled = match &parsed {
            Ok(report) => Ok((
                report.submitted_at,
                report.rtype,
                report.regctl,
                report.entries.len(),
            )),
            Err(error) => Err(error.map_or(NotSole::Unreadable, |error| error.refusal())),
        };
        let own = token.map(|token| crate::failover::evidence::Pair {
            exhid: token.exhid,
            key: token.key,
        });
        let pre_boundary = self.metadata.fenced.is_none();
        let sole = if let (Ok(report), Some(own)) = (&parsed, own) {
            let bounds = &self.authority.bounds;
            let recorded = self.authority.recorded.as_deref();
            let holders = recorded.map(|recorded| {
                &recorded[..recorded.len().saturating_sub(self.authority.ended_admitted)]
            });
            let late = recorded.map_or(&[][..], |recorded| {
                &recorded[recorded.len().saturating_sub(self.authority.ended_admitted)..]
            });
            let ended = &self.authority.ended_pairs;
            // SERVING-DEFERS-UNRECORDED: `recorded` changes only at activation and in `owner_poll`, so a standby that
            // enrolls and registers between polls is outside it. While the own pair is the one holder, such a
            // non-holding registrant issues no medium I/O under type-2 Exclusive Access. Each such pair is deferred for
            // one serving window from the first Report that listed it, so the owner serves at most two windows beside
            // that pair. The first Report submitted after the deferral window that still lists the pair refuses
            // `ForeignRegistrant` and withdraws the owner. An owner poll whose volume record enrolls the pair inside
            // the window keeps the owner serving.
            //
            // The census admits the recorded pairs. Each listed pair outside them and the own pair holds a deferral
            // or takes one, which this Report anchors, while the list has room. The parser orders the entries by key
            // and refuses one key under two host IDs, and the deferrals are in key order, so one position passes
            // over the earlier deferrals as the census passes over the entries. A pair listed twice fills adjacent
            // entries, and the second finds the deferral the first took at the list's end.
            let pending = &mut self.authority.pending;
            let anchors = pending.len();
            let (mut within_bound, mut unlapsed) = (true, true);
            let (mut seen, mut waited) = (0, 0);
            let census = report.census(own, |pair| {
                if find_from(recorded.unwrap_or_default(), &mut seen, |held| held == pair).is_some()
                {
                    return true;
                }
                match anchor(&pending[..anchors], &mut waited, pair) {
                    Some(since) => {
                        unlapsed &= submitted_at.saturating_sub(since) < bounds.window();
                    }
                    None if pending[anchors..]
                        .last()
                        .is_some_and(|(last, _)| last == pair) => {}
                    None if pending.len() < bounds.registrant_max() as usize => {
                        pending.push((*pair, submitted_at));
                    }
                    None => within_bound = false,
                }
                false
            });
            let within_window = within_bound && unlapsed;
            let verdict = report.verdict(
                &census,
                own,
                Some(recorded.unwrap_or_default().iter()),
                bounds,
            );
            let defers = recorded.is_some()
                && verdict == Err(NotSole::ForeignRegistrant)
                && report.holding_of(&census, own, bounds) == Holding::One(own);
            let deferred = defers && within_window;
            // RECORDED-HOLDER-HOLD: a holder of the recorded pairs, beside registrants that are recorded or deferred
            // within their window, withdraws the owner with no flip request, so a reservation change by a recorded
            // attachment never retires the volume. NO-HOLDER-HOLD: a
            // Report with nobody holding withdraws the same way with `Cause::Unheld` when every registrant is the own
            // pair, a recorded pair, or a pair SERVING-DEFERS-UNRECORDED holds within its window, which the Report
            // anchors as a deferral does; the owner's poll then judges that pair against a fresh volume record. An
            // authority with no recorded set judges the no-holder hold after the boundary over the own pair alone. This
            // Report reads no listing; POST-WITHDRAWAL-POLL in `poll` keeps the listing check.
            //
            // Within the bound every listed pair outside a recorded set holds a deferral, so the hold tests admit
            // each registrant; an authority with no recorded set admits none beside the own pair.
            let beside = Census {
                unknown: census.unknown && recorded.is_none(),
                ..census
            };
            let holds = match (verdict, holders) {
                (Err(NotSole::ForeignHolder), Some(holders)) if within_bound => {
                    super::super::device::held_by_recorded(report, &beside, holders, own, bounds)
                        .then_some(Cause::RecordedHolder)
                }
                (
                    Err(NotSole::ReservationType | NotSole::NotHolder | NotSole::ForeignRegistrant),
                    recorded,
                ) if within_bound && (recorded.is_some() || !pre_boundary) => {
                    super::super::device::unheld_among_recorded(report, &beside, own, bounds)
                        .then_some(Cause::Unheld)
                }
                _ => None,
            };
            let hold = holds.filter(|_| unlapsed);
            let duplicate = super::super::device::own_record(&census).is_err();
            // LAPSE-UNVERIFIED: a Report that defers or holds but for a lapsed deferral withdraws with
            // `Cause::Unverified`, which requests no flip, and leaves the flip to the owner's poll. A second own
            // record and a deferral list past its bound keep their trigger and its flip.
            let lapsed = within_bound && !unlapsed && !duplicate && (defers || holds.is_some());
            #[cfg(test)]
            let lapsed = lapsed && !lapse_plant::FLIP_AT_LAPSE.get();
            if !deferred && hold.is_none() && !lapsed {
                pending.truncate(anchors);
            } else if anchors > 0 && pending.len() > anchors {
                // The deferrals this Report anchored follow the earlier ones, each run in key order.
                pending.sort_unstable_by_key(|(pair, _)| pair.key);
            }
            let refusal = if duplicate {
                Some(NotSole::DuplicateOwnRecord)
            } else if deferred {
                None
            } else {
                verdict.err()
            };
            // The serving refusal, or the verdict's refusal of a registrant SERVING-DEFERS-UNRECORDED defers.
            let judgment = match refusal.or(verdict.err()) {
                Some(refused) => RegistrantJudgment::Refused(refused),
                None if report.entries.iter().all(|entry| entry.pair == own) => {
                    RegistrantJudgment::Sole
                }
                None if (report.entries.iter()).any(|entry| {
                    entry.pair != own && (ended.contains(&entry.pair) || late.contains(&entry.pair))
                }) =>
                {
                    RegistrantJudgment::Ended
                }
                None => RegistrantJudgment::Recorded,
            };
            Some(Judged {
                refusal,
                foreign: census.foreign.map(|(holder, _)| holder.key.epoch()),
                hold: hold.or(lapsed.then_some(Cause::Unverified)),
                own_host: census.own_host,
                judgment,
            })
        } else {
            None
        };
        let own_records = match (&parsed, &sole) {
            (Ok(_), Some(evaluated)) => Some(evaluated.own_host),
            (Err(Some(super::super::device::ReportError::DuplicateOwnHostId { records })), _) => {
                Some(*records)
            }
            (Err(Some(super::super::device::ReportError::OwnHostIdKey)), _) => Some(1),
            _ => None,
        };
        let judged = sole.is_some();
        let (refusal, foreign, hold, judgment) = match sole {
            Some(evaluated) => (
                evaluated.refusal,
                evaluated.foreign,
                evaluated.hold,
                evaluated.judgment,
            ),
            None => {
                let refusal = parsed
                    .as_ref()
                    .err()
                    .copied()
                    .flatten()
                    .map(|error| error.refusal());
                // A Report of the own pair that gave no bytes to judge reads `Unreadable`, as `own_records` reads
                // no count for it.
                (
                    refusal,
                    None,
                    None,
                    RegistrantJudgment::Refused(refusal.unwrap_or(NotSole::Unreadable)),
                )
            }
        };
        // Each Report of the own pair is the last evaluated Report: the judgment, the hold and `own_records` all
        // describe it. A closed machine keeps the snapshot it closed with.
        if hold == Some(Cause::Unverified) {
            self.authority.lapsed_at = self.authority.lapsed_at.max(submitted_at);
        }
        if own.is_some() && self.authority.machine.state() != State::Closed {
            self.authority.own_records = own_records;
            self.authority.registrants = Some(judgment);
            self.authority.held = matches!(hold, Some(Cause::RecordedHolder | Cause::Unheld));
        }
        let observed = judged || refusal.is_some_and(NotSole::observed);
        let rejudge = &mut self.authority.rejudge;
        *rejudge =
            rejudge.and_then(|before| (before == Some(command) || !observed).then_some(None));
        let trigger = refusal.and_then(|refusal| retirement(refusal, pre_boundary));
        if current && gate && !authority_lost {
            let succeeded = limits
                .zip(status(terminal))
                .is_some_and(|(limits, status)| {
                    super::fence::succeeded(status, limits.report_bytes())
                });
            let verdict = match own {
                Some(own) => super::fence::judge(succeeded, &parsed, own, &self.authority.bounds),
                None => Err(super::fence::GateRefusal::AuthorityLost),
            };
            self.gate_judged(verdict);
        }
        if current || trigger.is_some() {
            let telemetry = match (refusal, foreign) {
                (None, _) if judged => None,
                (Some(NotSole::DuplicateOwnRecord), _) if !pre_boundary => {
                    Some(AuthorityRefusal::OwnHostId)
                }
                (Some(_), Some(foreign)) => own.map(|own| match own.key.epoch().cmp(&foreign) {
                    std::cmp::Ordering::Greater => AuthorityRefusal::ForeignLower,
                    std::cmp::Ordering::Equal => AuthorityRefusal::ForeignEqual,
                    std::cmp::Ordering::Less => AuthorityRefusal::ForeignHigher,
                }),
                (Some(refusal), _) if judged && refusal != NotSole::Unreadable => None,
                _ => Some(AuthorityRefusal::ReportMalformed),
            };
            if telemetry.is_some() {
                self.authority.refusal = telemetry;
            }
        }
        match (trigger, refusal, own) {
            (Some(_), ..) if let Some(cause) = hold => {
                self.authority_apply(Event::Withdraw(cause));
            }
            (Some(trigger), ..) => {
                self.authority_apply(Event::Withdraw(Cause::Report(trigger)));
            }
            (None, None, Some(pair)) if current && judged => {
                self.authority_apply(Event::OwnHolder(serving::OwnReport {
                    pair,
                    lineage,
                    submitted_at,
                    certified_at: self.authority.now,
                }));
            }
            _ if current => {
                self.authority_apply(Event::Expire {
                    now: self.authority.now,
                });
            }
            _ => {}
        }
        true
    }

    /// Recovery and restart owners supply tuple-scoped events on this thread.
    pub fn authority_event(&mut self, event: Event) -> Outcome {
        self.authority_deadlines();
        self.authority_apply(event)
    }

    #[cfg(test)]
    pub(crate) fn withhold(&self) -> crate::failover::withhold::Withhold {
        *self.authority.machine.withhold()
    }

    /// A stored Report expires one serving window after submission. `poll_report` returns `NotSole::Unreadable`
    /// when the latest deadline sample reaches or passes that boundary.
    pub fn poll_report(&self) -> Result<PolledReport, NotSole> {
        let a = &self.authority;
        let (submitted_at, rtype, regctl, len) = a.polled?;
        if a.now.saturating_sub(submitted_at) >= a.bounds.window() {
            return Err(NotSole::Unreadable);
        }
        Ok(PolledReport {
            submitted_at,
            rtype,
            regctl,
            entries: a.entries[..len].to_vec(),
        })
    }

    /// The serving clock's reading at the latest deadline sample.
    pub fn serving_sample(&self) -> u64 {
        self.authority.now
    }

    /// RECORDED-PAIRS-FOLLOW-READS: a volume record of `holder`'s volume in `reads` replaces the authority's recorded
    /// pairs with the pairs it admits, its recorded pairs and each pair `report` lists under an ended attach's key
    /// (ENDED-NEVER-RETIRES), and drops the deferral of each admitted pair before [`poll::poll`] judges `reads`, whose
    /// Report the poll judges against that volume record. A deferred pair the record does not enroll keeps its window, and a
    /// poll without a volume record changes nothing. The caller completes such a poll within one serving window of a
    /// legitimate standby's first deferred Report. ROLE-BOUND: once the authority observed a later tenure
    /// (`Machine::superseded`), `owner_poll` returns [`Verdict::Deposed`] at once, because the record has left the
    /// caller's target `(g, owner, E)` for a later tenure. TransferRetainsVolume: when a planned exit withdrew the
    /// machine (`Cause::Planned`) and [`poll::poll`] yields [`Verdict::Retire`], `owner_poll` returns
    /// [`Verdict::Withdraw`], because the shard's next tenure takes over the same volume; every other verdict of
    /// [`poll::poll`], [`Verdict::Deposed`] included, passes through. LAPSE-UNVERIFIED: `sent_at` is the
    /// serving-clock sample ([`Self::serving_sample`]) at which the caller sent `reads`, after it took `report`
    /// (READ-ORDER). While the machine is withdrawn with `Cause::Unverified`, a Report counts as unread unless
    /// `sent_at` is at or after its submission and less than a serving window past it, for the admission refresh as
    /// for the verdict, so a lapsed pair retires only on a Report that lay inside its window when the reads were
    /// sent and the volume record the caller read after it, and a store that answers later than one window delays
    /// the lapsed pair's flip by its latency alone. A `Continue`, `Unobserved` or `Withdraw` verdict over a present
    /// shard read, which therefore names the target, sets [`Self::lapse_verified`] when this poll's volume record
    /// admits every deferred pair (the recorded pairs and the pairs listed under an ended attach's key), or when a
    /// Report with a conclusive count, submitted after the last Report the lapse judged, lists none of the pairs
    /// still deferred.
    pub fn owner_poll(
        &mut self,
        holder: &Holder,
        target: Target,
        own: Pair,
        report: Result<&Report<'_>, NotSole>,
        reads: &Reads<'_>,
        sent_at: u64,
    ) -> Verdict {
        let a = &self.authority;
        let unverified = a.machine.state() == State::Withdrawn
            && a.machine.cause() == Some(Cause::Unverified)
            && a.machine.flip_open();
        // LAPSE-UNVERIFIED: while the machine is withdrawn with `Cause::Unverified`, the poll takes a Report's rows as
        // evidence only inside the Report's serving window on the authority's clock, measured at the sample the
        // caller sent its reads at; a Report stamped after that sample and an older Report read as unread, for the
        // admission refresh, the verdict and the absence test alike.
        let fresh = |report: &Report<'_>| {
            #[cfg(test)]
            if lapse_plant::IGNORE_REPORTS.get() {
                return false;
            }
            #[cfg(test)]
            let Some(sent_at) = (if lapse_plant::AGE_AT_THE_POLL.get() {
                a.reading()
            } else {
                Some(sent_at)
            }) else {
                return false;
            };
            sent_at
                .checked_sub(report.submitted_at)
                .is_some_and(|age| age < a.bounds.window())
        };
        let report = match report {
            Ok(report) if unverified && !fresh(report) => Err(NotSole::Unreadable),
            report => report,
        };
        let volume = reads.volume.filter(|record| record.volume == holder.volume);
        if let Some(record) = volume {
            let a = &mut self.authority;
            a.pending
                .retain(|(pair, _)| record.registrant(pair) == Registration::Unknown);
            let held = a.recorded.as_deref().unwrap_or_default();
            let listed = report
                .ok()
                .filter(|report| report.counted(&a.bounds))
                .map(|report| report.entries);
            let carried = match listed {
                Some(_) => &[][..],
                None => &held[held.len().saturating_sub(a.ended_admitted)..],
            };
            let admitted = record.admitted(listed.unwrap_or_default()).chain(
                carried
                    .iter()
                    .filter(|pair| record.registrant(pair) == Registration::Ended),
            );
            if !(a.recorded.as_deref()).is_some_and(|held| held.iter().eq(admitted.clone())) {
                let mut next = Vec::with_capacity(admitted.clone().count());
                next.extend(admitted.copied());
                a.recorded = Some(next.into_boxed_slice());
            }
            a.ended_admitted = a.recorded.as_deref().map_or(0, <[Pair]>::len) - record.pairs.len();
            if !a.ended_pairs.iter().eq(record.ended_attach_pairs()) {
                a.ended_pairs = record.ended_attach_pairs().copied().collect();
            }
        }
        if self.authority.machine.superseded() {
            return Verdict::Deposed;
        }
        let verdict = match poll::poll(holder, target, own, report, reads, &self.authority.bounds) {
            Verdict::Retire(_) if self.authority.machine.planned() => Verdict::Withdraw,
            verdict => verdict,
        };
        // ROLE-BOUND: `poll::judge` deposes on a shard read that does not name `target` and the holder, so these
        // verdicts over a present shard read name the tenure.
        if unverified
            && reads.shard.is_some()
            && matches!(
                verdict,
                Verdict::Continue | Verdict::Unobserved | Verdict::Withdraw
            )
        {
            let a = &self.authority;
            let pending = &a.pending;
            // The absence test takes a conclusive Report submitted after the last one the lapse judged.
            let unlisted = report.is_ok_and(|report| {
                !pending.is_empty()
                    && report.submitted_at > a.lapsed_at
                    && report.holding(&a.bounds) != crate::failover::evidence::Holding::Inconclusive
                    && !(report.entries.iter())
                        .any(|entry| pending.iter().any(|(pair, _)| *pair == entry.pair))
            });
            let admitted = volume.is_some() && pending.is_empty();
            self.authority.verified |= admitted || unlisted;
        }
        verdict
    }

    /// LAPSE-UNVERIFIED: whether an owner poll of the tenure withdrawn with `Cause::Unverified` read a shard record
    /// naming the tenure beside a volume record that admits every deferred pair, or beside a conclusive Report inside
    /// its window, submitted after the last Report the lapse judged, that lists none of the pairs still deferred.
    pub fn lapse_verified(&self) -> bool {
        self.authority.verified
    }

    /// The caller supplies `volume` from a read of `holder.volume` after the poll that judged `report` and returned
    /// `verdict`. On [`Verdict::Continue`], an authority that holds a serving token and passes the read gate's loss,
    /// closure and fencing-boundary checks ([`Volume::past_gate`]) consults [`poll::reclaim`] with `report` and
    /// `volume`. FRESH-AT-EFFECT: after `poll::reclaim`, the read gate ([`Volume::admission`]) must admit a read for
    /// the serving token at a new clock reading, so the step issues a command and returns a pair only where the
    /// volume admits a read. ENDED-PREEMPT: when `poll::reclaim` names a key, `authority.preempt` is `None` and
    /// [`EndedPreempt::resolve`] admits the key for the serving token's pair, `owner_reclaim` submits one
    /// `PreemptEnded`. EndOrder: `owner_reclaim` returns the recorded pairs of ended entries whose keys `report` does
    /// not list and that an earlier call saw ended at a reading before `report` was submitted. Every other verdict,
    /// state or read yields an empty list and no command. A submit refused for the device's loss sets `lost` and
    /// yields an empty list.
    pub fn owner_reclaim(
        &mut self,
        _gate: &StandbyGate,
        holder: &Holder,
        verdict: &Verdict,
        report: Result<&Report<'_>, NotSole>,
        volume: &VolumeRecord,
    ) -> Vec<Pair> {
        let Some(token) = self.serving_token() else {
            return Vec::new();
        };
        let serves = *verdict == Verdict::Continue
            && volume.volume == holder.volume
            && self.past_gate().is_ok();
        let report = match report {
            Ok(report) if serves => report,
            _ => return Vec::new(),
        };
        let a = &mut self.authority;
        // The reading follows the volume read that showed each newly seen ended pair.
        let Some(seen) = a.clock.now_us().filter(|now| *now >= a.now) else {
            return Vec::new();
        };
        (a.ended).retain(|(pinned, _)| volume.ended_pairs().any(|held| held == pinned));
        for held in volume.ended_pairs() {
            if !a.ended.iter().any(|(pinned, _)| pinned == held) {
                a.ended.push((*held, seen));
            }
        }
        let own = Pair {
            exhid: token.exhid,
            key: token.key,
        };
        let bounds = a.bounds;
        let reclaim = poll::reclaim(report, volume, &bounds);
        let preempt = (reclaim.preempt)
            .filter(|_| self.authority.preempt.is_none())
            .and_then(|key| EndedPreempt::resolve(report, volume, key, own, &bounds).ok());
        if self.admission().is_err() {
            return Vec::new();
        }
        if let Some(preempt) = preempt {
            #[cfg(test)]
            reclaim_plant::submitted(preempt.ended());
            let submitted = self.submit_ordered(|_| ReservationCommand::PreemptEnded(preempt));
            self.authority.preempt = self.sent(submitted);
            if self.lost {
                return Vec::new();
            }
        }
        let sightings = &self.authority.ended;
        let mut dropped = reclaim.dropped;
        dropped.retain(|pair| {
            let pinned = volume.ended_pairs().find(|held| held.pair == *pair);
            (sightings.iter())
                .any(|(sighted, at)| Some(sighted) == pinned && *at < report.submitted_at)
        });
        #[cfg(test)]
        reclaim_plant::receipt(volume, &mut dropped);
        dropped
    }

    /// Steps the machine and applies the step's effects. This function and [`Machine::step`] are `#[inline(always)]`,
    /// so a call site that builds its event lets the compiler reduce the step's match to that event's arm and drop an
    /// outcome the site ignores.
    #[inline(always)]
    fn authority_apply(&mut self, event: Event) -> Outcome {
        let outcome = self.authority.machine.step(event);
        self.authority_effects();
        outcome
    }
}

/// The LAPSE-UNVERIFIED controls' planted defects: while `FLIP_AT_LAPSE` is set, a lapsed deferral refuses with its
/// Report trigger and requests the flip; while `IGNORE_REPORTS` is set, the owner poll of a tenure withdrawn with
/// `Cause::Unverified` takes no Report's rows as evidence, so no Report-based retirement follows the lapse; while
/// `AGE_AT_THE_POLL` is set, that poll measures a Report's age on a reading taken at the call whatever send sample
/// its caller passes.
#[cfg(test)]
pub(crate) mod lapse_plant {
    use std::cell::Cell;

    thread_local! {
        pub(crate) static FLIP_AT_LAPSE: Cell<bool> = const { Cell::new(false) };
        pub(crate) static IGNORE_REPORTS: Cell<bool> = const { Cell::new(false) };
        pub(crate) static AGE_AT_THE_POLL: Cell<bool> = const { Cell::new(false) };
    }
}

/// The EndOrder control's planted defect: while `DROP_ON_STATUS` is set, a preempt whose terminal carries a success
/// status counts as the receipt that its key left, and the next reclaim step returns the ended pairs under that key.
#[cfg(test)]
pub(crate) mod reclaim_plant {
    use std::cell::Cell;

    use crate::failover::evidence::Pair;
    use crate::failover::identity::Key;
    use crate::failover::records::VolumeRecord;

    thread_local! {
        static DROP_ON_STATUS: Cell<bool> = const { Cell::new(false) };
        static SUBMITTED: Cell<Option<Key>> = const { Cell::new(None) };
        static RECEIPT: Cell<Option<Key>> = const { Cell::new(None) };
    }

    /// Each call starts an independent history on the calling thread.
    pub(crate) fn arm(planted: bool) {
        DROP_ON_STATUS.set(planted);
        SUBMITTED.set(None);
        RECEIPT.set(None);
    }

    pub(super) fn submitted(key: Key) {
        SUBMITTED.set(Some(key));
    }

    pub(super) fn completed() {
        if DROP_ON_STATUS.get() {
            RECEIPT.set(SUBMITTED.get());
        }
    }

    pub(super) fn receipt(volume: &VolumeRecord, dropped: &mut Vec<Pair>) {
        let Some(key) = RECEIPT.get().filter(|_| DROP_ON_STATUS.get()) else {
            return;
        };
        for held in volume.ended_pairs() {
            if held.pair.key == key && !dropped.contains(&held.pair) {
                dropped.push(held.pair);
            }
        }
    }
}

/// The submission time that anchors `pair` among `deferrals`, which are in key order. `from` is the position the
/// last lookup reached: lookups arrive in key order, so one position passes over the deferrals.
fn anchor(deferrals: &[(Pair, u64)], from: &mut usize, pair: &Pair) -> Option<u64> {
    while deferrals
        .get(*from)
        .is_some_and(|(deferred, _)| deferred.key < pair.key)
    {
        *from += 1;
    }
    deferrals[*from..]
        .iter()
        .take_while(|(deferred, _)| deferred.key == pair.key)
        .find(|(deferred, _)| deferred == pair)
        .map(|&(_, since)| since)
}

fn retirement(refusal: NotSole, pre_boundary: bool) -> Option<serving::ReportTrigger> {
    match refusal {
        NotSole::DuplicateOwnRecord if pre_boundary => None,
        refusal => serving::ReportTrigger::new(refusal),
    }
}

fn status(terminal: &Terminal<'_>) -> Option<super::super::device::DeviceStatus> {
    match terminal {
        Terminal::Read { status, .. }
        | Terminal::Written { status, .. }
        | Terminal::Failed { status, .. } => Some(*status),
        Terminal::Reservation { status, .. } | Terminal::Abandoned { status, .. } => *status,
        Terminal::Quiesced { .. } => None,
    }
}

#[cfg(test)]
mod clock_tests {
    use super::{BootClock, ServingClock};

    #[test]
    fn a_wide_sample_preserves_the_tight_offset_bound_and_detects_suspend() {
        let mut clock = BootClock::default();
        assert_eq!(clock.observe(1_000, 2_000, 1_000), Some(2));
        assert_eq!(clock.observe(2_000, 12_000, 12_000), Some(12));
        assert_eq!(clock.observe(13_000, 15_000, 13_000), None);
        assert_eq!(clock.observe(14_000, 16_000, 14_000), None);
        clock.clear_suspend();
        assert_eq!(clock.observe(15_000, 17_000, 15_000), Some(17));
        assert_eq!(clock.observe(16_000, 19_000, 16_000), None);
    }

    /// Scripted clocks: before each read monotonic time advances by the next entry of `steps`, or 20 ns once it is empty; boot time is monotonic time plus `offset`.
    struct Host {
        monotonic: u64,
        offset: u64,
        steps: std::collections::VecDeque<u64>,
        reads: u32,
    }

    impl Host {
        fn new() -> Self {
            Self {
                monotonic: 5_000_000_000,
                offset: 7_000_000_000,
                steps: std::collections::VecDeque::new(),
                reads: 0,
            }
        }

        fn read(&mut self, clock: &BootClock) -> Option<u64> {
            clock.read(|id| {
                self.reads += 1;
                self.monotonic += self.steps.pop_front().unwrap_or(20);
                Some(if id == libc::CLOCK_BOOTTIME {
                    self.monotonic + self.offset
                } else {
                    self.monotonic
                })
            })
        }
    }

    #[test]
    fn a_tight_bound_leaves_two_read_readings_that_still_detect_suspend() {
        let (mut clock, mut host) = (BootClock::default(), Host::new());
        assert!(host.read(&clock).is_some());
        assert_eq!(host.reads, 3, "the first reading brackets boot time");
        for _ in 0..100 {
            host.monotonic += 1_000_000;
            assert!(host.read(&clock).is_some(), "a constant offset");
        }
        assert_eq!(host.reads, 3 + 200, "each later reading reads twice");
        host.offset += 2_000;
        assert_eq!(host.read(&clock), None, "a 2 µs suspend");
        let reads = host.reads;
        assert_eq!(host.read(&clock), None, "the suspend stays reported");
        assert_eq!(host.reads - reads, 3, "the detection loosened the bound");
        clock.clear_suspend();
        assert!(host.read(&clock).is_some());
        assert!(host.read(&clock).is_some());
        host.offset += 2_000;
        assert_eq!(host.read(&clock), None, "a second suspend");
    }

    /// A time namespace may set its boot-time offset below its monotonic one, so boot time reads behind monotonic time.
    #[test]
    fn a_suspend_is_reported_where_boot_time_runs_behind_monotonic_time() {
        let clock = BootClock::default();
        let behind = 1_000_000_000;
        let mut monotonic = 5_000_000_000_u64;
        let mut suspended = 0;
        let mut read = |suspended: u64| {
            clock.read(|id| {
                monotonic += 20;
                Some(if id == libc::CLOCK_BOOTTIME {
                    monotonic + suspended - behind
                } else {
                    monotonic
                })
            })
        };
        for _ in 0..10 {
            assert!(read(suspended).is_some(), "a constant offset");
        }
        suspended += 500_000;
        assert_eq!(read(suspended), None, "a 500 µs suspend");
    }

    #[test]
    fn a_loose_bracket_keeps_bracketing_and_one_clock_tick_reports_no_suspend() {
        let (clock, mut host) = (BootClock::default(), Host::new());
        host.steps
            .extend([5_000, 5_000, 5_000, 5_000, 5_000, 5_000]);
        assert!(host.read(&clock).is_some());
        assert!(host.read(&clock).is_some(), "a wide bracket is no suspend");
        assert_eq!(host.reads, 6, "a loose bound brackets again");
        host.steps.extend([20, 20, 20, 20, 500]);
        assert!(host.read(&clock).is_some(), "a tight bracket");
        assert!(host.read(&clock).is_some(), "a 500 ns gap after boot time");
        host.steps.extend([0, 0, 0, 0, 0]);
        for _ in 0..2 {
            assert!(host.read(&clock).is_some(), "readings within one tick");
        }
    }
}
