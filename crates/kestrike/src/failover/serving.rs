//! The serving-authority table of one tenure: five states stepped by the table's event columns and matched exhaustively by state and column, beside three state-independent withhold inputs.
//!
//! - BOUNDARY-FIRST: a machine starts in `PreBoundary`, which admits no read, fill, reply or metadata submission. Only [`Machine::cross_boundary`] enters `Recovering`, and it takes the attach gate's [`Fenced`] value, which only a passing Report of a gate sequence mints, so no admission precedes the fencing boundary (`NoWriteBeforeFB`).
//! - OWN-SESSION-TOKEN: Each machine holds one token identifying its shard and session `(g, a)`. Admission permits sends and writes only when the whole token matches. [`Machine::gated`] issues the token at construction for the pair registered by the attach's Register, Acquire and Report gate. [`Machine::new`] issues the token at the fencing boundary for the pair named by its [`Fenced`] value.
//! - WINDOW-IS-AVAILABILITY: a Report's belief holds on `[t_submit, t_submit + delta)`; outside that window `Recovering` and `Serving` admit nothing and keep their state and custody, and a Report timeout, an unreadable Report or a clock fault closes the window without moving the state. A Report whose registrant set or parse refusal shows retirement evidence withdraws instead.
//! - WITHDRAWN-EXITS-ONLY-TO-CLOSED: every [`Cause`] moves each state except `Closed` to `Withdrawn`. `Withdrawn` refuses every admission and medium command, retains the registration and command custody, and moves only to `Closed`. Deposition observations, a deposing command status and a recorded holder's Report included, a Report with nobody holding beside recorded registrants and a Report that would defer or hold but for a lapsed deferral ([`Cause::Unverified`]) produce the withdrawal alone (`DetectedLossWithdraws`). While [`Machine::flip_open`] holds, a retirement trigger records its cause, emits [`Effect::RequestFlip`] naming the own `(g, owner, E)` and closes [`Machine::flip_open`], whether the trigger withdraws the machine or follows a withdrawal alone. A withdrawal by a planned exit ([`Cause::Planned`]) closes [`Machine::flip_open`] and keeps the volume for the shard's next tenure (`TransferRetainsVolume`); a planned exit stepped on a machine another cause already withdrew keeps that withdrawal's cause and flip state. A cause that observed a later tenure ([`Cause::shows_successor`]), whether it withdrew the machine or came later, marks the tenure's `(g, owner, E)` stale and closes [`Machine::flip_open`], so the withdrawal keeps its cause from then on (`SupersededRequestsNoFlip`). A flip request emitted before that observation stays recorded, and `Retirement::admit` refuses the request once the record has left the `(g, owner, E)` the request names.
//! - WITHHOLD-IS-AVAILABILITY: [`Event::Refresh`], [`Event::ReadFailed`] and [`Event::Peer`] update the [`Withhold`] in every state and move no state; a store timeout or an unavailable read is such an input. The withhold refuses [`Operation::Get`] at the owner's serving gate, which the owner answers as a miss, and a parked GET at its wake visit; device reads already admitted run to completion.
//!
//! Each `Machine` gate answers through `admit`, `retry` or `admit_metadata` over the machine's `Standing` at the decision's `now`: the state, the held token, the window bounds, the fill latch and whether the withhold holds at that `now`.
//!
//! Every timestamp the table takes, its bounds and the withhold inputs included, is in microseconds on one nondecreasing, suspend-aware elapsed clock.

use super::bounds::Bounds;
use super::evidence::{NotSole, PREEMPT_ABORTED, Pair, RESERVATION_CONFLICT};
use super::identity::{Exhid, Key};
use super::retire::Target;
use super::withhold::Withhold;
use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration};
use crate::storage::{Fenced, Session};

/// A serving-authority state. `PreBoundary` lies before the fencing boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    PreBoundary,
    Recovering,
    Serving,
    Withdrawn,
    Closed,
}

/// A serving token: the shard and the `(g, a)` of the machine's session, the own pair whose Reports renew the window, and `lineage`, the incarnation, which is 1 for the one token a machine issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token {
    pub shard: Shard,
    pub generation: ShardGeneration,
    pub epoch: ActivatedEpoch,
    pub exhid: Exhid,
    pub key: Key,
    pub lineage: u32,
}

/// A metadata or capture step the metadata owner submits. A checkpoint unit is a capture's write or read-back of
/// one unit of a checkpoint slot; the root kinds are the bootstrap's probes, RESET roots and named-slot reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetadataKind {
    CheckpointUnit,
    CheckpointRoot,
    ResetRoot,
}

/// An rtype-2 Report with the own pair as sole holder, submitted under the token of `lineage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OwnReport {
    pub pair: Pair,
    pub lineage: u32,
    pub submitted_at: u64,
    pub certified_at: u64,
}

/// A Report's retirement evidence: a [`NotSole`] refusal that observes the Report's registrant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReportTrigger(NotSole);

impl ReportTrigger {
    /// Observed registrant-set refusals produce a trigger; [`NotSole::Unreadable`] produces `None`.
    pub fn new(refusal: NotSole) -> Option<Self> {
        refusal.observed().then_some(Self(refusal))
    }

    pub fn refusal(self) -> NotSole {
        self.0
    }
}

/// A certified command status that deposes the tenure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Deposing {
    /// NVMe status code `0x83`.
    Conflict,
    /// NVMe status code `0x1b`.
    PreemptAborted,
}

/// Why the owner withdraws, from a closed list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cause {
    /// A Report whose registrant set fails the admitted-registrant check (`Report::registrants`) for the own pair.
    Report(ReportTrigger),
    /// RECORDED-HOLDER-HOLD: a serving Report in which a pair of another attachment holds the type-2 reservation
    /// beside registrants that are recorded or deferred within their serving window, judged against the recorded pairs of the authority's last volume-record read. The owner withdraws and alarms; the retained volume awaits its recovery, so the
    /// withdrawal requests no flip. The owner's poll keeps the listing check (POST-WITHDRAWAL-POLL).
    RecordedHolder,
    /// NO-HOLDER-HOLD: a serving Report in which nobody holds the reservation, beside the own pair and registrants
    /// that are recorded or deferred within their serving window, judged as [`Cause::RecordedHolder`] is. A
    /// registration that ended without a preempt, or a reservation the own pair never acquired, shows no volume loss,
    /// so the owner withdraws and alarms with no flip request, and the owner's poll judges the registrants against a
    /// fresh volume record and keeps the listing check.
    Unheld,
    /// LAPSE-UNVERIFIED: a serving Report that SERVING-DEFERS-UNRECORDED would defer, or hold under
    /// [`Cause::RecordedHolder`] or [`Cause::Unheld`], but for a non-holding registrant whose deferral window
    /// ended. Its foreignness rests on the authority's last volume-record read, and a legitimate standby's pair is
    /// enrolled before it registers, so a store that fails or answers late past the window leaves that read without
    /// the standby's enrollment. The owner stops serving with no flip request, the authority keeps its periodic
    /// Report, and the owner's poll decides from a Report inside its window and a later volume-record read
    /// (`Volume::owner_poll`). Beside the own holder the reservation keeps the registrant from medium I/O; beside
    /// nobody holding, or a reservation of type 0, it does not, and a pair that unregisters before the owner's reads
    /// return leaves no flip request.
    Unverified,
    Status(Deposing),
    /// A recorded force detach.
    ForceDetach,
    /// An attachment event beyond the first, or a control-plane attachment the desired state does not name.
    Attachment,
    /// A modification record against the active volume.
    Modification,
    /// A failed check of the same-host restart sequence.
    RestartCheck,
    /// The activation record failed its validation; the withdrawal requests no flip.
    ActivationRecord,
    /// `E` or `g` exhaustion.
    Exhausted,
    /// A planned exit: a transfer to the named standby, a requested same-host restart or a roll at a tenure bound.
    /// The shard's next tenure takes over the same volume, so the withdrawal requests no flip, and a machine it
    /// withdrew requests none afterwards.
    Planned,
    /// A shard-record value with another `(g, owner, E)`.
    Flipped,
    /// A coverage page result with `fence` above the own session.
    NewerFence {
        page: u16,
        fence: u64,
    },
    /// A failed store write whose result shows a later tenure.
    LaterTenure,
    /// A store result below the local watermark.
    Regression,
}

impl Cause {
    /// Whether the cause is a retirement trigger, whose withdrawal requests the flip; a deposition observation, a
    /// Report with nobody holding beside recorded registrants, an unverified registrant and a planned exit request none. STATUS-IS-DEPOSITION: a deposing command status (`0x83`, `0x1B`) shows that another
    /// registration holds or preempted; which registration, and whether the volume retires or holds, is the judgment
    /// of a Report the authority submits after the status (STATUS-REJUDGE), so the status withdraws alone and a
    /// later `Report` trigger emits the flip once while [`Machine::flip_open`] holds; a cause that observed a later
    /// tenure closes [`Machine::flip_open`]. A deposing status on a gate command ends the attach `Unfenced`. After
    /// the Acquire's or the gate Report's status the authority's Report judges the holder the same way; after the
    /// Register's status that Report shows the own host ID under another key, which is no retirement evidence before
    /// the boundary, so the withdrawal keeps `Cause::Status` and the owner's poll remains the judge.
    pub fn requests_flip(self) -> bool {
        match self {
            // UNIT-ZERO-INERT: unit 0 carries no authority, so no activation record proves volume loss.
            Self::RecordedHolder
            | Self::Unheld
            | Self::Unverified
            | Self::Status(_)
            | Self::ActivationRecord => false,
            Self::Report(_)
            | Self::ForceDetach
            | Self::Attachment
            | Self::Modification
            | Self::RestartCheck
            | Self::Exhausted => true,
            Self::Planned => false,
            Self::Flipped | Self::NewerFence { .. } | Self::LaterTenure | Self::Regression => false,
        }
    }

    /// Whether the cause observed a later tenure of the shard: a shard record naming another `(g, owner, E)`, a
    /// coverage page fenced above the own session, or a store write refused for a later tenure. The shard record
    /// has then left this tenure's `(g, owner, E)`, which a flip request would name, and a successor that retained
    /// the volume shares its generation, so a machine that took such a cause requests no flip afterwards.
    pub fn shows_successor(self) -> bool {
        match self {
            Self::Flipped | Self::NewerFence { .. } | Self::LaterTenure => true,
            Self::Report(_)
            | Self::RecordedHolder
            | Self::Unheld
            | Self::Unverified
            | Self::Status(_)
            | Self::ForceDetach
            | Self::Attachment
            | Self::Modification
            | Self::RestartCheck
            | Self::ActivationRecord
            | Self::Exhausted
            | Self::Planned
            | Self::Regression => false,
        }
    }

    /// Whether the cause names a later tenure of the shard: a cause that [shows a successor](Self::shows_successor),
    /// except a coverage page whose fence is no activated session ([`Session::is_activated`]). Every tenure fences
    /// its pages with its own activated session, so such a fence identifies no tenure. The machine still closes its
    /// flip on that page, and an exit judges the tenure deposed by this narrower fact.
    pub fn names_successor(self) -> bool {
        match self {
            Self::NewerFence { fence, .. } => Session::is_activated(fence),
            cause => cause.shows_successor(),
        }
    }
}

/// The readiness column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Readiness {
    /// The recovery owner opened recovered reads under this token.
    ReadReady {
        token: Token,
    },
    AllocationReady {
        token: Token,
    },
}

/// The events the table steps on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Event {
    OwnHolder(OwnReport),
    Withdraw(Cause),
    /// The window closes at `now`: a suspend, a clock fault, a Report timeout or an unreadable Report.
    Expire {
        now: u64,
    },
    Readiness(Readiness),
    Close,
    /// Recovery withheld the volume's content, ending this owner instance.
    Withheld,
    /// `now` is sampled at submission admission, after queueing.
    Metadata {
        token: Token,
        now: u64,
        kind: MetadataKind,
    },
    /// A command terminal carrying the lineage of the token it was issued under.
    Terminal {
        lineage: u32,
    },
    /// The freshness clock refreshed by a shard-record read or own CAS showing the own `(g, owner, E)`, sent at `at`.
    Refresh {
        at: u64,
    },
    /// A shard-record read sent at `sent_at` timed out or came back unavailable.
    ReadFailed {
        sent_at: u64,
    },
    /// The latest peer read time: over the admitted heartbeats in the zone that carry a read age and acknowledge a recent observer heartbeat, the latest send time of that acknowledged heartbeat minus the reported age; `None` clears the peer input.
    Peer {
        read_at: Option<u64>,
    },
}

/// The effect a transition carries beside its new state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    None,
    Issue(Token),
    /// The serving window now ends at `until`.
    Renew {
        until: u64,
    },
    /// The flip request, naming the shard record's `(g, owner, E)` of this tenure.
    RequestFlip(Target),
    AdmitFills,
}

/// Why an event changed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    Closed,
    Withdrawn,
    /// An own-holder Report before the fencing boundary, where only the gate's verdict acts on it.
    BeforeBoundary,
    /// Readiness arrived in a state that cannot use it.
    Miss,
    Duplicate,
    LineageMismatch,
    PairMismatch,
    /// Certification exceeded `T_report` or preceded submission.
    ReportLate,
    /// The Report was submitted at or before the window last closed.
    BeforeExpiry,
    /// The window closed; the state and custody stay, and admission refuses until a renewal.
    WindowClosed,
    /// A withhold input updated the withhold; the state stays.
    Availability,
    TerminalApplied,
    /// A terminal of another token applies to custody only.
    StaleTokenCustodyOnly,
}

/// Why an event was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rejection {
    /// This state cannot consume the event; duplicates and stale inputs stay.
    Unsupported {
        state: State,
    },
    /// A metadata submission outside Recovering and Serving, or a checkpoint unit outside Serving.
    MetadataRefused {
        state: State,
        kind: MetadataKind,
    },
    AuthorityDenied(Denial),
}

/// The result of one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    Moved {
        to: State,
        effect: Effect,
    },
    /// A duplicate, stale or currently unusable event, or a window closure or withhold input, leaves the state unchanged.
    Stayed(Reason),
    Rejected(Rejection),
    /// A metadata submission admitted under the token.
    Admitted(Token),
}

/// An operation checked against the token before it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// A GET at the owner's serving gate, a RAM hit included; the availability withhold refuses it.
    Get,
    /// A device read of admitted work; the withhold leaves it admitted, and the token and window checks still apply.
    Read,
    Fill,
    Reply {
        lineage: u32,
    },
}

/// Why an operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Denial {
    WindowExpired,
    WindowNotStarted,
    TokenMismatch,
    NotServing(State),
    FillsNotAdmitted,
    StaleLineage {
        lineage: u32,
        current: u32,
    },
    /// `0x83` and `0x1b` are never retried; the volume's terminal path withdraws on them.
    DeposingStatusNeverRetried(u16),
    /// The availability withhold answers the GET as a miss.
    Withheld,
}

/// A [`Machine`] snapshot for one admission decision.
///
/// Callers must pass the same `now` to `Machine::standing(now)` and the gate because the snapshot captures the
/// withhold at that time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Standing {
    pub(super) state: State,
    /// The held token; the gates admit only a submitted token equal to it in every field.
    pub(super) token: Option<Token>,
    /// The Report window `[window_start, window_end)`; the gates admit only while both bounds are present.
    pub(super) window_start: Option<u64>,
    pub(super) window_end: Option<u64>,
    /// The fill latch that `AllocationReady` sets; [`Operation::Fill`] requires it.
    pub(super) fills: bool,
    /// Whether the availability withhold holds at the decision's time; it refuses [`Operation::Get`] alone.
    pub(super) withheld: bool,
}

/// One tenure's serving authority, built from the tenure's session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    bounds: Bounds,
    shard: Shard,
    target: Target,
    epoch: ActivatedEpoch,
    state: State,
    token: Option<Token>,
    window_start: Option<u64>,
    window_end: Option<u64>,
    expired_at: Option<u64>,
    fills: bool,
    cause: Option<Cause>,
    /// A withdrawal cause observed a later tenure ([`Cause::shows_successor`]), in any state; a `Closed` machine keeps
    /// its state and cause and still latches the observation, so its owner poll is deposed.
    superseded: bool,
    /// A withdrawal cause named a later tenure ([`Cause::names_successor`]), latched as `superseded` is; it implies
    /// `superseded`.
    successor: bool,
    withhold: Withhold,
}

impl Machine {
    /// Starts in `PreBoundary` without a token for the tenure of `session`, with fresh local event custody.
    pub fn new(bounds: Bounds, session: &Session) -> Self {
        Self {
            bounds,
            shard: session.shard(),
            target: session.target(),
            epoch: session.epoch(),
            state: State::PreBoundary,
            token: None,
            window_start: None,
            window_end: None,
            expired_at: None,
            fills: false,
            cause: None,
            superseded: false,
            successor: false,
            withhold: Withhold::default(),
        }
    }

    pub fn gated(bounds: Bounds, session: &Session, pair: Pair) -> Self {
        let mut machine = Self::new(bounds, session);
        machine.token = Some(machine.token_for(pair));
        machine
    }

    pub fn bounds(&self) -> Bounds {
        self.bounds
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn token(&self) -> Option<Token> {
        self.token
    }

    pub fn window_start(&self) -> Option<u64> {
        self.window_start
    }

    pub fn window_end(&self) -> Option<u64> {
        self.window_end
    }

    pub fn expired_at(&self) -> Option<u64> {
        self.expired_at
    }

    /// The withdrawing cause, which a later retirement trigger replaces while [`Self::flip_open`] holds.
    pub fn cause(&self) -> Option<Cause> {
        self.cause
    }

    /// Whether a withdrawal cause named a later tenure of the shard ([`Cause::names_successor`]), in any state and
    /// after any first cause. A coverage page fenced above the session by a value that is no activated session sets
    /// [`Self::superseded`] alone.
    pub fn has_successor(&self) -> bool {
        self.successor
    }

    /// Whether a withdrawal cause observed a later tenure, after which the machine requests no flip.
    pub fn superseded(&self) -> bool {
        self.superseded
    }

    pub fn planned(&self) -> bool {
        self.cause == Some(Cause::Planned)
    }

    /// Whether a later retirement trigger can request the machine's first flip. It can until the machine requests that
    /// flip, observes a later tenure (`SupersededRequestsNoFlip`), withdraws for a planned exit
    /// (`TransferRetainsVolume`) or closes; from then on the machine keeps its withdrawal as it is.
    pub fn flip_open(&self) -> bool {
        self.state != State::Closed
            && self.flip_request().is_none()
            && !self.superseded
            && !self.planned()
    }

    /// The `(g, a)` of the machine's session.
    pub fn tenure(&self) -> (ShardGeneration, ActivatedEpoch) {
        (self.target.generation, self.epoch)
    }

    /// Whether the machine was built from `session`'s shard, flip target and activated epoch.
    pub(crate) fn built_from(&self, session: &Session) -> bool {
        self.shard == session.shard()
            && self.target == session.target()
            && self.epoch == session.epoch()
    }

    #[cfg(test)]
    pub(crate) fn withhold(&self) -> &Withhold {
        &self.withhold
    }

    /// The tenure's heartbeat read age at `now`, from its freshness clock.
    pub fn read_age(&self, now: u64) -> Option<u64> {
        self.withhold.read_age(now)
    }

    /// The flip request a withdrawal on a retirement trigger made.
    pub fn flip_request(&self) -> Option<Target> {
        self.cause
            .filter(|cause| cause.requests_flip())
            .map(|_| self.target)
    }

    pub(crate) fn awaits_readiness(&self) -> bool {
        match self.state {
            State::Recovering => true,
            State::Serving => !self.fills,
            State::PreBoundary | State::Withdrawn | State::Closed => false,
        }
    }

    /// Enters `Recovering` at the fencing boundary from `PreBoundary`; `fenced` is the gate's value, so no other path reaches `Recovering`. A machine without a token issues the tenure's token for the pair `fenced` names, with no window until an own-holder Report renews it.
    pub(crate) fn cross_boundary(&mut self, fenced: &Fenced) -> Outcome {
        match (self.state, self.token) {
            (State::PreBoundary, Some(token)) => {
                debug_assert_eq!(
                    (token.exhid, token.key),
                    (fenced.own().exhid, fenced.own().key)
                );
                self.move_to(State::Recovering, Effect::None)
            }
            (State::PreBoundary, None) => {
                let token = self.token_for(fenced.own());
                self.token = Some(token);
                self.move_to(State::Recovering, Effect::Issue(token))
            }
            (state, _) => Outcome::Rejected(Rejection::Unsupported { state }),
        }
    }

    /// Steps the closed table. Every timestamp is in microseconds on one nondecreasing, suspend-aware elapsed clock, the unit of the Bounds; the owner consumes due expiries before evidence, readiness or new admissions.
    #[inline(always)]
    pub fn step(&mut self, event: Event) -> Outcome {
        match event {
            Event::Terminal { lineage } => self.terminal(lineage),
            Event::Metadata { token, now, kind } => self.metadata(&token, now, kind),
            Event::OwnHolder(ref report) => self.own_holder(report),
            Event::Expire { now } => self.expire(now),
            Event::Withdraw(cause) => self.withdraw(cause),
            Event::Readiness(ref readiness) => self.readiness(readiness),
            Event::Close => self.close(),
            Event::Withheld => self.withheld(),
            Event::Refresh { at } => {
                self.withhold.refresh(at);
                Outcome::Stayed(Reason::Availability)
            }
            Event::ReadFailed { sent_at } => {
                self.withhold.failed(sent_at);
                Outcome::Stayed(Reason::Availability)
            }
            Event::Peer { read_at } => {
                self.withhold.peer(read_at);
                Outcome::Stayed(Reason::Availability)
            }
        }
    }

    #[inline]
    fn terminal(&self, lineage: u32) -> Outcome {
        use State as S;
        Outcome::Stayed(match self.state {
            S::PreBoundary | S::Recovering | S::Serving | S::Withdrawn
                if self.token.is_some_and(|token| token.lineage == lineage) =>
            {
                Reason::TerminalApplied
            }
            S::PreBoundary | S::Recovering | S::Serving | S::Withdrawn | S::Closed => {
                Reason::StaleTokenCustodyOnly
            }
        })
    }

    /// The answer of [`admit_metadata`] at the machine's [`Standing`] at `now`.
    #[inline]
    pub(crate) fn metadata(&self, submitted: &Token, now: u64, kind: MetadataKind) -> Outcome {
        admit_metadata(self.standing(now), *submitted, now, kind)
    }

    #[inline]
    fn own_holder(&mut self, report: &OwnReport) -> Outcome {
        use State as S;
        match self.state {
            S::Recovering | S::Serving => {
                if let Err(reason) = self.reported_token(report) {
                    return Outcome::Stayed(reason);
                }
                if self.expired_at.is_some_and(|at| report.submitted_at <= at) {
                    return Outcome::Stayed(Reason::BeforeExpiry);
                }
                let until = self.renew(report.submitted_at);
                self.move_to(self.state, Effect::Renew { until })
            }
            S::PreBoundary => Outcome::Stayed(Reason::BeforeBoundary),
            S::Withdrawn => Outcome::Stayed(Reason::Withdrawn),
            S::Closed => Outcome::Stayed(Reason::Closed),
        }
    }

    fn expire(&mut self, now: u64) -> Outcome {
        use State as S;
        match self.state {
            S::Recovering | S::Serving | S::PreBoundary => {
                self.expired_at = Some(self.expired_at.map_or(now, |at| at.max(now)));
                self.window_end = self.window_end.map(|end| end.min(now));
                Outcome::Stayed(Reason::WindowClosed)
            }
            S::Withdrawn => Outcome::Stayed(Reason::Withdrawn),
            S::Closed => Outcome::Stayed(Reason::Closed),
        }
    }

    fn withdraw(&mut self, cause: Cause) -> Outcome {
        use State as S;
        self.superseded |= cause.shows_successor();
        self.successor |= cause.names_successor();
        match self.state {
            S::PreBoundary | S::Recovering | S::Serving => {
                self.window_start = None;
                self.window_end = None;
                self.cause = Some(cause);
                let effect = self
                    .flip_request()
                    .map_or(Effect::None, Effect::RequestFlip);
                self.move_to(S::Withdrawn, effect)
            }
            S::Withdrawn if self.flip_open() && cause.requests_flip() => {
                self.cause = Some(cause);
                Outcome::Moved {
                    to: S::Withdrawn,
                    effect: Effect::RequestFlip(self.target),
                }
            }
            S::Withdrawn => Outcome::Stayed(Reason::Withdrawn),
            S::Closed => Outcome::Stayed(Reason::Closed),
        }
    }

    fn readiness(&mut self, readiness: &Readiness) -> Outcome {
        use Readiness::{AllocationReady, ReadReady};
        use State as S;
        match (self.state, *readiness) {
            (S::Recovering, ReadReady { token }) => {
                if self.token != Some(token) {
                    return Outcome::Rejected(Rejection::AuthorityDenied(Denial::TokenMismatch));
                }
                self.move_to(S::Serving, Effect::None)
            }
            (S::Serving, ReadReady { token }) => Outcome::Stayed(if self.token == Some(token) {
                Reason::Duplicate
            } else {
                Reason::LineageMismatch
            }),
            (S::Serving, AllocationReady { token }) => {
                if self.token != Some(token) {
                    return Outcome::Stayed(Reason::LineageMismatch);
                }
                if self.fills {
                    return Outcome::Stayed(Reason::Duplicate);
                }
                self.fills = true;
                self.move_to(S::Serving, Effect::AdmitFills)
            }
            (S::PreBoundary | S::Recovering, _) => Outcome::Stayed(Reason::Miss),
            (S::Withdrawn, _) => Outcome::Stayed(Reason::Withdrawn),
            (S::Closed, _) => Outcome::Stayed(Reason::Closed),
        }
    }

    fn close(&mut self) -> Outcome {
        use State as S;
        match self.state {
            S::Closed => Outcome::Stayed(Reason::Closed),
            S::PreBoundary | S::Recovering | S::Serving | S::Withdrawn => {
                self.move_to(S::Closed, Effect::None)
            }
        }
    }

    fn withheld(&mut self) -> Outcome {
        use State as S;
        match self.state {
            S::Recovering => self.move_to(S::Closed, Effect::None),
            S::Withdrawn => Outcome::Stayed(Reason::Withdrawn),
            S::Closed => Outcome::Stayed(Reason::Closed),
            state @ (S::PreBoundary | S::Serving) => {
                Outcome::Rejected(Rejection::Unsupported { state })
            }
        }
    }

    /// Admits `operation` under the exact current token inside the half-open Report window, answering as `admit`
    /// over the machine's `Standing` at `now`. `now` is a serving-clock sample in microseconds: a caller that issues
    /// a device command, publication or reply samples it at admission after queueing, and a state-only check may pass
    /// the owner's latest deadline sample. `Serving` admits reads and GETs, fills need `AllocationReady`, and replies
    /// carry their buffered lineage; every other state, and `Serving` without a token, refuses as `NotServing`. While
    /// the availability withhold holds, a GET refuses `Withheld`; a `Read` passes the withhold and still takes the
    /// token and window checks.
    ///
    /// # Errors
    ///
    /// Returns the [`Denial`] of the first failing check, in the order `admit` applies them.
    #[inline]
    pub fn admit_at(
        &self,
        operation: Operation,
        submitted: Token,
        now: u64,
    ) -> Result<Token, Denial> {
        admit(self.standing(now), operation, submitted, now)
    }

    fn move_to(&mut self, to: State, effect: Effect) -> Outcome {
        self.state = to;
        Outcome::Moved { to, effect }
    }

    /// Retries the named operation through its normal admission gate. A
    /// certified conflict or abort always refuses and leaves the machine
    /// unchanged; the volume's terminal path applies the withdrawal. The answer
    /// is that of `retry` at the machine's `Standing` at `now`.
    #[inline]
    pub fn retry_at(
        &self,
        operation: Operation,
        status: u16,
        submitted: Token,
        now: u64,
    ) -> Result<Token, Denial> {
        retry(self.standing(now), operation, status, submitted, now)
    }

    /// The gate's inputs at `now`: the five fields the gate reads and the withhold evaluated at the same `now`.
    #[inline]
    fn standing(&self, now: u64) -> Standing {
        Standing {
            state: self.state,
            token: self.token,
            window_start: self.window_start,
            window_end: self.window_end,
            fills: self.fills,
            withheld: self.withhold.withholds(now),
        }
    }

    fn reported_token(&self, report: &OwnReport) -> Result<Token, Reason> {
        let token = self
            .token
            .filter(|token| token.lineage == report.lineage)
            .ok_or(Reason::LineageMismatch)?;
        if token.key != report.pair.key || token.exhid != report.pair.exhid {
            return Err(Reason::PairMismatch);
        }
        if self.late(report) {
            return Err(Reason::ReportLate);
        }
        Ok(token)
    }

    fn late(&self, report: &OwnReport) -> bool {
        report
            .certified_at
            .checked_sub(report.submitted_at)
            .is_none_or(|elapsed| elapsed > self.bounds.report_deadline())
    }

    /// Advances the start to the latest submission and extends the end to `submitted_at + delta`; a Report submitted earlier than the one that set the window leaves it, and a sum past `u64::MAX` saturates at the latest representable instant.
    fn renew(&mut self, submitted_at: u64) -> u64 {
        let until = submitted_at.saturating_add(self.bounds.window());
        let until = self.window_end.map_or(until, |end| end.max(until));
        self.window_start = Some(
            self.window_start
                .map_or(submitted_at, |start| start.max(submitted_at)),
        );
        self.window_end = Some(until);
        until
    }

    /// The tenure's one token, for `pair`.
    fn token_for(&self, pair: Pair) -> Token {
        Token {
            shard: self.shard,
            generation: self.target.generation,
            epoch: self.epoch,
            exhid: pair.exhid,
            key: pair.key,
            lineage: 1,
        }
    }

    /// The Register, Acquire and Report gate uses the returned `PreBoundary` machine as input, with its window
    /// anchored at time zero.
    #[cfg(test)]
    pub(crate) fn issued(bounds: Bounds, session: &Session, pair: Pair) -> Self {
        let mut machine = Self::gated(bounds, session, pair);
        machine.renew(0);
        machine
    }
}

/// The operation gate of [`Machine::admit_at`] over one [`Standing`]; an admission returns `submitted`.
///
/// # Errors
///
/// The checks run in this order, and the first that fails names the denial:
///
/// - `NotServing(state)` if `state` differs from `Serving` or the held token is `None`.
/// - `TokenMismatch` if `submitted` differs from the held token.
/// - `WindowNotStarted` if `now` precedes the window start.
/// - `WindowExpired` if the window lacks an end or a start, or `now` reaches the end.
/// - `Withheld` for [`Operation::Get`] while the withhold holds.
/// - `FillsNotAdmitted` for [`Operation::Fill`] while the fill latch is clear.
/// - `StaleLineage` for an [`Operation::Reply`] whose lineage differs from `submitted.lineage`.
#[inline]
pub(super) fn admit(
    standing: Standing,
    operation: Operation,
    submitted: Token,
    now: u64,
) -> Result<Token, Denial> {
    if standing.state != State::Serving || standing.token.is_none() {
        return Err(Denial::NotServing(standing.state));
    }
    authorize(&standing, &submitted, now)?;
    match operation {
        Operation::Get if standing.withheld => Err(Denial::Withheld),
        Operation::Fill if !standing.fills => Err(Denial::FillsNotAdmitted),
        Operation::Reply { lineage } if lineage != submitted.lineage => Err(Denial::StaleLineage {
            lineage,
            current: submitted.lineage,
        }),
        Operation::Get | Operation::Read | Operation::Fill | Operation::Reply { .. } => {
            Ok(submitted)
        }
    }
}

/// The retry gate of [`Machine::retry_at`] over one [`Standing`]: statuses `0x83` and `0x1b` refuse before
/// [`admit`].
#[inline]
pub(super) fn retry(
    standing: Standing,
    operation: Operation,
    status: u16,
    submitted: Token,
    now: u64,
) -> Result<Token, Denial> {
    if status == RESERVATION_CONFLICT || status == PREEMPT_ABORTED {
        return Err(Denial::DeposingStatusNeverRetried(status));
    }
    admit(standing, operation, submitted, now)
}

/// Admits a metadata submission: `Serving` takes every kind and `Recovering`
/// takes the root kinds, each under the token and window checks of [`admit`];
/// every other pair refuses as `MetadataRefused`.
#[inline]
pub(super) fn admit_metadata(
    standing: Standing,
    submitted: Token,
    now: u64,
    kind: MetadataKind,
) -> Outcome {
    use State as S;
    match (standing.state, kind) {
        (S::Serving, _)
        | (S::Recovering, MetadataKind::CheckpointRoot | MetadataKind::ResetRoot) => {
            match authorize(&standing, &submitted, now) {
                Ok(()) => Outcome::Admitted(submitted),
                Err(denial) => Outcome::Rejected(Rejection::AuthorityDenied(denial)),
            }
        }
        (state @ (S::PreBoundary | S::Recovering | S::Withdrawn | S::Closed), _) => {
            Outcome::Rejected(Rejection::MetadataRefused { state, kind })
        }
    }
}

/// Checks that `submitted` equals the held token in every field and that `now` lies inside the half-open Report
/// window `[window_start, window_end)` with both bounds present. [`admit`] and [`admit_metadata`] share this check
/// order.
///
/// # Errors
///
/// `TokenMismatch`, then `WindowNotStarted`, then `WindowExpired`: the first failed check names the denial, under
/// the conditions [`admit`] lists.
#[inline(always)]
fn authorize(standing: &Standing, submitted: &Token, now: u64) -> Result<(), Denial> {
    if standing.token.as_ref() != Some(submitted) {
        return Err(Denial::TokenMismatch);
    }
    if standing.window_start.is_some_and(|start| now < start) {
        return Err(Denial::WindowNotStarted);
    }
    if standing
        .window_end
        .is_none_or(|end| !super::window::contains(standing.window_start.unwrap_or(end), end, now))
    {
        return Err(Denial::WindowExpired);
    }
    Ok(())
}

#[cfg(test)]
#[path = "serving_tests.rs"]
mod tests;
