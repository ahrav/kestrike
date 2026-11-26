//! The pure planned-exit machine of one serving tenure. It orders a requested transfer to the named standby, a
//! requested same-host restart and the owner-raised roll from the stop of fills to the withdrawal, and from the
//! withdrawal to an exit or one restart. Its driver performs each [`Step`] that [`Planned::step`] returns and feeds
//! each result back as an [`Input`]. The machine performs no I/O and reads no clock of its own: it decides over the
//! evidence the driver supplies, under the feeding rules stated on [`Input`].
//!
//! ONE-TENURE: an exit request names the shard, generation, owner and attempt counter of the session it drains.
//!
//! THE CUT RULE: the machine withdraws only on the acknowledgment of the certify it requested last, when the
//! acknowledged record names the own `(shard, g, owner, E)`, leaves the attempt counter room for the exit's bumps,
//! names the required standby, and
//!
//! - W1: the tenure's possibly named set settled to the record's checkpoint (the acknowledgment carries a floor);
//! - W2: the record names the checkpoint of this drain's acknowledged Publish, or, for a restart or roll that skipped
//!   the Publish, the receipt's checkpoint;
//! - W3: the newest suffix position is settled at the certified end, and the record's own-session suffix is
//!   certified at that end, or, when the own-session suffix is empty, the record's cut is at that end;
//! - W4: the newest coverage reading, fed after mutations stopped, shows no write that can still be acknowledged;
//! - W5: the record names the transfer's target as standby, or any standby for a restart or roll;
//! - W6: the deadline has not passed.
//!
//! A suffix that moved past the certified end while the certify ran certifies again at its settled end; the
//! withdrawal waits for the acknowledgment of that later certify.
//!
//! UNOPENED: a restart or roll with no Publish of its own, by a tenure whose log stayed closed since its open
//! ([`Input::Unopened`]), has no suffix to seal or certify. It confirms the record with its own exact-version write
//! ([`Step::Confirm`]) and withdraws on that acknowledgment when W1, W2 over the receipt's checkpoint and cut, W4, W5
//! and W6 hold and the record holds no suffix of the own session. The tenure admitted no mutation, so the next tenure
//! replays the checkpoint and the certified predecessor suffixes this tenure loaded (`HandoffCutIsExact`).
//!
//! RESUME-BEFORE-WITHDRAWAL: from `Received`, `FillsStopped` and `Sealed` the machine leaves by [`Step::Resume`] or
//! [`Step::Withdraw`]. A passed deadline resumes `deadline`; a record naming another tenure or leaving no room for
//! the exit's attempt bumps, and a failed store request, resume `store`; a record without the required standby resumes
//! `standby`; a refused or unusable Publish or certify, a transfer whose capture finds no free slot, and a W1 to W4
//! failure resume `cut`. WITHDRAWN-EXITS-ONLY-TO-CLOSED: from `Withdrawn` the machine leaves only by an exit or one
//! restart.
//!
//! No [`Input`] counts outstanding device commands, so no withdrawal waits on an unrelated device completion.

use std::num::{NonZeroU32, NonZeroU64};

use crate::failover::planned::request::AuthenticatedRequest;
use crate::failover::records::{ATTEMPTS_MAX, Host, NamedCheckpoint, ShardRecord};
use crate::failover::report::{ExitStatus, Restart, Resume};
use crate::failover::retire::Target;
use crate::net::ownership::Shard;
use crate::storage::Session;

/// The validated cap on a planned exit's deadline, in microseconds of the owner's suspend-aware clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    cap_us: NonZeroU64,
}

/// Why [`Deadline::new`] refuses a cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineError {
    Zero,
}

impl Deadline {
    /// # Errors
    ///
    /// [`DeadlineError::Zero`] for a zero cap.
    pub fn new(cap_us: u64) -> Result<Self, DeadlineError> {
        NonZeroU64::new(cap_us)
            .map(|cap_us| Self { cap_us })
            .ok_or(DeadlineError::Zero)
    }

    pub fn cap_us(&self) -> u64 {
        self.cap_us.get()
    }

    /// The deadline of an exit, measured from its receipt: the requested one at most the cap, or the cap for a roll,
    /// which carries no request.
    pub fn of(&self, requested_us: Option<NonZeroU32>) -> u64 {
        requested_us.map_or(self.cap_us(), |requested| {
            u64::from(requested.get()).min(self.cap_us())
        })
    }
}

/// The exit a machine runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    /// A requested transfer to the standby `target`.
    Transfer { target: Host },
    /// A requested same-host restart.
    Restart,
    /// The owner-raised same-host restart at a tenure bound. `publish` is false for a roll raised because no
    /// checkpoint slot is free: that roll skips the capture and the Publish.
    Roll { publish: bool },
}

impl From<super::request::Kind> for ExitKind {
    fn from(kind: super::request::Kind) -> Self {
        match kind {
            super::request::Kind::Transfer { target } => Self::Transfer { target },
            super::request::Kind::Restart => Self::Restart,
        }
    }
}

/// Where the exit stands. `Received`, `FillsStopped` and `Sealed` are the drain, from which the exit may resume;
/// `Withdrawn` holds no serving authority; the other states are ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// The exit started; nothing is stopped.
    Received,
    /// Fills are stopped; the capture and its Publish run.
    FillsStopped,
    /// Mutations are stopped; the seal and the certify run.
    Sealed,
    /// Serving authority is withdrawn.
    Withdrawn,
    /// The transfer write is acknowledged.
    Transferred,
    /// The tenure exits for a successor tenure.
    Exited,
    /// Admission reopened in place before the withdrawal.
    Resumed(Resume),
    /// The tenure restarts once on the same host.
    Restarting(Restart),
}

/// The outcome of the Publish of the capture pass this drain started after [`Step::Capture`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "a lane completion's committed record travels by value, which keeps each step allocation-free"
)]
pub enum Published {
    /// The store committed the Publish; the record it committed.
    Acknowledged(ShardRecord),
    /// The capture found no free checkpoint slot.
    NoSlot,
    /// The capture pass or its Publish refused for another reason.
    Refused,
    /// The store request failed or its outcome is unknown.
    Store,
}

/// The outcome of the certify of the last [`Step::Certify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "a lane completion's committed record travels by value, which keeps each step allocation-free"
)]
pub enum Certified {
    /// The store committed the certify, or, for a record that holds no suffix of the own session, an exact-version
    /// confirm of the record. `record` is the committed record and `floor` is `checkpoint::settled_floor` of the
    /// tenure's possibly named set over it.
    Acknowledged {
        record: ShardRecord,
        floor: Option<u64>,
    },
    /// The certify refused before any store request or on its write condition.
    Refused,
    /// The store request failed or its outcome is unknown.
    Store,
}

/// The outcome of the transfer write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transferred {
    /// The store committed the record naming the target as owner.
    Acknowledged,
    /// The store refused the write's condition.
    Refused,
    /// The write's outcome is unknown.
    Unknown,
}

/// One snapshot of the tenure's suffix log, all three fields read together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    /// A record of the tenure is not yet durable: a record in the open block, a sealed block waiting for its write,
    /// or a write in flight.
    pub pending: bool,
    /// Every block of the tenure below this LSN is durable.
    pub durable: u64,
    /// The LSN of the open block.
    pub head: u64,
}

impl Position {
    fn settled(&self) -> bool {
        !self.pending && self.durable == self.head
    }

    /// Whether `self` reads below `earlier` in either field, which a later snapshot of one log never does.
    fn behind(&self, earlier: &Self) -> bool {
        let same = self.durable == earlier.durable && self.head == earlier.head;
        self.durable < earlier.durable
            || self.head < earlier.head
            || (same && earlier.pending && !self.pending)
    }
}

/// A reading or an effect's outcome the driver feeds to [`Planned::step`].
///
/// In each turn the driver feeds a `Clock`, a `Coverage` and a `Suffix` reading taken after it adopted the turn's
/// completions, and then the completions, so the decision on a completion reads current evidence. The driver must
/// perform a returned [`Step::Withdraw`] before it appends to the suffix or changes coverage again. It feeds
/// `Published` only for the capture pass it started after [`Step::Capture`], `Certified` only for the certify of the
/// last [`Step::Certify`] or for the write of [`Step::Confirm`], and after a refused or unknown transfer a `Record`
/// only from a read issued after that outcome; it drops every other completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// The machine's first record: for a roll, the record of the latest view, which met the roll's start conditions
    /// on the turn that builds the machine; for a requested exit, a read the driver issues after it builds the
    /// machine. After a refused or unknown transfer the driver feeds a record only from a read issued after that
    /// outcome.
    Record(ShardRecord),
    Published(Published),
    Certified(Certified),
    /// A suffix snapshot. A snapshot behind an earlier one is stale, and the machine keeps the earlier one.
    Suffix(Position),
    /// Whether a coverage write can still be acknowledged. The machine holds `true` until a reading arrives and again
    /// from [`Step::StopMutations`], so only a reading taken after mutations stopped clears W4.
    Coverage {
        acknowledgeable: bool,
    },
    /// The outcome of the transfer write.
    Transfer(Transferred),
    /// A reading of the owner's suspend-aware clock in microseconds. A reading below an earlier one leaves the
    /// machine's time unchanged.
    Clock(u64),
    /// The tenure's suffix log has stayed closed since the tenure opened, so the tenure admitted no FILL and no
    /// INVALIDATE, and the record certifies each predecessor suffix to the end the tenure's warm load established.
    /// The driver feeds it, when it holds, after [`Step::StopMutations`] took effect and before the next `Clock`.
    /// That `Clock` returns [`Step::Confirm`] for a restart or roll with no Publish of its own and [`Step::Seal`]
    /// for every other drain, and an `Unopened` fed after the seal was issued changes nothing.
    Unopened,
}

/// What the driver does after it withdraws serving authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Then {
    /// In the same turn, the transfer write naming `target` as owner, with an exact-version condition on the record
    /// the certify acknowledged; its outcome comes back as [`Input::Transfer`].
    Transfer { target: Host },
    /// The exit and one same-host restart. A later [`Input::Clock`] returns the restart as [`Step::Restart`].
    Restart,
}

/// The driver performs each effect the machine returns.
#[must_use = "the machine has already moved to the state after this step"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Wait,
    StopFills,
    /// Start a capture pass with the planned-restart and fill-stopped flags set, and Publish its checkpoint.
    Capture,
    /// Stop admitting mutations, then feed a coverage reading taken after the stop.
    StopMutations,
    /// Seal the suffix log's open block.
    Seal,
    /// Certify the own session's suffix at `end`.
    Certify {
        end: u64,
    },
    /// Confirm the record with the tenure's own exact-version write; its outcome comes back as
    /// [`Input::Certified`].
    Confirm,
    /// Withdraw serving authority, emit no reply or device command after it, then do what [`Then`] says.
    Withdraw(Then),
    /// The transfer is acknowledged, or a successor tenure holds the shard.
    Exit,
    /// Restart once on the same host.
    Restart(Restart),
    /// Reopen admission in place; the tenure consumes no attempt.
    Resume(Resume),
}

/// [`Planned::requested`] rejects a request bound to a tenure other than the session's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    Tenure,
}

/// The planned-exit machine of one serving tenure; see the module documentation for its rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    kind: ExitKind,
    shard: Shard,
    own: Target,
    session: u64,
    deadline_at_us: u64,
    state: State,
    now_us: u64,
    received: Option<(NamedCheckpoint, u64)>,
    capturing: bool,
    published: Option<(NamedCheckpoint, u64)>,
    seal_issued: bool,
    certifying: Option<u64>,
    suffix: Option<Position>,
    acknowledgeable: bool,
    retry: Option<Restart>,
    unopened: bool,
    confirming: bool,
}

impl Planned {
    /// # Errors
    ///
    /// `requested` returns [`StartError::Tenure`] if the request and session differ in shard, generation, owner, or
    /// attempt counter.
    pub fn requested(
        request: &AuthenticatedRequest,
        session: &Session,
        received_us: u64,
        deadline: Deadline,
    ) -> Result<Self, StartError> {
        let request = request.request();
        let named = Target {
            generation: request.generation,
            owner: request.owner,
            attempts: request.attempts,
        };
        if request.shard != session.shard() || named != session.target() {
            return Err(StartError::Tenure);
        }
        let deadline_us = deadline.of(Some(request.deadline_us));
        Ok(Self::start(
            request.kind.into(),
            session,
            received_us,
            deadline_us,
        ))
    }

    pub fn roll(publish: bool, session: &Session, received_us: u64, deadline: Deadline) -> Self {
        let deadline_us = deadline.of(None);
        Self::start(
            ExitKind::Roll { publish },
            session,
            received_us,
            deadline_us,
        )
    }

    fn start(kind: ExitKind, session: &Session, received_us: u64, deadline_us: u64) -> Self {
        Self {
            kind,
            shard: session.shard(),
            own: session.target(),
            session: session.get(),
            deadline_at_us: received_us.saturating_add(deadline_us),
            state: State::Received,
            now_us: received_us,
            received: None,
            capturing: false,
            published: None,
            seal_issued: false,
            certifying: None,
            suffix: None,
            acknowledgeable: true,
            retry: None,
            unopened: false,
            confirming: false,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// The exit's deadline as a reading of the clock [`Input::Clock`] carries: the receipt plus the deadline. A
    /// reading at or past it resumes a draining machine.
    pub fn deadline_at(&self) -> u64 {
        self.deadline_at_us
    }

    pub fn kind(&self) -> ExitKind {
        self.kind
    }

    /// The status a repeated request for this exit reads; reading it changes nothing. A deadline that passes before
    /// the withdrawal reads `Resumed(Deadline)`; after the withdrawal no deadline applies.
    pub fn status(&self) -> ExitStatus {
        match self.state {
            State::Received => ExitStatus::Received,
            State::FillsStopped | State::Sealed => ExitStatus::Draining,
            State::Withdrawn => ExitStatus::Withdrawn,
            State::Transferred | State::Exited => ExitStatus::Exited,
            State::Resumed(reason) => ExitStatus::Resumed(reason),
            State::Restarting(reason) => ExitStatus::Restarting(reason),
        }
    }

    /// Takes one input and returns the effect it calls for.
    pub fn step(&mut self, input: Input) -> Step {
        if let Input::Clock(now) = input {
            self.now_us = self.now_us.max(now);
        }
        match self.state {
            State::Received | State::FillsStopped | State::Sealed => self.draining(input),
            State::Withdrawn => self.withdrawn(input),
            State::Transferred | State::Exited | State::Resumed(_) | State::Restarting(_) => {
                Step::Wait
            }
        }
    }

    fn draining(&mut self, input: Input) -> Step {
        if self.now_us >= self.deadline_at_us {
            return self.resume(Resume::Deadline);
        }
        match (self.state, input) {
            (state, Input::Record(record)) => match (self.refusal(&record), state) {
                (Some(reason), _) => self.resume(reason),
                (None, State::Received) => {
                    self.received = record.checkpoint.map(|named| (named, record.cut));
                    self.state = State::FillsStopped;
                    Step::StopFills
                }
                (None, _) => Step::Wait,
            },
            (State::FillsStopped, Input::Clock(_)) if !self.capturing => {
                self.capturing = true;
                match self.kind {
                    ExitKind::Roll { publish: false } => self.stop_mutations(),
                    ExitKind::Transfer { .. }
                    | ExitKind::Restart
                    | ExitKind::Roll { publish: true } => Step::Capture,
                }
            }
            (State::FillsStopped, Input::Published(published)) if self.capturing => {
                self.published(published)
            }
            (_, Input::Unopened) => {
                self.unopened = true;
                Step::Wait
            }
            (State::Sealed, Input::Clock(_)) if self.skips_suffix() => {
                if std::mem::replace(&mut self.confirming, true) {
                    Step::Wait
                } else {
                    Step::Confirm
                }
            }
            (State::Sealed, Input::Clock(_)) if !self.seal_issued => {
                self.seal_issued = true;
                Step::Seal
            }
            (State::Sealed, Input::Certified(certified)) if self.confirming => {
                self.confirmed(certified)
            }
            (_, Input::Suffix(position)) => self.observed(position),
            (_, Input::Coverage { acknowledgeable }) => {
                self.acknowledgeable = acknowledgeable;
                Step::Wait
            }
            (State::Sealed, Input::Certified(certified)) => {
                #[cfg(test)]
                if tests::planted(tests::Plant::WaitOnBlockers) && tests::blockers().is_some() {
                    return Step::Wait;
                }
                match (self.certifying.take(), self.suffix) {
                    (Some(end), Some(suffix)) => self.certified(end, suffix, certified),
                    (Some(_) | None, _) => Step::Wait,
                }
            }
            (
                State::Received | State::FillsStopped,
                Input::Published(_) | Input::Certified(_) | Input::Transfer(_) | Input::Clock(_),
            )
            | (State::Sealed, Input::Published(_) | Input::Transfer(_) | Input::Clock(_))
            | (
                State::Withdrawn
                | State::Transferred
                | State::Exited
                | State::Resumed(_)
                | State::Restarting(_),
                _,
            ) => Step::Wait,
        }
    }

    fn published(&mut self, published: Published) -> Step {
        match self.judged(&published) {
            Ok(named) => {
                self.published = named.or(self.published);
                self.stop_mutations()
            }
            Err(reason) => self.resume(reason),
        }
    }

    /// Whether taking `published` while the drain captures stops mutations, as [`Step::StopMutations`]: an
    /// acknowledged Publish of a new checkpoint of this session over a record this drain admits, or a restart's or
    /// roll's Publish that found no free slot. Every other outcome resumes the tenure.
    pub fn publish_stops_mutations(&self, published: &Published) -> bool {
        self.judged(published).is_ok()
    }

    /// The effect of `published`: `Ok` with the checkpoint and cut an acknowledged Publish named, or `Ok(None)` for a
    /// restart's or roll's Publish that found no free slot, each of which stops mutations; `Err` with the reason the
    /// tenure resumes for.
    fn judged(&self, published: &Published) -> Result<Option<(NamedCheckpoint, u64)>, Resume> {
        match published {
            Published::Acknowledged(record) => {
                if let Some(reason) = self.refusal(record) {
                    return Err(reason);
                }
                let receipt = self.received.map(|(named, _)| named);
                match record.checkpoint {
                    Some(named) if named.session == self.session && Some(named) != receipt => {
                        Ok(Some((named, record.cut)))
                    }
                    Some(_) | None => Err(Resume::Cut),
                }
            }
            Published::NoSlot => match self.kind {
                ExitKind::Transfer { .. } => Err(Resume::Cut),
                ExitKind::Restart | ExitKind::Roll { .. } => Ok(None),
            },
            Published::Refused => Err(Resume::Cut),
            Published::Store => Err(Resume::Store),
        }
    }

    fn observed(&mut self, position: Position) -> Step {
        if self.suffix.is_some_and(|seen| position.behind(&seen)) {
            return Step::Wait;
        }
        self.suffix = Some(position);
        let ready = self.state == State::Sealed
            && self.seal_issued
            && self.certifying.is_none()
            && position.settled();
        if ready {
            self.certify(position)
        } else {
            Step::Wait
        }
    }

    fn certify(&mut self, position: Position) -> Step {
        #[cfg(test)]
        if tests::planted(tests::Plant::TransferBeforeCertify) {
            return self.withdraw();
        }
        self.certifying = Some(position.durable);
        Step::Certify {
            end: position.durable,
        }
    }

    fn certified(&mut self, end: u64, position: Position, certified: Certified) -> Step {
        let (record, floor) = match certified {
            Certified::Acknowledged { record, floor } => (record, floor),
            Certified::Refused => return self.resume(Resume::Cut),
            Certified::Store => return self.resume(Resume::Store),
        };
        if let Some(reason) = self.refusal(&record) {
            return self.resume(reason);
        }
        if !position.settled() {
            return Step::Wait;
        }
        if position.durable != end {
            return self.certify(position);
        }
        let expected = match (self.published, self.kind) {
            (Some(published), _) => Some(published),
            (None, ExitKind::Transfer { .. }) => None,
            (None, ExitKind::Restart | ExitKind::Roll { .. }) => self.received,
        };
        let Some((checkpoint, cut)) = expected else {
            return self.resume(Resume::Cut);
        };
        let named = record.checkpoint == Some(checkpoint) && record.cut == cut;
        let own = (record.ancestry.as_slice().iter()).find(|suffix| suffix.session == self.session);
        let covered = own.map_or(cut == end, |own| own.certified == end);
        if floor.is_some() && named && covered && !self.acknowledgeable {
            self.withdraw()
        } else {
            self.resume(Resume::Cut)
        }
    }

    /// Whether the drain has no suffix to seal or certify: a restart or roll with no Publish of its own, by a tenure
    /// whose log never opened, before any seal was issued.
    fn skips_suffix(&self) -> bool {
        let restarts = matches!(self.kind, ExitKind::Restart | ExitKind::Roll { .. });
        self.unopened && restarts && self.published.is_none() && !self.seal_issued
    }

    /// The withdrawal of a tenure whose log never opened, on the acknowledgment of its own confirming write: W1, W2
    /// over the receipt's checkpoint and cut, and W4 hold, and the record holds no suffix of the own session. The
    /// next tenure then replays the receipt's checkpoint and the certified predecessor suffixes, which is what this
    /// tenure loaded.
    fn confirmed(&mut self, certified: Certified) -> Step {
        let (record, floor) = match certified {
            Certified::Acknowledged { record, floor } => (record, floor),
            Certified::Refused => return self.resume(Resume::Cut),
            Certified::Store => return self.resume(Resume::Store),
        };
        if let Some(reason) = self.refusal(&record) {
            return self.resume(reason);
        }
        #[cfg(test)]
        if tests::planted(tests::Plant::OwnSuffixRequired) {
            return self.resume(Resume::Cut);
        }
        let named = (self.received)
            .is_some_and(|(named, cut)| record.checkpoint == Some(named) && record.cut == cut);
        let own = (record.ancestry.as_slice().iter()).any(|suffix| suffix.session == self.session);
        if floor.is_some() && named && !own && !self.acknowledgeable {
            self.withdraw()
        } else {
            self.resume(Resume::Cut)
        }
    }

    fn withdraw(&mut self) -> Step {
        self.state = State::Withdrawn;
        Step::Withdraw(match self.kind {
            ExitKind::Transfer { target } => Then::Transfer { target },
            ExitKind::Restart | ExitKind::Roll { .. } => Then::Restart,
        })
    }

    /// After a refused or unknown transfer, a record of this shard naming the own tenure restarts once, and one naming
    /// a later `(g, E)` exits; a record of another shard or an earlier tenure leaves the machine waiting.
    fn withdrawn(&mut self, input: Input) -> Step {
        match (self.kind, input, self.retry) {
            (ExitKind::Transfer { .. }, Input::Transfer(outcome), None) => match outcome {
                Transferred::Acknowledged => {
                    self.state = State::Transferred;
                    Step::Exit
                }
                Transferred::Refused => {
                    self.retry = Some(Restart::TransferRefused);
                    Step::Wait
                }
                Transferred::Unknown => {
                    self.retry = Some(Restart::TransferUnknown);
                    Step::Wait
                }
            },
            (ExitKind::Transfer { .. }, Input::Record(record), Some(reason))
                if record.shard == self.shard =>
            {
                let seen = Target::of(&record);
                if seen == self.own {
                    self.state = State::Restarting(reason);
                    Step::Restart(reason)
                } else if (seen.generation, seen.attempts)
                    > (self.own.generation, self.own.attempts)
                {
                    self.state = State::Exited;
                    Step::Exit
                } else {
                    Step::Wait
                }
            }
            (ExitKind::Restart | ExitKind::Roll { .. }, Input::Clock(_), _) => {
                self.state = State::Restarting(Restart::Planned);
                Step::Restart(Restart::Planned)
            }
            (ExitKind::Transfer { .. } | ExitKind::Restart | ExitKind::Roll { .. }, _, _) => {
                Step::Wait
            }
        }
    }

    /// Mutations stop, and the coverage latch returns to `true` until a reading taken after the stop arrives.
    fn stop_mutations(&mut self) -> Step {
        self.state = State::Sealed;
        self.acknowledgeable = true;
        Step::StopMutations
    }

    fn resume(&mut self, reason: Resume) -> Step {
        self.state = State::Resumed(reason);
        Step::Resume(reason)
    }

    /// The resume a committed or read record forces before the withdrawal: `store` for a record of another shard or
    /// tenure, or one whose attempt counter leaves no room for the exit's bumps, then `standby` for a record without
    /// the required standby.
    fn refusal(&self, record: &ShardRecord) -> Option<Resume> {
        let own = record.shard == self.shard && Target::of(record) == self.own;
        if !own || !self.budgeted() {
            return Some(Resume::Store);
        }
        let standby = match self.kind {
            ExitKind::Transfer { target } => record.standby == Some(target),
            ExitKind::Restart | ExitKind::Roll { .. } => record.standby.is_some(),
        };
        #[cfg(test)]
        let standby = standby || tests::planted(tests::Plant::StandbyIgnored);
        (!standby).then_some(Resume::Standby)
    }

    fn budgeted(&self) -> bool {
        let bumps = match self.kind {
            ExitKind::Transfer { .. } => 2,
            ExitKind::Restart | ExitKind::Roll { .. } => 1,
        };
        self.own.attempts.saturating_add(bumps) <= ATTEMPTS_MAX
    }
}

#[cfg(test)]
#[path = "machine_tests.rs"]
pub(crate) mod tests;
