//! The [`Planned`] state machine coordinates a cooperative same-host restart of a serving tenure, the roll, through
//! the duties' lane and the owner's admission stages.
//!
//! Invariants:
//!
//! - ROLL-START: a roll starts only for a serving tenure with a capture policy and an idle capture pass, at `Opened`
//!   with the log reopen settled, when a view that read the volume record and the shard record shows the tenure's own suffix, a named
//!   standby and room in `E` and `g` for the restart's bump. Until then the tenure keeps serving hits and its log
//!   refuses mutations at its bound.
//! - BOUND-CUT ROLL: a Publish whose cut reaches the end of the tenure's reserved suffix drops that suffix from the
//!   record, and at the tenure's bound the store step leaves the record as that Publish wrote it. With the handoff
//!   due, a view that names a checkpoint and a duties' read that shows the dropped suffix satisfy ROLL-START's
//!   own-suffix condition. The certify job then confirms the record, and the machine withdraws when the record's cut
//!   equals the log's durable end.
//! - CLOSED-LOG ROLL: a tenure whose log stayed closed since its open, with the reopen still owed, rolls when the view
//!   shows a record that holds only predecessor suffixes, each certified to the end the warm load established. The
//!   duties feed [`Input::Unopened`] from the stop of mutations, and the certify job confirms the record. Each such
//!   roll follows one exhaustion of the tenure's checkpoint slots, a refused pass waiting one view period, and
//!   consumes one attempt.
//! - INPUT-ORDER: each turn feeds the machine its clock, a coverage reading, the latest view, a suffix snapshot, and
//!   then the turn's completions, each input read after the steps of the earlier inputs took effect. A record in the
//!   open block counts as pending, so a certify names an end at or above every record the tenure appended. The seal
//!   runs in the acquisition that takes the snapshot, and a busy capture mutex keeps it owed for a later turn. An
//!   acknowledged certify reaches the machine on a turn whose snapshot succeeded and whose latest view read the
//!   volume record; a refused or failed certify reaches it on the turn it lands.
//! - ATTEMPT-BOUND: the machine reads the Publish of the pass the roll started and the certify the current attempt
//!   submitted; a completion of an earlier pass or attempt only reconciles the duties' read and set.
//! - RESULT-BEFORE-WITHDRAWAL: every planned exit, the roll, a requested restart and a transfer alike, leaves its
//!   stage 1 only while no published fill's first PUT RESULT waits in the reply rings ([`Owner::put_results_queued`]).
//!   While one waits, the duties hold back a capture's Publish outcome that stops mutations, and for a roll with no
//!   capture they hold the clock reading that stops mutations; the duties can deliver a Publish outcome that resumes
//!   the tenure while the result waits. The stop of fills ends every unpublished upload, so
//!   the waiting results only leave, and the wait overlaps the Publish. The exit's deadline bounds the wait: a clock
//!   reading at or past it reaches the machine, which resumes the tenure in place, with no withdrawal and no attempt
//!   consumed. From `Sealed` on the duties read no reply ring, so the wait never lengthens the stage that refuses
//!   INVALIDATEs. A planned exit abandons no first-time result of a published fill that is still queued; it does not
//!   promise that the client receives it. A result dropped by a full reply ring, or lost after it was handed to the
//!   transport, holds no exit; the client's upload ends `Unknown` unless a replay of the retained terminal reaches
//!   the client before the withdrawal. The lost reply removes no object: the fill stays in the retained cut under
//!   the INVALIDATE and expiry rules of every other object. A replay of a retained terminal holds no exit.
//! - SET-HOLDER: the certify is one shard-record job; it waits for an idle lane, takes the possibly named set and
//!   holds capture unit commands as a suffix step does. From `Sealed` the suffix step and the capture Publish submit
//!   pause.
//!
//! Duties built through [`Duties::requesting`] also run the machine for an authenticated planned request, the
//! owner's one request intake:
//!
//! - ONE-LEDGER: the duties keep one [`Ledger`] for the tenure's session, which a later builder call keeps. Each
//!   request one inbox drain delivered decodes under the host's request key, in delivery order, and starts only when
//!   the ledger accepts it; a roll registers with the ledger when it starts and leaves it when it resumes, so a
//!   request that meets a running roll is refused `Busy` and starts nothing.
//! - REQUEST-START: an accepted request starts its machine on the first view submitted after its acceptance, in the
//!   duties' count of submitted views, whose shard record the machine checks for this tenure and, for a transfer, the
//!   target as standby and, from the same view's volume record of the active volume, enrolled for its live attach; a
//!   record that fails the check resumes before any drain stage, consuming no `E`. A transfer whose later view shows
//!   its target unenrolled resumes `standby` before its acknowledged certify can withdraw the tenure. A request
//!   whose capped deadline, measured from its receipt under the cap in force at its acceptance, passes before that
//!   view resumes `deadline`, and a request on duties whose capture cannot publish, with no capture policy, with
//!   every later capture start refused or with the open stopped, resumes `cut`, each before any drain stage.
//! - TRANSFER-OFF-POLL: at the withdrawal the owner closes and, in the same turn, submits one [`Job::Transfer`] over
//!   the read the current attempt's acknowledged certify committed. After the acknowledged transfer the incarnation
//!   ends [`Exit::Stopped`]. After a refused or unknown outcome the duties submit a view and feed the machine only
//!   the shard record of a view submitted after that outcome: a record naming this tenure ends in one same-host
//!   restart ([`Rerun::Planned`]), and a later tenure ends [`Exit::Deposed`]. A client alarm on the transfer ends the
//!   incarnation [`Rerun::Withdrawn`].
//! - TURN-CLOCK: the `now` each turn passes is the owner's suspend-inclusive elapsed clock in microseconds, the
//!   timeline of the request receipt and [`Input::Clock`], so a deadline counts the time the host spent suspended.
//!   Each turn reads that clock once, at its start, and every decision of the turn compares the
//!   deadline with that sample, so a withdrawal can follow the deadline by the turn's own duration, any suspension
//!   inside the turn included. The deadline bounds the decision to withdraw; a transfer that commits after the
//!   withdrawal is the outcome the driver reads next.

use super::super::exit::{Exit, Rerun};
use super::super::lane::Job;
use super::super::serve;
use super::capture::Pass;
use super::{Duties, Open};
use crate::failover::planned::{
    AuthenticatedRequest, Binding, Certified, Deadline, ExitKind, Input, Ledger, Planned, Position,
    Published, RequestKey, State as PlannedState, Step, Then, Transferred,
};
use crate::failover::records::ShardRecord;
use crate::failover::report::Resume;
use crate::failover::restart;
use crate::failover::serving::{Cause, Event, State};
use crate::net::{Datagrams, DrainStage, Owner};
use crate::storage::checkpoint::{self, PossiblyNamed, WriteRefused};
use crate::storage::store::{Outgoing, Read, Store, StoreError, WatermarkLog};
use crate::storage::{Disk, Platform};

/// The capture pass a roll asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Asked {
    /// The next capture start runs with the planned flags.
    Start,
    /// The pass of this counter started with the planned flags.
    Pass(u32),
}

pub(super) struct Roll {
    /// The cap of a roll at the tenure's bound, for duties built through [`Duties::rolling`]; `None` starts no
    /// bound roll.
    roll_deadline: Option<Deadline>,
    planned: Option<Planned>,
    pub(super) start_at: u64,
    attempt: u64,
    pub(super) capture: Option<Asked>,
    pub(super) published: Option<Published>,
    /// A seal the machine asked for and the capture mutex has yet to admit.
    seal: bool,
    certify: Option<u64>,
    /// The attempt whose certify is on the lane.
    certifying: Option<u64>,
    certified: Option<Certified>,
    /// The read the current attempt's acknowledged certify committed: the version the transfer conditions on.
    certified_read: Option<Read<ShardRecord>>,
    pub(super) viewed: Option<ShardRecord>,
    /// The latest view read the volume record.
    pub(super) volume_read: bool,
    /// The latest view's volume record, of its shard record's active volume, enrolls a pair for the live attach of
    /// the standby that shard record names.
    pub(super) standby_enrolled: bool,
    /// The shard record the latest view read, whatever tenure it names, and that view's number in submission order
    /// ([`Duties::views`]).
    pub(super) seen: Option<(ShardRecord, u64)>,
    /// The key planned requests to this host are sealed under and the cap of each requested exit, for duties built
    /// through [`Duties::requesting`].
    requests: Option<(RequestKey, Deadline)>,
    /// The one ledger of the tenure's session, built at the first request or roll.
    ledger: Option<Ledger>,
    /// An accepted request waiting for a view submitted after its acceptance: the request, its receipt time, the
    /// number of views submitted before it and the request cap in force at its acceptance.
    accepted: Option<(AuthenticatedRequest, u64, u64, Deadline)>,
    /// The outcome of the transfer job, adopted and not yet fed to the machine.
    transferred: Option<Transferred>,
    /// The number of views submitted before a refused or unknown transfer's outcome: only a view submitted after it
    /// feeds the machine a record.
    reread_after: Option<u64>,
    /// The turns the planted emitting owner kept serving after its transfer's outcome.
    #[cfg(test)]
    emitting: u32,
}

impl Roll {
    /// Whether the duties were built through [`Duties::requesting`].
    pub(super) fn takes_requests(&self) -> bool {
        self.requests.is_some()
    }

    fn new() -> Self {
        Self {
            roll_deadline: None,
            planned: None,
            start_at: 0,
            attempt: 0,
            capture: None,
            published: None,
            seal: false,
            certify: None,
            certifying: None,
            certified: None,
            certified_read: None,
            viewed: None,
            volume_read: false,
            standby_enrolled: false,
            seen: None,
            requests: None,
            ledger: None,
            accepted: None,
            transferred: None,
            reread_after: None,
            #[cfg(test)]
            emitting: 0,
        }
    }
}

impl<S: Store, L: WatermarkLog, P: Platform> Duties<'_, S, L, P> {
    /// Rolls the tenure at its bound once a record read names a standby: stops fills, publishes a capture when the
    /// bound permits stage placement, stops mutations, seals and certifies the suffix with a [`Job::Certify`],
    /// withdraws for `Cause::Planned` and ends with [`Rerun::Planned`]. A roll still draining `deadline` after its
    /// start, and one whose step fails before the withdrawal, reopens admission in the same tenure and starts again
    /// one view period later. A roll starts only for duties built through [`Duties::capturing`]. A later call sets the
    /// cap of the next roll and keeps the tenure's ledger, its request intake and any running exit.
    ///
    /// The duties hold a mutation-stopping Publish outcome while a published fill's first PUT RESULT waits in the
    /// reply rings, and a clock reading at or past the exit's deadline resumes the tenure in place
    /// (RESULT-BEFORE-WITHDRAWAL). A refused Publish, one lost to the store and a transfer's Publish with no free slot
    /// resume the exit while the result waits. The withdrawal ends every session and sends
    /// nothing after it. A result a full reply ring dropped, or one lost after the transport took it, leaves that
    /// client's upload `Unknown` unless a replay of the retained terminal reaches the client before the withdrawal;
    /// the object stays in the retained cut under the INVALIDATE and expiry rules of every other object.
    pub fn rolling(mut self, deadline: Deadline) -> Self {
        self.rolling
            .get_or_insert_with(|| Box::new(Roll::new()))
            .roll_deadline = Some(deadline);
        self
    }

    /// Takes planned requests sealed for this host under `key` as the owner's one request intake, each requested exit
    /// capped at `deadline`: an accepted transfer drains, publishes, certifies, withdraws and transfers the shard to
    /// the named standby, and an accepted restart drains to the roll's restart exit. A request drains only under a
    /// capture policy ([`Duties::capturing`]); without one it resumes `cut` before any drain stage. Duties built
    /// through both builders also roll at the tenure's bound under the cap [`Duties::rolling`] sets, and the two exits
    /// share the tenure's one ledger. A later call keeps that ledger and any running exit, and its cap applies to the
    /// requests accepted after it.
    pub fn requesting(mut self, key: RequestKey, deadline: Deadline) -> Self {
        self.rolling
            .get_or_insert_with(|| Box::new(Roll::new()))
            .requests = Some((key, deadline));
        self
    }

    /// Decodes and admits, in delivery order, each request the inbox delivered this turn, for duties built through
    /// [`Duties::requesting`]. An accepted request records its receipt on the owner's exit tracker and waits for a
    /// view submitted after now. A request that fails its tag or fields changes nothing; every other binding changes
    /// only the ledger's sequence high-water mark, as [`Ledger::admit`] states.
    pub(super) fn intake<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        now: u64,
    ) {
        let mut delivered = std::mem::take(&mut self.delivered);
        for bytes in delivered.drain(..) {
            self.admit_request(owner, &bytes, now);
        }
        self.delivered = delivered;
    }

    /// Delivers `bytes` as the inbox delivers a request to duties built through [`Duties::requesting`].
    #[cfg(test)]
    pub(super) fn deliver(&mut self, bytes: &[u8]) {
        if let Some(request) = crate::host::link::Request::new(bytes) {
            self.delivered.push(request);
        }
    }

    fn admit_request<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        bytes: &crate::host::link::Request,
        now: u64,
    ) {
        let Some((key, _)) = self.rolling.as_ref().and_then(|roll| roll.requests) else {
            return;
        };
        let addressed = owner.tenure().target().owner;
        let Ok(request) = crate::failover::planned::decode(bytes.as_bytes(), addressed, &key)
        else {
            return;
        };
        let state = owner.authority_report().state;
        let Some(roll) = self.rolling.as_mut() else {
            return;
        };
        let ledger = roll
            .ledger
            .get_or_insert_with(|| Ledger::new(owner.tenure()));
        let binding = ledger.admit(&request, state);
        #[cfg(test)]
        super::transfer_tests::bound(binding);
        let Some((_, cap)) = roll.requests.filter(|_| binding == Binding::Accept) else {
            return;
        };
        owner.exit_received(request.request().operation);
        roll.accepted = Some((request, now, self.views, cap));
        self.view_at = self.view_at.min(now);
    }

    /// Adopts the transfer job's completion: an acknowledged transfer's committed record reaches the owner's views, a
    /// refused or unknown outcome sets a reread due, and a client alarm ends the incarnation.
    pub(super) fn transfer_done<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        transferred: Result<crate::storage::store::Transferred, StoreError>,
        now: u64,
    ) -> Option<Exit> {
        let outcome = match transferred {
            #[cfg(test)]
            Ok(_)
                if super::transfer_tests::planted(
                    super::transfer_tests::Plant::EmitAfterTransfer,
                ) =>
            {
                Transferred::Acknowledged
            }
            // A receipt that settles no outstanding transfer of this tenure proves no commit the owner can adopt: the
            // reread after it decides between the exit and the one restart, as for an unknown outcome.
            Ok(transferred) => {
                match owner.transfer_committed(&transferred, self.records.holder.volume, now) {
                    true => Transferred::Acknowledged,
                    false => Transferred::Unknown,
                }
            }
            Err(StoreError::Unknown) => Transferred::Unknown,
            Err(
                StoreError::Refused(_)
                | StoreError::Stale(_)
                | StoreError::AttemptsExhausted
                | StoreError::Successor(_)
                | StoreError::Codec(_)
                | StoreError::Flip(_)
                | StoreError::Absent
                | StoreError::Unavailable,
            ) => Transferred::Refused,
            Err(
                StoreError::Log
                | StoreError::Regression(_)
                | StoreError::Namespace
                | StoreError::Withdrawn,
            ) => return Some(Exit::Rerun(Rerun::Withdrawn)),
        };
        if let Some(roll) = self.rolling.as_mut() {
            roll.transferred = Some(outcome);
            if outcome != Transferred::Acknowledged {
                roll.reread_after = Some(self.views);
                self.view_at = self.view_at.min(now);
            }
        }
        None
    }

    /// Whether the withdrawn owner's transfer is submitted and its outcome has asked for no reread.
    pub(super) fn transfer_waits<'a, D: Disk, T: Datagrams<'a>>(
        &self,
        owner: &Owner<'_, 'a, '_, P, D, T>,
    ) -> bool {
        matches!(
            owner.transfer(),
            Some(crate::net::Handoff::Outstanding { .. })
        ) && (self.rolling.as_ref()).is_some_and(|roll| roll.reread_after.is_none())
    }

    /// The state of the running planned exit's machine.
    #[cfg(test)]
    pub(super) fn planned_state(&self) -> Option<PlannedState> {
        (self.rolling.as_ref())
            .and_then(|roll| roll.planned.as_ref())
            .map(Planned::state)
    }

    /// Whether a planned exit runs, a roll, a requested restart or a transfer, from the request's start or the roll's
    /// start. A roll or a requested restart runs to its withdrawal or its resume. A transfer runs to its resume before
    /// the withdrawal, or past the withdrawal through the wait for its outcome to [`Exit::Stopped`],
    /// [`Exit::Deposed`] or its one same-host restart; a withdrawn transfer grants no service. An accepted request
    /// waiting for its first view reads clear.
    pub fn roll_active(&self) -> bool {
        self.rolling
            .as_ref()
            .is_some_and(|roll| roll.planned.is_some())
    }

    /// Whether a same-host restart runs, a roll or a requested restart: the planned exit the published status reads
    /// as `roll_active`. A transfer hands the shard to another host and reads clear.
    pub(super) fn restart_active(&self) -> bool {
        let kind = (self.rolling.as_ref())
            .and_then(|roll| roll.planned.as_ref())
            .map(Planned::kind);
        matches!(kind, Some(ExitKind::Restart | ExitKind::Roll { .. }))
    }

    pub(super) fn roll_sealed(&self) -> bool {
        let state = (self.rolling.as_ref())
            .and_then(|roll| roll.planned.as_ref())
            .map(Planned::state);
        matches!(state, Some(PlannedState::Sealed | PlannedState::Withdrawn))
    }

    /// Whether the machine asked for a seal that the capture mutex has yet to admit.
    #[cfg(test)]
    pub(super) fn roll_seal_asked(&self) -> bool {
        (self.rolling.as_ref()).is_some_and(|roll| roll.seal)
    }

    /// Whether the roll holds an acknowledged certify that the machine has yet to take.
    #[cfg(test)]
    pub(super) fn roll_certify_held(&self) -> bool {
        (self.rolling.as_ref())
            .is_some_and(|roll| matches!(roll.certified, Some(Certified::Acknowledged { .. })))
    }

    /// Whether the roll asked for a capture start that has yet to run.
    pub(super) fn roll_asks_start(&self) -> bool {
        (self.rolling.as_ref()).is_some_and(|roll| roll.capture == Some(Asked::Start))
    }

    /// Records that the planned start began the pass of `counter`.
    pub(super) fn roll_pass(&mut self, counter: u32) {
        if let Some(roll) =
            (self.rolling.as_mut()).filter(|roll| roll.capture == Some(Asked::Start))
        {
            roll.capture = Some(Asked::Pass(counter));
        }
    }

    /// Hands `result` to the roll when it ends the pass the roll asked for: the planned start's refusal for `None`,
    /// the end of the pass of `counter` otherwise.
    pub(super) fn planned_pass(&mut self, counter: Option<u32>, result: Published) {
        let asked = counter.map_or(Asked::Start, Asked::Pass);
        if let Some(roll) = (self.rolling.as_mut()).filter(|roll| roll.capture == Some(asked)) {
            roll.capture = None;
            roll.published = Some(result);
        }
    }

    /// Adopts a certify's completion: the set returns, a committed read replaces the duties' read and raises the
    /// log's certified end, and the outcome reaches the machine when the current attempt submitted the certify.
    pub(super) fn roll_certified(
        &mut self,
        possible: PossiblyNamed,
        end: u64,
        certified: Result<Read<ShardRecord>, WriteRefused>,
        storage: impl FnOnce(u64),
    ) {
        (self.writing, self.stepping) = (false, false);
        let mut committed = None;
        let input = match certified {
            Ok(read) => {
                let floor = checkpoint::settled_floor(&possible, read.value());
                let record = *read.value();
                committed = Some(read.clone());
                self.read = Some(read);
                storage(end);
                Certified::Acknowledged { record, floor }
            }
            Err(WriteRefused::Store(_)) => {
                self.read = None;
                Certified::Store
            }
            Err(_) => Certified::Refused,
        };
        self.returned(possible);
        if let Some(roll) = self.rolling.as_mut() {
            let current = roll.planned.is_some().then_some(roll.attempt);
            if roll.certifying.take().is_some_and(|at| Some(at) == current) {
                roll.certified = Some(input);
                roll.certified_read = committed;
            }
        }
    }

    pub(super) fn roll<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        now: u64,
    ) -> Option<Exit> {
        let roll = self.rolling.as_ref()?;
        let starting = roll.planned.is_none();
        // Most turns end here: with no machine and no accepted request, the turn reads the roll in place and moves it
        // only to start a bound roll.
        if starting && roll.accepted.is_none() && !self.roll_starts(roll, owner, now) {
            return None;
        }
        let mut roll = self.rolling.take()?;
        let exit = match starting {
            true => self.roll_start(&mut roll, owner, now),
            false => self.roll_turn(&mut roll, owner, now),
        };
        self.rolling = Some(roll);
        exit
    }

    /// Whether a roll starts this turn (ROLL-START). The tests run in this order and the first that fails ends the
    /// check: a roll cap ([`Duties::rolling`]), `roll_due` and a view of the tenure, the named standby, the volume
    /// record read, the retry time `now >= roll.start_at`, the room in `E` and `g`, the open at `Opened`, the idle
    /// pass, the authority's state, and the record's suffixes.
    pub(super) fn roll_starts<'a, D: Disk, T: Datagrams<'a>>(
        &self,
        roll: &Roll,
        owner: &Owner<'_, 'a, '_, P, D, T>,
        now: u64,
    ) -> bool {
        let bound = roll.roll_deadline.is_some();
        let Some(record) = roll.viewed.as_ref().filter(|_| bound && self.roll_due) else {
            return false;
        };
        let named = record.standby.is_some();
        #[cfg(test)]
        let named = named || {
            use crate::failover::planned::machine::tests::{Plant, planted};
            planted(Plant::StandbyIgnored)
        };
        let suffixes = || {
            let session = owner.tenure().get();
            (holds(record, session) || self.cut_at_handoff(record, session)) != self.unopened()
        };
        named
            && roll.volume_read
            && now >= roll.start_at
            && restart::exhausted(record).is_ok()
            && self.open == Open::Opened
            && (self.capture.as_ref()).is_some_and(|capture| matches!(capture.pass, Pass::Idle))
            && owner.authority_state() == State::Serving
            && suffixes()
    }

    /// Whether the tenure's capture can still publish and certify: a capture policy whose starts stay open
    /// (`start_at` below `u64::MAX`) over an open that has not stopped.
    fn capture_runs(&self) -> bool {
        (self.capture.as_ref()).is_some_and(|capture| capture.start_at != u64::MAX)
            && self.open != Open::Stopped
    }

    /// Whether the tenure's log has stayed closed since its open, with each predecessor suffix the duties' read
    /// holds certified to the end the warm load established: the open settled closed on a refused reservation, which
    /// follows the predecessor certifies, and no Publish has run the open again.
    fn unopened(&self) -> bool {
        let certified = |chain: &[crate::failover::records::Suffix]| {
            self.ends.iter().all(|&(session, end)| {
                (chain.iter().find(|suffix| suffix.session == session))
                    .is_none_or(|suffix| suffix.certified >= end)
            })
        };
        self.open_again
            && (self.read.as_ref()).is_some_and(|read| certified(read.value().ancestry.as_slice()))
    }

    fn cut_at_handoff(&self, record: &ShardRecord, session: u64) -> bool {
        self.due.is_some_and(|due| due.handoff)
            && !self.open_again
            && record.checkpoint.is_some()
            && (self.read.as_ref()).is_some_and(|read| !holds(read.value(), session))
    }

    /// Starts the machine of an accepted request on the first view submitted after its acceptance, or else starts the
    /// roll over the record of the latest view; [`Duties::roll_starts`] held this turn.
    #[inline(never)]
    fn roll_start<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        roll: &mut Roll,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        now: u64,
    ) -> Option<Exit> {
        if let Some((request, received_us, views, cap)) = roll.accepted {
            // The capped deadline runs from the receipt under the cap in force at the acceptance, so a request whose
            // first view comes late resumes before any drain stage, whatever cap a later builder call sets.
            let deadline_us = cap.of(Some(request.request().deadline_us));
            if now >= received_us.saturating_add(deadline_us) {
                roll.accepted = None;
                return self.perform(roll, Step::Resume(Resume::Deadline), owner, now);
            }
            let seen = (roll.seen).filter(|(_, view)| roll.volume_read && *view > views);
            let (record, _) = seen?;
            (roll.accepted, roll.viewed) = (None, None);
            #[cfg(test)]
            super::roll_tests::started(ExitKind::from(request.request().kind));
            roll.attempt += 1;
            let session = owner.tenure();
            // The ledger admitted the request for this tenure, so the machine's own tenure check passes; a refusal
            // resumes before any drain stage.
            let Ok(mut planned) = Planned::requested(&request, session, received_us, cap) else {
                return self.perform(roll, Step::Resume(Resume::Store), owner, now);
            };
            let step = match planned.step(Input::Record(record)) {
                // A request drains only under a capture that can still publish: with no policy, a capture that
                // refuses every later start, or an open that stopped, its Publish or its certify never runs.
                Step::StopFills if !self.capture_runs() => Step::Resume(Resume::Cut),
                // A transfer drains only toward a target the same view shows enrolled on the active volume.
                Step::StopFills if transfers(&planned) && !roll.standby_enrolled => {
                    Step::Resume(Resume::Standby)
                }
                step => step,
            };
            roll.planned = Some(planned);
            return self.perform(roll, step, owner, now);
        }
        // A bound roll registers with the tenure's one ledger when it starts.
        let deadline = roll.roll_deadline?;
        let ledger = roll
            .ledger
            .get_or_insert_with(|| Ledger::new(owner.tenure()));
        if !ledger.start_roll() {
            return None;
        }
        let record = roll.viewed.take()?;
        let publish = !self.roll_unpublished && !self.open_again;
        #[cfg(test)]
        super::roll_tests::started(crate::failover::planned::ExitKind::Roll { publish });
        roll.attempt += 1;
        let mut planned = Planned::roll(publish, owner.tenure(), now, deadline);
        let step = planned.step(Input::Record(record));
        roll.planned = Some(planned);
        self.perform(roll, step, owner, now)
    }

    #[inline(never)]
    fn roll_turn<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        roll: &mut Roll,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        now: u64,
    ) -> Option<Exit> {
        if let Some(exit) = self.withdrawn_turn(roll, owner, now) {
            return exit;
        }
        // Each input is read after the steps the earlier inputs returned took effect, so the coverage and the suffix
        // position follow a stop of mutations or a seal of this turn.
        let mut observed = false;
        for at in 0..7 {
            let sealed = (roll.planned.as_ref())
                .is_some_and(|planned| planned.state() == PlannedState::Sealed);
            let input = match at {
                // A roll with no capture leaves stage 1 on its next clock reading.
                0 if (roll.planned.as_ref()).is_some_and(|planned| {
                    planned.state() == PlannedState::FillsStopped
                        && planned.kind() == ExitKind::Roll { publish: false }
                        && now < planned.deadline_at()
                }) && results_owed(owner) =>
                {
                    None
                }
                0 => Some(Input::Clock(now)),
                1 => Some(Input::Coverage {
                    acknowledgeable: owner.held_invalidations() > 0
                        && owner.draining() != Some(DrainStage::Mutations),
                }),
                2 => roll.viewed.take().map(Input::Record),
                3 if sealed => {
                    let seal = roll.seal;
                    let position = owner.storage().with_suffix(|log| {
                        if seal {
                            log.seal_cut();
                        }
                        Position {
                            pending: !log.idle(),
                            durable: log.durable(),
                            head: log.head(),
                        }
                    });
                    observed = position.is_ok();
                    roll.seal &= !observed;
                    #[cfg(test)]
                    if super::roll_tests::planted(super::roll_tests::Plant::SealDroppedWhenBusy) {
                        roll.seal = false;
                    }
                    position.ok().map(Input::Suffix)
                }
                3 => None,
                4 if sealed && self.unopened() => {
                    observed = true;
                    Some(Input::Unopened)
                }
                4 => None,
                5 if publish_waits(roll) && results_owed(owner) => None,
                5 => roll.published.take().map(Input::Published),
                // A transfer whose latest view shows its target unenrolled resumes before the acknowledged certify can
                // withdraw the tenure; the lane's enrollment read stays the guard for an end no view showed.
                _ if matches!(roll.certified, Some(Certified::Acknowledged { .. }))
                    && roll.volume_read
                    && !roll.standby_enrolled
                    && roll.planned.as_ref().is_some_and(transfers) =>
                {
                    roll.certified = None;
                    let step = Step::Resume(Resume::Standby);
                    if let Some(exit) = self.perform(roll, step, owner, now) {
                        return Some(exit);
                    }
                    None
                }
                _ => {
                    let ready = roll.volume_read && observed;
                    #[cfg(test)]
                    let ready = ready
                        && !(super::roll_tests::planted(super::roll_tests::Plant::SealedGate)
                            && owner.put_results_queued());
                    let held = matches!(roll.certified, Some(Certified::Acknowledged { .. }));
                    (ready || !held)
                        .then(|| roll.certified.take())
                        .flatten()
                        .map(Input::Certified)
                }
            };
            let (Some(input), Some(planned)) = (input, roll.planned.as_mut()) else {
                continue;
            };
            let step = planned.step(input);
            if let Some(exit) = self.perform(roll, step, owner, now) {
                return Some(exit);
            }
            // `planned.step(Input::Published)` can return `Step::StopMutations` after the turn's `Input::Unopened`
            // slot. If `self.unopened()` holds, the machine takes `Input::Unopened` in this turn, before the next
            // `Input::Clock`.
            #[cfg(test)]
            let step = match super::roll_tests::planted(super::roll_tests::Plant::UnopenedAtItsSlot)
            {
                true => Step::Wait,
                false => step,
            };
            if step == Step::StopMutations
                && self.unopened()
                && let Some(planned) = roll.planned.as_mut()
            {
                observed = true;
                let step = planned.step(Input::Unopened);
                if let Some(exit) = self.perform(roll, step, owner, now) {
                    return Some(exit);
                }
            }
        }
        self.submit_certify(roll, owner);
        None
    }

    fn perform<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        roll: &mut Roll,
        step: Step,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        now: u64,
    ) -> Option<Exit> {
        match step {
            Step::Wait => {}
            Step::Exit => {
                let transferred = (roll.planned.as_ref())
                    .is_some_and(|planned| planned.state() == PlannedState::Transferred);
                if !transferred {
                    owner.transfer_settled();
                }
                roll.planned = None;
                return Some(if transferred {
                    Exit::Stopped
                } else {
                    Exit::Deposed
                });
            }
            Step::Withdraw(Then::Transfer { target }) => {
                #[cfg(test)]
                if super::transfer_tests::planted(super::transfer_tests::Plant::MutationsAfterSeal)
                {
                    owner.resume(crate::failover::report::Resume::Cut);
                    return None;
                }
                return self.withdraw_for_transfer(roll, owner, target, now);
            }
            Step::StopFills => owner.drain(DrainStage::Fills, now),
            Step::Capture => roll.capture = Some(Asked::Start),
            Step::StopMutations => {
                owner.drain(DrainStage::Mutations, now);
                self.page_next = None;
            }
            Step::Seal => roll.seal = true,
            Step::Certify { end } => roll.certify = Some(end),
            // The certify job confirms a record that holds no suffix of the tenure's session.
            Step::Confirm => roll.certify = Some(0),
            Step::Withdraw(Then::Restart) | Step::Restart(_) => {
                let reason = match step {
                    Step::Restart(reason) => reason,
                    _ => crate::failover::report::Restart::Planned,
                };
                #[cfg(test)]
                super::transfer_tests::boundary();
                #[cfg(test)]
                if let Some(cause) = super::transfer_tests::withdrawn_first() {
                    owner.authority_event(Event::Withdraw(cause), now);
                }
                let withdrawn = withdraw_planned(owner, now);
                // An earlier cause's withdrawal keeps the exit the tracker observed for it.
                if withdrawn.is_ok() {
                    owner.exit_restarting(reason);
                }
                owner.transfer_settled();
                roll.planned = None;
                return match withdrawn {
                    Ok(()) => Some(Exit::Rerun(Rerun::Planned)),
                    Err(exit) => exit,
                };
            }
            Step::Resume(reason) => {
                #[cfg(test)]
                {
                    use super::roll_tests::{Plant, planted};
                    if reason == Resume::Deadline && planted(Plant::DeadlineWithdraws) {
                        let withdraw = Step::Withdraw(Then::Restart);
                        return self.perform(roll, withdraw, owner, now);
                    }
                }
                #[cfg(test)]
                super::roll_tests::resumed(reason);
                owner.resume(reason);
                #[cfg(test)]
                if super::roll_tests::planted(super::roll_tests::Plant::ResumeEndsSessions) {
                    owner.end_sessions();
                }
                let mut ledger = roll.ledger.take();
                if let Some(ledger) = ledger.as_mut() {
                    match ledger.running() {
                        Some(operation) => ledger.resumed(operation),
                        None => ledger.roll_resumed(),
                    }
                }
                *roll = Roll {
                    roll_deadline: roll.roll_deadline,
                    start_at: now.saturating_add(self.periods.view_us),
                    attempt: roll.attempt,
                    certifying: roll.certifying,
                    volume_read: roll.volume_read,
                    standby_enrolled: roll.standby_enrolled,
                    seen: roll.seen,
                    requests: roll.requests,
                    ledger,
                    ..Roll::new()
                };
            }
        }
        None
    }

    /// The transfer's withdrawal: the authority withdraws for `Cause::Planned`, the owner closes, and the same turn
    /// submits the transfer job over the read the current attempt's acknowledged certify committed, whatever later
    /// views read. A tenure that an earlier cause withdrew takes the exit that cause names. With no certified read,
    /// no gate or a refused submit no write was issued, and the tenure ends in its one same-host restart.
    fn withdraw_for_transfer<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        roll: &mut Roll,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        target: crate::failover::records::Host,
        now: u64,
    ) -> Option<Exit> {
        #[cfg(test)]
        super::transfer_tests::boundary();
        #[cfg(test)]
        let serving =
            super::transfer_tests::planted(super::transfer_tests::Plant::EmitAfterTransfer);
        #[cfg(not(test))]
        let serving = false;
        #[cfg(test)]
        if let Some(cause) = super::transfer_tests::withdrawn_first() {
            owner.authority_event(Event::Withdraw(cause), now);
        }
        if !serving {
            if let Err(exit) = withdraw_planned(owner, now) {
                roll.planned = None;
                return exit;
            }
            owner.close(now);
        }
        // No write was issued: the withdrawn tenure ends in its one same-host restart.
        let unissued = |roll: &mut Roll, owner: &mut Owner<'_, 'a, '_, P, D, T>| {
            roll.planned = None;
            owner.exit_restarting(crate::failover::report::Restart::TransferRefused);
            Some(Exit::Rerun(Rerun::Planned))
        };
        let job = match (roll.certified_read.take(), self.standby.take()) {
            (Some(read), Some(gate)) => Job::Transfer {
                gate,
                read,
                outgoing: Outgoing::of(owner.tenure()),
                target,
            },
            (_, gate) => {
                self.standby = gate;
                return unissued(roll, owner);
            }
        };
        #[cfg(test)]
        if super::transfer_tests::holds_transfer() {
            self.lane.inline_mut().hold();
        }
        #[cfg(test)]
        let submitted = match super::transfer_tests::refuses_transfer() {
            true => Err(Box::new(job)),
            false => self.lane.submit(job),
        };
        #[cfg(not(test))]
        let submitted = self.lane.submit(job);
        if let Err(job) = submitted {
            if let Job::Transfer { gate, .. } = *job {
                self.standby = Some(gate);
            }
            return unissued(roll, owner);
        }
        let recorded = owner.transfer_submitted(target);
        debug_assert!(
            recorded || serving,
            "the withdrawn tenure records its one submitted transfer"
        );
        None
    }

    /// A withdrawn transfer's turn: the adopted outcome, then the shard record of a view sent after a refused or
    /// unknown outcome, reach the machine; `None` while the machine is not withdrawn.
    fn withdrawn_turn<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        roll: &mut Roll,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        now: u64,
    ) -> Option<Option<Exit>> {
        let withdrawn = (roll.planned.as_ref()).is_some_and(|planned| {
            planned.state() == PlannedState::Withdrawn
                && matches!(planned.kind(), ExitKind::Transfer { .. })
        });
        if !withdrawn {
            return None;
        }
        #[cfg(test)]
        if super::transfer_tests::planted(super::transfer_tests::Plant::EmitAfterTransfer)
            && roll.transferred.is_some()
            && roll.emitting < 40
        {
            roll.emitting += 1;
            return Some(None);
        }
        #[cfg(test)]
        if super::transfer_tests::planted(super::transfer_tests::Plant::MutationsAfterSeal)
            && owner.transfer().is_none()
        {
            roll.emitting += 1;
            let target = match roll.planned.as_ref().map(Planned::kind) {
                Some(ExitKind::Transfer { target }) if roll.emitting > 40 => target,
                _ => return Some(None),
            };
            return Some(self.withdraw_for_transfer(roll, owner, target, now));
        }
        let reread = roll.reread_after.and_then(|views| {
            (roll.seen)
                .filter(|(_, view)| *view > views)
                .map(|(record, _)| record)
        });
        let inputs = [
            roll.transferred.take().map(Input::Transfer),
            reread.map(Input::Record),
        ];
        for input in inputs.into_iter().flatten() {
            let Some(planned) = roll.planned.as_mut() else {
                break;
            };
            let step = planned.step(input);
            if let Some(exit) = self.perform(roll, step, owner, now) {
                return Some(Some(exit));
            }
        }
        Some(None)
    }

    /// Submits the certify the machine asked for once the open settled at `Opened`, the lane is idle and the set is
    /// here, so the certify is the lane's one outstanding job from its submit to its adoption, as a suffix step is. A
    /// view, a listing or a page job in flight delays the submit until the duties adopt its completion. Certifies end
    /// once the owner is closed to writes, as steps do.
    fn submit_certify<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        roll: &mut Roll,
        owner: &Owner<'_, 'a, '_, P, D, T>,
    ) {
        let Some(end) = roll.certify else {
            return;
        };
        let free = self.lane.outstanding() == 0 && self.set_here();
        let read = match &self.read {
            Some(read) if self.open == Open::Opened && free && !super::closed_to_writes(owner) => {
                read.clone()
            }
            _ => return,
        };
        let tenure = owner.tenure();
        let job = Job::Certify {
            possible: self.take_set(),
            read,
            own: tenure.target(),
            session: tenure.get(),
            end,
        };
        (roll.certify, roll.certifying) = (None, Some(roll.attempt));
        (self.writing, self.stepping) = (true, true);
        self.lane
            .submit(job)
            .expect("the duties hold one shard-record job outstanding");
    }
}

/// Whether `planned` transfers the shard to another host.
fn transfers(planned: &Planned) -> bool {
    matches!(planned.kind(), ExitKind::Transfer { .. })
}

/// Withdraws the authority for `Cause::Planned`. `Err` carries the exit [`serve::ended`] names when an earlier cause
/// withdrew the tenure or a flip request stands.
fn withdraw_planned<'a, P: Platform, D: Disk, T: Datagrams<'a>>(
    owner: &mut Owner<'_, 'a, '_, P, D, T>,
    now: u64,
) -> Result<(), Option<Exit>> {
    owner.authority_event(Event::Withdraw(Cause::Planned), now);
    let report = owner.authority_report();
    let planned = report.state == State::Withdrawn
        && report.withdrawal == Some(Cause::Planned)
        && report.flip.is_none();
    match planned {
        true => Ok(()),
        false => Err(serve::ended(owner)),
    }
}

/// Whether the roll holds a capture's Publish outcome that would stop mutations, which RESULT-BEFORE-WITHDRAWAL holds
/// back from the machine while a first PUT RESULT waits.
fn publish_waits(roll: &Roll) -> bool {
    #[cfg(test)]
    if super::roll_tests::planted(super::roll_tests::Plant::PublishOutcomesHeld) {
        return roll.published.is_some();
    }
    (roll.planned.as_ref().zip(roll.published.as_ref()))
        .is_some_and(|(planned, published)| planned.publish_stops_mutations(published))
}

/// RESULT-BEFORE-WITHDRAWAL's reading: whether a published fill's first PUT RESULT waits in the reply rings.
fn results_owed<'a, P: Platform, D: Disk, T: Datagrams<'a>>(
    owner: &Owner<'_, 'a, '_, P, D, T>,
) -> bool {
    #[cfg(test)]
    {
        use super::roll_tests::{Plant, planted};
        if planted(Plant::ResultsUnwaited) || planted(Plant::SealedGate) {
            return false;
        }
    }
    owner.put_results_queued()
}

fn holds(record: &ShardRecord, session: u64) -> bool {
    (record.ancestry.as_slice().iter()).any(|suffix| suffix.session == session)
}
