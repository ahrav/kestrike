//! The same-volume takeover: the one path by which the shard record's standby acquires a new tenure on the retained
//! active volume, by its own acknowledged compare-and-swap on the shard record. The sequence runs these steps in order
//! and refuses at the first failed check:
//!
//! 1. Read the shard record, then the volume record, and refuse unless the shard record names this host as its standby,
//!    holds the nomination's `(g, owner, E)` with `E > 0` and this active volume, admits one more session, names a
//!    checkpoint whenever it names suffixes, and the volume is active under it, unmodified, with a layout
//!    `Layout::check_floor` admits, events that pass the poll's OWNER-EVENTS rule for this host over `peers`, a live
//!    own entry (an ended or gone one refuses `Local(Ended)`), and a pair recorded for the predecessor on a live
//!    attach or an ended entry.
//! 2. Read the host-local record, and require it present, readable, valid, bound to this instance and this volume,
//!    and carrying the pair the volume record enrolls for this host's live attach, whose entry binds this instance or
//!    none (INSTANCE-BOUND in `failover::restart`); the volume rereads after Reports #1 and #2 repeat the check.
//! 3. The takeover CAS ([`Client::take_over`]): owner `:= this host`, `E: n -> n + 1`, no standby, by an exact-version
//!    compare-and-swap on the step-1 read, and proceed only on its acknowledged success; the session is
//!    `g·2^32 + 2n + 2`.
//! 4. Detect the driver, wait for the controller to report ready and set the local record's host ID.
//! 5. Report #1, judged against a volume record read after it that repeats the volume and own-enrollment checks:
//!    [`LineagePreempt::resolve`] admits a type-2 reservation held by a pair the volume record records for another
//!    host, on a live attach or an ended entry (`VolumeRecord::recorded_beside`), the owner the nomination names or a
//!    host whose tenure that owner's line of takeovers succeeded, with at most one record carrying the own host ID,
//!    under the own key, and every other registrant the own pair or a pair of `VolumeRecord::admitted`: a recorded
//!    pair, or a non-holding registrant under the key of an ended or gone entry (ENDED-NEVER-RETIRES).
//! 6. Register the own pair when Report #1 listed no record of it, whatever count that Report shows: at `N_reg`
//!    registrants the table holds `N_reg + 1` until step 7's preempt removes the holder's registration, and a
//!    sequence that stops between the two leaves this host's restart a Report over the bound, which refuses
//!    `NotHolding(Excess)` with the flip request. The restart's lineage arm alone holds before such a Register
//!    (REGISTER-ROOM in `failover::restart`).
//! 7. Read the shard record and refuse `Superseded` unless it still names this tenure and active volume, then
//!    Preempt-and-Abort naming the own key as CRKEY and the key of the holder Report #1 showed as PRKEY.
//! 8. Report #2, judged against a volume record read after it that repeats the volume and own-enrollment checks: the
//!    own pair as the one holder, with one own record and every other registrant a pair of
//!    `VolumeRecord::admitted`, so the tenure starts with the recorded pairs and those ended-key registrants.
//!    [`Fenced::restarted`] reads it as the admission capability; a final shard read must still name this tenure.
//! 9. Fence every coverage page under the new session ([`Fencing::fenced`](crate::storage::page_coverage::Fencing::fenced)),
//!    so the acknowledged invalidations precede the tenure's service; the final shard read names the checkpoint, cut
//!    and ancestry the tenure's warm bootstrap reads ([`WarmSource`](crate::storage::WarmSource)).
//!
//! [`Takeover::nominated`] builds the sequence from the witness this standby's detector minted when it revalidated
//! a published nomination, while the witness names this shard and `now` lies before its expiry, and
//! [`Takeover::next`] names the one step after a refusal: this host's same-host restart or nothing.
//!
//! Invariants:
//!
//! - NAMED-STANDBY: only the host the shard record names as standby passes step 1 or the CAS, and the CAS clears the
//!   name, so one nomination of `(g, owner, E)` yields at most one takeover. An attached host the record does not
//!   name, a replacement standby included, refuses `Stale` with no write and no device command.
//! - CAS-BEFORE-DEVICE: the sequence makes no device call before the acknowledged CAS. A refused, failed or unknown
//!   CAS ends the attempt with no device call. After an unknown outcome the caller runs only the same-host restart
//!   that [`Takeover::next`] returns (`failover::restart`): it refuses `Deposed` while the record names the
//!   predecessor. While the record names this host, the predecessor's recorded registration holding sends it through
//!   its lineage arm: its own acknowledged bump, then the preempt of that holder. It refuses at Report #1 with no
//!   flip as `Unheld` when `unheld_among_recorded` accepts the Report: nobody holds on a conclusive count, at most one
//!   record carries its host ID, under its key, and every other registrant is recorded. A Report refusal that
//!   `restart::disposition` classifies as `Flip` keeps the restart's refusal and its flip. A failed device step of
//!   that restart, an unreadable Report, or a failed bump holds the attempt with the flip disabled
//!   (DEVICE-FAILURE-HOLD). Rereads leave the attempt and session unauthorized (`NoEpochReuse`).
//! - CAS-AT-READ: the CAS conditions on the step-1 version, so a same-host restart's bump of the same record, or a
//!   record whose standby changed, commits at most one write over that version; the loser mints nothing.
//! - SUPERSEDED-TENURE-PREEMPT (`NoPreemptOfForeignKey`): the preempt names another host's key only as a successor,
//!   directly or through committed takeover writes, of that host's tenure on this volume, after the own takeover
//!   write committed. The same-host restart's lineage arm preempts under the same rule after its own acknowledged
//!   bump, as that tenure's successor: the record names its host owner, so the holder's tenure lies below it. The key is the holder's that Report #1 showed, of a
//!   pair the volume record read after it records for another host, and the step-7 read still
//!   names this tenure. A registration acquires the reservation only under a tenure of its own host on this volume:
//!   the fresh Acquire, the restart's self preempt and this preempt each follow their host's own acknowledged write
//!   of the shard record, a volume is active in one generation, and `E` rises with every tenure of it. So while the
//!   record names this tenure, every other host's holding belongs to a tenure below it: the predecessor's, or one
//!   that the predecessor's line of takeovers succeeded when a successor in that line stopped before its preempt.
//!   A holder whose key falls outside the recorded pairs, a dropped ended pair's key included, refuses before the
//!   preempt. At most [`MAX_ATTACHED`] hosts hold a live attach of the volume at one time, and `E` ([`ATTEMPTS_MAX`])
//!   bounds the depth of a chain. The argument rests on every acquisition path
//!   following its own host's acknowledged shard-record write.
//!   KEY-REUSE-EXPOSURE: a process paused between its last tenure check and the preempt can preempt a later tenure
//!   of the attachment whose key it captured, because an attachment keeps its key across its tenures. A later attach
//!   of the same host takes its own key (KEY-PER-ATTACH), so such a preempt spares it. The deposed
//!   owner withdraws with no request on the deposing status (STATUS-IS-DEPOSITION) or under the recorded holder, and
//!   its next restart preempts that holder through its lineage arm; the paused process refuses at Report #2 or as
//!   `Superseded`, a paused lineage restart as `Lineage::Superseded` at its tenure read before the fence, and the
//!   volume stays retained. Each tenure read shows the record at that read only.
//! - HOST-LOSS-KEEPS-VOLUME: no refusal requests a retirement, and step 1 refuses before the CAS unless its volume
//!   record read records a pair for the predecessor; a detach or end recorded between that read and the CAS keeps
//!   that pair recorded, so Report #1 still admits its holding. Step 1 reads the shard record before the volume
//!   record, so a CAS that commits conditions on a shard version its volume read follows: when a designation of this
//!   host commits after the end of this host's entry and the drop of its pair, the volume read shows the entry ended
//!   and step 1 refuses `Local(Ended)` before the CAS and before any device command, so no takeover leaves the shard
//!   an owner with no recorded pair. The order closes that race only together with the owner's View, which reads the
//!   volume record before the shard record (FP-HOST-07), and the pair drop's rule NAMED-PAIR-KEPT, which keeps the
//!   pair of a host the View's shard read names standby: a drop of this host's pair then follows the end and
//!   precedes the designation. After the CAS the record names this host at `E + 1` with no
//!   standby; while the predecessor's recorded pair holds, a successor that stops before its preempt leaves it
//!   holding, the predecessor's restart refuses `Deposed` with no flip, and the successor's own restart preempts the
//!   holder through its lineage arm. A failed step of that arm holds with no flip, and when the successor's host is
//!   lost the volume and its evidence stay for the fresh-host attach: the reconciler designates an attached and
//!   enrolled fresh host over the stopped successor's tenure, and that host's takeover preempts the holder under
//!   SUPERSEDED-TENURE-PREEMPT while every other registrant is a pair of `VolumeRecord::admitted`: a recorded pair,
//!   or a non-holding registrant under the key of an ended or gone entry. One case differs: a successor that
//!   registered into a table already at `N_reg` registrants (step 6) and stopped before its preempt leaves
//!   `N_reg + 1`. Its restart's Report #1 is over the bound and refuses `NotHolding(Excess)` with the flip request,
//!   and the process parks with the volume retained, since no automatic step serves that request
//!   ([`Exit::Retire`](crate::host::Exit::Retire)). A fresh host designated over that tenure reads the same count:
//!   its takeover refuses `Unparsed(Excess)` at Report #1, after its CAS and before any Register or preempt, and
//!   its restart refuses `NotHolding(Excess)` and parks the same way. No automatic step ends that case: the volume
//!   stays retained and the shard unavailable until an operator removes a registration or the volume is lost. A
//!   Report #1 with nobody holding refuses `Holder(Unresolved)`. When `unheld_among_recorded` accepts the successor's
//!   restart Report, that restart refuses `Unheld` with no flip under NO-HOLDER-HOLD, so a registration that ended
//!   without a preempt leaves the volume retained as well; an unrecorded registrant keeps the refusal and its flip. A
//!   successor restart whose device step fails holds with no flip (DEVICE-FAILURE-HOLD), so a transient fault on it
//!   keeps the volume.
//! - UNIT-ZERO-INERT: the sequence reads and writes no unit 0; its authority is the acknowledged CAS on the record
//!   naming this host as standby, so a predecessor's activation record at unit 0 changes nothing it decides.
//! - STANDBY-WRITERS: the reconciler's shard creation refuses a record naming a standby, and
//!   [`Record::succeeds`](crate::failover::records::Record::succeeds) refuses a standby change in a replacement; the
//!   reconciler's designation ([`Reconciler::designate`]) names the standby, and the flip, the takeover CAS and the
//!   planned transfer (`Client::transfer`) clear it.
//!
//! [`Reconciler::designate`]: crate::failover::reconcile::Reconciler::designate
//! [`MAX_ATTACHED`]: crate::failover::records::MAX_ATTACHED
//! [`ATTEMPTS_MAX`]: crate::failover::records::ATTEMPTS_MAX
//!
//! [`Client::take_over`]: crate::storage::store::Client::take_over

use crate::failover::detect::host::Revalidated;
use crate::failover::evidence::{NotSole, Pair, Registrant};
use crate::failover::identity::Exhid;
use crate::failover::poll::{Contradiction, contradiction};
use crate::failover::records::{ShardRecord, VolumeRecord};
use crate::failover::restart::{
    Driver, Failed, Local, LocalSource, Restart, Restarted, bound, enrolled, exhausted, parse,
};
use crate::failover::retire::{Role, Target, Trigger};
use crate::storage::page_coverage::FenceRefused;
use crate::storage::store::{Client, Key, Read, Store, StoreError, WatermarkLog};
use crate::storage::{Fenced, HolderRefusal, LineagePreempt, Session, SessionRefusal};

/// The device half of the sequence. Each method issues its step's commands. An `Ok` return follows every command's
/// terminal; an `Err` return may come while a command is outstanding, and the implementation keeps its custody.
pub trait Device {
    /// Inspects the driver before any device command.
    ///
    /// # Errors
    ///
    /// The [`Driver`] condition that forbids the start.
    fn start(&mut self) -> Result<(), Driver>;

    /// Returns once the controller reports ready.
    ///
    /// # Errors
    ///
    /// [`Failed`] when the controller did not become ready.
    fn ready(&mut self) -> Result<(), Failed>;

    /// Sets the controller's host identifier to `exhid` and confirms it.
    ///
    /// # Errors
    ///
    /// [`Failed`] when the identifier was not set or not confirmed.
    fn set_host_id(&mut self, exhid: Exhid) -> Result<(), Failed>;

    /// Takes an extended Report and returns its bytes after the driver's Report checks passed.
    ///
    /// # Errors
    ///
    /// [`Failed`] when the Report did not complete with success or the driver withheld its bytes.
    fn report(&mut self) -> Result<Vec<u8>, Failed>;

    /// Registers the own pair's key.
    ///
    /// # Errors
    ///
    /// [`Failed`] when the Register did not complete with success.
    fn register(&mut self, own: Pair) -> Result<(), Failed>;

    /// Issues the Preempt-and-Abort of the superseded holder's key.
    ///
    /// # Errors
    ///
    /// [`Failed`] when the command did not complete with success.
    fn preempt(&mut self, preempt: LineagePreempt) -> Result<(), Failed>;
}

/// The check that refused. No variant requests a retirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// A record read failed: step 1, a volume reread after a Report, or a shard read of a tenure check.
    Records(StoreError),
    /// Step 1: the record names another standby, `(g, owner, E)` or active volume than this takeover's, or holds
    /// `E = 0`, a generation whose fresh first acquisition has not run.
    Stale,
    /// Step 1: the record names this host owner; the caller runs the same-host restart.
    Restart,
    /// Step 1: the record admits no further session.
    Exhausted(SessionRefusal),
    /// Step 1, or a volume reread after a Report: the volume record retires the volume ([`Trigger`]).
    Volume(Trigger),
    /// Step 1: the volume record records no pair for the predecessor, on a live attach or an ended entry, so no
    /// Report can resolve its holder.
    Predecessor,
    /// Step 1 or a volume reread after a Report that ends this host's own entry (`Local::Ended`); step 2, or a volume
    /// reread that enrolls no pair or another pair for this host's live attach.
    Local(Local),
    /// Step 3: the takeover CAS did not acknowledge success.
    TakeOver(StoreError),
    Driver(Driver),
    Ready(Failed),
    HostId(Failed),
    FirstReport(Failed),
    /// Report #1 did not parse under the reservation limits.
    Unparsed(NotSole),
    /// Report #1 fails the holder or registrant checks of the superseded-tenure preempt ([`HolderRefusal`]).
    Holder(HolderRefusal),
    Register(Failed),
    Preempt(Failed),
    SecondReport(Failed),
    /// Report #2 refuses the own pair as the holder among recorded registrants.
    NotSole(NotSole),
    /// Report #2 failed structural decoding.
    SecondUnparsed(NotSole),
    /// The record has moved past the acknowledged CAS.
    Superseded,
    /// Step 9: the coverage pages could not be fenced under the new session.
    Coverage(FenceRefused),
    /// Step 1: the shard record names suffixes and no checkpoint, which the warm read cannot replay; the takeover
    /// refuses before its compare-and-swap with the record unchanged.
    SuffixOnly,
}

/// A refused takeover. `recovery` names this host's tenure `(g, self, E + 1)` after an unknown, `Log` or `Regression`
/// CAS outcome and after every refusal that follows the acknowledged CAS, and is `None` otherwise; the record may hold
/// that tenure, and the hint licenses nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub check: Check,
    pub recovery: Option<Target>,
}

impl Refused {
    /// Whether the refusal leaves this standby only the same-host restart: it is [`Check::Restart`] or names a
    /// recovery tenure. [`Takeover::next`] returns [`Next::Restart`] exactly then.
    pub(crate) fn restarts(&self) -> bool {
        self.recovery.is_some() || self.check == Check::Restart
    }
}

/// One takeover of the shard's active volume by this host, the record's standby, for the arbiter's nomination of
/// `target`.
#[derive(Debug, Clone, Copy)]
pub struct Takeover<'a> {
    /// This standby's inputs: the shard, its holder of the active volume, the bounds, the reservation limits, the
    /// verified instance of each standby host the caller expects, a host whose attach failed with no enrolled pair
    /// included, as in `Reads::peers`, and the intervals of one key
    /// the coverage keeps on a page.
    restart: Restart<'a>,
    /// The `(g, owner, E)` the nomination names.
    target: Target,
}

/// The standby's one step after a refused takeover. No variant flips or retires, so host loss keeps the volume
/// (HOST-LOSS-KEEPS-VOLUME).
#[derive(Debug, Clone, Copy)]
pub enum Next<'a> {
    /// Run only this same-host restart, whose step 1 issues no device command unless the shard record names this host
    /// owner: the refusal is [`Check::Restart`], or names a recovery tenure because the CAS may have committed or did.
    /// It carries the peers the takeover was built with; the caller rebinds [`Restart::peers`] to the hosts its
    /// current read of the volume record shows attached with no enrolled pair before running it, since an attach the
    /// reconciler recorded after those peers were fixed, with an entry that binds no instance, refuses step 1 as
    /// `Check::Volume(Events)` with the flip.
    Restart(Restart<'a>),
    /// End the attempt: the CAS committed nothing and the sequence issued no device command.
    Stop,
}

impl<'a> Takeover<'a> {
    /// The takeover a revalidated nomination starts: the `(g, owner, E)` of `witness`, with `restart`'s holder,
    /// bounds, limits, peers and intervals, which name this standby. `None` unless `witness` names `restart`'s shard
    /// and `now < witness.until_us`, so a witness of another shard and an expired one start nothing. The standby's
    /// detector mints the witness only while it revalidates the nomination ([`Watch::revalidate`]), so a
    /// self-suspecting standby, a lapsed probe cycle and a target the last sync dropped mint none. The expiry is
    /// checked here only, so the caller runs the takeover in the turn that built it. Detection carries no safety:
    /// the CAS of [`Takeover::run`] decides.
    ///
    /// [`Watch::revalidate`]: crate::failover::detect::host::Watch::revalidate
    pub fn nominated(restart: Restart<'a>, witness: &Revalidated, now: u64) -> Option<Self> {
        (witness.shard == restart.shard && now < witness.until_us).then_some(Self {
            restart,
            target: witness.target,
        })
    }

    /// The step after `refused`: [`Next::Restart`] of this standby's volume when the refusal is [`Check::Restart`] or
    /// names a recovery tenure, and [`Next::Stop`] otherwise. A reread licenses no session: the restart mints one
    /// only from its own acknowledged bump.
    pub fn next(&self, refused: &Refused) -> Next<'a> {
        if !refused.restarts() {
            return Next::Stop;
        }
        Next::Restart(self.restart)
    }

    /// Runs the sequence through `client`, the local record of `local` and `device`.
    ///
    /// # Errors
    ///
    /// [`Refused`] at the first failed check, after which the sequence issued no further device command.
    pub fn run<S: Store, L: WatermarkLog, D: Device>(
        &self,
        client: &mut Client<S, L>,
        local: &impl LocalSource,
        device: &mut D,
    ) -> Result<Restarted, Refused> {
        let before = |check| Refused {
            check,
            recovery: None,
        };
        let (shard, volume) = self.records(client).map_err(before)?;
        // Step 1 matched the read to `self.target` and bounded `E` below `ATTEMPTS_MAX`.
        let own_target = Target {
            owner: self.restart.holder.host,
            attempts: self.target.attempts + 1,
            ..self.target
        };
        let own = bound(&self.restart.holder, local, volume.value())
            .map_err(|local| before(Check::Local(local)))?;
        let taken = client
            .take_over(&shard, self.target, self.restart.holder.host)
            .map_err(|error| Refused {
                recovery: matches!(
                    error,
                    StoreError::Unknown | StoreError::Log | StoreError::Regression(_)
                )
                .then_some(own_target),
                check: Check::TakeOver(error),
            })?;
        let session = Session::activate(taken)
            .expect("step 1 refused an exhausted generation or attempt counter");
        let refuse = |check| Refused {
            check,
            recovery: Some(own_target),
        };
        device
            .start()
            .map_err(|driver| refuse(Check::Driver(driver)))?;
        device
            .ready()
            .map_err(|failed| refuse(Check::Ready(failed)))?;
        device
            .set_host_id(own.exhid)
            .map_err(|failed| refuse(Check::HostId(failed)))?;
        let mut entries = vec![
            Registrant {
                cntlid: 0,
                holder: false,
                pair: own,
            };
            self.restart.limits.registrants() as usize
        ];
        let first = device
            .report()
            .map_err(|failed| refuse(Check::FirstReport(failed)))?;
        let report = parse(self.restart.limits, &first, &mut entries)
            .map_err(|refusal| refuse(Check::Unparsed(refusal)))?;
        let volume = self.reread(client, own, shard.value()).map_err(refuse)?;
        let admitted: Vec<Pair> = volume.value().admitted(report.entries).copied().collect();
        let preempt = LineagePreempt::resolve(
            &report,
            &admitted,
            volume.value().recorded_beside(self.restart.holder.host),
            own,
            &self.restart.bounds,
        )
        .map_err(|refusal| refuse(Check::Holder(refusal)))?;
        if !report.entries.iter().any(|entry| entry.pair == own) {
            device
                .register(own)
                .map_err(|failed| refuse(Check::Register(failed)))?;
        }
        self.current(client, &session).map_err(refuse)?;
        device
            .preempt(preempt)
            .map_err(|failed| refuse(Check::Preempt(failed)))?;
        let second = device
            .report()
            .map_err(|failed| refuse(Check::SecondReport(failed)))?;
        let report = parse(self.restart.limits, &second, &mut entries)
            .map_err(|refusal| refuse(Check::SecondUnparsed(refusal)))?;
        let volume = self.reread(client, own, shard.value()).map_err(refuse)?;
        let recorded: Vec<Pair> = volume.value().admitted(report.entries).copied().collect();
        let fenced = Fenced::restarted(&report, own, &recorded, &self.restart.bounds)
            .map_err(|refusal| refuse(Check::NotSole(refusal)))?;
        let current = self.current(client, &session).map_err(refuse)?;
        Restarted::complete(
            client,
            (&current, volume.value()),
            (session, fenced, recorded),
            self.restart.intervals,
        )
        .map_err(|refused| refuse(Check::Coverage(refused)))
    }

    /// The tenure check before the preempt and before the capability returns, which yields the record it read; a
    /// pause after its read is KEY-REUSE-EXPOSURE.
    fn current<S: Store, L: WatermarkLog>(
        &self,
        client: &mut Client<S, L>,
        session: &Session,
    ) -> Result<ShardRecord, Check> {
        crate::failover::restart::named_tenure(
            client,
            self.restart.shard,
            self.restart.holder.volume,
            session,
        )
        .map_err(Check::Records)?
        .ok_or(Check::Superseded)
    }

    /// Step 1: the shard record, which the CAS conditions on, then the volume record (HOST-LOSS-KEEPS-VOLUME). Both
    /// reads precede the checks of [`Takeover::step_one`], so a failed read refuses `Records` whatever the roles.
    fn records<S: Store, L: WatermarkLog>(
        &self,
        client: &mut Client<S, L>,
    ) -> Result<(Read<ShardRecord>, Read<VolumeRecord>), Check> {
        #[cfg(test)]
        if tests::volume_first() {
            let volume = client
                .read::<VolumeRecord>(Key::Volume(self.restart.holder.volume))
                .map_err(Check::Records)?;
            let shard = client
                .read::<ShardRecord>(Key::Shard(self.restart.shard))
                .map_err(Check::Records)?;
            return self.step_one(shard, volume);
        }
        let shard = client
            .read::<ShardRecord>(Key::Shard(self.restart.shard))
            .map_err(Check::Records)?;
        let volume = client
            .read::<VolumeRecord>(Key::Volume(self.restart.holder.volume))
            .map_err(Check::Records)?;
        self.step_one(shard, volume)
    }

    /// Step 1's checks of the shard record `shard` and the volume record `volume`.
    fn step_one(
        &self,
        shard: Read<ShardRecord>,
        volume: Read<VolumeRecord>,
    ) -> Result<(Read<ShardRecord>, Read<VolumeRecord>), Check> {
        let record = shard.value();
        if record.active == self.restart.holder.volume && record.owner == self.restart.holder.host {
            return Err(Check::Restart);
        }
        if record.standby != Some(self.restart.holder.host)
            || Target::of(record) != self.target
            || record.active != self.restart.holder.volume
            || record.attempts == 0
        {
            return Err(Check::Stale);
        }
        exhausted(record).map_err(Check::Exhausted)?;
        if record.checkpoint.is_none() && !record.ancestry.as_slice().is_empty() {
            return Err(Check::SuffixOnly);
        }
        self.judge(record, volume.value())?;
        if !volume.value().records_pair_of(self.target.owner) {
            return Err(Check::Predecessor);
        }
        Ok((shard, volume))
    }

    /// The poll's OWNER-EVENTS rule for this host over `self.restart.peers`, so the predecessor and each other live
    /// host is enrolled or bound.
    fn judge(&self, shard: &ShardRecord, volume: &VolumeRecord) -> Result<(), Check> {
        match contradiction(
            Role::Active,
            Some(self.restart.peers),
            &self.restart.holder,
            shard,
            volume,
        ) {
            None => Ok(()),
            Some(Contradiction::Retire(trigger)) => Err(Check::Volume(trigger)),
            Some(Contradiction::Ended) => Err(Check::Local(Local::Ended)),
        }
    }

    /// READ-ORDER-ADMISSION: a Report is judged against a volume record read after it, which must pass the volume
    /// checks and still enroll the own pair.
    fn reread<S: Store, L: WatermarkLog>(
        &self,
        client: &mut Client<S, L>,
        own: Pair,
        shard: &ShardRecord,
    ) -> Result<Read<VolumeRecord>, Check> {
        let volume = client
            .read::<VolumeRecord>(Key::Volume(self.restart.holder.volume))
            .map_err(Check::Records)?;
        self.judge(shard, volume.value())?;
        enrolled(&self.restart.holder, volume.value(), own).map_err(Check::Local)?;
        Ok(volume)
    }
}

#[cfg(test)]
#[path = "takeover_tests.rs"]
pub(crate) mod tests;
