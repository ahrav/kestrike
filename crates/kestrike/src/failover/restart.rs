//! The same-host restart sequence: the one path by which a restarted process reaches the fencing boundary (FB) on
//! the volume it owns. The sequence runs these steps in order and refuses at the first failed check:
//!
//! 1. Read the volume record, then the shard record, and refuse unless the shard record names this host as owner of
//!    this volume with `E > 0`, the volume is active under it, its record's events pass the poll's OWNER-EVENTS rule
//!    over `peers`, the volume is unmodified with a layout that `Layout::check_floor` admits, and
//!    the shard record names a checkpoint whenever it names suffixes and admits one more session, with
//!    `g < 2^32 - 1` and `E < ATTEMPTS_MAX`. At `E = 0` the volume belongs to the fresh first acquisition.
//! 2. Read the host-local record, and require it present, readable, valid, bound to this instance and this volume,
//!    and carrying the pair the volume record enrolls for this host's live attach, whose entry binds this instance
//!    or none (INSTANCE-BOUND). The live attach event stands in for the attachment ID, which only the signed
//!    assignment carries.
//! 3. Detect the driver: a held device address or device lock, which a live earlier incarnation or a bind holds, or a binding
//!    other than the userspace driver refuses. Then wait for the controller to report ready.
//! 4. Set the local record's host ID.
//! 5. Report #1: the own pair registered and the one holder of a type-2 reservation, with one record carrying the own
//!    host ID and every other registrant a recorded pair of the volume record or a registrant under the key of an
//!    attach the record ended ([`VolumeRecord::registrant`], ENDED-NEVER-RETIRES). A registrant under another key survives
//!    the self Preempt-and-Abort, so an unrecorded one refuses here, before any further command; an enrolled
//!    standby's registration survives it while the own pair stays the one holder. When Report #1 shows instead a
//!    pair the volume record read after it records for another host as the one holder, with every other registrant
//!    recorded or under an ended attach's key ([`LineagePreempt::resolve_counted`] over the census above), the
//!    restart takes the lineage arm of steps 6 to 9.
//! 6. Bump `E: n -> n + 1` by an exact-version compare-and-swap on the shard record read in step 1, and proceed only
//!    on its acknowledged success; the session is `g·2^32 + 2n + 2`.
//! 7. Preempt-and-Abort naming the own key, which requires Success. The lineage arm instead registers the own pair
//!    when Report #1 listed no record of it, rereads the shard record, which must still name the bumped tenure and
//!    this active volume, and issues the Preempt-and-Abort naming the own key as CRKEY and the holder's key as PRKEY.
//!    A Report #1 that lists no record of the own pair and counts `N_reg` registrants refuses the arm before step 6
//!    ([`Lineage::Full`], REGISTER-ROOM), since its Register would leave a table above the bound.
//!    A handoff target, a successor whose takeover write committed with an unknown reply, and a tenure that
//!    withdrew under another host's recorded holder while the record still names it owner take this arm.
//! 8. Report #2: the own pair as the one holder, with one own record and every other registrant a recorded pair of
//!    the volume record or under an ended attach's key. [`Fenced::restarted`] reads Report #2 as the fencing
//!    boundary over those admitted pairs, which the tenure's serving authority starts from. The lineage arm then
//!    reads the shard record again, and that read must still name the bumped tenure and this active volume: its
//!    preempt named another host's key, and a takeover can commit over the bumped tenure while that preempt runs.
//! 9. Fence every coverage page under the new session ([`Fencing::fenced`]), so the acknowledged invalidations
//!    precede the tenure's service; the shard record read at step 1, or for the lineage arm its read after
//!    Report #2, names the checkpoint, cut and ancestry the tenure's warm bootstrap reads ([`WarmSource`]).
//!
//! Invariants:
//!
//! - RecordsBeforeDevice: the sequence issues no device command before steps 1 and 2 pass, so a host that no longer
//!   owns the volume, or a volume the records retire, receives nothing from it.
//! - INSTANCE-BOUND: step 2 and the volume record read after each Report refuse `Local::Binding` with no flip when the
//!   entry of this host's live attach binds an instance other than the holder's, so a process on an instance other
//!   than the one the reconciler recorded for the attach takes no tenure from it. An entry that binds none, an
//!   owner's first attach that no standby attach write bound, passes; `enroll_standby` applies the same rule before
//!   it persists a standby's local record.
//! - NoEpochReuse: the session comes only from the acknowledged success of this attempt's own bump. A failed bump,
//!   a timeout and a lost acknowledgment refuse, and no later read of the shard record licenses proceeding.
//! - BumpAtOwnGeneration: the bump conditions on the version of the step-1 read, so it commits only at the
//!   generation, owner and `E` that read showed.
//! - OwnBumpBeforePreempt, `NoPreemptOfForeignKey`: the lineage arm issues its Register and its preempt only after
//!   the acknowledged bump, and the preempt only after a shard read that still names the bumped tenure. The record
//!   names this host owner at that tenure, and every registration acquires the reservation only under a tenure of
//!   its own host on this volume after its own acknowledged shard-record write, so the holder's tenure lies below
//!   the bumped one: the preempted key is a predecessor's on this volume. A refused or unknown bump, a moved record
//!   and a failed reread issue no preempt; a takeover that commits between the reread and the preempt is the
//!   KEY-REUSE-EXPOSURE of `failover::takeover`. The read after Report #2 shows the tenure at that read only, and no
//!   preempt of the arm follows it: a takeover that commits after it supersedes this tenure as it supersedes any
//!   serving tenure, through its own preempt of this host's registration.
//! - NoPredecessorEffectAfterFB: the ready wait returns only after every request of the earlier incarnation ended at
//!   the card, the self Preempt-and-Abort aborts what remains under the own registration, and Report #2 confirms
//!   the own pair still holds. A write of an earlier incarnation that lands, before FB or after it as a stale
//!   attempt, carries that incarnation's session. A cold rerun's index starts empty and names only its own writes, so
//!   the read check turns such a landing into a miss; a warm rerun restores the checkpoint's entries of earlier
//!   sessions, and a read of a restored entry checks its header identity (allocation, session, version, key) and its
//!   chunk checksums before any byte is exposed, so a landing that changed the bytes misses; one that passes both
//!   carries that entry's own identity and checksummed bytes.
//! - HOST-LOSS-KEEPS-VOLUME: a step-2 refusal other than a retained refusal, and the `Local::Unenrolled` or
//!   `Local::Altered` refusal of the volume record reread at step 5 or 8, leave `flip` `None`, so a retained volume
//!   stays active through host-local faults.
//! - UNIT-ZERO-INERT: the sequence reads and writes no unit 0; its authority is its own acknowledged bump, so an
//!   activation record at unit 0, of any tenure, changes nothing it decides.
//! - Every refusal issues no later device command. A refusal requests the flip only on observed evidence or
//!   exhausted counters: a volume-record trigger ([`Check::Volume`]), exhausted session counters
//!   ([`Check::Exhausted`]), a retained refusal ([`Local::Retained`]), and a Report refusal that rests on an observed
//!   registrant set ([`NotSole::observed`]): an unrecorded holder or registrant, a second own record, a reservation
//!   of another type, or a count the recorded pairs cannot account for. The flip names the step-1 read's
//!   `(g, owner, E)`, or `(g, owner, n + 1)` once the own bump committed and the client reported the commit; a
//!   bump error requests no flip. The reconciler admits the request while the record holds that value, and refuses
//!   it as stale after a racing bump. A step-1 refusal whose records show another owner or another active volume, `E = 0`, or whose reads
//!   returned no value, requests nothing, so a stale restart never retires a successor or a fresh volume. A record
//!   read that failed outside the lineage arm ([`Check::Records`]), a deposition ([`Check::Deposed`]), a suffix-only
//!   record ([`Check::SuffixOnly`]) and every [`Check::Local`] refusal but a retained one request no flip and carry no
//!   recovery hint.
//! - DEVICE-FAILURE-HOLD: a driver refusal ([`Check::Driver`]), a device step that ends without success, whatever
//!   its status, a Report that is no observation ([`NotSole::Unreadable`], [`Check::Unobserved`]) and a bump without
//!   an acknowledged success ([`Check::Bump`]) request no flip and carry a target in [`Refused::recovery`], as a
//!   recorded holder the lineage arm cannot preempt ([`Check::RecordedHolder`]), a failed step of the lineage arm
//!   ([`Check::Lineage`]), a Report with nobody holding beside recorded registrants ([`Check::Unheld`]) and a
//!   coverage fencing refusal ([`Check::Coverage`]) do. Every refusal after the lineage arm's bump but a deposition
//!   holds this way, an observed Report #2 refusal and a failed record read included ([`Lineage::Confirm`],
//!   [`Lineage::Reread`]): the rerun's step 1 and Report #1 judge that evidence again. None of them shows
//!   volume loss, so host-local faults, store outages and unreadable Reports keep the retained volume active: host
//!   loss keeps the volume, and only observed volume loss replaces it. A hold returns no session: a hold after the
//!   acknowledged bump drops the session that bump activated, and no rerun reuses it. The sequence issues no record
//!   write after a hold; a bump of unknown outcome issued before the hold may still commit (SERIAL-ISSUE). A hold
//!   ends by one of these events:
//!   - a rerun of the sequence, the caller's, after the fault cleared: a refusal before the bump consumed no `E`, so
//!     its rerun bumps from the same `E`; a refusal after the acknowledged bump consumed one, so its rerun takes the
//!     next `E` through its own acknowledged bump (NoEpochReuse);
//!   - the named standby's takeover, whose exact-version CAS conditions on the record the hold left; a rerun that
//!     bumps, or a bump of unknown outcome that commits late, moves `E`, so a nomination of an earlier `E` refuses
//!     `Stale` and a nomination at the record's current `E` commits;
//!   - the fresh-host attach to the retained volume, while a recorded registration of another host holds, or a
//!     replacement on control-plane evidence of actual volume loss.
//!
//!   A [`Check::Unheld`] refusal recurs on every rerun while its Report does, and a takeover's Report #1 with nobody
//!   holding refuses `Holder(Unresolved)`, a designated fresh host's included, so no automatic step ends it: the
//!   volume and its evidence stay retained and the shard unavailable until an operator acts or the volume is lost. A
//!   [`Check::RecordedHolder`] refusal at Report #1 recurs while its holder, a recorded pair of this host's own
//!   earlier attach, holds. It ends by the fresh-host attach, or by a designated standby's takeover, whose Report #1
//!   admits the holder under SUPERSEDED-TENURE-PREEMPT (`failover::takeover`). A takeover's resolution admits the
//!   recorded pairs and the non-holding registrants under an ended attach's key, as the lineage arm's does
//!   (`VolumeRecord::admitted`), so such a registrant listed beside that holder leaves the takeover its preempt.
//!   A Report #2
//!   refusal of the self preempt ends at the rerun, whose Report #1 takes the lineage arm while the record names this
//!   host owner. A [`Check::Lineage`] refusal after the arm's bump consumed one `E`, and its rerun
//!   takes the arm again at the next `E`. A [`Lineage::Full`] refusal consumed none and recurs on every rerun while
//!   the table stays full: the ended-attach pair drop and reclaim need a serving owner past its fencing boundary, so
//!   no automatic step of this tree ends it; it ends when an operator removes a registration or another host takes
//!   over. The heartbeat producer's caller sends `healthy = false`
//!   (`detect::beat::Header::healthy`) while this host's restart holds, so its standby's detector reads a declared
//!   failure and nominates it on the ordinary quorum while its counted votes read silent or declared and its
//!   brake on correlated declarations does not hold (DECLARED-BRAKE in `detect::host`); recovery of a held live
//!   host depends on that caller obligation.
//!   Reruns that keep failing after the bump consume `E` until step 1 refuses [`Check::Exhausted`],
//!   which requests the flip.
//! - No timing carries safety: a device step that ends without success refuses and holds, whatever deadline ended
//!   it.
//!
//! A [`ControllerEvent`] during a tenure ends the incarnation: the owner stops submitting, tears down the queues,
//! discards the index and runs the sequence again from step 1. The SPDK driver records the first such event and
//! refuses every later submit; the owner's rerun is the caller's.
//!
//! [`ControllerEvent`]: crate::storage::ControllerEvent

use crate::failover::attachments::Peer;
use crate::failover::bounds::Bounds;
use crate::failover::evidence::{Holding, NotSole, Pair, Registrant, Report};
use crate::failover::identity::Exhid;
use crate::failover::poll::{Contradiction, Holder, contradiction};
use crate::failover::record::{LocalRecord, RecordError};
use crate::failover::records::{ATTEMPTS_MAX, ShardRecord, VolumeRecord};
use crate::failover::retire::{Role, Target, Trigger};
use crate::net::ownership::Shard;
use crate::storage::page_coverage::{FenceRefused, Fencing};
use crate::storage::store::{Client, Key, Read, Store, StoreError, WatermarkLog};
use crate::storage::{
    DeviceStatus, Fenced, LineagePreempt, ReservationLimits, SelfPreempt, Session, SessionRefusal,
    SpdkAttachError, WarmSource, parse_extended_report,
};

/// Rounds of [`Fencing::fence_all`] a fresh activation, a restart or a takeover runs before it refuses an unresolved
/// page.
pub const FENCE_ROUNDS: usize = 4;

/// The device half of the sequence. Each method issues its step's commands. An `Ok` return follows every command's
/// terminal; an `Err` return may come while a command is outstanding, and the implementation keeps its custody.
pub trait Device {
    /// Inspects the driver before any device command.
    ///
    /// # Errors
    ///
    /// The [`Driver`] condition that forbids the start.
    fn start(&mut self) -> Result<(), Driver>;

    /// Returns once the controller reports ready. The driver reports ready only after every request of the earlier
    /// incarnation completed at the card.
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

    /// Takes an extended Report and returns its bytes whenever the command completed with success. The sequence's own
    /// parse and registrant checks judge the bytes, so an own-host-ID alias, a second own record and a count above
    /// the reservation limits reach [`NotSole::observed`] and keep their flip.
    ///
    /// # Errors
    ///
    /// [`Failed`] when the Report did not complete with success.
    fn report(&mut self) -> Result<Vec<u8>, Failed>;

    /// Issues the self Preempt-and-Abort.
    ///
    /// # Errors
    ///
    /// [`Failed`] when the command did not complete with success.
    fn preempt(&mut self, preempt: SelfPreempt) -> Result<(), Failed>;

    /// Registers the own pair's key: the lineage arm's Register.
    ///
    /// # Errors
    ///
    /// [`Failed`] when the Register did not complete with success.
    fn register(&mut self, own: Pair) -> Result<(), Failed>;

    /// Issues the Preempt-and-Abort naming the own key as CRKEY and the recorded holder's key as PRKEY.
    ///
    /// # Errors
    ///
    /// [`Failed`] when the command did not complete with success.
    fn preempt_lineage(&mut self, preempt: LineagePreempt) -> Result<(), Failed>;
}

/// The host-local record the sequence reads at step 2.
pub trait LocalSource {
    fn local(&self) -> Result<LocalRecord, Local>;
}

/// A device step that ended without success: the device's status, or `None` when the device gave no status for the
/// step: no completion by the step's deadline, a refused submit or local step, or a Report whose bytes the driver
/// withheld.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failed(pub Option<DeviceStatus>);

/// A driver condition that refuses the start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Driver {
    /// This process already attached the controller's address, or another holder has its device lock.
    LiveQueues,
    /// The attach found the function bound to a driver other than `vfio-pci`.
    KernelBinding,
}

impl Driver {
    pub fn of_attach(error: &SpdkAttachError) -> Option<Self> {
        match error {
            SpdkAttachError::KernelBinding => Some(Self::KernelBinding),
            SpdkAttachError::AlreadyAttached
            | SpdkAttachError::DeviceLock(std::io::ErrorKind::WouldBlock) => Some(Self::LiveQueues),
            _ => None,
        }
    }
}

/// The local record's refusal at step 2; `Binding`, `Unenrolled` and `Altered` also refuse the volume record reread at
/// step 5 or 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Local {
    Absent,
    Unreadable,
    Invalid(RecordError),
    /// INSTANCE-BOUND: the local record is bound to another instance or another volume, or the volume record's entry
    /// for this host's live attach binds an instance other than the holder's.
    Binding,
    Retained,
    /// The volume record enrolls no pair for this host's live attach.
    Unenrolled,
    /// The volume record enrolls another pair for this host's live attach.
    Altered,
    /// ENDED-GRANTS-NOTHING: [`VolumeRecord::ended`] returns `true` for the holder's host, so the restart refuses
    /// admission.
    Ended,
}

/// The check that refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// A volume or shard read in `records`, or the volume reread in `admit` outside the lineage arm's Report #2,
    /// failed.
    Records(StoreError),
    /// The step-1 shard record names another owner or another active volume, or in `admit` a `ForeignHolder`
    /// refusal's `superseded`, checked against the reread volume record before the reread's step-1 and enrollment
    /// checks, finds a later tenure whose owner's enrolled pair is the holder.
    Deposed,
    /// RECORDED-HOLDER-HOLD: a Report shows a recorded pair of another attachment holding, a live attach's or an ended
    /// one's, with every other registrant recorded or under an ended attach's key, under the shard record step 1 read
    /// naming this host, and the lineage arm does not apply: the Report is Report #2 of the self preempt, or the holder
    /// is a pair recorded for this host. The restart refuses with no flip and carries the record's target in
    /// [`Refused::recovery`]. A registrant the volume record ties to no attach keeps `NotHolding(ForeignHolder)` and
    /// its flip.
    RecordedHolder,
    /// A step of the lineage arm failed: a full registrant table before its bump, which holds with the step-1 target
    /// in [`Refused::recovery`], or a step after its acknowledged bump, which holds with the bumped target there. No
    /// later device command follows (RECORDED-HOLDER-HOLD).
    Lineage(Lineage),
    /// NO-HOLDER-HOLD: `unheld_among_recorded` accepts the Report over the pairs of the volume record reread after
    /// it: nobody holds on a conclusive count, at most one record carries the own host ID, under the own key, and every other
    /// registrant is recorded, under the shard record step 1 read naming this host. A predecessor's
    /// registration that ended after a committed takeover, a fresh path that stopped after its bump and before its
    /// Acquire, and a self preempt that unregistered its caller leave this state; none shows volume loss. The restart
    /// refuses with no flip and carries the target in [`Refused::recovery`]. It issues no Register or Acquire, so a
    /// rerun over the same reservation refuses again, and a designated host's takeover refuses `Holder(Unresolved)`
    /// with nobody holding, so the volume stays active and retained and the shard stays unavailable until an operator
    /// acts or the volume is lost. A rerun whose device step fails holds as well (DEVICE-FAILURE-HOLD).
    Unheld,
    /// Step 1: the shard record holds `E = 0`, so the volume awaits its fresh first acquisition.
    Fresh,
    /// Step 1, or at step 5 or 8 the volume record reread in `admit`: the volume record retires the volume: a state other than active under the shard record
    /// ([`Trigger::VolumeState`]), attachment events outside the owner rule of step 1 ([`Trigger::Events`]), a
    /// modification ([`Trigger::Modification`]), or a layout below the floor ([`Trigger::Layout`]).
    Volume(Trigger),
    /// Step 1: the shard record's session counters are exhausted, at `g = 2^32 - 1` or `E = ATTEMPTS_MAX`.
    Exhausted(SessionRefusal),
    /// Step 1: the shard record names suffixes and no checkpoint. The warm read replays suffixes only over a named
    /// checkpoint, so the restart refuses before any write with no flip, no recovery hint and the record unchanged;
    /// every restart and takeover of the record refuses the same way, and the shard stays unavailable until an
    /// operator rewrites the record or its volume is replaced.
    SuffixOnly,
    /// Step 2, or at step 5 or 8 the volume record reread in `admit` enrolls no pair or another pair for this host's
    /// live attach.
    Local(Local),
    /// Step 3: a host-local driver condition; holds (DEVICE-FAILURE-HOLD).
    Driver(Driver),
    /// Step 3: the controller did not report ready; holds (DEVICE-FAILURE-HOLD).
    Ready(Failed),
    /// Step 4; holds (DEVICE-FAILURE-HOLD).
    HostId(Failed),
    /// Step 5: Report #1 failed; holds (DEVICE-FAILURE-HOLD).
    FirstReport(Failed),
    /// Step 5: Report #1 refuses the own pair as the holder of a type-2 reservation among recorded registrants. An
    /// observed refusal requests the flip; [`NotSole::Unreadable`] holds (DEVICE-FAILURE-HOLD).
    NotHolding(NotSole),
    /// Step 5 or 8: the Report counts more registrants than `N_reg`, a bound below `MAX_REGISTRANTS`, and the pairs
    /// of the volume record it was judged against, the step-1 record or the record `admit` reread after the Report,
    /// with the own pair account for every listed pair and the count, so the Report is
    /// no observation; holds (DEVICE-FAILURE-HOLD). The parser refuses such a count first when the reservation limits equal
    /// `N_reg`, which attach requires, so a production restart refuses it with the flip, as `NotHolding(Excess)` after
    /// Report #1 and `NotSole(Excess)` after Report #2.
    Unobserved,
    /// Step 6: the bump returned no acknowledged success; holds (DEVICE-FAILURE-HOLD).
    Bump(StoreError),
    /// Step 7; holds (DEVICE-FAILURE-HOLD).
    Preempt(Failed),
    /// Step 8: Report #2 failed; holds (DEVICE-FAILURE-HOLD).
    SecondReport(Failed),
    /// Step 8: Report #2 refuses the own pair as the holder among recorded registrants. An observed refusal requests
    /// the flip; [`NotSole::Unreadable`] holds (DEVICE-FAILURE-HOLD).
    NotSole(NotSole),
    /// Step 9: [`Fencing::fenced`] refused to fence the coverage pages under the new session. Every coverage refusal
    /// leaves `flip` `None` and carries the bumped target in [`Refused::recovery`]. A newer fence belongs to a later tenure and an unresolved page to contention. A malformed
    /// page, or a `C_page` below the encoded empty page, is shard-record state every replacement volume reads
    /// unchanged; the shard stays unavailable until an operator rewrites the page or the record.
    Coverage(FenceRefused),
}

/// The step of the lineage arm that refused. Each one holds with `flip` `None`. `Full` refuses before the arm's bump
/// and [`Refused::recovery`] names the step-1 target; every other one follows the arm's acknowledged bump and names
/// the bumped target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lineage {
    /// REGISTER-ROOM: Report #1 lists no record of the own pair and counts `N_reg` registrants, so the arm's Register
    /// would raise the table above the bound every later Report is parsed under. The arm refuses before its bump: no
    /// bump, no Register, no preempt and no session. The check reads the Report #1 sample and reserves no slot, so a
    /// registration that lands after Report #1 is outside it.
    Full,
    /// The Register of the own pair, which Report #1 did not list, did not complete with success.
    Register(Failed),
    /// A shard reread of the arm, before the preempt or after Report #2, names another tenure or another active
    /// volume than the bump's: the arm stops there, before its preempt or before its fencing boundary.
    Superseded,
    /// A shard reread of the arm, before the preempt or after Report #2, failed.
    Reread(StoreError),
    /// The Preempt-and-Abort of the holder's key did not complete with success.
    Preempt(Failed),
    /// The lineage arm propagates [`Check::Deposed`] directly and wraps the remaining Report #2, parse, and admission
    /// checks in `Confirm`.
    Confirm(Box<Check>),
}

/// A refused restart: the check that refused, and the flip it requests, naming the `(g, owner, E)` the shard record holds.
/// `recovery` names the record's target for each refusal that holds (DEVICE-FAILURE-HOLD), whose holder a rerun's
/// Report #1 judges: the step-1 target before the bump, a full table's [`Lineage::Full`] included, the target
/// [`bump_target`] names for a bump error, and the bumped target after the bump. The shard record may have moved since, so the hint is an observation for the
/// fresh-host recovery that licenses no write or session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub check: Check,
    pub flip: Option<Target>,
    pub recovery: Option<Target>,
}

/// What [`Restarted::into_parts`] moves into the serving authority: the session, the Report #2 value, the admitted
/// pairs with the count of trailing ended-key pairs among them, the fencing, the warm source and the volume record's
/// pairs for ended attaches.
pub(crate) type Parts = (
    Session,
    Fenced,
    (Vec<Pair>, usize),
    Fencing,
    Option<WarmSource>,
    Vec<Pair>,
);

/// A restart that reached FB, or a takeover that reached its admission capability: the session of its acknowledged
/// bump or CAS, the value its Report #2 minted, the recorded pairs of the volume record Report #2 was judged
/// against, the fencing of the shard's coverage pages under the session, and the warm source the shard record names,
/// which move together into the serving authority.
#[derive(Debug)]
pub struct Restarted {
    pub(super) session: Session,
    pub(super) fenced: Fenced,
    pub(super) recorded: Vec<Pair>,
    /// The count of trailing pairs of `recorded` that Report #2 listed under an ended attach's key; the pairs before
    /// them are the volume record's.
    pub(super) late: usize,
    /// The pairs of the volume record that `recorded` starts with and that the record associates with an ended
    /// attach ([`VolumeRecord::ended_pairs`]).
    pub(super) ended: Vec<Pair>,
    pub(super) fencing: Fencing,
    pub(super) warm: Option<WarmSource>,
    /// The restart reached FB through its lineage arm.
    pub(super) lineage: bool,
}

impl Restarted {
    /// Whether the restart reached FB through its lineage arm: its preempt named another host's recorded holder.
    pub fn lineage(&self) -> bool {
        self.lineage
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    #[cfg(test)]
    pub fn fencing(&self) -> &Fencing {
        &self.fencing
    }

    /// The warm source the shard record names, present when it names a checkpoint.
    #[cfg(test)]
    pub fn warm(&self) -> Option<&WarmSource> {
        self.warm.as_ref()
    }

    pub(crate) fn into_parts(self) -> Parts {
        (
            self.session,
            self.fenced,
            (self.recorded, self.late),
            self.fencing,
            self.warm,
            self.ended,
        )
    }

    /// The restart's or takeover's step 9: fences `record`'s pages under `session` and builds the warm source
    /// `record` names under `volume`'s layout.
    pub(super) fn complete<S: Store, L: WatermarkLog>(
        client: &mut Client<S, L>,
        (record, volume): (&ShardRecord, &VolumeRecord),
        (session, fenced, recorded): (Session, Fenced, Vec<Pair>),
        intervals: usize,
    ) -> Result<Self, FenceRefused> {
        let fencing = Fencing::fenced(client, record, &session, intervals, FENCE_ROUNDS)?;
        let coverage = fencing
            .coverage()
            .expect("a complete fencing of a tenure not withdrawn holds its coverage");
        let warm = WarmSource::new(record, volume.layout, &session, coverage);
        let late = recorded.len().saturating_sub(volume.pairs.len());
        Ok(Self {
            session,
            fenced,
            recorded,
            late,
            ended: volume.ended_attach_pairs().copied().collect(),
            fencing,
            warm,
            lineage: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn fenced(&self) -> &Fenced {
        &self.fenced
    }
}

/// One restart of this host's volume of `shard`.
#[derive(Debug, Clone, Copy)]
pub struct Restart<'a> {
    pub shard: Shard,
    pub holder: Holder,
    pub bounds: Bounds,
    pub limits: ReservationLimits,
    /// The verified instance of each standby host the caller expects, a host whose attach failed with no enrolled
    /// pair included, as in `Reads::peers`: step 1 admits a bound standby's live attach before its enrollment. The
    /// caller fixes it from a volume record read before the run, so an attach recorded during the run whose entry
    /// binds no instance refuses the next volume check as `Check::Volume(Events)`, which requests the flip; an entry
    /// that binds its instance admits its live attach with no peer.
    pub peers: &'a [Peer],
    /// The intervals of one key the coverage keeps on a page.
    pub intervals: usize,
}

impl Restart<'_> {
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
        let (shard, mut volume) = self.records(client).map_err(|check| Refused {
            check,
            flip: None,
            recovery: None,
        })?;
        let read = Target::of(shard.value());
        let refuse = |check: Check| Refused::at(check, read);

        self.judge(shard.value(), &volume).map_err(refuse)?;
        let own =
            bound(&self.holder, local, &volume).map_err(|local| refuse(Check::Local(local)))?;
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
            self.limits.registrants() as usize
        ];
        let first = device
            .report()
            .map_err(|failed| refuse(Check::FirstReport(failed)))?;
        let report = parse(self.limits, &first, &mut entries)
            .map_err(|refusal| refuse(Check::NotHolding(refusal)))?;
        let lineage = self
            .admit(
                client,
                &report,
                own,
                &mut volume,
                (shard.value(), read),
                Check::NotHolding,
            )
            .map_err(refuse)?;
        let fence =
            match lineage {
                None => Fence::Own(SelfPreempt::from_report(&report, &self.bounds, own).expect(
                    "a Report whose admitted holder is the own pair admits the self preempt",
                )),
                Some(preempt) => {
                    let registered = report.entries.iter().any(|entry| entry.pair == own);
                    // REGISTER-ROOM: a Register into a table Report #1 shows at `N_reg` would leave `N_reg + 1`
                    // registrants, which every later parse refuses as over the bound.
                    let full = !registered && report.regctl >= self.bounds.registrant_max();
                    #[cfg(test)]
                    let full = full && !tests::planted(tests::Plant::NoRoom);
                    if full {
                        return Err(refuse(Check::Lineage(Lineage::Full)));
                    }
                    Fence::Lineage {
                        preempt,
                        registered,
                    }
                }
            };
        let bumped_target = Target {
            attempts: read.attempts + 1,
            ..read
        };
        #[cfg(test)]
        if let Fence::Lineage {
            preempt,
            registered,
        } = &fence
        {
            use tests::{Plant, planted};
            if planted(Plant::NoBump) || planted(Plant::PreemptBeforeBump) {
                if !registered {
                    let _ = device.register(own);
                }
                let _ = client.read::<ShardRecord>(Key::Shard(self.shard));
                let _ = device.preempt_lineage(*preempt);
            }
            if planted(Plant::NoBump) {
                return Err(Refused::at(Check::Bump(StoreError::Unknown), read));
            }
        }
        let bumped = client
            .bump(&shard)
            .map_err(|error| Refused::at(Check::Bump(error), bump_target(&error, read)))?;
        let refuse = |check: Check| Refused::at(check, bumped_target);
        let session = Session::activate(bumped)
            .expect("step 1 refused an exhausted generation or attempt counter");
        debug_assert_eq!(session.target(), bumped_target);
        let arm = matches!(fence, Fence::Lineage { .. });
        let confirm = |check: Check| match check {
            Check::Deposed => check,
            check if arm => Check::Lineage(Lineage::Confirm(Box::new(check))),
            check => check,
        };
        match fence {
            Fence::Own(preempt) => device
                .preempt(preempt)
                .map_err(|failed| refuse(Check::Preempt(failed)))?,
            Fence::Lineage {
                preempt,
                registered,
            } => {
                if !registered {
                    device
                        .register(own)
                        .map_err(|failed| refuse(Check::Lineage(Lineage::Register(failed))))?;
                }
                self.attached(client).map_err(refuse)?;
                self.current(client, &session).map_err(refuse)?;
                device
                    .preempt_lineage(preempt)
                    .map_err(|failed| refuse(Check::Lineage(Lineage::Preempt(failed))))?;
            }
        }
        let second = device
            .report()
            .map_err(|failed| refuse(confirm(Check::SecondReport(failed))))?;
        let report = parse(self.limits, &second, &mut entries)
            .map_err(|refusal| refuse(confirm(Check::NotSole(refusal))))?;
        let holder = self
            .admit(
                client,
                &report,
                own,
                &mut volume,
                (shard.value(), bumped_target),
                Check::NotSole,
            )
            .map_err(|check| refuse(confirm(check)))?;
        // Report #2 takes no lineage arm: a resolvable holder there refuses, and the rerun's Report #1 judges it.
        if holder.is_some() {
            return Err(refuse(confirm(Check::RecordedHolder)));
        }
        let recorded: Vec<Pair> = volume.admitted(report.entries).copied().collect();
        let fenced = Fenced::restarted(&report, own, &recorded, &self.bounds)
            .expect("admit accepted Report #2 under these admitted pairs");
        // The self preempt names only the own key, and the bump changed `E` alone, so the step-1 read still names the
        // shard, generation, pages and manifest. The arm's preempt named another host's key, and a takeover may have
        // moved the record after the reread before it, so the arm reads the record again and fences from that read.
        let reread = arm;
        #[cfg(test)]
        let reread = reread && !tests::planted(tests::Plant::NoFinalReread);
        let record = if reread {
            self.current(client, &session).map_err(refuse)?
        } else {
            *shard.value()
        };
        let restarted = Restarted::complete(
            client,
            (&record, &volume),
            (session, fenced, recorded),
            self.intervals,
        )
        .map_err(|refused| refuse(Check::Coverage(refused)))?;
        Ok(Restarted {
            lineage: arm,
            ..restarted
        })
    }

    /// The lineage arm's shard reread: the record it returns names `session`'s target and `self.holder.volume` as
    /// active.
    /// The lineage arm rereads the volume before the shard to detect a local attachment that ended after Report #1's
    /// volume reread. If the attachment ended, `attached` returns `Check::Local(Local::Ended)` before the preempt
    /// (ENDED-GRANTS-NOTHING).
    fn attached<S: Store, L: WatermarkLog>(&self, client: &mut Client<S, L>) -> Result<(), Check> {
        let volume = client
            .read::<VolumeRecord>(Key::Volume(self.holder.volume))
            .map_err(|error| Check::Lineage(Lineage::Reread(error)))?;
        match volume.value().ended(self.holder.host) {
            true => Err(Check::Local(Local::Ended)),
            false => Ok(()),
        }
    }

    fn current<S: Store, L: WatermarkLog>(
        &self,
        client: &mut Client<S, L>,
        session: &Session,
    ) -> Result<ShardRecord, Check> {
        named_tenure(client, self.shard, self.holder.volume, session)
            .map_err(|error| Check::Lineage(Lineage::Reread(error)))?
            .ok_or(Check::Lineage(Lineage::Superseded))
    }

    /// Step 1: the volume record, then the shard record, which the bump conditions on. The restart keeps this order,
    /// which the takeover reverses: step 1 passes only for a host the shard record already names owner, the reconciler
    /// `Reconciler::end_attach` refuses the owner's entry, and the bump preserves the owner.
    fn records<S: Store, L: WatermarkLog>(
        &self,
        client: &mut Client<S, L>,
    ) -> Result<(Read<ShardRecord>, VolumeRecord), Check> {
        let volume = client
            .read::<VolumeRecord>(Key::Volume(self.holder.volume))
            .map_err(Check::Records)?;
        let shard = client
            .read::<ShardRecord>(Key::Shard(self.shard))
            .map_err(Check::Records)?;
        let record = shard.value();
        if record.active != self.holder.volume || record.owner != self.holder.host {
            return Err(Check::Deposed);
        }
        if record.attempts == 0 {
            return Err(Check::Fresh);
        }
        Ok((shard, volume.value().clone()))
    }

    /// Step 1's checks of the volume record under the shard record that names this host and volume.
    /// PENDING-ENROLLMENT: the poll's OWNER-EVENTS rule over `self.peers`, so a bound standby's live attach passes
    /// before its enrollment and every other live host must be enrolled.
    fn judge(&self, shard: &ShardRecord, volume: &VolumeRecord) -> Result<(), Check> {
        match contradiction(Role::Active, Some(self.peers), &self.holder, shard, volume) {
            None => {}
            Some(Contradiction::Retire(trigger)) => return Err(Check::Volume(trigger)),
            Some(Contradiction::Ended) => return Err(Check::Local(Local::Ended)),
        }
        // Suffixes with no checkpoint form a history the warm read replays only over a checkpoint.
        if shard.checkpoint.is_none() && !shard.ancestry.as_slice().is_empty() {
            return Err(Check::SuffixOnly);
        }
        exhausted(shard).map_err(Check::Exhausted)
    }

    /// READ-ORDER-ADMISSION: a refusal that a recorded pair could explain stands only under a volume record read after
    /// the Report, so `Excess`, `ForeignHolder`, `ForeignRegistrant`, `ReservationType` and `NotHolder` reread the
    /// volume record. ENDED-GRANTS-NOTHING: when the step-1 record accepts the Report, `admit` reads the volume record
    /// again as well, refuses `Local::Ended` with no flip when that read ends the own attach, requires the own pair
    /// enrolled there and judges the Report under it. The read narrows the window in which an end races the restart;
    /// the owner poll withdraws an ended owner after the restart. A `ForeignHolder`
    /// first asks `superseded` whether the holder is a successor's pair enrolled after step 1, and maps to
    /// `Check::Deposed` when it is. The reread record must then pass step 1's checks under the step-1 shard record and
    /// still enroll the own pair (`Local::Unenrolled` or `Local::Altered`, no flip), and the Report is judged again. A
    /// Report over `N_reg` that the judging record's pairs with the own pair account for maps to `Check::Unobserved`.
    /// A failed reread is `Check::Records`; a failed shard read in `superseded` shows no successor and keeps the
    /// Report's refusal with its flip, which stale-request admission bounds. The pair argument holds the shard record
    /// step 1 read and the `(g, owner, E)` the Report was taken under: the step-1 target for Report #1 and the bumped
    /// target for Report #2. After the volume and enrollment checks, a recorded foreign holder that the holder resolver
    /// validates returns the lineage arm's preempt when [`LineagePreempt::resolve_counted`], over the same census,
    /// admits it among the pairs the reread record records for other hosts, and refuses as `RecordedHolder` for a pair
    /// recorded for this host: recovery retains this volume for the fresh-host attach. After those checks, a Report
    /// that `unheld_among_recorded` accepts over the reread record's pairs refuses as `Unheld` (NO-HOLDER-HOLD).
    /// After a clean or refused Report, the reread record must pass step 1's checks. `Ok(None)` admits the own pair as
    /// the holder.
    fn admit<S: Store, L: WatermarkLog>(
        &self,
        client: &mut Client<S, L>,
        report: &Report<'_>,
        own: Pair,
        volume: &mut VolumeRecord,
        (shard, tenure): (&ShardRecord, Target),
        refused: fn(NotSole) -> Check,
    ) -> Result<Option<LineagePreempt>, Check> {
        let census = |volume: &VolumeRecord| {
            report.census(own, |pair| {
                volume.recorded().any(|recorded| recorded == pair)
                    || volume.ended_registrant(report.entries, pair)
            })
        };
        let unparsed = |refusal: NotSole| {
            if refusal == NotSole::Unreadable && report.regctl > self.bounds.registrant_max() {
                Check::Unobserved
            } else {
                refused(refusal)
            }
        };
        let refusal = match report.verdict(
            &census(volume),
            own,
            Some(volume.admitted(report.entries)),
            &self.bounds,
        ) {
            Ok(()) => None,
            Err(
                refusal @ (NotSole::Excess
                | NotSole::ForeignHolder
                | NotSole::ForeignRegistrant
                | NotSole::ReservationType
                | NotSole::NotHolder),
            ) => Some(refusal),
            Err(refusal) => return Err(unparsed(refusal)),
        };
        *volume = client
            .read::<VolumeRecord>(Key::Volume(self.holder.volume))
            .map_err(Check::Records)?
            .value()
            .clone();
        match refusal {
            None if volume.ended(self.holder.host) => return Err(Check::Local(Local::Ended)),
            Some(NotSole::ForeignHolder) if self.superseded(client, report, volume, tenure) => {
                return Err(Check::Deposed);
            }
            _ => {}
        }
        self.judge(shard, volume)?;
        enrolled(&self.holder, volume, own).map_err(Check::Local)?;
        let census = census(volume);
        if refusal == Some(NotSole::ForeignHolder)
            && crate::storage::held_by_recorded(
                report,
                &census,
                volume.recorded(),
                own,
                &self.bounds,
            )
        {
            #[cfg(test)]
            if tests::planted(tests::Plant::NoLineage) {
                return Err(Check::RecordedHolder);
            }
            return LineagePreempt::resolve_counted(
                report,
                &census,
                volume.recorded_beside(self.holder.host),
                own,
                &self.bounds,
            )
            .map(Some)
            .map_err(|_| Check::RecordedHolder);
        }
        if crate::storage::unheld_among_recorded(report, &census, own, &self.bounds) {
            return Err(Check::Unheld);
        }
        report
            .verdict(
                &census,
                own,
                Some(volume.admitted(report.entries)),
                &self.bounds,
            )
            .map(|()| None)
            .map_err(unparsed)
    }

    /// DEPOSE-ONLY-BY-SUCCESSOR: the shard record establishes ownership and the volume record's enrollment identifies
    /// the owner's pair. A shard reread at a later `(g, E)` than `tenure`, the tenure the Report was taken under, whose
    /// owner's enrolled pair in `volume`, the record `admit` reread after the Report, is the Report's one holder shows
    /// a successor; a failed shard read shows none.
    fn superseded<S: Store, L: WatermarkLog>(
        &self,
        client: &mut Client<S, L>,
        report: &Report<'_>,
        volume: &VolumeRecord,
        tenure: Target,
    ) -> bool {
        let Holding::One(holder) = report.holding(&self.bounds) else {
            return false;
        };
        client
            .read::<ShardRecord>(Key::Shard(self.shard))
            .is_ok_and(|read| {
                let later = read.value();
                (later.generation, later.attempts) > (tenure.generation, tenure.attempts)
                    && volume.enrolled(later.owner) == Some(holder)
            })
    }
}

/// Reads the shard record of `shard` and returns it when it names `session`'s `(g, owner, E)` and `volume` as its
/// active volume; `Ok(None)` for a record that names another tenure or another active volume. The result shows the
/// record at this read only.
///
/// # Errors
///
/// The read's [`StoreError`].
pub(crate) fn named_tenure<S: Store, L: WatermarkLog>(
    client: &mut Client<S, L>,
    shard: Shard,
    volume: crate::failover::records::VolumeId,
    session: &Session,
) -> Result<Option<ShardRecord>, StoreError> {
    let read = client.read::<ShardRecord>(Key::Shard(shard))?;
    let record = *read.value();
    Ok((Target::of(&record) == session.target() && record.active == volume).then_some(record))
}

pub(crate) fn exhausted(shard: &ShardRecord) -> Result<(), SessionRefusal> {
    if shard.generation.get() == u64::from(u32::MAX) {
        return Err(SessionRefusal::GenerationExhausted);
    }
    if shard.attempts >= ATTEMPTS_MAX {
        return Err(SessionRefusal::AttemptsExhausted);
    }
    Ok(())
}

/// The preempt a restart issues after its acknowledged bump: the self preempt, or the lineage arm's preempt of a
/// recorded holder, after a Register when Report #1 listed no record of the own pair.
enum Fence {
    Own(SelfPreempt),
    Lineage {
        preempt: LineagePreempt,
        registered: bool,
    },
}

/// The `(g, owner, E)` a bump error leaves this host knowing. The client returns [`StoreError::Log`] and
/// [`StoreError::Regression`] only after the store committed the bump, so they name the bumped `E`; every other error
/// names the read's `E`. After [`StoreError::Unknown`] the record holds that `E` or `E + 1`, and the issued bump may
/// still commit after the refusal returns (SERIAL-ISSUE).
pub(crate) fn bump_target(error: &StoreError, read: Target) -> Target {
    let committed = matches!(error, StoreError::Log | StoreError::Regression(_));
    Target {
        attempts: read.attempts + u32::from(committed),
        ..read
    }
}

pub(crate) fn parse<'e>(
    limits: ReservationLimits,
    bytes: &[u8],
    entries: &'e mut [Registrant],
) -> Result<Report<'e>, NotSole> {
    parse_extended_report(bytes, limits, 0, entries).map_err(|error| error.refusal())
}

/// What a restart refusal asks of the records. One classifier keeps the flip request and the recovery hint disjoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// The refusal rests on observed evidence or exhausted counters, so it requests the flip.
    Flip,
    /// DEVICE-FAILURE-HOLD: none of these refusals shows volume loss, so each keeps the retained volume with a
    /// recovery hint and no flip, a deposing status included (STATUS-IS-DEPOSITION). The rerun's Report #1 judges the
    /// holder.
    Hold,
    /// HOST-LOSS-KEEPS-VOLUME: host-local state, a failed read, a deposition, or a step-1 record this host starts no
    /// tenure from (`E = 0`, a suffix-only history) requests nothing and carries no hint.
    Neither,
}

pub(crate) fn disposition(check: &Check) -> Disposition {
    match check {
        Check::Volume(_) | Check::Exhausted(_) | Check::Local(Local::Retained) => Disposition::Flip,
        Check::NotHolding(refusal) | Check::NotSole(refusal) if refusal.observed() => {
            Disposition::Flip
        }
        Check::NotHolding(_)
        | Check::NotSole(_)
        | Check::RecordedHolder
        | Check::Lineage(_)
        | Check::Unheld
        | Check::Unobserved
        | Check::Driver(_)
        | Check::Coverage(_)
        | Check::Ready(_)
        | Check::HostId(_)
        | Check::FirstReport(_)
        | Check::Bump(_)
        | Check::Preempt(_)
        | Check::SecondReport(_) => Disposition::Hold,
        Check::Records(_) | Check::Deposed | Check::Fresh | Check::SuffixOnly | Check::Local(_) => {
            Disposition::Neither
        }
    }
}

impl Refused {
    /// `target` is the `(g, owner, E)` this host knows the shard record to hold.
    fn at(check: Check, target: Target) -> Self {
        let (flip, recovery) = match disposition(&check) {
            Disposition::Flip => (Some(target), None),
            Disposition::Hold => (None, Some(target)),
            Disposition::Neither => (None, None),
        };
        Self {
            check,
            flip,
            recovery,
        }
    }
}

/// Step 2: the local record of `source`, bound to `holder` and enrolled in `volume`.
pub(crate) fn bound(
    holder: &Holder,
    source: &impl LocalSource,
    volume: &VolumeRecord,
) -> Result<Pair, Local> {
    let record = source.local()?;
    if !holder.binds(record.binding()) {
        return Err(Local::Binding);
    }
    enrolled(holder, volume, record.pair())
}

/// The pair `volume` enrolls for the holder's live attach when it is `pair`. INSTANCE-BOUND: an entry for that attach
/// that binds an instance other than `holder.instance` refuses `Binding`, so a host whose attach another instance
/// made takes no tenure from it; an entry that binds none passes.
pub(crate) fn enrolled(holder: &Holder, volume: &VolumeRecord, pair: Pair) -> Result<Pair, Local> {
    if volume
        .live(holder.host)
        .and_then(|live| volume.event(live))
        .and_then(|entry| entry.instance)
        .is_some_and(|bound| bound != holder.instance)
    {
        return Err(Local::Binding);
    }
    match volume.enrolled(holder.host) {
        None => Err(Local::Unenrolled),
        Some(enrolled) if enrolled != pair => Err(Local::Altered),
        Some(enrolled) => Ok(enrolled),
    }
}

#[cfg(test)]
#[path = "restart_lineage_tests.rs"]
mod lineage_tests;
#[cfg(test)]
#[path = "restart_tests.rs"]
pub(crate) mod tests;
