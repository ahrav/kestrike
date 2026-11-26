//! The reconciler's store writes: the volume record before its attach, the attach event before the attach request,
//! the shard record with its coverage pages, the spare, and the retired state after the flip or the spare's
//! removal; the gated generation flips: the flip to a replacement after actual volume loss ([`Reconciler::flip`])
//! and the flip that serves a host's retirement request under an operator's release ([`Reconciler::flip_for`]);
//! and the gated standby writes on the active volume: a standby's attach event before its attach
//! request ([`Reconciler::record_standby`]), its pair's enrollment before its Register ([`enroll_standby`]), the
//! reservation of the shard's slot in its AZ's standby census ([`Reconciler::reserve`], [`Reconciler::release`]),
//! the shard record's designation of the enrolled host as its standby ([`Reconciler::designate`]), and the
//! replacement receipt of an actual volume loss with the provider create it records ([`Reconciler::replacement`],
//! [`Reconciler::create_replacement`], [`Reconciler::abandon`]), whose correlated hold only the operator's
//! [`Reconciler::release_hold`] releases; and the gated steps that end an attach and free its slot: the end of a
//! third host's attach ([`Reconciler::end_attach`]) and the gone mark after two settled listings
//! ([`Reconciler::release_attach`]), between which [`Reconciler::detachable`] reads the detach witness outside the
//! gate, and after which [`Reconciler::relisted`] reads, outside the gate, the detach witness of a gone entry whose
//! instance lists again.
//!
//! - END-RECORDED-FIRST: the end write precedes every other effect on the attach it ends. [`Reconciler::end_attach`]
//!   ends only an attach of a host the shard record names neither owner nor standby at `E > 0`, keeps its pair
//!   recorded, and rereads the shard record, reporting a designation that committed after a read made before the end.
//!   The owner drops the pair only after a Report shows its key absent ([`VolumeRecord::dropped`]), under the fence
//!   the record holds; the record's successor rule admits that drop because the prior record holds the entry ended.
//! - DETACH-AFTER-DROP: the control-plane detach of an enrolled attach follows the owner's drop of its pair: the
//!   caller detaches an ended entry only with a [`Detachable`], which a read showing the entry ended with no pair
//!   makes. The caller detaches an instance that lists again after its entry's gone mark only with a [`Relisted`],
//!   which a read showing the host's latest entry gone and no attach or ended entry bound to its instance makes
//!   (DETACH-RELISTED).
//! - GONE-AFTER-CLEAN-LISTINGS: [`Reconciler::release_attach`] records an ended entry gone only for two listings at
//!   least the settle time apart, both at least the settle time after the caller's last attach or detach request for
//!   the instance, both omitting it; a gone entry's host may attach again (ATTACH-AFTER-GONE). The caller meets the
//!   timing premises of [`Settle`]: every request that can land falls before `requested`, and an owner's poll judges
//!   its listing within the settle time.
//!
//! - ACKNOWLEDGED-ONLY: every witness this module returns, [`AttachRecorded`], [`StandbyRecorded`], [`Retired`]
//!   and the client's [`Flipped`], comes from the reconciler's own acknowledged write or from a read that shows the written value, so
//!   a timeout or a failure that may have committed yields [`StoreError::Unknown`] and no witness. A caller retries
//!   the same step, which reads the record again and finds the earlier write or makes it; a retry that finds another
//!   writer's value refuses. A condition refusal on a retry shows only that the record moved; the step's earlier
//!   write may have committed, and a later retry on a fresh read finds it.
//! - WRITE-ORDER: the caller obligation is to make the attach request only after it holds the volume's
//!   [`AttachRecorded`], and a detach or delete of a retiring volume only after it holds the volume's [`Retired`], so the volume record
//!   and its attach event exist before the attach and the retired state before the detach or delete. The new owner's
//!   first command needs the shard record the flip wrote.
//! - STANDBY-WRITE-ORDER: the caller makes a standby's attach request only after it holds the volume's
//!   [`StandbyRecorded`] or a volume record read that shows the host's live entry bound to the requested instance,
//!   and the standby issues Register only after [`enroll_standby`] returns, for the pair it
//!   returns, which its durable local record carries. The attach entry [`Reconciler::record_standby`] writes binds the
//!   host's verified instance, and the same write binds each live entry that binds none, so every judge of OWNER-EVENTS
//!   and of the listing, the owner's poll and restart and a running takeover, admits the standby's attachment from the
//!   record (BIND-AT-ATTACH); the entry's instance replaces the caller obligation to bind the host in every judge's
//!   peers, and every live entry the write leaves binds an instance. An owner poll whose volume record read fails
//!   admits only its caller's peers. The owner's caller keeps, from its last volume read, the peers its own instance
//!   lookup bound and, with its host, each instance an attach or ended entry bound, so that poll admits a standby
//!   whose entry binds its instance.
//!   A host takes a new entry only after its earlier one is gone (ATTACH-AFTER-GONE): a host that holds an ended entry,
//!   or whose latest event is a format-2 detach or force-detach, takes none. A full record sheds its lowest-numbered
//!   gone entry whose bound instance is absent from the same tick's complete listing and that `removable_gone`
//!   yields for the host. [`Reconciler::designate`] names the host standby only while the volume record enrolls a
//!   pair for its live attach, so the named standby's takeover finds its pair, and only at the `(g, owner, E)` of a
//!   census slot [`Reconciler::reserve`] wrote or read, so the designations of every reconciler stay under the AZ's
//!   cap (`failover::standbys`, POPULATION-CAP).
//! - LISTED-SPARE: the caller flips only to a spare whose control-plane attachment listing holds its standby's
//!   instance alone ([`check`] against that instance), and retires a spare whose listing shows another attachment
//!   with [`Reconciler::retire_spare`].
//! - RETIRED-IS-FINAL: [`Retired`] comes only from an acknowledged exact-version write of the shard record that
//!   names the volume in no role, made after the volume record shows retired. A shard write conditioned on an earlier
//!   version then fails, and a later [`Reconciler::add_spare`] reads the volume record after the shard record and
//!   refuses the retired volume, so no write names the volume again once its witness exists. Both retirement steps
//!   make that shard write for a volume already retired, which also clears a spare a racing write left naming it.
//! - ACTIVATION-FENCE: [`Reconciler::flip`] and [`Reconciler::flip_for`] raise the spare's volume version before
//!   they activate the spare, and
//!   both retirement steps read the volume record before the shard record, so a retired-state write conditioned on a
//!   read from before the flip fails, and one conditioned on a later read follows a shard read that shows the flip.
//! - SUPERSESSION-FENCE: a receipt of an earlier replacement that records a volume short of retired is superseded
//!   only while the shard record names that volume. To supersede a receipt whose recorded volume its shard read names,
//!   [`Reconciler::replacement`] reads the shard record, then the receipt, writes the unchanged shard record back over
//!   that read, and then writes the later receipt over its receipt read; when the shard write loses its version
//!   condition it starts again from fresh reads. [`Reconciler::flip`] and [`Reconciler::flip_for`], for the active
//!   volume they displace, and
//!   [`Reconciler::retire_spare`], for the spare it removes, read the receipt after the shard record and write a
//!   receipt that records that volume back unchanged before their shard write. A shard write that un-names the
//!   recorded volume between the replacement's shard read and its receipt write commits either before the
//!   replacement's shard write, which then fails its condition, or after it. In the second case its step read the
//!   shard record, and then the receipt, after the replacement's receipt read, so the step's receipt write, or an
//!   earlier write that moved the receipt off that volume, commits before the replacement's receipt write, which then
//!   fails its condition. Every other shard write of this module that un-names a volume follows a read of its record
//!   that shows it at or beyond [`VolumeState::Retired`].
//! - ONE-TENURE-PER-VOLUME: [`Reconciler::flip`] and [`Reconciler::flip_for`] raise the displaced active volume's
//!   record to at least active before the flip, and [`Reconciler::add_spare`] and both flip steps require the spare
//!   they name or activate unused, so a
//!   volume that held a tenure is never named again (`RetiredVolumeNeverReturns`). [`Reconciler::create_shard`]
//!   relies on its caller to name a newly provisioned volume active. [`Reconciler`] flips only through those two
//!   steps, which share one unused-spare check, and [`Reconciler::retire_spare`] admits only a spare's removal.
//! - FLIP-ONCE-PER-TENURE: [`Reconciler::flip`] flips the shard from the `(g, owner, E)` its caller names, and
//!   [`Reconciler::flip_for`] writes each flip over a read its request admits, rereading after a lost version
//!   condition. A retry after an unknown outcome therefore repeats the same flip, refuses on a record that moved
//!   within `g`, or finds the shard past `g`
//!   (`OneActiveVolumePerShard`, `OneFlipPerGeneration`). A recovering request admits `E + 1` under the
//!   STALE-REQUEST-REFUSED exception stated in [`retire`](crate::failover::retire).
//! - Every write is an exact-version compare-and-swap or a conditional create through the store client, raising the
//!   record's version. Shard creation requires no spare, no named checkpoint, no cut, no ancestry and `E = 0`, the flip clears `ck`,
//!   and every other reconciler shard write copies the read `ck` under an exact-version compare-and-swap, so no
//!   reconciler write changes `ck` to a slot.
//!
//! [`Reconciler`] makes no check of which principal its client runs under. The deployment gives the long-running
//! reconciler principal no write on any coverage page, so its client's page creates are denied, and runs
//! [`Reconciler::create_shard`] under the shard-provisioning principal, which creates the empty pages.
//!
//! [`check`]: crate::failover::attachments::check

use crate::failover::admission::AdmissionError;
use crate::failover::attachments::{InstanceId, Peer};
use crate::failover::bounds::Bounds;
use crate::failover::evidence::Pair;
use crate::failover::flip::flipped;
use crate::failover::identity::Key as ReservationKey;
use crate::failover::loss::{
    CreateError, Decision, Health, Phase, Provider, Receipt, Request, decide,
};
use crate::failover::poll::Holder;
use crate::failover::record::LocalRecord;
use crate::failover::records::{
    AttachmentEvent, CoveragePage, CreationSource, Enrollment, EventKind, Host, Layout,
    LayoutRefusal, Lineage, MAX_EVENTS, ShardRecord, VolumeId, VolumeRecord, VolumeState,
    attachment_key,
};
use crate::failover::report::HostReport;
use crate::failover::retire::{Retirement, Role, Target};
use crate::failover::standbys::{
    Attach, Census, Entry, Population, Refusal as PopulationRefusal, Slot, Zone, standby_ended,
};
use crate::net::ownership::{ActivatedEpoch, Shard};
use crate::storage::store::{
    Alarm, Client, Flipped, Key, Read, Refusal, Store, StoreError, Tally, Tracked, WatermarkLog,
};

const FLIP_ROUNDS: usize = 4;
const REPLACEMENT_ROUNDS: usize = 4;

/// The volume record of `volume` held `host`'s one attach event, with the volume fresh, when the witness was made.
#[derive(Debug, PartialEq, Eq)]
pub struct AttachRecorded {
    volume: VolumeId,
    host: Host,
}

/// The volume record of the shard's active volume held `host`'s live attach event when the witness was made.
#[derive(Debug, PartialEq, Eq)]
pub struct StandbyRecorded {
    volume: VolumeId,
    host: Host,
}

/// The reconciler makes this witness of `host`'s entry `seq` of `volume` after its own acknowledged end write, or
/// after a volume record read shows the entry ended (END-RECORDED-FIRST).
#[derive(Debug, PartialEq, Eq)]
pub struct AttachEnded {
    volume: VolumeId,
    host: Host,
    seq: u32,
    named: bool,
}

impl AttachEnded {
    /// Whether the shard record read after the end names the host owner or standby, as after a designation or a
    /// takeover computed before the end that committed before that read. A role that commits after the read shows
    /// on a later survey: the host's takeover refuses `Local(Ended)`, and `standbys::need_of` counts a named standby
    /// with no live attach lost. Permission to detach comes from [`Detachable`] alone.
    ///
    /// A caller that reads `true` stops reclaiming this attach and replans from fresh records.
    pub fn named(&self) -> bool {
        self.named
    }
}

/// DETACH-AFTER-DROP: a volume record read showed `host`'s entry `seq` of `volume`, bound to `instance`, ended with
/// no recorded pair. The control-plane detach of that attachment takes this witness, and
/// [`Reconciler::release_attach`] marks the entry `seq` alone gone. Once that entry is gone, the host may attach the
/// same `instance` again under a later number, so the caller rereads the volume record before the detach request
/// and proceeds only while the host's latest entry is still `seq`, ended with no pair. That reread orders the request
/// after the pair drop. After the reread, an authorized detach can still await dispatch or remain in flight, so the
/// caller serializes each such detach across all reconcilers and restarts with the gone mark of `seq` and the next
/// attach of `instance`, and sends the detach only if it establishes that order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detachable {
    volume: VolumeId,
    host: Host,
    seq: u32,
    instance: InstanceId,
}

impl Detachable {
    pub fn volume(&self) -> VolumeId {
        self.volume
    }

    pub fn host(&self) -> Host {
        self.host
    }

    pub fn seq(&self) -> u32 {
        self.seq
    }

    pub fn instance(&self) -> InstanceId {
        self.instance
    }
}

#[cfg(test)]
impl Detachable {
    pub(crate) fn forged(volume: VolumeId, host: Host, seq: u32, instance: InstanceId) -> Self {
        Self {
            volume,
            host,
            seq,
            instance,
        }
    }
}

/// DETACH-RELISTED: a volume record read showed `host`'s latest entry `seq` of `volume` gone and bound to
/// `instance`, with no attach or ended entry of the record bound to that instance. The control-plane detach of an
/// attachment of `instance` that landed after the gone mark takes this witness. The caller rereads the witness before
/// each detach request, so the request follows a read in which no entry of the record binds the instance live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relisted {
    volume: VolumeId,
    host: Host,
    seq: u32,
    instance: InstanceId,
}

impl Relisted {
    pub fn volume(&self) -> VolumeId {
        self.volume
    }

    pub fn host(&self) -> Host {
        self.host
    }

    pub fn seq(&self) -> u32 {
        self.seq
    }

    pub fn instance(&self) -> InstanceId {
        self.instance
    }
}

/// One complete control-plane attachment listing of the witnessed volume, with `at`, the caller's clock reading
/// taken before the listing request is sent ([`Settle`]); `instances` holds every record the listing returned. A
/// listing shows an instance absent only when every record it returned is a canonical instance ID other than that
/// instance.
#[derive(Debug, Clone, Copy)]
pub struct Listing<'a> {
    pub at: u64,
    pub instances: &'a [String],
}

/// An unparseable record may name any instance, so a listing shows `instance` absent only when it identifies every
/// instance it lists.
fn omits(listing: &[String], instance: Option<InstanceId>) -> bool {
    listing
        .iter()
        .all(|listed| InstanceId::new(listed).is_some_and(|id| Some(id) != instance))
}

/// The longest span from the request of an attachment listing to the volume read of the owner's poll that judges
/// that listing. [`Periods::new`](crate::host::duties::Periods::new) admits only periods whose span stays below it,
/// and a settle time covers that span only above it ([`Settle::settle`]).
pub const LISTING_HOLD_US: u64 = 120_000_000;

/// The timing [`Reconciler::release_attach`] requires of two listings. Every reading comes from one clock of one run
/// of the calling process, a clock that never steps back and counts time in suspend, such as `CLOCK_BOOTTIME`, in
/// microseconds. A caller that loses its run's readings, as at a restart, takes a fresh request time and fresh
/// listings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settle {
    /// Read after the last attach or detach request for the instance on this volume returned or reached its
    /// deadline. The caller accounts for every request still in flight from any reconciler, including pre-restart
    /// requests, and every request a sender can still dispatch under authorization from a reread or
    /// [`StandbyRecorded`].
    pub requested: u64,
    /// The settle time, above zero. It covers one listing call's duration, the control plane's consistency lag, the
    /// landing delay of a request made before `requested`, and the span an owner's poll holds a listing before it
    /// reads the volume record, so a poll that listed the instance judges it against a record that still holds the
    /// entry ended. The periods an owner's duties admit keep that span below [`LISTING_HOLD_US`] while each call
    /// meets its deadline and the owner's lane thread and owner thread run, so the settle time covers it only above
    /// that constant. The caller chooses the settle time, and [`Reconciler::release_attach`] checks the readings
    /// against it.
    pub settle: u64,
}

/// What [`Reconciler::record_standby`] binds and judges beside the host it records: the host's verified instance,
/// which its new entry binds (BIND-AT-ATTACH); the verified instance of each live host whose entry binds none, the
/// owner's first attach included, which the same write binds; and the control plane's attachment listing of the
/// volume. The caller passes `Some` only for a complete listing: the rows of one successful attachment listing
/// call for this volume made in this tick, as the control plane returned them. A listing that shows the host's
/// instance refuses the new entry; with `None`, the caller establishes that absence.
#[derive(Debug, Clone, Copy)]
pub struct Binding<'a> {
    pub instance: InstanceId,
    pub unbound: &'a [Peer],
    pub listing: Option<&'a [String]>,
}

/// STANDBY-GATE: a `StandbyGate` authorizes the automated writes [`Reconciler::record_standby`],
/// [`enroll_standby`], [`Reconciler::reserve`], [`Reconciler::release`], [`Reconciler::designate`],
/// [`Reconciler::end_attach`], [`Reconciler::release_attach`], [`Reconciler::replacement`],
/// [`Reconciler::create_replacement`], [`Reconciler::create_attempt`], [`Reconciler::latch`],
/// [`Reconciler::abandon`], [`Reconciler::flip`] and [`Reconciler::flip_to`], and the owner's planned transfer
/// (`Client::transfer`), which the gate's holder issues after its withdrawal. An [`OperatorRelease`] authorizes the
/// operator steps [`Reconciler::release_hold`] and [`Reconciler::flip_for`]. Only crate tests can authorize a
/// `Reconciler` flip because `StandbyGate` and `OperatorRelease` have test-only constructors.
/// [`Reconciler::flip`] activates a replacement after actual volume loss. Its caller invokes it only under the
/// replacement receipt started on that loss: the gate authorizes the step, and the receipt records the loss
/// decision. [`Reconciler::flip_for`] serves a host's retirement request under an operator's release: the request
/// alone leaves the shard on its active volume (HOST-LOSS-KEEPS-VOLUME).
///
/// ```compile_fail,E0423
/// # use kestrike::failover::reconcile::StandbyGate;
/// let forged = StandbyGate(());
/// ```
///
/// ```compile_fail,E0599
/// # use kestrike::failover::reconcile::StandbyGate;
/// let qualified = StandbyGate::qualified();
/// ```
#[derive(Debug)]
pub struct StandbyGate(());

impl StandbyGate {
    /// Public visibility makes `#[cfg(test)]` the access boundary for the external `compile_fail` doctest on
    /// [`StandbyGate`]. Removing the attribute lets the constructor call compile, which fails the doctest.
    #[cfg(test)]
    pub fn qualified() -> Self {
        Self(())
    }
}

/// An operator's authorization, after diagnosis, to release a correlated-impairment hold
/// ([`Reconciler::release_hold`]) or to serve a host's retirement request with a generation flip
/// ([`Reconciler::flip_for`]), distinct from the [`StandbyGate`] of the automated writes; its constructor is
/// restricted to test builds.
///
/// ```compile_fail,E0423
/// # use kestrike::failover::reconcile::OperatorRelease;
/// let forged = OperatorRelease(());
/// ```
///
/// ```compile_fail,E0599
/// # use kestrike::failover::reconcile::OperatorRelease;
/// let diagnosed = OperatorRelease::diagnosed();
/// ```
pub struct OperatorRelease(());

impl OperatorRelease {
    /// Public visibility makes `#[cfg(test)]` the access boundary for the external `compile_fail` doctest on
    /// [`OperatorRelease`]. Removing the attribute lets the constructor call compile, which fails the doctest.
    #[cfg(test)]
    pub fn diagnosed() -> Self {
        Self(())
    }
}

/// Why [`enroll_standby`] refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandbyRefusal {
    /// A read failed: the volume record, the shard record or coverage page 0 before the enrollment write, or the
    /// shard record or page 0 after that write commits.
    Records(StoreError),
    /// The shard record does not name the holder's volume active under another owner at `E > 0`, or the volume
    /// record fails `serving`, before the enrollment write or after it commits.
    Tenure,
    /// `persist` failed.
    Persist(AdmissionError),
    /// Before `persist`, the holder's live attach entry binds an instance other than the holder's. After `persist`,
    /// the persisted record's instance or volume differs from the corresponding value in the holder's binding.
    Binding,
    /// The volume record refuses the pair. `Unattached` and `Full` precede `persist`. For a live attach on an
    /// unenrolled host, `Key` also precedes `persist` when [`VolumeRecord::enrollment_key`] returns `None`, and
    /// `Shared` when a recorded pair holds that key.
    Enrollment(Enrollment),
    /// The enrollment write failed or returned no acknowledgment, after which it may have committed.
    Write(StoreError),
}

/// Enrolls the standby `holder`'s pair for its live attach in the record of the shard's active volume, and returns
/// that pair. It reads the volume record, then the shard record, refuses unless they pass STANDBY-TENURE and
/// `serving`, refuses before `persist` when the host has no live attach or the record holds [`Bounds::pair_cap`]
/// pairs and none for that attach, then calls `persist` with the key of the pair already recorded for that attach, or
/// else the key of that attach ([`VolumeRecord::attach_key`], KEY-PER-ATTACH), so a recorded pair replays under the
/// key it carries. `persist` makes the standby's local record durable under that key
/// and keeps its pair across retries of the same attachment. The step then writes the enrollment by an exact-version
/// replace of the read volume record, which refuses a pair under any other key with no write. A shard record read after that write must still pass STANDBY-TENURE and `serving`, or the step
/// refuses `Tenure` with the enrollment written. A retry that finds the pair enrolled writes nothing. `bounds`
/// carries the owner's `N_reg`.
///
/// # Errors
///
/// In check order: `Records`, `Tenure`, `Enrollment(Unattached)`, `Enrollment(Full)`, `Enrollment(Key)` for an
/// unenrolled host whose key lookup returns `None`, `Enrollment(Shared)` for an unenrolled host whose derived key a
/// recorded pair holds, `Persist`, `Binding`, the
/// other `Enrollment` refusals of [`VolumeRecord::enroll`], `Write`, and, with the enrollment written, `Records`
/// and `Tenure` from the shard record and page 0 read after the write.
/// `Binding` for a live attach entry bound to an instance other than the holder's follows `Enrollment(Unattached)`
/// and precedes `Enrollment(Full)` and `persist`.
pub fn enroll_standby<S: Store, L: WatermarkLog>(
    _gate: &StandbyGate,
    shard: Shard,
    holder: &Holder,
    bounds: &Bounds,
    client: &mut Client<S, L>,
    persist: impl FnOnce(ReservationKey) -> Result<LocalRecord, AdmissionError>,
) -> Result<Pair, StandbyRefusal> {
    let read = client
        .read::<VolumeRecord>(Key::Volume(holder.volume))
        .map_err(StandbyRefusal::Records)?;
    let held = read.value();
    if !standby_serving(client, shard, held, holder.host).map_err(StandbyRefusal::Records)? {
        return Err(StandbyRefusal::Tenure);
    }
    let live = held
        .live(holder.host)
        .ok_or(StandbyRefusal::Enrollment(Enrollment::Unattached))?;
    if held
        .event(live)
        .and_then(|entry| entry.instance)
        .is_some_and(|bound| bound != holder.instance)
    {
        return Err(StandbyRefusal::Binding);
    }
    let recorded = held.enrolled(holder.host);
    if recorded.is_none() && held.pairs.len() >= bounds.pair_cap() {
        return Err(StandbyRefusal::Enrollment(Enrollment::Full));
    }
    let key = held
        .enrollment_key(holder.host)
        .ok_or(StandbyRefusal::Enrollment(Enrollment::Key))?;
    if recorded.is_none() && held.pairs.iter().any(|pair| pair.pair.key == key) {
        return Err(StandbyRefusal::Enrollment(Enrollment::Shared));
    }
    let record = persist(key).map_err(StandbyRefusal::Persist)?;
    if !holder.binds(record.binding()) {
        return Err(StandbyRefusal::Binding);
    }
    let pair = record.pair();
    if let Some(next) = read
        .value()
        .enroll(holder.host, pair, bounds)
        .map_err(StandbyRefusal::Enrollment)?
    {
        let written = client.replace(&read, next).map_err(StandbyRefusal::Write)?;
        if !standby_serving(client, shard, written.value(), holder.host)
            .map_err(StandbyRefusal::Records)?
        {
            return Err(StandbyRefusal::Tenure);
        }
    }
    Ok(pair)
}

/// The volume record of `volume` shows it retired or deleted, and the shard record names it in no role and never
/// will again (RETIRED-IS-FINAL). The volume may already be deleted.
#[derive(Debug, PartialEq, Eq)]
pub struct Retired {
    shard: Shard,
    volume: VolumeId,
}

/// Why a reconciler step refused or failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileError {
    Store(StoreError),
    /// A record holds another value than the step writes or requires: another creation, layout, attachment event,
    /// state or spare; a layout [`Layout::check_floor`] refuses; a creation source other than provisioning, a lineage,
    /// a modification record, a compacted attachment history, a recorded pair or a nonzero fence; a shard record of
    /// another namespace than the one [`Reconciler::create_shard`] creates; a shard record that names the volume
    /// active or another spare; a standby attach that [`Reconciler::record_standby`] refuses; when [`Reconciler::create_shard`]
    /// finds the shard record absent, a coverage page past `Version::FIRST`, one that fails decoding, or one holding a
    /// nonzero fence, `saturated: true` or entries; a spare's removal requested for the active role; a designation
    /// whose census slot, standby tenure, serving volume or enrolled pair [`Reconciler::designate`] refuses; a
    /// replacement receipt of another layout than the caller's ([`Reconciler::replacement`]); or an attempt counter at
    /// `u32::MAX`.
    Conflict,
    /// The shard record holds another `(g, owner, E)` than the step names; or a replacement receipt names another
    /// replacement or attempt than the step's, moved off the step's read, or names a generation the shard record
    /// already holds ([`Reconciler::release_hold`], [`Reconciler::create_replacement`], [`Reconciler::abandon`]).
    Stale,
    Retry,
    /// The shard record names the volume active, or spare before its removal, so it retires only after the flip or
    /// the spare's removal.
    Named,
    /// The shard record to create names a spare, a checkpoint, a cut, an ancestry or an attempt.
    Unclean,
    /// `Layout::check_floor` rejects the layout `provision` was asked to record, or the layout of a replacement
    /// receipt to start or to create.
    Layout(LayoutRefusal),
    /// The standby population refuses the candidate or the slot.
    Population(PopulationRefusal),
    /// The replacement receipt is held for an operator (CORRELATED-HOLD).
    Held,
    /// The active volume is lost at the last generation a replacement can activate, so no replacement exists and an
    /// operator diagnoses the shard.
    Exhausted,
    /// The provider's create returned no volume; a `Failed` attempt raised the receipt's attempt.
    Create(CreateError),
}

impl From<StoreError> for ReconcileError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// The outcome of a flip of one tenure.
#[derive(Debug, PartialEq, Eq)]
pub enum Flip {
    /// The reconciler's own acknowledged flip.
    Flipped(Flipped),
    /// The shard record is past the tenure's generation; a flip of it committed earlier, by this reconciler or
    /// another.
    Past,
}

/// The reconciler's record writes over one store client, whose principal the caller chooses: the shard-provisioning
/// principal for [`Reconciler::create_shard`] and the long-running reconciler principal for every other step.
/// Each step takes the shard and the volume it acts on as separate inputs; the caller supplies a volume the shard
/// owns, since the volume record names no shard.
pub struct Reconciler<S, L> {
    client: Client<S, L>,
    /// `Census::decode_like` uses this census, retained from an earlier read or write, as its decoding memo.
    census: Option<Census>,
}

impl<S: Store, L: WatermarkLog> Reconciler<S, L> {
    pub fn new(client: Client<S, L>) -> Self {
        let census = None;
        Self { client, census }
    }

    /// The store client's watermark alarm and its tallied outcomes, which the reconciler status reports.
    pub(crate) fn store_state(&self) -> (Alarm, Tally) {
        (self.client.alarm(), self.client.outcomes())
    }

    pub(crate) fn read<R: Tracked>(&mut self, key: Key) -> Result<Read<R>, StoreError> {
        self.client.read(key)
    }

    /// The reconciler supplies its cached census to `Client::read_census` as the decoding memo and replaces the cache
    /// only on success.
    pub(crate) fn read_census(&mut self, zone: Zone) -> Result<Read<Census>, StoreError> {
        let read = self.client.read_census(Key::Standbys(zone), &self.census)?;
        self.census = Some(read.value().clone());
        Ok(read)
    }

    /// Creates the shard's `B` empty coverage pages and then its shard record, each by conditional create. The
    /// caller runs it under the shard-provisioning principal; the long-running reconciler principal is denied the
    /// first page create. The caller names a newly provisioned volume active, whose record the provisioning
    /// principal cannot read. A call that finds the shard record returns it without a page write, so a retry after an
    /// unknown outcome makes only what the first call left absent.
    ///
    /// # Errors
    ///
    /// [`ReconcileError::Unclean`] before any request for a record that names a spare, a standby, a checkpoint, a cut,
    /// an ancestry or `E > 0`, so every spare enters through [`Reconciler::add_spare`];
    /// the store client's errors; [`ReconcileError::Conflict`] for a shard record of another shard, generation,
    /// active volume, owner, `B`, `C_page` or namespace, or a coverage page that is not empty at its first version
    /// while the shard record is absent.
    /// Spare bookkeeping and the owner's `E`, `ck`, cut and ancestry may differ.
    pub fn create_shard(
        &mut self,
        record: ShardRecord,
    ) -> Result<Read<ShardRecord>, ReconcileError> {
        let unclean = record.spare.is_some()
            || record.standby.is_some()
            || record.checkpoint.is_some()
            || record.attempts != 0
            || record.cut != 0
            || !record.ancestry.as_slice().is_empty();
        if unclean {
            return Err(ReconcileError::Unclean);
        }
        let key = Key::Shard(record.shard);
        match self.client.read::<ShardRecord>(key) {
            Err(StoreError::Absent) => {}
            held => return created(held?, &record),
        }
        match self.client.create_shard(record) {
            Err(StoreError::Refused(Refusal::Condition)) => match self.client.read(key) {
                Err(StoreError::Absent) => Err(ReconcileError::Conflict),
                held => created(held?, &record),
            },
            done => Ok(done?),
        }
    }

    /// Creates the record of a newly provisioned `volume`, provisioning with no attachment event, before any attach
    /// of it. A retry finds the record it created; any other record under the key refuses.
    ///
    /// # Errors
    ///
    /// The store client's errors; [`ReconcileError::Conflict`] for an existing record of another value.
    /// `provision` returns [`ReconcileError::Layout`] before issuing any request when `Layout::check_floor` rejects `layout`.
    pub fn provision(
        &mut self,
        volume: VolumeId,
        layout: Layout,
    ) -> Result<Read<VolumeRecord>, ReconcileError> {
        layout.check_floor().map_err(ReconcileError::Layout)?;
        let record = VolumeRecord {
            volume,
            state: VolumeState::Provisioning,
            source: CreationSource::Provisioned,
            lineage: Lineage::None,
            modification: None,
            layout,
            next: 0,
            forced: false,
            fence: 0,
            pairs: Vec::new(),
            events: Vec::new(),
        };
        match self.client.create(Key::Volume(volume), record.clone()) {
            Err(StoreError::Refused(Refusal::Condition)) => {
                let held = self.client.read::<VolumeRecord>(Key::Volume(volume))?;
                (*held.value() == record)
                    .then_some(held)
                    .ok_or(ReconcileError::Conflict)
            }
            done => Ok(done?),
        }
    }

    /// Records the attach event of `host`, running a binary of era `era`, in the volume record and moves it to
    /// fresh, before the attach request. A volume takes one attach event for life. The record must be a provisioned
    /// one with no lineage and no modification record; a provisioning record with no event takes the event, and a
    /// fresh record that holds exactly this event, era included, returns its witness.
    ///
    /// # Errors
    ///
    /// The store client's errors; [`ReconcileError::Conflict`] for a record in any other state, with another event,
    /// another source or lineage, a modification record, a compacted attachment history, a recorded pair, a nonzero
    /// fence, or a layout [`Layout::check_floor`] refuses.
    pub fn record_attach(
        &mut self,
        volume: VolumeId,
        host: Host,
        era: u32,
    ) -> Result<AttachRecorded, ReconcileError> {
        let read = self.client.read::<VolumeRecord>(Key::Volume(volume))?;
        let attach = AttachmentEvent {
            seq: 0,
            kind: EventKind::Attach,
            host,
            era,
            instance: None,
        };
        let held = read.value();
        match (held.state, held.events.as_slice()) {
            (VolumeState::Fresh, [event]) if *event == attach && provisioned(held) => {
                Ok(AttachRecorded { volume, host })
            }
            (VolumeState::Provisioning, []) if provisioned(held) => {
                let mut next = VolumeRecord {
                    state: VolumeState::Fresh,
                    ..held.clone()
                };
                next.push(EventKind::Attach, host, era);
                self.client.replace(&read, next)?;
                Ok(AttachRecorded { volume, host })
            }
            _ => Err(ReconcileError::Conflict),
        }
    }

    /// Appends the attach entry of standby `host` at era `era`, bound to `binding.instance`, to the record of the
    /// shard's active volume, before the standby's attach request (STANDBY-WRITE-ORDER), and binds in the same write
    /// the instance `binding.unbound` names for each live entry that binds none. A retry that finds the host's live
    /// entry at `era` bound to the same instance, on a record that still passes STANDBY-TENURE and `serving`, returns
    /// its witness with no write. When the record holds [`MAX_EVENTS`] entries, the write removes the lowest-numbered
    /// gone entry that `removable_gone` yields for `host` and whose instance is absent from the complete
    /// `binding.listing`; a gone entry with no instance stays. The write preserves live and ended entries.
    /// After the write, a shard record read must still pass STANDBY-TENURE and `serving`, or the step conflicts with
    /// the entry written. `bounds` carries the owner's `N_reg`.
    ///
    /// # Errors
    ///
    /// The store client's errors; [`ReconcileError::Conflict`] when the shard record fails STANDBY-TENURE, when the
    /// volume record fails the `serving` check, which requires a provisioned, unmodified fresh or active volume with
    /// the owner's pair recorded and coverage page 0 fenced in the shard record's generation, when `host`'s live entry
    /// differs in era or instance or binds none, when a retry's live entry does not read [`Attach::Live`], or when a
    /// new attach does not read [`Attach::Open`], at the first check `Closed::of` names: `host` holds an ended entry
    /// or its latest event is a detach or force-detach (ATTACH-AFTER-GONE), the record is at `MAX_ATTACHED` live
    /// attaches, or at `MAX_EVENTS` entries with no gone entry `removable_gone` yields, its next sequence number has
    /// no attachment key or a recorded pair holds that key, or its pairs and its live attaches that await enrollment
    /// reach [`Bounds::pair_cap`]: each recorded attach takes one pair at its enrollment, and [`enroll_standby`]
    /// refuses `Full`, leaving the attach recorded; when `binding.unbound` names no instance, or two different ones,
    /// for a live entry that binds none; when two attach or ended entries would bind one instance; when a supplied
    /// listing holds a row that is no instance ID or shows `binding.instance`; and, at `MAX_EVENTS` entries, when the
    /// listing is absent or leaves no gone entry removable. Each of these refusals precedes the write and writes
    /// nothing. The pre-write checks use only the current call's reads, so an earlier call whose write returned
    /// [`StoreError::Unknown`] stays unsettled until a later call's read shows its entry. After the write, a shard
    /// record that fails STANDBY-TENURE or `serving` conflicts, and a failed shard or page 0 read returns its store
    /// error; in both cases the volume record keeps the entry and the step returns no witness.
    #[expect(clippy::too_many_arguments)]
    pub fn record_standby(
        &mut self,
        _gate: &StandbyGate,
        shard: Shard,
        volume: VolumeId,
        host: Host,
        era: u32,
        bounds: &Bounds,
        binding: &Binding<'_>,
    ) -> Result<StandbyRecorded, ReconcileError> {
        let read = self.client.read::<VolumeRecord>(Key::Volume(volume))?;
        let held = read.value();
        if !standby_serving(&mut self.client, shard, held, host)? {
            return Err(ReconcileError::Conflict);
        }
        if let Some((_, latest)) = held
            .latest(host)
            .filter(|(_, event)| event.kind == EventKind::Attach)
        {
            return (latest.era == era
                && latest.instance == Some(binding.instance)
                && Attach::of(held, host, bounds) == Attach::Live)
                .then_some(StandbyRecorded { volume, host })
                .ok_or(ReconcileError::Conflict);
        }
        if Attach::of(held, host, bounds) != Attach::Open {
            return Err(ReconcileError::Conflict);
        }
        let next = standby_successor(held, host, era, binding).ok_or(ReconcileError::Conflict)?;
        let written = self.client.replace(&read, next)?;
        if !standby_serving(&mut self.client, shard, written.value(), host)? {
            return Err(ReconcileError::Conflict);
        }
        Ok(StandbyRecorded { volume, host })
    }

    /// `standby_ready` evaluates standby readiness against `volume`'s record as read at call time.
    pub(crate) fn standby_ready(
        &mut self,
        shard: Shard,
        volume: VolumeId,
        host: Host,
    ) -> Result<bool, StoreError> {
        let read = self.client.read::<VolumeRecord>(Key::Volume(volume))?;
        standby_serving(&mut self.client, shard, read.value(), host)
    }

    /// Ends `host`'s live attach of the shard's active volume: reads the shard record, then the volume record, and
    /// moves the host's live entry to ended by one exact-version replace, keeping its pair recorded, then reads the
    /// shard record again and reports in the witness whether it names the host (END-RECORDED-FIRST). The entry
    /// leaves the live count at that write. A retry that finds the host's latest entry ended returns the witness with
    /// no write, whatever roles the shard record names by then. The step uses the roles from its first shard read, so
    /// a designation or takeover that commits after that read can name the ended host; the reread reports one that
    /// committed before it. The end writes the volume record alone.
    ///
    /// A successful call ends only the attach identified by `seq`, even if `host` later reattaches to `volume`: a
    /// retry that finds a later entry for `host` returns [`ReconcileError::Conflict`] before writing.
    ///
    /// A live entry that binds no instance keeps its slot until a [`Reconciler::record_standby`] write binds it,
    /// because the detach and the gone mark check listings against the entry's instance. A live entry keeps its slot
    /// when its recorded pair's key differs from [`attachment_key`] of its number and is no spent key, an epoch-1 key of
    /// a number below `next` that no live attach holds: once such a pair dropped, a later attach could take its key
    /// (KEY-PER-ATTACH).
    ///
    /// The binding write records another host's attach, which needs a free live slot. At `MAX_ATTACHED` live
    /// attaches an unbound entry therefore keeps its slot until another live attach of the volume ends.
    ///
    /// # Errors
    ///
    /// The store client's errors, a lost version condition included, after which the caller retries on a fresh read;
    /// [`ReconcileError::Conflict`] with no write when the shard record holds `E = 0`, when the host's latest entry is
    /// neither live nor ended, or when its live entry is the owner's or the named standby's, binds no instance or
    /// carries a pair whose key differs from [`attachment_key`] of the entry's number and is no spent key.
    /// If the shard's active volume differs from `volume` or `host` has no latest entry matching `seq`, `end_attach`
    /// returns [`ReconcileError::Conflict`] before writing.
    pub fn end_attach(
        &mut self,
        _gate: &StandbyGate,
        shard: Shard,
        volume: VolumeId,
        host: Host,
        seq: u32,
    ) -> Result<AttachEnded, ReconcileError> {
        let record = self.client.read::<ShardRecord>(Key::Shard(shard))?;
        let tenure = record.value();
        if tenure.attempts == 0 || tenure.active != volume {
            return Err(ReconcileError::Conflict);
        }
        let read = self.client.read::<VolumeRecord>(Key::Volume(volume))?;
        let held = read.value();
        let (_, event) = held
            .latest(host)
            .filter(|&(latest, _)| latest == seq)
            .ok_or(ReconcileError::Conflict)?;
        match event.kind {
            EventKind::Attach => {
                if names(tenure, host) || end_ready(held, host).is_none() {
                    return Err(ReconcileError::Conflict);
                }
                let next = moved(held, seq, EventKind::Ended).ok_or(ReconcileError::Conflict)?;
                self.client.replace(&read, next)?;
            }
            EventKind::Ended => {}
            _ => return Err(ReconcileError::Conflict),
        }
        let after = self.client.read::<ShardRecord>(Key::Shard(shard))?;
        Ok(AttachEnded {
            volume,
            host,
            seq,
            named: names(after.value(), host),
        })
    }

    /// DETACH-AFTER-DROP: the witness a control-plane detach of `host`'s attachment of `volume` requires, from a read
    /// of the volume record that shows the host's latest entry ended, bound to an instance, with no pair recorded
    /// for it. An unenrolled attach passes at once. A caller can read the witness before it holds the gate; the
    /// detach call that takes the witness runs under [`StandbyGate`].
    ///
    /// # Errors
    ///
    /// The store client's errors; [`ReconcileError::Conflict`] when the host's latest entry is not ended, binds no
    /// instance, or still has its pair recorded.
    pub fn detachable(
        &mut self,
        volume: VolumeId,
        host: Host,
    ) -> Result<Detachable, ReconcileError> {
        let read = self.client.read::<VolumeRecord>(Key::Volume(volume))?;
        let (seq, instance) = detach_ready(read.value(), host).ok_or(ReconcileError::Conflict)?;
        Ok(Detachable {
            volume,
            host,
            seq,
            instance,
        })
    }

    /// DETACH-RELISTED: the witness a control-plane detach of `host`'s gone attachment of `volume` requires, from a
    /// read of the volume record that shows the host's latest entry gone and bound to an instance that no attach or
    /// ended entry of the record binds. The detach call that takes the witness runs under [`StandbyGate`].
    ///
    /// # Errors
    ///
    /// The store client's errors; [`ReconcileError::Conflict`] when the host's latest entry is not gone or binds no
    /// instance, or when an attach or ended entry of the record binds its instance.
    pub fn relisted(&mut self, volume: VolumeId, host: Host) -> Result<Relisted, ReconcileError> {
        let read = self.client.read::<VolumeRecord>(Key::Volume(volume))?;
        let (seq, instance) = relist_ready(read.value(), host).ok_or(ReconcileError::Conflict)?;
        Ok(Relisted {
            volume,
            host,
            seq,
            instance,
        })
    }

    /// Records the entry `witness` names gone by one exact-version replace, once two settled listings show its
    /// instance detached (GONE-AFTER-CLEAN-LISTINGS): the host's latest entry is still that entry, ended with no
    /// recorded pair; `listings` holds exactly two listings, in either order, at least `timing.settle` apart; the
    /// earlier listing falls at least `timing.settle` after `timing.requested`; and both listings show the instance
    /// absent ([`Listing`]). A retry that finds that entry gone writes nothing. The gone mark writes the volume record
    /// alone.
    ///
    /// An owner's poll retires on a listed instance of a gone entry as a late-landing attach (ATTACH-AFTER-GONE), and
    /// judges a cached listing beside a volume read that follows it. The gap from that listing's request to that
    /// volume read is the listing's deadline, its cache age up to the owner's listing period (`listing_us`), the view
    /// job's queue wait and its store latency, which the owner's periods keep below [`LISTING_HOLD_US`]. Choosing
    /// `settle` above that constant is the caller's obligation, which this step does not check; it makes the listing
    /// of any owner poll that reads the entry gone one requested after the earlier of the two clean listings.
    ///
    /// # Errors
    ///
    /// The store client's errors; [`ReconcileError::Conflict`] with no write when the host's latest entry is another
    /// entry, or is the witnessed entry neither ended with no pair nor gone; or when `timing.settle` is zero, the
    /// listings are not two, lie less than `timing.settle` apart, the earlier precedes
    /// `timing.requested + timing.settle`, or a listing contains the instance.
    pub fn release_attach(
        &mut self,
        _gate: &StandbyGate,
        witness: &Detachable,
        listings: &[Listing<'_>],
        timing: Settle,
    ) -> Result<(), ReconcileError> {
        let read = self
            .client
            .read::<VolumeRecord>(Key::Volume(witness.volume))?;
        let held = read.value();
        match held.latest(witness.host) {
            Some((seq, event))
                if seq == witness.seq
                    && event.instance == Some(witness.instance)
                    && event.kind == EventKind::Gone =>
            {
                return Ok(());
            }
            Some((seq, _)) if seq == witness.seq => {}
            _ => return Err(ReconcileError::Conflict),
        }
        let (seq, instance) = detach_ready(held, witness.host)
            .filter(|&(_, instance)| instance == witness.instance)
            .ok_or(ReconcileError::Conflict)?;
        let [first, second] = listings else {
            return Err(ReconcileError::Conflict);
        };
        let settled = timing.settle > 0
            && first.at.abs_diff(second.at) >= timing.settle
            && first
                .at
                .min(second.at)
                .checked_sub(timing.requested)
                .is_some_and(|after| after >= timing.settle);
        let clean = listings
            .iter()
            .all(|listing| omits(listing.instances, Some(instance)));
        if !settled || !clean {
            return Err(ReconcileError::Conflict);
        }
        let next = moved(held, seq, EventKind::Gone).ok_or(ReconcileError::Conflict)?;
        self.client.replace(&read, next)?;
        Ok(())
    }

    /// Reserves the census slot of `shard` in `zone` for designating `candidate`'s writer at the `(g, owner, E)` the
    /// shard record holds, under `population`'s cap (POPULATION-CAP, ONE-HOST-PER-SLOT, FEASIBLE-SLOT), with `lost`
    /// the caller's evidence that a host is gone. It reads the census, then the shard record, then the record of its
    /// active volume for the candidate's [`Attach`], so the entry it writes never names an earlier `(g, owner, E)`
    /// than the entry it read; it creates the census when the AZ has none, and writes the reservation by an
    /// exact-version write. A census that already lists the slot for this host takes no write, so a retry after an
    /// unknown outcome or a restart converges. The caller supplies a report it accepted and bounds its age, and
    /// `bounds` carries the owner's `N_reg` for the attach rule [`Attach::of`] shares with
    /// [`Reconciler::record_standby`].
    ///
    /// # Errors
    ///
    /// The store client's errors, a lost version condition included, after which the caller retries on a fresh read;
    /// [`ReconcileError::Conflict`] before any write when the active volume's record shows a creation other than
    /// provisioning, a lineage, a modification, a layout below the floor or a state other than fresh or active, which
    /// no designation accepts; [`ReconcileError::Population`] when [`Population::admit`] refuses.
    #[expect(clippy::too_many_arguments)]
    pub fn reserve(
        &mut self,
        _gate: &StandbyGate,
        population: &Population,
        bounds: &Bounds,
        zone: Zone,
        shard: Shard,
        candidate: &HostReport,
        lost: impl Fn(Host) -> bool,
    ) -> Result<Slot, ReconcileError> {
        let key = Key::Standbys(zone);
        let held = match self.client.read_census(key, &self.census) {
            Err(StoreError::Absent) => None,
            held => Some(held?),
        };
        let record = self.client.read::<ShardRecord>(Key::Shard(shard))?;
        let volume = self
            .client
            .read::<VolumeRecord>(Key::Volume(record.value().active))?;
        let held_volume = volume.value();
        if !reservable(held_volume) {
            return Err(ReconcileError::Conflict);
        }
        let attach = Attach::of(held_volume, candidate.writer.host, bounds);
        let empty = Census::empty(zone);
        let census = held.as_ref().map_or(&empty, |r| r.value());
        let lost = |host| lost(host) || standby_ended(record.value(), held_volume, host);
        let admitted = population.admit(census, record.value(), candidate, attach, lost);
        let listed = match (admitted, held) {
            (Err(refusal), held) => {
                self.census = held.map(Read::into_value).or(self.census.take());
                return Err(ReconcileError::Population(refusal));
            }
            (Ok(Some(next)), Some(held)) => self.client.replace(&held, next)?,
            (Ok(Some(next)), None) => self.client.create(key, next)?,
            // Invariant: `admit` writes nothing only for a census that lists the slot, which an absent one cannot.
            (Ok(None), held) => held.expect("an absent census lists no slot"),
        };
        // Invariant: `listed` is the census `admit` found or wrote listing the slot for the candidate.
        let slot = Slot::held(&listed, shard, candidate.writer.host);
        self.census = Some(listed.into_value());
        Ok(slot.expect("the census lists the reserved slot"))
    }

    /// Drops the census entry of `shard` in `zone` once the shard record, read after the census, names no standby
    /// and holds another `(g, owner, E)` than the entry's, and the entry's host is the owner, is shown lost by
    /// `lost`, the caller's evidence that a host is gone or that its attach failed for good, or holds no live attach
    /// in the record of the active volume read after the shard record (CENSUS-COVERS), and returns whether the census
    /// lists the shard afterwards.
    /// The entry is eligible for release only while it matches `held`, the entry the caller evaluated. A census that
    /// lists another entry for the shard keeps it, and the call returns after its census read.
    ///
    /// # Errors
    ///
    /// The store client's errors, a lost version condition included, after which the caller retries.
    pub fn release(
        &mut self,
        _gate: &StandbyGate,
        zone: Zone,
        shard: Shard,
        held: Entry,
        lost: impl Fn(Host) -> bool,
    ) -> Result<bool, ReconcileError> {
        let census = match self.client.read_census(Key::Standbys(zone), &self.census) {
            Err(StoreError::Absent) => return Ok(false),
            census => census?,
        };
        let listed = census.value().slot(shard);
        if listed != Some(held) {
            self.census = Some(census.into_value());
            return Ok(listed.is_some());
        }
        let record = self.client.read::<ShardRecord>(Key::Shard(shard))?;
        let volume = self
            .client
            .read::<VolumeRecord>(Key::Volume(record.value().active))?;
        let live = |host| !lost(host) && volume.value().live(host).is_some();
        let (kept, listed) = match census.value().released(record.value(), live) {
            Some(next) => (self.client.replace(&census, next)?, false),
            None => {
                let listed = census.value().slot(shard).is_some();
                (census, listed)
            }
        };
        self.census = Some(kept.into_value());
        Ok(listed)
    }

    /// Names `slot`'s host the standby of `slot`'s shard at `slot`'s `(g, owner, E)` on its active volume `volume`,
    /// by the exact-version designation write ([`Client::designate`]) over a shard record read after the volume
    /// record, and only while the census, read after the shard record, still lists the slot for this host
    /// (ONE-HOST-PER-SLOT). The shard record must pass STANDBY-TENURE and the volume record `serving` and enroll a
    /// pair for the host's live attach. A shard record that already names the host on `volume` returns as it is, so
    /// a retry after an unknown outcome writes nothing; one that names another standby is replaced, which fails the
    /// condition of that standby's takeover CAS over the earlier version. The retry also requires the enrolled pair,
    /// so `designate` returns [`ReconcileError::Conflict`] when the named host's attach has ended.
    ///
    /// # Errors
    ///
    /// The store client's errors; [`ReconcileError::Stale`] when the shard record holds another `(g, owner, E)`
    /// than the slot's; [`ReconcileError::Conflict`] when the census lists the slot for another host or target or
    /// not at all, the shard record fails STANDBY-TENURE, the volume record fails `serving`, or it enrolls no pair
    /// for the host's live attach, an attach not recorded or not enrolled included.
    pub fn designate(
        &mut self,
        _gate: &StandbyGate,
        slot: &Slot,
        volume: VolumeId,
    ) -> Result<Read<ShardRecord>, ReconcileError> {
        let (host, target) = (slot.host(), slot.target());
        let held = self.client.read::<VolumeRecord>(Key::Volume(volume))?;
        let read = self.client.read::<ShardRecord>(Key::Shard(slot.shard()))?;
        let tenure = read.value();
        if Target::of(tenure) != target {
            return Err(ReconcileError::Stale);
        }
        let key = Key::Standbys(slot.zone());
        let census = self.client.read_census(key, &self.census)?;
        let listed = census.value().slot(slot.shard());
        self.census = Some(census.into_value());
        if listed != Some(Entry { target, host }) {
            return Err(ReconcileError::Conflict);
        }
        let held = held.value();
        if !standby_tenure(tenure, volume, host)
            || held.enrolled(host).is_none()
            || !serving(&mut self.client, held, tenure)?
        {
            return Err(ReconcileError::Conflict);
        }
        if tenure.standby == Some(host) && tenure.active == volume {
            return Ok(read);
        }
        Ok(self.client.designate(&read, target, host)?)
    }

    /// The replacement receipt of `shard` for the decision [`decide`] returns over the shard record this step reads,
    /// `evidence` and `others` (CORRELATED-HOLD, IDEMPOTENT-PROVISIONING in `failover::loss`), read and written by
    /// conditional create or exact-version write. A `Provision` or `Hold` of a replacement the receipt does not hold
    /// starts its receipt at attempt 1 of `layout`, held for a `Hold`; a `Hold` of the receipt's replacement latches
    /// an unreleased receipt that is not held, keeping a recorded volume, whatever layout the caller passes; and a held
    /// receipt stays held under any later decision for its replacement until [`Reconciler::release_hold`]. `Retain`
    /// writes nothing and returns `None`. A receipt started over one whose recorded volume the shard record names
    /// follows an exact-version write of that unchanged shard record over this step's read (SUPERSESSION-FENCE).
    /// When that write loses its version condition the step reads the shard record and the receipt again and decides
    /// over the fresh reads.
    ///
    /// # Errors
    ///
    /// [`ReconcileError::Exhausted`] for a loss at the last generation a replacement can activate, with no write;
    /// [`ReconcileError::Layout`] before any receipt write for a layout [`Layout::check_floor`] refuses, when the step
    /// starts a receipt; [`ReconcileError::Conflict`] when a receipt of this replacement that this step does not latch
    /// records another layout, and before starting a receipt over one that records a volume the shard record names in
    /// no role and whose record is not yet retired, so the caller retires that volume first; the store client's
    /// errors; [`ReconcileError::Retry`] with no receipt write after `REPLACEMENT_ROUNDS` rounds in each of which
    /// the shard record moved after the step read it. Returns [`ReconcileError::Conflict`] for an earlier issued
    /// receipt until
    /// [`Reconciler::create_replacement`] records the volume created with that receipt's token.
    pub fn replacement(
        &mut self,
        _gate: &StandbyGate,
        shard: Shard,
        evidence: (VolumeId, Health),
        others: usize,
        layout: Layout,
    ) -> Result<Option<Read<Receipt>>, ReconcileError> {
        for _ in 0..REPLACEMENT_ROUNDS {
            let record = self.client.read::<ShardRecord>(Key::Shard(shard))?;
            let (request, hold) = match decide(record.value(), evidence, others) {
                Decision::Provision(request) => (request, false),
                Decision::Hold(Some(request)) => (request, true),
                Decision::Hold(None) => return Err(ReconcileError::Exhausted),
                Decision::Retain => return Ok(None),
            };
            let read = self.receipt(shard)?;
            let next = match &read {
                Some(read) if read.value().request == request => {
                    let current = read.value();
                    let latch = hold && !current.released && !current.held;
                    if !latch {
                        return if current.layout == layout {
                            Ok(Some(read.clone()))
                        } else {
                            Err(ReconcileError::Conflict)
                        };
                    }
                    Receipt {
                        held: true,
                        ..current.clone()
                    }
                }
                _ => {
                    layout.check_floor().map_err(ReconcileError::Layout)?;
                    if let Some(prior) = &read {
                        match self.prior(record.value(), prior.value())? {
                            Prior::Unresolved => return Err(ReconcileError::Conflict),
                            Prior::Named => {
                                match self.client.replace(&record, *record.value()) {
                                    Err(StoreError::Refused(Refusal::Condition)) => continue,
                                    fenced => fenced?,
                                };
                            }
                            Prior::Settled => {}
                        }
                    }
                    Receipt {
                        request,
                        layout,
                        attempt: 1,
                        phase: Phase::Open,
                        held: hold,
                        released: false,
                    }
                }
            };
            return Ok(Some(match read {
                Some(read) => self.client.replace(&read, next)?,
                None => self.client.create(Key::Replacement(shard), next)?,
            }));
        }
        Err(ReconcileError::Retry)
    }

    /// The operator releases the held receipt of `request`, preserving its phase and clearing its hold. The receipt is
    /// marked released, and later holds of `request` leave it unchanged. A receipt that is not held returns unchanged.
    ///
    /// # Errors
    ///
    /// The store client's errors; [`ReconcileError::Stale`] when the receipt names another replacement.
    pub fn release_hold(
        &mut self,
        _release: &OperatorRelease,
        request: Request,
    ) -> Result<Read<Receipt>, ReconcileError> {
        let read = self
            .client
            .read::<Receipt>(Key::Replacement(request.shard))?;
        let current = read.value();
        if current.request != request {
            return Err(ReconcileError::Stale);
        }
        if !current.held {
            return Ok(read);
        }
        let next = Receipt {
            held: false,
            released: true,
            ..current.clone()
        };
        Ok(self.client.replace(&read, next)?)
    }

    /// `latch` records a correlated hold on the receipt for `request` using an exact-version write. A receipt already
    /// held, or one the operator released, retains its version. `latch` accesses only the receipt store and reads
    /// neither the shard record nor any volume: its caller has observed the shard's active volume lost beside another
    /// impaired or lost volume of the AZ (CORRELATED-HOLD).
    ///
    /// # Errors
    ///
    /// The store client's errors; [`ReconcileError::Stale`] when the receipt names another replacement.
    pub fn latch(
        &mut self,
        _gate: &StandbyGate,
        request: Request,
    ) -> Result<Read<Receipt>, ReconcileError> {
        let read = self
            .client
            .read::<Receipt>(Key::Replacement(request.shard))?;
        let current = read.value();
        if current.request != request {
            return Err(ReconcileError::Stale);
        }
        if current.held || current.released {
            return Ok(read);
        }
        let next = Receipt {
            held: true,
            ..current.clone()
        };
        Ok(self.client.replace(&read, next)?)
    }

    /// Creates the replacement named by `shard`'s receipt and records its volume:
    ///
    /// 1. A held receipt returns `Held`. While `others` other volumes of the AZ are impaired or lost, the step latches
    ///    an unreleased receipt held and returns `Held`.
    /// 2. A [`Phase::Created`] receipt returns its recorded volume, which covers a reconciler that resumes after
    ///    `record_attach`. A created receipt whose generation the shard record already holds returns `Stale`.
    /// 3. The receipt's layout must meet the floor. An open receipt must name the generation after the shard
    ///    record's, and the step commits [`Phase::Issued`] over it by an exact-version write. An issued receipt keeps
    ///    its token.
    /// 4. The step calls `provider` under the receipt's token and layout, creates the returned volume's provisioned
    ///    record ([`Reconciler::provision`]), and records the volume in the receipt by an exact-version write.
    /// 5. The step reads the shard record again. An issued receipt whose generation the shard record holds, before
    ///    step 3 or by this read, returns `Stale` after step 4, with its volume recorded for the caller to retire.
    ///    The second read covers a flip that commits while the provider call is in flight.
    ///
    /// A `Failed` create opens the next attempt, held while `others` other volumes of the AZ are impaired or lost and
    /// the receipt is unreleased.
    ///
    /// # Errors
    ///
    /// [`ReconcileError::Held`] for a held receipt, or one this step latched, before any provider call;
    /// [`ReconcileError::Layout`] before any write or provider call for a layout below the floor;
    /// [`ReconcileError::Stale`] for a created receipt whose generation the shard record already holds;
    /// [`ReconcileError::Stale`] for an open receipt past its generation before any write or provider call, and for an
    /// issued receipt past its generation after step 4, by either shard read; [`ReconcileError::Create`]
    /// with `Unknown`, after which a retry repeats the token, and with `Failed` after the exact-version write that
    /// raised the attempt; [`ReconcileError::Conflict`] for an attempt at `u32::MAX`; the store client's errors, a
    /// lost version condition on the issue write included; and [`Reconciler::provision`]'s. After its `Conflict` the
    /// step reads the receipt again: one that still holds the issue this step read refuses `Conflict`, so a volume
    /// record of another value under the returned name refuses `Conflict` on every repeat; one that records the
    /// returned volume, as after another reconciler finished the same create and its caller ran `record_attach`,
    /// returns that volume record; and one that moved otherwise refuses [`ReconcileError::Stale`].
    pub fn create_replacement(
        &mut self,
        gate: &StandbyGate,
        shard: Shard,
        others: usize,
        provider: &mut impl Provider,
    ) -> Result<Read<VolumeRecord>, ReconcileError> {
        self.create_at(gate, shard, others, None, provider)
    }

    /// Creates the replacement for the `request` and `attempt` the caller admitted. `create_attempt` sends only the
    /// admitted token: it returns [`ReconcileError::Stale`] before any write or provider call when the stored
    /// receipt names another request or attempt. For every receipt phase, `create_attempt` returns
    /// [`ReconcileError::Stale`] before any provider call if the shard record's generation differs from the
    /// request's predecessor generation. When the shard record already holds the issued receipt's generation, the
    /// receipt retains its token for settlement by [`Reconciler::create_replacement`]. When the shard record reaches
    /// that generation while the provider call is in flight, `create_attempt` records the returned volume in the
    /// receipt and returns [`ReconcileError::Stale`], as step 5 of [`Reconciler::create_replacement`] states.
    ///
    /// # Errors
    ///
    /// [`ReconcileError::Stale`] for a stored receipt of another request or attempt, and for a shard record whose
    /// generation differs from the request's predecessor generation, before the provider call or by the read after
    /// it; otherwise, errors from
    /// [`Reconciler::create_replacement`].
    pub fn create_attempt(
        &mut self,
        gate: &StandbyGate,
        (request, attempt): (Request, u32),
        others: usize,
        provider: &mut impl Provider,
    ) -> Result<Read<VolumeRecord>, ReconcileError> {
        self.create_at(
            gate,
            request.shard,
            others,
            Some((request, attempt)),
            provider,
        )
    }

    fn create_at(
        &mut self,
        _gate: &StandbyGate,
        shard: Shard,
        others: usize,
        admitted: Option<(Request, u32)>,
        provider: &mut impl Provider,
    ) -> Result<Read<VolumeRecord>, ReconcileError> {
        let read = self.client.read::<Receipt>(Key::Replacement(shard))?;
        let current = read.value();
        if admitted.is_some_and(|admitted| admitted != (current.request, current.attempt)) {
            return Err(ReconcileError::Stale);
        }
        if current.held {
            return Err(ReconcileError::Held);
        }
        if others > 0 && !current.released {
            let next = Receipt {
                held: true,
                ..current.clone()
            };
            self.client.replace(&read, next)?;
            return Err(ReconcileError::Held);
        }
        let record = self.client.read::<ShardRecord>(Key::Shard(shard))?;
        let due = next_generation(record.value(), current.request);
        if admitted.is_some() && !due {
            return Err(ReconcileError::Stale);
        }
        if let Phase::Created(volume) = current.phase {
            if !due {
                return Err(ReconcileError::Stale);
            }
            return Ok(self.client.read(Key::Volume(volume))?);
        }
        current
            .layout
            .check_floor()
            .map_err(ReconcileError::Layout)?;
        let read = match current.phase {
            Phase::Issued => read,
            _ if !due => return Err(ReconcileError::Stale),
            _ => {
                let next = Receipt {
                    phase: Phase::Issued,
                    ..current.clone()
                };
                self.client.replace(&read, next)?
            }
        };
        let current = read.value();
        let volume = match provider.create(&current.token(), current.layout) {
            Ok(volume) => volume,
            Err(CreateError::Failed) => {
                self.client.replace(&read, next_attempt(current, others)?)?;
                return Err(ReconcileError::Create(CreateError::Failed));
            }
            Err(unknown) => return Err(ReconcileError::Create(unknown)),
        };
        let record = match self.provision(volume, current.layout) {
            Err(ReconcileError::Conflict) => {
                let now = self.client.read::<Receipt>(Key::Replacement(shard))?;
                let recorded = now.value().phase == Phase::Created(volume) && !now.value().held;
                if !recorded {
                    let moved = now != read;
                    return Err(if moved {
                        ReconcileError::Stale
                    } else {
                        ReconcileError::Conflict
                    });
                }
                self.client.read(Key::Volume(volume))?
            }
            provisioned => {
                let record = provisioned?;
                let next = Receipt {
                    phase: Phase::Created(volume),
                    ..current.clone()
                };
                self.client.replace(&read, next)?;
                record
            }
        };
        if !due {
            return Err(ReconcileError::Stale);
        }
        let shard = self.client.read::<ShardRecord>(Key::Shard(shard))?;
        if !next_generation(shard.value(), read.value().request) {
            return Err(ReconcileError::Stale);
        }
        Ok(record)
    }

    /// Moves the receipt of `shard` past `observed`, the caller's read of it recording its created volume, which
    /// `retired` shows retired for this shard on the caller's evidence of a known terminal failure, while `others`
    /// other volumes of the AZ are impaired or lost: the receipt moves to the next attempt, whose token creates another
    /// volume, held beside another impaired or lost volume unless the operator released this replacement
    /// (CORRELATED-HOLD), and open otherwise. The retirement, by [`Reconciler::retire`] or
    /// [`Reconciler::retire_spare`], refuses a volume a flip activated and removes it as the shard's spare, so the
    /// failed volume is never activated and stays recorded as retired for its cleanup. The step reads the receipt,
    /// then the shard record, and refuses unless the receipt names the generation after the record's, since a
    /// replacement already active is an active volume's loss for [`Reconciler::replacement`] to judge. A receipt of
    /// the same replacement already at the next attempt, open or held with no volume, returns as it is, so a retry
    /// after an unknown outcome converges. A flip that commits between the shard read and the receipt write leaves the
    /// receipt at its next attempt, whose create then refuses `Stale`.
    ///
    /// # Errors
    ///
    /// The store client's errors; [`ReconcileError::Held`] while a hold latched over `observed` keeps its volume;
    /// [`ReconcileError::Stale`] when `retired` is another shard's or names another volume than `observed` records, the receipt moved off `observed` otherwise, or the receipt names another generation
    /// than the one after the shard record's; [`ReconcileError::Conflict`] for an attempt at `u32::MAX`.
    pub fn abandon(
        &mut self,
        _gate: &StandbyGate,
        shard: Shard,
        observed: &Receipt,
        retired: &Retired,
        others: usize,
    ) -> Result<Read<Receipt>, ReconcileError> {
        let created = Phase::Created(retired.volume);
        if retired.shard != shard || observed.held || observed.phase != created {
            return Err(ReconcileError::Stale);
        }
        let read = self.client.read::<Receipt>(Key::Replacement(shard))?;
        let current = read.value();
        let replayed = current.request == observed.request
            && observed.attempt.checked_add(1) == Some(current.attempt)
            && current.phase == Phase::Open;
        if replayed {
            return Ok(read);
        }
        if (
            current.request,
            current.attempt,
            current.phase,
            current.held,
        ) == (observed.request, observed.attempt, created, true)
        {
            return Err(ReconcileError::Held);
        }
        if current != observed {
            return Err(ReconcileError::Stale);
        }
        let record = self.client.read::<ShardRecord>(Key::Shard(shard))?;
        if !next_generation(record.value(), current.request) {
            return Err(ReconcileError::Stale);
        }
        let next = next_attempt(current, others)?;
        Ok(self.client.replace(&read, next)?)
    }

    /// Names the attached volume the spare of the shard's tenure `target`, held by its attaching host. The shard
    /// record must hold `target`, and the volume record, read after the shard record, must show the volume unused:
    /// provisioned and fresh, retaining the lineage and modification state provisioning wrote, with a layout at or
    /// above its floor and exactly the attaching host's attach event. A retry after a flip, a retirement or a tenure
    /// change names nothing, and a shard record that already names this spare returns as it is.
    ///
    /// # Errors
    ///
    /// The store client's errors; [`ReconcileError::Stale`] when the shard record holds another `(g, owner, E)`;
    /// [`ReconcileError::Conflict`] when the shard record names another spare or this volume active, or the volume
    /// record does not show the volume unused: provisioned and fresh, with no lineage, modification record, recorded
    /// pair or fence, and a whole history of exactly the attaching host's attach event.
    pub fn add_spare(
        &mut self,
        shard: Shard,
        target: Target,
        attached: &AttachRecorded,
    ) -> Result<Read<ShardRecord>, ReconcileError> {
        let read = self.client.read::<ShardRecord>(Key::Shard(shard))?;
        if Target::of(read.value()) != target {
            return Err(ReconcileError::Stale);
        }
        let spare = (attached.volume, attached.host);
        let held = read.value().spare;
        if read.value().active == attached.volume || held.is_some_and(|current| current != spare) {
            return Err(ReconcileError::Conflict);
        }
        let candidate = self
            .client
            .read::<VolumeRecord>(Key::Volume(attached.volume))?;
        if !unused(candidate.value(), attached.host) {
            return Err(ReconcileError::Conflict);
        }
        if held == Some(spare) {
            return Ok(read);
        }
        self.unheld(shard, attached.volume)?;
        let next = ShardRecord {
            spare: Some(spare),
            ..*read.value()
        };
        Ok(self.client.replace(&read, next)?)
    }

    /// Serves a retirement request a host raised for the shard's active volume by flipping the shard to its spare,
    /// under an operator's release (HOST-LOSS-KEEPS-VOLUME). When its first shard read is past the request's
    /// generation, it returns [`Flip::Past`] before any store write; a `Past` on a later round can follow the
    /// volume-record and receipt writes of earlier rounds.
    /// The caller has checked the spare's attachment listing (LISTED-SPARE), as required by [`Self::flip`].
    /// Version-condition losses use fresh reads, so every flip write conditions on a record the request admits:
    /// its exact `(g, owner, E)`, or `E + 1` for a recovering request.
    ///
    /// # Errors
    ///
    /// [`ReconcileError::Conflict`] before any request for a request of another role than active, and when the
    /// shard record's spare changes between rounds; [`ReconcileError::Stale`] when [`Retirement::admit`] refuses the
    /// read record; [`ReconcileError::Retry`] after `FLIP_ROUNDS` version-condition losses; otherwise the errors of
    /// [`Reconciler::flip`]. A later round's refusal can follow volume-record writes of earlier rounds.
    pub fn flip_for(
        &mut self,
        _release: &OperatorRelease,
        shard: Shard,
        request: &Retirement,
    ) -> Result<Flip, ReconcileError> {
        if request.role != Role::Active {
            return Err(ReconcileError::Conflict);
        }
        let mut first_spare = None;
        for _ in 0..FLIP_ROUNDS {
            let read = self.client.read::<ShardRecord>(Key::Shard(shard))?;
            if read.value().generation > request.target.generation {
                return Ok(Flip::Past);
            }
            if *first_spare.get_or_insert(read.value().spare) != read.value().spare {
                return Err(ReconcileError::Conflict);
            }
            request
                .admit(read.value())
                .map_err(|_| ReconcileError::Stale)?;
            match self.flip_read(read) {
                Err(ReconcileError::Store(StoreError::Refused(Refusal::Condition))) => {}
                result => return result,
            }
        }
        Err(ReconcileError::Retry)
    }

    /// Flips the shard from the tenure `target` to its spare after actual loss of the active volume. The caller must
    /// hold the replacement receipt started on that loss; this step checks the tenure, the spare and the hold. A
    /// host's retirement request goes to [`Self::flip_for`]. The caller has checked the spare's attachment listing
    /// (LISTED-SPARE). The spare's volume record must show it unused, and an
    /// exact-version write of that unchanged record raises its version before the flip, so a retired-state write
    /// conditioned on an earlier read of it fails and no retirement lands on the volume the flip activates. The
    /// displaced active volume's record moves to active before the flip from any earlier state, so it never reads
    /// unused again. A receipt that records the displaced volume is written back unchanged before the flip
    /// (SUPERSESSION-FENCE).
    ///
    /// # Errors
    ///
    /// The store client's errors, [`StoreError::Unknown`] included, after which the caller retries the flip of the
    /// same tenure; [`ReconcileError::Stale`] when the shard record holds another `(g, owner, E)` at or below
    /// `target`'s generation; [`ReconcileError::Conflict`] when the spare's record does not show it unused: provisioned
    /// and fresh, with no lineage, modification record, recorded pair or fence, and a whole history of exactly the
    /// spare host's attach event; [`ReconcileError::Held`] while the shard's replacement receipt holds the spare as
    /// the volume its create returned, after the spare's and the displaced volume's record writes.
    pub fn flip(
        &mut self,
        _gate: &StandbyGate,
        shard: Shard,
        target: Target,
    ) -> Result<Flip, ReconcileError> {
        self.flip_of(shard, target, None)
    }

    /// Flips the shard as [`Reconciler::flip`] does when the shard record names `spare` as the shard's spare.
    ///
    /// # Errors
    ///
    /// When the shard record matches `target` but names another spare or none, `flip_to` returns
    /// [`ReconcileError::Conflict`]. Other errors follow [`Reconciler::flip`].
    pub fn flip_to(
        &mut self,
        _gate: &StandbyGate,
        shard: Shard,
        target: Target,
        spare: (VolumeId, Host),
    ) -> Result<Flip, ReconcileError> {
        self.flip_of(shard, target, Some(spare))
    }

    fn flip_of(
        &mut self,
        shard: Shard,
        target: Target,
        spare: Option<(VolumeId, Host)>,
    ) -> Result<Flip, ReconcileError> {
        let read = self.client.read::<ShardRecord>(Key::Shard(shard))?;
        if read.value().generation > target.generation {
            return Ok(Flip::Past);
        }
        if Target::of(read.value()) != target {
            return Err(ReconcileError::Stale);
        }
        if spare.is_some_and(|spare| read.value().spare != Some(spare)) {
            return Err(ReconcileError::Conflict);
        }
        self.flip_read(read)
    }

    fn flip_read(&mut self, read: Read<ShardRecord>) -> Result<Flip, ReconcileError> {
        let after = flipped(read.value()).map_err(StoreError::Flip)?;
        let spare = self
            .client
            .read::<VolumeRecord>(Key::Volume(after.active))?;
        if !unused(spare.value(), after.owner) {
            return Err(ReconcileError::Conflict);
        }
        self.client.replace(&spare, spare.value().clone())?;
        let active = self
            .client
            .read::<VolumeRecord>(Key::Volume(read.value().active))?;
        if active.value().state < VolumeState::Active {
            let next = VolumeRecord {
                state: VolumeState::Active,
                ..active.value().clone()
            };
            self.client.replace(&active, next)?;
        }
        let receipt = self.unheld(after.shard, after.active)?;
        self.fence(receipt.as_ref(), read.value().active)?;
        Ok(Flip::Flipped(self.client.flip(&read)?))
    }

    /// The replacement receipt of `shard`, or `None` when the shard has none.
    fn receipt(&mut self, shard: Shard) -> Result<Option<Read<Receipt>>, ReconcileError> {
        match self.client.read::<Receipt>(Key::Replacement(shard)) {
            Err(StoreError::Absent) => Ok(None),
            receipt => Ok(Some(receipt?)),
        }
    }

    /// Refuses [`ReconcileError::Held`] while the shard's replacement receipt holds `volume` as the volume its create
    /// returned (CORRELATED-HOLD), so neither the spare naming nor the flip advances a held replacement. A hold of
    /// `volume` that latches after this read does not stop the write that follows it. Returns the receipt it read.
    fn unheld(
        &mut self,
        shard: Shard,
        volume: VolumeId,
    ) -> Result<Option<Read<Receipt>>, ReconcileError> {
        let receipt = self.receipt(shard)?;
        if let Some(receipt) = &receipt {
            let current = receipt.value();
            if current.held && current.phase == Phase::Created(volume) {
                return Err(ReconcileError::Held);
            }
        }
        Ok(receipt)
    }

    /// SUPERSESSION-FENCE for a step whose next shard write names `volume` in no role while the volume's record is
    /// short of retired: writes `receipt`, read after the shard record that write conditions on, back unchanged by
    /// an exact-version write when it records `volume`. A later replacement's receipt write conditioned on an
    /// earlier read of the receipt then fails.
    fn fence(
        &mut self,
        receipt: Option<&Read<Receipt>>,
        volume: VolumeId,
    ) -> Result<(), ReconcileError> {
        if let Some(receipt) = receipt
            && receipt.value().phase == Phase::Created(volume)
        {
            self.client.replace(receipt, receipt.value().clone())?;
        }
        Ok(())
    }

    /// What `prior`, the receipt of an earlier replacement, holds for a step that starts a later one over `record`,
    /// its read of the shard record (IDEMPOTENT-PROVISIONING).
    fn prior(&mut self, record: &ShardRecord, prior: &Receipt) -> Result<Prior, ReconcileError> {
        let made = match prior.phase {
            Phase::Open => return Ok(Prior::Settled),
            Phase::Issued => return Ok(Prior::Unresolved),
            Phase::Created(made) => made,
        };
        if named(record, made) {
            return Ok(Prior::Named);
        }
        let volume = self.client.read::<VolumeRecord>(Key::Volume(made))?;
        Ok(if volume.value().state < VolumeState::Retired {
            Prior::Unresolved
        } else {
            Prior::Settled
        })
    }

    /// Writes the retired state of `volume`, which the shard record names neither active nor spare, after the flip
    /// that displaced it, and returns the witness from the shard write of RETIRED-IS-FINAL. The volume record is read
    /// before the shard record, so a flip that activates the volume after that read raises the version the
    /// retired-state write conditions on. The settling shard write conditions on the version of that same shard read.
    /// When the retired-state write commits and a shard write lands between the shard read and the settling write,
    /// the settling write's version condition fails and the step returns that refusal with the retired state
    /// written.
    ///
    /// # Errors
    ///
    /// The store client's errors; [`ReconcileError::Named`] while the shard record names the volume active, or
    /// spare before the volume record shows it retired.
    pub fn retire(&mut self, shard: Shard, volume: VolumeId) -> Result<Retired, ReconcileError> {
        let read = self.client.read::<VolumeRecord>(Key::Volume(volume))?;
        if read.value().state >= VolumeState::Retired {
            return self.settle(shard, volume);
        }
        let record = self.client.read::<ShardRecord>(Key::Shard(shard))?;
        if named(record.value(), volume) {
            return Err(ReconcileError::Named);
        }
        self.write_retired(&read)?;
        self.settle_on(&record, volume)
    }

    /// Removes the spare `request` names and retires it. The step reads the volume record before the shard record, as
    /// [`Reconciler::retire`] does, and takes the first case that holds:
    ///
    /// 1. The volume record is at or past retired. The step goes straight to the shard write of RETIRED-IS-FINAL,
    ///    which clears the volume from the spare slot, under any `(g, owner, E)` the request carries.
    /// 2. The shard record names the volume spare. [`Retirement::admit`] checks the request against that shard read,
    ///    and the step returns [`ReconcileError::Stale`] if the request's `(g, owner, E)` differs from the shard
    ///    record's, before any write. After admission, if the receipt records the volume, `fence` writes the receipt
    ///    back unchanged (SUPERSESSION-FENCE). The step then removes the spare by an exact-version write over the
    ///    shard read, writes the retired state and settles.
    /// 3. The volume occupies no shard role. The step writes the retired state and settles under any `(g, owner, E)`
    ///    the request carries, so a retry can finish a committed removal.
    ///
    /// The settling shard write conditions on the version the
    /// removal committed, or on the shard read when the step made no removal. When the retired-state write commits
    /// and a pending [`Reconciler::add_spare`] names the volume again before the settling write, the settling write's
    /// version condition fails and the step returns that refusal with the retired state written.
    ///
    /// # Errors
    ///
    /// The store client's errors; [`ReconcileError::Stale`] in case 2, when the request's `(g, owner, E)` differs
    /// from the shard record's;
    /// [`ReconcileError::Named`] while the shard record names the volume active; [`ReconcileError::Conflict`] for a
    /// request of the active role.
    pub fn retire_spare(
        &mut self,
        shard: Shard,
        request: &Retirement,
    ) -> Result<Retired, ReconcileError> {
        if request.role != Role::Spare {
            return Err(ReconcileError::Conflict);
        }
        let volume = request.volume;
        let read = self.client.read::<VolumeRecord>(Key::Volume(volume))?;
        if read.value().state >= VolumeState::Retired {
            return self.settle(shard, volume);
        }
        let record = self.client.read::<ShardRecord>(Key::Shard(shard))?;
        if record.value().active == volume {
            return Err(ReconcileError::Named);
        }
        let record = if named(record.value(), volume) {
            request
                .admit(record.value())
                .map_err(|_| ReconcileError::Stale)?;
            let receipt = self.receipt(shard)?;
            self.fence(receipt.as_ref(), volume)?;
            self.client.retire(&record, request)?
        } else {
            record
        };
        self.write_retired(&read)?;
        self.settle_on(&record, volume)
    }

    fn write_retired(&mut self, read: &Read<VolumeRecord>) -> Result<(), ReconcileError> {
        let next = VolumeRecord {
            state: VolumeState::Retired,
            ..read.value().clone()
        };
        self.client.replace(read, next)?;
        Ok(())
    }

    fn settle(&mut self, shard: Shard, volume: VolumeId) -> Result<Retired, ReconcileError> {
        let record = self.client.read::<ShardRecord>(Key::Shard(shard))?;
        self.settle_on(&record, volume)
    }

    /// `settle_on` establishes RETIRED-IS-FINAL through an exact-version shard write over `record`, which clears
    /// `volume` from the spare slot, after the caller observes `volume` at or beyond [`VolumeState::Retired`].
    fn settle_on(
        &mut self,
        record: &Read<ShardRecord>,
        volume: VolumeId,
    ) -> Result<Retired, ReconcileError> {
        if record.value().active == volume {
            return Err(ReconcileError::Named);
        }
        let next = ShardRecord {
            spare: record.value().spare.filter(|&(spare, _)| spare != volume),
            ..*record.value()
        };
        self.client.replace(record, next)?;
        Ok(Retired {
            shard: record.value().shard,
            volume,
        })
    }
}

/// What the receipt of an earlier replacement holds for a step that starts a later one.
enum Prior {
    /// A token outcome the shard needs: an issued attempt whose create may have made a volume, or a recorded volume
    /// that the shard record names in no role and whose record is short of retired.
    Unresolved,
    /// A recorded volume that the step's shard read names. The receipt is superseded only while the shard record
    /// still names the volume (SUPERSESSION-FENCE).
    Named,
    /// No token outcome the shard needs: the receipt's attempt is open, or its recorded volume, which the step's
    /// shard read names in no role, reads at or beyond [`VolumeState::Retired`].
    Settled,
}

/// `held` when it records the creation of `record`: the same shard, generation, active volume, owner, `B`,
/// `C_page` and namespace.
fn created(
    held: Read<ShardRecord>,
    record: &ShardRecord,
) -> Result<Read<ShardRecord>, ReconcileError> {
    let creation = |r: &ShardRecord| {
        (
            r.shard,
            r.generation,
            r.active,
            r.owner,
            r.pages,
            r.page_cap,
            r.namespace,
        )
    };
    (creation(held.value()) == creation(record))
        .then_some(held)
        .ok_or(ReconcileError::Conflict)
}

/// Whether `held` keeps the state the cache's provisioning path wrote, lineage and modification included, with its
/// whole attachment history, no recorded pair, a zero fence and a layout [`Layout::check_floor`] admits.
fn provisioned(held: &VolumeRecord) -> bool {
    held.uncompacted() && held.pairs.is_empty() && held.fence == 0 && origin_intact(held)
}

/// The volume record [`Reconciler::reserve`] reserves a census slot on: fresh or active, and with its origin intact.
pub(crate) fn reservable(held: &VolumeRecord) -> bool {
    origin_intact(held) && matches!(held.state, VolumeState::Fresh | VolumeState::Active)
}

/// A provisioned volume with no lineage, no modification record and a layout at the floor.
fn origin_intact(held: &VolumeRecord) -> bool {
    held.source == CreationSource::Provisioned
        && held.lineage == Lineage::None
        && held.modification.is_none()
        && held.layout.check_floor().is_ok()
}

/// Whether `request` names the generation after `record`'s, the one a replacement of its active volume activates at.
fn next_generation(record: &ShardRecord, request: Request) -> bool {
    record.generation.get() + 1 == request.generation.get()
}

/// The receipt at the attempt after `current`'s, held while `others` other volumes of the AZ are impaired or lost and
/// the receipt is unreleased, and open otherwise (CORRELATED-HOLD).
fn next_attempt(current: &Receipt, others: usize) -> Result<Receipt, ReconcileError> {
    Ok(Receipt {
        attempt: current
            .attempt
            .checked_add(1)
            .ok_or(ReconcileError::Conflict)?,
        phase: Phase::Open,
        held: others > 0 && !current.released,
        ..current.clone()
    })
}

/// STANDBY-TENURE: the shard record names `volume` active, under an owner other than `host`, at `E > 0`.
fn standby_tenure(tenure: &ShardRecord, volume: VolumeId, host: Host) -> bool {
    tenure.active == volume && tenure.owner != host && tenure.attempts > 0
}

/// `standby_successor` builds a candidate successor to `held` for a standby attach of `host` at `era`. Each live
/// attach of `held` that binds no instance takes the one instance `binding.unbound` names for its host, and the
/// pushed attach entry binds `binding.instance`. At [`MAX_EVENTS`] entries it considers the gone entries
/// [`VolumeRecord::removable_gone`] yields in `held.events` order; the successor omits the first such entry whose
/// instance is absent from the complete `binding.listing`.
///
/// The result is `None` in each of these cases:
/// - `binding.listing` holds a row that fails [`InstanceId::new`] or equals `binding.instance`;
/// - `binding.unbound` names zero instances, or two different ones, for a live attach without an instance;
/// - two attach or ended entries of the successor bind one instance;
/// - `held.next` is `u32::MAX`;
/// - `held` has `MAX_EVENTS` entries and `binding.listing` is absent or leaves no gone entry to remove.
fn standby_successor(
    held: &VolumeRecord,
    host: Host,
    era: u32,
    binding: &Binding<'_>,
) -> Option<VolumeRecord> {
    let listed = match binding.listing {
        Some(rows) => Some(
            rows.iter()
                .map(|row| InstanceId::new(row))
                .collect::<Option<Vec<_>>>()?,
        ),
        None => None,
    };
    if listed
        .as_ref()
        .is_some_and(|rows| rows.contains(&binding.instance))
    {
        return None;
    }
    let mut bound = held.clone();
    for (seq, live) in held.live_attaches() {
        let entry = bound.events.iter_mut().find(|event| event.seq == seq)?;
        if entry.instance.is_none() {
            let mut named = binding
                .unbound
                .iter()
                .filter(|peer| peer.host == live)
                .map(|peer| peer.instance);
            let instance = named.next()?;
            if named.any(|other| other != instance) {
                return None;
            }
            entry.instance = Some(instance);
        }
    }
    let successor = |shed: Option<usize>| {
        let mut next = bound.clone();
        if let Some(at) = shed {
            next.events.remove(at);
        }
        let seq = next.push(EventKind::Attach, host, era)?;
        next.events
            .iter_mut()
            .rfind(|event| event.seq == seq)?
            .instance = Some(binding.instance);
        let mut instances: Vec<InstanceId> = next
            .events
            .iter()
            .filter(|event| matches!(event.kind, EventKind::Attach | EventKind::Ended))
            .filter_map(|event| event.instance)
            .collect();
        let count = instances.len();
        instances.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        instances.dedup();
        (instances.len() == count).then_some(next)
    };
    if held.events.len() < MAX_EVENTS {
        return successor(None);
    }
    let listed = listed?;
    held.removable_gone(host)
        .filter(|&at| {
            held.events[at]
                .instance
                .is_some_and(|gone| !listed.contains(&gone))
        })
        .find_map(|at| successor(Some(at)))
}

/// What the shard record `tenure` and the volume record `held` decide of [`enroll_standby`]'s precondition for
/// `host` with no further read: STANDBY-TENURE, and a reservable volume record that holds the owner's pair. When
/// this is false, `enroll_standby` over the same two records refuses [`StandbyRefusal::Tenure`] after its volume
/// read and its shard read, before `persist`. When it is true, the fence of coverage page 0 decides.
pub(crate) fn records_admit_standby(tenure: &ShardRecord, held: &VolumeRecord, host: Host) -> bool {
    standby_tenure(tenure, held.volume, host) && owner_recorded(held, tenure)
}

/// `flip_read` writes the displaced volume's record at most once, as the active mark before its shard write, so a
/// standby's exact-version volume write can commit across a shard write that lands after the standby's reads.
/// The shard read a standby step makes after its write observes a flip that committed before that read.
fn standby_serving<S: Store, L: WatermarkLog>(
    client: &mut Client<S, L>,
    shard: Shard,
    held: &VolumeRecord,
    host: Host,
) -> Result<bool, StoreError> {
    let tenure = client.read::<ShardRecord>(Key::Shard(shard))?;
    Ok(standby_tenure(tenure.value(), held.volume, host) && serving(client, held, tenure.value())?)
}

/// Whether `held` shows a volume that held no tenure: provisioned, fresh, with exactly `host`'s one attach event.
pub(crate) fn unused(held: &VolumeRecord, host: Host) -> bool {
    provisioned(held) && held.state == VolumeState::Fresh && held.attached_once(host)
}

/// The part of `serving` the two records decide: a reservable volume record that holds a pair of the tenure's
/// owner, on a live attach or an ended entry.
fn owner_recorded(held: &VolumeRecord, tenure: &ShardRecord) -> bool {
    reservable(held) && held.records_pair_of(tenure.owner)
}

/// Whether `held` passes [`owner_recorded`] and page 0's fence supplies activation evidence: its high word matches
/// the tenure's generation and its low word is nonzero.
fn serving<S: Store, L: WatermarkLog>(
    client: &mut Client<S, L>,
    held: &VolumeRecord,
    tenure: &ShardRecord,
) -> Result<bool, StoreError> {
    if !owner_recorded(held, tenure) {
        return Ok(false);
    }
    let fence = client
        .read::<CoveragePage>(Key::Page(tenure.shard, 0))?
        .value()
        .fence;
    let generation = tenure.generation.get();
    let epoch = ActivatedEpoch::new(fence as u32);
    Ok(fence >> 32 == generation && epoch.is_some_and(ActivatedEpoch::is_activated))
}

fn named(record: &ShardRecord, volume: VolumeId) -> bool {
    record.active == volume || record.spare.is_some_and(|(spare, _)| spare == volume)
}

fn names(record: &ShardRecord, host: Host) -> bool {
    record.owner == host || record.standby == Some(host)
}

pub(crate) fn end_ready(held: &VolumeRecord, host: Host) -> Option<u32> {
    let (seq, event) = held.latest(host)?;
    let foreign_key = held
        .pinned(host, seq)
        .is_some_and(|pair| Some(pair.key) != attachment_key(seq) && !held.spent_key(pair.key));
    (event.kind == EventKind::Attach && event.instance.is_some() && !foreign_key).then_some(seq)
}

fn detach_ready(held: &VolumeRecord, host: Host) -> Option<(u32, InstanceId)> {
    let (seq, event) = held.latest(host)?;
    let instance = event.instance?;
    let shared = held.events.iter().any(|other| {
        other.seq != seq
            && other.instance == Some(instance)
            && (other.kind == EventKind::Attach || held.pinned(other.host, other.seq).is_some())
    });
    (event.kind == EventKind::Ended && held.pinned(host, seq).is_none() && !shared)
        .then_some((seq, instance))
}

/// The latest entry of `host` in `held` with its instance when that entry is gone and binds an instance no attach or
/// ended entry of `held` binds.
pub(crate) fn relist_ready(held: &VolumeRecord, host: Host) -> Option<(u32, InstanceId)> {
    let (seq, event) = held.latest(host)?;
    let instance = event.instance?;
    let bound = held.events.iter().any(|other| {
        other.instance == Some(instance)
            && matches!(other.kind, EventKind::Attach | EventKind::Ended)
    });
    (event.kind == EventKind::Gone && !bound).then_some((seq, instance))
}

fn moved(held: &VolumeRecord, seq: u32, kind: EventKind) -> Option<VolumeRecord> {
    let mut next = held.clone();
    next.events.iter_mut().find(|entry| entry.seq == seq)?.kind = kind;
    Some(next)
}

#[cfg(test)]
#[path = "reconcile_supersession_tests.rs"]
mod supersession_tests;
