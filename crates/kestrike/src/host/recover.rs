//! [`role`] reads the volume record before the shard record (READ-ORDER) to classify this host's role for its
//! volume. It issues at most two store reads and no store write, touches no device and mints no session
//! (ROLE-LICENSES-NOTHING); its shard read may persist a raised watermark to the client's local log.
//! [`recover`] then runs the sequence of a restart or fresh role once, through a [`Fencer`], and returns the
//! [`Tenure`] the sequence acquired, or one [`Exit`] with the fencer's driver or table: the exit a refusal maps to,
//! or a hold when the sequence succeeded and the fencer still held a command.
//! [`stand_by`] holds a standby or unnamed host through its wait, enrolls an attached host's pair and runs the
//! takeover a nomination starts.
//!
//! Invariants:
//!
//! - NoEpochReuse: the serving authority comes only from the sequence's own result, whose session is its own
//!   acknowledged bump. A refusal builds no authority, and the next incarnation runs its sequence from step 1. A
//!   [`Tenure`]'s fields are private to the host composition, so only [`recover`] and [`stand_by`] build one, and
//!   only the crate-visible first step of [`bring_up`](super::serve::bring_up), `start_up`, takes it apart.
//! - RecordsBeforeDevice: `recover` issues no device command of its own; the fencer connects at the sequence's first
//!   device step.
//! - HOST-LOSS-KEEPS-VOLUME: an exit requests a flip only where the sequence's refusal requested it.
//! - NAMED-STANDBY, DETECTION-CARRIES-NO-SAFETY: [`stand_by`] starts a takeover only from a witness that names its
//!   shard and has yet to expire, and the takeover's own step 1 and compare-and-swap decide.
//! - ENROLL-BEFORE-REGISTER: [`stand_by`] makes an attached unnamed host's local record durable before its one
//!   enrollment write. Its wait and its enrollment issue no Register; a standby's pair is registered at the
//!   device only by its takeover, at the takeover's own step, when the first Report lists none.
//!   A named standby makes its local record durable before writing the pair enrollment for its live attach.

use super::exit::{Exit, Refusal, Rerun};
use super::fencer::{Fencer, Release};
use super::gate::HostGate;
use super::inputs::{self, Inputs};
use std::sync::atomic::AtomicBool;

use super::serve::{Surveyed, wait_with};
use crate::failover::admission::AdmissionError;
use crate::failover::attachments::{ControlPlane, InstanceId, Peer};
use crate::failover::detect::host::Revalidated;
use crate::failover::flip::{VolumeMismatch, volume_state};
use crate::failover::fresh::{self, LocalRecords, Refusals};
use crate::failover::identity::Key as ReservationKey;
use crate::failover::poll::Holder;
use crate::failover::reconcile::{StandbyGate, enroll_standby, records_admit_standby};
use crate::failover::record::LocalRecord;
use crate::failover::records::Host;
use crate::failover::records::{ShardRecord, VolumeId, VolumeRecord, VolumeState};
use crate::failover::report::RecoveryRefusal;
use crate::failover::restart::{self, Check, Local, LocalSource};
use crate::failover::retire::Target;
use crate::failover::takeover::Next;
use crate::net::ownership::Shard;
use crate::storage::device::connect::Connected;
use crate::storage::page_coverage::{FenceRefused, Fencing, FencingRefusal, Withdraw};
use crate::storage::store::{Client, Key, Store, StoreError, WatermarkLog};
use crate::storage::{
    BufferArena, Disk, Platform, ServingAuthority, ServingClock, Session, contain,
};

/// What the records say this host is for its volume. A role selects a sequence and licenses no write, device
/// command or session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The shard record names this host owner of this active volume at `E > 0`: a host that served the volume, a
    /// planned handoff's target and a successor whose takeover write committed each run the same-host restart.
    Restart,
    /// The shard record names this host owner of this active volume at `E = 0`.
    Fresh,
    /// `target` is the record's `(g, owner, E)`, which a nomination must name for the takeover to start.
    Standby { target: Target },
    /// Every other case on a volume that is neither retired nor deleted: the host of a spare that no flip made
    /// active, an attached host the record names in no role, and a former owner whose volume read came before the
    /// displacing flip marked that volume active.
    Unnamed,
    /// The volume is retired: its record shows retired or deleted, or shows active while the shard record names
    /// another active volume (`flip::volume_state`). This takes precedence over the shard record's host assignments.
    Retired,
}

/// Reads the volume record once, then the shard record once.
///
/// # Errors
///
/// [`role`] returns the first read error, after at most one request when the volume read fails. The shard read
/// requires a successful volume read. `StoreError::Log`, `Regression` and `Namespace` withdraw the client.
pub fn role<S: Store, L: WatermarkLog>(
    client: &mut Client<S, L>,
    shard: Shard,
    holder: &Holder,
) -> Result<Role, StoreError> {
    survey(client, shard, holder).map(|(role, _, _)| role)
}

/// [`role`] with the two records its reads returned: the volume record, which a waiting host judges its attach and
/// peers by, and the shard record, which with the volume record decides whether an unnamed host calls its
/// enrollment.
///
/// # Errors
///
/// As for [`role`].
pub fn survey<S: Store, L: WatermarkLog>(
    client: &mut Client<S, L>,
    shard: Shard,
    holder: &Holder,
) -> Result<(Role, VolumeRecord, ShardRecord), StoreError> {
    let volume = client.read::<VolumeRecord>(Key::Volume(holder.volume))?;
    let record = client.read::<ShardRecord>(Key::Shard(shard))?;
    let role = classify(holder, record.value(), volume.value());
    Ok((role, volume.into_value(), record.into_value()))
}

/// A retired volume, by [`volume_state`], takes precedence over the shard record's host assignments.
fn classify(holder: &Holder, shard: &ShardRecord, volume: &VolumeRecord) -> Role {
    match volume_state(shard, volume) {
        Ok(VolumeState::Active) => {}
        Ok(VolumeState::Provisioning | VolumeState::Fresh) => return Role::Unnamed,
        Ok(VolumeState::Retired | VolumeState::Deleted)
        | Err(VolumeMismatch::ActiveElsewhere | VolumeMismatch::RetiredNamedActive) => {
            return Role::Retired;
        }
    }
    if shard.owner == holder.host {
        return if shard.attempts > 0 {
            Role::Restart
        } else {
            Role::Fresh
        };
    }
    if shard.standby == Some(holder.host) {
        return Role::Standby {
            target: Target::of(shard),
        };
    }
    Role::Unnamed
}

/// A tenure one sequence acquired: the serving authority built from the sequence's own result, the coverage fencing
/// that the owner installs, the driver the fencer released once each of its commands reached its terminal, and the
/// fencer's arena, the one whose memory that driver registered and the volume attaches over. The fields are private
/// to the host composition: only [`recover`] and a [`stand_by`] takeover build a tenure, and only `start_up`, the
/// crate-visible first step of [`bring_up`](super::serve::bring_up), takes it apart. The fencing reaches the owner's `install_coverage` with no hold or cover write after the sequence
/// returned, so a warm restart's load filters its restored entries against the coverage the live fencing holds.
///
/// A caller outside the host composition names a tenure:
///
/// ```
/// # use kestrike::host::Tenure;
/// # use kestrike::storage::Platform;
/// fn hand_over<P: Platform, D>(tenure: Tenure<'_, P, D>) -> Tenure<'_, P, D> {
///     tenure
/// }
/// ```
///
/// It can neither build one nor reach one of its parts:
///
/// ```compile_fail,E0451
/// # use kestrike::host::Tenure;
/// # use kestrike::storage::Platform;
/// fn swap<P: Platform, D>(tenure: Tenure<'_, P, D>, disk: D) -> Tenure<'_, P, D> {
///     Tenure { disk, ..tenure }
/// }
/// ```
///
/// ```compile_fail,E0616
/// # use kestrike::host::Tenure;
/// # use kestrike::storage::Platform;
/// fn driver<P: Platform, D>(tenure: Tenure<'_, P, D>) -> D {
///     tenure.disk
/// }
/// ```
///
/// ```compile_fail,E0616
/// # use kestrike::host::Tenure;
/// # use kestrike::storage::Platform;
/// fn fencing<P: Platform, D>(tenure: &mut Tenure<'_, P, D>) {
///     let _ = &mut tenure.fencing;
/// }
/// ```
///
/// ```compile_fail,E0616
/// # use kestrike::host::Tenure;
/// # use kestrike::storage::Platform;
/// fn authority<P: Platform, D>(tenure: &mut Tenure<'_, P, D>) {
///     let _ = &mut tenure.authority;
/// }
/// ```
pub struct Tenure<'a, P: Platform, D> {
    pub(super) authority: ServingAuthority,
    pub(super) fencing: Fencing,
    pub(super) disk: D,
    pub(super) arena: &'a BufferArena<P>,
    pub(super) lineage: bool,
}

impl<P: Platform, D> Tenure<'_, P, D> {
    /// Whether the restart reached its fencing boundary through its lineage arm ([`Restarted::lineage`]), which a
    /// recovery report records as `RecoveryStatus::lineage`.
    ///
    /// [`Restarted::lineage`]: crate::failover::restart::Restarted::lineage
    pub fn lineage(&self) -> bool {
        self.lineage
    }
}

/// An incarnation that returned no usable [`Tenure`], and the fencer's driver, table or
/// [`Release::Unconnected`] as [`Fencer::release`] returned it. The exit is the one a refusal maps to,
/// [`Exit::Retired`], [`Rerun::Unwound`] when the sequence unwound, a hold at the acquired tenure's `(g, owner, E)`
/// when the sequence succeeded, its bump committed, and the fencer still held a command, or [`Exit::Fault`] when a
/// waiting role was given a fencer that had connected. The caller ends a returned driver or table through the proven
/// stop.
pub struct Ended<'a, D: Disk> {
    pub exit: Exit,
    pub device: Release<'a, D>,
    /// The class of the sequence's own refusal that `exit` maps: the restart's, the fresh path's, or the standby
    /// takeover's whose next step reruns the incarnation. `None` for the exits no sequence refusal made: a retired
    /// role, an unwound sequence, a waiting role given a connected fencer, a failed role read, a changed role, a stop,
    /// and the hold of a success whose fencer still held a command.
    pub refusal: Option<RecoveryRefusal>,
}

/// What [`recover`] returns.
pub enum Recovery<'a, P: Platform, D: Disk> {
    Tenure(Box<Tenure<'a, P, D>>),
    Ended(Box<Ended<'a, D>>),
    /// [`Role::Standby`] and [`Role::Unnamed`] hold no tenure: `recover` read nothing, and the fencer it took
    /// released [`Release::Unconnected`].
    Waits,
}

/// The store client, the host-local records and the control plane one recovery reads and writes through, with the
/// fresh path's refusal tally. The restart reads `local`; the fresh path persists it and checks `plane`'s listing.
pub struct Sources<'r, S: Store, L: WatermarkLog, R, K> {
    pub client: &'r mut Client<S, L>,
    pub local: &'r mut R,
    pub plane: &'r mut K,
    pub refusals: &'r mut Refusals,
}

/// Runs the sequence `role` names, once: [`Restart::run`] for [`Role::Restart`] and [`Fresh::run`] for
/// [`Role::Fresh`], through `fencer`. The serving authority comes only from the sequence's success, through
/// [`ServingAuthority::restarted`] or [`ServingAuthority::activated`] on `clock`, and the tenure takes the driver
/// [`Fencer::release`] returns with the fencer's arena. A success whose fencer still holds a command ends
/// [`Exit::Held`] at the acquired tenure's `(g, owner, E)`: the sequence's bump advanced `E`, and `Ended::device`
/// carries the fencer's table for the proven stop. A refusal maps to one [`Exit`] by `restart_exit` or `fresh_exit`,
/// and the sequence issued no device command after it. A sequence that unwinds ends [`Rerun::Unwound`] with the
/// fencer's release, in builds whose panics unwind; a connect closure that unwinds produced no driver, so the
/// release is [`Release::Unconnected`]. [`Role::Retired`] ends with [`Exit::Retired`]; [`Role::Standby`] and
/// [`Role::Unnamed`] return [`Recovery::Waits`] when the fencer never connected, and end [`Exit::Fault`] with its
/// driver or table otherwise. A role or refusal that reaches no device step drops the connect closure uncalled.
///
/// [`Restart::run`]: crate::failover::restart::Restart::run
/// [`Fresh::run`]: crate::failover::fresh::Fresh::run
pub fn recover<'a, P, D, C, S, L, R, K>(
    _gate: &HostGate,
    role: Role,
    (inputs, peers): (&Inputs, &[Peer]),
    sources: Sources<'_, S, L, R, K>,
    mut fencer: Fencer<'a, P, D, C>,
    clock: Box<dyn ServingClock>,
) -> Recovery<'a, P, D>
where
    P: Platform,
    D: Disk,
    C: FnOnce() -> Connected<D>,
    S: Store,
    L: WatermarkLog,
    R: LocalSource + LocalRecords,
    K: ControlPlane,
{
    let Sources {
        client,
        local,
        plane,
        refusals,
    } = sources;
    let sequence = match role {
        Role::Restart => contain(|| {
            inputs::restart(inputs, peers)
                .run(client, &*local, &mut fencer)
                .map(|restarted| serving(inputs, clock, restarted))
                .map_err(|refused| {
                    (
                        restart_exit(&refused),
                        Some(RecoveryRefusal::from(&refused)),
                    )
                })
        }),
        Role::Fresh => contain(|| {
            inputs::fresh(inputs)
                .run(client, plane, local, &mut fencer, refusals)
                .map(|activated| {
                    let (authority, fencing) =
                        ServingAuthority::activated(inputs.bounds(), clock, activated);
                    (authority, fencing, false)
                })
                .map_err(|refused| {
                    let refusal = Some(RecoveryRefusal::from(&refused));
                    (fresh_exit(&refused, inputs.holder().volume), refusal)
                })
        }),
        Role::Retired => Ok(Err((Exit::Retired, None))),
        Role::Standby { .. } | Role::Unnamed => {
            return match deviceless(fencer) {
                Ok(fencer) => {
                    let _ = fencer.release();
                    Recovery::Waits
                }
                Err(ended) => Recovery::Ended(ended),
            };
        }
    };
    // An unwound sequence resumes nothing; the fencer's release keeps every command it still owns.
    let acquired = sequence.unwrap_or(Err((Exit::Rerun(Rerun::Unwound), None)));
    match finish(acquired, fencer) {
        Ok(tenure) => Recovery::Tenure(tenure),
        Err(ended) => Recovery::Ended(ended),
    }
}

/// Ends a recovery over what its sequence acquired: the tenure with the driver `fencer` releases and the arena it
/// built its table over, or the exit with whatever `fencer` releases.
fn finish<'a, P, D, C>(
    acquired: Result<(ServingAuthority, Fencing, bool), (Exit, Option<RecoveryRefusal>)>,
    fencer: Fencer<'a, P, D, C>,
) -> Result<Box<Tenure<'a, P, D>>, Box<Ended<'a, D>>>
where
    P: Platform,
    D: Disk,
    C: FnOnce() -> Connected<D>,
{
    let arena = fencer.arena();
    let (exit, device, refusal) = match acquired {
        Ok((authority, fencing, lineage)) => match fencer.release() {
            Release::Driver(disk) => {
                return Ok(Box::new(Tenure {
                    authority,
                    fencing,
                    disk,
                    arena,
                    lineage,
                }));
            }
            // DEVICE-FAILURE-HOLD: the tenure's driver stays in custody, so its session drops with a hold.
            device => (
                Exit::Held {
                    recovery: authority.session().target(),
                },
                device,
                None,
            ),
        },
        Err((exit, refusal)) => (exit, fencer.release(), refusal),
    };
    Err(Box::new(Ended {
        exit,
        device,
        refusal,
    }))
}

/// A waiting role requires a deviceless fencer. If the fencer holds a device, `deviceless` returns the released
/// device with [`Exit::Fault`].
fn deviceless<'a, P, D, C>(
    fencer: Fencer<'a, P, D, C>,
) -> Result<Fencer<'a, P, D, C>, Box<Ended<'a, D>>>
where
    P: Platform,
    D: Disk,
    C: FnOnce() -> Connected<D>,
{
    if !fencer.holds_device() {
        return Ok(fencer);
    }
    Err(Box::new(Ended {
        exit: Exit::Fault("a waiting role took a fencer that had connected".to_owned()),
        device: fencer.release(),
        refusal: None,
    }))
}

/// What a waiting host is told: the stop flag, the view period, the nominations its host agent sends and the time
/// they expire on.
pub struct Signals<'w, W, N, T> {
    pub stop: &'w AtomicBool,
    /// Returns once one view period passed.
    pub period: W,
    /// Takes the pending witness of a nomination of this standby's shard. The source holds at most one witness: a
    /// witness the host's detector sends replaces an unread one, and a call takes it, so an expired witness never
    /// waits ahead of a live one. `None` when the detector sent none since the last call.
    pub nominations: N,
    /// The observer's `CLOCK_BOOTTIME` in microseconds, which a witness's `until_us` is read against. The witness
    /// was minted on the same host in the same boot.
    pub now: T,
}

/// The standby arm and the unnamed arm of the recovery: holds a host the records name standby, or name in no role,
/// through [`wait_with`], and calls `fencer` only inside a takeover, so a fencer that connects at its first
/// command holds no device during the wait. Each view period, after the role read:
///
/// - `Role::Unnamed` or `Role::Standby`,
///   while the role read's volume record shows this host's live attach with no enrolled pair
///   and its two records pass `reconcile::records_admit_standby`, the part of the enrollment precondition they
///   decide: one [`enroll_standby`] call, which makes the local record durable through `persist` before its one
///   enrollment write and hands `persist` the key its live attach enrolls under (KEY-PER-ATTACH). A refusal keeps
///   the wait, and the next period's role read decides again: the arm calls
///   `enroll_standby` while that read's records show the same, and calls nothing once the volume record shows the
///   pair, as after a write of unknown outcome that committed. A call whose own volume read already finds the pair
///   still runs `persist` and issues no store write. A host the role read shows enrolled, and a host whose role
///   read fails that precondition, as the host of a spare that no flip made active does, issue no further read,
///   no store write and no `persist` in the period. `enroll_standby` judges the precondition again on its own
///   reads, so a record that changes after the role read costs at most one view period.
///   The takeover requires the enrolled pair, so the witness read from `signals.nominations` waits until after the
///   enrollment period.
///   An enrolled named standby reads `signals.nominations` each period and runs the takeover a witness starts.
/// - `Role::Standby`, when `signals.nominations` returns a witness that [`Takeover::nominated`] accepts at
///   `signals.now()`: [`Takeover::run`] in the same period through `fencer`, over the peers `instance` resolves in
///   the period's volume record. The run judges its later volume reads against those peers: a host whose attach
///   is recorded during the run with an entry that binds no instance and is still unenrolled at such a read refuses `Volume(Events)` with no flip
///   request, which returns to the wait at step 1 and ends [`Rerun::Takeover`] after the acknowledged
///   compare-and-swap. Success returns the tenure, its authority built by
///   [`ServingAuthority::restarted`], when `fencer` releases its driver, and otherwise ends [`Exit::Held`] at the
///   new session's `(g, owner, E)` with the released device in the caller's custody. A refusal whose
///   [`Takeover::next`] is `Stop` issued no device command and returns to the wait, where a later witness starts
///   another takeover; `Restart` ends the incarnation with [`Rerun::Takeover`].
///
/// The wait and the enrollment issue no Register and no device command, and the wait issues no store write
/// (ENROLL-BEFORE-REGISTER): the takeover registers the own pair at its own step. A role read raises the client's
/// local watermark log when it shows a newer record. A role read of a restart or fresh role ends the arm with
/// [`Rerun::RoleChanged`] and a set stop flag with [`Exit::Stopped`]. A retired role keeps the arm waiting with
/// role reads only. A failed role read keeps the wait, unless the store client is withdrawn, by that read or by
/// an enrollment or takeover read before it: a withdrawn client issues no further request, so the arm ends
/// [`Rerun::Records`] and the next incarnation opens a client from the durable watermark.
///
/// `local` reads the record `persist` makes durable, replacements during this call included; one owner lock
/// behind both gives that.
///
/// If `fencer` holds a device at entry, the arm returns that device with [`Exit::Fault`] before the first view
/// period.
///
/// [`Takeover::nominated`]: crate::failover::takeover::Takeover::nominated
/// [`Takeover::run`]: crate::failover::takeover::Takeover::run
/// [`Takeover::next`]: crate::failover::takeover::Takeover::next
#[expect(
    clippy::too_many_arguments,
    reason = "the arms take both gates, the standby's inputs, its two record sources, the fencer and the signals"
)]
pub fn stand_by<'a, P, D, C, S, L, R, W, N, T>(
    (host, standby): (&HostGate, &StandbyGate),
    (inputs, instance): (&Inputs, &dyn Fn(Host) -> Option<InstanceId>),
    client: &mut Client<S, L>,
    local: &R,
    mut persist: impl FnMut(ReservationKey) -> Result<LocalRecord, AdmissionError>,
    fencer: Fencer<'a, P, D, C>,
    clock: Box<dyn ServingClock>,
    signals: Signals<'_, W, N, T>,
) -> Result<Box<Tenure<'a, P, D>>, Box<Ended<'a, D>>>
where
    P: Platform,
    D: Disk,
    C: FnOnce() -> Connected<D>,
    S: Store,
    L: WatermarkLog,
    R: LocalSource,
    W: FnMut(),
    N: FnMut() -> Option<Revalidated>,
    T: FnMut() -> u64,
{
    let mut fencer = deviceless(fencer)?;
    let Signals {
        stop,
        period,
        mut nominations,
        mut now,
    } = signals;
    let holder = *inputs.holder();
    let unenrolled = |volume: &VolumeRecord, shard: &ShardRecord| {
        volume.live(holder.host).is_some()
            && volume.enrolled(holder.host).is_none()
            && records_admit_standby(shard, volume, holder.host)
    };
    // A takeover's refusal that ends the incarnation leaves the wait as its exit with the refusal's class.
    let act = |read: Surveyed, client: &mut Client<S, L>| match read {
        Err(_) => None,
        Ok((Role::Restart | Role::Fresh, ..)) => Some(Err(Exit::Rerun(Rerun::RoleChanged))),
        Ok((Role::Retired, ..)) => None,
        Ok((Role::Unnamed | Role::Standby { .. }, volume, shard))
            if unenrolled(&volume, &shard) =>
        {
            // A refusal keeps the wait. The call may have committed its enrollment or withdrawn the client, so
            // the next view period's role read decides whether the arm calls again, waits or ends.
            let _ = enroll_standby(
                standby,
                inputs.shard(),
                &holder,
                &inputs.bounds(),
                client,
                &mut persist,
            );
            None
        }
        Ok((Role::Unnamed, ..)) => None,
        Ok((Role::Standby { .. }, volume, _)) => {
            let witness = nominations()?;
            let peers = inputs::peers(&holder, &volume, instance)?;
            let takeover = inputs::takeover(inputs, &peers, &witness, now())?;
            // An unwound takeover resumes nothing; the fencer's release keeps every command it still owns.
            match contain(|| takeover.run(client, local, &mut fencer)) {
                Ok(Ok(restarted)) => Some(Ok(Ok(restarted))),
                Ok(Err(refused)) => match takeover.next(&refused) {
                    Next::Stop => None,
                    Next::Restart(_) => Some(Ok(Err((
                        Exit::Rerun(Rerun::Takeover),
                        Some(RecoveryRefusal::from(&refused)),
                    )))),
                },
                Err(_) => Some(Err(Exit::Rerun(Rerun::Unwound))),
            }
        }
    };
    let acquired = match wait_with(host, (inputs.shard(), &holder), client, stop, period, act) {
        Ok(Ok(restarted)) => Ok(serving(inputs, clock, restarted)),
        Ok(Err(refused)) => Err(refused),
        Err(exit) => Err((exit, None)),
    };
    finish(acquired, fencer)
}

/// The serving authority and coverage fencing a restart or a takeover reached, and whether it reached them through
/// the restart's lineage arm ([`Restarted::lineage`]).
fn serving(
    inputs: &Inputs,
    clock: Box<dyn ServingClock>,
    restarted: restart::Restarted,
) -> (ServingAuthority, Fencing, bool) {
    let lineage = restarted.lineage();
    let (authority, fencing) = ServingAuthority::restarted(inputs.bounds(), clock, restarted);
    (authority, fencing, lineage)
}

/// How a coverage refusal ends either sequence's incarnation.
enum Coverage {
    /// A page holds a later tenure's fence: the tenure is deposed.
    Deposed,
    /// The refusal recurs on every rerun over the same pages, each of which would take another `E`.
    Parks,
    /// The sequence's own split decides.
    Sequence,
}

/// The class of a coverage refusal. A fence that is no activated session shows no later tenure, and parks with the
/// damaged pages: a page whose record or entries fail the fencing checks, a page the store holds no record of, and a
/// `C_page` below the encoded empty page.
fn coverage(refused: &FenceRefused) -> Coverage {
    match refused {
        FenceRefused::Fence(Withdraw::NewerFence { fence, .. })
            if Session::is_activated(*fence) =>
        {
            Coverage::Deposed
        }
        FenceRefused::Fence(
            Withdraw::NewerFence { .. }
            | Withdraw::Malformed { .. }
            | Withdraw::Store(StoreError::Codec(_) | StoreError::Absent),
        )
        | FenceRefused::Fencing(FencingRefusal::PageCap) => Coverage::Parks,
        FenceRefused::Fence(Withdraw::Store(_) | Withdraw::NoPage { .. } | Withdraw::Unpaired)
        | FenceRefused::Fencing(FencingRefusal::Shard | FencingRefusal::Generation)
        | FenceRefused::Unresolved { .. } => Coverage::Sequence,
    }
}

/// The one [`Exit`] of a refused restart:
///
/// - a deposition, and a coverage page a later tenure fenced, end `Deposed`;
/// - a failed record read, a step-1 record of the fresh path and an unreadable host-local record rerun as
///   `Rerun(Records)`: the sequence issued no device command after any of them, and it reads the host-local record
///   at step 2, before its first device command and its bump;
/// - `Unheld` and the coverage refusals that recur on every rerun park as `Refused`, overriding the sequence's hold;
/// - every other refusal follows the sequence's own split: a flip request parks as `Retire`, a hold ends `Held` at
///   its recovery target, and a refusal with neither parks as `Refused`.
pub(super) fn restart_exit(refused: &restart::Refused) -> Exit {
    let parked = |check: &Check| Exit::Refused(Refusal::Restart(check.clone()));
    match &refused.check {
        Check::Deposed => Exit::Deposed,
        Check::Records(_) | Check::Fresh | Check::Local(Local::Unreadable) => {
            Exit::Rerun(Rerun::Records)
        }
        check @ Check::Unheld => parked(check),
        check @ Check::Coverage(fence) => match coverage(fence) {
            Coverage::Deposed => Exit::Deposed,
            Coverage::Parks => parked(check),
            Coverage::Sequence => split(refused),
        },
        _ => split(refused),
    }
}

/// The restart's own split of `refused`: a flip request parks as `Retire`, a hold ends `Held`, and a refusal with
/// neither parks as `Refused`.
fn split(refused: &restart::Refused) -> Exit {
    match (refused.flip, refused.recovery) {
        (Some(target), _) => Exit::Retire(target),
        (None, Some(recovery)) => Exit::Held { recovery },
        (None, None) => Exit::Refused(Refusal::Restart(refused.check.clone())),
    }
}

/// The one [`Exit`] of a refused fresh first acquisition. A refusal with a retirement request parks as `Retire`.
/// Otherwise a refusal whose retention release failed takes the exit of the refusal it wraps, through every wrapper,
/// and `Refused` keeps the whole outer check:
///
/// - a deposing or superseding record, and a coverage page a later tenure fenced, end `Deposed`;
/// - a failed record read and a step-1 record of the restart rerun as `Rerun(Records)`;
/// - the coverage refusals that recur on every rerun park as `Refused`;
/// - every other refusal ends the incarnation as `Rerun(Unactivated)`, and the next role read finds the record's
///   current `E`.
pub(super) fn fresh_exit(refused: &fresh::Refused, volume: VolumeId) -> Exit {
    if let Some(retirement) = refused.retirement(volume) {
        return Exit::Retire(retirement.target);
    }
    fresh_class(&refused.check, &refused.check)
}

/// The exit of the fresh refusal `outer` by the class of `check`, the check it wraps.
fn fresh_class(check: &fresh::Check, outer: &fresh::Check) -> Exit {
    use fresh::Check as F;
    let fenced = |fence: FenceRefused| match coverage(&fence) {
        Coverage::Deposed => Exit::Deposed,
        Coverage::Parks => Exit::Refused(Refusal::Fresh(outer.clone())),
        Coverage::Sequence => Exit::Rerun(Rerun::Unactivated),
    };
    match check {
        F::Retention { original, .. } => fresh_class(original, outer),
        F::Deposed | F::Superseded => Exit::Deposed,
        F::Records(_) | F::Restart => Exit::Rerun(Rerun::Records),
        F::Fence(withdraw) => fenced(FenceRefused::Fence(*withdraw)),
        F::Fencing(refusal) => fenced(FenceRefused::Fencing(*refusal)),
        F::UnresolvedPage { page } => fenced(FenceRefused::Unresolved { page: *page }),
        F::Unobserved
        | F::Volume(_)
        | F::Origin
        | F::Exhausted(_)
        | F::Persist(_)
        | F::EnrollWrite(_)
        | F::EnrollRefused(_)
        | F::Bump(_)
        | F::Local(_)
        | F::HostId(_)
        | F::Register(_)
        | F::Acquire(_)
        | F::Report(_)
        | F::NotSole(_)
        | F::Hold(_)
        | F::Write(_)
        | F::Read(_)
        | F::Activation(_)
        | F::Confirm(_)
        | F::Named
        | F::Release(_) => Exit::Rerun(Rerun::Unactivated),
    }
}
