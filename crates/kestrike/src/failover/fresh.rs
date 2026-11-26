//! Fresh acquisition brings a new owner to the fencing boundary (FB) on the pre-attached spare a flip made its
//! shard's active volume, then activates the tenure there. [`Fresh::run`] orders its effects in this sequence and
//! refuses at the first failed check: the record and listing checks; the local record and the enrollment of its pair
//! in the volume record, both durable before the `E: 0 -> 1` compare-and-swap, which must succeed with an
//! acknowledgment; the host ID, Register, type-2 Acquire and the fresh Report, from which `Fenced::fresh` builds the
//! FB value; the durable retention of the attachment's refusal; the activation record's write and read-back at unit
//! 0; the Confirm of the tenure's `(g, owner, E)` on a shard record whose `checkpoint` is `None`, first conditioned
//! on the bump's committed version, so a record unchanged since the bump confirms on that first write; the fence of
//! every coverage page in at most [`FENCE_ROUNDS`] rounds, each round a [`Fencing::fence_all`] pass; and the release
//! of that retention. The tenure starts with
//! an empty index and serves misses until [`Fencing::coverage`] answers, so every FILL follows the fence of every
//! page.
//!
//! Invariants:
//!
//! - RecordsBeforeDevice: no device command precedes the record checks of [`poll::fresh`], the provisioning-path
//!   origin and lineage none, and the acknowledged bump, so a host that no longer owns the volume, or a spare the
//!   records or the listing retire, receives nothing from it. At `E > 0` the volume belongs to the restart sequence.
//! - NoWriteBeforeFB: [`Fresh::run`] passes [`Device::write`] and [`Device::read`] the FB value minted by its own fresh Report.
//! - NoEpochReuse: the session comes only from the acknowledged success of the path's own bump. A failed bump, a
//!   timeout and a lost acknowledgment refuse, and a rerun at `E = 1` takes the restart sequence, whose own bump
//!   activates `a = 4`.
//! - FreshIsEmpty, attachment scope: the path continues only on a listing of exactly the own attachment, the
//!   listing premise of [`poll::fresh`].
//! - Every refusal issues no later device command. A refusal on records that name this host and this volume active
//!   at `E = 0` requests the flip naming the read `(g, owner, E)`, or `(g, owner, 1)` once the own bump committed and
//!   the client reported the commit. Under an operator's release, the reconciler serves the flip request with
//!   `Reconciler::flip_for`. These
//!   refusals request nothing: a read that returned no value or shows another owner, another active volume or
//!   `E > 0`; a bump that failed its version condition, after which the next start rereads the stored record; a
//!   deposing or controller-event status on the activation command; a Confirm store outcome that is unavailable,
//!   unknown or a failed version condition; a shard record superseded before Confirm; every refusal of the
//!   coverage fence, whose record and pages a replacement volume reads unchanged; a failed or unacknowledged
//!   enrollment write ([`Check::EnrollWrite`]); a listing whose sole discrepancy is the omission of this host's
//!   attachment ([`Check::Unobserved`]), which keeps the volume; and an
//!   activation read-back that decodes another volume's or tenure's record or damage ([`Check::Activation`]).
//!   Once the bump committed, this sequence leaves `E = 1` on every refusal, so the next start takes the restart
//!   sequence while the record stays as the bump wrote it. Two refusals show another writer moved the record, and
//!   the next start's role read decides there: [`Check::Superseded`], by the Confirm reread, and a
//!   [`Check::Fence`] of a coverage page that a later tenure's session fenced ([`Session::is_activated`]). An
//!   unacknowledged enrollment write precedes the bump and leaves `E = 0`, so the next start reruns the fresh path.
//! - ENROLL-BEFORE-REGISTER: the local record is durable, then the acknowledged volume-record write enrolls its pair
//!   for this host's attach, then the bump, then Register. A pair the volume record refuses requests the empty
//!   spare's flip, and an enrollment write without an acknowledgment requests nothing; a rerun finds the enrolled
//!   pair or writes it.
//! - KEY-PER-ATTACH: [`Fresh::run`] hands [`LocalRecords::persist`] the one key the volume record admits for this
//!   host's live attach, the key of the pair already recorded for it or else [`VolumeRecord::attach_key`]. On a key
//!   mismatch, `persist` returns an error before [`Fresh::run`] writes to the local record, the volume record or the
//!   device.
//! - RetainedRefusal: once `Fenced::fresh` accepts the fresh Report, and before [`Device::write`], [`Fresh::run`]
//!   calls [`LocalRecords::retain_refusal`]. It calls [`LocalRecords::release_refusal`] on activation and on a
//!   refusal from the activation write onward that requests no flip. Once that retention is written, a refusal that
//!   requests a flip and a crash after FB both keep it, so the next restart refuses at its local-record step with
//!   `Local::Retained` and requests the flip. A failed retention refuses with [`Check::Hold`] before the activation
//!   write and removes the local record, so that restart refuses with `Local::Absent`; when the removal also fails,
//!   restart runs on the volume in its state before any medium command. A refusal on an unknown bump outcome calls
//!   `retain_refusal` before [`Fresh::run`] returns. Later fresh and restart starts of a retained attachment refuse
//!   at or before their local-record step, preserving the request's target. A rerun at `E = 0` stopped by a
//!   retained refusal requests the recovery target of the unknown bump that caused the retention.
//! - UNIT-ZERO-INERT: unit 0 carries no authority. The acknowledged bump and the fresh Report are the tenure's
//!   authority, so a delayed write of a predecessor's activation record, or a torn unit 0, refuses this attempt with
//!   no flip: the retention releases, `E = 1` sends the next start to the restart sequence on the same volume, and
//!   no unit-0 content causes volume replacement.
//! - OWNER-FENCED-BEFORE-STANDBY: [`Fresh::run`] fences its coverage pages only after `Fenced::fresh` accepts the
//!   fresh Report. [`Reconciler::record_standby`](crate::failover::reconcile::Reconciler::record_standby) and
//!   [`enroll_standby`](crate::failover::reconcile::enroll_standby) check page 0 for a fence of the shard record's
//!   generation, so a standby registers only after that Report.

use crate::failover::attachments::ControlPlane;
use crate::failover::bounds::Bounds;
use crate::failover::evidence::{NotSole, Pair, Registrant};
use crate::failover::identity::{Exhid, Key as ReservationKey};
use crate::failover::poll::{self, Holder, Reads, Verdict};
use crate::failover::record::LocalRecord;
use crate::failover::records::{
    CreationSource, Enrollment, Lineage, ShardRecord, VolumeId, VolumeRecord,
};
pub use crate::failover::restart::FENCE_ROUNDS;
use crate::failover::restart::{Failed, Local, bump_target, exhausted, parse};
use crate::failover::retire::{Retirement, Role, Target, Trigger};
use crate::net::ownership::Shard;
use crate::storage::activation::{Action, ActivationStep, Command, Fault, RECORD_LEN};
use crate::storage::page_coverage::{FenceRefused, Fencing, FencingRefusal, Withdraw};
use crate::storage::store::{Client, Key, Read, Refusal, Store, StoreError, WatermarkLog};
use crate::storage::{
    ControllerEvent, Crc32c, DeviceStatus, Fenced, ReservationLimits, Session, SessionRefusal,
};

use crate::failover::admission::AdmissionError;

/// Device completions preserve their raw failure status. `Ok` acknowledges the step's completion; Report
/// supplies the complete extended report used to establish the fencing boundary.
pub trait Device {
    fn set_host_id(&mut self, exhid: Exhid) -> Result<(), Failed>;

    fn register(&mut self, own: Pair) -> Result<(), Failed>;

    fn acquire(&mut self, own: Pair) -> Result<(), Failed>;

    fn report(&mut self) -> Result<Vec<u8>, Failed>;

    fn write(&mut self, fenced: &Fenced, unit: u64, bytes: &[u8; RECORD_LEN])
    -> Result<(), Failed>;

    fn read(&mut self, fenced: &Fenced, unit: u64) -> Result<Vec<u8>, Failed>;
}

/// The fresh path's local-record effects on the host's state directory.
pub trait LocalRecords {
    /// Durably writes the local record for the holder's attachment under `key` at the shard record's attempt counter
    /// `attempt`. [`Fresh::run`] bumps `E` only after `persist` succeeds. `key` is the one key the volume record
    /// admits for the holder's live attach: the key of the pair already recorded for it, or else
    /// [`VolumeRecord::attach_key`] (KEY-PER-ATTACH). An implementation returns [`AdmissionError::Key`], before any
    /// write, when the record it would write or keep carries another full key than `key`. If the attachment has a
    /// retained refusal, `persist` returns [`AdmissionError::Retained`] before any write.
    fn persist(
        &mut self,
        holder: &Holder,
        attempt: u32,
        key: ReservationKey,
    ) -> Result<LocalRecord, AdmissionError>;

    /// Durably records that `record`'s binding and key incarnation are excluded from fresh persistence and from the
    /// restart local-record read, until [`LocalRecords::release_refusal`] removes the exclusion. `record` is the one
    /// `persist` returned. When the exclusion cannot be recorded, the implementation removes the local record so that
    /// restart refuses at its local-record step; `retain_refusal` returns the recording error, or `DurableWrite` with
    /// the local record in place when that removal also fails.
    fn retain_refusal(&mut self, record: &LocalRecord) -> Result<(), AdmissionError>;

    /// Durably removes the exclusion [`LocalRecords::retain_refusal`] recorded for `record`; an absent exclusion
    /// counts as removed. A failed removal returns its error with the exclusion recorded, or with the local record
    /// removed when the exclusion can be neither kept nor recorded again; when that removal also fails, it returns
    /// with the exclusion gone and the local record in place.
    fn release_refusal(&mut self, record: &LocalRecord) -> Result<(), AdmissionError>;
}

/// The first failed protocol check, including store, binding, device and post-boundary validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    Records(StoreError),
    Unobserved,
    Deposed,
    Restart,
    Volume(Trigger),
    Origin,
    Exhausted(SessionRefusal),
    Persist(AdmissionError),
    /// The enrollment write of the volume record failed or returned no acknowledgment.
    EnrollWrite(StoreError),
    /// The volume record refuses the local record's pair.
    EnrollRefused(Enrollment),
    Bump(StoreError),
    Local(Local),
    HostId(Failed),
    Register(Failed),
    Acquire(Failed),
    Report(Failed),
    NotSole(NotSole),
    Hold(AdmissionError),
    Write(Failed),
    /// The activation read-back completed with a deposing or controller-event status; any other failed read-back
    /// counts as a torn read of the step.
    Read(Failed),
    /// The activation read-back decoded another volume's or tenure's record, or damage; unit 0 carries no authority,
    /// so the refusal requests no flip (UNIT-ZERO-INERT).
    Activation(Fault),
    Confirm(StoreError),
    /// The shard record names another `(g, owner, E)` or another active volume.
    Superseded,
    /// The shard record names a checkpoint.
    Named,
    Fencing(FencingRefusal),
    Fence(Withdraw),
    /// Page `page` remains unresolved after [`FENCE_ROUNDS`] fencing rounds.
    UnresolvedPage {
        page: u16,
    },
    /// [`LocalRecords::release_refusal`] failed with this error on activation.
    Release(AdmissionError),
    /// Retention failed with `error` while handling refusal `original`: retain after an unknown bump outcome, or
    /// release when the refusal requests no flip.
    Retention {
        original: Box<Check>,
        error: AdmissionError,
    },
}

/// The span of the sequence a refusal falls in: before any device command, between the first command and FB, and
/// after FB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    BeforeCommands,
    BeforeFb,
    AfterFb,
}

impl Check {
    /// For a refusal without a flip request, `true` selects a same-host restart: the check is [`Check::Restart`], or
    /// it follows the path's acknowledged bump with the shard record as the bump wrote it. [`Fresh::run`] bumps
    /// before its first device command, so each check outside `Phase::BeforeCommands` follows the bump, and a
    /// [`Check::Retention`] follows it when its original does. Two checks, each alone or as a retention's original,
    /// read `false` because they show a later tenure, so the next start's role read selects the sequence: a
    /// [`Check::Superseded`], whose Confirm reread showed the shard record naming another `(g, owner, E)` or another
    /// active volume, and a [`Check::Fence`] of a page whose newer fence is an activated session
    /// ([`Session::is_activated`]), which only a later tenure writes. Every other coverage refusal, a newer fence
    /// that is no activated session included, leaves the record as the bump wrote it and reads `true`. A
    /// [`Check::Bump`] reads `false`: [`Fresh::run`] attaches a flip request to every bump error other than a
    /// failed version condition. The phase marks the bump because the first device command is the next point of
    /// refusal after it.
    pub(crate) fn restarts(&self) -> bool {
        matches!(self, Check::Restart)
            || (self.phase() != Phase::BeforeCommands && !self.shows_successor())
    }

    fn shows_successor(&self) -> bool {
        match self {
            Check::Retention { original, .. } => original.shows_successor(),
            Check::Fence(Withdraw::NewerFence { fence, .. }) => Session::is_activated(*fence),
            check => matches!(check, Check::Superseded),
        }
    }

    fn phase(&self) -> Phase {
        match self {
            Check::Records(_)
            | Check::Unobserved
            | Check::Deposed
            | Check::Restart
            | Check::Volume(_)
            | Check::Origin
            | Check::Exhausted(_)
            | Check::Persist(_)
            | Check::EnrollWrite(_)
            | Check::EnrollRefused(_)
            | Check::Bump(_)
            | Check::Local(_) => Phase::BeforeCommands,
            Check::HostId(_)
            | Check::Register(_)
            | Check::Acquire(_)
            | Check::Report(_)
            | Check::NotSole(_) => Phase::BeforeFb,
            Check::Hold(_)
            | Check::Write(_)
            | Check::Read(_)
            | Check::Activation(_)
            | Check::Confirm(_)
            | Check::Superseded
            | Check::Named
            | Check::Fencing(_)
            | Check::Fence(_)
            | Check::UnresolvedPage { .. }
            | Check::Release(_) => Phase::AfterFb,
            Check::Retention { original, .. } => original.phase(),
        }
    }
}

/// A refused activation identifies the failed check and the requested flip's `(g, owner, E)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub check: Check,
    pub flip: Option<Target>,
}

impl Refused {
    /// A recovering request accounts for a bump that may still commit after an unknown outcome, including the bump
    /// behind a refusal retained when `flip.attempts == 0`. A [`Check::Retention`] requests the exact target.
    pub fn retirement(&self, volume: VolumeId) -> Option<Retirement> {
        let trigger = match &self.check {
            Check::Volume(trigger) => trigger.clone(),
            Check::NotSole(refusal) if refusal.observed() => Trigger::Report(*refusal),
            _ => Trigger::Activation,
        };
        let flip = self.flip?;
        match self.check {
            Check::Bump(StoreError::Unknown) => Retirement::recovering(volume, flip, trigger),
            Check::Persist(AdmissionError::Retained) if flip.attempts == 0 => {
                Retirement::recovering(volume, flip, trigger)
            }
            _ => Retirement::new(volume, Role::Active, flip, trigger),
        }
    }
}

/// The activated session, its own Report's fencing boundary, the fully fenced inherited coverage, and the recorded
/// pairs of the enrollment's volume record, which seed the serving authority's admitted set.
#[derive(Debug)]
pub struct Activated {
    session: Session,
    fenced: Fenced,
    fencing: Fencing,
    recorded: Vec<Pair>,
    /// The subset of `recorded` that the enrollment's volume record associates with an ended attach.
    ended: Vec<Pair>,
}

impl Activated {
    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn fencing(&self) -> &Fencing {
        &self.fencing
    }

    pub(crate) fn into_parts(self) -> (Session, Fenced, Fencing, Vec<Pair>, Vec<Pair>) {
        (
            self.session,
            self.fenced,
            self.fencing,
            self.recorded,
            self.ended,
        )
    }
}

/// `Refusals` tracks fresh-activation refusals by the refusing check's phase, refusals that requested a flip, and
/// the last refusal's check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Refusals {
    pub before_commands: u64,
    pub before_fb: u64,
    pub after_fb: u64,
    pub flip_requests: u64,
    pub last: Option<Check>,
}

impl Refusals {
    fn record(&mut self, refused: &Refused) {
        *match refused.check.phase() {
            Phase::BeforeCommands => &mut self.before_commands,
            Phase::BeforeFb => &mut self.before_fb,
            Phase::AfterFb => &mut self.after_fb,
        } += 1;
        self.flip_requests += u64::from(refused.flip.is_some());
        self.last = Some(refused.check.clone());
    }
}

/// Record-authorized fresh activation for one pre-attached volume. The holder identifies the host and
/// attachment; the bounds and reservation limits govern its Report and the page coverage.
#[derive(Debug, Clone, Copy)]
pub struct Fresh {
    pub shard: Shard,
    pub holder: Holder,
    pub bounds: Bounds,
    pub limits: ReservationLimits,
    /// The intervals of one key the coverage keeps on a page.
    pub intervals: usize,
}

impl Fresh {
    pub fn run<S: Store, L: WatermarkLog>(
        &self,
        client: &mut Client<S, L>,
        plane: &mut impl ControlPlane,
        local: &mut impl LocalRecords,
        device: &mut impl Device,
        refusals: &mut Refusals,
    ) -> Result<Activated, Refused> {
        let result = self.attempt(client, plane, local, device);
        if let Err(refused) = &result {
            refusals.record(refused);
        }
        result
    }

    fn attempt<S: Store, L: WatermarkLog>(
        &self,
        client: &mut Client<S, L>,
        plane: &mut impl ControlPlane,
        local: &mut impl LocalRecords,
        device: &mut impl Device,
    ) -> Result<Activated, Refused> {
        let (shard, volume) = self.records(client, plane)?;
        let read = Target::of(shard.value());
        let held = volume.value();
        let host = self.holder.host;
        let Some(key) = held.enrollment_key(host) else {
            let refusal = if held.live(host).is_some() {
                Enrollment::Key
            } else {
                Enrollment::Unattached
            };
            return Err(Refused {
                check: Check::EnrollRefused(refusal),
                flip: Some(read),
            });
        };
        let record = local
            .persist(&self.holder, read.attempts, key)
            .map_err(|error| Refused {
                check: Check::Persist(error),
                flip: Some(read),
            })?;
        if !self.holder.binds(record.binding()) {
            return Err(Refused {
                check: Check::Local(Local::Binding),
                flip: Some(read),
            });
        }
        let enrolled = match volume
            .value()
            .enroll(self.holder.host, record.pair(), &self.bounds)
        {
            Ok(Some(next)) => client.replace(&volume, next).map_err(|error| Refused {
                check: Check::EnrollWrite(error),
                flip: None,
            })?,
            Ok(None) => volume,
            Err(refusal) => {
                return Err(Refused {
                    check: Check::EnrollRefused(refusal),
                    flip: Some(read),
                });
            }
        };
        self.acquire_recorded(client, local, device, &shard, &record, &enrolled)
    }

    fn acquire_recorded<S: Store, L: WatermarkLog>(
        &self,
        client: &mut Client<S, L>,
        local: &mut impl LocalRecords,
        device: &mut impl Device,
        shard: &Read<ShardRecord>,
        record: &LocalRecord,
        enrolled: &Read<VolumeRecord>,
    ) -> Result<Activated, Refused> {
        let read = Target::of(shard.value());
        let own = record.pair();
        let bumped = client.bump(shard).map_err(|error| {
            let unknown = matches!(error, StoreError::Unknown);
            let uncommitted = matches!(error, StoreError::Refused(Refusal::Condition));
            let refused = Refused {
                flip: (!uncommitted).then(|| bump_target(&error, read)),
                check: Check::Bump(error),
            };
            match unknown.then(|| local.retain_refusal(record)) {
                Some(Err(error)) => Refused {
                    check: Check::Retention {
                        original: Box::new(refused.check),
                        error,
                    },
                    ..refused
                },
                _ => refused,
            }
        })?;
        let own_target = Target {
            attempts: read.attempts + 1,
            ..read
        };
        let refuse = |check| Refused {
            check,
            flip: Some(own_target),
        };
        let committed = bumped.committed().clone();
        let session =
            Session::activate(bumped).expect("the record checks refused an exhausted generation");
        device
            .set_host_id(own.exhid)
            .map_err(|failed| refuse(Check::HostId(failed)))?;
        device
            .register(own)
            .map_err(|failed| refuse(Check::Register(failed)))?;
        device
            .acquire(own)
            .map_err(|failed| refuse(Check::Acquire(failed)))?;
        let bytes = device
            .report()
            .map_err(|failed| refuse(Check::Report(failed)))?;
        let mut entries = vec![
            Registrant {
                cntlid: 0,
                holder: false,
                pair: own,
            };
            self.limits.registrants() as usize
        ];
        let fenced = parse(self.limits, &bytes, &mut entries)
            .and_then(|report| Fenced::fresh(&report, own, &self.bounds))
            .map_err(|refusal| refuse(Check::NotSole(refusal)))?;
        local
            .retain_refusal(record)
            .map_err(|error| refuse(Check::Hold(error)))?;
        let fencing =
            match self.serve_from(client, device, &fenced, &session, own_target, &committed) {
                Ok(fencing) => {
                    local
                        .release_refusal(record)
                        .map_err(|error| refuse(Check::Release(error)))?;
                    fencing
                }
                Err(refused) if refused.flip.is_none() => {
                    return Err(match local.release_refusal(record) {
                        Ok(()) => refused,
                        Err(error) => Refused {
                            check: Check::Retention {
                                original: Box::new(refused.check),
                                error,
                            },
                            flip: None,
                        },
                    });
                }
                Err(refused) => return Err(refused),
            };
        Ok(Activated {
            session,
            fenced,
            fencing,
            recorded: enrolled.value().recorded_pairs(),
            ended: enrolled.value().ended_attach_pairs().copied().collect(),
        })
    }

    fn serve_from<S: Store, L: WatermarkLog>(
        &self,
        client: &mut Client<S, L>,
        device: &mut impl Device,
        fenced: &Fenced,
        session: &Session,
        own_target: Target,
        committed: &Read<ShardRecord>,
    ) -> Result<Fencing, Refused> {
        self.activate(device, fenced, session).map_err(|check| {
            let ended = matches!(&check, Check::Read(Failed(Some(status))) | Check::Write(Failed(Some(status)))
                if ends_tenure(*status));
            // UNIT-ZERO-INERT: a read-back of another tenure's record or of damage proves no volume loss.
            let inert = matches!(check, Check::Activation(_));
            Refused {
                flip: (!ended && !inert).then_some(own_target),
                check,
            }
        })?;
        let confirmed = self.confirm(client, own_target, committed)?;
        // A fence refusal comes from the shard's record or its coverage pages, which a replacement volume reads
        // unchanged, so it requests no flip, as in the restart and takeover sequences.
        self.fence(client, confirmed.value(), session)
            .map_err(|check| Refused { check, flip: None })
    }

    fn records<S: Store, L: WatermarkLog>(
        &self,
        client: &mut Client<S, L>,
        plane: &mut impl ControlPlane,
    ) -> Result<(Read<ShardRecord>, Read<VolumeRecord>), Refused> {
        let unread = |error| Refused {
            check: Check::Records(error),
            flip: None,
        };
        let volume = client
            .read::<VolumeRecord>(Key::Volume(self.holder.volume))
            .map_err(unread)?;
        let shard = client
            .read::<ShardRecord>(Key::Shard(self.shard))
            .map_err(unread)?;
        let record = shard.value();
        let quiet = |check| Refused { check, flip: None };
        if record.active == self.holder.volume
            && record.owner == self.holder.host
            && record.attempts > 0
        {
            return Err(quiet(Check::Restart));
        }
        if record.active != self.holder.volume || record.owner != self.holder.host {
            return Err(quiet(Check::Deposed));
        }
        let listed = plane.attachments(&self.holder.volume).ok();
        let reads = Reads {
            shard: Some(record),
            volume: Some(volume.value()),
            listed: listed.as_deref(),
            peers: &[],
        };
        match poll::fresh(&self.holder, &reads) {
            Verdict::Continue => {}
            Verdict::Unobserved => return Err(quiet(Check::Unobserved)),
            Verdict::Deposed | Verdict::Withdraw => return Err(quiet(Check::Deposed)),
            Verdict::Retire(retirement) => {
                return Err(Refused {
                    flip: Some(retirement.target),
                    check: Check::Volume(retirement.trigger().clone()),
                });
            }
        }
        let refuse = |check| Refused {
            check,
            flip: Some(Target::of(record)),
        };
        let held = volume.value();
        if held.source != CreationSource::Provisioned || held.lineage != Lineage::None {
            return Err(refuse(Check::Origin));
        }
        exhausted(record).map_err(|refusal| refuse(Check::Exhausted(refusal)))?;
        Ok((shard, volume))
    }

    fn activate(
        &self,
        device: &mut impl Device,
        fenced: &Fenced,
        session: &Session,
    ) -> Result<(), Check> {
        let crc = Crc32c::detect();
        let mut step = ActivationStep::new(self.holder.volume, session);
        let mut record = [0; RECORD_LEN];
        let mut action = step.start(crc, &mut record);
        loop {
            action = match action {
                Action::Submit(Command::Write { unit }) => {
                    device.write(fenced, unit, &record).map_err(Check::Write)?;
                    step.written()
                }
                Action::Submit(Command::Read { unit }) => {
                    let bytes = match device.read(fenced, unit) {
                        Err(failed @ Failed(Some(status))) if ends_tenure(status) => {
                            return Err(Check::Read(failed));
                        }
                        result => result.ok(),
                    };
                    step.read(crc, bytes.as_deref())
                }
                Action::Activated => return Ok(()),
                Action::Refused(fault) => return Err(Check::Activation(fault)),
            };
        }
    }

    /// A commit conditioned on `bumped`'s version shows that the record still held the bumped value, so the Confirm
    /// reads the record only after that condition fails or when `bumped` names a checkpoint.
    fn confirm<S: Store, L: WatermarkLog>(
        &self,
        client: &mut Client<S, L>,
        own: Target,
        bumped: &Read<ShardRecord>,
    ) -> Result<Read<ShardRecord>, Refused> {
        let refuse = |check| Refused {
            check,
            flip: Some(own),
        };
        let store_refusal = |error| Refused {
            check: Check::Confirm(error),
            flip: (!matches!(
                error,
                StoreError::Unavailable
                    | StoreError::Unknown
                    | StoreError::Refused(Refusal::Condition)
            ))
            .then_some(own),
        };
        if bumped.value().checkpoint.is_none() {
            match client.replace(bumped, *bumped.value()) {
                Err(StoreError::Refused(Refusal::Condition)) => {}
                result => return result.map_err(store_refusal),
            }
        }
        let read = client
            .read::<ShardRecord>(Key::Shard(self.shard))
            .map_err(store_refusal)?;
        let record = *read.value();
        if Target::of(&record) != own || record.active != self.holder.volume {
            return Err(Refused {
                check: Check::Superseded,
                flip: None,
            });
        }
        if record.checkpoint.is_some() {
            return Err(refuse(Check::Named));
        }
        client.replace(&read, record).map_err(store_refusal)
    }

    fn fence<S: Store, L: WatermarkLog>(
        &self,
        client: &mut Client<S, L>,
        record: &ShardRecord,
        session: &Session,
    ) -> Result<Fencing, Check> {
        Fencing::fenced(client, record, session, self.intervals, FENCE_ROUNDS).map_err(|refused| {
            match refused {
                FenceRefused::Fencing(refusal) => Check::Fencing(refusal),
                FenceRefused::Fence(withdraw) => Check::Fence(withdraw),
                FenceRefused::Unresolved { page } => Check::UnresolvedPage { page },
            }
        })
    }
}

fn ends_tenure(status: DeviceStatus) -> bool {
    status.deposes() || ControllerEvent::of_status(status).is_some()
}

#[cfg(test)]
#[path = "fresh_tests.rs"]
pub(crate) mod tests;
