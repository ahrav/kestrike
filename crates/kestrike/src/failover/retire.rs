//! The retirement request a holder's check produces, and the reconciler's admission of it.
//!
//! - ACTIONABLE-TRIGGER: [`Retirement::new`] builds a request only on a trigger that shows evidence,
//!   [`Trigger::retires`], so a request on listing or Report evidence rests on an observed foreign attachment or
//!   registrant.
//! - STALE-REQUEST-REFUSED: a request names the `(g, owner, E)` it targets, and [`Retirement::admit`] refuses it
//!   when the shard record holds another value, so a request computed before a flip, an `E` bump or a takeover never retires
//!   the successor's volume. A recovering request, built by `Retirement::recovering` after a fresh bump of unknown
//!   outcome, also admits `(g, owner, E + 1)`: the fresh path durably retains the attachment's refusal before it
//!   returns that request, so every later fresh and restart start of the attachment refuses at its local-record
//!   step, and a record at `E + 1` holds only the bump the request accounts for. Under an operator's release, the
//!   reconciler serves an admitted request for the active volume with [`Reconciler::flip_for`], which admits the
//!   request against each read it flips from, once the spare's attachment listing passes [`check`] against its
//!   standby, and then [`Reconciler::retire`] of the displaced volume. The request alone leaves the shard on its
//!   active volume; a replacement after actual volume loss is a separate reconciler step. The reconciler serves a
//!   request for the spare with [`Reconciler::retire_spare`], which
//!   clears the spare so the reconciler provisions a replacement; the retired volume is never named again.
//!   `Client::retire` uses the same shard record value to admit the request and condition the write.
//!
//! [`check`]: crate::failover::attachments::check
//! [`Reconciler::flip_for`]: crate::failover::reconcile::Reconciler::flip_for
//! [`Reconciler::retire`]: crate::failover::reconcile::Reconciler::retire
//! [`Reconciler::retire_spare`]: crate::failover::reconcile::Reconciler::retire_spare

use crate::failover::attachments::Mismatch;
use crate::failover::evidence::NotSole;
use crate::failover::records::{Host, LayoutRefusal, ShardRecord, VolumeId};
use crate::net::ownership::ShardGeneration;

/// The `(g, owner, E)` of a shard record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    pub generation: ShardGeneration,
    pub owner: Host,
    pub attempts: u32,
}

impl Target {
    pub fn of(record: &ShardRecord) -> Self {
        Self {
            generation: record.generation,
            owner: record.owner,
            attempts: record.attempts,
        }
    }
}

/// The evidence for a holder's retirement request. [`Retirement::new`] accepts only a trigger that
/// [`Trigger::retires`], so every trigger in a [`Retirement`] is an alarm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trigger {
    /// The control plane lists an attachment outside the desired state: an instance outside the check's admitted set,
    /// or the holder's own instance or an admitted peer more than once. A listing without the own record is no
    /// observation.
    Attachment(Mismatch),
    /// The Report refuses the own pair as the holder of a type-2 reservation among admitted registrants.
    Report(NotSole),
    /// The volume's state under the shard record differs from the state the holder's role requires, or the two
    /// records contradict each other.
    VolumeState,
    /// The spare and fresh checks require the holder's one attach over the volume's whole life: exactly one event,
    /// that attach, in an uncompacted history. The owner check at `E > 0` requires the poll's OWNER-EVENTS rule.
    Events,
    /// The volume record holds a modification record.
    Modification,
    /// `Layout::check_floor` refuses the volume record's layout with this refusal.
    Layout(LayoutRefusal),
    Activation,
}

impl Trigger {
    /// Whether the trigger warrants a holder's retirement request. [`Mismatch::Missing`] and
    /// [`NotSole::Unreadable`] represent unavailable observations.
    pub fn retires(&self) -> bool {
        match self {
            Self::Attachment(mismatch) => mismatch.retires(),
            Self::Report(refusal) => refusal.observed(),
            Self::VolumeState
            | Self::Events
            | Self::Modification
            | Self::Layout(_)
            | Self::Activation => true,
        }
    }
}

/// The role a shard record holds a volume in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Active,
    Spare,
}

/// A request that the reconciler retire `volume`, which the shard record held in `role` at `target`. Its trigger
/// always retires ([`Trigger::retires`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retirement {
    pub volume: VolumeId,
    pub role: Role,
    pub target: Target,
    trigger: Trigger,
    recovery: bool,
}

/// The action an admitted request names on the shard record it was admitted against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admitted {
    /// The volume is active: the shard flips to its spare through
    /// [`Reconciler::flip_for`](crate::failover::reconcile::Reconciler::flip_for) under an operator's release.
    Flip,
    /// The volume is the spare: the reconciler replaces the shard record with the admitted record naming no spare.
    DropSpare,
}

/// A shard record mismatch causes [`Retirement::admit`] to reject a request, or the store client to reject a
/// takeover, a planned transfer or a designation: the shard record no longer holds what the request, the takeover,
/// the transfer or the designation names. The store client's spare removal rejects an active-volume request that
/// admission accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stale {
    /// The shard record holds another `(g, owner, E)`, or another value than `E + 1` for a recovering request; for a
    /// takeover, it names no standby or another standby than the successor, or holds `E = 0`; for a planned transfer,
    /// it names another shard, holds `E = 0`, names no standby or another standby than the target, names the target
    /// as owner or names no checkpoint, or its active volume's record enrolls no pair for the target's live attach
    /// ([`Job::Transfer`](crate::host::lane::Job::Transfer)); for a designation, it holds `E = 0` or names the
    /// designated standby as owner.
    Target,
    /// The volume's recorded role differs from the role the request names, or the record omits the volume. The
    /// store client rejects spare removal when the record names the volume as active.
    Volume,
}

impl Retirement {
    /// The request to retire `volume` on `trigger`, or `None` when `trigger` shows no evidence.
    pub fn new(volume: VolumeId, role: Role, target: Target, trigger: Trigger) -> Option<Self> {
        trigger.retires().then_some(Self {
            volume,
            role,
            target,
            trigger,
            recovery: false,
        })
    }

    /// The request for the active volume after a fresh bump of unknown outcome at `target`. [`Retirement::admit`]
    /// admits it at `target` and at `target` with `E + 1`, the record the bump leaves when it commits after the
    /// request. The fresh path retains the attachment's refusal before returning it.
    pub(crate) fn recovering(volume: VolumeId, target: Target, trigger: Trigger) -> Option<Self> {
        Self::new(volume, Role::Active, target, trigger).map(|request| Self {
            recovery: true,
            ..request
        })
    }

    pub fn trigger(&self) -> &Trigger {
        &self.trigger
    }

    /// Admits the request against `record`; the reconciler makes the admitted write by an exact-version
    /// compare-and-swap on the read that holds `record`. A recovering request is also admitted when `record` holds
    /// the request's `(g, owner)` at `E + 1`.
    ///
    /// # Errors
    ///
    /// [`Stale::Target`] before [`Stale::Volume`].
    pub fn admit(&self, record: &ShardRecord) -> Result<Admitted, Stale> {
        let current = Target::of(record);
        let held = self.recovery
            && self.target.attempts.checked_add(1).is_some_and(|attempts| {
                current
                    == Target {
                        attempts,
                        ..self.target
                    }
            });
        if current != self.target && !held {
            return Err(Stale::Target);
        }
        match self.role {
            Role::Active if record.active == self.volume => Ok(Admitted::Flip),
            Role::Spare if record.spare.is_some_and(|(spare, _)| spare == self.volume) => {
                Ok(Admitted::DropSpare)
            }
            _ => Err(Stale::Volume),
        }
    }
}
