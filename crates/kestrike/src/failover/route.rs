//! RouteMonotonic over `(g, a)`: the per-shard high-water never decreases in `(g, a)`, ordered by generation, then
//! activated epoch, and a Dark route keeps the epoch it recorded when its generation darkened. Equal `(g, a)` with distinct host identifiers produce one Conflict value that withholds requests
//! and responses until a higher tenure. A generation has one volume, so a retirement frame of the held or a later
//! generation darkens that generation at any epoch and from any state: the route answers "do not route" for every
//! tenure of the generation and rebinds only at a later one. An `Invalid` frame raises the route to its tenure as a
//! Candidate, which withdraws a binding at that tenure: a READY at the same tenure binds it again, and every lower
//! tenure stays refused. The client merges a not-serving reply as `Invalid` only for a withdrawal it ordered after the
//! route's binding admissions (WITHDRAWAL-NEEDS-SESSION on `ShardRoutes::reply`) and as a `Candidate` otherwise.

use std::cmp::Ordering;

use super::identity::Exhid;
use super::route_merge::merge_identity;
use crate::net::ownership::{ActivatedEpoch, ShardGeneration, Tenure, session_of};

/// An authenticated holder frame, a retirement observation or an invalid-flag observation, for one shard. A tenure with epoch 0 sorts below every
/// activated epoch of its generation.
#[derive(Debug, Clone, Copy)]
pub struct HolderFrame {
    pub tenure: Tenure,
    pub kind: FrameKind,
}

/// What a frame reports about its tenure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// The holder announces the tenure; requests may connect. A Candidate at a Bound tenure keeps the binding.
    Candidate,
    /// READY binds the session to this tenure and admits responses.
    Ready,
    /// The frame's volume is retired; it darkens every tenure of `tenure.generation`, a bound session included. The
    /// tenure is the retired volume's own; merge reads its generation and epoch and ignores its host. A tenure from an ownership reply names the shard's current owner, and
    /// marking it retired darkens that live generation until a later one arrives.
    Retired,
    /// The responder reports its own tenure with its serving or liveness bit clear, or with no volume named, in a
    /// withdrawal the caller ordered after the route's binding admissions; it withdraws a binding at that tenure.
    Invalid,
}

/// Candidate permits connection; Bound permits responses. Conflict withholds both until a higher tenure. Dark withholds
/// both until a later generation and records the retired generation and an epoch. When the held generation darkens,
/// the epoch is the larger of the held epoch and the retirement frame's epoch; when a later generation darkens, it is
/// the frame's epoch. Later frames of that generation leave Dark unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HighWater {
    Candidate(Tenure),
    Bound(Tenure),
    Conflict {
        generation: ShardGeneration,
        epoch: ActivatedEpoch,
    },
    Dark {
        generation: ShardGeneration,
        epoch: ActivatedEpoch,
    },
}

/// The `(g, a)` order key, the session `g·2^32 + a`. `ShardGeneration` holds `g < 2^32`, so the narrowing is exact.
#[inline]
pub(crate) fn key(generation: ShardGeneration, epoch: ActivatedEpoch) -> u64 {
    session_of(generation.get() as u32, epoch.get())
}

/// The host identifier as one integer; merge compares identities only for equality.
#[inline]
pub(crate) fn identity(host: Exhid) -> u128 {
    u128::from_ne_bytes(host.bytes())
}

impl HighWater {
    pub fn generation(self) -> ShardGeneration {
        match self {
            Self::Candidate(tenure) | Self::Bound(tenure) => tenure.generation,
            Self::Conflict { generation, .. } | Self::Dark { generation, .. } => generation,
        }
    }

    pub fn epoch(self) -> ActivatedEpoch {
        match self {
            Self::Candidate(tenure) | Self::Bound(tenure) => tenure.epoch,
            Self::Conflict { epoch, .. } | Self::Dark { epoch, .. } => epoch,
        }
    }

    pub fn host(self) -> Option<Exhid> {
        match self {
            Self::Candidate(tenure) | Self::Bound(tenure) => Some(tenure.host),
            Self::Conflict { .. } | Self::Dark { .. } => None,
        }
    }

    /// The caller authenticates frames for this shard. Every frame of a Dark route's generation or an earlier one
    /// returns the route unchanged. A retirement of the held generation darkens it whatever its epoch or host; a
    /// retirement of a later generation darkens that generation. Otherwise lower tenures keep the route, equal-`(g, a)`
    /// identity conflicts persist until a higher tenure, and an invalid frame merges as a Candidate. At a Bound route's
    /// own tenure, a Candidate frame keeps the binding and an invalid frame leaves a Candidate of that tenure. A route
    /// that leaves a Bound `(g, a)` binds that `(g, a)` again only to the same host, and otherwise only a higher
    /// `(g, a)`.
    #[inline]
    pub fn merge(current: Option<Self>, frame: HolderFrame) -> Self {
        let tenure = frame.tenure;
        let Some(old) = current else {
            return match frame.kind {
                FrameKind::Retired => Self::Dark {
                    generation: tenure.generation,
                    epoch: tenure.epoch,
                },
                FrameKind::Ready => Self::Bound(tenure),
                FrameKind::Candidate | FrameKind::Invalid => Self::Candidate(tenure),
            };
        };
        let (generation, epoch, held_host, held_conflict) = match old {
            Self::Candidate(held) | Self::Bound(held) => {
                (held.generation, held.epoch, identity(held.host), false)
            }
            Self::Conflict { generation, epoch } => (generation, epoch, 0, true),
            Self::Dark { generation, .. } if tenure.generation <= generation => return old,
            Self::Dark { generation, epoch } => (generation, epoch, 0, false),
        };
        if frame.kind == FrameKind::Retired {
            return Self::retire(old, generation, epoch, tenure);
        }
        let held_key = key(generation, epoch);
        let frame_key = key(tenure.generation, tenure.epoch);
        let (_, _, conflict, admitted) = merge_identity(
            held_key,
            held_host,
            held_conflict,
            frame_key,
            identity(tenure.host),
        );
        let keeps = !admitted
            || (matches!(old, Self::Bound(_))
                && frame_key == held_key
                && frame.kind != FrameKind::Invalid);
        match (conflict, keeps, frame.kind) {
            (true, ..) => Self::Conflict { generation, epoch },
            (false, true, _) => old,
            (false, false, FrameKind::Ready) => Self::Bound(tenure),
            (false, false, _) => Self::Candidate(tenure),
        }
    }

    /// The route after a retirement of `tenure` reaches `old`, which holds `generation` and `epoch`: an earlier
    /// generation leaves it, the held generation darkens at the larger epoch, and a later generation darkens the route
    /// at that generation and the frame's epoch.
    #[cold]
    fn retire(
        old: Self,
        generation: ShardGeneration,
        epoch: ActivatedEpoch,
        tenure: Tenure,
    ) -> Self {
        match tenure.generation.cmp(&generation) {
            Ordering::Less => old,
            Ordering::Equal => Self::Dark {
                generation,
                epoch: tenure.epoch.max(epoch),
            },
            Ordering::Greater => Self::Dark {
                generation: tenure.generation,
                epoch: tenure.epoch,
            },
        }
    }

    pub fn requests(self) -> bool {
        matches!(self, Self::Candidate(_) | Self::Bound(_))
    }

    pub fn response(self, tenure: Tenure) -> bool {
        self == Self::Bound(tenure)
    }
}
