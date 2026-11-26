//! Outcome vocabulary that separates observations carrying information about
//! a key's mapping from those that leave every expectation unchanged.
//!
//! `Acknowledged`, `Hit`, `Missing`, `Expired`, `Complete`, `Damaged` and
//! every known PUT outcome move a checker's model; every [`NoInformation`]
//! member and an `Unknown` PUT outcome leave the expected mapping, every
//! acknowledgment and every right as it was. A visibility end with a cause
//! ends one label's visibility and preserves every acknowledgment.

use super::attempt::PutOutcome;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Outcome {
    /// An effect took hold: a fill was admitted, or a publication,
    /// replacement, invalidation or close was acknowledged.
    Acknowledged,
    /// A lookup acquired a candidate under the row's label.
    Hit,
    /// A lookup proved the key absent.
    Missing,
    /// A lookup found the key's candidate at or past its deadline.
    Expired,
    /// A delivery handed off every byte of the label's content, or a
    /// command's terminal reported success.
    Complete,
    /// A delivery handed off the row's payload as an exact verified prefix
    /// and then ended with a typed failure, or a command's terminal reported
    /// that failure.
    Damaged(Failure),
    /// A remote upload attempt's client outcome.
    Put(PutOutcome),
    NoInformation(NoInformation),
}

impl Outcome {
    /// The outcome family a row kind must use, or `None` for outcomes every
    /// outcome-bearing kind admits.
    pub(crate) const fn family(self) -> Option<OutcomeFamily> {
        match self {
            Self::Acknowledged => Some(OutcomeFamily::Effect),
            Self::Hit | Self::Missing | Self::Expired => Some(OutcomeFamily::Lookup),
            Self::Complete | Self::Damaged(_) => Some(OutcomeFamily::Delivery),
            Self::Put(_) => Some(OutcomeFamily::Put),
            Self::NoInformation(_) => None,
        }
    }

    pub(crate) const fn carries_information(self) -> bool {
        !matches!(
            self,
            Self::NoInformation(_) | Self::Put(PutOutcome::Unknown)
        )
    }

    /// Whether a client received this outcome as the serving tenure's
    /// reply, so its row carries that tenure's tag and the client's
    /// acceptance. A cancelled, timed-out or dropped request and an
    /// `Unknown` PUT outcome name no reply.
    pub(crate) const fn is_answer(self) -> bool {
        match self {
            Self::NoInformation(member) => !matches!(
                member,
                NoInformation::Cancelled | NoInformation::TimedOut | NoInformation::Dropped
            ),
            Self::Put(PutOutcome::Unknown) => false,
            _ => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum OutcomeFamily {
    Effect,
    Lookup,
    Delivery,
    Put,
}

/// Outcomes that end an attempt and leave the expected mapping, every
/// acknowledgment and every right unchanged.
///
/// A cancelled or timed-out command is recorded here only for the outcome
/// observed before its terminal; the terminal row that follows carries the
/// command's real result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum NoInformation {
    Contended,
    Closed,
    ClockUnavailable,
    LeaseLimit,
    RetainLimit,
    /// A publication, replacement, invalidation or PUT retry the cache
    /// refused.
    Refused,
    Cancelled,
    TimedOut,
    /// The device discarded the command, and the discard is the last event
    /// the fixture records for it.
    Dropped,
}

impl NoInformation {
    pub(crate) const ALL: [Self; 9] = [
        Self::Contended,
        Self::Closed,
        Self::ClockUnavailable,
        Self::LeaseLimit,
        Self::RetainLimit,
        Self::Refused,
        Self::Cancelled,
        Self::TimedOut,
        Self::Dropped,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Failure {
    HeaderMismatch,
    /// Chunk `index` failed its checksum after every earlier chunk verified.
    ChunkMismatch {
        index: u32,
    },
    DeviceError,
    Short,
    Quiesced,
    Lost,
}

/// Each visibility cause ends one label's visibility and preserves every
/// acknowledgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum VisibilityCause {
    /// An invalidation of a key sharing the fingerprint removed this label.
    CollisionCollateral,
    Eviction,
    Expiry,
    /// The grace interval after a retirement ended.
    GraceEnd,
}

impl VisibilityCause {
    pub(crate) const ALL: [Self; 4] = [
        Self::CollisionCollateral,
        Self::Eviction,
        Self::Expiry,
        Self::GraceEnd,
    ];
}
