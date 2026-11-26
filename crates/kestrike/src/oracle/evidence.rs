//! Durable facts enter a history as declared abstract rows under a named
//! `Hypothesis`, or as qualified rows that name the qualified persistence
//! profile, the attached device's identity, the command and its
//! predecessors, the boundary observed and the writing incarnation; a
//! table that passes tests checker semantics under that hypothesis or
//! profile. A durable fact enters a ledger only through a persistence
//! row.

use std::collections::HashSet;

use super::action::ActionKind;
use super::ids::{Episode, KeyId, Label};
use super::row::Row;

/// The declared assumption an abstract row is checked under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Hypothesis(pub(crate) &'static str);

/// The declared persistence profiles that count as qualified, each with
/// the boundary its evidence must observe for a qualified row to count.
pub(crate) const QUALIFIED: [(&str, &str); 2] = [
    ("declared-16k", "completion-without-volatile-cache"),
    ("declared-512", "completion-without-volatile-cache"),
];

/// The most predecessor commands a qualified row names.
pub(crate) const PREDECESSORS: usize = 2;

/// A concrete row's evidence: the persistence profile and the attached
/// device's Identify identity it was observed under, the command whose
/// effect it covers and the commands that command depends on, the boundary
/// the evidence observed, and the owner incarnation that wrote it, counted
/// from 0 by the restarts before it. Admission, restart and recovered
/// lookup rows carry it to join the scope its profile and identity name.
/// The ledger judges profile, boundary, incarnation and predecessors on
/// persistence rows only, and a qualified exclusion binds whether they
/// count or not; row validation requires a profile and a
/// boundary, and no self-predecessor, on every qualified row. A
/// predecessor names a command of the same incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Qualified {
    pub(crate) profile: &'static str,
    pub(crate) identity: u64,
    pub(crate) command: u32,
    pub(crate) predecessors: [Option<u32>; PREDECESSORS],
    pub(crate) boundary: &'static str,
    pub(crate) incarnation: u64,
}

impl Qualified {
    /// Whether the profile is qualified and the evidence observed the
    /// boundary the profile names.
    pub(crate) fn accepted(&self) -> bool {
        QUALIFIED.contains(&(self.profile, self.boundary))
    }

    /// Whether the evidence names a profile and a boundary and leaves its
    /// own command out of its predecessors.
    pub(crate) fn well_formed(&self) -> bool {
        !self.profile.is_empty()
            && !self.boundary.is_empty()
            && !self.predecessors.contains(&Some(self.command))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Evidence {
    Live,
    Abstract(Hypothesis),
    Qualified(Qualified),
}

/// What a recovery ledger judges a row within: a hypothesis, or a
/// qualified profile under one attached identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Scope {
    Hypothesis(Hypothesis),
    Profile(&'static str, u64),
}

impl Evidence {
    /// Whether the row is recovery evidence, abstract or qualified, which
    /// the recovery ledger judges and every live checker passes over.
    pub(crate) const fn is_recovery(self) -> bool {
        matches!(self, Self::Abstract(_) | Self::Qualified(_))
    }

    /// The scope a recovery ledger judges the row within.
    pub(crate) const fn scope(self) -> Option<Scope> {
        match self {
            Self::Live => None,
            Self::Abstract(hypothesis) => Some(Scope::Hypothesis(hypothesis)),
            Self::Qualified(qualified) => {
                Some(Scope::Profile(qualified.profile, qualified.identity))
            }
        }
    }
}

impl From<Hypothesis> for Evidence {
    fn from(hypothesis: Hypothesis) -> Self {
        Self::Abstract(hypothesis)
    }
}

impl From<Qualified> for Evidence {
    fn from(qualified: Qualified) -> Self {
        Self::Qualified(qualified)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum DurableFact {
    Binding,
    Payload,
    Identity,
    Ownership,
    Freshness,
    PortableExpiry,
    ServingAuthority,
    InvalidationReplayed,
    RecoveryExclusion,
}

impl DurableFact {
    pub(crate) const ALL: [Self; 9] = [
        Self::Binding,
        Self::Payload,
        Self::Identity,
        Self::Ownership,
        Self::Freshness,
        Self::PortableExpiry,
        Self::ServingAuthority,
        Self::InvalidationReplayed,
        Self::RecoveryExclusion,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Decision {
    CallerFreshness,
    DurableBeforeExclusion,
    ReserveExhaustion,
}

impl Decision {
    pub(crate) const ALL: [Self; 3] = [
        Self::CallerFreshness,
        Self::DurableBeforeExclusion,
        Self::ReserveExhaustion,
    ];
}

pub(crate) type FactEntry = (Hypothesis, Episode, KeyId, Label, DurableFact);

pub(crate) fn fact(row: &Row) -> Option<FactEntry> {
    match (
        row.kind,
        row.evidence,
        row.episode,
        row.key(),
        row.label,
        row.fact,
    ) {
        (
            ActionKind::Persistence,
            Evidence::Abstract(hypothesis),
            Some(episode),
            Some(key),
            Some(label),
            Some(fact),
        ) => Some((hypothesis, episode, key, label, fact)),
        _ => None,
    }
}

pub(crate) fn abstract_facts<'r>(rows: impl IntoIterator<Item = &'r Row>) -> HashSet<FactEntry> {
    rows.into_iter().filter_map(fact).collect()
}
