//! The census of a set of cycle runs: every registered interruption site under every failure class as `covered`,
//! `gap`, `undecided` or `not-required`.
//!
//! A site counts for a class only when the descriptor marks it required there. A required site a run reached
//! under the class is `covered` and one no run reached is a `gap`. The sites of
//! [`UNDECIDED`](crate::sim::ledger::UNDECIDED) read `undecided` under every class and earn no credit, and
//! [`census`] refuses a descriptor that marks one required. It also refuses two reports of one run identity, so a
//! second run of an identity never stands for the first.

use std::collections::BTreeSet;

use crate::sim::cut::{Class, Site};
use crate::sim::ledger::UNDECIDED;

use super::Report;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Covered,
    Gap,
    Undecided,
    NotRequired,
}

/// The sites a class requires.
pub(crate) type Descriptor = [(Class, &'static [Site]); 4];

/// The sites the cycle composition requires: a cut whose owner holds a GET, a cut holding a fill's persistence
/// and a cut holding a root or admission publication under process death and host loss, a second crash inside a
/// recovery's own record and reservation changes under host loss, and a cut whose owner holds a GET under a fresh
/// host's first attach. Every cut of the composition falls after its tenure's quiescent boundary, so the
/// persistence and publication sites read `gap`. The composition resets no controller, so it requires no site
/// there.
pub(crate) const REQUIRED: Descriptor = [
    (
        Class::ProcessDeath,
        &[Site::Persistence, Site::Publication, Site::Response],
    ),
    (
        Class::HostOrDevice,
        &[
            Site::Persistence,
            Site::Publication,
            Site::Response,
            Site::RecoveryMutation,
        ],
    ),
    (Class::ControllerReset, &[]),
    (Class::ReplacementAttach, &[Site::Response]),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The descriptor marks an undecided site required.
    UndecidedRequired(Site),
    /// Two reports carry this run identity.
    Repeated(String),
}

/// The status of every site under every class of `descriptor` over `reports`, in class then site order.
///
/// # Errors
///
/// [`Refused::UndecidedRequired`] for the first undecided site the descriptor requires, then
/// [`Refused::Repeated`] for the first identity two reports carry.
pub(crate) fn census(
    descriptor: &Descriptor,
    reports: &[&Report],
) -> Result<Vec<(Class, Site, Status)>, Refused> {
    let undecided = |site: &Site| UNDECIDED.contains(site);
    let required = descriptor.iter().flat_map(|(_, sites)| sites.iter());
    if let Some(site) = required.copied().find(|site| undecided(site)) {
        return Err(Refused::UndecidedRequired(site));
    }
    let mut identities = BTreeSet::new();
    if let Some(report) = (reports.iter()).find(|report| !identities.insert(&report.identity)) {
        return Err(Refused::Repeated(report.identity.clone()));
    }
    let reached = |class: Class, site: Site| {
        (reports.iter()).any(|report| report.reached.contains(&(class, site)))
    };
    let mut rows = Vec::new();
    for (class, sites) in descriptor {
        for site in Site::ALL {
            let status = if undecided(&site) {
                Status::Undecided
            } else if !sites.contains(&site) {
                Status::NotRequired
            } else if reached(*class, site) {
                Status::Covered
            } else {
                Status::Gap
            };
            rows.push((*class, site, status));
        }
    }
    Ok(rows)
}
