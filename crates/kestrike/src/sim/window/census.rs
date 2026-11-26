//! Coverage joins descriptor boundaries to the ledger by cut-table position.
//! A required boundary with no table entry remains visible as a gap.
//!
//! The key `operation.site.occurrence.side.Class` names a boundary and class
//! within one profile descriptor. Point identity, before/after side and class
//! determine row order. Bare keys for sites without points follow in registry
//! order. Both forms use names free of spaces and equals signs. One qualifying
//! table cut covers its required row; campaign credit requires a separate assessment.

use crate::sim::cut::{Boundary, Class, Cut, Descriptor, Site};
use crate::sim::ledger::{Ledger, UNDECIDED};
use crate::sim::recovery::Recovery;

/// Point rows distinguish an optional interruption from a required one whose
/// evidence is missing. Bare-site rows distinguish sites in `UNDECIDED` from
/// sites classified as `Unreached`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Status {
    /// At least one cut passed with attributed evidence, the planned mask and class, and a drained queue.
    Covered,
    /// A required boundary and class with zero qualifying cuts.
    Gap,
    /// The descriptor declares this point at an optional site.
    NotRequired,
    /// Exclusion or successor visibility with zero descriptor points.
    Undecided,
    /// Another registered site with zero descriptor points.
    Unreached,
}

/// Each covered cut contributes once to its window's count.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Row {
    pub(crate) name: String,
    pub(crate) status: Status,
    pub(crate) count: usize,
}

/// The caller supplies a ledger whose indices refer to the cuts in this profile's table.
pub(crate) fn census(profile: Recovery, ledger: &Ledger) -> Vec<Row> {
    rows(&profile.descriptor(), &profile.table(), ledger)
}

pub(crate) fn recorded(loaded: &crate::sim::trace::Loaded) -> Option<([usize; 6], Vec<Row>)> {
    let profile = crate::sim::trace::recorded_profile(&loaded.fields).and_then(Recovery::named)?;
    let table = profile.table();
    let ledger = crate::sim::ledger::rebuild(&loaded.events, table.len() as u32).ok()?;
    Some((
        crate::sim::ledger::stage_counts(&ledger),
        rows(&profile.descriptor(), &table, &ledger),
    ))
}

/// Each ledger index refers to its position in `table`.
pub(super) fn rows(descriptor: &Descriptor, table: &[Cut], ledger: &Ledger) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut points: Vec<_> = descriptor.points.iter().collect();
    points.sort_unstable_by_key(|point| point.identity());
    let classes: Vec<_> = Class::ALL
        .into_iter()
        .filter(|c| descriptor.classes.contains(c))
        .collect();
    for point in points {
        let (operation, site, occurrence) = point.identity();
        let required = descriptor.requires(site);
        let site_name = Site::from_code(site)
            .expect("a registered descriptor site")
            .name();
        for boundary in Boundary::ALL {
            let side = match boundary {
                Boundary::Before => "before",
                Boundary::After => "after",
            };
            for &class in &classes {
                let count = table
                    .iter()
                    .enumerate()
                    .filter(|&(at, cut)| {
                        (cut.operation, cut.site, cut.occurrence) == (operation, site, occurrence)
                            && cut.boundary == boundary
                            && cut.class == class
                            && ledger.covers(at as u32, cut)
                    })
                    .count();
                let status = if !required {
                    Status::NotRequired
                } else if count == 0 {
                    Status::Gap
                } else {
                    Status::Covered
                };
                rows.push(Row {
                    name: format!("{operation}.{site_name}.{occurrence}.{side}.{class:?}"),
                    count,
                    status,
                });
            }
        }
    }
    for site in Site::ALL {
        if !descriptor
            .points
            .iter()
            .any(|point| point.site == site as u16)
        {
            let status = if UNDECIDED.contains(&site) {
                Status::Undecided
            } else {
                Status::Unreached
            };
            rows.push(Row {
                name: site.name().to_owned(),
                status,
                count: 0,
            });
        }
    }
    rows
}
