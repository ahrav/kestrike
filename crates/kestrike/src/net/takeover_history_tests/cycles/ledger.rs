//! The boundary ledger of a cycle run: one [`Sample`] of the live tenure at each quiescent boundary, and the
//! conservation judgment over a run's samples.
//!
//! A quiescent boundary is the turn after a tenure's serve phase drained: no request is in flight, the device holds
//! no command, and every INVALIDATE the tenure took has its coverage page write acknowledged. A drain whose requests
//! and device are quiet at its tick bound while an INVALIDATE is still held is sampled there, so the held INVALIDATE
//! fails the ledger by name. A sample is read from the live tenure's own storage, owner, device and store. At a
//! boundary:
//!
//! - every INVALIDATE is published and no capture pass is in flight, and every other transient is exactly zero:
//!   filling slots, reserved bytes, pending ledger marks and escrowed units; live requests and device commands are
//!   zero by the boundary's definition and are recorded, not judged;
//! - retained state is counted, never released to reach zero: the resident slots equal the entries the tenure
//!   restored plus its published fills less its acknowledged removals, no object slot is quarantined on an exhausted
//!   incarnation counter, retired slots, retired bytes and waste are recorded and not judged, the suffix chain holds one suffix for each
//!   tenure that recorded one, and the coverage entries the store holds are at least the acknowledged INVALIDATEs;
//! - every hard cap holds: the suffix chain, each coverage page and the volume's live attachments;
//! - [`conserved`] checks the storage's tables at each sample. A violation fails the ledger by the rule's text. An
//!   unreadable snapshot makes the ledger inconclusive by the snapshot's reason unless a sample fails.
//!
//! [`conserved`]: crate::net::observe::conserved
//!
//! Coverage entries no acknowledged INVALIDATE accounts for are a leak. A run tolerates `epsilon` of them, so a
//! leak of slope `l` entries a cycle fails at boundary `floor(epsilon / l) + 1` ([`crossing_floor`]), and a run of
//! fewer boundaries cannot show that leak and reads inconclusive. A boundary the drain did not reach within its
//! tick bound has no sample, and a run with a missing sample reads inconclusive unless a sample fails. The
//! plateau of resident bytes is judged against a declared band: a spread past it fails, and a spread within it reads
//! inconclusive, since a plateau is publish-aligned; with no band it reads inconclusive while the exact quantities
//! still pass or fail.
//!
//! A publish-aligned boundary also needs an acknowledged checkpoint or frontier publication begun after quiescence.
//! No sample carries one, so the publish-aligned judgment reads inconclusive unless the quiescent judgment fails.

use super::Verdict;
use crate::net::observe::Tables;

/// What the harness accounts for at a boundary: the resident slots as the slots its load restored plus the fills it
/// published less the removals the owner reported, the coverage entries its acknowledged INVALIDATEs wrote, and the
/// suffixes its tenures recorded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Accounted {
    pub(crate) resident_slots: u64,
    pub(crate) coverage_entries: u64,
    pub(crate) suffixes: u64,
}

/// One boundary's reading of the live tenure.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Sample {
    pub(crate) cycle: u32,
    /// Whether a capture pass the tenure started is still in flight.
    pub(crate) capture: bool,
    pub(crate) filling: u64,
    pub(crate) reserved_bytes: u64,
    pub(crate) pending_marks: u64,
    pub(crate) escrow_units: u64,
    pub(crate) held_invalidations: u64,
    pub(crate) requests: u64,
    pub(crate) device_commands: u64,
    pub(crate) resident_slots: u64,
    pub(crate) resident_bytes: u64,
    /// The slots and payload bytes retired and not yet released, the object slots quarantined on an exhausted
    /// incarnation counter, and the bytes the extents hold past their payloads. A tenure's retired slots can exceed
    /// every removal the harness accounts for, so retired slots, retired bytes and waste are recorded and not judged.
    pub(crate) retired_slots: u64,
    pub(crate) retired_bytes: u64,
    pub(crate) quarantined_slots: u64,
    pub(crate) waste_bytes: u64,
    pub(crate) coverage_entries: u64,
    /// The encoded bytes of the largest coverage page and the page cap.
    pub(crate) page_bytes: u64,
    pub(crate) page_cap: u64,
    pub(crate) suffixes: u64,
    pub(crate) attachments: u64,
    pub(crate) accounted: Accounted,
    pub(crate) conservation: Tables,
}

/// A publish-aligned judgment stays inconclusive pending a checkpoint or frontier publication after a quiescent
/// boundary, unless a sample fails.
pub(crate) const UNPUBLISHED: &str =
    "no checkpoint or frontier publication follows a quiescent boundary";

/// The limits a run's samples are judged under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// The unaccounted coverage entries a run tolerates.
    pub(crate) epsilon: u64,
    /// The leak slope, in entries a cycle, the run must be long enough to show; positive.
    pub(crate) slope: u64,
    pub(crate) chain_cap: u64,
    pub(crate) attach_cap: u64,
    /// The accepted band of resident bytes across boundaries; `None` while its owner has declared none.
    pub(crate) band: Option<u64>,
}

/// The conservation judgment of a run: the exact quantities, caps, accounted growth and storage tables at the
/// quiescent boundaries, the publish-aligned judgment, and the plateau.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Conservation {
    pub(crate) exact: Verdict,
    pub(crate) aligned: Verdict,
    pub(crate) plateau: Verdict,
}

/// The boundaries a run needs before a leak of `slope` entries a cycle exceeds `epsilon`: `floor(epsilon / slope)
/// + 1`, or `u64::MAX`, which no run reaches, when that is past `u64::MAX`. `slope` is positive.
pub(crate) fn crossing_floor(epsilon: u64, slope: u64) -> u64 {
    (epsilon / slope).saturating_add(1)
}

/// The first rule `sample` breaks: a quantity's name, or the rule text of tables that disagree. `broken` checks a
/// sample's quantities before its tables.
fn broken(sample: &Sample, limits: &Limits) -> Option<&'static str> {
    let Sample { accounted, .. } = sample;
    let zero = [
        (sample.filling, "exact: filling slots at the boundary"),
        (
            sample.reserved_bytes,
            "exact: reserved bytes at the boundary",
        ),
        (
            sample.pending_marks,
            "exact: pending ledger marks at the boundary",
        ),
        (sample.escrow_units, "exact: escrowed units at the boundary"),
    ];
    if sample.held_invalidations != 0 {
        return Some(
            "no-publish: the boundary holds an INVALIDATE with no acknowledged publication",
        );
    }
    if sample.capture {
        return Some("stuck-capture: a capture pass is in flight at the boundary");
    }
    if let Some((_, rule)) = zero.iter().find(|(value, _)| *value != 0) {
        return Some(rule);
    }
    if sample.quarantined_slots != 0 {
        return Some("exact: quarantined slots at the boundary");
    }
    if sample.resident_slots != accounted.resident_slots {
        return Some("accounted: resident slots differ from restores plus fills less removals");
    }
    if sample.suffixes != accounted.suffixes {
        return Some("accounted: the suffix chain differs from the suffixes the tenures recorded");
    }
    if sample.coverage_entries < accounted.coverage_entries {
        return Some(
            "accounted: the store holds fewer coverage entries than acknowledged INVALIDATEs",
        );
    }
    if sample.coverage_entries - accounted.coverage_entries > limits.epsilon {
        return Some("leak: unaccounted coverage entries past the tolerance");
    }
    if sample.suffixes > limits.chain_cap {
        return Some("cap: the suffix chain is past its cap");
    }
    if sample.page_bytes > sample.page_cap {
        return Some("cap: a coverage page is past its byte cap");
    }
    if sample.attachments > limits.attach_cap {
        return Some("cap: the volume's live attachments are past their cap");
    }
    match sample.conservation {
        Tables::Violated(rule) => Some(rule),
        Tables::Conserved | Tables::Unreadable(_) => None,
    }
}

/// Judges `samples`, one entry per boundary in cycle order, `None` where the drain reached no boundary. The first
/// boundary that breaks a rule fails the run. Otherwise an unreadable snapshot reads inconclusive by its reason,
/// ahead of a missing sample.
pub(crate) fn judge(samples: &[Option<Sample>], limits: &Limits) -> Conservation {
    let taken: Vec<&Sample> = samples.iter().flatten().collect();
    let failed = taken
        .iter()
        .find_map(|sample| broken(sample, limits).map(|rule| (rule, sample.cycle)));
    let unreadable = taken.iter().find_map(|sample| match sample.conservation {
        Tables::Unreadable(reason) => Some(reason),
        Tables::Conserved | Tables::Violated(_) => None,
    });
    let exact = if let Some((rule, cycle)) = failed {
        Verdict::Fail(rule, format!("boundary {cycle}"))
    } else if let Some(reason) = unreadable {
        Verdict::Inconclusive(reason)
    } else if taken.len() < samples.len() {
        Verdict::Inconclusive("a boundary has no sample")
    } else if (samples.len() as u64) < crossing_floor(limits.epsilon, limits.slope) {
        Verdict::Inconclusive("fewer boundaries than the leak crossing floor")
    } else {
        Verdict::Pass
    };
    let aligned = match &exact {
        Verdict::Fail(..) => exact.clone(),
        _ => Verdict::Inconclusive(UNPUBLISHED),
    };
    let bytes = taken.iter().map(|sample| sample.resident_bytes);
    let spread = bytes
        .clone()
        .max()
        .zip(bytes.min())
        .map(|(most, least)| most - least);
    let plateau = match (limits.band, spread) {
        (None, _) => Verdict::Inconclusive("no accepted plateau band"),
        (Some(_), None) => Verdict::Inconclusive("a boundary has no sample"),
        (Some(band), Some(spread)) if spread > band => Verdict::Fail(
            "plateau: resident bytes left the accepted band",
            format!("spread {spread} over band {band}"),
        ),
        (Some(_), Some(_)) if taken.len() < samples.len() => {
            Verdict::Inconclusive("a boundary has no sample")
        }
        (Some(_), Some(_)) => Verdict::Inconclusive(UNPUBLISHED),
    };
    Conservation {
        exact,
        aligned,
        plateau,
    }
}
