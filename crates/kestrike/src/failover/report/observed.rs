//! The values an owner's driver holds and the owner does not, which [`Owner::report_entry`] reads beside the owner's
//! own state, and conversions into the entry's labels and counts from both: the driver's alarm, tally and enumeration
//! check, and the owner's registrant judgment, hold, unit damage, recovery report, suffix backlog and read counts. A
//! part the driver lacks reads unavailable (NO-INVENTED-VALUES).
//!
//! [`Owner::report_entry`]: crate::net::owner::Owner::report_entry

use super::{
    Backlog, Captures, Damage, Enumeration, Gauge, Hold, RecoveryStatus, RecoveryTimes,
    Registrants, Retention, StoreOutcomes, Watermark,
};
use crate::failover::attachments::Mismatch;
use crate::storage::checkpoint::{SuffixDue, UnitDamage};
use crate::storage::store::{Alarm, Tallied, Tally};
use crate::storage::{
    HoldState, RecoveryPhase, RecoveryReport, RegistrantJudgment, SuffixBacklog, VolumeReport,
};

/// The driver's part of one owner's entry.
///
/// [`Owner::report_entry`]: crate::net::owner::Owner::report_entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observed {
    /// The last enumeration outcome: the `failover::attachments::check` result of a listing the call returned, an
    /// empty listing included; `Unlisted` when the last listing call returned no listing; `Unavailable` when the driver
    /// holds no outcome.
    pub enumeration: Enumeration,
    /// The store client's alarm.
    pub alarm: Option<Alarm>,
    /// The store client's tally over the tenure's calls: the tally since `Client::open` for a driver that opens its
    /// owner's client at the tenure's activation, or the gain over a baseline the driver takes at the tenure's start
    /// (`Tally::since`).
    pub store: Option<Tally>,
    /// The owner process's recovery status, its attempts started on the owner's microsecond turn clock, which
    /// `now_us` of [`Owner::report_entry`] ages: [`RecoveryStatus::NO_ATTEMPT`] before any attempt, which reads a known
    /// zero attempt count, and `None` when the driver holds no status, which reads every recovery field unavailable.
    ///
    /// [`Owner::report_entry`]: crate::net::owner::Owner::report_entry
    pub recovery: Option<RecoveryStatus>,
    /// The tenure's capture refusals and abandonments.
    pub captures: Captures,
    /// The tenure's possibly-named set, as [`super::Pressure::unresolved`] reads it.
    pub quarantine: Gauge,
    /// The [`SuffixDue`] the last suffix store step returned, the log's signal sampled before the step's writes.
    /// `None` before the first step, and when the last step sampled nothing: it found the capture mutex held or
    /// poisoned, or the storage in finalization.
    pub suffix_due: Option<SuffixDue>,
    /// The tenure stands at a bound that asks for a planned same-host restart: the suffix handoff signal, no free
    /// checkpoint slot, or a stage refused for placement. The driver sets it for each cause.
    pub roll_due: Option<bool>,
    /// A planned same-host restart runs.
    pub roll_active: Option<bool>,
}

impl Observed {
    pub const UNAVAILABLE: Self = Self {
        enumeration: Enumeration::Unavailable,
        alarm: None,
        store: None,
        recovery: None,
        captures: Captures {
            refused: None,
            abandoned: None,
        },
        quarantine: Gauge::Unavailable,
        suffix_due: None,
        roll_due: None,
        roll_active: None,
    };
}

impl From<SuffixBacklog> for Backlog {
    fn from(backlog: SuffixBacklog) -> Self {
        Self {
            blocks: Gauge::known(backlog.blocks, backlog.limit),
            flush_lag_us: backlog.age_ns.map(|age| age / 1_000),
        }
    }
}

impl From<Alarm> for Watermark {
    fn from(alarm: Alarm) -> Self {
        match alarm {
            Alarm::Clear => Self::Clear,
            Alarm::Regression => Self::Regression,
            Alarm::Checkpoint => Self::Checkpoint,
            Alarm::Log => Self::Log,
            Alarm::Namespace => Self::Namespace,
        }
    }
}

impl From<&Result<(), Mismatch>> for Enumeration {
    fn from(checked: &Result<(), Mismatch>) -> Self {
        match checked {
            Ok(()) => Self::Matches,
            Err(Mismatch::Foreign(_)) => Self::Foreign,
            Err(Mismatch::Duplicate) => Self::Duplicate,
            Err(Mismatch::Missing) => Self::Missing,
        }
    }
}

impl From<Tally> for StoreOutcomes {
    fn from(tally: Tally) -> Self {
        Self {
            unknown: Some(tally.total(Tallied::Unknown)),
            unavailable: Some(tally.total(Tallied::Unavailable)),
            refused: Some(tally.total(Tallied::Refused)),
            log: Some(tally.total(Tallied::Log)),
        }
    }
}

impl From<RegistrantJudgment> for Registrants {
    fn from(judgment: RegistrantJudgment) -> Self {
        match judgment {
            RegistrantJudgment::Sole => Self::Sole,
            RegistrantJudgment::Recorded => Self::Recorded,
            RegistrantJudgment::Ended => Self::EndedRegistrant,
            RegistrantJudgment::Refused(refusal) => Self::from(refusal),
        }
    }
}

impl From<HoldState> for Hold {
    fn from(hold: HoldState) -> Self {
        match hold {
            HoldState::Clear => Self::Clear,
            HoldState::Held => Self::Held,
            HoldState::Pending => Self::Pending,
            HoldState::Superseded => Self::Superseded,
        }
    }
}

impl From<&UnitDamage> for Damage {
    fn from(damage: &UnitDamage) -> Self {
        match damage {
            UnitDamage::Header { .. } => Self::Header,
            UnitDamage::Chunk { .. } => Self::Chunk,
            UnitDamage::Content { .. } => Self::Content,
            UnitDamage::Units { .. } => Self::Units,
            UnitDamage::Unread { .. } => Self::Unread,
        }
    }
}

impl Retention {
    /// The warm load's account in `report`: its entry, unit and suffix counts and the units its allocator holds
    /// restored.
    pub fn of(report: &RecoveryReport) -> Self {
        let warm = &report.warm;
        Self {
            first_damage: warm.first_damage.as_ref().map(Damage::from),
            installed: warm.installed,
            omitted: warm.omitted,
            held_units: report.held_units,
            failed_units: warm.failed_units,
            unread_units: warm.unread_units,
            suffix_damage: warm.suffix_damage,
            suffix_tails: warm.suffix_tails,
            suffix_dropped: warm.suffix_dropped,
            suffix_unread: warm.suffix_unread,
            slot_superseded: warm.slot_superseded,
            slot_withheld: warm.slot_withheld,
        }
    }
}

impl RecoveryTimes {
    /// The milestones in `report`, each counted from the start of its initialization, which is the attach's first
    /// tick when the report has an origin (`Volume::recovery_timed`). `report`'s ticks are the owner's microsecond turn
    /// clock, which the owner's poll passes the volume; the conversion subtracts them as they are and rescales none. A
    /// milestone out of the recorder's order, as a backward clock step leaves it, reads unavailable: live, retained
    /// readiness, first hit and fill each follow the load, the first hit and the fill follow live, and retained
    /// readiness equals live. The result is one the entry codec accepts.
    pub fn of(report: &RecoveryReport) -> Self {
        let Some(base) = report.phase(RecoveryPhase::Initialization).start else {
            return Self::UNAVAILABLE;
        };
        let since = |at: Option<u64>| at.and_then(|at| at.checked_sub(base));
        let start = |phase| since(report.phase(phase).start);
        let after = |earlier: Option<u64>, at: Option<u64>| {
            at.filter(|at| earlier.is_none_or(|earlier| earlier <= *at))
        };
        let live = report
            .transitions
            .iter()
            .flatten()
            .find(|transition| transition.to == crate::storage::Readiness::Live);
        let loaded_us = since(report.phase(RecoveryPhase::Initialization).end);
        let live_us = after(loaded_us, since(live.map(|transition| transition.at)));
        let retained_us = after(loaded_us, start(RecoveryPhase::RetainedReadiness))
            .filter(|retained| live_us.is_none_or(|live| live == *retained));
        let floor = live_us.or(retained_us).or(loaded_us);
        Self {
            loaded_us,
            live_us,
            first_hit_us: after(floor, start(RecoveryPhase::FirstSafeHit)),
            retained_us,
            fill_us: after(floor, start(RecoveryPhase::FillReadiness)),
        }
    }
}

/// The reads in `reads` that failed their identity or checksum check: every header mismatch other than a first
/// extent's key mismatch, which the read answers `Missing`, and every chunk mismatch. A later extent's key mismatch
/// counts.
pub fn read_defects(reads: &VolumeReport) -> u64 {
    reads
        .header_mismatch
        .saturating_sub(reads.lookup_false_positives)
        .saturating_add(reads.chunk_mismatch)
}

#[cfg(test)]
#[path = "observed_tests.rs"]
mod tests;
