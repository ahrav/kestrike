#[cfg(test)]
mod dispatch_tests;
mod policy;
mod recent;
mod recovery;
mod runner;

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Instant;

use super::{Error, name};
use crate::record::Finished;
pub(crate) use policy::backlog;
pub(crate) use policy::storage_pauses;
pub(in crate::campaign) use policy::{ancestor_fit, backlog_hold, fit_or_stop};
pub use recent::{RECENT, RECENT_BYTES, Recent};
#[cfg(test)]
pub(in crate::campaign) use runner::PASS_DELETIONS;
pub use runner::dispatch;
#[cfg(test)]
pub(in crate::campaign) use runner::session;
#[cfg(test)]
pub(in crate::campaign) use runner::{
    ordinary_admission_during_triage, resume_pending_capture, run_with_settled,
    triage_admission_waits_for_pending_capture,
};

pub struct Options {
    pub archive: PathBuf,
    pub gate: PathBuf,
    pub launcher: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub deadline: Option<Instant>,
    pub max_attempts: Option<u64>,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    /// The greatest 16 id-keyed diagnostics; admission retains its full controls.
    pub unfit: BTreeMap<String, String>,
    /// The window's newest attempt completions: at most [`RECENT`], within
    /// [`RECENT_BYTES`] of JSON.
    pub completed: Recent<Finished>,
    /// The window's attempt completions per class, and its triage
    /// completions under `triage`.
    pub counts: BTreeMap<String, u64>,
    pub paused: BTreeSet<String>,
    /// How many start decisions each storage, slot, share or build
    /// dimension paused.
    pub pauses: BTreeMap<String, u64>,
    /// The first 16 causes, with dropped visits counted in `diagnostics_omitted`.
    pub refusals: Vec<String>,
    /// The first 16 causes, with dropped visits counted in `diagnostics_omitted`.
    pub rejections: Vec<String>,
    pub started: u64,
    pub triage_started: u64,
    /// Dispatch-owned passes and their probe-directory or file deletions.
    pub collect_passes: u64,
    pub collect_deletions: u64,
    /// The last attempted pass reached its end (`Some(true)`) or paused
    /// unfinished (`Some(false)`, including gating holds, marker headroom
    /// stops, a busy hardware lock and a pass stopped by a failed signal
    /// read); `None` means no pass ran or the pass itself returned an error.
    pub collect_finished: Option<bool>,
    /// Diagnostic rows dropped from each bounded sample, counting visits.
    pub diagnostics_omitted: BTreeMap<String, u64>,
    /// The greatest 16 id-keyed diagnostics; admission retains its full controls.
    pub calibration_held: BTreeMap<String, String>,
    /// The greatest 16 id-keyed diagnostics; admission retains its full controls.
    pub triage_skipped: BTreeMap<String, String>,
    /// The window's newest triage completions: at most [`RECENT`], within
    /// [`RECENT_BYTES`] of JSON.
    pub triage_completed: Recent<crate::record::TriageResult>,
    /// Why the admission loop ended.
    pub state: State,
    /// Each root's entry count and free space when the window ended: the
    /// fullest shard for `jobs` and `attempts`, top-level entries for other
    /// roots. `None` means measurement failed; its refusal is retained within
    /// the first 16 causes or counted in `diagnostics_omitted`. The charged
    /// census also lists each `attempts/<xx>/<id>`, so
    /// a job's attempt history can hold while each top-level root fits.
    pub storage: Option<crate::campaign::Storage>,
}

/// The branch that ended a dispatch window's admission loop.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// No queued job could start.
    #[default]
    QueueEmpty,
    /// A pause dimension stopped new starts.
    Paused,
    /// A refusal stopped the window, or the backlog hold stopped job
    /// starts while triage steps kept running.
    Held,
    /// The deadline passed.
    Deadline,
    /// The window started its maximum number of attempts.
    MaxAttempts,
    /// The controller was interrupted.
    Interrupted,
    /// A rejection stopped the window.
    Rejected,
}

/// Diagnostic samples retain 16 rows per field, with omitted-visit counts.
const DIAGNOSTICS: usize = 16;

impl Report {
    /// Records attempt completion `finished`.
    pub(super) fn complete(&mut self, finished: Finished) {
        *self
            .counts
            .entry(finished.class.name().to_owned())
            .or_insert(0) += 1;
        self.completed.push(finished);
    }

    /// Records triage completion `result`.
    fn triage(&mut self, result: crate::record::TriageResult) {
        *self.counts.entry("triage".to_owned()).or_insert(0) += 1;
        self.triage_completed.push(result);
    }

    /// Records that each of `dimensions` paused a start decision.
    pub(super) fn pause(&mut self, dimensions: impl IntoIterator<Item = String>) {
        for dimension in dimensions {
            *self.pauses.entry(dimension.clone()).or_insert(0) += 1;
            self.paused.insert(dimension);
        }
    }

    /// Retains the greatest map keys and first list causes, counting dropped
    /// visits. `Jobs::excluded` and `Dispatcher::unchanged` own admission controls.
    fn trim_diagnostics(&mut self) {
        for (name, rows) in [
            ("unfit", &mut self.unfit),
            ("calibration_held", &mut self.calibration_held),
            ("triage_skipped", &mut self.triage_skipped),
        ] {
            let dropped = rows.len().saturating_sub(DIAGNOSTICS);
            if dropped > 0 {
                *self.diagnostics_omitted.entry(name.to_owned()).or_default() += dropped as u64;
                for _ in 0..dropped {
                    rows.pop_first();
                }
            }
        }
        for (name, rows) in [
            ("refusals", &mut self.refusals),
            ("rejections", &mut self.rejections),
        ] {
            let dropped = rows.len().saturating_sub(DIAGNOSTICS);
            if dropped > 0 {
                *self.diagnostics_omitted.entry(name.to_owned()).or_default() += dropped as u64;
                rows.truncate(DIAGNOSTICS);
            }
        }
    }

    fn stopping(&self) -> bool {
        !self.refusals.is_empty() || !self.rejections.is_empty()
    }

    /// The refusals as one hold message: the sampled causes, then the count
    /// of causes the sample leaves out.
    pub(in crate::campaign) fn held_reason(&self) -> String {
        let mut reason = self.refusals.join("; ");
        if let Some(omitted) = self.diagnostics_omitted.get("refusals") {
            reason.push_str(&format!("; omitted refusals: {omitted}"));
        }
        reason
    }

    pub fn exit(&self) -> crate::exit::Supervisor {
        if !self.refusals.is_empty() {
            crate::exit::Supervisor::Held
        } else if !self.rejections.is_empty() {
            crate::exit::Supervisor::Rejected
        } else {
            crate::exit::Supervisor::Success
        }
    }

    /// The failure of a window that a refusal or a rejection stopped, as
    /// the command that ran the window returns it.
    pub(crate) fn failure(&self) -> Option<super::Error> {
        match self.exit() {
            crate::exit::Supervisor::Held => Some(super::Error::Held(self.held_reason())),
            crate::exit::Supervisor::Rejected => {
                Some(super::Error::Rejected(self.rejections.join("; ")))
            }
            _ => None,
        }
    }

    /// Records the state directory's storage and, for a window that a
    /// refusal or a rejection stopped, that cause as its state. A failed
    /// measurement whose text the window already refused with, such as the
    /// same root's bound hold, is recorded once.
    fn finish(&mut self, store: &crate::store::Store) {
        self.trim_diagnostics();
        match crate::campaign::storage::measure(store) {
            Ok(storage) => self.storage = Some(storage),
            Err(error) if self.refusals.contains(&error.to_string()) => {}
            Err(error) => self.error(error),
        }
        if !self.refusals.is_empty() {
            self.state = State::Held;
        } else if !self.rejections.is_empty() {
            self.state = State::Rejected;
        }
    }

    fn error(&mut self, error: Error) {
        match error {
            Error::Rejected(reason) => self.rejections.push(reason),
            error => self.refuse(error.to_string()),
        }
        self.trim_diagnostics();
    }

    fn refuse(&mut self, reason: String) {
        self.refusals.push(reason);
        self.trim_diagnostics();
    }
}

#[cfg(test)]
pub(crate) fn recover(
    store: &crate::store::Store,
    custody: &mut crate::custody::Custody,
) -> Result<(), Error> {
    recover_counted(store, custody, &mut None)
}

/// Recovers jobs and probes, applying job-publication deltas to a census
/// already counted during triage recovery.
pub(crate) fn recover_counted(
    store: &crate::store::Store,
    custody: &mut crate::custody::Custody,
    census: &mut Option<crate::campaign::census::Census>,
) -> Result<(), Error> {
    crate::campaign::calibration::reconcile(store, custody)?;
    let mut report = Report::default();
    if let Err(error) = crate::campaign::probe::reconcile_records(store, custody) {
        report.error(error);
    }
    match recovery::Jobs::load(store, &mut report) {
        Ok(Some(mut jobs)) => jobs.reconcile(store, custody, &mut report, census),
        Ok(None) => {}
        Err(error) => report.error(error),
    }
    match custody.unrecorded(&[], crate::scan_bound()) {
        Ok(groups) if groups.is_empty() => {}
        Ok(_) => report.refuse("unrecorded custody tree".into()),
        Err(error) => report.error(error.into()),
    }
    if report.stopping() {
        return Err(Error::Held(report.held_reason()));
    }
    Ok(())
}
