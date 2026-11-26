//! The terminal monitor's state: the derived snapshot shown, and the
//! navigation, search and drill-down state that keys change. A new
//! [`Derived`] replaces the shown one whole in [`App::apply`], which then
//! rebuilds `listed` and the focused job set, so both always describe the
//! snapshot shown.

pub mod derived;
mod fetched;
mod focus;
mod from_jobs;
mod ids;
mod naming;
mod nav;
mod populations;
mod sanitize;
mod search;
mod update;

use std::cell::Cell;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

pub use derived::Derived;
pub use fetched::age_text;
pub use focus::{Focus, JobFilter};
pub use nav::{Tab, Viewport};
pub(crate) use update::replay_command;
pub use update::{Effect, FLASH_FOR, Flash, Level};

use crate::outcome::Outcome;
use crate::poll::Fetch;
use crate::signals::{Severity, Signal};
use crate::snapshot::{FailureGroup, FindingRow, Job};
use focus::Back;
use nav::Mark;
use search::Edit;

/// `listed` holds the admitted `snapshot.jobs` indices in display order,
/// and `selections` one row per tab in [`Tab::index`] order. `listed_query`
/// is the lowercased Jobs query `listed` was matched against.
pub struct App {
    pub(crate) source: String,
    pub(crate) interval: Duration,
    pub(crate) derived: Option<Arc<Derived>>,
    pub(crate) listed: Vec<usize>,
    listed_query: String,
    /// The last fetch error, or a history write error after a snapshot. A
    /// snapshot clears it before its history write can set it again.
    pub(crate) error: Option<String>,
    /// Whether the latest fetch failed.
    latest_failed: bool,
    /// When the fetch of the snapshot shown returned, on the monotonic and
    /// wall clocks, and how long that fetch took.
    pub(crate) fetched_at: Option<Instant>,
    pub(crate) fetched_wall: Option<SystemTime>,
    pub(crate) snapshot_fetch_ms: Option<u64>,
    /// How long the latest fetch took, failed ones included; the poller
    /// sizes its next wait by it.
    pub(crate) fetch_ms: Option<u64>,
    /// When `r` asked for a refresh; a fetch that returned at or after it
    /// answers it.
    pub(crate) refresh_asked: Option<Instant>,
    pub(crate) tab: Tab,
    pub(crate) selections: [usize; Tab::ALL.len()],
    views: [Viewport; Tab::ALL.len()],
    /// Newest Profiles runs scrolled off the right edge; 0 shows the
    /// newest. The renderer clamps it to the runs that do not fit and
    /// stores the clamped value.
    pub(crate) run_shift: Cell<usize>,
    /// Whether the last Profiles draw hid runs; true before the first draw,
    /// when the run keys may still have runs to scroll.
    pub(crate) runs_hidden: Cell<bool>,
    pub(crate) filter: JobFilter,
    /// The filter a Jobs search replaced, restored when the Jobs query is
    /// cleared; `f` drops it.
    base_filter: Option<JobFilter>,
    pub(crate) focus: Option<Focus>,
    /// One query per tab: in Jobs it narrows the list, elsewhere it is the
    /// text that `/`, `n` and `N` find.
    searches: [String; Tab::ALL.len()],
    /// The open search; set while `/` takes keys.
    edit: Option<Edit>,
    pending: Option<char>,
    back: Vec<Back>,
    pub(crate) help: bool,
    /// The first help row shown and the rows the last draw had room for;
    /// the renderer clamps the offset to the rows that do not fit.
    pub(crate) help_scroll: Cell<usize>,
    pub(crate) help_height: Cell<usize>,
    pub(crate) flash: Option<Flash>,
    /// Whether snapshot swaps are paused; `held` keeps the newest snapshot
    /// fetched meanwhile, which a resume applies, and `resumed` the one that
    /// resume replaced, until the loop takes it to free.
    pub(crate) paused: bool,
    held: Option<Fetch>,
    resumed: Option<Arc<Derived>>,
}

impl App {
    pub fn new(source: String, interval: Duration) -> Self {
        Self {
            source,
            interval,
            derived: None,
            listed: Vec::new(),
            listed_query: String::new(),
            error: None,
            latest_failed: false,
            fetched_at: None,
            fetched_wall: None,
            snapshot_fetch_ms: None,
            fetch_ms: None,
            refresh_asked: None,
            tab: Tab::Overview,
            selections: [0; Tab::ALL.len()],
            views: Default::default(),
            run_shift: Cell::new(0),
            runs_hidden: Cell::new(true),
            filter: JobFilter::Problems,
            base_filter: None,
            focus: None,
            searches: Default::default(),
            edit: None,
            pending: None,
            back: Vec::new(),
            help: false,
            help_scroll: Cell::new(0),
            help_height: Cell::new(0),
            flash: None,
            paused: false,
            held: None,
            resumed: None,
        }
    }

    /// The derived snapshot shown, if one arrived.
    pub fn derived(&self) -> Option<&Derived> {
        self.derived.as_deref()
    }

    pub fn selected(&self) -> usize {
        self.selections[self.tab.index()]
    }

    pub fn view(&self, tab: Tab) -> &Viewport {
        &self.views[tab.index()]
    }

    /// The query of `tab`.
    pub fn search(&self, tab: Tab) -> &str {
        &self.searches[tab.index()]
    }

    /// Whether a `/` search is open and taking keys.
    pub fn searching(&self) -> bool {
        self.edit.is_some()
    }

    /// Whether a refresh was asked for and no fetch has answered it yet.
    pub fn refresh_pending(&self) -> bool {
        self.refresh_asked.is_some()
    }

    /// The job at `row` of the Jobs list, a position in `listed`.
    pub fn job(&self, row: usize) -> Option<(&Job, &Outcome)> {
        let index = *self.listed.get(row)?;
        let d = self.derived()?;
        Some((&d.snapshot.jobs[index], &d.outcomes[index]))
    }

    /// The signals that name the job `id`, in signal order.
    pub fn naming(&self, id: &str) -> impl Iterator<Item = &Signal> {
        self.derived().into_iter().flat_map(move |d| d.naming(id))
    }

    /// The worst severity among the signals that name the job `id`.
    pub fn flag(&self, id: &str) -> Option<Severity> {
        self.derived()?.flag(id)
    }

    /// The first finding row with `id`.
    pub fn finding(&self, id: &str) -> Option<&FindingRow> {
        let d = self.derived()?;
        let index = *d.finding_rows.get(id)?;
        d.snapshot.findings.get(index)
    }

    pub fn groups(&self) -> &[FailureGroup] {
        self.derived()
            .map_or(&[], |d| d.snapshot.failure_groups.as_slice())
    }

    pub fn signals(&self) -> &[Signal] {
        self.derived().map_or(&[], |d| d.signals.as_slice())
    }

    /// Runs of the Profiles matrix.
    fn runs(&self) -> usize {
        self.derived().map_or(0, |d| d.matrix.runs.len())
    }

    fn rows(&self, tab: Tab) -> usize {
        match tab {
            Tab::Overview => 0,
            Tab::Signals => self.signals().len(),
            Tab::Profiles => self.derived().map_or(0, |d| d.matrix.rows.len()),
            Tab::Jobs => self.listed.len(),
            Tab::Findings => self.groups().len(),
        }
    }

    /// The `g` or `z` prefix waiting for its second key.
    pub fn pending(&self) -> Option<char> {
        self.pending
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
pub(crate) mod tests;
