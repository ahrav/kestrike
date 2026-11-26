//! How a poller result reaches the screen: a snapshot swaps in whole and
//! every tab keeps its selected item, and the shown age counts from the
//! moment its fetch returned.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use super::{App, Mark, Tab};
use crate::poll::{Fetch, poll_wait};
use crate::state::derived::Derived;

impl App {
    /// Applies one poller result. A snapshot replaces the shown one,
    /// re-resolves the focused jobs, and keeps each tab's selected item
    /// selected while it is still listed; its history write error, if any,
    /// replaces the shown error. A snapshot with the shown one's
    /// `observed_ms` keeps the shown one's fetch time, so a source that
    /// serves the same observation again ages and turns stale. An error keeps the previous snapshot and
    /// shows the message. Returns the snapshot replaced, so the caller
    /// chooses the thread that frees it.
    /// While paused, a snapshot is held instead, its history write error
    /// replaces the shown error, and an older held one is returned.
    pub fn apply(&mut self, fetch: Fetch) -> Option<Arc<Derived>> {
        self.fetch_ms = Some(millis(fetch.elapsed));
        self.latest_failed = fetch.result.is_err();
        if self
            .refresh_asked
            .is_some_and(|asked| fetch.completed >= asked)
        {
            self.refresh_asked = None;
        }
        if let Err(error) = &fetch.result {
            self.error = Some(error.clone());
            return None;
        }
        if self.paused {
            if let Ok(derived) = &fetch.result {
                self.error = derived.history_error.clone();
            }
            return self.held.replace(fetch).and_then(|held| held.result.ok());
        }
        self.swap(fetch)
    }

    pub(super) fn swap(&mut self, fetch: Fetch) -> Option<Arc<Derived>> {
        let Ok(derived) = fetch.result else {
            return None;
        };
        let kept: Vec<Mark> = Tab::ALL.iter().map(|tab| self.mark(*tab)).collect();
        self.error = derived.history_error.clone();
        let same_observation = self
            .derived
            .as_ref()
            .is_some_and(|shown| shown.snapshot.observed_ms == derived.snapshot.observed_ms);
        if !same_observation {
            self.fetched_at = Some(fetch.completed);
            self.fetched_wall = Some(fetch.completed_wall);
            self.snapshot_fetch_ms = Some(millis(fetch.elapsed));
        }
        let replaced = self.derived.replace(derived);
        if let Some(focus) = self.focus.take() {
            self.focus = Some(self.refocus(focus));
        }
        self.relist();
        for (tab, kept) in Tab::ALL.into_iter().zip(kept) {
            let rows = self.rows(tab);
            let row = self.locate(tab, &kept);
            self.selections[tab.index()] = row.min(rows.saturating_sub(1));
        }
        replaced
    }

    /// How old the snapshot shown is at `now`, in milliseconds, and whether
    /// it is stale. The monotonic clock stops while the machine sleeps and
    /// the wall clock can step, so the time since the snapshot's fetch
    /// returned takes the larger reading. Adding that fetch's own duration
    /// bounds how long before receipt the source took the snapshot. The
    /// next snapshot is due one poll wait and one more fetch, both sized by
    /// the latest fetch, after this one returned, plus 5 s of slack, and
    /// never sooner than two intervals; `due` carries the same own-fetch
    /// term as the age, so both count from the moment the shown fetch
    /// returned.
    pub fn age(&self, now: Instant) -> Option<(u64, bool)> {
        self.age_and_due(now).map(|(age, due)| (age, age > due))
    }

    /// When the screen next changes without input: the shown age changes
    /// or the flash expires, whichever comes first.
    pub fn next_change(&self, now: Instant) -> Option<Instant> {
        let flash = self.flash_at(now).map(|flash| flash.until);
        match (self.next_age_change(now), flash) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// When the shown age next changes: its displayed [`age_text`], or its
    /// turn to stale, whichever comes first. `None` without a snapshot.
    pub fn next_age_change(&self, now: Instant) -> Option<Instant> {
        let (age, due) = self.age_and_due(now)?;
        let mut wait = age_text_lasts(age);
        if age <= due {
            wait = wait.min(due - age + 1);
        }
        Some(now + Duration::from_millis(wait))
    }

    pub(super) fn age_and_due(&self, now: Instant) -> Option<(u64, u64)> {
        let (_, fetched) = (self.derived.as_ref()?, self.fetched_at?);
        let latest = self.fetch_ms.unwrap_or(0);
        let own = self.snapshot_fetch_ms.unwrap_or(0);
        let wall = self
            .fetched_wall
            .and_then(|then| SystemTime::now().duration_since(then).ok())
            .map_or(0, millis);
        let age = millis(now.saturating_duration_since(fetched))
            .max(wall)
            .saturating_add(own);
        let wait = millis(poll_wait(self.interval, Duration::from_millis(latest)));
        let due = wait
            .saturating_add(latest)
            .saturating_add(own)
            .saturating_add(5_000)
            .max(millis(self.interval).saturating_mul(2));
        Some((age, due))
    }
}

pub(super) fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// A snapshot age in whole units: seconds under a minute, minutes under an
/// hour, then hours and minutes, then days and hours.
pub fn age_text(ms: u64) -> String {
    let seconds = ms / 1000;
    match seconds {
        0..60 => format!("{seconds}s"),
        60..3600 => format!("{}m", seconds / 60),
        3600..86_400 => format!("{}h{:02}m", seconds / 3600, (seconds % 3600) / 60),
        _ => format!("{}d{:02}h", seconds / 86_400, (seconds % 86_400) / 3600),
    }
}

/// Milliseconds until [`age_text`] of an age of `ms` changes.
pub(super) fn age_text_lasts(ms: u64) -> u64 {
    let unit = match ms / 1000 {
        0..60 => 1_000,
        60..86_400 => 60_000,
        _ => 3_600_000,
    };
    unit - ms % unit
}
