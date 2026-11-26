//! Actions to state changes: `App::update` applies one binding-table
//! action and returns the effect the run loop performs. An action that
//! cannot act flashes its reason instead.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{App, Tab};
use crate::source::shell_quote;
use crate::state::derived::Derived;
use crate::tui::keymap::{Action, Context};

/// Work [`App::update`] hands to the run loop, which performs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    None,
    Quit,
    Refresh,
    /// Copy the text to the clipboard.
    Yank(String),
}

/// How long a flash message shows.
pub const FLASH_FOR: Duration = Duration::from_secs(6);

/// The most text `y` puts on the clipboard. The OSC 52 write runs on the
/// loop thread and its base64 form is a third larger, so a signal naming
/// every job of a hostile snapshot is refused with the bound named.
pub const COPY_BYTES: usize = 16 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

/// A one-line message about the last key, shown until `until`; a newer
/// message replaces it.
#[derive(Debug, Clone)]
pub struct Flash {
    pub level: Level,
    pub text: String,
    pub until: Instant,
}

impl App {
    pub fn context(&self) -> Context {
        if self.searching() {
            Context::Search
        } else if self.help {
            Context::Help
        } else {
            match self.pending {
                Some('g') => Context::PendingG,
                Some('z') => Context::PendingZ,
                _ => Context::of(self.tab),
            }
        }
    }

    pub fn flash_at(&self, now: Instant) -> Option<&Flash> {
        self.flash.as_ref().filter(|flash| now < flash.until)
    }

    pub fn notify(&mut self, level: Level, text: impl Into<String>) {
        self.flash = Some(Flash {
            level,
            text: text.into(),
            until: Instant::now() + FLASH_FOR,
        });
    }

    /// When `can(action)` is false, [`App::update`] flashes the reason from
    /// `cannot(action)` and returns `Effect::None`.
    pub fn can(&self, action: Action) -> bool {
        let rows = self.rows(self.tab);
        match action {
            Action::NextMatch | Action::PrevMatch => !self.search(self.tab).is_empty(),
            Action::Drill => self.can_drill(),
            Action::Back => self.can_go_back(),
            Action::Clear => {
                !self.search(self.tab).is_empty() || (self.tab == Tab::Jobs && self.focus.is_some())
            }
            Action::RunsOlder | Action::RunsNewer | Action::RunsOldest | Action::RunsNewest => {
                self.runs_hidden.get()
            }
            Action::Yank => self.yank_target().is_ok(),
            Action::Down
            | Action::Up
            | Action::HalfDown
            | Action::HalfUp
            | Action::PageDown
            | Action::PageUp
            | Action::Top
            | Action::Bottom
            | Action::ScreenTop
            | Action::ScreenMiddle
            | Action::ScreenBottom
            | Action::ScrollDown
            | Action::ScrollUp
            | Action::Center
            | Action::AlignTop
            | Action::AlignBottom => rows > 0,
            _ => true,
        }
    }

    pub fn update(&mut self, action: Action) -> Effect {
        if !matches!(action, Action::PrefixG | Action::PrefixZ) {
            self.pending = None;
        }
        if !self.can(action) {
            let reason = self.cannot(action);
            self.notify(Level::Warn, reason);
            return Effect::None;
        }
        let half = (self.page() / 2).max(1) as isize;
        let page = self.page() as isize;
        match action {
            Action::Quit => return Effect::Quit,
            Action::Refresh => {
                self.refresh_asked.get_or_insert_with(Instant::now);
                return Effect::Refresh;
            }
            Action::Help => {
                self.help = true;
                self.help_scroll.set(0);
            }
            Action::HelpDown => self.scroll_help(1),
            Action::HelpUp => self.scroll_help(-1),
            Action::HelpHalfDown => self.scroll_help((self.help_height.get() / 2).max(1) as isize),
            Action::HelpHalfUp => self.scroll_help(-((self.help_height.get() / 2).max(1) as isize)),
            Action::HelpTop => self.help_scroll.set(0),
            Action::HelpBottom => self.help_scroll.set(usize::MAX),
            Action::CloseHelp => self.help = false,
            Action::Pause => self.toggle_pause(),
            Action::Yank => return self.yank(),
            Action::Open(tab) => self.tab = tab,
            Action::NextTab => self.tab = self.tab.step(1),
            Action::PrevTab => self.tab = self.tab.step(-1),
            Action::Down => self.step(1),
            Action::Up => self.step(-1),
            Action::HalfDown => self.step(half),
            Action::HalfUp => self.step(-half),
            Action::PageDown => self.step(page),
            Action::PageUp => self.step(-page),
            Action::Top => self.select(0),
            Action::Bottom => self.select(usize::MAX),
            Action::ScreenTop => self.screen_row('H'),
            Action::ScreenMiddle => self.screen_row('M'),
            Action::ScreenBottom => self.screen_row('L'),
            Action::ScrollDown => self.scroll(1),
            Action::ScrollUp => self.scroll(-1),
            Action::Center => self.align('z'),
            Action::AlignTop => self.align('t'),
            Action::AlignBottom => self.align('b'),
            Action::PrefixG => self.pending = Some('g'),
            Action::PrefixZ => self.pending = Some('z'),
            Action::CancelPrefix => {}
            Action::RunsOlder => {
                let shift = self.run_shift.get().saturating_add(1);
                self.run_shift.set(shift.min(self.runs()));
            }
            Action::RunsNewer => self.run_shift.set(self.run_shift.get().saturating_sub(1)),
            Action::RunsOldest => self.run_shift.set(self.runs()),
            Action::RunsNewest => self.run_shift.set(0),
            Action::Search => self.open_search(),
            Action::NextMatch => {
                let from = self.selected() + 1;
                self.find_or_flash(from, true);
            }
            Action::PrevMatch => {
                let rows = self.rows(self.tab);
                let from = self
                    .selected()
                    .checked_sub(1)
                    .unwrap_or(rows.saturating_sub(1));
                self.find_or_flash(from, false);
            }
            Action::Drill => {
                if let Err(reason) = self.drill() {
                    self.notify(Level::Warn, format!("enter: {reason}"));
                }
            }
            Action::Back => {
                self.go_back();
            }
            Action::Clear => self.clear(),
            Action::Filter => {
                self.filter = self.filter.next();
                self.base_filter = None;
                self.focus = None;
                self.relist_from_top();
            }
            Action::SearchKeep => {
                let tab = self.tab;
                let edit = self.edit.take();
                if self.searches[tab.index()].is_empty()
                    && let Some(edit) = edit
                {
                    self.cancel(tab, edit, false);
                }
                self.searched();
            }
            Action::SearchCancel => {
                let tab = self.tab;
                if let Some(edit) = self.edit.take() {
                    self.cancel(tab, edit, true);
                }
                self.searched();
            }
            Action::SearchErase => {
                self.searches[self.tab.index()].pop();
                self.searched();
            }
        }
        Effect::None
    }

    fn scroll_help(&self, delta: isize) {
        self.help_scroll
            .set(self.help_scroll.get().saturating_add_signed(delta));
    }

    pub(super) fn cannot(&self, action: Action) -> String {
        match action {
            Action::NextMatch | Action::PrevMatch => "n and N need a search; / starts one".into(),
            Action::Drill => format!(
                "enter: {}",
                match self.tab {
                    Tab::Overview | Tab::Jobs => "opens jobs from Signals, Profiles or Findings",
                    _ if self.rows(self.tab) == 0 => "no row to open",
                    _ => "the selected row names no job in this snapshot",
                }
            ),
            Action::Back => "nothing to go back to".into(),
            Action::Clear => "nothing to clear: no search or focus".into(),
            Action::RunsOlder | Action::RunsNewer | Action::RunsOldest | Action::RunsNewest => {
                "every run fits on screen".into()
            }
            Action::Yank => match self.yank_target() {
                Err(reason) => format!("y: {reason}"),
                Ok(_) => String::new(),
            },
            _ => "no rows to move through".into(),
        }
    }

    pub(super) fn toggle_pause(&mut self) {
        self.paused = !self.paused;
        if self.paused {
            self.notify(Level::Info, "paused: snapshots are fetched but not shown");
        } else {
            self.notify(Level::Info, "resumed");
            if let Some(held) = self.held.take() {
                // The latest source failure survives the held snapshot swap.
                let failure = self.latest_failed.then(|| self.error.clone()).flatten();
                self.resumed = self.swap(held);
                if failure.is_some() {
                    self.error = failure;
                }
            }
        }
    }

    pub fn take_resumed(&mut self) -> Option<Arc<Derived>> {
        self.resumed.take()
    }

    pub fn holding(&self) -> bool {
        self.held.is_some()
    }

    pub(super) fn yank(&mut self) -> Effect {
        match self.yank_text() {
            Ok((what, text)) => {
                self.notify(Level::Info, format!("copied {what}"));
                Effect::Yank(text)
            }
            Err(reason) => {
                self.notify(Level::Warn, format!("y: {reason}"));
                Effect::None
            }
        }
    }

    pub(super) fn yank_text(&self) -> Result<(&'static str, String), &'static str> {
        let yank = self.yank_target()?;
        let d = self.derived().ok_or("no snapshot yet")?;
        yank.unaltered(&d.altered)?;
        let (what, text) = match yank {
            Yank::Job(id) => ("the job id", id.to_owned()),
            Yank::Profile(name) => ("the profile name", name.to_owned()),
            Yank::Subjects(subjects) => {
                let bytes: usize =
                    subjects.iter().map(String::len).sum::<usize>() + subjects.len() - 1;
                if bytes > COPY_BYTES {
                    return Err("the subjects exceed the 16 MiB copy bound");
                }
                ("the signal's subjects", subjects.join(" "))
            }
            Yank::Replay { state, id } => (
                "the replay command",
                replay_command(&shell_quote(state), &shell_quote(id)),
            ),
        };
        if text.len() > COPY_BYTES {
            return Err("the text exceeds the 16 MiB copy bound");
        }
        Ok((what, text))
    }

    fn yank_target(&self) -> Result<Yank<'_>, &'static str> {
        let d = self.derived().ok_or("no snapshot yet")?;
        let row = self.selected();
        match self.tab {
            Tab::Overview => Err("selects nothing on Overview"),
            Tab::Jobs => self
                .job(row)
                .map(|(job, _)| Yank::Job(&job.id))
                .ok_or("no job is selected"),
            Tab::Profiles => d
                .matrix
                .rows
                .get(row)
                .map(|matrix_row| Yank::Profile(&matrix_row.profile))
                .ok_or("no profile is selected"),
            Tab::Signals => {
                let signal = d.signals.get(row).ok_or("no signal is selected")?;
                if signal.subjects.is_empty() {
                    return Err("the selected signal names no subject");
                }
                Ok(Yank::Subjects(&signal.subjects))
            }
            Tab::Findings => {
                let (group, summary) = self
                    .groups()
                    .get(row)
                    .zip(d.group_summaries.get(row))
                    .ok_or("no failure group is selected")?;
                let id = summary
                    .target
                    .and_then(|index| group.findings.get(index))
                    .ok_or("the selected group has no finding")?;
                let state = &d.snapshot.state;
                Ok(Yank::Replay { state, id })
            }
        }
    }
}

enum Yank<'a> {
    Job(&'a str),
    Profile(&'a str),
    Subjects(&'a [String]),
    Replay { state: &'a str, id: &'a str },
}

impl Yank<'_> {
    /// A value sanitizing changed is an error: the clipboard only receives
    /// strings equal to the fetched value.
    fn unaltered(&self, altered: &BTreeSet<String>) -> Result<(), &'static str> {
        let changed = |text: &str| altered.contains(text);
        let (hit, reason) = match self {
            Yank::Job(id) => (changed(id), "the job id holds a control character"),
            Yank::Profile(name) => (changed(name), "the profile name holds a control character"),
            Yank::Subjects(subjects) => (
                subjects.iter().any(|subject| changed(subject)),
                "a subject holds a control character",
            ),
            Yank::Replay { state, id } => (
                changed(id) || changed(state),
                "the finding id or state path holds a control character",
            ),
        };
        if hit { Err(reason) } else { Ok(()) }
    }
}

/// `state` and `from_run` must already be shell words or placeholders
/// because interpolation inserts them verbatim. Triage takes its delegated
/// cgroup root from `--cgroup-root`, and `"${CAMPAIGN_CGROUP_ROOT:?}"` makes
/// the shell report an error naming the variable when it is unset or empty.
pub(crate) fn replay_command(state: &str, from_run: &str) -> String {
    format!(
        "campaign triage --state {state} --cgroup-root \"${{CAMPAIGN_CGROUP_ROOT:?}}\" \
         --from-run {from_run} --step replay"
    )
}
