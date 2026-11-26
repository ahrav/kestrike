//! Per-tab search. In Jobs the query narrows the list; on the other tabs it
//! is the text `/`, `n` and `N` find. An open search keeps what `/` found,
//! so Esc restores the query, filter and row it started from.

use super::focus::JobFilter;
use super::nav::Mark;
use super::{App, Derived, Level, Tab};

/// The Jobs query, lowercased, as it tests one job of a snapshot after
/// another. A job matches an empty query, or when its lowercased profile
/// or lowercased outcome label contains the query, or its id starts with
/// the query ignoring ASCII case. The
/// profile test runs once per population, whose jobs share a profile, and
/// the label result is kept for the label last tested, so a run of jobs
/// with one label tests it once.
pub(super) struct JobQuery<'a> {
    pub(super) query: String,
    /// The query as typed, for the id prefix, whose case fold is ASCII-only
    /// so a byte of the id lines up with a byte of the query.
    typed: String,
    derived: &'a Derived,
    profiles: Vec<bool>,
    label: Memo<'a>,
}

/// The text last tested and whether it matched.
#[derive(Default)]
struct Memo<'a> {
    text: Option<&'a str>,
    hit: bool,
}

impl<'a> Memo<'a> {
    fn test(&mut self, text: &'a str, test: impl FnOnce(&str) -> bool) -> bool {
        if self.text != Some(text) {
            self.hit = test(text);
            self.text = Some(text);
        }
        self.hit
    }
}

/// `query` must be lowercase.
fn lowercase_holds(text: &str, query: &str) -> bool {
    let lowercase = text.bytes().fold(true, |lowercase, byte| {
        lowercase & byte.is_ascii() & !byte.is_ascii_uppercase()
    });
    if lowercase {
        text.contains(query)
    } else {
        text.to_lowercase().contains(query)
    }
}

impl<'a> JobQuery<'a> {
    pub(super) fn new(query: &str, derived: &'a Derived) -> Self {
        let typed = query.to_owned();
        let query = query.to_lowercase();
        let profiles = if query.is_empty() {
            Vec::new()
        } else {
            derived.populations.tested(&derived.snapshot.jobs, |job| {
                job.profile.to_lowercase().contains(&query)
            })
        };
        Self {
            query,
            typed,
            derived,
            profiles,
            label: Memo::default(),
        }
    }

    /// Whether the job at `index` in `snapshot.jobs` matches.
    pub(super) fn matches(&mut self, index: usize) -> bool {
        let Self {
            query,
            typed,
            derived,
            profiles,
            label,
        } = self;
        query.is_empty()
            || profiles[derived.populations.of(index)]
            || derived.snapshot.jobs[index]
                .id
                .get(..typed.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(typed))
            || label.test(&derived.outcomes[index].label, |label| {
                lowercase_holds(label, query)
            })
    }

    /// Keeps the jobs of `listed`, indices into `snapshot.jobs`, that match.
    /// A list of more than half of the jobs is tested through a mask
    /// of every job built in `snapshot.jobs` order, which reads the job
    /// rows in memory order; a shorter one is tested job by job.
    pub(super) fn retain(&mut self, listed: &mut Vec<usize>) {
        if self.query.is_empty() {
            return;
        }
        let jobs = self.derived.snapshot.jobs.len();
        if listed.len() <= jobs / 2 {
            listed.retain(|&index| self.matches(index));
            return;
        }
        let mask: Vec<bool> = (0..jobs).map(|index| self.matches(index)).collect();
        listed.retain(|&index| mask[index]);
    }
}

/// An open search: the tab's query, Jobs filter and replaced-filter slot
/// before `/`, restored if the search is cancelled, and the row it started
/// from.
#[derive(Debug)]
pub(super) struct Edit {
    pub(super) query: String,
    pub(super) filter: JobFilter,
    pub(super) base: Option<JobFilter>,
    pub(super) origin: Mark,
}

impl App {
    /// The lowercase text `/` matches at `row` of `tab`; empty for Overview
    /// and Jobs, whose search filters the list instead.
    pub fn row_text(&self, tab: Tab, row: usize) -> &str {
        self.derived()
            .and_then(|d| d.texts[tab.index()].get(row))
            .map_or("", String::as_str)
    }

    pub(super) fn find(&mut self, from: usize, forward: bool) -> bool {
        let rows = self.rows(self.tab);
        let query = self.searches[self.tab.index()].to_lowercase();
        if rows == 0 || query.is_empty() {
            return false;
        }
        let from = from % rows;
        for distance in 0..rows {
            let row = if forward {
                (from + distance) % rows
            } else {
                (from + rows - distance) % rows
            };
            if self.row_text(self.tab, row).contains(&query) {
                self.select(row);
                return true;
            }
        }
        false
    }

    /// Appends pasted `text`, already one line of printable characters, to
    /// the open search; without an open search the paste is dropped, so
    /// pasted letters never act as keys.
    pub fn paste(&mut self, text: &str) {
        if !self.searching() || text.is_empty() {
            return;
        }
        self.searches[self.tab.index()].push_str(text);
        self.extended();
    }

    pub fn type_char(&mut self, c: char) {
        if !self.searching() {
            return;
        }
        self.searches[self.tab.index()].push(c);
        self.extended();
    }

    /// Applies text appended to the open search's query. When the
    /// lowercased Jobs query still starts with the query `listed` was
    /// matched against, every job that matches it is already listed, since
    /// a text containing or starting with the longer query contains or
    /// starts with its prefix, so Jobs narrows `listed` in place.
    fn extended(&mut self) {
        let Some(d) = self.derived.clone().filter(|_| self.tab == Tab::Jobs) else {
            return self.searched();
        };
        let mut query = JobQuery::new(&self.searches[Tab::Jobs.index()], &d);
        if !query.query.starts_with(&self.listed_query) {
            return self.searched();
        }
        query.retain(&mut self.listed);
        self.listed_query = query.query;
        self.selections[Tab::Jobs.index()] = 0;
    }

    /// Applies an edit of the open search's query: Jobs relists from the
    /// top, other tabs select the first match from the search's origin.
    pub(super) fn searched(&mut self) {
        let tab = self.tab;
        if tab == Tab::Jobs {
            self.relist_from_top();
        } else if self.searching() {
            let origin = self
                .edit
                .as_ref()
                .map_or(0, |edit| self.locate(tab, &edit.origin));
            if !self.find(origin, true) {
                self.select(origin);
            }
        }
    }

    /// Restores the state `edit` saved at `/`; `position` also returns a
    /// view search to the row it started from.
    pub(super) fn cancel(&mut self, tab: Tab, edit: Edit, position: bool) {
        self.searches[tab.index()] = edit.query;
        self.filter = edit.filter;
        self.base_filter = edit.base;
        if position && tab != Tab::Jobs {
            let row = self.locate(tab, &edit.origin);
            self.select(row);
        }
    }

    pub(super) fn open_search(&mut self) {
        let tab = self.tab;
        self.edit = Some(Edit {
            query: std::mem::take(&mut self.searches[tab.index()]),
            filter: self.filter,
            base: self.base_filter,
            origin: self.mark(tab),
        });
        if tab == Tab::Jobs {
            self.base_filter.get_or_insert(self.filter);
            self.filter = JobFilter::All;
            self.relist_from_top();
        }
    }

    pub(super) fn find_or_flash(&mut self, from: usize, forward: bool) {
        if !self.find(from, forward) {
            let query = self.search(self.tab).to_owned();
            self.notify(Level::Warn, format!("no match for \"{query}\""));
        }
    }

    pub(super) fn clear(&mut self) {
        let tab = self.tab;
        if !self.searches[tab.index()].is_empty() {
            self.searches[tab.index()].clear();
            if tab == Tab::Jobs {
                self.filter = self.base_filter.take().unwrap_or(self.filter);
                self.relist_from_top();
            }
        } else if self.focus.is_some() && tab == Tab::Jobs {
            self.focus = None;
            self.relist_keeping();
        }
    }
}
