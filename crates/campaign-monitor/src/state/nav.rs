//! Rows, pages and screen positions. Each tab's selection stays below its
//! tab's row count, or is 0 when the tab has no rows; a saved position
//! names its item by identity and is resolved against the snapshot shown.

use std::cell::Cell;

use super::App;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Signals,
    Profiles,
    Jobs,
    Findings,
}

impl Tab {
    /// Every tab in declaration order, so `ALL[tab.index()] == tab`; the
    /// digit key `n` opens `ALL[n - 1]`.
    pub const ALL: [Self; 5] = [
        Self::Overview,
        Self::Signals,
        Self::Profiles,
        Self::Jobs,
        Self::Findings,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Signals => "Signals",
            Self::Profiles => "Profiles",
            Self::Jobs => "Jobs",
            Self::Findings => "Findings",
        }
    }

    /// The tab's label with the digit key that opens it.
    pub fn title(self) -> String {
        format!("{} {}", self.index() + 1, self.name())
    }

    pub fn index(self) -> usize {
        self as usize
    }

    pub(super) fn step(self, delta: isize) -> Self {
        let count = Self::ALL.len() as isize;
        Self::ALL[(self.index() as isize + delta).rem_euclid(count) as usize]
    }
}

const _: () = {
    let mut index = 0;
    while index < Tab::ALL.len() {
        assert!(
            Tab::ALL[index] as usize == index,
            "Tab::ALL lists the tabs in declaration order"
        );
        index += 1;
    }
};

/// The window of one list as the last draw placed it. Drawing takes `&App`
/// and records the window through these cells; the paging keys size their
/// moves by the recorded `height`, which is 0 until the list is first drawn.
#[derive(Debug, Default)]
pub struct Viewport {
    pub(crate) offset: Cell<usize>,
    pub(crate) height: Cell<usize>,
}

impl Viewport {
    /// Returns the half-open `[start, end)` rows to draw for `selected`
    /// among `len` rows in a body of `height` rows, and records that window.
    /// The window moves only when `selected` leaves it and never starts past
    /// the last `height` rows. A table always lays out at least one body
    /// row, and a `height` of 0 is placed as one row.
    pub fn place(&self, selected: usize, len: usize, height: usize) -> (usize, usize) {
        let height = height.max(1);
        self.height.set(height);
        let mut offset = self.offset.get();
        if selected < offset {
            offset = selected;
        } else if selected >= offset + height {
            offset = selected + 1 - height;
        }
        offset = offset.min(len.saturating_sub(height));
        self.offset.set(offset);
        (offset, len.min(offset + height))
    }
}

/// A position in one tab: the identity of the selected item, and its row
/// for when the item is gone.
#[derive(Debug, Clone)]
pub(super) struct Mark {
    pub(super) identity: Option<String>,
    pub(super) row: usize,
}

impl App {
    /// A name for the item at `row` that stays the same when a later
    /// snapshot moves the item to another row.
    pub(super) fn identity(&self, tab: Tab, row: usize) -> Option<&str> {
        match tab {
            Tab::Jobs => self.job(row).map(|(job, _)| job.id.as_str()),
            _ => self.derived()?.keys[tab.index()]
                .get(row)
                .map(String::as_str),
        }
    }

    pub(super) fn mark(&self, tab: Tab) -> Mark {
        let row = self.selections[tab.index()];
        Mark {
            identity: self.identity(tab, row).map(str::to_owned),
            row,
        }
    }

    /// The row of `mark`'s item in `tab`, or its saved row when the item is
    /// no longer listed.
    pub(super) fn locate(&self, tab: Tab, mark: &Mark) -> usize {
        mark.identity
            .as_deref()
            .and_then(|identity| {
                (0..self.rows(tab)).find(|&row| self.identity(tab, row) == Some(identity))
            })
            .unwrap_or(mark.row)
    }

    /// The body height of the current tab's last draw, or 1 before its first.
    pub(super) fn page(&self) -> usize {
        self.view(self.tab).height.get().max(1)
    }

    pub(super) fn select(&mut self, row: usize) {
        let rows = self.rows(self.tab);
        self.selections[self.tab.index()] = row.min(rows.saturating_sub(1));
    }

    pub(super) fn step(&mut self, delta: isize) {
        self.select(self.selected().saturating_add_signed(delta));
    }

    pub(super) fn scroll(&mut self, delta: isize) {
        let view = self.view(self.tab);
        let rows = self.rows(self.tab);
        let height = self.page();
        let offset = view
            .offset
            .get()
            .saturating_add_signed(delta)
            .min(rows.saturating_sub(height));
        view.offset.set(offset);
        let selected = self.selected().clamp(offset, offset + height - 1);
        self.select(selected);
    }

    pub(super) fn align(&mut self, place: char) {
        let height = self.page();
        let selected = self.selected();
        let offset = match place {
            't' => selected,
            'b' => (selected + 1).saturating_sub(height),
            _ => selected.saturating_sub(height / 2),
        };
        self.view(self.tab).offset.set(offset);
    }

    pub(super) fn screen_row(&mut self, place: char) {
        let offset = self.view(self.tab).offset.get();
        let height = self.page();
        let shown = self.rows(self.tab).saturating_sub(offset).min(height);
        let row = match place {
            'H' => offset,
            'L' => offset + shown.saturating_sub(1),
            _ => offset + shown.saturating_sub(1) / 2,
        };
        self.select(row);
    }
}
