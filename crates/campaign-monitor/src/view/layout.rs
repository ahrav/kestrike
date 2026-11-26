//! Where each region of a frame goes, as a pure function of the frame size
//! and the state, so the breakpoints are tested without a terminal.

use ratatui::layout::{Constraint, Layout, Rect};

use crate::outcome::Domain;
use crate::state::{App, Tab};

pub const MIN_WIDTH: u16 = 60;
pub const MIN_HEIGHT: u16 = 16;

/// The regions of a frame at or above the minimum size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Areas {
    pub header: Rect,
    pub body: Body,
    pub footer: Rect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    /// No snapshot has arrived.
    Waiting(Rect),
    Overview(OverviewAreas),
    /// A list over its detail pane, on Signals, Jobs and Findings.
    Split {
        list: Rect,
        detail: Rect,
    },
    /// Profiles; [`profiles`] splits it once the run window is known.
    Profiles(Rect),
}

/// The Overview panes. `trend` is present from 110 columns; `domains` and
/// `outcomes` are zero-height when the body is too short for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverviewAreas {
    pub facts: Rect,
    pub trend: Option<Rect>,
    pub domains: Rect,
    pub outcomes: Rect,
    pub signals: Rect,
}

/// The regions of `area` for `app`, or `None` below
/// [`MIN_WIDTH`]x[`MIN_HEIGHT`], where the compact view takes the frame.
pub fn layout(area: Rect, app: &App) -> Option<Areas> {
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        return None;
    }
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(area);
    let body = match (app.derived(), app.tab) {
        (None, _) => Body::Waiting(body),
        (Some(d), Tab::Overview) => Body::Overview(overview(body, d.labels.len())),
        (Some(_), Tab::Profiles) => Body::Profiles(body),
        (Some(d), Tab::Findings) => {
            let (list, detail) = findings(body, d.snapshot.failure_groups.len());
            Body::Split { list, detail }
        }
        (Some(_), Tab::Signals | Tab::Jobs) => {
            let [list, detail] =
                Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .areas(body);
            Body::Split { list, detail }
        }
    };
    Some(Areas {
        header,
        body,
        footer,
    })
}

/// The signal table keeps at least five rows: borders, header and two
/// signals. The facts block holds seven lines and two borders; on a shorter
/// body it gives up its lowest-priority lines for the table. The band of
/// domain and outcome tables wants a row per domain or each of `labels`
/// outcomes plus two borders; below 11 remaining rows it is dropped so the
/// signal table keeps its rows, and otherwise it takes at most half of them
/// and at least five, which shows three entries.
pub fn overview(area: Rect, labels: usize) -> OverviewAreas {
    let facts_height = area.height.saturating_sub(5).min(9);
    let rest = area.height.saturating_sub(facts_height);
    let wanted = u16::try_from(labels.max(Domain::ALL.len() + 1))
        .unwrap_or(u16::MAX)
        .saturating_add(2);
    let band = if rest < 11 {
        0
    } else {
        wanted.min(rest / 2).max(5)
    };
    let [top, middle, signals] = Layout::vertical([
        Constraint::Length(facts_height),
        Constraint::Length(band),
        Constraint::Min(3),
    ])
    .areas(area);
    let (facts, trend) = if top.width >= 110 {
        let [facts, trend] =
            Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)]).areas(top);
        (facts, Some(trend))
    } else {
        (top, None)
    };
    let [domains, outcomes] =
        Layout::horizontal([Constraint::Length(26), Constraint::Min(30)]).areas(middle);
    OverviewAreas {
        facts,
        trend,
        domains,
        outcomes,
        signals,
    }
}

/// The group table wants its borders, header and a row per one of `groups`,
/// and takes at most two fifths of the pane and at least one data row, so
/// the detail below keeps room for the target finding and its commands.
pub fn findings(area: Rect, groups: usize) -> (Rect, Rect) {
    let listed = u16::try_from(groups).unwrap_or(u16::MAX).saturating_add(3);
    let [table, detail] = Layout::vertical([
        Constraint::Length(listed.min(area.height * 2 / 5).max(4)),
        Constraint::Min(4),
    ])
    .areas(area);
    (table, detail)
}

/// The Profiles table, its workload pane and the run header depth for runs
/// of `digits` digits. The table needs its borders, a header row per digit
/// and one data row; the workload pane takes at most its five lines and
/// borders and at least one line. When the stacked digits leave no room,
/// the header shows only the last digit of each run.
pub fn profiles(area: Rect, digits: u32) -> (Rect, Rect, u16) {
    let depth = u16::try_from(digits).unwrap_or(u16::MAX).max(2);
    let depth = if area.height >= depth.saturating_add(3 + 3) {
        depth
    } else {
        1
    };
    let detail_height = area.height.saturating_sub(depth + 3).min(7);
    let [table, detail] = Layout::vertical([
        Constraint::Min(depth + 3),
        Constraint::Length(detail_height),
    ])
    .areas(area);
    (table, detail, depth)
}
