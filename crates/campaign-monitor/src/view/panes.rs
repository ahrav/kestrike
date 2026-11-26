//! Pieces every pane shares: titles that fit their border, table windows,
//! row budgets for word-wrapped detail panes, and the selection marker.

use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Wrap};

use crate::state::App;
use crate::tui::text::{clip_left, fit, width};
use crate::tui::theme::Theme;

/// Marks the selected row of a table, so the selection shows without
/// color.
pub(super) const SELECTED: &str = "▌ ";

pub(super) const SELECTED_WIDTH: u16 = 2;

/// The selected row's style: inactive while a search has the keys.
pub(super) fn selection(app: &App, t: &Theme) -> Style {
    if app.searching() {
        t.selection_inactive
    } else {
        t.selection
    }
}

/// A one-line block title for a block `width` columns wide: the first of
/// `parts` always, cut to fit, then each later part that still fits, in
/// order. A part that says rows are hidden therefore goes first.
pub(super) fn title(parts: impl IntoIterator<Item = String>, columns: u16) -> String {
    let room = usize::from(columns.saturating_sub(4));
    let mut title = String::new();
    for part in parts {
        if title.is_empty() {
            title = part;
            continue;
        }
        let next = format!("{title} · {part}");
        if width(&next) <= room {
            title = next;
        }
    }
    format!(" {} ", fit([title], room))
}

pub(super) fn table_rows(area: Rect, header: u16) -> usize {
    usize::from(area.height.saturating_sub(2 + header))
}

/// How many of `len` items to list in `room` rows: all when they fit,
/// otherwise one fewer than the room, leaving a row to count the rest.
pub(super) fn fits(len: usize, room: usize) -> usize {
    if len > room {
        room.saturating_sub(1)
    } else {
        len
    }
}

/// Rows `line` takes in a paragraph word-wrapped to `width` columns.
pub(super) fn rows(line: &Line, width: usize) -> usize {
    Paragraph::new(line.clone())
        .wrap(Wrap { trim: false })
        .line_count(u16::try_from(width).unwrap_or(u16::MAX).max(1))
        .max(1)
}

pub(super) fn rows_of(lines: &[Line], width: usize) -> usize {
    lines.iter().map(|line| rows(line, width)).sum()
}

/// Appends whole `blocks` to `lines` while they fit in `height` rows of
/// `width` columns, keeping a row for a count of the rest when fewer than
/// `total` fit, and returns how many it appended.
pub(super) fn fill(
    lines: &mut Vec<Line<'static>>,
    blocks: impl IntoIterator<Item = Vec<Line<'static>>>,
    total: usize,
    height: usize,
    width: usize,
) -> usize {
    let mut used = rows_of(lines, width);
    let mut shown = 0;
    for block in blocks {
        let need = rows_of(&block, width);
        let reserve = usize::from(shown + 1 < total);
        if used + need + reserve > height {
            break;
        }
        used += need;
        lines.extend(block);
        shown += 1;
    }
    shown
}

/// `lines` kept within `height` rows of `width` columns. When they take
/// more, lines are dropped from the end and `notice` ends the pane, so a
/// pane that cannot show everything says so.
pub(super) fn bound(
    mut lines: Vec<Line<'static>>,
    height: usize,
    width: usize,
    notice: &str,
    t: &Theme,
) -> Vec<Line<'static>> {
    let heights: Vec<usize> = lines.iter().map(|line| rows(line, width)).collect();
    let mut used: usize = heights.iter().sum();
    if used <= height {
        return lines;
    }
    let notice = Line::from(notice.to_owned()).style(t.muted);
    let reserve = rows(&notice, width);
    for rows in heights.iter().rev() {
        if lines.is_empty() || used + reserve <= height {
            break;
        }
        lines.pop();
        used -= rows;
    }
    lines.push(notice);
    lines
}

/// `rows a-b of n` when a table window shows fewer than its `len` rows.
pub(super) fn window_note(start: usize, end: usize, len: usize) -> Option<String> {
    (end - start < len).then(|| format!("rows {}-{end} of {len}", start + 1))
}

pub(super) fn si(value: u64) -> String {
    match value {
        0..1_000 => value.to_string(),
        1_000..1_000_000 => format!("{:.1}k", value as f64 / 1e3),
        1_000_000..1_000_000_000 => format!("{:.1}M", value as f64 / 1e6),
        _ => format!("{:.2}G", value as f64 / 1e9),
    }
}

/// A detail pane title naming the state directory that its relative paths
/// start from, cut from the left to fit `width`.
pub(super) fn paths_title(pane: &str, state: &str, width: u16) -> String {
    let fixed = self::width(pane) + self::width(" ·  paths under  ");
    let room = usize::from(width.saturating_sub(2)).saturating_sub(fixed);
    format!(" {pane} · paths under {} ", clip_left(state, room))
}
