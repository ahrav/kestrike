//! The Profiles tab: the workload-by-run matrix over the selected
//! workload's counts and the glyph legend.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table, TableState, Wrap};

use super::layout;
use super::panes::{SELECTED, SELECTED_WIDTH, bound, selection, table_rows, title, window_note};
use super::{LEGEND, VARIANT_WIDTH};
use crate::model::{MatrixRow, glyph};
use crate::signals::Severity;
use crate::snapshot::Snapshot;
use crate::state::{App, Derived, Tab};
use crate::tui::text::prefix;
use crate::tui::theme::{Theme, marker};

pub(super) const FAIL_WIDTH: u16 = 7;

/// The numbers of the `shown` runs, one character each with a space
/// between, written down `depth` lines. A higher place's digit prints where
/// the run's digits from that place up differ from the run before it, so
/// each change of tens, hundreds or thousands is marked once.
pub(super) fn runs_header(shown: &[u64], depth: u16, t: &Theme) -> Cell<'static> {
    let mut lines: Vec<Line> = (1..u32::from(depth))
        .rev()
        .map(|power| {
            let place = 10u64.pow(power);
            let mut spans = Vec::with_capacity(2 * shown.len());
            for (index, run) in shown.iter().enumerate() {
                let previous = index.checked_sub(1).map(|i| shown[i]);
                if index > 0 {
                    spans.push(Span::raw(" "));
                }
                spans.push(
                    if previous.is_none_or(|previous| previous / place != run / place) {
                        Span::styled(format!("{}", (run / place) % 10), t.muted)
                    } else {
                        Span::raw(" ")
                    },
                );
            }
            Line::from(spans)
        })
        .collect();
    let mut units = Vec::with_capacity(2 * shown.len());
    for (index, run) in shown.iter().enumerate() {
        if index > 0 {
            units.push(Span::raw(" "));
        }
        units.push(Span::raw(format!("{}", run % 10)));
    }
    lines.push(Line::from(units));
    Cell::from(Text::from(lines))
}

pub(super) fn labelled(title: &str, depth: u16) -> Cell<'static> {
    Cell::from(format!("{}{title}", "\n".repeat(usize::from(depth) - 1)))
}

pub(super) fn profiles(frame: &mut Frame, area: Rect, app: &App, d: &Derived, t: &Theme) {
    let snapshot = &d.snapshot;
    let matrix = &d.matrix;
    let summary = &d.profile_summary;
    let show_campaign = summary.campaign.is_none() && !matrix.rows.is_empty();
    let campaign_width = summary.campaign_width;
    let profile_width = summary.profile_width;
    // The selection marker, the profile, variant and fail columns, each
    // followed by one space, then the borders and one spare cell.
    let fixed = SELECTED_WIDTH
        + profile_width
        + VARIANT_WIDTH
        + FAIL_WIDTH
        + 3
        + if show_campaign { campaign_width + 1 } else { 0 }
        + 3;
    let fits = usize::from(area.width.saturating_sub(fixed) / 2).max(1);
    let shift = app
        .run_shift
        .get()
        .min(matrix.runs.len().saturating_sub(fits));
    app.run_shift.set(shift);
    let last = matrix.runs.len() - shift;
    let shown = &matrix.runs[last.saturating_sub(fits)..last];
    app.runs_hidden.set(shown.len() < matrix.runs.len());
    let digits = shown
        .last()
        .map_or(1, |run| run.checked_ilog10().unwrap_or(0) + 1);
    let (table, detail, depth) = layout::profiles(area, digits);
    let mut header = Vec::new();
    let mut widths = Vec::new();
    if show_campaign {
        header.push(labelled("campaign", depth));
        widths.push(Constraint::Length(campaign_width));
    }
    header.extend([
        labelled("profile", depth),
        labelled("variant", depth),
        labelled("fail", depth),
    ]);
    widths.extend([
        Constraint::Length(profile_width),
        Constraint::Length(VARIANT_WIDTH),
        Constraint::Length(FAIL_WIDTH),
    ]);
    // All shown runs share one column of width 2n - 1: run i's glyph sits
    // at offset 2i in the header and in every row, under its run number.
    if !shown.is_empty() {
        let runs_width = u16::try_from(2 * shown.len() - 1).unwrap_or(u16::MAX);
        header.push(runs_header(shown, depth, t));
        widths.push(Constraint::Length(runs_width));
    }
    let height = table_rows(table, depth);
    let (start, end) = app
        .view(Tab::Profiles)
        .place(app.selected(), matrix.rows.len(), height);
    let rows = matrix.rows[start..end]
        .iter()
        .zip(&summary.failed[start..end])
        .map(|(row, &failed)| {
            let mut cells = Vec::new();
            if show_campaign {
                cells.push(Cell::from(row.campaign.clone()).style(t.muted));
            }
            cells.push(Cell::from(row.profile.clone()).style(if row.rank == 0 {
                t.service
            } else if row.failing() {
                t.heading
            } else {
                t.text
            }));
            cells.push(
                Cell::from(prefix(&row.variant, usize::from(VARIANT_WIDTH)).to_owned())
                    .style(t.muted),
            );
            // A service failure's count also carries the critical marker, so
            // it reads apart from other failures without color.
            cells.push(match failed {
                0 => Cell::from("   ·").style(t.muted),
                n if row.rank == 0 => {
                    Cell::from(format!("{n:>4} {}", marker(Severity::Critical))).style(t.service)
                }
                n => Cell::from(format!("{n:>4}")).style(t.warning),
            });
            if !shown.is_empty() {
                let mut spans = Vec::with_capacity(2 * shown.len());
                for (index, run) in shown.iter().enumerate() {
                    if index > 0 {
                        spans.push(Span::raw(" "));
                    }
                    spans.push(match row.cells.get(run) {
                        Some(cell) => {
                            Span::styled(glyph(&cell.outcome).to_string(), t.outcome(&cell.outcome))
                        }
                        None => Span::raw(" "),
                    });
                }
                cells.push(Cell::from(Line::from(spans)));
            }
            Row::new(cells)
        });
    let range = match (shown.first(), shown.last()) {
        (Some(first), Some(last)) if shown.len() < matrix.runs.len() => {
            format!("runs {first}-{last} of {}", matrix.runs.len())
        }
        (Some(first), Some(last)) => format!("runs {first}-{last}"),
        _ => "no runs".to_owned(),
    };
    // Both overflow notes lead, so neither is the part a narrow title drops.
    let workloads = match window_note(start, end, matrix.rows.len()) {
        Some(note) => format!("{} workloads, {note} · {range}", matrix.rows.len()),
        None => format!("{} workloads · {range}", matrix.rows.len()),
    };
    let mut parts = vec![workloads];
    if let Some(campaign) = &summary.campaign {
        parts.push(campaign.clone());
    }
    parts.extend([
        format!("{} with service failures", summary.service),
        format!("{} not passing", summary.failing),
    ]);
    let title = title(parts, table.width);
    let mut state = TableState::default().with_selected(Some(app.selected() - start));
    frame.render_stateful_widget(
        Table::new(rows, widths)
            .style(t.text)
            .header(Row::new(header).height(depth).style(t.heading))
            .column_spacing(1)
            .row_highlight_style(selection(app, t))
            .highlight_symbol(SELECTED)
            .block(
                Block::bordered()
                    .border_style(t.border_focused)
                    .title(title),
            ),
        table,
        &mut state,
    );
    let inner = usize::from(detail.width.saturating_sub(2)).max(1);
    let lines = match matrix.rows.get(app.selected()) {
        Some(row) => workload(row, &summary.counts[app.selected()], snapshot, t),
        None => vec![Line::from("no jobs")],
    };
    frame.render_widget(
        Paragraph::new(bound(
            lines,
            usize::from(detail.height.saturating_sub(2)),
            inner,
            "? shows the glyph legend",
            t,
        ))
        .wrap(Wrap { trim: true })
        .block(Block::bordered().border_style(t.border).title(" workload ")),
        detail,
    );
}

/// The selected workload's identity, its outcome `counts`, its declared
/// counts and the glyph legend, in the order a short pane keeps them.
pub(super) fn workload(
    row: &MatrixRow,
    counts: &str,
    snapshot: &Snapshot,
    t: &Theme,
) -> Vec<Line<'static>> {
    let declared = snapshot
        .variants
        .get(&row.variant)
        .map(|counts| {
            counts
                .iter()
                .filter(|(key, _)| {
                    matches!(
                        key.as_str(),
                        "turns" | "same_time" | "no_progress" | "records" | "bytes"
                    )
                })
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let build = if row.build.is_empty() {
        String::new()
    } else {
        format!(" · build {}", row.build)
    };
    vec![
        Line::from(format!(
            "{} · {}{build} · variant {}",
            row.profile, row.campaign, row.variant
        ))
        .style(t.heading),
        Line::from(counts.to_owned()),
        Line::from(declared).style(t.muted),
        Line::from(LEGEND[0]).style(t.muted),
        Line::from(LEGEND[1]).style(t.muted),
    ]
}
