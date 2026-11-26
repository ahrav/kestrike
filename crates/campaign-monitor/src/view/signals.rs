//! The Signals tab: the signal table over the selected signal's detail.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table, TableState, Wrap};

use super::panes::{SELECTED, bound, fill, selection, table_rows, window_note};
use crate::state::{App, Derived, Tab};
use crate::tui::theme::Theme;

pub(super) fn signal_table(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    d: &Derived,
    t: &Theme,
    selected: Option<usize>,
    title: &str,
) {
    let height = table_rows(area, 1);
    let (start, end) = match selected {
        Some(row) => app.view(Tab::Signals).place(row, d.signals.len(), height),
        None => (0, d.signals.len().min(height)),
    };
    let rows = d.signals[start..end].iter().map(|signal| {
        Row::new(vec![
            Cell::from(signal.severity.name()).style(t.severity(signal.severity)),
            Cell::from(signal.domain.name()),
            Cell::from(signal.title.clone()),
        ])
    });
    let mut state = TableState::default().with_selected(selected.map(|row| row - start));
    let title = match window_note(start, end, d.signals.len()).filter(|_| selected.is_some()) {
        Some(note) => format!("{title}· {note} "),
        None => title.to_owned(),
    };
    frame.render_stateful_widget(
        Table::new(
            rows,
            [
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Min(20),
            ],
        )
        .header(Row::new(["severity", "domain", "signal"]).style(t.heading))
        .row_highlight_style(selection(app, t))
        .highlight_symbol(SELECTED)
        .block(
            Block::bordered()
                .border_style(if selected.is_some() {
                    t.border_focused
                } else {
                    t.border
                })
                .title(title),
        ),
        area,
        &mut state,
    );
}

pub(super) fn signals(
    frame: &mut Frame,
    list: Rect,
    detail: Rect,
    app: &App,
    d: &Derived,
    t: &Theme,
) {
    let selected = app.selected();
    signal_table(
        frame,
        list,
        app,
        d,
        t,
        Some(selected),
        &format!(" {} signals ", d.signals.len()),
    );
    let height = usize::from(detail.height.saturating_sub(2));
    let width = usize::from(detail.width.saturating_sub(2));
    let text = match d.signals.get(selected) {
        Some(signal) => {
            let mut lines = vec![
                Line::from(signal.title.clone()).style(t.severity(signal.severity)),
                Line::from(format!(
                    "{} · {} · detector {}",
                    signal.severity.name(),
                    signal.domain.name(),
                    signal.detector
                ))
                .style(t.muted),
                Line::from(""),
                Line::from(signal.detail.clone()),
            ];
            if !signal.subjects.is_empty() {
                lines.push(Line::from(""));
                lines.push(
                    Line::from(format!("subjects ({}):", signal.subjects.len())).style(t.heading),
                );
                let total = signal.subjects.len();
                let blocks = signal
                    .subjects
                    .iter()
                    .map(|subject| vec![Line::from(format!("  {subject}"))]);
                let shown = fill(&mut lines, blocks, total, height, width);
                if shown < total {
                    lines.push(
                        Line::from(format!(
                            "  {} more; `campaign-monitor check --json` lists all",
                            total - shown
                        ))
                        .style(t.muted),
                    );
                }
            }
            Text::from(bound(
                lines,
                height,
                width,
                "more in `campaign-monitor check --json`",
                t,
            ))
        }
        None => Text::from("no signals"),
    };
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().border_style(t.border).title(" detail ")),
        detail,
    );
}
