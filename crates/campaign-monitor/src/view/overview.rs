//! The Overview tab: campaign facts, the finished-attempt trend, settled
//! counts by domain and by outcome, and the top signals.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, Cell, Paragraph, Row, Sparkline, Table, Wrap};

use super::layout::OverviewAreas;
use super::panes::{fits, si, table_rows, title};
use super::signals::signal_table;
use crate::outcome::{Domain, Outcome};
use crate::signals::{bytes, duration};
use crate::snapshot::JobState;
use crate::state::{App, Derived};
use crate::tui::text::{clip_left, fit};
use crate::tui::theme::{Theme, marker};

pub(super) fn overview(
    frame: &mut Frame,
    panes: &OverviewAreas,
    app: &App,
    d: &Derived,
    t: &Theme,
) {
    let snapshot = &d.snapshot;
    let totals = &d.totals;
    let labels = &d.labels;
    let (facts, domains, outcomes, bottom) =
        (panes.facts, panes.domains, panes.outcomes, panes.signals);
    let state = |state: JobState| totals.by_state.get(&state).copied().unwrap_or(0);
    let wall = |ms: Option<u64>| ms.map_or("-".to_owned(), duration);
    // A flagged fact line takes its detector's severity style and ends in
    // the severity's marker, so the flag reads without color.
    let flagged = |line: String, detector: &str| match d.worst.get(detector) {
        Some(severity) => {
            Line::from(format!("{line} {}", marker(*severity))).style(t.severity(*severity))
        }
        None => Line::from(line).style(t.text),
    };
    // Each fact line falls back to shorter forms, so its counts stay whole
    // at the narrowest facts pane.
    let inner = usize::from(facts.width.saturating_sub(2));
    let (held, settled, running, queued) = (
        state(JobState::Held),
        state(JobState::Settled),
        state(JobState::Running),
        state(JobState::Queued),
    );
    let waiting = state(JobState::Waiting).saturating_add(state(JobState::Settling));
    let jobs = fit(
        [
            format!(
                "jobs       {settled} settled · {running} running · {waiting} waiting · {queued} queued · {held} held"
            ),
            format!(
                "jobs  {held} held · {settled} settled · {running} running · {waiting} waiting · {queued} queued"
            ),
            format!("jobs {held} held {settled} done {running} run {waiting} wait {queued} queue"),
        ],
        inner,
    );
    let (findings, blockers, groups) = (
        snapshot.findings.len(),
        snapshot.release_blockers.len(),
        snapshot.failure_groups.len(),
    );
    let findings = fit(
        [
            format!(
                "findings   {findings} · {blockers} release blockers · {groups} failure groups"
            ),
            format!("findings {findings} · {blockers} blockers · {groups} groups"),
        ],
        inner,
    );
    let free = snapshot
        .space
        .map_or("-".to_owned(), |space| bytes(space.free_bytes));
    let inodes = snapshot
        .space
        .map_or("-".to_owned(), |space| si(space.free_inodes));
    let probes = snapshot.probes;
    let storage = fit(
        [
            format!("storage    {free} free · {inodes} inodes free · {probes} probe dirs"),
            format!("storage {free} free · {inodes} inodes · {probes} probes"),
        ],
        inner,
    );
    let state_dir = format!(
        "state dir  {}",
        clip_left(&snapshot.state, inner.saturating_sub(11))
    );
    // Each fact carries a drop rank: 0 always stays, and when the block is
    // short the line with the lowest remaining rank goes first. The minimum
    // body leaves five fact rows, so config goes, then wall.
    let mut facts_lines: Vec<(u8, Line)> = vec![
        (0, Line::from(state_dir)),
        (0, flagged(jobs, "held-record")),
        (
            0,
            Line::from(format!(
                "attempts   {} finished · {} in the last hour",
                totals.attempts, totals.finished_last_hour
            )),
        ),
        (
            2,
            Line::from(format!(
                "wall       p50 {} · p95 {} · max {}",
                wall(totals.wall_p50_ms),
                wall(totals.wall_p95_ms),
                wall(totals.wall_max_ms)
            )),
        ),
        (0, Line::from(findings)),
        (0, flagged(storage, "space")),
        (
            1,
            Line::from(format!(
                "config     {} slot(s) · wall limit {}",
                snapshot
                    .config_value("slots")
                    .map_or("-".into(), |v| v.to_string()),
                snapshot
                    .config_value("wall")
                    .map_or("-".into(), |v| duration(v.saturating_mul(1000)))
            )),
        ),
    ];
    let room = usize::from(facts.height.saturating_sub(2));
    for rank in 1..=2 {
        if facts_lines.len() > room {
            facts_lines.retain(|(drop, _)| *drop != rank);
        }
    }
    let lines: Vec<Line> = facts_lines.into_iter().map(|(_, line)| line).collect();
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().border_style(t.border).title(" campaign ")),
        facts,
    );
    if let Some(trend) = panes.trend {
        attempts_trend(frame, trend, d, t);
    }

    let mut counted: Vec<(Option<Domain>, u64)> = Domain::ALL
        .iter()
        .map(|domain| Some(*domain))
        .chain([None])
        .map(|domain| (domain, totals.by_domain.get(&domain).copied().unwrap_or(0)))
        .collect();
    let room = table_rows(domains, 0);
    if counted.len() > room {
        counted.retain(|(_, count)| *count > 0);
    }
    let shown = fits(counted.len(), room);
    let hidden = counted.len() - shown;
    counted.truncate(shown);
    let mut domain_rows: Vec<Row> = counted
        .into_iter()
        .map(|(domain, count)| {
            let name = domain.map_or("pass", Domain::name).to_owned();
            let style = if count == 0 {
                t.muted
            } else {
                t.outcome(&Outcome {
                    label: name.clone(),
                    domain,
                })
            };
            Row::new(vec![Cell::from(name), Cell::from(format!("{count:>7}"))]).style(style)
        })
        .collect();
    if hidden > 0 {
        domain_rows.push(Row::new(vec![Cell::from(format!("+{hidden} more"))]).style(t.muted));
    }
    frame.render_widget(
        Table::new(domain_rows, [Constraint::Length(11), Constraint::Length(8)])
            .style(t.text)
            .block(
                Block::bordered()
                    .border_style(t.border)
                    .title(" settled by domain "),
            ),
        domains,
    );
    let shown = fits(labels.len(), table_rows(outcomes, 0));
    let mut outcome_rows: Vec<Row> = labels[..shown]
        .iter()
        .map(|(label, count)| {
            Row::new(vec![
                Cell::from(format!("{count:>7}")),
                Cell::from(label.clone()),
            ])
        })
        .collect();
    if shown < labels.len() {
        let hidden: u64 = labels[shown..].iter().map(|(_, count)| *count).sum();
        outcome_rows.push(
            Row::new(vec![
                Cell::from(format!("{hidden:>7}")),
                Cell::from(format!(
                    "in {} more outcomes; 4 Jobs with filter all lists them",
                    labels.len() - shown
                )),
            ])
            .style(t.muted),
        );
    }
    frame.render_widget(
        Table::new(outcome_rows, [Constraint::Length(8), Constraint::Min(20)])
            .style(t.text)
            .block(
                Block::bordered()
                    .border_style(t.border)
                    .title(format!(" settled by outcome ({}) ", labels.len())),
            ),
        outcomes,
    );
    let room = table_rows(bottom, 1);
    let title = title(
        [
            format!(
                "signals: {} of {} shown",
                d.signals.len().min(room),
                d.signals.len()
            ),
            format!("{} critical", d.critical),
            "press 2 for details".to_owned(),
        ],
        bottom.width,
    );
    signal_table(frame, bottom, app, d, t, None, &title);
}

/// Plots the finished-attempt count of each history sample, offset by the
/// window's lowest count. The count is a level, so a record that turns held
/// lowers it and its recovery raises it again.
pub(super) fn attempts_trend(frame: &mut Frame, area: Rect, d: &Derived, t: &Theme) {
    let samples = &d.attempts;
    if samples.len() < 2 {
        frame.render_widget(
            Paragraph::new(format!(
                "collecting samples ({} of 2); a snapshot with a newer observation time adds one",
                samples.len()
            ))
            .style(t.muted)
            .wrap(Wrap { trim: true })
            .block(
                Block::bordered()
                    .border_style(t.border)
                    .title(" finished attempts "),
            ),
            area,
        );
        return;
    }
    let width = usize::from(area.width.saturating_sub(2));
    let attempts = &samples[samples.len().saturating_sub(width)..];
    let low = attempts.iter().copied().min().unwrap_or(0);
    let high = attempts.iter().copied().max().unwrap_or(0);
    let level: Vec<u64> = attempts.iter().map(|count| count - low).collect();
    let block = Block::bordered().border_style(t.border).title(title(
        [
            format!("last {} samples", attempts.len()),
            format!("finished attempts {low}-{high}"),
        ],
        area.width,
    ));
    frame.render_widget(Sparkline::default().data(&level).block(block), area);
}
