//! The Jobs tab: the listed jobs, with columns dropped by priority as the
//! table narrows, over the selected job's signals and attempts.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table, TableState, Wrap};

use super::panes::{
    SELECTED, SELECTED_WIDTH, bound, fill, paths_title, selection, table_rows, title, window_note,
};
use crate::outcome::Outcome;
use crate::signals::{Severity, Signal, duration};
use crate::snapshot::{Job, JobState};
use crate::state::{App, Derived, JobFilter, Tab};
use crate::tui::text::{clip, prefix, width};
use crate::tui::theme::{Theme, marker};

/// Columns of the widest label that names no rule, `inconclusive: limit
/// no_progress`: the least the Outcome column takes.
const OUTCOME_WIDTH: u16 = 31;

/// The least the Profile column takes.
const PROFILE_WIDTH: u16 = 12;

/// The columns one frame gives the Outcome and Profile cells.
#[derive(Clone, Copy)]
struct Room {
    outcome: usize,
    profile: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JobColumn {
    Flag,
    State,
    Outcome,
    Profile,
    CampaignRun,
    Wall,
    Attempts,
    Id,
}

impl JobColumn {
    fn title(self) -> &'static str {
        match self {
            Self::Flag => "",
            Self::State => "state",
            Self::Outcome => "outcome",
            Self::Profile => "profile",
            Self::CampaignRun => "campaign/run",
            Self::Wall => "wall",
            Self::Attempts => "att",
            Self::Id => "job",
        }
    }

    /// Each column's width, with Outcome and Profile at their least.
    /// [`jobs`] widens Outcome to the labels on screen and gives Profile
    /// the rest.
    fn width(self) -> Constraint {
        match self {
            Self::Flag => Constraint::Length(2),
            Self::State => Constraint::Length(8),
            Self::Outcome => Constraint::Length(OUTCOME_WIDTH),
            Self::Profile => Constraint::Min(PROFILE_WIDTH),
            Self::CampaignRun => Constraint::Length(16),
            Self::Wall => Constraint::Length(7),
            Self::Attempts => Constraint::Length(5),
            Self::Id => Constraint::Length(12),
        }
    }

    fn shown(table: u16) -> Vec<Self> {
        [
            (Self::Flag, 0),
            (Self::State, 0),
            (Self::Outcome, 0),
            (Self::Profile, 0),
            (Self::CampaignRun, 90),
            (Self::Wall, 75),
            (Self::Attempts, 105),
            (Self::Id, 125),
        ]
        .into_iter()
        .filter(|(_, minimum)| table >= *minimum)
        .map(|(column, _)| column)
        .collect()
    }

    fn cell(
        self,
        job: &Job,
        outcome: &Outcome,
        flag: Option<Severity>,
        now: u64,
        room: Room,
        t: &Theme,
    ) -> Cell<'static> {
        match self {
            Self::Flag => match flag {
                Some(severity) => Cell::from(marker(severity)).style(t.severity(severity)),
                None => Cell::from(" "),
            },
            Self::Profile if job.held.is_some() => {
                Cell::from(format!("job {}", clip(&job.id, 13))).style(t.muted)
            }
            _ if job.held.is_some() && self != Self::Outcome && self != Self::Id => {
                Cell::from("-").style(t.muted)
            }
            Self::State => Cell::from(job.state.name()),
            Self::Outcome => {
                Cell::from(clip(&outcome.label, room.outcome)).style(t.outcome(outcome))
            }
            Self::Profile => Cell::from(clip(&job.profile, room.profile)),
            Self::CampaignRun => Cell::from(format!("{}/{}", job.campaign, run_text(job))),
            Self::Wall => {
                let last = job.last_attempt();
                let wall = last.and_then(|row| row.wall_ms()).or_else(|| {
                    last.and_then(|row| row.intent_ms)
                        .map(|intent| now.saturating_sub(intent))
                });
                let cell = Cell::from(wall.map_or("-".to_owned(), duration));
                match flag {
                    Some(severity) if job.state == JobState::Running => {
                        cell.style(t.severity(severity))
                    }
                    _ => cell,
                }
            }
            Self::Attempts => {
                Cell::from(format!("{}/{}", job.attempts.len(), job.attempts_allowed))
            }
            Self::Id => Cell::from(prefix(&job.id, 12).to_owned()).style(t.muted),
        }
    }
}

fn run_text(job: &Job) -> String {
    job.run
        .map_or_else(|| "-".to_owned(), |run| run.to_string())
}

pub(super) fn jobs(
    frame: &mut Frame,
    table: Rect,
    detail: Rect,
    app: &App,
    d: &Derived,
    t: &Theme,
) {
    let snapshot = &d.snapshot;
    let columns = JobColumn::shown(table.width);
    let fixed: u16 = columns
        .iter()
        .map(|column| match column.width() {
            Constraint::Length(width) => width + 1,
            _ => 1,
        })
        .sum();
    let height = table_rows(table, 1);
    let (start, end) = app
        .view(Tab::Jobs)
        .place(app.selected(), app.listed.len(), height);
    // Outcome grows to the widest label on screen by at most the columns
    // Profile holds past its minimum; a label cut there ends in a mark.
    let spare = table.width.saturating_sub(fixed + 2 + SELECTED_WIDTH);
    let widest = (start..end)
        .filter_map(|row| app.job(row))
        .map(|(_, outcome)| width(&outcome.label))
        .max()
        .unwrap_or(0);
    let grown = u16::try_from(widest)
        .unwrap_or(u16::MAX)
        .saturating_sub(OUTCOME_WIDTH)
        .min(spare.saturating_sub(PROFILE_WIDTH));
    let room = Room {
        outcome: usize::from(OUTCOME_WIDTH + grown),
        profile: usize::from((spare - grown).max(PROFILE_WIDTH)),
    };
    let widths = columns.iter().map(|column| match column {
        JobColumn::Outcome => Constraint::Length(OUTCOME_WIDTH + grown),
        column => column.width(),
    });
    let rows = (start..end).filter_map(|row| {
        let (job, outcome) = app.job(row)?;
        let flag = app.flag(&job.id);
        Some(Row::new(columns.iter().map(|column| {
            column.cell(job, outcome, flag, snapshot.observed_ms, room, t)
        })))
    });
    let mut state = TableState::default().with_selected(Some(app.selected() - start));
    let mut parts = vec![match window_note(start, end, app.listed.len()) {
        Some(note) => format!(
            "{} of {} jobs, {note}",
            app.listed.len(),
            snapshot.jobs.len()
        ),
        None => format!("{} of {} jobs", app.listed.len(), snapshot.jobs.len()),
    }];
    parts.push(match &app.focus {
        Some(focus) => format!("focus {}", clip(&focus.label, 41)),
        None => format!("filter {}", app.filter.name()),
    });
    let search = app.search(Tab::Jobs);
    if !search.is_empty() {
        parts.push(format!("search \"{search}\""));
    }
    if app.focus.is_none() && app.filter == JobFilter::Problems {
        parts.push("!! ! i: worst signal naming the job".to_owned());
    }
    let title = title(parts, table.width);
    frame.render_stateful_widget(
        Table::new(rows, widths)
            .style(t.text)
            .header(Row::new(columns.iter().map(|column| column.title())).style(t.heading))
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
    let text = match app.job(app.selected()) {
        Some((job, _)) => Text::from(job_detail(
            job,
            app.naming(&job.id),
            usize::from(detail.height.saturating_sub(2)),
            usize::from(detail.width.saturating_sub(2)).max(1),
            t,
        )),
        None => Text::from(match (&app.focus, app.search(Tab::Jobs).is_empty()) {
            (_, false) => "no jobs match; esc clears the search",
            (Some(_), true) => "the focus names no listed job; esc clears the focus",
            (None, true) => "no jobs match; f changes the filter",
        }),
    };
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(
            Block::bordered().border_style(t.border).title(paths_title(
                "job",
                &snapshot.state,
                detail.width,
            )),
        ),
        detail,
    );
}

/// The detail of `job` in `height` rows of `width` columns: its identity,
/// as many of the `naming` signals and then of the attempts as fit, each
/// list with a count of the rest. A held job shows its reason and record
/// path before its id.
pub(super) fn job_detail<'a>(
    job: &Job,
    naming: impl Iterator<Item = &'a Signal>,
    height: usize,
    width: usize,
    t: &Theme,
) -> Vec<Line<'static>> {
    let id = &job.id;
    if let Some(held) = &job.held {
        let lines = vec![
            Line::from(format!("held: {held}")).style(t.error),
            Line::from(format!("jobs/{id}.json")).style(t.muted),
            Line::from(format!("job {id}")).style(t.heading),
        ];
        return bound(lines, height, width, "enlarge the pane for the job id", t);
    }
    let mut lines = vec![
        Line::from(format!(
            "{} · {} run {} · seed {} · variant {} · class {}",
            job.profile,
            job.campaign,
            run_text(job),
            job.seed,
            job.variant,
            job.class.as_deref().unwrap_or("-")
        ))
        .style(t.heading),
        Line::from(format!("job {id}")).style(t.muted),
    ];
    let naming: Vec<&Signal> = naming.collect();
    let signals = naming.len();
    let named = fill(
        &mut lines,
        naming.iter().map(|signal| {
            vec![
                Line::from(format!("{}: {}", signal.severity.name(), signal.title))
                    .style(t.severity(signal.severity)),
            ]
        }),
        signals,
        height,
        width,
    );
    if named < signals {
        lines.push(
            Line::from(format!("  {} more signals name the job", signals - named)).style(t.muted),
        );
    }
    let blocks = job.attempts.iter().map(|row| {
        let outcome = Outcome::of_attempt(row);
        let number = row.number.map_or_else(
            || row.entry.clone().unwrap_or_default(),
            |n| format!("{n:04}"),
        );
        let mut spans = vec![
            Span::raw(format!("  {number} ")),
            Span::styled(outcome.label.clone(), t.outcome(&outcome)),
        ];
        if let Some(wall) = row.wall_ms() {
            spans.push(Span::raw(format!(" · {}", duration(wall))));
        }
        if let Some(finish) = &row.finished {
            if let Some(cpu) = finish.kernel.cpu_usage_usec {
                spans.push(Span::raw(format!(" · cpu {}", duration(cpu / 1000))));
            }
            if let Some(exit) = finish.exit {
                spans.push(Span::raw(format!(" · exit {exit}")));
            }
            if let Some(signal) = finish.signal {
                spans.push(Span::raw(format!(" · signal {signal}")));
            }
            if finish.watchdog {
                spans.push(Span::raw(" · watchdog"));
            }
        }
        if let Some(finding) = &row.finding {
            spans.push(Span::styled(format!(" · finding {finding}"), t.error));
        }
        let mut block = vec![Line::from(spans)];
        if let Some(held) = &row.held {
            block.push(Line::from(format!("       held: {held}")).style(t.error));
        }
        if let Some(sim) = &row.sim {
            if let Some(held) = &sim.held {
                block.push(Line::from(format!("       artifact held: {held}")).style(t.error));
            }
            if let Some(cause) = &sim.cause {
                block.push(Line::from(format!("       cause: {cause}")));
            }
            if let Some(terminal) = &sim.terminal {
                block.push(Line::from(format!("       terminal: {terminal}")).style(t.muted));
            }
        }
        if let (Some(number), Some(attempt)) = (row.number, &row.attempt) {
            block.push(
                Line::from(format!(
                    "       attempts/{}/{number:04}/artifacts/{attempt}/run.stdout",
                    job.id
                ))
                .style(t.muted),
            );
        }
        block
    });
    let total = job.attempts.len();
    let shown = fill(&mut lines, blocks, total, height, width);
    if shown < total {
        lines.push(Line::from(format!("  {} more attempts", total - shown)).style(t.muted));
    }
    if job.attempts.is_empty() {
        lines.push(Line::from("  no attempts yet").style(t.muted));
    }
    bound(lines, height, width, "enlarge the pane for the attempts", t)
}
