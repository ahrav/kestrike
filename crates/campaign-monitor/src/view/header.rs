//! The summary bar keeps the severity counts, the snapshot age and PAUSED,
//! then adds job state counts, a pending refresh, the fetch error and the
//! state directory's controller while they fit; the fetch line under the tabs repeats an error it dropped.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Tabs};

use crate::signals::{Severity, duration};
use crate::snapshot::{Controller, JobState, Snapshot};
use crate::state::{App, Tab, age_text};
use crate::tui::text::width;
use crate::tui::theme::{Theme, marker};

pub(super) fn header(frame: &mut Frame, area: Rect, app: &App, t: &Theme) {
    let room = usize::from(area.width.saturating_sub(4));
    let (top, error_shown) = summary(app, t, room);
    let titles: Vec<Line> = Tab::ALL.iter().map(|tab| Line::from(tab.title())).collect();
    frame.render_widget(
        Tabs::new(titles)
            .select(app.tab.index())
            .style(t.text)
            .highlight_style(t.selection)
            .block(
                Block::bordered()
                    .border_style(t.border)
                    .title(top)
                    .title_bottom(fetch_line(app, t, !error_shown)),
            ),
        area,
    );
}

/// The fetch error, with a leading quoted source command and space
/// stripped.
fn cause(app: &App) -> Option<&str> {
    let error = app.error.as_deref()?;
    let command = format!("`{}` ", app.source);
    Some(error.strip_prefix(&command).unwrap_or(error))
}

/// The summary bar in `room` columns, and whether it shows the fetch
/// error.
pub(super) fn summary(app: &App, t: &Theme, room: usize) -> (Line<'static>, bool) {
    let mut kept: Vec<Span<'static>> = Vec::new();
    if let Some(d) = app.derived() {
        let count = |severity: Severity, n: usize, name: &str| {
            let style = if n == 0 {
                t.muted
            } else {
                t.severity(severity)
            };
            Span::styled(format!("{} {n} {name}", marker(severity)), style)
        };
        kept.push(count(Severity::Critical, d.critical, "critical"));
        kept.push(count(Severity::Warning, d.warnings, "warning"));
    }
    if let Some((age, stale)) = app.age(std::time::Instant::now()) {
        let (style, note) = if stale {
            (t.error, " STALE")
        } else {
            (t.text, "")
        };
        kept.push(Span::styled(
            format!("snapshot {} old{note}", age_text(age)),
            style,
        ));
    }
    if app.paused {
        let held = if app.holding() { " newer held" } else { "" };
        kept.push(Span::styled(format!("PAUSED{held}"), t.warning));
    }
    let mut optional: Vec<(Span<'static>, bool)> = Vec::new();
    if let Some(d) = app.derived() {
        let state = |state: JobState| d.totals.by_state.get(&state).copied().unwrap_or(0);
        let waiting = state(JobState::Waiting).saturating_add(state(JobState::Settling));
        let held = state(JobState::Held);
        optional.push((
            Span::styled(
                format!(
                    "{} running · {} queued · {waiting} waiting · {held} held",
                    state(JobState::Running),
                    state(JobState::Queued)
                ),
                if held > 0 { t.warning } else { t.text },
            ),
            false,
        ));
    }
    if app.refresh_pending() {
        optional.push((Span::styled("refresh pending", t.text), false));
    }
    if let Some(cause) = cause(app) {
        optional.push((Span::styled(cause.to_owned(), t.error), true));
    }
    if let Some(d) = app.derived() {
        let needs_controller = d
            .totals
            .by_state
            .iter()
            .any(|(state, &n)| state.needs_controller() && n > 0);
        if let Some(span) = controller(&d.snapshot, needs_controller, t) {
            optional.push((span, false));
        }
    }
    let joined = |spans: &[Span]| {
        spans
            .iter()
            .map(|span| width(&span.content) + 3)
            .sum::<usize>()
    };
    let mut error_shown = false;
    for (span, is_error) in optional {
        if joined(&kept) + width(&span.content) + 3 <= room {
            error_shown |= is_error;
            kept.push(span);
        }
    }
    let mut spans = vec![Span::raw(" ")];
    for (index, span) in kept.into_iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" · ", t.muted));
        }
        spans.push(span);
    }
    spans.push(Span::raw(" "));
    (Line::from(spans), error_shown)
}

/// The controller holding the state directory: its command and pid, `no
/// visible controller`, marked as a warning when `needs_controller` says
/// a job is unsettled, or `controller unknown`; `None` for a snapshot
/// without `lock`.
fn controller(snapshot: &Snapshot, needs_controller: bool, t: &Theme) -> Option<Span<'static>> {
    Some(match snapshot.controller()? {
        Controller::Running(holder) => {
            let command = holder.command.as_deref().unwrap_or("controller");
            let text = match holder.pid {
                Some(pid) => format!("{command} pid {pid}"),
                None => format!("{command} running"),
            };
            Span::styled(text, t.text)
        }
        Controller::None { .. } if needs_controller => Span::styled(
            format!("{} no visible controller", marker(Severity::Warning)),
            t.warning,
        ),
        Controller::None { .. } => Span::styled("no visible controller", t.muted),
        Controller::Unknown => Span::styled("controller unknown", t.muted),
    })
}

/// The latest fetch's duration, the error when the summary had no room for
/// it, then the source command, so a long command is what the border cuts.
fn fetch_line(app: &App, t: &Theme, with_error: bool) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    if let Some(fetch) = app.fetch_ms {
        spans.push(Span::styled(
            format!("fetch {} · ", duration(fetch)),
            t.muted,
        ));
    }
    if with_error && let Some(cause) = cause(app) {
        spans.push(Span::styled(format!("{cause} · "), t.error));
    }
    spans.push(Span::styled(format!("{} ", app.source), t.muted));
    Line::from(spans)
}
