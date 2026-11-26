//! Rendering of [`App`] with ratatui, one file per region or tab. Each
//! table builds rows only for the window
//! [`Viewport::place`](crate::state::Viewport::place) returns, and a table
//! that hides rows says which rows it shows.

mod findings;
mod footer;
mod header;
mod help;
mod jobs;
pub mod layout;
mod overview;
mod panes;
mod profiles;
mod signals;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Wrap};

pub use layout::{MIN_HEIGHT, MIN_WIDTH};

use crate::signals::Severity;
use crate::state::{App, Tab};
use crate::tui::keymap::Keymap;
use crate::tui::text::clip;
use crate::tui::theme::{Theme, marker};
use layout::Body;

pub(crate) const VARIANT_WIDTH: u16 = 8;

pub const LEGEND: [&str; 2] = [
    "✓ pass  ✗ violation  ~ unsuccessful  ? inconclusive  ! failure",
    "k killed  ▶ running  … waiting  · queued",
];

/// Draws `app` into `frame`. Drawing a tab records the window of its list
/// in that tab's [`Viewport`](crate::state::Viewport), which [`App::update`]
/// reads to size paging moves, so the caller draws before it passes keys.
/// The minimum-size and waiting views record no window. Styles come from
/// `t`, and the drawn buffer is rewritten to its glyph set.
pub fn draw(frame: &mut Frame, app: &App, t: &Theme, keymap: &Keymap) {
    draw_views(frame, app, t, keymap);
    t.glyphs.apply(frame.buffer_mut());
}

fn draw_views(frame: &mut Frame, app: &App, t: &Theme, keymap: &Keymap) {
    let area = frame.area();
    let Some(areas) = layout::layout(area, app) else {
        tiny(frame, area, app, t);
        return;
    };
    header::header(frame, areas.header, app, t);
    match (areas.body, app.derived()) {
        (Body::Overview(panes), Some(d)) => overview::overview(frame, &panes, app, d, t),
        (Body::Split { list, detail }, Some(d)) => match app.tab {
            Tab::Signals => signals::signals(frame, list, detail, app, d, t),
            Tab::Jobs => jobs::jobs(frame, list, detail, app, d, t),
            _ => findings::findings(frame, list, detail, app, d, t),
        },
        (Body::Profiles(body), Some(d)) => profiles::profiles(frame, body, app, d, t),
        (Body::Waiting(_), _) | (_, None) => {
            frame.render_widget(
                Paragraph::new(app.error.clone().unwrap_or_else(|| {
                    format!("waiting for the first snapshot from {}", app.source)
                }))
                .style(t.text)
                .wrap(Wrap { trim: false }),
                body_rect(areas.body),
            )
        }
    }
    frame.render_widget(
        Paragraph::new(footer::footer(app, keymap, areas.footer.width, t)).style(t.muted),
        areas.footer,
    );
    if app.help {
        help::help(frame, area, app, keymap, t);
    }
}

fn body_rect(body: Body) -> Rect {
    match body {
        Body::Waiting(rect) | Body::Profiles(rect) => rect,
        Body::Split { list, detail } => list.union(detail),
        Body::Overview(panes) => panes.facts.union(panes.signals),
    }
}

fn tiny(frame: &mut Frame, area: Rect, app: &App, t: &Theme) {
    let (critical, warnings) = app.derived().map_or((0, 0), |d| (d.critical, d.warnings));
    let worst = app.derived().and_then(|d| d.signals.first());
    let style = worst.map_or(t.success, |signal| t.severity(signal.severity));
    let mut lines = vec![
        Line::from(format!(
            "{} {critical} critical · {} {warnings} warning",
            marker(Severity::Critical),
            marker(Severity::Warning)
        ))
        .style(style),
    ];
    if let Some(signal) = worst {
        lines.push(Line::from(clip(&signal.title, usize::from(area.width) * 2)).style(style));
    }
    let quits = if app.searching() {
        "a search is open; ctrl-c quits"
    } else if app.help {
        "help is open; ctrl-c quits"
    } else if app.pending().is_some() {
        "a key prefix is pending; ctrl-c quits"
    } else {
        "q quits"
    };
    lines.extend([
        Line::from(format!("enlarge the terminal to {MIN_WIDTH}x{MIN_HEIGHT}")),
        Line::from(quits).style(t.muted),
    ]);
    // The error follows the counts and hints, cut to twice the width in
    // characters, so the lines above it keep their place on a small screen.
    if let Some(error) = &app.error {
        lines.push(Line::from(clip(error, usize::from(area.width) * 2)).style(t.error));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .style(t.text)
            .wrap(Wrap { trim: true }),
        area,
    );
}

#[cfg(test)]
#[path = "view_tests.rs"]
mod tests;
