//! The help overlay, read from the binding table, then the severity, domain
//! and glyph legends.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use super::LEGEND;
use super::panes::rows_of;
use crate::state::App;
use crate::tui::keymap::{Context, Keymap, Scope};
use crate::tui::theme::Theme;

/// Columns of one key entry in the help overlay.
pub(super) const HELP_COLUMN: u16 = 52;

/// The help overlay: the keys of the tab shown, then those after `g` and
/// `z`, in a search and in help on a list tab, read from the binding table and set
/// in two columns when the popup is wide enough, then the severity, domain
/// and glyph legends.
pub(super) fn help(frame: &mut Frame, area: Rect, app: &App, keymap: &Keymap, t: &Theme) {
    let tab = Context::of(app.tab);
    let mut sections = vec![(format!("Keys on {}", tab.name()), tab)];
    if tab != Context::Overview {
        sections.extend([
            ("After g".to_owned(), Context::PendingG),
            ("After z".to_owned(), Context::PendingZ),
            ("In a search".to_owned(), Context::Search),
            ("In help".to_owned(), Context::Help),
        ]);
    }
    let columns = if area.width >= 2 * HELP_COLUMN + 4 {
        2
    } else {
        1
    };
    let mut lines = Vec::new();
    for (heading, context) in sections {
        lines.push(Line::from(heading).style(t.heading));
        let entries: Vec<String> = keymap
            .entries(context, |binding| {
                context == tab || binding.scope == Scope::In(context)
            })
            .iter()
            .map(|entry| {
                let cell = format!("  {:<21} {}", entry.keys(), entry.label);
                format!("{cell:<width$}", width = usize::from(HELP_COLUMN))
            })
            .collect();
        for pair in entries.chunks(columns) {
            lines.push(Line::from(pair.concat().trim_end().to_owned()).style(t.text));
        }
    }
    lines.push(Line::from(""));
    lines.extend([
        Line::from("Severity").style(t.heading),
        Line::from("  critical  a failure group, a held record or triage history, a stuck"),
        Line::from("            attempt, a replay that is not deterministic, a simulator or"),
        Line::from("            campaign outcome, < 5 GiB free"),
        Line::from("  warning   a service or host outcome, a service seed change, undersized"),
        Line::from("            counts, triage that stalled, lacks evidence or hit a limit,"),
        Line::from("            an idle queue, a filling disk"),
        Line::from("  info      other seed changes, inconclusive simulator and chaos outcomes,"),
        Line::from("            throttling, retained probes"),
        Line::from(""),
        Line::from("Domains").style(t.heading),
        Line::from("  service    a checked property failed or the goal was missed"),
        Line::from("  simulator  the worker, replay, or evidence disagrees with itself"),
        Line::from("  campaign   supervisor records, admitted counts, evidence binding"),
        Line::from("  host       cgroup limits, watchdog, custody residue, filesystem space"),
        Line::from("  chaos      controller interruptions"),
        Line::from(""),
        Line::from("Profiles glyphs").style(t.heading),
        Line::from(format!("  {}", LEGEND[0])),
        Line::from(format!("  {}", LEGEND[1])),
    ]);
    // The popup fits the help text and its borders when the screen allows.
    let widest = lines.iter().map(Line::width).max().unwrap_or(0);
    let width = area
        .width
        .min(u16::try_from(widest + 2).unwrap_or(u16::MAX));
    let height = area
        .height
        .min(u16::try_from(lines.len() + 2).unwrap_or(u16::MAX));
    let popup = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    };
    let (inner_height, inner_width) = (
        usize::from(height.saturating_sub(2)),
        usize::from(width.saturating_sub(2)),
    );
    let total = rows_of(&lines, inner_width);
    let offset = app
        .help_scroll
        .get()
        .min(total.saturating_sub(inner_height));
    app.help_scroll.set(offset);
    app.help_height.set(inner_height);
    let title = if total > inner_height {
        format!(
            " help · rows {}-{} of {total} · j/k scroll · ? or esc closes ",
            offset + 1,
            (offset + inner_height).min(total)
        )
    } else {
        " help · ? or esc closes ".to_owned()
    };
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((u16::try_from(offset).unwrap_or(u16::MAX), 0))
            .block(Block::bordered().border_style(t.border).title(title)),
        popup,
    );
}
