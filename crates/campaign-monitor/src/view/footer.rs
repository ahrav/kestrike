//! The footer row, read from the binding table.

use ratatui::text::{Line, Span};

use crate::state::{App, Level, Tab};
use crate::tui::keymap::{Context, Keymap};
use crate::tui::text::clip;
use crate::tui::theme::Theme;

/// The footer: a live flash message, else the open search with its keys,
/// the keys a pending prefix takes, or the hints of the context, all from
/// the binding table.
pub(super) fn footer(app: &App, keymap: &Keymap, width: u16, t: &Theme) -> Line<'static> {
    if let Some(flash) = app.flash_at(std::time::Instant::now()) {
        let (style, mark) = match flash.level {
            Level::Info => (t.info, "i"),
            Level::Warn => (t.warning, "!"),
            Level::Error => (t.error, "!!"),
        };
        return Line::styled(
            clip(&format!("{mark} {}", flash.text), usize::from(width)),
            style,
        );
    }
    let context = app.context();
    let mut spans = match context {
        Context::Search => {
            let effect = if app.tab == Tab::Jobs {
                "narrows the job list"
            } else {
                "jumps to the first match"
            };
            vec![
                Span::styled("/", t.key_hint),
                Span::styled(app.search(app.tab).to_owned(), t.matched),
                Span::styled(format!("▏   {effect} · "), t.muted),
            ]
        }
        Context::PendingG | Context::PendingZ => {
            vec![Span::styled(
                format!("{}…   ", context.prefix()),
                t.key_hint,
            )]
        }
        _ => Vec::new(),
    };
    let used: usize = spans.iter().map(Span::width).sum();
    let room = u16::try_from(usize::from(width).saturating_sub(used)).unwrap_or(0);
    let hints = keymap.hint_line(context, room, |action| app.can(action), t.key_hint, t.muted);
    spans.extend(hints.spans);
    Line::from(spans)
}
