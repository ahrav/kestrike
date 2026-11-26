//! The binding table's rows. A new key is one row here; dispatch, the hint
//! bar, the which-key footer and help all read these rows.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::keymap::{Action, Binding, Context, Keymap, Scope};
use crate::state::Tab;

impl Keymap {
    pub fn default_map() -> Self {
        use Action::*;
        use Context::{Findings, Help as HelpContext, Jobs, PendingG, PendingZ, Profiles, Signals};
        use Scope::{Any, In, Lists, Tabs};
        let k = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let c = |c| k(KeyCode::Char(c));
        let ctrl = |c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL);
        let b = |scope, key, action, label, in_hint_bar| Binding {
            scope,
            key,
            action,
            label,
            in_hint_bar,
        };
        let mut bindings = vec![
            b(Lists, c('j'), Down, "move", true),
            b(Lists, c('k'), Up, "move", true),
            b(Lists, k(KeyCode::Down), Down, "move", false),
            b(Lists, k(KeyCode::Up), Up, "move", false),
            b(Lists, ctrl('d'), HalfDown, "half screen", true),
            b(Lists, ctrl('u'), HalfUp, "half screen", true),
            b(Lists, ctrl('f'), PageDown, "screen", false),
            b(Lists, ctrl('b'), PageUp, "screen", false),
            b(Lists, k(KeyCode::PageDown), PageDown, "screen", false),
            b(Lists, k(KeyCode::PageUp), PageUp, "screen", false),
            b(Lists, c(' '), PageDown, "screen", false),
            b(Tabs, c('g'), PrefixG, "g prefix", false),
            b(Lists, c('G'), Bottom, "last row", true),
            b(Lists, k(KeyCode::Home), Top, "first row", false),
            b(Lists, k(KeyCode::End), Bottom, "last row", false),
            b(
                Lists,
                c('H'),
                ScreenTop,
                "screen top, middle, bottom",
                false,
            ),
            b(
                Lists,
                c('M'),
                ScreenMiddle,
                "screen top, middle, bottom",
                false,
            ),
            b(
                Lists,
                c('L'),
                ScreenBottom,
                "screen top, middle, bottom",
                false,
            ),
            b(Lists, c('z'), PrefixZ, "z prefix", false),
            b(Lists, ctrl('e'), ScrollDown, "scroll a line", false),
            b(Lists, ctrl('y'), ScrollUp, "scroll a line", false),
            b(Lists, c('/'), Search, "search", true),
            b(In(Signals), c('n'), NextMatch, "next, previous match", true),
            b(In(Signals), c('N'), PrevMatch, "next, previous match", true),
            b(
                In(Profiles),
                c('n'),
                NextMatch,
                "next, previous match",
                true,
            ),
            b(
                In(Profiles),
                c('N'),
                PrevMatch,
                "next, previous match",
                true,
            ),
            b(
                In(Findings),
                c('n'),
                NextMatch,
                "next, previous match",
                true,
            ),
            b(
                In(Findings),
                c('N'),
                PrevMatch,
                "next, previous match",
                true,
            ),
            b(In(Profiles), c('h'), RunsOlder, "older, newer runs", true),
            b(In(Profiles), c('l'), RunsNewer, "older, newer runs", true),
            b(
                In(Profiles),
                k(KeyCode::Left),
                RunsOlder,
                "older, newer runs",
                false,
            ),
            b(
                In(Profiles),
                k(KeyCode::Right),
                RunsNewer,
                "older, newer runs",
                false,
            ),
            b(
                In(Profiles),
                c('0'),
                RunsOldest,
                "oldest, newest runs",
                false,
            ),
            b(
                In(Profiles),
                c('$'),
                RunsNewest,
                "oldest, newest runs",
                false,
            ),
            b(In(Jobs), c('f'), Filter, "filter", true),
            b(Lists, k(KeyCode::Enter), Drill, "open as jobs", true),
            b(Lists, ctrl('o'), Back, "back", true),
            b(Lists, k(KeyCode::Backspace), Back, "back", false),
            b(
                Lists,
                k(KeyCode::Esc),
                Clear,
                "clear search, then focus",
                true,
            ),
            b(Lists, c('y'), Yank, "copy", true),
            b(Tabs, c('1'), Open(Tab::Overview), "tab", true),
            b(Tabs, c('2'), Open(Tab::Signals), "tab", true),
            b(Tabs, c('3'), Open(Tab::Profiles), "tab", true),
            b(Tabs, c('4'), Open(Tab::Jobs), "tab", true),
            b(Tabs, c('5'), Open(Tab::Findings), "tab", true),
            b(Tabs, k(KeyCode::Tab), NextTab, "next, previous tab", false),
            b(
                Tabs,
                KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT),
                PrevTab,
                "next, previous tab",
                false,
            ),
            b(Tabs, c('r'), Refresh, "refresh", true),
            b(Tabs, c('p'), Pause, "pause", true),
            b(Tabs, c('?'), Help, "help", true),
            b(Tabs, c('q'), Quit, "quit", true),
            b(In(PendingG), c('g'), Top, "first row", true),
            b(In(PendingG), c('t'), NextTab, "next tab", true),
            b(In(PendingG), c('T'), PrevTab, "previous tab", true),
            b(In(PendingZ), c('z'), Center, "center the row", true),
            b(In(PendingZ), c('t'), AlignTop, "row to the top", true),
            b(In(PendingZ), c('b'), AlignBottom, "row to the bottom", true),
            b(
                In(Context::Search),
                k(KeyCode::Enter),
                SearchKeep,
                "keep",
                true,
            ),
            b(
                In(Context::Search),
                k(KeyCode::Esc),
                SearchCancel,
                "cancel",
                true,
            ),
            b(
                In(Context::Search),
                k(KeyCode::Backspace),
                SearchErase,
                "erase",
                false,
            ),
            b(In(HelpContext), c('j'), HelpDown, "scroll", true),
            b(In(HelpContext), c('k'), HelpUp, "scroll", true),
            b(In(HelpContext), k(KeyCode::Down), HelpDown, "scroll", false),
            b(In(HelpContext), k(KeyCode::Up), HelpUp, "scroll", false),
            b(
                In(HelpContext),
                ctrl('d'),
                HelpHalfDown,
                "half screen",
                true,
            ),
            b(In(HelpContext), ctrl('u'), HelpHalfUp, "half screen", true),
            b(
                In(HelpContext),
                k(KeyCode::PageDown),
                HelpHalfDown,
                "half screen",
                false,
            ),
            b(
                In(HelpContext),
                k(KeyCode::PageUp),
                HelpHalfUp,
                "half screen",
                false,
            ),
            b(In(HelpContext), c('G'), HelpBottom, "end", false),
            b(In(HelpContext), k(KeyCode::Home), HelpTop, "top", false),
            b(In(HelpContext), c('?'), CloseHelp, "close", true),
            b(In(HelpContext), k(KeyCode::Esc), CloseHelp, "close", true),
            b(In(HelpContext), c('q'), CloseHelp, "close", true),
            b(Any, ctrl('c'), Quit, "quit", false),
        ];
        for context in [PendingG, PendingZ] {
            bindings.push(b(
                In(context),
                k(KeyCode::Esc),
                CancelPrefix,
                "cancel",
                true,
            ));
        }
        Self::new(bindings)
    }
}
