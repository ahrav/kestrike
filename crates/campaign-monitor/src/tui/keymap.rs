//! The one binding table. Dispatch, the hint bar, the which-key footer of a
//! pending `g` or `z`, and the help overlay all read [`Keymap`], so the keys
//! they show are the keys that act.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::style::Style;
use ratatui::text::{Line, Span};

use crate::state::Tab;

/// What a key does. [`crate::state::App::update`] applies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Quit,
    Refresh,
    Help,
    CloseHelp,
    HelpDown,
    HelpUp,
    HelpHalfDown,
    HelpHalfUp,
    HelpTop,
    HelpBottom,
    Pause,
    Yank,
    Open(Tab),
    NextTab,
    PrevTab,
    Down,
    Up,
    HalfDown,
    HalfUp,
    PageDown,
    PageUp,
    Top,
    Bottom,
    ScreenTop,
    ScreenMiddle,
    ScreenBottom,
    ScrollDown,
    ScrollUp,
    Center,
    AlignTop,
    AlignBottom,
    PrefixG,
    PrefixZ,
    CancelPrefix,
    RunsOlder,
    RunsNewer,
    RunsOldest,
    RunsNewest,
    Search,
    NextMatch,
    PrevMatch,
    Drill,
    Back,
    Clear,
    Filter,
    SearchKeep,
    SearchCancel,
    SearchErase,
}

/// Where keys go. The five tab contexts follow the tab shown; `Search`,
/// `Help`, `PendingG` and `PendingZ` take the keys while a search is open,
/// help is shown, or a `g` or `z` prefix waits for its second key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    Overview,
    Signals,
    Profiles,
    Jobs,
    Findings,
    Search,
    Help,
    PendingG,
    PendingZ,
}

impl Context {
    /// The context of `tab` with nothing open over it.
    pub fn of(tab: Tab) -> Self {
        match tab {
            Tab::Overview => Self::Overview,
            Tab::Signals => Self::Signals,
            Tab::Profiles => Self::Profiles,
            Tab::Jobs => Self::Jobs,
            Tab::Findings => Self::Findings,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Signals => "Signals",
            Self::Profiles => "Profiles",
            Self::Jobs => "Jobs",
            Self::Findings => "Findings",
            Self::Search => "search",
            Self::Help => "help",
            Self::PendingG => "after g",
            Self::PendingZ => "after z",
        }
    }

    fn is_tab(self) -> bool {
        matches!(
            self,
            Self::Overview | Self::Signals | Self::Profiles | Self::Jobs | Self::Findings
        )
    }

    fn is_list(self) -> bool {
        self.is_tab() && self != Self::Overview
    }

    /// The key that opened this context, written before the keys bound in
    /// it.
    pub fn prefix(self) -> &'static str {
        match self {
            Self::PendingG => "g",
            Self::PendingZ => "z",
            _ => "",
        }
    }
}

/// The contexts a binding acts in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Every context, the open search and help included.
    Any,
    /// The five tab contexts.
    Tabs,
    /// The four tab contexts with a list.
    Lists,
    In(Context),
}

impl Scope {
    fn holds(self, context: Context) -> bool {
        match self {
            Self::Any => true,
            Self::Tabs => context.is_tab(),
            Self::Lists => context.is_list(),
            Self::In(only) => only == context,
        }
    }

    /// Lower ranks match first, so a context's own binding shadows a wider
    /// one for the same key.
    fn rank(self) -> u8 {
        match self {
            Self::In(_) => 0,
            Self::Lists => 1,
            Self::Tabs => 2,
            Self::Any => 3,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Any => "everywhere",
            Self::Tabs => "every tab",
            Self::Lists => "every list",
            Self::In(context) => context.name(),
        }
    }
}

/// One row of the table. Bindings that share a `label` in one scope are one
/// entry in the hint bar and the help overlay, keys joined by `/`.
/// `in_hint_bar` puts the binding in the hint bar while its action can act.
#[derive(Clone, Debug)]
pub struct Binding {
    pub scope: Scope,
    pub key: KeyEvent,
    pub action: Action,
    pub label: &'static str,
    pub in_hint_bar: bool,
}

/// The outcome of one key press.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dispatch {
    Act(Action),
    /// The key is bound only on other tabs, such as `f` outside Jobs or
    /// `j` on Overview; the first binding's scope and label are named.
    Elsewhere(Scope, &'static str),
    /// Nothing binds the key here or on another tab.
    Unbound,
}

pub struct Keymap {
    bindings: Vec<Binding>,
}

impl Keymap {
    pub(super) fn new(bindings: Vec<Binding>) -> Self {
        Self { bindings }
    }

    pub fn bindings(&self) -> &[Binding] {
        &self.bindings
    }

    /// The binding `key` takes in `context`: the narrowest scope wins. Only
    /// `KeyEventKind::Press` dispatches. A key bound only in other tab
    /// contexts reports the first of them, so the caller can say where it
    /// acts.
    pub fn dispatch(&self, context: Context, key: KeyEvent) -> Dispatch {
        if key.kind != KeyEventKind::Press {
            return Dispatch::Unbound;
        }
        let key = normalize(key);
        let matching = |binding: &&Binding| normalize(binding.key) == key;
        if let Some(binding) = self
            .bindings
            .iter()
            .filter(|binding| binding.scope.holds(context))
            .filter(matching)
            .min_by_key(|binding| binding.scope.rank())
        {
            return Dispatch::Act(binding.action);
        }
        if !context.is_tab() {
            return Dispatch::Unbound;
        }
        self.bindings
            .iter()
            .filter(matching)
            .find(|binding| match binding.scope {
                Scope::In(other) => other.is_tab(),
                Scope::Lists => true,
                Scope::Any | Scope::Tabs => false,
            })
            .map_or(Dispatch::Unbound, |binding| {
                Dispatch::Elsewhere(binding.scope, binding.label)
            })
    }

    /// The bindings that act in `context`, narrowest scope first, grouped
    /// by scope and label in table order: each entry is the scope, the label
    /// and the keys.
    pub fn entries(&self, context: Context, keep: impl Fn(&Binding) -> bool) -> Vec<Entry> {
        let mut entries: Vec<Entry> = Vec::new();
        let mut scoped: Vec<&Binding> = self
            .bindings
            .iter()
            .filter(|binding| binding.scope.holds(context) && keep(binding))
            .collect();
        scoped.sort_by_key(|binding| binding.scope.rank());
        for binding in scoped {
            let label = key_label(binding.key, context.prefix());
            match entries
                .iter_mut()
                .find(|entry| entry.scope == binding.scope && entry.label == binding.label)
            {
                Some(entry) => entry.keys.push(label),
                None => entries.push(Entry {
                    scope: binding.scope,
                    label: binding.label,
                    action: binding.action,
                    keys: vec![label],
                }),
            }
        }
        entries
    }

    /// One row of hints for `context`: the hinted bindings whose action
    /// `acts` accepts, grouped by label, cut with `…` to `width` columns.
    /// Help and quit lead, so a narrow bar still says where the rest are.
    pub fn hint_line(
        &self,
        context: Context,
        width: u16,
        acts: impl Fn(Action) -> bool,
        key: Style,
        text: Style,
    ) -> Line<'static> {
        let mut spans = Vec::new();
        let mut used = 0usize;
        let width = usize::from(width);
        let mut entries = self.entries(context, |binding| {
            binding.in_hint_bar && acts(binding.action)
        });
        entries.sort_by_key(|entry| !matches!(entry.action, Action::Help | Action::Quit));
        for entry in entries {
            let keys = entry.keys();
            let separator = if spans.is_empty() { 0 } else { 3 };
            let need = separator + crate::tui::text::width(&keys) + 1 + entry.label.len();
            if used + need > width.saturating_sub(2) {
                spans.push(Span::styled(" …", text));
                break;
            }
            if separator > 0 {
                spans.push(Span::styled(" · ", text));
            }
            spans.push(Span::styled(keys, key));
            spans.push(Span::styled(format!(" {}", entry.label), text));
            used += need;
        }
        Line::from(spans)
    }
}

/// The keys of one label in one scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub scope: Scope,
    pub label: &'static str,
    /// The action of the entry's first binding.
    pub action: Action,
    pub keys: Vec<String>,
}

impl Entry {
    /// The keys joined by `/`; a run of the digit keys reads `1-5`.
    pub fn keys(&self) -> String {
        let digits: Vec<&str> = self
            .keys
            .iter()
            .map(String::as_str)
            .filter(|key| key.len() == 1 && key.as_bytes()[0].is_ascii_digit())
            .collect();
        if digits.len() > 2 && digits.len() == self.keys.len() {
            return format!("{}-{}", digits[0], digits[digits.len() - 1]);
        }
        self.keys.join("/")
    }
}

/// Shift is part of an uppercase letter, a symbol or BackTab, so it is
/// dropped there: `Q` and `q` stay distinct, and a terminal that reports
/// `?` with Shift matches the `?` binding.
fn normalize(key: KeyEvent) -> KeyEvent {
    let mut modifiers = key.modifiers;
    if matches!(key.code, KeyCode::Char(_) | KeyCode::BackTab) {
        modifiers.remove(KeyModifiers::SHIFT);
    }
    KeyEvent::new(key.code, modifiers)
}

/// How a key is written in hints and help; a character key follows the
/// `prefix` key that opened its context.
pub fn key_label(key: KeyEvent, prefix: &str) -> String {
    let base = match key.code {
        KeyCode::Char(' ') => "space".into(),
        KeyCode::Char(c) => c.to_string(),
        KeyCode::Esc => "esc".into(),
        KeyCode::Enter => "enter".into(),
        KeyCode::Backspace => "backspace".into(),
        KeyCode::Tab => "tab".into(),
        KeyCode::BackTab => "shift-tab".into(),
        KeyCode::Up => "↑".into(),
        KeyCode::Down => "↓".into(),
        KeyCode::Left => "←".into(),
        KeyCode::Right => "→".into(),
        KeyCode::PageUp => "pgup".into(),
        KeyCode::PageDown => "pgdn".into(),
        KeyCode::Home => "home".into(),
        KeyCode::End => "end".into(),
        other => format!("{other:?}").to_lowercase(),
    };
    let prefix = if matches!(key.code, KeyCode::Char(_)) {
        prefix
    } else {
        ""
    };
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        format!("{prefix}^{base}")
    } else {
        format!("{prefix}{base}")
    }
}

#[cfg(test)]
#[path = "keymap_tests.rs"]
mod tests;
