//! Binding-table tests: release and shifted events, the tab a key reports
//! acting on, and agreement between the hint bar and dispatch.

use super::*;
use ratatui::crossterm::event::KeyEventState;

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

#[test]
fn release_events_do_not_dispatch() {
    let keymap = Keymap::default_map();
    let mut key = press(KeyCode::Char('q'));
    key.kind = KeyEventKind::Release;
    assert_eq!(keymap.dispatch(Context::Jobs, key), Dispatch::Unbound);
}

/// The open search binds only its own keys and ctrl-c, so letters type
/// and `q` does not quit.
#[test]
fn a_search_takes_letters_and_ctrl_c_still_quits() {
    let keymap = Keymap::default_map();
    let q = press(KeyCode::Char('q'));
    assert_eq!(keymap.dispatch(Context::Search, q), Dispatch::Unbound);
    assert_eq!(
        keymap.dispatch(Context::Jobs, q),
        Dispatch::Act(Action::Quit)
    );
    let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
    for context in [Context::Search, Context::Help, Context::PendingG] {
        assert_eq!(
            keymap.dispatch(context, ctrl_c),
            Dispatch::Act(Action::Quit)
        );
    }
}

#[test]
fn a_key_of_another_tab_names_where_it_acts() {
    let keymap = Keymap::default_map();
    assert_eq!(
        keymap.dispatch(Context::Signals, press(KeyCode::Char('f'))),
        Dispatch::Elsewhere(Scope::In(Context::Jobs), "filter")
    );
    assert_eq!(
        keymap.dispatch(Context::Jobs, press(KeyCode::Char('n'))),
        Dispatch::Elsewhere(Scope::In(Context::Signals), "next, previous match")
    );
    assert_eq!(
        keymap.dispatch(Context::Overview, press(KeyCode::Char('j'))),
        Dispatch::Elsewhere(Scope::Lists, "move")
    );
}

#[test]
fn shift_is_dropped_from_letters_symbols_and_backtab() {
    let keymap = Keymap::default_map();
    let shifted = KeyEvent {
        code: KeyCode::Char('G'),
        modifiers: KeyModifiers::SHIFT,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    };
    assert_eq!(
        keymap.dispatch(Context::Jobs, shifted),
        Dispatch::Act(Action::Bottom)
    );
    let backtab = KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT);
    assert_eq!(
        keymap.dispatch(Context::Jobs, backtab),
        Dispatch::Act(Action::PrevTab)
    );
    let question = KeyEvent::new(KeyCode::Char('?'), KeyModifiers::SHIFT);
    assert_eq!(
        keymap.dispatch(Context::Overview, question),
        Dispatch::Act(Action::Help)
    );
}

#[test]
fn the_hint_bar_groups_keys_by_label_and_fits_its_width() {
    let keymap = Keymap::default_map();
    let line = keymap.hint_line(Context::Overview, 200, |_| true, Style::new(), Style::new());
    let text = line.to_string();
    assert!(text.starts_with("? help · q quit · 1-5 tab"), "{text}");
    let line = keymap.hint_line(Context::Jobs, 30, |_| true, Style::new(), Style::new());
    assert!(line.width() <= 30, "{line:?}");
    assert_eq!(
        line.spans.last().map(|span| span.content.as_ref()),
        Some(" …")
    );
    let pending = keymap.hint_line(Context::PendingG, 200, |_| true, Style::new(), Style::new());
    assert!(pending.to_string().contains("gt next tab"), "{pending}");
}

const CONTEXTS: [Context; 9] = [
    Context::Overview,
    Context::Signals,
    Context::Profiles,
    Context::Jobs,
    Context::Findings,
    Context::Search,
    Context::Help,
    Context::PendingG,
    Context::PendingZ,
];

/// Every hinted key dispatches to its own action in every context its scope
/// holds, unless a narrower binding of the same key shadows it there, so
/// the hint bar never shows a key that does something else.
#[test]
fn every_hinted_key_dispatches_its_action_where_it_is_hinted() {
    let keymap = Keymap::default_map();
    for binding in keymap
        .bindings()
        .iter()
        .filter(|binding| binding.in_hint_bar)
    {
        for context in CONTEXTS
            .into_iter()
            .filter(|context| binding.scope.holds(*context))
        {
            let shadowed = keymap.bindings().iter().any(|other| {
                other.scope.holds(context)
                    && other.scope.rank() < binding.scope.rank()
                    && normalize(other.key) == normalize(binding.key)
            });
            if shadowed {
                continue;
            }
            assert_eq!(
                keymap.dispatch(context, binding.key),
                Dispatch::Act(binding.action),
                "{} in {context:?}",
                key_label(binding.key, "")
            );
        }
    }
}

/// One key acts once per context: two bindings of the same key in the same
/// scope would make dispatch depend on table order.
#[test]
fn no_key_is_bound_twice_in_one_scope() {
    let keymap = Keymap::default_map();
    for (index, binding) in keymap.bindings().iter().enumerate() {
        for other in &keymap.bindings()[index + 1..] {
            assert!(
                !(other.scope == binding.scope && normalize(other.key) == normalize(binding.key)),
                "{} twice in {:?}",
                key_label(binding.key, ""),
                binding.scope
            );
        }
    }
}
