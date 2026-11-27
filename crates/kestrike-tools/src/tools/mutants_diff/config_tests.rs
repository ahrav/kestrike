use super::config::{debug_assertions, pins, stables};

#[test]
fn a_pin_line_ends_at_a_line_feed_and_holds_no_whitespace() {
    let text = "# Tool pin: cargo-mutants 1.0\r\n# Tool pin: cargo-mutants 2.0\n# Tool pin: cargo-mutants a b\n\
                # Tool pin: cargo-mutants \n # Tool pin: cargo-mutants 3";
    assert_eq!(pins(text), ["2.0"], "PIN.findall(text) gives ['2.0']");
}

#[test]
fn a_stable_pin_follows_whitespace_from_a_line_start_and_its_value_may_span_lines() {
    let text = "  \n  STABLE: \"a\nb\"\nx STABLE: \"c\"\n\tSTABLE: \"\"\nSTABLE: \"d\" STABLE: \"e\"\n\u{2028}STABLE: \"f\"";
    assert_eq!(
        stables(text),
        ["a\nb", "d", "f"],
        "STABLE.findall(text) gives ['a\\nb', 'd', 'f']"
    );
}

#[test]
fn a_debug_assertion_value_is_ascii_word_characters_and_commas_are_optional() {
    let unicode = "additional_cargo_args = [\"profile.dev.debug-assertions=tr\u{fc}e\"]";
    let refused = "additional_cargo_args entry 'profile.dev.debug-assertions=tr\u{fc}e' sets debug assertions in a \
                   form the runner does not read";
    assert_eq!(
        debug_assertions(unicode),
        Err(refused.to_owned()),
        "Python reads 'tr\u{fc}e'; the value takes ASCII word characters"
    );
    let loose = "additional_cargo_args = [\"a\" \"profile.dev.debug-assertions=on\",,]";
    assert_eq!(
        debug_assertions(loose),
        Ok(Some("on".to_owned())),
        "debug_assertions(loose) gives 'on'"
    );
}
