use super::config::{debug_assertions, pins, stables};

#[test]
fn a_pin_line_ends_at_a_line_feed_and_holds_no_whitespace() {
    let text = "# Tool pin: cargo-mutants 1.0\r\n# Tool pin: cargo-mutants 2.0\n# Tool pin: cargo-mutants a b\n\
                # Tool pin: cargo-mutants \n # Tool pin: cargo-mutants 3";
    assert_eq!(pins(text), ["2.0"], "PIN.findall(text) gives ['2.0']");
}

/// A pin is one line: spaces or tabs alone before the key, a value that ends at the first quote of its
/// line, and any text after that quote.
#[test]
fn a_stable_pin_is_read_on_one_line_after_spaces_or_tabs() {
    let text = "  \n  STABLE: \"a\nb\"\nx STABLE: \"c\"\n\tSTABLE: \"\"\nSTABLE: \"d\" STABLE: \"e\"\n\u{2028}STABLE: \"f\"\n\
                \t STABLE: \"g\"\n\u{b}STABLE: \"h\"\nSTABLE: \"i\"  # the pin\n";
    assert_eq!(
        stables(text),
        ["d", "g", "i"],
        "a value across lines, a key after other text or after whitespace other than spaces and tabs, \
         and an empty value are no pins"
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

#[test]
fn the_pin_files_read_their_line_ends_as_line_feeds() {
    let scratch = crate::paths::tests::Scratch::new("pins");
    let directory = &scratch.0;
    let (config, workflow) = (
        directory.join("mutants.toml"),
        directory.join("agent-checks.yml"),
    );
    std::fs::write(&config, "# Tool pin: cargo-mutants 27.1.0\r\n").expect("written");
    std::fs::write(&workflow, "a\r  STABLE: \"1.99.0\"\n").expect("written");
    let config = super::preflight::read_pins(&config).expect("the file reads");
    let workflow = super::preflight::read_pins(&workflow).expect("the file reads");
    assert_eq!(
        pins(&config),
        ["27.1.0"],
        "PIN.findall(Path(config).read_text()) gives ['27.1.0']"
    );
    assert_eq!(
        stables(&workflow),
        ["1.99.0"],
        "STABLE.findall(Path(workflow).read_text()) gives ['1.99.0']"
    );
}
