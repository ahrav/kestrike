//! Rule catalog tests: the parser reads each scope and text, and refuses a
//! missing, repeated, malformed or torn line for that line's own reason.

use super::{Error, Rule, Rules, Scope};

const CATALOG: &str = "rules: 1\n\
    rule: boundary an unexpected binding\n\
    rule: world a refused read exposed bytes\n\
    rule: cluster a GET returned bytes no upload of its key wrote\n\
    rule: history the replacement never published\n\
    rule: oracle a refused read exposed bytes\n";

/// A catalog parses into its rules in output order, a text keeps its
/// spaces, and one text under two scopes is two rules.
#[test]
fn the_catalog_parses_each_rule_with_its_scope() {
    let catalog = Rules::parse(CATALOG).expect("the fixture parses");
    let scopes: Vec<Scope> = catalog.rules.iter().map(|rule| rule.scope).collect();
    assert_eq!(scopes, Scope::ALL);
    assert_eq!(
        catalog.rules[0],
        Rule {
            scope: Scope::Boundary,
            text: "an unexpected binding".into()
        }
    );
    assert_eq!(catalog.rules[1].text, catalog.rules[4].text);
}

/// The parser refuses a catalog without its version or with another
/// version, without a rule, with a rule line twice, with a scope outside
/// the words, with a rule of no text, with a foreign line, and cut short.
#[test]
fn a_changed_catalog_is_refused_for_its_own_reason() {
    let edited = |from: &str, to: &str| CATALOG.replacen(from, to, 1);
    let refused = |text: &str| Rules::parse(text).expect_err("the catalog is refused");
    assert_eq!(refused(&edited("rules: 1\n", "")), Error::Missing("rules"));
    assert_eq!(
        refused(&edited("rules: 1\n", "rules: 2\n")),
        Error::Value("rules")
    );
    assert_eq!(
        refused(&edited("rules: 1\n", "rules: 1\nrules: 1\n")),
        Error::Repeated("rules".into())
    );
    assert_eq!(refused("rules: 1\n"), Error::Missing("rule"));
    let twice = format!("{CATALOG}rule: world a refused read exposed bytes\n");
    assert_eq!(
        refused(&twice),
        Error::Repeated("rule world a refused read exposed bytes".into())
    );
    for (from, to) in [
        ("rule: boundary ", "rule: observer "),
        ("rule: boundary an unexpected binding", "rule: boundary "),
        ("rule: boundary an unexpected binding", "rule: boundary"),
    ] {
        assert_eq!(refused(&edited(from, to)), Error::Value("rule"), "{to}");
    }
    assert_eq!(
        refused(&format!("{CATALOG}foreign: line\n")),
        Error::Unknown("foreign".into())
    );
    assert_eq!(refused(&CATALOG[..CATALOG.len() - 1]), Error::Torn);
    assert_eq!(refused(""), Error::Torn);
}
