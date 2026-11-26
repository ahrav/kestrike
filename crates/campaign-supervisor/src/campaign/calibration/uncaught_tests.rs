use super::*;

/// The worker's rule catalog source. Its `scoped` chain adds each
/// `scope("NAME", LIST)` call's texts, from `const LIST: &[&str] = &[...];`,
/// to scope `NAME`, and adds the `MIXED` texts satisfying `!world(text)` to
/// `history`; [`calls`] recognizes the latter chain by matching
/// [`MIXED_CHAIN`].
const CATALOG: &str = include_str!("../../../../kestrike/src/net/world_tests/narrate/rules.rs");

/// The link of the catalog's `scoped` chain that adds the `MIXED` texts
/// satisfying `!world(text)` to `history`, with its whitespace removed.
const MIXED_CHAIN: &str =
    ".chain(MIXED.iter().filter(move|text|!world(text)).map(|text|(\"history\",*text)),)";

/// Removes each `/*` to `*/` span of `source`, then cuts each line at its
/// first `//`, which drops commented-out texts and calls. A `//` or `/*`
/// inside a catalog text would cut that text too.
fn code(source: &str) -> String {
    let mut live = String::new();
    let mut rest = source;
    while let Some((before, after)) = rest.split_once("/*") {
        live.push_str(before);
        rest = after.split_once("*/").map_or("", |(_, rest)| rest);
    }
    live.push_str(rest);
    live.lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Each scope the code of `source` adds texts to, in catalog order, with
/// the body of the list it adds: one entry per `scope("NAME", LIST)` call
/// and one `history` entry for [`MIXED_CHAIN`].
fn calls(source: &str) -> Vec<(String, String)> {
    let code = code(source);
    let compact: String = code.split_whitespace().collect();
    let mut found: Vec<(usize, String, &str)> = compact
        .match_indices("scope(\"")
        .filter_map(|(at, call)| {
            let (name, rest) = compact[at + call.len()..].split_once("\",")?;
            Some((at, name.to_owned(), rest.split_once(')')?.0))
        })
        .chain(
            compact
                .match_indices(MIXED_CHAIN)
                .map(|(at, _)| (at, "history".to_owned(), "MIXED")),
        )
        .collect();
    found.sort_by_key(|&(at, ..)| at);
    found
        .into_iter()
        .filter_map(|(_, name, list)| {
            let body = code
                .split_once(&format!("const {list}: &[&str] = &["))?
                .1
                .split_once("];")?
                .0;
            Some((name, body.to_owned()))
        })
        .collect()
}

/// `absent` returns unmatched rows: a whole-scope row matches a list of its
/// scope holding a text, and a text row matches when the first list holding
/// its quoted text belongs to the row's scope.
fn absent<'r>(rows: &'r [Row], source: &str) -> Vec<&'r Row> {
    let calls = calls(source);
    rows.iter()
        .filter(|(scope, text, _)| match text {
            None => !calls
                .iter()
                .any(|(name, body)| name == scope.name() && body.contains('"')),
            Some(text) => {
                let quoted = format!("\"{text}\"");
                let first = calls.iter().find(|(_, body)| body.contains(&quoted));
                first.is_none_or(|(name, _)| name != scope.name())
            }
        })
        .collect()
}

/// The check reads the catalog's scope calls and its mixed chain in
/// catalog order. It refuses a row whose text the catalog lacks or holds
/// only in a comment, a row of a scope no live call names, and a row that
/// pairs a cataloged text with a scope other than its first.
#[test]
fn each_allowed_row_names_a_cataloged_scope_and_text() {
    let names: Vec<String> = calls(CATALOG).into_iter().map(|call| call.0).collect();
    assert_eq!(
        names,
        [
            "boundary", "world", "cluster", "history", "history", "history", "oracle"
        ]
    );
    assert_eq!(names.len(), CATALOG.matches("scope(\"").count() + 1);
    assert_eq!(absent(ALLOWED, CATALOG), Vec::<&Row>::new());
    assert!(ALLOWED.iter().all(|(_, _, reason)| !reason.is_empty()));
    let mixed: &[Row] = &[(
        Scope::History,
        Some("a closed owner kept sending"),
        CONSERVATION,
    )];
    assert_eq!(absent(mixed, CATALOG), Vec::<&Row>::new());
    let foreign: &[Row] = &[
        (
            Scope::Boundary,
            Some("a slot word is misshapen"),
            CONSERVATION,
        ),
        (Scope::World, Some("a slot word is malformed"), CONSERVATION),
        (
            Scope::Oracle,
            Some("a refused read exposed bytes"),
            CONSERVATION,
        ),
        (Scope::Cluster, None, CONSERVATION),
    ];
    let later = "\"a refused read exposed bytes\"";
    let holding: Vec<String> = calls(CATALOG)
        .into_iter()
        .filter(|(_, body)| body.contains(later))
        .map(|call| call.0)
        .collect();
    assert_eq!(holding, ["world", "oracle"]);
    let swarm = CATALOG.replace("scope(\"cluster\", ", "scope(\"swarm\", ");
    assert_eq!(absent(foreign, &swarm).len(), 4);
    let entry = "    \"a slot word is malformed\",";
    let commented = CATALOG.replacen(entry, &format!("    //{}", entry.trim_start()), 1);
    assert_ne!(commented, CATALOG);
    assert_eq!(absent(&ALLOWED[..1], &commented).len(), 1);
    let blocked = CATALOG.replacen(entry, &format!("    /* {} */", entry.trim_start()), 1);
    assert_ne!(blocked, CATALOG);
    assert_eq!(absent(&ALLOWED[..1], &blocked).len(), 1);
    let call = ".chain(scope(\"oracle\", ORACLE))";
    let unchained = CATALOG.replace(call, &format!("// {call}"));
    assert_ne!(unchained, CATALOG);
    let oracle: Vec<&Row> = ALLOWED.iter().filter(|row| row.1.is_none()).collect();
    assert_eq!(absent(ALLOWED, &unchained), oracle);
    assert_eq!(absent(&ALLOWED[..1], "").len(), 1);
}

/// Each row of [`ALLOWED`] removes texts from `unlisted_uncaught`, so the
/// test pins every `(scope, text)` pair in order.
#[test]
fn the_list_pins_each_allowed_scope_and_text_in_order() {
    let rows: Vec<(&str, Option<&str>)> = ALLOWED
        .iter()
        .map(|&(scope, text, _)| (scope.name(), text))
        .collect();
    assert_eq!(
        rows,
        [
            ("boundary", Some("a slot word is malformed")),
            (
                "boundary",
                Some("a held extent overlaps another or lies outside the volume")
            ),
            (
                "boundary",
                Some("a ledger term differs from the slot words or the free units")
            ),
            ("boundary", Some("a resident slot has no binding")),
            (
                "history",
                Some("an owner turn sampled a tick other than its projection")
            ),
            (
                "history",
                Some("the held sample began at or past the deadline")
            ),
            ("oracle", None),
        ]
    );
}

/// `unlisted` assigns each text to its first catalog scope, keeps catalog
/// order within a scope, and omits caught texts and texts a text row or a
/// whole-scope row of `ALLOWED` covers, a later copy of an allowed text
/// included. A text row covers its text in the row's scope alone, and
/// covers that exact text: a text that extends the row's text and a text
/// the row's text extends both stand in the result, each in full.
#[test]
fn unlisted_holds_each_first_scope_text_no_catch_or_row_accounts_for() {
    let catalog: Vec<(String, String)> = [
        ("boundary", "a slot word is malformed"),
        ("boundary", "a slot word is malformed in its reserved bits"),
        ("boundary", "two bindings name one slot"),
        ("boundary", "a bound slot's extent lies outside the device"),
        ("boundary", "an unexpected binding"),
        ("boundary", "a slot word"),
        ("world", "a read check"),
        ("world", "a resident slot has no binding"),
        ("history", "a step check"),
        ("history", "a read check"),
        ("history", "a slot word is malformed"),
        (
            "history",
            "an owner turn sampled a tick other than its projection",
        ),
        ("history", "the held sample began at or past the deadline"),
        ("oracle", "a step check"),
        ("oracle", "a custody check"),
        ("boundary", "a resident slot has no binding"),
    ]
    .map(|(scope, text)| (scope.to_owned(), text.to_owned()))
    .to_vec();
    let caught = BTreeSet::from(["a bound slot's extent lies outside the device"]);
    assert_eq!(
        unlisted(&catalog, |text| caught.contains(text)),
        BTreeMap::from([
            (
                "boundary",
                vec![
                    "a slot word is malformed in its reserved bits",
                    "two bindings name one slot",
                    "an unexpected binding",
                    "a slot word",
                ]
            ),
            ("history", vec!["a step check"]),
            (
                "world",
                vec!["a read check", "a resident slot has no binding"]
            ),
        ])
    );
    let every = BTreeSet::from([
        "a bound slot's extent lies outside the device",
        "a slot word is malformed in its reserved bits",
        "a slot word",
        "two bindings name one slot",
        "an unexpected binding",
        "a read check",
        "a resident slot has no binding",
        "a step check",
    ]);
    assert!(unlisted(&catalog, |text| every.contains(text)).is_empty());
}
