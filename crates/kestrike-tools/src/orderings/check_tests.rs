use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;

use super::{CATALOG, UNMODELED, check};
use crate::json::{self, Object, Text, Value};
use crate::orderings::sites::{EXTERNAL, Pin};
use crate::orderings::sources::tests::{
    Plant, committed, package_of, planted as source, planted_package, reader, root_of, text, top,
};

const FILL: &str = "crates/kestrike/src/storage/fill.rs";
const GRACE: &str = "crates/kestrike/src/storage/grace.rs";
const CREDIT: &str = "crates/kestrike/src/storage/credit.rs";
const STORAGE: &str = "crates/kestrike/src/storage/mod.rs";
const STEPS: &str = "crates/kestrike/src/storage/credit_steps.rs";
const SLOT: &str = "crates/kestrike/src/storage/slot.rs";
const TREE: &str = "crates/kestrike/src/mod.rs";
const LIB: &str = "crates/kestrike/src/lib.rs";
const REVISION: &str = "0000000000000000000000000000000000000000";
const ANCHOR: &str = "pub(crate) fn observe<W: FillWord>";
const UNPIN: &str = "pub(crate) fn unpin<W: EraWord>(record: &W) {";
const ACQUIRE_UNROWED: &str = "Ordering::Acquire lies in no row's find";
const MACRO_TOKENS: &str =
    "a module declaration inside a macro's tokens, which the scope rule cannot read";

const DEPARTED: &str = r#"{"lane": "loom", "tests": ["storage::fill_model::two_owners_on_one_key_and_a_servicer", "storage::fill_model::three_participants_over_two_keys_reach_the_serial_maximum"], "failure": "a departed record whose owner had not ended"}"#;
const FOLLOWER: &str = r#"{"lane": "genmc", "tests": ["join-production"], "failure": "a follower saw the departure without its terminal"}"#;
const FREED: &str = r#"{"lane": "genmc", "tests": ["join-production"], "failure": "a follower's record was freed or reissued under it"}"#;

type Plants<'p> = Vec<(&'p str, Plant)>;

fn value(text: &str) -> Value {
    json::parse(text).unwrap_or_else(|error| panic!("{text}: {error}"))
}

fn checked_at(root: &Path, plants: Plants<'_>, pins: &[Pin]) -> (Value, u8) {
    check(&reader(plants), root, &top(), pins)
}

fn checked(plants: Plants<'_>) -> (Value, u8) {
    checked_at(&top(), plants, EXTERNAL)
}

fn member<'r>(report: &'r Value, key: &str) -> &'r Value {
    match report {
        Value::Object(object) => object
            .get(key)
            .unwrap_or_else(|| panic!("the report has {key}: {report:?}")),
        _ => panic!("the report is an object: {report:?}"),
    }
}

fn catalog() -> Value {
    value(&committed(CATALOG))
}

fn catalog_with(change: impl FnOnce(&mut Value)) -> String {
    let mut planted = catalog();
    change(&mut planted);
    json::dump(&planted)
}

fn object(value: &mut Value) -> &mut Object {
    match value {
        Value::Object(object) => object,
        _ => panic!("an object: {value:?}"),
    }
}

fn rows(catalog: &mut Value) -> &mut Vec<Value> {
    match object(catalog).get_mut("rows") {
        Some(Value::Array(rows)) => rows,
        _ => panic!("the catalog holds rows"),
    }
}

fn row<'c>(catalog: &'c mut Value, id: &str) -> &'c mut Object {
    rows(catalog)
        .iter_mut()
        .map(object)
        .find(|row| row.get("id") == Some(&Value::String(Text::from(id))))
        .unwrap_or_else(|| panic!("the catalog holds row {id}"))
}

fn string(text: &str) -> Value {
    Value::String(Text::from(text))
}

/// Sets row `id`'s disposition, whichever it holds, to `kind` with `disposition` and a revision.
fn decided(catalog: &mut Value, id: &str, kind: &str, disposition: Value) {
    let planted = row(catalog, id);
    for key in ["kill", "survives", "unrun"] {
        planted.remove(key);
    }
    planted.insert("revision", string(REVISION));
    planted.insert(kind, disposition);
}

fn get<'v>(value: &'v Value, key: &str) -> &'v Value {
    match value {
        Value::Object(object) => object
            .get(key)
            .unwrap_or_else(|| panic!("{key} in {value:?}")),
        _ => panic!("an object: {value:?}"),
    }
}

fn items(value: &Value) -> &[Value] {
    match value {
        Value::Array(items) => items,
        _ => panic!("an array: {value:?}"),
    }
}

/// Sets every row to `survives`, with the tests of its needs as passed: none for a row of
/// `UNMODELED`.
fn survived(catalog: &mut Value) {
    let entries: Vec<(Text, Vec<Value>)> = rows(catalog)
        .iter()
        .map(|entry| {
            let Value::String(id) = get(entry, "id") else {
                panic!("a row's id is a string");
            };
            let passed = items(get(get(entry, "unrun"), "needs"))
                .iter()
                .map(|need| {
                    let mut pass = Object::new();
                    pass.insert("lane", get(need, "lane").clone());
                    pass.insert("tests", get(need, "tests").clone());
                    Value::Object(pass)
                })
                .collect();
            (id.clone(), passed)
        })
        .collect();
    for (id, passed) in entries {
        let mut survives = Object::new();
        survives.insert("reason", string("planted"));
        survives.insert("passed", Value::Array(passed));
        decided(
            catalog,
            &id.to_string(),
            "survives",
            Value::Object(survives),
        );
    }
}

/// An unrun row for the fill file beside the committed rows, with `fields` over its defaults.
fn planted_row(fields: &[(&str, Value)]) -> Value {
    let mut planted = Object::new();
    planted.insert("id", string("planted"));
    planted.insert("path", string(FILL));
    planted.insert("op", string("fence"));
    planted.insert("scope", value(r#"["fn extra"]"#));
    planted.insert("unrun", value(&format!(r#"{{"needs": [{DEPARTED}]}}"#)));
    for (key, field) in fields {
        planted.insert(*key, field.clone());
    }
    Value::Object(planted)
}

fn refusals_of<'r>(report: &'r Value, name: &str) -> Vec<&'r Value> {
    items(member(report, "refusals"))
        .iter()
        .filter(|entry| *get(entry, "refusal") == string(name))
        .map(|entry| get(entry, "message"))
        .collect()
}

fn messages_of(report: &Value, name: &str) -> Vec<String> {
    refusals_of(report, name)
        .into_iter()
        .map(|message| match message {
            Value::String(message) => message.to_string(),
            _ => panic!("a message is a string: {message:?}"),
        })
        .collect()
}

/// Asserts that the check over `plants` exits 1, credits nothing and refuses `name` with a sentence
/// that holds `holds`.
fn refused_at(root: &Path, plants: Plants<'_>, name: &str, holds: &str) {
    let (report, code) = checked_at(root, plants, EXTERNAL);
    assert_eq!(code, 1, "{report:?}");
    assert_eq!(*member(&report, "credited"), Value::Bool(false));
    let messages = messages_of(&report, name);
    assert!(
        messages.iter().any(|message| message.contains(holds)),
        "{name}: {holds:?} in {:?}",
        member(&report, "refusals")
    );
}

fn refused(plants: Plants<'_>, name: &str, holds: &str) {
    refused_at(&top(), plants, name, holds);
}

fn with_catalog(change: impl FnOnce(&mut Value)) -> Plants<'static> {
    vec![(CATALOG, text(catalog_with(change)))]
}

fn with_source<'p>(path: &'p str, old: &str, new: &str) -> Plants<'p> {
    vec![(path, text(source(path, old, new)))]
}

/// Asserts that the check over `plants` exits 0 and refuses nothing.
fn accepted(plants: Plants<'_>) -> Value {
    let (report, code) = checked(plants);
    assert_eq!(
        (code, member(&report, "refusals")),
        (0, &Value::Array(Vec::new())),
        "{report:?}"
    );
    report
}

fn names(list: &[&str]) -> Value {
    Value::Array(list.iter().map(|name| string(name)).collect())
}

fn ids_of(report: &Value) -> Vec<Text> {
    match member(report, "rows") {
        Value::Object(rows) => rows.iter().map(|(id, _)| id.clone()).collect(),
        rows => panic!("rows is an object: {rows:?}"),
    }
}

fn disposition(report: &Value, id: &str) -> Value {
    get(member(report, "rows"), id).clone()
}

#[test]
fn the_committed_catalog_holds_29_unrun_rows_and_credits_nothing() {
    let report = accepted(vec![]);
    let ids = ids_of(&report);
    assert_eq!(ids.len(), 29);
    for id in &ids {
        assert_eq!(
            disposition(&report, &id.to_string()),
            string("unrun"),
            "{id}"
        );
    }
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(
        *member(&report, "unrun"),
        Value::Array(sorted.into_iter().map(Value::String).collect())
    );
    assert_eq!(*member(&report, "sites"), value("29"));
    assert_eq!(*member(&report, "credited"), Value::Bool(false));
    assert_eq!(*member(&report, "excluded"), names(&[STEPS]));
    let mut planted = catalog();
    let twin_steps = |catalog: &mut Value, id: &str| -> Vec<Value> {
        items(row(catalog, id).get("twin").expect("the row holds twins"))
            .iter()
            .map(|twin| get(twin, "steps").clone())
            .collect()
    };
    assert_eq!(
        twin_steps(&mut planted, "grace-bump"),
        [value("3"), value("3")]
    );
    assert_eq!(
        twin_steps(&mut planted, "grace-start"),
        [value("2"), value("2")]
    );
    let unmodeled: Vec<String> = items(get(&planted, "rows"))
        .iter()
        .filter(|entry| items(get(get(entry, "unrun"), "needs")).is_empty())
        .map(|entry| match get(entry, "id") {
            Value::String(id) => id.to_string(),
            id => panic!("an id is a string: {id:?}"),
        })
        .collect();
    let mut expected: Vec<String> = UNMODELED.iter().map(|id| (*id).to_owned()).collect();
    expected.sort();
    let mut unmodeled_sorted = unmodeled.clone();
    unmodeled_sorted.sort();
    assert_eq!(unmodeled_sorted, expected);
    assert_eq!(UNMODELED.len(), 4);
    for id in UNMODELED {
        let reason = row(&mut planted, id)
            .get("unrun")
            .map(|unrun| get(unrun, "reason").clone());
        assert!(
            matches!(&reason, Some(Value::String(reason)) if !reason.strip().is_empty()),
            "{id}: {reason:?}"
        );
    }
}

#[test]
fn a_kill_and_a_survivor_with_passed_tests_are_accepted() {
    let plants = with_catalog(|catalog| {
        survived(catalog);
        decided(
            catalog,
            "fill-observe",
            "kill",
            value(&format!("[{DEPARTED}, {FOLLOWER}]")),
        );
        decided(
            catalog,
            "row-observers",
            "kill",
            value(&format!("[{FREED}]")),
        );
        let departed = value(DEPARTED);
        decided(
            catalog,
            "fill-depart-release",
            "survives",
            value(&format!(
                r#"{{"reason": "planted", "passed": [{{"lane": "loom", "tests": {}}}, {{"lane": "genmc", "tests": ["join-production"]}}]}}"#,
                json::dump(get(&departed, "tests"))
            )),
        );
    });
    let report = accepted(plants);
    assert_eq!(*member(&report, "unrun"), Value::Array(Vec::new()));
    assert_eq!(*member(&report, "credited"), Value::Bool(true));
    let held: Vec<Value> = ["fill-observe", "row-observers", "fill-depart-release"]
        .iter()
        .map(|id| disposition(&report, id))
        .collect();
    assert_eq!(held, [string("kill"), string("kill"), string("survives")]);
}

#[test]
fn a_new_acquire_load_without_a_row_is_refused_by_file_and_token() {
    let peek = format!(
        "pub(crate) fn peek(state: &AtomicU64) -> u64 {{\n    state.load(Ordering::Acquire)\n}}\n\n{ANCHOR}"
    );
    refused(
        with_source(FILL, ANCHOR, &peek),
        "unrowed site",
        &format!("{FILL}:"),
    );
    refused(
        with_source(FILL, ANCHOR, &peek),
        "unrowed site",
        ACQUIRE_UNROWED,
    );
    let trailing = "pub(crate) fn peek(state: &AtomicU64, #[cfg(test)] probe: u8) -> u64 {\n    state.load(Ordering::Acquire)\n}\n\n";
    refused(
        with_source(FILL, ANCHOR, &format!("{trailing}{ANCHOR}")),
        "unrowed site",
        ACQUIRE_UNROWED,
    );
    let generic = "pub(crate) fn peek<A, #[cfg(test)] B>(state: &AtomicU64) -> u64 {\n    state.load(Ordering::Acquire)\n}\n\n";
    refused(
        with_source(FILL, ANCHOR, &format!("{generic}{ANCHOR}")),
        "unrowed site",
        ACQUIRE_UNROWED,
    );
}

#[test]
fn a_new_fence_without_a_row_is_refused() {
    for call in [
        "std::sync::atomic::fence(Ordering::SeqCst);",
        "std::sync::atomic::compiler_fence(Ordering::Release);",
        "::std::sync::atomic::fence(Ordering::SeqCst);",
        "<W as FillWord>::acquire_fence();",
        "<W as Into<u8>>::acquire_fence();",
        "W::fence_clear();",
    ] {
        let extra = format!("fn extra<W: FillWord>() {{\n    {call}\n}}\n\n{ANCHOR}");
        refused(
            with_source(FILL, ANCHOR, &extra),
            "unrowed site",
            &format!("{call} lies in no row's find"),
        );
    }
}

#[test]
fn a_rooted_fence_row_deletes_the_whole_path() {
    let call = "::std::sync::atomic::fence(Ordering::SeqCst);";
    let planted_text = source(
        FILL,
        ANCHOR,
        &format!("fn extra() {{\n    {call}\n}}\n\n{ANCHOR}"),
    );
    let planted = |replace: &str| -> Plants<'static> {
        let fields = [("find", string(call)), ("replace", string(replace))];
        vec![
            (FILL, text(planted_text.clone())),
            (
                CATALOG,
                text(catalog_with(|catalog| {
                    rows(catalog).push(planted_row(&fields))
                })),
            ),
        ]
    };
    accepted(planted(""));
    refused(
        planted("::"),
        "step",
        "planted: its replace is not its find after one fence step",
    );
}

#[test]
fn an_ordering_inside_a_comment_or_a_test_item_is_no_site() {
    let peek = format!(
        "// state.load(Ordering::Acquire)\n#[cfg(test)]\nfn peek(state: &AtomicU64) -> u64 {{\n    state.load(Ordering::Acquire)\n}}\n\n{ANCHOR}"
    );
    let (report, _) = checked(with_source(FILL, ANCHOR, &peek));
    assert_eq!(*member(&report, "refusals"), Value::Array(Vec::new()));
}

#[test]
fn a_site_after_a_test_only_element_is_a_site() {
    let load = "state.load(Ordering::Acquire)";
    let plants = [
        (
            "a generic parameter after a braced const argument",
            format!(
                "pub(crate) trait Planted<T: Bound<{{ true }}>, #[cfg(test)] U> {{\n    fn peek(state: &AtomicU64) -> u64 {{\n        {load}\n    }}\n}}\n"
            ),
        ),
        (
            "an arm after an arm that holds `||`",
            format!(
                "fn ready(state: &AtomicU64, a: bool, b: bool, n: u64) -> bool {{\n    match n {{\n        0 => a || b,\n        #[cfg(test)]\n        1 => n < 2,\n        _ => {load} == n,\n    }}\n}}\n"
            ),
        ),
        (
            "a field after a field that holds `||`",
            format!(
                "fn probe(state: &AtomicU64) -> S {{\n    S {{ a: x || y, #[cfg(test)] probe: n < 2, live: {load} }}\n}}\n"
            ),
        ),
    ];
    for (label, planted) in plants {
        let (report, code) = checked(with_source(FILL, ANCHOR, &format!("{planted}\n{ANCHOR}")));
        assert_eq!(code, 1, "{label}: {report:?}");
        assert!(
            messages_of(&report, "unrowed site")
                .iter()
                .any(|message| message.contains(ACQUIRE_UNROWED)),
            "{label}: {report:?}"
        );
    }
}

#[test]
fn an_ordering_nested_in_a_fence_named_call_is_its_own_site() {
    let call = "record_fence_epoch(state.load(Ordering::Acquire));";
    let planted_text = source(
        FILL,
        ANCHOR,
        &format!("fn extra(state: &AtomicU64) {{\n    {call}\n}}\n\n{ANCHOR}"),
    );
    refused(
        vec![(FILL, text(planted_text.clone()))],
        "unrowed site",
        ACQUIRE_UNROWED,
    );
    let fields = [("find", string(call)), ("replace", string(""))];
    let whole = catalog_with(|catalog| rows(catalog).push(planted_row(&fields)));
    refused(
        vec![(FILL, text(planted_text)), (CATALOG, text(whole))],
        "find",
        "planted: its find holds 2 sites",
    );
    let computed = "std::sync::atomic::fence(order_of(state.load(Ordering::Acquire)));";
    let extra = format!("fn extra(state: &AtomicU64) {{\n    {computed}\n}}\n\n{ANCHOR}");
    refused(
        with_source(FILL, ANCHOR, &extra),
        "unrowed site",
        ACQUIRE_UNROWED,
    );
}

#[test]
fn a_hook_with_a_body_is_a_fence_site() {
    let body = "    fn fence_pin() {\n        std::sync::atomic::fence(Ordering::SeqCst);\n    }";
    let fence = "std::sync::atomic::fence(Ordering::SeqCst);";
    let plants = [
        (
            "a default with a body",
            source(GRACE, "    fn fence_pin() {}", body),
            names(&["fn fence_pin"]),
        ),
        (
            "a production override",
            source(
                GRACE,
                "impl Strength for Sequential {",
                &format!("impl Strength for Sequential {{\n{body}"),
            ),
            names(&["impl Strength for Sequential", "fn fence_pin"]),
        ),
    ];
    for (label, planted, scope) in plants {
        let fields = [
            ("path", string(GRACE)),
            ("find", string(fence)),
            ("replace", string("")),
            ("scope", scope),
        ];
        let rowed = catalog_with(|catalog| rows(catalog).push(planted_row(&fields)));
        let (report, code) = checked(vec![(GRACE, text(planted)), (CATALOG, text(rowed))]);
        assert_eq!(code, 1, "{label}: {report:?}");
        assert!(
            messages_of(&report, "unrowed site")
                .iter()
                .any(|message| message.contains("S::fence_pin(); lies in no row's find")),
            "{label}: {report:?}"
        );
    }
    for (label, definition) in [
        ("no definition", ""),
        ("a declaration", "trait Hooks {\n    fn fence_pin();\n}\n"),
    ] {
        let extra =
            format!("{definition}fn extra<S: Strength>() {{\n    S::fence_pin();\n}}\n\n{ANCHOR}");
        let (report, code) = checked(with_source(FILL, ANCHOR, &extra));
        assert_eq!(code, 1, "{label}: {report:?}");
        assert!(
            messages_of(&report, "unrowed site")
                .iter()
                .any(|message| message.contains("S::fence_pin(); lies in no row's find")),
            "{label}: {report:?}"
        );
    }
}

#[test]
fn a_hidden_spelling_of_an_ordering_is_refused() {
    for spelling in [
        "use std::sync::atomic::Ordering::{Acquire};",
        "use std::sync::atomic::Ordering::*;",
        "use std::sync::atomic::Ordering as O;",
        "type O = Ordering;\nfn peek(s: &AtomicU64) -> u64 { s.load(O::Acquire) }",
        "type O<'a> = Ordering;\nfn peek(s: &AtomicU64) -> u64 { s.load(O::SeqCst) }",
        "fn peek(s: &AtomicU64) -> u64 { s.load(<Ordering>::Acquire) }",
        "fn peek(s: &AtomicU64) -> u64 { s.load(<std::sync::atomic::Ordering>::Acquire) }",
        "fn peek(s: &AtomicU64) -> u64 { s.load(Ordering::r#Acquire) }",
        "macro_rules! o { ($t:ident) => { $t::SeqCst }; }",
        "fn peek<W: FillWord>() { let f = W::acquire_fence; f(); }",
        "fn peek<W: FillWord>() { (W::acquire_fence)(); }",
        "fn peek() { std::convert::identity(std::sync::atomic::fence); }",
        "fn peek(order: Ordering) { apply(order, std::sync::atomic::fence); }",
        "fn peek(word: &W) { word.acquire_fence(); }",
        "fn peek() { $crate::x::settle_fence(); }",
        "fn peek<W>() { <W as Foo<Bar<Baz>>>::acquire_fence(); }",
    ] {
        refused(
            with_source(FILL, ANCHOR, &format!("{spelling}\n{ANCHOR}")),
            "spelling",
            "hides",
        );
    }
}

#[test]
fn a_forwarder_that_passes_another_fence_is_refused() {
    let invocation = "forward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);";
    let swapped = "forward_fill_word!(std::sync::atomic::AtomicU64, settle);";
    let decoy = format!("{swapped}\nstringify!(u8, std::sync::atomic::fence);");
    let plants = [
        (
            "another function",
            swapped.to_owned(),
            "forward_fill_word! holds a $fence call, and 0 of its 1 production invocations",
        ),
        (
            "a hand-written impl",
            "impl FillWord for std::sync::atomic::AtomicU64 {\n    fn acquire_fence() {}\n}"
                .to_owned(),
            "forward_fill_word! holds a $fence call, and 0 of its 0 production invocations",
        ),
        (
            "a decoy macro",
            decoy.clone(),
            "stringify! receives std::sync::atomic::fence and holds no $fence call",
        ),
        (
            "a decoy macro beside the swap",
            decoy,
            "forward_fill_word! holds a $fence call, and 0 of its 1 production invocations",
        ),
        (
            "a $fence call outside a macro",
            format!("{invocation}\nfn stray() {{\n    $fence(Ordering::Acquire);\n}}"),
            "a $fence call lies in no macro_rules! body",
        ),
        (
            "a bracket invocation beside the canonical one",
            format!("{invocation}\nforward_fill_word![std::sync::atomic::AtomicU32, settle];"),
            "forward_fill_word! holds a $fence call, and 1 of its 2 production invocations",
        ),
        (
            "a brace invocation beside the canonical one",
            format!("{invocation}\nforward_fill_word! {{std::sync::atomic::AtomicU32, settle}}"),
            "forward_fill_word! holds a $fence call, and 1 of its 2 production invocations",
        ),
        (
            "a spaced-bang invocation beside the canonical one",
            format!("{invocation}\nforward_fill_word ! (std::sync::atomic::AtomicU32, settle);"),
            "forward_fill_word! holds a $fence call, and 1 of its 2 production invocations",
        ),
        (
            "the canonical invocation in an arm of another macro",
            format!(
                "impl FillWord for std::sync::atomic::AtomicU64 {{\n    fn acquire_fence() {{}}\n}}\nmacro_rules! spare {{\n    (unused) => {{\n        {invocation}\n    }};\n    () => {{}};\n}}\nspare!();"
            ),
            "forward_fill_word! is invoked among another macro's tokens",
        ),
    ];
    for (label, new, message) in plants {
        for holds in [format!("{FILL}: "), message.to_owned()] {
            let (report, code) = checked(with_source(FILL, invocation, &new));
            assert_eq!(code, 1, "{label}: {report:?}");
            assert!(
                messages_of(&report, "spelling")
                    .iter()
                    .any(|found| found.contains(&holds)),
                "{label}: {holds:?} in {report:?}"
            );
        }
    }
    let fill = committed(FILL);
    let start = fill
        .find("macro_rules! forward_fill_word {")
        .expect("the fill file defines its forwarder");
    let end = fill
        .find(invocation)
        .expect("the fill file invokes its forwarder")
        + invocation.len();
    let forwarder = &fill[start..end];
    for name in ["spare", "r#spare"] {
        let arm = format!(
            "impl FillWord for std::sync::atomic::AtomicU64 {{\n    fn acquire_fence() {{}}\n}}\nmacro_rules! {name} {{\n    (unused) => {{\n{forwarder}\n    }};\n    () => {{}};\n}}\nspare!();"
        );
        refused(
            vec![(FILL, text(fill.replace(forwarder, &arm)))],
            "spelling",
            "spare! holds a $fence call, and 0 of its 1 production invocations",
        );
    }
}

/// `text` with each `(old, new)` applied in order, every occurrence replaced.
fn edited(text: &str, edits: &[(String, String)]) -> String {
    edits.iter().fold(text.to_owned(), |text, (old, new)| {
        text.replace(old.as_str(), new)
    })
}

#[test]
fn a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused() {
    let header = "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {";
    let footer = "        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);";
    let invocation = "forward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);";
    let fence = "            #[inline(always)]\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n\n";
    let fill = committed(FILL);
    for anchor in [header, footer, invocation, fence] {
        assert_eq!(fill.matches(anchor).count(), 1, "{anchor}");
    }
    let pair = |old: &str, new: String| (old.to_owned(), new);
    let mut plants: Vec<(&str, Vec<(String, String)>)> = vec![
        (
            "swapped parameters",
            vec![
                pair(
                    header,
                    header
                        .replace("($atomic:ty, $fence:path)", "($fence:path, $_unused:path)")
                        .replace("for $atomic", "for std::sync::atomic::AtomicU64"),
                ),
                pair(
                    invocation,
                    "fn noop<T>(_: T) {}\nforward_fill_word!(noop, std::sync::atomic::fence);"
                        .to_owned(),
                ),
            ],
        ),
        (
            "the fence in a second arm that no invocation matches",
            vec![
                pair(fence, String::new()),
                pair(
                    footer,
                    footer.replace(
                        "    };\n}",
                        "    };\n    (unused, $fence:path) => {\n        fn acquire_fence() {\n            $fence(Ordering::Acquire);\n        }\n    };\n}",
                    ),
                ),
            ],
        ),
        (
            "a catch-all arm before the arm",
            vec![pair(
                header,
                header.replace("    ($atomic", "    ($atomic:ty, $($rest:tt)*) => {};\n    ($atomic"),
            )],
        ),
        (
            "a literal arm before the arm",
            vec![pair(
                header,
                header.replace(
                    "    ($atomic",
                    "    (std::sync::atomic::AtomicU64, $other:path) => {};\n    ($atomic",
                ),
            )],
        ),
        (
            "an arm after the arm",
            vec![pair(footer, footer.replace("    };\n}", "    };\n    () => {};\n}"))],
        ),
        (
            "a third parameter",
            vec![pair(header, header.replace("$fence:path)", "$fence:path, $spare:path)"))],
        ),
    ];
    for (label, bang, name, open, close) in [
        ("a second definition", "!", "forward_fill_word", "{", "}"),
        (
            "a second definition with a spaced bang",
            " !",
            "forward_fill_word",
            "{",
            "}",
        ),
        (
            "a second definition in parentheses",
            "!",
            "forward_fill_word",
            "(",
            ");",
        ),
        (
            "a second definition named by a raw identifier",
            "!",
            "r#forward_fill_word",
            "{",
            "}",
        ),
    ] {
        let spare = format!(
            "macro_rules{bang} {name} {open}\n    ($atomic:ty, $fence:path) => {{\n        impl Spare for $atomic {{}}\n    }};\n{close}\n"
        );
        plants.push((
            label,
            vec![pair(invocation, format!("{spare}{invocation}"))],
        ));
    }
    let start = fill
        .find("macro_rules! forward_fill_word {")
        .expect("the fill file defines its forwarder");
    let definition = &fill[start
        ..fill
            .find(invocation)
            .expect("the fill file invokes its forwarder")];
    plants.push((
        "the definition after its invocation",
        vec![
            pair(definition, String::new()),
            pair(
                invocation,
                format!("{invocation}\n\n{}", definition.trim_end()),
            ),
        ],
    ));
    plants.push((
        "the definition in an inline module",
        vec![pair(
            definition,
            format!("mod forwarders {{\n{definition}}}\n\n"),
        )],
    ));
    plants.push((
        "an invocation through a path",
        vec![pair(
            invocation,
            invocation.replace("forward_fill_word!", "forwarders::forward_fill_word!"),
        )],
    ));
    plants.push((
        "an item between the definition and its invocation",
        vec![pair(
            invocation,
            format!("const SPARE: u8 = 0;\n{invocation}"),
        )],
    ));
    let expected = format!(
        "{FILL}: forward_fill_word! is not one arm ($name:ty, $fence:path) => {{..}} that its production invocations directly follow"
    );
    for (label, edits) in plants {
        let planted = edited(&fill, &edits);
        assert_ne!(planted, fill, "{label}");
        let (report, code) = checked(vec![(FILL, text(planted))]);
        assert_eq!(code, 1, "{label}: {report:?}");
        assert!(
            messages_of(&report, "spelling")
                .iter()
                .any(|message| message.contains(&expected)),
            "{label}: {report:?}"
        );
    }
    let sequence = "crates/kestrike/src/index/sequence.rs";
    let split = source(
        sequence,
        "macro_rules! forward_seq_word {\n",
        "macro_rules! forward_seq_word {\n    () => {};\n",
    );
    refused(
        vec![(sequence, text(split))],
        "spelling",
        &format!("{sequence}: forward_seq_word! is not one arm"),
    );
    let kept = [
        ("another name for the type parameter", fill.replace("$atomic", "$word")),
        (
            "the arm without its `;`",
            fill.replace(footer, &footer.replace("    };\n}", "    }\n}")),
        ),
        (
            "a comment before the arm and a reflowed header",
            fill.replace(
                header,
                &header.replace(
                    "    ($atomic:ty, $fence:path) =>",
                    "    // The arm.\n    (\n        $atomic:ty,\n        $fence:path\n    ) =>",
                ),
            ),
        ),
        (
            "a second invocation after a comment",
            fill.replace(
                invocation,
                &format!(
                    "{invocation}\n// Another word.\nforward_fill_word!(std::sync::atomic::AtomicUsize, std::sync::atomic::fence);"
                ),
            ),
        ),
    ];
    for (label, planted) in kept {
        assert_ne!(planted, fill, "{label}");
        let (report, code) = checked(vec![(FILL, text(planted))]);
        assert_eq!(
            (code, member(&report, "refusals"), member(&report, "sites")),
            (0, &Value::Array(Vec::new()), &value("29")),
            "{label}"
        );
    }
}

#[test]
fn a_test_only_element_the_matcher_cuts_is_refused() {
    let visit = "    const VISIT: Ordering = Ordering::SeqCst;\n";
    let weak = "    #[cfg(not(test))]\n    const VISIT: Ordering = Ordering::Relaxed;\n";
    let nested = "        const VISIT: Ordering = Ordering::SeqCst;\n        VISIT\n";
    let store = "    record.store(INACTIVE, Ordering::Release);\n}";
    let relaxed = "    record.store(INACTIVE, Ordering::Relaxed);\n}";
    let load = "    decode(state.load(Ordering::Acquire), next_serial)\n}";
    let plants: [(&str, &str, &str, String); 9] = [
        (
            "an arm with an or-pattern after an arm with an or-pattern",
            FILL,
            ANCHOR,
            format!(
                "fn extra(n: u8) -> u8 {{\n    match n {{\n        2 | 3 => 2,\n        #[cfg(test)]\n        0 | 1 => 1,\n        _ => 0,\n    }}\n}}\n\n{ANCHOR}"
            ),
        ),
        (
            "a statement cut at a comma among its own generic arguments",
            GRACE,
            store,
            format!(
                "    #[cfg(test)]\n    pick::<u8, u8>({{ record.store(INACTIVE, Ordering::Release); 1 }});\n{relaxed}"
            ),
        ),
        (
            "an assignment cut at a comma among its own closure parameters",
            GRACE,
            store,
            format!(
                "    #[cfg(test)]\n    hook = |a, b| {{ record.store(INACTIVE, Ordering::Release); }};\n{relaxed}"
            ),
        ),
        (
            "a fn-pointer field cut at a comma among its own generic arguments",
            GRACE,
            store,
            format!(
                "    struct _S(#[cfg(test)] fn() -> W<u8, {{ record.store(INACTIVE, Ordering::Release); 1 }}>, u8);\n{relaxed}"
            ),
        ),
        (
            "a first arm cut at a comma among its own generic arguments",
            FILL,
            load,
            "    match next_serial {\n        #[cfg(test)]\n        0 => pick::<u8, u8>(decode(state.load(Ordering::Acquire), next_serial)),\n        _ => decode(state.load(Ordering::Relaxed), next_serial),\n    }\n}".to_owned(),
        ),
        (
            "a parameter among a macro's tokens",
            FILL,
            ANCHOR,
            format!(
                "with_probe!(; #[cfg(test)] B> fn extra(state: &AtomicU64) {{ state.load(Ordering::Relaxed); }});\n\n{ANCHOR}"
            ),
        ),
        (
            "a generic parameter",
            FILL,
            ANCHOR,
            format!("fn extra<A, #[cfg(test)] B>(a: A) -> A {{\n    a\n}}\n\n{ANCHOR}"),
        ),
        (
            "a statement cut at the comma of its closure parameters",
            FILL,
            ANCHOR,
            format!("fn extra() {{\n    #[cfg(test)]\n    let sum = |a, b| a + b;\n}}\n\n{ANCHOR}"),
        ),
        (
            "a tuple element cut at the comma of its generic arguments",
            GRACE,
            store,
            "    let _ = (a | b, #[cfg(test)] if pick::<u8, u8>() { record.store(INACTIVE, Ordering::Release); 1 } else { 2 });\n    record.store(INACTIVE, Ordering::Relaxed);\n}".to_owned(),
        ),
    ];
    let cut = "a test-only element whose end the matcher reads more than one way";
    for (label, path, old, new) in &plants {
        let (report, code) = checked(with_source(path, old, new));
        assert_eq!(code, 1, "{label}: {report:?}");
        assert!(
            messages_of(&report, "spelling")
                .iter()
                .any(|message| message.contains(cut)),
            "{label}: {report:?}"
        );
    }
    refused(
        with_source(
            FILL,
            ANCHOR,
            &format!(
                "with_probe!(; #[cfg(test)] B> fn extra(state: &AtomicU64) {{ state.load(Ordering::Acquire); }});\n\n{ANCHOR}"
            ),
        ),
        "unrowed site",
        ACQUIRE_UNROWED,
    );
    let compared = format!(
        "{weak}    #[cfg(test)]\n    const VISIT: Ordering = if 1 > 0 {{\n{nested}    }} else {{\n        Ordering::Relaxed\n    }};\n"
    );
    let arm = "    match next_serial {\n        #[cfg(test)]\n        0 | 1 => decode(state.load(Ordering::Acquire), next_serial),\n        _ => decode(state.load(Ordering::Relaxed), next_serial),\n    }\n}";
    let whole = format!("{weak}    #[cfg(test)]\n    const VISIT: Ordering = Ordering::SeqCst;\n");
    for (label, path, old, new, id) in [
        (
            "a const whose initializer holds a comparison",
            GRACE,
            visit,
            compared.as_str(),
            "grace-visit",
        ),
        (
            "an or-pattern first arm that holds a row's find",
            FILL,
            load,
            arm,
            "fill-observe",
        ),
        ("a const", GRACE, visit, whole.as_str(), "grace-visit"),
    ] {
        let (report, code) = checked(with_source(path, old, new));
        assert_eq!(code, 1, "{label}: {report:?}");
        assert!(
            messages_of(&report, "find")
                .iter()
                .any(|message| message.contains(&format!("{id}: its find occurs 0 times"))),
            "{label}: {report:?}"
        );
        assert!(
            refusals_of(&report, "spelling").is_empty(),
            "{label}: {report:?}"
        );
    }
    let first = "fn extra(n: u8) -> u8 {\n    match n {\n        #[cfg(test)]\n        0 | 1 => 1,\n        _ => 0,\n    }\n}\n\n";
    accepted(with_source(FILL, ANCHOR, &format!("{first}{ANCHOR}")));
    let inner = "#[cfg(test)]\nmod probes {\n    #[cfg(all(test, loom))]\n    const ROOM: usize = 1 << 12;\n}\n\n";
    accepted(with_source(FILL, ANCHOR, &format!("{inner}{ANCHOR}")));
    for (label, whole) in [
        (
            "an extern fn with a comma in its generics",
            "#[cfg(test)]\nextern \"C\" fn probe<A, B>() {}\n\n",
        ),
        (
            "an extern fn with no ABI",
            "#[cfg(test)]\nextern fn probe<A, B>() {}\n\n",
        ),
    ] {
        let (report, code) = checked(with_source(FILL, ANCHOR, &format!("{whole}{ANCHOR}")));
        assert_eq!(
            (code, member(&report, "refusals")),
            (0, &Value::Array(Vec::new())),
            "{label}"
        );
    }
}

#[test]
fn the_text_of_a_test_only_element_after_its_first_block_is_a_stated_limit() {
    let store = "    record.store(INACTIVE, Ordering::Release);\n}";
    let weak = "    record.store(INACTIVE, Ordering::Relaxed);\n}";
    for (label, kept) in [
        (
            "the else of an if",
            "let _ = if skip() { 0 } else { record.store(INACTIVE, Ordering::Release); 1 };",
        ),
        (
            "a loop body after a struct pattern",
            "for Probe { n } in probes() { record.store(INACTIVE, Ordering::Release); }",
        ),
    ] {
        let (report, code) = checked(with_source(
            GRACE,
            store,
            &format!("    #[cfg(test)]\n    {kept}\n{weak}"),
        ));
        assert_eq!(
            (code, member(&report, "refusals")),
            (0, &Value::Array(Vec::new())),
            "{label}"
        );
    }
}

#[test]
fn an_ordering_type_in_a_type_position_is_no_spelling() {
    let pick =
        format!("fn pick(_: Option<Ordering>) -> Option<Ordering> {{\n    None\n}}\n\n{ANCHOR}");
    let (report, _) = checked(with_source(FILL, ANCHOR, &pick));
    assert_eq!(*member(&report, "refusals"), Value::Array(Vec::new()));
}

#[test]
fn a_cataloged_release_weakened_in_the_source_is_refused_by_row() {
    refused(
        with_source(
            GRACE,
            "record.store(INACTIVE, Ordering::Release);",
            "record.store(INACTIVE, Ordering::Relaxed);",
        ),
        "find",
        "grace-unpin: its find occurs 0 times",
    );
}

#[test]
fn an_emptied_fill_forwarder_is_refused() {
    refused(
        with_source(FILL, "$fence(Ordering::Acquire);", ""),
        "find",
        "fill-forward-fence: its find occurs 0 times",
    );
}

#[test]
fn a_find_that_occurs_twice_is_refused() {
    let spare = format!(
        "fn spare<W: EraWord>(record: &W) {{\n    // record.store(INACTIVE, Ordering::Release);\n}}\n\n{UNPIN}"
    );
    refused(
        with_source(GRACE, UNPIN, &spare),
        "find",
        "grace-unpin: its find occurs 2 times",
    );
}

#[test]
fn a_find_whose_site_moved_to_a_comment_holds_no_site() {
    refused(
        with_source(
            GRACE,
            "    record.store(INACTIVE, Ordering::Release);\n}",
            "    // record.store(INACTIVE, Ordering::Release);\n    record.store(INACTIVE, Ordering::Relaxed);\n}",
        ),
        "find",
        "grace-unpin: its find holds 0 sites",
    );
}

#[test]
fn a_find_that_holds_two_sites_is_refused() {
    refused(
        with_catalog(|catalog| {
            let planted = row(catalog, "grace-start");
            planted.insert(
                "find",
                string("const START: Ordering = Ordering::SeqCst;\n    const VISIT: Ordering = Ordering::SeqCst;"),
            );
            planted.insert(
                "replace",
                string("const START: Ordering = Ordering::Acquire;\n    const VISIT: Ordering = Ordering::SeqCst;"),
            );
        }),
        "find",
        "grace-start: its find holds 2 sites",
    );
}

fn field(catalog: &mut Value, id: &str, key: &str) -> String {
    match row(catalog, id).get(key) {
        Some(Value::String(text)) => text.to_string(),
        found => panic!("{id} holds {key}: {found:?}"),
    }
}

#[test]
fn a_replace_that_weakens_seqcst_to_relaxed_is_refused() {
    refused(
        with_catalog(|catalog| {
            row(catalog, "grace-visit").insert(
                "replace",
                string("const VISIT: Ordering = Ordering::Relaxed;"),
            );
        }),
        "step",
        "grace-visit: its replace is not its find after one load step",
    );
    refused(
        with_catalog(|catalog| {
            let replace = field(catalog, "grace-unpin", "replace").replace("INACTIVE", "0");
            row(catalog, "grace-unpin").insert("replace", string(&replace));
        }),
        "step",
        "grace-unpin: its replace is not its find after one store step",
    );
}

#[test]
fn an_op_the_matcher_reads_otherwise_is_refused() {
    refused(
        with_catalog(|catalog| {
            let planted = row(catalog, "grace-pin-store");
            planted.insert("op", string("load"));
            planted.insert(
                "replace",
                string("const PIN_STORE: Ordering = Ordering::Acquire;"),
            );
        }),
        "step",
        "grace-pin-store: its site is a store, the row says load",
    );
}

#[test]
fn a_site_whose_op_the_matcher_cannot_read_is_refused() {
    let credit = source(
        CREDIT,
        "map.fetch_or(bits, Ordering::SeqCst);",
        "let order = Ordering::SeqCst;\n    map.fetch_or(bits, order);",
    );
    let planted = catalog_with(|catalog| {
        let planted = row(catalog, "credit-reset-flag");
        planted.insert("find", string("let order = Ordering::SeqCst;"));
        planted.insert("replace", string("let order = Ordering::AcqRel;"));
    });
    refused(
        vec![(CREDIT, text(credit)), (CATALOG, text(planted))],
        "step",
        "credit-reset-flag: the matcher reads no op for its site",
    );
}

#[test]
fn a_strength_constant_takes_its_op_from_the_code() {
    for (op, step) in [("store", "Release"), ("rmw", "AcqRel")] {
        refused(
            with_catalog(|catalog| {
                let planted = row(catalog, "credit-reload");
                planted.insert("op", string(op));
                planted.insert(
                    "replace",
                    string(&format!("const RELOAD: Ordering = Ordering::{step};")),
                );
            }),
            "step",
            &format!("credit-reload: its site is a load, the row says {op}"),
        );
    }
    let (report, code) = checked_at(&top(), vec![], &[]);
    assert_eq!(code, 1, "{report:?}");
    assert!(
        messages_of(&report, "step")
            .iter()
            .any(|message| message.contains("credit-reload: the matcher reads no op for its site")),
        "{report:?}"
    );
}

#[test]
fn a_strength_constant_passed_to_two_ops_is_unread() {
    for path in ["S::VISIT", "S :: VISIT"] {
        let spare = format!(
            "fn spare<W: EraWord, S: Strength>(record: &W) {{\n    record.store(0, {path});\n}}\n\n{UNPIN}"
        );
        refused(
            with_source(GRACE, UNPIN, &spare),
            "step",
            "grace-visit: the matcher reads no op for its site",
        );
    }
}

#[test]
fn a_fence_row_that_keeps_the_call_is_refused() {
    refused(
        with_catalog(|catalog| {
            row(catalog, "fill-forward-fence")
                .insert("replace", string("$fence(Ordering::Relaxed);"));
        }),
        "step",
        "fill-forward-fence: its replace is not its find after one fence step",
    );
}

#[test]
fn a_site_in_two_rows_is_refused() {
    let mut committed_catalog = catalog();
    let find = field(&mut committed_catalog, "grace-visit", "find");
    let line = committed(GRACE)
        .split('\n')
        .position(|line| line.contains(&find))
        .expect("the grace file holds grace-visit's find")
        + 1;
    refused(
        with_catalog(|catalog| {
            let mut again = row(catalog, "grace-visit").clone();
            again.insert("id", string("grace-visit-again"));
            rows(catalog).push(Value::Object(again));
        }),
        "site rows",
        &format!("{GRACE}:{line}: Ordering::SeqCst has rows to ['Acquire', 'Acquire']"),
    );
}

#[test]
fn an_acqrel_site_needs_a_row_to_acquire_and_a_row_to_release() {
    let new = "map.fetch_or(bits, Ordering::AcqRel);";
    let credit = source(CREDIT, "map.fetch_or(bits, Ordering::SeqCst);", new);
    let one = |catalog: &mut Value| {
        let planted = row(catalog, "credit-reset-flag");
        planted.insert("find", string(new));
        planted.insert("replace", string(&new.replace("AcqRel", "Acquire")));
    };
    let with = |id: &'static str, replace: Option<String>| {
        move |catalog: &mut Value| {
            one(catalog);
            let mut added = row(catalog, "credit-reset-flag").clone();
            added.insert("id", string(id));
            if let Some(replace) = &replace {
                added.insert("replace", string(replace));
            }
            rows(catalog).push(Value::Object(added));
        }
    };
    let planted = |catalog: String| vec![(CREDIT, text(credit.clone())), (CATALOG, text(catalog))];
    refused(
        planted(catalog_with(one)),
        "site rows",
        "Ordering::AcqRel has rows to ['Acquire'], its steps are ['Acquire', 'Release']",
    );
    refused(
        planted(catalog_with(with("credit-reset-again", None))),
        "site rows",
        "has rows to ['Acquire', 'Acquire']",
    );
    accepted(planted(catalog_with(with(
        "credit-reset-release",
        Some(new.replace("AcqRel", "Release")),
    ))));
}

fn refused_in(root: &Path, plants: Plants<'_>, holds: &str) {
    refused_at(root, plants, "scope file", holds);
}

fn lacks(path: &str) -> String {
    format!("{path} is a production file the kernel package includes and files lacks")
}

fn undeclared(path: &str) -> String {
    format!("the kernel package includes {path} and no module file declares it")
}

#[test]
fn a_production_file_the_package_includes_and_files_lacks_is_refused() {
    let scratch = planted_package(&[SLOT], None);
    refused_in(
        &root_of(&scratch),
        vec![],
        &format!("{SLOT} is a production file"),
    );
}

#[test]
fn an_include_macro_in_a_package_source_is_refused() {
    for planted in [
        "include!(\"{up}crates/kestrike/src/storage/slot.rs\");\n",
        "use std::include as inc;\ninc!(\"{up}crates/kestrike/src/storage/slot.rs\");\n",
    ] {
        let scratch = planted_package(&[], Some(planted));
        refused_in(
            &root_of(&scratch),
            vec![],
            "an include! macro, whose source the scope rule does not read",
        );
    }
}

#[test]
fn a_model_support_file_the_package_includes_is_excluded() {
    let model = "crates/kestrike/src/storage/credit_model.rs";
    let scratch = planted_package(&[model, CREDIT], None);
    let (report, code) = checked_at(&root_of(&scratch), vec![], EXTERNAL);
    assert_eq!(
        (code, member(&report, "excluded")),
        (0, &names(&[model, STEPS])),
        "{report:?}"
    );
}

#[test]
fn a_commented_declaration_declares_nothing() {
    let planted = "// mod credit_steps;\n// #[path = \"credit_steps.rs\"]\nconst _DECLARED: &str = \"mod credit_steps;\";\nmod credit;\n";
    let (report, code) = checked(with_source(
        STORAGE,
        "\nmod credit;\n",
        &format!("\n{planted}"),
    ));
    assert_eq!(
        (code, member(&report, "excluded")),
        (0, &names(&[STEPS])),
        "{report:?}"
    );
}

#[test]
fn a_module_declaration_inside_a_macro_is_refused() {
    let moved = source(
        STORAGE,
        "\nmod fill;\n",
        "\n#[path = \"fill_v2.rs\"]\nmod fill;\n",
    );
    let storage = committed(STORAGE);
    let plants = [
        (
            "an unexpanded definition beside a redirected module",
            format!("{moved}macro_rules! decoy {{\n    () => {{\n        mod fill;\n    }};\n}}\n"),
        ),
        (
            "a definition in parentheses",
            format!("{moved}macro_rules! decoy (\n    () => {{\n        mod fill;\n    }};\n);\n"),
        ),
        (
            "a definition named by a raw identifier",
            format!(
                "{moved}macro_rules! r#decoy {{\n    () => {{\n        mod fill;\n    }};\n}}\n"
            ),
        ),
        (
            "a definition with a spaced bang",
            format!(
                "{moved}macro_rules ! decoy {{\n    () => {{\n        mod fill;\n    }};\n}}\n"
            ),
        ),
        (
            "an invocation that drops its tokens",
            format!("{moved}ignore! {{\n    mod fill;\n}}\n"),
        ),
        (
            "an invocation in parentheses",
            format!("{moved}const _DECOY: &str = stringify!(mod fill;);\n"),
        ),
        (
            "an invoked definition beside a test-only declaration",
            format!(
                "{storage}macro_rules! live {{\n    () => {{\n        #[cfg(not(test))]\n        mod credit_steps;\n    }};\n}}\nlive!();\n"
            ),
        ),
        (
            "a path attribute in a definition",
            format!(
                "{storage}macro_rules! live {{\n    () => {{\n        #[path = \"credit_steps.rs\"]\n        mod steps_live;\n    }};\n}}\nlive!();\n"
            ),
        ),
        (
            "a module named by a fragment",
            format!(
                "{storage}macro_rules! declare {{\n    ($name:ident) => {{\n        mod $name;\n    }};\n}}\ndeclare!(credit_steps);\n"
            ),
        ),
        (
            "a module whose `;` the macro supplies",
            format!("{storage}#[cfg(not(all(test, loom)))]\ndeclare!(mod credit_steps);\n"),
        ),
        (
            "a module a macro declares from an inline block",
            format!(
                "{storage}macro_rules! child {{\n    ($kw:tt $name:ident $body:tt) => {{\n        $kw $name;\n    }};\n}}\nchild!(mod credit_steps {{}});\n"
            ),
        ),
        (
            "an inline module in a definition",
            format!(
                "{storage}macro_rules! plain {{\n    () => {{\n        mod inner {{}}\n    }};\n}}\nplain!();\n"
            ),
        ),
    ];
    for (label, planted) in plants {
        let (report, code) = checked(vec![(STORAGE, text(planted))]);
        assert_eq!(code, 1, "{label}: {report:?}");
        assert!(
            messages_of(&report, "scope file")
                .iter()
                .any(|message| message.contains(MACRO_TOKENS)),
            "{label}: {report:?}"
        );
    }
    let plain = format!(
        "{storage}macro_rules! plain {{\n    () => {{\n        fn helper() {{}}\n    }};\n}}\nplain!();\n"
    );
    accepted(vec![(STORAGE, text(plain))]);
}

#[test]
fn a_declaration_in_an_inline_module_loads_from_that_modules_directory() {
    let moved = source(
        STORAGE,
        "\nmod fill;\n",
        "\n#[path = \"fill_v2.rs\"]\nmod fill;\n",
    );
    refused(
        vec![(
            STORAGE,
            text(format!("{moved}mod inner {{\n    mod fill;\n}}\n")),
        )],
        "scope file",
        &undeclared(FILL),
    );
    let storage = committed(STORAGE);
    for (label, nested) in [
        (
            "a nested declaration",
            "mod nested {\n    mod credit_steps;\n}\n",
        ),
        (
            "a nested path attribute",
            "mod nested {\n    #[path = \"credit_steps.rs\"]\n    mod steps;\n}\n",
        ),
    ] {
        let report = accepted(vec![(STORAGE, text(format!("{storage}{nested}")))]);
        assert_eq!(*member(&report, "excluded"), names(&[STEPS]), "{label}");
    }
    let climbing = "mod nested {\n    mod deeper {\n        #[path = \"../../credit_steps.rs\"]\n        mod steps;\n    }\n}\n";
    refused(
        vec![(STORAGE, text(format!("{storage}{climbing}")))],
        "scope file",
        &lacks(STEPS),
    );
}

#[test]
fn a_module_declared_by_a_raw_identifier_loads_its_file() {
    let storage = committed(STORAGE);
    for (label, declaration) in [
        ("a declaration", "mod r#credit_steps;"),
        (
            "a path attribute",
            "#[path = \"credit_steps.rs\"]\nmod r#steps;",
        ),
        (
            "an inline module",
            "mod r#storage {\n    #[path = \"../credit_steps.rs\"]\n    mod steps;\n}",
        ),
    ] {
        let (report, code) = checked(vec![(
            STORAGE,
            text(format!("{storage}#[cfg(not(test))]\n{declaration}\n")),
        )]);
        assert_eq!(code, 1, "{label}: {report:?}");
        assert!(
            messages_of(&report, "scope file").contains(&lacks(STEPS)),
            "{label}: {report:?}"
        );
    }
    accepted(with_source(STORAGE, "\nmod fill;\n", "\nmod r#fill;\n"));
    refused(
        vec![(
            STORAGE,
            text(format!(
                "{storage}ignore! {{\n    mod r#credit_steps;\n}}\n"
            )),
        )],
        "scope file",
        MACRO_TOKENS,
    );
}

#[test]
fn a_parent_that_declares_a_file_by_path_makes_it_production() {
    let scratch = planted_package(&[SLOT], None);
    refused_in(
        &root_of(&scratch),
        with_source(
            STORAGE,
            "\nmod slot;\n",
            "\n#[path = \"slot.rs\"]\nmod slot_file;\n",
        ),
        &format!("{SLOT} is a production file"),
    );
}

#[test]
fn a_directory_module_is_classified_by_its_parent() {
    let include = "crates/kestrike/src/storage/planted/mod.rs";
    let scratch = planted_package(&[include], None);
    let root = root_of(&scratch);
    refused_in(
        &root,
        with_source(STORAGE, "\nmod slot;\n", "\nmod slot;\nmod planted;\n"),
        &lacks(include),
    );
    let (report, code) = checked_at(
        &root,
        with_source(
            STORAGE,
            "\nmod slot;\n",
            "\nmod slot;\n#[cfg(test)]\nmod planted;\n",
        ),
        EXTERNAL,
    );
    assert_eq!(code, 0, "{report:?}");
    assert!(
        items(member(&report, "excluded")).contains(&string(include)),
        "{report:?}"
    );
}

#[test]
fn a_crate_root_or_another_directory_declares_an_include() {
    let include = "crates/kestrike/src/planted.rs";
    let scratch = planted_package(&[include], None);
    refused_in(
        &root_of(&scratch),
        vec![(LIB, text(format!("{}\nmod planted;\n", committed(LIB))))],
        &lacks(include),
    );
    refused(
        vec![(
            LIB,
            text(format!(
                "{}\n#[path = \"storage/credit_steps.rs\"]\nmod steps;\n",
                committed(LIB)
            )),
        )],
        "scope file",
        &lacks(STEPS),
    );
    refused(
        vec![(
            STORAGE,
            text(format!(
                "{}\n#[path = r\"credit_steps.rs\"]\nmod steps;\n",
                committed(STORAGE)
            )),
        )],
        "scope file",
        &format!("{STORAGE} holds a path attribute the scope rule cannot read"),
    );
    refused(
        vec![(
            STORAGE,
            text(format!(
                "{}\n#[path = \"credit\\x5fsteps.rs\"]\nmod steps;\n",
                committed(STORAGE)
            )),
        )],
        "scope file",
        "the path attribute holds an escape the scope rule cannot read",
    );
}

#[test]
fn a_file_declared_only_from_another_directory_is_refused() {
    let holder = "crates/kestrike/src/failover/reconcile_tests.rs";
    let moved = source(
        STORAGE,
        "\nmod fill;\n",
        "\n#[path = \"fill_v2.rs\"]\nmod fill;\n",
    );
    let decoy = format!(
        "{}\n#[path = \"../storage/fill.rs\"]\nmod decoy;\n",
        committed(holder)
    );
    refused(
        vec![(STORAGE, text(moved)), (holder, text(decoy))],
        "scope file",
        &format!(
            "{FILL} is declared only by a path attribute outside its module files and the crate root"
        ),
    );
}

fn listed_files() -> Vec<String> {
    items(get(&catalog(), "files"))
        .iter()
        .map(|path| match path {
            Value::String(path) => path.to_string(),
            _ => panic!("a listed file is a string: {path:?}"),
        })
        .collect()
}

#[test]
fn an_included_file_is_classified_through_its_chain_to_the_crate_root() {
    let storage_files: Vec<String> = listed_files()
        .into_iter()
        .filter(|path| path.contains("/storage/"))
        .collect();
    let moved = source(
        STORAGE,
        "\nmod fill;\n",
        "\n#[path = \"fill_v2.rs\"]\nmod fill;\n",
    );
    refused(
        vec![
            (STORAGE, text(moved)),
            (
                "crates/kestrike/src/storage/lib.rs",
                text("mod fill;\n".to_owned()),
            ),
        ],
        "scope file",
        &undeclared(FILL),
    );
    let redirected = source(
        TREE,
        "pub mod storage;",
        "#[path = \"storage_v2/mod.rs\"]\npub mod storage;",
    );
    for (label, extra) in [
        ("a redirected directory", None),
        (
            "a declaration beside the source directory",
            Some(("crates/kestrike/src.rs", text("mod storage;\n".to_owned()))),
        ),
    ] {
        let mut plants = vec![(TREE, text(redirected.clone()))];
        plants.extend(extra);
        let (report, code) = checked(plants);
        let messages = messages_of(&report, "scope file");
        assert_eq!(code, 1, "{label}: {report:?}");
        let joined = messages.join(" ");
        for path in storage_files.iter().map(String::as_str).chain([STEPS]) {
            assert!(
                joined.contains(&undeclared(path)),
                "{label}: {path}: {messages:?}"
            );
        }
        assert!(
            !messages
                .iter()
                .any(|message| message.contains("index/sequence.rs")),
            "{label}: {messages:?}"
        );
        assert_eq!(
            *member(&report, "excluded"),
            Value::Array(Vec::new()),
            "{label}"
        );
    }
    let tested = source(TREE, "pub mod storage;", "#[cfg(test)]\npub mod storage;");
    let (report, code) = checked(vec![(TREE, text(tested.clone()))]);
    let mut excluded: Vec<&str> = storage_files
        .iter()
        .map(String::as_str)
        .chain([STEPS])
        .collect();
    excluded.sort_unstable();
    assert_eq!(
        (code, member(&report, "excluded")),
        (1, &names(&excluded)),
        "{report:?}"
    );
    refused(
        vec![(TREE, text(tested))],
        "scope file",
        &format!("{FILL} is listed and the kernel package includes no production file there"),
    );
    let sibling = "crates/kestrike/src/storage.rs";
    let by_path = source(
        TREE,
        "pub mod storage;",
        "#[path = \"storage.rs\"]\npub mod storage;",
    );
    refused(
        vec![
            (TREE, text(by_path.clone())),
            (sibling, text(committed(STORAGE))),
        ],
        "scope file",
        &undeclared(FILL),
    );
    let (report, _) = checked(vec![
        (TREE, text(by_path)),
        (
            sibling,
            text("#[path = \"storage/fill.rs\"]\nmod fill;\n".to_owned()),
        ),
    ]);
    let about_fill: Vec<String> = items(member(&report, "refusals"))
        .iter()
        .filter_map(|entry| match get(entry, "message") {
            Value::String(message) => Some(message.to_string()),
            _ => None,
        })
        .filter(|message| {
            message.starts_with(&format!("the kernel package includes {FILL} "))
                || message.starts_with(FILL)
        })
        .collect();
    assert!(about_fill.is_empty(), "{about_fill:?}");
    let report = accepted(with_source(
        TREE,
        "pub mod storage;",
        "#[path = \"storage/mod.rs\"]\npub mod storage;",
    ));
    assert_eq!(
        (member(&report, "sites"), member(&report, "excluded")),
        (&value("29"), &names(&[STEPS]))
    );
    let storage = committed(STORAGE);
    refused(
        vec![
            (
                STORAGE,
                text(format!("{storage}#[path = \"via.rs\"]\nmod via;\n")),
            ),
            (
                "crates/kestrike/src/storage/via.rs",
                text("mod credit_steps;\n".to_owned()),
            ),
        ],
        "scope file",
        &lacks(STEPS),
    );
    refused(
        vec![(
            TREE,
            text(format!(
                "{}\n#[path = \"storage/credit_steps.rs\"]\nmod steps;\n",
                committed(TREE)
            )),
        )],
        "scope file",
        &lacks(STEPS),
    );
    let before = source(
        STORAGE,
        "#[cfg(all(test, loom))]\nmod credit_steps;",
        "#[path = \"credit_steps.rs\"]\n#[cfg(all(test, loom))]\nmod credit_steps;",
    );
    let report = accepted(vec![(STORAGE, text(before))]);
    assert_eq!(*member(&report, "excluded"), names(&[STEPS]));
    let extra = "crates/kestrike/src/storage/helpers/extra.rs";
    let helpers = || {
        (
            "crates/kestrike/src/storage/helpers/mod.rs",
            text("mod extra;\n".to_owned()),
        )
    };
    let scratch = planted_package(&[extra], None);
    let root = root_of(&scratch);
    let (report, code) = checked_at(
        &root,
        vec![
            (
                STORAGE,
                text(format!("{storage}#[cfg(test)]\nmod helpers;\n")),
            ),
            helpers(),
        ],
        EXTERNAL,
    );
    assert_eq!(
        (code, member(&report, "refusals")),
        (0, &Value::Array(Vec::new())),
        "{report:?}"
    );
    assert!(
        items(member(&report, "excluded")).contains(&string(extra)),
        "{report:?}"
    );
    refused_in(
        &root,
        vec![
            (STORAGE, text(format!("{storage}mod helpers;\n"))),
            helpers(),
        ],
        &lacks(extra),
    );
    refused_in(&root, vec![helpers()], &undeclared(extra));
}

#[test]
fn a_scoped_file_that_loads_other_source_is_refused() {
    for (label, loaded) in [
        ("an include! macro", "include!(\"fill_peek.rs\");"),
        ("a child module", "mod extra;"),
        ("a child module named by a raw identifier", "mod r#extra;"),
        (
            "a renamed include macro",
            "use std::include as inc;\ninc!(\"fill_peek.rs\");",
        ),
        (
            "an include macro renamed from its raw identifier",
            "use std::r#include as inc;\ninc!(\"fill_peek.rs\");",
        ),
        (
            "a child module a macro names by a fragment",
            "macro_rules! child {\n    ($name:ident) => {\n        mod $name;\n    };\n}\nchild!(extra);",
        ),
        (
            "a child module whose `;` a macro supplies",
            "declare!(mod extra);",
        ),
        (
            "a child module a macro declares from an inline block",
            "child!(mod extra {});",
        ),
        ("an inline module", "mod extra {}"),
        (
            "a module by path",
            "#[path = \"fill_extra.rs\"]\nmod extra;",
        ),
    ] {
        for holds in [
            format!("{FILL}:"),
            "can load source that the catalog does not scope".to_owned(),
        ] {
            let (report, code) =
                checked(with_source(FILL, ANCHOR, &format!("{loaded}\n\n{ANCHOR}")));
            assert_eq!(code, 1, "{label}: {report:?}");
            assert!(
                messages_of(&report, "scope file")
                    .iter()
                    .any(|message| message.contains(&holds)),
                "{label}: {holds:?} in {report:?}"
            );
        }
    }
    for (label, kept) in [
        ("a test-only child module", "#[cfg(test)]\nmod fill_probes;"),
        ("a fn named by the raw identifier mod", "fn r#mod() {}"),
        (
            "a test-only module declared by path before its test attribute",
            "#[path = \"probes.rs\"]\n#[cfg(test)]\nmod fill_probes;",
        ),
    ] {
        let (report, code) = checked(with_source(FILL, ANCHOR, &format!("{kept}\n\n{ANCHOR}")));
        assert_eq!(
            (code, member(&report, "refusals")),
            (0, &Value::Array(Vec::new())),
            "{label}"
        );
    }
}

#[test]
fn an_include_no_module_file_declares_is_refused() {
    let include = "crates/kestrike/src/storage/undeclared.rs";
    let scratch = planted_package(&[include], None);
    let root = root_of(&scratch);
    refused_in(&root, vec![], &undeclared(include));
    refused_in(
        &root,
        vec![(STORAGE, Plant::Refused)],
        &format!("{STORAGE} cannot be read to classify {include}"),
    );
    let extra = "crates/kestrike/src/storage/extra.rs";
    let scratch = planted_package(&[extra], None);
    refused_in(
        &root_of(&scratch),
        vec![(
            STORAGE,
            text(format!(
                "{}\n#[cfg(test)]\n#[path = \"tests/extra.rs\"]\nmod extra;\n",
                committed(STORAGE)
            )),
        )],
        &undeclared(extra),
    );
    let scratch = planted_package(&["undeclared.rs"], None);
    refused_in(&root_of(&scratch), vec![], &undeclared("undeclared.rs"));
}

/// Writes `contents` to a new file at `path`, which no entry may hold yet.
fn create(path: &Path, contents: &str) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    file.write_all(contents.as_bytes())
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

#[test]
fn a_path_attribute_the_include_scanner_misses_is_refused() {
    let slot = "{up}crates/kestrike/src/storage/slot.rs";
    let missed = "kernels/src/planted.rs:1: a path attribute the include scanner misses";
    let plants = [
        (
            "a raw string",
            format!("#[path = r\"{slot}\"]\nmod m0;\n"),
            missed,
        ),
        (
            "other spacing",
            format!("#[path  =  \"{slot}\"]\nmod m0;\n"),
            missed,
        ),
        (
            "a conditional attribute",
            format!("#[cfg_attr(kernel = \"x\", path = \"{slot}\")]\nmod m0;\n"),
            missed,
        ),
        (
            "a commented include beside a missed one",
            format!("/*\n#[path = \"{{up}}{CREDIT}\"]\n*/\n#[path = r\"{slot}\"]\nmod m0;\n"),
            "kernels/src/planted.rs:2: the include scanner reads a path attribute outside live code",
        ),
        (
            "an escaped include",
            "#[path = \"{up}crates/kestrike/src/storage/sl\\x6ft.rs\"]\nmod m0;\n".to_owned(),
            "kernels/src/planted.rs:1: the include path",
        ),
    ];
    for (label, planted, message) in &plants {
        let scratch = planted_package(&[], Some(planted));
        let (report, code) = checked_at(&root_of(&scratch), vec![], EXTERNAL);
        assert_eq!(code, 1, "{label}: {report:?}");
        assert!(
            messages_of(&report, "scope file")
                .iter()
                .any(|found| found.contains(message)),
            "{label}: {report:?}"
        );
    }
    let scratch = planted_package(&[], Some("#[path = \"extra.inc\"]\nmod extra;\n"));
    create(
        &package_of(&scratch).join("src/extra.inc"),
        &format!(
            "#[path = \"../{}crates/kestrike/src/storage/slot.rs\"]\nmod m0;\n",
            "../".repeat(5)
        ),
    );
    refused_in(
        &root_of(&scratch),
        vec![],
        "the include 'extra.inc' is no Rust source of the package the scan reads",
    );
}

#[test]
fn a_directory_named_like_a_source_is_skipped() {
    let scratch = planted_package(&[], Some(""));
    fs::create_dir(package_of(&scratch).join("src/spare.rs")).expect("the directory is made");
    let (report, code) = checked_at(&root_of(&scratch), vec![], EXTERNAL);
    assert_eq!(
        (code, member(&report, "refusals")),
        (0, &Value::Array(Vec::new())),
        "{report:?}"
    );
}

#[test]
fn a_listed_file_the_package_does_not_include_is_refused() {
    let scratch = planted_package(&[], None);
    refused_in(
        &root_of(&scratch),
        with_catalog(|catalog| match object(catalog).get_mut("files") {
            Some(Value::Array(files)) => files.push(string(SLOT)),
            _ => panic!("the catalog lists files"),
        }),
        "slot.rs is listed and the kernel package includes no production file",
    );
}

#[test]
fn an_include_outside_the_repository_is_refused() {
    let scratch = planted_package(&["../outside.rs"], None);
    refused_in(&root_of(&scratch), vec![], "outside the repository");
}

#[test]
fn an_unreadable_scope_file_is_refused() {
    refused(
        vec![(FILL, Plant::Refused)],
        "scope file",
        &format!("{FILL} cannot be read"),
    );
    let (report, _) = checked(vec![(FILL, Plant::Refused)]);
    assert!(refusals_of(&report, "row").is_empty(), "{report:?}");
    assert_eq!(disposition(&report, "fill-observe"), string("unrun"));
}

#[test]
fn an_empty_scoped_file_refuses_each_of_its_rows() {
    let (report, code) = checked(vec![(FILL, text(String::new()))]);
    assert_eq!(code, 1, "{report:?}");
    let refused_ids: BTreeSet<String> = messages_of(&report, "find")
        .iter()
        .map(|message| message.split(':').next().unwrap_or_default().to_owned())
        .collect();
    let fill_ids: BTreeSet<String> = items(get(&catalog(), "rows"))
        .iter()
        .filter(|entry| *get(entry, "path") == string(FILL))
        .map(|entry| match get(entry, "id") {
            Value::String(id) => id.to_string(),
            id => panic!("an id is a string: {id:?}"),
        })
        .collect();
    assert_eq!(refused_ids, fill_ids);
    refused(
        vec![(FILL, text(String::new()))],
        "find",
        &format!("fill-observe: its find occurs 0 times in {FILL}"),
    );
}

#[test]
fn a_word_inside_a_path_attribute_belongs_to_its_refusal() {
    let loaded = "#[cfg_attr(include, path = \"fill_extra.rs\")]\nmod extra;\n\n";
    let planted = source(FILL, ANCHOR, &format!("{loaded}{ANCHOR}"));
    let line = planted[..planted.find(loaded).expect("the plant stands")]
        .matches('\n')
        .count()
        + 1;
    let (report, code) = checked(vec![(FILL, text(planted))]);
    assert_eq!(code, 1, "{report:?}");
    assert_eq!(
        messages_of(&report, "scope file"),
        [
            format!(
                "{FILL}:{line}: #[cfg_attr(include, path = can load source that the catalog does not scope"
            ),
            format!(
                "{FILL}:{}: mod can load source that the catalog does not scope",
                line + 1
            ),
        ]
    );
}
