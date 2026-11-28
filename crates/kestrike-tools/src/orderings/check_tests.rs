use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::{CATALOG, UNMODELED, check, family_kernel, row_entries};
use crate::genmc::package_sources;
use crate::json::{self, Object, Text, Value};
use crate::orderings::sites::{EXTERNAL, Pin};
use crate::orderings::sources::tests::{
    Plant, committed, package_of, planted as source, planted_package, reader, root_of, text, top,
};
use crate::orderings::sources::{c_literals, diagnostics, kernel_texts, module_source};
use crate::python::repr;

const FILL: &str = "crates/kestrike/src/storage/fill.rs";
const GRACE: &str = "crates/kestrike/src/storage/grace.rs";
const CREDIT: &str = "crates/kestrike/src/storage/credit.rs";
const STORAGE: &str = "crates/kestrike/src/storage/mod.rs";
const STEPS: &str = "crates/kestrike/src/storage/credit_steps.rs";
const SLOT: &str = "crates/kestrike/src/storage/slot.rs";
const TREE: &str = "crates/kestrike/src/mod.rs";
const LIB: &str = "crates/kestrike/src/lib.rs";
const PACKAGE: &str = "verification/genmc/packages/kernels";
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
    check(&reader(plants), root, &top(), pins, &package_sources)
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

/// Asserts that the check over `plants` refuses `name` with exactly `message`.
fn sentence(plants: Plants<'_>, name: &str, message: &str) {
    let report = checked(plants).0;
    assert!(
        messages_of(&report, name)
            .iter()
            .any(|found| found == message),
        "{name}: {message:?} in {:?}",
        member(&report, "refusals")
    );
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
        assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
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
        assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
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
        assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
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
            assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
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
        assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
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
        assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
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
        assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
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
        assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
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
        assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
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
            assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
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
        assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
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

const FILL_MODEL: &str = "storage::fill_model::";
const CONTROL: &str =
    "storage::fill_model::negative_control_a_relaxed_departure_loses_the_owners_last_write";
const CUTOFF: &str = r#"{"lane": "genmc", "tests": ["cutoff-pinfirst"], "failure": "protection violated: a scan after the close missed an admitted interval's live pin"}"#;
const TERMINAL: &str = r#"{"lane": "genmc", "tests": ["terminal-own"], "failure": "a copy of the terminal removal's bare store was accepted under the old sequence"}"#;
const TORN: &str = r#"{"lane": "loom", "tests": ["index::scan_model::readers_return_no_copy_or_a_copy_of_one_stable_state_across_an_insert"], "failure": "torn copy of"}"#;
const GRACE_MODEL: &str = "crates/kestrike/src/storage/grace_model.rs";
const GRACE_TEST: &str =
    "storage::grace_model::pinned_readers_never_observe_a_released_anchor_or_a_reused_slot";

/// Sets row `id`'s disposition, whichever it holds, to `unrun` with `needs`, and drops its revision.
fn needing(catalog: &mut Value, id: &str, needs: Value) {
    let planted = row(catalog, id);
    for key in ["kill", "survives", "unrun", "revision"] {
        planted.remove(key);
    }
    let mut unrun = Object::new();
    unrun.insert("needs", needs);
    planted.insert("unrun", Value::Object(unrun));
}

/// The entry `base` with each of `fields` set over its own.
fn with(base: &str, fields: &[(&str, Value)]) -> Value {
    let mut entry = value(base);
    for (key, field) in fields {
        object(&mut entry).insert(*key, field.clone());
    }
    entry
}

fn list(entries: &[Value]) -> Value {
    Value::Array(entries.to_vec())
}

/// The report of the check over `plants`.
fn report_of(plants: Plants<'_>) -> Value {
    checked(plants).0
}

#[test]
fn a_catalog_with_every_row_decided_and_none_refused_credits() {
    let (report, code) = checked(with_catalog(survived));
    assert_eq!(
        (
            code,
            member(&report, "refusals"),
            member(&report, "unrun"),
            member(&report, "credited")
        ),
        (
            0,
            &Value::Array(Vec::new()),
            &Value::Array(Vec::new()),
            &Value::Bool(true)
        ),
        "{report:?}"
    );
    let (report, code) = checked(with_catalog(|catalog| {
        survived(catalog);
        row(catalog, "grace-visit").insert("revision", string("planted"));
    }));
    assert_eq!(
        (code, member(&report, "unrun"), member(&report, "credited")),
        (1, &Value::Array(Vec::new()), &Value::Bool(false)),
        "{report:?}"
    );
    assert_eq!(
        messages_of(&report, "revision"),
        ["grace-visit: its survives disposition records no revision"]
    );
}

/// A file listed outside the package's scope and a test that is no positive one are refused without a
/// read of either: the reader sees neither the file nor any model source of the test's module.
#[test]
fn a_refused_path_or_test_is_never_read() {
    let spy = "storage::spy_model::a_test";
    let planted = catalog_with(|catalog| {
        match object(catalog).get_mut("files") {
            Some(Value::Array(files)) => files.push(string(SLOT)),
            _ => panic!("the catalog lists files"),
        }
        needing(
            catalog,
            "fill-observe",
            list(&[with(DEPARTED, &[("tests", names(&[spy]))])]),
        );
    });
    let spied = std::cell::RefCell::new(Vec::new());
    let committed_read = reader(vec![]);
    let read = |path: &str| {
        spied.borrow_mut().push(path.to_owned());
        if path == CATALOG {
            Ok(planted.clone())
        } else {
            committed_read(path)
        }
    };
    let (report, code) = check(&read, &top(), &top(), EXTERNAL, &package_sources);
    assert_eq!(code, 1, "{report:?}");
    assert_eq!(*member(&report, "credited"), Value::Bool(false));
    let refused = messages_of(&report, "reference");
    assert!(
        refused
            .iter()
            .any(|message| message.contains(&format!("{spy} is no positive loom test"))),
        "{report:?}"
    );
    assert!(
        !refused
            .iter()
            .any(|message| message.contains("no model source of")),
        "{report:?}"
    );
    assert!(
        messages_of(&report, "scope file").contains(&format!(
            "{SLOT} is listed and the kernel package includes no production file there"
        )),
        "{report:?}"
    );
    let spied = spied.into_inner();
    assert!(!spied.iter().any(|path| path == SLOT), "{spied:?}");
    assert!(
        !spied.iter().any(|path| path.contains("spy_model")),
        "{spied:?}"
    );
}

fn with_binding(id: &'static str, binding: &'static str) -> Plants<'static> {
    with_catalog(move |catalog| {
        row(catalog, id).insert("binding", string(binding));
    })
}

#[test]
fn an_unknown_binding_is_refused() {
    refused(
        with_binding("row-detach", "join-detach-acquire"),
        "reference",
        "row-detach: binding 'join-detach-acquire' binds no operation",
    );
}

#[test]
fn a_binding_of_another_file_is_refused() {
    refused(
        with_binding("row-detach", "publication-install"),
        "reference",
        "row-detach: binding 'publication-install' binds no operation",
    );
}

/// A binding of another call is refused by the call its find lacks, a binding whose scope names another
/// item by its enclosing item, and a binding whose production entry lacks its call or its scope by
/// that lack.
#[test]
fn a_binding_of_another_operation_in_the_same_file_is_refused() {
    refused(
        with_binding("row-detach", "join-observers-acquire"),
        "reference",
        "row-detach: binding 'join-observers-acquire' binds 'self.observers.load', which its find lacks",
    );
    refused(
        with_binding("sequence-read-stable", "sequence-second-load"),
        "enclosing item",
        "sequence-read-stable: fn still resolves to 1 bodies, or its body lacks the find",
    );
    for field in ["call", "scope"] {
        let mut declared = value(&committed(super::GENMC));
        let bindings = match object(&mut declared).get_mut("bindings") {
            Some(Value::Array(bindings)) => bindings,
            _ => panic!("the declaration lists bindings"),
        };
        let entry = bindings
            .iter_mut()
            .map(object)
            .find(|entry| entry.get("id") == Some(&string("join-detach-release")))
            .expect("the declaration binds join-detach-release");
        match entry.get_mut("production") {
            Some(Value::Object(production)) => production.remove(field),
            _ => panic!("the binding has a production entry"),
        };
        refused(
            vec![(super::GENMC, text(json::dump(&declared)))],
            "reference",
            "row-detach: binding 'join-detach-release' holds no call or scope",
        );
    }
}

fn twins(catalog: &mut Value, id: &str) -> Vec<Value> {
    items(row(catalog, id).get("twin").expect("the row holds twins")).to_vec()
}

fn twin_field(twin: &Value, key: &str) -> Value {
    get(twin, key).clone()
}

/// Each twin that is no control of its lane, or whose steps are absent, zero or a boolean, is refused
/// by row and twin, and the row's site stays rowed; a twin without a string lane, and a twin list that
/// is no list of entries, are refused as such.
#[test]
fn a_twin_that_is_no_control_is_refused() {
    type Plant = fn(&mut Vec<Value>);
    let plants: [(&str, Plant); 8] = [
        ("a positive GenMC case", |twin| {
            object(&mut twin[1]).insert("test", string("join-production"));
        }),
        ("a Never litmus test", |twin| {
            object(&mut twin[2]).insert("test", string("F0-fill-terminal-production"));
        }),
        ("a positive loom test", |twin| {
            object(&mut twin[0]).insert(
                "test",
                string("storage::fill_model::two_owners_on_one_key_and_a_servicer"),
            );
        }),
        ("a loom control under the genmc lane", |twin| {
            let control = twin_field(&twin[0], "test");
            object(&mut twin[1]).insert("test", control);
        }),
        ("no steps", |twin| {
            object(&mut twin[0]).remove("steps");
        }),
        ("zero steps", |twin| {
            object(&mut twin[0]).insert("steps", value("0"));
        }),
        ("boolean steps", |twin| {
            object(&mut twin[0]).insert("steps", Value::Bool(true));
        }),
        ("a list for a test", |twin| {
            let control = twin_field(&twin[0], "test");
            object(&mut twin[0]).insert("test", list(&[control]));
        }),
    ];
    for (label, plant) in plants {
        let plants = with_catalog(|catalog| {
            let mut twin = twins(catalog, "fill-depart-release");
            plant(&mut twin);
            row(catalog, "fill-depart-release").insert("twin", Value::Array(twin));
        });
        let report = report_of(plants.clone());
        assert!(
            refusals_of(&report, "unrowed site").is_empty(),
            "{label}: {report:?}"
        );
        refused(plants, "reference", "fill-depart-release: twin");
    }
    sentence(
        with_catalog(|catalog| {
            let mut twin = twins(catalog, "fill-depart-release");
            object(&mut twin[0]).insert("steps", value("0"));
            row(catalog, "fill-depart-release").insert("twin", Value::Array(twin));
        }),
        "reference",
        &format!(
            "fill-depart-release: twin {{'lane': 'loom', 'test': '{CONTROL}', 'steps': 0}} is no loom twin with its steps"
        ),
    );
    refused(
        with_catalog(|catalog| {
            let mut twin = twins(catalog, "fill-depart-release");
            object(&mut twin[0]).insert("lane", names(&["loom"]));
            row(catalog, "fill-depart-release").insert("twin", Value::Array(twin));
        }),
        "reference",
        "fill-depart-release: a twin names no lane",
    );
    for twin in ["null", "\"join-relaxeddepart\"", r#"{"lane": "loom"}"#] {
        refused(
            with_catalog(|catalog| {
                row(catalog, "fill-depart-release").insert("twin", value(twin));
            }),
            "reference",
            "fill-depart-release: its twin is no list of lane entries",
        );
    }
}

#[test]
fn two_twins_in_one_lane_are_refused() {
    refused(
        with_catalog(|catalog| {
            let mut twin = twins(catalog, "grace-bump");
            let mut extra = twin[0].clone();
            object(&mut extra).insert("test", string("grace2-bumprelaxed"));
            twin.push(extra);
            row(catalog, "grace-bump").insert("twin", Value::Array(twin));
        }),
        "reference",
        "grace-bump: its twins name a lane twice",
    );
}

#[test]
fn a_kill_row_naming_a_loom_control_is_refused() {
    refused(
        with_catalog(|catalog| {
            decided(
                catalog,
                "fill-depart-release",
                "kill",
                list(&[with(DEPARTED, &[("tests", names(&[CONTROL]))])]),
            );
        }),
        "reference",
        &format!("{CONTROL} is no positive loom test"),
    );
}

/// A GenMC violation case is no positive test of an unrun or a kill entry, and a loom control is none of
/// a passed entry.
#[test]
fn an_entry_naming_a_violation_case_or_a_control_is_refused() {
    let early = || list(&[with(FREED, &[("tests", names(&["join-earlydetach"]))])]);
    refused(
        with_catalog(|catalog| needing(catalog, "row-detach", early())),
        "reference",
        "join-earlydetach is no positive genmc test",
    );
    refused(
        with_catalog(|catalog| decided(catalog, "row-detach", "kill", early())),
        "reference",
        "join-earlydetach is no positive genmc test",
    );
    let passed = format!(
        r#"{{"reason": "planted", "passed": [{{"lane": "loom", "tests": ["{CONTROL}"]}}]}}"#
    );
    refused(
        with_catalog(|catalog| decided(catalog, "row-detach", "survives", value(&passed))),
        "reference",
        &format!("{CONTROL} is no positive loom test"),
    );
}

/// A loom control stays no positive test when a record also lists it under `tests`, for a kill and for
/// a survivor.
#[test]
fn a_control_also_listed_under_tests_is_no_positive_test() {
    let mut records = value(&committed(super::OBLIGATIONS));
    let listed = match object(&mut records).get_mut("records") {
        Some(Value::Array(listed)) => listed,
        _ => panic!("the obligation records list records"),
    };
    let record = listed
        .iter_mut()
        .find(|entry| match entry {
            Value::Object(entry) => matches!(entry.get("controls"), Some(Value::Array(controls))
                if controls.iter().any(|control| *get(control, "test") == string(CONTROL))),
            _ => false,
        })
        .expect("a record lists the control");
    match object(record).get_mut("tests") {
        Some(Value::Array(tests)) => tests.push(string(CONTROL)),
        _ => panic!("the record lists tests"),
    }
    let records = json::dump(&records);
    let passed = format!(
        r#"{{"reason": "planted", "passed": [{{"lane": "loom", "tests": ["{CONTROL}"]}}]}}"#
    );
    for (kind, planted) in [
        (
            "kill",
            list(&[with(DEPARTED, &[("tests", names(&[CONTROL]))])]),
        ),
        ("survives", value(&passed)),
    ] {
        let mut plants = with_catalog(|catalog| decided(catalog, "fill-observe", kind, planted));
        plants.push((super::OBLIGATIONS, text(records.clone())));
        refused(
            plants,
            "reference",
            &format!("{CONTROL} is no positive loom test"),
        );
    }
}

/// A loom failure that no message literal of each model source holds whole, as its head or as the text
/// after a `: ` separator is refused: an absent text, under a kill as under an unrun row, code text, a
/// literal of one model file of two, a substring and a message's leading part.
#[test]
fn a_loom_failure_in_no_string_literal_is_refused() {
    let scan = "index::scan_model::readers_never_copy_a_pending_pair_across_its_cancel";
    let run = format!("{FILL_MODEL}two_owners_on_one_key_and_a_servicer_observing_the_run");
    let one = [run.as_str()];
    let two = [run.as_str(), scan];
    let plants: [(&str, &str, &str, &[&str]); 6] = [
        ("absent", "unrun", "a record departed twice", &one),
        ("a kill row", "kill", "a record departed twice", &one),
        ("code text, not a literal", "unrun", "fill::depart", &one),
        (
            "in one model file of two",
            "unrun",
            "a departed record whose owner had not ended",
            &two,
        ),
        ("a substring of a literal", "unrun", "a", &one),
        (
            "the leading part of a message",
            "unrun",
            "protection violated",
            &one,
        ),
    ];
    for (label, kind, failure, tests) in plants {
        let mut entry = Object::new();
        entry.insert("lane", string("loom"));
        entry.insert("tests", names(tests));
        entry.insert("failure", string(failure));
        let entries = list(&[Value::Object(entry)]);
        let plants = with_catalog(|catalog| {
            if kind == "kill" {
                decided(catalog, "fill-run-fence", "kill", entries);
            } else {
                needing(catalog, "fill-run-fence", entries);
            }
        });
        let report = report_of(plants.clone());
        assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
        refused(
            plants,
            "reference",
            &format!(
                "fill-run-fence: the failure {} is no message literal",
                Text::from(failure).repr()
            ),
        );
    }
}

fn fill_ids() -> Vec<String> {
    items(get(&catalog(), "rows"))
        .iter()
        .filter(|entry| *get(entry, "path") == string(FILL))
        .map(|entry| match get(entry, "id") {
            Value::String(id) => id.to_string(),
            id => panic!("an id is a string: {id:?}"),
        })
        .collect()
}

#[test]
fn an_empty_included_file_refuses_each_of_its_rows() {
    let names = fill_ids();
    assert!(!names.is_empty());
    refused(
        vec![(FILL, text(String::new()))],
        "find",
        &format!("{}: its find occurs 0 times in {FILL}", names[0]),
    );
    let (report, code) = checked(vec![(FILL, text(String::new()))]);
    assert_eq!(code, 1, "{report:?}");
    let refused = messages_of(&report, "find");
    for name in &names {
        let message = format!("{name}: its find occurs 0 times in {FILL}");
        assert!(refused.contains(&message), "{message} in {refused:?}");
    }
}

fn grace_unpin(entry: Value) -> Plants<'static> {
    with_catalog(move |catalog| needing(catalog, "grace-unpin", list(&[entry])))
}

fn grace_entry(failure: &str) -> Value {
    let mut entry = Object::new();
    entry.insert("lane", string("loom"));
    entry.insert("tests", names(&[GRACE_TEST]));
    entry.insert("failure", string(failure));
    Value::Object(entry)
}

#[test]
fn a_loom_failure_two_message_literals_hold_is_refused() {
    let held = diagnostics(&committed(GRACE_MODEL))
        .iter()
        .filter(|content| *content == "protection violated: anchor released twice")
        .count();
    assert_eq!(held, 2);
    refused(
        grace_unpin(grace_entry("anchor released twice")),
        "reference",
        "grace-unpin: the failure 'anchor released twice' lies in more than one message literal",
    );
    sentence(
        grace_unpin(grace_entry("anchor released twice")),
        "reference",
        "grace-unpin: the failure 'anchor released twice' lies in more than one message literal of \
         a model source of its tests, so a panic holding it names no one assertion",
    );
}

#[test]
fn a_loom_failure_another_message_literal_extends_is_refused() {
    let anchor = "\"protection violated: anchor released under a pinned reader\"";
    let extended = source(
        GRACE_MODEL,
        anchor,
        &format!(
            "{anchor});\n        assert!(false, \"protection violated: anchor released under a pinned reader twice\""
        ),
    );
    let held = diagnostics(&extended)
        .iter()
        .filter(|content| content.contains("anchor released under a pinned reader"))
        .count();
    assert_eq!(held, 2);
    let mut plants = grace_unpin(grace_entry("anchor released under a pinned reader"));
    plants.push((GRACE_MODEL, text(extended)));
    refused(
        plants,
        "reference",
        "grace-unpin: the failure 'anchor released under a pinned reader' lies in more than one \
         message literal",
    );
}

/// A failure that only a `should_panic` attribute holds, whole or as a substring, is no message
/// literal, and a model source whose attribute is bare draws no `reference` refusal for a failure its
/// assertions hold.
#[test]
fn a_loom_failure_only_an_attribute_holds_is_refused() {
    assert!(
        committed("crates/kestrike/src/index/scan_model.rs")
            .contains("#[should_panic(expected = \"torn copy of B\")]")
    );
    for failure in ["torn copy of B", "A"] {
        refused(
            with_catalog(|catalog| {
                needing(
                    catalog,
                    "sequence-begin-fence",
                    list(&[with(TORN, &[("failure", string(failure))])]),
                );
            }),
            "reference",
            &format!(
                "sequence-begin-fence: the failure {} is no message literal",
                Text::from(failure).repr()
            ),
        );
    }
    let model = "crates/kestrike/src/storage/fill_model.rs";
    let attribute = "#[should_panic(expected = \"a departed record whose owner had not ended\")]";
    let text_of = committed(model);
    assert!(text_of.contains(attribute));
    let bare = text_of.replace(attribute, "#[should_panic]");
    let mut plants = with_catalog(|catalog| {
        needing(catalog, "fill-observe", list(&[value(DEPARTED)]));
    });
    plants.push((model, text(bare)));
    let report = report_of(plants);
    assert!(refusals_of(&report, "reference").is_empty(), "{report:?}");
}

#[test]
fn a_loom_test_whose_model_source_cannot_be_read_is_refused() {
    let model = "crates/kestrike/src/storage/fill_model.rs";
    let mut plants = with_catalog(|catalog| {
        needing(catalog, "fill-observe", list(&[value(DEPARTED)]));
    });
    plants.push((model, Plant::Refused));
    refused(
        plants,
        "reference",
        &format!(
            "fill-observe: no model source of {FILL_MODEL}two_owners_on_one_key_and_a_servicer can be read"
        ),
    );
}

/// A loom test's model source follows inline, path and bare declarations; a commented decoy loads
/// nothing; a path declaration moves the source, and the check then reads the moved one; no source
/// stands for an undeclared module, a dropped declaration, one in an unexpanded macro or one a parent
/// declares twice, which the check refuses by test.
#[test]
fn a_loom_model_source_follows_inline_and_path_declared_modules() {
    let readiness = "crates/kestrike/src/storage/readiness.rs";
    let fill_model = "crates/kestrike/src/storage/fill_model.rs";
    let authority = "storage::readiness::authority_model::withdrawal_and_serving_publication_preserve_both_word_fields";
    let cases = [
        (authority, readiness),
        (
            "net::client::route::route_model::a_read_racing_a_rebind_takes_one_binding_whole",
            "crates/kestrike/src/net/client/route_model.rs",
        ),
        (
            "storage::fill_model::two_owners_on_one_key_and_a_servicer",
            fill_model,
        ),
    ];
    let committed_read = reader(vec![]);
    for (test, path) in cases {
        assert_eq!(
            module_source(test, &committed_read),
            Some(committed(path)),
            "{test}"
        );
    }
    assert_eq!(module_source("undeclared::a_test", &committed_read), None);
    let decoyed = format!(
        "/*\n#[path = \"decoy.rs\"]\nmod authority_model;\n*/\n{}",
        committed(readiness)
    );
    let read = reader(vec![(readiness, text(decoyed.clone()))]);
    assert_eq!(module_source(authority, &read), Some(decoyed));
    let live = "crates/kestrike/src/storage/fill_model_v2.rs";
    let test = "storage::fill_model::two_owners_on_one_key_and_a_servicer";
    let moved = || {
        vec![
            (
                STORAGE,
                text(source(
                    STORAGE,
                    "\nmod fill_model;\n",
                    "\n#[path = \"fill_model_v2.rs\"]\nmod fill_model;\n",
                )),
            ),
            (live, text("// The live model.\n".to_owned())),
        ]
    };
    assert_eq!(
        module_source(test, &reader(moved())),
        Some("// The live model.\n".to_owned())
    );
    refused(
        moved(),
        "reference",
        "is no message literal of a model source of its tests",
    );
    let dropped = reader(vec![(
        STORAGE,
        text(source(STORAGE, "\nmod fill_model;\n", "\n")),
    )]);
    assert_eq!(module_source(test, &dropped), None);
    let stale = "crates/kestrike/src/storage/fill_model_stale.rs";
    let stale_live =
        "#[cfg(all(test, loom))]\n#[path = \"fill_model_stale.rs\"]\nmod stale_model;\n";
    for decoy in [
        "macro_rules! decoy {\n    () => {\n#[path = \"fill_model_stale.rs\"]\nmod fill_model;\n    };\n}\n",
        "/*\n#[path = \"fill_model_stale.rs\"]\nmod fill_model;\n*/\n",
    ] {
        let decoyed = reader(vec![
            (
                STORAGE,
                text(format!("{decoy}{}{stale_live}", committed(STORAGE))),
            ),
            (stale, text("// A stale model.\n".to_owned())),
        ]);
        assert_eq!(
            module_source(test, &decoyed),
            Some(committed(fill_model)),
            "{decoy}"
        );
    }
    let unexpanded = reader(vec![(
        STORAGE,
        text(source(
            STORAGE,
            "\nmod fill_model;\n",
            "\nmacro_rules! decoy {\n    () => {\n        mod fill_model;\n    };\n}\n",
        )),
    )]);
    assert_eq!(module_source(test, &unexpanded), None);
    let doubled = || {
        vec![
            (
                STORAGE,
                text(source(
                    STORAGE,
                    "#[cfg(all(test, loom))]\nmod fill_model;",
                    "#[cfg(all(test, loom, any()))]\n#[path = \"fill_model_stale.rs\"]\nmod fill_model;\n#[cfg(all(test, loom))]\nmod fill_model;",
                )),
            ),
            (stale, text("// A stale model.\n".to_owned())),
        ]
    };
    assert_eq!(module_source(test, &reader(doubled())), None);
    refused(
        doubled(),
        "reference",
        &format!("no model source of {test} can be read"),
    );
    let beside = format!(
        "#[cfg(any())]\n#[path = \"authority_model_stale.rs\"]\nmod authority_model;\n{}",
        committed(readiness)
    );
    let inline = reader(vec![
        (readiness, text(beside)),
        (
            "crates/kestrike/src/storage/authority_model_stale.rs",
            text("// A stale model.\n".to_owned()),
        ),
    ]);
    assert_eq!(module_source(authority, &inline), None);
}

/// A GenMC failure that is not exactly one `check!` message of its family's kernel file is refused: a
/// substring, another family's message, a message the kernel holds twice and a plain string; so is a
/// case whose family has no kernel file.
#[test]
fn a_genmc_failure_that_is_no_one_check_message_is_refused() {
    let cutoff = committed(&format!("{PACKAGE}/src/cutoff_kernel.rs"));
    let twice = c_literals(&cutoff)
        .iter()
        .filter(|message| *message == "pin refused")
        .count();
    assert_eq!(twice, 2);
    let plants = [
        (
            "a substring",
            "row-observers",
            FREED,
            "a follower's record was freed",
        ),
        (
            "another family's message",
            "row-observers",
            FREED,
            "pin refused",
        ),
        (
            "another family's message again",
            "row-observers",
            FREED,
            "a record holding credits is flagged",
        ),
        (
            "a message its kernel holds twice",
            "grace-era-load",
            CUTOFF,
            "pin refused",
        ),
        (
            "a plain string",
            "sequence-terminate-store",
            TERMINAL,
            "own",
        ),
    ];
    for (label, id, entry, failure) in plants {
        let report = report_of(with_catalog(|catalog| {
            needing(
                catalog,
                id,
                list(&[with(entry, &[("failure", string(failure))])]),
            );
        }));
        assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
        refused(
            with_catalog(|catalog| {
                needing(
                    catalog,
                    id,
                    list(&[with(entry, &[("failure", string(failure))])]),
                );
            }),
            "reference",
            &format!(
                "{id}: the failure {} is no one check! message of its cases' kernel file",
                Text::from(failure).repr()
            ),
        );
    }
    refused(
        with_catalog(|catalog| {
            needing(
                catalog,
                "row-observers",
                list(&[with(FREED, &[("tests", names(&["sb_sc"]))])]),
            );
        }),
        "reference",
        "row-observers: sb_sc has no kernel file of its family",
    );
}

/// A failure the kernel file spells as a `c"..."` literal only in a comment, outside a `check!` call or
/// in its condition is refused; a plain string beside the one message draws no `reference` refusal.
#[test]
fn a_genmc_failure_spelled_c_only_in_a_comment_is_refused() {
    let literal = "c\"a follower's record was freed or reissued under it\"";
    let plain = &literal[1..];
    let call = format!("check!(false, {literal})");
    let rows = [
        (
            "a comment",
            format!("check!(false, {plain} /* {literal} */)"),
            true,
        ),
        (
            "the literal outside check!",
            format!("check!(false, {plain}); let _stale = ({literal})"),
            true,
        ),
        (
            "the literal in the condition",
            format!("check!({literal}.is_empty(), c\"another message\")"),
            true,
        ),
        (
            "a plain duplicate beside it",
            format!("check!(false, {literal}); let _plain = ({plain})"),
            false,
        ),
    ];
    let planted =
        || with_catalog(|catalog| needing(catalog, "row-observers", list(&[value(FREED)])));
    for (label, new, refuses) in rows {
        let scratch = planted_package(&[], Some(""));
        let path = package_of(&scratch).join("src/join_kernel.rs");
        let kernel = fs::read_to_string(&path).expect("the kernel file reads");
        assert_eq!(kernel.matches(&call).count(), 1, "{label}");
        fs::write(&path, kernel.replacen(&call, &new, 1)).expect("the kernel file is written");
        if refuses {
            refused_at(
                &root_of(&scratch),
                planted(),
                "reference",
                "row-observers: the failure \"a follower's record was freed or reissued under it\" \
                 is no one check! message",
            );
        } else {
            let (report, _) = checked_at(&root_of(&scratch), planted(), EXTERNAL);
            assert!(
                refusals_of(&report, "reference").is_empty(),
                "{label}: {report:?}"
            );
        }
    }
}

#[test]
fn a_survives_row_with_an_empty_reason_is_refused() {
    refused(
        with_catalog(|catalog| {
            decided(
                catalog,
                "fill-depart-held",
                "survives",
                value(r#"{"reason": " ", "passed": []}"#),
            );
        }),
        "disposition",
        "fill-depart-held: its survives disposition lacks a field",
    );
}

#[test]
fn a_survives_row_with_a_reason_and_its_revision_is_accepted() {
    let (report, code) = checked(with_catalog(|catalog| {
        decided(
            catalog,
            "fill-depart-held",
            "survives",
            value(r#"{"reason": "no model calls depart_held", "passed": []}"#),
        );
    }));
    assert_eq!(
        (code, disposition(&report, "fill-depart-held")),
        (0, string("survives")),
        "{report:?}"
    );
}

/// An empty `passed` or `needs` is refused on every row outside `UNMODELED` and only there, and an
/// unmodeled row may name a run.
#[test]
fn a_disposition_that_names_no_run_is_refused_outside_the_unmodeled_rows() {
    let (report, code) = checked(with_catalog(|catalog| {
        let ids: Vec<String> = ids_in(catalog);
        for id in ids {
            decided(
                catalog,
                &id,
                "survives",
                value(r#"{"reason": "planted", "passed": []}"#),
            );
        }
    }));
    assert_eq!(
        (code, member(&report, "credited")),
        (1, &Value::Bool(false)),
        "{report:?}"
    );
    let kinds: BTreeSet<String> = items(member(&report, "refusals"))
        .iter()
        .map(|entry| match get(entry, "refusal") {
            Value::String(name) => name.to_string(),
            name => panic!("a refusal's name is a string: {name:?}"),
        })
        .collect();
    assert_eq!(kinds, BTreeSet::from(["disposition".to_owned()]));
    let mut refused_ids: Vec<String> = messages_of(&report, "disposition")
        .iter()
        .map(|message| message.split(':').next().unwrap_or_default().to_owned())
        .collect();
    refused_ids.sort();
    let mut expected: Vec<String> = ids_in(&mut catalog())
        .into_iter()
        .filter(|id| !UNMODELED.contains(&id.as_str()))
        .collect();
    expected.sort();
    assert_eq!(refused_ids, expected);
    refused(
        with_catalog(|catalog| {
            decided(
                catalog,
                "grace-visit",
                "survives",
                value(r#"{"reason": "planted", "passed": []}"#),
            );
        }),
        "disposition",
        "grace-visit: its survives disposition names no run",
    );
    sentence(
        with_catalog(|catalog| {
            decided(
                catalog,
                "grace-visit",
                "survives",
                value(r#"{"reason": "planted", "passed": []}"#),
            );
        }),
        "disposition",
        "grace-visit: its survives disposition names no run, and the row is outside \
         ['word-install', 'fill-depart-held', 'sequence-begin-store', 'sequence-commit']",
    );
    refused(
        with_catalog(|catalog| {
            row(catalog, "grace-visit")
                .insert("unrun", value(r#"{"needs": [], "reason": "planted"}"#));
        }),
        "disposition",
        "grace-visit: its unrun disposition names no run",
    );
    let (report, code) = checked(with_catalog(|catalog| {
        needing(catalog, "fill-depart-held", list(&[value(DEPARTED)]));
    }));
    assert_eq!(
        (code, member(&report, "refusals")),
        (0, &Value::Array(Vec::new())),
        "{report:?}"
    );
}

fn ids_in(catalog: &mut Value) -> Vec<String> {
    rows(catalog)
        .iter()
        .map(|entry| match get(entry, "id") {
            Value::String(id) => id.to_string(),
            id => panic!("an id is a string: {id:?}"),
        })
        .collect()
}

type Change<'c> = &'c dyn Fn(&mut Value);

/// A row with two dispositions or none is refused by its count, maps to null and is no unrun row.
#[test]
fn a_row_with_two_dispositions_or_none_is_refused() {
    let two = |catalog: &mut Value| {
        needing(catalog, "grace-visit", list(&[value(CUTOFF)]));
        row(catalog, "grace-visit")
            .insert("survives", value(r#"{"reason": "planted", "passed": []}"#));
    };
    let none = |catalog: &mut Value| {
        for key in ["kill", "survives", "unrun"] {
            row(catalog, "grace-visit").remove(key);
        }
    };
    let changes: [(Change<'_>, usize, &str); 2] =
        [(&two, 2, "['survives', 'unrun']"), (&none, 0, "[]")];
    for (change, count, held) in changes {
        refused(
            with_catalog(change),
            "disposition",
            &format!("grace-visit: it holds {count} dispositions"),
        );
        sentence(
            with_catalog(change),
            "disposition",
            &format!("grace-visit: it holds {count} dispositions {held}"),
        );
        let report = report_of(with_catalog(change));
        assert_eq!(disposition(&report, "grace-visit"), Value::Null);
        assert!(
            !items(member(&report, "unrun")).contains(&string("grace-visit")),
            "{report:?}"
        );
    }
}

/// Each malformed disposition is refused by its kind: an unrun without needs or a reason, beside a
/// blank reason, as a list or a string; a needs entry without a failure, with a blank or a numeric one,
/// or with no tests; an empty kill, a kill that is an object, a kill entry without a failure, two kill
/// entries in one lane; a survives that is a list, a passed entry without tests or in another lane.
#[test]
fn a_disposition_entry_without_its_fields_is_refused() {
    let without_failure = || {
        let entries = [DEPARTED, FOLLOWER].map(|entry| {
            let mut entry = value(entry);
            object(&mut entry).remove("failure");
            entry
        });
        list(&entries)
    };
    let needs = |entries: Value| {
        let mut unrun = Object::new();
        unrun.insert("needs", entries);
        Value::Object(unrun)
    };
    let plants: Vec<(&str, &str, Value)> = vec![
        (
            "unrun without needs or a reason",
            "unrun",
            value(r#"{"needs": []}"#),
        ),
        (
            "unrun without needs beside a blank reason",
            "unrun",
            value(r#"{"needs": [], "reason": " "}"#),
        ),
        ("unrun that is a list", "unrun", list(&[value(DEPARTED)])),
        ("unrun that is a string", "unrun", string("planted")),
        (
            "a needs entry without a failure",
            "unrun",
            needs(without_failure()),
        ),
        (
            "a needs entry with a blank failure",
            "unrun",
            needs(list(&[with(DEPARTED, &[("failure", string(" "))])])),
        ),
        (
            "a needs entry with a numeric failure",
            "unrun",
            needs(list(&[with(DEPARTED, &[("failure", value("7"))])])),
        ),
        (
            "a needs entry with no tests",
            "unrun",
            needs(list(&[with(DEPARTED, &[("tests", list(&[]))])])),
        ),
        ("an empty kill", "kill", list(&[])),
        (
            "a kill that is an object",
            "kill",
            needs(list(&[value(DEPARTED)])),
        ),
        ("a kill entry without a failure", "kill", without_failure()),
        (
            "two kill entries in one lane",
            "kill",
            list(&[value(DEPARTED), value(DEPARTED)]),
        ),
        (
            "a survives that is a list",
            "survives",
            list(&[with(
                r#"{"lane": "loom"}"#,
                &[("tests", get(&value(DEPARTED), "tests").clone())],
            )]),
        ),
        (
            "a passed entry without tests",
            "survives",
            value(r#"{"reason": "planted", "passed": [{"lane": "loom"}]}"#),
        ),
        (
            "a passed entry in another lane",
            "survives",
            value(r#"{"reason": "planted", "passed": [{"lane": "rc11", "tests": ["F0"]}]}"#),
        ),
    ];
    for (label, kind, planted) in plants {
        let report = report_of(with_catalog(|catalog| {
            decided(catalog, "fill-observe", kind, planted.clone());
            if kind == "unrun" {
                row(catalog, "fill-observe").remove("revision");
            }
        }));
        assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
        refused(
            with_catalog(|catalog| {
                decided(catalog, "fill-observe", kind, planted);
                if kind == "unrun" {
                    row(catalog, "fill-observe").remove("revision");
                }
            }),
            "disposition",
            &format!("fill-observe: its {kind} disposition lacks a field"),
        );
    }
}

/// A kill or a survivor whose revision is absent, a number, has a trailing newline or is upper case is
/// refused.
#[test]
fn a_decided_row_without_a_revision_is_refused() {
    let survives = format!(
        r#"{{"reason": "planted", "passed": [{{"lane": "loom", "tests": {}}}]}}"#,
        json::dump(get(&value(DEPARTED), "tests"))
    );
    let decisions = [
        ("kill", list(&[value(DEPARTED), value(FOLLOWER)])),
        ("survives", value(&survives)),
    ];
    let revisions = [
        ("none", None),
        ("a number", Some(value(&"1".repeat(40)))),
        ("a trailing newline", Some(string(&format!("{REVISION}\n")))),
        ("upper case", Some(string(&"A".repeat(40)))),
        ("39 digits", Some(string(&"0".repeat(39)))),
        ("41 digits", Some(string(&"0".repeat(41)))),
        ("a letter past f", Some(string(&"g".repeat(40)))),
    ];
    for (kind, planted) in &decisions {
        for (label, revision) in &revisions {
            let plants = with_catalog(|catalog| {
                decided(catalog, "fill-observe", kind, planted.clone());
                match revision {
                    None => {
                        row(catalog, "fill-observe").remove("revision");
                    }
                    Some(revision) => {
                        row(catalog, "fill-observe").insert("revision", revision.clone());
                    }
                }
            });
            let report = report_of(plants.clone());
            assert_eq!(
                *member(&report, "credited"),
                Value::Bool(false),
                "{kind}: {label}"
            );
            refused(
                plants,
                "revision",
                &format!("fill-observe: its {kind} disposition records no revision"),
            );
        }
    }
}

const RELEASE_STORE: &str = "    record.store(INACTIVE, Ordering::Release);\n}";

/// A find moved into another item is refused by the row's scope, and a binding of null beside it is a
/// malformed row.
#[test]
fn a_find_moved_out_of_its_enclosing_item_is_refused() {
    let moved = source(
        GRACE,
        RELEASE_STORE,
        "    clear(record);\n}\n\nfn clear<W: EraWord>(record: &W) {\n    record.store(INACTIVE, Ordering::Release);\n}",
    );
    refused(
        vec![(GRACE, text(moved.clone()))],
        "enclosing item",
        "grace-unpin: fn unpin resolves to 1 bodies, or its body lacks the find",
    );
    let mut plants = with_catalog(|catalog| {
        row(catalog, "grace-unpin").insert("binding", Value::Null);
    });
    plants.push((GRACE, text(moved)));
    refused(
        plants,
        "row",
        "row 'grace-unpin' is malformed: a field has the wrong type",
    );
}

/// A find moved into an `fn` or an `impl` nested in the row's enclosing item is refused, a nested `fn`
/// with a `;` in its parameters included, and so is a find that holds the nested item's header.
#[test]
fn a_find_moved_into_a_nested_item_is_refused() {
    let live = "    record.store(INACTIVE, Ordering::Relaxed);\n}";
    let nested_fn = "    fn clear<W: EraWord>(record: &W) {\n        record.store(INACTIVE, Ordering::Release);\n    }\n";
    let plants = [
        ("a nested fn", nested_fn),
        (
            "a nested fn with an array parameter",
            "    fn clear<W: EraWord>(record: &W, _: [u8; 0]) {\n        record.store(INACTIVE, Ordering::Release);\n    }\n",
        ),
        (
            "a nested impl",
            "    impl Spare {\n        const _: () = record.store(INACTIVE, Ordering::Release);\n    }\n",
        ),
    ];
    for (label, helper) in plants {
        let nested = source(GRACE, RELEASE_STORE, &format!("{helper}{live}"));
        let report = report_of(vec![(GRACE, text(nested.clone()))]);
        assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
        refused(
            vec![(GRACE, text(nested))],
            "enclosing item",
            "grace-unpin: its site lies in an item nested in fn unpin",
        );
    }
    let nested = source(GRACE, RELEASE_STORE, &format!("{nested_fn}{live}"));
    let find = "(record: &W) {\n        record.store(INACTIVE, Ordering::Release);";
    let mut plants = with_catalog(|catalog| {
        let planted = row(catalog, "grace-unpin");
        planted.insert("find", string(find));
        planted.insert("replace", string(&find.replace("Release", "Relaxed")));
    });
    plants.push((GRACE, text(nested)));
    refused(
        plants,
        "enclosing item",
        "grace-unpin: its site lies in an item nested in fn unpin",
    );
}

#[test]
fn a_scope_that_resolves_to_two_bodies_is_refused() {
    refused(
        with_source(
            GRACE,
            RELEASE_STORE,
            "    record.store(INACTIVE, Ordering::Release);\n}\n\nmod spare {\n    fn unpin() {}\n}",
        ),
        "enclosing item",
        "grace-unpin: fn unpin resolves to 2 bodies",
    );
}

#[test]
fn a_row_without_an_enclosing_item_is_refused() {
    refused(
        with_catalog(|catalog| {
            row(catalog, "grace-visit").remove("scope");
        }),
        "enclosing item",
        "grace-visit: it names no enclosing item",
    );
    refused(
        with_catalog(|catalog| {
            row(catalog, "grace-visit").insert("scope", list(&[]));
        }),
        "enclosing item",
        "grace-visit: it names no enclosing item",
    );
}

#[test]
fn a_repeated_row_id_is_refused() {
    refused(
        with_catalog(|catalog| {
            let repeated = Value::Object(row(catalog, "grace-visit").clone());
            rows(catalog).push(repeated);
        }),
        "row",
        "row 'grace-visit' is malformed: its id is repeated",
    );
}

type RowPlant = Box<dyn Fn(&mut Object)>;

/// Each malformed row is refused by the `repr` of its id and by its defect.
#[test]
fn a_malformed_row_is_refused_by_name() {
    let set = |key: &'static str, field: &'static str| {
        move |entry: &mut Object| entry.insert(key, value(field))
    };
    let drop = |key: &'static str| {
        move |entry: &mut Object| {
            entry.remove(key);
        }
    };
    let plants: Vec<(&str, RowPlant, &str, &str)> = vec![
        (
            "an unlisted path",
            Box::new(set("path", "\"crates/kestrike/src/storage/slot.rs\"")),
            "'grace-visit'",
            "it names an unlisted path",
        ),
        (
            "an unhashable path",
            Box::new(set("path", "[1]")),
            "'grace-visit'",
            "a field has the wrong type",
        ),
        (
            "an unhashable binding",
            Box::new(set("binding", "[\"x\"]")),
            "'grace-visit'",
            "a field has the wrong type",
        ),
        (
            "a scope of numbers",
            Box::new(set("scope", "[1]")),
            "'grace-visit'",
            "a field has the wrong type",
        ),
        (
            "a scope that is a string",
            Box::new(set("scope", "\"fn unpin\"")),
            "'grace-visit'",
            "a field has the wrong type",
        ),
        (
            "an unknown op",
            Box::new(set("op", "\"swap\"")),
            "'grace-visit'",
            "its op 'swap'",
        ),
        (
            "a numeric id",
            Box::new(set("id", "7")),
            "7",
            "a field has the wrong type",
        ),
        (
            "a numeric find",
            Box::new(set("find", "7")),
            "'grace-visit'",
            "a field has the wrong type",
        ),
        (
            "a blank id",
            Box::new(set("id", "\"\"")),
            "''",
            "its id is blank",
        ),
        (
            "a whitespace id",
            Box::new(set("id", "\"  \"")),
            "'  '",
            "its id is blank",
        ),
        ("no id", Box::new(drop("id")), "None", "it lacks ['id']"),
        (
            "no find",
            Box::new(drop("find")),
            "'grace-visit'",
            "it lacks ['find']",
        ),
        (
            "no replace",
            Box::new(drop("replace")),
            "'grace-visit'",
            "it lacks ['replace']",
        ),
        (
            "no path",
            Box::new(drop("path")),
            "'grace-visit'",
            "it lacks ['path']",
        ),
        (
            "no op",
            Box::new(drop("op")),
            "'grace-visit'",
            "it lacks ['op']",
        ),
        (
            "a numeric op",
            Box::new(set("op", "1")),
            "'grace-visit'",
            "a field has the wrong type",
        ),
        (
            "a numeric replace",
            Box::new(set("replace", "1")),
            "'grace-visit'",
            "a field has the wrong type",
        ),
        (
            "a binding beside a scope",
            Box::new(set("binding", "\"join-detach-release\"")),
            "'grace-visit'",
            "it holds both a binding and a scope",
        ),
        (
            "a misspelled key",
            Box::new(set("twins", "[]")),
            "'grace-visit'",
            "it holds the unknown keys ['twins']",
        ),
    ];
    for (label, plant, shown, defect) in plants {
        let plants = with_catalog(|catalog| plant(row(catalog, "grace-visit")));
        let report = report_of(plants.clone());
        assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
        refused(
            plants,
            "row",
            &format!("row {shown} is malformed: {defect}"),
        );
    }
    refused(
        with_catalog(|catalog| rows(catalog).push(string("grace-visit"))),
        "row",
        "row 'grace-visit' is malformed: it is no object",
    );
    sentence(
        with_catalog(|catalog| {
            row(catalog, "grace-visit").insert("op", string("swap"));
        }),
        "row",
        "row 'grace-visit' is malformed: its op 'swap' is none of ['load', 'store', 'rmw', 'fence']",
    );
}

fn error_of(report: &Value) -> String {
    match member(report, "error") {
        Value::String(error) => error.to_string(),
        error => panic!("the error is a string: {error:?}"),
    }
}

/// A walk of the kernel package that fails with the reason `planted` and the error kind `kind`.
fn failing(kind: io::ErrorKind) -> impl Fn(&Path) -> io::Result<Vec<PathBuf>> {
    move |_: &Path| Err(io::Error::new(kind, "planted"))
}

/// A catalog that is truncated, holds files or rows of another shape, repeats a file or a key, or
/// nests past the reader's bound exits 2 as unreadable, as does a declaration nested past it; a walk of
/// the kernel package that fails, whatever its error's kind, exits 2 with its reason alone.
#[test]
fn an_unreadable_catalog_exits_2() {
    let files = get(&catalog(), "files").clone();
    let listed = items(&files).to_vec();
    let document = |files: Value, rows: &str| {
        let mut planted = Object::new();
        planted.insert("files", files);
        planted.insert("rows", value(rows));
        json::dump(&Value::Object(planted))
    };
    let mut keyed = Object::new();
    for file in &listed {
        let Value::String(file) = file else {
            panic!("a file is a string");
        };
        keyed.insert(file.clone(), Value::Bool(true));
    }
    let repeated = {
        let mut planted = listed.clone();
        planted.push(listed[0].clone());
        planted
    };
    let numeric = {
        let mut planted = listed.clone();
        planted.push(value("7"));
        planted
    };
    let texts = [
        ("truncated", "{".to_owned()),
        ("files that are a number", document(value("5"), "[]")),
        (
            "files that are an object",
            document(Value::Object(keyed), "[]"),
        ),
        ("a repeated file", document(Value::Array(repeated), "[]")),
        ("a numeric file", document(Value::Array(numeric), "[]")),
        ("rows that are an object", document(files.clone(), "{}")),
        (
            "a repeated key",
            json::dump(&catalog()).replacen("\"find\":", "\"find\":\"stale\",\"find\":", 1),
        ),
        (
            "deep nesting",
            format!("{}{}", "[".repeat(100_000), "]".repeat(100_000)),
        ),
    ];
    for (label, planted) in texts {
        let (report, code) = checked(vec![(CATALOG, text(planted))]);
        assert_eq!(code, 2, "{label}: {report:?}");
        assert!(
            error_of(&report).contains("unreadable catalog"),
            "{label}: {report:?}"
        );
    }
    let mut keys = Vec::new();
    for (key, _) in object(&mut items(get(&catalog(), "rows"))[0].clone()).iter() {
        keys.push(Value::String(key.clone()));
        if *key == "find" {
            keys.push(Value::String(key.clone()));
        }
    }
    let repeated = json::dump(&catalog()).replacen("\"find\":", "\"find\":\"stale\",\"find\":", 1);
    assert_eq!(
        error_of(&checked(vec![(CATALOG, text(repeated))]).0),
        format!(
            "unreadable catalog or declaration: an object repeats a key among {}",
            repr(&Value::Array(keys))
        )
    );
    assert_eq!(
        error_of(&checked(vec![(CATALOG, text(document(value("5"), "[]")))]).0),
        "unreadable catalog or declaration: files is no list of distinct paths, or rows is no list"
    );
    let mut no_rows = Object::new();
    no_rows.insert("files", files.clone());
    for (label, plant) in [
        ("a list", text("[]".to_owned())),
        ("no rows", text(json::dump(&Value::Object(no_rows)))),
        ("a refused read", Plant::Refused),
    ] {
        let (report, code) = checked(vec![(CATALOG, plant)]);
        assert_eq!(code, 2, "{label}: {report:?}");
        assert!(
            error_of(&report).starts_with("unreadable catalog or declaration: "),
            "{label}: {report:?}"
        );
    }
    let (report, code) = checked(vec![(super::GENMC, text("[".repeat(100_000)))]);
    assert_eq!(code, 2, "{report:?}");
    assert!(
        error_of(&report).starts_with("unreadable catalog or declaration: "),
        "{report:?}"
    );
    for kind in [
        io::ErrorKind::Other,
        io::ErrorKind::NotFound,
        io::ErrorKind::InvalidData,
    ] {
        let walk = failing(kind);
        let (report, code) = check(&reader(vec![]), &top(), &top(), EXTERNAL, &walk);
        let mut expected = Object::new();
        expected.insert("error", string("unreadable kernel package: planted"));
        assert_eq!((code, report), (2, Value::Object(expected)), "{kind:?}");
    }
}

/// A source of the kernel package that links to itself makes the package unreadable: exit 2, never an
/// accepted include.
#[test]
fn a_symlink_loop_in_the_kernel_package_is_never_accepted() {
    let scratch = planted_package(&[], Some("#[path = \"loop.rs\"]\nmod looped;\n"));
    std::os::unix::fs::symlink("loop.rs", package_of(&scratch).join("src/loop.rs"))
        .expect("the link is made");
    let (report, code) = checked_at(&root_of(&scratch), vec![], EXTERNAL);
    assert_eq!(code, 2, "{report:?}");
    assert!(
        error_of(&report).starts_with("unreadable kernel package: "),
        "{report:?}"
    );
}

/// Every GenMC failure of a row's entries is a `check!` message of its case family's one kernel file,
/// whose text the lookup gives; a family's kernel file stands at any depth of the package, and a family
/// with two has none.
#[test]
fn each_cataloged_genmc_failure_lies_in_its_case_family_kernel() {
    let package = top().join(PACKAGE);
    let kernels = kernel_texts(&package).expect("the kernel package reads");
    let catalog = catalog();
    let mut checked_cases = 0;
    for entry in items(get(&catalog, "rows")) {
        let Value::Object(entry) = entry else {
            panic!("a row is an object");
        };
        let (entries, wanted) =
            row_entries(entry).expect("a committed row's disposition is well formed");
        assert_eq!(wanted, None, "a committed row is unrun");
        for entry in entries {
            let failure = match entry.get("failure") {
                Some(Value::String(failure)) if !failure.is_empty() => failure.to_string(),
                _ => continue,
            };
            if entry.get("lane") != Some(&string("genmc")) {
                continue;
            }
            for case in items(entry.get("tests").expect("an entry lists tests")) {
                let Value::String(case) = case else {
                    panic!("a test is a string");
                };
                let (path, text) =
                    family_kernel(case, &kernels).unwrap_or_else(|| panic!("{case} has a kernel"));
                assert_eq!(
                    fs::read_to_string(package.join(path)).expect("the kernel reads"),
                    text
                );
                assert!(text.contains(&format!("c\"{failure}\"")), "{case}");
                let messages = c_literals(text);
                assert_eq!(
                    messages
                        .iter()
                        .filter(|message| **message == failure)
                        .count(),
                    1,
                    "{case}"
                );
                checked_cases += 1;
            }
        }
    }
    let nested = BTreeMap::from([("src/nested/grace_kernel.rs".to_owned(), "t".to_owned())]);
    assert_eq!(
        family_kernel(&Text::from("grace1-seq"), &nested),
        Some(("src/nested/grace_kernel.rs", "t"))
    );
    let both = BTreeMap::from([
        ("src/grace_kernel.rs".to_owned(), "t".to_owned()),
        ("src/nested/grace_kernel.rs".to_owned(), "u".to_owned()),
    ]);
    assert_eq!(family_kernel(&Text::from("grace1-seq"), &both), None);
    assert!(checked_cases > 0);
}

/// The GenMC declaration with the production entry of `join-detach-release` set by `change`.
fn detach_production(change: impl FnOnce(&mut Object)) -> String {
    let mut declared = value(&committed(super::GENMC));
    let bindings = match object(&mut declared).get_mut("bindings") {
        Some(Value::Array(bindings)) => bindings,
        _ => panic!("the declaration lists bindings"),
    };
    let entry = bindings
        .iter_mut()
        .map(object)
        .find(|entry| entry.get("id") == Some(&string("join-detach-release")))
        .expect("the declaration binds join-detach-release");
    change(entry);
    json::dump(&declared)
}

/// A bound row whose binding's production is no object, or whose binding scope holds a header that is
/// no string, is a malformed row; that refusal ends the row's checks, so its planted second disposition
/// draws no `disposition` refusal.
#[test]
fn a_binding_of_another_shape_makes_its_row_malformed() {
    let production = |planted: &'static str| {
        move |entry: &mut Object| match entry.get_mut("production") {
            Some(Value::Object(production)) => {
                production.insert("scope", value(planted));
            }
            _ => panic!("the binding has a production entry"),
        }
    };
    let plants: [(&str, String, &str); 3] = [
        (
            "a production that is a number",
            detach_production(|entry| entry.insert("production", value("5"))),
            "its binding's production is no object",
        ),
        (
            "a header that is a number",
            detach_production(production("[1]")),
            "a header of its binding's scope is no string",
        ),
        (
            "a number after a header that resolves to no body",
            detach_production(production(r#"["fn nowhere", 1]"#)),
            "a header of its binding's scope is no string",
        ),
    ];
    for (label, declared, reason) in plants {
        let mut plants = with_catalog(|catalog| {
            row(catalog, "row-detach")
                .insert("survives", value(r#"{"reason": "planted", "passed": []}"#));
        });
        plants.push((super::GENMC, text(declared)));
        let (report, code) = checked(plants);
        assert_eq!(code, 1, "{label}: {report:?}");
        assert_eq!(*member(&report, "credited"), Value::Bool(false), "{label}");
        assert_eq!(
            messages_of(&report, "row"),
            [format!("row 'row-detach' is malformed: {reason}")],
            "{label}"
        );
        let row_detach: Vec<&Value> = items(member(&report, "refusals"))
            .iter()
            .filter(|entry| match get(entry, "message") {
                Value::String(message) => message.to_string().contains("row-detach"),
                _ => false,
            })
            .collect();
        assert_eq!(row_detach.len(), 1, "{label}: {report:?}");
    }
}

/// `row_entries` gives a row's entries with the result each run must give, `killed`, `survived` or none,
/// and refuses a row with a malformed disposition or none by the row's id.
#[test]
fn row_entries_gives_each_disposition_its_entries_and_its_result() {
    let mut planted = catalog();
    let entry = |planted: &mut Value| Value::Object(row(planted, "fill-observe").clone());
    let read = |row: &Value| match row {
        Value::Object(row) => row_entries(row).map(|(entries, wanted)| {
            (
                entries
                    .into_iter()
                    .map(|entry| Value::Object(entry.clone()))
                    .collect::<Vec<_>>(),
                wanted,
            )
        }),
        _ => panic!("a row is an object"),
    };
    decided(
        &mut planted,
        "fill-observe",
        "kill",
        list(&[value(DEPARTED), value(FOLLOWER)]),
    );
    assert_eq!(
        read(&entry(&mut planted)),
        Ok((vec![value(DEPARTED), value(FOLLOWER)], Some("killed")))
    );
    let passed = with(
        r#"{"lane": "genmc"}"#,
        &[("tests", names(&["join-production"]))],
    );
    decided(
        &mut planted,
        "fill-observe",
        "survives",
        Value::Object({
            let mut survives = Object::new();
            survives.insert("reason", string("planted"));
            survives.insert("passed", list(&[passed.clone()]));
            survives
        }),
    );
    assert_eq!(
        read(&entry(&mut planted)),
        Ok((vec![passed], Some("survived")))
    );
    needing(&mut planted, "fill-observe", list(&[value(FREED)]));
    assert_eq!(read(&entry(&mut planted)), Ok((vec![value(FREED)], None)));
    decided(&mut planted, "fill-observe", "kill", list(&[]));
    assert_eq!(
        read(&entry(&mut planted)),
        Err(Text::from(
            "fill-observe: its kill disposition is malformed"
        ))
    );
    row(&mut planted, "fill-observe").remove("kill");
    assert_eq!(
        read(&entry(&mut planted)),
        Err(Text::from("fill-observe: it holds no disposition"))
    );
}

/// A site after an `fn` nested in its enclosing item lies at the item's own level, also where the
/// nested body's `}` directly precedes the site in the normalized text.
#[test]
fn a_site_after_a_nested_item_lies_in_its_enclosing_item() {
    let call = "std::sync::atomic::fence(Ordering::SeqCst);";
    let planted = source(
        FILL,
        ANCHOR,
        &format!("fn extra() {{\n    fn inner() {{}}\n    {call}\n}}\n\n{ANCHOR}"),
    );
    let mut plants = with_catalog(|catalog| {
        rows(catalog).push(planted_row(&[
            ("find", string(call)),
            ("replace", string("")),
        ]));
    });
    plants.push((FILL, text(planted)));
    accepted(plants);
}

/// A word that starts where a path attribute's match ends lies outside it and is refused on its own.
#[test]
fn a_word_after_a_path_attribute_is_its_own_refusal() {
    let loaded = "#[cfg_attr(x, path =include)]\nmod extra;\n\n";
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
                "{FILL}:{line}: #[cfg_attr(x, path = can load source that the catalog does not scope"
            ),
            format!("{FILL}:{line}: include can load source that the catalog does not scope"),
            format!(
                "{FILL}:{}: mod can load source that the catalog does not scope",
                line + 1
            ),
        ]
    );
}
