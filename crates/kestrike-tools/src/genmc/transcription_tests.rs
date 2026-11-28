use std::fs;
use std::io;

use super::{calls, package_path, transcription_drift};
use crate::genmc::case::tests::root;
use crate::genmc::refusal::Error;
use crate::json::parse;
use crate::paths::tests::Scratch;

#[test]
fn a_kernel_path_joins_the_package_as_a_path_join_does() {
    assert_eq!(package_path("", "src/k.rs"), "src/k.rs");
    assert_eq!(package_path("/", "src/k.rs"), "/src/k.rs");
    assert_eq!(
        package_path("verification/genmc/packages/kernels", "src/k.rs"),
        "verification/genmc/packages/kernels/src/k.rs"
    );
}

#[test]
fn an_empty_package_reads_kernel_files_under_the_root_and_a_root_package_reads_from_slash() {
    let scratch = Scratch::new("transcription-package");
    fs::create_dir_all(scratch.0.join("src")).expect("the directory is made");
    fs::copy(
        root().join("verification/genmc/packages/kernels/src/grace_kernel.rs"),
        scratch.0.join("src/grace_kernel.rs"),
    )
    .expect("the kernel copies");
    let declared = |package: &str| {
        parse(&format!(
            r#"{{"package": "{package}", "transcribed": [], "bindings": [],
                "strengths": [{{"file": "src/grace_kernel.rs", "impl": "impl ModelStrength for Sequential"}}]}}"#
        ))
        .expect("JSON")
    };
    let unbound: Vec<String> = ["BOUND_LOAD", "CLAIM_LOAD", "CLAIM_RAISE", "COMMIT", "OBSERVE"]
        .iter()
        .map(|constant| {
            format!(
                "src/grace_kernel.rs transcribes {constant} in its strength and no binding entry binds it"
            )
        })
        .collect();
    assert_eq!(
        transcription_drift(&declared(""), &scratch.0).expect("the kernel reads"),
        unbound
    );
    match transcription_drift(&declared("/"), &scratch.0) {
        Err(Error::Os(error)) => assert_eq!(error.kind(), io::ErrorKind::NotFound),
        other => panic!("the file /src/grace_kernel.rs is read, not {other:?}"),
    }
}

const PRODUCTION: &str = "use core::sync::atomic::compiler_fence as fence;

fn nested_generic() {
    cell.load::<A<B>>(Ordering::SeqCst);
    cell.load(Ordering::SeqCst);
}

fn named_ordering() {
    word.compare_exchange(old, new, OTHER, Ordering::Acquire);
}

fn two_loads() {
    cell.load(Ordering::SeqCst);
    cell.load(Ordering::Relaxed);
}

fn qualified() {
    other::claim(record);
}

fn aliased() {
    fence(Ordering::Release);
}

fn outer() {
    fn inner() {
        cell.load(Ordering::SeqCst);
    }
}

fn own_anchor() {
    cell.store(v, Ordering::Release);
}

fn weakened() {
    cell.load(Ordering::SeqCst);
}
";

const STRENGTH: &str = "struct Sequential;

impl ModelStrength for Sequential {
    const LOAD: Ordering = Ordering::Relaxed;
    const LOAD: Ordering = Ordering::SeqCst;
}

fn read() {
    CELL.load(S::LOAD);
}
";

const STRENGTHS: &str = r#"[{"file": "src/k.rs", "impl": "impl ModelStrength for Sequential"}]"#;

/// A scratch checkout with one production file `src/p.rs` and one kernel file `kernels/src/k.rs`.
fn planted() -> Scratch {
    let scratch = Scratch::new("transcription-rules");
    fs::create_dir_all(scratch.0.join("src")).expect("the directory is made");
    fs::create_dir_all(scratch.0.join("kernels/src")).expect("the directory is made");
    fs::write(scratch.0.join("src/p.rs"), PRODUCTION).expect("the source writes");
    fs::write(scratch.0.join("kernels/src/k.rs"), STRENGTH).expect("the kernel writes");
    scratch
}

/// The drift of a declaration that holds `binding` alone, with the production file listed as
/// `src/p.rs/`, and the strength of `kernels/src/k.rs` when `strengths` holds.
fn drift_of(root: &std::path::Path, binding: &str, strengths: bool) -> Vec<String> {
    let strengths = if strengths { STRENGTHS } else { "[]" };
    let declared = parse(&format!(
        r#"{{"package": "kernels", "transcribed": ["src/p.rs/"], "strengths": {strengths},
            "bindings": [{binding}]}}"#
    ))
    .expect("JSON");
    transcription_drift(&declared, root).expect("the sources read")
}

fn production(id: &str, kind: &str, operands: &str, orderings: &str, site: &str) -> String {
    format!(
        r#"{{"id": "{id}", "kind": "{kind}", "operands": {operands}, "orderings": {orderings},
            "production": {{"file": "src/p.rs/", {site}}}}}"#
    )
}

/// Each binding below resolves against the planted sources with no drift: the check reads callees,
/// operands and anchors as text, so each row stands where the source differs from the binding in a way
/// that text does not show.
#[test]
fn the_text_rules_accept_what_the_spelling_of_a_call_does_not_show() {
    let scratch = planted();
    #[rustfmt::skip]
    let rows = [
        ("a call with a nested generic argument is no occurrence",
         production("nested-generic", "load", "[]", r#"["SeqCst"]"#, r#""scope": ["fn nested_generic"], "call": "cell.load""#)),
        ("a named ordering in an ordering slot is an operand",
         production("named-ordering", "cas", r#"["old", "new", "OTHER"]"#, r#"["Acquire"]"#,
                    r#""scope": ["fn named_ordering"], "call": "word.compare_exchange""#)),
        ("the first operand-matching occurrence gives the orderings",
         production("first-match", "load", "[]", r#"["SeqCst"]"#,
                    r#""scope": ["fn two_loads"], "call": "cell.load", "among": 2, "matching": 2"#)),
        ("a callee matches as the last segment of another path",
         production("qualified", "call", r#"["record"]"#, "[]", r#""scope": ["fn qualified"], "call": "claim""#)),
        ("a fence is its callee's name whatever the import binds",
         production("aliased", "fence", "[]", r#"["Release"]"#, r#""scope": ["fn aliased"], "call": "fence""#)),
        ("a call inside a nested fn counts in the outer scope",
         production("nested-fn", "load", "[]", r#"["SeqCst"]"#, r#""scope": ["fn outer"], "call": "cell.load""#)),
        ("an after anchor at the operation's own offset holds",
         production("own-anchor", "store", r#"["v"]"#, r#"["Release"]"#,
                    r#""scope": ["fn own_anchor"], "call": "cell.store", "after": ["own-anchor"]"#)),
        ("a binding with neither side checks nothing",
         r#"{"id": "no-side", "kind": "load", "operands": [], "orderings": ["SeqCst"]}"#.to_owned()),
    ];
    for (rule, binding) in rows {
        assert_eq!(
            drift_of(&scratch.0, &binding, false),
            Vec::<String>::new(),
            "{rule}"
        );
    }
}

/// A strength that defines one constant twice resolves it by its last definition.
#[test]
fn a_strength_constant_defined_twice_takes_its_last_definition() {
    let scratch = planted();
    let binding = r#"{"id": "strength", "kind": "load", "operands": [], "orderings": ["SeqCst"],
        "kernel": {"file": "src/k.rs", "scope": ["fn read"], "call": "CELL.load"}}"#;
    assert_eq!(drift_of(&scratch.0, binding, true), Vec::<String>::new());
    fs::write(
        scratch.0.join("kernels/src/k.rs"),
        STRENGTH
            .replace("Relaxed", "Other")
            .replace("SeqCst", "Relaxed")
            .replace("Other", "SeqCst"),
    )
    .expect("the kernel writes");
    assert_eq!(
        drift_of(&scratch.0, binding, true),
        ["strength: the kernel orderings are ['Relaxed'], bound ['SeqCst']"]
    );
}

/// The sources come from the root the caller names, and a path with a trailing `/` reads its file:
/// weakening the planted source alone drifts the binding.
#[test]
fn the_sources_are_read_under_the_given_root() {
    let scratch = planted();
    let binding = production(
        "weakened",
        "load",
        "[]",
        r#"["SeqCst"]"#,
        r#""scope": ["fn weakened"], "call": "cell.load""#,
    );
    assert_eq!(drift_of(&scratch.0, &binding, false), Vec::<String>::new());
    fs::write(
        scratch.0.join("src/p.rs"),
        PRODUCTION.replace(
            "fn weakened() {\n    cell.load(Ordering::SeqCst)",
            "fn weakened() {\n    cell.load(Ordering::Acquire)",
        ),
    )
    .expect("the source writes");
    assert_eq!(
        drift_of(&scratch.0, &binding, false),
        ["weakened: the production orderings are ['Acquire'], bound ['SeqCst']"]
    );
}

/// A callee is found as literal text at each start that no word character, `.` or `$` precedes, with an
/// optional `::<...>` before its `(`; each offset is the byte offset of that `(`. A rejected start moves
/// one code point on, so an overlapping occurrence is still found, and a callee of any length is text.
#[test]
fn a_callee_is_found_as_literal_text_at_its_boundaries() {
    #[rustfmt::skip]
    let rows: [(&str, &str, &[usize]); 6] = [
        ("f(a);g.f(b);$f(c);\u{e9}f(d);f::<A,B>(e);f::<A(", "f", &[1, 33]),
        ("f::f::f(x)", "f::f", &[7]),
        ("a(b)(c)", "", &[4]),
        ("xf(1) f (2) f(3)", "f", &[13]),
        ("\u{e9}(f(", "f", &[4]),
        ("f::<x>y(", "f", &[]),
    ];
    for (scope, call, wanted) in rows {
        assert_eq!(calls(scope, call), wanted, "{scope} {call}");
    }
    assert_eq!(calls("call(a)", &"x".repeat(200_000)), Vec::<usize>::new());
    let scratch = planted();
    let long = "x".repeat(200_000);
    let binding = production(
        "long",
        "call",
        "[]",
        "[]",
        &format!(r#""scope": ["fn weakened"], "call": "{long}""#),
    );
    assert_eq!(
        drift_of(&scratch.0, &binding, false),
        [format!(
            "long: the production {long} appears 0 times in fn weakened"
        )]
    );
}
