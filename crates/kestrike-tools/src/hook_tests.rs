use crate::hook::guard::CHAOS_RECORD;
use crate::hook::members::{Members, link_inputs, verus_sources};
use crate::hook::table::{Check, Held, ORDER, checks_for};
use crate::hook::{account_number, record_values, shown};
use crate::text::Text;

/// The run order holds the ten checks of the hook, each at the index of its `Check`, with the argument
/// vectors the hook runs.
#[test]
fn the_rows_hold_the_hooks_checks_in_run_order() {
    let argvs: Vec<String> = ORDER.iter().map(|row| row.argv.join(" ")).collect();
    assert_eq!(
        argvs,
        [
            "python3 scripts/test-select-tests.py",
            "python3 scripts/verify-receipts.py admit",
            "python3 scripts/judge-verus.py reconcile",
            "python3 scripts/model-links.py check",
            "python3 scripts/test-model-links.py",
            "python3 -I chaos/tools/validate_contract.py chaos/ledger.json --root . --project chaos/project.yaml \
             --receipts chaos/receipts --check-claim chaos/READINESS.md",
            "python3 -I scripts/chaos-receipt-replay.py",
            "python3 -I chaos/tests/test_judges.py",
            "python3 -I scripts/test-gameday-judge.py",
            "python3 -I scripts/test-host-stop-controller.py",
        ]
    );
    for (at, row) in ORDER.iter().enumerate() {
        assert_eq!(row.check as usize, at);
    }
}

/// A judge script or a checker's `expected.json` selects the test selection: a name part is word
/// characters, outside ASCII too, or `-`, and the path may end in one line feed; the values are the
/// interpreter's for the hook's pattern.
#[test]
fn a_judge_script_change_runs_selection_checks() {
    let none = Members::default();
    let selects = |path: &str| {
        checks_for(&[path], Some(&none), Some(&none), false, Held::default())
            .contains(&Check::SelectTests)
    };
    for (path, expected) in [
        ("scripts/judge-kani.py", true),
        ("scripts/judge-kani.py\n", true),
        ("scripts/judge-kani.py\n\n", false),
        ("scripts/judge-caf\u{e9}.py", true),
        ("scripts/judge-\u{663}.py", true),
        ("scripts/judge-.py", false),
        ("scripts/judge--.py", true),
        ("verification/a-b_c/expected.json", true),
        ("verification/a/b/expected.json", false),
        ("scripts/judge-a.b.py", false),
        ("scripts/judge-a b.py", false),
        ("xscripts/judge-a.py", false),
    ] {
        assert_eq!(selects(path), expected, "{path:?}");
    }
}

/// A record path matches whole, with `.` and `[^/]` taking a line feed; the values are the interpreter's
/// for the hook's pattern.
#[test]
fn a_chaos_record_with_an_account_number_fails_the_push_by_its_path() {
    for (path, expected) in [
        ("chaos/receipts/a.json", true),
        ("chaos/receipts/a\nb.json", true),
        ("chaos/receipts/.json", false),
        ("chaos/receipts/x/y.json", true),
        ("chaos/runs/r/run.json", true),
        ("chaos/runs/r/s/run.json", false),
        ("chaos/runs/a\nb/run.json", true),
        ("chaos/tests/runs/r/run.json", true),
        ("chaos/tests/receipts/x.json", true),
        ("chaos/runs//run.json", false),
        ("chaos/receipts/a.json\n", false),
        ("chaos/runs/r/history.jsonl", false),
    ] {
        assert_eq!(CHAOS_RECORD.is_match(path), expected, "{path:?}");
    }
}

/// A failure names a printable path as it is and quotes any other; the values are the interpreter's.
#[test]
fn a_record_path_with_a_control_character_is_quoted() {
    for (path, expected) in [
        ("a b", "a b"),
        ("a\tb", "'a\\tb'"),
        ("caf\u{e9}", "caf\u{e9}"),
        ("a\u{a0}b", "'a\\xa0b'"),
        ("\u{200b}", "'\\u200b'"),
        ("a\u{7f}", "'a\\x7f'"),
        ("", ""),
    ] {
        assert_eq!(shown(path), expected, "{path:?}");
    }
}

fn members(texts: &[&str]) -> Members {
    texts.iter().collect()
}

/// The inventory names its `sources` keys, the items of a `sources` list and the code points of a
/// `sources` string; a `sources` of another shape, an inventory that is no object and a text that is no
/// JSON or no UTF-8 read as `None`. The values are the interpreter's for the hook's read.
#[test]
fn a_malformed_verus_inventory_reads_as_none_for_each_shape() {
    for (text, expected) in [
        ("{}", Some(members(&[]))),
        (r#"{"sources": {"a": 1}}"#, Some(members(&["a"]))),
        (r#"{"sources": "ab"}"#, Some(members(&["a", "b"]))),
        (
            r#"{"sources": {"a": 1}, "sources": ["b"]}"#,
            Some(members(&["b"])),
        ),
        (r#"{"sources": 3}"#, None),
        (r#"{"sources": null}"#, None),
        (r#"{"sources": [["a"]]}"#, None),
        (r#"{"sources": [{}]}"#, None),
        ("[]", None),
        (r#""x""#, None),
        ("not json", None),
    ] {
        assert_eq!(verus_sources(text.as_bytes()), expected, "{text}");
    }
    let mixed = verus_sources(br#"{"sources": ["a", 1, null]}"#).expect("the list reads");
    assert!(mixed.holds("a") && !mixed.holds("1") && !mixed.is_empty());
    assert_eq!(verus_sources(b"{\"sources\": {\"\xff\": 1}}"), None);
}

/// The registry names its models' and its anchors' paths; each shape a reader of Python's typing refuses
/// reads as `None`, and an empty object or string iterates as nothing. The values are the interpreter's.
#[test]
fn an_unreadable_links_registry_runs_the_links_check_for_each_shape() {
    let base = [
        "verification/models/links.json",
        "scripts/model-links.py",
        "scripts/test-model-links.py",
        "tla/check.py",
        "scripts/judge-verus.py",
        "scripts/judge-rc11.py",
    ];
    let with = |extra: &[&str]| -> Members { base.iter().chain(extra).collect() };
    for (text, expected) in [
        (r#"{"models": [], "rows": []}"#, Some(with(&[]))),
        (
            r#"{"models": [{"path": "m"}], "rows": [{"anchors": [{"path": "c"}]}]}"#,
            Some(with(&["m", "c"])),
        ),
        (r#"{"models": {}, "rows": ""}"#, Some(with(&[]))),
        (r#"{"models": "", "rows": {}}"#, Some(with(&[]))),
        (r#"{"models": [], "rows": [{}]}"#, Some(with(&[]))),
        (
            r#"{"models": [], "rows": [{"anchors": ""}]}"#,
            Some(with(&[])),
        ),
        (r#"{"models": "x", "rows": []}"#, None),
        (r#"{"models": {"k": 1}, "rows": []}"#, None),
        (r#"{"models": [{}], "rows": []}"#, None),
        (r#"{"models": [{"path": ["a"]}], "rows": []}"#, None),
        (r#"{"models": [], "rows": [[]]}"#, None),
        (r#"{"models": [], "rows": [{"anchors": null}]}"#, None),
        (r#"{"models": [], "rows": [{"anchors": "ab"}]}"#, None),
        (r#"{"models": []}"#, None),
        (r#"{"rows": []}"#, None),
        ("[]", None),
        (r#"{"models": 1, "rows": []}"#, None),
        (r#"{"models": ["a"], "rows": []}"#, None),
    ] {
        assert_eq!(link_inputs(text.as_bytes()), expected, "{text}");
    }
    let numbered =
        link_inputs(br#"{"models": [{"path": 1}], "rows": []}"#).expect("a number reads");
    assert!(!numbered.holds("1") && numbered.holds("tla/check.py"));
}

/// The two samples a chaos test keeps, a run of 12 digits between spaces and three groups of four, match.
#[test]
fn the_account_pattern_matches_the_samples_a_chaos_test_keeps() {
    assert!(account_number(&Text::from("a 123456789012 b")));
    assert!(account_number(&Text::from("account 1234-5678-9012")));
    assert!(!account_number(&Text::from("a 12345678901 b")));
}

/// A repeated key's earlier value is read, so a record that repeats `a` after an account number holds one.
#[test]
fn a_chaos_record_with_an_account_number_under_a_repeated_key_is_refused() {
    let values = record_values(r#"{"a": 123456789012, "a": 0}"#).expect("the record is JSON");
    assert_eq!(
        values,
        ["0", "a", "123456789012", "a"].map(Text::from).to_vec()
    );
    assert!(values.iter().any(account_number));
}
