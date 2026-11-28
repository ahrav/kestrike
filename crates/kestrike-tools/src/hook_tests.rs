use std::ffi::OsStr;

use crate::git::push_environ;
use crate::hook::guard::CHAOS_RECORD;
use crate::hook::members::{Members, link_inputs, verus_sources};
use crate::hook::reads::spans;
use crate::hook::table::{Check, Held, ORDER, checks_for};
use crate::hook::{Failure, Plan, account_number, ignored_tests, record_values, shown};
use crate::rust_text::FUNCTION;
use crate::text::Text;

/// The run order holds the ten checks of the hook, each at the index of its `Check`, with the argument
/// vectors the hook runs.
#[test]
fn the_rows_hold_the_hooks_checks_in_run_order() {
    let argvs: Vec<&[&str]> = ORDER.iter().map(|row| row.argv).collect();
    let expected: [&[&str]; 10] = [
        &["python3", "scripts/test-select-tests.py"],
        &["python3", "scripts/verify-receipts.py", "admit"],
        &["python3", "scripts/judge-verus.py", "reconcile"],
        &["python3", "scripts/model-links.py", "check"],
        &["python3", "scripts/test-model-links.py"],
        &[
            "python3",
            "-I",
            "chaos/tools/validate_contract.py",
            "chaos/ledger.json",
            "--root",
            ".",
            "--project",
            "chaos/project.yaml",
            "--receipts",
            "chaos/receipts",
            "--check-claim",
            "chaos/READINESS.md",
        ],
        &["python3", "-I", "scripts/chaos-receipt-replay.py"],
        &["python3", "-I", "chaos/tests/test_judges.py"],
        &["python3", "-I", "scripts/test-gameday-judge.py"],
        &[
            "cargo",
            "test",
            "--package",
            "kestrike-tools",
            "--test",
            "tools",
            "--",
            "host_stop::",
            "host_stop_checks::",
            "host_stop_controller::",
            "host_stop_support::",
        ],
    ];
    assert_eq!(argvs, expected);
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
fn a_chaos_record_path_matches_whole_with_line_feeds_inside() {
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
    assert_eq!(mixed, members(&["a"]));
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

/// `selected` is `checks_for` of `paths` with `sources`, `links` and the default `Held`.
fn selected(paths: &[&str], sources: Option<&Members>, links: Option<&Members>) -> Vec<Check> {
    checks_for(paths, sources, links, false, Held::default())
}

/// Each row names the file whose presence at the tip the plan reads for its check, and no other row does.
#[test]
fn each_row_names_the_file_the_plan_asks_the_tip_for() {
    let held: Vec<(Check, Option<&str>)> = ORDER.iter().map(|row| (row.check, row.held)).collect();
    assert_eq!(
        held,
        [
            (Check::SelectTests, None),
            (Check::Admit, None),
            (Check::Reconcile, None),
            (Check::Links, Some("scripts/model-links.py")),
            (Check::LinksSelfTest, None),
            (Check::Contract, Some("chaos/ledger.json")),
            (Check::Replay, Some("scripts/chaos-receipt-replay.py")),
            (Check::Judges, Some("chaos/tests/test_judges.py")),
            (Check::Gameday, Some("scripts/test-gameday-judge.py")),
            (
                Check::HostStop,
                Some("crates/kestrike-tools/tests/host_stop_controller/mod.rs")
            ),
        ]
    );
}

/// Each selection input, and each path under the intake directory, selects the test selection and the
/// receipt admission; a directory that only starts like the intake directory selects nothing.
#[test]
fn each_admission_input_runs_its_checks() {
    let none = Members::default();
    let both = [Check::SelectTests, Check::Admit];
    for path in [
        "scripts/test-inventory.json",
        "scripts/test-registry.json",
        "scripts/select-tests.py",
        "scripts/test-select-tests.py",
        "verification/obligations.json",
        "verification/control-less.json",
        ".github/workflows/agent-checks.yml",
        "scripts/verify-receipts.py",
        "scripts/test-verify-receipts.py",
        "scripts/run-receipt-selftests.py",
        "scripts/scan-tag-compare.py",
        "scripts/classify-atomics.py",
        "verification/atomics/census.json",
        "quint/check.py",
        "verification/intake/dsw-4.json",
        "verification/intake/exclusions/old/notes.md",
        "verification/intake/old\nrow.md",
    ] {
        let unheld = Held {
            gameday: false,
            host_stop: false,
            ..Held::default()
        };
        let checks = checks_for(&[path], Some(&none), Some(&none), false, unheld);
        assert_eq!(checks, both, "{path:?}");
    }
    let inventory = selected(
        &["verification/verus/inventory.json"],
        Some(&none),
        Some(&none),
    );
    assert_eq!(
        inventory,
        [Check::SelectTests, Check::Admit, Check::Reconcile]
    );
    assert!(selected(&["tla/check.py"], Some(&none), Some(&none)).starts_with(&both));
    let outside = selected(
        &["verification/intake-old/dsw-4.json"],
        Some(&none),
        Some(&none),
    );
    assert_eq!(outside, []);
}

/// A path the inventory names or one under `verification/verus/` runs reconciliation, and an inventory
/// that could not be read runs it on any change but none for no change.
#[test]
fn a_verus_source_change_runs_reconciliation() {
    let none = Members::default();
    let sources = members(&["crates/v.rs"]);
    assert_eq!(
        selected(&["crates/v.rs"], Some(&sources), Some(&none)),
        [Check::Reconcile]
    );
    assert_eq!(
        selected(&["crates/plain.rs"], Some(&sources), Some(&none)),
        []
    );
    assert_eq!(
        selected(&["verification/verus/x.rs"], Some(&none), Some(&none)),
        [Check::Reconcile]
    );
    assert_eq!(
        selected(&["crates/plain.rs"], None, Some(&none)),
        [Check::Reconcile]
    );
    assert_eq!(selected(&[], None, None), []);
}

/// A path the registry names runs the links check, a script the check loads also runs its self-test, and a
/// registry that could not be read runs the check on any change.
#[test]
fn each_links_input_runs_its_checks_by_the_selection() {
    let none = Members::default();
    let links = members(&["tla/M.tla", "scripts/model-links.py"]);
    assert_eq!(
        selected(&["tla/M.tla"], Some(&none), Some(&links)),
        [Check::Links]
    );
    assert_eq!(selected(&["tla/Other.tla"], Some(&none), Some(&links)), []);
    assert_eq!(
        selected(&["scripts/model-links.py"], Some(&none), Some(&links)),
        [Check::Links, Check::LinksSelfTest]
    );
    assert_eq!(
        selected(&["scripts/judge-rc11.py"], Some(&none), Some(&none)),
        [Check::SelectTests, Check::Admit]
    );
    assert_eq!(
        selected(&["crates/plain.rs"], Some(&none), None),
        [Check::Links]
    );
    assert_eq!(
        selected(&["scripts/test-model-links.py"], Some(&none), None),
        [Check::Links, Check::LinksSelfTest]
    );
}

/// A chaos change runs the replay at a tip that holds it, and a change to the replay runs it at any tip.
#[test]
fn a_chaos_change_at_a_tip_that_holds_the_receipt_replay_runs_it() {
    let none = Members::default();
    let replay = "scripts/chaos-receipt-replay.py";
    assert_eq!(
        selected(&[replay], Some(&none), Some(&none)),
        [Check::Replay]
    );
    let held = Held {
        replay: true,
        ..Held::default()
    };
    let chaos = checks_for(
        &["chaos/READINESS.md"],
        Some(&none),
        Some(&none),
        false,
        held,
    );
    assert_eq!(chaos, [Check::Contract, Check::Replay]);
    assert_eq!(
        selected(&["chaos/READINESS.md"], Some(&none), Some(&none)),
        [Check::Contract]
    );
}

/// Each ignore attribute's span runs through the name of the next fn past the attributes between them, a
/// later attribute takes a new fn once the found one starts before its end, and an attribute with no fn
/// after it spans to the end of the text.
#[test]
fn the_ignore_spans_end_at_the_fn_each_attribute_precedes() {
    let text = "#[ignore]\nfn a() {}\n#[cfg_attr(\n    miri,\n    ignore = \"slow\"\n)]\n\
                #[should_panic(expected = \"fn sentinel\")]\nfn b() {}\n#[ignore]\nconst N: u8 = 1;\n";
    let spans = ignored_tests(text);
    assert_eq!(spans.len(), 3);
    assert_eq!(spans[0], "#[ignore]\nfn a");
    assert!(
        spans[1].starts_with("#[cfg_attr(") && spans[1].ends_with("fn sentinel\")]\nfn b"),
        "{spans:?}"
    );
    assert_eq!(spans[2], "#[ignore]\nconst N: u8 = 1;\n");
    assert_eq!(ignored_tests("fn plain() {}\n"), Vec::<&str>::new());
}

/// The span search reads the raw text: a `fn` name in a comment ends the span there, and so does a `]`
/// inside an attribute's string followed by `fn` and a name, so renaming the real test leaves both spans
/// as they were.
#[test]
fn a_fn_name_in_a_comment_or_after_a_bracket_in_a_string_ends_the_span() {
    let commented = |name: &str| format!("#[ignore]\n// fn stale\nfn {name}() {{}}\n");
    let (old, new) = (commented("a"), commented("b"));
    assert_eq!(ignored_tests(&old), ["#[ignore]\n// fn stale"]);
    assert_eq!(ignored_tests(&old), ignored_tests(&new));
    let quoted = |name: &str| {
        format!("#[ignore]\n#[should_panic(expected = \"]fn stale\")]\nfn {name}() {{}}\n")
    };
    let (old, new) = (quoted("a"), quoted("b"));
    assert_eq!(
        ignored_tests(&old),
        ["#[ignore]\n#[should_panic(expected = \"]fn stale"]
    );
    assert_eq!(ignored_tests(&old), ignored_tests(&new));
}

/// The record read takes nesting up to the reader's 1,000 levels and refuses deeper.
#[test]
fn a_record_nested_past_the_readers_depth_is_not_json() {
    let nested = |depth: usize| "[".repeat(depth) + &"]".repeat(depth);
    assert_eq!(record_values(&nested(1000)), Some(Vec::new()));
    assert_eq!(record_values(&nested(1001)), None);
}

/// A commit whose text is not UTF-8 names itself by its `repr` when a batch read cannot name it.
#[test]
fn an_unencodable_commit_names_itself_by_its_repr() {
    let commit = Text::from_code_points([0x61, 0xdcff]).expect("the code points are in range");
    assert_eq!(
        Failure::Unencodable(commit).to_string(),
        "the batch name of 'a\\udcff' is not UTF-8"
    );
}

/// The attributes that end before a found fn's match starts share its search, and an attribute the match
/// starts before searches again: three attributes before `a` and two before `b`, each behind a comment
/// the fn's match cannot span, search twice, and the spans run through each attribute's own fn.
#[test]
fn the_attributes_before_one_fn_share_its_search() {
    let text = "#[ignore]\n// a\n#[ignore]\n// b\n#[ignore]\n// c\nfn a() {}\n#[ignore]\n// d\n#[ignore]\n// e\nfn b() {}\n";
    let mut searches = 0;
    let found = spans(text, |from| {
        searches += 1;
        FUNCTION.find_at(text, from)
    });
    assert_eq!(searches, 2);
    assert_eq!(found.len(), 5);
    assert!(found[..3].iter().all(|span| span.ends_with("fn a")));
    assert!(found[3..].iter().all(|span| span.ends_with("fn b")));
}

/// A plan's environment is the push's, and its `Debug` leaves the environment out.
#[test]
fn a_plan_reads_git_in_the_push_environment_and_debug_leaves_it_out() {
    let plan = Plan::new(OsStr::new(""), || Ok(())).expect("an empty destination reads no remote");
    assert_eq!(plan.environ(), &push_environ());
    let path = std::env::var("PATH").unwrap_or_default();
    let shown = format!("{plan:?}");
    assert!(path.is_empty() || !shown.contains(&path), "{shown}");
    assert!(!shown.contains("GIT_NO_REPLACE_OBJECTS"), "{shown}");
}
