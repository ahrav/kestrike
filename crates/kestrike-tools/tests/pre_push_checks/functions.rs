//! The seven cases of the hook's self-test that call its functions alone and start no hook.

use std::fs;
use std::path::Path;

use kestrike_tools::hook::{
    Check, Held, Members, account_number, checks_for, destination_refs, ignored_tests,
    record_values,
};
use kestrike_tools::text::Text;

const CONTROLS: &str = "crates/campaign-supervisor/src/campaign/calibration/controls.rs";

/// `selected` is `checks_for` of one path with no Verus source, no links input and `held`.
fn selected(path: &str, held: Held) -> Vec<Check> {
    let none = Members::default();
    checks_for(&[path], Some(&none), Some(&none), false, held)
}

fn argv(check: Check) -> Vec<&'static str> {
    check.row().argv.to_vec()
}

/// Each path under `chaos/` runs the contract check, and each input the judges' test reads also runs that
/// test; a path that only starts like such an input runs the contract check alone, and the controls run
/// the judges' test only at a tip that holds it.
#[test]
fn each_contract_input_selects_its_checks() {
    let contract = vec![Check::Contract];
    let both = vec![Check::Contract, Check::Judges];
    for (path, expected) in [
        ("chaos/READINESS.md", &contract),
        ("chaos/harness/run_scenario.py", &both),
        ("chaos/judges/core/common.py", &both),
        ("chaos/tests/test_judges.py", &both),
        ("chaos/tests/runs/fixture/run.json", &both),
        ("chaos/tools/validate_contract.py", &both),
        ("chaos/receipts/run/row.json", &both),
        ("chaos/ledger.json", &both),
        ("chaos/project.yaml", &both),
        ("chaos/approval-policy.md", &both),
        ("chaos/judges", &both),
        ("chaos/harness", &both),
        ("chaos", &contract),
        ("chaos/ledger.json.old", &contract),
        ("chaos/project.yaml.example", &contract),
        ("chaos/approval-policy.md.bak", &contract),
        ("chaos/survey.md", &contract),
        ("chaos/runs/run/run.json", &contract),
        ("crates/plain.rs", &vec![]),
        (CONTROLS, &vec![Check::Judges]),
        (
            &CONTROLS.replace("controls.rs", "controls_tests.rs"),
            &vec![],
        ),
    ] {
        assert_eq!(&selected(path, Held::default()), expected, "{path}");
    }
    let unheld = Held {
        judges: false,
        ..Held::default()
    };
    assert_eq!(selected(CONTROLS, unheld), []);
    assert_eq!(
        argv(Check::Contract),
        [
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
        ]
    );
}

/// Each source the judges' test reads beside the controls runs it at a tip that holds it and not
/// elsewhere, and a file beside them that it does not read runs nothing.
#[test]
fn each_rust_source_beside_the_controls_runs_the_judges_test_of_a_tip_that_holds_it() {
    let crate_ = "crates/campaign-supervisor/src";
    let unheld = Held {
        judges: false,
        ..Held::default()
    };
    for (path, held) in [
        (
            format!("{crate_}/campaign/seeds/required.rs"),
            vec![Check::Judges],
        ),
        (format!("{crate_}/campaign/seeds.rs"), vec![Check::Judges]),
        (format!("{crate_}/protocol/summary.rs"), vec![Check::Judges]),
        (format!("{crate_}/campaign/seeds/pen.rs"), vec![]),
    ] {
        assert_eq!(selected(&path, Held::default()), held, "{path}");
        assert_eq!(selected(&path, unheld), [], "{path}");
    }
}

/// `literal_strings` returns the double-quoted string literals of the one top-level assignment of `name`
/// in the Python file `path` at the checkout's top, and fails unless the file assigns `name` exactly once.
/// The literal runs from the `=` to the line where its brackets close, and holds brackets, double-quoted
/// strings without escapes, commas, colons and white space alone; anything else in it, and anything but
/// white space or a comment after it on its closing line, a second statement included, fails the read, so
/// no member of the table is skipped.
fn literal_strings(path: &str, name: &str) -> Vec<String> {
    let top = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    literals(
        path,
        &fs::read_to_string(top.join(path)).expect("the Python file reads"),
        name,
    )
}

/// `literals` is [`literal_strings`] over `text`, the file `path` holds.
fn literals(path: &str, text: &str, name: &str) -> Vec<String> {
    let starts: Vec<&str> = text
        .split('\n')
        .filter(|line| {
            line.strip_prefix(name)
                .map(str::trim_start)
                .is_some_and(|rest| rest.starts_with('=') && !rest.starts_with("=="))
        })
        .collect();
    assert_eq!(starts.len(), 1, "{path} assigns {name} once");
    let at = text
        .find(starts[0])
        .expect("the assignment stands in the text");
    let value = &text[at..][text[at..].find('=').expect("an assignment holds `=`") + 1..];
    let mut depth = 0_i32;
    let mut strings = Vec::new();
    let mut chars = value.chars();
    let mut opened = false;
    while let Some(c) = chars.next() {
        if opened && depth == 0 {
            match c {
                '\n' => break,
                '#' => {
                    chars.by_ref().find(|&c| c == '\n');
                    break;
                }
                c if c.is_whitespace() => continue,
                c => panic!("{path}: {name} is followed by {c:?} on its closing line"),
            }
        }
        match c {
            '(' | '[' | '{' => {
                depth += 1;
                opened = true;
            }
            ')' | ']' | '}' => depth -= 1,
            '"' => {
                let literal: String = chars.by_ref().take_while(|&c| c != '"').collect();
                assert!(!literal.contains('\\'), "{literal} holds no escape");
                strings.push(literal);
            }
            ',' | ':' => {}
            c if c.is_whitespace() => {}
            c => panic!("{path}: {name} holds {c:?}, which the read does not take"),
        }
    }
    strings
}

/// The table read takes the two forms of the tables it reads and fails on a member that is no
/// double-quoted string and on a second statement after the table's closing line.
#[test]
fn the_table_read_fails_on_a_member_it_does_not_read() {
    let read =
        |text: &str| std::panic::catch_unwind(|| literals("t.py", text, "T")).map_err(|_| ());
    assert_eq!(
        read("T = (\"a\", \"b\",\n     \"c\")  # note\nU = 1\n"),
        Ok(vec!["a".to_owned(), "b".to_owned(), "c".to_owned()])
    );
    assert_eq!(
        read("T = {\"k\": (\"p\", \"N\"),\n     \"j\": (\"q\", \"M\")}\n"),
        Ok(["k", "p", "N", "j", "q", "M"].map(str::to_owned).to_vec())
    );
    for refused in [
        "T = (\"a\", 'b')\n",
        "T = (\"a\", NAME)\n",
        "T = (\"a\",); T = ()\n",
    ] {
        assert_eq!(read(refused), Err(()), "{refused}");
    }
}

/// Each game-day judge input runs the judge's self-test at a tip that holds it, and the judge and its
/// self-test run it at any tip; each file of the judge's fleet bounds and each script of the readiness
/// module's `OWNING` tuple, read from those files, selects it, so the hook's copy of those tables cannot
/// fall behind them.
#[test]
fn a_game_day_judge_input_runs_its_self_test_at_a_tip_that_holds_it() {
    assert_eq!(
        argv(Check::Gameday),
        ["python3", "-I", "scripts/test-gameday-judge.py"]
    );
    let no_host_stop = Held {
        host_stop: false,
        ..Held::default()
    };
    let inputs = [
        "scripts/readiness.py",
        "scripts/fis-profiles.json",
        "verification/readiness/gamedays.json",
        "verification/readiness/failover.json",
        "scripts/gameday-fixtures/held/package.json",
        "scripts/measurement-frame.py",
        "scripts/acceptance.py",
        "scripts/hit-gate.py",
    ];
    for path in ["scripts/gameday-judge.py", "scripts/test-gameday-judge.py"]
        .into_iter()
        .chain(inputs)
    {
        assert_eq!(selected(path, no_host_stop), [Check::Gameday], "{path}");
    }
    let neither = Held {
        gameday: false,
        host_stop: false,
        ..Held::default()
    };
    for path in inputs {
        assert_eq!(selected(path, neither), [], "{path}");
    }
    let no_gameday = Held {
        gameday: false,
        ..Held::default()
    };
    assert_eq!(
        selected("scripts/test-gameday-judge.py", no_gameday),
        [Check::Gameday]
    );
    let bounds = literal_strings("scripts/gameday-judge.py", "FLEET_BOUNDS");
    assert!(
        !bounds.is_empty() && bounds.len().is_multiple_of(3),
        "each bound is a key, a path and a constant: {bounds:?}"
    );
    let mut paths: Vec<&String> = bounds.iter().skip(1).step_by(3).collect();
    paths.sort_unstable();
    paths.dedup();
    for path in paths {
        for (test, unheld) in [
            (Check::Gameday, no_gameday),
            (Check::HostStop, no_host_stop),
        ] {
            assert!(selected(path, Held::default()).contains(&test), "{path}");
            assert!(!selected(path, unheld).contains(&test), "{path}");
        }
    }
    let owning = literal_strings("scripts/readiness.py", "OWNING");
    assert!(owning.len() >= 9, "{owning:?}");
    let own = ["scripts/gameday-judge.py", "scripts/test-gameday-judge.py"];
    let shared: Vec<String> = owning
        .iter()
        .map(|name| format!("scripts/{name}"))
        .filter(|path| own.contains(&path.as_str()))
        .collect();
    assert_eq!(shared, ["scripts/gameday-judge.py"]);
    for name in &owning {
        let path = format!("scripts/{name}");
        assert!(
            selected(&path, Held::default()).contains(&Check::Gameday),
            "{path}"
        );
        assert_eq!(
            selected(&path, no_gameday).contains(&Check::Gameday),
            own.contains(&path.as_str()),
            "{path}"
        );
    }
}

/// Each input of the host stop controller's self-test runs it at a tip that holds it; at a tip without it
/// only the controller and the self-test run it, and unrelated paths never do.
#[test]
fn a_host_stop_controller_input_runs_its_self_test_at_a_tip_that_holds_it() {
    assert_eq!(
        argv(Check::HostStop),
        ["python3", "-I", "scripts/test-host-stop-controller.py"]
    );
    let inputs = [
        "scripts/host-stop-controller.py",
        "scripts/test-host-stop-controller.py",
        "scripts/host-stop-fixtures/operator.json",
        "scripts/host-stop-fixtures/snapshot/shards.jsonl",
        "scripts/gameday-fixtures/held/package.json",
        "scripts/gameday-judge.py",
        "scripts/readiness.py",
        "scripts/acceptance.py",
        "scripts/fis-controller.py",
        "scripts/hardware-lane.py",
        "scripts/reproduce-test.py",
        "scripts/select-tests.py",
        "scripts/sizing-worksheet.py",
        "scripts/recovery-packages.py",
        "scripts/measurement-frame.py",
        "scripts/hit-gate.py",
        "scripts/verify-receipts.py",
        "scripts/fis-profiles.json",
        "verification/readiness/gamedays.json",
    ];
    let unheld = Held {
        host_stop: false,
        ..Held::default()
    };
    for path in inputs {
        assert!(
            selected(path, Held::default()).contains(&Check::HostStop),
            "{path}"
        );
    }
    for path in &inputs[2..] {
        assert!(!selected(path, unheld).contains(&Check::HostStop), "{path}");
    }
    for path in &inputs[..2] {
        assert_eq!(selected(path, unheld), [Check::HostStop], "{path}");
    }
    for path in [
        "verification/readiness/failover.json",
        "scripts/test-fis-controller.py",
        "scripts/host-stop-controller.md",
        "docs/agents/ci.md",
    ] {
        assert!(
            !selected(path, Held::default()).contains(&Check::HostStop),
            "{path}"
        );
    }
    assert_eq!(
        selected("scripts/host-stop-controller.py", Held::default()),
        [Check::HostStop]
    );
    assert_eq!(
        kestrike_tools::hook::ORDER[Check::HostStop as usize].check,
        Check::HostStop
    );
}

/// `matched` holds when a decoded value of the record `text` holds what may be an account number, and
/// fails the case unless `text` reads as JSON.
fn matched(text: &str) -> bool {
    record_values(text)
        .unwrap_or_else(|| panic!("{text} reads as JSON"))
        .iter()
        .any(account_number)
}

/// A match is 12 digits, or three groups of 4 joined by `-`, with no letter or digit beside them (and for
/// the groups no `-`), in each decoded key, string and integer, nested or not; a float, a digit run inside
/// a digest or a longer number, and an escape that decodes to a letter make none, and a text that is no
/// JSON reads as none at all.
#[test]
fn the_account_number_match_reads_each_decoded_key_string_and_integer() {
    let digest = format!("ab123456789012{}", "cd".repeat(25));
    for (text, refused) in [
        (
            r#"{"arn": "arn:aws:sts::123456789012:assumed-role/r"}"#.to_owned(),
            true,
        ),
        (r#"{"output": "account 1234-5678-9012"}"#.to_owned(), true),
        (r#"{"account": 123456789012}"#.to_owned(), true),
        (r#"{"account": -123456789012}"#.to_owned(), true),
        (r#"{"123456789012": "key"}"#.to_owned(), true),
        (
            r#"{"bucket": "assets-123456789012-us-east-1"}"#.to_owned(),
            true,
        ),
        (r#"{"output": "line\n123456789012"}"#.to_owned(), true),
        (r#"{"output": "cell\t1234-5678-9012"}"#.to_owned(), true),
        (r#"{"output": "x\u0020123456789012"}"#.to_owned(), true),
        (
            r#"{"nested": [[{"deep": "123456789012"}]]}"#.to_owned(),
            true,
        ),
        (
            format!(r#"{{"judge": "{digest}", "runs": [12345678901, 1234567890123]}}"#),
            false,
        ),
        (
            r#"{"head": "123456789012cdcd", "tail": "abab123456789012"}"#.to_owned(),
            false,
        ),
        (
            r#"{"before": "x1234-5678-9012", "after": "1234-5678-9012y"}"#.to_owned(),
            false,
        ),
        (
            r#"{"card": "1234-5678-9012-3456", "lead": "0-1234-5678-9012"}"#.to_owned(),
            false,
        ),
        (r#"{"b": 0.000244140625}"#.to_owned(), false),
        (r#"{"output": "x\u0041123456789012"}"#.to_owned(), false),
        (r#"{"output": "x\\n123456789012"}"#.to_owned(), false),
    ] {
        assert_eq!(matched(&text), refused, "{text}");
    }
    let deep = "[".repeat(100_000);
    for text in [
        "not json: account 123456789012",
        r#"{"a": "\n123456789012""#,
        "\u{feff}{}",
        deep.as_str(),
    ] {
        assert_eq!(record_values(text), None, "{}", &text[..text.len().min(40)]);
    }
}

/// A destination name selects its own remote-tracking refs, excluding the refs of each remote whose name
/// extends it with `/`; an empty name, a glob character, and a name that extends another remote's name
/// with `/` select none.
#[test]
fn the_destination_refs_come_only_from_a_remote_name_without_a_glob() {
    let texts = |names: &[&str]| {
        names
            .iter()
            .map(|name| Text::from(*name))
            .collect::<Vec<_>>()
    };
    let remotes = texts(&["origin", "team/fork", "team", "teammate"]);
    for (name, expected) in [
        ("origin", texts(&["--remotes=origin"])),
        ("group/fork", texts(&["--remotes=group/fork"])),
        ("team/fork", Vec::new()),
        ("", Vec::new()),
        ("*", Vec::new()),
        ("orig?n", Vec::new()),
        ("[o]rigin", Vec::new()),
        ("o\\rigin", Vec::new()),
    ] {
        assert_eq!(
            destination_refs(&Text::from(name), &remotes),
            expected,
            "{name}"
        );
    }
    let remotes = texts(&["team/fork", "team", "teammate", "team/fork/deep"]);
    assert_eq!(
        destination_refs(&Text::from("team"), &remotes),
        texts(&[
            "--exclude=team/fork/*",
            "--exclude=team/fork/deep/*",
            "--remotes=team"
        ])
    );
}

/// Three thousand ignore attributes before one fn each take that fn's name, past the struct between them.
#[test]
fn the_ignore_spans_reuse_a_search_that_still_holds() {
    let text = "#[ignore]\n".repeat(3000) + "struct S;\nfn f() {}\n";
    let spans = ignored_tests(&text);
    assert_eq!(spans.len(), 3000);
    assert!(spans.iter().all(|span| span.ends_with("fn f")));
}
