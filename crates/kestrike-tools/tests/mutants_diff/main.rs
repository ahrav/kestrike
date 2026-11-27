//! The cases of the `mutants-diff` tool. Each process case starts the built binary against the stand-ins
//! of [`standins`] over a fixture repository; four cases call the tool's functions, two of them in a
//! process of their own.
#![cfg(target_os = "linux")]

mod fixture;
mod functions;
mod inputs;
mod signals;
mod standins;

use std::ffi::OsStr;
use std::fs;

use kestrike_tools::json::Value;
use kestrike_tools::text::Text;

use fixture::{Fixture, Plan, SOURCE, lib_rs, listed, registered, t, two_mutants};

fn integer(value: &Value) -> String {
    match value {
        Value::Integer(integer) => integer.to_string(),
        other => panic!("{other:?} is an integer"),
    }
}

fn string(value: &Value) -> String {
    match value {
        Value::String(text) => text.to_string(),
        other => panic!("{other:?} is a string"),
    }
}

fn get<'a>(report: &'a kestrike_tools::json::Object, key: &str) -> &'a Value {
    report
        .get(key)
        .unwrap_or_else(|| panic!("the report holds {key}"))
}

fn outcomes_of(report: &kestrike_tools::json::Object) -> Vec<String> {
    let Value::Array(mutants) = get(report, "mutants") else {
        panic!("mutants is an array");
    };
    mutants
        .iter()
        .map(|mutant| match mutant {
            Value::Object(mutant) => string(get(mutant, "outcome")),
            other => panic!("{other:?} is a mutant"),
        })
        .collect()
}

/// `counts` reads `counts` in the order listed, caught, missed, timeout, unviable, not-run.
fn counts(report: &kestrike_tools::json::Object) -> [String; 6] {
    let Value::Object(counts) = get(report, "counts") else {
        panic!("counts is an object");
    };
    [
        "listed", "caught", "missed", "timeout", "unviable", "not-run",
    ]
    .map(|kind| integer(get(counts, kind)))
}

fn reason(report: &kestrike_tools::json::Object) -> Option<String> {
    match get(report, "reason") {
        Value::Null => None,
        value => Some(string(value)),
    }
}

fn complete(report: &kestrike_tools::json::Object) -> bool {
    get(report, "complete") == &Value::Bool(true)
}

fn strings(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items.iter().map(string).collect(),
        other => panic!("{other:?} is an array"),
    }
}

fn one_mutant(name: &str) -> Vec<(Text, Text)> {
    listed(&lib_rs(), &[format!("{SOURCE}/lib.rs:{name}")])
}

fn short(id: &str) -> &str {
    &id[..12]
}

#[test]
fn a_complete_run_with_missed_mutants_exits_0_and_prints_each_missed() {
    let fx = Fixture::new("complete");
    let mut mutants = two_mutants();
    mutants.extend(listed(
        &format!("{SOURCE}/other.rs"),
        &[format!(
            "{SOURCE}/other.rs:1:1: replace three -> u32 with 0"
        )],
    ));
    let outcomes = [
        (mutants[0].1.clone(), "MissedMutant"),
        (mutants[1].1.clone(), "MissedMutant"),
        (mutants[2].1.clone(), "CaughtMutant"),
    ];
    fx.plan(&Plan {
        exit: 2,
        stray: true,
        ..Plan::new(&mutants, &outcomes)
    });
    let before = fx.snapshot();
    let out = fx.start().run();
    assert_eq!(out.code, 0, "{}", out.all());
    let line = format!(
        "mutants: {} against {} on aarch64: 3 listed, 1 caught, 2 missed, 0 timeout, 0 unviable; complete",
        short(&fx.head),
        short(&fx.base)
    );
    assert_eq!(
        out.lines(),
        [
            line,
            format!("missed: {}", mutants[0].1),
            format!("missed: {}", mutants[1].1)
        ]
    );
    let report = fx.report(Some(&out));
    assert!(complete(&report));
    assert_eq!(
        strings(get(&report, "flagged")),
        [lib_rs()],
        "the file with a caught mutant is not flagged"
    );
    assert_eq!(integer(get(&report, "tool_exit")), "2");
    let Value::Array(entries) = get(&report, "mutants") else {
        panic!("mutants is an array")
    };
    let Value::Object(first) = &entries[0] else {
        panic!("a mutant is an object")
    };
    assert_eq!(
        kestrike_tools::json::text(get(first, "phase_seconds")),
        r#"{"build":1.25,"test":0.5}"#
    );
    let listings: Vec<_> = fs::read_dir(&fx.artifacts)
        .expect("the artifacts directory holds the run")
        .map(|entry| entry.expect("an entry").path().join("list.json"))
        .filter(|path| path.is_file())
        .collect();
    let [listing] = listings.as_slice() else {
        panic!("one list.json: {listings:?}")
    };
    let Value::Array(rows) =
        kestrike_tools::json::parse(&fs::read_to_string(listing).expect("UTF-8")).expect("JSON")
    else {
        panic!("the listing is an array")
    };
    let kept: Vec<(String, String)> = rows
        .iter()
        .map(|row| match row {
            Value::Object(row) => (string(get(row, "name")), string(get(row, "diff"))),
            other => panic!("{other:?}"),
        })
        .collect();
    let expected: Vec<(String, String)> = mutants
        .iter()
        .map(|(_, name)| (name.to_string(), format!("--- {name}")))
        .collect();
    assert_eq!(kept, expected, "list.json keeps each mutant's diff");
    let run_dir = listing.parent().expect("a run directory");
    let name = run_dir
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a UTF-8 name");
    let (stamp, letters) = name.split_at(name.len() - 8);
    let digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    assert!(
        stamp.len() == 17 && digits(&stamp[..8]) && &stamp[8..9] == "T" && digits(&stamp[9..15]),
        "{name}"
    );
    assert_eq!(&stamp[15..], "Z-", "{name}");
    let letter = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_';
    assert!(letters.bytes().all(letter), "{name}");
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(run_dir)
        .expect("the run directory exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700, "the run directory is private");
    assert_eq!(fx.snapshot(), before);
    fx.assert_gone("grandchild.pid");
}

#[test]
fn a_listed_mutant_without_an_outcome_makes_the_run_incomplete() {
    let fx = Fixture::new("unjudged");
    let mutants = two_mutants();
    fx.plan(&Plan::new(
        &mutants,
        &[(mutants[0].1.clone(), "CaughtMutant")],
    ));
    let out = fx.start().run();
    assert_eq!(out.code, 1, "{}", out.all());
    assert!(
        out.lines()[0].ends_with("1 caught, 0 missed, 0 timeout, 0 unviable; incomplete"),
        "{}",
        out.all()
    );
    let report = fx.report(Some(&out));
    assert!(!complete(&report));
    assert_eq!(
        reason(&report).as_deref(),
        Some("1 listed mutants have no outcome and 0 judged mutants were not listed")
    );
    assert_eq!(outcomes_of(&report), ["caught", "not-run"]);
    assert_eq!(counts(&report)[5], "1");
}

#[test]
fn a_failed_baseline_credits_no_kill() {
    let fx = Fixture::new("baseline");
    let mutants = one_mutant("2:1: replace two -> u32 with 0");
    let plan = Plan::new(&mutants, &[(mutants[0].1.clone(), "CaughtMutant")]);
    fx.plan(&Plan {
        baseline: Some("Failure"),
        exit: 4,
        ..plan
    });
    let out = fx.start().run();
    assert_eq!(out.code, 1, "{}", out.all());
    let report = fx.report(Some(&out));
    assert_eq!(string(get(&report, "baseline")), "failed");
    assert!(!complete(&report));
    assert_eq!(reason(&report).as_deref(), Some("the baseline failed"));
    assert_eq!(
        counts(&report),
        ["1", "0", "0", "0", "0", "1"].map(str::to_owned)
    );
    assert!(
        out.stdout.contains("reason: the baseline failed"),
        "{}",
        out.all()
    );
}

fn phase(duration: Value) -> Value {
    let mut phase = kestrike_tools::json::Object::new();
    phase.insert("phase", Value::String(t("Test")));
    phase.insert("duration", duration);
    Value::Array(vec![Value::Object(phase)])
}

fn record(scenario: Value, summary: &str, duration: Value) -> Value {
    let mut record = kestrike_tools::json::Object::new();
    record.insert("scenario", scenario);
    record.insert("summary", Value::String(t(summary)));
    record.insert("phase_results", phase(duration));
    Value::Object(record)
}

fn baseline(summary: &str, duration: Value) -> Value {
    record(Value::String(t("Baseline")), summary, duration)
}

fn mutant(name: &str, summary: &str, duration: Value) -> Value {
    let mut inner = kestrike_tools::json::Object::new();
    inner.insert("name", Value::String(t(name)));
    inner.insert("file", Value::String(Text::from(lib_rs())));
    let mut scenario = kestrike_tools::json::Object::new();
    scenario.insert("Mutant", Value::Object(inner));
    record(Value::Object(scenario), summary, duration)
}

fn outcome_file(records: Vec<Value>) -> String {
    let mut file = kestrike_tools::json::Object::new();
    file.insert("outcomes", Value::Array(records));
    kestrike_tools::json::text(&Value::Object(file))
}

fn half() -> Value {
    Value::Float(0.5)
}

#[test]
fn a_malformed_listing_or_outcome_file_makes_the_run_incomplete() {
    let fx = Fixture::new("malformed");
    let names: Vec<String> = (0..2)
        .map(|n| format!("{SOURCE}/lib.rs:2:1: replace two -> u32 with {n}"))
        .collect();
    let mutants = listed(&lib_rs(), &names);
    let (a, b) = (names[0].as_str(), names[1].as_str());
    let unreadable = "the tool wrote no readable outcome file";
    let failed = "the baseline failed";
    let absent = "the outcome file holds no baseline";
    let listing = "the listing does not parse: expected an array of mutants";
    let ok = || baseline("Success", half());
    let caught = || {
        vec![
            mutant(a, "CaughtMutant", half()),
            mutant(b, "CaughtMutant", half()),
        ]
    };
    let with = |mut head: Vec<Value>, tail: Vec<Value>| {
        head.extend(tail);
        head
    };
    let huge = kestrike_tools::json::Integer::from_digits(false, &format!("1{}", "0".repeat(400)))
        .expect("digits");
    let mut empty_phases = match mutant(a, "CaughtMutant", half()) {
        Value::Object(object) => object,
        other => panic!("{other:?}"),
    };
    empty_phases.insert(
        "phase_results",
        Value::Object(kestrike_tools::json::Object::new()),
    );
    let listing_of = |rows: &str| Plan {
        raw_listing: Some(rows.as_bytes().to_vec()),
        ..Plan::new(&mutants, &[])
    };
    let outcomes_of_file = |records: Vec<Value>, exit: i32| Plan {
        raw_outcomes: Some(outcome_file(records)),
        exit,
        ..Plan::new(&mutants, &[])
    };
    #[rustfmt::skip]
    let rows: Vec<(&str, Plan, &str)> = vec![
        ("{}", listing_of("{}"), listing),
        ("a name that is no string", listing_of(r#"[{"name": ["x"], "file": "f"}]"#), listing),
        ("a repeated name", listing_of(&format!(r#"[{{"name": "{a}", "file": "f"}}, {{"name": "{a}", "file": "f"}}]"#)),
         "the listing does not parse: a mutant name repeats"),
        ("200,000 open brackets", Plan { raw_outcomes: Some("[".repeat(200_000)), ..Plan::new(&mutants, &[]) }, unreadable),
        ("a repeated mutant", outcomes_of_file(vec![ok(), mutant(a, "CaughtMutant", half()), mutant(a, "MissedMutant", half()), mutant(b, "CaughtMutant", half())], 0), unreadable),
        ("an unjudged mutant repeated later", outcomes_of_file(with(vec![ok(), mutant(a, "Failure", half())], caught()), 0), unreadable),
        ("a judged mutant repeated unjudged", outcomes_of_file(with(with(vec![ok()], caught()), vec![mutant(a, "Failure", half())]), 0), unreadable),
        ("a failed baseline repeated", outcomes_of_file(with(vec![baseline("Failure", half()), ok()], caught()), 0), unreadable),
        ("a passed baseline repeated", outcomes_of_file(with(vec![ok(), baseline("Failure", half())], caught()), 0), unreadable),
        ("a NaN phase time", outcomes_of_file(vec![ok(), mutant(a, "CaughtMutant", Value::Float(f64::NAN)), mutant(b, "CaughtMutant", half())], 0), unreadable),
        ("a negative phase time", outcomes_of_file(vec![ok(), mutant(a, "CaughtMutant", Value::Integer(kestrike_tools::json::Integer::from_digits(true, "1").expect("-1"))), mutant(b, "CaughtMutant", half())], 0), unreadable),
        ("a phase time of 10 ** 400", outcomes_of_file(vec![ok(), mutant(a, "CaughtMutant", Value::Integer(huge)), mutant(b, "CaughtMutant", half())], 0), unreadable),
        ("a NaN baseline time", outcomes_of_file(with(vec![baseline("Success", Value::Float(f64::NAN))], caught()), 0), unreadable),
        ("phase results that are an object", outcomes_of_file(vec![ok(), Value::Object(empty_phases), mutant(b, "CaughtMutant", half())], 0), unreadable),
        ("no baseline", outcomes_of_file(caught(), 0), absent),
        ("an unlisted mutant", outcomes_of_file(with(with(vec![ok()], caught()), vec![mutant("unlisted", "CaughtMutant", half())]), 0),
         "0 listed mutants have no outcome and 1 judged mutants were not listed"),
        ("one listed and one unlisted", outcomes_of_file(vec![ok(), mutant(a, "CaughtMutant", half()), mutant("unlisted", "CaughtMutant", half())], 0),
         "1 listed mutants have no outcome and 1 judged mutants were not listed"),
        ("an unjudged summary", outcomes_of_file(vec![ok(), mutant(a, "CaughtMutant", half()), mutant(b, "Failure", half())], 0),
         "1 listed mutants have no outcome and 0 judged mutants were not listed"),
        ("a failed baseline", outcomes_of_file(with(vec![baseline("Failure", half())], caught()), 0), failed),
        ("a tool exit of 4", outcomes_of_file(with(vec![ok()], caught()), 4), failed),
        ("a tool exit of 4 with one judged", outcomes_of_file(vec![ok(), mutant(a, "CaughtMutant", half())], 4), failed),
    ];
    assert_eq!(rows.len(), 21);
    for (label, plan, expected) in rows {
        fx.clear();
        let from_listing = plan.raw_listing.is_some();
        fx.plan(&plan);
        let out = fx.start().run();
        assert_eq!(out.code, 1, "{label}: {}", out.all());
        assert!(!out.stderr.contains("panicked"), "{label}: {}", out.all());
        let report = fx.report(Some(&out));
        assert!(!complete(&report), "{label}");
        let found = reason(&report).unwrap_or_default();
        assert!(found.starts_with(expected), "{label}: {found}");
        if [unreadable, failed, absent].contains(&expected) {
            assert_eq!(counts(&report)[1], "0", "{label}");
        }
        if from_listing {
            assert!(fx.builds().is_empty(), "{label}");
            assert_eq!(counts(&report)[0], "0", "{label}");
        }
        if [failed, absent].contains(&expected) {
            assert!(
                outcomes_of(&report)
                    .iter()
                    .all(|outcome| outcome == "not-run"),
                "{label}"
            );
        }
    }
}

#[test]
fn timeout_and_unviable_are_counted_apart_and_the_tool_totals_are_recomputed() {
    let fx = Fixture::new("counts");
    let names: Vec<String> = (0..4)
        .map(|n| format!("{SOURCE}/lib.rs:{n}:1: replace two -> u32 with {n}"))
        .collect();
    let mutants = listed(&lib_rs(), &names);
    let summaries = ["Timeout", "Unviable", "CaughtMutant", "MissedMutant"];
    let outcomes: Vec<(Text, &str)> = mutants
        .iter()
        .zip(summaries)
        .map(|((_, name), s)| (name.clone(), s))
        .collect();
    let totals = vec![
        ("total_mutants", 9),
        ("caught", 4),
        ("missed", 0),
        ("timeout", 0),
        ("unviable", 0),
    ];
    fx.plan(&Plan {
        totals,
        exit: 3,
        ..Plan::new(&mutants, &outcomes)
    });
    let out = fx.start().run();
    assert_eq!(out.code, 0, "{}", out.all());
    assert!(
        out.stdout
            .contains(": 4 listed, 1 caught, 1 missed, 1 timeout, 1 unviable; complete"),
        "{}",
        out.all()
    );
    let report = fx.report(Some(&out));
    assert_eq!(
        counts(&report),
        ["4", "1", "1", "1", "1", "0"].map(str::to_owned)
    );
    assert!(
        strings(get(&report, "flagged")).is_empty(),
        "a file whose viable mutants include a timeout is not flagged"
    );
}

#[test]
fn a_file_whose_viable_mutants_were_all_missed_is_flagged() {
    let fx = Fixture::new("flagged");
    let (missed, unviable) = (
        format!("{SOURCE}/gated.rs"),
        format!("{SOURCE}/unviable.rs"),
    );
    let (caught, timeout) = (
        format!("{SOURCE}/caught.rs"),
        format!("{SOURCE}/timeout.rs"),
    );
    let plan = [
        (format!("{missed}:1:1: a"), "MissedMutant"),
        (format!("{missed}:2:1: b"), "Unviable"),
        (format!("{unviable}:1:1: c"), "Unviable"),
        (format!("{caught}:1:1: d"), "CaughtMutant"),
        (format!("{caught}:2:1: e"), "MissedMutant"),
        (format!("{timeout}:1:1: f"), "Timeout"),
        (format!("{timeout}:2:1: g"), "MissedMutant"),
    ];
    let mutants: Vec<(Text, Text)> = plan
        .iter()
        .map(|(name, _)| (t(name.split(':').next().expect("a file")), t(name)))
        .collect();
    let outcomes: Vec<(Text, &str)> = plan
        .iter()
        .map(|(name, summary)| (t(name), *summary))
        .collect();
    fx.plan(&Plan {
        exit: 3,
        ..Plan::new(&mutants, &outcomes)
    });
    let out = fx.start().run();
    assert_eq!(out.code, 0, "{}", out.all());
    assert_eq!(
        strings(get(&fx.report(Some(&out)), "flagged")),
        [missed],
        "a caught or timed-out mutant beside a missed one keeps its file unflagged"
    );
}

#[test]
fn an_empty_diff_and_an_excluded_only_diff_list_nothing_and_build_nothing() {
    let fx = Fixture::new("empty");
    fx.write("README.md", "changed\n");
    let docs = fx.commit("docs");
    fx.write(&format!("{SOURCE}/bind/host.rs"), "pub fn host() {}\n");
    let excluded = fx.commit("excluded");
    fx.plan(&Plan::default());
    for (base, head, listings) in [(&fx.head, &docs, 0), (&docs, &excluded, 1)] {
        for stale in fx.reports() {
            fs::remove_file(stale).expect("a stale report is removed");
        }
        let out = fx.start().base(base).head(head).run();
        assert_eq!(
            (out.code, out.stdout.as_str()),
            (0, "mutants: 0 listed\n"),
            "{}",
            out.all()
        );
        let report = fx.report(Some(&out));
        assert!(complete(&report));
        assert!(outcomes_of(&report).is_empty());
        assert_eq!(counts(&report)[0], "0");
        assert_eq!(fx.listings().len(), listings);
    }
    assert!(fx.builds().is_empty());
}

#[test]
fn a_tool_failure_is_incomplete_and_leaves_the_checkout_as_it_was() {
    let fx = Fixture::new("failure");
    let mutants = one_mutant("2:1: replace two -> u32 with 0");
    let before = fx.snapshot();
    let name = mutants[0].1.clone();
    let rows: Vec<(Plan, Option<fixture::Env>, &str, &str)> = vec![
        (
            Plan {
                no_outcomes: true,
                stray: true,
                ..Plan::new(&mutants, &[])
            },
            None,
            "0",
            "the tool wrote no readable outcome file",
        ),
        (
            Plan {
                list_exit: Some(1),
                ..Plan::new(&mutants, &[])
            },
            None,
            "0",
            "the listing exited 1",
        ),
        (
            Plan {
                exit: 70,
                stray: true,
                ..Plan::new(&mutants, &[(name, "CaughtMutant")])
            },
            None,
            "1",
            "the tool exited 70",
        ),
        (
            Plan::new(&mutants, &[]),
            Some(fx.git_wrapper("fail-add")),
            "0",
            "git worktree add exited 3",
        ),
    ];
    for (plan, env, caught, expected) in rows {
        fx.clear();
        let stray = plan.stray;
        fx.plan(&plan);
        let wrapped = env.is_some();
        let start = fx.start();
        let out = match env {
            Some(env) => start.env(env).run(),
            None => start.run(),
        };
        assert_eq!(out.code, 1, "{expected}: {}", out.all());
        let report = fx.report(Some(&out));
        assert!(!complete(&report), "{expected}");
        assert_eq!(reason(&report).as_deref(), Some(expected));
        assert_eq!(counts(&report)[1], caught, "{expected}");
        assert_eq!(fx.snapshot(), before, "{expected}");
        if stray {
            fx.assert_gone("grandchild.pid");
        }
        if wrapped {
            assert!(fx.calls().is_empty(), "{expected}");
        }
    }
}

#[test]
fn a_worktree_that_remains_after_removal_makes_the_run_incomplete() {
    let fx = Fixture::new("remains");
    fx.plan(&Plan::caught(&one_mutant("2:1: m")));
    let out = fx.start().env(fx.git_wrapper("fail-remove")).run();
    assert_eq!(out.code, 1, "{}", out.all());
    let report = fx.report(Some(&out));
    assert!(!complete(&report));
    let found = reason(&report).unwrap_or_default();
    assert!(found.starts_with("the worktree "), "{found}");
    assert!(found.contains("fatal: refused"), "{found}");
    assert_eq!(registered(&fx), 2);
}

#[test]
fn a_worktree_that_remains_under_a_path_with_a_line_break_makes_the_run_incomplete() {
    let fx = Fixture::new("line-break");
    fx.plan(&Plan::caught(&one_mutant("2:1: m")));
    for (count, name) in [(2, "arti\nfacts"), (3, "arti\rfacts")] {
        let artifacts = fx.state.join(name);
        let out = fx
            .start()
            .artifacts(&artifacts)
            .env(fx.git_wrapper("fail-remove"))
            .run();
        assert_eq!(out.code, 1, "{name:?}: {}", out.all());
        let report = fx.report_in(Some(&out), &artifacts);
        assert!(!complete(&report), "{name:?}");
        let found = reason(&report).unwrap_or_default();
        assert!(found.starts_with("the worktree "), "{name:?}: {found}");
        assert_eq!(registered(&fx), count, "{name:?}");
    }
}

#[test]
fn a_worktree_without_its_git_file_is_removed_once_its_directory_is_gone() {
    let fx = Fixture::new("dropped-git");
    let mutants = one_mutant("2:1: m");
    fx.plan(&Plan {
        drop_git: true,
        ..Plan::caught(&mutants)
    });
    let before = fx.snapshot();
    let out = fx.start().run();
    assert_eq!(out.code, 0, "{}", out.all());
    assert!(complete(&fx.report(Some(&out))));
    assert_eq!(fx.snapshot(), before);
}

#[test]
fn each_printed_line_is_one_line_the_stream_can_encode() {
    let fx = Fixture::new("printed");
    let mut lone = Text::from(format!("{SOURCE}/lib.rs:2:1: lone "));
    lone.push_code_point(0xd800)
        .expect("a surrogate is a code point");
    lone.push_str(" surrogate");
    let forged = Text::from(format!("{SOURCE}/lib.rs:3:1: first\nmissed: forged\rline"));
    let names = [lone, forged];
    let mutants: Vec<(Text, Text)> = names
        .iter()
        .map(|name| (Text::from(lib_rs()), name.clone()))
        .collect();
    let outcomes: Vec<(Text, &str)> = names
        .iter()
        .map(|name| (name.clone(), "MissedMutant"))
        .collect();
    fx.plan(&Plan {
        exit: 2,
        ..Plan::new(&mutants, &outcomes)
    });
    let out = fx.start().run();
    assert_eq!(out.code, 0, "{}", out.all());
    assert!(!out.stderr.contains("panicked"), "{}", out.all());
    let report = fx.report(Some(&out));
    let Value::Array(entries) = get(&report, "mutants") else {
        panic!("mutants is an array")
    };
    let kept: Vec<Text> = entries
        .iter()
        .map(|entry| match entry {
            Value::Object(entry) => match get(entry, "name") {
                Value::String(name) => name.clone(),
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        kept, names,
        "the report holds each name as the tool gave it"
    );
    assert_eq!(
        out.lines()[1..],
        [
            format!("missed: {SOURCE}/lib.rs:2:1: lone \\ud800 surrogate"),
            format!("missed: {SOURCE}/lib.rs:3:1: first\\nmissed: forged\\rline"),
        ]
    );
}

#[test]
fn a_checkout_path_that_is_not_utf_8_is_kept() {
    use std::os::unix::ffi::OsStringExt;
    let fx = Fixture::new("not-utf-8");
    let mut bytes = fx.state.join("repo").into_os_string().into_vec();
    bytes.push(0xff);
    let odd = std::path::PathBuf::from(std::ffi::OsString::from_vec(bytes));
    fx.git(&[
        OsStr::new("clone"),
        OsStr::new("-q"),
        fx.repo.as_os_str(),
        odd.as_os_str(),
    ]);
    fx.plan(&Plan::caught(&one_mutant("2:1: m")));
    let clean = fx.start().cwd(&odd).run();
    assert_eq!(clean.code, 0, "{}", clean.all());
    fx.clear();
    let artifacts = odd.join("target/mutants");
    let left = fx
        .start()
        .cwd(&odd)
        .artifacts(&artifacts)
        .env(fx.git_wrapper("fail-remove"))
        .run();
    assert_eq!(left.code, 1, "{}", left.all());
    assert!(!left.stderr.contains("panicked"), "{}", left.all());
    assert!(
        left.stdout.contains("reason: the worktree "),
        "{}",
        left.all()
    );
    assert!(left.stdout.contains("repo\\udcff"), "{}", left.all());
}

#[test]
fn a_head_without_a_root_manifest_starts_no_listing() {
    let fx = Fixture::new("no-manifest");
    fs::remove_file(fx.repo.join("Cargo.toml")).expect("the manifest is removed");
    fx.write(
        &lib_rs(),
        "pub fn one() -> u32 { 1 }\npub fn three() -> u32 { 3 }\n",
    );
    let head = fx.commit("no root manifest");
    fx.git(&["checkout", "-q", "--detach", &fx.head]);
    fx.plan(&Plan::new(&one_mutant("2:1: m"), &[]));
    let before = fx.snapshot();
    let out = fx.start().base(&fx.head).head(&head).run();
    assert_eq!(out.code, 1, "{}", out.all());
    assert_eq!(
        reason(&fx.report(Some(&out))).as_deref(),
        Some("the head has no root Cargo.toml, so Cargo would take an enclosing workspace")
    );
    assert!(fx.calls().is_empty());
    assert_eq!(fx.snapshot(), before);
}

#[test]
fn a_configuration_the_runner_cannot_read_makes_the_run_incomplete() {
    let fx = Fixture::new("unread-config");
    let config = fixture::CONFIG.replace(
        "profile.dev.debug-assertions",
        "profile.test.debug-assertions",
    );
    fx.write(".cargo/mutants.toml", &config);
    fx.write(
        &lib_rs(),
        "pub fn one() -> u32 { 1 }\npub fn three() -> u32 { 3 }\n",
    );
    let head = fx.commit("an unread entry");
    fx.plan(&Plan::new(&one_mutant("2:1: m"), &[]));
    let out = fx.start().base(&fx.head).head(&head).run();
    assert_eq!(out.code, 1, "{}", out.all());
    let found = reason(&fx.report(Some(&out))).unwrap_or_default();
    assert!(
        found.starts_with("the worktree configuration does not parse"),
        "{found}"
    );
    assert!(fx.calls().is_empty());
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn only(paths: Vec<std::path::PathBuf>) -> std::path::PathBuf {
    let [path] = paths.as_slice() else {
        panic!("one path: {paths:?}")
    };
    path.clone()
}

/// `run_files` returns each `<artifacts>/*/<name>`.
fn run_files(artifacts: &std::path::Path, name: &str) -> Vec<std::path::PathBuf> {
    let Ok(entries) = fs::read_dir(artifacts) else {
        return Vec::new();
    };
    let mut found: Vec<_> = entries
        .map(|entry| entry.expect("an entry").path().join(name))
        .filter(|path| path.exists())
        .collect();
    found.sort();
    found
}

#[test]
fn the_report_binds_the_diff_the_configuration_and_the_test_arguments() {
    let fx = Fixture::new("binds");
    let config = fixture::CONFIG.replace(r#""--config", "profile.dev.debug-assertions=false""#, "");
    fx.write(".cargo/mutants.toml", &config);
    fx.write(
        &lib_rs(),
        "pub fn one() -> u32 { 1 }\npub fn three() -> u32 { 3 }\n",
    );
    let head = fx.commit("head with another configuration");
    fx.git(&["branch", "topic", &head]);
    fx.git(&["checkout", "-q", "--detach", &fx.base]);
    fx.write(
        &lib_rs(),
        "pub fn one() -> u32 { 1 }\npub fn main_side() -> u32 { 4 }\n",
    );
    fx.write(
        ".cargo/mutants.toml",
        &format!("{}# a later edit\n", fixture::CONFIG),
    );
    fx.write(
        ".github/workflows/agent-checks.yml",
        &fixture::WORKFLOW.replace("1.99.0", "1.99.1"),
    );
    let main = fx.commit("main side");
    fx.git(&["update-ref", "refs/remotes/origin/main", &main]);
    let mutants = one_mutant("2:1: replace three -> u32 with 0");
    fx.plan(&Plan {
        exit: 3,
        ..Plan::new(&mutants, &[(mutants[0].1.clone(), "Timeout")])
    });
    let inherited = fixture::with(
        &fx.env,
        &[
            ("CARGO_TARGET_DIR", OsStr::new("/inherited/target")),
            ("CARGO_BUILD_BUILD_DIR", OsStr::new("/inherited/build")),
            ("CARGO_PROFILE_DEV_OPT_LEVEL", OsStr::new("3")),
            ("CARGO_PROFILE_DEV_DEBUG", OsStr::new("full")),
        ],
    );
    let args = [
        OsStr::new("--head"),
        OsStr::new("topic"),
        OsStr::new("--artifacts"),
        OsStr::new("relative/artifacts"),
        OsStr::new("--cargo"),
        fx.cargo.as_os_str(),
        OsStr::new("--tests=--test sim_worker -- --exact 'a b'"),
    ];
    let out = fx.start().raw().args(args).env(inherited).run();
    assert_eq!(out.code, 0, "{}", out.all());
    let artifacts = fx.repo.join("relative/artifacts");
    let path = only(run_files(&artifacts, "report.json"));
    let report = fx.report_in(Some(&out), &artifacts);
    let diff = only(run_files(&artifacts, "diff.patch"));
    let diff_args = [
        fixture::DIFF[0],
        fixture::DIFF[1],
        &fx.base,
        &head,
        "--",
        SOURCE,
    ];
    assert_eq!(
        fs::read_to_string(&diff).expect("UTF-8"),
        fx.git(&diff_args),
        "the default base is the merge base of the head with origin/main"
    );
    let fields = ["base", "head", "tool_version"].map(|key| string(get(&report, key)));
    assert_eq!(fields, [fx.base.clone(), head.clone(), "27.1.0".to_owned()]);
    assert_eq!(
        string(get(&report, "diff_sha256")),
        sha256(&fs::read(&diff).expect("the diff is readable"))
    );
    let head_config = fx.git(&["show", &format!("{head}:.cargo/mutants.toml")]);
    assert_eq!(
        string(get(&report, "config_sha256")),
        sha256(head_config.as_bytes())
    );
    let calls = fx.calls();
    let [listing, run] = calls.as_slice() else {
        panic!("a listing and a run: {calls:?}")
    };
    let tests = ["--test", "sim_worker", "--", "--exact", "a b"]
        .map(str::to_owned)
        .to_vec();
    assert_eq!(
        (strings(get(&report, "tests")), run.tests()),
        (tests.clone(), Some(tests))
    );
    assert_eq!(
        get(&report, "debug_assertions"),
        &Value::Null,
        "the head's configuration sets no debug-assertion entry"
    );
    let build = fs::canonicalize(&artifacts)
        .expect("the artifacts directory exists")
        .join("build");
    let run_dir = fs::canonicalize(path.parent().expect("a run directory")).expect("it exists");
    for call in [listing, run] {
        assert_eq!(
            call.diff_sha256.as_deref(),
            Some(string(get(&report, "diff_sha256")).as_str())
        );
        assert_eq!(
            call.config_sha256.as_deref(),
            Some(string(get(&report, "config_sha256")).as_str())
        );
        assert!(
            call.argv.join(" ").contains("-p kestrike"),
            "{:?}",
            call.argv
        );
        let build = build.to_str().expect("UTF-8");
        assert_eq!(
            (
                call.var("CARGO_TARGET_DIR"),
                call.var("CARGO_BUILD_BUILD_DIR")
            ),
            (Some(build), Some(build))
        );
        assert_eq!(
            (
                call.var("CARGO_PROFILE_DEV_OPT_LEVEL"),
                call.var("CARGO_PROFILE_DEV_DEBUG")
            ),
            (Some("1"), Some("line-tables-only"))
        );
        assert_eq!(
            call.var("RUSTUP_TOOLCHAIN"),
            Some("1.99.1"),
            "the pin comes from the invoking checkout"
        );
        assert_eq!(
            call.lock.as_deref(),
            Some("# lock\n"),
            "the worktree holds the checkout's Cargo.lock"
        );
        assert!(std::path::Path::new(call.value("--in-diff")).is_absolute());
        let cwd = std::path::Path::new(&call.cwd);
        assert_eq!(
            cwd.parent(),
            Some(run_dir.as_path()),
            "the worktree sits in the run directory"
        );
    }
    assert_eq!(listing.argv[1..3], ["--list", "--json"]);
    assert!(run.argv.iter().any(|arg| arg == "--in-place"));
    let output = std::path::Path::new(run.value("--output"));
    assert!(output.is_absolute());
    assert_eq!(
        fs::canonicalize(output).expect("the tool output exists"),
        run_dir.join("tool")
    );
    fs::remove_file(fx.state.join("calls")).expect("the calls are cleared");
    let out = fx.start().run();
    assert_eq!(out.code, 0, "{}", out.all());
    let report = fx.report(Some(&out));
    let defaults = fixture::DEFAULT_TESTS.map(str::to_owned).to_vec();
    assert_eq!(
        (strings(get(&report, "tests")), fx.calls()[1].tests()),
        (defaults.clone(), Some(defaults))
    );
    assert_eq!(string(get(&report, "debug_assertions")), "false");
}

#[test]
fn the_default_head_and_artifacts_come_from_the_invoking_checkout() {
    let fx = Fixture::new("defaults");
    fx.plan(&Plan::caught(&one_mutant("2:1: m")));
    let before = fx.snapshot();
    let args = [
        OsStr::new("--base"),
        OsStr::new(&fx.base),
        OsStr::new("--cargo"),
        fx.cargo.as_os_str(),
    ];
    let out = fx.start().raw().args(args).cwd(&fx.repo.join(SOURCE)).run();
    assert_eq!(out.code, 0, "{}", out.all());
    let artifacts = fx.repo.join("target/mutants");
    assert_eq!(
        string(get(&fx.report_in(Some(&out), &artifacts), "head")),
        fx.head
    );
    let build = fs::canonicalize(&artifacts)
        .expect("the artifacts directory exists")
        .join("build");
    let build = build.to_str().expect("UTF-8");
    for call in fx.calls() {
        assert_eq!(
            (
                call.var("CARGO_TARGET_DIR"),
                call.var("CARGO_BUILD_BUILD_DIR")
            ),
            (Some(build), Some(build))
        );
    }
    assert_eq!(fx.snapshot(), before);
}

#[test]
fn a_checkout_name_with_a_trailing_space_is_kept() {
    let fx = Fixture::new("trailing-space");
    let spaced = fx.state.join("repo ");
    fx.git(&[
        OsStr::new("clone"),
        OsStr::new("-q"),
        fx.repo.as_os_str(),
        spaced.as_os_str(),
    ]);
    fs::write(spaced.join("src-note"), "only in the spaced clone\n").expect("the note is written");
    let head = fx.commit_in(&spaced, "spaced head");
    fx.plan(&Plan::default());
    let out = fx.start().head(&head).cwd(&spaced).run();
    assert_eq!(
        (out.code, out.stdout.as_str()),
        (0, "mutants: 0 listed\n"),
        "{}",
        out.all()
    );
    assert_eq!(string(get(&fx.report(Some(&out)), "head")), head);
}

fn copy_executable(from: &std::path::Path, to: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::copy(from, to).expect("the stand-in is copied");
    fs::set_permissions(to, fs::Permissions::from_mode(0o755)).expect("the copy is executable");
}

#[test]
fn a_relative_cargo_path_names_the_same_program_in_the_worktree() {
    let fx = Fixture::new("relative-cargo");
    fs::create_dir(fx.repo.join("tools")).expect("the directory is made");
    copy_executable(&fx.cargo, &fx.repo.join("tools/cargo"));
    fx.plan(&Plan::caught(&one_mutant("2:1: m")));
    let out = fx.start().args(["--cargo", "tools/cargo"]).run();
    assert_eq!(out.code, 0, "{}", out.all());
    assert_eq!(
        fx.calls().len(),
        2,
        "the listing and the run reach the invoking checkout's program"
    );
}

#[test]
fn a_relative_path_entry_names_the_same_program_in_the_worktree() {
    // `link/../tools` is `real/tools`, since the kernel follows the link before it applies `..`.
    let fx = Fixture::new("relative-path");
    fs::create_dir_all(fx.repo.join("real/sub")).expect("the directory is made");
    fs::create_dir(fx.repo.join("real/tools")).expect("the directory is made");
    std::os::unix::fs::symlink("real/sub", fx.repo.join("link")).expect("the link is made");
    copy_executable(&fx.cargo, &fx.repo.join("real/tools/cargo"));
    fx.plan(&Plan::caught(&one_mutant("2:1: m")));
    let path = fx
        .env
        .iter()
        .find(|(name, _)| name == "PATH")
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    for (entry, program) in [
        ("real/tools", "cargo"),
        ("link/../tools", "cargo"),
        ("", "link/../tools/cargo"),
    ] {
        fx.clear();
        let mut joined = std::ffi::OsString::from(format!("{entry}:"));
        joined.push(&path);
        let env = fixture::with(&fx.env, &[("PATH", &joined)]);
        let out = fx.start().args(["--cargo", program]).env(env).run();
        assert_eq!(out.code, 0, "{entry} {program}: {}", out.all());
        let elsewhere: Vec<bool> = fx
            .calls()
            .iter()
            .map(|call| std::path::Path::new(&call.cwd) != fx.repo)
            .collect();
        assert_eq!(
            elsewhere,
            [true, true],
            "the listing and the run reach the invoking checkout's program from the worktree"
        );
    }
    fx.clear();
    let env = fixture::with(
        &fx.env,
        &[
            ("CARGO_HOME", OsStr::new("home")),
            ("RUSTUP_HOME", OsStr::new("link/../rustup")),
        ],
    );
    let out = fx.start().env(env).run();
    assert_eq!(out.code, 0, "{}", out.all());
    let homes: Vec<(Option<String>, Option<String>)> = fx
        .calls()
        .iter()
        .map(|call| {
            (
                call.var("CARGO_HOME").map(str::to_owned),
                call.var("RUSTUP_HOME").map(str::to_owned),
            )
        })
        .collect();
    let expected = (
        Some(fx.repo.join("home").to_string_lossy().into_owned()),
        Some(
            fx.repo
                .join("link/../rustup")
                .to_string_lossy()
                .into_owned(),
        ),
    );
    assert_eq!(homes, [expected.clone(), expected]);
}

#[test]
fn the_lock_copy_keeps_a_lock_file_or_link_the_head_tracks() {
    let fx = Fixture::new("lock-copy");
    let lock = fx.repo.join("Cargo.lock");
    let mut heads = Vec::new();
    for (name, target) in [
        ("linked", fx.state.join("sentinel")),
        ("dangling", fx.state.join("absent")),
    ] {
        fs::remove_file(&lock).expect("the lock is removed");
        std::os::unix::fs::symlink(&target, &lock).expect("the link is made");
        fx.git(&["add", "-f", "Cargo.lock"]);
        heads.push((name, fx.commit(&format!("track a {name} lock"))));
        fx.git(&["rm", "-q", "--cached", "Cargo.lock"]);
        fs::remove_file(&lock).expect("the link is removed");
        fs::write(&lock, "# lock\n").expect("the lock is written");
        fx.commit(&format!("untrack the {name} lock"));
    }
    fs::write(fx.state.join("sentinel"), "sentinel\n").expect("the sentinel is written");
    fs::write(&lock, "# tracked\n").expect("the lock is written");
    fx.git(&["add", "-f", "Cargo.lock"]);
    fx.write(
        &lib_rs(),
        "pub fn one() -> u32 { 1 }\npub fn three() -> u32 { 3 }\n",
    );
    let tracked = fx.commit("track a lock");
    fx.git(&["rm", "-q", "--cached", "Cargo.lock"]);
    fs::write(&lock, "# lock\n").expect("the lock is written");
    fx.commit("untrack the lock");
    fx.plan(&Plan::default());
    for (name, head) in &heads {
        for stale in fx.reports() {
            fs::remove_file(stale).expect("a stale report is removed");
        }
        let out = fx.start().base(&fx.head).head(head).run();
        assert_eq!(
            (out.code, out.stdout.as_str()),
            (0, "mutants: 0 listed\n"),
            "{name}: {}",
            out.all()
        );
    }
    assert_eq!(
        fs::read_to_string(fx.state.join("sentinel")).expect("UTF-8"),
        "sentinel\n",
        "the copy does not write through a tracked link"
    );
    assert!(
        fs::symlink_metadata(fx.state.join("absent")).is_err(),
        "the copy does not create a dangling link's target"
    );
    fx.plan(&Plan::caught(&one_mutant("2:1: m")));
    let out = fx.start().base(&fx.head).head(&tracked).run();
    assert_eq!(out.code, 0, "{}", out.all());
    assert_eq!(
        fx.calls()[0].lock.as_deref(),
        Some("# tracked\n"),
        "the head's own Cargo.lock stays"
    );
    assert_eq!(fs::read_to_string(&lock).expect("UTF-8"), "# lock\n");
}

#[test]
fn replace_refs_leave_the_compared_commits_as_they_are() {
    let fx = Fixture::new("replace");
    let tree = fx
        .git(&["rev-parse", &format!("{}^{{tree}}", fx.head)])
        .trim()
        .to_owned();
    let replacement = fx
        .git(&["commit-tree", &tree, "-m", "replacement"])
        .trim()
        .to_owned();
    fx.git(&["replace", &fx.base, &replacement]);
    fx.plan(&Plan::caught(&one_mutant("2:1: m")));
    let out = fx.start().run();
    assert_eq!(out.code, 0, "{}", out.all());
    let diff = only(run_files(&fx.artifacts, "diff.patch"));
    let expected = fx.git(&[
        "--no-replace-objects",
        fixture::DIFF[0],
        fixture::DIFF[1],
        &fx.base,
        &fx.head,
        "--",
        SOURCE,
    ]);
    assert!(!expected.is_empty());
    assert_eq!(fs::read_to_string(diff).expect("UTF-8"), expected);
}

#[test]
fn the_user_diff_settings_and_hooks_leave_the_patch_and_the_worktree_unchanged() {
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::new("diff-settings");
    let mut lines: Vec<String> = (1..31)
        .map(|n| {
            if n % 7 == 0 {
                String::new()
            } else {
                format!("line {n}")
            }
        })
        .collect();
    let mut moved: Vec<String> = (1..21).map(|n| format!("moved {n}")).collect();
    fx.write(
        &format!("{SOURCE}/long.rs"),
        &format!("{}\n", lines.join("\n")),
    );
    fx.write(
        &format!("{SOURCE}/old.rs"),
        &format!("{}\n", moved.join("\n")),
    );
    let base = fx.commit("long file");
    lines[9] = "changed 10".to_owned();
    lines[21] = "changed 22".to_owned();
    moved[4] = "edited 5".to_owned();
    fx.write(
        &format!("{SOURCE}/long.rs"),
        &format!("{}\n", lines.join("\n")),
    );
    fs::remove_file(fx.repo.join(SOURCE).join("old.rs")).expect("the old file is removed");
    fx.write(
        &format!("{SOURCE}/zz.rs"),
        &format!("{}\n", moved.join("\n")),
    );
    let head = fx.commit("two hunks and a rename");
    let expected = fx.git(&[
        fixture::DIFF[0],
        fixture::DIFF[1],
        &base,
        &head,
        "--",
        SOURCE,
    ]);
    assert_eq!(
        expected.matches("\n@@ ").count(),
        3,
        "the clean patch holds three hunks"
    );
    assert!(expected.contains("rename to crates/kestrike/src/zz.rs"));
    assert!(expected.find("long.rs") < expected.find("zz.rs"));
    for (name, body) in [
        ("convert", r#"tr a-z A-Z < "$1""#),
        ("external", "echo EXTERNAL"),
    ] {
        let script = fx.state.join(name);
        fs::write(&script, format!("#!/bin/sh\n{body}\n")).expect("the script is written");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("it is executable");
    }
    fs::write(fx.state.join("order"), format!("{SOURCE}/zz.rs\n"))
        .expect("the order file is written");
    let config = format!(
        "[color]\n    ui = always\n    diff = always\n[diff]\n    noprefix = true\n    mnemonicPrefix = true\n    \
         external = {}\n    algorithm = patience\n    context = 10\n    interHunkContext = 20\n    \
         suppressBlankEmpty = true\n    renames = false\n    orderFile = {}\n[diff \"conv\"]\n    textconv = {}\n\
         [core]\n    bigFileThreshold = 1\n    abbrev = 7\n",
        fx.state.join("external").display(),
        fx.state.join("order").display(),
        fx.state.join("convert").display()
    );
    fs::write(fx.state.join("gitconfig"), config).expect("the user configuration is written");
    fs::write(fx.repo.join(".git/info/attributes"), "*.rs diff=conv\n")
        .expect("the attributes are written");
    let hook = fx.repo.join(".git/hooks/post-checkout");
    fs::write(
        &hook,
        format!("#!/bin/sh\ntouch {}\n", fx.state.join("hooked").display()),
    )
    .expect("the hook is written");
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).expect("the hook is executable");
    let name = format!("{SOURCE}/long.rs:10:1: m");
    fx.plan(&Plan::caught(&listed(
        &format!("{SOURCE}/long.rs"),
        &[name],
    )));
    let env = fixture::with(&fx.env, &[("GIT_DIFF_OPTS", OsStr::new("--unified=0"))]);
    let out = fx.start().base(&base).head(&head).env(env).run();
    assert_eq!(out.code, 0, "{}", out.all());
    let diff = only(run_files(&fx.artifacts, "diff.patch"));
    assert_eq!(fs::read_to_string(diff).expect("UTF-8"), expected);
    assert!(
        !fx.state.join("hooked").exists(),
        "the worktree add runs no hook"
    );
}

#[test]
fn a_shard_applies_the_limit_to_its_slice_and_records_k_and_n() {
    let fx = Fixture::new("shard");
    let names: Vec<String> = (0..5)
        .map(|n| format!("{SOURCE}/lib.rs:{n}:1: m"))
        .collect();
    fx.plan(&Plan {
        host: Some("x86_64-unknown-linux-gnu"),
        ..Plan::caught(&listed(&lib_rs(), &names))
    });
    assert_eq!(fx.start().args(["--max-mutants", "2"]).run().code, 2);
    let sliced = fx
        .start()
        .args(["--max-mutants", "2", "--shard", "0/2"])
        .run();
    assert_eq!(
        sliced.code,
        2,
        "a three-mutant slice is above the limit: {}",
        sliced.all()
    );
    assert!(fx.builds().is_empty());
    let out = fx
        .start()
        .args(["--max-mutants", "2", "--shard", "1/2"])
        .run();
    assert_eq!(out.code, 0, "{}", out.all());
    let line = format!(
        "mutants: {} against {} on x86_64, shard 1/2: 2 listed, 2 caught, 0 missed, 0 timeout, 0 unviable; complete",
        short(&fx.head),
        short(&fx.base)
    );
    assert_eq!(out.lines()[0], line);
    let report = fx.report(Some(&out));
    assert_eq!(
        kestrike_tools::json::text(get(&report, "shard")),
        r#"{"k":1,"n":2}"#
    );
    assert_eq!(string(get(&report, "machine")), "x86_64");
    let Value::Array(entries) = get(&report, "mutants") else {
        panic!("mutants is an array")
    };
    let kept: Vec<String> = entries
        .iter()
        .map(|entry| match entry {
            Value::Object(entry) => string(get(entry, "name")),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(kept, names[3..]);
    let calls = fx.calls();
    for call in &calls[calls.len() - 2..] {
        assert_eq!(call.value("--shard"), "1/2");
    }
}

#[test]
fn a_head_configuration_and_a_listing_that_are_not_utf_8_read_as_the_runner_reads_them() {
    let fx = Fixture::new("not-utf-8-files");
    let config = [b"# \xff a comment\n".as_slice(), fixture::CONFIG.as_bytes()].concat();
    fs::write(fx.repo.join(".cargo/mutants.toml"), &config).expect("the configuration is written");
    fx.write(
        &lib_rs(),
        "pub fn one() -> u32 { 1 }\npub fn three() -> u32 { 3 }\n",
    );
    let head = fx.commit("a configuration that is not UTF-8");
    fs::write(fx.repo.join(".cargo/mutants.toml"), fixture::CONFIG)
        .expect("the invoking checkout's copy");
    fx.plan(&Plan::caught(&one_mutant("2:1: m")));
    let out = fx.start().base(&fx.head).head(&head).run();
    assert_eq!(
        out.code,
        0,
        "the head's configuration is decoded with replacement: {}",
        out.all()
    );
    let report = fx.report(Some(&out));
    assert_eq!(string(get(&report, "debug_assertions")), "false");
    assert_eq!(
        string(get(&report, "config_sha256")),
        sha256(&config),
        "the digest is of the raw bytes"
    );
    fx.clear();
    fx.plan(&Plan {
        raw_listing: Some(b"\xff".to_vec()),
        ..Plan::new(&one_mutant("2:1: m"), &[])
    });
    let out = fx.start().base(&fx.head).head(&head).run();
    assert_eq!(out.code, 1, "{}", out.all());
    let found = reason(&fx.report(Some(&out))).unwrap_or_default();
    assert!(
        found.starts_with("the listing does not parse: "),
        "a listing that is not UTF-8: {found}"
    );
    assert!(fx.builds().is_empty());
}
