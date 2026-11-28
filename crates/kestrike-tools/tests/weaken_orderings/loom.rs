//! The run's loom rows: the verdict of each test outcome, a decided row's agreement, the rebuild each row
//! needs, and the report's members.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use kestrike_tools::json::Value;

use super::fixture::*;

pub fn named_failure_kills(fixture: &Fixture) {
    let revision = fixture.commit();
    let before = status(&fixture.repo);
    let tests = run_tests();
    let (fail, at) = (format!("fail:{RUN_FAILURE}"), run_at());
    let modes: &[(&str, &str)] = &[("planted", &fail), ("at", &at)];
    let planned = plan(&[(&tests[0], modes), (&tests[1], modes)]);
    let ran = fixture.run_with(
        &[RUN_FENCE],
        Opts {
            plan: Some(planned),
            env: env(&[("CARGO_BUILD_JOBS", "3")]),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    assert!(
        ran.stderr
            .contains(&format!("running the committed revision {revision}")),
        "{}",
        ran.stderr
    );
    let report = ran.report();
    assert_eq!(results(report, RUN_FENCE), ["killed"; 2]);
    assert_eq!(status(&fixture.repo), before);
    assert_eq!(string(get(report, "revision")), revision);
    let pins = get(report, "pins");
    let stable = workflow_pin(&fixture.repo, "STABLE");
    assert_eq!(string(get(pins, "STABLE")), stable);
    assert_eq!(
        string(get(pins, "NIGHTLY")),
        workflow_pin(&fixture.repo, "NIGHTLY")
    );
    assert_eq!(
        string(get(pins, "loom resolved")),
        format!("v{}", workflow_pin(&fixture.repo, "LOOM"))
    );
    assert_eq!(string(get(pins, "rustc")), format!("rustc +{stable}-stub"));
    assert_eq!(string(get(pins, "host")), std::env::consts::ARCH);
    // SAFETY: `sysconf` takes a constant name and touches no memory of the caller.
    let online = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    assert_eq!(number(get(pins, "cpus")), i64::from(online as i32));
    assert_eq!(string(get(pins, "CARGO_BUILD_JOBS")), "3");
    let work = fixture.resolved("work");
    assert_eq!(
        fs::read_to_string(work.join("copy/Cargo.lock")).expect("reads"),
        "stub lock\n"
    );
    assert_eq!(
        string(get(pins, "Cargo.lock sha256")),
        kestrike_tools::python::hexdigest(b"stub lock\n")
    );
    let baseline = items(get(report, "baseline"));
    let exits: Vec<i64> = baseline
        .iter()
        .map(|entry| number(get(entry, "exit")))
        .collect();
    assert_eq!(exits, [0, 0]);
    let planted = row_results(report, RUN_FENCE);
    let exits: Vec<i64> = planted
        .iter()
        .map(|entry| number(get(entry, "exit")))
        .collect();
    assert_eq!(exits, [101, 101]);
    let mut catalog = fixture.catalog.clone();
    let fence = row(&mut catalog, RUN_FENCE).clone();
    let record = get(get(report, "rows"), RUN_FENCE);
    let plant = get(record, "plant");
    for key in ["path", "find", "replace"] {
        assert_eq!(get(plant, key), fence.get(key).expect("a member"), "{key}");
    }
    assert_eq!(get(record, "expected"), &Value::Null);
    let seconds = |value: &Value| match value {
        Value::Float(seconds) => *seconds,
        _ => panic!("{value:?} is no float"),
    };
    assert!(seconds(get(report, "seconds")) >= seconds(get(record, "seconds")));
    let index = row_ids(&fixture.catalog)
        .iter()
        .position(|id| id == RUN_FENCE)
        .expect("the row stands");
    let label = format!("-row{index:02}-");
    let mut outputs = BTreeSet::new();
    for entry in baseline.iter().chain(planted) {
        let test = string(get(entry, "test"));
        assert_eq!(
            string(get(entry, "command")),
            format!(
                "RUSTFLAGS=\"--cfg loom\" cargo +{stable} test -p kestrike --lib --release {test} -- --exact"
            )
        );
        let output = string(get(entry, "output"));
        assert_eq!(string(get(entry, "digest")), sha256_of(Path::new(&output)));
        assert!(
            Path::new(&output).starts_with(work.join("evidence")),
            "{output}"
        );
        seconds(get(entry, "seconds"));
        outputs.insert(output);
    }
    assert_eq!(outputs.len(), 4);
    for entry in planted {
        assert!(string(get(entry, "output")).contains(&label));
    }
    let log = fixture.lines(".log");
    let target = format!("{}/target-loom", work.display());
    for line in &log {
        assert!(
            line.contains(" --cfg loom ")
                && line.contains(&target)
                && line.contains(" [] None never/false "),
            "{line}"
        );
    }
    let path = string(fence.get("path").expect("a path"));
    let original = fs::read_to_string(fixture.repo.join(&path)).expect("reads");
    let find = string(fence.get("find").expect("a find"));
    let weakened = original.replace(&find, &string(fence.get("replace").expect("a replace")));
    assert_eq!(original.matches(&find).count(), 1);
    let digests: BTreeSet<String> = log
        .iter()
        .filter(|line| line.contains(" planted "))
        .map(|line| line.rsplit(' ').next().expect("a digest").to_owned())
        .collect();
    assert_eq!(
        digests,
        BTreeSet::from([kestrike_tools::python::hexdigest(weakened.as_bytes())])
    );
    fixture.assert_restored(&work);
}

#[test]
fn the_named_failure_kills_and_the_checkout_is_unchanged() {
    named_failure_kills(&Fixture::new("named"));
}

#[test]
fn the_run_tests_hold_under_a_temporary_directory_behind_a_symbolic_link() {
    let fixture = Fixture::behind_link("linked");
    assert_ne!(fixture.given, fixture.base);
    assert_eq!(
        fixture.given.canonicalize().expect("resolves"),
        fixture.base
    );
    named_failure_kills(&fixture);
}

#[test]
fn a_named_failure_at_another_assertion_is_no_verdict() {
    let fixture = Fixture::new("another");
    fixture.commit();
    let (path, line) = run_site();
    let fail = format!("fail:protection violated: {RUN_FAILURE}");
    let at = format!("{path}:{}", line + 40);
    let modes: &[(&str, &str)] = &[("planted", &fail), ("at", &at)];
    let tests = run_tests();
    let planned = plan(&[(&tests[0], modes), (&tests[1], modes)]);
    let ran = fixture.run_with(
        &[RUN_FENCE],
        Opts {
            plan: Some(planned),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    let first = &row_results(ran.report(), RUN_FENCE)[0];
    assert_eq!(string(get(first, "result")), "no verdict");
    assert_eq!(
        string(get(first, "reason")),
        "failed with another text or at another assertion"
    );
}

#[test]
fn the_loom_build_runs_without_the_operators_build_overrides() {
    let fixture = Fixture::new("overrides");
    fixture.commit();
    let elsewhere = fixture.base.join("elsewhere").display().to_string();
    let mut ambient = env(&[
        ("RUSTC_WRAPPER", "sccache"),
        ("RUSTC", "/elsewhere/rustc"),
        ("CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS", "false"),
        (
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER",
            "/elsewhere/run",
        ),
        ("CARGO_BUILD_TARGET", "x86_64-unknown-linux-gnu"),
        ("CARGO_BUILD_BUILD_DIR", &elsewhere),
        ("RUSTDOCFLAGS", "--cfg x"),
    ]);
    ambient.push(("CARGO_BUILD_JOBS", None));
    let ran = fixture.run_with(
        &[RUN_FENCE],
        Opts {
            env: ambient,
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    assert_eq!(
        get(get(ran.report(), "pins"), "CARGO_BUILD_JOBS"),
        &Value::Null
    );
    let target = fixture.resolved("work/target-loom").display().to_string();
    let calls = fixture.stub_calls();
    assert!(!calls.is_empty());
    for call in calls {
        let wanted = [
            ("CARGO_BUILD_BUILD_DIR", target.as_str()),
            ("CARGO_TARGET_DIR", target.as_str()),
            ("RUSTFLAGS", "--cfg loom"),
        ]
        .map(|(name, value)| (name.to_owned(), value.to_owned()));
        assert_eq!(pairs(get(&call, "env")), wanted.into(), "{call:?}");
    }
}

#[test]
fn a_pass_under_the_plant_survives() {
    let fixture = Fixture::new("pass");
    fixture.commit();
    let ran = fixture.run_rows(&[RUN_FENCE]);
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    assert_eq!(results(ran.report(), RUN_FENCE), ["survived"; 2]);
    assert_eq!(items(get(ran.report(), "mismatched")), &[]);
    assert_eq!(items(get(ran.report(), "no verdict")), &[]);
}

#[test]
fn every_other_outcome_is_no_verdict() {
    let fixture = Fixture::new("outcomes");
    fixture.commit();
    let reasons = [
        ("build", "a build failure"),
        (
            "fail:another assertion",
            "failed with another text or at another assertion",
        ),
        ("none", "the test is absent: no test matched its name"),
        ("ignored", "the test is ignored"),
        ("norebuild", "no evidence that kestrike rebuilt"),
        ("crash", "the test crashed: its run ended without a summary"),
    ];
    let (tests, at) = (run_tests(), run_at());
    for (mode, reason) in reasons {
        let work = fixture.work(&format!("work-{}", mode.replace([':', ' '], "-")));
        let planned = plan(&[(&tests[0], &[("planted", mode), ("at", &at)])]);
        let ran = fixture.run_with(
            &[RUN_FENCE],
            Opts {
                work: Some(work),
                plan: Some(planned),
                ..Opts::default()
            },
        );
        assert_eq!(ran.code(), Some(0), "{mode}: {}", ran.stderr);
        let first = &row_results(ran.report(), RUN_FENCE)[0];
        assert_eq!(string(get(first, "result")), "no verdict", "{mode}");
        assert_eq!(string(get(first, "reason")), reason, "{mode}");
        assert_eq!(strings_of(get(ran.report(), "no verdict")), [RUN_FENCE]);
        assert!(
            ran.stdout.contains("\"no verdict\": [\"fill-run-fence\"]"),
            "{}",
            ran.stdout
        );
    }
}

#[test]
fn a_red_baseline_stops_the_run_with_no_row_result() {
    let fixture = Fixture::new("red");
    fixture.commit();
    let tests = run_tests();
    let fail = format!("fail:{RUN_FAILURE}");
    for mode in [fail.as_str(), "none", "ignored"] {
        let name = format!("red-{}", mode.split(':').next().unwrap_or_default());
        let planned = plan(&[(&tests[0], &[("clean", mode)])]);
        let ran = fixture.run_with(
            &[RUN_FENCE],
            Opts {
                work: Some(fixture.work(&name)),
                plan: Some(planned),
                ..Opts::default()
            },
        );
        assert_eq!(ran.code(), Some(3), "{mode}: {}", ran.stderr);
        assert!(ran.report.is_none());
        assert!(ran.stderr.contains("\"rows\": {}"), "{}", ran.stderr);
        let progress = read_json(&fixture.resolved(&name).join("progress.json"));
        assert_eq!(get(&progress, "rows"), &object(&[]));
    }
}

#[test]
fn a_red_test_of_a_later_row_stops_the_run_before_any_plant() {
    let fixture = Fixture::new("red-later");
    fixture.commit();
    let violation = format!("violation:{JOIN_FREED}");
    let planned = plan(&[("join-production", &[("clean", &violation)])]);
    let ran = fixture.run_with(
        &[RUN_FENCE, JOIN_ROW],
        Opts {
            plan: Some(planned),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(3), "{}", ran.stderr);
    assert!(ran.report.is_none());
    let phases: Vec<String> = fixture
        .lines(".lane")
        .iter()
        .map(|line| line.split(' ').next().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(phases, ["clean"]);
    assert_eq!(fixture.logged("planted"), Vec::<String>::new());
}

fn fence_entries() -> Value {
    let (_, needs) = seeded()
        .into_iter()
        .find(|(id, _)| *id == RUN_FENCE)
        .expect("seeded");
    Value::Array(needs)
}

fn mismatched(ran: &Ran) -> Vec<String> {
    strings_of(get(ran.report(), "mismatched"))
}

#[test]
fn a_result_that_differs_from_a_decided_row_fails_and_names_it() {
    let fixture = Fixture::new("differs");
    fixture.commit_with(|catalog| decided(catalog, RUN_FENCE, "kill", fence_entries()));
    let ran = fixture.run_rows(&[RUN_FENCE]);
    assert_eq!(ran.code(), Some(1), "{}", ran.stderr);
    assert_eq!(mismatched(&ran), [RUN_FENCE]);
    let record = get(get(ran.report(), "rows"), RUN_FENCE);
    assert_eq!(get(record, "agrees"), &Value::Bool(false));
    assert_eq!(string(get(record, "expected")), "killed");
}

#[test]
fn a_kill_row_agrees_only_when_every_test_is_killed() {
    let fixture = Fixture::new("kill-row");
    fixture.commit_with(|catalog| decided(catalog, RUN_FENCE, "kill", fence_entries()));
    let (tests, fail, at) = (run_tests(), format!("fail:{RUN_FAILURE}"), run_at());
    let killed: &[(&str, &str)] = &[("planted", &fail), ("at", &at)];
    let one = fixture.run_with(
        &[RUN_FENCE],
        Opts {
            plan: Some(plan(&[(&tests[0], killed)])),
            ..Opts::default()
        },
    );
    assert_eq!(
        (one.code(), mismatched(&one)),
        (Some(1), vec![RUN_FENCE.to_owned()]),
        "{}",
        one.stderr
    );
    let built = fixture.run_with(
        &[RUN_FENCE],
        Opts {
            work: Some(fixture.work("built")),
            plan: Some(plan(&[
                (&tests[0], killed),
                (&tests[1], &[("planted", "build")]),
            ])),
            ..Opts::default()
        },
    );
    assert_eq!(built.code(), Some(1), "{}", built.stderr);
    assert_eq!(mismatched(&built), [RUN_FENCE]);
    assert_eq!(strings_of(get(built.report(), "no verdict")), [RUN_FENCE]);
    let every = fixture.run_with(
        &[RUN_FENCE],
        Opts {
            work: Some(fixture.work("killed")),
            plan: Some(plan(&[(&tests[0], killed), (&tests[1], killed)])),
            ..Opts::default()
        },
    );
    assert_eq!(
        (every.code(), mismatched(&every)),
        (Some(0), vec![]),
        "{}",
        every.stderr
    );
    assert_eq!(results(every.report(), RUN_FENCE), ["killed"; 2]);
    let record = get(get(every.report(), "rows"), RUN_FENCE);
    assert_eq!(get(record, "agrees"), &Value::Bool(true));
}

#[test]
fn a_survives_row_agrees_only_when_its_tests_pass() {
    let fixture = Fixture::new("survives-row");
    let tests = run_tests();
    let passed = object(&[
        ("reason", text("planted")),
        (
            "passed",
            Value::Array(vec![object(&[
                ("lane", text("loom")),
                ("tests", texts(&[&tests[0], &tests[1]])),
            ])]),
        ),
    ]);
    fixture.commit_with(|catalog| decided(catalog, RUN_FENCE, "survives", passed));
    let ran = fixture.run_rows(&[RUN_FENCE]);
    assert_eq!(
        (ran.code(), mismatched(&ran)),
        (Some(0), vec![]),
        "{}",
        ran.stderr
    );
    let fail = format!("fail:{RUN_FAILURE}");
    let killed = fixture.run_with(
        &[RUN_FENCE],
        Opts {
            work: Some(fixture.work("killed")),
            plan: Some(plan(&[(&tests[0], &[("planted", &fail)])])),
            ..Opts::default()
        },
    );
    assert_eq!(killed.code(), Some(1), "{}", killed.stderr);
    assert_eq!(mismatched(&killed), [RUN_FENCE]);
}

#[test]
fn a_later_row_needs_its_own_rebuild() {
    let fixture = Fixture::new("rebuild");
    let ids = row_ids(&fixture.catalog);
    let at = |id: &str| ids.iter().position(|held| held == id).expect("a row");
    assert!(at(DEPART_ROW) < at(RUN_FENCE));
    let (tests, depart) = (run_tests(), depart_tests());
    assert!(!tests.contains(&depart[0]));
    fixture.commit();
    let norebuild: &[(&str, &str)] = &[("planted", "norebuild")];
    let planned = plan(&[(&tests[0], norebuild), (&tests[1], norebuild)]);
    let ran = fixture.run_with(
        &[RUN_FENCE, DEPART_ROW],
        Opts {
            plan: Some(planned),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    assert_eq!(results(ran.report(), DEPART_ROW), ["survived"; 4]);
    let fence: BTreeSet<String> = results(ran.report(), RUN_FENCE).into_iter().collect();
    assert_eq!(fence, BTreeSet::from(["no verdict".to_owned()]));
}

#[test]
fn a_test_a_row_names_twice_runs_once() {
    let fixture = Fixture::new("twice");
    let tests = run_tests();
    fixture.commit_with(|catalog| {
        needing(
            catalog,
            RUN_FENCE,
            vec![entry("loom", &[&tests[0], &tests[0]], RUN_FAILURE)],
        );
        let join = entry("genmc", &["join-production", "join-production"], JOIN_FREED);
        needing(catalog, JOIN_ROW, vec![join.clone(), join]);
    });
    let ran = fixture.run_rows(&[RUN_FENCE, JOIN_ROW]);
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    assert_eq!(fixture.logged("planted").len(), 1);
    let planted: Vec<String> = fixture
        .lines(".lane")
        .iter()
        .filter(|line| line.starts_with("planted "))
        .map(|line| line.split(' ').skip(3).collect::<Vec<_>>().join(" "))
        .collect();
    assert_eq!(planted, ["genmc pr join-production"]);
    for (id, count) in [(RUN_FENCE, 2), (JOIN_ROW, 4)] {
        let entries = row_results(ran.report(), id);
        let outputs: BTreeSet<String> = entries
            .iter()
            .map(|entry| string(get(entry, "output")))
            .collect();
        assert_eq!((entries.len(), outputs.len()), (count, 1), "{entries:?}");
        let digests: BTreeSet<String> = entries
            .iter()
            .map(|entry| string(get(entry, "digest")))
            .collect();
        let output = outputs.first().expect("one output");
        assert_eq!(digests, BTreeSet::from([sha256_of(Path::new(output))]));
    }
}

#[test]
fn a_row_id_never_names_an_output_path() {
    let fixture = Fixture::new("ids");
    fixture.commit_with(|catalog| {
        row(catalog, RUN_FENCE).insert("id", text("baseline"));
        row(catalog, JOIN_ROW).insert("id", text("../../escape"));
    });
    let work = fixture.work("ids");
    let ran = fixture.run_with(
        &["baseline", "../../escape"],
        Opts {
            work: Some(work),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    let report = ran.report();
    let mut ids: Vec<String> = match get(report, "rows") {
        Value::Object(rows) => rows.iter().map(|(id, _)| id.to_string()).collect(),
        _ => panic!("the rows are an object"),
    };
    ids.sort();
    assert_eq!(ids, ["../../escape", "baseline"]);
    let mut outputs: Vec<String> = items(get(report, "baseline"))
        .iter()
        .chain(row_results(report, "baseline"))
        .chain(row_results(report, "../../escape"))
        .map(|entry| string(get(entry, "output")))
        .collect();
    let evidence = fixture.resolved("ids/evidence");
    for output in &outputs {
        let resolved = kestrike_tools::paths::resolve(Path::new(output)).expect("resolves");
        assert!(resolved.starts_with(&evidence), "{output}");
    }
    let count = outputs.len();
    outputs.sort();
    outputs.dedup();
    assert_eq!(outputs.len(), count);
    let escaped: Vec<String> = fs::read_dir(&fixture.base)
        .expect("lists")
        .map(|entry| {
            entry
                .expect("lists")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with("escape"))
        .collect();
    assert_eq!(escaped, Vec::<String>::new());
}

#[test]
fn a_row_no_model_runs_is_skipped_and_agrees() {
    let fixture = Fixture::new("skipped");
    let reason = object(&[
        ("reason", text("no model runs the site")),
        ("passed", Value::Array(Vec::new())),
    ]);
    fixture.commit_with(|catalog| decided(catalog, "word-install", "survives", reason));
    let ran = fixture.run_rows(&["word-install"]);
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    let skipped = get(get(ran.report(), "rows"), "word-install");
    assert_eq!(string(get(skipped, "result")), "skipped");
    assert_eq!(string(get(skipped, "reason")), "no model runs the site");
    assert_eq!(get(skipped, "agrees"), &Value::Bool(true));
    assert_eq!(items(get(ran.report(), "baseline")), &[]);
    let words: Vec<String> = fixture
        .stub_calls()
        .iter()
        .map(|call| strings_of(get(call, "args"))[1].clone())
        .collect();
    assert_eq!(words, ["tree"]);
}

#[test]
fn a_run_without_rows_selects_every_row() {
    let fixture = Fixture::new("every");
    fixture.commit();
    let ran = fixture.run_rows(&[]);
    assert!(matches!(ran.code(), Some(0 | 1)), "{}", ran.stderr);
    let ids: Vec<String> = match get(ran.report(), "rows") {
        Value::Object(rows) => rows.iter().map(|(id, _)| id.to_string()).collect(),
        _ => panic!("the rows are an object"),
    };
    assert_eq!(ids, row_ids(&fixture.catalog));
}

#[test]
fn an_unknown_row_stops_the_run() {
    let fixture = Fixture::new("unknown");
    fixture.commit();
    let ran = fixture.run_rows(&[RUN_FENCE, "no-such-row"]);
    assert_eq!(ran.code(), Some(2), "{}", ran.stderr);
    assert!(
        ran.stderr.contains("no catalog row named ['no-such-row']"),
        "{}",
        ran.stderr
    );
    assert!(ran.report.is_none());
    assert_eq!(fixture.lines(".log"), Vec::<String>::new());
}
