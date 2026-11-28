use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::super::execute::{GENMC_DEADLINE, GENMC_SETUP, Launch};
use super::super::halt::Halt;
use super::{Runner, Runs};
use crate::genmc::case::tests::{POSITIVE, POSITIVE_GRAPH};
use crate::json::{self, Text, Value};
use crate::orderings::check::GENMC;
use crate::orderings::sources::kernel_texts;
use crate::orderings::verdicts::tests::Lane;
use crate::paths::tests::Scratch;
use crate::process::Interrupt;

fn top() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the checkout resolves")
}

thread_local! {
    static DEADLINE: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

/// `lane_evidence` leaves the complete evidence of a positive `join-production` run, as the lane writes
/// it, in the evidence directory the call names, and records the call's deadline.
fn lane_evidence(
    launch: &Launch<'_>,
    env: Option<&[(OsString, OsString)]>,
    deadline: Duration,
    output: &Path,
) {
    assert_eq!(launch.grace, super::super::execute::STOP_GRACE);
    DEADLINE.with(|held| held.set(Some(deadline)));
    std::fs::write(output, "").expect("the lane's output writes");
    let evidence = env
        .and_then(|env| env.iter().find(|(name, _)| name == "EVIDENCE"))
        .map(|(_, value)| PathBuf::from(value))
        .expect("the lane is given its evidence directory");
    let declared =
        json::parse(&std::fs::read_to_string(top().join(GENMC)).expect("reads")).expect("parses");
    Lane::new(POSITIVE, POSITIVE_GRAPH, "0").write(&evidence, &declared);
}

/// The lane call's stand-in that leaves a positive case's evidence and reports the deadline.
fn expired(
    launch: &Launch<'_>,
    _: &[OsString],
    _: &Path,
    env: Option<&[(OsString, OsString)]>,
    deadline: Duration,
    output: &Path,
) -> Result<(Option<i32>, f64), Halt> {
    lane_evidence(launch, env, deadline, output);
    Ok((None, 1.0))
}

/// The lane call's stand-in that leaves the same evidence and reports the lane's exit 0.
fn finished(
    launch: &Launch<'_>,
    _: &[OsString],
    _: &Path,
    env: Option<&[(OsString, OsString)]>,
    deadline: Duration,
    output: &Path,
) -> Result<(Option<i32>, f64), Halt> {
    lane_evidence(launch, env, deadline, output);
    Ok((Some(0), 1.0))
}

/// `standing` is a runner over this checkout as its copy, with the declaration `change` gives, the run's
/// pins, an evidence directory under `scratch` and `execute` for each test's run.
fn standing<'l>(
    scratch: &Scratch,
    launch: &'l Launch<'l>,
    execute: super::Execute,
    change: impl FnOnce(&mut Value),
) -> Runner<'l> {
    let top = top();
    let mut declared =
        json::parse(&std::fs::read_to_string(top.join(GENMC)).expect("reads")).expect("parses");
    let Value::Object(object) = &declared else {
        panic!("the declaration is an object");
    };
    let Some(Value::String(package)) = object.get("package") else {
        panic!("the declaration names its package");
    };
    let kernels = kernel_texts(&top.join(package.to_string())).expect("the kernels read");
    change(&mut declared);
    let pins = [
        ("STABLE", "1.99.0"),
        ("NIGHTLY", "nightly-2026-07-27"),
        ("LOOM", "0.7.2"),
    ]
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .into();
    let evidence = scratch.0.join("evidence");
    std::fs::create_dir(&evidence).expect("made");
    Runner {
        work: scratch.0.clone(),
        copy: top,
        evidence,
        revision: "0".repeat(40),
        pins,
        environ: Vec::new(),
        launch,
        execute,
        serial: 0,
        rebuilt: None,
        declared,
        kernels,
        reads: std::cell::RefCell::new(BTreeMap::new()),
    }
}

/// A lane call past its deadline gives every case of the call no verdict, whatever a case's own output
/// and exit, and each result keeps the exit the lane recorded for its case: the complete evidence of a
/// positive `join-production` that a finished call judges survived. The call's deadline is each case's
/// share plus the lane's setup, and its stop's grace the run's.
#[test]
fn a_genmc_lane_past_its_deadline_gives_no_verdict_for_every_case() {
    let field = |result: &Value, key: &str| match result {
        Value::Object(result) => result.get(key).cloned().expect("a member"),
        _ => panic!("a result is an object"),
    };
    let cases = [
        Text::from("join-production"),
        Text::from("credit-seq-empty"),
    ];
    let control = Scratch::new("weaken-lane-finished");
    let interrupt = Interrupt::new();
    let launch = Launch::new(&interrupt);
    let mut runner = standing(&control, &launch, finished, |_| {});
    let mut runs: Runs = BTreeMap::new();
    let judged = runner
        .genmc(&cases[..1], "", Some(&Text::from("row00")), &mut runs)
        .expect("the lane is judged");
    assert_eq!(
        field(&judged[0], "result"),
        Value::String(Text::from("survived")),
        "{judged:?}"
    );
    let scratch = Scratch::new("weaken-lane-deadline");
    let mut runner = standing(&scratch, &launch, expired, |_| {});
    let mut runs: Runs = BTreeMap::new();
    let results = runner
        .genmc(&cases, "", Some(&Text::from("row00")), &mut runs)
        .expect("the lane is judged");
    let deadline = DEADLINE.with(std::cell::Cell::get);
    assert_eq!(
        deadline,
        Some(GENMC_DEADLINE * 2 + GENMC_SETUP),
        "two fresh cases"
    );
    for result in &results {
        assert_eq!(field(result, "lane_exit"), Value::Null);
        assert_eq!(
            field(result, "result"),
            Value::String(Text::from("no verdict"))
        );
        assert_eq!(
            field(result, "reason"),
            Value::String(Text::from("the lane passed its deadline"))
        );
    }
    assert_eq!(results.len(), 2);
    assert_eq!(
        field(&results[0], "exit"),
        json::parse("0").expect("parses")
    );
}

static PROFILE: std::sync::Mutex<Vec<OsString>> = std::sync::Mutex::new(Vec::new());

/// The lane call's stand-in that records its command line and reports the deadline.
fn recording(
    launch: &Launch<'_>,
    argv: &[OsString],
    cwd: &Path,
    env: Option<&[(OsString, OsString)]>,
    deadline: Duration,
    output: &Path,
) -> Result<(Option<i32>, f64), Halt> {
    *PROFILE.lock().expect("unpoisoned") = argv.to_vec();
    expired(launch, argv, cwd, env, deadline, output)
}

/// The `pr` profile is a set as Python builds one of its JSON value: an object's keys name its cases, so a
/// case that is one of them runs under `pr`.
#[test]
fn a_pr_profile_that_is_an_object_names_its_keys() {
    let scratch = Scratch::new("weaken-profile");
    let interrupt = Interrupt::new();
    let launch = Launch::new(&interrupt);
    let mut runner = standing(&scratch, &launch, recording, |declared| {
        let Value::Object(declared) = declared else {
            panic!("the declaration is an object");
        };
        let Some(Value::Object(profiles)) = declared.get_mut("profiles") else {
            panic!("the declaration holds profiles");
        };
        profiles.insert(
            "pr",
            json::parse(r#"{"join-production": 1}"#).expect("parses"),
        );
    });
    let mut runs: Runs = BTreeMap::new();
    runner
        .genmc(&[Text::from("join-production")], "", None, &mut runs)
        .expect("the lane is judged");
    let argv = PROFILE.lock().expect("unpoisoned").clone();
    assert_eq!(argv[3], "pr", "{argv:?}");
}

/// A loom entry whose failure is a number ends the judgment with Python's type error, before any test
/// runs.
#[test]
fn a_loom_failure_that_is_no_text_fails_the_run() {
    let scratch = Scratch::new("weaken-failure-type");
    let interrupt = Interrupt::new();
    let launch = Launch::new(&interrupt);
    let mut runner = standing(&scratch, &launch, expired, |_| {});
    let entry = json::parse(r#"{"lane": "loom", "tests": ["storage::x::y"], "failure": 7}"#)
        .expect("parses");
    let Value::Object(entry) = entry else {
        panic!("an object");
    };
    let mut runs: Runs = BTreeMap::new();
    let ran = runner.each(&entry, None, &mut runs, &mut |_| Ok(()));
    match ran {
        Err(Halt::Failed(message)) => assert_eq!(
            message,
            "TypeError: 'in <string>' requires string as left operand, not int"
        ),
        other => panic!("{other:?}"),
    }
    assert!(runs.is_empty());
}

/// A file the run has read keeps the text of that first read, so a loom site's judgment under a plant reads
/// the model text the copy's check read.
#[test]
fn a_read_keeps_the_text_of_the_first_read() {
    let scratch = Scratch::new("weaken-reads");
    let interrupt = Interrupt::new();
    let launch = Launch::new(&interrupt);
    let mut runner = standing(&scratch, &launch, expired, |_| {});
    let copy = scratch.0.join("copy");
    std::fs::create_dir(&copy).expect("made");
    std::fs::write(copy.join("model.rs"), "first\n").expect("written");
    runner.copy = copy.clone();
    assert_eq!(runner.read("model.rs").expect("reads"), "first\n");
    std::fs::write(copy.join("model.rs"), "planted\n").expect("written");
    assert_eq!(runner.read("model.rs").expect("reads"), "first\n");
    assert!(runner.read("absent.rs").is_err());
    std::fs::write(copy.join("absent.rs"), "late\n").expect("written");
    assert!(
        runner.read("absent.rs").is_err(),
        "a failed first read stays failed"
    );
}

/// The `LOOM_` names of a merged configuration's `env` table, sorted; other tables and names stay out.
#[test]
fn the_loom_entries_of_a_configuration_are_its_sorted_loom_names() {
    let parsed = json::parse(
        r#"{"env": {"LOOM_Z": "1", "PATH": "/bin", "LOOM_A": {"value": "2"}}, "build": {"LOOM_B": 1}}"#,
    )
    .expect("parses");
    assert_eq!(
        super::loom_entries(&parsed),
        [Text::from("LOOM_A"), Text::from("LOOM_Z")]
    );
    assert!(super::loom_entries(&json::parse("[]").expect("parses")).is_empty());
}
