use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::super::execute::{Launch, POLL};
use super::super::halt::Halt;
use super::{Runner, Runs};
use crate::genmc::case::tests::{POSITIVE, POSITIVE_GRAPH, declaration, root as top};
use crate::json::{self, Text, Value};
use crate::orderings::sources::kernel_texts;
use crate::orderings::verdicts::tests::Lane;
use crate::paths::tests::Scratch;
use crate::process::Interrupt;

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
    assert_eq!(launch.grace, Duration::from_secs(45), "the stop's grace");
    DEADLINE.with(|held| held.set(Some(deadline)));
    std::fs::write(output, "").expect("the lane's output writes");
    let evidence = env
        .and_then(|env| env.iter().find(|(name, _)| name == "EVIDENCE"))
        .map(|(_, value)| PathBuf::from(value))
        .expect("the lane is given its evidence directory");
    Lane::new(POSITIVE, POSITIVE_GRAPH, "0").write(&evidence, &declaration());
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
    let mut declared = declaration();
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
        models: std::cell::RefCell::new(BTreeMap::new()),
    }
}

/// A lane call past its deadline gives every case of the call no verdict, whatever a case's own output
/// and exit, and each result keeps the exit the lane recorded for its case: the complete evidence of a
/// positive `join-production` that a finished call judges survived. The call's deadline is each case's
/// share of 1,200 seconds plus the lane's setup of 2,700, and its stop's grace the run's 45 seconds.
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
        .genmc(
            &cases[..1],
            &Value::Null,
            Some(&Text::from("row00")),
            &mut runs,
        )
        .expect("the lane is judged");
    assert_eq!(
        field(&judged[0], "result"),
        Value::String(Text::from("survived")),
        "{judged:?}"
    );
    assert_eq!(
        DEADLINE.with(std::cell::Cell::get),
        Some(Duration::from_secs(3900)),
        "one fresh case"
    );
    let scratch = Scratch::new("weaken-lane-deadline");
    let mut runner = standing(&scratch, &launch, expired, |_| {});
    let mut runs: Runs = BTreeMap::new();
    let results = runner
        .genmc(&cases, &Value::Null, Some(&Text::from("row00")), &mut runs)
        .expect("the lane is judged");
    let deadline = DEADLINE.with(std::cell::Cell::get);
    assert_eq!(deadline, Some(Duration::from_secs(5100)), "two fresh cases");
    assert_eq!(POLL, Duration::from_millis(50));
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
        .genmc(
            &[Text::from("join-production")],
            &Value::Null,
            None,
            &mut runs,
        )
        .expect("the lane is judged");
    let argv = PROFILE.lock().expect("unpoisoned").clone();
    assert_eq!(argv[3], "pr", "{argv:?}");
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

thread_local! {
    static OUTPUT: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
    static CODE: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(Some(101)) };
    static CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The loom test's stand-in: it writes the thread's [`OUTPUT`] to the output, counts the call and gives
/// the thread's [`CODE`].
fn loom_output(
    _: &Launch<'_>,
    _: &[OsString],
    _: &Path,
    _: Option<&[(OsString, OsString)]>,
    deadline: Duration,
    output: &Path,
) -> Result<(Option<i32>, f64), Halt> {
    assert_eq!(deadline, Duration::from_secs(3600), "the loom deadline");
    CALLS.with(|calls| calls.set(calls.get() + 1));
    std::fs::write(output, OUTPUT.with(|text| text.borrow().clone())).expect("written");
    Ok((CODE.with(std::cell::Cell::get), 1.0))
}

const MODEL: &str = "crates/kestrike/src/mod.rs";

/// `modeled` is a runner whose copy under `scratch` holds `model` as the crate's `mod.rs`, with each loom
/// test run by [`loom_output`].
fn modeled<'l>(scratch: &Scratch, launch: &'l Launch<'l>, model: &str) -> Runner<'l> {
    let mut runner = standing(scratch, launch, loom_output, |_| {});
    let copy = scratch.0.join("copy");
    std::fs::create_dir_all(copy.join("crates/kestrike/src")).expect("made");
    std::fs::write(copy.join(MODEL), model).expect("written");
    runner.copy = copy;
    runner
}

/// A failed run of `test` whose panic at `line` of the model prints `message`.
fn failed_at(test: &str, line: usize, message: &str) -> String {
    format!(
        "   Compiling kestrike v0.1.0 (copy)\nrunning 1 test\ntest {test} ... FAILED\nthread '{test}' \
         panicked at {MODEL}:{line}:9:\n{message}\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; \
         0 measured; 0 filtered out\n"
    )
}

fn passed(test: &str) -> String {
    format!(
        "   Compiling kestrike v0.1.0 (copy)\nrunning 1 test\ntest {test} ... ok\ntest result: ok. 1 \
         passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
    )
}

fn judged(runner: &mut Runner<'_>, test: &str, failure: &str, output: &str) -> (String, String) {
    OUTPUT.with(|text| *text.borrow_mut() = output.to_owned());
    let code = if output.contains("test result: ok") {
        0
    } else {
        101
    };
    CODE.with(|held| held.set(Some(code)));
    let failure = json::parse(failure).expect("parses");
    let mut runs: Runs = BTreeMap::new();
    let result = runner
        .loom(&Text::from(test), &failure, None, &mut runs)
        .expect("judged");
    let member = |key: &str| match &result {
        Value::Object(result) => json::line(result.get(key).expect("a member")),
        _ => panic!("a result is an object"),
    };
    (member("result"), member("reason"))
}

const WITH_LITERAL: &str =
    "mod m {\n    fn t() {\n        assert!(held(), \"the record holds\");\n    }\n}\n";

/// A loom failure that is no text but that Python reads as true runs its test first; the judgment then
/// fails with Python's type error where the model source holds a message literal, and is made as for no
/// site where it holds none. A failure Python reads as false names no site and fails nothing.
#[test]
fn a_loom_failure_that_is_no_text_fails_after_its_run_where_its_model_holds_a_literal() {
    let scratch = Scratch::new("weaken-failure-type");
    let interrupt = Interrupt::new();
    let launch = Launch::new(&interrupt);
    let mut runner = modeled(&scratch, &launch, WITH_LITERAL);
    OUTPUT.with(|text| *text.borrow_mut() = failed_at("m::t", 3, "the record holds"));
    CALLS.with(|calls| calls.set(0));
    let mut runs: Runs = BTreeMap::new();
    let ran = runner.loom(
        &Text::from("m::t"),
        &json::parse("7").expect("parses"),
        None,
        &mut runs,
    );
    match ran {
        Err(Halt::Failed(message)) => assert_eq!(
            message,
            "TypeError: 'in <string>' requires string as left operand, not int"
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(CALLS.with(std::cell::Cell::get), 1, "the test ran first");
    assert!(runs.contains_key(&("loom", Text::from("m::t"))));
    let other = "another text or at another assertion";
    for falsy in ["0", "false", "[]", "{}", "\"\"", "null"] {
        let (result, reason) = judged(&mut runner, "m::t", falsy, &failed_at("m::t", 3, "x"));
        assert_eq!(result, "\"no verdict\"", "{falsy}");
        assert_eq!(reason, format!("\"failed with {other}\""), "{falsy}");
    }
    let scratch = Scratch::new("weaken-failure-type-bare");
    let mut bare = modeled(&scratch, &launch, "mod m {\n    fn t() {}\n}\n");
    let (result, _) = judged(&mut bare, "m::t", "7", &passed("m::t"));
    assert_eq!(result, "\"survived\"");
    let (result, reason) = judged(&mut bare, "m::t", "7", &failed_at("m::t", 2, "7"));
    assert_eq!(
        (result.as_str(), reason),
        ("\"no verdict\"", format!("\"failed with {other}\""))
    );
}

/// A loom failure whose text holds a lone surrogate is held by no message literal, so a panic whose
/// message prints the surrogate's escape at the literal's line kills nothing; the six-character escape
/// itself as the failure is held by that literal and kills.
#[test]
fn a_loom_failure_with_a_lone_surrogate_matches_no_literal() {
    let scratch = Scratch::new("weaken-surrogate");
    let interrupt = Interrupt::new();
    let launch = Launch::new(&interrupt);
    let model = "mod m {\n    fn t() {\n        assert!(held(), \"\\ud800\");\n    }\n}\n";
    let mut runner = modeled(&scratch, &launch, model);
    let output = failed_at("m::t", 3, "\\ud800");
    let (result, reason) = judged(&mut runner, "m::t", r#""\ud800""#, &output);
    assert_eq!(result, "\"no verdict\"");
    assert_eq!(
        reason,
        "\"failed with another text or at another assertion\""
    );
    let (result, _) = judged(&mut runner, "m::t", r#""\\ud800""#, &output);
    assert_eq!(result, "\"killed\"");
}

/// A test the run looked up before any plant keeps the model text of that lookup, so its site is the
/// unplanted line even where a plant moves the assertion: a panic at the moved line gives no verdict and
/// one at the remembered line kills. A test first looked up at its judgment reads the planted text.
#[test]
fn a_model_looked_up_before_the_plant_keeps_its_line_and_a_later_one_reads_the_plant() {
    let scratch = Scratch::new("weaken-models");
    let interrupt = Interrupt::new();
    let launch = Launch::new(&interrupt);
    let unplanted = "mod m {\n    fn t() {\n        assert!(a(), \"held at the check\");\n    }\n    fn u() {\n        assert!(b(), \"held under the plant\");\n    }\n}\n";
    let mut runner = modeled(&scratch, &launch, unplanted);
    assert!(runner.model(&Text::from("m::t")).is_some());
    let planted = format!("// a planted line\n{unplanted}");
    std::fs::write(runner.copy.join(MODEL), &planted).expect("written");
    let line = |text: &str, held: &str| {
        text.lines()
            .position(|line| line.contains(held))
            .expect("the assertion stands")
            + 1
    };
    let (before, after) = (
        line(unplanted, "held at the check"),
        line(&planted, "held at the check"),
    );
    assert_eq!(after, before + 1);
    let failure = r#""held at the check""#;
    let moved = failed_at("m::t", after, "held at the check");
    assert_eq!(
        judged(&mut runner, "m::t", failure, &moved),
        (
            "\"no verdict\"".to_owned(),
            "\"failed with another text or at another assertion\"".to_owned()
        )
    );
    let kept = failed_at("m::t", before, "held at the check");
    assert_eq!(judged(&mut runner, "m::t", failure, &kept).0, "\"killed\"");
    let shifted = line(&planted, "held under the plant");
    let later = failed_at("m::u", shifted, "held under the plant");
    assert_eq!(
        judged(&mut runner, "m::u", r#""held under the plant""#, &later).0,
        "\"killed\""
    );
}

/// The run looks up the model of each test of every `kill` and `unrun` loom entry of the catalog, the
/// rows the run does not select included, and of no test that only a `survives` entry names.
#[test]
fn the_models_remembered_are_those_of_kill_and_unrun_loom_entries() {
    let scratch = Scratch::new("weaken-remembered");
    let interrupt = Interrupt::new();
    let launch = Launch::new(&interrupt);
    let runner = modeled(&scratch, &launch, WITH_LITERAL);
    let catalog = r#"{"rows": [
        {"id": "a", "kill": [{"lane": "loom", "tests": ["m::t"], "failure": "the record holds"}]},
        {"id": "b", "survives": {"passed": [{"lane": "loom", "tests": ["m::u"], "failure": "x"}], "reason": "r"}},
        {"id": "c", "unrun": {"needs": [{"lane": "loom", "tests": ["n::v"], "failure": "y"}]}},
        {"id": "d", "unrun": {"needs": [{"lane": "genmc", "tests": ["join-production"], "failure": "z"}]}}
    ]}"#;
    let path = runner.copy.join(crate::orderings::check::CATALOG);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("made");
    std::fs::write(&path, catalog).expect("written");
    runner.remember_models().expect("remembered");
    let models = runner.models.borrow();
    let names: Vec<String> = models.keys().map(ToString::to_string).collect();
    assert_eq!(names, ["m::t", "n::v"]);
    assert!(models[&Text::from("m::t")].is_some());
    assert!(models[&Text::from("n::v")].is_none(), "no module n stands");
}

/// A loom test a signal ended gives the negated signal number as its report's `exit`, a JSON integer.
#[test]
fn a_signal_ended_loom_test_reports_its_negated_number() {
    let scratch = Scratch::new("weaken-negative");
    let interrupt = Interrupt::new();
    let launch = Launch::new(&interrupt);
    let mut runner = modeled(&scratch, &launch, WITH_LITERAL);
    CODE.with(|code| code.set(Some(-9)));
    OUTPUT.with(|text| *text.borrow_mut() = String::new());
    let mut runs: Runs = BTreeMap::new();
    let result = runner
        .loom(&Text::from("m::t"), &Value::Null, None, &mut runs)
        .expect("judged");
    CODE.with(|code| code.set(Some(101)));
    let Value::Object(result) = result else {
        panic!("a result is an object");
    };
    assert_eq!(json::line(result.get("exit").expect("an exit")), "-9");
    assert_eq!(json::line(&super::code_value(Some(-9))), "-9");
}

/// The profile of a lane call: `pr` where the set Python builds of `profiles.pr` holds every fresh case,
/// from an array, an object's keys or a string's code points, else `scheduled`; a missing member is
/// Python's `KeyError`, and a scalar or a member that is an array or an object its `TypeError`.
#[test]
fn the_profile_is_pr_where_its_set_holds_each_fresh_case() {
    let (join, j) = (Text::from("join-production"), Text::from("j"));
    let chosen = |declared: &str, fresh: &[&Text]| match super::profile(
        &json::parse(declared).expect("parses"),
        fresh,
    ) {
        Ok(profile) => profile.to_owned(),
        Err(Halt::Failed(message)) => message,
        Err(other) => panic!("{other:?}"),
    };
    #[rustfmt::skip]
    let rows: [(&str, &[&Text], &str); 10] = [
        (r#"{"profiles": {"pr": ["join-production"]}}"#, &[&join], "pr"),
        (r#"{"profiles": {"pr": ["join-production"]}}"#, &[&join, &j], "scheduled"),
        (r#"{"profiles": {"pr": {"join-production": 0}}}"#, &[&join], "pr"),
        (r#"{"profiles": {"pr": "jx"}}"#, &[&j], "pr"),
        (r#"{"profiles": {"pr": "join-production"}}"#, &[&join], "scheduled"),
        (r#"{"cases": {}}"#, &[&join], "KeyError: 'profiles'"),
        (r#"{"profiles": {}}"#, &[&join], "KeyError: 'pr'"),
        (r#"{"profiles": {"pr": 7}}"#, &[&join], "the pr profile is not iterable"),
        (r#"{"profiles": {"pr": ["join-production", ["x"]]}}"#, &[&join], "TypeError: unhashable type: 'list'"),
        (r#"{"profiles": {"pr": ["join-production", {"x": 1}]}}"#, &[&join], "TypeError: unhashable type: 'dict'"),
    ];
    for (declared, fresh, wanted) in rows {
        assert_eq!(chosen(declared, fresh), wanted, "{declared}");
    }
}

/// A signal recorded while the copy's two children run makes their wait kill and reap both and return
/// that signal's interruption.
#[test]
fn a_signal_during_the_copy_kills_and_reaps_both_children() {
    let spawn = || {
        std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("the child starts")
    };
    let mut children = [spawn(), spawn()];
    let pids: Vec<u32> = children.iter().map(std::process::Child::id).collect();
    let interrupt = Interrupt::new();
    interrupt.record(libc::SIGTERM);
    let waited = super::waited(&mut children, &interrupt);
    assert!(
        matches!(waited, Err(Halt::Interrupted(libc::SIGTERM))),
        "{waited:?}"
    );
    for pid in pids {
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "the child {pid} is killed and reaped"
        );
    }
}
