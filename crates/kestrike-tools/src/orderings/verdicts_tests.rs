use std::fs;
use std::path::Path;

use super::{LOOM_REBUILT, Outcome, Verdict, case_exit, genmc_result, loom_result};
use crate::genmc::case::tests::{
    DEPARTURE, FREED, POSITIVE, POSITIVE_GRAPH, case_of, declaration, line_of, root, violation,
    violation_graph,
};
use crate::genmc::read_source;
use crate::json::{Integer, Value};
use crate::orderings::sources::loom_site;
use crate::paths::tests::Scratch;

const CASE: &str = "join-production";
const KERNEL: &str = "src/join_kernel.rs";
const RUN_FAILURE: &str = "a departed record whose owner had not ended";
const RUN_TEST: &str =
    "storage::fill_model::two_owners_on_one_key_and_a_servicer_observing_the_run";
const FILL_MODEL: &str = "crates/kestrike/src/storage/fill_model.rs";

/// The files the GenMC lane writes for one case.
pub(crate) struct Lane<'a> {
    text: &'a str,
    graph: &'a str,
    code: &'a str,
    check: bool,
    record: Option<&'a str>,
    config: Option<&'a str>,
    argv: Option<Vec<String>>,
    intrinsics: Option<&'a [&'a str]>,
}

impl<'a> Lane<'a> {
    pub(crate) fn new(text: &'a str, graph: &'a str, code: &'a str) -> Self {
        Self {
            text,
            graph,
            code,
            check: true,
            record: None,
            config: None,
            argv: None,
            intrinsics: None,
        }
    }

    pub(crate) fn write(&self, evidence: &Path, declared: &Value) {
        let file = |name: &str, text: &str| {
            fs::write(evidence.join(name), text).expect("the lane's file writes");
        };
        file(&format!("genmc-{CASE}.txt"), self.text);
        file(&format!("genmc-{CASE}.exit"), &format!("{}\n", self.code));
        file(&format!("genmc-{CASE}.dot"), self.graph);
        let check = if self.check {
            "    Checking genmc-kernels v0.0.0\n"
        } else {
            ""
        };
        file(&format!("check-{CASE}.txt"), check);
        if let Some(intrinsics) = self.intrinsics {
            file(
                &format!("genmc-{CASE}.intrinsics"),
                &format!("{}\n", intrinsics.join("\n")),
            );
        }
        let record = r#"{"binary": {"path": "/genmc/build/bin/genmc"}, "rustc": {"name": "nightly-2026-07-27", "toolchain": "/toolchain"}}"#;
        file("identity.json", self.record.unwrap_or(record));
        file("cargo-config.json", self.config.unwrap_or("{}"));
        let argv = self
            .argv
            .clone()
            .unwrap_or_else(|| default_argv(evidence, declared));
        file(
            &format!("genmc-{CASE}.argv"),
            &format!("{}\n", argv.join("\n")),
        );
        file(
            &format!("genmc-{CASE}.env"),
            &format!(
                "CASE={CASE}\nRUSTUP_TOOLCHAIN=nightly-2026-07-27\nRUSTC=/toolchain/bin/rustc\n\
                 RUSTC_WRAPPER=\nRUSTC_WORKSPACE_WRAPPER=\n"
            ),
        );
    }
}

fn default_argv(evidence: &Path, declared: &Value) -> Vec<String> {
    let Value::Object(declared) = declared else {
        panic!("the declaration is an object");
    };
    let Some(Value::Array(options)) = declared.get("options") else {
        panic!("the declaration holds options");
    };
    let manifest = root().join(format!("verification/genmc/packages/run-{CASE}/Cargo.toml"));
    let mut argv = vec!["/genmc/build/bin/genmc".to_owned()];
    argv.extend(options.iter().map(|option| match option {
        Value::String(option) => option.to_string(),
        _ => panic!("an option is a string"),
    }));
    argv.push(format!(
        "--dump-error-graph={}",
        evidence.join(format!("genmc-{CASE}.dot")).display()
    ));
    argv.push(manifest.display().to_string());
    argv
}

fn with_intrinsics(declared: &Value, intrinsics: &[&str]) -> Value {
    let mut declared = declared.clone();
    case_of(&mut declared, CASE).insert(
        "intrinsics",
        Value::Array(
            intrinsics
                .iter()
                .map(|&name| Value::String(name.into()))
                .collect(),
        ),
    );
    declared
}

type Judged = (Verdict, String);

/// A GenMC outcome as its verdict, its reason with the evidence directory written `<EV>`, and its
/// execution count.
type Counted = (Verdict, String, Option<u64>);

fn judged(lane: &Lane<'_>, declared: &Value, kernel: Option<&str>) -> Counted {
    judged_over(
        lane,
        declared,
        kernel.map(|kernel| (DEPARTURE, kernel)),
        &[],
        &[],
    )
    .expect("the evidence is judged")
}

/// The outcome of `lane` with each file of `written` written over and each of `removed` removed.
fn judged_over(
    lane: &Lane<'_>,
    declared: &Value,
    kill: Option<(&str, &str)>,
    written: &[(&str, &[u8])],
    removed: &[&str],
) -> Result<Counted, crate::genmc::refusal::Error> {
    let scratch = Scratch::new("genmc-verdict");
    lane.write(&scratch.0, declared);
    for (name, bytes) in written {
        fs::write(scratch.0.join(name), bytes).expect("the file writes");
    }
    for name in removed {
        fs::remove_file(scratch.0.join(name)).expect("the file is removed");
    }
    let code = case_exit(&scratch.0, CASE);
    let outcome: Outcome = genmc_result(
        &root(),
        declared,
        CASE,
        kill,
        &scratch.0,
        true,
        code.as_ref(),
    )?;
    let evidence = scratch.0.display().to_string();
    Ok((
        outcome.verdict(),
        outcome.reason().replace(&evidence, "<EV>"),
        outcome.executions().map(|count| {
            count
                .to_string()
                .parse()
                .expect("a recorded count fits 64 bits")
        }),
    ))
}

fn named_violation(message: &str) -> (String, String) {
    let line = line_of(message);
    (violation(line), violation_graph(line))
}

#[test]
fn genmc_verdicts_come_from_judge_case() {
    let declared = declaration();
    let (killing, killing_graph) = named_violation(DEPARTURE);
    let (freed, freed_graph) = named_violation(FREED);
    let aborted = format!("LLVM ERROR: unsupported intrinsic\n{POSITIVE}");
    let manifest = root().join(format!("verification/genmc/packages/run-{CASE}/Cargo.toml"));
    let command = format!(
        "join-production ran ['/elsewhere/genmc', 'x'], not genmc -rc11 --disable-estimation \
         --dump-error-graph=<EV>/genmc-{CASE}.dot {}",
        manifest.display()
    );
    let shape = "the lane's build or command is not the declared one: the identity record lacks a \
                 binary path or a rustc name and toolchain";
    let (killed_line, freed_line) = (line_of(DEPARTURE), line_of(FREED));
    let judge = |lane: Lane<'_>| judged(&lane, &declared, Some(KERNEL));
    #[rustfmt::skip]
    let rows: Vec<(Counted, Counted)> = vec![
        (judge(Lane::new(POSITIVE, POSITIVE_GRAPH, "0")),
         (Verdict::Survived, "judge_case accepts the positive declaration".into(), Some(3))),
        (judge(Lane::new(&killing, &killing_graph, "42")),
         (Verdict::Killed, "judge_case accepts the violation declaration".into(), Some(0))),
        (judge(Lane::new(&freed, &freed_graph, "42")),
         (Verdict::NoVerdict, format!("join-production exited 42, declared positive; join-production failed at \
join_kernel.rs:{freed_line}, declared join_kernel.rs:{killed_line}"), None)),
        (judge(Lane::new(POSITIVE, POSITIVE_GRAPH, "124")),
         (Verdict::NoVerdict, "join-production was interrupted (exit 124); join-production was interrupted (exit 124)".into(), None)),
        (judge(Lane::new(&aborted, POSITIVE_GRAPH, "0")),
         (Verdict::NoVerdict, "join-production aborted: 'LLVM ERROR: unsupported intrinsic'; join-production aborted: \
'LLVM ERROR: unsupported intrinsic'".into(), None)),
        (judge(Lane { check: false, ..Lane::new(POSITIVE, POSITIVE_GRAPH, "0") }),
         (Verdict::NoVerdict, "no evidence that the kernel rebuilt".into(), None)),
        (judge(Lane { config: Some(r#"{"build": {"rustflags": ["--cfg", "x"]}}"#), ..Lane::new(POSITIVE, POSITIVE_GRAPH, "0") }),
         (Verdict::NoVerdict, "the lane's build or command is not the declared one: the cargo configuration sets \
build.rustflags".into(), None)),
        (judge(Lane { argv: Some(vec!["/elsewhere/genmc".into(), "x".into()]), ..Lane::new(POSITIVE, POSITIVE_GRAPH, "0") }),
         (Verdict::NoVerdict, format!("the lane's build or command is not the declared one: {command}"), None)),
    ];
    for (found, wanted) in rows {
        assert_eq!(found, wanted);
    }
    let records = [
        r#"{"binary": null, "rustc": {"name": "n", "toolchain": "/t"}}"#,
        r#"["not", "an", "object"]"#,
        r#"{"binary": {"path": "/g"}}"#,
    ];
    for record in records {
        let lane = Lane {
            record: Some(record),
            ..Lane::new(POSITIVE, POSITIVE_GRAPH, "0")
        };
        assert_eq!(
            judge(lane),
            (Verdict::NoVerdict, shape.to_owned(), None),
            "{record}"
        );
    }
}

#[test]
fn a_genmc_kill_keeps_the_case_declaration_and_needs_its_kernel() {
    let declared = declaration();
    let (named, graph) = named_violation(DEPARTURE);
    let pin = ["llvm.umin.i64"];
    let pinned = with_intrinsics(&declared, &pin);
    let lane = |intrinsics| Lane {
        intrinsics,
        ..Lane::new(&named, &graph, "42")
    };
    assert_eq!(
        judged(&lane(Some(&pin)), &pinned, Some(KERNEL)),
        (
            Verdict::Killed,
            "judge_case accepts the violation declaration".to_owned(),
            Some(0)
        )
    );
    let calls = "join-production's bitcode calls [], declared ['llvm.umin.i64']";
    assert_eq!(
        judged(&lane(Some(&[])), &pinned, Some(KERNEL)),
        (Verdict::NoVerdict, format!("{calls}; {calls}"), None)
    );
    let positive = "join-production exited 42, declared positive";
    assert_eq!(
        judged(&lane(None), &declared, None),
        (Verdict::NoVerdict, positive.to_owned(), None)
    );
    let (verdict, reason, _) = judged(&lane(None), &declared, Some("src/absent_kernel.rs"));
    assert_eq!(verdict, Verdict::NoVerdict);
    assert!(reason.starts_with(&format!("{positive}; ")), "{reason}");
}

#[test]
fn a_loom_kill_needs_the_named_assertion_at_its_location() {
    let failed = |location: &str, message: &str| {
        format!(
            "   Compiling kestrike v0.1.0\nrunning 1 test\ntest t ... FAILED\nthread 't' (12) panicked at \
             {location}:21:\n{message}\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 \
             filtered out\n"
        )
    };
    let named = "protection violated: a departed record whose owner had not ended";
    let site = (FILL_MODEL, 333);
    let verdict = |text: &str, site| {
        loom_result(text, Some(101), RUN_FAILURE, true, site)
            .expect("the panic lines are read")
            .0
    };
    let at = format!("{FILL_MODEL}:333");
    assert_eq!(verdict(&failed(&at, named), Some(site)), Verdict::Killed);
    for (location, message) in [
        (format!("{FILL_MODEL}:340"), named),
        ("crates/kestrike/src/storage/fill.rs:333".to_owned(), named),
        (at.clone(), "another assertion"),
    ] {
        assert_eq!(
            verdict(&failed(&location, message), Some(site)),
            Verdict::NoVerdict,
            "{location} {message}"
        );
    }
    assert_eq!(verdict(&failed(&at, named), None), Verdict::NoVerdict);
    let top = root();
    let read = |path: &str| read_source(&top, path);
    assert_eq!(
        loom_site(RUN_TEST, RUN_FAILURE, &read),
        Some((FILL_MODEL.to_owned(), 333))
    );
}

#[test]
fn a_loom_result_follows_the_order_of_its_rules() {
    let summary = |line: &str| format!("running 1 test\n{line}\n");
    let pass = summary("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured");
    let ignored = summary("test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured");
    let absent = summary("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured");
    let failed = summary("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured");
    let result = |text: &str, code, rebuilt| {
        loom_result(text, code, RUN_FAILURE, rebuilt, None).expect("the run is read")
    };
    #[rustfmt::skip]
    let rows: Vec<(Judged, (Verdict, &str))> = vec![
        (result(&pass, None, true), (Verdict::NoVerdict, "timeout")),
        (result(&pass, None, false), (Verdict::NoVerdict, "timeout")),
        (result(&pass, Some(0), false), (Verdict::NoVerdict, "no evidence that kestrike rebuilt")),
        (result(&pass, Some(0), true), (Verdict::Survived, "one executed test passed")),
        (result(&pass, Some(101), true), (Verdict::NoVerdict, "the test crashed: its run ended without a summary")),
        (result(&failed, Some(101), true), (Verdict::NoVerdict, "failed with another text or at another assertion")),
        (result(&ignored, Some(0), true), (Verdict::NoVerdict, "the test is ignored")),
        (result(&absent, Some(0), true), (Verdict::NoVerdict, "the test is absent: no test matched its name")),
        (result("error[E0425]: cannot find value\n", Some(101), true), (Verdict::NoVerdict, "a build failure")),
    ];
    for (found, (verdict, reason)) in rows {
        assert_eq!(found, (verdict, reason.to_owned()));
    }
    let killed = format!("thread 't' panicked at {FILL_MODEL}:0333:9:\n{RUN_FAILURE}\n{failed}");
    assert_eq!(
        loom_result(
            &killed,
            Some(101),
            RUN_FAILURE,
            true,
            Some((FILL_MODEL, 333))
        )
        .expect("the run is read"),
        (
            Verdict::Killed,
            format!(
                "failed with 'a departed record whose owner had not ended' at {FILL_MODEL}:333"
            )
        )
    );
    let long = format!(
        "thread 't' panicked at {FILL_MODEL}:{}:9:\n{RUN_FAILURE}\n{failed}",
        "1".repeat(4301)
    );
    assert!(loom_result(&long, Some(101), RUN_FAILURE, true, Some((FILL_MODEL, 333))).is_err());
}

#[test]
fn an_exit_file_reads_as_an_integer_or_none() {
    let scratch = Scratch::new("case-exit");
    let exit = scratch.0.join(format!("genmc-{CASE}.exit"));
    assert_eq!(case_exit(&scratch.0, CASE), None);
    for (written, wanted) in [
        (" 42\n", Some("42")),
        ("\u{ff14}\u{ff12}\n", Some("42")),
        ("+\u{664}_\u{662}", Some("42")),
        ("+0_42", Some("42")),
        ("x\n", None),
        ("", None),
    ] {
        fs::write(&exit, written).expect("the exit writes");
        assert_eq!(
            case_exit(&scratch.0, CASE).map(|code| code.to_string()),
            wanted.map(str::to_owned),
            "{written:?}"
        );
    }
}

#[test]
fn a_lane_without_a_file_or_an_exit_code_gives_no_verdict() {
    let declared = declaration();
    let scratch = Scratch::new("genmc-missing");
    Lane::new(POSITIVE, POSITIVE_GRAPH, "0").write(&scratch.0, &declared);
    fs::remove_file(scratch.0.join("identity.json")).expect("the record is removed");
    let outcome = genmc_result(&root(), &declared, CASE, None, &scratch.0, true, None)
        .expect("the evidence is judged");
    assert_eq!(
        (outcome.verdict(), outcome.reason(), outcome.executions()),
        (Verdict::NoVerdict, "the lane left no output", None)
    );
    Lane::new(POSITIVE, POSITIVE_GRAPH, "x").write(&scratch.0, &declared);
    let code = case_exit(&scratch.0, CASE);
    let outcome = genmc_result(
        &root(),
        &declared,
        CASE,
        None,
        &scratch.0,
        true,
        code.as_ref(),
    )
    .expect("the evidence is judged");
    assert_eq!(
        (outcome.verdict(), outcome.reason()),
        (Verdict::NoVerdict, "no exit code")
    );
    let survived = genmc_result(
        &root(),
        &declared,
        CASE,
        Some(("", KERNEL)),
        &scratch.0,
        false,
        Some(&Integer::from(0_u64)),
    )
    .expect("the evidence is judged");
    assert_eq!(
        (survived.verdict(), survived.executions()),
        (Verdict::Survived, Some(&Integer::from(3_u64)))
    );
}

#[test]
fn each_file_the_lane_leaves_is_needed_for_a_verdict() {
    let declared = declaration();
    for name in [
        "genmc-join-production.txt",
        "genmc-join-production.exit",
        "genmc-join-production.argv",
        "genmc-join-production.env",
        "identity.json",
    ] {
        let scratch = Scratch::new("genmc-each-file");
        Lane::new(POSITIVE, POSITIVE_GRAPH, "0").write(&scratch.0, &declared);
        fs::remove_file(scratch.0.join(name)).expect("the file is removed");
        let outcome = genmc_result(
            &root(),
            &declared,
            CASE,
            Some((DEPARTURE, KERNEL)),
            &scratch.0,
            true,
            Some(&Integer::from(0_u64)),
        )
        .expect("the evidence is judged");
        assert_eq!(
            (outcome.verdict(), outcome.reason(), outcome.executions()),
            (Verdict::NoVerdict, "the lane left no output", None),
            "{name}"
        );
    }
}

#[test]
fn an_identity_record_of_another_shape_gives_no_verdict() {
    let declared = declaration();
    let lane = Lane {
        record: Some(r#"{"binary": {"path": 5}, "rustc": {"name": "x", "toolchain": "y"}}"#),
        ..Lane::new(POSITIVE, POSITIVE_GRAPH, "0")
    };
    assert_eq!(
        judged(&lane, &declared, Some(KERNEL)),
        (
            Verdict::NoVerdict,
            "the lane's build or command is not the declared one: the identity record lacks a \
             binary path or a rustc name and toolchain"
                .to_owned(),
            None
        )
    );
}

#[test]
fn a_planted_run_needs_the_kernel_package_compiled_and_an_unplanted_run_does_not() {
    let declared = declaration();
    let scratch = Scratch::new("genmc-planted");
    let lane = Lane {
        check: false,
        ..Lane::new(POSITIVE, POSITIVE_GRAPH, "0")
    };
    lane.write(&scratch.0, &declared);
    let code = Integer::from(0_u64);
    let judge = |planted| {
        genmc_result(
            &root(),
            &declared,
            CASE,
            None,
            &scratch.0,
            planted,
            Some(&code),
        )
        .expect("the evidence is judged")
    };
    assert_eq!(judge(true).reason(), "no evidence that the kernel rebuilt");
    let unplanted = judge(false);
    assert_eq!(
        (unplanted.verdict(), unplanted.executions()),
        (Verdict::Survived, Some(&Integer::from(3_u64)))
    );
    fs::write(
        scratch.0.join("check-join-production.txt"),
        "   Compiling genmc-kernels v0.0.0\n",
    )
    .expect("the log writes");
    assert_eq!(judge(true).verdict(), Verdict::Survived);
}

#[test]
fn a_graph_path_that_loops_ends_the_judgment() {
    let declared = declaration();
    let scratch = Scratch::new("genmc-loop");
    Lane::new(POSITIVE, POSITIVE_GRAPH, "0").write(&scratch.0, &declared);
    let graph = scratch.0.join("genmc-join-production.dot");
    fs::remove_file(&graph).expect("the graph is removed");
    std::os::unix::fs::symlink(&graph, &graph).expect("the link is made");
    let result = genmc_result(
        &root(),
        &declared,
        CASE,
        None,
        &scratch.0,
        true,
        Some(&Integer::from(0_u64)),
    );
    assert!(
        matches!(result, Err(crate::genmc::refusal::Error::Runtime(_))),
        "{result:?}"
    );
}

#[test]
fn verdicts_have_their_report_names_and_a_loom_rebuild_reads_its_status_line() {
    assert_eq!(
        [Verdict::Killed, Verdict::Survived, Verdict::NoVerdict].map(Verdict::name),
        ["killed", "survived", "no verdict"]
    );
    assert!(LOOM_REBUILT.is_match("running\n   Compiling kestrike v0.1.0 (/x)\n"));
    assert!(
        !LOOM_REBUILT.is_match("   Compiling kestrike-tools v0.1.0\n   Checking kestrike v0.1.0\n")
    );
}

const ENV: &str = "CASE=join-production\nRUSTUP_TOOLCHAIN=nightly-2026-07-27\nRUSTC=/toolchain/bin/rustc\n\
RUSTC_WRAPPER=\nRUSTC_WORKSPACE_WRAPPER=\n";

/// Each row changes the lane's files and gives the verdict, reason and count the rules read from them:
/// the rebuild line names the package and no checkout, the environment file keeps its lines with `=`
/// and the last of a repeated name, the identity record is checked for the fields the command reads,
/// the output and check log read with ill-formed bytes replaced and any line end, the checks stand in
/// their order, and the kill attempt needs both its failure and its kernel.
#[test]
fn a_genmc_verdict_reads_each_lane_file_as_its_rules_read_it() {
    let declared = declaration();
    let (killing, killing_graph) = named_violation(DEPARTURE);
    let counted = killing.replace("explored: 0", "explored: 5");
    let crlf = format!("{}\u{fffd}\r\n", POSITIVE.replace('\n', "\r\n"));
    let mut crlf = crlf.into_bytes();
    crlf.splice(crlf.len() - 5..crlf.len() - 2, [0xff]);
    let repeated = format!("junk line\nRUSTC=/other\n{ENV}");
    let equals = ENV.replace("RUSTC=/toolchain/bin/rustc", "RUSTC=/toolchain/bin/rustc=x");
    let record = r#"{"upstream": "other", "binary": {"path": "/genmc/build/bin/genmc", "x": 1}, "rustc": {"name": "nightly-2026-07-27", "toolchain": "/toolchain"}}"#;
    let txt = "genmc-join-production.txt";
    let log = "check-join-production.txt";
    let env = "genmc-join-production.env";
    let positive = Lane::new(POSITIVE, POSITIVE_GRAPH, "0");
    let kill = Some((DEPARTURE, KERNEL));
    let survived = (
        Verdict::Survived,
        "judge_case accepts the positive declaration".to_owned(),
        Some(3),
    );
    let unbuilt = (
        Verdict::NoVerdict,
        "no evidence that the kernel rebuilt".to_owned(),
        None,
    );
    let command = |reason: &str| {
        (
            Verdict::NoVerdict,
            format!("the lane's build or command is not the declared one: {reason}"),
            None,
        )
    };
    let env_reason = "join-production ran with {'CASE': 'join-production', 'RUSTUP_TOOLCHAIN': \
'nightly-2026-07-27', 'RUSTC': '/toolchain/bin/rustc=x', 'RUSTC_WRAPPER': '', 'RUSTC_WORKSPACE_WRAPPER': ''}, \
not {'CASE': 'join-production', 'RUSTUP_TOOLCHAIN': 'nightly-2026-07-27', 'RUSTC': '/toolchain/bin/rustc', \
'RUSTC_WRAPPER': '', 'RUSTC_WORKSPACE_WRAPPER': ''}";
    let positive_42 = "join-production exited 42, declared positive";
    let judge = |lane: &Lane<'_>, kill, written: &[(&str, &[u8])], removed: &[&str]| {
        judged_over(lane, &declared, kill, written, removed).expect("the evidence is judged")
    };
    #[rustfmt::skip]
    let rows: Vec<(&str, Counted, Counted)> = vec![
        ("another checkout's log", judge(&positive, kill, &[(log, b"   Checking genmc-kernels v9.9.9 (/elsewhere)\n")], &[]), survived.clone()),
        ("another package", judge(&positive, kill, &[(log, b"   Compiling other v0.1.0\n    Checking kestrike v0.1.0\n")], &[]), unbuilt.clone()),
        ("no log", judge(&positive, kill, &[], &[log]), unbuilt.clone()),
        ("junk and a repeated name", judge(&positive, kill, &[(env, repeated.as_bytes())], &[]), survived.clone()),
        ("a value holding =", judge(&positive, kill, &[(env, equals.as_bytes())], &[]), command(env_reason)),
        ("an identity with other fields", judge(&Lane { record: Some(record), ..Lane::new(POSITIVE, POSITIVE_GRAPH, "0") }, kill, &[], &[]),
         survived.clone()),
        ("replaced bytes and CRLF", judge(&positive, kill, &[(txt, &crlf), (log, b"\xfe\r\n    Checking genmc-kernels v0.0.0\r\n")], &[]),
         survived.clone()),
        ("lone CR", judge(&positive, kill, &[(txt, POSITIVE.replace('\n', "\r").as_bytes()), (log, b"x\r    Checking genmc-kernels v0.0.0\r")], &[]),
         survived.clone()),
        ("no rebuild before no exit", judge(&Lane { check: false, ..Lane::new(POSITIVE, POSITIVE_GRAPH, "x") }, kill, &[], &[]), unbuilt.clone()),
        ("configuration before rebuild", judge(&Lane { check: false, config: Some(r#"{"build": {"rustflags": []}}"#), ..Lane::new(POSITIVE, POSITIVE_GRAPH, "0") }, kill, &[], &[]),
         command("the cargo configuration sets build.rustflags")),
        ("a kill without its graph", judge(&Lane::new(&killing, &killing_graph, "42"), kill, &[], &["genmc-join-production.dot"]),
         (Verdict::NoVerdict, format!("{positive_42}; join-production left no error graph"), None)),
        ("an empty failure", judge(&Lane::new(&killing, &killing_graph, "42"), Some(("", KERNEL)), &[], &[]),
         (Verdict::NoVerdict, positive_42.to_owned(), None)),
        ("an empty kernel", judge(&Lane::new(&killing, &killing_graph, "42"), Some((DEPARTURE, "")), &[], &[]),
         (Verdict::NoVerdict, positive_42.to_owned(), None)),
        ("a kill's count", judge(&Lane::new(&counted, &killing_graph, "42"), kill, &[], &[]),
         (Verdict::Killed, "judge_case accepts the violation declaration".to_owned(), Some(5))),
        ("an exit in Arabic-Indic digits", judge(&Lane::new(POSITIVE, POSITIVE_GRAPH, "\u{660}"), kill, &[], &[]), survived.clone()),
    ];
    for (row, found, wanted) in rows {
        assert_eq!(found, wanted, "{row}");
    }
    let long = POSITIVE.replace("explored: 3", &format!("explored: {}", "1".repeat(4301)));
    for (lane, written) in [
        (Lane::new(&long, POSITIVE_GRAPH, "0"), Vec::new()),
        (
            positive,
            vec![("genmc-join-production.intrinsics", b"\xff\n".as_slice())],
        ),
    ] {
        let result = judged_over(&lane, &declared, kill, &written, &[]);
        assert!(
            matches!(result, Err(crate::genmc::refusal::Error::Value(_))),
            "{result:?}"
        );
    }
}

/// A lane, its declaration, the command argument written over, that argument for an evidence directory,
/// and the outcome.
type CommandRow<'l, 'd> = (
    Lane<'l>,
    &'d Value,
    usize,
    Box<dyn Fn(&Path) -> String>,
    Counted,
);

/// A declaration without `options` gives no verdict with the missing key, a recorded path that holds a
/// NUL byte gives no verdict as a value error, and the kill attempt reads the package of the
/// declaration file under the root, apart from the package the command check reads from `declared`.
#[test]
fn a_genmc_command_check_quotes_its_key_and_value_errors() {
    let declared = declaration();
    let Value::Object(mut unoptioned) = declared.clone() else {
        panic!("the declaration is an object");
    };
    unoptioned.remove("options");
    let lane = Lane {
        argv: Some(vec!["/genmc/build/bin/genmc".into(), "x".into()]),
        ..Lane::new(POSITIVE, POSITIVE_GRAPH, "0")
    };
    assert_eq!(
        judged(&lane, &Value::Object(unoptioned), Some(KERNEL)),
        (
            Verdict::NoVerdict,
            "the lane's build or command is not the declared one: 'options'".to_owned(),
            None
        )
    );
    let (killing, killing_graph) = named_violation(DEPARTURE);
    let Value::Object(mut moved) = declared.clone() else {
        panic!("the declaration is an object");
    };
    moved.insert(
        "package",
        Value::String("verification/genmc/other/kernels".into()),
    );
    let moved = Value::Object(moved);
    let other = root().join(format!("verification/genmc/other/run-{CASE}/Cargo.toml"));
    let written = |evidence: &Path, at: usize, argument: String, declared: &Value| {
        let mut argv = default_argv(evidence, declared);
        argv[at] = argument;
        fs::write(
            evidence.join(format!("genmc-{CASE}.argv")),
            format!("{}\n", argv.join("\n")),
        )
        .expect("the command writes");
    };
    let nul_graph = |evidence: &Path| {
        format!(
            "--dump-error-graph={}/bad\0/../genmc-{CASE}.dot",
            evidence.display()
        )
    };
    let nul_manifest = root()
        .join(format!(
            "verification/genmc/packages/bad\0/../run-{CASE}/Cargo.toml"
        ))
        .display()
        .to_string();
    let nul = "the lane's build or command is not the declared one: embedded null byte";
    #[rustfmt::skip]
    let rows: Vec<CommandRow<'_, '_>> = vec![
        (Lane::new(POSITIVE, POSITIVE_GRAPH, "0"), &declared, 3, Box::new(nul_graph), (Verdict::NoVerdict, nul.to_owned(), None)),
        (Lane::new(POSITIVE, POSITIVE_GRAPH, "0"), &declared, 4, Box::new(move |_| nul_manifest.clone()),
         (Verdict::NoVerdict, nul.to_owned(), None)),
        (Lane::new(&killing, &killing_graph, "42"), &moved, 4, Box::new(move |_| other.display().to_string()),
         (Verdict::Killed, "judge_case accepts the violation declaration".to_owned(), Some(0))),
    ];
    for (lane, declared, at, argument, wanted) in rows {
        let scratch = Scratch::new("genmc-command");
        lane.write(&scratch.0, declared);
        written(&scratch.0, at, argument(&scratch.0), declared);
        let code = case_exit(&scratch.0, CASE);
        let outcome = genmc_result(
            &root(),
            declared,
            CASE,
            Some((DEPARTURE, KERNEL)),
            &scratch.0,
            true,
            code.as_ref(),
        )
        .expect("the evidence is judged");
        assert_eq!(
            (
                outcome.verdict(),
                outcome.reason().to_owned(),
                outcome
                    .executions()
                    .map(|count| count.to_string().parse().expect("a count"))
            ),
            wanted
        );
    }
}

/// The loom rules read the whole output: a summary counts without a `running` line, the first
/// summary that matches decides, a panic anywhere in the text kills where it reports the site, the
/// failure must stand in the first line of that same panic's message, a FAILED summary under exit 0 is
/// no kill, and an empty failure kills nothing.
#[test]
fn a_loom_result_reads_its_summary_and_panics_from_the_whole_output() {
    let summary = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured";
    let site = Some((FILL_MODEL, 333));
    let panic = |at: u32, message: &str| {
        format!("thread 't' panicked at {FILL_MODEL}:{at}:9:\n{message}\n")
    };
    let killed = (
        Verdict::Killed,
        format!("failed with '{RUN_FAILURE}' at {FILL_MODEL}:333"),
    );
    let other = (
        Verdict::NoVerdict,
        "failed with another text or at another assertion".to_owned(),
    );
    let passed = (Verdict::Survived, "one executed test passed".to_owned());
    let result = |text: &str, code, failure| {
        loom_result(text, Some(code), failure, true, site).expect("the run is read")
    };
    #[rustfmt::skip]
    let rows: Vec<(&str, Judged, Judged)> = vec![
        ("no running line", result("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured\n", 0, RUN_FAILURE), passed.clone()),
        ("two summaries", result("running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n\
test result: FAILED. 0 passed; 1 failed; 0 ignored;\n", 0, RUN_FAILURE), passed),
        ("a panic before the run", result(&format!("{}running 1 test\n{summary}\n", panic(333, RUN_FAILURE)), 101, RUN_FAILURE), killed.clone()),
        ("a second panic", result(&format!("running 1 test\nthread 't' panicked at x.rs:1:1:\nother\n{}{summary}\n",
            panic(333, RUN_FAILURE)), 101, RUN_FAILURE), killed),
        ("site and failure apart", result(&format!("running 1 test\n{}{}{summary}\n", panic(333, "other"), panic(340, RUN_FAILURE)),
            101, RUN_FAILURE), other.clone()),
        ("the failure on a second line", result(&format!("running 1 test\n{}{RUN_FAILURE}\n{summary}\n", panic(333, "other")),
            101, RUN_FAILURE), other.clone()),
        ("exit 0", result(&format!("running 1 test\n{}{summary}\n", panic(333, RUN_FAILURE)), 0, RUN_FAILURE),
            (Verdict::NoVerdict, "the test crashed: its run ended without a summary".to_owned())),
        ("an empty failure", result(&format!("running 1 test\n{}{summary}\n", panic(333, RUN_FAILURE)), 101, ""), other),
    ];
    for (row, found, wanted) in rows {
        assert_eq!(found, wanted, "{row}");
    }
}
