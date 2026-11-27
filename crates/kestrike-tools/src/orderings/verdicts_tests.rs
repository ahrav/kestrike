use std::fs;
use std::path::Path;

use super::{Outcome, Verdict, case_exit, genmc_result, loom_result};
use crate::genmc::case::tests::{
    DEPARTURE, FREED, POSITIVE, POSITIVE_GRAPH, declaration, line_of, root, violation,
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
struct Lane<'a> {
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
    fn new(text: &'a str, graph: &'a str, code: &'a str) -> Self {
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

    fn write(&self, evidence: &Path, declared: &Value) {
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
    let Value::Object(mut declared) = declared.clone() else {
        panic!("the declaration is an object");
    };
    let Some(Value::Object(cases)) = declared.get_mut("cases") else {
        panic!("the declaration holds cases");
    };
    let Some(Value::Object(own)) = cases.get_mut(CASE) else {
        panic!("the case is declared");
    };
    own.insert(
        "intrinsics",
        Value::Array(
            intrinsics
                .iter()
                .map(|&name| Value::String(name.into()))
                .collect(),
        ),
    );
    Value::Object(declared)
}

type Judged = (Verdict, String);

fn judged(lane: &Lane<'_>, declared: &Value, kernel: Option<&str>) -> Judged {
    let scratch = Scratch::new("genmc-verdict");
    lane.write(&scratch.0, declared);
    let code = case_exit(&scratch.0, CASE);
    let kill = kernel.map(|kernel| (DEPARTURE, kernel));
    let outcome: Outcome = genmc_result(
        &root(),
        declared,
        CASE,
        kill,
        &scratch.0,
        true,
        code.as_ref(),
    )
    .expect("the evidence is judged");
    let evidence = scratch.0.display().to_string();
    (
        outcome.verdict(),
        outcome.reason().replace(&evidence, "<EV>"),
    )
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
    let rows: Vec<(Judged, Judged)> = vec![
        (judge(Lane::new(POSITIVE, POSITIVE_GRAPH, "0")),
         (Verdict::Survived, "judge_case accepts the positive declaration".into())),
        (judge(Lane::new(&killing, &killing_graph, "42")),
         (Verdict::Killed, "judge_case accepts the violation declaration".into())),
        (judge(Lane::new(&freed, &freed_graph, "42")),
         (Verdict::NoVerdict, format!("join-production exited 42, declared positive; join-production failed at \
join_kernel.rs:{freed_line}, declared join_kernel.rs:{killed_line}"))),
        (judge(Lane::new(POSITIVE, POSITIVE_GRAPH, "124")),
         (Verdict::NoVerdict, "join-production was interrupted (exit 124); join-production was interrupted (exit 124)".into())),
        (judge(Lane::new(&aborted, POSITIVE_GRAPH, "0")),
         (Verdict::NoVerdict, "join-production aborted: 'LLVM ERROR: unsupported intrinsic'; join-production aborted: \
'LLVM ERROR: unsupported intrinsic'".into())),
        (judge(Lane { check: false, ..Lane::new(POSITIVE, POSITIVE_GRAPH, "0") }),
         (Verdict::NoVerdict, "no evidence that the kernel rebuilt".into())),
        (judge(Lane { config: Some(r#"{"build": {"rustflags": ["--cfg", "x"]}}"#), ..Lane::new(POSITIVE, POSITIVE_GRAPH, "0") }),
         (Verdict::NoVerdict, "the lane's build or command is not the declared one: the cargo configuration sets \
build.rustflags".into())),
        (judge(Lane { argv: Some(vec!["/elsewhere/genmc".into(), "x".into()]), ..Lane::new(POSITIVE, POSITIVE_GRAPH, "0") }),
         (Verdict::NoVerdict, format!("the lane's build or command is not the declared one: {command}"))),
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
            (Verdict::NoVerdict, shape.to_owned()),
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
            "judge_case accepts the violation declaration".to_owned()
        )
    );
    let calls = "join-production's bitcode calls [], declared ['llvm.umin.i64']";
    assert_eq!(
        judged(&lane(Some(&[])), &pinned, Some(KERNEL)),
        (Verdict::NoVerdict, format!("{calls}; {calls}"))
    );
    let positive = "join-production exited 42, declared positive";
    assert_eq!(
        judged(&lane(None), &declared, None),
        (Verdict::NoVerdict, positive.to_owned())
    );
    let (verdict, reason) = judged(&lane(None), &declared, Some("src/absent_kernel.rs"));
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
