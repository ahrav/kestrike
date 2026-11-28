//! The run's GenMC rows: one lane call for the cases a plant has not run, each case judged by its own
//! output, and the second read of a case's output at its judgment.

use std::path::Path;

use kestrike_tools::json::Value;

use super::fixture::*;
use super::standins::positive;

fn lane_calls(fixture: &Fixture) -> Vec<Vec<String>> {
    fixture
        .lines(".lane")
        .iter()
        .map(|line| line.split(' ').map(str::to_owned).collect())
        .collect()
}

#[test]
fn a_genmc_row_runs_the_case_list_lane_and_judges_each_case() {
    let fixture = Fixture::new("genmc-row");
    fixture.commit();
    let violation = format!("violation:{JOIN_FREED}");
    let ran = fixture.run_with(
        &[JOIN_ROW],
        Opts {
            plan: Some(plan(&[("join-production", &[("planted", &violation)])])),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    let report = ran.report();
    assert_eq!(results(report, JOIN_ROW), ["killed"]);
    let entry = &row_results(report, JOIN_ROW)[0];
    assert_eq!(
        string(get(entry, "command")),
        "bash scripts/rust-lane.sh genmc pr join-production"
    );
    assert_eq!(
        (number(get(entry, "exit")), number(get(entry, "lane_exit"))),
        (42, 0)
    );
    let output = string(get(entry, "output"));
    assert_eq!(string(get(entry, "digest")), sha256_of(Path::new(&output)));
    assert_eq!(
        Path::new(&output)
            .file_name()
            .and_then(|name| name.to_str()),
        Some("genmc-join-production.txt")
    );
    let baseline = &items(get(report, "baseline"))[0];
    assert_eq!(
        (
            number(get(entry, "executions")),
            number(get(baseline, "executions"))
        ),
        (0, 5)
    );
    let lanes = lane_calls(&fixture);
    let phases: Vec<&str> = lanes.iter().map(|line| line[0].as_str()).collect();
    assert_eq!(phases, ["clean", "planted"]);
    assert_eq!(Path::new(&output).parent(), Some(Path::new(&lanes[1][1])));
    let work = format!("{}/", fixture.resolved("work").display());
    for line in &lanes {
        assert!(
            line[1].starts_with(&work) && line[2] == "never/false",
            "{line:?}"
        );
    }
    let survived = fixture.run_with(
        &[JOIN_ROW],
        Opts {
            work: Some(fixture.work("survived")),
            ..Opts::default()
        },
    );
    assert_eq!(results(survived.report(), JOIN_ROW), ["survived"]);
    let entry = &row_results(survived.report(), JOIN_ROW)[0];
    assert_eq!(
        (number(get(entry, "exit")), number(get(entry, "executions"))),
        (0, 3)
    );
    let modes = [
        ("norebuild", "no evidence that the kernel rebuilt"),
        ("abort", "the lane left no output"),
        ("badexit", "no exit code"),
    ];
    for (mode, reason) in modes {
        let ran = fixture.run_with(
            &[JOIN_ROW],
            Opts {
                work: Some(fixture.work(&format!("lane-{mode}"))),
                plan: Some(plan(&[("join-production", &[("planted", mode)])])),
                ..Opts::default()
            },
        );
        assert_eq!(ran.code(), Some(0), "{mode}: {}", ran.stderr);
        let entry = &row_results(ran.report(), JOIN_ROW)[0];
        assert_eq!(string(get(entry, "result")), "no verdict", "{mode}");
        assert_eq!(string(get(entry, "reason")), reason, "{mode}");
        assert_eq!(get(entry, "executions"), &Value::Null, "{mode}");
        if mode == "abort" {
            assert_eq!(get(entry, "exit"), &Value::Null);
            assert_eq!(number(get(entry, "lane_exit")), 1);
            assert_eq!(get(entry, "digest"), &Value::Null);
        }
    }
    let red = fixture.run_with(
        &[JOIN_ROW],
        Opts {
            work: Some(fixture.work("red")),
            plan: Some(plan(&[("join-production", &[("clean", &violation)])])),
            ..Opts::default()
        },
    );
    assert_eq!(red.code(), Some(3), "{}", red.stderr);
}

#[test]
fn a_multi_case_entry_judges_each_case_by_its_own_output() {
    let fixture = Fixture::new("multi-case");
    fixture.commit();
    let flagged = format!("violation:{CREDIT_FLAGGED}");
    let retain = format!("violation:{RETAIN}");
    let mut planned: Vec<(&str, &[(&str, &str)])> = Vec::new();
    let flagged_modes: &[(&str, &str)] = &[("planted", &flagged)];
    for case in &CREDIT_CASES[1..] {
        planned.push((case, flagged_modes));
    }
    let retain_modes: &[(&str, &str)] = &[("planted", &retain)];
    planned.push(("grace1-seq", retain_modes));
    let ran = fixture.run_with(
        &[CREDIT_ROW, GRACE_ROW],
        Opts {
            plan: Some(plan(&planned)),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    let report = ran.report();
    for entry in row_results(report, CREDIT_ROW) {
        let test = string(get(entry, "test"));
        let wanted = if test == "credit-seq-empty" {
            ("survived", 0)
        } else {
            ("killed", 42)
        };
        assert_eq!(
            (
                string(get(entry, "result")).as_str(),
                number(get(entry, "exit"))
            ),
            wanted,
            "{test}"
        );
        let output = string(get(entry, "output"));
        assert!(output.ends_with(&format!("/genmc-{test}.txt")), "{output}");
        assert_eq!(string(get(entry, "digest")), sha256_of(Path::new(&output)));
    }
    let tests: Vec<String> = row_results(report, CREDIT_ROW)
        .iter()
        .map(|entry| string(get(entry, "test")))
        .collect();
    assert_eq!(tests, CREDIT_CASES);
    let grace: Vec<(String, String)> = row_results(report, GRACE_ROW)
        .iter()
        .map(|entry| (string(get(entry, "test")), string(get(entry, "result"))))
        .collect();
    let wanted = [
        ("grace1-seq", "no verdict"),
        ("grace1-seq", "killed"),
        ("cutoff-pinfirst", "survived"),
    ]
    .map(|(test, result)| (test.to_owned(), result.to_owned()));
    assert_eq!(grace, wanted);
    let outputs = row_results(report, GRACE_ROW);
    assert_eq!(get(&outputs[0], "output"), get(&outputs[1], "output"));
    assert_eq!(items(get(report, "no verdict")), &[]);
    let planted: Vec<String> = lane_calls(&fixture)
        .iter()
        .filter(|line| line[0] == "planted")
        .map(|line| line[3..].join(" "))
        .collect();
    let credit = format!("genmc pr {}", CREDIT_CASES.join(" "));
    assert_eq!(
        planted,
        [
            credit.as_str(),
            "genmc pr grace1-seq",
            "genmc pr cutoff-pinfirst"
        ]
    );
}

/// The run takes a GenMC case's digest when the lane call ends and reads the case's output again by its
/// path at each judgment. A row whose loom test, run between two entries that name one case, rewrites that
/// case's output gets a later judgment of the new bytes, while every result of the case keeps the digest of
/// the bytes the lane wrote.
#[test]
fn a_genmc_output_rewritten_after_its_digest_is_judged_by_its_later_bytes() {
    let fixture = Fixture::new("second-read");
    let test = run_tests()[0].clone();
    fixture.commit_with(|catalog| {
        let join = entry("genmc", &["join-production"], JOIN_FREED);
        needing(
            catalog,
            JOIN_ROW,
            vec![join.clone(), entry("loom", &[&test], RUN_FAILURE), join],
        );
    });
    let rewrite = format!("rewrite:join-production:{JOIN_FREED}");
    let ran = fixture.run_with(
        &[JOIN_ROW],
        Opts {
            plan: Some(plan(&[(&test, &[("planted", &rewrite)])])),
            ..Opts::default()
        },
    );
    assert_eq!(ran.code(), Some(0), "{}", ran.stderr);
    let entries = row_results(ran.report(), JOIN_ROW);
    let judged: Vec<String> = entries
        .iter()
        .map(|entry| string(get(entry, "result")))
        .collect();
    assert_eq!(
        judged,
        ["survived", "survived", "no verdict"],
        "{entries:?}"
    );
    assert_eq!(
        string(get(&entries[2], "reason")),
        "join-production prints 0 Verification complete lines; join-production exited 0, declared a violation"
    );
    let (first, last) = (&entries[0], &entries[2]);
    assert_eq!(get(first, "output"), get(last, "output"));
    let earlier = kestrike_tools::python::hexdigest(positive(3).as_bytes());
    assert_eq!(string(get(first, "digest")), earlier);
    assert_eq!(string(get(last, "digest")), earlier);
    assert_ne!(sha256_of(Path::new(&string(get(last, "output")))), earlier);
}
