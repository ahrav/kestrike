//! The order of a sweep's and a fuzz run's argument checks and their
//! search for a cgroup root, and the result of a scoped command's end.

use super::*;
use crate::store::fixture::Case;

/// The sweep arguments `line` holds beside a root, an archive and the
/// campaign `host`.
fn swept(case: &Case, line: &[(&str, &str)]) -> Result<serde_json::Value, Error> {
    let mut words: Vec<OsString> = Vec::new();
    for (key, value) in [
        ("--root", case.root.join("sweep").into_os_string()),
        ("--archive", case.root.join("archive").into_os_string()),
        ("--campaign", "host".into()),
    ] {
        words.extend([key.into(), value]);
    }
    for (key, value) in line {
        words.extend([key.into(), value.into()]);
    }
    sweep_campaign("sweep", &Args::parse("sweep", &words)?)
}

/// A sweep checks the ranges of its arguments before it looks for a cgroup
/// root, so a refused one is a rejection whether or not a root is named
/// and on a host that can start no scope: zero workers here.
#[test]
fn a_sweep_with_no_workers_is_rejected_before_a_cgroup_root_is_sought() {
    let case = Case::new();
    let swept = swept(&case, &[("--profiles", "upload"), ("--workers", "0")]);
    assert!(
        matches!(&swept, Err(Error::Rejected(reason)) if reason.contains("1 to 1024 workers")),
        "{swept:?}"
    );
}

/// A fuzz run checks its ranges and the bytes of its root and archive
/// paths before it looks for a cgroup root, so each refusal is a
/// rejection on a host that can start no scope, with the root unmade: no
/// `--for`, a value one past either end of each range, and a root path
/// with a space, which the merge's shell line would split. The spaced
/// root carries a `--scope` value the cgroup search refuses with its own
/// reason, so the byte check is seen to come first on any host. Each
/// range's two ends pass the checks and meet that `--scope` refusal.
#[test]
fn a_fuzz_run_refuses_its_arguments_before_a_cgroup_root_is_sought() {
    let case = Case::new();
    let range = "1 to 2147483647 seconds, 1 to 1024 workers";
    for (name, line, reason) in [
        ("fuzz", vec![], "missing --for"),
        ("fuzz", vec!["--for", "0"], range),
        ("fuzz", vec!["--for", "2147483648"], range),
        ("fuzz", vec!["--for", "60", "--workers", "0"], range),
        ("fuzz", vec!["--for", "60", "--workers", "1025"], range),
        ("fuzz", vec!["--for", "60", "--memory", "0"], range),
        ("fuzz", vec!["--for", "60", "--processes", "0"], range),
        ("fuzz", vec!["--for", "60", "--processes", "4194305"], range),
        (
            "fuzz root",
            vec!["--for", "60", "--scope", "elsewhere"],
            "A-Za-z0-9/._=,-",
        ),
        (
            "fuzz",
            vec![
                "--for",
                "1",
                "--workers",
                "1",
                "--memory",
                "1",
                "--processes",
                "1",
                "--scope",
                "elsewhere",
            ],
            "--scope takes the value own",
        ),
        (
            "fuzz",
            vec![
                "--for",
                "2147483647",
                "--workers",
                "1024",
                "--processes",
                "4194304",
                "--scope",
                "elsewhere",
            ],
            "--scope takes the value own",
        ),
    ] {
        let root = case.root.join(name);
        let mut words: Vec<OsString> = vec![
            "--root".into(),
            root.clone().into_os_string(),
            "--archive".into(),
            case.root.join("archive").into_os_string(),
        ];
        words.extend(line.into_iter().map(OsString::from));
        let ran = fuzz_campaign("fuzz", &Args::parse("fuzz", &words).unwrap());
        assert!(
            matches!(&ran, Err(Error::Rejected(found)) if found.contains(reason)),
            "{reason}: {ran:?}"
        );
        assert!(!root.exists(), "{reason}");
    }
}

/// A fuzz run whose control was missed has the exit 1 verdict, as has
/// the recorded exit 1 of a scoped one, and a scoped fuzz run's exit 1 is
/// that verdict only beside the record its run wrote for this command's
/// token. Every other ending of a run is a success.
#[test]
fn a_fuzz_run_has_a_verdict_for_a_missed_control() {
    use serde_json::json;
    use std::os::unix::process::ExitStatusExt;

    let missed = json!({"run": 3, "ending": "control missed"});
    assert!(is_verdict("fuzz", &missed) && is_verdict("fuzz", &json!({"exit": 1})));
    assert!(!is_verdict("fuzz-status", &missed));
    // The command's output carries the verdict the exit code is read from.
    assert!(matches!(output("fuzz", missed.clone()), Output::Verdict(_)));
    for command in ["fuzz-status", "confirm"] {
        let plain = output(command, missed.clone());
        assert!(matches!(plain, Output::Value(_)), "{command}");
    }
    for ending in ["deadline", "signal", "failed workers", "key table full"] {
        assert!(!is_verdict("fuzz", &json!({"ending": ending})), "{ending}");
    }
    let case = Case::new();
    let token = OsString::from("7-11");
    let ended = || scoped("fuzz", ExitStatus::from_raw(1 << 8), &case.root, &token);
    // A scoped run records its verdict for its token alone and for a
    // missed control alone.
    record(
        "fuzz",
        &case.root,
        Some(&token),
        &json!({"ending": "deadline"}),
    )
    .unwrap();
    record("fuzz", &case.root, None, &missed).unwrap();
    assert!(matches!(ended(), Err(Error::Held(_))));
    record("fuzz", &case.root, Some(&token), &missed).unwrap();
    assert_eq!(ended().unwrap(), json!({"exit": 1}));
    // A fuzz run refuses a token given without `--scope`, as a sweep does.
    let words: Vec<OsString> = [
        "--root",
        "/r",
        "--archive",
        "/a",
        "--for",
        "9",
        "--verdict",
        "7-11",
    ]
    .map(OsString::from)
    .to_vec();
    let refused = fuzz_campaign("fuzz", &Args::parse("fuzz", &words).unwrap());
    assert!(
        matches!(&refused, Err(Error::Rejected(reason)) if reason.contains("--verdict")),
        "{refused:?}"
    );
}

/// `fuzz-status` on a root no run has written is a rejection, and it
/// leaves the absent root unmade.
#[test]
fn the_status_of_a_root_without_a_run_is_rejected() {
    let case = Case::new();
    let root = case.root.join("fuzz");
    let words: Vec<OsString> = vec!["--root".into(), root.clone().into_os_string()];
    let status = fuzz_campaign("fuzz-status", &Args::parse("fuzz-status", &words).unwrap());
    assert!(
        matches!(&status, Err(Error::Rejected(reason)) if reason.contains("no fuzz run")),
        "{status:?}"
    );
    assert!(!root.exists());
}

/// A count or a profile name the sweep refuses without its archive is
/// rejected before a scope is made for a sweep with no cgroup root: a
/// `root` count and a profile name that is a path here.
#[test]
fn a_sweep_admission_would_refuse_is_rejected_before_a_scope_is_made() {
    let case = Case::new();
    for line in [
        [("--profiles", "upload"), ("--set", "root=1")],
        [("--profiles", "a/b"), ("--set", "turns=64")],
    ] {
        let swept = swept(&case, &line);
        assert!(matches!(&swept, Err(Error::Rejected(_))), "{swept:?}");
    }
}

/// `systemd-run` exits 1 also when it starts no scope, so a scoped
/// `sweep`'s exit 1 is a verdict only when its run recorded it for this
/// command's token. A scoped `confirm` that exits 1 is a hold, and so is
/// a scoped `sweep` whose root holds no verdict or the verdict of a run
/// another command named. Every other end is the one
/// [`scope::ended`](super::super::scope::ended) gives it.
#[test]
fn a_scoped_sweeps_exit_1_is_a_verdict_only_beside_its_record() {
    use std::os::unix::process::ExitStatusExt;

    let case = Case::new();
    let exited = |code: i32| ExitStatus::from_raw(code << 8);
    let token = OsString::from("7-11");
    let scoped = |command: &str, status| scoped(command, status, &case.root, &token);
    let held = |command: &str| matches!(scoped(command, exited(1)), Err(Error::Held(_)));
    assert_eq!(
        scoped("sweep", exited(0)).unwrap(),
        serde_json::json!({"exit": 0})
    );
    assert!(matches!(
        scoped("sweep", exited(2)),
        Err(Error::Rejected(_))
    ));
    assert!(held("sweep") && held("confirm"));
    let record = |token: &str| {
        super::super::scope::record_verdict(&case.root, &OsString::from(token)).unwrap();
    };
    record("7-12");
    assert!(held("sweep") && held("confirm"));
    // The verdict of another command's run, recorded after this one's,
    // leaves this one's in place.
    record("7-11");
    record("7-13");
    assert!(held("confirm"));
    assert_eq!(
        scoped("sweep", exited(1)).unwrap(),
        serde_json::json!({"exit": 1})
    );
    // The command that read its verdict removed it.
    assert!(held("sweep"));
}

/// `sweep-status` and `confirm` can read the totals even when `sweep`
/// issues a verdict for an alarm or a profile with zero passes.
#[test]
fn a_sweep_has_a_verdict_for_an_alarm_or_a_profile_with_no_pass() {
    use serde_json::json;

    let no_pass = json!({"runs": 64, "no_pass": ["upload"]});
    let alarm = json!({"runs": 64, "alarm": "1 control runs were missed"});
    for value in [&no_pass, &alarm, &json!({"exit": 1})] {
        assert!(is_verdict("sweep", value), "{value}");
        assert!(!is_verdict("sweep-status", value), "{value}");
        assert!(!is_verdict("confirm", value), "{value}");
    }
    for value in [json!({"runs": 64}), json!({"exit": 0}), json!(null)] {
        assert!(!is_verdict("sweep", &value), "{value}");
    }
}

#[test]
fn a_sweep_prints_totals_that_report_unlisted_uncaught_texts_as_a_value() {
    let reported = serde_json::json!({
        "runs": 64,
        "unlisted_uncaught": {"boundary": ["an unexpected binding"]},
    });
    assert!(!is_verdict("sweep", &reported));
    assert!(matches!(output("sweep", reported), Output::Value(_)));
}

/// A status read preserves access to totals that caused a sweep verdict.
#[test]
fn a_sweep_has_a_verdict_for_an_unreached_event() {
    let totals = serde_json::json!({"unreached": {"cluster-pressure": ["misses"]}});
    assert!(is_verdict("sweep", &totals));
    assert!(!is_verdict("sweep-status", &totals));
}

/// A sweep whose totals list a planned crash window under `no_window`
/// has a verdict, prints them as one and exits 1; `sweep-status` prints
/// the same totals as a value and exits 0. `windows_missing` alone is no
/// verdict, and a sweep that prints it exits 0.
#[test]
fn a_sweep_has_a_verdict_for_a_planned_window_at_zero() {
    use crate::exit::Exit;

    let code = |printed: Output| Exit::Supervisor(printed.exit()).code();
    let totals = serde_json::json!({
        "windows_missing": {"recovery-512": ["b"]},
        "no_window": {"recovery-512": ["b"]},
    });
    assert!(is_verdict("sweep", &totals));
    assert!(!is_verdict("sweep-status", &totals));
    assert!(
        matches!(output("sweep", totals.clone()), Output::Verdict(printed) if printed == totals)
    );
    assert!(
        matches!(output("sweep-status", totals.clone()), Output::Value(printed) if printed == totals)
    );
    assert_eq!(code(output("sweep", totals.clone())), 1);
    assert_eq!(code(output("sweep-status", totals)), 0);
    let diagnostic = serde_json::json!({"windows_missing": {"recovery-512": ["b"]}});
    assert!(!is_verdict("sweep", &diagnostic));
    assert!(matches!(
        output("sweep", diagnostic.clone()),
        Output::Value(_)
    ));
    assert_eq!(code(output("sweep", diagnostic)), 0);
}

/// Recording needs both the command's token and verdict totals. The outer
/// command consumes the matching record once to distinguish exit 1 from a hold.
#[test]
fn a_scoped_sweep_records_the_verdict_of_its_totals() {
    use serde_json::json;
    use std::os::unix::process::ExitStatusExt;

    let case = Case::new();
    let token = OsString::from("7-11");
    let ended = || scoped("sweep", ExitStatus::from_raw(1 << 8), &case.root, &token);
    let no_pass = json!({"runs": 64, "no_pass": ["upload"]});
    let alarm = json!({"runs": 64, "alarm": "1 control runs were missed"});
    record("sweep", &case.root, Some(&token), &json!({"runs": 64})).unwrap();
    assert!(matches!(ended(), Err(Error::Held(_))));
    for totals in [
        &no_pass,
        &alarm,
        &json!({"unreached": {"cluster-pressure": ["misses"]}}),
        &json!({"no_window": {"recovery-512": ["b"]}}),
    ] {
        record("sweep", &case.root, None, totals).unwrap();
        assert!(matches!(ended(), Err(Error::Held(_))), "{totals}");
        record("sweep", &case.root, Some(&token), totals).unwrap();
        assert_eq!(ended().unwrap(), json!({"exit": 1}), "{totals}");
        assert!(matches!(ended(), Err(Error::Held(_))), "{totals}");
    }
}

/// A process limit past the largest a cgroup takes is a refused argument,
/// as it is for a supervised attempt, so the sweep exits as a rejection
/// before it claims its root or makes a scope.
#[test]
fn a_sweep_with_a_process_limit_past_the_cgroup_bound_is_rejected() {
    let case = Case::new();
    let swept = swept(
        &case,
        &[("--profiles", "upload"), ("--processes", "4194305")],
    );
    assert!(
        matches!(&swept, Err(Error::Rejected(reason)) if reason.contains("4194304 processes")),
        "{swept:?}"
    );
    assert!(!case.root.join("sweep").exists());
}

/// A `--scope` value other than `own` is refused: the option marks the
/// run a sweep makes of itself inside a scope, and names nothing else.
#[test]
fn a_scope_value_other_than_own_is_rejected() {
    let case = Case::new();
    let swept = swept(&case, &[("--profiles", "upload"), ("--scope", "other")]);
    assert!(
        matches!(&swept, Err(Error::Rejected(reason)) if reason.contains("--scope")),
        "{swept:?}"
    );
    assert!(!case.root.join("sweep").exists());
}

/// `--verdict` names the record of a scoped run's verdict, so a sweep
/// refuses one given without `--scope`, and one that is no token: a file
/// name of the root is made from it.
#[test]
fn a_verdict_token_is_rejected_outside_a_scoped_sweep_or_malformed() {
    let case = Case::new();
    for line in [
        vec![("--profiles", "upload"), ("--verdict", "7-11")],
        vec![
            ("--profiles", "upload"),
            ("--scope", "own"),
            ("--verdict", "../7"),
        ],
    ] {
        let swept = swept(&case, &line);
        assert!(
            matches!(&swept, Err(Error::Rejected(reason)) if reason.contains("--verdict")),
            "{swept:?}"
        );
    }
    assert!(!case.root.join("sweep").exists());
}
