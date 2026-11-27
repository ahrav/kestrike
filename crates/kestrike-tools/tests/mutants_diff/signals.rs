//! The cases of signals: a handled signal stops the supervised group, removes the worktree and writes an
//! incomplete report; an ignored one stays ignored; a killed runner stops its tool through the
//! parent-death signal. The two signal windows run each in a process of its own, started from this test
//! executable.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use kestrike_tools::args::Parsed;
use kestrike_tools::json::Value;
use kestrike_tools::tools::mutants_diff::{self, INTERRUPT, Run};

use crate::fixture::{
    self, Fixture, HANGUP_PAUSE, MARKER_LIMIT, Plan, RUN_LIMIT, SOURCE, lib_rs, listed,
};

/// The variable that names the window a re-started test executable runs.
const ROLE: &str = "MUTANTS_DIFF_WINDOW";
const PLACE: &str = "MUTANTS_DIFF_PLACE";
const ARGS: &str = "MUTANTS_DIFF_ARGS";
/// Each of the two waits for a group leader after SIGTERM and after SIGKILL; a child that ends in less
/// time ended on SIGTERM.
const GRACE: Duration = Duration::from_secs(10);

fn two() -> Vec<(kestrike_tools::text::Text, kestrike_tools::text::Text)> {
    let names: Vec<String> = (0..2)
        .map(|n| format!("{SOURCE}/lib.rs:2:1: replace two -> u32 with {n}"))
        .collect();
    listed(&lib_rs(), &names)
}

fn reason(report: &kestrike_tools::json::Object) -> (bool, String) {
    let complete = report.get("complete") == Some(&Value::Bool(true));
    let reason = match report.get("reason") {
        Some(Value::String(text)) => text.to_string(),
        other => format!("{other:?}"),
    };
    (complete, reason)
}

#[test]
fn a_signal_while_a_mutant_runs_stops_the_tool_and_removes_the_worktree() {
    let fx = Fixture::new("signal-run");
    let before = fx.snapshot();
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        fx.clear();
        fx.plan(&Plan {
            hang: true,
            ..Plan::caught(&two())
        });
        let mut runner = fx.start_until_ready(fx.start(), "ready");
        runner.signal(signal);
        let out = runner.communicate(RUN_LIMIT);
        assert_eq!(out.code, 1, "{signal}: {}", out.all());
        let report = fx.report(Some(&out));
        assert_eq!(
            reason(&report),
            (false, format!("interrupted by signal {signal}"))
        );
        let Some(Value::Array(mutants)) = report.get("mutants") else {
            panic!("mutants is an array")
        };
        let outcomes: Vec<&Value> = mutants
            .iter()
            .map(|mutant| match mutant {
                Value::Object(mutant) => mutant.get("outcome").expect("an outcome"),
                other => panic!("{other:?}"),
            })
            .collect();
        let expected = [
            Value::String("caught".into()),
            Value::String("not-run".into()),
        ];
        assert_eq!(outcomes, expected.iter().collect::<Vec<_>>(), "{signal}");
        assert!(out.lines()[0].ends_with("; incomplete"), "{}", out.all());
        assert_eq!(
            fx.snapshot(),
            before,
            "{signal}: the dirty worktree is removed"
        );
        assert!(
            fx.state.join("terminated").exists(),
            "{signal}: the tool received SIGTERM first"
        );
        fx.assert_gone("grandchild.pid");
        fx.assert_gone("ready");
    }
}

#[test]
fn a_second_signal_during_cleanup_is_discarded() {
    let fx = Fixture::new("second-signal");
    let mutants = listed(&lib_rs(), &[format!("{SOURCE}/lib.rs:2:1: m")]);
    fx.plan(&Plan {
        list_hang: true,
        hold: true,
        ..Plan::new(&mutants, &[])
    });
    let before = fx.snapshot();
    let mut runner = fx.start_until_ready(fx.start(), "ready");
    runner.signal(libc::SIGTERM);
    fx.wait_for("terminating", &mut runner);
    runner.signal(libc::SIGINT);
    fs::write(fx.state.join("release"), "").expect("the release is written");
    let out = runner.communicate(RUN_LIMIT);
    assert_eq!(out.code, 1, "{}", out.all());
    let report = fx.report(Some(&out));
    assert_eq!(
        reason(&report),
        (false, format!("interrupted by signal {}", libc::SIGTERM))
    );
    assert_eq!(fx.snapshot(), before);
    assert!(fx.builds().is_empty());
    fx.assert_gone("grandchild.pid");
    fx.assert_gone("ready");
}

#[test]
fn a_signal_while_the_worktree_is_added_or_the_listing_runs_stops_it_and_removes_the_worktree() {
    let fx = Fixture::new("signal-early");
    let mutants = listed(&lib_rs(), &[format!("{SOURCE}/lib.rs:2:1: m")]);
    let before = fx.snapshot();
    let phases = [
        (
            "worktree add",
            Some(fx.git_wrapper("hang-add")),
            Plan::new(&mutants, &[]),
        ),
        (
            "listing",
            None,
            Plan {
                list_hang: true,
                ..Plan::new(&mutants, &[])
            },
        ),
    ];
    for (phase, env, plan) in phases {
        fx.clear();
        fx.plan(&plan);
        let start = match env {
            Some(env) => fx.start().env(env),
            None => fx.start(),
        };
        let mut runner = fx.start_until_ready(start, "ready");
        runner.signal(libc::SIGTERM);
        let out = runner.communicate(RUN_LIMIT);
        assert_eq!(out.code, 1, "{phase}: {}", out.all());
        let report = fx.report(Some(&out));
        assert_eq!(
            reason(&report),
            (false, format!("interrupted by signal {}", libc::SIGTERM)),
            "{phase}"
        );
        assert_eq!(fx.snapshot(), before, "{phase}");
        assert!(fx.builds().is_empty(), "{phase}");
        fx.assert_gone("ready");
    }
}

#[test]
fn a_signal_ignored_at_start_stays_ignored() {
    let fx = Fixture::new("ignored-hangup");
    fx.plan(&Plan {
        hang: true,
        ..Plan::caught(&two())
    });
    let mut runner = fx.start_until_ready(fx.start().ignore_hangup(), "ready");
    runner.signal(libc::SIGHUP);
    thread::sleep(HANGUP_PAUSE);
    assert!(
        runner.poll().is_none(),
        "a run started under nohup outlives its terminal"
    );
    runner.signal(libc::SIGTERM);
    let out = runner.communicate(RUN_LIMIT);
    assert_eq!(out.code, 1, "{}", out.all());
    assert_eq!(
        reason(&fx.report(Some(&out))).1,
        format!("interrupted by signal {}", libc::SIGTERM)
    );
}

#[test]
fn a_killed_runner_stops_the_tool() {
    let fx = Fixture::new("killed-runner");
    fx.plan(&Plan {
        hang: true,
        ..Plan::caught(&two())
    });
    let mut runner = fx.start_until_ready(fx.start(), "ready");
    runner.kill();
    runner.communicate(RUN_LIMIT);
    fx.assert_gone("ready");
    fx.assert_gone("grandchild.pid");
    let start = Instant::now();
    while !fx.state.join("terminated").exists() && start.elapsed() < MARKER_LIMIT {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        fx.state.join("terminated").exists(),
        "the tool received SIGTERM when the runner died"
    );
}

/// `start_window` starts this test executable again for the test `name` with `window` in [`ROLE`], in
/// `cwd` with `env`, and fails the case unless that run passes.
fn start_window(name: &str, window: &str, cwd: &Path, env: &fixture::Env) {
    let output = Command::new(std::env::current_exe().expect("the test executable is known"))
        .args(["--exact", name, "--nocapture", "--test-threads", "1"])
        .current_dir(cwd)
        .env_clear()
        .envs(fixture::with(env, &[(ROLE, OsStr::new(window))]))
        .output()
        .expect("the test executable starts");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let shown = format!(
        "{window}: {}\n{stdout}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{shown}");
    assert!(stdout.contains("1 passed"), "{shown}");
}

fn raise(signal: i32) {
    // SAFETY: `raise` takes an integer; the handlers record the signal and return.
    assert_eq!(unsafe { libc::raise(signal) }, 0);
}

/// `blocked` returns the `SigBlk` mask of a `/proc/<pid>/status` text.
fn blocked(status: &str) -> u64 {
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix("SigBlk:"))
        .expect("the status has SigBlk");
    u64::from_str_radix(line.trim(), 16).expect("the mask is hexadecimal")
}

/// `spawn_window` runs in a process of its own. With `before` the signal is recorded before the child
/// starts; with `after` a thread sends it once the child has written its signal mask.
fn spawn_window(window: &str) {
    let place = PathBuf::from(std::env::var_os(PLACE).expect("the place is given"));
    mutants_diff::install_handlers().expect("the handlers install");
    let mask = place.join(format!("{window}.mask"));
    let script = format!(
        "grep '^SigBlk:' /proc/self/status > '{0}.tmp' && mv '{0}.tmp' '{0}'; exec sleep 600",
        mask.display()
    );
    let argv = [OsStr::new("sh"), OsStr::new("-c"), OsStr::new(&script)];
    let (stdout, stderr) = (
        place.join(format!("{window}.out")),
        place.join(format!("{window}.err")),
    );
    let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let (sent, signaled) = std::sync::mpsc::channel();
    if window == "before" {
        raise(libc::SIGTERM);
        sent.send(Instant::now()).expect("the time is sent");
    } else {
        let mask = mask.clone();
        thread::spawn(move || {
            let start = Instant::now();
            while !mask.exists() && start.elapsed() < MARKER_LIMIT {
                thread::sleep(Duration::from_millis(10));
            }
            sent.send(Instant::now()).expect("the time is sent");
            // SAFETY: `kill` and `getpid` take and return integers.
            unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
        });
    }
    let ended = mutants_diff::supervise(&INTERRUPT, &argv, &stdout, &stderr, None, &env);
    let elapsed = signaled.recv().expect("the signal time arrives").elapsed();
    let stop = ended.expect_err("the recorded signal stops the child");
    assert_eq!(
        (stop.code(), stop.reason().to_string()),
        (1, format!("interrupted by signal {}", libc::SIGTERM))
    );
    assert!(
        elapsed < GRACE,
        "the new process ended on SIGTERM, before SIGKILL could follow: {elapsed:?}"
    );
    if window == "after" {
        let blocked = blocked(&fs::read_to_string(&mask).expect("the child wrote its mask"));
        let handled =
            [libc::SIGINT, libc::SIGTERM, libc::SIGHUP].map(|signal| 1u64 << (signal - 1));
        assert_eq!(
            blocked & handled.iter().sum::<u64>(),
            0,
            "the new process starts with none of the three blocked"
        );
    }
    raise(libc::SIGINT);
    assert_eq!(
        INTERRUPT.recorded(),
        Some(libc::SIGTERM),
        "a later signal changes nothing"
    );
}

#[test]
fn a_signal_during_a_spawn_stops_the_new_process() {
    if let Some(window) = std::env::var_os(ROLE) {
        spawn_window(&window.to_string_lossy());
        return;
    }
    let fx = Fixture::new("spawn-window");
    let env = fixture::with(&fx.env, &[(PLACE, fx.state.as_os_str())]);
    for window in ["before", "after"] {
        start_window(
            "signals::a_signal_during_a_spawn_stops_the_new_process",
            window,
            &fx.state,
            &env,
        );
    }
}

/// `hand_off_window` runs the tool's steps in a process of its own and records SIGTERM between the last
/// step and the hand-off to cleanup.
fn hand_off_window() {
    let args: Vec<OsString> = std::env::var(ARGS)
        .expect("the arguments are given")
        .split('\n')
        .map(OsString::from)
        .collect();
    let Parsed::Run(options) = mutants_diff::parse(&args) else {
        panic!("the arguments parse: {args:?}");
    };
    let prepared = mutants_diff::preflight(options).expect("the input passes");
    let mut run = Run::new(prepared);
    run.install().expect("the handlers install");
    let executed = run.execute();
    assert_eq!(INTERRUPT.recorded(), None);
    raise(libc::SIGTERM);
    let stop = run.hand_off(executed);
    assert_eq!(run.finish(stop), 1);
}

#[test]
fn a_first_signal_at_the_hand_off_to_cleanup_still_removes_the_worktree_and_writes_the_report() {
    if std::env::var_os(ROLE).is_some() {
        hand_off_window();
        return;
    }
    let fx = Fixture::new("hand-off");
    fx.plan(&Plan::caught(&listed(
        &lib_rs(),
        &[format!("{SOURCE}/lib.rs:2:1: m")],
    )));
    let before = fx.git(&["worktree", "list", "--porcelain"]);
    let args = [
        "--base".to_owned(),
        fx.base.clone(),
        "--head".to_owned(),
        fx.head.clone(),
        "--artifacts".to_owned(),
        fx.artifacts.display().to_string(),
        "--cargo".to_owned(),
        fx.cargo.display().to_string(),
    ]
    .join("\n");
    let env = fixture::with(&fx.env, &[(ARGS, OsStr::new(&args))]);
    let name = "signals::a_first_signal_at_the_hand_off_to_cleanup_still_removes_the_worktree_and_writes_the_report";
    start_window(name, "hand-off", &fx.repo, &env);
    let report = fx.report(None);
    assert_eq!(
        reason(&report),
        (false, format!("interrupted by signal {}", libc::SIGTERM))
    );
    assert_eq!(fx.git(&["worktree", "list", "--porcelain"]), before);
}
