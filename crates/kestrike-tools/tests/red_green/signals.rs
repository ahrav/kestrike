//! These tests cover build-lock lifetime and signal handling.

use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;

use super::standins::stub_runner;
use super::support::{
    Call, Done, Fixture, HOOKLESS, MADE, MAKE_TEMP, SPAWN, SPAWNED, assert_alive, assert_ended,
    assert_gone, at, keys, kill, pid_in, private_dir, read, root, state_of, text, wait_for, write,
};

pub fn stub_top(fx: &Fixture) -> PathBuf {
    let top = fx.root.join("top");
    let scripts = top.join("scripts");
    if !scripts.exists() {
        private_dir(&top);
        private_dir(&scripts);
        fs::copy(
            root().join("scripts/select-tests.py"),
            scripts.join("select-tests.py"),
        )
        .expect("the selector is copied");
        write(
            &scripts.join("reproduce-test.py"),
            stub_runner(&root().join("scripts/reproduce-test.py")),
        );
    }
    top
}

/// A signal-stopped run exits with status `128 + signal`, leaves stdout empty, writes no receipt and
/// preserves the checkout. If `base.pid` exists, the recorded runner must have terminated when
/// `stopped` checks it.
pub fn stopped(fx: &Fixture, done: &Done, signal: i32) {
    assert_eq!(done.code, 128 + signal, "{}", done.shown());
    assert_eq!(done.stdout, "", "{}", done.shown());
    assert_eq!(fx.receipts(), Vec::<PathBuf>::new());
    let runner = fx.state.join("base.pid");
    if runner.exists() {
        assert_ended(pid_in(&runner));
    }
    fx.assert_checkout_unchanged();
}

struct Point<'a> {
    ready: PathBuf,
    plan: &'a str,
    call: Call,
    signal: i32,
    again: bool,
    before: &'a dyn Fn(),
}

impl Default for Point<'_> {
    fn default() -> Self {
        Self {
            ready: PathBuf::new(),
            plan: "{}",
            call: Call::default(),
            signal: libc::SIGTERM,
            again: false,
            before: &|| {},
        }
    }
}

fn interrupt(fx: &Fixture, point: &Point<'_>) {
    let Point {
        ready,
        plan,
        call,
        signal,
        again,
        before,
    } = point;
    let (signal, again) = (*signal, *again);
    fx.plan(plan);
    let running = fx.spawn_tool(call);
    wait_for(ready);
    if ready.ends_with("grandchild.pid") {
        assert_alive(pid_in(ready));
    }
    before();
    running.signal(signal);
    if again {
        std::thread::sleep(std::time::Duration::from_millis(500));
        running.signal(signal);
    }
    let done = running.finish();
    stopped(fx, &done, signal);
}

/// The surviving runner keeps the build lock after SIGKILL terminates the command: a second run prints
/// the waiting line once and waits for the surviving runner to release the build lock.
#[test]
fn a_runner_left_by_a_killed_command_keeps_the_build_lock() {
    let fx = Fixture::new();
    fx.plan(r#"{"base": {"build_hang": true}}"#);
    let first = fx.spawn_tool(&Call::default());
    wait_for(&fx.state.join("grandchild.pid"));
    first.signal(libc::SIGKILL);
    let killed = first.finish();
    assert_eq!(killed.code, -libc::SIGKILL, "{}", killed.shown());
    let runner = pid_in(&fx.state.join("base.pid"));
    assert_alive(runner);
    fx.plan("{}");
    let second = fx.spawn_tool(&Call::default());
    let target = fx.repo.join("target/red-green/build");
    assert_eq!(
        second.first_stderr_line(),
        Some(format!(
            "red-green: waiting for another run that builds in {}\n",
            target.display()
        ))
    );
    assert_eq!(fx.build_legs(), ["base"]);
    assert!(kill(runner, libc::SIGTERM));
    let done = second.finish();
    assert_eq!(done.code, 0, "{}", done.shown());
    assert_eq!(done.stderr.matches("waiting for another run").count(), 1);
    assert_gone(pid_in(&fx.state.join("grandchild.pid")));
}

struct Orphan(i32);

impl Drop for Orphan {
    fn drop(&mut self) {
        kill(-self.0, libc::SIGKILL);
    }
}

/// A build keeps the build lock after SIGKILL terminates its runner. The first run reports the base
/// leg as incomplete, and a second run waits for the build lock.
#[test]
fn a_build_left_by_a_killed_runner_keeps_the_build_lock() {
    let fx = Fixture::new();
    fx.plan(r#"{"base": {"build_hang": true}}"#);
    let first = fx.spawn_tool(&Call::default());
    wait_for(&fx.state.join("grandchild.pid"));
    let orphan = Orphan(pid_in(&fx.state.join("supervised.pid")));
    assert!(kill(pid_in(&fx.state.join("base.pid")), libc::SIGKILL));
    let done = first.finish();
    assert_eq!(done.code, 1, "{}", done.shown());
    assert!(
        done.stdout
            .contains("the runner did not complete the base leg: exit -9"),
        "{}",
        done.shown()
    );
    assert_eq!(state_of(orphan.0), Some('S'));
    fx.plan("{}");
    let second = fx.spawn_tool(&Call::default());
    let target = fx.repo.join("target/red-green/build");
    assert_eq!(
        second.first_stderr_line(),
        Some(format!(
            "red-green: waiting for another run that builds in {}\n",
            target.display()
        ))
    );
    assert_eq!(fx.build_legs(), ["base"]);
    drop(orphan);
    let done = second.finish();
    assert_eq!(done.code, 0, "{}", done.shown());
}

/// The run records `proven` even when it receives SIGTERM during final cleanup.
#[test]
fn a_signal_during_the_final_cleanup_lets_the_run_finish() {
    let fx = Fixture::new();
    let delivered = fx.state.join("delivered");
    let env = fx.git_wrapper(&format!(
        "case \"$*\" in \"worktree remove \"*) [ -e '{0}' ] || {{ touch '{0}'; kill -TERM \"$PPID\"; \
         echo 'fatal: refused' >&2; exit 1; }};;\nesac\nexec GIT \"$@\"\n",
        delivered.display()
    ));
    let done = fx.tool(&Call {
        env: Some(env),
        ..Call::default()
    });
    assert!(delivered.exists());
    assert_eq!(done.code, 0, "{}", done.shown());
    assert!(done.stdout.starts_with("red-green: "), "{}", done.shown());
    let (path, receipt) = fx.receipt(&done);
    assert_eq!(text(at(&receipt, "result")), "proven");
    assert_eq!(fx.receipts(), [path]);
    assert_eq!(fx.build_legs(), ["base", "head"]);
    assert!(!done.stderr.contains("could not remove worktree"));
    fx.assert_checkout_unchanged();
    let always = fx.git_wrapper(
        "case \"$*\" in \"worktree remove \"*/base) echo 'fatal: refused' >&2; exit 1;;\nesac\n\
         exec GIT \"$@\"\n",
    );
    let done = fx.tool(&Call {
        env: Some(always),
        ..Call::default()
    });
    assert_eq!(done.code, 0, "{}", done.shown());
    let named: Vec<&str> = done
        .stderr
        .lines()
        .filter_map(|line| line.strip_prefix("red-green: could not remove worktree "))
        .collect();
    let [named] = named[..] else {
        panic!("one worktree is named: {}", done.shown());
    };
    let tree = named
        .strip_suffix("/base: fatal: refused")
        .expect("the base worktree is named with Git's error");
    assert!(
        tree.starts_with(&format!("{}/kestrike-red-green-", fx.tmp.display()))
            && !tree.contains(char::is_whitespace),
        "{named}"
    );
    assert_eq!(fx.worktrees(), 2);
    assert_eq!(fs::read_dir(&fx.tmp).expect("listed").count(), 0);
}

/// A SIGTERM during a build stops the leg, ends the build's process group and removes the worktrees.
#[test]
fn a_sigterm_during_a_build_stops_the_leg_and_removes_the_worktrees() {
    let fx = Fixture::new();
    interrupt(
        &fx,
        &Point {
            ready: fx.state.join("grandchild.pid"),
            plan: r#"{"base": {"build_hang": true}}"#,
            ..Point::default()
        },
    );
    assert_gone(pid_in(&fx.state.join("grandchild.pid")));
    assert_gone(pid_in(&fx.state.join("supervised.pid")));
}

/// A SIGTERM during an attempt that ignores SIGTERM stops the leg: the run waits through a second
/// SIGTERM for the runner's exit before the first worktree removal.
#[test]
fn a_sigterm_during_an_attempt_stops_the_leg_and_removes_the_worktrees() {
    let fx = Fixture::new();
    let (observed, alive) = (
        fx.state.join("remove-observed"),
        fx.state.join("runner-alive"),
    );
    let probe = format!(
        "pid=$(cat '{}')\nif [ -e \"/proc/$pid\" ] && [ \"$(sed 's/.*) //' \"/proc/$pid/stat\" | cut -d' ' -f1)\" \
         != Z ]; then touch '{}'; fi\n",
        fx.state.join("base.pid").display(),
        alive.display()
    );
    let env = fx.git_wrapper(&format!(
        "case \"$*\" in \"worktree remove \"*)\n{probe}touch '{}';;\nesac\nexec GIT \"$@\"\n",
        observed.display()
    ));
    let control = || {
        let status = std::process::Command::new("/bin/sh")
            .args(["-c", &probe])
            .status()
            .expect("the probe runs");
        assert!(status.success());
        assert!(alive.exists(), "the probe sees the running runner");
        fs::remove_file(&alive).expect("the probe's mark is removed");
    };
    interrupt(
        &fx,
        &Point {
            ready: fx.state.join("grandchild.pid"),
            plan: r#"{"base": {"attempt": "stubborn"}}"#,
            call: Call {
                env: Some(env),
                ..Call::default()
            },
            again: true,
            before: &control,
            ..Point::default()
        },
    );
    assert!(observed.exists());
    assert!(!alive.exists());
    assert_gone(pid_in(&fx.state.join("grandchild.pid")));
    assert_gone(pid_in(&fx.state.join("supervised.pid")));
}

#[test]
fn a_sighup_or_sigint_during_an_attempt_stops_the_leg_and_removes_the_worktrees() {
    let fx = Fixture::new();
    for signal in [libc::SIGHUP, libc::SIGINT] {
        let _ = fs::remove_file(fx.state.join("grandchild.pid"));
        interrupt(
            &fx,
            &Point {
                ready: fx.state.join("grandchild.pid"),
                plan: r#"{"base": {"attempt": "hang"}}"#,
                signal,
                ..Point::default()
            },
        );
        assert_gone(pid_in(&fx.state.join("grandchild.pid")));
    }
}

/// When SIGTERM arrives during the overlay checkout, the run waits for the checkout to finish and
/// exits before the build.
#[test]
fn a_sigterm_during_the_overlay_waits_for_it_and_starts_no_leg() {
    let fx = Fixture::new();
    let (marker, finished) = (
        fx.state.join("overlay.txt"),
        fx.state.join("overlay-finished"),
    );
    let env = fx.git_wrapper(&format!(
        "GIT \"$@\"\nstatus=$?\ncase \"$*\" in \"{HOOKLESS}--literal-pathspecs checkout \"*)\n  touch '{}'; \
         kill -TERM \"$PPID\"; sleep 1; touch '{}' ;;\nesac\nexit \"$status\"\n",
        marker.display(),
        finished.display()
    ));
    interrupt(
        &fx,
        &Point {
            ready: marker,
            call: Call {
                env: Some(env),
                ..Call::default()
            },
            ..Point::default()
        },
    );
    assert!(finished.exists());
    assert_eq!(fx.build_legs(), Vec::<String>::new());
}

/// When SIGTERM arrives during the head worktree's add, the run waits for that Git step to finish,
/// then removes both worktrees.
#[test]
fn a_sigterm_between_legs_starts_no_head_leg_and_removes_the_worktrees() {
    let fx = Fixture::new();
    let (marker, finished) = (fx.state.join("between.txt"), fx.state.join("add-finished"));
    let env = fx.git_wrapper(&format!(
        "GIT \"$@\"\nstatus=$?\ncase \"$*\" in \"{HOOKLESS}worktree add --quiet --detach \"*/head\" \"*)\n  \
         GIT worktree lock \"$7\"; touch '{}'; kill -TERM \"$PPID\"; sleep 1; touch '{}' ;;\nesac\n\
         exit \"$status\"\n",
        marker.display(),
        finished.display()
    ));
    interrupt(
        &fx,
        &Point {
            ready: marker,
            call: Call {
                env: Some(env),
                ..Call::default()
            },
            ..Point::default()
        },
    );
    assert!(finished.exists());
    assert_eq!(fx.build_legs(), ["base"]);
}

/// If temporary directory creation fails, red-green refuses the run and writes a receipt with an empty
/// `legs` object. A SIGTERM recorded while the directory is made stops the run, and the cleanup
/// removes that directory.
#[test]
fn a_temporary_directory_step_is_shielded_and_its_failure_is_refused() {
    let fx = Fixture::new();
    let made = fx.state.join("made.txt");
    let env = fx.with_env(&[(MAKE_TEMP, OsStr::new("fail")), (MADE, made.as_os_str())]);
    let done = fx.red_green(&Call {
        env: Some(env),
        ..Call::default()
    });
    assert_eq!(done.code, 1, "{}", done.shown());
    assert_eq!(
        done.stdout,
        "red-green refused: a leg could not run: no temporary directory\n"
    );
    assert!(
        fx.repo
            .join("target/red-green/build/red-green.lock")
            .is_file()
    );
    let (_, receipt) = fx.receipt(&done);
    assert_eq!(keys(at(&receipt, "legs")), Vec::<String>::new());
    assert_eq!(read(&made), format!("{}\n", fx.tmp.display()));
    fx.assert_checkout_unchanged();
    let fx = Fixture::new();
    let made = fx.state.join("made.txt");
    let env = fx.with_env(&[(MAKE_TEMP, OsStr::new("signal")), (MADE, made.as_os_str())]);
    let done = fx.red_green(&Call {
        env: Some(env),
        ..Call::default()
    });
    stopped(&fx, &done, libc::SIGTERM);
    let lines: Vec<PathBuf> = read(&made).lines().map(PathBuf::from).collect();
    let [parent, directory] = &lines[..] else {
        panic!("the maker logs its parent and its directory: {lines:?}");
    };
    assert_eq!(parent, &fx.tmp);
    assert_eq!(directory.parent(), Some(fx.tmp.as_path()));
    assert!(!directory.exists());
    assert_eq!(fx.build_legs(), Vec::<String>::new());
}

/// If SIGTERM arrives during the base artifact read after the runner exits, red-green finishes judging
/// the base and stops before the head leg starts. SIGTERM during runner execution stops the leg.
#[test]
fn a_signal_waits_once_the_runner_has_exited() {
    let fx = Fixture::new();
    fx.plan(r#"{"base": {"stub": "fifo"}}"#);
    let done = fx.tool(&Call {
        top: Some(stub_top(&fx)),
        ..Call::default()
    });
    stopped(&fx, &done, libc::SIGTERM);
    assert!(fx.state.join("base-fed.sent").exists());
    assert!(fx.state.join("base-fed.written").exists());
    assert_eq!(fx.build_legs(), ["base"]);
    let fx = Fixture::new();
    interrupt(
        &fx,
        &Point {
            ready: fx.state.join("grandchild.pid"),
            plan: r#"{"base": {"attempt": "hang"}}"#,
            ..Point::default()
        },
    );
    assert_gone(pid_in(&fx.state.join("grandchild.pid")));
}

/// If SIGTERM arrives during the last leg's artifact read after its runner exits, red-green finishes
/// the run: the head leg of a proven run, and the base leg of a run refused for a passing base.
#[test]
fn a_signal_after_the_head_runner_exits_lets_the_run_finish() {
    for (last, plan, code, line) in [
        (
            "head",
            r#"{"base": {"stub": "real"}, "head": {"stub": "fifo"}}"#,
            0,
            "red-green: ",
        ),
        (
            "base",
            r#"{"base": {"stub": "fifo", "attempt": "pass"}}"#,
            1,
            "red-green refused: the test passes on the base",
        ),
    ] {
        let fx = Fixture::new();
        fx.plan(plan);
        let done = fx.tool(&Call {
            top: Some(stub_top(&fx)),
            ..Call::default()
        });
        assert_eq!(done.code, code, "{last}: {}", done.shown());
        assert!(done.stdout.starts_with(line), "{last}: {}", done.shown());
        assert!(fx.state.join(format!("{last}-fed.sent")).exists(), "{last}");
        assert!(
            fx.state.join(format!("{last}-fed.written")).exists(),
            "{last}"
        );
        let (_, receipt) = fx.receipt(&done);
        assert_eq!(
            text(at(&receipt, "result")) == "proven",
            code == 0,
            "{last}"
        );
        fx.assert_checkout_unchanged();
    }
}

/// Red-green handles a signal recorded during spawn as soon as it registers the runner: the first
/// recorded signal determines red-green's exit status, and the runner ends before red-green exits. If
/// spawn fails, red-green uses the first recorded signal to determine its exit status; with no signal
/// recorded, red-green refuses the run.
#[test]
fn a_signal_during_a_spawn_takes_effect_once_the_runner_is_registered() {
    let fx = Fixture::new();
    let spawned = fx.state.join("spawned.txt");
    let env = fx.with_env(&[
        (SPAWN, OsStr::new("signal")),
        (SPAWNED, spawned.as_os_str()),
    ]);
    let done = fx.red_green(&Call {
        env: Some(env),
        ..Call::default()
    });
    stopped(&fx, &done, libc::SIGINT);
    assert_ended(pid_in(&spawned));
    let fx = Fixture::new();
    let env = fx.with_env(&[(SPAWN, OsStr::new("fail"))]);
    let done = fx.red_green(&Call {
        env: Some(env),
        ..Call::default()
    });
    stopped(&fx, &done, libc::SIGTERM);
    assert_eq!(fx.build_legs(), Vec::<String>::new());
    let env = fx.with_env(&[(SPAWN, OsStr::new("error"))]);
    let done = fx.red_green(&Call {
        env: Some(env),
        ..Call::default()
    });
    assert_eq!(done.code, 1, "{}", done.shown());
    assert_eq!(
        done.stdout,
        "red-green refused: a leg could not run: spawn failed\n"
    );
    assert_eq!(fx.receipts().len(), 1);
}
