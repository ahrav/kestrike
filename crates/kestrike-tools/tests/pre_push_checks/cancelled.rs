//! The cases of a cancelled push: a signal to the tool's process while `git worktree add` runs, while a
//! check and its child run, twice in a row, and after one check's leader ended. Each waits for the file a
//! stand-in writes before it signals, and for the end of the check's process group against
//! [`LIMIT`](super::push::LIMIT) after the tool exits.

use std::fs;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::time::Instant;

use super::push::{
    BINARY, Fixture, LIMIT, STUB, alive, executable, finished, group_alive, process_id, signal,
    spawn_with_input, top, waited, which,
};

/// `hanging` commits an inventory change with the selection script holding `first` and the admission
/// script holding `second`, each a marker line before the stub, and returns the commit.
fn hanging(fx: &Fixture, first: &str, second: &str) -> String {
    fx.commit(&[
        ("scripts/test-inventory.json", r#"{"rows": []}"#),
        ("scripts/test-select-tests.py", &format!("{first}\n{STUB}")),
        ("scripts/verify-receipts.py", &format!("{second}\n{STUB}")),
    ])
}

/// `zombie` holds when `/proc` reads `pid` as a process that ended and waits for its reap.
fn zombie(pid: libc::pid_t) -> bool {
    state(pid) == Some('Z')
}

/// `state` is the letter after the command in `/proc/<pid>/stat`, or `None` if reading the file fails,
/// the final `)` is missing, or only white space follows it.
fn state(pid: libc::pid_t) -> Option<char> {
    fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat"))
        .ok()
        .and_then(|stat| {
            stat.rsplit_once(')')
                .and_then(|(_, rest)| rest.trim_start().chars().next())
        })
}

fn killpg(group: libc::pid_t, signal: i32) {
    // SAFETY: `killpg` takes two integers and touches no memory of the caller.
    assert_eq!(
        unsafe { libc::killpg(group, signal) },
        0,
        "the signal is sent"
    );
}

/// A SIGTERM to the tool once `git worktree add` returns, the worktree locked, exits 143, runs no check
/// and leaves no worktree registered or standing.
#[test]
fn a_signal_during_worktree_creation_leaves_no_worktree() {
    let fx = Fixture::new();
    let head = fx.commit(&[("scripts/test-inventory.json", r#"{"rows": []}"#)]);
    fx.wrap_git();
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

/// Each of SIGINT, SIGTERM, SIGHUP and SIGQUIT to the tool while a check and its child run ends the check's
/// group,
/// runs no later check, prints no failure, removes the worktree and exits `128 + n`.
#[test]
fn each_signal_while_a_check_and_its_child_run_ends_the_group_and_removes_the_worktree() {
    for sent in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        let fx = Fixture::new();
        let head = hanging(&fx, "# hang", "");
        let tool = fx.start(&Fixture::input(&[(&head, &fx.base)]));
        let child = process_id(&fx.logged(".child"));
        let leader = process_id(&fx.logged(".leader"));
        signal(tool.id(), sent);
        let run = finished(tool);
        assert_eq!(run.code, Some(128 + sent), "{sent}: {}", run.stderr);
        let announced = format!(
            "pre-push: {}: python3 scripts/test-select-tests.py\n",
            &head[..12]
        );
        assert!(run.stderr.ends_with(&announced), "{sent}: {}", run.stderr);
        assert!(
            waited(|| !group_alive(leader)),
            "{sent}: the check's group ends"
        );
        assert!(
            !alive(child) || zombie(child),
            "{sent}: the check's child ends"
        );
        assert_eq!(fx.ran(), ["test-select-tests.py"], "{sent}");
        assert_eq!(fx.worktrees(), 1, "{sent}");
        assert!(fx.left().is_empty(), "{sent}: {:?}", fx.left());
    }
}

/// A SIGINT that arrives while the worktree is being removed after a SIGTERM changes nothing: the exit is
/// 143, the worktree is removed once and unregistered, and the check's leader had ended before the removal
/// started.
#[test]
fn two_signals_in_a_row_remove_the_worktree_once() {
    let fx = Fixture::new();
    let head = hanging(&fx, "# hang", "");
    fx.wrap_git_around(
        "if [ \"$1 $2\" = 'worktree remove' ]; then\n\
         \x20 if kill -0 \"$(cat \"$STUB_LOG.leader\")\" 2>/dev/null; then echo leader-alive >> \"$STUB_LOG.git\"; fi\n\
         \x20 printf 'remove\\n' >> \"$STUB_LOG.git\"\n\
         \x20 n=0\n\
         \x20 while [ ! -e \"$STUB_LOG.release\" ] && [ \"$n\" -lt 1000 ]; do sleep 0.01; n=$((n + 1)); done\n\
         fi",
    );
    let tool = fx.start(&Fixture::input(&[(&head, &fx.base)]));
    let leader = process_id(&fx.logged(".leader"));
    signal(tool.id(), libc::SIGTERM);
    assert!(waited(|| fx.logged(".git").exists()), "the removal starts");
    signal(tool.id(), libc::SIGINT);
    fs::write(fx.logged(".release"), "").expect("the removal is released");
    let run = finished(tool);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert!(waited(|| !group_alive(leader)), "the check's group ends");
    let removes = fs::read_to_string(fx.logged(".git")).expect("the wrapper logs the removal");
    assert_eq!(removes, "remove\n");
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

/// A check whose leader exited and was reaped gets no signal when a later check is cancelled: the child it
/// left in its group runs on, while the running check's group ends.
#[test]
fn a_leader_that_ended_before_the_signal_gets_none() {
    let fx = Fixture::new();
    let head = hanging(&fx, "# linger", "# hang");
    let tool = fx.start(&Fixture::input(&[(&head, &fx.base)]));
    let lingering = process_id(&fx.logged(".lingering"));
    let leader = process_id(&fx.logged(".leader"));
    signal(tool.id(), libc::SIGTERM);
    let run = finished(tool);
    let survived = alive(lingering) && !zombie(lingering);
    if survived {
        // SAFETY: `kill` takes two integers and touches no memory of the caller.
        unsafe { libc::kill(lingering, libc::SIGKILL) };
        // SAFETY: `waitpid` with a null status pointer reaps the child where this process is its subreaper
        // and returns at once where it is not this process's child.
        unsafe { libc::waitpid(lingering, std::ptr::null_mut(), 0) };
    }
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert!(
        waited(|| !group_alive(leader)),
        "the running check's group ends"
    );
    assert!(
        survived,
        "the child of the reaped leader received no signal"
    );
    assert_eq!(
        fx.ran(),
        ["test-select-tests.py", "verify-receipts.py admit"]
    );
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

/// A SIGHUP that the tool's starter ignores, as `nohup` does, is still recorded: the check's group ends and
/// the exit is 129.
#[test]
fn an_ignored_signal_is_still_recorded() {
    let fx = Fixture::new();
    let head = hanging(&fx, "# hang", "");
    let mut command = fx.command("sh");
    command
        .args(["-c", "trap '' HUP; exec \"$0\" \"$@\"", BINARY])
        .arg(top())
        .args(["pre-push-checks", "origin", "url"]);
    let tool = spawn_with_input(&mut command, &Fixture::input(&[(&head, &fx.base)]));
    let leader = process_id(&fx.logged(".leader"));
    signal(tool.id(), libc::SIGHUP);
    let run = finished(tool);
    assert_eq!(run.code, Some(128 + libc::SIGHUP), "{}", run.stderr);
    assert!(waited(|| !group_alive(leader)), "the check's group ends");
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

/// A SIGTERM that arrives while a ref line is planned ends the push with 143 once that Git read returns,
/// before any scan, guard or check.
#[test]
fn a_signal_while_a_ref_line_is_planned_ends_the_push() {
    let fx = Fixture::new();
    let head = fx.commit(&[("scripts/test-inventory.json", r#"{"rows": []}"#)]);
    fx.wrap_git_around("if [ \"$1\" = rev-list ]; then kill -TERM \"$PPID\"; fi");
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert!(run.stderr.is_empty(), "{}", run.stderr);
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

/// SIGTERM takes precedence over the `git rev-list` failure: the tool exits 143 with empty standard error
/// before running any checks.
#[test]
fn a_signal_during_a_git_read_that_fails_exits_with_the_signal() {
    let fx = Fixture::new();
    let head = fx.commit(&[("scripts/test-inventory.json", r#"{"rows": []}"#)]);
    fx.wrap_git_around("if [ \"$1\" = rev-list ]; then kill -TERM \"$PPID\"; exit 1; fi");
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert!(run.stderr.is_empty(), "{}", run.stderr);
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

/// When the tool receives SIGTERM after `git worktree add` registers the worktree, the tool exits 143
/// within [`LIMIT`]. The add's process group terminates, the tool skips all checks, and only the original
/// worktree remains registered.
#[test]
fn a_signal_while_worktree_add_runs_stops_the_add() {
    let fx = Fixture::new();
    let head = fx.commit(&[("scripts/test-inventory.json", r#"{"rows": []}"#)]);
    let git = which("git");
    executable(
        &fx.bin.join("git"),
        &format!(
            "#!/bin/sh\n\
             if [ \"$1 $2\" = 'worktree add' ]; then\n\
             \x20 \"{git}\" \"$@\" || exit\n\
             \x20 printf '%s\\n' \"$$\" > \"$STUB_LOG.add.tmp\" && mv \"$STUB_LOG.add.tmp\" \"$STUB_LOG.add\"\n\
             \x20 n=0\n\
             \x20 while [ ! -e \"$STUB_LOG.release\" ] && [ \"$n\" -lt 6000 ]; do sleep 0.01; n=$((n + 1)); done\n\
             \x20 exit 0\n\
             fi\n\
             exec \"{git}\" \"$@\"\n",
            git = git.display()
        ),
    );
    let tool = fx.start(&Fixture::input(&[(&head, &fx.base)]));
    let add = process_id(&fx.logged(".add"));
    let sent = Instant::now();
    signal(tool.id(), libc::SIGTERM);
    let run = finished(tool);
    assert!(
        sent.elapsed() < LIMIT,
        "the tool exits {:?} after the signal",
        sent.elapsed()
    );
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert!(waited(|| !group_alive(add)), "the add's group ends");
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

#[test]
fn a_signal_recorded_before_the_leader_s_reap_ends_what_the_leader_left() {
    let fx = Fixture::new();
    let head = hanging(&fx, "# release", "");
    let tool = fx.start(&Fixture::input(&[(&head, &fx.base)]));
    let child = process_id(&fx.logged(".child"));
    let leader = process_id(&fx.logged(".leader"));
    let pid = libc::pid_t::try_from(tool.id()).expect("a process id fits pid_t");
    signal(tool.id(), libc::SIGSTOP);
    assert!(waited(|| state(pid) == Some('T')), "the tool stops");
    signal(tool.id(), libc::SIGTERM);
    fs::write(fx.logged(".release"), "").expect("the leader is released");
    assert!(waited(|| zombie(leader)), "the leader exits unreaped");
    signal(tool.id(), libc::SIGCONT);
    let run = finished(tool);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert!(waited(|| !group_alive(leader)), "the leader's group ends");
    assert!(!alive(child) || zombie(child), "the leader's child ends");
    assert_eq!(fx.ran(), ["test-select-tests.py"]);
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

#[test]
fn a_signal_blocked_at_the_tool_s_start_is_still_recorded() {
    let fx = Fixture::new();
    let head = hanging(&fx, "# hang", "");
    let mut command = fx.command(BINARY);
    command
        .arg(top())
        .args(["pre-push-checks", "origin", "url"]);
    // SAFETY: the closure runs in the child before `execve` and calls `sigemptyset`, `sigaddset` and
    // `sigprocmask`, which are async-signal-safe, on a set on its own stack.
    unsafe {
        command.pre_exec(|| {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGTERM);
            if libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
    let tool = spawn_with_input(&mut command, &Fixture::input(&[(&head, &fx.base)]));
    let leader = process_id(&fx.logged(".leader"));
    signal(tool.id(), libc::SIGTERM);
    let run = finished(tool);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert!(waited(|| !group_alive(leader)), "the check's group ends");
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

#[test]
fn a_check_that_ignores_the_recorded_signals_still_ends() {
    let fx = Fixture::new();
    let head = hanging(&fx, "# deaf", "");
    let tool = fx.start(&Fixture::input(&[(&head, &fx.base)]));
    let child = process_id(&fx.logged(".child"));
    let leader = process_id(&fx.logged(".leader"));
    signal(tool.id(), libc::SIGTERM);
    let run = finished(tool);
    let ended = waited(|| !group_alive(leader));
    if !ended {
        killpg(leader, libc::SIGKILL);
    }
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert!(ended, "the check's group ends");
    assert!(!alive(child) || zombie(child), "the check's child ends");
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

#[test]
fn a_signal_to_the_tool_s_group_during_the_removal_leaves_no_worktree_registered() {
    let fx = Fixture::new();
    let head = hanging(&fx, "# hang", "");
    fx.wrap_git_around(
        "if [ \"$1 $2\" = 'worktree remove' ]; then\n\
         \x20 printf 'remove\\n' >> \"$STUB_LOG.git\"\n\
         \x20 n=0\n\
         \x20 while [ ! -e \"$STUB_LOG.release\" ] && [ \"$n\" -lt 1000 ]; do sleep 0.01; n=$((n + 1)); done\n\
         fi",
    );
    let mut command = fx.command(BINARY);
    command
        .arg(top())
        .args(["pre-push-checks", "origin", "url"])
        .process_group(0);
    let tool = spawn_with_input(&mut command, &Fixture::input(&[(&head, &fx.base)]));
    let group = libc::pid_t::try_from(tool.id()).expect("a process id fits pid_t");
    let leader = process_id(&fx.logged(".leader"));
    signal(tool.id(), libc::SIGTERM);
    assert!(waited(|| fx.logged(".git").exists()), "the removal starts");
    killpg(group, libc::SIGINT);
    fs::write(fx.logged(".release"), "").expect("the removal is released");
    let run = finished(tool);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert!(waited(|| !group_alive(leader)), "the check's group ends");
    let removes = fs::read_to_string(fx.logged(".git")).expect("the wrapper logs the removal");
    assert_eq!(removes, "remove\n");
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}
