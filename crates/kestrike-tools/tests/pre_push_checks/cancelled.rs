//! The cases of a cancelled push: a signal to the tool's process while `git worktree add` runs, while a
//! check and its child run, twice in a row, and after one check's leader ended. Each waits for the file a
//! stand-in writes before it signals, and for the end of the check's process group against
//! [`LIMIT`](super::push::LIMIT) after the tool exits.

use std::fs;
use std::path::Path;

use super::push::{Fixture, STUB, alive, finished, group_alive, process_id, signal, waited};

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
    fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat"))
        .ok()
        .and_then(|stat| {
            stat.rsplit_once(')')
                .map(|(_, rest)| rest.trim_start().starts_with('Z'))
        })
        .unwrap_or(false)
}

/// A SIGTERM to the tool once `git worktree add` returns, the worktree locked, exits 143, runs no check
/// and leaves no worktree registered or standing.
#[test]
fn a_signal_during_worktree_creation_leaves_no_worktree() {
    let fx = Fixture::new();
    let head = fx.commit(&[("scripts/test-inventory.json", r#"{"rows": []}"#)]);
    fx.wrap_git(true);
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

/// Each of SIGINT, SIGTERM and SIGHUP to the tool while a check and its child run ends the check's group,
/// runs no later check, prints no failure, removes the worktree and exits `128 + n`.
#[test]
fn each_signal_while_a_check_and_its_child_run_ends_the_group_and_removes_the_worktree() {
    for sent in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let fx = Fixture::new();
        let head = hanging(&fx, "# hang", "");
        let tool = fx.start(&Fixture::input(&[(&head, &fx.base)]));
        let child = process_id(&fx.logged(".child"));
        let leader = process_id(&fx.logged(".leader"));
        signal(tool.id(), sent);
        let run = finished(tool);
        assert_eq!(run.code, Some(128 + sent), "{sent}: {}", run.stderr);
        assert!(!run.stderr.contains("failed:"), "{sent}: {}", run.stderr);
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

/// A SIGINT right after a SIGTERM changes nothing: the exit is 143 and the worktree is removed once and
/// unregistered.
#[test]
fn two_signals_in_a_row_remove_the_worktree_once() {
    let fx = Fixture::new();
    let head = hanging(&fx, "# hang", "");
    fx.wrap_git(false);
    let tool = fx.start(&Fixture::input(&[(&head, &fx.base)]));
    let leader = process_id(&fx.logged(".leader"));
    signal(tool.id(), libc::SIGTERM);
    signal(tool.id(), libc::SIGINT);
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
    // SAFETY: `kill` takes two integers and touches no memory of the caller.
    unsafe { libc::kill(lingering, libc::SIGKILL) };
    // SAFETY: `waitpid` with a null status pointer reaps the child where this process is its subreaper and
    // returns at once where it is not this process's child.
    unsafe { libc::waitpid(lingering, std::ptr::null_mut(), 0) };
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
