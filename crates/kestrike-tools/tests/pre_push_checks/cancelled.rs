//! The cases of a cancelled push: a signal to the tool's process while `git worktree add` runs or after it
//! exited while its group holds a stream, while a check and its child run, twice in a row, after one
//! check's leader ended, during a ref line's reads, the guard, a scan and the removal. A case signals once
//! a stand-in has written its file or from a wrapper of Git that signals the tool itself, and waits for the
//! end of the check's process group against [`LIMIT`](super::push::LIMIT) after the tool exits.

use std::fs;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::time::Instant;

use super::chaos_checks::contract;
use super::push::{
    BINARY, Fixture, LIMIT, STUB, alive, executable, finished, group_alive, process_id, signal,
    spawn_with_input, top, waited, which,
};

/// `announced` is the line the tool prints before it starts `check` at `head`.
fn announced(head: &str, check: &str) -> String {
    format!("pre-push: {}: python3 scripts/{check}\n", &head[..12])
}

/// `scanned` is the scan's announcement of the range from `base` to `head`.
fn scanned(head: &str, base: &str) -> String {
    format!(
        "pre-push: {}: tool.sh scan-weakened-tests --base {}\n",
        &head[..12],
        &base[..12]
    )
}

/// `hold_removal` holds `git worktree remove` until `.release` appears or ten seconds pass, after it logs
/// `leader-alive` where the check's leader still runs and then `remove` to the `.git` log.
fn hold_removal(fx: &Fixture) {
    fx.wrap_git_around(
        "if [ \"$1 $2\" = 'worktree remove' ]; then\n\
         \x20 if kill -0 \"$(cat \"$STUB_LOG.leader\")\" 2>/dev/null; then echo leader-alive >> \"$STUB_LOG.git\"; fi\n\
         \x20 printf 'remove\\n' >> \"$STUB_LOG.git\"\n\
         \x20 n=0\n\
         \x20 while [ ! -e \"$STUB_LOG.release\" ] && [ \"$n\" -lt 1000 ]; do sleep 0.01; n=$((n + 1)); done\n\
         \x20 if [ ! -e \"$STUB_LOG.release\" ]; then printf 'expired\\n' >> \"$STUB_LOG.git\"; fi\n\
         fi",
    );
}

/// `holding_add` puts a `git` first on `PATH` whose `git worktree add` runs Git's add, leaves a shell in
/// its process group that holds the add's standard error alone until `.release` appears or a minute
/// passes, publishes that shell's id as `.held` and its own as `.add`, and exits `code`.
fn holding_add(fx: &Fixture, code: i32) {
    let git = which("git");
    executable(
        &fx.bin.join("git"),
        &format!(
            "#!/bin/sh\n\
             if [ \"$1 $2\" = 'worktree add' ]; then\n\
             \x20 \"{git}\" \"$@\" || exit\n\
             \x20 ( n=0; while [ ! -e \"$STUB_LOG.release\" ] && [ \"$n\" -lt 6000 ]; do sleep 0.01; n=$((n + 1)); done ) > /dev/null < /dev/null &\n\
             \x20 printf '%s\\n' \"$!\" > \"$STUB_LOG.held.tmp\" && mv \"$STUB_LOG.held.tmp\" \"$STUB_LOG.held\"\n\
             \x20 printf '%s\\n' \"$$\" > \"$STUB_LOG.add.tmp\" && mv \"$STUB_LOG.add.tmp\" \"$STUB_LOG.add\"\n\
             \x20 exit {code}\n\
             fi\n\
             exec \"{git}\" \"$@\"\n",
            git = git.display()
        ),
    );
}

/// A `git worktree add` that exits 0 while a process of its group holds its standard error starts no
/// check until that stream ends: the add's leader stays unreaped, and once the holder ends the checks run.
#[cfg(target_os = "linux")]
#[test]
fn a_successful_add_starts_no_check_while_its_group_holds_standard_error() {
    let fx = Fixture::new();
    let head = fx.commit(&[("scripts/test-inventory.json", r#"{"rows": []}"#)]);
    holding_add(&fx, 0);
    let tool = fx.start(&Fixture::input(&[(&head, &fx.base)]));
    let add = process_id(&fx.logged(".add"));
    let held = process_id(&fx.logged(".held"));
    let exited = waited(|| zombie(add));
    std::thread::sleep(std::time::Duration::from_millis(300));
    let early = fx.ran();
    fs::write(fx.logged(".release"), "").expect("the holder is released");
    let run = finished(tool);
    let ended = waited(|| !alive(held) || zombie(held));
    assert!(exited, "the add's leader exits and stays unreaped");
    assert!(
        early.is_empty(),
        "a check started while the stream was held: {early:?}"
    );
    assert!(ended, "the holder ends");
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(!fx.ran().is_empty(), "the checks run once the stream ends");
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

/// A SIGTERM after a failed `git worktree add` exited, while a process of its group holds its standard
/// error, ends that group and exits 143 within [`LIMIT`], with no check run and no worktree left.
#[cfg(target_os = "linux")]
#[test]
fn a_signal_after_a_failed_add_exits_while_its_group_holds_standard_error_ends_the_group() {
    let fx = Fixture::new();
    let head = fx.commit(&[("scripts/test-inventory.json", r#"{"rows": []}"#)]);
    holding_add(&fx, 1);
    let tool = fx.start(&Fixture::input(&[(&head, &fx.base)]));
    let add = process_id(&fx.logged(".add"));
    let held = process_id(&fx.logged(".held"));
    let exited = waited(|| zombie(add));
    let sent = Instant::now();
    signal(tool.id(), libc::SIGTERM);
    let run = finished(tool);
    let elapsed = sent.elapsed();
    let ended = waited(|| !alive(held) || zombie(held));
    fs::write(fx.logged(".release"), "").expect("the holder is released");
    assert!(exited, "the add's leader exits and stays unreaped");
    assert!(
        elapsed < LIMIT,
        "the tool exits {elapsed:?} after the signal"
    );
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert_eq!(run.stderr, scanned(&head, &fx.base));
    assert!(ended, "the holder in the add's group ends");
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

/// `invoked` lists the first argument of each Git command the `.git` log holds, in the order they ran.
fn invoked(fx: &Fixture) -> Vec<String> {
    fs::read_to_string(fx.logged(".git"))
        .expect("the wrapper logs each Git command")
        .lines()
        .map(str::to_owned)
        .collect()
}

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
    assert_eq!(run.stderr, scanned(&head, &fx.base));
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
        let announced = announced(&head, "test-select-tests.py");
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
    hold_removal(&fx);
    let tool = fx.start(&Fixture::input(&[(&head, &fx.base)]));
    let leader = process_id(&fx.logged(".leader"));
    signal(tool.id(), libc::SIGTERM);
    assert!(waited(|| fx.logged(".git").exists()), "the removal starts");
    signal(tool.id(), libc::SIGINT);
    fs::write(fx.logged(".release"), "").expect("the removal is released");
    let run = finished(tool);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    let announced = announced(&head, "test-select-tests.py");
    assert!(run.stderr.ends_with(&announced), "{}", run.stderr);
    assert_eq!(
        run.stderr.matches(announced.as_str()).count(),
        1,
        "{}",
        run.stderr
    );
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
    let sampled = alive(lingering) && !zombie(lingering);
    // SAFETY: `kill` takes two integers and touches no memory of the caller; the lingering child is this
    // process's adopted child on Linux, unreaped, so its id names it.
    unsafe { libc::kill(lingering, libc::SIGTERM) };
    let mut status = 0;
    // SAFETY: `waitpid` writes the status into `status`, which outlives the call; it reaps the child where
    // this process is its subreaper and returns at once where it is not this process's child.
    let reaped = unsafe { libc::waitpid(lingering, &mut status, 0) } == lingering;
    let survived = if reaped {
        libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGTERM
    } else {
        sampled
    };
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    let announced = announced(&head, "verify-receipts.py admit");
    assert!(run.stderr.ends_with(&announced), "{}", run.stderr);
    assert_eq!(
        run.stderr.matches(announced.as_str()).count(),
        1,
        "{}",
        run.stderr
    );
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
    let tool = spawn_with_input(&mut command, Fixture::input(&[(&head, &fx.base)]));
    let leader = process_id(&fx.logged(".leader"));
    signal(tool.id(), libc::SIGHUP);
    let run = finished(tool);
    assert_eq!(run.code, Some(128 + libc::SIGHUP), "{}", run.stderr);
    let announced = announced(&head, "test-select-tests.py");
    assert!(run.stderr.ends_with(&announced), "{}", run.stderr);
    assert_eq!(
        run.stderr.matches(announced.as_str()).count(),
        1,
        "{}",
        run.stderr
    );
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
/// within [`LIMIT`]. The add's process group terminates, a `sleep` the add left in its group included, the
/// tool skips all checks and prints nothing after the scan, and only the original worktree remains
/// registered.
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
             \x20 sleep 600 > /dev/null 2>&1 < /dev/null &\n\
             \x20 printf '%s\\n' \"$!\" > \"$STUB_LOG.held.tmp\" && mv \"$STUB_LOG.held.tmp\" \"$STUB_LOG.held\"\n\
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
    let held = process_id(&fx.logged(".held"));
    // SAFETY: `getpgid` takes one integer and touches no memory of the caller.
    let grouped = unsafe { libc::getpgid(held) } == add;
    let live = alive(held) && !zombie(held);
    let sent = Instant::now();
    signal(tool.id(), libc::SIGTERM);
    let run = finished(tool);
    let elapsed = sent.elapsed();
    let ended = waited(|| !alive(held) || zombie(held));
    if !ended {
        // SAFETY: `kill` takes two integers and touches no memory of the caller.
        unsafe { libc::kill(held, libc::SIGKILL) };
    }
    assert!(grouped, "the add's sleep stands in the add's group");
    assert!(live, "the add's sleep runs when the signal is sent");
    assert!(
        elapsed < LIMIT,
        "the tool exits {elapsed:?} after the signal"
    );
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert_eq!(run.stderr, scanned(&head, &fx.base));
    assert!(ended, "the add's sleep ends");
    assert!(waited(|| !group_alive(add)), "the add's group ends");
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

/// The case reads the stopped tool's state from `/proc`, so it runs on Linux alone.
#[cfg(target_os = "linux")]
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
    let announced = announced(&head, "test-select-tests.py");
    assert!(run.stderr.ends_with(&announced), "{}", run.stderr);
    assert_eq!(
        run.stderr.matches(announced.as_str()).count(),
        1,
        "{}",
        run.stderr
    );
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
    let mut command = fx.tool();
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
    let tool = spawn_with_input(&mut command, Fixture::input(&[(&head, &fx.base)]));
    let leader = process_id(&fx.logged(".leader"));
    signal(tool.id(), libc::SIGTERM);
    let run = finished(tool);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    let announced = announced(&head, "test-select-tests.py");
    assert!(run.stderr.ends_with(&announced), "{}", run.stderr);
    assert_eq!(
        run.stderr.matches(announced.as_str()).count(),
        1,
        "{}",
        run.stderr
    );
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
    let announced = announced(&head, "test-select-tests.py");
    assert!(run.stderr.ends_with(&announced), "{}", run.stderr);
    assert_eq!(
        run.stderr.matches(announced.as_str()).count(),
        1,
        "{}",
        run.stderr
    );
    assert!(ended, "the check's group ends");
    assert!(!alive(child) || zombie(child), "the check's child ends");
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

#[test]
fn a_signal_to_the_tool_s_group_during_the_removal_leaves_no_worktree_registered() {
    let fx = Fixture::new();
    let head = hanging(&fx, "# hang", "");
    hold_removal(&fx);
    let mut command = fx.tool();
    command.process_group(0);
    let tool = spawn_with_input(&mut command, Fixture::input(&[(&head, &fx.base)]));
    let group = libc::pid_t::try_from(tool.id()).expect("a process id fits pid_t");
    let leader = process_id(&fx.logged(".leader"));
    signal(tool.id(), libc::SIGTERM);
    assert!(waited(|| fx.logged(".git").exists()), "the removal starts");
    killpg(group, libc::SIGINT);
    fs::write(fx.logged(".release"), "").expect("the removal is released");
    let run = finished(tool);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    let announced = announced(&head, "test-select-tests.py");
    assert!(run.stderr.ends_with(&announced), "{}", run.stderr);
    assert_eq!(
        run.stderr.matches(announced.as_str()).count(),
        1,
        "{}",
        run.stderr
    );
    assert!(waited(|| !group_alive(leader)), "the check's group ends");
    let removes = fs::read_to_string(fx.logged(".git")).expect("the wrapper logs the removal");
    assert_eq!(removes, "remove\n");
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

/// A SIGTERM while the comparison base is read, the first Git read of a ref line, ends the push with 143
/// once that read returns: no later Git read starts and nothing is printed.
#[test]
fn a_signal_during_the_first_read_of_a_ref_line_starts_no_later_read() {
    let fx = Fixture::new();
    let head = fx.commit(&[("scripts/test-inventory.json", r#"{"rows": []}"#)]);
    fx.wrap_git_around(
        "printf '%s\\n' \"$1\" >> \"$STUB_LOG.git\"\n\
         case \"$1 $3\" in 'cat-file '*'^{commit}') kill -TERM \"$PPID\" ;; esac",
    );
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert!(run.stderr.is_empty(), "{}", run.stderr);
    assert_eq!(invoked(&fx), ["remote", "cat-file"]);
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
}

/// A SIGTERM while the guard lists a tip's chaos tree, its first Git read, ends the push with 143 once that
/// read returns: the guard starts no later read, and nothing is printed after the scan.
#[test]
fn a_signal_during_the_first_read_of_the_guard_starts_no_later_read() {
    let fx = Fixture::new();
    let base = contract(&fx);
    let head = fx.commit(&[("chaos/receipts/run/row.json", r#"{"a": 1}"#)]);
    fx.wrap_git_around(
        "printf '%s\\n' \"$1\" >> \"$STUB_LOG.git\"\n\
         if [ \"$1\" = ls-tree ]; then kill -TERM \"$PPID\"; fi",
    );
    let run = fx.push(&[(&head, &base)]);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert_eq!(run.stderr, scanned(&head, &base));
    let invoked = invoked(&fx);
    assert_eq!(
        invoked.last().map(String::as_str),
        Some("ls-tree"),
        "{invoked:?}"
    );
    assert_eq!(invoked.iter().filter(|name| *name == "ls-tree").count(), 1);
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
}

/// A SIGTERM while the guard reads a pushed commit's records exits 143 and prints no failure; the guard's
/// read is the last Git command, so no worktree is added or removed after it.
#[test]
fn a_signal_during_the_guard_of_a_push_with_no_check_exits_with_the_signal() {
    let fx = Fixture::new();
    let base = contract(&fx);
    fx.commit(&[(
        "chaos/receipts/run/row.json",
        r#"{"account": 123456789012}"#,
    )]);
    fx.git(&["rm", "-q", "--", "chaos/receipts/run/row.json"]);
    fx.git(&["commit", "-q", "-m", "remove the record"]);
    let clean = fx.git(&["rev-parse", "HEAD"]);
    fx.wrap_git_around(
        "printf '%s %s\\n' \"$1\" \"$2\" >> \"$STUB_LOG.git\"\n\
         if [ \"$1\" = diff-tree ]; then kill -TERM \"$PPID\"; fi",
    );
    let run = fx.push(&[(&clean, &base)]);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert_eq!(run.stderr, scanned(&clean, &base));
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    let logged = invoked(&fx);
    assert_eq!(
        logged.last().map(String::as_str),
        Some("diff-tree -r"),
        "the guard's read is the last Git command: {logged:?}"
    );
    assert_eq!(fx.worktrees(), 1);
}

/// A SIGTERM that first arrives while the worktree is removed after every check passed exits 143; the
/// worktree is removed once and unregistered, and nothing is printed after the last check's announcement.
#[test]
fn a_signal_during_the_removal_after_passing_checks_exits_with_the_signal() {
    let fx = Fixture::new();
    let head = hanging(&fx, "", "");
    fx.wrap_git_around(
        "if [ \"$1 $2\" = 'worktree remove' ]; then printf 'remove\\n' >> \"$STUB_LOG.git\"; kill -TERM \"$PPID\"; fi",
    );
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    let announced = announced(&head, "verify-receipts.py admit");
    assert!(run.stderr.ends_with(&announced), "{}", run.stderr);
    assert_eq!(
        run.stderr.matches(announced.as_str()).count(),
        1,
        "{}",
        run.stderr
    );
    assert_eq!(
        fx.ran(),
        ["test-select-tests.py", "verify-receipts.py admit"]
    );
    assert_eq!(invoked(&fx), ["remove"]);
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

/// A SIGTERM during the first of two scans ends the push with 143 once that scan returns: the second scan
/// is not announced.
#[test]
fn a_signal_during_the_first_of_two_scans_starts_no_second_scan() {
    let fx = Fixture::new();
    let first = fx.commit(&[("notes/a.txt", "a\n")]);
    let second = fx.commit(&[("notes/b.txt", "b\n")]);
    fx.wrap_git_around(
        "printf '%s %s\\n' \"$1\" \"$2\" >> \"$STUB_LOG.git\"\n\
         if [ \"$1 $2\" = 'rev-list --count' ] && [ ! -e \"$STUB_LOG.sent\" ]; then : > \"$STUB_LOG.sent\"; kill -TERM \"$PPID\"; fi",
    );
    let run = fx.push(&[(&first, &fx.base), (&second, &fx.base)]);
    assert_eq!(run.code, Some(128 + libc::SIGTERM), "{}", run.stderr);
    assert_eq!(run.stderr, scanned(&first, &fx.base));
    let logged = invoked(&fx);
    let counted = logged
        .iter()
        .position(|command| command == "rev-list --count")
        .expect("the first scan counts its commits");
    let after = &logged[counted + 1..];
    assert!(
        !after.is_empty() && !after.iter().any(|command| command == "rev-list --count"),
        "the first scan reads on after its count and no second scan starts: {logged:?}"
    );
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
}
