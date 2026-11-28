//! The cases of the checkout a run judges: it stays as it was but for the score, the score's file is
//! written through a staging file beside it, each worktree goes, and a signal stops the running child,
//! removes the worktrees and exits 128 plus the signal with no score.

use std::time::Duration;

use super::fixture::{APART, Fixture, PLANTS, extras, mode_bits, shown, text_of, umask, wait_for};

/// A run of every plant but those that need a signal leaves the checkout as it was but for the score.
#[test]
fn the_starting_checkout_stays_unchanged_but_for_the_score() {
    let mut fx = Fixture::new();
    let mut names: Vec<String> = PLANTS.iter().map(|(name, _)| (*name).to_owned()).collect();
    names.extend(
        extras()
            .into_iter()
            .filter(|name| !APART.contains(&name.as_str())),
    );
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    fx.stock(&names);
    let before = fx.state();
    let done = fx.run(&names, &[]);
    assert_eq!(done.code, 1, "{}", done.stderr);
    fx.verdict("p-lock", "missed", "each expected profile reached 300 runs");
    std::fs::remove_file(&fx.score).expect("the score is removed");
    assert_eq!(fx.state(), before);
}

/// A run of the whole store names no plant in its settings.
#[test]
fn a_run_of_the_whole_store_selects_no_plant_in_its_settings() {
    let mut fx = Fixture::new();
    fx.run(&[], &[]);
    let (written, _) = fx.results();
    let Some(kestrike_tools::json::Value::Object(settings)) = written.get("settings") else {
        panic!("the score holds its settings");
    };
    assert_eq!(shown(settings.get("plants")), "null");
}

/// A file or a link at a staging name beside the score stays as it was, and the score takes mode 0666
/// less the umask.
#[test]
fn a_staging_file_or_link_beside_the_score_stays_as_it_was() {
    let mut fx = Fixture::new();
    let (sentinel, target) = (fx.store.join("score.json.tmp"), fx.scratch.join("target"));
    std::fs::write(&sentinel, "a sentinel\n").expect("written");
    std::fs::write(&target, "a target\n").expect("written");
    let link = fx.store.join(".score.json.link");
    std::os::unix::fs::symlink(&target, &link).expect("linked");
    let done = fx.run(&["p-miss"], &[]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    assert_eq!(
        std::fs::read_to_string(&sentinel).expect("reads"),
        "a sentinel\n"
    );
    assert!(
        link.symlink_metadata()
            .expect("stats")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("reads"),
        "a target\n"
    );
    assert!(
        !fx.score
            .symlink_metadata()
            .expect("stats")
            .file_type()
            .is_symlink()
    );
    assert_eq!(mode_bits(&fx.score), 0o666 & !umask());
}

/// A score that is a link is replaced, and its target stays.
#[test]
fn a_score_that_is_a_link_is_replaced_and_its_target_stays() {
    let mut fx = Fixture::new();
    let target = fx.scratch.join("elsewhere.json");
    std::fs::write(&target, "another file\n").expect("written");
    std::os::unix::fs::symlink(&target, &fx.score).expect("linked");
    let done = fx.run(&["p-noprofile"], &[]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    assert!(
        !fx.score
            .symlink_metadata()
            .expect("stats")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("reads"),
        "another file\n"
    );
    let (written, _) = fx.results();
    assert_eq!(text_of(written.get("commit").expect("a commit")), fx.head);
}

/// A run leaves an index whose plant entry is stale as it was.
#[test]
fn a_run_leaves_an_index_whose_plant_entry_is_stale_as_it_was() {
    let mut fx = Fixture::new();
    let index = fx.repo.join(".git/index");
    let before = std::fs::read(&index).expect("reads");
    let record = fx.store.join("p-noprofile/plant.json");
    let later = std::fs::metadata(&record)
        .expect("stats")
        .modified()
        .expect("a time")
        + Duration::from_secs(5);
    std::fs::File::options()
        .write(true)
        .open(&record)
        .expect("opens")
        .set_modified(later)
        .expect("set");
    let done = fx.run(&["p-noprofile"], &[]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    assert_eq!(std::fs::read(&index).expect("reads"), before);
    fx.git(&["status", "--porcelain"]);
    assert_ne!(
        std::fs::read(&index).expect("reads"),
        before,
        "a refreshing status rewrites the stale index"
    );
}

/// A worktree the run cannot remove exits 4, is named, and leaves no score.
#[test]
fn a_worktree_the_run_cannot_remove_exits_4_and_names_it() {
    let mut fx = Fixture::new();
    let (name, path) = fx.git_shim("remove", "echo 'a refused removal' >&2; exit 1");
    let done = fx.run(&["p-miss"], &[(name, &path)]);
    assert_eq!(done.code, 4, "{}", done.stderr);
    let tree = fx.work.join("plants/p-miss/tree");
    assert!(
        done.stderr.contains(&format!(
            "plant-runner left the worktree {}",
            tree.display()
        )),
        "{}",
        done.stderr
    );
    assert!(!fx.score.exists());
}

/// A worktree listing that fails exits 4 and names the worktree.
#[test]
fn a_worktree_listing_that_fails_exits_4_and_names_the_worktree() {
    let mut fx = Fixture::new();
    let (name, path) = fx.git_shim("list", "echo 'a refused listing' >&2; exit 1");
    let done = fx.run(&["p-miss"], &[(name, &path)]);
    assert_eq!(done.code, 4, "{}", done.stderr);
    let tree = fx.work.join("plants/p-miss/tree");
    let named = format!(
        "plant-runner cannot tell whether the worktree {} remains",
        tree.display()
    );
    assert!(done.stderr.contains(&named), "{}", done.stderr);
    assert!(!fx.score.exists());
}

/// A signal during the worktree add lands while the cleanup's removal is refused: the cleanup names
/// the worktree before the run exits 128 plus the signal, with no stand-in call and no score.
#[test]
fn a_worktree_the_run_cannot_remove_after_a_signal_is_named_before_the_signal_s_exit() {
    let mut fx = Fixture::new();
    let action = "case \" $* \" in *\" add \"*) kill -TERM $PPID; sleep 0.5;; \
                  *\" remove \"*) echo 'a refused removal' >&2; exit 1;; esac";
    let (name, path) = fx.git_shim("worktree", action);
    let done = fx.run(&["p-miss"], &[(name, &path)]);
    assert_eq!(done.code, 128 + libc::SIGTERM, "{}", done.stderr);
    let tree = fx.work.join("plants/p-miss/tree");
    assert!(
        done.stderr.contains(&format!(
            "plant-runner left the worktree {}",
            tree.display()
        )),
        "{}",
        done.stderr
    );
    assert!(fx.calls(&[]).is_empty());
    assert!(!fx.score.exists());
}

/// A signal during the worktree add lets the add finish, then the worktree goes and the run exits 128
/// plus the signal with the checkout as it was.
#[test]
fn a_signal_during_the_worktree_add_lets_the_add_finish_and_removes_the_worktree() {
    let mut fx = Fixture::new();
    let before = fx.state();
    let (started, finished) = (fx.scratch.join("started"), fx.scratch.join("finished"));
    let add = format!(
        "touch {}; kill -TERM $PPID; sleep 0.5; \"$real\" \"$@\"; code=$?; touch {}; exit $code",
        started.display(),
        finished.display()
    );
    let (name, path) = fx.git_shim("add", &add);
    let done = fx.run(&["p-miss"], &[(name, &path)]);
    assert_eq!(done.code, 128 + libc::SIGTERM, "{}", done.stderr);
    assert!(
        started.exists() && finished.exists(),
        "the signal ended the worktree add"
    );
    assert!(fx.calls(&[]).is_empty());
    assert!(!fx.score.exists());
    assert_eq!(fx.state(), before);
}

/// `signal_run` starts the tool on `name`, sends `first` once the stand-in is ready and `second` while
/// the stand-in handles the first, releases the stand-in, and returns the tool's exit and error output.
/// The stand-in must have been sent SIGTERM, and the checkout stays as it was with no score.
fn signal_run(
    fx: &mut Fixture,
    name: &str,
    first: i32,
    second: Option<i32>,
    group: bool,
) -> (i32, String) {
    fx.stock(&[name]);
    let before = fx.state();
    let mut runner = fx.spawn(&[name], &[], group);
    wait_for(&fx.scratch.join("ready"), &mut runner.child);
    runner.signal(first, group);
    wait_for(&fx.scratch.join("handling"), &mut runner.child);
    if let Some(second) = second {
        runner.signal(second, group);
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            matches!(runner.child.try_wait(), Ok(None)),
            "the tool exited before the stand-in finished"
        );
    }
    std::fs::write(fx.scratch.join("release"), "").expect("released");
    let ended = runner.finish();
    let terminated =
        std::fs::read_to_string(fx.scratch.join("terminated")).expect("the stand-in ended");
    assert_eq!(terminated, libc::SIGTERM.to_string());
    assert!(!fx.score.exists());
    assert_eq!(fx.state(), before);
    ended
}

fn reset_markers(fx: &Fixture) {
    for marker in ["ready", "handling", "release", "terminated"] {
        let _ = std::fs::remove_file(fx.scratch.join(marker));
    }
    let _ = std::fs::remove_dir_all(&fx.work);
}

/// The first of two signals stops the sweep, removes the worktrees and gives the exit.
#[test]
fn a_signal_stops_the_sweep_and_removes_the_worktrees() {
    let mut fx = Fixture::new();
    for (first, second) in [
        (libc::SIGTERM, libc::SIGHUP),
        (libc::SIGINT, libc::SIGTERM),
        (libc::SIGTERM, libc::SIGINT),
    ] {
        reset_markers(&fx);
        let (code, err) = signal_run(&mut fx, "p-hang", first, Some(second), false);
        assert_eq!(code, 128 + first, "{err}");
    }
}

/// A signal during the archive build removes its target and worktree.
#[test]
fn a_signal_during_the_build_removes_its_target_and_worktree() {
    let mut fx = Fixture::new();
    let (code, err) = signal_run(
        &mut fx,
        "p-hangbuild",
        libc::SIGTERM,
        Some(libc::SIGHUP),
        false,
    );
    assert_eq!(code, 128 + libc::SIGTERM, "{err}");
    assert!(!fx.work.join("plants/p-hangbuild/target").exists());
}

/// A signal while `campaign confirm` or a seed check runs stops that child and ends the run with 128
/// plus the signal and no score, though the judgment that asked for the child goes on to its end.
#[test]
fn a_signal_during_confirm_or_a_seed_check_ends_the_run() {
    for name in ["p-hangconfirm", "p-hangseed"] {
        let mut fx = Fixture::new();
        let (code, err) = signal_run(&mut fx, name, libc::SIGTERM, None, false);
        assert_eq!(code, 128 + libc::SIGTERM, "{name}: {err}");
    }
}

/// A signal to the tool's process group reaches the proof rerun, which leads a session of its own,
/// only through the tool; the proof's target and worktree go.
#[test]
fn a_signal_to_the_group_during_a_proof_rerun_reaches_the_proof_only_through_the_runner() {
    let mut fx = Fixture::new();
    let (code, err) = signal_run(&mut fx, "p-hangproof", libc::SIGHUP, None, true);
    assert_eq!(code, 128 + libc::SIGHUP, "{err}");
    assert!(!fx.work.join("proof/target").exists());
    assert!(!fx.work.join("proof/tree").exists());
}

/// A tool started with SIGTERM blocked still takes it once its handlers stand: the handlers' install
/// unblocks the three handled signals, so the sweep is stopped and the run ends with 128 plus SIGTERM.
#[test]
fn a_sigterm_inherited_as_blocked_is_taken_once_the_handlers_stand() {
    use std::os::unix::process::CommandExt;
    let mut fx = Fixture::new();
    fx.stock(&["p-hang"]);
    let before = fx.state();
    let mut runner = fx.spawn_with(&["p-hang"], &[], false, |command| {
        // SAFETY: the hook runs in the forked child before `exec` and calls only `sigemptyset`,
        // `sigaddset` and `sigprocmask`, which are async-signal-safe, on a set of its own.
        unsafe {
            command.pre_exec(|| {
                let mut blocked: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut blocked);
                libc::sigaddset(&mut blocked, libc::SIGTERM);
                if libc::sigprocmask(libc::SIG_BLOCK, &blocked, std::ptr::null_mut()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    });
    wait_for(&fx.scratch.join("ready"), &mut runner.child);
    runner.signal(libc::SIGTERM, false);
    wait_for(&fx.scratch.join("handling"), &mut runner.child);
    std::fs::write(fx.scratch.join("release"), "").expect("released");
    let (code, err) = runner.finish();
    assert_eq!(code, 128 + libc::SIGTERM, "{err}");
    assert!(!fx.score.exists());
    assert_eq!(fx.state(), before);
}

/// A SIGHUP the tool inherits as ignored stays ignored; a later SIGTERM ends the run.
#[test]
fn a_sighup_inherited_as_ignored_stays_ignored() {
    let mut fx = Fixture::new();
    fx.stock(&["p-hang"]);
    let before = fx.state();
    let mut runner = fx.spawn(
        &["p-hang"],
        &["sh", "-c", "trap '' HUP; exec \"$@\"", "sh"],
        false,
    );
    wait_for(&fx.scratch.join("ready"), &mut runner.child);
    runner.signal(libc::SIGHUP, false);
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        matches!(runner.child.try_wait(), Ok(None)),
        "an ignored SIGHUP stopped the run"
    );
    assert!(!fx.scratch.join("handling").exists());
    runner.signal(libc::SIGTERM, false);
    wait_for(&fx.scratch.join("handling"), &mut runner.child);
    std::fs::write(fx.scratch.join("release"), "").expect("released");
    let (code, err) = runner.finish();
    assert_eq!(code, 128 + libc::SIGTERM, "{err}");
    assert_eq!(fx.state(), before);
}

/// Every child the run starts reads no replacement object: each call of `campaign`, of the head's
/// helper and of the question to it is given `GIT_NO_REPLACE_OBJECTS=1`, which the caller did not set.
#[test]
fn every_child_is_given_no_replacement_objects() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-miss"], &[]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    let calls = [
        ("campaign", fx.calls(&[]).len()),
        ("python3", fx.proof_log().len()),
        ("question", 3),
    ];
    for (role, count) in calls {
        let seen = std::fs::read_to_string(fx.scratch.join(format!("{role}-no-replace")))
            .expect("the stand-in ran");
        assert_eq!(seen, "1\n".repeat(count), "{role}");
    }
}

/// A signal while a Git step runs kills Git with SIGKILL and ends the run within Git's grace, with 128
/// plus the signal, the worktrees removed and no score. Each row's Git step ignores SIGTERM, so only
/// SIGKILL ends it, and the step's process is gone once the tool has exited: the apply check of the
/// plant, the reset of the proof's worktree and the planted commit.
#[test]
fn a_signal_during_a_git_step_kills_git_and_ends_the_run() {
    for word in ["--check", "reset", "commit"] {
        let mut fx = Fixture::new();
        fx.stock(&["p-miss"]);
        let before = fx.state();
        let (ready, pid) = (fx.scratch.join("ready"), fx.scratch.join("git.pid"));
        let (_, path) = fx.git_shim(
            word,
            &format!(
                "trap '' TERM; echo $$ > {}; touch {}; exec sleep 30",
                pid.display(),
                ready.display()
            ),
        );
        let real = fx.env.clone();
        fx.env.retain(|(name, _)| name != "PATH");
        fx.env.push(("PATH".into(), path.into()));
        let mut runner = fx.spawn(&["p-miss"], &[], false);
        wait_for(&ready, &mut runner.child);
        let start = std::time::Instant::now();
        runner.signal(libc::SIGTERM, false);
        let (code, err) = runner.finish();
        assert_eq!(code, 128 + libc::SIGTERM, "{word}: {err}");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{word}: the run ended {:?} after the signal",
            start.elapsed()
        );
        let pid: libc::pid_t = std::fs::read_to_string(&pid)
            .expect("the step wrote its process id")
            .trim()
            .parse()
            .expect("a process id");
        // SAFETY: `kill` with signal 0 takes two integers and only checks that the process exists.
        let gone = unsafe { libc::kill(pid, 0) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        assert!(gone, "{word}: the Git step outlived the tool");
        fx.env = real;
        assert!(!fx.score.exists(), "{word}");
        assert_eq!(fx.state(), before, "{word}");
    }
}
