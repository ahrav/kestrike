//! The hook's cases of where and how a check starts and of the tool's own failures, started through the
//! tool: a check runs in a worktree of mode 0700 under `TMPDIR`, else `/tmp`, with the push's environment
//! and the tool's standard output, and each failure of the tool's own steps exits with its code after the
//! worktree is removed.

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Stdio;

use super::push::{BINARY, Fixture, STUB, finished, spawn_with_input, top, which};

const PATHSPEC_MODES: [&str; 4] = [
    "GIT_LITERAL_PATHSPECS",
    "GIT_GLOB_PATHSPECS",
    "GIT_NOGLOB_PATHSPECS",
    "GIT_ICASE_PATHSPECS",
];

const INVENTORY: (&str, &str) = ("scripts/test-inventory.json", r#"{"rows": []}"#);

fn reporting(fx: &Fixture) -> String {
    fx.commit(&[
        INVENTORY,
        ("scripts/test-select-tests.py", &format!("# env\n{STUB}")),
    ])
}

fn in_worktree(where_: &str, parent: &Path) {
    let parent = fs::canonicalize(parent).expect("the parent resolves");
    let mut lines = where_.lines();
    let tree = lines.next().expect("the directory is logged");
    let name = tree
        .strip_prefix(&format!("{}/kestrike-pre-push-", parent.display()))
        .unwrap_or_else(|| panic!("{tree} lies under {}", parent.display()));
    assert_eq!(name.len(), 8, "{tree}");
    assert!(
        name.bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
        "{tree}"
    );
    assert_eq!(lines.next(), Some("drwx------"), "{where_}");
    assert!(!Path::new(tree).exists(), "{tree} is removed");
}

#[test]
fn a_check_runs_in_the_pushed_tip_s_worktree_with_the_push_s_environment_and_output() {
    let mut fx = Fixture::new();
    let head = reporting(&fx);
    fx.set("KESTRIKE_PUSH_MARK", "pushed");
    for mode in PATHSPEC_MODES {
        fx.set(mode, "1");
    }
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.stdout, "output of test-select-tests.py\n");
    assert!(
        run.stderr
            .contains("\nerror output of test-select-tests.py\n"),
        "{}",
        run.stderr
    );
    let env = fs::read_to_string(fx.logged(".env")).expect("the check logs its environment");
    let env: Vec<&str> = env.lines().collect();
    for present in [
        "KESTRIKE_PUSH_MARK=pushed",
        "GIT_NO_REPLACE_OBJECTS=1",
        &format!("STUB_LOG={}", fx.log.display()),
        &format!("TMPDIR={}", fx.tmp.display()),
    ] {
        assert!(env.contains(&present), "{present}: {env:?}");
    }
    for mode in PATHSPEC_MODES {
        assert!(
            !env.iter().any(|line| line.starts_with(&format!("{mode}="))),
            "{mode}: {env:?}"
        );
    }
    let where_ = fs::read_to_string(fx.logged(".where")).expect("the check logs its directory");
    in_worktree(&where_, &fx.tmp);
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

#[test]
fn an_empty_or_unset_tmpdir_puts_the_worktree_under_tmp() {
    let mut fx = Fixture::new();
    let head = reporting(&fx);
    for set in [true, false] {
        fx.clear();
        if set {
            fx.set("TMPDIR", "");
        } else {
            fx.unset("TMPDIR");
        }
        let run = fx.push(&[(&head, &fx.base)]);
        assert_eq!(run.code, Some(0), "{set}: {}", run.stderr);
        let where_ = fs::read_to_string(fx.logged(".where")).expect("the check logs its directory");
        in_worktree(&where_, Path::new("/tmp"));
        assert_eq!(fx.worktrees(), 1, "{set}");
    }
}

#[test]
fn a_check_that_cannot_start_exits_1_after_the_worktree_is_removed() {
    let mut fx = Fixture::new();
    let head = fx.commit(&[INVENTORY]);
    let bare = fx.temp.join("git-only");
    fs::create_dir(&bare).expect("the directory is made");
    symlink(which("git"), bare.join("git")).expect("the link is made");
    fx.set("PATH", bare.clone());
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(
        run.stderr
            .ends_with("pre-push-checks: python3: No such file or directory (os error 2)\n"),
        "{}",
        run.stderr
    );
    assert!(!run.stderr.contains("failed:"), "{}", run.stderr);
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

#[test]
fn a_failed_worktree_add_exits_2_after_the_directory_is_removed() {
    let fx = Fixture::new();
    let head = fx.commit(&[INVENTORY]);
    fx.wrap_git_around(
        "if [ \"$1 $2\" = 'worktree add' ]; then echo 'fatal: refused by the stand-in' >&2; exit 128; fi",
    );
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(2), "{}", run.stderr);
    let last = run
        .stderr
        .lines()
        .last()
        .expect("the tool prints the failure");
    assert!(
        last.starts_with("pre-push: git worktree add")
            && last.ends_with("fatal: refused by the stand-in"),
        "{}",
        run.stderr
    );
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

#[test]
fn a_failed_worktree_removal_is_named_and_the_checks_decide_the_exit() {
    let fx = Fixture::new();
    let head = fx.commit(&[INVENTORY]);
    fx.wrap_git_around(
        "if [ \"$1 $2\" = 'worktree remove' ]; then echo 'error: kept by the stand-in' >&2; exit 1; fi",
    );
    let prefix = format!(
        "pre-push: could not remove worktree {}/kestrike-pre-push-",
        fx.tmp.display()
    );
    for (pushes, code) in (1..).zip([0, 1]) {
        let run = fx.push_with(&[(&head, &fx.base)], &[("test_select_tests", code)]);
        assert_eq!(run.code, Some(code), "{}", run.stderr);
        let named: Vec<&str> = run
            .stderr
            .lines()
            .filter(|line| line.starts_with(&prefix))
            .collect();
        assert_eq!(named.len(), 1, "{}", run.stderr);
        assert!(
            named[0].ends_with(": error: kept by the stand-in"),
            "{}",
            run.stderr
        );
        assert!(fx.left().is_empty(), "{:?}", fx.left());
        assert_eq!(
            fx.worktrees(),
            1 + pushes,
            "the refused worktree stays registered"
        );
    }
    fs::remove_file(fx.bin.join("git")).expect("the wrapper is removed");
    fx.git(&["worktree", "prune"]);
    assert_eq!(fx.worktrees(), 1);
}

#[test]
fn a_failed_write_to_standard_error_exits_120_before_any_check() {
    let fx = Fixture::new();
    let head = fx.commit(&[INVENTORY]);
    let full = File::options()
        .write(true)
        .open("/dev/full")
        .expect("the full device opens");
    let mut child = fx
        .command(BINARY)
        .arg(top())
        .args(["pre-push-checks", "origin", "url"])
        .stdin(Stdio::piped())
        .stderr(full)
        .spawn()
        .expect("the tool starts");
    child
        .stdin
        .take()
        .expect("standard input is piped")
        .write_all(Fixture::input(&[(&head, &fx.base)]).as_bytes())
        .expect("the ref lines are written");
    let status = finished(child);
    assert_eq!(status.code, Some(120));
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

#[test]
fn a_failed_read_of_standard_input_exits_1() {
    let fx = Fixture::new();
    let mut command = fx.command(BINARY);
    command
        .arg(top())
        .args(["pre-push-checks", "origin"])
        .stdin(File::open(&fx.repo).expect("the directory opens"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = finished(command.spawn().expect("the tool starts"));
    assert_eq!(output.code, Some(1));
    assert_eq!(
        output.stderr,
        "pre-push-checks: standard input: Is a directory (os error 21)\n"
    );
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
}

#[test]
fn a_git_that_cannot_start_exits_1_before_any_check() {
    let fx = Fixture::new();
    let head = fx.commit(&[INVENTORY]);
    let empty = fx.temp.join("empty");
    fs::create_dir(&empty).expect("the directory is made");
    for ignored in [false, true] {
        let mut command = fx.command("/bin/sh");
        let trap = if ignored { "trap '' CHLD; " } else { "" };
        command
            .args(["-c", &format!("{trap}exec \"$0\" \"$@\""), BINARY])
            .arg(top())
            .args(["pre-push-checks", "origin", "url"])
            .env("PATH", &empty);
        let run = finished(spawn_with_input(
            &mut command,
            &Fixture::input(&[(&head, &fx.base)]),
        ));
        assert_eq!(run.code, Some(1), "{ignored}: {}", run.stderr);
        assert_eq!(
            run.stderr, "pre-push-checks: git: No such file or directory (os error 2)\n",
            "{ignored}"
        );
        assert!(fx.ran().is_empty(), "{:?}", fx.ran());
        assert!(fx.left().is_empty(), "{:?}", fx.left());
    }
}

#[test]
fn a_tool_started_with_sigchld_ignored_reads_each_child_s_status() {
    let fx = Fixture::new();
    let head = fx.commit(&[INVENTORY]);
    for code in [0, 1] {
        fx.clear();
        let mut command = fx.command("/bin/sh");
        command
            .args(["-c", "trap '' CHLD; exec \"$0\" \"$@\"", BINARY])
            .arg(top())
            .args(["pre-push-checks", "origin", "url"])
            .env("STUB_TEST_SELECT_TESTS", code.to_string());
        let run = finished(spawn_with_input(
            &mut command,
            &Fixture::input(&[(&head, &fx.base)]),
        ));
        assert_eq!(run.code, Some(code), "{}", run.stderr);
        assert_eq!(
            run.stderr
                .contains("failed: python3 scripts/test-select-tests.py"),
            code == 1,
            "{}",
            run.stderr
        );
        assert_eq!(
            fx.ran(),
            ["test-select-tests.py", "verify-receipts.py admit"]
        );
        assert_eq!(fx.worktrees(), 1);
        assert!(fx.left().is_empty(), "{:?}", fx.left());
    }
}

#[test]
fn a_git_that_cannot_start_for_the_removal_exits_1_after_passing_checks() {
    let mut fx = Fixture::new();
    let head = fx.commit(&[
        INVENTORY,
        (
            "scripts/test-select-tests.py",
            &format!("# unlink-git\n{STUB}"),
        ),
    ]);
    let tools = fx.temp.join("tools");
    let linked = fx.temp.join("git-dir");
    for dir in [&tools, &linked] {
        fs::create_dir(dir).expect("the directory is made");
    }
    for program in [
        "cat", "cut", "env", "grep", "head", "ls", "mv", "rm", "sed", "sleep", "tr",
    ] {
        symlink(which(program), tools.join(program)).expect("the link is made");
    }
    let link = linked.join("git");
    symlink(which("git"), &link).expect("the link is made");
    let path = fx
        .env
        .iter()
        .find(|(key, _)| key == "PATH")
        .map(|(_, value)| value.clone())
        .expect("the fixture sets PATH");
    let mut searched = fx.bin.clone().into_os_string();
    for dir in [&tools, &linked] {
        searched.push(":");
        searched.push(dir);
    }
    fx.set("PATH", searched);
    fx.set("STUB_GIT_LINK", link.clone());
    let run = fx.push(&[(&head, &fx.base)]);
    fx.set("PATH", path);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    let named = format!(
        "pre-push: could not remove worktree {}/kestrike-pre-push-",
        fx.tmp.display()
    );
    let last = run
        .stderr
        .lines()
        .last()
        .expect("the tool prints the failure");
    assert!(
        last.starts_with(&named) && last.ends_with(": git: No such file or directory (os error 2)"),
        "{}",
        run.stderr
    );
    assert!(!run.stderr.contains("failed:"), "{}", run.stderr);
    assert_eq!(
        fx.ran(),
        ["test-select-tests.py", "verify-receipts.py admit"]
    );
    assert!(fx.left().is_empty(), "{:?}", fx.left());
    assert_eq!(fx.worktrees(), 2, "the worktree stays registered");
    fx.git(&["worktree", "prune"]);
    assert_eq!(fx.worktrees(), 1);
}

/// A `git worktree add` that ends after registering a locked worktree whose directory lacks its `.git`
/// file leaves the registration standing: the removal names the worktree it could not remove, the exit is
/// the add's 2, and the locked entry stays registered until a `git worktree remove` or `prune` of the
/// user's own clears it.
#[test]
fn a_half_linked_locked_worktree_stays_registered_after_a_failed_add() {
    let fx = Fixture::new();
    let head = fx.commit(&[INVENTORY]);
    super::push::executable(
        &fx.bin.join("git"),
        &format!(
            "#!/bin/sh\nif [ \"$1 $2\" = 'worktree add' ]; then\n  shift 2\n  \"{git}\" worktree add --lock \"$@\" || exit\n  rm -f \"$3/.git\"\n  exit 128\nfi\nexec \"{git}\" \"$@\"\n",
            git = which("git").display()
        ),
    );
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(2), "{}", run.stderr);
    let prefix = format!(
        "pre-push: could not remove worktree {}/kestrike-pre-push-",
        fx.tmp.display()
    );
    assert!(
        run.stderr.lines().any(|line| line.starts_with(&prefix)),
        "{}",
        run.stderr
    );
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    fs::remove_file(fx.bin.join("git")).expect("the wrapper is removed");
    assert_eq!(fx.worktrees(), 2);
    let listed = fx.git(&["worktree", "list", "--porcelain"]);
    let half_linked = listed
        .lines()
        .filter_map(|line| line.strip_prefix("worktree "))
        .nth(1)
        .expect("the half-linked worktree is listed");
    fx.git(&["worktree", "unlock", half_linked]);
    fx.git(&["worktree", "prune"]);
    assert_eq!(fx.worktrees(), 1);
}
