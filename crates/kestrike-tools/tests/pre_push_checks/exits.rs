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

const INVENTORY: (&str, &str) = ("scripts/test-inventory.json", r#"{"rows": []}"#);

fn reporting(fx: &Fixture) -> String {
    fx.commit(&[
        INVENTORY,
        ("scripts/test-select-tests.py", &format!("# env\n{STUB}")),
    ])
}

fn in_worktree(where_: &str, parent: &Path) {
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
    fx.set("GIT_LITERAL_PATHSPECS", "1");
    fx.set("GIT_ICASE_PATHSPECS", "1");
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.stdout, "output of test-select-tests.py\n");
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
    for absent in ["GIT_LITERAL_PATHSPECS=", "GIT_ICASE_PATHSPECS="] {
        assert!(
            !env.iter().any(|line| line.starts_with(absent)),
            "{absent}: {env:?}"
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
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let prefix = format!(
        "pre-push: could not remove worktree {}/kestrike-pre-push-",
        fx.tmp.display()
    );
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
    let status = child.wait().expect("the tool is reaped");
    assert_eq!(status.code(), Some(120));
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

#[test]
fn a_failed_read_of_standard_input_exits_1() {
    let fx = Fixture::new();
    let output = fx
        .command(BINARY)
        .arg(top())
        .args(["pre-push-checks", "origin"])
        .stdin(File::open(&fx.repo).expect("the directory opens"))
        .output()
        .expect("the tool runs");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "pre-push-checks: standard input: Is a directory (os error 21)\n"
    );
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
}

#[test]
fn the_hook_s_empty_remote_name_reads_a_deletion_and_refuses_a_malformed_line() {
    let fx = Fixture::new();
    let deletion = format!(
        "(delete) {} refs/heads/gone {}\n",
        "0".repeat(40),
        "1".repeat(40)
    );
    for (input, code, stderr) in [
        (deletion.as_str(), 0, ""),
        (
            "ref-update\n",
            2,
            "pre-push: malformed ref line: 'ref-update'\n",
        ),
    ] {
        let mut command = fx.command(BINARY);
        command.arg(top()).args(["pre-push-checks", ""]);
        let run = finished(spawn_with_input(&mut command, input));
        assert_eq!(run.code, Some(code), "{input:?}: {}", run.stderr);
        assert_eq!(run.stderr, stderr, "{input:?}");
        assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    }
}
