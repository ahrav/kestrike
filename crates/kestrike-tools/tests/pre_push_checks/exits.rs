//! The hook's cases of where and how a check starts and of the tool's own failures, started through the
//! tool: a check runs in a worktree of mode 0700 under `TMPDIR`, else `/tmp`, with the push's environment
//! and the tool's standard output, and each failure of the tool's own steps exits with its code after the
//! worktree is removed.

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;

use super::push::{Fixture, STUB, executable, finished, spawn_with_input, which};

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

/// A `git worktree add` that registers the worktree and exits 0 after writing a byte outside UTF-8 to its
/// standard output is refused: the tool runs no check, removes the worktree and exits 2 with a
/// `pre-push: git worktree add` line.
#[test]
fn a_worktree_add_whose_output_is_not_utf8_exits_2_before_any_check() {
    let fx = Fixture::new();
    let head = fx.commit(&[INVENTORY]);
    let git = which("git");
    executable(
        &fx.bin.join("git"),
        &format!(
            "#!/bin/sh
\
             if [ \"$1 $2\" = 'worktree add' ]; then \"{git}\" \"$@\" || exit; printf '\\377'; exit 0; fi\n\
             exec \"{git}\" \"$@\"\n",
            git = git.display()
        ),
    );
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(2), "{}", run.stderr);
    let last = run
        .stderr
        .lines()
        .last()
        .expect("the tool prints the refusal");
    assert!(
        last.starts_with("pre-push: git worktree add"),
        "{}",
        run.stderr
    );
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
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

/// A `git worktree remove` that Git runs and refuses is named by its line, the worktree stays registered,
/// and the checks decide the exit, as the script's removal did.
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
    let (reader, unread) = std::io::pipe().expect("the pipe is made");
    drop(reader);
    let mut child = fx
        .tool()
        .stdin(Stdio::piped())
        .stderr(unread)
        .spawn()
        .expect("the tool starts");
    child
        .stdin
        .take()
        .expect("standard input is piped")
        .write_all(Fixture::input(&[(&head, &fx.base)]).as_bytes())
        .expect("the ref lines are written");
    let status = finished(child.into());
    assert_eq!(status.code, Some(120));
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

#[test]
fn a_failed_read_of_standard_input_exits_1() {
    let fx = Fixture::new();
    let mut command = fx.tool();
    command
        .stdin(File::open(&fx.repo).expect("the directory opens"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = finished(command.spawn().expect("the tool starts").into());
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
        let mut command = fx.tool();
        if ignored {
            ignoring_sigchld(&mut command);
        }
        command.env("PATH", &empty);
        let run = finished(spawn_with_input(
            &mut command,
            Fixture::input(&[(&head, &fx.base)]),
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
        let mut command = fx.tool();
        ignoring_sigchld(&mut command);
        command.env("STUB_TEST_SELECT_TESTS", code.to_string());
        let run = finished(spawn_with_input(
            &mut command,
            Fixture::input(&[(&head, &fx.base)]),
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
    let head = fx.commit(&[INVENTORY]);
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
    executable(
        &linked.join("git"),
        &format!(
            "#!/bin/sh\nif [ \"$1 $2\" = 'worktree add' ]; then \"{git}\" \"$@\"; status=$?; rm -f \"$0\"; exit \"$status\"; fi\nexec \"{git}\" \"$@\"\n",
            git = which("git").display()
        ),
    );
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
/// the add's 2, and the locked entry stays registered until `git worktree unlock` and then
/// `git worktree prune`, or a doubly forced `git worktree remove`, clears it.
#[test]
fn a_half_linked_locked_worktree_stays_registered_after_a_failed_add() {
    let fx = Fixture::new();
    let head = fx.commit(&[INVENTORY]);
    executable(
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

/// A `git worktree add` stopped before it writes the worktree's `gitdir` file can leave an entry under the
/// common `.git/worktrees` directory that holds only its `locked` file: Git lists no such worktree, the
/// removal names a tree Git does not know, the exit is the add's 2, and the entry stays for its owner to
/// delete.
#[test]
fn a_locked_only_entry_left_by_a_failed_add_stays_and_is_not_listed() {
    let fx = Fixture::new();
    let head = fx.commit(&[INVENTORY]);
    executable(
        &fx.bin.join("git"),
        &format!(
            "#!/bin/sh\nif [ \"$1 $2\" = 'worktree add' ]; then\n\
             \x20 entry=\"$(\"{git}\" rev-parse --git-common-dir)/worktrees/$(basename \"$5\")\"\n\
             \x20 mkdir -p \"$entry\" && : > \"$entry/locked\" || exit\n\
             \x20 printf '%s\\n' \"$entry\" > \"$STUB_LOG.entry\"\n\
             \x20 exit 128\n\
             fi\nexec \"{git}\" \"$@\"\n",
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
    assert_eq!(fx.worktrees(), 1);
    let entry = fs::read_to_string(fx.logged(".entry")).expect("the stand-in names its entry");
    let entry = fx.repo.join(entry.trim_end());
    let held: Vec<_> = fs::read_dir(&entry)
        .expect("the entry stays")
        .map(|item| item.expect("the entry reads").file_name())
        .collect();
    assert_eq!(held, ["locked"]);
    fs::remove_dir_all(&entry).expect("the entry is deleted");
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

/// A ref field holding a NUL byte reaches a Git argument that the standard library refuses before any
/// start; the tool prints `pre-push: ` and the refusal and exits 2, as for a Git read that fails.
#[test]
fn a_nul_byte_in_a_ref_field_exits_2() {
    let fx = Fixture::new();
    let run = finished(fx.start(&format!("refs/heads/x a\0b refs/heads/x {}\n", fx.base)));
    assert_eq!(run.code, Some(2), "{}", run.stderr);
    assert!(run.stderr.starts_with("pre-push: "), "{}", run.stderr);
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
}

/// `ignoring_sigchld` starts `command` with SIGCHLD ignored, set in the child just before `exec`.
fn ignoring_sigchld(command: &mut std::process::Command) {
    // SAFETY: the closure calls `signal`, which is async-signal-safe, and reads `errno` through
    // `last_os_error`; it allocates nothing and takes no lock.
    unsafe {
        command.pre_exec(|| {
            if libc::signal(libc::SIGCHLD, libc::SIG_IGN) == libc::SIG_ERR {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// `tree_line` holds when `line` names a worktree directory under `parent` and ends with `ending`.
fn tree_line(line: &str, parent: &Path, ending: &str) -> bool {
    line.strip_prefix(&format!(
        "pre-push-checks: {}/kestrike-pre-push-",
        parent.display()
    ))
    .is_some_and(|rest| rest.ends_with(ending))
}

/// A `TMPDIR` that names a missing directory fails the worktree's `mkdir`: the tool prints the path and
/// the error, runs no check, registers no worktree and exits 1.
#[test]
fn a_tmpdir_that_names_a_missing_directory_exits_1() {
    let mut fx = Fixture::new();
    let head = fx.commit(&[INVENTORY]);
    let missing = fx.temp.join("missing");
    fx.set("TMPDIR", missing.clone());
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    let last = run
        .stderr
        .lines()
        .last()
        .expect("the tool prints the failure");
    assert!(
        tree_line(last, &missing, ": No such file or directory (os error 2)"),
        "{}",
        run.stderr
    );
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert_eq!(fx.worktrees(), 1);
    assert!(!missing.exists());
}

/// A relative `TMPDIR` is made absolute against the tool's working directory, its `..` components kept:
/// Git's `worktree add` gets the absolute path, and the check runs there.
#[test]
fn a_relative_tmpdir_is_read_against_the_working_directory() {
    let mut fx = Fixture::new();
    let head = reporting(&fx);
    let parent = fx.temp.join("relative");
    fs::create_dir(&parent).expect("the parent is made");
    let started = fx.repo.join("sub");
    fs::create_dir(&started).expect("the working directory is made");
    let started = fs::canonicalize(&started).expect("the working directory resolves");
    fx.set("TMPDIR", "../../relative");
    fx.wrap_git_around(
        "if [ \"$1 $2\" = 'worktree add' ]; then printf '%s\\n' \"$5\" >> \"$STUB_LOG.git\"; fi",
    );
    let run = finished(fx.start_in(&started, &Fixture::input(&[(&head, &fx.base)]), &[]));
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let added = fs::read_to_string(fx.logged(".git")).expect("the wrapper logs the add");
    assert!(
        added.starts_with(&format!(
            "{}/../../relative/kestrike-pre-push-",
            started.display()
        )),
        "{added}"
    );
    let where_ = fs::read_to_string(fx.logged(".where")).expect("the check logs its directory");
    in_worktree(&where_, &parent);
    assert_eq!(fx.worktrees(), 1);
}

/// A check that passes but leaves a directory the removal cannot empty, a nonempty directory of mode 0500,
/// makes the final removal of the worktree's directory fail: the tool prints the directory and the error
/// and exits 1.
#[test]
fn a_worktree_directory_that_cannot_be_removed_exits_1() {
    // SAFETY: `geteuid` takes no arguments and touches no memory.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let fx = Fixture::new();
    let head = fx.commit(&[
        INVENTORY,
        ("scripts/test-select-tests.py", &format!("# locked\n{STUB}")),
    ]);
    let run = fx.push(&[(&head, &fx.base)]);
    let left = fx.left();
    for tree in &left {
        let locked = tree.join("locked");
        if locked.exists() {
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o700))
                .expect("the mode is restored");
        }
    }
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    let last = run
        .stderr
        .lines()
        .last()
        .expect("the tool prints the failure");
    assert!(
        tree_line(last, &fx.tmp, ": Permission denied (os error 13)"),
        "{}",
        run.stderr
    );
    assert!(!run.stderr.contains("failed:"), "{}", run.stderr);
    assert_eq!(
        fx.ran(),
        ["test-select-tests.py", "verify-receipts.py admit"]
    );
    assert_eq!(left.len(), 1, "{left:?}");
    fx.git(&["worktree", "prune"]);
}

/// Ref lines that hold bytes outside UTF-8 read each such byte as a surrogate: a malformed line is refused
/// with the byte as `\udcff`, and a four-field line whose ref name holds one is planned as any other.
#[test]
fn bytes_outside_utf8_on_standard_input_read_as_surrogates() {
    let fx = Fixture::new();
    let run = finished(spawn_with_input(&mut fx.tool(), b"ref\xff\n"));
    assert_eq!(run.code, Some(2), "{}", run.stderr);
    assert_eq!(run.stderr, "pre-push: malformed ref line: 'ref\\udcff'\n");
    let head = fx.commit(&[INVENTORY]);
    let mut line = b"refs/heads/\xff ".to_vec();
    line.extend(format!("{head} refs/heads/x {}\n", fx.base).as_bytes());
    let run = finished(spawn_with_input(&mut fx.tool(), line));
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(
        fx.ran(),
        ["test-select-tests.py", "verify-receipts.py admit"]
    );
}

/// A removal that Git refuses with an interior CRLF and a lone CR in its error prints each as one line
/// feed.
#[test]
fn a_refused_removal_s_carriage_returns_read_as_line_feeds() {
    let fx = Fixture::new();
    let head = fx.commit(&[INVENTORY]);
    fx.wrap_git_around(
        "if [ \"$1 $2\" = 'worktree remove' ]; then printf 'error: kept\\r\\nby the\\rstand-in\\r\\n' >&2; exit 1; fi",
    );
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(
        run.stderr.ends_with(": error: kept\nby the\nstand-in\n"),
        "{:?}",
        run.stderr
    );
    assert!(!run.stderr.contains('\r'), "{:?}", run.stderr);
    fs::remove_file(fx.bin.join("git")).expect("the wrapper is removed");
    fx.git(&["worktree", "prune"]);
    assert_eq!(fx.worktrees(), 1);
}

/// A `git worktree add` that exits nonzero, after which Git cannot start for the removal, exits 1: the
/// removal's line comes first and the add's refusal last.
#[test]
fn a_failed_add_beside_a_removal_whose_git_cannot_start_exits_1() {
    let fx = Fixture::new();
    let head = fx.commit(&[INVENTORY]);
    let tools = fx.temp.join("tools");
    fs::create_dir(&tools).expect("the directory is made");
    symlink(which("rm"), tools.join("rm")).expect("the link is made");
    fx.wrap_git_around(
        "if [ \"$1 $2\" = 'worktree add' ]; then rm -f \"$0\"; echo 'fatal: refused by the stand-in' >&2; exit 128; fi",
    );
    let mut searched = fx.bin.clone().into_os_string();
    searched.push(":");
    searched.push(&tools);
    let mut command = fx.tool();
    command.env("PATH", searched);
    let run = finished(spawn_with_input(
        &mut command,
        Fixture::input(&[(&head, &fx.base)]),
    ));
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    let lines: Vec<&str> = run.stderr.lines().collect();
    let [.., removal, add] = lines.as_slice() else {
        panic!("two lines end the run: {}", run.stderr);
    };
    assert!(
        removal.starts_with(&format!(
            "pre-push: could not remove worktree {}/kestrike-pre-push-",
            fx.tmp.display()
        )) && removal.ends_with(": git: No such file or directory (os error 2)"),
        "{}",
        run.stderr
    );
    assert!(
        add.starts_with("pre-push: git worktree add")
            && add.ends_with("fatal: refused by the stand-in"),
        "{}",
        run.stderr
    );
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert!(fx.left().is_empty(), "{:?}", fx.left());
    assert_eq!(fx.worktrees(), 1);
}

/// Git that can no longer start once the plan, the scan and the guard have read it fails the worktree add:
/// the tool prints `pre-push-checks: git: ` and the error after the removal's line, runs no check and
/// exits 1.
#[test]
fn a_git_that_cannot_start_for_the_add_exits_1() {
    let fx = Fixture::new();
    let head = fx.commit(&[INVENTORY, ("chaos/receipts/run/notes.txt", "n\n")]);
    let rm = which("rm");
    fx.wrap_git_around(&format!(
        "if [ \"$1\" = diff-tree ]; then \"{}\" -f \"$0\"; fi",
        rm.display()
    ));
    let mut command = fx.tool();
    command.env("PATH", &fx.bin);
    let run = finished(spawn_with_input(
        &mut command,
        Fixture::input(&[(&head, &fx.base)]),
    ));
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(
        run.stderr
            .ends_with(": git: No such file or directory (os error 2)\npre-push-checks: git: No such file or directory (os error 2)\n"),
        "{}",
        run.stderr
    );
    assert!(fx.ran().is_empty(), "{:?}", fx.ran());
    assert!(fx.left().is_empty(), "{:?}", fx.left());
    assert_eq!(fx.worktrees(), 1);
}
