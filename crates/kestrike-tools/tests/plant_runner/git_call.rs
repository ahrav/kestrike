//! The Git call: its argument vector, the environment it is given, input bytes, the exit code, both
//! streams with their line ends, a checked failure, and the hooks it never runs.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;

use kestrike_tools::environ::{Environ, set};
use kestrike_tools::plants::git::{self, CallError, FIXED};

use super::repository::{Repository, executable, private_dir};

/// `recorder` puts a `git` first on `PATH` that writes each argument on a line of `args` and its whole
/// environment to `env`. Called with `apply` it copies its input to its output and writes `err\r\n` to
/// standard error; with `lines` it writes `a\r\nb\rc` and `err\r\n\r`; with `term` a SIGTERM ends it.
/// It exits 3. Text calls read the test's standard input, which the recorder leaves unread.
fn recorder(repository: &Repository) -> Environ {
    let dir = repository.scratch.join("recorder");
    private_dir(&dir);
    let (args, env) = (dir.join("args"), dir.join("env"));
    executable(
        &dir.join("git"),
        &format!(
            "#!/bin/sh\nfor arg; do printf '%s\\n' \"$arg\"; done > '{}'\nenv -0 > '{}'\n\
             for arg; do case \"$arg\" in\n  apply) cat; printf 'err\\r\\n' >&2;;\n  \
             lines) printf 'a\\r\\nb\\rc'; printf 'err\\r\\n\\r' >&2;;\n  term) kill -TERM $$;;\n\
             esac; done\nexit 3\n",
            args.display(),
            env.display()
        ),
    );
    let mut env = repository.env();
    let mut path = dir.into_os_string();
    path.push(":/usr/bin:/bin");
    set(&mut env, "PATH", path);
    env
}

fn recorded(repository: &Repository, file: &str) -> Vec<u8> {
    fs::read(repository.scratch.join("recorder").join(file)).expect("recorded")
}

/// `seen` is the environment the recorder saw, without the variables `sh` sets itself.
fn seen(repository: &Repository) -> Environ {
    let mut found: Environ = recorded(repository, "env")
        .split(|&byte| byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let at = entry
                .iter()
                .position(|&byte| byte == b'=')
                .expect("NAME=VALUE");
            let (name, value) = (&entry[..at], &entry[at + 1..]);
            (
                OsStr::from_bytes(name).to_owned(),
                OsStr::from_bytes(value).to_owned(),
            )
        })
        .filter(|(name, _)| !["PWD", "SHLVL", "_"].map(OsString::from).contains(name))
        .collect();
    found.sort();
    found
}

/// A text call passes the fixed options, `-C DIR` and its arguments, and gives Git exactly the environment
/// it is given, none of the test process's own variables.
#[test]
fn a_text_call_passes_its_vector_and_environment() {
    let repository = Repository::new();
    let mut env = recorder(&repository);
    set(&mut env, "PROBE", "passed".into());
    let args = ["status", "a b", "--", ""].map(OsStr::new);
    let done = git::text(&env, &repository.top, &args).expect("the call runs");
    let mut expected: Vec<String> = FIXED.iter().map(|arg| (*arg).to_owned()).collect();
    expected.push("-C".to_owned());
    expected.push(repository.top.display().to_string());
    expected.extend(["status", "a b", "--", ""].map(str::to_owned));
    assert_eq!(
        String::from_utf8(recorded(&repository, "args")).expect("UTF-8"),
        format!("{}\n", expected.join("\n"))
    );
    let mut given = env.clone();
    given.sort();
    assert_eq!(seen(&repository), given);
    let names: Vec<OsString> = given.iter().map(|(name, _)| name.clone()).collect();
    assert!(
        std::env::vars_os().any(|(name, _)| !names.contains(&name)),
        "the test process holds a variable the given environment lacks"
    );
    assert_eq!(
        (done.code, done.stdout.as_str(), done.stderr.as_str()),
        (3, "", "")
    );
    assert_eq!(done.step.to_string(), "status");
    assert_eq!(
        FIXED,
        [
            "--no-optional-locks",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "i18n.commitEncoding=UTF-8",
            "-c",
            "apply.whitespace=nowarn",
            "-c",
            "apply.ignoreWhitespace=no",
        ]
    );
}

/// A text call reads `\r\n` and `\r` as `\n` on both streams.
#[test]
fn a_text_call_reads_each_line_end_as_a_newline() {
    let repository = Repository::new();
    let env = recorder(&repository);
    let done = git::text(&env, &repository.top, &[OsStr::new("lines")]).expect("the call runs");
    assert_eq!(
        (done.stdout.as_str(), done.stderr.as_str()),
        ("a\nb\nc", "err\n\n")
    );
}

/// A bytes call writes its input to Git and returns both streams as bytes, line ends unchanged.
#[test]
fn a_bytes_call_writes_its_input() {
    let repository = Repository::new();
    let env = recorder(&repository);
    let input = b"\xff\r\n\0patch\r".repeat(50_000);
    let done = git::bytes(&env, &repository.top, &[OsStr::new("apply")], &input).expect("runs");
    assert_eq!(
        (done.code, done.stdout, done.stderr),
        (3, input, b"err\r\n".to_vec())
    );
}

/// A checked call that exits nonzero is `` `git STEP` exited CODE `` with its error output kept; a call a
/// signal ends returns the negated signal; a Git that cannot start fails the call.
#[test]
fn failures_of_the_call() {
    let repository = Repository::new();
    let env = recorder(&repository);
    let failed = git::text(&env, &repository.top, &[OsStr::new("lines")])
        .expect("runs")
        .checked();
    let Err(CallError::Failed { step, code, stderr }) = &failed else {
        panic!("{failed:?} fails");
    };
    assert_eq!(
        (step.to_string(), *code, stderr.to_string()),
        ("lines".to_owned(), 3, "err\n\n".to_owned())
    );
    assert_eq!(
        failed.expect_err("fails").to_string(),
        "`git lines` exited 3"
    );
    let ended = git::text(&env, &repository.top, &[OsStr::new("term")]).expect("runs");
    assert_eq!(ended.code, -libc::SIGTERM);
    let mut none = repository.env();
    set(&mut none, "PATH", repository.bin.clone().into_os_string());
    let start = git::text(&none, &repository.top, &[OsStr::new("status")]).expect_err("no git");
    assert!(matches!(start, CallError::Start(_)), "{start:?}");
    assert_eq!(
        start.to_string(),
        "git cannot be started: No such file or directory (os error 2)"
    );
}

/// Output that is no UTF-8, on either stream, fails a text call with its step; a bytes call returns the
/// bytes.
#[test]
fn text_output_must_be_utf8() {
    let repository = Repository::new();
    let dir = repository.scratch.join("odd");
    private_dir(&dir);
    executable(&dir.join("git"), "#!/bin/sh\nprintf '\\377'\n");
    let mut env = repository.env();
    set(&mut env, "PATH", dir.into_os_string());
    let error = git::text(&env, &repository.top, &[OsStr::new("rev-parse")]).expect_err("fails");
    assert_eq!(
        error.to_string(),
        "`git rev-parse` wrote output that is no UTF-8"
    );
    let done = git::bytes(&env, &repository.top, &[OsStr::new("x")], b"").expect("runs");
    assert_eq!(done.stdout, b"\xff");
    let dir = repository.scratch.join("odd-error");
    private_dir(&dir);
    executable(&dir.join("git"), "#!/bin/sh\nprintf '\\377' >&2\n");
    set(&mut env, "PATH", dir.into_os_string());
    let error = git::text(&env, &repository.top, &[OsStr::new("status")]).expect_err("fails");
    assert_eq!(
        error.to_string(),
        "`git status` wrote output that is no UTF-8"
    );
}

/// The repository's hooks run for the host's Git and never for the call, which a commit through it
/// shows.
#[test]
fn the_call_runs_no_hook() {
    let repository = Repository::new();
    let mut env = repository.env();
    for (name, value) in [("GIT_AUTHOR_NAME", "a"), ("GIT_COMMITTER_NAME", "c")] {
        set(&mut env, name, value.into());
    }
    let args = [
        "commit",
        "--allow-empty",
        "--quiet",
        "-m",
        "through the call",
    ]
    .map(OsStr::new);
    let done = git::text(&env, &repository.top, &args)
        .expect("runs")
        .checked()
        .expect("commits");
    assert_eq!(done.code, 0);
    assert_eq!(repository.hooks_ran(), "");
    repository.hooked_git(&["commit", "--allow-empty", "--quiet", "-m", "with hooks"]);
    assert!(
        repository.hooks_ran().contains("pre-commit"),
        "{}",
        repository.hooks_ran()
    );
}
