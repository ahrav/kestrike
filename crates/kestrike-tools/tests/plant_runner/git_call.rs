//! The Git call: its argument vector, the environment it is given, input bytes, the exit code, both
//! streams with their line ends, a checked failure, and the hooks it never runs.

use std::ffi::OsStr;
use std::fs;

use kestrike_tools::environ::set;
use kestrike_tools::plants::git::{self, FIXED, GitError};

use super::repository::{Repository, chmod, private_dir, write};

/// `recorder` puts a `git` first on `PATH` that writes each argument on a line of `args`, the value of
/// `PROBE` to `probe`, copies its input to its output, writes `err\r\n` to standard error and exits 3,
/// or ends itself with SIGTERM when its first argument after the fixed options is `term`.
fn recorder(repository: &Repository) -> kestrike_tools::environ::Environ {
    let dir = repository.scratch.join("recorder");
    private_dir(&dir);
    let script = dir.join("git");
    let (args, probe) = (dir.join("args"), dir.join("probe"));
    write(
        &script,
        format!(
            "#!/bin/sh\nfor arg; do printf '%s\\n' \"$arg\"; done > '{}'\nprintf '%s' \"${{PROBE-unset}}\" > '{}'\n\
             for arg; do [ \"$arg\" = term ] && kill -TERM $$; done\ncat\nprintf 'err\\r\\n' >&2\nexit 3\n",
            args.display(),
            probe.display()
        ),
    );
    chmod(&script, 0o755);
    let mut env = repository.env();
    let mut path = dir.into_os_string();
    path.push(":/usr/bin:/bin");
    set(&mut env, "PATH", path);
    env
}

fn recorded(repository: &Repository, file: &str) -> String {
    fs::read_to_string(repository.scratch.join("recorder").join(file)).expect("recorded")
}

/// A text call passes the fixed options, `-C DIR` and its arguments, gives Git exactly the environment
/// it is given, reads `\r\n` and `\r` as `\n` on both streams, and returns the exit code.
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
        recorded(&repository, "args"),
        format!("{}\n", expected.join("\n"))
    );
    assert_eq!(recorded(&repository, "probe"), "passed");
    assert_eq!(
        (done.code, done.stdout.as_str(), done.stderr.as_str()),
        (3, "", "err\n")
    );
    assert_eq!(done.step.to_string(), "status");
    env.retain(|(name, _)| name != "PROBE");
    git::text(&env, &repository.top, &args).expect("the call runs");
    assert_eq!(recorded(&repository, "probe"), "unset");
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
/// signal ends returns the negated signal; output that is no UTF-8 fails a text call; a Git that cannot
/// start fails the call.
#[test]
fn failures_of_the_call() {
    let repository = Repository::new();
    let env = recorder(&repository);
    let failed = git::text(&env, &repository.top, &[OsStr::new("status")])
        .expect("runs")
        .checked();
    let Err(GitError::Failed { step, code, stderr }) = &failed else {
        panic!("{failed:?} fails");
    };
    assert_eq!(
        (step.to_string(), *code, stderr.to_string()),
        ("status".to_owned(), 3, "err\n".to_owned())
    );
    assert_eq!(
        failed.expect_err("fails").to_string(),
        "`git status` exited 3"
    );
    let bytes = git::bytes(&env, &repository.top, &[OsStr::new("apply")], b"")
        .expect("runs")
        .checked()
        .expect_err("fails");
    assert_eq!(bytes.to_string(), "`git apply` exited 3");
    let ended = git::text(&env, &repository.top, &[OsStr::new("term")]).expect("runs");
    assert_eq!(ended.code, -libc::SIGTERM);
    let odd = git::bytes(&env, &repository.top, &[OsStr::new("x")], b"\xff").expect("runs");
    assert_eq!(odd.stdout, b"\xff");
    let mut none = repository.env();
    set(&mut none, "PATH", repository.bin.clone().into_os_string());
    let start = git::text(&none, &repository.top, &[OsStr::new("status")]).expect_err("no git");
    assert!(matches!(start, GitError::Start(_)), "{start:?}");
}

/// Output that is no UTF-8 fails a text call with its step.
#[test]
fn text_output_must_be_utf8() {
    let repository = Repository::new();
    let dir = repository.scratch.join("odd");
    private_dir(&dir);
    write(&dir.join("git"), "#!/bin/sh\nprintf '\\377'\n");
    chmod(&dir.join("git"), 0o755);
    let mut env = repository.env();
    set(&mut env, "PATH", dir.into_os_string());
    let error = git::text(&env, &repository.top, &[OsStr::new("rev-parse")]).expect_err("fails");
    assert_eq!(
        error.to_string(),
        "`git rev-parse` wrote output that is no UTF-8"
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
