//! A tool that starts children through the library refuses a start with SIGCHLD ignored, before its first
//! child: the kernel would reap each child as it ends and every wait would fail. Each tool runs in a
//! window that `env --ignore-signal=CHLD` starts, since a shell between the two can reset the disposition.
#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const BINARY: &str = env!("CARGO_BIN_EXE_kestrike-tools");

/// `in_window` runs `program` with `args` with SIGCHLD ignored and the Git variables of the test's
/// environment removed.
fn in_window(program: &str, args: &[&str]) -> Output {
    let env: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(name, _)| !name.as_bytes().starts_with(b"GIT_"))
        .collect();
    Command::new("env")
        .arg("--ignore-signal=CHLD")
        .arg(program)
        .args(args)
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .output()
        .expect("the window starts")
}

#[test]
fn a_tool_started_with_sigchld_ignored_refuses_before_its_first_child() {
    let status = in_window("cat", &["/proc/self/status"]);
    let status = String::from_utf8_lossy(&status.stdout);
    let ignored = status
        .lines()
        .find_map(|line| line.strip_prefix("SigIgn:"))
        .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
        .expect("a SigIgn line");
    assert_ne!(
        ignored & (1 << (libc::SIGCHLD - 1)),
        0,
        "the window starts with SIGCHLD ignored"
    );
    let top = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let top = top.to_str().expect("the top level is UTF-8");
    for (tool, code, line) in [
        (
            "mutants-diff",
            2,
            "mutants rejected: SIGCHLD is ignored, so the child's exit cannot be read\n",
        ),
        (
            "plant-runner",
            4,
            "plant-runner: SIGCHLD is ignored, so the child's exit cannot be read\n",
        ),
    ] {
        let out = in_window(BINARY, &[top, tool]);
        assert_eq!(
            (
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).into_owned()
            ),
            (Some(code), line.to_owned()),
            "{tool}"
        );
        assert!(out.stdout.is_empty(), "{tool}");
    }
}
