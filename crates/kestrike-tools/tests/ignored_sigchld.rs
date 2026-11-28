//! `mutants-diff` and `plant-runner`, the tools that call the library's SIGCHLD refusal, refuse a start
//! with SIGCHLD ignored after their argument reading and before their first child: the kernel would reap
//! each child as it ends and every wait would fail. Each tool runs in a window that
//! `env --ignore-signal=CHLD` starts, since a shell between the two can reset the disposition.
#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use kestrike_tools::temp_dir::make_temp_dir;

const BINARY: &str = env!("CARGO_BIN_EXE_kestrike-tools");
const IGNORED: &str = "--ignore-signal=CHLD";
const DEFAULT: &str = "--default-signal=CHLD";

/// `in_window` runs `program` with `args` under `env` with `disposition` (`--ignore-signal=CHLD` or
/// `--default-signal=CHLD`), the Git variables of the test's environment removed and `first` put
/// before the test's `PATH`.
fn in_window(disposition: &str, first: &Path, program: &str, args: &[&str]) -> Output {
    let mut path = first.as_os_str().to_owned();
    if let Some(rest) = std::env::var_os("PATH") {
        path.push(":");
        path.push(rest);
    }
    let env: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(name, _)| !name.as_bytes().starts_with(b"GIT_") && name != "PATH")
        .chain([(OsString::from("PATH"), path)])
        .collect();
    Command::new("env")
        .arg(disposition)
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
    let scratch = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let stand_in = make_temp_dir("ignored-sigchld-", scratch).expect("the scratch is made");
    let marker = stand_in.join("marker");
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut git = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(stand_in.join("git"))
            .expect("the stand-in is made");
        let script = format!("#!/bin/sh\necho \"$0\" >> '{}'\nexit 1\n", marker.display());
        std::io::Write::write_all(&mut git, script.as_bytes()).expect("the stand-in is written");
    }
    let status = in_window(IGNORED, &stand_in, "cat", &["/proc/self/status"]);
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
        let help = in_window(IGNORED, &stand_in, BINARY, &[top, tool, "--help"]);
        assert_eq!(help.status.code(), Some(0), "{tool} --help");
        assert!(help.stderr.is_empty(), "{tool} --help");
        assert!(
            String::from_utf8_lossy(&help.stdout).contains("usage"),
            "{tool} --help prints its usage"
        );
        let _ = std::fs::remove_file(&marker);
        let control = in_window(DEFAULT, &stand_in, BINARY, &[top, tool]);
        assert!(
            marker.exists(),
            "{tool} reaches the stand-in with SIGCHLD at its default: {control:?}"
        );
        std::fs::remove_file(&marker).expect("the marker is removed");
        let out = in_window(IGNORED, &stand_in, BINARY, &[top, tool]);
        assert!(
            !marker.exists(),
            "{tool} starts no Git with SIGCHLD ignored"
        );
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
    std::fs::remove_dir_all(&stand_in).expect("the scratch is removed");
}
