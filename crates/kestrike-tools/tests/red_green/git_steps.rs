//! A Git step that builds a leg tree and fails after the checks is refused by the step's own words.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use super::support::{Call, Fixture, HOOKLESS, at, keys};

/// A failed worktree step of either leg and a failed overlay are each refused as `git` and the step's
/// arguments, a carried name outside UTF-8 shown escaped, with the receipt of the legs that ran.
#[test]
fn a_git_step_that_fails_after_validation_is_refused_by_name() {
    let fx = Fixture::new();
    for (pattern, legs, carry, prefix) in [
        (
            format!("\"{HOOKLESS}worktree add --quiet --detach \"*/base\" \"*"),
            &[][..],
            &[&b"table_tests.rs"[..]][..],
            "git worktree add --quiet --detach ",
        ),
        (
            format!("\"{HOOKLESS}worktree add --quiet --detach \"*/head\" \"*"),
            &["base"][..],
            &[&b"table_tests.rs"[..]][..],
            "git worktree add --quiet --detach ",
        ),
        (
            format!("\"{HOOKLESS}--literal-pathspecs checkout \"*"),
            &[][..],
            &[&b"table_tests.rs"[..], b"\xff.rs"][..],
            "git --literal-pathspecs checkout ",
        ),
    ] {
        fx.clear_builds();
        let env = fx.git_wrapper(&format!(
            "case \"$*\" in {pattern}) echo \"fatal: refused\" >&2; exit 128;;\nesac\nexec GIT \"$@\"\n"
        ));
        let done = fx.red_green(&Call {
            carry: carry
                .iter()
                .map(|name| OsStr::from_bytes(name).to_os_string())
                .collect(),
            env: Some(env),
            ..Call::default()
        });
        assert_eq!(done.code, 1, "{pattern}: {}", done.shown());
        let line = done.line();
        assert!(
            line.starts_with(&format!("red-green refused: {prefix}")),
            "{line}"
        );
        if carry.len() == 2 {
            assert!(line.contains("\\udcff.rs"), "{line}");
        }
        let (_, receipt) = fx.receipt(&done);
        assert_eq!(keys(at(&receipt, "legs")), legs, "{pattern}");
        assert_eq!(fx.build_legs(), legs, "{pattern}");
        fx.assert_checkout_unchanged();
    }
}
