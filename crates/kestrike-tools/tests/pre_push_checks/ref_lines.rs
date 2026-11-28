//! The hook's cases of the ref lines and the tree a check reads, started through the tool: the checks read
//! the pushed commit, a deletion and a blank line run nothing, a malformed line and a failed Git read end
//! the push with exit 2, and a path outside ASCII is read whatever the locale.

use std::fs;

use super::push::{BINARY, Fixture, STUB, ZERO, finished, spawn_with_input, top};

fn unnamed(fx: &Fixture, input: &str) -> std::process::Child {
    let mut command = fx.command(BINARY);
    command.arg(top()).args(["pre-push-checks", ""]);
    spawn_with_input(&mut command, input)
}

/// The checks run the pushed commit's scripts, a failure there fails the push though the working tree's
/// copy passes, and the worktree is removed.
#[test]
fn checks_run_on_the_pushed_commit_not_the_working_tree() {
    let fx = Fixture::new();
    let head = fx.commit(&[
        ("scripts/test-inventory.json", r#"{"rows": []}"#),
        ("scripts/verify-receipts.py", "import sys\nsys.exit(4)\n"),
    ]);
    fs::write(fx.repo.join("scripts/verify-receipts.py"), STUB)
        .expect("the working copy is written");
    let run = fx.push(&[(&head, &fx.base)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(
        run.stderr
            .contains("failed: python3 scripts/verify-receipts.py admit"),
        "{}",
        run.stderr
    );
    assert_eq!(fx.worktrees(), 1);
    assert!(fx.left().is_empty(), "{:?}", fx.left());
}

/// A deleted ref runs no check and passes.
#[test]
fn a_deletion_runs_no_check() {
    let fx = Fixture::new();
    let deletion = format!("(delete) {ZERO} refs/heads/gone {}\n", "1".repeat(40));
    let run = finished(unnamed(&fx, &deletion));
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(fx.ran().is_empty());
}

/// A ref line of other than four fields exits 2 and names the line.
#[test]
fn a_malformed_ref_line_fails() {
    let fx = Fixture::new();
    let run = finished(unnamed(&fx, "ref-update\n"));
    assert_eq!(run.code, Some(2), "{}", run.stderr);
    assert_eq!(run.stderr, "pre-push: malformed ref line: 'ref-update'\n");
    assert!(run.stdout.is_empty(), "{}", run.stdout);
    assert!(fx.ran().is_empty());
}

/// An `origin/main` that names a missing object exits 2 with Git's merge-base failure and prints no
/// skipped scan.
#[test]
fn an_unreadable_origin_main_fails_the_push_with_a_git_error() {
    let fx = Fixture::new();
    let head = fx.commit(&[("crates/plain.rs", "edited\n")]);
    fx.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    let reference = fx.repo.join(".git/refs/remotes/origin/main");
    fs::create_dir_all(reference.parent().expect("the ref has a parent"))
        .expect("the directory is made");
    fs::write(&reference, format!("{}\n", "1".repeat(40))).expect("the ref is written");
    let run = fx.push(&[(&head, ZERO)]);
    assert_eq!(run.code, Some(2), "{}", run.stderr);
    assert!(
        run.stderr.contains("pre-push: git merge-base origin/main"),
        "{}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("weakened-test scan skipped"),
        "{}",
        run.stderr
    );
}

/// A source path outside ASCII that the inventory names selects reconciliation under the C locale and
/// under an ISO-8859-1 locale where the host has one installed, since the locale plays no part in what the
/// tool reads.
#[test]
fn a_non_ascii_verus_source_selects_reconciliation_under_a_non_utf8_locale() {
    let mut fx = Fixture::new();
    let source = "crates/caf\u{e9}.rs";
    let base = fx.commit(&[
        (
            "verification/verus/inventory.json",
            &format!("{{\"sources\": {{\"{source}\": \"d\"}}}}"),
        ),
        (source, "v\n"),
    ]);
    let head = fx.commit(&[(source, "edited\n")]);
    let installed = std::process::Command::new("locale")
        .arg("-a")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default();
    let latin = ["en_US.iso88591", "en_US.ISO-8859-1"]
        .into_iter()
        .find(|name| installed.split_whitespace().any(|line| line == *name));
    for locale in std::iter::once("C").chain(latin) {
        fx.clear();
        fx.set("LC_ALL", locale);
        let run = fx.push(&[(&head, &base)]);
        assert_eq!(run.code, Some(0), "{locale}: {}", run.stderr);
        assert_eq!(fx.ran(), ["judge-verus.py reconcile"], "{locale}");
    }
}
