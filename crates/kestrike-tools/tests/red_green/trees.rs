//! The leg trees: a tree that differs from its commit is refused, a carried path replaces a base
//! directory or file as Git's overlay does, and carried paths match literally.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;

use kestrike_tools::text::Text;

use super::support::{Fixture, at, executable, keys, members, private_dir, text, tree_keys, write};

/// A smudge filter that changes one leg's tree in one way, a rewritten, ignored, untracked or missing
/// file, an empty or unlistable directory, refuses that leg by the first differing path before it runs;
/// a filter that changes nothing lets the run prove.
#[test]
fn a_leg_whose_tree_differs_from_its_commit_is_refused() {
    let fx = Fixture::new();
    let (mode, script) = (fx.state.join("filter-mode"), fx.state.join("filter.sh"));
    executable(
        &script,
        &format!(
            "#!/bin/sh\ncase \"$(cat \"{}\"):$PWD\" in\n    rewrite:*/base) sed s/unfixed/rewritten/;;\n    \
             ignored:*/base) cat; mkdir -p target; echo planted > target/planted;;\n    \
             untracked:*/base) cat; echo planted > extra.rs;;\n    \
             directory:*/base) cat; mkdir -p sub/empty;;\n    \
             sealed:*/base) cat; mkdir -p sealed; chmod 000 sealed;;\n    \
             missing:*/base) cat; rm -f Cargo.toml;;\n    \
             head:*/head) sed s/fixed/rewritten/;;\n    *) cat;;\nesac\n",
            mode.display()
        ),
    );
    fx.git(&["config", "filter.mark.smudge", &script.to_string_lossy()]);
    write(
        &fx.repo.join(".git/info/attributes"),
        "table.rs filter=mark\n",
    );
    for (name, leg, path) in [
        ("rewrite", Some("base"), "table.rs"),
        ("ignored", Some("base"), "target/planted"),
        ("untracked", Some("base"), "extra.rs"),
        ("directory", Some("base"), "sub/empty"),
        ("sealed", Some("base"), "sealed"),
        ("missing", Some("base"), "Cargo.toml"),
        ("head", Some("head"), "table.rs"),
        ("none", None, ""),
    ] {
        write(&mode, name);
        fx.clear_builds();
        let done = fx.run(|_| {});
        let Some(leg) = leg else {
            assert_eq!(done.code, 0, "{name}: {}", done.shown());
            continue;
        };
        assert_eq!(done.code, 1, "{name}: {}", done.shown());
        let line = done.line();
        assert!(
            line.starts_with(&format!(
                "red-green refused: the {leg} leg's tree differs from its commit at '{path}'"
            )),
            "{name}: {line}"
        );
        let (_, receipt) = fx.receipt(&done);
        let legs: &[&str] = if leg == "head" { &["base"] } else { &[] };
        assert_eq!(keys(at(&receipt, "legs")), legs, "{name}");
        assert_eq!(fx.build_legs(), legs, "{name}");
        fx.assert_checkout_unchanged();
    }
}

/// A carried file that replaces a base directory, and a carried file below a path the base holds as a
/// file, lay the head's files over the base as `git checkout` does: the base's entries at those paths
/// leave the base leg's tree.
#[test]
fn a_carried_path_that_replaces_a_base_directory_or_file_is_overlaid_as_git_does() {
    let fx = Fixture::new();
    private_dir(&fx.repo.join("conf"));
    let base = fx.commit(&[
        (b"conf/inner.rs", "a directory on the base\n"),
        (b"flat", "a file on the base\n"),
    ]);
    fx.git(&["rm", "-q", "-r", "conf", "flat"]);
    private_dir(&fx.repo.join("flat"));
    let head = fx.commit(&[
        (b"conf", "a file on the head\n"),
        (b"flat/inner.rs", "a directory on the head\n"),
        (b"notes.txt", "a later head file\n"),
    ]);
    fx.plan(r#"{"base": {"attempt": "fail"}}"#);
    let done = fx.run(|call| {
        call.base = Some(base.clone());
        call.head = Some(head.clone());
        call.carry = vec!["conf".into(), "flat/inner.rs".into()];
    });
    assert_eq!(done.code, 0, "{}", done.shown());
    let tree = members(&fx.tree_of("base"));
    let found: Vec<Option<&str>> = ["conf", "flat/inner.rs", "conf/inner.rs", "flat"]
        .iter()
        .map(|path| tree.get(*path).map(String::as_str))
        .collect();
    assert_eq!(
        found,
        [
            Some("a file on the head\n"),
            Some("a directory on the head\n"),
            None,
            None
        ]
    );
    fx.assert_checkout_unchanged();
}

/// Carried paths match literally whatever pathspec mode the caller sets, names with glob characters, a
/// byte outside UTF-8 and a carriage return included; a replace object stands in for no commit; and
/// the cleanup removes the run's worktrees alone, leaving the registration of another whose directory
/// is gone.
#[test]
fn carried_paths_match_literally_and_cleanup_keeps_unrelated_worktrees() {
    let fx = Fixture::new();
    let other = fx.root.join("other");
    fx.git(&[
        "worktree",
        "add",
        "--quiet",
        "--detach",
        &other.to_string_lossy(),
        &fx.base,
    ]);
    fs::remove_dir_all(&other).expect("the other worktree's directory goes");
    let tree = fx.git(&[
        "commit-tree",
        &format!("{}^{{tree}}", fx.head),
        "-m",
        "replacement",
    ]);
    fx.git(&["replace", &fx.base, &tree]);
    let names: [&[u8]; 4] = [b"table_tests.rs", b"t[a-z].rs", b"\xff.rs", b"cr\r.rs"];
    let done = fx.run(|call| {
        call.carry = names
            .iter()
            .map(|name| OsStr::from_bytes(name).to_os_string())
            .collect();
        call.env = Some(fx.with_env(&[("GIT_GLOB_PATHSPECS", OsStr::new("1"))]));
    });
    assert_eq!(done.code, 0, "{}", done.shown());
    let base_tree = fx.tree_of("base");
    let mut expected: Vec<Text> = [
        &b".gitignore"[..],
        b"Cargo.toml",
        b"t[a-z].rs",
        b"table.rs",
        b"table_tests.rs",
        b"\xff.rs",
        b"cr\r.rs",
    ]
    .iter()
    .map(|name| Text::from_os(OsStr::from_bytes(name)))
    .collect();
    expected.sort();
    assert_eq!(tree_keys(&base_tree), expected);
    assert_eq!(text(at(&base_tree, "table.rs")), "unfixed\n");
    assert!(
        fx.repo.join(".git/worktrees/other").is_dir(),
        "cleanup removed an unrelated worktree"
    );
}
