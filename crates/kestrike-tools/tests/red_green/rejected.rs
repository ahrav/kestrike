//! Rejected input: each check that ends a run with exit 2 before any worktree or build, the checks of
//! the temporary directory's toolchain configuration, and a directory whose links loop.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::Path;

use kestrike_tools::ownership::foreign_toolchain_paths_for;
use kestrike_tools::red_green::run::resolved_by;

use super::support::{Call, Fixture, UID, chmod, private_dir, words};

fn me() -> u32 {
    // SAFETY: `getuid` takes no argument and always succeeds.
    unsafe { libc::getuid() }
}

/// `rejects` runs `call` and asserts a rejection whose line holds one of `reasons`, with nothing on
/// standard output, no escape byte on standard error, no build, no `target/` and the checkout as it was.
fn rejects(fx: &Fixture, name: &str, call: &Call, reasons: &[&str]) {
    let done = fx.red_green(call);
    assert_eq!(done.code, 2, "{name}: {}", done.shown());
    assert!(
        done.stderr.contains("red-green rejected: "),
        "{name}: {}",
        done.shown()
    );
    assert!(
        reasons.iter().any(|reason| done.stderr.contains(reason)),
        "{name}: {}",
        done.shown()
    );
    assert_eq!(done.stdout, "", "{name}");
    assert!(!done.stderr.contains('\u{1b}'), "{name}");
    assert!(fx.builds().is_empty(), "{name}");
    assert!(!fx.repo.join("target").exists(), "{name}");
    fx.assert_checkout_unchanged();
}

/// Each rejected input ends the run with exit 2 before any worktree or build: an unknown revision; a
/// carried path the head holds as no regular file; a head that changes only carried paths, a swap of a
/// directory and a file at a carried path included; an empty, blank or test-ID `--expect`; a watchdog
/// out of its range; a base that is the head or not its ancestor; a receipt or build directory whose
/// links loop; an invoking directory outside a checkout; each set Git variable that points the legs at
/// another repository; a receipt directory that the announcement cannot name; an option with no value;
/// a temporary directory or build directory below one another user can write; a build directory another
/// user owns; and a default base with no merge base.
#[test]
fn rejected_input_starts_no_worktree_and_no_build() {
    let mut fx = Fixture::new();
    symlink("table_tests.rs", fx.repo.join("link.rs")).expect("the link is made");
    fx.git(&["add", "link.rs"]);
    fx.git(&["commit", "-q", "-m", "link"]);
    let linked = fx.git(&["rev-parse", "HEAD"]);
    let carried_only = fx.commit(&[(b"table_tests.rs", "#[test] again\n")]);
    fx.git(&["commit", "-q", "--allow-empty", "-m", "empty"]);
    let empty = fx.git(&["rev-parse", "HEAD"]);
    private_dir(&fx.repo.join("conf"));
    let swap_base = fx.commit(&[
        (b"conf/inner.rs", "a directory on the base\n"),
        (b"flat", "a file on the base\n"),
    ]);
    fx.git(&["rm", "-q", "-r", "conf"]);
    let file_for_directory = fx.commit(&[(b"conf", "a file on the head\n")]);
    fx.git(&["rm", "-q", "flat"]);
    private_dir(&fx.repo.join("flat"));
    let directory_for_file = fx.commit(&[(b"flat/inner.rs", "a directory on the head\n")]);
    fx.status = fx.git(&["status", "--porcelain"]);
    let root = fx.root.clone();
    let lp = root.join("loop");
    symlink(&lp, &lp).expect("the loop is made");
    let outside = root.join("outside");
    private_dir(&outside);
    let (shared, grouped) = (root.join("shared"), root.join("grouped"));
    for directory in [&shared, &shared.join("mine"), &grouped] {
        private_dir(directory);
    }
    chmod(&shared, 0o1707);
    chmod(&grouped, 0o770);
    let erasing = root.join("e\u{1b}[2Kx");
    private_dir(&erasing);
    chmod(&erasing, 0o770);
    let built = root.join("private/red-green");
    fs::create_dir_all(&built).expect("the build directory is made");
    chmod(&built, 0o775);
    let owned = root.join("owned");
    private_dir(&owned);
    let path = |path: &Path| path.as_os_str().to_os_string();
    let env = |vars: &[(&str, &OsStr)]| Some(fx.with_env(vars));
    let s = |text: &str| Some(text.to_owned());
    let other = (me() + 1).to_string();
    let mut cases: Vec<(String, Call, Vec<String>)> = Vec::new();
    let mut case = |name: &str, edit: &dyn Fn(&mut Call), reasons: &[&str]| {
        let mut call = Call::default();
        edit(&mut call);
        cases.push((
            name.to_owned(),
            call,
            reasons.iter().map(|r| (*r).to_owned()).collect(),
        ));
    };
    case(
        "revision",
        &|c| c.base = s("no-such-revision"),
        &["names no commit"],
    );
    case(
        "carry",
        &|c| c.carry = words(&["table_tests.rs", "missing.rs"]),
        &["holds no regular file 'missing.rs'"],
    );
    case(
        "directory",
        &|c| c.carry = words(&["."]),
        &["holds no regular file '.'"],
    );
    case(
        "subdirectory",
        &|c| c.carry = words(&["sub"]),
        &["holds no regular file 'sub'"],
    );
    case(
        "symlink",
        &|c| {
            c.head = Some(linked.clone());
            c.carry = words(&["table_tests.rs", "link.rs"]);
        },
        &["holds no regular file 'link.rs'"],
    );
    case(
        "carried-only",
        &|c| {
            c.base = Some(linked.clone());
            c.head = Some(carried_only.clone());
        },
        &["changes only carried paths"],
    );
    case(
        "empty-head",
        &|c| {
            c.base = Some(carried_only.clone());
            c.head = Some(empty.clone());
        },
        &["changes only carried paths"],
    );
    case(
        "file-for-directory",
        &|c| {
            c.base = Some(swap_base.clone());
            c.head = Some(file_for_directory.clone());
            c.carry = words(&["conf"]);
        },
        &["changes only carried paths"],
    );
    case(
        "directory-for-file",
        &|c| {
            c.base = Some(file_for_directory.clone());
            c.head = Some(directory_for_file.clone());
            c.carry = words(&["flat/inner.rs"]);
        },
        &["changes only carried paths"],
    );
    case(
        "empty",
        &|c| c.expect = String::new(),
        &["--expect is empty"],
    );
    case(
        "blank",
        &|c| c.expect = " \t ".to_owned(),
        &["--expect is empty"],
    );
    case(
        "test-id",
        &|c| c.expect = "table_tests::a_poll".to_owned(),
        &["is part of the test ID"],
    );
    case(
        "watchdog-zero",
        &|c| c.watchdog = "0".to_owned(),
        &["--watchdog must be a positive number"],
    );
    case(
        "watchdog-huge",
        &|c| c.watchdog = "1e10".to_owned(),
        &["--watchdog must be a positive number"],
    );
    case(
        "same",
        &|c| c.base = Some(fx.head.clone()),
        &["is not an ancestor"],
    );
    case(
        "swapped",
        &|c| {
            c.base = Some(fx.head.clone());
            c.head = Some(fx.base.clone());
            c.carry = words(&["table.rs"]);
        },
        &["is not an ancestor"],
    );
    case(
        "artifacts",
        &|c| c.extra = vec!["--artifacts".into(), path(&lp.join("receipts"))],
        &["cannot be resolved"],
    );
    case(
        "outside",
        &|c| c.cwd = Some(outside.clone()),
        &["not in a Git checkout"],
    );
    for (name, value) in [
        ("GIT_DIR", fx.repo.join(".git")),
        ("GIT_WORK_TREE", fx.repo.clone()),
        ("GIT_INDEX_FILE", fx.repo.join(".git/index")),
        ("GIT_COMMON_DIR", fx.repo.join(".git")),
        ("GIT_OBJECT_DIRECTORY", fx.repo.join(".git/objects")),
    ] {
        let reason = format!("{name} would point the leg worktrees");
        case(
            name,
            &|c| c.env = env(&[(name, value.as_os_str())]),
            &[&reason],
        );
    }
    case(
        "target-loop",
        &|c| c.env = env(&[("CARGO_TARGET_DIR", lp.as_os_str())]),
        &["cannot be resolved"],
    );
    let mut byte = root.clone().into_os_string();
    byte.push(OsStr::from_bytes(b"/\xffreceipts"));
    case(
        "artifacts-byte",
        &|c| c.extra = vec!["--artifacts".into(), byte.clone()],
        &["cannot appear"],
    );
    case(
        "artifacts-newline",
        &|c| c.extra = vec!["--artifacts".into(), path(&root.join("a\nb"))],
        &["cannot appear"],
    );
    case(
        "carry-only-dashes",
        &|c| {
            c.carry = Vec::new();
            c.extra = words(&["--carry=--"]);
        },
        &["names no path", "holds no regular"],
    );
    case(
        "carry-then-dashes",
        &|c| c.extra = words(&["--carry=--"]),
        &["names no path", "holds no regular"],
    );
    case(
        "expect-dashes",
        &|c| c.extra = words(&["--expect=--"]),
        &["has no value", "is part of the test ID"],
    );
    let reason = format!("can write {}, and so can configure", shared.display());
    case(
        "temp-below-all-writable",
        &|c| c.env = env(&[("TMPDIR", shared.join("mine").as_os_str())]),
        &[&reason],
    );
    let reason = format!("can write {}, and so can configure", grouped.display());
    case(
        "temp-group-writable",
        &|c| c.env = env(&[("TMPDIR", grouped.as_os_str())]),
        &[&reason],
    );
    case(
        "temp-control-characters",
        &|c| c.env = env(&[("TMPDIR", erasing.as_os_str())]),
        &["e\\x1b[2Kx, and so can"],
    );
    case(
        "package-empty",
        &|c| c.package = String::new(),
        &["an option has no value"],
    );
    case(
        "cargo-empty",
        &|c| c.extra = words(&["--cargo="]),
        &["an option has no value"],
    );
    case(
        "artifacts-empty",
        &|c| c.extra = words(&["--artifacts="]),
        &["an option has no value"],
    );
    let reason = format!("can write {}, and so can replace", shared.display());
    case(
        "build-below-all-writable",
        &|c| c.env = env(&[("CARGO_TARGET_DIR", shared.join("mine").as_os_str())]),
        &[&reason],
    );
    let reason = format!("can write {}, and so can replace", grouped.display());
    case(
        "build-group-writable",
        &|c| c.env = env(&[("CARGO_TARGET_DIR", grouped.as_os_str())]),
        &[&reason],
    );
    let reason = format!("can write {}, and so can replace", built.display());
    case(
        "build-directory-writable",
        &|c| {
            c.env = env(&[(
                "CARGO_TARGET_DIR",
                built.parent().expect("a parent").as_os_str(),
            )])
        },
        &[&reason],
    );
    let reason = format!("can write {}, {}, ", owned.display(), root.display());
    case(
        "build-directory-owned",
        &|c| {
            c.env = env(&[
                ("CARGO_TARGET_DIR", owned.as_os_str()),
                ("TMPDIR", OsStr::new("/")),
                (UID, OsStr::new(&other)),
            ])
        },
        &[&reason],
    );
    case(
        "no-merge-base",
        &|c| c.base = s(""),
        &["has no merge base with origin/main"],
    );
    for (name, call, reasons) in &cases {
        if name == "no-merge-base" {
            let tree = fx.git_os(&words(&["mktree"]), Some(""));
            let orphan = fx.git(&["commit-tree", &tree, "-m", "orphan"]);
            fx.git(&["update-ref", "refs/remotes/origin/main", &orphan]);
        }
        let reasons: Vec<&str> = reasons.iter().map(String::as_str).collect();
        rejects(&fx, name, call, &reasons);
    }
    // The control: the default call, from which each row differs in one input, builds both legs.
    fx.git(&["update-ref", "refs/remotes/origin/main", &fx.base]);
    let done = fx.red_green(&Call::default());
    assert_eq!(done.code, 0, "{}", done.shown());
    assert_eq!(fx.build_legs(), ["base", "head"]);
    assert!(fx.repo.join("target").exists());
}

/// `found` is `foreign_toolchain_paths_for(tmp, uid)` as texts.
fn found(tmp: &Path, uid: u32) -> Vec<String> {
    foreign_toolchain_paths_for(tmp, uid)
        .expect("the lineage reads")
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect()
}

/// A `.cargo` above the temporary directory that another user owns is reported, and so is the
/// temporary directory itself, which root alone would not have been; `/` stays trusted. A run whose
/// checks judge by another user ID is rejected by that entry before the runner is copied anywhere.
#[test]
fn toolchain_configuration_another_user_owns_or_can_add_above_the_temporary_directory_is_rejected()
{
    let fx = Fixture::new();
    private_dir(&fx.root.join(".cargo"));
    assert_eq!(found(&fx.tmp, me()), Vec::<String>::new());
    let other = me() + 1;
    let reported = found(&fx.tmp, other);
    let cargo = fx.root.join(".cargo").to_string_lossy().into_owned();
    assert!(reported.contains(&cargo), "{reported:?}");
    assert_eq!(
        reported.contains(&fx.tmp.to_string_lossy().into_owned()),
        me() != 0
    );
    assert!(!reported.contains(&"/".to_owned()));
    let uid = other.to_string();
    let done = fx.red_green(&Call {
        env: Some(fx.with_env(&[(UID, OsStr::new(&uid))])),
        ..Call::default()
    });
    assert_eq!(
        (done.code, done.stdout.as_str()),
        (2, ""),
        "{}",
        done.shown()
    );
    assert!(done.stderr.contains(&cargo), "{}", done.stderr);
    assert!(
        done.stderr
            .contains("can configure Cargo or rustup in the leg worktrees")
    );
    assert!(fx.builds().is_empty());
    fx.assert_checkout_unchanged();
    // The control: the same run judged by the fixture's own user ID builds both legs.
    let done = fx.red_green(&Call::default());
    assert_eq!(done.code, 0, "{}", done.shown());
    assert_eq!(fx.build_legs(), ["base", "head"]);
}

/// Toolchain configuration another user can write above the temporary directory is reported: a
/// `.cargo` or a configuration file writable by its group or all users, a link whose target is absent,
/// a link to a target another user can write, and a link that resolves through a directory another
/// user can write, directly or through a link met on the way. A run is rejected by such an entry.
#[test]
fn toolchain_configuration_another_user_can_write_above_the_temporary_directory_is_rejected() {
    let fx = Fixture::new();
    let (entry, shared) = (fx.root.join(".cargo"), fx.root.join("shared"));
    private_dir(&entry);
    private_dir(&shared);
    let me = me();
    let shown = |path: &Path| vec![path.to_string_lossy().into_owned()];
    let none = Vec::<String>::new();
    assert_eq!(found(&fx.tmp, me), none);
    for mode in [0o775, 0o757] {
        chmod(&entry, mode);
        assert_eq!(found(&fx.tmp, me), shown(&entry), "{mode:o}");
    }
    chmod(&entry, 0o755);
    for name in ["config.toml", "config"] {
        let (config, target) = (entry.join(name), shared.join(name));
        fs::write(&config, "").expect("written");
        chmod(&config, 0o644);
        assert_eq!(found(&fx.tmp, me), none, "{name}");
        for mode in [0o664, 0o646] {
            chmod(&config, mode);
            assert_eq!(found(&fx.tmp, me), shown(&config), "{name} {mode:o}");
        }
        fs::remove_file(&config).expect("removed");
        symlink(&target, &config).expect("linked");
        assert_eq!(found(&fx.tmp, me), shown(&config), "{name}");
        fs::write(&target, "").expect("written");
        chmod(&target, 0o644);
        assert_eq!(found(&fx.tmp, me), none, "{name}");
        chmod(&target, 0o666);
        assert_eq!(found(&fx.tmp, me), shown(&config), "{name}");
        fs::remove_file(&config).expect("removed");
        fs::remove_file(&target).expect("removed");
    }
    fs::remove_dir(&entry).expect("removed");
    symlink(&shared, &entry).expect("linked");
    assert_eq!(found(&fx.tmp, me), none);
    let inner = fx.root.join("open/inner");
    fs::create_dir_all(&inner).expect("made");
    fs::remove_file(&entry).expect("removed");
    symlink(&inner, &entry).expect("linked");
    assert_eq!(found(&fx.tmp, me), none);
    chmod(inner.parent().expect("a parent"), 0o777);
    assert_eq!(found(&fx.tmp, me), shown(&entry));
    chmod(inner.parent().expect("a parent"), 0o755);
    let hop = fx.root.join("hop");
    private_dir(&hop);
    symlink(&inner, hop.join("middle")).expect("linked");
    fs::remove_file(&entry).expect("removed");
    symlink(hop.join("middle"), &entry).expect("linked");
    assert_eq!(found(&fx.tmp, me), none);
    chmod(&hop, 0o777);
    assert_eq!(found(&fx.tmp, me), shown(&entry));
    fs::remove_file(&entry).expect("removed");
    symlink(&shared, &entry).expect("linked");
    chmod(&shared, 0o777);
    assert_eq!(found(&fx.tmp, me), shown(&entry));
    let done = fx.red_green(&Call::default());
    assert_eq!(
        (done.code, done.stdout.as_str()),
        (2, ""),
        "{}",
        done.shown()
    );
    assert!(
        done.stderr.contains(&entry.to_string_lossy().into_owned()),
        "{}",
        done.stderr
    );
    assert!(fx.builds().is_empty());
}

/// A path whose links loop is rejected when the resolution hands it back unresolved: the status read
/// after it meets the loop.
#[test]
fn a_looping_directory_is_rejected_when_resolve_returns_it() {
    let fx = Fixture::new();
    let lp = fx.root.join("loop");
    symlink(&lp, &lp).expect("the loop is made");
    let rejected = resolved_by(&lp.join("receipts"), |path| Ok(path.to_path_buf()))
        .expect_err("the loop is rejected");
    assert!(
        rejected
            .to_string()
            .starts_with("a receipt or build directory cannot be resolved: "),
        "{rejected}"
    );
    let control = resolved_by(&fx.root.join("receipts"), |path| Ok(path.to_path_buf()));
    assert_eq!(control, Ok(fx.root.join("receipts")));
}
