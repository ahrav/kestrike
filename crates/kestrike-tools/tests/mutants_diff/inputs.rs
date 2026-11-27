//! The cases of rejected input: a refusal exits 2, writes no report and starts no build.

use std::ffi::OsStr;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::PathBuf;

use crate::fixture::{self, CONFIG, Fixture, Plan, SOURCE, WORKFLOW, lib_rs, listed, registered};

fn three() -> Vec<(kestrike_tools::text::Text, kestrike_tools::text::Text)> {
    let names: Vec<String> = (0..3)
        .map(|n| format!("{SOURCE}/lib.rs:{n}:1: m"))
        .collect();
    listed(&lib_rs(), &names)
}

#[test]
fn more_mutants_than_the_limit_are_refused_before_any_build() {
    let fx = Fixture::new("limit");
    fx.plan(&Plan::new(&three(), &[]));
    let before = fx.snapshot();
    let out = fx.start().args(["--max-mutants", "2"]).run();
    assert_eq!(out.code, 2, "{}", out.all());
    assert!(
        out.stdout
            .contains("mutants: 3 listed, above --max-mutants 2"),
        "{}",
        out.all()
    );
    assert!(fx.builds().is_empty());
    assert!(fx.reports().is_empty());
    assert_eq!(fx.snapshot(), before);
}

#[test]
fn a_limit_refusal_whose_worktree_remains_exits_2_and_names_the_worktree() {
    let fx = Fixture::new("limit-remains");
    fx.plan(&Plan::new(&three(), &[]));
    let out = fx
        .start()
        .args(["--max-mutants", "2"])
        .env(fx.git_wrapper("fail-remove"))
        .run();
    assert_eq!(out.code, 2, "{}", out.all());
    assert!(
        out.stdout
            .contains("mutants: 3 listed, above --max-mutants 2"),
        "{}",
        out.all()
    );
    assert!(
        out.stderr.contains("mutants rejected: raise --max-mutants"),
        "{}",
        out.all()
    );
    let named = out.stderr.lines().any(|line| {
        line.starts_with("mutants: the worktree ") && line.contains(" remains: fatal: refused")
    });
    assert!(named, "{}", out.all());
    assert!(fx.builds().is_empty());
    assert!(fx.reports().is_empty());
    assert_eq!(registered(&fx), 2);
}

#[test]
fn an_unknown_revision_an_absent_tool_and_another_version_are_refused_before_any_build() {
    let fx = Fixture::new("refused-tool");
    let mutants = listed(&lib_rs(), &[format!("{SOURCE}/lib.rs:1:1: m")]);
    fx.plan(&Plan::new(&mutants, &[]));
    for (head, base) in [
        (Some("no-such-revision"), None),
        (None, Some("no-such-base")),
    ] {
        let mut start = fx.start();
        if let Some(head) = head {
            start = start.head(head);
        }
        if let Some(base) = base {
            start = start.base(base);
        }
        let out = start.run();
        assert_eq!(out.code, 2, "{}", out.all());
        let revision = head.or(base).expect("one revision");
        assert!(
            out.stderr
                .contains(&format!("unknown revision '{revision}'")),
            "{}",
            out.all()
        );
    }
    fx.plan(&Plan {
        absent: true,
        ..Plan::new(&mutants, &[])
    });
    let out = fx.start().run();
    assert_eq!(out.code, 2, "{}", out.all());
    let absent = "cargo mutants --version exited 101 (error: no such command: `mutants`); install the pinned tool: \
                  cargo install --locked --version 27.1.0 cargo-mutants";
    assert!(out.stderr.contains(absent), "{}", out.all());
    fx.plan(&Plan {
        version: Some("26.2.0"),
        ..Plan::new(&mutants, &[])
    });
    let out = fx.start().run();
    assert_eq!(out.code, 2, "{}", out.all());
    let other = "cargo mutants is 26.2.0, the configuration pins 27.1.0; install it: cargo install --locked --version \
                 27.1.0 cargo-mutants";
    assert!(out.stderr.contains(other), "{}", out.all());
    assert!(fx.calls().is_empty());
    assert!(
        !fx.artifacts.exists(),
        "each refusal comes before the run directory"
    );
}

/// `entries` lists every entry under `directory`, recursively.
fn entries(directory: &std::path::Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    if let Ok(read) = fs::read_dir(directory) {
        for entry in read {
            let path = entry.expect("an entry").path();
            if fs::symlink_metadata(&path).is_ok_and(|status| status.is_dir()) {
                found.extend(entries(&path));
            }
            found.push(path);
        }
    }
    found
}

#[test]
fn each_rejected_input_exits_2_without_a_report_or_a_build() {
    let fx = Fixture::new("rejected");
    let mutants = listed(&lib_rs(), &[format!("{SOURCE}/lib.rs:2:1: m")]);
    let config = fx.repo.join(".cargo/mutants.toml");
    let workflow = fx.repo.join(".github/workflows/agent-checks.yml");
    let originals = [
        (
            config.clone(),
            fs::read(&config).expect("the configuration"),
        ),
        (workflow.clone(), fs::read(&workflow).expect("the workflow")),
    ];
    fs::create_dir(&fx.artifacts).expect("the artifacts directory is made");
    let held = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(fx.artifacts.join("build.lock"))
        .expect("the lock opens");
    let [fifo, link, shared, looping] =
        ["fifo", "link", "shared", "loop"].map(|name| fx.state.join(name));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&fifo)
        .expect("the directory is made");
    let lock_name = std::ffi::CString::new(
        fifo.join("build.lock")
            .into_os_string()
            .into_encoded_bytes(),
    )
    .expect("no NUL");
    // SAFETY: `mkfifo` reads the NUL-terminated path, which outlives the call.
    assert_eq!(
        unsafe { libc::mkfifo(lock_name.as_ptr(), 0o600) },
        0,
        "the FIFO is made"
    );
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&link)
        .expect("the directory is made");
    symlink(fx.state.join("absent-lock"), link.join("build.lock")).expect("the link is made");
    fs::create_dir(&shared).expect("the directory is made");
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777))
        .expect("the directory is shared");
    symlink(&shared, fx.state.join("into-shared")).expect("the link is made");
    symlink(&looping, &looping).expect("the loop is made");
    // Cargo searches the worktree's ancestors for `.cargo/config.toml`. Another user can edit a
    // world-writable configuration file or create one in a world-writable `.cargo` directory.
    let (open_file, open_entry) = (fx.state.join("open-file"), fx.state.join("open-entry"));
    for private in [&open_file, &open_entry] {
        fs::create_dir_all(private.join(".cargo")).expect("the directory is made");
    }
    fs::write(
        open_file.join(".cargo/config.toml"),
        "[build]\nrustc-wrapper = \"/nonexistent\"\n",
    )
    .expect("written");
    fs::set_permissions(
        open_file.join(".cargo/config.toml"),
        fs::Permissions::from_mode(0o666),
    )
    .expect("shared");
    fs::set_permissions(open_entry.join(".cargo"), fs::Permissions::from_mode(0o777))
        .expect("shared");
    let pinless = CONFIG.replace("# Tool pin: cargo-mutants 27.1.0\n", "");
    let shown = |path: &std::path::Path| path.display().to_string();
    type Setup<'a> = Option<Box<dyn Fn() + 'a>>;
    type Row<'a> = (
        &'a str,
        Vec<String>,
        Vec<(&'a str, &'a str)>,
        Option<&'static str>,
        Setup<'a>,
        String,
    );
    let write = |path: PathBuf, bytes: Vec<u8>| -> Setup<'_> {
        Some(Box::new(move || fs::write(&path, &bytes).expect("written")))
    };
    let path_arg =
        |flag: &str, path: PathBuf| vec![flag.to_owned(), path.to_str().expect("UTF-8").to_owned()];
    let args = |args: &[&str]| {
        args.iter()
            .map(|arg| (*arg).to_owned())
            .collect::<Vec<String>>()
    };
    let lock_held = || {
        // SAFETY: `flock` takes the descriptor of `held`, which stays open for the case.
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) },
            0,
            "the test holds the lock"
        );
    };
    #[rustfmt::skip]
    let rows: Vec<Row<'_>> = vec![
        ("two pin lines", vec![], vec![], None, write(config.clone(), format!("{CONFIG}# Tool pin: cargo-mutants 27.1.0\n").into_bytes()), "must hold one tool pin line".into()),
        ("no pin line", vec![], vec![], None, write(config.clone(), pinless.clone().into_bytes()), "must hold one tool pin line".into()),
        ("no STABLE pin", vec![], vec![], None, write(workflow.clone(), b"env: {}\n".to_vec()), "one STABLE pin".into()),
        ("two STABLE pins", vec![], vec![], None, write(workflow.clone(), format!("{WORKFLOW}  STABLE: \"1.98.0\"\n").into_bytes()), "one STABLE pin".into()),
        ("an unreadable configuration", vec![], vec![], None, write(config.clone(), [b"\xff".as_slice(), &originals[0].1].concat()),
         "mutants rejected: Utf8Error: invalid utf-8 sequence of 1 bytes from index 0".into()),
        ("a cargo that cannot run", path_arg("--cargo", fx.state.join("absent")), vec![], None, None, "cannot run".into()),
        ("no host", vec![], vec![], Some(""), None, "-vV names no host".into()),
        ("a test-profile assertion variable", vec![], vec![("CARGO_PROFILE_TEST_DEBUG_ASSERTIONS", "true")], None, None, "unset CARGO_PROFILE_TEST_DEBUG_ASSERTIONS".into()),
        ("an overflow-check variable", vec![], vec![("CARGO_PROFILE_DEV_OVERFLOW_CHECKS", "false")], None, None, "unset CARGO_PROFILE_DEV_OVERFLOW_CHECKS".into()),
        ("a tool variable", vec![], vec![("CARGO_MUTANTS_JOBS", "4")], None, None, "unset CARGO_MUTANTS_JOBS".into()),
        ("assertions in RUSTFLAGS", vec![], vec![("RUSTFLAGS", "-C debug-assertions=on")], None, None, "unset RUSTFLAGS".into()),
        ("assertions in encoded flags", vec![], vec![("CARGO_ENCODED_RUSTFLAGS", "-Cdebug-assertions=on")], None, None, "unset CARGO_ENCODED_RUSTFLAGS".into()),
        ("an abbreviated option", args(&["--test", "sim_worker"]), vec![], None, None, "unrecognized arguments".into()),
        ("shard index N", args(&["--shard", "2/2"]), vec![], None, None, "K/N with 0 <= K < N".into()),
        ("a zero limit", args(&["--max-mutants", "0"]), vec![], None, None, "a positive integer".into()),
        ("an empty base", args(&["--base", ""]), vec![], None, None, "argument --base: a value".into()),
        ("an empty artifacts directory", args(&["--artifacts", ""]), vec![], None, None, "argument --artifacts: a value".into()),
        ("a held artifacts directory", vec![], vec![], None, Some(Box::new(lock_held)), "another run holds".into()),
        ("a FIFO lock", path_arg("--artifacts", fifo.clone()), vec![], None, None, "cannot be opened as a lock file".into()),
        ("a linked lock", path_arg("--artifacts", link.clone()), vec![], None, None, "cannot be opened as a lock file".into()),
        ("a shared ancestor", path_arg("--artifacts", shared.join("artifacts")), vec![], None, None, format!("another user owns or can write {}", shown(&shared))),
        ("a link into a shared ancestor", path_arg("--artifacts", fx.state.join("into-shared/artifacts")), vec![], None, None,
         format!("another user owns or can write {}", shown(&shared))),
        ("a Cargo configuration file another user can write", path_arg("--artifacts", open_file.join("artifacts")), vec![], None, None,
         format!("another user owns or can write {}", shown(&open_file.join(".cargo/config.toml")))),
        ("a Cargo configuration directory another user can write", path_arg("--artifacts", open_entry.join("artifacts")), vec![], None, None,
         format!("another user owns or can write {}", shown(&open_entry.join(".cargo")))),
        ("a looping artifacts path", path_arg("--artifacts", looping.join("artifacts")), vec![], None, None, "mutants rejected:".into()),
    ];
    assert_eq!(rows.len(), 25);
    for (label, extra, inherited, host, setup, message) in rows {
        fx.clear();
        let name = mutants[0].1.clone();
        fx.plan(&Plan {
            host,
            ..Plan::new(&mutants, &[(name, "CaughtMutant")])
        });
        if let Some(setup) = &setup {
            setup();
        }
        let pairs: Vec<(&str, &OsStr)> = inherited
            .iter()
            .map(|(name, value)| (*name, OsStr::new(value)))
            .collect();
        let out = fx
            .start()
            .args(&extra)
            .env(fixture::with(&fx.env, &pairs))
            .run();
        for (path, bytes) in &originals {
            fs::write(path, bytes).expect("the original is restored");
        }
        assert_eq!(out.code, 2, "{label}: {}", out.all());
        assert!(out.stderr.contains(&message), "{label}: {}", out.all());
        assert!(!out.stderr.contains("panicked"), "{label}: {}", out.all());
        assert!(fx.calls().is_empty(), "{label}");
        let mut left: Vec<PathBuf> = fx.reports();
        left.extend(entries(&shared));
        left.extend(
            [open_file.join("artifacts"), open_entry.join("artifacts")]
                .into_iter()
                .filter(|path| path.exists()),
        );
        left.extend(
            entries(&fifo)
                .into_iter()
                .chain(entries(&link))
                .filter(|path| fs::symlink_metadata(path).is_ok_and(|status| status.is_dir())),
        );
        assert!(left.is_empty(), "{label}: {left:?}");
    }
    assert!(
        fs::symlink_metadata(fx.state.join("absent-lock")).is_err(),
        "the lock open does not follow a link"
    );
    let env = fixture::with(&fx.env, &[("RUSTFLAGS", OsStr::new("-C opt"))]);
    let out = fx
        .start()
        .artifacts(&fx.state.join("other-artifacts"))
        .env(env)
        .run();
    assert_eq!(
        out.code,
        0,
        "another artifacts directory runs beside the held one, and flags that set no assertion pass: {}",
        out.all()
    );
    assert_eq!(fx.calls()[0].var("RUSTFLAGS"), Some("-C opt"));
}

#[test]
fn an_inherited_repository_override_is_refused_and_leaves_the_index_unchanged() {
    let fx = Fixture::new("overrides");
    fx.write(&lib_rs(), "pub fn staged() {}\n");
    fx.git(&["add", &lib_rs()]);
    fx.write(&lib_rs(), "pub fn unstaged() {}\n");
    fx.plan(&Plan::new(
        &listed(&lib_rs(), &[format!("{SOURCE}/lib.rs:2:1: m")]),
        &[],
    ));
    let before = fx.snapshot();
    let dot_git = fx.repo.join(".git");
    let overrides = [
        ("GIT_DIR", dot_git.clone()),
        ("GIT_WORK_TREE", fx.repo.clone()),
        ("GIT_INDEX_FILE", dot_git.join("index")),
        ("GIT_COMMON_DIR", dot_git.clone()),
        ("GIT_OBJECT_DIRECTORY", dot_git.join("objects")),
    ];
    for (name, value) in overrides {
        let out = fx
            .start()
            .env(fixture::with(&fx.env, &[(name, value.as_os_str())]))
            .run();
        assert_eq!(out.code, 2, "{name}: {}", out.all());
        assert!(
            out.stderr.contains(&format!("unset {name}")),
            "{name}: {}",
            out.all()
        );
        assert_eq!(fx.snapshot(), before, "{name}");
        assert!(fx.calls().is_empty(), "{name}");
        assert!(!fx.artifacts.exists(), "{name}");
    }
}

#[test]
fn malformed_test_arguments_are_refused_and_a_refused_report_directory_is_reported() {
    let fx = Fixture::new("test-arguments");
    let mutants = listed(&lib_rs(), &[format!("{SOURCE}/lib.rs:1:1: m")]);
    fx.plan(&Plan::caught(&mutants));
    for tests in ["--test 'unclosed", ""] {
        let out = fx.start().args(["--tests", tests]).run();
        assert_eq!(out.code, 2, "{tests:?}: {}", out.all());
    }
    assert!(fx.calls().is_empty());
    fs::write(
        fx.state.join("blocked"),
        "a file where the artifacts directory would be\n",
    )
    .expect("written");
    let out = fx
        .start()
        .artifacts(&fx.state.join("blocked/artifacts"))
        .run();
    assert_eq!(out.code, 1, "{}", out.all());
    assert!(
        out.stderr
            .contains("mutants: the report could not be written:"),
        "{}",
        out.all()
    );
    assert_eq!(registered(&fx), 1);
}

#[test]
fn a_live_run_holds_its_artifacts_directory() {
    let fx = Fixture::new("live-lock");
    let names: Vec<String> = (0..2)
        .map(|n| format!("{SOURCE}/lib.rs:2:1: replace two -> u32 with {n}"))
        .collect();
    let mutants = listed(&lib_rs(), &names);
    fx.plan(&Plan {
        hang: true,
        ..Plan::caught(&mutants)
    });
    let mut first = fx.start_until_ready(fx.start(), "ready");
    fx.plan(&Plan::caught(&mutants));
    let builds = fx.builds().len();
    let out = fx.start().run();
    assert_eq!(out.code, 2, "{}", out.all());
    assert!(out.stderr.contains("another run holds"), "{}", out.all());
    assert_eq!((fx.builds().len(), fx.reports().len()), (builds, 0));
    let other = fx.state.join("other-artifacts");
    assert_eq!(
        fx.start().artifacts(&other).run().code,
        0,
        "another directory runs beside it"
    );
    first.signal(libc::SIGTERM);
    first.communicate(fixture::RUN_LIMIT);
    for stale in fx.reports() {
        fs::remove_file(stale).expect("a stale report is removed");
    }
    let out = fx.start().run();
    assert_eq!(
        out.code,
        0,
        "the lock ends with the first run: {}",
        out.all()
    );
}

/// A Git whose successful `rev-parse --verify` or `merge-base` prints the byte 0xff exits 2 with a
/// `Utf8Error` refusal, and no report or build follows.
#[test]
fn revision_output_that_is_not_utf_8_is_refused() {
    let fx = Fixture::new("bad-revision");
    let mutants = listed(&lib_rs(), &[format!("{SOURCE}/lib.rs:1:1: m")]);
    fx.plan(&Plan::new(&mutants, &[]));
    let head = fx.head.clone();
    let artifacts = fx.artifacts.clone();
    let cargo = fx.cargo.clone();
    let rows = [
        (fx.start().env(fx.git_wrapper("bad-rev")), "bad-rev"),
        (
            fx.start()
                .raw()
                .args([OsStr::new("--head"), OsStr::new(&head)])
                .args([OsStr::new("--artifacts"), artifacts.as_os_str()])
                .args([OsStr::new("--cargo"), cargo.as_os_str()])
                .env(fx.git_wrapper("bad-base")),
            "bad-base",
        ),
    ];
    for (start, mode) in rows {
        let out = start.run();
        assert_eq!(out.code, 2, "{mode}: {}", out.all());
        assert!(
            out.stderr.contains(
                "mutants rejected: Utf8Error: invalid utf-8 sequence of 1 bytes from index 0"
            ),
            "{mode}: {}",
            out.all()
        );
        assert!(fx.builds().is_empty(), "{mode}");
        assert!(fx.reports().is_empty(), "{mode}");
    }
}
