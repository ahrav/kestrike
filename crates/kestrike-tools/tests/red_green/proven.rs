//! A proven run: what the receipt binds and what both legs saw.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use kestrike_tools::python::say;
use kestrike_tools::text::Text;

use super::support::{
    Call, EXPECT, Fixture, TEST, at, chmod, executable, json_of, keys, members, private_dir, read,
    root, sha256, split, text, texts, write,
};

/// A red base and a green head are proven: the receipt names both commits, the carried blob, the
/// digests of the runner and its selector and of each leg's artifact and attempt output, and the
/// command that repeats the run; both builds share the build directory and hold the lock with the empty
/// lock file as their standard input, where the command's own holds a line.
#[test]
fn a_red_base_and_a_green_head_are_proven_and_the_receipt_binds_both_legs() {
    let fx = Fixture::new();
    let done = fx.run(|call| {
        call.cargo = Some(String::new());
        call.env = Some(fx.path_env(&fx.state));
        call.input = b"the command's standard input\n".to_vec();
    });
    assert_eq!(done.code, 0, "{}", done.shown());
    assert_eq!(
        done.stdout,
        format!(
            "red-green: {TEST} failed on {} with \"{EXPECT}\" and passed on {}\n",
            &fx.base[..12],
            &fx.head[..12]
        )
    );
    let (path, receipt) = fx.receipt(&done);
    let run = path
        .parent()
        .expect("the receipt stands in its run directory");
    assert_eq!(
        run.parent(),
        Some(fx.repo.join("target/red-green").as_path())
    );
    assert_eq!(
        [
            text(at(&receipt, "base")),
            text(at(&receipt, "head")),
            text(at(&receipt, "result"))
        ],
        [fx.base.clone(), fx.head.clone(), "proven".to_owned()]
    );
    let blob = fx.git(&["rev-parse", &format!("{}:table_tests.rs", fx.head)]);
    assert_eq!(
        json_of(at(&receipt, "carried")),
        format!("[{{\"blob\":\"{blob}\",\"path\":\"table_tests.rs\"}}]")
    );
    let scripts = at(&receipt, "scripts");
    assert_eq!(keys(scripts), ["reproduce-test.py", "select-tests.py"]);
    for name in ["reproduce-test.py", "select-tests.py"] {
        assert_eq!(
            text(at(scripts, name)),
            sha256(&root().join("scripts").join(name))
        );
    }
    for (leg, commit, code, verdict, dirty) in [
        (
            "base",
            &fx.base,
            "1",
            "reproduced: reproduced on attempt 1",
            "true",
        ),
        (
            "head",
            &fx.head,
            "0",
            "not reproduced in 1 attempts",
            "false",
        ),
    ] {
        let entry = at(at(&receipt, "legs"), leg);
        let artifact = PathBuf::from(text(at(entry, "artifact")));
        assert_eq!(
            artifact.parent().and_then(|parent| parent.parent()),
            Some(run)
        );
        assert_eq!(text(at(entry, "sha256")), sha256(&artifact));
        assert_eq!(json_of(at(entry, "exit")), code);
        assert_eq!(text(at(entry, "verdict")), verdict);
        assert!(
            json_of(at(entry, "seconds"))
                .parse::<f64>()
                .expect("seconds")
                > 0.0
        );
        for stream in ["stdout", "stderr"] {
            let output = artifact.with_file_name(format!("attempt-1.{stream}"));
            assert_eq!(
                text(at(at(entry, "attempt_sha256"), stream)),
                sha256(&output)
            );
        }
        let record = kestrike_tools::json::parse(&read(&artifact)).expect("JSON");
        let fields: Vec<String> = [
            "revision",
            "test_id",
            "attempts_requested",
            "watchdog_seconds",
            "release",
            "package",
            "target",
            "dirty",
            "untracked",
        ]
        .iter()
        .map(|name| json_of(at(&record, name)))
        .collect();
        assert_eq!(
            fields,
            [
                format!("\"{commit}\""),
                format!("\"{TEST}\""),
                "1".to_owned(),
                "30.0".to_owned(),
                "false".to_owned(),
                "\"kestrike\"".to_owned(),
                "\"lib\"".to_owned(),
                dirty.to_owned(),
                "[]".to_owned(),
            ]
        );
    }
    assert!(fx.attempt_output(&receipt, "stdout").contains(EXPECT));
    assert_eq!(
        texts(at(at(at(&receipt, "legs"), "base"), "expect_streams")),
        ["stdout"]
    );
    let command = split(&text(at(&receipt, "command")));
    assert_eq!(
        command,
        [
            "bash".to_owned(),
            "scripts/tool.sh".to_owned(),
            "red-green".to_owned(),
            "--package=kestrike".to_owned(),
            "--target=lib".to_owned(),
            format!("--test={TEST}"),
            format!("--expect={EXPECT}"),
            "--carry=table_tests.rs".to_owned(),
            format!("--base={}", fx.base),
            format!("--head={}", fx.head),
            "--watchdog=30.0".to_owned(),
        ]
    );
    assert_eq!(
        members(&fx.tree_of("base")),
        [
            (".gitignore", "/target\n"),
            ("Cargo.toml", "[package]\n"),
            ("table.rs", "unfixed\n"),
            ("table_tests.rs", "#[test]\n"),
        ]
        .map(|(path, content)| (path.to_owned(), content.to_owned()))
        .into_iter()
        .collect()
    );
    let builds = fx.builds();
    assert_eq!(fx.build_legs(), ["base", "head"]);
    let build_dir = fx
        .repo
        .join("target/red-green/build")
        .to_string_lossy()
        .into_owned();
    for build in &builds {
        assert_eq!(
            [
                text(at(build, "target_dir")),
                text(at(build, "build_dir")),
                json_of(at(build, "lock_held"))
            ],
            [build_dir.clone(), build_dir.clone(), "true".to_owned()]
        );
        assert_eq!(text(at(build, "stdin")), "");
    }
    let argv: Vec<Vec<String>> = builds
        .iter()
        .map(|build| texts(at(build, "argv")))
        .collect();
    assert_eq!(argv[0], argv[1]);
    assert_eq!(argv[0][..4], ["test", "-p", "kestrike", "--lib"]);
    fx.assert_checkout_unchanged();
}

/// A post-checkout hook in the checkout runs in no leg worktree: the base, which holds the fix marker
/// that the hook would remove, passes and is refused as such, and the hook's log stays absent.
#[test]
fn a_checkout_hook_never_runs_in_a_leg_worktree() {
    let fx = Fixture::new();
    let head = fx.commit(&[(b"notes.txt", "a later head file\n")]);
    let log = fx.state.join("hook.log");
    let hook = fx.repo.join(".git/hooks/post-checkout");
    fs::create_dir_all(hook.parent().expect("a parent")).expect("made");
    executable(
        &hook,
        &format!(
            "#!/bin/sh\necho \"$PWD\" >> \"{}\"\ncase \"$PWD\" in */base) rm -f fix.marker;; esac\n",
            log.display()
        ),
    );
    let done = fx.run(|call| {
        call.base = Some(fx.head.clone());
        call.head = Some(head.clone());
    });
    assert_eq!(done.code, 1, "{}", done.shown());
    assert!(
        done.stdout
            .starts_with("red-green refused: the test passes on the base: "),
        "{}",
        done.stdout
    );
    assert!(!log.exists(), "a post-checkout hook ran in a leg worktree");
    assert!(members(&fx.tree_of("base")).contains_key("fix.marker"));
    fx.assert_checkout_unchanged();
    // The control: the same worktree step with the checkout's hooks runs the hook.
    let control = fx.root.join("control");
    fx.git(&[
        "worktree",
        "add",
        "--quiet",
        "--detach",
        &control.to_string_lossy(),
        &fx.head,
    ]);
    assert!(log.exists(), "the hook runs where hooks are enabled");
    fx.git(&["worktree", "remove", "--force", &control.to_string_lossy()]);
}

/// A named head, package, integration target, release profile and build directory reach both legs: the
/// default base is the merge base with `origin/main`, a `--cargo` without a directory part runs from
/// `PATH`, and the invoking checkout's index and working tree stay as they were.
#[test]
fn a_named_head_package_target_release_and_build_directory_reach_both_legs() {
    let mut fx = Fixture::new();
    fx.git(&["checkout", "-q", "-b", "side", &fx.base]);
    let later = fx.commit(&[(b"table_tests.rs", "#[test] later\n")]);
    fx.git(&["update-ref", "refs/remotes/origin/main", &later]);
    write(&fx.repo.join("table_tests.rs"), "staged\n");
    fx.git(&["add", "table_tests.rs"]);
    write(&fx.repo.join("table_tests.rs"), "working\n");
    write(&fx.repo.join("scratch.txt"), "untracked\n");
    fx.status = fx.git(&["status", "--porcelain"]);
    let staged = fx.git(&["rev-parse", ":table_tests.rs"]);
    let binaries = fx.root.join("bin");
    private_dir(&binaries);
    symlink(fx.state.join("cargo"), binaries.join("-cargo")).expect("linked");
    let elsewhere = fx.root.join("elsewhere");
    let mut env = fx.path_env(&binaries);
    env.push(("CARGO_TARGET_DIR".into(), "../shared".into()));
    env.push(("CARGO_BUILD_BUILD_DIR".into(), elsewhere.into_os_string()));
    let done = fx.red_green(&Call {
        extra: vec!["--release".into()],
        package: "fixture-pkg".to_owned(),
        target: "table_it".to_owned(),
        base: Some(String::new()),
        cargo: Some("-cargo".to_owned()),
        env: Some(env),
        ..Call::default()
    });
    assert_eq!(done.code, 0, "{}", done.shown());
    let (_, receipt) = fx.receipt(&done);
    let target = fx
        .root
        .join("shared/red-green")
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        [
            text(at(&receipt, "base")),
            text(at(&receipt, "head")),
            json_of(at(&receipt, "release")),
            text(at(&receipt, "cargo_target_dir")),
        ],
        [
            fx.base.clone(),
            fx.head.clone(),
            "true".to_owned(),
            target.clone()
        ]
    );
    let blob = fx.git(&["rev-parse", &format!("{}:table_tests.rs", fx.head)]);
    assert_eq!(
        json_of(at(&receipt, "carried")),
        format!("[{{\"blob\":\"{blob}\",\"path\":\"table_tests.rs\"}}]")
    );
    for (leg, commit) in [("base", &fx.base), ("head", &fx.head)] {
        let artifact = PathBuf::from(text(at(at(at(&receipt, "legs"), leg), "artifact")));
        let record = kestrike_tools::json::parse(&read(&artifact)).expect("JSON");
        assert_eq!(
            [
                text(at(&record, "revision")),
                json_of(at(&record, "release")),
                text(at(&record, "package")),
                text(at(&record, "target")),
            ],
            [
                commit.clone(),
                "true".to_owned(),
                "fixture-pkg".to_owned(),
                "table_it".to_owned()
            ]
        );
    }
    assert_eq!(text(at(&fx.tree_of("base"), "table_tests.rs")), "#[test]\n");
    let builds = fx.builds();
    for build in &builds {
        let argv = texts(at(build, "argv"));
        assert_eq!(
            argv[..5],
            ["test", "-p", "fixture-pkg", "--test", "table_it"]
        );
        assert!(argv.contains(&"--release".to_owned()));
        assert_eq!(
            [text(at(build, "target_dir")), text(at(build, "build_dir"))],
            [target.clone(), target.clone()]
        );
    }
    assert_eq!(builds.len(), 2);
    let command = split(&text(at(&receipt, "command")));
    assert!(
        command.contains(&"--release".to_owned()) && command.contains(&"--cargo=-cargo".to_owned())
    );
    assert_eq!(
        (
            fx.git(&["rev-parse", ":table_tests.rs"]),
            read(&fx.repo.join("table_tests.rs"))
        ),
        (staged, "working\n".to_owned())
    );
    fx.assert_checkout_unchanged();
}

/// The default base is the merge base with `origin/main` and the default head `HEAD`, and a relative
/// `--artifacts` and a `--cargo` with a directory part are made absolute against the invoking
/// directory, in the receipt's command too.
#[test]
fn the_default_base_is_the_merge_base_and_relative_paths_are_anchored_at_the_invoking_directory() {
    let fx = Fixture::new();
    let side = fx.git(&[
        "commit-tree",
        &format!("{}^{{tree}}", fx.base),
        "-p",
        &fx.base,
        "-m",
        "side",
    ]);
    fx.git(&["update-ref", "refs/remotes/origin/main", &side]);
    let later = fx.commit(&[(b"notes.txt", "a later head\n")]);
    let done = fx.red_green(&Call {
        extra: vec!["--artifacts".into(), "../receipts".into()],
        base: Some(String::new()),
        head: Some(String::new()),
        cargo: Some("../state/cargo".to_owned()),
        ..Call::default()
    });
    assert_eq!(done.code, 0, "{}", done.shown());
    let (path, receipt) = fx.receipt(&done);
    assert_eq!(
        path.parent().and_then(|run| run.parent()),
        Some(fx.root.join("receipts").as_path())
    );
    assert_eq!(
        [text(at(&receipt, "base")), text(at(&receipt, "head"))],
        [fx.base.clone(), later]
    );
    for leg in ["base", "head"] {
        assert!(PathBuf::from(text(at(at(at(&receipt, "legs"), leg), "artifact"))).is_file());
    }
    assert_eq!(fx.build_legs(), ["base", "head"]);
    let command = split(&text(at(&receipt, "command")));
    assert!(command.contains(&format!(
        "--artifacts={}",
        fx.root.join("receipts").display()
    )));
    assert!(command.contains(&format!("--cargo={}", fx.state.join("cargo").display())));
    fx.assert_checkout_unchanged();
}

/// A Cargo home that all users can write is used as the environment provides it: the run proves.
#[test]
fn a_cargo_home_another_user_can_write_is_used_as_the_environment_provides_it() {
    let fx = Fixture::new();
    let home = fx.root.join("cargo-home");
    private_dir(&home);
    chmod(&home, 0o777);
    let done = fx.red_green(&Call {
        env: Some(fx.with_env(&[("CARGO_HOME", home.as_os_str())])),
        ..Call::default()
    });
    assert_eq!(done.code, 0, "{}", done.shown());
}

/// A receipt directory whose name holds an escape sequence is printed escaped on the `receipt: ` line,
/// and the receipt stands under it.
#[test]
fn a_path_with_control_characters_is_printed_escaped() {
    let fx = Fixture::new();
    let erasing = fx.root.join("e\u{1b}[2Kx");
    let done = fx.red_green(&Call {
        extra: vec!["--artifacts".into(), erasing.clone().into_os_string()],
        ..Call::default()
    });
    assert_eq!(done.code, 0, "{}", done.shown());
    assert!(!done.stderr.contains('\u{1b}'));
    assert!(done.stderr.contains("receipt: "));
    let receipts = fs::read_dir(&erasing)
        .expect("lists")
        .filter(|entry| {
            entry
                .as_ref()
                .is_ok_and(|entry| entry.path().join("receipt.json").is_file())
        })
        .count();
    assert_eq!(receipts, 1);
}

/// A result line escapes each control character, C1 controls and the line and paragraph separators
/// among them, as Python's `repr` writes it.
#[test]
fn a_result_line_escapes_control_characters() {
    let mut out = Vec::new();
    say(
        &mut out,
        &Text::from("a\u{1b}[100Db\u{8}c\u{7f}d\u{9b}e\tf\u{2028}g"),
    )
    .expect("written");
    assert_eq!(
        String::from_utf8(out).expect("UTF-8"),
        "a\\x1b[100Db\\x08c\\x7fd\\x9be\\tf\\u2028g\n"
    );
}
