//! The run's directories: the build directory and its ancestors, made for the invoking user alone; a
//! receipt directory that cannot be made or that stands already; the checked temporary directory, in
//! which the run makes its own; a receipt that cannot be written.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use kestrike_tools::ownership::{PrivateError, make_private_with, shared_directories};

use super::support::{Call, Fixture, MADE, RUN_NAME, chmod, me, private_dir, read, write};

/// Under an open umask each directory the run makes on the way to the build directory has no group or
/// world write permission, so a second run accepts it; an ancestor all users can write is then shared.
#[test]
fn the_build_directory_is_created_for_the_invoking_user_alone() {
    let fx = Fixture::new();
    let build = fx.repo.join("target/red-green/build");
    assert_eq!(
        shared_directories(&build).expect("the lineage reads"),
        Vec::<PathBuf>::new()
    );
    for _ in 0..2 {
        let done = fx.red_green(&Call {
            umask: Some(0),
            ..Call::default()
        });
        assert_eq!(done.code, 0, "{}", done.shown());
        for directory in ["target", "target/red-green", "target/red-green/build"] {
            let mode = fs::metadata(fx.repo.join(directory))
                .expect("it stands")
                .permissions()
                .mode();
            assert_eq!(mode & 0o022, 0, "{directory} has mode {mode:o}");
        }
    }
    chmod(&fx.repo.join("target/red-green"), 0o777);
    assert_eq!(
        shared_directories(&build.join("absent")).expect("the lineage reads"),
        [fx.repo.join("target/red-green")]
    );
}

/// A receipt directory below a file and a build directory in a directory its owner cannot write are
/// refused by name, before any build and with no receipt.
#[test]
fn an_uncreatable_receipt_directory_is_refused_by_name() {
    let fx = Fixture::new();
    let blocker = fx.root.join("file");
    write(&blocker, "");
    let locked = fx.root.join("locked");
    private_dir(&locked);
    chmod(&locked, 0o500);
    for (name, call, path) in [
        (
            "receipt",
            Call {
                extra: vec!["--artifacts".into(), blocker.clone().into_os_string()],
                ..Call::default()
            },
            format!("{}/local-", blocker.display()),
        ),
        (
            "build",
            Call {
                env: Some(fx.with_env(&[("CARGO_TARGET_DIR", locked.as_os_str())])),
                ..Call::default()
            },
            format!("{}/red-green ", locked.display()),
        ),
    ] {
        if name == "build" && me() == 0 {
            continue;
        }
        let done = fx.red_green(&call);
        assert_eq!(done.code, 1, "{name}: {}", done.shown());
        let line = done.line();
        assert!(
            line.starts_with(&format!("red-green refused: the {name} directory {path}")),
            "{line}"
        );
        assert!(line.contains("could not be created"), "{line}");
        assert!(!done.stderr.contains("receipt: "), "{name}");
        assert!(fx.builds().is_empty(), "{name}");
        fx.assert_checkout_unchanged();
    }
}

/// A run directory that stands already is refused by name and left as it is.
#[test]
fn a_receipt_directory_that_exists_is_refused_and_left_unchanged() {
    let fx = Fixture::new();
    let existing = fx.repo.join("target/red-green/local-1700000000-4242");
    fs::create_dir_all(&existing).expect("made");
    write(&existing.join("receipt.json"), "an earlier receipt\n");
    let done = fx.red_green(&Call {
        env: Some(fx.with_env(&[(RUN_NAME, OsStr::new("local-1700000000-4242"))])),
        ..Call::default()
    });
    assert_eq!(done.code, 1, "{}", done.shown());
    assert!(
        done.stdout.starts_with(&format!(
            "red-green refused: the receipt directory {} could not be created",
            existing.display()
        )),
        "{}",
        done.stdout
    );
    assert!(!done.stderr.contains("receipt: "));
    assert_eq!(read(&existing.join("receipt.json")), "an earlier receipt\n");
    assert!(fx.builds().is_empty());
}

/// With `TMPDIR` a link to the fixture's temporary directory, the run makes its one temporary
/// directory in the directory the link resolves to, the one the toolchain check examined.
#[test]
fn the_runner_copy_and_the_worktrees_are_created_in_the_checked_temporary_directory() {
    let fx = Fixture::new();
    let link = fx.root.join("tmp-link");
    symlink(&fx.tmp, &link).expect("linked");
    let made = fx.root.join("made.log");
    let done = fx.red_green(&Call {
        env: Some(fx.with_env(&[("TMPDIR", link.as_os_str()), (MADE, made.as_os_str())])),
        ..Call::default()
    });
    assert_eq!(done.code, 0, "{}", done.shown());
    let used: Vec<String> = read(&made).lines().map(str::to_owned).collect();
    assert_eq!(used, [fx.tmp.to_string_lossy().into_owned()]);
}

/// A receipt whose path a directory, a file or a link already takes cannot be written: the proven run
/// is refused with the receipt's path and its result, and the planted file stays as it was.
#[test]
fn a_receipt_that_cannot_be_written_is_refused() {
    let fx = Fixture::new();
    let planted = fx.state.join("planted.txt");
    write(&planted, "planted\n");
    let shape = regex_lite(
        "red-green refused: the receipt ",
        "/receipt.json could not be written: ",
        "; proven",
    );
    for outcome in ["block-receipt", "file-receipt", "link-receipt"] {
        fx.plan(&format!(r#"{{"head": {{"attempt": "{outcome}"}}}}"#));
        let done = fx.red_green(&Call::default());
        assert_eq!(done.code, 1, "{outcome}: {}", done.shown());
        assert!(shape(done.line()), "{outcome}: {}", done.line());
        assert!(!done.stderr.contains("receipt: "), "{outcome}");
        assert_eq!(read(&planted), "planted\n");
        fx.assert_checkout_unchanged();
    }
}

/// `regex_lite` matches a line that opens with `open`, holds `middle` after it and ends with `close`.
fn regex_lite<'a>(open: &'a str, middle: &'a str, close: &'a str) -> impl Fn(&str) -> bool + 'a {
    move |line: &str| {
        line.strip_prefix(open)
            .and_then(|rest| rest.find(middle).map(|at| &rest[at + middle.len()..]))
            .is_some_and(|rest| rest.ends_with(close))
    }
}

/// A build directory another run made between the probe and this run's `mkdir` is used; one that
/// appears with group or world write permission is refused, and a file in its place fails the creation.
#[test]
fn a_build_directory_that_another_run_creates_first_is_used() {
    let fx = Fixture::new();
    let build = fx.root.join("made/first");
    fs::create_dir_all(&build).expect("made");
    let absent = |_: &Path| Ok(false);
    make_private_with(&build, me(), &absent).expect("a directory made first is used");
    chmod(&build, 0o777);
    let shared =
        make_private_with(&build, me(), &absent).expect_err("a shared directory is refused");
    assert!(
        matches!(shared, PrivateError::Shared(ref found) if found == std::slice::from_ref(&build)),
        "{shared}"
    );
    write(&fx.root.join("made/file"), "");
    let taken =
        make_private_with(&fx.root.join("made/file"), me(), &absent).expect_err("a file fails");
    let PrivateError::Io(error) = taken else {
        panic!("a file in the place is no shared directory: {taken}");
    };
    assert_eq!(error.error().kind(), std::io::ErrorKind::AlreadyExists);
}

/// A run directory's name that is not one normal path component fails the run before the build
/// directory, with exit 1 and one line naming it; a name of one component is used.
#[test]
fn a_run_directory_name_of_more_than_one_component_fails_the_run() {
    let fx = Fixture::new();
    for name in ["a/b", "/abs", "..", "."] {
        let done = fx.red_green(&Call {
            env: Some(fx.with_env(&[(RUN_NAME, OsStr::new(name))])),
            ..Call::default()
        });
        assert_eq!(done.code, 1, "{name}: {}", done.shown());
        assert_eq!(
            done.stderr,
            format!("red-green: the run directory's name '{name}' is not one path component\n"),
            "{name}"
        );
        assert!(!fx.repo.join("target").exists(), "{name}");
    }
    let done = fx.red_green(&Call {
        env: Some(fx.with_env(&[(RUN_NAME, OsStr::new("one"))])),
        ..Call::default()
    });
    assert_eq!(done.code, 0, "{}", done.shown());
    assert!(fx.repo.join("target/red-green/one/receipt.json").is_file());
}
