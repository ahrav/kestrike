//! The worker build against a test checkout whose Cargo is
//! `testdata/fake-cargo`: the provenance it records, the lockfile's
//! resolution and pinning, and the exit of each failure.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{Archive, Built, Error, Invalid, archive, build, publish};
use crate::exit::Sim;
use crate::record::Digest;
use crate::store::Refusal;
use crate::store::fixture::{Case, processes};
use crate::sys;

fn cargo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/fake-cargo")
}

/// Runs git in `dir` under no global or system configuration, signing
/// and hooks off.
fn git(dir: &Path, args: &[&str]) -> String {
    let ran = Command::new("git")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(["-c", "user.name=test", "-c", "user.email=test@example.com"])
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git runs");
    assert!(ran.status.success(), "git {args:?}: {ran:?}");
    String::from_utf8(ran.stdout)
        .expect("git prints UTF-8")
        .trim()
        .to_owned()
}

/// A test checkout with a workspace manifest, a lockfile, notes, the
/// native build's install record and link plan, and a worker executable
/// copied from the host, committed when `commit`.
fn checkout(case: &Case, commit: bool) -> PathBuf {
    let dir = case.root.join("checkout");
    for (path, bytes) in [
        ("Cargo.toml", "[workspace]\n"),
        ("Cargo.lock", "version = 4\n"),
        ("notes", "notes\n"),
        ("install/native", "install record\n"),
        ("out/link-plan.txt", "system uuid\n"),
    ] {
        let path = dir.join(path);
        fs::create_dir_all(path.parent().expect("it has a parent")).expect("it is made");
        fs::write(path, bytes).expect("it is written");
    }
    fs::copy("/usr/bin/true", dir.join("worker")).expect("the worker is copied");
    git(&dir, &["init", "-q"]);
    if commit {
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-qm", "fixture"]);
    }
    dir
}

/// Runs `op` in `dir` on a thread with its own working directory.
fn in_checkout<T: Send>(dir: &Path, op: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                sys::private_fs(0o022).expect("the thread gets its own working directory");
                std::env::set_current_dir(dir).expect("the working directory changes");
                op()
            })
            .join()
            .expect("the checkout thread finishes")
    })
}

/// Runs the build in `dir`.
fn built_in(dir: &Path) -> Result<Built, Error> {
    in_checkout(dir, || build(&cargo()))
}

/// The Cargo calls the fake recorded, in order.
fn calls(dir: &Path) -> Vec<String> {
    fs::read_to_string(dir.join(".git/calls"))
        .map(|calls| calls.lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// A build of a clean checkout records its revision, a clean state, the
/// locked build command, the host target, the native install record and
/// link plan digests, the executable Cargo names and the lockfile's exact
/// bytes, and runs the compiler whose version it records. An untracked
/// file is counted and leaves the checkout clean; a tracked change makes
/// it dirty.
#[test]
fn a_build_records_its_revision_dirty_state_lockfile_and_native_identity() {
    let _processes = processes();
    let case = Case::new();
    let dir = checkout(&case, true);
    let built = built_in(&dir).expect("the build succeeds");
    let provenance = &built.provenance;
    assert_eq!(
        provenance.revision.as_str(),
        git(&dir, &["rev-parse", "HEAD"])
    );
    assert!(!provenance.dirty);
    assert_eq!(provenance.untracked, 0);
    assert_eq!(built.lock, b"version = 4\n");
    assert_eq!(built.executable, dir.join("worker"));
    let command = provenance.command.as_str();
    assert_eq!(
        command,
        "test -p kestrike --test sim_worker --no-run --locked \
         --message-format=json-render-diagnostics --quiet"
    );
    assert_eq!(calls(&dir), [command]);
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let ran = fs::read_to_string(dir.join(".git/rustc")).expect("the build recorded RUSTC");
    assert_eq!(ran.trim(), format!("RUSTC={rustc}"));
    let target = match std::env::var("CARGO_BUILD_TARGET") {
        Ok(target) if target != "host-tuple" => target,
        _ => {
            let host = Command::new(&rustc)
                .arg("-vV")
                .output()
                .expect("rustc runs");
            let host = String::from_utf8(host.stdout).expect("rustc prints UTF-8");
            let host = host.lines().find_map(|line| line.strip_prefix("host: "));
            host.expect("rustc names its host").to_owned()
        }
    };
    assert_eq!(provenance.target.as_str(), target);
    assert_eq!(
        fs::read_to_string(dir.join(".git/target"))
            .expect("effective target recorded")
            .trim(),
        target
    );
    assert_eq!(
        fs::read_to_string(dir.join(".git/lockfile"))
            .expect("lockfile recorded")
            .trim(),
        dir.join("Cargo.lock").display().to_string()
    );
    assert_eq!(
        provenance.native.package.as_str(),
        format!("path+file://{}/native-owner#0.1.0", dir.display())
    );
    assert_eq!(provenance.native.install_record.as_str(), "native");
    assert_eq!(
        provenance.native.install_record_sha256,
        Digest::of(b"install record\n")
    );
    assert_eq!(
        provenance.native.link_plan_sha256,
        Digest::of(b"system uuid\n")
    );
    assert!(provenance.cargo.as_str().starts_with("cargo 1.0.0"));
    assert!(provenance.toolchain.as_str().starts_with("rustc "));
    let mut vars: Vec<_> = std::env::vars_os().collect();
    vars.retain(|(name, _)| {
        name != "RUSTC" && name != "CARGO_BUILD_TARGET" && name != "CARGO_RESOLVER_LOCKFILE_PATH"
    });
    vars.extend([
        (OsString::from("RUSTC"), OsString::from(&rustc)),
        (
            OsString::from("CARGO_BUILD_TARGET"),
            OsString::from(&target),
        ),
        (
            OsString::from("CARGO_RESOLVER_LOCKFILE_PATH"),
            dir.join("Cargo.lock").into_os_string(),
        ),
    ]);
    let environment = super::build::environment(vars.into_iter()).expect("it is recorded");
    assert_eq!(provenance.environment, environment);
    fs::write(dir.join("extra"), "x").expect("it is written");
    let untracked = built_in(&dir).expect("the build succeeds").provenance;
    assert!(
        !untracked.dirty,
        "an untracked file alone leaves the checkout clean"
    );
    assert_eq!(untracked.untracked, 1);
    fs::write(dir.join("Cargo.toml"), "[workspace]\nmembers = []\n").expect("it is edited");
    let dirty = built_in(&dir).expect("the build succeeds").provenance;
    assert!(dirty.dirty);
    assert_eq!(dirty.untracked, 1);
}

/// A workspace without a lockfile has one resolved before the build, which
/// then runs locked, and the resolved bytes are the ones pinned.
#[test]
fn a_missing_lockfile_is_resolved_before_the_locked_build() {
    let _processes = processes();
    let case = Case::new();
    let dir = checkout(&case, true);
    fs::remove_file(dir.join("Cargo.lock")).expect("it is removed");
    let built = built_in(&dir).expect("the build succeeds");
    let calls = calls(&dir);
    assert_eq!(calls[0], "generate-lockfile");
    assert!(calls[1].contains("--locked"), "{calls:?}");
    assert_eq!(built.lock, b"version = 4\n");
    let paths = fs::read_to_string(dir.join(".git/lockfile")).expect("lock paths recorded");
    assert_eq!(
        paths.lines().collect::<Vec<_>>(),
        [
            dir.join("Cargo.lock").to_str().expect("UTF-8"),
            dir.join("Cargo.lock").to_str().expect("UTF-8")
        ]
    );
}

/// A changed lockfile or checkout status row, including a clean file edited in an already dirty checkout, a
/// lockfile replaced by a directory and a reported worker that is missing
/// refuse publication as incomplete, exit 4; a failed build, a checkout
/// with no revision, a build that reports no native identity, one naming
/// no install or output directory, two identities or one install twice,
/// one that compiles the supervisor into the worker, one reporting no or
/// two worker executables, one printing a truncated message and one
/// printing output that is not UTF-8 are build failures, exit 3, each for
/// its own reason, and a checkout with no revision starts no build.
#[test]
fn each_build_failure_exits_with_its_class() {
    let _processes = processes();
    for (flag, exit, reason) in [
        ("relock", Sim::Incomplete, "lockfile changed"),
        ("edit", Sim::Incomplete, "status changed"),
        ("lockdir", Sim::Incomplete, "unreadable after the build"),
        ("no-exe", Sim::Incomplete, "worker is unreadable"),
        ("fail", Sim::BuildFailure, "the build exited"),
        ("no-native", Sim::BuildFailure, "unidentified"),
        ("partial-native", Sim::BuildFailure, "unidentified"),
        ("no-out-dir", Sim::BuildFailure, "malformed message"),
        ("no-package", Sim::BuildFailure, "malformed message"),
        ("nameless-install", Sim::BuildFailure, "unidentified"),
        ("no-install", Sim::Incomplete, "unreadable"),
        ("no-plan", Sim::Incomplete, "unreadable"),
        ("unrevise", Sim::Incomplete, "no revision"),
        ("bad-env", Sim::BuildFailure, "malformed message"),
        ("bad-target", Sim::BuildFailure, "malformed message"),
        ("bad-profile", Sim::BuildFailure, "malformed message"),
        ("bad-kind", Sim::BuildFailure, "malformed message"),
        ("repeated-name", Sim::BuildFailure, "malformed message"),
        ("two-natives", Sim::BuildFailure, "more than one native"),
        ("two-installs", Sim::BuildFailure, "more than one native"),
        ("contract", Sim::BuildFailure, "compiles the supervisor"),
        ("no-worker", Sim::BuildFailure, "no single worker"),
        ("two-workers", Sim::BuildFailure, "no single worker"),
        ("malformed", Sim::BuildFailure, "malformed message"),
        ("binary", Sim::BuildFailure, "not UTF-8"),
    ] {
        let case = Case::new();
        let dir = checkout(&case, true);
        fs::write(dir.join(".git").join(flag), "").expect("the flag is set");
        let failed = built_in(&dir).expect_err(flag);
        assert_eq!(failed.exit(), exit, "{flag}: {failed}");
        assert!(failed.to_string().contains(reason), "{flag}: {failed}");
        assert_eq!(calls(&dir).len(), 1, "{flag}");
    }
    let case = Case::new();
    let dir = checkout(&case, true);
    fs::write(dir.join("Cargo.toml"), "[workspace]\nmembers = []\n").expect("it is edited");
    fs::write(dir.join(".git/edit-notes"), "").expect("the flag is set");
    let failed = built_in(&dir).expect_err("a dirty checkout changes");
    assert_eq!(failed.exit(), Sim::Incomplete, "{failed}");
    assert!(failed.to_string().contains("status changed"), "{failed}");
    let case = Case::new();
    let dir = checkout(&case, false);
    let failed = built_in(&dir).expect_err("the checkout has no revision");
    assert!(
        matches!(&failed, Error::Build(why) if why.contains("no revision")),
        "{failed}"
    );
    assert!(calls(&dir).is_empty());
}

#[test]
fn unsearchable_shared_and_existing_outputs_are_refused_before_the_build() {
    let _processes = processes();
    let case = Case::new();
    let dir = checkout(&case, true);
    let existing = super::publish_tests::published(&case);
    let before = fs::read(existing.join("build")).expect("it reads");
    let shared = case.root.join("shared");
    fs::create_dir(&shared).expect("the shared directory is made");
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).expect("it is shared");
    let mut outputs: Vec<PathBuf> = [":", ";", "$"]
        .map(|special| case.root.join(format!("bad{special}archive")))
        .into();
    outputs.push(existing.clone());
    outputs.push(shared.join("archive"));
    for output in outputs {
        let refused = in_checkout(&dir, || archive(&cargo(), &output).map(drop))
            .expect_err("the output is refused");
        let invalid = matches!(
            refused,
            Error::Invalid(
                Invalid::Path(_) | Invalid::Exists | Invalid::Refused(Refusal::Ancestor(_))
            )
        );
        assert!(invalid, "{}: {refused}", output.display());
        assert_eq!(refused.exit(), Sim::Rejected);
        assert!(calls(&dir).is_empty(), "no build started");
    }
    assert!(!case.root.join("bad:archive").exists());
    assert!(!shared.join("archive").exists());
    assert_eq!(fs::read(existing.join("build")).expect("it reads"), before);
    let refused = publish(&existing, &super::publish_tests::built()).expect_err("it exists");
    assert!(
        matches!(refused, Error::Invalid(Invalid::Exists)),
        "{refused}"
    );
    let refused = publish(&shared.join("archive"), &super::publish_tests::built())
        .expect_err("its parent is shared");
    assert!(
        matches!(
            refused,
            Error::Invalid(Invalid::Refused(Refusal::Ancestor(_)))
        ),
        "{refused}"
    );
    assert!(!shared.join("archive").exists(), "no directory is created");
}

/// The build record keeps each build-affecting variable by name or
/// prefix, escaped to printable ASCII, and no other variable.
#[test]
fn the_build_affecting_environment_is_recorded_escaped() {
    let vars = [
        ("CARGO_BUILD_TARGET", "x86_64-unknown-linux-gnu"),
        ("CARGO_ENCODED_RUSTFLAGS", "--cfg\u{1f}x"),
        ("CARGO_HOME", "/home/user/.cargo"),
        ("CARGO_PROFILE_DEV_DEBUG", "0"),
        ("CARGO_UNSTABLE_BUILD_STD", "std"),
        ("KESTRIKE_SEED", "7"),
        ("HOME", "/home/user"),
        ("RUSTFLAGS", "-C \"quoted\""),
    ]
    .map(|(name, value)| (OsString::from(name), OsString::from(value)));
    let kept = super::build::environment(vars.into_iter()).expect("it is recorded");
    let kept: Vec<(&str, &str)> = kept
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    assert_eq!(
        kept,
        [
            ("CARGO_BUILD_TARGET", "x86_64-unknown-linux-gnu"),
            ("CARGO_ENCODED_RUSTFLAGS", "--cfg\\u{1f}x"),
            ("CARGO_PROFILE_DEV_DEBUG", "0"),
            ("CARGO_UNSTABLE_BUILD_STD", "std"),
            ("KESTRIKE_SEED", "7"),
            ("RUSTFLAGS", "-C \\\"quoted\\\""),
        ]
    );
}

/// An object name is 40 or 64 lowercase hexadecimal digits; another
/// length, an uppercase or other digit, and an empty name are refused.
#[test]
fn a_revision_has_the_shape_of_an_object_name() {
    assert!(super::build::revised(&"a".repeat(40)));
    assert!(super::build::revised(&"0".repeat(64)));
    for refused in [
        String::new(),
        "a".repeat(39),
        "a".repeat(41),
        "A".repeat(40),
        "g".repeat(40),
    ] {
        assert!(!super::build::revised(&refused), "{refused:?}");
    }
}

/// `archive` builds the checkout's worker and publishes it: the record
/// names the built executable's digest and the build's provenance, and
/// the archive verifies.
#[test]
fn an_archive_publishes_the_worker_its_build_reports() {
    let _processes = processes();
    let case = Case::new();
    let dir = checkout(&case, true);
    let output = case.root.join("archive");
    let mut archived =
        in_checkout(&dir, || archive(&cargo(), &output)).expect("the archive is published");
    let built = built_in(&dir).expect("the build succeeds");
    let worker = fs::read(dir.join("worker")).expect("it reads");
    assert_eq!(archived.record().executable, Digest::of(&worker));
    assert_eq!(archived.record().provenance, built.provenance);
    assert_eq!(fs::read(output.join("worker")).expect("it reads"), worker);
    archived.verify().map(drop).expect("it verifies");
    Archive::load(&output)
        .expect("it loads")
        .verify()
        .map(drop)
        .expect("it verifies after a load");
}

#[test]
fn cargo_receives_the_recorded_target_compiler_and_lockfile() {
    let _processes = processes();
    let case = Case::new();
    let dir = checkout(&case, true);
    let rustc = dir.join(".git/rustc-tool");
    fs::write(&rustc, "#!/bin/sh\ncase \"$1\" in -V) echo 'rustc fixture';; -vV) echo 'host: fixture-host';; esac\n").expect("compiler fixture written");
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&rustc, fs::Permissions::from_mode(0o700)).expect("fixture executable");
    for (requested, expected) in [
        ("explicit-target", "explicit-target"),
        ("host-tuple", "fixture-host"),
    ] {
        let mut vars: Vec<_> = std::env::vars_os().collect();
        vars.retain(|(name, _)| {
            name != "RUSTC"
                && name != "CARGO_BUILD_TARGET"
                && name != "CARGO_RESOLVER_LOCKFILE_PATH"
        });
        vars.extend([
            (OsString::from("RUSTC"), rustc.clone().into_os_string()),
            (
                OsString::from("CARGO_BUILD_TARGET"),
                OsString::from(requested),
            ),
            (
                OsString::from("CARGO_RESOLVER_LOCKFILE_PATH"),
                dir.join("elsewhere/Cargo.lock").into_os_string(),
            ),
        ]);
        let built =
            in_checkout(&dir, || super::build::build_with(&cargo(), vars)).expect("build succeeds");
        assert_eq!(built.provenance.target.as_str(), expected);
        assert_eq!(built.provenance.toolchain.as_str(), "rustc fixture");
        assert_eq!(
            fs::read_to_string(dir.join(".git/target"))
                .expect("target recorded")
                .lines()
                .last(),
            Some(expected)
        );
        assert_eq!(
            fs::read_to_string(dir.join(".git/lockfile"))
                .expect("lock recorded")
                .lines()
                .last(),
            Some(dir.join("Cargo.lock").to_str().expect("path UTF-8"))
        );
        assert_eq!(
            built
                .provenance
                .environment
                .get(&crate::record::Text::new("RUSTC").expect("text"))
                .expect("compiler env recorded")
                .as_str(),
            rustc.to_str().expect("path UTF-8")
        );
    }
}

#[test]
fn a_reedit_that_keeps_a_dirty_status_row_keeps_dirty_provenance() {
    let _processes = processes();
    let case = Case::new();
    let dir = checkout(&case, true);
    fs::write(dir.join("Cargo.toml"), "[workspace]\nmembers=[ ]\n").expect("initial edit");
    fs::write(dir.join(".git/edit"), "").expect("build edit flag");
    let built = built_in(&dir).expect("the status row stays modified");
    assert!(built.provenance.dirty);
    assert_eq!(
        fs::read_to_string(dir.join("Cargo.toml")).expect("changed content"),
        "[workspace]\nmembers = []\n"
    );
}

#[test]
fn archive_sigterm_at_the_build_seam_exits_five_and_leaves_no_record() {
    const CARGO: &str = "CAMPAIGN_TEST_INTERRUPTED_ARCHIVE_CARGO";
    const OUTPUT: &str = "CAMPAIGN_TEST_INTERRUPTED_ARCHIVE_OUTPUT";
    if let Some(cargo) = std::env::var_os(CARGO) {
        let output = PathBuf::from(std::env::var_os(OUTPUT).unwrap());
        sys::child_subreaper().unwrap();
        let error = archive(Path::new(&cargo), &output).unwrap_err();
        assert_eq!(error.exit(), Sim::Interrupted, "{error}");
        let group: u32 = fs::read_to_string(".git/build-entered")
            .unwrap()
            .parse()
            .unwrap();
        let grandchild: u32 = fs::read_to_string(".git/grandchild")
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while PathBuf::from(format!("/proc/{grandchild}")).exists() {
            while sys::reap_group(group).unwrap() {}
            assert!(
                std::time::Instant::now() < deadline,
                "archive grandchild survived cancellation"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        std::process::exit(i32::from(crate::exit::Exit::Sim(error.exit()).code()));
    }
    let _processes = processes();
    let case = Case::new();
    let dir = checkout(&case, true);
    let tool = dir.join(".git/interrupted-cargo");
    fs::write(&tool, format!("#!/bin/sh\nif [ \"$1\" = test ]; then sleep 90 & echo $! > .git/grandchild; printf '%s' \"$$\" > .git/build-entered; wait; fi\nexec '{}' \"$@\"\n", cargo().display())).unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
    let output = case.root.join("interrupted-archive");
    sys::block_interruptions().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "archive::build_tests::archive_sigterm_at_the_build_seam_exits_five_and_leaves_no_record", "--nocapture"])
        .current_dir(&dir).env(CARGO, &tool).env(OUTPUT, &output)
        .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while !dir.join(".git/build-entered").exists() {
        if child.try_wait().unwrap().is_some() {
            let result = child.wait_with_output().unwrap();
            panic!(
                "archive exited before build seam: {} {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
        assert!(
            std::time::Instant::now() < deadline,
            "build seam was unreached"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .output()
            .unwrap()
            .status
            .success()
    );
    let result = child.wait_with_output().unwrap();
    assert_eq!(
        result.status.code(),
        Some(5),
        "{} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.join("build").exists());
    assert!(!output.exists());
}

#[test]
fn archive_signal_after_record_commit_returns_zero_and_keeps_a_verified_archive() {
    const OUTPUT: &str = "CAMPAIGN_TEST_COMMITTED_ARCHIVE_OUTPUT";
    if let Some(output) = std::env::var_os(OUTPUT) {
        let output = PathBuf::from(output);
        let observed = output.clone();
        let sent = std::rc::Rc::new(std::cell::Cell::new(false));
        let witness = sent.clone();
        crate::step::install(Some(crate::step::Script {
            observe: Some(Box::new(move |point| {
                if point == crate::step::Step::Check
                    && observed.join("build").is_file()
                    && !witness.get()
                {
                    witness.set(true);
                    sys::interrupt(libc::SIGTERM).unwrap();
                }
            })),
            ..crate::step::Script::default()
        }));
        let result = archive(&cargo(), &output);
        crate::step::install(None);
        let mut archived = result.unwrap();
        assert!(sent.get());
        archived.verify().map(drop).unwrap();
        assert_eq!(
            sys::interruption(std::time::Duration::ZERO).unwrap(),
            Some(libc::SIGTERM)
        );
        assert_eq!(fs::read_dir(output.join(".staging")).unwrap().count(), 0);
        std::process::exit(0);
    }
    let _processes = processes();
    let case = Case::new();
    let dir = checkout(&case, true);
    let output = case.root.join("committed-archive");
    sys::block_interruptions().unwrap();
    let result = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "archive::build_tests::archive_signal_after_record_commit_returns_zero_and_keeps_a_verified_archive", "--nocapture"])
        .current_dir(&dir).env(OUTPUT, &output).output().unwrap();
    assert_eq!(
        result.status.code(),
        Some(0),
        "{} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    Archive::load(&output).unwrap().verify().map(drop).unwrap();
    assert_eq!(fs::read_dir(output.join(".staging")).unwrap().count(), 0);
}

#[test]
fn a_verifier_command_defers_archive_interruption_to_its_owner() {
    let _processes = processes();
    let context = super::command::Context::open().unwrap();
    sys::interrupt(libc::SIGTERM).unwrap();
    let result = super::run::run(
        Command::new("/bin/true").args([] as [&str; 0]),
        super::run::Stderr::Capture,
        Some(std::time::Duration::from_secs(1)),
    )
    .unwrap();
    assert!(result.status.success());
    assert!(matches!(context.check(), Err(Error::Interrupted(signal)) if signal == libc::SIGTERM));
}

#[test]
fn archive_signal_during_final_record_sync_cleans_up_before_commit() {
    let _processes = processes();
    let mut baseline = Vec::new();
    for failure in [
        None,
        Some(crate::step::Step::Unlink),
        Some(crate::step::Step::Sync),
    ] {
        let nth = failure.map(|point| {
            (
                point,
                baseline.iter().filter(|found| **found == point).count() - 1,
                crate::step::Outcome::Errno(libc::EIO),
            )
        });
        let case = Case::new();
        let dir = checkout(&case, true);
        let output = case.root.join("cancelled-staged-record");
        let observed = output.clone();
        in_checkout(&dir, || {
            let sent = std::rc::Rc::new(std::cell::Cell::new(false));
            let witness = sent.clone();
            crate::step::install(Some(crate::step::Script {
                nth,
                observe: Some(Box::new(move |point| {
                    if point == crate::step::Step::Close
                        && !witness.get()
                        && fs::read_dir(observed.join(".staging")).is_ok_and(|entries| {
                            entries.flatten().any(|entry| {
                                entry
                                    .file_name()
                                    .to_str()
                                    .is_some_and(|name| name.ends_with(".build"))
                            })
                        })
                    {
                        assert!(!observed.join("build").exists());
                        witness.set(true);
                        sys::interrupt(libc::SIGTERM).unwrap();
                    }
                })),
                ..crate::step::Script::default()
            }));
            let result = archive(&cargo(), &output);
            let script = crate::step::install(None).unwrap();
            assert!(sent.get());
            let error = result.unwrap_err();
            if let Some((point, index, _)) = nth {
                assert!(matches!(error, Error::Store(_)), "{error}");
                assert_eq!(error.exit(), Sim::Incomplete);
                assert_eq!(
                    script
                        .reached
                        .iter()
                        .filter(|found| **found == point)
                        .count(),
                    index + 1
                );
            } else {
                assert_eq!(error.exit(), Sim::Interrupted);
                baseline = script.reached;
            }
            assert!(!output.join("build").exists());
            assert_eq!(
                fs::read_dir(output.join(".staging")).unwrap().count(),
                usize::from(failure == Some(crate::step::Step::Unlink))
            );
        });
    }
}

#[test]
fn archive_signal_during_publication_leaves_no_build_or_staged_temporary() {
    let _processes = processes();
    let case = Case::new();
    let dir = checkout(&case, true);
    let output = case.root.join("cancelled-publication");
    let observed = output.clone();
    in_checkout(&dir, || {
        let sent = std::rc::Rc::new(std::cell::Cell::new(false));
        let witness = sent.clone();
        crate::step::install(Some(crate::step::Script {
            observe: Some(Box::new(move |point| {
                if point == crate::step::Step::Check
                    && observed.join(".state").is_file()
                    && !observed.join("build").exists()
                    && !witness.get()
                {
                    witness.set(true);
                    sys::interrupt(libc::SIGTERM).unwrap();
                }
            })),
            ..crate::step::Script::default()
        }));
        let result = archive(&cargo(), &output);
        crate::step::install(None);
        assert!(sent.get());
        assert_eq!(result.unwrap_err().exit(), Sim::Interrupted);
        assert!(!output.join("build").exists());
        assert_eq!(fs::read_dir(output.join(".staging")).unwrap().count(), 0);
    });
}
