//! These tests cover path resolution, directory permissions and build-lock lifetime. The run rejects a
//! looping `TMPDIR` as a receipt or build directory, holds the build lock after the legs end and uses a
//! receipt directory that another user can write.

use std::ffi::OsStr;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;

use kestrike_tools::ownership::{PrivateError, make_private_with, shared_directories_for, status};
use kestrike_tools::paths;
use kestrike_tools::red_green::run::resolved_by;

use super::support::{Call, Fixture, at, chmod, me, private_dir, read, text};

#[test]
fn a_looping_temporary_directory_is_rejected_as_a_receipt_or_build_directory() {
    let fx = Fixture::new();
    let lp = fx.root.join("loop");
    symlink(&lp, &lp).expect("the loop is made");
    let done = fx.tool(&Call {
        env: Some(fx.with_env(&[("TMPDIR", lp.as_os_str())])),
        ..Call::default()
    });
    assert_eq!(done.code, 2, "{}", done.shown());
    assert!(
        done.stderr
            .starts_with("red-green rejected: a receipt or build directory cannot be resolved: "),
        "{}",
        done.shown()
    );
    assert_eq!(fx.build_legs(), Vec::<String>::new());
    assert!(!fx.repo.join("target").exists());
    let done = fx.tool(&Call::default());
    assert_eq!(done.code, 0, "{}", done.shown());
    assert_eq!(fx.build_legs(), ["base", "head"]);
}

#[test]
fn the_build_lock_is_held_after_the_legs_end() {
    let fx = Fixture::new();
    let lock = fx.repo.join("target/red-green/build/red-green.lock");
    let probe = fx.state.join("probe.txt");
    let env = fx.git_wrapper(&format!(
        "case \"$*\" in \"worktree remove \"*) /usr/bin/flock -n -E 75 '{}' /bin/true; echo $? >> '{}';;\n\
         esac\nexec GIT \"$@\"\n",
        lock.display(),
        probe.display()
    ));
    let done = fx.tool(&Call {
        env: Some(env),
        ..Call::default()
    });
    assert_eq!(done.code, 0, "{}", done.shown());
    assert_eq!(read(&probe), "75\n75\n");
    let free = Command::new("/usr/bin/flock")
        .args([OsStr::new("-n"), OsStr::new("-E"), OsStr::new("75")])
        .arg(&lock)
        .arg("/bin/true")
        .status()
        .expect("flock runs");
    assert_eq!(free.code(), Some(0));
}

#[test]
fn a_receipt_directory_another_user_can_write_is_used() {
    let fx = Fixture::new();
    let shared = fx.root.join("shared");
    private_dir(&shared);
    chmod(&shared, 0o777);
    let done = fx.tool(&Call {
        extra: vec![
            "--artifacts".into(),
            shared.join("receipts").into_os_string(),
        ],
        ..Call::default()
    });
    assert_eq!(done.code, 0, "{}", done.shown());
    let (path, receipt) = fx.receipt(&done);
    assert_eq!(
        path.parent().and_then(Path::parent),
        Some(shared.join("receipts").as_path())
    );
    assert_eq!(text(at(&receipt, "result")), "proven");
    let done = fx.tool(&Call {
        env: Some(fx.with_env(&[("CARGO_TARGET_DIR", shared.join("build").as_os_str())])),
        ..Call::default()
    });
    assert_eq!(done.code, 2, "{}", done.shown());
    assert!(
        done.stderr.starts_with(&format!(
            "red-green rejected: another user owns or can write {}",
            shared.display()
        )),
        "{}",
        done.shown()
    );
}

#[test]
fn a_build_directory_made_shared_between_its_two_judgments_is_refused_at_its_creation() {
    let fx = Fixture::new();
    let lineage = fx.root.join("lineage");
    let build = lineage.join("red-green");
    let first = shared_directories_for(&build, me()).expect("the first judgment reads");
    assert_eq!(first, Vec::<std::path::PathBuf>::new());
    let planting = |step: &Path| {
        if step == lineage && status(step)?.is_none() {
            private_dir(step);
            chmod(step, 0o777);
            return Ok(false);
        }
        Ok(status(step)?.is_some())
    };
    let refused = make_private_with(&build, me(), &planting)
        .expect_err("the second judgment finds the planted directory");
    assert!(
        matches!(refused, PrivateError::Shared(ref found) if found == std::slice::from_ref(&lineage)),
        "{refused}"
    );
    let other = fx.root.join("other/red-green");
    let probe = |step: &Path| Ok(status(step)?.is_some());
    assert_eq!(
        make_private_with(&other, me(), &probe).map_err(|e| e.to_string()),
        Ok(())
    );
}

#[test]
fn a_link_planted_between_resolution_and_status_is_rejected() {
    let fx = Fixture::new();
    let receipts = fx.root.join("receipts");
    let planting = |path: &Path| {
        let resolved = paths::resolve(path)?;
        symlink(&resolved, &resolved)?;
        Ok(resolved)
    };
    let rejected = resolved_by(&receipts, planting).expect_err("the status read meets the loop");
    assert!(
        rejected
            .to_string()
            .starts_with("a receipt or build directory cannot be resolved: "),
        "{rejected}"
    );
    let other = fx.root.join("other");
    assert_eq!(resolved_by(&other, paths::resolve), Ok(other.clone()));
}

#[test]
fn a_worktree_path_planted_after_its_removal_is_named_as_not_removed() {
    for (plant, named) in [("mkdir -p \"$5\"; ", true), ("", false)] {
        let fx = Fixture::new();
        let mark = fx.state.join("first-removal");
        let env = fx.git_wrapper(&format!(
            "case \"$*\" in \"worktree remove \"*/base)\n  if [ -e '{0}' ]; then GIT \"$@\"; {plant}exit 1; fi\n  \
             touch '{0}'; echo 'fatal: refused' >&2; exit 1;;\nesac\nexec GIT \"$@\"\n",
            mark.display()
        ));
        let done = fx.tool(&Call {
            env: Some(env),
            ..Call::default()
        });
        assert_eq!(done.code, 0, "{}", done.shown());
        let lines: Vec<&str> = done
            .stderr
            .lines()
            .filter_map(|line| line.strip_prefix("red-green: could not remove worktree "))
            .collect();
        assert_eq!(fx.worktrees(), 1, "{}", done.shown());
        if named {
            let [line] = lines[..] else {
                panic!("one worktree is named: {}", done.shown());
            };
            let tree = line
                .strip_suffix(": ")
                .expect("the removal printed no error");
            assert!(tree.ends_with("/base"), "{line}");
            assert!(Path::new(tree).is_dir());
        } else {
            assert_eq!(lines, Vec::<&str>::new(), "{}", done.shown());
            fx.assert_checkout_unchanged();
        }
    }
}
