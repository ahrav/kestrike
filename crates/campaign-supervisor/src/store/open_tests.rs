//! Startup: the lock, the startup barrier, the staging sweep and the state
//! marker, against real state directories on the Cargo target directory's
//! filesystem.

use std::fs::{self, DirBuilder};
use std::os::unix::fs::symlink;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::fixture::{Case, Snapshot, name, observed, recovered, replace, scripted, snapshot};
use super::{Error, Refusal, Store, Unreadable};
use crate::exit::{Exit, Supervisor};
use crate::step::{Outcome, Step};
use crate::sys;

/// A second controller on a locked state directory gets `Busy`, which
/// exits 3, leaves the holder's staged file and every other entry
/// unchanged, and opens once the first controller is gone. The lock is
/// taken on the state directory's own handle, so this holds on whatever
/// filesystem holds the target directory.
#[test]
fn a_second_controller_exits_3_while_the_first_holds_the_lock() {
    let case = Case::new();
    let first = Store::open(&case.state).expect("the first controller opens");
    fs::write(
        case.state.join(".staging/00000000000000ff.record"),
        b"staged",
    )
    .expect("a staged file is planted");
    let before = snapshot(&case.state);
    let second = Store::open(&case.state);
    assert!(matches!(second, Err(Error::Busy)));
    assert_eq!(Exit::Supervisor(second.unwrap_err().exit()).code(), 3);
    assert_eq!(snapshot(&case.state), before);
    drop(first);
    Store::open(&case.state).expect("the lock is free once the holder closes");
}

/// Startup syncs the state directory and its parent before its first
/// mutation, on a fresh directory and on a marked one holding a record, so
/// no record is acknowledged in a directory entry a crash or VM reset can
/// drop.
#[test]
fn startup_syncs_the_directory_and_its_parent_before_any_mutation() {
    for marked in [false, true] {
        let case = Case::new();
        if marked {
            let store = Store::open(&case.state).expect("the store initializes");
            store
                .create_once(store.root(), &name("record"), b"record")
                .expect("the record is created");
        }
        let (opened, reached) = scripted(None, || Store::open(&case.state));
        opened.expect("the open ran").expect("the store opens");
        let mutates = |step: &Step| {
            matches!(
                step,
                Step::Mkdir | Step::Unlink | Step::Write | Step::Rename
            )
        };
        let first = reached
            .iter()
            .position(mutates)
            .expect("startup mutates the directory");
        let syncs = reached[..first]
            .iter()
            .filter(|&&step| step == Step::Sync)
            .count();
        assert_eq!(syncs, 2, "marked {marked}: {reached:?}");
    }
}

/// A state directory that holds entries but no marker, such as a `jobs`
/// directory, is refused before the store writes anything into it. So is
/// an unmarked directory whose only entry is a `.staging` directory
/// holding a file an interrupted startup never leaves.
#[test]
fn a_directory_with_jobs_and_no_marker_is_refused_unchanged() {
    let case = Case::new();
    fs::create_dir(case.state.join("jobs")).expect("the jobs directory is made");
    let before = snapshot(&case.state);
    let refused = Store::open(&case.state);
    assert!(
        matches!(refused, Err(Error::Refused(Refusal::Unmarked))),
        "{refused:?}"
    );
    assert_eq!(snapshot(&case.state), before);
}

/// An unmarked directory whose only entry is a `.staging` directory is
/// refused unchanged when that directory holds a name an interrupted
/// startup never leaves: a foreign file, or a name that only resembles the
/// marker's staged file of this root, with another inode's prefix, a
/// non-hex prefix, or this root's prefix and another suffix.
#[test]
fn a_foreign_staged_name_is_refused_unchanged() {
    let ino = |case: &Case| fs::metadata(&case.state).expect("the state stats").ino();
    let names: [fn(u64) -> String; 4] = [
        |_| "report.json".into(),
        |ino| format!("{:016x}..state", ino + 1),
        |_| "abcdefghijklmnopq..state".into(),
        |ino| format!("{ino:016x}..stat"),
    ];
    for staged in names {
        let case = Case::new();
        let staged = staged(ino(&case));
        fs::create_dir(case.state.join(".staging")).expect("the staging directory is made");
        fs::write(case.state.join(".staging").join(&staged), b"x").expect("a file is planted");
        let before = snapshot(&case.state);
        let refused = Store::open(&case.state);
        assert!(
            matches!(refused, Err(Error::Refused(Refusal::Unmarked))),
            "{staged}: {refused:?}"
        );
        assert_eq!(snapshot(&case.state), before, "{staged}");
    }
}

/// A `.state` directory or a `.staging` symlink is an unreadable store
/// entry: the open exits 4 and leaves the directory, the symlink and its
/// target unchanged.
#[test]
fn a_store_entry_of_the_wrong_kind_is_unreadable() {
    let case = Case::new();
    fs::create_dir(case.state.join(".state")).expect("the directory is made");
    let before = snapshot(&case.state);
    let refused = Store::open(&case.state);
    assert!(
        matches!(&refused, Err(Error::Unreadable(Unreadable::NotRegular))),
        "{refused:?}"
    );
    assert_eq!(refused.unwrap_err().exit(), Supervisor::Held);
    assert_eq!(snapshot(&case.state), before);
    let case = Case::new();
    let elsewhere = case.root.join("elsewhere");
    fs::create_dir(&elsewhere).expect("the directory is made");
    symlink(&elsewhere, case.state.join(".staging")).expect("the link is made");
    let refused = Store::open(&case.state);
    assert!(
        matches!(&refused, Err(Error::Unreadable(Unreadable::Symlink))),
        "{refused:?}"
    );
    assert_eq!(refused.unwrap_err().exit(), Supervisor::Held);
    let link = fs::read_link(case.state.join(".staging")).expect("the symlink stays");
    assert_eq!(link, elsewhere);
    assert!(snapshot(&elsewhere).is_empty());
    assert_eq!(
        fs::read_dir(&case.state).expect("the state lists").count(),
        1
    );
}

/// A state directory replaced during startup fails the open with
/// `Replaced`, exit 4, and the replacement stays empty.
#[test]
fn a_state_directory_replaced_during_startup_fails_the_open() {
    let case = Case::new();
    let (state, old) = (case.state.clone(), case.root.join("old"));
    let mut moved = false;
    let observe = move |at| {
        if at == Step::Rename && !moved {
            moved = true;
            replace(&state, &old);
        }
    };
    let opened = observed(observe, || Store::open(&case.state));
    assert!(matches!(&opened, Err(Error::Replaced)), "{opened:?}");
    assert_eq!(opened.unwrap_err().exit(), Supervisor::Held);
    assert!(snapshot(&case.state).is_empty());
}

/// On a marked directory, a probe destination already present when the
/// startup probe renames fails the no-replace rename with `EEXIST` and
/// keeps its bytes, so the probe distinguishes no-replace rename from a
/// plain one.
#[test]
fn the_startup_probe_renames_without_replacing() {
    let case = Case::new();
    drop(Store::open(&case.state).expect("the store initializes"));
    let probed = case.state.join(".staging/probed");
    let planted = probed.clone();
    let observe = move |at| {
        if at == Step::Rename {
            fs::write(&planted, b"planted").expect("the destination is planted");
        }
    };
    let opened = observed(observe, || Store::open(&case.state));
    let exists = std::io::ErrorKind::AlreadyExists;
    assert!(
        matches!(&opened, Err(Error::Io(error)) if error.kind() == exists),
        "{opened:?}"
    );
    assert_eq!(
        fs::read(&probed).expect("the destination stays"),
        b"planted"
    );
}

/// A store opened through a relative path keeps checking the directory it
/// locked after the working directory changes, because it holds the
/// absolute path.
#[test]
fn a_relative_path_names_the_same_directory_after_a_directory_change() {
    let case = Case::new();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            sys::private_fs(0o077).expect("the thread gets its own working directory");
            std::env::set_current_dir(&case.root).expect("the working directory changes");
            let store = Store::open("state".as_ref()).expect("the relative path opens");
            std::env::set_current_dir(&case.state).expect("the working directory changes");
            store
                .create_once(store.root(), &name("record"), b"record")
                .expect("the publication is acknowledged");
        });
    });
    assert_eq!(
        fs::read(case.state.join("record")).expect("it reads"),
        b"record"
    );
}

/// An empty directory gains the marker, a marker of other bytes is
/// refused, and a marked directory opens unchanged.
#[test]
fn the_marker_is_written_once_and_checked_on_every_open() {
    let case = Case::new();
    drop(Store::open(&case.state).expect("an empty directory initializes"));
    assert_eq!(
        fs::read(case.state.join(".state")).expect("the marker exists"),
        super::MARKER_BYTES
    );
    let marked = snapshot(&case.state);
    drop(Store::open(&case.state).expect("a marked directory opens"));
    assert_eq!(snapshot(&case.state), marked);
    fs::write(case.state.join(".state"), b"other\n").expect("the marker is overwritten");
    assert!(matches!(
        Store::open(&case.state),
        Err(Error::Refused(Refusal::Marker))
    ));
}

/// Staged files a crash left are removed at startup and never listed; a
/// staging directory past its sweep bound holds the state with exit 4.
#[test]
fn startup_sweeps_staged_files_within_its_bound() {
    let case = Case::new();
    drop(Store::open(&case.state).expect("the store initializes"));
    let staging = case.state.join(".staging");
    fs::write(staging.join("00000000000000ff.record"), b"partial")
        .expect("a staged file is planted");
    let store = Store::open(&case.state).expect("the store reopens");
    assert_eq!(
        fs::read_dir(&staging)
            .expect("the staging directory lists")
            .count(),
        0
    );
    // The marker and the staging directory are dot-named, so the root
    // lists no entry.
    assert_eq!(store.list(store.root(), 8).expect("the root lists"), []);
    drop(store);
    for index in 0..=super::SWEEP_BOUND {
        fs::write(staging.join(format!("{index:016x}.record")), b"")
            .expect("a staged file is planted");
    }
    let refused = Store::open(&case.state);
    assert!(matches!(refused, Err(Error::ScanBound)), "{refused:?}");
    assert_eq!(refused.unwrap_err().exit(), Supervisor::Held);
}

/// A missing state directory, a directory of another mode, a symlink at
/// the state path and a directory on another filesystem type are refused,
/// and the missing one is never created.
#[test]
fn missing_paths_wrong_modes_symlinks_and_filesystems_are_refused() {
    let case = Case::new();
    let missing = Store::open(&case.root.join("missing"));
    assert!(
        matches!(&missing, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound),
        "{missing:?}"
    );
    assert!(!case.root.join("missing").exists());
    fs::set_permissions(&case.state, fs::Permissions::from_mode(0o750)).expect("the mode changes");
    assert!(matches!(
        Store::open(&case.state),
        Err(Error::Refused(Refusal::Mode(0o750)))
    ));
    let real = case.root.join("real");
    DirBuilder::new()
        .mode(0o700)
        .create(&real)
        .expect("the directory is made");
    symlink(&real, case.root.join("link")).expect("the symlink is made");
    // `O_NOFOLLOW` with `O_DIRECTORY` refuses a symlink with `ENOTDIR`,
    // and a trailing separator or `.` still names the symlink itself.
    for spelling in ["link", "link/", "link/."] {
        let linked = Store::open(&case.root.join(spelling));
        assert!(
            matches!(&linked, Err(Error::Io(error)) if error.raw_os_error() == Some(libc::ENOTDIR)),
            "{spelling}: {linked:?}"
        );
    }
    assert_eq!(fs::read_dir(&real).expect("the target lists").count(), 0);
    let proc = Store::open("/proc".as_ref());
    assert!(
        matches!(proc, Err(Error::Refused(Refusal::Filesystem(ref fstype))) if fstype == "proc"),
        "{proc:?}"
    );
}

/// A fault or a kill at every startup step leaves a directory the next
/// startup opens, two recoveries in a row reach the same state holding only
/// the marker, the staging directory and any prior record, and the marker
/// holds its bytes. An interrupted step is retried and the open succeeds,
/// except at `close`. The sweep runs on a fresh directory and on a
/// marked one that holds a record and a staged file a crash left, whose
/// record keeps its bytes and whose staged file is gone.
#[test]
fn startup_recovers_from_a_fault_at_every_step() {
    let fresh: fn(&Path) = |_| {};
    let marked: fn(&Path) = |state| {
        let store = Store::open(state).expect("the store initializes");
        store
            .create_once(store.root(), &name("record"), b"record")
            .expect("the record is created");
        drop(store);
        fs::write(state.join(".staging/00000000000000ff.record"), b"partial")
            .expect("a staged file is planted");
    };
    for prepare in [fresh, marked] {
        let steps = {
            let case = Case::new();
            prepare(&case.state);
            scripted(None, || Store::open(&case.state)).1
        };
        for (index, &at) in steps.iter().enumerate() {
            for outcome in [
                Outcome::Errno(libc::EIO),
                Outcome::Kill,
                Outcome::Errno(libc::EINTR),
            ] {
                let case = Case::new();
                prepare(&case.state);
                let record = fs::read(case.state.join("record")).ok();
                let (opened, reached) =
                    scripted(Some((index, outcome)), || Store::open(&case.state));
                assert!(
                    reached.len() > index,
                    "step {index}: the fault was never reached"
                );
                // An interrupted step is retried, except `close`, which
                // fails the open like any other error.
                let retried = outcome == Outcome::Errno(libc::EINTR) && at != Step::Close;
                let context = format!("step {index} {outcome:?}");
                if let Some(opened) = opened {
                    assert_eq!(opened.is_ok(), retried, "{context}");
                }
                let expected_steps = if retried { steps.len() + 1 } else { index + 1 };
                assert_eq!(reached.len(), expected_steps, "{context}: {reached:?}");
                let mut expected = Snapshot::from([
                    (PathBuf::from(".staging"), None),
                    (PathBuf::from(".state"), Some(super::MARKER_BYTES.to_vec())),
                ]);
                if let Some(record) = &record {
                    expected.insert(PathBuf::from("record"), Some(record.clone()));
                }
                assert_eq!(recovered(&case.state, &context), expected, "{context}");
            }
        }
    }
}

#[test]
fn a_mode_changed_store_refuses_publication_and_stays_poisoned() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("store");
    fs::set_permissions(&case.state, fs::Permissions::from_mode(0o750)).expect("changed mode");
    assert!(matches!(
        store.create_once(store.root(), &name("record"), b"data"),
        Err(Error::Refused(Refusal::Mode(0o750)))
    ));
    assert!(!case.state.join("record").exists());
    fs::set_permissions(&case.state, fs::Permissions::from_mode(0o700)).expect("private mode");
    assert!(matches!(
        store.create_once(store.root(), &name("record"), b"data"),
        Err(Error::Poisoned)
    ));
}
