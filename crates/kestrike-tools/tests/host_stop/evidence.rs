//! The evidence lock, the probe of a directory for unnamed files, and the lookup of an entry.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use kestrike_tools::host_stop::{Disk, LockError, ProbeError, lock, probe, stands};

use super::{Fault, Observed, PLACE, ROLE, Scratch, listing, passed, start_window};

/// `held_twice` takes the lock of a new directory under `place`, is refused twice, drops the lock and
/// takes it again.
fn held_twice(place: &Path) {
    let directory = place.join("injection");
    fs::create_dir(&directory).expect("the directory is made");
    let first = lock(&Disk, &directory).expect("the first holder locks");
    for _ in 0..2 {
        match lock(&Disk, &directory) {
            Err(LockError::Taken(error)) => {
                assert_eq!(error.raw_os_error(), Some(libc::EWOULDBLOCK));
            }
            other => panic!("{other:?}"),
        }
    }
    drop(first);
    let second = lock(&Disk, &directory).expect("the lock is free once dropped");
    drop(second);
    assert_eq!(
        listing(&directory),
        Vec::<String>::new(),
        "the lock adds no file"
    );
}

/// A second holder of a directory's lock gets the system's `EWOULDBLOCK` at once, and the lock frees
/// when its value drops. The case runs in a process of its own: a child another test thread forks
/// shares the lock's open file description until its `exec`, which would hold the lock past the drop.
#[test]
fn a_second_holder_is_refused_and_the_lock_frees_on_drop() {
    if let (Some(_), Some(place)) = (std::env::var_os(ROLE), std::env::var_os(PLACE)) {
        held_twice(Path::new(&place));
        return;
    }
    let scratch = Scratch::new("lock");
    let output = start_window(
        "host_stop::evidence::a_second_holder_is_refused_and_the_lock_frees_on_drop",
        "lock",
        &scratch.0,
        "",
    )
    .output()
    .expect("the window starts");
    passed("lock", &output);
    assert!(
        scratch.0.join("injection").is_dir(),
        "the window ran its checks"
    );
}

/// The lock opens the directory without following a link, so a link to a directory (`ENOTDIR`) and a missing
/// directory are both failures of the open, and neither takes the lock.
#[test]
fn the_lock_opens_the_directory_without_following_a_link() {
    let scratch = Scratch::new("lock-open");
    let directory = scratch.dir("real");
    symlink(&directory, scratch.0.join("link")).expect("the link is made");
    for (path, errno) in [("link", libc::ENOTDIR), ("missing", libc::ENOENT)] {
        let files = Observed::default();
        match lock(&files, &scratch.0.join(path)) {
            Err(LockError::Open(error)) => assert_eq!(error.raw_os_error(), Some(errno), "{path}"),
            other => panic!("{path}: {other:?}"),
        }
        assert_eq!(files.steps(), ["open_directory"], "{path}");
    }
    let interrupted = Observed::failing(&[Fault {
        step: "try_lock",
        nth: 1,
        errno: libc::EINTR,
    }]);
    let held = lock(&interrupted, &directory).expect("an interrupted flock runs again");
    assert_eq!(
        interrupted.steps(),
        ["open_directory", "try_lock", "try_lock"]
    );
    drop(held);
}

/// The probe passes on a directory that takes an unnamed file whose `/proc/self/fd` path resolves, and
/// leaves no entry; it fails when the unnamed file cannot open, with the system's error, and when its
/// path does not resolve, naming that path.
#[test]
fn the_probe_refuses_a_directory_without_unnamed_files_or_their_link() {
    let scratch = Scratch::new("probe");
    let root = scratch.dir("evidence");
    let files = Observed::default();
    probe(&files, &root).expect("the directory takes unnamed files");
    assert_eq!(files.steps(), ["open_unnamed", "exists"]);
    let seen = files.seen();
    assert_eq!(seen[0].path.as_deref(), Some(root.as_path()));
    let unnamed = seen[0].fds[0];
    assert_eq!(
        seen[1].path.as_deref(),
        Some(Path::new(&format!("/proc/self/fd/{unnamed}"))),
        "the probe resolves the unnamed file's own descriptor"
    );
    assert_eq!(listing(&root), Vec::<String>::new());
    let unsupported = Observed::failing(&[Fault {
        step: "open_unnamed",
        nth: 1,
        errno: libc::EOPNOTSUPP,
    }]);
    match probe(&unsupported, &root) {
        Err(ProbeError::Unnamed(error)) => assert_eq!(error.raw_os_error(), Some(libc::EOPNOTSUPP)),
        other => panic!("{other:?}"),
    }
    assert_eq!(unsupported.steps(), ["open_unnamed"]);
    let unresolved = Observed::failing(&[Fault {
        step: "exists",
        nth: 1,
        errno: libc::ENOENT,
    }]);
    match probe(&unresolved, &root) {
        Err(ProbeError::Unresolved(path)) => {
            let seen = unresolved.seen();
            let unnamed = seen[0].fds[0];
            assert_eq!(path, Path::new(&format!("/proc/self/fd/{unnamed}")));
            assert_eq!(seen[1].path.as_deref(), Some(path.as_path()));
        }
        other => panic!("{other:?}"),
    }
    fs::write(root.join("file"), b"x").expect("the file is made");
    match probe(&Disk, &root.join("file")) {
        Err(ProbeError::Unnamed(error)) => assert_eq!(error.raw_os_error(), Some(libc::ENOTDIR)),
        other => panic!("{other:?}"),
    }
}

/// The lookup reads a link as an entry: a file and a dangling link stand, a missing name does not, and
/// a lookup that fails otherwise returns its error.
#[test]
fn the_lookup_answers_stands_absent_or_its_error() {
    let scratch = Scratch::new("lookup");
    let base = &scratch.0;
    fs::write(base.join("file"), b"x").expect("the file is made");
    symlink("missing", base.join("dangling")).expect("the link is made");
    assert!(stands(&Disk, &base.join("file")).expect("looks up"));
    assert!(stands(&Disk, &base.join("dangling")).expect("looks up"));
    assert!(!stands(&Disk, &base.join("missing")).expect("looks up"));
    let failed = stands(&Disk, &base.join("file/below")).expect_err("a file has no entries");
    assert_eq!(failed.raw_os_error(), Some(libc::ENOTDIR));
    let planted = Observed::failing(&[Fault {
        step: "lstat",
        nth: 1,
        errno: libc::EACCES,
    }]);
    let denied = stands(&planted, Path::new(&base.join("file"))).expect_err("the planted error");
    assert_eq!(denied.raw_os_error(), Some(libc::EACCES));
}

/// A lock reads the directory it holds as the one at its name, with one `lstat` of that path through
/// the file steps it is given. A directory removed and made again at the name reads as another, since
/// the held descriptor keeps the first inode number in use; a lock taken on the new directory reads
/// it as itself. A sibling directory and a link at the name to the locked directory read as another,
/// and a name with no entry and a lookup that fails return the lookup's error.
#[test]
fn a_lock_reads_its_directory_at_the_name_as_itself_and_one_made_again_there_as_another() {
    let scratch = Scratch::new("lock-name");
    let directory = scratch.dir("injection");
    let held = lock(&Disk, &directory).expect("the holder locks");
    let files = Observed::default();
    assert!(held.stands_at(&files, &directory).expect("looks up"));
    assert_eq!(files.steps(), ["lstat"]);
    assert_eq!(files.seen()[0].path.as_deref(), Some(directory.as_path()));
    let sibling = scratch.dir("sibling");
    assert!(!held.stands_at(&Disk, &sibling).expect("looks up"));

    fs::remove_dir(&directory).expect("the directory is removed");
    let missing = held
        .stands_at(&Disk, &directory)
        .expect_err("no entry stands at the name");
    assert_eq!(missing.raw_os_error(), Some(libc::ENOENT));
    fs::create_dir(&directory).expect("the directory is made again");
    assert!(!held.stands_at(&Disk, &directory).expect("looks up"));
    let again = lock(&Disk, &directory).expect("the new directory's lock is free");
    assert!(again.stands_at(&Disk, &directory).expect("looks up"));

    let planted = Observed::failing(&[Fault {
        step: "lstat",
        nth: 1,
        errno: libc::EACCES,
    }]);
    let denied = again
        .stands_at(&planted, &directory)
        .expect_err("the planted error");
    assert_eq!(denied.raw_os_error(), Some(libc::EACCES));
    fs::rename(&directory, scratch.0.join("moved")).expect("the directory is renamed");
    symlink("moved", &directory).expect("the link is made");
    assert!(!again.stands_at(&Disk, &directory).expect("looks up"));
    assert!(
        again
            .stands_at(&Disk, &scratch.0.join("moved"))
            .expect("looks up")
    );
}
