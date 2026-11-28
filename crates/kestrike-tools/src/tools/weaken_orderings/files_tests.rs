use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{fresh_write, regular_digest};
use crate::paths::tests::Scratch;

/// A fresh write is a new file, a link beside it named after the file and the staging suffix stays, it
/// keeps the replaced file's mode and takes a time later than that file's, even one in the future; a link
/// at the path is replaced and its target keeps its bytes.
#[test]
fn a_fresh_write_is_a_new_later_file_and_follows_no_link() {
    let scratch = Scratch::new("weaken-fresh");
    let (target, outside) = (scratch.0.join("f.rs"), scratch.0.join("outside"));
    fs::write(&target, "a").expect("written");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).expect("moded");
    fs::write(&outside, "kept").expect("written");
    symlink(&outside, scratch.0.join("f.rs.weaken")).expect("linked");
    let future = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_nanos()
        + 10_000_000_000;
    let stamp = libc::timespec {
        tv_sec: libc::time_t::try_from(future / 1_000_000_000).expect("fits"),
        tv_nsec: libc::c_long::try_from(future % 1_000_000_000).expect("fits"),
    };
    let file = fs::File::open(&target).expect("opens");
    // SAFETY: `file` holds an open descriptor and the two timespecs outlive the call.
    let set = unsafe {
        libc::futimens(
            std::os::fd::AsRawFd::as_raw_fd(&file),
            [stamp, stamp].as_ptr(),
        )
    };
    assert_eq!(set, 0);
    drop(file);
    let inode = fs::metadata(&target).expect("stats").ino();
    fresh_write(&target, "b", None).expect("written");
    let status = fs::symlink_metadata(&target).expect("stats");
    assert_eq!(fs::read_to_string(&target).expect("reads"), "b");
    assert_ne!(status.ino(), inode);
    assert!(status.is_file());
    assert_eq!(status.permissions().mode() & 0o777, 0o640);
    let written = i128::from(status.mtime()) * 1_000_000_000 + i128::from(status.mtime_nsec());
    assert!(
        written > i128::try_from(future).expect("fits"),
        "{written} after {future}"
    );
    assert_eq!(fs::read_to_string(&outside).expect("reads"), "kept");
    let mut names: Vec<String> = fs::read_dir(&scratch.0)
        .expect("lists")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    assert_eq!(names, ["f.rs", "f.rs.weaken", "outside"]);
    let linked = scratch.0.join("g.rs");
    symlink(&outside, &linked).expect("linked");
    fresh_write(&linked, "c", None).expect("written");
    assert!(
        !fs::symlink_metadata(&linked)
            .expect("stats")
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_to_string(&linked).expect("reads"), "c");
    assert_eq!(fs::read_to_string(&outside).expect("reads"), "kept");
}

/// The digest names a regular file alone: a link to one, a directory and a missing path give none.
#[test]
fn a_digest_is_read_from_a_regular_file_and_no_link() {
    let scratch = Scratch::new("weaken-digest");
    let file = scratch.0.join("f");
    fs::write(&file, "x").expect("written");
    assert_eq!(
        regular_digest(&file).as_deref(),
        Some("2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881")
    );
    symlink(&file, scratch.0.join("l")).expect("linked");
    assert_eq!(regular_digest(&scratch.0.join("l")), None);
    assert_eq!(regular_digest(&scratch.0), None);
    assert_eq!(regular_digest(&scratch.0.join("absent")), None);
}

/// A fresh write over a file with a time in the past takes the wall clock's time, read around the write.
#[test]
fn a_fresh_write_over_an_old_file_takes_the_wall_clock() {
    let scratch = Scratch::new("weaken-fresh-clock");
    let target = scratch.0.join("old.rs");
    fs::write(&target, "a").expect("written");
    let past = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
    fs::File::options()
        .write(true)
        .open(&target)
        .expect("opens")
        .set_modified(past)
        .expect("timed");
    let before = SystemTime::now();
    fresh_write(&target, "b", None).expect("written");
    let after = SystemTime::now();
    let written = fs::metadata(&target)
        .expect("stats")
        .modified()
        .expect("a time");
    let slack = std::time::Duration::from_millis(20);
    assert!(
        written + slack >= before && written <= after + slack,
        "{written:?}"
    );
}
