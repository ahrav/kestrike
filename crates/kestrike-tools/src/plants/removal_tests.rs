//! The removal of a run's directory: past what it cannot remove, through links inside the tree, past
//! `PATH_MAX`, under a parent it cannot read, and within its depth bound.

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{PermissionsExt, symlink};

use super::{REMOVAL_DEPTH, remove, remove_with};
use crate::paths::tests::Scratch;

/// The removal goes past an entry it cannot remove, removes the rest, and leaves a link at its path.
#[test]
fn a_removal_goes_past_what_it_cannot_remove_and_leaves_a_link() {
    let scratch = Scratch::new("remove");
    let tree = scratch.0.join("tree");
    fs::create_dir_all(tree.join("pinned")).expect("made");
    fs::create_dir_all(tree.join("free")).expect("made");
    fs::write(tree.join("pinned/file"), "held").expect("written");
    fs::write(tree.join("free/file"), "free").expect("written");
    fs::set_permissions(tree.join("pinned"), fs::Permissions::from_mode(0o500)).expect("chmod");
    let link = scratch.0.join("link");
    symlink(&tree, &link).expect("linked");
    remove(&link);
    assert!(
        fs::symlink_metadata(&link).is_ok() && tree.join("free").exists(),
        "a link stays as it is"
    );
    remove(&tree);
    // SAFETY: `geteuid` takes no argument and always succeeds.
    let root = unsafe { libc::geteuid() } == 0;
    assert!(!tree.join("free").exists());
    assert_eq!(tree.join("pinned/file").exists(), !root);
    fs::set_permissions(tree.join("pinned"), fs::Permissions::from_mode(0o700)).ok();
}

/// The removal walk treats directory symlinks as leaves.
#[test]
fn a_removal_removes_a_link_inside_the_tree_and_keeps_its_target() {
    let scratch = Scratch::new("remove-inner-link");
    let (tree, outside) = (scratch.0.join("tree"), scratch.0.join("outside"));
    fs::create_dir_all(tree.join("inner")).expect("made");
    fs::create_dir_all(&outside).expect("made");
    fs::write(outside.join("sentinel"), "kept").expect("written");
    symlink(&outside, tree.join("inner/link")).expect("linked");
    remove(&tree);
    assert!(!tree.exists());
    assert_eq!(
        fs::read_to_string(outside.join("sentinel")).expect("reads"),
        "kept"
    );
}

/// Each level adds a 200-byte name and a slash to the path, so some 22 levels pass `PATH_MAX` and the
/// removal holds about 25 descriptors; directory-relative calls let the test build past `PATH_MAX`.
#[test]
fn a_removal_reaches_a_path_past_path_max() {
    let scratch = Scratch::new("remove-deep");
    let tree = scratch.0.join("tree");
    fs::create_dir(&tree).expect("made");
    let mut parent = fs::File::open(&tree).expect("opens");
    let name = std::ffi::CString::new("d".repeat(200)).expect("a name");
    let depth = usize::try_from(libc::PATH_MAX).expect("a bound") / 201 + 2;
    for _ in 0..depth {
        // SAFETY: `parent` is an open directory and `name` a NUL-terminated string.
        let made = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        assert_eq!(made, 0, "{}", std::io::Error::last_os_error());
        // SAFETY: `parent` is an open directory and `name` a NUL-terminated string.
        let next = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(next >= 0, "{}", std::io::Error::last_os_error());
        // SAFETY: `next` is a new open descriptor that this loop alone owns.
        parent = unsafe { fs::File::from_raw_fd(next) };
    }
    // SAFETY: `parent` is an open directory and the name a NUL-terminated literal.
    let file = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c"file".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC,
            0o600,
        )
    };
    assert!(file >= 0, "{}", std::io::Error::last_os_error());
    // SAFETY: `file` is a new open descriptor, closed here once.
    unsafe { libc::close(file) };
    drop(parent);
    remove(&tree);
    assert!(!tree.exists());
}

/// A directory put at the root's path between the status read and the open has another inode, so the
/// removal leaves it and its entries as they are.
#[test]
fn a_root_substituted_after_its_status_read_stays() {
    let scratch = Scratch::new("remove-swap");
    let tree = scratch.0.join("tree");
    let moved = scratch.0.join("moved");
    fs::create_dir(&tree).expect("made");
    fs::write(tree.join("first"), "first").expect("written");
    remove_with(&tree, || {
        fs::rename(&tree, &moved).expect("moved");
        fs::create_dir(&tree).expect("made again");
        fs::write(tree.join("marker"), "kept").expect("written");
    });
    assert_eq!(
        fs::read_to_string(tree.join("marker")).expect("reads"),
        "kept"
    );
    assert_eq!(
        fs::read_to_string(moved.join("first")).expect("reads"),
        "first"
    );
}

/// The walk goes [`REMOVAL_DEPTH`] levels below the root: the directory one level deeper stays, with
/// the levels above it.
#[test]
fn a_removal_leaves_what_lies_past_its_depth_bound() {
    let scratch = Scratch::new("remove-bound");
    let tree = scratch.0.join("tree");
    fs::create_dir(&tree).expect("made");
    let mut parent = fs::File::open(&tree).expect("opens");
    for _ in 0..=REMOVAL_DEPTH {
        // SAFETY: `parent` is an open directory and the name a NUL-terminated literal.
        let made = unsafe { libc::mkdirat(parent.as_raw_fd(), c"d".as_ptr(), 0o700) };
        assert_eq!(made, 0, "{}", std::io::Error::last_os_error());
        // SAFETY: `parent` is an open directory and the name a NUL-terminated literal.
        let next = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c"d".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(next >= 0, "{}", std::io::Error::last_os_error());
        // SAFETY: `next` is a new open descriptor that this loop alone owns.
        parent = unsafe { fs::File::from_raw_fd(next) };
    }
    drop(parent);
    remove(&tree);
    assert!(tree.join("d").exists(), "the levels above the bound stay");
    let mut deepest = tree.clone();
    for _ in 0..=REMOVAL_DEPTH {
        deepest.push("d");
    }
    assert!(deepest.exists(), "the level past the bound stays");
}

/// The parent of the removed directory is opened for its path alone, so a parent this user may search
/// and write and may not read still lets the directory go.
#[test]
fn a_removal_goes_through_a_parent_it_cannot_read() {
    // SAFETY: `geteuid` takes no argument and always succeeds.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let scratch = Scratch::new("remove-unreadable-parent");
    let parent = scratch.0.join("parent");
    let tree = parent.join("tree");
    fs::create_dir_all(tree.join("inner")).expect("made");
    fs::write(tree.join("inner/file"), "gone").expect("written");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o300)).expect("chmod");
    remove(&tree);
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).expect("chmod");
    assert!(
        !tree.exists(),
        "the directory went through a parent of mode 0300"
    );
}
