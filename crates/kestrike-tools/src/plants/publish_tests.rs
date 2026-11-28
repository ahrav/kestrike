//! The score's write: through a new staging file beside the target, renamed over it, with mode 0666
//! less the umask; a write that fails leaves no staging file. And the removal of a run's directory.

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{PermissionsExt, symlink};

use std::io::Write;

use super::{Creation, UNANNOUNCED, conclude, publish, publish_with, staging_with};
use crate::paths::tests::Scratch;
use crate::plants::run::{REMOVAL_DEPTH, remove, remove_with};

fn umask() -> u32 {
    let status = fs::read_to_string("/proc/thread-self/status").expect("the status reads");
    let line = status
        .lines()
        .find(|line| line.starts_with("Umask:"))
        .expect("a Umask line");
    u32::from_str_radix(line.trim_start_matches("Umask:").trim(), 8).expect("an octal umask")
}

fn staged(dir: &std::path::Path) -> usize {
    fs::read_dir(dir)
        .expect("lists")
        .filter(|entry| {
            entry
                .as_ref()
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".score.json.")
        })
        .count()
}

/// A link at the score's path is replaced and its target stays; the score takes mode 0666 less the
/// umask, and no staging file stays.
#[test]
fn a_score_replaces_a_link_and_takes_its_mode() {
    let scratch = Scratch::new("publish");
    let (target, elsewhere) = (scratch.0.join("score.json"), scratch.0.join("elsewhere"));
    fs::write(&elsewhere, "kept\n").expect("written");
    symlink(&elsewhere, &target).expect("linked");
    publish(&target, "{}\n").expect("the score is written");
    assert_eq!(fs::read_to_string(&target).expect("reads"), "{}\n");
    assert_eq!(fs::read_to_string(&elsewhere).expect("reads"), "kept\n");
    let mode = fs::symlink_metadata(&target)
        .expect("stats")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o666 & !umask());
    assert_eq!(staged(&scratch.0), 0);
}

/// A file published with a creation mode takes the permission bits of any file created there with that
/// mode, as `elsewhere` is, whether the kernel applies the umask or the directory's default ACL, and
/// replaces a link at its path while the link's target stays.
#[test]
fn a_file_published_with_a_creation_mode_takes_the_bits_of_a_file_created_beside_it() {
    let scratch = Scratch::new("publish-mode");
    let (target, elsewhere) = (scratch.0.join("report.json"), scratch.0.join("elsewhere"));
    fs::write(&elsewhere, "kept\n").expect("written");
    symlink(&elsewhere, &target).expect("linked");
    publish_with(&target, "{}\n", Creation::Mode(0o666)).expect("the report is written");
    assert_eq!(fs::read_to_string(&target).expect("reads"), "{}\n");
    assert_eq!(fs::read_to_string(&elsewhere).expect("reads"), "kept\n");
    let status = fs::symlink_metadata(&target).expect("stats");
    assert!(status.is_file());
    let control = fs::metadata(&elsewhere)
        .expect("stats")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(status.permissions().mode() & 0o777, control);
    let leftover = fs::read_dir(&scratch.0)
        .expect("lists")
        .filter(|entry| {
            let name = entry.as_ref().expect("an entry").file_name();
            name.to_string_lossy().starts_with(".report.json.")
        })
        .count();
    assert_eq!(leftover, 0);
}

#[test]
fn a_score_takes_the_publishing_thread_s_mask() {
    let scratch = Scratch::new("publish");
    let target = scratch.0.join("score.json");
    let mode = std::thread::spawn(move || {
        // SAFETY: on success, `unshare(CLONE_FS)` gives the calling thread a private filesystem
        // context.
        let unshared = unsafe { libc::unshare(libc::CLONE_FS) };
        assert_eq!(
            unshared, 0,
            "the thread takes a filesystem context of its own"
        );
        // SAFETY: `umask` sets the mask of the private context unshared above.
        unsafe { libc::umask(0o077) };
        publish(&target, "{}\n").expect("the score is written");
        fs::symlink_metadata(&target)
            .expect("stats")
            .permissions()
            .mode()
            & 0o777
    })
    .join()
    .expect("the thread ends");
    assert_eq!(mode, 0o600);
}

/// A staging name that is taken, by a regular file or by a link, is left as it is, and the next name
/// drawn takes the staging file.
#[test]
fn a_taken_staging_name_is_left_as_it_is() {
    let scratch = Scratch::new("publish-taken");
    let target = scratch.0.join("score.json");
    let elsewhere = scratch.0.join("elsewhere");
    fs::write(&elsewhere, "outside\n").expect("written");
    fs::write(scratch.0.join(".score.json.aaaaaaaa"), "taken\n").expect("written");
    symlink(&elsewhere, scratch.0.join(".score.json.bbbbbbbb")).expect("linked");
    let mut names = b"abc".iter().copied();
    let (path, mut file) = staging_with(&target, 0o600, |letters| {
        letters.fill(names.next().expect("three names are drawn at most"));
        Ok(())
    })
    .expect("a free name is found");
    assert_eq!(path, scratch.0.join(".score.json.cccccccc"));
    file.write_all(b"staged\n").expect("written");
    assert_eq!(
        fs::read_to_string(scratch.0.join(".score.json.aaaaaaaa")).expect("reads"),
        "taken\n"
    );
    let link = scratch.0.join(".score.json.bbbbbbbb");
    assert!(
        fs::symlink_metadata(&link)
            .expect("stats")
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_to_string(&elsewhere).expect("reads"), "outside\n");
    assert_eq!(fs::read_to_string(&path).expect("reads"), "staged\n");
}

/// A directory at the score's path fails the write, which leaves the directory and no staging file.
#[test]
fn a_score_that_cannot_be_renamed_leaves_no_staging_file() {
    let scratch = Scratch::new("publish-blocked");
    let target = scratch.0.join("score.json");
    fs::create_dir(&target).expect("made");
    let error = publish(&target, "{}\n").expect_err("a directory takes no score");
    assert!(error.to_string().contains("score.json"), "{error}");
    assert!(target.is_dir());
    assert_eq!(staged(&scratch.0), 0);
}

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

struct Refusing;

impl Write for Refusing {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from_raw_os_error(libc::EPIPE))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `publish` renames the staging file over the target before `conclude` writes the score lines to
/// standard output.
#[test]
fn a_refused_write_of_the_score_s_lines_exits_120_and_keeps_the_score() {
    let scratch = Scratch::new("announce");
    let target = scratch.0.join("score.json");
    let mut err = Vec::new();
    let code = conclude("h", &target, &[], "{}\n", publish, &mut Refusing, &mut err);
    assert_eq!(code, UNANNOUNCED);
    assert_eq!(fs::read_to_string(&target).expect("reads"), "{}\n");
    assert!(err.is_empty());
}
