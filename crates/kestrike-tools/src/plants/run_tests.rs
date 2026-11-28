//! `listed` splits the listing at a form feed as at a line feed, so a worktree path that holds a form
//! feed matches no line of `git worktree list --porcelain`.

use std::path::Path;

use super::{listed, lock_bytes, open_lock};

#[test]
fn a_listed_path_with_a_form_feed_matches_no_line() {
    let plain = Path::new("/work/plants/p-a/tree");
    assert!(listed("worktree /work/plants/p-a/tree\nHEAD 0\n", plain));
    let fed = Path::new("/work/plants/p-\u{c}a/tree");
    assert!(!listed(
        "worktree /work/plants/p-\u{c}a/tree\nHEAD 0\n",
        fed
    ));
}

/// The lockfile check opens a FIFO with no writer without blocking, refuses a link, and reads a file of
/// a tebibyte's length only one byte past the run's lockfile.
#[test]
fn the_lockfile_check_reads_one_regular_file_through_one_descriptor_and_a_bound() {
    let scratch = crate::paths::tests::Scratch::new("lock-check");
    let lock = b"# the run's resolution\n";
    let fifo = scratch.0.join("fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("a name");
    // SAFETY: `name` is a NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let opened = open_lock(&fifo).expect("a FIFO opens with no writer");
    assert_eq!(lock_bytes(opened, lock).expect("its status reads"), None);
    let regular = scratch.0.join("regular");
    std::fs::write(&regular, lock).expect("written");
    let link = scratch.0.join("link");
    std::os::unix::fs::symlink(&regular, &link).expect("linked");
    assert_eq!(
        open_lock(&link)
            .expect_err("a link is refused")
            .raw_os_error(),
        Some(libc::ELOOP)
    );
    let read = lock_bytes(open_lock(&regular).expect("opens"), lock).expect("reads");
    assert_eq!(read.as_deref(), Some(&lock[..]));
    let long = scratch.0.join("long");
    std::fs::File::create(&long)
        .and_then(|file| file.set_len(1 << 40))
        .expect("a sparse file is made");
    let read = lock_bytes(open_lock(&long).expect("opens"), lock).expect("reads");
    assert_eq!(read.map(|bytes| bytes.len()), Some(lock.len() + 1));
}
