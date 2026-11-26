//! Bounded reads, confined opens and bounded listings against real entries
//! on the Cargo target directory's filesystem.

use std::ffi::CStr;
use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, symlink};

use super::fixture::{Case, name, observed, scripted};
use super::{Error, Name, Store, Unreadable};
use crate::exit::Supervisor;
use crate::step::{Outcome, Step};
use crate::sys;

/// A file within its bound reads back exactly; one byte past the bound is
/// refused after reading at most bound + 1 bytes; an absent name is `None`.
#[test]
fn a_read_takes_a_regular_file_up_to_its_bound() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    fs::write(case.state.join("exact"), b"0123").expect("the file is written");
    fs::write(case.state.join("over"), b"01234").expect("the file is written");
    let read = store
        .read(store.root(), &name("exact"), 4)
        .expect("the read succeeds");
    assert_eq!(read.expect("the file exists").bytes(), b"0123");
    assert!(matches!(
        store.read(store.root(), &name("over"), 4),
        Err(Unreadable::Oversize)
    ));
    // A terabyte-long sparse file refuses after bound + 1 bytes; a read
    // without that limit would try to buffer all of it.
    File::create(case.state.join("sparse"))
        .and_then(|file| file.set_len(1 << 40))
        .expect("the sparse file is made");
    assert!(matches!(
        store.read(store.root(), &name("sparse"), 4),
        Err(Unreadable::Oversize)
    ));
    assert!(matches!(
        store.read(store.root(), &name("absent"), 4),
        Ok(None)
    ));
}

/// A symlink, a FIFO, a socket and a directory at a record's name are
/// refused, and the FIFO's open returns at once with no writer present; a
/// socket fails its open with `ENXIO`.
#[test]
fn symlinks_fifos_and_directories_are_refused_without_blocking() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    fs::write(case.root.join("outside"), b"outside").expect("the target is written");
    symlink(case.root.join("outside"), case.state.join("link")).expect("the symlink is made");
    let state = File::open(&case.state).expect("the state directory opens");
    sys::mkfifo(&state, c"fifo").expect("the FIFO is made");
    fs::create_dir(case.state.join("directory")).expect("the directory is made");
    let _socket = std::os::unix::net::UnixListener::bind(case.state.join("socket"))
        .expect("the socket is bound");
    assert!(matches!(
        store.read(store.root(), &name("socket"), 64),
        Err(Unreadable::Io(error)) if error.raw_os_error() == Some(libc::ENXIO)
    ));
    assert!(matches!(
        store.open_dir(store.root(), &name("fifo")),
        Err(Unreadable::Io(error)) if error.raw_os_error() == Some(libc::ENOTDIR)
    ));
    assert!(matches!(
        store.read(store.root(), &name("link"), 64),
        Err(Unreadable::Symlink)
    ));
    assert!(matches!(
        store.read(store.root(), &name("fifo"), 64),
        Err(Unreadable::NotRegular)
    ));
    assert!(matches!(
        store.read(store.root(), &name("directory"), 64),
        Err(Unreadable::NotRegular)
    ));
    assert!(matches!(
        store.open_dir(store.root(), &name("link")),
        Err(Unreadable::Symlink)
    ));
    fs::write(case.state.join("file"), b"").expect("the file is written");
    assert!(matches!(
        store.open_dir(store.root(), &name("file")),
        Err(Unreadable::Io(error)) if error.raw_os_error() == Some(libc::ENOTDIR)
    ));
    assert!(matches!(
        store.open_dir(store.root(), &name("absent")),
        Ok(None)
    ));
}

/// `open_file` opens a regular file of any size for streaming with the
/// identity it had, and refuses a symlink, a FIFO without blocking, and a
/// directory; an absent name is `None`.
#[test]
fn an_opened_file_streams_and_other_kinds_are_refused() {
    use std::io::Read as _;
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    fs::write(case.state.join("file"), b"bytes").expect("the file is written");
    let mut opened = store
        .open_file(store.root(), &name("file"))
        .expect("the open succeeds")
        .expect("the file exists");
    let mut bytes = Vec::new();
    opened.read_to_end(&mut bytes).expect("the file reads");
    assert_eq!(bytes, b"bytes");
    let status = fs::metadata(case.state.join("file")).expect("it exists");
    assert_eq!(opened.identity(), super::Identity::from(&status));
    symlink(case.state.join("file"), case.state.join("link")).expect("the symlink is made");
    let state = File::open(&case.state).expect("the state directory opens");
    sys::mkfifo(&state, c"fifo").expect("the FIFO is made");
    fs::create_dir(case.state.join("directory")).expect("the directory is made");
    let open = |entry| store.open_file(store.root(), &name(entry));
    assert!(matches!(open("link"), Err(Unreadable::Symlink)));
    assert!(matches!(open("fifo"), Err(Unreadable::NotRegular)));
    assert!(matches!(open("directory"), Err(Unreadable::NotRegular)));
    assert!(matches!(open("absent"), Ok(None)));
}

/// The kernel's symlink and mount-crossing errors become their refusals,
/// and every other errno stays an I/O failure.
#[test]
fn resolution_errors_map_to_their_refusals() {
    let unreadable = |errno| Unreadable::from(std::io::Error::from_raw_os_error(errno));
    assert!(matches!(unreadable(libc::ELOOP), Unreadable::Symlink));
    assert!(matches!(unreadable(libc::EXDEV), Unreadable::CrossMount));
    assert!(matches!(unreadable(libc::ENOENT), Unreadable::Io(_)));
}

/// The confined open refuses a parent component, a mount crossing and a
/// procfs magic link, each beneath a real directory handle.
#[test]
fn a_confined_open_stays_beneath_its_handle_on_one_mount() {
    let case = Case::new();
    let flags = libc::O_RDONLY | libc::O_DIRECTORY;
    let errno = |dir: &File, name: &CStr, flags| {
        sys::open_beneath(dir, name, flags, 0)
            .map(drop)
            .map_err(|e| e.raw_os_error())
    };
    let state = File::open(&case.state).expect("the state directory opens");
    assert_eq!(errno(&state, c"..", flags), Err(Some(libc::EXDEV)));
    let parent = sys::open_parent(&state).expect("the parent opens");
    let (opened, expected) = (
        parent.metadata().expect("the parent stats"),
        fs::metadata(&case.root).expect("the root stats"),
    );
    assert_eq!(
        (opened.dev(), opened.ino()),
        (expected.dev(), expected.ino())
    );
    let root = File::open("/").expect("the root directory opens");
    assert_eq!(errno(&root, c"proc", flags), Err(Some(libc::EXDEV)));
    let process = File::open("/proc/self").expect("the process directory opens");
    assert_eq!(
        errno(&process, c"exe", libc::O_RDONLY),
        Err(Some(libc::ELOOP))
    );
}

/// A listing returns every name sorted and refuses one entry past its
/// bound with exit 4 instead of returning a truncated listing.
#[test]
fn a_listing_past_its_bound_is_refused() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    let dir = case.state.join("jobs");
    fs::create_dir(&dir).expect("the directory is made");
    for entry in ["c", "a", "b"] {
        fs::write(dir.join(entry), b"").expect("the entry is written");
    }
    let jobs = store
        .open_dir(store.root(), &name("jobs"))
        .expect("the directory opens")
        .expect("it exists");
    let listed = store.list(&jobs, 3).expect("three entries fit the bound");
    assert_eq!(listed, [name("a"), name("b"), name("c")]);
    let refused = store.list(&jobs, 2);
    assert!(matches!(refused, Err(Error::ScanBound)));
    assert_eq!(refused.unwrap_err().exit(), Supervisor::Held);
}

/// An entry whose name breaks the name rules fails the listing with exit 4
/// and names the entry, in a subdirectory and in the root, so no caller
/// acts on a listing that omits it. The root's own `.state` and `.staging`
/// are left out of its listing and count toward its bound; in a
/// subdirectory a `.state` entry is foreign.
#[test]
fn a_foreign_name_fails_the_listing() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    assert_eq!(store.list(store.root(), 2).expect("the root lists"), []);
    assert!(matches!(store.list(store.root(), 1), Err(Error::ScanBound)));
    fs::create_dir(case.state.join("jobs")).expect("the directory is made");
    let jobs = store
        .open_dir(store.root(), &name("jobs"))
        .expect("the directory opens")
        .expect("it exists");
    let foreign = |dir, entry: &str| {
        let refused = store.list(dir, 8);
        assert!(
            matches!(&refused, Err(Error::Foreign(name)) if name == entry),
            "{entry}: {refused:?}"
        );
        assert_eq!(refused.unwrap_err().exit(), Supervisor::Held);
    };
    for entry in ["not a name", ".state"] {
        let path = case.state.join("jobs").join(entry);
        fs::write(&path, b"").expect("the entry is written");
        foreign(&jobs, entry);
        fs::remove_file(&path).expect("the entry is removed");
    }
    fs::write(case.state.join(".other"), b"").expect("the entry is written");
    foreign(store.root(), ".other");
}

/// A directory the listing cannot read fails the listing with exit 4; it
/// never reads as an empty directory. A scripted `EACCES` on the listing
/// call checks the propagation for every user, and a mode-000 directory
/// checks the kernel's refusal for a user other than root, which reads
/// through mode bits.
#[test]
fn an_unreadable_directory_is_a_failed_listing() {
    use std::os::unix::fs::PermissionsExt;
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    let dir = case.state.join("jobs");
    fs::create_dir(&dir).expect("the directory is made");
    fs::write(dir.join("a"), b"").expect("the entry is written");
    let jobs = store
        .open_dir(store.root(), &name("jobs"))
        .expect("the directory opens")
        .expect("it exists");
    let list = 1;
    let (listed, reached) = scripted(Some((list, Outcome::Errno(libc::EACCES))), || {
        store.list(&jobs, 8)
    });
    assert_eq!(reached.len(), list + 1, "{reached:?}");
    assert_eq!(reached[list], Step::List);
    let listed = listed.expect("the listing runs");
    assert!(
        matches!(&listed, Err(Error::Io(error)) if error.raw_os_error() == Some(libc::EACCES)),
        "{listed:?}"
    );
    if sys::euid() == 0 {
        return;
    }
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).expect("the mode changes");
    let listed = store.list(&jobs, 8);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("the mode is restored");
    assert!(
        matches!(&listed, Err(Error::Io(error)) if error.raw_os_error() == Some(libc::EACCES)),
        "{listed:?}"
    );
    assert_eq!(listed.unwrap_err().exit(), Supervisor::Held);
}

/// A listing longer than one kernel batch of entries returns every name,
/// and its bound counts across batches.
#[test]
fn a_listing_spans_kernel_batches() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    let dir = case.state.join("jobs");
    fs::create_dir(&dir).expect("the directory is made");
    let names: Vec<String> = (0..1500).map(|index| format!("{index:040}")).collect();
    for entry in &names {
        fs::write(dir.join(entry), b"").expect("the entry is written");
    }
    let jobs = store
        .open_dir(store.root(), &name("jobs"))
        .expect("the directory opens")
        .expect("it exists");
    let (listed, reached) = scripted(None, || store.list(&jobs, names.len()));
    let listed = listed
        .expect("the listing runs")
        .expect("every entry fits the bound");
    let batches = reached.iter().filter(|&&at| at == Step::List).count();
    assert!(batches > 2, "{batches} listing calls: {reached:?}");
    assert_eq!(listed.iter().map(Name::as_str).collect::<Vec<_>>(), names);
    assert!(matches!(
        store.list(&jobs, names.len() - 1),
        Err(Error::ScanBound)
    ));
}

/// `remove_host` removes a file that is there, succeeds for one that is
/// not, and fails for a directory.
#[test]
fn remove_host_removes_a_present_file_and_accepts_an_absent_one() {
    let case = Case::new();
    let file = case.root.join("file");
    fs::write(&file, b"bytes").unwrap();
    super::remove_host(&file).unwrap();
    assert!(!file.exists());
    super::remove_host(&file).unwrap();
    assert!(super::remove_host(&case.state).is_err());
    assert!(case.state.is_dir());
}

/// A read of a root-level file holds no share of the lock: once its store
/// drops, the next controller opens while the read is still alive.
#[test]
fn a_live_read_holds_no_share_of_the_lock() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    fs::write(case.state.join("record"), b"record").expect("the record is written");
    let read = store
        .read(store.root(), &name("record"), 64)
        .expect("the read succeeds")
        .expect("the record exists");
    drop(store);
    Store::open(&case.state).expect("the lock is free while the read lives");
    assert_eq!(read.bytes(), b"record");
}

#[test]
fn newly_created_ancestors_have_parent_barriers() {
    let case = Case::new();
    let path = case.root.join("a/b/c");
    let (result, reached) = scripted([], || super::create_dirs(&path));
    result.expect("script").expect("directories");
    let syncs: Vec<_> = reached
        .iter()
        .enumerate()
        .filter_map(|(at, step)| (*step == Step::Sync).then_some(at))
        .collect();
    assert_eq!(syncs.len(), 3);
    for (index, at) in syncs.into_iter().enumerate() {
        let path = case.root.join(format!("failure-{index}/b/c"));
        let (result, _) = scripted([(at, Outcome::Errno(libc::EIO))], || {
            super::create_dirs(&path)
        });
        assert_eq!(
            result
                .expect("script")
                .expect_err("sync failed")
                .raw_os_error(),
            Some(libc::EIO)
        );
    }
}

/// A symlink that appears at a missing ancestor between the existence
/// scan and the creation is refused, and nothing is created through it:
/// the creation follows no symlink in a component it creates itself.
#[test]
fn a_symlink_planted_in_a_missing_ancestor_is_refused() {
    let case = Case::new();
    let elsewhere = case.root.join("elsewhere");
    fs::create_dir(&elsewhere).expect("the target");
    let (planted, target) = (case.root.join("a"), elsewhere.clone());
    let mut once = false;
    let observe = move |at| {
        if at == Step::Mkdir && !once {
            once = true;
            symlink(&target, &planted).expect("the symlink is planted");
        }
    };
    let result = observed(observe, || super::create_dirs(&case.root.join("a/b/c")));
    assert_eq!(
        result
            .expect_err("the planted symlink is refused")
            .raw_os_error(),
        Some(libc::ELOOP)
    );
    assert!(!elsewhere.join("b").exists());
    assert!(
        case.root
            .join("a")
            .symlink_metadata()
            .expect("the symlink stays")
            .file_type()
            .is_symlink()
    );
}

/// A symlink already present at a component of the given path is refused
/// by the creation itself, and nothing is created through it: the
/// existing prefix is opened with no symlink followed in any component.
#[test]
fn a_symlink_in_the_existing_prefix_is_refused() {
    let case = Case::new();
    let elsewhere = case.root.join("elsewhere");
    fs::create_dir(&elsewhere).expect("the target");
    symlink(&elsewhere, case.root.join("a")).expect("the symlink");
    let result = super::create_dirs(&case.root.join("a/b/c"));
    assert_eq!(
        result
            .expect_err("the linked prefix is refused")
            .raw_os_error(),
        Some(libc::ELOOP)
    );
    assert!(!elsewhere.join("b").exists());
}

/// A replacement stages its bytes in a file it creates. A symlink at the
/// staging name is removed, its target keeps its bytes, and the path holds
/// the new bytes as a regular file.
#[test]
fn a_replacement_writes_through_no_symlink_at_its_staging_name() {
    let case = Case::new();
    let victim = case.root.join("victim");
    fs::write(&victim, b"kept").expect("the target");
    symlink(&victim, case.root.join("sweep.json.tmp")).expect("the symlink");
    let path = case.root.join("sweep.json");
    super::replace_host(&path, b"new").expect("the replacement");
    assert_eq!(fs::read(&victim).expect("the target reads"), b"kept");
    assert_eq!(fs::read(&path).expect("the path reads"), b"new");
    let status = path.symlink_metadata().expect("the path has a status");
    assert!(status.file_type().is_file());
    super::replace_host(&path, b"newer").expect("a second replacement");
    assert_eq!(fs::read(&path).expect("the path reads"), b"newer");
}

/// A replacement syncs the directory after its rename, so the new name
/// outlasts a power loss, and a replacement whose directory sync fails
/// reports the failure.
#[test]
fn a_replacement_syncs_its_directory_after_the_rename() {
    let case = Case::new();
    let path = case.root.join("sweep.json");
    let (replaced, reached) = scripted([], || super::replace_host(&path, b"new"));
    replaced
        .expect("the run completes")
        .expect("the replacement succeeds");
    let rename = reached.iter().rposition(|&at| at == Step::Rename);
    let sync = reached.iter().rposition(|&at| at == Step::Sync);
    assert!(rename.is_some() && sync > rename, "{reached:?}");
    let failed = [(sync.expect("a sync"), Outcome::Errno(libc::EIO))];
    let (replaced, _) = scripted(failed, || super::replace_host(&path, b"newer"));
    let error = replaced
        .expect("the run completes")
        .expect_err("the directory sync fails");
    assert_eq!(error.raw_os_error(), Some(libc::EIO));
}

/// A trim cuts the file after its last newline, so a record left without
/// one is gone: a whole file of one such record becomes empty, and a long
/// one after a complete line leaves that line. A file that ends in a
/// newline, an empty file and a path with no entry are left, and a
/// symlink is refused with its target unchanged.
#[test]
fn a_trim_cuts_an_unterminated_record_from_the_end() {
    let case = Case::new();
    let path = case.root.join("suspects.jsonl");
    let long = "x".repeat(200_000);
    for (before, after) in [
        ("first\nsecond", "first\n"),
        ("first\nsecond\n", "first\nsecond\n"),
        ("only", ""),
        ("", ""),
        (&format!("first\n{long}"), "first\n"),
        (long.as_str(), ""),
    ] {
        fs::write(&path, before).expect("the file");
        super::trim_host(&path).expect("the trim");
        assert_eq!(fs::read_to_string(&path).expect("the file reads"), after);
    }
    fs::remove_file(&path).expect("the file is removed");
    super::trim_host(&path).expect("a trim of no entry");
    assert!(!path.exists());
    let victim = case.root.join("victim");
    fs::write(&victim, b"kept\nrest").expect("the target");
    symlink(&victim, &path).expect("the symlink");
    let refused = super::trim_host(&path).expect_err("the symlink is refused");
    assert_eq!(refused.raw_os_error(), Some(libc::ELOOP));
    assert_eq!(fs::read(&victim).expect("the target reads"), b"kept\nrest");
}

/// An append to a path that is a symlink is refused, and the symlink's
/// target keeps its bytes.
#[test]
fn an_append_follows_no_symlink_at_its_path() {
    let case = Case::new();
    let victim = case.root.join("victim");
    fs::write(&victim, b"kept").expect("the target");
    let path = case.root.join("suspects.jsonl");
    symlink(&victim, &path).expect("the symlink");
    let appended = super::append_host(&path, b"line\n");
    assert_eq!(
        appended.expect_err("the symlink is refused").raw_os_error(),
        Some(libc::ELOOP)
    );
    assert_eq!(fs::read(&victim).expect("the target reads"), b"kept");
}

/// An append that creates its file syncs the directory after the file,
/// so the new name outlasts a power loss, and a later append to the file
/// syncs the file alone. A creating append whose directory sync fails
/// reports the failure and leaves the file empty.
#[test]
fn an_append_that_creates_its_file_syncs_the_directory() {
    let case = Case::new();
    let path = case.root.join("suspects.jsonl");
    let syncs = |reached: &[Step]| reached.iter().filter(|&&at| at == Step::Sync).count();
    let (appended, reached) = scripted([], || super::append_host(&path, b"line\n"));
    appended
        .expect("the run completes")
        .expect("the append succeeds");
    assert_eq!(syncs(&reached), 2, "{reached:?}");
    let (appended, later) = scripted([], || super::append_host(&path, b"more\n"));
    appended
        .expect("the run completes")
        .expect("the append succeeds");
    assert_eq!(syncs(&later), 1, "{later:?}");
    fs::remove_file(&path).expect("the file is removed");
    let last = reached.iter().rposition(|&at| at == Step::Sync);
    let failed = [(last.expect("a sync"), Outcome::Errno(libc::EIO))];
    let (appended, _) = scripted(failed, || super::append_host(&path, b"line\n"));
    let error = appended
        .expect("the run completes")
        .expect_err("the directory sync fails");
    assert_eq!(error.raw_os_error(), Some(libc::EIO));
    assert_eq!(fs::read(&path).expect("the file reads"), b"");
}

/// The index of the first `Write` step an append of `bytes` to `path`
/// reaches. The append it runs to find it is truncated away.
fn first_write(path: &std::path::Path, bytes: &[u8]) -> usize {
    let before = fs::read(path).unwrap_or_default();
    let (appended, reached) = scripted([], || super::append_host(path, bytes));
    appended
        .expect("the run completes")
        .expect("the append succeeds");
    fs::write(path, before).expect("the file is restored");
    reached
        .iter()
        .position(|&at| at == Step::Write)
        .expect("an append writes")
}

/// An append that fails after a short write, as one that meets a full
/// filesystem does, leaves the file with the bytes it had before the
/// call, so the next append starts its own line.
#[test]
fn a_failed_append_leaves_the_bytes_the_file_had() {
    let case = Case::new();
    let path = case.root.join("suspects.jsonl");
    for before in [&b""[..], b"first\n"] {
        fs::write(&path, before).expect("the file");
        let write = first_write(&path, b"line\n");
        let script = [
            (write, Outcome::Short(2)),
            (write + 1, Outcome::Errno(libc::ENOSPC)),
        ];
        let (appended, _) = scripted(script, || super::append_host(&path, b"line\n"));
        let error = appended
            .expect("the run completes")
            .expect_err("the append fails");
        assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
        assert_eq!(fs::read(&path).expect("the file reads"), before);
        super::append_host(&path, b"line\n").expect("a later append");
        assert_eq!(
            fs::read(&path).expect("the file reads"),
            [before, b"line\n"].concat()
        );
    }
}

/// A failed append syncs the file after it truncates it, so the bytes the
/// append wrote do not come back with a power loss after the call has
/// returned its error.
#[test]
fn a_failed_append_syncs_its_truncation() {
    let case = Case::new();
    let path = case.root.join("suspects.jsonl");
    fs::write(&path, b"first\n").expect("the file");
    let write = first_write(&path, b"line\n");
    let script = [
        (write, Outcome::Short(2)),
        (write + 1, Outcome::Errno(libc::ENOSPC)),
    ];
    let (appended, reached) = scripted(script, || super::append_host(&path, b"line\n"));
    let error = appended
        .expect("the run completes")
        .expect_err("the append fails");
    assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
    assert_eq!(reached.last(), Some(&Step::Sync), "{reached:?}");
    assert_eq!(fs::read(&path).expect("the file reads"), b"first\n");
}

/// An append syncs the file after its last write, and an append whose
/// sync fails leaves the file with the bytes it had before the call.
#[test]
fn an_append_is_synced_or_undone() {
    let case = Case::new();
    let path = case.root.join("suspects.jsonl");
    fs::write(&path, b"first\n").expect("the file");
    let (appended, reached) = scripted([], || super::append_host(&path, b"line\n"));
    appended
        .expect("the run completes")
        .expect("the append succeeds");
    let write = reached.iter().rposition(|&at| at == Step::Write);
    let sync = reached.iter().rposition(|&at| at == Step::Sync);
    assert!(write.is_some() && sync > write, "{reached:?}");
    let failed = [(sync.expect("a sync"), Outcome::Errno(libc::EIO))];
    let (appended, _) = scripted(failed, || super::append_host(&path, b"more\n"));
    let error = appended
        .expect("the run completes")
        .expect_err("the sync fails");
    assert_eq!(error.raw_os_error(), Some(libc::EIO));
    assert_eq!(fs::read(&path).expect("the file reads"), b"first\nline\n");
}

/// A private directory lies on a filesystem a state directory accepts.
/// One on tmpfs, here under `/dev/shm`, is refused for its filesystem.
#[test]
fn a_private_directory_on_tmpfs_is_refused() {
    let path = std::path::PathBuf::from(format!("/dev/shm/private-dir-{}", std::process::id()));
    let opened = super::private_dir(&path);
    let _ = fs::remove_dir(&path);
    assert!(
        matches!(
            &opened,
            Err(Error::Refused(super::Refusal::Filesystem(fstype))) if fstype == "tmpfs"
        ),
        "{opened:?}"
    );
}
