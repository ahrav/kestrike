//! The walker must report the target node even when `statx` returns
//! `ENOENT` for a held procfs `fd` directory.
//!
//! procfs answers `statx` with `ENOENT` for the `fd` directory of a process
//! that exited, on a kernel that reports a table's entry count as that
//! directory's size. A descriptor on the directory stays open after the
//! process exits, so every listing of its holder's table returns its number
//! and every `statx` through that number reports `ENOENT`.
//! `Host::check_unused` refuses a bind when the walk has no answer, so the
//! walk must answer for such a table and report its other descriptors.
//!
//! A case that forks runs its body in a fresh child of the test
//! executable, where it is the one test with open descriptors and locks.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::super::fixture::Fixture;
use super::super::host::Host;
use super::{
    Directory, Facts, Node, Os, Procfs, Queue, Walker, answer, boot_ticks, numbers_tasks_as_kcmp,
    procfs_directory,
};
use crate::exact_child;

const CHILD_DEADLINE: Duration = Duration::from_secs(60);

/// A directory [`Procfs`] opened.
type Table = <Procfs<'static> as Os>::Table;

/// A forked copy of this process. It holds every descriptor this process
/// held at the fork and waits for a signal. Dropping it kills and reaps it.
struct Copy(libc::pid_t);

impl Copy {
    fn fork() -> Self {
        let parent = libc::pid_t::try_from(std::process::id()).unwrap();
        // SAFETY: Between `fork` and termination, the child calls
        // `libc::prctl` to set its parent-death signal and otherwise calls
        // only the async-signal-safe `getppid`, `_exit`, and `pause`.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // `PR_SET_PDEATHSIG` makes the kernel kill the copy when the
            // thread that forked it exits. The `getppid` check makes the
            // copy exit if its parent died before `PR_SET_PDEATHSIG` took
            // effect.
            // SAFETY: `prctl` reads the `PR_SET_PDEATHSIG` signal as an
            // `unsigned long`, which the cast supplies; `getppid`,
            // `_exit(0)`, and `pause` have no pointer preconditions.
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
                if libc::getppid() != parent {
                    libc::_exit(0);
                }
                loop {
                    libc::pause();
                }
            }
        }
        Self(pid)
    }

    fn id(&self) -> u32 {
        u32::try_from(self.0).unwrap()
    }
}

impl Drop for Copy {
    fn drop(&mut self) {
        // SAFETY: `self.0` is this process's child, and this is its one
        // wait; `waitpid` accepts a null status pointer.
        unsafe {
            libc::kill(self.0, libc::SIGKILL);
            libc::waitpid(self.0, std::ptr::null_mut(), 0);
        }
    }
}

/// A process whose table holds the target file and the `fd` directory of a
/// process that exited, with the number each has in that table.
struct Holder {
    process: Copy,
    refused: CString,
    held: CString,
}

impl Holder {
    /// The open directory survives its process, so the holder inherits a
    /// descriptor for the exited process's `fd` directory.
    fn of(target: &Path) -> Self {
        let exited = Copy::fork();
        let directory = File::open(format!("/proc/{}/fd", exited.id())).unwrap();
        drop(exited);
        let target = File::open(target).unwrap();
        let number = |file: &File| CString::new(file.as_raw_fd().to_string()).unwrap();
        Self {
            process: Copy::fork(),
            refused: number(&directory),
            held: number(&target),
        }
    }

    fn table(&self, os: &Procfs<'_>) -> Table {
        os.open(&CString::new(format!("{}/fd", self.process.id())).unwrap())
            .unwrap()
    }
}

/// The process table at `/proc`, as `Host::opened` reads it.
fn procfs() -> Procfs<'static> {
    let proc = Path::new("/proc");
    Procfs {
        root: Directory::open(libc::AT_FDCWD, c"/proc").unwrap(),
        proc,
        own: numbers_tasks_as_kcmp(proc),
    }
}

fn target(fixture: &Fixture) -> (PathBuf, Node) {
    fixture.file("dev/held", "");
    let target = fixture.root.join("dev/held");
    let node = Host::node(&target).unwrap();
    (target, node)
}

/// Whether `statx` through `table` reports `ENOENT` for descriptor `name`.
/// Each case requires `statx` to return `ENOENT` for the open `fd`
/// directory after its process exits. For any result other than `ENOENT`,
/// `refuses` prints the `not run` diagnostic and returns `false`.
fn refuses(table: &Table, name: &CStr) -> bool {
    let refused = Node::at(table.as_raw_fd(), name)
        .is_err_and(|error| error.raw_os_error() == Some(libc::ENOENT));
    if !refused {
        eprintln!("not run: this kernel answers `statx` for an exited process's `fd` directory");
    }
    refused
}

pub(super) fn walked(os: &Procfs<'_>, pid: u32, target: Node) -> Option<Vec<Node>> {
    let queue = Queue::<Table>::default();
    queue.push(&queue.processes, &mut vec![pid], true);
    queue.listed.store(true, Ordering::Release);
    let facts = Facts {
        reports_count: false,
        kcmp: os.own,
        begun: boot_ticks(os.proc),
        walkers: 1,
    };
    let found = Mutex::new(Some(Vec::new()));
    Walker::new(os, &queue, &|found| found == target, facts).walk(&found);
    answer(found, true)
}

/// `statx` through a table returns `ENOENT` both for a vacant number and
/// for a descriptor on an exited process's `fd` directory. A number that
/// was vacant at the `statx` can hold that directory at the open that
/// follows, so the first read that finds the directory reports the
/// descriptor vanished. Each later read through that table opens the
/// number first and returns `Ok(None)` for the directory, `ENOENT` for a
/// vacant number, and the target's node for a descriptor on the target.
#[test]
fn a_descriptor_whose_file_refuses_its_attributes_reads_as_vanished_once_then_as_a_present_non_device()
 {
    exact_child::run(
        "bind::walk::refused_attributes_tests::a_descriptor_whose_file_refuses_its_attributes_reads_as_vanished_once_then_as_a_present_non_device",
        CHILD_DEADLINE,
        || {
            let fixture = Fixture::new(4096);
            let (target, node) = target(&fixture);
            let holder = Holder::of(&target);
            let os = procfs();
            let table = holder.table(&os);
            if !refuses(&table, &holder.refused) {
                return;
            }
            let read = |name: &CStr| os.node(&table, name).map_err(|error| error.raw_os_error());
            // A descriptor number fits a C `int`, so this number is empty in
            // every table.
            let vacant = c"4294967295";
            assert_eq!(
                read(vacant),
                Err(Some(libc::ENOENT)),
                "a number that holds no descriptor, read by `statx` first"
            );
            assert_eq!(
                read(&holder.held),
                Ok(Some(node)),
                "a descriptor on the target, read by `statx` first"
            );
            assert_eq!(
                read(&holder.refused),
                Err(Some(libc::ENOENT)),
                "the first read of a descriptor on a procfs directory that refuses its attributes"
            );
            assert_eq!(
                read(&holder.refused),
                Ok(None),
                "a later read of that descriptor through the same table"
            );
            assert_eq!(
                read(vacant),
                Err(Some(libc::ENOENT)),
                "a number that holds no descriptor, opened first"
            );
            assert_eq!(
                read(&holder.held),
                Ok(Some(node)),
                "a descriptor on the target, opened first"
            );
        },
    );
}

/// The walker must report the target node even when `statx` returns
/// `ENOENT` for the held procfs directory. A walk that reads that `ENOENT`
/// as a vanished descriptor reads the table at every listing up to its
/// bound and has no answer.
#[test]
fn a_table_that_holds_a_descriptor_whose_file_refuses_its_attributes_is_walked() {
    exact_child::run(
        "bind::walk::refused_attributes_tests::a_table_that_holds_a_descriptor_whose_file_refuses_its_attributes_is_walked",
        CHILD_DEADLINE,
        || {
            let fixture = Fixture::new(4096);
            let (target, node) = target(&fixture);
            let holder = Holder::of(&target);
            let os = procfs();
            if !refuses(&holder.table(&os), &holder.refused) {
                return;
            }
            assert_eq!(walked(&os, holder.process.id(), node), Some(vec![node]));
        },
    );
}

/// `fstatfs` reports the same filesystem type for procfs directories and
/// regular files. Resolving `.` relative to the open descriptor verifies
/// that the descriptor names a directory.
#[test]
fn only_a_directory_on_procfs_passes_as_a_non_device() {
    let open = |path: &Path| OwnedFd::from(File::open(path).unwrap());
    let executable = std::env::current_exe().unwrap();
    assert!(
        procfs_directory(&open(Path::new("/proc/self/fd"))),
        "a directory on procfs"
    );
    assert!(
        !procfs_directory(&open(Path::new("/proc/self/stat"))),
        "a regular file that reports the procfs type"
    );
    assert!(
        !procfs_directory(&open(executable.parent().unwrap())),
        "a directory on another filesystem"
    );
    assert!(
        !procfs_directory(&open(&executable)),
        "a regular file on another filesystem"
    );
    assert!(
        !procfs_directory(&open(Path::new("/dev/null"))),
        "a device node on another filesystem"
    );
}
