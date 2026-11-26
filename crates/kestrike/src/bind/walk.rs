//! Identifies the node behind every open descriptor of every process, for
//! the in-use check of a namespace a bind claims.
//!
//! A walk opens and lists the descriptor table of each process's leader and
//! of each of its other threads, and identifies each descriptor with one
//! `statx`. If `statx` reports `ENOENT`, the walk opens the descriptor
//! number with `O_PATH` and calls `statx` on the file the open pins. Once
//! `statx` returns `ENOENT` for a pinned procfs directory, the walk reads
//! each later descriptor through that open `fd` directory with such an
//! open. A thread holds a
//! private table after
//! `unshare(CLONE_FILES)` or
//! a `clone` without `CLONE_FILES`, so the walk reads every thread's table
//! whatever the leader's holds, and reports each matching node once,
//! however many threads share its table. When `kcmp` resolves the process
//! table's IDs to the tasks it lists, a thread that `kcmp` reports sharing
//! its leader's table is read through the leader alone. The calling thread
//! lists the process table, reads the start tick of each listed process,
//! on several threads when the table is large, and queues the processes
//! for the walker threads, which start once the listing has queued them. A
//! walker reads a
//! table's first [`SHARE`] descriptors itself and queues the rest of a large
//! table in shares of that size for whichever walker is free, so one process
//! with thousands of descriptors spreads across the walkers. Each descriptor
//! is identified when a walker reads it, so the walk reports the descriptors
//! each table held while it was read.
//!
//! A process that starts after the listing passed its ID holds descriptors
//! no walker reads, and a child inherits its parent's at the fork, so a
//! parent that exits or closes a descriptor before a walker reads its table
//! would leave the descriptor unreported though some process held it
//! throughout. So the walk runs in rounds. Each round lists the process
//! table again and walks the processes no earlier round listed, and the
//! walk ends with the first round that lists no such process, which begins
//! after every earlier round's reads. The host can give a process the ID
//! of one that exited, so a listing tells processes apart by ID and the
//! clock tick the leader started in: a process under an ID an earlier
//! round listed with another start tick is one no round listed. A listing
//! reads that tick from the leader's `stat` entry whatever the leader's
//! state, so a process still shows it once it has exited and awaits its
//! parent, or once its leader has exited while its threads live. A process
//! whose tick a listing cannot read, as once the process is gone, counts
//! as one no round listed. Under an ID an earlier round listed without a
//! tick, nothing tells it from that round's process, so the listing fails
//! the walk. A descriptor that passes from parent to child by `fork` alone
//! through the whole walk is then reported, or the walk fails: its holder
//! when the walk's last listing begins was read in an earlier round, or
//! the last listing reaches it or a descendant holding the descriptor,
//! while each child's ID lies above its parent's. The kernel lists the process table in ascending ID order and
//! takes each new ID from a cursor that returns to its lowest ID after its
//! highest, so a child that starts after the cursor turned back takes an
//! ID below its parent's, which a listing may have passed while the parent
//! exits before the listing reaches it. So the walk reads the last ID the
//! host gave before its first round and after each round, and a round that
//! lists no new process ends the walk only when that ID fell across
//! neither that round nor the round before it, the two in which the last
//! listing's unread holder and its child can have started. A process table
//! that numbers tasks as another PID namespace does, or whose `loadavg`
//! cannot be read, shows no such ID, and the walk over it relies on a
//! child's ID lying above its parent's. Every walk relies on no process
//! taking, within it, the ID of one that started in its own clock tick, and
//! on no process choosing its child's ID. A reading of the last ID shows a
//! turn of the cursor only by standing below the reading before it, so
//! every walk also relies on a cursor that turned back between two readings
//! still standing below the earlier one at the later: a turn that carries
//! the cursor back to that reading or past it, which the IDs live tasks
//! hold shorten, reads as no turn. A walk whose every round up to
//! [`ROUNDS`] lists a new process or follows such a fall fails.
//!
//! A process's other threads are compared with its leader only once every
//! share of the leader's table is read, so a thread that leaves the table
//! afterward holds only descriptors the walk read there or opened later.
//! A non-leader thread that execs takes over the process's ID with its own
//! table once every other thread has exited. The walk skips a thread of the
//! first `task` listing by `kcmp` only when the first listed thread started
//! before the walk and is still present after the comparisons; otherwise it
//! reads every thread's table. The host can give a listed thread's ID,
//! once that thread is gone, to a thread started later, and a comparison
//! under that ID then says nothing of the table the listed thread used,
//! which a thread it started may still hold. So the comparisons stand
//! alone only while the last ID the host gave stands, after them, where it
//! stood before the walk counted the process's threads; otherwise the walk
//! lists the process's threads again, as below, whatever the comparisons
//! reported. Once every queued table of the process's
//! threads is read, the walk checks that first thread again, and reads the
//! table under the process's ID when the thread is gone, or when the
//! process had other threads and none remains, since an exec may have
//! replaced the leader whose table it read. A thread can also start after
//! the walk counted the process's threads, on a table of its own, and exec
//! before the walk lists them, which leaves one thread as before. The host
//! gives every task it starts an ID, so the walk notes the last ID given
//! before it counts the threads and reads the table under the process's ID
//! again when that ID has changed or cannot be read. Until the cursor
//! returns to the earlier reading, equal readings of the last ID rule out
//! a start between them. Starts that cycle the cursor back to that reading
//! produce equal readings, and the IDs live tasks hold shorten the cycle.
//! The comparisons above and this second read rely on fewer starts between
//! two readings than one cycle takes, and the recheck relies on the same
//! bound to tell a listed thread from a later one. A walker reads each
//! table the recheck reads whole, without queuing shares of it, and only
//! then lists the process's threads again and reads the table of each
//! thread the earlier listings lacked, telling a thread under a departed
//! thread's ID apart by the clock tick it started in, until a listing names
//! no new thread:
//! a thread that starts another on its private table and exits before the
//! walk reads that table leaves it to a thread the first listing could not
//! name. When `kcmp` resolves the process table's IDs, the recheck compares
//! each such thread's table with the leader's and skips the read of a thread
//! that shares it, while a thread that started before the walk, or one
//! listed before the walk last read the table under the process's ID, is
//! still present after the comparisons. An exec ends every other thread
//! before it swaps the table under that ID, so that thread shows the
//! comparisons were with a table the walk has read, whose reads cover the
//! threads that share it. The recheck reads the table of every other such
//! thread. A process that keeps starting threads through sixteen listings
//! fails the walk.
//! Each thread found with a private table is queued for any walker. A share
//! of a multithreaded process's leader table is read through the `fd`
//! directory of one of its threads, which spreads the kernel's per-task
//! locks across the walkers, and kept only when `kcmp` then shows that
//! thread still uses the leader's table and the thread under that ID started
//! before the walk, so it is the thread whose directory was read; otherwise
//! the share is read through the leader.
//!
//! The kernel returns a `task` directory's listing over several reads and
//! resumes by count once a thread it stood on has exited, so a listing that
//! threads exit during can pass over a thread that stays. The walk keeps a
//! listing only when it names as many tasks as the directory's link count
//! reports both before and after it, lists the directory again otherwise,
//! and fails when no listing of a process agrees. A listing that as many
//! threads start during as exit can still agree and lack a thread.
//!
//! A descriptor is identified by the file its link resolves to, so every
//! name a process opened a device through identifies the same device. A
//! process or descriptor that vanishes during the walk reports `ENOENT` and
//! is skipped; any other failure to read a table or a descriptor fails the
//! walk.
//!
//! `statx` through a table reports `ENOENT` both for a number that holds no
//! descriptor and for a descriptor whose file's filesystem refuses its
//! attributes with that error. procfs refuses those of the `fd` directory
//! of a process that exited, and an open descriptor keeps that directory
//! after its process exits. A read that reports `ENOENT` therefore opens
//! the number with `O_PATH`. That open reports `ENOENT` while the number
//! holds no descriptor. A successful `O_PATH` open pins the descriptor's
//! file at the VFS layer. If `statx` succeeds on the pinned file, the read
//! reports that the descriptor vanished. If `statx` reports `ENOENT` on
//! the pinned file, the read checks that the file is a directory on
//! procfs: `fstatfs` reports the procfs type, and `.` resolves relative to
//! the pinned file, which the kernel allows only for a directory the
//! walker may search. Any other refusal fails the walk. The `ENOENT` that
//! led to that directory
//! can also come from a number that was empty at the first `statx` and took
//! the directory before the open, so the read reports the descriptor
//! vanished and marks the open `fd` directory it read through. Every later
//! read through that open directory opens the number with `O_PATH` first
//! and identifies the file that open pins, so the read observes its number
//! once: an empty number reports `ENOENT`, and the directory reads as a
//! present descriptor that is no device. Each other open of a table's `fd`
//! directory starts unmarked. Both files and directories of a `/proc/sys`
//! table the kernel unregistered, as after its network interface is
//! deleted, report `ENOENT` to `statx`. Resolving `.` returns `ENOTDIR`
//! for the file and `ENOENT` for the directory, so a descriptor on either
//! fails the walk while it stays open.
//!
//! A process can move a descriptor to a number the listing of its table did
//! not return, as `dup2` and a `close` of the old number do, or onto a
//! number that is open and already read, as `dup2` onto an open number
//! does. An `open` can then reuse the old number, so the read of that number
//! finds another file and nothing vanished. A table is therefore listed
//! again once every descriptor of its first listing is read, by the walker
//! that listed it or by the walkers of its queued shares, and every number
//! that listing returns is read again, read before or not. Whichever of
//! those reads ends last lists the table, so the listing and its reads
//! follow every read of the first listing. A descriptor that one such move
//! renumbers while its table is read was read at its old number before the
//! move, or sits at its new number for the whole second reading, and is
//! therefore reported. Each later listing reads the numbers no earlier one
//! returned, until a listing returns none, and a descriptor that vanishes
//! in the second reading or later makes the next listing read every number
//! again. A table that still returns unread numbers after [`RELISTS`]
//! listings fails the walk.
//!
//! The walkers are threads of the calling process, and each opens and
//! closes descriptors in that process's own table, at the numbers it frees,
//! for as long as it runs. A walker that read that table beside them would
//! find descriptors vanished in reading after reading. So a listing leaves
//! the calling process out of the walkers' queue, and the calling thread
//! walks it alone once the round's walkers have finished.
//!
//! A procfs mounted with `hidepid` lists no process its reader may not
//! trace and reports `ENOENT` for that process's entries, as for a process
//! that exited. A reader with `CAP_SYS_PTRACE` in the initial user
//! namespace may trace every process; a capability held in a child user
//! namespace confers no access to a process of an ancestor namespace that
//! holds capabilities there. The kernel keeps capabilities per thread, and
//! the thread that calls the walk lists the process table and starts the
//! threads that read start ticks and the walkers, which take its
//! credentials, so a walk called from a thread without that capability, or
//! by a process in another user namespace, fails, whatever the process's
//! other threads hold.

use std::collections::{BTreeSet, HashSet};
use std::ffi::{CStr, CString, c_int};
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::num::NonZero;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::sync::Arc;
#[cfg(not(all(test, loom)))]
use std::sync::Mutex;
#[cfg(not(all(test, loom)))]
use std::sync::OnceLock;
use std::sync::atomic::Ordering;
#[cfg(not(all(test, loom)))]
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::thread;
#[cfg(not(all(test, loom)))]
use std::thread::yield_now;

#[cfg(all(test, loom))]
use loom::sync::Mutex;
#[cfg(all(test, loom))]
use walk_model::{Flag as AtomicBool, Once as OnceLock, Word as AtomicUsize, idle as yield_now};

use super::host::Host;

#[cfg(all(test, not(loom)))]
mod exec_window_tests;
#[cfg(all(test, not(loom)))]
mod fd_move_tests;
#[cfg(all(test, not(loom)))]
mod id_order_tests;
#[cfg(all(test, not(loom)))]
mod listing_tests;
#[cfg(all(test, not(loom)))]
mod refused_attributes_tests;
#[cfg(all(test, not(loom)))]
mod reused_id_tests;
#[cfg(all(test, not(loom)))]
mod task_change_tests;
#[cfg(all(test, loom))]
mod walk_model;
#[cfg(all(test, not(loom)))]
mod walk_tests;

#[cfg(all(test, not(loom)))]
mod tests;

/// The count of work not yet finished: [`AtomicUsize`] in a walk.
trait Count: Default + Sync {
    fn load(&self, order: Ordering) -> usize;
    fn fetch_add(&self, value: usize, order: Ordering) -> usize;
    fn fetch_sub(&self, value: usize, order: Ordering) -> usize;
}

impl Count for AtomicUsize {
    #[inline(always)]
    fn load(&self, order: Ordering) -> usize {
        Self::load(self, order)
    }

    #[inline(always)]
    fn fetch_add(&self, value: usize, order: Ordering) -> usize {
        Self::fetch_add(self, value, order)
    }

    #[inline(always)]
    fn fetch_sub(&self, value: usize, order: Ordering) -> usize {
        Self::fetch_sub(self, value, order)
    }
}

/// What a walk reads from the process table: each path is relative to its
/// root.
trait Os: Sync {
    /// An open directory: the process table, a descriptor table or a
    /// `task` directory.
    type Table: Send + Sync;
    /// The size and link count of `path`.
    fn status(&self, path: &CStr) -> io::Result<Status>;
    fn open(&self, path: &CStr) -> io::Result<Self::Table>;
    /// Calls `visit` with each entry name of `table` but `.` and `..`, with
    /// `records` as the read buffer.
    fn entries(
        &self,
        table: &Self::Table,
        records: &mut [u8],
        visit: impl FnMut(&CStr),
    ) -> io::Result<()>;
    /// The node descriptor `name` of `table` refers to.
    /// `Ok(None)` identifies a non-device file. [`Procfs`] returns
    /// `ENOENT` when `name` holds no descriptor, and when `statx` through
    /// `table` returns `ENOENT` and [`Node::pinned`] then returns `Ok`.
    fn node(&self, table: &Self::Table, name: &CStr) -> io::Result<Option<Node>>;
    /// Whether thread `tid` of `pid` uses its leader's descriptor table.
    fn shares_leader_table(&self, pid: u32, tid: u32) -> bool;
    /// The clock tick since boot thread `tid` of `pid` started in, while it
    /// is present.
    fn started(&self, pid: u32, tid: u32) -> Option<u64>;
    /// The clock tick since boot the leader of `pid` started in, while the
    /// process table holds the process, whatever the leader's state. A
    /// table whose tasks leave it when they exit reads the tick as
    /// [`Os::started`] does.
    fn leader_started(&self, pid: u32) -> Option<u64> {
        self.started(pid, pid)
    }
    /// The ID the host gave the task it started last, when the process
    /// table shows it and every task the table lists takes its ID from the
    /// same sequence. A thread that starts in any listed process changes
    /// it, unless a process with the privilege to set the sequence sets it
    /// back. Later starts can cycle the sequence back to that ID.
    fn last_task(&self) -> Option<u32>;
    /// The ID the process table lists the calling process under, when the
    /// table numbers tasks as the calling process's PID namespace does.
    fn own_process(&self) -> Option<u32> {
        None
    }
}

/// The size and link count `stat` reports for a path.
#[derive(Debug, Clone, Copy)]
struct Status {
    size: libc::off_t,
    links: libc::nlink_t,
}

/// The process table procfs mounts at `proc`, open as `root`.
struct Procfs<'p> {
    root: Directory,
    proc: &'p Path,
    /// Whether `proc` numbers tasks as this process's PID namespace does.
    /// `loadavg` reports the last ID of the reader's namespace, which every
    /// task `proc` lists then takes an ID from.
    own: bool,
}

impl Os for Procfs<'_> {
    type Table = ProcfsTable;

    fn status(&self, path: &CStr) -> io::Result<Status> {
        let stat = self.root.stat_of(path)?;
        Ok(Status {
            size: stat.st_size,
            links: stat.st_nlink,
        })
    }

    fn open(&self, path: &CStr) -> io::Result<ProcfsTable> {
        Ok(ProcfsTable {
            directory: Directory::open(self.root.as_raw_fd(), path)?,
            pins: AtomicBool::new(false),
        })
    }

    fn entries(
        &self,
        table: &ProcfsTable,
        records: &mut [u8],
        visit: impl FnMut(&CStr),
    ) -> io::Result<()> {
        table.directory.entries(records, visit)
    }

    fn node(&self, table: &ProcfsTable, name: &CStr) -> io::Result<Option<Node>> {
        Node::held(table, name)
    }

    fn shares_leader_table(&self, pid: u32, tid: u32) -> bool {
        shares_leader_table(pid, tid)
    }

    fn started(&self, pid: u32, tid: u32) -> Option<u64> {
        start_ticks(&task_stat(self.proc, pid, tid)?)
    }

    fn leader_started(&self, pid: u32) -> Option<u64> {
        leader_start_tick(self.proc, pid)
    }

    fn last_task(&self) -> Option<u32> {
        if !self.own {
            return None;
        }
        Host::read(&self.proc.join("loadavg")).and_then(|loadavg| last_task(&loadavg))
    }

    fn own_process(&self) -> Option<u32> {
        self.own.then(std::process::id)
    }
}

/// A directory [`Procfs`] opened: the process table, a descriptor table or
/// a `task` directory.
struct ProcfsTable {
    directory: Directory,
    /// [`Node::pinned`] sets `pins` when it verifies that a pinned file
    /// whose `statx` returned `ENOENT` is a procfs directory.
    /// [`Node::held`] then opens each number of this table before it
    /// identifies the file. A walker that reads `pins` as `false` calls
    /// `statx` through the table first. If that `statx` returns `ENOENT`,
    /// `held` returns that error when `pinned` succeeds and `pinned`'s
    /// error when it fails.
    pins: AtomicBool,
}

impl AsRawFd for ProcfsTable {
    fn as_raw_fd(&self) -> c_int {
        self.directory.as_raw_fd()
    }
}

/// Walker threads, fewer on a host with less parallelism.
pub(super) const WALKERS: usize = 32;
/// Descriptors of one table a walker reads before sharing the rest.
const SHARE: usize = 128;
/// Listings of one table, after its first, that may each leave a
/// descriptor to read before the walk fails. The first of them, and each
/// that follows a read that found a descriptor vanished, reads every number
/// it returns; any other reads the numbers no listing since the last such
/// full reading returned.
const RELISTS: usize = 16;
/// Bytes of directory records read per `getdents64` call from a descriptor table.
pub(super) const RECORDS: usize = 32 * 1024;
/// Bytes of process table records read per `getdents64` call, about 150
/// processes.
const LISTING: usize = 4 * 1024;
/// Listings of one process's threads the recheck makes while each names a
/// thread the ones before lacked, before the walk fails.
const THREAD_RELISTS: usize = 16;
/// Processes queued per lock of the process queue.
const BATCH: usize = 128;
/// Listed IDs per thread that reads their start ticks.
const PER_READER: usize = 16;
/// Listings of the process table one walk makes before it fails: each but
/// the last found a process no earlier one listed.
const ROUNDS: usize = 16;
/// Offsets of the record length and name in a `linux_dirent64` record.
const RECORD_LENGTH: usize = std::mem::offset_of!(libc::dirent64, d_reclen);
const RECORD_NAME: usize = std::mem::offset_of!(libc::dirent64, d_name);
/// Links of a procfs `task` directory beyond one per thread.
const TASK_LINKS: libc::nlink_t = 2;
/// Listings of one `task` directory a walk makes before it fails for want
/// of one that agrees with the directory's link count.
const LISTINGS: usize = 64;
/// The `kcmp` type that compares two tasks' descriptor tables, from `linux/kcmp.h`.
const KCMP_FILES: c_int = 2;
/// The bit of `CAP_SYS_PTRACE` in a capability set, from `linux/capability.h`.
const CAP_SYS_PTRACE: u32 = 19;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Node {
    /// A block or character device node by its device number, so every
    /// node for one device is the same `Node`.
    Device { block: bool, major: u32, minor: u32 },
    /// Any other file by its filesystem and inode.
    File { major: u32, minor: u32, inode: u64 },
}

impl Node {
    /// Identifies `path`, relative to the directory `at` unless absolute,
    /// following symbolic links, including a descriptor's link in procfs.
    /// `Ok(None)` when the file is no device and its filesystem withholds
    /// its inode from this process.
    ///
    /// # Errors
    ///
    /// The `statx` error, or [`Node::of`]'s when the file's filesystem
    /// withholds its type.
    fn at(at: RawFd, path: &CStr) -> io::Result<Option<Self>> {
        Self::at_with(at, path, 0)
    }

    /// Identifies `path` as [`at`](Self::at) does, with `flags` added to
    /// the `statx` flags. With `AT_EMPTY_PATH` in `flags` and an empty
    /// `path`, `at_with` identifies the open file `at` itself.
    ///
    /// # Errors
    ///
    /// As [`at`](Self::at).
    fn at_with(at: RawFd, path: &CStr, flags: c_int) -> io::Result<Option<Self>> {
        let mut found = MaybeUninit::<libc::statx>::uninit();
        // With an empty request mask, a filesystem that withholds attributes
        // from this process answers with their bits clear in `stx_mask`.
        // `AT_STATX_DONT_SYNC` asks a network filesystem for its cached
        // attributes.
        // SAFETY: `path` is NUL-terminated and `found` is writable for one `statx` record.
        let result = unsafe {
            libc::statx(
                at,
                path.as_ptr(),
                flags | libc::AT_STATX_DONT_SYNC | libc::AT_NO_AUTOMOUNT,
                0,
                found.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a zero result means the kernel filled the whole record.
        Self::of(&unsafe { found.assume_init() })
    }

    /// Identifies the file that descriptor `name` of the descriptor table
    /// `table` refers to, as [`at`](Self::at) does. `statx` through the
    /// table answers `ENOENT` both for a number that holds no descriptor
    /// and for a descriptor whose file's `statx` returns `ENOENT`, as an
    /// exited process's `fd` directory does. After `statx` returns
    /// `ENOENT`, `held` calls [`pinned`](Self::pinned). An `Ok` result of
    /// `pinned` preserves the `ENOENT`: at the `statx` the number was empty
    /// or held a file the `statx` cannot tell from an empty number. An
    /// `Err` result supplies the returned error. While `table`'s `pins` is
    /// set, `held` returns what `pinned` reads for every number.
    ///
    /// # Errors
    ///
    /// `held` propagates errors from [`pinned`](Self::pinned), and every
    /// error from [`at`](Self::at) but `ENOENT`.
    fn held(table: &ProcfsTable, name: &CStr) -> io::Result<Option<Self>> {
        if table.pins.load(Ordering::Acquire) {
            return Self::pinned(table, name);
        }
        match Self::at(table.as_raw_fd(), name) {
            Err(absent) if absent.raw_os_error() == Some(libc::ENOENT) => {
                Self::pinned(table, name).and(Err(absent))
            }
            identified => identified,
        }
    }

    /// Opens descriptor `name` of the descriptor table `table` with
    /// `O_PATH` and identifies the opened file. The open succeeds only
    /// while the number holds a descriptor, and it opens the file the
    /// number holds at that instant. `pinned` returns `Ok(None)` and sets
    /// `table`'s `pins` when the opened file's `statx` returns `ENOENT`
    /// and [`procfs_directory`] returns `true` for the file.
    ///
    /// # Errors
    ///
    /// - `ENOENT` when the `O_PATH` open reports it.
    /// - `Unsupported` when the opened file answers `statx` with `ENOENT`
    ///   and [`procfs_directory`] returns `false` for it: the file could
    ///   be a device.
    /// - Any other error of the open or of [`at_with`](Self::at_with) on
    ///   the opened file.
    #[cold]
    fn pinned(table: &ProcfsTable, name: &CStr) -> io::Result<Option<Self>> {
        // SAFETY: `name` is NUL-terminated and `table` is an open directory.
        let pinned = unsafe {
            libc::openat(
                table.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        if pinned < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a nonnegative result is a descriptor this process now owns.
        let pinned = unsafe { OwnedFd::from_raw_fd(pinned) };
        match Self::at_with(pinned.as_raw_fd(), c"", libc::AT_EMPTY_PATH) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                if !procfs_directory(&pinned) {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "the file's filesystem refused its attributes",
                    ));
                }
                table.pins.store(true, Ordering::Release);
                Ok(None)
            }
            identified => identified,
        }
    }

    /// The node the `statx` record `found` identifies. `Ok(None)` when the
    /// record states a non-device file's type and withholds its inode: the
    /// file is known to be no device.
    ///
    /// # Errors
    ///
    /// `Unsupported` when the record withholds the file's type. The file
    /// may then be any device, so a walk that reads it fails.
    fn of(found: &libc::statx) -> io::Result<Option<Self>> {
        if found.stx_mask & libc::STATX_TYPE == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "statx withheld the file's type",
            ));
        }
        let kind = libc::mode_t::from(found.stx_mode) & libc::S_IFMT;
        Ok(if kind == libc::S_IFBLK || kind == libc::S_IFCHR {
            Some(Self::Device {
                block: kind == libc::S_IFBLK,
                major: found.stx_rdev_major,
                minor: found.stx_rdev_minor,
            })
        } else {
            (found.stx_mask & libc::STATX_INO != 0).then_some(Self::File {
                major: found.stx_dev_major,
                minor: found.stx_dev_minor,
                inode: found.stx_ino,
            })
        })
    }
}

/// Returns `true` when `fstatfs` reports the procfs type for `file` and
/// `.` opens relative to `file`, which the kernel permits for a directory
/// the caller may search. 9P2000.L reports the type its server sends, so a
/// device node can report the procfs type. Resolving `.` relative to
/// `file` checks that the kernel treats the open file as a directory,
/// independently of the filesystem type the server reports.
fn procfs_directory(file: &OwnedFd) -> bool {
    let mut found = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `file` is open and `found` is writable for one `statfs` record.
    let result = unsafe { libc::fstatfs(file.as_raw_fd(), found.as_mut_ptr()) };
    // SAFETY: a zero result means the kernel filled the whole record.
    if result != 0 || unsafe { found.assume_init() }.f_type != libc::PROC_SUPER_MAGIC {
        return false;
    }
    // SAFETY: the path is NUL-terminated and `file` is open.
    let directory = unsafe {
        libc::openat(
            file.as_raw_fd(),
            c".".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if directory < 0 {
        return false;
    }
    // SAFETY: a nonnegative result is a descriptor this process now owns.
    drop(unsafe { OwnedFd::from_raw_fd(directory) });
    true
}

impl Host {
    /// The node `path` refers to, or `None` when it cannot be identified.
    pub(crate) fn node(path: &Path) -> Option<Node> {
        let path = CString::new(path.as_os_str().as_bytes()).ok()?;
        Node::at(libc::AT_FDCWD, &path).ok().flatten()
    }

    /// Every node that `matches` and that some open descriptor refers to,
    /// once each, in ascending order.
    ///
    /// Each numeric entry of `proc` is one process. The walkers call
    /// `matches` concurrently. The walk reads the table of each process's
    /// leader and of each of its other threads, so it finds a descriptor held
    /// only in a thread's private table, as after `unshare(CLONE_FILES)`, or
    /// held by the threads of a process whose leader exited. A thread that
    /// `kcmp` reports sharing its leader's table is read through the leader
    /// alone when `proc` numbers tasks as this process's PID namespace does.
    ///
    /// Returns `None` when the calling thread lacks `CAP_SYS_PTRACE` or this
    /// process runs outside the initial user namespace, so `proc` may hide
    /// processes from it and the walkers it starts, when `proc` cannot be
    /// opened, a listing read fails or
    /// yields a malformed record, a table or descriptor cannot be read for a
    /// reason other than its process or descriptor vanishing, a table keeps
    /// returning unread descriptor numbers through [`RELISTS`] listings, no
    /// listing of a process's threads agrees with its thread count, a walker
    /// thread fails to spawn, a walker panics, a listing finds a process
    /// without a start tick under an ID an earlier listing found without
    /// one, or each of [`ROUNDS`] listings finds a process no earlier one
    /// listed or follows, within two rounds, a fall of the last task ID
    /// `proc` reports. Every walker has finished walking before `opened`
    /// returns; the walker threads exit afterward.
    ///
    /// # Panics
    ///
    /// With the panic of a thread that read start ticks for a listing.
    pub(crate) fn opened(&self, matches: impl Fn(Node) -> bool + Sync) -> Option<Vec<Node>> {
        if !traces_every_process(&self.proc) {
            return None;
        }
        let root = CString::new(self.proc.as_os_str().as_bytes())
            .ok()
            .and_then(|path| Directory::open(libc::AT_FDCWD, &path).ok())?;
        let kcmp = numbers_tasks_as_kcmp(&self.proc);
        let os = Procfs {
            root,
            proc: &self.proc,
            own: kcmp,
        };
        // Linux 6.2 and later report a descriptor table's entry count as the
        // size of its `fd` directory. This process holds `root` open, so a
        // zero size for its own table identifies an older kernel, and every
        // table is then read.
        let reports_count =
            fs::metadata(self.proc.join("self/fd")).is_ok_and(|meta| meta.len() > 0);
        let begun = boot_ticks(&self.proc);
        let walkers = thread::available_parallelism()
            .map_or(1, NonZero::get)
            .min(WALKERS);
        let facts = Facts {
            reports_count,
            kcmp,
            begun,
            walkers,
        };
        let found = Mutex::new(Some(Vec::new()));
        let round = |seen: &mut BTreeSet<Listed>| {
            // A listing reads on from where the directory's last one ended,
            // so each round lists through a descriptor of its own.
            let Ok(table) = os.open(c".") else {
                return false;
            };
            let queue = Queue::<ProcfsTable>::default();
            let walk = || {
                // SAFETY: `unshare` takes no memory arguments. On success,
                // `CLONE_FS` gives this thread a private `fs_struct` and lock.
                unsafe { libc::unshare(libc::CLONE_FS) };
                Walker::new(&os, &queue, &matches, facts).walk(&found);
            };
            // The listing queues its processes once it has read every
            // start tick, so the walkers start after it, in a round that
            // queued a process.
            let own = os.own_process();
            let walked = |seen: &BTreeSet<Listed>| {
                own.is_some_and(|own| seen.range((own, None)..=(own, Some(u64::MAX))).count() > 0)
            };
            let before = walked(seen);
            let listed = queue.list(&os, &table, seen);
            if queue.queued.load(Ordering::Acquire) != 0 {
                thread::scope(|scope| {
                    // The scope waits for every walker's closure, not for its
                    // thread to exit, so a round ends while the kernel tears the
                    // threads down.
                    for _ in 0..walkers {
                        if thread::Builder::new().spawn_scoped(scope, walk).is_err() {
                            keep(&found, None);
                        }
                    }
                });
            }
            // The walkers open and close descriptors in this process's own
            // table, at the numbers they free, for as long as they run. The
            // listing leaves this process out of their queue, and the
            // calling thread walks it here, once they have finished.
            if let Some(own) = own.filter(|_| !before && walked(seen)) {
                let alone = Queue::<ProcfsTable>::default();
                alone.push(&alone.processes, &mut vec![own], true);
                alone.listed.store(true, Ordering::Release);
                let facts = Facts {
                    walkers: 1,
                    ..facts
                };
                Walker::new(&os, &alone, &matches, facts).walk(&found);
            }
            listed
        };
        let walked = settled(round, || os.last_task());
        answer(found, walked)
    }
}

/// A listed process: its ID and the clock tick its leader started in, or
/// `None` when the listing could not read that tick. An entry without a
/// tick names no one process: it records that a listing found a process it
/// could not identify under the ID.
pub(super) type Listed = (u32, Option<u64>);

/// Runs rounds of one walk, or of one ring pass, until a round adds no
/// process to those the rounds before it listed and the host's ID cursor
/// turned back across neither that round nor the one before it. Each
/// `round` lists the process table, adding each process it takes up to the
/// set it is given, and returns once every read of those processes has
/// finished, with whether the listing and every read or spawn succeeded.
/// `last` reads the ID the host gave the task it started last; it is read
/// before the first round and after each round, and a reading below the
/// latest one before it shows that the cursor turned back in a round
/// between them. A reading at or above that one shows no turn only on the
/// module's premise that a cursor which turned back still stands below the
/// earlier reading. A failed reading shows nothing, so a walk that can read
/// no ID ends with its first round that lists no new process. Reports
/// whether every round succeeded and one within [`ROUNDS`] ended the walk.
///
/// A process the last listing passed over while its parent exited unread
/// started under an ID below its parent's, and that parent, which no
/// earlier round listed, started after the listing before began. Without a
/// turn of the cursor between the two starts the child's ID lies above its
/// parent's, and the listing reaches it.
pub(super) fn settled<P: Ord>(
    mut round: impl FnMut(&mut BTreeSet<P>) -> bool,
    last: impl Fn() -> Option<u32>,
) -> bool {
    let mut seen = BTreeSet::new();
    let mut mark = last();
    // Rounds, up to this one, since a reading of the last ID fell.
    let mut ordered = 0;
    for _ in 0..ROUNDS {
        let before = seen.len();
        if !round(&mut seen) {
            return false;
        }
        let now = last();
        let fell = mark.zip(now).is_some_and(|(mark, now)| now < mark);
        ordered = if fell { 0 } else { ordered + 1 };
        mark = now.or(mark);
        if seen.len() == before && ordered >= 2 {
            return true;
        }
    }
    false
}

/// Adds each of `pids`, the processes one listing of a process table
/// found, to `seen` with the clock tick its leader started in, which `tick`
/// reads as [`started`] states. Returns the IDs of the processes `seen`
/// lacked, in listing order, and whether the listing identified every
/// process: it found none without a start tick under an ID `seen` held
/// without one.
///
/// A process under an ID `seen` holds with another start tick is one `seen`
/// lacks: the host gave it the ID of a process that exited. A process
/// without a start tick under an ID `seen` holds without one may be the
/// process that entry was listed for or one the host gave its ID since,
/// which no round has read. The listing cannot tell which, so its round
/// fails.
///
/// # Panics
///
/// As [`started`].
pub(super) fn unlisted(
    tick: impl Fn(u32) -> Option<u64> + Sync,
    pids: Vec<u32>,
    seen: &mut BTreeSet<Listed>,
) -> (Vec<u32>, bool) {
    let ticks = started(&tick, &pids);
    let mut identified = true;
    let new = pids
        .into_iter()
        .zip(ticks)
        .filter(|&listed| {
            let new = seen.insert(listed);
            identified &= new || listed.1.is_some();
            new
        })
        .map(|listed| listed.0)
        .collect();
    (new, identified)
}

/// The clock tick the leader of each of `pids` started in, in their order,
/// or `None` where it cannot be read: one call of `tick`, which reads a
/// `stat` entry, each. The reads are shared by one thread per
/// [`PER_READER`] IDs, at least one and at most the host's parallelism or
/// [`WALKERS`], the calling thread among them, so fewer than twice
/// [`PER_READER`] IDs are read by the calling thread alone, in order. A
/// thread that cannot start leaves its IDs to the calling thread.
///
/// # Panics
///
/// With the panic of a thread that read a share.
fn started(tick: &(impl Fn(u32) -> Option<u64> + Sync), pids: &[u32]) -> Vec<Option<u64>> {
    let read = |pids: &[u32]| -> Vec<Option<u64>> { pids.iter().map(|&pid| tick(pid)).collect() };
    let readers = (pids.len() / PER_READER).min(WALKERS);
    if readers < 2 {
        return read(pids);
    }
    let readers = readers.min(thread::available_parallelism().map_or(1, NonZero::get));
    let mut shares = pids.chunks(pids.len().div_ceil(readers));
    let own = shares.next().unwrap_or_default();
    thread::scope(|scope| {
        let others: Vec<_> = shares
            .map(|share| {
                let reader = thread::Builder::new().spawn_scoped(scope, move || read(share));
                (share, reader)
            })
            .collect();
        let mut ticks = read(own);
        for (share, reader) in others {
            ticks.extend(match reader {
                Ok(reader) => reader
                    .join()
                    .unwrap_or_else(|panic| panic::resume_unwind(panic)),
                Err(_) => read(share),
            });
        }
        ticks
    })
}

/// The walk's answer once every walker has finished: every node the walkers
/// kept, once each, in ascending order, or `None` when a walker failed or
/// could not start, or `walked` is unset because a listing failed or the
/// rounds did not settle.
fn answer(found: Mutex<Option<Vec<Node>>>, walked: bool) -> Option<Vec<Node>> {
    let mut found = found.into_inner().ok().flatten().filter(|_| walked)?;
    found.sort_unstable();
    found.dedup();
    Some(found)
}

/// Adds a walker's result to `found`, or clears it when the walker failed.
fn keep(found: &Mutex<Option<Vec<Node>>>, walked: Option<Vec<Node>>) {
    if let Ok(mut found) = found.lock() {
        match (found.as_mut(), walked) {
            (Some(found), Some(mut walked)) => found.append(&mut walked),
            _ => *found = None,
        }
    }
}

/// The work the walkers share: processes the listing has found, shares of
/// large descriptor tables, processes whose counted reads are done and whose
/// next step is due, and threads whose own tables are due.
struct Queue<T, C = AtomicUsize> {
    processes: Lane<u32>,
    shares: Lane<Share<T>>,
    /// Processes whose leader's table every share of has been read, due
    /// for their threads, or whose threads' tables are all read, due for
    /// the leader's recheck.
    threads: Lane<Arc<Leader>>,
    /// Threads, by thread ID and process, whose own tables are due.
    tables: Lane<(u32, Arc<Leader>)>,
    /// Items held by the four queues, so an idle walker locks none of them
    /// while all are empty.
    queued: AtomicUsize,
    /// Work not yet finished: each process until its other threads' tables
    /// are read and its leader rechecked, each thread table and each share.
    /// Work is counted before it is queued, and the work that queues it
    /// finishes after, so the count reaches zero only once every listed
    /// process is walked.
    pending: C,
    /// Set once every process is counted and queued.
    listed: AtomicBool,
    /// Set when a walker panicked, which fails the walk.
    aborted: AtomicBool,
}

impl<T, C: Default> Default for Queue<T, C> {
    fn default() -> Self {
        Self {
            processes: Lane::default(),
            shares: Lane::default(),
            threads: Lane::default(),
            tables: Lane::default(),
            queued: AtomicUsize::new(0),
            pending: C::default(),
            listed: AtomicBool::new(false),
            aborted: AtomicBool::new(false),
        }
    }
}

/// One kind of queued work, with its length readable without the lock.
/// The alignment gives each lane cache lines of its own, apart from the
/// other lanes and the queue's counts.
#[repr(align(128))]
struct Lane<T> {
    items: Mutex<Vec<T>>,
    len: AtomicUsize,
}

impl<T> Default for Lane<T> {
    fn default() -> Self {
        Self {
            items: Mutex::new(Vec::new()),
            len: AtomicUsize::new(0),
        }
    }
}

impl<T, C: Count> Queue<T, C> {
    /// Lists the processes of `root`, the process table, and queues those
    /// `seen` lacks on the process lane in batches, adding each to `seen`,
    /// then marks the listing ended. A process under an ID `seen` holds
    /// with another start tick is one `seen` lacks: the host gave it the ID
    /// of a process that exited. The calling process, where
    /// [`Os::own_process`] names it, is added to `seen` and left off the
    /// lane, for the caller to walk once the walkers have finished. The
    /// start ticks of the listed IDs are read once the listing ends, by
    /// [`unlisted`]. Reports whether the listing read every entry and
    /// identified every process, as [`unlisted`] states.
    ///
    /// # Panics
    ///
    /// As [`unlisted`].
    fn list<O: Os<Table = T>>(&self, os: &O, root: &T, seen: &mut BTreeSet<Listed>) -> bool {
        let mut pids = Vec::new();
        let mut records = vec![0u8; LISTING];
        let listed = os.entries(root, &mut records, |name| pids.extend(decimal(name)));
        let (new, identified) = unlisted(|pid| os.leader_started(pid), pids, seen);
        let mut batch = Vec::with_capacity(BATCH);
        let own = os.own_process();
        for pid in new {
            if Some(pid) != own {
                batch.push(pid);
                if batch.len() == BATCH {
                    self.push(&self.processes, &mut batch, true);
                }
            }
        }
        self.push(&self.processes, &mut batch, true);
        self.listed.store(true, Ordering::Release);
        listed.is_ok() && identified
    }

    /// Queues `items` on `lane`, counting each as pending when `work` is set.
    fn push<U>(&self, lane: &Lane<U>, items: &mut Vec<U>, work: bool) {
        let count = items.len();
        if work {
            self.pending.fetch_add(count, Ordering::AcqRel);
        }
        if let Ok(mut queued) = lane.items.lock() {
            queued.append(items);
            lane.len.fetch_add(count, Ordering::AcqRel);
        }
        self.queued.fetch_add(count, Ordering::AcqRel);
    }

    /// Takes the last item queued on `lane`.
    fn pop<U>(&self, lane: &Lane<U>) -> Option<U> {
        if lane.len.load(Ordering::Acquire) == 0 {
            return None;
        }
        let item = {
            let mut queued = lane.items.lock().ok()?;
            let item = queued.pop()?;
            lane.len.fetch_sub(1, Ordering::AcqRel);
            item
        };
        self.queued.fetch_sub(1, Ordering::AcqRel);
        Some(item)
    }

    /// Counts one piece of work finished.
    fn finish(&self) {
        self.pending.fetch_sub(1, Ordering::AcqRel);
    }

    /// Queues `names` of `table` for any walker, counting the share as
    /// unread in `listing`, and in `leader` when the table is a leader's.
    fn share(
        &self,
        (table, listing): (&Arc<T>, &Arc<FirstListing>),
        names: &mut Vec<CString>,
        leader: Option<&Arc<Leader>>,
        via: Option<u32>,
    ) {
        if let Some(leader) = leader {
            leader.unread.fetch_add(1, Ordering::AcqRel);
        }
        listing.unread.fetch_add(1, Ordering::AcqRel);
        let share = Share {
            table: Arc::clone(table),
            names: std::mem::take(names),
            listing: Arc::clone(listing),
            leader: leader.cloned(),
            via,
        };
        self.push(&self.shares, &mut vec![share], true);
    }

    /// Whether every process is listed and all work is finished, or a
    /// walker panicked.
    fn drained(&self) -> bool {
        self.aborted.load(Ordering::Acquire)
            || self.listed.load(Ordering::Acquire) && self.pending.load(Ordering::Acquire) == 0
    }
}

/// Up to [`SHARE`] descriptors of one table, to be read by any walker.
struct Share<T> {
    table: Arc<T>,
    names: Vec<CString>,
    /// The reads of the table's first listing, which the last of them ends.
    listing: Arc<FirstListing>,
    /// The process whose leader's or thread's table holds these descriptors.
    leader: Option<Arc<Leader>>,
    /// A thread of that process, whose own `fd` directory the share is read
    /// through first.
    via: Option<u32>,
}

/// The reads of one table's first listing: the listing walker's own and one
/// per queued share. The read that ends last lists the table again.
struct FirstListing {
    /// Reads not yet ended: one per queued share, plus one until the listing
    /// walker has read its own descriptors.
    unread: AtomicUsize,
}

/// A process whose tables are being read: first its leader's, then its
/// other threads' own tables, then the leader's again when an exec may
/// have replaced the leader.
struct Leader {
    pid: u32,
    /// Whether the process had threads other than its leader before the
    /// read began.
    threaded: bool,
    /// The ID the host gave the task it started last, read before
    /// `threaded`, when it could be read.
    last: Option<u32>,
    /// Reads of the current step not yet done: shares of the leader's table,
    /// plus one while the walker that took the process lists it; then its
    /// threads' own tables and their shares.
    unread: AtomicUsize,
    /// Set once the threads are compared: the threads other than the leader
    /// that the `task` directory listed then. The recheck reads the table
    /// under `pid` again when the first listed thread is gone. For each
    /// thread a later listing adds, it reads the thread's table, or skips
    /// the read when `kcmp` reports that thread on the leader's table under
    /// the rule [`Walker::recheck`] states.
    listed: OnceLock<Vec<u32>>,
}

/// What every walker of one walk knows about the host and the walk.
#[derive(Debug, Clone, Copy)]
struct Facts {
    /// Whether the kernel reports a table's entry count as its directory size.
    reports_count: bool,
    /// Whether `kcmp` resolves the process table's IDs to the tasks it lists.
    kcmp: bool,
    /// The clock tick since boot at which the walk began, rounded down.
    begun: Option<u64>,
    /// Walker threads of the walk. After listing a table, a walker reads
    /// queued shares itself while the queue holds more than this many.
    walkers: usize,
}

struct Walker<'w, M, O: Os, C> {
    os: &'w O,
    queue: &'w Queue<O::Table, C>,
    matches: &'w M,
    facts: Facts,
    records: Vec<u8>,
    found: Vec<Node>,
    /// Whether a table or descriptor this walker read failed with an error
    /// other than `ENOENT`.
    failed: bool,
    /// Whether a descriptor read since this was last cleared had vanished.
    vanished: bool,
}

impl<'w, M: Fn(Node) -> bool, O: Os, C: Count> Walker<'w, M, O, C> {
    fn new(os: &'w O, queue: &'w Queue<O::Table, C>, matches: &'w M, facts: Facts) -> Self {
        Self {
            os,
            queue,
            matches,
            facts,
            records: vec![0u8; RECORDS],
            found: Vec::new(),
            failed: false,
            vanished: false,
        }
    }

    /// Runs this walker and adds its result to `found`, or clears `found`
    /// when it failed. A walker that panicked leaves its work unfinished,
    /// so it sets the queue aborted and the others stop instead of waiting
    /// for it.
    fn walk(self, found: &Mutex<Option<Vec<Node>>>) {
        let queue = self.queue;
        let walked = panic::catch_unwind(AssertUnwindSafe(|| self.run()));
        if walked.is_err() {
            queue.aborted.store(true, Ordering::Release);
        }
        keep(found, walked.ok().flatten());
    }

    /// Reads queued shares, then the threads of processes whose leader's
    /// table is read, then threads' own tables, before taking new processes,
    /// until all work is finished. `None` when a read failed.
    fn run(mut self) -> Option<Vec<Node>> {
        loop {
            if self.queue.queued.load(Ordering::Acquire) == 0 {
                if self.queue.drained() {
                    return (!self.failed).then_some(self.found);
                }
                yield_now();
                continue;
            }
            if self.read_share(true) {
                continue;
            }
            if let Some(leader) = self.queue.pop(&self.queue.threads) {
                self.next(&leader);
                continue;
            }
            if let Some((tid, leader)) = self.queue.pop(&self.queue.tables) {
                self.descriptors(&format!("{}/task/{tid}/fd", leader.pid), Some(&leader));
                self.read_of(&leader, true);
                self.queue.finish();
                continue;
            }
            if let Some(pid) = self.queue.pop(&self.queue.processes) {
                self.process(pid);
            } else {
                // Another walker took the item the count still holds.
                yield_now();
            }
        }
    }

    /// Reads the descriptor table of `pid`'s leader. Once every share of it
    /// is read, the walker that read the last one reads `pid`'s other
    /// threads, and `pid` stays pending until they are compared, every
    /// private table among them is read, and the leader is rechecked.
    fn process(&mut self, pid: u32) {
        let last = self.os.last_task();
        let leader = Arc::new(Leader {
            pid,
            threaded: self.threaded(pid),
            last,
            unread: AtomicUsize::new(1),
            listed: OnceLock::new(),
        });
        self.descriptors(&format!("{pid}/fd"), Some(&leader));
        self.read_of(&leader, true);
    }

    /// Counts one read of `leader`'s current step done. When it was the
    /// last, takes the process's next step now if `now` is set, and
    /// otherwise queues it for any walker.
    fn read_of(&mut self, leader: &Arc<Leader>, now: bool) {
        if leader.unread.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        if now {
            self.next(leader);
        } else {
            let mut due = vec![Arc::clone(leader)];
            self.queue.push(&self.queue.threads, &mut due, false);
        }
    }

    /// Takes `leader`'s next step: its threads once its leader's table is
    /// read, or the recheck once their tables are read, which finishes the
    /// process.
    fn next(&mut self, leader: &Arc<Leader>) {
        if leader.listed.get().is_some() {
            self.recheck(leader);
            self.queue.finish();
        } else {
            self.threads(leader);
        }
    }

    /// Queues the table of every thread of `leader`'s process but the
    /// leader, when the process has more than one thread, and finishes the
    /// process when none is queued. With `kcmp` set, a thread that `kcmp`
    /// reports sharing the leader's table is skipped: every descriptor of
    /// that table was read before the comparison, so the walk reports the
    /// descriptors it held then.
    ///
    /// A comparison names a thread by its ID, which the host can give to a
    /// thread started after the listing once the listed thread is gone. The
    /// listed thread may have used a table of its own and left it to a
    /// thread it started. So a process with no table queued finishes here
    /// only when the host has started no task since its threads were
    /// counted; otherwise the recheck lists its threads again. It reads the
    /// table of each thread it cannot tell is a listed one, or skips a
    /// thread that `kcmp` reports on the leader's table under the rule
    /// [`Walker::recheck`] states. A thread left a table of its own
    /// compares as different from the leader, so the recheck reads that
    /// table.
    fn threads(&mut self, leader: &Arc<Leader>) {
        let pid = leader.pid;
        let mut failure = None;
        let tids = self.tids(pid, &mut failure);
        if let Some(error) = failure {
            self.note(&error);
        }
        let shared: Vec<bool> = tids
            .iter()
            .map(|tid| self.facts.kcmp && self.os.shares_leader_table(pid, *tid))
            .collect();
        // An exec swaps a process's leader only after every other thread is
        // gone, so a thread that started before the walk and is still listed
        // after every comparison proves all comparisons used the leader whose
        // table the walk read. An exec in this process ends the walk before
        // it returns.
        let witness = tids.first().copied();
        let unchanged =
            pid == std::process::id() || witness.is_some_and(|tid| self.predates_walk(pid, tid));
        let own: Vec<u32> = tids
            .iter()
            .zip(shared)
            .filter(|(_, shared)| !(unchanged && *shared))
            .map(|(tid, _)| *tid)
            .collect();
        let _ = leader.listed.set(tids);
        if own.is_empty() {
            // With no table queued after the check, an unchanged leader's
            // table stands as read, and each comparison was of the listed
            // thread while no task has started since the count.
            if !unchanged || self.task_started_since(leader) {
                self.recheck(leader);
            }
            self.queue.finish();
            return;
        }
        leader.unread.store(own.len(), Ordering::Release);
        let mut own: Vec<(u32, Arc<Leader>)> = own
            .into_iter()
            .map(|tid| (tid, Arc::clone(leader)))
            .collect();
        self.queue.push(&self.queue.tables, &mut own, true);
    }

    /// Reads the table under `leader`'s process ID again, unless its witness
    /// thread remains or the process has had no other thread. A thread that
    /// execs after the comparisons takes over the process's ID with its own
    /// table, and its former ID vanishes before or while the walk reads the
    /// table there. The process has had no other thread when it had none
    /// before the read and the host has started no task since.
    ///
    /// Then lists the process's threads again and reads the table of each
    /// thread no earlier listing named, until a listing names no new one. A
    /// thread on a private table that starts another thread after the first
    /// listing and exits hands its table to a thread that listing lacks, and
    /// its own table reads `ENOENT`. The host can give a departed thread's
    /// ID to a thread started later, so a listed ID counts as a thread an
    /// earlier listing named only while the walk can tell it is that
    /// thread: for the first listing, while its thread started before the
    /// walk; for a relisting, while its thread started in the clock tick
    /// that relisting read for it; and for either, while the host has
    /// started no task since that listing, by the last task ID it gave. A
    /// start tick that cannot be read, as once a thread is gone, matches no
    /// tick. A thread that takes a departed thread's ID in the tick that
    /// thread started in is not told apart from it. After
    /// [`THREAD_RELISTS`] listings that each named a new thread, the walk
    /// fails. This process is not listed again: its walker threads share its
    /// leader's table. Until the cursor cycles back to the ID read after
    /// a listing, a matching ID rules out a task start between the two
    /// readings.
    ///
    /// Exec terminates the process's other threads. Each process-ID table
    /// read follows a thread listing whose (thread ID, start tick) pairs
    /// serve as witnesses. Before any such read, the witness set contains
    /// only the witness thread, if one exists. A listing with no new thread
    /// ends the recheck if a listed thread predates the walk or every
    /// witness appears with its recorded start tick. Otherwise, the walk
    /// repeats the process-ID table read and thread listing; the listing
    /// counts toward [`THREAD_RELISTS`]. Threads created after a
    /// witness-free read share or copy the table read at that point. If a
    /// witness exits and no thread predating the walk remains, the check
    /// requires one additional listing and process-ID table read.
    ///
    /// With [`Facts::kcmp`] set, the recheck uses `kcmp` to compare each
    /// newly listed thread's table with the leader's, and skips the read of
    /// a thread that shares it while one witness, or one listed thread that
    /// predates the walk, has its recorded start tick after the
    /// comparisons. That thread ties the compared table to a read the walk
    /// made under the process's ID, and the read covers the threads that
    /// share the table. The recheck reads the table of every other newly
    /// listed thread. The next listing rechecks the thread ID regardless of
    /// the `kcmp` result.
    fn recheck(&mut self, leader: &Leader) {
        let pid = leader.pid;
        if pid == std::process::id() {
            return;
        }
        let listed = leader.listed.get().cloned().unwrap_or_default();
        let witness = listed
            .first()
            .filter(|_| self.facts.begun.is_some())
            .and_then(|&tid| Some((tid, self.os.started(pid, tid)?)))
            .filter(|&(_, tick)| self.before_walk(tick));
        let mut reread = witness.is_none()
            && (leader.threaded || !listed.is_empty() || self.task_started_since(leader));
        let mut before: Vec<(u32, u64)> = witness.into_iter().collect();
        // Each thread a relisting named, with the clock tick read for it
        // and the last task ID read after that listing, each when read.
        let mut relisted: Vec<(u32, Option<u64>, Option<u32>)> = Vec::new();
        for _ in 0..THREAD_RELISTS {
            let mut failure = None;
            let tids = self.tids(pid, &mut failure);
            if let Some(error) = failure {
                self.note(&error);
            }
            let ticks: Vec<(u32, Option<u64>)> = tids
                .into_iter()
                .map(|tid| (tid, self.os.started(pid, tid)))
                .collect();
            let mut now = None;
            let mut started = Vec::new();
            for &(tid, since) in &ticks {
                if listed.contains(&tid) && since.is_some_and(|tick| self.before_walk(tick)) {
                    continue;
                }
                if since.is_some()
                    && relisted
                        .iter()
                        .any(|named| (named.0, named.1) == (tid, since))
                {
                    continue;
                }
                let now = *now.get_or_insert_with(|| self.os.last_task());
                let quiet = |last: Option<u32>| last.is_some() && last == now;
                if listed.contains(&tid) && quiet(leader.last)
                    || relisted
                        .iter()
                        .any(|named| named.0 == tid && quiet(named.2))
                {
                    continue;
                }
                started.push((tid, since, now));
            }
            if started.is_empty() && !reread && self.unexeced(&before, &ticks) {
                return;
            }
            // A successful comparison establishes table sharing only at the
            // instant of the comparison. An exec ends the process's other
            // threads before it swaps the table under the process's ID. A
            // witness of the last read under that ID that is present after
            // the comparisons therefore ties the shared table to that read,
            // and a thread that started before the walk ties it to the
            // leader's first read.
            let witnesses: Vec<(u32, u64)> = ticks
                .iter()
                .filter_map(|&(tid, tick)| Some((tid, tick?)))
                .filter(|&(_, tick)| self.before_walk(tick))
                .chain(before.iter().copied())
                .collect();
            let compared = self.facts.kcmp && !witnesses.is_empty();
            let shared: Vec<bool> = started
                .iter()
                .map(|&(tid, _, _)| compared && self.os.shares_leader_table(pid, tid))
                .collect();
            let unchanged = shared.contains(&true)
                && witnesses
                    .iter()
                    .any(|&(tid, tick)| self.os.started(pid, tid) == Some(tick));
            for (&(tid, _, _), shared) in started.iter().zip(shared) {
                if !(unchanged && shared) {
                    self.descriptors(&format!("{pid}/task/{tid}/fd"), None);
                }
            }
            if reread || started.is_empty() {
                before = ticks
                    .iter()
                    .filter_map(|&(tid, tick)| Some((tid, tick?)))
                    .collect();
                self.descriptors(&format!("{pid}/fd"), None);
            }
            reread = false;
            relisted.append(&mut started);
        }
        self.failed = true;
    }

    fn unexeced(&self, before: &[(u32, u64)], ticks: &[(u32, Option<u64>)]) -> bool {
        ticks
            .iter()
            .any(|&(_, tick)| tick.is_some_and(|tick| self.before_walk(tick)))
            || before
                .iter()
                .all(|&(tid, tick)| ticks.contains(&(tid, Some(tick))))
    }

    /// Whether `pid` has threads other than its leader, by the link count of
    /// its `task` directory. A directory that cannot be stat-ed reports
    /// `false`; listing it later reports the failure.
    fn threaded(&self, pid: u32) -> bool {
        CString::new(format!("{pid}/task"))
            .ok()
            .and_then(|task| self.os.status(&task).ok())
            .is_some_and(|task| task.links > TASK_LINKS + 1)
    }

    /// Whether the host may have started a task since `leader`'s threads
    /// were counted: the last task ID it gave has changed or cannot be read.
    /// Until the cursor returns to the same ID, an equal reading rules out
    /// a start.
    fn task_started_since(&self, leader: &Leader) -> bool {
        leader.last.is_none() || self.os.last_task() != leader.last
    }

    /// Whether thread `tid` of `pid` is present and started in a clock tick
    /// before the one the walk began in, which proves it started before the
    /// walk.
    fn predates_walk(&self, pid: u32, tid: u32) -> bool {
        self.facts.begun.is_some()
            && self
                .os
                .started(pid, tid)
                .is_some_and(|started| self.before_walk(started))
    }

    fn before_walk(&self, started: u64) -> bool {
        self.facts.begun.is_some_and(|begun| started < begun)
    }

    /// The IDs of `pid`'s threads other than its leader, empty when it has
    /// one thread. A failure to stat or list `<pid>/task` is left in `failure`.
    ///
    /// The kernel resumes a listing by count once a thread it stood on has
    /// exited, and so passes over a thread that stays when threads exit
    /// during the listing. A listing is kept only when it names as many tasks
    /// as the directory's link count reports both before and after it, which
    /// no listing a single exit shortened does. The directory is listed
    /// again otherwise, up to [`LISTINGS`] times, and `failure` then holds an
    /// error that fails the walk.
    fn tids(&mut self, pid: u32, failure: &mut Option<io::Error>) -> Vec<u32> {
        let Ok(task) = CString::new(format!("{pid}/task")) else {
            return Vec::new();
        };
        let mut links = match self.os.status(&task) {
            Ok(task) => task.links,
            Err(error) => {
                *failure = Some(error);
                return Vec::new();
            }
        };
        for _ in 0..LISTINGS {
            if links <= TASK_LINKS + 1 {
                return Vec::new();
            }
            let threads = match self.os.open(&task) {
                Ok(threads) => threads,
                Err(error) => {
                    *failure = Some(error);
                    return Vec::new();
                }
            };
            let mut tids = Vec::new();
            let mut tasks: libc::nlink_t = 0;
            let mut records = std::mem::take(&mut self.records);
            let listed = self.os.entries(&threads, &mut records, |name| {
                if let Some(tid) = decimal(name) {
                    tasks += 1;
                    tids.extend((tid != pid).then_some(tid));
                }
            });
            self.records = records;
            if let Err(error) = listed {
                *failure = Some(error);
                return tids;
            }
            let after = match self.os.status(&task) {
                Ok(task) => task.links,
                Err(error) => {
                    *failure = Some(error);
                    return tids;
                }
            };
            if after == links && tasks + TASK_LINKS == links {
                return tids;
            }
            links = after;
            yield_now();
        }
        *failure = Some(io::Error::other("threads exited through every listing"));
        Vec::new()
    }

    /// Reads one queued share, and reports whether the queue held one. When
    /// it was the last share of a leader's table, reads that process's other
    /// threads now if `now` is set, and otherwise queues them.
    fn read_share(&mut self, now: bool) -> bool {
        let Some(share) = self.queue.pop(&self.queue.shares) else {
            return false;
        };
        let through = match (&share.leader, share.via) {
            (Some(leader), Some(tid)) => self.read_through(leader.pid, tid, &share.names),
            _ => false,
        };
        if !through {
            for name in &share.names {
                self.read(&share.table, name);
            }
        }
        self.listed(&share.table, &share.listing);
        if let Some(leader) = &share.leader {
            self.read_of(leader, now);
        }
        self.queue.finish();
        true
    }

    /// Queues all but the first [`SHARE`] descriptors of the table at `path`
    /// in the process table, reads those first ones, then reads queued
    /// shares while the queue holds more than one per walker. Without a
    /// `leader` to count its shares, as when the recheck reads a table, it
    /// reads every descriptor of the table itself, so the recheck lists the
    /// process's threads again only once the table is read. A queued share
    /// keeps its table open, so the open tables stay within about three per
    /// walker however many threads a process has: the queued shares', the
    /// `task` directory each walker lists threads from, and the one table
    /// each lists or reads a share of. With `reports_count` set, a table of
    /// size zero is skipped unopened. Once this walker and the walkers of the
    /// queued shares have read every descriptor of the first listing, the
    /// table is listed again for numbers the first listing did not return.
    fn descriptors(&mut self, path: &str, leader: Option<&Arc<Leader>>) {
        let Ok(path) = CString::new(path) else {
            return;
        };
        let mut size = 0;
        if self.facts.reports_count {
            match self.os.status(&path) {
                Ok(table) if table.size == 0 => return,
                Ok(table) => size = usize::try_from(table.size).unwrap_or(0),
                Err(_) => {}
            }
        }
        // The threads a leader table's shares are read through. Listing them
        // is an optimization alone, so a failure leaves the shares to the
        // leader's directory. A thread's own table is read through its own
        // directory.
        let mut via = Vec::new();
        if self.facts.kcmp
            && size > SHARE
            && let Some(leader) = leader
            && leader.listed.get().is_none()
        {
            via = self.tids(leader.pid, &mut None);
        }
        let mut shares = 0;
        let descriptors = match self.os.open(&path) {
            Ok(descriptors) => Arc::new(descriptors),
            Err(error) => return self.note(&error),
        };
        let mut own: Vec<CString> = Vec::new();
        let mut rest: Vec<CString> = Vec::new();
        let listing = Arc::new(FirstListing {
            unread: AtomicUsize::new(1),
        });
        let mut records = std::mem::take(&mut self.records);
        let listed = self.os.entries(&descriptors, &mut records, |name| {
            if decimal(name).is_none() {
                return;
            }
            if own.len() < SHARE || leader.is_none() {
                own.push(name.to_owned());
                return;
            }
            rest.push(name.to_owned());
            if rest.len() == SHARE {
                let through = (!via.is_empty()).then(|| via[shares % via.len()]);
                self.queue
                    .share((&descriptors, &listing), &mut rest, leader, through);
                shares += 1;
            }
        });
        self.records = records;
        if let Err(error) = listed {
            self.note(&error);
        }
        if !rest.is_empty() {
            let through = (!via.is_empty()).then(|| via[shares % via.len()]);
            self.queue
                .share((&descriptors, &listing), &mut rest, leader, through);
        }
        for name in &own {
            self.read(&descriptors, name);
        }
        self.listed(&descriptors, &listing);
        drop(descriptors);
        while self.queue.shares.len.load(Ordering::Acquire) > self.facts.walkers {
            if !self.read_share(false) {
                break;
            }
        }
    }

    /// Reads `names` of `pid`'s leader's table through the `fd` directory of
    /// its thread `tid`, and keeps the result only when `kcmp` then reports
    /// that `tid` uses the leader's table and `tid` still names a thread
    /// that started before the walk. A thread that leaves its leader's
    /// table never uses it again, so the result is the leader's table's.
    /// The start time ties the comparison to the thread whose directory was
    /// read: the directory of a thread that exited answers `ENOENT` for
    /// every name, and a thread that took its ID since then started during
    /// the walk. Reports whether the result was kept.
    fn read_through(&mut self, pid: u32, tid: u32, names: &[CString]) -> bool {
        let Ok(path) = CString::new(format!("{pid}/task/{tid}/fd")) else {
            return false;
        };
        let Ok(table) = self.os.open(&path) else {
            return false;
        };
        let (found, failed) = (self.found.len(), self.failed);
        for name in names {
            self.read(&table, name);
        }
        let kept = self.os.shares_leader_table(pid, tid) && self.predates_walk(pid, tid);
        if !kept {
            self.found.truncate(found);
            self.failed = failed;
        }
        kept
    }

    /// Ends one read of `table`'s first listing, and when it was the last,
    /// lists the table again and reads every number that listing returns.
    fn listed(&mut self, table: &O::Table, listing: &FirstListing) {
        if listing.unread.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.relist(table);
        }
    }

    /// Lists `table` again and reads every descriptor that listing returns,
    /// then lists it again and reads each descriptor whose number no
    /// earlier listing returned, until a listing returns no such number.
    /// Each listing follows every read this walker made of the listings
    /// before it, so a descriptor the process moved to a new number before
    /// the last listing is read under that number. A descriptor that a read
    /// here finds vanished may sit at a number already read, which then
    /// held another file, so the next listing reads every number it returns
    /// again. Fails the walk when [`RELISTS`] listings each returned an
    /// unread number.
    fn relist(&mut self, table: &O::Table) {
        let mut records = std::mem::take(&mut self.records);
        let mut settled = false;
        let mut seen = HashSet::new();
        let mut moved = false;
        for _ in 0..RELISTS {
            if std::mem::take(&mut moved) {
                seen.clear();
            }
            let mut unread: Vec<CString> = Vec::new();
            let listed = self.os.entries(table, &mut records, |name| {
                if decimal(name).is_some_and(|fd| seen.insert(fd)) {
                    unread.push(name.to_owned());
                }
            });
            if let Err(error) = listed {
                self.note(&error);
            }
            if unread.is_empty() {
                settled = true;
                break;
            }
            for name in &unread {
                self.vanished = false;
                self.read(table, name);
                moved |= self.vanished;
            }
        }
        self.records = records;
        if !settled {
            self.failed = true;
        }
    }

    /// Keeps the node of descriptor `name` in `table` when it matches, and
    /// records a descriptor that vanished.
    fn read(&mut self, table: &O::Table, name: &CStr) {
        match self.os.node(table, name) {
            Ok(Some(node)) if (self.matches)(node) => self.found.push(node),
            Ok(_) => {}
            Err(error) => {
                self.vanished |= error.raw_os_error() == Some(libc::ENOENT);
                self.note(&error);
            }
        }
    }

    /// Fails the walk for any error but `ENOENT`, which a process or
    /// descriptor that vanished during the walk reports.
    fn note(&mut self, error: &io::Error) {
        if error.raw_os_error() != Some(libc::ENOENT) {
            self.failed = true;
        }
    }
}

/// An open directory, read through its descriptor.
pub(super) struct Directory(OwnedFd);

impl Directory {
    /// Opens `path`, relative to the directory `at` unless absolute.
    pub(super) fn open(at: RawFd, path: &CStr) -> io::Result<Self> {
        // SAFETY: `path` is NUL-terminated and `at` is an open directory or `AT_FDCWD`.
        let fd = unsafe {
            libc::openat(
                at,
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a nonnegative result is a descriptor this process now owns.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// The status the kernel reports for `path` relative to this directory,
    /// or the error when it cannot be read.
    fn stat_of(&self, path: &CStr) -> io::Result<libc::stat> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `path` is NUL-terminated and `stat` is writable for one `stat` record.
        let result =
            unsafe { libc::fstatat(self.as_raw_fd(), path.as_ptr(), stat.as_mut_ptr(), 0) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a zero result means the kernel filled the whole record.
        Ok(unsafe { stat.assume_init() })
    }

    /// The length of the text the symbolic link `name` of this directory
    /// holds, and that text in `target` up to `target`'s length: a longer
    /// text fills `target` and reports `target`'s length.
    ///
    /// # Errors
    ///
    /// The `readlinkat` error.
    pub(super) fn link(&self, name: &CStr, target: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `name` is NUL-terminated and `target` is writable for its
        // length, which bounds what the kernel writes.
        let length = unsafe {
            libc::readlinkat(
                self.as_raw_fd(),
                name.as_ptr(),
                target.as_mut_ptr().cast(),
                target.len(),
            )
        };
        usize::try_from(length).map_err(|_| io::Error::last_os_error())
    }

    /// Calls `visit` with each entry name except `.` and `..`, in the order
    /// the kernel lists them, from the directory's first entry until the
    /// listing ends, so a second call lists the directory again. A failed
    /// seek or read returns its error and a malformed record `InvalidData`.
    fn entries(&self, records: &mut [u8], visit: impl FnMut(&CStr)) -> io::Result<()> {
        // SAFETY: `lseek` takes no memory arguments.
        if unsafe { libc::lseek(self.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
            return Err(io::Error::last_os_error());
        }
        self.rest(records, visit)
    }

    /// Calls `visit` with each entry name except `.` and `..`, in the order
    /// the kernel lists them, from where the directory's last read ended
    /// until the listing ends: every entry of a directory just opened. A
    /// failed read returns its error and a malformed record `InvalidData`.
    pub(super) fn rest(&self, records: &mut [u8], mut visit: impl FnMut(&CStr)) -> io::Result<()> {
        let malformed = || io::Error::from(io::ErrorKind::InvalidData);
        loop {
            // SAFETY: `records` is writable for its length, and the kernel
            // fills it with whole `linux_dirent64` records.
            let filled = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    self.as_raw_fd(),
                    records.as_mut_ptr(),
                    records.len(),
                )
            };
            let Ok(filled) = usize::try_from(filled) else {
                return Err(io::Error::last_os_error());
            };
            if filled == 0 {
                return Ok(());
            }
            let mut record = 0;
            while record < filled {
                let rest = &records[record..filled];
                let length = rest
                    .get(RECORD_LENGTH..RECORD_LENGTH + 2)
                    .map(|bytes| usize::from(u16::from_ne_bytes([bytes[0], bytes[1]])))
                    .filter(|length| *length > RECORD_NAME)
                    .ok_or_else(malformed)?;
                let name = rest
                    .get(RECORD_NAME..length)
                    .and_then(|name| CStr::from_bytes_until_nul(name).ok())
                    .ok_or_else(malformed)?;
                if name != c"." && name != c".." {
                    visit(name);
                }
                record += length;
            }
        }
    }
}

impl AsRawFd for Directory {
    fn as_raw_fd(&self) -> c_int {
        self.0.as_raw_fd()
    }
}

/// Whether `proc` numbers tasks as this process's PID namespace does, so
/// `kcmp` resolves its process and thread IDs to the tasks it lists. procfs
/// lists a task's thread-group ID (`NStgid`) in each PID namespace from the
/// mount's down to the task's own, so a single entry equal to this process's
/// ID identifies this process's namespace.
pub(super) fn numbers_tasks_as_kcmp(proc: &Path) -> bool {
    let own = std::process::id().to_string();
    Host::read(&proc.join("self/status")).is_some_and(|status| {
        status
            .lines()
            .find_map(|line| line.strip_prefix("NStgid:"))
            .is_some_and(|ids| ids.split_whitespace().eq([own.as_str()]))
    })
}

/// Whether `proc` places this process in the initial user namespace and its
/// `thread-self/status` reports `CAP_SYS_PTRACE` in the calling thread's
/// effective set (`CapEff`, in hexadecimal). `self/status` reports the set
/// of the process's first thread, which another thread can differ from. The
/// kernel gives the initial namespace's `ns/user` file the fixed inode
/// `PROC_USER_INIT_INO`; every other user namespace has an ordinary one, and
/// `CapEff` counts only in the reader's own namespace. An unreadable
/// namespace file or a missing or malformed line reports `false`.
fn traces_every_process(proc: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    const PROC_USER_INIT_INO: u64 = 0xEFFF_FFFD;
    let initial =
        fs::metadata(proc.join("self/ns/user")).is_ok_and(|meta| meta.ino() == PROC_USER_INIT_INO);
    initial
        && Host::read(&proc.join("thread-self/status")).is_some_and(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("CapEff:"))
                .and_then(|set| u64::from_str_radix(set.trim(), 16).ok())
                .is_some_and(|set| set & (1 << CAP_SYS_PTRACE) != 0)
        })
}

/// Converts the uptime `proc`'s `uptime` reports to whole boot-clock ticks
/// at the kernel's tick rate, as [`uptime_ticks`] does, or `None` when the
/// file is unreadable or not UTF-8, or when [`uptime_ticks`] refuses its
/// text or the tick rate. procfs counts a task's start time in the same
/// ticks on the same clock.
pub(crate) fn boot_ticks(proc: &Path) -> Option<u64> {
    let uptime = Host::read(&proc.join("uptime"))?;
    // SAFETY: `sysconf` reads a constant and has no memory arguments.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    uptime_ticks(&uptime, hz)
}

/// The boot-clock ticks at `hz` ticks a second of the uptime whose first
/// field `uptime` holds as `<seconds>.<hundredths>`: ASCII digits, a dot and
/// exactly two ASCII digits. The result is `floor((seconds * 100 +
/// hundredths) * hz / 100)`, or `None` for other text, a tick rate below
/// one, or a seconds value, `seconds * 100`, its sum with the hundredths or
/// that sum times `hz` past `u64::MAX`.
pub(crate) fn uptime_ticks(uptime: &str, hz: libc::c_long) -> Option<u64> {
    let field = uptime.trim_start();
    let bytes = field.as_bytes();
    let dot = bytes.iter().position(|byte| !byte.is_ascii_digit())?;
    let (seconds, rest) = bytes.split_at(dot);
    // The field ends after the second hundredths digit, at the text's end
    // or a whitespace character.
    let [b'.', tens @ b'0'..=b'9', ones @ b'0'..=b'9', ..] = *rest else {
        return None;
    };
    if seconds.is_empty()
        || !field[dot + 3..]
            .chars()
            .next()
            .is_none_or(char::is_whitespace)
    {
        return None;
    }
    let hz = u64::try_from(hz).ok().filter(|&hz| hz > 0)?;
    let seconds = seconds.iter().try_fold(0u64, |seconds, &digit| {
        seconds
            .checked_mul(10)?
            .checked_add(u64::from(digit - b'0'))
    })?;
    let hundredths = u64::from(tens - b'0') * 10 + u64::from(ones - b'0');
    let centiseconds = seconds.checked_mul(100)?.checked_add(hundredths)?;
    Some(centiseconds.checked_mul(hz)? / 100)
}

/// The last task ID given, from the text of `loadavg`: the fifth field.
fn last_task(loadavg: &str) -> Option<u32> {
    loadavg.split_whitespace().nth(4)?.parse().ok()
}

/// The `stat` entry of thread `tid` of `pid` under the process table at
/// `proc`, or `None` when it cannot be read. The entry is read as bytes:
/// the command name can lie outside UTF-8, and the fields after it do not.
/// Each run of bytes outside UTF-8 reads as replacement characters.
fn task_stat(proc: &Path, pid: u32, tid: u32) -> Option<String> {
    let mut stat = Vec::new();
    Host::stream(&proc.join(format!("{pid}/task/{tid}/stat")), |bytes| {
        stat.extend_from_slice(bytes);
    })?;
    let lossy =
        |error: std::string::FromUtf8Error| String::from_utf8_lossy(error.as_bytes()).into_owned();
    Some(String::from_utf8(stat).unwrap_or_else(lossy))
}

/// The clock tick since boot the leader of `pid` started in, from the
/// leader's `stat` entry under the process table at `proc`, whatever the
/// leader's state; `None` when the entry cannot be read.
pub(super) fn leader_start_tick(proc: &Path, pid: u32) -> Option<u64> {
    start_tick_field(&task_stat(proc, pid, pid)?)
}

/// Returns the task's start time in clock ticks since boot from its `stat`
/// line, whatever the task's state: field 22 overall, the 20th field after
/// the command name, which ends at the line's last `)` and can hold spaces.
/// An exec by another thread of the process leaves the leader's start time
/// to the thread that takes the leader's ID.
fn start_tick_field(stat: &str) -> Option<u64> {
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    fields.nth(19)?.parse().ok()
}

/// Returns the start time [`start_tick_field`] reads from the task's
/// `stat` line while the task has not exited. A task that has exited,
/// in state `Z` or `X`, reports `None`: between an exec's ID swap and its
/// release of the old leader, the exec'ing thread's former ID names that
/// leader, a zombie until the exec marks it dead. A zombie thread that
/// awaits its tracer reports `None` too, and the walk then reads every
/// table of its process.
fn start_ticks(stat: &str) -> Option<u64> {
    let state = stat.rsplit_once(')')?.1.split_whitespace().next()?;
    if matches!(state, "X" | "Z") {
        return None;
    }
    start_tick_field(stat)
}

/// Whether thread `tid` of process `pid` uses its leader's descriptor table,
/// as `kcmp` reports. A failed comparison, as for an exited thread or a
/// kernel built without `kcmp`, reports `false`, so the thread's table is
/// read.
pub(super) fn shares_leader_table(pid: u32, tid: u32) -> bool {
    let unused: libc::c_ulong = 0;
    // SAFETY: `kcmp` with `KCMP_FILES` reads no user memory and ignores the
    // two indexes.
    let order = unsafe {
        libc::syscall(
            libc::SYS_kcmp,
            libc::c_long::from(pid),
            libc::c_long::from(tid),
            libc::c_long::from(KCMP_FILES),
            unused,
            unused,
        )
    };
    order == 0
}

/// The value of a name made only of decimal digits that fits a `u32`.
fn decimal(name: &CStr) -> Option<u32> {
    let digits = name.to_bytes();
    (!digits.is_empty() && digits.iter().all(u8::is_ascii_digit))
        .then(|| std::str::from_utf8(digits).ok()?.parse().ok())
        .flatten()
}
