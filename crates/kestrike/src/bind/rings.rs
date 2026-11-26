//! Lists the files io_uring instances hold registered, for the in-use
//! check of a namespace a bind claims.
//!
//! A file registered with a ring stays open in the ring's registered-file
//! table after the process closes the descriptor it registered, and the ring
//! reads and writes it from there. The file then has no entry in any
//! descriptor table, so the descriptor walk does not report it. The ring
//! itself is a descriptor whose link reads [`RING`], and its `fdinfo` lists
//! the table under `UserFiles`: a count, then one line per slot, or per
//! filled slot on later kernels. The kernel prints each name raw, so
//! [`registered_files`] reads the listing without trusting any line to end
//! it.
//!
//! procfs names a registered file by the last component of the path it was
//! opened through, and through Linux 6.13 by nothing else; later kernels
//! print the whole path. The pass matches that last component on every
//! kernel, so it reports names, not nodes: a device registered through a
//! node under another name is not reported, and a file elsewhere whose name
//! is a device's is.
//!
//! The pass finds a ring through a descriptor open on it, so it reports
//! the files of rings some task holds as a descriptor. A ring whose every
//! descriptor is closed stays alive while a task holds it registered
//! (`IORING_REGISTER_RING_FDS`) or mapped, keeps its registered files open,
//! and has no entry under procfs: the pass does not report its files.
//!
//! The pass reads the table under each process's ID, the table of each of
//! its other threads, since a thread can hold a ring in a private table,
//! and the table under the process's ID again, since a ring can move
//! between tables during the pass. A thread started without `CLONE_FILES`
//! after the threads are listed gets a copy of the table it starts from,
//! which the first read covers when that table is the process's. A thread
//! that execs takes over the process's ID with its own table and leaves
//! `task`, which the last read covers. When `kcmp` resolves the process
//! table's IDs to the tasks it lists, a thread that `kcmp` reports on the
//! table the process's ID names is read through the process's ID alone:
//! the reads before and after the threads read that table, a thread that
//! leaves it takes a copy of what it held, and an exec keeps it, or a copy
//! of it, under the process's ID or ends every thread on it. A
//! process, thread or descriptor that vanishes during the pass is skipped.
//! procfs reports `ENOENT` for it, or, for a task released between two
//! reads, `EACCES` from its `fd` directory or a link there and `ESRCH` from
//! its `fdinfo`; the pass takes such an error as a vanished task only when
//! the task's directory then reports `ENOENT`. Any other failure fails the
//! pass.
//!
//! One pass over a table opens the task's `fd` directory, lists it, and
//! reads each link relative to that open directory as the listing returns
//! its name.
//! A descriptor that vanishes may be a ring the process moved to another
//! number, so each table is read at least twice, and again while a pass
//! shows a sign of a move, as [`Reader::files`] states. A ring that moves
//! during every pass over its table and leaves no such sign is not
//! reported: a ring's link names no file, so two passes cannot tell one
//! ring from another. A number counts as a sign only the first time it
//! reads as vanished, so a ring moved between two numbers before each read
//! of its link, each number having vanished once, is not reported either.
//!
//! A child inherits its parent's rings at the fork, and a process that
//! starts after the listing passed its ID is not in that listing. So the
//! pass runs in rounds, as the descriptor walk does: each round lists the
//! process table again and reads the processes no earlier round listed, and
//! the pass ends with the first round that lists no such process. A
//! listing tells processes apart as the walk's does, by ID and the clock
//! tick the leader started in: a process under an ID an earlier round
//! listed with another start tick is one no round listed, and a process
//! without a start tick under an ID an earlier round listed without one
//! fails the pass. A ring that passes from parent to child by `fork` alone
//! through the whole pass is then read, or the pass fails, on two premises:
//! a child's ID is above its parent's while a listing runs, and no process
//! takes, within a pass, the ID of one that started in its own clock tick.
//! A pass whose every round lists a new process fails. A process's threads
//! are listed once, so a ring that passes to a thread started after that
//! listing, on a table of its own, is not read.
//!
//! The rounds read each table at a different instant, so a ring that a
//! task not yet read hands to a task already read is in no table they
//! read. The pass therefore runs its rounds [`LISTINGS`] times, each from
//! no process listed, and reports the rings of every run: a ring some task
//! holds throughout is missed only when it changes tasks that way during
//! each run.
//!
//! A round lists the process table, reads the start tick of each listed
//! process, then reads the processes no earlier round listed on one
//! reader thread per [`PER_READER`] of them, up to the host's parallelism
//! and [`WALKERS`], the calling thread among them. Each reader takes the next listed
//! process and reads its tables in the order above, so a table of fewer
//! than twice [`PER_READER`] processes is read by the calling thread alone,
//! in listing order. A round ends once every reader has finished.

use std::collections::{BTreeSet, HashSet};
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io;
use std::num::NonZero;
use std::os::unix::ffi::OsStrExt;
use std::panic;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

use super::host::Host;
use super::walk::{
    Directory, Listed, RECORDS, WALKERS, leader_start_tick, numbers_tasks_as_kcmp, settled,
    shares_leader_table, unlisted,
};

/// The text the link of a descriptor open on a ring reads as.
const RING: &str = "anon_inode:[io_uring]";
/// Reads of one ring's `fdinfo` before the pass fails. The kernel lists the
/// table only when it takes the ring's lock without waiting, so a read
/// beside a submission can print only the count.
const READS: usize = 8;
/// Passes over one task's descriptor table before the pass fails. Each
/// pass after the second follows one that showed a sign of a moved ring, as
/// [`Reader::files`] states.
const PASSES: usize = 16;
/// Runs of the pass's rounds over the process table. A ring that changes
/// tasks during one run is in a table the next one reads.
const LISTINGS: usize = 2;
/// Listed processes per reader thread of a round.
const PER_READER: usize = 8;

impl Host {
    /// The name of every file a ring some task holds as a descriptor has
    /// registered that `matches` accepts, once each, in ascending order:
    /// the last path component of each slot `fdinfo` lists, an empty slot's
    /// placeholder included where the kernel prints one. The list can hold
    /// more than the names, as [`registered_files`] states. The pass reads
    /// the kernel release from `sys/kernel/osrelease` once, for
    /// [`registered_files`]; an unreadable or unparsable release reads as
    /// one that prints the `UserFiles` count outside the ring's lock.
    ///
    /// The readers call `matches` concurrently, for each slot whose name
    /// they have not kept, and copy a name only when `matches` accepts it.
    /// Each reader keeps an accepted name once, so the pass holds at most
    /// one copy of each accepted name per reader and one in the result,
    /// beside the `fdinfo` text it reads and one slice per slot of that
    /// text.
    ///
    /// Returns `None` when `proc` cannot be listed, when a `task` or `fd`
    /// directory, a descriptor's link or a ring's `fdinfo` cannot be read
    /// while its task is [`present`], when [`READS`] reads of one ring's
    /// `fdinfo` each fail [`registered_files`], when [`PASSES`] passes over
    /// one task's table each showed a sign of a moved ring, when a round
    /// lists a process without a start tick under an ID an earlier round of
    /// its run listed without one, or when every round [`settled`] allows
    /// listed a process no earlier round had.
    ///
    /// # Panics
    ///
    /// With the panic of a reader thread, once every reader of its round
    /// has finished, or of a thread that read start ticks for a listing.
    pub(crate) fn registered(&self, matches: impl Fn(&str) -> bool + Sync) -> Option<Vec<String>> {
        let kernel = Kernel::read(&self.proc);
        let mut names = BTreeSet::new();
        for _ in 0..LISTINGS {
            // The ring pass reads no ID cursor, so it ends with its first round
            // that lists no new process.
            let round = |seen: &mut BTreeSet<Listed>| {
                self.ring_round(kernel, &matches, seen, &mut names)
                    .is_some()
            };
            if !settled(round, || None) {
                return None;
            }
        }
        Some(names.into_iter().collect())
    }

    /// Lists the process table once and adds to `names` the registered
    /// files that `matches` accepts from every ring of each process absent
    /// from `seen`, adding the process to `seen`, as [`unlisted`] states: a
    /// process under an ID `seen` holds with another start tick is absent
    /// from it. A name of digits too long for a process ID names no process
    /// and is skipped. Those processes are read by one reader per
    /// [`PER_READER`] of them, at least one and at most the host's
    /// parallelism or [`WALKERS`]: the calling thread and the threads it
    /// starts, each taking the next of those processes until none is left
    /// or a read failed. A reader that cannot start leaves its share to the
    /// others. `None` as [`Host::registered`] states for a failed read, and
    /// before any ring is read when the listing did not identify every
    /// process.
    ///
    /// # Panics
    ///
    /// With the panic of a reader thread, once every reader has finished,
    /// and as [`unlisted`].
    pub(super) fn ring_round(
        &self,
        kernel: Kernel,
        matches: &(impl Fn(&str) -> bool + Sync),
        seen: &mut BTreeSet<Listed>,
        names: &mut BTreeSet<String>,
    ) -> Option<()> {
        let mut pids = Vec::new();
        for process in fs::read_dir(&self.proc).ok()? {
            let name = process.ok()?.file_name();
            let pid = name.to_str().and_then(|pid| pid.parse::<u32>().ok());
            pids.extend(pid.filter(|_| numeric(&name)));
        }
        let (listed, identified) = unlisted(|pid| leader_start_tick(&self.proc, pid), pids, seen);
        if !identified {
            return None;
        }
        let parallelism = thread::available_parallelism()
            .map_or(1, NonZero::get)
            .min(WALKERS);
        let readers = (listed.len() / PER_READER).clamp(1, parallelism);
        let (next, failed) = (AtomicUsize::new(0), AtomicBool::new(false));
        let read = || {
            let mut reader = Reader {
                kernel,
                matches,
                names: BTreeSet::new(),
                records: vec![0u8; RECORDS],
            };
            while !failed.load(Ordering::Acquire) {
                let Some(&pid) = listed.get(next.fetch_add(1, Ordering::AcqRel)) else {
                    return Some(reader.names);
                };
                let process = self.proc.join(pid.to_string());
                if reader.process(pid, &process).is_none() {
                    failed.store(true, Ordering::Release);
                }
            }
            None
        };
        let mut found = thread::scope(|scope| {
            let started: Vec<_> = (1..readers)
                .filter_map(|_| thread::Builder::new().spawn_scoped(scope, read).ok())
                .collect();
            let mut found = read();
            for reader in started {
                let names = reader
                    .join()
                    .unwrap_or_else(|panic| panic::resume_unwind(panic));
                found = found.zip(names).map(|(mut found, mut names)| {
                    found.append(&mut names);
                    found
                });
            }
            found
        })?;
        names.append(&mut found);
        Some(())
    }
}

/// Each reader thread tracks the registered files it discovers that
/// `matches` accepts, once each per round, and holds a buffer for reading
/// descriptor-table directory records.
struct Reader<'m, M> {
    kernel: Kernel,
    matches: &'m M,
    names: BTreeSet<String>,
    records: Vec<u8>,
}

impl<M: Fn(&str) -> bool> Reader<'_, M> {
    /// Adds to the reader's names the registered files of every ring of the
    /// process `pid`, whose procfs directory is `process`: of the table
    /// under the process's ID, of the table of each of its other threads,
    /// and of the table under the process's ID again. With `kcmp` set, the
    /// table of a thread that `kcmp` reports on the table the process's ID
    /// names is left to the reads of that table. `None` as
    /// [`Host::registered`] states for a failed read.
    fn process(&mut self, pid: u32, process: &Path) -> Option<()> {
        self.files(process)?;
        let task = process.join("task");
        for tid in present(process, fs::read_dir(&task))?.into_iter().flatten() {
            let tid = present(process, tid)?.map(|tid| tid.file_name());
            if let Some(tid) =
                tid.filter(|tid| numeric(tid) && Some(tid.as_os_str()) != process.file_name())
            {
                let shared = self.kernel.kcmp
                    && (tid.to_str())
                        .and_then(|tid| tid.parse().ok())
                        .is_some_and(|tid| shares_leader_table(pid, tid));
                if !shared {
                    self.files(&task.join(tid))?;
                }
            }
        }
        self.files(process)
    }

    /// Adds to the reader's names the registered files of every ring in the
    /// descriptor table of the task whose procfs directory is `task`.
    /// `None` when the table, a link or a ring's `fdinfo` is unreadable as
    /// [`Host::registered`] states, or when [`PASSES`] passes over the
    /// table each showed a sign of a moved ring.
    ///
    /// A process can move a ring to another number while a pass reads its
    /// table (`dup2` then `close`), away from the numbers the pass has yet
    /// to read. The table is therefore read at least twice, so a ring that
    /// moved during one pass alone is read by the other. The passes go on
    /// while one shows a sign of a move: a number that reads as vanished for
    /// the first time, or rings at other numbers than the pass before found
    /// them at. A number that vanishes again is no sign, so a process that
    /// opens and closes files at the same numbers throughout does not fail
    /// the pass.
    fn files(&mut self, task: &Path) -> Option<()> {
        let mut gone = HashSet::new();
        let mut before: Option<Vec<OsString>> = None;
        for _ in 0..PASSES {
            let Some(pass) = self.pass(task, &mut gone)? else {
                return Some(());
            };
            let settled = !pass.moved && before.as_ref() == Some(&pass.rings);
            if settled {
                return Some(());
            }
            before = Some(pass.rings);
        }
        None
    }

    /// Lists the descriptor table of the task whose procfs directory is
    /// `task` once, through one open of its `fd` directory, adds to the
    /// reader's names the registered files of every ring it lists, and adds
    /// to `gone` each number whose link or ring `fdinfo` had vanished. Each
    /// link is read as the listing returns its name, relative to the open
    /// directory. The inner `None` when the table itself vanished, the
    /// outer `None` as [`files`](Self::files) states for an unreadable
    /// table, link or `fdinfo`.
    fn pass(&mut self, task: &Path, gone: &mut HashSet<OsString>) -> Option<Option<Pass>> {
        let opened = CString::new(task.join("fd").as_os_str().as_bytes())
            .map_err(io::Error::other)
            .and_then(|table| Directory::open(libc::AT_FDCWD, &table));
        let Some(table) = present(task, opened)? else {
            return Some(None);
        };
        let mut pass = Pass {
            rings: Vec::new(),
            moved: false,
        };
        let mut readable = true;
        let mut records = std::mem::take(&mut self.records);
        let listed = table.rest(&mut records, |name| {
            if !readable {
                return;
            }
            let fd = OsStr::from_bytes(name.to_bytes());
            // A descriptor table lists numbers alone.
            if !numeric(fd) {
                return;
            }
            // The buffer holds twice a ring's text, so a longer text
            // reads longer than a ring's and differs from it.
            let mut target = [0u8; 2 * RING.len()];
            let ring = table
                .link(name, &mut target)
                .map(|length| &target[..length] == RING.as_bytes());
            match present(task, ring) {
                None => readable = false,
                Some(None) => pass.moved |= gone.insert(fd.to_owned()),
                Some(Some(false)) => {}
                Some(Some(true)) => match self.ring_names(task, &task.join("fdinfo").join(fd)) {
                    None => readable = false,
                    Some(read) => {
                        if read.is_none() {
                            pass.moved |= gone.insert(fd.to_owned());
                        }
                        pass.rings.push(fd.to_owned());
                    }
                },
            }
        });
        self.records = records;
        if !readable {
            return None;
        }
        if present(task, listed)?.is_none() {
            pass.moved = true;
        }
        pass.rings.sort_unstable();
        Some(Some(pass))
    }

    /// Adds matching registered file names listed in the ring's `fdinfo` at
    /// `info`, copying names only when the reader has not kept them. `task`
    /// identifies the task's procfs directory. Returns `Some(None)` if the
    /// ring vanished, or `None` if the file is unreadable while the task is
    /// [`present`] or all [`READS`] reads fail [`registered_files`].
    fn ring_names(&mut self, task: &Path, info: &Path) -> Option<Option<()>> {
        for _ in 0..READS {
            let Some(text) = present(task, fs::read(info))? else {
                return Some(None);
            };
            // A name is the kernel's copy of a path component and can hold any
            // bytes.
            let text = String::from_utf8_lossy(&text);
            if let Some(files) = registered_files(&text, self.kernel.counts_under_lock) {
                for file in files {
                    if !self.names.contains(file) && (self.matches)(file) {
                        self.names.insert(file.to_owned());
                    }
                }
                return Some(Some(()));
            }
            thread::yield_now();
        }
        None
    }
}

/// What one pass over a task's descriptor table saw.
struct Pass {
    /// The numbers whose link read as a ring's, in ascending order.
    rings: Vec<OsString>,
    /// Whether a descriptor vanished whose number no earlier pass found
    /// vanished.
    moved: bool,
}

/// The kernel facts [`Host::registered`] reads on entry, which every
/// [`Reader`] of its rounds shares.
#[derive(Clone, Copy)]
pub(super) struct Kernel {
    /// Whether [`numbers_tasks_as_kcmp`] holds for the host's `proc`.
    kcmp: bool,
    /// Whether the release `sys/kernel/osrelease` names prints a ring's
    /// `UserFiles` count only under the ring's lock, as
    /// [`counts_under_lock`] states.
    counts_under_lock: bool,
}

impl Kernel {
    pub(super) fn read(proc: &Path) -> Self {
        Self {
            kcmp: numbers_tasks_as_kcmp(proc),
            counts_under_lock: Host::read(&proc.join("sys/kernel/osrelease"))
                .is_some_and(|release| counts_under_lock(&release)),
        }
    }
}

/// What a kernel that prints a registered file's path appends to the path
/// of a file with no link left, its space escaped.
const DELETED: &str = "\\040(deleted)";

/// The last path component of every slot-shaped line a ring's `fdinfo` text
/// holds after its `UserFiles` count, without the [`DELETED`] suffix of an
/// unlinked file, which the ring still holds open, or `None` when the text
/// has no
/// `UserFiles` count or may list the table short: the count is above zero,
/// no slot-shaped line follows it, and `counted_under_lock` is unset.
///
/// The kernel prints slot lines only when it takes the ring's lock without
/// waiting, and then prints every slot through Linux 6.13, an empty one as
/// `<none>`, and every filled slot by its full path from Linux 6.14. It
/// prints the slots of `UserBufs` under the same lock taken once, so one
/// slot-shaped line of either table after the count shows the file listing
/// whole. A table whose slots are all empty then shows only its count, and
/// from Linux 6.15 the kernel prints that count only under the lock, which
/// `counted_under_lock` states, so the count alone shows the listing whole.
///
/// The kernel prints a registered name raw, so a name that holds a line
/// break can supply slot-shaped lines of its own and any line that would
/// end the table. No line therefore ends the read: each slot's own line
/// starts a line of the text, and the read takes every such line to the
/// end of the text. The result is the table's names and can hold more: the
/// tail of a name after a line break, and the length of each registered
/// buffer, which the kernel lists in the same shape under `UserBufs`.
pub(super) fn registered_files(info: &str, counted_under_lock: bool) -> Option<Vec<&str>> {
    let mut lines = info.lines();
    let count: usize = lines
        .by_ref()
        .find_map(|line| line.strip_prefix("UserFiles:"))?
        .trim()
        .parse()
        .ok()?;
    let files: Vec<&str> = lines
        .filter_map(|line| {
            let (slot, file) = line.trim_start().split_once(": ")?;
            if slot.is_empty() || !slot.bytes().all(|digit| digit.is_ascii_digit()) {
                return None;
            }
            let name = file.rsplit('/').next().unwrap_or(file);
            Some(name.strip_suffix(DELETED).unwrap_or(name))
        })
        .collect();
    (count == 0 || counted_under_lock || !files.is_empty()).then_some(files)
}

/// Whether kernel `release` prints a ring's `UserFiles` count only under
/// the ring's lock. If either version number is unparseable, an empty table
/// with a nonzero `UserFiles` count is treated as a short read.
fn counts_under_lock(release: &str) -> bool {
    let number = |part: Option<&str>| -> Option<u32> {
        let part = part?;
        let digits = part.bytes().take_while(u8::is_ascii_digit).count();
        part[..digits].parse().ok()
    };
    let mut parts = release.split('.');
    let (major, minor) = (number(parts.next()), number(parts.next()));
    major.zip(minor).is_some_and(|version| version >= (6, 15))
}

/// `read`'s value, for a read under `task`, the procfs directory of a
/// process or thread. `None` in its place when what was read vanished: the
/// read failed with `ENOENT`, or it failed otherwise and `task` itself then
/// reports `ENOENT`, as after procfs answered `EACCES` or `ESRCH` for a
/// task released since the pass listed it. The outer `None` for a failure
/// while `task` is present.
fn present<T>(task: &Path, read: io::Result<T>) -> Option<Option<T>> {
    let vanished = |error: &io::Error| error.raw_os_error() == Some(libc::ENOENT);
    match read {
        Ok(value) => Some(Some(value)),
        Err(error) if vanished(&error) => Some(None),
        Err(_) => fs::metadata(task)
            .is_err_and(|error| vanished(&error))
            .then_some(None),
    }
}

/// Whether `name` is made only of ASCII digits, as a process or thread ID is.
fn numeric(name: &std::ffi::OsStr) -> bool {
    let name = name.as_encoded_bytes();
    !name.is_empty() && name.iter().all(u8::is_ascii_digit)
}
