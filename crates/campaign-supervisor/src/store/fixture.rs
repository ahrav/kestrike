//! Test state directories under the build's target directory, a recursive
//! snapshot of their contents, and the fault-script runners. Store tests
//! run on the target directory's filesystem, which must meet the
//! [store's durability contract](super#durability).
//!
//! A child process holds a copy of every descriptor of the test process
//! from its fork until its exec, the store's locked directory handles
//! included, so a test that drops a store and opens it again could find a
//! sibling test's child holding its lock. A test that starts child
//! processes therefore holds [`processes`] for its whole run, which
//! excludes every [`Case`] of other threads while it runs. A spawn whose
//! exec fails forks a child too, which holds the copies until it exits, so
//! its test holds [`processes`] as well.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs::{self, DirBuilder};
use std::marker::PhantomData;
use std::os::unix::fs::DirBuilderExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::Name;
use crate::step::{self, Killed, Outcome, Script, Step};

/// A directory tree by relative path: a file's bytes, or `None` for a
/// directory.
pub(crate) type Snapshot = BTreeMap<PathBuf, Option<Vec<u8>>>;

/// `text` as a name.
pub(crate) fn name(text: &str) -> Name {
    Name::new(text).expect("the test name is valid")
}

/// Runs `op` with a script that applies each outcome of `at` at its step
/// index, returning its result, or `None` when the script killed it, and
/// every step it reached.
pub(crate) fn scripted<T>(
    at: impl IntoIterator<Item = (usize, Outcome)>,
    op: impl FnOnce() -> T,
) -> (Option<T>, Vec<Step>) {
    step::install(Some(Script {
        at: at.into_iter().collect(),
        ..Script::default()
    }));
    let result = catch_unwind(AssertUnwindSafe(op));
    let script = step::install(None).expect("the script stays installed");
    match result {
        Ok(value) => (Some(value), script.reached),
        Err(payload) => {
            assert!(payload.is::<Killed>(), "the operation panicked");
            (None, script.reached)
        }
    }
}

/// Runs `op` under the scan bound `bound`, returning its result and trace.
/// The prior script is restored before a panic propagates.
pub(crate) fn bounded<T>(bound: usize, op: impl FnOnce() -> T) -> (T, Vec<Step>) {
    let prior = step::install(Some(Script {
        scan_bound: Some(bound),
        ..Script::default()
    }));
    let result = catch_unwind(AssertUnwindSafe(op));
    let script = step::install(prior).expect("the script stays installed");
    match result {
        Ok(value) => (value, script.reached),
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

static CASES: AtomicUsize = AtomicUsize::new(0);

/// Held shared by each [`Case`] and exclusively by a test that starts
/// child processes.
static PROCESSES: RwLock<()> = RwLock::new(());

thread_local! {
    static SPAWNING: Cell<bool> = const { Cell::new(false) };
    /// This thread's live cases and, while any lives, the one shared guard
    /// they hold; a thread never takes a second read guard, which a waiting
    /// writer would block.
    static SHARED: RefCell<(usize, Option<RwLockReadGuard<'static, ()>>)> =
        const { RefCell::new((0, None)) };
}

/// Exclusion of every other thread's [`Case`] while this thread's test
/// starts child processes.
pub(crate) struct Processes {
    _exclusive: RwLockWriteGuard<'static, ()>,
}

/// Waits for every other thread's [`Case`] to drop and holds new ones off
/// until the returned guard drops; this thread's own cases proceed. A test
/// takes it before its first [`Case`], since a thread holding a case holds
/// the shared side this call waits to exclude.
///
/// # Panics
///
/// When this thread holds a [`Case`], whose shared guard would block the
/// exclusive one forever.
pub(crate) fn processes() -> Processes {
    let live = SHARED.with_borrow(|(live, _)| *live);
    assert_eq!(live, 0, "a test takes `processes` before its first `Case`");
    let guard = PROCESSES.write().unwrap_or_else(PoisonError::into_inner);
    SPAWNING.set(true);
    Processes { _exclusive: guard }
}

impl Drop for Processes {
    fn drop(&mut self) {
        SPAWNING.set(false);
    }
}

/// A test's own directory, removed on drop, and its mode-0700 `state`
/// directory inside it. A case stays on the thread that made it, whose
/// count of live cases it keeps, and other threads may borrow it.
pub(crate) struct Case {
    pub(crate) root: PathBuf,
    pub(crate) state: PathBuf,
    /// A `MutexGuard` is `!Send` and `Sync`, so a case cannot move off the
    /// thread whose live-case count it changes, and other threads may
    /// still borrow it.
    _thread: PhantomData<MutexGuard<'static, ()>>,
}

impl Case {
    pub(crate) fn new() -> Self {
        SHARED.with_borrow_mut(|(live, guard)| {
            if *live == 0 && !SPAWNING.get() {
                *guard = Some(PROCESSES.read().unwrap_or_else(PoisonError::into_inner));
            }
            *live += 1;
        });
        let exe = std::env::current_exe().expect("the test executable has a path");
        let target = exe
            .parent()
            .and_then(Path::parent)
            .expect("the executable lies under the target directory");
        let number = CASES.fetch_add(1, Ordering::Relaxed);
        let root = target
            .join("campaign-store-tests")
            .join(format!("{}-{number}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("the case directory is created");
        let state = root.join("state");
        DirBuilder::new()
            .mode(0o700)
            .create(&state)
            .expect("the state directory is created");
        Self {
            root,
            state,
            _thread: PhantomData,
        }
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        SHARED.with_borrow_mut(|(live, guard)| {
            *live -= 1;
            if *live == 0 {
                *guard = None;
            }
        });
    }
}

/// The most reads one [`reread`] call makes.
const REREADS: usize = 16;

/// Calls `read` until `accepted` holds of its value, at most [`REREADS`]
/// times, and returns the last value read. One read of `/proc/locks` can
/// miss a held lock or list it twice while other tests and processes take
/// and release locks, so a test that expects one holder reads again.
pub(crate) fn reread<T>(mut read: impl FnMut() -> T, accepted: impl Fn(&T) -> bool) -> T {
    let mut value = read();
    for _ in 1..REREADS {
        if accepted(&value) {
            break;
        }
        value = read();
    }
    value
}

/// Runs `op` with `observe` called at each step it reaches, as another
/// controller acting at that moment would, and no scripted fault.
pub(crate) fn observed<T>(observe: impl FnMut(Step) + 'static, op: impl FnOnce() -> T) -> T {
    step::install(Some(Script {
        observe: Some(Box::new(observe)),
        ..Script::default()
    }));
    let result = op();
    step::install(None);
    result
}

/// Moves the state directory at `state` to `old` and makes an empty
/// mode-0700 replacement at `state`.
pub(crate) fn replace(state: &Path, old: &Path) {
    fs::rename(state, old).expect("the state directory moves away");
    DirBuilder::new()
        .mode(0o700)
        .create(state)
        .expect("a replacement is made");
}

/// Opens the store at `state` twice, requires the second open to change
/// nothing, and returns the state after them.
pub(crate) fn recovered(state: &Path, context: &str) -> Snapshot {
    drop(super::Store::open(state).expect("recovery opens"));
    let once = snapshot(state);
    drop(super::Store::open(state).expect("a second recovery opens"));
    assert_eq!(snapshot(state), once, "{context}");
    once
}

/// Every entry under `path` by relative path: a file's bytes, or `None`
/// for a directory.
pub(crate) fn snapshot(path: &Path) -> Snapshot {
    let mut entries = BTreeMap::new();
    let mut pending = vec![path.to_owned()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).expect("the directory lists") {
            let entry = entry.expect("the entry reads").path();
            let relative = entry
                .strip_prefix(path)
                .expect("the entry lies under the root")
                .to_owned();
            if entry.is_dir() {
                entries.insert(relative, None);
                pending.push(entry);
            } else {
                entries.insert(relative, Some(fs::read(&entry).expect("the file reads")));
            }
        }
    }
    entries
}
