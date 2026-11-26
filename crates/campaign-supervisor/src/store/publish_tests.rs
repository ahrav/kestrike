//! Fault-index sweeps of the durable mutations through the step seam, and
//! the state-directory replacement schedule, on the Cargo target
//! directory's filesystem.

use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use super::fixture::{Case, Snapshot, name, observed, recovered, replace, scripted, snapshot};
use super::{Creation, Error, Refusal, Store};
use crate::exit::Supervisor;
use crate::step::{Outcome, Step};
use crate::sys;

/// The `record` entry: `None` when absent, `Some(None)` for a directory.
fn record(state: &Snapshot) -> Option<&Option<Vec<u8>>> {
    state.get(Path::new("record"))
}

/// The bytes of the `record` file, when it is one.
fn file(state: &Snapshot) -> Option<&[u8]> {
    record(state)?.as_deref()
}

/// The entries of `state` other than the marker, the staging directory and
/// `record`, and any staged file.
fn stray(state: &Snapshot) -> Vec<&PathBuf> {
    state
        .keys()
        .filter(|path| ![".state", ".staging", "record"].contains(&path.to_str().unwrap_or("")))
        .collect()
}

/// The steps of a publication onto a new name: the pre-check, the stale
/// staged file's unlink, the exclusive create, the write, the file's
/// `fsync`, its `close`, the rename, the directory's `fsync`, and the
/// post-check.
const PUBLISH: &[Step] = &[
    Step::Stat,
    Step::Check,
    Step::Unlink,
    Step::Open,
    Step::Write,
    Step::Sync,
    Step::Close,
    Step::Rename,
    Step::Sync,
    Step::Stat,
    Step::Check,
];

/// A create-once onto an existing name: the no-replace rename fails, and
/// the staged file is unlinked before the directory's `fsync`.
const EXISTING: &[Step] = &[
    Step::Stat,
    Step::Check,
    Step::Unlink,
    Step::Open,
    Step::Write,
    Step::Sync,
    Step::Close,
    Step::Rename,
    Step::Unlink,
    Step::Sync,
    Step::Stat,
    Step::Check,
];

/// One mutation under test: what the state holds before it, the mutation,
/// its fault-free steps, the step whose call changes the record, and the
/// states before and after that change.
struct Sweep {
    prepare: fn(&Store),
    op: fn(&Store) -> Result<(), Error>,
    trace: &'static [Step],
    effect: Step,
    before: fn(&Snapshot) -> bool,
    acknowledged: fn(&Snapshot) -> bool,
}

impl Sweep {
    /// The fault-free run reaches exactly the contract's steps, leaves
    /// nothing staged, and its acknowledged state survives two recoveries.
    /// Then each step index in turn fails with `EIO`, is killed, and is
    /// interrupted. A failure or kill reaches no step after the faulted
    /// one. A failure poisons the store, so the next mutation reaches no
    /// step; a kill ends the run and the store is dropped. Recovery leaves
    /// the before state when the fault came at or before the effect step
    /// and the acknowledged state after it, with no stray or staged entry,
    /// unchanged by a second recovery. An interrupted step is retried once
    /// and the mutation is acknowledged, except at `close`, which fails
    /// like any other error.
    fn run(&self) {
        let effect = self
            .trace
            .iter()
            .position(|&at| at == self.effect)
            .expect("the trace holds the effect step");
        let case = Case::new();
        let store = Store::open(&case.state).expect("the store opens");
        (self.prepare)(&store);
        let (result, reached) = scripted(None, || (self.op)(&store));
        result
            .expect("the run completes")
            .expect("the fault-free mutation succeeds");
        assert_eq!(reached, self.trace);
        let live = snapshot(&case.state);
        assert!((self.acknowledged)(&live), "the fault-free state: {live:?}");
        assert!(stray(&live).is_empty(), "{live:?}");
        drop(store);
        let recovered = recover(&case.state, "fault-free");
        assert!((self.acknowledged)(&recovered), "{recovered:?}");
        for index in 0..self.trace.len() {
            for outcome in [
                Outcome::Errno(libc::EIO),
                Outcome::Kill,
                Outcome::Errno(libc::EINTR),
            ] {
                self.fault(index, outcome, index > effect);
            }
        }
    }

    fn fault(&self, index: usize, outcome: Outcome, after: bool) {
        let case = Case::new();
        let store = Store::open(&case.state).expect("the store opens");
        (self.prepare)(&store);
        let (result, reached) = scripted(Some((index, outcome)), || (self.op)(&store));
        let context = format!("step {index} {outcome:?}");
        assert!(
            reached.len() > index,
            "{context}: the fault was never reached"
        );
        let interrupted = outcome == Outcome::Errno(libc::EINTR);
        let stops = !interrupted || self.trace[index] == Step::Close;
        if stops {
            assert_eq!(reached.len(), index + 1, "{context}: {reached:?}");
        }
        let acknowledged = match result {
            Some(Ok(())) => {
                assert!(!stops, "{context}: an injected error was absorbed");
                assert_eq!(reached.len(), self.trace.len() + 1, "{context}");
                true
            }
            Some(Err(error)) => {
                assert!(stops, "{context}: {error}");
                assert_eq!(error.exit(), Supervisor::Held, "{context}");
                let (later, reached) = scripted(None, || (self.op)(&store));
                assert!(matches!(later, Some(Err(Error::Poisoned))), "{context}");
                assert!(reached.is_empty(), "{context}: {reached:?}");
                after
            }
            None => after,
        };
        drop(store);
        let recovered = recover(&case.state, &context);
        if acknowledged {
            assert!((self.acknowledged)(&recovered), "{context}: {recovered:?}");
        } else {
            assert!((self.before)(&recovered), "{context}: {recovered:?}");
        }
    }
}

/// Recovers the store at `state` twice and requires the result to hold no
/// stray or staged entry.
fn recover(state: &Path, context: &str) -> Snapshot {
    let once = recovered(state, context);
    assert!(stray(&once).is_empty(), "{context}: {once:?}");
    once
}

fn create(store: &Store) -> Result<(), Error> {
    store
        .create_once(store.root(), &name("record"), b"new")
        .map(|_| ())
}

fn create_prior(store: &Store) {
    let created = store.create_once(store.root(), &name("record"), b"prior");
    assert_eq!(
        created.expect("the prior record is created"),
        Creation::Created
    );
}

/// Create-once never replaces an existing record and an acknowledged
/// create reads back exactly its bytes, under a fault at every step.
#[test]
fn create_once_never_replaces_under_a_fault_at_every_step() {
    Sweep {
        prepare: |_| {},
        op: create,
        trace: PUBLISH,
        effect: Step::Rename,
        before: |state| record(state).is_none(),
        acknowledged: |state| file(state) == Some(b"new"),
    }
    .run();
    Sweep {
        prepare: create_prior,
        op: create,
        trace: EXISTING,
        effect: Step::Rename,
        before: |state| file(state) == Some(b"prior"),
        acknowledged: |state| file(state) == Some(b"prior"),
    }
    .run();
}

#[test]
fn declined_publication_cleans_staging_and_poisons_on_every_failed_step() {
    Sweep {
        prepare: |_| {},
        op: |store| {
            let creation = store.create_once_if(store.root(), &name("record"), b"new", || false)?;
            assert_eq!(creation, None);
            Ok(())
        },
        trace: &[
            Step::Stat,
            Step::Check,
            Step::Unlink,
            Step::Open,
            Step::Write,
            Step::Sync,
            Step::Close,
            Step::Unlink,
            Step::Sync,
            Step::Stat,
            Step::Check,
        ],
        effect: Step::Unlink,
        before: |state| record(state).is_none(),
        acknowledged: |state| record(state).is_none(),
    }
    .run();
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    create_prior(&store);
    assert_eq!(
        store
            .create_once_if(store.root(), &name("record"), b"new", || true)
            .unwrap(),
        Some(Creation::Existing)
    );
    assert_eq!(file(&snapshot(&case.state)), Some(b"prior".as_slice()));
    assert!(stray(&snapshot(&case.state)).is_empty());
}

/// A replace leaves the prior bytes or the new bytes, never a mix, and an
/// acknowledged replace leaves the new bytes.
#[test]
fn replace_leaves_old_or_new_bytes_under_a_fault_at_every_step() {
    Sweep {
        prepare: create_prior,
        op: |store| store.replace(store.root(), &name("record"), b"new"),
        trace: PUBLISH,
        effect: Step::Rename,
        before: |state| file(state) == Some(b"prior"),
        acknowledged: |state| file(state) == Some(b"new"),
    }
    .run();
}

/// A directory creation and a delete each leave the before or the after
/// state, and their acknowledgment means the after state.
#[test]
fn mkdir_and_delete_leave_before_or_after_under_a_fault_at_every_step() {
    let namespace = &[
        Step::Stat,
        Step::Check,
        Step::Mkdir,
        Step::Sync,
        Step::Stat,
        Step::Check,
    ];
    Sweep {
        prepare: |_| {},
        op: |store| store.mkdir(store.root(), &name("record")).map(|_| ()),
        trace: namespace,
        effect: Step::Mkdir,
        before: |state| record(state).is_none(),
        acknowledged: |state| record(state) == Some(&None),
    }
    .run();
    Sweep {
        prepare: create_prior,
        op: |store| store.delete(store.root(), &name("record")),
        trace: &[
            Step::Stat,
            Step::Check,
            Step::Unlink,
            Step::Sync,
            Step::Stat,
            Step::Check,
        ],
        effect: Step::Unlink,
        before: |state| file(state) == Some(b"prior"),
        acknowledged: |state| record(state).is_none(),
    }
    .run();
}

/// An rmdir of an empty directory leaves the before or the after state
/// under a fault at every step, and its acknowledgment means the after
/// state. An absent target succeeds; a directory that holds an entry fails
/// and stays.
#[test]
fn rmdir_leaves_before_or_after_under_a_fault_at_every_step() {
    Sweep {
        prepare: |store| {
            store.mkdir(store.root(), &name("record")).unwrap();
        },
        op: |store| store.rmdir(store.root(), &name("record")),
        trace: &[
            Step::Stat,
            Step::Check,
            Step::Unlink,
            Step::Sync,
            Step::Stat,
            Step::Check,
        ],
        effect: Step::Unlink,
        before: |state| record(state) == Some(&None),
        acknowledged: |state| record(state).is_none(),
    }
    .run();
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let (absent, trace) = scripted([], || store.rmdir(store.root(), &name("record")));
    absent.unwrap().unwrap();
    assert_eq!(
        trace,
        [
            Step::Stat,
            Step::Check,
            Step::Unlink,
            Step::Sync,
            Step::Stat,
            Step::Check
        ]
    );
    store.mkdir(store.root(), &name("record")).unwrap();
    let directory = store
        .open_dir(store.root(), &name("record"))
        .unwrap()
        .unwrap();
    store
        .create_once(&directory, &name("inner"), b"kept")
        .unwrap();
    let error = store.rmdir(store.root(), &name("record")).unwrap_err();
    assert!(
        matches!(&error, Error::Io(error) if error.raw_os_error() == Some(libc::ENOTEMPTY)),
        "{error}"
    );
    assert_eq!(fs::read(case.state.join("record/inner")).unwrap(), b"kept");
}

/// Unmarking a nested state directory removes its staging directory and
/// then its marker, so a fault at any step leaves both, the marker alone,
/// or neither; a staged entry keeps both and changes nothing.
#[test]
fn unmark_removes_staging_then_marker_under_a_fault_at_every_step() {
    let nested = |case: &Case, store: &Store| {
        store.mkdir(store.root(), &name("nested")).unwrap();
        drop(Store::open(&case.state.join("nested")).unwrap());
        store
            .open_dir(store.root(), &name("nested"))
            .unwrap()
            .unwrap()
    };
    let marks = |case: &Case| {
        (
            case.state.join("nested/.staging").exists(),
            case.state.join("nested/.state").exists(),
        )
    };
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let directory = nested(&case, &store);
    let (unmarked, trace) = scripted(None, || store.unmark(&directory));
    assert!(unmarked.unwrap().unwrap());
    assert_eq!(marks(&case), (false, false));
    let tail = [
        Step::Stat,
        Step::Check,
        Step::Unlink,
        Step::Unlink,
        Step::Sync,
        Step::Stat,
        Step::Check,
    ];
    assert!(trace.ends_with(&tail), "{trace:?}");
    assert_eq!(
        trace
            .iter()
            .filter(|step| matches!(step, Step::Unlink | Step::Sync))
            .copied()
            .collect::<Vec<_>>(),
        [Step::Unlink, Step::Unlink, Step::Sync]
    );
    let guarded = trace.len() - tail.len();
    let (absent, absent_trace) = scripted([], || store.unmark(&directory));
    assert!(absent.unwrap().unwrap());
    assert!(absent_trace.ends_with(&tail), "{absent_trace:?}");
    for index in 0..trace.len() {
        for outcome in [Outcome::Errno(libc::EIO), Outcome::Kill] {
            let case = Case::new();
            let store = Store::open(&case.state).unwrap();
            let directory = nested(&case, &store);
            let (result, reached) = scripted(Some((index, outcome)), || store.unmark(&directory));
            let context = format!("step {index} {outcome:?}");
            assert_eq!(reached, trace[..=index], "{context}");
            match outcome {
                Outcome::Kill => assert!(result.is_none(), "{context}"),
                Outcome::Errno(_) => {
                    assert!(matches!(result, Some(Err(_))), "{context}: {result:?}");
                    let (later, steps) = scripted([], || {
                        store.create_once(store.root(), &name("later"), b"kept")
                    });
                    if index >= guarded {
                        assert!(
                            matches!(later, Some(Err(Error::Poisoned))),
                            "{context}: {later:?}"
                        );
                        assert!(steps.is_empty(), "{context}: {steps:?}");
                    } else {
                        later.unwrap().unwrap();
                    }
                }
                _ => unreachable!(),
            }
            assert!(
                [(true, true), (false, true), (false, false)].contains(&marks(&case)),
                "{context}: {:?}",
                marks(&case)
            );
            drop(store);
            let store = Store::open(&case.state).unwrap();
            let directory = store
                .open_dir(store.root(), &name("nested"))
                .unwrap()
                .unwrap();
            let (rerun, rerun_trace) = scripted([], || store.unmark(&directory));
            assert!(rerun.unwrap().unwrap(), "{context}");
            assert!(rerun_trace.ends_with(&tail), "{context}: {rerun_trace:?}");
            assert_eq!(marks(&case), (false, false), "{context}");
            drop(store);
            for second in rerun_trace
                .iter()
                .enumerate()
                .filter_map(|(i, step)| (*step == Step::Unlink).then_some(i))
            {
                let case = Case::new();
                let store = Store::open(&case.state).unwrap();
                let dir = nested(&case, &store);
                scripted([(index, outcome)], || store.unmark(&dir));
                drop(store);
                let store = Store::open(&case.state).unwrap();
                let dir = store
                    .open_dir(store.root(), &name("nested"))
                    .unwrap()
                    .unwrap();
                let (killed, reached) = scripted([(second, Outcome::Kill)], || store.unmark(&dir));
                assert!(killed.is_none(), "{context}, second kill {second}");
                assert_eq!(reached, rerun_trace[..=second], "{context}");
                assert!(
                    [(true, true), (false, true), (false, false)].contains(&marks(&case)),
                    "{context}"
                );
                drop(store);
                let store = Store::open(&case.state).unwrap();
                let dir = store
                    .open_dir(store.root(), &name("nested"))
                    .unwrap()
                    .unwrap();
                let (rerun, trace) = scripted([], || store.unmark(&dir));
                assert!(rerun.unwrap().unwrap());
                assert!(trace.ends_with(&tail), "{trace:?}");
                assert_eq!(marks(&case), (false, false));
            }
        }
    }
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let directory = nested(&case, &store);
    assert!(store.marks_removable(&directory).unwrap());
    fs::write(case.state.join("nested/.staging/staged"), b"").unwrap();
    assert!(!store.marks_removable(&directory).unwrap());
    assert!(!store.unmark(&directory).unwrap());
    assert_eq!(marks(&case), (true, true));
    fs::remove_file(case.state.join("nested/.staging/staged")).unwrap();
    let (listed, _) = scripted(Some((0, Outcome::Kill)), || {
        store.marks_removable(&directory)
    });
    assert!(listed.is_none());
    let (faulted, trace) = scripted(None, || store.marks_removable(&directory));
    assert!(faulted.unwrap().unwrap());
    let list = trace.iter().position(|step| *step == Step::List).unwrap();
    let (faulted, _) = scripted(Some((list, Outcome::Errno(libc::EIO))), || {
        store.marks_removable(&directory)
    });
    assert!(matches!(faulted, Some(Err(Error::Io(_)))), "{faulted:?}");
    assert!(store.unmark(&directory).unwrap());
    assert!(store.marks_removable(&directory).unwrap());
}

#[test]
fn unmark_keeps_the_marks_beside_another_entry() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store.mkdir(store.root(), &name("nested")).unwrap();
    drop(Store::open(&case.state.join("nested")).unwrap());
    let directory = store
        .open_dir(store.root(), &name("nested"))
        .unwrap()
        .unwrap();
    fs::write(case.state.join("nested/entry"), b"kept").unwrap();
    let before = snapshot(&case.state);
    assert!(store.marks_removable(&directory).unwrap());
    assert!(!store.unmark(&directory).unwrap());
    assert_eq!(snapshot(&case.state), before);
    fs::remove_file(case.state.join("nested/entry")).unwrap();
    assert!(store.unmark(&directory).unwrap());
    assert!(!case.state.join("nested/.state").exists());
}

#[test]
fn an_absent_marker_allows_the_marks_only_beside_the_staging_directory() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store.mkdir(store.root(), &name("nested")).unwrap();
    drop(Store::open(&case.state.join("nested")).unwrap());
    let directory = store
        .open_dir(store.root(), &name("nested"))
        .unwrap()
        .unwrap();
    fs::write(case.state.join("nested/entry"), b"kept").unwrap();
    fs::remove_file(case.state.join("nested/.state")).unwrap();
    let before = snapshot(&case.state);
    assert!(!store.marks_removable(&directory).unwrap());
    assert!(!store.unmark(&directory).unwrap());
    assert_eq!(snapshot(&case.state), before);
    let (refused, trace) = scripted(None, || store.marks_removable(&directory));
    assert!(!refused.unwrap().unwrap());
    let list = trace.iter().position(|step| *step == Step::List).unwrap();
    let (faulted, _) = scripted(Some((list, Outcome::Errno(libc::EIO))), || {
        store.marks_removable(&directory)
    });
    assert!(matches!(faulted, Some(Err(Error::Io(_)))), "{faulted:?}");
    fs::remove_file(case.state.join("nested/entry")).unwrap();
    assert!(store.marks_removable(&directory).unwrap());
    fs::remove_dir(case.state.join("nested/.staging")).unwrap();
    assert!(store.marks_removable(&directory).unwrap());
    assert!(store.unmark(&directory).unwrap());
    store.rmdir(store.root(), &name("nested")).unwrap();
    assert!(!case.state.join("nested").exists());
}

/// A create-once onto an existing record reports `Existing` with the prior
/// bytes and nothing staged; a second mkdir reports `Existing`; a delete of
/// an absent name succeeds; a replace onto an absent name creates it; and
/// the store stays writable throughout.
#[test]
fn existing_and_absent_targets_leave_the_store_writable() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    let root = store.root();
    create_prior(&store);
    let again = store.create_once(root, &name("record"), b"new");
    assert_eq!(again.expect("the create runs"), Creation::Existing);
    assert_eq!(
        fs::read(case.state.join("record")).expect("it reads"),
        b"prior"
    );
    assert_eq!(
        fs::read_dir(case.state.join(".staging"))
            .expect("it lists")
            .count(),
        0
    );
    assert_eq!(
        store.mkdir(root, &name("jobs")).expect("mkdir runs"),
        Creation::Created
    );
    assert_eq!(
        store.mkdir(root, &name("jobs")).expect("mkdir runs"),
        Creation::Existing
    );
    store
        .delete(root, &name("absent"))
        .expect("an absent delete succeeds");
    store
        .delete(root, &name("absent"))
        .expect("a second delete succeeds");
    store
        .replace(root, &name("fresh"), b"fresh")
        .expect("the replace creates");
    assert_eq!(
        fs::read(case.state.join("fresh")).expect("it reads"),
        b"fresh"
    );
    store
        .create_once(root, &name("later"), b"later")
        .expect("the store stays writable");
}

/// Publication, reads, listings, the barrier and delete through a
/// subdirectory's handle change only that subdirectory.
#[test]
fn a_subdirectory_handle_confines_every_operation_to_it() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    store
        .mkdir(store.root(), &name("jobs"))
        .expect("the directory is made");
    let jobs = store
        .open_dir(store.root(), &name("jobs"))
        .expect("the directory opens")
        .expect("it exists");
    store
        .create_once(&jobs, &name("record"), b"once")
        .expect("the create runs");
    store
        .replace(&jobs, &name("other"), b"replaced")
        .expect("the replace runs");
    store.mkdir(&jobs, &name("nested")).expect("the mkdir runs");
    let read = store
        .read(&jobs, &name("record"), 64)
        .expect("the read runs")
        .expect("the record exists");
    assert_eq!(read.bytes(), b"once");
    store.barrier(&read).expect("the barrier runs");
    store
        .delete(&jobs, &name("other"))
        .expect("the delete runs");
    assert_eq!(
        store.list(&jobs, 8).expect("it lists"),
        [name("nested"), name("record")]
    );
    assert_eq!(
        store.list(store.root(), 8).expect("it lists"),
        [name("jobs")]
    );
    let paths: Vec<PathBuf> = snapshot(&case.state).into_keys().collect();
    let expected = [".staging", ".state", "jobs", "jobs/nested", "jobs/record"];
    assert_eq!(paths, expected.map(PathBuf::from));
}

/// A umask that clears an owner bit is refused before the store writes
/// anything. Under a umask that leaves the owner bits, a published record
/// has mode 0600 and created directories have mode 0700.
#[test]
fn a_restrictive_umask_is_refused_and_modes_are_exact() {
    let case = Case::new();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            sys::private_fs(0o477).expect("the thread gets its own umask");
            let refused = Store::open(&case.state);
            assert!(
                matches!(refused, Err(Error::Refused(Refusal::Umask(Some(0o477))))),
                "{refused:?}"
            );
            assert!(snapshot(&case.state).is_empty());
            // Umask 0 narrows nothing, so each mode below is the create's
            // own mode argument.
            sys::private_fs(0).expect("the thread's umask changes");
            let store = Store::open(&case.state).expect("the store opens");
            store
                .create_once(store.root(), &name("record"), b"bytes")
                .expect("it publishes");
            store
                .mkdir(store.root(), &name("jobs"))
                .expect("the directory is made");
        });
    });
    for (entry, mode) in [("record", 0o600), ("jobs", 0o700), (".staging", 0o700)] {
        let status = fs::metadata(case.state.join(entry)).expect("the entry stats");
        assert_eq!(status.permissions().mode() & 0o7777, mode, "{entry}");
    }
}

/// A short write continues with the rest of the bytes, and an interrupted
/// write after a short one is retried; a write that accepts no bytes fails
/// with `WriteZero`; and a failure or kill on the write after a short one
/// fails the create. A failed write poisons the store, and recovery leaves
/// no record and nothing staged.
#[test]
fn a_short_write_completes_and_a_failed_write_poisons() {
    let write = PUBLISH
        .iter()
        .position(|&at| at == Step::Write)
        .expect("a create writes");
    for (at, writes) in [
        (vec![(write, Outcome::Short(1))], 2),
        (
            vec![
                (write, Outcome::Short(1)),
                (write + 1, Outcome::Errno(libc::EINTR)),
            ],
            3,
        ),
    ] {
        let case = Case::new();
        let store = Store::open(&case.state).expect("the store opens");
        let (result, reached) = scripted(at, || create(&store));
        result
            .expect("the run completes")
            .expect("a short write continues");
        assert_eq!(
            reached.iter().filter(|&&at| at == Step::Write).count(),
            writes
        );
        drop(store);
        assert_eq!(file(&recover(&case.state, "short")), Some(&b"new"[..]));
    }
    // The expected error of each failed create, `None` for a kill.
    type Expected = Option<fn(&std::io::Error) -> bool>;
    let failures: [(_, Expected); 3] = [
        (
            vec![(write, Outcome::Short(0))],
            Some(|error: &std::io::Error| error.kind() == std::io::ErrorKind::WriteZero),
        ),
        (
            vec![
                (write, Outcome::Short(1)),
                (write + 1, Outcome::Errno(libc::EIO)),
            ],
            Some(|error: &std::io::Error| error.raw_os_error() == Some(libc::EIO)),
        ),
        (
            vec![(write, Outcome::Short(1)), (write + 1, Outcome::Kill)],
            None,
        ),
    ];
    for (at, expected) in failures {
        let case = Case::new();
        let store = Store::open(&case.state).expect("the store opens");
        let context = format!("{at:?}");
        let last = at.last().map(|&(index, _)| index);
        let (result, reached) = scripted(at, || create(&store));
        assert_eq!(
            Some(reached.len()),
            last.map(|index| index + 1),
            "{context}"
        );
        assert_eq!(reached.last(), Some(&Step::Write), "{context}");
        match (result, expected) {
            (Some(Err(Error::Io(error))), Some(expected)) => {
                assert!(expected(&error), "{context}: {error}");
                let (later, reached) = scripted(None, || create(&store));
                assert!(matches!(later, Some(Err(Error::Poisoned))), "{context}");
                assert!(reached.is_empty(), "{context}");
            }
            (None, None) => {}
            (other, _) => panic!("{context}: {other:?}"),
        }
        drop(store);
        assert!(
            record(&recover(&case.state, &context)).is_none(),
            "{context}"
        );
    }
}

/// A failed `fsync` of a prerequisite's file or directory poisons the
/// store, so no dependent record is published after it.
#[test]
fn a_failed_prerequisite_barrier_poisons_the_store() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    create_prior(&store);
    let read = store
        .read(store.root(), &name("record"), 64)
        .expect("the read succeeds")
        .expect("the record exists");
    let (_, reached) = scripted(None, || store.barrier(&read).expect("the barrier succeeds"));
    let syncs: Vec<usize> = (0..reached.len())
        .filter(|&index| reached[index] == Step::Sync)
        .collect();
    assert_eq!(syncs.len(), 2, "{reached:?}");
    for index in syncs {
        let case = Case::new();
        let store = Store::open(&case.state).expect("the store opens");
        create_prior(&store);
        let read = store
            .read(store.root(), &name("record"), 64)
            .expect("the read succeeds")
            .expect("the record exists");
        let (failed, _) = scripted(Some((index, Outcome::Errno(libc::EIO))), || {
            store.barrier(&read)
        });
        assert!(matches!(failed, Some(Err(Error::Io(_)))));
        let later = store.create_once(store.root(), &name("dependent"), b"dependent");
        assert!(matches!(later, Err(Error::Poisoned)));
        assert!(!case.state.join("dependent").exists());
    }
}

/// A state directory renamed away between the publish's pre-check and its
/// rename, with a second controller publishing in its replacement, leaves
/// the first controller's write unacknowledged: its bytes land only in the
/// old directory inode, it reports `Replaced` with exit 4, and it writes
/// nothing more. The second controller's record stands.
#[test]
fn a_replaced_state_directory_leaves_the_write_unacknowledged() {
    let case = Case::new();
    let first = Store::open(&case.state).expect("the first controller opens");
    let (state, old) = (case.state.clone(), case.root.join("old"));
    let second = Rc::new(RefCell::new(None));
    let held = Rc::clone(&second);
    let observe = move |at: Step| {
        if at == Step::Rename && held.borrow().is_none() {
            replace(&state, &old);
            let store = Store::open(&state).expect("the second controller opens the replacement");
            let created = store.create_once(store.root(), &name("record"), b"second");
            assert_eq!(
                created.expect("the second controller publishes"),
                Creation::Created
            );
            *held.borrow_mut() = Some(store);
        }
    };
    let result = observed(observe, || {
        first.create_once(first.root(), &name("record"), b"first")
    });
    assert!(matches!(result, Err(Error::Replaced)), "{result:?}");
    assert_eq!(result.unwrap_err().exit(), Supervisor::Held);
    assert_eq!(
        fs::read(case.state.join("record")).expect("the second record stands"),
        b"second"
    );
    assert_eq!(
        fs::read(case.root.join("old/record")).expect("the remnant exists"),
        b"first"
    );
    assert!(matches!(
        first.create_once(first.root(), &name("later"), b"later"),
        Err(Error::Poisoned)
    ));
    assert!(second.borrow().is_some());
}

/// A state directory replaced before a publish starts fails its pre-check,
/// so nothing is written anywhere, staging included, and the store is
/// poisoned.
#[test]
fn a_state_directory_replaced_before_a_publish_writes_nothing() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    let before = snapshot(&case.state);
    replace(&case.state, &case.root.join("old"));
    assert!(matches!(create(&store), Err(Error::Replaced)));
    assert_eq!(snapshot(&case.root.join("old")), before);
    assert!(snapshot(&case.state).is_empty());
    let (later, reached) = scripted(None, || create(&store));
    assert!(matches!(later, Some(Err(Error::Poisoned))));
    assert!(reached.is_empty(), "{reached:?}");
}

/// A store refuses every directory handle and read another store opened,
/// before it writes anything, so a publication lands only under the lock
/// its store holds and a read never crosses stores.
#[test]
fn a_store_refuses_another_stores_directory_handle() {
    let (first, second) = (Case::new(), Case::new());
    let owner = Store::open(&first.state).expect("the first store opens");
    let other = Store::open(&second.state).expect("the second store opens");
    let foreign = |op: &dyn Fn()| {
        let payload = catch_unwind(AssertUnwindSafe(op)).expect_err("a foreign handle panics");
        let message = payload
            .downcast_ref::<String>()
            .expect("the panic carries its message");
        assert!(
            message.contains("a store uses only its own directory handles"),
            "{message}"
        );
    };
    create_prior(&owner);
    let (before, before_other) = (snapshot(&first.state), snapshot(&second.state));
    let read = owner
        .read(owner.root(), &name("record"), 64)
        .expect("the read succeeds")
        .expect("the record exists");
    foreign(&|| drop(other.create_once(owner.root(), &name("foreign"), b"foreign")));
    foreign(&|| drop(other.barrier(&read)));
    foreign(&|| drop(other.open_dir(owner.root(), &name("record"))));
    foreign(&|| drop(other.read(owner.root(), &name("record"), 64)));
    foreign(&|| drop(other.list(owner.root(), 8)));
    assert_eq!(snapshot(&first.state), before);
    assert_eq!(snapshot(&second.state), before_other);
}

#[test]
fn evidence_barriers_sync_the_file_and_two_directories_and_poison_on_failure() {
    for failed in 0..3 {
        let case = Case::new();
        let store = Store::open(&case.state).expect("store");
        let path = case.state.join("candidate");
        fs::write(&path, b"bundle").expect("worker evidence");
        let (opened, parent) = super::open_evidence(&path).expect("confined evidence");
        let (synced, reached) = scripted(None, || store.sync_evidence(&parent, &opened));
        synced.expect("script").expect("barrier");
        let syncs: Vec<_> = reached
            .iter()
            .enumerate()
            .filter_map(|(at, step)| (*step == Step::Sync).then_some(at))
            .collect();
        assert_eq!(syncs.len(), 3);
        let (synced, _) = scripted(Some((syncs[failed], Outcome::Errno(libc::EIO))), || {
            store.sync_evidence(&parent, &opened)
        });
        assert!(matches!(synced, Some(Err(Error::Io(_)))));
        assert!(matches!(
            store.create_once(store.root(), &name("later"), b"later"),
            Err(Error::Poisoned)
        ));
    }
}

/// `sync_file` syncs the file, then its directory; an `EIO` at either
/// poisons the store, so no later mutation runs.
#[test]
fn a_failed_file_sync_poisons_the_store() {
    for failed in 0..2 {
        let case = Case::new();
        let store = Store::open(&case.state).expect("the store opens");
        fs::write(case.state.join("written"), b"bytes").expect("the file is written");
        let opened = store
            .open_file(store.root(), &name("written"))
            .expect("the open succeeds")
            .expect("the file exists");
        let (synced, reached) = scripted(None, || store.sync_file(store.root(), &opened));
        synced
            .expect("the script kills nothing")
            .expect("the sync succeeds");
        let syncs: Vec<usize> = (0..reached.len())
            .filter(|&at| reached[at] == Step::Sync)
            .collect();
        assert_eq!(syncs.len(), 2, "{reached:?}");
        let (synced, _) = scripted(Some((syncs[failed], Outcome::Errno(libc::EIO))), || {
            store.sync_file(store.root(), &opened)
        });
        assert!(matches!(synced, Some(Err(Error::Io(_)))), "{synced:?}");
        assert!(matches!(
            store.create_once(store.root(), &name("later"), b"later"),
            Err(Error::Poisoned)
        ));
    }
}

/// A store's live marks survive an attempt to unmark its own root, and
/// nested reads reject handles belonging to another state directory.
#[test]
fn nested_store_operations_refuse_the_live_root_or_foreign_handles() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let before = snapshot(&case.state);
    let panic = catch_unwind(AssertUnwindSafe(|| store.unmark(store.root()))).unwrap_err();
    let message = panic.downcast_ref::<String>().unwrap();
    assert!(message.contains("a store never unmarks itself"));
    assert_eq!(snapshot(&case.state), before);
    let other = Case::new();
    let foreign = Store::open(&other.state).unwrap();
    assert!(catch_unwind(AssertUnwindSafe(|| store.marks_removable(foreign.root()))).is_err());
    assert!(catch_unwind(AssertUnwindSafe(|| store.list_nested(foreign.root(), 5))).is_err());
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn evidence_barrier_exempts_every_controller_record_at_the_exact_bound() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    for record in super::evidence::ATTEMPT_RECORDS {
        store
            .create_once(store.root(), &name(record), b"record")
            .unwrap();
    }
    store.evidence_barrier(store.root(), 2).unwrap();
    store
        .create_once(store.root(), &name("bulk"), b"bulk")
        .unwrap();
    assert!(matches!(
        store.evidence_barrier(store.root(), 2),
        Err(Error::ScanBound)
    ));
}

#[test]
fn target_staging_cleanup_is_guarded_idempotent_and_preserves_other_targets() {
    let prepare = || {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let staged = case
            .state
            .join(".staging")
            .join(format!("{:016x}.record", store.root().identity().1));
        fs::write(&staged, b"interrupted publication").unwrap();
        fs::write(case.state.join(".staging/other"), b"other target").unwrap();
        (case, store, staged)
    };
    let (case, store, staged) = prepare();
    let (_, trace) = scripted([], || {
        store.clear_staged(store.root(), &name("record")).unwrap()
    });
    assert_eq!(
        trace,
        [
            Step::Stat,
            Step::Check,
            Step::Open,
            Step::Unlink,
            Step::Sync,
            Step::Stat,
            Step::Check
        ]
    );
    assert!(!staged.exists());
    let (_, absent) = scripted([], || {
        store.clear_staged(store.root(), &name("record")).unwrap()
    });
    assert_eq!(
        absent,
        [
            Step::Stat,
            Step::Check,
            Step::Open,
            Step::Sync,
            Step::Stat,
            Step::Check
        ]
    );
    assert_eq!(
        fs::read(case.state.join(".staging/other")).unwrap(),
        b"other target"
    );
    for index in 0..trace.len() {
        for outcome in [Outcome::Errno(libc::EIO), Outcome::Kill] {
            let (case, store, staged) = prepare();
            let (result, reached) = scripted([(index, outcome)], || {
                store.clear_staged(store.root(), &name("record"))
            });
            if outcome == Outcome::Kill {
                assert!(result.is_none(), "step {index}");
            } else {
                assert!(result.unwrap().is_err(), "step {index}");
                assert!(matches!(
                    store.clear_staged(store.root(), &name("record")),
                    Err(Error::Poisoned)
                ));
            }
            assert_eq!(reached, trace[..=index]);
            assert_eq!(staged.exists(), index <= 3);
            assert_eq!(
                fs::read(case.state.join(".staging/other")).unwrap(),
                b"other target"
            );
            drop(store);
            let store = Store::for_collection(&case.state).unwrap();
            let (_, retry) = scripted([], || {
                store.clear_staged(store.root(), &name("record")).unwrap()
            });
            assert!(retry.contains(&Step::Sync));
            assert_eq!(
                retry,
                if index <= 3 {
                    trace.clone()
                } else {
                    absent.clone()
                }
            );
            assert!(!staged.exists(), "step {index}");
        }
    }
}
