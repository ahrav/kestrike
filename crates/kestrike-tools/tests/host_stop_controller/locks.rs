//! If a run ends before `roles.json` stands, it removes the `injection/` it created only while
//! holding that directory's lock, and it frees the lock after the removal and the evidence
//! directory's sync. Restore and seal require the name to resolve to the directory they locked.

use std::cell::{Cell, RefCell};
use std::fs::{self, File, TryLockError};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use kestrike_tools::host_stop::{Disk, Lock, Signal, lock};

use super::plane::{CALLER, STATUS};
use super::sealed::taken_now;
use super::sealing::{copy_tree, window_end};
use super::steps::{Step, errno, links};
use super::{CHILD, COPY, Case, child, listing};
use crate::host_stop_support::free_lock;

const LEFT: &str = " is left as it stands, since this run never held its lock: remove it before \
                    another run, once no run, restore or seal holds it\n";

fn fail_the_evidence_sync(case: &Case) {
    let evidence = case.evidence.clone();
    case.fail_once(
        libc::EIO,
        move |step| matches!(step, Step::FsyncDirectory(path) if *path == evidence),
    );
}

fn removals(case: &Case) -> Rc<Cell<usize>> {
    let count = Rc::new(Cell::new(0));
    let counted = Rc::clone(&count);
    case.plant(Box::new(move |_, step| {
        if matches!(step, Step::Rmdir) {
            counted.set(counted.get() + 1);
        }
        None
    }));
    count
}

/// In `taken` and `unopened`, the run leaves `injection/` in place because it never acquired the
/// lock.
#[test]
fn a_run_that_never_held_the_lock_leaves_injection_and_the_holders_lock() {
    for arm in ["taken", "unopened", "panicked", "held"] {
        let mut case = Case::new("lock-lost");
        let injection = case.evidence.join("injection");
        fail_the_evidence_sync(&case);
        let holder = Rc::new(RefCell::new(None));
        if arm == "taken" {
            case.contended.set(true);
            let (held, at) = (Rc::clone(&holder), injection.clone());
            let mut locked = false;
            case.plant(Box::new(move |_, step| {
                if matches!(step, Step::TryLock) && !locked {
                    locked = true;
                    let other = lock(&Disk, &at).expect("the other command locks first");
                    *held.borrow_mut() = Some(other);
                }
                None
            }));
        } else if arm == "unopened" {
            let mut made = false;
            case.plant(Box::new(move |_, step| {
                let opens = made && matches!(step, Step::OpenDirectory);
                made = matches!(step, Step::Mkdir(_));
                opens.then(|| errno(libc::EMFILE))
            }));
        } else if arm == "panicked" {
            let mut locking = false;
            case.plant(Box::new(move |_, step| {
                if matches!(step, Step::TryLock) && !locking {
                    locking = true;
                    panic!("a planted lock fault");
                }
                None
            }));
        }
        let removed = removals(&case);
        assert_eq!(case.run(), 2, "{arm}: {}", case.output());
        assert_eq!(case.ops(), [CALLER, STATUS], "{arm}");
        assert_eq!(case.stdout(), "", "{arm}");
        let stderr = case.stderr();
        let shown = injection.display();
        if arm == "held" {
            let line = format!(
                "host-stop-controller: refused: OSError: [Errno 5] Input/output error before \
                 roles.json stood; {shown} is removed; nothing written\n"
            );
            assert_eq!(stderr, line, "{arm}");
            assert_eq!(removed.get(), 1, "{arm}");
            assert_eq!(listing(&case.evidence), [COPY], "{arm}");
            continue;
        }
        let failed = match arm {
            "taken" => format!(
                "Refusal: {shown} is held by a run, restore or seal that has not ended: Resource \
                 temporarily unavailable"
            ),
            "unopened" => format!("Refusal: {shown} cannot be opened: Too many open files"),
            _ => "panic: a planted lock fault".to_owned(),
        };
        let line = format!(
            "host-stop-controller: refused: {failed} before roles.json stood; {shown}{LEFT}"
        );
        assert_eq!(stderr, line, "{arm}");
        assert_eq!(removed.get(), 0, "{arm}");
        assert_eq!(listing(&case.evidence), ["injection", COPY], "{arm}");
        if arm == "taken" {
            let held = holder.borrow_mut().take().expect("the other command holds");
            assert!(held.stands_at(&Disk, &injection).expect("looks up"));
            assert!(taken_now(&injection));
            drop(held);
        }
        drop(free_lock(&injection));
        case.contended.set(false);
        let seen = case.output().len();
        assert_eq!(case.run(), 2, "{arm}: {}", case.output());
        let again = &case.output()[seen..];
        assert!(
            again.contains("injection exists: a run's marks are written once; nothing written"),
            "{arm}: {again}"
        );
        fs::remove_dir(&injection).expect("the directory the run left is empty");
        case.plants.borrow_mut().clear();
        assert_eq!(case.run(), 0, "{arm}: {}", case.output());
    }
}

const KEPT: &str = "locks::a_run_that_holds_the_lock_keeps_it_through_the_removal_and_the_sync";
const PROBE: &str = "HOST_STOP_LOCK_PROBE";
const READS: &str = "the lock reads ";

fn probe_in_this_process() {
    let path = std::env::var_os(PROBE).expect("the probe is given a path");
    let directory = File::open(&path).expect("the probe opens the directory");
    let found = match directory.try_lock() {
        Ok(()) => "free",
        Err(TryLockError::WouldBlock) => "taken",
        Err(TryLockError::Error(error)) => panic!("{}: {error}", Path::new(&path).display()),
    };
    println!("{READS}{found}");
}

fn probed(place: &Path, path: &Path) -> &'static str {
    let path = path.to_str().expect("a scratch path is UTF-8");
    let (status, shown) = child(KEPT, place, &[(PROBE, path)]);
    assert!(status.success(), "{shown}");
    let reads = |found: &str| shown.contains(&format!("{READS}{found}\n"));
    match (reads("taken"), reads("free")) {
        (true, false) => "taken",
        (false, true) => "free",
        _ => panic!("{shown}"),
    }
}

/// A lock freed before `rmdir` lets another command lock a directory that is about to lose its
/// name.
#[test]
fn a_run_that_holds_the_lock_keeps_it_through_the_removal_and_the_sync() {
    if std::env::var_os(CHILD).is_some() {
        probe_in_this_process();
        return;
    }
    let mut case = Case::new("lock-kept");
    case.fail_once(libc::ENOSPC, |step| links(step, "roles.json"));
    let place = case.scratch.0.join("probes");
    fs::create_dir(&place).expect("the probes' directory is made");
    let (injection, evidence) = (case.evidence.join("injection"), case.evidence.clone());
    let probes = Rc::new(RefCell::new(Vec::new()));
    let pinned: Rc<RefCell<Option<(File, PathBuf)>>> = Rc::new(RefCell::new(None));
    let (seen, pin) = (Rc::clone(&probes), Rc::clone(&pinned));
    let mut locking = false;
    case.plant(Box::new(move |_, step| {
        match step {
            Step::TryLock if !locking => {
                locking = true;
                seen.borrow_mut().push(("lock", probed(&place, &injection)));
            }
            Step::Rmdir => {
                let open = File::open(&injection).expect("the directory stands at its removal");
                let through = format!("/proc/{}/fd/{}", std::process::id(), open.as_raw_fd());
                *pin.borrow_mut() = Some((open, PathBuf::from(through)));
                seen.borrow_mut()
                    .push(("removal", probed(&place, &injection)));
            }
            Step::FsyncDirectory(synced) if *synced == evidence => {
                if let Some((_, through)) = &*pin.borrow() {
                    assert!(!injection.exists(), "the sync follows the removal");
                    seen.borrow_mut().push(("sync", probed(&place, through)));
                }
            }
            _ => {}
        }
        None
    }));
    assert_eq!(case.run(), 2, "{}", case.output());
    assert!(
        case.stderr().ends_with("is removed; nothing written\n"),
        "{}",
        case.stderr()
    );
    assert_eq!(
        *probes.borrow(),
        [("lock", "free"), ("removal", "taken"), ("sync", "taken")]
    );
    let (open, _) = pinned.borrow_mut().take().expect("the removal was reached");
    let through = PathBuf::from(format!("/proc/self/fd/{}/.", open.as_raw_fd()));
    drop(free_lock(&through));
}

/// A panic in the removal or in the evidence directory's sync behind it ends the run with the
/// refusal that names `injection/` as possibly standing, and the lock is free once the run returns.
#[test]
fn a_panic_in_the_removal_or_its_sync_names_injection_as_possibly_standing() {
    for arm in ["removal", "sync"] {
        let mut case = Case::new("removal-panic");
        case.fail_once(libc::ENOSPC, |step| links(step, "roles.json"));
        let (injection, evidence) = (case.evidence.join("injection"), case.evidence.clone());
        let pinned = Rc::new(RefCell::new(None));
        let (pin, at) = (Rc::clone(&pinned), injection.clone());
        case.plant(Box::new(move |_, step| {
            match step {
                Step::Rmdir => {
                    let open = File::open(&at).expect("the directory stands at its removal");
                    *pin.borrow_mut() = Some(open);
                    assert!(arm != "removal", "a planted removal fault");
                }
                Step::FsyncDirectory(synced) if *synced == evidence && pin.borrow().is_some() => {
                    panic!("a planted removal fault");
                }
                _ => {}
            }
            None
        }));
        assert_eq!(case.run(), 2, "{arm}: {}", case.output());
        let line = format!(
            "host-stop-controller: refused: OSError: [Errno 28] No space left on device before \
             roles.json stood; {} may stand, since its removal failed or is unsynced (panic: a \
             planted removal fault): remove it before another run\n",
            injection.display()
        );
        assert_eq!(case.stderr(), line, "{arm}");
        assert_eq!(case.stdout(), "", "{arm}");
        assert_eq!(injection.exists(), arm == "removal", "{arm}");
        let open = pinned.borrow_mut().take().expect("the removal was reached");
        let through = PathBuf::from(format!("/proc/self/fd/{}/.", open.as_raw_fd()));
        drop(free_lock(&through));
    }
}

/// After the command opens `injection` and before it calls `flock`, the plant renames the directory
/// to `aside`. If `remade` is true, the plant copies `aside` to `injection`.
fn swap_at_the_lock(case: &Case, injection: &Path, aside: &Path, remade: bool) {
    let (at, aside) = (injection.to_path_buf(), aside.to_path_buf());
    let mut swapped = false;
    case.plant(Box::new(move |_, step| {
        if matches!(step, Step::TryLock) && !swapped {
            swapped = true;
            fs::rename(&at, &aside).expect("the opened directory leaves the name");
            if remade {
                copy_tree(&aside, &at, &[]);
            }
        }
        None
    }));
}

/// Plants on the first lookup of `injection` behind the command's `flock`: with `signal`, the
/// lookup stores SIGTERM, and with `fails`, it returns `EIO`.
fn at_the_lookup_behind_the_lock(case: &Case, injection: &Path, signal: bool, fails: bool) {
    let (at, delivered) = (injection.to_path_buf(), case.delivered);
    let (mut locked, mut looked) = (false, false);
    case.plant(Box::new(move |_, step| {
        locked |= matches!(step, Step::TryLock);
        if !locked || looked || !matches!(step, Step::Lstat(path) if *path == at) {
            return None;
        }
        looked = true;
        if signal {
            delivered.deliver(Signal::Terminate);
        }
        fails.then(|| errno(libc::EIO))
    }));
}

fn lock_refusal(injection: &Path, arm: &str) -> String {
    let reason = match arm {
        "another" => "names another entry than the directory this command locked",
        "none" => {
            "cannot be looked up behind its lock, so the directory locked may be another: No such \
             file or directory"
        }
        "unread" => {
            "cannot be looked up behind its lock, so the directory locked may be another: \
             Input/output error"
        }
        _ => {
            "is held by a run, restore or seal that has not ended: Resource temporarily unavailable"
        }
    };
    format!(
        "host-stop-controller: refused: {} {reason}; nothing written\n",
        injection.display()
    )
}

/// Arranges `arm` on `case`: the directory replaced (`another`) or gone (`none`) at the lock, the
/// lookup behind the lock failed (`unread`), or the lock held by another descriptor (`taken`),
/// whose lock is returned. With `signal`, SIGTERM is stored at the lookup behind the lock, and for
/// `taken` before the command starts.
fn arrange(case: &Case, arm: &str, signal: bool, injection: &Path, aside: &Path) -> Option<Lock> {
    match arm {
        "another" | "none" => {
            swap_at_the_lock(case, injection, aside, arm == "another");
            at_the_lookup_behind_the_lock(case, injection, signal, false);
        }
        "unread" => at_the_lookup_behind_the_lock(case, injection, signal, true),
        "taken" => {
            case.contended.set(true);
            if signal {
                case.delivered.deliver(Signal::Terminate);
            }
            return Some(lock(&Disk, injection).expect("another descriptor takes the lock"));
        }
        _ => {}
    }
    None
}

const ARMS: [&str; 4] = ["another", "none", "unread", "taken"];

/// After directory replacement, publishing by name targets the replacement directory, but the
/// seal's lock covers the original directory.
#[test]
fn a_seal_refuses_a_name_that_no_longer_gives_the_directory_it_locked() {
    let arms = ARMS.iter().flat_map(|arm| [(*arm, false), (*arm, true)]);
    for (arm, signal) in arms.chain([("same", false)]) {
        let mut case = Case::new("seal-swapped");
        let root = case.restored_copy();
        case.advance_to(window_end().0 + 30.0);
        let (injection, aside) = (root.join("injection"), case.scratch.0.join("aside"));
        let holder = arrange(&case, arm, signal, &injection, &aside);
        let read = case.reads_under(&root);
        let seen = case.output().len();
        let code = case.seal_at(&root);
        let output = case.output()[seen..].to_owned();
        let seal = injection.join("collected.json");
        if arm == "same" {
            assert_eq!(code, 0, "{output}");
            assert!(seal.exists() && !read.borrow().is_empty(), "{output}");
            continue;
        }
        assert_eq!(code, 2, "{arm} {signal}: {output}");
        let stored = case.delivered.stored();
        if signal && arm != "taken" {
            let line = "host-stop-controller: signal SIGTERM before any mark; nothing written\n";
            assert_eq!((output.as_str(), stored), (line, None), "{arm}");
        } else {
            let pending = signal.then_some(Signal::Terminate);
            let line = lock_refusal(&injection, arm);
            assert_eq!((output, stored), (line, pending), "{arm} {signal}");
        }
        assert!(read.borrow().is_empty(), "{arm}: {:?}", read.borrow());
        assert!(!seal.exists() && !aside.join("collected.json").exists());
        drop(holder);
        let locked = if aside.exists() { &aside } else { &injection };
        drop(free_lock(locked));
    }
}

/// `restore` raises a signal in its caller check and its poll, so a refusal behind its lock leaves
/// a stored SIGTERM pending, as the refusal of a taken lock does.
#[test]
fn a_restore_refuses_a_name_that_no_longer_gives_the_directory_it_locked() {
    let arms = ARMS.iter().flat_map(|arm| [(*arm, false), (*arm, true)]);
    for (arm, signal) in arms.chain([("same", false)]) {
        let mut case = Case::new("restore-swapped");
        assert_eq!(case.run(), 0, "{}", case.output());
        case.start_target(0);
        let (injection, aside) = (
            case.evidence.join("injection"),
            case.scratch.0.join("aside"),
        );
        let holder = arrange(&case, arm, signal, &injection, &aside);
        let (calls, seen) = (case.log().len(), case.output().len());
        let evidence = case.evidence.clone();
        let code = case.restore_at(&evidence, None);
        let output = case.output()[seen..].to_owned();
        let mark = injection.join("restoration.json");
        if arm == "same" {
            assert_eq!(code, 0, "{output}");
            assert!(mark.exists() && case.log().len() > calls, "{output}");
            continue;
        }
        assert_eq!(code, 2, "{arm} {signal}: {output}");
        assert_eq!(output, lock_refusal(&injection, arm), "{arm} {signal}");
        let pending = signal.then_some(Signal::Terminate);
        assert_eq!(case.delivered.stored(), pending, "{arm} {signal}");
        assert_eq!(case.log().len(), calls, "{arm}: the restore makes no call");
        assert!(!mark.exists() && !aside.join("restoration.json").exists());
        drop(holder);
        let locked = if aside.exists() { &aside } else { &injection };
        drop(free_lock(locked));
    }
}
