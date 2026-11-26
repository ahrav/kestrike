//! Scripted filesystem faults and refusals at every step of a record's
//! publication, a release, a failed bind's rollback, and the owner, device
//! and VFIO group exclusion. Each case judges its effects through raw record
//! bytes, the `.tmp` staging path, the state directory's listing and the
//! fake kernel's driver, command and neighbor logs, read independently of
//! the binder's result.
//!
//! The faults are errnos returned before a step's call and short writes
//! that apply exactly their returned prefix, on a live filesystem whose
//! rename is atomic. The checks read the page cache of a running system
//! and establish what a reader sees at each step: a record shown in place
//! after a failed sync is visible, and its durability across power
//! loss, writeback error or a crash image needs a crash-image test.
//!
//! Every case has a stable name and a deadline it declares before it runs;
//! a case that misses its deadline is missing evidence and fails. The
//! inventory [`REQUIRED`] is frozen here, and
//! [`every_required_fault_case_is_witnessed`] runs every declared case and
//! checks that each required case is among those witnessed.

use std::cell::RefCell;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::binder::{BindError, Binder, mappings_path};
use super::binder_tests::{
    SECONDARY_BDF, between_checks, bind_eni, neighbors_untouched, new_binder, observed,
    stale_gateway, untouched, with_secondary,
};
use super::fixture::{BDF, ENI_BDF, FakeKernel, FakeMetadata, Fixture, VOLUME, group_of};
use super::host::{Host, Kernel};
use super::lock::OwnerLock;
use super::mappings::Mappings;
use super::mappings_tests::{eni, sample};
use super::record_step::{RecordStep, SCRIPT, Script, Scripted, StepWriter, step};

/// The errnos each per-step fault sweep scripts: an I/O error, two
/// exhaustion errors, and an interruption. Some pairs are defensive faults
/// the standard library cannot surface: it retries `EINTR` from `open` and
/// `fsync` itself, and `unlink` and a directory's read-only `open` document
/// neither `ENOSPC` nor `EDQUOT`. Those cases check that the binder returns
/// such an errno from a failing step, and that a failed best-effort staging
/// unlink leaves the exclusive create to refuse any file it left.
const ERRNOS: [i32; 4] = [libc::EIO, libc::ENOSPC, libc::EDQUOT, libc::EINTR];

const DEADLINE: Duration = Duration::from_secs(10);

/// One declared case: its stable name, its deadline, and its run, which
/// panics when a check fails.
struct Case {
    name: &'static str,
    deadline: Duration,
    run: fn(),
}

/// The frozen inventory of the binder's filesystem-fault and refusal cases.
const REQUIRED: [&str; 29] = [
    "publication/fault-free",
    "publication/stale-temporary",
    "publication/temporary-unlink",
    "publication/create",
    "publication/write",
    "publication/short-write",
    "publication/file-sync",
    "publication/rename",
    "publication/directory-open",
    "publication/directory-sync",
    "publication/bind-after-rename",
    "release/refused-before-restore",
    "release/failed-restore",
    "release/unlink-refused",
    "release/directory-after-unlink",
    "release/success",
    "rollback/controller-step",
    "rollback/eni-step",
    "rollback/second-eni-check",
    "rollback/restore-failed",
    "rollback/discard-failed",
    "exclusion/live-owner",
    "exclusion/competitor",
    "exclusion/group-holder",
    "exclusion/device-holder",
    "exclusion/invalid-guard",
    "exclusion/holder-death",
    "exclusion/guard-state-race",
    "exclusion/guards-before-restore",
];

const CASES: [Case; 29] = [
    case("publication/fault-free", publication_fault_free),
    case("publication/stale-temporary", publication_stale_temporary),
    case("publication/temporary-unlink", publication_temporary_unlink),
    case("publication/create", publication_create),
    case("publication/write", publication_write),
    case("publication/short-write", publication_short_write),
    case("publication/file-sync", publication_file_sync),
    case("publication/rename", publication_rename),
    case("publication/directory-open", publication_directory_open),
    case("publication/directory-sync", publication_directory_sync),
    case(
        "publication/bind-after-rename",
        publication_bind_after_rename,
    ),
    case(
        "release/refused-before-restore",
        release_refused_before_restore,
    ),
    case("release/failed-restore", release_failed_restore),
    case("release/unlink-refused", release_unlink_refused),
    case(
        "release/directory-after-unlink",
        release_directory_after_unlink,
    ),
    case("release/success", release_success),
    case("rollback/controller-step", rollback_controller_step),
    case("rollback/eni-step", rollback_eni_step),
    case("rollback/second-eni-check", rollback_second_eni_check),
    case("rollback/restore-failed", rollback_restore_failed),
    case("rollback/discard-failed", rollback_discard_failed),
    case("exclusion/live-owner", exclusion_live_owner),
    case("exclusion/competitor", exclusion_competitor),
    case("exclusion/group-holder", exclusion_group_holder),
    case("exclusion/device-holder", exclusion_device_holder),
    case("exclusion/invalid-guard", exclusion_invalid_guard),
    case("exclusion/holder-death", exclusion_holder_death),
    case("exclusion/guard-state-race", exclusion_guard_state_race),
    case(
        "exclusion/guards-before-restore",
        exclusion_guards_before_restore,
    ),
];

const fn case(name: &'static str, run: fn()) -> Case {
    Case {
        name,
        deadline: DEADLINE,
        run,
    }
}

/// Runs `case` on its own thread and returns once it passes within its
/// deadline. A failed check fails with that check's panic; a run past the
/// deadline fails as missing evidence.
fn witness(case: &Case) {
    Run::start(case).judge();
}

struct Run<'a> {
    case: &'a Case,
    /// The run's own duration, sent once it passes. `recv_timeout` returns
    /// a value already sent however late the parent asks, so its timeout
    /// alone admits a pass from a run past the deadline.
    passed: Receiver<Duration>,
    worker: JoinHandle<()>,
}

impl<'a> Run<'a> {
    fn start(case: &'a Case) -> Self {
        let (done, passed) = mpsc::channel();
        let run = case.run;
        let worker = thread::spawn(move || {
            let began = Instant::now();
            run();
            let _ = done.send(began.elapsed());
        });
        Self {
            case,
            passed,
            worker,
        }
    }

    /// A pass counts when its duration arrives within `case.deadline` of
    /// this call and is itself at most that deadline. The worker sends
    /// when the run returns, so a disconnected channel is a panicked run.
    fn judge(self) {
        match self.passed.recv_timeout(self.case.deadline) {
            Ok(ran) if ran <= self.case.deadline => self.worker.join().unwrap(),
            Err(RecvTimeoutError::Disconnected) => {
                std::panic::resume_unwind(self.worker.join().unwrap_err())
            }
            Ok(_) | Err(RecvTimeoutError::Timeout) => panic!(
                "{} gave no witness within {:?}: missing evidence",
                self.case.name, self.case.deadline
            ),
        }
    }
}

fn run_case(name: &str) {
    let case = CASES
        .iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("{name} is a declared case"));
    witness(case);
}

#[test]
fn every_required_fault_case_is_witnessed() {
    witness_all(&CASES, &REQUIRED);
}

/// The check of [`every_required_fault_case_is_witnessed`]: witnesses every
/// case of `cases` within its deadline, then checks that each name of
/// `required` is among those witnessed.
fn witness_all(cases: &[Case], required: &[&str]) {
    let mut witnessed = Vec::new();
    for case in cases {
        witness(case);
        witnessed.push(case.name);
    }
    for required in required {
        assert!(
            witnessed.contains(required),
            "{required} is required but no case witnessed it"
        );
    }
}

/// The steps one scripted run reached, each with the outcome it took.
type Reached = Vec<(RecordStep, Option<Scripted>)>;

/// Installs `outcomes` and `observe` on this thread, runs `body`, and returns
/// its result with the steps it reached; every scripted outcome must have
/// been consumed.
fn scripted<T>(
    outcomes: &[(RecordStep, Scripted)],
    observe: impl FnMut(RecordStep) + 'static,
    body: impl FnOnce() -> T,
) -> (T, Reached) {
    SCRIPT.with(|script| {
        *script.borrow_mut() = Some(Script {
            outcomes: outcomes.to_vec(),
            reached: Vec::new(),
            observe: Box::new(observe),
        })
    });
    let result = body();
    let script = SCRIPT.with(|script| script.borrow_mut().take()).unwrap();
    assert!(
        script.outcomes.is_empty(),
        "every scripted outcome was reached: {:?}",
        script.outcomes
    );
    (result, script.reached)
}

fn errno(step: RecordStep, errno: i32) -> (RecordStep, Scripted) {
    (step, Scripted::Errno(errno))
}

/// The index in `reached` at which `step` makes its call.
fn call_index(reached: &Reached, step: RecordStep) -> Option<usize> {
    reached
        .iter()
        .position(|(at, outcome)| *at == step && !matches!(outcome, Some(Scripted::Errno(_))))
}

/// The bytes at `path`, `None` when it is absent.
fn bytes(path: &Path) -> Option<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => panic!("{}: {error}", path.display()),
    }
}

fn staging(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

fn listing(dir: &Path) -> Vec<OsString> {
    let mut names: Vec<OsString> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort();
    names
}

/// A scratch state directory for one publication, holding an old record
/// when the case starts from one.
struct Publication {
    dir: PathBuf,
    path: PathBuf,
    old: Option<Vec<u8>>,
    next: Mappings,
    /// The next record's bytes, as a fault-free write to another path lays
    /// them down.
    next_bytes: Vec<u8>,
}

impl Publication {
    fn new(old: bool) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bind-faults-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("state")).unwrap();
        let path = dir.join("state/mappings");
        let mut next = sample(Some("nvme"));
        next.eni = Some(eni(2));
        let reference = dir.join("reference");
        next.write(&reference).unwrap();
        let next_bytes = fs::read(&reference).unwrap();
        fs::remove_file(&reference).unwrap();
        let old = old.then(|| {
            sample(None).write(&path).unwrap();
            fs::read(&path).unwrap()
        });
        assert_ne!(old.as_ref(), Some(&next_bytes));
        Self {
            dir,
            path,
            old,
            next,
            next_bytes,
        }
    }

    /// Writes the next record under `outcomes`, reading the record's path at
    /// every step as an independent reader would. Checks that every
    /// observation and the final path hold the complete old record until the
    /// rename makes its call and the complete next record from then on, and
    /// that a success leaves the directory holding the record alone.
    fn publish(&self, outcomes: &[(RecordStep, Scripted)]) -> (io::Result<()>, Reached) {
        self.publish_with(outcomes, || self.next.write(&self.path))
    }

    /// [`Self::publish`] over the writer `write`, which lays the next record
    /// down at the record's path through the record steps. The record's
    /// cases pass [`Mappings::write`]; a negative control passes a writer
    /// with a planted defect, and the checks [`Self::publish`] describes apply
    /// to both.
    fn publish_with(
        &self,
        outcomes: &[(RecordStep, Scripted)],
        write: impl FnOnce() -> io::Result<()>,
    ) -> (io::Result<()>, Reached) {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let (path, log) = (self.path.clone(), seen.clone());
        let (result, reached) = scripted(
            outcomes,
            move |step| log.borrow_mut().push((step, bytes(&path))),
            write,
        );
        let renamed = call_index(&reached, RecordStep::Rename);
        for (at, (step, observed)) in seen.borrow().iter().enumerate() {
            let expected = match renamed {
                Some(rename) if at > rename => Some(&self.next_bytes),
                _ => self.old.as_ref(),
            };
            assert_eq!(observed.as_ref(), expected, "the path read at {step:?}");
        }
        if renamed.is_some() {
            assert_eq!(bytes(&self.path).as_ref(), Some(&self.next_bytes));
            assert_eq!(Mappings::read(&self.path).unwrap(), self.next);
        } else {
            assert_eq!(
                bytes(&self.path),
                self.old,
                "the old record until the rename"
            );
        }
        if result.is_ok() {
            assert_eq!(listing(&self.dir.join("state")), ["mappings"]);
        }
        (result, reached)
    }

    /// Checks that `result` failed with `errno`, that the staging path holds
    /// `left`, and that the directory holds nothing beside the record and
    /// that staging file.
    fn failed(&self, result: io::Result<()>, errno: i32, left: Option<&[u8]>) {
        assert_eq!(result.unwrap_err().raw_os_error(), Some(errno));
        assert_eq!(
            bytes(&staging(&self.path)).as_deref(),
            left,
            "the staging path after errno {errno}"
        );
        let mut expected = Vec::new();
        if self.path.exists() {
            expected.push("mappings");
        }
        if left.is_some() {
            expected.push("mappings.tmp");
        }
        assert_eq!(listing(&self.dir.join("state")), expected);
    }
}

impl Drop for Publication {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// From no record and from an old one, a fault-free write makes its calls
/// in order: the file syncs before its rename and the directory after it.
fn publication_fault_free() {
    for old in [false, true] {
        let publication = Publication::new(old);
        let (result, reached) = publication.publish(&[]);
        result.unwrap();
        let steps: Vec<RecordStep> = reached.iter().map(|(step, _)| *step).collect();
        assert_eq!(
            steps,
            [
                RecordStep::TemporaryUnlink,
                RecordStep::Create,
                RecordStep::Write,
                RecordStep::FileSync,
                RecordStep::Rename,
                RecordStep::DirectoryOpen,
                RecordStep::DirectorySync,
            ]
        );
    }
}

/// A writer that breaks the publication property: it lays the record down
/// in place, so a reader sees a partial record before the rename. It reaches
/// the steps [`Mappings::write`] reaches, in the same order, but creates and
/// truncates the record's own path where the write creates a staging file,
/// and its rename step returns success without a filesystem call.
fn write_in_place(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let _ = step(RecordStep::TemporaryUnlink, || {
        fs::remove_file(staging(path))
    });
    let file = step(RecordStep::Create, || File::create(path))?;
    StepWriter(&file).write_all(bytes)?;
    step(RecordStep::FileSync, || file.sync_all())?;
    step(RecordStep::Rename, || Ok(()))?;
    Mappings::sync_directory_of(path)
}

/// An in-place write fails the publication checks. The final record of
/// [`write_in_place`] is the complete next one and its step sequence is the
/// fault-free one, so of the publication checks only an observation during
/// the write tells it from [`Mappings::write`]:
/// [`Publication::publish_with`] reads the path as the `Write` step is
/// reached, finds an empty file where the complete old record must still
/// be, and fails its "the path read at" check.
#[test]
#[should_panic(expected = "the path read at Write")]
fn negative_control_an_in_place_record_write_shows_a_reader_a_truncated_record() {
    let publication = Publication::new(true);
    let _ = publication.publish_with(&[], || {
        write_in_place(&publication.path, &publication.next_bytes)
    });
}

/// A staging file a failed attempt left is replaced by the next write.
fn publication_stale_temporary() {
    let publication = Publication::new(true);
    fs::write(staging(&publication.path), b"format=3\ninstance=stale").unwrap();
    let (result, _) = publication.publish(&[]);
    result.unwrap();
}

/// The stale staging file's unlink is best effort: the write proceeds past
/// its failure and succeeds, and the exclusive creation refuses a staging
/// file that unlink left, keeping the old record and that file.
fn publication_temporary_unlink() {
    for code in ERRNOS {
        let publication = Publication::new(true);
        let (result, _) = publication.publish(&[errno(RecordStep::TemporaryUnlink, code)]);
        result.unwrap();
        let publication = Publication::new(true);
        let stale = b"format=3\ninstance=stale".to_vec();
        fs::write(staging(&publication.path), &stale).unwrap();
        let (result, _) = publication.publish(&[errno(RecordStep::TemporaryUnlink, code)]);
        publication.failed(result, libc::EEXIST, Some(&stale));
    }
}

fn publication_create() {
    for code in ERRNOS {
        for old in [false, true] {
            let publication = Publication::new(old);
            let (result, _) = publication.publish(&[errno(RecordStep::Create, code)]);
            publication.failed(result, code, None);
        }
    }
}

/// A failed `write` leaves the staging file holding nothing; an interrupted
/// one is retried and the write completes.
fn publication_write() {
    for code in ERRNOS {
        let publication = Publication::new(true);
        let (result, reached) = publication.publish(&[errno(RecordStep::Write, code)]);
        if code == libc::EINTR {
            result.unwrap();
            let writes = reached
                .iter()
                .filter(|(step, _)| *step == RecordStep::Write)
                .count();
            assert_eq!(writes, 2, "the interrupted write is retried once");
        } else {
            publication.failed(result, code, Some(b""));
        }
    }
}

/// A short write changes exactly the prefix it returns: the rest follows in
/// later writes, and a failure after it leaves exactly that prefix.
fn publication_short_write() {
    let length = Publication::new(false).next_bytes.len();
    for count in [1, length / 2, length - 1] {
        let publication = Publication::new(true);
        let short = Scripted::Short(count);
        let (result, reached) = publication.publish(&[(RecordStep::Write, short)]);
        result.unwrap();
        assert_eq!(
            reached[2..4],
            [(RecordStep::Write, Some(short)), (RecordStep::Write, None)]
        );
        let publication = Publication::new(true);
        let (result, _) = publication.publish(&[
            (RecordStep::Write, short),
            errno(RecordStep::Write, libc::EIO),
        ]);
        let prefix = publication.next_bytes[..count].to_vec();
        publication.failed(result, libc::EIO, Some(&prefix));
    }
}

fn publication_file_sync() {
    for code in ERRNOS {
        let publication = Publication::new(true);
        let (result, _) = publication.publish(&[errno(RecordStep::FileSync, code)]);
        let complete = publication.next_bytes.clone();
        publication.failed(result, code, Some(&complete));
    }
}

fn publication_rename() {
    for code in ERRNOS {
        for old in [false, true] {
            let publication = Publication::new(old);
            let (result, _) = publication.publish(&[errno(RecordStep::Rename, code)]);
            let complete = publication.next_bytes.clone();
            publication.failed(result, code, Some(&complete));
        }
    }
}

/// A directory failure after the rename returns its error. The next record
/// stays in place and the staging path is empty.
fn publication_directory(at: RecordStep) {
    for code in ERRNOS {
        let publication = Publication::new(true);
        let (result, _) = publication.publish(&[errno(at, code)]);
        publication.failed(result, code, None);
        assert_eq!(listing(&publication.dir.join("state")), ["mappings"]);
    }
}

fn publication_directory_open() {
    publication_directory(RecordStep::DirectoryOpen);
}

fn publication_directory_sync() {
    publication_directory(RecordStep::DirectorySync);
}

/// A bind whose record's directory open or sync fails after the rename
/// returns the `mappings` step. The kernel's write log stays empty, and the
/// record stays in place for a release to restore from.
fn publication_bind_after_rename() {
    for at in [RecordStep::DirectoryOpen, RecordStep::DirectorySync] {
        let (fixture, metadata) = with_secondary();
        let binder = new_binder(&fixture);
        let (result, _) = scripted(
            &[errno(at, libc::EIO)],
            |_| {},
            || bind_eni(&binder, Some(VOLUME), &metadata),
        );
        let Err(BindError::Step {
            step: "mappings",
            error: Some(error),
            ..
        }) = result
        else {
            panic!("{at:?} fails the bind at its record: {result:?}");
        };
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert!(untouched(&binder), "no driver write after the record");
        let record = Mappings::read(&mappings_path(&fixture.state_dir())).unwrap();
        assert_eq!(
            (
                record.nvme.unwrap().bdf.as_str(),
                record.eni.unwrap().eni.bdf.as_str()
            ),
            (BDF, ENI_BDF)
        );
        assert!(!staging(&mappings_path(&fixture.state_dir())).exists());
        binder.release(&[]).unwrap();
        assert!(drivers_restored(&fixture.host));
    }
}

#[test]
fn a_bind_whose_directory_fails_after_the_rename_keeps_the_record_and_moves_nothing() {
    run_case("publication/bind-after-rename");
}

#[test]
fn a_fault_free_publication_syncs_the_file_before_its_rename() {
    run_case("publication/fault-free");
}

#[test]
fn a_stale_staging_file_is_replaced_by_the_next_publication() {
    run_case("publication/stale-temporary");
}

#[test]
fn a_failed_stale_staging_unlink_leaves_the_exclusive_create_to_refuse() {
    run_case("publication/temporary-unlink");
}

#[test]
fn a_failed_staging_create_keeps_the_old_record() {
    run_case("publication/create");
}

#[test]
fn a_failed_record_write_keeps_the_old_record_and_an_interrupted_one_retries() {
    run_case("publication/write");
}

#[test]
fn a_short_record_write_changes_exactly_its_returned_prefix() {
    run_case("publication/short-write");
}

#[test]
fn a_failed_staging_sync_keeps_the_old_record() {
    run_case("publication/file-sync");
}

#[test]
fn a_failed_rename_keeps_the_old_record() {
    run_case("publication/rename");
}

#[test]
fn a_failed_directory_open_after_the_rename_keeps_the_next_record() {
    run_case("publication/directory-open");
}

#[test]
fn a_failed_directory_sync_after_the_rename_keeps_the_next_record() {
    run_case("publication/directory-sync");
}

/// Whether the controller and the ENI are on their original drivers with
/// their original overrides.
fn drivers_restored(host: &Host) -> bool {
    let original = |bdf: &str, driver: &str| {
        host.driver(bdf).as_deref() == Some(driver) && host.driver_override(bdf) == Some(None)
    };
    original(BDF, "nvme") && original(ENI_BDF, "ena")
}

/// The devices the binder's driver writes name, in first-write order.
fn written(binder: &Binder<FakeKernel>) -> Vec<String> {
    let mut devices = Vec::new();
    for (path, value) in binder.kernel.writes.borrow().iter() {
        let device = [BDF, ENI_BDF, SECONDARY_BDF]
            .into_iter()
            .find(|bdf| path.contains(bdf) || value == bdf)
            .unwrap_or_else(|| panic!("a driver write names a device: {path}"));
        if !devices.iter().any(|known| known == device) {
            devices.push(device.to_owned());
        }
    }
    devices
}

/// A host whose controller and dataplane ENI one combined bind moved, beside
/// an unrelated ENI no step may touch, with the record's bytes as the bind
/// published them and the kernel's logs cleared.
struct Bound {
    fixture: Fixture,
    binder: Binder<FakeKernel>,
    record: Vec<u8>,
}

impl Bound {
    fn new() -> Self {
        let (fixture, metadata) = with_secondary();
        let binder = new_binder(&fixture);
        bind_eni(&binder, Some(VOLUME), &metadata).unwrap();
        let record = fs::read(mappings_path(&fixture.state_dir())).unwrap();
        let kernel = &binder.kernel;
        kernel.writes.borrow_mut().clear();
        kernel.runs.borrow_mut().clear();
        kernel.solicits.borrow_mut().clear();
        kernel.group_opens.borrow_mut().clear();
        kernel.guarded_unbinds.borrow_mut().clear();
        Self {
            fixture,
            binder,
            record,
        }
    }

    fn path(&self) -> PathBuf {
        mappings_path(&self.fixture.state_dir())
    }

    /// Checks that the record is byte-identical to the published one, that
    /// release wrote no driver attribute, ran no command and solicited no
    /// neighbor, and that both devices stay on `vfio-pci`.
    fn unchanged(&self) {
        assert_eq!(bytes(&self.path()).as_ref(), Some(&self.record));
        assert!(untouched(&self.binder), "{:?}", self.binder.kernel.writes);
        assert!(self.binder.kernel.runs.borrow().is_empty());
        assert!(self.binder.kernel.solicits.borrow().is_empty());
        assert_eq!(observed(&self.fixture, BDF).0.as_deref(), Some("vfio-pci"));
        assert_eq!(
            observed(&self.fixture, ENI_BDF).0.as_deref(),
            Some("vfio-pci")
        );
    }

    /// Whether both devices are restored and the ENI's network batch ran.
    fn restored(&self) -> bool {
        drivers_restored(&self.fixture.host)
            && self
                .binder
                .kernel
                .runs
                .borrow()
                .iter()
                .any(|run| run.starts_with("ip link set dev if6 mtu"))
    }

    /// Checks that no driver write named the unrelated ENI, which stays on `ena`.
    fn unrelated_untouched(&self) {
        assert!(!written(&self.binder).contains(&SECONDARY_BDF.to_owned()));
        assert_eq!(
            observed(&self.fixture, SECONDARY_BDF),
            (Some("ena".into()), None)
        );
    }

    fn group_node(&self, bdf: &str) -> PathBuf {
        self.fixture
            .host
            .dev
            .join(format!("vfio/noiommu-{}", group_of(bdf)))
    }
}

/// Refusals before any restore keep the record byte-identical and write
/// nothing: the owner lock held, and a running module the record does not
/// approve.
fn release_refused_before_restore() {
    let bound = Bound::new();
    let held = OwnerLock::acquire(&bound.fixture.state_dir()).unwrap();
    assert!(matches!(bound.binder.release(&[]), Err(BindError::Lock(_))));
    bound.unchanged();
    drop(held);
    bound
        .fixture
        .file("sys/module/vfio_pci/srcversion", "RELOADED\n");
    assert!(matches!(bound.binder.release(&[]), Err(BindError::Wc(_))));
    bound.unchanged();
}

/// A failed restore keeps the record byte-identical, the other device's
/// restore still runs, and the returned step's state is the device's
/// observed state.
fn release_failed_restore() {
    let bound = Bound::new();
    bound.binder.kernel.fail.replace(Some("nvme/bind"));
    let released = bound.binder.release(&[]);
    let Err(BindError::Step {
        step: "bind",
        state,
        ..
    }) = released
    else {
        panic!("the controller's restore fails at its bind: {released:?}");
    };
    assert!(
        bound.binder.kernel.fail.borrow().is_none(),
        "the fault fired"
    );
    assert_eq!(state.bdf, BDF);
    assert_eq!(bytes(&bound.path()).as_ref(), Some(&bound.record));
    assert_eq!(
        (state.driver, state.driver_override),
        observed(&bound.fixture, BDF)
    );
    assert_eq!(
        observed(&bound.fixture, ENI_BDF),
        (Some("ena".into()), None)
    );
    bound.unrelated_untouched();
}

/// The unlink is reached only once every recorded device is restored, and
/// a refused unlink keeps the record byte-identical.
fn release_unlink_refused() {
    for code in ERRNOS {
        let bound = Bound::new();
        let host = bound.fixture.host.clone();
        let at_unlink = Rc::new(RefCell::new(None));
        let seen = at_unlink.clone();
        let (released, _) = scripted(
            &[errno(RecordStep::Unlink, code)],
            move |step| {
                if step == RecordStep::Unlink {
                    *seen.borrow_mut() = Some(drivers_restored(&host));
                }
            },
            || bound.binder.release(&[]),
        );
        let Err(BindError::Step {
            step: "mappings",
            error: Some(error),
            ..
        }) = released
        else {
            panic!("the refused unlink fails the release: {released:?}");
        };
        assert_eq!(error.raw_os_error(), Some(code));
        assert_eq!(
            *at_unlink.borrow(),
            Some(true),
            "restored before the unlink"
        );
        assert!(bound.restored());
        assert_eq!(bytes(&bound.path()).as_ref(), Some(&bound.record));
        bound.unrelated_untouched();
    }
}

/// A directory open or sync failing after a successful unlink returns its
/// error with the record already removed and every device restored.
fn release_directory_after_unlink() {
    for at in [RecordStep::DirectoryOpen, RecordStep::DirectorySync] {
        for code in ERRNOS {
            let bound = Bound::new();
            let (released, reached) =
                scripted(&[errno(at, code)], |_| {}, || bound.binder.release(&[]));
            let Err(BindError::Step {
                step: "mappings",
                error: Some(error),
                ..
            }) = released
            else {
                panic!("{at:?} fails the release: {released:?}");
            };
            assert_eq!(error.raw_os_error(), Some(code));
            assert_eq!(reached[0], (RecordStep::Unlink, None));
            assert!(!bound.path().exists(), "the record is already removed");
            assert!(bound.restored());
            bound.unrelated_untouched();
        }
    }
}

fn release_success() {
    let bound = Bound::new();
    let (released, reached) = scripted(&[], |_| {}, || bound.binder.release(&[]));
    released.unwrap();
    assert_eq!(
        reached,
        [
            (RecordStep::Unlink, None),
            (RecordStep::DirectoryOpen, None),
            (RecordStep::DirectorySync, None)
        ]
    );
    assert!(bound.restored());
    // The fixture's state directory also holds the owner lock file and the
    // host's device lock directory.
    assert_eq!(
        listing(&bound.fixture.state_dir()),
        ["bind.lock", "kestrike-bind"]
    );
    bound.unrelated_untouched();
}

#[test]
fn a_refusal_before_restore_keeps_the_record_and_writes_nothing() {
    run_case("release/refused-before-restore");
}

#[test]
fn a_failed_restore_keeps_the_record_and_reports_the_observed_state() {
    run_case("release/failed-restore");
}

#[test]
fn a_refused_unlink_keeps_the_record_after_every_device_is_restored() {
    run_case("release/unlink-refused");
}

#[test]
fn a_directory_failure_after_the_unlink_reports_the_error_with_the_record_removed() {
    run_case("release/directory-after-unlink");
}

#[test]
fn a_successful_release_restores_every_device_and_removes_the_record() {
    run_case("release/success");
}

/// A combined bind of the controller and the ENI beside an unrelated ENI,
/// with `fail` and `ignore` set on its kernel.
fn combined(
    fail: Option<&'static str>,
    ignore: Option<&'static str>,
) -> (Fixture, Binder<FakeKernel>, Result<Mappings, BindError>) {
    let (fixture, metadata) = with_secondary();
    let binder = new_binder(&fixture);
    binder.kernel.fail.replace(fail);
    binder.kernel.ignore.replace(ignore);
    let result = bind_eni(&binder, Some(VOLUME), &metadata);
    assert!(binder.kernel.fail.borrow().is_none(), "the fault fired");
    (fixture, binder, result)
}

/// Checks that a failed bind wrote only to `moved`, in order, that rollback
/// restored those devices with the unrelated ENI untouched and removed the
/// record, and that a returned step names the last moved device, the one
/// that failed, with its observed state.
fn rolled_back(
    fixture: &Fixture,
    binder: &Binder<FakeKernel>,
    result: &Result<Mappings, BindError>,
    moved: &[&str],
) {
    assert_eq!(
        written(binder),
        moved,
        "every write belongs to the moved set"
    );
    assert!(drivers_restored(&fixture.host));
    assert_eq!(observed(fixture, SECONDARY_BDF), (Some("ena".into()), None));
    assert!(!mappings_path(&fixture.state_dir()).exists());
    match result {
        Err(BindError::Step { state, .. }) => {
            assert_eq!(Some(&state.bdf.as_str()), moved.last());
            assert_eq!(
                (state.driver.clone(), state.driver_override.clone()),
                observed(fixture, &state.bdf),
                "the returned state is the observed one"
            );
        }
        other => assert!(matches!(other, Err(BindError::Changed)), "{other:?}"),
    }
}

/// Each controller driver write refused, and a bind the kernel accepts
/// without acting on, moves the controller alone, which rollback restores.
fn rollback_controller_step() {
    for (fail, ignore) in [
        (Some("1f.0/driver_override"), None),
        (Some("nvme/unbind=0000:00:1f.0"), None),
        (Some("vfio-pci/bind=0000:00:1f.0"), None),
        (None, Some("vfio-pci/bind=0000:00:1f.0")),
    ] {
        let (fixture, binder, result) = combined(fail, ignore);
        assert!(matches!(result, Err(BindError::Step { .. })), "{result:?}");
        rolled_back(&fixture, &binder, &result, &[BDF]);
    }
}

/// Each ENI driver write refused, and an ENI bind the kernel accepts
/// without acting on, after the controller moved: rollback restores both.
fn rollback_eni_step() {
    for (fail, ignore) in [
        (Some("06.0/driver_override"), None),
        (Some("ena/unbind=0000:00:06.0"), None),
        (Some("vfio-pci/bind=0000:00:06.0"), None),
        (None, Some("vfio-pci/bind=0000:00:06.0")),
    ] {
        let (fixture, binder, result) = combined(fail, ignore);
        assert!(matches!(result, Err(BindError::Step { .. })), "{result:?}");
        rolled_back(&fixture, &binder, &result, &[BDF, ENI_BDF]);
    }
}

/// The ENI's second check refuses after the controller moved: the ENI is
/// never written, and rollback restores the controller alone.
fn rollback_second_eni_check() {
    let (fixture, metadata) = with_secondary();
    let binder = new_binder(&fixture);
    let sys = fixture.host.sys.clone();
    between_checks(&fixture, &binder, move || {
        fs::write(sys.join("class/net/ens6/mtu"), "1500\n").unwrap()
    });
    let result = bind_eni(&binder, Some(VOLUME), &metadata);
    assert!(matches!(result, Err(BindError::Changed)), "{result:?}");
    rolled_back(&fixture, &binder, &result, &[BDF]);
}

/// A rollback whose restore fails returns the original and the restore
/// causes as `Unrestored` and keeps the record, whose original values are
/// the pre-bind ones, and the restore cause's state is the observed one.
fn rollback_restore_failed() {
    let (fixture, binder, result) = combined(Some("ena/unbind=0000:00:06.0"), Some("nvme/bind"));
    let Err(BindError::Unrestored(causes)) = result else {
        panic!("a failed rollback is unrestored: {result:?}");
    };
    assert!(
        matches!(causes.0, BindError::Step { step: "unbind", .. }),
        "{:?}",
        causes.0
    );
    let BindError::Step {
        step: "restore",
        state,
        ..
    } = &causes.1
    else {
        panic!(
            "the controller's restore fails verification: {:?}",
            causes.1
        );
    };
    assert_eq!(state.bdf, BDF);
    assert_eq!(
        observed(&fixture, ENI_BDF),
        (Some("ena".into()), None),
        "the ENI's restore still runs after the controller's fails"
    );
    assert_eq!(
        (state.driver.clone(), state.driver_override.clone()),
        observed(&fixture, &state.bdf)
    );
    assert_eq!(written(&binder), [BDF, ENI_BDF]);
    let record = Mappings::read(&mappings_path(&fixture.state_dir())).unwrap();
    let nvme = record.nvme.unwrap();
    assert_eq!(
        (
            nvme.bdf.as_str(),
            nvme.original_driver.as_str(),
            nvme.original_override
        ),
        (BDF, "nvme", None)
    );
    let eni = record.eni.unwrap();
    assert_eq!(
        (
            eni.eni.bdf.as_str(),
            eni.original_driver.as_str(),
            eni.original_override
        ),
        (ENI_BDF, "ena", None)
    );
    assert_eq!(
        observed(&fixture, SECONDARY_BDF),
        (Some("ena".into()), None)
    );
}

/// After a successful rollback of moved devices, a failed record removal
/// leaves the original error; with nothing moved, the removal's error
/// outranks the refusal. A refused unlink keeps the record, and a directory
/// failure after the unlink leaves it removed. The publication's own
/// directory open or sync passes, so the scripted errno falls on the
/// removal's.
fn rollback_discard_failed() {
    for (at, code) in [
        RecordStep::Unlink,
        RecordStep::DirectoryOpen,
        RecordStep::DirectorySync,
    ]
    .into_iter()
    .flat_map(|at| ERRNOS.map(|code| (at, code)))
    {
        let outcomes = match at {
            RecordStep::Unlink => vec![errno(at, code)],
            _ => vec![(at, Scripted::Pass), errno(at, code)],
        };
        let (fixture, metadata) = with_secondary();
        let binder = new_binder(&fixture);
        binder.kernel.fail.replace(Some("ena/unbind=0000:00:06.0"));
        let (result, reached) = scripted(
            &outcomes,
            |_| {},
            || bind_eni(&binder, Some(VOLUME), &metadata),
        );
        assert!(
            matches!(result, Err(BindError::Step { step: "unbind", .. })),
            "the original error outranks the removal's: {result:?}"
        );
        assert!(reached.contains(&(at, Some(Scripted::Errno(code)))));
        assert!(drivers_restored(&fixture.host));
        assert_eq!(written(&binder), [BDF, ENI_BDF]);
        assert_eq!(
            mappings_path(&fixture.state_dir()).exists(),
            at == RecordStep::Unlink
        );

        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        let sys = fixture.host.sys.clone();
        between_checks(&fixture, &binder, move || {
            fs::write(sys.join("class/net/ens6/mtu"), "1500\n").unwrap()
        });
        let metadata = FakeMetadata::new();
        let (result, _) = scripted(&outcomes, |_| {}, || bind_eni(&binder, None, &metadata));
        let Err(BindError::Step {
            step: "mappings",
            error: Some(error),
            ..
        }) = result
        else {
            panic!("with nothing moved the removal's error outranks the refusal: {result:?}");
        };
        assert_eq!(error.raw_os_error(), Some(code));
        assert!(untouched(&binder));
        assert_eq!(
            mappings_path(&fixture.state_dir()).exists(),
            at == RecordStep::Unlink
        );
    }
}

#[test]
fn a_refused_controller_write_rolls_back_the_controller_alone() {
    run_case("rollback/controller-step");
}

#[test]
fn a_refused_eni_write_rolls_back_both_moved_devices() {
    run_case("rollback/eni-step");
}

#[test]
fn a_second_eni_check_refusal_rolls_back_the_moved_controller_alone() {
    run_case("rollback/second-eni-check");
}

#[test]
fn a_failed_rollback_is_unrestored_with_both_causes_and_keeps_the_record() {
    run_case("rollback/restore-failed");
}

#[test]
fn a_failed_record_removal_after_rollback_keeps_the_pinned_precedence() {
    run_case("rollback/discard-failed");
}

/// A held owner lock refuses a bind before any driver write, neighbor
/// change or record, and a release before any write, keeping the record.
fn exclusion_live_owner() {
    let (fixture, metadata) = with_secondary();
    let binder = new_binder(&fixture);
    stale_gateway(&fixture);
    let held = OwnerLock::acquire(&fixture.state_dir()).unwrap();
    let refused = bind_eni(&binder, Some(VOLUME), &metadata);
    assert!(matches!(refused, Err(BindError::Lock(_))), "{refused:?}");
    assert!(untouched(&binder) && neighbors_untouched(&binder));
    assert!(!mappings_path(&fixture.state_dir()).exists());
    drop(held);

    let bound = Bound::new();
    let held = OwnerLock::acquire(&bound.fixture.state_dir()).unwrap();
    assert!(matches!(bound.binder.release(&[]), Err(BindError::Lock(_))));
    bound.unchanged();
    assert!(bound.binder.kernel.group_opens.borrow().is_empty());
    drop(held);
}

/// A competing binder holding a requested device's lock refuses a bind
/// before any driver write, neighbor change or record, and a competitor
/// holding a recorded device's lock refuses release before any group open
/// or write.
fn exclusion_competitor() {
    let (fixture, metadata) = with_secondary();
    let binder = new_binder(&fixture);
    stale_gateway(&fixture);
    let competitor = fixture.lock_device(ENI_BDF);
    let refused = bind_eni(&binder, Some(VOLUME), &metadata);
    assert!(matches!(refused, Err(BindError::Lock(_))), "{refused:?}");
    assert!(untouched(&binder) && neighbors_untouched(&binder));
    assert!(!mappings_path(&fixture.state_dir()).exists());
    drop(competitor);

    let bound = Bound::new();
    let competitor = bound.fixture.lock_device(BDF);
    assert!(matches!(bound.binder.release(&[]), Err(BindError::Lock(_))));
    bound.unchanged();
    assert!(bound.binder.kernel.group_opens.borrow().is_empty());
    drop(competitor);
}

/// A process holding the ENI's VFIO group, with every device lock free,
/// refuses release with no driver write.
fn exclusion_group_holder() {
    let bound = Bound::new();
    let node = bound.group_node(ENI_BDF);
    bound.fixture.hold(&node);
    assert!(matches!(
        bound.binder.release(&[]),
        Err(BindError::VfioInUse)
    ));
    bound.unchanged();
    bound.fixture.unhold(&node);
}

/// A holder of the ENI's device lock alone, with its group free, refuses
/// release before any group open or write.
fn exclusion_device_holder() {
    let bound = Bound::new();
    let holder = bound.fixture.lock_device(ENI_BDF);
    assert!(matches!(bound.binder.release(&[]), Err(BindError::Lock(_))));
    bound.unchanged();
    assert!(bound.binder.kernel.group_opens.borrow().is_empty());
    drop(holder);
}

/// A guard that cannot be verified refuses release with no driver write: a
/// failed status request, and a regular file at the group's node.
fn exclusion_invalid_guard() {
    let bound = Bound::new();
    bound.binder.kernel.group_status.replace(None);
    assert!(matches!(
        bound.binder.release(&[]),
        Err(BindError::VfioGroup("status"))
    ));
    bound.unchanged();
    bound
        .binder
        .kernel
        .group_status
        .replace(Some(super::group::VIABLE));
    let node = bound.group_node(ENI_BDF);
    fs::remove_file(&node).unwrap();
    fs::write(&node, "").unwrap();
    assert!(matches!(
        bound.binder.release(&[]),
        Err(BindError::VfioGroup("node"))
    ));
    bound.unchanged();
}

/// Once a device lock's holder closes its sole descriptor, which its death
/// does, release proceeds and restores every device. The close stands in
/// for the death, because the kernel closes every descriptor of a process
/// that exits.
fn exclusion_holder_death() {
    let bound = Bound::new();
    let holder = bound.fixture.lock_device(ENI_BDF);
    assert!(matches!(bound.binder.release(&[]), Err(BindError::Lock(_))));
    bound.unchanged();
    drop(holder);
    bound.binder.release(&[]).unwrap();
    assert!(bound.restored());
    assert!(!bound.path().exists());
}

/// A recorded device found unbound, and so unguarded, that another actor
/// binds to `vfio-pci` before its restore is refused with `Changed` and no
/// write for it; the record stays.
fn exclusion_guard_state_race() {
    let bound = Bound::new();
    let pci = bound.fixture.host.pci(ENI_BDF);
    bound
        .binder
        .kernel
        .write(&pci.join("driver/unbind"), ENI_BDF)
        .unwrap();
    bound.binder.kernel.writes.borrow_mut().clear();
    bound.binder.kernel.guarded_unbinds.borrow_mut().clear();
    let host = bound.fixture.host.clone();
    bound.binder.kernel.after_write.replace(Some((
        "nvme/bind",
        Box::new(move || {
            FakeKernel::new(&host)
                .write(&host.bind_file("vfio-pci"), ENI_BDF)
                .unwrap();
        }),
    )));
    assert!(matches!(bound.binder.release(&[]), Err(BindError::Changed)));
    assert_eq!(
        written(&bound.binder),
        [BDF],
        "no write for the unguarded device"
    );
    assert_eq!(
        observed(&bound.fixture, ENI_BDF).0.as_deref(),
        Some("vfio-pci")
    );
    assert_eq!(bytes(&bound.path()).as_ref(), Some(&bound.record));
}

/// Release opens and verifies both devices' group guards before its first
/// write, and each `vfio-pci` unbind runs with its own device's guard open.
fn exclusion_guards_before_restore() {
    let bound = Bound::new();
    bound.binder.release(&[]).unwrap();
    assert_eq!(
        *bound.binder.kernel.group_opens.borrow(),
        [(bound.group_node(BDF), 0), (bound.group_node(ENI_BDF), 0)]
    );
    assert_eq!(*bound.binder.kernel.guarded_unbinds.borrow(), [true, true]);
    assert!(bound.restored());
}

#[test]
fn a_live_owner_refuses_bind_and_release_before_any_effect() {
    run_case("exclusion/live-owner");
}

#[test]
fn a_competitor_s_device_lock_refuses_bind_and_release_before_any_effect() {
    run_case("exclusion/competitor");
}

#[test]
fn a_held_group_with_free_locks_refuses_release_before_any_write() {
    run_case("exclusion/group-holder");
}

#[test]
fn a_held_device_lock_with_a_free_group_refuses_release_before_any_guard() {
    run_case("exclusion/device-holder");
}

#[test]
fn an_unverifiable_guard_refuses_release_before_any_write() {
    run_case("exclusion/invalid-guard");
}

#[test]
fn a_dead_holder_s_lock_admits_the_release() {
    run_case("exclusion/holder-death");
}

#[test]
fn a_device_bound_to_vfio_after_the_guards_is_refused_without_a_write() {
    run_case("exclusion/guard-state-race");
}

#[test]
fn every_guard_is_verified_before_the_first_restore_write() {
    run_case("exclusion/guards-before-restore");
}

/// A case run that passes only after a delay far past
/// [`negative_control_a_case_past_its_deadline_is_missing_evidence`]'s
/// deadline.
fn passes_late() {
    thread::sleep(Duration::from_millis(500));
}

/// The inventory check, [`witness_all`], run over a case that passes only
/// after its 50 ms deadline, fails as missing evidence in [`Run::judge`].
#[test]
#[should_panic(expected = "gave no witness within 50ms: missing evidence")]
fn negative_control_a_case_past_its_deadline_is_missing_evidence() {
    let late = [Case {
        name: "control/late",
        deadline: Duration::from_millis(50),
        run: passes_late,
    }];
    witness_all(&late, &["control/late"]);
}

/// `recv_timeout` returns a value already in the channel before it checks
/// its timeout, so this failure comes from [`Run::judge`]'s comparison of
/// the run's duration with the deadline.
#[test]
#[should_panic(expected = "control/late-and-sent gave no witness within 1ms: missing evidence")]
fn a_late_pass_the_parent_finds_already_sent_is_missing_evidence() {
    let late = Case {
        name: "control/late-and-sent",
        deadline: Duration::from_millis(1),
        run: || thread::sleep(Duration::from_millis(5)),
    };
    let run = Run::start(&late);
    while !run.worker.is_finished() {
        thread::yield_now();
    }
    run.judge();
}

/// The inventory check, [`witness_all`], run over the declared cases with
/// the first one removed while the frozen inventory still requires it,
/// fails at its required-case assert.
#[test]
#[should_panic(expected = "publication/fault-free is required but no case witnessed it")]
fn negative_control_a_required_case_no_declared_case_witnesses_is_missing_evidence() {
    witness_all(&CASES[1..], &REQUIRED);
}
