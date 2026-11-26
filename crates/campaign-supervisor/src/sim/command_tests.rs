//! Watchdog admission, archive failure classes and bundle evidence barriers.

use super::*;

#[test]
fn bundle_evidence_barriers_precede_reads_and_fail_closed() {
    use crate::step::{Outcome, Step};
    use crate::store::fixture::{Case, scripted};
    let mut bytes = vec![0u8; 48];
    bytes[0] = 1;
    let text = "version = 2\nprofile = upload\nbuild = b\nexecutable = e\nplatform = p\ntoolchain = t\nrecords = 20\nbytes = 960\n";
    for chunk in text.as_bytes().chunks(43) {
        let mut record = [0u8; 48];
        record[0] = 2;
        record[1] = 1;
        record[4] = chunk.len() as u8;
        record[5..5 + chunk.len()].copy_from_slice(chunk);
        bytes.extend_from_slice(&record);
    }
    let case = Case::new();
    let store = Store::open(&case.state).expect("store");
    std::fs::write(case.state.join("bundle"), &bytes).expect("worker bytes");
    let opened = store
        .open_file(store.root(), &entry("bundle"))
        .expect("open")
        .expect("bundle");
    let (result, reached) = scripted([], || durable_bundle(&store, opened, 20));
    assert_eq!(
        result.expect("script").expect("bundle evidence").digest,
        Digest::of(&bytes)
    );
    let syncs: Vec<_> = reached
        .iter()
        .enumerate()
        .filter_map(|(at, step)| (*step == Step::Sync).then_some(at))
        .collect();
    assert_eq!(syncs.len(), 2);
    let read = reached
        .iter()
        .position(|step| *step == Step::Read)
        .expect("bundle read");
    assert!(syncs.iter().all(|at| *at < read), "{reached:?}");
    for at in syncs {
        let case = Case::new();
        let store = Store::open(&case.state).expect("store");
        std::fs::write(case.state.join("bundle"), &bytes).expect("worker bytes");
        let opened = store
            .open_file(store.root(), &entry("bundle"))
            .expect("open")
            .expect("bundle");
        let (result, reached) = scripted([(at, Outcome::Errno(libc::EIO))], || {
            durable_bundle(&store, opened, 20)
        });
        let Stop(class, reason) = result.expect("script").expect_err("failed barrier");
        assert_eq!(class, Sim::Incomplete);
        assert!(reason.contains("bundle cannot be made durable"));
        assert!(!reached.contains(&Step::Read));
        assert!(matches!(
            store.create_once(store.root(), &entry("artifact"), b"record"),
            Err(store::Error::Poisoned)
        ));
        assert!(
            store
                .read(store.root(), &entry("artifact"), BOUND)
                .expect("record read")
                .is_none()
        );
    }
}

#[test]
fn triage_evidence_barriers_precede_bundle_reads_and_fail_closed() {
    use crate::step::{Outcome, Step};
    use crate::store::fixture::{Case, scripted};
    let mut bytes = vec![0u8; 48];
    bytes[0] = 1;
    let manifest =
        "build = b\nexecutable = e\nplatform = p\ntoolchain = t\nrecords = 100\nbytes = 4800\n";
    for chunk in manifest.as_bytes().chunks(43) {
        let mut record = [0; 48];
        record[0] = 2;
        record[1] = 1;
        record[4] = chunk.len() as u8;
        record[5..5 + chunk.len()].copy_from_slice(chunk);
        bytes.extend_from_slice(&record);
    }
    let fixture = || {
        let case = Case::new();
        let store = Store::open(&case.state).expect("store");
        let directory = case.root.join("output");
        store::create_dir(&directory).expect("worker directory");
        let path = directory.join("regression.bundle");
        std::fs::write(&path, &bytes).expect("worker evidence");
        (case, store, path)
    };
    let (_case, store, path) = fixture();
    let (result, reached) = scripted([], || durable_triage_bundle(&store, &path));
    assert_eq!(
        result.expect("script").expect("evidence").digest,
        Digest::of(&bytes)
    );
    let syncs: Vec<_> = reached
        .iter()
        .enumerate()
        .filter_map(|(at, step)| (*step == Step::Sync).then_some(at))
        .collect();
    assert_eq!(syncs.len(), 3);
    let data_read = reached
        .iter()
        .rposition(|step| *step == Step::Read)
        .expect("bundle read");
    assert!(syncs.iter().all(|at| *at < data_read));
    for at in syncs {
        let (_case, store, path) = fixture();
        let (result, reached) = scripted([(at, Outcome::Errno(libc::EIO))], || {
            durable_triage_bundle(&store, &path)
        });
        let stopped = result.expect("script").expect_err("barrier refusal");
        assert_eq!(stopped.0, Sim::Incomplete);
        assert!(stopped.1.contains("cannot be made durable"));
        assert!(!reached[at + 1..].contains(&Step::Read));
        assert!(matches!(
            store.create_once(store.root(), &entry("artifact"), b"record"),
            Err(store::Error::Poisoned)
        ));
    }
}

#[test]
fn from_run_source_read_failure_is_incomplete_after_view_open() {
    use crate::step::{Outcome, Step};
    use crate::store::fixture::{Case, scripted};
    let case = Case::new();
    let store = Store::open(&case.state).expect("store");
    store
        .create_once(store.root(), &entry("bundle"), b"source")
        .expect("source");
    let view = store::View::open(&case.state).expect("view");
    let opened = view
        .open_file(view.root(), &entry("bundle"))
        .expect("view open")
        .expect("source");
    let (result, reached) = scripted([(0, Outcome::Errno(libc::EIO))], || {
        super::super::triage::read_original_bundle(opened)
    });
    assert_eq!(reached.first(), Some(&Step::Read));
    let stopped = result.expect("script").expect_err("read failure");
    assert_eq!(stopped.0, Sim::Incomplete);
    assert!(stopped.1.contains("input source read failed"));
}

#[test]
fn output_admission_distinguishes_path_refusals_from_host_and_store_faults() {
    for errno in [libc::EIO, libc::EMFILE, libc::EACCES, libc::ENOENT] {
        assert_eq!(
            input_store_error(
                store::Error::Io(io::Error::from_raw_os_error(errno)),
                "host"
            )
            .0,
            Sim::Incomplete
        );
    }
    for errno in [libc::ENOENT, libc::EACCES, libc::EEXIST] {
        assert_eq!(
            input_store_error(
                store::Error::Unreadable(store::Unreadable::Io(io::Error::from_raw_os_error(
                    errno
                ))),
                "path"
            )
            .0,
            Sim::Rejected
        );
    }
    assert_eq!(
        input_store_error(
            store::Error::Unreadable(store::Unreadable::Io(io::Error::from_raw_os_error(
                libc::EIO
            ))),
            "read"
        )
        .0,
        Sim::Incomplete
    );
    for (kind, class) in [
        (io::ErrorKind::NotFound, Sim::Rejected),
        (io::ErrorKind::PermissionDenied, Sim::Rejected),
        (io::ErrorKind::Other, Sim::Incomplete),
        (io::ErrorKind::OutOfMemory, Sim::Incomplete),
    ] {
        let unreadable = || store::Unreadable::Io(io::Error::from(kind));
        assert_eq!(input_read_error(&unreadable(), "read").0, class);
        assert_eq!(
            input_store_error(store::Error::Unreadable(unreadable()), "open").0,
            class
        );
    }
    assert_eq!(
        input_store_error(store::Error::Refused(store::Refusal::Mode(0o755)), "mode").0,
        Sim::Rejected
    );
    for error in [
        store::Error::Busy,
        store::Error::Poisoned,
        store::Error::Replaced,
        store::Error::ScanBound,
        store::Error::Oversize,
        store::Error::Foreign("entry".into()),
    ] {
        assert_eq!(input_store_error(error, "state").0, Sim::Incomplete);
    }
}

#[test]
fn public_watchdogs_are_refused_before_creating_a_directory() {
    let case = crate::store::fixture::Case::new();
    let artifacts = case.root.join("artifacts");
    for watchdog in [
        Duration::ZERO,
        Duration::MAX,
        Duration::from_secs(u64::from(u32::MAX) + 1),
    ] {
        let options = Options {
            artifacts: artifacts.clone(),
            run_id: Some("fixed".to_owned()),
            watchdog: Some(watchdog),
        };
        let Stop(class, reason) = open(&options).expect_err("refused watchdog");
        assert_eq!(class, Sim::Rejected);
        assert!(reason.contains("watchdog"));
        assert!(!artifacts.exists(), "refusal precedes directory creation");
    }
    let options = Options {
        artifacts: artifacts.clone(),
        run_id: Some("fixed".to_owned()),
        watchdog: Some(Duration::from_secs(u64::from(u32::MAX))),
    };
    assert!(open(&options).is_ok());
    assert!(artifacts.join("fixed").is_dir());
}

#[test]
fn archive_io_and_later_refusals_are_incomplete() {
    assert_eq!(
        archive_failure(Invalid::Io(io::Error::other("read")), false, "load").0,
        Sim::Incomplete
    );
    assert_eq!(
        archive_failure(Invalid::Changed, true, "phase").0,
        Sim::Incomplete
    );
    assert_eq!(
        archive_failure(Invalid::Changed, false, "phase").0,
        Sim::Rejected
    );
}

#[test]
fn capability_watchdogs_default_to_sixty_seconds_and_flags_override() {
    let capabilities = Input::Capabilities(PathBuf::from("archive"));
    assert_eq!(
        initial_watchdog(&capabilities, None),
        Some(Duration::from_secs(60))
    );
    assert_eq!(
        initial_watchdog(&capabilities, Some(Duration::from_millis(1))),
        Some(Duration::from_millis(1))
    );
    let run = Input::Manifest {
        archive: "archive".into(),
        manifest: "manifest".into(),
    };
    assert_eq!(initial_watchdog(&run, None), None);
    assert_eq!(
        initial_watchdog(&run, Some(Duration::from_secs(2))),
        Some(Duration::from_secs(2))
    );
}

#[test]
fn nested_archive_io_keeps_infrastructure_separate_from_input_refusal() {
    for held in [false, true] {
        for (errno, class) in [
            (libc::EIO, Sim::Incomplete),
            (libc::EMFILE, Sim::Incomplete),
            (libc::ENOENT, Sim::Rejected),
            (libc::ENOTDIR, Sim::Rejected),
            (libc::EACCES, Sim::Rejected),
            (libc::ENXIO, Sim::Rejected),
            (libc::ENAMETOOLONG, Sim::Rejected),
            (libc::ELOOP, Sim::Rejected),
            (libc::EINVAL, Sim::Rejected),
        ] {
            let unreadable = store::Unreadable::Io(io::Error::from_raw_os_error(errno));
            let invalid = if held {
                Invalid::Record(crate::record::Held::Unreadable(unreadable))
            } else {
                Invalid::Unreadable("entry".to_owned(), unreadable)
            };
            assert_eq!(invalid.exit(false), class);
            assert_eq!(crate::archive::Error::Invalid(invalid).exit(), class);
        }
    }
}

#[test]
fn frozen_bundle_cap_bounds_source_reads_and_accepts_its_exact_edge() {
    use crate::step::Step;
    use crate::store::fixture::{Case, scripted};
    let case = Case::new();
    let store = Store::open(&case.state).expect("store");
    let text = "build = b\nexecutable = e\nplatform = p\ntoolchain = t\nrecords = 100000\nbytes = 4800000\n";
    let mut bytes = vec![0u8; 48];
    bytes[0] = 1;
    for chunk in text.as_bytes().chunks(43) {
        let mut record = [0u8; 48];
        record[0] = 2;
        record[1] = 1;
        record[4] = chunk.len() as u8;
        record[5..5 + chunk.len()].copy_from_slice(chunk);
        bytes.extend_from_slice(&record);
    }
    let head = bytes.len() / 48;
    let path = case.state.join("bundle");
    std::fs::write(&path, &bytes).expect("header");
    let opened = store
        .open_file(store.root(), &entry("bundle"))
        .expect("open")
        .expect("bundle");
    assert!(durable_bundle(&store, opened, head as u64).is_ok());
    let opened = store
        .open_file(store.root(), &entry("bundle"))
        .expect("open")
        .expect("bundle");
    assert_eq!(
        durable_bundle(&store, opened, head as u64 - 1)
            .expect_err("past frozen cap")
            .0,
        Sim::Incomplete
    );
    for _ in 0..8 {
        let mut checkpoint = [0u8; 48];
        checkpoint[0] = 9;
        bytes.extend_from_slice(&checkpoint);
    }
    std::fs::write(&path, &bytes).expect("leading checkpoints");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("file")
        .set_len(1 << 40)
        .expect("sparse body");
    let opened = store
        .open_file(store.root(), &entry("bundle"))
        .expect("open")
        .expect("bundle");
    let (result, reached) = scripted([], || durable_bundle(&store, opened, head as u64 + 2));
    let Stop(class, reason) = result.expect("script").expect_err("frozen cap");
    assert_eq!(class, Sim::Incomplete);
    assert!(reason.contains("frozen manifest"));
    assert_eq!(
        reached.iter().filter(|step| **step == Step::Read).count(),
        head + 3,
        "each leading read consumes 48 bytes, up to cap+1 records"
    );
}

fn counting_artifact() -> Artifact {
    Artifact {
        archive: None,
        archive_path: None,
        comparison: None,
        bundle: None,
        class: text("counts"),
        command: text("run"),
        manifest: None,
        reason: text("counts"),
        run_id: text("fixed"),
        output: None,
        session: None,
        session_original: None,
        summary: None,
        workers: BTreeMap::new(),
    }
}

#[test]
fn a_failed_final_record_changes_counts_to_incomplete() {
    use crate::step::{Outcome, Step};
    use crate::store::fixture::{Case, scripted};
    let artifact = counting_artifact();
    let case = Case::new();
    let store = Store::open(&case.state).expect("store");
    let (record, reached) = scripted([], || {
        store.create_record(store.root(), &entry("artifact"), &artifact)
    });
    assert_eq!(
        published(Sim::Counts, "counts".to_owned(), record.expect("script")).0,
        Sim::Counts
    );
    let original = store
        .read(store.root(), &entry("artifact"), BOUND)
        .expect("read")
        .expect("original")
        .bytes()
        .to_vec();
    let repeated = store.create_record(store.root(), &entry("artifact"), &artifact);
    let (class, reason) = published(Sim::Counts, "counts".to_owned(), repeated);
    assert_eq!(class, Sim::Incomplete);
    assert!(reason.contains("another artifact entry holds its name"));
    assert_eq!(
        store
            .read(store.root(), &entry("artifact"), BOUND)
            .expect("read")
            .expect("original retained")
            .bytes(),
        original
    );
    let write = reached
        .iter()
        .position(|step| *step == Step::Write)
        .expect("record write");
    let failed = Case::new();
    let store = Store::open(&failed.state).expect("store");
    let (record, _) = scripted([(write, Outcome::Errno(libc::EIO))], || {
        store.create_record(store.root(), &entry("artifact"), &artifact)
    });
    let (class, reason) = published(Sim::Counts, "counts".to_owned(), record.expect("script"));
    assert_eq!(class, Sim::Incomplete);
    assert!(reason.contains("artifact record failed"));
    assert!(
        store
            .read(store.root(), &entry("artifact"), BOUND)
            .expect("read")
            .is_none()
    );
    assert!(matches!(
        store.create_once(store.root(), &entry("later"), b"bytes"),
        Err(store::Error::Poisoned)
    ));
}

#[test]
fn input_host_faults_are_incomplete_and_input_refusals_are_rejected() {
    use crate::step::Outcome;
    use crate::store::fixture::{Case, scripted};
    let case = Case::new();
    let input = case.root.join("input");
    std::fs::write(&input, b"bytes").expect("input");
    let open = |path: &Path| {
        open_host(path).map_err(|why| input_read_error(&why, "the bundle cannot be read"))
    };
    for (errno, class) in [
        (libc::EIO, Sim::Incomplete),
        (libc::EMFILE, Sim::Incomplete),
        (libc::ENOENT, Sim::Rejected),
        (libc::EACCES, Sim::Rejected),
        (libc::ELOOP, Sim::Rejected),
    ] {
        let (result, _) = scripted([(0, Outcome::Errno(errno))], || open(&input));
        let Stop(found, reason) = result.expect("script").expect_err("the open fails");
        assert_eq!(found, class, "{errno}");
        assert!(reason.starts_with("the bundle cannot be read"), "{reason}");
    }
    let Stop(found, _) = open(&case.root).expect_err("a directory is no bundle");
    assert_eq!(found, Sim::Rejected);
    assert!(open(&input).is_ok());
}

#[test]
fn an_existing_final_record_changes_counts_to_incomplete() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).expect("store");
    store
        .create_once(store.root(), &entry("artifact"), b"foreign")
        .expect("the foreign entry is written");
    let record = store.create_record(store.root(), &entry("artifact"), &counting_artifact());
    assert!(matches!(record, Ok(Creation::Existing)), "{record:?}");
    let (class, reason) = published(Sim::Counts, "counts".to_owned(), record);
    assert_eq!(class, Sim::Incomplete);
    assert!(
        reason.contains("another artifact entry holds its name"),
        "{reason}"
    );
    assert_eq!(
        store
            .read(store.root(), &entry("artifact"), BOUND)
            .expect("read")
            .expect("the entry")
            .bytes(),
        b"foreign"
    );
}

/// A bundle whose source is truncated while it is staged is incomplete
/// evidence: the scan's refusal came from a source that changed under it,
/// so the class is 4, as for a source that changes while the worker runs.
/// The same bytes left alone stage as a valid bundle.
#[test]
fn a_bundle_changed_during_staging_is_incomplete() {
    use crate::step::Step;
    use crate::store::fixture::{Case, observed};
    let text = "version = 2\nprofile = upload\nbuild = b\nexecutable = e\nplatform = p\ntoolchain = t\nrecords = 20\nbytes = 960\n";
    let mut bytes = vec![0u8; 48];
    bytes[0] = 1;
    for chunk in text.as_bytes().chunks(43) {
        let mut record = [0u8; 48];
        record[0] = 2;
        record[1] = 1;
        record[4] = chunk.len() as u8;
        record[5..5 + chunk.len()].copy_from_slice(chunk);
        bytes.extend_from_slice(&record);
    }
    let control = Case::new();
    let store = Store::open(&control.state).expect("store");
    let source = control.root.join("bundle");
    std::fs::write(&source, &bytes).expect("bundle");
    let staged = stage_input(&store, &source).expect("the unchanged bundle stages");
    assert_eq!(staged.digest, Digest::of(&bytes));

    let case = Case::new();
    let store = Store::open(&case.state).expect("store");
    let source = case.root.join("bundle");
    std::fs::write(&source, &bytes).expect("bundle");
    let truncated = source.clone();
    let mut once = false;
    let observe = move |at| {
        if at == Step::Read && !once {
            once = true;
            std::fs::OpenOptions::new()
                .write(true)
                .open(&truncated)
                .expect("the source")
                .set_len(48)
                .expect("the source is truncated");
        }
    };
    let Stop(class, reason) =
        observed(observe, || stage_input(&store, &source)).expect_err("the truncated bundle");
    assert_eq!(class, Sim::Incomplete, "{reason}");
    assert!(reason.contains("changed"), "{reason}");
}

/// A symlink already present in the artifact path's prefix is refused
/// before anything is created: the ancestor check reads the path as
/// given, so a link placed in a shared directory cannot route the artifact
/// directory into its target, where the canonical path's check would pass.
#[test]
fn a_symlink_in_the_given_artifact_prefix_is_refused() {
    let case = crate::store::fixture::Case::new();
    let elsewhere = case.root.join("elsewhere");
    std::fs::create_dir(&elsewhere).expect("the target");
    let shared = case.root.join("shared");
    std::fs::create_dir(&shared).expect("the shared directory");
    std::os::unix::fs::symlink(&elsewhere, shared.join("link")).expect("the link");
    let options = Options {
        artifacts: shared.join("link/missing"),
        run_id: Some("fixed".to_owned()),
        watchdog: None,
    };
    let Stop(class, reason) = open(&options).expect_err("the linked prefix is refused");
    assert_eq!(class, Sim::Rejected, "{reason}");
    assert!(reason.contains("refused"), "{reason}");
    assert!(!elsewhere.join("missing").exists());
}

fn partial_command(bytes: usize) -> (crate::store::fixture::Case, Command) {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    store
        .create_once(store.root(), &entry("bundle"), &vec![0; bytes])
        .unwrap();
    let command = Command {
        store,
        interruptions: Interruptions::block().unwrap(),
        watchdog: None,
        archive: None,
        archive_path: None,
        comparison: None,
        session: None,
        session_original: None,
        capabilities: None,
        frozen: Vec::new(),
        manifest: None,
        output: None,
        bundle: None,
        summary: None,
        ruleless: false,
        workers: BTreeMap::new(),
        profile: None,
        maximum: Some(1),
    };
    (case, command)
}

#[test]
fn partial_bundle_staging_uses_frozen_bound_below_inherited_file_quota() {
    let _processes = crate::store::fixture::processes();
    let (_case, mut command) = partial_command(49);
    assert!(crate::sys::file_limit().unwrap() > 49);
    let Stop(class, reason) = command.stage_partial_bundle().unwrap_err();
    assert_eq!(class, Sim::Incomplete);
    assert!(reason.contains("frozen or inherited file bound"));
    assert_eq!(command.bundle, None);
}

#[test]
fn partial_bundle_barrier_faults_poison_and_preserve_uncaptured_digest() {
    use crate::step::{Outcome, Step};
    use crate::store::fixture::scripted;
    let _processes = crate::store::fixture::processes();
    let (_case, mut baseline) = partial_command(32);
    let (result, trace) = scripted([], || baseline.stage_partial_bundle());
    result.unwrap().unwrap();
    assert_eq!(baseline.bundle, Some(Digest::of(&[0; 32])));
    let syncs: Vec<_> = trace
        .iter()
        .enumerate()
        .filter(|(_, step)| **step == Step::Sync)
        .map(|(index, _)| index)
        .collect();
    assert!(!syncs.is_empty());
    for index in syncs {
        for errno in [libc::EIO, libc::EROFS] {
            let (_case, mut command) = partial_command(32);
            let (result, reached) = scripted([(index, Outcome::Errno(errno))], || {
                command.stage_partial_bundle()
            });
            let Stop(class, reason) = result.unwrap().unwrap_err();
            assert_eq!(reached[index], Step::Sync);
            assert_eq!(class, Sim::Incomplete);
            assert!(reason.contains("cannot be made durable"), "{reason}");
            assert_eq!(command.bundle, None);
            assert!(matches!(
                command
                    .store
                    .create_once(command.store.root(), &entry("forbidden"), b"write"),
                Err(store::Error::Poisoned)
            ));
        }
    }
}
