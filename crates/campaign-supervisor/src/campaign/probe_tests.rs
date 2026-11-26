use std::os::unix::fs::MetadataExt;
use std::time::Duration;

use super::*;
use crate::custody::run_tests::Hosted;
use crate::record::{Reservation, Text};
use crate::step::{Outcome, Step};
use crate::store::fixture::{Case, observed, processes, scripted, snapshot};

fn release_fixture(index: usize) -> (Hosted, Custody, Store, Dir, Stopped) {
    let hosted = Hosted::new(index);
    let mut custody = hosted.custody(Duration::from_secs(1));
    let store = Store::open(&hosted.case.state).unwrap();
    store.mkdir(store.root(), &name("probes")).unwrap();
    let probes = store
        .open_dir(store.root(), &name("probes"))
        .unwrap()
        .unwrap();
    store.mkdir(&probes, &name("probe-1")).unwrap();
    let directory = store.open_dir(&probes, &name("probe-1")).unwrap().unwrap();
    let group = hosted.root.join("probe-1");
    std::fs::create_dir(&group).unwrap();
    store
        .create_record(
            &directory,
            &name("reservation"),
            &Reservation {
                attempt: text("probe-1"),
            },
        )
        .unwrap();
    store
        .create_record(
            &directory,
            &name("intent"),
            &Intent {
                attempt: text("probe-1"),
                boot: text(&crate::store::cgroup::boot().unwrap()),
                cgroup: text(group.to_str().unwrap()),
            },
        )
        .unwrap();
    store
        .create_record(
            &directory,
            &name("started"),
            &Started {
                baseline: Default::default(),
                attempt: text("probe-1"),
                boot: text(&crate::store::cgroup::boot().unwrap()),
                cgroup: text(group.to_str().unwrap()),
                cgroup_inode: std::fs::metadata(&group).unwrap().ino(),
                launcher_pid: u64::from(std::process::id()),
            },
        )
        .unwrap();
    let intent = store
        .read_record::<Intent>(&directory, &name("intent"))
        .unwrap()
        .unwrap();
    let started = store
        .read_record::<Started>(&directory, &name("started"))
        .unwrap()
        .unwrap();
    let stopped = custody.reconcile(&store, &intent, Some(&started)).unwrap();
    (hosted, custody, store, directory, stopped)
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn absent_cgroups_still_hold_started_intent_mismatches() {
    let _processes = processes();
    for fault in 0..3 {
        let (hosted, mut custody, store, directory, stopped) = release_fixture(16000 + fault);
        stopped.remove_group().unwrap();
        let intent = store
            .read_record::<Intent>(&directory, &name("intent"))
            .unwrap()
            .unwrap();
        let mut started = store
            .read_record::<Started>(&directory, &name("started"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        match fault {
            0 => started.attempt = text("other-attempt"),
            1 => started.boot = text("other-boot"),
            2 => started.cgroup = text("/other-cgroup"),
            _ => unreachable!(),
        }
        store
            .replace_record(&directory, &name("started"), &started)
            .unwrap();
        let started = store
            .read_record::<Started>(&directory, &name("started"))
            .unwrap()
            .unwrap();
        let before = snapshot(&hosted.case.state);
        assert!(matches!(
            custody.reconcile(&store, &intent, Some(&started)),
            Err(crate::custody::Error::Held("cgroup lacks matching started"))
        ));
        let error = reconcile(&store, &mut custody).unwrap_err();
        assert_eq!(
            error.to_string(),
            "probe started record differs from its intent"
        );
        assert_eq!(snapshot(&hosted.case.state), before);
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn release_preserves_an_existing_complete_finished_record() {
    let _processes = processes();
    let (hosted, _, store, directory, stopped) = release_fixture(15000);
    let complete = ProbeFinished {
        attempt: text("probe-1"),
        outcome: ProbeOutcome::Complete,
    };
    store
        .create_record(&directory, &name("finished"), &complete)
        .unwrap();
    let path = hosted.case.state.join("probes/probe-1/finished");
    let before = std::fs::read(&path).unwrap();
    release(
        &store,
        &directory,
        stopped,
        &ProbeFinished {
            attempt: text("probe-1"),
            outcome: ProbeOutcome::Held,
        },
    )
    .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert_eq!(
        store
            .read_record::<ProbeFinished>(&directory, &name("finished"))
            .unwrap()
            .unwrap()
            .record(),
        &complete
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn probe_release_order_and_crash_cells_preserve_charges_until_finished_and_removed() {
    let _processes = processes();
    let finished = ProbeFinished {
        attempt: text("probe-1"),
        outcome: ProbeOutcome::Held,
    };
    let trace = {
        let (hosted, _, store, directory, stopped) = release_fixture(0);
        let path = hosted.case.state.join("probes/probe-1");
        let group = hosted.root.join("probe-1");
        let trace = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let observed_trace = trace.clone();
        observed(
            move |at| {
                if at == Step::Removed
                    || (at == Step::Unlink && observed_trace.borrow().contains(&Step::Removed))
                {
                    assert!(!group.exists());
                    assert!(path.join("reservation").exists());
                    let record: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(path.join("finished")).unwrap())
                            .unwrap();
                    assert_eq!(record["kind"], "probe_finished");
                    assert_eq!(record["record"]["outcome"], "held");
                }
                observed_trace.borrow_mut().push(at);
            },
            || release(&store, &directory, stopped, &finished),
        )
        .unwrap();
        assert!(!hosted.root.join("probe-1").exists());
        assert!(
            !hosted
                .case
                .state
                .join("probes/probe-1/reservation")
                .exists()
        );
        trace.borrow().clone()
    };
    let removed = trace.iter().position(|at| *at == Step::Removed).unwrap();
    let renamed = trace.iter().position(|at| *at == Step::Rename).unwrap();
    for (fixture, index) in trace
        .iter()
        .enumerate()
        .filter_map(|(index, at)| (*at == Step::Sync && index < removed).then_some(index))
        .enumerate()
    {
        let (hosted, _, store, directory, stopped) = release_fixture(17000 + fixture);
        let (result, reached) = scripted(Some((index, Outcome::Errno(libc::EIO))), || {
            release(&store, &directory, stopped, &finished)
        });
        assert_eq!(reached[index], Step::Sync);
        assert!(matches!(result, Some(Err(Error::Store(_)))));
        assert!(hosted.root.join("probe-1").exists());
        let path = hosted.case.state.join("probes/probe-1");
        assert!(path.join("reservation").exists());
        if index < renamed {
            assert!(!path.join("finished").exists());
        }
        assert!(matches!(
            store.create_once(store.root(), &name("later"), b"later"),
            Err(crate::store::Error::Poisoned)
        ));
    }
    let mut indices: Vec<_> = trace
        .iter()
        .enumerate()
        .filter_map(|(index, at)| (*at == Step::Sync).then_some(index))
        .collect();
    indices.push(removed);
    indices.push(trace.iter().rposition(|at| *at == Step::Unlink).unwrap());
    for (fixture, index) in indices.into_iter().enumerate() {
        let (hosted, mut custody, store, directory, stopped) = release_fixture(fixture + 1);
        let (result, reached) = scripted(Some((index, Outcome::Kill)), || {
            release(&store, &directory, stopped, &finished)
        });
        assert!(result.is_none());
        assert_eq!(reached[index], trace[index]);
        let path = hosted.case.state.join("probes/probe-1");
        if !path.join("reservation").exists() {
            assert!(!hosted.root.join("probe-1").exists());
            assert_eq!(
                store
                    .read_record::<ProbeFinished>(&directory, &name("finished"))
                    .unwrap()
                    .unwrap()
                    .record(),
                &finished
            );
        }
        drop(directory);
        drop(store);
        let store = Store::open(&hosted.case.state).unwrap();
        reconcile(&store, &mut custody).unwrap();
        assert!(!path.join("reservation").exists());
        assert!(!hosted.root.join("probe-1").exists());
        let probes = store
            .open_dir(store.root(), &name("probes"))
            .unwrap()
            .unwrap();
        let directory = store.open_dir(&probes, &name("probe-1")).unwrap().unwrap();
        let recorded = store
            .read_record::<ProbeFinished>(&directory, &name("finished"))
            .unwrap()
            .unwrap();
        assert_eq!(recorded.record(), &finished);
        let before = snapshot(&hosted.case.state);
        reconcile(&store, &mut custody).unwrap();
        assert_eq!(snapshot(&hosted.case.state), before);
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_poisoned_probe_release_stops_before_the_next_charged_tree() {
    let _processes = processes();
    let fixture = |index| {
        let (hosted, custody, store, directory, stopped) = release_fixture(index);
        drop(stopped);
        let probes = store
            .open_dir(store.root(), &name("probes"))
            .unwrap()
            .unwrap();
        store.mkdir(&probes, &name("probe-2")).unwrap();
        let second = store.open_dir(&probes, &name("probe-2")).unwrap().unwrap();
        let group = hosted.root.join("probe-2");
        std::fs::create_dir(&group).unwrap();
        let mut intent = store
            .read_record::<Intent>(&directory, &name("intent"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        intent.attempt = text("probe-2");
        intent.cgroup = text(group.to_str().unwrap());
        let mut started = store
            .read_record::<Started>(&directory, &name("started"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        started.attempt = intent.attempt.clone();
        started.cgroup = intent.cgroup.clone();
        started.cgroup_inode = std::fs::metadata(&group).unwrap().ino();
        store
            .create_record(
                &second,
                &name("reservation"),
                &Reservation {
                    attempt: text("probe-2"),
                },
            )
            .unwrap();
        store
            .create_record(&second, &name("intent"), &intent)
            .unwrap();
        store
            .create_record(&second, &name("started"), &started)
            .unwrap();
        (hosted, custody, store)
    };
    let index = {
        let (_hosted, mut custody, store) = fixture(18000);
        let (result, trace) = scripted(None, || reconcile(&store, &mut custody));
        result.unwrap().unwrap();
        let drained = trace.iter().position(|at| *at == Step::Drained).unwrap();
        trace
            .iter()
            .enumerate()
            .find(|(index, at)| *index > drained && **at == Step::Sync)
            .unwrap()
            .0
    };
    let (hosted, mut custody, store) = fixture(18001);
    let (result, trace) = scripted(Some((index, Outcome::Errno(libc::EIO))), || {
        reconcile(&store, &mut custody)
    });
    assert!(matches!(result, Some(Err(Error::Store(_)))));
    assert_eq!(trace[index], Step::Sync);
    assert_eq!(trace.len(), index + 1);
    for attempt in ["probe-1", "probe-2"] {
        assert!(hosted.root.join(attempt).exists());
        assert!(
            hosted
                .case
                .state
                .join("probes")
                .join(attempt)
                .join("reservation")
                .exists()
        );
    }
    assert!(matches!(
        store.create_once(store.root(), &name("later"), b"later"),
        Err(crate::store::Error::Poisoned)
    ));
    drop(store);
    let store = Store::open(&hosted.case.state).unwrap();
    reconcile(&store, &mut custody).unwrap();
    for attempt in ["probe-1", "probe-2"] {
        assert!(!hosted.root.join(attempt).exists());
        assert!(
            !hosted
                .case
                .state
                .join("probes")
                .join(attempt)
                .join("reservation")
                .exists()
        );
    }
}

fn text(value: &str) -> Text {
    Text::new(value).unwrap()
}

fn evidence(store: &Store, archive: Digest) -> Dir {
    store.mkdir(store.root(), &name("artifacts")).unwrap();
    let artifacts = store
        .open_dir(store.root(), &name("artifacts"))
        .unwrap()
        .unwrap();
    store.mkdir(&artifacts, &name("probe")).unwrap();
    let evidence = store.open_dir(&artifacts, &name("probe")).unwrap().unwrap();
    store
        .create_record(
            &evidence,
            &name("artifact"),
            &crate::campaign::state_fixture::capability_artifact(archive),
        )
        .unwrap();
    store
        .create_once(
            &evidence,
            &name("capabilities.stdout"),
            include_bytes!("../../testdata/admission-listing.txt"),
        )
        .unwrap();
    evidence
}

#[test]
fn capability_binding_checks_every_required_fact_after_a_valid_witness() {
    let archive = Digest::of(b"archive");
    for fault in 0..11 {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let evidence = evidence(&store, archive);
        assert!(read_listing(&store, store.root(), archive).is_ok());
        let mut bad = crate::campaign::state_fixture::capability_artifact(archive);
        let worker = bad.workers.get_mut(&text("capabilities")).unwrap();
        match fault {
            0 => bad.archive = None,
            1 => bad.class = text("incomplete"),
            2 => worker.stdout = Digest::of(b"other output"),
            3 => worker.exit = Some(1),
            4 => worker.signal = Some(9),
            5 => bad.workers.clear(),
            6 => bad.command = text("run"),
            7 => bad.run_id = text("other-probe"),
            8 => bad.archive = Some(Digest::of(b"different archive")),
            9 => worker.ended = text("escaped"),
            10 => worker.ended = text("unknown"),
            _ => unreachable!(),
        }
        store
            .replace_record(&evidence, &name("artifact"), &bad)
            .unwrap();
        let before = snapshot(&case.state);
        let error = read_listing(&store, store.root(), archive).unwrap_err();
        assert!(matches!(error, Error::Held(_)));
        assert_eq!(
            error.to_string(),
            if fault == 5 {
                "probe worker missing"
            } else {
                "capability artifact binding differs"
            }
        );
        assert_eq!(snapshot(&case.state), before);
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn probe_exit_two_is_rejected_after_a_successful_exit_witness() {
    let _processes = processes();
    for code in [0, 2] {
        let hosted = Hosted::new(19000 + code);
        let mut custody = hosted.custody(Duration::from_secs(5));
        let store = Store::open(&hosted.case.state).unwrap();
        let mut launch = hosted.launch();
        launch.args = vec!["-c".into(), format!("exit {code}").into()];
        let running = custody.launch(&store, store.root(), launch).unwrap();
        let stopped = custody.wait_any(vec![running]).unwrap().stopped;
        assert_eq!(stopped.status().unwrap().code(), Some(code as i32));
        assert!(!hosted.case.state.join("jobs").exists());
        let result = verify_exit(&stopped);
        if code == 0 {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(Error::Rejected(_))));
        }
        stopped.remove_group().unwrap();
    }
}

#[test]
fn bound_capability_output_with_invalid_text_or_listing_is_rejected() {
    let archive = Digest::of(b"archive");
    for bytes in [b"\xff".as_slice(), b"capabilities: missing".as_slice()] {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let evidence = evidence(&store, archive);
        assert!(read_listing(&store, store.root(), archive).is_ok());
        let mut bad = crate::campaign::state_fixture::capability_artifact(archive);
        bad.workers.get_mut(&text("capabilities")).unwrap().stdout = Digest::of(bytes);
        store
            .replace_record(&evidence, &name("artifact"), &bad)
            .unwrap();
        store
            .replace(&evidence, &name("capabilities.stdout"), bytes)
            .unwrap();
        let before = snapshot(&case.state);
        assert!(matches!(
            read_listing(&store, store.root(), archive),
            Err(Error::Rejected(_))
        ));
        assert_eq!(snapshot(&case.state), before);
    }
}

#[test]
fn symlinked_probe_evidence_is_refused_even_when_its_target_is_valid() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let archive = Digest::of(b"archive");
    evidence(&store, archive);
    assert!(read_listing(&store, store.root(), archive).is_ok());
    std::fs::rename(
        case.state.join("artifacts/probe"),
        case.state.join("elsewhere"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        case.state.join("elsewhere"),
        case.state.join("artifacts/probe"),
    )
    .unwrap();
    let before = std::fs::read(case.state.join("elsewhere/artifact")).unwrap();
    assert!(matches!(
        read_listing(&store, store.root(), archive),
        Err(Error::Unreadable(_))
    ));
    assert_eq!(
        std::fs::read(case.state.join("elsewhere/artifact")).unwrap(),
        before
    );
}

#[test]
fn archive_host_fault_is_held_before_custody_or_probe_writes() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let before = snapshot(&case.state);
    let (result, reached) = scripted(Some((0, Outcome::Errno(libc::EIO))), || {
        probe(
            &store,
            &case.root.join("archive"),
            &case.root.join("cgroup"),
            Duration::from_secs(1),
        )
    });
    assert_eq!(reached[0], Step::Open);
    assert!(matches!(result, Some(Err(Error::Held(_)))));
    assert_eq!(snapshot(&case.state), before);
}

/// A probe directory is created only while `probes/` holds fewer entries
/// than the scan bound; at the bound the write holds and the root is
/// unchanged.
#[test]
fn probe_directory_holds_at_the_scan_bound_and_writes_nothing() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store.mkdir(store.root(), &name("probes")).unwrap();
    let probes = store
        .open_dir(store.root(), &name("probes"))
        .unwrap()
        .unwrap();
    for index in 0..2 {
        store
            .mkdir(&probes, &name(&format!("probe-{index}")))
            .unwrap();
    }
    let before = snapshot(&case.state);
    let (held, _) = crate::store::fixture::bounded(2, || directory(&store, "probe").map(drop));
    assert_eq!(
        held.unwrap_err().to_string(),
        "probes holds 2 entries at bound 2; collect or shard"
    );
    assert_eq!(snapshot(&case.state), before);
    let (listed, _) = crate::store::fixture::bounded(1, || directory(&store, "probe").map(drop));
    assert_eq!(
        listed.unwrap_err().to_string(),
        "probes holds more than 1 entries at bound 1; collect or shard"
    );
    assert_eq!(snapshot(&case.state), before);
    let (created, _) = crate::store::fixture::bounded(3, || directory(&store, "probe").map(drop));
    created.unwrap();
    assert_eq!(
        std::fs::read_dir(case.state.join("probes"))
            .unwrap()
            .count(),
        3
    );
}
