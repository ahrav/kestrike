use super::*;
use crate::record::HardwareKind;
use crate::step::{Outcome, Step};
use crate::store::fixture::{Case, scripted};

fn admitted(store: &Store) -> (Dir, Hardware, std::path::PathBuf) {
    let (number, dir, path) = allocate(store).unwrap();
    let run = Hardware {
        argv: vec![text("controller").unwrap()],
        class: None,
        custody_directory: None,
        directory: text(path.to_str().unwrap()).unwrap(),
        exit: None,
        kind: HardwareKind::Sweep,
        number,
        phase: HardwarePhase::Intent,
        platform: text("local").unwrap(),
        profile: text("profile").unwrap(),
        reason: text("admitted").unwrap(),
        signal: None,
        stopped: false,
    };
    write(store, &dir, "intent", &run).unwrap();
    (dir, run, path)
}

#[test]
fn skipped_started_read_still_refuses_a_successor() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let (dir, mut run, path) = admitted(&store);
    run.phase = HardwarePhase::Started;
    write(&store, &dir, "started", &run).unwrap();
    let (result, steps) = scripted([], || {
        each_run(&store, |number, dir| {
            assert_eq!(
                record(&store, dir, number)?.unwrap().phase,
                HardwarePhase::Started
            );
            Ok(())
        })
    });
    result.unwrap().unwrap();
    let index = steps.iter().position(|step| *step == Step::Read).unwrap();
    let (result, _) = scripted([(index, Outcome::Errno(libc::EIO))], || reconcile(&store));
    result.unwrap().unwrap();
    assert!(!path.join("finished").exists());
    assert_eq!(
        admit(&store).unwrap_err().exit(),
        crate::exit::Supervisor::Held
    );
    assert!(!case.state.join("runs/0002").exists());
}

#[test]
fn admission_reads_each_phase_record_once() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let (dir, mut run, path) = admitted(&store);
    run.phase = HardwarePhase::Started;
    write(&store, &dir, "started", &run).unwrap();
    let (result, steps) = scripted([], || admit(&store));
    let error = result.unwrap().unwrap_err();
    assert_eq!(error.exit(), crate::exit::Supervisor::Held);
    assert!(error.to_string().contains("supervisor lost after started"));
    assert!(path.join("finished").exists());
    let reads = steps.iter().filter(|step| **step == Step::Read).count();
    assert_eq!(reads, 2, "{steps:?}");
}

/// Allocation refuses a run that would carry the run listing past the scan
/// bound, so every retained run stays listable by admission and the report.
#[test]
fn allocation_refuses_a_run_past_the_scan_bound() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store.mkdir(store.root(), &name("runs")).unwrap();
    let runs = case.state.join("runs");
    for number in 1..=crate::SCAN_BOUND {
        std::fs::create_dir(runs.join(format!("{number:04}"))).unwrap();
    }
    let error = allocate(&store).unwrap_err();
    assert_eq!(error.exit(), crate::exit::Supervisor::Held);
    assert!(!runs.join(format!("{:04}", crate::SCAN_BOUND + 1)).exists());
    let root = root(&store).unwrap().unwrap();
    assert_eq!(entries(&store, &root).unwrap().len(), crate::SCAN_BOUND);
}
