//! Capture oracles over recorded simulation traces: seeded schedules, mutations each oracle must reject, and the unit-reuse checks.

use crate::storage::{CAPTURE_ORACLES, CaptureTrace, TraceEvent, capture_mutate, capture_recorded};

/// These counts let the test require schedule coverage across seeds independently of oracle verdicts.
fn classes(trace: &CaptureTrace) -> [usize; 4] {
    let mut counts = [0; 4];
    let (mut t0, mut inserted, mut emitted, mut removed) =
        (None, Vec::new(), Vec::new(), Vec::new());
    for event in &trace.events {
        match event {
            TraceEvent::Start { t0: at } => t0 = Some(*at),
            TraceEvent::Insert { step, entry } => {
                if let Some(t0) = t0 {
                    counts[2] += usize::from(*step > t0);
                    let reused: &Vec<u64> = &entry.extents;
                    counts[3] +=
                        usize::from(removed.iter().any(|(_, e): &(u64, Vec<u64>)| e == reused));
                }
                inserted.push((entry.allocation, entry.extents.clone()));
            }
            TraceEvent::Emit { entry } => emitted.push(entry.allocation),
            TraceEvent::Remove { allocation } if t0.is_some() => {
                let visited = emitted.contains(allocation);
                counts[usize::from(visited)] += 1;
                if let Some((_, extents)) = inserted.iter().find(|(a, _)| a == allocation) {
                    removed.push((*allocation, extents.clone()));
                }
            }
            _ => {}
        }
    }
    counts
}

#[test]
fn capture_oracles_and_mutations() {
    let mut seen = [0; 4];
    for seed in 0..256 {
        let trace = capture_recorded(seed);
        for (total, count) in seen.iter_mut().zip(classes(&trace)) {
            *total += count;
        }
        for oracle in CAPTURE_ORACLES {
            assert!(oracle.judge(&trace), "{seed}: {oracle:?}");
            let mut mutated = trace.clone();
            capture_mutate(&mut mutated, oracle);
            assert!(
                !oracle.judge(&mutated),
                "{seed}: {oracle:?} mutation escaped"
            );
        }
    }
    assert!(seen.iter().all(|&n| n > 0), "schedule classes {seen:?}");
}
#[test]
fn oracles_judge_recorded_traces() {
    for seed in 0..256 {
        let live = capture_recorded(seed);
        let record = serde_json::to_vec(&live).unwrap();
        let reload = serde_json::from_slice(&record).unwrap();
        for oracle in CAPTURE_ORACLES {
            assert_eq!(
                oracle.judge(&live),
                oracle.judge(&reload),
                "{seed}: {oracle:?}"
            );
            let mut mutation = live.clone();
            capture_mutate(&mut mutation, oracle);
            let record = serde_json::to_vec(&mutation).unwrap();
            let reloaded_mutation = serde_json::from_slice(&record).unwrap();
            assert!(
                !oracle.judge(&reloaded_mutation),
                "{seed}: {oracle:?} reloaded mutation escaped"
            );
        }
    }
}

#[test]
fn reusable_unit_oracle_refuses_duplicate_live_slots_and_stale_removals() {
    use crate::storage::{CaptureEntry, CaptureOracle, CaptureTrace, ExtentLocator, TraceEvent};
    let old = CaptureEntry {
        key: [1; 32],
        allocation: 1,
        session: 2,
        version: 1,
        deadline_ns: 0,
        lifetime_ms: 0,
        tail: 0,
        extents: vec![ExtentLocator::new(0, 1).unwrap().bits()],
    };
    let good = CaptureTrace {
        payload_units: 10,
        events: vec![
            TraceEvent::Insert {
                step: 1,
                entry: old.clone(),
            },
            TraceEvent::Ledger {
                free: 9,
                reported_owned: 1,
                owners: vec![old.extents.clone()],
            },
        ],
    };
    assert!(CaptureOracle::UnitsExclusive.judge(&good));
    let mut duplicate = old.clone();
    duplicate.allocation = 2;
    duplicate.key = [2; 32];
    duplicate.extents = vec![ExtentLocator::new(1, 1).unwrap().bits()];
    let duplicate_trace = CaptureTrace {
        payload_units: 10,
        events: vec![
            TraceEvent::Insert {
                step: 1,
                entry: old.clone(),
            },
            TraceEvent::Insert {
                step: 2,
                entry: duplicate.clone(),
            },
            TraceEvent::Ledger {
                free: 8,
                reported_owned: 2,
                owners: vec![old.extents.clone(), duplicate.extents],
            },
        ],
    };
    assert!(!CaptureOracle::UnitsExclusive.judge(&duplicate_trace));
    let stale = CaptureTrace {
        payload_units: 10,
        events: vec![
            TraceEvent::Insert {
                step: 1,
                entry: old,
            },
            TraceEvent::Remove { allocation: 2 },
            TraceEvent::Ledger {
                free: 10,
                reported_owned: 0,
                owners: vec![],
            },
        ],
    };
    assert!(!CaptureOracle::UnitsExclusive.judge(&stale));
}
