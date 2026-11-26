//! Verdicts depend only on the supplied trace, so recorded histories remain checkable after their storage instances are gone.

use super::super::extent::ExtentLocator;
use super::{CaptureEntry, LoadEvent, LoadLimits};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct CaptureTrace {
    pub payload_units: u64,
    pub events: Vec<TraceEvent>,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) enum TraceEvent {
    Insert {
        step: u64,
        entry: CaptureEntry,
    },
    Remove {
        allocation: u64,
    },
    Start {
        t0: u64,
    },
    Emit {
        entry: CaptureEntry,
    },
    Complete,
    Load {
        limits: LoadLimits,
        entries: Vec<CaptureEntry>,
        events: Vec<LoadEvent>,
    },
    Ledger {
        free: u64,
        reported_owned: u64,
        owners: Vec<Vec<u64>>,
    },
}
#[derive(Debug, Clone, Copy)]
pub(crate) enum CaptureOracle {
    CaptureConsistent,
    UnitsExclusive,
    LedgerConserved,
    LoadGuardNeverFires,
}

fn exclusive(entries: &[CaptureEntry]) -> bool {
    let mut slots = HashSet::new();
    let mut keys = HashSet::new();
    entries
        .iter()
        .all(|e| slots.insert(e.slot()) && keys.insert(e.key))
        && exclusive_extents(entries.iter().map(|e| e.extents.as_slice()))
}
fn exclusive_extents<'a>(owners: impl IntoIterator<Item = &'a [u64]>) -> bool {
    let mut ranges = Vec::new();
    for extents in owners {
        if extents.is_empty() {
            return false;
        }
        for &bits in extents {
            let x = ExtentLocator::from_bits(bits);
            if x.len_units() == 0 {
                return false;
            }
            ranges.push((x.start_unit(), x.start_unit() + u64::from(x.len_units())));
        }
    }
    ranges.sort_unstable();
    ranges.windows(2).all(|w| w[0].1 <= w[1].0)
}
impl CaptureOracle {
    /// `judge` returns `false` for malformed traces as well as property violations.
    pub(crate) fn judge(self, trace: &CaptureTrace) -> bool {
        match self {
            Self::CaptureConsistent => {
                let mut live = BTreeMap::new();
                let mut expected = None;
                let mut checkpoint = None;
                let mut emitted = Vec::new();
                let mut last_step = 0;
                let mut completes = 0;
                for event in &trace.events {
                    match event {
                        TraceEvent::Insert { step, entry } => {
                            if *step <= last_step
                                || live.insert(entry.slot(), entry.clone()).is_some()
                            {
                                return false;
                            }
                            last_step = *step;
                        }
                        TraceEvent::Remove { allocation } => {
                            let slot = (allocation >> 32) as usize;
                            if live
                                .remove(&slot)
                                .is_none_or(|e| e.allocation != *allocation)
                            {
                                return false;
                            }
                        }
                        TraceEvent::Start { t0 } => {
                            if expected.is_some() || *t0 != last_step {
                                return false;
                            }
                            expected = Some(live.values().cloned().collect::<Vec<_>>());
                            checkpoint = None;
                            emitted.clear();
                        }
                        TraceEvent::Emit { entry } => {
                            if expected.is_none() {
                                return false;
                            }
                            emitted.push(entry.clone());
                        }
                        TraceEvent::Complete => {
                            let Some(mut snapshot) = expected.take() else {
                                return false;
                            };
                            snapshot.sort_by_key(|e| e.allocation);
                            emitted.sort_by_key(|e| e.allocation);
                            if snapshot != emitted {
                                return false;
                            }
                            checkpoint = Some(snapshot);
                            completes += 1;
                        }
                        TraceEvent::Load { entries, .. } => {
                            let mut recovered = entries.clone();
                            recovered.sort_by_key(|e| e.allocation);
                            if checkpoint.as_ref() != Some(&recovered) {
                                return false;
                            }
                        }
                        _ => {}
                    }
                }
                completes != 0 && expected.is_none()
            }
            Self::UnitsExclusive => {
                let mut live = BTreeMap::new();
                let mut captured = Vec::new();
                let mut checks = 0;
                for event in &trace.events {
                    match event {
                        TraceEvent::Insert { entry, .. } => {
                            if live.insert(entry.slot(), entry.clone()).is_some() {
                                return false;
                            }
                        }
                        TraceEvent::Remove { allocation } => {
                            if live
                                .remove(&((allocation >> 32) as usize))
                                .is_none_or(|entry| entry.allocation != *allocation)
                            {
                                return false;
                            }
                        }
                        TraceEvent::Start { .. } => captured.clear(),
                        TraceEvent::Emit { entry } => captured.push(entry.clone()),
                        TraceEvent::Complete => {
                            if !exclusive(&captured) {
                                return false;
                            }
                            checks += 1;
                        }
                        TraceEvent::Ledger { owners, .. } => {
                            if !exclusive_extents(owners.iter().map(Vec::as_slice)) {
                                return false;
                            }
                            checks += 1;
                        }
                        TraceEvent::Load { entries, .. } => {
                            if !exclusive(entries) {
                                return false;
                            }
                            checks += 1;
                        }
                    }
                    if !exclusive(&live.values().cloned().collect::<Vec<_>>()) {
                        return false;
                    }
                }
                checks != 0
            }
            Self::LedgerConserved => {
                let mut checks = 0;
                for event in &trace.events {
                    if let TraceEvent::Ledger {
                        free,
                        reported_owned,
                        owners,
                    } = event
                    {
                        let actual: u64 = owners
                            .iter()
                            .flatten()
                            .map(|&bits| u64::from(ExtentLocator::from_bits(bits).len_units()))
                            .sum();
                        if actual != *reported_owned
                            || free.checked_add(actual) != Some(trace.payload_units)
                        {
                            return false;
                        }
                        checks += 1;
                    }
                }
                checks != 0
            }
            Self::LoadGuardNeverFires => {
                let mut checks = 0;
                for event in &trace.events {
                    if let TraceEvent::Load {
                        limits,
                        entries,
                        events,
                    } = event
                    {
                        if !events.is_empty()
                            || !exclusive(entries)
                            || limits.payload_start >= limits.payload_end
                            || limits.reserve_units > limits.payload_end - limits.payload_start
                            || entries.len() > limits.n_max
                        {
                            return false;
                        }
                        let mut units = 0u64;
                        for e in entries {
                            if e.slot() >= limits.slot_count {
                                return false;
                            }
                            for &bits in &e.extents {
                                let x = ExtentLocator::from_bits(bits);
                                if x.start_unit() < limits.payload_start
                                    || x.start_unit() + u64::from(x.len_units())
                                        > limits.payload_end
                                {
                                    return false;
                                }
                                let Some(total) = units.checked_add(u64::from(x.len_units()))
                                else {
                                    return false;
                                };
                                units = total;
                            }
                        }
                        if units > limits.payload_end - limits.payload_start - limits.reserve_units
                        {
                            return false;
                        }
                        checks += 1;
                    }
                }
                checks != 0
            }
        }
    }
}
