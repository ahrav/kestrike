//! Exact geometry and object boundary probes over the churn's parameterized
//! storage.
//!
//! Each probe drives the storage through a fixed script and compares every
//! observation with an expectation this module computes by its own
//! arithmetic: a best-fit free-run model with the clean reserve for unit
//! placement, a slot count for admission, and the record header rule
//! `108 + 4 * (ceil(payload / chunk_len) + 1)` bytes, then whole 4,096-byte
//! units, for layouts. The unit probes run at 63, 64, 65, 127, 128 and 129
//! units and observe an empty volume, extents that cross a 64-unit word,
//! an extent that fits the volume's final unit and a full volume whose next
//! claim the clean reserve refuses. The unit, slot and layout probes also
//! run controls: model variants that change one boundary by one unit or
//! slot, or the placement order, each of which must disagree with the
//! storage somewhere in the script.

use super::churn_tests::{BODY_CAP, Geometry, METADATA_CAP, churn_storage};
use super::layout::{IO_UNIT, LayoutError};
use super::owner::Storage;
use super::record::RecordConfig;
use super::reserve::ReserveError;
use super::test_platform::TestPlatform;
use super::{ExtentReservation, WorkBudget};

/// Unit counts on either side of the first and second 64-unit word ends.
const UNITS: [usize; 6] = [63, 64, 65, 127, 128, 129];

/// A one-unit clean reserve: the smallest the configuration admits, so the
/// final unit is reachable once units below it return.
const RESERVE: u64 = 1;

fn budget() -> WorkBudget {
    WorkBudget::new(1 << 16)
}

/// The free runs the extent bitmap holds, as `(start, len)` in unit order.
pub(super) fn free_runs(storage: &Storage<TestPlatform>) -> Vec<(u64, u64)> {
    let live = storage.live_pool().expect("a live pool");
    let mut access = live.lock().expect("the pool gate");
    access.tables().extents().free_set()
}

/// How a probe's claim ended: the extent it took, or the refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Claimed {
    Extent(u64, u64),
    CleanReserve,
    SlotsFull,
    PayloadFull,
}

/// One step of a unit probe: claim a record charging this many units, or
/// cancel the claim the earlier step at this index made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Claim(u64),
    Cancel(usize),
}

/// What one step left: its claim's result, if it claimed, and the free runs.
type Observation = (Option<Claimed>, Vec<(u64, u64)>);

/// The rule a placement model follows. `Exact` is the expectation; every
/// other rule is a control that changes one boundary by one unit or slot, or
/// the placement order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    Exact,
    /// A claim needs strictly more free units than its charge plus the
    /// reserve.
    StrictReserve,
    /// A claim ignores the clean reserve.
    NoReserve,
    /// A claim takes the lowest fitting run instead of the smallest.
    FirstFit,
    /// The volume's final unit is missing.
    LostFinalUnit,
    /// The slot table holds one slot fewer.
    SlotShort,
    /// The slot table holds one slot more.
    SlotExtra,
}

/// A best-fit allocator over `units` with the clean reserve and a slot
/// limit, independent of the storage's allocator.
struct Model {
    rule: Rule,
    free: Vec<(u64, u64)>,
    slots: usize,
    held: Vec<Option<(u64, u64)>>,
}

impl Model {
    fn new(rule: Rule, units: u64, slots: usize) -> Self {
        let units = units - u64::from(rule == Rule::LostFinalUnit);
        let slots = match rule {
            Rule::SlotShort => slots - 1,
            Rule::SlotExtra => slots + 1,
            _ => slots,
        };
        Self {
            rule,
            free: vec![(0, units)],
            slots,
            held: Vec::new(),
        }
    }

    fn claim(&mut self, units: u64) -> Claimed {
        let live = self.held.iter().flatten().count();
        if live == self.slots {
            return Claimed::SlotsFull;
        }
        let total: u64 = self.free.iter().map(|&(_, len)| len).sum();
        let admitted = match self.rule {
            Rule::StrictReserve => units + RESERVE < total,
            Rule::NoReserve => units <= total,
            _ => units + RESERVE <= total,
        };
        if !admitted {
            return Claimed::CleanReserve;
        }
        let fits = self
            .free
            .iter()
            .enumerate()
            .filter(|(_, run)| run.1 >= units);
        let chosen = if self.rule == Rule::FirstFit {
            fits.min_by_key(|(_, run)| run.0)
        } else {
            fits.min_by_key(|(_, run)| (run.1, run.0))
        };
        let Some((at, &(start, len))) = chosen else {
            return Claimed::PayloadFull;
        };
        if len == units {
            self.free.remove(at);
        } else {
            self.free[at] = (start + units, len - units);
        }
        Claimed::Extent(start, units)
    }

    /// Frees the extent step `index` claimed and merges the free runs; a
    /// claim the model refused frees nothing.
    fn cancel(&mut self, index: usize) {
        let Some((start, len)) = self.held[index].take() else {
            return;
        };
        self.free.push((start, len));
        self.free.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (start, len) in self.free.drain(..) {
            match merged.last_mut() {
                Some(last) if last.0 + last.1 == start => last.1 += len,
                _ => merged.push((start, len)),
            }
        }
        self.free = merged;
    }

    fn run(rule: Rule, units: u64, slots: usize, script: &[Step]) -> Vec<Observation> {
        let mut model = Self::new(rule, units, slots);
        script
            .iter()
            .map(|step| {
                let claimed = match *step {
                    Step::Claim(units) => Some(model.claim(units)),
                    Step::Cancel(index) => {
                        model.cancel(index);
                        None
                    }
                };
                model.held.push(match claimed {
                    Some(Claimed::Extent(start, len)) => Some((start, len)),
                    _ => None,
                });
                (claimed, model.free.clone())
            })
            .collect()
    }
}

/// A geometry of `units` units and `slots` slots with 16-KiB chunks and the
/// one-unit reserve.
fn geometry(units: usize, slots: usize) -> Geometry {
    Geometry {
        units,
        metadata_units: 1,
        slots,
        chunk_len: 16384,
        reserve: RESERVE,
    }
}

/// Bytes a sized record leaves for its header, so the record keeps its
/// requested unit charge.
const HEADER_SLACK: usize = 300;

/// Metadata and body lengths of a record that charges exactly `units` units
/// under `geometry`, checked by the header arithmetic.
fn sized(geometry: Geometry, units: u64) -> (usize, usize) {
    let (metadata, body) = if units == geometry.largest() {
        (METADATA_CAP, BODY_CAP)
    } else {
        (0, units as usize * IO_UNIT - HEADER_SLACK)
    };
    assert_eq!(geometry.charged_units(metadata + body) as u64, units);
    (metadata, body)
}

/// Runs `script` on a fresh storage of `geometry`, observing each claim's
/// extent or refusal and the free runs after each step.
fn observe(geometry: Geometry, script: &[Step]) -> Vec<Observation> {
    let storage = churn_storage(geometry, false);
    let mut held: Vec<Option<ExtentReservation<'_, TestPlatform>>> = Vec::new();
    script
        .iter()
        .map(|step| {
            let (claimed, reservation) = match *step {
                Step::Claim(units) => {
                    let (metadata, body) = sized(geometry, units);
                    let result = storage.reserve(Some(metadata), Some(body), &mut budget());
                    let claimed = match &result {
                        Ok(reservation) => {
                            let locator = reservation.locator();
                            let len = u64::from(locator.len_units());
                            assert_eq!(len, units, "the extent charges its record's units");
                            Claimed::Extent(locator.start_unit(), len)
                        }
                        Err(ReserveError::CleanReserve) => Claimed::CleanReserve,
                        Err(ReserveError::ObjectSlotsFull) => Claimed::SlotsFull,
                        Err(ReserveError::PayloadFull) => Claimed::PayloadFull,
                        Err(error) => panic!("claim of {units} units: {error:?}"),
                    };
                    (Some(claimed), result.ok())
                }
                Step::Cancel(index) => {
                    held[index]
                        .take()
                        .expect("a held claim")
                        .cancel()
                        .expect("an unwritten claim rolls back");
                    (None, None)
                }
            };
            held.push(reservation);
            (claimed, free_runs(storage))
        })
        .collect()
}

/// The unit script for a `units`-unit volume: a three-unit claim at the
/// start, records of at most the largest size filling the units up to the
/// last two, the first claim's return, a two-unit claim that best fit
/// places on the final two units, a two-unit claim that leaves only the
/// reserve, a one-unit claim the reserve refuses, then every return.
fn unit_script(geometry: Geometry) -> Vec<Step> {
    let units = geometry.units as u64;
    let largest = geometry.largest();
    let mut script = vec![Step::Claim(3)];
    let mut left = units - 5;
    while left > 0 {
        let take = left.min(largest);
        script.push(Step::Claim(take));
        left -= take;
    }
    script.push(Step::Cancel(0));
    script.extend([Step::Claim(2), Step::Claim(2)]);
    let held: Vec<usize> = (1..script.len())
        .filter(|&at| matches!(script[at], Step::Claim(_)))
        .collect();
    script.push(Step::Claim(1));
    script.extend(held.into_iter().map(Step::Cancel));
    script
}

/// At every unit count, the storage places, refuses and returns exactly as
/// the best-fit model with the clean reserve predicts: the empty volume is
/// one free run, an extent crosses each 64-unit word end inside the volume,
/// the final two units take a best-fit claim, a claim that would spend the
/// reserve is refused with the reserve free, and every return merges back
/// to one run. Each control model disagrees.
#[test]
fn unit_boundaries_place_cross_and_fill_to_the_final_unit_exactly() {
    let controls = [
        Rule::StrictReserve,
        Rule::NoReserve,
        Rule::FirstFit,
        Rule::LostFinalUnit,
    ];
    for units in UNITS {
        let geometry = geometry(units, 33);
        let script = unit_script(geometry);
        let observed = observe(geometry, &script);
        let total = units as u64;
        assert_eq!(
            Model::run(Rule::Exact, total, 33, &script),
            observed,
            "{units} units"
        );
        let extents: Vec<(u64, u64)> = observed
            .iter()
            .filter_map(|(claimed, _)| match claimed {
                Some(Claimed::Extent(start, len)) => Some((*start, *len)),
                _ => None,
            })
            .collect();
        for word_end in (64..total).step_by(64) {
            assert!(
                extents
                    .iter()
                    .any(|&(start, len)| start < word_end && word_end < start + len),
                "{units} units: no extent crosses unit {word_end}"
            );
        }
        assert!(
            extents.contains(&(total - 2, 2)),
            "{units} units: final fit"
        );
        let full = observed
            .iter()
            .find(|(claimed, _)| *claimed == Some(Claimed::CleanReserve))
            .expect("a refused claim");
        assert_eq!(full.1, [(2, RESERVE)], "{units} units: full");
        assert_eq!(observed.last().map(|o| &o.1[..]), Some(&[(0, total)][..]));
        for rule in controls {
            assert_ne!(
                Model::run(rule, total, 33, &script),
                observed,
                "{units} units: control {rule:?} passed"
            );
        }
    }
}

/// With `N` slots, `N - 1` and `N` one-unit claims are admitted and claim
/// `N + 1` is refused for slots; a model one slot short or long disagrees.
#[test]
fn slot_boundaries_admit_n_and_refuse_n_plus_one() {
    for slots in [4, 16, 33] {
        let geometry = geometry(64, slots);
        let script = vec![Step::Claim(1); slots + 1];
        let observed = observe(geometry, &script);
        assert_eq!(Model::run(Rule::Exact, 64, slots, &script), observed);
        assert!(matches!(observed[slots - 1].0, Some(Claimed::Extent(..))));
        assert_eq!(observed[slots].0, Some(Claimed::SlotsFull));
        for rule in [Rule::SlotShort, Rule::SlotExtra] {
            assert_ne!(Model::run(rule, 64, slots, &script), observed, "{rule:?}");
        }
    }
}

/// A record layout as independent arithmetic gives it: header bytes,
/// charged units and the chunk windows its payload overlaps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Expected {
    header: u64,
    units: u64,
    chunks: u64,
}

/// The arithmetic a layout control follows. `Exact` is the expectation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arithmetic {
    Exact,
    /// The chunk table drops its extra entry.
    NoExtraEntry,
    /// The chunk count rounds down.
    FloorChunks,
    /// The record rounds down to whole units.
    FloorUnits,
    /// The chunk windows ignore the header's offset.
    UnshiftedWindows,
}

fn expected(arithmetic: Arithmetic, payload: u64, chunk: u64) -> Expected {
    let chunks_in = match arithmetic {
        Arithmetic::FloorChunks => payload / chunk,
        _ => payload.div_ceil(chunk),
    };
    let extra = u64::from(arithmetic != Arithmetic::NoExtraEntry);
    let header = 108 + 4 * (chunks_in + extra);
    let record = header + payload;
    let units = match arithmetic {
        Arithmetic::FloorUnits => record / IO_UNIT as u64,
        _ => record.div_ceil(IO_UNIT as u64),
    };
    let start = if arithmetic == Arithmetic::UnshiftedWindows {
        0
    } else {
        header
    };
    let chunks = if payload == 0 {
        0
    } else {
        (start + payload - 1) / chunk - start / chunk + 1
    };
    Expected {
        header,
        units,
        chunks,
    }
}

/// The payload lengths whose record ends one byte before, at and one byte
/// after `target` bytes under `chunk`-byte windows.
fn ending_near(target: u64, chunk: u64) -> Vec<u64> {
    let exact = (0..=target)
        .find(|&payload| expected(Arithmetic::Exact, payload, chunk).header + payload >= target)
        .expect("a payload reaching the target");
    [exact.saturating_sub(1), exact, exact + 1].to_vec()
}

/// Every named object boundary lays out as the header arithmetic says:
/// zero payload, one byte, records ending around the first unit and around
/// the first and second window ends, a payload of exactly one window and
/// the largest record. Each control arithmetic disagrees with the layout
/// at one of them.
#[test]
fn record_layouts_match_the_header_arithmetic_at_every_named_boundary() {
    let controls = [
        Arithmetic::NoExtraEntry,
        Arithmetic::FloorChunks,
        Arithmetic::FloorUnits,
        Arithmetic::UnshiftedWindows,
    ];
    for chunk in [4096, 8192, 16384] {
        let config = RecordConfig {
            chunk_len: chunk as u32,
        }
        .validate()
        .expect("a valid chunk length");
        let mut payloads = vec![0, 1, chunk, (METADATA_CAP + BODY_CAP) as u64];
        for target in [IO_UNIT as u64, chunk, 2 * chunk] {
            payloads.extend(ending_near(target, chunk));
        }
        let layout = |payload: u64| {
            let layout = config.layout(0, payload as u32);
            Expected {
                header: layout.header_bytes() as u64,
                units: layout.record_units(),
                chunks: u64::from(layout.chunk_count()),
            }
        };
        for &payload in &payloads {
            assert_eq!(
                layout(payload),
                expected(Arithmetic::Exact, payload, chunk),
                "chunk {chunk}, payload {payload}"
            );
        }
        for control in controls {
            assert!(
                payloads
                    .iter()
                    .any(|&payload| layout(payload) != expected(control, payload, chunk)),
                "chunk {chunk}: control {control:?} passed"
            );
        }
    }
}

/// A zero-length record charges one unit; the largest admitted record
/// charges the geometry's largest units; one byte past either cap, or an
/// unknown length, is refused by layout and leaves the free runs, the slots
/// and the reservations unchanged.
#[test]
fn zero_maximum_and_over_limit_reservations_follow_the_caps_exactly() {
    let geometry = geometry(64, 16);
    let storage = churn_storage(geometry, false);
    let before = free_runs(storage);
    let report = storage.domain_report().expect("a report");
    for (metadata, body, error) in [
        (
            Some(METADATA_CAP),
            Some(BODY_CAP + 1),
            LayoutError::BodyTooLarge {
                len: BODY_CAP + 1,
                cap: BODY_CAP,
            },
        ),
        (
            Some(METADATA_CAP + 1),
            Some(0),
            LayoutError::MetadataTooLarge {
                len: METADATA_CAP + 1,
                cap: METADATA_CAP,
            },
        ),
        (
            Some(0),
            Some(usize::MAX),
            LayoutError::BodyTooLarge {
                len: usize::MAX,
                cap: BODY_CAP,
            },
        ),
        (
            Some(usize::MAX),
            Some(usize::MAX),
            LayoutError::MetadataTooLarge {
                len: usize::MAX,
                cap: METADATA_CAP,
            },
        ),
        (None, Some(0), LayoutError::UnknownLength),
        (Some(0), None, LayoutError::UnknownLength),
    ] {
        let allocations = crate::instrument::allocations();
        assert_eq!(
            storage.reserve(metadata, body, &mut budget()).err(),
            Some(ReserveError::Layout(error))
        );
        assert_eq!(crate::instrument::allocations(), allocations);
        assert_eq!(free_runs(storage), before);
        assert_eq!(storage.domain_report().expect("a report"), report);
        assert_eq!(report.free_units, 64);
    }
    let empty = storage
        .reserve(Some(0), Some(0), &mut budget())
        .expect("an empty record");
    assert_eq!(empty.locator().len_units(), 1);
    assert_eq!(geometry.charged_units(0), 1);
    let largest = storage
        .reserve(Some(METADATA_CAP), Some(BODY_CAP), &mut budget())
        .expect("the largest record");
    assert_eq!(u64::from(largest.locator().len_units()), geometry.largest());
    let held = 1 + geometry.largest();
    assert_eq!(free_runs(storage), [(held, 64 - held)]);
}
