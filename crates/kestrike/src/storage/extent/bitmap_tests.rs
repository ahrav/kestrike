//! The bitmap's summary recomputation and its first-fit descent, each against a model read one unit or one free run at a time.
//!
//! Through histories of reservations and returns, each summary node equals a unit-by-unit reading of the free units below it, with units past the volume taken. The histories take the longest free run of a volume's first chunk, so the chunk recomputes from its bitmap words, on volumes whose first chunk has fewer than eight words, exactly eight, and a short last word.
//!
//! First fit names the first unit of the lowest run of `n` free units, descending from a root whose longest run the caller found at least `n`. Its volumes hold `2^24 + 512` payload units, so the root has two children of `2^24` units each and the descent starts on a wide summary level.

use super::super::budget::WorkBudget;
use super::allocator_tests::Tables;
use super::bitmap::{levels, span};
use super::index::index_nodes;
use super::summary::Summary;
use super::{
    ExtentAllocator, ExtentLocator, ExtentRefusal, ExtentRoot, HeldPhase, RunNode, index_capacity,
    space_words,
};

/// The free flag of each unit of a volume, kept by the test from the extents the allocator returned.
struct Units(Vec<bool>);

impl Units {
    /// The summary of units `n0..n1` read one unit at a time; a unit past the volume is taken.
    fn summary(&self, n0: u64, n1: u64) -> Summary {
        let free = |unit: u64| self.0.get(unit as usize).copied().unwrap_or(false);
        let (mut max, mut run) = (0, 0);
        for unit in n0..n1 {
            run = if free(unit) { run + 1 } else { 0 };
            max = max.max(run);
        }
        Summary {
            start: (n0..n1).take_while(|&unit| free(unit)).count() as u64,
            max,
            end: run,
        }
    }

    fn mark(&mut self, extent: ExtentLocator, free: bool) {
        let start = extent.start_unit() as usize;
        self.0[start..start + extent.len_units() as usize].fill(free);
    }
}

/// Every summary node of `allocator` holds the unit reading of its span.
fn summaries_equal_the_unit_reading(allocator: &ExtentAllocator<'_>, units: &Units, step: &str) {
    for level in 0..allocator.levels() {
        for node in 0..allocator.nodes(level) {
            let n0 = node * span(level);
            assert_eq!(
                allocator.decode(level, node),
                units.summary(n0, n0 + span(level)),
                "node {node} of level {level} of a {}-unit volume after {step}",
                units.0.len()
            );
        }
    }
}

fn reserve(allocator: &mut ExtentAllocator<'_>, units: &mut Units, len: u32) -> ExtentLocator {
    let limit = allocator.bound_for(u64::from(len));
    let extent = allocator
        .reserve(len, 0, limit, &mut WorkBudget::new(limit))
        .expect("the volume holds a free run of the length");
    units.mark(extent, false);
    extent
}

fn release(allocator: &mut ExtentAllocator<'_>, units: &mut Units, extent: ExtentLocator) {
    allocator
        .release(extent, HeldPhase::Reserved, 0)
        .expect("the extent is held");
    units.mark(extent, true);
}

/// Fills a volume of `volume` units, frees two interior runs of seven units in its first chunk, takes three units of the lower run, the whole of the upper run and the rest of the lower, then returns the upper run, reading every summary against the units after each step.
///
/// Each take removes units from the chunk's longest run, which leaves the chunk's summary to its bitmap words; the last leaves every unit taken.
fn tied_runs_taken_one_after_the_other(volume: u64) {
    let mut tables = Tables::new(volume, 16);
    let mut allocator = tables.init();
    let mut units = Units(vec![true; volume as usize]);
    summaries_equal_the_unit_reading(&allocator, &units, "initialization");

    let lens = [10, 7, 10, 7, volume as u32 - 34];
    let held = lens.map(|len| reserve(&mut allocator, &mut units, len));
    assert_eq!(
        held.map(|extent| extent.start_unit()),
        [0, 10, 17, 27, 34],
        "the fill places its extents in address order"
    );
    summaries_equal_the_unit_reading(&allocator, &units, "the fill");

    release(&mut allocator, &mut units, held[1]);
    release(&mut allocator, &mut units, held[3]);
    summaries_equal_the_unit_reading(&allocator, &units, "two runs of seven units went free");

    let part = reserve(&mut allocator, &mut units, 3);
    assert_eq!(part.start_unit(), 10, "the take splits the lower tied run");
    summaries_equal_the_unit_reading(&allocator, &units, "three units left one tied run");

    let other = reserve(&mut allocator, &mut units, 7);
    assert_eq!(other.start_unit(), 27, "the take is the whole longest run");
    summaries_equal_the_unit_reading(&allocator, &units, "the longest run was taken whole");

    let rest = reserve(&mut allocator, &mut units, 4);
    assert_eq!(rest.start_unit(), 13, "the take is the last free run");
    assert!(units.0.iter().all(|&free| !free));
    summaries_equal_the_unit_reading(&allocator, &units, "the last free run was taken");

    release(&mut allocator, &mut units, other);
    summaries_equal_the_unit_reading(&allocator, &units, "a run went free again");
}

/// A 400-unit volume's only chunk has seven bitmap words, so its summary comes from those seven words alone: every summary equals the unit reading through the history.
#[test]
fn a_short_first_chunk_is_summarized_from_its_own_words() {
    tied_runs_taken_one_after_the_other(400);
}

/// The same holds on volumes whose first chunk holds six words, seven with the last one full, eight with a one-unit last word, and eight full words.
#[test]
fn a_first_chunk_at_each_word_boundary_is_summarized_from_its_own_words() {
    for volume in [384, 448, 449, 512] {
        tied_runs_taken_one_after_the_other(volume);
    }
}

/// The units under one child of the root: the span of the lowest wide level.
const WIDE: u64 = 1 << 24;
/// The payload units of every volume here: one whole wide child and one chunk of a second.
const UNITS: u64 = WIDE + 512;
const METADATA_UNITS: u64 = 3;
const CHARGE: u64 = 63;
const N: u64 = 4;

/// The tables of one volume of [`UNITS`] units.
struct WideTables {
    capacity: usize,
    root: ExtentRoot,
    space: Vec<u64>,
    nodes: Vec<RunNode>,
}

impl WideTables {
    fn new(slots: usize) -> Self {
        let capacity = index_capacity(slots);
        Self {
            capacity,
            root: ExtentRoot::default(),
            space: vec![u64::MAX; space_words(UNITS)],
            nodes: vec![RunNode::default(); index_nodes(capacity)],
        }
    }

    /// An allocator whose free units are exactly `free`, maximal runs as `(start, len)` in address order.
    fn restored(&mut self, free: &[(u64, u64)]) -> ExtentAllocator<'_> {
        let mut held = Vec::new();
        let mut low = 0;
        for &(start, len) in free {
            if start > low {
                held.push((low, start));
            }
            low = start + len;
        }
        if low < UNITS {
            held.push((low, UNITS));
        }
        let units_held = UNITS - free.iter().map(|&(_, len)| len).sum::<u64>();
        let allocator = ExtentAllocator::restored_runs(
            (UNITS, METADATA_UNITS, self.capacity, CHARGE),
            (&mut self.root, &mut self.space, &mut self.nodes),
            held.into_iter(),
            (units_held as usize, 0),
        )
        .expect("valid held ranges");
        assert_eq!(allocator.levels(), 7, "the volume has seven summary levels");
        assert_eq!(span(allocator.levels() - 2), WIDE);
        assert_eq!(allocator.nodes(allocator.levels() - 2), 2);
        allocator
    }
}

/// The free-unit model: the first unit of the lowest run of `n` free units among the maximal runs `free`, read from
/// the list alone.
fn lowest_fit(free: &[(u64, u64)], n: u64) -> Option<u64> {
    free.iter()
        .find(|&&(_, len)| len >= n)
        .map(|&(start, _)| start)
}

/// Restores a volume whose free runs are `free`, checks the bitmap and every summary against the list, validates
/// the root's longest run against the model, and returns what `first_fit(N)` names.
fn first_fit_over(free: &[(u64, u64)]) -> Option<u64> {
    let mut tables = WideTables::new(1024);
    let mut allocator = tables.restored(free);
    assert_eq!(
        allocator.free_set(),
        free,
        "the bitmap holds the model's runs"
    );
    allocator.summaries_check(free);
    let longest = free.iter().map(|&(_, len)| len).max().unwrap_or(0);
    assert_eq!(allocator.longest_run(), longest);
    assert!(longest >= N, "the caller found a root run of at least n");
    allocator.first_fit(N)
}

/// A volume of [`UNITS`] units has seven summary levels, so the level below its root is a wide one and the root's first-fit scan reads two wide children.
#[test]
fn the_volume_has_seven_summary_levels() {
    assert_eq!(levels(UNITS), 7);
}

/// The sole free run lies across the boundary of the root's two wide children: two units end the first child and two
/// start the second. First fit names the run's first unit, which the model gives, and not the second child's first
/// unit.
#[test]
fn a_run_across_a_wide_child_boundary_fits_at_its_first_unit() {
    let free = [(WIDE - 2, N)];
    let found = first_fit_over(&free);
    assert_eq!(
        found,
        lowest_fit(&free, N),
        "first fit names the first unit of the lowest run of n free units"
    );
    assert_eq!(found, Some(WIDE - 2));
}

/// Siblings of the boundary run: a sole fitting run inside the first wide child, a sole fitting run inside the second,
/// a boundary run too short to fit before a fitting run inside the later child, a fitting run inside the first child
/// before the boundary run, a boundary run that begins deeper in the first child, and a boundary run of five units
/// between a run too short to fit and a longer run. Each agrees with the model.
#[test]
fn inside_child_and_later_child_fits_agree_with_the_free_unit_model() {
    let cases: [&[(u64, u64)]; 6] = [
        &[(WIDE / 2 + 7, N)],
        &[(WIDE + 100, N)],
        &[(WIDE - 1, 2), (WIDE + 200, N)],
        &[(4096 + 61, N + 2), (WIDE - 2, N)],
        &[(WIDE - 3, N)],
        &[(5, 3), (WIDE - 1, N + 1), (WIDE + 300, 9)],
    ];
    for free in cases {
        let found = first_fit_over(free);
        assert!(found.is_some(), "a root run of n units has a fit: {free:?}");
        assert_eq!(
            found,
            lowest_fit(free, N),
            "first fit names the first unit of the lowest run of n free units of {free:?}"
        );
    }
}

/// A reservation with no fitting indexed run falls back to first fit over the wide level. The index holds one entry,
/// so the returned four-unit run across the boundary is dropped beside the eight-unit tail; once the tail is cut to
/// three units, a four-unit request misses the index and takes the boundary run at its first unit, and a second
/// four-unit request is refused `NoFit`.
#[test]
fn a_reservation_no_indexed_run_fits_takes_the_boundary_run_at_its_first_unit() {
    let mut tables = WideTables::new(8);
    let mut allocator = tables.restored(&[(UNITS - 8, 8)]);
    assert_eq!(allocator.capacity(), 1);
    let boundary = ExtentLocator::new(WIDE - 2, N as u32).expect("inside the limits");
    allocator
        .release(boundary, HeldPhase::Reserved, 0)
        .expect("the restored volume holds the units");
    assert_eq!(allocator.drops(), 1, "the index keeps the tail alone");
    let reserve = |allocator: &mut ExtentAllocator<'_>, units: u32| {
        let limit = allocator.bound_for(u64::from(units));
        allocator.reserve(units, 0, limit, &mut WorkBudget::new(limit))
    };
    assert_eq!(
        reserve(&mut allocator, 5),
        Ok(ExtentLocator::new(UNITS - 8, 5).unwrap())
    );
    assert_eq!(allocator.indexed_runs(), [(UNITS - 3, 3)]);
    assert_eq!(allocator.free_set(), [(WIDE - 2, N), (UNITS - 3, 3)]);
    assert_eq!(
        reserve(&mut allocator, N as u32),
        Ok(boundary),
        "the fallback takes the first unit of the lowest run of n free units"
    );
    assert_eq!(allocator.free_set(), [(UNITS - 3, 3)]);
    assert_eq!(
        reserve(&mut allocator, N as u32),
        Err(ExtentRefusal::NoFit { units: N as u32 })
    );
}
