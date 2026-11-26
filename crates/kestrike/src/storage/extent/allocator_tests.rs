//! The allocator's calls against models it shares no code with.
//! Free sets, placements and ledgers come from `Units`, a vector of free flags with its own maximal-run and first-fit scans, and from the run index as `indexed_runs` reads it before each call; refusal rates come from `BestFit`, an exact best-fit allocator over ordered maps.

use std::collections::{BTreeMap, BTreeSet};

use super::super::budget::WorkBudget;
use super::super::device::IO_UNIT;
use super::super::ledger::LedgerOverflow;
use super::super::seeded::SplitMix64;
use super::allocator::{ExtentConfigError, ExtentStateError, bound};
use super::bitmap::{Change, levels, longest, pack_narrow, run_in, space_base, span};
use super::index::{SATURATED, index_nodes, run_key};
use super::summary::Summary;
use super::{
    ExtentAllocator, ExtentLocator, ExtentRefusal, ExtentRoot, HeldPhase, LOCATOR_LEN_LIMIT,
    LOCATOR_START_LIMIT, LocatorError, RawPartition, RunNode, index_capacity, space_words,
    work_bound,
};

const METADATA_UNITS: u64 = 3;
/// The full-extent charge every multi-extent geometry gives.
const CHARGE: u64 = 63;

pub(super) struct Tables {
    units: u64,
    capacity: usize,
    root: ExtentRoot,
    space: Vec<u64>,
    nodes: Vec<RunNode>,
}

impl Tables {
    /// Tables for `units` units and `slots` slots.
    pub(super) fn new(units: u64, slots: usize) -> Self {
        let capacity = index_capacity(slots);
        Self {
            units,
            capacity,
            root: ExtentRoot::default(),
            space: vec![u64::MAX; space_words(units)],
            nodes: vec![RunNode::default(); index_nodes(capacity)],
        }
    }

    pub(super) fn init(&mut self) -> ExtentAllocator<'_> {
        self.init_charged(CHARGE)
    }

    /// As [`init`](Self::init), with the full-extent charge `charge`.
    fn init_charged(&mut self, charge: u64) -> ExtentAllocator<'_> {
        ExtentAllocator::init(
            self.units,
            METADATA_UNITS,
            self.capacity,
            charge,
            &mut self.root,
            &mut self.space,
            &mut self.nodes,
        )
        .expect("valid tables")
    }

    fn view(&mut self) -> ExtentAllocator<'_> {
        ExtentAllocator::attach(&mut self.root, &mut self.space, &mut self.nodes)
    }
}

fn at(start: u64, len: u32) -> ExtentLocator {
    ExtentLocator::new(start, len).expect("inside the limits")
}

/// The work limit the storage passes for `units` units: the derived bound for that extent.
fn limit(allocator: &ExtentAllocator<'_>, units: u32) -> usize {
    allocator.bound_for(u64::from(units))
}

/// Reserves `units` units with the storage's limit and budget, and checks the debit equals the counted visits.
fn reserve(allocator: &mut ExtentAllocator<'_>, units: u32) -> ExtentLocator {
    let limit = limit(allocator, units);
    let mut budget = WorkBudget::new(limit);
    let locator = allocator
        .reserve(units, 0, limit, &mut budget)
        .expect("fits");
    assert_eq!(budget.counters().visits, allocator.work);
    locator
}

/// Returns `locator` and checks the call stayed within the derived bound for its extent.
fn release(allocator: &mut ExtentAllocator<'_>, locator: ExtentLocator) {
    allocator
        .release(locator, HeldPhase::Reserved, 0)
        .expect("held");
    assert!(allocator.work <= limit(allocator, locator.len_units()));
}

/// Everything a refusal must leave unchanged.
fn snapshot(allocator: &ExtentAllocator<'_>) -> (ExtentRoot, Vec<u64>, Vec<RunNode>) {
    (
        *allocator.root,
        allocator.space.to_vec(),
        allocator.nodes.to_vec(),
    )
}

#[test]
fn locator_round_trips_at_both_limits_and_refuses_past_them() {
    let (start, len) = (LOCATOR_START_LIMIT - 1, LOCATOR_LEN_LIMIT - 1);
    let edge = at(start, len);
    assert_eq!((edge.start_unit(), edge.len_units()), (start, len));
    assert_eq!(ExtentLocator::from_bits(edge.bits()), edge);
    // Every bit but the tail's, which a new locator leaves zero.
    assert_eq!(edge.bits(), !(0b111 << 37));
    let ended = edge.ending_at((u64::from(len) - 1) * IO_UNIT as u64 + 1);
    assert_eq!(ended.bits(), !(0b110 << 37), "a one-sector tail");
    assert_eq!((ended.start_unit(), ended.len_units()), (start, len));
    let zero = at(0, 0);
    assert_eq!(
        (zero.start_unit(), zero.len_units(), zero.bits()),
        (0, 0, 0)
    );
    assert_eq!(
        ExtentLocator::new(1 << 37, 1),
        Err(LocatorError::Start {
            start_unit: 1 << 37
        })
    );
    assert_eq!(
        ExtentLocator::new(0, 1 << 24),
        Err(LocatorError::Len { len_units: 1 << 24 })
    );
    let mut rng = SplitMix64::new(7);
    for _ in 0..1000 {
        let (start, len) = (rng.below(1 << 37), rng.below(1 << 24) as u32);
        let locator = at(start, len);
        assert_eq!((locator.start_unit(), locator.len_units()), (start, len));
    }
}

/// A record end in the extent's last unit rounds up to its 512-byte sector, a record that fills the last unit reads the whole extent, and an end outside the last unit leaves the extent's whole length; the start and length never change.
#[test]
fn a_locator_ends_at_its_record_s_last_sector() {
    const UNIT: u64 = IO_UNIT as u64;
    let base = at(9, 3);
    assert_eq!(
        base.record_end(),
        3 * UNIT,
        "a new locator reads its whole extent"
    );
    for (record_len, end) in [
        (2 * UNIT + 1, 2 * UNIT + 512),
        (2 * UNIT + 512, 2 * UNIT + 512),
        (2 * UNIT + 513, 2 * UNIT + 1024),
        (3 * UNIT - 1, 3 * UNIT),
        (3 * UNIT, 3 * UNIT),
        (2 * UNIT, 3 * UNIT),
        (3 * UNIT + 1, 3 * UNIT),
    ] {
        let ended = base.ending_at(record_len);
        assert_eq!(ended.record_end(), end, "record of {record_len} bytes");
        assert_eq!((ended.start_unit(), ended.len_units()), (9, 3));
        assert_eq!(
            ended.ending_at(3 * UNIT).record_end(),
            3 * UNIT,
            "a later end replaces the tail"
        );
    }
}

#[test]
fn construction_refuses_each_invalid_size_with_its_own_error() {
    let mut tables = Tables::new(1000, 16);
    let Tables {
        root,
        space,
        nodes,
        capacity,
        ..
    } = &mut tables;
    let capacity = *capacity;
    assert_eq!(
        ExtentAllocator::init(0, METADATA_UNITS, capacity, CHARGE, root, space, nodes).err(),
        Some(ExtentConfigError::ZeroUnits)
    );
    assert_eq!(
        ExtentAllocator::init(1000, METADATA_UNITS, capacity, 0, root, space, nodes).err(),
        Some(ExtentConfigError::ZeroCharge)
    );
    assert_eq!(
        ExtentAllocator::init(
            LOCATOR_START_LIMIT + 1,
            METADATA_UNITS,
            capacity,
            CHARGE,
            root,
            space,
            nodes
        )
        .err(),
        Some(ExtentConfigError::VolumeTooLarge {
            payload_units: LOCATOR_START_LIMIT + 1
        })
    );
    let needed = space_words(1000);
    assert_eq!(
        ExtentAllocator::init(
            1000,
            METADATA_UNITS,
            capacity,
            CHARGE,
            root,
            &mut space[1..],
            nodes
        )
        .err(),
        Some(ExtentConfigError::SpaceLength {
            len: needed - 1,
            needed
        })
    );
    assert_eq!(
        ExtentAllocator::init(1000, METADATA_UNITS, 0, CHARGE, root, space, nodes).err(),
        Some(ExtentConfigError::IndexCapacity { capacity: 0 })
    );
    assert_eq!(
        ExtentAllocator::init(
            1000,
            METADATA_UNITS,
            capacity,
            CHARGE,
            root,
            space,
            &mut nodes[1..]
        )
        .err(),
        Some(ExtentConfigError::IndexLength {
            len: nodes.len() - 1,
            needed: nodes.len()
        })
    );
    tables.init().check(METADATA_UNITS);
}

/// Space words for the largest volume: `2^31` bitmap words, then level sizes `2^28`, `2^25` down to 1, whose levels 5 and above take two words a node.
#[test]
fn the_space_of_the_largest_volume_sums_its_bitmap_and_levels() {
    let narrow: u64 = (0..5).map(|level| 1u64 << (28 - 3 * level)).sum();
    let wide: u64 = (5..10).map(|level| 2u64 << (28 - 3 * level)).sum::<u64>() + 2;
    assert_eq!(
        space_words(LOCATOR_START_LIMIT) as u64,
        (1 << 31) + narrow + wide
    );
    assert_eq!(space_words(1), 2);
    assert_eq!(space_words(512), 9);
    assert_eq!(space_words(513), 9 + 2 + 1);
}

/// The closed-form level count agrees with the space layout's loop at every chunk count boundary: one chunk, a power of eight chunks, one more, and the largest volume.
#[test]
fn the_level_count_formula_agrees_with_the_space_layout() {
    let mut volumes = vec![
        1,
        2,
        63,
        64,
        65,
        511,
        512,
        513,
        1 << 20,
        100_000_000,
        LOCATOR_START_LIMIT,
    ];
    for power in 0..=10 {
        let chunks = 8u64.pow(power);
        volumes.extend([chunks * 512 - 1, chunks * 512, chunks * 512 + 1]);
    }
    for volume in volumes {
        let volume = volume.clamp(1, LOCATOR_START_LIMIT);
        assert_eq!(levels(volume), space_base(volume).1, "volume {volume}");
    }
}

/// A narrow node keeps its three 21-bit fields exactly, and a level-4 node spanning `2^21` units marks itself entirely free with its spare bit; a wide node keeps 42-bit fields, so a volume of exactly `2^40` units summarizes exactly at its root.
#[test]
fn summary_nodes_keep_every_field_exact_at_their_widths() {
    let mut root = ExtentRoot {
        levels: 12,
        ..ExtentRoot::default()
    };
    for (level, base) in root.base.iter_mut().enumerate() {
        *base = 2 * level as u64;
    }
    let mut space = vec![0; 24];
    let mut allocator = ExtentAllocator::attach(&mut root, &mut space, &mut []);
    let narrow = [
        (
            0,
            Summary {
                start: 511,
                max: 511,
                end: 0,
            },
        ),
        (
            0,
            Summary {
                start: 512,
                max: 512,
                end: 512,
            },
        ),
        (
            4,
            Summary {
                start: (1 << 21) - 1,
                max: (1 << 21) - 1,
                end: 0,
            },
        ),
        (
            4,
            Summary {
                start: 1 << 21,
                max: 1 << 21,
                end: 1 << 21,
            },
        ),
        (
            4,
            Summary {
                start: 3,
                max: (1 << 21) - 7,
                end: 4,
            },
        ),
    ];
    for (level, sum) in narrow {
        allocator.space[2 * level] = pack_narrow(sum, span(level));
        assert_eq!(allocator.decode(level, 0), sum, "level {level}");
    }
    let full = Summary {
        start: 1 << 21,
        max: 1 << 21,
        end: 1 << 21,
    };
    assert_eq!(
        pack_narrow(full, span(4)),
        1 << 63,
        "the spare bit alone marks the node free"
    );
    let wide = [
        (
            5,
            Summary {
                start: 1 << 24,
                max: 1 << 24,
                end: 1 << 24,
            },
        ),
        (
            10,
            Summary {
                start: 1 << 39,
                max: 1 << 39,
                end: 1 << 39,
            },
        ),
        (
            11,
            Summary {
                start: 1 << 40,
                max: 1 << 40,
                end: 1 << 40,
            },
        ),
        (
            11,
            Summary {
                start: (1 << 40) - 1,
                max: (1 << 40) - 1,
                end: 0,
            },
        ),
    ];
    for (level, sum) in wide {
        assert!(allocator.store(level, 0, sum), "level {level} changed");
        assert_eq!(allocator.decode(level, 0), sum, "level {level}");
        assert!(!allocator.store(level, 0, sum), "level {level} unchanged");
    }
}

#[test]
fn best_fit_takes_the_smallest_fitting_run_not_the_first() {
    let mut tables = Tables::new(12, 24);
    let mut allocator = tables.init();
    let first = reserve(&mut allocator, 3);
    reserve(&mut allocator, 7);
    let third = reserve(&mut allocator, 2);
    release(&mut allocator, first);
    release(&mut allocator, third);
    assert_eq!(allocator.free_set(), [(0, 3), (10, 2)]);
    assert_eq!(reserve(&mut allocator, 2), at(10, 2));
    assert_eq!(allocator.free_set(), [(0, 3)]);
    allocator.check(METADATA_UNITS);
}

#[test]
fn equal_lengths_pick_the_lowest_start() {
    let mut tables = Tables::new(9, 24);
    let mut allocator = tables.init();
    let held: Vec<ExtentLocator> = [2, 3, 2, 2]
        .into_iter()
        .map(|units| reserve(&mut allocator, units))
        .collect();
    release(&mut allocator, held[2]);
    release(&mut allocator, held[0]);
    assert_eq!(allocator.free_set(), [(0, 2), (5, 2)]);
    assert_eq!(reserve(&mut allocator, 1), at(0, 1));
    assert_eq!(allocator.free_set(), [(1, 1), (5, 2)]);
    assert_eq!(reserve(&mut allocator, 2), at(5, 2));
    allocator.check(METADATA_UNITS);
}

/// The 400-unit request passes the long-run tree's 300-unit run; the 250-unit request finds its exact tree empty and takes the long-run tree's smallest run.
#[test]
fn a_request_takes_the_smallest_fit_past_a_shorter_long_run_or_an_empty_exact_tree() {
    let mut tables = Tables::new(2000, 64);
    let mut allocator = tables.init();
    let held: Vec<ExtentLocator> = [300, 10, 600, 10]
        .into_iter()
        .map(|units| reserve(&mut allocator, units))
        .collect();
    release(&mut allocator, held[0]);
    release(&mut allocator, held[2]);
    assert_eq!(allocator.free_set(), [(0, 300), (310, 600), (920, 1080)]);
    assert_eq!(reserve(&mut allocator, 400), at(310, 400));
    assert_eq!(reserve(&mut allocator, 250), at(0, 250));
    assert_eq!(
        allocator.indexed_runs(),
        [(250, 50), (710, 200), (920, 1080)]
    );
    allocator.check(METADATA_UNITS);
}

#[test]
fn a_split_keeps_the_low_units_and_leaves_the_remainder_free() {
    let mut tables = Tables::new(10, 8);
    let mut allocator = tables.init();
    assert_eq!(reserve(&mut allocator, 4), at(0, 4));
    assert_eq!(allocator.free_set(), [(4, 6)]);
    assert_eq!(allocator.indexed_runs(), [(4, 6)]);
    assert_eq!(reserve(&mut allocator, 6), at(4, 6));
    assert_eq!(allocator.free_set(), []);
    allocator.check(METADATA_UNITS);
}

#[test]
fn a_return_between_two_free_runs_leaves_one_run() {
    let mut tables = Tables::new(9, 24);
    let mut allocator = tables.init();
    let held: Vec<ExtentLocator> = (0..3).map(|_| reserve(&mut allocator, 3)).collect();
    release(&mut allocator, held[0]);
    release(&mut allocator, held[2]);
    assert_eq!(allocator.indexed_runs(), [(0, 3), (6, 3)]);
    release(&mut allocator, held[1]);
    // The held check, the summary update and each run-end search read the one word;
    // the own-key descent and each neighbour's descent read the one leaf of the
    // three-unit tree, and the joined run starts the empty nine-unit tree.
    assert_eq!(allocator.work, 1 + 1 + 2 + 1 + 2);
    assert_eq!(allocator.free_set(), [(0, 9)]);
    assert_eq!(allocator.indexed_runs(), [(0, 9)]);
    allocator.check(METADATA_UNITS);
}

/// A return with no free neighbour inserts its run into the leaf its own-key descent read: the held check, the summary update and the two run-end searches read the one word, and the descent reads the two-unit tree's one leaf.
#[test]
fn a_return_counts_its_held_check_summary_update_run_ends_and_insertion_visits() {
    let mut tables = Tables::new(20, 24);
    let mut allocator = tables.init();
    let held: Vec<ExtentLocator> = (0..5).map(|_| reserve(&mut allocator, 2)).collect();
    // The two-unit tree starts with `(0, 2)`; `(10, 10)` holds the ten-unit tree.
    release(&mut allocator, held[0]);
    assert_eq!(allocator.indexed_runs(), [(0, 2), (10, 10)]);
    release(&mut allocator, held[2]);
    assert_eq!(allocator.work, 1 + 1 + 2 + 1);
    assert_eq!(allocator.indexed_runs(), [(0, 2), (4, 2), (10, 10)]);
    allocator.check(METADATA_UNITS);
}

/// A refresh whose chunks keep their summaries stops above them and still counts every read a full recomputation makes: each chunk's words, then each level's children under the covered nodes, fewer where the volume ends.
#[test]
fn a_refresh_that_changes_nothing_counts_the_reads_of_a_full_recomputation() {
    // Sixty chunks: the last holds seven bitmap words, level 1 holds eight nodes, the last with four children, and level 2 is the root.
    let mut tables = Tables::new(60 * 512 - 100, 8);
    let mut allocator = tables.init();
    let before = snapshot(&allocator);
    allocator.work = 0;
    allocator.refresh(57, 59);
    assert_eq!(allocator.work, (8 + 8 + 7) + 4 + 8);
    assert_eq!(snapshot(&allocator), before);
}

/// A one-chunk recomputation counts the chunk's words and each ancestor's children: eight per level away from the volume's end, fewer under the last node of a level, and the root's children.
#[test]
fn a_one_chunk_refresh_counts_its_words_and_each_ancestor_s_children() {
    // Sixty chunks: the last holds seven bitmap words, level 1 holds eight nodes, the last with four children, and level 2 is the root.
    let mut tables = Tables::new(60 * 512 - 100, 8);
    let mut allocator = tables.init();
    for (chunk, visits) in [
        (0, 8 + 8 + 8),
        (10, 8 + 8 + 8),
        (55, 8 + 8 + 8),
        (56, 8 + 4 + 8),
        (59, 7 + 4 + 8),
    ] {
        allocator.work = 0;
        allocator.refresh(chunk, chunk);
        assert_eq!(allocator.work, visits, "chunk {chunk}");
    }
    // Three chunks under the root alone.
    let mut tables = Tables::new(3 * 512, 8);
    let mut allocator = tables.init();
    allocator.work = 0;
    allocator.refresh(1, 1);
    assert_eq!(allocator.work, 8 + 3);
}

/// Every chunk's one-chunk refresh counts its bitmap words and each ancestor's children as the level-by-level count does, across volumes whose last chunk, last level-1 node or last level-2 node is short, and a volume of full groups.
#[test]
fn a_one_chunk_refresh_counts_match_the_level_by_level_count_at_every_chunk() {
    for units in [
        513,
        4097,
        60 * 512 - 100,
        64 * 512,
        65 * 512,
        100_000,
        (1 << 20) + 7,
        3 * 512 * 512 + 1,
    ] {
        let mut tables = Tables::new(units, 8);
        let mut allocator = tables.init();
        let nodes = |level: usize| units.div_ceil(512 << (3 * level));
        let words = units.div_ceil(64);
        let chunks = nodes(0);
        for chunk in 0..chunks {
            let mut expected = words.min(8 * (chunk + 1)) - 8 * chunk;
            for level in 1..levels(units) {
                let node = chunk >> (3 * level);
                expected += nodes(level - 1).min(8 * (node + 1)) - 8 * node;
            }
            allocator.work = 0;
            allocator.refresh(chunk, chunk);
            assert_eq!(
                allocator.work as u64, expected,
                "units {units} chunk {chunk}"
            );
        }
    }
}

/// A level-1 node whose eight chunks each hold a taken unit takes its longest run from one chunk or from one chunk boundary, the left chunk's end run plus the right chunk's start run; a node with an entirely free chunk folds the free chunk into the runs on both sides.
#[test]
fn a_merge_takes_the_longest_run_across_a_chunk_boundary_and_through_a_free_chunk() {
    let mut tables = Tables::new(16 * 512, 64);
    let mut allocator = tables.init();
    allocator.mark(0, 16 * 512, false);
    // A 100-unit run across the boundary of chunks 2 and 3, and a 60-unit run inside chunk 6.
    allocator.mark(1500, 100, true);
    allocator.mark(3200, 60, true);
    allocator.refresh(0, 15);
    assert_eq!(
        allocator.decode(1, 0),
        Summary {
            start: 0,
            max: 100,
            end: 0
        }
    );
    assert_eq!(allocator.decode(0, 2).end, 36);
    assert_eq!(allocator.decode(0, 3).start, 64);
    // Chunk 5 entirely free joins the runs on both sides: 10 units at the end of chunk 4, the chunk, and the 128 units at the start of chunk 6, which reach the 60-unit run.
    allocator.mark(2550, 512 + 10, true);
    allocator.mark(3072, 128, true);
    allocator.refresh(4, 6);
    assert_eq!(allocator.decode(1, 0).max, 10 + 512 + 128 + 60);
    assert_eq!(
        allocator.decode(0, 5),
        Summary {
            start: 512,
            max: 512,
            end: 512
        }
    );
}

/// Taking a node's longest run recomputes it over eight zero words, eight children with one entirely free child, a four-chunk last node and a seven-word last chunk.
#[test]
fn a_take_of_a_longest_run_recomputes_each_group_shape() {
    // Sixty chunks: the last holds seven bitmap words, and the last level-1 node holds four chunks.
    let units = 60 * 512 - 100;
    let mut tables = Tables::new(units, 8);
    let mut allocator = tables.init();
    allocator.mark(0, units, false);
    // Chunk 3 holds one run; chunks 1 and 5 lie entirely free inside runs of 514 and 513 units; chunks 56 to 59 sit under the short level-1 node, with 300 units across chunks 57 and 58 and 100 units in the short chunk 59.
    let runs = [
        (1700, 100),
        (511, 514),
        (2559, 513),
        (29000, 100),
        (29500, 300),
        (30300, 100),
    ];
    for (start, len) in runs {
        allocator.mark(start, len, true);
    }
    allocator.refresh(0, 59);
    allocator.summaries_check(&allocator.free_set());
    fn take(allocator: &mut ExtentAllocator<'_>, start: u64, len: u64) {
        allocator.mark(start, len, false);
        allocator.update(
            start,
            start + len,
            Change::Split {
                low: start,
                start,
                end: start + len,
                high: start + len,
            },
        );
        allocator.summaries_check(&allocator.free_set());
    }
    // Chunk 3's eight words are all zero after the take.
    take(&mut allocator, 1700, 100);
    assert_eq!(allocator.decode(0, 3), Summary::default());
    // Level-1 node 0 recomputes from its chunks, of which chunk 5 is entirely free.
    take(&mut allocator, 511, 514);
    assert_eq!(
        allocator.decode(1, 0),
        Summary {
            start: 0,
            max: 513,
            end: 0
        }
    );
    // The short level-1 node recomputes from its four chunks.
    take(&mut allocator, 29500, 300);
    assert_eq!(allocator.decode(1, 7).max, 100);
    // The short chunk recomputes from its seven words.
    take(&mut allocator, 30300, 100);
    assert_eq!(allocator.decode(0, 59), Summary::default());
    assert_eq!(allocator.decode(1, 7).max, 100);
}

/// Taking one of two longest runs preserves the chunk's longest-run length because the update recomputes the chunk from its words.
#[test]
fn a_take_of_one_of_two_longest_runs_keeps_the_other_in_the_summary() {
    let mut tables = Tables::new(64, 16);
    let mut allocator = tables.init();
    let held: Vec<ExtentLocator> = [10, 5, 10, 5, 34]
        .map(|units| reserve(&mut allocator, units))
        .to_vec();
    release(&mut allocator, held[1]);
    release(&mut allocator, held[3]);
    assert_eq!(allocator.free_set(), [(10, 5), (25, 5)]);
    assert_eq!(reserve(&mut allocator, 5), at(10, 5));
    assert_eq!(
        allocator.decode(0, 0),
        Summary {
            start: 0,
            max: 5,
            end: 0
        }
    );
    allocator.check(METADATA_UNITS);
}

/// The derived bound at the notes' recorded configurations, for records up to 82 units, and at a small volume where the return's term is the largest.
#[test]
fn the_work_bound_takes_its_recorded_values() {
    for (units, slots, bound) in [
        (100_000_000, 196_608, 311),
        (100_000_000, 655_360, 326),
        (1_000_000_000, 196_608, 341),
        (1_000_000_000, 655_360, 356),
        (10_000_000_000, 196_608, 401),
        (10_000_000_000, 655_360, 416),
        (4096, 64, 86),
    ] {
        assert_eq!(
            work_bound(units, slots, 82),
            bound,
            "{units} units, {slots} slots"
        );
    }
}

/// The bound from the documented terms, with `h` the most inner levels `h` for which a tree's `2 * 5^(h - 1)` leaves of eight keys fit in `entries`.
fn documented_bound(payload_units: u64, entries: usize, record_units: u64) -> usize {
    let depth = levels(payload_units) as u64 - 1;
    let words = payload_units.div_ceil(64).min(8);
    let chunks = (record_units / 512 + 2).min(payload_units.div_ceil(512));
    let height = (1..)
        .take_while(|&levels| 16 * 5u64.pow(levels - 1) <= entries as u64)
        .count() as u64;
    let lookup = 3 * height + 1;
    let descent = height + 1;
    let remove = 3 * height;
    let insert = descent + 2 * height + 3;
    let offer = 1 + remove + insert;
    let run_end = words + 7 * depth;
    let update = chunks * (words + 8 * depth);
    let take = 1 + lookup + run_end + remove + update + insert;
    let fallback = 1 + lookup + (8 * depth + words) + run_end + update + offer;
    let give = chunks * words + update + 2 * run_end + descent + 2 * (descent + remove) + offer;
    take.max(fallback).max(give) as usize
}

/// The cases cover chunk-count transitions at 512 and 1,024 record units, volume chunk caps, and index heights 0, 1, 3 and 6.
#[test]
fn the_work_terms_give_the_documented_bound() {
    for payload_units in [1, 64, 65, 511, 512, 513, 1536, 4096, 100_000_000, 1 << 40] {
        for entries in [1, 15, 16, 1000, 81_920] {
            for record_units in [1, 82, 511, 512, 513, 1023, 1024, 1100, 4095, (1 << 24) - 1] {
                assert_eq!(
                    bound(payload_units, entries, record_units),
                    documented_bound(payload_units, entries, record_units),
                    "{payload_units} units, {entries} entries, {record_units} record units"
                );
            }
        }
    }
}

/// A return across a chunk boundary that joins two indexed neighbours reaching into the chunks on either side, with the index full, stays within the literal bound for its volume.
#[test]
fn an_adversarial_return_stays_within_its_literal_bound() {
    let mut tables = Tables::new(4096, 64);
    let mut allocator = tables.init();
    let [_, left, across, right] = [100, 400, 30, 570].map(|units| reserve(&mut allocator, units));
    assert_eq!(across, at(500, 30));
    let singles: Vec<ExtentLocator> = (0..20).map(|_| reserve(&mut allocator, 1)).collect();
    for &single in singles.iter().step_by(2) {
        release(&mut allocator, single);
    }
    release(&mut allocator, left);
    release(&mut allocator, right);
    assert_eq!(allocator.capacity(), 8);
    assert_eq!(allocator.indexed_runs().len(), 8, "the index is full");
    assert!(allocator.drops() > 0);
    release(&mut allocator, across);
    assert!(allocator.work <= 192, "{}", allocator.work);
    // The first single joined the right neighbour.
    assert!(allocator.indexed_runs().contains(&(100, 1001)));
    allocator.check(METADATA_UNITS);
}

/// `run_in` and `longest` agree with a bit-by-bit scan on edge words and lengths.
#[test]
fn in_word_run_searches_agree_with_a_bit_scan() {
    let naive_run = |x: u64, n: u64| {
        (0..=64 - n.min(64)).find(|&i| n <= 64 && (i..i + n).all(|bit| x >> bit & 1 == 1))
    };
    let naive_longest = |x: u64| {
        let (mut best, mut run) = (0, 0);
        for bit in 0..64 {
            run = if x >> bit & 1 == 1 { run + 1 } else { 0 };
            best = best.max(run);
        }
        best
    };
    for x in [
        0,
        1,
        u64::MAX,
        u64::MAX >> 1,
        u64::MAX << 1,
        1 << 63,
        0x00FF_FF00_0000_FFFF,
    ] {
        assert_eq!(longest(x), naive_longest(x), "{x:#x}");
        for n in [1, 2, 32, 33, 63, 64, 65] {
            assert_eq!(run_in(x, n), naive_run(x, n), "{x:#x} {n}");
        }
    }
}

#[test]
fn a_return_merges_a_lone_right_neighbour() {
    let mut tables = Tables::new(6, 16);
    let mut allocator = tables.init();
    let first = reserve(&mut allocator, 2);
    let second = reserve(&mut allocator, 2);
    release(&mut allocator, first);
    assert_eq!(allocator.free_set(), [(0, 2), (4, 2)]);
    release(&mut allocator, second);
    assert_eq!(allocator.free_set(), [(0, 6)]);
    assert_eq!(allocator.indexed_runs(), [(0, 6)]);
    allocator.check(METADATA_UNITS);
}

/// A full index drops its smallest run, which stays free in the bitmap; a request no indexed run fits then takes the lowest-addressed fit through the summaries, and a return that joins a dropped neighbour indexes the joined run.
#[test]
fn a_full_index_drops_its_smallest_run_and_a_miss_falls_back_to_first_fit() {
    // Eight slots give the index one entry.
    let mut tables = Tables::new(40, 8);
    let mut allocator = tables.init();
    assert_eq!(allocator.capacity(), 1);
    let held: Vec<ExtentLocator> = [3, 5, 4, 20]
        .into_iter()
        .map(|units| reserve(&mut allocator, units))
        .collect();
    assert_eq!(allocator.drops(), 0);
    release(&mut allocator, held[0]);
    // Four visits: one bitmap word each for the held check, the right run-end
    // search and the summary update, and the first leaf the full index's offer
    // reads for its minimum; the three-unit tree is empty, so the own-key
    // descent reads nothing.
    assert_eq!(allocator.work, 1 + 1 + 1 + 1);
    assert_eq!(
        allocator.drops(),
        1,
        "the 3-unit run could not enter beside the 8-unit tail"
    );
    assert_eq!(allocator.indexed_runs(), [(32, 8)]);
    assert_eq!(allocator.free_set(), [(0, 3), (32, 8)]);
    allocator.check(METADATA_UNITS);
    // Two units: the indexed tail is the only indexed fit.
    assert_eq!(reserve(&mut allocator, 2), at(32, 2));
    assert_eq!(allocator.indexed_runs(), [(34, 6)]);
    // Seven units: the index misses, and first fit finds none below the tail either.
    let mut budget = WorkBudget::new(limit(&allocator, 7));
    assert_eq!(
        allocator.reserve(7, 0, limit(&allocator, 7), &mut budget),
        Err(ExtentRefusal::NoFit { units: 7 })
    );
    release(&mut allocator, held[2]);
    // The dropped 3-unit run is back: the joined run at 8 holds four units and was dropped too.
    assert_eq!(allocator.free_set(), [(0, 3), (8, 4), (34, 6)]);
    assert_eq!(allocator.indexed_runs(), [(34, 6)]);
    // Three units: the tail is indexed and fits, so the index serves it.
    assert_eq!(reserve(&mut allocator, 3), at(34, 3));
    // Four units: the indexed tail of three misses; first fit takes the lowest fitting run.
    assert_eq!(reserve(&mut allocator, 4), at(8, 4));
    assert_eq!(allocator.free_set(), [(0, 3), (37, 3)]);
    allocator.check(METADATA_UNITS);
    release(&mut allocator, held[1]);
    assert_eq!(allocator.free_set(), [(0, 8), (37, 3)]);
    assert_eq!(
        allocator.indexed_runs(),
        [(0, 8)],
        "the joined run outranks the indexed tail"
    );
    allocator.check(METADATA_UNITS);
}

/// An index miss places the request by first fit through the summaries, across a word boundary inside a chunk, and offers the remainder, which outranks the one indexed run.
#[test]
fn an_index_miss_takes_the_lowest_fit_across_a_word_boundary_and_indexes_its_remainder() {
    // Eight slots give the index one entry.
    let mut tables = Tables::new(256, 8);
    let mut allocator = tables.init();
    let held: Vec<ExtentLocator> = [40, 50, 10]
        .into_iter()
        .map(|units| reserve(&mut allocator, units))
        .collect();
    release(&mut allocator, held[1]);
    assert_eq!(
        allocator.indexed_runs(),
        [(100, 156)],
        "the 50-unit run was dropped"
    );
    assert_eq!(reserve(&mut allocator, 150), at(100, 150));
    assert_eq!(allocator.indexed_runs(), [(250, 6)]);
    // The dropped run at 40 spans units 40 to 89, across the word boundary at 64.
    assert_eq!(reserve(&mut allocator, 30), at(40, 30));
    assert_eq!(allocator.free_set(), [(70, 20), (250, 6)]);
    assert_eq!(allocator.indexed_runs(), [(70, 20)]);
    allocator.check(METADATA_UNITS);
}

/// Runs of `2^24` units or more share the saturated length key and rank by start: a request no shorter run fits takes the lowest-starting one, here longer than a higher-starting one that exact best fit would take, and a run-end search finds its exact length.
#[test]
fn saturated_runs_rank_by_start_and_resolve_their_length_through_the_summaries() {
    let big = LOCATOR_LEN_LIMIT - 1;
    let units = (1 << 25) + (1 << 21);
    let mut tables = Tables::new(units, 64);
    let mut allocator = tables.init();
    assert_eq!(allocator.levels(), 7, "levels 5 and 6 hold wide nodes");
    // The lower run joins two extents; the higher run, past a four-unit fence, is 212 units shorter.
    let low = (1 << 24) + (1 << 20) + 100;
    assert_eq!(reserve(&mut allocator, 8), at(0, 8));
    let first = reserve(&mut allocator, big);
    let second = reserve(&mut allocator, (low - u64::from(big)) as u32);
    let fence = reserve(&mut allocator, 4);
    assert_eq!(fence, at(8 + low, 4));
    release(&mut allocator, first);
    release(&mut allocator, second);
    let (tail, high) = (12 + low, units - 12 - low);
    assert!(high < low && high > u64::from(big));
    assert_eq!(allocator.free_set(), [(8, low), (tail, high)]);
    assert_eq!(allocator.indexed_runs(), [(8, low), (tail, high)]);
    allocator.check(METADATA_UNITS);
    let rest = low - u64::from(big);
    assert_eq!(
        reserve(&mut allocator, big),
        at(8, big),
        "the lower start wins"
    );
    assert_eq!(
        allocator.indexed_runs(),
        [(8 + u64::from(big), rest), (tail, high)]
    );
    let small = reserve(&mut allocator, 100);
    assert_eq!(small, at(8 + u64::from(big), 100));
    allocator.check(METADATA_UNITS);
    release(&mut allocator, fence);
    release(&mut allocator, small);
    assert_eq!(
        allocator.free_set(),
        [(8 + u64::from(big), units - 8 - u64::from(big))]
    );
    allocator.check(METADATA_UNITS);
}

#[test]
fn a_budget_one_visit_short_refuses_and_changes_nothing() {
    let mut tables = Tables::new(16, 32);
    let mut allocator = tables.init();
    reserve(&mut allocator, 5);
    let before = snapshot(&allocator);
    let mut budget = WorkBudget::new(limit(&allocator, 2) - 1);
    let unspent = budget;
    assert_eq!(
        allocator.reserve(2, 100, limit(&allocator, 2), &mut budget),
        Err(ExtentRefusal::BudgetExhausted)
    );
    assert_eq!(budget, unspent);
    assert_eq!(snapshot(&allocator), before);
    allocator.check(METADATA_UNITS);
}

/// A search that exceeds its work limit refuses `NoFit` before any change and debits the whole limit: a limit of one visit covers the root summary and leaves the index descent unfunded.
/// A one-unit charge makes allocation change the placeable count, so snapshot equality verifies that the refusal preserves the count.
#[test]
fn a_search_past_the_work_limit_refuses_and_changes_nothing() {
    let mut tables = Tables::new(4096, 64);
    let mut allocator = tables.init_charged(1);
    let held: Vec<ExtentLocator> = (0..8).map(|_| reserve(&mut allocator, 3)).collect();
    for &locator in held.iter().step_by(2) {
        release(&mut allocator, locator);
    }
    let before = snapshot(&allocator);
    let mut budget = WorkBudget::new(1);
    assert_eq!(
        allocator.reserve(1, 0, 1, &mut budget),
        Err(ExtentRefusal::NoFit { units: 1 })
    );
    assert!(allocator.work > 1, "the search read past the root");
    assert_eq!(budget.remaining(), 0, "the search debits its whole limit");
    assert_eq!(snapshot(&allocator), before);
}

#[test]
fn a_shortage_refuses_after_one_root_read_with_the_tables_unchanged() {
    let mut tables = Tables::new(16, 32);
    let mut allocator = tables.init();
    let first = reserve(&mut allocator, 5);
    reserve(&mut allocator, 2);
    release(&mut allocator, first);
    let before = snapshot(&allocator);
    let mut budget = WorkBudget::new(limit(&allocator, 10));
    assert_eq!(
        allocator.reserve(10, 0, limit(&allocator, 10), &mut budget),
        Err(ExtentRefusal::NoFit { units: 10 })
    );
    assert_eq!(budget.counters().visits, 1, "the root summary alone");
    assert_eq!(snapshot(&allocator), before);
    allocator.check(METADATA_UNITS);
}

#[test]
fn argument_refusals_precede_the_preflight() {
    let mut tables = Tables::new(8, 16);
    let mut allocator = tables.init();
    reserve(&mut allocator, 1);
    let mut budget = WorkBudget::new(0);
    for (units, payload) in [(0, 0), (LOCATOR_LEN_LIMIT, 0), (1, IO_UNIT + 1)] {
        assert_eq!(
            allocator.reserve(units, payload, 0, &mut budget),
            Err(ExtentRefusal::Length { units, payload })
        );
    }
    allocator.check(METADATA_UNITS);
}

#[test]
fn phase_transitions_move_payload_and_refuse_out_of_order() {
    let mut tables = Tables::new(8, 16);
    let mut allocator = tables.init_charged(1);
    let mut budget = WorkBudget::new(limit(&allocator, 2));
    let held = allocator
        .reserve(2, 5000, limit(&allocator, 2), &mut budget)
        .expect("fits");
    let waste = 2 * IO_UNIT - 5000;
    let expect = |reserved, resident, retired| RawPartition {
        metadata: METADATA_UNITS as usize * IO_UNIT,
        free: 6 * IO_UNIT,
        reserved,
        resident,
        retired,
        waste,
    };
    assert_eq!(allocator.ledger(), expect(5000, 0, 0));
    assert_eq!(allocator.retire(5000), Err(LedgerOverflow));
    allocator.publish(5000).expect("reserved");
    assert_eq!(allocator.ledger(), expect(0, 5000, 0));
    assert_eq!(allocator.publish(1), Err(LedgerOverflow));
    allocator.retire(5000).expect("resident");
    assert_eq!(allocator.ledger(), expect(0, 0, 5000));
    let before = snapshot(&allocator);
    assert_eq!(
        allocator.release(held, HeldPhase::Resident, 5000),
        Err(ExtentStateError::Ledger)
    );
    assert_eq!(snapshot(&allocator), before);
    assert_eq!(allocator.release(held, HeldPhase::Retired, 5000), Ok(()));
    assert_eq!(
        allocator.ledger(),
        RawPartition::new(METADATA_UNITS as usize * IO_UNIT, 8 * IO_UNIT)
    );
    let before = snapshot(&allocator);
    for locator in [held, at(0, 0), at(7, 2), at(8, 1)] {
        assert_eq!(
            allocator.release(locator, HeldPhase::Reserved, 0),
            Err(ExtentStateError::NotHeld),
            "{locator:?}"
        );
    }
    assert_eq!(snapshot(&allocator), before);
    allocator.check(METADATA_UNITS);
}

#[test]
fn a_return_past_the_volume_refuses_over_a_deep_long_run_tree() {
    let pairs = 107;
    let mut tables = Tables::new(pairs * 257, 1024);
    let mut allocator = tables.init();
    let long: Vec<ExtentLocator> = (0..pairs)
        .map(|_| {
            let long = reserve(&mut allocator, 256);
            reserve(&mut allocator, 1);
            long
        })
        .collect();
    assert_eq!(allocator.free_set(), []);
    // The held one-unit reservations separate the released 256-unit runs, so each stays its own long-run entry.
    for &locator in &long {
        release(&mut allocator, locator);
    }
    assert!(allocator.deepest() >= 2, "depth {}", allocator.deepest());
    let edge = at(LOCATOR_START_LIMIT - 1, LOCATOR_LEN_LIMIT - 1);
    let before = snapshot(&allocator);
    assert_eq!(
        allocator.release(edge, HeldPhase::Reserved, 0),
        Err(ExtentStateError::NotHeld)
    );
    assert_eq!(snapshot(&allocator), before);
    allocator.check(METADATA_UNITS);
}

#[test]
fn an_aborted_reservation_returns_its_waste_without_a_publish() {
    let mut tables = Tables::new(4, 8);
    let mut allocator = tables.init();
    let mut budget = WorkBudget::new(limit(&allocator, 3));
    let held = allocator
        .reserve(3, 1, limit(&allocator, 3), &mut budget)
        .expect("fits");
    assert_eq!(allocator.ledger().waste, 3 * IO_UNIT - 1);
    allocator
        .release(held, HeldPhase::Reserved, 1)
        .expect("held");
    assert_eq!(
        allocator.ledger(),
        RawPartition::new(METADATA_UNITS as usize * IO_UNIT, 4 * IO_UNIT)
    );
}

#[test]
fn reservation_transitions_and_return_allocate_nothing() {
    let mut tables = Tables::new(2000, 16);
    let mut allocator = tables.init();
    let mut budget = WorkBudget::new(1 << 20);
    let before = crate::instrument::allocations();
    let held: Vec<ExtentLocator> = (0..8)
        .map(|index| {
            let units = 1 + 70 * index;
            let limit = limit(&allocator, units);
            allocator
                .reserve(units, 10, limit, &mut budget)
                .expect("fits")
        })
        .collect::<Vec<_>>();
    let after_collect = crate::instrument::allocations();
    for _ in (0..8).step_by(2) {
        allocator.publish(10).expect("reserved");
        allocator.retire(10).expect("resident");
    }
    for index in [3, 0, 7, 1, 2, 6, 4, 5] {
        let phase = if index % 2 == 0 {
            HeldPhase::Retired
        } else {
            HeldPhase::Reserved
        };
        allocator.release(held[index], phase, 10).expect("held");
    }
    assert_eq!(crate::instrument::allocations(), after_collect);
    assert!(after_collect - before <= 1, "only the test's own vector");
}

#[test]
fn a_reattached_view_continues_the_history_an_uninterrupted_view_records() {
    let sizes = [3, 2, 4, 1];
    let mut whole = Tables::new(16, 16);
    let mut split = Tables::new(16, 16);
    let mut uninterrupted = whole.init();
    let held: Vec<ExtentLocator> = sizes
        .iter()
        .map(|&units| reserve(&mut uninterrupted, units))
        .collect();
    split.init();
    for (&units, &expected) in sizes.iter().zip(&held) {
        assert_eq!(reserve(&mut split.view(), units), expected);
    }
    for index in [1, 3, 0] {
        release(&mut uninterrupted, held[index]);
        let mut view = split.view();
        release(&mut view, held[index]);
        view.check(METADATA_UNITS);
        assert_eq!(view.free_set(), uninterrupted.free_set());
        assert_eq!(view.ledger(), uninterrupted.ledger());
    }
    uninterrupted.check(METADATA_UNITS);
    assert_eq!(split.root, whole.root);
    assert_eq!(split.space, whole.space);
    assert_eq!(split.nodes, whole.nodes);
}

/// The free units of a volume, one flag per unit.
struct Units(Vec<bool>);

impl Units {
    fn runs(&self) -> Vec<(u64, u64)> {
        let mut runs = Vec::new();
        let mut unit = 0;
        while unit < self.0.len() {
            let start = unit;
            while unit < self.0.len() && self.0[unit] {
                unit += 1;
            }
            if unit > start {
                runs.push((start as u64, (unit - start) as u64));
            }
            unit += 1;
        }
        runs
    }

    fn first_fit(&self, units: u64) -> Option<u64> {
        self.runs()
            .into_iter()
            .find(|&(_, len)| len >= units)
            .map(|(start, _)| start)
    }

    fn set(&mut self, locator: ExtentLocator, free: bool) {
        let start = locator.start_unit() as usize;
        for unit in &mut self.0[start..start + locator.len_units() as usize] {
            assert_ne!(*unit, free, "a unit changed hands twice");
            *unit = free;
        }
    }
}

/// Counts of the paths one history exercised.
#[derive(Default)]
struct Paths {
    indexed: usize,
    fallback: usize,
    refused: usize,
    drops: u64,
    /// Reservations taken from a saturated index key, and returns that joined a run of at least `SATURATED` units.
    saturated: usize,
}

/// The placeable units a free set gives under [`CHARGE`], counted from the runs alone.
fn placeable_of(free: &[(u64, u64)]) -> u64 {
    free.iter().map(|&(_, len)| len / CHARGE * CHARGE).sum()
}

/// The ledger the held tuples imply, tallied without the partition's own operations: every byte outside a held extent is free, each phase sums its extents' payloads, and waste is each extent's bytes beyond its payload.
fn census(units: u64, held: &[(ExtentLocator, usize, HeldPhase)]) -> RawPartition {
    let mut tally = RawPartition {
        metadata: METADATA_UNITS as usize * IO_UNIT,
        free: units as usize * IO_UNIT,
        ..RawPartition::default()
    };
    for &(locator, payload, phase) in held {
        let extent = locator.len_units() as usize * IO_UNIT;
        tally.free -= extent;
        tally.waste += extent - payload;
        *match phase {
            HeldPhase::Reserved => &mut tally.reserved,
            HeldPhase::Resident => &mut tally.resident,
            HeldPhase::Retired => &mut tally.retired,
        } += payload;
    }
    tally
}

/// One seeded history over `units` units and `slots` slots, with requests of up to `largest` units: every placement, refusal and free set agrees with `Units` and the index, every call stays within the work bound for its extent, and every invariant holds after each call.
/// A reservation of `n` units moves the placeable count by less than [`CHARGE`] from `-n`, a return of `n` units raises it by at least `n`'s whole charges, and halfway through the history a restore over the held set rebuilds the tables with init's charge, every held extent resident.
fn run_history(seed: u64, units: u64, slots: usize, largest: u64, steps: usize) -> Paths {
    let mut tables = Tables::new(units, slots);
    let mut allocator = tables.init();
    let mut model = Units(vec![true; units as usize]);
    let mut held: Vec<(ExtentLocator, usize, HeldPhase)> = Vec::new();
    let mut rng = SplitMix64::new(seed);
    let mut paths = Paths::default();
    for step in 0..steps {
        let at_step = format!("seed {seed} units {units} slots {slots} step {step}");
        let placeable = allocator.placeable();
        let mut released = None;
        if step == steps / 2 {
            let mut listed: Vec<(u64, u32, usize)> = held
                .iter()
                .map(|&(locator, payload, _)| (locator.start_unit(), locator.len_units(), payload))
                .collect();
            listed.sort_unstable();
            let (runs, totals) = runs_of(&listed);
            assert!(
                ExtentAllocator::restore_runs(
                    (
                        &mut *allocator.root,
                        &mut *allocator.space,
                        &mut *allocator.nodes
                    ),
                    runs.into_iter(),
                    totals,
                ),
                "{at_step}: the held set restores"
            );
            assert_eq!(
                allocator.root.charge, CHARGE,
                "{at_step}: the restore keeps the charge"
            );
            assert_eq!(
                allocator.placeable(),
                placeable,
                "{at_step}: the restore keeps the count"
            );
            for entry in &mut held {
                entry.2 = HeldPhase::Resident;
            }
        }
        match rng.below(10) {
            0..=4 => {
                // Sizes that straddle a word, a chunk and several chunks.
                let n = match rng.below(4) {
                    0 => 1 + rng.below(8),
                    1 => [63, 64, 65, 127, 511, 512, 513][rng.below(7) as usize],
                    _ => 1 + rng.below(largest),
                }
                .min(largest);
                let payload = rng.below(n * IO_UNIT as u64 + 1) as usize;
                let indexed = allocator.indexed_runs();
                let best = indexed
                    .iter()
                    .filter(|run| run.1 >= n)
                    .min_by_key(|run| (run.1.min(SATURATED), run.0));
                paths.saturated += usize::from(best.is_some_and(|run| run.1 >= SATURATED));
                let best = best.map(|run| run.0);
                let expected = best.or_else(|| model.first_fit(n));
                let bound = limit(&allocator, n as u32);
                let mut budget = WorkBudget::new(bound);
                let got = allocator.reserve(n as u32, payload, bound, &mut budget);
                assert!(
                    allocator.work <= bound,
                    "{at_step}: {} > {bound}",
                    allocator.work
                );
                assert_eq!(budget.counters().visits, allocator.work, "{at_step}");
                match (got, expected) {
                    (Ok(locator), Some(start)) => {
                        assert_eq!(locator, at(start, n as u32), "{at_step}");
                        let moved = allocator.placeable() as i64 - placeable as i64;
                        assert!(
                            (moved + n as i64).abs() < CHARGE as i64,
                            "{at_step}: {moved}"
                        );
                        model.set(locator, false);
                        held.push((locator, payload, HeldPhase::Reserved));
                        if best.is_some() {
                            paths.indexed += 1;
                        } else {
                            paths.fallback += 1;
                        }
                    }
                    (Err(ExtentRefusal::NoFit { units: refused }), None) => {
                        assert_eq!(u64::from(refused), n, "{at_step}");
                        paths.refused += 1;
                    }
                    (got, expected) => panic!("{at_step}: got {got:?}, expected {expected:?}"),
                }
            }
            5 | 6 if !held.is_empty() => {
                let index = rng.below(held.len() as u64) as usize;
                let (locator, payload, phase) = held[index];
                let next = match phase {
                    HeldPhase::Reserved => {
                        allocator.publish(payload).expect("reserved");
                        HeldPhase::Resident
                    }
                    HeldPhase::Resident => {
                        allocator.retire(payload).expect("resident");
                        HeldPhase::Retired
                    }
                    HeldPhase::Retired => continue,
                };
                held[index] = (locator, payload, next);
            }
            _ if !held.is_empty() => {
                let index = rng.below(held.len() as u64) as usize;
                let (locator, payload, phase) = held.swap_remove(index);
                assert_eq!(
                    allocator.release(locator, phase, payload),
                    Ok(()),
                    "{at_step}"
                );
                let bound = limit(&allocator, locator.len_units());
                assert!(
                    allocator.work <= bound,
                    "{at_step}: {} > {bound}",
                    allocator.work
                );
                model.set(locator, true);
                let n = u64::from(locator.len_units());
                assert!(
                    allocator.placeable() >= placeable + n / CHARGE * CHARGE,
                    "{at_step}: a return of {n} units"
                );
                let start = locator.start_unit();
                released = Some(start);
                let before = snapshot(&allocator);
                assert_eq!(
                    allocator.release(locator, phase, payload),
                    Err(ExtentStateError::NotHeld),
                    "{at_step}: a second return"
                );
                assert_eq!(snapshot(&allocator), before, "{at_step}");
            }
            _ => {}
        }
        let runs = model.runs();
        if let Some(start) = released {
            paths.saturated += usize::from(
                runs.iter()
                    .any(|run| run.0 <= start && start < run.0 + run.1 && run.1 >= SATURATED),
            );
        }
        assert_eq!(allocator.free_set(), runs, "{at_step}");
        assert_eq!(allocator.placeable(), placeable_of(&runs), "{at_step}");
        assert_eq!(allocator.ledger(), census(units, &held), "{at_step}");
        allocator.check(METADATA_UNITS);
    }
    paths.drops = allocator.drops();
    paths
}

/// Seeded reserve and return histories cover volumes from one word through several summary levels and indexes of 1 to 25 entries. [`run_history`] checks every history.
/// A volume of `2^24 + 2^13` units starts as one saturated run: its reservations take from the saturated key until the run falls below `2^24` units, and returns join it back into a saturated run and remove its entry by that key.
#[test]
fn seeded_histories_agree_with_the_free_unit_model() {
    let mut total = Paths::default();
    for (units, slots, largest) in [
        (40, 8, 12),
        (300, 24, 40),
        (5000, 48, 700),
        (40_000, 200, 1500),
    ] {
        for seed in 0..6 {
            let paths = run_history(seed, units, slots, largest, 400);
            total.indexed += paths.indexed;
            total.fallback += paths.fallback;
            total.refused += paths.refused;
            total.drops += paths.drops;
        }
    }
    let mut saturated = 0;
    for seed in 0..2 {
        let paths = run_history(seed, (1 << 24) + (1 << 13), 64, 1500, 80);
        saturated += paths.saturated;
    }
    assert!(saturated > 0, "reservations and returns met saturated runs");
    assert!(total.indexed > 0, "the index placed reservations");
    assert!(total.fallback > 0, "first fit placed index misses");
    assert!(total.refused > 0, "some reservations found no fitting run");
    assert!(total.drops > 0, "full indexes dropped runs");
}

/// Twin allocators replay one seeded history; each run reservation on one
/// matches the single reservations the other makes for its extents and
/// tail, and both end every step with equal free sets, ledgers and indexes.
#[test]
fn a_run_reservation_takes_the_extents_successive_reservations_take() {
    let (mut runs, mut partial, mut tails, mut drops) = (0, 0, 0, 0);
    for (units, slots, largest) in [(300, 24, 40), (5000, 48, 700), (40_000, 8, 1500)] {
        for seed in 0..6 {
            let mut single = Tables::new(units, slots);
            let mut run = Tables::new(units, slots);
            let (mut one, mut many) = (single.init(), run.init());
            let mut held: Vec<(ExtentLocator, usize)> = Vec::new();
            let mut rng = SplitMix64::new(seed);
            for step in 0..300 {
                let at_step = format!("units {units} seed {seed} step {step}");
                let n = (1 + rng.below(largest)) as u32;
                let payload = rng.below(u64::from(n) * IO_UNIT as u64 + 1) as usize;
                match rng.below(3) {
                    0 if !held.is_empty() => {
                        let (locator, bytes) =
                            held.swap_remove(rng.below(held.len() as u64) as usize);
                        for allocator in [&mut one, &mut many] {
                            assert_eq!(
                                allocator.release(locator, HeldPhase::Reserved, bytes),
                                Ok(()),
                                "{at_step}"
                            );
                        }
                    }
                    1 => {
                        let k = 2 + rng.below(6) as u32;
                        let tail = (rng.below(2) == 0).then(|| {
                            let m = (1 + rng.below(u64::from(n))) as u32;
                            (m, rng.below(u64::from(m) * IO_UNIT as u64 + 1) as usize)
                        });
                        let span =
                            u64::from(n) * u64::from(k) + tail.map_or(0, |(m, _)| u64::from(m));
                        let bound = many.bound_for(span)
                            + tail.map_or(0, |(m, _)| many.bound_for(u64::from(m)));
                        let mut budget = WorkBudget::new(bound);
                        let Ok(placed) = many.reserve_run(n, k, payload, tail, bound, &mut budget)
                        else {
                            let mut probe = WorkBudget::new(bound);
                            assert!(one.reserve(n, payload, bound, &mut probe).is_err());
                            continue;
                        };
                        assert!(many.work <= bound, "{at_step}");
                        runs += 1;
                        partial += usize::from(placed.taken < k);
                        assert!(placed.tail.is_none() || placed.taken == k, "{at_step}");
                        let mut single = |units: u32, bytes: usize| {
                            let limit = one.bound_for(u64::from(units));
                            let mut steps = WorkBudget::new(limit);
                            one.reserve(units, bytes, limit, &mut steps)
                        };
                        for index in 0..placed.taken {
                            let start = placed.first.start_unit() + u64::from(index * n);
                            let got = single(n, payload);
                            assert_eq!(got, Ok(at(start, n)), "{at_step} extent {index}");
                            held.push((at(start, n), payload));
                        }
                        let end = placed.first.start_unit() + u64::from(placed.taken * n);
                        match (tail, placed.tail) {
                            (Some((m, bytes)), Some(located)) => {
                                tails += 1;
                                assert_eq!(located, at(end, m), "{at_step}");
                                assert_eq!(single(m, bytes), Ok(located), "{at_step} tail");
                                held.push((located, bytes));
                            }
                            (None, Some(_)) => panic!("{at_step}: a tail nobody asked for"),
                            _ => {}
                        }
                    }
                    _ => {
                        let bound = one.bound_for(u64::from(n));
                        let (mut a, mut b) = (WorkBudget::new(bound), WorkBudget::new(bound));
                        let got = one.reserve(n, payload, bound, &mut a);
                        assert_eq!(many.reserve(n, payload, bound, &mut b), got, "{at_step}");
                        if let Ok(locator) = got {
                            held.push((locator, payload));
                        }
                    }
                }
                assert_eq!(one.free_set(), many.free_set(), "{at_step}");
                assert_eq!(one.ledger(), many.ledger(), "{at_step}");
                let (mut keys, mut twin) = (one.index_keys(), many.index_keys());
                keys.sort_unstable();
                twin.sort_unstable();
                assert_eq!(keys, twin, "{at_step}");
                one.check(METADATA_UNITS);
                many.check(METADATA_UNITS);
            }
            drops += many.drops();
        }
    }
    assert!(drops > 0, "full indexes dropped runs");
    assert!(runs > 0, "run reservations placed extents");
    assert!(partial > 0, "some runs stopped short of their count");
    assert!(tails > 0, "some runs placed their tail");
}

/// A tail whose best fit is a smaller run than the run's stays unplaced, so
/// the 5-unit run at unit 0 still holds a later 3-unit reservation.
#[test]
fn a_run_leaves_its_tail_to_a_smaller_fit() {
    let mut tables = Tables::new(60, 24);
    let mut allocator = tables.init();
    let low = reserve(&mut allocator, 5);
    let _middle = reserve(&mut allocator, 15);
    release(&mut allocator, low);
    assert_eq!(allocator.free_set(), [(0, 5), (20, 40)]);
    let bound = allocator.bound_for(23) + allocator.bound_for(3);
    let mut budget = WorkBudget::new(bound);
    let placed = allocator
        .reserve_run(10, 2, 0, Some((3, 0)), bound, &mut budget)
        .unwrap();
    assert_eq!(
        (placed.first, placed.taken, placed.tail),
        (at(20, 10), 2, None)
    );
    assert_eq!(reserve(&mut allocator, 3), at(0, 3));
    allocator.check(METADATA_UNITS);
}

/// A run that holds `2^32` extents of the requested length still places the extents the call asked for: `Run` documents `taken >= 1`, and an indexed fit takes as many of the `count` extents as its run holds.
/// The free run is the whole of a `2^32`-unit volume, the shortest volume whose run holds that many one-unit extents.
#[test]
fn a_run_reservation_takes_its_count_from_a_run_of_two_to_the_32_extents() {
    let units = 1u64 << 32;
    let mut tables = Tables::new(units, 24);
    let mut allocator = tables.init();
    let bound = allocator.bound_for(2);
    let mut budget = WorkBudget::new(bound);
    let placed = allocator
        .reserve_run(1, 2, 0, None, bound, &mut budget)
        .unwrap();
    assert_eq!(
        (placed.first, placed.taken, placed.tail),
        (at(0, 1), 2, None)
    );
    assert_eq!(allocator.ledger().free, (units - 2) as usize * IO_UNIT);
    assert_eq!(allocator.longest_free_run(), units - 2);
}

/// An exact best-fit allocator: free runs by `(len, start)` and by start, coalescing on return.
struct BestFit {
    by_size: BTreeSet<(u64, u64)>,
    by_start: BTreeMap<u64, u64>,
}

impl BestFit {
    fn new(units: u64) -> Self {
        Self {
            by_size: BTreeSet::from([(units, 0)]),
            by_start: BTreeMap::from([(0, units)]),
        }
    }

    fn take(&mut self, n: u64) -> Option<u64> {
        let (len, start) = *self.by_size.range((n, 0)..).next()?;
        self.by_size.remove(&(len, start));
        self.by_start.remove(&start);
        if len > n {
            self.by_size.insert((len - n, start + n));
            self.by_start.insert(start + n, len - n);
        }
        Some(start)
    }

    fn give(&mut self, mut start: u64, n: u64) {
        let mut end = start + n;
        if let Some((&before, &len)) = self.by_start.range(..start).next_back()
            && before + len == start
        {
            self.by_start.remove(&before);
            self.by_size.remove(&(len, before));
            start = before;
        }
        if let Some(len) = self.by_start.remove(&end) {
            self.by_size.remove(&(len, end));
            end += len;
        }
        self.by_size.insert((end - start, start));
        self.by_start.insert(start, end - start);
    }
}

/// Bodies up to 324 KiB take at most 82 units with their header; the history also admits larger bodies, which it does not score.
const SCORED_UNITS: u64 = 82;

/// A request size in units: mostly small objects, a tail up to the scored bound and a few larger ones.
fn object_units(rng: &mut SplitMix64) -> u64 {
    match rng.below(100) {
        0..=54 => 1 + rng.below(4),
        55..=84 => 5 + rng.below(16),
        85..=96 => 21 + rng.below(SCORED_UNITS - 20),
        _ => SCORED_UNITS + 1 + rng.below(174),
    }
}

/// Scored refusals and scored requests of one seeded history at `occupancy`: each arrival first evicts uniformly chosen objects until the live units leave room for it under `occupancy` of the volume, then reserves.
fn refusals(
    seed: u64,
    occupancy: f64,
    mut take: impl FnMut(u64) -> Option<u64>,
    mut give: impl FnMut(u64, u64),
) -> (u64, u64) {
    const UNITS: u64 = 1 << 17;
    const ARRIVALS: usize = 120_000;
    let cap = (UNITS as f64 * occupancy) as u64;
    let mut rng = SplitMix64::new(seed);
    let mut live: Vec<(u64, u64)> = Vec::new();
    let mut used = 0;
    let (mut refused, mut scored) = (0, 0);
    for arrival in 0..ARRIVALS {
        let n = object_units(&mut rng);
        while used + n > cap {
            let (start, len) = live.swap_remove(rng.below(live.len() as u64) as usize);
            give(start, len);
            used -= len;
        }
        let warm = arrival >= ARRIVALS / 4;
        let placed = take(n);
        if warm && n <= SCORED_UNITS {
            scored += 1;
            refused += u64::from(placed.is_none());
        }
        if let Some(start) = placed {
            live.push((start, n));
            used += n;
        }
    }
    (refused, scored)
}

/// A regression gate on the drop path: with the index cap binding, seeded histories at occupancy 0.90 and 0.95 refuse bodies up to 324 KiB at a rate within 0.1 points of exact best fit.
/// The slot count, 2,048, caps the index at 256 entries, below the histories' free-run counts, so the index drops runs throughout; at a slot count that covers the live objects the cap stays above the run count and the two allocators refuse alike.
/// Exact best fit refuses 0.000% at 0.90 and 0.010% to 0.015% at 0.95 for this mix, so the gate catches a drop path that refuses far more than best fit, and the margin at refusal rates near 1% rests on the design's replay evidence.
#[test]
fn a_binding_index_cap_keeps_seeded_refusals_within_a_tenth_of_a_point_of_exact_best_fit() {
    const SLOTS: usize = 2048;
    for occupancy in [0.90, 0.95] {
        for seed in 1..=2 {
            let mut tables = Tables::new(1 << 17, SLOTS);
            let mut allocator = tables.init();
            let cell = std::cell::RefCell::new(&mut allocator);
            let ours = refusals(
                seed,
                occupancy,
                |n| {
                    let mut allocator = cell.borrow_mut();
                    let limit = limit(&allocator, n as u32);
                    allocator
                        .reserve(n as u32, 0, limit, &mut WorkBudget::new(limit))
                        .ok()
                        .map(|locator| locator.start_unit())
                },
                |start, len| {
                    cell.borrow_mut()
                        .release(at(start, len as u32), HeldPhase::Reserved, 0)
                        .expect("held")
                },
            );
            let drops = allocator.drops();
            allocator.check(METADATA_UNITS);
            let reference = std::cell::RefCell::new(BestFit::new(1 << 17));
            let exact = refusals(
                seed,
                occupancy,
                |n| reference.borrow_mut().take(n),
                |start, len| reference.borrow_mut().give(start, len),
            );
            let rate = |(refused, scored): (u64, u64)| 100.0 * refused as f64 / scored as f64;
            assert!(
                occupancy < 0.95 || exact.0 > 0,
                "the reference refuses some bodies"
            );
            assert!(drops > 0, "the cap binds at {occupancy}");
            assert!(
                rate(ours) - rate(exact) <= 0.1,
                "occupancy {occupancy} seed {seed}: {:.3}% against {:.3}%",
                rate(ours),
                rate(exact)
            );
        }
    }
}

/// A run-end search's free-unit count and visits, from the free runs alone: the scan reads the unit's word, then each later (earlier) word of its chunk while the words stay free, then on each level the siblings after (before) the unit's ancestor node, one visit each, while each sibling is free from end to end.
struct RunScan<'r> {
    /// The maximal free runs in address order.
    runs: &'r [(u64, u64)],
    units: u64,
    levels: usize,
    /// Nodes on each summary level.
    nodes: Vec<u64>,
}

impl RunScan<'_> {
    /// The free units from `unit` up to `limit`, the first taken unit or the volume's end, whichever comes first.
    fn free_from(&self, unit: u64, limit: u64) -> u64 {
        let at = self.runs.partition_point(|run| run.0 + run.1 <= unit);
        match self.runs.get(at) {
            Some(&(start, len)) if start <= unit => (start + len).min(limit) - unit,
            _ => 0,
        }
    }

    /// The free units below `unit` down to `limit`, the first taken unit or unit zero, whichever comes first.
    fn free_below(&self, unit: u64, limit: u64) -> u64 {
        let at = self.runs.partition_point(|run| run.0 + run.1 < unit);
        match self.runs.get(at) {
            Some(&(start, len)) if start < unit && unit <= start + len => unit - start.max(limit),
            _ => 0,
        }
    }

    fn after(&self, unit: u64) -> (u64, usize) {
        let words = self.units.div_ceil(64);
        let index = unit / 64;
        if index >= words {
            return (0, 0);
        }
        let word_end = (index + 1) * 64;
        let mut total = self.free_from(unit, word_end);
        let mut reads = 1;
        if total < word_end - unit {
            return (total, reads);
        }
        for word in index + 1..words.min((index / 8 + 1) * 8) {
            reads += 1;
            let ones = self.free_from(word * 64, (word + 1) * 64);
            total += ones;
            if ones < 64 {
                return (total, reads);
            }
        }
        let mut node = index / 8;
        for level in 0..self.levels - 1 {
            let size = 512 << (3 * level);
            for sibling in node + 1..self.nodes[level].min((node / 8 + 1) * 8) {
                reads += 1;
                let head = self.free_from(sibling * size, (sibling + 1) * size);
                if head < size {
                    return (total + head, reads);
                }
                total += size;
            }
            node /= 8;
        }
        (total, reads)
    }

    fn before(&self, unit: u64) -> (u64, usize) {
        if unit == 0 {
            return (0, 0);
        }
        let index = (unit - 1) / 64;
        let mut total = self.free_below(unit, index * 64);
        let mut reads = 1;
        if total < unit - index * 64 {
            return (total, reads);
        }
        for word in (index / 8 * 8..index).rev() {
            reads += 1;
            let ones = self.free_below((word + 1) * 64, word * 64);
            total += ones;
            if ones < 64 {
                return (total, reads);
            }
        }
        let mut node = index / 8;
        for level in 0..self.levels - 1 {
            let size = 512 << (3 * level);
            for sibling in (node / 8 * 8..node).rev() {
                reads += 1;
                let (low, high) = (sibling * size, (sibling + 1) * size);
                if self.free_from(low, high) < size {
                    return (total + self.free_below(high.min(self.units), low), reads);
                }
                total += size;
            }
            node /= 8;
        }
        (total, reads)
    }
}

/// Every run-end search returns the free units and counts the visits a scan of words and sibling nodes makes, over seeded free sets on volumes of five and six summary levels, a level-5 node among them; a return's searches also agree after its extent is marked free and before the summaries are updated.
#[test]
fn run_end_searches_count_the_visits_of_a_word_and_sibling_scan() {
    for (units, largest, steps) in [(300_000, 70_000, 160), (2_200_000, 600_000, 60)] {
        let mut tables = Tables::new(units, 64);
        let mut model = Units(vec![true; units as usize]);
        let mut held: Vec<ExtentLocator> = Vec::new();
        let mut rng = SplitMix64::new(units);
        tables.init();
        for step in 0..steps {
            let mut allocator = tables.view();
            if held.is_empty() || rng.below(3) != 0 {
                let n = 1 + rng.below(largest);
                let limit = limit(&allocator, n as u32);
                if let Ok(locator) =
                    allocator.reserve(n as u32, 0, limit, &mut WorkBudget::new(limit))
                {
                    model.set(locator, false);
                    held.push(locator);
                }
            } else {
                let locator = held.swap_remove(rng.below(held.len() as u64) as usize);
                release(&mut allocator, locator);
                model.set(locator, true);
            }
            let runs = model.runs();
            let scan = RunScan {
                runs: &runs,
                units,
                levels: allocator.levels(),
                nodes: (0..allocator.levels())
                    .map(|level| allocator.nodes(level))
                    .collect(),
            };
            let mut probes: Vec<u64> = (0..24).map(|_| rng.below(units + 2)).collect();
            probes.extend(
                runs.iter()
                    .flat_map(|&(start, len)| [start, start + len])
                    .take(64),
            );
            for unit in probes {
                allocator.work = 0;
                let after = allocator.free_after(unit);
                assert_eq!(
                    (after, allocator.work),
                    scan.after(unit),
                    "step {step}: after {unit}"
                );
                allocator.work = 0;
                let before = allocator.free_before(unit.min(units));
                assert_eq!(
                    (before, allocator.work),
                    scan.before(unit.min(units)),
                    "step {step}: before {unit}"
                );
            }
            let Some(&locator) = held.get(rng.below(held.len().max(1) as u64) as usize) else {
                continue;
            };
            let kept = snapshot(&allocator);
            let (start, len) = (locator.start_unit(), u64::from(locator.len_units()));
            allocator.mark(start, len, true);
            model.set(locator, true);
            let runs = model.runs();
            let scan = RunScan {
                runs: &runs,
                ..scan
            };
            allocator.work = 0;
            let below = allocator.free_before(start);
            assert_eq!(
                (below, allocator.work),
                scan.before(start),
                "step {step}: marked before"
            );
            allocator.work = 0;
            let above = allocator.free_after(start + len);
            assert_eq!(
                (above, allocator.work),
                scan.after(start + len),
                "step {step}: marked after"
            );
            model.set(locator, false);
            (tables.root, tables.space, tables.nodes) = kept;
        }
    }
}

/// The half-open unit runs of `held`'s `(start, units, payload)` extents, and their unit and payload-byte totals.
fn runs_of(held: &[(u64, u32, usize)]) -> (Vec<(u64, u64)>, (usize, usize)) {
    let runs = (held.iter())
        .map(|&(start, units, _)| (start, start + u64::from(units)))
        .collect();
    let units = held.iter().map(|&(_, units, _)| units as usize).sum();
    let payload = held.iter().map(|&(_, _, payload)| payload).sum();
    (runs, (units, payload))
}

/// The free set an independent interval complement of `held` gives over `units` units.
fn complement(units: u64, held: &[(u64, u32, usize)]) -> Vec<(u64, u64)> {
    let mut free = Vec::new();
    let mut at = 0;
    for &(start, len, _) in held {
        if start > at {
            free.push((at, start - at));
        }
        at = start + u64::from(len);
    }
    if units > at {
        free.push((at, units - at));
    }
    free
}

/// The restored constructor's bitmap equals the independent complement of the held set for a held run, and separately a free run, ending at each of 63, 64, 65, 127, 128 and 129 units, plus a held run crossing a word edge; the six raw terms sum to the volume's bytes with every held byte resident or waste, and a reservation afterwards takes only free units.
#[test]
fn the_restored_allocator_equals_the_complement_of_its_held_set() {
    let units = 512;
    for end in [63, 64, 65, 127, 128, 129] {
        for held in [
            vec![(end - 3, 3, IO_UNIT + 100), (190, 4, IO_UNIT)],
            vec![(0, end as u32 - 10, IO_UNIT), (end, 2, 5)],
        ] {
            let mut tables = restore(units, 64, &held);
            let mut allocator = tables.view();
            assert_eq!(allocator.free_set(), complement(units, &held), "{held:?}");
            publishes_the_held_payload(&allocator, &held);
            let ledger = allocator.ledger();
            let held_units: u64 = held.iter().map(|&(_, len, _)| u64::from(len)).sum();
            let payload: usize = held.iter().map(|&(_, _, payload)| payload).sum();
            assert_eq!(ledger.waste, held_units as usize * IO_UNIT - payload);
            assert_eq!(ledger.free, (units - held_units) as usize * IO_UNIT);
            let taken = reserve(&mut allocator, 4);
            assert!(
                held.iter().all(|&(start, len, _)| {
                    taken.start_unit() + 4 <= start || start + u64::from(len) <= taken.start_unit()
                }),
                "a reservation never takes a held unit"
            );
        }
    }
}

fn publishes_the_held_payload(allocator: &ExtentAllocator<'_>, held: &[(u64, u32, usize)]) {
    let payload: usize = held.iter().map(|&(_, _, payload)| payload).sum();
    assert_eq!(
        allocator.ledger().resident,
        payload,
        "the restore publishes the held payload as resident {held:?}"
    );
}

/// The restore receives the held runs with no payload, so its ledger publishes no resident byte, the ledger a restore
/// that drops the publish of the held bytes leaves.
#[test]
#[should_panic(expected = "the restore publishes the held payload as resident")]
fn negative_control_a_restore_of_held_runs_without_their_payload_fails_the_resident_bytes() {
    let held = [(61, 3, IO_UNIT + 100), (190, 4, IO_UNIT)];
    let mut tables = restore(512, 64, &held.map(|(start, len, _)| (start, len, 0)));
    publishes_the_held_payload(&tables.view(), &held);
}

/// The restore accepts adjacent held runs, a run ending at the payload's end and a single slot, and a held set whose
/// payload total equals its units' bytes restores with every held byte resident and no waste.
#[test]
fn the_restored_allocator_accepts_its_boundaries() {
    let held = [(10, 2, 2 * IO_UNIT), (12, 2, 1), (508, 4, 4 * IO_UNIT)];
    let mut tables = restore(512, 1, &held);
    assert_eq!(tables.view().free_set(), complement(512, &held));
    let full = [(10, 2, 2 * IO_UNIT), (508, 4, 4 * IO_UNIT)];
    let mut tables = restore(512, 1, &full);
    let allocator = tables.view();
    assert_eq!(allocator.free_set(), complement(512, &full));
    let ledger = allocator.ledger();
    assert_eq!((ledger.resident, ledger.waste), (6 * IO_UNIT, 0));
}

/// `restored_runs` refuses runs out of order, overlapping, inverted or past the payload, and totals the runs do not
/// hold, each `Held` before any table is written.
#[test]
fn restored_runs_refuses_malformed_runs_and_mismatched_totals() {
    for (runs, totals, start) in [
        (vec![(8, 10), (4, 6)], (4, 0), 4),
        (vec![(4, 8), (6, 10)], (6, 0), 6),
        (vec![(6, 4)], (0, 0), 6),
        (vec![(510, 514)], (4, 0), 510),
        (vec![(4, 6)], (3, 0), 512),
        (vec![(4, 6)], (2, 2 * IO_UNIT + 1), 512),
        (vec![(6, 6)], (0, 0), 6),
        (vec![(4, 6)], (1, 0), 512),
        (vec![(4, 6)], (usize::MAX / IO_UNIT + 1, 0), 512),
    ] {
        let mut tables = Tables::new(512, 64);
        let fresh = Tables::new(512, 64);
        let refused = ExtentAllocator::restored_runs(
            (512, METADATA_UNITS, tables.capacity, CHARGE),
            (&mut tables.root, &mut tables.space, &mut tables.nodes),
            runs.iter().copied(),
            totals,
        );
        assert_eq!(
            refused.err(),
            Some(ExtentConfigError::Held { start }),
            "{runs:?} {totals:?}"
        );
        assert_eq!(
            (tables.root, tables.space, tables.nodes),
            (fresh.root, fresh.space, fresh.nodes),
            "nothing written"
        );
    }
}

/// The restore constructor refuses a payload past `LOCATOR_START_LIMIT` units `VolumeTooLarge` before any arithmetic on
/// the held set, so a fully held payload whose bytes overflow `usize` returns a typed refusal.
#[test]
fn the_restore_constructor_refuses_an_oversized_payload_before_its_sums() {
    // A fully held payload of 2^60 units names more bytes than `usize` holds.
    let units = 1 << 60;
    let mut tables = Tables::new(512, 64);
    let shape = (units, METADATA_UNITS, tables.capacity, CHARGE);
    let refused = ExtentAllocator::restored_runs(
        shape,
        (&mut tables.root, &mut tables.space, &mut tables.nodes),
        [(0, units)].into_iter(),
        (units as usize, 0),
    );
    assert_eq!(
        refused.err(),
        Some(ExtentConfigError::VolumeTooLarge {
            payload_units: units
        })
    );
}

/// The restored index holds the largest keys of the complement's runs up to its capacity and counts every other run in `drops`, as offering each run in address order leaves it: over short gaps the capacity reaches an exact tree partway, and over long gaps tree 0 alone exceeds it.
#[test]
fn the_restored_index_keeps_the_largest_runs_up_to_its_capacity() {
    let mut rng = SplitMix64::new(1151);
    for round in 0..600 {
        let units = 4096 + rng.below(4096);
        let slots = 1 + rng.below(200) as usize;
        let mut held = Vec::new();
        let mut at = rng.below(3);
        loop {
            let gap = match round % 3 {
                0 => 256 + rng.below(300),
                1 => rng.below(12),
                _ => rng.below(400),
            };
            let len = 1 + rng.below(8);
            if at + gap + len > units {
                break;
            }
            held.push((at + gap, len as u32, 0));
            at += gap + len;
        }
        let mut tables = restore(units, slots, &held);
        let capacity = tables.capacity;
        let allocator = tables.view();
        let mut keys: Vec<u64> = complement(units, &held)
            .into_iter()
            .map(|(start, len)| run_key(start, len))
            .collect();
        keys.sort_unstable_by(|a, b| b.cmp(a));
        let kept = keys.len().min(capacity);
        let mut expected = keys[..kept].to_vec();
        expected.sort_unstable();
        let mut indexed = allocator.index_keys();
        indexed.sort_unstable();
        assert_eq!(indexed, expected, "round {round}");
        assert_eq!(
            allocator.drops(),
            (keys.len() - kept) as u64,
            "round {round}"
        );
    }
}

/// A restored index whose runs share a few lengths builds trees of several inner levels that pass `check`, and its entries and drops are the largest keys up to the capacity, which successive offers leave, whether the capacity holds every run or reaches a tree partway.
#[test]
fn a_restored_index_of_deep_trees_keeps_the_largest_runs() {
    let mut rng = SplitMix64::new(1226);
    for (units, slots, lengths) in [
        (1 << 16, 1 << 17, 1),
        (1 << 16, 1 << 17, 3),
        (1 << 16, 40_000, 2),
        (1 << 16, 9_000, 5),
        (1 << 17, 1 << 18, 300),
    ] {
        let mut held = Vec::new();
        let mut at = 0;
        loop {
            let gap = 1 + rng.below(lengths);
            if at + gap + 1 > units {
                break;
            }
            held.push((at + gap, 1, 0));
            at += gap + 1;
        }
        let mut tables = restore(units, slots, &held);
        let capacity = tables.capacity;
        let allocator = tables.view();
        assert!(allocator.deepest() >= 2, "{units} {slots} {lengths}");
        let mut keys: Vec<u64> = complement(units, &held)
            .into_iter()
            .map(|(start, len)| run_key(start, len))
            .collect();
        keys.sort_unstable_by(|a, b| b.cmp(a));
        let kept = keys.len().min(capacity);
        let mut expected = keys[..kept].to_vec();
        expected.sort_unstable();
        assert_eq!(allocator.index_keys(), expected);
        assert_eq!(allocator.drops(), (keys.len() - kept) as u64);
    }
}

/// Restores `held` over fresh tables of `units` units and `slots` slots, with the full-extent charge [`CHARGE`].
fn restore(units: u64, slots: usize, held: &[(u64, u32, usize)]) -> Tables {
    let mut tables = Tables::new(units, slots);
    let capacity = tables.capacity;
    let (runs, totals) = runs_of(held);
    ExtentAllocator::restored_runs(
        (units, METADATA_UNITS, capacity, CHARGE),
        (&mut tables.root, &mut tables.space, &mut tables.nodes),
        runs.into_iter(),
        totals,
    )
    .expect("a valid held set")
    .check(METADATA_UNITS);
    tables
}

/// Each maximal free run counts its whole charges once, at its full length: a run crossing two 512-unit chunk boundaries counts `f(1490) = 1449`, the whole charges of its full length, a run crossing upper summary levels counts `f(59,899)`, and one free run of `2^24 + 2^13` units counts `f` of its length; a lone 63-unit hole counts 63 and a lone 62-unit hole counts zero.
/// After a restore, free runs of 255 and 256 units each count 252.
#[test]
fn placeable_counts_each_maximal_run_once_at_its_full_length() {
    for (units, held, expected) in [
        (2048, vec![(0, 10, 0), (1500, 4, 0)], 1449 + 504),
        (
            1 << 16,
            vec![(100, 1, 0), (60_000, 1, 0)],
            63 + 59_850 + 5481,
        ),
        (512, vec![(0, 200, 0), (263, 249, 0)], 63),
        (512, vec![(0, 200, 0), (262, 250, 0)], 0),
        (1024, vec![(255, 1, 0), (512, 1, 0)], 252 + 252 + 504),
    ] {
        let mut tables = restore(units, 64, &held);
        let view = tables.view();
        assert_eq!(view.placeable(), expected, "{held:?}");
        assert_eq!(view.placeable(), placeable_of(&complement(units, &held)));
    }
    let units = (1 << 24) + (1 << 13);
    let mut tables = Tables::new(units, 64);
    assert_eq!(tables.init().placeable(), 16_785_405);
}

/// A run reservation of `n` full extents from the low end of one run lowers the count by exactly `63n`; a full extent returned between two held extents raises it by exactly 63, and one returned beside a free neighbour by at least 63.
#[test]
fn whole_extents_move_the_placeable_count_by_their_charges() {
    let mut tables = Tables::new(10_000, 64);
    let mut allocator = tables.init();
    let mut runs = Vec::new();
    for n in 1..=4 {
        let before = allocator.placeable();
        let span = 63 * u64::from(n);
        let limit = allocator.bound_for(span);
        let run = allocator
            .reserve_run(63, n, 0, None, limit, &mut WorkBudget::new(limit))
            .expect("fits");
        assert_eq!(run.taken, n);
        assert_eq!(before - allocator.placeable(), span, "{n} full extents");
        runs.push(run);
    }
    allocator.check(METADATA_UNITS);
    // The second run's first extent lies between held units on both sides.
    let before = allocator.placeable();
    release(&mut allocator, runs[1].first);
    assert_eq!(allocator.placeable() - before, 63, "an isolated return");
    // The first run's extent joins the free extent above it.
    let before = allocator.placeable();
    release(&mut allocator, runs[0].first);
    assert!(allocator.placeable() - before >= 63, "a joining return");
    allocator.check(METADATA_UNITS);
}

/// The count follows the free runs alone. One held set is restored twice: under a one-entry index, which drops runs, and under an index that holds every run. Both restores give equal counts, and so does each return of a held extent, applied to both in the same order.
#[test]
fn index_drops_leave_the_placeable_count_unchanged() {
    let units = 8192;
    let held: Vec<(u64, u32, usize)> = (0..60)
        .map(|i| (i * 130 + 70, 7 + i as u32 % 5, 0))
        .collect();
    let mut dropping = restore(units, 1, &held);
    let mut whole = restore(units, 4096, &held);
    assert!(dropping.view().drops() > 0 && whole.view().drops() == 0);
    assert_eq!(
        dropping.view().placeable(),
        placeable_of(&complement(units, &held))
    );
    for (index, &(start, len, _)) in held.iter().enumerate().rev() {
        for tables in [&mut dropping, &mut whole] {
            let mut view = tables.view();
            release(&mut view, at(start, len));
            view.check(METADATA_UNITS);
        }
        assert_eq!(
            dropping.view().placeable(),
            whole.view().placeable(),
            "return {index}"
        );
    }
    assert_eq!(dropping.view().placeable(), units / CHARGE * CHARGE);
}

/// A restore keeps the charge that init set, so tables initialized with a 17-unit charge count each restored run in whole 17-unit charges; a root whose charge reads zero refuses the restore and leaves the tables unchanged.
#[test]
fn a_restore_keeps_the_charge_that_init_set_and_refuses_a_zero_charge() {
    let mut tables = Tables::new(512, 64);
    tables.init_charged(17);
    let (runs, totals) = runs_of(&[(30, 5, 0), (100, 9, 0)]);
    assert!(ExtentAllocator::restore_runs(
        (&mut tables.root, &mut tables.space, &mut tables.nodes),
        runs.iter().copied(),
        totals,
    ));
    let view = tables.view();
    assert_eq!(view.root.charge, 17);
    assert_eq!(view.placeable(), 17 + 51 + 391);
    view.check(METADATA_UNITS);
    tables.root.charge = 0;
    let before = snapshot(&tables.view());
    assert!(!ExtentAllocator::restore_runs(
        (&mut tables.root, &mut tables.space, &mut tables.nodes),
        runs.iter().copied(),
        totals,
    ));
    assert_eq!(snapshot(&tables.view()), before, "nothing written");
}
