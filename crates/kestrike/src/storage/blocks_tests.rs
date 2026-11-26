//! The sequence arena against an independent block map: seeded histories
//! over every order with fragmentation, exhaustion, stale owners, bad counts
//! and duplicate frees, the work meter on every operation, a planted join
//! of an allocated buddy that the map rejects, stale handles and a damaged
//! header over planted words, and the arena a storage lays out in its
//! control mapping.

use std::collections::BTreeMap;

use super::allocation::AllocationId;
use super::block_order::block_order;
use super::blocks::{
    ArenaError, ArenaLists, BIT_WORDS, Block, BlockArena, ROOT_GRANULES, ROOT_WORDS,
};
use super::budget::WorkBudget;
use super::extent::ExtentLocator;
use super::owner::Storage;
use super::placement::PlacementConfig;
use super::publish_tests::{PAGE, storage_config};
use super::seeded::SplitMix64;
use super::tables::SlotIndex;
use super::test_platform::TestPlatform;

/// Arena tables on the heap, as the control mapping holds them.
#[derive(Clone, PartialEq, Eq)]
struct Tables {
    lists: ArenaLists,
    words: Vec<u64>,
    bits: Vec<u64>,
}

impl Tables {
    fn new(roots: usize) -> Self {
        let mut tables = Self {
            lists: ArenaLists::EMPTY,
            words: vec![0; roots * ROOT_WORDS],
            bits: vec![0; roots * BIT_WORDS],
        };
        tables.arena().init();
        tables
    }

    fn arena(&mut self) -> BlockArena<'_> {
        BlockArena::attach(&mut self.lists, &mut self.words, &mut self.bits)
    }

    fn roots(&self) -> usize {
        self.bits.len() / BIT_WORDS
    }
}

impl std::fmt::Debug for Tables {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.lists)
    }
}

/// Whether `tables` lists every root whole and nothing else.
fn whole(tables: &mut Tables) -> bool {
    let roots = tables.roots() as u32;
    let arena = tables.arena();
    let mut listed: Vec<u32> = arena.listed(10).into_iter().map(|(at, _)| at).collect();
    listed.sort_unstable();
    listed
        == (0..roots)
            .map(|root| root * ROOT_GRANULES)
            .collect::<Vec<_>>()
        && (0..10).all(|order| arena.listed(order).is_empty())
}

/// The locator appended at `index` of the block at `at`, distinct for
/// every block and index.
fn locator(at: u32, index: u32) -> ExtentLocator {
    ExtentLocator::new(u64::from(at) << 12 | u64::from(index), 1 + index % 64).unwrap()
}

fn owner(slot: usize, incarnation: u32) -> AllocationId {
    AllocationId::new(SlotIndex(slot), incarnation)
}

/// The order whose block holds `count` locators behind the 16-byte header,
/// found by doubling from 32 bytes.
fn order_for(count: u32) -> u32 {
    let need = 16 + 8 * u64::from(count);
    (0..=10)
        .find(|&order| 32 << order >= need)
        .expect("one root holds every sequence")
}

/// Every extent count whose sequence takes `order`.
fn counts_of(order: u32) -> std::ops::RangeInclusive<u32> {
    let low = if order == 0 {
        2
    } else {
        ((32u32 << (order - 1)) - 16) / 8 + 1
    };
    let high = (((32u32 << order) - 16) / 8).min(2115);
    low..=high
}

/// One live block of the map: its owner, extent count and held prefix.
#[derive(Clone, Copy, Debug)]
struct Live {
    owner: AllocationId,
    count: u32,
    held: u32,
}

/// Checks `tables` against the block map `live`: every granule lies in
/// exactly one listed free block or one live block; each list links back
/// by its `prev` links from the head, whose `prev` is empty, and each listed
/// block's second word reads zero; no listed block's buddy is listed at its
/// order, so every join happened; a free bit is set exactly on a listed
/// block and a live bit exactly on a live block's first granule; every live
/// block sits at its order's alignment with its owner,
/// count and held prefix; and the free byte count equals the listed bytes.
fn judged(tables: &mut Tables, live: &BTreeMap<u32, Live>) -> Result<(), String> {
    let granules = tables.roots() * ROOT_GRANULES as usize;
    let roots = tables.roots() as u32;
    let mut cover = vec![None; granules];
    let mut free_bytes = 0;
    let arena = tables.arena();
    let mut lists = Vec::new();
    for order in 0..=10u32 {
        let listed = arena.listed(order);
        let mut prev = u32::MAX;
        for &(at, (_, back, second)) in &listed {
            if !at.is_multiple_of(1 << order) || at as usize >= granules {
                return Err(format!("free block {at} of order {order} is misplaced"));
            }
            if back != prev || second != 0 {
                return Err(format!(
                    "free block {at} of order {order} has links {back} {second}"
                ));
            }
            prev = at;
            for granule in at..at + (1 << order) {
                if cover[granule as usize].replace(("free", at)).is_some() {
                    return Err(format!("free block {at} of order {order} overlaps"));
                }
            }
            free_bytes += 32u64 << order;
        }
        lists.push(
            listed
                .iter()
                .map(|&(at, _)| at)
                .collect::<std::collections::BTreeSet<u32>>(),
        );
    }
    for (&at, block) in live {
        let order = order_for(block.count);
        if !at.is_multiple_of(1 << order) {
            return Err(format!("live block {at} is off its order's alignment"));
        }
        for granule in at..at + (1 << order) {
            match cover[granule as usize].replace(("live", at)) {
                Some(("free", free)) => {
                    return Err(format!("free block {free} aliases a live block at {at}"));
                }
                Some(_) => return Err(format!("live block {at} overlaps another")),
                None => {}
            }
        }
        let held = arena
            .held(Block(at), block.owner, block.count)
            .map_err(|e| format!("live block {at}: {e:?}"))?;
        if held != block.held {
            return Err(format!("live block {at} holds {held}"));
        }
        let expected: Vec<u64> = (0..held).map(|index| locator(at, index).bits()).collect();
        if arena.prefix(Block(at), block.owner, block.count) != Ok(&expected[..]) {
            return Err(format!("live block {at} lost a locator of its prefix"));
        }
    }
    if let Some(leaked) = cover.iter().position(Option::is_none) {
        return Err(format!("granule {leaked} is neither free nor live"));
    }
    for (order, set) in lists.iter().enumerate().take(10) {
        if let Some(at) = set.iter().find(|&&at| set.contains(&(at ^ (1 << order)))) {
            return Err(format!(
                "free block {at} of order {order} kept its free buddy"
            ));
        }
    }
    for root in 0..roots {
        for order in 0..=10u32 {
            for local in (0..ROOT_GRANULES).step_by(1 << order) {
                let at = root * ROOT_GRANULES + local;
                if arena.is_free(at, order) != lists[order as usize].contains(&at) {
                    return Err(format!("free bit of {at} at order {order} disagrees"));
                }
            }
        }
        for local in 0..ROOT_GRANULES {
            let at = root * ROOT_GRANULES + local;
            if arena.is_live(at) != live.contains_key(&at) {
                return Err(format!("live bit of {at} disagrees"));
            }
        }
    }
    if arena.free_bytes() != free_bytes {
        return Err(format!("free bytes {} of {free_bytes}", arena.free_bytes()));
    }
    Ok(())
}

/// The largest listed block's order, or `None` with every list empty.
fn largest_free(tables: &mut Tables) -> Option<u32> {
    let arena = tables.arena();
    (0..=10u32)
        .rev()
        .find(|&order| !arena.listed(order).is_empty())
}

/// Allocates `count` for `owner` under a budget of exactly the bound, and
/// checks the work meter and, on a refusal, the reason and that the tables
/// stayed unchanged.
fn allocate(tables: &mut Tables, owner: AllocationId, count: u32) -> Result<Block, ArenaError> {
    let before = tables.clone();
    let order = order_for(count);
    let lowest = (order..=10).find(|&at| !tables.arena().listed(at).is_empty());
    let mut budget = WorkBudget::new(BlockArena::ALLOCATE_STEPS);
    let result = tables.arena().allocate(owner, count, &mut budget);
    let work = budget.counters();
    assert!(work.visits <= 11 && work.updates <= 10, "{work:?}");
    let probes = lowest.map_or(11, |at| at + 1) - order;
    assert_eq!(
        work.visits, probes as usize,
        "a probe per order to the lowest listed"
    );
    match result {
        Ok(_) => assert_eq!(
            work.updates + 1,
            work.visits,
            "a split per order past the first probe"
        ),
        Err(error) => {
            assert_eq!(*tables, before, "{error:?} changed the arena");
            let block_bytes = 32u64 << order_for(count);
            let free_bytes = before.clone().arena().free_bytes();
            let fits =
                largest_free(&mut before.clone()).is_some_and(|order| order >= order_for(count));
            assert!(!fits, "{error:?} with a block free");
            assert_eq!(
                error,
                if free_bytes < block_bytes {
                    ArenaError::Exhausted {
                        free_bytes,
                        block_bytes,
                    }
                } else {
                    ArenaError::Fragmented {
                        free_bytes,
                        block_bytes,
                    }
                }
            );
        }
    }
    result
}

/// Frees `block` under a budget of exactly the bound, checking the meter.
fn free(
    tables: &mut Tables,
    block: u32,
    owner: AllocationId,
    count: u32,
) -> Result<(), ArenaError> {
    let before = tables.clone();
    // The joins the listed buddies predict, from the lists alone.
    let (mut order, mut at, mut joins) = (order_for(count), block, 0);
    while order < 10
        && tables
            .arena()
            .listed(order)
            .iter()
            .any(|&(b, _)| b == at ^ (1 << order))
    {
        (at, order, joins) = (at & !(1 << order), order + 1, joins + 1);
    }
    let mut budget = WorkBudget::new(BlockArena::FREE_STEPS);
    let result = tables.arena().free(Block(block), owner, count, &mut budget);
    let work = budget.counters();
    assert!(work.visits <= 10 && work.updates <= 11, "{work:?}");
    match result {
        Ok(()) => assert_eq!(
            (work.visits, work.updates),
            (joins + usize::from(order < 10), joins + 1),
            "a buddy check per join and one at the stop, an update per join and the release"
        ),
        Err(_) => assert_eq!(*tables, before, "{result:?} changed the arena"),
    }
    result
}

/// A count drawn so every order is reached: an order, then a count of it.
fn draw_count(rng: &mut SplitMix64) -> u32 {
    let order = rng.below(11) as u32;
    let counts = counts_of(order);
    counts.start() + rng.below(u64::from(counts.end() - counts.start() + 1)) as u32
}

#[test]
fn seeded_histories_match_the_block_map() {
    let mut reached = [false; 11];
    let (mut exhausted, mut fragmented, mut joined_to_root) = (0, 0, 0);
    let mut refused = [0; 4];
    for seed in 0..24u64 {
        let mut rng = SplitMix64::new(seed);
        let roots = 1 + rng.below(3) as usize;
        let mut tables = Tables::new(roots);
        let mut live = BTreeMap::new();
        let mut next_slot = 0;
        let mut freed: Option<(u32, Live)> = None;
        // Each step judges every node and granule, so 300 steps keep the
        // history short in a debug build.
        for step in 0..300 {
            match rng.below(10) {
                0..=4 => {
                    let count = draw_count(&mut rng);
                    let block = Live {
                        owner: owner(next_slot, seed as u32),
                        count,
                        held: 0,
                    };
                    next_slot += 1;
                    match allocate(&mut tables, block.owner, count) {
                        Ok(Block(at)) => {
                            reached[order_for(count) as usize] = true;
                            assert!(live.insert(at, block).is_none());
                        }
                        Err(ArenaError::Exhausted { .. }) => exhausted += 1,
                        Err(ArenaError::Fragmented { .. }) => fragmented += 1,
                        Err(other) => panic!("seed {seed} step {step}: {other:?}"),
                    }
                }
                5..=7 if !live.is_empty() => {
                    let at = *live
                        .keys()
                        .nth(rng.below(live.len() as u64) as usize)
                        .unwrap();
                    let block = live.remove(&at).unwrap();
                    free(&mut tables, at, block.owner, block.count).unwrap();
                    freed = Some((at, block));
                    if tables.arena().free_bytes() == roots as u64 * 32_768 {
                        joined_to_root += 1;
                    }
                }
                8 if !live.is_empty() => {
                    let at = *live
                        .keys()
                        .nth(rng.below(live.len() as u64) as usize)
                        .unwrap();
                    // An append or a pop keeps the prefix exact: a pop
                    // returns the last locator appended.
                    let block = live[&at];
                    let pushed = locator(at, block.held);
                    if rng.below(2) == 0 {
                        let result = tables
                            .arena()
                            .open(Block(at), block.owner, block.count)
                            .and_then(|mut prefix| prefix.push(pushed));
                        if block.held == block.count {
                            assert_eq!(result, Err(ArenaError::Full { count: block.count }));
                        } else {
                            assert_eq!(result, Ok(block.held + 1));
                            live.get_mut(&at).unwrap().held += 1;
                        }
                    } else {
                        let popped = tables
                            .arena()
                            .open(Block(at), block.owner, block.count)
                            .map(|mut prefix| prefix.pop())
                            .unwrap();
                        let last = block.held.checked_sub(1);
                        assert_eq!(popped, last.map(|index| (index, locator(at, index))));
                        if let Some(last) = last {
                            live.get_mut(&at).unwrap().held = last;
                        }
                    }
                }
                _ => {
                    // A stale owner, another slot, a bad count and a
                    // duplicate free each refuse with the arena unchanged.
                    if !live.is_empty() {
                        let at = *live
                            .keys()
                            .nth(rng.below(live.len() as u64) as usize)
                            .unwrap();
                        let block = live[&at];
                        let slot = block.owner.slot_index();
                        let stale = owner(slot, block.owner.incarnation() + 1);
                        let other_slot = owner(slot + 1_000_000, block.owner.incarnation());
                        for wrong in [stale, other_slot] {
                            assert!(matches!(
                                free(&mut tables, at, wrong, block.count),
                                Err(ArenaError::Owner { .. })
                            ));
                            let before = tables.clone();
                            let stale_push = tables
                                .arena()
                                .open(Block(at), wrong, block.count)
                                .and_then(|mut prefix| prefix.push(locator(at, 0)));
                            assert!(matches!(stale_push, Err(ArenaError::Owner { .. })));
                            let stale_pop = tables
                                .arena()
                                .open(Block(at), wrong, block.count)
                                .map(|mut prefix| prefix.pop());
                            assert!(matches!(stale_pop, Err(ArenaError::Owner { .. })));
                            assert_eq!(tables, before, "a refused append or pop changed the arena");
                        }
                        refused[0] += 1;
                        let other = if block.count == 2 { 3 } else { block.count - 1 };
                        let result = free(&mut tables, at, block.owner, other);
                        if order_for(other) == order_for(block.count) {
                            let found = block.count;
                            assert_eq!(
                                result,
                                Err(ArenaError::HeaderCount {
                                    expected: other,
                                    found
                                })
                            );
                            refused[1] += 1;
                        } else {
                            // Another order names another node: off its
                            // alignment, a free node, or header words that
                            // record no such owner and count.
                            assert!(result.is_err(), "{result:?}");
                            refused[2] += 1;
                        }
                    }
                    if let Some((at, block)) = freed.take()
                        && !live.contains_key(&at)
                    {
                        assert!(matches!(
                            free(&mut tables, at, block.owner, block.count),
                            Err(ArenaError::NotLive { .. })
                        ));
                        refused[3] += 1;
                    }
                }
            }
            judged(&mut tables, &live).unwrap_or_else(|e| panic!("seed {seed} step {step}: {e}"));
        }
        for (at, block) in std::mem::take(&mut live) {
            free(&mut tables, at, block.owner, block.count).unwrap();
        }
        judged(&mut tables, &live).unwrap();
        assert!(whole(&mut tables), "seed {seed}: every root joins whole");
    }
    assert!(reached.iter().all(|&r| r), "{reached:?}");
    assert!(exhausted > 0 && fragmented > 0 && joined_to_root > 0);
    assert!(refused.iter().all(|&n| n > 0), "{refused:?}");
}

/// A block's buddy joins only while its free bit is set. The planted join
/// that skips the bit lists the parent over the live buddy, and the block
/// map rejects the alias.
#[test]
fn negative_control_joining_an_allocated_buddy_aliases_a_live_block() {
    let mut tables = Tables::new(1);
    let (a, b) = (owner(0, 1), owner(1, 1));
    let Block(first) = allocate(&mut tables, a, 2).unwrap();
    let Block(second) = allocate(&mut tables, b, 2).unwrap();
    assert_eq!(first ^ 1, second, "two locators fit 32-byte buddies");
    let held = |owner| Live {
        owner,
        count: 2,
        held: 0,
    };
    let mut live = BTreeMap::from([(first, held(a)), (second, held(b))]);
    judged(&mut tables, &live).unwrap();
    live.remove(&first);
    let mut planted = tables.clone();
    // The planted join: the parent is listed without checking the buddy.
    planted.arena().plant_link(first & !1, 1);
    assert_eq!(
        judged(&mut planted, &live),
        Err(format!(
            "free block {} aliases a live block at {second}",
            first & !1
        ))
    );
    free(&mut tables, first, a, 2).unwrap();
    judged(&mut tables, &live).unwrap();
    assert!(
        tables.arena().is_free(first, 0),
        "an allocated buddy keeps the block at its order"
    );
}

/// The closed-form order of every extent count, two through the largest
/// object's 2,115, is the smallest order whose block holds the header and
/// its locators, found by doubling from the smallest block.
#[test]
fn every_count_takes_the_smallest_order_that_holds_it() {
    for count in 2..=2115 {
        assert_eq!(
            block_order(u64::from(count)),
            u64::from(order_for(count)),
            "count {count}"
        );
    }
}

/// The largest object's sequence takes one whole root, and a full arena
/// refuses `Exhausted` with every byte allocated; an allocation or a free
/// the budget cannot fund refuses `Budget` with the arena unchanged, and a
/// second free of the same block refuses `NotLive`.
#[test]
fn the_largest_sequence_takes_a_root_and_the_budget_preflights_the_bound() {
    let mut tables = Tables::new(2);
    assert_eq!(order_for(2115), 10);
    let roots: Vec<Block> = (0..2)
        .map(|slot| allocate(&mut tables, owner(slot, 1), 2115).unwrap())
        .collect();
    assert_eq!(roots, [Block(0), Block(ROOT_GRANULES)]);
    assert_eq!(
        allocate(&mut tables, owner(9, 1), 2),
        Err(ArenaError::Exhausted {
            free_bytes: 0,
            block_bytes: 32
        })
    );
    let mut tables = Tables::new(1);
    let before = tables.clone();
    let mut short = WorkBudget::new(BlockArena::ALLOCATE_STEPS - 1);
    assert_eq!(
        tables.arena().allocate(owner(0, 1), 2, &mut short),
        Err(ArenaError::Budget)
    );
    assert_eq!(tables, before);
    let mut whole = WorkBudget::new(BlockArena::ALLOCATE_STEPS);
    let Block(at) = tables.arena().allocate(owner(0, 1), 2, &mut whole).unwrap();
    assert_eq!(
        whole.counters().visits,
        11,
        "the empty lists below the root are probed"
    );
    assert_eq!(
        whole.counters().updates,
        10,
        "the root splits down to order 0"
    );
    let mut short = WorkBudget::new(BlockArena::FREE_STEPS - 1);
    let full = tables.clone();
    assert_eq!(
        tables.arena().free(Block(at), owner(0, 1), 2, &mut short),
        Err(ArenaError::Budget)
    );
    assert_eq!(tables, full);
    let mut whole = WorkBudget::new(BlockArena::FREE_STEPS);
    tables
        .arena()
        .free(Block(at), owner(0, 1), 2, &mut whole)
        .unwrap();
    assert_eq!(
        (whole.counters().visits, whole.counters().updates),
        (10, 11)
    );
    assert_eq!(
        tables, before,
        "the free releases the block once and joins the root whole"
    );
    assert_eq!(
        free(&mut tables, at, owner(0, 1), 2),
        Err(ArenaError::NotLive { block: Block(at) })
    );
}

#[test]
fn a_whole_root_free_debits_its_release_from_a_shared_budget() {
    let mut tables = Tables::new(2);
    for slot in 0..2 {
        allocate(&mut tables, owner(slot, 1), 2115).unwrap();
    }
    let mut shared = WorkBudget::new(BlockArena::FREE_STEPS);
    tables
        .arena()
        .free(Block(0), owner(0, 1), 2115, &mut shared)
        .unwrap();
    assert_eq!(
        (shared.counters().visits, shared.counters().updates),
        (0, 1),
        "a root at the top checks no buddy and charges its release"
    );
    let before = tables.clone();
    assert_eq!(
        tables
            .arena()
            .free(Block(ROOT_GRANULES), owner(1, 1), 2115, &mut shared),
        Err(ArenaError::Budget)
    );
    assert_eq!(tables, before, "a refused free changed the arena");
}

/// Counts outside `2..=2115`, misplaced blocks, a wrong count, an append
/// to a full prefix and a planted header prefix past its count refuse with
/// their own variants.
#[test]
fn malformed_requests_refuse_typed() {
    let mut tables = Tables::new(1);
    let mut budget = WorkBudget::new(1 << 10);
    for count in [0, 1, 2116] {
        assert_eq!(
            tables.arena().allocate(owner(0, 1), count, &mut budget),
            Err(ArenaError::Count { count })
        );
    }
    let Block(at) = allocate(&mut tables, owner(0, 1), 6).unwrap();
    assert_eq!(order_for(6), 1);
    let arena = tables.arena();
    assert_eq!(
        arena.held(Block(at + 1), owner(0, 1), 6),
        Err(ArenaError::Range {
            block: Block(at + 1)
        })
    );
    assert_eq!(
        arena.held(Block(ROOT_GRANULES), owner(0, 1), 6),
        Err(ArenaError::Range {
            block: Block(ROOT_GRANULES)
        })
    );
    assert_eq!(
        arena.held(Block(at), owner(0, 1), 5),
        Err(ArenaError::HeaderCount {
            expected: 5,
            found: 6
        })
    );
    for index in 0..6 {
        let pushed = tables
            .arena()
            .open(Block(at), owner(0, 1), 6)
            .and_then(|mut prefix| prefix.push(locator(at, index)));
        assert_eq!(pushed, Ok(index + 1));
    }
    assert_eq!(
        tables
            .arena()
            .open(Block(at), owner(0, 1), 6)
            .and_then(|mut prefix| prefix.push(locator(at, 6))),
        Err(ArenaError::Full { count: 6 })
    );
    assert_eq!(tables.arena().held(Block(at), owner(0, 1), 6), Ok(6));
    let expected: Vec<u64> = (0..6).map(|index| locator(at, index).bits()).collect();
    assert_eq!(
        tables.arena().prefix(Block(at), owner(0, 1), 6),
        Ok(&expected[..])
    );
    let mut corrupt = tables.clone();
    corrupt.arena().plant_word(at as usize * 4 + 1, 6 | 7 << 32);
    assert_eq!(
        corrupt.arena().held(Block(at), owner(0, 1), 6),
        Err(ArenaError::Corrupt { held: 7, count: 6 })
    );
}

/// A storage lays the arena out in its control mapping: one list record,
/// line-aligned root words and bit words sized by its roots, and every root
/// listed free at order 10.
#[test]
fn a_storage_lays_out_its_roots_free() {
    let mut config = storage_config(4);
    config.volume.block_roots = 3;
    let storage = Storage::initialize(
        &config.validate().unwrap(),
        &PlacementConfig { control_home: 0 },
        TestPlatform::heap(PAGE),
    )
    .unwrap();
    let inventory = storage.table_inventory().unwrap();
    assert_eq!(inventory.block_words.1, 3 * ROOT_WORDS);
    assert_eq!(inventory.block_bits.1, 3 * BIT_WORDS);
    assert_eq!(inventory.block_lists.1, 1);
    assert!(inventory.block_words.0.is_multiple_of(64));
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let arena = tables.blocks();
    assert_eq!(arena.free_bytes(), 3 * 32_768);
    let roots: Vec<u32> = arena.listed(10).into_iter().map(|(at, _)| at).collect();
    assert_eq!(roots, [0, ROOT_GRANULES, 2 * ROOT_GRANULES]);
}

/// A handle that names no live block's start refuses `NotLive` even when
/// the words there spell a matching header: a freed block's granule, now
/// the start of the order-1 block its join formed, and a granule inside a
/// live block whose body holds the header words a stale owner expects.
#[test]
fn a_stale_handle_refuses_whatever_words_it_finds() {
    let mut tables = Tables::new(1);
    let (stale, big) = (owner(0, 1), owner(1, 1));
    let Block(freed) = allocate(&mut tables, stale, 2).unwrap();
    let Block(live) = allocate(&mut tables, big, 6).unwrap();
    assert_eq!(order_for(6), 1);
    free(&mut tables, freed, stale, 2).unwrap();
    assert!(
        tables.arena().is_free(freed & !1, 1),
        "the freed block joined its buddy"
    );
    let fake = [stale.record_tag(), 2];
    for at in [freed, live + 1] {
        let mut planted = tables.clone();
        let mut arena = planted.arena();
        arena.plant_word(at as usize * 4, fake[0]);
        arena.plant_word(at as usize * 4 + 1, fake[1]);
        let before = planted.clone();
        assert_eq!(
            planted.arena().held(Block(at), stale, 2),
            Err(ArenaError::NotLive { block: Block(at) })
        );
        assert_eq!(
            free(&mut planted, at, stale, 2),
            Err(ArenaError::NotLive { block: Block(at) })
        );
        assert_eq!(planted, before, "{at}");
    }
}

#[test]
fn popping_an_open_prefix_keeps_the_held_prefix_exact_at_every_step() {
    let mut tables = Tables::new(1);
    let (held, other) = (owner(2, 4), owner(3, 4));
    let block = allocate(&mut tables, held, 5).unwrap();
    let appended: Vec<ExtentLocator> = (0..5).map(|index| locator(block.0, index)).collect();
    for &extent in &appended {
        tables
            .arena()
            .open(block, held, 5)
            .and_then(|mut prefix| prefix.push(extent))
            .unwrap();
    }
    let before = tables.clone();
    assert_eq!(
        tables.arena().open(block, other, 5).err(),
        Some(ArenaError::Owner {
            expected: other.record_tag(),
            found: held.record_tag(),
        })
    );
    assert_eq!(tables, before);
    let mut arena = tables.arena();
    let mut prefix = arena.open(block, held, 5).unwrap();
    let popped = [prefix.pop(), prefix.pop()];
    assert_eq!(popped, [Some((4, appended[4])), Some((3, appended[3]))]);
    assert_eq!(arena.held(block, held, 5), Ok(3));
    let bits: Vec<u64> = appended[..3].iter().map(|extent| extent.bits()).collect();
    assert_eq!(arena.prefix(block, held, 5), Ok(&bits[..]));
    let mut prefix = arena.open(block, held, 5).unwrap();
    let rest: Vec<_> = std::iter::from_fn(|| prefix.pop()).collect();
    assert_eq!(rest, [(2, appended[2]), (1, appended[1]), (0, appended[0])]);
    assert_eq!(prefix.pop(), None);
    assert_eq!(arena.held(block, held, 5), Ok(0));
}
