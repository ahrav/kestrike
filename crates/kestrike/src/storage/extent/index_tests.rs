//! Synthetic run starts beyond the 64-unit volume let the tests exercise index capacity independently of volume size.

use std::collections::BTreeSet;

use super::super::seeded::SplitMix64;
use super::ExtentAllocator;
use super::allocator_tests::Tables;
use super::index::{SATURATED, TREES, index_height, key_run, run_key, spread};

fn length(rng: &mut SplitMix64) -> u64 {
    match rng.below(10) {
        0..=4 => 1,
        5 => 2,
        6 => 3 + rng.below(TREES as u64 - 3),
        7 | 8 => TREES as u64 + rng.below(4000),
        _ => SATURATED + rng.below(3),
    }
}

#[derive(Default)]
struct Seen {
    takes: usize,
    long_takes: usize,
    misses: usize,
    unindexed: usize,
    drops: usize,
    deepest: u64,
}

/// The index's own offer: a full index keeps the larger of the offered run and its smallest entry.
fn offer(index: &mut ExtentAllocator<'_>, start: u64, len: u64) {
    index.offer(start, len);
}

/// A seeded history of offers, best-fit takes and removals through `offer`, checked against an ordered set of keys.
fn history(
    seed: u64,
    capacity: usize,
    steps: usize,
    every: usize,
    offer: fn(&mut ExtentAllocator<'_>, u64, u64),
) -> Seen {
    let mut tables = Tables::new(64, capacity * 8);
    let mut index = tables.init();
    let height = index_height(capacity) as usize;
    let mut model = BTreeSet::from([run_key(0, 64)]);
    let mut rng = SplitMix64::new(seed);
    let mut seen = Seen::default();
    let mut starts = 1u64 << 39;
    for step in 0..steps {
        let at = format!("seed {seed} step {step}");
        let offers = if (step / (steps / 4)).is_multiple_of(2) {
            6
        } else {
            2
        };
        match rng.below(8) {
            draw if draw < offers || model.is_empty() => {
                let len = length(&mut rng);
                starts += 1 + rng.below(3);
                let key = run_key(starts, len);
                let full = model.len() == capacity;
                let drops = index.drops();
                index.work = 0;
                offer(&mut index, starts, len);
                if full {
                    assert!(
                        index.work <= 1 + 3 * height + height + 1 + 2 * height + 3,
                        "{at}"
                    );
                    assert_eq!(index.drops(), drops + 1, "{at}");
                    seen.drops += 1;
                    let smallest = *model.first().expect("a full index holds a key");
                    if key > smallest {
                        model.remove(&smallest);
                        model.insert(key);
                    }
                } else {
                    assert!(index.work <= height + 1 + 2 * height + 3, "{at}");
                    model.insert(key);
                }
            }
            draw if draw < 6 => {
                let n = match rng.below(4) {
                    0 => 1 + rng.below(3),
                    1 => 1 + rng.below(TREES as u64),
                    2 => TREES as u64 + rng.below(4000),
                    _ => SATURATED,
                };
                let expected = model.range(run_key(0, n)..).next().copied();
                index.work = 0;
                let found = index.index_best_fit(n);
                assert!(index.work <= 3 * height + 1, "{at}");
                assert_eq!(
                    found.map(|found| found.key),
                    expected,
                    "{at}: best fit for {n}"
                );
                let Some(found) = found else {
                    seen.misses += 1;
                    continue;
                };
                index.work = 0;
                index.index_remove(found);
                assert!(index.work <= 3 * height, "{at}");
                model.remove(&found.key);
                seen.takes += 1;
                seen.long_takes += usize::from(n >= TREES as u64);
            }
            _ => {
                let pick = rng.below(model.len().max(1) as u64) as usize;
                let (start, len) = match model.iter().nth(pick) {
                    Some(&key) if rng.below(4) > 0 => key_run(key),
                    _ => (starts + 1, 1 + rng.below(100)),
                };
                index.work = 0;
                index.unindex(start, len);
                assert!(index.work <= height + 1 + 3 * height, "{at}");
                seen.unindexed += usize::from(model.remove(&run_key(start, len)));
            }
        }
        seen.deepest = seen.deepest.max(index.deepest());
        if step % every == 0 {
            index.index_check();
            assert_eq!(
                index.index_keys(),
                model.iter().copied().collect::<Vec<_>>(),
                "{at}"
            );
        }
    }
    index.index_check();
    assert_eq!(index.index_keys(), model.into_iter().collect::<Vec<_>>());
    seen
}

#[test]
fn index_histories_agree_with_an_ordered_set() {
    let mut total = Seen::default();
    for seed in 1..=4 {
        let seen = history(seed, 3000, 40_000, 97, offer);
        total.takes += seen.takes;
        total.long_takes += seen.long_takes;
        total.misses += seen.misses;
        total.unindexed += seen.unindexed;
        total.drops += seen.drops;
        total.deepest = total.deepest.max(seen.deepest);
    }
    assert!(total.takes > 0 && total.long_takes > 0 && total.misses > 0);
    assert!(total.unindexed > 0 && total.drops > 0);
    assert!(
        total.deepest >= 3,
        "trees reached {} inner levels",
        total.deepest
    );
}

#[test]
fn small_index_histories_agree_with_an_ordered_set() {
    for capacity in [1, 2, 15, 16, 17, 40] {
        for seed in 1..=3 {
            history(seed, capacity, 3_000, 1, offer);
        }
    }
}

/// A full index that removes its smallest entry for every offered run, a smaller one included.
fn offer_that_always_evicts(index: &mut ExtentAllocator<'_>, start: u64, len: u64) {
    if !index.index_full() {
        index.offer(start, len);
        return;
    }
    index.root.drops += 1;
    let smallest = index.index_best_fit(1).expect("a full index holds a key");
    index.index_remove(smallest);
    index.index_insert(start, len);
}

/// Planted defect: a full index evicts its smallest entry for an offered run that is smaller still, so it holds a key the ordered set left out, and the history fails at its best-fit comparison.
#[test]
#[should_panic(expected = "best fit for")]
fn negative_control_a_full_offer_that_always_evicts_fails_the_best_fit() {
    history(1, 2, 3_000, usize::MAX, offer_that_always_evicts);
}

/// Children spread over the parents of one level give each parent between 5 and 11 children and cover every child once, at child counts whose `part * count` products pass `u32::MAX`.
#[test]
fn spread_children_fill_every_parent_within_its_bounds() {
    for count in [2, 11, 12, 121, 3_000_000, u32::MAX / 2] {
        let parents = count.div_ceil(11);
        assert_eq!(
            (spread(0, count, parents), spread(parents, count, parents)),
            (0, count)
        );
        let least = if parents == 1 { 2 } else { 5 };
        for part in (0..parents).step_by((parents as usize / 4096).max(1)) {
            let taken = spread(part + 1, count, parents) - spread(part, count, parents);
            assert!(
                (least..=11).contains(&taken),
                "{count} children, parent {part} takes {taken}"
            );
        }
    }
}
