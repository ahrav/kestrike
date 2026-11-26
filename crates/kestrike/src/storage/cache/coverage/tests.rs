//! Coverage holds a version exactly when it lies in an interval or hull of its key or on a saturated page; a merge
//! saturates when its encoded page exceeds `Limits::page_bytes`.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU16, NonZeroU32};

use super::super::super::seeded::SplitMix64;
use super::{
    Coverage, Draft, Entry, Fencing, Held, Interval, KeyHash, Limits, Marks, Progress,
    REMOVAL_SHARE, decode_entries, encode_entries, merge, merge_each, merged, page_len, page_of,
};
use crate::failover::records::{CoveragePage, Record, ShardRecord};
use crate::storage::store::sim::Shared;
use crate::storage::store_tests::{client, page, record};
use crate::storage::{CacheVersion, session_at};

const PAGES: NonZeroU16 = NonZeroU16::new(4).unwrap();
const MANY: NonZeroU16 = NonZeroU16::new(64).unwrap();

fn key(rng: &mut SplitMix64, page: u16) -> [u8; 32] {
    key_among(rng, PAGES, page)
}

pub(super) fn key_among(rng: &mut SplitMix64, pages: NonZeroU16, page: u16) -> [u8; 32] {
    let mut key = [0; 32];
    for byte in &mut key {
        *byte = rng.next_u64() as u8;
    }
    let head = rng.next_u64() / u64::from(pages.get()) * u64::from(pages.get()) + u64::from(page);
    key[..8].copy_from_slice(&head.to_le_bytes());
    key
}

pub(super) fn interval(low: u64, high: u64) -> Interval {
    Interval::new(CacheVersion(low), CacheVersion(high)).unwrap()
}

/// On an unsaturated page, coverage requires the full key and a version within one of that key's intervals or its
/// hull; a key sharing the covered key's first 8 bytes is covered once the page saturates.
#[test]
fn membership_over_intervals_hulls_and_saturation() {
    let mut rng = SplitMix64::new(0x1289);
    let limits = Limits {
        intervals: 2,
        page_bytes: 1 << 20,
    };
    for case in 0..512 {
        let mut coverage = Coverage::new(PAGES, limits);
        let covered = key(&mut rng, 0);
        let other = key(&mut rng, 1);
        let mut sibling = covered;
        sibling[31] ^= 1;
        assert_eq!(
            (
                page_of(&covered, PAGES),
                page_of(&other, PAGES),
                page_of(&sibling, PAGES)
            ),
            (0, 1, 0)
        );
        let low = rng.below(1 << 40);
        let first = interval(low, low + rng.below(16));
        let gap = first.high().0 + 2 + rng.below(16);
        let second = interval(gap, gap + rng.below(16));
        let one = merged(&CoveragePage::default(), (covered, first), limits).unwrap();
        let page = merged(&one, (covered, second), limits).unwrap();
        assert!(coverage.absorb(0, &page), "case {case}");
        for version in [first.low(), first.high(), second.low(), second.high()] {
            assert!(
                coverage.covers(&covered, version),
                "case {case} {version:?}"
            );
            assert!(!coverage.covers(&sibling, version), "case {case}: sibling");
        }
        for version in [
            first.low().0.wrapping_sub(1),
            first.high().0 + 1,
            second.high().0 + 1,
        ] {
            assert!(
                !coverage.covers(&covered, CacheVersion(version)),
                "case {case} {version}"
            );
        }
        assert!(!coverage.covers(&other, first.low()), "case {case}");

        let exact = page.encode().len();
        let fits = Limits {
            intervals: 8,
            page_bytes: exact,
        };
        assert_eq!(
            merged(&one, (covered, second), fits).as_ref(),
            Some(&page),
            "case {case}: a merge of exactly page_bytes keeps its entries"
        );
        let over = Limits {
            page_bytes: exact - 1,
            ..fits
        };
        let saturated_merge = merged(&one, (covered, second), over).unwrap();
        assert!(
            saturated_merge.saturated && saturated_merge.entries.is_empty(),
            "case {case}: one byte less saturates"
        );

        let far = second.high().0 + 10;
        let third = interval(far, far);
        let hulled = merged(&page, (covered, third), limits).unwrap();
        let entries = decode_entries(&hulled.entries).unwrap();
        let hull = interval(first.low().0, far);
        assert_eq!(entries, [(covered, hull)], "case {case}");
        assert!(coverage.absorb(0, &hulled));
        assert!(
            coverage.covers(&covered, CacheVersion(first.high().0 + 1)),
            "case {case}: inside the hull"
        );
        assert!(
            !coverage.covers(&covered, CacheVersion(far + 1)),
            "case {case}: past the hull"
        );
        assert!(!coverage.covers(&sibling, first.low()), "case {case}");
        let mut only_hull = Coverage::new(PAGES, limits);
        only_hull.add(covered, hull);
        assert_eq!(
            coverage, only_hull,
            "case {case}: the hull replaces the intervals it contains"
        );

        let overflow = merged(&page, (covered, third), fits).unwrap();
        assert!(
            overflow.saturated && overflow.entries.is_empty(),
            "case {case}"
        );
        let mut saturated = Coverage::new(PAGES, limits);
        assert!(saturated.absorb(0, &overflow));
        for probe in [&covered, &sibling] {
            assert!(
                saturated.covers(probe, CacheVersion(rng.next_u64())),
                "case {case}: saturated page"
            );
        }
        assert!(
            !saturated.covers(&other, first.low()),
            "case {case}: another page"
        );
        assert!(coverage.absorb(0, &overflow));
        assert_eq!(
            coverage, saturated,
            "case {case}: saturation drops the page's keys"
        );
        coverage.add(sibling, third);
        assert_eq!(
            coverage, saturated,
            "case {case}: a saturated page holds no interval"
        );
    }
}

#[test]
fn absorb_refuses_a_page_past_b_or_a_key_of_another_page() {
    let limits = Limits {
        intervals: 2,
        page_bytes: 1 << 20,
    };
    let mut rng = SplitMix64::new(0x1383);
    let on_one = (key(&mut rng, 1), interval(1, 2));
    let misplaced = CoveragePage {
        entries: encode_entries(&[on_one]),
        ..CoveragePage::default()
    };
    let mut coverage = Coverage::new(PAGES, limits);
    assert!(!coverage.absorb(0, &misplaced));
    assert!(!coverage.absorb(PAGES.get(), &CoveragePage::default()));
    assert_eq!(coverage, Coverage::new(PAGES, limits));
    assert!(coverage.absorb(1, &misplaced));
    assert!(coverage.covers(&on_one.0, CacheVersion(2)));
}

#[test]
fn merged_replaces_the_intervals_a_new_interval_contains() {
    let limits = Limits {
        intervals: 4,
        page_bytes: 1 << 20,
    };
    let mut rng = SplitMix64::new(0x1384);
    let k = key(&mut rng, 0);
    let inner = merged(&CoveragePage::default(), (k, interval(3, 4)), limits).unwrap();
    let outer = merged(&inner, (k, interval(1, 9)), limits).unwrap();
    assert_eq!(
        decode_entries(&outer.entries).unwrap(),
        [(k, interval(1, 9))]
    );
    assert_eq!(merged(&outer, (k, interval(2, 8)), limits), Some(outer));
}

/// Coverage bounds its in-memory state: a key's disjoint intervals past `intervals` become their hull, and a page
/// whose held intervals would encode past `page_bytes` saturates.
#[test]
fn coverage_holds_its_hull_and_page_bounds() {
    let limits = Limits {
        intervals: 2,
        page_bytes: page_len(4),
    };
    let mut rng = SplitMix64::new(0x1385);
    let mut coverage = Coverage::new(PAGES, limits);
    let k = key(&mut rng, 0);
    for low in [1, 10, 20, 30] {
        coverage.add(k, interval(low, low));
    }
    assert_eq!(
        coverage.intervals_of(&k),
        [interval(1, 20), interval(30, 30)]
    );
    assert!(coverage.covers(&k, CacheVersion(15)));
    let others: Vec<_> = (0..3).map(|_| key(&mut rng, 0)).collect();
    for (n, other) in (0..).zip(&others[..2]) {
        coverage.add(*other, interval(n, n));
    }
    assert!(!coverage.saturated[0]);
    coverage.add(others[2], interval(0, 0));
    assert!(coverage.saturated[0] && coverage.entries().is_empty());
    assert!(coverage.covers(&key(&mut rng, 0), CacheVersion(u64::MAX)));
}

fn slots_of(coverage: &Coverage) -> BTreeMap<Entry, usize> {
    coverage
        .full_slots()
        .map(|at| (coverage.slots[at], at))
        .collect()
}

#[test]
fn saturation_frees_only_the_page_slots_in_place() {
    let limits = Limits {
        intervals: 2,
        page_bytes: 1 << 20,
    };
    let mut rng = SplitMix64::new(0x1289_0004);
    let mut coverage = Coverage::new(MANY, limits);
    let entries: Vec<Entry> = (0..600)
        .map(|n| {
            let low = rng.below(1 << 20);
            (
                key_among(&mut rng, MANY, n % MANY.get()),
                interval(low, low + 3),
            )
        })
        .collect();
    for &(key, interval) in &entries {
        coverage.add(key, interval);
    }
    let before = slots_of(&coverage);
    assert_eq!(before.len(), entries.len());
    let table = (
        coverage.control.as_ptr(),
        coverage.slots.as_ptr(),
        coverage.control.len(),
    );

    coverage.saturate(0);

    assert_eq!(
        (
            coverage.control.as_ptr(),
            coverage.slots.as_ptr(),
            coverage.control.len()
        ),
        table,
        "saturation keeps the table's allocation"
    );
    let kept: BTreeMap<Entry, usize> = before
        .into_iter()
        .filter(|((key, _), _)| page_of(key, MANY) != 0)
        .collect();
    assert_eq!(
        slots_of(&coverage),
        kept,
        "every other page's entry keeps its slot"
    );
    assert_eq!(coverage.full, kept.len());
    assert_eq!(coverage.on_page[0], 0);
    for &(key, interval) in &entries {
        assert!(coverage.covers(&key, interval.low()));
        assert_eq!(
            coverage.covers(&key, CacheVersion(interval.high().0 + 1)),
            page_of(&key, MANY) == 0,
            "only the saturated page covers past an interval"
        );
    }
}

#[test]
fn saturations_rebuild_once_per_share_of_removals() {
    let limits = Limits {
        intervals: 2,
        page_bytes: 1 << 20,
    };
    let mut rng = SplitMix64::new(0x1289_0005);
    let mut coverage = Coverage::new(MANY, limits);
    let mut entries: Vec<Entry> = (0..7168u16)
        .map(|n| {
            let page = n % MANY.get();
            (
                key_among(&mut rng, MANY, page),
                interval(n.into(), n.into()),
            )
        })
        .collect();
    for &(key, interval) in &entries {
        coverage.add(key, interval);
    }
    let groups = coverage.control.len();
    assert_eq!(
        coverage.full * 8,
        groups * 8 * 7,
        "the table is seven eighths full"
    );
    let mut rebuilds = 0;
    for page in 0..MANY.get() - 1 {
        let slots_at = coverage.slots.as_ptr();
        coverage.saturate(page);
        rebuilds += usize::from(coverage.slots.as_ptr() != slots_at);
        assert!(
            coverage.removed * REMOVAL_SHARE <= groups * 8 && coverage.deleted <= coverage.removed,
            "page {page}: {} removed and {} deleted of {} slots",
            coverage.removed,
            coverage.deleted,
            groups * 8
        );
        assert_eq!(coverage.control.len(), groups, "page {page}");
        let fresh = (key_among(&mut rng, MANY, MANY.get() - 1), interval(9, 9));
        coverage.add(fresh.0, fresh.1);
        entries.push(fresh);
        for &(key, interval) in &entries {
            assert!(coverage.covers(&key, interval.low()), "page {page}");
            assert_eq!(
                coverage.covers(&key, CacheVersion(u64::MAX)),
                page_of(&key, MANY) <= page,
                "page {page}"
            );
        }
    }
    let share = groups * 8 / REMOVAL_SHARE;
    let per_page = 7168 / usize::from(MANY.get());
    let per_rebuild = share / per_page + 1;
    assert_eq!(
        rebuilds,
        63 / per_rebuild,
        "{rebuilds} rebuilds over 63 saturations of {per_page} entries with a share of {share} slots"
    );
}

#[test]
fn entry_codec_bytes() {
    let entries = [(
        [7; 32],
        interval(0x0102_0304_0506_0708, 0x1112_1314_1516_1718),
    )];
    let mut bytes = vec![7; 32];
    bytes.extend([8, 7, 6, 5, 4, 3, 2, 1]);
    bytes.extend([0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]);
    assert_eq!(encode_entries(&entries), bytes);
    assert_eq!(decode_entries(&bytes).unwrap(), entries);
    assert_eq!(decode_entries(&bytes[..47]), None);
    let mut inverted = bytes;
    inverted[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(decode_entries(&inverted), None);
    assert_eq!(Interval::new(CacheVersion(5), CacheVersion(4)), None);
}

/// SetModel stores an interval antichain for each key and tracks saturated pages.
struct SetModel {
    limits: Limits,
    keys: BTreeMap<[u8; 32], BTreeSet<Interval>>,
    on_page: Vec<usize>,
    saturated: Vec<bool>,
}

impl SetModel {
    fn new(limits: Limits) -> Self {
        let pages = usize::from(PAGES.get());
        Self {
            limits,
            keys: BTreeMap::new(),
            on_page: vec![0; pages],
            saturated: vec![false; pages],
        }
    }

    fn add(&mut self, key: [u8; 32], interval: Interval) {
        let page = page_of(&key, PAGES);
        let at = usize::from(page);
        if self.saturated[at] {
            return;
        }
        let held = self.keys.entry(key).or_default();
        if held.iter().any(|other| interval.within(*other)) {
            return;
        }
        let before = held.len();
        held.retain(|other| !other.within(interval));
        held.insert(interval);
        if held.len() > self.limits.intervals {
            let hull = held.iter().fold(interval, |hull, other| hull.hull(*other));
            held.clear();
            held.insert(hull);
        }
        self.on_page[at] = self.on_page[at] - before + held.len();
        if page_len(self.on_page[at]) > self.limits.page_bytes {
            self.saturate(page);
        }
    }

    fn saturate(&mut self, page: u16) {
        let at = usize::from(page);
        if !self.saturated[at] {
            self.saturated[at] = true;
            self.on_page[at] = 0;
            self.keys.retain(|key, _| page_of(key, PAGES) != page);
        }
    }

    fn covers(&self, key: &[u8; 32], version: CacheVersion) -> bool {
        self.saturated[usize::from(page_of(key, PAGES))]
            || self
                .keys
                .get(key)
                .is_some_and(|held| held.iter().any(|interval| interval.contains(version)))
    }

    fn entries(&self) -> Vec<Entry> {
        self.keys
            .iter()
            .flat_map(|(key, held)| held.iter().map(|&interval| (*key, interval)))
            .collect()
    }
}

#[test]
fn coverage_matches_a_set_model_through_growth_removal_and_saturation() {
    let mut rng = SplitMix64::new(0x1289_0002);
    for case in 0..48 {
        let limits = Limits {
            intervals: 1 + rng.below(3) as usize,
            page_bytes: page_len([6, 40, 160, 4096][rng.below(4) as usize]),
        };
        let mut coverage = Coverage::new(PAGES, limits);
        let mut model = SetModel::new(limits);
        let keys: Vec<[u8; 32]> = (0..240).map(|n| key(&mut rng, n % PAGES.get())).collect();
        for step in 0..1500 {
            if rng.below(40) == 0 {
                let page = rng.below(u64::from(PAGES.get())) as u16;
                let entries: Vec<Entry> = (0..rng.below(6))
                    .map(|_| {
                        let low = rng.below(48);
                        let fresh = key(&mut rng, page);
                        let key = if rng.below(2) == 0 {
                            fresh
                        } else {
                            let at =
                                rng.below(keys.len() as u64 / 4) as usize * 4 + usize::from(page);
                            keys[at]
                        };
                        (key, interval(low, low + rng.below(4)))
                    })
                    .collect();
                let value = CoveragePage {
                    fence: 0,
                    saturated: rng.below(8) == 0,
                    entries: encode_entries(&entries),
                };
                let value = if value.saturated {
                    CoveragePage {
                        entries: Vec::new(),
                        ..value
                    }
                } else {
                    value
                };
                assert!(coverage.absorb(page, &value), "case {case} step {step}");
                if value.saturated {
                    model.saturate(page);
                } else {
                    for (key, interval) in entries {
                        model.add(key, interval);
                    }
                }
            } else {
                let key = keys[rng.below(keys.len() as u64) as usize];
                let low = rng.below(48);
                let entry = interval(low, low + rng.below(6));
                coverage.add(key, entry);
                model.add(key, entry);
            }
            assert_eq!(coverage.on_page, model.on_page, "case {case} step {step}");
            assert_eq!(
                coverage.saturated, model.saturated,
                "case {case} step {step}"
            );
            if step % 50 == 0 {
                assert_eq!(
                    coverage.entries(),
                    model.entries(),
                    "case {case} step {step}"
                );
                for probe in &keys {
                    for version in [0, 7, 23, 47, 53] {
                        let version = CacheVersion(version);
                        assert_eq!(
                            coverage.covers(probe, version),
                            model.covers(probe, version),
                            "case {case} step {step}"
                        );
                    }
                }
            }
        }
        assert_eq!(coverage.entries(), model.entries(), "case {case}");
    }
}

/// decoded_merge merges over decoded entries: it drops the key's intervals that the new one contains, appends it,
/// and past the interval bound replaces the key's intervals with their hull.
fn decoded_merge(page: &CoveragePage, entry: Entry, limits: Limits) -> Option<CoveragePage> {
    let mut entries = decode_entries(&page.entries)?;
    let (key, interval) = entry;
    let blocked = entries
        .iter()
        .any(|(other, held)| *other == key && interval.within(*held));
    if page.saturated || blocked {
        return Some(page.clone());
    }
    entries.retain(|(other, held)| *other != key || !held.within(interval));
    entries.push(entry);
    if entries.iter().filter(|(other, _)| *other == key).count() > limits.intervals {
        let hull = entries
            .iter()
            .filter(|(other, _)| *other == key)
            .fold(interval, |hull, (_, other)| hull.hull(*other));
        entries.retain(|(other, _)| *other != key);
        entries.push((key, hull));
    }
    let next = CoveragePage {
        fence: page.fence,
        saturated: false,
        entries: encode_entries(&entries),
    };
    Some(if next.encoded_len() > limits.page_bytes {
        CoveragePage {
            fence: page.fence,
            saturated: true,
            entries: Vec::new(),
        }
    } else {
        next
    })
}

/// `merged` writes the bytes of the merge over decoded entries, on pages that repeat a key and on pages whose
/// entries fail to decode.
#[test]
fn merged_writes_the_bytes_of_the_decoded_merge() {
    let mut rng = SplitMix64::new(0x1289_0003);
    for case in 0..4000 {
        let limits = Limits {
            intervals: rng.below(4) as usize,
            page_bytes: page_len(rng.below(8) as usize) + rng.below(48) as usize,
        };
        let keys: Vec<[u8; 32]> = (0..1 + rng.below(3)).map(|_| key(&mut rng, 0)).collect();
        let entries: Vec<Entry> = (0..rng.below(8))
            .map(|_| {
                let low = rng.below(16);
                (
                    keys[rng.below(keys.len() as u64) as usize],
                    interval(low, low + rng.below(4)),
                )
            })
            .collect();
        let mut page = CoveragePage {
            fence: rng.below(4),
            saturated: rng.below(10) == 0,
            entries: encode_entries(&entries),
        };
        if rng.below(10) == 0 && !page.entries.is_empty() {
            page.entries[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        }
        let low = rng.below(16);
        let entry = (
            keys[rng.below(keys.len() as u64) as usize],
            interval(low, low + rng.below(6)),
        );
        assert_eq!(
            merged(&page, entry, limits),
            decoded_merge(&page, entry, limits),
            "case {case}"
        );
    }
}

/// `merge_each` gives the page and the changes of one merge per entry that reads the whole page, in order, whether
/// or not a key that nothing holds is stated fresh. The batches mix keys the page holds, keys an earlier entry of
/// the batch holds, keys nothing holds, and keys that share their first eight bytes with another key, on pages near
/// their interval and byte bounds.
#[test]
fn a_batch_merges_as_its_entries_one_by_one() {
    let mut rng = SplitMix64::new(0x1821_0001);
    let (mut unread, mut read, mut saturations) = (0, 0, 0);
    for case in 0..4000 {
        let limits = Limits {
            intervals: rng.below(4) as usize,
            page_bytes: page_len(rng.below(24) as usize) + rng.below(48) as usize,
        };
        let mut keys: Vec<[u8; 32]> = (0..6).map(|_| key(&mut rng, 0)).collect();
        for at in 0..4 {
            let mut twin = key(&mut rng, 0);
            twin[..8].copy_from_slice(&keys[at][..8]);
            keys.push(twin);
        }
        let drawn = |rng: &mut SplitMix64, count: u64| -> Vec<Entry> {
            (0..count)
                .map(|_| {
                    let low = rng.below(16);
                    (
                        keys[rng.below(keys.len() as u64) as usize],
                        interval(low, low + rng.below(4)),
                    )
                })
                .collect()
        };
        let stored = rng.below(12);
        let page = CoveragePage {
            fence: rng.below(4),
            saturated: rng.below(10) == 0,
            entries: encode_entries(&drawn(&mut rng, stored)),
        };
        let held = |page: &CoveragePage, key: &[u8; 32]| {
            let entries = decode_entries(&page.entries).unwrap();
            entries.iter().any(|(other, _)| other == key)
        };
        let count = rng.below(12);
        let batch = drawn(&mut rng, count);
        let mut expected = Vec::new();
        let mut folded = page.clone();
        for &entry in &batch {
            match held(&folded, &entry.0) {
                true => read += 1,
                false => unread += 1,
            }
            let mut draft = Draft::of(&folded);
            let change = merge(&mut draft, entry, limits, Held::Unread);
            folded = draft.next().over(&folded);
            saturations += usize::from(change == super::Change::Saturated);
            expected.push((entry, change));
        }
        // A key neither the page nor an earlier entry holds is stated fresh, except one in four of them.
        let fresh: Vec<bool> = (batch.iter().enumerate())
            .map(|(at, (key, _))| {
                let earlier = batch[..at].iter().any(|(other, _)| other == key);
                !held(&page, key) && !earlier && rng.below(4) != 0
            })
            .collect();
        let mut changes = Vec::new();
        let merged = merge_each(&page, &batch, &fresh, limits, None, |entry, change| {
            changes.push((entry, change));
        });
        assert_eq!(merged.over(&page), folded, "case {case}");
        assert_eq!(changes, expected, "case {case}");
    }
    assert!(
        unread > 2000 && read > 2000 && saturations > 200,
        "{unread} merges onto a page without the key, {read} with it, {saturations} saturations"
    );
}

/// `Marks::insert` reports a mark new exactly once, through growth, for marks that repeat and for marks whose
/// probes start in the table's last slots and wrap to its first; the table stays a power of two, at most half full
/// and, past 8 slots, at least a quarter full.
#[test]
fn marks_report_each_mark_new_once() {
    let mut rng = SplitMix64::new(0x1821_0002);
    let mut marks = Marks::default();
    let mut model = BTreeSet::new();
    for round in 0..20_000 {
        let top = match round % 3 {
            0 => rng.below(1 << 12) << 20,
            1 => 0xFFFF_F000 | rng.below(1 << 12),
            _ => rng.next_u64() >> 32,
        };
        let hash = KeyHash(top << 32 | rng.next_u64() >> 32);
        assert_eq!(marks.insert(hash), model.insert(top as u32 | 1), "{round}");
        let slots = marks.slots.len();
        assert!(slots.is_power_of_two() && 2 * marks.len <= slots);
        assert!(
            slots <= (4 * marks.len).max(8),
            "{slots} slots for {}",
            marks.len
        );
    }
    assert_eq!(marks.len, model.len());
    assert!(model.len() > 8000, "{} marks", model.len());
}

/// `Marks::of` sizes the table for the value's entry count and marks every key: a value of 16 keys with 4
/// intervals each has at most 16 marks in the 128 slots that hold 64 marks at half full, and an empty value has no
/// table.
#[test]
fn marks_of_a_value_are_sized_for_its_entries() {
    let mut rng = SplitMix64::new(0x1821_0003);
    let limits = Limits {
        intervals: 4,
        page_bytes: 1 << 20,
    };
    let coverage = Coverage::new(PAGES, limits);
    let keys: Vec<[u8; 32]> = (0..16).map(|_| key(&mut rng, 0)).collect();
    let entries: Vec<Entry> = (keys.iter())
        .flat_map(|key| (0..4).map(|i| (*key, interval(10 * i, 10 * i + 1))))
        .collect();
    let value = CoveragePage {
        entries: encode_entries(&entries),
        ..CoveragePage::default()
    };
    let mut marks = Marks::of(&value, &coverage);
    let built = (marks.len, marks.slots.len());
    assert!(built.0 <= 16 && built.1 == 128, "{built:?}");
    for key in &keys {
        assert!(!marks.insert(coverage.hash(key)));
    }
    assert_eq!((marks.len, marks.slots.len()), built);
    let empty = Marks::of(&CoveragePage::default(), &coverage);
    assert_eq!((empty.len, empty.slots.len()), (0, 0));
}

#[test]
fn a_page_write_merges_its_entries_in_order() {
    let mut rng = SplitMix64::new(0x1291_0001);
    for case in 0..400 {
        let intervals = 1 + rng.below(3) as usize;
        let shard = ShardRecord {
            page_cap: NonZeroU32::new(page_len(4 + rng.below(12) as usize) as u32).unwrap(),
            ..record()
        };
        let limits = Limits {
            intervals,
            page_bytes: shard.page_cap.get() as usize,
        };
        let store = Shared::new();
        let mut client = client(&store);
        client.create_shard(shard).unwrap();
        let mut fencing = Fencing::new(&shard, &session_at(3, 0), intervals).unwrap();
        for at in 0..shard.pages.get() {
            assert_eq!(fencing.fence(&mut client, at), Ok(Progress::Done));
        }
        let keys: Vec<[u8; 32]> = (0..3)
            .map(|_| key_among(&mut rng, shard.pages, 1))
            .collect();
        for round in 0..4 {
            let batch: Vec<Entry> = (0..1 + rng.below(6))
                .map(|_| {
                    let low = rng.below(16);
                    let key = keys[rng.below(keys.len() as u64) as usize];
                    (key, interval(low, low + rng.below(4)))
                })
                .collect();
            let basis = fencing.known(1).unwrap().value().clone();
            if rng.below(2) == 0 {
                let low = rng.below(16);
                fencing.hold((keys[0], interval(low, low + rng.below(8))));
            }
            let expected = (batch.iter())
                .try_fold(basis, |page, &entry| decoded_merge(&page, entry, limits))
                .unwrap();
            assert_eq!(fencing.cover_page(&mut client, &batch), Ok(Progress::Done));
            assert_eq!(page(&store, 1), expected, "case {case} round {round}");
            let coverage = fencing.coverage().unwrap();
            if expected.saturated {
                assert!(coverage.covers(&keys[0], CacheVersion(u64::MAX)));
            }
            for (key, interval) in decode_entries(&expected.entries).unwrap() {
                let (low, high) = (interval.low().0, interval.high().0);
                assert!((low..=high).all(|version| coverage.covers(&key, CacheVersion(version))));
            }
        }
    }
}

#[test]
fn stale_checkpoint_attempt_after_ack_loses_its_units_and_resurrects_nothing() {
    use crate::failover::records::{Layout, NamedCheckpoint, UNIT_ENTRIES};
    use crate::storage::checkpoint::tests::Inline;
    use crate::storage::checkpoint::{Checkpoint, SlotReader, UNIT_LEN, encode};
    use crate::storage::recovery::capture_tests::{entry, limits};
    use crate::storage::{EngineBudget, GuardedLoad, IO_UNIT, LoadRefusal, record::Crc32c};

    let crc = Crc32c::detect();
    let shard = record();
    let session = session_at(3, 0);
    let mut rng = SplitMix64::new(0x1294_0004);
    let invalidated = key_among(&mut rng, shard.pages, 1);
    let entries = |capture: u32| -> Vec<_> {
        (0..2 * UNIT_ENTRIES as usize + 5)
            .map(|at| {
                let mut entry = entry(at, capture, 8 * at as u64);
                // The reader withholds an entry of a session it does not admit.
                entry.session = session.get();
                if at == 0 && capture == 1 {
                    entry.key = invalidated;
                    entry.version = 5;
                }
                entry
            })
            .collect()
    };
    let at = |capture| Checkpoint {
        shard: shard.shard,
        session: session.get(),
        capture,
    };
    for stale in [0, 1, 2] {
        let store = Shared::new();
        let mut client = client(&store);
        client.create_shard(shard).unwrap();
        let mut fencing = Fencing::new(&shard, &session, 2).unwrap();
        for page in 0..shard.pages.get() {
            assert_eq!(fencing.fence(&mut client, page), Ok(Progress::Done));
        }
        let first = encode(crc, at(1), &entries(1), u32::MAX).unwrap();
        let entry = (invalidated, interval(5, 5));
        let page = page_of(&invalidated, shard.pages);
        assert_eq!(
            fencing.cover_page(&mut client, &[entry]),
            Ok(Progress::Done)
        );
        let third = encode(crc, at(3), &entries(3), u32::MAX).unwrap();
        let layout = Layout {
            units: 1 + 3 * third.len() as u64,
            slots: 3,
            slot_units: third.len() as u32,
            entries: 3 * UNIT_ENTRIES as u32,
        };
        let mut image = vec![0; layout.units as usize * IO_UNIT];
        let start = IO_UNIT;
        for (unit, bytes) in third.iter().enumerate() {
            image[start + unit * UNIT_LEN..start + (unit + 1) * UNIT_LEN]
                .copy_from_slice(&bytes[..]);
        }
        for unit in 1..=stale {
            image[start + unit * UNIT_LEN..start + (unit + 1) * UNIT_LEN]
                .copy_from_slice(&first[unit][..]);
        }
        drop(fencing);
        let named = NamedCheckpoint {
            slot: 0,
            session: session.get(),
            capture: 3,
            units: third.len() as u32,
        };
        let limits = crate::storage::LoadLimits {
            payload_end: 8 * 100,
            slot_count: 100,
            n_max: 100,
            ..limits()
        };
        let mut reader = SlotReader::new(
            crc,
            &layout,
            shard.shard,
            (named, 0, &[]),
            session.get(),
            (limits, &EngineBudget::unlimited()),
            crate::storage::recovery::checkpoint_tests::routing(4),
        )
        .unwrap();
        while !reader.done() {
            let Some(range) = reader.next_read() else {
                unreachable!("a reader whose jobs ran and that is not done issues a read");
            };
            let begin = range.start() as usize;
            reader.complete(range, &image[begin..begin + range.byte_len() as usize]);
        }
        let load = reader.load();
        if stale == 0 {
            assert_eq!(
                (load.load(), load.damage),
                (GuardedLoad::Warm(entries(3)), None),
                "control: with no stale attempt the reused slot loads warm without the invalidated key"
            );
            continue;
        }
        let damaged = load.damage.clone().expect("a stale unit is damage");
        assert_eq!(
            (damaged.alarm(), damaged.failed),
            (LoadRefusal::StaleWrite, (1..=stale as u32).collect()),
            "{stale} stale attempts: the reader names each stale unit"
        );
        assert_eq!(
            load.load(),
            GuardedLoad::Warm(entries(3)[stale * UNIT_ENTRIES as usize..].to_vec()),
            "{stale} stale attempts: every entry of the intact units loads and the invalidated entry is not resurrected"
        );
        let pages: Vec<CoveragePage> = (0..shard.pages.get())
            .map(|at| crate::storage::store_tests::page(&store, at))
            .collect();
        let coverage = Coverage::of_pages(shard.pages, &pages);
        assert!(
            coverage.covers(&invalidated, CacheVersion(5)),
            "{stale} stale attempts: the invalidation on page {page} stays covered"
        );
    }
}
