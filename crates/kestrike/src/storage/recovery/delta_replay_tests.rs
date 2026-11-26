//! Replay of mutation suffixes over a checkpoint: the tombstone frontier excludes with or without holes, inserts
//! stop at their suffix's first hole and are named as dropped, records apply whole or not at all, a stale, damaged
//! or malformed block is a hole classified as damage or tail, and one owner per unit and slot remains. A block the
//! device could not read lists its LSN as unread, which bars the report from installing.

use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::HashMap;

use super::capture::CaptureEntry;
use super::delta::*;
use super::delta_replay::*;
use super::delta_tests::{SESSION, block, packed, packed_at, push, remove, shard, wide};
use super::load_guard::LoadLimits;
use crate::failover::records::{Layout, Suffix};
use crate::index::Key;
use crate::storage::extent::ExtentLocator;
use crate::storage::record::Crc32c;

impl Patch {
    /// The fate of the checkpoint entry `entry`.
    pub(crate) fn fate_of(&self, entry: &CaptureEntry) -> Fate {
        self.fate(&mut Seek::default(), &identity_of(entry), &entry.extents)
    }
}

/// Blocks on the medium by LSN, as a replay reads them.
#[derive(Default)]
struct Medium {
    units: HashMap<u64, Box<[u8; UNIT_LEN]>>,
}

impl Medium {
    fn damage(&mut self, lsn: u64) {
        self.units.get_mut(&lsn).unwrap()[UNIT_LEN / 2] ^= 0xFF;
    }

    fn write(&mut self, first: u64, units: Vec<Box<[u8; UNIT_LEN]>>) -> u64 {
        for (at, unit) in units.into_iter().enumerate() {
            self.units.insert(first + at as u64, unit);
        }
        self.units.keys().max().map_or(first, |max| max + 1)
    }

    fn replay(&self, base: &[CaptureEntry], cut: u64, ancestry: &[Suffix]) -> SuffixLoad {
        self.replay_in(1 << 20, base, cut, ancestry, |_| true)
    }

    fn replay_in(
        &self,
        blocks: u64,
        base: &[CaptureEntry],
        cut: u64,
        ancestry: &[Suffix],
        mut readable: impl FnMut(u64) -> bool,
    ) -> SuffixLoad {
        let layout = Layout {
            units: 1 + blocks,
            slots: 0,
            slot_units: 0,
            entries: 0,
        };
        let reader = (Crc32c::detect(), shard(), SESSION);
        replay(
            reader,
            (&layout, &limits()),
            base.to_vec(),
            cut,
            ancestry,
            |lsn, unit| {
                *unit = self.units.get(&lsn).map_or([0; UNIT_LEN], |unit| **unit);
                readable(lsn)
            },
        )
        .unwrap()
    }
}

pub(crate) fn limits() -> LoadLimits {
    LoadLimits {
        payload_start: 0,
        payload_end: 1 << 30,
        reserve_units: 0,
        slot_count: 64,
        n_max: 1 << 20,
        record_chunk_len: 8192,
    }
}

impl Medium {
    /// The suffix-only replay of `ancestry` from `cut`, as [`Medium::replay`] reads it.
    fn patch(&self, cut: u64, ancestry: &[Suffix]) -> (Vec<CaptureEntry>, SuffixReport, Patch) {
        let layout = Layout {
            units: 1 + (1 << 20),
            slots: 0,
            slot_units: 0,
            entries: 0,
        };
        patch(
            (Crc32c::detect(), shard(), SESSION),
            (&layout, &limits()),
            cut,
            ancestry,
            |lsn, unit| {
                *unit = self.units.get(&lsn).map_or([0; UNIT_LEN], |unit| **unit);
                true
            },
        )
        .unwrap()
    }
}

fn suffix(start: u64, certified: u64, end: u64) -> Suffix {
    Suffix {
        session: SESSION,
        start,
        certified,
        end,
    }
}

fn ids(entries: &[CaptureEntry]) -> Vec<Identity> {
    entries.iter().map(identity_of).collect()
}

fn planted<T>(plant: Plant, run: impl FnOnce() -> T) -> T {
    PLANT.with(|cell| cell.set(Some(plant)));
    let out = run();
    PLANT.with(|cell| cell.set(None));
    out
}

#[test]
fn a_remove_that_never_reached_the_medium_keeps_its_entry() {
    let (x, y) = (wide(0, 0, 1), wide(1, 8, 1));
    let mut medium = Medium::default();
    let head = medium.write(10, packed(10, &[Record::Insert(y.clone())]));
    // The REMOVE of `x` was appended at the head and never written: the block is a hole at the certified end.
    let load = medium.replay(std::slice::from_ref(&x), 10, &[suffix(10, head, head + 2)]);
    assert_eq!(
        load.entries,
        vec![x, y.clone()],
        "a lost tombstone leaves its entry eligible"
    );
    assert_eq!(load.report.tails.len(), 1);
    assert_eq!(load.report.tails[0].lsn, head);
    assert!(load.report.damage.is_empty() && load.report.excluded.is_empty());
    assert!(load.installable(), "a load with only a tail installs");
    // Over a region of 4 blocks, a suffix recorded 6 long reads LSNs 0..4 and lists the region's end as unread; a
    // read the device fails is an unread hole that keeps the load from installing.
    let mut medium = Medium::default();
    medium.write(0, packed(0, &[Record::Insert(y)]));
    let mut asked = Vec::new();
    let load = medium.replay_in(4, &[], 0, &[suffix(0, 6, 6)], |lsn| {
        asked.push(lsn);
        lsn != 1
    });
    assert_eq!(asked, vec![0, 1, 2, 3]);
    assert_eq!(load.report.unread, vec![4, 1]);
    assert_eq!(
        load.report.damage,
        vec![Hole {
            lsn: 1,
            cause: BlockHole::Unread
        }]
    );
    assert!(!load.installable());
    let load = medium.replay_in(4, &[], 0, &[suffix(0, 4, 4)], |_| true);
    assert!(load.report.unread.is_empty());
    let load = medium.replay_in(4, &[], 0, &[suffix(0, 1, 4)], |lsn| lsn != 1);
    assert!(load.report.damage.is_empty());
    assert_eq!(
        load.report.tails,
        [Hole {
            lsn: 1,
            cause: BlockHole::Unread
        }],
        "an unread first hole at the certified end with no passed block after it is the tail"
    );
    assert_eq!(load.report.unread, vec![1]);
    assert!(!load.installable(), "an unread block alone holds the load");
    let load = medium.replay_in(4, &[], 0, &[suffix(0, 1, 6)], |_| true);
    assert!(load.report.damage.is_empty());
    assert_eq!(load.report.unread, vec![4]);
    assert!(
        !load.installable(),
        "a suffix past its region alone holds the load"
    );
    let healed = medium.replay_in(4, &[], 0, &[suffix(0, 1, 4)], |_| true);
    assert!(healed.installable());
}

/// A failed read at any position of a suffix certified to its end makes that block's LSN the one unread LSN and the
/// suffix's damage hole, and holds the load from installing. An unread first block at the certified end, before a block
/// that passed its checks, is damage as well.
#[test]
fn a_failed_read_at_each_position_of_a_suffix_lists_its_lsn_unread_and_holds_the_load() {
    let inserts: Vec<CaptureEntry> = (0..3).map(|at| wide(at, 4096 * at as u64, 484)).collect();
    let records: Vec<Record> = inserts.iter().cloned().map(Record::Insert).collect();
    let units = packed(5, &records);
    for (at, record) in records.iter().enumerate() {
        let alone = packed_at(block(5 + at as u64), [(at as u64, record)]);
        assert!(
            alone.len() == 1 && alone[0] == units[at],
            "block {at} holds insert {at} alone"
        );
    }
    let mut medium = Medium::default();
    let head = medium.write(5, units);
    assert_eq!(head, 8, "each insert fills one block");
    let ancestry = [suffix(5, head, head)];
    let run = |fault: Option<usize>| {
        let (mut reads, mut failed) = (Vec::new(), Vec::new());
        let load = medium.replay_in(3, &[], 5, &ancestry, |lsn| {
            reads.push(lsn);
            let fails = Some(reads.len()) == fault;
            failed.extend(fails.then_some(lsn));
            !fails
        });
        (reads, failed, load)
    };
    let (clean, _, load) = run(None);
    assert_eq!(clean, [5, 6, 7], "the clean replay reads each block once");
    assert_eq!(load.entries, inserts);
    assert!(load.installable());
    let mut unread = Vec::new();
    for n in 1..=clean.len() {
        let (reads, failed, load) = run(Some(n));
        let [lsn] = failed[..] else {
            panic!("read {n} alone fails: {failed:?}");
        };
        assert_eq!(reads, clean, "read {n}: every block is read once");
        assert_eq!(load.report.unread, [lsn], "read {n}");
        let hole = Hole {
            lsn,
            cause: BlockHole::Unread,
        };
        assert_eq!(load.report.damage, [hole], "read {n}");
        assert!(
            load.report.tails.is_empty(),
            "read {n}: the hole is damage alone"
        );
        assert_eq!(
            load.entries,
            inserts[..n - 1],
            "read {n}: the inserts before the hole apply"
        );
        assert_eq!(
            load.report.dropped,
            ids(&inserts[n..]),
            "read {n}: the inserts behind the hole are dropped"
        );
        assert!(!load.installable(), "read {n}");
        unread.extend(load.report.unread);
    }
    assert_eq!(
        unread, clean,
        "the replay reports each read of the clean replay unread once"
    );
    let load = medium.replay_in(3, &[], 5, &[suffix(5, 5, 8)], |lsn| lsn != 5);
    let hole = Hole {
        lsn: 5,
        cause: BlockHole::Unread,
    };
    assert_eq!(
        (load.report.damage, load.report.tails, load.report.unread),
        (vec![hole], vec![], vec![5]),
        "an unread first hole at the certified end before a passed block is damage"
    );
}

#[test]
fn a_removal_after_the_cut_excludes_a_snapshot_member_through_the_suffix() {
    let (x, y) = (wide(0, 0, 1), wide(1, 8, 1));
    let mut medium = Medium::default();
    // The cut is sealed at head 10; the removal of snapshot member `x` lands at or above it.
    let head = medium.write(10, packed(10, &[remove(&x, Cause::Evict)]));
    let load = medium.replay(&[x.clone(), y.clone()], 10, &[suffix(10, head, head)]);
    assert_eq!(load.entries, vec![y]);
    assert_eq!(load.report.excluded, ids(&[x]));
    assert!(load.report.tails.is_empty() && load.report.damage.is_empty());
}

#[test]
fn a_replace_on_another_extent_excludes_the_old_identity_and_installs_the_new_or_neither() {
    let old = wide(0, 0, 1);
    let mut new = wide(0, 8, 600);
    new.allocation += 1;
    let mut new_short = wide(0, 8, 1);
    new_short.allocation += 1;
    let replace = |new: &CaptureEntry| Record::Replace {
        old: identity_of(&old),
        cause: Cause::Evict,
        new: new.clone(),
    };
    let mut medium = Medium::default();
    let head = medium.write(0, packed(0, &[replace(&new_short)]));
    let load = medium.replay(std::slice::from_ref(&old), 0, &[suffix(0, head, head)]);
    assert_eq!(load.entries, vec![new_short.clone()]);
    assert_eq!(load.report.excluded, ids(std::slice::from_ref(&old)));
    // The replacement torn across two blocks: its second block never landed, so the old entry stays and the new
    // one is lost; the key never has two identities.
    let mut torn = Medium::default();
    let units = packed(0, &[replace(&new)]);
    assert!(units.len() >= 2);
    let head = units.len() as u64;
    torn.write(0, units[..1].to_vec());
    let load = torn.replay(std::slice::from_ref(&old), 0, &[suffix(0, 1, head)]);
    assert_eq!(load.entries, vec![old.clone()]);
    assert!(
        load.report.excluded.is_empty(),
        "a torn record excludes nothing"
    );
    assert_eq!(load.report.tails.len(), 1);
    assert_eq!(
        load.report.damage[..],
        [],
        "the torn block is above the certified end"
    );
    let open = torn.replay(std::slice::from_ref(&old), 0, &[suffix(0, 1, 1)]);
    assert_eq!(open.entries, vec![old.clone()]);
    assert_eq!(
        open.report.damage,
        vec![Hole {
            lsn: 0,
            cause: BlockHole::Content
        }],
        "a record still open at the end of its suffix is damage"
    );
    let partial = planted(Plant::PartialRecord, || {
        torn.replay(std::slice::from_ref(&old), 0, &[suffix(0, 1, head)])
    });
    assert_eq!(
        partial.report.excluded,
        ids(&[old]),
        "PartialRecord: the cut REPLACE excludes its old identity and installs nothing"
    );
    assert_eq!(partial.entries, vec![]);
}

#[test]
fn a_damaged_remove_block_stops_inserts_and_leaves_one_owner_per_unit() {
    let x = wide(0, 0, 1);
    let y = wide(1, 0, 1);
    let mut medium = Medium::default();
    let mut units = packed(0, &[remove(&x, Cause::Evict)]);
    // Resealed at LSN 1 as the second block of the chain: the sequence continues from the removal.
    let crc = Crc32c::detect();
    let mut packer = Packer::default();
    let (kind, body) = Record::Insert(y.clone()).body().unwrap();
    push(&mut packer, 1, (kind, &body));
    packer.seal();
    let second = seal(crc, block(1), &packer.sealed.pop_front().unwrap());
    units.push(second);
    let head = medium.write(0, units);
    let whole = medium.replay(std::slice::from_ref(&x), 0, &[suffix(0, head, head)]);
    assert_eq!(
        whole.entries,
        vec![y.clone()],
        "intact: X leaves, Y owns the unit"
    );
    // The REMOVE's block is damaged after it was certified.
    medium.damage(0);
    let load = medium.replay(std::slice::from_ref(&x), 0, &[suffix(0, head, head)]);
    assert_eq!(
        load.entries,
        vec![x.clone()],
        "Y is behind the hole and does not apply"
    );
    assert_eq!(
        load.report.damage.len(),
        1,
        "the hole below the certified end is damage"
    );
    assert_eq!(load.report.damage[0].lsn, 0);
    assert!(
        whole.installable() && !load.installable(),
        "damage keeps the load from installing"
    );
    assert!(load.report.withheld.is_empty(), "one owner of the unit");
    assert_eq!(
        load.report.dropped,
        ids(std::slice::from_ref(&y)),
        "the dropped insert is named"
    );
    // The skip-holes control applies Y behind the hole, and Y's later level supersedes X on unit 0.
    let skipped = planted(Plant::SkipHoles, || {
        medium.replay(std::slice::from_ref(&x), 0, &[suffix(0, head, head)])
    });
    assert_eq!(
        skipped.entries,
        vec![y],
        "SkipHoles applies the insert behind the hole"
    );
    assert_eq!(skipped.report.superseded, ids(&[x]));
}

#[test]
fn a_record_missing_its_last_part_applies_nothing_and_earlier_records_apply() {
    let (a, wide_b, c) = (wide(0, 0, 1), wide(1, 8, 700), wide(2, 800, 1));
    let units = packed(
        0,
        &[
            Record::Insert(a.clone()),
            Record::Insert(wide_b.clone()),
            Record::Insert(c.clone()),
        ],
    );
    assert!(units.len() >= 2);
    let head = units.len() as u64;
    let mut medium = Medium::default();
    medium.write(0, units[..units.len() - 1].to_vec());
    let load = medium.replay(&[], 0, &[suffix(0, 0, head)]);
    assert_eq!(
        load.entries,
        vec![a.clone()],
        "A applies, cut B and later C do not"
    );
    assert_eq!(
        load.report.tails.len(),
        1,
        "the missing block holds B's tail and C"
    );
}

#[test]
fn replay_starts_at_the_cut_inside_a_kept_suffix_and_a_later_suffix_starts_fresh() {
    let (a, b, c) = (wide(0, 0, 1), wide(1, 8, 1), wide(2, 16, 1));
    let mut medium = Medium::default();
    let mut head = medium.write(0, packed(0, &[Record::Insert(a.clone())]));
    head = medium.write(head, packed(head, &[Record::Insert(b.clone())]));
    let cut = head;
    head = medium.write(head, packed(head, &[remove(&b, Cause::Expire)]));
    let first = Suffix {
        session: SESSION,
        start: 0,
        certified: head,
        end: head + 1,
    };
    // Tenure B's suffix after A's reserved end; A's unwritten block is A's tail, and B's insert still applies.
    let next = Suffix {
        session: SESSION,
        start: head + 1,
        certified: head + 2,
        end: head + 2,
    };
    medium.write(head + 1, packed(head + 1, &[Record::Insert(c.clone())]));
    let load = medium.replay(&[a.clone(), b.clone()], cut, &[first, next]);
    assert_eq!(
        load.entries,
        vec![a, c],
        "records below the cut are not replayed"
    );
    assert_eq!(load.report.excluded, ids(&[b]));
    assert_eq!(load.report.tails.len(), 1);
    assert_eq!(load.report.tails[0].lsn, head);
}

#[test]
fn a_hole_is_damage_below_the_certified_end_or_before_a_passed_block_and_otherwise_the_tail() {
    let (a, b) = (wide(0, 0, 1), wide(1, 8, 1));
    let mut medium = Medium::default();
    medium.write(0, packed(0, &[Record::Insert(a.clone())]));
    // LSN 1's unit holds a block of LSN 5 from an earlier ring cycle.
    medium.write(1, packed(5, &[Record::Insert(b.clone())]));
    let load = medium.replay(&[], 0, &[suffix(0, 2, 2)]);
    assert_eq!(load.entries, vec![a.clone()]);
    assert_eq!(load.report.damage.len(), 1);
    assert!(matches!(load.report.damage[0].cause, BlockHole::Header(_)));
    // A block whose sequence does not continue the block before it.
    let mut medium = Medium::default();
    medium.write(0, packed(0, &[Record::Insert(a.clone())]));
    let mut packer = Packer::default();
    let (kind, body) = Record::Insert(b.clone()).body().unwrap();
    push(&mut packer, 5, (kind, &body));
    packer.seal();
    medium.units.insert(
        1,
        seal(
            Crc32c::detect(),
            block(1),
            &packer.sealed.pop_front().unwrap(),
        ),
    );
    let load = medium.replay(&[], 0, &[suffix(0, 1, 2)]);
    assert_eq!(load.entries, vec![a]);
    assert!(load.report.tails.is_empty());
    assert_eq!(
        load.report.damage,
        vec![Hole {
            lsn: 1,
            cause: BlockHole::Content
        }],
        "a block of its identity and crc that breaks the sequence was written whole, so its hole is damage"
    );
    // Above the certified end, a stale block with nothing valid after it is the tail; a flipped block followed by an
    // intact block of its suffix is damage.
    let mut medium = Medium::default();
    medium.write(0, packed(0, &[Record::Insert(b.clone())]));
    medium.write(1, packed(9, &[Record::Insert(wide(2, 16, 1))]));
    let load = medium.replay(&[], 0, &[suffix(0, 1, 3)]);
    assert!(load.report.damage.is_empty() && load.installable());
    assert_eq!(load.report.tails.len(), 1);
    assert!(matches!(load.report.tails[0].cause, BlockHole::Header(_)));
    let mut medium = Medium::default();
    let head = medium.write(
        0,
        packed(0, &[Record::Insert(b), Record::Insert(wide(2, 16, 700))]),
    );
    medium.damage(0);
    let load = medium.replay(&[], 0, &[suffix(0, 0, head)]);
    assert_eq!(load.report.damage.len(), 1);
    assert_eq!(load.report.damage[0].lsn, 0);
    assert!(load.report.tails.is_empty());
}

#[test]
fn a_later_insert_of_a_key_supersedes_the_checkpoints_identity_and_every_earlier_one() {
    let first = wide(0, 0, 1);
    let mut second = wide(3, 8, 1);
    second.key = first.key;
    let mut medium = Medium::default();
    let head = medium.write(0, packed(0, &[Record::Insert(second.clone())]));
    let load = medium.replay(std::slice::from_ref(&first), 0, &[suffix(0, head, head)]);
    assert_eq!(load.entries, vec![second]);
    assert_eq!(load.report.superseded, ids(&[first]));
}

#[test]
fn an_exclusion_applies_whatever_its_order_against_a_hole() {
    let (x, y) = (wide(0, 0, 1), wide(1, 8, 1));
    let mut medium = Medium::default();
    let mut head = medium.write(0, packed(0, &[Record::Insert(y.clone())]));
    head += 1;
    head = medium.write(head, packed(head, &[remove(&x, Cause::Invalidate)]));
    let load = medium.replay(std::slice::from_ref(&x), 0, &[suffix(0, head, head)]);
    assert_eq!(load.entries, vec![y]);
    assert_eq!(
        load.report.excluded,
        ids(std::slice::from_ref(&x)),
        "the tombstone after the hole still excludes"
    );
    assert_eq!(load.report.damage.len(), 1);
    // A split INSERT and a REMOVE of X pack into two blocks; the first is damaged, so the second's continuation
    // part drops and its whole REMOVE still excludes X.
    let split = wide(2, 16, 700);
    let units = packed(0, &[Record::Insert(split), remove(&x, Cause::Evict)]);
    assert_eq!(units.len(), 2);
    let mut medium = Medium::default();
    let head = medium.write(0, units);
    medium.damage(0);
    let load = medium.replay(std::slice::from_ref(&x), 0, &[suffix(0, head, head)]);
    assert_eq!(load.entries, vec![]);
    assert_eq!(load.report.excluded, ids(&[x]));
    assert!(
        load.report.dropped.is_empty(),
        "the torn insert never completes"
    );
    assert_eq!(load.report.damage.len(), 1);
    assert_eq!(load.report.damage[0].lsn, 0);
}

fn owner(slot: usize, extents: &[(u64, u32)]) -> CaptureEntry {
    let mut entry = wide(slot, 0, 1);
    entry.key[8] = extents[0].0 as u8;
    entry.extents = extents
        .iter()
        .map(|&(start, len)| {
            crate::storage::extent::ExtentLocator::new(start, len)
                .unwrap()
                .bits()
        })
        .collect();
    entry
}

/// Within one level, adjacent spans keep both owners, while a partial overlap of multi-unit extents, an overlap on an
/// entry's second extent and a shared slot withhold both entries and leave the others loaded.
#[test]
fn entries_of_one_level_sharing_a_unit_or_slot_are_both_withheld_and_adjacent_spans_are_kept() {
    let adjacent = [owner(0, &[(0, 2)]), owner(1, &[(2, 1)])];
    let second_extent = [owner(2, &[(10, 1), (20, 2)]), owner(3, &[(21, 1)])];
    let partial = [owner(4, &[(30, 1)]), owner(5, &[(30, 2)])];
    let slot = [owner(6, &[(50, 1)]), owner(6, &[(60, 1)])];
    let alone = owner(7, &[(40, 1)]);
    let base: Vec<CaptureEntry> = [
        &adjacent[..],
        &second_extent,
        &partial,
        &slot,
        std::slice::from_ref(&alone),
    ]
    .concat();
    let load = Medium::default().replay(&base, 0, &[]);
    let mut kept = adjacent.to_vec();
    kept.push(alone);
    assert_eq!(load.entries, kept);
    let mut withheld = ids(&[&second_extent[..], &partial, &slot].concat());
    let mut found = load.report.withheld.clone();
    withheld.sort_by_key(|id| id.key);
    found.sort_by_key(|id| id.key);
    assert_eq!(found, withheld);
}

/// A predecessor's certified REMOVE of X is damaged after the successor reused X's unit and slot for Y: Y's later
/// level supersedes the resurrected X, the damage is accounted, and the load guard admits the result. An entry
/// sharing only a slot with a later level's entry is superseded the same way.
#[test]
fn a_later_level_owner_supersedes_an_earlier_entry_on_its_unit_or_slot_and_the_guard_admits_the_load()
 {
    let x = owner(0, &[(0, 1)]);
    let mut y = owner(0, &[(0, 1)]);
    y.key[9] = 1;
    y.allocation += 1;
    let slot_only = owner(1, &[(5, 1)]);
    let mut successor = owner(1, &[(6, 1)]);
    successor.key[9] = 1;
    successor.allocation += 1;
    let mut medium = Medium::default();
    medium.write(0, packed(0, &[remove(&x, Cause::Evict)]));
    medium.write(
        1,
        packed(
            1,
            &[Record::Insert(y.clone()), Record::Insert(successor.clone())],
        ),
    );
    medium.damage(0);
    let chain = [suffix(0, 1, 1), suffix(1, 2, 2)];
    let load = medium.replay(&[x.clone(), slot_only.clone()], 0, &chain);
    assert_eq!(load.entries, vec![y, successor]);
    assert_eq!(load.report.superseded, ids(&[x, slot_only]));
    assert_eq!(load.report.damage.len(), 1);
    assert!(!load.installable(), "the damaged load is held");
    assert!(load.report.withheld.is_empty());
    let limits = super::capture_tests::limits();
    let budget = crate::storage::ledger::EngineBudget::unlimited();
    assert_eq!(super::load_guard(&load.entries, limits, &budget), Ok(()));
}

/// A crc-valid block whose record does not decode as its kind is a hole: the inserts behind it are named as dropped,
/// and the block, written whole, makes it damage below a certified end that does not cover it. A block that opens
/// with a part of a record no earlier block opened is damage too.
#[test]
fn a_malformed_record_or_an_unopened_continuation_is_a_hole_that_names_the_inserts_it_drops() {
    let (a, b) = (wide(0, 0, 1), wide(1, 8, 1));
    let mut packer = Packer::default();
    let (kind, body) = Record::Insert(a.clone()).body().unwrap();
    push(&mut packer, 0, (kind, &body));
    let (_, removal) = remove(&b, Cause::Evict).body().unwrap();
    push(&mut packer, 1, (kind, &removal));
    packer.seal();
    let mut medium = Medium::default();
    medium.units.insert(
        0,
        seal(
            Crc32c::detect(),
            block(0),
            &packer.sealed.pop_front().unwrap(),
        ),
    );
    let mut later = packed(1, &[Record::Insert(wide(2, 16, 1))]);
    let mut payload = later[0][super::checkpoint::layout().1.header_bytes()..].to_vec();
    payload[..8].copy_from_slice(&2u64.to_le_bytes());
    payload[14..22].copy_from_slice(&2u64.to_le_bytes());
    later[0] = seal(Crc32c::detect(), block(1), &payload);
    medium.write(1, later);
    let load = medium.replay(&[], 0, &[suffix(0, 0, 2)]);
    assert_eq!(load.entries, vec![a.clone()]);
    assert_eq!(
        load.report.damage,
        vec![Hole {
            lsn: 0,
            cause: BlockHole::Content
        }]
    );
    assert_eq!(load.report.dropped, ids(&[wide(2, 16, 1)]));
    // Block 1 opens with the second part of a record no earlier block opened.
    let mut medium = Medium::default();
    medium.write(0, packed(0, &[Record::Insert(a.clone())]));
    let split = packed(0, &[Record::Insert(wide(3, 24, 700))]);
    let mut payload = split[1][super::checkpoint::layout().1.header_bytes()..].to_vec();
    payload[..8].copy_from_slice(&1u64.to_le_bytes());
    payload[14..22].copy_from_slice(&1u64.to_le_bytes());
    medium
        .units
        .insert(1, seal(Crc32c::detect(), block(1), &payload));
    let load = medium.replay(&[], 0, &[suffix(0, 0, 2)]);
    assert_eq!(load.entries, vec![a]);
    assert_eq!(
        load.report.damage,
        vec![Hole {
            lsn: 1,
            cause: BlockHole::Content
        }]
    );
}

/// A suffix's first replayed block must open a record: the writer starts every suffix and every cut on a fresh
/// record, so a first part with a nonzero index is a hole and its tail, which may hold a REMOVE, is not lost silently.
#[test]
fn a_suffix_whose_first_block_continues_an_unseen_record_is_a_hole() {
    let split = packed(0, &[Record::Insert(wide(3, 24, 700))]);
    let header = super::checkpoint::layout().1.header_bytes();
    let mut payload = split[1][header..].to_vec();
    payload[..8].copy_from_slice(&0u64.to_le_bytes());
    let mut medium = Medium::default();
    medium
        .units
        .insert(0, seal(Crc32c::detect(), block(0), &payload));
    let load = medium.replay(&[], 0, &[suffix(0, 1, 1)]);
    assert_eq!(
        load.report.damage,
        vec![Hole {
            lsn: 0,
            cause: BlockHole::Content
        }]
    );
}

/// A withheld entry bars its units and slot: an earlier level's entry on a unit only the withheld entry also owns is
/// superseded, so no unit is left to an entry whose bytes belong to another.
#[test]
fn a_withheld_entry_bars_its_units_from_earlier_levels() {
    let x = owner(0, &[(2, 1)]);
    let mut y = owner(1, &[(1, 1), (2, 1)]);
    y.key[9] = 1;
    let mut z = owner(2, &[(1, 1)]);
    z.key[9] = 2;
    let mut medium = Medium::default();
    medium.write(
        0,
        packed(0, &[Record::Insert(y.clone()), Record::Insert(z.clone())]),
    );
    let load = medium.replay(std::slice::from_ref(&x), 0, &[suffix(0, 1, 1)]);
    assert_eq!(load.entries, vec![]);
    assert_eq!(load.report.superseded, ids(&[x]));
    let mut withheld = load.report.withheld.clone();
    withheld.sort_by_key(|id| id.key);
    assert_eq!(withheld, ids(&[y, z]));
}

/// A key replaced 300 times loads only its last identity and excludes every earlier one, whether the first identity
/// comes from the checkpoint or from the suffix; a later insert of the key without a removal supersedes that last
/// identity.
#[test]
fn a_key_replaced_many_times_loads_its_last_identity() {
    let version = |at: usize| {
        let mut entry = wide(at % 60, 8 * at as u64, 1);
        (entry.key, entry.version) = ([7; 32], at as u64);
        entry.allocation = (at as u64 % 60) << 32 | (1 + at as u64 / 60);
        entry
    };
    let versions: Vec<CaptureEntry> = (0..=300).map(version).collect();
    let replace = |pair: &[CaptureEntry]| Record::Replace {
        old: identity_of(&pair[0]),
        cause: Cause::Evict,
        new: pair[1].clone(),
    };
    let replaces: Vec<Record> = versions.windows(2).map(replace).collect();
    for from_checkpoint in [false, true] {
        let first = Record::Insert(versions[0].clone());
        let records: Vec<Record> = (!from_checkpoint)
            .then_some(first)
            .into_iter()
            .chain(replaces.clone())
            .collect();
        let base = &versions[..usize::from(from_checkpoint)];
        let mut medium = Medium::default();
        let head = medium.write(0, packed(0, &records));
        let load = medium.replay(base, 0, &[suffix(0, head, head)]);
        assert_eq!(load.entries, versions[300..]);
        assert_eq!(load.report.excluded, ids(&versions[..300]));
        assert_eq!(
            (
                load.report.superseded.len(),
                load.report.withheld.len(),
                load.report.dropped.len()
            ),
            (0, 0, 0)
        );
        assert!(load.installable());
    }
    let mut again = wide(61, 4000, 1);
    (again.key, again.version) = ([7; 32], 301);
    let records: Vec<Record> = [Record::Insert(versions[0].clone())]
        .into_iter()
        .chain(replaces)
        .chain([Record::Insert(again.clone())])
        .collect();
    let mut medium = Medium::default();
    let head = medium.write(0, packed(0, &records));
    let load = medium.replay(&[], 0, &[suffix(0, head, head)]);
    assert_eq!(load.entries, vec![again]);
    assert_eq!(load.report.superseded, ids(&versions[300..]));
}

/// Two keys of one fingerprint are two keys: neither supersedes the other, and a removal that names one identity
/// under the other's key is recorded in `excluded` and drops neither entry.
#[test]
fn keys_of_one_fingerprint_are_settled_by_full_key() {
    let (mut a, mut b) = (wide(0, 0, 1), wide(1, 8, 1));
    let word = |key: &mut [u8; 32], at: usize, value: u64| {
        key[8 * at..8 * at + 8].copy_from_slice(&value.to_le_bytes())
    };
    (a.key, b.key) = ([0; 32], [0; 32]);
    word(&mut a.key, 0, 0x0123_4567_89ab_cdef);
    word(
        &mut b.key,
        0,
        0x0123_4567_89ab_cdef ^ 0x5555u64.rotate_left(16),
    );
    word(&mut b.key, 1, 0x5555);
    assert_eq!(
        super::load_guard::fingerprint(&a.key),
        super::load_guard::fingerprint(&b.key)
    );
    let mut crossed = a.clone();
    crossed.key = b.key;
    let records = [
        Record::Insert(a.clone()),
        Record::Insert(b.clone()),
        remove(&crossed, Cause::Evict),
    ];
    let mut medium = Medium::default();
    let head = medium.write(0, packed(0, &records));
    let load = medium.replay(&[], 0, &[suffix(0, head, head)]);
    assert_eq!(load.entries, vec![a.clone(), b.clone()]);
    assert_eq!(load.report.excluded, ids(&[crossed]));
    assert_eq!(
        (load.report.superseded.len(), load.report.withheld.len()),
        (0, 0)
    );
    let load = Medium::default().replay(&[b.clone(), a.clone()], 0, &[]);
    assert_eq!(load.entries, vec![b, a]);
}

/// Forty entries of one level that claim one unit are all withheld, and an entry of a later level on that unit
/// supersedes each of them and loads.
#[test]
fn many_entries_claiming_one_unit_are_withheld_together_or_superseded_by_a_later_level() {
    let claim = |slot: usize| {
        let mut entry = owner(slot, &[(100, 1)]);
        entry.key[9] = slot as u8;
        entry
    };
    let base: Vec<CaptureEntry> = (0..40).map(claim).collect();
    let load = Medium::default().replay(&base, 0, &[]);
    assert_eq!(load.entries, vec![]);
    assert_eq!(load.report.withheld, ids(&base));
    let later = claim(41);
    let mut medium = Medium::default();
    let head = medium.write(0, packed(0, &[Record::Insert(later.clone())]));
    let load = medium.replay(&base, 0, &[suffix(0, head, head)]);
    assert_eq!(load.entries, vec![later]);
    assert_eq!(
        (load.report.superseded, load.report.withheld.len()),
        (ids(&base), 0)
    );
}

/// An entry a later key or owner superseded still bars its units and slot: an earlier level's entry on them is
/// superseded too, since that level allocated them only after excluding the earlier owner, and the superseded entry
/// is never flipped to withheld by a same-level neighbour.
#[test]
fn a_superseded_entry_bars_its_units_and_slot_from_earlier_levels() {
    let x = owner(0, &[(2, 1)]);
    let mut y = owner(1, &[(2, 1), (3, 1)]);
    y.key[9] = 1;
    let mut later_y = owner(1, &[(5, 1)]);
    later_y.key = y.key;
    later_y.allocation += 1;
    let mut medium = Medium::default();
    let units = packed(
        0,
        &[Record::Insert(y.clone()), Record::Insert(later_y.clone())],
    );
    let head = medium.write(0, units);
    let load = medium.replay(std::slice::from_ref(&x), 0, &[suffix(0, head, head)]);
    assert_eq!(load.entries, vec![later_y]);
    let mut superseded = load.report.superseded.clone();
    superseded.sort_by_key(|id| id.key);
    assert_eq!(superseded, ids(&[x, y]));
    assert!(load.report.withheld.is_empty());
    // The checkpoint entry shares only the slot of a key-superseded later-level entry whose successor moved to
    // another slot, and that slot bar alone supersedes it.
    let slot_only = owner(5, &[(20, 1)]);
    let mut moved = owner(5, &[(30, 1)]);
    moved.key[9] = 4;
    let mut successor = owner(6, &[(31, 1)]);
    successor.key = moved.key;
    successor.allocation += 1;
    let mut medium = Medium::default();
    let head = medium.write(
        0,
        packed(
            0,
            &[
                Record::Insert(moved.clone()),
                Record::Insert(successor.clone()),
            ],
        ),
    );
    let load = medium.replay(
        std::slice::from_ref(&slot_only),
        0,
        &[suffix(0, head, head)],
    );
    assert_eq!(load.entries, vec![successor.clone()]);
    let mut superseded = load.report.superseded.clone();
    superseded.sort_by_key(|id| id.key);
    assert_eq!(superseded, ids(&[slot_only, moved.clone()]));
    let mut neighbour = owner(7, &[(30, 1)]);
    neighbour.key[9] = 5;
    let mut medium = Medium::default();
    let head = medium.write(
        0,
        packed(
            0,
            &[
                Record::Insert(neighbour.clone()),
                Record::Insert(moved.clone()),
                Record::Insert(successor.clone()),
            ],
        ),
    );
    let load = medium.replay(&[], 0, &[suffix(0, head, head)]);
    assert_eq!(load.entries, vec![successor]);
    assert_eq!(load.report.withheld, ids(&[neighbour]));
    assert_eq!(load.report.superseded, ids(&[moved]));
}

/// A record whose body fails to decode resets the assembler at that record alone: a REPLACE opened later in the
/// same block, and completed in the next, still excludes its old identity, and its new one is dropped behind the hole.
#[test]
fn a_malformed_record_does_not_discard_a_record_opened_after_it_in_the_same_block() {
    let (a, old) = (wide(0, 0, 1), wide(1, 8, 1));
    let replace = Record::Replace {
        old: identity_of(&old),
        cause: Cause::Evict,
        new: wide(2, 16, 700),
    };
    let mut packer = Packer::default();
    // A REMOVE body under the INSERT kind byte is malformed.
    let (kind, _) = Record::Insert(a).body().unwrap();
    let (_, removal) = remove(&old, Cause::Evict).body().unwrap();
    push(&mut packer, 0, (kind, &removal));
    let (kind, body) = replace.body().unwrap();
    push(&mut packer, 1, (kind, &body));
    packer.seal();
    let mut medium = Medium::default();
    let mut lsn = 0;
    while let Some(payload) = packer.sealed.pop_front() {
        medium
            .units
            .insert(lsn, seal(Crc32c::detect(), block(lsn), &payload));
        lsn += 1;
    }
    assert!(lsn >= 2);
    let load = medium.replay(std::slice::from_ref(&old), 0, &[suffix(0, lsn, lsn)]);
    assert_eq!(load.entries, vec![]);
    assert_eq!(load.report.excluded, ids(&[old]));
    assert_eq!(load.report.dropped, ids(&[wide(2, 16, 700)]));
    assert_eq!(load.report.damage.len(), 1);
}

/// A body of a REPLACE whose part chain declares more bytes than the widest body is refused at the part that passes
/// the bound, before the rest is buffered, and an INSERT with overlapping or empty extents decodes as no record.
#[test]
fn an_oversized_or_misshapen_record_is_a_content_hole() {
    let mut assembler = Assembler::default();
    let zeros = [0; 4000];
    let part = |index: u16, len: usize| {
        let head = Head {
            kind: 3,
            seq: 0,
            index,
            count: u16::MAX,
        };
        (head, &zeros[..len])
    };
    assert_eq!(assembler.feed(part(0, 4000)), Ok(None));
    let mut fed = 4000;
    let refused = (1..).find_map(|index| {
        fed += 4000;
        assembler
            .feed(part(index, 4000))
            .err()
            .map(|hole| (hole, fed))
    });
    let (hole, fed) = refused.unwrap();
    assert_eq!(hole, BlockHole::Content);
    assert!(
        fed <= 57 + 72 + 8 * 2115 + 4000,
        "refused once the body passed the widest"
    );
    let mut overlapping = wide(0, 0, 2);
    overlapping.extents[1] = overlapping.extents[0];
    let mut empty = wide(1, 8, 1);
    empty.extents[0] = ExtentLocator::new(8, 0).unwrap().bits();
    for entry in [overlapping, empty] {
        assert_eq!(
            Record::Insert(entry).body(),
            None,
            "a misshapen entry has no body"
        );
    }
    let valid = wide(2, 16, 2);
    let (kind, mut body) = Record::Insert(valid.clone()).body().unwrap();
    let second = body[80..88].to_vec();
    body[72..80].copy_from_slice(&second);
    let mut medium = Medium::default();
    let mut packer = Packer::default();
    push(&mut packer, 0, (kind, &body));
    packer.seal();
    medium.units.insert(
        0,
        seal(
            Crc32c::detect(),
            block(0),
            &packer.sealed.pop_front().unwrap(),
        ),
    );
    let load = medium.replay(&[], 0, &[suffix(0, 1, 1)]);
    assert_eq!(load.entries, vec![]);
    assert_eq!(
        load.report.damage.len(),
        1,
        "a decoded entry with overlapping extents is a hole"
    );
    // A crc-valid INSERT of a slot past the pool's, or a REPLACE whose new entry lies past the payload, is a
    // content hole that applies neither half, so it supersedes no valid entry.
    let x = owner(0, &[(2, 1)]);
    let mut past_slot = owner(64, &[(2, 1)]);
    past_slot.key[9] = 1;
    let mut past_payload = owner(1, &[(1 << 30, 1)]);
    past_payload.key[9] = 2;
    for record in [
        Record::Insert(past_slot),
        Record::Replace {
            old: identity_of(&x),
            cause: Cause::Evict,
            new: past_payload,
        },
    ] {
        let mut medium = Medium::default();
        medium.write(0, packed(0, &[record]));
        let load = medium.replay(std::slice::from_ref(&x), 0, &[suffix(0, 1, 1)]);
        assert_eq!(load.entries, vec![x.clone()]);
        assert!(load.report.excluded.is_empty() && load.report.superseded.is_empty());
        assert_eq!(
            load.report.damage,
            vec![Hole {
                lsn: 0,
                cause: BlockHole::Content
            }]
        );
    }
    // A base entry whose own extents overlap is withheld, so it claims no unit another entry owns.
    let overlapping = owner(2, &[(10, 3), (11, 1)]);
    let mut neighbour = owner(3, &[(12, 1)]);
    neighbour.key[9] = 3;
    let load = Medium::default().replay(&[neighbour.clone(), overlapping.clone()], 0, &[]);
    assert_eq!(load.entries, vec![neighbour.clone()]);
    assert_eq!(load.report.withheld, ids(&[overlapping]));
    let mut tail_past_record = owner(4, &[(40, 1)]);
    tail_past_record.key[9] = 4;
    tail_past_record.tail = 1;
    let mut second_past_payload = owner(5, &[(50, 1), ((1 << 30) - 1, 2)]);
    second_past_payload.key[9] = 5;
    let mut base_past_slot = owner(64, &[(60, 1)]);
    base_past_slot.key[9] = 6;
    let mut foreign_session = owner(6, &[(70, 1)]);
    foreign_session.key[9] = 7;
    foreign_session.session = (4 << 32) | 2;
    let mut future_epoch = owner(7, &[(80, 1)]);
    future_epoch.key[9] = 8;
    future_epoch.session = SESSION + 2;
    for misfit in [
        tail_past_record,
        second_past_payload,
        base_past_slot,
        foreign_session,
        future_epoch,
    ] {
        let load = Medium::default().replay(&[neighbour.clone(), misfit.clone()], 0, &[]);
        assert_eq!(load.entries, vec![neighbour.clone()], "{misfit:?}");
        assert_eq!(load.report.withheld, ids(std::slice::from_ref(&misfit)));
        let mut successor = misfit.clone();
        successor.key = neighbour.key;
        let mut medium = Medium::default();
        medium.write(0, packed(0, &[Record::Insert(successor)]));
        let load = medium.replay(std::slice::from_ref(&neighbour), 0, &[suffix(0, 1, 1)]);
        assert_eq!(load.entries, vec![neighbour.clone()], "{misfit:?}");
        assert_eq!(load.report.damage.len(), 1);
    }
    for invalid in [
        LoadLimits {
            record_chunk_len: 0,
            ..limits()
        },
        LoadLimits {
            reserve_units: 1 << 31,
            ..limits()
        },
    ] {
        let layout = Layout {
            units: 1 << 10,
            slots: 0,
            slot_units: 0,
            entries: 0,
        };
        let refused = replay(
            (Crc32c::detect(), shard(), SESSION),
            (&layout, &invalid),
            vec![neighbour.clone()],
            0,
            &[],
            |_, _| true,
        );
        assert_eq!(refused, Err(super::load_guard::LoadRefusal::Limits));
    }
}

/// Over checkpoints of pairwise disjoint entries and one to three suffix levels of random INSERTs, REMOVEs and
/// REPLACEs that reuse checkpoint keys, slots and units, the suffix-only replay plus each checkpoint entry's patch fate
/// equals the batch replay over checkpoint and suffix: the same live entries in the same order, the same report for the
/// suffix's own entries, and the checkpoint entries it names excluded or superseded. A patch blind to shared units
/// keeps an entry the batch replay supersedes.
#[test]
fn the_patch_fate_of_a_base_entry_equals_its_batch_resolve_fate() {
    let mut rng = crate::storage::seeded::SplitMix64::new(0x1445B);
    let (mut fates, mut span_blind) = ([0; 3], false);
    for _ in 0..1000 {
        let count = 1 + rng.below(40) as usize;
        let base: Vec<CaptureEntry> = (0..count)
            .map(|at| wide(at, 4 * at as u64, 1 + rng.below(3) as usize))
            .collect();
        let (mut medium, mut chain, mut serial) = (Medium::default(), Vec::new(), 0);
        for _ in 0..1 + rng.below(3) {
            let records: Vec<Record> = (0..rng.below(8))
                .map(|_| {
                    serial += 1;
                    let of = &base[rng.below(count as u64) as usize];
                    let mut made = wide(count + serial, 4 * (count + serial) as u64, 1);
                    match rng.below(5) {
                        0 => made.allocation = of.allocation + 1,
                        1 => made.extents = vec![of.extents[of.extents.len() - 1]],
                        2 => made.key = of.key,
                        _ => {}
                    }
                    match rng.below(4) {
                        0 => remove(of, Cause::Evict),
                        1 => Record::Replace {
                            old: identity_of(of),
                            cause: Cause::Invalidate,
                            new: made,
                        },
                        _ => Record::Insert(made),
                    }
                })
                .collect();
            let start = medium.units.keys().max().map_or(0, |max| max + 1);
            let head = medium.write(start, packed(start, &records));
            chain.push(suffix(start, head, head));
        }
        let batch = medium.replay(&base, 0, &chain);
        let (live, report, patch) = medium.patch(0, &chain);
        let fate: Vec<Fate> = base.iter().map(|entry| patch.fate_of(entry)).collect();
        let kept = (base.iter().zip(&fate))
            .filter(|(_, fate)| **fate == Fate::Kept)
            .map(|(entry, _)| entry.clone());
        assert_eq!(kept.chain(live).collect::<Vec<_>>(), batch.entries);
        let named = |of: Fate| -> Vec<Identity> {
            (base.iter().zip(&fate))
                .filter(|(_, fate)| **fate == of)
                .map(|(entry, _)| identity_of(entry))
                .collect()
        };
        let mut own = batch.report.clone();
        own.superseded.retain(|id| !ids(&base).contains(id));
        assert_eq!(report, own);
        let superseded = batch
            .report
            .superseded
            .iter()
            .filter(|id| ids(&base).contains(id));
        assert_eq!(
            superseded.copied().collect::<Vec<_>>(),
            named(Fate::Superseded)
        );
        let excluded = named(Fate::Excluded);
        assert!(excluded.iter().all(|id| batch.report.excluded.contains(id)));
        for (at, of) in [Fate::Kept, Fate::Excluded, Fate::Superseded]
            .into_iter()
            .enumerate()
        {
            fates[at] += usize::from(fate.contains(&of));
        }
        span_blind |= planted(Plant::SpanBlind, || {
            base.iter()
                .zip(&fate)
                .any(|(entry, fate)| patch.fate_of(entry) != *fate)
        });
    }
    assert!(
        fates.iter().all(|&count| count > 0),
        "every fate is reached: {fates:?}"
    );
    assert!(
        span_blind,
        "control: a patch blind to shared units keeps an entry the batch replay supersedes"
    );
}

/// A later level that reinserts every key of an earlier level onto the same units supersedes every earlier entry, over
/// `2^14` such pairs.
#[test]
fn a_level_that_reuses_every_unit_of_an_earlier_level_supersedes_each_entry() {
    let count = 1 << 14;
    let earlier: Vec<CaptureEntry> = (0..count).map(|at| wide(at, 4 * at as u64, 1)).collect();
    let later: Vec<CaptureEntry> = (0..count)
        .map(|at| {
            let mut entry = wide(at, 4 * at as u64, 1);
            entry.allocation += 1;
            entry.key[20] = 1;
            entry
        })
        .collect();
    let first: Vec<Record> = earlier.iter().cloned().map(Record::Insert).collect();
    let second: Vec<Record> = later.iter().cloned().map(Record::Insert).collect();
    let mut medium = Medium::default();
    let head = medium.write(0, packed(0, &first));
    let end = medium.write(head, packed(head, &second));
    let layout = Layout {
        units: 1 + (1 << 20),
        slots: 0,
        slot_units: 0,
        entries: 0,
    };
    let wide_limits = LoadLimits {
        slot_count: 2 * count,
        ..limits()
    };
    let load = replay(
        (Crc32c::detect(), shard(), SESSION),
        (&layout, &wide_limits),
        Vec::new(),
        0,
        &[suffix(0, head, head), suffix(head, end, end)],
        |lsn, unit| {
            *unit = medium.units.get(&lsn).map_or([0; UNIT_LEN], |unit| **unit);
            true
        },
    )
    .unwrap();
    assert_eq!(load.entries, later);
    assert_eq!(load.report.superseded, ids(&earlier));
}

/// A barred span that starts below an earlier entry's extent still bars it: a later level's withheld pair, one spanning
/// units 20..30 and one on unit 29, supersedes a checkpoint entry on unit 25 and one on unit 163 that a span of
/// `DIRECT_UNITS` units from 100 covers at its last unit, and keeps the entry on unit 30 beside them. The suffix-only
/// patch gives each checkpoint entry the same fate.
#[test]
fn a_bar_starting_before_an_earlier_extent_supersedes_it_and_its_neighbour_stays() {
    let wide_span = crate::storage::geometry::DIRECT_UNITS;
    let inside = owner(0, &[(25, 1)]);
    let neighbour = owner(1, &[(30, 1)]);
    let last_unit = owner(2, &[(163, 1)]);
    let spanning = owner(3, &[(20, 10)]);
    let sharing = owner(4, &[(29, 1)]);
    let far = owner(5, &[(100, wide_span)]);
    let mut far_pair = owner(6, &[(120, 1)]);
    far_pair.key[9] = 1;
    let mut medium = Medium::default();
    let records = [
        spanning.clone(),
        sharing.clone(),
        far.clone(),
        far_pair.clone(),
    ]
    .map(Record::Insert);
    let end = medium.write(0, packed(0, &records));
    let chain = [suffix(0, end, end)];
    let base = [inside.clone(), neighbour.clone(), last_unit.clone()];
    let load = medium.replay(&base, 0, &chain);
    assert_eq!(load.entries, vec![neighbour.clone()]);
    assert_eq!(
        load.report.superseded,
        ids(&[inside.clone(), last_unit.clone()])
    );
    let mut withheld = load.report.withheld.clone();
    withheld.sort_by_key(|id| id.key);
    let mut expected = ids(&[spanning, sharing, far, far_pair]);
    expected.sort_by_key(|id| id.key);
    assert_eq!(withheld, expected);
    let (_, _, patch) = medium.patch(0, &chain);
    let fates = base.map(|entry| patch.fate_of(&entry));
    assert_eq!(fates, [Fate::Superseded, Fate::Kept, Fate::Superseded]);
}

/// A checkpoint entry meets a live suffix entry on part of a multi-unit extent, or only in the second 64-unit block of
/// an extent that crosses a block edge, and is superseded; one that ends where the suffix entry starts is kept.
#[test]
fn the_patch_supersedes_a_partial_or_second_block_overlap_and_keeps_an_adjacent_extent() {
    let patch_of = |live: &[CaptureEntry]| {
        let mut medium = Medium::default();
        let records: Vec<Record> = live.iter().cloned().map(Record::Insert).collect();
        let end = medium.write(0, packed(0, &records));
        let (entries, _, patch) = medium.patch(0, &[suffix(0, end, end)]);
        assert_eq!(entries, live.to_vec());
        patch
    };
    // Two abutting suffix spans merge into one, units 80 to 84, so an entry on unit 83 meets the merged span's end.
    let merged = patch_of(&[owner(12, &[(80, 2)]), owner(13, &[(82, 2)])]);
    assert_eq!(merged.fate_of(&owner(24, &[(83, 1)])), Fate::Superseded);
    assert_eq!(merged.fate_of(&owner(25, &[(84, 1)])), Fate::Kept);
    let partial_patch = patch_of(&[owner(10, &[(42, 1)])]);
    assert_eq!(
        partial_patch.fate_of(&owner(20, &[(40, 4)])),
        Fate::Superseded
    );
    assert_eq!(partial_patch.fate_of(&owner(22, &[(38, 4)])), Fate::Kept);
    // The patch's only span lies in the 64-unit block from unit 64, so only the probe of the extent's second block
    // reaches the span search.
    let second_patch = patch_of(&[owner(11, &[(66, 1)])]);
    assert_eq!(
        second_patch.fate_of(&owner(21, &[(60, 10)])),
        Fate::Superseded
    );
    assert_eq!(second_patch.fate_of(&owner(23, &[(60, 4)])), Fate::Kept);
}

/// A patch of more spans than a few sampled runs hold supersedes an entry on the last unit of any span, the spans at
/// each run's edges included, and keeps an entry in the gap after it, before the first span and past the last. The
/// suffix entries reuse the limits' 64 slots, and the entries of one slot share a key: the replay supersedes all but
/// the last of each slot, and the patch holds the span of every entry.
#[test]
fn a_patch_of_many_spans_supersedes_on_each_span_and_keeps_each_gap() {
    let start = |at: u64| 1000 + 8 * at;
    let live: Vec<CaptureEntry> = (0..300)
        .map(|at| owner((at % 64) as usize, &[(start(at), 2)]))
        .collect();
    let mut medium = Medium::default();
    let records: Vec<Record> = live.iter().cloned().map(Record::Insert).collect();
    let end = medium.write(0, packed(0, &records));
    let (_, report, patch) = medium.patch(0, &[suffix(0, end, end)]);
    assert!(report.installable() && report.excluded.is_empty());
    for at in 0..300 {
        let on = owner(1000 + at as usize, &[(start(at) + 1, 1)]);
        let after = owner(2000 + at as usize, &[(start(at) + 2, 6)]);
        assert_eq!(patch.fate_of(&on), Fate::Superseded, "span {at}");
        assert_eq!(patch.fate_of(&after), Fate::Kept, "the gap after span {at}");
    }
    assert_eq!(patch.fate_of(&owner(3000, &[(990, 10)])), Fate::Kept);
    assert_eq!(patch.fate_of(&owner(3001, &[(start(300), 4)])), Fate::Kept);
}

/// A patch of more keys and excluded identities than a few buckets hold excludes an entry of an excluded identity,
/// keeps an entry that shares only an excluded identity's key, supersedes an entry with a suffix entry's key, and
/// keeps an entry of any other key. The same records in the reverse order replay to an equal patch.
#[test]
fn a_patch_of_many_keys_finds_each_key_and_each_excluded_identity() {
    let keyed = |slot: usize, unit: u64, tag: u8, at: u16| {
        let mut entry = owner(slot, &[(unit, 1)]);
        entry.key[16] = tag;
        entry.key[24..26].copy_from_slice(&at.to_le_bytes());
        entry
    };
    // Suffix entries on slots 0 to 31 and units from 1000; removed identities that no suffix entry names.
    let live: Vec<CaptureEntry> = (0..300)
        .map(|at| keyed(usize::from(at % 32), 1000 + 8 * u64::from(at), 1, at))
        .collect();
    let gone: Vec<CaptureEntry> = (0..200)
        .map(|at| keyed(40, 20_000 + 8 * u64::from(at), 2, at))
        .collect();
    let inserts = live.iter().cloned().map(Record::Insert);
    let removes = gone.iter().map(|entry| remove(entry, Cause::Evict));
    let records: Vec<Record> = inserts.chain(removes).collect();
    let patch_of = |records: &[Record]| {
        let mut medium = Medium::default();
        let end = medium.write(0, packed(0, records));
        let (_, report, patch) = medium.patch(0, &[suffix(0, end, end)]);
        assert!(report.installable());
        patch
    };
    let patch = patch_of(&records);
    for (at, entry) in live.iter().enumerate() {
        // On a slot and a unit no suffix entry holds, so only the key decides.
        let free = owner(50, &[(40_000 + 8 * at as u64, 1)]);
        let mut shares = free.clone();
        shares.key = entry.key;
        let mut other = shares.clone();
        other.key[16] = 3;
        assert_eq!(patch.fate_of(&shares), Fate::Superseded, "key {at}");
        assert_eq!(patch.fate_of(&other), Fate::Kept, "beside key {at}");
    }
    for (at, entry) in gone.iter().enumerate() {
        let mut later = entry.clone();
        later.version += 1;
        assert_eq!(patch.fate_of(entry), Fate::Excluded, "identity {at}");
        assert_eq!(patch.fate_of(&later), Fate::Kept, "beside identity {at}");
    }
    let reversed: Vec<Record> = records.into_iter().rev().collect();
    assert_eq!(patch_of(&reversed), patch);
}

thread_local! {
    static COMPARED: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug, Clone, Copy, Default)]
struct Probe(Key);

impl PartialEq for Probe {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for Probe {}

impl PartialOrd for Probe {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Probe {
    fn cmp(&self, other: &Self) -> Ordering {
        COMPARED.set(COMPARED.get() + 1);
        self.0.cmp(&other.0)
    }
}

/// The keys share a zero wordwise xor, so the test exercises lookups within one collision bucket.
#[test]
fn keys_of_one_wordwise_xor_are_searched_in_a_logarithmic_count_of_comparisons() {
    const HELD: u64 = 1 << 12;
    // Two equal words and two zero words xor to zero.
    let key = |at: u64| {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&at.to_le_bytes());
        key[8..16].copy_from_slice(&at.to_le_bytes());
        Probe(key)
    };
    let held = Bucketed::new((0..HELD).map(|at| key(2 * at)), |probe| &probe.0);
    let most = 2 * (HELD.ilog2() as usize + 1);
    for at in 0..2 * HELD {
        let probe = key(at);
        COMPARED.set(0);
        assert_eq!(held.holds(&probe, &probe.0), at % 2 == 0, "key {at}");
        let compared = COMPARED.get();
        assert!(compared <= most, "key {at} took {compared} comparisons");
    }
}

/// Entries passed with one seek get the fates they get alone, whether their slots ascend, repeat or fall back below
/// an earlier one: an entry on a suffix entry's slot is superseded, and any other is kept.
#[test]
fn a_seek_over_entries_in_any_slot_order_gives_each_its_own_fate() {
    let held = [3, 7, 20, 41];
    let live: Vec<CaptureEntry> = (held.iter().zip(0..))
        .map(|(&slot, at)| owner(slot, &[(5000 + 8 * at, 1)]))
        .collect();
    let mut medium = Medium::default();
    let records: Vec<Record> = live.iter().cloned().map(Record::Insert).collect();
    let end = medium.write(0, packed(0, &records));
    let (_, _, patch) = medium.patch(0, &[suffix(0, end, end)]);
    let mut seek = Seek::default();
    for (at, slot) in [1, 3, 5, 7, 7, 60, 41, 20, 2, 3, 63, 41]
        .into_iter()
        .enumerate()
    {
        // A key and a unit no suffix entry holds, so only the slot decides.
        let mut entry = owner(slot, &[(100 + 8 * at as u64, 1)]);
        entry.key[16] = 1 + at as u8;
        let expected = match held.contains(&slot) {
            true => Fate::Superseded,
            false => Fate::Kept,
        };
        let fate = patch.fate(&mut seek, &identity_of(&entry), &entry.extents);
        assert_eq!(
            (fate, patch.fate_of(&entry)),
            (expected, expected),
            "slot {slot} at {at}"
        );
    }
}

/// An extent far longer than any valid one, which the load guard refuses as out of bounds, gets its exact fate: it
/// meets the suffix's span and is superseded, or lies past it and is kept.
#[test]
fn a_patch_gives_an_overlong_extent_its_exact_fate() {
    let live = owner(10, &[(5000, 1)]);
    let mut medium = Medium::default();
    let end = medium.write(0, packed(0, &[Record::Insert(live)]));
    let (_, _, patch) = medium.patch(0, &[suffix(0, end, end)]);
    let meeting = owner(20, &[(0, 1 << 20)]);
    let past = owner(21, &[(6000, 1 << 20)]);
    assert_eq!(patch.fate_of(&meeting), Fate::Superseded);
    assert_eq!(patch.fate_of(&past), Fate::Kept);
}

/// The patch of a replay that found nothing keeps every entry.
#[test]
fn an_empty_patch_keeps_every_entry() {
    let patch = Patch::new(&SuffixReport::default(), std::iter::empty());
    assert!(patch.is_empty());
    assert_eq!(patch.fate_of(&owner(0, &[(3, 2)])), Fate::Kept);
}
