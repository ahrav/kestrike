//! The checkpoint unit codec: a slot round-trips in any arrival order, a torn, foreign, missing or repeated unit stays undecoded and loses only the entries with a row on it, and the streamed guard returns the batch guard's verdict.

use super::capture::CaptureEntry;

use super::checkpoint::*;
use crate::index::KeyHasher;
use crate::net::ownership::Shard;
use crate::storage::extent::ExtentLocator;
use crate::storage::record::Crc32c;

pub(crate) const SESSION: u64 = (3 << 32) | 4;

/// The capture tests' entry of `slot`, `incarnation` and first unit `start`, under the session the decode's reader
/// admits, since a slot load withholds an entry of a session its reader does not admit.
fn entry(slot: usize, incarnation: u32, start: u64) -> CaptureEntry {
    CaptureEntry {
        session: SESSION,
        ..super::capture_tests::entry(slot, incarnation, start)
    }
}

pub(crate) fn checkpoint(capture: u32) -> Checkpoint {
    Checkpoint {
        shard: Shard::new(7).unwrap(),
        session: SESSION,
        capture,
    }
}

pub(crate) fn entries(count: usize) -> Vec<CaptureEntry> {
    (0..count)
        .map(|at| {
            let mut entry = entry(at, 2, 64 * at as u64);
            entry.extents = (0..1 + at % 3)
                .map(|extent| {
                    ExtentLocator::new(64 * at as u64 + 8 * extent as u64, 1)
                        .unwrap()
                        .bits()
                })
                .collect();
            entry
        })
        .collect()
}

fn limits() -> super::LoadLimits {
    super::LoadLimits {
        payload_end: 1 << 20,
        slot_count: 1 << 10,
        n_max: 1 << 10,
        ..super::capture_tests::limits()
    }
}

/// A prefix layout with no delta region, for a decode with no suffix.
pub(crate) fn no_suffix() -> crate::failover::records::Layout {
    crate::failover::records::Layout {
        units: 1,
        slots: 0,
        slot_units: 0,
        entries: 0,
    }
}

/// `entries` in one total order, so loads compare as entry sets: a load holds its entries by destination.
pub(crate) fn canonical(mut entries: Vec<CaptureEntry>) -> Vec<CaptureEntry> {
    entries.sort_by(|a, b| {
        let fields = |e: &CaptureEntry| {
            let times = (e.session, e.version, e.deadline_ns, e.lifetime_ms, e.tail);
            (e.allocation, e.key, e.extents.clone(), times)
        };
        fields(a).cmp(&fields(b))
    });
    entries
}

/// `load` with its entries in [`canonical`] order.
pub(crate) fn canon(load: super::GuardedLoad) -> super::GuardedLoad {
    match load {
        super::GuardedLoad::Warm(entries) => super::GuardedLoad::Warm(canonical(entries)),
        super::GuardedLoad::Cold { entries, refusal } => super::GuardedLoad::Cold {
            entries: canonical(entries),
            refusal,
        },
    }
}

impl Chunk {
    /// Each entry as the capture entry it loads, with its key's routing fingerprint.
    pub(crate) fn captured(&self) -> Vec<(CaptureEntry, u64)> {
        let captured = |(entry, extents): (&Loaded, &[u64])| CaptureEntry {
            key: entry.identity.key,
            allocation: entry.identity.allocation,
            session: entry.identity.session,
            version: entry.identity.version,
            deadline_ns: entry.deadline_ns,
            lifetime_ms: entry.lifetime_ms,
            tail: entry.tail,
            extents: extents.to_vec(),
        };
        let entries =
            (self.placed()).map(|(_, entry, extents)| (captured((entry, extents)), entry.print));
        entries.collect()
    }
}

impl SlotLoad {
    /// The final entries of every destination in [`canonical`] order, warm or cold with the verdict's refusal.
    pub(crate) fn load(&self) -> super::GuardedLoad {
        let entries = self.shards.iter().flatten().flat_map(Chunk::captured);
        let entries = canonical(entries.map(|(entry, _)| entry).collect());
        match self.verdict {
            Ok(()) => super::GuardedLoad::Warm(entries),
            Err(refusal) => super::GuardedLoad::Cold { entries, refusal },
        }
    }
}

/// The load of a slot that decoded with no damage.
pub(crate) fn whole(slot: SlotLoad) -> super::GuardedLoad {
    assert_eq!(slot.damage, None, "the slot decodes whole");
    slot.load()
}

/// The damage and load of a damaged slot.
pub(crate) fn damaged(slot: SlotLoad) -> (Damage, super::GuardedLoad) {
    let load = slot.load();
    (slot.damage.expect("the slot is damaged"), load)
}

/// The entries of `load`, whatever its verdict.
pub(crate) fn loaded(load: super::GuardedLoad) -> Vec<CaptureEntry> {
    let (super::GuardedLoad::Warm(entries) | super::GuardedLoad::Cold { entries, .. }) = load;
    entries
}

/// The entries of `entries` with no row in data unit `unit`: row `r` lies in unit `1 + r / UNIT_ENTRIES`.
pub(crate) fn outside(entries: &[CaptureEntry], unit: usize) -> Vec<CaptureEntry> {
    let rows = crate::failover::records::UNIT_ENTRIES as usize;
    let mut first = 0;
    let mut kept = Vec::new();
    for entry in entries {
        let last = first + entry.extents.len() - 1;
        if !(1 + first / rows..=1 + last / rows).contains(&unit) {
            kept.push(entry.clone());
        }
        first = last + 1;
    }
    kept
}

/// `entries` with every key after the first rewritten so that all keys stay distinct and share the first key's
/// fingerprint.
pub(crate) fn colliding(entries: &[CaptureEntry]) -> Vec<CaptureEntry> {
    let mut entries = entries.to_vec();
    let word =
        |key: &[u8; 32], at: usize| u64::from_le_bytes(key[8 * at..8 * at + 8].try_into().unwrap());
    let base = entries[0].key;
    // Every later key xors `d` into the first key's first word and `d` rotated right 16 bits into its second word;
    // the fold rotates the second word left 16 bits, so both xors cancel and every key folds to the first key's word.
    for (at, entry) in entries.iter_mut().enumerate().skip(1) {
        let d = (at as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        entry.key[..8].copy_from_slice(&(word(&base, 0) ^ d).to_le_bytes());
        entry.key[8..16].copy_from_slice(&(word(&base, 1) ^ d.rotate_right(16)).to_le_bytes());
        entry.key[16..].copy_from_slice(&base[16..]);
        assert_eq!(
            super::load_guard::fingerprint(&entry.key),
            super::load_guard::fingerprint(&base)
        );
        assert_ne!(entry.key, base);
    }
    entries
}

/// A fixed hasher and `destinations` destinations: a decode routes each key to the destination whose position the
/// hasher's fingerprint selects among `destinations` enabled shards.
pub(crate) fn routing(destinations: usize) -> (KeyHasher, usize) {
    (KeyHasher::with_key_pair(0x1445, 0x1438), destinations)
}

/// Runs `job` and every destination job the decode then offers, inline.
pub(crate) fn settle(decode: &mut SlotDecode, job: Option<Work>) {
    let mut jobs: Vec<Work> = job.into_iter().collect();
    while let Some(job) = jobs.pop().or_else(|| decode.work()) {
        decode.landed(run(job));
    }
}

/// A decode of capture 5 over four destinations whose units each land as a one-unit window, recording the units fed.
pub(crate) struct Fed {
    pub(crate) decode: SlotDecode,
    fed: Vec<bool>,
}

impl Fed {
    pub(crate) fn new(units: usize, destinations: usize) -> Self {
        Self::under(units, limits(), destinations)
    }

    pub(crate) fn under(units: usize, limits: super::LoadLimits, destinations: usize) -> Self {
        Self::reading(units, limits, destinations, SESSION)
    }

    /// A decode of capture 5 over four destinations for a reader of session `reader`.
    pub(crate) fn read_by(units: usize, reader: u64) -> Self {
        Self::reading(units, limits(), 4, reader)
    }

    fn reading(units: usize, limits: super::LoadLimits, destinations: usize, reader: u64) -> Self {
        let decode = SlotDecode::new(
            Crc32c::detect(),
            checkpoint(5),
            units as u32,
            reader,
            limits,
            routing(destinations),
            (no_suffix(), 0, &[]),
        )
        .unwrap();
        Self {
            decode,
            fed: vec![false; units],
        }
    }

    /// A decode of capture 5 under `limits` whose ancestry is one suffix of `records` from LSN 0, every block of
    /// which lands before any unit.
    pub(crate) fn with_suffix(
        units: usize,
        records: &[super::delta::Record],
        limits: super::LoadLimits,
    ) -> Self {
        let blocks = super::delta_tests::packed(0, records);
        let count = blocks.len() as u64;
        let prefix = crate::failover::records::Layout {
            units: 1 + count,
            ..no_suffix()
        };
        let ancestry = [crate::failover::records::Suffix {
            session: SESSION,
            start: 0,
            certified: count,
            end: count,
        }];
        let mut decode = SlotDecode::new(
            Crc32c::detect(),
            checkpoint(5),
            units as u32,
            SESSION,
            limits,
            routing(4),
            (prefix, 0, &ancestry),
        )
        .unwrap();
        decode.blocks(
            0,
            count,
            blocks
                .iter()
                .flat_map(|unit| unit.iter().copied())
                .collect(),
        );
        Self {
            decode,
            fed: vec![false; units],
        }
    }

    /// Lands unit `unit` from `bytes`, unread when `bytes` is empty.
    pub(crate) fn land(&mut self, unit: usize, bytes: &[u8]) {
        self.fed[unit] = true;
        let job = self.decode.window(unit as u32, 1, bytes.to_vec());
        settle(&mut self.decode, Some(job));
    }

    /// Lands `units` as one window from unit `first`.
    pub(crate) fn land_window(&mut self, first: usize, units: &[Box<[u8; UNIT_LEN]>]) {
        self.fed[first..first + units.len()].fill(true);
        let bytes = units.iter().flat_map(|unit| unit.iter().copied()).collect();
        let job = self.decode.window(first as u32, units.len() as u32, bytes);
        settle(&mut self.decode, Some(job));
    }

    /// The load once every unit not fed landed unread, as the reader reports a unit it could not read.
    pub(crate) fn finish(mut self) -> SlotLoad {
        for unit in 0..self.fed.len() {
            if !self.fed[unit] {
                self.land(unit, &[]);
            }
        }
        assert!(self.decode.done());
        self.decode.finish().expect("no helper failed")
    }
}

fn decode(units: &[Box<[u8; UNIT_LEN]>], order: impl Iterator<Item = usize>) -> Fed {
    let mut fed = Fed::new(units.len(), 4);
    for at in order {
        fed.land(at, &units[at][..]);
    }
    fed
}

/// A destination's sealing job hands its bitmaps and key words to its runner apart from the guard it returns, a job of
/// another kind hands over nothing, and the decode finishes the same load whether or not a runner took them.
#[test]
fn a_sealing_job_hands_its_spent_buffers_to_its_runner() {
    let entries = entries(100);
    let units = encode(Crc32c::detect(), checkpoint(5), &entries, u32::MAX).unwrap();
    let mut fed = Fed::new(units.len(), 4);
    let (mut handed, mut seals) = (0, 0);
    for (at, unit) in units.iter().enumerate() {
        fed.fed[at] = true;
        let mut jobs = vec![fed.decode.window(at as u32, 1, unit.to_vec())];
        while let Some(job) = jobs.pop().or_else(|| fed.decode.work()) {
            let mut done = run(job);
            let spent: usize = done.spent().iter().map(Vec::capacity).sum();
            assert!(done.spent().is_empty(), "a job hands its buffers over once");
            seals += usize::from(spent > 0);
            handed += spent * 8;
            fed.decode.landed(done);
        }
    }
    let bitmaps = 4 * fed.decode.guard_capacity();
    assert_eq!(seals, 4, "each destination's seal hands buffers over");
    assert!(
        handed >= bitmaps,
        "{handed} bytes handed of {bitmaps} bitmap bytes"
    );
    let taken = fed.finish();
    assert_eq!(taken, decode(&units, 0..units.len()).finish());
    assert_eq!(whole(taken), super::GuardedLoad::Warm(entries));
}

#[test]
fn a_slot_round_trips_in_any_arrival_order() {
    let crc = Crc32c::detect();
    // Entry `at` owns `1 + at % 3` extents, so the counts hold 0, 1, 25, 81, 84 and 199 rows.
    for (count, rows, units) in [
        (0, 0, 1),
        (1, 1, 2),
        (13, 25, 2),
        (41, 81, 3),
        (42, 84, 4),
        (100, 199, 6),
    ] {
        let entries = entries(count);
        assert_eq!(super::checkpoint::rows(&entries), rows, "{count} entries");
        let units_of = encode(crc, checkpoint(5), &entries, u32::MAX).unwrap();
        assert_eq!(
            units_of.len(),
            units,
            "{count} entries span 1 + ceil({rows} / 41) units"
        );
        let units = units_of;
        let forward = decode(&units, 0..units.len());
        assert_eq!(
            whole(forward.finish()),
            super::GuardedLoad::Warm(entries.clone()),
            "{count} entries in order"
        );
        let backward = decode(&units, (0..units.len()).rev());
        assert_eq!(
            whole(backward.finish()),
            super::GuardedLoad::Warm(entries.clone()),
            "{count} entries reversed"
        );
    }
}

/// A torn sector fails its unit's check, the damage names that unit alone, and the load keeps every entry with no row
/// on it: every entry when unit 0, which holds only counts, is torn.
#[test]
fn a_torn_unit_loses_only_the_entries_with_a_row_on_it() {
    let crc = Crc32c::detect();
    let entries = entries(60);
    let units = encode(crc, checkpoint(5), &entries, u32::MAX).unwrap();
    for unit in 0..units.len() {
        for sector in 0..UNIT_LEN / 512 {
            let mut torn = units.clone();
            torn[unit][sector * 512..(sector + 1) * 512].fill(0xA5);
            let decoded = decode(&torn, 0..torn.len());
            let (damage, load) = damaged(decoded.finish());
            assert!(
                matches!(
                    damage.first,
                    UnitDamage::Header { .. } | UnitDamage::Chunk { .. }
                ),
                "unit {unit} sector {sector}: {:?}",
                damage.first
            );
            assert_eq!((damage.failed, damage.unread), (vec![unit as u32], vec![]));
            assert_eq!(
                load,
                super::GuardedLoad::Warm(outside(&entries, unit)),
                "unit {unit} sector {sector}"
            );
        }
    }
}

#[test]
fn a_unit_of_another_checkpoint_fails_its_identity() {
    let crc = Crc32c::detect();
    let entries = entries(60);
    let named = encode(crc, checkpoint(5), &entries, u32::MAX).unwrap();
    let earlier = encode(crc, checkpoint(4), &entries, u32::MAX).unwrap();
    let other_session = encode(
        crc,
        Checkpoint {
            session: SESSION - 2,
            ..checkpoint(5)
        },
        &entries,
        u32::MAX,
    )
    .unwrap();
    let other_shard = encode(
        crc,
        Checkpoint {
            shard: Shard::new(8).unwrap(),
            ..checkpoint(5)
        },
        &entries,
        u32::MAX,
    )
    .unwrap();
    for stale in [&earlier, &other_session, &other_shard] {
        let mut mixed = named.clone();
        mixed[1] = stale[1].clone();
        let (damage, load) = damaged(decode(&mixed, 0..mixed.len()).finish());
        assert!(
            matches!(damage.first, UnitDamage::Header { unit: 1, .. }),
            "{damage:?}"
        );
        assert_eq!((damage.failed, damage.unread), (vec![1], vec![]));
        assert_eq!(load, super::GuardedLoad::Warm(outside(&entries, 1)));
    }
    let mut moved = named.clone();
    moved.swap(1, 2);
    let (damage, load) = damaged(decode(&moved, 0..moved.len()).finish());
    assert!(
        matches!(damage.first, UnitDamage::Header { unit: 1, .. }),
        "a unit read at another index: {damage:?}"
    );
    assert_eq!(damage.failed, [1, 2]);
    let past_unit_2 = outside(&entries, 2);
    let kept: Vec<CaptureEntry> = outside(&entries, 1)
        .into_iter()
        .filter(|entry| past_unit_2.contains(entry))
        .collect();
    assert_eq!(load, super::GuardedLoad::Warm(kept));
}

#[test]
fn a_slot_missing_a_unit_keeps_the_rest_and_a_unit_0_naming_another_count_fails() {
    let crc = Crc32c::detect();
    let entries = entries(60);
    let units = encode(crc, checkpoint(5), &entries, u32::MAX).unwrap();
    let (damage, load) = damaged(decode(&units, 0..units.len() - 1).finish());
    let last = units.len() - 1;
    assert_eq!(damage.first, UnitDamage::Unread { unit: last as u32 });
    assert_eq!(damage.alarm(), super::LoadRefusal::Unreadable);
    assert_eq!(
        (damage.failed, damage.unread),
        (vec![], vec![last as u32]),
        "a unit that never arrived may still be read"
    );
    assert_eq!(load, super::GuardedLoad::Warm(outside(&entries, last)));
    let mut short = Fed::new(units.len() - 1, 1);
    short.land(0, &units[0][..]);
    assert!(matches!(
        short.decode.damage(),
        Some(UnitDamage::Units { .. })
    ));
    let empty = CaptureEntry {
        extents: Vec::new(),
        ..entry(0, 2, 0)
    };
    assert_eq!(
        encode(crc, checkpoint(5), &[empty], u32::MAX),
        Err(EncodeRefusal::Extents {
            allocation: entry(0, 2, 0).allocation
        })
    );
}

/// Units that each pass their identity and crc checks but come from two encodings under one identity break an entry
/// across a unit boundary. No unit is damaged, so the inconsistency cannot be another unit's loss: the slot loads
/// cold with the stale-write refusal, and the entry the foreign unit starts is evicted, not loaded.
#[test]
fn a_slot_whose_intact_units_break_an_entry_loads_cold() {
    let crc = Crc32c::detect();
    let mut spanning: Vec<CaptureEntry> = (0..41).map(|at| entry(at, 2, 64 * at as u64)).collect();
    spanning[40].extents = vec![
        ExtentLocator::new(5000, 1).unwrap().bits(),
        ExtentLocator::new(5008, 1).unwrap().bits(),
    ];
    let mut later: Vec<CaptureEntry> = (0..41).map(|at| entry(at, 2, 64 * at as u64)).collect();
    later.push(entry(100, 2, 6400));
    let cut = encode(crc, checkpoint(5), &spanning, u32::MAX).unwrap();
    let next = encode(crc, checkpoint(5), &later, u32::MAX).unwrap();
    let mixed = vec![cut[0].clone(), cut[1].clone(), next[2].clone()];
    let (damage, load) = damaged(decode(&mixed, 0..mixed.len()).finish());
    assert_eq!(damage.first, UnitDamage::Content { unit: 2 });
    assert!(
        damage.failed.is_empty() && damage.unread.is_empty(),
        "every unit decoded"
    );
    let super::GuardedLoad::Cold {
        entries: evicted,
        refusal: super::LoadRefusal::StaleWrite,
    } = load
    else {
        panic!("an inconsistent slot of intact units loads cold: {load:?}");
    };
    assert!(
        evicted.iter().any(|entry| entry.key == later[41].key),
        "the entry the foreign unit starts is evicted"
    );
}

/// A data unit before the last that holds fewer rows than a unit holds is the unit's own inconsistency, which another
/// unit's damage cannot cause, so the slot loads cold even beside a damaged unit.
#[test]
fn a_short_unit_before_the_last_loads_cold_beside_a_damaged_unit() {
    let crc = Crc32c::detect();
    let full = encode(crc, checkpoint(5), &entries(60), u32::MAX).unwrap();
    let few = encode(crc, checkpoint(5), &entries(10), u32::MAX).unwrap();
    let aligned: Vec<CaptureEntry> = (0..100)
        .map(|at| entry(at + 200, 2, 64 * (at as u64 + 200)))
        .collect();
    let single = encode(crc, checkpoint(5), &aligned, u32::MAX).unwrap();
    let mut mixed = full.clone();
    mixed[1] = few[1].clone();
    mixed[2] = single[2].clone();
    let last = mixed.len() - 1;
    let mut decode = decode(&mixed, 0..last);
    decode.land(last, &[]);
    let (damage, load) = damaged(decode.finish());
    assert_eq!(damage.first, UnitDamage::Content { unit: 1 });
    assert_eq!(damage.unread, [last as u32]);
    assert!(
        matches!(
            load,
            super::GuardedLoad::Cold {
                refusal: super::LoadRefusal::StaleWrite,
                ..
            }
        ),
        "{load:?}"
    );
}

/// A slot of `S = slot_units(N_max)` units holds `N_max` rows and an entry takes one row per extent, so `N_max`
/// entries that include a multi-extent entry need more rows than the slot holds. The encode skips each entry whose
/// rows no longer fit and keeps every later entry that does.
#[test]
fn a_full_slot_skips_an_entry_whose_rows_do_not_fit_and_keeps_the_later_entries() {
    let crc = Crc32c::detect();
    let n_max = 2 * crate::failover::records::UNIT_ENTRIES;
    let slot_units = crate::failover::records::slot_units(n_max) as u32;
    let mut entries: Vec<CaptureEntry> = (0..n_max as usize)
        .map(|at| entry(at, 2, 64 * at as u64))
        .collect();
    let wide = n_max as usize - 2;
    entries[wide].extents = (0..3)
        .map(|extent| {
            ExtentLocator::new(64 * wide as u64 + 8 * extent, 1)
                .unwrap()
                .bits()
        })
        .collect();
    let units = encode(crc, checkpoint(5), &entries, slot_units)
        .expect("a checkpoint of N_max entries encodes into its slot");
    assert_eq!(units.len(), slot_units as usize);
    let mut kept = entries.clone();
    kept.remove(wide);
    assert_eq!(
        whole(decode(&units, 0..units.len()).finish()),
        super::GuardedLoad::Warm(kept),
        "every entry but the one whose rows pass the slot, in capture order"
    );
}

/// Known answers: unit `j` of capture `c` by session `s` of shard 7 carries key `"IMGCKCK1"` then the shard
/// big-endian, allocation `c << 32 | j`, session `s` and cache version `c`, and its payload holds the counts and rows
/// at the documented offsets.
#[test]
fn a_unit_carries_its_identity_and_layout_at_known_offsets() {
    use super::super::record::{RecordConfig, claim_header};
    let crc = Crc32c::detect();
    let mut entry = entry(3, 9, 64);
    entry.extents = vec![
        ExtentLocator::new(64, 1).unwrap().bits(),
        ExtentLocator::new(72, 1).unwrap().bits(),
    ];
    entry.deadline_ns = 0x1122_3344_5566_7788;
    entry.lifetime_ms = 0x99AA_BBCC;
    entry.tail = 0x0DEF;
    let units = encode(crc, checkpoint(5), std::slice::from_ref(&entry), 2).unwrap();
    let config = RecordConfig { chunk_len: 4096 }.validate().unwrap();
    let mut key = [0; 32];
    key[..12].copy_from_slice(b"IMGCKCK1\0\0\0\x07");
    for (at, unit) in units.iter().enumerate() {
        let claimed = claim_header(crc, &config, &unit[..]).unwrap();
        assert_eq!(claimed.identity.key, key);
        assert_eq!(claimed.identity.allocation, (5 << 32) | at as u64);
        assert_eq!(claimed.identity.session, (3 << 32) | 4);
        assert_eq!(claimed.identity.version, 5);
    }
    let header = claim_header(crc, &config, &units[0][..])
        .unwrap()
        .layout
        .header_bytes();
    let counts = &units[0][header..header + 20];
    assert_eq!(counts[..8], 2u64.to_le_bytes(), "row count");
    assert_eq!(counts[8..16], 1u64.to_le_bytes(), "entry count");
    assert_eq!(counts[16..20], 2u32.to_le_bytes(), "unit count");
    let payload = &units[1][header..];
    assert_eq!(
        payload[..8],
        [2, 0, 0, 0, 0, 0, 0, 0],
        "the unit's row count, then zeros"
    );
    for (index, row) in payload[8..8 + 2 * 96].chunks(96).enumerate() {
        assert_eq!(row[..32], entry.key);
        assert_eq!(row[32..40], entry.allocation.to_le_bytes());
        assert_eq!(row[40..48], entry.session.to_le_bytes());
        assert_eq!(row[48..56], entry.version.to_le_bytes());
        assert_eq!(
            row[56..64],
            [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
        assert_eq!(row[64..68], [0xCC, 0xBB, 0xAA, 0x99]);
        assert_eq!(row[68..70], [0xEF, 0x0D]);
        assert_eq!(row[70..72], (index as u16).to_le_bytes());
        assert_eq!(row[72..74], [2, 0]);
        assert_eq!(row[74..80], [0; 6]);
        assert_eq!(row[80..88], entry.extents[index].to_le_bytes());
        assert_eq!(row[88..96], [0; 8]);
    }
    let bare = encode(crc, checkpoint(5), std::slice::from_ref(&entry), 1).unwrap();
    assert_eq!(
        whole(decode(&bare, 0..bare.len()).finish()),
        super::GuardedLoad::Warm(Vec::new()),
        "a slot of unit 0 alone holds no row, so the entry is left out"
    );
    assert_eq!(
        encode(crc, checkpoint(5), std::slice::from_ref(&entry), 0),
        Err(EncodeRefusal::EmptySlot)
    );
}

/// The streamed decode of `entries` in order over `destinations` destinations and the batch guard's load of the same
/// entries.
fn both_over(
    entries: &[CaptureEntry],
    destinations: usize,
) -> (super::GuardedLoad, super::GuardedLoad) {
    both_under(entries, limits(), destinations)
}

fn both_under(
    entries: &[CaptureEntry],
    limits: super::LoadLimits,
    destinations: usize,
) -> (super::GuardedLoad, super::GuardedLoad) {
    let units = encode(Crc32c::detect(), checkpoint(5), entries, u32::MAX).unwrap();
    let mut fed = Fed::under(units.len(), limits, destinations);
    for (at, unit) in units.iter().enumerate() {
        fed.land(at, &unit[..]);
    }
    let budget = crate::storage::EngineBudget::unlimited();
    (
        whole(fed.finish()),
        canon(super::guarded_load(entries.to_vec(), limits, &budget)),
    )
}

fn both(entries: &[CaptureEntry]) -> (super::GuardedLoad, super::GuardedLoad) {
    both_over(entries, 4)
}

/// Data units that arrive last to first each wait as a decoded one-unit window until unit 0 stitches, and the verdict
/// then sorts the keys. For a full slot of single-extent entries the heap the decode requests at that peak stays
/// within the bytes [`SlotDecode::bytes`] charges for every unit held as a window over four destinations.
#[test]
fn a_full_slot_decoded_in_reverse_peaks_within_its_charged_bytes() {
    let rows = crate::failover::records::UNIT_ENTRIES as usize;
    for data_units in [1, 5] {
        let full: Vec<CaptureEntry> = (0..rows * data_units)
            .map(|at| entry(at, 2, 64 * at as u64))
            .collect();
        let units = encode(Crc32c::detect(), checkpoint(5), &full, u32::MAX).unwrap();
        assert_eq!(units.len(), data_units + 1, "every data unit is full");
        let held = (units.len(), UNIT_LEN);
        let charged = SlotDecode::bytes(units.len() as u32, &limits(), 4, held).unwrap();
        let live = crate::instrument::live_bytes();
        crate::instrument::reset_peak();
        let load = decode(&units, (0..units.len()).rev()).finish();
        let peak = crate::instrument::peak_bytes().wrapping_sub(live);
        assert_eq!(
            whole(load),
            super::GuardedLoad::Warm(full),
            "{data_units} data units: the verdict sorted the keys"
        );
        assert!(
            peak <= charged,
            "{data_units} data units: {peak} heap bytes at the peak beside {charged} charged"
        );
    }
}

/// A slot of unit 0 alone is charged its per-unit entries and the guards' bitmaps, so the charge includes the damage
/// list's entry: a unit 0 that fails its check or its read decodes within the bytes [`SlotDecode::bytes`] charges for
/// one window over four destinations.
#[test]
fn a_one_unit_slot_whose_unit_is_damaged_peaks_within_its_charged_bytes() {
    let units = encode(Crc32c::detect(), checkpoint(5), &[], u32::MAX).unwrap();
    assert_eq!(units.len(), 1);
    let mut torn = units.clone();
    torn[0][UNIT_LEN - 1] ^= 1;
    let charged = SlotDecode::bytes(1, &limits(), 4, (1, UNIT_LEN)).unwrap();
    for unread in [false, true] {
        let live = crate::instrument::live_bytes();
        crate::instrument::reset_peak();
        let slot = decode(&torn, 0..usize::from(!unread)).finish();
        let peak = crate::instrument::peak_bytes().wrapping_sub(live);
        let (damage, _) = damaged(slot);
        assert_eq!(
            (damage.failed.len(), damage.unread.len()),
            (usize::from(!unread), usize::from(unread)),
            "unread {unread}"
        );
        assert!(
            peak <= charged,
            "unread {unread}: {peak} heap bytes at the peak beside {charged} charged"
        );
    }
}

/// Regrouping a crc-valid unit whose first two rows each open an entry with room for every row that remains holds
/// both entries' extent lists while the second opens. Beside an unread unit 0 and its damage list, that regroup
/// peaks within the bytes [`SlotDecode::bytes`] charges for both units held as windows over four destinations.
#[test]
fn a_unit_opening_two_long_entries_beside_an_unread_unit_0_peaks_within_its_charged_bytes() {
    use super::super::record::{ExtentPosition, RecordConfig, claim_header, encode_header};
    let crc = Crc32c::detect();
    let rows = crate::failover::records::UNIT_ENTRIES as usize;
    let mut long = entry(0, 2, 0);
    long.extents = (0..rows as u64)
        .map(|at| ExtentLocator::new(8 * at, 1).unwrap().bits())
        .collect();
    let mut units = encode(crc, checkpoint(5), &[long], u32::MAX).unwrap();
    assert_eq!(units.len(), 2);
    let config = RecordConfig {
        chunk_len: UNIT_LEN as u32,
    }
    .validate()
    .unwrap();
    let claimed = claim_header(crc, &config, &units[1][..]).unwrap();
    let (layout, identity) = (claimed.layout, claimed.identity);
    // The second row's extent index, at byte 70 of its row.
    let index = layout.header_bytes() + 8 + ROW_LEN + 70;
    units[1][index..index + 2].fill(0);
    encode_header(
        crc,
        &layout,
        &identity,
        ExtentPosition::FIRST,
        &mut units[1][..],
    )
    .unwrap();
    let charged = SlotDecode::bytes(2, &limits(), 4, (2, UNIT_LEN)).unwrap();
    let live = crate::instrument::live_bytes();
    crate::instrument::reset_peak();
    let slot = decode(&units, 1..2).finish();
    let peak = crate::instrument::peak_bytes().wrapping_sub(live);
    let (damage, _) = damaged(slot);
    assert_eq!((damage.failed, damage.unread), (vec![], vec![0]));
    assert!(
        peak <= charged,
        "{peak} heap bytes at the peak beside {charged} charged"
    );
}

/// Distinct keys whose fingerprints all collide load warm because the guard compares the keys of every run of equal
/// fingerprints; the guard refuses a key two entries share, matching the batch guard.
#[test]
fn colliding_fingerprints_load_warm_and_a_shared_key_is_refused() {
    let entries = colliding(&entries(100));
    let mut shared = entries.clone();
    shared[70].key = shared[3].key;
    let (warm, _) = both(&entries);
    let (refused, batch) = both(&shared);
    assert_eq!(warm, super::GuardedLoad::Warm(entries.clone()));
    assert!(matches!(
        batch,
        super::GuardedLoad::Cold {
            refusal: super::LoadRefusal::Key,
            ..
        }
    ));
    assert_eq!(refused, batch);
}

/// A key shared by a whole entry and an entry a torn unit cut refuses nothing: the cut entry reaches no destination's
/// chunks, and each seal compares the keys of its whole entries only. The same two entries in an intact slot are
/// refused `Key`.
#[test]
fn a_key_shared_with_an_entry_a_torn_unit_cut_loads_warm() {
    // Entry 40 owns rows 40 and 41: the last row of unit 1 and the first row of unit 2.
    let mut entries: Vec<CaptureEntry> = (0..100).map(|at| entry(at, 2, 8 * at as u64)).collect();
    entries[40]
        .extents
        .push(ExtentLocator::new(8 * 40 + 1, 1).unwrap().bits());
    entries[40].key = entries[3].key;
    let units = encode(Crc32c::detect(), checkpoint(5), &entries, u32::MAX).unwrap();
    let (intact, batch) = both(&entries);
    assert!(matches!(
        batch,
        super::GuardedLoad::Cold {
            refusal: super::LoadRefusal::Key,
            ..
        }
    ));
    assert_eq!(intact, batch);
    let mut torn = units.clone();
    torn[2][UNIT_LEN - 1] ^= 1;
    let (damage, load) = damaged(decode(&torn, 0..torn.len()).finish());
    assert_eq!(damage.failed, [2]);
    let kept = outside(&entries, 2);
    assert!(!kept.contains(&entries[40]) && kept.contains(&entries[3]));
    assert_eq!(load, super::GuardedLoad::Warm(kept));
}

/// A slot decoded as one-unit windows over 64 destinations peaks within its estimate: each destination keeps one chunk
/// per window until its seal, and the estimate counts the chunk handles and drop masks per window and destination.
#[test]
fn a_decode_of_one_unit_windows_over_many_destinations_peaks_within_its_estimate() {
    let count = 41 * 1500;
    let entries: Vec<CaptureEntry> = (0..count).map(|at| entry(at, 2, 8 * at as u64)).collect();
    let limits = super::LoadLimits {
        payload_end: 8 * count as u64 + 8,
        slot_count: count + 1,
        n_max: count + 1,
        ..limits()
    };
    let units = encode(Crc32c::detect(), checkpoint(5), &entries, u32::MAX).unwrap();
    let estimate = SlotDecode::bytes(units.len() as u32, &limits, 64, (1, UNIT_LEN)).unwrap();
    let live = crate::instrument::live_bytes();
    crate::instrument::reset_peak();
    let mut fed = Fed::under(units.len(), limits, 64);
    for (at, unit) in units.iter().enumerate() {
        fed.land(at, &unit[..]);
    }
    let slot = fed.finish();
    let peak = crate::instrument::peak_bytes().wrapping_sub(live);
    let load = whole(slot);
    assert!(peak <= estimate, "peak {peak} within {estimate}");
    assert_eq!(load, super::GuardedLoad::Warm(entries));
}

/// A unit that passes its identity and crc checks but holds a malformed row after intact rows routes none of its
/// rows (CHECK-BEFORE-ROUTE): an intact row of it that names another entry's slot refuses nothing, and the load
/// keeps the other unit's entries warm.
#[test]
fn a_unit_with_a_malformed_row_routes_none_of_its_rows() {
    use super::super::record::{ExtentPosition, RecordIdentity, encode_header};
    let crc = Crc32c::detect();
    let mut entries: Vec<CaptureEntry> = (0..82).map(|at| entry(at, 2, 8 * at as u64)).collect();
    entries[50].allocation = entries[5].allocation;
    let mut units = encode(crc, checkpoint(5), &entries, u32::MAX).unwrap();
    let (_, layout) = layout();
    // A reserved byte of unit 2's last row, then the unit's header over the changed payload.
    units[2][layout.header_bytes() + 8 + 40 * ROW_LEN + 74] = 1;
    let identity = RecordIdentity {
        key: key(checkpoint(5).shard),
        allocation: 5 << 32 | 2,
        session: SESSION,
        version: 5,
    };
    encode_header(
        crc,
        &layout,
        &identity,
        ExtentPosition::FIRST,
        &mut units[2][..],
    )
    .unwrap();
    let (damage, load) = damaged(decode(&units, 0..units.len()).finish());
    assert_eq!(damage.first, UnitDamage::Content { unit: 2 });
    assert_eq!(damage.failed, [2]);
    assert_eq!(load, super::GuardedLoad::Warm(outside(&entries, 2)));
}

/// A slot in which every key belongs to two entries is refused `Key` and peaks within its estimate over one
/// destination: the seal holds every entry's fingerprint beside the sort's scratch.
#[test]
fn a_slot_of_paired_keys_is_refused_within_its_estimate() {
    let count = 41 * 2000;
    let mut entries: Vec<CaptureEntry> = (0..count).map(|at| entry(at, 2, 8 * at as u64)).collect();
    for pair in entries.as_chunks_mut::<2>().0 {
        pair[1].key = pair[0].key;
    }
    let limits = super::LoadLimits {
        payload_end: 8 * count as u64 + 8,
        slot_count: count + 1,
        n_max: count + 1,
        ..limits()
    };
    let units = encode(Crc32c::detect(), checkpoint(5), &entries, u32::MAX).unwrap();
    let estimate = SlotDecode::bytes(units.len() as u32, &limits, 1, (1, UNIT_LEN)).unwrap();
    let live = crate::instrument::live_bytes();
    crate::instrument::reset_peak();
    let mut fed = Fed::under(units.len(), limits, 1);
    for (at, unit) in units.iter().enumerate() {
        fed.land(at, &unit[..]);
    }
    let slot = fed.finish();
    let peak = crate::instrument::peak_bytes().wrapping_sub(live);
    let load = whole(slot);
    assert!(peak <= estimate, "peak {peak} within {estimate}");
    let refusal = super::LoadRefusal::Key;
    assert_eq!(load, super::GuardedLoad::Cold { entries, refusal });
}

/// Extents that cross a 64-unit word of the guard's bitmap overlap exactly when the batch guard finds them
/// overlapping: a shared unit in either word is refused, and extents that only touch load.
#[test]
fn extents_across_a_bitmap_word_overlap_as_the_batch_guard_decides() {
    for ((first, first_len), (second, second_len), overlaps) in [
        ((60, 10), (69, 2), true),
        ((60, 10), (70, 2), false),
        ((60, 10), (56, 5), true),
        ((64, 64), (127, 1), true),
        ((64, 64), (128, 64), false),
        ((1, 64), (64, 1), true),
    ] {
        let mut entries = entries(2);
        entries[0].extents = vec![ExtentLocator::new(first, first_len).unwrap().bits()];
        entries[1].extents = vec![ExtentLocator::new(second, second_len).unwrap().bits()];
        let (streamed, batch) = both(&entries);
        assert_eq!(
            streamed, batch,
            "{first}+{first_len} and {second}+{second_len}"
        );
        assert_eq!(
            batch != super::GuardedLoad::Warm(entries.clone()),
            overlaps,
            "{first}+{first_len} and {second}+{second_len}: {batch:?}"
        );
    }
}

#[test]
fn a_slot_two_windows_share_is_refused_as_the_batch_guard_decides() {
    let mut shared = entries(60);
    shared[59].allocation = 3;
    let units = encode(Crc32c::detect(), checkpoint(5), &shared, u32::MAX).unwrap();
    assert!(units.len() > 3, "the entries span several one-unit windows");
    for shards in [1, 4] {
        let (streamed, batch) = both_over(&shared, shards);
        assert_eq!(streamed, batch, "over {shards}");
        assert!(
            matches!(
                batch,
                super::GuardedLoad::Cold {
                    refusal: super::LoadRefusal::Slot,
                    ..
                }
            ),
            "{batch:?}"
        );
    }
}

#[test]
fn guard_bytes_is_the_allocation_of_a_destination_guard() {
    for (payload_end, slot_count) in [(63, 63), (64, 64), (65, 65), (1 << 20, 1 << 10)] {
        let limits = super::LoadLimits {
            payload_end,
            slot_count,
            ..limits()
        };
        for (units, shards) in [(1, 1), (2, 4), (65, 16), (1000, 4)] {
            let decode = SlotDecode::new(
                Crc32c::detect(),
                checkpoint(5),
                units,
                SESSION,
                limits,
                routing(shards),
                (no_suffix(), 0, &[]),
            )
            .unwrap();
            assert_eq!(
                decode.guard_capacity(),
                decode.guard_bytes(),
                "{payload_end} units, {slot_count} slots, {units} units over {shards}"
            );
        }
    }
}

/// The slot one below the slot count loads and the slot count itself is refused, as the batch guard decides.
#[test]
fn the_slot_below_the_slot_count_loads_and_the_count_itself_is_refused() {
    let count = limits().slot_count as u64;
    for (slot, refused) in [(count - 1, false), (count, true)] {
        let mut entries = entries(3);
        entries[2].allocation = slot << 32 | 2;
        let (streamed, batch) = both(&entries);
        assert_eq!(streamed, batch, "slot {slot}");
        assert_eq!(
            matches!(
                batch,
                super::GuardedLoad::Cold {
                    refusal: super::LoadRefusal::Slot,
                    ..
                }
            ),
            refused,
            "slot {slot}: {batch:?}"
        );
    }
}

/// A unit that arrives a second time decodes once, whether its first copy still waits for an earlier unit or already
/// stitched: the repeat is dropped and the slot loads every entry warm with no damage. The first landing decides, so
/// a torn copy landing before an intact one leaves the unit failed.
#[test]
fn a_unit_arriving_twice_decodes_once_before_and_after_it_stitches() {
    let units = encode(Crc32c::detect(), checkpoint(5), &entries(60), u32::MAX).unwrap();
    let mut torn = units[2].clone();
    torn[UNIT_LEN - 1] ^= 1;
    for (waiting, unit) in [(true, 2), (false, 1)] {
        let mut fed = Fed::new(units.len(), 4);
        let order: Vec<usize> = match waiting {
            true => [2, 2].into_iter().chain(0..units.len()).collect(),
            false => (0..units.len()).collect(),
        };
        for (at, &unit) in order.iter().enumerate() {
            let repeat = waiting && at > 0 && unit == 2;
            fed.land(unit, if repeat { &torn[..] } else { &units[unit][..] });
        }
        if !waiting {
            fed.land(unit, &torn[..]);
        }
        let slot = fed.finish();
        assert_eq!(slot.damage, None, "unit {unit}");
        assert_eq!(
            slot.load(),
            super::GuardedLoad::Warm(entries(60)),
            "unit {unit}"
        );
    }
    let mut fed = decode(&units, [0, 1].into_iter());
    fed.land(2, &torn[..]);
    fed.land(2, &units[2][..]);
    assert_eq!(
        damaged(fed.finish()).0.failed,
        [2],
        "the torn copy landed first"
    );
}

/// A unit whose read failed stays unread even when its bytes arrive later, so the load is not installable and a later
/// reader rereads the slot; bytes that land before a failed read of the same unit decode it.
#[test]
fn a_unit_arriving_after_its_failed_read_stays_unread() {
    let units = encode(Crc32c::detect(), checkpoint(5), &entries(60), u32::MAX).unwrap();
    let mut late = decode(&units, [0, 2, 3].into_iter());
    late.land(1, &[]);
    late.land(1, &units[1][..]);
    let slot = late.finish();
    assert!(!slot.installable());
    assert_eq!(slot.damage.unwrap().unread, [1]);
    let mut early = decode(&units, 0..units.len());
    early.land(1, &[]);
    let slot = early.finish();
    assert!(slot.installable());
    assert_eq!(slot.load(), super::GuardedLoad::Warm(entries(60)));
}

/// The decode publishes no load before every destination applied every stitched window, so a verdict never skips a
/// guard still out on a job or facts no guard applied yet: with every window landed and no destination job run, an
/// overlap the guards would refuse yields no load, and the same decode loads cold once its jobs ran.
#[test]
fn a_decode_publishes_no_load_before_every_destination_applied_its_windows() {
    let mut overlapping = entries(60);
    overlapping[1].extents = overlapping[0].extents.clone();
    let units = encode(Crc32c::detect(), checkpoint(5), &overlapping, u32::MAX).unwrap();
    let windows = |fed: &mut Fed| {
        for (at, unit) in units.iter().enumerate() {
            let job = fed.decode.window(at as u32, 1, unit.to_vec());
            fed.decode.landed(run(job));
        }
    };
    let mut early = Fed::new(units.len(), 4);
    windows(&mut early);
    assert!(!early.decode.done());
    assert!(early.decode.finish().is_none(), "no load before the join");
    let mut joined = Fed::new(units.len(), 4);
    windows(&mut joined);
    settle(&mut joined.decode, None);
    assert!(matches!(
        joined.finish().load(),
        super::GuardedLoad::Cold {
            refusal: super::LoadRefusal::Overlap,
            ..
        }
    ));
}

/// A sealed destination job run again keeps its seal: its key refusal and its applied windows survive the rerun, so a
/// shared key still refuses the load and every window counts as released.
#[test]
fn a_finished_destination_job_run_again_applies_no_window_twice() {
    let mut shared = entries(60);
    shared[40].key = shared[3].key;
    for (checkpoint_entries, expected) in [
        (entries(60), super::GuardedLoad::Warm(entries(60))),
        (shared.clone(), {
            let budget = crate::storage::EngineBudget::unlimited();
            super::guarded_load(shared, limits(), &budget)
        }),
    ] {
        let units = encode(
            Crc32c::detect(),
            checkpoint(5),
            &checkpoint_entries,
            u32::MAX,
        )
        .unwrap();
        let mut fed = Fed::new(units.len(), 4);
        for (at, unit) in units.iter().enumerate() {
            let job = fed.decode.window(at as u32, 1, unit.to_vec());
            fed.decode.landed(run(job));
        }
        let replay = fed.decode.work().expect("the replay of an empty ancestry");
        fed.decode.landed(run(replay));
        let taken: Vec<Work> = std::iter::from_fn(|| fed.decode.work()).collect();
        for job in taken {
            let Done::Dest(job) = run(job) else {
                panic!("a destination terminal");
            };
            fed.decode.landed(run(Work::Dest(job)));
        }
        assert!(fed.decode.done());
        assert_eq!(
            fed.decode.released(),
            units.len(),
            "every window counts as applied"
        );
        assert_eq!(fed.finish().load(), expected);
    }
}

#[test]
fn an_empty_slot_decode_holds_within_the_charge_of_no_window() {
    let units = encode(Crc32c::detect(), checkpoint(5), &[], u32::MAX).unwrap();
    assert_eq!(units.len(), 1);
    for shards in [1, 4, 16] {
        let routing = routing(shards);
        let charge = SlotDecode::bytes(1, &limits(), shards, (0, 0)).unwrap();
        let live = crate::instrument::live_bytes();
        let mut decode = SlotDecode::new(
            Crc32c::detect(),
            checkpoint(5),
            1,
            SESSION,
            limits(),
            routing,
            (no_suffix(), 0, &[]),
        )
        .unwrap();
        let built = crate::instrument::live_bytes().wrapping_sub(live);
        assert!(built <= charge, "{shards}: built {built} within {charge}");
        let job = decode.window(0, 1, units[0].to_vec());
        settle(&mut decode, Some(job));
        crate::instrument::reset_peak();
        let slot = decode.finish().expect("no helper failed");
        let peak = crate::instrument::peak_bytes().wrapping_sub(live);
        assert_eq!(whole(slot), super::GuardedLoad::Warm(Vec::new()));
        assert!(peak <= charge, "{shards}: verdict {peak} within {charge}");
    }
}

#[test]
fn a_destination_job_landed_unrun_applies_no_window() {
    let mut overlapping = entries(60);
    overlapping[1].extents = overlapping[0].extents.clone();
    let units = encode(Crc32c::detect(), checkpoint(5), &overlapping, u32::MAX).unwrap();
    let mut fed = Fed::new(units.len(), 4);
    for (at, unit) in units.iter().enumerate() {
        let job = fed.decode.window(at as u32, 1, unit.to_vec());
        fed.decode.landed(run(job));
    }
    let replay = fed.decode.work().expect("the replay of an empty ancestry");
    assert!(matches!(replay, Work::Replay(_)));
    fed.decode.landed(run(replay));
    let taken: Vec<Work> = std::iter::from_fn(|| fed.decode.work()).collect();
    assert_eq!(taken.len(), 4, "one job per destination");
    for job in taken {
        let Work::Dest(job) = job else {
            panic!("a destination job");
        };
        fed.decode.landed(Done::Dest(job));
    }
    assert_eq!(fed.decode.released(), 0, "no window counts as applied");
    assert!(!fed.decode.done());
    settle(&mut fed.decode, None);
    assert!(matches!(
        fed.finish().load(),
        super::GuardedLoad::Cold {
            refusal: super::LoadRefusal::Overlap,
            ..
        }
    ));
}

/// A decode adopts only its own terminals: a window or destination terminal of another decode of a different slot
/// changes nothing, so neither another slot's entries nor its guards reach this decode's verdict.
#[test]
fn a_decode_refuses_the_terminals_of_another_decode() {
    let mut overlapping = entries(60);
    overlapping[1].extents = overlapping[0].extents.clone();
    let ours = encode(Crc32c::detect(), checkpoint(5), &overlapping, u32::MAX).unwrap();
    let theirs = encode(Crc32c::detect(), checkpoint(5), &entries(60), u32::MAX).unwrap();
    let other = Fed::new(theirs.len(), 4);
    let mut stray = Vec::new();
    for (at, unit) in theirs.iter().enumerate() {
        stray.push(run(other.decode.window(at as u32, 1, unit.to_vec())));
    }
    let mut fed = Fed::new(ours.len(), 4);
    for done in stray {
        fed.decode.landed(done);
    }
    assert!(
        !fed.decode.done(),
        "another decode's windows stitch nothing here"
    );
    for (at, unit) in ours.iter().enumerate() {
        let job = fed.decode.window(at as u32, 1, unit.to_vec());
        fed.decode.landed(run(job));
    }
    let mut late = Fed::new(theirs.len(), 4);
    for (at, unit) in theirs.iter().enumerate() {
        let job = late.decode.window(at as u32, 1, unit.to_vec());
        late.decode.landed(run(job));
    }
    while let Some(job) = late.decode.work() {
        fed.decode.landed(run(job));
    }
    assert!(
        !fed.decode.done(),
        "another decode's guards return to no home here"
    );
    assert!(matches!(
        fed.finish().load(),
        super::GuardedLoad::Cold {
            refusal: super::LoadRefusal::Overlap,
            ..
        }
    ));
}

/// Intact units of one identity that hold more rows than intact unit 0 counts come from two encodings. A lost unit
/// explains only a deficit, so the slot loads cold with the stale-write refusal beside an unread unit.
#[test]
fn intact_units_beyond_unit_0s_counts_load_cold_beside_an_unread_unit() {
    let crc = Crc32c::detect();
    let ours = encode(crc, checkpoint(5), &entries(60), u32::MAX).unwrap();
    let fewer = encode(crc, checkpoint(5), &entries(55), u32::MAX).unwrap();
    assert_eq!(ours.len(), fewer.len());
    let mut mixed = ours.clone();
    mixed[0] = fewer[0].clone();
    let (never, _) = damaged(decode(&mixed, [0, 2, 3].into_iter()).finish());
    assert_eq!(
        (never.alarm(), never.unread),
        (super::LoadRefusal::StaleWrite, vec![1]),
        "a unit that never arrived ranks below the inconsistency"
    );
    let mut decode = decode(&mixed, [0, 2, 3].into_iter());
    decode.land(1, &[]);
    let (damage, load) = damaged(decode.finish());
    assert_eq!(damage.unread, [1]);
    assert_eq!(damage.alarm(), super::LoadRefusal::StaleWrite);
    assert!(
        matches!(
            load,
            super::GuardedLoad::Cold {
                refusal: super::LoadRefusal::StaleWrite,
                ..
            }
        ),
        "{load:?}"
    );
}

/// Intact units that all decode but whose rows miss unit 0's counts hold another encoding: with no failed or unread
/// unit, the counts alone load the slot cold.
#[test]
fn intact_units_that_miss_unit_0s_counts_load_cold() {
    let crc = Crc32c::detect();
    let ours = encode(crc, checkpoint(5), &entries(60), u32::MAX).unwrap();
    let mut mixed = encode(crc, checkpoint(5), &entries(61), u32::MAX).unwrap();
    assert_eq!(ours.len(), mixed.len());
    mixed[0] = ours[0].clone();
    let (damage, load) = damaged(decode(&mixed, 0..mixed.len()).finish());
    assert!(damage.failed.is_empty() && damage.unread.is_empty());
    assert!(
        matches!(
            load,
            super::GuardedLoad::Cold {
                refusal: super::LoadRefusal::StaleWrite,
                ..
            }
        ),
        "{load:?}"
    );
}

/// An intact unit 0 that records another unit count than the store names comes from another encoding, so the slot
/// loads cold even though every data unit decodes.
#[test]
fn an_intact_unit_0_naming_another_unit_count_loads_the_slot_cold() {
    let crc = Crc32c::detect();
    let ours = encode(crc, checkpoint(5), &entries(60), u32::MAX).unwrap();
    let longer = encode(crc, checkpoint(5), &entries(100), u32::MAX).unwrap();
    assert_ne!(ours.len(), longer.len());
    let mut mixed = ours.clone();
    mixed[0] = longer[0].clone();
    let (damage, load) = damaged(decode(&mixed, 0..mixed.len()).finish());
    assert!(
        matches!(damage.first, UnitDamage::Units { .. }),
        "{damage:?}"
    );
    assert_eq!(damage.failed, [0]);
    assert!(
        matches!(
            load,
            super::GuardedLoad::Cold {
                refusal: super::LoadRefusal::StaleWrite,
                ..
            }
        ),
        "{load:?}"
    );
}

/// Unit 0 counts more entries than the intact units' rows lack: a lost unit drops at most one entry per row it held,
/// so an entry shortfall beyond the rows of the undecoded units loads the slot cold beside a torn or an unread unit.
#[test]
fn an_entry_shortfall_beyond_the_lost_rows_loads_cold() {
    let crc = Crc32c::detect();
    let ours = encode(crc, checkpoint(5), &entries(60), u32::MAX).unwrap();
    let single: Vec<CaptureEntry> = (0..120).map(|at| entry(at, 2, 64 * at as u64)).collect();
    let more = encode(crc, checkpoint(5), &single, u32::MAX).unwrap();
    assert_eq!(ours.len(), more.len());
    for case in ["torn", "unread", "whole"] {
        let mut mixed = ours.clone();
        mixed[0] = more[0].clone();
        let mut slot = match case {
            "torn" => {
                mixed[1][UNIT_LEN - 1] ^= 1;
                decode(&mixed, 0..mixed.len())
            }
            "unread" => decode(&mixed, [0, 2, 3].into_iter()),
            _ => decode(&mixed, 0..mixed.len()),
        };
        if case == "unread" {
            slot.land(1, &[]);
        }
        let (damage, load) = damaged(slot.finish());
        let lost: (Vec<u32>, Vec<u32>) = match case {
            "torn" => (vec![1], vec![]),
            "unread" => (vec![], vec![1]),
            _ => (vec![], vec![]),
        };
        assert_eq!((damage.failed, damage.unread), lost, "{case}");
        assert!(
            matches!(
                load,
                super::GuardedLoad::Cold {
                    refusal: super::LoadRefusal::StaleWrite,
                    ..
                }
            ),
            "{case}: {load:?}"
        );
    }
}

/// Unit 0 counts fewer entries than the intact units regroup into, with the same rows and last-unit fill, so only
/// the entry surplus shows the second encoding and the slot loads cold.
#[test]
fn an_entry_surplus_over_unit_0s_count_loads_cold() {
    let crc = Crc32c::detect();
    let ours = encode(crc, checkpoint(5), &entries(60), u32::MAX).unwrap();
    let wide: Vec<CaptureEntry> = (0..40)
        .map(|at| {
            let mut entry = entry(at, 2, 0);
            entry.extents = (0..3)
                .map(|extent| {
                    ExtentLocator::new(64 * at as u64 + 8 * extent, 1)
                        .unwrap()
                        .bits()
                })
                .collect();
            entry
        })
        .collect();
    let fewer = encode(crc, checkpoint(5), &wide, u32::MAX).unwrap();
    assert_eq!(rows(&wide), rows(&entries(60)));
    let mut mixed = ours.clone();
    mixed[0] = fewer[0].clone();
    let (damage, load) = damaged(decode(&mixed, 0..mixed.len()).finish());
    assert!(damage.failed.is_empty() && damage.unread.is_empty());
    assert!(
        matches!(
            load,
            super::GuardedLoad::Cold {
                refusal: super::LoadRefusal::StaleWrite,
                ..
            }
        ),
        "{load:?}"
    );
}

/// After a torn unit, the continuation rows of the next unit open an orphan entry the later rows must continue: a
/// unit of another encoding whose rows continue a different entry breaks it, so the slot loads cold.
#[test]
fn continuation_rows_after_a_torn_unit_that_disagree_load_cold() {
    let crc = Crc32c::detect();
    let long = |key: usize, base: u64| {
        let mut entry = entry(key, 2, 0);
        entry.extents = (0..100)
            .map(|at| ExtentLocator::new(base + 8 * at, 1).unwrap().bits())
            .collect();
        entry
    };
    let ours = encode(crc, checkpoint(5), &[long(0, 0)], u32::MAX).unwrap();
    let theirs = encode(crc, checkpoint(5), &[long(1, 4000)], u32::MAX).unwrap();
    assert_eq!(ours.len(), 4);
    let mut torn = ours.clone();
    torn[1][UNIT_LEN - 1] ^= 1;
    let (damage, load) = damaged(decode(&torn, 0..torn.len()).finish());
    assert_eq!(damage.failed, [1]);
    assert_eq!(
        load,
        super::GuardedLoad::Warm(Vec::new()),
        "control: one cut entry"
    );
    torn[3] = theirs[3].clone();
    let (damage, load) = damaged(decode(&torn, 0..torn.len()).finish());
    assert_eq!(damage.failed, [1]);
    assert!(
        matches!(
            load,
            super::GuardedLoad::Cold {
                refusal: super::LoadRefusal::StaleWrite,
                ..
            }
        ),
        "{load:?}"
    );
}

/// Intact units that start more entries than unit 0 counts hold another encoding, even when a damaged later unit
/// cuts the last of them off so the whole entries stay within the count.
#[test]
fn intact_entry_starts_beyond_unit_0s_count_load_cold_beside_an_unread_unit() {
    let crc = Crc32c::detect();
    let ours = encode(crc, checkpoint(5), &entries(60), u32::MAX).unwrap();
    let wider: Vec<CaptureEntry> = (0..41)
        .map(|at| {
            let mut entry = entry(at, 2, 0);
            entry.extents = (0..if at < 38 { 3 } else { 2 })
                .map(|extent| {
                    ExtentLocator::new(64 * at as u64 + 8 * extent, 1)
                        .unwrap()
                        .bits()
                })
                .collect();
            entry
        })
        .collect();
    assert_eq!(rows(&wider), rows(&entries(60)));
    let fewer = encode(crc, checkpoint(5), &wider, u32::MAX).unwrap();
    let mut mixed = ours.clone();
    mixed[0] = fewer[0].clone();
    let mut decode = decode(&mixed, 0..3);
    decode.land(3, &[]);
    let (damage, load) = damaged(decode.finish());
    assert_eq!(damage.unread, [3]);
    assert!(
        matches!(
            load,
            super::GuardedLoad::Cold {
                refusal: super::LoadRefusal::StaleWrite,
                ..
            }
        ),
        "{load:?}"
    );
}

/// An entry an undecoded unit cut needs more rows than that unit can hold, so the entry that opens right after the
/// gap comes from another encoding, and the slot loads cold although every count still fits, whether the gap and the
/// opening row share a window or not.
#[test]
fn an_entry_opening_before_the_cut_entry_could_end_loads_cold() {
    let crc = Crc32c::detect();
    let spread = |key: usize, from: u64, count: u64| {
        let mut entry = entry(key, 2, 0);
        entry.extents = (from..from + count)
            .map(|at| ExtentLocator::new(1000 + 8 * at, 1).unwrap().bits())
            .collect();
        entry
    };
    let (first, last) = (entry(0, 2, 0), entry(2, 2, 4000));
    let ours = [first.clone(), spread(1, 0, 100), last.clone()];
    let split = [first, spread(1, 0, 81), spread(3, 81, 19), last];
    assert_eq!(rows(&ours), rows(&split));
    let ours = encode(crc, checkpoint(5), &ours, u32::MAX).unwrap();
    let split = encode(crc, checkpoint(5), &split, u32::MAX).unwrap();
    assert_eq!(ours.len(), split.len());
    let mut mixed = [
        split[0].clone(),
        ours[1].clone(),
        ours[2].clone(),
        split[3].clone(),
    ];
    mixed[2][UNIT_LEN - 1] ^= 1;
    for sizes in [&[1, 1, 1, 1][..], &[3, 1], &[4]] {
        let mut fed = Fed::new(mixed.len(), 4);
        let mut first = 0;
        for &size in sizes {
            fed.land_window(first, &mixed[first..first + size]);
            first += size;
        }
        let (damage, load) = damaged(fed.finish());
        assert_eq!(damage.failed, [2], "{sizes:?}");
        assert!(
            matches!(
                load,
                super::GuardedLoad::Cold {
                    refusal: super::LoadRefusal::StaleWrite,
                    ..
                }
            ),
            "{sizes:?}: {load:?}"
        );
    }
}

#[test]
fn a_cut_entry_resumes_exactly_one_unit_of_rows_after_the_gap() {
    let crc = Crc32c::detect();
    let spread = |key: usize| {
        let mut entry = entry(key, 2, 0);
        entry.extents = (0..100)
            .map(|at| ExtentLocator::new(1000 + 8 * at, 1).unwrap().bits())
            .collect();
        entry
    };
    let (first, last) = (entry(0, 2, 0), entry(2, 2, 4000));
    let ours = [first.clone(), spread(1), last.clone()];
    let shifted = [first.clone(), entry(9, 2, 9000), spread(1)];
    let pair = |key: usize| {
        let mut entry = entry(key, 2, 9000);
        entry.extents = (0..2)
            .map(|at| ExtentLocator::new(9000 + 8 * at, 1).unwrap().bits())
            .collect();
        entry
    };
    let later = [spread(1), pair(9)];
    let ours = encode(crc, checkpoint(5), &ours, u32::MAX).unwrap();
    let shifted = encode(crc, checkpoint(5), &shifted, u32::MAX).unwrap();
    let later = encode(crc, checkpoint(5), &later, u32::MAX).unwrap();
    assert_eq!((ours.len(), shifted.len(), later.len()), (4, 4, 4));
    let mut torn = ours.clone();
    torn[2][UNIT_LEN - 1] ^= 1;
    let mut early = torn.clone();
    early[3] = shifted[3].clone();
    let mut late = torn.clone();
    late[3] = later[3].clone();
    for sizes in [&[1, 1, 1, 1][..], &[1, 3], &[3, 1], &[2, 2], &[4]] {
        let land = |units: &[Box<[u8; UNIT_LEN]>]| {
            let mut fed = Fed::new(units.len(), 4);
            let mut at = 0;
            for &size in sizes {
                fed.land_window(at, &units[at..at + size]);
                at += size;
            }
            damaged(fed.finish())
        };
        let (damage, load) = land(&torn);
        assert_eq!(damage.failed, [2], "{sizes:?}");
        assert_eq!(
            load,
            super::GuardedLoad::Warm(vec![first.clone(), last.clone()]),
            "{sizes:?}: the cut entry resumes 41 rows later"
        );
        let (damage, load) = land(&early);
        assert_eq!(damage.failed, [2], "{sizes:?}");
        assert!(
            matches!(
                load,
                super::GuardedLoad::Cold {
                    refusal: super::LoadRefusal::StaleWrite,
                    ..
                }
            ),
            "{sizes:?}: a resume one row early: {load:?}"
        );
        let (damage, load) = land(&late);
        assert_eq!(damage.failed, [2], "{sizes:?}");
        assert!(
            matches!(
                load,
                super::GuardedLoad::Cold {
                    refusal: super::LoadRefusal::StaleWrite,
                    ..
                }
            ),
            "{sizes:?}: a resume one row late: {load:?}"
        );
    }
}

#[test]
fn a_short_cut_entry_resuming_at_another_index_loads_cold() {
    let crc = Crc32c::detect();
    let single = |at: usize| entry(100 + at, 2, 8000 + 8 * at as u64);
    let mut cut = entry(1, 2, 0);
    cut.extents = (0..10)
        .map(|at| ExtentLocator::new(1000 + 8 * at, 1).unwrap().bits())
        .collect();
    let ours: Vec<CaptureEntry> = (0..40)
        .map(single)
        .chain([cut.clone()])
        .chain((40..90).map(single))
        .collect();
    let theirs: Vec<CaptureEntry> = (0..80)
        .map(single)
        .chain([cut])
        .chain((80..90).map(single))
        .collect();
    let ours_units = encode(crc, checkpoint(5), &ours, u32::MAX).unwrap();
    let theirs_units = encode(crc, checkpoint(5), &theirs, u32::MAX).unwrap();
    assert_eq!((ours_units.len(), theirs_units.len()), (4, 4));
    let mut torn = ours_units.clone();
    torn[2][UNIT_LEN - 1] ^= 1;
    let mut mixed = torn.clone();
    mixed[3] = theirs_units[3].clone();
    for sizes in [&[1, 1, 1, 1][..], &[1, 3], &[3, 1], &[4]] {
        let land = |units: &[Box<[u8; UNIT_LEN]>]| {
            let mut fed = Fed::new(units.len(), 4);
            let mut at = 0;
            for &size in sizes {
                fed.land_window(at, &units[at..at + size]);
                at += size;
            }
            damaged(fed.finish())
        };
        let (damage, load) = land(&torn);
        assert_eq!(damage.failed, [2], "{sizes:?}");
        assert_eq!(
            load,
            super::GuardedLoad::Warm(outside(&ours, 2)),
            "{sizes:?}"
        );
        let (damage, load) = land(&mixed);
        assert_eq!(damage.failed, [2], "{sizes:?}");
        assert!(
            matches!(
                load,
                super::GuardedLoad::Cold {
                    refusal: super::LoadRefusal::StaleWrite,
                    ..
                }
            ),
            "{sizes:?}: the cut entry's row at another index: {load:?}"
        );
    }
}

#[test]
fn an_entry_past_the_extent_limit_gets_the_batch_verdict() {
    let mut long = entry(0, 2, 0);
    long.extents = (0..crate::storage::geometry::EXTENT_LIMIT + 1)
        .map(|at| ExtentLocator::new(8 * at, 1).unwrap().bits())
        .collect();
    let entries = [entry(1, 2, 1 << 19), long, entry(2, 2, (1 << 19) + 8)];
    let (streamed, batch) = both(&entries);
    assert_eq!(streamed, batch);
    assert!(
        matches!(
            batch,
            super::GuardedLoad::Cold {
                refusal: super::LoadRefusal::Bounds,
                ..
            }
        ),
        "{batch:?}"
    );
}

#[test]
fn a_cut_entry_reopening_after_the_gap_loads_cold() {
    let crc = Crc32c::detect();
    let single = |at: usize| entry(100 + at, 2, 8000 + 8 * at as u64);
    let long = |count: u64, base: u64| {
        let mut entry = entry(1, 2, 0);
        entry.extents = (0..count)
            .map(|at| ExtentLocator::new(base + 8 * at, 1).unwrap().bits())
            .collect();
        entry
    };
    let ours: Vec<CaptureEntry> = [single(0), long(100, 1000)]
        .into_iter()
        .chain((1..65).map(single))
        .collect();
    let theirs: Vec<CaptureEntry> = (200..323).map(single).chain([long(41, 20000)]).collect();
    let ours_units = encode(crc, checkpoint(5), &ours, u32::MAX).unwrap();
    let theirs_units = encode(crc, checkpoint(5), &theirs, u32::MAX).unwrap();
    assert_eq!((ours_units.len(), theirs_units.len()), (6, 5));
    let mut torn = ours_units.clone();
    torn[1][UNIT_LEN - 1] ^= 1;
    torn[3][UNIT_LEN - 1] ^= 1;
    let mut mixed = torn.clone();
    mixed[4] = theirs_units[4].clone();
    for sizes in [&[1, 1, 1, 1, 1, 1][..], &[3, 3], &[4, 2], &[2, 2, 2], &[6]] {
        let land = |units: &[Box<[u8; UNIT_LEN]>]| {
            let mut fed = Fed::new(units.len(), 4);
            let mut at = 0;
            for &size in sizes {
                fed.land_window(at, &units[at..at + size]);
                at += size;
            }
            damaged(fed.finish())
        };
        let (damage, load) = land(&torn);
        assert_eq!(damage.failed, [1, 3], "{sizes:?}");
        let kept = (23..65).map(single).collect();
        assert_eq!(load, super::GuardedLoad::Warm(kept), "{sizes:?}");
        let (damage, load) = land(&mixed);
        assert_eq!(damage.failed, [1, 3], "{sizes:?}");
        assert!(
            matches!(
                load,
                super::GuardedLoad::Cold {
                    refusal: super::LoadRefusal::StaleWrite,
                    ..
                }
            ),
            "{sizes:?}: the cut entry reopens after the gap: {load:?}"
        );
    }
}

#[test]
fn a_window_opening_an_oversized_entry_reserves_at_most_the_extent_limit() {
    let mut long = entry(0, 2, 0);
    long.extents = (0..u64::from(u16::MAX))
        .map(|at| ExtentLocator::new(8 * at, 1).unwrap().bits())
        .collect();
    let units = encode(Crc32c::detect(), checkpoint(5), &[long], u32::MAX).unwrap();
    let fed = Fed::new(units.len(), 1);
    let live = crate::instrument::live_bytes();
    let done = run(fed.decode.window(1, 1, units[1].to_vec()));
    let held = crate::instrument::live_bytes().wrapping_sub(live);
    assert!(held < 128 * 1024, "the window holds {held} bytes");
    drop(done);
}

#[test]
fn the_destination_furthest_behind_runs_first() {
    let units = encode(Crc32c::detect(), checkpoint(5), &entries(60), u32::MAX).unwrap();
    let mut fed = Fed::new(units.len(), 2);
    let replay = fed.decode.work().expect("the replay of an empty ancestry");
    fed.decode.landed(run(replay));
    let job = fed.decode.window(0, 1, units[0].to_vec());
    fed.decode.landed(run(job));
    let ahead = fed.decode.work().expect("a destination job");
    fed.decode.landed(run(ahead));
    let job = fed.decode.window(1, 1, units[1].to_vec());
    fed.decode.landed(run(job));
    let next = fed.decode.work().expect("a destination job");
    fed.decode.landed(run(next));
    assert_eq!(
        fed.decode.released(),
        1,
        "the job applied the laggard's windows"
    );
}

#[test]
fn a_window_job_keeps_no_spare_capacity_of_its_buffer() {
    let units = encode(Crc32c::detect(), checkpoint(5), &entries(60), u32::MAX).unwrap();
    let fed = Fed::new(units.len(), 4);
    let live = crate::instrument::live_bytes();
    let mut bytes = Vec::with_capacity(1 << 20);
    bytes.extend_from_slice(&units[1][..]);
    let job = fed.decode.window(1, 1, bytes);
    let held = crate::instrument::live_bytes().wrapping_sub(live);
    assert!(held < 2 * UNIT_LEN, "the job holds {held} bytes");
    drop(job);
}

/// A suffix read's buffer keeps none of its spare capacity once the decode takes it.
#[test]
fn a_suffix_read_keeps_no_spare_capacity_of_its_buffer() {
    let records = [super::delta::Record::Insert(entry(500, 4, 64 * 500))];
    let block = super::delta_tests::packed(0, &records).remove(0);
    let prefix = crate::failover::records::Layout {
        units: 2,
        ..no_suffix()
    };
    let ancestry = [crate::failover::records::Suffix {
        session: SESSION,
        start: 0,
        certified: 1,
        end: 1,
    }];
    let mut decode = SlotDecode::new(
        Crc32c::detect(),
        checkpoint(5),
        2,
        SESSION,
        limits(),
        routing(4),
        (prefix, 0, &ancestry),
    )
    .unwrap();
    let live = crate::instrument::live_bytes();
    let mut bytes = Vec::with_capacity(1 << 20);
    bytes.extend_from_slice(&block[..]);
    decode.blocks(0, 1, bytes);
    let held = crate::instrument::live_bytes().wrapping_sub(live);
    assert!(held < 2 * UNIT_LEN, "the decode holds {held} bytes");
}

#[test]
fn an_entry_of_three_hundred_extents_round_trips() {
    let mut long = entry(0, 2, 0);
    long.extents = (0..300)
        .map(|at| ExtentLocator::new(8 * at, 1).unwrap().bits())
        .collect();
    let units = encode(Crc32c::detect(), checkpoint(5), &[long.clone()], u32::MAX).unwrap();
    assert_eq!(
        whole(decode(&units, 0..units.len()).finish()),
        super::GuardedLoad::Warm(vec![long])
    );
}

/// A torn unit explains only the continuation rows right after it. A foreign unit at a distant index whose first row
/// cuts the entry the unit before it left open is a second encoding under the named identity, so the slot loads cold
/// beside the torn unit; without the foreign unit the same torn slot keeps its intact entries.
#[test]
fn a_foreign_unit_far_from_a_torn_unit_loads_cold() {
    let crc = Crc32c::detect();
    let named = entries(100);
    let single: Vec<CaptureEntry> = (0..200)
        .map(|at| entry(at + 500, 2, 64 * at as u64))
        .collect();
    let ours = encode(crc, checkpoint(5), &named, u32::MAX).unwrap();
    let theirs = encode(crc, checkpoint(5), &single, u32::MAX).unwrap();
    assert_eq!(ours.len(), 6);
    let mut torn = ours.clone();
    torn[1][UNIT_LEN - 1] ^= 1;
    let (damage, load) = damaged(decode(&torn, 0..torn.len()).finish());
    assert_eq!(damage.failed, [1]);
    assert_eq!(load, super::GuardedLoad::Warm(outside(&named, 1)));
    let mut mixed = torn;
    mixed[5] = theirs[5].clone();
    let (damage, load) = damaged(decode(&mixed, 0..mixed.len()).finish());
    assert_eq!(damage.failed, [1], "the foreign unit passes its own checks");
    assert!(
        matches!(
            load,
            super::GuardedLoad::Cold {
                refusal: super::LoadRefusal::StaleWrite,
                ..
            }
        ),
        "{load:?}"
    );
}

/// Extents and slots on either side of a destination's range edge overlap and repeat exactly when the batch guard
/// finds them so, over one, four and sixteen destinations: an extent that crosses an edge is split there and each part
/// checked by its own destination.
#[test]
fn extents_and_slots_across_a_destination_edge_get_the_batch_verdict() {
    // Four destinations split the `1 << 20` payload units at multiples of `1 << 18` and the `1 << 10` slots at
    // multiples of 256.
    let edge = 1 << 18;
    for (first, second, slots) in [
        ((edge - 2, 4), (edge + 1, 1), (3, 4)),
        ((edge - 2, 4), (edge + 2, 1), (3, 4)),
        ((edge - 1, 1), (edge, 1), (3, 4)),
        ((edge - 4, 2), (edge - 3, 8), (3, 4)),
        ((8, 1), (16, 1), (255, 256)),
        ((8, 1), (16, 1), (256, 256)),
    ] {
        let mut entries = entries(2);
        for (entry, ((start, len), slot)) in entries
            .iter_mut()
            .zip([(first, slots.0), (second, slots.1)])
        {
            entry.extents = vec![ExtentLocator::new(start, len).unwrap().bits()];
            entry.allocation = slot << 32 | 2;
        }
        for shards in [1, 4, 16] {
            let (streamed, batch) = both_over(&entries, shards);
            assert_eq!(
                streamed, batch,
                "{first:?} {second:?} {slots:?} over {shards}"
            );
        }
    }
    // A payload area from unit 1001 to `(1 << 20) + 1001`: four destinations split it at 1001 plus multiples of
    // `1 << 18`, so extents meet, overlap and end at shifted edges and at the area's end.
    let shifted = super::LoadLimits {
        payload_start: 1001,
        payload_end: (1 << 20) + 1001,
        ..limits()
    };
    let (low, top) = (1001 + edge, (1 << 20) + 1001);
    for (first, second, warm) in [
        ((low - 2, 4), (low + 1, 1), false),
        ((low - 2, 2), (low, 2), true),
        ((low - 1, 1), (low - 1, 1), false),
        ((top - 4, 4), (top - 8, 4), true),
        ((top - 4, 4), (top - 5, 2), false),
        ((1001, 1), (1000, 1), false),
    ] {
        let mut entries = entries(2);
        entries[0].extents = vec![ExtentLocator::new(first.0, first.1).unwrap().bits()];
        entries[1].extents = vec![ExtentLocator::new(second.0, second.1).unwrap().bits()];
        for shards in [1, 4, 16] {
            let (streamed, batch) = both_under(&entries, shifted, shards);
            assert_eq!(streamed, batch, "{first:?} {second:?} over {shards}");
            let loads = matches!(batch, super::GuardedLoad::Warm(_));
            assert_eq!(loads, warm, "{first:?} {second:?}: {batch:?}");
        }
    }
}

/// An extent outside the payload area outranks a total past the capacity wherever the two rows lie, in the batch
/// guard and in the stream alike, so the refusal does not depend on row order.
#[test]
fn an_out_of_bounds_row_outranks_units_wherever_it_lies() {
    let tight = super::LoadLimits {
        reserve_units: (1 << 20) - 100,
        ..limits()
    };
    for outside in [0, 59] {
        let mut entries = entries(60);
        entries[outside].extents = vec![ExtentLocator::new(1 << 20, 1).unwrap().bits()];
        let units = encode(Crc32c::detect(), checkpoint(5), &entries, u32::MAX).unwrap();
        let mut fed = Fed::under(units.len(), tight, 4);
        for (at, unit) in units.iter().enumerate() {
            fed.land(at, &unit[..]);
        }
        let budget = crate::storage::EngineBudget::unlimited();
        let batch = super::guarded_load(entries.clone(), tight, &budget);
        assert!(
            matches!(
                batch,
                super::GuardedLoad::Cold {
                    refusal: super::LoadRefusal::Bounds,
                    ..
                }
            ),
            "row {outside}: {batch:?}"
        );
        assert_eq!(whole(fed.finish()), batch, "row {outside}");
    }
}

/// The first damage of a slot torn in units 2 and 4 is unit 2's in every arrival order, including the orders in which
/// unit 4 lands first, and a failed check outranks an earlier unit's failed read.
#[test]
fn the_first_damage_is_the_lowest_failed_unit_in_any_arrival_order() {
    let mut units = encode(Crc32c::detect(), checkpoint(5), &entries(120), u32::MAX).unwrap();
    for at in [2, 4] {
        units[at][UNIT_LEN - 1] ^= 1;
    }
    let mut rng = crate::storage::seeded::SplitMix64::new(0x1445);
    let mut fourth_first = false;
    for _ in 0..40 {
        let mut order: Vec<usize> = (0..units.len()).collect();
        for at in (1..order.len()).rev() {
            order.swap(at, rng.next_u64() as usize % (at + 1));
        }
        fourth_first |= order.iter().position(|&at| at == 4) < order.iter().position(|&at| at == 2);
        let mut fed = Fed::new(units.len(), 4);
        for &at in &order {
            fed.land(at, if at == 1 { &[][..] } else { &units[at][..] });
        }
        let (damage, _) = damaged(fed.finish());
        assert_eq!(damage.first, UnitDamage::Chunk { unit: 2 }, "{order:?}");
        assert_eq!(
            (damage.failed, damage.unread),
            (vec![2, 4], vec![1]),
            "{order:?}"
        );
    }
    assert!(fourth_first, "some order lands unit 4 before unit 2");
}

/// The verdict's precedence: the stale-write refusal of a slot whose intact unit 0 names another unit count outranks a
/// refusal of the checkpoint's own entries, which outranks a refusal of the final set, whose Entries outranks its Units.
/// A suffix insert past the slot
/// count is a damage hole of its suffix, so the load keeps the checkpoint's entries and does not install.
#[test]
fn stale_write_outranks_a_base_refusal_which_outranks_a_union_refusal() {
    use super::LoadRefusal::{Entries, Overlap, StaleWrite, Units};
    let crc = Crc32c::detect();
    let ours = encode(crc, checkpoint(5), &entries(60), u32::MAX).unwrap();
    let longer = encode(crc, checkpoint(5), &entries(100), u32::MAX).unwrap();
    // Entry 1's first extent overlaps entry 0's and its second stays its own, so the checkpoint's entries still cover
    // 120 units and the final set's 122 pass the capacity: Overlap leads the final set's Units.
    let mut overlapping = entries(60);
    overlapping[1].extents[0] = overlapping[0].extents[0];
    let overlapped = encode(crc, checkpoint(5), &overlapping, u32::MAX).unwrap();
    // The checkpoint's entries cover 120 units; the capacity holds one more.
    let tight = super::LoadLimits {
        reserve_units: limits().payload_end - 121,
        ..limits()
    };
    let wide = |slot: usize| {
        let mut made = entry(slot, 4, 64 * 500);
        made.extents = vec![ExtentLocator::new(64 * 500, 2).unwrap().bits()];
        super::delta::Record::Insert(made)
    };
    let load_under = |limits, units: &[Box<[u8; UNIT_LEN]>], mixed: bool, slot: usize| {
        let mut units = units.to_vec();
        if mixed {
            units[0] = longer[0].clone();
        }
        let mut fed = Fed::with_suffix(units.len(), &[wide(slot)], limits);
        for (at, unit) in units.iter().enumerate() {
            fed.land(at, &unit[..]);
        }
        fed.finish()
    };
    let load = |units: &[Box<[u8; UNIT_LEN]>], mixed, slot| load_under(tight, units, mixed, slot);
    // The checkpoint's 60 entries fill `n_max`, so the suffix's insert passes it.
    let full = super::LoadLimits { n_max: 60, ..tight };
    assert_eq!(
        load_under(full, &ours, true, 500).verdict,
        Err(StaleWrite),
        "stale before Entries"
    );
    assert_eq!(
        load_under(full, &ours, false, 500).verdict,
        Err(Entries),
        "Entries before Units"
    );
    assert_eq!(
        load(&overlapped, true, 500).verdict,
        Err(StaleWrite),
        "an inconsistent slot is stale whatever the guard decides"
    );
    assert_eq!(
        load(&overlapped, false, 500).verdict,
        Err(Overlap),
        "the checkpoint's refusal leads the final set's"
    );
    assert_eq!(
        load(&ours, true, 500).verdict,
        Err(StaleWrite),
        "an inconsistent slot is stale"
    );
    assert_eq!(
        load(&ours, false, 500).verdict,
        Err(Units),
        "the suffix's units pass the capacity"
    );
    let past = load(&ours, false, 1 << 11);
    assert_eq!(past.verdict, Ok(()), "the misfit insert is a hole");
    assert_eq!(past.suffix.damage.len(), 1);
    assert!(
        !past.installable(),
        "damaged suffix history does not install"
    );
}

/// A destination's first job allocates its guard; when the allocator refuses the bits of its ranges, here a payload area
/// of 2^63 units, the job applies nothing and the decode ends with no load, so a caller keeps the record.
#[test]
fn a_guard_the_allocator_refuses_fails_the_decode() {
    let units = encode(Crc32c::detect(), checkpoint(5), &entries(60), u32::MAX).unwrap();
    let huge = super::LoadLimits {
        payload_end: 1 << 63,
        ..limits()
    };
    let mut fed = Fed::with_suffix(units.len(), &[], huge);
    for (at, unit) in units.iter().enumerate() {
        fed.land(at, &unit[..]);
    }
    assert!(fed.decode.done(), "the refused guards end the decode");
    assert_eq!(fed.decode.finish(), None);
}

/// A seal whose key comparison scratch the allocator refuses fails the decode whatever another destination's seal
/// found: with a key two entries share on one destination and the refused scratch on any other, before or after it in
/// destination order, the decode yields no load, so a caller keeps the record.
#[test]
fn a_refused_seal_scratch_fails_the_decode_beside_another_destinations_key_refusal() {
    use super::checkpoint::SEAL_REFUSED;
    let (hasher, destinations) = routing(4);
    let dest_of = |key: &[u8; 32]| {
        let mut prints = [0; crate::index::LANES];
        hasher.fingerprints(std::slice::from_ref(key), &mut prints);
        crate::index::reduce(prints[0], destinations)
    };
    // The shared key routes to an inner destination, so refused seals lie on both sides of it.
    let mut shared = entries(60);
    let owner = (0..40)
        .find(|&at| (1..destinations - 1).contains(&dest_of(&shared[at].key)))
        .expect("a key routes to an inner destination");
    shared[40].key = shared[owner].key;
    let keyed = dest_of(&shared[owner].key);
    let units = encode(Crc32c::detect(), checkpoint(5), &shared, u32::MAX).unwrap();
    let (mut before, mut after) = (false, false);
    for refused in (0..destinations).filter(|&dest| dest != keyed) {
        (before, after) = (before || refused < keyed, after || refused > keyed);
        SEAL_REFUSED.with(|cell| cell.set(Some(refused)));
        let mut fed = Fed::new(units.len(), destinations);
        for (at, unit) in units.iter().enumerate() {
            fed.land(at, &unit[..]);
        }
        SEAL_REFUSED.with(|cell| cell.set(None));
        assert!(fed.decode.done(), "refused at {refused}");
        assert_eq!(
            fed.decode.finish(),
            None,
            "refused at {refused}, key at {keyed}"
        );
    }
    assert!(
        before && after,
        "a refused seal both before and after the key's destination"
    );
    let mut fed = Fed::new(units.len(), destinations);
    for (at, unit) in units.iter().enumerate() {
        fed.land(at, &unit[..]);
    }
    assert_eq!(
        fed.finish().verdict,
        Err(super::LoadRefusal::Key),
        "control: with every seal's scratch the shared key refuses"
    );
}

/// A destination job whose room for a window's fingerprints and chunks the allocator refuses, and a window job whose
/// entry chunks the allocator refuses, each fail the decode, so a caller keeps the record.
#[test]
fn a_refused_window_room_or_chunk_reservation_fails_the_decode() {
    use super::checkpoint::{CHUNKS_REFUSED, ROOM_REFUSED};
    let units = encode(Crc32c::detect(), checkpoint(5), &entries(60), u32::MAX).unwrap();
    for plant in [&ROOM_REFUSED, &CHUNKS_REFUSED] {
        plant.with(|cell| cell.set(true));
        let mut fed = Fed::new(units.len(), 4);
        for (at, unit) in units.iter().enumerate() {
            fed.land(at, &unit[..]);
        }
        plant.with(|cell| cell.set(false));
        assert!(fed.decode.done());
        assert_eq!(fed.decode.finish(), None);
    }
}

/// Limits the guard refuses refuse the slot `Limits`, and the suffix they also refuse replays nothing and reports its
/// first LSN unread, so the load does not install; the same suffix under valid limits replays and installs.
#[test]
fn invalid_limits_refuse_the_slot_and_leave_the_suffix_uninstallable() {
    let units = encode(Crc32c::detect(), checkpoint(5), &entries(60), u32::MAX).unwrap();
    let mut made = entry(500, 4, 64 * 500);
    made.extents = vec![ExtentLocator::new(64 * 500, 1).unwrap().bits()];
    let records = [super::delta::Record::Insert(made)];
    let invalid = super::LoadLimits {
        record_chunk_len: 0,
        ..limits()
    };
    for (limits, valid) in [(invalid, false), (limits(), true)] {
        let mut fed = Fed::with_suffix(units.len(), &records, limits);
        for (at, unit) in units.iter().enumerate() {
            fed.land(at, &unit[..]);
        }
        let load = fed.finish();
        assert_eq!(load.verdict.is_ok(), valid, "{:?}", load.verdict);
        assert_eq!(load.installable(), valid);
        if valid {
            assert!(load.suffix.unread.is_empty());
        } else {
            assert_eq!(load.verdict, Err(super::LoadRefusal::Limits));
            assert_eq!(load.suffix.unread, vec![0]);
        }
    }
}

/// A destination job refused on its first run keeps its refusal when it runs again, for a refused window room and a
/// refused seal scratch, so the decode yields no load.
#[test]
fn a_refused_destination_job_run_again_keeps_its_refusal() {
    use super::checkpoint::{ROOM_REFUSED, SEAL_REFUSED};
    let units = encode(Crc32c::detect(), checkpoint(5), &entries(60), u32::MAX).unwrap();
    for room in [true, false] {
        let mut fed = Fed::new(units.len(), 4);
        for (at, unit) in units.iter().enumerate() {
            let job = fed.decode.window(at as u32, 1, unit.to_vec());
            fed.decode.landed(run(job));
        }
        let replay = fed.decode.work().expect("the replay of an empty ancestry");
        fed.decode.landed(run(replay));
        let taken: Vec<Work> = std::iter::from_fn(|| fed.decode.work()).collect();
        // The first runs refuse every window room, or destination 0's seal scratch; the reruns refuse nothing.
        match room {
            true => ROOM_REFUSED.with(|cell| cell.set(true)),
            false => SEAL_REFUSED.with(|cell| cell.set(Some(0))),
        }
        let first: Vec<Done> = taken.into_iter().map(run).collect();
        ROOM_REFUSED.with(|cell| cell.set(false));
        SEAL_REFUSED.with(|cell| cell.set(None));
        for done in first {
            let Done::Dest(job) = done else {
                panic!("a destination terminal");
            };
            fed.decode.landed(run(Work::Dest(job)));
        }
        assert_eq!(fed.decode.finish(), None, "room refused: {room}");
    }
}

/// A window landing after the decode is done, at the named unit count with no unit, offers no job: a sealed guard is
/// never dispatched again, and the decode stays done.
#[test]
fn a_window_after_the_last_seal_offers_no_job() {
    let units = encode(Crc32c::detect(), checkpoint(5), &entries(60), u32::MAX).unwrap();
    let mut fed = Fed::new(units.len(), 4);
    for (at, unit) in units.iter().enumerate() {
        fed.land(at, &unit[..]);
    }
    assert!(fed.decode.done());
    let late = fed.decode.window(units.len() as u32, 0, Vec::new());
    fed.decode.landed(run(late));
    assert!(
        fed.decode.work().is_none(),
        "a sealed guard is not dispatched"
    );
    assert!(fed.decode.done());
    assert_eq!(whole(fed.finish()), super::GuardedLoad::Warm(entries(60)));
}

/// A decode of an ancestry whose LSN count passes `u64` is refused.
#[test]
fn a_decode_of_an_ancestry_past_u64_lsns_is_refused() {
    let prefix = crate::failover::records::Layout {
        units: 1 << 51,
        ..no_suffix()
    };
    let long = |start| crate::failover::records::Suffix {
        session: SESSION,
        start,
        certified: u64::MAX,
        end: u64::MAX,
    };
    let ancestry: Vec<_> = (0..1 << 14).map(long).collect();
    let decode = SlotDecode::new(
        Crc32c::detect(),
        checkpoint(5),
        2,
        SESSION,
        limits(),
        routing(4),
        (prefix, 0, &ancestry),
    );
    assert!(decode.is_none());
    let one = SlotDecode::new(
        Crc32c::detect(),
        checkpoint(5),
        2,
        SESSION,
        limits(),
        routing(4),
        (prefix, 0, &ancestry[..1]),
    );
    assert!(
        one.is_some(),
        "control: one suffix of the same layout decodes"
    );
}

/// The entry whose rows cross from data unit 1 into data unit 2 of [`entries`]`(60)`.
fn crossing() -> CaptureEntry {
    crossing_at(1)
}

/// The entry whose rows cross from data unit `unit` into data unit `unit + 1` of [`entries`]`(60)`.
fn crossing_at(unit: usize) -> CaptureEntry {
    let rows = crate::failover::records::UNIT_ENTRIES as usize;
    let edge = unit * rows;
    let mut first = 0;
    for entry in entries(60) {
        let last = first + entry.extents.len() - 1;
        if first < edge && last >= edge {
            return entry;
        }
        first = last + 1;
    }
    unreachable!("an entry crosses the unit edge")
}

/// A torn unit cuts an entry whose later rows decode on the next unit; the suffix removes that entry and reuses its
/// unit for a new entry. The final set, the intact whole entries and the new one, fits a capacity that holds exactly
/// the decoded rows, so the load is warm: the cut entry's decoded rows count in the slot's own rules and not in the
/// final set's units.
#[test]
fn a_cut_entry_whose_unit_the_suffix_reuses_leaves_the_final_set_within_the_capacity() {
    let crc = Crc32c::detect();
    let mut units = encode(crc, checkpoint(5), &entries(60), u32::MAX).unwrap();
    units[1][UNIT_LEN - 1] ^= 1;
    let rows = crate::failover::records::UNIT_ENTRIES;
    let decoded = super::checkpoint::rows(&entries(60)) - rows;
    let exact = super::LoadLimits {
        reserve_units: limits().payload_end - decoded,
        ..limits()
    };
    let cut = crossing();
    let mut reuse = entry(500, 4, 0);
    reuse.extents = vec![cut.extents[cut.extents.len() - 1]];
    let records = [
        super::delta::Record::Remove {
            identity: super::delta::identity_of(&cut),
            cause: super::delta::Cause::Evict,
        },
        super::delta::Record::Insert(reuse.clone()),
    ];
    let mut fed = Fed::with_suffix(units.len(), &records, exact);
    for (at, unit) in units.iter().enumerate() {
        fed.land(at, &unit[..]);
    }
    let load = fed.finish();
    let mut kept = outside(&entries(60), 1);
    kept.push(reuse);
    assert_eq!(
        load.damage.as_ref().map(|damage| &damage.failed[..]),
        Some(&[1][..])
    );
    assert_eq!(load.verdict, Ok(()), "the final set fits");
    assert_eq!(load.load(), super::GuardedLoad::Warm(canonical(kept)));
}

/// An entry that crosses a window edge reaches its destination as a chunk the owner stitched, which no window job
/// classified; its seal still drops it when the suffix removes it, and withholds it when the reader does not admit its
/// session. A seal that keeps every unclassified chunk loads both.
#[test]
fn a_stitched_entry_is_classified_at_its_seal() {
    use super::checkpoint::SKIP_UNCLASSIFIED;
    let crc = Crc32c::detect();
    let mut checkpoint_entries = entries(60);
    let cut = crossing();
    // The unadmitted entry also crosses a unit edge, so only its seal classifies its session.
    let other = crossing_at(2);
    let foreign = checkpoint_entries
        .iter()
        .position(|entry| *entry == other)
        .unwrap();
    checkpoint_entries[foreign].session = 2;
    let units = encode(crc, checkpoint(5), &checkpoint_entries, u32::MAX).unwrap();
    let removal = super::delta::Record::Remove {
        identity: super::delta::identity_of(&cut),
        cause: super::delta::Cause::Evict,
    };
    let load = |skip: bool| {
        SKIP_UNCLASSIFIED.with(|cell| cell.set(skip));
        let mut fed = Fed::with_suffix(units.len(), std::slice::from_ref(&removal), limits());
        for (at, unit) in units.iter().enumerate() {
            fed.land(at, &unit[..]);
        }
        let load = fed.finish();
        SKIP_UNCLASSIFIED.with(|cell| cell.set(false));
        load
    };
    let held = |load: &SlotLoad, entry: &CaptureEntry| {
        load.shards
            .iter()
            .flatten()
            .flat_map(Chunk::captured)
            .any(|(held, _)| &held == entry)
    };
    let sealed = load(false);
    assert!(!held(&sealed, &cut) && !held(&sealed, &checkpoint_entries[foreign]));
    assert_eq!((sealed.slot_withheld, sealed.verdict), (1, Ok(())));
    let skipped = load(true);
    assert!(
        held(&skipped, &cut),
        "control: a seal that keeps unclassified chunks loads the removed entry"
    );
    assert!(
        held(&skipped, &checkpoint_entries[foreign]),
        "control: a seal that keeps unclassified chunks loads the unadmitted entry"
    );
}

/// A replay terminal of another decode changes nothing here, even after this decode's own replay landed: a foreign
/// suffix that removes one of this slot's entries leaves the entry loaded.
#[test]
fn a_decode_refuses_the_replay_of_another_decode() {
    let units = encode(Crc32c::detect(), checkpoint(5), &entries(60), u32::MAX).unwrap();
    let removal = super::delta::Record::Remove {
        identity: super::delta::identity_of(&entries(60)[5]),
        cause: super::delta::Cause::Evict,
    };
    let mut other = Fed::with_suffix(units.len(), std::slice::from_ref(&removal), limits());
    let foreign = run(other.decode.work().expect("the other decode's replay"));
    assert!(matches!(foreign, Done::Replay(_)));
    let mut fed = Fed::new(units.len(), 4);
    let own = fed.decode.work().expect("this decode's replay");
    fed.decode.landed(run(own));
    fed.decode.landed(foreign);
    for (at, unit) in units.iter().enumerate() {
        fed.land(at, &unit[..]);
    }
    assert_eq!(fed.finish().load(), super::GuardedLoad::Warm(entries(60)));
}

/// A second encoding's unit marks the slot as a stale write when its first row breaks the previous unit's open entry.
/// The slot loads `Cold` with `StaleWrite`, which takes precedence over the guard's refusal.
#[test]
fn a_foreign_unit_whose_extents_overlap_ours_loads_cold_as_a_stale_write() {
    let crc = Crc32c::detect();
    let named = entries(100);
    let single: Vec<CaptureEntry> = (0..200)
        .map(|at| entry(at + 500, 2, 64 * (at as u64 % 100)))
        .collect();
    let ours = encode(crc, checkpoint(5), &named, u32::MAX).unwrap();
    let theirs = encode(crc, checkpoint(5), &single, u32::MAX).unwrap();
    let mut mixed = ours;
    mixed[1][UNIT_LEN - 1] ^= 1;
    mixed[5] = theirs[5].clone();
    let (damage, load) = damaged(decode(&mixed, 0..mixed.len()).finish());
    assert_eq!(damage.failed, [1], "the foreign unit passes its own checks");
    assert_eq!(damage.alarm(), super::LoadRefusal::StaleWrite);
    let events: Vec<_> = load.events().collect();
    let mixed = loaded(load);
    assert_eq!(
        super::load_guard(&mixed, limits(), &crate::storage::EngineBudget::unlimited()),
        Err(super::LoadRefusal::Overlap),
        "the guard refuses the entries of the two encodings"
    );
    let (alarm, evicts) = events.split_last().expect("a cold load raises an alarm");
    assert_eq!(
        alarm,
        &super::LoadEvent::Alarm {
            refusal: super::LoadRefusal::StaleWrite
        }
    );
    assert_eq!(evicts.len(), mixed.len());
    assert!(
        evicts.iter().all(|event| matches!(
            event,
            super::LoadEvent::Evict {
                cause: super::EvictCause::StaleWriteLoss,
                ..
            }
        )),
        "{evicts:?}"
    );
}

/// Every data unit before the last holds a full unit of rows, so the entry an undecoded unit cut resumes exactly that
/// many rows past its next index, and only while it has rows left. A unit of a second encoding whose first row is a
/// row of the cut entry anywhere else loads the slot cold beside the torn unit: at the entry's next index, as if the
/// torn unit held no row, and after a torn unit that held the entry's last rows. Without the second encoding's unit
/// the same torn slot keeps its intact entries.
#[test]
fn a_cut_entry_resuming_off_the_row_the_undecoded_units_place_it_loads_cold() {
    let crc = Crc32c::detect();
    let spread = |key: usize, count: u64| {
        let mut entry = entry(key, 2, 0);
        entry.extents = (0..count)
            .map(|at| {
                ExtentLocator::new(1000 * key as u64 + 8 * at, 1)
                    .unwrap()
                    .bits()
            })
            .collect();
        entry
    };
    let (long, brief) = (spread(0, 60), spread(1, 5));
    let cases = [
        (
            "at its next index",
            vec![long.clone(), spread(2, 41), spread(3, 1)],
            vec![spread(2, 41), long, spread(4, 1)],
        ),
        (
            "after its last row",
            vec![spread(5, 39), brief.clone(), spread(6, 1), spread(7, 59)],
            vec![spread(8, 79), brief, spread(9, 20)],
        ),
    ];
    for (case, named, second) in cases {
        let ours = encode(crc, checkpoint(5), &named, u32::MAX).unwrap();
        let theirs = encode(crc, checkpoint(5), &second, u32::MAX).unwrap();
        assert_eq!((ours.len(), theirs.len()), (4, 4), "{case}");
        let mut torn = ours;
        torn[2][UNIT_LEN - 1] ^= 1;
        let (damage, load) = damaged(decode(&torn, 0..torn.len()).finish());
        assert_eq!(damage.failed, [2], "{case}");
        assert_eq!(
            load,
            super::GuardedLoad::Warm(outside(&named, 2)),
            "{case} control: one encoding"
        );
        let mut mixed = torn;
        mixed[3] = theirs[3].clone();
        let (damage, load) = damaged(decode(&mixed, 0..mixed.len()).finish());
        assert_eq!(
            damage.failed,
            [2],
            "{case}: the second encoding's unit passes its own checks"
        );
        assert!(
            matches!(
                load,
                super::GuardedLoad::Cold {
                    refusal: super::LoadRefusal::StaleWrite,
                    ..
                }
            ),
            "{case}: {load:?}"
        );
    }
}

/// The capture of the checkpoint the resealed units belong to, which [`Fed`] decodes.
const CAPTURE: u32 = 5;

/// The rows of one full data unit.
const ROWS: usize = crate::failover::records::UNIT_ENTRIES as usize;

/// The data unit [`resealed`] rewrites and reseals; unit 1 stays intact beside it.
const DAMAGED: usize = 2;

/// One-row entries that fill data units 1 and 2. Each entry of unit 2 names the slot of an entry of unit 1, so the
/// guard refuses the load whenever a row of unit 2 is routed.
fn two_full_units() -> Vec<CaptureEntry> {
    let mut entries: Vec<CaptureEntry> = (0..2 * ROWS)
        .map(|at| entry(at, 2, 8 * at as u64))
        .collect();
    for at in 0..ROWS {
        entries[ROWS + at].allocation = entries[at].allocation;
    }
    entries
}

/// The units of [`two_full_units`] after `change` rewrote the payload of unit [`DAMAGED`] and [`reseal`] encoded the
/// unit's header again over the changed payload.
fn resealed(change: impl FnOnce(&mut [u8])) -> Vec<Box<[u8; UNIT_LEN]>> {
    let mut units = encode(
        Crc32c::detect(),
        checkpoint(CAPTURE),
        &two_full_units(),
        u32::MAX,
    )
    .unwrap();
    assert_eq!(units.len(), 3, "unit 0 and two full data units");
    let start = layout().1.header_bytes();
    assert!(
        start + 8 + ROWS * ROW_LEN < UNIT_LEN,
        "a full unit has unused bytes after its rows"
    );
    let payload = &mut units[DAMAGED][start..];
    assert_eq!(
        payload[..4],
        (ROWS as u32).to_le_bytes(),
        "data unit 2 is full as encoded"
    );
    assert_eq!(payload[4..8], [0; 4], "bytes 4..8 are zero as encoded");
    assert!(
        payload[8 + ROWS * ROW_LEN..].iter().all(|&byte| byte == 0),
        "the bytes after the rows are zero as encoded"
    );
    change(payload);
    reseal(&mut units[DAMAGED], DAMAGED);
    units
}

/// Encodes the header of `unit`, unit `at` of capture [`CAPTURE`] by [`SESSION`], again over its payload, so the unit
/// keeps its identity and carries the crc of its current payload.
pub(crate) fn reseal(unit: &mut [u8; UNIT_LEN], at: usize) {
    use super::super::record::{ExtentPosition, RecordIdentity, encode_header};
    let identity = RecordIdentity {
        key: key(checkpoint(CAPTURE).shard),
        allocation: u64::from(CAPTURE) << 32 | at as u64,
        session: SESSION,
        version: u64::from(CAPTURE),
    };
    let (_, layout) = layout();
    encode_header(
        Crc32c::detect(),
        &layout,
        &identity,
        ExtentPosition::FIRST,
        unit,
    )
    .unwrap();
}

/// Asserts that `units` report the content damage of unit [`DAMAGED`] alone and load warm exactly the entries of the
/// intact unit: a routed row of the damaged unit would add its entry or refuse the load for the slot it shares.
fn assert_adds_no_row(units: &[Box<[u8; UNIT_LEN]>], case: &str) {
    let slot = decode(units, 0..units.len()).finish();
    let load = slot.load();
    let unit = DAMAGED as u32;
    let Some(damage) = slot.damage else {
        panic!("{case}: unit {unit} passed its content check and added its rows: {load:?}");
    };
    assert_eq!(damage.first, UnitDamage::Content { unit }, "{case}");
    assert_eq!(damage.failed, [unit], "{case}");
    assert_eq!(damage.unread, [0u32; 0], "{case}");
    let kept = outside(&two_full_units(), DAMAGED);
    assert_eq!(kept.len(), ROWS, "{case}: the intact unit's entries");
    assert_eq!(load, super::GuardedLoad::Warm(kept), "{case}");
}

/// The unit resealed with its payload unchanged passes every check and its rows are routed, so the guard sees the
/// slots the two units' entries share and refuses the load with exactly the entries of both units in it: resealing
/// alone damages nothing.
#[test]
fn a_resealed_unit_with_an_intact_payload_adds_its_rows() {
    let units = resealed(|_| ());
    let load = whole(decode(&units, 0..units.len()).finish());
    let super::GuardedLoad::Cold {
        entries: loaded,
        refusal,
    } = load
    else {
        panic!("the shared slots are refused: {load:?}");
    };
    assert_eq!(refusal, super::LoadRefusal::Slot);
    assert_eq!(loaded.len(), 2 * ROWS);
    assert_eq!(loaded, canonical(two_full_units()));
}

/// Bytes `4..8` of a later unit's payload are zero. A unit with byte 4 set, resealed so that its identity and crc
/// verify, fails its content check and adds no row.
#[test]
fn a_unit_with_a_nonzero_byte_at_4_of_its_payload_adds_no_row() {
    assert_adds_no_row(&resealed(|payload| payload[4] = 1), "payload[4] = 1");
}

/// Each of the 32 bits of bytes `4..8`, set alone under a resealed header, fails the unit's content check, and the
/// unit adds no row.
#[test]
fn a_unit_with_a_nonzero_byte_anywhere_in_4_to_8_of_its_payload_adds_no_row() {
    for at in 4..8 {
        for bit in 0..8 {
            let units = resealed(|payload| payload[at] = 1 << bit);
            assert_adds_no_row(&units, &format!("payload[{at}] = 1 << {bit}"));
        }
    }
}

/// The decode refuses a later unit whose row count is zero as content damage of that unit, and the unit adds no row.
/// The checkpoint module's documentation bounds a later unit's row count from above, at `UNIT_ENTRIES`; the lower
/// bound of one row is the decode's own check. With the unit's rows left after the zero count, the nonzero bytes
/// after the count fail the check as well; with every payload byte zero, the zero count alone fails it.
#[test]
fn a_unit_with_a_zero_row_count_adds_no_row() {
    let units = resealed(|payload| payload[..4].copy_from_slice(&0u32.to_le_bytes()));
    assert_adds_no_row(&units, "filled = 0");
    let units = resealed(|payload| payload.fill(0));
    assert_adds_no_row(&units, "a zero payload");
}

/// A later unit carries at most `UNIT_ENTRIES` rows: a resealed unit whose row count is one above that, or the
/// largest count the field holds, fails its content check and adds no row.
#[test]
fn a_unit_with_a_row_count_above_its_rows_adds_no_row() {
    let above = (ROWS as u32 + 1).to_le_bytes();
    let units = resealed(|payload| payload[..4].copy_from_slice(&above));
    assert_adds_no_row(&units, "filled = ROWS + 1");
    let units = resealed(|payload| payload[..4].copy_from_slice(&u32::MAX.to_le_bytes()));
    assert_adds_no_row(&units, "filled = u32::MAX");
}

/// The bytes after a later unit's rows are zero: a resealed unit with the first of them set, or the low or the high
/// bit of the last, fails its content check and adds no row.
#[test]
fn a_unit_with_a_nonzero_byte_after_its_rows_adds_no_row() {
    let units = resealed(|payload| payload[8 + ROWS * ROW_LEN] = 1);
    assert_adds_no_row(&units, "the first byte after the rows");
    let units = resealed(|payload| *payload.last_mut().unwrap() = 1);
    assert_adds_no_row(&units, "the last byte of the payload");
    let units = resealed(|payload| *payload.last_mut().unwrap() = 0x80);
    assert_adds_no_row(&units, "the high bit of the last byte of the payload");
}

/// Members with every field varied and one to five extents, then one member of `large` extents.
fn varied(seed: u64, count: usize, large: usize) -> Vec<CaptureEntry> {
    let mut random = crate::storage::seeded::SplitMix64::new(seed);
    let mut entries: Vec<CaptureEntry> = (0..count)
        .map(|at| {
            let mut key = [0; 32];
            for word in key.as_chunks_mut::<8>().0 {
                *word = random.next_u64().to_le_bytes();
            }
            CaptureEntry {
                key,
                allocation: (at as u64) << 32 | random.below(1 << 32),
                session: SESSION,
                version: random.next_u64(),
                deadline_ns: random.next_u64(),
                lifetime_ms: random.next_u64() as u32,
                tail: random.next_u64() as u16,
                extents: (0..1 + random.below(5))
                    .map(|_| random.next_u64())
                    .collect(),
            }
        })
        .collect();
    entries.push(CaptureEntry {
        extents: (0..large as u64).collect(),
        ..entry(count, 2, 0)
    });
    entries
}

/// The walk's copy of `entries`: the first `walked` pushed in order under an unlimited budget, the rest saved as
/// the side list.
fn cut_of(entries: &[CaptureEntry], walked: usize) -> Cut {
    let mut cut = Cut::new();
    for entry in &entries[..walked] {
        cut.push(entry, &crate::storage::EngineBudget::unlimited())
            .unwrap();
    }
    cut.save(entries[walked..].to_vec());
    cut
}

/// `UniqueCapture`: a cut packed by a walk encodes to the units its entries encode to, for members of one to five
/// extents with every field set, a member larger than one chunk, a side list, and slots that hold every row, some
/// rows and none.
#[test]
fn a_packed_cut_encodes_to_the_units_of_its_entries() {
    let crc = Crc32c::detect();
    for (seed, count, large) in [(1, 0, 1), (2, 300, 3), (3, 2_000, 9_000)] {
        let entries = varied(seed, count, large);
        let rows = rows(&entries);
        for walked in [0, entries.len() / 2, entries.len()] {
            let cut = cut_of(&entries, walked);
            assert_eq!(cut.len(), entries.len());
            assert_eq!(cut.is_empty(), entries.is_empty());
            assert_eq!(cut.counted(), Counted::of(&entries));
            for slot_units in [u32::MAX, units(rows) as u32, units(rows / 2) as u32, 1, 0] {
                let packed = encode_counted(
                    crc,
                    checkpoint(5),
                    (&cut, cut.counted()),
                    slot_units,
                    &mut Vec::new(),
                );
                let plain = encode(crc, checkpoint(5), &entries, slot_units);
                assert!(
                    packed == plain,
                    "seed {seed}, {walked} walked, {slot_units} slot units"
                );
            }
        }
    }
}

/// A cut holding a member of no extent, or of more extents than a row counts, refuses as its entries do, with the
/// first such member's allocation.
#[test]
fn a_cut_with_an_unencodable_member_refuses_as_its_entries_do() {
    let crc = Crc32c::detect();
    for extents in [0, usize::from(u16::MAX) + 1] {
        let mut entries = entries(5);
        entries[2].extents = vec![7; extents];
        entries[4].extents = Vec::new();
        let refusal = EncodeRefusal::Extents {
            allocation: entries[2].allocation,
        };
        for walked in [0, 3, 5] {
            let cut = cut_of(&entries, walked);
            assert_eq!(cut.counted(), Counted::of(&entries));
            assert_eq!(
                encode_counted(
                    crc,
                    checkpoint(5),
                    (&cut, cut.counted()),
                    u32::MAX,
                    &mut Vec::new()
                )
                .err(),
                Some(refusal)
            );
        }
        assert_eq!(
            encode(crc, checkpoint(5), &entries, u32::MAX).err(),
            Some(refusal)
        );
    }
}

/// A cut reserves a chunk only when the budget holds its bytes with that chunk: a budget one byte short refuses the
/// push with no member copied and no chunk reserved, and the members a chunk holds need no further bytes.
#[test]
fn a_cut_reserves_a_chunk_only_under_its_budget() {
    use crate::storage::EngineBudget;
    let entries = entries(2_000);
    let mut first = Cut::new();
    first.push(&entries[0], &EngineBudget::unlimited()).unwrap();
    let chunk = first.bytes();
    assert!(chunk >= 8192 * size_of::<u64>());

    let mut cut = Cut::new();
    assert_eq!(
        cut.push(&entries[0], &EngineBudget::new(chunk - 1)),
        Err(EncodeRefusal::Memory)
    );
    assert_eq!(cut.len(), 0);
    assert!(cut.bytes() < chunk - 8192 * size_of::<u64>() + 1);
    let budget = EngineBudget::new(chunk);
    let mut pushed = 0;
    while cut.push(&entries[pushed], &budget).is_ok() {
        pushed += 1;
    }
    assert!(pushed > 1, "one chunk holds many members");
    assert_eq!((cut.len(), cut.bytes()), (pushed, chunk));
    cut.save(Vec::new());
    let crc = Crc32c::detect();
    assert!(
        encode_counted(
            crc,
            checkpoint(5),
            (&cut, cut.counted()),
            u32::MAX,
            &mut Vec::new()
        ) == encode(crc, checkpoint(5), &entries[..pushed], u32::MAX)
    );
}

/// A recycled cut is empty, hands back its side list, and refills the chunks it reserved: a second walk of no more
/// words than the first reserves nothing, so it fits a budget of the bytes the cut already holds, and it encodes to
/// the units of its own entries. A member larger than the kept chunk behind the one in use takes a chunk of its
/// own, and a trim frees the chunks behind those the walk filled.
#[test]
fn a_recycled_cut_refills_its_chunks_and_encodes_its_own_members() {
    use crate::storage::EngineBudget;
    let crc = Crc32c::detect();
    let first = varied(7, 3_000, 4);
    let mut cut = cut_of(&first, first.len() - 2);
    let held = cut.bytes();
    assert_eq!(cut.recycle(), first[first.len() - 2..]);
    assert_eq!((cut.len(), cut.bytes()), (0, held));
    assert_eq!(cut.counted(), Counted::default());
    let empty: &[CaptureEntry] = &[];
    assert!(
        encode_counted(
            crc,
            checkpoint(5),
            (&cut, cut.counted()),
            u32::MAX,
            &mut Vec::new()
        ) == encode(crc, checkpoint(5), empty, u32::MAX)
    );

    let second = varied(8, 1_000, 2);
    for entry in &second {
        cut.push(entry, &EngineBudget::new(held)).unwrap();
    }
    cut.save(Vec::new());
    assert_eq!((cut.len(), cut.bytes()), (second.len(), held));
    assert!(
        encode_counted(
            crc,
            checkpoint(6),
            (&cut, cut.counted()),
            u32::MAX,
            &mut Vec::new()
        ) == encode(crc, checkpoint(6), &second, u32::MAX)
    );
    cut.trim();
    let trimmed = cut.bytes();
    assert!(trimmed < held, "the second walk filled fewer chunks");
    assert!(
        encode_counted(
            crc,
            checkpoint(6),
            (&cut, cut.counted()),
            u32::MAX,
            &mut Vec::new()
        ) == encode(crc, checkpoint(6), &second, u32::MAX)
    );

    // The third walk's second member is larger than the kept chunk that follows the first chunk.
    let _ = cut.recycle();
    let mut third = varied(9, 1, 20_000);
    third.extend(varied(10, 2_500, 3));
    for entry in &third {
        cut.push(entry, &EngineBudget::unlimited()).unwrap();
    }
    cut.save(Vec::new());
    assert!(cut.bytes() >= trimmed + 20_000 * size_of::<u64>());
    assert!(
        encode_counted(
            crc,
            checkpoint(7),
            (&cut, cut.counted()),
            u32::MAX,
            &mut Vec::new()
        ) == encode(crc, checkpoint(7), &third, u32::MAX)
    );
}

/// The crc32c of each unit's bytes, unit 0 first.
fn unit_crcs(units: &[Box<[u8; UNIT_LEN]>]) -> Vec<u32> {
    let crc = Crc32c::detect();
    units.iter().map(|unit| crc.checksum(&unit[..])).collect()
}

/// The first unit and byte at which `reused` differs from `fresh`, or the unit counts when they differ.
fn first_difference(reused: &Units, fresh: &Units) -> Option<String> {
    if reused.len() != fresh.len() {
        return Some(format!("{} units, fresh {}", reused.len(), fresh.len()));
    }
    let (unit, (reused, fresh)) = (reused.iter().zip(fresh))
        .enumerate()
        .find(|(_, (a, b))| a != b)?;
    let byte = (reused.iter().zip(fresh.iter())).position(|(a, b)| a != b);
    Some(format!("unit {unit}, byte {byte:?}"))
}

/// Runs passes over kept unit buffers, each encoding a cut into the buffers the passes before it left, and checks
/// each pass's units and their checksums against an encode of the same cut into fresh zeroed buffers. The passes
/// follow a pass over 3,000 members of one to five extents: one over a prefix of those members, one over 3,000 other
/// members, one over other members in a slot that holds half their rows, and one into buffers every byte of which
/// is 0xA5. Each reused pass takes the kept buffers in order before it allocates, and the buffers it leaves stay
/// kept. Returns the first pass whose bytes differ.
fn passes_over_kept_buffers() -> Result<(), String> {
    let crc = Crc32c::detect();
    let first = varied(11, 3_000, 4);
    let mut kept = Vec::new();
    let cut = cut_of(&first, 2_000);
    let encoded = encode_counted(
        crc,
        checkpoint(5),
        (&cut, cut.counted()),
        u32::MAX,
        &mut kept,
    )
    .map_err(|refusal| format!("the first pass refused: {refusal:?}"))?;
    assert!(
        kept.is_empty() && encoded.len() > 100,
        "the first pass fills many units"
    );
    kept = encoded;
    let other = varied(12, 3_000, 4);
    let halved = varied(13, 2_000, 3);
    let passes = [
        (6, first[..1_000].to_vec(), u32::MAX, false),
        (7, other, u32::MAX, false),
        (8, halved.clone(), units(rows(&halved) / 2) as u32, false),
        (9, halved, u32::MAX, true),
    ];
    for (capture, entries, slot_units, scrambled) in passes {
        if scrambled {
            kept = (0..kept.len() + 5)
                .map(|_| Box::new([0xA5; UNIT_LEN]))
                .collect();
        }
        let cut = cut_of(&entries, entries.len() / 2);
        let fresh = encode_counted(
            crc,
            checkpoint(capture),
            (&cut, cut.counted()),
            slot_units,
            &mut Vec::new(),
        )
        .map_err(|refusal| format!("capture {capture} refused fresh: {refusal:?}"))?;
        let before: Vec<*const u8> = kept.iter().map(|unit| unit.as_ptr()).collect();
        let reused = encode_counted(
            crc,
            checkpoint(capture),
            (&cut, cut.counted()),
            slot_units,
            &mut kept,
        )
        .map_err(|refusal| format!("capture {capture} refused reused: {refusal:?}"))?;
        if let Some(difference) = first_difference(&reused, &fresh) {
            return Err(format!("capture {capture}: {difference}"));
        }
        if unit_crcs(&reused) != unit_crcs(&fresh) {
            return Err(format!("capture {capture}: the checksums differ"));
        }
        let taken = before.len().min(reused.len());
        let after: Vec<*const u8> = (reused.iter().take(taken).chain(&kept))
            .map(|unit| unit.as_ptr())
            .collect();
        assert_eq!(
            after[..],
            before[..taken.max(before.len())],
            "capture {capture} takes the kept buffers in order and keeps the rest"
        );
        let mut next = reused;
        next.append(&mut kept);
        kept = next;
    }
    Ok(())
}

/// `UniqueCapture`: an encode into the unit buffers earlier encodes left writes every byte of each unit it returns,
/// so a pass over a smaller cut, a pass over other members, a pass into a slot that holds half the rows and a pass
/// into buffers of arbitrary bytes each give the units and checksums of an encode into fresh zeroed buffers.
#[test]
fn an_encode_into_kept_buffers_gives_the_units_of_fresh_buffers() {
    assert_eq!(passes_over_kept_buffers(), Ok(()));
}

/// The control of [`an_encode_into_kept_buffers_gives_the_units_of_fresh_buffers`]: a planted seal that leaves the
/// payload behind a unit's rows as the buffer held it gives the pass over a smaller cut a unit that differs from its
/// fresh encode, past the rows of its last unit.
#[test]
fn a_stale_tail_of_an_earlier_pass_fails_the_kept_buffer_check() {
    STALE_TAIL.with(|plant| plant.set(true));
    let result = passes_over_kept_buffers();
    STALE_TAIL.with(|plant| plant.set(false));
    let difference = result.expect_err("a stale tail differs from a fresh encode");
    assert!(difference.starts_with("capture 6: unit "), "{difference}");
}
