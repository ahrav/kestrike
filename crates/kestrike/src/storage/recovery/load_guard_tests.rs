//! `load_guard` against a direct reference check of each admission rule, in the order the function reports refusals, plus cases that reach its fingerprint-collision and multi-pass sort paths.

use super::super::IO_UNIT;
use super::super::extent::ExtentLocator;
use super::super::geometry::{DIRECT_UNITS, EXTENT_LIMIT};
use super::super::ledger::EngineBudget;
use super::super::record::RecordConfig;
use super::super::seeded::SplitMix64;
use super::capture::CaptureEntry;
use super::load_guard::{fingerprint, key_high, shared_key};
use super::{LoadLimits, LoadRefusal, load_guard};

// The admission rules checked pairwise, in `load_guard`'s refusal order.
fn reference(entries: &[CaptureEntry], limits: LoadLimits) -> Result<(), LoadRefusal> {
    let record = RecordConfig {
        chunk_len: limits.record_chunk_len,
    }
    .validate()
    .map_err(|_| LoadRefusal::Limits)?;
    let capacity = (limits.payload_end.checked_sub(limits.payload_start))
        .and_then(|p| p.checked_sub(limits.reserve_units))
        .ok_or(LoadRefusal::Limits)?;
    if entries.len() > limits.n_max {
        return Err(LoadRefusal::Entries);
    }
    let shapeless = |e: &CaptureEntry| {
        e.extents.is_empty()
            || e.extents.len() > EXTENT_LIMIT as usize
            || usize::from(e.tail) >= IO_UNIT
    };
    if entries.iter().any(shapeless) {
        return Err(LoadRefusal::Bounds);
    }
    for (i, a) in entries.iter().enumerate() {
        if entries[..i].iter().any(|b| a.key == b.key) {
            return Err(LoadRefusal::Key);
        }
    }
    for (i, a) in entries.iter().enumerate() {
        if a.slot() >= limits.slot_count || entries[..i].iter().any(|b| a.slot() == b.slot()) {
            return Err(LoadRefusal::Slot);
        }
    }
    let (mut units, mut ranges, mut bounds) = (0u64, Vec::new(), false);
    for e in entries {
        for &bits in &e.extents {
            let extent = ExtentLocator::from_bits(bits);
            let (start, len) = (extent.start_unit(), u64::from(extent.len_units()));
            if len == 0
                || len > u64::from(DIRECT_UNITS)
                || start < limits.payload_start
                || start + len > limits.payload_end
            {
                bounds = true;
                continue;
            }
            units += len;
            ranges.push((start, start + len));
        }
        // A zero-length last extent already failed its bounds above.
        let last = ExtentLocator::from_bits(e.extents[e.extents.len() - 1]);
        if last.len_units() > 0 {
            let length = super::super::layout::record_len(last.len_units(), e.tail);
            bounds |= record.payload_of(length).is_none();
        }
    }
    if bounds {
        return Err(LoadRefusal::Bounds);
    }
    if units > capacity {
        return Err(LoadRefusal::Units);
    }
    for (i, a) in ranges.iter().enumerate() {
        if ranges[..i].iter().any(|b| a.0 < b.1 && b.0 < a.1) {
            return Err(LoadRefusal::Overlap);
        }
    }
    Ok(())
}

fn limits(slot_count: usize, payload_end: u64, reserve_units: u64) -> LoadLimits {
    LoadLimits {
        payload_start: 2,
        payload_end,
        reserve_units,
        slot_count,
        n_max: 40,
        record_chunk_len: 8192,
    }
}

fn entry(key: [u8; 32], slot: usize, extents: &[(u64, u32)], tail: u16) -> CaptureEntry {
    CaptureEntry {
        key,
        allocation: (slot as u64) << 32 | 1,
        extents: extents
            .iter()
            .map(|&(start, len)| ExtentLocator::new(start, len).unwrap().bits())
            .collect(),
        tail,
        ..CaptureEntry::default()
    }
}

/// Random checkpoints mixing every refusal (repeated keys and slots, slots past the count, out-of-range, empty and overlapping extents, unit totals past the capacity, invalid tails, too many entries) get `reference`'s verdict.
#[test]
fn random_checkpoints_get_the_reference_verdict() {
    let mut rng = SplitMix64::new(0x1293);
    let mut verdicts = std::collections::BTreeMap::new();
    for _ in 0..4000 {
        let n = (rng.next_u64() % 44) as usize;
        let (slot_count, payload_end) = (48, 160 + rng.next_u64() % 120);
        let mut entries: Vec<CaptureEntry> = Vec::new();
        for i in 0..n {
            let roll = rng.next_u64() % 100;
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&rng.next_u64().to_le_bytes());
            key[31] = rng.next_u64() as u8;
            if roll < 3 && i > 0 {
                key = entries[(rng.next_u64() % i as u64) as usize].key;
            }
            let slot = if roll % 50 == 7 {
                (rng.next_u64() % 56) as usize
            } else {
                i
            };
            let extents: Vec<(u64, u32)> = (0..1 + rng.next_u64() % 3)
                .map(|_| {
                    if roll % 40 == 11 {
                        (rng.next_u64() % payload_end, (rng.next_u64() % 3) as u32)
                    } else {
                        (
                            2 + 6 * (i as u64) + rng.next_u64() % 2,
                            1 + (rng.next_u64() % 2) as u32,
                        )
                    }
                })
                .collect();
            let tail = if roll % 30 == 13 {
                (rng.next_u64() % IO_UNIT as u64) as u16
            } else {
                0
            };
            entries.push(entry(key, slot, &extents, tail));
        }
        let reserve = if rng.next_u64().is_multiple_of(6) {
            payload_end - 40
        } else {
            3
        };
        let lim = limits(slot_count, payload_end, reserve);
        let expected = reference(&entries, lim);
        assert_eq!(
            load_guard(&entries, lim, &EngineBudget::unlimited()),
            expected,
            "{entries:?}"
        );
        *verdicts.entry(format!("{expected:?}")).or_insert(0) += 1;
    }
    assert!(verdicts.len() >= 7, "every verdict reached: {verdicts:?}");
}

/// Distinct keys whose fingerprints coincide load, and a third entry repeating one of them is refused `Key`, so equal fingerprints are settled by full key.
#[test]
fn equal_fingerprints_are_settled_by_full_key() {
    let word = |key: &mut [u8; 32], i: usize, value: u64| {
        key[8 * i..8 * i + 8].copy_from_slice(&value.to_le_bytes())
    };
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    word(&mut a, 0, 0x0123_4567_89ab_cdef);
    word(&mut b, 0, 0x0123_4567_89ab_cdef ^ 0x5555u64.rotate_left(16));
    word(&mut b, 1, 0x5555);
    assert_ne!(a, b);
    assert_eq!(fingerprint(&a), fingerprint(&b));
    let lim = limits(8, 64, 3);
    let pair = [entry(a, 0, &[(2, 1)], 0), entry(b, 1, &[(4, 1)], 0)];
    assert_eq!(load_guard(&pair, lim, &EngineBudget::unlimited()), Ok(()));
    let triple = [pair[0].clone(), pair[1].clone(), entry(a, 2, &[(6, 1)], 0)];
    assert_eq!(
        load_guard(&triple, lim, &EngineBudget::unlimited()),
        Err(LoadRefusal::Key)
    );
}

/// A checkpoint of 70,000 entries whose keys differ only in their last bytes, past the 2^16 entries one byte pass of the 24-bit sort orders, loads; one repeated key, one repeated slot and one overlapping extent are each refused.
#[test]
fn a_large_checkpoint_of_shared_prefix_keys_is_checked_exactly() {
    let n = 70_000;
    let key = |i: usize| {
        let mut key = [7u8; 32];
        key[28..].copy_from_slice(&(i as u32).to_le_bytes());
        key
    };
    let mut entries: Vec<_> = (0..n)
        .map(|i| entry(key(i), n - 1 - i, &[(2 * i as u64, 2)], 0))
        .collect();
    let lim = LoadLimits {
        payload_start: 0,
        payload_end: 2 * n as u64,
        reserve_units: 0,
        slot_count: n,
        n_max: n,
        record_chunk_len: 8192,
    };
    let budget = EngineBudget::unlimited();
    assert_eq!(load_guard(&entries, lim, &budget), Ok(()));
    entries[n - 1].key = entries[n / 2].key;
    assert_eq!(load_guard(&entries, lim, &budget), Err(LoadRefusal::Key));
    entries[n - 1].key = key(n - 1);
    entries[n - 1].allocation = entries[3].allocation;
    assert_eq!(load_guard(&entries, lim, &budget), Err(LoadRefusal::Slot));
    entries[n - 1].allocation = 0;
    entries[n - 1].extents = vec![ExtentLocator::new(2 * 31_000 + 1, 1).unwrap().bits()];
    assert_eq!(
        load_guard(&entries, lim, &budget),
        Err(LoadRefusal::Overlap)
    );
}

/// Over a payload area of more than 2^24 units the 24-bit sort key groups nearby starts, so disjoint extents listed in descending order inside one group load, and an overlap among them is still refused.
#[test]
fn extents_sharing_a_sort_key_are_ordered_by_start() {
    let lim = LoadLimits {
        payload_start: 0,
        payload_end: 1 << 32,
        reserve_units: 0,
        slot_count: 8,
        n_max: 8,
        record_chunk_len: 8192,
    };
    let key = |n: u8| [n; 32];
    let mut entries = vec![
        entry(key(1), 0, &[(1 << 31, 1)], 0),
        entry(key(2), 1, &[(1005, 1)], 0),
        entry(key(3), 2, &[(1000, 3)], 0),
        entry(key(4), 3, &[(1003, 2)], 0),
    ];
    let budget = EngineBudget::unlimited();
    assert_eq!(load_guard(&entries, lim, &budget), Ok(()));
    entries[3].extents = vec![ExtentLocator::new(1002, 2).unwrap().bits()];
    assert_eq!(
        load_guard(&entries, lim, &budget),
        Err(LoadRefusal::Overlap)
    );
}

/// Among 600 words of one top byte, more than a partition the sort orders by comparison holds, two words of one
/// fingerprint lie apart, with a word of another fingerprint and the same top 24 bits between them: the key check
/// finds their equal keys, and passes when the two keys differ.
#[test]
fn equal_keys_are_found_across_a_word_of_another_fingerprint_in_their_run() {
    let count = 600;
    let high = key_high(count);
    let print = |at: usize| match at {
        10 | 500 => 0xAB00_0700_0000_5000,
        300 => 0xAB00_0700_0000_9000,
        at => 0xAB00_0000_0000_0000 | (1000 + at as u64) << 40,
    };
    let words = || -> Vec<u64> { (0..count).map(|at| print(at) & high | at as u64).collect() };
    let distinct: Vec<[u8; 32]> = (0..count as u16)
        .map(|at| {
            let mut key = [3; 32];
            key[..2].copy_from_slice(&at.to_le_bytes());
            key
        })
        .collect();
    let mut shared = distinct.clone();
    shared[500] = shared[10];
    for (keys, expected) in [(&distinct, false), (&shared, true)] {
        let (mut words, mut aux) = (words(), vec![0; count]);
        assert_eq!(
            shared_key(|at| &keys[at], &mut words, &mut aux, high),
            expected
        );
    }
}
