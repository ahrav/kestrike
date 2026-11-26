//! SIEVE's visited bit in the slot word: a registered hit's retain sets it
//! in the exchange that takes the hit's right, inside the protected
//! interval and before the final bracket; a refusal before the retain
//! writes nothing and a retain the bracket refuses leaves the bit set; a
//! batch records through each element's retain; and no production code
//! outside the word module names the bit except eviction's hand and the
//! extent's return.

use super::AllocationId;
use super::batch::BatchSlot;
use super::lookup::{LookupError, Pause};
use super::lookup_tests::{body, key, lookup, paused, publish, ready, ticks};
use super::owner::Storage;
use super::publish_tests::{RETRIES, budget, refs};
use super::test_platform::TestPlatform;
use super::word::VISITED;

/// A deadline 100 seconds into the engine's nanosecond timeline.
const DEADLINE: u64 = 100 * 1_000_000_000;

fn visited(storage: &Storage<TestPlatform>, id: AllocationId) -> bool {
    storage.live_pool().unwrap().word(id.slot_index()) & VISITED != 0
}

/// The first hit sets the bit beside its right, a repeated hit keeps it
/// set, and releasing the leases changes only the count.
#[test]
fn a_hit_sets_visited_and_a_repeated_hit_keeps_it() {
    let storage = ready(8);
    let id = publish(&storage, key(0x41), DEADLINE, &body(0x41));
    ticks(&storage, &[Some(1)]);
    let mut reader = storage.register().unwrap();
    let pool = storage.live_pool().unwrap();
    let published = pool.word(id.slot_index());
    assert!(!visited(&storage, id));
    let first = lookup(&mut reader, &key(0x41), RETRIES).unwrap();
    assert!(visited(&storage, id));
    assert_eq!(refs(&storage, id), 2);
    let second = lookup(&mut reader, &key(0x41), RETRIES).unwrap();
    assert_eq!(refs(&storage, id), 3);
    drop((first, second));
    assert_eq!(pool.word(id.slot_index()), published | VISITED);
}

/// The retain records the hit inside the protected interval: paused before
/// the final bracket, the reader's record still holds its pin, the slot
/// counts its anchor and the hit's right, and the bit is already set.
#[test]
fn the_retain_sets_visited_before_the_final_bracket() {
    let storage = ready(8);
    let id = publish(&storage, key(0x47), DEADLINE, &body(0x47));
    ticks(&storage, &[Some(1)]);
    let mut reader = storage.register().unwrap();
    let index = reader.index();
    let seen = std::sync::Mutex::new(None);
    let lease = paused(
        &storage,
        Pause::FinalBracket,
        |storage| {
            let pinned = storage.registration_report(index).unwrap().pinned_era;
            *seen.lock().unwrap() =
                Some((pinned.is_some(), refs(storage, id), visited(storage, id)));
        },
        || lookup(&mut reader, &key(0x47), RETRIES).unwrap(),
    );
    assert_eq!(seen.into_inner().unwrap(), Some((true, 2, true)));
    drop(lease);
    assert_eq!(refs(&storage, id), 1);
}

/// `Missing`, `Contended` before any attempt and `Closed` refuse before a
/// retain and leave the bit clear; `Expired` and `ClockUnavailable` are
/// decided by the final bracket after the retain, so they leave it set and
/// the right refunded.
#[test]
fn only_a_retain_sets_visited() {
    let storage = ready(8);
    let id = publish(&storage, key(0x42), DEADLINE, &body(0x42));
    let mut reader = storage.register().unwrap();
    let pool = storage.live_pool().unwrap();
    assert_eq!(
        lookup(&mut reader, &key(0x43), RETRIES).err(),
        Some(LookupError::Missing)
    );
    ticks(&storage, &[Some(1)]);
    assert_eq!(
        reader.lookup(&key(0x42), 0, &mut budget()).err(),
        Some(LookupError::Contended)
    );
    assert!(!visited(&storage, id));
    for (sample, error) in [
        (Some(DEADLINE), LookupError::Expired),
        (None, LookupError::ClockUnavailable),
    ] {
        ticks(&storage, &[sample]);
        assert_eq!(lookup(&mut reader, &key(0x42), RETRIES).err(), Some(error));
        assert!(visited(&storage, id), "{error:?}");
        assert_eq!(refs(&storage, id), 1, "{error:?}");
        pool.edit_word(id.slot_index(), |word| word & !VISITED);
    }
    storage.close();
    assert_eq!(
        lookup(&mut reader, &key(0x42), RETRIES).err(),
        Some(LookupError::Closed)
    );
    assert!(!visited(&storage, id));
}

/// A batch records through each element's retain: a key repeated inside
/// one batch sets its bit once and keeps it, and a missing element sets
/// nothing.
#[test]
fn a_batch_sets_visited_per_hit_element() {
    let storage = ready(8);
    let a = publish(&storage, key(0x44), DEADLINE, &body(0x44));
    let b = publish(&storage, key(0x45), DEADLINE, &body(0x45));
    let c = publish(&storage, key(0x48), DEADLINE, &body(0x48));
    ticks(&storage, &[Some(1)]);
    let mut reader = storage.register().unwrap();
    let keys = [key(0x44), key(0x46), key(0x44), key(0x45)];
    let mut outputs: Vec<BatchSlot<'_, TestPlatform>> = (0..keys.len()).map(|_| None).collect();
    reader
        .lookup_batch(&keys, &mut outputs, RETRIES, &mut budget())
        .unwrap();
    assert!(matches!(outputs[1], Some(Err(LookupError::Missing))));
    assert_eq!(
        outputs.iter().filter(|o| matches!(o, Some(Ok(_)))).count(),
        3
    );
    assert!(visited(&storage, a) && visited(&storage, b));
    assert!(!visited(&storage, c));
    assert_eq!(refs(&storage, a), 3);
}

/// No production code outside the word module names the visited bit
/// except eviction's selection, which reads it and clears it, and the
/// extent's return, which clears it with every flag; the retain sets it
/// through the word's transition. Any new line that names it fails here
/// and must be judged.
#[test]
fn only_eviction_and_the_return_name_the_visited_bit() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/storage");
    let mut uses = Vec::new();
    let mut dirs = vec![std::path::PathBuf::from(dir)];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name.ends_with("_tests.rs") || name.ends_with("_model.rs") || name == "word.rs" {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let tests = source
                .find("#[cfg(test)]\nmod tests")
                .unwrap_or(source.len());
            for line in source[..tests].lines() {
                let code = line.split("//").next().unwrap().trim();
                if code.contains("VISITED") {
                    uses.push(format!("{name}: {code}"));
                }
            }
        }
    }
    uses.sort();
    assert_eq!(
        uses,
        [
            "evict.rs: 1 if current & VISITED != 0 => Visit::Clear,",
            "evict.rs: current & (ABANDONED | VISITED | RESERVED | STATE) == SlotState::Resident.bits()",
            "evict.rs: current & (ABANDONED | VISITED | RESERVED | STATE) == set && word::refs(current) == 1",
            "evict.rs: if candidate(current & !VISITED) && visits >= 2 && tables.queue().members_len() >= 2 {",
            "evict.rs: if current & VISITED != 0 {",
            "evict.rs: let set = SlotState::Resident.bits() | VISITED;",
            "evict.rs: record.ident.fetch_and(!VISITED, Ordering::Relaxed);",
            "evict.rs: record.ident.fetch_and(!VISITED, Ordering::Relaxed);",
            "evict.rs: record.ident.fetch_and(!VISITED, Ordering::Relaxed);",
            "evict.rs: use super::word::{self, ABANDONED, ANCHORED, RESERVED, STATE, VISITED};",
            "reserve.rs: !(FLAGS | VISITED | STATE | POLICY | MARKER),",
            "reserve.rs: use super::word::{self, FLAGS, INCARNATION, MARKER, POLICY, STATE, VISITED};",
        ]
    );
}
