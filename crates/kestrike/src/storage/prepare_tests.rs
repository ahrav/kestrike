//! Lookup preparation against independent expectations: each entry owns the
//! key and ordinal it was derived for and serves no other, a reset or a new
//! window discards every earlier entry, a route cut from a group's word
//! equals the scalar route at every window width on every multi-key
//! mechanism this CPU runs, only full groups run the vector pass, and each
//! stage of the lookahead hints its lines at its own distance ahead of the
//! lookup.

use std::sync::atomic::{AtomicU64, Ordering};

use super::batch_tests::{key, publish, ready};
use super::budget::WorkBudget;
use super::lookup::LookupError;
use super::owner::Storage;
use super::prefetch::READ_HINTS;
use super::prepare::{DEPTH, PEEK, Preparation, SLOTS, STAGE};
use super::publish_tests::{RETRIES, index_config, install_seam, spread, storage};
use super::test_platform::TestPlatform;
use crate::index::{
    Bucket, DERIVATIONS, Identity, Key, KeyHasher, LANES, Lanes, SCALAR_PASSES, VECTOR_PASSES,
    excludes, summary_bits,
};

/// A deadline 100 seconds into the engine's nanosecond timeline.
const DEADLINE: u64 = 100 * 1_000_000_000;

fn generous() -> WorkBudget {
    WorkBudget::new(if cfg!(miri) { 4096 } else { 1024 })
}

/// An entry serves only the ordinal and the key it was derived for, and
/// owns its key. Under the spreading seam `A` and `B` have distinct
/// buckets and fingerprints, and `B` is absent, so `A`'s route consumed for
/// `B` would search `A`'s chain for `A`'s fingerprint and return a lease on
/// `A`'s object: the test witnesses that hazard first. Then an entry keeps
/// the key it was derived for after the caller rewrites its buffer; `B`
/// asked for at `A`'s entry gets no route and its literal `Missing`; an
/// ordinal other than the entry's, including one on the same ring
/// position, takes nothing and leaves the entry for its own ordinal; a
/// reset empties the ring; and a new window at the same ordinal serves
/// `B`'s own route and `B`'s literal `Missing`.
#[test]
fn an_entry_serves_only_its_own_ordinal_and_key() {
    let storage = ready();
    storage.platform.ticks(&[Some(1)]);
    let (a, b) = (key(0x31), key(0x32));
    let id = publish(&storage, a, DEADLINE, &[0x31; 24]);
    let route_a = storage.route(&a).unwrap();
    let route_b = storage.route(&b).unwrap();
    assert_ne!(route_a.fingerprint(), route_b.fingerprint());
    let mut reader = storage.register().unwrap();

    // The enabling state: `A`'s route carried into `B`'s lookup finds `A`.
    let wrong = reader
        .lookup_routed(&b, Some(route_a), RETRIES, &mut generous())
        .unwrap();
    assert_eq!(wrong.id(), id);
    drop(wrong);

    let mut preparation = Preparation::new(&storage);

    // The window's keys are copied at derivation: the caller's buffer is
    // rewritten after the call, and the entry still names `A`.
    let mut window: Vec<Key> = vec![a, b];
    preparation.prime(&window, 0);
    window[0] = b;
    window[1] = a;
    let prepared = preparation.take(0, &a);
    assert_eq!(prepared.route(), Some(route_a));
    let lease = reader
        .lookup_prepared(&prepared, RETRIES, &mut generous())
        .unwrap();
    assert_eq!((lease.id(), *lease.key()), (id, a));
    drop(lease);
    // Ordinal 1's entry was derived for `B`, its key at the time.
    assert_eq!(preparation.take(1, &b).route(), Some(route_b));

    // A key other than the entry's discards the entry; the context carries
    // the key asked for and no route.
    preparation.prime(&[a], 0);
    let substituted = preparation.take(0, &b);
    assert_eq!(substituted.route(), None);
    assert_eq!(
        reader
            .lookup_prepared(&substituted, RETRIES, &mut generous())
            .err(),
        Some(LookupError::Missing)
    );
    assert_eq!(preparation.take(0, &a).route(), None);

    // A context taken for `A` serves only `A`: asked for `B` it yields
    // nothing, so `B`'s lookup is `B`'s own.
    preparation.prime(&[a], 0);
    let taken = preparation.take(0, &a);
    let scalar = preparation.scalar(&b);
    let context = taken.for_key(&b).unwrap_or(&scalar);
    assert_eq!(context.route(), None);
    assert_eq!(
        reader
            .lookup_prepared(context, RETRIES, &mut generous())
            .err(),
        Some(LookupError::Missing)
    );
    preparation.prime(&[a], 0);
    let taken = preparation.take(0, &a);
    assert_eq!(
        taken.for_key(&a).and_then(|taken| taken.route()),
        Some(route_a)
    );

    // Another ordinal, even one on the entry's ring position, leaves the
    // entry in place for its own.
    preparation.prime(&[a], 5);
    assert_eq!(preparation.take(0, &a).route(), None);
    assert_eq!(preparation.take(5 + SLOTS, &a).route(), None);
    assert_eq!(preparation.take(5, &a).route(), Some(route_a));

    // A reset discards every entry.
    preparation.prime(&[a], 0);
    preparation.reset();
    assert_eq!(preparation.take(0, &a).route(), None);

    // A new window replaces the old one at the same ordinal: `B`'s entry is
    // `B`'s, and `B`'s lookup is `B`'s validation.
    preparation.prime(&[a], 0);
    preparation.prime(&[b], 0);
    let fresh = preparation.take(0, &b);
    assert_eq!(fresh.route(), Some(route_b));
    assert_eq!(
        reader
            .lookup_prepared(&fresh, RETRIES, &mut generous())
            .err(),
        Some(LookupError::Missing)
    );
    assert_eq!(storage.lease_report().unwrap().reserved, 0);
}

/// A context prepared on another storage holds that storage's route for its
/// key; this storage's lookup drops the route, derives the key's own and
/// acquires the key's object. The other storage's seam flips bit 4 of the
/// key's word, which in this four-bucket shard keeps the key's bucket and
/// changes its fingerprint and tag, so its route followed here reports
/// `Missing`.
#[test]
fn a_foreign_context_routes_itself() {
    let storage = ready();
    let mut other = ready();
    install_seam(&mut other, |key| spread(key) ^ 0x10);
    storage.platform.ticks(&[Some(1)]);
    let a = key(0x41);
    let id = publish(&storage, a, DEADLINE, &[0x41; 24]);
    let mut foreign = Preparation::new(&other);
    foreign.prime(&[a], 0);
    let prepared = foreign.take(0, &a);
    assert!(prepared.route().is_some());
    assert_ne!(prepared.route(), storage.route(&a));
    let mut reader = storage.register().unwrap();
    // The enabling state: the foreign route followed here misses.
    assert_eq!(
        reader
            .lookup_routed(&a, prepared.route(), RETRIES, &mut generous())
            .err(),
        Some(LookupError::Missing)
    );
    let derivations = DERIVATIONS.with(std::cell::Cell::get);
    let lease = reader
        .lookup_prepared(&prepared, RETRIES, &mut generous())
        .unwrap();
    assert_eq!((lease.id(), *lease.key()), (id, a));
    // The lookup derived the key's own route.
    assert_eq!(DERIVATIONS.with(std::cell::Cell::get) - derivations, 1);
}

/// An indexed storage hashing with the keyed rounds of a fixed pair on the
/// multi-key mechanism `lanes`.
fn keyed(lanes: Lanes) -> Storage<TestPlatform> {
    let limits = [16usize, 16];
    let mut storage = storage(32, &index_config(&limits, (1, 1), 1));
    storage.install_hasher(
        KeyHasher::with_key_pair(0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908).with_lanes(lanes),
    );
    storage
}

/// Seventeen keys, each nonzero in its own bytes, with positions 3 and 11
/// repeating position 0's key and position 16 repeating position 8's, so a
/// repeated key inside a group and across groups is hashed in place.
fn window() -> Vec<Key> {
    let mut keys: Vec<Key> = (0..17u8)
        .map(|n| {
            let mut key = [0u8; 32];
            key[usize::from(n) % 32] = 0x80 | n;
            key[31 - usize::from(n) % 32] ^= n.wrapping_mul(37);
            key
        })
        .collect();
    keys[3] = keys[0];
    keys[11] = keys[0];
    keys[16] = keys[8];
    keys
}

/// Every route the preparation derives equals the scalar route of its own
/// key, at window widths 0 through 8 and at the group boundaries 9, 15, 16
/// and 17, on every multi-key mechanism this CPU runs. The AVX-512
/// mechanism runs one vector pass per full group of eight and one scalar
/// pass per key of a shorter final group; the scalar mechanism hashes each
/// key through its own route derivation, outside the multi-key passes, so
/// it runs neither pass. Each key is derived once.
#[test]
fn every_route_matches_the_scalar_route_at_every_width() {
    use std::cell::Cell;
    let keys = window();
    let mechanisms = Lanes::available();
    for lanes in &mechanisms {
        let storage = keyed(*lanes);
        let mut preparation = Preparation::new(&storage);
        for width in (0..=LANES).chain([9, 15, 16, 17]) {
            let keys = &keys[..width];
            let expected: Vec<_> = keys.iter().map(|key| storage.route(key).unwrap()).collect();
            let derivations = DERIVATIONS.with(Cell::get);
            let vector = VECTOR_PASSES.with(Cell::get);
            let scalar = SCALAR_PASSES.with(Cell::get);
            preparation.prime(keys, 0);
            for (i, key) in keys.iter().enumerate() {
                let prepared = preparation.take(i, key);
                assert_eq!(prepared.route(), Some(expected[i]), "{lanes:?} {width} {i}");
                preparation.advance(keys, i);
            }
            assert_eq!(
                DERIVATIONS.with(Cell::get) - derivations,
                width,
                "{lanes:?} {width}"
            );
            let (full, tail) = if lanes.width() == LANES {
                (width / LANES, width % LANES)
            } else {
                (0, 0)
            };
            assert_eq!(
                VECTOR_PASSES.with(Cell::get) - vector,
                full,
                "{lanes:?} {width}"
            );
            assert_eq!(
                SCALAR_PASSES.with(Cell::get) - scalar,
                tail,
                "{lanes:?} {width}"
            );
        }
    }
    if mechanisms.iter().all(|lanes| lanes.width() == 1) {
        eprintln!("vector pass unreached: this CPU runs the scalar mechanism alone");
    }
}

/// A window wider than the ring keeps each entry for its own position: a
/// group resolved ahead fills only ring positions whose entries were
/// already taken, never one still waiting.
#[test]
fn a_window_wider_than_the_ring_keeps_every_entry_for_its_position() {
    let storage = ready();
    let keys: Vec<Key> = (0..(2 * DEPTH + 3) as u8).map(|n| key(0x50 + n)).collect();
    let mut preparation = Preparation::new(&storage);
    preparation.prime(&keys, 0);
    for (i, key) in keys.iter().enumerate() {
        assert_eq!(preparation.take(i, key).route(), storage.route(key), "{i}");
        preparation.advance(&keys, i);
    }
    // The window is spent: nothing remains to take.
    for (i, key) in keys.iter().enumerate() {
        assert_eq!(preparation.take(i, key).route(), None, "{i}");
    }
}

/// An entry's key and route come from the same bytes. With a lane width of
/// eight, the second group of a sixteen-key window is hashed while position
/// 8 is derived; the caller then rewrites position 9 before the call that
/// derives it. Its entry keeps the key the group hashed, so asking for the
/// rewritten key at ordinal 9 yields no route, never the old key's route,
/// and asking for the hashed key yields that key's own route. A mechanism
/// that hashes one key per derivation derives position 9 from the rewritten
/// key, whose own route the entry then carries.
#[test]
fn a_key_rewritten_inside_a_hashed_group_never_takes_the_old_route() {
    let mut keys = window();
    keys.truncate(16);
    let original = keys[9];
    let rewritten = key(0xEE);
    for lanes in Lanes::available() {
        let storage = keyed(lanes);
        let mut window = keys.clone();
        let mut preparation = Preparation::new(&storage);
        preparation.prime(&window, 0);
        assert_eq!(
            preparation.take(0, &window[0]).route(),
            storage.route(&window[0])
        );
        preparation.advance(&window, 0);
        window[9] = rewritten;
        assert_eq!(
            preparation.take(1, &window[1]).route(),
            storage.route(&window[1])
        );
        preparation.advance(&window, 1);
        let old = storage.route(&original);
        let asked = preparation.take(9, &rewritten).route();
        assert_ne!(asked, old, "{lanes:?}");
        if lanes.width() == LANES {
            assert_eq!(asked, None, "{lanes:?}");
            let mut again = Preparation::new(&storage);
            again.prime(&keys, 0);
            again.take(0, &keys[0]);
            again.advance(&keys, 0);
            window = keys.clone();
            window[9] = rewritten;
            again.take(1, &keys[1]);
            again.advance(&window, 1);
            assert_eq!(again.take(9, &original).route(), old, "{lanes:?}");
        } else {
            assert_eq!(asked, storage.route(&rewritten), "{lanes:?}");
        }
    }
    if Lanes::available().iter().all(|lanes| lanes.width() == 1) {
        eprintln!("group path unreached: this CPU runs the scalar mechanism alone");
    }
}

/// An index with every shard disabled gives no key a route, so the window
/// keeps no entry and hashes nothing on any mechanism.
#[test]
fn a_window_over_disabled_shards_hashes_nothing() {
    use std::cell::Cell;
    let keys = window();
    for lanes in Lanes::available() {
        let mut storage = storage(32, &index_config(&[0], (1, 1), 1));
        storage.install_hasher(KeyHasher::with_key_pair(1, 2).with_lanes(lanes));
        let mut preparation = Preparation::new(&storage);
        let derivations = DERIVATIONS.with(Cell::get);
        preparation.prime(&keys, 0);
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(preparation.take(i, key).route(), None, "{lanes:?} {i}");
            preparation.advance(&keys, i);
        }
        assert_eq!(DERIVATIONS.with(Cell::get) - derivations, 0, "{lanes:?}");
    }
}

/// Each summary is hinted when the lookahead reaches its own position,
/// `DEPTH` positions ahead of its lookup, never earlier with its group. The
/// index is empty, so every summary excludes its key and staging hints
/// nothing: priming hints the first `DEPTH` summaries and each advance
/// hints one more until the window ends. A group that hinted every summary
/// it resolved would hint eight at once.
#[test]
fn each_summary_is_hinted_depth_positions_ahead() {
    let keys = window();
    let hints = || READ_HINTS.with(|count| count.replace(0));
    for lanes in Lanes::available() {
        let storage = keyed(lanes);
        let mut preparation = Preparation::new(&storage);
        hints();
        preparation.prime(&keys, 0);
        assert_eq!(hints(), DEPTH, "{lanes:?}");
        for (i, key) in keys.iter().enumerate() {
            preparation.take(i, key);
            preparation.advance(&keys, i);
            assert_eq!(
                hints(),
                usize::from(i + DEPTH < keys.len()),
                "{lanes:?} {i}"
            );
        }
    }
}

/// Keys in the windows of the record-hint tests: wider than `DEPTH`, so
/// the windows hold positions derived by the priming and by an advance.
const WIDTH: usize = DEPTH + 4;

/// Read hints one staged route takes when its summary admits its tag: both
/// lines of its base bucket, then the generation line and the version line
/// of each end of its placement window.
const SEARCH_READS: usize = 2 + 2 + 2;

/// `key`'s base bucket and chain summary in `storage`'s index.
fn search_start<'s>(storage: &'s Storage<TestPlatform>, key: &Key) -> (&'s Bucket, &'s AtomicU64) {
    let route = storage.route(key).unwrap();
    let index = storage.index().unwrap();
    let shard = index.image.shard(route.shard()).unwrap();
    // SAFETY: the index mapping is live for the storage's borrow, and every
    // shared field is an atomic.
    let (buckets, summaries) = unsafe {
        (
            shard.buckets(&index.mapping),
            shard.summaries(&index.mapping),
        )
    };
    (&buckets[route.bucket()], &summaries[route.bucket()])
}

/// A window of [`WIDTH`] keys with `key` at position `at` and, at every
/// other position, a key whose chain summary excludes its tag, so the
/// lookahead stages no route but `key`'s.
fn window_with(storage: &Storage<TestPlatform>, key: Key, at: usize) -> Vec<Key> {
    let mut keys: Vec<Key> = (0..WIDTH as u8).map(|n| self::key(0x50 + n)).collect();
    keys[at] = key;
    for (position, other) in keys.iter().enumerate() {
        let summary = search_start(storage, other).1.load(Ordering::Relaxed);
        let tag = storage.route(other).unwrap().tag();
        assert!(
            position == at || excludes(summary, tag),
            "position {position}'s summary admits its tag"
        );
    }
    keys
}

/// The read hints of one window's lookahead over `storage` with no lookup
/// run: the priming's count, then the count of each position's take and
/// advance.
fn lookahead_read_hints(storage: &Storage<TestPlatform>, keys: &[Key]) -> (usize, Vec<usize>) {
    let hints = || READ_HINTS.with(|count| count.replace(0));
    let mut preparation = Preparation::new(storage);
    hints();
    preparation.prime(keys, 0);
    let primed = hints();
    let steps = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            preparation.take(i, key);
            preparation.advance(keys, i);
            hints()
        })
        .collect();
    (primed, steps)
}

/// The read hints the module documentation gives a [`WIDTH`]-key window in
/// which position `admitted` alone, or none, has a summary that admits its
/// tag, in the shape [`lookahead_read_hints`] returns. The priming hints
/// the first `DEPTH` summaries and stages the first `STAGE` positions.
/// Position `i`'s advance hints the summary of position `i + DEPTH`;
/// position 1's stages positions `STAGE` and `STAGE + 1` and each later
/// one's position `i + STAGE`; and from position 1 on, when `record` says
/// the admitted position's base bucket names a record of the pool, the
/// advance `PEEK` positions before it hints that record's line.
fn expected_read_hints(admitted: Option<usize>, record: bool) -> (usize, Vec<usize>) {
    let search = |staged: bool| if staged { SEARCH_READS } else { 0 };
    let primed = DEPTH + search(admitted.is_some_and(|at| at < STAGE));
    let steps = (0..WIDTH)
        .map(|i| {
            let derived = i + DEPTH < WIDTH;
            let staged = admitted.is_some_and(|at| at >= STAGE && i == (at - STAGE).max(1));
            let peeked = record && i >= 1 && admitted == Some(i + PEEK);
            usize::from(derived) + search(staged) + usize::from(peeked)
        })
        .collect();
    (primed, steps)
}

/// A published key's record line is hinted once, by the advance `PEEK`
/// positions before the key's own. One key is published and placed at each
/// position of a window of absent keys in turn, and the read hints of the
/// priming and of every advance are compared with the documented schedule,
/// so the counts fix the one advance that issues the record hint. The first
/// record hint is position `PEEK + 1`'s, issued by position 1's advance:
/// position 0's advance derives one route and reads nothing else.
#[test]
fn a_published_keys_record_is_hinted_once_peek_positions_ahead() {
    let storage = ready();
    storage.platform.ticks(&[Some(1)]);
    let present = key(0x41);
    publish(&storage, present, DEADLINE, &[0x41; 24]);
    for at in 0..WIDTH {
        let keys = window_with(&storage, present, at);
        assert_eq!(
            lookahead_read_hints(&storage, &keys),
            expected_read_hints(Some(at), true),
            "position {at}"
        );
    }
}

/// The record hint goes to a key whose summary admits its tag and whose
/// base bucket holds a pair that carries the tag and names a slot below the
/// pool's slot count. Each storage holds one forged base bucket, so each
/// case is one state. Under an admitting summary, an empty bucket takes the
/// staging's hints alone, a pair naming the pool's last slot adds the
/// record hint, and a pair naming the slot count or the largest slot a pair
/// can hold takes the staging's hints alone, so every record address the
/// lookahead forms lies inside the pool. Under a summary that excludes the
/// tag, a pair naming the last slot takes the summary hint alone. The
/// lookahead is the only reader of the forged tables.
#[test]
fn a_record_hint_needs_an_admitted_pair_naming_a_slot_of_the_pool() {
    let at = STAGE + 2;
    let forged = key(0x41);
    let count = ready().live_pool().unwrap().descriptor().slot_count;
    let last = u32::try_from(count).unwrap() - 1;
    let hints_with = |admits: bool, slot: Option<u32>| {
        let storage = ready();
        let tag = storage.route(&forged).unwrap().tag();
        let (bucket, summary) = search_start(&storage, &forged);
        if admits {
            summary.store(summary_bits(tag), Ordering::Relaxed);
        }
        if let Some(slot) = slot {
            let planted = bucket.plant(Identity {
                tag,
                incarnation_low: 1,
                slot,
            });
            assert_eq!(planted, Some(0));
        }
        lookahead_read_hints(&storage, &window_with(&storage, forged, at))
    };
    let admitted = Some(at);
    assert_eq!(hints_with(true, None), expected_read_hints(admitted, false));
    assert_eq!(
        hints_with(true, Some(last)),
        expected_read_hints(admitted, true)
    );
    assert_eq!(
        hints_with(true, Some(last + 1)),
        expected_read_hints(admitted, false)
    );
    assert_eq!(
        hints_with(true, Some(u32::MAX)),
        expected_read_hints(admitted, false)
    );
    assert_eq!(
        hints_with(false, Some(last)),
        expected_read_hints(None, false)
    );
}
