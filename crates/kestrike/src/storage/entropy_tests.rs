//! Fixed index keys: a key pair installed after construction routes every
//! key as any hasher under the same pair does, the storage keeps that state
//! while it publishes and looks keys up, and an index that holds a key
//! refuses a new state.

use super::owner::Storage;
use super::publish_tests::{TRIES, budget, candidates, completed, index_config, key, storage};
use super::test_platform::TestPlatform;
use crate::index::{Key, KeyHasher, KeyRoute, Prefetch};

const LIMITS: [usize; 2] = [8, 8];
const SLOTS: usize = 24;
const PAIR: (u64, u64) = (0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210);

fn keys() -> impl Iterator<Item = Key> {
    (1..=8u8).map(key)
}

/// A two-shard indexed storage keyed by `hasher`.
fn keyed(hasher: KeyHasher) -> Storage<TestPlatform> {
    let mut storage = storage(SLOTS, &index_config(&LIMITS, (1, 1), 1));
    storage.install_hasher(hasher);
    storage
}

fn routes(storage: &Storage<TestPlatform>) -> Vec<KeyRoute> {
    keys()
        .map(|key| storage.route(&key).expect("an indexed storage routes"))
        .collect()
}

/// A storage keyed by a fixed pair routes every key as a hasher built apart
/// from it with the same pair does; another pair changes the placement.
#[test]
fn a_fixed_key_pair_routes_alike_on_every_storage() {
    let storage = keyed(KeyHasher::with_key_pair(PAIR.0, PAIR.1));
    let geometry = storage.index_geometry().unwrap();
    let apart = KeyHasher::with_key_pair(PAIR.0, PAIR.1);
    let expected: Vec<KeyRoute> = keys()
        .map(|key| apart.route_unpaid(&key, geometry, Prefetch::NONE).unwrap())
        .collect();
    assert_eq!(routes(&storage), expected);
    let other = keyed(KeyHasher::with_key_pair(PAIR.0, PAIR.1 ^ 1));
    assert_ne!(routes(&other), expected, "the placement follows the pair");
}

/// Publishing every key and looking each one up leaves the installed state
/// where it was: each key finds exactly its own object, and every route
/// after the run equals the route before it.
#[test]
fn the_installed_state_holds_while_the_storage_publishes_and_looks_up() {
    let storage = keyed(KeyHasher::with_key_pair(PAIR.0, PAIR.1));
    let before = routes(&storage);
    let published: Vec<_> = keys()
        .map(|key| {
            completed(&storage, key)
                .publish(TRIES, &mut budget())
                .unwrap()
        })
        .collect();
    for (key, id) in keys().zip(published) {
        assert_eq!(candidates(&storage, &key), [id]);
    }
    assert_eq!(routes(&storage), before);
}

/// An index holding a published key refuses a new hasher, which would
/// misplace every key the earlier state placed.
#[test]
#[should_panic(expected = "a hasher is installed only into an empty index")]
fn an_index_holding_a_key_refuses_a_new_hasher() {
    let mut storage = keyed(KeyHasher::with_key_pair(PAIR.0, PAIR.1));
    completed(&storage, key(1))
        .publish(TRIES, &mut budget())
        .unwrap();
    storage.install_hasher(KeyHasher::with_key_pair(PAIR.1, PAIR.0));
}
