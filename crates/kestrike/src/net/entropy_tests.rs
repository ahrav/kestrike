//! Supplied boot nonces at the endpoints' entropy draw. The nonce-taking
//! siblings of owner start, owner rekey and client initialize call their
//! supplier exactly where the public entry points read the operating
//! system's entropy, keep every refusal, returned bundle and charge, and
//! make the supplied nonce the endpoint's boot nonce.

use std::cell::Cell;

use crate::index::{KeyHasher, KeyRoute};
use crate::storage::owner_fixture::{Device, SimDisk, TestPlatform, arena, storage};
use crate::storage::{BufferArena, EngineBudget, Storage};

use super::auth::{EntropyError, KeyEntry, KeyError};
use super::client::{Client, ClientConfig, ClientError, ClientMemory};
use super::fetch::Releases;
use super::link::{Faults, LinkEnd, network};
use super::owner::{Bundle, Keys, Owner, OwnerConfig, OwnerError, OwnerRekeyError};
use super::owner_tests::{Mux, OWNER, PRINCIPALS, TestOwner, client_config, entries, key, pool};
use super::packet::PacketPool;
use super::requests::RequestTable;
use super::session::{Caps, RekeyError};

const NONCE: [u8; 16] = *b"supplied nonce 1";
const FRESH: [u8; 16] = *b"supplied nonce 2";
const UNAVAILABLE: EntropyError = EntropyError::Unavailable { code: 5 };

/// A supplier that answers `outcome`, writing its nonce on success, and
/// counts its calls in `calls`.
fn supplier(
    outcome: Result<[u8; 16], EntropyError>,
    calls: &Cell<u32>,
) -> impl FnOnce(&mut [u8; 16]) -> Result<(), EntropyError> + '_ {
    move |bytes| {
        calls.set(calls.get() + 1);
        *bytes = outcome?;
        Ok(())
    }
}

/// Two simulated peer links behind one transport.
fn ends<'a>() -> Mux<'a> {
    let (_, a, _) = network(4, 8384, 1, [Faults::default(); 2]);
    let (_, b, _) = network(4, 8384, 2, [Faults::default(); 2]);
    Mux::new(vec![a, b])
}

/// Both peers' keys at epoch 1, granting no PUT.
fn keys<'k>(entries: &'k [KeyEntry<'k>]) -> Keys<'k> {
    Keys {
        principals: &PRINCIPALS,
        entries,
        epoch: 1,
        put: &[],
    }
}

/// The parts an owner consumes, over `storage` and `buffers`.
fn bundle<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    buffers: &'a BufferArena<TestPlatform>,
) -> Bundle<'s, 'a, TestPlatform, SimDisk> {
    let Device { volume, .. } = Device::new(storage, buffers);
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    Bundle {
        cache,
        registration,
        volume,
    }
}

/// The keys whose routes name an owner index's placement.
const ROUTED: [u8; 4] = [1, 2, 3, 4];

/// An owner over a fresh stack whose index `hasher` keys, started with
/// `nonce` as its supplier: its boot nonce and the routes of the `ROUTED`
/// keys in its index, for the cross-process identity case.
pub(crate) fn owner_identity(
    nonce: impl FnOnce(&mut [u8; 16]) -> Result<(), EntropyError>,
    hasher: KeyHasher,
) -> ([u8; 16], [KeyRoute; ROUTED.len()]) {
    let receive = pool();
    let entries = entries();
    let mut storage = storage(8);
    storage.install_hasher(hasher);
    let routes = ROUTED.map(|n| storage.route(&key(n)).expect("an indexed storage routes"));
    let buffers = arena(8);
    let mut budget = EngineBudget::new(1 << 26);
    let owner = Owner::start_with_nonce(
        OWNER,
        bundle(&storage, &buffers),
        keys(&entries),
        ends(),
        &receive,
        &mut budget,
        nonce,
    )
    .map_err(|refused| refused.error)
    .unwrap();
    (owner.boot_nonce(), routes)
}

/// A `Caps` or `Batch` refusal before the nonce leaves the supplier
/// uncalled; a zero or unavailable nonce and a refused key set after the
/// draw each return the bundle with the budget unchanged; a start charges
/// what the public start charges and carries the supplied nonce.
#[test]
fn owner_start_draws_the_supplied_nonce_after_batch_and_before_keys() {
    let receive = pool();
    let entries = entries();
    let storage = storage(8);
    let buffers = arena(8);
    let mut bundle = bundle(&storage, &buffers);
    let cases = [
        (
            OwnerConfig { batch: 1, ..OWNER },
            &entries[..],
            Ok(NONCE),
            OwnerError::Batch,
            0,
        ),
        (
            OwnerConfig {
                caps: Caps {
                    slots: 0,
                    window: 4,
                },
                ..OWNER
            },
            &entries[..],
            Ok(NONCE),
            OwnerError::Caps,
            0,
        ),
        (
            OWNER,
            &entries[..],
            Ok([0; 16]),
            OwnerError::Entropy(EntropyError::Zero),
            1,
        ),
        (
            OWNER,
            &entries[..],
            Err(UNAVAILABLE),
            OwnerError::Entropy(UNAVAILABLE),
            1,
        ),
        (
            OWNER,
            &entries[..1],
            Ok(NONCE),
            OwnerError::Keys(KeyError::Missing {
                principal: PRINCIPALS[1],
            }),
            1,
        ),
    ];
    for (config, entries, outcome, error, draws) in cases {
        let calls = Cell::new(0);
        let mut budget = EngineBudget::new(1 << 26);
        let refused = Owner::start_with_nonce(
            config,
            bundle,
            keys(entries),
            ends(),
            &receive,
            &mut budget,
            supplier(outcome, &calls),
        )
        .err()
        .unwrap();
        assert_eq!(refused.error, error);
        assert_eq!(calls.get(), draws, "{error:?}");
        assert_eq!(budget.used(), 0, "{error:?}");
        bundle = refused.bundle;
    }
    let calls = Cell::new(0);
    let mut budget = EngineBudget::new(1 << 26);
    let started = Owner::start_with_nonce(
        OWNER,
        bundle,
        keys(&entries),
        ends(),
        &receive,
        &mut budget,
        supplier(Ok(NONCE), &calls),
    )
    .map_err(|refused| refused.error)
    .unwrap();
    assert_eq!((started.boot_nonce(), calls.get()), (NONCE, 1));
    let (other, charge) = public_start();
    assert_eq!(budget.used(), charge);
    assert_ne!(other, public_start().0, "each public start draws afresh");
    assert!(![[0; 16], NONCE, FRESH].contains(&other));
}

/// The boot nonce and the charge of an owner the public start starts over a
/// fresh stack.
fn public_start() -> ([u8; 16], usize) {
    let receive = pool();
    let entries = entries();
    let storage = storage(8);
    let buffers = arena(8);
    let mut budget = EngineBudget::new(1 << 26);
    let started = Owner::start(
        OWNER,
        bundle(&storage, &buffers),
        keys(&entries),
        ends(),
        &receive,
        &mut budget,
    )
    .map_err(|refused| refused.error)
    .unwrap();
    (started.boot_nonce(), budget.used())
}

/// The re-keyed entries at epoch 2.
const NEW_KEYS: [[u8; 32]; 2] = [[0x7E; 32], [0x7F; 32]];

fn new_entries() -> [KeyEntry<'static>; 2] {
    [
        KeyEntry {
            principal: PRINCIPALS[0],
            key: &NEW_KEYS[0],
        },
        KeyEntry {
            principal: PRINCIPALS[1],
            key: &NEW_KEYS[1],
        },
    ]
}

/// A rekey refused for a zero or unavailable nonce, or for its key set after
/// the draw, keeps the boot nonce, the key epoch, the volume and the census;
/// an accepted rekey carries the supplied nonce and the new epoch, and the
/// public rekey draws a fresh nonce from the operating system each time.
#[test]
fn owner_rekey_draws_before_its_keys_and_a_refusal_changes_nothing() {
    let receive = pool();
    let entries = entries();
    let storage = storage(8);
    let buffers = arena(8);
    let calls = Cell::new(0);
    let mut owner = Owner::start_with_nonce(
        OWNER,
        bundle(&storage, &buffers),
        keys(&entries),
        ends(),
        &receive,
        &mut EngineBudget::new(1 << 26),
        supplier(Ok(NONCE), &calls),
    )
    .map_err(|refused| refused.error)
    .unwrap();
    let state = |owner: &TestOwner<'_, '_, '_>| {
        (
            owner.boot_nonce(),
            owner.key_epoch(),
            owner.volume_report(),
            owner.census(),
        )
    };
    let before = state(&owner);
    let new = new_entries();
    let refusals = [
        (
            &new[..],
            Ok([0; 16]),
            OwnerRekeyError::Entropy(EntropyError::Zero),
        ),
        (
            &new[..],
            Err(UNAVAILABLE),
            OwnerRekeyError::Entropy(UNAVAILABLE),
        ),
        (
            &new[..1],
            Ok(FRESH),
            OwnerRekeyError::Rekey(RekeyError::Keys(KeyError::Missing {
                principal: PRINCIPALS[1],
            })),
        ),
    ];
    for (entries, outcome, error) in refusals {
        let calls = Cell::new(0);
        let refused = owner.rekey_with_nonce(entries, 2, 0, supplier(outcome, &calls));
        assert_eq!(refused, Err(error));
        assert_eq!(calls.get(), 1, "{error:?}");
        assert_eq!(state(&owner), before, "{error:?} changes nothing");
    }
    let calls = Cell::new(0);
    owner
        .rekey_with_nonce(&new, 2, 0, supplier(Ok(FRESH), &calls))
        .unwrap();
    assert_eq!(
        (owner.boot_nonce(), owner.key_epoch(), calls.get()),
        (FRESH, 2, 1)
    );
    owner.rekey(&entries, 3, 0).unwrap();
    let first = owner.boot_nonce();
    owner.rekey(&new, 4, 0).unwrap();
    assert_ne!(owner.boot_nonce(), first, "each public rekey draws afresh");
    assert!(![[0; 16], NONCE, FRESH].contains(&first));
}

/// Client memory over `receive` and `releases`.
fn memory<'m>(receive: &'m PacketPool<'m>, releases: &'m Releases) -> ClientMemory<'m> {
    ClientMemory {
        receive,
        releases,
        requests: RequestTable::new(4, 1, 4),
        sources: Box::default(),
        routes: super::client_tests::routes(),
    }
}

fn releases() -> Releases {
    Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap()
}

fn client_end<'m>() -> LinkEnd<'m> {
    network(64, 8384, 3, [Faults::default(); 2]).0
}

/// Every shape refusal leaves the supplier uncalled; a zero or unavailable
/// nonce and a refused key set after the draw each leave the budget
/// unchanged; an initialized client charges what the public initialize
/// charges and carries the supplied nonce.
#[test]
fn client_initialize_draws_the_supplied_nonce_after_its_shape_checks() {
    let receive = pool();
    let short = super::packet::test_pool(20, 8).unwrap();
    let releases = releases();
    let config = client_config(0);
    let own = [entries()[0]];
    let other = [entries()[1]];
    let cases: [(ClientConfig, _, &[KeyEntry<'_>], _, _, _); 6] = [
        (
            ClientConfig { batch: 0, ..config },
            &receive,
            &own,
            Ok(NONCE),
            ClientError::Batch,
            0,
        ),
        (
            ClientConfig {
                caps: Caps {
                    slots: 0,
                    window: 4,
                },
                ..config
            },
            &receive,
            &own,
            Ok(NONCE),
            ClientError::Caps,
            0,
        ),
        (config, &short, &own, Ok(NONCE), ClientError::Pool, 0),
        (
            config,
            &receive,
            &own,
            Ok([0; 16]),
            ClientError::Entropy(EntropyError::Zero),
            1,
        ),
        (
            config,
            &receive,
            &own,
            Err(UNAVAILABLE),
            ClientError::Entropy(UNAVAILABLE),
            1,
        ),
        (
            config,
            &receive,
            &other,
            Ok(NONCE),
            ClientError::Keys(KeyError::Unknown {
                principal: PRINCIPALS[1],
            }),
            1,
        ),
    ];
    for (config, pool, keys, outcome, error, draws) in cases {
        let calls = Cell::new(0);
        let mut budget = EngineBudget::new(1 << 24);
        let refused = Client::initialize_with_nonce(
            config,
            memory(pool, &releases),
            client_end(),
            keys,
            1,
            &mut budget,
            supplier(outcome, &calls),
        );
        assert_eq!(refused.err(), Some(error));
        assert_eq!(calls.get(), draws, "{error:?}");
        assert_eq!(budget.used(), 0, "{error:?}");
    }
    let calls = Cell::new(0);
    let mut budget = EngineBudget::new(1 << 24);
    let client = Client::initialize_with_nonce(
        config,
        memory(&receive, &releases),
        client_end(),
        &own,
        1,
        &mut budget,
        supplier(Ok(NONCE), &calls),
    )
    .unwrap();
    assert_eq!((client.boot_nonce(), calls.get()), (NONCE, 1));
    let (other, charge) = public_initialize();
    assert_eq!(budget.used(), charge);
    assert_ne!(
        other,
        public_initialize().0,
        "each public initialize draws afresh"
    );
    assert!(![[0; 16], NONCE, FRESH].contains(&other));
}

/// The boot nonce and the charge of a client the public initialize builds
/// over fresh memory.
fn public_initialize() -> ([u8; 16], usize) {
    let (receive, releases) = (pool(), releases());
    let mut budget = EngineBudget::new(1 << 24);
    let client = Client::initialize(
        client_config(0),
        memory(&receive, &releases),
        client_end(),
        &[entries()[0]],
        1,
        &mut budget,
    )
    .unwrap();
    (client.boot_nonce(), budget.used())
}

/// The boot nonce of a client initialized over fresh memory with `nonce` as
/// its supplier, for the cross-process identity case.
pub(crate) fn client_nonce(
    nonce: impl FnOnce(&mut [u8; 16]) -> Result<(), EntropyError>,
) -> [u8; 16] {
    let (receive, releases) = (pool(), releases());
    Client::initialize_with_nonce(
        client_config(0),
        memory(&receive, &releases),
        client_end(),
        &[entries()[0]],
        1,
        &mut EngineBudget::new(1 << 24),
        nonce,
    )
    .unwrap()
    .boot_nonce()
}
