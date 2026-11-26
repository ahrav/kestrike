//! A stale attempt's record over a unit the index names misses on every explored seed, with each stale arm refused by its own `HeaderMismatch`, and the observer lens expects the slot's session and cache version.

use std::sync::atomic::Ordering;

use super::super::CacheVersion;
use super::super::budget::WorkBudget;
use super::super::publish_tests::{TRIES, key};
use super::super::record::{Crc32c, HeaderMismatch, RecordIdentity, claim_header};
use super::super::seeded::SplitMix64;
use super::super::volume_fixture::{Device, TestVolume, arena_with, drive, identity_bytes, place};
use super::super::writable_tests::reserve_at;
use super::ReadStatus;
use super::journal_tests::storage_with;

const VERSION: u64 = 0x000B_1EC7;
const METADATA: [u8; 4] = *b"meta";

fn stale(identity: RecordIdentity, rng: &mut SplitMix64) -> [(RecordIdentity, HeaderMismatch); 7] {
    let session = identity.session;
    let mut key = identity.key;
    key[rng.below(32) as usize] ^= 1 << rng.below(8);
    let sessions = [
        session - 2,
        session + 2 * (1 + rng.below(8)),
        session - 1,
        session ^ (1 << (32 + rng.below(31))),
    ];
    let allocation = identity.allocation - 1;
    let version = identity.version + 1 + rng.below(1 << 20);
    let [earlier, later, odd, foreign] = sessions.map(|found| {
        (
            RecordIdentity {
                session: found,
                ..identity
            },
            HeaderMismatch::Session {
                expected: session,
                found,
            },
        )
    });
    [
        (RecordIdentity { key, ..identity }, HeaderMismatch::Key),
        (
            RecordIdentity {
                allocation,
                ..identity
            },
            HeaderMismatch::Allocation {
                expected: identity.allocation,
                found: allocation,
            },
        ),
        earlier,
        later,
        odd,
        foreign,
        (
            RecordIdentity {
                version,
                ..identity
            },
            HeaderMismatch::CacheVersion {
                expected: identity.version,
                found: version,
            },
        ),
    ]
}

#[test]
fn stale_attempt_over_named_unit_misses() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let _ = crate::storage::next_session();
    let mut dev = Device::new(&storage, &buffers);
    let body = vec![0xC4; 150];
    let payload = [&METADATA[..], &body].concat();
    let object = key(7);
    let mut fill = reserve_at(
        &storage,
        &object,
        CacheVersion(VERSION),
        METADATA.len(),
        body.len(),
    )
    .expect("a reservation");
    dev.fill(&mut fill, &payload);
    let lease = fill
        .publish(
            &mut dev.volume,
            u64::MAX,
            TRIES,
            &mut WorkBudget::new(1 << 20),
        )
        .expect("published");
    let pool = storage.live_pool().expect("a live pool");
    let slot = lease.id().slot_index();
    let read = TestVolume::request(pool, lease.id(), &object);
    let named = RecordIdentity {
        key: object,
        allocation: read.allocation,
        session: read.session,
        version: read.version,
    };
    let reader = dev.volume.session();
    assert_eq!((named.session, named.version), (reader, VERSION));
    assert!(reader & 0xFFFF_FFFF >= 4);
    let op = dev.volume.read_raw(&read, u64::MAX).expect("a read");
    assert_eq!(drive(&mut dev.volume, &dev.control, op).bytes, payload);
    let mut rng = SplitMix64::new(0x5_7A1E);
    for seed in 0..16 {
        for (arm, (attempt, refusal)) in stale(named, &mut rng).iter().enumerate() {
            let bytes = identity_bytes(&storage, attempt, &METADATA, &body);
            // Every crc the stale record carries verifies, so a reader that served on a crc match alone would expose it.
            let claimed =
                claim_header(Crc32c::detect(), &storage.record, &bytes).expect("a whole record");
            assert_eq!(claimed.identity, *attempt, "seed {seed} arm {arm}");
            place(&storage, &dev.control, read.locator, &bytes);
            let op = dev.volume.read_raw(&read, u64::MAX).expect("a read");
            let delivered = drive(&mut dev.volume, &dev.control, op);
            assert_eq!(
                delivered.status,
                ReadStatus::HeaderMismatch(*refusal),
                "seed {seed} arm {arm}"
            );
            assert!(delivered.bytes.is_empty(), "seed {seed} arm {arm}");
        }
    }
    let foreign = [
        reader ^ 1 << 40,
        reader + 2,
        reader - 1,
        reader & !0xFFFF_FFFF,
    ];
    for session in foreign {
        pool.generations()[slot].store(session, Ordering::Relaxed);
        let read = TestVolume::request(pool, lease.id(), &object);
        let written = RecordIdentity { session, ..named };
        place(
            &storage,
            &dev.control,
            read.locator,
            &identity_bytes(&storage, &written, &METADATA, &body),
        );
        let op = dev.volume.read_raw(&read, u64::MAX).expect("a read");
        let delivered = drive(&mut dev.volume, &dev.control, op);
        assert_eq!(
            delivered.status,
            ReadStatus::HeaderMismatch(HeaderMismatch::ForeignSession {
                found: session,
                reader
            }),
            "session {session:#x}"
        );
        assert!(delivered.bytes.is_empty(), "session {session:#x}");
    }
    let earlier = reader - 2;
    pool.generations()[slot].store(earlier, Ordering::Relaxed);
    let read = TestVolume::request(pool, lease.id(), &object);
    let written = RecordIdentity {
        session: earlier,
        ..named
    };
    place(
        &storage,
        &dev.control,
        read.locator,
        &identity_bytes(&storage, &written, &METADATA, &body),
    );
    let op = dev.volume.read_raw(&read, u64::MAX).expect("a read");
    assert_eq!(drive(&mut dev.volume, &dev.control, op).bytes, payload);
    pool.generations()[slot].store(reader, Ordering::Relaxed);
}

#[test]
fn the_observer_lens_expects_the_slot_s_session_and_cache_version() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let _ = crate::storage::next_session();
    let mut dev = Device::new(&storage, &buffers);
    let body = vec![0x5A; 150];
    let payload = [&METADATA[..], &body].concat();
    let object = key(9);
    let mut fill = reserve_at(
        &storage,
        &object,
        CacheVersion(VERSION),
        METADATA.len(),
        body.len(),
    )
    .expect("a reservation");
    dev.fill(&mut fill, &payload);
    let lease = fill
        .publish(
            &mut dev.volume,
            u64::MAX,
            TRIES,
            &mut WorkBudget::new(1 << 20),
        )
        .expect("published");
    let pool = storage.live_pool().expect("a live pool");
    let slot = lease.id().slot_index();
    let allocation = lease.id().record_tag();
    let reader = dev.volume.session();
    let lens = |media: &[u8]| {
        let mut facts = Vec::new();
        storage.slot_facts_into(&mut facts).expect("live");
        storage
            .record_payload(media, allocation, &facts[slot], reader)
            .map(|(key, metadata, bytes)| (key, metadata, bytes.to_vec()))
    };
    let mut facts = Vec::new();
    storage.slot_facts_into(&mut facts).expect("live");
    let mut media = Vec::new();
    assert!(
        dev.control
            .try_device_into(facts[slot].media().expect("a range"), &mut media)
    );
    let served = Some((object, METADATA.len() as u32, payload.clone()));
    assert_eq!(lens(&media), served);
    pool.versions()[slot].store(VERSION + 1, Ordering::Relaxed);
    assert_eq!(lens(&media), None);
    pool.versions()[slot].store(VERSION, Ordering::Relaxed);
    let earlier = reader - 2;
    pool.generations()[slot].store(earlier, Ordering::Relaxed);
    assert_eq!(lens(&media), None);
    let written = RecordIdentity {
        key: object,
        allocation,
        session: earlier,
        version: VERSION,
    };
    let restored = identity_bytes(&storage, &written, &METADATA, &body);
    assert_eq!(restored.len(), media.len());
    assert_eq!(lens(&restored), served);
    pool.generations()[slot].store(reader, Ordering::Relaxed);
}
