//! Each slot's record generation: reads expect it as the header session, the restored install (one lane over every slot, composed from the lane install and fold the warm bootstrap uses) writes a historical one with the recovered-origin marker and admits only the sessions the read predicate admits, and a return clears the slot's column, version and step.

use std::rc::Rc;
use std::sync::atomic::Ordering;

use super::super::allocation::AllocationId;
use super::super::device::sim::{Media, media};
use super::super::extent::ExtentLocator;
use super::super::owner::Pool;
use super::super::portable::PortableExpiry;
use super::super::publish_tests::key;
use super::super::record::HeaderMismatch;
use super::super::reserve::{RestoreRefusal, Restored};
use super::super::tables::{SlotIndex, SlotState, Tables};
use super::super::volume_fixture::{
    Device, MEDIA, TestVolume, arena_with, drive, place, record_bytes,
};
use super::super::word::{self, ANCHORED, LINKED, MARKER, REF};
use super::ReadStatus;
use super::journal_tests::storage_with;

/// Installs `restored` for writer session `writer` inside the caller's pool-gate hold, as one lane over every slot
/// folded with capture serialization held, after abandoning any capture pass in flight. It returns
/// [`Lane::install`](super::super::tables::Lane)'s refusal, which leaves the tables unchanged.
fn install_restored(
    tables: &mut Tables<'_>,
    live: &Pool,
    restored: &Restored,
    writer: u64,
) -> Result<(), RestoreRefusal> {
    let mut capture = live.capture_lock().expect("capture serialization is free");
    capture.abandon();
    live.replaced();
    let len = live.records().len();
    let mut lane =
        (tables.lanes(live, &capture, len, &[1]).next()).expect("one reservation splits one lane");
    let installed = lane.install(restored, writer);
    let fold = lane.done();
    if tables.fold_lanes(live, &capture, [fold]) {
        live.publish_deadline_bound(tables.state.earliest_deadline);
    }
    installed
}

/// Media whose root slots hold the session of the last of `attaches` attaches that formatted and relaunched it.
fn relaunched(attaches: usize) -> Media {
    let store = media(MEDIA);
    for _ in 0..attaches {
        let storage = storage_with(|_| {});
        let buffers = arena_with(4, 5);
        drop(Device::over(&storage, &buffers, Rc::clone(&store)));
    }
    store
}

/// The writer session the install tests restore under: generation 1, epoch 8.
const WRITER: u64 = (1 << 32) | 8;

fn restored(slot: usize, session: u64, start: u64, units: u32) -> Restored {
    Restored {
        id: AllocationId::new(SlotIndex(slot), 1),
        session,
        key: key(slot as u8 + 1),
        fingerprint: 0,
        expiry: PortableExpiry::ABSENT,
        expires_at_s: u32::MAX,
        locator: ExtentLocator::new(start, units).unwrap(),
        tail: 0,
        version: 0,
    }
}

/// Under the third attach's session, slots restored at the two earlier sessions of its generation read their records' exact bytes, and a header carrying the writer generation at a restored extent exposes no byte.
#[test]
fn two_retained_sessions_read_exact_bytes_under_a_third() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let store = relaunched(2);
    let expected = crate::storage::upcoming_session();
    let mut dev = Device::over(&storage, &buffers, store);
    let writer = dev.volume.session();
    assert_eq!(
        writer, expected,
        "the third attach writes its tenure's session"
    );
    assert!(
        writer & 0xFFFF_FFFF >= 6,
        "the third attach writes a session above the two restored sessions"
    );
    let pool = storage.live_pool().unwrap();
    for (slot, generation) in [(0, writer - 4), (1, writer - 2)] {
        let (metadata, body) = (&key(slot as u8 + 1)[..4], vec![0xA0 + slot as u8; 100]);
        let units = storage.record.layout(4, 100).record_units() as u32;
        let mut install = restored(slot, generation, u64::from(units) * slot as u64, units);
        let id = install.id;
        install.locator = install
            .locator
            .ending_at(storage.record.layout(4, 100).record_len());
        let mut access = pool.try_lock().unwrap();
        assert_eq!(
            install_restored(&mut access.tables(), pool, &install, writer),
            Ok(())
        );
        access.release();
        let raw = TestVolume::request(pool, id, &install.key);
        assert_eq!(raw.session, generation);
        let stale = record_bytes(&storage, install.key, id, writer, metadata, &body);
        place(&storage, &dev.control, install.locator, &stale);
        let op = dev.volume.read_raw(&raw, u64::MAX).unwrap();
        let delivered = drive(&mut dev.volume, &dev.control, op);
        assert_eq!(
            delivered.status,
            ReadStatus::HeaderMismatch(HeaderMismatch::Session {
                expected: generation,
                found: writer,
            })
        );
        assert!(delivered.bytes.is_empty());
        let retained = record_bytes(&storage, install.key, id, generation, metadata, &body);
        place(&storage, &dev.control, install.locator, &retained);
        let op = dev.volume.read_raw(&raw, u64::MAX).unwrap();
        let delivered = drive(&mut dev.volume, &dev.control, op);
        assert_eq!(delivered.status, ReadStatus::Complete);
        assert_eq!(delivered.bytes, [metadata, &body].concat());
    }
}

/// The restored install leaves one counted anchor, `Resident`, `LINKED` and the marker with every retirement flag clear, the historical generation and the restored facts in the record and tables, the published deadline bound lowered, and the slot taken from the free set into the resident ledger; it refuses a session the read predicate refuses for the writer's session, a slot outside the free set, and an incarnation the slot already issued, each before any write.
#[test]
fn a_restored_slot_holds_one_anchor_and_its_historical_facts() {
    let storage = storage_with(|_| {});
    let pool = storage.live_pool().unwrap();
    let expiry = PortableExpiry {
        deadline_ns: 9_000_000_000,
        lifetime_ms: 1_000,
    };
    let install = Restored {
        id: AllocationId::new(SlotIndex(3), 5),
        version: 0x5EED,
        tail: 7,
        fingerprint: 0xF1F2,
        expiry,
        expires_at_s: 9,
        ..restored(3, (1 << 32) | 4, 4, 1)
    };
    pool.edit_word(6, |_| 4);
    let mut access = pool.try_lock().unwrap();
    let mut tables = access.tables();
    let (free, resident) = (tables.state.ledger.free, tables.state.ledger.resident);
    let inserts = pool.insert_step.load(Ordering::Relaxed);
    tables.free_slots().take(5);
    let refusals = [
        (
            Restored {
                session: (1 << 32) | 10,
                ..install
            },
            RestoreRefusal::Session,
        ),
        (
            Restored {
                session: (1 << 32) | 5,
                ..install
            },
            RestoreRefusal::Session,
        ),
        (
            Restored {
                session: (2 << 32) | 4,
                ..install
            },
            RestoreRefusal::Session,
        ),
        (
            Restored {
                session: 1 << 32,
                ..install
            },
            RestoreRefusal::Session,
        ),
        (
            Restored {
                id: AllocationId::new(SlotIndex(5), 1),
                ..install
            },
            RestoreRefusal::NotFree,
        ),
        (
            Restored {
                id: AllocationId::new(SlotIndex(6), 4),
                ..install
            },
            RestoreRefusal::NotFree,
        ),
        (
            Restored {
                id: AllocationId::new(SlotIndex(6), 3),
                ..install
            },
            RestoreRefusal::NotFree,
        ),
    ];
    for (refused, refusal) in refusals {
        assert_eq!(
            install_restored(&mut tables, pool, &refused, WRITER),
            Err(refusal)
        );
        let slot = refused.id.slot_index();
        assert_eq!(
            pool.records()[slot].ident.load(Ordering::Relaxed),
            if slot == 6 { 4 } else { 0 }
        );
        assert_eq!(tables.generation(slot), 0);
        assert_eq!((tables.version(slot), tables.step(slot)), (0, 0));
        assert_eq!(
            (tables.state.ledger.free, tables.state.ledger.resident),
            (free, resident)
        );
        assert_eq!(pool.insert_step.load(Ordering::Relaxed), inserts);
    }
    tables.free_slots().give(5);
    assert_eq!(
        install_restored(&mut tables, pool, &install, WRITER),
        Ok(())
    );
    let installed = pool.records()[3].ident.load(Ordering::Relaxed);
    assert_eq!(
        installed,
        5 | SlotState::Resident.bits() | LINKED | MARKER | REF
    );
    assert!(word::well_formed(installed));
    assert_eq!((installed & ANCHORED, word::refs(installed)), (0, 1));
    assert_eq!(
        (tables.generation(3), *tables.key(3), tables.tails[3]),
        ((1 << 32) | 4, key(4), 7)
    );
    assert_eq!(tables.version(3), 0x5EED);
    assert_eq!(
        (tables.step(3), pool.insert_step.load(Ordering::Relaxed)),
        (inserts + 1, inserts + 1)
    );
    let record = &pool.records()[3];
    assert_eq!((record.fingerprint(), record.expires_at_s()), (0xF1F2, 9));
    assert_eq!(record.locator(), install.locator);
    assert_eq!(tables.expiry(3), expiry);
    assert_eq!(
        (tables.state.earliest_deadline, tables.state.pass_earliest),
        (9, 9)
    );
    assert_eq!(pool.deadline_bound.load(Ordering::Relaxed), 9);
    assert!(!tables.free_slots().contains(3));
    assert_eq!(
        (tables.state.ledger.free, tables.state.ledger.resident),
        (free - 1, resident + 1)
    );
    assert_eq!(
        install_restored(&mut tables, pool, &install, WRITER),
        Err(RestoreRefusal::NotFree)
    );
    access.release();
}

fn column(
    storage: &crate::storage::Storage<crate::storage::test_platform::TestPlatform>,
    slot: usize,
) -> u64 {
    storage.live_pool().unwrap().generations()[slot].load(Ordering::Relaxed)
}

/// A fresh bind writes the writer generation into the column; a marked slot's return clears its marker, column,
/// version and step, and leaves another slot's.
#[test]
fn the_return_clears_the_column_and_leaves_another_slot_s() {
    use super::super::attempt_tests::invalidate;
    use super::super::publication_tests::{drain, publish};
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let mut dev = Device::over(&storage, &buffers, relaunched(1));
    let writer = dev.volume.session();
    let lease = publish(&storage, &mut dev, &key(1), &[1; 20]).unwrap();
    let other = publish(&storage, &mut dev, &key(2), &[2; 20]).unwrap();
    let (id, kept) = (lease.id(), other.id());
    assert_eq!(column(&storage, id.slot_index()), writer);
    drop(lease);
    let pool = storage.live_pool().unwrap();
    pool.edit_word(id.slot_index(), |word| word | MARKER);
    pool.versions()[id.slot_index()].store(9, Ordering::Relaxed);
    {
        let mut access = pool.try_lock().unwrap();
        assert_eq!(access.tables().version(id.slot_index()), 9);
        access.release();
    }
    invalidate(&storage, &key(1)).unwrap();
    drain(&storage);
    let returned = pool.records()[id.slot_index()]
        .ident
        .load(Ordering::Relaxed);
    assert_eq!(
        word::state(returned),
        SlotState::Free,
        "the extent returned"
    );
    assert_eq!(returned & MARKER, 0);
    assert_eq!(column(&storage, id.slot_index()), 0);
    assert_eq!(column(&storage, kept.slot_index()), writer);
    let mut access = pool.try_lock().unwrap();
    let tables = access.tables();
    assert_eq!(
        (
            tables.version(id.slot_index()),
            tables.step(id.slot_index())
        ),
        (0, 0)
    );
    assert_ne!(tables.step(kept.slot_index()), 0);
    access.release();
}

/// A restored install refuses `Session` for exactly the sessions the read predicate refuses for the reader's session:
/// generation 5 with a nonzero even epoch at or below 8 is admitted, over 4,096 random restored identities; every
/// refused one leaves the insert step, and every installed one takes the next step. On a free slot with a fresh
/// incarnation, the reader's own epoch 8 installs and epoch 10 refuses `Session`.
#[test]
fn admission_uses_read_predicate() {
    use super::super::owner_fixture::narrow;
    use super::super::record::{RecordIdentity, admits};
    use super::super::seeded::SplitMix64;

    let (storage, _arena) = narrow(4096, 4, 16384);
    let pool = storage.live_pool().unwrap();
    let slots = pool.records().len() as u64;
    let reader = (5 << 32) | 8;
    let mut rng = SplitMix64::new(0xACCE);
    let (mut admitted_count, mut refused_count, mut installs) = (0, 0, 0);
    for case in 0..4096 {
        let generation = [4, 5, 6][rng.below(3) as usize];
        let session = (generation << 32) | rng.below(12);
        let restored = Restored {
            id: AllocationId::new(
                SlotIndex(rng.below(slots) as usize),
                1 + rng.below(9) as u32,
            ),
            session,
            version: rng.next_u64(),
            key: [case as u8; 32],
            fingerprint: 0,
            expiry: PortableExpiry::ABSENT,
            expires_at_s: u32::MAX,
            locator: ExtentLocator::new(0, 1).unwrap(),
            tail: 0,
        };
        let identity = RecordIdentity {
            key: restored.key,
            allocation: restored.id.record_tag(),
            session,
            version: restored.version,
        };
        let verdict = admits(&identity, &identity, reader);
        let epoch = session & 0xFFFF_FFFF;
        assert_eq!(
            verdict,
            generation == 5 && epoch.is_multiple_of(2) && epoch != 0 && epoch <= 8,
            "case {case}: session {session:#x}"
        );
        let mut access = pool.try_lock().unwrap();
        let mut tables = access.tables();
        let inserts = pool.insert_step.load(std::sync::atomic::Ordering::Relaxed);
        let installed = install_restored(&mut tables, pool, &restored, reader);
        if installed.is_ok() {
            let slot = restored.id.slot_index();
            assert_eq!(
                pool.insert_step.load(std::sync::atomic::Ordering::Relaxed),
                inserts + 1,
                "case {case}"
            );
            assert_eq!(
                (tables.version(slot), tables.step(slot)),
                (restored.version, inserts + 1),
                "case {case}"
            );
        } else {
            assert_eq!(
                pool.insert_step.load(std::sync::atomic::Ordering::Relaxed),
                inserts,
                "case {case}"
            );
        }
        access.release();
        if verdict {
            admitted_count += 1;
            assert_ne!(installed, Err(RestoreRefusal::Session), "case {case}");
            installs += usize::from(installed.is_ok());
        } else {
            refused_count += 1;
            assert_eq!(installed, Err(RestoreRefusal::Session), "case {case}");
        }
    }
    assert!(admitted_count > 0 && refused_count > 0 && installs > 0);
    for (epoch, expected) in [(8, Ok(())), (10, Err(RestoreRefusal::Session))] {
        let (storage, _arena) = narrow(4096, 4, 16384);
        let pool = storage.live_pool().unwrap();
        let restored = Restored {
            id: AllocationId::new(SlotIndex(0), 1),
            session: (5 << 32) | epoch,
            version: 7,
            key: [0xEE; 32],
            fingerprint: 0,
            expiry: PortableExpiry::ABSENT,
            expires_at_s: u32::MAX,
            locator: ExtentLocator::new(0, 1).unwrap(),
            tail: 0,
        };
        let mut access = pool.try_lock().unwrap();
        let mut tables = access.tables();
        let inserts = pool.insert_step.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            install_restored(&mut tables, pool, &restored, reader),
            expected,
            "epoch {epoch}"
        );
        let step = inserts + u64::from(expected.is_ok());
        assert_eq!(
            pool.insert_step.load(std::sync::atomic::Ordering::Relaxed),
            step,
            "epoch {epoch}"
        );
        if expected.is_ok() {
            assert_eq!(
                (tables.version(0), tables.step(0)),
                (7, step),
                "epoch {epoch}"
            );
        }
        access.release();
    }
}
