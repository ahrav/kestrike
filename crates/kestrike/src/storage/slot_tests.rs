//! The 32-byte record's protocols through the storage API: the locator
//! stays fixed from binding to the return and a free slot keeps its last
//! one, the fingerprint holds the key's hash word until retirement and the
//! era after it, expiry and eviction route removal from the stored
//! fingerprint, deadlines compare whole seconds, gate-free readers ignore
//! the state bits while gate holders fail closed on an unknown state.

use super::evict::Commit;
use super::evict_tests::{drain, generous};
use super::gate::GateError;
use super::lookup::LookupError;
use super::lookup_tests::{body, key, lookup, publish, ready, replace, ticks};
use super::owner::Storage;
use super::publish_tests::RETRIES;
use super::tables::SlotState;
use super::test_platform::TestPlatform;
use super::word::{ANCHORED, STATE};

/// One second on the engine's nanosecond timeline.
const SECOND: u64 = 1_000_000_000;

/// Runs `step` expecting a panic whose message contains `reason`, and checks
/// that it poisoned the pool gate.
pub(super) fn poisons(storage: &Storage<TestPlatform>, reason: &str, step: impl FnOnce()) {
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(step)).unwrap_err();
    let message = payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap();
    assert!(message.contains(reason), "{message}");
    let live = storage.live_pool().unwrap();
    assert!(matches!(
        live.try_lock_quiet().err(),
        Some(GateError::Poisoned)
    ));
}

/// A published object's record holds its extent and the key's hash word. A
/// replacement retires it while a lease holds it: the fingerprint word then
/// holds the retirement era until the return. Grace certification and
/// service release the anchor while the lease still counts, and an unrelated
/// key published into another slot meanwhile writes only its own record, so
/// the locator stays as bound; the return, once the lease is gone, receives
/// that locator, and the freed slot's record keeps it.
#[test]
fn a_bound_record_keeps_its_locator_until_the_return() {
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    let id = publish(&storage, key(1), 100 * SECOND, &body(1));
    let slot = id.slot_index();
    let live = storage.live_pool().unwrap();
    let record = &live.records()[slot];
    let locator = record.locator();
    let fingerprint = storage.route(&key(1)).unwrap().fingerprint();
    assert_eq!(record.fingerprint(), fingerprint);

    let mut reader = storage.register().unwrap();
    let lease = lookup(&mut reader, &key(1), RETRIES).unwrap();
    let era = storage.era_report().unwrap().era;
    let replacement = replace(&storage, key(1), 100 * SECOND, &body(2));
    assert_eq!(replacement.replaced.map(|(retired, _)| retired), Some(id));
    assert_eq!(
        storage.slot_state(id.slot()),
        Some((SlotState::Retired, id.incarnation()))
    );
    assert_ne!(live.flags(slot) & ANCHORED, 0);
    let other = publish(&storage, key(7), 100 * SECOND, &body(7));
    assert_ne!(other.slot_index(), slot);
    for _ in 0..2 {
        let _ = storage.certify(&mut generous()).unwrap();
        storage.service(&mut generous()).unwrap();
        assert_eq!(live.flags(slot) & ANCHORED, 0);
        assert_eq!(live.refs(slot), 1);
        assert_eq!(record.fingerprint(), era);
        assert_eq!(record.locator(), locator);
    }
    drop(lease);
    drain(&storage);
    assert_eq!(storage.slot_state(id.slot()).unwrap().0, SlotState::Free);
    assert_eq!(record.locator(), locator);
}

/// A record whose locator changed while it was bound names a free unit, so
/// the allocator refuses the return and the panic poisons the gate instead
/// of freeing units no slot holds.
#[test]
fn a_return_fails_closed_on_a_locator_its_record_does_not_hold() {
    let storage = ready(8);
    let id = publish(&storage, key(2), 100 * SECOND, &body(2));
    let live = storage.live_pool().unwrap();
    let record = &live.records()[id.slot_index()];
    let bound = record.locator();
    let other = super::ExtentLocator::new(bound.start_unit() + 1, bound.len_units()).unwrap();
    let removed = storage.remove(&key(2), id, RETRIES, &mut generous());
    assert!(removed.is_ok());
    record.set_locator(other);
    poisons(&storage, "does not match its record", || {
        drain(&storage);
    });
}

/// A fresh slot's locator field is zero; the claim stores its extent, and a
/// cancelled reservation's return leaves that extent in the free slot's
/// record while the free set takes the slot back; the next claim of the
/// slot overwrites it.
#[test]
fn a_free_slot_keeps_the_locator_of_its_last_extent() {
    let storage = ready(8);
    let live = storage.live_pool().unwrap();
    let records = live.records();
    assert!(records.iter().all(|record| record.locator().bits() == 0));
    let allocation = storage.reserve(Some(4), Some(20), &mut generous()).unwrap();
    let slot = allocation.id().slot_index();
    assert_eq!(slot, 0);
    let locator = allocation.locator();
    assert_eq!(records[slot].locator(), locator);
    assert_eq!(allocation.cancel(), Ok(()));
    assert_eq!(
        storage.slot_state(super::SlotIndex(slot)).unwrap().0,
        SlotState::Free
    );
    assert_eq!(records[slot].locator(), locator);
    live.claim_next(slot);
    let again = storage.reserve(Some(4), Some(20), &mut generous()).unwrap();
    assert_eq!(again.id().slot_index(), slot);
    assert_eq!(records[slot].locator(), again.locator());
}

/// Expiry and eviction route their removal from the fingerprint the record
/// holds: with the stored word inverted, which changes its bucket and tag,
/// each removal routes to a chain without the pair and ends `Absent`; with
/// the word restored, each removes the object.
#[test]
fn expiry_and_eviction_route_removal_from_the_stored_fingerprint() {
    for evicting in [false, true] {
        let storage = super::evict_tests::ready(8);
        let id = publish(&storage, key(3), 10 * SECOND, &body(3));
        let live = storage.live_pool().unwrap();
        let record = &live.records()[id.slot_index()];
        let fingerprint = record.fingerprint();
        let step = |storage: &Storage<TestPlatform>| {
            if evicting {
                storage
                    .evict_step(&mut generous(), |_, _| true)
                    .unwrap()
                    .commit
            } else {
                ticks(storage, &[Some(20 * SECOND)]);
                storage.expire_step(&mut generous()).unwrap().commit
            }
        };
        {
            let _held = live.lock().unwrap();
            record.set_fingerprint(!fingerprint);
        }
        assert_eq!(step(&storage), Some(Commit::Absent), "evicting {evicting}");
        {
            let _held = live.lock().unwrap();
            record.set_fingerprint(fingerprint);
        }
        assert!(
            matches!(step(&storage), Some(Commit::Evicted { victim, .. }) if victim == id),
            "evicting {evicting}"
        );
    }
}

/// A deadline of 5.3 s serves every sample below 5 s and none from 5 s on,
/// so the object is never served at or after its deadline and expires at
/// most one second early; the sweep removes it at the same second. A
/// deadline past `u32::MAX` seconds clamps and expires only at that second.
#[test]
fn deadlines_expire_on_whole_seconds_never_late_and_at_most_a_second_early() {
    let storage = ready(8);
    let deadline = 5 * SECOND + 300_000_000;
    publish(&storage, key(4), deadline, &body(4));
    publish(&storage, key(5), u64::MAX, &body(5));
    let mut reader = storage.register().unwrap();
    for (sample, served) in [
        (4 * SECOND, true),
        (5 * SECOND - 1, true),
        (5 * SECOND, false),
        (deadline - 1, false),
        (deadline, false),
        (deadline + 1, false),
    ] {
        ticks(&storage, &[Some(sample)]);
        let outcome = lookup(&mut reader, &key(4), RETRIES).map(drop);
        let expected = if served {
            Ok(())
        } else {
            Err(LookupError::Expired)
        };
        assert_eq!(outcome, expected, "sample {sample}");
    }
    let last = u64::from(u32::MAX) * SECOND;
    ticks(&storage, &[Some(last - 1)]);
    assert!(lookup(&mut reader, &key(5), RETRIES).is_ok());
    ticks(&storage, &[Some(last)]);
    assert_eq!(
        lookup(&mut reader, &key(5), RETRIES).err(),
        Some(LookupError::Expired)
    );
    drop(reader);

    let sweeping = super::evict_tests::ready(8);
    let id = publish(&sweeping, key(4), deadline, &body(4));
    ticks(&sweeping, &[Some(5 * SECOND - 1)]);
    assert_eq!(sweeping.expire_step(&mut generous()).unwrap().commit, None);
    ticks(&sweeping, &[Some(5 * SECOND)]);
    assert!(matches!(
        sweeping.expire_step(&mut generous()).unwrap().commit,
        Some(Commit::Evicted { victim, .. }) if victim == id
    ));
    // A clamped deadline is a deadline: a pool whose only resident clamps
    // publishes `u32::MAX` as its bound, and the sweep still removes the
    // object at the second lookup starts refusing it.
    let clamping = super::evict_tests::ready(8);
    let clamped = publish(&clamping, key(5), u64::MAX, &body(5));
    ticks(&clamping, &[Some(last - 1)]);
    assert_eq!(clamping.expire_step(&mut generous()).unwrap().commit, None);
    ticks(&clamping, &[Some(last)]);
    assert!(matches!(
        clamping.expire_step(&mut generous()).unwrap().commit,
        Some(Commit::Evicted { victim, .. }) if victim == clamped
    ));
}

/// Readers without the gate ignore the state bits: a lookup hits a resident
/// whose state bits read `Filling`. A gate holder that meets a state
/// encoding past `Quarantined` panics and poisons the gate: an identity
/// report, and eviction's visit of a linked member in every build.
#[test]
fn gate_free_readers_ignore_the_state_and_gate_holders_fail_closed_on_an_unknown_one() {
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    let id = publish(&storage, key(6), 100 * SECOND, &body(6));
    let live = storage.live_pool().unwrap();
    let slot = id.slot_index();
    live.set_state(slot, SlotState::Filling);
    let mut reader = storage.register().unwrap();
    drop(lookup(&mut reader, &key(6), RETRIES).unwrap());
    live.set_state(slot, SlotState::Resident);
    drop(lookup(&mut reader, &key(6), RETRIES).unwrap());
    drop(reader);
    live.edit_word(slot, |word| word & !STATE | 5 << 36);
    poisons(&storage, "unknown state", || {
        let _ = storage.slot_state(id.slot());
    });

    // A lease keeps the member, so the visit is the only gate-held read of
    // its word.
    let evicting = super::evict_tests::ready(8);
    let id = publish(&evicting, key(6), 100 * SECOND, &body(6));
    let mut reader = evicting.register().unwrap();
    let lease = lookup(&mut reader, &key(6), RETRIES).unwrap();
    let live = evicting.live_pool().unwrap();
    live.edit_word(id.slot_index(), |word| word & !STATE | 7 << 36);
    poisons(&evicting, "unknown state", || {
        let _ = evicting.evict_step(&mut generous(), |_, _| true);
    });
    drop(lease);
}

#[test]
fn per_slot_fields_live_in_side_arrays() {
    use super::budget::WorkBudget;
    use super::owner_fixture::{Device, narrow};
    use super::publish_tests::TRIES;
    use super::slot::Record;
    use super::volume_fixture::SESSION;
    use super::writable_tests::reserve_at;

    assert_eq!(std::mem::size_of::<Record>(), 32);
    let (storage, arena) = narrow(4096, 4, 16384);
    let mut device = Device::new(&storage, &arena);
    let mut bound = Vec::new();
    for (n, version) in [(1, 0x7007), (2, 0x9009)] {
        let mut fill = reserve_at(
            &storage,
            &key(n),
            crate::storage::CacheVersion(version),
            4,
            100,
        )
        .unwrap();
        device.fill(&mut fill, &[n; 104]);
        let lease = fill
            .publish(
                &mut device.volume,
                u64::MAX,
                TRIES,
                &mut WorkBudget::new(1 << 20),
            )
            .unwrap();
        bound.push((lease.id().slot_index(), version));
    }
    let inventory = storage.table_inventory().unwrap();
    let slots = inventory.records.1;
    assert_eq!(
        (
            inventory.generations.1,
            inventory.versions.1,
            inventory.steps.1
        ),
        (slots, slots, slots)
    );
    let pool = storage.live_pool().unwrap();
    let mut access = pool.try_lock().unwrap();
    let tables = access.tables();
    for (step, (slot, version)) in (1..).zip(bound) {
        assert_eq!(
            (
                tables.generation(slot),
                tables.version(slot),
                tables.step(slot)
            ),
            (SESSION, version, step)
        );
    }
    access.release();
}
