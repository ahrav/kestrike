//! The slot word's read sites fail closed on a reserved bit, and a park of
//! the current incarnation sets its flag once however many land together.
//!
//! A reader without the gate refuses a malformed word, a park leaves it
//! unchanged and a drain count holds it; every gate-held read, service's
//! sighting, eviction's and expiry's visits, the pending mark's
//! application, the owner check of an abandonment, the claim, the return
//! and the capture walk's entry copy, panics and poisons the pool gate, so
//! no allocator step runs on a word it cannot trust. The candidate compare
//! under a shard gate refuses a malformed word as corruption and poisons
//! that gate.

use std::sync::atomic::Ordering;

use super::budget::WorkBudget;
use super::gate::GateError;
use super::lookup::{LookupError, REJECTED_BEFORE_ACCESS};
use super::lookup_tests::{body, completed, key, lookup, publish, ready, ticks};
use super::owner::Storage;
use super::publish::PublishError;
use super::publish_tests::{RETRIES, TRIES};
use super::release::{PARKED_PROBE, SERVICE_CONTROLS, SERVICE_PER_SLOT, ServiceReport, park};
use super::tables::SlotState;
use super::test_platform::TestPlatform;
use super::word::{ABANDONED, ANCHORED, REF, RESERVED, RETIRED, STATE};

/// A deadline 100 seconds into the engine's nanosecond timeline.
const DEADLINE: u64 = 100 * 1_000_000_000;
/// The lowest reserved bit.
const BIT: u64 = RESERVED & RESERVED.wrapping_neg();

fn budget() -> WorkBudget {
    WorkBudget::new(1 << 16)
}

/// Runs `step` expecting a panic whose message contains `reason`, and
/// checks that it poisoned the pool gate.
fn poisons(storage: &Storage<TestPlatform>, reason: &str, step: impl FnOnce()) {
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

/// Without the gate: the lookup refuses before the fingerprint, a park of
/// the word's own incarnation changes nothing, and the outstanding report
/// counts a malformed free word as held; with the bit cleared the same
/// lookup hits.
#[test]
fn a_reserved_bit_fails_closed_without_the_gate() {
    let storage = ready(8);
    let id = publish(&storage, key(0x61), DEADLINE, &body(0x61));
    ticks(&storage, &[Some(1)]);
    let live = storage.live_pool().unwrap();
    let slot = id.slot_index();
    live.edit_word(slot, |word| word | BIT);
    let malformed = live.word(slot);
    let mut reader = storage.register().unwrap();
    let rejected = REJECTED_BEFORE_ACCESS.with(std::cell::Cell::get);
    assert_eq!(
        lookup(&mut reader, &key(0x61), RETRIES).err(),
        Some(LookupError::Contended)
    );
    assert!(REJECTED_BEFORE_ACCESS.with(std::cell::Cell::get) > rejected);
    park(live, slot, id.incarnation());
    assert_eq!(live.word(slot), malformed);
    assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 0);
    let free = (0..8).find(|&other| other != slot).unwrap();
    assert_eq!(storage.outstanding().anchored, 1);
    live.edit_word(free, |word| word | BIT);
    assert_eq!(storage.outstanding().anchored, 2);
    live.edit_word(free, |word| word & !RESERVED);
    live.edit_word(slot, |word| word & !RESERVED);
    drop(lookup(&mut reader, &key(0x61), RETRIES).unwrap());
}

/// Service's sighting of a flagged slot panics on a reserved bit.
#[test]
fn a_reserved_bit_poisons_service() {
    let storage = ready(8);
    let id = publish(&storage, key(0x62), DEADLINE, &body(0x62));
    let live = storage.live_pool().unwrap();
    live.telemetry()
        .pending_marks
        .fetch_add(1, Ordering::Relaxed);
    live.edit_word(id.slot_index(), |word| word | ABANDONED | BIT);
    live.mark_parked_slot(id.slot_index());
    poisons(&storage, "reserved bit", || {
        let _ = storage.service(&mut budget());
    });
}

/// Eviction's visit of a resident member panics on a reserved bit.
#[test]
fn a_reserved_bit_poisons_eviction() {
    let storage = ready(8);
    let id = publish(&storage, key(0x63), DEADLINE, &body(0x63));
    storage
        .live_pool()
        .unwrap()
        .edit_word(id.slot_index(), |word| word | BIT);
    poisons(&storage, "reserved bit", || {
        let _ = storage.evict_step(&mut budget(), |_, _| true);
    });
}

/// Expiry's scan stops at an unexpired resident with a reserved bit ahead
/// of an expired one, and its visit panics: once where the malformed
/// resident opens the stretch, the stop test the walk makes on its own,
/// and once behind it, where the block scan decides. With two or three
/// residents in eight slots the walk takes the block scan.
#[test]
fn a_reserved_bit_poisons_expiry() {
    const EARLY: u64 = DEADLINE / 2;
    for healthy_first in [false, true] {
        let storage = ready(8);
        let mut slot = 0;
        if healthy_first {
            let id = publish(&storage, key(0x60), DEADLINE, &body(0x60));
            assert_eq!(id.slot_index(), slot);
            slot += 1;
        }
        let malformed = publish(&storage, key(0x64), DEADLINE, &body(0x64));
        assert_eq!(malformed.slot_index(), slot);
        let expired = publish(&storage, key(0x65), EARLY, &body(0x65));
        assert_eq!(expired.slot_index(), slot + 1);
        storage
            .live_pool()
            .unwrap()
            .edit_word(malformed.slot_index(), |word| word | BIT);
        ticks(&storage, &[Some(EARLY)]);
        poisons(&storage, "reserved bit", || {
            let _ = storage.expire_step(&mut budget());
        });
    }
}

/// Applying a pending mark reads the marked slot's word and panics on a
/// reserved bit, before any selection.
#[test]
fn a_reserved_bit_poisons_the_pending_mark() {
    let storage = ready(8);
    let live = storage.live_pool().unwrap();
    live.pending_mark().set(3, 0);
    live.edit_word(3, |word| word | BIT);
    poisons(&storage, "reserved bit", || {
        let _ = storage.evict_step(&mut budget(), |_, _| true);
    });
}

/// An owner's drop checks under the gate that the word still names it,
/// and panics on a reserved bit.
#[test]
fn a_reserved_bit_poisons_the_abandonment() {
    let storage = ready(8);
    let owner = storage.reserve(Some(4), Some(20), &mut budget()).unwrap();
    let live = storage.live_pool().unwrap();
    live.edit_word(owner.id().slot_index(), |word| word | BIT);
    poisons(&storage, "reserved bit", || drop(owner));
}

/// The gate-held report paths read the word checked and panic on a
/// reserved bit.
#[test]
fn a_reserved_bit_poisons_the_identity_reports() {
    let storage = ready(8);
    let id = publish(&storage, key(0x66), DEADLINE, &body(0x66));
    let live = storage.live_pool().unwrap();
    live.edit_word(id.slot_index(), |word| word | BIT);
    poisons(&storage, "reserved bit", || {
        let _ = storage.identity_is_current(id);
    });
    let storage = ready(8);
    let id = publish(&storage, key(0x66), DEADLINE, &body(0x66));
    let live = storage.live_pool().unwrap();
    live.edit_word(id.slot_index(), |word| word | BIT);
    poisons(&storage, "reserved bit", || {
        let _ = storage.slot_state(super::tables::SlotIndex(id.slot_index()));
    });
}

/// Publication's fingerprint compare against an occupied pair whose slot
/// word is malformed refuses `Corrupt`, poisoning the shard gate, and
/// changes neither count.
#[test]
fn a_reserved_bit_under_a_candidate_is_corrupt() {
    let storage = ready(8);
    let published = publish(&storage, key(0x67), DEADLINE, &body(0x67));
    let live = storage.live_pool().unwrap();
    live.edit_word(published.slot_index(), |word| word | BIT);
    let (owner, error) = completed(&storage, key(0x67), DEADLINE, &body(0x67))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::Corrupt);
    assert_eq!(live.refs(owner.id().slot_index()), 0);
    assert_eq!(live.refs(published.slot_index()), 1);
    let (owner, error) = owner.publish(TRIES, &mut budget()).err().unwrap();
    assert_eq!(error, PublishError::Contended);
    drop(owner);
}

/// Service refuses an anchored flag beside a zero count before judging
/// the anchor's grace, so the extent is never returned while the flag names
/// an anchor.
#[test]
fn an_anchored_flag_without_its_anchor_poisons_service() {
    let storage = ready(8);
    let id = publish(&storage, key(0x68), DEADLINE, &body(0x68));
    let live = storage.live_pool().unwrap();
    let slot = id.slot_index();
    live.records()[slot].stamp_era(u64::MAX);
    live.telemetry()
        .pending_marks
        .fetch_add(1, Ordering::Relaxed);
    live.edit_word(slot, |word| (word | ABANDONED | ANCHORED) - REF);
    live.mark_parked_slot(slot);
    poisons(&storage, "anchored flag without its counted anchor", || {
        let _ = storage.service(&mut budget());
    });
}

/// Only a park of a record's current incarnation sets a flag, so service
/// panics on a flag beside a free record.
#[test]
fn a_flag_on_a_free_record_poisons_service() {
    let storage = ready(8);
    let live = storage.live_pool().unwrap();
    live.telemetry()
        .pending_marks
        .fetch_add(1, Ordering::Relaxed);
    live.edit_word(2, |word| word | ABANDONED);
    live.mark_parked_slot(2);
    poisons(&storage, "free or quarantined record", || {
        let _ = storage.service(&mut budget());
    });
}

/// Runs service over one published record whose word is edited to carry
/// the state `encoding` and `flags`, with its parked bit set and one
/// pending mark counted, and returns the report when service returned
/// without a panic. A panic must name the unknown state and poison the gate.
fn service_of_a_parked_state(flags: u64, encoding: u64) -> Option<ServiceReport> {
    let storage = ready(8);
    let slot = publish(&storage, key(0x67), DEADLINE, &body(0x67)).slot_index();
    let live = storage.live_pool().unwrap();
    live.telemetry()
        .pending_marks
        .fetch_add(1, Ordering::Relaxed);
    live.edit_word(slot, |word| word & !STATE | encoding << 36 | flags);
    live.mark_parked_slot(slot);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        storage.service(&mut budget()).unwrap()
    }));
    match outcome {
        Ok(report) => {
            live.try_lock_quiet().unwrap().release();
            Some(report)
        }
        Err(payload) => {
            let message = payload.downcast_ref::<&str>().copied().unwrap();
            assert!(message.contains("unknown state"), "{message}");
            assert!(matches!(
                live.try_lock_quiet().err(),
                Some(GateError::Poisoned)
            ));
            None
        }
    }
}

/// Service's sighting of a member of the parked set whose word carries a
/// state encoding past `Quarantined` panics and poisons the gate, as the
/// word module requires of every gate holder, whatever flags stand beside
/// the state: an abandoned flag alone, no flag, and an abandoned and
/// retired flag. The sibling keeps the published record's own state under
/// the same three flag sets and returns without a panic.
#[test]
fn an_unknown_state_beside_a_parked_bit_poisons_service() {
    let resident = SlotState::Resident.bits() >> 36;
    let mut passed = Vec::new();
    for flags in [ABANDONED, 0, ABANDONED | RETIRED] {
        assert!(service_of_a_parked_state(flags, resident).is_some());
        for encoding in [5, 6, 7] {
            if let Some(report) = service_of_a_parked_state(flags, encoding) {
                passed.push((flags, encoding, report.skipped));
            }
        }
    }
    assert_eq!(passed, []);
}

/// A pass that panics under the gate debits every step it funded before the
/// panic: the call controls, the park pass's two probes with their repair
/// updates, and the visited slot's bundle, by kind, with the allowance
/// conserved.
#[test]
fn a_panic_in_a_pass_keeps_every_funded_debit() {
    const INITIAL: usize = 1 << 16;
    let storage = ready(8);
    let live = storage.live_pool().unwrap();
    live.telemetry()
        .pending_marks
        .fetch_add(1, Ordering::Relaxed);
    live.edit_word(2, |word| word | ABANDONED);
    live.mark_parked_slot(2);
    let mut spent = WorkBudget::new(INITIAL);
    poisons(&storage, "free or quarantined record", || {
        let _ = storage.service(&mut spent);
    });
    let counters = spent.counters();
    let probes = 2;
    assert_eq!(
        (
            counters.coordination_attempts,
            counters.visits,
            counters.comparisons,
            counters.updates
        ),
        (
            1,
            probes + 1,
            3,
            SERVICE_CONTROLS - 1 + probes * (PARKED_PROBE - 1) + 2
        )
    );
    let charged = 1 + SERVICE_CONTROLS - 1 + probes * PARKED_PROBE + SERVICE_PER_SLOT;
    assert_eq!(spent.remaining(), INITIAL - charged);
}

/// A parked member behind the park cursor whose word carries a reserved
/// bit fails closed in its visit, after the pass wrote its funded probes
/// back, so the panic debits the same steps as a malformed free record.
#[test]
fn a_panic_on_a_reserved_bit_keeps_every_funded_debit() {
    const INITIAL: usize = 1 << 16;
    let storage = ready(8);
    let live = storage.live_pool().unwrap();
    live.telemetry()
        .pending_marks
        .fetch_add(1, Ordering::Relaxed);
    live.edit_word(2, |word| word | ABANDONED | BIT);
    live.mark_parked_slot(2);
    let mut spent = WorkBudget::new(INITIAL);
    poisons(&storage, "reserved bit", || {
        let _ = storage.service(&mut spent);
    });
    let counters = spent.counters();
    let probes = 2;
    assert_eq!(
        (
            counters.coordination_attempts,
            counters.visits,
            counters.comparisons,
            counters.updates
        ),
        (
            1,
            probes + 1,
            3,
            SERVICE_CONTROLS - 1 + probes * (PARKED_PROBE - 1) + 2
        )
    );
    let charged = 1 + SERVICE_CONTROLS - 1 + probes * PARKED_PROBE + SERVICE_PER_SLOT;
    assert_eq!(spent.remaining(), INITIAL - charged);
}

/// A word a held member's fast pass would accept but for a reserved bit
/// takes the full decision, which fails closed: a retired record a right
/// holds, and a parked filling record a right holds.
#[test]
fn a_reserved_bit_on_a_held_member_poisons_service() {
    for parked in [false, true] {
        let storage = ready(8);
        let owner = storage.reserve(Some(4), Some(20), &mut budget()).unwrap();
        let slot = owner.id().slot_index();
        let live = storage.live_pool().unwrap();
        if parked {
            let held = live.lock().unwrap();
            drop(owner);
            drop(held);
        } else {
            drop(owner);
        }
        live.edit_word(slot, |word| (word + REF) | BIT);
        poisons(&storage, "reserved bit", || {
            let _ = storage.service(&mut budget());
        });
    }
}

/// The claim refuses a free word carrying anything beside its incarnation.
#[test]
fn a_reserved_bit_poisons_the_claim() {
    let storage = ready(8);
    let live = storage.live_pool().unwrap();
    let head = live.claim_order(None, 1)[0];
    live.edit_word(head, |word| word | BIT);
    poisons(&storage, "a reserved bit", || {
        let _ = storage.reserve(Some(4), Some(20), &mut budget());
    });
}

/// The return's owner check refuses a word with a reserved bit.
#[test]
fn a_reserved_bit_poisons_the_return() {
    let storage = ready(8);
    let owner = storage.reserve(Some(4), Some(20), &mut budget()).unwrap();
    let live = storage.live_pool().unwrap();
    live.edit_word(owner.id().slot_index(), |word| word | BIT);
    poisons(&storage, "reserved bit", || {
        let _ = owner.cancel();
    });
}

/// The capture walk copies each member's entry under the pool gate, so a
/// member whose word carries a reserved bit panics the walk, which poisons
/// the pool gate and the capture mutex, and no entry reaches the sink.
#[test]
fn a_reserved_bit_poisons_the_capture_walk() {
    let storage = ready(8);
    let id = publish(&storage, key(0x67), DEADLINE, &body(0x67));
    let live = storage.live_pool().unwrap();
    live.edit_word(id.slot_index(), |word| word | BIT);
    let counter = storage.start_capture(8, true, 8).unwrap();
    let mut copied = 0;
    poisons(&storage, "reserved bit", || {
        let _ = storage.capture_visit(counter, 8, |_| copied += 1);
    });
    assert_eq!(copied, 0);
    assert_eq!(live.capture_lock().err(), Some(GateError::Poisoned));
}

#[test]
fn an_unknown_state_poisons_the_capture_walk() {
    for encoding in [SlotState::Resident.bits() >> 36, 5, 6, 7] {
        let storage = ready(8);
        let id = publish(&storage, key(0x68), DEADLINE, &body(0x68));
        let live = storage.live_pool().unwrap();
        live.edit_word(id.slot_index(), |word| word & !STATE | encoding << 36);
        let counter = storage.start_capture(8, true, 8).unwrap();
        let mut copied = 0;
        if encoding == SlotState::Resident.bits() >> 36 {
            storage.capture_visit(counter, 8, |_| copied += 1).unwrap();
            assert_eq!(copied, 1);
            continue;
        }
        poisons(&storage, "unknown state", || {
            let _ = storage.capture_visit(counter, 8, |_| copied += 1);
        });
        assert_eq!(copied, 0, "encoding {encoding}");
        assert_eq!(live.capture_lock().err(), Some(GateError::Poisoned));
    }
}

/// Parks of the current incarnation racing on many threads while the gate
/// is held set the flag once and leave exactly one counter entry; the
/// owner's drop then absorbs it and service returns the slot.
#[test]
fn a_current_park_sets_its_flag_exactly_once_under_contention() {
    const THREADS: usize = 8;
    let storage = ready(8);
    let owner = storage.reserve(Some(4), Some(20), &mut budget()).unwrap();
    let (slot, incarnation) = (owner.id().slot_index(), owner.id().incarnation());
    let live = storage.live_pool().unwrap();
    let before = live.word(slot);
    let held = live.lock().unwrap();
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                let live = storage.live_pool().unwrap();
                for _ in 0..4 {
                    park(live, slot, incarnation);
                }
            });
        }
    });
    assert_eq!(live.word(slot), before | ABANDONED);
    assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 1);
    drop(held);
    drop(owner);
    assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 0);
    assert_eq!(storage.service(&mut budget()).unwrap().serviced, 1);
    assert!(storage.outstanding().is_clear());
}

/// Service's sighting of a member of the parked set whose word carries a reserved bit beside a clear abandoned flag panics and poisons the gate, on a resident record and on a free one, as the word module requires of every gate-held read.
#[test]
fn a_reserved_bit_beside_a_stale_parked_bit_poisons_service() {
    for resident in [true, false] {
        let storage = ready(8);
        let slot = if resident {
            publish(&storage, key(0x66), DEADLINE, &body(0x66)).slot_index()
        } else {
            2
        };
        let live = storage.live_pool().unwrap();
        live.telemetry()
            .pending_marks
            .fetch_add(1, Ordering::Relaxed);
        live.edit_word(slot, |word| word | BIT);
        live.mark_parked_slot(slot);
        poisons(&storage, "reserved bit", || {
            let _ = storage.service(&mut budget());
        });
    }
}

/// Runs `step` from a destructor that catches its panic, directly or while
/// the thread unwinds from an unrelated panic, and returns whether the step
/// panicked.
fn panics_in_a_destructor(unwinding: bool, step: impl FnOnce()) -> bool {
    struct StepsOnDrop<'a, F: FnOnce()> {
        step: Option<F>,
        panicked: &'a std::cell::Cell<bool>,
    }
    impl<F: FnOnce()> Drop for StepsOnDrop<'_, F> {
        fn drop(&mut self) {
            let step = self.step.take().unwrap();
            let stepped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(step));
            self.panicked.set(stepped.is_err());
        }
    }
    let panicked = std::cell::Cell::new(false);
    let stepper = StepsOnDrop {
        step: Some(step),
        panicked: &panicked,
    };
    if unwinding {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _stepper = stepper;
            panic!("an unrelated panic with a live stepper");
        }));
        assert!(outcome.is_err());
    } else {
        drop(stepper);
    }
    panicked.get()
}

/// A reserved bit panics a gate-held report and the panic poisons the pool
/// gate (`Storage::identity_is_current`: "panics under the gate and poisons
/// it"; `Storage::slot_state`: "the gate is held, so the panic poisons it"),
/// on a thread that is not unwinding and from a destructor that asks while
/// its thread unwinds from another panic: the guard, taken during the
/// unwind, would release open on drop.
#[test]
fn a_reserved_bit_poisons_the_identity_reports_even_during_unwinding() {
    for (report, unwinding) in [(0, false), (0, true), (1, false), (1, true)] {
        let storage = ready(8);
        let id = publish(&storage, key(0x66), DEADLINE, &body(0x66));
        let live = storage.live_pool().unwrap();
        live.edit_word(id.slot_index(), |word| word | BIT);
        let panicked = panics_in_a_destructor(unwinding, || {
            if report == 0 {
                let _ = storage.identity_is_current(id);
            } else {
                let _ = storage.slot_state(super::tables::SlotIndex(id.slot_index()));
            }
        });
        assert!(
            panicked,
            "premise: report {report} panicked, unwinding={unwinding}"
        );
        assert!(
            matches!(live.try_lock_quiet(), Err(GateError::Poisoned)),
            "report {report}'s panic poisons the gate, unwinding={unwinding}"
        );
    }
}

/// A reserved bit panics the owner check of a completed owner's return
/// (`Pool::gate_state`: "the caller holds the gate, so the panic poisons
/// it") and the panic poisons the pool gate, on a thread that is not
/// unwinding and from a destructor that returns while its thread unwinds
/// from another panic: the guard, taken during the unwind, would release
/// open on drop.
#[test]
fn a_reserved_bit_poisons_the_allocation_return_even_during_unwinding() {
    for unwinding in [false, true] {
        let storage = ready(8);
        let owner = completed(&storage, key(0x67), DEADLINE, &body(0x67));
        let live = storage.live_pool().unwrap();
        let slot = owner.id().slot_index();
        let transfer = owner.release();
        live.edit_word(slot, |word| word | BIT);
        let before = live.word(slot);
        let panicked = panics_in_a_destructor(unwinding, || {
            let _ = storage.return_allocation(transfer, &mut budget());
        });
        assert!(
            panicked,
            "premise: the return panicked, unwinding={unwinding}"
        );
        assert_eq!(
            live.word(slot),
            before,
            "the return wrote the malformed word, unwinding={unwinding}"
        );
        assert!(
            matches!(live.try_lock_quiet(), Err(GateError::Poisoned)),
            "the return's panic poisons the gate, unwinding={unwinding}"
        );
    }
}
