//! Loom kernel for the lookup's protected retain and final bracket: one
//! reader over one mapping, one writer removing it, one maintainer certifying
//! and releasing its anchor, and one closer, over every schedule the search
//! reaches within the recorded preemption bound.
//!
//! Model substitutions, each replacing a mapped word or code the storage
//! owns with a loom atomic:
//!
//! - `sequence` is the shard sequence, driven by the production
//!   `read_stable`, `still` and `Busy`; `pair` is the one identity word of
//!   the chain, `X` while visible and `NONE` after removal, standing for the
//!   scan's copy. The writer's stores are spelled out in the production
//!   order and strength: the odd sequence with its release fence, the
//!   `Relaxed` pair, the even sequence, then the era bump and the park that
//!   sets the anchored flag, as removal records them.
//! - `era`, `certified` and `records` are the grace words; the maintainer
//!   calls the production `PassCursor`, releases the anchor with
//!   `releasable` and one exchange on the word from its acquire sighting,
//!   then reuses the slot from the count that exchange left or the sighting
//!   read, exactly as the grace kernel does: return, incarnation two claimed
//!   from the `Free` value, payload and fingerprint overwritten, anchor
//!   installed.
//! - `slot` is the grace kernel's model record: `ident` the slot's lifetime
//!   word, incarnation, flags, state and count with the anchor counted,
//!   driven through the production transitions; `fingerprint` the key's
//!   hash word, the object's identity, which the reader compares with an
//!   `Acquire` load after its validation, and which the retirement
//!   overwrites with its era by a `Release` store once the mapping has
//!   ended, as `retire_anchored` does, and from which the maintainer reads
//!   the era; `payload` the record's locator and the extent's bytes a lease
//!   reads under its right;
//!   `closed` is the admission cutoff: the closer stores it with `SeqCst`
//!   as production does, and the reader loads it with `SeqCst` in the final
//!   bracket only. The entry's cutoff read after its pin store is not
//!   modelled, since no thread in this kernel stores the cutoff and then
//!   loads a pin; `clock` is the platform sample, fixed before the deadline
//!   so the lease path is the one explored.
//! - The reader is the lookup's examination of one copied candidate, spelled
//!   out over the model words: pin, stable sequence, copy, second sequence
//!   load, one load of the word checking the incarnation and the count, the
//!   fingerprint's load and its compare with the probed key's, then for a
//!   mismatch the absence bracket, the cutoff and the sequence, and for a
//!   match the retain's exchange expecting that word, final bracket, then
//!   either the lease's reads, with the pin ended before the second read and
//!   the right released after it, or the refund. The retain runs the production
//!   transition in an unbounded loop where production bounds it by the
//!   budget; loom cannot drive the production loop, which uses `std`
//!   atomics, so the `C` refusal and the loop's charges are outside this
//!   kernel.
//!
//! Each kernel's participants share its state through an `Rc`. Loom runs
//! every participant as a coroutine on one OS thread, and the `Rc` reference
//! count is plain memory outside the model, so a participant's last step ends
//! at its last model access and its join orders those accesses before the
//! checks that follow.
//!
//! Properties, each an assertion on the reader and each beyond what the
//! grace kernel's reader asserts: the retain, taken only after the copy's
//! validation, never lands on a count of zero; the incarnation read is the
//! copied one and the payload reads the published value, so protection held
//! through the retain; and a hit saw the pair visible after its sample, so
//! the witness names a mapping that was in place when the sample was taken.
//! Loom reports a concurrent overwrite of the payload as a causality
//! violation. The first kernel probes with the object's own key: a
//! fingerprint load that reads the era mismatches, and the absence bracket
//! must then find the sequence moved, so `Missing` is never reported while
//! the copied mapping stands. The era-overlay kernel probes with a key whose
//! fingerprint equals the era the writer stamps, so only a load of the era
//! matches, and the final bracket must refuse it: a hit is always on the
//! key's hash, never on an era.
//! With every reader gone the maintainer reuses the slot, so the right and
//! the anchor were both given back. Four negative controls: omitting the
//! final sequence load lets a reader hit on a mapping removed before its
//! sample; releasing the anchor at removal lets the retain land on a
//! released anchor or the payload be reused under the reader; an anchor
//! exchange that succeeds with `Release` alone reuses the slot under the
//! lease's payload read; and splitting the
//! anchor release into a plain store of the word without the flag and a
//! separate decrement lets the store and a lease's concurrent release
//! overwrite each other: the release is lost and the slot is never reused,
//! or the flag clear is lost and the flag outlives the anchor. Two more, one
//! per probe: trusting a mismatch without the absence bracket's sequence
//! load reports `Missing` on the key's visible mapping, and omitting the
//! final sequence load lets the era-overlay reader hit on the era. And one
//! per probe for the fingerprint load's strength: loaded with `Relaxed`, a
//! read of the era leaves the reader's later sequence loads free to return
//! the copy's value, so the first kernel reports `Missing` on the visible
//! mapping and the era-overlay kernel hits on the era.
//!
//! The stamp is a `Release` store and the fingerprint load `Acquire`, as in
//! production. The writer stamps on the thread that ran the removal, after
//! `Busy::begin`'s release fence, so a reader whose `Acquire` load reads the
//! era synchronizes with that fence and sees the odd sequence value or a
//! later one; the fence alone gives the edge, so a `Relaxed` stamp is sound
//! in these kernels and in production, where every stamp of a mapped object
//! runs on the thread that cleared the mapping. The `Release` stamp adds the
//! even commit to the edge.
//!
//! The third kernel, `two_object_model`, is the replacement race with the
//! charged retain: two readers over one key whose mapping the writer moves
//! from an object at its deadline to a fresh one, the maintainer certifying
//! and reusing the old slot, and the clock fixed at the old deadline. Each
//! reader makes up to two attempts, exactly as the lookup does: every copy
//! is retained through the bounded compare-exchange over a real
//! `WorkBudget`, each attempt charged before it runs, and refused
//! `Contended` when the allowance is spent; the final bracket then takes
//! the sample, and a copy at or past its deadline refunds and is `Expired`
//! only under the unchanged sequence, else the attempt is spent and the next
//! copy finds the fresh object. Its properties: `Expired` is never reported
//! on a mapping already replaced, the retain never lands on a released
//! anchor or a reused slot, a hit saw its mapping visible after the sample,
//! every compare-exchange the readers ran was charged, and with the readers
//! gone the old slot is reused and the fresh object keeps exactly its
//! anchor. Its negative controls: skipping the sequence load of the final
//! bracket lets a reader report `Expired` on the replaced mapping, and
//! retrying a lost compare-exchange without a charge runs more attempts than
//! were paid. A third control loads the fingerprint `Relaxed`, so a read of
//! the old object's era meets an unchanged sequence at the absence bracket.
//! The old object sits at its deadline, so it is only ever expired, never
//! leased: the retain on it under the pin checks that its
//! anchor is still counted, the reuse of its slot is checked by the
//! incarnation assertion, and the reused-cell oracle runs on the fresh
//! object. Both objects carry the key's hash, and a reader whose
//! fingerprint load reads the old object's era must find the sequence moved
//! at its absence bracket.
//!
//! Correspondence of `two_object_model`'s retain and publication to
//! production:
//!
//! | Model operation | Production operation | Ordering |
//! |---|---|---|
//! | `retain`'s compare-exchange on the slot word | `retain_right`'s `exchange_weak` on the lifetime word (`storage::acquire`, `storage::lease`) | `Relaxed` success, `Relaxed` failure |
//! | `replacer`'s store of the pair word | `Bucket::publish_pair` (`index::bucket`) | `Relaxed` |
//!
//! The model's compare-exchange is the strong form, so it fails only on a
//! lost race, and its charge accounting covers that path. Production's weak
//! form also fails spuriously with the expected value in place;
//! `retain_right` charges that attempt and retries it through
//! `update_after` as it does a lost race, counting it in the `stalled`
//! counter. The correspondence relies on `update_after` handling a
//! spurious failure as it does a lost race; the model explores the success
//! and lost-race outcomes.
//!
//! The pair store sits between `Busy`'s odd and even sequence values. A
//! reader whose stable sequence load reads the even commit sees the pair
//! store: the commit is a `SeqCst`, hence release, store sequenced after
//! it. A reader whose acquiring pair load reads the stored pair
//! synchronizes with `Busy::begin`'s release fence, which follows the odd
//! store, so that reader's later sequence load finds the sequence moved.
//!
//! Bounds: loom `0.7.2`, preemption bound 2 for the first and the
//! era-overlay kernels and 1 for `two_object_model`; each property holds on
//! every schedule the bounded search reached. Every kernel thread runs a
//! finite sequence of steps to completion on every schedule, so loom's
//! bounded search covers each schedule within the bound under its default
//! scheduling. A green run is finite-model evidence over exactly those
//! schedules; schedules beyond the bound stay unchecked. Loom models
//! happens-before and per-location coherence, and the cross-location
//! `SeqCst` total order sits outside its model, so a green run checks the
//! bracket and refund logic on every schedule it reached, while the
//! total-order argument in the sequence module rests on that module's
//! proof. Run with
//! `RUSTFLAGS="--cfg loom" cargo test -p kestrike --lib --release lookup_model`.

use std::rc::Rc;
use std::sync::atomic::Ordering;

use loom::sync::atomic::{AtomicBool, AtomicU64};
use loom::thread;

use super::budget::{WorkBudget, WorkKind};
use super::grace::{ERA_FIRST, INACTIVE, PassCursor, bump, pin, releasable, unpin};
use super::grace_model::{
    Fenced, KEY_HASH, ModelRecord, park_word, release_anchor_word, release_anchor_word_at,
    retain_word,
};
use super::word::{self, ANCHORED, REF};
use crate::index::{Busy, read_stable, still};

const NONE: u64 = 0;
const X: u64 = 1;
const PAYLOAD: u64 = 0xA5;
const DEADLINE: u64 = 10;
const SAMPLE: u64 = 5;
const PREEMPTION_BOUND: usize = 2;

struct Shard {
    sequence: AtomicU64,
    pair: AtomicU64,
    era: AtomicU64,
    certified: AtomicU64,
    record: AtomicU64,
    slot: ModelRecord,
    closed: AtomicBool,
    clock: AtomicU64,
}

impl Shard {
    fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            pair: AtomicU64::new(X),
            era: AtomicU64::new(ERA_FIRST),
            certified: AtomicU64::new(0),
            record: AtomicU64::new(INACTIVE),
            slot: ModelRecord::resident(PAYLOAD),
            closed: AtomicBool::new(false),
            clock: AtomicU64::new(SAMPLE),
        }
    }
}

/// Which bug the model injects, if any.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    /// The reader skips the final sequence load and trusts its copy.
    OmitFinalValidation,
    /// The writer releases the anchor when it removes the mapping.
    ReleaseAtRemoval,
    /// The maintainer releases the anchor with a plain store of the word it
    /// loaded, less the flag, and then a separate decrement.
    SplitAnchorRelease,
    /// The maintainer's anchor exchange succeeds with `Release` alone.
    ReleaseOnlyAnchor,
    /// The reader reports a fingerprint mismatch as `Missing` without the
    /// absence bracket's sequence load.
    SkipAbsenceBracket,
    /// The reader loads the fingerprint with `Relaxed`.
    RelaxedFingerprintLoad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Hit,
    Missing,
    Moved,
    Closed,
}

/// One lookup of the key whose fingerprint is `probe` over the one copied
/// candidate.
fn reader(shard: &Shard, fault: Fault, probe: u64) -> Outcome {
    pin::<_, Fenced>(&shard.era, &shard.record).unwrap();
    let Ok(stable) = read_stable(&shard.sequence) else {
        unpin(&shard.record);
        return Outcome::Moved;
    };
    let copied = shard.pair.load(Ordering::SeqCst) == X;
    if !still(&shard.sequence, stable) {
        unpin(&shard.record);
        return Outcome::Moved;
    }
    if !copied {
        unpin(&shard.record);
        return Outcome::Missing;
    }
    // Validation before the fingerprint, inside the pinned interval: one
    // `Acquire` load of the word, as production's; the protection that
    // keeps the copied value current is the grace argument.
    let current = shard.slot.ident.load(Ordering::Acquire);
    assert_eq!(
        word::incarnation(current),
        1,
        "protection violated: slot reused under a pinned reader"
    );
    assert!(
        word::refs(current) >= 1,
        "protection violated: anchor released under a pinned reader"
    );
    // The identity compare: `Acquire`, as production's, so a load of the
    // era is ordered after the removal the stamp follows.
    let order = if fault == Fault::RelaxedFingerprintLoad {
        Ordering::Relaxed
    } else {
        Ordering::Acquire
    };
    let fingerprint = shard.slot.fingerprint.load(order);
    if fingerprint != probe {
        // No other candidate: the absence bracket, the cutoff and then the
        // sequence.
        let closed = shard.closed.load(Ordering::SeqCst);
        let unchanged = fault == Fault::SkipAbsenceBracket || still(&shard.sequence, stable);
        unpin(&shard.record);
        if !unchanged {
            return Outcome::Moved;
        }
        assert!(
            probe != KEY_HASH,
            "wrong Missing: an era mismatch skipped the key's visible mapping"
        );
        return if closed {
            Outcome::Closed
        } else {
            Outcome::Missing
        };
    }
    assert!(
        retain_word(&shard.slot.ident, current, 1),
        "protection violated: right taken on a released anchor"
    );
    // The final bracket: sample, cutoff, visibility witness, sequence.
    let now = shard.clock.load(Ordering::SeqCst);
    let closed = shard.closed.load(Ordering::SeqCst);
    let visible = shard.pair.load(Ordering::SeqCst) == X;
    let unchanged = fault == Fault::OmitFinalValidation || still(&shard.sequence, stable);
    if unchanged {
        assert_eq!(
            fingerprint, KEY_HASH,
            "an era counted as identity: a hit on the retirement era"
        );
    }
    if !unchanged || closed {
        shard.slot.ident.fetch_sub(REF, Ordering::Release);
        unpin(&shard.record);
        return if unchanged {
            Outcome::Closed
        } else {
            Outcome::Moved
        };
    }
    assert!(now < DEADLINE);
    assert!(
        visible,
        "witness violated: a hit on a mapping removed before its sample"
    );
    shard.slot.payload.with(|payload| {
        // SAFETY: a counted right keeps the cell unwritten; loom reports a
        // concurrent overwrite as a causality violation.
        assert_eq!(unsafe { *payload }, PAYLOAD, "hit read a reused cell");
    });
    // The pin ends before the lease escapes; the right outlives it.
    unpin(&shard.record);
    shard.slot.payload.with(|payload| {
        // SAFETY: as above; the right is still counted.
        assert_eq!(unsafe { *payload }, PAYLOAD, "lease read a reused cell");
    });
    shard.slot.ident.fetch_sub(REF, Ordering::Release);
    Outcome::Hit
}

/// Removal of the one mapping, then its retirement record.
fn writer(shard: &Shard, fault: Fault) {
    let stable = read_stable(&shard.sequence).unwrap();
    let busy = Busy::begin(&shard.sequence, stable);
    shard.pair.store(NONE, Ordering::Relaxed);
    busy.commit();
    if fault == Fault::ReleaseAtRemoval {
        shard.slot.ident.fetch_sub(REF, Ordering::AcqRel);
        return;
    }
    let stamp = bump::<_, Fenced>(&shard.era);
    shard.slot.stamp(stamp.retire_era);
    assert!(park_word(&shard.slot.ident, 1, ANCHORED));
}

/// The anchor's release from `sighted` as `fault` has it: one exchange,
/// the `Release`-only exchange, or the split control's plain store of the
/// sighted word less the flag and then a decrement. Returns the count it
/// left.
fn release_anchor(slot_word: &AtomicU64, sighted: u64, fault: Fault) -> usize {
    match fault {
        Fault::SplitAnchorRelease => {
            slot_word.store(sighted & !ANCHORED, Ordering::Relaxed);
            let stored = slot_word.fetch_sub(REF, Ordering::AcqRel);
            // A lease's release between the load and the store is either
            // overwritten by the store or overwrites its flag clear.
            assert_eq!(
                stored & ANCHORED,
                0,
                "a count update was lost: the flag clear was overwritten"
            );
            word::refs(stored) - 1
        }
        Fault::ReleaseOnlyAnchor => release_anchor_word_at(slot_word, sighted, Ordering::Release).0,
        _ => release_anchor_word(slot_word, sighted),
    }
}

/// Reuses `slot` when the count its anchor's release left, or the one the
/// sighting read, is zero: incarnation one's last release.
fn reuse_from_count(slot: &ModelRecord, sighted: u64, released_to: Option<usize>) {
    if released_to.unwrap_or(word::refs(sighted)) == 0 && word::incarnation(sighted) == 1 {
        slot.reuse();
    }
}

/// One certification pass, the anchor release it permits, and the reuse of
/// the slot from the count that release left or the sighting read.
fn maintain(shard: &Shard, fault: Fault) {
    let mut cursor = PassCursor::begin::<_, Fenced>(&shard.era);
    cursor.visit::<_, Fenced>(&shard.record);
    let certified = cursor.complete::<_, Fenced>(1, &shard.certified);
    let sighted = shard.slot.ident.load(Ordering::Acquire);
    let released_to = (sighted & ANCHORED != 0
        && releasable(shard.slot.fingerprint.load(Ordering::Relaxed), certified))
    .then(|| release_anchor(&shard.slot.ident, sighted, fault));
    reuse_from_count(&shard.slot, sighted, released_to);
}

/// The first kernel with the reader probing `probe`: [`KEY_HASH`], the
/// object's own key, or [`ERA_FIRST`], the era the writer stamps.
fn model(fault: Fault, probe: u64) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        let shard = Rc::new(Shard::new());
        let writer = {
            let shard = Rc::clone(&shard);
            thread::spawn(move || writer(&shard, fault))
        };
        let maintainer = {
            let shard = Rc::clone(&shard);
            thread::spawn(move || maintain(&shard, fault))
        };
        let closer = {
            let shard = Rc::clone(&shard);
            thread::spawn(move || shard.closed.store(true, Ordering::SeqCst))
        };
        let outcome = reader(&shard, fault, probe);
        writer.join().unwrap();
        maintainer.join().unwrap();
        closer.join().unwrap();
        // With the reader gone one more pass releases the anchor if it is
        // still held, and the count at zero lets the slot be reused: the
        // right and the anchor were both given back on every path.
        maintain(&shard, Fault::None);
        maintain(&shard, Fault::None);
        let current = shard.slot.ident.load(Ordering::SeqCst);
        if fault != Fault::ReleaseAtRemoval {
            assert_eq!(
                word::incarnation(current),
                2,
                "a count update was lost: the slot was never reused, {outcome:?}"
            );
        }
        assert_eq!(word::refs(current), 1, "{outcome:?}");
    });
}

#[test]
fn a_hit_is_retained_under_protection_and_witnessed_on_a_visible_mapping() {
    model(Fault::None, KEY_HASH);
}

#[test]
#[should_panic(expected = "witness violated")]
fn negative_control_omitting_the_final_sequence_validation_fails() {
    model(Fault::OmitFinalValidation, KEY_HASH);
}

#[test]
#[should_panic(expected = "protection violated")]
fn negative_control_releasing_the_anchor_at_removal_fails() {
    model(Fault::ReleaseAtRemoval, KEY_HASH);
}

#[test]
#[should_panic(expected = "a count update was lost")]
fn negative_control_splitting_the_anchor_release_into_a_store_and_a_decrement_fails() {
    model(Fault::SplitAnchorRelease, KEY_HASH);
}

#[test]
#[should_panic(expected = "wrong Missing")]
fn negative_control_trusting_an_era_mismatch_without_the_absence_bracket_fails() {
    model(Fault::SkipAbsenceBracket, KEY_HASH);
}

#[test]
#[should_panic(expected = "Causality violation")]
fn negative_control_an_anchor_exchange_without_acquire_reuses_under_a_lease() {
    model(Fault::ReleaseOnlyAnchor, KEY_HASH);
}

/// The era-overlay kernel: a lookup racing invalidate-then-retire whose
/// probed fingerprint equals the era the retirement stamps. Only a load of
/// the era matches, and the final bracket refuses every such match.
#[test]
fn an_era_equal_to_the_probed_fingerprint_is_never_a_hit() {
    model(Fault::None, ERA_FIRST);
}

#[test]
#[should_panic(expected = "an era counted as identity")]
fn negative_control_omitting_the_final_sequence_load_lets_an_era_count_as_identity() {
    model(Fault::OmitFinalValidation, ERA_FIRST);
}

#[test]
#[should_panic(expected = "wrong Missing")]
fn negative_control_a_relaxed_fingerprint_load_lets_an_era_mismatch_report_missing() {
    model(Fault::RelaxedFingerprintLoad, KEY_HASH);
}

#[test]
#[should_panic(expected = "an era counted as identity")]
fn negative_control_a_relaxed_fingerprint_load_lets_an_era_count_as_identity() {
    model(Fault::RelaxedFingerprintLoad, ERA_FIRST);
}

/// The mapping's identity word in the two-object kernel: the object at its
/// deadline, then its replacement.
const Y: u64 = 2;
const PAYLOAD_Y: u64 = 0x5A;
const FAR: u64 = 100;
/// Compare-exchange attempts one reader may pay for across its attempts.
const ALLOWANCE: usize = 2;

/// One object's slot: its model record holding `payload`, and its deadline.
struct Slot {
    record: ModelRecord,
    deadline: u64,
}

impl Slot {
    fn new(deadline: u64, payload: u64) -> Self {
        Self {
            record: ModelRecord::resident(payload),
            deadline,
        }
    }
}

struct Pair {
    sequence: AtomicU64,
    pair: AtomicU64,
    era: AtomicU64,
    certified: AtomicU64,
    records: [AtomicU64; 2],
    clock: AtomicU64,
    slots: [Slot; 2],
}

impl Pair {
    fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            pair: AtomicU64::new(X),
            era: AtomicU64::new(ERA_FIRST),
            certified: AtomicU64::new(0),
            records: [AtomicU64::new(INACTIVE), AtomicU64::new(INACTIVE)],
            clock: AtomicU64::new(DEADLINE),
            slots: [Slot::new(DEADLINE, PAYLOAD), Slot::new(FAR, PAYLOAD_Y)],
        }
    }

    fn slot(&self, copied: u64) -> &Slot {
        &self.slots[usize::from(copied == Y)]
    }
}

/// Which bug the two-object kernel injects, if any.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PairFault {
    None,
    /// The final bracket skips its sequence load and reports the copy's
    /// expiry on whatever the mapping now holds.
    StaleExpiry,
    /// A lost compare-exchange is retried without a charge.
    UnchargedRetry,
    /// The reader loads the fingerprint with `Relaxed`.
    RelaxedFingerprintLoad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairOutcome {
    Hit,
    Expired,
    Contended,
}

/// The bounded retain of the lookup over a loom word, expecting `current`,
/// the word the validation loaded: each attempt charged before it runs, a
/// lost attempt retried while the allowance lasts, through the production
/// transition, at the orderings the module's correspondence table records.
/// Returns the attempts run, so the caller can hold them against the
/// charge.
fn retain(
    slot_word: &AtomicU64,
    mut current: u64,
    budget: &mut WorkBudget,
    fault: PairFault,
) -> (bool, usize) {
    let mut attempts = 0;
    loop {
        let charged = attempts == 0 || fault != PairFault::UnchargedRetry;
        if charged && budget.debit(WorkKind::CoordinationAttempt).is_err() {
            return (false, attempts);
        }
        let next = word::retained(current, 1)
            .expect("protection violated: right taken on a released anchor or a reused slot");
        attempts += 1;
        match slot_word.compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return (true, attempts),
            Err(seen) => current = seen,
        }
    }
}

/// One reader's lookup: up to two attempts over the model words.
fn pair_reader(pair: &Pair, record: &AtomicU64, fault: PairFault) -> PairOutcome {
    let mut budget = WorkBudget::new(ALLOWANCE);
    let mut attempts = 0;
    let outcome = 'attempts: {
        for _ in 0..2 {
            pin::<_, Fenced>(&pair.era, record).unwrap();
            let Ok(stable) = read_stable(&pair.sequence) else {
                unpin(record);
                continue;
            };
            let copied = pair.pair.load(Ordering::SeqCst);
            if !still(&pair.sequence, stable) {
                unpin(record);
                continue;
            }
            let slot = pair.slot(copied);
            let current = slot.record.ident.load(Ordering::Acquire);
            assert_eq!(
                word::incarnation(current),
                1,
                "protection violated: slot reused under a pinned reader"
            );
            assert!(
                word::refs(current) >= 1,
                "protection violated: anchor released under a pinned reader"
            );
            // Both objects carry the key's hash; a load of the old object's
            // era mismatches, and the absence bracket then finds the
            // sequence moved.
            let order = if fault == PairFault::RelaxedFingerprintLoad {
                Ordering::Relaxed
            } else {
                Ordering::Acquire
            };
            if slot.record.fingerprint.load(order) != KEY_HASH {
                assert!(
                    !still(&pair.sequence, stable),
                    "wrong Missing: an era mismatch under an unchanged copy"
                );
                unpin(record);
                continue;
            }
            let (retained, ran) = retain(&slot.record.ident, current, &mut budget, fault);
            attempts += ran;
            if !retained {
                unpin(record);
                break 'attempts PairOutcome::Contended;
            }
            // The final bracket: sample, visibility witness, then the
            // sequence that must still show the copy, or the deadline
            // belongs to a mapping that is gone.
            let now = pair.clock.load(Ordering::SeqCst);
            let visible = pair.pair.load(Ordering::SeqCst) == copied;
            let unchanged = fault == PairFault::StaleExpiry || still(&pair.sequence, stable);
            if !unchanged {
                slot.record.ident.fetch_sub(REF, Ordering::Release);
                unpin(record);
                continue;
            }
            if now >= slot.deadline {
                // Expired under the unchanged copy: the right comes back
                // and nothing is leased.
                slot.record.ident.fetch_sub(REF, Ordering::Release);
                unpin(record);
                assert!(
                    visible,
                    "stale expiry: Expired reported on a replaced mapping"
                );
                break 'attempts PairOutcome::Expired;
            }
            assert!(
                visible,
                "witness violated: a hit on a mapping replaced before its sample"
            );
            slot.record.payload.with(|payload| {
                // SAFETY: a counted right keeps the cell unwritten; loom
                // reports a concurrent overwrite as a causality violation.
                assert_eq!(unsafe { *payload }, PAYLOAD_Y, "hit read a reused cell");
            });
            unpin(record);
            slot.record.payload.with(|payload| {
                // SAFETY: as above; the right is still counted.
                assert_eq!(unsafe { *payload }, PAYLOAD_Y, "lease read a reused cell");
            });
            slot.record.ident.fetch_sub(REF, Ordering::Release);
            break 'attempts PairOutcome::Hit;
        }
        PairOutcome::Contended
    };
    assert_eq!(
        attempts,
        budget.counters().coordination_attempts,
        "uncharged work: compare-exchange attempts beyond the charge"
    );
    outcome
}

/// Replacement of the mapping from the expiring object to the fresh one,
/// then the old object's retirement record, with the pair store at the
/// ordering the module's correspondence table records.
fn replacer(pair: &Pair) {
    let stable = read_stable(&pair.sequence).unwrap();
    let busy = Busy::begin(&pair.sequence, stable);
    pair.pair.store(Y, Ordering::Relaxed);
    busy.commit();
    let stamp = bump::<_, Fenced>(&pair.era);
    pair.slots[0].record.stamp(stamp.retire_era);
    assert!(park_word(&pair.slots[0].record.ident, 1, ANCHORED));
}

/// One certification pass over both records, the old anchor's release it
/// permits, and the reuse of the old slot from the count that release left
/// or the sighting read.
fn pair_maintain(pair: &Pair) {
    let mut cursor = PassCursor::begin::<_, Fenced>(&pair.era);
    for record in &pair.records {
        cursor.visit::<_, Fenced>(record);
    }
    let certified = cursor.complete::<_, Fenced>(2, &pair.certified);
    let old = &pair.slots[0];
    let sighted = old.record.ident.load(Ordering::Acquire);
    let released_to = (sighted & ANCHORED != 0
        && releasable(old.record.fingerprint.load(Ordering::Relaxed), certified))
    .then(|| release_anchor_word(&old.record.ident, sighted));
    reuse_from_count(&old.record, sighted, released_to);
}

fn two_object_model(fault: PairFault) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(1);
    builder.check(move || {
        let pair = Rc::new(Pair::new());
        let replacer = {
            let pair = Rc::clone(&pair);
            thread::spawn(move || replacer(&pair))
        };
        let maintainer = {
            let pair = Rc::clone(&pair);
            thread::spawn(move || pair_maintain(&pair))
        };
        let other = {
            let pair = Rc::clone(&pair);
            thread::spawn(move || pair_reader(&pair, &pair.records[1], fault))
        };
        let outcome = pair_reader(&pair, &pair.records[0], fault);
        replacer.join().unwrap();
        maintainer.join().unwrap();
        let second = other.join().unwrap();
        // With both readers gone, one more pass releases the old anchor if
        // it is still held and the zero count lets the old slot be reused;
        // the fresh object keeps exactly its anchor.
        pair_maintain(&pair);
        pair_maintain(&pair);
        let old = pair.slots[0].record.ident.load(Ordering::SeqCst);
        assert_eq!(word::incarnation(old), 2, "{outcome:?} {second:?}");
        assert_eq!(word::refs(old), 1, "{outcome:?} {second:?}");
        assert_eq!(
            word::refs(pair.slots[1].record.ident.load(Ordering::SeqCst)),
            1,
            "{outcome:?} {second:?}"
        );
    });
}

#[test]
fn two_readers_retain_the_replacement_charged_and_never_expire_a_replaced_mapping() {
    two_object_model(PairFault::None);
}

#[test]
#[should_panic(expected = "stale expiry")]
fn negative_control_skipping_the_final_sequence_load_fails() {
    two_object_model(PairFault::StaleExpiry);
}

#[test]
#[should_panic(expected = "uncharged work")]
fn negative_control_retrying_a_lost_compare_exchange_unpaid_fails() {
    two_object_model(PairFault::UnchargedRetry);
}

#[test]
#[should_panic(expected = "wrong Missing")]
fn negative_control_a_relaxed_fingerprint_load_lets_the_old_era_pass_as_absence() {
    two_object_model(PairFault::RelaxedFingerprintLoad);
}
