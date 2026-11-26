//! The `grace_model` kernel under GenMC, `model::<S>(Fault::None)`: readers,
//! one writer and one maintainer over one slot, then one more pass with
//! every reader gone that must release the anchor and reuse the slot.
//! Service reuses from the count the anchor's exchange left, the anchor
//! last, or from the count its acquire sighting read, as production's
//! visit does. The readers here release their rights before they unpin,
//! so every explored reuse is the anchor last; the sighting branch is
//! transcribed for correspondence.
//! `pin`, `unpin`, `bump`, `PassCursor` and `releasable` are the production
//! `grace` module and the word transitions the production `word` module.
//! Each handwritten atomic access that stands for a production operation is
//! one entry of the declaration's `bindings`, which names the production file
//! and scope of that operation. Before crediting a case, the judge checks both
//! sides of each entry: the shared kind and orderings, and each side's
//! operands and position in its scope.
//!
//! The `readers` cfg runs one reader, on the main thread, or two. The
//! `strength` cfg picks the encoding:
//!
//! - `seq`: production `Sequential` at the three points, with the index's
//!   observation load and removal store, the registration's claimed-bound
//!   load and raise and the pass's bound load all `SeqCst`, as `grace.rs`
//!   requires of the index and the `register` module.
//! - `fenced`: `Release`/`Acquire` with a `SeqCst` fence at each of the
//!   three points and after the claim, the Loom model's stand-in.
//! - `weakpin`: the stand-in without the reader's pin fence.
//! - `readeralone`: the stand-in with the reader's pin and claim fences
//!   alone, the writer's and the maintainer's dropped.
//! - `claimmisencoded`: production `Sequential` at the three points with
//!   the claim and the bound load encoded as the stand-in encodes them, the
//!   translation error the qualification control must expose.
//! - `weakretire`: the stand-in without the writer's retire fence.
//! - `weakcertify`: the stand-in without the maintainer's certify fence.
//! - `bumprelaxed`: production `Sequential` with the writer's era bump
//!   `Relaxed`.
//! - `startrelaxed`: production `Sequential` with the maintainer's
//!   `start_era` load `Relaxed`.
//!
//! Model substitutions: `bucket` stands for the index entry, `X` while
//! visible and `NONE` after removal, its load for the sequence's first load
//! and its store for the removal's commit; the next bind's payload and
//! fingerprint stores and the next publication's `Release` count add stand
//! for the bind and install path; `claimed` is the claimed bound; the
//! record's lifetime word, fingerprint and payload are statics, the payload
//! a plain `u64` behind an `UnsafeCell`, so a reuse racing a reader's read
//! of it is a data race GenMC reports. Each protection property has its own
//! check; a control is matched on the two pinned-reader checks, the anchor
//! released or the retain refused under a pin, and on no other.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering, fence};

use crate::check::check;
use crate::storage::grace::{
    ERA_FIRST, INACTIVE, PassCursor, Sequential, Strength, bump, pin, releasable, unpin,
};
use crate::storage::word::{
    self, ANCHORED, FLAGS, INCARNATION, MARKER, POLICY, REF, STATE, SlotState, VISITED,
};

const NONE: u64 = 0;
const X: u64 = 1;
const PAYLOAD: u64 = 0xA5;
const POISON: u64 = 0xDE;
const KEY_HASH: u64 = 0xF1F1;
#[cfg(readers = "1")]
const READERS: usize = 1;
#[cfg(readers = "2")]
const READERS: usize = 2;

/// The operations the index and the `register` module perform in
/// production beside the three points: the observation load, the removal
/// store, the claim's bound load and raise with an optional fence after
/// them, and the pass's bound load.
trait ModelStrength: Strength {
    const OBSERVE: Ordering;
    const COMMIT: Ordering;
    const CLAIM_LOAD: Ordering;
    const CLAIM_RAISE: Ordering;
    const BOUND_LOAD: Ordering;
    fn fence_claim() {}
}

impl ModelStrength for Sequential {
    const OBSERVE: Ordering = Ordering::SeqCst;
    const COMMIT: Ordering = Ordering::SeqCst;
    const CLAIM_LOAD: Ordering = Ordering::SeqCst;
    const CLAIM_RAISE: Ordering = Ordering::SeqCst;
    const BOUND_LOAD: Ordering = Ordering::SeqCst;
}

/// `Release`/`Acquire` accesses with a `SeqCst` fence at each point whose
/// parameter is `true`, and after the claim.
struct Model<const PIN: bool, const RETIRE: bool, const CERTIFY: bool>;

impl<const PIN: bool, const RETIRE: bool, const CERTIFY: bool> Strength
    for Model<PIN, RETIRE, CERTIFY>
{
    const ERA_LOAD: Ordering = Ordering::Acquire;
    const PIN_STORE: Ordering = Ordering::Release;
    const BUMP: Ordering = Ordering::AcqRel;
    const START: Ordering = Ordering::Acquire;
    const VISIT: Ordering = Ordering::Acquire;
    const PUBLISH: Ordering = Ordering::Release;

    fn fence_pin() {
        if PIN {
            fence(Ordering::SeqCst);
        }
    }

    fn fence_retire() {
        if RETIRE {
            fence(Ordering::SeqCst);
        }
    }

    fn fence_certify() {
        if CERTIFY {
            fence(Ordering::SeqCst);
        }
    }
}

impl<const PIN: bool, const RETIRE: bool, const CERTIFY: bool> ModelStrength
    for Model<PIN, RETIRE, CERTIFY>
{
    const OBSERVE: Ordering = Ordering::Acquire;
    const COMMIT: Ordering = Ordering::Release;
    const CLAIM_LOAD: Ordering = Ordering::Acquire;
    const CLAIM_RAISE: Ordering = Ordering::AcqRel;
    const BOUND_LOAD: Ordering = Ordering::Acquire;

    fn fence_claim() {
        fence(Ordering::SeqCst);
    }
}

/// Production `Sequential` at the three points with the claim and the bound
/// load encoded as `Model` encodes them. Its point orderings repeat
/// `grace.rs`'s `impl Strength for Sequential`, empty fences included, and
/// track it.
struct ClaimMisencoded;

impl Strength for ClaimMisencoded {
    const ERA_LOAD: Ordering = Sequential::ERA_LOAD;
    const PIN_STORE: Ordering = Sequential::PIN_STORE;
    const BUMP: Ordering = Sequential::BUMP;
    const START: Ordering = Sequential::START;
    const VISIT: Ordering = Sequential::VISIT;
    const PUBLISH: Ordering = Sequential::PUBLISH;
}

impl ModelStrength for ClaimMisencoded {
    const OBSERVE: Ordering = Ordering::SeqCst;
    const COMMIT: Ordering = Ordering::SeqCst;
    const CLAIM_LOAD: Ordering = Ordering::Acquire;
    const CLAIM_RAISE: Ordering = Ordering::AcqRel;
    const BOUND_LOAD: Ordering = Ordering::Acquire;

    fn fence_claim() {
        fence(Ordering::SeqCst);
    }
}

/// Production `Sequential` with one point's access weakened to `Relaxed`:
/// the writer's era bump when `WEAK_BUMP`, else the maintainer's
/// `start_era` load. Every other ordering is `Sequential`'s.
struct OneRelaxed<const WEAK_BUMP: bool>;

impl<const WEAK_BUMP: bool> Strength for OneRelaxed<WEAK_BUMP> {
    const ERA_LOAD: Ordering = Sequential::ERA_LOAD;
    const PIN_STORE: Ordering = Sequential::PIN_STORE;
    const BUMP: Ordering = if WEAK_BUMP {
        Ordering::Relaxed
    } else {
        Sequential::BUMP
    };
    const START: Ordering = if WEAK_BUMP {
        Sequential::START
    } else {
        Ordering::Relaxed
    };
    const VISIT: Ordering = Sequential::VISIT;
    const PUBLISH: Ordering = Sequential::PUBLISH;
}

impl<const WEAK_BUMP: bool> ModelStrength for OneRelaxed<WEAK_BUMP> {
    const OBSERVE: Ordering = <Sequential as ModelStrength>::OBSERVE;
    const COMMIT: Ordering = <Sequential as ModelStrength>::COMMIT;
    const CLAIM_LOAD: Ordering = <Sequential as ModelStrength>::CLAIM_LOAD;
    const CLAIM_RAISE: Ordering = <Sequential as ModelStrength>::CLAIM_RAISE;
    const BOUND_LOAD: Ordering = <Sequential as ModelStrength>::BOUND_LOAD;
}

#[cfg(strength = "seq")]
type S = Sequential;
#[cfg(strength = "fenced")]
type S = Model<true, true, true>;
#[cfg(strength = "weakpin")]
type S = Model<false, true, true>;
#[cfg(strength = "readeralone")]
type S = Model<true, false, false>;
#[cfg(strength = "claimmisencoded")]
type S = ClaimMisencoded;
#[cfg(strength = "weakretire")]
type S = Model<true, false, true>;
#[cfg(strength = "weakcertify")]
type S = Model<true, true, false>;
#[cfg(strength = "bumprelaxed")]
type S = OneRelaxed<true>;
#[cfg(strength = "startrelaxed")]
type S = OneRelaxed<false>;

struct Record {
    ident: AtomicU64,
    fingerprint: AtomicU64,
    payload: UnsafeCell<u64>,
}

struct Slot {
    era: AtomicU64,
    certified: AtomicU64,
    claimed: AtomicUsize,
    records: [AtomicU64; READERS],
    bucket: AtomicU64,
    record: Record,
    anchor_released: AtomicBool,
}

// SAFETY: the payload cell is the one non-atomic field; the protocol under
// test is what keeps its accesses race-free, and GenMC reports a race.
unsafe impl Sync for Slot {}

static SLOT: Slot = Slot {
    era: AtomicU64::new(ERA_FIRST),
    certified: AtomicU64::new(0),
    claimed: AtomicUsize::new(0),
    records: [const { AtomicU64::new(INACTIVE) }; READERS],
    bucket: AtomicU64::new(X),
    record: Record {
        ident: AtomicU64::new(1 | REF | SlotState::Resident.bits()),
        fingerprint: AtomicU64::new(KEY_HASH),
        payload: UnsafeCell::new(PAYLOAD),
    },
    anchor_released: AtomicBool::new(false),
};

/// Sets `ABANDONED` and `marks` on `slot_word` while it carries
/// `incarnation`, through the production park transition.
fn park_word(slot_word: &AtomicU64, incarnation: u32, marks: u64) -> bool {
    let mut current = slot_word.load(Ordering::Relaxed);
    while let Some(next) = word::parked(current, incarnation, marks) {
        match slot_word.compare_exchange(current, next, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(seen) => current = seen,
        }
    }
    false
}

/// One right on `incarnation` through the production retain transition.
fn retain_word(slot_word: &AtomicU64, mut current: u64, incarnation: u32) -> bool {
    while let Some(next) = word::retained(current, incarnation) {
        match slot_word.compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(seen) => current = seen,
        }
    }
    false
}

/// The anchor's release from `sighted`, the word the pass's acquire load
/// read: one exchange clearing `ANCHORED` and taking the anchor out of the
/// count, retried against the value found. Returns the count it left.
fn release_anchor_word(slot_word: &AtomicU64, sighted: u64) -> usize {
    let mut current = sighted;
    loop {
        check!(
            current & ANCHORED != 0 && word::refs(current) >= 1,
            c"protection violated: anchor released twice"
        );
        match slot_word.compare_exchange(
            current,
            word::unanchored(current),
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return word::refs(current) - 1,
            Err(seen) => current = seen,
        }
    }
}

/// The return and the next claim of a slot whose count is zero: the
/// return's clear with production's full mask, then the claim of
/// `incarnation` over the free word the previous incarnation leaves.
fn reuse_word(slot_word: &AtomicU64, incarnation: u32) {
    let previous = slot_word.fetch_and(
        !(FLAGS | VISITED | STATE | POLICY | MARKER),
        Ordering::Relaxed,
    );
    let free = previous & !(FLAGS | VISITED | STATE | POLICY | MARKER);
    check!(free & !INCARNATION == 0, c"a returned word carries a count");
    check!(
        slot_word
            .compare_exchange(
                u64::from(incarnation - 1),
                u64::from(incarnation) | SlotState::Filling.bits(),
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_ok(),
        c"a stale park flagged a free slot"
    );
}

impl Record {
    /// Stores the retirement era over the fingerprint with production's
    /// `Release`; the fingerprint must still hold the key's hash.
    fn stamp(&self, era: u64) {
        check!(
            self.fingerprint.load(Ordering::Relaxed) == KEY_HASH,
            c"the fingerprint changed before retirement"
        );
        self.fingerprint.store(era, Ordering::Release);
    }

    /// The reuse after the return: the next claim, the next bind's payload
    /// and fingerprint, and the next publication's anchor.
    fn reuse(&self) {
        reuse_word(&self.ident, 2);
        // SAFETY: a zero count proves no right and no anchor; GenMC checks
        // the write against every reader access.
        unsafe { *self.payload.get() = POISON }
        self.fingerprint.store(!KEY_HASH, Ordering::Relaxed);
        self.ident.fetch_xor(
            SlotState::Filling.bits() ^ SlotState::Resident.bits(),
            Ordering::Relaxed,
        );
        self.ident.fetch_add(REF, Ordering::Release);
    }
}

/// A registration's claim of `record`: the claimed bound covers the record
/// before its first pin.
fn claim(record: usize) {
    if SLOT.claimed.load(S::CLAIM_LOAD) <= record {
        SLOT.claimed.fetch_max(record + 1, S::CLAIM_RAISE);
    }
    S::fence_claim();
}

fn reader(record: usize) {
    claim(record);
    check!(
        pin::<_, S>(&SLOT.era, &SLOT.records[record]).is_ok(),
        c"pin refused"
    );
    if SLOT.bucket.load(S::OBSERVE) == X {
        check!(
            !SLOT.anchor_released.load(Ordering::SeqCst),
            c"protection violated: anchor released under a pinned reader"
        );
        check!(
            retain_word(
                &SLOT.record.ident,
                SLOT.record.ident.load(Ordering::Acquire),
                1
            ),
            c"protection violated: a pinned reader's retain refused"
        );
        // SAFETY: a counted right keeps the cell unwritten; GenMC reports a
        // concurrent overwrite as a data race.
        let payload = unsafe { *SLOT.record.payload.get() };
        check!(
            payload == PAYLOAD,
            c"protection violated: payload overwritten under a right"
        );
        SLOT.record.ident.fetch_sub(REF, Ordering::Release);
    }
    unpin(&SLOT.records[record]);
}

#[cfg(readers = "2")]
fn second_reader() {
    reader(1);
}

fn writer() {
    SLOT.bucket.store(NONE, S::COMMIT);
    let stamp = bump::<_, S>(&SLOT.era);
    SLOT.record.stamp(stamp.retire_era);
    check!(
        park_word(&SLOT.record.ident, 1, ANCHORED),
        c"the retirement park failed"
    );
}

/// One certification pass over the records below the claimed bound, then
/// one service visit of the slot.
fn maintain() {
    let mut cursor = PassCursor::begin::<_, S>(&SLOT.era);
    let bound = SLOT.claimed.load(S::BOUND_LOAD);
    let mut index = 0;
    while index < bound {
        cursor.visit::<_, S>(&SLOT.records[index]);
        index += 1;
    }
    let certified = cursor.complete::<_, S>(bound, &SLOT.certified);
    // One acquire load of the word decides the visit, as service's does.
    let sighted = SLOT.record.ident.load(Ordering::Acquire);
    // Production's `retire_era`: a `Relaxed` load the acquire sighting of
    // the anchored word orders after the stamp.
    let released_to = if sighted & ANCHORED != 0
        && releasable(SLOT.record.fingerprint.load(Ordering::Relaxed), certified)
    {
        SLOT.anchor_released.store(true, Ordering::SeqCst);
        Some(release_anchor_word(&SLOT.record.ident, sighted))
    } else {
        None
    };
    // The count the anchor's exchange left, acquired by that exchange, or
    // the one the sighting read: zero returns and reuses the slot, the
    // anchor last or the last right's release last.
    let refs = released_to.unwrap_or(word::refs(sighted));
    if refs == 0 {
        SLOT.record.reuse();
    }
}

pub(crate) fn run() {
    // SAFETY: every thread body touches only `SLOT`.
    #[cfg(readers = "2")]
    let other = unsafe { std::thread::spawn_f(second_reader) };
    let (writer, maintainer) =
        unsafe { (std::thread::spawn_f(writer), std::thread::spawn_f(maintain)) };
    reader(0);
    #[cfg(readers = "2")]
    let _ = other.join();
    let _ = writer.join();
    let _ = maintainer.join();
    // With every reader gone, one more pass releases and reuses. A slot left
    // unreused means a right was lost to an anchor released under it.
    maintain();
    let incarnation = word::incarnation(SLOT.record.ident.load(Ordering::SeqCst));
    check!(
        incarnation == 2,
        c"protection violated: a right was lost and the slot never reused"
    );
    check!(
        SLOT.anchor_released.load(Ordering::SeqCst),
        c"the final pass released no anchor"
    );
}
