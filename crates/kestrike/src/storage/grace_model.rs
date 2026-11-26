//! Loom kernel for the grace protocol: two readers, one writer and one
//! maintainer over one slot, over every schedule of the pin store,
//! observation load, removal, era bump, certification pass and anchor
//! release that the search reaches within the recorded preemption bound.
//!
//! Model substitutions, each replacing a mapped control word or code the
//! index owns with a loom atomic:
//!
//! - `bucket` is one identity word standing for the index entry: `X` while
//!   visible, `NONE` after removal. The reader's observation load and the
//!   writer's removal store use the model strength's `OBSERVE` and `COMMIT`
//!   orderings, which production leaves to the index.
//! - `record` is the slot's record: `ident` its lifetime word, laid out as
//!   the `word` module states, with the incarnation, the flags, the state
//!   and the count with the anchor counted, every write a read-modify-write
//!   through the production transitions; `fingerprint` holds the key's hash
//!   word until the retirement, once the mapping has ended, stores its era
//!   there with a `Release` store, where the anchor's release reads it;
//!   `payload` stands for the record's locator and the extent's bytes that
//!   a lease reads under its right.
//! - `claimed` is the claimed bound: each reader raises it for its record
//!   before pinning, and the maintainer's pass visits the records below the
//!   value it loads after its start era, so executions in which a pass sees
//!   neither, one or both readers' claims are all explored.
//! - Service decides each visit from one acquire load of the word, as
//!   production's does: the anchor's exchange runs from that sighting and
//!   returns the count it left, and a zero count, the one the exchange left
//!   (the anchor last) or the one a later sighting read after the last
//!   right's release (the reader last), reuses the slot at once by
//!   returning the word, claiming incarnation two from its `Free` value and
//!   overwriting the payload and the fingerprint.
//!   `anchor_released` records the release itself. A reader that copied `X`
//!   inside its interval asserts the anchor has not been released, retains a
//!   right with the production retain transition expecting incarnation one,
//!   and reads the payload of incarnation one; loom reports a reused slot as
//!   an assertion failure and a concurrent overwrite as a causality
//!   violation. The writer asserts the fingerprint still holds the key's
//!   hash when it stores the era. The second reader holds its right past
//!   its interval, as a lease does: it unpins, then reads the payload and
//!   releases the right, so the anchor's release can overlap the right, and
//!   the right's `Release` and the acquire that reads it, the sighting or
//!   the exchange after a retry, order the read before the reuse. The
//!   kernel counts, outside the model, the executions in which the
//!   concurrent maintainer reuses with the anchor last and in which its
//!   anchor exchange retried, and asserts each count is nonzero.
//! - One reader runs in the model's main thread, so the model has four
//!   participants on four loom threads and the search stays tractable; the
//!   maintainer performs the service inline after its pass.
//!
//! Each kernel's participants share its state through an `Rc`. Loom runs
//! every participant as a coroutine on one OS thread, and the `Rc` reference
//! count is plain memory outside the model, so a participant's last step ends
//! at its last model access and its join orders those accesses before the
//! checks that follow.
//!
//! The protocol code under test is the `grace` module itself; the model calls
//! `pin`, `unpin`, `bump`, `PassCursor` and `releasable` unchanged, choosing
//! the orderings through [`Strength`]. Loom 0.7.2 does not model the
//! cross-location total order of `SeqCst` accesses, so [`Model`] stands in
//! for the production `Sequential`: every
//! access is `Release`/`Acquire` and a `SeqCst` fence separates the store
//! from the load at each of the three points. Turning fences off is the
//! model's form of weakening; the findings below record which drops weaken a
//! point.
//!
//! Negative controls: releasing the anchor at removal, certifying from a
//! pass that skipped a record, loading the claimed bound before the start
//! era, and dropping the reader's fence each produce a counterexample at a
//! `protection violated` assertion. An anchor exchange that succeeds with
//! `Release` alone, and a right released `Relaxed`, each let the reuse's
//! payload write race the leased read, which loom reports as a causality
//! violation. Keeping the reader's fence alone, with
//! the writer's and the maintainer's dropped, produces one at a pinned
//! reader's protection assertion, the anchor released or the retain refused
//! under the pin, and that control is matched on those two messages alone.
//!
//! Finite-model findings. Under RC11 the reader's fence together with
//! either the writer's or the maintainer's fence excludes the violating
//! store-buffering cycle, and the reader's fence alone permits it. Dropping
//! only the writer's or only the maintainer's fence is therefore not a
//! weakening, and the discriminating control is the reader's fence alone.
//! Loom's `SeqCst` fence joins the fencing thread's whole causality into one
//! global clock (`rt::thread::Set::seq_cst_fence`), so the model cannot
//! distinguish the writer's fence from the maintainer's beside the reader's;
//! on these controls its verdicts match the RC11 reading. The GenMC kernel
//! over the production `grace` source checks that reading with one and two
//! readers (`verification/genmc/expected.json`): its `weakretire` and
//! `weakcertify` cases complete without a violation and herd7's
//! `G4-grace-retire-fence-dropped` and `G5-grace-certify-fence-dropped`
//! forbid the cycle, so a writer-fence or maintainer-fence control is
//! redundant within those domains; the composite litmus tests
//! `G11-composite-retire-fence-dropped` and
//! `G12-composite-certify-fence-dropped` add the claim to the same shape.
//! The distinguishing controls are a `Relaxed` era bump or `start_era`
//! load under `Sequential`, the kernel's `bumprelaxed` and `startrelaxed`
//! cases, which fail at a pinned reader's check as `G6-grace-bump-relaxed`
//! and `G7-grace-start-relaxed` allow. Loom encodes only the stand-in's
//! fence variants, so those two controls run under GenMC. These findings are
//! about the model's encoding. The production argument is the `grace`
//! module's. Its `Sequential` accesses at the three points sit in one
//! `SeqCst` total order. The claimed-bound load and raise and the admission
//! cutoff sit in that order too. The pass's `SeqCst` record load acquires
//! the `Release` clearing store, and the ordinary-memory lifetime argument
//! covers the slot's reuse. The finite model corroborates that argument
//! within the bound and checks none of it.
//!
//! Four further kernels cover the maintenance, terminal and handoff
//! protocols over the same words at preemption bound 2, and one more
//! negative control runs the grace kernel at its bound of 3:
//!
//! - Two collectors hand one pass cursor off through the model's gate, a
//!   loom mutex holding the production [`PassCursor`], each call funded for
//!   exactly one visit and charging a model budget: the pass publishes only
//!   when its last record is visited, the published value is the pass's own
//!   bound raised to what was certified before, gate attempts observed never
//!   exceed attempts charged, and at least one explored execution has one
//!   collector begin the pass and the other publish it. Negative control: a
//!   busy attempt left uncharged; the grace kernel's incomplete-pass control
//!   covers partial certification.
//! - A reused registration record and a delayed announcement: one reader
//!   unpins, gives its record up, and a second claimant pins it again with
//!   the era load and the pin store separated by a yield, so the schedule in
//!   which the whole removal, bump and pass run between the two is explored.
//! - A tiny terminal band, [`TinyBand`] with `TERMINAL = 4`, starting one
//!   below it: one retirement crosses into the band and one lands inside it
//!   while an allocator reads the cutoff open, takes the gate, rechecks it
//!   and claims the first free slot; service returns marked slots under the
//!   same gate. A claim of a slot whose stamp lies in the band is the
//!   violation, and the era stops at `TERMINAL + 1`. Negative controls: a
//!   rule that closes only on the crossing bump, and one that never closes.
//! - Double anchor release: a maintainer that decrements the count twice
//!   for one anchor lets the slot be reused under a reader's right.
//! - Certificate handoff: a distinct certifier runs the pass, writes its
//!   report, the bound its pin reads computed, and publishes the
//!   certificate through the production `complete`; two reclaimers, the
//!   first making two attempts and the second one, each attempt at the
//!   production [`Gate`] over a loom word, holding it acquire the
//!   certificate, read the report, release the anchor and reuse as one
//!   service visit allows, and count the return in a gate-held table cell
//!   every holder reads. A reader on its own thread leases its right past
//!   its interval. The slot returns at most once and is reused as
//!   incarnation two, and the kernel counts the executions with a contended
//!   attempt, with a handoff between the reclaimers, and with a reclaimer's
//!   reuse with the anchor last and with the last right's release last,
//!   events that happen before any join. Negative controls: the
//!   certificate published `Relaxed`, acquired `Relaxed`, the gate word's
//!   release or take `Relaxed`, and the service sighting `Relaxed`, each
//!   one substitution; and the reader's right released `Relaxed` with the
//!   anchor-last reuse left to a later sighting, so the race lands on the
//!   reader-last reuse. Loom reports each as a causality violation on the
//!   report, the table or the payload.
//!
//! Bounds: loom `0.7.2`, preemption bound 3 for the grace kernel and its
//! controls, 2 for the maintenance, terminal and handoff kernels above;
//! each property holds on every schedule the bounded search reached. Run
//! with
//! `RUSTFLAGS="--cfg loom" cargo test -p kestrike --lib --release grace_model`.

use std::rc::Rc;
use std::sync::Arc as StdArc;
use std::sync::atomic::{AtomicUsize as StdUsize, Ordering};

use loom::cell::UnsafeCell;
use loom::sync::Mutex;
use loom::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, fence};
use loom::thread;

use super::budget::{WorkBudget, WorkKind};
use super::gate::{Gate, GateWord, WeakGate};
use super::grace::{ERA_FIRST, ERA_TERMINAL, INACTIVE, PassCursor, Strength, bump, pin, unpin};
use super::word::{self, ANCHORED, FLAGS, INCARNATION, REF, STATE, SlotState, VISITED};

const NONE: u64 = 0;
const X: u64 = 1;
const PAYLOAD: u64 = 0xA5;
const POISON: u64 = 0xDE;
const READERS: usize = 2;
const PREEMPTION_BOUND: usize = 3;

/// The two operations the index performs in production, named here so the
/// model can weaken them together with the protocol's own accesses.
trait ModelStrength: Strength {
    /// The reader's observation load.
    const OBSERVE: Ordering;
    /// The writer's visibility removal.
    const COMMIT: Ordering;
}

/// `Release`/`Acquire` accesses with a `SeqCst` fence at each point whose
/// parameter is `true`, and the first terminal era as `TERMINAL`. All three
/// fences on with the production band is the stand-in for production.
pub(super) struct Model<
    const PIN: bool,
    const RETIRE: bool,
    const CERTIFY: bool,
    const TERMINAL: u64,
>;

impl<const PIN: bool, const RETIRE: bool, const CERTIFY: bool, const TERMINAL: u64> Strength
    for Model<PIN, RETIRE, CERTIFY, TERMINAL>
{
    const TERMINAL: u64 = TERMINAL;
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

impl<const PIN: bool, const RETIRE: bool, const CERTIFY: bool, const TERMINAL: u64> ModelStrength
    for Model<PIN, RETIRE, CERTIFY, TERMINAL>
{
    const OBSERVE: Ordering = Ordering::Acquire;
    const COMMIT: Ordering = Ordering::Release;
}

pub(super) type Fenced = Model<true, true, true, ERA_TERMINAL>;
type WeakPin = Model<false, true, true, ERA_TERMINAL>;
type ReaderFencedAlone = Model<true, false, false, ERA_TERMINAL>;

/// First terminal era of the tiny band the terminal kernel runs.
const TINY_TERMINAL: u64 = 4;

/// The fenced encoding with a terminal band the model can reach.
type TinyBand = Model<true, true, true, TINY_TERMINAL>;

/// Sets `ABANDONED` and `marks` on `slot_word` while it carries
/// `incarnation`, through the production park transition; returns whether
/// the park changed the word.
pub(super) fn park_word(slot_word: &AtomicU64, incarnation: u32, marks: u64) -> bool {
    let mut current = slot_word.load(Ordering::Relaxed);
    while let Some(next) = word::parked(current, incarnation, marks) {
        match slot_word.compare_exchange(current, next, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(seen) => current = seen,
        }
    }
    false
}

/// One right on `incarnation` through the production retain transition,
/// expecting `current`, the word the caller's validation loaded, and
/// retried against the value found; returns whether it was taken.
pub(super) fn retain_word(slot_word: &AtomicU64, mut current: u64, incarnation: u32) -> bool {
    while let Some(next) = word::retained(current, incarnation) {
        match slot_word.compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(seen) => current = seen,
        }
    }
    false
}

/// The anchor's release from `sighted`, the word the caller's acquire load
/// read: one exchange clearing `ANCHORED` and taking the anchor out of the
/// count, retried against the value found. Returns the count it left; at
/// zero the exchange's acquire half orders every right's release before
/// the caller's reuse.
pub(super) fn release_anchor_word(slot_word: &AtomicU64, sighted: u64) -> usize {
    release_anchor_word_at(slot_word, sighted, Ordering::AcqRel).0
}

/// [`release_anchor_word`] with the exchange's success ordering `success`;
/// also returns whether an exchange failed and retried.
pub(super) fn release_anchor_word_at(
    slot_word: &AtomicU64,
    sighted: u64,
    success: Ordering,
) -> (usize, bool) {
    let mut current = sighted;
    let mut retried = false;
    loop {
        assert!(
            current & ANCHORED != 0 && word::refs(current) >= 1,
            "protection violated: anchor released twice"
        );
        match slot_word.compare_exchange(
            current,
            word::unanchored(current),
            success,
            Ordering::Relaxed,
        ) {
            Ok(_) => return (word::refs(current) - 1, retried),
            Err(seen) => {
                current = seen;
                retried = true;
            }
        }
    }
}

/// The return and the next claim of a slot whose count is zero: the
/// return's read-modify-write clears the flags, the visited bit and the
/// state, and the claim's exchange installs `next` and the `Filling` state
/// from the `Free` value. The count the next publication installs follows as
/// one more read-modify-write.
pub(super) fn reuse_word(slot_word: &AtomicU64, next: u32) {
    let cleared = FLAGS | VISITED | STATE;
    let free = slot_word.fetch_and(!cleared, Ordering::Relaxed) & !cleared;
    assert_eq!(free & !INCARNATION, 0, "a returned word carries a count");
    let filling = u64::from(next) | SlotState::Filling.bits();
    slot_word
        .compare_exchange(free, filling, Ordering::Release, Ordering::Relaxed)
        .expect("a stale park flagged a free slot");
}

/// The key's hash word `bind` stored in the model record's fingerprint.
pub(super) const KEY_HASH: u64 = 0xF1F1;

/// The model's slot record: the lifetime word, the fingerprint word that
/// the era overlays once the mapping has ended, and the payload, the one
/// field a reader reads without an atomic.
pub(super) struct ModelRecord {
    pub(super) ident: AtomicU64,
    pub(super) fingerprint: AtomicU64,
    pub(super) payload: UnsafeCell<u64>,
}

impl ModelRecord {
    /// A resident, anchored record of incarnation one with `payload` and the
    /// key's hash in its fingerprint.
    pub(super) fn resident(payload: u64) -> Self {
        Self {
            ident: AtomicU64::new(1 | REF | SlotState::Resident.bits()),
            fingerprint: AtomicU64::new(KEY_HASH),
            payload: UnsafeCell::new(payload),
        }
    }

    /// Stores the retirement era over the fingerprint once the mapping has
    /// ended, with production's `Release`; the fingerprint must still hold
    /// the key's hash.
    pub(super) fn stamp(&self, era: u64) {
        assert_eq!(
            self.fingerprint.load(Ordering::Relaxed),
            KEY_HASH,
            "the fingerprint changed before retirement"
        );
        self.fingerprint.store(era, Ordering::Release);
    }

    /// The reuse after the return: the next claim takes the slot, the next
    /// bind overwrites the payload and the fingerprint, and the next
    /// publication installs its anchor.
    pub(super) fn reuse(&self) {
        reuse_word(&self.ident, 2);
        self.payload.with_mut(|row| {
            // SAFETY: a zero count proves no right and no anchor; loom checks
            // the claim against every reader access.
            unsafe { *row = POISON }
        });
        self.fingerprint.store(!KEY_HASH, Ordering::Relaxed);
        self.ident.fetch_xor(
            SlotState::Filling.bits() ^ SlotState::Resident.bits(),
            Ordering::Relaxed,
        );
        self.ident.fetch_add(REF, Ordering::Release);
    }
}

struct Slot {
    era: AtomicU64,
    certified: AtomicU64,
    /// One past the highest record claimed; a pass visits the records below.
    claimed: AtomicUsize,
    records: [AtomicU64; READERS],
    bucket: AtomicU64,
    record: ModelRecord,
    anchor_released: AtomicBool,
}

impl Slot {
    fn new() -> Self {
        Self {
            era: AtomicU64::new(ERA_FIRST),
            certified: AtomicU64::new(0),
            claimed: AtomicUsize::new(0),
            records: [AtomicU64::new(INACTIVE), AtomicU64::new(INACTIVE)],
            bucket: AtomicU64::new(X),
            record: ModelRecord::resident(PAYLOAD),
            anchor_released: AtomicBool::new(false),
        }
    }
}

/// Which bug the model injects, if any.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    /// The writer releases the anchor when it removes visibility.
    ReleaseAtUnlink,
    /// The maintainer certifies after visiting only the first record.
    CertifyIncomplete,
    /// The maintainer decrements the count twice for one anchor.
    DoubleRelease,
    /// The maintainer loads the claimed bound before its start era.
    BoundBeforeStart,
    /// The anchor's exchange succeeds with `Release` alone.
    ReleaseOnlyAnchor,
    /// The reader releases its right `Relaxed`.
    RelaxedRight,
    /// Service sights the word `Relaxed`.
    RelaxedSighting,
    /// The reader releases its right `Relaxed`, and service reuses only
    /// from the count a sighting read, so a later visit's sighting, a
    /// reclaimer's or the pass after the joins, performs the reuse an
    /// anchor-last exchange would.
    RelaxedRightReaderLast,
}

/// A registration's claim of `record`: the claimed bound covers the record
/// before its first pin, raised only when the load finds it short. The
/// accesses and the fence stand for production's `SeqCst` load and
/// read-modify-write followed, in program order, by the pin's `SeqCst` era
/// load.
fn claim(slot: &Slot, record: usize) {
    if slot.claimed.load(Ordering::Acquire) <= record {
        slot.claimed.fetch_max(record + 1, Ordering::AcqRel);
    }
    fence(Ordering::SeqCst);
}

fn reader<S: ModelStrength>(slot: &Slot, record: usize) {
    reader_at::<S>(slot, record, Ordering::Release, Span::Interval);
}

/// How long a reader's right lasts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Span {
    /// Within the reader's interval: it releases the right, then unpins.
    Interval,
    /// Past the interval, as a lease's does: it unpins, then reads the
    /// payload and releases the right.
    Lease,
}

/// [`reader`] with its right released at `release` and lasting `span`; a
/// leased right lets the anchor's release overlap it.
fn reader_at<S: ModelStrength>(slot: &Slot, record: usize, release: Ordering, span: Span) {
    claim(slot, record);
    pin::<_, S>(&slot.era, &slot.records[record]).unwrap();
    if slot.bucket.load(S::OBSERVE) == X {
        // Inside the interval the identity copied is protected: the anchor
        // is still counted, so retaining a right lands on incarnation one.
        assert!(
            !slot.anchor_released.load(Ordering::SeqCst),
            "protection violated: anchor released under a pinned reader"
        );
        assert!(
            retain_word(
                &slot.record.ident,
                slot.record.ident.load(Ordering::Acquire),
                1
            ),
            "protection violated: a pinned reader's retain refused: slot reused or anchor gone"
        );
        let read_and_release = || {
            slot.record.payload.with(|payload| {
                // SAFETY: a counted right keeps the cell unwritten; loom
                // reports a concurrent overwrite as a causality violation.
                assert_eq!(unsafe { *payload }, PAYLOAD)
            });
            slot.record.ident.fetch_sub(REF, release);
        };
        match span {
            Span::Interval => {
                read_and_release();
                unpin(&slot.records[record]);
            }
            Span::Lease => {
                unpin(&slot.records[record]);
                read_and_release();
            }
        }
    } else {
        unpin(&slot.records[record]);
    }
}

fn writer<S: ModelStrength>(slot: &Slot, fault: Fault) {
    slot.bucket.store(NONE, S::COMMIT);
    if fault == Fault::ReleaseAtUnlink {
        slot.anchor_released.store(true, Ordering::SeqCst);
        slot.record.ident.fetch_sub(REF, Ordering::AcqRel);
        return;
    }
    let stamp = bump::<_, S>(&slot.era);
    slot.record.stamp(stamp.retire_era);
    // The retirement's park: the stamp is published by the exchange that
    // sets the anchored flag.
    assert!(park_word(&slot.record.ident, 1, ANCHORED));
}

/// The anchor's release from `sighted`, and in the double-release control
/// a second decrement for the same anchor, whose count must still be
/// positive; returns the count left and whether the exchange retried.
fn release_once(slot: &Slot, sighted: u64, fault: Fault) -> (usize, bool) {
    let success = if fault == Fault::ReleaseOnlyAnchor {
        Ordering::Release
    } else {
        Ordering::AcqRel
    };
    let (left, retried) = release_anchor_word_at(&slot.record.ident, sighted, success);
    if fault == Fault::DoubleRelease {
        let previous = slot.record.ident.fetch_sub(REF, Ordering::AcqRel);
        assert!(
            word::refs(previous) >= 1,
            "protection violated: anchor released twice"
        );
        return (word::refs(previous) - 1, retried);
    }
    (left, retried)
}

/// Which release left the count a reuse read at zero.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Last {
    /// The anchor's exchange, with every right already released.
    Anchor,
    /// The last right's release, after the anchor's exchange.
    Right,
}

/// How a service visit ended: the release that let it reuse the slot, if
/// it did, and whether the anchor's exchange retried.
#[derive(Default, Clone, Copy)]
struct Reclaimed {
    reused: Option<Last>,
    retried: bool,
}

/// The anchor's release from `sighted` when the word is anchored and its
/// stamp lies below `certified`: the count the exchange left and whether it
/// retried, or `None` otherwise.
fn release_if_releasable(
    slot: &Slot,
    sighted: u64,
    certified: u64,
    fault: Fault,
) -> Option<(usize, bool)> {
    let releasable = sighted & ANCHORED != 0
        && super::grace::releasable(slot.record.fingerprint.load(Ordering::SeqCst), certified);
    releasable.then(|| {
        slot.anchor_released.store(true, Ordering::SeqCst);
        release_once(slot, sighted, fault)
    })
}

/// One service visit of the slot from one load of its word, `Acquire`
/// except in the relaxed-sighting control: the anchor's release when
/// [`release_if_releasable`] allows it, then the reuse a zero count allows,
/// the count the anchor's exchange left or the one the sighting read. The
/// word's count holds the anchor until its release and the next
/// incarnation's anchor after a reuse, so a zero count is incarnation one's
/// last release.
fn service(slot: &Slot, certified: u64, fault: Fault) -> Reclaimed {
    let sighting = if fault == Fault::RelaxedSighting {
        Ordering::Relaxed
    } else {
        Ordering::Acquire
    };
    let sighted = slot.record.ident.load(sighting);
    let (left, last, retried) = match release_if_releasable(slot, sighted, certified, fault) {
        Some((left, retried)) => (left, Last::Anchor, retried),
        None => (word::refs(sighted), Last::Right, false),
    };
    let deferred = fault == Fault::RelaxedRightReaderLast && last == Last::Anchor;
    let reuse = left == 0 && word::incarnation(sighted) == 1 && !deferred;
    if reuse {
        slot.record.reuse();
    }
    Reclaimed {
        reused: reuse.then_some(last),
        retried,
    }
}

/// One certification pass over the records below the claimed bound, then
/// one service visit of the slot.
fn maintain<S: Strength>(slot: &Slot, fault: Fault) -> Reclaimed {
    let early = (fault == Fault::BoundBeforeStart).then(|| slot.claimed.load(Ordering::Acquire));
    let mut cursor = PassCursor::begin::<_, S>(&slot.era);
    let bound = early.unwrap_or_else(|| slot.claimed.load(Ordering::Acquire));
    let visited = if fault == Fault::CertifyIncomplete {
        bound.min(1)
    } else {
        bound
    };
    for record in &slot.records[..visited] {
        cursor.visit::<_, S>(record);
    }
    let certified = cursor.complete::<_, S>(visited, &slot.certified);
    service(slot, certified, fault)
}

/// The slot's incarnation.
fn incarnation(slot: &Slot) -> u32 {
    word::incarnation(slot.record.ident.load(Ordering::SeqCst))
}

fn model<S: ModelStrength + 'static>(fault: Fault) {
    // Executions, counted outside the model, in which the concurrent
    // maintainer reuses with the anchor last, and in which its anchor
    // exchange failed against a concurrent write and retried.
    let histories: StdArc<[StdUsize; 2]> = StdArc::new(Default::default());
    let reached = StdArc::clone(&histories);
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        let right = if fault == Fault::RelaxedRight {
            Ordering::Relaxed
        } else {
            Ordering::Release
        };
        let slot = Rc::new(Slot::new());
        let other = {
            let slot = Rc::clone(&slot);
            thread::spawn(move || reader_at::<S>(&slot, 1, right, Span::Lease))
        };
        let writer = {
            let slot = Rc::clone(&slot);
            thread::spawn(move || writer::<S>(&slot, fault))
        };
        let maintainer = {
            let slot = Rc::clone(&slot);
            thread::spawn(move || maintain::<S>(&slot, fault))
        };
        reader_at::<S>(&slot, 0, right, Span::Interval);
        other.join().unwrap();
        writer.join().unwrap();
        let first = maintainer.join().unwrap();
        // With every reader gone, one more pass releases and reuses. A slot
        // left unreused means a right was lost to an anchor released under
        // it, which only a protection failure allows.
        maintain::<S>(&slot, Fault::None);
        reached[0].fetch_add(
            usize::from(first.reused == Some(Last::Anchor)),
            Ordering::Relaxed,
        );
        reached[1].fetch_add(usize::from(first.retried), Ordering::Relaxed);
        if fault != Fault::ReleaseAtUnlink {
            assert_eq!(
                incarnation(&slot),
                2,
                "protection violated: a right was lost and the slot never reused"
            );
        }
    });
    if fault == Fault::None {
        let [anchor_last, retried] = histories
            .each_ref()
            .map(|count| count.load(Ordering::Relaxed));
        assert!(
            anchor_last > 0,
            "no explored execution reused with the anchor last"
        );
        assert!(
            retried > 0,
            "no explored execution retried the anchor's exchange"
        );
    }
}

/// A reader that gives its record up after one interval, so a second
/// claimant pins the same record with its announcement delayed: the era load
/// and the pin store are separated by a yield, and both claimants make the
/// protected observation.
fn reader_reusing_record<S: ModelStrength>(slot: &Slot, record: usize) {
    reader::<S>(slot, record);
    // The second claimant of the same record, announcing late.
    claim(slot, record);
    let now = slot.era.load(S::ERA_LOAD);
    thread::yield_now();
    if now >= S::TERMINAL {
        return;
    }
    assert_eq!(slot.records[record].load(Ordering::Relaxed), INACTIVE);
    slot.records[record].store(now, S::PIN_STORE);
    S::fence_pin();
    if slot.bucket.load(S::OBSERVE) == X {
        assert!(
            !slot.anchor_released.load(Ordering::SeqCst),
            "protection violated: anchor released under a delayed pinned reader"
        );
        assert!(
            retain_word(
                &slot.record.ident,
                slot.record.ident.load(Ordering::Acquire),
                1
            ),
            "protection violated: a delayed reader's retain refused: slot reused or anchor gone"
        );
        slot.record.ident.fetch_sub(REF, Ordering::Release);
    }
    unpin(&slot.records[record]);
}

/// One reader reusing its record with a delayed announcement while the
/// writer and the maintainer run, then the reuse pass.
fn model_reused_registration<S: ModelStrength + 'static>() {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(move || {
        let slot = Rc::new(Slot::new());
        let writer = {
            let slot = Rc::clone(&slot);
            thread::spawn(move || writer::<S>(&slot, Fault::None))
        };
        let maintainer = {
            let slot = Rc::clone(&slot);
            thread::spawn(move || maintain::<S>(&slot, Fault::None))
        };
        reader_reusing_record::<S>(&slot, 0);
        writer.join().unwrap();
        maintainer.join().unwrap();
        maintain::<S>(&slot, Fault::None);
        assert_eq!(incarnation(&slot), 2);
    });
}

/// The maintenance gate with the pass cursor it protects, and the model's
/// independent ledgers: gate attempts observed, publications made, and who
/// began the pass that was published.
struct Collectors {
    slot: Slot,
    gate: Mutex<PassCursor>,
    attempts_observed: AtomicUsize,
    published: AtomicUsize,
    /// The collector that began the pass in progress, plus one.
    began_by: AtomicUsize,
    /// Set once some execution had one collector begin a pass and the other
    /// publish it: the handoff the kernel exists to explore was reached. A
    /// `std` atomic owned by one `model_collectors` call, so it survives
    /// across loom's executions and is read by no other test.
    handoff_reached: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// The allowance one collector call carries, the production minimum; the
/// kernel debits the gate attempt and one visit from it.
const COLLECTOR_CALL: usize = super::release::certify_minimum(READERS);

/// One collector, `who` being 1 or 2: calls funded for exactly one visit
/// each, until the pass it took part in has published. A busy attempt is
/// charged unless `charge_busy` is off, the kernel's negative control.
/// Returns the attempts it charged.
fn collector<S: Strength>(shared: &Collectors, who: usize, charge_busy: bool) -> usize {
    let mut charged = 0;
    let mut calls = 0;
    while shared.published.load(Ordering::SeqCst) == 0 && calls <= READERS + 1 {
        calls += 1;
        let mut budget = WorkBudget::new(COLLECTOR_CALL);
        shared.attempts_observed.fetch_add(1, Ordering::SeqCst);
        let Ok(mut cursor) = shared.gate.try_lock() else {
            if charge_busy {
                budget.debit(WorkKind::CoordinationAttempt).unwrap();
                charged += 1;
            }
            thread::yield_now();
            continue;
        };
        budget.debit(WorkKind::CoordinationAttempt).unwrap();
        charged += 1;
        if !cursor.in_progress() {
            *cursor = PassCursor::begin::<_, S>(&shared.slot.era);
            shared.began_by.store(who, Ordering::SeqCst);
        }
        budget.debit(WorkKind::Visit).unwrap();
        let next = cursor.next;
        cursor.visit::<_, S>(&shared.slot.records[next]);
        // Assertions run after the gate is released: a panic under a loom
        // mutex guard aborts the model instead of reporting.
        let mut published = None;
        if cursor.next == READERS {
            let expected = cursor.bound();
            let before = shared.slot.certified.load(Ordering::SeqCst);
            let certified = cursor.complete::<_, S>(READERS, &shared.slot.certified);
            published = Some((before, expected, certified));
            shared.published.fetch_add(1, Ordering::SeqCst);
            if shared.began_by.load(Ordering::SeqCst) != who {
                shared.handoff_reached.store(true, Ordering::SeqCst);
            }
            *cursor = PassCursor::IDLE;
            // Service under the same gate: release the anchor if eligible.
            let slot = &shared.slot;
            let sighted = slot.record.ident.load(Ordering::Acquire);
            release_if_releasable(slot, sighted, certified, Fault::None);
        }
        drop(cursor);
        if let Some((before, expected, certified)) = published {
            // The publication is the pass's own bound, min(start, minimum
            // pin), never below what was certified before.
            assert_eq!(certified, before.max(expected), "published a foreign bound");
        }
    }
    charged
}

/// Two collectors handing the cursor off across calls of one visit each,
/// while both readers and the writer run; the collectors' charged attempts
/// are compared with the attempts observed.
fn model_collectors<S: ModelStrength + 'static>(charge_busy: bool) {
    let handoff_reached = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reached = std::sync::Arc::clone(&handoff_reached);
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(move || {
        let shared = Rc::new(Collectors {
            slot: Slot::new(),
            gate: Mutex::new(PassCursor::IDLE),
            attempts_observed: AtomicUsize::new(0),
            published: AtomicUsize::new(0),
            began_by: AtomicUsize::new(0),
            handoff_reached: std::sync::Arc::clone(&reached),
        });
        let other = {
            let shared = Rc::clone(&shared);
            thread::spawn(move || reader::<S>(&shared.slot, 1))
        };
        let writer = {
            let shared = Rc::clone(&shared);
            thread::spawn(move || writer::<S>(&shared.slot, Fault::None))
        };
        let second = {
            let shared = Rc::clone(&shared);
            thread::spawn(move || collector::<S>(&shared, 2, charge_busy))
        };
        reader::<S>(&shared.slot, 0);
        let first = collector::<S>(&shared, 1, charge_busy);
        other.join().unwrap();
        writer.join().unwrap();
        let second = second.join().unwrap();
        // With every reader gone, one more complete pass releases and reuses.
        shared.published.store(0, Ordering::SeqCst);
        let rest = collector::<S>(&shared, 1, true);
        maintain::<S>(&shared.slot, Fault::None);
        assert_eq!(incarnation(&shared.slot), 2);
        assert!(
            shared.attempts_observed.load(Ordering::SeqCst) <= first + second + rest,
            "protection violated: gate attempts observed exceed attempts charged"
        );
    });
    assert!(
        handoff_reached.load(Ordering::SeqCst),
        "no explored execution handed the pass from one collector to the other"
    );
}

/// The terminal kernel's words: the era, the cutoff, per-slot stamps and
/// marks, the pool gate, and the admission ledger.
struct Band {
    era: AtomicU64,
    closed: AtomicBool,
    /// Per slot: `0` while resident, `stamp + 1` once retired and marked.
    marked: [AtomicU64; 2],
    /// Per slot: whether service returned it, under the gate.
    free: [AtomicBool; 2],
    gate: Mutex<()>,
}

/// Which retirements close admission: the production rule, every stamp in
/// the band; or one of the two negative controls.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CloseRule {
    /// Every retirement stamped `TERMINAL - 1` or above closes.
    EveryBandStamp,
    /// Only the bump that crosses into the band closes.
    CrossingOnly,
    /// No retirement closes.
    Never,
}

/// One retirement in the tiny band: the bump, the close the rule owes, then
/// the published mark.
fn band_writer(band: &Band, slot: usize, rule: CloseRule) {
    let stamp = bump::<_, TinyBand>(&band.era);
    let closes = match rule {
        CloseRule::EveryBandStamp => stamp.closes_admission,
        CloseRule::CrossingOnly => stamp.retire_era + 1 == TINY_TERMINAL,
        CloseRule::Never => false,
    };
    if closes {
        band.closed.store(true, Ordering::SeqCst);
    }
    band.marked[slot].store(stamp.retire_era + 1, Ordering::Release);
}

/// Service under the gate: every marked slot is returned.
fn band_service(band: &Band) {
    let _gate = band.gate.lock().unwrap();
    for slot in 0..2 {
        if band.marked[slot].load(Ordering::Acquire) != 0 {
            band.free[slot].store(true, Ordering::SeqCst);
        }
    }
}

/// One allocation: the early cutoff read, the gate, the recheck under it,
/// then the claim of the first free slot. Claiming a slot whose stamp lies
/// in the band is the violation.
fn band_allocator(band: &Band) {
    if band.closed.load(Ordering::SeqCst) {
        return;
    }
    let gate = band.gate.lock().unwrap();
    let mut claimed = None;
    if !band.closed.load(Ordering::SeqCst) {
        for slot in 0..2 {
            if band.free[slot].load(Ordering::SeqCst) {
                claimed = Some(band.marked[slot].load(Ordering::Acquire) - 1);
                band.free[slot].store(false, Ordering::SeqCst);
                break;
            }
        }
    }
    drop(gate);
    // Asserted after the gate is released, as in the collector kernel.
    if let Some(stamp) = claimed {
        assert!(
            stamp < TINY_TERMINAL - 1,
            "protection violated: a terminal-band retirement recycled into a new admission"
        );
    }
}

/// Two retirements, one crossing into the tiny band and one inside it,
/// interleaved with two allocation attempts and two service calls; the era
/// never leaves the band's reserve.
fn model_terminal_band(rule: CloseRule) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(move || {
        let band = Rc::new(Band {
            era: AtomicU64::new(TINY_TERMINAL - 1),
            closed: AtomicBool::new(false),
            marked: [AtomicU64::new(0), AtomicU64::new(0)],
            free: [AtomicBool::new(false), AtomicBool::new(false)],
            gate: Mutex::new(()),
        });
        let first = {
            let band = Rc::clone(&band);
            thread::spawn(move || band_writer(&band, 0, rule))
        };
        let second = {
            let band = Rc::clone(&band);
            thread::spawn(move || {
                band_writer(&band, 1, rule);
                band_service(&band);
            })
        };
        band_allocator(&band);
        band_service(&band);
        band_allocator(&band);
        first.join().unwrap();
        second.join().unwrap();
        // Two retirements from the era below the band: one stamp crosses,
        // one lands inside, and the counter stops one past the band's first
        // value, never wrapping.
        assert_eq!(band.era.load(Ordering::SeqCst), TINY_TERMINAL + 1);
        assert!(band.closed.load(Ordering::SeqCst) || rule == CloseRule::Never);
    });
}

/// The fenced strength with the certificate published `Relaxed`.
struct WeakPublish;

impl Strength for WeakPublish {
    const ERA_LOAD: Ordering = <Fenced as Strength>::ERA_LOAD;
    const PIN_STORE: Ordering = <Fenced as Strength>::PIN_STORE;
    const BUMP: Ordering = <Fenced as Strength>::BUMP;
    const START: Ordering = <Fenced as Strength>::START;
    const VISIT: Ordering = <Fenced as Strength>::VISIT;
    const PUBLISH: Ordering = Ordering::Relaxed;

    fn fence_pin() {
        Fenced::fence_pin();
    }

    fn fence_retire() {
        Fenced::fence_retire();
    }

    fn fence_certify() {
        Fenced::fence_certify();
    }
}

/// The certificate handoff's state: the slot, the production pool gate over
/// a loom word, the pass report the certifier writes before it publishes
/// the certificate, and the gate-held count of the slot's returns.
struct Handoff<W: GateWord> {
    slot: Slot,
    gate: Gate<W>,
    report: UnsafeCell<u64>,
    returns: UnsafeCell<u32>,
}

/// The certifier: one pass over the records below the claimed bound, whose
/// report, the bound its pin reads computed, it writes before the
/// production `complete` publishes the certificate at `P::PUBLISH`.
fn certifier<P: Strength>(handoff: &Handoff<impl GateWord>) {
    let slot = &handoff.slot;
    let mut cursor = PassCursor::begin::<_, P>(&slot.era);
    let bound = slot.claimed.load(Ordering::Acquire);
    for record in &slot.records[..bound] {
        cursor.visit::<_, P>(record);
    }
    let report = cursor.bound();
    handoff.report.with_mut(|cell| {
        // SAFETY: only the certifier writes the report, before publishing.
        unsafe { *cell = report }
    });
    cursor.complete::<_, P>(bound, &slot.certified);
}

/// What one reclaimer's gate attempt did: found the gate held, or held it
/// and reused the slot through the release `Last` names, if it did.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Attempt {
    Contended,
    Held(Option<Last>),
}

/// A reclaimer: one attempt at the production pool gate. Holding it, the
/// reclaimer acquires the certificate at `acquire`, reads the certifier's
/// report, releases the anchor and reuses the slot as one service visit
/// allows, and counts the return in the gate-held table every holder
/// reads.
fn reclaimer<W: GateWord>(handoff: &Handoff<W>, acquire: Ordering, fault: Fault) -> Attempt {
    let Ok(guard) = handoff.gate.try_lock() else {
        return Attempt::Contended;
    };
    let certified = handoff.slot.certified.load(acquire);
    let mut reused = None;
    if certified != 0 {
        let report = handoff.report.with(|cell| {
            // SAFETY: the certificate's publication orders the report's
            // write before this read; loom reports a missing edge.
            unsafe { *cell }
        });
        assert_eq!(report, certified, "a certificate without its pass's report");
        reused = service(&handoff.slot, certified, fault).reused;
    }
    let returns = handoff.returns.with_mut(|cell| {
        // SAFETY: the gate orders every holder's access to the table.
        unsafe {
            *cell += u32::from(reused.is_some());
            *cell
        }
    });
    guard.release();
    assert!(returns <= 1, "protection violated: the slot returned twice");
    Attempt::Held(reused)
}

/// Executions of the handoff kernel, counted outside the model: a
/// reclaimer found the gate held, both reclaimers held it in turn, and a
/// reclaimer reused with the anchor last and with the last right's release
/// last.
#[derive(Default)]
struct HandoffWitnesses {
    contended: StdUsize,
    both: StdUsize,
    anchor_last: StdUsize,
    reader_last: StdUsize,
}

/// A distinct certifier and two reclaimers behind the production gate, the
/// first making two attempts and the second one, beside the writer's
/// retirement and a reader on its own thread whose right outlives its
/// interval; with every actor joined, one more pass and
/// service visit finish the reuse. `fault` reaches the reader's right
/// release and the reclaimers' service visits.
fn model_handoff<P: Strength + 'static, W: GateWord + Send + Sync + 'static>(
    gate: fn(u32) -> W,
    acquire: Ordering,
    fault: Fault,
) {
    let witnesses: StdArc<HandoffWitnesses> = StdArc::new(HandoffWitnesses::default());
    let reached = StdArc::clone(&witnesses);
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(move || {
        let handoff = Rc::new(Handoff {
            slot: Slot::new(),
            gate: Gate::open_over(gate),
            report: UnsafeCell::new(0),
            returns: UnsafeCell::new(0),
        });
        let right = if matches!(fault, Fault::RelaxedRight | Fault::RelaxedRightReaderLast) {
            Ordering::Relaxed
        } else {
            Ordering::Release
        };
        let reader = {
            let handoff = Rc::clone(&handoff);
            thread::spawn(move || reader_at::<Fenced>(&handoff.slot, 0, right, Span::Lease))
        };
        let writer = {
            let handoff = Rc::clone(&handoff);
            thread::spawn(move || writer::<Fenced>(&handoff.slot, Fault::None))
        };
        let certifier = {
            let handoff = Rc::clone(&handoff);
            thread::spawn(move || certifier::<P>(&handoff))
        };
        let first = {
            let handoff = Rc::clone(&handoff);
            thread::spawn(move || {
                let early = reclaimer(&handoff, acquire, fault);
                [early, reclaimer(&handoff, acquire, fault)]
            })
        };
        let second = reclaimer(&handoff, acquire, fault);
        let [early, late] = first.join().unwrap();
        let attempts = [early, late, second];
        reader.join().unwrap();
        writer.join().unwrap();
        certifier.join().unwrap();
        for (count, reached_here) in [
            (&reached.contended, attempts.contains(&Attempt::Contended)),
            (
                &reached.both,
                attempts[1] != Attempt::Contended && attempts[2] != Attempt::Contended,
            ),
            (
                &reached.anchor_last,
                attempts.contains(&Attempt::Held(Some(Last::Anchor))),
            ),
            (
                &reached.reader_last,
                attempts.contains(&Attempt::Held(Some(Last::Right))),
            ),
        ] {
            count.fetch_add(usize::from(reached_here), Ordering::Relaxed);
        }
        maintain::<Fenced>(&handoff.slot, Fault::None);
        assert_eq!(
            incarnation(&handoff.slot),
            2,
            "protection violated: a right was lost and the slot never reused"
        );
    });
    if fault == Fault::None {
        let [contended, both, anchor_last, reader_last] = [
            &witnesses.contended,
            &witnesses.both,
            &witnesses.anchor_last,
            &witnesses.reader_last,
        ]
        .map(|count| count.load(Ordering::Relaxed));
        assert!(contended > 0, "no explored execution found the gate held");
        assert!(
            both > 0,
            "no explored execution handed the gate from one reclaimer to the other"
        );
        assert!(anchor_last > 0, "no reclaimer reused with the anchor last");
        assert!(
            reader_last > 0,
            "no reclaimer reused with the last right's release last"
        );
    }
}

/// The gate's production word over a loom atomic.
fn loom_gate(open: u32) -> AtomicU32 {
    AtomicU32::new(open)
}

#[test]
fn a_certificate_handed_from_certifier_to_reclaimers_releases_once() {
    model_handoff::<Fenced, _>(loom_gate, Ordering::Acquire, Fault::None);
}

#[test]
#[should_panic(expected = "Causality violation")]
fn negative_control_a_relaxed_certificate_publication_loses_the_report() {
    model_handoff::<WeakPublish, _>(loom_gate, Ordering::Acquire, Fault::None);
}

#[test]
#[should_panic(expected = "Causality violation")]
fn negative_control_a_relaxed_certificate_acquisition_loses_the_report() {
    model_handoff::<Fenced, _>(loom_gate, Ordering::Relaxed, Fault::None);
}

#[test]
#[should_panic(expected = "Causality violation")]
fn negative_control_a_relaxed_gate_release_races_the_next_holder() {
    model_handoff::<Fenced, _>(
        |open| WeakGate::<_, false>(loom_gate(open)),
        Ordering::Acquire,
        Fault::None,
    );
}

#[test]
#[should_panic(expected = "Causality violation")]
fn negative_control_a_relaxed_gate_take_races_the_previous_holder() {
    model_handoff::<Fenced, _>(
        |open| WeakGate::<_, true>(loom_gate(open)),
        Ordering::Acquire,
        Fault::None,
    );
}

#[test]
#[should_panic(expected = "Causality violation")]
fn negative_control_a_relaxed_service_sighting_reuses_under_a_read() {
    model_handoff::<Fenced, _>(loom_gate, Ordering::Acquire, Fault::RelaxedSighting);
}

#[test]
#[should_panic(expected = "Causality violation")]
fn negative_control_a_relaxed_right_release_races_the_reader_last_reuse() {
    model_handoff::<Fenced, _>(loom_gate, Ordering::Acquire, Fault::RelaxedRightReaderLast);
}

#[test]
fn pinned_readers_never_observe_a_released_anchor_or_a_reused_slot() {
    model::<Fenced>(Fault::None);
}

#[test]
fn two_collectors_hand_the_cursor_off_and_publish_only_a_complete_pass() {
    model_collectors::<Fenced>(true);
}

#[test]
#[should_panic(expected = "protection violated")]
fn negative_control_an_uncharged_busy_attempt_fails() {
    model_collectors::<Fenced>(false);
}

#[test]
fn a_reused_record_with_a_delayed_announcement_stays_protected() {
    model_reused_registration::<Fenced>();
}

#[test]
fn terminal_band_retirements_close_before_any_recycled_admission() {
    model_terminal_band(CloseRule::EveryBandStamp);
}

#[test]
#[should_panic(expected = "protection violated")]
fn negative_control_closing_only_on_the_crossing_bump_fails() {
    model_terminal_band(CloseRule::CrossingOnly);
}

#[test]
#[should_panic(expected = "protection violated")]
fn negative_control_a_band_retirement_that_never_closes_fails() {
    model_terminal_band(CloseRule::Never);
}

#[test]
#[should_panic(expected = "protection violated")]
fn negative_control_releasing_the_anchor_twice_fails() {
    model::<Fenced>(Fault::DoubleRelease);
}

#[test]
#[should_panic(expected = "protection violated")]
fn negative_control_releasing_the_anchor_at_unlink_fails() {
    model::<Fenced>(Fault::ReleaseAtUnlink);
}

#[test]
#[should_panic(expected = "protection violated")]
fn negative_control_certifying_from_an_incomplete_pass_fails() {
    model::<Fenced>(Fault::CertifyIncomplete);
}

#[test]
#[should_panic(expected = "protection violated")]
fn negative_control_loading_the_claimed_bound_before_the_start_era_fails() {
    model::<Fenced>(Fault::BoundBeforeStart);
}

#[test]
#[should_panic(expected = "protection violated")]
fn negative_control_weakening_the_pin_point_fails() {
    model::<WeakPin>(Fault::None);
}

#[test]
#[should_panic(expected = "Causality violation")]
fn negative_control_an_anchor_exchange_without_acquire_reuses_under_a_read() {
    model::<Fenced>(Fault::ReleaseOnlyAnchor);
}

#[test]
#[should_panic(expected = "Causality violation")]
fn negative_control_a_relaxed_right_release_reuses_under_a_read() {
    model::<Fenced>(Fault::RelaxedRight);
}

#[test]
#[should_panic(expected = "pinned reader")]
fn negative_control_fencing_only_the_reader_fails() {
    model::<ReaderFencedAlone>(Fault::None);
}
