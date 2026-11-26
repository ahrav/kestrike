//! Fixed allocation structures of the volume, laid out in its control
//! mapping and mutated only under the pool gate.
//!
//! Every table is sized once from the validated configuration and never moves
//! or grows.
//! Links are indices into these tables, never pointers and never bytes inside
//! payload. The free slots form the `free` module's set: a claim takes the lowest free slot of
//! its key's placement window, or the first free slot after it, and a claim
//! without a key takes the first free slot at or after the claim cursor; a
//! return gives the slot back to the set and a reservation refused after its
//! claim gives its slot back unchanged.
//!
//! Allocator paths take exclusive access with one nonblocking `try_lock` on
//! the [`Gate`]; reports may wait on it. A holder gets a [`Tables`] view
//! whose slices borrow disjoint fields, so no two views alias, and builds its
//! [`ExtentAllocator`] over the three extent tables from that view. The view
//! derives the sequence arena's three tables from the layout.
//! The records, the failed-try counter and the parked-slot bitmap with its
//! summary hold only atomics, which gate-independent paths also read and
//! write, so they sit apart from the [`Tables`] view's exclusive slices: the
//! view borrows the records and the parked tables shared, the records for
//! the policy's `prev` links and bits. The record's fingerprint identifies the
//! object in RAM; the full key lives in the record's header on the device,
//! which a volume read checks against the key it was started for. The retired bitmap
//! holds one bit per slot, set exactly while the slot's state is `Retired`,
//! and its summary one bit per bitmap word, set exactly while that word is
//! nonzero; both are read and written only under the gate, in the same hold
//! as the state, so a search for the next retired slot skips a whole
//! unmarked word per summary bit. The waiting bitmap holds one bit per
//! slot beside the retired bitmap, set and cleared under the gate by
//! service for the retired slots its retired pass leaves unvisited. The
//! parked-slot bitmap holds one atomic
//! bit per slot, set by a park after its exchange sets the slot's
//! abandonment flag and cleared by the gate holder that absorbs or returns
//! that park, or finds the bit stale beside a clear flag or beside the
//! retired flag of a retirement that absorbed the park, and its summary one
//! atomic bit per bitmap word, set by the park after the slot's bit and
//! repaired by a search that finds the word zero; the `pending` module
//! states the protocol. A search for the next flagged slot therefore reads
//! summary and bitmap words and loads a record's word only behind a set
//! parked bit.
//! Only the gate holder, or a restore lane worker it starts and joins within
//! its hold (`word` module), changes a slot's incarnation or state: the claim
//! installs the next incarnation after the slot's extent is reserved. A
//! registered reader loads the slot's word without the gate to reject a
//! stale copied identity, a zero count and a malformed word before reading
//! the slot's other record fields.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::allocation::AllocationId;
use super::blocks::Block;
use super::blocks::{ArenaLists, BIT_WORDS, BlockArena, ROOT_WORDS};
use super::config::ValidatedConfig;
use super::control::{ControlLayout, ControlLayoutOverflow, Field};
use super::extent::{
    ExtentAllocator, ExtentLocator, ExtentRoot, HeldPhase, RunNode, index_capacity,
    index_table_nodes, space_words,
};
use super::free::{self, FreeSlots};
use super::gate::{Gate, GateError, GateGuard};
use super::held::Held;
use super::layout::IO_UNIT;
use super::ledger::SlotPartition;
use super::mapping::Mapping;
use super::policy::{Domain, POLICY_NONE, PendingMark, Queue};
use super::portable::PortableExpiry;
use super::prefetch::{LINE, hint, hint_read};
use super::recovery::{JournalHold, JournalWords, NO_RECORD};
use super::slot::Record;
use super::volume::VolumeWatermarks;
use super::word;

mod lanes;
pub use super::word::SlotState;
pub(crate) use lanes::{Folded, Lane, lane_len};

/// Panic message for a sequence block that refuses its slot's own
/// incarnation, which only a corrupt record produces: the block's owner is
/// the slot's incarnation from its claim.
pub(crate) const SEQUENCE_REFUSED: &str =
    "a slot's sequence block refuses the slot's own incarnation";

pub(crate) const EXTENT_REFUSED: &str =
    "a slot's extent or its ledger phase does not match its record";

/// Returns the extent `locator` names, whose `payload` bytes sit in `phase`,
/// to the free set.
#[inline(always)]
pub(crate) fn release_extent(
    extents: &mut ExtentAllocator<'_>,
    locator: ExtentLocator,
    phase: HeldPhase,
    payload: usize,
) -> usize {
    if extents.release(locator, phase, payload).is_err() {
        panic!("{EXTENT_REFUSED}");
    }
    extents.visits()
}

/// Units of `block`'s held prefix, kept out of line so the direct-extent
/// path of [`Tables::held_units`] stays small.
#[cold]
#[inline(never)]
fn block_units(arena: BlockArena<'_>, block: Block, count: u32, owner: AllocationId) -> u32 {
    prefix_units(arena.prefix(block, owner, count).expect(SEQUENCE_REFUSED))
}

/// Units of a sequence's held `prefix` of locator bits, from its two ends:
/// every extent before the object's last carries a full
/// [`EXTENT_PAYLOAD`](super::geometry::EXTENT_PAYLOAD) and charges the
/// first extent's units, so the prefix charges one multiply of those plus
/// the last held locator's own units, whether or not that locator is the
/// object's last. An empty prefix charges nothing.
#[inline(always)]
pub(crate) fn prefix_units(prefix: &[u64]) -> u32 {
    match (prefix.first(), prefix.last()) {
        (Some(&first), Some(&last)) => {
            let full = ExtentLocator::from_bits(first).len_units();
            (prefix.len() as u32 - 1) * full + ExtentLocator::from_bits(last).len_units()
        }
        _ => 0,
    }
}

/// Position of an object slot in the volume. An index alone confers no access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SlotIndex(pub usize);

/// Mutable volume-wide state: the slot ledger and the cursors.
///
/// Invariant: `ledger` sums to `O` after every transition; the raw-byte
/// ledger lives in the extent root and sums to the volume's raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PoolState {
    pub ledger: SlotPartition,
    /// Where a claim without a placement window starts its search for a
    /// free slot; a claim moves it past the slot it took, wrapping at `O`,
    /// so such claims visit the slots in index order.
    pub cursor_claim: usize,
    /// Resumable position of service's retired pass over the retired set.
    pub cursor_slot: usize,
    /// Resumable position of service's park pass over the parked set.
    pub cursor_park: usize,
    /// The next slot the expiry sweep examines.
    pub cursor_expiry: usize,
    /// No resident's deadline, in whole seconds, lies below this value;
    /// `u32::MAX` before any resident and after a wrap over none. The expiry
    /// sweep skips a sample whose whole seconds lie below it.
    pub earliest_deadline: u32,
    /// The least deadline bound or visited since the expiry cursor last
    /// wrapped; the wrap publishes it as `earliest_deadline`.
    pub pass_earliest: u32,
    /// The number of slots the waiting set marks.
    pub waiting: usize,
    /// The durable prefix the waiting set's marks were made under.
    pub waiting_under: u64,
}

impl PoolState {
    /// Folds a deadline, in whole seconds, that `bind` or a restored install
    /// is making resident into both bounds; `true` when it lowered the
    /// published bound.
    #[inline(always)]
    pub(crate) fn note_deadline(&mut self, deadline: u32) -> bool {
        self.pass_earliest = self.pass_earliest.min(deadline);
        let lowered = deadline < self.earliest_deadline;
        if lowered {
            self.earliest_deadline = deadline;
        }
        lowered
    }
}

/// What the index names for a bound slot beside its key and allocation word: the session of the tenure that wrote the slot's record and the record's cache version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Naming {
    pub(crate) session: u64,
    pub(crate) version: u64,
}

/// Fixed-cardinality atomic counters, readable with or without the gate.
/// The escrow's two terms are the admission counter claims read under the
/// gate.
#[derive(Debug)]
pub(crate) struct Telemetry {
    /// Nonblocking gate attempts that found it busy or poisoned.
    pub failed_tries: AtomicUsize,
    /// Abandoned owners whose ledger transition is still waiting for the
    /// gate. Incremented by a dropping owner, decremented when serviced.
    pub pending_marks: AtomicUsize,
    /// Failed right reservations of test acquisitions under a resident
    /// authority, which reserve outside any registration record; every
    /// lookup counts its own in its registration record.
    pub retains: RetainCounters,
    /// The escrow's gate-held term: units promised to builders, less the
    /// units placed and the charges refunded under the pool gate, in
    /// wrapping arithmetic. Only a gate holder writes it, and the pool gate
    /// serializes each load-and-store update.
    pub promised: AtomicU64,
    /// Remaining charges refunded without the gate, summed in wrapping
    /// arithmetic. Only a refund changes it, with one read-modify-write.
    pub refunded: AtomicU64,
    run_bound: AtomicU64,
}

impl Telemetry {
    /// The escrow `U`: units promised to builders and not yet placed, the
    /// gate-held term less the gate-free refunds.
    ///
    /// Read under the gate, the value bounds `U` from above: the gate-held
    /// term is exact, and the read counts only refunds whose charges
    /// `promised` holds, so a refund it misses only overstates `U`. Read
    /// without the gate, it is a sample: `refunded` is read first, with
    /// acquire, so every refund it counts follows the gate-held write that
    /// left the refunded charge in `promised`.
    #[inline(always)]
    pub(crate) fn escrow(&self) -> u64 {
        let refunded = self.refunded.load(Ordering::Acquire);
        self.promised.load(Ordering::Relaxed).wrapping_sub(refunded)
    }

    /// Adds `units` to the escrow's gate-held term. `_hold` proves the
    /// caller holds the pool gate, which serializes the load and store.
    #[inline(always)]
    pub(crate) fn promise(&self, _hold: &mut Tables<'_>, units: u64) {
        let promised = self.promised.load(Ordering::Relaxed);
        self.promised
            .store(promised.wrapping_add(units), Ordering::Relaxed);
    }

    /// Subtracts `units`, placed or refunded under the pool gate, from the
    /// escrow's gate-held term. `_hold` proves the caller holds the gate.
    #[inline(always)]
    pub(crate) fn settle(&self, _hold: &mut Tables<'_>, units: u64) {
        let promised = self.promised.load(Ordering::Relaxed);
        self.promised
            .store(promised.wrapping_sub(units), Ordering::Relaxed);
    }

    /// Adds `units` to the gate-free refunds with one read-modify-write.
    /// Its release orders the refunder's earlier gate-held writes before
    /// any sample that counts the refund.
    #[inline(always)]
    pub(crate) fn refund(&self, units: u64) {
        self.refunded.fetch_add(units, Ordering::Release);
    }

    #[inline(always)]
    pub(crate) fn run_bound(&self) -> u64 {
        self.run_bound.load(Ordering::Relaxed)
    }
}

/// Right reservations whose compare-exchange failed, counted beside the
/// reader that made them: each registration record holds its own, so a
/// retain that loses its exchange writes its count to its own reader's
/// record line.
#[derive(Debug)]
pub(crate) struct RetainCounters {
    /// Reservations whose compare-exchange saw another writer's value.
    pub lost: AtomicUsize,
    /// Reservations whose weak compare-exchange failed with the expected
    /// value still in place.
    pub stalled: AtomicUsize,
}

impl RetainCounters {
    pub(crate) const fn new() -> Self {
        Self {
            lost: AtomicUsize::new(0),
            stalled: AtomicUsize::new(0),
        }
    }
}

/// Where the tables live inside the control mapping. Fields are private so
/// only this module ever forms a reference into a locked table, which is what
/// the `&mut` slices in [`PoolAccess::tables`] rely on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TableImage {
    gate: Field<Gate>,
    state: Field<PoolState>,
    extent_root: Field<ExtentRoot>,
    /// The free-unit bitmap and its run summaries.
    extent_space: Field<u64>,
    /// The run index's nodes, enough for `slot_count.div_ceil(8)` entries.
    extent_index: Field<RunNode>,
    /// One 32-byte record per slot: the lifetime word, the fingerprint or
    /// retirement era, the locator and the deadline, as the `slot` module
    /// states.
    records: Field<Record>,
    /// The free-slot set's words, every level, as the `free` module lays
    /// them out; read and written only under the gate.
    free_slots: Field<u64>,
    /// One tail per slot: the held record's length modulo [`IO_UNIT`],
    /// written by the claim and read by every ledger move, both under the
    /// gate.
    tails: Field<u16>,
    telemetry: Field<Telemetry>,
    /// One bit per slot, set exactly while the slot's state is `Retired`;
    /// written and read only under the gate, so service can locate retired
    /// slots a word at a time instead of sighting every flag.
    retired: Field<u64>,
    /// One bit per word of `retired`, set exactly while that word is
    /// nonzero, so a search skips 4096 unmarked slots per summary word.
    retired_summary: Field<u64>,
    /// The waiting set: one bit per slot, set under the gate by service's
    /// retired pass, while admission is open, for a retired slot that no
    /// right or anchor holds and whose position lies outside the durable
    /// prefix the pass loaded. The pass leaves a marked slot
    /// unvisited, and a service call that loads another prefix or finds
    /// admission closed clears every mark before its pass.
    waiting: Field<u64>,
    /// One bit per slot, set by a park once its exchange flagged the slot
    /// and cleared by the gate holder that absorbs or returns the park, or
    /// finds the bit stale beside a clear flag or beside the retired flag of
    /// a retirement that absorbed the park.
    parked_slots: Field<AtomicU64>,
    /// One bit per word of `parked_slots`, set by a park after its slot's
    /// bit. A search that finds the word zero clears the bit, loads the
    /// word again, and sets the bit back when a park's bit landed meanwhile.
    parked_summary: Field<AtomicU64>,
    /// One gate-owned policy `next` link per slot.
    policy_next: Field<u32>,
    /// The volume's one policy domain record.
    domain: Field<Domain>,
    /// The volume's one pending removal mark, written by eviction or expiry.
    pending_mark: Field<PendingMark>,
    /// One position word per slot, gate-held.
    positions: Field<AtomicU64>,
    /// The position words' shared words, read without the gate.
    journal_words: Field<JournalWords>,
    /// One 32-byte full key per slot, written by `bind` or the restored install and cleared by the extent's return, gate-held.
    keys: Field<[u8; 32]>,
    /// One portable deadline per slot in nanoseconds, zero for an absent pair, written beside the key and cleared with it, gate-held.
    deadlines: Field<u64>,
    /// One portable lifetime per slot in milliseconds, written and cleared with the deadline, gate-held.
    lifetimes: Field<u32>,
    /// One record generation per slot: the session `g·2^32 + a` that wrote the slot's record. Reads load it without the gate.
    generations: Field<AtomicU64>,
    /// One cache version per slot: the version the slot's record header carries, written beside the record generation and cleared with it, and loaded without the gate by reads.
    versions: Field<AtomicU64>,
    /// Membership steps remain shared across views because `Pool` also exposes them without the gate.
    steps: Field<AtomicU64>,
    /// The headroom watermarks, `None` without maintenance; written once at
    /// initialization.
    watermarks: Field<Option<VolumeWatermarks>>,
    /// The sequence arena's list heads and free granule count.
    block_lists: Field<ArenaLists>,
    /// The sequence arena's roots, 4,096 words each, line-aligned.
    block_words: Field<u64>,
    /// The sequence arena's free and live bits, 48 words per root.
    block_bits: Field<u64>,
}

/// Offset and element count of every table, for inventory checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableInventory {
    pub gate: (usize, usize),
    pub state: (usize, usize),
    /// Offset and count of the extent allocator's root record.
    pub extent_root: (usize, usize),
    /// Offset and count of the extent allocator's space words: the
    /// free-unit bitmap and its run summaries.
    pub extent_space: (usize, usize),
    /// Offset and count of the extent allocator's run index nodes.
    pub extent_index: (usize, usize),
    /// Offset and count of the `O` 32-byte slot records.
    pub records: (usize, usize),
    /// Offset and count of the `O` 2-byte record tails.
    pub tails: (usize, usize),
    /// Offset and count of the free-slot set's words.
    pub free_slots: (usize, usize),
    pub telemetry: (usize, usize),
    /// Offset and count of the words of the retired-slot bitmap, one bit per
    /// slot.
    pub retired: (usize, usize),
    /// Offset and count of the words of its summary, one bit per bitmap
    /// word.
    pub retired_summary: (usize, usize),
    /// Offset and count of the words of the waiting set, one bit per slot.
    pub waiting: (usize, usize),
    /// Offset and count of the words of the parked-slot bitmap, one bit per
    /// slot.
    pub parked_slots: (usize, usize),
    /// Offset and count of the words of its summary, one bit per bitmap
    /// word.
    pub parked_summary: (usize, usize),
    /// Offset and count of the `O` 4-byte policy `next` links.
    pub policy_next: (usize, usize),
    /// Offset and count of the volume's policy domain record.
    pub domain: (usize, usize),
    /// Offset and count of the volume's pending removal mark.
    pub pending_mark: (usize, usize),
    /// Offset and count of the `O` 8-byte position words.
    pub positions: (usize, usize),
    /// Offset and count of the position words' shared words.
    pub journal_words: (usize, usize),
    /// Offset and count of the `O` 32-byte full keys.
    pub keys: (usize, usize),
    /// Offset and count of the `O` 8-byte portable deadlines.
    pub deadlines: (usize, usize),
    /// Offset and count of the `O` 4-byte portable lifetimes.
    pub lifetimes: (usize, usize),
    /// Offset and count of the `O` 8-byte record generations.
    pub generations: (usize, usize),
    /// Offset and count of the `O` 8-byte cache versions.
    pub versions: (usize, usize),
    /// Offset and count of the `O` 8-byte insert steps.
    pub steps: (usize, usize),
    /// Offset and count of the headroom watermark record.
    pub watermarks: (usize, usize),
    /// Offset and count of the sequence arena's list record.
    pub block_lists: (usize, usize),
    /// Offset and count of the sequence arena's root words.
    pub block_words: (usize, usize),
    /// Offset and count of the sequence arena's free-bit and live-bit words.
    pub block_bits: (usize, usize),
}

/// Exclusive, gate-protected view of the volume's tables.
pub(crate) struct Tables<'a> {
    pub state: &'a mut PoolState,
    extent_root: &'a mut ExtentRoot,
    extent_space: &'a mut [u64],
    extent_index: &'a mut [RunNode],
    /// Every slot's record, shared: the policy reads and writes its `prev`
    /// link and bits under this hold.
    records: &'a [Record],
    /// One record tail per slot: `record_len % IO_UNIT` of the extent it holds.
    pub tails: &'a mut [u16],
    /// The free-slot set's words.
    free_slots: &'a mut [u64],
    /// One bit per slot, set exactly while the slot's state is `Retired`.
    pub retired: &'a mut [u64],
    /// One bit per word of `retired`, set exactly while that word is nonzero.
    pub retired_summary: &'a mut [u64],
    /// One bit per slot the waiting set marks.
    pub waiting: &'a mut [u64],
    /// One bit per slot, set by a park without the gate; shared, as the
    /// records are.
    pub parked_slots: &'a [AtomicU64],
    /// One bit per word of `parked_slots`, set by a park without the gate.
    pub parked_summary: &'a [AtomicU64],
    /// One policy `next` link per slot.
    pub policy_next: &'a mut [u32],
    /// The volume's one policy domain.
    pub domain: &'a mut Domain,
    /// One position word per slot, shared: a parking thread stores its retirement's epoch there without the gate.
    positions: &'a [AtomicU64],
    journal_words: &'a JournalWords,
    /// Every slot's full key.
    keys: &'a mut [[u8; 32]],
    /// Every slot's portable deadline, zero for an absent pair.
    deadlines: &'a mut [u64],
    /// Every slot's portable lifetime.
    lifetimes: &'a mut [u32],
    /// Every slot's record generation, shared: reads load it without the gate.
    generations: &'a [AtomicU64],
    /// Every slot's cache version, shared as the generations are.
    versions: &'a [AtomicU64],
    /// Every view keeps atomic accesses shared with gate-free membership bookkeeping.
    steps: &'a [AtomicU64],
    /// The layout and mapping the sequence arena's tables are derived from
    /// when a hold reaches the arena.
    image: &'a TableImage,
    control: &'a Mapping,
}

impl Tables<'_> {
    /// Stores `slot`'s record generation, cache version, full key and portable pair.
    /// `Lane::install` and `Tables::fold_lanes` write the same facts for a range-split restore; a fact added here is added
    /// there, and the lane equivalence test compares both. The caller binds naming before publishing slot rights, whose release orders read validation after these stores.
    ///
    /// # Panics
    ///
    /// Panics when `slot`'s step is nonzero: a slot is bound only while it is outside the capture membership, which the caller's `capture_insert` enters after this call.
    #[inline(always)]
    pub(crate) fn bind_naming(
        &mut self,
        slot: usize,
        key: [u8; 32],
        expiry: PortableExpiry,
        naming: Naming,
    ) {
        self.generations[slot].store(naming.session, Ordering::Relaxed);
        self.versions[slot].store(naming.version, Ordering::Relaxed);
        assert_eq!(
            self.steps[slot].load(Ordering::Relaxed),
            0,
            "binding requires an ineligible slot"
        );
        self.keys[slot] = key;
        self.deadlines[slot] = expiry.deadline_ns;
        self.lifetimes[slot] = expiry.lifetime_ms;
    }

    #[inline(always)]
    pub(crate) fn clear_naming(&mut self, slot: usize) {
        self.generations[slot].store(0, Ordering::Relaxed);
        self.versions[slot].store(0, Ordering::Relaxed);
        self.keys[slot] = [0; 32];
        self.deadlines[slot] = 0;
        self.lifetimes[slot] = 0;
    }

    /// `slot`'s portable pair, [`PortableExpiry::ABSENT`] for a slot bound without one.
    #[inline(always)]
    pub(crate) fn expiry(&self, slot: usize) -> PortableExpiry {
        PortableExpiry {
            deadline_ns: self.deadlines[slot],
            lifetime_ms: self.lifetimes[slot],
        }
    }

    /// `slot`'s record generation: the session that wrote its record.
    #[inline(always)]
    pub(crate) fn generation(&self, slot: usize) -> u64 {
        self.generations[slot].load(Ordering::Relaxed)
    }

    /// `slot`'s cache version.
    pub(crate) fn version(&self, slot: usize) -> u64 {
        self.versions[slot].load(Ordering::Relaxed)
    }

    pub(crate) fn step(&self, slot: usize) -> u64 {
        self.steps[slot].load(Ordering::Relaxed)
    }

    /// `slot`'s full key.
    #[inline(always)]
    pub(crate) fn key(&self, slot: usize) -> &[u8; 32] {
        &self.keys[slot]
    }

    /// The position words' view in this hold.
    #[inline(always)]
    pub(crate) fn journal(&mut self) -> JournalHold<'_> {
        JournalHold {
            positions: self.positions,
            words: self.journal_words,
        }
    }

    /// Whether the pool carries no object: no slot filling, resident or retired, and no extent unit reserved, resident
    /// or retired.
    pub(crate) fn pristine(&mut self) -> bool {
        let (slots, raw) = (self.state.ledger, self.extents().ledger());
        slots.filling + slots.resident + slots.retired == 0
            && raw.reserved + raw.resident + raw.retired == 0
    }

    /// The extent allocator over the tables initialization set up, borrowed
    /// from this hold.
    #[inline(always)]
    pub(crate) fn extents(&mut self) -> ExtentAllocator<'_> {
        ExtentAllocator::attach(self.extent_root, self.extent_space, self.extent_index)
    }

    /// `restore_runs` rebuilds the extent allocator with exactly the units of `held`, nonempty, ascending, pairwise-disjoint `[start, end)` runs inside the payload holding `totals = (units, payload bytes)`, held and every other unit free, as [`ExtentAllocator::restored_runs`] does; it returns false, writing nothing, for runs or totals [`ExtentAllocator::restored_runs`] refuses or a root of zero charge.
    pub(crate) fn restore_runs(
        &mut self,
        held: impl Iterator<Item = (u64, u64)> + Clone,
        totals: (usize, usize),
    ) -> bool {
        let restored = ExtentAllocator::restore_runs(
            (self.extent_root, self.extent_space, self.extent_index),
            held,
            totals,
        );
        if restored {
            self.bound_runs();
        }
        restored
    }

    /// Stores the longest free run as the run bound. A hold that returns
    /// units to the allocator must call this after the return, so the run
    /// bound covers the runs the return lengthened. Any other gate holder may
    /// call it to lower a bound that claims left above the longest run.
    #[inline(always)]
    pub(crate) fn bound_runs(&mut self) {
        let longest = self.extents().longest_free_run();
        self.store_run_bound(longest);
    }

    /// `longest` must equal the longest free run this hold observed.
    #[inline(always)]
    pub(crate) fn store_run_bound(&mut self, longest: u64) {
        // SAFETY: as for `PoolAccess::tables`; the record holds only atomics.
        let telemetry = unsafe { self.image.telemetry(self.control) };
        telemetry.run_bound.store(longest, Ordering::Relaxed);
    }

    /// Moves `payload` reserved bytes to resident in the raw-byte ledger.
    ///
    /// # Panics
    ///
    /// If the ledger refuses, which a conserved ledger with a correct slot
    /// record never does; the caller holds the gate, so the panic poisons it.
    #[inline(always)]
    pub(crate) fn publish_payload(&mut self, payload: usize) {
        if self.extents().publish(payload).is_err() {
            panic!("the raw-byte ledger holds fewer reserved bytes than a filling slot names");
        }
    }

    /// Moves `payload` resident bytes to retired in the raw-byte ledger.
    ///
    /// # Panics
    ///
    /// As for [`publish_payload`](Self::publish_payload).
    #[inline(always)]
    pub(crate) fn retire_payload(&mut self, payload: usize) {
        if self.extents().retire(payload).is_err() {
            panic!("the raw-byte ledger holds fewer resident bytes than a resident slot names");
        }
    }

    /// Disjoint tables let callers borrow `BlockArena` and
    /// `ExtentAllocator` together.
    #[inline(always)]
    pub(crate) fn blocks_and_extents(&mut self) -> (BlockArena<'_>, ExtentAllocator<'_>) {
        // SAFETY: as for `blocks`; the extent tables are disjoint from the
        // arena's.
        let arena = unsafe { self.image.arena(self.control) };
        (
            arena,
            ExtentAllocator::attach(self.extent_root, self.extent_space, self.extent_index),
        )
    }

    /// The raw locator `slot`'s record stores.
    #[inline(always)]
    pub(crate) fn held_locator(&self, slot: usize) -> ExtentLocator {
        self.records[slot].locator()
    }

    /// What `slot`'s record holds, from its locator, which stays fixed from
    /// the claim to the return.
    ///
    /// # Panics
    ///
    /// If the locator is neither form, which only corruption produces; the
    /// panic poisons the gate the caller holds.
    #[inline(always)]
    pub(crate) fn held(&self, slot: usize) -> Held {
        match Held::decode(self.records[slot].locator()) {
            Some(held) => held,
            None => panic!("a slot's locator names neither an extent nor a sequence"),
        }
    }

    /// The identity of `slot`'s current incarnation, which owns its
    /// sequence block.
    #[inline(always)]
    pub(crate) fn owner(&self, slot: usize) -> AllocationId {
        AllocationId::new(SlotIndex(slot), word::incarnation(self.word(slot)))
    }

    /// `slot`'s record word, loaded relaxed. Only the pool gate's holder
    /// writes its state and policy bits; while the gate is held a lease can
    /// still change the count and set `VISITED`, and `park_marked` can set
    /// `ABANDONED`.
    #[inline(always)]
    pub(crate) fn word(&self, slot: usize) -> u64 {
        self.records[slot].ident.load(Ordering::Relaxed)
    }

    /// The block, count and owner of `slot`'s sequence, or `None` for a
    /// direct extent.
    ///
    /// # Panics
    ///
    /// As for [`held`](Self::held).
    #[cfg(test)]
    #[inline(always)]
    pub(crate) fn sequence(&self, slot: usize) -> Option<(Block, u32, AllocationId)> {
        match self.held(slot) {
            Held::Direct(_) => None,
            Held::Sequence { block, count } => Some((block, count, self.owner(slot))),
        }
    }

    /// Units of the extents `slot` holds, from its record; the caller found
    /// the slot owned under the gate, so the record names what it holds.
    ///
    /// # Panics
    ///
    /// `held_units` panics as [`held`](Self::held) does, or with
    /// [`SEQUENCE_REFUSED`] if the sequence block refuses the held-prefix
    /// request.
    #[inline(always)]
    pub(crate) fn held_units(&mut self, slot: usize) -> u32 {
        match self.held(slot) {
            Held::Direct(locator) => locator.len_units(),
            Held::Sequence { block, count } => {
                let owner = self.owner(slot);
                block_units(self.blocks(), block, count, owner)
            }
        }
    }

    /// Whole free units of the volume, from the raw-byte ledger.
    #[inline(always)]
    pub(crate) fn free_units(&mut self) -> u64 {
        (self.extents().ledger().free / IO_UNIT) as u64
    }

    #[inline(always)]
    pub(crate) fn longest_free_run(&mut self) -> u64 {
        self.extents().longest_free_run()
    }

    /// Free units in whole charges of the largest admitted object's first extent, as [`ExtentAllocator::placeable`] counts them; at most [`free_units`](Self::free_units).
    #[inline(always)]
    pub(crate) fn placeable_units(&mut self) -> u64 {
        self.extents().placeable()
    }

    /// Marks `slot`, whose state the caller just moved to `Retired`.
    #[inline(always)]
    pub(crate) fn mark_retired(&mut self, slot: usize) {
        let word = slot / 64;
        self.retired[word] |= 1 << (slot % 64);
        self.retired_summary[word / 64] |= 1 << (word % 64);
    }

    /// Unmarks `slot`, whose state the caller just moved out of `Retired`.
    /// The slot carries no waiting mark: a marked slot leaves the retired
    /// set only through a visit, and the retired pass visits it after
    /// [`clear_waiting`](Self::clear_waiting).
    #[inline(always)]
    pub(crate) fn unmark_retired(&mut self, slot: usize) {
        let word = slot / 64;
        debug_assert_eq!(
            self.waiting[word] >> (slot % 64) & 1,
            0,
            "a waiting mark on a slot leaving the retired set"
        );
        self.retired[word] &= !(1 << (slot % 64));
        if self.retired[word] == 0 {
            self.retired_summary[word / 64] &= !(1 << (word % 64));
        }
    }

    /// Marks retired `slot` in the waiting set: admission is open, no right
    /// or anchor holds the slot and its position lies
    /// outside the durable prefix the marks are made under, so service's
    /// retired pass leaves it unvisited until
    /// [`clear_waiting`](Self::clear_waiting).
    #[inline(always)]
    pub(crate) fn mark_waiting(&mut self, slot: usize) {
        self.waiting[slot / 64] |= 1 << (slot % 64);
        self.state.waiting += 1;
    }

    /// Clears every mark of the waiting set and records `prefix` as the
    /// durable prefix later marks are made under. A marked slot has no
    /// owner, right or anchor, so only a visit of the retired pass returns
    /// it and it stays retired until then; the bitmap words the retired
    /// summary marks therefore hold every mark.
    pub(crate) fn clear_waiting(&mut self, prefix: u64) {
        if self.state.waiting != 0 {
            for (group, &summary) in self.retired_summary.iter().enumerate() {
                let mut words = summary;
                while words != 0 {
                    self.waiting[64 * group + words.trailing_zeros() as usize] = 0;
                    words &= words - 1;
                }
            }
            self.state.waiting = 0;
        }
        self.state.waiting_under = prefix;
    }

    /// The volume's policy domain, over the records and the `next` table.
    #[inline(always)]
    pub(crate) fn queue(&mut self) -> Queue<'_> {
        Queue::new(self.records, self.policy_next, self.domain)
    }

    /// The free-slot set over its words.
    #[inline(always)]
    pub(crate) fn free_slots(&mut self) -> FreeSlots<'_> {
        FreeSlots::attach(self.free_slots, self.records.len())
    }

    /// The sequence arena over its tables.
    #[inline(always)]
    pub(crate) fn blocks(&mut self) -> BlockArena<'_> {
        // SAFETY: the hold's gate makes this view the only holder of the
        // arena's tables, which `PoolAccess::tables` leaves underived, and
        // `&mut self` proves no earlier arena from this view is live.
        unsafe { self.image.arena(self.control) }
    }
}

/// Gate holder for the volume's tables. Dropping it releases the gate.
pub(crate) struct PoolAccess<'a> {
    guard: GateGuard<'a>,
    control: &'a Mapping,
    image: &'a TableImage,
}

impl PoolAccess<'_> {
    /// Poisons the gate at the end of a hold whose tables a failed writer may have left half-written, so the gate admits
    /// nobody; see [`GateGuard::poison`].
    pub(crate) fn poison(self) {
        self.guard.poison();
    }

    /// Makes the hold's drop poison the gate whenever the thread is unwinding, a thread that was already unwinding at
    /// the take included, for a holder that ends every completed or refused hold through [`release`](Self::release) or
    /// [`poison`](Self::poison); see [`GateGuard::poison_on_unwind`].
    pub(crate) fn poison_on_unwind(self) -> Self {
        Self {
            guard: self.guard.poison_on_unwind(),
            ..self
        }
    }

    /// Releases the gate at the end of a completed hold; see
    /// [`GateGuard::release`]. Dropping the access releases too, with the
    /// poison decision.
    #[inline(always)]
    pub(crate) fn release(self) {
        self.guard.release();
    }
}

impl TableImage {
    /// Appends every table to `layout`, sized from the validated volume.
    ///
    /// # Errors
    ///
    /// `ControlLayoutOverflow` if any table or the running total is
    /// unrepresentable.
    pub(crate) fn layout(
        layout: &mut ControlLayout,
        config: &ValidatedConfig,
    ) -> Result<Self, ControlLayoutOverflow> {
        let volume = config.volume();
        let slot_count = volume.slot_count;
        // The gate comes last, after every table a hold reads, so its
        // 128-byte block does not separate the state from the tables.
        let state = layout.field::<PoolState>(1)?;
        let extent_root = layout.field::<ExtentRoot>(1)?;
        let extent_space = layout.field::<u64>(space_words(config.geometry().payload_units()))?;
        let extent_index = layout.field::<RunNode>(index_table_nodes(slot_count))?;
        // Line-aligned, so two records share each line and none straddles
        // two.
        layout.align_to(LINE)?;
        let records = layout.field::<Record>(slot_count)?;
        let tails = layout.field::<u16>(slot_count)?;
        let free_slots = layout.field::<u64>(free::words(slot_count))?;
        let telemetry = layout.field::<Telemetry>(1)?;
        let retired_words = slot_count.div_ceil(64);
        let retired = layout.field::<u64>(retired_words)?;
        let retired_summary = layout.field::<u64>(retired_words.div_ceil(64))?;
        let waiting = layout.field::<u64>(retired_words)?;
        let parked_slots = layout.field::<AtomicU64>(retired_words)?;
        let parked_summary = layout.field::<AtomicU64>(retired_words.div_ceil(64))?;
        // Aligned so the four `next` links of one placement window lie in one
        // line, which a fill's grant hints with the window.
        layout.align_to(4 * free::WINDOW)?;
        let policy_next = layout.field::<u32>(slot_count)?;
        let domain = layout.field::<Domain>(1)?;
        let pending_mark = layout.field::<PendingMark>(1)?;
        let positions = layout.field::<AtomicU64>(slot_count)?;
        let journal_words = layout.field::<JournalWords>(1)?;
        let keys = layout.field::<[u8; 32]>(slot_count)?;
        let deadlines = layout.field::<u64>(slot_count)?;
        let lifetimes = layout.field::<u32>(slot_count)?;
        let generations = layout.field::<AtomicU64>(slot_count)?;
        let versions = layout.field::<AtomicU64>(slot_count)?;
        let steps = layout.field::<AtomicU64>(slot_count)?;
        let watermarks = layout.field::<Option<VolumeWatermarks>>(1)?;
        let block_lists = layout.field::<ArenaLists>(1)?;
        layout.align_to(LINE)?;
        let roots = volume.block_roots;
        let block_words =
            layout.field::<u64>(roots.checked_mul(ROOT_WORDS).ok_or(ControlLayoutOverflow)?)?;
        let block_bits =
            layout.field::<u64>(roots.checked_mul(BIT_WORDS).ok_or(ControlLayoutOverflow)?)?;
        Ok(Self {
            gate: layout.field::<Gate>(1)?,
            state,
            extent_root,
            extent_space,
            extent_index,
            records,
            tails,
            free_slots,
            telemetry,
            retired,
            retired_summary,
            waiting,
            parked_slots,
            parked_summary,
            policy_next,
            domain,
            pending_mark,
            positions,
            journal_words,
            keys,
            deadlines,
            lifetimes,
            generations,
            versions,
            steps,
            watermarks,
            block_lists,
            block_words,
            block_bits,
        })
    }

    /// Whether the image carries a sequence arena, so slots can hold
    /// sequences.
    pub(crate) fn has_arena(&self) -> bool {
        self.block_words.len() != 0
    }

    pub(crate) fn inventory(&self) -> TableInventory {
        fn entry<T>(field: Field<T>) -> (usize, usize) {
            (field.offset(), field.len())
        }
        TableInventory {
            gate: entry(self.gate),
            state: entry(self.state),
            extent_root: entry(self.extent_root),
            extent_space: entry(self.extent_space),
            extent_index: entry(self.extent_index),
            records: entry(self.records),
            tails: entry(self.tails),
            free_slots: entry(self.free_slots),
            telemetry: entry(self.telemetry),
            retired: entry(self.retired),
            retired_summary: entry(self.retired_summary),
            waiting: entry(self.waiting),
            parked_slots: entry(self.parked_slots),
            parked_summary: entry(self.parked_summary),
            policy_next: entry(self.policy_next),
            domain: entry(self.domain),
            pending_mark: entry(self.pending_mark),
            positions: entry(self.positions),
            journal_words: entry(self.journal_words),
            keys: entry(self.keys),
            deadlines: entry(self.deadlines),
            lifetimes: entry(self.lifetimes),
            generations: entry(self.generations),
            versions: entry(self.versions),
            steps: entry(self.steps),
            watermarks: entry(self.watermarks),
            block_lists: entry(self.block_lists),
            block_words: entry(self.block_words),
            block_bits: entry(self.block_bits),
        }
    }

    /// Writes every table of `control` to its initial state: every slot free
    /// and in the free-slot set, cursors at zero, and the extent allocator
    /// with one free run covering the volume.
    ///
    /// # Safety
    ///
    /// `control` is the owned, populated control mapping this image was laid
    /// out for, the caller has exclusive access to the mapping, and every
    /// byte of this image's fields is still zero: [`Field::init`] relies on
    /// the mapping's zero fill for zero-valued elements.
    pub(crate) unsafe fn init(&self, control: &Mapping, config: &ValidatedConfig) {
        let volume = config.volume();
        let slot_count = volume.slot_count;
        // SAFETY: forwarded from the caller for every field of one mapping.
        // The writes between these calls reach only fields already
        // initialized, so each field is still zero when its `init` runs.
        unsafe {
            self.gate.init(control, |_| Gate::open());
            self.state.init(control, |_| PoolState {
                ledger: SlotPartition {
                    free: slot_count,
                    ..SlotPartition::default()
                },
                cursor_claim: 0,
                cursor_slot: 0,
                cursor_park: 0,
                cursor_expiry: 0,
                earliest_deadline: u32::MAX,
                pass_earliest: u32::MAX,
                waiting: 0,
                waiting_under: 0,
            });
            self.extent_root.init(control, |_| ExtentRoot::default());
            self.extent_space.init(control, |_| 0);
            self.extent_index.init(control, |_| RunNode::default());
            // SAFETY: the three fields were initialized just above; each is a
            // distinct field of the one control mapping, disjoint from the
            // others and from every later field, and no other reference into
            // them is live while the allocator borrows them.
            let geometry = config.geometry();
            let initialized = ExtentAllocator::init(
                geometry.payload_units(),
                geometry.metadata_units(),
                index_capacity(slot_count),
                config.largest_geometry().units(0),
                &mut (*self.extent_root.slice_ptr(control).as_ptr())[0],
                &mut *self.extent_space.slice_ptr(control).as_ptr(),
                &mut *self.extent_index.slice_ptr(control).as_ptr(),
            );
            if initialized.is_err() {
                unreachable!(
                    "validation admitted the volume's units and slot count, the layout sized both tables from them, and the largest object's first extent charges at least one unit"
                );
            }
            self.records.init(control, |_| Record::free());
            self.tails.init(control, |_| 0);
            self.free_slots.init(control, |_| 0);
            // SAFETY: the field was initialized just above and is disjoint
            // from every other field of the one mapping; no other reference
            // into it is live while the set fills it.
            FreeSlots::attach(
                &mut *self.free_slots.slice_ptr(control).as_ptr(),
                slot_count,
            )
            .fill();
            self.telemetry.init(control, |_| Telemetry {
                failed_tries: AtomicUsize::new(0),
                pending_marks: AtomicUsize::new(0),
                retains: RetainCounters::new(),
                promised: AtomicU64::new(0),
                refunded: AtomicU64::new(0),
                run_bound: AtomicU64::new(u64::MAX),
            });
            self.retired.init(control, |_| 0);
            self.retired_summary.init(control, |_| 0);
            self.waiting.init(control, |_| 0);
            self.parked_slots.init(control, |_| AtomicU64::new(0));
            self.parked_summary.init(control, |_| AtomicU64::new(0));
            self.policy_next.init(control, |_| POLICY_NONE);
            self.domain.init(control, |_| Domain::EMPTY);
            self.pending_mark.init(control, |_| PendingMark::empty());
            self.positions.init(control, |_| AtomicU64::new(NO_RECORD));
            self.journal_words
                .init(control, |_| JournalWords::default());
            self.keys.init(control, |_| [0; 32]);
            self.deadlines.init(control, |_| 0);
            self.lifetimes.init(control, |_| 0);
            self.generations.init(control, |_| AtomicU64::new(0));
            self.versions.init(control, |_| AtomicU64::new(0));
            self.steps.init(control, |_| AtomicU64::new(0));
            self.watermarks.init(control, |_| volume.maintenance);
            self.block_lists.init(control, |_| ArenaLists::EMPTY);
            self.block_words.init(control, |_| 0);
            self.block_bits.init(control, |_| 0);
            // SAFETY: the three fields were initialized just above and are
            // disjoint from each other and from every other field of the one
            // mapping; no other reference into them is live.
            BlockArena::attach(
                &mut (*self.block_lists.slice_ptr(control).as_ptr())[0],
                &mut *self.block_words.slice_ptr(control).as_ptr(),
                &mut *self.block_bits.slice_ptr(control).as_ptr(),
            )
            .init();
        }
    }

    /// One nonblocking attempt to take the gate.
    ///
    /// # Safety
    ///
    /// `control` is the owned control mapping this image was laid out for and
    /// its tables were initialized.
    ///
    /// # Errors
    ///
    /// `Contended` if held elsewhere, `Poisoned` if a holder panicked.
    #[inline(always)]
    pub(crate) unsafe fn try_lock<'a>(
        &'a self,
        control: &'a Mapping,
    ) -> Result<PoolAccess<'a>, GateError> {
        // SAFETY: the caller's guarantee is exactly `as_slice`'s contract; the
        // gate is a shared atomic that many readers may hold references to.
        let gate = unsafe { &self.gate.as_slice(control)[0] };
        let guard = gate.try_lock()?;
        Ok(PoolAccess {
            guard,
            control,
            image: self,
        })
    }

    /// Waiting access for reports. Reports are operator paths, not allocator
    /// work, so they may wait; see [`Gate::lock`] for how.
    /// A poisoned gate yields `None`.
    /// A thread that already holds the gate must not call it: the wait would never end.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    pub(crate) unsafe fn lock<'a>(&'a self, control: &'a Mapping) -> Option<PoolAccess<'a>> {
        // SAFETY: as for `try_lock`.
        let gate = unsafe { &self.gate.as_slice(control)[0] };
        let guard = gate.lock()?;
        Some(PoolAccess {
            guard,
            control,
            image: self,
        })
    }

    /// The counters, readable and writable without the gate.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    #[inline]
    pub(crate) unsafe fn telemetry<'a>(&self, control: &'a Mapping) -> &'a Telemetry {
        // SAFETY: as for `try_lock`; the record holds only atomics.
        unsafe { &self.telemetry.as_slice(control)[0] }
    }

    /// Every slot's record, in slot order, readable and writable without
    /// the gate.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    #[inline(always)]
    pub(crate) unsafe fn records<'a>(&self, control: &'a Mapping) -> &'a [Record] {
        // SAFETY: as for `try_lock`; the table holds only atomics.
        unsafe { self.records.as_slice(control) }
    }

    /// Every slot's position word, readable and writable without the gate.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    #[inline(always)]
    pub(crate) unsafe fn positions<'a>(&self, control: &'a Mapping) -> &'a [AtomicU64] {
        // SAFETY: as for `try_lock`; the table holds only atomics.
        unsafe { self.positions.as_slice(control) }
    }

    /// Every slot's record generation, readable without the gate.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    #[inline(always)]
    pub(crate) unsafe fn generations<'a>(&self, control: &'a Mapping) -> &'a [AtomicU64] {
        // SAFETY: as for `try_lock`; the table holds only atomics.
        unsafe { self.generations.as_slice(control) }
    }

    /// Every slot's cache version, readable without the gate.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    #[inline(always)]
    pub(crate) unsafe fn versions<'a>(&self, control: &'a Mapping) -> &'a [AtomicU64] {
        // SAFETY: as for `try_lock`; the table holds only atomics.
        unsafe { self.versions.as_slice(control) }
    }

    /// # Safety
    /// `steps` has the same safety requirements as [`try_lock`](Self::try_lock).
    pub(crate) unsafe fn steps<'a>(&self, control: &'a Mapping) -> &'a [AtomicU64] {
        // SAFETY: initialization constructs atomics, and every borrow of the steps table is shared.
        unsafe { self.steps.as_slice(control) }
    }

    /// The parked-slot bitmap, readable and writable without the gate.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    #[inline(always)]
    pub(crate) unsafe fn parked_slots<'a>(&self, control: &'a Mapping) -> &'a [AtomicU64] {
        // SAFETY: as for `try_lock`; the table holds only atomics.
        unsafe { self.parked_slots.as_slice(control) }
    }

    /// The parked-slot bitmap's summary, readable and writable without the
    /// gate.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    #[inline(always)]
    pub(crate) unsafe fn parked_summary<'a>(&self, control: &'a Mapping) -> &'a [AtomicU64] {
        // SAFETY: as for `try_lock`; the table holds only atomics.
        unsafe { self.parked_summary.as_slice(control) }
    }

    /// The position words' shared words, readable and writable without the gate.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    #[inline(always)]
    pub(crate) unsafe fn journal_words<'a>(&self, control: &'a Mapping) -> &'a JournalWords {
        // SAFETY: as for `try_lock`; the record holds only atomics.
        unsafe { &self.journal_words.as_slice(control)[0] }
    }

    /// One slot's record, with no bounds check, for the hit path.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock), and `slot < O`: the caller's
    /// bound is the element bound.
    #[inline(always)]
    pub(crate) unsafe fn record<'a>(&self, control: &'a Mapping, slot: usize) -> &'a Record {
        // SAFETY: as for `try_lock`; the caller's `slot < O` keeps the
        // element inside the field, and a record holds only atomics, so a
        // shared reference for the mapping's lifetime is sound.
        unsafe { self.records.element_ptr(control, slot).as_ref() }
    }

    /// The volume's pending removal mark, readable and writable without the gate.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    pub(crate) unsafe fn pending_mark<'a>(&self, control: &'a Mapping) -> &'a PendingMark {
        // SAFETY: as for `try_lock`; the record holds only atomics.
        unsafe { &self.pending_mark.as_slice(control)[0] }
    }

    /// The headroom watermarks, `None` without maintenance. Immutable after
    /// initialization.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    pub(crate) unsafe fn watermarks(&self, control: &Mapping) -> Option<VolumeWatermarks> {
        // SAFETY: as for `try_lock`; nothing writes the field after
        // initialization, so a shared read is sound.
        unsafe { self.watermarks.as_slice(control)[0] }
    }

    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock); the caller holds the gate, binds
    /// the returned arena to its own exclusive borrow of the hold's view,
    /// and derives no second arena while the returned one is live.
    #[inline(always)]
    unsafe fn arena<'a>(&self, control: &'a Mapping) -> BlockArena<'a> {
        // SAFETY: the caller's guarantee makes each pointer the one `&mut`
        // to its table; the three tables are disjoint arrays of the mapping.
        unsafe {
            BlockArena::attach(
                &mut (*self.block_lists.slice_ptr(control).as_ptr())[0],
                &mut *self.block_words.slice_ptr(control).as_ptr(),
                &mut *self.block_bits.slice_ptr(control).as_ptr(),
            )
        }
    }

    /// `prefetch_slot` warms the slot's record and its policy `next` link,
    /// for writing, before a gate-held return, drop or retirement: the hold
    /// writes the record's word, a retirement also stores its stamp over the
    /// fingerprint, and a return or a resident retirement reads and rewrites
    /// the links, the `next` link on a cold line of its own in a pool larger
    /// than the cache.
    /// Prefetching forms addresses without reading, so it neither requires
    /// the gate nor validates `slot`.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    #[inline(always)]
    pub(crate) unsafe fn prefetch_slot(&self, control: &Mapping, slot: usize) {
        // SAFETY: the caller's guarantee is `element_address`'s contract;
        // only addresses are formed here, no reference and no read.
        unsafe {
            hint(self.records.element_address(control, slot));
            hint(self.policy_next.element_address(control, slot));
        }
    }

    /// `prefetch_retirement` hints retirement and return metadata beyond the record and policy link hinted by [`prefetch_slot`](Self::prefetch_slot). Retirement reads `slot`'s step and tail and stores its position word. For capture members, `capture_unpublish` stores zero in the step. A recorded removal reads the key, generation, and version through `Pool::capture_identity`. `return_extent` calls [`Tables::clear_naming`] to zero the key, deadline, lifetime, generation, and version. The tail takes a read hint, since retirement and return load it; the other seven entries take write hints.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    #[inline(always)]
    pub(crate) unsafe fn prefetch_retirement(&self, control: &Mapping, slot: usize) {
        // SAFETY: as for `prefetch_slot`.
        unsafe {
            hint(self.positions.element_address(control, slot));
            hint(self.steps.element_address(control, slot));
            hint_read(self.tails.element_address(control, slot));
            hint(self.keys.element_address(control, slot));
            hint(self.deadlines.element_address(control, slot));
            hint(self.lifetimes.element_address(control, slot));
            hint(self.generations.element_address(control, slot));
            hint(self.versions.element_address(control, slot));
        }
    }

    /// The write hint requests the cache line containing `slot`'s record.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    #[inline(always)]
    pub(crate) unsafe fn prefetch_record(&self, control: &Mapping, slot: usize) {
        // SAFETY: as for `prefetch_slot`.
        unsafe { hint(self.records.element_address(control, slot)) }
    }

    /// The read hint requests the cache line containing `slot`'s 8-byte record
    /// generation.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    #[inline(always)]
    pub(crate) unsafe fn prefetch_generation(&self, control: &Mapping, slot: usize) {
        // SAFETY: as for `prefetch_slot`.
        unsafe { hint_read(self.generations.element_address(control, slot)) }
    }

    /// The read hint requests the cache line containing `slot`'s cache version.
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    #[inline(always)]
    pub(crate) unsafe fn prefetch_version(&self, control: &Mapping, slot: usize) {
        // SAFETY: as for `prefetch_slot`.
        unsafe { hint_read(self.versions.element_address(control, slot)) }
    }

    /// Write hints for the gate-held table lines a slot of the window at
    /// `start` is written through beside its record: the free-slot set's
    /// level-0 word and the tail at the claim, the policy `next` link at the
    /// publication's bind. One line each: a window's slots are consecutive,
    /// its tails and `next` links start on a multiple of their group's size,
    /// and its four free bits lie in one word. Only addresses are formed, as
    /// in [`prefetch_slot`](Self::prefetch_slot).
    ///
    /// # Safety
    ///
    /// As for [`try_lock`](Self::try_lock).
    #[inline(always)]
    pub(crate) unsafe fn prefetch_claim_tables(&self, control: &Mapping, start: usize) {
        // SAFETY: as for `prefetch_slot`.
        unsafe {
            hint(self.free_slots.element_address(control, start / 64));
            hint(self.tails.element_address(control, start));
            hint(self.policy_next.element_address(control, start));
        }
    }
}

impl PoolAccess<'_> {
    /// Every locked table, borrowed exclusively from this holder.
    #[inline(always)]
    pub(crate) fn tables(&mut self) -> Tables<'_> {
        let image = self.image;
        let control = self.control;
        // SAFETY: the guard proves this is the only holder, `&mut self`
        // proves no earlier `Tables` from this holder is live, and the fields
        // are disjoint arrays of a mapping that was fully initialized before
        // the owner existed, so each pointer may become the one `&mut`. The
        // records, the parked bitmaps, the position words, their shared
        // words, the record generations, the cache versions and the membership steps hold only atomics that `Pool`
        // also hands out without the gate, so they are borrowed shared and
        // no view forms `&mut` over them.
        unsafe {
            Tables {
                state: &mut (*image.state.slice_ptr(control).as_ptr())[0],
                extent_root: &mut (*image.extent_root.slice_ptr(control).as_ptr())[0],
                extent_space: &mut *image.extent_space.slice_ptr(control).as_ptr(),
                extent_index: &mut *image.extent_index.slice_ptr(control).as_ptr(),
                records: image.records.as_slice(control),
                tails: &mut *image.tails.slice_ptr(control).as_ptr(),
                free_slots: &mut *image.free_slots.slice_ptr(control).as_ptr(),
                retired: &mut *image.retired.slice_ptr(control).as_ptr(),
                retired_summary: &mut *image.retired_summary.slice_ptr(control).as_ptr(),
                waiting: &mut *image.waiting.slice_ptr(control).as_ptr(),
                parked_slots: image.parked_slots.as_slice(control),
                parked_summary: image.parked_summary.as_slice(control),
                policy_next: &mut *image.policy_next.slice_ptr(control).as_ptr(),
                domain: &mut (*image.domain.slice_ptr(control).as_ptr())[0],
                positions: image.positions.as_slice(control),
                journal_words: &image.journal_words.as_slice(control)[0],
                keys: &mut *image.keys.slice_ptr(control).as_ptr(),
                deadlines: &mut *image.deadlines.slice_ptr(control).as_ptr(),
                lifetimes: &mut *image.lifetimes.slice_ptr(control).as_ptr(),
                generations: image.generations.as_slice(control),
                versions: image.versions.as_slice(control),
                steps: image.steps.as_slice(control),
                image,
                control,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::StorageConfig;
    use super::super::layout::IO_UNIT;
    use super::super::owner::Storage;
    use super::super::pending::{Counted, Retired, Seek, seek};
    use super::super::placement::PlacementConfig;
    use super::super::test_platform::TestPlatform;
    use super::Tables;

    /// A storage of 512 units and `slots` slots, every slot free.
    fn storage_of(slots: usize) -> Storage<TestPlatform> {
        let config = StorageConfig {
            page_size: 4096,
            engine_budget: 1 << 26,
            body_cap: 200_000,
            metadata_cap: Some(64),
            lease_limit: 64,
            object_rights: 8,
            reader_limit: 4,
            volume: crate::storage::test_volume(512 * IO_UNIT, slots),
        };
        Storage::initialize(
            &config.validate().unwrap(),
            &PlacementConfig { control_home: 0 },
            TestPlatform::heap(4096),
        )
        .unwrap()
    }

    #[test]
    fn the_retired_search_matches_a_slot_by_slot_scan() {
        check_retired_search(150, &[0, 1, 63, 64, 65, 100, 127, 128, 149], |_| true);
        const LARGE: usize = 2 * 4096 + 150;
        let marked = [0, 63, 4095, 4096, 4097, 6000, 8191, 8192, LARGE - 1];
        let edges: Vec<usize> = marked
            .iter()
            .flat_map(|&slot| [slot.saturating_sub(1), slot, slot + 1])
            .chain((0..=LARGE).step_by(64))
            .chain([4095, 4096, 4097, 8191, 8192, 8193])
            .filter(|&slot| slot <= LARGE)
            .collect();
        check_retired_search(LARGE, &marked, |slot| edges.contains(&slot));
    }

    /// Marks `marked` one at a time, then clears them all, comparing the
    /// retired set's search with a naive scan over every range whose bounds
    /// `probe` accepts, and the summary with the words, at each step.
    fn check_retired_search(slots: usize, marked: &[usize], probe: impl Fn(usize) -> bool) {
        let storage = storage_of(slots);
        let live = storage.live_pool().unwrap();
        let mut access = live.lock().unwrap();
        let mut tables = access.tables();
        let search = |tables: &Tables<'_>, start: usize, end: usize| {
            let mut levels = Retired {
                bits: tables.retired,
                summary: tables.retired_summary,
            };
            match seek(&mut levels, start, end, &mut Counted::unbounded()) {
                Seek::Member(slot) => Some(slot),
                Seek::Clear => None,
                Seek::Short(_) => unreachable!("an unbounded search stopped short"),
            }
        };
        let naive = |tables: &Tables<'_>, start: usize, end: usize| {
            (start..end).find(|slot| tables.retired[slot / 64] >> (slot % 64) & 1 == 1)
        };
        let bounds: Vec<usize> = (0..=slots).filter(|&slot| probe(slot)).collect();
        for round in 0..=marked.len() {
            for (word, &bits) in tables.retired.iter().enumerate() {
                let summarized = tables.retired_summary[word / 64] >> (word % 64) & 1 == 1;
                assert_eq!(summarized, bits != 0, "{round} word {word}");
            }
            for &start in bounds.iter().filter(|&&slot| slot < slots) {
                for &end in bounds.iter().filter(|&&slot| slot > start) {
                    assert_eq!(
                        search(&tables, start, end),
                        naive(&tables, start, end),
                        "{round} {start}..{end}"
                    );
                }
            }
            match marked.get(round) {
                Some(&slot) => tables.mark_retired(slot),
                None => marked.iter().for_each(|&slot| tables.unmark_retired(slot)),
            }
        }
        assert!(tables.retired.iter().all(|&word| word == 0));
        assert!(tables.retired_summary.iter().all(|&word| word == 0));
        assert_eq!(search(&tables, 0, slots), None);
    }
}
