//! The store-named checkpoint of one tenure: the possibly-named set a capture must avoid, the staged checkpoint a
//! capture writes, the Publish and Confirm writes on the shard record, and the named-slot reader.
//!
//! Invariants owned by this module:
//!
//! - `PossNamedCoversStore`: [`PossiblyNamed`] holds every slot the store names or an own shard-record write whose
//!   outcome is unknown may name. Submitting a Publish adds its slot. The set shrinks only on the acknowledged success
//!   of an own exact-version write at a version at least the last one a success settled, with no own write submitted
//!   after it still unsucceeded, and then holds only the slot that write committed over. Every own write is an
//!   exact-version compare-and-swap, so no earlier write can commit after that success.
//! - `QuarantineUntilBarrier`: a slot this tenure wrote that leaves the set, and the slot of a staged checkpoint
//!   abandoned after a unit write, is quarantined for the rest of the tenure: an earlier attempt may still land on it,
//!   and no in-tenure barrier ends such attempts. Under the preservation model's END premise the next tenure's fence
//!   is that barrier, so [`PossiblyNamed::new`] starts with an empty quarantine, and the slot named at the tenure's
//!   start, which no attempt of this tenure reached, leaves the set free. Each slot therefore takes at most one
//!   exposed reservation per tenure, and a tenure of `K` slots publishes at most `K` captures; a longer tenure needs
//!   an in-tenure barrier that frees the quarantine.
//! - `ReservedBeforeWrite`: [`StagedCheckpoint::new`] reserves one slot outside the set and the quarantine for one
//!   stage, and a checkpoint-unit write is admitted only to the reserved slot of its own stage before
//!   that stage's Publish, so no unit of a slot the store may name is written (`SlotNotOverwrittenWhileNamed`).
//! - `UniqueCapture`: a reservation names a `(session, capture)` above every one the set reserved or found named, and
//!   a stage encodes its entries once, so each unit identity `(session, capture, unit)` has one encoding and every
//!   write attempt of a unit carries the bytes the stage retains. The caller reserves under its tenure's session,
//!   `g·2^32 + a`, which a later tenure never reissues, so the identities stay unique across tenures.
//! - Publication (`VerifiedBeforePublish`): [`publish`] compare-and-swaps the stage's checkpoint only after every unit
//!   read back equal to the staged bytes, only under its own pass's proof that every member of its cut still owned
//!   its units or left through a removal the tenure's suffix recorded at or above the cut, a proof naming the
//!   stage's shard, session and capture number and carrying the capture epoch its pass started under, which must
//!   equal the epoch its caller read from the storage, whose cut is at or above the tenure's first suffix LSN,
//!   and only on a value of the stage's
//!   shard showing the tenure's own `(generation, owner, E)` and the `ck` the tenure knows. A stage holds every row
//!   of its cut or is refused, so a published slot names the whole cut. It writes the proof's suffix cut and keeps
//!   every suffix ending above it (`PreserveUnconsolidated`).
//! - `RootNamedByStore`: [`SlotReader`] reads only the slot `ck` names and the delta blocks of the record's ancestry
//!   from its cut, issues reads that each lie inside one window of at most [`READ_LEN`] bytes, the suffix blocks first, keeps
//!   [`READ_DEPTH`] outstanding while that many remain and holds at most [`WINDOWS`] windows until the guard applied
//!   them or the replay took their blocks, and decodes each read as recovery-helper jobs. A unit that
//!   fails its identity or crc check, or that the device could not read, loses only the entries with a row on it (`LossIsFaultLocal`): the load holds
//!   the guard's verdict over the whole entries of the intact units and the suffix's replay over them, beside the
//!   failed and unread units. Intact units
//!   that contradict each other or unit 0's counts hold another encoding, and the slot loads cold. A caller installs
//!   a load only once no unit or suffix block is unread ([`SlotLoad::installable`]).

use crate::failover::records::{Ancestry, Layout, NamedCheckpoint, ShardRecord, Suffix};
use crate::failover::retire::Target;
use crate::index::KeyHasher;
use crate::net::ownership::{Shard, session_of};

use super::IO_UNIT;
use super::device::DeviceRange;
use super::ledger::EngineBudget;
use super::record::Crc32c;
use super::recovery::CaptureEntry;
use super::recovery::LoadLimits;
pub use super::recovery::checkpoint::{
    Checkpoint, Chunk, Cut, Damage, Done, EncodeRefusal, Loaded, ROW_LEN, SlotDecode, SlotLoad,
    UNIT_LEN, UnitDamage, Units, Work, encode, key, rows, run, units,
};
use super::recovery::checkpoint::{Counted, Members, encode_counted};
use super::recovery::delta::blocks as delta_blocks;
use super::recovery::delta_replay::{bytes as replay_bytes, lsns};
pub use super::recovery::suffix::SuffixLimits;
pub use super::recovery::{CaptureEpoch, CutIntact};
use super::store::{Client, Read, Store, StoreError, Version, WatermarkLog};
pub use super::volume::PlacementRefusal;
use super::volume::place;

/// The most bytes of one slot or suffix read, and the alignment of the window each read lies in.
pub const READ_LEN: u64 = 256 * 1024;

/// Slot and suffix reads, counted together, that a reader keeps outstanding while that many remain.
pub const READ_DEPTH: usize = 16;

/// An own shard-record write the set tracks until a later success settles it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Submitted(u64);

#[derive(Debug, Clone, Copy)]
struct Pending {
    id: u64,
    slot: Option<u32>,
    succeeded: bool,
}

/// The slots the store may name as one tenure knows them: the named slot and the slot of every own write whose
/// outcome has not been settled by a later success, beside the recorded layout that maps a slot to its prefix units,
/// the quarantined slots, and the one slot reserved for a staged checkpoint. The tenure holds one set and passes it
/// by reference, so every unit admission reads the set every Publish updates.
#[derive(Debug)]
pub struct PossiblyNamed {
    tenure: (Shard, u64),
    layout: Layout,
    named: Option<u32>,
    pending: Vec<Pending>,
    next: u64,
    /// The version of the success that last settled the set.
    settled: Option<Version>,
    /// Each slot at most once, so at most `layout.slots` entries.
    quarantined: Vec<u32>,
    reserved: Option<(u32, Checkpoint)>,
    /// The highest `(session, capture)` the set reserved or found named.
    highest: Option<(u64, u32)>,
    /// The slot named at the tenure's start while it stays in the set.
    fenced: Option<u32>,
}

/// Why [`StagedCheckpoint::new`] reserved no slot. A refusal changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveRefusal {
    /// The layout fails its floor, the cut's rows exceed the layout's `N_max` rows per slot, or every slot is
    /// possibly named or quarantined.
    Placement(PlacementRefusal),
    /// The checkpoint's `(session, capture)` is at or below one the set reserved or found named.
    Capture,
    /// Another staged checkpoint holds the reservation.
    Busy,
    /// The checkpoint names another shard or session than the set's tenure.
    Tenure,
}

impl PossiblyNamed {
    /// The set at a tenure's start under the volume's recorded `layout`, holding the slot `named` names, with no
    /// slot quarantined: under the END premise the fence before the tenure's first medium command ended every
    /// attempt of earlier tenures.
    /// The caller builds it from the value an own shard-record write committed at or after the fencing boundary:
    /// that success moved the record's version, so no write of an earlier tenure can commit a Publish after it.
    pub fn new(tenure: (Shard, u64), layout: Layout, named: Option<NamedCheckpoint>) -> Self {
        Self {
            tenure,
            layout,
            named: named.map(|ck| ck.slot),
            pending: Vec::new(),
            next: 0,
            settled: None,
            quarantined: Vec::new(),
            reserved: None,
            highest: named.map(|ck| (ck.session, ck.capture)),
            fenced: named.map(|ck| ck.slot),
        }
    }

    fn holds(&self, record: &ShardRecord, own: Target) -> bool {
        self.of_tenure(record) && Target::of(record) == own
    }

    fn of_tenure(&self, record: &ShardRecord) -> bool {
        let session = session_of(
            record.generation.get() as u32,
            record.attempts.saturating_mul(2),
        );
        record.shard == self.tenure.0 && record.attempts > 0 && session == self.tenure.1
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn contains(&self, slot: u32) -> bool {
        self.named == Some(slot) || self.pending.iter().any(|p| p.slot == Some(slot))
    }

    /// The slots of the set, the named slot first.
    pub fn slots(&self) -> Vec<u32> {
        let mut slots: Vec<u32> = self.named.into_iter().collect();
        for slot in self.pending.iter().filter_map(|p| p.slot) {
            if !slots.contains(&slot) {
                slots.push(slot);
            }
        }
        slots
    }

    pub fn quarantined(&self) -> &[u32] {
        &self.quarantined
    }

    /// The slots the set holds quarantined or names for an own write no success settled, and the layout's slots.
    pub fn unresolved(&self) -> (u64, u64) {
        let unsettled = self.pending.iter().filter_map(|p| p.slot);
        let mut slots: Vec<u32> = unsettled.filter(|&slot| self.named != Some(slot)).collect();
        slots.extend(&self.quarantined);
        slots.sort_unstable();
        slots.dedup();
        (slots.len() as u64, u64::from(self.layout.slots))
    }

    /// The own writes the set holds pending, at most one unsucceeded write per slot and one naming no checkpoint.
    #[cfg(test)]
    pub(crate) fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// The slots no new reservation may take: the set and the quarantine.
    fn unavailable(&self) -> Vec<u32> {
        let mut slots = self.slots();
        slots.extend(&self.quarantined);
        slots
    }

    /// The slot a reservation would take now, or `None` while a stage holds the reservation, when the layout fails
    /// its floor, or when every slot is possibly named or quarantined. A capture start takes `free_slot().is_some()`
    /// as its `checkpoint_slot_free` and refuses `CaptureError::NoFreeCheckpointSlot` on `false`; a settling success
    /// before the pass's reservation may still quarantine that slot, so the start's check is a hint and
    /// [`StagedCheckpoint::new`] decides.
    pub fn free_slot(&self) -> Option<u32> {
        self.reserved
            .is_none()
            .then(|| place(&self.layout, &self.unavailable(), 0).ok())
            .flatten()
    }

    /// The slot a reservation of checkpoint `ck` for a cut of `rows` extent rows would take.
    ///
    /// # Errors
    ///
    /// `Busy`, then `Capture`, then `Placement`.
    fn placement(&self, ck: Checkpoint, rows: u64) -> Result<u32, ReserveRefusal> {
        if (ck.shard, ck.session) != self.tenure {
            return Err(ReserveRefusal::Tenure);
        }
        if self.reserved.is_some() {
            return Err(ReserveRefusal::Busy);
        }
        #[cfg(test)]
        if planted(Plant::CaptureReuse) {
            return place(&self.layout, &self.unavailable(), rows)
                .map_err(ReserveRefusal::Placement);
        }
        if self
            .highest
            .is_some_and(|highest| (ck.session, ck.capture) <= highest)
        {
            return Err(ReserveRefusal::Capture);
        }
        place(&self.layout, &self.unavailable(), rows).map_err(ReserveRefusal::Placement)
    }

    /// Reserves the lowest free slot for checkpoint `ck` of a cut of `rows` extent rows and raises the highest
    /// `(session, capture)` to `ck`'s.
    ///
    /// # Errors
    ///
    /// As [`placement`](Self::placement); each leaves the set unchanged.
    #[cfg(test)]
    fn reserve(&mut self, ck: Checkpoint, rows: u64) -> Result<u32, ReserveRefusal> {
        let slot = self.placement(ck, rows)?;
        self.commit(slot, ck);
        Ok(slot)
    }

    fn commit(&mut self, slot: u32, ck: Checkpoint) {
        self.reserved = Some((slot, ck));
        self.highest = Some((ck.session, ck.capture));
    }

    /// Reserves the lowest free slot for the stage of checkpoint `ck` over `cut` and raises the highest
    /// `(session, capture)` to `ck`'s. The thread that holds the set reserves; [`StagedCheckpoint::encode`] then
    /// builds the stage from the reservation and the same cut with no access to the set, so the encode may run on
    /// another thread while the set stays with its holder.
    ///
    /// # Errors
    ///
    /// As `placement`; each leaves the set unchanged.
    pub fn reserve_stage(
        &mut self,
        ck: Checkpoint,
        cut: &Cut,
    ) -> Result<Reservation, ReserveRefusal> {
        let rows = cut.counted().rows;
        let slot = self.placement(ck, rows)?;
        self.commit(slot, ck);
        Ok(Reservation {
            checkpoint: ck,
            slot,
            slot_units: self.layout.slot_units,
            rows,
        })
    }

    /// Ends `reservation`, whose stage was never built, when the set holds it: no unit write reached the slot, so
    /// it goes free.
    pub fn release(&mut self, reservation: Reservation) {
        if self.reserved == Some((reservation.slot, reservation.checkpoint)) {
            self.reserved = None;
        }
    }

    /// Whether a checkpoint-unit write of `staged` is admitted: the set holds the reservation for its slot and
    /// checkpoint.
    pub fn admits(&self, staged: &StagedCheckpoint) -> bool {
        self.reserved == Some((staged.slot, staged.checkpoint))
    }

    fn quarantine(&mut self, slot: u32) {
        if !self.quarantined.contains(&slot) {
            self.quarantined.push(slot);
        }
    }

    /// Quarantines each slot of `before` that the set no longer holds, except the slot named at the tenure's start,
    /// which goes free.
    fn quarantine_left(&mut self, before: &[u32]) {
        for &slot in before {
            if self.contains(slot) {
                continue;
            }
            if self.fenced == Some(slot) {
                self.fenced = None;
            } else {
                self.quarantine(slot);
            }
        }
    }

    /// Ends `staged`'s reservation as its Publish is submitted; the Publish enters the slot into the set. A retry of a
    /// stage whose first Publish already ended its reservation leaves a later stage's reservation in place.
    fn consume(&mut self, staged: &StagedCheckpoint) {
        if self.admits(staged) {
            self.reserved = None;
        }
    }

    /// Ends `staged`'s reservation when the set holds it, quarantining its slot when a unit write exposed it.
    fn release_stage(&mut self, staged: &StagedCheckpoint) {
        if self.admits(staged) {
            self.reserved = None;
            if staged.exposed {
                self.quarantine(staged.slot);
            }
        }
    }

    /// Records an own shard-record write naming `slot`, or naming no checkpoint when `None`, before it is sent.
    pub(crate) fn submit(&mut self, slot: Option<u32>) -> Submitted {
        let id = self.next;
        self.next += 1;
        self.pending.push(Pending {
            id,
            slot,
            succeeded: false,
        });
        Submitted(id)
    }

    /// Removes `write`, which the client refused before sending any request, so it can never commit, and quarantines
    /// its slot when the set no longer holds it: the stage that wrote the slot may have left attempts on it.
    fn abandon(&mut self, write: Submitted) {
        let before = self.slots();
        self.pending.retain(|p| p.id != write.0);
        self.quarantine_left(&before);
    }

    /// Takes `write`, sent with its outcome unsettled, as superseding every earlier unsucceeded write of its slot: a
    /// success settles the set only when its version is at least the last settled one and no unsucceeded write
    /// follows it, and `write` follows each of them, so the set keeps one pending entry per slot.
    fn sent(&mut self, write: Submitted) {
        let Some(slot) = self
            .pending
            .iter()
            .find(|p| p.id == write.0)
            .map(|p| p.slot)
        else {
            return;
        };
        self.pending
            .retain(|p| p.id >= write.0 || p.succeeded || p.slot != slot);
    }

    /// Takes the acknowledged success of `write`, which committed a record naming `named` at `version`. When
    /// `version` is at least the last settled one and every own write that has not succeeded was submitted before
    /// `write`, the set becomes `named` alone and every slot it dropped is quarantined; otherwise `write` is marked
    /// succeeded and the set keeps its slots.
    fn succeeded(&mut self, write: Submitted, named: Option<NamedCheckpoint>, version: Version) {
        let Some(at) = self.pending.iter().position(|p| p.id == write.0) else {
            return;
        };
        let newest = self.settled.is_none_or(|settled| version >= settled);
        let settles = newest
            && self
                .pending
                .iter()
                .all(|p| p.id == write.0 || p.succeeded || p.id < write.0);
        if settles {
            let before = self.slots();
            self.named = named.map(|ck| ck.slot);
            self.pending.clear();
            self.settled = Some(version);
            self.quarantine_left(&before);
        } else {
            self.pending[at].succeeded = true;
        }
    }
}

/// The bytes the capture budget is charged for each unit buffer a stage or a tenure holds: the buffer, its pointer
/// in the unit list and the unit's verified flag.
pub const PER_UNIT: usize = UNIT_LEN + size_of::<Box<[u8; UNIT_LEN]>>() + size_of::<bool>();

/// One capture's checkpoint from encode to Publish: its units, encoded once and retained so every write attempt of a
/// unit carries the same bytes, the slot reserved for it, and which units read back equal since their last write.
/// [`abandon`](Self::abandon) ends an unpublished stage; a stage dropped unpublished keeps its reservation, and every
/// later reservation of the tenure refuses `Busy`.
#[must_use]
#[derive(Debug)]
pub struct StagedCheckpoint {
    checkpoint: Checkpoint,
    slot: u32,
    units: Vec<Box<[u8; UNIT_LEN]>>,
    verified: Vec<bool>,
    /// A unit write was staged, so an attempt may land on the slot.
    exposed: bool,
    /// A Publish of the stage was submitted, which consumed the reservation.
    published: bool,
}

/// The slot a possibly-named set reserved for one stage ([`PossiblyNamed::reserve_stage`]), from the reservation
/// until [`StagedCheckpoint::encode`] builds the stage or [`PossiblyNamed::release`] ends it. A reservation dropped
/// without either keeps the set's reservation, and every later reservation of the tenure refuses `Busy`.
#[must_use]
#[derive(Debug)]
pub struct Reservation {
    checkpoint: Checkpoint,
    slot: u32,
    slot_units: u32,
    /// The extent rows of the cut the slot was placed for.
    rows: u64,
}

/// Why [`StagedCheckpoint::new`] staged nothing. A refusal reserves no slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageRefusal {
    Encode(EncodeRefusal),
    Reserve(ReserveRefusal),
    /// The engine budget cannot hold the encoded units, or the allocator refused them.
    Memory,
}

impl StagedCheckpoint {
    /// Reserves a slot in `possible`'s layout and encodes every row of `entries` into that slot as checkpoint
    /// `checkpoint`.
    ///
    /// # Errors
    ///
    /// `Reserve` when no slot can be reserved, `Memory` when `budget` or the allocator cannot hold the units, `Encode`
    /// when an entry cannot be encoded.
    pub fn new(
        crc: Crc32c,
        possible: &mut PossiblyNamed,
        (checkpoint, entries): (Checkpoint, &[CaptureEntry]),
        budget: &EngineBudget,
    ) -> Result<Self, StageRefusal> {
        let counted = Counted::of(entries);
        Self::stage(crc, possible, checkpoint, (entries, counted), budget)
    }

    /// Builds the stage `reservation` holds a slot for from `cut`, the cut the reservation was taken over: checks
    /// the units against `budget` and encodes every row into the buffers of `kept` first, so a tenure's pass reuses
    /// the unit buffers its last pass kept, and into fresh buffers after them. The call reads no possibly-named set.
    ///
    /// The units the stage needs and the kept buffers past them are checked together against `budget`. The kept
    /// buffers past the units the stage needs are freed first when they number more than twice those units, and when
    /// `budget` cannot hold them with the stage. On success `kept` holds the kept buffers the stage did not take;
    /// after a refusal it holds at most the buffers it held before the call.
    ///
    /// # Errors
    ///
    /// `Memory` when `budget` or the allocator cannot hold the units and `Encode` when a member cannot be encoded,
    /// each with the reservation, which the set's holder releases.
    ///
    /// # Panics
    ///
    /// When `cut` holds another row count than the reservation was placed for.
    pub fn encode(
        crc: Crc32c,
        reservation: Reservation,
        (cut, kept): (&Cut, &mut Units),
        budget: &EngineBudget,
    ) -> Result<Self, (StageRefusal, Reservation)> {
        let counted = cut.counted();
        assert_eq!(
            counted.rows, reservation.rows,
            "ReservedBeforeWrite: a stage encodes the cut its slot was placed for"
        );
        let Reservation {
            checkpoint,
            slot,
            slot_units,
            ..
        } = reservation;
        match Self::encoded(crc, checkpoint, (cut, counted), (slot_units, budget), kept) {
            Ok((units, verified)) => Ok(Self {
                checkpoint,
                slot,
                verified,
                units,
                exposed: false,
                published: false,
            }),
            Err(refusal) => Err((refusal, reservation)),
        }
    }

    /// The units of `members` as checkpoint `checkpoint` in a slot of `slot_units` units, in the buffers of `kept`
    /// first, checked with the kept buffers against `budget`, and their unverified flags.
    fn encoded<M: Members + ?Sized>(
        crc: Crc32c,
        checkpoint: Checkpoint,
        (members, counted): (&M, Counted),
        (slot_units, budget): (u32, &EngineBudget),
        kept: &mut Units,
    ) -> Result<(Units, Vec<bool>), StageRefusal> {
        let needed = usize::try_from(units(counted.rows)).map_err(|_| StageRefusal::Memory)?;
        if kept.len() > needed.saturating_mul(2) {
            kept.truncate(needed);
        }
        // The stage's units and the kept buffers it leaves are held together until the pass ends.
        let fits = |held: usize| {
            let mut scratch = *budget;
            (held.checked_mul(PER_UNIT)).is_some_and(|bytes| scratch.charge(bytes).is_ok())
        };
        if !fits(kept.len().max(needed)) {
            kept.truncate(needed);
            if !fits(needed) {
                return Err(StageRefusal::Memory);
            }
        }
        let units = encode_counted(crc, checkpoint, (members, counted), slot_units, kept).map_err(
            |refusal| match refusal {
                EncodeRefusal::Memory => StageRefusal::Memory,
                refusal => StageRefusal::Encode(refusal),
            },
        )?;
        let mut verified = Vec::new();
        verified
            .try_reserve_exact(units.len())
            .map_err(|_| StageRefusal::Memory)?;
        verified.resize(units.len(), false);
        Ok((units, verified))
    }

    fn stage<M: Members + ?Sized>(
        crc: Crc32c,
        possible: &mut PossiblyNamed,
        checkpoint: Checkpoint,
        (members, counted): (&M, Counted),
        budget: &EngineBudget,
    ) -> Result<Self, StageRefusal> {
        let slot_units = possible.layout.slot_units;
        let slot = possible
            .placement(checkpoint, counted.rows)
            .map_err(StageRefusal::Reserve)?;
        let (units, verified) = Self::encoded(
            crc,
            checkpoint,
            (members, counted),
            (slot_units, budget),
            &mut Vec::new(),
        )?;
        possible.commit(slot, checkpoint);
        Ok(Self {
            checkpoint,
            slot,
            verified,
            units,
            exposed: false,
            published: false,
        })
    }

    /// A stage of `units` for `checkpoint` holding a reservation of `slot`, set directly so a test can stage any slot
    /// and capture.
    #[cfg(test)]
    pub(crate) fn reserved_at(
        possible: &mut PossiblyNamed,
        checkpoint: Checkpoint,
        slot: u32,
        units: Vec<Box<[u8; UNIT_LEN]>>,
    ) -> Self {
        possible.reserved = Some((slot, checkpoint));
        Self {
            checkpoint,
            slot,
            verified: vec![false; units.len()],
            units,
            exposed: false,
            published: false,
        }
    }

    pub fn slot(&self) -> u32 {
        self.slot
    }

    /// The units, unit 0 first.
    pub fn units(&self) -> &[Box<[u8; UNIT_LEN]>] {
        &self.units
    }

    /// The checkpoint a Publish of the stage names.
    pub fn named(&self) -> NamedCheckpoint {
        NamedCheckpoint {
            slot: self.slot,
            session: self.checkpoint.session,
            capture: self.checkpoint.capture,
            units: self.verified.len() as u32,
        }
    }

    /// Records that a write of unit `unit` was staged: the slot is exposed and the unit awaits its read-back.
    pub(crate) fn wrote(&mut self, unit: u32) {
        self.exposed = true;
        self.verified[unit as usize] = false;
    }

    /// Takes the read-back of unit `unit` of slot `slot`, which returned `read`: a unit of this stage's slot is
    /// verified when `read` equals its staged bytes and unverified otherwise.
    pub(crate) fn read_back(&mut self, (slot, unit): (u32, u32), read: &[u8; UNIT_LEN]) {
        if slot == self.slot
            && let Some(staged) = self.units.get(unit as usize)
        {
            self.verified[unit as usize] = **staged == *read;
        }
    }

    /// Whether every unit read back equal since its last write.
    pub fn verified(&self) -> bool {
        self.verified.iter().all(|&verified| verified)
    }

    /// Whether unit `unit` read back equal since its last write; `false` for a unit the stage does not hold.
    pub fn unit_verified(&self, unit: u32) -> bool {
        self.verified.get(unit as usize).copied().unwrap_or(false)
    }

    /// Takes the stage's units, which leaves it none to write, so the caller keeps their buffers for a later encode
    /// or frees them where it chooses.
    pub fn take_units(&mut self) -> Vec<Box<[u8; UNIT_LEN]>> {
        std::mem::take(&mut self.units)
    }

    /// Ends the stage. An unpublished stage releases its reservation: the slot is quarantined once a unit write was
    /// staged and free otherwise. A published stage's slot stays in the set: its own Publish's settling success
    /// leaves it named, and a later settling success or the client's refusal of the Publish before sending
    /// quarantines it.
    pub fn abandon(self, possible: &mut PossiblyNamed) {
        possible.release_stage(&self);
    }
}

/// Why a Publish or Confirm returned no adopted success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteRefused {
    /// A unit of the staged checkpoint has not read back equal since its last write; a read-back may verify it.
    Unverified,
    /// The stage holds neither the reservation nor, after its first submission, a slot in the set: a later success
    /// or a refusal before sending moved its slot out, and the stage can never publish.
    Superseded,
    /// The capture proof identifies a different shard, session, or pass counter than the stage encodes.
    OtherPass,
    /// The capture proof's epoch differs from the epoch the caller read from the storage: an attach, a restored
    /// install or a load commit replaced the membership between the pass's start and that read, so its cut may omit
    /// live members.
    Replaced,
    /// The read value is of another shard than the stage's checkpoint, or shows another `(generation, owner, E)`.
    Tenure,
    /// The read value names another `ck` than the tenure knows.
    Known,
    /// The proof's cut is below the record's or below the publishing tenure's first suffix LSN, the chain would pass
    /// `MAX_CHAIN` suffixes or a suffix would span more than the region's blocks, a reservation's record names no
    /// checkpoint, or no suffix is of the session a certification names.
    Chain,
    /// The client returned an error. The write may have committed when the error followed a request: a refusal
    /// before any request leaves the set, and every other error keeps the write's slot in it. A Confirm, a chain
    /// rewrite or a retry that found its stage named, on a read below the version the set last settled at, cannot
    /// commit and entered no slot.
    Store(StoreError),
}

/// Publishes `staged` with an exact-version compare-and-swap on `read`, which must show `own` and the `known`
/// checkpoint. `cut` is the capture's proof that every member of the stage's cut still owned its units or left
/// through a removal the suffix recorded at or above the cut, which the replay from the cut excludes; it must name
/// the stage's shard, session and capture number, and carry `epoch`, the capture epoch of the storage that took it,
/// read by the caller at this call. The first
/// submission consumes the stage's reservation. A retry after an unknown outcome resubmits the same checkpoint while
/// its slot is still in the set; when `read` already names the stage, that outcome committed, and the retry
/// compare-and-swaps `read`'s own value, which settles the set as a Confirm does. The published record's cut is the
/// proof's, and its ancestry keeps every suffix ending above that cut.
///
/// The epoch comparison covers the replacements that ran before the caller read `epoch`, and the request's
/// condition is the record version alone. The caller keeps every attach, restored install and load commit of that
/// storage from running between that read and the settlement of this Publish's write: the store's acknowledged
/// outcome for it, or the acknowledged success of a later own exact-version write, after which it cannot commit. A
/// write whose outcome is unknown stays unsettled when this call returns. A replacement inside that interval lets
/// the write name a cut taken before the replacement, so the checkpoint may omit live members.
///
/// # Errors
///
/// `OtherPass`, `Replaced`, `Unverified`, `Superseded`, `Tenure`, `Known` or `Chain` before any request, or `Store`
/// with the client's error.
pub fn publish<S: Store, L: WatermarkLog>(
    client: &mut Client<S, L>,
    possible: &mut PossiblyNamed,
    read: &Read<ShardRecord>,
    (own, known): (Target, Option<NamedCheckpoint>),
    (cut, epoch): (&CutIntact, CaptureEpoch),
    staged: &mut StagedCheckpoint,
) -> Result<Read<ShardRecord>, WriteRefused> {
    let Checkpoint {
        shard,
        session,
        capture,
    } = staged.checkpoint;
    if (cut.tenure(), cut.counter()) != ((shard, session), capture) {
        return Err(WriteRefused::OtherPass);
    }
    if cut.epoch() != epoch {
        return Err(WriteRefused::Replaced);
    }
    if !staged.verified() {
        return Err(WriteRefused::Unverified);
    }
    if !(possible.admits(staged) || staged.published && possible.contains(staged.slot)) {
        return Err(WriteRefused::Superseded);
    }
    let record = read.value();
    if !possible.holds(record, own)
        || (staged.checkpoint.shard, staged.checkpoint.session) != possible.tenure
    {
        return Err(WriteRefused::Tenure);
    }
    if staged.published && record.checkpoint == Some(staged.named()) {
        return write(client, possible, read, *record);
    }
    if record.checkpoint != known {
        return Err(WriteRefused::Known);
    }
    // A pass whose cut lies below the tenure's first suffix LSN, its own suffix's start or the end of every recorded
    // suffix, sealed its cut before the tenure's log opened: its snapshot already reflects the records a replay from
    // that cut would apply again.
    let first = (record.ancestry.as_slice().iter())
        .find(|suffix| suffix.session == session)
        .map_or_else(|| suffix_start(record), |suffix| suffix.start);
    if cut.cut() < record.cut.max(first) {
        return Err(WriteRefused::Chain);
    }
    let kept: Vec<Suffix> = record
        .ancestry
        .as_slice()
        .iter()
        .copied()
        .skip_while(|suffix| suffix.end <= cut.cut())
        .collect();
    let next = ShardRecord {
        checkpoint: Some(staged.named()),
        cut: cut.cut(),
        ancestry: Ancestry::new(&kept).expect("a kept chain is no longer than the record's"),
        ..*record
    };
    possible.consume(staged);
    staged.published = true;
    staged.units = Vec::new();
    write(client, possible, read, next)
}

/// Confirms the tenure with an exact-version compare-and-swap of `read`'s own value, which must show `own`.
///
/// # Errors
///
/// `Tenure` before any request, or `Store` with the client's error.
pub fn confirm<S: Store, L: WatermarkLog>(
    client: &mut Client<S, L>,
    possible: &mut PossiblyNamed,
    read: &Read<ShardRecord>,
    own: Target,
) -> Result<Read<ShardRecord>, WriteRefused> {
    if !possible.holds(read.value(), own) {
        return Err(WriteRefused::Tenure);
    }
    write(client, possible, read, *read.value())
}

/// The first LSN of a new tenure's suffix under `record`: one past every recorded suffix, or the cut with none.
pub fn suffix_start(record: &ShardRecord) -> u64 {
    record
        .ancestry
        .as_slice()
        .last()
        .map_or(record.cut, |last| last.end)
}

/// The delta blocks `record`'s replay still requires, from its floor to the end of its last suffix, and the `J`
/// blocks of `layout`'s delta region.
pub fn required_history(record: &ShardRecord, layout: &Layout) -> (u64, u64) {
    let required = suffix_start(record).saturating_sub(suffix_floor(record));
    (required, delta_blocks(layout))
}

/// The floor of `record`'s required history: the lowest LSN its replay reads, the cut or the first suffix's start
/// when higher.
fn suffix_floor(record: &ShardRecord) -> u64 {
    let first = record.ancestry.as_slice().first();
    first.map_or(record.cut, |first| first.start.max(record.cut))
}

/// Whether `record` names a checkpoint or a suffix of another tenure than the one of `session`. A later replay of
/// such a record can rebuild entries that the membership of the tenure of `session` does not count: those the
/// conversion of that tenure's warm load omitted, those of a checkpoint unit that failed its checks at that load,
/// and those of a suffix block that load took for the unflushed tail.
fn inherited(record: &ShardRecord, session: u64) -> bool {
    record
        .checkpoint
        .is_some_and(|named| named.session != session)
        || (record.ancestry.as_slice().iter()).any(|suffix| suffix.session != session)
}

/// The floor the store names once `committed`, an own write's result, settled `possible` to its checkpoint alone:
/// no write that may still commit names a lower cut. `None` while another slot stays possibly named.
pub fn settled_floor(possible: &PossiblyNamed, committed: &ShardRecord) -> Option<u64> {
    (possible.of_tenure(committed)
        && possible.slots() == Vec::from_iter(committed.checkpoint.map(|ck| ck.slot)))
    .then(|| suffix_floor(committed))
}

/// Records the tenure's suffix `suffix`: raises the reserved end of the last suffix when it is of `suffix.session`,
/// and appends `suffix` otherwise. The store admits an append of the tenure's session that starts at or after every
/// recorded suffix and ends above the cut, and an extension of the current session's last suffix alone. Refuses
/// `Tenure`, or `Chain` for a record naming no checkpoint, which restart and takeover refuse beside a suffix, a
/// suffix of another session than the set's tenure, a chain at its cap or a suffix ending past
/// `min(floor, start) + J`, the appender's capacity over the read record's floor and the region's `J` blocks, before
/// any request.
pub fn reserve_suffix<S: Store, L: WatermarkLog>(
    client: &mut Client<S, L>,
    possible: &mut PossiblyNamed,
    (read, own): (&Read<ShardRecord>, Target),
    suffix: Suffix,
) -> Result<Read<ShardRecord>, WriteRefused> {
    if !possible.holds(read.value(), own) {
        return Err(WriteRefused::Tenure);
    }
    if read.value().checkpoint.is_none() {
        return Err(WriteRefused::Chain);
    }
    let region = super::recovery::delta::blocks(possible.layout());
    let (session, floor) = (possible.tenure.1, suffix_floor(read.value()));
    #[cfg(test)]
    let floor = if planted(Plant::Floorless) {
        u64::MAX
    } else {
        floor
    };
    rewrite_chain(client, possible, (read, own), |chain| {
        (suffix.session == session).then_some(())?;
        match chain
            .last_mut()
            .filter(|last| last.session == suffix.session)
        {
            Some(last) => last.end = last.end.max(suffix.end),
            None => chain.push(Suffix {
                certified: suffix.start,
                ..suffix
            }),
        }
        let last = chain.last()?;
        (last.end <= floor.min(last.start).saturating_add(region)).then_some(())
    })
}

/// Raises the certified end of the suffix of `session` to `certified`: the tenure's own log's `durable`, or for a
/// predecessor the blocks a recovery read whole, so a later hole below that end counts as damage. Refuses `Tenure`,
/// or `Chain` when no suffix is of `session`, before any request.
pub fn certify<S: Store, L: WatermarkLog>(
    client: &mut Client<S, L>,
    possible: &mut PossiblyNamed,
    (read, own): (&Read<ShardRecord>, Target),
    (session, certified): (u64, u64),
) -> Result<Read<ShardRecord>, WriteRefused> {
    rewrite_chain(client, possible, (read, own), |chain| {
        let suffix = chain.iter_mut().find(|suffix| suffix.session == session)?;
        suffix.certified = suffix.certified.max(certified);
        Some(())
    })
}

/// Certifies each `(session, certified)` of `ends`, the ends a warm load established for the predecessor suffixes
/// (`Volume::certified`), in order, each write over the record the previous one committed; a suffix the chain no
/// longer holds is skipped. Returns the last committed read.
///
/// # Errors
///
/// The first [`WriteRefused`] other than `Chain`, with the earlier writes committed.
pub fn certify_suffixes<S: Store, L: WatermarkLog>(
    client: &mut Client<S, L>,
    possible: &mut PossiblyNamed,
    (mut read, own): (Read<ShardRecord>, Target),
    ends: &[(u64, u64)],
) -> Result<Read<ShardRecord>, WriteRefused> {
    for &end in ends {
        match certify(client, possible, (&read, own), end) {
            Ok(committed) => read = committed,
            Err(WriteRefused::Chain) => {}
            Err(refused) => return Err(refused),
        }
    }
    Ok(read)
}

/// The bounds a tenure's mutation suffix runs under: the appender's limits, the blocks each reservation or extension
/// records past the head, and the blocks from the reserved end at which the tenure extends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuffixBounds {
    pub limits: SuffixLimits,
    pub step: u64,
    pub margin: u64,
}

/// Opens the tenure's mutation suffix once its warm load committed: certifies each predecessor suffix to its end in
/// `ends`, the ends the load established ([`Volume::certified`](super::Volume::certified)), places `storage`'s
/// unopened log at [`suffix_start`], records the tenure's own suffix of `bounds.step` blocks from there, at most
/// through `LSN_LIMIT`, then opens the log over the suffix the store
/// committed from its settled floor, so every membership change after the open is recorded or refused and no block
/// is written before the store records its range. The open tells the log whether the committed record names a checkpoint or
/// a suffix of another tenure (`SuffixLog::inherits`). The storage requires the log at the warm install and at each proof
/// [`cut_intact`](super::Storage::cut_intact) returns, so every change between those and the open refuses `History`;
/// a tenure whose record names no checkpoint calls this after its first Publish. A record already holding a suffix of the
/// tenure's session keeps it: the call reserves nothing more and opens over that suffix. Returns the last committed
/// read and whether this call opened the log, false for a log already open or used: it stays closed while the record names no checkpoint, since restart and takeover
/// refuse a suffix beside none, and while the floor is unsettled, the capture mutex is busy or `bounds.limits` are
/// invalid, and a later call opens it over the same reservation.
///
/// # Errors
///
/// The call returns the first [`WriteRefused`]; earlier writes remain committed and the log remains closed.
///
/// The store refuses the reservation with `Chain` while the record's chain is at its cap.
/// `open_suffix` tries the capture mutex once to place the log.
/// A placed log seals the next capture pass's cut at [`suffix_start`], so [`publish`] of that pass drops the
/// predecessor suffixes and a later `open_suffix` call reserves from the published cut.
/// A busy capture mutex leaves the log at its position; a later `open_suffix` call retries placement.
pub fn open_suffix<S: Store, L: WatermarkLog, P: super::Platform>(
    client: &mut Client<S, L>,
    possible: &mut PossiblyNamed,
    (read, own): (Read<ShardRecord>, Target),
    (storage, ends): (&super::Storage<P>, &[(u64, u64)]),
    bounds: SuffixBounds,
) -> Result<(Read<ShardRecord>, bool), WriteRefused> {
    if read.value().checkpoint.is_none() {
        return Ok((read, false));
    }
    let mut read = certify_suffixes(client, possible, (read, own), ends)?;
    let (shard, session) = possible.tenure;
    let own_last = |read: &Read<ShardRecord>| {
        let last = read.value().ancestry.as_slice().last().copied();
        last.filter(|last| last.session == session)
    };
    if own_last(&read).is_none() {
        let start = suffix_start(read.value());
        let _ = storage.with_suffix(|log| log.place(start));
        let suffix = Suffix {
            session,
            start,
            certified: start,
            end: start.saturating_add(bounds.step).min(super::LSN_LIMIT + 1),
        };
        read = reserve_suffix(client, possible, (&read, own), suffix)?;
    }
    let last = own_last(&read);
    let opened = match (settled_floor(possible, read.value()), last) {
        (Some(floor), Some(suffix)) => {
            let open = (bounds.limits, possible.layout());
            let inherited = inherited(read.value(), session);
            let opened = storage.with_suffix(|log| {
                log.inherits(inherited);
                log.open((Crc32c::detect(), shard), open, suffix, floor)
            });
            opened.unwrap_or(false)
        }
        _ => false,
    };
    Ok((read, opened))
}

/// What an open suffix asks of its tenure once a store step ran: a planned handoff, due when the head lies
/// within the margin of the tenure's bound of `J` blocks from its start, which only a new tenure clears; and a
/// checkpoint publication, due when the reserved end reached the capacity the settled floor allows below that bound
/// and the head lies within the margin of it, which only a settled publish raising the floor clears.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SuffixDue {
    pub handoff: bool,
    pub publication: bool,
}

/// One store step of an open suffix, run off the publication path: tells the log whether `read` still names a
/// checkpoint or a suffix of another tenure (`SuffixLog::inherits`), raises the log's capacity to the floor `read`
/// settles, records a continuation of the tenure's suffix from the cut when a Publish whose cut reached the reserved
/// end dropped it and the cut lies below the tenure's bound of `J` blocks from its start, certifies the durable prefix once it passed the certified end, then records a reserved end
/// `bounds.step` blocks past the head, at most the capacity, once the head lies within `bounds.margin` of the
/// reserved end; each write reaches the log only after the store committed it, so the log never admits past what
/// the store records, and a certification never waits on an extension. A dropped suffix whose cut reached the
/// tenure's bound writes nothing. Returns the last committed read, or the first [`WriteRefused`] with the earlier
/// writes committed and the log refusing at its reserved and certified ends, beside the signals the log raised before
/// the writes, which a refusal does not drop. A step whose one try of the capture mutex fails, on a held or poisoned
/// mutex or a storage in finalization, samples nothing: it writes nothing and returns `read` with `None` for the
/// signals. A log that never opened is sampled: the step writes nothing and returns `read` with the log's signals.
pub fn suffix_step<S: Store, L: WatermarkLog, P: super::Platform>(
    client: &mut Client<S, L>,
    possible: &mut PossiblyNamed,
    (read, own): (Read<ShardRecord>, Target),
    storage: &super::Storage<P>,
    bounds: SuffixBounds,
) -> (Result<Read<ShardRecord>, WriteRefused>, Option<SuffixDue>) {
    let floor = settled_floor(possible, read.value());
    // A read outside the possible tenure preserves the log's inheritance flag.
    let inherited = possible
        .of_tenure(read.value())
        .then(|| inherited(read.value(), possible.tenure.1));
    let state = storage.with_suffix(|log| {
        if let Some(inherited) = inherited {
            log.inherits(inherited);
        }
        if let Some(floor) = floor {
            log.covered(floor);
        }
        let end = log.head().saturating_add(bounds.step).min(log.capacity());
        let extend = log.needs_extension(bounds.margin) && end > log.recorded().end;
        let due = SuffixDue {
            handoff: log.handoff_due(bounds.margin),
            publication: log.publication_due(bounds.margin),
        };
        (
            log.recorded(),
            extend.then_some(end),
            log.durable(),
            due,
            log.bound(),
        )
    });
    let Ok((suffix, end, durable, due, bound)) = state else {
        return (Ok(read), None);
    };
    if suffix.session == 0 {
        return (Ok(read), Some(due));
    }
    let step = || -> Result<Read<ShardRecord>, WriteRefused> {
        let mut read = read;
        let ancestry = read.value().ancestry;
        if !(ancestry.as_slice().iter()).any(|kept| kept.session == suffix.session) {
            let cut = read.value().cut;
            // A continuation starts at the cut, below the tenure's bound of `J` blocks from its start.
            if cut >= bound {
                return Ok(read);
            }
            let end = end.unwrap_or(suffix.end).max(cut + 1);
            let continued = Suffix {
                start: cut,
                certified: cut,
                end,
                ..suffix
            };
            let read = reserve_suffix(client, possible, (&read, own), continued)?;
            let _ = storage.with_suffix(|log| {
                log.extend(end);
                log.certified(cut);
            });
            return Ok(read);
        }
        if durable > suffix.certified {
            read = certify(client, possible, (&read, own), (suffix.session, durable))?;
            let _ = storage.with_suffix(|log| log.certified(durable));
        }
        if let Some(end) = end {
            let extended = Suffix { end, ..suffix };
            read = reserve_suffix(client, possible, (&read, own), extended)?;
            let _ = storage.with_suffix(|log| log.extend(end));
        }
        Ok(read)
    };
    (step(), Some(due))
}

/// Writes `read`'s value, which must be of `possible`'s tenure and show `own`, with the ancestry `edit` produces, settling
/// `possible` as a Confirm does; refuses `Chain` when `edit` refuses or the chain exceeds its cap, and returns `Store`
/// with the client's error.
fn rewrite_chain<S: Store, L: WatermarkLog>(
    client: &mut Client<S, L>,
    possible: &mut PossiblyNamed,
    (read, own): (&Read<ShardRecord>, Target),
    edit: impl FnOnce(&mut Vec<Suffix>) -> Option<()>,
) -> Result<Read<ShardRecord>, WriteRefused> {
    let record = read.value();
    if !possible.holds(record, own) {
        return Err(WriteRefused::Tenure);
    }
    let mut chain = record.ancestry.as_slice().to_vec();
    edit(&mut chain).ok_or(WriteRefused::Chain)?;
    #[cfg(test)]
    if planted(Plant::ChainDropsOldest) && chain.len() > crate::failover::records::MAX_CHAIN {
        chain.remove(0);
    }
    let next = ShardRecord {
        ancestry: Ancestry::new(&chain).ok_or(WriteRefused::Chain)?,
        ..*record
    };
    write(client, possible, read, next)
}

/// Writes `next` over `read` with an exact-version compare-and-swap, entering the slot `next` names into `possible`
/// before the request and settling `possible` on the adopted success. A write that keeps `read`'s checkpoint on a
/// read below the version the set last settled at enters nothing: the record's version passed `read`'s, so the write
/// cannot commit, and a settling success since `read` may have dropped the slot it names. A Publish on such a read
/// names its stage's own slot and enters it, so the next settling success quarantines the slot.
fn write<S: Store, L: WatermarkLog>(
    client: &mut Client<S, L>,
    possible: &mut PossiblyNamed,
    read: &Read<ShardRecord>,
    next: ShardRecord,
) -> Result<Read<ShardRecord>, WriteRefused> {
    let slot = next.checkpoint.map(|ck| ck.slot);
    let passed = next.checkpoint == read.value().checkpoint
        && (possible.settled).is_some_and(|settled| read.version() < settled);
    let write = (!passed).then(|| possible.submit(slot));
    match client.replace(read, next) {
        Ok(committed) => {
            let write = write.unwrap_or_else(|| possible.submit(slot));
            possible.succeeded(write, next.checkpoint, committed.version());
            Ok(committed)
        }
        Err(error) => Err(write.map_or(WriteRefused::Store(error), |write| {
            refused(possible, write, error)
        })),
    }
}

/// The refusal of `write` for `error`: a write the client refused before sending, by withdrawal, the successor
/// rule, the namespace check or the codec (the errors [`Client::replace`] returns before any request), leaves the set; every other error
/// may follow a sent request and keeps its slot.
fn refused(possible: &mut PossiblyNamed, write: Submitted, error: StoreError) -> WriteRefused {
    if matches!(
        error,
        StoreError::Withdrawn
            | StoreError::Successor(_)
            | StoreError::Namespace
            | StoreError::Codec(_)
    ) || planted_unknown()
    {
        possible.abandon(write);
    } else {
        possible.sent(write);
    }
    WriteRefused::Store(error)
}

/// Why a reader for a named checkpoint could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderRefusal {
    /// The layout fails its floor, the named slot is past the layout's slots, its unit count is zero or past the
    /// slot's units, the layout's or the suffix's extent overflows `u64`, or the reader was given zero destinations.
    Slot,
    /// The engine budget cannot hold the decode of the named units and the replay of the suffix, or the allocator
    /// refused the decode's destination table.
    Memory,
}

/// A planted defect for a negative control of the reader.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plant {
    /// The reader loads nothing from a damaged slot and evicts every whole entry of its intact units.
    AllOrNothing,
    /// A write whose outcome is unknown leaves the set as a refusal before sending does.
    AbandonUnknown,
    /// A chain rewrite past the cap drops its oldest suffix.
    ChainDropsOldest,
    /// A reservation admits a `(session, capture)` the set already reserved or found named.
    CaptureReuse,
    /// A suffix reservation's bound ignores the read record's floor, as a release of that history by elapsed time
    /// would allow.
    Floorless,
}

#[cfg(test)]
thread_local! {
    pub(crate) static PLANT: std::cell::Cell<Option<Plant>> = const { std::cell::Cell::new(None) };
    /// The reads [`SlotReader::completed_copy`] copied on this thread, for the tests that a late terminal copies none.
    pub(crate) static COPIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn planted(plant: Plant) -> bool {
    PLANT.with(std::cell::Cell::get) == Some(plant)
}

/// Whether the `AbandonUnknown` plant is set; false outside tests.
fn planted_unknown() -> bool {
    #[cfg(test)]
    return planted(Plant::AbandonUnknown);
    #[cfg(not(test))]
    false
}

/// Read windows a reader holds: a slot read's from its issue until every destination applied its facts, and a suffix
/// read's from its issue until the read completes.
pub const WINDOWS: usize = 2 * READ_DEPTH;

/// The reader of the one slot the store names and of its ancestry's suffix blocks, whose [`decode`](Self::decode) runs
/// on the recovery helpers.
pub struct SlotReader {
    decode: SlotDecode,
    /// The slot's first byte and one past its last named unit.
    start: u64,
    end: u64,
    /// The next read's first byte.
    next: u64,
    flight: Vec<DeviceRange>,
    /// Reads issued; at most [`WINDOWS`] more than the decode released.
    issued: usize,
    /// The delta region's first byte and its blocks, the suffix LSN runs still to read, last run first, and the
    /// suffix reads outstanding with their first LSN.
    delta: (u64, u64),
    /// The bytes one read spans at most; every read lies inside one window of this length.
    read_len: u64,
    /// The decode and replay estimate the construction checked against the budget.
    bytes: usize,
    runs: Vec<(u64, u64)>,
    blocks: Vec<(DeviceRange, u64)>,
}

impl SlotReader {
    /// # Errors
    ///
    /// `Slot` when the suffix LSN count overflows `u64`, and `Memory` when the estimate overflows `usize`.
    pub fn estimate(
        layout: &Layout,
        (named, cut, ancestry): (NamedCheckpoint, u64, &[Suffix]),
        (limits, destinations): (&LoadLimits, usize),
        read_len: u64,
    ) -> Result<usize, ReaderRefusal> {
        let blocks = (ancestry.iter())
            .map(|suffix| lsns(suffix, cut, layout))
            .try_fold(0u64, |sum, lsns| {
                sum.checked_add(lsns.end.saturating_sub(lsns.start))
            })
            .ok_or(ReaderRefusal::Slot)?;
        let windows = (WINDOWS, read_len as usize);
        SlotDecode::bytes(named.units, limits, destinations, windows)
            .zip(replay_bytes(blocks))
            .and_then(|(slot, suffix)| slot.checked_add(suffix))
            .ok_or(ReaderRefusal::Memory)
    }

    /// A reader of `named`'s slot under `layout` and of the suffixes of `ancestry` from `cut`, the record's
    /// `(ck, cut, ancestry)`, for the shard's reader session `reader`. The decode checks every entry against `limits`;
    /// `hasher` routes keys over `destinations` destinations, and `budget` must admit the peak decode and replay bytes.
    /// `hasher` is the installing index's hasher and `destinations` its enabled-shard count, so destination `d` of
    /// [`SlotLoad::shards`] is the index's `d`th enabled shard.
    /// The reader checks the decode and replay estimate, [`SlotDecode::bytes`] plus the replay's bytes, against
    /// `budget` and charges nothing; the caller holds a charge of that estimate until the load
    /// [`finish`](Self::finish) returns is installed or dropped and the threads that ran the reader's jobs ended,
    /// since a helper frees the buffers a seal is done with after it sent the seal's terminal; when a warm bootstrap
    /// stages the load, until the volume and its helper pool drop, since the warm state and its free jobs keep the
    /// load's chunks. Reads span [`READ_LEN`]-aligned windows.
    ///
    /// # Errors
    ///
    /// `Slot` when `layout.check_floor()` fails, `named` does not fit `layout`, the layout's bytes or the suffix
    /// LSN count overflow `u64`, or `destinations` is zero. `Memory` when the decode and the replay exceed `budget`
    /// or the allocator refuses the decode's destination table.
    #[cfg(test)]
    pub fn new(
        crc: Crc32c,
        layout: &Layout,
        shard: Shard,
        named: (NamedCheckpoint, u64, &[Suffix]),
        reader: u64,
        limits: (LoadLimits, &EngineBudget),
        routing: (KeyHasher, usize),
    ) -> Result<Self, ReaderRefusal> {
        Self::with_read_len(crc, layout, shard, named, reader, limits, routing, READ_LEN)
    }

    /// A reader of `named`'s slot under `layout` and of the suffixes of `ancestry` from `cut` for the reader session
    /// `reader`, whose reads span windows of `read_len` bytes, a power of two of whole units at most [`READ_LEN`]: a
    /// device or buffer that carries less than a window per command reads the slot in shorter windows. The decode
    /// checks every entry against `limits`; `hasher` is the installing index's hasher and `destinations` its
    /// enabled-shard count, so destination `d` of [`SlotLoad::shards`] is the index's `d`th enabled shard. The reader
    /// checks its decode and replay estimate against `budget` and charges nothing; the caller holds a charge of that
    /// estimate until the load is installed or dropped and the threads that ran the reader's jobs ended; when a warm
    /// bootstrap stages the load, until the volume and its helper pool drop, since the warm state and its free jobs
    /// keep the load's chunks.
    ///
    /// # Errors
    ///
    /// `Slot` when `layout.check_floor()` fails, `read_len` is outside its bounds, `named` does not fit `layout`, the
    /// layout's bytes or the suffix LSN count overflow `u64`, or `destinations` is zero. `Memory` when the decode and
    /// the replay exceed `budget` or the allocator refuses the decode's destination table.
    #[expect(
        clippy::too_many_arguments,
        reason = "the reader takes the record's manifest, the tenure's limits and the index routing it serves"
    )]
    pub fn with_read_len(
        crc: Crc32c,
        layout: &Layout,
        shard: Shard,
        (named, cut, ancestry): (NamedCheckpoint, u64, &[Suffix]),
        reader: u64,
        (limits, budget): (LoadLimits, &EngineBudget),
        (hasher, destinations): (KeyHasher, usize),
        read_len: u64,
    ) -> Result<Self, ReaderRefusal> {
        layout.check_floor().map_err(|_| ReaderRefusal::Slot)?;
        if !read_len.is_power_of_two() || read_len < IO_UNIT as u64 || read_len > READ_LEN {
            return Err(ReaderRefusal::Slot);
        }
        let first = layout
            .prefix_unit(named.slot, 0)
            .ok_or(ReaderRefusal::Slot)?;
        if named.units == 0 || named.units > layout.slot_units || destinations == 0 {
            return Err(ReaderRefusal::Slot);
        }
        let unit = IO_UNIT as u64;
        let start = first.checked_mul(unit).ok_or(ReaderRefusal::Slot)?;
        // The floor holds every slot inside the layout's units, so the named units end inside the metadata area.
        let end = first
            .checked_add(u64::from(named.units))
            .and_then(|end| end.checked_mul(unit))
            .filter(|end| end.checked_add(READ_LEN).is_some())
            .ok_or(ReaderRefusal::Slot)?;
        let runs: Vec<(u64, u64)> = ancestry
            .iter()
            .map(|suffix| lsns(suffix, cut, layout))
            .filter(|lsns| lsns.start < lsns.end)
            .map(|lsns| (lsns.start, lsns.end))
            .rev()
            .collect();
        // Every suffix read ends at or before the layout's last unit, whose end leaves one read window inside `u64`.
        let region = delta_blocks(layout);
        let units_end = (layout.units.checked_mul(unit))
            .filter(|end| end.checked_add(READ_LEN).is_some())
            .ok_or(ReaderRefusal::Slot)?;
        let manifest = (named, cut, ancestry);
        let bytes = Self::estimate(layout, manifest, (&limits, destinations), read_len)?;
        let mut scratch = *budget;
        if scratch.charge(bytes).is_err() {
            return Err(ReaderRefusal::Memory);
        }
        let checkpoint = Checkpoint {
            shard,
            session: named.session,
            capture: named.capture,
        };
        let decode = SlotDecode::new(
            crc,
            checkpoint,
            named.units,
            reader,
            limits,
            (hasher, destinations),
            (*layout, cut, ancestry),
        )
        .ok_or(ReaderRefusal::Memory)?;
        Ok(Self {
            decode,
            start,
            end,
            next: start,
            flight: Vec::with_capacity(READ_DEPTH),
            issued: 0,
            delta: (units_end - region * unit, region),
            read_len,
            bytes,
            runs,
            blocks: Vec::new(),
        })
    }

    /// The decode and replay estimate the construction checked against the budget, which the caller holds charged
    /// until the load is installed or dropped.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// The next read to submit, while fewer than [`READ_DEPTH`] are outstanding and fewer than [`WINDOWS`] windows are
    /// held: the suffix blocks first, each read ending at the next window boundary, the region's wrap or its
    /// run's end, then the slot's bytes from the previous read's end to the next window boundary or the slot's
    /// end.
    #[must_use]
    pub fn next_read(&mut self) -> Option<DeviceRange> {
        let (issued, released) = (self.issued, self.decode.released());
        let held = (issued.checked_sub(released))
            .unwrap_or_else(|| panic!("{released} windows released of {issued} issued reads"));
        let full = self.flight.len() + self.blocks.len() >= READ_DEPTH || held >= WINDOWS;
        let exhausted = self.next >= self.end && self.runs.is_empty();
        if full || exhausted || self.decode.done() {
            return None;
        }
        self.issued += 1;
        if let Some((lsn, end)) = self.runs.last_mut() {
            let ((first, region), unit) = (self.delta, IO_UNIT as u64);
            let byte = first + *lsn % region * unit;
            let room = (byte / self.read_len + 1) * self.read_len - byte;
            let count = (*end - *lsn).min(region - *lsn % region).min(room / unit);
            let range =
                DeviceRange::new(byte, (count * unit) as u32).expect("a block read is in range");
            self.blocks.push((range, *lsn));
            *lsn += count;
            if lsn == end {
                self.runs.pop();
            }
            return Some(range);
        }
        let range = self.read_at(self.next);
        self.next = range.end();
        self.flight.push(range);
        Some(range)
    }

    fn read_at(&self, at: u64) -> DeviceRange {
        let window_end = (at / self.read_len + 1) * self.read_len;
        let len = window_end.min(self.end) - at;
        DeviceRange::new(at, len as u32).expect("a slot read is in range")
    }

    /// Takes the buffer `bytes` of a completed read of `range`, which [`next_read`](Self::next_read) issued: a suffix
    /// read's bytes go to the decode's replay, and a slot read's into its window's decode job. A unit the buffer does
    /// not hold whole counts as unread. The buffer holds at most one window, as the reader's estimate counts it; a
    /// caller copies the read into `SlotDecode::spare`'s buffer.
    /// A slot read returns its window's job; a suffix read returns `None`, and a caller that reserved a helper job for
    /// the read releases that reservation.
    #[must_use]
    pub fn completed(&mut self, range: DeviceRange, bytes: Vec<u8>) -> Option<Work> {
        debug_assert!(
            bytes.capacity() <= self.read_len as usize,
            "a read's buffer exceeds its charge"
        );
        let count = range.byte_len() / IO_UNIT as u32;
        if let Some(at) = self.blocks.iter().position(|(issued, _)| *issued == range) {
            let (_, lsn) = self.blocks.swap_remove(at);
            self.decode.blocks(lsn, u64::from(count), bytes);
            return None;
        }
        let at = range.start();
        let Some(flight) = self.flight.iter().position(|&read| read == range) else {
            let outstanding: Vec<_> = self.flight.iter().map(DeviceRange::start).collect();
            panic!("{range:?} is none of the outstanding reads starting at {outstanding:?}");
        };
        self.flight.swap_remove(flight);
        let first = ((at - self.start) / IO_UNIT as u64) as u32;
        Some(self.decode.window(first, count, bytes))
    }

    /// [`completed`](Self::completed) of a read of `range` whose device buffer holds `bytes`. The bytes are copied into
    /// `SlotDecode::spare`'s buffer, an emptied buffer of a landed window or a new one, which `reserve_exact` grows
    /// to the read's length when it is shorter. Every read lies inside one read window, so each buffer's capacity stays
    /// at most one window (BOUNDED).
    #[must_use]
    pub fn completed_copy(&mut self, range: DeviceRange, bytes: &[u8]) -> Option<Work> {
        #[cfg(test)]
        COPIES.with(|copies| copies.set(copies.get() + 1));
        let mut copy = self.decode.spare();
        copy.reserve_exact(bytes.len());
        copy.extend_from_slice(bytes);
        self.completed(range, copy)
    }

    /// [`completed`](Self::completed) of a read of `range` the device failed: each of its units or blocks counts as
    /// unread, and the return and the reservation follow `completed`.
    #[must_use]
    pub fn failed(&mut self, range: DeviceRange) -> Option<Work> {
        self.completed(range, Vec::new())
    }

    /// The decode, whose jobs the caller runs on the recovery helpers.
    pub fn decode(&mut self) -> &mut SlotDecode {
        &mut self.decode
    }

    /// Whether every issued read completed and the decode is done.
    pub fn done(&self) -> bool {
        self.flight.is_empty() && self.blocks.is_empty() && self.decode.done()
    }

    /// The load of the slot and its suffix once [`done`](Self::done), as [`SlotDecode::finish`] states it: a unit that
    /// failed its check or its read loses only the entries with a row on it, and the load keeps the whole entries of
    /// the intact units the suffix left in place and the suffix's live entries under the guard's verdict.
    /// `None` when a helper failed a job or the allocator refused a guard, a window's chunks, a destination's room or a
    /// seal's scratch, so the caller keeps the record.
    #[must_use]
    pub fn finish(self) -> Option<SlotLoad> {
        debug_assert!(self.done(), "the reader finishes after its last read");
        #[cfg(test)]
        if planted(Plant::AllOrNothing) {
            let mut slot = self.decode.finish()?;
            if let Some(damage) = &slot.damage {
                slot.verdict = Err(damage.alarm());
            }
            return Some(slot);
        }
        self.decode.finish()
    }
}

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
pub(crate) mod tests;
