//! The writable owner streams one attempt's records, one per extent, to the device through the volume, and publication requires every write of them to have succeeded.
//!
//! [`FillAttempt::reserve_storage`] consumes the attempt on every outcome.
//! It returns `Superseded` when the decision was made for other lengths or under a record format other than this storage's. An object of several extents is claimed through a builder: its whole charge is promised and every extent placed before the shard hold. [`FillAttempt::promise_storage`] starts that claim as a [`PlacingFill`], whose [`place`](PlacingFill::place) calls each place the extents one call's budget funds and whose [`reserve_storage`](PlacingFill::reserve_storage) runs the shard hold once every extent is placed, so a caller bounds each call's work and the placement spans calls; `FillAttempt::reserve_storage` drives the same owner to completion within its one budget.
//! Drained and geometry refusals precede the cutoff read, so `TornDown` and `Layout` are possible after close, as they are for the decision itself; the `MultipleExtents` refusal of a volume without a sequence arena follows it.
//! The extent claim follows [`Storage::reserve`], or for an object of several extents [`Storage::promise`] and its placements, outside the shard hold and shares the caller's budget.
//! The shard gate is then taken within the caller's tries; under it the cutoff is read once more and the record is revalidated: it must still carry this attempt's serial, undeparted and unrevoked, and this attempt's key.
//! Before the shard gate the key's fingerprint is routed again; a route to a shard other than the record's returns `Superseded`.
//! After the record check, under the same hold, the `place_claim` module claims the key's index place, one pending pair and one additional key against `V + P_index <= N`, and two `Shared` lease credits, the publisher's and the terminal read right's, and the record's place word names the place; a refused claim takes none of them.
//! The same hold marks the record's row upload-granted with the allocation and both lengths, so a follower may join the fill from then on.
//! No gate is held while another is taken.
//!
//! A refusal after the extent was claimed disposes of the extent first: the unwritten extent cancels, which returns it at once when the pool gate is free and otherwise records the abandonment for service, and only afterwards does the record depart, so a disposal panic there keeps the record occupied exactly as it does for an abort.
//! A newer attempt on the same key holds another record under another serial, so neither the disposal nor the departure can reach it.
//! A panic in the revalidation itself leaves the claimed extent charged and the record occupied, as a forgotten owner does, and finalization blocks on both.
//! A panic in the extent claim or the promise, under the pool gate, leaves the record occupied as well.
//!
//! [`WritableFill::receive`] takes the payload, metadata then body, as a stream, in pieces of any size.
//! An object of several extents streams each extent's record in order, each extent's locator read from its sequence's block under a quiet pool gate try, a later extent's once the previous extent's header segment was accepted; a busy gate refuses `TableFull`.
//! Each record is its header's bytes, then the extent's part of the payload, padded to the unit, cut into segments of the volume's write command length: segment `k` is record bytes `[k * S, (k + 1) * S)`, the last one ending at the extent's end.
//! The first segment's buffer holds the header's bytes and the extent's first payload bytes and stays staged until the extent's last payload byte arrives; each later segment's buffer submits once it is full or the record is complete, so the fill holds at most two buffers outside the table.
//! Attach requires at least `sum(F[s]) + 1` receive-write buffers, so while every live fill holds its first segment's buffer one more is left for some fill's later segment, and that segment's terminal returns it.
//! Copying folds each chunk's crc32c, over its record-aligned window, with the volume's mechanism, and stores it in the first buffer's chunk table.
//! For an input of at least `DERIVE_MIN` bytes that [`WritableFill::receive_verified`] takes with its verified crc32c, the fill copies each run of the input within one chunk that is at least as long as the input after it and derives that run's register from the crc32c; the chunk checksums it stores are the ones the fold stores.
//! When an extent's last payload byte arrives the fill encodes its header, carrying the key, the allocation's slot and incarnation, the volume's session, the object's cache version, the extent's index and payload offset and the whole lengths, with its context and header crc32c, into the first buffer and submits that buffer last: its chunk table needs every checksum.
//! The fill writes every byte of a submitted segment: header, payload, and zeros from the record's end to the extent's end, so each command carries only this record's bytes.
//! Readiness, not command order, enforces publication: `publish` refuses unless every unit of every extent reached a successful terminal and none failed.
//! Each segment submit first debits the caller's budget for one write command, one operation and the segment's aligned bytes; a short budget refuses `Budget` before the submit.
//! A refused submit leaves its buffer staged with the fill, copies nothing further, and leaves the set, the token map and the slot's count as they were; the next `receive`, with or without new bytes, retries it first.
//!
//! Revocation forbids publication and further receives: the revoking invalidation refunds the place, and a revoked owner keeps its extent, its record and its credits and disposes of them when it ends.
//! [`WritableFill::fail`] records a typed failure in the row before the owner's end, so its followers report that failure; an abort or a drop records none.
//! Close refuses new receives, reservations and publications. The owner keeps its extent and record, and abort and drop still dispose of them.
//!
//! [`WritableFill::abort`] consumes the owner; dropping it is the bounded fallback with no source, shard or grace waiting.
//! Both first dispose of the reservation through its own owner path, cancelling an extent no write was submitted for whose slot counts no right, or abandoning a written one or one whose slot counts a right, and only afterwards depart the record with the owner's final `Release` access; staged buffers return to their pool and both credits return at once, and the service pass that releases the departed record refunds its place.
//! A write still outstanding keeps its right in the slot's count, so service holds the abandoned extent until the write's terminal or, for a submit whose driver call unwound, the proven stop, and the volume frees the write set there.
//! A panic in the disposal leaves the record occupied and undeparted, so finalization blocks on it instead of a record freeing while its extent's fate is unknown.
//! An abandonment made while the pool gate is busy parks the slot, and a park that finds the slot word malformed or naming another incarnation leaves the slot to no one, so the record stays occupied and undeparted then too.
//!
//! The owner holds receive-write buffers, so it is neither `Send` nor `Sync`: it stays on the thread that reserved it.
//!
//! Compile-fail examples reject cloning, sharing, moving to another thread, reservation escape, owner reuse, and reusing a consumed attempt.
//!
//! ```compile_fail,E0599
//! # use kestrike::storage::*;
//! # fn f(fill: WritableFill<'_, '_, LinuxPlatform>) {
//! let _twin = fill.clone();
//! # }
//! ```
//!
//! ```compile_fail,E0277
//! # use kestrike::storage::*;
//! fn shared<T: Sync>(_: &T) {}
//! # fn f(fill: WritableFill<'_, '_, LinuxPlatform>) {
//! shared(&fill);
//! # }
//! ```
//!
//! ```compile_fail,E0277
//! # use kestrike::storage::*;
//! fn requires_send<T: Send>(_: T) {}
//! # fn f(fill: WritableFill<'_, '_, LinuxPlatform>) {
//! requires_send(fill);
//! # }
//! ```
//!
//! ```compile_fail,E0616
//! # use kestrike::storage::*;
//! # fn f(fill: WritableFill<'_, '_, LinuxPlatform>) {
//! let escaped = fill.reservation;
//! # }
//! ```
//!
//! ```compile_fail,E0382
//! # use kestrike::storage::*;
//! # fn f<'s, 'a, D: Disk>(mut fill: WritableFill<'s, 'a, LinuxPlatform>, volume: &mut Volume<'s, 'a, LinuxPlatform, D>, budget: &mut WorkBudget) {
//! fill.abort();
//! let _ = fill.receive(volume, &[1], budget);
//! # }
//! ```
//!
//! ```compile_fail,E0382
//! # use kestrike::storage::*;
//! # fn f(attempt: FillAttempt<'_, LinuxPlatform>, admitted: Admitted, budget: &mut WorkBudget) {
//! let _first = attempt.reserve_storage(admitted, Some(1), Some(1), 3, budget);
//! let _second = attempt.reserve_storage(admitted, Some(1), Some(1), 3, budget);
//! # }
//! ```
//!
//! Stable rustdoc does not check the error codes above; they record the intended causes for a reader, and `cargo +nightly test --doc` verifies them.

use std::mem::ManuallyDrop;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};

use super::admission::Admitted;
use super::allocation::{AllocationId, ExtentReservation};
use super::attempt::{AttemptRecord, CacheVersion, FillAttempt, FillHold, depart_word};
use super::budget::{BudgetExhausted, BudgetShort, WorkBudget, WorkKind};
use super::builder::{Builder, PromiseError};
use super::device::{Buffer, Disk, IO_UNIT, RefusalReason, SubmitRefusal};
use super::extent::ExtentLocator;
use super::fill::{self, FillSerial, Record};
use super::layout::{AllocationLayout, LayoutError, ObjectGeometry, object_geometry};
use super::os::Platform;
use super::owner::Storage;
use super::place_claim::{self, return_fill_credits};
use super::probe::{self, Primitive};
use super::publish::{Refusal, Tables, take_gate};
use super::record::{
    Crc32c, ExtentPosition, RecordIdentity, RecordLayout, RunningCrc, put_chunk_crc, seal_header,
};
use super::reserve::ReserveError;
use super::row::FillFailure;
use super::volume::{Volume, WriteProgress, WriteSet};
use crate::index::{Key, Prefetch, RouteError, ShardIndex};

/// Refusals of [`FillAttempt::reserve_storage`]; every variant consumes the attempt, and an extent claimed before the refusal was returned or parked for service before the record departed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillReserveError {
    Withdrawn,
    /// The storage is drained.
    TornDown,
    /// The lengths cannot be laid out under the live root's caps, or name an
    /// object of several extents on a volume without a sequence arena
    /// (`MultipleExtents`).
    Layout(LayoutError),
    /// Admission is closed, or the attached volume's attempt is withheld or closed.
    Closed,
    /// The attached volume is bootstrapping (running its Register, Acquire and Report gate, reading root slots, writing RESET roots, or waiting for a format) or awaiting replay reaching `Live`.
    Bootstrapping,
    /// The budget could not pay for a gate try, the update, a slot take, the extent search, the place's hash pass, the record visit, the key comparison, the credit attempt or the chain walk.
    BudgetExhausted,
    /// The pool gate was busy or poisoned, every paid shard gate attempt found it busy or poisoned, the attempt allowance was zero, or the lease credit's bounded compare-exchange ran out of attempts.
    Contended,
    /// Every slot is filling, resident, retired or quarantined.
    ObjectSlotsFull,
    /// No free run of the volume holds the layout's units or an extent of
    /// the object's, or the sequence arena holds no block for its extents.
    PayloadFull,
    /// The layout's charged units plus the clean reserve `R` and the escrow
    /// `U` of units promised to builders exceed the volume's free units; the
    /// attempt claimed no slot or extent.
    CleanReserve,
    /// The retired charge reached the volume's allowance `T`; the attempt
    /// claimed no slot or extent, and an incumbent stays current.
    RetiredPressure,
    /// The decision was made for other lengths or under another record format, the key's fingerprint routes to a shard other than the record's or to no enabled shard, or the record no longer carries this attempt's unrevoked serial and key.
    Superseded,
    /// The shard's fill table, chain, free stack or sequence is malformed; the gate is poisoned.
    Corrupt,
    /// The key's chain has no place for the object, `N` is reached or the shard is terminal; the attempt holds no place and no credit, and its extent was disposed of.
    IndexFull,
    /// Fewer than two lease credits are free, so the publisher's lease or the terminal read right has none; the attempt holds no place and no credit, and its extent was disposed of.
    LeaseLimit,
}

impl From<ReserveError> for FillReserveError {
    fn from(error: ReserveError) -> Self {
        match error {
            ReserveError::TornDown => Self::TornDown,
            ReserveError::Layout(error) => Self::Layout(error),
            ReserveError::Closed => Self::Closed,
            ReserveError::BudgetExhausted => Self::BudgetExhausted,
            ReserveError::Gate(_) => Self::Contended,
            ReserveError::ObjectSlotsFull => Self::ObjectSlotsFull,
            ReserveError::PayloadFull => Self::PayloadFull,
            ReserveError::CleanReserve => Self::CleanReserve,
            ReserveError::RetiredPressure => Self::RetiredPressure,
            ReserveError::Bootstrapping => Self::Bootstrapping,
            ReserveError::Withdrawn => Self::Withdrawn,
        }
    }
}

impl From<BudgetExhausted> for FillReserveError {
    fn from(_: BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

impl From<Refusal> for FillReserveError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::BudgetExhausted => Self::BudgetExhausted,
            Refusal::Contended | Refusal::Poisoned => Self::Contended,
            Refusal::Corrupt => Self::Corrupt,
        }
    }
}

/// Refusals of [`WritableFill::receive`]; each copies no byte of the input, and a submit the refusal names leaves its buffer staged and the set, the token map and the slot's count as they were.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveError {
    /// The input runs past the payload's remaining length.
    LengthExceeded,
    /// No receive-write buffer is free.
    PoolExhausted,
    /// The command table, its quarantine, the fills' write share or the
    /// device queue is full, or the pool gate an extent's locator is read
    /// under is busy.
    TableFull,
    /// Admission or the volume is closed; the owner keeps its extent and record for abort.
    Closed,
    /// The volume has yet to open: its bootstrap has persisted neither both RESET roots nor a warm
    /// load's allocation-readiness commit.
    Bootstrapping,
    /// The volume is lost.
    Lost,
    /// The table or the device refused the command for good while the volume stays live; the segment stays staged.
    Refused(super::device::Refusal),
    /// An invalidation revoked the attempt, so the record can never publish.
    Revoked,
    /// The volume belongs to another storage, whose slot table and device the fill's extent does not name.
    ForeignVolume,
    /// The segment's write command exceeds the caller's budget.
    Budget(BudgetShort),
}

impl ReceiveError {
    /// Classifies a refused write submit: a busy table or device queue is `TableFull`, closed admission `Closed`, a refusal on a lost volume `Lost`, and any other `Refused`.
    fn of_submit(refusal: super::device::Refusal, lost: bool) -> Self {
        use super::device::Refusal as Submit;
        match refusal {
            Submit::TableFull { .. }
            | Submit::Device(SubmitRefusal {
                reason: RefusalReason::QueueFull,
                ..
            }) => Self::TableFull,
            Submit::Closed => Self::Closed,
            _ if lost => Self::Lost,
            refusal => Self::Refused(refusal),
        }
    }
}

/// The exclusive owner of one attempt's object, one extent or a sequence, while its records are written.
#[must_use = "a dropped fill disposes of its extent and departs its record; call abort() to end it deliberately"]
pub struct WritableFill<'s, 'a, P: Platform> {
    storage: &'s Storage<P>,
    record: AttemptRecord<'s>,
    /// Disposed of in place before the record departs, so the departure never runs while the extent's fate is unknown.
    reservation: ManuallyDrop<ExtentReservation<'s, P>>,
    lineage: u32,
    /// Payload bytes received so far, metadata then body.
    received: u64,
    /// The whole object's lengths, units and extent count.
    object: Object,
    /// The extent the fill writes now.
    extent: Extent,
    /// The write set and its staged buffers, from the first `receive` on.
    staging: Option<Staging<'a>>,
    /// Whether the last `receive` returned `Ok` after a submit it made was refused for the call's budget.
    budget_refused: bool,
    /// Whether the last `receive` returned `Ok` after a submit it made was refused, for the call's budget or by the volume.
    submit_refused: bool,
}

/// The object a fill writes: its whole `metadata_len` and `body_len` and
/// its geometry.
#[derive(Debug, Clone, Copy)]
struct Object {
    lengths: (u32, u32),
    geometry: ObjectGeometry,
}

/// The extent a fill writes: its index, the payload offset of its first
/// byte, and its record's layout.
#[derive(Debug, Clone, Copy)]
struct Extent {
    index: u32,
    offset: u64,
    layout: RecordLayout,
}

impl Object {
    /// The object `layout`, a reservation's layout of its first extent,
    /// belongs to, under `record`.
    fn of(layout: &AllocationLayout, record: &super::record::ValidRecordConfig) -> Self {
        let lengths = (layout.record().metadata_len(), layout.record().body_len());
        let len = u64::from(lengths.0) + u64::from(lengths.1);
        let geometry = ObjectGeometry::new(len, record)
            .expect("a reservation's lengths lie within the object limit");
        Self { lengths, geometry }
    }

    fn payload_len(&self) -> u64 {
        u64::from(self.lengths.0) + u64::from(self.lengths.1)
    }

    /// Units of every extent of the object.
    fn units(&self) -> u32 {
        self.geometry.total_units() as u32
    }

    /// Extent `index`: the payload it covers and its record's layout.
    fn extent(&self, record: &super::record::ValidRecordConfig, index: u32) -> Extent {
        let coverage = self.geometry.coverage(index);
        Extent {
            index,
            offset: coverage.start,
            layout: record.extent_layout(
                self.lengths.0,
                self.lengths.1,
                coverage.end - coverage.start,
            ),
        }
    }
}

/// A fill's write set, the buffers it stages and the chunk checksum in progress.
struct Staging<'a> {
    set: WriteSet,
    /// The extent the staged segments belong to.
    locator: ExtentLocator,
    /// Segment 0: the header's bytes and the first payload bytes, submitted last.
    first: First<'a>,
    /// The later segment being filled, or full and waiting for its submit.
    current: Option<Buffer<'a>>,
    /// The segment holding the last payload byte received; 0 before the first.
    /// A staged `current` buffer is this segment's.
    index: u64,
    /// The chunk whose checksum `running` folds.
    chunk: u32,
    /// The payload byte where `chunk` ends; unchanged once every chunk is folded.
    chunk_end: u64,
    running: RunningCrc,
}

impl<'a> Staging<'a> {
    /// The staging of an extent whose record has `layout`, at `locator`,
    /// with `first` for its header segment, under the write set `set`.
    fn new(
        set: WriteSet,
        locator: ExtentLocator,
        first: Buffer<'a>,
        layout: &RecordLayout,
        crc: Crc32c,
    ) -> Self {
        Self {
            set,
            locator,
            first: First::Filling(first),
            current: None,
            index: 0,
            chunk: 0,
            chunk_end: layout.chunk(0).map_or(0, |range| range.end),
            running: crc.start(),
        }
    }
}

/// Segment 0's buffer, which holds the record's header.
enum First<'a> {
    /// The payload is still arriving.
    Filling(Buffer<'a>),
    /// The header is encoded and submission awaits acceptance; retries
    /// submit the buffer unchanged.
    Sealed(Buffer<'a>),
    Submitted,
}

impl<P: Platform> std::fmt::Debug for WritableFill<'_, '_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WritableFill")
            .field("shard", &self.record.shard)
            .field("serial", &self.record.serial.get())
            .field("id", &self.reservation.id())
            .field("received", &self.received)
            .finish_non_exhaustive()
    }
}

impl<'s, P: Platform> FillAttempt<'s, P> {
    /// Reserves exclusive write access to every extent of an object of `metadata_len` followed by `body_len` bytes, subject to `admitted`, with at most `tries` shard-gate attempts.
    /// `budget` is charged one coordination attempt per gate try, the claim's update, slot takes and extent search, the hash pass of the key's route, and the record visit, key comparison, credit attempt and chain walk of the revalidation; the module documentation gives the order.
    /// An object of several extents claims through [`Storage::promise`] and [`Builder::place`](super::Builder::place) instead of the one-extent claim: the budget is charged the promise's try, update, slot take and block allocation, then one [`place_steps`](super::Builder::place_steps) per extent placed, all within this one call.
    ///
    /// # Errors
    ///
    /// [`FillReserveError`]; every variant consumes the attempt and departs its record, and an extent claimed before the refusal is returned or parked for service before the departure.
    // Forced inline, as `claim` and `revalidate` are: out of line, the allocation and then this owner return through memory, written as words and read back by wider moves that wait for the store buffer to drain; inlined, the owner stays in registers.
    #[inline(always)]
    pub fn reserve_storage<'a>(
        self,
        admitted: Admitted,
        metadata_len: Option<usize>,
        body_len: Option<usize>,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<WritableFill<'s, 'a, P>, FillReserveError> {
        if admitted.extents() > 1 {
            return self.reserve_sequence(admitted, metadata_len, body_len, tries, budget);
        }
        let storage = self.storage();
        let fingerprint = self.fingerprint();
        // From here on the record is plain data with no destructor, so a claim that unwinds under the pool gate leaves it occupied, a refused claim departs it through the explicit step below, and a later refusal departs it only after the extent's disposal, whose panic leaves it occupied.
        let record = self.into_record();
        let claimed = claim(
            storage,
            admitted,
            fingerprint,
            metadata_len,
            body_len,
            budget,
        );
        // Held without a destructor, like the record, so no unwinding path drops it by address; a refusal disposes of it explicitly, and a panic in the revalidation leaves the extent charged and the record occupied.
        let reservation = match claimed {
            Ok(reservation) => ManuallyDrop::new(reservation),
            Err(error) => {
                record.depart();
                return Err(error);
            }
        };
        revalidated(storage, record, reservation, tries, budget)
    }

    /// [`reserve_storage`](Self::reserve_storage) for an object of several
    /// extents: the whole placement within this one budget, then the shard
    /// hold. A budget that funds the promise and some placements but not
    /// the rest refuses `BudgetExhausted` with every placed extent returned;
    /// [`promise_storage`](Self::promise_storage) spreads the placement over
    /// calls instead.
    #[cold]
    #[inline(never)]
    fn reserve_sequence<'a>(
        self,
        admitted: Admitted,
        metadata_len: Option<usize>,
        body_len: Option<usize>,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<WritableFill<'s, 'a, P>, FillReserveError> {
        let mut placing = self.promise_storage(admitted, metadata_len, body_len, budget)?;
        loop {
            match placing.place(budget) {
                Ok(true) => return placing.reserve_storage(tries, budget),
                Ok(false) => {}
                Err(error) => {
                    placing.abort();
                    return Err(error);
                }
            }
        }
    }

    /// Promises the whole charge of an object of several extents, `metadata_len` followed by `body_len` bytes, subject to `admitted`, as a [`PlacingFill`] that places the extents over later calls.
    /// `budget` is charged the geometry and decision checks, then the promise's gate try, update, slot take and block allocation.
    ///
    /// # Errors
    ///
    /// [`FillReserveError`] in the order `claim`'s checks run: `TornDown`, `Layout`, `Superseded`, `Closed`, `Bootstrapping` while the attached volume's readiness is `Loading`, `Loaded` or `Replaying`, or `Detached` while its attach gate runs, `Closed` while it is `Withheld` or `Closed`, `Layout(MultipleExtents)` on a volume without a sequence arena, then the promise's refusals, `PayloadFull` for a sequence arena without a free block. Every variant consumes the attempt and departs its record.
    ///
    /// # Panics
    ///
    /// If `admitted` admits one extent, which [`reserve_storage`](Self::reserve_storage) claims.
    pub fn promise_storage(
        self,
        admitted: Admitted,
        metadata_len: Option<usize>,
        body_len: Option<usize>,
        budget: &mut WorkBudget,
    ) -> Result<PlacingFill<'s, P>, FillReserveError> {
        assert!(
            admitted.extents() > 1,
            "an object of one extent is reserved, not promised"
        );
        let storage = self.storage();
        let ((live, _), geometry, lengths) =
            admitted_geometry(storage, admitted, metadata_len, body_len)?;
        // A volume without a sequence arena holds objects of one extent.
        if !live.image.tables.has_arena() {
            return Err(FillReserveError::Layout(LayoutError::MultipleExtents {
                extents: geometry.extents(),
            }));
        }
        // Held without its destructor across the promise, so a promise that unwinds under the pool gate leaves the record occupied, as an unwound claim does; both outcomes take the attempt back.
        let attempt = ManuallyDrop::new(self);
        match storage.promise(Some(lengths.0), Some(lengths.1), budget) {
            Ok(builder) => Ok(PlacingFill {
                builder: ManuallyDrop::new(builder),
                attempt: Some(ManuallyDrop::into_inner(attempt)),
                lengths,
            }),
            Err(error) => {
                drop(ManuallyDrop::into_inner(attempt));
                Err(promise_refusal(error))
            }
        }
    }
}

/// A placement's attempt lent across a pool gate hold. [`PlacingFill::place`] and [`PlacingFill::retry`] forget the guard on return; an unwind drops it, which turns the attempt into its record, plain data with no destructor, so the record stays occupied and undeparted.
struct KeepOnUnwind<'r, 's, P: Platform>(&'r mut Option<FillAttempt<'s, P>>);

impl<P: Platform> Drop for KeepOnUnwind<'_, '_, P> {
    fn drop(&mut self) {
        if let Some(attempt) = self.0.take() {
            attempt.into_record();
        }
    }
}

/// Takes the shard hold for `record` and builds the owner of `reservation`, or disposes of the reservation and departs the record.
// Forced inline, as `reserve_storage` is, so the one-extent owner returns in registers.
#[inline(always)]
fn revalidated<'s, 'a, P: Platform>(
    storage: &'s Storage<P>,
    record: AttemptRecord<'s>,
    reservation: ManuallyDrop<ExtentReservation<'s, P>>,
    tries: usize,
    budget: &mut WorkBudget,
) -> Result<WritableFill<'s, 'a, P>, FillReserveError> {
    #[cfg(test)]
    if let Ok(Some(interpose)) = INTERPOSE_BEFORE_REVALIDATION.try_with(|hook| hook.take()) {
        interpose(storage.closed());
    }
    let layout = reservation.layout();
    let lengths = (layout.record().metadata_len(), layout.record().body_len());
    match revalidate(storage, &record, reservation.id(), lengths, tries, budget) {
        // The owner is built once, in the caller's slot, only for a reservation that succeeds.
        Ok(()) => {
            let object = Object::of(&reservation.layout(), &storage.record);
            let extent = object.extent(&storage.record, 0);
            Ok(WritableFill {
                lineage: reservation.lineage,
                storage,
                record,
                reservation,
                received: 0,
                object,
                extent,
                staging: None,
                budget_refused: false,
                submit_refused: false,
            })
        }
        Err(error) => {
            // Disposal precedes departure, as at the owner's end; a disposal whose park found the slot word malformed or naming another incarnation leaves the record occupied.
            if ManuallyDrop::into_inner(reservation).dispose() {
                record.depart();
            }
            Err(error)
        }
    }
}

/// An attempt whose object of several extents is promised and being placed: the escrow holds the unplaced charge and the sequence's block holds the placed extents between calls, until every extent is placed and [`reserve_storage`](Self::reserve_storage) takes the shard hold.
///
/// Dropping or aborting a placement refunds the unplaced charge, parks the slot for service, and departs the attempt's record; service returns the placed extents and the block. A placement that panics under the pool gate leaves the record occupied and undeparted, as a panicking disposal does, so finalization blocks on it. A park that finds the slot word malformed or naming another incarnation leaves the slot to no one, so the record stays occupied and finalization blocks on it too. For a placement with zero placed extents, [`end`](Self::end) returns the block and slot in one gate hold when the gate is free and parks the slot when the gate is busy.
#[must_use = "a dropped placement returns its extents and departs its record; call abort() or end() to end it deliberately"]
pub struct PlacingFill<'s, P: Platform> {
    // Taken once, by the drop or by a consuming method, so disposal precedes departure, as at the owner's end, and the departure runs only after a disposal that returned or parked the slot.
    builder: ManuallyDrop<Builder<'s, P>>,
    /// `None` once a placement unwound: the record then stays occupied and undeparted.
    attempt: Option<FillAttempt<'s, P>>,
    /// The object's metadata and body lengths, which lay out the first extent's record.
    lengths: (usize, usize),
}

impl<'s, P: Platform> PlacingFill<'s, P> {
    /// Whether every extent is placed.
    pub fn is_complete(&self) -> bool {
        self.builder.is_complete()
    }

    /// Extents placed so far, of [`extents`](Self::extents).
    pub fn placed(&self) -> u32 {
        self.builder.placed()
    }

    /// A true result means the placement is waiting for a free run.
    pub fn waiting(&self) -> bool {
        self.builder.waiting()
    }

    /// A waiting placement's [`retry`](Self::retry) passes this value to [`Storage::proves_no_run`].
    pub(crate) fn wait_units(&self) -> u64 {
        self.builder.wait_units()
    }

    /// Extents of the object.
    pub fn extents(&self) -> u32 {
        self.builder.extents()
    }

    /// Work steps that fund one extent of a [`place`](Self::place) call.
    pub fn place_steps(&self) -> usize {
        self.builder.place_steps()
    }

    /// Places the extents `budget` funds, one [`place_steps`](Self::place_steps) each, under one pool gate try, and returns whether every extent is placed; a complete placement returns `Ok(true)` without a gate try.
    ///
    /// # Errors
    ///
    /// [`Builder::place`]'s refusals as [`FillReserveError`]: `TornDown`, `BudgetExhausted` for a budget below `place_steps`, `Contended` for a busy gate, and `PayloadFull` when the first pass finds no free run. Every refusal leaves the placement as it was, apart from `PayloadFull`, which sets [`waiting`](Self::waiting), so the caller retries with another budget, once extents return, or aborts.
    pub fn place(&mut self, budget: &mut WorkBudget) -> Result<bool, FillReserveError> {
        if self.builder.is_complete() {
            return Ok(true);
        }
        let kept = KeepOnUnwind(&mut self.attempt);
        let placed = self.builder.place(budget).map_err(promise_refusal);
        std::mem::forget(kept);
        debug_assert!(
            !matches!(placed, Err(FillReserveError::PayloadFull)) || self.builder.waiting(),
            "a placement's no-run refusal waits"
        );
        placed
    }

    pub fn retry(&mut self, budget: &mut WorkBudget) -> Result<bool, FillReserveError> {
        if self.builder.is_complete() {
            return Ok(true);
        }
        let kept = KeepOnUnwind(&mut self.attempt);
        let placed = self.builder.retry(budget).map_err(promise_refusal);
        std::mem::forget(kept);
        debug_assert!(
            !matches!(placed, Err(FillReserveError::PayloadFull)) || self.builder.waiting(),
            "a placement's no-run refusal waits"
        );
        placed
    }

    /// Takes the shard hold for the complete placement and returns the fill of every placed extent, or disposes of the placement and departs the record. `budget` and `tries` fund the revalidation as in [`FillAttempt::reserve_storage`].
    ///
    /// # Errors
    ///
    /// The revalidation's refusals of [`FillReserveError`]; every variant consumes the placement and the attempt.
    ///
    /// # Panics
    ///
    /// If an extent is unplaced.
    pub fn reserve_storage<'a>(
        self,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<WritableFill<'s, 'a, P>, FillReserveError> {
        assert!(
            self.is_complete(),
            "only a complete placement takes the shard hold"
        );
        let lengths = self.lengths;
        let (builder, attempt) = self.into_parts();
        // Only a caller that caught a placement's unwind holds a placement without its attempt; the panic poisoned the pool gate.
        let Some(attempt) = attempt else {
            return Err(FillReserveError::Contended);
        };
        let storage = attempt.storage();
        let first = storage.record.extent_layout(
            lengths.0 as u32,
            lengths.1 as u32,
            super::geometry::EXTENT_PAYLOAD,
        );
        let reservation =
            ManuallyDrop::new(builder.into_reservation(AllocationLayout::of_extent(first)));
        let record = attempt.into_record();
        revalidated(storage, record, reservation, tries, budget)
    }

    /// Ends the placement: refunds the unplaced charge, parks the slot so service returns the placed extents and the block, and departs the attempt's record.
    pub fn abort(self) {
        drop(self);
    }

    /// Ends the placement and departs the attempt's record. With no extent placed, [`Builder::cancel`] returns the block and the slot in its one gate hold when the gate is free; with extents placed, the placement ends as [`abort`](Self::abort) does, and budgeted service returns them.
    /// The cancel precedes the departure, so a cancel that panics under the gate, which only corruption of a slot word produces, leaves the record occupied.
    pub fn end(self) {
        if self.builder.placed() > 0 {
            return self.abort();
        }
        let (builder, attempt) = self.into_parts();
        // The record is plain data with no destructor, so a panic in the cancel leaves it occupied, as a fill's panicking disposal does.
        let record = attempt.map(FillAttempt::into_record);
        // A placement that unwound holds no attempt, and its record stays occupied; so does one whose park found the slot word malformed or naming another incarnation.
        if builder.cancel()
            && let Some(record) = record
        {
            record.depart();
        }
    }

    /// The builder and the attempt, without running the placement's drop.
    fn into_parts(self) -> (Builder<'s, P>, Option<FillAttempt<'s, P>>) {
        let mut this = ManuallyDrop::new(self);
        let attempt = this.attempt.take();
        // SAFETY: `this` is never dropped, so the builder is taken exactly once, here.
        (unsafe { ManuallyDrop::take(&mut this.builder) }, attempt)
    }
}

impl<P: Platform> Drop for PlacingFill<'_, P> {
    /// Disposal precedes departure: the builder's end refunds the unplaced charge and parks the slot, and the record departs only when the park took the slot. A malformed slot word, or one naming another incarnation, refuses the park, so the record stays occupied; a panic in the end, or a placement that unwound and holds no attempt, leaves it occupied too.
    fn drop(&mut self) {
        // SAFETY: the builder is taken exactly once, here, and `self` is not used afterwards.
        let builder = unsafe { ManuallyDrop::take(&mut self.builder) };
        let record = self.attempt.take().map(FillAttempt::into_record);
        if builder.abandon()
            && let Some(record) = record
        {
            record.depart();
        }
    }
}

/// A promise's or placement's refusal as the fill reservation's.
fn promise_refusal(error: PromiseError) -> FillReserveError {
    match error {
        PromiseError::Reserve(error) => FillReserveError::from(error),
        PromiseError::Blocks => FillReserveError::PayloadFull,
        PromiseError::OneExtent => unreachable!("the geometry has several extents"),
    }
}

impl<'s, 'a, P: Platform> WritableFill<'s, 'a, P> {
    pub fn key(&self) -> &Key {
        &self.record.key
    }

    pub fn shard(&self) -> ShardIndex {
        self.record.shard
    }

    /// The cache version the fill writes, the version of its source read.
    pub fn version(&self) -> CacheVersion {
        self.record.version
    }

    /// The checked serial that identifies this attempt with its shard; never the record position.
    pub fn serial(&self) -> u64 {
        self.record.serial.get()
    }

    pub fn id(&self) -> AllocationId {
        self.reservation.id()
    }

    /// The checked layout the extent was claimed for: for an object of
    /// several extents, its first extent's record.
    pub fn layout(&self) -> AllocationLayout {
        self.reservation.layout()
    }

    /// Payload bytes received so far, metadata then body.
    pub fn received(&self) -> u64 {
        self.received
    }

    /// Whether the volume serves this fill's lineage and its token admits fills at the owner's latest deadline sample: the precheck of a receive and of a publication, whose write submits and install are admitted again on their own readings.
    pub(super) fn authority_current<D: Disk>(&self, volume: &Volume<'s, 'a, P, D>) -> bool {
        volume
            .serving_token()
            .is_some_and(|token| token.lineage == self.lineage)
            && volume
                .admit_authority_at_sample(
                    crate::failover::serving::Operation::Fill,
                    volume.serving_token(),
                )
                .is_ok()
    }

    /// Progress on this volume's write set, or only the record's length before
    /// staging or on another volume. Authority refusal at the owner's latest deadline sample also sets `failed`.
    pub fn progress<D: Disk>(&self, volume: &Volume<'s, 'a, P, D>) -> WriteProgress {
        self.staging
            .as_ref()
            .filter(|_| volume.serves(self.storage))
            .and_then(|staging| volume.write_progress(staging.set))
            .unwrap_or(WriteProgress {
                len_units: self.object.units(),
                ..WriteProgress::default()
            })
    }

    /// Write commands of this fill awaiting their terminals on `volume`; zero
    /// before staging or on another volume.
    pub(crate) fn outstanding_commands<D: Disk>(&self, volume: &Volume<'s, 'a, P, D>) -> u32 {
        self.staging
            .as_ref()
            .filter(|_| volume.serves(self.storage))
            .and_then(|staging| volume.write_outstanding(staging.set))
            .unwrap_or(0)
    }

    /// Whether the last [`receive`](Self::receive) or [`receive_verified`](Self::receive_verified) returned `Ok` after a submit it made was refused for its budget, so a segment waits staged for a call with budget.
    pub fn budget_refused(&self) -> bool {
        self.budget_refused
    }

    /// Whether the last [`receive`](Self::receive) or [`receive_verified`](Self::receive_verified) returned `Ok` after a submit it made was refused, for its budget or by the volume, so a segment waits staged for the next call, which retries it with or without new bytes.
    pub fn submit_refused(&self) -> bool {
        self.submit_refused
    }

    /// Whether every unit of the record reached a successful terminal on `volume` and none failed: the precondition [`publish`](Self::publish) checks.
    /// A fill that took its whole payload stays unready while a refused segment is staged; `receive(volume, &[], budget)` submits it.
    ///
    /// Readiness is device acknowledgment: every write of the record completed under the [`Disk`] driver's contract, which [`SpdkDisk`](super::device::SpdkDisk) meets with direct NVMe writes at I/O flags zero.
    /// Submitting a staged segment issues its write; the recovery owner decides whether completion establishes persistence.
    /// [`completion_is_durable`](super::device::completion_is_durable) decides from Identify evidence only whether a device is eligible for a profile in which completion may stand for persistence.
    pub fn is_ready<D: Disk>(&self, volume: &Volume<'s, 'a, P, D>) -> bool {
        self.progress(volume).is_ready()
    }

    /// Copies the next `input` bytes of the payload into staged buffers and submits every segment that became full, each extent's header segment last, once that extent's payload arrived; returns the bytes taken.
    ///
    /// A buffer the volume refused earlier is submitted first. Copying stops at a segment whose buffer cannot be acquired or whose submit is refused, and at an extent boundary whose next locator waits for a busy pool gate; a staged submit stays for the next call, so a call with an empty input retries it. Fewer bytes than `input` holds are taken only at such a stop.
    /// A call that takes the last payload byte returns `Ok` with every byte it took even when a submit it made was refused: once [`received`](Self::received) covers the payload, [`progress`](Self::progress) with `submitted_units` below `len_units` means a segment is still staged, and `receive(volume, &[], budget)` retries it, the header's segment last.
    ///
    /// # Errors
    ///
    /// In this order, with no byte copied: `ForeignVolume`, `Lost`, `Closed`, `Bootstrapping`, `Revoked`, `LengthExceeded` when `input` runs past the payload, `TableFull` while the first extent's locator waits for the pool gate, `PoolExhausted` for the first buffer or the first call's write set, any refusal of the staged submit this call retried first, `Budget` included, then `TableFull` or `PoolExhausted` for the next extent's locator or first buffer, or `PoolExhausted` for a later buffer, before any byte was taken.
    ///
    /// # Panics
    ///
    /// If a submit that installs the write set's right finds the slot's count nonzero or its word naming another incarnation, which only corruption of the word produces.
    pub fn receive<D: Disk>(
        &mut self,
        volume: &mut Volume<'s, 'a, P, D>,
        input: &[u8],
        budget: &mut WorkBudget,
    ) -> Result<usize, ReceiveError> {
        self.receive_piece(volume, input, None, budget)
    }

    /// [`receive`](Self::receive) for an `input` whose crc32c the caller verified to be `checksum`: for an input of at least `DERIVE_MIN` bytes the chunk checksums the record stores follow from `checksum` where that takes less folding than the bytes do, and they are the checksums `receive` stores for the same bytes.
    ///
    /// `checksum` must be `input`'s crc32c. A build without debug assertions takes it unchecked: the fill derives the register of each part, a run of the input within one chunk, that is at least as long as the input after it, and under another value the chunk that holds the first such part stores a checksum its bytes do not have, so a read of the record refuses that chunk. A call that derives no part stores the checksums `receive` stores whatever `checksum` is: one with an input shorter than `DERIVE_MIN`, and one that stops before it reaches such a part.
    ///
    /// # Errors
    ///
    /// As [`receive`](Self::receive).
    ///
    /// # Panics
    ///
    /// As [`receive`](Self::receive). In a build with debug assertions, also if the fill derives a part's register from a `checksum` that is not `input`'s crc32c.
    pub fn receive_verified<D: Disk>(
        &mut self,
        volume: &mut Volume<'s, 'a, P, D>,
        input: &[u8],
        checksum: u32,
        budget: &mut WorkBudget,
    ) -> Result<usize, ReceiveError> {
        self.receive_piece(volume, input, Some(checksum), budget)
    }

    /// [`receive`](Self::receive), with the crc32c of `input` when the caller verified one.
    fn receive_piece<D: Disk>(
        &mut self,
        volume: &mut Volume<'s, 'a, P, D>,
        input: &[u8],
        checksum: Option<u32>,
        budget: &mut WorkBudget,
    ) -> Result<usize, ReceiveError> {
        // The register, folded from zero, of the input from `taken` on, which `fold_derived` keeps while the caller's checksum gives it. Deriving it first leaves the checks below no checksum to hold in a register.
        let mut unfolded = checksum
            .filter(|_| input.len() >= DERIVE_MIN)
            .map(|checksum| {
                let crc = volume.crc();
                crc.from_zero(checksum, &crc.zero_run(input.len() as u64))
            });
        self.budget_refused = false;
        self.submit_refused = false;
        if !volume.serves(self.storage) {
            return Err(ReceiveError::ForeignVolume);
        }
        if volume.is_lost() {
            return Err(ReceiveError::Lost);
        }
        // `Relaxed` suffices here: the cutoff never clears, and a receive admitted by a stale read writes only to an extent this owner holds.
        if volume.is_closed() || self.storage.closed().load(Ordering::Relaxed) {
            return Err(ReceiveError::Closed);
        }
        if !volume.admits_payload_writes() {
            return Err(ReceiveError::Bootstrapping);
        }
        // A pre-attach reservation can enter only the first serving lineage,
        // before any bytes were staged; a later lineage requires a new fill.
        if self.lineage == 0
            && volume
                .serving_token()
                .is_some_and(|token| token.lineage == 1)
            && self.staging.is_none()
            && self.received == 0
        {
            self.lineage = volume.serving_token().map_or(0, |token| token.lineage);
        }
        if !self.authority_current(volume) {
            return Err(ReceiveError::Closed);
        }
        if fill::revoked(self.record.state.load(Ordering::Relaxed)) {
            return Err(ReceiveError::Revoked);
        }
        if self.received + input.len() as u64 > self.object.payload_len() {
            return Err(ReceiveError::LengthExceeded);
        }
        if self.staging.is_none() {
            let locator = self.locate(0).ok_or(ReceiveError::TableFull)?;
            let first = volume
                .acquire_write_buffer()
                .map_err(|_| ReceiveError::PoolExhausted)?;
            let id = self.reservation.id();
            let units = self.object.units();
            let Some(set) =
                volume.begin_fill(id, locator, units, self.record.state, self.record.serial)
            else {
                return Err(ReceiveError::PoolExhausted);
            };
            self.staging = Some(Staging::new(
                set,
                locator,
                first,
                &self.extent.layout,
                volume.crc(),
            ));
        }
        let segment = volume.segment_len() as u64;
        // A later segment submits once full, so a staged buffer is retried only when its segment ended at `at`; the first segment submits once the extent's payload is complete.
        {
            let (extent, staging) = (self.extent, self.staging.as_mut().expect("staged above"));
            let received = self.received - extent.offset;
            let at = extent.layout.header_bytes() as u64 + received;
            if (staging.current.is_some()
                && at == segment_end(&extent.layout, segment, staging.index))
                || received == extent.layout.payload_len()
            {
                flush(
                    staging,
                    &mut self.reservation,
                    &self.record,
                    volume,
                    &extent,
                    received,
                    budget,
                )?;
            }
        }
        let mut taken = 0;
        while taken < input.len() {
            // An extent whose payload arrived and whose header segment was accepted passes the stream to the next.
            if self.received == self.extent.offset + self.extent.layout.payload_len()
                && let Err(refusal) = self.advance(volume)
            {
                if taken == 0 {
                    return Err(refusal);
                }
                break;
            }
            let (extent, staging) = (self.extent, self.staging.as_mut().expect("staged above"));
            let layout = &extent.layout;
            let received = self.received - extent.offset;
            let at = layout.header_bytes() as u64 + received;
            let mut index = staging.index;
            let mut end = segment_end(layout, segment, index);
            if at == end {
                index += 1;
                end = segment_end(layout, segment, index);
            }
            if index > 0 && staging.current.is_none() {
                match volume.acquire_write_buffer() {
                    Ok(buffer) => staging.current = Some(buffer),
                    Err(_) if taken == 0 => return Err(ReceiveError::PoolExhausted),
                    Err(_) => break,
                }
            }
            staging.index = index;
            let count = ((end - at) as usize).min(input.len() - taken);
            let offset = (at - index * segment) as usize;
            match &mut unfolded {
                None => fold(
                    staging,
                    layout,
                    received,
                    &input[taken..taken + count],
                    (index, offset),
                    volume.crc(),
                    |running, part, to| running.update_and_copy(part, to),
                ),
                Some(register) => fold_derived(
                    staging,
                    layout,
                    received,
                    (input, taken..taken + count),
                    register,
                    (index, offset),
                    volume.crc(),
                ),
            }
            self.received += count as u64;
            taken += count;
            // A refusal leaves its segment staged; the next call retries it before taking a byte.
            if at + count as u64 == end
                && let Err(refusal) = flush(
                    staging,
                    &mut self.reservation,
                    &self.record,
                    volume,
                    &extent,
                    received + count as u64,
                    budget,
                )
            {
                self.budget_refused = matches!(refusal, ReceiveError::Budget(_));
                self.submit_refused = true;
                break;
            }
        }
        Ok(taken)
    }

    /// The locator of extent `index`: the reservation's own for an object of
    /// one extent, else the one its sequence's block names, read under a
    /// quiet pool gate try; `None` while the gate is busy or poisoned or the
    /// storage is past its live phase.
    fn locate(&self, index: u32) -> Option<ExtentLocator> {
        if self.object.geometry.extents() == 1 {
            return Some(self.reservation.locator());
        }
        self.storage
            .live_pool()?
            .sequence_extent(self.reservation.id(), index)
    }

    /// Moves the stream to the next extent once the current one's header
    /// segment was accepted: its locator, a first buffer for its header and
    /// its first payload bytes, and the write set's next extent.
    ///
    /// # Errors
    ///
    /// `TableFull` while the header segment waits for its submit or the pool
    /// gate is busy or poisoned, or `PoolExhausted` with no buffer free; the
    /// stream stays at the current extent.
    fn advance<D: Disk>(&mut self, volume: &mut Volume<'s, 'a, P, D>) -> Result<(), ReceiveError> {
        let Some(staging) = self.staging.as_mut() else {
            unreachable!("a receive stages before it takes a byte")
        };
        if !matches!(staging.first, First::Submitted) {
            return Err(ReceiveError::TableFull);
        }
        let index = self.extent.index + 1;
        let next = self.object.extent(&self.storage.record, index);
        let locator = self.locate(index).ok_or(ReceiveError::TableFull)?;
        let first = volume
            .acquire_write_buffer()
            .map_err(|_| ReceiveError::PoolExhausted)?;
        let Some(staging) = self.staging.as_mut() else {
            unreachable!("a receive stages before it takes a byte")
        };
        volume.next_extent(staging.set, locator);
        *staging = Staging::new(staging.set, locator, first, &next.layout, volume.crc());
        self.extent = next;
        Ok(())
    }

    // The disposal is inlined here rather than reached through the drop glue, which is too large to inline once it holds the rollback and the abandonment.
    #[inline(always)]
    pub fn abort(self) {
        let mut owner = ManuallyDrop::new(self);
        owner.end();
    }

    /// Ends the fill as [`abort`](Self::abort) does, after recording `failure` as its terminal, so every follower joined to the fill reports `failure`.
    /// An abort or a drop records none, and neither does a fill an invalidation revoked, whose revocation the followers report as the key missing.
    pub fn fail(self, failure: FillFailure) {
        // The owner reads its own word: only the gate holder's revocation
        // and the owner's departure write it, and a revocation landing after
        // this read still leaves one terminal for every follower to read at
        // the departure.
        if !fill::revoked(self.record.state.load(Ordering::Relaxed)) {
            self.record.row.record_failure(failure);
        }
        self.abort();
    }

    pub(super) fn storage(&self) -> &'s Storage<P> {
        self.storage
    }

    /// The attempt's record, whose row the owner writes its terminal to.
    pub(super) fn record(&self) -> &AttemptRecord<'s> {
        &self.record
    }

    /// Ends the write set on `volume` and transfers the reservation, the undeparted record and the fill's two `Shared` credits without running `Drop`; the receiver owes the disposal and the departure in that order, and each credit's return or its transfer to a lease or the row. Staged buffers return to their pool.
    pub(super) fn into_parts<D: Disk>(
        self,
        volume: &mut Volume<'s, 'a, P, D>,
    ) -> (ExtentReservation<'s, P>, AttemptRecord<'s>) {
        let mut this = ManuallyDrop::new(self);
        if let Some(staging) = this.staging.take() {
            volume.end_fill(staging.set);
        }
        // SAFETY: `this` is never dropped, so the reservation is taken exactly once.
        let reservation = unsafe { ManuallyDrop::take(&mut this.reservation) };
        (reservation, this.record)
    }
}

fn segment_end(layout: &RecordLayout, segment: u64, index: u64) -> u64 {
    ((index + 1) * segment).min(layout.record_len())
}

/// Submits segment `index` from `buffer` as its write command, after zeroing the buffer from the record's last byte to the extent's end when the segment is the last one; once the submit is accepted the reservation counts as written.
fn submit_segment<'s, 'a, P: Platform, D: Disk>(
    (set, locator): (WriteSet, ExtentLocator),
    reservation: &mut ExtentReservation<'s, P>,
    volume: &mut Volume<'s, 'a, P, D>,
    layout: &RecordLayout,
    mut buffer: Buffer<'a>,
    index: u64,
    budget: &mut WorkBudget,
) -> Result<(), (Buffer<'a>, ReceiveError)> {
    let unit = IO_UNIT as u64;
    let start = index * volume.segment_len() as u64;
    let end = (start + volume.segment_len() as u64).min(u64::from(locator.len_units()) * unit);
    if let Err(short) = budget.debit_command(WorkKind::Update, 0, (end - start) as usize) {
        return Err((buffer, ReceiveError::Budget(short)));
    }
    if end >= layout.record_len() {
        buffer.bytes_mut()[(layout.record_len() - start) as usize..(end - start) as usize].fill(0);
    }
    if let Err((buffer, refusal)) = volume.write_at(set, buffer, (start / unit) as u32) {
        return Err((buffer, ReceiveError::of_submit(refusal, volume.is_lost())));
    }
    reservation.mark_written();
    Ok(())
}

/// `fold` copies `piece` into segment `index`'s buffer at byte `offset`, updates chunk checksums, and writes each completed chunk's crc32c to the first buffer's chunk table. `received` is the payload byte offset where `piece` begins.
///
/// `part` copies each run of `piece` that lies in one chunk to its place in the buffer and brings the chunk's running checksum past it, as [`RunningCrc::update_and_copy`] does.
// `fold` and `flush` inline into `receive_piece` so the piece loop of an input that carries no checksum runs in one frame; for an input that carries one, `fold` inlines into `fold_derived`, which runs out of line.
#[inline(always)]
fn fold(
    staging: &mut Staging<'_>,
    layout: &RecordLayout,
    received: u64,
    piece: &[u8],
    (index, mut offset): (u64, usize),
    crc: Crc32c,
    mut part: impl FnMut(&mut RunningCrc, &[u8], &mut [u8]),
) {
    let Staging {
        first,
        current,
        chunk,
        chunk_end,
        running,
        ..
    } = staging;
    let First::Filling(first) = first else {
        unreachable!("the first segment is staged until the whole payload arrived");
    };
    let (target, mut table): (&mut [u8], Option<&mut Buffer<'_>>) = match current {
        Some(current) if index > 0 => (current.bytes_mut(), Some(first)),
        _ => (first.bytes_mut(), None),
    };
    let (mut at, mut rest) = (received, piece);
    while !rest.is_empty() {
        let take = ((*chunk_end - at) as usize).min(rest.len());
        part(running, &rest[..take], &mut target[offset..offset + take]);
        (at, offset, rest) = (at + take as u64, offset + take, &rest[take..]);
        if at == *chunk_end {
            let finished = std::mem::replace(running, crc.start()).finish();
            match &mut table {
                Some(first) => put_chunk_crc(first.bytes_mut(), *chunk, finished),
                None => put_chunk_crc(target, *chunk, finished),
            }
            *chunk += 1;
            if let Some(range) = layout.chunk(*chunk) {
                *chunk_end = range.end;
            }
        }
    }
}

/// [`fold`] for the bytes `piece` of an `input` whose crc32c the caller verified. `register` holds the register, folded from zero, of `input` from the piece's start to the input's end, and leaves holding that register from the piece's end.
///
/// The register of bytes folded from zero is linear in them: it is the register of a first part, carried past the bytes after that part, xor the register of those bytes. So a part that is at least as long as the input after it is copied without a fold, its register being the difference carried back, at the cost of a fold over the shorter rest; a shorter part is folded as it is copied, which yields the register of the rest. Either way the chunk's running checksum leaves a part as a fold of the part leaves it: past a part that was only copied, it resumes at the register that the chunk's earlier bytes and the part's derived register give.
// Out of line: the piece loop of an input that carries no checksum holds none of this code.
#[inline(never)]
fn fold_derived(
    staging: &mut Staging<'_>,
    layout: &RecordLayout,
    received: u64,
    (input, piece): (&[u8], Range<usize>),
    register: &mut u32,
    place: (u64, usize),
    crc: Crc32c,
) {
    let mut next = piece.start;
    fold(
        staging,
        layout,
        received,
        &input[piece],
        place,
        crc,
        |running, part, to| {
            next += part.len();
            let after = &input[next..];
            let run = crc.zero_run(part.len() as u64);
            // The register the chunk's bytes before `part` left, which `finish` inverts.
            let before = !running.finish();
            if part.len() >= after.len() {
                let rest = crc.fold_from_zero(after);
                let derived = carried_back(crc, *register ^ rest, after.len() as u64);
                debug_assert_eq!(
                    derived,
                    crc.fold_from_zero(part),
                    "a checksum of other bytes than the input's"
                );
                to.copy_from_slice(part);
                *running = RunningCrc::from_register(crc, crc.append(before, &run, derived));
                *register = rest;
            } else {
                running.update_and_copy(part, to);
                let folded = !running.finish() ^ run.advance(before);
                *register ^= carried(crc, folded, after.len() as u64);
            }
        },
    );
}

/// The shortest input whose verified checksum the fill uses. Deriving a part's register costs a few carries, each a zero run and a multiply, whatever the input's length, and saves a fold in proportion to the part's length, so a shorter input is folded whole.
const DERIVE_MIN: usize = 4096;

/// The multiplicative order of `x` modulo the crc32c polynomial, the product of `x + 1` and a primitive polynomial of degree 31: carrying a value past this many zero bytes leaves it as it was.
const X_ORDER: u64 = (1 << 31) - 1;

/// `value`, a checksum or a register folded from zero, carried past `len` zero bytes.
#[inline]
fn carried(crc: Crc32c, value: u32, len: u64) -> u32 {
    if value == 0 || len == 0 {
        value
    } else {
        crc.zero_run(len).advance(value)
    }
}

/// The value that [`carried`] past `len` zero bytes is `value`: carrying past the bytes that complete a multiple of [`X_ORDER`] undoes the carry past `len`.
#[inline]
fn carried_back(crc: Crc32c, value: u32, len: u64) -> u32 {
    carried(crc, value, (X_ORDER - len % X_ORDER) % X_ORDER)
}

/// Submits whatever `staging` holds ready: a full later segment, then, once all `received` payload bytes are in and no later segment waits, the first segment with its header encoded and its tail zeroed.
#[inline(always)]
fn flush<'s, 'a, P: Platform, D: Disk>(
    staging: &mut Staging<'a>,
    reservation: &mut ExtentReservation<'s, P>,
    record: &AttemptRecord<'s>,
    volume: &mut Volume<'s, 'a, P, D>,
    extent: &Extent,
    received: u64,
    budget: &mut WorkBudget,
) -> Result<(), ReceiveError> {
    let layout = &extent.layout;
    let segment = volume.segment_len() as u64;
    let at = layout.header_bytes() as u64 + received;
    let complete = received == layout.payload_len();
    if at == segment_end(layout, segment, staging.index)
        && let Some(current) = staging.current.take()
        && let Err((current, refusal)) = submit_segment(
            (staging.set, staging.locator),
            reservation,
            volume,
            layout,
            current,
            staging.index,
            budget,
        )
    {
        staging.current = Some(current);
        return Err(refusal);
    }
    if !complete {
        return Ok(());
    }
    let first = match std::mem::replace(&mut staging.first, First::Submitted) {
        First::Submitted => return Ok(()),
        First::Sealed(first) => first,
        First::Filling(mut first) => {
            let identity = RecordIdentity {
                key: record.key,
                allocation: reservation.id().record_tag(),
                session: volume.session(),
                version: record.version.0,
            };
            let position = ExtentPosition {
                index: extent.index,
                offset: extent.offset,
            };
            seal_header(volume.crc(), layout, &identity, position, first.bytes_mut());
            first
        }
    };
    match submit_segment(
        (staging.set, staging.locator),
        reservation,
        volume,
        layout,
        first,
        0,
        budget,
    ) {
        Ok(()) => Ok(()),
        Err((first, refusal)) => {
            staging.first = First::Sealed(first);
            Err(refusal)
        }
    }
}
impl<P: Platform> WritableFill<'_, '_, P> {
    /// The owner's end in place, run exactly once by `abort`, which returns the credits last. Disposal precedes departure: if the rollback or the abandonment panics, neither the extent nor the record is released and no abandonment is recorded, and finalization blocks on the occupied record rather than reuse a record whose extent may still be charged. An abandonment whose park finds the slot word malformed or naming another incarnation records nothing either, and the record stays occupied the same way.
    // Forced inline: out of line, the owner's fields are read back from the memory the caller's move just wrote them to.
    #[inline(always)]
    fn end(&mut self) {
        // The reservation is disposed of where it lies: a returned extent leaves it forgotten, and a retained one is abandoned in place, as its drop would.
        // An abandonment whose park found the slot word malformed or naming another incarnation left the slot to no one, so the record stays occupied.
        if self.reservation.rollback().is_ok() || self.reservation.abandon_in_place() {
            self.record.depart();
        }
        drop(self.staging.take());
        return_fill_credits(self.storage);
    }
}

impl<P: Platform> Drop for WritableFill<'_, '_, P> {
    /// The bounded fallback for an owner that was not aborted: the same disposal, departure and credit returns, the disposal and departure run out of line on the reservation and the record's state word and serial rather than on the owner, so the out-of-line part never receives the owner's address.
    /// Only a panicking disposal differs: here the unwinding reservation parks its abandonment.
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY: the reservation is taken exactly once, here, and `self` is not used as a whole afterwards.
        let reservation = unsafe { ManuallyDrop::take(&mut self.reservation) };
        end_parts(self.record.state, self.record.serial, reservation);
        return_fill_credits(self.storage);
    }
}

/// The drop's end on the owner's parts: the disposal returns an extent no write was submitted for or, failing, abandons the reservation as its drop does; then the record departs.
/// If the disposal panics, the unwinding reservation parks its abandonment and the record stays occupied; it stays occupied too when the abandonment's park finds the slot word malformed or naming another incarnation.
#[inline(never)]
fn end_parts<P: Platform>(
    state: &AtomicU64,
    serial: FillSerial,
    reservation: ExtentReservation<'_, P>,
) {
    if reservation.dispose() {
        depart_word(state, serial);
    }
}

#[cfg(test)]
thread_local! {
    /// Runs once after a fill's extent is claimed and before its shard gate attempt, so a test can close admission where only the read under the shard gate can catch it.
    pub(crate) static INTERPOSE_BEFORE_REVALIDATION: std::cell::Cell<Option<fn(&std::sync::atomic::AtomicBool)>> =
        const { std::cell::Cell::new(None) };
}

/// Verifies the decision against the live storage: the storage is live, the lengths lay out under its caps, the decision was made for those lengths under its record format, admission is open, and the volume's readiness admits a fill. Returns the pool and root, the geometry and both lengths.
#[inline(always)]
fn admitted_geometry<'s, P: Platform>(
    storage: &'s Storage<P>,
    admitted: Admitted,
    metadata_len: Option<usize>,
    body_len: Option<usize>,
) -> Result<Checked<'s>, FillReserveError> {
    let (live, root) = storage.live().ok_or(FillReserveError::TornDown)?;
    let geometry = object_geometry(
        metadata_len,
        body_len,
        root.metadata_cap,
        root.body_cap,
        &storage.record,
    )
    .map_err(FillReserveError::Layout)?;
    // The geometry accepted both lengths, so both are known.
    let lengths = (
        metadata_len.unwrap_or_default(),
        body_len.unwrap_or_default(),
    );
    if !admitted.describes(lengths.0, lengths.1, &storage.record) {
        return Err(FillReserveError::Superseded);
    }
    if storage.is_closed() {
        return Err(FillReserveError::Closed);
    }
    if let Some(refusal) = storage.readiness.fill_refusal() {
        return Err(refusal.into());
    }
    Ok(((live, root), geometry, lengths))
}

/// What [`admitted_geometry`] checked: the live pool and root, the object's geometry and its known lengths.
type Checked<'s> = (
    (&'s super::owner::Pool, &'s super::image::RootDescriptor),
    ObjectGeometry,
    (usize, usize),
);

/// Verifies the decision against the live storage and claims the one extent of an object the decision admits as one, with its slot from the key's placement window, sharing the caller's budget; the cutoff is read before the gate attempt and again under the pool gate.
#[inline(always)]
fn claim<'s, P: Platform>(
    storage: &'s Storage<P>,
    admitted: Admitted,
    fingerprint: u64,
    metadata_len: Option<usize>,
    body_len: Option<usize>,
    budget: &mut WorkBudget,
) -> Result<ExtentReservation<'s, P>, FillReserveError> {
    let ((live, root), geometry, _) = admitted_geometry(storage, admitted, metadata_len, body_len)?;
    // The decision was made for these lengths, and `reserve_storage` sends a decision of several extents to `reserve_sequence`, so this one has one extent.
    debug_assert_eq!(geometry.extents(), 1);
    let layout = AllocationLayout::new(
        metadata_len,
        body_len,
        root.metadata_cap,
        root.body_cap,
        &storage.record,
    )
    .map_err(FillReserveError::Layout)?;
    Ok(storage.reserve_layout(live, layout, Some(fingerprint), budget)?)
}

/// Routes `record`'s fingerprint, takes its shard gate within `tries` and, under it, reads the cutoff and the record, then claims `id`'s index place and both credits, names the place in the record's place word, and marks the record's row upload-granted with `id` and the object's `lengths` word, so a follower may join from that hold on; a `Corrupt` refusal poisons the gate. Precondition: `storage` granted `record` and the attempt's borrow holds it live.
#[inline(always)]
fn revalidate<P: Platform>(
    storage: &Storage<P>,
    record: &AttemptRecord<'_>,
    id: AllocationId,
    lengths: (u32, u32),
    tries: usize,
    budget: &mut WorkBudget,
) -> Result<(), FillReserveError> {
    let shard = record.shard;
    let index = storage.index().ok_or(FillReserveError::Superseded)?;
    let (_, root) = storage.live().ok_or(FillReserveError::TornDown)?;
    let route = index
        .hasher
        .reroute_prefetching(record.fingerprint, &index.geometry, budget, Prefetch::NONE)
        .map_err(|error| match error {
            RouteError::BudgetExhausted => FillReserveError::BudgetExhausted,
            RouteError::NoEnabledShard => FillReserveError::Superseded,
        })?;
    // The grant routed this fingerprint to `shard`; a different route
    // supersedes the attempt.
    if route.shard() != shard {
        return Err(FillReserveError::Superseded);
    }
    let table = storage
        .fill_table(shard)
        .ok_or(FillReserveError::Superseded)?;
    let image = index
        .image
        .shard(shard)
        .ok_or(FillReserveError::Contended)?;
    // SAFETY: the index mapping is owned and initialized while the storage is live, which the attempt's borrow guarantees.
    let (gate, control) = unsafe { (image.gate(&index.mapping), image.control(&index.mapping)) };
    // Revalidation explicitly releases or poisons the gate on every normal exit. Dropping a guard that still holds the gate therefore signals a panic during revalidation, even if the caller was already unwinding.
    let guard = take_gate(gate, control, tries, budget)?.poison_on_unwind();
    probe::note(Primitive::GateTaken);
    // SAFETY: the storage is live, `table` is one of its root image's tables, and the gate hold just taken makes the keys' `&mut` the only reference into them for the hold.
    let hold = unsafe { storage.fill_hold(table) };
    let outcome = check(storage, &hold, record, budget).and_then(|()| {
        // SAFETY: as for the fill hold, under the same gate hold.
        let mut tables = Tables {
            shard: image,
            hold: unsafe { image.hold(&index.mapping) },
            control,
        };
        let claimed =
            place_claim::claim(storage, &mut tables, &route, id, root.lease_limit, budget)?;
        let position = record.position(hold.view.states);
        hold.places[position] = claimed.word();
        record.row.mark_ready(id.record_tag(), lengths.0, lengths.1);
        Ok(())
    });
    match outcome {
        Err(FillReserveError::Corrupt) => guard.poison(),
        _ => guard.release(),
    }
    outcome
}

/// The revalidation under the gate: the cutoff, then one paid visit of the record and one paid comparison of its key.
#[inline(always)]
pub(super) fn check<P: Platform>(
    storage: &Storage<P>,
    hold: &FillHold<'_, '_>,
    record: &AttemptRecord<'_>,
    budget: &mut WorkBudget,
) -> Result<(), FillReserveError> {
    // `SeqCst` orders this reservation with concurrent close operations.
    if storage.closed().load(Ordering::SeqCst) {
        return Err(FillReserveError::Closed);
    }
    budget.debit(WorkKind::Visit)?;
    probe::note(Primitive::Load);
    let next_serial = hold.view.control.next_serial.load();
    let word = record.state.load(Ordering::Relaxed);
    let decoded = fill::decode(word, next_serial).map_err(|_| FillReserveError::Corrupt)?;
    let current = matches!(
        decoded,
        Record::Occupied {
            serial,
            departed: false,
            revoked: false,
        } if serial == record.serial
    );
    if !current {
        return Err(FillReserveError::Superseded);
    }
    budget.debit(WorkKind::Comparison)?;
    if !same_key(&hold.keys[record.position(hold.view.states)], &record.key) {
        return Err(FillReserveError::Superseded);
    }
    Ok(())
}

#[inline(always)]
fn same_key(a: &Key, b: &Key) -> bool {
    const _: () = assert!(size_of::<Key>() == 32);
    let word = |key: &Key, at: usize| {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&key[at..at + 8]);
        u64::from_ne_bytes(bytes)
    };
    (word(a, 0) ^ word(b, 0))
        | (word(a, 8) ^ word(b, 8))
        | (word(a, 16) ^ word(b, 16))
        | (word(a, 24) ^ word(b, 24))
        == 0
}
