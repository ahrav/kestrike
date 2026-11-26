//! The client side of PUT: each upload's phases, source slots and outcome.
//!
//! - Phases. [`UploadCore::put`] admits an upload in `Begin`, and PUT BEGIN
//!   is resent until the owner's PUT AUTHORITY names the fill serial
//!   (`Authority`). [`UploadCore::prepare`] then fixes the metadata length,
//!   body length and time to live (`Prepared`), and PUT PREPARE is resent
//!   until PUT READY grants fragments (`Ready`), then again on each retry in
//!   `Ready` and `Received`, which is how a lost PUT RESULT is recovered.
//!   [`UploadCore::supply`] copies each fragment into a source slot, and PUT
//!   DATA leaves only below the grant. A receipt covering every fragment
//!   moves the upload to `Received`, which awaits PUT RESULT, the only reply
//!   that publishes.
//! - Outcomes. See [`UploadOutcome`]. A PUT RESULT or PUT ERROR in the same
//!   session still settles an upload its deadline or resends ended
//!   `Unknown`; every other outcome is final.
//! - Time to live. The owner adds `ttl_ms` to its storage clock and keeps the
//!   expiry in whole seconds, rounded down, so the object may expire up to a
//!   second before `ttl_ms` alone would put it. `prepare` refuses a zero
//!   `ttl_ms`; the owner answers `InvalidRequest` for an expiry at or past
//!   `u32::MAX` seconds.
//! - Caps. The owner admits the metadata and body lengths together through
//!   its storage admission; a shape whose record layout its storage cannot
//!   hold ends `Failed(TooLarge)`. The owner's total and per-peer PUT shares
//!   bound its uploads at once, and an upload past either ends
//!   `Failed(RequestPressure)`. The session's request slots bound the
//!   uploads in flight, and the source slots bound the fragments held.
//! - Supply order. Every live upload draws its source slots from one free
//!   list. While two or more slots are free, [`UploadCore::supply`] admits
//!   any in-range fragment of the right length that the upload does not
//!   hold. The last free slot goes only to the upload's lowest fragment at
//!   or above its receipt base that it holds no slot for; any other fragment
//!   is refused with [`SupplyRefused::Prefix`], which names that index. The
//!   refusal leaves every slot, chain, cursor, due mark and timer as the
//!   supply found them after the reclaim it runs first on an empty free
//!   list. With one source slot, a caller that answers each refusal by
//!   supplying the named index sends the fragments in ascending order, and
//!   each receipt frees the slot for the next one. Whenever every source
//!   slot holds a fragment an undecided upload still needs, the upload that
//!   took the last slot holds a run of fragments starting at its receipt
//!   base; the owner raises its grant above that base once it consumes the
//!   fragments it holds, so that upload's next send below the grant can
//!   advance its base and free a slot. A slot a device still reads parks,
//!   and the first release after the device returns it frees the slot.
//! - Source custody and shutdown. A source slot stays held until the receipt
//!   passes its fragment and no device reads it. Once an upload is decided
//!   or cancelled, every slot it held frees except those a device still
//!   reads, which park until the device returns them.
//!   [`UploadCore::close`] releases an upload only once it is decided and no
//!   device holds its slots, and an `Unknown` upload only after
//!   [`UploadCore::abandon`]. Closing the client hands its transport back
//!   with device references still held, so the caller proves the device's
//!   stop before the arena releases.

use crate::storage::{
    Buffer, CacheVersion, Crc32c, EngineBudget, SourceRange, source_frees, source_writable,
};

use super::client_namespace::{ClientRequest, ClientRequests, IdentityPressure};
use super::datagram::PeerId;
use super::fetch::{FetchCoreError, Releases};
use super::frame::{Header, Kind, Status};
use super::geometry::{FRAGMENT_LEN, FragmentGeometry};
use super::namespace::Operation;
use super::requests::RequestId;
use super::serve::header;
use super::session::Admitted;
use super::slot_index::{Marks, Timers};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadConfig {
    /// Microseconds a sent BEGIN, PREPARE or PUT CANCEL waits for its reply before the next resend; the interval, from entering `Ready`, the last PREPARE send, or the last ACK that advanced the receipt base, before a `Ready` or `Received` upload resends its PREPARE, in `Ready` with every held fragment the receipt has not passed; the least time between two receipt masks marking one fragment they name as a hole due; and how long the client sleeps before it retries a PUT frame the transport refused or that failed to seal.
    pub retry_us: u64,
    /// Resends of a BEGIN, PREPARE or PUT CANCEL after its first send before a silent owner ends the upload `Unknown`, or `NotStarted` when no send call reached any of its frames; a READY or ACK resets the count.
    pub attempts: u32,
}

/// What the client knows about one upload's effect at the owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadOutcome {
    /// This attempt published in the owner's session. A later invalidation,
    /// eviction or expiry of the object leaves the outcome as it is.
    Published,
    /// The owner answered that this attempt did not publish, with its reason.
    Failed(Status),
    /// No send call reached any frame of this upload, so the owner never saw it.
    NotStarted,
    /// A frame may have reached the owner and no reply settled the attempt:
    /// the deadline passed, the resends ran out, the session or its send
    /// sequence refused a send, the session ended, the shard route stopped
    /// admitting the session's tenure, the client closed, or the owner could
    /// not tell. The object may or may not be published.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareRefused {
    Phase,
    Mismatch,
    Ttl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupplyRefused {
    NotReady,
    Index,
    Length,
    Slots,
    /// The free list holds its last slot, which goes only to the index this names: the upload's lowest fragment at or above its receipt base that it holds no slot for, always below its fragment count.
    Prefix(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Begin,
    Authority,
    Prepared,
    Ready,
    Received,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Shape {
    metadata_len: u32,
    body_len: u32,
    ttl_ms: u32,
}

impl Shape {
    fn total(self) -> u64 {
        u64::from(self.metadata_len) + u64::from(self.body_len)
    }

    fn count(self) -> u32 {
        FragmentGeometry::fragments(self.total()) as u32
    }

    fn len(self, index: u32) -> usize {
        let start = u64::from(index) * u64::from(FRAGMENT_LEN);
        (self.total() - start).min(u64::from(FRAGMENT_LEN)) as usize
    }

    /// Canonical manifests derive `total` and `count` from `metadata_len` and `body_len`, so matching lengths imply matching manifests.
    fn matches(self, header: &Header) -> bool {
        debug_assert!(
            header.total == u64::from(header.metadata_len) + u64::from(header.body_len)
                && u64::from(header.count) == FragmentGeometry::fragments(header.total),
            "a canonical manifest's total and count follow from its lengths"
        );
        header.metadata_len == self.metadata_len && header.body_len == self.body_len
    }
}

#[cfg_attr(test, derive(Debug))]
pub struct Upload {
    peer: PeerId,
    epoch: u64,
    wire: u64,
    key: [u8; 32],
    version: CacheVersion,
    phase: Phase,
    serial: u64,
    shape: Option<Shape>,
    base: u32,
    /// The fragment count the owner's last READY or ACK admitted; a held fragment at or past it waits for a higher grant.
    grant: u32,
    cancelled: bool,
    abandoned: bool,
    /// The first and last source slots this upload holds, a chain linked through each slot ascending by fragment index.
    first: Option<u32>,
    last: Option<u32>,
    /// The number of source slots on this upload's chain, parked slots included; `supply` and `release` keep it equal to the chain's length.
    held: u32,
    /// The held due slot with the lowest fragment index, or `None` while no held slot is due; [`next_data`](UploadCore::next_data) moves it past fragments the receipt passed.
    cursor: Option<u32>,
    due: bool,
    handed: bool,
    /// Control frames the upload staged since admission or its latest prepare, READY, ACK, full receipt or cancel, less those the transport left untaken, the first send included; 64 bits wide, so it passes any `u32` resend budget without wrapping.
    sends: u64,
    retry_us: u64,
    deadline_us: u64,
    outcome: Option<UploadOutcome>,
}

impl Upload {
    pub(super) fn peer(&self) -> PeerId {
        self.peer
    }

    pub(super) fn wire(&self) -> u64 {
        self.wire
    }

    #[cfg(test)]
    pub(super) fn key(&self) -> [u8; 32] {
        self.key
    }

    /// The prepared metadata and body lengths, once `prepare` fixed them.
    #[cfg(test)]
    pub(super) fn prepared(&self) -> Option<(u32, u32)> {
        self.shape.map(|shape| (shape.metadata_len, shape.body_len))
    }

    fn fits(&self, header: &Header) -> bool {
        self.shape.is_some_and(|shape| shape.matches(header))
    }

    fn undecided(&self) -> bool {
        self.outcome.is_none()
    }

    fn decide(&mut self, outcome: UploadOutcome) {
        if self
            .outcome
            .is_none_or(|known| known == UploadOutcome::Unknown)
        {
            self.outcome = Some(outcome);
            self.due = false;
        }
    }

    fn uncertain(&self) -> UploadOutcome {
        if self.handed {
            UploadOutcome::Unknown
        } else {
            UploadOutcome::NotStarted
        }
    }

    fn receipt(&mut self, index: u32, now_us: u64, retry_us: u64) {
        self.base = self.base.max(index);
        if self.shape.is_some_and(|shape| self.base >= shape.count()) {
            self.phase = Phase::Received;
            self.sends = 0;
            self.retry_us = now_us.saturating_add(retry_us);
        }
    }

    /// Whether the upload accepts and sends fragments: undecided, not cancelled, and in `Ready`.
    fn takes_data(&self) -> bool {
        self.undecided() && !self.cancelled && self.phase == Phase::Ready
    }

    /// Whether a reply is awaited, so the retry timer acts: every phase but `Authority`, where the caller's PREPARE is awaited instead, and always once cancelled.
    fn waits(&self) -> bool {
        self.cancelled || self.phase != Phase::Authority
    }

    /// Whether the outcome lets `close` release the upload: decided other than `Unknown`, or `Unknown` and abandoned.
    fn known(&self) -> bool {
        matches!(self.outcome, Some(outcome) if outcome != UploadOutcome::Unknown) || self.abandoned
    }

    /// Whether every held fragment is unneeded: the upload is decided or cancelled.
    fn releases_all(&self) -> bool {
        !self.undecided() || self.cancelled
    }

    /// The time `tick` next acts on this upload: its deadline while a frame is due or no reply is awaited, else the earlier of its retry and its deadline; `None` once decided.
    fn timer(&self) -> Option<u64> {
        match self.outcome {
            Some(_) => None,
            None if self.waits() && !self.due => Some(self.retry_us.min(self.deadline_us)),
            None => Some(self.deadline_us),
        }
    }

    fn frame(&self, now_us: u64) -> Header {
        if self.cancelled {
            return Header {
                allocation: self.serial,
                status: Status::Cancelled as u16,
                ..header(Kind::PutCancel, self.wire, self.key)
            };
        }
        match (self.phase, self.shape) {
            (Phase::Begin, _) | (_, None) => Header {
                offset: self.version.0,
                remaining_ms: self
                    .deadline_us
                    .saturating_sub(now_us)
                    .div_ceil(1_000)
                    .clamp(1, u64::from(u32::MAX)) as u32,
                ..header(Kind::PutBegin, self.wire, self.key)
            },
            (_, Some(shape)) => Header {
                allocation: self.serial,
                total: shape.total(),
                metadata_len: shape.metadata_len,
                body_len: shape.body_len,
                count: shape.count(),
                remaining_ms: shape.ttl_ms,
                ..header(Kind::PutPrepare, self.wire, self.key)
            },
        }
    }
}

/// [`writable`](Self::writable) returns the bytes only while the slot holds no fragment and the buffer has no device reference. A device reference keeps the slot held until the reference ends, so the bytes a device reads stay fixed.
pub struct SourceSlot<'a> {
    buffer: Buffer<'a>,
    len: usize,
    holder: Option<(RequestId, u32)>,
    /// Neighbors in the holder's chain; `next` alone links a free slot into the free list.
    prev: Option<u32>,
    next: Option<u32>,
    /// The time before which a receipt mask naming this fragment as a hole resends nothing.
    guard_us: u64,
    /// Whether the held fragment waits for a send.
    due: bool,
    /// The crc32c of the held fragment's bytes, as the frame's body crc carries it.
    crc: u32,
}

impl<'a> SourceSlot<'a> {
    pub(super) fn new(buffer: Buffer<'a>) -> Self {
        Self {
            buffer,
            len: 0,
            holder: None,
            prev: None,
            next: None,
            guard_us: 0,
            due: false,
            crc: 0,
        }
    }

    pub(super) fn crc(&self) -> u32 {
        self.crc
    }

    /// The fragment index of a slot on a chain, which always holds one.
    fn index(&self) -> u32 {
        self.holder.map_or(0, |(_, index)| index)
    }

    pub fn writable(&mut self) -> Option<&mut [u8]> {
        source_writable(self.holder.is_some(), self.buffer.device_held())
            .then(|| self.buffer.bytes_mut())
    }

    /// Whether a device reference holds the slot's buffer, for a test
    /// adapter that records NIC custody.
    #[cfg(test)]
    pub(super) fn device_held(&self) -> bool {
        self.buffer.device_held()
    }

    pub fn piece(&self) -> Option<SourceRange<'_, 'a>> {
        self.holder?;
        self.buffer.source(0..self.len)
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.buffer.bytes()[..self.len]
    }
}

/// The client's uploads: their timers, due frames and source slots.
///
/// - A slot on the free list holds no fragment and no device reference; every other slot is on the chain of the upload whose fragment it holds, ascending by index.
/// - The event that leaves a held slot unneeded, a receipt past its fragment or its upload's decision or cancel, frees it unless a device still reads it, which sets `parked` until a later release frees it.
/// - `timers` holds, by table slot, the time `tick` next acts on each undecided upload, and no timer elsewhere.
/// - `marked` names every upload with a control frame due, and `data` every upload that may hold a due fragment below its grant.
pub struct UploadCore<'a> {
    config: UploadConfig,
    /// The release board of the namespace the core was built from, and that namespace's number on it.
    releases: &'a Releases,
    board: u64,
    crc: Crc32c,
    slots: Box<[SourceSlot<'a>]>,
    /// The head of the list of slots that hold no fragment; a held slot is on its upload's chain instead.
    free: Option<u32>,
    /// `live` contains admitted upload table slots in ascending order until release.
    live: Vec<u16>,
    /// Each table slot's upload timer; a slot that holds no undecided upload carries none.
    timers: Timers,
    /// One bit per table slot, set for every upload with a control frame due; `poll` clears a bit whose upload has none.
    marked: Marks,
    /// One bit per table slot, set for every upload that may have a fragment due below its grant; `data` clears a bit whose upload has none.
    data: Marks,
    /// The table slot where the next `poll` starts its scan: one past the last slot a send left, so uploads share a short budget in turn.
    cursor: u32,
    /// The table slot where the next `data` starts its pass, so uploads share the turn's DATA sends in turn.
    data_cursor: u32,
    /// Scratch for [`data`](Self::data): the table slots of the uploads that staged a fragment in its last pass.
    runnable: Box<[u16]>,
    /// `parked` marks that some upload may retain slots pending release, because of device references or staged frames; `tick` retries the release until all such slots are reclaimed.
    parked: bool,
    /// RESULT frames an upload accepted and decided on.
    #[cfg(test)]
    results: u64,
}

impl<'a> UploadCore<'a> {
    /// RESULT frames uploads have accepted since the core was built.
    #[cfg(test)]
    pub(super) fn results(&self) -> u64 {
        self.results
    }

    /// `new` charges `budget` for a live index entry, a runnable entry, a timer and two due bits per table slot, so admission fits within the initial allocation. Each [`ClientRequests`] supports at most one upload core.
    ///
    /// # Errors
    ///
    /// `Paired` when `requests` already serves an upload core, `Sources` when `slots` holds more than the 65,536 source slots a staged frame's `u16` slot index names, or `Budget`; `budget` and `requests` are unchanged on every error.
    pub fn new(
        config: UploadConfig,
        mut slots: Box<[SourceSlot<'a>]>,
        requests: &mut ClientRequests<'a>,
        budget: &mut EngineBudget,
    ) -> Result<Self, FetchCoreError> {
        if requests.serves(Operation::Put) {
            return Err(FetchCoreError::Paired);
        }
        // `stage` hands `send` each slot's index as a `u16`.
        if slots.len() > usize::from(u16::MAX) + 1 {
            return Err(FetchCoreError::Sources { count: slots.len() });
        }
        let table = requests.table().slots();
        budget
            .charge(
                2 * table as usize * size_of::<u16>()
                    + Timers::charge(table)
                    + 2 * Marks::charge(table),
            )
            .map_err(FetchCoreError::Budget)?;
        requests.serve(Operation::Put);
        let count = slots.len() as u32;
        for (at, slot) in (0..).zip(slots.iter_mut()) {
            slot.next = (at + 1 < count).then_some(at + 1);
        }
        let releases = requests.releases();
        Ok(Self {
            config,
            releases,
            board: releases.board(),
            crc: Crc32c::detect(),
            slots,
            free: (count > 0).then_some(0),
            live: Vec::with_capacity(table as usize),
            timers: Timers::new(table),
            marked: Marks::new(table),
            data: Marks::new(table),
            cursor: 0,
            data_cursor: 0,
            runnable: vec![0; table as usize].into_boxed_slice(),
            parked: false,
            #[cfg(test)]
            results: 0,
        })
    }

    /// The core requires the `ClientRequests` namespace used at construction; a pairing mismatch panics.
    fn check_pair(&self, requests: &ClientRequests<'_>) {
        assert!(
            std::ptr::eq(self.releases, requests.releases()) && self.board == self.releases.board(),
            "an upload core runs over the namespace it was built from"
        );
    }

    fn uploads<'r>(&'r self, requests: &'r ClientRequests<'_>) -> impl Iterator<Item = &'r Upload> {
        self.live.iter().filter_map(|&slot| {
            requests
                .table()
                .live_id(u32::from(slot))
                .and_then(|id| requests.upload(id))
        })
    }

    pub(super) fn slots(&self) -> &[SourceSlot<'a>] {
        &self.slots
    }

    /// Upload `id`'s send count.
    #[cfg(test)]
    pub(super) fn sends(requests: &ClientRequests<'_>, id: RequestId) -> Option<u64> {
        Some(requests.upload(id)?.sends)
    }

    /// Sets upload `id`'s send count to `sends`, so a test reaches the count's limit without that many sends, and leaves the upload's timer as it is.
    #[cfg(test)]
    pub(super) fn seed_sends(requests: &mut ClientRequests<'_>, id: RequestId, sends: u64) {
        if let Some(upload) = requests.upload_mut(id) {
            upload.sends = sends;
        }
    }

    /// Admitted uploads not yet released, for a test that bounds them.
    #[cfg(test)]
    pub(super) fn live(&self) -> usize {
        self.live.len()
    }

    /// Upload `id`'s record with the source slots it holds and their bytes, its timer, its due marks and the free list head, for a test that compares an upload's whole state across one input.
    #[cfg(test)]
    pub(super) fn snapshot(&self, requests: &ClientRequests<'_>, id: RequestId) -> String {
        let held: Vec<_> = self
            .slots
            .iter()
            .filter(|slot| slot.holder.is_some_and(|(holder, _)| holder == id))
            .map(|slot| {
                let (holder, len, prev, next) = (slot.holder, slot.len, slot.prev, slot.next);
                let (guard_us, due, crc) = (slot.guard_us, slot.due, slot.crc);
                (
                    holder,
                    len,
                    prev,
                    next,
                    guard_us,
                    due,
                    crc,
                    slot.bytes().to_vec(),
                )
            })
            .collect();
        format!(
            "{:?} {held:?} timer {:?} marked {} data {} free {:?}",
            requests.upload(id),
            self.timers.get(usize::from(id.slot())),
            self.marked.contains(id.slot()),
            self.data.contains(id.slot()),
            self.free,
        )
    }

    /// The source slots, for a test that probes `writable` while a device reads them.
    #[cfg(test)]
    pub(super) fn slots_mut(&mut self) -> &mut [SourceSlot<'a>] {
        &mut self.slots
    }

    /// Starts an upload of `key` whose BEGIN names cache `version`; [`Client::put`](super::Client::put) states how the owner's coverage judges a version, 0 included.
    pub fn put(
        &mut self,
        requests: &mut ClientRequests<'_>,
        session: Admitted,
        key: [u8; 32],
        version: CacheVersion,
        now_us: u64,
        wait_us: u64,
    ) -> Result<RequestId, IdentityPressure> {
        self.check_pair(requests);
        let id = requests.admit(session.peer, session.caps.slots, |wire| {
            ClientRequest::Put(Upload {
                peer: session.peer,
                epoch: session.epoch,
                wire,
                key,
                version,
                phase: Phase::Begin,
                serial: 0,
                shape: None,
                base: 0,
                grant: 0,
                cancelled: false,
                abandoned: false,
                first: None,
                last: None,
                held: 0,
                cursor: None,
                due: true,
                handed: false,
                sends: 0,
                retry_us: now_us,
                deadline_us: now_us.saturating_add(wait_us),
                outcome: None,
            })
        })?;
        let at = self.live.partition_point(|&slot| slot < id.slot());
        self.live.insert(at, id.slot());
        // A new upload's BEGIN is due, so `tick` acts on it next at its deadline.
        self.timers
            .set(usize::from(id.slot()), Some(now_us.saturating_add(wait_us)));
        self.marked.set(id.slot());
        Ok(id)
    }

    pub fn prepare(
        &mut self,
        requests: &mut ClientRequests<'_>,
        id: RequestId,
        metadata_len: u32,
        body_len: u32,
        ttl_ms: u32,
    ) -> Result<(), PrepareRefused> {
        self.check_pair(requests);
        let upload = requests
            .upload_mut(id)
            .filter(|upload| upload.undecided() && !upload.cancelled)
            .ok_or(PrepareRefused::Phase)?;
        let shape = Shape {
            metadata_len,
            body_len,
            ttl_ms,
        };
        match (upload.phase, upload.shape) {
            (Phase::Begin, _) => Err(PrepareRefused::Phase),
            (_, Some(prepared)) if prepared == shape => Ok(()),
            (_, Some(_)) => Err(PrepareRefused::Mismatch),
            _ if ttl_ms == 0 => Err(PrepareRefused::Ttl),
            _ => {
                upload.shape = Some(shape);
                upload.phase = Phase::Prepared;
                upload.due = true;
                upload.sends = 0;
                self.timers.set(usize::from(id.slot()), upload.timer());
                self.marked.set(id.slot());
                Ok(())
            }
        }
    }

    /// The lowest fragment index at or above `upload`'s receipt base that it holds no slot for: its chain ascends by index, so the walk skips the parked slots below the base and stops at the first gap in the run from the base.
    fn wanted(slots: &[SourceSlot<'_>], upload: &Upload) -> u32 {
        let mut wanted = upload.base;
        let mut at = upload.first;
        while let Some(here) = at {
            let index = slots[here as usize].index();
            if index > wanted {
                break;
            }
            if index == wanted {
                wanted += 1;
            }
            at = slots[here as usize].next;
        }
        wanted
    }

    pub fn supply(
        &mut self,
        requests: &mut ClientRequests<'_>,
        id: RequestId,
        index: u32,
        bytes: &[u8],
    ) -> Result<usize, SupplyRefused> {
        self.check_pair(requests);
        // Events free every slot no device reads once its upload no longer needs it, so only a parked slot can still be freed here.
        if self.free.is_none() && self.parked {
            self.reclaim(requests);
        }
        let Self { slots, free, .. } = self;
        let upload = requests
            .upload_mut(id)
            .filter(|upload| upload.takes_data())
            .ok_or(SupplyRefused::NotReady)?;
        let shape = upload.shape.ok_or(SupplyRefused::NotReady)?;
        if index < upload.base || index >= shape.count() {
            return Err(SupplyRefused::Index);
        }
        let mut after = upload.last;
        let mut above = 0;
        while let Some(at) = after.filter(|&at| slots[at as usize].index() >= index) {
            if slots[at as usize].index() == index {
                return Err(SupplyRefused::Index);
            }
            above += 1;
            after = slots[at as usize].prev;
        }
        if bytes.len() != shape.len(index) {
            return Err(SupplyRefused::Length);
        }
        let at = free.ok_or(SupplyRefused::Slots)?;
        // The last free slot goes only to the fragment the receipt base waits for, so whenever every slot is full the upload that took the last one holds its base fragment.
        if slots[at as usize].next.is_none() {
            debug_assert_eq!(
                std::iter::successors(upload.first, |&at| slots[at as usize].next).count(),
                upload.held as usize,
                "`held` counts the upload's chain"
            );
            // The chain's indices strictly increase. When its first slot is at or above the base, its `held - above` slots below `index` cover the run from the base to `index` exactly when they number `index - base`, which makes `index` the wanted index.
            let from_base = upload
                .first
                .is_none_or(|first| slots[first as usize].index() >= upload.base);
            if from_base && upload.held - above == index - upload.base {
                debug_assert_eq!(Self::wanted(slots, upload), index);
            } else {
                let wanted = Self::wanted(slots, upload);
                if index != wanted {
                    return Err(SupplyRefused::Prefix(wanted));
                }
            }
        }
        self.fill(upload, id, index, bytes, at, after)
    }

    /// Copies `bytes` into free slot `at` with their crc32c and links the slot into `upload`'s chain after `after`, once `supply`'s checks admitted fragment `index`.
    ///
    /// # Errors
    ///
    /// - The method returns `SupplyRefused::Slots` and preserves all state while a device still reads slot `at`'s buffer.
    #[inline(never)]
    fn fill(
        &mut self,
        upload: &mut Upload,
        id: RequestId,
        index: u32,
        bytes: &[u8],
        at: u32,
        after: Option<u32>,
    ) -> Result<usize, SupplyRefused> {
        let Self {
            slots, free, crc, ..
        } = self;
        let slot = &mut slots[at as usize];
        let target = slot.writable().ok_or(SupplyRefused::Slots)?;
        let mut running = crc.start();
        running.update_and_copy(bytes, &mut target[..bytes.len()]);
        let sum = running.finish();
        *free = slot.next;
        let before = after.map_or(upload.first, |after| slots[after as usize].next);
        let slot = &mut slots[at as usize];
        slot.len = bytes.len();
        slot.holder = Some((id, index));
        upload.held += 1;
        slot.prev = after;
        slot.next = before;
        slot.guard_us = 0;
        slot.due = true;
        slot.crc = sum;
        match after {
            Some(after) => slots[after as usize].next = Some(at),
            None => upload.first = Some(at),
        }
        match before {
            Some(before) => slots[before as usize].prev = Some(at),
            None => upload.last = Some(at),
        }
        if upload
            .cursor
            .is_none_or(|cursor| slots[cursor as usize].index() > index)
        {
            upload.cursor = Some(at);
        }
        self.mark_data(id.slot(), upload);
        Ok(bytes.len())
    }

    /// Refuses further input to upload `id`, stops its resends and queues PUT CANCEL, resent alone until the owner answers; an upload no send call reached ends `NotStarted` at once. Its held slots free, or wait for the device. A cancel of an upload already cancelled changes nothing, so the queued CANCEL keeps its resend count and interval.
    pub fn cancel(&mut self, requests: &mut ClientRequests<'_>, id: RequestId) {
        self.check_pair(requests);
        let Some(upload) = requests
            .upload_mut(id)
            .filter(|upload| upload.undecided() && !upload.cancelled)
        else {
            return;
        };
        let slot = id.slot();
        if upload.handed {
            upload.cancelled = true;
            upload.due = true;
            upload.sends = 0;
            self.marked.set(slot);
        } else {
            upload.decide(UploadOutcome::NotStarted);
        }
        self.timers.set(usize::from(slot), upload.timer());
        self.parked |= Self::release(&mut self.slots, &mut self.free, upload);
    }

    /// Lets `close` release an upload whose outcome is `Unknown`; false for any other outcome.
    pub fn abandon(&mut self, requests: &mut ClientRequests<'_>, id: RequestId) -> bool {
        self.check_pair(requests);
        let Some(upload) = requests
            .upload_mut(id)
            .filter(|upload| upload.outcome == Some(UploadOutcome::Unknown))
        else {
            return false;
        };
        upload.abandoned = true;
        true
    }

    /// Frees `upload`'s slots below its receipt base, or every slot once it is decided or cancelled, except the slots a device still reads, and returns whether any such slot stays held.
    fn release(slots: &mut [SourceSlot<'_>], free: &mut Option<u32>, upload: &mut Upload) -> bool {
        let all = upload.releases_all();
        let mut parked = false;
        let mut next = upload.first;
        while let Some(at) = next {
            let slot = &mut slots[at as usize];
            next = slot.next;
            let retention_ended = all || slot.index() < upload.base;
            if !source_frees(retention_ended, slot.buffer.device_held()) {
                // The chain ascends by index, so the first retained slot ends the walk; a device-held slot whose retention ended parks.
                if !retention_ended {
                    break;
                }
                parked = true;
                continue;
            }
            let prev = slot.prev;
            slot.holder = None;
            upload.held -= 1;
            slot.due = false;
            slot.prev = None;
            slot.next = *free;
            *free = Some(at);
            match prev {
                Some(prev) => slots[prev as usize].next = next,
                None => upload.first = next,
            }
            match next {
                Some(next) => slots[next as usize].prev = prev,
                None => upload.last = prev,
            }
            if upload.cursor == Some(at) {
                upload.cursor = first_due(slots, next);
            }
        }
        parked
    }

    pub fn outcome(&self, requests: &ClientRequests<'_>, id: RequestId) -> Option<UploadOutcome> {
        self.check_pair(requests);
        requests.upload(id)?.outcome
    }

    /// Upload `id`'s fill serial, cumulative receipt base and grant, for a
    /// test adapter that records them as observations.
    #[cfg(test)]
    pub(super) fn receipt(
        &self,
        requests: &ClientRequests<'_>,
        id: RequestId,
    ) -> Option<(u64, u32, u32)> {
        let upload = requests.upload(id)?;
        Some((upload.serial, upload.base, upload.grant))
    }

    /// Releases upload `id` once its outcome is known and no slot it held stays with the device; an `Unknown` upload waits for [`abandon`](Self::abandon).
    pub fn close(&mut self, requests: &mut ClientRequests<'_>, id: RequestId) -> bool {
        self.check_pair(requests);
        let decided = requests.upload_mut(id).is_some_and(|upload| {
            self.parked |= Self::release(&mut self.slots, &mut self.free, upload);
            upload.known() && upload.first.is_none()
        });
        let released = decided && requests.release(id);
        if released && let Ok(at) = self.live.binary_search(&id.slot()) {
            self.live.remove(at);
        }
        released
    }

    /// Retries the release of every upload's unneeded slots, for slots whose device reference has since ended.
    fn reclaim(&mut self, requests: &mut ClientRequests<'_>) {
        let mut parked = false;
        for &slot in &self.live {
            if let Some((_, upload)) = requests.live_upload_mut(u32::from(slot)) {
                parked |= Self::release(&mut self.slots, &mut self.free, upload);
            }
        }
        self.parked = parked;
    }

    /// The lowest due fragment of `upload` below its grant, with its slot, moving the cursor past fragments the receipt passed.
    fn next_data(&mut self, upload: &mut Upload) -> Option<(u32, u32)> {
        while let Some(at) = upload.cursor {
            let slot = &self.slots[at as usize];
            let index = slot.index();
            if index >= upload.base {
                return (index < upload.grant).then_some((index, at));
            }
            upload.cursor = first_due(&self.slots, slot.next);
        }
        None
    }

    /// The lowest due fragment index of `upload` the receipt has not passed; the caller applies the grant.
    fn due_from(&self, upload: &Upload) -> Option<u32> {
        let mut at = upload.cursor;
        while let Some(slot) = at {
            let entry = &self.slots[slot as usize];
            let index = entry.index();
            if index >= upload.base {
                return Some(index);
            }
            at = first_due(&self.slots, entry.next);
        }
        None
    }

    /// Marks table slot `slot` for `data` while its upload has a fragment to send below the grant.
    fn mark_data(&mut self, slot: u16, upload: &mut Upload) {
        if upload.takes_data() && self.next_data(upload).is_some() {
            self.data.set(slot);
        }
    }

    /// Stages at most `budget` PUT DATA frames: one pass over the uploads with a fragment due, from the cursor, stages one fragment each, and further passes over the uploads that staged share the rest of the budget in turn. `send` seals and stages a frame from the slot it names, or returns false for a send the session or sequence refused, which ends the upload.
    pub fn data(
        &mut self,
        requests: &mut ClientRequests<'_>,
        budget: usize,
        mut send: impl FnMut(u64, Header, u16, &SourceSlot<'a>) -> bool,
    ) -> usize {
        self.check_pair(requests);
        if budget == 0 {
            return 0;
        }
        let slots = requests.table().slots();
        let (mut staged, mut visited, mut from) = (0, 0, self.data_cursor);
        let mut runnable = 0;
        // Visits marked slots in slot order from the cursor, wrapping, until every slot is passed once; the cursor stays on the first marked slot the budget left unvisited.
        while visited < slots {
            let Some(at) = self.data.next(from) else {
                break;
            };
            visited += if at >= from {
                at - from + 1
            } else {
                at + slots - from + 1
            };
            if visited > slots {
                break;
            }
            if staged == budget {
                self.data_cursor = at;
                break;
            }
            from = if at + 1 < slots { at + 1 } else { 0 };
            self.data_cursor = from;
            let slot = at as u16;
            if self.stage(requests, slot, &mut send) {
                staged += 1;
                self.runnable[runnable] = slot;
                runnable += 1;
            } else {
                self.data.remove(slot);
            }
        }
        while staged < budget && runnable > 0 {
            let mut kept = 0;
            for read in 0..runnable {
                if staged == budget {
                    break;
                }
                let slot = self.runnable[read];
                if self.stage(requests, slot, &mut send) {
                    staged += 1;
                    self.runnable[kept] = slot;
                    kept += 1;
                } else {
                    self.data.remove(slot);
                }
            }
            runnable = kept;
        }
        staged
    }

    /// Stages the next due fragment of the upload in table slot `slot`, or returns false when it has none below its grant or the send refused it.
    #[inline(always)]
    fn stage(
        &mut self,
        requests: &mut ClientRequests<'_>,
        slot: u16,
        send: &mut impl FnMut(u64, Header, u16, &SourceSlot<'a>) -> bool,
    ) -> bool {
        let Some((_, upload)) = requests
            .live_upload_mut(u32::from(slot))
            .filter(|(_, upload)| upload.takes_data())
        else {
            return false;
        };
        let (Some(shape), Some((index, at))) = (upload.shape, self.next_data(upload)) else {
            return false;
        };
        let source = &self.slots[at as usize];
        let header = Header {
            allocation: upload.serial,
            total: shape.total(),
            metadata_len: shape.metadata_len,
            body_len: shape.body_len,
            count: shape.count(),
            index,
            offset: u64::from(index) * u64::from(FRAGMENT_LEN),
            datagram_len: source.len as u32,
            ..header(Kind::PutData, upload.wire, upload.key)
        };
        if !send(upload.epoch, header, at as u16, source) {
            // The frames this turn staged before the refusal still read the upload's slots, so their release waits for the next tick.
            upload.decide(upload.uncertain());
            self.timers.set(usize::from(slot), upload.timer());
            self.parked |= upload.first.is_some();
            return false;
        }
        self.slots[at as usize].due = false;
        upload.cursor = first_due(&self.slots, self.slots[at as usize].next);
        true
    }

    /// Returns a staged DATA frame the transport left unsent to due, from source slot `slot`.
    pub fn unsent(&mut self, requests: &mut ClientRequests<'_>, slot: u16) {
        self.check_pair(requests);
        let at = u32::from(slot);
        let Some((id, index)) = self.slots.get(at as usize).and_then(|slot| slot.holder) else {
            return;
        };
        self.slots[at as usize].due = true;
        let Some(upload) = requests.upload_mut(id) else {
            return;
        };
        if upload
            .cursor
            .is_none_or(|cursor| self.slots[cursor as usize].index() > index)
        {
            upload.cursor = Some(at);
        }
        self.mark_data(id.slot(), upload);
    }

    pub fn receive(
        &mut self,
        requests: &mut ClientRequests<'_>,
        session: Admitted,
        header: &Header,
        now_us: u64,
    ) -> bool {
        self.check_pair(requests);
        let Some((id, upload)) = requests
            .route_upload_mut(session.peer, header.request)
            .filter(|(_, upload)| {
                upload.epoch == session.epoch
                    && upload.key == header.key
                    && (upload.undecided() || upload.outcome == Some(UploadOutcome::Unknown))
            })
            .filter(|(_, upload)| {
                upload.phase == Phase::Begin
                    || header.allocation == 0
                    || header.allocation == upload.serial
            })
        else {
            return false;
        };
        let retry_us = self.config.retry_us;
        let settled = !upload.undecided();
        match (header.kind, upload.phase) {
            _ if settled && !matches!(header.kind, Kind::PutResult | Kind::PutError) => {
                return false;
            }
            (Kind::PutAuthority, Phase::Begin) => {
                upload.serial = header.allocation;
                upload.phase = Phase::Authority;
                upload.due = upload.cancelled;
                upload.handed = true;
            }
            // The READY, ACK and RESULT arms below require the shape fixed by PREPARE. Canonical frames bound their receipt index and grant by their fragment count, so matching shapes bound both by the prepared count.
            (Kind::PutReady, Phase::Ready) if upload.fits(header) => {
                upload.sends = 0;
                upload.grant = upload.grant.max(header.grant);
            }
            (Kind::PutReady, Phase::Prepared) if upload.fits(header) => {
                upload.phase = Phase::Ready;
                upload.sends = 0;
                upload.grant = header.grant;
                upload.due = upload.cancelled;
                upload.retry_us = now_us.saturating_add(retry_us);
                upload.receipt(header.index, now_us, retry_us);
            }
            (Kind::PutAck, Phase::Ready | Phase::Received) if upload.fits(header) => {
                upload.sends = 0;
                if header.index > upload.base {
                    upload.retry_us = now_us.saturating_add(retry_us);
                }
                upload.grant = upload.grant.max(header.grant);
                upload.due &= upload.cancelled;
                let mask_at_base = header.index >= upload.base;
                upload.receipt(header.index, now_us, retry_us);
                // Mask bit `i` names fragment `base + 1 + i`; the base itself is always a hole.
                let (base, mask) = (upload.base, header.offset);
                let named = if mask_at_base {
                    64 - mask.leading_zeros()
                } else {
                    0
                };
                if named > 0 {
                    let mut at = upload.first;
                    while let Some(here) = at {
                        let slot = &self.slots[here as usize];
                        let index = slot.index();
                        at = slot.next;
                        if index < base {
                            continue;
                        }
                        let rel = index - base;
                        if rel > named {
                            break;
                        }
                        let hole = rel == 0 || mask & 1 << (rel - 1) == 0;
                        if hole && now_us >= slot.guard_us {
                            let slot = &mut self.slots[here as usize];
                            slot.due = true;
                            slot.guard_us = now_us.saturating_add(retry_us);
                            if upload
                                .cursor
                                .is_none_or(|cursor| self.slots[cursor as usize].index() > index)
                            {
                                upload.cursor = Some(here);
                            }
                        }
                    }
                }
            }
            (Kind::PutResult, Phase::Prepared | Phase::Ready | Phase::Received)
                if upload.fits(header) =>
            {
                upload.decide(UploadOutcome::Published);
                #[cfg(test)]
                {
                    self.results += 1;
                }
            }
            (Kind::PutError, phase) => match Status::from_wire(header.status) {
                Some(Status::UnknownOutcome) => upload.decide(UploadOutcome::Unknown),
                Some(_) if phase != Phase::Begin && header.allocation == 0 => return false,
                Some(status) => upload.decide(UploadOutcome::Failed(status)),
                None => return false,
            },
            _ => return false,
        }
        debug_assert!(
            !matches!(header.kind, Kind::PutReady | Kind::PutAck | Kind::PutResult)
                || upload.fits(header),
            "READY, ACK and RESULT act only on the prepared shape"
        );
        self.timers.set(usize::from(id.slot()), upload.timer());
        // A reply that crosses a sent PUT CANCEL makes the CANCEL due again.
        if upload.due {
            self.marked.set(id.slot());
        }
        if upload.first.is_some() {
            self.parked |= Self::release(&mut self.slots, &mut self.free, upload);
        }
        self.mark_data(id.slot(), upload);
        true
    }

    /// Decides each upload whose deadline or retries ran out, makes due each one whose retry timer fired, and frees the source slots each upload no longer needs.
    #[inline]
    pub fn tick(&mut self, requests: &mut ClientRequests<'_>, now_us: u64) {
        self.check_pair(requests);
        if self.timers.floor().is_none_or(|floor| now_us < floor) && !self.parked {
            debug_assert!(
                self.uploads(requests)
                    .all(|upload| upload.timer().is_none_or(|at| at > now_us)
                        && upload.first.is_none_or(|at| {
                            !upload.releases_all() && self.slots[at as usize].index() >= upload.base
                        }))
                    && self.live.iter().all(|&slot| {
                        requests
                            .table()
                            .live_id(u32::from(slot))
                            .and_then(|id| requests.upload(id))
                            .is_none_or(|upload| {
                                self.timers.get(usize::from(slot)) == upload.timer()
                            })
                    }),
                "below the floor no timer is due, and with nothing parked no upload holds a slot it no longer needs"
            );
            return;
        }
        self.scan(requests, now_us);
    }

    /// Acts on every upload whose timer is due, retries parked releases, and refolds the floor.
    fn scan(&mut self, requests: &mut ClientRequests<'_>, now_us: u64) {
        let (retry_us, attempts) = (self.config.retry_us, self.config.attempts);
        let end = requests.table().high_water() as usize;
        let mut from = 0;
        while let Some(slot) = self.timers.next_due(from, end, now_us) {
            from = slot + 1;
            let Some((_, upload)) = requests
                .live_upload_mut(slot as u32)
                .filter(|(_, upload)| upload.undecided())
            else {
                self.timers.set(slot, None);
                continue;
            };
            if now_us >= upload.deadline_us {
                upload.decide(upload.uncertain());
            } else if upload.waits() && !upload.due && now_us >= upload.retry_us {
                // `sends` counts the first send too, so the upload ends once it exceeds the resend budget.
                if upload.sends > u64::from(attempts) {
                    upload.decide(upload.uncertain());
                } else {
                    upload.due = true;
                    upload.retry_us = now_us.saturating_add(retry_us);
                    self.marked.set(slot as u16);
                    // A retry in `Ready` resends every held fragment the receipt has not passed, with the PREPARE it queued.
                    if upload.takes_data() {
                        let mut at = upload.first;
                        while let Some(here) = at {
                            let held = &mut self.slots[here as usize];
                            if held.index() >= upload.base {
                                held.due = true;
                            }
                            at = held.next;
                        }
                        upload.cursor = first_due(&self.slots, upload.first);
                        self.mark_data(slot as u16, upload);
                    }
                }
            }
            if !upload.undecided() {
                self.parked |= Self::release(&mut self.slots, &mut self.free, upload);
            }
            self.timers.set(slot, upload.timer());
        }
        if self.parked {
            self.reclaim(requests);
        }
        self.timers.fold(end);
    }

    pub(super) fn close_all(&mut self, requests: &mut ClientRequests<'_>) {
        self.check_pair(requests);
        for at in 0..self.live.len() {
            let slot = self.live[at];
            if let Some((_, upload)) = requests.live_upload_mut(u32::from(slot)) {
                self.end(slot, upload);
            }
        }
    }

    /// Decides `upload`, in table slot `slot`, as its possible send makes it, `Unknown` or `NotStarted`, and frees the slots it held.
    fn end(&mut self, slot: u16, upload: &mut Upload) {
        upload.decide(upload.uncertain());
        self.timers.set(usize::from(slot), upload.timer());
        self.parked |= Self::release(&mut self.slots, &mut self.free, upload);
    }

    pub fn end_session(&mut self, requests: &mut ClientRequests<'_>, epoch: u64) {
        self.check_pair(requests);
        for at in 0..self.live.len() {
            let slot = self.live[at];
            if let Some((_, upload)) = requests
                .live_upload_mut(u32::from(slot))
                .filter(|(_, upload)| upload.epoch == epoch)
            {
                self.end(slot, upload);
            }
        }
    }

    /// Whether some upload may have a control frame or a fragment due, so a send batch keeps one send for [`poll`](Self::poll) and [`data`](Self::data).
    #[inline]
    pub(super) fn may_send(&self) -> bool {
        self.marked.maybe_any(&self.data)
    }

    #[inline]
    pub(super) fn poll(
        &mut self,
        requests: &mut ClientRequests<'_>,
        now_us: u64,
        budget: usize,
        send: impl FnMut(u64, Header) -> bool,
    ) -> usize {
        self.check_pair(requests);
        debug_assert!(
            self.live.iter().all(|&slot| {
                self.marked.contains(slot)
                    || requests
                        .table()
                        .live_id(u32::from(slot))
                        .and_then(|id| requests.upload(id))
                        .is_none_or(|upload| !upload.due)
            }),
            "every upload with a frame due is marked"
        );
        self.send_marked(requests, now_us, budget, send)
    }

    fn send_marked(
        &mut self,
        requests: &mut ClientRequests<'_>,
        now_us: u64,
        budget: usize,
        mut send: impl FnMut(u64, Header) -> bool,
    ) -> usize {
        let slots = requests.table().slots();
        let (mut staged, mut visited, mut from) = (0, 0, self.cursor);
        // Visits marked slots in slot order from the cursor, wrapping, until every slot is passed once; the cursor stays on the first due slot the budget left unsent.
        while visited < slots {
            let Some(at) = self.marked.next(from) else {
                break;
            };
            visited += if at >= from {
                at - from + 1
            } else {
                at + slots - from + 1
            };
            if visited > slots {
                break;
            }
            let slot = at as u16;
            let next = if at + 1 < slots { at + 1 } else { 0 };
            let Some((_, upload)) = requests
                .live_upload_mut(at)
                .filter(|(_, upload)| upload.due)
            else {
                self.marked.remove(slot);
                from = next;
                self.cursor = from;
                continue;
            };
            if staged == budget {
                self.cursor = at;
                break;
            }
            from = next;
            self.cursor = from;
            self.marked.remove(slot);
            if !send(upload.epoch, upload.frame(now_us)) {
                self.end(slot, upload);
                continue;
            }
            upload.due = false;
            upload.sends += 1;
            upload.retry_us = now_us.saturating_add(self.config.retry_us);
            self.timers.set(usize::from(slot), upload.timer());
            staged += 1;
        }
        staged
    }

    pub(super) fn handed(
        &mut self,
        requests: &mut ClientRequests<'_>,
        (peer, wire): (PeerId, u64),
        reached: bool,
        taken: bool,
    ) {
        self.check_pair(requests);
        let Some((id, upload)) = requests.route_upload_mut(peer, wire) else {
            return;
        };
        let slot = id.slot();
        upload.handed |= reached;
        if !taken && upload.undecided() {
            upload.due = true;
            upload.sends = upload.sends.saturating_sub(1);
            self.timers.set(usize::from(slot), upload.timer());
            self.marked.set(slot);
        }
    }

    /// Whether a frame is due and the least upload timer; raises of the timer at the floor since the last read cost at most one fold of their stale paths here.
    #[inline]
    pub(super) fn wake(&self, requests: &ClientRequests<'_>) -> (bool, Option<u64>) {
        self.check_pair(requests);
        let least = self.timers.least(requests.table().high_water() as usize);
        debug_assert_eq!(
            least,
            self.uploads(requests).filter_map(Upload::timer).min(),
            "an exact floor is the least upload timer"
        );
        let upload = |slot: u32| {
            requests
                .table()
                .live_id(slot)
                .and_then(|id| requests.upload(id))
        };
        let due = self
            .marked
            .any(|slot| upload(slot).is_some_and(|upload| upload.due))
            || self.data.any(|slot| {
                upload(slot).is_some_and(|upload| {
                    upload.takes_data()
                        && self
                            .due_from(upload)
                            .is_some_and(|index| index < upload.grant)
                })
            });
        (due, least)
    }
}

/// The first due slot on a chain from `from`, following each slot's `next`.
fn first_due(slots: &[SourceSlot<'_>], from: Option<u32>) -> Option<u32> {
    let mut at = from;
    while let Some(here) = at {
        if slots[here as usize].due {
            return Some(here);
        }
        at = slots[here as usize].next;
    }
    None
}
