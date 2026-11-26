//! Request slots: generation-checked request identities over a fixed record array, with a conserved active-plus-draining census per peer and in total.
//!
//! Invariants owned by this module:
//!
//! - A [`RequestId`] is a 16-bit slot and a 48-bit generation. A slot's generation advances by one each time its request is released, and a slot whose generation has reached [`GENERATION_LIMIT`] retires for good, so no handle of a released request ever names its successor.
//! - Each live request is active or draining, and counts against its peer's share and the table's total. After every call, for every peer, `active + draining <= peer_cap`, and the sum over peers of `active + draining` equals the live records.
//! - A request is admitted only when its peer and the table both have room; a refusal names the share that turned it away, the peer's or the table's, and returns the state it was given. Draining requests keep their slot and their share until released, so a peer cannot free share by ending its work logically while custody is still held.
//! - Each retired slot permanently reduces shared request capacity, the owner's GET headroom included, by one. Table pressure occurs when every slot is live or retired; [`RequestCensus::retired`] counts retired slots.
//! - The table allocates its records, its free list and its census once, charged by its creator, and allocates nothing after.

use crate::records::Records;

use super::datagram::PeerId;

/// The largest generation a request slot reaches before it retires.
pub const GENERATION_LIMIT: u64 = (1 << 48) - 1;

/// The most request slots a table holds: every 16-bit slot.
pub const MAX_REQUEST_SLOTS: u32 = 1 << 16;

/// A request's identity: its slot in the issuing table and the generation that slot had when the request was admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId {
    slot: u16,
    generation: u64,
}

impl RequestId {
    /// The identity a wire request ID carries: the slot in the high 16 bits and the generation in the low 48.
    pub fn from_wire(wire: u64) -> Self {
        Self {
            slot: (wire >> 48) as u16,
            generation: wire & GENERATION_LIMIT,
        }
    }

    pub fn wire(self) -> u64 {
        u64::from(self.slot) << 48 | self.generation
    }

    pub fn slot(self) -> u16 {
        self.slot
    }

    pub fn generation(self) -> u64 {
        self.generation
    }
}

/// Which share was full when a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestPressure {
    /// The peer's active and draining requests already hold its whole share, or the peer is outside the table.
    Peer,
    /// Every slot is live or retired.
    Table,
}

/// One peer's live requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerCensus {
    pub active: u32,
    pub draining: u32,
}

/// The table's live requests by phase, and its retired slots.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestCensus {
    pub active: u32,
    pub draining: u32,
    /// Slots whose generation is exhausted; they never hold a request again.
    pub retired: u32,
}

/// Live requests and the draining ones among them; `active` is `live - draining`.
#[derive(Clone, Copy, Default)]
#[cfg_attr(test, derive(Debug))]
struct Counts {
    live: u32,
    draining: u32,
}

impl Counts {
    fn census(self) -> PeerCensus {
        PeerCensus {
            active: self.live - self.draining,
            draining: self.draining,
        }
    }
}

impl RequestCensus {
    /// Requests that are active or draining.
    pub fn live(&self) -> u32 {
        self.active + self.draining
    }
}

#[cfg_attr(test, derive(Clone, Debug))]
struct Entry<T> {
    peer: u16,
    draining: bool,
    state: T,
}

/// A fixed table of request slots shared by a fixed set of peers.
#[cfg_attr(test, derive(Clone, Debug))]
pub struct RequestTable<T> {
    records: Records<Entry<T>>,
    peers: Box<[Counts]>,
    peer_cap: u32,
    /// Draining requests across every peer.
    draining: u32,
}

impl<T> RequestTable<T> {
    /// Bytes a table of `slots` slots over `peers` peers allocates, or `None` when they overflow `usize`.
    pub fn metadata_bytes(slots: u32, peers: u16) -> Option<usize> {
        let records = (slots as usize).checked_mul(Records::<Entry<T>>::entry_bytes())?;
        records.checked_add(usize::from(peers) * size_of::<Counts>())
    }

    /// A table of `slots` slots, at most [`MAX_REQUEST_SLOTS`], each peer's live requests capped at `peer_cap`.
    /// Its caller charges [`metadata_bytes`](Self::metadata_bytes) first.
    pub(super) fn new(slots: u32, peers: u16, peer_cap: u32) -> Self {
        Self::with_generation_limit(slots, peers, peer_cap, GENERATION_LIMIT)
    }

    /// Starts free slot `slot` at `generation`, so a test reaches the table's generation limit at its actual width.
    #[cfg(test)]
    pub(super) fn start_slot_at(&mut self, slot: u16, generation: u64) {
        self.records.start_slot_at(u32::from(slot), generation);
    }

    /// [`new`](Self::new) with each slot retiring once its generation would pass `limit`.
    pub(super) fn with_generation_limit(slots: u32, peers: u16, peer_cap: u32, limit: u64) -> Self {
        debug_assert!(slots <= MAX_REQUEST_SLOTS);
        Self {
            records: Records::with_generation_limit(slots, limit),
            peers: vec![Counts::default(); usize::from(peers)].into_boxed_slice(),
            peer_cap,
            draining: 0,
        }
    }

    /// Admits an active request for `peer` holding `state`.
    ///
    /// # Errors
    ///
    /// `Peer` when the peer's share is full, or `peer` is none of the table's peers and so has no share; else `Table` when no slot is free.
    /// Each returns `state` and changes nothing.
    #[inline]
    pub fn admit(&mut self, peer: PeerId, state: T) -> Result<RequestId, (RequestPressure, T)> {
        // Checking capacity before building the entry returns `state` on table pressure untouched and guarantees `insert` a free slot.
        if let Err(pressure) = self.room(peer) {
            return Err((pressure, state));
        }
        let entry = Entry {
            peer: peer.0,
            draining: false,
            state,
        };
        let Ok((slot, generation)) = self.records.insert(entry) else {
            unreachable!("a free slot takes the entry")
        };
        debug_assert!(
            generation <= GENERATION_LIMIT,
            "a generation fits the wire's 48 bits"
        );
        self.peers[usize::from(peer.0)].live += 1;
        Ok(RequestId {
            slot: slot as u16,
            generation,
        })
    }

    pub fn room(&self, peer: PeerId) -> Result<(), RequestPressure> {
        let counts = self
            .peers
            .get(usize::from(peer.0))
            .ok_or(RequestPressure::Peer)?;
        if counts.live >= self.peer_cap {
            return Err(RequestPressure::Peer);
        }
        if !self.records.has_free() {
            return Err(RequestPressure::Table);
        }
        Ok(())
    }

    #[inline]
    pub fn get(&self, id: RequestId) -> Option<&T> {
        let entry = self.records.get(u32::from(id.slot), id.generation)?;
        Some(&entry.state)
    }

    #[inline]
    pub fn get_mut(&mut self, id: RequestId) -> Option<&mut T> {
        let entry = self.records.get_mut(u32::from(id.slot), id.generation)?;
        Some(&mut entry.state)
    }

    /// The peer a live request belongs to.
    #[inline]
    pub fn peer(&self, id: RequestId) -> Option<PeerId> {
        let entry = self.records.get(u32::from(id.slot), id.generation)?;
        Some(PeerId(entry.peer))
    }

    /// Whether `id` names a live request that [`begin_drain`](Self::begin_drain) moved to draining.
    #[inline]
    pub fn draining(&self, id: RequestId) -> bool {
        self.records
            .get(u32::from(id.slot), id.generation)
            .is_some_and(|entry| entry.draining)
    }

    /// Moves a live active request to draining: its logical work ended and it keeps its slot and share until [`release`](Self::release).
    /// Returns whether the request was active.
    #[inline]
    pub fn begin_drain(&mut self, id: RequestId) -> bool {
        let Some(entry) = self.records.get_mut(u32::from(id.slot), id.generation) else {
            return false;
        };
        if entry.draining {
            return false;
        }
        entry.draining = true;
        self.peers[usize::from(entry.peer)].draining += 1;
        self.draining += 1;
        true
    }

    /// Releases a live request, active or draining, returning its state; its slot's generation advances, or the slot retires once the generation is exhausted.
    pub fn release(&mut self, id: RequestId) -> Option<T> {
        let entry = self.records.take(u32::from(id.slot), id.generation)?;
        self.settle(entry.peer, entry.draining);
        Some(entry.state)
    }

    /// Releases a live request as [`release`](Self::release) does, dropping its state in place, and returns its peer.
    #[inline]
    pub fn discard(&mut self, id: RequestId) -> Option<PeerId> {
        self.discard_with(id, |_| ()).map(|(peer, ())| peer)
    }

    /// Reads a live request's state through `read`, then releases it as [`discard`](Self::discard) does, returning its peer with what `read` returned.
    #[inline]
    pub fn discard_with<R>(
        &mut self,
        id: RequestId,
        read: impl FnOnce(&T) -> R,
    ) -> Option<(PeerId, R)> {
        let (peer, draining, read) =
            self.records
                .drop_with(u32::from(id.slot), id.generation, |entry| {
                    (entry.peer, entry.draining, read(&entry.state))
                })?;
        self.settle(peer, draining);
        Some((PeerId(peer), read))
    }

    #[inline]
    fn settle(&mut self, peer: u16, draining: bool) {
        let counts = &mut self.peers[usize::from(peer)];
        counts.live -= 1;
        if draining {
            counts.draining -= 1;
            self.draining -= 1;
        }
    }

    /// The handle of the live request in table slot `slot`, for a scan over every slot below [`high_water`](Self::high_water).
    #[inline]
    pub fn live_id(&self, slot: u32) -> Option<RequestId> {
        let generation = self.records.generation_of(slot)?;
        Some(RequestId {
            slot: slot as u16,
            generation,
        })
    }

    /// The live request in table slot `slot` with its handle, for a scan that acts on what it visits.
    #[inline]
    pub fn live_mut(&mut self, slot: u32) -> Option<(RequestId, &mut T)> {
        let (generation, entry) = self.records.slot_mut(slot)?;
        let id = RequestId {
            slot: slot as u16,
            generation,
        };
        Some((id, &mut entry.state))
    }

    /// The peer's live requests; empty for a peer outside the table.
    pub fn peer_census(&self, peer: PeerId) -> PeerCensus {
        self.peers
            .get(usize::from(peer.0))
            .map_or_else(PeerCensus::default, |counts| counts.census())
    }

    pub fn census(&self) -> RequestCensus {
        RequestCensus {
            active: self.records.live() - self.draining,
            draining: self.draining,
            retired: self.records.retired(),
        }
    }

    pub fn slots(&self) -> u32 {
        self.records.len()
    }

    /// Peers the table holds shares for.
    pub fn peers(&self) -> u16 {
        self.peers.len() as u16
    }

    /// The most live requests one peer holds.
    pub fn peer_cap(&self) -> u32 {
        self.peer_cap
    }

    /// One past the highest slot that has held a request: every live request lies below it, so a scan over them stops here.
    pub fn high_water(&self) -> u32 {
        self.records.high_water()
    }
}
