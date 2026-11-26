//! Client request admission and wire routing for every operation the client runs.
//!
//! - Every operation draws wire generations from the one release-board counter.
//!   The counter advances only after table admission succeeds, so a refusal
//!   leaves the counter, the table, its census and the wire slots unchanged, and
//!   a slot reused by any operation carries a higher generation.
//! - Routing returns a request only when its peer, full wire ID and operation
//!   all match the frame, so a delayed frame of a released request, or a frame of
//!   another operation, reaches no request.
//! - Release and destruction close the request's slot on the board. Leases the
//!   application still holds from that request count as orphans until dropped.
//! - Construction charges and allocates the wire slots and takes the board.
//!   Destruction returns the board for a successor namespace.

use crate::storage::EngineBudget;

use super::datagram::PeerId;
use super::fetch::{Fetch, FetchCoreError, Releases};
use super::namespace::{Operated, Operation};
use super::requests::{RequestId, RequestPressure, RequestTable};
use super::upload::Upload;

/// What the namespace reads from each record it routes and closes.
pub trait ClientRecord: Operated {
    fn peer(&self) -> PeerId;
    /// The wire ID this request's frames carry, fixed at admission.
    fn wire(&self) -> u64;
    /// Fragment leases handed to the application, which the board counts against its releases at close.
    fn handed(&self) -> u32;
}

/// Why the namespace refused to admit a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityPressure {
    /// The peer's busy wire slots reach the session's slot cap, or the table refused.
    Requests(RequestPressure),
    /// The board issued its last wire generation.
    Generations,
}

/// One endpoint's requests of every operation, with their wire identities and their release-board slots.
pub struct ClientNamespace<'p, R: ClientRecord> {
    table: RequestTable<R>,
    wires: Wires,
    releases: &'p Releases,
    /// One bit per [`Operation`] whose transfer core runs over this namespace.
    cores: u8,
}

impl<'p, R: ClientRecord> ClientNamespace<'p, R> {
    /// Bytes construction charges beyond the table, or `None` when they overflow `usize`.
    pub fn charge(table: &RequestTable<R>) -> Option<usize> {
        Wires::charge(table.peers(), Wires::width(table))
    }

    /// A namespace over the empty `table` and the board `releases`, charging [`charge`](Self::charge) bytes.
    ///
    /// # Errors
    ///
    /// `BoardInUse` when another live namespace holds `releases`, `Board` when it numbers fewer slots than `table`, or `Budget`; `budget` is unchanged on every error.
    pub fn new(
        table: RequestTable<R>,
        releases: &'p Releases,
        budget: &mut EngineBudget,
    ) -> Result<Self, FetchCoreError> {
        debug_assert_eq!(table.census().live(), 0, "a namespace starts empty");
        releases.check(table.slots())?;
        budget
            .charge(Self::charge(&table).unwrap_or(usize::MAX))
            .map_err(FetchCoreError::Budget)?;
        releases.attach();
        let wires = Wires::new(table.peers(), Wires::width(&table));
        Ok(Self {
            table,
            wires,
            releases,
            cores: 0,
        })
    }

    pub fn table(&self) -> &RequestTable<R> {
        &self.table
    }

    pub(super) fn releases(&self) -> &'p Releases {
        self.releases
    }

    pub(super) fn serves(&self, operation: Operation) -> bool {
        self.cores & 1 << operation as u8 != 0
    }

    pub(super) fn serve(&mut self, operation: Operation) {
        self.cores |= 1 << operation as u8;
    }

    /// Admits the request `build` makes from its wire ID, on the lowest free wire slot of `peer` below `cap`.
    ///
    /// # Errors
    ///
    /// `Generations` once the board issued its last generation; `Requests(Peer)` when `peer`'s live requests hold every wire slot below `cap`; or the table's pressure. Every refusal leaves the generation counter, table, census and wire slots unchanged.
    #[inline]
    pub fn admit(
        &mut self,
        peer: PeerId,
        cap: u32,
        build: impl FnOnce(u64) -> R,
    ) -> Result<RequestId, IdentityPressure> {
        let generation = self
            .releases
            .next_generation()
            .ok_or(IdentityPressure::Generations)?;
        let slot = self
            .wires
            .free(peer, cap)
            .ok_or(IdentityPressure::Requests(RequestPressure::Peer))?;
        let wire = u64::from(slot) << 48 | generation;
        let record = build(wire);
        debug_assert!(record.peer() == peer && record.wire() == wire);
        let id = self
            .table
            .admit(peer, record)
            .map_err(|(pressure, _)| IdentityPressure::Requests(pressure))?;
        self.releases.issue(generation, id);
        self.wires.hold(peer, slot, id.slot());
        Ok(id)
    }

    /// The live `operation` request of `peer` whose wire ID is `wire`.
    pub fn route(&self, peer: PeerId, wire: u64, operation: Operation) -> Option<RequestId> {
        let table_slot = self.wires.route(peer, RequestId::from_wire(wire).slot())?;
        let id = self.table.live_id(u32::from(table_slot))?;
        let record = self.table.get(id)?;
        (record.peer() == peer && record.wire() == wire && record.operation() == operation)
            .then_some(id)
    }

    /// Releases request `id`, dropping its record in place, freeing its wire slot and closing its board slot. Returns whether `id` named a live request.
    #[inline]
    pub(super) fn release(&mut self, id: RequestId) -> bool {
        let Some((peer, (slot, handed))) = self.table.discard_with(id, |record| {
            (RequestId::from_wire(record.wire()).slot(), record.handed())
        }) else {
            return false;
        };
        self.wires.release(peer, slot);
        self.releases.close(id, handed);
        true
    }
}

impl<R: ClientRecord> Drop for ClientNamespace<'_, R> {
    fn drop(&mut self) {
        for slot in 0..self.table.high_water() {
            if let Some(id) = self.table.live_id(slot)
                && let Some(record) = self.table.get(id)
            {
                self.releases.close(id, record.handed());
            }
        }
        self.releases.detach();
    }
}

/// Each request the client runs, by operation.
pub enum ClientRequest {
    Get(Fetch),
    Put(Upload),
}

impl Operated for ClientRequest {
    fn operation(&self) -> Operation {
        match self {
            Self::Get(_) => Operation::Get,
            Self::Put(_) => Operation::Put,
        }
    }
}

impl ClientRecord for ClientRequest {
    fn peer(&self) -> PeerId {
        match self {
            Self::Get(fetch) => fetch.peer(),
            Self::Put(upload) => upload.peer(),
        }
    }

    fn wire(&self) -> u64 {
        match self {
            Self::Get(fetch) => fetch.wire(),
            Self::Put(upload) => upload.wire(),
        }
    }

    fn handed(&self) -> u32 {
        match self {
            Self::Get(fetch) => fetch.handed(),
            Self::Put(_) => 0,
        }
    }
}

/// The client's request namespace.
pub type ClientRequests<'p> = ClientNamespace<'p, ClientRequest>;

impl ClientRequests<'_> {
    pub(super) fn fetch(&self, id: RequestId) -> Option<&Fetch> {
        match self.table.get(id)? {
            ClientRequest::Get(fetch) => Some(fetch),
            ClientRequest::Put(_) => None,
        }
    }

    pub(super) fn fetch_mut(&mut self, id: RequestId) -> Option<&mut Fetch> {
        match self.table.get_mut(id)? {
            ClientRequest::Get(fetch) => Some(fetch),
            ClientRequest::Put(_) => None,
        }
    }

    pub(super) fn live_fetch_mut(&mut self, slot: u32) -> Option<(RequestId, &mut Fetch)> {
        match self.table.live_mut(slot)? {
            (id, ClientRequest::Get(fetch)) => Some((id, fetch)),
            (_, ClientRequest::Put(_)) => None,
        }
    }

    pub(super) fn upload(&self, id: RequestId) -> Option<&Upload> {
        match self.table.get(id)? {
            ClientRequest::Put(upload) => Some(upload),
            ClientRequest::Get(_) => None,
        }
    }

    pub(super) fn upload_mut(&mut self, id: RequestId) -> Option<&mut Upload> {
        match self.table.get_mut(id)? {
            ClientRequest::Put(upload) => Some(upload),
            ClientRequest::Get(_) => None,
        }
    }

    /// The live upload in table slot `slot` with its handle, for a scan over the upload core's live list.
    pub(super) fn live_upload_mut(&mut self, slot: u32) -> Option<(RequestId, &mut Upload)> {
        match self.table.live_mut(slot)? {
            (id, ClientRequest::Put(upload)) => Some((id, upload)),
            (_, ClientRequest::Get(_)) => None,
        }
    }

    /// The live upload of `peer` whose wire ID is `wire`, as [`route`](Self::route) selects it, read once.
    pub(super) fn route_upload_mut(
        &mut self,
        peer: PeerId,
        wire: u64,
    ) -> Option<(RequestId, &mut Upload)> {
        let table_slot = self.wires.route(peer, RequestId::from_wire(wire).slot())?;
        match self.table.live_mut(u32::from(table_slot))? {
            (id, ClientRequest::Put(upload)) if upload.peer() == peer && upload.wire() == wire => {
                Some((id, upload))
            }
            _ => None,
        }
    }
}

/// Each peer's wire slots: which live requests hold them, and the table slot each one last routed to.
struct Wires {
    /// Wire slots per peer.
    width: u32,
    /// Words of `busy` per peer: `width.div_ceil(64)`.
    words: usize,
    /// `routes[peer * width + slot]` is the table slot of the request that last held wire slot `slot` of `peer`, or 0 before any request held it.
    routes: Box<[u16]>,
    /// The wire slots live requests hold, one bit each. Each peer occupies `words` words starting at word `peer * words`.
    busy: Box<[u64]>,
}

impl Wires {
    /// Wire slots per peer: as many as one peer's live requests can hold.
    fn width<R>(table: &RequestTable<R>) -> u32 {
        table.peer_cap().min(table.slots())
    }

    fn charge(peers: u16, width: u32) -> Option<usize> {
        usize::from(peers).checked_mul(
            width as usize * size_of::<u16>() + width.div_ceil(64) as usize * size_of::<u64>(),
        )
    }

    fn new(peers: u16, width: u32) -> Self {
        let peers = usize::from(peers);
        let words = width.div_ceil(64) as usize;
        Self {
            width,
            words,
            routes: vec![0; peers * width as usize].into_boxed_slice(),
            busy: vec![0; peers * words].into_boxed_slice(),
        }
    }

    /// The lowest wire slot of `peer` below `cap` that no live request holds; `None` for a peer outside the table.
    fn free(&self, peer: PeerId, cap: u32) -> Option<u16> {
        let row = usize::from(peer.0) * self.words;
        let limit = self.width.min(cap);
        let mut first = 0;
        while first < limit {
            let word = *self.busy.get(row + first as usize / 64)?;
            if word != u64::MAX {
                let slot = first + (!word).trailing_zeros();
                return (slot < limit).then_some(slot as u16);
            }
            first += 64;
        }
        None
    }

    fn hold(&mut self, peer: PeerId, slot: u16, table: u16) {
        let at = usize::from(peer.0) * self.words + usize::from(slot) / 64;
        self.busy[at] |= 1 << (slot % 64);
        self.routes[usize::from(peer.0) * self.width as usize + usize::from(slot)] = table;
    }

    fn release(&mut self, peer: PeerId, slot: u16) {
        let at = usize::from(peer.0) * self.words + usize::from(slot) / 64;
        self.busy[at] &= !(1 << (slot % 64));
    }

    /// The table slot that last held wire slot `slot` of `peer`. A `slot` at or past `width` indexes a later peer's row, and a never-held slot reads 0; [`route`](ClientNamespace::route) accepts the routed request only when its peer, wire ID and operation equal the frame's, so neither reaches another request.
    fn route(&self, peer: PeerId, slot: u16) -> Option<u16> {
        self.routes
            .get(usize::from(peer.0) * self.width as usize + usize::from(slot))
            .copied()
    }
}
