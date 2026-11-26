//! The client endpoint: one owner, one authenticated session, bounded GETs that hand the application ordered fragment leases and one explicit outcome, polled on the caller's thread, where a call waits only for the shared [`ShardRoutes`] lock, held for one route merge, read or count.
//!
//! Invariants owned by this module:
//!
//! - BOUNDED: [`initialize`](Client::initialize) charges every key, session, request and upload structure once; [`poll`](Client::poll) handles at most one receive batch and stages at most `batch` request frames, which leave in at most `batch` datagrams, and steady-state get, put, poll, cancel and release allocate nothing.
//! - Every received datagram is parsed with its truncation flag and authenticated under the owner's key. Every frame but an ownership frame is admitted by the session table before any request state reads it. A response frame is then admitted by the shared shard route, which raises the shard's high-water to the session's tenure and admits the frame only while the route is Bound to that tenure; once it refuses, the poll ends the session's GETs with `SessionMismatch` and its uploads, and requests on the session are refused with `Unrouted` until a later poll finds the route Bound to the session's tenure or a READY activates another session. Ownership frames (Holder, WrongOwner, Heartbeat and ProbeReply) merge into the shard routes on authentication alone, and a repeated one merges to the route it already produced; one withdraws a binding only as a WrongOwner of the active session, admitted above every sequence that session admitted and naming its tenure, while that session made the route's latest binding admission (`ShardRoutes::reply`). A receive batch authenticates its parsed datagrams two at a time, in order, each with the verdict it gets alone.
//! - The session opens through HELLO, CHALLENGE, CONFIRM and READY. The client resends its bootstrap frame after `bootstrap_retry_us`, at most `bootstrap_attempts` times per opening or accepted CHALLENGE, so an absent owner ends the opening with [`SessionState::Failed`]; a CHALLENGE that still arrives reopens it. A resend repeats the pending handshake's CONFIRM up to [`CONFIRM_REPEATS`](super::CONFIRM_REPEATS) times and then sends a fresh HELLO, so an opening whose CONFIRM keeps mismatching restarts the handshake when `bootstrap_attempts` exceeds that bound. A GET needs the active session, and replacing a session, or spending its send sequence, ends its GETs with `SessionMismatch` and its PUTs `Unknown`, or `NotStarted` when no send call reached any of their frames.
//! - [`initialize`](Client::initialize) accepts only caps the wire can carry and a receive pool whose buffers' data room holds a complete protocol datagram, so every opening can encode its HELLO and every DATA frame can arrive whole, and whose configured control reserve holds the device ring's posted buffers plus one batch, so at initialization the data buffers that grants count and the buffers the ring and one batch hold are separate buffers. A retirement after initialization lowers the pool's data cap by one, and data leases live at that moment may exceed the cap, which leaves the reserve short by the excess until they drain ([`PacketPoolReport::reserve_shortfall`](super::PacketPoolReport::reserve_shortfall)).
//! - The caller's thread owns the client and runs it to completion: it calls [`poll`](Client::poll) in its own loop, and [`next_deadline_us`](Client::next_deadline_us) names the earliest retry, expiry or bootstrap deadline, or 0 while a frame is due and the transport takes sends; a refused send is due again one retry interval later, so every due frame has a finite deadline.
//! - Fragment leases borrow the caller's receive pool and release board, which outlive the client, so a lease stays valid after poll, timeout, cancel and close until the application drops it.

use std::collections::VecDeque;
use std::ops::Range;
use std::sync::Arc;

use crate::storage::{CacheVersion, Crc32c, EngineBudget, EngineBudgetExceeded, SourceRange};

use super::auth::{
    Authenticated, EntropyError, KeyEntry, KeyError, KeyRing, TAG_LEN, nonce_from, os_entropy,
};
use super::client_namespace::{ClientRequest, ClientRequests};
use super::datagram::{
    DatagramError, Datagrams, HEADER_LEN, MAX_DATAGRAM, MAX_PACKED_GETS, Outgoing, Payload, PeerId,
    Received,
};
use super::fetch::{
    Asked, FetchConfig, FetchCore, FetchCoreError, FetchLimits, FetchPressure, FetchReport,
    FragmentLease, Outcome, Releases, Terminal, Wanted,
};
use super::frame::{
    Direction, Frame, Header, Kind, MAX_SLOT_CAP, MAX_WINDOW, Status, encode, encode_with_body_crc,
    mac_input_for, parse, seal,
};
use super::ownership::{OwnershipBody, Shard};
use super::packet::{PacketLease, PacketPool};
use super::requests::{RequestId, RequestTable};
use super::serve::header;
use super::session::{Admitted, Bootstrap, Caps, Role, Sessions};
use super::upload::{
    PrepareRefused, SourceSlot, SupplyRefused, UploadConfig, UploadCore, UploadOutcome,
};
use route::{Binder, Receiver, ShardRoutes};

#[cfg(test)]
thread_local! {
    /// Planted: every WrongOwner counts as the active session's newest frame, whatever session and sequence it
    /// names.
    pub(super) static UNORDERED_WITHDRAWALS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Planted: a session sends and admits responses whatever tenure its shard route is Bound to.
    pub(super) static NO_ROUTE_CHECK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
mod early_retire;
pub mod route;

/// The owner, the client's only peer.
const OWNER: PeerId = PeerId(0);

/// INVALIDATED acknowledgments the client keeps until [`Client::take_invalidated`] takes them; a full inbox drops the next one.
const INVALIDATED_INBOX: usize = 64;

/// Request datagrams one transport call carries at most.
const SEND_CHUNK: usize = 8;

/// A client's identity, caps and timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientConfig {
    /// The owner endpoint's identifier, which every tag's domain names.
    pub endpoint: u32,
    /// The principal this client authenticates as.
    pub principal: u32,
    /// This end's request-slot and window caps, met against the owner's at bootstrap.
    pub caps: Caps,
    pub fetch: FetchConfig,
    pub upload: UploadConfig,
    /// Microseconds between bootstrap resends.
    pub bootstrap_retry_us: u64,
    /// Bootstrap resends per opening or accepted CHALLENGE before the opening fails. The first [`CONFIRM_REPEATS`](super::CONFIRM_REPEATS) resends after a CHALLENGE repeat its CONFIRM and later ones send a fresh HELLO, so a restart needs a limit above that bound.
    pub bootstrap_attempts: u32,
    /// Datagrams one poll receives at most, and request frames one poll stages at most; the staged frames leave in at
    /// most `batch` datagrams.
    pub batch: u32,
}

/// The memory a client borrows or takes: the receive pool and release board outlive it, and the request table moves into it.
pub struct ClientMemory<'m> {
    pub receive: &'m PacketPool<'m>,
    pub releases: &'m Releases,
    pub requests: RequestTable<ClientRequest>,
    pub sources: Box<[SourceSlot<'m>]>,
    /// The shard routes every client of the application shares, so all their sessions raise one high-water per shard.
    pub routes: Arc<ShardRoutes>,
}

/// Why a client could not be initialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientError {
    Entropy(EntropyError),
    Keys(KeyError),
    Fetch(FetchCoreError),
    Budget(EngineBudgetExceeded),
    /// The batch is zero.
    Batch,
    /// A session cap lies outside the wire's range: slots in `1..=MAX_SLOT_CAP`, window in `1..=MAX_WINDOW`.
    Caps,
    /// The receive pool holds fewer data buffers than the fetch core promises, a control reserve smaller than the device ring plus one batch, or a data room shorter than a complete protocol datagram.
    Pool,
}

/// Where the client's session stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// No session was asked for.
    Idle,
    /// A handshake is under way; an active session, if any, still serves GETs while the shard route admits it.
    Opening,
    Active,
    /// The last opening spent its resends, or the session table refused its HELLO or a resend; an active session, if any, still serves GETs while the shard route admits it, and a late CHALLENGE reopens the handshake.
    Failed,
}

/// Why a GET was refused before it started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetRefused {
    /// No session is active.
    NoSession,
    /// The receive buffers the GET's window needs are reserved by other requests or held leases.
    ReceivePressure,
    /// Every request slot, this peer's share of them, or every wire slot below the session's slot cap is live, or the release board issued its last wire generation.
    ///
    /// GETs and uploads share this client's request slots and session slot cap, so the client's live uploads can fill its request slots, causing its GET to fail locally until an upload retires.
    ///
    /// [`OwnerConfig::get_reserve`](super::owner::OwnerConfig::get_reserve) reserves slots in the owner's request table for GETs. This client's uploads and GETs both admit into every slot below the session's slot cap, so the application bounds its concurrent uploads to keep slots free for its GETs.
    RequestPressure,
    /// The active session's tenure is not the shard route's Bound tenure: the route is a Candidate, Conflict
    /// or Dark, is Bound to another tenure, or the shard routes hold no route for the shard.
    Unrouted,
}

/// GETs refused at admission, by [`GetRefused`] cause.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdmissionRefusals {
    pub no_session: u64,
    pub receive_pressure: u64,
    pub request_pressure: u64,
    pub unrouted: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutRefused {
    NoSession,
    RequestPressure,
    /// The client rejects an INVALIDATE whose `low` exceeds its `high`, including retries with the same interval.
    Interval,
    /// As [`GetRefused::Unrouted`].
    Unrouted,
}

/// What one poll did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PollReport {
    pub received: u32,
    /// Datagrams the transport took, a packed datagram once.
    pub sent: u32,
    /// Datagrams dropped as from another peer, truncated, unparseable, unauthenticated, of an unexpected kind, failing the body crc, refused by the session table, the upload core or the shard route, or ownership frames for a shard the full route table does not hold; and frames left unsent because their session ended or its send sequence ran out.
    pub dropped: u32,
    /// Of `dropped`, frames the shard routes refused: response frames on a session whose tenure the route does not admit, and ownership frames for a shard the full table does not hold.
    pub unrouted: u32,
    /// The transport refused a send, which stays due for the next poll.
    pub blocked: bool,
    /// The transport failed the receive or a send, or a frame failed to encode or tag; the error number of the last failure, when it had one.
    pub failed: Option<Option<i32>>,
    /// GETs this poll decided, whose terminal observations [`Client::terminal`] then gives. A GET that
    /// [`Client::cancel`] or [`Client::close`] ends counts in the fetch report's outcomes alone.
    /// The close consumes the client with that report, so callers read [`Client::fetch_report`] before closing.
    pub decided: u32,
}

/// A client endpoint over transport `D`, borrowing its receive pool and release board for `'m`.
pub struct Client<'m, D> {
    config: ClientConfig,
    crc: Crc32c,
    transport: D,
    ring: KeyRing,
    sessions: Sessions,
    requests: ClientRequests<'m>,
    fetch: FetchCore<'m>,
    refused: AdmissionRefusals,
    upload: UploadCore<'m>,
    receive: &'m PacketPool<'m>,
    routes: Arc<ShardRoutes>,
    /// The shard the last activating READY bound, `None` before the first one; read only beside the active session's
    /// tenure.
    shard: Option<Shard>,
    /// The index of `shard`'s slot in the shard routes, at which `routable` reads the tenure the route publishes. The READY that binds `shard` stores it; it is `None` before the first such READY and for a shard the full route table does not hold. The full table gives that shard no route, so `routable` returns false while this is `None`.
    route_slot: Option<usize>,
    /// Set when the poll ends the active session's GETs and uploads because the shard route stopped admitting its
    /// tenure. The READY that activates the next session clears it, and so does a later poll that finds the route bound
    /// to the session's tenure again.
    withheld: bool,
    /// The first wire generation of the active session. The release board issues generations in order across sessions, so every request admitted under the active session carries one at or above it and every request of an earlier session one below it; owner epochs repeat across owner boots and cannot tell the two apart.
    session_wires: u64,
    /// Receive slots for one batch, empty between polls.
    scratch: Box<[Option<PacketLease<'m>>]>,
    meta: Box<[Received]>,
    /// The encoded and tagged request frames of one send batch, `batch` of them kept between polls.
    frames: Box<[[u8; HEADER_LEN]]>,
    /// What each frame staged in `frames` asks, in order, kept between polls at its full capacity.
    asked: Vec<Asked>,
    staged: Vec<Staged>,
    state: SessionState,
    /// The bootstrap frame waiting to be sent.
    bootstrap: Option<Bootstrap>,
    bootstrap_due_us: u64,
    /// Bootstrap frames sent or lost since the latest opening or accepted CHALLENGE, the first included; 64 bits wide, so it passes any `u32` resend budget without wrapping.
    bootstrap_sent: u64,
    /// When a frame the transport refused this turn is retried at the latest:
    /// one bootstrap retry out for a HELLO or CONFIRM, one fetch retry out
    /// for a GET frame, one upload retry out for a PUT frame, and the lesser
    /// of the two when the refused range holds both. A turn whose PUT DATA
    /// frames failed to seal and whose sealed frames the transport took sets
    /// one upload retry out.
    /// The deadline bounds the caller's sleep after a refusal.
    refused_retry_us: Option<u64>,
    /// Whether the upload core takes the next contested lone send: a poll with one send left after any bootstrap frame while both the fetch and upload cores may have a frame due. Each contested poll flips it, so the two cores take those sends in turn.
    lone_send_to_upload: bool,
    /// The request field of the last INVALIDATE sent.
    invalidate_request: u64,
    /// The client retains up to [`INVALIDATED_INBOX`] INVALIDATED acknowledgments until [`Client::take_invalidated`] consumes them.
    invalidated: VecDeque<Invalidated>,
}

/// An INVALIDATED the owner sent: the key and the inclusive version interval of the INVALIDATE it acknowledges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invalidated {
    pub request: u64,
    pub key: [u8; 32],
    pub low: u64,
    pub high: u64,
}

impl<'m, D: Datagrams<'m>> Client<'m, D> {
    /// Initializes a client over `transport` with `keys` at `key_epoch`, drawing a boot nonce and charging its keys, sessions and request structures to `budget`. The send scratch it charges holds `batch` staged frames. The caller supplies a `transport` whose sends carry a header of up to [`MAX_PACKED_GETS`] frames of [`HEADER_LEN`] bytes whole; the checks below cover the receive pool and leave that header length to the caller.
    ///
    /// # Errors
    ///
    /// `Batch` for a zero batch, `Caps` for a session cap outside the wire's range, `Pool` for a receive pool whose data cap is below `fetch.boxes`, whose control reserve is below the transport's [`rx_ring`](Datagrams::rx_ring) plus `batch`, or whose data room is shorter than [`MAX_DATAGRAM`], `Entropy` when no boot nonce is available, `Keys` for a refused key set, `Fetch` when the request structures are refused, or `Budget`; `budget` is unchanged on every error.
    pub fn initialize(
        config: ClientConfig,
        memory: ClientMemory<'m>,
        transport: D,
        keys: &[KeyEntry<'_>],
        key_epoch: u32,
        budget: &mut EngineBudget,
    ) -> Result<Self, ClientError> {
        Self::initialize_with_nonce(
            config, memory, transport, keys, key_epoch, budget, os_entropy,
        )
    }

    /// [`initialize`](Self::initialize) with the boot nonce filled by
    /// `nonce` where `initialize` reads the operating system's entropy:
    /// `nonce` runs only after the `Batch`, `Caps` and `Pool` checks pass
    /// and before the keys load.
    ///
    /// # Errors
    ///
    /// As [`initialize`](Self::initialize).
    pub(super) fn initialize_with_nonce(
        config: ClientConfig,
        memory: ClientMemory<'m>,
        transport: D,
        keys: &[KeyEntry<'_>],
        key_epoch: u32,
        budget: &mut EngineBudget,
        nonce: impl FnOnce(&mut [u8; 16]) -> Result<(), EntropyError>,
    ) -> Result<Self, ClientError> {
        if config.batch == 0 {
            return Err(ClientError::Batch);
        }
        if !(1..=MAX_SLOT_CAP).contains(&config.caps.slots)
            || !(1..=MAX_WINDOW).contains(&config.caps.window)
        {
            return Err(ClientError::Caps);
        }
        let pool = memory.receive.report();
        if memory.receive.data_cap() < config.fetch.boxes
            || u64::from(memory.receive.control_reserve())
                < u64::from(transport.rx_ring()) + u64::from(config.batch)
            || (pool.data_room as usize) < MAX_DATAGRAM
        {
            return Err(ClientError::Pool);
        }
        let nonce = nonce_from(nonce).map_err(ClientError::Entropy)?;
        let mut staged = *budget;
        let ring = KeyRing::load(&[config.principal], keys, key_epoch, &mut staged)
            .map_err(ClientError::Keys)?;
        let sessions = Sessions::new(Role::Client, nonce, config.caps, 1, &mut staged)
            .map_err(ClientError::Budget)?;
        let batch = config.batch as usize;
        let scratch_bytes = batch
            * (size_of::<Option<PacketLease<'m>>>()
                + size_of::<Received>()
                + HEADER_LEN
                + size_of::<Asked>()
                + size_of::<Staged>())
            + INVALIDATED_INBOX * size_of::<Invalidated>();
        staged.charge(scratch_bytes).map_err(ClientError::Budget)?;
        let mut requests = ClientRequests::new(memory.requests, memory.releases, &mut staged)
            .map_err(ClientError::Fetch)?;
        let fetch =
            FetchCore::new(config.fetch, &mut requests, &mut staged).map_err(ClientError::Fetch)?;
        let upload = UploadCore::new(config.upload, memory.sources, &mut requests, &mut staged)
            .map_err(ClientError::Fetch)?;
        *budget = staged;
        Ok(Self {
            config,
            crc: Crc32c::detect(),
            transport,
            ring,
            sessions,
            requests,
            fetch,
            upload,
            receive: memory.receive,
            routes: memory.routes,
            shard: None,
            route_slot: None,
            withheld: false,
            session_wires: 0,
            scratch: std::iter::repeat_with(|| None).take(batch).collect(),
            meta: vec![Received::default(); batch].into_boxed_slice(),
            frames: vec![[0; HEADER_LEN]; batch].into_boxed_slice(),
            asked: Vec::with_capacity(batch),
            staged: Vec::with_capacity(batch),
            state: SessionState::Idle,
            bootstrap: None,
            bootstrap_due_us: 0,
            bootstrap_sent: 0,
            refused_retry_us: None,
            refused: AdmissionRefusals::default(),
            lone_send_to_upload: true,
            invalidate_request: 0,
            invalidated: VecDeque::with_capacity(INVALIDATED_INBOX),
        })
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    #[cfg(test)]
    pub(super) fn routes(&self) -> &Arc<ShardRoutes> {
        &self.routes
    }

    /// The epoch of this client's active session with the owner, if any.
    #[cfg(test)]
    pub(super) fn session_epoch(&self) -> Option<u64> {
        self.sessions.active(OWNER).map(|admitted| admitted.epoch)
    }

    /// This client's session counters, among them the frames refused for
    /// naming a session other than the active one.
    #[cfg(test)]
    pub(super) fn session_report(&self) -> super::session::SessionReport {
        self.sessions.report()
    }

    /// The bootstrap send count since the latest opening or accepted CHALLENGE.
    #[cfg(test)]
    pub(super) fn bootstrap_sent(&self) -> u64 {
        self.bootstrap_sent
    }

    /// Sets the bootstrap send count to `sent`, so a test reaches the count's limit without that many sends.
    #[cfg(test)]
    pub(super) fn seed_bootstrap_sent(&mut self, sent: u64) {
        self.bootstrap_sent = sent;
    }

    /// This client's boot nonce, which every session it opens carries.
    #[cfg(test)]
    pub(super) fn boot_nonce(&self) -> [u8; 16] {
        self.sessions.nonce()
    }

    /// Opens a session, or a fresh one beside the active session, at `now_us`; the next poll sends its HELLO.
    pub fn session(&mut self, now_us: u64) {
        match self.sessions.hello(OWNER) {
            Ok(hello) => {
                self.bootstrap = Some(hello);
                self.bootstrap_due_us = now_us;
                self.bootstrap_sent = 0;
                self.state = SessionState::Opening;
            }
            Err(_) => self.state = SessionState::Failed,
        }
    }

    /// Starts a GET for `key` under the active session, accepting at most `metadata_cap` and `body_cap` bytes and ending by `now_us + wait_us`.
    ///
    /// # Errors
    ///
    /// `NoSession` without an active session, `Unrouted` while the shard route does not admit the active session's tenure, `ReceivePressure`, or `RequestPressure` when the table, the peer's share, the session's slot cap or the wire generations refuse the request.
    pub fn get(
        &mut self,
        key: [u8; 32],
        metadata_cap: u32,
        body_cap: u32,
        now_us: u64,
        wait_us: u64,
    ) -> Result<RequestId, GetRefused> {
        self.get_intended(key, metadata_cap, body_cap, now_us, now_us, wait_us)
    }

    /// [`get`](Self::get) for a request the caller intended to arrive at `intended_us`. Its terminal
    /// observation keeps `intended_us`, which precedes the admission at `now_us` when the caller lagged. A
    /// refusal counts under its cause in [`refusals`](Self::refusals); [`get`](Self::get) passes
    /// `intended_us = now_us`.
    ///
    /// # Errors
    ///
    /// As for [`get`](Self::get).
    pub fn get_intended(
        &mut self,
        key: [u8; 32],
        metadata_cap: u32,
        body_cap: u32,
        intended_us: u64,
        now_us: u64,
        wait_us: u64,
    ) -> Result<RequestId, GetRefused> {
        let limits = FetchLimits {
            metadata_cap,
            body_cap,
            wait_us,
            intended_us,
        };
        let admitted = self.admit(key, limits, now_us);
        if let Err(refused) = admitted {
            let cause = match refused {
                GetRefused::NoSession => &mut self.refused.no_session,
                GetRefused::ReceivePressure => &mut self.refused.receive_pressure,
                GetRefused::RequestPressure => &mut self.refused.request_pressure,
                GetRefused::Unrouted => &mut self.refused.unrouted,
            };
            *cause += 1;
        }
        admitted
    }

    /// Whether the shard route lets the active session send. A session sends while the route is Bound to its tenure,
    /// which is when its responses are admitted, and `withheld` is clear; a session without a READY-bound shard and
    /// tenure sends nothing.
    #[inline(always)]
    fn routable(&self) -> bool {
        #[cfg(test)]
        if NO_ROUTE_CHECK.with(std::cell::Cell::get) {
            return true;
        }
        match (self.shard, self.sessions.tenure(OWNER)) {
            (Some(shard), Some(tenure)) => {
                !self.withheld
                    && self
                        .route_slot
                        .is_some_and(|at| self.routes.bound_at(at, shard, tenure))
            }
            _ => false,
        }
    }

    fn admit(
        &mut self,
        key: [u8; 32],
        limits: FetchLimits,
        now_us: u64,
    ) -> Result<RequestId, GetRefused> {
        let session = self.sessions.active(OWNER).ok_or(GetRefused::NoSession)?;
        if !self.routable() {
            return Err(GetRefused::Unrouted);
        }
        self.fetch
            .fetch(&mut self.requests, session, key, limits, now_us)
            .map_err(|pressure| match pressure {
                FetchPressure::Receive => GetRefused::ReceivePressure,
                FetchPressure::Identity(_) => GetRefused::RequestPressure,
            })
    }

    /// Starts an upload of `key` at cache `version` under the active session, ending by `now_us + wait_us`; its BEGIN names `version`. Uploads and GETs share this client's request table.
    ///
    /// The owner rejects a version 0 upload with [`Status::Contended`](super::Status::Contended), reported as [`UploadOutcome::Failed`], when its coverage holds any interval of `key`, including intervals above 0. For a nonzero version, coverage causes rejection when an interval contains the upload's version.
    ///
    /// # Errors
    ///
    /// `NoSession` without an active owner session, `Unrouted` as for [`get`](Self::get), and `RequestPressure` when the session's slot cap, the request table or the wire generations refuse the request.
    pub fn put(
        &mut self,
        key: [u8; 32],
        version: CacheVersion,
        now_us: u64,
        wait_us: u64,
    ) -> Result<RequestId, PutRefused> {
        let session = self.sessions.active(OWNER).ok_or(PutRefused::NoSession)?;
        if !self.routable() {
            return Err(PutRefused::Unrouted);
        }
        self.upload
            .put(&mut self.requests, session, key, version, now_us, wait_us)
            .map_err(|_| PutRefused::RequestPressure)
    }

    /// The client sends an INVALIDATE for `key`'s versions `low..=high` under the active owner session and returns the request field when the transport takes the frame. The client sends the frame once; retrying is the caller's. The INVALIDATE or its INVALIDATED can be lost on the link, dropped at the owner's full reply ring, or dropped at this client's full inbox, so the caller resends with a new `invalidate` call, which returns a new request field, until [`Client::take_invalidated`] returns an [`Invalidated`] carrying that request.
    ///
    /// # Errors
    ///
    /// The client returns `NoSession` when the active owner session or its nonces are unavailable, `Unrouted` as for [`get`](Self::get), `Interval` when `low > high`, and `RequestPressure` when sequence allocation fails or the transport refuses or fails the frame.
    pub fn invalidate(&mut self, key: [u8; 32], low: u64, high: u64) -> Result<u64, PutRefused> {
        let active = self.sessions.active(OWNER).ok_or(PutRefused::NoSession)?;
        if !self.routable() {
            return Err(PutRefused::Unrouted);
        }
        let Self {
            sessions,
            ring,
            transport,
            config,
            crc,
            fetch,
            upload,
            requests,
            ..
        } = self;
        let (owner_nonce, client_nonce) = sessions.nonces(OWNER).ok_or(PutRefused::NoSession)?;
        if low > high {
            return Err(PutRefused::Interval);
        }
        // A spent send sequence ends the session, so its requests end with it.
        let Ok(sequence) = sessions.next_sequence(OWNER) else {
            end_requests(fetch, upload, requests, active.epoch);
            return Err(PutRefused::RequestPressure);
        };
        self.invalidate_request += 1;
        let header = Header {
            principal: config.principal,
            key_epoch: ring.epoch(),
            owner_nonce,
            client_nonce,
            sequence,
            epoch: active.epoch,
            allocation: low,
            offset: high,
            ..header(Kind::Invalidate, self.invalidate_request, key)
        };
        match transmit(*crc, ring, transport, config.endpoint, &header, &[]) {
            Sent::Taken => Ok(self.invalidate_request),
            _ => Err(PutRefused::RequestPressure),
        }
    }

    /// The oldest INVALIDATED received and not yet taken. The inbox holds `INVALIDATED_INBOX` untaken acknowledgments and drops the next one to arrive.
    pub fn take_invalidated(&mut self) -> Option<Invalidated> {
        self.invalidated.pop_front()
    }

    pub fn prepare(
        &mut self,
        id: RequestId,
        metadata_len: u32,
        body_len: u32,
        ttl_ms: u32,
    ) -> Result<(), PrepareRefused> {
        self.upload
            .prepare(&mut self.requests, id, metadata_len, body_len, ttl_ms)
    }

    pub fn supply(
        &mut self,
        id: RequestId,
        index: u32,
        bytes: &[u8],
    ) -> Result<usize, SupplyRefused> {
        self.upload.supply(&mut self.requests, id, index, bytes)
    }

    pub fn put_outcome(&self, id: RequestId) -> Option<UploadOutcome> {
        self.upload.outcome(&self.requests, id)
    }

    /// Upload `id`'s fill serial, cumulative receipt base and grant.
    #[cfg(test)]
    pub(super) fn put_receipt(&self, id: RequestId) -> Option<(u64, u32, u32)> {
        self.upload.receipt(&self.requests, id)
    }

    /// The request ID carried by upload `id`'s frames; `id` is the
    /// request-table handle.
    #[cfg(test)]
    pub(super) fn put_wire(&self, id: RequestId) -> Option<u64> {
        self.requests.upload(id).map(|upload| upload.wire())
    }

    /// The request ID carried by GET `id`'s frames; `id` is the
    /// request-table handle.
    #[cfg(test)]
    pub(super) fn get_wire(&self, id: RequestId) -> Option<u64> {
        self.requests.fetch(id).map(|fetch| fetch.wire())
    }

    /// RESULT frames this client's uploads have accepted.
    #[cfg(test)]
    pub(super) fn put_results(&self) -> u64 {
        self.upload.results()
    }

    pub fn sources(&self) -> &[SourceSlot<'m>] {
        self.upload.slots()
    }

    /// Admitted uploads not yet released.
    #[cfg(test)]
    pub(super) fn live_uploads(&self) -> usize {
        self.upload.live()
    }

    /// `admission_state` returns the request census and the next generation.
    #[cfg(test)]
    pub(super) fn admission_state(&self) -> (super::requests::RequestCensus, Option<u64>) {
        let census = self.requests.table().census();
        (census, self.requests.releases().next_generation())
    }

    /// Upload `id`'s whole state; see [`UploadCore::snapshot`].
    #[cfg(test)]
    pub(super) fn upload_snapshot(&self, id: RequestId) -> String {
        self.upload.snapshot(&self.requests, id)
    }

    /// Receive boxes reserved: the live requests' initial grants and the leases the application holds from closed requests.
    #[cfg(test)]
    pub(super) fn reserved(&self) -> u32 {
        self.fetch.reserved()
    }

    /// The next fragment of request `id` in order, if received.
    #[inline]
    pub fn take(&mut self, id: RequestId) -> Option<FragmentLease<'m>> {
        self.fetch.take(&mut self.requests, id)
    }

    /// Request `id`'s outcome once decided.
    pub fn outcome(&self, id: RequestId) -> Option<Outcome> {
        self.fetch.outcome(&self.requests, id)
    }

    /// GET `id`'s terminal observation once its outcome is decided.
    pub fn terminal(&self, id: RequestId) -> Option<Terminal> {
        self.fetch.terminal(&self.requests, id)
    }

    /// Ends request `id`. A GET ends at once, its outcome taking the time of the client's latest poll or admission, and sends its CANCEL. A PUT with a control frame in a chunk handed to a send call sends PUT CANCEL and settles on the owner's reply, or `Unknown` once retries run out; any other PUT ends `NotStarted`.
    pub fn cancel(&mut self, id: RequestId) {
        self.fetch.cancel(&mut self.requests, id);
        self.upload.cancel(&mut self.requests, id);
    }

    /// Lets [`retire`](Self::retire) release PUT `id` once its outcome is `Unknown`, returning whether it was; false for any other outcome.
    pub fn abandon(&mut self, id: RequestId) -> bool {
        self.upload.abandon(&mut self.requests, id)
    }

    /// Retires request `id`'s slot once its outcome is decided and its CANCEL, if any, was sent, returning whether it did; a PUT whose outcome is `Unknown` retires once [`abandon`](Self::abandon) accepted it, and a PUT retires once the device returned every slot it held. Leases already taken stay valid.
    #[must_use = "a false result leaves the request's slot live until a later poll sends its CANCEL, `abandon` accepts an `Unknown` PUT, or the device returns a PUT's slots"]
    pub fn retire(&mut self, id: RequestId) -> bool {
        self.fetch.close(&mut self.requests, id) || self.upload.close(&mut self.requests, id)
    }

    /// One bounded turn at `now_us`: GET deadlines, one receive batch, the shard-route check that ends the active session's requests once its route stops admitting its tenure, timers, then at most `batch` request frames staged together and handed to the transport in calls of up to 8 datagrams, ending the session's requests when its send sequence ran out, then the transport's device returns.
    ///
    /// After a waiting HELLO or CONFIRM, the poll selects its frames in this order: the GET, ACK and CANCEL frames of the requests in request-table slot order from a cursor, wrapping, then PUT control frames, then PUT DATA frames. The frames leave in that order, except that each GET frame after the poll's first GET moves up behind it, and the poll's GET frames leave as packed GETs: datagrams of up to [`MAX_PACKED_GETS`] GET frames cut from the poll's first GET frame, each frame with its own session sequence and tag. Every other frame leaves in a datagram of its own, so a poll with fewer than two GET frames sends each frame in a datagram of its own, in the order it selected them. A packed datagram needs an owner that accepts packed datagrams: every owner this client can open a session with accepts them, and an owner that does not drops the datagram whole as `Malformed`, with no reply.
    #[inline]
    pub fn poll(&mut self, now_us: u64) -> PollReport {
        let mut report = PollReport::default();
        self.turn(now_us, &mut report);
        report
    }

    /// The turn [`poll`](Self::poll) describes, counted into `report`. `poll` is the `#[inline]` wrapper that builds the report, so in a caller that inlines it the report lives in the caller's frame and the turn fills it there.
    fn turn(&mut self, now_us: u64, report: &mut PollReport) {
        let decided = self.fetch.decided();
        self.fetch.begin(now_us);
        self.refused_retry_us = None;
        self.fetch.expire(&mut self.requests, now_us);
        self.receive_batch(now_us, report);
        self.withhold_unrouted();
        self.fetch.tick(&mut self.requests, now_us);
        self.upload.tick(&mut self.requests, now_us);
        self.bootstrap_tick(now_us);
        // A send sequence that ran out during the turn's sends deleted its session from the session table, so the session's requests end as a replaced session's do.
        if let Some(epoch) = self.send_batch(now_us, report) {
            end_requests(&mut self.fetch, &mut self.upload, &mut self.requests, epoch);
        }
        self.transport.reclaim();
        report.decided = u32::try_from(self.fetch.decided() - decided).unwrap_or(u32::MAX);
    }

    fn withhold_unrouted(&mut self) {
        if self.withheld {
            self.withheld = match (self.shard, self.sessions.tenure(OWNER)) {
                (Some(shard), Some(tenure)) => !self.routes.binds(shard, tenure),
                _ => self.sessions.active(OWNER).is_some(),
            };
            return;
        }
        // A session the route admits is active and keeps its requests.
        if self.routable() {
            return;
        }
        if let Some(session) = self.sessions.active(OWNER) {
            end_requests(
                &mut self.fetch,
                &mut self.upload,
                &mut self.requests,
                session.epoch,
            );
            self.withheld = true;
        }
    }

    fn receive_batch(&mut self, now_us: u64, report: &mut PollReport) {
        let got = match self
            .transport
            .receive(self.receive, &mut self.scratch, &mut self.meta)
        {
            Ok(got) => got,
            Err(error) => {
                report.failed = Some(code_of(error));
                0
            }
        };
        report.received += got as u32;
        // An empty receive hands the inbox nothing.
        if got == 0 {
            return;
        }
        let Self {
            config,
            crc,
            ring,
            sessions,
            requests,
            fetch,
            upload,
            scratch,
            meta,
            state,
            bootstrap,
            bootstrap_due_us,
            bootstrap_sent,
            invalidated,
            routes,
            shard,
            route_slot,
            withheld,
            session_wires,
            ..
        } = self;
        let mut inbox = Inbox {
            endpoint: config.endpoint,
            crc: *crc,
            ring,
            sessions,
            requests,
            fetch,
            upload,
            state,
            bootstrap,
            bootstrap_due_us,
            bootstrap_sent,
            invalidated,
            routes: routes.as_ref(),
            shard,
            route_slot,
            withheld,
            session_wires,
            unrouted: 0,
        };
        // Datagrams go two at a time, their tags verified together; a datagram without a parsed partner is verified alone.
        let got = got.min(scratch.len());
        let mut at = 0;
        while at < got {
            let Some(lease) = scratch[at].take() else {
                at += 1;
                continue;
            };
            let first_meta = meta[at];
            at += 1;
            let Some(first) = inbox.parsed(&lease, first_meta) else {
                report.dropped += 1;
                continue;
            };
            let partner = (at < got)
                .then(|| scratch[at].take())
                .flatten()
                .map(|lease| (lease, meta[at]));
            let Some((other, other_meta)) = partner else {
                let accepted = match inbox.alone(&first) {
                    Some(frame) => {
                        let taken = inbox.dispatch(&frame, now_us);
                        inbox.finish(taken, frame.header(), lease, now_us)
                    }
                    None => false,
                };
                report.dropped += u32::from(!accepted);
                continue;
            };
            at += 1;
            let Some(second) = inbox.parsed(&other, other_meta) else {
                report.dropped += 1;
                let accepted = match inbox.alone(&first) {
                    Some(frame) => {
                        let taken = inbox.dispatch(&frame, now_us);
                        inbox.finish(taken, frame.header(), lease, now_us)
                    }
                    None => false,
                };
                report.dropped += u32::from(!accepted);
                continue;
            };
            let (verified_first, verified_second) = inbox.ring.authenticate_pair(
                (&first, OWNER),
                (&second, OWNER),
                inbox.endpoint,
                Direction::OwnerToClient,
            );
            let accepted = match verified_first {
                Ok(frame) => {
                    let taken = inbox.dispatch(&frame, now_us);
                    inbox.finish(taken, frame.header(), lease, now_us)
                }
                Err(_) => false,
            };
            report.dropped += u32::from(!accepted);
            let accepted = match verified_second {
                Ok(frame) => {
                    let taken = inbox.dispatch(&frame, now_us);
                    inbox.finish(taken, frame.header(), other, now_us)
                }
                Err(_) => false,
            };
            report.dropped += u32::from(!accepted);
        }
        report.unrouted += inbox.unrouted;
    }

    /// Resends the bootstrap frame of an opening that went unanswered, or fails the opening once its resends are spent. The resend is the pending handshake's CONFIRM while [`Sessions::confirm`] grants a repeat, and a fresh HELLO otherwise.
    fn bootstrap_tick(&mut self, now_us: u64) {
        if self.state != SessionState::Opening
            || self.bootstrap.is_some()
            || now_us < self.bootstrap_due_us
        {
            return;
        }
        if self.bootstrap_sent > u64::from(self.config.bootstrap_attempts) {
            self.state = SessionState::Failed;
            return;
        }
        let resend = match self.sessions.confirm(OWNER) {
            Ok(confirm) => Ok(confirm),
            Err(_) => self.sessions.hello(OWNER),
        };
        match resend {
            Ok(frame) => self.bootstrap = Some(frame),
            Err(_) => self.state = SessionState::Failed,
        }
    }

    /// Stages, seals and sends the turn's frames. Returns the epoch of the active session when its send sequence ran out under a frame being staged: the session table deleted that session, and the frame went unsent and counts in `report.dropped`.
    fn send_batch(&mut self, now_us: u64, report: &mut PollReport) -> Option<u64> {
        // Every frame the turn stages is the waiting bootstrap frame or the frame of a marked fetch or upload slot, so a turn with none of them returns before staging.
        if self.bootstrap.is_none() && !self.fetch.marked() && !self.upload.may_send() {
            return None;
        }
        let budget = self.meta.len();
        let Self {
            requests,
            fetch,
            upload,
            sessions,
            ring,
            config,
            transport,
            crc,
            refused_retry_us,
            bootstrap,
            bootstrap_sent,
            bootstrap_due_us,
            frames,
            asked,
            staged,
            lone_send_to_upload,
            session_wires,
            ..
        } = self;
        let bootstrap_sent_now = bootstrap.is_some();
        if let Some(step) = *bootstrap {
            let header = Header {
                principal: config.principal,
                key_epoch: ring.epoch(),
                owner_nonce: step.owner_nonce,
                client_nonce: step.client_nonce,
                sequence: step.sequence,
                epoch: step.epoch,
                datagram_len: step.caps.body().len() as u32,
                ..header(step.kind, 0, [0; 32])
            };
            let sent = transmit(
                *crc,
                ring,
                transport,
                config.endpoint,
                &header,
                &step.caps.body(),
            );
            sent.record(report);
            if sent == Sent::Blocked {
                *refused_retry_us = Some(now_us.saturating_add(config.bootstrap_retry_us));
                return None;
            }
            // A frame the transport failed counts as one sent and lost, so a failing transport spends the resends too.
            *bootstrap = None;
            *bootstrap_sent += 1;
            *bootstrap_due_us = now_us.saturating_add(config.bootstrap_retry_us);
        }
        // A bootstrap send, taken or failed, uses one of the turn's sends.
        let remaining = budget - usize::from(bootstrap_sent_now);
        // Only the active session's frames pass `of_session` and reach `next_sequence`, so a refusal there is that session's spent sequence.
        let mut spent = None;
        asked.clear();
        // One send stays with the upload core while it may have a control frame or a fragment due, so GET frames due every poll leave PUT control and DATA frames their turn; a lone send both cores may claim goes to each in turn.
        let reserve = upload.may_send() && (remaining > 1 || *lone_send_to_upload);
        if remaining == 1 && upload.may_send() && fetch.marked() {
            *lone_send_to_upload = !*lone_send_to_upload;
        }
        let fetch_budget = remaining.saturating_sub(usize::from(reserve));
        // The fetch core hands out the poll's GET frames with no other frame between them, and an ACK or CANCEL it
        // selects after the first GET behind the last GET. Each frame is staged and takes its sequence as it is
        // handed out, so on the wire the GET frames form one block, `block`, at the first GET's position, and
        // sequences rise in wire order.
        let mut block = 0..0;
        if fetch.marked() {
            let mut get_staged = false;
            fetch.poll(requests, now_us, fetch_budget, |ask| {
                let live = of_session(sessions, *session_wires, ask.epoch, ask.header.request);
                // A frame whose session ended goes unsent; its request ended with it.
                let Some((owner_nonce, client_nonce)) = live else {
                    report.dropped += 1;
                    return true;
                };
                // A frame whose send sequence ran out goes unsent; the poll ends its session's requests after the sends.
                let Ok(sequence) = sessions.next_sequence(OWNER) else {
                    report.dropped += 1;
                    spent = Some(ask.epoch);
                    return true;
                };
                let header = Header {
                    principal: config.principal,
                    key_epoch: ring.epoch(),
                    owner_nonce,
                    client_nonce,
                    sequence,
                    epoch: ask.epoch,
                    ..ask.header
                };
                // The fetch core hands out at most `fetch_budget` frames, so a box is left for each.
                let Some(encoded) = frames.get_mut(asked.len()) else {
                    return false;
                };
                if encode(*crc, &header, [&[], &[]], encoded).is_ok() {
                    if ask.header.kind == Kind::Get {
                        // The fetch core hands out a poll's GET frames with no other frame between them, so each staged GET extends the block by one frame.
                        if !get_staged {
                            get_staged = true;
                            block = asked.len()..asked.len();
                        }
                        debug_assert_eq!(block.end, asked.len());
                        block.end += 1;
                    }
                    asked.push(Asked::from(&ask));
                } else {
                    Sent::Failed(None).record(report);
                }
                true
            });
        }
        staged.clear();
        // `frames` holds, in wire order: the fetch frames handed out ahead of the first GET, the GET block at `block`,
        // the ACK and CANCEL frames handed out behind it up to `fetched`, then the PUT control frames up to `data`
        // and the PUT DATA frames up to `total`.
        let fetched = asked.len();
        upload.poll(requests, now_us, remaining - fetched, |epoch, ask| {
            let live = of_session(sessions, *session_wires, epoch, ask.request);
            // A frame whose session ended, or whose send sequence ran out, goes unsent; its upload ends with it.
            let (Some((owner_nonce, client_nonce)), Some(encoded)) =
                (live, frames.get_mut(fetched + staged.len()))
            else {
                report.dropped += 1;
                return false;
            };
            let Ok(sequence) = sessions.next_sequence(OWNER) else {
                report.dropped += 1;
                spent = Some(epoch);
                return false;
            };
            let header = Header {
                principal: config.principal,
                key_epoch: ring.epoch(),
                owner_nonce,
                client_nonce,
                sequence,
                epoch,
                ..ask
            };
            if encode(*crc, &header, [&[], &[]], encoded).is_ok() {
                staged.push((OWNER, ask.request, None));
            } else {
                Sent::Failed(None).record(report);
            }
            true
        });
        let headers = fetched + staged.len();
        let tagged = seal_headers(ring, config.endpoint, &mut frames[..headers]);
        if tagged < headers {
            Sent::Failed(None).record(report);
            asked.truncate(tagged);
            staged.truncate(tagged.saturating_sub(fetched));
            block.end = block.end.min(tagged);
        }
        let fetched = asked.len();
        let room = remaining - fetched - staged.len();
        let polled = staged.len();
        upload.data(requests, room, |epoch, ask, slot, source| {
            let live = of_session(sessions, *session_wires, epoch, ask.request);
            // A DATA frame whose session ended, or whose send sequence ran out, goes unsent; its upload ends with it.
            let (Some((owner_nonce, client_nonce)), Some(encoded)) =
                (live, frames.get_mut(fetched + staged.len()))
            else {
                report.dropped += 1;
                return false;
            };
            let Ok(sequence) = sessions.next_sequence(OWNER) else {
                report.dropped += 1;
                spent = Some(epoch);
                return false;
            };
            let header = Header {
                principal: config.principal,
                key_epoch: ring.epoch(),
                owner_nonce,
                client_nonce,
                sequence,
                epoch,
                ..ask
            };
            // The tag comes once the turn's DATA frames are encoded, so their hash chains run together.
            if encode_with_body_crc(*crc, &header, [source.bytes(), &[]], source.crc(), encoded)
                .is_ok()
            {
                staged.push((OWNER, ask.request, Some(slot)));
            } else {
                Sent::Failed(None).record(report);
            }
            true
        });
        let data = fetched + polled;
        let sealed = seal_data(
            ring,
            config.endpoint,
            &mut frames[data..fetched + staged.len()],
            (&staged[polled..], upload.slots()),
        );
        // Unsealed frames are PUT DATA, so their upload's retry sets the wake.
        if polled + sealed < staged.len() {
            Sent::Failed(None).record(report);
            *refused_retry_us = Some(now_us.saturating_add(config.upload.retry_us));
        }
        // Only the sealed prefix goes to the transport; every staged frame past the ones it took or lost stays due.
        let total = data + sealed;
        // Where the datagram that starts at the poll's first frame ends: the GET block when it starts there.
        let first = if block.contains(&0) {
            block.end.min(MAX_PACKED_GETS)
        } else {
            1
        };
        let (done, reached) = if total == 0 {
            (0, 0)
        } else if first == total && fetched == total {
            // One fetch datagram holds the whole poll: a lone GET, ACK or CANCEL, or one GET block of at most
            // `MAX_PACKED_GETS` frames. `send_batch` sends it inline in one transport call; `send_staged` is an
            // out-of-line call that serves every other poll. `send_batch` and `send_staged` handle the result of a
            // one-datagram transport call the same way.
            match send_one(transport, &frames[..total], None) {
                Ok(0) => {
                    Sent::Blocked.record(report);
                    (0, total)
                }
                Ok(_) => {
                    report.sent += 1;
                    if !block.is_empty() {
                        fetch.taken(requests, &asked[..total], now_us);
                    }
                    (total, total)
                }
                Err(error) => {
                    Sent::Failed(code_of(error)).record(report);
                    (total, total)
                }
            }
        } else {
            send_staged(
                transport,
                &frames[..total],
                block,
                (&staged[..polled + sealed], upload.slots()),
                report,
                |taken| fetch.taken(requests, &asked[taken], now_us),
            )
        };
        if done < total {
            // Fetch frames fill `frames[..fetched]` and PUT frames the rest, so the refused range names which retry intervals apply.
            let retry_us = match (done < fetched, total > fetched) {
                (true, true) => config.fetch.retry_us.min(config.upload.retry_us),
                (true, false) => config.fetch.retry_us,
                (false, _) => config.upload.retry_us,
            };
            *refused_retry_us = Some(now_us.saturating_add(retry_us));
            // The frames the transport refused stay due for the next sending poll.
            for frame in &asked[done.min(fetched)..] {
                fetch.unsend(requests, *frame);
            }
        }
        for (at, (peer, wire, slot)) in staged.iter().enumerate() {
            match slot {
                Some(slot) if fetched + at >= done => upload.unsent(requests, *slot),
                Some(_) => {}
                None => upload.handed(
                    requests,
                    (*peer, *wire),
                    fetched + at < reached,
                    fetched + at < done,
                ),
            }
        }
        spent
    }

    /// Cancels every undecided request, discards any pending HELLO or CONFIRM, and sends the CANCELs in turns of at most `batch` until every one went out or the transport refuses a send, then closes and returns the report of those sends, where `blocked` means CANCELs stayed unsent, with the transport, whose device the caller stops. Leases already taken stay valid until dropped. The close consumes the client with the fetch report its cancels update, so callers read [`fetch_report`](Self::fetch_report) before the call.
    #[must_use = "the report's `blocked` says whether every CANCEL went out"]
    pub fn close(mut self, now_us: u64) -> (PollReport, D) {
        self.fetch.cancel_all(&mut self.requests);
        self.upload.close_all(&mut self.requests);
        self.bootstrap = None;
        // Only a refusal during this close stops the drain; an earlier poll's refusal has no bearing on it.
        self.refused_retry_us = None;
        let mut report = PollReport::default();
        // Each turn sends or drops at least one due CANCEL unless the transport refuses, so the loop ends within one turn per live request.
        while self.fetch.due(&self.requests) && self.refused_retry_us.is_none() {
            self.send_batch(now_us, &mut report);
        }
        (report, self.transport)
    }
}

#[cfg(test)]
impl<D> Client<'_, D> {
    pub(super) fn sessions_mut(&mut self) -> &mut Sessions {
        &mut self.sessions
    }
}

impl<D> Client<'_, D> {
    /// The transport, for its counters and device state.
    pub fn transport(&self) -> &D {
        &self.transport
    }

    /// The fetch core's counters over the client's life.
    pub fn fetch_report(&self) -> FetchReport {
        self.fetch.report()
    }

    /// GETs refused at admission over the client's life, one count per refused call, by cause. A refused GET
    /// receives no attempt identity, so it has no outcome or terminal observation.
    pub fn refusals(&self) -> AdmissionRefusals {
        self.refused
    }

    /// The earliest time the client has timer work: 0 while a frame is due and the transport takes sends, one retry interval after a refused send, or `None` when only arriving datagrams can give it work.
    /// Read it after releasing leases, since a release can make a grant due.
    pub fn next_deadline_us(&self) -> Option<u64> {
        let wake = self.fetch.wake(&self.requests);
        let (uploads_due, uploads_at) = self.upload.wake(&self.requests);
        let due = wake.due || uploads_due || self.bootstrap.is_some();
        let bootstrap = (self.state == SessionState::Opening && self.bootstrap.is_none())
            .then_some(self.bootstrap_due_us);
        let timers = wake
            .deadline_us
            .into_iter()
            .chain(uploads_at)
            .chain(bootstrap)
            .chain(self.refused_retry_us)
            .min();
        if due && self.refused_retry_us.is_none() {
            Some(0)
        } else {
            timers
        }
    }
}

/// The client's receive side for one batch: the parts of the endpoint a received datagram reaches.
struct Inbox<'c, 'm> {
    endpoint: u32,
    crc: Crc32c,
    ring: &'c KeyRing,
    sessions: &'c mut Sessions,
    requests: &'c mut ClientRequests<'m>,
    fetch: &'c mut FetchCore<'m>,
    upload: &'c mut UploadCore<'m>,
    state: &'c mut SessionState,
    bootstrap: &'c mut Option<Bootstrap>,
    bootstrap_due_us: &'c mut u64,
    bootstrap_sent: &'c mut u64,
    invalidated: &'c mut VecDeque<Invalidated>,
    routes: &'c ShardRoutes,
    shard: &'c mut Option<Shard>,
    route_slot: &'c mut Option<usize>,
    withheld: &'c mut bool,
    session_wires: &'c mut u64,
    unrouted: u32,
}

impl<'m> Inbox<'_, 'm> {
    /// The datagram parsed, when it came from the owner and parses.
    fn parsed<'b>(&self, lease: &'b PacketLease<'m>, meta: Received) -> Option<Frame<'b>> {
        if meta.peer != Some(OWNER) {
            return None;
        }
        parse(self.crc, lease.bytes(), meta.truncated).ok()
    }

    /// One parsed datagram authenticated alone; `None` for a frame that failed to authenticate. The caller dispatches and completes it as it does each frame of a verified pair, decoding the header `finish` takes from the authenticated frame at the call site.
    fn alone<'f, 'b>(&self, frame: &'f Frame<'b>) -> Option<Authenticated<'f, 'b>> {
        self.ring
            .authenticate(frame, OWNER, self.endpoint, Direction::OwnerToClient)
            .ok()
    }

    /// Completes a dispatched datagram, handing an admitted DATA frame's lease to the fetch core under its session, and returns whether the datagram was accepted.
    fn finish(
        &mut self,
        taken: Taken,
        header: Header,
        lease: PacketLease<'m>,
        now_us: u64,
    ) -> bool {
        match taken {
            Taken::Dropped => false,
            Taken::Accepted => true,
            Taken::Data(session, wanted) => {
                self.fetch
                    .data(self.requests, session, &header, wanted, lease, now_us);
                true
            }
        }
    }

    /// Whether the shard route admits a response on the active session, checked for each frame before the fetch or
    /// upload core reads it, the frame carrying a response's last byte included. A session raises its
    /// shard's high-water to its bound tenure and is admitted only while the route is Bound to exactly that tenure, and
    /// a withheld session is refused without the table's lock. A refused frame is dropped, and the poll's
    /// [`withhold_unrouted`](Client::withhold_unrouted) then ends the session's GETs and uploads. A session without a
    /// READY-bound shard and tenure is refused.
    fn routed(&mut self) -> bool {
        #[cfg(test)]
        if NO_ROUTE_CHECK.with(std::cell::Cell::get) {
            return true;
        }
        let admitted = match (*self.shard, self.sessions.tenure(OWNER)) {
            (Some(shard), Some(tenure)) => {
                !*self.withheld && self.routes.admit(shard, tenure, || self.binder())
            }
            _ => false,
        };
        if !admitted {
            self.unrouted += 1;
        }
        admitted
    }

    /// The active session as the shard routes name it: this client's boot nonce and the session's epoch.
    fn binder(&self) -> Option<Binder> {
        let (_, client_nonce) = self.sessions.nonces(OWNER)?;
        Binder::new(client_nonce, self.sessions.active(OWNER)?.epoch)
    }

    /// Admits `frame` to the active session when its sequence is above every sequence that session admitted, and
    /// reports whether it did; such a frame may withdraw a binding (`ShardRoutes::reply`).
    fn admit_newest(&mut self, frame: &Authenticated<'_, '_>) -> bool {
        #[cfg(test)]
        if UNORDERED_WITHDRAWALS.get() {
            return self.sessions.active(OWNER).is_some();
        }
        self.sessions.admit_newest(frame)
    }

    /// Admits a response frame through the session table and then the shard route.
    fn admit_response(&mut self, frame: &Authenticated<'_, '_>) -> Option<Admitted> {
        let session = self.sessions.admit(frame).ok()?;
        self.routed().then_some(session)
    }

    /// Hands one authenticated datagram to the session table, the shard route and the fetch or upload core, or merges an ownership frame into the shard routes, where the session table decides only whether a WrongOwner may withdraw a binding; an admitted DATA frame comes back for its lease once its body crc passed, when the fetch core wants it.
    fn dispatch(&mut self, frame: &Authenticated<'_, '_>, now_us: u64) -> Taken {
        let header = frame.header();
        match header.kind {
            Kind::Challenge => match self.sessions.on_challenge(frame) {
                Ok(confirm) => {
                    // A CHALLENGE answering a HELLO whose resends were spent reopens the handshake, so its CONFIRM gets resends and a deadline.
                    *self.state = SessionState::Opening;
                    *self.bootstrap = Some(confirm);
                    *self.bootstrap_due_us = now_us;
                    *self.bootstrap_sent = 0;
                    Taken::Accepted
                }
                Err(_) => Taken::Dropped,
            },
            Kind::Ready => {
                let had_active = self.sessions.active(OWNER).is_some();
                match self.sessions.on_ready(frame) {
                    Ok((_, None, _)) if had_active => Taken::Accepted,
                    Ok((_, replaced, ready)) => {
                        *self.state = SessionState::Active;
                        *self.bootstrap = None;
                        self.routes.ready(ready.shard, ready.tenure, self.binder());
                        *self.shard = Some(ready.shard);
                        // `ready` gives the shard its route and slot while the table has room, so the index is read after it.
                        *self.route_slot = self.routes.slot(ready.shard);
                        *self.withheld = false;
                        // No request is admitted under the fresh session yet; a board past its last generation admits none.
                        *self.session_wires = self
                            .requests
                            .releases()
                            .next_generation()
                            .unwrap_or(u64::MAX);
                        if let Some(replaced) = replaced {
                            end_requests(self.fetch, self.upload, self.requests, replaced.epoch);
                        }
                        Taken::Accepted
                    }
                    Err(_) => Taken::Dropped,
                }
            }
            Kind::Start | Kind::Data | Kind::Complete | Kind::Error => {
                let Some(session) = self.admit_response(frame) else {
                    return Taken::Dropped;
                };
                match header.kind {
                    Kind::Start => self.fetch.start(self.requests, session, &header, now_us),
                    Kind::Data => {
                        // The request check precedes the body crc: a fragment the window refuses drops before its body is summed, and a frame whose body crc failed drops after the session admitted it, so its sequence counts as seen.
                        let wanted = self.fetch.wants(self.requests, session, &header);
                        if wanted.is_some() && frame.frame().check_body(self.crc).is_err() {
                            return Taken::Dropped;
                        }
                        return Taken::Data(session, wanted);
                    }
                    Kind::Complete => self.fetch.complete(self.requests, session, &header),
                    _ => self.fetch.error(self.requests, session, &header),
                }
                Taken::Accepted
            }
            Kind::PutAuthority
            | Kind::PutReady
            | Kind::PutAck
            | Kind::PutResult
            | Kind::PutError => match self.admit_response(frame) {
                Some(session) if self.upload.receive(self.requests, session, &header, now_us) => {
                    Taken::Accepted
                }
                _ => Taken::Dropped,
            },
            Kind::Invalidated => match self.admit_response(frame) {
                Some(_) => received_invalidated(self.invalidated, &header),
                None => Taken::Dropped,
            },
            Kind::Holder | Kind::WrongOwner | Kind::Heartbeat | Kind::ProbeReply => {
                let Ok(body) = OwnershipBody::decode(header.kind, frame.frame().raw_body()) else {
                    return Taken::Dropped;
                };
                let bound = self
                    .sessions
                    .tenure(OWNER)
                    .filter(|_| *self.shard == Some(body.shard));
                // A WrongOwner answers a PROBE of the session it names; the other ownership kinds name no session.
                let newest =
                    header.kind == Kind::WrongOwner && bound.is_some() && self.admit_newest(frame);
                let receiver = match (bound, self.binder()) {
                    (Some(tenure), Some(binder)) if newest => Receiver::Newest(tenure, binder),
                    (Some(tenure), _) => Receiver::Bound(tenure),
                    (None, _) => Receiver::Unbound,
                };
                if self.routes.reply(&body, receiver).is_some() {
                    Taken::Accepted
                } else {
                    self.unrouted += 1;
                    Taken::Dropped
                }
            }
            Kind::Hello
            | Kind::Confirm
            | Kind::Get
            | Kind::Ack
            | Kind::Cancel
            | Kind::PutBegin
            | Kind::PutPrepare
            | Kind::PutData
            | Kind::PutCancel
            | Kind::WhoHolds
            | Kind::Probe
            | Kind::Invalidate => Taken::Dropped,
        }
    }
}

pub(super) type Staged = (PeerId, u64, Option<u16>);

/// The active session's boot nonces when the frame of epoch `epoch` and wire ID `wire` belongs to it: the epoch matches and the wire generation is at or above `session_wires`, the active session's first.
fn of_session(
    sessions: &Sessions,
    session_wires: u64,
    epoch: u64,
    wire: u64,
) -> Option<([u8; 16], [u8; 16])> {
    sessions
        .active(OWNER)
        .zip(sessions.nonces(OWNER))
        .filter(|(active, _)| {
            active.epoch == epoch && RequestId::from_wire(wire).generation() >= session_wires
        })
        .map(|(_, nonces)| nonces)
}

/// Ends session `epoch`'s undecided GETs with `SessionMismatch` and no CANCEL, then decides its uploads `Unknown`, or
/// `NotStarted` when no frame of the upload was sent.
fn end_requests<'m>(
    fetch: &mut FetchCore<'m>,
    upload: &mut UploadCore<'m>,
    requests: &mut ClientRequests<'m>,
    epoch: u64,
) {
    fetch.end_session(requests, epoch, Status::SessionMismatch);
    upload.end_session(requests, epoch);
}

/// What the session table, the shard route and the fetch or upload core made of an authenticated datagram.
enum Taken {
    Dropped,
    Accepted,
    /// An admitted DATA frame, its body crc verified when the fetch core wants it; the fetch core takes its lease under this session and the request `wants` routed it to.
    Data(Admitted, Option<Wanted>),
}

/// The error number a transport failure carries, if any.
fn code_of(error: DatagramError) -> Option<i32> {
    match error {
        DatagramError::Failed { code } => code,
        DatagramError::Closed => None,
    }
}

/// Encodes `header` with `body` into `encoded` and tags it under the owner's key for `endpoint`, returning whether both succeeded.
fn seal_frame(
    crc: Crc32c,
    ring: &KeyRing,
    endpoint: u32,
    header: &Header,
    body: &[u8],
    encoded: &mut [u8; HEADER_LEN],
) -> bool {
    if encode(crc, header, [body, &[]], encoded).is_err() {
        return false;
    }
    tag_frame(ring, endpoint, body, encoded)
}

fn tag_frame(ring: &KeyRing, endpoint: u32, body: &[u8], encoded: &mut [u8; HEADER_LEN]) -> bool {
    let Some(tag) = mac_input_for(encoded, [body, &[]], endpoint, Direction::ClientToOwner)
        .and_then(|input| ring.tag(OWNER, &input))
    else {
        return false;
    };
    seal(encoded, tag);
    true
}

/// Tags each encoded DATA frame of `frames` with the bytes of its slot in `slots`, up to sixteen frames to one [`KeyRing::tags`] call, and returns the count of frames tagged from the start; a frame that fails to tag ends the count, and it and every later frame stay due.
pub(super) fn seal_data(
    ring: &KeyRing,
    endpoint: u32,
    frames: &mut [[u8; HEADER_LEN]],
    (staged, slots): (&[Staged], &[SourceSlot<'_>]),
) -> usize {
    seal_tagged(ring, endpoint, frames, |at| {
        staged[at]
            .2
            .and_then(|slot| slots.get(usize::from(slot)))
            .map(SourceSlot::bytes)
    })
}

/// The return value counts frames tagged consecutively from the start of `frames`.
fn seal_headers(ring: &KeyRing, endpoint: u32, frames: &mut [[u8; HEADER_LEN]]) -> usize {
    if let [frame] = frames {
        return usize::from(tag_frame(ring, endpoint, &[], frame));
    }
    seal_tagged(ring, endpoint, frames, |_| Some(&[]))
}

/// Whether a [`KeyRing::tags`] call of sixteen frames gives its last frame to the next call, given the `after` frames that follow it: when exactly one follows and `vector` reports no vector pass, so the last call tags a pair together. With the pass the call keeps its sixteenth frame, which fills a lane the pass runs whatever the count, and the frame that follows hashes alone. `vector` is asked only when one frame follows.
#[inline]
pub(super) fn yields_a_frame(after: usize, vector: impl FnOnce() -> bool) -> bool {
    after == 1 && !vector()
}

/// Tags each frame of `frames` over the body `body` returns for its index, up to sixteen frames to one [`KeyRing::tags`] call. A call of sixteen that one frame follows [`yields_a_frame`] to it. The return value counts frames tagged consecutively from the start of `frames`.
fn seal_tagged<'b>(
    ring: &KeyRing,
    endpoint: u32,
    frames: &mut [[u8; HEADER_LEN]],
    body: impl Fn(usize) -> Option<&'b [u8]>,
) -> usize {
    const GROUP: usize = 16;
    let mut sealed = 0;
    while sealed < frames.len() {
        let mut end = frames.len().min(sealed + GROUP);
        if yields_a_frame(frames.len() - end, KeyRing::vector_pass_detected) {
            end -= 1;
        }
        let mut tags = [[0; TAG_LEN]; GROUP];
        let mut taken = 0;
        let input = |at: usize| {
            mac_input_for(
                &frames[at],
                [body(at)?, &[]],
                endpoint,
                Direction::ClientToOwner,
            )
        };
        if let Some(first) = input(sealed) {
            // `MacInput` has no empty value, so the first input fills the array before each slot takes its own.
            let mut inputs = [first; GROUP];
            for at in sealed..end {
                let Some(input) = input(at) else {
                    break;
                };
                inputs[taken] = input;
                taken += 1;
            }
            if ring
                .tags(OWNER, &inputs[..taken], &mut tags[..taken])
                .is_none()
            {
                taken = 0;
            }
        }
        for (frame, tag) in frames[sealed..sealed + taken].iter_mut().zip(tags) {
            seal(frame, tag);
        }
        sealed += taken;
        if sealed < end {
            break;
        }
    }
    sealed
}

/// Sends `frames` through `transport`, at most [`SEND_CHUNK`] datagrams per call, until every frame went out or a call
/// returns `Ok(0)`. A call that takes a prefix of its datagrams is followed by a call that starts at the first
/// datagram it left. The GET frames at `block` leave in datagrams of up to [`MAX_PACKED_GETS`] frames cut from the
/// block's start; every other frame leaves in a datagram of its own with its payload. `taken` receives the frame range
/// of each datagram of the block that a call reports taken.
///
/// `block` lies within the fetch frames, `frames[..frames.len() - staged.len()]`, and holds GET frames only.
///
/// Returns `(done, reached)` in frames, each at a datagram's end: `done` counts the frames the transport took or lost,
/// and `reached` the frames that some call carried. A failed call loses its leading datagram whole: its frames count
/// in `done` and add nothing to [`PollReport::sent`], and the next call starts at the datagram after it. The
/// transport reported none of the frames from `done` on taken, and the caller keeps them due.
///
/// A call fills an array of [`SEND_CHUNK`] datagrams, except a call whose first datagram carries every frame that
/// is left, which passes that one datagram through [`send_one`]. That is the call of a poll whose one frame is a
/// PUT frame, and the last call of any poll when the calls before it left one datagram. `send_batch` itself makes
/// the call of a poll whose frames are one datagram of fetch frames, so such a poll's frames do not come here.
#[inline(never)]
fn send_staged<'a, D: Datagrams<'a>>(
    transport: &mut D,
    frames: &[[u8; HEADER_LEN]],
    block: Range<usize>,
    (staged, slots): (&[Staged], &[SourceSlot<'a>]),
    report: &mut PollReport,
    mut taken: impl FnMut(Range<usize>),
) -> (usize, usize) {
    let fetched = frames.len() - staged.len();
    debug_assert!(block.end <= fetched);
    // Where the datagram that starts at frame `at` ends.
    let cut = |at: usize| {
        if block.contains(&at) {
            block.end.min(at + MAX_PACKED_GETS)
        } else {
            at + 1
        }
    };
    let piece = |at: usize| {
        at.checked_sub(fetched)
            .and_then(|at| staged[at].2)
            .and_then(|slot| slots.get(usize::from(slot)))
            .and_then(SourceSlot::piece)
    };
    let (mut done, mut reached) = (0, 0);
    while done < frames.len() {
        let first = cut(done);
        let (sent, count) = if first == frames.len() {
            reached = first;
            (send_one(transport, &frames[done..first], piece(done)), 1)
        } else {
            const EMPTY: Outgoing<'static, 'static> = Outgoing {
                peer: OWNER,
                header: &[],
                payload: [Payload::EMPTY, Payload::EMPTY],
            };
            let mut datagrams = [EMPTY; SEND_CHUNK];
            let (mut count, mut at) = (0, done);
            while count < SEND_CHUNK && at < frames.len() {
                let end = cut(at);
                let datagram = &mut datagrams[count];
                datagram.header = frames[at..end].as_flattened();
                if let Some(piece) = piece(at) {
                    datagram.payload[0] = Payload::Retained(piece);
                }
                (count, at) = (count + 1, end);
            }
            reached = at;
            (transport.send(&datagrams[..count]), count)
        };
        match sent {
            Ok(0) => {
                Sent::Blocked.record(report);
                break;
            }
            Ok(took) => {
                let took = took.min(count);
                report.sent += took as u32;
                for _ in 0..took {
                    let end = cut(done);
                    if block.contains(&done) {
                        taken(done..end);
                    }
                    done = end;
                }
            }
            Err(error) => {
                Sent::Failed(code_of(error)).record(report);
                done = first;
            }
        }
    }
    (done, reached)
}

/// One transport call for one datagram: `frames` back to back as its header, and `piece` as its payload when the
/// frame carries one. Returns the call's result: `Ok(1)` when the transport took the datagram, `Ok(0)` when it
/// refused it.
#[inline(always)]
fn send_one<'a, D: Datagrams<'a>>(
    transport: &mut D,
    frames: &[[u8; HEADER_LEN]],
    piece: Option<SourceRange<'_, 'a>>,
) -> Result<usize, DatagramError> {
    let datagram = Outgoing {
        peer: OWNER,
        header: frames.as_flattened(),
        payload: [
            piece.map_or(Payload::EMPTY, Payload::Retained),
            Payload::EMPTY,
        ],
    };
    transport.send(std::slice::from_ref(&datagram))
}

fn received_invalidated(invalidated: &mut VecDeque<Invalidated>, header: &Header) -> Taken {
    if invalidated.len() == INVALIDATED_INBOX {
        return Taken::Dropped;
    }
    invalidated.push_back(Invalidated {
        request: header.request,
        key: header.key,
        low: header.allocation,
        high: header.offset,
    });
    Taken::Accepted
}

/// Encodes `header` with `body`, tags it under the owner's key for `endpoint`, and sends it through `transport`.
fn transmit<'a, D: Datagrams<'a>>(
    crc: Crc32c,
    ring: &KeyRing,
    transport: &mut D,
    endpoint: u32,
    header: &Header,
    body: &[u8],
) -> Sent {
    let mut encoded = [0u8; HEADER_LEN];
    if !seal_frame(crc, ring, endpoint, header, body, &mut encoded) {
        return Sent::Failed(None);
    }
    let datagram = Outgoing {
        peer: OWNER,
        header: &encoded,
        payload: [Payload::Inline(body), Payload::EMPTY],
    };
    match transport.send(&[datagram]) {
        Ok(0) => Sent::Blocked,
        Ok(_) => Sent::Taken,
        Err(error) => Sent::Failed(code_of(error)),
    }
}

/// What a send came to: the one frame [`transmit`] sends, one transport call of [`send_staged`], or a frame that
/// failed to encode or tag. Each caller states what it does with the outcome: the bootstrap send of `send_batch`,
/// [`send_staged`] and [`Client::invalidate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sent {
    /// The transport took the frame.
    Taken,
    /// The transport call returned `Ok(0)`.
    Blocked,
    /// A frame failed to encode or tag, or the transport failed a call, with the error number when it had one.
    Failed(Option<i32>),
}

impl Sent {
    fn record(self, report: &mut PollReport) {
        match self {
            Self::Taken => report.sent += 1,
            Self::Blocked => report.blocked = true,
            Self::Failed(code) => report.failed = Some(code),
        }
    }
}

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
#[path = "client_inbox_tests.rs"]
mod inbox_tests;
