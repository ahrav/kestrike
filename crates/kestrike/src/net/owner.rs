//! The owner endpoint: one cache facade, one registration and one attached volume serving authenticated GETs from fixed peers, each GET a fresh lookup whose right one volume read takes over, feeding the transfer core.
//!
//! Invariants owned by this module:
//!
//! - One [`Requests`] namespace owns the request table, wire bindings, retained
//!   outcomes and census. [`ServeCore`] schedules its GET records. Active and
//!   draining records consume the same peer share. Session replacement, send
//!   exhaustion and close retire GET work before clearing namespace evidence.
//!
//! - GET reserves require positive `get_reserve` and `peer_get_reserve`, with `put.puts <= request_slots - get_reserve` and `put.peer_puts <= peer_requests - peer_get_reserve` validated by checked subtraction at start. PUTs count against both caps from admission until their records release, draining included. While every slot remains usable, a table-pressure refusal of a GET implies at least `get_reserve` live GET records, and a peer-share refusal implies at least `peer_get_reserve` GET records for that peer. Generation exhaustion retires a slot for good, reducing GET headroom by one, and the request census counts retired slots; a relaunch creates a fresh table. The reserves guarantee request-slot headroom alone: a GET admitted inside them still depends on its wire-slot binding, its generation and its lookup and read outcomes. Start provisions a read operation record and response buffers for every request slot, so a reserved GET's read has capacity. Device-write and receive-pool limits apply independently; the PUT caps hold the reserves, and the request table's census counts every live and retired slot.
//! - BOUNDED: [`start`](Owner::start) checks the bundle and charges every key, PUT grant, session, request, PUT, event and receive-window structure once; a refusal returns the whole bundle with the budget unchanged. Each [`poll`](Owner::poll) handles at most one receive batch of `batch` datagrams, one storage tick, `batch` sends, `follow.wake` parked-GET visits and at most one maintenance call funded with `maintain_work` steps, and the hit path allocates nothing. The receive step is the part of a poll that handles its one receive batch. It carries at most `batch * MAX_PACKED_GETS` GET frames, and the poll handles all of them under each datagram's one receive lease, shedding and buffering none. After a call that reports no more work, the maintenance stage rests until a turn's `now_us` reaches [`MAINTAIN_REST_US`] microseconds past that call's, so a caller passes advancing turn times; the events [`MAINTAIN_REST_US`] names end the rest, so the next turn's call sees the change.
//! - The bundle is coherent: the facade, the registration and the volume serve one storage, the read path admits a [`FragmentGeometry`], every request slot has a read operation record, and the response pool holds two whole buffers, plus one for each command the volume reads ahead, for every slot. The integrator dedicates the read-response pool to this owner, which start checks is unborrowed at that moment; under that condition a request's read is never short of its backing.
//! - Every received frame is parsed with its datagram's truncation flag, authenticated under its peer's key, and admitted by the session table before any request state reads it. A packed datagram is 2 to [`MAX_PACKED_GETS`] canonical GET frames back to back, each under its own session sequence and tag. The owner takes the packed path for a leased datagram from a configured peer with a clear truncation flag whose length is 2 to [`MAX_PACKED_GETS`] whole 192-byte chunks and whose every chunk's kind byte says GET. That shape test reads the metadata, the length and the kind bytes alone, before any parse, and each chunk then goes as one frame to [`parse`], the check a lone datagram meets. Its frames are handled in byte order in the receiving poll, each to its end before the next, through the lone GET path: parse, the frame's own tag, session admission, the serve core and the read start. A frame that fails a check is dropped alone under the reason a lone datagram of the same bytes gets, and later frames continue. Every other datagram takes the path of a lone datagram, where the parse refuses whole an untruncated datagram from a configured peer whose first kind byte says GET and that holds more than [`MAX_PACKED_GETS`] frames, has a ragged length or has a later chunk of another kind.
//! - Two accounts hold while no turn unwound. Every datagram the transport reports received is counted once: as handled, or as dropped under the one [`DropReason`] of the first check it failed on its kind's path, and [`OwnerReport::dropped`] moves with that reason's counter. A slot the transport counted and left empty, and every datagram it reports past the slots it was given, count as [`DropReason::Vacant`], so `received == handled + dropped`; a packed datagram counts as handled once it passes the shape test. Every frame of a packed datagram moves exactly one frame account: [`OwnerReport::get_frames`] when it reaches the serve core, or [`OwnerReport::packed_dropped_by`] under the reason of the first check it failed.
//! - Receive windows: each frame of a receive step is a lone datagram or one frame of a packed datagram. Each has one ordinal, which ascends across the step, and its own key and tag slot in the window. When the turn reaches a frame outside a window, it takes the contiguous run of eligible GET frames from that frame, lone or packed and across datagram boundaries, at most `C = min(batch, BatchMax)` of them, with `BatchMax` zero when the storage has no index. An eligible GET is a frame of a packed datagram, or a leased datagram from a configured peer, that parses as a GET under its truncation flag; parsing checks the frame's structure and header CRC, and authentication runs when the frame is handled. A run of two or more is a window: the turn copies its keys and prepares their lookups, deriving each key's route once and hinting each search's first lines, then computes the tag under its peer's key of each frame whose principal is that peer's and whose key epoch is the ring's, up to four frames' hash chains interleaved, four while four frames remain and then the last three, two or one, while the hinted lines arrive, and stages the lookahead's first positions once the tags are done. A frame that fails those checks keeps no tag of its own, the other frames of its group hash two together or alone, and its authentication refuses it on the same checks before comparing a tag. Preparation only reads, hashes and hints; a frame's own handling takes any session, request, pin, credit, right, buffer or command it needs. Every frame of the window is handled at its own ordinal in receive order, so authentication, which compares the tag computed for the frame, session admission, request state, lookup, read start and refusal complete for one frame before the next begins. A GET looks up when the transfer core turns it into a read; its lookup starts from the route prepared for its ordinal when the prepared key equals its authenticated key, and validates and reserves as an unrouted lookup does. A run of one, a capacity below two, or a `lookup_work` below `AHEAD`, one lookup's guard bundle and hash charge, leaves its GETs on the scalar path with an empty lookahead. The first ineligible frame ends a run and a window ends at its capacity; the next run starts at the following frame, so a batch above `BatchMax`, or a packed datagram of more frames than `C`, can yield successive windows in one receive, each a run of two or more eligible frames, and a last frame without a neighbor takes the scalar path. Bare-frame pairing and the PUT DATA group stay indexed by receive slot, and the check that takes a pending PUT DATA group before a frame that would age it out runs before each frame with that frame's own sequence. Each frame's handling takes or replaces its own entry, so a handled window leaves the lookahead empty. A frame is parsed at most three times however runs form: at most once by a scan that started at an earlier frame, at most once by the scan that starts at it, and at most once when it is handled. A scan that starts at a frame of a packed datagram keeps each frame it parses from that datagram, and the handling of a kept frame reads it in place of a parse, so a frame of a packed datagram that parses is parsed once when the scan that reaches it first starts in its own datagram, and twice when the window of an earlier datagram holds it.
//! - A GET completes its lookup before starting its read, and the read takes over the lookup's right through the volume's key read, which reserves no lease credit, so lookup protection ends before any wait or send. A lookup that proves the key missing joins the key's fill in progress within the follower caps, and the GET parks as the [`parked`](super::parked) module states until the turn's wake pass starts its read of the published version or ends it. Each read is bound to the request that started it; the read takes a further command only when the transfer core asks for one, a request that ends cancels its read, and a request's slot and peer share are released only once [`Volume::read_drained`] proves its read drained, every device reference to its chunks returned, and its ERROR, if any, was sent or cleared. Each turn drops the chunks whose last device reference returned before it releases drained requests and grants read commands, so a device's return alone lets a read continue and a request drain. A turn reaps only when the read-response pool counted a last-reference return since the previous reap, because a retained chunk a device reads becomes droppable only through such a return. The pass that cancels ended requests' reads runs only when a request ended since its last pass, the grant pass runs only on the first turn and after a read start that wants a command, an ACK, a chunk's delivery, a reap or a refused or merged grant, and the wake and detach pass runs only while a GET is parked and a parked GET is owed a visit, a check of its fill is under way or due, the read admission changed, or a PUT's fill departed; on any other turn each of the four passes costs a few counter or flag checks, whatever the number of live reads and parked GETs.
//! - Lookup errors, read refusals and read statuses map to one fixed wire status each; a refusal that a correct owner never sees counts as a defect and answers `OwnerUnavailable`, and a lost volume closes admission for later GETs and PUT BEGINs; a turn that unwound refuses later GETs and PUT BEGINs `OwnerUnavailable` while every read keeps its custody, and the next turn, re-key or close first returns the receive leases it left unhandled and empties the lookahead.
//! - A turn runs in order: the PUT core's per-turn command and copy budgets; the transport's device returns, closed or not; receive, authenticate and control; GET then PUT deadlines; cancels of ended requests' reads; the wake and detach pass over parked GETs; device-returned chunks; read grants; one storage tick; its verified events; PUT progress, then PUT ACKs; replies, then a data round across requests that stages each visited request's frames in a bounded burst, or the volume's close once the owner closed; drains; the egress control step when due; a released PUT or a PUT admitted as a run waiter under the cap ending the maintenance rest and a lost volume seen by the PUT core closing admission; then maintenance. Taking the returns first lets this turn's ACKs, reap, drains and grants see every return this turn's reclaim collected.
//! - Local fills, publishes and invalidations reach the volume and storage only through the owner's forwarding methods, and [`shutdown`](Owner::shutdown) releases the volume only after the owner closed, every request was released and the volume quiesced.
//! - `NoAckBeforeAuthoritative`: [`Owner::cover_end`], which [`Owner::cover_pending`] runs, queues an INVALIDATE's INVALIDATED only once it applies the acknowledged success of a page write that carried the INVALIDATE's entry.

use crate::index::Key;
use crate::storage::CacheVersion;
use crate::storage::checkpoint::{PossiblyNamed, StagedCheckpoint};
use crate::storage::page_coverage::{
    Cover, Entry as CoverageEntry, Fencing, Interval, PageReply, PageRequest, Withdraw, page_of,
};
use crate::storage::store::{Client, Store, StoreError, WatermarkLog};
use crate::storage::{
    AHEAD, Cache, ControlRefusal, Disk, EngineBudget, EngineBudgetExceeded, Grant, JoinError,
    JoinedReadError, JoinedRefusal, KeyRead, KeyReadError, LookupError, Platform, Preparation,
    PreparedLookup, ReadEvent, ReadOp, ReadRefusal, ReadStatus, Refusal, Registration,
    ValidatedChunk, Volume, WorkBudget,
};
use crate::storage::{
    Advance, CoverageError, ExtentLease, FillFailure, FillPublishError, HeaderMismatch,
    InvalidateError, Invalidation, Maintained, Quiesced, ReadShape, ReceiveError, WritableFill,
    WriteProgress,
};
use crate::storage::{Encode, Encoded, Leftovers, Panicked, UnitDone, UnitRefused};

use super::auth::{
    AuthError, Authenticated, EntropyError, KeyEntry, KeyError, KeyRing, TAG_LEN, nonce_from,
    os_entropy,
};
use super::datagram::{
    DatagramError, Datagrams, HEADER_LEN, MAX_PACKED_GETS, Outgoing, Payload, PeerId, Received,
};
use super::frame::{
    AUTHENTICATED_LEN, DATA_DIGEST_LEN, Direction, Frame, Header, KIND_AT, Kind, MAX_SLOT_CAP,
    MAX_WINDOW, MacInput, Status, encode, encode_with_body_crc, parse, principal_and_key_epoch,
    raw_sequence, seal,
};
use super::geometry::{BUFFERS_PER_READ, FragmentGeometry, GeometryError, GeometryInputs};
use super::packet::{PacketLease, PacketPool};
use super::parked::{Entry, FollowConfig, Parked, ParkedReport, joined_status};
use super::permit::PutPermits;
use super::put::{Departed, Put, PutConfig, PutCore, PutLimits, Retag, Verdict};
use super::requests::{RequestId, RequestTable};
use super::serve::{
    Asker, ChunkInput, FragmentDigest, GetOutcome, Manifest, Out, ReadEnd, ServeConfig, ServeCore,
    header,
};
use super::served::{Request, Requests};
use super::session::{Admitted, Bootstrap, Caps, RekeyError, Role, SessionReject, Sessions};

/// An owner's identity, caps, transfer timing and per-turn work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerConfig {
    /// This owner endpoint's identifier, which every tag's domain names.
    pub endpoint: u32,
    /// This end's request-slot and window caps, met against each client's at bootstrap.
    pub caps: Caps,
    pub serve: ServeConfig,
    /// Datagrams one poll receives and sends at most.
    pub batch: u32,
    /// Retries one GET's lookup may make.
    pub lookup_retries: usize,
    /// `lookup_work` limits each GET lookup, including a join after a proved miss, and each PUT reservation call: the BEGIN grant, the PREPARE claim and revalidation, and each multi-extent placement call (one during PREPARE and one per progress turn until all extents are placed). A GET retains `Missing` when the join exhausts the remaining steps.
    pub lookup_work: usize,
    /// Table slots shared by the owner's operation records.
    pub request_slots: u32,
    /// Live records one peer may hold across operations, active and draining together.
    pub peer_requests: u32,
    /// Live PUTs, active and draining, leave at least `get_reserve` request slots available to GETs: `put.puts` must be at most `request_slots - get_reserve`. `get_reserve` must be positive and at most `request_slots`. Each retired request slot reduces this headroom by one.
    pub get_reserve: u32,
    /// A peer's live PUTs leave at least `peer_get_reserve` slots of its share available to its GETs: `put.peer_puts` must be at most `peer_requests - peer_get_reserve`. `peer_get_reserve` must be positive and at most `peer_requests`. Each reserve bounds its own PUT cap, so `get_reserve` may be below the sum of the peers' reserves, and the peers' GETs share the table as every peer's operations do.
    pub peer_get_reserve: u32,
    /// Work steps a maintenance call may spend on the storage; zero leaves maintenance to the caller. A storage configured without maintenance watermarks refuses every call, which the report counts.
    pub maintain_work: usize,
    pub put: PutConfig,
    /// Caps on GETs parked behind a fill in progress and the wake pass's per-turn visits.
    pub follow: FollowConfig,
}

impl OwnerConfig {
    fn reserves_fit(&self) -> bool {
        let fits = |reserve: u32, slots: u32, puts: u32| {
            reserve > 0 && slots.checked_sub(reserve).is_some_and(|room| puts <= room)
        };
        fits(self.get_reserve, self.request_slots, self.put.puts)
            && fits(
                self.peer_get_reserve,
                self.peer_requests,
                self.put.peer_puts,
            )
    }
}

#[cfg(test)]
#[path = "owner_tenure_tests.rs"]
pub(crate) mod tests;

#[cfg(kani)]
mod verification {
    use super::{OwnerConfig, PutConfig};
    use crate::net::parked::FollowConfig;
    use crate::net::serve::ServeConfig;
    use crate::net::session::Caps;

    /// Over symbolic slots, shares, reserves and PUT caps: the reserves fit
    /// exactly when each reserve is positive and at most its slots, and the
    /// PUT caps leave at least the reserves free. The reserve tests show
    /// the admitted configurations' GETs inside those reserves at runtime.
    #[kani::proof]
    fn the_reserves_fit_exactly_when_the_put_caps_leave_them_free() {
        let (request_slots, peer_requests): (u32, u32) = (kani::any(), kani::any());
        let (get_reserve, peer_get_reserve): (u32, u32) = (kani::any(), kani::any());
        let (puts, peer_puts): (u32, u32) = (kani::any(), kani::any());
        let config = OwnerConfig {
            endpoint: 1,
            caps: Caps {
                slots: 1,
                window: 1,
            },
            serve: ServeConfig {
                retry_us: 1,
                attempts: 1,
                linger_us: 1,
                rate_per_sec: 1,
                burst: 1,
                slots: 1,
                replies: 1,
                max_wait_us: 1,
            },
            batch: 2,
            lookup_retries: 1,
            lookup_work: 1,
            request_slots,
            peer_requests,
            get_reserve,
            peer_get_reserve,
            maintain_work: 0,
            put: PutConfig {
                puts,
                peer_puts,
                run_waiters: puts,
                get_backlog: u32::MAX,
                commands: 1,
                command_bytes: 1,
                window: 1,
                copy_bytes: 1,
                publish_tries: 1,
                publish_work: 1,
            },
            follow: FollowConfig::OFF,
        };
        let fits = config.reserves_fit();
        let expected = get_reserve > 0
            && get_reserve <= request_slots
            && u64::from(puts) + u64::from(get_reserve) <= u64::from(request_slots)
            && peer_get_reserve > 0
            && peer_get_reserve <= peer_requests
            && u64::from(peer_puts) + u64::from(peer_get_reserve) <= u64::from(peer_requests);
        assert_eq!(fits, expected);
        kani::cover!(fits && puts > 0 && peer_puts > 0);
        kani::cover!(!fits && get_reserve > 0 && get_reserve <= request_slots);
    }
}

/// The storage parts an owner consumes: the one facade, one registration and the attached volume.
pub struct Bundle<'s, 'a, P: Platform, D: Disk> {
    pub cache: Cache<'s, P>,
    pub registration: Registration<'s, P>,
    pub volume: Volume<'s, 'a, P, D>,
}

/// Why an owner did not start; the bundle comes back whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerError {
    /// The facade, the registration and the volume serve different storages.
    Foreign,
    /// The slot or window cap lies outside what a bootstrap frame carries.
    Caps,
    /// The read path admits no fragment geometry.
    Geometry(GeometryError),
    /// The request table needs more read operation records, or more response buffers, at two per request plus one for each command the volume reads ahead, than the volume has.
    Capacity {
        slots: u32,
        read_ops: u32,
        buffers: u32,
    },
    /// Response buffers were already borrowed.
    Borrowed,
    /// The maintenance stage's work is positive but below the storage's maintenance minimum, so every call on the open storage refuses `BudgetExhausted`.
    Maintenance {
        minimum: usize,
    },
    /// The batch is below two, which bootstrap replies and the transfer core share, or the batch and the transport's posted receive ring together exceed the receive pool's control reserve.
    Batch,
    /// The peers number zero or more than `u16::MAX`, the request slots are zero or above the table's maximum, the per-peer share is zero, the peers' shares exceed the slots, the serve slots fall below the caps' slot count, or `config.serve.replies` is zero.
    Requests,
    /// One of these PUT limits is out of range:
    /// - the peers' PUT shares exceed `put.puts`;
    /// - `put.puts` exceeds the request slots;
    /// - `put.puts` times `put.window` exceeds the receive pool's data cap;
    /// - `put.publish_tries` or `put.publish_work` is zero, at any `put.puts`;
    /// - with `put.puts` positive, `put.commands` is zero, `put.get_backlog` is zero, the volume's write share (its queue depth less the read, metadata and reservation shares) numbers fewer than the peers, `put.command_bytes` is below one segment, `put.copy_bytes` is below two maximum datagrams, or `put.window` lies outside `1..=MAX_WINDOW`.
    Puts,
    /// `put.puts` is positive and `put.run_waiters` lies outside `1..=put.puts`.
    RunWaiters {
        run_waiters: u32,
        puts: u32,
    },
    /// `put.puts` exceeds `capacity`, the storage's pooled fill capacity: the lesser of its fill records `sum(F[s])` and half its lease limit, two lease credits per fill. When half the lease limit is the lesser, the refusal is on lease credits, which the fills' reservations take. Passing bounds `put.puts` by `sum(F[s])`, which every BEGIN at the PUT cap finding a record requires; each BEGIN draws from its key's shard, sized by [`IndexConfig::fills`](crate::index::IndexConfig::fills).
    FillCapacity {
        puts: u32,
        capacity: usize,
    },
    /// `put.puts` is positive, the volume carries watermarks, and `low_units` lies below `floor`, the [`structural_floor`](crate::storage::ValidatedConfig::structural_floor) of `put.puts`, or `floor` is the error that method returns. At the floor, while every eviction counted in `in_flight_units` also counts toward `retired_units`, a read whose units rule is not short keeps at least `put.puts × Cmax + 1` units claimable for every claim that passes the retired-pressure check.
    ///
    /// The check counts `put.puts` alone. Local fills claim against the same clean reserve, so a deployment that streams them beside PUTs sizes `low_units` from the floor of their sum.
    WatermarkFloor {
        low_units: u64,
        floor: Result<u64, crate::storage::ConfigError>,
    },
    /// `get_reserve` is zero or above `request_slots`, `peer_get_reserve` is zero or above `peer_requests`, `put.puts` exceeds `request_slots - get_reserve`, or `put.peer_puts` exceeds `peer_requests - peer_get_reserve`.
    GetReserve,
    /// Joins are on and a follower cap or the wake allowance is zero.
    Followers,
    Keys(KeyError),
    /// The PUT grant names a principal outside the peers, or one principal twice.
    Permits(KeyError),
    Entropy(EntropyError),
    Budget(EngineBudgetExceeded),
}

/// The bytes [`Owner::start`] charges, by part, in charge order: the key ring and PUT grants, the request table and the turn's scratch (receive slots, send headers, reply slots, bound reads, parked GETs, events, the receive window and the INVALIDATE queue), the session table, the namespace's wire slots, the GET scheduler's timers, pacing, reply rings and window checksums, and the PUT core's lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerCharges {
    pub(crate) keys: usize,
    pub(crate) request_table: usize,
    pub(crate) sessions: usize,
    pub(crate) wire_slots: usize,
    pub(crate) serve: usize,
    pub(crate) put: usize,
}

impl OwnerCharges {
    /// The owner's budget share: every part, or `None` past `usize`.
    pub fn total(&self) -> Option<usize> {
        [
            self.request_table,
            self.sessions,
            self.wire_slots,
            self.serve,
            self.put,
        ]
        .into_iter()
        .try_fold(self.keys, usize::checked_add)
    }
}

/// Why the owner dropped a received datagram: the first check it failed on its kind's path. A refused frame of a
/// packed datagram takes the same reasons. `Declined` stays the last reason, which [`DropReason::COUNT`] counts from,
/// and each reason's discriminant is its index in [`OwnerReport::dropped_by`] and
/// [`OwnerReport::packed_dropped_by`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// It arrived from no configured peer.
    NoPeer,
    /// The transport counted it in a slot it left empty, or past the slots it was given.
    Vacant,
    /// It carries the transport's truncation flag, which the frame parse refuses first.
    Truncated,
    /// It fails another frame parse check, or its ownership body does not decode.
    Malformed,
    /// The key ring refuses the datagram under its peer's key at one of the checks [`AuthError`] names: principal,
    /// key epoch or tag.
    Unauthenticated,
    /// The session table refuses it.
    Session,
    /// Its kind is one the owner role does not take.
    Kind,
    /// It is a PUT DATA frame whose body crc fails.
    Body,
    /// A handler exit or the PUT core refused it. The CONFIRM token check and the PROBE queue and shard checks run
    /// before session admission, so they name this reason even when the session table would also refuse the frame;
    /// a WHO HOLDS meets the same queue and shard checks and takes no session admission. The exits, by kind:
    /// - HELLO: the session table took it and its peer has no reply slot.
    /// - CONFIRM: no serving token, or one that admits no reply; after session admission, a repeat CONFIRM under
    ///   another tenure, or a peer with no reply slot.
    /// - WHO HOLDS and PROBE: an ownership answer already queued for its peer, or no serving token for its shard;
    ///   for a PROBE after session admission, a session bound to another tenure, or a named tenure at or above the
    ///   owner's.
    /// - INVALIDATE, after session admission: mutation is closed, its peer holds no permit, or the owner cannot
    ///   hold its interval.
    /// - PUT DATA, after session admission and the body crc check: the PUT core refuses the fragment.
    Declined,
}

impl DropReason {
    /// The number of reasons, for a counter per reason.
    pub const COUNT: usize = Self::Declined as usize + 1;
}

/// Counters over the owner's life.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OwnerReport {
    /// Datagrams the transport reported received, each counted once in `handled` or `dropped` while no turn has
    /// unwound.
    pub received: u64,
    pub sent: u64,
    /// Datagrams that passed every owner drop check and reached their handler or the PUT core. A GET, ACK or CANCEL
    /// counts here whatever the serve core then does with it, and a PUT BEGIN, PREPARE or CANCEL whatever the PUT
    /// core does; those cores' reports count the outcome. A packed datagram counts here once it passes the packed
    /// shape test, whatever its frames then meet, even when every frame is refused.
    pub handled: u64,
    /// The total of `dropped_by`: datagrams from no peer, counted in an empty slot or past the transport's slots,
    /// truncated, unparseable, unauthenticated, refused by the session table, of a kind the owner does not take,
    /// PUT DATA whose body crc fails, or refused at an exit [`DropReason::Declined`] lists.
    pub dropped: u64,
    /// Dropped datagrams by reason, indexed by [`DropReason`]. A refused frame of a datagram that passed the packed
    /// shape test counts in [`packed_dropped_by`](Self::packed_dropped_by) and leaves this field as it is; that
    /// field's documentation gives the sum of the two.
    pub dropped_by: [u64; DropReason::COUNT],
    /// GET frames, lone or packed, that passed the frame parse, the tag check and session admission and reached the
    /// serve core, whatever the serve core then did with them.
    pub get_frames: u64,
    /// Datagrams that carried at least one frame `get_frames` counts: a lone GET datagram, or a packed datagram with
    /// such a frame. A turn that unwound inside a datagram leaves the frames it handled in `get_frames` and that
    /// datagram out of this count.
    pub get_datagrams: u64,
    /// Refused frames of packed datagrams by the reason of the first check each failed, indexed by [`DropReason`]:
    /// `Malformed`, `Unauthenticated` or `Session`. Receive refusals by reason are
    /// `dropped_by[r] + packed_dropped_by[r]`.
    pub packed_dropped_by: [u64; DropReason::COUNT],
    /// Session-admitted frames whose wire generation names another operation's
    /// live record or retained row, including an expired row.
    pub wrong_operation: u64,
    /// Lookups whose object's header named another key: fingerprint false positives, answered `Missing`.
    pub false_positives: u64,
    /// Read refusals a correct owner never sees, answered `OwnerUnavailable`.
    pub defects: u64,
    /// Chunks discarded because their read's request had ended or the owner closed.
    pub discarded: u64,
    /// Frames that failed to encode or tag, or that the transport failed.
    pub failed: u64,
    /// Maintenance calls the storage ran.
    pub maintained: u64,
    /// Maintenance calls the storage refused.
    pub maintenance_refused: u64,
    pub parked: ParkedReport,
    /// The last maintenance refusal's reason.
    pub last_maintenance_refusal: Option<crate::storage::MaintainError>,
    /// `maintenance_clock_unavailable` counts open maintenance calls that reported [`MaintainReport::clock_unavailable`](crate::storage::MaintainReport::clock_unavailable).
    pub maintenance_clock_unavailable: u64,
    /// `maintenance_contended` sums every open maintenance call's [`MaintainReport::contended`](crate::storage::MaintainReport::contended).
    pub maintenance_contended: u64,
    /// `last_certify_stall` holds the last open maintenance call's [`MaintainReport::certify_stall`](crate::storage::MaintainReport::certify_stall).
    pub last_certify_stall: Option<crate::storage::CertifyStall>,
    /// The longest gap between the starts of two successive turns, in microseconds of the turns' clock.
    pub poll_gap_max_us: u64,
    /// What the turn before the longest gap did.
    pub poll_gap_max_after: TurnSources,
    /// Gaps between successive turns' starts: entry `k` counts gaps of `2^k` to `2^(k+1)` microseconds, entry
    /// 0 also counts gaps under one microsecond, and the last entry every longer gap.
    pub poll_gaps: [u64; POLL_GAP_BUCKETS],
    /// What the owner held at the report.
    pub retained: RetainedCensus,
}

/// Entries of [`OwnerReport::poll_gaps`]. The last entry starts at `2^23` microseconds, about 8.4 s, so every
/// longer stall lands in one bucket.
pub const POLL_GAP_BUCKETS: usize = 24;

/// What one turn did: the counts it added to datagrams received, datagrams sent and PUTs published. A packed
/// datagram counts once in `received`, whatever the number of its frames.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TurnSources {
    pub received: u64,
    pub sent: u64,
    pub published: u64,
}

/// What the owner holds at one report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetainedCensus {
    /// Buffers of the read-response and receive-write pools that are not free, retired and quarantined ones
    /// among them.
    pub buffers: u32,
    /// Device commands the volume's table still owns: accepted, reserved by a submit whose driver call never
    /// returned, or cancelled and awaiting their terminal.
    pub commands: u32,
    /// Receive-pool buffers that are not free: leased to the owner, posted to the device, or retired.
    pub packets: u32,
}

/// Microseconds of turn time the maintenance stage rests after the storage reported no more work. Changes the owner does not forward wait out the rest: an expiry, a fill attempt dropped outside the owner, a mark a lease drop parked, a reservation that leaves the volume short, and a placement that splits a free run into fewer whole charges each meet the next call by at most the rest plus the calls its stage needs to reach it. Lookups refuse an object from its deadline on, so an expired object keeps only its units until then.
///
/// A PUT release (`take_released`), a PUT placement admitted as a run waiter under the cap (`take_run_waiter`), a successful owner-forwarded publish or invalidation, and a `begin_replay` or `complete_replay` reaching `Live` clear the rest deadline. The run-waiter wake clears the rest on a waiter's first registration, so the headroom stage reads the volume within the calls its stage needs to reach it.
pub(super) const MAINTAIN_REST_US: u64 = 1_000;

/// The gate tries and work the planted aborting detach's invalidation takes.
#[cfg(test)]
const PLANT_TRIES: usize = 4;
#[cfg(test)]
const PLANT_WORK: usize = 1 << 12;

/// An owner holds up to this many distinct `(entry, asker session)` pairs awaiting page writes.
pub const INVALIDATIONS: usize = 64;

/// A held INVALIDATE: its entry, and the asker of a wire INVALIDATE, which its INVALIDATED answers.
type Held = (CoverageEntry, Option<Asker>);

/// Receive windows an owner prepared and the GETs they held, counted for tests.
#[cfg(test)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Windows {
    pub(super) prepared: u64,
    pub(super) gets: u64,
}

#[cfg(test)]
thread_local! {
    pub(super) static WINDOW_TAGS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Header-only frames, ACKs and PUT control frames, whose tags came from one paired computation.
    pub(super) static PAIRED_BARE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// PUT DATA frames passed to authentication as a group of three.
    pub(super) static TRIPLED_DATA: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Planted: a request is released while the device command of its read still holds its response buffers.
    pub(super) static RELEASE_UNDRAINED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A read bound to the namespace table handle that started it.
#[derive(Debug, Clone, Copy)]
struct Bound {
    request: RequestId,
    op: ReadOp,
    /// The read delivered its `Done`.
    done: bool,
    /// The volume answered a grant `Exhausted`: the read's submitted commands reach its end, so the owner grants it no more.
    exhausted: bool,
    /// The owner asked the volume to cancel it.
    cancelled: bool,
}

/// The owner endpoint over transport `T`, serving the storage `'s` through response buffers of arena `'a`, receiving into the pool `'m`.
pub struct Owner<'s, 'a, 'm, P: Platform, D: Disk, T> {
    config: OwnerConfig,
    crc: crate::storage::Crc32c,
    cache: Cache<'s, P>,
    registration: Registration<'s, P>,
    volume: Volume<'s, 'a, P, D>,
    /// The one request namespace every operation's requests and wire slots live in.
    requests: Requests<ValidatedChunk<'a>, Put<'s, 'a, P>>,
    serve: ServeCore,
    put: PutCore<'m>,
    ring: KeyRing,
    /// The peers the configuration granted PUT, fixed for the owner's life.
    permits: PutPermits,
    sessions: Sessions,
    ownership_view: super::owner_view::OwnerView,
    /// Each peer's pending ownership reply header and optional tenure binding.
    ownership: Box<[Option<OwnershipReply>]>,
    /// One bit per peer, set exactly when the peer's `ownership` entry holds a reply, so `send_next_ownership` scans 64 peers per word; bits past the last peer stay clear, so a search yields only peer indexes.
    ownership_queued: Box<[u64]>,
    /// How many entries of `ownership` hold a reply; `send_ownership` searches only while it is nonzero. `queue_ownership` and `take_ownership` keep this count and `ownership_queued` in step with `ownership`.
    ownership_waiting: u32,
    ownership_cursor: u16,
    ownership_leads: bool,
    transport: T,
    receive: &'m PacketPool<'a>,
    /// Receive slots for one batch, empty between turns.
    scratch: Box<[Option<PacketLease<'m>>]>,
    meta: Box<[Received]>,
    /// The keys of the receive window being handled; its length is [`window_width`]'s capacity, zero when every GET takes the scalar path.
    window: Box<[Key]>,
    /// The tag the window computed for each of its frames under its peer's key, at the frame's window position.
    tags: Box<[[u8; TAG_LEN]]>,
    /// The lookahead over the current window's keys; empty between windows.
    preparation: Preparation<'s, P>,
    #[cfg(test)]
    windows: Windows,
    /// The bytes start charged for `window` and the lookahead.
    #[cfg(test)]
    window_charge: usize,
    /// Encoded headers for one send round; its length bounds the round, and the round's `Outgoing` entries borrow them.
    headers: Box<[[u8; HEADER_LEN]]>,
    /// Each peer's newest bootstrap reply waiting to be sent; a newer one replaces it, as a newer HELLO replaces the handshake an older CHALLENGE named.
    replies: Box<[Option<Bootstrap>]>,
    /// How many entries of `replies` hold a waiting reply; a reply round stops once it has visited this many.
    waiting: u32,
    /// The peer the next reply round starts at.
    reply_cursor: u16,
    /// Peers whose session a send batch found exhausted; the batch's end retires their requests, as a replaced session's activation does.
    exhausted: Vec<PeerId>,
    /// Each request slot's bound read.
    bound: Box<[Option<Bound>]>,
    /// The GETs parked behind fills in progress, by request slot.
    parked: Parked<'s, P>,
    /// How many entries of `bound` hold a bound read; a scan of it stops once it has visited this many.
    reads: u32,
    /// Each read operation slot's request slot.
    by_op: Box<[Option<u16>]>,
    events: Vec<ReadEvent<'a>>,
    /// The peers served, numbered from 0.
    peers: u16,
    admission: Admission,
    exit: Option<crate::failover::report::ExitTracker>,
    handoff: Option<Handoff>,
    /// Last state and token observed before receives and after storage work.
    authority_seen: (
        crate::failover::serving::State,
        Option<crate::failover::serving::Token>,
    ),
    close_effects: CloseEffects,
    /// The volume's last quiesce progress, once the owner closed.
    quiesce: Option<crate::storage::QuiesceProgress>,
    /// The turn time at which the maintenance stage's rest ends, while it rests.
    maintain_rest_until_us: Option<u64>,
    /// Steps the last turn's maintenance call spent, and whether its allowance stopped it.
    #[cfg(test)]
    maintain_spent: (usize, bool),
    /// Receive batches and storage ticks the last turn ran.
    #[cfg(test)]
    turn_stages: (u32, u32),
    /// Whether the last turn's PUT core admitted a placement as a run waiter under the cap.
    #[cfg(test)]
    run_wait_woke: bool,
    /// The read-response pool's count of last-reference returns at the last reap.
    reaped_at: u64,
    /// Records events since the last grant pass that can create command demand for a read: a read's initial demand, an ACK, a chunk's delivery, a reap, or a refused or merged grant.
    regrant: bool,
    /// Set for the length of a turn, so a turn that unwound leaves it set.
    armed: bool,
    /// A turn unwound: while the owner is open or its volume lost, later GETs and PUT BEGINs are refused `OwnerUnavailable`; every read keeps its custody, and the flag stays set after a close.
    poisoned: bool,
    /// The tenure's coverage fencing governs FILL admission and INVALIDATE writes. Invalidation returns `InvalidateError::Withdrawn` when `coverage` is `None`.
    coverage: Option<Fencing>,
    /// Set once [`Owner::publish_fill`] returned a lease. Together with `PutReport::published`, this flag requires the coverage install to precede the owner's first published wire PUT or local fill.
    published_locally: bool,
    /// The entries of INVALIDATEs whose removal ran and whose page write has not been acknowledged, at most [`INVALIDATIONS`].
    invalidations: Vec<Held>,
    /// The entries of one page's held INVALIDATEs, which one page write covers.
    page_entries: Vec<CoverageEntry>,
    /// Whether `page_entries` are the entries of a page write in flight, from [`Owner::cover_begin`] until
    /// [`Owner::cover_end`] ends its step.
    covering: bool,
    /// Poll-gap observations use the last turn's start time, the source counters at that start, and the last
    /// ended turn's activity.
    last_poll_us: Option<u64>,
    turn_start: TurnSources,
    last_turn: TurnSources,
    report: OwnerReport,
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    use crate::failover::serving::{Cause, Event, State};
    use crate::net::link::{Faults, network};
    use crate::net::owner_tests::{pool, start};
    use crate::storage::owner_fixture::{arena, storage};

    #[test]
    fn a_deposing_status_delivered_inside_a_poll_withdraws_and_drops_the_buffered_reply() {
        use crate::net::fetch::Releases;
        use crate::net::owner_tests::{client, hold_next_read, key, open, payload};
        use crate::storage::DeviceStatus;
        use crate::storage::device::sim::Fault;
        let object = payload(40_000, 71);
        let storage = storage(8);
        let buffers = arena(8);
        let receive = pool();
        let client_pool = pool();
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let (client_end, owner_end, net) = network(64, 8384, 71, [Faults::default(); 2]);
        let (mut owner, control) = start(
            &storage,
            &buffers,
            &receive,
            &[(key(1), 0, &object)],
            vec![owner_end],
        );
        let mut client = client(0, &client_pool, &releases, client_end);
        let turn = open(
            &mut client,
            &mut owner,
            &control,
            &[std::rc::Rc::clone(&net)],
            0,
        );
        client
            .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
            .unwrap();
        let (held, turn) = hold_next_read(&mut client, &mut owner, &control, &net, turn);
        assert!(owner.session_epoch(PeerId(0)).is_some());
        control.fault(held, Fault::Status(DeviceStatus::Nvme(0x83 << 1)));
        control.release(held);
        control.tick(64);
        let reply = Bootstrap {
            tenure: None,
            peer: PeerId(0),
            kind: Kind::Challenge,
            owner_nonce: [1; 16],
            client_nonce: [2; 16],
            epoch: 1,
            caps: owner.config.caps,
            sequence: 1,
        };
        assert!(owner.reply(reply));
        assert_eq!(owner.waiting, 1);
        let sent = owner.report.sent;
        owner.poll(turn * 100 + 100);
        let report = owner.authority_report();
        assert_eq!(
            (report.state, report.withdrawal),
            (
                State::Withdrawn,
                Some(Cause::Status(crate::failover::serving::Deposing::Conflict))
            )
        );
        assert_eq!(owner.waiting, 0, "the buffered reply is dropped");
        assert!(owner.replies.iter().all(Option::is_none));
        assert_eq!(owner.session_epoch(PeerId(0)), None, "the session ended");
        assert_eq!(
            owner.report.sent, sent,
            "PR-TEN-4: the observing poll sends nothing"
        );
    }

    #[test]
    fn an_owner_whose_turn_unwound_runs_no_reclaim_step() {
        use crate::failover::evidence::{Pair, Registrant};
        use crate::failover::poll::Verdict;
        use crate::failover::poll_tests::{owner as holder, report_of, volume};
        use crate::failover::reconcile::StandbyGate;
        use crate::failover::records::{
            AttachmentEvent, ERA, EventKind, Host, RecordedPair, VolumeState, attachment_key,
        };
        let storage = storage(8);
        let buffers = arena(8);
        let receive = pool();
        let (_client, end, _net) = network(64, 8384, 13, [Faults::default(); 2]);
        let (mut owner, _control) = start(&storage, &buffers, &receive, &[], vec![end]);
        let token = owner.volume.serving_token().expect("a serving owner");
        let own = Pair {
            exhid: token.exhid,
            key: token.key,
        };
        let holder = holder();
        let ended = Pair {
            exhid: crate::failover::identity::Exhid::new([0x31; 16]).unwrap(),
            key: attachment_key(1).unwrap(),
        };
        let replaced = Host::new(holder.host.get() + 101).unwrap();
        let mut record = volume(VolumeState::Active, holder.host);
        record.events.push(AttachmentEvent {
            seq: 1,
            kind: EventKind::Ended,
            host: replaced,
            era: ERA,
            instance: None,
        });
        record.next = 2;
        record.pairs = vec![
            RecordedPair {
                host: holder.host,
                pair: own,
                attach: 0,
            },
            RecordedPair {
                host: replaced,
                pair: ended,
                attach: 1,
            },
        ];
        let entries = [Registrant {
            cntlid: 1,
            holder: true,
            pair: own,
        }];
        let report = crate::failover::evidence::Report {
            submitted_at: u64::MAX,
            ..report_of(&entries)
        };
        let gate = StandbyGate::qualified();
        let verdict = Verdict::Continue;
        assert_eq!(
            owner.owner_reclaim(&gate, &holder, &verdict, Ok(&report), &record),
            [ended],
            "the serving owner returns the pair whose key the Report omits"
        );
        owner.armed = true;
        assert_eq!(
            owner.owner_reclaim(&gate, &holder, &verdict, Ok(&report), &record),
            [],
            "a turn that unwound"
        );
        owner.armed = false;
        assert!(owner.poisoned());
        assert_eq!(
            owner.owner_reclaim(&gate, &holder, &verdict, Ok(&report), &record),
            [],
            "the owner stays poisoned"
        );
    }

    #[test]
    fn a_reply_queued_before_expiry_or_withdrawal_sends_nothing() {
        for withdrawn in [false, true] {
            let storage = storage(8);
            let buffers = arena(8);
            let receive = pool();
            let (_client, end, _net) = network(64, 8384, 13, [Faults::default(); 2]);
            let (mut owner, _control) = start(&storage, &buffers, &receive, &[], vec![end]);
            let reply = Bootstrap {
                tenure: None,
                peer: PeerId(0),
                kind: Kind::Challenge,
                owner_nonce: [1; 16],
                client_nonce: [2; 16],
                epoch: 1,
                caps: owner.config.caps,
                sequence: 1,
            };
            assert!(owner.reply(reply));
            assert!(owner.send_replies(0).is_some());
            assert_eq!(owner.report.sent, 1);
            assert!(owner.reply(reply));
            assert_eq!(owner.waiting, 1);
            owner.volume.authority_event(if withdrawn {
                Event::Withdraw(Cause::Planned)
            } else {
                Event::Expire { now: 0 }
            });
            assert_eq!(
                owner.authority_report().state,
                if withdrawn {
                    State::Withdrawn
                } else {
                    State::Serving
                }
            );
            assert_eq!(owner.send_replies(0), None);
            assert_eq!(
                owner.report.sent, 1,
                "ResponseInIncarnation: the queued reply stays unsent"
            );
        }
    }

    #[test]
    fn active_get_and_put_send_and_write_nothing_after_authority_loss() {
        use crate::net::geometry::FRAGMENT_LEN;
        use crate::net::owner_tests::payload;
        use crate::net::put_tests::{ready_upload, request, scene, send_all};
        for change in 0..5 {
            scene(&crate::net::owner_tests::PRINCIPALS, |mut scene| {
                let object = payload(6 * FRAGMENT_LEN as usize, 31);
                let (at, serial) = ready_upload(&mut scene, &object);
                let accepted = send_all(&mut scene, at, serial, &object, 0..4);
                for &token in &accepted {
                    scene.control.hold(token);
                }
                let held = accepted.len();
                // Changes 0 and 4 expire the serving window, at the volume and through the owner.
                let expired = change == 0 || change == 4;
                let get = scene.get(0, request(2, 1), 1);
                scene.inject(0, &get);
                scene.polls(2);
                assert!(scene.owner.census().live() >= 2);
                assert!(
                    (0..2).all(|peer| scene.owner.session_epoch(PeerId(peer)).is_some()),
                    "both sessions are active before the change"
                );
                let admitted = scene.owner.volume.serving_token();
                let sent = scene.owner.report.sent;
                let writes = scene.owner.volume.report().writes_submitted;
                match change {
                    0 => {
                        scene.owner.volume.authority_event(Event::Expire { now: 0 });
                    }
                    1 => {
                        scene
                            .owner
                            .volume
                            .authority_event(Event::Withdraw(Cause::Planned));
                    }
                    2 => {
                        scene.owner.volume.serve_later_tenure();
                        assert_ne!(scene.owner.volume.serving_token(), admitted);
                    }
                    4 => {
                        let now_us = scene.turn * 100;
                        scene
                            .owner
                            .authority_event(Event::Expire { now: 0 }, now_us);
                    }
                    _ => {}
                }
                if expired || change == 3 {
                    assert_eq!(
                        scene.owner.authority_report().state,
                        State::Serving,
                        "change {change}: the tenure stays Serving"
                    );
                }
                for index in 4..6 {
                    let (header, body) = scene.fragment(at, serial, &object, index);
                    scene.inject_edited(1, &header, &body, |_| {});
                }
                assert!(
                    held > 0 && scene.control.pending() >= held,
                    "change {change}: the device holds the upload's accepted writes"
                );
                scene.turns(4);
                assert!(
                    scene.control.pending() >= held,
                    "change {change}: the held writes stay on the device until they are let go"
                );
                if expired {
                    assert_eq!(
                        (
                            scene.owner.report.sent,
                            scene.owner.volume.report().writes_submitted
                        ),
                        (sent, writes),
                        "change {change}: nothing is sent or written while the writes are held"
                    );
                }
                if change == 1 || change == 2 {
                    assert!(
                        scene.live() > 0,
                        "change {change}: the retired PUT keeps its held writes until their terminals"
                    );
                }
                if change == 1 {
                    assert!(
                        (0..2).all(|peer| scene.owner.session_epoch(PeerId(peer)).is_none()),
                        "the withdrawal ends every session"
                    );
                }
                for &token in &accepted {
                    scene.control.release(token);
                }
                scene.turns(16);
                if change == 3 {
                    assert!(
                        scene.owner.volume.report().writes_submitted > writes,
                        "without an authority change the staged segments are written"
                    );
                    assert!(
                        scene.owner.report.sent > sent,
                        "without an authority change the owner sends"
                    );
                    assert!(scene.visible(5), "and the upload publishes");
                    assert_eq!(
                        scene.control.pending(),
                        0,
                        "the device finishes every command"
                    );
                    return;
                }
                if change == 1 || change == 2 {
                    assert_eq!(
                        scene.live(),
                        0,
                        "change {change}: the held writes' terminals end the retired PUT"
                    );
                }
                assert_eq!(
                    scene.owner.report.sent, sent,
                    "ResponseInIncarnation: change {change}"
                );
                assert_eq!(
                    scene.owner.volume.report().writes_submitted,
                    writes,
                    "NoStaleEpochWriteLands: change {change}"
                );
                assert!(!scene.visible(5), "change {change}");
                if expired {
                    assert_eq!(
                        scene.control.pending(),
                        0,
                        "change {change}: the device finishes the commands it held at the expiry"
                    );
                }
            });
        }
    }

    #[test]
    fn an_authority_change_ends_a_run_wait_and_lowers_the_waiter_count() {
        use crate::net::put_tests::{
            escrow, fragmentable_storage, pin_holes, request, run_wait_scene, three_extents,
        };
        for event in [Event::Close, Event::Withdraw(Cause::Planned)] {
            run_wait_scene(
                fragmentable_storage(),
                crate::net::owner_tests::OWNER,
                |mut scene| {
                    let pins = pin_holes(scene.storage, 8);
                    let at = request(1, 1);
                    let serial = scene.begin(1, at, 10);
                    let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
                    scene.inject(1, &header);
                    scene.polls(1);
                    assert_eq!(scene.owner.put_report().run_waiters, 1);
                    let before = scene.owner.put_report();
                    scene.owner.volume.authority_event(event);
                    scene.polls(1);
                    let report = scene.owner.put_report();
                    assert_eq!(scene.owner.census().live(), 0, "{event:?}");
                    assert_eq!(
                        (
                            report.run_waiters,
                            report.reserve_refused,
                            report.run_wait_refused,
                            report.failed_other,
                            report.failed_timed_out,
                            report.cancelled
                        ),
                        (
                            0,
                            before.reserve_refused,
                            before.run_wait_refused,
                            before.failed_other,
                            before.failed_timed_out,
                            before.cancelled
                        ),
                        "{event:?} ends the wait without a tally: {report:?}"
                    );
                    assert_eq!(escrow(&scene), 0);
                    drop(pins);
                },
            );
        }
    }

    /// A deposition takes effect when the owner observes it: an observation before the send discards the buffered reply; an observation after the send leaves the completed send. The observations are a shard record or page fence of a later tenure, a store regression, the deposing command statuses `0x83` and `0x1B`, and a recorded successor holding the reservation; none requests a flip.
    #[test]
    fn a_deposition_between_reply_and_send_drops_the_buffered_reply() {
        use crate::failover::serving::Deposing;
        for late in [false, true] {
            for cause in [
                Cause::Flipped,
                Cause::NewerFence { page: 0, fence: 9 },
                Cause::LaterTenure,
                Cause::Regression,
                Cause::Status(Deposing::Conflict),
                Cause::Status(Deposing::PreemptAborted),
                Cause::RecordedHolder,
            ] {
                let storage = storage(8);
                let buffers = arena(8);
                let receive = pool();
                let (_client, end, _net) = network(64, 8384, 13, [Faults::default(); 2]);
                let (mut owner, _control) = start(&storage, &buffers, &receive, &[], vec![end]);
                let reply = Bootstrap {
                    tenure: None,
                    peer: PeerId(0),
                    kind: Kind::Challenge,
                    owner_nonce: [1; 16],
                    client_nonce: [2; 16],
                    epoch: 1,
                    caps: owner.config.caps,
                    sequence: 1,
                };
                assert!(owner.reply(reply));
                assert!(owner.send_replies(0).is_some());
                assert_eq!(owner.report.sent, 1);
                assert!(owner.reply(reply));
                assert_eq!(owner.waiting, 1);
                if late {
                    assert!(owner.send_replies(0).is_some());
                }
                owner.authority_event(Event::Withdraw(cause), 0);
                let report = owner.authority_report();
                assert_eq!(
                    (report.state, report.withdrawal, report.flip),
                    (State::Withdrawn, Some(cause), None),
                    "a same-generation deposition requests no flip"
                );
                assert_eq!(owner.waiting, 0, "{cause:?}");
                assert!(owner.replies.iter().all(Option::is_none), "{cause:?}");
                assert_eq!(owner.send_replies(0), None);
                assert_eq!(
                    owner.report.sent,
                    if late { 2 } else { 1 },
                    "PR-TEN-4: {cause:?}, observed after the send: {late}"
                );
            }
        }
    }

    /// What a read command held across a deposition leaves: the live requests and whether the pool lends response
    /// buffers while the command is held, the custody check's count and held tokens at that point beside the held
    /// command's token, frames sent between the observation and the end, the live requests and whether every buffer
    /// returned after the terminal, and the withdrawal with its flip request.
    struct LateTerminal {
        held: (u32, bool),
        custody: (usize, Vec<crate::storage::CommandToken>),
        token: crate::storage::CommandToken,
        sent: u64,
        after: (u32, bool),
        withdrawal: (Option<Cause>, bool),
    }

    fn late_read_terminal() -> LateTerminal {
        use crate::net::fetch::Releases;
        use crate::net::owner_tests::{client, hold_next_read, key, open, payload};
        use crate::storage::PoolKind;
        let object = payload(40_000, 71);
        let storage = storage(8);
        let buffers = arena(8);
        let receive = pool();
        let client_pool = pool();
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let (client_end, owner_end, net) = network(64, 8384, 71, [Faults::default(); 2]);
        let (mut owner, control) = start(
            &storage,
            &buffers,
            &receive,
            &[(key(1), 0, &object)],
            vec![owner_end],
        );
        let idle = buffers.report(PoolKind::ReadResponse).free;
        let mut client = client(0, &client_pool, &releases, client_end);
        let turn = open(
            &mut client,
            &mut owner,
            &control,
            &[std::rc::Rc::clone(&net)],
            0,
        );
        client
            .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
            .unwrap();
        let (held, turn) = hold_next_read(&mut client, &mut owner, &control, &net, turn);
        owner.authority_event(Event::Withdraw(Cause::Flipped), turn * 100);
        assert_eq!(owner.session_epoch(PeerId(0)), None, "the session ended");
        let sent = owner.report.sent;
        for at in 1..4 {
            owner.poll(turn * 100 + at);
        }
        let lent = buffers.report(PoolKind::ReadResponse).free < idle;
        let held_state = (owner.census().live(), lent);
        let custody = crate::storage::device::custody_witness::judged(&control, &buffers);
        control.release(held);
        control.tick(64);
        for at in 4..12 {
            owner.poll(turn * 100 + at);
            control.tick(64);
        }
        let report = owner.authority_report();
        LateTerminal {
            held: held_state,
            custody,
            token: held,
            sent: owner.report.sent - sent,
            after: (
                owner.census().live(),
                buffers.report(PoolKind::ReadResponse).free == idle,
            ),
            withdrawal: (report.withdrawal, report.flip.is_some()),
        }
    }

    /// A read command of a deposed tenure reaches its terminal after the owner observed the successor. Until that
    /// terminal the request stays live while the command holds its response buffers, so no later request is given
    /// them; the terminal's bytes are never sent, and after it the request ends and the buffers return to the pool.
    /// The withdrawal requests no flip.
    #[test]
    fn a_late_read_terminal_after_a_deposition_sends_nothing_and_keeps_its_buffers_until_then() {
        let run = late_read_terminal();
        assert_eq!(
            run.held,
            (1, true),
            "the request stays live while the held command keeps its response buffers"
        );
        assert_eq!(
            run.custody,
            (1, vec![run.token]),
            "the held command's buffer stays in storage custody"
        );
        assert_eq!(run.sent, 0, "PR-TEN-4: the late terminal sends nothing");
        assert_eq!(
            run.after,
            (0, true),
            "the terminal releases the request and every response buffer"
        );
        assert_eq!(run.withdrawal, (Some(Cause::Flipped), false));
    }

    /// The `RELEASE_UNDRAINED` plant releases a request at the withdrawal while its device command still holds its
    /// response buffers, so the live-request half of the late-terminal test's `held` assertion reads 0 where that test
    /// requires 1. The pool keeps lending the held command's buffers in both runs; the plant leaves buffer custody as
    /// it is, so the custody check judges the held command's buffer in storage custody here too.
    #[test]
    fn negative_control_a_request_released_at_withdrawal_leaves_its_buffers_with_the_device() {
        RELEASE_UNDRAINED.set(true);
        let run = late_read_terminal();
        RELEASE_UNDRAINED.set(false);
        assert_eq!(
            run.held,
            (0, true),
            "a request released while a device command holds its response buffers"
        );
        assert_eq!(
            run.custody,
            (1, vec![run.token]),
            "the plant leaves the held command's buffer in storage custody"
        );
    }

    /// A withdrawal followed by a `Close` before the owner observes either still ends the sessions and withholds fills at the next turn, and that turn returns while the test holds the pool gate.
    #[test]
    fn close_effects_run_at_the_first_observed_withdrawal_without_waiting_on_the_pool_gate() {
        use crate::net::fetch::Releases;
        use crate::net::owner_tests::{client, open};
        use crate::storage::Readiness;
        let storage = storage(8);
        let buffers = arena(8);
        let receive = pool();
        let client_pool = pool();
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let (client_end, owner_end, net) = network(64, 8384, 17, [Faults::default(); 2]);
        let (mut owner, control) = start(&storage, &buffers, &receive, &[], vec![owner_end]);
        let mut client = client(0, &client_pool, &releases, client_end);
        let turn = open(&mut client, &mut owner, &control, &[net], 0);
        assert!(owner.session_epoch(PeerId(0)).is_some());
        assert_eq!(owner.readiness(), Readiness::Live);
        owner
            .volume
            .authority_event(Event::Withdraw(Cause::Planned));
        owner.volume.authority_event(Event::Close);
        assert_eq!(owner.authority_report().state, State::Closed);
        assert_eq!(owner.close_effects, CloseEffects::Awaiting);
        storage.with_pool_gate_held(|| owner.poll(turn * 100));
        assert_eq!(owner.session_epoch(PeerId(0)), None, "the session ended");
        assert_eq!(owner.readiness(), Readiness::Withheld);
        assert_eq!(owner.close_effects, CloseEffects::GateOwed);
        owner.poll(turn * 100 + 100);
        assert_eq!(owner.close_effects, CloseEffects::Applied);
    }

    #[test]
    fn sender_round_rechecks_the_window_after_batch_preparation() {
        use std::{cell::Cell, rc::Rc};
        struct Clock(Rc<Cell<u64>>);
        impl crate::storage::ServingClock for Clock {
            fn now_us(&self) -> Option<u64> {
                Some(self.0.get())
            }
        }
        crate::net::put_tests::scene(&crate::net::owner_tests::PRINCIPALS, |mut scene| {
            let time = Rc::new(Cell::new(0));
            scene
                .owner
                .volume
                .set_serving_clock(Box::new(Clock(Rc::clone(&time))));
            let epoch = scene.owner.sessions.active(PeerId(0)).unwrap().epoch;
            let token = scene.owner.volume.serving_token();
            let Owner {
                volume,
                crc,
                ring,
                sessions,
                config,
                transport,
                headers,
                exhausted,
                report,
                ..
            } = &mut scene.owner;
            let mut sender = Sender {
                volume,
                token,
                crc: *crc,
                ring,
                sessions,
                endpoint: config.endpoint,
                transport,
                headers,
                exhausted,
                report,
            };
            let frame = Out {
                peer: PeerId(0),
                epoch,
                header: Header {
                    status: Status::Missing as u16,
                    ..header(Kind::Error, 1, [0; 32])
                },
                payload: [Payload::EMPTY; 2],
                body_crc: 0,
                digest: None,
            };
            let before = sender.report.sent;
            assert_eq!(
                sender.round::<SMALL_ROUND>(&mut std::iter::once(frame)),
                (1, true)
            );
            assert_eq!(
                sender.report.sent,
                before + 1,
                "the control frame reached the transport"
            );
            time.set(u64::MAX);
            assert_eq!(
                sender.round::<SMALL_ROUND>(&mut std::iter::once(frame)),
                (1, true)
            );
            assert_eq!(sender.report.sent, before + 1, "ResponseInIncarnation");
        });
    }
}

/// The owner's progress through a withdrawal's close effects, which start at the first turn that observes the machine's withdrawal cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseEffects {
    /// The owner awaits its first observation of a withdrawal cause.
    Awaiting,
    /// The sessions ended; each observation retries `Storage::try_withdraw` until the pool gate passes.
    GateOwed,
    Applied,
}

/// Whether the owner admits GETs and PUTs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    Open,
    /// A planned exit stops admission in stages while the owner serves GET hits. A successful [`Owner::resume`]
    /// restores `Open`.
    Draining(DrainStage),
    /// The volume was lost; later GETs and PUT BEGINs are refused `OwnerUnavailable`.
    Lost,
    /// The owner closed; it receives and sends nothing.
    Closed,
}

impl Admission {
    /// Ends admission for a lost volume; a closed owner stays closed.
    fn lose(&mut self) {
        if matches!(self, Self::Open | Self::Draining(_)) {
            *self = Self::Lost;
        }
    }
}

/// The stage of a planned drain, ordered `Fills` before `Mutations`. A drain starts at either stage and moves only to
/// a later one. `Fills` rejects PUT BEGIN with `Status::OwnerUnavailable` and terminates unpublished uploads.
/// `Mutations` also rejects INVALIDATE and every other membership change. The owner serves GET hits in both stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DrainStage {
    Fills,
    Mutations,
}

/// Where the withdrawn owner's planned transfer stands, as its driver records it through
/// [`Owner::transfer_submitted`], [`Owner::transfer_committed`] and [`Owner::transfer_settled`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handoff {
    /// The transfer write to `target` is submitted, or its refused or unknown outcome awaits the record read that
    /// decides between the exit and the one same-host restart.
    Outstanding {
        target: crate::failover::records::Host,
    },
    /// The store acknowledged the transfer: the record names the standby owner.
    Committed,
}

impl<'s, 'a, 'm, P: Platform, D: Disk, T: Datagrams<'a>> Owner<'s, 'a, 'm, P, D, T> {
    /// Starts an owner over `bundle`, serving the peers `keys` names through `transport`, receiving into `receive`.
    ///
    /// Volume ticks advance bootstrap while serving authority permits metadata.
    /// Replies and recovered reads require Serving and Live; fills also require
    /// AllocationReady. A Recovering or Unformatted volume keeps replies withheld.
    /// An unformatted volume requires an explicit [`format`](Self::format)
    /// before replay can reach Live; see [`begin_replay`](Self::begin_replay).
    ///
    /// # Errors
    ///
    /// `start` refuses at the first failing check, in this order: `Foreign`, `Caps`, `Requests`, `Puts`, `RunWaiters`,
    /// `FillCapacity`, `WatermarkFloor`, `GetReserve`, `Followers`, `Geometry`, `Capacity`, `Borrowed`, `Maintenance`, `Batch`, `Entropy`, `Keys`, `Permits`, then `Budget`.
    /// Each refusal returns `bundle` and `transport` with `budget` unchanged.
    /// `Keys` and `Permits` can also wrap budget failures during their own loads.
    pub fn start(
        config: OwnerConfig,
        bundle: Bundle<'s, 'a, P, D>,
        keys: Keys<'_>,
        transport: T,
        receive: &'m PacketPool<'a>,
        budget: &mut EngineBudget,
    ) -> Result<Self, Box<Refused<'s, 'a, P, D, T>>> {
        Self::start_with_nonce(config, bundle, keys, transport, receive, budget, os_entropy)
    }

    /// [`start`](Self::start) with the boot nonce filled by `nonce` where
    /// `start` reads the operating system's entropy: `nonce` runs only after
    /// the checks through `Batch` pass and before `Keys`.
    ///
    /// # Errors
    ///
    /// As [`start`](Self::start).
    pub(crate) fn start_with_nonce(
        config: OwnerConfig,
        bundle: Bundle<'s, 'a, P, D>,
        keys: Keys<'_>,
        transport: T,
        receive: &'m PacketPool<'a>,
        budget: &mut EngineBudget,
        nonce: impl FnOnce(&mut [u8; 16]) -> Result<(), EntropyError>,
    ) -> Result<Self, Box<Refused<'s, 'a, P, D, T>>> {
        let refuse = |error, bundle, transport| {
            Err(Box::new(Refused {
                error,
                bundle,
                transport,
            }))
        };
        let shape = bundle.volume.read_shape();
        let storage = bundle.volume.storage();
        if !std::ptr::eq(bundle.cache.storage(), storage)
            || !std::ptr::eq(bundle.registration.storage(), storage)
        {
            return refuse(OwnerError::Foreign, bundle, transport);
        }
        if !(1..=MAX_SLOT_CAP).contains(&config.caps.slots)
            || !(1..=MAX_WINDOW).contains(&config.caps.window)
        {
            return refuse(OwnerError::Caps, bundle, transport);
        }
        let peers = u16::try_from(keys.principals.len()).unwrap_or(0);
        let (slots, share) = (config.request_slots, config.peer_requests);
        let shares = u64::from(peers) * u64::from(share);
        if peers == 0
            || slots == 0
            || slots > super::requests::MAX_REQUEST_SLOTS
            || share == 0
            || shares > u64::from(slots)
            || config.serve.slots < config.caps.slots
            || config.serve.replies == 0
        {
            return refuse(OwnerError::Requests, bundle, transport);
        }
        let write_cap = u64::from(bundle.volume.write_share());
        let segment_len = bundle.volume.segment_len();
        if !config
            .put
            .fits((peers, slots), (receive.data_cap(), write_cap, segment_len))
        {
            return refuse(OwnerError::Puts, bundle, transport);
        }
        let (puts, run_waiters) = (config.put.puts, config.put.run_waiters);
        if puts > 0 && !(1..=puts).contains(&run_waiters) {
            return refuse(
                OwnerError::RunWaiters { run_waiters, puts },
                bundle,
                transport,
            );
        }
        let capacity = storage.fill_capacity();
        if puts as usize > capacity {
            return refuse(
                OwnerError::FillCapacity { puts, capacity },
                bundle,
                transport,
            );
        }
        if puts > 0
            && let Some(terms) = storage.floor_terms()
            && let Some(marks) = terms.marks
        {
            let floor = terms.floor(puts);
            if !floor.is_ok_and(|floor| marks.low_units >= floor) {
                let low_units = marks.low_units;
                return refuse(
                    OwnerError::WatermarkFloor { low_units, floor },
                    bundle,
                    transport,
                );
            }
        }
        if !config.reserves_fit() {
            return refuse(OwnerError::GetReserve, bundle, transport);
        }
        if !config.follow.fits() {
            return refuse(OwnerError::Followers, bundle, transport);
        }
        if let Err(error) = FragmentGeometry::new(inputs(&shape)) {
            return refuse(OwnerError::Geometry(error), bundle, transport);
        }
        let buffers = u64::from(slots) * u64::from(BUFFERS_PER_READ + u32::from(shape.read_ahead));
        if slots > shape.read_ops || buffers > u64::from(shape.response_buffers) {
            let error = OwnerError::Capacity {
                slots,
                read_ops: shape.read_ops,
                buffers: shape.response_buffers,
            };
            return refuse(error, bundle, transport);
        }
        if shape.response_free != shape.response_buffers {
            return refuse(OwnerError::Borrowed, bundle, transport);
        }
        if config.maintain_work != 0 && config.maintain_work < storage.maintain_minimum() {
            return refuse(
                OwnerError::Maintenance {
                    minimum: storage.maintain_minimum(),
                },
                bundle,
                transport,
            );
        }
        if config.batch < 2
            || u64::from(config.batch) + u64::from(transport.rx_ring())
                > u64::from(receive.control_reserve())
        {
            return refuse(OwnerError::Batch, bundle, transport);
        }
        let nonce = match nonce_from(nonce) {
            Ok(nonce) => nonce,
            Err(error) => return refuse(OwnerError::Entropy(error), bundle, transport),
        };
        let mut staged = *budget;
        let ring = match KeyRing::load(keys.principals, keys.entries, keys.epoch, &mut staged) {
            Ok(ring) => ring,
            Err(error) => return refuse(OwnerError::Keys(error), bundle, transport),
        };
        let permits = match PutPermits::load(&ring, keys.put, &mut staged) {
            Ok(permits) => permits,
            Err(error) => return refuse(OwnerError::Permits(error), bundle, transport),
        };
        let batch = config.batch as usize;
        let headers = batch.min(SEND_ROUND);
        let window = window_width(&config, storage);
        let fragments = FragmentGeometry::fragments(storage.payload_cap() as u64) as u32;
        let turn = Self::charges(&config, &bundle.volume, peers)
            .map_or(usize::MAX, |charges| charges.request_table);
        // Each charge lands on `staged`, a copy that replaces `budget` only once every part is built.
        let built = staged.charge(turn).and_then(|()| {
            let sessions = Sessions::new(Role::Owner, nonce, config.caps, peers, &mut staged)?;
            let requests = Requests::new(
                RequestTable::new(slots, peers, share),
                config.serve.slots,
                &mut staged,
            )?;
            let mut serve = ServeCore::new(
                config.serve,
                &requests,
                config.batch,
                0,
                shape.read_windows,
                &mut staged,
            )?;
            serve.read_ahead(shape.read_ahead);
            let limits = PutLimits {
                linger_us: config.serve.linger_us,
                max_wait_us: config.serve.max_wait_us,
                tries: config.lookup_retries,
                work: config.lookup_work,
                fragments,
                write_cap,
            };
            let put = PutCore::new(config.put, &limits, &requests, &mut staged)?;
            Ok((sessions, requests, serve, put))
        });
        let (sessions, requests, serve, put) = match built {
            Ok(parts) => parts,
            Err(error) => return refuse(OwnerError::Budget(error), bundle, transport),
        };
        *budget = staged;
        let Bundle {
            cache,
            registration,
            volume,
        } = bundle;
        let reaped_at = volume.response_holds_ended();
        let authority_seen = (volume.authority_state(), volume.serving_token());
        Ok(Self {
            config,
            crc: crate::storage::Crc32c::detect(),
            cache,
            registration,
            volume,
            requests,
            serve,
            put,
            ring,
            permits,
            sessions,
            ownership_view: super::owner_view::OwnerView::default(),
            ownership: vec![None; usize::from(peers)].into_boxed_slice(),
            ownership_queued: vec![0; usize::from(peers).div_ceil(64)].into_boxed_slice(),
            ownership_waiting: 0,
            ownership_cursor: 0,
            ownership_leads: false,
            transport,
            receive,
            scratch: std::iter::repeat_with(|| None).take(batch).collect(),
            meta: vec![Received::default(); batch].into_boxed_slice(),
            window: vec![[0; 32]; window].into_boxed_slice(),
            tags: vec![[0; TAG_LEN]; window].into_boxed_slice(),
            preparation: Preparation::new(storage),
            #[cfg(test)]
            windows: Windows::default(),
            #[cfg(test)]
            window_charge: Self::window_bytes(window),
            headers: vec![[0; HEADER_LEN]; headers].into_boxed_slice(),
            replies: vec![None; usize::from(peers)].into_boxed_slice(),
            waiting: 0,
            reply_cursor: 0,
            exhausted: Vec::with_capacity(usize::from(peers)),
            bound: vec![None; slots as usize].into_boxed_slice(),
            parked: Parked::new(config.follow, slots, peers),
            reads: 0,
            by_op: vec![None; shape.read_ops as usize].into_boxed_slice(),
            events: Vec::with_capacity(events(&shape)),
            peers,
            admission: Admission::Open,
            exit: None,
            handoff: None,
            authority_seen,
            close_effects: CloseEffects::Awaiting,
            quiesce: None,
            maintain_rest_until_us: None,
            #[cfg(test)]
            maintain_spent: (0, false),
            #[cfg(test)]
            turn_stages: (0, 0),
            #[cfg(test)]
            run_wait_woke: false,
            reaped_at,
            regrant: true,
            armed: false,
            poisoned: false,
            coverage: None,
            published_locally: false,
            invalidations: Vec::with_capacity(INVALIDATIONS),
            page_entries: Vec::with_capacity(INVALIDATIONS),
            covering: false,
            last_poll_us: None,
            turn_start: TurnSources::default(),
            last_turn: TurnSources::default(),
            report: OwnerReport::default(),
        })
    }

    /// The bytes [`start`](Self::start) charges by part, or `None` when a sum overflows.
    pub fn charges(
        config: &OwnerConfig,
        volume: &Volume<'s, 'a, P, D>,
        peers: u16,
    ) -> Option<OwnerCharges> {
        let shape = &volume.read_shape();
        let storage = volume.storage();
        let window = window_width(config, storage);
        let fragments = FragmentGeometry::fragments(storage.payload_cap() as u64) as u32;
        let (slots, batch) = (config.request_slots, config.batch as usize);
        let headers = batch.min(SEND_ROUND);
        let peer_count = usize::from(peers);
        let scratch = batch
            .checked_mul(size_of::<Option<PacketLease<'m>>>() + size_of::<Received>())?
            .checked_add(headers.checked_mul(HEADER_LEN)?)?
            .checked_add(peer_count.checked_mul(
                size_of::<Option<Bootstrap>>()
                    + size_of::<PeerId>()
                    + size_of::<Option<OwnershipReply>>(),
            )?)?
            .checked_add(peer_count.div_ceil(64).checked_mul(size_of::<u64>())?)?
            .checked_add((slots as usize).checked_mul(size_of::<Option<Bound>>())?)?
            .checked_add((shape.read_ops as usize).checked_mul(size_of::<Option<u16>>())?)?
            .checked_add(events(shape).checked_mul(size_of::<ReadEvent<'a>>())?)?
            .checked_add(Parked::<'s, P>::bytes(config.follow, slots, peers))?
            .checked_add(Self::window_bytes(window))?
            .checked_add(INVALIDATIONS * (size_of::<Held>() + size_of::<CoverageEntry>()))?;
        let table = RequestTable::<Request<ValidatedChunk<'a>, Put<'s, 'a, P>>>::metadata_bytes(
            slots, peers,
        )?;
        Some(OwnerCharges {
            keys: KeyRing::charge(peer_count).checked_add(PutPermits::charge(peer_count))?,
            request_table: table.checked_add(scratch)?,
            sessions: Sessions::charge(peers, config.caps.window),
            wire_slots: super::namespace::Namespace::<
                Request<ValidatedChunk<'a>, Put<'s, 'a, P>>,
                super::served::Outcome,
            >::charge(config.serve.slots, peers, slots)?,
            serve: ServeCore::charge(
                &config.serve,
                peers,
                slots,
                config.batch,
                shape.read_windows,
            )?,
            put: PutCore::<'m>::charge(&config.put, (peers, slots), fragments)?,
        })
    }

    /// Bytes of a receive window of `window` keys, their tags and the lookahead.
    fn window_bytes(window: usize) -> usize {
        std::alloc::Layout::array::<Key>(window)
            .map_or(usize::MAX, |layout| layout.size())
            .saturating_add(
                std::alloc::Layout::array::<[u8; TAG_LEN]>(window)
                    .map_or(usize::MAX, |layout| layout.size()),
            )
            .saturating_add(size_of::<Preparation<'s, P>>())
    }

    /// The owner's counters, with the retained census taken at the call.
    pub fn report(&self) -> OwnerReport {
        let table = self.volume.table_report();
        OwnerReport {
            wrong_operation: self.requests.wrong_operation(),
            parked: self.parked.report(),
            retained: RetainedCensus {
                buffers: self.volume.held_buffers(),
                commands: table.pending + table.abandoned,
                packets: self.receive.not_free(),
            },
            ..self.report
        }
    }

    /// Checks `peer`'s configured PUT grant, which stays fixed across re-key.
    /// The check preserves request, session and storage state.
    ///
    /// # Errors
    ///
    /// [`Status::PermissionDenied`] for a peer the configuration did not grant PUT.
    pub fn put_permission(&self, peer: PeerId) -> Result<(), Status> {
        self.permits.check(peer)
    }

    pub fn put_report(&self) -> super::put::PutReport {
        self.put.report()
    }

    pub fn serve_report(&self) -> super::serve::ServeReport {
        self.serve.report()
    }

    pub fn volume_report(&self) -> crate::storage::VolumeReport {
        self.volume.report()
    }

    /// The volume's recovery report; see [`Volume::recovery_report`](crate::storage::Volume::recovery_report).
    pub fn recovery_report(&self) -> crate::storage::RecoveryReport {
        self.volume.recovery_report()
    }

    /// The volume's metadata outcome; see [`Volume::metadata_outcome`](crate::storage::Volume::metadata_outcome).
    pub fn volume_metadata_outcome(&self) -> crate::storage::MetadataOutcome {
        self.volume.metadata_outcome()
    }

    /// Every command the volume accepted with the owner its token was bound to; see `Volume::bound_tokens`.
    #[cfg(test)]
    pub(crate) fn volume_bound(
        &self,
    ) -> (
        &[(crate::storage::CommandToken, crate::storage::Bound)],
        bool,
    ) {
        self.volume.bound_tokens()
    }

    /// See `PutCore::track_validated`.
    #[cfg(test)]
    pub(crate) fn track_put_validation(&mut self) {
        self.put.track_validated();
    }

    /// See `PutCore::validated`.
    #[cfg(test)]
    pub(crate) fn put_validated(&self) -> (&[super::put::Validation], bool) {
        self.put.validated()
    }

    /// Bytes the last turn's copies and resend comparisons charged against its copy budget.
    #[cfg(test)]
    pub(crate) fn put_turn_copy_bytes(&self) -> usize {
        self.put.turn_copy_bytes()
    }

    /// Steps the last turn's maintenance call spent, zero for a turn that made none, and whether its allowance stopped the call in front of a stage it could not fund.
    #[cfg(test)]
    pub(crate) fn maintain_spent(&self) -> (usize, bool) {
        self.maintain_spent
    }

    /// The parked GETs as a test observes them.
    #[cfg(test)]
    pub(super) fn parked_view(&self) -> super::parked::ParkedView {
        let mut view = self.parked.view();
        view.deadlines = view
            .entries
            .iter()
            .map(|(id, _, _)| {
                self.requests
                    .serve(*id)
                    .map_or(0, |serve| serve.deadline_us())
            })
            .collect();
        view
    }

    /// GETs parked now.
    #[cfg(test)]
    pub(crate) fn parked_count(&self) -> u32 {
        self.parked.count()
    }

    /// Visits and check observations the last turn's wake and detach pass made.
    #[cfg(test)]
    pub(crate) fn wake_visits(&self) -> u32 {
        self.parked.visits()
    }

    /// Receive batches and storage ticks the last turn ran.
    #[cfg(test)]
    pub(crate) fn turn_stages(&self) -> (u32, u32) {
        self.turn_stages
    }

    /// Whether the last turn's PUT core admitted a placement as a run waiter under the cap.
    #[cfg(test)]
    pub(crate) fn run_wait_woke(&self) -> bool {
        self.run_wait_woke
    }

    #[cfg(test)]
    pub(crate) fn check_marked_waiters(&self) -> Result<(), String> {
        self.put.check_marked_waiters(&self.requests)
    }

    #[cfg(test)]
    pub(crate) fn check_put_holding(&self) -> Result<(), String> {
        self.put.check_holding(&self.requests)
    }

    #[cfg(test)]
    pub(crate) fn put_lends(&self) -> bool {
        self.put.lends()
    }

    #[cfg(test)]
    pub(crate) fn put_admission_order(&self) -> Vec<u32> {
        self.put.admission_order()
    }

    /// Checks the parked GETs against the request census: each parked request is live in the namespace and bound to no read, the parked count is at most the live requests, each peer's parked count is at most its live requests, and the parked table's due set and fill tracking match its entries.
    #[cfg(test)]
    pub(crate) fn check_parked_census(&self) -> Result<(), String> {
        self.parked.check_tracking()?;
        let view = self.parked.view();
        for &(id, peer, _) in &view.entries {
            if self.requests.serve(id).is_none() {
                return Err(format!("parked {id:?} is not a live GET"));
            }
            if self.bound[usize::from(id.slot())].is_some_and(|read| read.request == id) {
                return Err(format!("parked {id:?} is also bound to a read"));
            }
            let share = self.requests.table().peer_census(peer);
            let parked = view.by_peer[usize::from(peer.0)];
            if parked > share.active + share.draining {
                return Err(format!("{peer:?} parks {parked} beyond its {share:?}"));
            }
        }
        let census = self.requests.census();
        if view.count as usize != view.entries.len() || view.count > census.live() {
            return Err(format!("{} parked beside {census:?}", view.count));
        }
        Ok(())
    }

    /// Runs the driver's housekeeping once the volume's attach gate passed, through [`Volume::service_disk`]; see [`Disk::service`].
    pub fn service_disk(&mut self) {
        self.volume.service_disk();
    }

    /// The owner's live requests, active and draining.
    pub fn census(&self) -> super::requests::RequestCensus {
        self.requests.census()
    }

    /// The requests the owner answered over its life: the GETs whose COMPLETE or ERROR frame the transport took,
    /// and the PUTs that reached their published or failed terminal, which queues the PUT's result or error for
    /// its peer. A request counts once, at that point, so the count holds still while requests wait on the device
    /// or on a fill, and a datagram that ends no request adds nothing.
    pub fn answered(&self) -> u64 {
        let (serve, put) = (self.serve.report(), self.put.report());
        serve.completed
            + serve.errors
            + put.published
            + put.failed_timed_out
            + put.cancelled
            + put.failed_other
    }

    /// The session table's counters.
    #[cfg(test)]
    pub(crate) fn session_report(&self) -> super::session::SessionReport {
        self.sessions.report()
    }

    /// The epoch of `peer`'s active session at this owner, if any.
    #[cfg(test)]
    pub(crate) fn session_epoch(&self, peer: PeerId) -> Option<u64> {
        self.sessions.active(peer).map(|admitted| admitted.epoch)
    }

    #[cfg(test)]
    pub(crate) fn set_deferral_window(&mut self, window: u64) {
        self.volume.set_deferral_window(window);
    }

    #[cfg(test)]
    pub(crate) fn end_sessions(&mut self) {
        self.sessions.end_sessions();
    }

    #[cfg(test)]
    pub(crate) fn set_serving_clock(&mut self, clock: Box<dyn crate::storage::ServingClock>) {
        self.volume.set_serving_clock(clock);
    }

    /// See `Volume::assume_warm`.
    #[cfg(test)]
    pub(crate) fn assume_warm(
        &mut self,
        load: crate::storage::SlotLoad,
        coverage: crate::storage::page_coverage::Coverage,
    ) -> Result<(), ()> {
        self.volume.assume_warm(load, coverage)
    }

    /// The live requests charged to `peer`'s share.
    #[cfg(test)]
    pub(crate) fn peer_census(&self, peer: PeerId) -> super::requests::PeerCensus {
        self.requests.table().peer_census(peer)
    }

    #[cfg(test)]
    pub(super) fn request_slot(
        &self,
        peer: PeerId,
        slot: u16,
    ) -> Option<super::namespace::WireSlot<super::served::Outcome>> {
        self.requests.slot(peer, slot)
    }

    #[cfg(test)]
    pub(super) fn put_occupancy(&self) -> super::put::Occupancy {
        self.put.occupancy(&self.requests)
    }

    /// See [`PutCore::ready_lanes`](super::put::PutCore::ready_lanes).
    #[cfg(test)]
    pub(super) fn put_ready_lanes(&self) -> Vec<(u32, usize)> {
        self.put.ready_lanes(&self.requests)
    }

    /// See `Volume::unwound_writes`.
    #[cfg(test)]
    pub(super) fn unwound_writes(&self) -> u32 {
        self.volume.unwound_writes()
    }

    /// The live PUTs whose fill waits for a free run, read from their stages, an independent check on the PUT core's count.
    #[cfg(test)]
    pub(super) fn waiting_placements(&self) -> u32 {
        super::put::waiting_placements(&self.requests)
    }

    /// See [`RequestTable::start_slot_at`].
    #[cfg(test)]
    pub(super) fn start_request_slot_at(&mut self, slot: u16, generation: u64) {
        self.requests.start_slot_at(slot, generation);
    }

    /// See [`Namespace::forget_unbound`](super::namespace::Namespace::forget_unbound).
    #[cfg(test)]
    pub(super) fn forget_unbound_requests(&mut self) {
        self.requests.forget_unbound();
    }

    /// One turn at `now_us`, which is also the volume's tick value; it does bounded, nonblocking work outside the warm
    /// bootstrap, whose ticks the `volume` module's Tick bounds state.
    pub fn poll(&mut self, now_us: u64) {
        self.observe_unwind();
        self.armed = true;
        self.observe_gap(now_us);
        self.turn_start = self.turn_sources();
        self.put.begin_turn();
        // Device returns arrive through the transport even while the owner is closed, so draining requests release; taking them first lets this turn's ACKs and reap drop the chunks they free.
        self.transport.reclaim();
        #[cfg(test)]
        {
            self.turn_stages = (0, 0);
        }
        self.volume.poll_terminals(now_us, &self.events);
        self.observe_authority(now_us);
        if self.admission != Admission::Closed {
            #[cfg(test)]
            {
                self.turn_stages.0 += 1;
            }
            self.receive_batch(now_us);
        }
        self.serve.tick(&mut self.requests, now_us);
        self.put.tick(&mut self.requests, &mut self.serve, now_us);
        self.cancel_ended();
        self.wake(now_us);
        // Chunks whose last device reference returned drop before drain and grants read the retained counts; a holder's chunk becomes droppable only after such a return, which the pool's count records.
        let holds_ended = self.volume.response_holds_ended();
        if holds_ended != self.reaped_at {
            self.reaped_at = holds_ended;
            self.serve.reap(&mut self.requests);
            self.regrant = true;
        }
        self.grant();
        #[cfg(test)]
        {
            self.turn_stages.1 += 1;
        }
        self.volume.poll_storage_prepared(now_us, &mut self.events);
        self.observe_authority(now_us);
        self.deliver(now_us);
        self.put.progress(
            &mut self.requests,
            &mut self.serve,
            &mut self.volume,
            self.coverage.as_ref(),
            now_us,
        );
        self.put.flush_acks(&mut self.requests, &mut self.serve);
        if self.admission == Admission::Closed {
            if !self.quiesced() {
                self.quiesce = Some(self.volume.close());
            }
        } else {
            self.send_batch(now_us);
        }
        self.release();
        if now_us >= self.serve.control_due_us() {
            let exceeded = self.transport.egress_exceeded();
            self.serve.control(now_us, exceeded);
        }
        let released = self.put.take_released();
        let run_waiter = self.put.take_run_waiter();
        #[cfg(test)]
        {
            self.run_wait_woke = run_waiter;
        }
        if released || run_waiter {
            self.maintain_rest_until_us = None;
        }
        if self.put.take_lost() {
            self.admission.lose();
        }
        self.maintain(now_us);
        self.end_turn_sources();
        self.armed = false;
    }

    /// State or token changes retire buffered work before a new incarnation can send it. The first observation of a withdrawal cause ends every session and starts the readiness withdrawal, whatever state the machine reached since; each call makes one nonblocking pool gate attempt until the withdrawal completes, so the owner's turn never waits on another thread's hold.
    fn observe_authority(&mut self, now_us: u64) {
        let seen = (self.volume.authority_state(), self.volume.serving_token());
        if seen != self.authority_seen {
            let tenure = seen.1.map(super::owner_view::tenure_of);
            let withdrawn = matches!(
                seen.0,
                crate::failover::serving::State::Closed
                    | crate::failover::serving::State::Withdrawn
            );
            if tenure != self.authority_seen.1.map(super::owner_view::tenure_of) || withdrawn {
                self.sessions.end_sessions();
            }
            for peer in 0..self.peers {
                self.retire_peer(PeerId(peer), now_us, Some(FillFailure::Closed));
            }
            self.authority_seen = seen;
            if let Some(exit) = self.exit.as_mut().filter(|_| withdrawn) {
                exit.withdrawn();
            }
        }
        if self.close_effects == CloseEffects::Awaiting
            && self.volume.authority_withdrawal().is_some()
        {
            self.sessions.end_sessions();
            self.close_effects = CloseEffects::GateOwed;
        }
        if self.close_effects == CloseEffects::GateOwed && self.volume.storage().try_withdraw() {
            self.close_effects = CloseEffects::Applied;
        }
    }

    /// The caller must verify that `owner` binds the record's host to its attachment identifier. A `None` read is one
    /// that returned no value, a store timeout or an unavailable store, and is no evidence. An observation in which
    /// both reads returned a value sets the owner's serving judgment, a returned read that contradicts the view clears
    /// it whatever the other read returned, and a deposition a returned read shows withdraws the tenure. A caller passes a record the store refused for its contents to the authority as a withdrawal cause.
    pub fn observe_shard_view(
        &mut self,
        own: crate::failover::records::VolumeId,
        shard: Option<&crate::storage::store::Read<crate::failover::records::ShardRecord>>,
        volume: Option<&crate::storage::store::Read<crate::failover::records::VolumeRecord>>,
        owner: Option<(
            crate::failover::records::Host,
            crate::failover::identity::Exhid,
        )>,
        now_us: u64,
    ) {
        let session = self.volume.tenure();
        if let Some(cause) = self
            .ownership_view
            .observe(session, own, shard, volume, owner, now_us)
        {
            self.authority_event(crate::failover::serving::Event::Withdraw(cause), now_us);
        }
        if let Some(exit) = self.exit.as_mut() {
            let authority = self.volume.authority_report();
            let shard = shard.map(crate::storage::store::Read::value);
            match self.handoff {
                Some(_) => exit.observe_handoff(&authority, shard),
                None => exit.observe(&authority, shard),
            }
        }
    }
    pub fn authority_report(&self) -> crate::storage::AuthorityReport {
        self.volume.authority_report()
    }

    #[cfg(test)]
    pub(crate) fn withhold(&self) -> crate::failover::withhold::Withhold {
        self.volume.withhold()
    }

    pub fn poll_report(
        &self,
    ) -> Result<crate::storage::PolledReport, crate::failover::evidence::NotSole> {
        self.volume.poll_report()
    }

    /// The serving clock's reading at the authority's latest deadline sample, the time base of
    /// `Event::Refresh` and `Event::ReadFailed`.
    pub fn serving_sample(&self) -> u64 {
        self.volume.serving_sample()
    }

    /// The owner's poll over `report` and the `reads` the caller sent at the serving-clock sample `sent_at`
    /// ([`Self::serving_sample`]) after it took `report`: a tenure withdrawn with `Cause::Unverified` measures the
    /// Report's age at that sample, as [`Volume::owner_poll`](crate::storage::Volume::owner_poll) states.
    pub fn owner_poll(
        &mut self,
        holder: &crate::failover::poll::Holder,
        report: Result<&crate::failover::evidence::Report<'_>, crate::failover::evidence::NotSole>,
        reads: &crate::failover::poll::Reads<'_>,
        sent_at: u64,
        now_us: u64,
    ) -> crate::failover::poll::Verdict {
        self.observe_unwind();
        let target = self.tenure().target();
        let verdict = match self.volume.serving_token() {
            Some(token) => {
                let own = crate::failover::evidence::Pair {
                    exhid: token.exhid,
                    key: token.key,
                };
                self.volume
                    .owner_poll(holder, target, own, report, reads, sent_at)
            }
            None => crate::failover::poll::Verdict::Unobserved,
        };
        self.observe_authority(now_us);
        verdict
    }

    /// The owner's reclaim step after [`Self::owner_poll`] returned `verdict` over `report` and `volume`:
    /// [`Volume::owner_reclaim`](crate::storage::Volume::owner_reclaim) for this tenure's serving pair. It returns the
    /// ended pairs the caller drops from `volume` through its store lane, and none without a serving token.
    pub fn owner_reclaim(
        &mut self,
        standby: &crate::failover::reconcile::StandbyGate,
        holder: &crate::failover::poll::Holder,
        verdict: &crate::failover::poll::Verdict,
        report: Result<&crate::failover::evidence::Report<'_>, crate::failover::evidence::NotSole>,
        volume: &crate::failover::records::VolumeRecord,
    ) -> Vec<crate::failover::evidence::Pair> {
        self.observe_unwind();
        if self.poisoned() {
            return Vec::new();
        }
        self.volume
            .owner_reclaim(standby, holder, verdict, report, volume)
    }

    /// The host report's entry for the owner's volume at `now_us`, from the owner's own state and the driver's
    /// `observed` part, or `None` before a shard view observation names the volume. `now_us` is the turn clock that
    /// [`Self::observe_shard_view`] receives, which the checkpoint age counts on; the writer's seal stamp is a
    /// separate wall-clock reading. The entry holds the values at this call, and sealing refreshes none. `now_us` also
    /// dates the recovery part's age and selects the recovery I/O share's window that `full` reads.
    ///
    /// The last observed records give the role, the volume state, the checkpoint and its age, `named`, and the
    /// history pressure, which reads the last accepted shard record over the layout of the last own-volume read
    /// while that record names the own volume active. The owner's state gives the authority fields, the registrant
    /// judgment and hold of the last evaluated Report, the readiness word, the metadata outcome and the warm load's
    /// refusal, the recovery times, unavailable for an attach whose first observation preceded its first tick, and
    /// the retention account of the attach's recovery report, the recovery I/O share's peak window, the live
    /// attaches of the last own-volume read, the coverage page census, the suffix backlog on the platform clock,
    /// the held INVALIDATEs, and the attach's read counts: its complete reads, and its reads that failed their
    /// identity or checksum check other than a first extent's key mismatch, which the read answers `Missing`. The
    /// retention account is present once the warm load commits, or ends `Unloadable`, `Collided` or
    /// `MetadataFailed` after its stage recorded the decoded load's account, and then fixed for the attach.
    /// `observed` gives the enumeration, the store alarm and counts, the recovery status, the capture counts, the
    /// quarantine gauge, `publication_due` from its suffix signal, and the roll flags, which the entry copies and
    /// derives from no other source; a quarantine gauge whose count exceeds its limit reads unavailable.
    /// The attach's counts restart with each tenure.
    pub fn report_entry(
        &self,
        now_us: u64,
        observed: &crate::failover::report::Observed,
    ) -> Option<crate::failover::report::VolumeEntry> {
        self.ownership_view.recorded()?;
        self.report_entry_at(self.volume.authority_report(), now_us, observed)
    }

    /// [`Self::report_entry`] with the authority fields of `authority`, a report [`Self::authority_report`] returned
    /// since the owner's state last changed. The call reads no serving clock, so a caller that dates other values
    /// by `authority` publishes them and the entry at one reading.
    pub fn report_entry_at(
        &self,
        authority: crate::storage::AuthorityReport,
        now_us: u64,
        observed: &crate::failover::report::Observed,
    ) -> Option<crate::failover::report::VolumeEntry> {
        use crate::failover::records::MAX_ATTACHED;
        use crate::failover::report::{
            Backlog, Coverage, ExitTracker, Gauge, Hold, Metadata, Pressure, Recovery, RecoveryIo,
            RecoveryTimes, Refusal, Registrants, Retention, StoreOutcomes, VolumeEntry, Watermark,
            Withdrawal,
        };
        let recorded = self.ownership_view.recorded()?;
        let recovery = self.volume.recovery_record();
        let (io_peak, io_saturated) = self.volume.recovery_io_peak();
        let reads = self.volume.counters();
        let metadata = self.volume.metadata_outcome();
        let census = self.coverage.as_ref().and_then(Fencing::census);
        let gauge = |used: usize, limit: usize| Gauge::known(used as u64, limit as u64);
        Some(VolumeEntry {
            volume: recorded.volume,
            shard: self.volume.tenure().shard(),
            role: recorded.role,
            tenure: Some(authority.tenure),
            volume_state: recorded.state,
            serving: Some(authority.state),
            withheld: authority.withheld,
            // No attach ends quarantined, so bit 1 of the entry's flags byte stays zero in the report's wire layout.
            quarantine: false,
            flip: authority.flip.is_some(),
            withdrawal: authority.withdrawal.map(Withdrawal::from),
            refusal: authority.refusal.map(Refusal::from),
            enumeration: observed.enumeration,
            watermark: observed
                .alarm
                .map_or(Watermark::Unavailable, Watermark::from),
            report_age_us: authority.report_age_us,
            own_records: authority.own_records,
            checkpoint: recorded.named_since.map(|(checkpoint, _)| checkpoint),
            checkpoint_age_us: recorded
                .named_since
                .and_then(|(_, at)| now_us.checked_sub(at)),
            captures: observed.captures,
            exit: self.exit.as_ref().and_then(ExitTracker::last),
            pressure: Pressure {
                quarantine: match observed.quarantine {
                    Gauge::Known { used, limit } => Gauge::known(used, limit.get()),
                    Gauge::Unavailable => Gauge::Unavailable,
                },
                ..Pressure::recorded(
                    recorded.shard,
                    recorded
                        .layout
                        .filter(|_| recorded.shard.is_some_and(|r| r.active == recorded.volume)),
                    self.volume.recovery_io_full(now_us),
                )
            },
            registrants: authority.registrants.map(Registrants::from),
            hold: Some(Hold::from(authority.hold)),
            readiness: Some(self.readiness()),
            metadata: Some(Metadata::from(&metadata)),
            load_refusal: match metadata {
                crate::storage::MetadataOutcome::Unloadable(refusal) => Some(refusal),
                _ => None,
            },
            recovery: observed
                .recovery
                .map_or(Recovery::UNAVAILABLE, |status| status.recovery(now_us)),
            phase: None,
            ended: None,
            named: recorded.named,
            roll_due: observed.roll_due,
            roll_active: observed.roll_active,
            publication_due: observed.suffix_due.map(|due| due.publication),
            times: if self.volume.recovery_timed() {
                RecoveryTimes::of(recovery)
            } else {
                RecoveryTimes::UNAVAILABLE
            },
            retention: self.volume.warm_decided().then(|| Retention::of(recovery)),
            suffix: self
                .volume
                .storage()
                .suffix_backlog()
                .map_or(Backlog::UNAVAILABLE, Backlog::from),
            recovery_io: RecoveryIo {
                peak: Gauge::known(io_peak, self.volume.recovery_io_limit()),
                saturated: Some(io_saturated),
            },
            attaches: recorded
                .attaches
                .map_or(Gauge::Unavailable, |live| gauge(live, MAX_ATTACHED)),
            store: observed
                .store
                .map_or(StoreOutcomes::UNAVAILABLE, StoreOutcomes::from),
            coverage: census.map_or(Coverage::UNAVAILABLE, |census| Coverage {
                saturated: gauge(census.saturated, census.pages),
                largest: gauge(census.largest, census.capacity),
            }),
            invalidations: gauge(self.held_invalidations(), INVALIDATIONS),
            read_defects: Some(crate::failover::report::read_defects(reads)),
            served: Some(reads.complete),
        })
    }

    /// Makes the volume's recovery I/O share refuse a charge in the window open at `now_us`.
    #[cfg(test)]
    pub(crate) fn refuse_recovery_io(&mut self, now_us: u64) {
        self.volume.refuse_recovery_io(now_us);
    }

    /// Applies `event` to the serving machine and observes the authority at `now_us`. The first observed withdrawal cause ends every session and withholds readiness before this returns; the pool gate takes one nonblocking attempt here and stays owed to a later observation while another holder keeps it.
    pub fn authority_event(
        &mut self,
        event: crate::failover::serving::Event,
        now_us: u64,
    ) -> crate::failover::serving::Outcome {
        let outcome = self.volume.authority_event(event);
        self.observe_authority(now_us);
        outcome
    }

    /// Unwinding skips the turn's normal completion, so [`observe_unwind`](Self::observe_unwind) calls this
    /// before the next gap reads `last_turn`.
    fn end_turn_sources(&mut self) {
        let (now, start) = (self.turn_sources(), self.turn_start);
        self.last_turn = TurnSources {
            received: now.received - start.received,
            sent: now.sent - start.sent,
            published: now.published - start.published,
        };
    }

    /// The counters a turn's sources move, as they stand.
    fn turn_sources(&self) -> TurnSources {
        TurnSources {
            received: self.report.received,
            sent: self.report.sent,
            published: self.put.report().published,
        }
    }

    /// The gap from the previous turn's start to `now_us` lands in its bucket, and the longest gap keeps that turn's sources. Gaps start at the second turn; the first gap sets the maximum even at zero, and a tie keeps the earlier maximum.
    fn observe_gap(&mut self, now_us: u64) {
        if let Some(last) = self.last_poll_us {
            let gap = now_us.saturating_sub(last);
            let bucket = (gap.max(1).ilog2() as usize).min(POLL_GAP_BUCKETS - 1);
            let first = self.report.poll_gaps == [0; POLL_GAP_BUCKETS];
            self.report.poll_gaps[bucket] += 1;
            if first || gap > self.report.poll_gap_max_us {
                self.report.poll_gap_max_us = gap;
                self.report.poll_gap_max_after = self.last_turn;
            }
        }
        self.last_poll_us = Some(now_us);
    }

    /// A turn that unwound left `armed` set and its state may be half applied, so admission ends; the receive leases the turn left unhandled return to their pool and the lookahead empties, while admitted reads, requests and device references keep their custody.
    fn observe_unwind(&mut self) {
        if self.armed {
            self.end_turn_sources();
            self.poisoned = true;
            // A visit the unwound pass settled may not have reached its entry.
            self.parked.owe_all();
            self.scratch.iter_mut().for_each(|lease| *lease = None);
            self.preparation.reset();
        }
    }

    /// Whether a turn unwound, which ends admission while every read keeps its custody.
    pub fn poisoned(&self) -> bool {
        self.poisoned || self.armed
    }

    /// Whether this attach lost its device ([`Volume::is_lost`]): the command table lost its admission, on a submit
    /// the driver refused `DeviceGone`, as it does after a controller event, or on a submit that unwound; or a
    /// volume tick or close unwound. Admission ends for the rest of the attach, and the call that first observes
    /// the loss withdraws the storage's readiness attempt.
    pub fn lost(&self) -> bool {
        self.volume.is_lost()
    }

    /// The serving machine's state, read without a clock sample.
    pub fn authority_state(&self) -> crate::failover::serving::State {
        self.volume.authority_state()
    }

    /// Whether a withdrawal cause named a later tenure of the shard (`Machine::has_successor`), in any state and
    /// after any first withdrawal cause: a later shard record, a store write refused for a later tenure, or a
    /// coverage page fenced by a later activated session.
    pub fn has_successor(&self) -> bool {
        self.volume.has_successor()
    }

    pub fn authority_withdrawal(&self) -> Option<crate::failover::serving::Cause> {
        self.volume.authority_withdrawal()
    }

    /// [`Volume::lapse_verified`](crate::storage::Volume::lapse_verified) of the owner's volume.
    pub fn lapse_verified(&self) -> bool {
        self.volume.lapse_verified()
    }

    pub fn authority_flip(&self) -> Option<crate::failover::retire::Target> {
        self.volume.authority_flip()
    }

    fn mutation_open(&mut self) -> Result<(), Status> {
        if self.volume.is_lost() {
            self.admission.lose();
        }
        match self.admission {
            Admission::Closed => Err(Status::Closed),
            Admission::Lost | Admission::Draining(DrainStage::Mutations) => {
                Err(Status::OwnerUnavailable)
            }
            Admission::Open | Admission::Draining(DrainStage::Fills) if self.poisoned => {
                Err(Status::OwnerUnavailable)
            }
            Admission::Open | Admission::Draining(DrainStage::Fills) => Ok(()),
        }
    }

    fn fill_open(&mut self) -> Result<(), Status> {
        self.mutation_open()?;
        #[cfg(test)]
        if super::owner_drain_tests::planted(super::owner_drain_tests::Plant::FillsAdmitted) {
            return Ok(());
        }
        match self.draining() {
            Some(_) => Err(Status::OwnerUnavailable),
            None => Ok(()),
        }
    }

    fn quiesced(&self) -> bool {
        matches!(
            self.quiesce,
            Some(crate::storage::QuiesceProgress::Quiesced(_))
        )
    }

    /// Each turn permits at most one storage maintenance call with a budget of `maintain_work` steps. When the call finds no more work, the owner waits [`MAINTAIN_REST_US`] microseconds before the next call. `DrainStage::Mutations` pauses expiry and headroom eviction to preserve membership until a successful [`Owner::resume`], a volume loss or [`Owner::close`]; a withdrawal keeps the pause. The pause also covers fill service, certification and slot service.
    fn maintain(&mut self, now_us: u64) {
        #[cfg(test)]
        {
            self.maintain_spent = (0, false);
        }
        if self.config.maintain_work == 0 || self.draining() == Some(DrainStage::Mutations) {
            return;
        }
        if let Some(until) = self.maintain_rest_until_us {
            if now_us < until {
                return;
            }
            self.maintain_rest_until_us = None;
        }
        let mut work = WorkBudget::new(self.config.maintain_work);
        let maintained = self.volume.storage().maintain(&mut work);
        #[cfg(test)]
        {
            // The steps the call debited: the sum of the budget's per-kind counters, which equals its spend.
            let counted = work.counters();
            let stopped =
                matches!(&maintained, Ok(Maintained::Open(report)) if report.budget_exhausted);
            let steps = counted.comparisons
                + counted.coordination_attempts
                + counted.visits
                + counted.updates
                + counted.hashes;
            self.maintain_spent = (steps, stopped);
        }
        match maintained {
            Ok(maintained) => {
                self.report.maintained += 1;
                if let Maintained::Open(report) = maintained {
                    self.report.maintenance_clock_unavailable +=
                        u64::from(report.clock_unavailable);
                    self.report.maintenance_contended += report.contended as u64;
                    self.report.last_certify_stall = report.certify_stall;
                    if !report.more_work {
                        self.maintain_rest_until_us = Some(now_us.saturating_add(MAINTAIN_REST_US));
                    }
                }
            }
            Err(error) => {
                self.report.maintenance_refused += 1;
                self.report.last_maintenance_refusal = Some(error);
            }
        }
    }

    fn receive_batch(&mut self, now_us: u64) {
        let got = self
            .transport
            .receive(self.receive, &mut self.scratch, &mut self.meta)
            .unwrap_or(0);
        self.report.received += got as u64;
        let end = got.min(self.scratch.len());
        self.drop_as(DropReason::Vacant, (got - end) as u64);
        // The ordinals of the frames of the window being handled; its keys lead `window`.
        let mut run = 0..0;
        // The ordinal of the next frame: one per lone datagram and one per frame of a packed datagram.
        let mut ordinal = 0;
        // The tag of the datagram after the one being handled, when `pair_bare` tagged the two in one computation.
        let mut ahead: Option<[u8; TAG_LEN]> = None;
        let mut group: [Option<(PacketLease<'m>, Received)>; DATA_GROUP] = [None, None, None, None];
        let mut count = 0;
        for at in 0..end {
            let here = ordinal;
            let meta = self.meta[at];
            let packed = packed_gets(self.scratch[at].as_ref(), meta);
            ordinal += packed.map_or(1, |(frames, _)| frames);
            let mut early_tag = ahead.take();
            // A packed datagram's frames are handled one by one, each to its end before the next, through the GET
            // path a lone datagram of the same bytes takes; a refused frame counts under its reason alone.
            if let Some((_, peer)) = packed {
                // A tag settled ahead belongs to the later frame of a bare pair, an ACK or a PUT control frame,
                // and a packed datagram's first kind byte says GET.
                debug_assert!(early_tag.is_none());
                let lease = self.scratch[at]
                    .take()
                    .expect("a packed datagram is leased");
                self.tally(Ok(()));
                let served = self.report.get_frames;
                let (frames, _) = lease.bytes().as_chunks::<HEADER_LEN>();
                // The frame a window scan parsed each of this datagram's chunks to; that frame's handling reads it
                // in place of a second parse.
                let mut scanned = [None; MAX_PACKED_GETS];
                for (frame, bytes) in frames.iter().enumerate() {
                    let ordinal = here + frame;
                    if ordinal >= run.end {
                        let own = Own {
                            frames: &frames[frame..],
                            received: meta,
                            scanned: &mut scanned[frame..],
                        };
                        run = self.prepare_window(ordinal, own, at + 1, end);
                    }
                    self.take_aged(&mut group, &mut count, bytes, meta, now_us);
                    let entry = run
                        .contains(&ordinal)
                        .then(|| self.window_entry(&run, ordinal));
                    let (prepared, tag) = entry.as_ref().map(|(p, t)| (p, *t)).unzip();
                    let outcome = match scanned[frame] {
                        Some(frame) => self.take_frame(&frame, peer, prepared, tag, now_us),
                        None => self.accept(bytes, meta, prepared, tag, now_us),
                    };
                    if let Err(reason) = outcome {
                        self.report.packed_dropped_by[reason as usize] += 1;
                    }
                }
                self.report.get_datagrams += u64::from(self.report.get_frames != served);
                continue;
            }
            if here >= run.end {
                // A window requires at least two frames.
                run = if self.window.len() < 2 || at + 1 >= end {
                    debug_assert!(
                        self.window.len() < 2
                            || window_frames(&self.scratch, &self.meta, at, end)
                                .nth(1)
                                .is_none(),
                        "the scan from the batch's last slot ends before a second frame"
                    );
                    here..here
                } else {
                    let own = Own {
                        frames: &[],
                        received: meta,
                        scanned: &mut [],
                    };
                    self.prepare_window(here, own, at, end)
                };
            }
            if early_tag.is_none()
                && !run.contains(&here)
                && at + 1 < end
                && let Some(tags) = self.pair_bare(at)
            {
                early_tag = Some(tags[0]);
                ahead = Some(tags[1]);
                #[cfg(test)]
                PAIRED_BARE.with(|count| count.set(count.get() + 2));
            }
            let Some(lease) = self.scratch[at].take() else {
                self.drop_as(DropReason::Vacant, 1);
                continue;
            };
            if is_put_data(lease.bytes()) {
                group[count] = Some((lease, meta));
                count += 1;
                if count == DATA_GROUP {
                    self.take_group(&mut group, now_us);
                    count = 0;
                }
                continue;
            }
            self.take_aged(&mut group, &mut count, lease.bytes(), meta, now_us);
            let entry = run.contains(&here).then(|| self.window_entry(&run, here));
            let (prepared, tag) = match &entry {
                Some((prepared, tag)) => {
                    // A window holds GET frames alone, and a tag settled ahead belongs to an ACK or a PUT
                    // control frame.
                    debug_assert!(early_tag.is_none());
                    (Some(prepared), Some(*tag))
                }
                None => (None, early_tag),
            };
            let served = self.report.get_frames;
            let outcome = self.accept(lease.bytes(), meta, prepared, tag, now_us);
            self.tally(outcome);
            self.report.get_datagrams += u64::from(self.report.get_frames != served);
        }
        if count > 0 {
            self.take_group(&mut group, now_us);
        }
    }

    /// The lookup context and window tag of the frame at `ordinal`, which the window `run` holds. A window frame
    /// takes its entry and derives the lookahead `DEPTH` frames on before it is handled, so the routes ahead are in
    /// flight across its handling; its lookup uses the entry only for its authenticated key.
    fn window_entry(
        &mut self,
        run: &std::ops::Range<usize>,
        ordinal: usize,
    ) -> (PreparedLookup<'s, P>, [u8; TAG_LEN]) {
        assert!(
            run.contains(&ordinal),
            "frame {ordinal} lies outside the window {run:?}"
        );
        let key = self.window[ordinal - run.start];
        let prepared = self.preparation.take(ordinal, &key);
        self.preparation.advance(&self.window[..run.len()], ordinal);
        (prepared, self.tags[ordinal - run.start])
    }

    /// The tags of the datagrams at `at` and `at + 1` from one computation of two chains, when both are [`bare_candidate`]s whose principal and key epoch the ring admits: ACK, PUT BEGIN, PUT PREPARE and PUT CANCEL tags cover the header and an empty body, so they are computed before the frames parse. `None` delegates tag computation to each frame's processing.
    fn pair_bare(&self, at: usize) -> Option<[[u8; TAG_LEN]; 2]> {
        let input = |slot: usize| {
            let lease = bare_candidate(&self.scratch[slot], self.meta[slot])?;
            let header = lease.bytes().first_chunk()?;
            tag_input(
                &self.ring,
                self.config.endpoint,
                header,
                self.meta[slot].peer?,
            )
        };
        let (first, peer_a) = input(at)?;
        let (second, peer_b) = input(at + 1)?;
        self.ring.tag_pair([peer_a, peer_b], [&first, &second])
    }

    /// Prepares the window of eligible GET frames that starts at the frame
    /// of ordinal `first`, as the module documentation states, and returns
    /// the ordinals of its frames: empty for a run shorter than two. The
    /// scan walks the frames of `own`, then the datagrams in receive slots
    /// `next..end`; `own` is empty when the frame at `first` is the lone
    /// datagram in slot `next`. When the scan parses the run's first GET, the
    /// lookahead empties before that key replaces the window's earlier keys.
    fn prepare_window(
        &mut self,
        first: usize,
        own: Own<'_, '_>,
        next: usize,
        end: usize,
    ) -> std::ops::Range<usize> {
        let empty = first..first;
        let crc = self.crc;
        let later = || window_frames(&self.scratch, &self.meta, next, end);
        // A run reaches two only when the capacity is at least two and a
        // frame that may extend the run follows the one at `first`; otherwise
        // that frame is handled alone, without the scan's parse.
        if self.window.len() < 2
            || (own.frames.len() < 2 && later().nth(1 - own.frames.len()).is_none())
        {
            return empty;
        }
        // A frame that parses as a GET joins the run; its key follows the
        // run's earlier keys.
        let capacity = self.window.len();
        let mut width = 0;
        let mut join = |frame: &Frame<'_>| {
            let get = frame.header().kind == Kind::Get;
            if get {
                if width == 0 {
                    self.preparation.reset();
                }
                self.window[width] = frame.header().key;
                width += 1;
            }
            get
        };
        // The datagram's own frames come first, and each that parses stays
        // in `own.scanned` for its handling; the first frame that fails ends
        // the run.
        let mut whole = true;
        for (bytes, scanned) in own.frames.iter().zip(own.scanned).take(capacity) {
            whole = match parse(crc, bytes, own.received.truncated) {
                Ok(frame) => {
                    *scanned = Some(frame);
                    join(&frame)
                }
                Err(_) => false,
            };
            if !whole {
                break;
            }
        }
        if whole {
            for (bytes, received) in later().take(capacity.saturating_sub(own.frames.len())) {
                if !parse(crc, bytes, received.truncated).is_ok_and(|frame| join(&frame)) {
                    break;
                }
            }
        }
        if width < 2 {
            return empty;
        }
        // The routes and summary hints go out first and the staging follows
        // the tags, so the summaries arrive during the hashing and the staged
        // reads hit; the head positions, looked up right after, are hinted
        // blind.
        self.preparation.derive_ahead(&self.window[..width], first);
        self.preparation.hint_head();
        let (endpoint, ring) = (self.config.endpoint, &self.ring);
        let alone =
            |tags: &mut [[u8; TAG_LEN]], position: usize, input: Option<(MacInput<'_>, PeerId)>| {
                if let Some((input, peer)) = input
                    && let Some(tag) = ring.tag(peer, &input)
                {
                    tags[position] = tag;
                    #[cfg(test)]
                    WINDOW_TAGS.with(|count| count.set(count.get() + 1));
                }
            };
        // The window's frames, walked again in the scan's order, each with its tag input.
        let mut inputs = own
            .frames
            .iter()
            .map(|bytes| (bytes.as_slice(), own.received))
            .chain(later())
            .take(width)
            .map(|(bytes, received)| {
                tag_input(ring, endpoint, bytes.first_chunk()?, received.peer?)
            });
        let pair = |tags: &mut [[u8; TAG_LEN]],
                    position: usize,
                    first: Option<(MacInput<'_>, PeerId)>,
                    second: Option<(MacInput<'_>, PeerId)>| {
            let paired = match (&first, &second) {
                (Some((first, peer_a)), Some((second, peer_b))) => {
                    ring.tag_pair([*peer_a, *peer_b], [first, second])
                }
                _ => None,
            };
            match paired {
                Some(two) => {
                    tags[position] = two[0];
                    tags[position + 1] = two[1];
                    #[cfg(test)]
                    WINDOW_TAGS.with(|count| count.set(count.get() + 2));
                }
                None => {
                    alone(tags, position, first);
                    alone(tags, position + 1, second);
                }
            }
        };
        let mut position = 0;
        // Four frames' chains hash together while four remain, then the last three, two or one.
        while position + 3 < width {
            let four: [_; 4] = std::array::from_fn(|_| inputs.next().flatten());
            let grouped = match &four {
                [
                    Some((a, peer_a)),
                    Some((b, peer_b)),
                    Some((c, peer_c)),
                    Some((d, peer_d)),
                ] => ring.tag_group([(*peer_a, a), (*peer_b, b), (*peer_c, c), (*peer_d, d)]),
                _ => None,
            };
            match grouped {
                Some(tags) => {
                    self.tags[position..position + 4].copy_from_slice(&tags);
                    #[cfg(test)]
                    WINDOW_TAGS.with(|count| count.set(count.get() + 4));
                }
                None => {
                    let [first, second, third, fourth] = four;
                    pair(&mut self.tags, position, first, second);
                    pair(&mut self.tags, position + 2, third, fourth);
                }
            }
            position += 4;
        }
        if position + 2 < width {
            let three: [_; 3] = std::array::from_fn(|_| inputs.next().flatten());
            let grouped = match &three {
                [Some((a, peer_a)), Some((b, peer_b)), Some((c, peer_c))] => {
                    ring.tag_group([(*peer_a, a), (*peer_b, b), (*peer_c, c)])
                }
                _ => None,
            };
            match grouped {
                Some(tags) => {
                    self.tags[position..position + 3].copy_from_slice(&tags);
                    #[cfg(test)]
                    WINDOW_TAGS.with(|count| count.set(count.get() + 3));
                }
                None => {
                    let [first, second, third] = three;
                    pair(&mut self.tags, position, first, second);
                    alone(&mut self.tags, position + 2, third);
                }
            }
        } else if position + 1 < width {
            let (first, second) = (inputs.next().flatten(), inputs.next().flatten());
            pair(&mut self.tags, position, first, second);
        } else if position < width {
            alone(&mut self.tags, position, inputs.next().flatten());
        }
        self.preparation.stage_first();
        #[cfg(test)]
        {
            self.windows.prepared += 1;
            self.windows.gets += width as u64;
        }
        first..first + width
    }

    fn take_group(
        &mut self,
        group: &mut [Option<(PacketLease<'m>, Received)>; DATA_GROUP],
        now_us: u64,
    ) {
        let outcomes = self.accept_data(std::mem::take(group), now_us);
        for outcome in outcomes.into_iter().flatten() {
            self.tally(outcome);
        }
    }

    /// Counts one examined datagram: handled, or dropped under its reason.
    fn tally(&mut self, outcome: Result<(), DropReason>) {
        match outcome {
            Ok(()) => self.report.handled += 1,
            Err(reason) => self.drop_as(reason, 1),
        }
    }

    /// Counts `n` datagrams dropped under `reason`, moving `dropped` with the reason's counter.
    fn drop_as(&mut self, reason: DropReason, n: u64) {
        self.report.dropped += n;
        self.report.dropped_by[reason as usize] += n;
    }

    /// Takes the `count` pending fragments of `group` before the frame `bytes` is handled, when that frame would age one of them out.
    #[inline(always)]
    fn take_aged(
        &mut self,
        group: &mut [Option<(PacketLease<'m>, Received)>; DATA_GROUP],
        count: &mut usize,
        bytes: &[u8],
        meta: Received,
        now_us: u64,
    ) {
        if *count > 0 && self.ages_out(group, bytes, meta) {
            self.take_group(group, now_us);
            *count = 0;
        }
    }

    /// The batch takes `group` before the frame `bytes` when admitting that frame first would make a pending same-peer fragment stale in that peer's replay window. The check reads the frame's own sequence, so each frame of a packed datagram meets it with its own.
    fn ages_out(
        &self,
        group: &[Option<(PacketLease<'m>, Received)>; DATA_GROUP],
        bytes: &[u8],
        meta: Received,
    ) -> bool {
        let Some(later) = meta.peer.and(raw_sequence(bytes)) else {
            return false;
        };
        group.iter().flatten().any(|(pending, received)| {
            received.peer == meta.peer
                && raw_sequence(pending.bytes())
                    .is_some_and(|earlier| self.sessions.ages_out(earlier, later))
        })
    }

    /// The outcome of each present datagram of `group`, `None` for an absent one. `accept_data` completes authentication attempts for parsed frames before calling `compare_resends` or `take_data`.
    #[inline(never)]
    fn accept_data(
        &mut self,
        group: [Option<(PacketLease<'m>, Received)>; DATA_GROUP],
        now_us: u64,
    ) -> [Option<Result<(), DropReason>>; DATA_GROUP] {
        let (endpoint, inbound) = (self.config.endpoint, Direction::ClientToOwner);
        // Each present datagram's admission, or the reason of the first check it failed.
        let mut checked: [Option<Result<AdmittedData, DropReason>>; DATA_GROUP] =
            [None; DATA_GROUP];
        let parsed: [Option<(Frame<'_>, PeerId)>; DATA_GROUP] = std::array::from_fn(|at| {
            let (lease, meta) = group[at].as_ref()?;
            parsed_put_data(self.crc, lease, *meta)
                .inspect_err(|reason| checked[at] = Some(Err(*reason)))
                .ok()
        });
        let present = parsed.iter().filter(|frame| frame.is_some()).count();
        if present == DATA_GROUP {
            let frames = parsed.each_ref().map(|frame| {
                frame
                    .as_ref()
                    .map(|(frame, peer)| (frame, *peer))
                    .expect("present")
            });
            let verified = self.ring.authenticate_group(frames, endpoint, inbound);
            for (at, verified) in verified.into_iter().enumerate() {
                checked[at] = Some(self.admit_put_data(verified));
            }
        } else {
            // Fewer than four parsed: three through one pass of three chains, else a pair, else one alone.
            let mut pending = [0usize; DATA_GROUP];
            let mut count = 0;
            for (at, frame) in parsed.iter().enumerate() {
                if frame.is_some() {
                    pending[count] = at;
                    count += 1;
                }
            }
            let mut next = 0;
            if count == 3 {
                let frames: [_; 3] = std::array::from_fn(|at| {
                    let (frame, peer) = parsed[pending[at]].as_ref().expect("present");
                    (frame, *peer)
                });
                let verified = self.ring.authenticate_group(frames, endpoint, inbound);
                for (at, verified) in pending.into_iter().zip(verified) {
                    checked[at] = Some(self.admit_put_data(verified));
                }
                #[cfg(test)]
                TRIPLED_DATA.with(|count| count.set(count.get() + 3));
                next = count;
            }
            while count - next >= 2 {
                let (i, j) = (pending[next], pending[next + 1]);
                next += 2;
                let (a, b) = (
                    parsed[i].as_ref().expect("present"),
                    parsed[j].as_ref().expect("present"),
                );
                let [va, vb] =
                    self.ring
                        .authenticate_group([(&a.0, a.1), (&b.0, b.1)], endpoint, inbound);
                checked[i] = Some(self.admit_put_data(va));
                checked[j] = Some(self.admit_put_data(vb));
            }
            if next < count {
                let i = pending[next];
                let a = parsed[i].as_ref().expect("present");
                let verified = self.ring.authenticate(&a.0, a.1, endpoint, inbound);
                checked[i] = Some(self.admit_put_data(verified));
            }
        }
        let verdicts = self.compare_resends(&group, &checked);
        let mut outcomes = [None; DATA_GROUP];
        for (at, entry) in group.into_iter().enumerate() {
            if let (Some((lease, _)), Some(checked)) = (entry, checked[at]) {
                outcomes[at] =
                    Some(checked.and_then(|admitted| {
                        self.take_data(admitted, lease, verdicts[at], now_us)
                    }));
            }
        }
        outcomes
    }

    fn compare_resends(
        &mut self,
        group: &[Option<(PacketLease<'m>, Received)>; DATA_GROUP],
        checked: &[Option<Result<AdmittedData, DropReason>>; DATA_GROUP],
    ) -> [Option<Verdict>; DATA_GROUP] {
        let frames = std::array::from_fn(|at| {
            let (session, header, crc) = checked[at].as_ref()?.as_ref().ok()?;
            let (lease, _) = group[at].as_ref()?;
            Some((*session, header, &lease.bytes()[HEADER_LEN..], *crc))
        });
        let retag = Retag {
            ring: &self.ring,
            endpoint: self.config.endpoint,
            crc: self.crc,
        };
        self.put.compare_resends(&self.requests, &retag, frames)
    }

    fn take_data(
        &mut self,
        (session, header, _): AdmittedData,
        lease: PacketLease<'m>,
        verdict: Option<Verdict>,
        now_us: u64,
    ) -> Result<(), DropReason> {
        declined(self.put.data(
            &mut self.requests,
            &mut self.serve,
            (session, &header),
            lease,
            verdict,
            now_us,
        ))
    }

    /// Hands one received frame to the session table and the transfer core, with the lookup context its window prepared for it if any, and returns the reason of the first check it failed when it was not accepted. `bytes` is a lone datagram's bytes or one frame of a packed datagram, and `meta` describes the datagram that carried it.
    fn accept(
        &mut self,
        bytes: &[u8],
        meta: Received,
        prepared: Option<&PreparedLookup<'s, P>>,
        tag: Option<[u8; TAG_LEN]>,
        now_us: u64,
    ) -> Result<(), DropReason> {
        debug_assert!(!is_put_data(bytes));
        let (frame, peer) = parse_received(self.crc, bytes, meta)?;
        self.take_frame(&frame, peer, prepared, tag, now_us)
    }

    /// Hands the parsed frame `frame` from `peer` to the session table and the transfer core, with the lookup context its window prepared for it if any, and returns the reason of the first check it failed when it was not accepted.
    fn take_frame(
        &mut self,
        frame: &Frame<'_>,
        peer: PeerId,
        prepared: Option<&PreparedLookup<'s, P>>,
        tag: Option<[u8; TAG_LEN]>,
        now_us: u64,
    ) -> Result<(), DropReason> {
        let authenticated = match tag {
            Some(tag) => self.ring.authenticate_tagged(frame, peer, tag),
            None => {
                self.ring
                    .authenticate(frame, peer, self.config.endpoint, Direction::ClientToOwner)
            }
        };
        let frame = authenticated.map_err(|_| DropReason::Unauthenticated)?;
        let header = frame.header();
        match header.kind {
            Kind::Hello => {
                let challenge = self
                    .sessions
                    .on_hello(&frame)
                    .map_err(|_| DropReason::Session)?;
                declined(self.reply(challenge))
            }
            Kind::Confirm => {
                let token = self
                    .volume
                    .serving_token()
                    .filter(|token| self.admits_reply(*token))
                    .ok_or(DropReason::Declined)?;
                let tenure = super::owner_view::tenure_of(token);
                let mut activation = self
                    .sessions
                    .on_confirm(&frame)
                    .map_err(|_| DropReason::Session)?;
                if activation.replaced.is_some() {
                    self.retire_peer(peer, now_us, None);
                }
                // A session binds its tenure once, at activation; a repeat CONFIRM answers only under that tenure.
                match self.sessions.tenure(peer) {
                    None => self.sessions.bind_tenure(peer, tenure),
                    Some(bound) if bound != tenure => return Err(DropReason::Declined),
                    Some(_) => {}
                }
                activation.ready.tenure = Some(tenure);
                declined(self.reply(activation.ready))
            }
            Kind::WhoHolds | Kind::Probe => self.take_question(&frame),
            Kind::Get | Kind::Ack | Kind::Cancel => {
                // The session is read where `admit` returned it. Moving it out of the `Result` would copy it to a second slot with loads wider than the stores that just wrote it, and such a load waits until those stores have left the store buffer.
                let admitted = self.sessions.admit(&frame);
                let Ok(session) = admitted.as_ref() else {
                    return Err(DropReason::Session);
                };
                match header.kind {
                    Kind::Get => {
                        self.report.get_frames += 1;
                        if let GetOutcome::Read { id, deadline_us } =
                            self.serve
                                .get(&mut self.requests, *session, &header, now_us)
                        {
                            self.start_read(
                                id,
                                session.peer,
                                &header.key,
                                prepared,
                                deadline_us,
                                now_us,
                            );
                        }
                    }
                    Kind::Ack => {
                        self.serve
                            .ack(&mut self.requests, *session, &header, now_us);
                        self.regrant = true;
                    }
                    _ => self
                        .serve
                        .cancel(&mut self.requests, *session, &header, now_us),
                }
                Ok(())
            }
            Kind::PutBegin | Kind::PutPrepare | Kind::PutCancel => {
                let session = self
                    .sessions
                    .admit(&frame)
                    .map_err(|_| DropReason::Session)?;
                let open = self.fill_open();
                self.put.take(
                    &mut self.requests,
                    &mut self.serve,
                    &mut self.volume,
                    &self.permits,
                    open,
                    self.coverage.as_ref(),
                    session,
                    &header,
                    now_us,
                );
                Ok(())
            }
            Kind::Invalidate => {
                let session = self
                    .sessions
                    .admit(&frame)
                    .map_err(|_| DropReason::Session)?;
                if self.mutation_open().is_err() || self.permits.check(session.peer).is_err() {
                    return Err(DropReason::Declined);
                }
                declined(self.take_invalidate(session, &header))
            }
            Kind::PutData
            | Kind::Challenge
            | Kind::Ready
            | Kind::Start
            | Kind::Data
            | Kind::Complete
            | Kind::Error
            | Kind::PutAuthority
            | Kind::PutReady
            | Kind::PutAck
            | Kind::PutResult
            | Kind::PutError
            | Kind::Holder
            | Kind::WrongOwner
            | Kind::Heartbeat
            | Kind::ProbeReply
            | Kind::Invalidated => Err(DropReason::Kind),
        }
    }

    /// Answers `question`, an authenticated WHO HOLDS or PROBE: queues the HOLDER, or for a PROBE the WRONG OWNER, for its peer, or returns the reason of the first check the question failed.
    #[inline]
    fn take_question(&mut self, question: &Authenticated<'_, '_>) -> Result<(), DropReason> {
        let header = question.header();
        debug_assert!(matches!(header.kind, Kind::WhoHolds | Kind::Probe));
        let peer = question.peer();
        if self.ownership[usize::from(peer.0)].is_some() {
            return Err(DropReason::Declined);
        }
        let query =
            super::ownership::OwnershipBody::decode(header.kind, question.frame().raw_body())
                .map_err(|_| DropReason::Malformed)?;
        let token = self
            .volume
            .serving_token()
            .filter(|token| token.shard == query.shard)
            .ok_or(DropReason::Declined)?;
        let own = super::owner_view::tenure_of(token);
        let (kind, binding) = if header.kind == Kind::Probe {
            self.sessions
                .admit(question)
                .map_err(|_| DropReason::Session)?;
            if self.sessions.tenure(peer) != Some(own)
                || query
                    .tenure
                    .is_some_and(|t| (t.generation, t.epoch) >= (own.generation, own.epoch))
            {
                return Err(DropReason::Declined);
            }
            (Kind::WrongOwner, Some(own))
        } else {
            (Kind::Holder, None)
        };
        self.queue_ownership(usize::from(peer.0), (Header { kind, ..header }, binding));
        Ok(())
    }

    /// Admits one authenticated PUT DATA frame to its session and checks its body crc, returning the session, the header and that crc, or the reason of the first step that refuses.
    fn admit_put_data(
        &mut self,
        verified: Result<Authenticated<'_, '_>, AuthError>,
    ) -> Result<AdmittedData, DropReason> {
        let frame = verified.map_err(|_| DropReason::Unauthenticated)?;
        let session = self
            .sessions
            .admit(&frame)
            .map_err(|_| DropReason::Session)?;
        frame
            .frame()
            .check_body(self.crc)
            .map_err(|_| DropReason::Body)?;
        Ok((session, frame.header(), frame.frame().body_crc()))
    }

    fn reply(&mut self, step: Bootstrap) -> bool {
        let Some(slot) = self.replies.get_mut(usize::from(step.peer.0)) else {
            return false;
        };
        self.waiting += u32::from(slot.is_none());
        *slot = Some(step);
        true
    }

    /// Looks `key` up afresh and starts the read of the object it finds for request `id` of `peer`, the lookup's right handed straight to the read, or parks the request as a follower of the key's fill when the lookup proves the key missing and the follower caps admit it, or ends the request with the refusal's status. The lookup starts from the route in `prepared`, the context the frame's window took for it, when that context is for `key`, the authenticated key, and validates and reserves as an unrouted lookup does either way.
    fn start_read(
        &mut self,
        id: RequestId,
        peer: PeerId,
        key: &[u8; 32],
        prepared: Option<&PreparedLookup<'s, P>>,
        deadline_us: u64,
        now_us: u64,
    ) {
        if let Err(status) = self.read_admission() {
            return self
                .serve
                .read_refused(&mut self.requests, id, status, now_us);
        }
        let scalar;
        let prepared = match prepared.and_then(|prepared| prepared.for_key(key)) {
            Some(prepared) => prepared,
            None => {
                scalar = self.preparation.scalar(key);
                &scalar
            }
        };
        let (max_observers, cap) = self.parked.limit(peer);
        let mut work = WorkBudget::new(self.config.lookup_work);
        let (retries, registration) = (self.config.lookup_retries, &mut self.registration);
        // With joins off a miss ends at the lookup, as a GET's lookup alone answers it.
        let started = if self.parked.enabled() {
            self.volume.read_or_join_prepared(
                registration,
                prepared,
                max_observers,
                retries,
                &mut work,
                deadline_us,
            )
        } else {
            self.volume
                .read_key_prepared(registration, prepared, retries, &mut work, deadline_us)
                .map(KeyRead::Started)
        };
        let status = match started {
            Ok(KeyRead::Started(op)) => return self.bind(id, op),
            Ok(KeyRead::Joined(follower)) => {
                let entry = Entry {
                    request: id,
                    peer,
                    follower,
                };
                let (put, requests) = (&self.put, &self.requests);
                return self.parked.park(entry, |fill| put.produces(requests, fill));
            }
            Err(KeyReadError::Lookup(error)) => lookup_status(error),
            Err(KeyReadError::Join(JoinError::FollowerLimit)) => {
                self.parked.saturated(cap);
                Status::RequestPressure
            }
            Err(KeyReadError::Join(JoinError::Contended)) => Status::Contended,
            // The lookup proves the key missing before the join exhausts `lookup_work`, so the GET retains `Missing`.
            Err(KeyReadError::Join(JoinError::BudgetExhausted)) => Status::Missing,
            // `seek` answers `NoFill` as `Missing`, and the lookup routed the key, so the index is live; `Corrupt` means a malformed table poisoned its gate.
            Err(KeyReadError::Join(
                JoinError::NoIndex | JoinError::NoFill | JoinError::Corrupt,
            )) => {
                self.report.defects += 1;
                Status::OwnerUnavailable
            }
            Err(KeyReadError::Read(refusal)) => self.read_refusal(refusal),
            // `start` checked that the registration and the volume serve one storage.
            Err(KeyReadError::ForeignRegistration) => {
                self.report.defects += 1;
                Status::OwnerUnavailable
            }
        };
        self.serve
            .read_refused(&mut self.requests, id, status, now_us);
    }

    /// `Ok` while the owner admits reads, else the status a read is refused with: `OwnerUnavailable` after a turn unwound while the owner is open or once its volume is lost, however the loss was seen, `Closed` once it closed.
    fn read_admission(&self) -> Result<(), Status> {
        match self.admission {
            Admission::Closed => return Err(Status::Closed),
            Admission::Lost => return Err(Status::OwnerUnavailable),
            Admission::Open | Admission::Draining(_) if self.poisoned || self.volume.is_lost() => {
                return Err(Status::OwnerUnavailable);
            }
            Admission::Open | Admission::Draining(_) => {}
        }
        #[cfg(test)]
        if matches!(self.admission, Admission::Draining(_))
            && super::owner_drain_tests::planted(super::owner_drain_tests::Plant::HitsRefused)
        {
            return Err(Status::OwnerUnavailable);
        }
        self.volume
            .admit_authority(
                crate::failover::serving::Operation::Get,
                self.volume.serving_token(),
            )
            .map(|_| ())
            .map_err(|denial| match denial {
                crate::failover::serving::Denial::Withheld => Status::Missing,
                _ => Status::OwnerUnavailable,
            })
    }

    /// The status of a refused read, counting a defect and closing admission on a lost volume.
    fn read_refusal(&mut self, refusal: ReadRefusal) -> Status {
        let (status, defect) = refusal_status(refusal);
        self.report.defects += u64::from(defect);
        if refusal == ReadRefusal::Lost {
            self.admission.lose();
        }
        status
    }

    /// Binds the read `op` the volume started to request `id`.
    fn bind(&mut self, id: RequestId, op: ReadOp) {
        self.serve.read_started(&mut self.requests, id);
        self.regrant |= self.serve.wants_grant(&self.requests, id);
        let at = &mut self.bound[usize::from(id.slot())];
        self.reads += u32::from(at.is_none());
        *at = Some(Bound {
            request: id,
            op,
            done: false,
            exhausted: false,
            cancelled: false,
        });
        self.by_op[op.slot as usize] = Some(id.slot());
    }

    /// The turn's wake and detach pass: at most `follow.wake` visits to a check's fills or to owed entries from the persistent cursor. The pass runs only while a GET is parked and a PUT fill departed, an entry is owed a visit, a check is under way or due, or the read admission changed. Each visit detaches an ended request's follower; ends a request the owner no longer admits reads for, or whose deadline passed, with that cause; or acquires the version the producer published under the read credit and starts the read under the request's deadline. The read checks the manifest against the GET's caps at its first chunk. The producer's terminal, or the observation's, acquisition's or read's refusal, ends the request with that cause. Pending, contended and budget-short followers stay parked; contended and budget-short ones are owed another visit.
    fn wake(&mut self, now_us: u64) {
        // Departures while no GET is parked owe no visit.
        let departed = self.put.take_departed();
        if self.parked.is_empty()
            || (departed.is_none() && !self.parked.has_work(now_us, self.read_admission()))
        {
            return self.parked.rest();
        }
        self.wake_pass(now_us, departed);
    }

    /// The pass of a turn that has work, as [`wake`](Self::wake) states, after the PUT core's `departed` fills, if any; kept out of line so the turns without work stay short.
    #[inline(never)]
    fn wake_pass(&mut self, now_us: u64, departed: Option<Departed>) {
        if let Some(departed) = departed {
            for fill in departed.fills.into_iter().flatten() {
                self.parked.departed(fill);
            }
            if departed.more {
                self.parked.owe_all();
            }
        }
        self.parked.begin_pass(now_us, self.read_admission());
        let retries = self.config.lookup_retries;
        // A check that finds its fill pending records it for the pass; any other observation owes the fill's followers a visit.
        while let Some(slot) = self.parked.check() {
            let mut work = WorkBudget::new(self.config.lookup_work);
            let follower = &self.parked.entry(slot).follower;
            if self.volume.joined_wait(follower, retries, &mut work)
                == Err(JoinedReadError::Pending)
            {
                self.parked.note_pending(slot);
            } else {
                self.parked.owe_fill_of(slot);
            }
        }
        self.parked.begin_visits();
        while let Some(slot) = self.parked.visit() {
            let entry = self.parked.entry(slot);
            let id = entry.request;
            let Some(deadline_us) = self
                .requests
                .serve(id)
                .filter(|_| !self.requests.get_is_ended(id))
                .map(|serve| serve.deadline_us())
            else {
                #[cfg(test)]
                if super::parked::planted(super::parked::Plant::ReleaseParked) {
                    continue;
                }
                let follower = self.parked.take(slot).follower;
                #[cfg(test)]
                if super::parked::planted(super::parked::Plant::DetachAborts) {
                    let key = *follower.key();
                    let _ = self.invalidate(&key, PLANT_TRIES, &mut WorkBudget::new(PLANT_WORK));
                }
                follower.detach();
                self.parked.detached(id);
                continue;
            };
            let checked = match self.read_admission() {
                Ok(()) if now_us >= deadline_us => Err(Status::TimedOut),
                checked => checked,
            };
            let mut work = WorkBudget::new(self.config.lookup_work);
            // A pending or busy follower stays parked in its slot, as does one whose fill a check or visit of this pass found pending; an ended fill takes the full read path.
            let observed = match checked {
                Err(status) => Err(status),
                Ok(()) if self.parked.found_pending(slot) => continue,
                Ok(()) => match self.volume.joined_wait(&entry.follower, retries, &mut work) {
                    Ok(()) => Ok(()),
                    Err(JoinedReadError::Pending) => {
                        self.parked.note_pending(slot);
                        continue;
                    }
                    Err(error) => match joined_status(error) {
                        // A busy gate or a short budget is retried by a later pass.
                        None => {
                            self.parked.owe(slot);
                            continue;
                        }
                        Some((status, defect)) => {
                            self.report.defects += u64::from(defect);
                            Err(status)
                        }
                    },
                },
            };
            let status = match observed {
                // A dropped follower detaches.
                Err(status) => {
                    drop(self.parked.take(slot));
                    status
                }
                Ok(()) => {
                    let Entry {
                        request: id,
                        peer,
                        follower,
                    } = self.parked.take(slot);
                    match self
                        .volume
                        .read_joined(follower, retries, &mut work, deadline_us)
                    {
                        Ok(op) => {
                            self.parked.woke(id);
                            self.serve.restart_progress(&mut self.requests, id, now_us);
                            self.bind(id, op);
                            continue;
                        }
                        Err(JoinedRefusal::Read(refusal)) => self.read_refusal(refusal),
                        Err(JoinedRefusal::Follower(follower, error)) => match joined_status(error)
                        {
                            None => {
                                let entry = Entry {
                                    request: id,
                                    peer,
                                    follower,
                                };
                                let (put, requests) = (&self.put, &self.requests);
                                self.parked.put(entry, |fill| put.produces(requests, fill));
                                self.parked.owe(slot);
                                continue;
                            }
                            Some((status, defect)) => {
                                self.report.defects += u64::from(defect);
                                status
                            }
                        },
                    }
                }
            };
            self.parked.ended(id, status);
            self.serve
                .read_refused(&mut self.requests, id, status, now_us);
        }
    }

    /// Releases every ended request whose read the volume proves drained, unbinding the read.
    fn release(&mut self) {
        let Self {
            requests,
            serve,
            volume,
            bound,
            reads,
            by_op,
            parked,
            ..
        } = self;
        serve.release_drained(requests, |id| {
            // A parked request's slot is released once the wake pass detached its follower.
            let held = parked.holds(id);
            #[cfg(test)]
            let held = held && !super::parked::planted(super::parked::Plant::ReleaseParked);
            if held {
                return false;
            }
            let Some(at) = bound.get_mut(usize::from(id.slot())) else {
                return true;
            };
            match *at {
                Some(read) if read.request == id => {
                    let drained = volume.read_drained(read.op);
                    #[cfg(test)]
                    let drained = drained || RELEASE_UNDRAINED.get();
                    if !drained {
                        return false;
                    }
                    // The volume may already have reused the drained read's slot for a later read, whose mapping stays.
                    let slot = &mut by_op[read.op.slot as usize];
                    if *slot == Some(id.slot()) {
                        *slot = None;
                    }
                    *at = None;
                    *reads -= 1;
                    true
                }
                _ => true,
            }
        });
    }

    /// Cancels the read of every request that ended while its read runs.
    /// The GET scheduler marks each logical end; this pass consumes that mark before scanning running reads.
    fn cancel_ended(&mut self) {
        if !self.serve.take_ends() {
            return;
        }
        // An ended request's parked follower detaches at its next visit.
        self.parked.owe_ended(self.serve.ended_slots());
        for read in self.bound.iter_mut().flatten().take(self.reads as usize) {
            if !read.done && !read.cancelled && self.requests.get_is_ended(read.request) {
                read.cancelled = true;
                // A read already decided or a closed volume refuses; its Done or the close ends it.
                let _: Result<(), ControlRefusal> = self.volume.cancel_read(read.op);
            }
        }
    }

    /// Grants each bound read the commands its request asks for, up to `1 + read_ahead`; a read answered `Exhausted` takes no further grants.
    /// The core counts only the grants the volume adds; a merged grant leaves the request's count unchanged, so `regrant` schedules a retry for the demand it left open.
    /// Grant passes run after read starts, ACKs, chunk deliveries or dropped chunks, and retry refused or merged grants.
    fn grant(&mut self) {
        if !std::mem::take(&mut self.regrant) {
            return;
        }
        let Self {
            bound,
            reads,
            requests,
            serve,
            volume,
            regrant,
            ..
        } = self;
        for read in bound.iter_mut().flatten().take(*reads as usize) {
            while !read.done && !read.exhausted && serve.wants_grant(requests, read.request) {
                match volume.grant_read(read.op) {
                    Ok(Grant::Added) => requests.get_granted(read.request),
                    Ok(Grant::Exhausted) => read.exhausted = true,
                    Ok(Grant::Merged) | Err(_) => {
                        *regrant = true;
                        break;
                    }
                }
            }
        }
    }

    /// Feeds the tick's verified events to the transfer core.
    fn deliver(&mut self, now_us: u64) {
        // The events drain in place, so the vector keeps the capacity the volume's tick needs even if a turn unwinds here.
        let Self {
            events,
            requests,
            serve,
            volume,
            bound,
            by_op,
            report,
            admission,
            regrant,
            ring,
            sessions,
            config,
            ..
        } = self;
        let endpoint = config.endpoint;
        let ring: &KeyRing = ring;
        for event in events.drain(..) {
            match event {
                ReadEvent::Chunk {
                    op,
                    info,
                    range,
                    chunk,
                } => match request_of(by_op, bound, op) {
                    Some(id) if *admission != Admission::Closed && !requests.get_is_ended(id) => {
                        let window_crcs = volume.chunk_crcs(&chunk);
                        let manifest = Manifest::from(&info);
                        // The digests are cached under the request's session when it is the peer's active one; a frame of that request later travels under that session or none.
                        let session = serve.session_of(requests, id).and_then(|(peer, epoch)| {
                            let active = sessions
                                .active(peer)
                                .filter(|active| active.epoch == epoch)?;
                            let nonces = sessions.nonces(active.peer)?;
                            Some((peer, nonces))
                        });
                        let mut digest = session.map(|(peer, nonces)| {
                            move |bytes: &[u8]| {
                                ring.data_digest(peer, endpoint, nonces, [bytes, &[]])
                            }
                        });
                        serve.chunk_with_digests(
                            requests,
                            id,
                            manifest,
                            ChunkInput {
                                range,
                                chunk,
                                window_crcs,
                            },
                            now_us,
                            digest
                                .as_mut()
                                .map(|digest| digest as &mut FragmentDigest<'_>),
                        );
                        *regrant = true;
                    }
                    _ => report.discarded += 1,
                },
                ReadEvent::Done { op, info, status } => {
                    let Some(id) = request_of(by_op, bound, op) else {
                        continue;
                    };
                    if let Some(read) = bound[usize::from(id.slot())].as_mut() {
                        read.done = true;
                    }
                    // `info` is present once the first extent's header
                    // verified, so a key mismatch without it is the lookup's
                    // false positive and one with it a later extent's.
                    let verified = info.is_some();
                    report.false_positives += u64::from(
                        status == ReadStatus::HeaderMismatch(HeaderMismatch::Key) && !verified,
                    );
                    if status == ReadStatus::Lost {
                        admission.lose();
                    }
                    let end = match (status, info) {
                        (ReadStatus::Complete, Some(info)) => {
                            ReadEnd::Complete(Manifest::from(&info))
                        }
                        (status, _) => ReadEnd::Failed(read_status(status, verified)),
                    };
                    serve.read_done(requests, id, end, now_us);
                }
            }
        }
    }

    /// `send_replies` counts the `spent` ownership replies against both send limits and returns the remaining total and control-reply budgets, respectively.
    fn send_replies(&mut self, spent: usize) -> Option<(usize, usize)> {
        // A precheck at the latest deadline sample; each reply below and each send of the transfer core is admitted on its own reading.
        let token = self.volume.serving_token().filter(|token| {
            self.volume
                .admit_authority_at_sample(
                    crate::failover::serving::Operation::Reply {
                        lineage: token.lineage,
                    },
                    Some(*token),
                )
                .is_ok()
        })?;
        let Self {
            ring,
            config,
            transport,
            crc,
            replies,
            waiting,
            reply_cursor,
            report,
            ..
        } = self;
        let mut budget = config.batch as usize - spent;
        // Control replies take at most half the turn's sends; a batch of at least two leaves the transfer core at least one.
        let mut control = (config.batch as usize / 2).saturating_sub(spent);
        if control == 0 {
            return Some((budget, 0));
        }
        let peers = replies.len();
        let mut unvisited = *waiting;
        for step in 0..peers {
            if control == 0 || unvisited == 0 {
                break;
            }
            let at = (usize::from(*reply_cursor) + step) % peers;
            let Some(reply) = replies[at] else {
                continue;
            };
            unvisited -= 1;
            let Some(principal) = ring.principal(reply.peer) else {
                replies[at] = None;
                *waiting -= 1;
                continue;
            };
            let mut body = [0; super::ownership::ReadyBody::LEN];
            let body_len = match reply.kind {
                Kind::Ready if reply.tenure != Some(super::owner_view::tenure_of(token)) => None,
                Kind::Ready => super::ownership::ReadyBody {
                    caps: reply.caps,
                    shard: token.shard,
                    tenure: super::owner_view::tenure_of(token),
                }
                .encode()
                .inspect_err(|_| report.failed += 1)
                .ok()
                .map(|ready| {
                    body.copy_from_slice(&ready);
                    ready.len()
                }),
                _ => {
                    body[..super::frame::BOOTSTRAP_BODY_LEN].copy_from_slice(&reply.caps.body());
                    Some(super::frame::BOOTSTRAP_BODY_LEN)
                }
            };
            let Some(body_len) = body_len else {
                replies[at] = None;
                *waiting -= 1;
                continue;
            };
            let body = &body[..body_len];
            let header = Header {
                principal,
                key_epoch: ring.epoch(),
                owner_nonce: reply.owner_nonce,
                client_nonce: reply.client_nonce,
                sequence: reply.sequence,
                epoch: reply.epoch,
                datagram_len: body.len() as u32,
                ..header(reply.kind, 0, [0; 32])
            };
            if self
                .volume
                .admit_authority(
                    crate::failover::serving::Operation::Reply {
                        lineage: token.lineage,
                    },
                    Some(token),
                )
                .is_err()
            {
                return None;
            }
            let sent = transmit(
                *crc,
                ring,
                transport,
                config.endpoint,
                reply.peer,
                &header,
                [body, &[]],
            );
            sent.record(report);
            if sent == Sent::Blocked {
                // The reply waits for the next poll.
                return None;
            }
            replies[at] = None;
            *waiting -= 1;
            control -= 1;
            budget -= 1;
        }
        *reply_cursor = ((usize::from(*reply_cursor) + 1) % peers.max(1)) as u16;
        Some((budget, control))
    }

    fn admits_reply(&self, token: crate::failover::serving::Token) -> bool {
        self.volume
            .admit_authority(
                crate::failover::serving::Operation::Reply {
                    lineage: token.lineage,
                },
                Some(token),
            )
            .is_ok()
    }
    fn queue_ownership(&mut self, at: usize, reply: OwnershipReply) {
        debug_assert!(self.ownership[at].is_none());
        self.ownership[at] = Some(reply);
        self.ownership_queued[at / 64] |= 1 << (at % 64);
        self.ownership_waiting += 1;
    }
    fn take_ownership(&mut self, at: usize) -> Option<OwnershipReply> {
        let reply = self.ownership[at].take()?;
        self.ownership_queued[at / 64] &= !(1 << (at % 64));
        self.ownership_waiting -= 1;
        Some(reply)
    }
    /// Returns the sends this turn's ownership reply spent, 0 or 1, or `None` when the transport blocks and the reply returns to the queue.
    fn send_ownership(&mut self, now_us: u64) -> Option<usize> {
        if self.ownership_waiting == 0 {
            return Some(0);
        }
        self.send_next_ownership(now_us)
    }
    /// The search and send behind [`send_ownership`](Self::send_ownership), cold and out of line to keep its `ownership_waiting` check small.
    #[cold]
    #[inline(never)]
    fn send_next_ownership(&mut self, now_us: u64) -> Option<usize> {
        let peers = self.ownership.len();
        let cursor = u32::from(self.ownership_cursor);
        let Some((at, pending)) = super::serve::next_set_wrapping(&self.ownership_queued, cursor)
            .and_then(|at| Some((at as usize, self.take_ownership(at as usize)?)))
        else {
            return Some(0);
        };
        self.ownership_cursor = ((at + 1) % peers) as u16;
        let (mut header, binding) = pending;
        let peer = PeerId(at as u16);
        let Some(token) = self.volume.serving_token() else {
            return Some(0);
        };
        if let Some(tenure) = binding {
            if super::owner_view::tenure_of(token) != tenure
                || self.sessions.tenure(peer) != Some(tenure)
                || !self.admits_reply(token)
            {
                return Some(0);
            }
            header.sequence = match self.sessions.next_sequence(peer) {
                Ok(sequence) => sequence,
                Err(SessionReject::Exhausted) => {
                    self.retire_peer(peer, now_us, None);
                    return Some(0);
                }
                Err(_) => return Some(0),
            };
        }
        let mut body = self.ownership_view.body(
            token,
            self.volume.authority_report(),
            self.volume
                .admit_authority(crate::failover::serving::Operation::Read, Some(token))
                .is_ok(),
        );
        body.tenure = binding.or(body.tenure);
        if binding.is_some() && !self.admits_reply(token) {
            return Some(0);
        }
        let mut bytes = [0; super::ownership::OwnershipBody::FIXED_LEN
            + crate::failover::identity::MAX_VOLUME_LEN];
        let len = body.encoded_len();
        if body.encode(header.kind, &mut bytes[..len]).is_err() {
            self.report.failed += 1;
            return Some(0);
        }
        header.key_epoch = self.ring.epoch();
        header.datagram_len = len as u32;
        let sent = transmit(
            self.crc,
            &self.ring,
            &mut self.transport,
            self.config.endpoint,
            peer,
            &header,
            [&bytes[..len], &[]],
        );
        sent.record(&mut self.report);
        if sent == Sent::Blocked {
            self.queue_ownership(at, pending);
            None
        } else {
            Some(1)
        }
    }
    fn send_batch(&mut self, now_us: u64) {
        // Ownership and bootstrap replies share the control half of the batch; alternating precedence gives each class first access every other turn.
        self.ownership_leads = !self.ownership_leads;
        let mut control = 0;
        if self.ownership_leads {
            let Some(sent) = self.send_ownership(now_us) else {
                return;
            };
            control = sent;
        }
        let Some((mut budget, left)) = self.send_replies(control) else {
            let admitted = self
                .volume
                .serving_token()
                .is_some_and(|token| self.admits_reply(token));
            if !self.ownership_leads && !admitted {
                let _ = self.send_ownership(now_us);
            }
            return;
        };
        if !self.ownership_leads && left > 0 {
            let Some(sent) = self.send_ownership(now_us) else {
                return;
            };
            budget -= sent;
        }
        let mut sender = Sender {
            volume: &self.volume,
            token: self.volume.serving_token(),
            crc: self.crc,
            ring: &self.ring,
            sessions: &mut self.sessions,
            endpoint: self.config.endpoint,
            transport: &mut self.transport,
            headers: &mut self.headers,
            exhausted: &mut self.exhausted,
            report: &mut self.report,
        };
        self.serve
            .poll(&mut self.requests, now_us, budget, |frames| {
                sender.send(frames)
            });
        // A session a frame's sequence spent is gone; nothing it carried can complete, so its peer's requests retire with it.
        for at in 0..self.exhausted.len() {
            self.retire_peer(self.exhausted[at], now_us, None);
        }
        self.exhausted.clear();
    }

    fn retire_peer(&mut self, peer: PeerId, now_us: u64, cause: Option<FillFailure>) {
        if self.replies[usize::from(peer.0)].take().is_some() {
            self.waiting -= 1;
        }
        self.take_ownership(usize::from(peer.0));
        self.serve.retire_peer(&mut self.requests, peer, now_us);
        self.put.retire_peer(&mut self.requests, peer, cause);
        self.requests.retire(peer);
    }

    /// Streams `input` into the local fill `fill` through the owner's volume, returning the bytes it took; later polls drive its writes.
    ///
    /// # Errors
    ///
    /// `receive_fill` returns `ReceiveError::Revoked` before consuming input when the installed fencing's `Fencing::admits` returns `false` for `fill`; otherwise, it follows [`WritableFill::receive`].
    pub fn receive_fill(
        &mut self,
        fill: &mut WritableFill<'s, 'a, P>,
        input: &[u8],
        budget: &mut WorkBudget,
    ) -> Result<usize, ReceiveError> {
        if (self.coverage.as_ref())
            .is_some_and(|fencing| !fencing.admits(fill.key(), fill.version()))
        {
            return Err(ReceiveError::Revoked);
        }
        fill.receive(&mut self.volume, input, budget)
    }

    /// The write progress of the local fill `fill` on the owner's volume.
    pub fn fill_progress(&self, fill: &WritableFill<'s, 'a, P>) -> WriteProgress {
        fill.progress(&self.volume)
    }

    /// Publishes the local fill `fill` through the owner's volume, expiring at `expires_at_ticks`. With a fencing installed, the index insert follows a recheck that the coverage admits the fill's key and version, as a wire FILL's does.
    ///
    /// # Errors
    ///
    /// `publish_fill` aborts the supplied fill and returns `Closed` after [`Owner::close`], since an acknowledged close cuts off later publications, or during either [`DrainStage`]. Retrying an aborted fill after [`Owner::resume`] requires a fresh fill. Otherwise, `publish_fill` returns `Superseded` if `coverage` is `Some` and `Fencing::admits` rejects the fill's key and version; in all other cases it delegates to [`WritableFill::publish`].
    pub fn publish_fill(
        &mut self,
        fill: WritableFill<'s, 'a, P>,
        expires_at_ticks: u64,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<ExtentLease<'s, P>, FillPublishError> {
        let id = (fill.shard(), fill.serial());
        let closed = self.admission == Admission::Closed || self.draining().is_some();
        let covered = (self.coverage.as_ref())
            .is_some_and(|fencing| !fencing.admits(fill.key(), fill.version()));
        let published = if closed {
            fill.abort();
            Err(FillPublishError::Closed)
        } else if covered {
            fill.abort();
            Err(FillPublishError::Superseded)
        } else {
            fill.publish(&mut self.volume, expires_at_ticks, tries, budget)
        };
        // The departed fill's followers observe its terminal at their next visit.
        self.parked.departed(id);
        let lease = published?;
        self.published_locally = true;
        self.maintain_rest_until_us = None;
        Ok(lease)
    }

    /// Invalidates `key`'s object in RAM; a read already running finishes with the version it acquired, and later GETs look the key up afresh. Coverage and its page writes belong to [`Owner::invalidate_interval`] and [`Owner::cover_pending`], or [`Owner::cover_begin`] and [`Owner::cover_end`], which carry an INVALIDATE to its acknowledgment.
    ///
    /// # Errors
    ///
    /// After [`Owner::close`] or during [`DrainStage::Mutations`], `invalidate` returns `Closed` and preserves the mapping: an acknowledged close cuts off later invalidations. Otherwise, including during [`DrainStage::Fills`], `invalidate` follows the contract of [`Storage::invalidate`](crate::storage::Storage::invalidate).
    pub fn invalidate(
        &mut self,
        key: &[u8; 32],
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<Invalidation, InvalidateError> {
        if self.admission == Admission::Closed || self.draining() == Some(DrainStage::Mutations) {
            return Err(InvalidateError::Closed);
        }
        let invalidation = self.volume.storage().invalidate(key, tries, budget)?;
        self.maintain_rest_until_us = None;
        Ok(invalidation)
    }

    /// The installed fencing governs FILL admission and INVALIDATE writes for the tenure's coverage pages. Installation requires `PutReport::published` to be zero and `published_locally` to be false, placing it before the owner's first published wire PUT or local fill. Under a warm bootstrap the fencing's coverage must stay as the restart or takeover returned it, with no `hold`, `cover_begin` or `cover_page` before the warm load's `LoadComplete`: the warm source checks restored entries against the coverage as it stood then, and the owner keeps it so by refusing every coverage hold while the readiness reads `Detached` or `Loading`.
    ///
    /// # Errors
    ///
    /// The method returns `fencing` and leaves `self.coverage` unchanged when a fencing is already installed, `Fencing::coverage` is `None`, `Fencing::shard` or `Fencing::session` differs from the volume's tenure, `PutReport::published` is positive, or [`Owner::publish_fill`] has returned a lease. Retaining an installed fencing preserves the entries held by its coverage.
    pub fn install_coverage(&mut self, fencing: Fencing) -> Result<(), Box<Fencing>> {
        let published = self.published_locally || self.put.report().published > 0;
        if self.coverage.is_some()
            || fencing.coverage().is_none()
            || fencing.shard() != self.volume.tenure().shard()
            || fencing.session() != self.volume.tenure_session()
            || published
        {
            return Err(Box::new(fencing));
        }
        self.coverage = Some(fencing);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn coverage_mut(&mut self) -> Option<&mut Fencing> {
        self.coverage.as_mut()
    }

    pub(crate) fn tenure(&self) -> &crate::storage::Session {
        self.volume.tenure()
    }

    pub(crate) fn storage(&self) -> &'s crate::storage::Storage<P> {
        self.volume.storage()
    }

    pub(crate) fn certified(&mut self) -> Option<Vec<(u64, u64)>> {
        self.volume.certified()
    }

    /// Stages the write of unit `unit` of `staged` into its reserved slot, as
    /// [`Volume::stage_unit_write`](crate::storage::Volume), for a later poll's tick to submit.
    ///
    /// # Errors
    ///
    /// `Unadmitted` after a turn unwound or the owner closed; otherwise as the volume's method.
    pub(crate) fn stage_unit_write(
        &mut self,
        possible: &PossiblyNamed,
        staged: &mut StagedCheckpoint,
        unit: u32,
    ) -> Result<(), UnitRefused> {
        self.unit_open()?;
        self.volume.stage_unit_write(possible, staged, unit)
    }

    /// Stages the read-back of unit `unit` of slot `slot`, as the volume's `stage_unit_read`.
    ///
    /// # Errors
    ///
    /// As [`Owner::stage_unit_write`].
    pub(crate) fn stage_unit_read(
        &mut self,
        possible: &PossiblyNamed,
        (slot, unit): (u32, u32),
    ) -> Result<(), UnitRefused> {
        self.unit_open()?;
        self.volume.stage_unit_read(possible, (slot, unit))
    }

    /// The last unit command's result once it ended, with a read-back of `staged`'s slot recorded in `staged`.
    pub(crate) fn take_unit_for(&mut self, staged: &mut StagedCheckpoint) -> Option<UnitDone> {
        self.volume.take_unit_for(staged)
    }

    /// Dispatches a capture pass's whole-cut encode to the volume's recovery helpers, as the volume's `encode`.
    ///
    /// # Errors
    ///
    /// `encode`, undispatched, after a turn unwound or the owner closed; otherwise as the volume's method.
    pub(crate) fn encode(&mut self, encode: Encode) -> Result<(), Box<Encode>> {
        if self.unit_open().is_err() {
            return Err(Box::new(encode));
        }
        self.volume.encode(encode)
    }

    /// Returns `true` if the volume's capture pool accepts the job of freeing `leftovers` off the owner thread.
    pub(crate) fn discard(&mut self, leftovers: Leftovers) -> bool {
        self.volume.discard(leftovers)
    }

    /// Returns `true` once every discard the volume's capture pool accepted has completed.
    pub(crate) fn discarded(&mut self) -> bool {
        self.volume.discarded()
    }

    /// The last encode's terminal once it landed; `Err` when the job panicked.
    pub(crate) fn take_encoded(&mut self) -> Option<Result<Encoded, Panicked>> {
        self.volume.take_encoded()
    }

    /// Releases the terminals a parked test pool of the volume holds.
    #[cfg(test)]
    pub(crate) fn release_parked(&mut self) {
        self.volume.release_parked();
    }

    /// Whether the owner's volume admits `layout` for its checkpoint and suffix writes, as the volume's
    /// `admits_layout`.
    pub(crate) fn admits_layout(&self, layout: &crate::failover::records::Layout) -> bool {
        self.volume.admits_layout(layout)
    }

    /// Admits a capture pass's unit command or encode: no turn unwound and the owner is not closed.
    fn unit_open(&mut self) -> Result<(), UnitRefused> {
        self.observe_unwind();
        if self.poisoned || self.admission == Admission::Closed {
            return Err(UnitRefused::Unadmitted);
        }
        Ok(())
    }

    pub(crate) fn warm_layout(&self) -> Option<crate::failover::records::Layout> {
        self.volume.warm_layout()
    }

    /// INVALIDATE(`key`, `interval`) removes `key`'s object and revokes its current attempt, as [`Storage::invalidate`](crate::storage::Storage::invalidate), then holds the entry in the tenure's coverage to block FILL admission for versions in `interval`. Removal and coverage installation form one exclusive operation. Removal ends every version of `key`, treating versions outside `interval` as hidden evictions. [`Owner::cover_end`], directly or through [`Owner::cover_pending`], acknowledges the held entry.
    ///
    /// # Errors
    ///
    /// `invalidate_interval` returns `Closed` when `mutation_open` fails after unwind observation, `Withdrawn` for absent or withdrawn fencing and for a serving authority in `Withdrawn` or `Closed`, and `Contended` when `INVALIDATIONS` pairs are queued and the pair is new, or while readiness reads `Detached` or `Loading` and the attach restores bindings through a warm bootstrap, which can still install and publish a restored binding of the key after the removal. It propagates removal errors. Errors preserve coverage and queued pairs. If the entry already has a queued pair, the method returns `Ok(None)` and preserves the earlier removal.
    pub fn invalidate_interval(
        &mut self,
        key: &[u8; 32],
        interval: Interval,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<Option<Invalidation>, InvalidateError> {
        self.observe_unwind();
        self.mutation_open().map_err(|_| InvalidateError::Closed)?;
        self.hold_invalidation(None, (*key, interval), tries, budget)
    }

    /// The count of INVALIDATE pairs held toward their acknowledgment, those whose page write is in flight on the
    /// store lane included.
    pub(crate) fn held_invalidations(&self) -> usize {
        self.invalidations.len()
    }

    fn hold_invalidation(
        &mut self,
        asker: Option<Asker>,
        entry: CoverageEntry,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<Option<Invalidation>, InvalidateError> {
        if (self.coverage.as_ref()).is_none_or(|fencing| fencing.coverage().is_none()) {
            return Err(InvalidateError::Withdrawn);
        }
        if matches!(
            self.volume.authority_state(),
            crate::failover::serving::State::Withdrawn | crate::failover::serving::State::Closed
        ) {
            return Err(InvalidateError::Withdrawn);
        }
        if self.readiness().initializing() && self.volume.warms() {
            return Err(InvalidateError::Contended);
        }
        let session = |asker: Option<Asker>| asker.map(|asker| (asker.peer, asker.epoch));
        let joins = |held: &Held| {
            held.0 == entry
                && (asker.is_none() || held.1.is_none() || session(held.1) == session(asker))
        };
        if let Some(held) = self.invalidations.iter_mut().find(|held| joins(held)) {
            // Datagrams reorder, so the owner answers the same-session INVALIDATE for an entry with the highest session sequence; a wire asker also takes a local row's slot.
            if asker.map(|asker| asker.sequence) > held.1.map(|held| held.sequence) {
                held.1 = asker;
            }
            return Ok(None);
        }
        if self.invalidations.len() == INVALIDATIONS {
            return Err(InvalidateError::Contended);
        }
        let removal = if self.invalidations.iter().any(|held| held.0 == entry) {
            None
        } else {
            Some(self.invalidate(&entry.0, tries, budget)?)
        };
        (self.coverage.as_mut())
            .expect("the first guard returns Withdrawn while no fencing is installed")
            .hold(entry);
        self.invalidations.push((entry, asker));
        Ok(removal)
    }

    /// Takes an admitted INVALIDATE frame: its interval, the allocation field through the offset field, is held as [`Owner::invalidate_interval`] holds one, and its INVALIDATED is queued once [`Owner::cover_end`], directly or through [`Owner::cover_pending`], acknowledges it. An inverted interval changes nothing.
    fn take_invalidate(&mut self, session: Admitted, header: &Header) -> bool {
        let (low, high) = (CacheVersion(header.allocation), CacheVersion(header.offset));
        let Some(interval) = Interval::new(low, high) else {
            return false;
        };
        let (tries, mut budget) = (
            self.config.put.publish_tries,
            WorkBudget::new(self.config.put.publish_work),
        );
        let asker = Some(Asker {
            peer: session.peer,
            epoch: session.epoch,
            request: header.request,
            sequence: header.sequence,
        });
        (self.hold_invalidation(asker, (header.key, interval), tries, &mut budget)).is_ok()
    }

    /// `cover_pending` runs [`Owner::cover_begin`] and [`Owner::cover_end`] synchronously for each held page while borrowing the owner. It appends entries covered by acknowledged page writes to `acknowledged`, queues INVALIDATED for each covered wire INVALIDATE, and retains unresolved entries for the next call. Before any store call, it retains all held entries and returns when `mutation_open` succeeds and authority is `PreBoundary` or `Recovering`; it discards all held entries when `mutation_open` fails or authority is `Withdrawn` or `Closed`. An observed newer fence or store regression withdraws the owner's serving authority at `now_us` before return. A page write still in flight from [`Owner::cover_begin`] is abandoned first: its entries stay held for this call's writes, and its reply, should one reach [`Owner::cover_end`], acknowledges nothing.
    ///
    /// # Errors
    ///
    /// The fencing's withdrawal, which drops every held entry unacknowledged.
    pub fn cover_pending<S: Store, L: WatermarkLog>(
        &mut self,
        client: &mut Client<S, L>,
        acknowledged: &mut Vec<CoverageEntry>,
        now_us: u64,
    ) -> Result<(), Withdraw> {
        self.covering = false;
        let mut after = None;
        while let Some(mut request) = self.cover_begin(after, now_us)? {
            after = Some(request.page());
            while let Cover::Next(next) =
                self.cover_end(request.run(client), acknowledged, now_us)?
            {
                request = next;
            }
        }
        Ok(())
    }

    /// Whether an INVALIDATE is held or a page write is in flight. While neither is, [`Owner::cover_begin`] starts no write and changes nothing.
    #[inline]
    pub fn cover_waits(&self) -> bool {
        !self.invalidations.is_empty() || self.covering
    }

    /// Whether coverage page writes may go on: after unwind observation, `mutation_open` succeeds and authority is `Serving`. While it is `PreBoundary` or `Recovering` the held entries stay held; when `mutation_open` fails or authority is `Withdrawn` or `Closed`, every held entry is discarded unacknowledged. Either `false` ends the page write in flight, if any, with nothing acknowledged, so a caller holding a follow-up request of that write drops it.
    pub fn cover_open(&mut self) -> bool {
        use crate::failover::serving::State;
        self.observe_unwind();
        let open = self.mutation_open().is_ok();
        match self.volume.authority_state() {
            State::Serving if open => return true,
            State::PreBoundary | State::Recovering if open => {}
            _ => self.invalidations.clear(),
        }
        self.covering = false;
        false
    }

    /// Whether [`Owner::cover_open`] holds and the page write [`Owner::cover_begin`] started is still in flight. Callers may issue a request saved from that write only while `cover_continues` returns `true`.
    pub fn cover_continues(&mut self) -> bool {
        self.cover_open() && self.covering
    }

    /// Starts the coverage page write of the first held page above `after`, in page order, and returns its request; the caller runs it on the shard's store client and passes the reply to [`Owner::cover_end`], then each `Cover::Next` request in turn, until the step ends. At most one write is in flight: from the returned request until [`Owner::cover_end`] ends its step, `cover_begin` returns `Ok(None)`. Its entries are every entry held on the page when it starts; an entry held on the page later waits for the next write. The write's entries, hull and saturation enter the coverage before the call returns (COVER-BEFORE-SUBMIT).
    ///
    /// `Ok(None)` also when [`Owner::cover_open`] is `false`, no held page lies above `after`, no fencing is installed, or the fencing has a page unfenced, which issues no request.
    ///
    /// # Errors
    ///
    /// The fencing's latched withdrawal, which discards every held entry unacknowledged; a newer fence or store regression also withdraws the owner's serving authority at `now_us`.
    pub fn cover_begin(
        &mut self,
        after: Option<u16>,
        now_us: u64,
    ) -> Result<Option<PageRequest>, Withdraw> {
        if !self.cover_open() || self.covering {
            return Ok(None);
        }
        let Some(fencing) = self.coverage.as_mut() else {
            return Ok(None);
        };
        let pages = fencing.pages();
        let page = |(entry, _): &Held| page_of(&entry.0, pages);
        // A stable order: a page's entries reach its write in the order they were held, so the write merges them as the holds did and blocks what the coverage already blocks, no further hull.
        self.invalidations.sort_by_key(page);
        let next = (self.invalidations.iter())
            .position(|held| after.is_none_or(|after| page(held) > after));
        let Some(from) = next else {
            return Ok(None);
        };
        let on = page(&self.invalidations[from]);
        let end = from + self.invalidations[from..].partition_point(|held| page(held) == on);
        self.page_entries.clear();
        (self.page_entries).extend(self.invalidations[from..end].iter().map(|held| held.0));
        match fencing.cover_begin(&self.page_entries) {
            Ok(request) => {
                self.covering = request.is_some();
                Ok(request)
            }
            Err(withdraw) => Err(self.withdraw_coverage(withdraw, now_us)),
        }
    }

    /// Applies `reply`, the store's reply to the last request of the write [`Owner::cover_begin`] started, and returns the fencing's decision. `Cover::Next` continues the same write with its next request, returned only while the write is in flight and [`Owner::cover_open`] holds; otherwise the write ends as `Cover::Unresolved` and the continuation is dropped, so no store request leaves the owner after its authority ended. A caller that defers a returned request issues it only while [`Owner::cover_continues`] holds. `Cover::Unresolved` and `Cover::Rebased` end the write with its entries still held for a later write, discarded instead when [`Owner::cover_open`] is then `false` under a terminal state. `Cover::Done` reports the write's acknowledged commit, which the fencing adopts: if [`Owner::cover_open`] is then `true`, every held entry the write carried leaves the held list, appended to `acknowledged` once per call however many sessions held it, with INVALIDATED queued for each wire asker, a later asker of a carried entry included; otherwise nothing is acknowledged. So `Done` alone does not mean an entry was acknowledged: the entries appended to `acknowledged` are the acknowledgment.
    ///
    /// # Errors
    ///
    /// `Withdraw::Unpaired`, with nothing applied and the write still in flight, when `reply` answers no request the fencing awaits. Any other withdrawal ends the write and discards every held entry unacknowledged; a newer fence or store regression also withdraws the owner's serving authority at `now_us`.
    pub fn cover_end(
        &mut self,
        reply: PageReply,
        acknowledged: &mut Vec<CoverageEntry>,
        now_us: u64,
    ) -> Result<Cover, Withdraw> {
        let Some(fencing) = self.coverage.as_mut() else {
            self.covering = false;
            return Ok(Cover::Unresolved);
        };
        let ended = match fencing.cover_end(reply) {
            Err(Withdraw::Unpaired) => return Err(Withdraw::Unpaired),
            Ok(Cover::Next(next)) if self.cover_continues() => {
                return Ok(Cover::Next(next));
            }
            // A continuation the gate refuses ends the write with nothing acknowledged.
            Ok(Cover::Next(_)) => Ok(Cover::Unresolved),
            ended => ended,
        };
        let in_flight = std::mem::take(&mut self.covering);
        match ended {
            Ok(Cover::Done) => {}
            Ok(cover) => {
                self.cover_open();
                return Ok(cover);
            }
            Err(withdraw) => return Err(self.withdraw_coverage(withdraw, now_us)),
        }
        if !self.cover_open() || !in_flight {
            return Ok(Cover::Done);
        }
        let appended_from = acknowledged.len();
        let (carried, serve) = (&self.page_entries, &mut self.serve);
        // The write's entries were a run of the held list in its order, so the next held entry it carried is usually the next carried one, and the search of all of them serves an entry held since.
        let mut next = 0;
        // One bit per key of an acknowledged entry: an entry whose bit is clear was not acknowledged in this call.
        let mut seen = 0_u128;
        self.invalidations.retain(|&(entry, asker)| {
            if carried.get(next) == Some(&entry) {
                next += 1;
            } else if !carried.contains(&entry) {
                return true;
            }
            let (head, _) = entry
                .0
                .split_first_chunk::<8>()
                .expect("a key holds 8 bytes");
            let bit = 1 << (u64::from_le_bytes(*head).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 57);
            // Several sessions can hold one entry; this write acknowledges the entry once.
            if seen & bit == 0 || !acknowledged[appended_from..].contains(&entry) {
                acknowledged.push(entry);
            }
            seen |= bit;
            if let Some(asker) = asker {
                serve.queue_invalidated(asker, entry);
            }
            false
        });
        Ok(Cover::Done)
    }

    fn withdraw_coverage(&mut self, withdraw: Withdraw, now_us: u64) -> Withdraw {
        use crate::failover::serving::{Cause, Event};
        self.invalidations.clear();
        let cause = match withdraw {
            Withdraw::NewerFence { page, fence } => Some(Cause::NewerFence { page, fence }),
            Withdraw::Store(StoreError::Regression(_)) => Some(Cause::Regression),
            _ => None,
        };
        if let Some(cause) = cause {
            self.authority_event(Event::Withdraw(cause), now_us);
        }
        withdraw
    }

    /// Advances the applied coverage position, as [`Storage::advance_coverage`](crate::storage::Storage::advance_coverage), whose promise the caller makes for every event at or below `position`.
    ///
    /// # Errors
    ///
    /// As for [`Storage::advance_coverage`](crate::storage::Storage::advance_coverage).
    pub fn advance_coverage(&mut self, position: u64) -> Result<Advance, CoverageError> {
        self.volume.storage().advance_coverage(position)
    }

    pub fn readiness(&self) -> crate::storage::Readiness {
        self.volume.readiness()
    }

    /// Begins replay once readiness reads `Loaded`, under a subscription to `feed` resuming after position `from`,
    /// as [`Volume::begin_replay`](crate::storage::Volume::begin_replay) does.
    ///
    /// # Errors
    ///
    /// As for [`Volume::begin_replay`](crate::storage::Volume::begin_replay).
    pub fn begin_replay(
        &mut self,
        feed: crate::storage::FeedContract,
        from: u64,
    ) -> Result<crate::storage::Readiness, crate::storage::ReadinessError> {
        let moved = self.volume.begin_replay(feed, from);
        self.end_rest_at_live(moved);
        moved
    }

    /// Reports that replay reached the feed's tip once readiness reads `Replaying`, as
    /// [`Volume::complete_replay`](crate::storage::Volume::complete_replay) does.
    ///
    /// # Errors
    ///
    /// As for [`Volume::complete_replay`](crate::storage::Volume::complete_replay).
    pub fn complete_replay(
        &mut self,
    ) -> Result<crate::storage::Readiness, crate::storage::ReadinessError> {
        let moved = self.volume.complete_replay();
        self.end_rest_at_live(moved);
        moved
    }

    fn end_rest_at_live(
        &mut self,
        moved: Result<crate::storage::Readiness, crate::storage::ReadinessError>,
    ) {
        if moved == Ok(crate::storage::Readiness::Live) {
            self.maintain_rest_until_us = None;
        }
    }

    /// Formats the owner's volume through [`Volume::format`](crate::storage::Volume::format): the request is
    /// accepted only while the bootstrap reads `Unformatted`, both root slots read and decoded invalid, and `Ok(())`
    /// reports the accepted request; the RESET writes follow in later polls.
    ///
    /// # Errors
    ///
    /// As for [`Volume::format`](crate::storage::Volume::format).
    pub fn format(&mut self) -> Result<(), crate::storage::MetadataOutcome> {
        self.volume.format()
    }

    /// Replaces every peer's key with `entries` at key epoch `epoch` in place while no request is live, retiring every session and drawing a fresh boot nonce; the bundle, its attachment and every charge stay, so resident objects serve again once peers bootstrap under the new keys.
    ///
    /// # Errors
    ///
    /// `Poisoned` after a turn unwound, `Rekey(Busy)` with the census while any request is active or draining, `Rekey(Keys)` for a refused key set, or `Entropy`; each changes nothing.
    pub fn rekey(
        &mut self,
        entries: &[KeyEntry<'_>],
        epoch: u32,
        now_us: u64,
    ) -> Result<(), OwnerRekeyError> {
        self.rekey_with_nonce(entries, epoch, now_us, os_entropy)
    }

    /// [`rekey`](Self::rekey) with the fresh boot nonce filled by `nonce`
    /// where `rekey` reads the operating system's entropy: after the
    /// `Poisoned` and `Busy` checks and before the key set is loaded.
    ///
    /// # Errors
    ///
    /// As [`rekey`](Self::rekey).
    pub(super) fn rekey_with_nonce(
        &mut self,
        entries: &[KeyEntry<'_>],
        epoch: u32,
        now_us: u64,
        nonce: impl FnOnce(&mut [u8; 16]) -> Result<(), EntropyError>,
    ) -> Result<(), OwnerRekeyError> {
        self.observe_unwind();
        if self.poisoned {
            return Err(OwnerRekeyError::Poisoned);
        }
        let census = self.requests.census();
        if census.live() > 0 {
            return Err(OwnerRekeyError::Rekey(RekeyError::Busy { census }));
        }
        let nonce = nonce_from(nonce).map_err(OwnerRekeyError::Entropy)?;
        self.sessions
            .rekey(&mut self.ring, entries, epoch, nonce, census)
            .map_err(OwnerRekeyError::Rekey)?;
        for peer in 0..self.peers {
            self.retire_peer(PeerId(peer), now_us, None);
        }
        Ok(())
    }

    /// This owner's boot nonce, which every session it activates carries.
    pub fn boot_nonce(&self) -> [u8; 16] {
        self.sessions.nonce()
    }

    /// When maintenance rests until, or `None` while it has more work.
    #[cfg(test)]
    pub(super) fn maintain_rest_until_us(&self) -> Option<u64> {
        self.maintain_rest_until_us
    }

    /// The key epoch of this owner's ring, which every frame it seals names.
    #[cfg(test)]
    pub(super) fn key_epoch(&self) -> u32 {
        self.ring.epoch()
    }

    /// The receive windows prepared so far and the GETs they held.
    #[cfg(test)]
    pub(super) fn windows(&self) -> Windows {
        self.windows
    }

    /// The bytes start charged for the receive window's keys and the
    /// lookahead.
    #[cfg(test)]
    pub(super) fn window_charge(&self) -> usize {
        self.window_charge
    }

    /// Whether the lookahead holds no entry.
    #[cfg(test)]
    pub(super) fn preparation_is_empty(&self) -> bool {
        self.preparation.is_empty()
    }

    /// Receive slots that still hold a lease.
    #[cfg(test)]
    pub(super) fn held_receive_leases(&self) -> usize {
        self.scratch.iter().filter(|lease| lease.is_some()).count()
    }

    /// Protected intervals the owner's registration has entered: one per
    /// lookup that reached its pin.
    #[cfg(test)]
    pub(super) fn lookups(&self) -> u64 {
        let storage = self.registration.storage();
        storage
            .registration_report(self.registration.index())
            .map_or(0, |report| report.intervals)
    }

    #[cfg(test)]
    pub(super) fn record_session(&self) -> u64 {
        self.volume.session()
    }

    /// What still keeps the owner from shutting down: the owner not yet closed, live requests, or a volume not yet quiesced.
    pub fn blockers(&self) -> Option<Blockers> {
        let blockers = self.blockers_now();
        (blockers.open || blockers.census.live() > 0 || !self.quiesced()).then_some(blockers)
    }

    fn blockers_now(&self) -> Blockers {
        Blockers {
            open: self.admission != Admission::Closed,
            poisoned: self.poisoned(),
            census: self.requests.census(),
            quiesce: self.quiesce,
        }
    }

    /// Releases the owner once it closed, every request was released and the volume quiesced, so every logical outcome was established before the volume's release consumes its undelivered events; returns the facade, the registration, the quiesce proof, the volume's driver, the transport and the owner's counters.
    ///
    /// # Errors
    ///
    /// The owner and its [`blockers`](Self::blockers); nothing is released and every custody stays.
    pub fn shutdown(mut self) -> Result<Shutdown<'s, P, D, T>, Box<(Self, Blockers)>> {
        if let Some(blockers) = self.blockers() {
            return Err(Box::new((self, blockers)));
        }
        let report = self.report();
        match self.volume.release_driver() {
            Ok((proof, disk)) => Ok(Shutdown {
                cache: self.cache,
                registration: self.registration,
                proof,
                disk,
                transport: self.transport,
                report,
            }),
            // A quiesced volume reports `Quiesced` again; the owner comes back whole if the device says otherwise.
            Err(refused) => {
                let (volume, progress) = *refused;
                self.volume = volume;
                self.quiesce = Some(progress);
                let blockers = self.blockers_now();
                Err(Box::new((self, blockers)))
            }
        }
    }

    /// Stops admission and sends at `now_us`, ends every request, cancels every running read while the volume still accepts cancellation, then closes the volume and returns its quiesce progress; later polls keep ticking storage and closing the volume until it quiesces, discard its chunks and release requests as their reads drain.
    pub fn close(&mut self, now_us: u64) -> crate::storage::QuiesceProgress {
        self.observe_unwind();
        self.admission = Admission::Closed;
        self.sessions.end_sessions();
        self.invalidations.clear();
        for peer in 0..self.peers {
            self.retire_peer(PeerId(peer), now_us, Some(FillFailure::Closed));
        }
        // Retiring every peer ended every request, so this cancels every running read.
        self.cancel_ended();
        let progress = self.volume.close();
        self.quiesce = Some(progress);
        progress
    }

    /// Moves admission to `stage` when `stage` lies past the current one. Leaving `Admission::Open`, for either stage,
    /// ends every upload that has not published with `Status::OwnerUnavailable`; an upload that published keeps its
    /// queued PUT RESULT. Entering `DrainStage::Mutations` drops the held INVALIDATEs unacknowledged and ends the
    /// in-flight coverage write with nothing acknowledged, as a `false` [`Owner::cover_open`] does: its reply, should
    /// one reach [`Owner::cover_end`], acknowledges nothing, and a follow-up request it asks for, the saturated write
    /// after a size rejection included, is dropped. The drain first observes an unwound turn and latches a volume loss
    /// into admission. A request
    /// at or below the current drain stage preserves that stage, and lost and closed admission remain unchanged. A
    /// drain that installs a stage or meets the owner draining records `draining` on the exit that
    /// [`Owner::exit_received`] recorded, so an operation that replaced the tracked one during the drain reads
    /// `draining` after the next request.
    pub fn drain(&mut self, stage: DrainStage, now_us: u64) {
        self.observe_unwind();
        if self.volume.is_lost() {
            self.admission.lose();
        }
        #[cfg(test)]
        let stage = match super::owner_drain_tests::planted(
            super::owner_drain_tests::Plant::MutationsAdmitted,
        ) {
            true => DrainStage::Fills,
            false => stage,
        };
        let open = match self.admission {
            Admission::Open => true,
            Admission::Draining(at) if at < stage => false,
            Admission::Draining(_) => {
                if let Some(exit) = self.exit.as_mut() {
                    exit.draining();
                }
                return;
            }
            Admission::Lost | Admission::Closed => return,
        };
        self.admission = Admission::Draining(stage);
        if open {
            self.put.stop_fills(
                &mut self.requests,
                &mut self.serve,
                Status::OwnerUnavailable,
                now_us,
            );
        }
        if stage == DrainStage::Mutations {
            self.drop_held();
        }
        if let Some(exit) = self.exit.as_mut() {
            exit.draining();
        }
    }

    /// Drops the held INVALIDATEs unacknowledged and ends the in-flight coverage write with nothing acknowledged.
    /// The fencing awaits that write's reply until a later [`Owner::cover_begin`] issues a request, whose step the
    /// fencing then awaits instead, so the earlier reply refuses `Withdraw::Unpaired`.
    fn drop_held(&mut self) {
        self.invalidations.clear();
        self.covering = false;
    }

    /// Observes an unwound turn and latches a volume loss into admission, then records `reason` on the exit
    /// [`Owner::exit_received`] recorded and reopens admission from a drain stage. Both require an authority that is
    /// neither withdrawn nor closed, a live volume and an unpoisoned owner; otherwise `resume` returns false. Returns
    /// whether admission reopened: an open owner returns false and records `reason` if an exit tracker exists.
    /// Uploads and held INVALIDATEs the drain ended stay ended.
    pub fn resume(&mut self, reason: crate::failover::report::Resume) -> bool {
        use crate::failover::serving::State;
        self.observe_unwind();
        if self.volume.is_lost() {
            self.admission.lose();
        }
        let withdrawn = matches!(
            self.volume.authority_state(),
            State::Withdrawn | State::Closed
        );
        let reopen = match self.admission {
            Admission::Draining(_) => true,
            Admission::Open => false,
            Admission::Lost | Admission::Closed => return false,
        };
        if withdrawn || self.poisoned() {
            return false;
        }
        if reopen {
            self.admission = Admission::Open;
            self.maintain_rest_until_us = None;
        }
        if let Some(exit) = self.exit.as_mut() {
            exit.resumed(reason);
        }
        reopen
    }

    /// Records the accepted planned request `operation`. A call before the drain lets the report entry read
    /// `draining`. Another operation replaces the tracked one, and a repeat of the tracked operation preserves its
    /// status. The request's deadline stays with the caller, which resumes at it before the withdrawal.
    pub fn exit_received(&mut self, operation: crate::failover::report::ExitOperation) {
        use crate::failover::report::ExitTracker;
        let session = self.volume.tenure();
        let authority = self.volume.authority_report();
        let host = session.target().owner;
        (self.exit)
            .get_or_insert_with(|| ExitTracker::new(session.shard(), host))
            .received(operation, &authority);
    }

    /// Whether a published fill's first PUT RESULT waits in the reply rings: the fill published and its client has
    /// yet to be sent the result. A replay of a retained terminal stays out of the count. Reads one counter.
    pub fn put_results_queued(&self) -> bool {
        self.serve.put_results_queued()
    }

    /// Records the planned transfer to `target` the driver submitted, while [`Owner::close`] has closed admission,
    /// the authority stands withdrawn for `Cause::Planned` with no flip request and no transfer is recorded:
    /// `serve::ended` then keeps the withdrawn tenure polling, with nothing received or sent, until the driver
    /// settles it. Returns whether the owner recorded it; an owner whose admission is open or draining records
    /// nothing, a tenure that serves or withdrew for another cause keeps the exit its state names, and an outstanding
    /// or committed transfer stays as it was.
    pub fn transfer_submitted(&mut self, target: crate::failover::records::Host) -> bool {
        let authority = self.volume.authority_report();
        let planned = self.admission == Admission::Closed
            && authority.state == crate::failover::serving::State::Withdrawn
            && authority.withdrawal == Some(crate::failover::serving::Cause::Planned)
            && authority.flip.is_none()
            && self.handoff.is_none();
        if planned {
            self.handoff = Some(Handoff::Outstanding { target });
        }
        planned
    }

    /// Settles the outstanding transfer with the store's acknowledgment `transferred`, whose committed record names
    /// the outstanding target owner of this shard at this tenure's `E + 1` with no standby: the owner's views observe
    /// that record on `volume`, and `serve::ended` ends the tenure `Stopped`. Returns whether it settled; another
    /// record, or no outstanding transfer, leaves the handoff as it was.
    pub fn transfer_committed(
        &mut self,
        transferred: &crate::storage::store::Transferred,
        volume: crate::failover::records::VolumeId,
        now: u64,
    ) -> bool {
        let Some(Handoff::Outstanding { target }) = self.handoff else {
            return false;
        };
        let own = self.volume.tenure().target();
        let record = transferred.committed().value();
        let named = record.shard == self.volume.tenure().shard()
            && record.generation == own.generation
            && record.owner == target
            && record.standby.is_none()
            && Some(record.attempts) == own.attempts.checked_add(1);
        if named {
            self.handoff = Some(Handoff::Committed);
            self.observe_shard_view(volume, Some(transferred.committed()), None, None, now);
        }
        named
    }

    /// Clears the planned transfer once its driver decided the exit or the restart.
    pub fn transfer_settled(&mut self) {
        self.handoff = None;
    }

    /// Where the withdrawn owner's planned transfer stands.
    pub fn transfer(&self) -> Option<Handoff> {
        self.handoff
    }

    /// Records that the exit [`Owner::exit_received`] recorded restarts once for `reason`, while it has not ended.
    pub fn exit_restarting(&mut self, reason: crate::failover::report::Restart) {
        if let Some(exit) = self.exit.as_mut() {
            exit.restarting(reason);
        }
    }

    /// Returns the active drain stage, or `None` for open, lost or closed admission.
    pub fn draining(&self) -> Option<DrainStage> {
        match self.admission {
            Admission::Draining(stage) => Some(stage),
            Admission::Open | Admission::Lost | Admission::Closed => None,
        }
    }

    /// The volume's last quiesce progress, once the owner closed.
    pub fn quiesce(&self) -> Option<crate::storage::QuiesceProgress> {
        self.quiesce
    }

    /// The transport, for a test's view of the device custody its chains carry.
    #[cfg(test)]
    pub(super) fn transport(&self) -> &T {
        &self.transport
    }

    /// The transport, for a test's control of the port behind it.
    #[cfg(test)]
    pub(super) fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Consumes the owner between turns, returning its open volume, transport and custody as they stand; after a turn unwound, `armed` still set, it returns the owner unchanged.
    #[cfg(test)]
    pub(super) fn extract(self) -> Result<Extracted<'s, 'a, 'm, P, D, T>, Box<Self>> {
        if self.armed {
            return Err(Box::new(self));
        }
        let Self {
            cache,
            registration,
            volume,
            requests,
            put,
            transport,
            ..
        } = self;
        Ok(Extracted {
            custody: Custody {
                requests,
                _put: put,
            },
            bundle: Bundle {
                cache,
                registration,
                volume,
            },
            transport,
        })
    }
}

/// What a consuming extraction returns: the bundle with its volume open, the transport, and the custody the owner held, its request records and upload lanes, which keep every chunk, fill and source they hold until the caller drops them.
#[cfg(test)]
pub(super) struct Extracted<'s, 'a, 'm, P: Platform, D: Disk, T> {
    pub(super) custody: Custody<'s, 'a, 'm, P>,
    pub(super) bundle: Bundle<'s, 'a, P, D>,
    pub(super) transport: T,
}

/// The request records and upload lanes an extracted owner held.
#[cfg(test)]
pub(super) struct Custody<'s, 'a, 'm, P: Platform> {
    pub(super) requests: Requests<ValidatedChunk<'a>, Put<'s, 'a, P>>,
    /// Held for the receive leases its lanes hold, which return when it drops.
    _put: PutCore<'m>,
}

/// What a shut-down owner returns: the facade and registration, the volume's quiesce proof and its driver, the transport, and the owner's counters.
pub struct Shutdown<'s, P: Platform, D, T> {
    pub cache: Cache<'s, P>,
    pub registration: Registration<'s, P>,
    pub proof: Quiesced,
    /// The volume's driver. Under `Quiesced::AllReturned` it still
    /// runs, so the caller quiesces it until it reports `Stopped` before its
    /// stop proof and the detach that follows the registration's undo.
    pub disk: D,
    /// The transport, whose device the caller stops before undoing the registration.
    pub transport: T,
    pub report: OwnerReport,
}

/// What keeps an owner from shutting down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blockers {
    /// The owner has not closed.
    pub open: bool,
    /// A turn unwound, so admission ended while every read kept its custody.
    pub poisoned: bool,
    /// Requests still active or draining, each holding its read's custody.
    pub census: super::requests::RequestCensus,
    /// The volume's last quiesce progress.
    pub quiesce: Option<crate::storage::QuiesceProgress>,
}

/// Why a re-key did not run; nothing changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerRekeyError {
    Rekey(RekeyError),
    Entropy(EntropyError),
    /// A turn unwound, so the state a re-key would keep may be half applied.
    Poisoned,
}

/// A refused start: why, and the bundle and transport it returns.
pub struct Refused<'s, 'a, P: Platform, D: Disk, T> {
    pub error: OwnerError,
    pub bundle: Bundle<'s, 'a, P, D>,
    pub transport: T,
}

/// The peers an owner serves: one principal per peer, in [`PeerId`] order, their keys at key epoch `epoch`, and the principals granted PUT.
#[derive(Debug, Clone, Copy)]
pub struct Keys<'k> {
    pub principals: &'k [u32],
    pub entries: &'k [KeyEntry<'k>],
    pub epoch: u32,
    /// The principals that may PUT, each one of `principals`; every other peer is refused PUT. A re-key keeps the grant.
    pub put: &'k [u32],
}

impl<P: Platform, D: Disk, T> std::fmt::Debug for Refused<'_, '_, P, D, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Refused")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// PUT DATA datagrams authenticated in one pass, the width of the SHA-256 kernel's chain group.
const DATA_GROUP: usize = 4;

#[inline]
fn is_put_data(bytes: &[u8]) -> bool {
    bytes.get(KIND_AT) == Some(&(Kind::PutData as u8))
}

/// Whether the kind byte of `bytes` says GET; false for bytes that end before it.
#[inline]
fn is_get(bytes: &[u8]) -> bool {
    bytes.get(KIND_AT) == Some(&(Kind::Get as u8))
}
type OwnershipReply = (Header, Option<super::ownership::Tenure>);

/// The receive window's capacity `C = min(batch, BatchMax)`, `BatchMax` zero without an index, when `C >= 2` and `lookup_work >= AHEAD`; otherwise zero.
fn window_width<P: Platform>(config: &OwnerConfig, storage: &crate::storage::Storage<P>) -> usize {
    let max = storage
        .index_geometry()
        .map_or(0, crate::index::ValidatedIndex::batch_max);
    let width = (config.batch as usize).min(max);
    if width >= 2 && config.lookup_work >= AHEAD {
        width
    } else {
        0
    }
}

/// The lease of a received datagram that may start or extend a receive window: a leased datagram from a configured peer whose kind byte says GET, the only kind that can parse as a GET.
#[inline]
fn get_candidate<'l, 'm>(
    lease: &'l Option<PacketLease<'m>>,
    meta: Received,
) -> Option<&'l PacketLease<'m>> {
    let lease = lease.as_ref()?;
    meta.peer?;
    is_get(lease.bytes()).then_some(lease)
}

/// The number of 192-byte chunks of a datagram that has the packed shape and that datagram's peer, `None` for every
/// other datagram. The shape
/// is a leased datagram from a configured peer with a clear truncation flag, whose length is exactly `k` whole 192-byte frames for `k` from 2 to [`MAX_PACKED_GETS`], and whose every frame's kind
/// byte says GET. The test reads the metadata, the length and the kind bytes alone, before any parse. `parse` refuses
/// every datagram of that shape, because a GET frame declares an empty body, so the shape gives no datagram `parse`
/// accepts a second meaning.
#[inline]
fn packed_gets(lease: Option<&PacketLease<'_>>, meta: Received) -> Option<(usize, PeerId)> {
    let lease = lease?;
    // One frame's length is below the shape's two frames.
    if lease.len() == HEADER_LEN {
        return None;
    }
    let (frames, rest) = lease.bytes().as_chunks::<HEADER_LEN>();
    let peer = meta.peer?;
    (!meta.truncated
        && rest.is_empty()
        && (2..=MAX_PACKED_GETS).contains(&frames.len())
        && frames.iter().all(|frame| is_get(frame)))
    .then_some((frames.len(), peer))
}

/// The tag input of the frame from `peer` whose authenticated bytes are `header`, a frame whose tag covers the header
/// and an empty body, when the ring admits its principal and key epoch for that peer. It inlines into the window's
/// tag pass, where a group's chains start once its frames' inputs are built.
#[inline]
fn tag_input<'b>(
    ring: &KeyRing,
    endpoint: u32,
    header: &'b [u8; AUTHENTICATED_LEN],
    peer: PeerId,
) -> Option<(MacInput<'b>, PeerId)> {
    let (principal, key_epoch) = principal_and_key_epoch(header);
    if !ring.admits(peer, principal, key_epoch) {
        return None;
    }
    let input = MacInput {
        endpoint,
        direction: Direction::ClientToOwner,
        header,
        body: [&[], &[]],
    };
    Some((input, peer))
}

/// The unhandled frames of the packed datagram being handled, for the window scan that starts at the first of them.
struct Own<'s, 'l> {
    /// The frames from the one the scan starts at to the datagram's end.
    frames: &'l [[u8; HEADER_LEN]],
    /// The datagram's metadata.
    received: Received,
    /// Where the scan leaves what each of `frames` parsed to, position by position, for that frame's handling.
    scanned: &'s mut [Option<Frame<'l>>],
}

/// The frames of the datagrams in receive slots `next..end`, while each datagram may start or extend a receive
/// window: every frame of a packed datagram, and a lone datagram [`get_candidate`] admits. Each comes with its bytes
/// and its datagram's metadata, and the first other datagram ends the walk, so its frames are a contiguous run across
/// datagram boundaries.
fn window_frames<'l>(
    scratch: &'l [Option<PacketLease<'_>>],
    meta: &'l [Received],
    next: usize,
    end: usize,
) -> impl Iterator<Item = (&'l [u8], Received)> {
    let (mut slot, mut frame) = (next, 0);
    // The frame count of the packed datagram at `slot` once read, zero for a lone datagram.
    let mut frames = None;
    std::iter::from_fn(move || {
        let lease = scratch[..end].get(slot)?;
        let received = meta[slot];
        let packed = *frames.get_or_insert_with(|| {
            packed_gets(lease.as_ref(), received).map_or(0, |(frames, _)| frames)
        });
        let bytes = if packed > 0 {
            let bytes = lease
                .as_ref()?
                .bytes()
                .get(frame * HEADER_LEN..(frame + 1) * HEADER_LEN)?;
            frame += 1;
            bytes
        } else {
            let lease = get_candidate(lease, received)?;
            frame = 1;
            lease.bytes()
        };
        if frame >= packed.max(1) {
            (slot, frame, frames) = (slot + 1, 0, None);
        }
        Some((bytes, received))
    })
}

/// A datagram whose tag can be computed before it parses: an untruncated ACK, PUT BEGIN, PUT PREPARE or PUT CANCEL from a known peer. The canonical frame of each of these kinds has an empty body, so the tag covers the header alone, and a frame of one of them that names a body fails to parse, whatever its tag.
#[inline]
fn bare_candidate<'l, 'm>(
    lease: &'l Option<PacketLease<'m>>,
    meta: Received,
) -> Option<&'l PacketLease<'m>> {
    const BARE: [u8; 4] = [
        Kind::Ack as u8,
        Kind::PutBegin as u8,
        Kind::PutPrepare as u8,
        Kind::PutCancel as u8,
    ];
    let lease = lease.as_ref()?;
    meta.peer?;
    (!meta.truncated
        && lease
            .bytes()
            .get(KIND_AT)
            .is_some_and(|kind| BARE.contains(kind)))
    .then_some(lease)
}

/// The frame `bytes` holds, parsed with the truncation flag of the datagram `meta` describes, and that datagram's peer; or the reason of the first check it failed. `bytes` is a lone datagram's bytes or one frame of a packed datagram. The peer check runs first, so a datagram from no configured peer returns [`DropReason::NoPeer`] ahead of the parse.
#[inline]
fn parse_received<'l>(
    crc: crate::storage::Crc32c,
    bytes: &'l [u8],
    meta: Received,
) -> Result<(Frame<'l>, PeerId), DropReason> {
    let peer = meta.peer.ok_or(DropReason::NoPeer)?;
    let frame = parse(crc, bytes, meta.truncated).map_err(parse_reason)?;
    Ok((frame, peer))
}

#[inline]
fn parsed_put_data<'l>(
    crc: crate::storage::Crc32c,
    lease: &'l PacketLease<'_>,
    meta: Received,
) -> Result<(Frame<'l>, PeerId), DropReason> {
    let (frame, peer) = parse_received(crc, lease.bytes(), meta)?;
    (frame.header().kind == Kind::PutData)
        .then_some((frame, peer))
        .ok_or(DropReason::Kind)
}

/// The drop reason of a frame parse refusal: the truncation flag, which the parse checks first, or any other check.
fn parse_reason(error: super::frame::FrameError) -> DropReason {
    match error {
        super::frame::FrameError::Truncated => DropReason::Truncated,
        _ => DropReason::Malformed,
    }
}

/// A PUT DATA fragment the session table admitted: its session, header and body crc.
type AdmittedData = (Admitted, Header, u32);

/// A handler's or the PUT core's acceptance, or [`DropReason::Declined`].
fn declined(accepted: bool) -> Result<(), DropReason> {
    accepted.then_some(()).ok_or(DropReason::Declined)
}

/// The live request bound to read `op`.
fn request_of(by_op: &[Option<u16>], bound: &[Option<Bound>], op: ReadOp) -> Option<RequestId> {
    let slot = (*by_op.get(op.slot as usize)?)?;
    let read = bound[usize::from(slot)]?;
    (read.op == op).then_some(read.request)
}

/// Events one storage tick may push: a chunk and an outcome per read operation, plus the two spare slots a tick needs before it works.
fn events(shape: &ReadShape) -> usize {
    2 * shape.read_ops as usize + 2
}

fn inputs(shape: &ReadShape) -> GeometryInputs {
    GeometryInputs {
        record_chunk_len: shape.chunk_len,
        response_buffer_len: shape.response_buffer_len,
        device_max_transfer: shape.max_transfer,
        header_max: shape.header_max,
    }
}

/// The wire status of a lookup error.
pub(super) fn lookup_status(error: LookupError) -> Status {
    match error {
        LookupError::Missing => Status::Missing,
        LookupError::Expired => Status::Expired,
        LookupError::Contended => Status::Contended,
        LookupError::LeaseLimit => Status::LeasePressure,
        // The object's rights are full.
        LookupError::RetainLimit => Status::ObjectPressure,
        LookupError::ClockUnavailable => Status::ClockUnavailable,
        LookupError::Closed => Status::Closed,
    }
}

/// The wire status of a read refusal, and whether a correct owner never sees it.
pub(super) fn refusal_status(refusal: ReadRefusal) -> (Status, bool) {
    let status = match refusal {
        ReadRefusal::PoolExhausted => Status::RetransmissionPressure,
        ReadRefusal::OpsExhausted => Status::ReadOpsPressure,
        ReadRefusal::Submit(Refusal::TableFull { .. })
        | ReadRefusal::Submit(Refusal::Device(crate::storage::SubmitRefusal {
            reason: crate::storage::RefusalReason::QueueFull,
            ..
        })) => return (Status::OwnerUnavailable, true),
        ReadRefusal::Submit(_) => Status::DeviceError,
        ReadRefusal::Layout => Status::IntegrityError,
        ReadRefusal::Closed => Status::Closed,
        ReadRefusal::Lost => Status::OwnerUnavailable,
        ReadRefusal::ForeignLease => return (Status::OwnerUnavailable, true),
    };
    (status, false)
}

/// The wire status of a read that ended other than complete, where `verified` says an earlier extent's header verified: a first extent's header naming another key answers the lookup's fingerprint false positive `Missing`, and a later extent's, reached through the object's block, an integrity failure.
pub(super) fn read_status(status: ReadStatus, verified: bool) -> Status {
    match status {
        ReadStatus::DeviceError => Status::DeviceError,
        ReadStatus::Short => Status::Short,
        ReadStatus::HeaderMismatch(HeaderMismatch::Key) if !verified => Status::Missing,
        ReadStatus::HeaderMismatch(_) | ReadStatus::ChunkMismatch { .. } => Status::IntegrityError,
        ReadStatus::Cancelled => Status::Cancelled,
        ReadStatus::TimedOut => Status::TimedOut,
        ReadStatus::Quiesced => Status::Closed,
        ReadStatus::Lost => Status::OwnerUnavailable,
        // A complete read without its header's information names no manifest.
        ReadStatus::Complete => Status::IntegrityError,
    }
}

/// What one frame's send came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sent {
    Taken,
    /// The transport would block; the frame waits for the next poll.
    Blocked,
    /// The frame failed to encode or tag, or the transport failed it; the report counts it in `failed`, the transfer core treats it as sent and lost, and retries recover it.
    Failed,
}

impl Sent {
    fn record(self, report: &mut OwnerReport) {
        match self {
            Self::Taken => report.sent += 1,
            Self::Blocked => {}
            Self::Failed => report.failed += 1,
        }
    }
}

#[cfg(test)]
impl<'s, 'a, 'm, P: Platform, D: Disk, T: Datagrams<'a>> Owner<'s, 'a, 'm, P, D, T> {
    /// Spends `peer`'s send sequence, so the next frame toward it finds the session exhausted.
    pub(super) fn exhaust_sends(&mut self, peer: PeerId) {
        self.sessions.set_send(peer, u64::MAX);
    }

    /// Whether the next turn runs a grant pass over the bound reads.
    pub(super) fn grant_pending(&self) -> bool {
        self.regrant
    }

    /// The reply round's count of waiting bootstrap replies, which equals the entries of `replies` that hold one.
    pub(super) fn waiting_replies(&self) -> u32 {
        assert_eq!(
            self.waiting as usize,
            self.replies.iter().flatten().count(),
            "the waiting count names the queued replies"
        );
        self.waiting
    }
}

/// The owner's send side for one batch of the transfer core's frames.
struct Sender<'o, 's, 'a, P: Platform, D: Disk, T> {
    volume: &'o Volume<'s, 'a, P, D>,
    token: Option<crate::failover::serving::Token>,
    crc: crate::storage::Crc32c,
    ring: &'o KeyRing,
    sessions: &'o mut Sessions,
    endpoint: u32,
    transport: &'o mut T,
    headers: &'o mut [[u8; HEADER_LEN]],
    exhausted: &'o mut Vec<PeerId>,
    report: &'o mut OwnerReport,
}

impl<'a, P: Platform, D: Disk, T: Datagrams<'a>> Sender<'_, '_, 'a, P, D, T> {
    /// Encodes and tags `frames` in rounds of at most [`SEND_ROUND`], hands each round to the transport, and returns how many frames count as sent: those the transport took, and those that failed or had no session; the first frame the transport left ends the batch.
    #[inline(always)]
    fn send(&mut self, frames: &mut dyn Iterator<Item = Out<'_, 'a>>) -> usize {
        let mut consumed = 0;
        loop {
            // When at most `SMALL_ROUND` frames are left, the round fills arrays of that length; the transport calls and the frames each carries match those of `SEND_ROUND` arrays.
            let small = frames.size_hint().1.is_some_and(|left| left <= SMALL_ROUND);
            let (sent, last) = if small {
                self.round::<SMALL_ROUND>(frames)
            } else {
                self.round::<SEND_ROUND>(frames)
            };
            consumed += sent;
            if last {
                return consumed;
            }
        }
    }

    /// Each call pulls at most `N` frames and at most one frame per header, encodes them, tags them two at a time, and sends sealed frames. The return value reports the count treated as sent and whether the frames were exhausted or the transport left a frame unsent.
    #[inline(always)]
    fn round<const N: usize>(
        &mut self,
        frames: &mut dyn Iterator<Item = Out<'_, 'a>>,
    ) -> (usize, bool) {
        let Self {
            crc,
            ring,
            sessions,
            endpoint,
            transport,
            headers,
            exhausted,
            report,
            volume,
            token,
        } = self;
        let (crc, endpoint) = (*crc, *endpoint);
        // Per header of the round, the frame encoded into it.
        let mut staged: [Option<Staged<'_, 'a>>; N] = [None; N];
        let (mut pulled, mut more) = (0, true);
        for (encoded, slot) in headers.iter_mut().zip(staged.iter_mut()) {
            // The frame is read where `next` returned it. Moving it out of the `Option` would copy the whole frame, its header included, to a second slot with loads wider than the stores that just wrote it.
            let next = frames.next();
            let Some(frame) = next.as_ref() else {
                more = false;
                break;
            };
            pulled += 1;
            if token.is_none_or(|token| {
                sessions.tenure(frame.peer) != Some(super::owner_view::tenure_of(token))
            }) {
                continue;
            }
            let Some(header) = under_session(sessions, ring, frame, exhausted) else {
                continue;
            };
            let payload = [frame.payload[0].bytes(), frame.payload[1].bytes()];
            if encode_with_body_crc(crc, &header, payload, frame.body_crc, encoded).is_err() {
                report.failed += 1;
                continue;
            }
            *slot = Some(Staged {
                peer: frame.peer,
                payload: frame.payload,
                position: pulled - 1,
                digest: frame.digest,
            });
        }
        if pulled == 0 {
            return (0, true);
        }
        // Tags go two frames at a time through the group path's two chains; an odd last frame is tagged alone.
        let mut waiting: Option<usize> = None;
        for at in 0..N.min(headers.len()) {
            if staged[at].is_none() {
                continue;
            }
            let Some(first) = waiting.take() else {
                waiting = Some(at);
                continue;
            };
            let (front, back) = headers.split_at_mut(at);
            let (a, b) = (&mut front[first], &mut back[0]);
            // Both entries are read in the round's array, not copied out of it.
            let (Some(sa), Some(sb)) = (staged[first].as_ref(), staged[at].as_ref()) else {
                continue;
            };
            let (mut da, mut db) = ([0; DATA_DIGEST_LEN], [0; DATA_DIGEST_LEN]);
            let outbound = (endpoint, Direction::OwnerToClient);
            let tags = match (
                sa.mac_input(ring, a, outbound, &mut da),
                sb.mac_input(ring, b, outbound, &mut db),
            ) {
                (Some(ia), Some(ib)) => ring.tag_pair([sa.peer, sb.peer], [&ia, &ib]),
                _ => None,
            };
            match tags {
                Some([ta, tb]) => {
                    seal(a, ta);
                    seal(b, tb);
                }
                None => {
                    for (encoded, slot) in [(a, first), (b, at)] {
                        if !seal_tag(ring, endpoint, staged[slot].as_ref(), encoded) {
                            staged[slot] = None;
                            report.failed += 1;
                        }
                    }
                }
            }
        }
        if let Some(at) = waiting
            && !seal_tag(ring, endpoint, staged[at].as_ref(), &mut headers[at])
        {
            staged[at] = None;
            report.failed += 1;
        }
        let mut outgoing = [EMPTY; N];
        // Each outgoing frame's position among the frames pulled this round.
        let mut position = [0; N];
        let mut sendable = 0;
        for (encoded, slot) in headers.iter().zip(staged.iter()) {
            let Some(frame) = slot else {
                continue;
            };
            outgoing[sendable] = Outgoing {
                peer: frame.peer,
                header: encoded,
                payload: frame.payload,
            };
            position[sendable] = frame.position;
            sendable += 1;
        }
        // A call fails only when it took nothing; the owner charges the failure to the leading datagram and sends the rest in a further call, and a closed transport fails them all.
        let mut accepted = 0;
        while accepted < sendable {
            if volume
                .admit_authority(
                    crate::failover::serving::Operation::Reply {
                        lineage: token.map_or(0, |t| t.lineage),
                    },
                    *token,
                )
                .is_err()
            {
                return (pulled, true);
            }
            match transport.send(&outgoing[accepted..sendable]) {
                Ok(taken) => {
                    report.sent += taken as u64;
                    accepted += taken;
                    break;
                }
                Err(DatagramError::Closed) => {
                    report.failed += (sendable - accepted) as u64;
                    accepted = sendable;
                }
                Err(DatagramError::Failed { .. }) => {
                    report.failed += 1;
                    accepted += 1;
                }
            }
        }
        if accepted < sendable {
            return (position[accepted], true);
        }
        (pulled, !more)
    }
}

/// A frame of a send round encoded into its header buffer and awaiting its tag or its send.
#[derive(Clone, Copy)]
struct Staged<'c, 'a> {
    peer: PeerId,
    payload: [Payload<'c, 'a>; 2],
    /// The frame's position among the frames pulled this round.
    position: usize,
    /// The DATA body digest the transfer core cached at the chunk's delivery, when it has one.
    digest: Option<[u8; DATA_DIGEST_LEN]>,
}

impl Staged<'_, '_> {
    /// The payload's bytes, which [`KeyRing::mac_input`] covers, digests or skips by the frame's kind.
    #[inline]
    fn payload(&self) -> [&[u8]; 2] {
        [self.payload[0].bytes(), self.payload[1].bytes()]
    }

    /// The MAC input of the frame encoded in `encoded`: with a cached digest, [`KeyRing::mac_input_digested`] over it, otherwise [`KeyRing::mac_input`], which writes the digest it computes to `scratch`.
    #[inline(always)]
    fn mac_input<'s>(
        &'s self,
        ring: &KeyRing,
        encoded: &'s [u8; HEADER_LEN],
        outbound: (u32, Direction),
        scratch: &'s mut [u8; DATA_DIGEST_LEN],
    ) -> Option<MacInput<'s>> {
        let payload = self.payload();
        match &self.digest {
            Some(digest) => ring.mac_input_digested(
                encoded,
                payload[0].len() + payload[1].len(),
                outbound,
                digest,
            ),
            None => ring.mac_input(self.peer, encoded, payload, outbound, scratch),
        }
    }
}

/// Tags the encoded header of `staged` alone and seals it; false when the frame has no staged entry or no tag.
#[inline]
fn seal_tag(
    ring: &KeyRing,
    endpoint: u32,
    staged: Option<&Staged<'_, '_>>,
    encoded: &mut [u8; HEADER_LEN],
) -> bool {
    let Some(staged) = staged else {
        return false;
    };
    let mut digest = [0; DATA_DIGEST_LEN];
    let Some(tag) = staged
        .mac_input(
            ring,
            encoded,
            (endpoint, Direction::OwnerToClient),
            &mut digest,
        )
        .and_then(|input| ring.tag(staged.peer, &input))
    else {
        return false;
    };
    seal(encoded, tag);
    true
}

/// The frames one transport call carries at most; a poll's budget beyond it takes further calls.
const SEND_ROUND: usize = 64;

/// The round length for a batch of at most this many frames left, whose arrays cost an eighth of a full round's to fill.
const SMALL_ROUND: usize = 8;

/// `EMPTY` fills a round's unused `Outgoing` slots.
const EMPTY: Outgoing<'static, 'static> = Outgoing {
    peer: PeerId(0),
    header: &[],
    payload: [Payload::EMPTY, Payload::EMPTY],
};

/// `frame`'s header under its peer's active session: the principal, key epoch, boot nonces and the next send sequence; `None` when the peer has no principal in the ring, no active session at the frame's epoch, or a spent send sequence, which retires the session and records the peer in `exhausted`; the caller drops such a frame and counts it as sent.
#[inline]
fn under_session(
    sessions: &mut Sessions,
    ring: &KeyRing,
    frame: &Out<'_, '_>,
    exhausted: &mut Vec<PeerId>,
) -> Option<Header> {
    let (owner_nonce, client_nonce) = sessions.nonces(frame.peer)?;
    let principal = ring.principal(frame.peer)?;
    let active = sessions
        .active(frame.peer)
        .filter(|active| active.epoch == frame.epoch)?;
    let sequence = match sessions.next_sequence(active.peer) {
        Ok(sequence) => sequence,
        Err(SessionReject::Exhausted) => {
            exhausted.push(frame.peer);
            return None;
        }
        Err(_) => return None,
    };
    Some(Header {
        principal,
        key_epoch: ring.epoch(),
        owner_nonce,
        client_nonce,
        sequence,
        epoch: frame.epoch,
        datagram_len: (frame.payload[0].len() + frame.payload[1].len()) as u32,
        ..frame.header
    })
}

/// Encodes `header` with `payload` into `encoded` and tags it under `peer`'s key for `endpoint`; false when the frame failed to encode or tag.
fn seal_into(
    crc: crate::storage::Crc32c,
    ring: &KeyRing,
    endpoint: u32,
    peer: PeerId,
    header: &Header,
    payload: [&[u8]; 2],
    encoded: &mut [u8; HEADER_LEN],
) -> bool {
    if encode(crc, header, payload, encoded).is_err() {
        return false;
    }
    let mut digest = [0; DATA_DIGEST_LEN];
    let Some(tag) = ring
        .mac_input(
            peer,
            encoded,
            payload,
            (endpoint, Direction::OwnerToClient),
            &mut digest,
        )
        .and_then(|input| ring.tag(peer, &input))
    else {
        return false;
    };
    seal(encoded, tag);
    true
}

/// Encodes `header` with `payload`, tags it under `peer`'s key for `endpoint`, and sends it alone.
fn transmit<'a, T: Datagrams<'a>>(
    crc: crate::storage::Crc32c,
    ring: &KeyRing,
    transport: &mut T,
    endpoint: u32,
    peer: PeerId,
    header: &Header,
    payload: [&[u8]; 2],
) -> Sent {
    let mut encoded = [0u8; HEADER_LEN];
    if !seal_into(crc, ring, endpoint, peer, header, payload, &mut encoded) {
        return Sent::Failed;
    }
    let datagram = Outgoing {
        peer,
        header: &encoded,
        payload: [Payload::Inline(payload[0]), Payload::Inline(payload[1])],
    };
    match transport.send(&[datagram]) {
        Ok(0) => Sent::Blocked,
        Ok(_) => Sent::Taken,
        Err(_) => Sent::Failed,
    }
}
