//! The owner's GET transfer scheduler over request state held in [`Requests`].
//!
//! The namespace owns admission, wire bindings, retained outcomes and the census.
//! [`ServeCore`] owns GET timers, send queues and per-table-slot scheduling indexes.
//! Callers must use one namespace throughout the core's lifetime.
//!
//! Invariants owned by this module:
//!
//! - A request's manifest comes from its read's verified information; DATA fragment `i` carries payload bytes `[i * 8192, min((i + 1) * 8192, total))` from at most two retained chunks, and COMPLETE is sent only after the read completed and the cumulative receipt base reached the fragment count.
//! - A DATA fragment's body crc is the crc32c of exactly the payload bytes it carries, derived at staging from the verified checksums of the record windows its chunks span and the bytes of the partial windows at its ends ([`Chunk::crc`]); the chunk's checksums stay in the core's table for the chunk's row while the chunk is retained.
//! - A chunk stays retained until the receipt base passes its last fragment, or its request ends, and every device reference to its buffer returned; [`ServeCore::reap`] drops such chunks, visiting only requests whose holding bit is set, with no further ACK. A request holds at most [`BUFFERS_PER_READ`] distinct backing buffers, plus one for each read command beyond the first the core lets a request hold outstanding or granted, across retained chunks, chunks a device still reads, and its outstanding or granted read commands; the next command is granted only within that bound and only when the client's cumulative grant admits the first fragment of the read's oldest outstanding command, or of the new command when none is outstanding, so a read runs at most `commands - 1` commands past the client's grant.
//! - A fragment's first send needs the client's cumulative grant to exceed its index; a retransmission needs no grant. Every datagram takes one pacing token from its peer and its wire bytes from the core's egress [`Shaper`] at staging, whose rate the caller's [`control`](ServeCore::control) steps settle just below the share of the host's bandwidth allowance whose bursts the allowance queues; a frame stages only when both admit it. The request the shaper refused keeps its turn, and the next data round visits it once the bucket holds its frame's bytes. A data round that stages nothing because the shaper refused it after its poll's replies runs before the replies of every following poll until a data round stages a frame or ends with no request waiting, and over those polls replies spend only the bytes above the refused frame's need, so the frame's credit accumulates however small the refill between polls and however many replies arrive; then the next poll's replies spend first again.
//! - Each poll stages one batch, and the caller reports its sent prefix. A data round visits the ready requests in table-slot order from its cursor and sends up to [`DATA_BURST`] frames of each visited request before it moves on. Visits throttled by the shaper or partly covered by the sent prefix keep their sent-frame count across polls, so the per-visit limit holds across polls. A visit the pacer stops before it stages a frame leaves the cursor where the visit found it. Unsent frames regain their pre-staging state, pacing tokens and shaper bytes. Reply and data rounds resume at their earliest unsent frames, and a round the shaper throttles resumes at the throttled source. A COMPLETE in the sent prefix ends its request.
//! - An ACK that names another manifest, lowers the base or the grant, acknowledges an unsent fragment, or grants more than the window above its base changes nothing.
//! - An ACK's receipt mask names the fragments the client holds above its base; the fragments below the highest held one that the mask leaves out are holes, and the core queues them for resending ahead of new fragments, at most once per [`HOLE_GUARD_US`] per request, so one lost fragment costs about a round trip instead of a retry interval; a hole round never names an unsent fragment, and a mask that does is stale. Retries restart from the receipt base after a wait without progress that starts at `retry_us` and doubles with each retry since the request's last progress, up to [`RETRY_DOUBLINGS`](super::RETRY_DOUBLINGS) times, at most `attempts` times, and clear the queued holes; the deadline and attempt exhaustion end the request with one ERROR. A duplicate GET with the same fingerprint and session tightens the deadline and requeues the unacknowledged work of the live request and its one read, or replays the cached terminal; a duplicate from the same session with another fingerprint is refused `ConflictingRequest`, and one from another session is refused `SessionMismatch` while the request is live and dropped with no reply once it ended.
//! - A logical end stops every send except a queued ERROR at once and drops every retained chunk no device reads. The request keeps its table slot and peer share, draining, until three conditions hold together: its ERROR, if any, was sent or cleared by a matching CANCEL or the session's retirement; every device reference to its chunks returned; and the caller's drain predicate proves its read drained.
//! - GET, ACK and CANCEL name a peer's wire ID, which the namespace resolves. [`GetOutcome::Read`] returns the namespace's table handle for subsequent read events and drain checks.
//! - A cached terminal answers duplicates with a matching session and fingerprint while `now_us < max(deadline_us, end_us) + linger_us`, with the expiry addition saturating. Fresh admission clears the row and advances the watermark; session retirement clears both.
//! - Bounded idle work: every request with a frame to send has its ready bit set; each unended request's due time is at most its deadline and, while it waits on receipt, its retry time, an ended request's due time is `u64::MAX`, and `tick_due_us` is at most every due time; a slot's ended bit is set exactly while it holds an ended request; a reply round runs only while a ring entry is queued, and a peer's busy bit is set exactly while its ring queues an entry, so a round jumps from an empty ring to the next peer whose ring queues one. A poll with no ready bit set reads only the ready count, a poll whose ready requests have nothing to send clears each of their bits once, and a data round visits a request whose peer is out of pacing tokens at most once per poll; a tick before its bound returns at once, and otherwise visits only requests whose due time has passed, which includes every request whose deadline or retry is due; a drain release visits only ended requests whose holding bit is clear, since an ended request keeps a chunk exactly while its holding bit is set; a reap visits only requests whose holding bit is set, which every request keeping a passed or ended chunk a device reads has, and a reap with no holding bit set reads only the holder count.

use std::ops::Range;

use crate::storage::page_coverage::Entry as CoverageEntry;
use crate::storage::{
    Crc32c, EngineBudget, EngineBudgetExceeded, MAX_READ_AHEAD, SourceRange, ValidatedChunk,
    VerifiedReadInfo, ZeroRuns,
};

use super::datagram::{FRAME_OVERHEAD, HEADER_LEN, MAX_PAYLOAD_SLICES, Payload, PeerId};
use super::frame::{DATA_DIGEST_LEN, Header, Kind, Status, retry_wait};
use super::geometry::{BUFFERS_PER_READ, FRAGMENT_LEN, FragmentGeometry};
use super::namespace::{Cached, Operation, Refusal, Route};
use super::pace::{Pacer, Shaper};
use super::put::next_set;
use super::requests::{RequestId, RequestPressure};
use super::served::{Outcome, Request, Requests};
use super::session::Admitted;

/// Retained chunks one request may hold: the [`BUFFERS_PER_READ`] backing buffers one fragment may span, and one more for each of up to [`MAX_READ_AHEAD`] commands ahead.
const HELD_CHUNKS: usize = BUFFERS_PER_READ as usize + MAX_READ_AHEAD as usize;

/// Microseconds between two hole rounds of one request: a receipt mask that still shows the holes within this interval of the last round changes nothing, so a burst of gap ACKs resends each hole once, while a lost resend is repeated on the next mask after it.
pub const HOLE_GUARD_US: u64 = 500;

/// The maximum number of frames a data-round visit sends for its request before the round advances to the next ready request.
pub const DATA_BURST: usize = 8;

const _: () = assert!(DATA_BURST <= u8::MAX as usize);

/// Timing and limits of the owner's transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeConfig {
    /// Microseconds without receipt progress before a retry from the base; each retry since the last progress doubles the wait, up to [`RETRY_DOUBLINGS`](super::RETRY_DOUBLINGS) times.
    pub retry_us: u64,
    /// Retries before a stalled request ends.
    pub attempts: u32,
    /// Microseconds a cached terminal outlives the later of its request's deadline and its end.
    pub linger_us: u64,
    /// Datagrams per second per peer.
    pub rate_per_sec: u64,
    /// Datagrams a peer may send at once.
    pub burst: u64,
    /// Client request slots tracked per peer: the negotiated slot cap.
    pub slots: u32,
    /// Capacity of each peer's reply ring, which queues refusals, cached-terminal replays, PUT replies and the
    /// INVALIDATED acknowledgments the owner queues between polls, which occupy the ring when a receive step starts.
    /// A full ring drops the reply and counts it. One receive step of the owner, the part of a poll that handles one receive
    /// call's datagrams, handles up to `OwnerConfig::batch * MAX_PACKED_GETS` GET frames. A peer's ring drops none of
    /// that step's replies when the step starts with the ring empty and `replies` is at least the replies that peer's
    /// frames in the step can draw: refusals, replays and PUT replies. Start does not check this.
    pub replies: u32,
    /// The longest a request may run, in microseconds, whatever duration its GET names.
    pub max_wait_us: u64,
}

/// An object's verified manifest: its allocation and both lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Manifest {
    pub allocation: u64,
    pub metadata_len: u32,
    pub body_len: u32,
}

impl Manifest {
    pub fn total(&self) -> u64 {
        u64::from(self.metadata_len) + u64::from(self.body_len)
    }

    pub fn count(&self) -> u32 {
        FragmentGeometry::fragments(self.total()) as u32
    }
}

/// How a request's read ended, as its caller maps it to the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadEnd {
    /// Every chunk verified, under the header this manifest describes.
    Complete(Manifest),
    Failed(Status),
}

impl From<&VerifiedReadInfo> for Manifest {
    fn from(info: &VerifiedReadInfo) -> Self {
        Self {
            allocation: info.identity().allocation,
            metadata_len: info.metadata_len(),
            body_len: info.body_len(),
        }
    }
}

/// What a GET did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetOutcome {
    /// A new request's namespace table handle and effective deadline.
    /// The caller starts one read and reports its admission or refusal under this handle.
    Read { id: RequestId, deadline_us: u64 },
    /// A duplicate of a live request: its deadline tightened and its unacknowledged work was requeued.
    Duplicate,
    /// A duplicate of an ended request: its cached terminal was queued again.
    Replayed,
    /// Dropped without a reply: an older generation, or a duplicate of an ended request with no terminal to replay for its session.
    Dropped,
    /// Refused with a queued ERROR of this status.
    Refused(Status),
}

/// The fields a GET binds, which a duplicate must repeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    key: [u8; 32],
    metadata_cap: u32,
    body_cap: u32,
    grant: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Terminal {
    Complete(Manifest),
    Error(Status),
    Put(PutReply),
    /// INVALIDATED for the inclusive interval `(low, high)`.
    Invalidated(u64, u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PutReply {
    pub(super) kind: Kind,
    pub(super) manifest: Manifest,
    pub(super) grant: u32,
    pub(super) status: u16,
    pub(super) index: u32,
    pub(super) offset: u64,
}

/// A GET's retained outcome: the fingerprint a duplicate must repeat and the terminal it replays.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct GetRow {
    fingerprint: Fingerprint,
    terminal: Terminal,
}

/// A frame the core sends: the request fields of its header, the session epoch it is bound to, and its payload pieces, borrowed from retained chunks until the send returns.
/// A piece from a chunk that can be a transmit source carries its source range as well as its bytes.
/// The caller fills the principal, key epoch, boot nonces, sequence and the header epoch from `epoch`, then tags it.
#[derive(Debug, Clone, Copy)]
pub struct Out<'c, 'a> {
    pub peer: PeerId,
    pub epoch: u64,
    pub header: Header,
    pub payload: [Payload<'c, 'a>; MAX_PAYLOAD_SLICES],
    /// The crc32c of the payload pieces together, computed at staging from the retained chunks.
    pub body_crc: u32,
    /// The body digest of a DATA fragment under its request's session, computed when its chunk was delivered; `None` leaves the digest to the sender.
    pub digest: Option<[u8; DATA_DIGEST_LEN]>,
}

/// A caller's body digest over one fragment's bytes under the request's session; `None` when the caller cannot digest under that session.
pub type FragmentDigest<'d> = dyn FnMut(&[u8]) -> Option<[u8; DATA_DIGEST_LEN]> + 'd;

/// A verified read delivery binds a chunk's payload range to its window checksums.
pub struct ChunkInput<'w, C> {
    pub range: Range<u64>,
    pub chunk: C,
    pub window_crcs: &'w [u32],
}

/// A retained chunk's bytes, whether a device still reads them, and the checksum of any range of them.
pub trait Chunk: AsRef<[u8]> {
    /// Whether a device holds a reference to the chunk's buffer, which then stays retained.
    fn device_held(&self) -> bool;

    /// The crc32c of `range` of [`as_ref`](AsRef::as_ref)'s bytes under `crc`, given `window_crcs`, the verified checksums the chunk arrived with, and `runs`, the caller's store of zero runs, which a chunk deriving the checksum from those checksums reads and fills.
    fn crc(
        &self,
        crc: Crc32c,
        runs: &mut ZeroRuns,
        window_crcs: &[u32],
        range: Range<usize>,
    ) -> u32;
}

/// A chunk in arena `'a`, which can give a transmit source over a range of its bytes.
pub trait Retained<'a>: Chunk {
    /// The source over `range` of [`as_ref`](AsRef::as_ref)'s bytes, or `None` for a chunk a device cannot read in place.
    fn source(&self, range: Range<usize>) -> Option<SourceRange<'_, 'a>>;
}

impl Chunk for ValidatedChunk<'_> {
    fn device_held(&self) -> bool {
        ValidatedChunk::device_held(self)
    }

    fn crc(
        &self,
        crc: Crc32c,
        runs: &mut ZeroRuns,
        window_crcs: &[u32],
        range: Range<usize>,
    ) -> u32 {
        ValidatedChunk::crc(self, crc, runs, window_crcs, range)
    }
}

impl<'a> Retained<'a> for ValidatedChunk<'a> {
    fn source(&self, range: Range<usize>) -> Option<SourceRange<'_, 'a>> {
        ValidatedChunk::source(self, range)
    }
}

/// Test chunks live on the heap, so no device holds a reference to them, and their checksums fold over their bytes.
#[cfg(test)]
impl Chunk for Box<[u8]> {
    fn device_held(&self) -> bool {
        false
    }

    fn crc(
        &self,
        crc: Crc32c,
        _runs: &mut ZeroRuns,
        _window_crcs: &[u32],
        range: Range<usize>,
    ) -> u32 {
        crc.checksum(&self[range])
    }
}

/// Test chunks live on the heap, so a device cannot read them in place.
#[cfg(test)]
impl Retained<'_> for Box<[u8]> {
    fn source(&self, _range: Range<usize>) -> Option<SourceRange<'_, 'static>> {
        None
    }
}

/// A GET as the core weighs it.
#[derive(Debug, Clone, Copy)]
struct Ask {
    session: Admitted,
    request: u64,
    fingerprint: Fingerprint,
    deadline_us: u64,
}

#[derive(Debug, Clone, Copy)]
struct Reply {
    table: Option<RequestId>,
    peer: PeerId,
    epoch: u64,
    request: u64,
    key: [u8; 32],
    terminal: Terminal,
    /// A published fill's first PUT RESULT, which [`ServeCore::put_results_queued`] counts while a ring holds it.
    first: bool,
}

/// `Asker` identifies the wire INVALIDATE that an INVALIDATED response answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Asker {
    pub(super) peer: PeerId,
    pub(super) epoch: u64,
    pub(super) request: u64,
    /// The session sequence of the INVALIDATE frame, which orders same-session resends of one entry by send order.
    pub(super) sequence: u64,
}

/// One request being served.
#[cfg_attr(test, derive(Clone, Debug))]
pub struct Serve<C> {
    peer: PeerId,
    epoch: u64,
    request: u64,
    fingerprint: Fingerprint,
    deadline_us: u64,
    manifest: Option<Manifest>,
    /// Retained chunks in payload order, the earlier first, filled from the first slot and compacted toward it, so a later slot holds a chunk only while every earlier slot does; a chunk the receipt passed, or of an ended request, stays while a device still reads it.
    chunks: [Option<Held<C>>; HELD_CHUNKS],
    /// `held` caches the retained chunk count for scalar-only grant checks.
    held: u8,
    runs: ZeroRuns,
    /// Read commands outstanding or granted: the first one from the read's start, and each one granted since whose chunk has not arrived.
    commanded: u8,
    /// The payload bytes the read has delivered so far.
    read_to: u64,
    /// The read completed; its manifest is `manifest`.
    read_complete: bool,
    base: u32,
    granted: u32,
    /// The lowest fragment not yet sent.
    next: u32,
    /// The next fragment of a retransmission round; at `next` when none is under way.
    resend: u32,
    /// Fragments the client's receipt mask showed missing below one it holds, bit `i` for fragment `base + i`; each is resent ahead of new fragments and its bit cleared at staging.
    holes: u64,
    /// When the last hole round was queued.
    holes_at_us: u64,
    start_acked: bool,
    start_due: bool,
    complete_due: bool,
    error_due: Option<Status>,
    progress_us: u64,
    attempts: u32,
    ended: bool,
    /// The request is outside any wait on receipt and its due time bounds only its deadline, so the next wait it starts arms its retry.
    disarmed: bool,
}

/// A retained chunk: the payload bytes it holds, and the row of the core's window checksum table that holds its windows' verified checksums, which stays with the chunk as the slots compact.
#[cfg_attr(test, derive(Clone, Debug))]
struct Held<C> {
    range: Range<u64>,
    chunk: C,
    row: u8,
}

/// One chunk's fate under a reap.
#[derive(Clone, Copy)]
struct Retain {
    /// The chunk stays in the request's `chunks`.
    keep: bool,
    /// The chunk stays only because a device reads it, which sets the request's holding bit.
    holding: bool,
}

impl<C: Chunk> Serve<C> {
    /// Drops every chunk the receipt passed, or every chunk once the request ended, whose last device reference returned, keeping the rest in payload order; returns whether such a chunk stays because a device reads it, which the caller stores as the request's holding bit.
    #[inline(always)]
    fn reap(&mut self) -> bool {
        let horizon = self.horizon();
        let (mut kept, mut holding) = (0, false);
        // A kept chunk swaps down past the dropped ones before it, which keeps payload order; with none dropped, every chunk stays in place.
        for at in 0..HELD_CHUNKS {
            let retain = Self::retain(&self.chunks[at], horizon);
            holding |= retain.holding;
            if retain.keep {
                if kept != at {
                    self.chunks.swap(kept, at);
                }
                kept += 1;
            } else if self.chunks[at].is_some() {
                self.chunks[at] = None;
            }
        }
        self.held = kept as u8;
        holding
    }

    /// Whether the chunk `held` stays retained under `horizon`, and whether it stays only because a device reads it.
    #[inline(always)]
    fn retain(held: &Option<Held<C>>, horizon: u64) -> Retain {
        let Some(Held { range, chunk, .. }) = held else {
            return Retain {
                keep: false,
                holding: false,
            };
        };
        if range.end > horizon {
            return Retain {
                keep: true,
                holding: false,
            };
        }
        let device = chunk.device_held();
        Retain {
            keep: device,
            holding: device,
        }
    }

    /// The payload offset below which chunks left retention: the receipt base's bytes, or every offset once the base covers the whole payload, the request ended, or while no manifest is bound.
    fn horizon(&self) -> u64 {
        let released = u64::from(self.base) * u64::from(FRAGMENT_LEN);
        let total = self.manifest.map_or(0, |manifest| manifest.total());
        if self.ended || released >= total {
            u64::MAX
        } else {
            released
        }
    }
}

impl<C> Serve<C> {
    /// The request's deadline, which a duplicate only tightens.
    pub(super) fn deadline_us(&self) -> u64 {
        self.deadline_us
    }

    /// The slots holding chunks: the first `held`, since the slots compact toward the first.
    #[inline(always)]
    fn held_chunks(&self) -> &[Option<Held<C>>] {
        &self.chunks[..usize::from(self.held).min(HELD_CHUNKS)]
    }

    /// When a request waiting on receipt, for START or for a sent fragment, retries without progress; `None` while it waits on nothing.
    fn retry_at(&self, retry_us: u64) -> Option<u64> {
        let count = self.manifest.map_or(0, |manifest| manifest.count());
        let waiting =
            self.manifest.is_some() && (!self.start_acked || self.base < self.next.min(count));
        waiting.then(|| self.retry_from_progress(retry_us))
    }

    /// The request's next retry time from its last progress: `retry_us` doubled once for each retry since then, up to [`RETRY_DOUBLINGS`](super::RETRY_DOUBLINGS) times.
    fn retry_from_progress(&self, retry_us: u64) -> u64 {
        self.progress_us
            .saturating_add(retry_wait(retry_us, self.attempts))
    }
}

/// Counters over the core's life.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServeReport {
    pub requests: u64,
    pub duplicates: u64,
    pub replays: u64,
    pub retries: u64,
    pub completed: u64,
    /// ERROR frames of admitted requests the send call reported consumed. Reply-ring ERRORs count in
    /// [`errors_by_status`](Self::errors_by_status) alone.
    pub errors: u64,
    /// ACKs rejected as stale.
    pub stale_acks: u64,
    /// Fragments resent from hole rounds.
    pub hole_resends: u64,
    /// The egress shaper's rate at the report, in bytes per second.
    pub shaped_bytes_per_s: u64,
    /// Replies dropped because the reply queue was full.
    pub dropped_replies: u64,
    /// The most replies one peer's ring held at once over the core's life, out of `reply_capacity`.
    pub reply_high_water: u32,
    /// Each peer's reply ring's width.
    pub reply_capacity: u32,
    /// ERROR frames the send call reported consumed, including ones it dropped after a failed send, indexed by
    /// status code minus one. Both an admitted request's ERROR and a reply-ring `Terminal::Error` count.
    pub errors_by_status: [u64; STATUSES],
    /// GET refusals at [`ServeCore::get`] by status; `refused_by_status` uses the status code minus one as its index.
    pub refused_by_status: [u64; STATUSES],
    /// `refused_pressure` splits the `RequestPressure` entry of `refused_by_status` by cause.
    pub refused_pressure: PressureRefusals,
}

/// GET refusals for request pressure: `busy` counts [`NamespaceRefusal::Busy`](super::NamespaceRefusal::Busy), and `peer` and `table` count [`RequestPressure::Peer`] and [`RequestPressure::Table`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PressureRefusals {
    pub busy: u64,
    pub peer: u64,
    pub table: u64,
}

/// The status codes an ERROR frame carries: 1 through [`Status::ConflictingData`], the highest.
pub const STATUSES: usize = Status::ConflictingData as usize;

impl ServeReport {
    /// ERROR frames of `status` the send call reported consumed.
    pub fn errors_of(&self, status: Status) -> u64 {
        self.errors_by_status[status as usize - 1]
    }

    /// The result counts GET refusals with `status`.
    pub fn refused_of(&self, status: Status) -> u64 {
        self.refused_by_status[status as usize - 1]
    }
}

/// A frame the current poll staged. Settling restores the state changed by staging for frames left unsent. The hand-over builds each frame's header from `source`.
#[derive(Debug, Clone, Copy)]
struct Staged {
    peer: PeerId,
    epoch: u64,
    source: Source,
    /// The datagram's bytes on the wire, which the shaper charged at staging and returns if the datagram goes unsent.
    bytes: u64,
    /// The visit's frames ahead of this one: those the visit sent in earlier polls plus those staged before it in this poll. Replies use zero.
    burst: u8,
}

/// Where a staged frame came from and what its staging changed: a reply left its peer's ring, a START, COMPLETE or ERROR cleared its request's due flag, and a DATA fragment advanced its request's send position.
#[derive(Debug, Clone, Copy)]
enum Source {
    /// The ring entry at this index of `replies`, which the ring passed and which holds the reply until the frame settles.
    Reply(u32),
    Start(RequestId),
    Complete(RequestId),
    Error(RequestId, Status),
    Data {
        id: RequestId,
        index: u32,
        offset: u64,
        len: u32,
        /// The request's `next` and `resend` before staging.
        prior_next: u32,
        prior_resend: u32,
        /// The fragment came from a hole round, which cleared its hole bit and left `next` and `resend` as they were.
        hole: bool,
        /// The crc32c of the fragment's payload, from the retained chunks.
        body_crc: u32,
        /// The fragment's body digest from its chunk's delivery, when the fragment lies within one chunk whose digests were cached.
        digest: Option<[u8; DATA_DIGEST_LEN]>,
    },
}

/// GET scheduling and egress state indexed by the caller's namespace table slots.
/// Each admitted GET's chunks and transfer progress live in [`Serve`] records
/// within that namespace.
pub struct ServeCore {
    config: ServeConfig,
    ended_since_scan: bool,
    pacers: Box<[Pacer]>,
    /// The core's request-frame egress, shaped to the learned allowance share.
    shaper: Shaper,
    /// The byte cost of the cursor request's frame the shaper refused last. A bucket below it ends the data round at once, and the refused request keeps its turn. Zero admits a visit. `mark`, `unmark` and ending a request clear it, because the request's next frame may change.
    egress_need: u64,
    /// Whether the next poll stages replies before requests; see [`poll`](Self::poll). While requests stage first, replies leave `egress_need` bytes in the bucket for the waiting request.
    replies_first: bool,
    /// Each peer's reply ring, `replies` entries at `peer * replies`.
    replies: Box<[Option<Reply>]>,
    /// Each peer's oldest queued reply and queued count.
    reply_heads: Box<[(u32, u32)]>,
    /// Ring entries queued over every peer, emptied ones included until their ring passes them; a reply round runs only while this is positive.
    queued: u32,
    /// Ring entries that hold a published fill's first PUT RESULT, from its queueing until a send takes it or the ring drops it.
    put_results: u32,
    /// One bit per peer, set exactly while the peer's ring queues an entry, so a reply round visits only those peers.
    reply_busy: Box<[u64]>,
    /// The first peer the next reply round visits.
    reply_cursor: u16,
    /// The first request slot the next data round visits.
    cursor: u32,
    /// The slot whose visit the next data round continues, and the frames that visit already sent.
    open_burst: Option<(u32, u8)>,
    /// At most every unended request's due time, so a tick before it returns at once.
    tick_due_us: u64,
    /// One bit per table slot, set for every request that may have a frame to send; a data round visits only set slots and clears a bit whose request has none.
    ready: Box<[u64]>,
    /// Set bits in `ready`.
    ready_count: u32,
    /// Ready bits a data round set aside for requests whose peer was out of pacing tokens; empty between polls.
    deferred: Box<[u64]>,
    /// Each table slot's due time: for an unended request, at most its deadline and, unless it is disarmed, its retry from its last progress; `u64::MAX` for a free slot or an ended request.
    due: Box<[u64]>,
    /// One bit per table slot, set exactly while the slot holds an ended request.
    ended: Box<[u64]>,
    /// One bit per table slot, set while its request keeps a chunk the receipt passed, or a chunk of an ended request, because a device still reads it.
    holding: Box<[u64]>,
    /// Set bits in `holding`, which bound a reap's scan: a reap stops after visiting this many, and returns at once at zero.
    holders: u32,
    /// The current poll's batch; its capacity, the batch size, caps a poll's budget.
    staged: Vec<Staged>,
    report: ServeReport,
    /// Read commands one request may have outstanding or granted: 1, or 1 plus the commands [`read_ahead`](Self::read_ahead) set.
    commands: u8,
    /// The checksum mechanism DATA fragments' body crcs come from.
    crc: Crc32c,
    /// The verified window checksums of every retained chunk: [`HELD_CHUNKS`] rows of `windows` entries per table slot, a row for each chunk the slot's request holds.
    window_crcs: Box<[u32]>,
    /// Entries of one row: the most windows one chunk spans.
    windows: usize,
    /// The body digests of the fragments each retained chunk holds whole within its row's span, in the chunk's row of `fragments` entries: entry `i` is fragment `first + i`, where `first` is the fragment holding the chunk's first payload byte.
    digests: Box<[[u8; DATA_DIGEST_LEN]]>,
    /// One word per row: bit `i` is set while entry `i` of the row holds the digest of the retained chunk's fragment.
    digest_valid: Box<[u64]>,
    /// `fragments` is the digest-row width computed by [`digest_row`](Self::digest_row) from `windows`. The row covers the fragment indices a chunk can touch when each window is at most one fragment long, starting with the fragment containing the chunk's first payload byte. `fragments` is zero when a row would require more than 64 validity bits, disabling digest caching.
    fragments: usize,
}

impl ServeCore {
    /// Bytes a core over `peers` peers, a namespace table of `request_slots` slots, `batch` staged frames and chunks of at most `windows` windows charges beyond that namespace.
    pub fn charge(
        config: &ServeConfig,
        peers: u16,
        request_slots: u32,
        batch: u32,
        windows: u32,
    ) -> Option<usize> {
        let rows = (request_slots as usize).checked_mul(HELD_CHUNKS)?;
        rows.checked_mul(windows as usize)?
            .checked_mul(size_of::<u32>())?
            .checked_add(
                rows.checked_mul(Self::digest_row(windows))?
                    .checked_mul(DATA_DIGEST_LEN)?,
            )?
            .checked_add(rows.checked_mul(size_of::<u64>())?)?
            .checked_add(usize::from(peers) * size_of::<Pacer>())?
            .checked_add(
                (config.replies as usize)
                    .checked_mul(usize::from(peers))?
                    .checked_mul(size_of::<Option<Reply>>())?,
            )?
            .checked_add(usize::from(peers) * size_of::<(u32, u32)>())?
            .checked_add(Self::ready_words(u32::from(peers)) * size_of::<u64>())?
            .checked_add(4 * Self::ready_words(request_slots) * size_of::<u64>())?
            .checked_add((request_slots as usize) * size_of::<u64>())?
            .checked_add((batch as usize).checked_mul(size_of::<Staged>())?)
    }

    /// Entries of one digest row for chunks of `windows` windows: one per window and one more, or zero when a word of valid bits cannot cover them.
    fn digest_row(windows: u32) -> usize {
        let fragments = windows as usize + 1;
        if fragments <= u64::BITS as usize {
            fragments
        } else {
            0
        }
    }

    /// Words of a one-bit-per-slot set over `request_slots` table slots.
    fn ready_words(request_slots: u32) -> usize {
        (request_slots as usize).div_ceil(u64::BITS as usize)
    }

    /// Callers must use one namespace throughout the core's lifetime.
    /// A poll stages at most `batch` frames. Each delivered chunk supplies at most
    /// `windows` verified checksums for DATA body CRCs.
    /// Construction charges [`charge`](Self::charge) bytes beyond the namespace.
    ///
    /// # Errors
    ///
    /// Returns `EngineBudgetExceeded` if the charge exceeds the remaining budget;
    /// `budget` stays unchanged.
    pub fn new<C, F>(
        config: ServeConfig,
        requests: &Requests<C, F>,
        batch: u32,
        now_us: u64,
        windows: u32,
        budget: &mut EngineBudget,
    ) -> Result<Self, EngineBudgetExceeded> {
        let (request_slots, peers) = (requests.table().slots(), requests.table().peers());
        let bytes =
            Self::charge(&config, peers, request_slots, batch, windows).unwrap_or(usize::MAX);
        budget.charge(bytes)?;
        let words = Self::ready_words(request_slots);
        let due = vec![u64::MAX; request_slots as usize].into_boxed_slice();
        let rows = request_slots as usize * HELD_CHUNKS;
        let window_crcs = vec![0; rows * windows as usize].into_boxed_slice();
        let fragments = Self::digest_row(windows);
        Ok(Self {
            config,
            ended_since_scan: false,
            pacers: vec![Pacer::new(config.rate_per_sec, config.burst, now_us); usize::from(peers)]
                .into_boxed_slice(),
            shaper: Shaper::new(now_us),
            egress_need: 0,
            replies_first: true,
            replies: vec![None; config.replies as usize * usize::from(peers)].into_boxed_slice(),
            reply_heads: vec![(0, 0); usize::from(peers)].into_boxed_slice(),
            queued: 0,
            put_results: 0,
            reply_busy: vec![0; Self::ready_words(u32::from(peers))].into_boxed_slice(),
            reply_cursor: 0,
            cursor: 0,
            open_burst: None,
            tick_due_us: u64::MAX,
            ready: vec![0; words].into_boxed_slice(),
            ready_count: 0,
            deferred: vec![0; words].into_boxed_slice(),
            due,
            ended: vec![0; words].into_boxed_slice(),
            holding: vec![0; words].into_boxed_slice(),
            holders: 0,
            staged: Vec::with_capacity(batch as usize),
            report: ServeReport::default(),
            commands: 1,
            crc: Crc32c::detect(),
            window_crcs,
            windows: windows as usize,
            digests: vec![[0; DATA_DIGEST_LEN]; rows * fragments].into_boxed_slice(),
            digest_valid: vec![0; rows].into_boxed_slice(),
            fragments,
        })
    }

    pub fn report(&self) -> ServeReport {
        ServeReport {
            shaped_bytes_per_s: self.shaper.rate(),
            reply_capacity: self.config.replies,
            ..self.report
        }
    }

    /// When the egress shaper's next control step is due.
    pub fn control_due_us(&self) -> u64 {
        self.shaper.control_due_us()
    }

    /// `exceeded` is the transport's cumulative count of datagrams the host's bandwidth allowance queued or dropped; `None` means the count is unavailable.
    pub fn control(&mut self, now_us: u64, exceeded: Option<u64>) {
        self.shaper.control(now_us, exceeded);
    }

    pub(super) fn take_ends(&mut self) -> bool {
        std::mem::take(&mut self.ended_since_scan)
    }

    /// One bit per table slot, set exactly while the slot holds an ended request.
    pub(super) fn ended_slots(&self) -> &[u64] {
        &self.ended
    }

    /// Peer `peer`'s entries of a per-peer array of `width` entries each, or `None` for a peer outside the core.
    fn of_peer<T>(entries: &mut [T], peer: PeerId, width: u32) -> Option<&mut [T]> {
        let width = width as usize;
        entries.get_mut(usize::from(peer.0) * width..(usize::from(peer.0) + 1) * width)
    }

    /// Marks request `id` as possibly having a frame to send.
    #[inline]
    fn mark(&mut self, id: RequestId) {
        let slot = usize::from(id.slot());
        let (word, bit) = (&mut self.ready[slot / 64], 1 << (slot % 64));
        self.ready_count += u32::from(*word & bit == 0);
        *word |= bit;
        self.egress_need = 0;
    }

    #[inline]
    fn unmark(&mut self, slot: u32) {
        let slot = slot as usize;
        let (word, bit) = (&mut self.ready[slot / 64], 1 << (slot % 64));
        self.ready_count -= u32::from(*word & bit != 0);
        *word &= !bit;
        self.egress_need = 0;
    }

    /// The first set ready bit at or after `from`, wrapping once to the slots before it.
    #[inline]
    fn next_ready(&self, from: u32) -> Option<u32> {
        next_set_wrapping(&self.ready, from)
    }

    /// Queues `reply` on its peer's ring and returns whether the ring took it; a full ring, or a peer outside the core, drops it and counts the drop.
    #[inline(always)]
    fn queue_reply(&mut self, reply: Reply) -> bool {
        let width = self.config.replies;
        let Some((head, len)) = self.reply_heads.get_mut(usize::from(reply.peer.0)) else {
            self.report.dropped_replies += 1;
            return false;
        };
        if *len == width {
            self.report.dropped_replies += 1;
            return false;
        }
        let mut tail = *head + *len;
        if tail >= width {
            tail -= width;
        }
        let at = usize::from(reply.peer.0) * width as usize + tail as usize;
        self.replies[at] = Some(reply);
        *len += 1;
        self.report.reply_high_water = self.report.reply_high_water.max(*len);
        self.queued += 1;
        self.set_busy(reply.peer.0);
        true
    }

    /// Whether a reply ring holds a published fill's first PUT RESULT: the fill published and no send has taken its
    /// acknowledgment. A replay of a retained terminal stays out of the count. Reads one counter.
    pub(super) fn put_results_queued(&self) -> bool {
        #[cfg(test)]
        if super::owner_drain_tests::planted(super::owner_drain_tests::Plant::ReplaysCounted) {
            return (self.replies.iter().flatten()).any(
                |reply| matches!(reply.terminal, Terminal::Put(put) if put.kind == Kind::PutResult),
            );
        }
        self.put_results > 0
    }

    #[inline]
    fn set_busy(&mut self, peer: u16) {
        self.reply_busy[usize::from(peer) / 64] |= 1 << (peer % 64);
    }

    /// The first peer at or after `from` whose ring queues an entry, wrapping once to the peers before it; `from` itself when no ring queues one.
    #[inline]
    fn next_busy(&self, from: u16) -> u16 {
        next_set_wrapping(&self.reply_busy, u32::from(from)).map_or(from, |peer| peer as u16)
    }

    /// Passes `peer`'s ring over its oldest entry and clears the peer's busy bit when the ring empties.
    #[inline]
    fn pass_reply(&mut self, peer: u16) {
        let width = self.config.replies;
        let (head, len) = &mut self.reply_heads[usize::from(peer)];
        *head = if *head + 1 == width { 0 } else { *head + 1 };
        *len -= 1;
        self.queued -= 1;
        self.reply_busy[usize::from(peer) / 64] &= !(u64::from(*len == 0) << (peer % 64));
    }

    /// Appends `frame` to the poll's batch. A round stages only below the poll's budget, which the batch's capacity caps, so the batch keeps its allocation.
    #[inline(always)]
    fn stage(&mut self, frame: Staged) {
        assert!(
            self.staged.len() < self.staged.capacity(),
            "a round stages within the poll's batch"
        );
        self.staged.push(frame);
    }

    /// Stages `peer`'s oldest queued reply, if one is queued and the peer's pacing admits it; an entry a CANCEL emptied leaves the ring without a send.
    #[inline(never)]
    fn stage_reply(&mut self, peer: u16, now_us: u64) -> Step {
        let (head, len) = self.reply_heads[usize::from(peer)];
        if len == 0 {
            return Step::Idle;
        }
        let at = usize::from(peer) * self.config.replies as usize + head as usize;
        let Some(reply) = self.replies[at] else {
            self.pass_reply(peer);
            return Step::Passed;
        };
        let pacer = &mut self.pacers[usize::from(peer)];
        if !pacer.ready(now_us) {
            return Step::Paced;
        }
        // A terminal reply carries no body. While requests stage first, replies leave `egress_need` bytes in the bucket, so the waiting request's credit accumulates across polls.
        let bytes = wire_bytes(0);
        let reserved = if self.replies_first {
            0
        } else {
            self.egress_need
        };
        if !self.shaper.ready(now_us, bytes.saturating_add(reserved)) {
            return Step::Throttled;
        }
        pacer.spend();
        let taken = self.shaper.take(now_us, bytes);
        debug_assert!(taken, "the shaper admits the bytes it reported ready");
        self.pass_reply(peer);
        self.stage(Staged {
            peer: reply.peer,
            epoch: reply.epoch,
            source: Source::Reply(at as u32),
            bytes,
            burst: 0,
        });
        Step::Sent
    }

    /// Takes an admitted GET at `now_us`, admitting a fresh request into `requests` or answering a duplicate from it.
    pub fn get<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        session: Admitted,
        header: &Header,
        now_us: u64,
    ) -> GetOutcome {
        debug_assert_eq!(requests.table().slots() as usize, self.due.len());
        let id = RequestId::from_wire(header.request);
        let fingerprint = Fingerprint {
            key: header.key,
            metadata_cap: header.metadata_len,
            body_cap: header.body_len,
            grant: header.grant,
        };
        let wait_us = (u64::from(header.remaining_ms) * 1000).min(self.config.max_wait_us);
        let deadline_us = now_us.saturating_add(wait_us);
        let ask = Ask {
            session,
            request: header.request,
            fingerprint,
            deadline_us,
        };
        if u32::from(id.slot()) >= session.caps.slots {
            return self.refuse(&ask, Status::InvalidRequest);
        }
        if header.grant > session.caps.window {
            // The refusal settles a fresh identity, so no GET under this request ID is admitted after its ERROR. A retransmission is refused again, and the same ID with another grant conflicts with the retained row.
            requests.settle(
                session.peer,
                id,
                Some(Cached {
                    epoch: session.epoch,
                    expires_us: deadline_us.saturating_add(self.config.linger_us),
                    outcome: Outcome::Get(GetRow {
                        fingerprint,
                        terminal: Terminal::Error(Status::InvalidRequest),
                    }),
                }),
            );
            return self.refuse(&ask, Status::InvalidRequest);
        }
        match requests.route(session.peer, id, Operation::Get) {
            Route::Outside => return self.refuse(&ask, Status::InvalidRequest),
            Route::Older | Route::WrongOperation => return GetOutcome::Dropped,
            Route::Same { active, cached } => {
                return self.duplicate(requests, &ask, active, cached, now_us);
            }
            Route::Fresh => {}
        }
        let serve = || {
            Request::Get(Serve {
                peer: session.peer,
                epoch: session.epoch,
                request: header.request,
                fingerprint,
                deadline_us,
                manifest: None,
                chunks: [const { None }; HELD_CHUNKS],
                held: 0,
                runs: ZeroRuns::new(),
                commanded: 0,
                read_to: 0,
                read_complete: false,
                base: 0,
                granted: header.grant,
                next: 0,
                resend: 0,
                holes: 0,
                holes_at_us: 0,
                start_acked: false,
                start_due: false,
                complete_due: false,
                error_due: None,
                progress_us: now_us,
                attempts: 0,
                ended: false,
                disarmed: false,
            })
        };
        let table = match requests.admit(session.peer, id, serve) {
            Ok(table) => table,
            Err(Refusal::Outside) => return self.refuse(&ask, Status::InvalidRequest),
            Err(Refusal::Stale) => return GetOutcome::Dropped,
            Err(Refusal::Exhausted) => return self.refuse(&ask, Status::CounterExhausted),
            Err(refusal @ (Refusal::Busy | Refusal::Pressure(_))) => {
                match refusal {
                    Refusal::Busy => self.report.refused_pressure.busy += 1,
                    Refusal::Pressure(RequestPressure::Peer) => {
                        self.report.refused_pressure.peer += 1;
                    }
                    _ => self.report.refused_pressure.table += 1,
                }
                // The refusal settles the identity, so no retransmission starts
                // a read the refused client never drives. On a free slot a
                // retransmission replays the refusal. On a slot a request
                // still binds the namespace keeps the refused generation
                // alone: a retransmission is refused again while the binding
                // lasts and dropped once it frees.
                requests.settle(
                    session.peer,
                    id,
                    Some(Cached {
                        epoch: session.epoch,
                        expires_us: deadline_us.saturating_add(self.config.linger_us),
                        outcome: Outcome::Get(GetRow {
                            fingerprint,
                            terminal: Terminal::Error(Status::RequestPressure),
                        }),
                    }),
                );
                return self.refuse(&ask, Status::RequestPressure);
            }
        };
        self.report.requests += 1;
        // The due time covers a retry from admission too, so a wait that starts before it passes needs no arming.
        self.arm(
            table,
            deadline_us.min(now_us.saturating_add(self.config.retry_us)),
        );
        GetOutcome::Read {
            id: table,
            deadline_us,
        }
    }

    fn duplicate<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        ask: &Ask,
        active: Option<RequestId>,
        cached: Option<Cached<Outcome>>,
        now_us: u64,
    ) -> GetOutcome {
        self.report.duplicates += 1;
        if let Some(table) = active
            && let Some(serve) = requests.serve_mut(table)
            && !serve.ended
        {
            if serve.epoch != ask.session.epoch {
                return self.refuse(ask, Status::SessionMismatch);
            }
            if serve.fingerprint != ask.fingerprint {
                return self.refuse(ask, Status::ConflictingRequest);
            }
            serve.deadline_us = serve.deadline_us.min(ask.deadline_us);
            #[cfg(test)]
            if super::parked::planted(super::parked::Plant::DuplicateExtends) {
                serve.deadline_us = serve.deadline_us.max(ask.deadline_us);
            }
            serve.start_due |= !serve.start_acked && serve.manifest.is_some();
            serve.resend = serve.base;
            let deadline_us = serve.deadline_us;
            self.arm(table, deadline_us);
            self.mark(table);
            return GetOutcome::Duplicate;
        }
        match cached.and_then(|row| row.current(ask.session.epoch, now_us)) {
            Some(Outcome::Get(row)) => {
                if row.fingerprint != ask.fingerprint {
                    return self.refuse(ask, Status::ConflictingRequest);
                }
                let pending = active
                    .and_then(|table| requests.serve(table))
                    .is_some_and(|serve| serve.error_due.is_some());
                if pending {
                    // The pending ERROR answers this duplicate too.
                    return GetOutcome::Replayed;
                }
                self.report.replays += 1;
                self.queue_reply(Reply {
                    table: active,
                    peer: ask.session.peer,
                    epoch: ask.session.epoch,
                    request: ask.request,
                    key: ask.fingerprint.key,
                    terminal: row.terminal,
                    first: false,
                });
                GetOutcome::Replayed
            }
            _ => GetOutcome::Dropped,
        }
    }

    /// Queues a PUT reply; `table` names the PUT's ended record when `put` is a PUT ERROR that tells the client the upload ended, and the sent prefix then frees the record's wire binding.
    #[inline]
    pub(super) fn queue_put(
        &mut self,
        table: Option<RequestId>,
        peer: PeerId,
        epoch: u64,
        request: u64,
        key: [u8; 32],
        put: PutReply,
    ) {
        debug_assert!(
            table.is_none() || put.kind == Kind::PutError,
            "only a PUT ERROR names its record"
        );
        self.queue_reply(Reply {
            table,
            peer,
            epoch,
            request,
            key,
            terminal: Terminal::Put(put),
            first: false,
        });
    }

    /// Queues `put`, the first PUT RESULT of a fill that just published. [`put_results_queued`](Self::put_results_queued) counts it while its peer's ring holds it; a full ring drops it uncounted.
    #[inline]
    pub(super) fn queue_put_result(
        &mut self,
        peer: PeerId,
        epoch: u64,
        request: u64,
        key: [u8; 32],
        put: PutReply,
    ) {
        debug_assert_eq!(put.kind, Kind::PutResult, "a fill's own result");
        let queued = self.queue_reply(Reply {
            table: None,
            peer,
            epoch,
            request,
            key,
            terminal: Terminal::Put(put),
            first: true,
        });
        self.put_results += u32::from(queued);
    }

    /// Queues INVALIDATED answering request `request` of key `key` under session `epoch`, for the interval `interval`.
    pub(super) fn queue_invalidated(&mut self, asker: Asker, (key, interval): CoverageEntry) {
        self.queue_reply(Reply {
            table: None,
            peer: asker.peer,
            epoch: asker.epoch,
            request: asker.request,
            key,
            terminal: Terminal::Invalidated(interval.low().0, interval.high().0),
            first: false,
        });
    }

    /// Queues an ERROR of `status` answering `ask`, which holds no request.
    #[inline]
    fn refuse(&mut self, ask: &Ask, status: Status) -> GetOutcome {
        self.report.refused_by_status[status as usize - 1] += 1;
        self.queue_reply(Reply {
            table: None,
            peer: ask.session.peer,
            epoch: ask.session.epoch,
            request: ask.request,
            key: ask.fingerprint.key,
            terminal: Terminal::Error(status),
            first: false,
        });
        GetOutcome::Refused(status)
    }

    /// Records that request `id`'s read was admitted, with its first command submitted or waiting for a table slot.
    #[inline]
    pub fn read_started<C: Chunk, F>(&mut self, requests: &mut Requests<C, F>, id: RequestId) {
        if let Some(serve) = requests.serve_mut(id) {
            serve.commanded = 1;
        }
    }

    #[inline]
    pub fn restart_progress<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        id: RequestId,
        now_us: u64,
    ) {
        if let Some(serve) = requests.serve_mut(id) {
            serve.progress_us = now_us;
        }
    }

    /// Ends request `id`, whose read was refused, with an ERROR of `status`.
    pub fn read_refused<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        id: RequestId,
        status: Status,
        now_us: u64,
    ) {
        self.end(requests, id, Some(status), now_us);
    }

    /// Takes a verified chunk of request `id`: payload bytes `range` under `manifest`, whose windows' verified checksums are `window_crcs`, at most the core's `windows`.
    /// Returns whether the read should continue: false once the request ended, including by this manifest exceeding the GET's caps (`TooLarge`) or differing from the bound one (`IntegrityError`).
    #[inline]
    pub fn chunk<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        id: RequestId,
        manifest: Manifest,
        input: ChunkInput<'_, C>,
        now_us: u64,
    ) -> bool {
        self.chunk_with_digests(requests, id, manifest, input, now_us, None)
    }

    /// The peer and session epoch of request `id` while it is live.
    pub fn session_of<C, F>(
        &self,
        requests: &Requests<C, F>,
        id: RequestId,
    ) -> Option<(PeerId, u64)> {
        requests.serve(id).map(|serve| (serve.peer, serve.epoch))
    }

    /// [`chunk`](Self::chunk) that also caches the body digest `digest` computes for each fragment the chunk holds whole within the `fragments` indices starting at the fragment containing the chunk's first byte. `digest` reads the fragment's bytes right after their verification, and staging the fragment carries the cached digest in its [`Out`]. The sender computes the digests of fragments beyond the row or declined by `digest`.
    #[inline]
    pub fn chunk_with_digests<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        id: RequestId,
        manifest: Manifest,
        input: ChunkInput<'_, C>,
        now_us: u64,
        digest: Option<&mut FragmentDigest<'_>>,
    ) -> bool {
        let ChunkInput {
            range,
            chunk,
            window_crcs,
        } = input;
        if !self.bind(requests, id, manifest, now_us) {
            return false;
        }
        let Some(serve) = requests.serve_mut(id) else {
            return false;
        };
        serve.commanded = serve.commanded.saturating_sub(1);
        if serve.ended {
            return false;
        }
        serve.read_to = serve.read_to.max(range.end);
        debug_assert!(
            window_crcs.len() <= self.windows,
            "a chunk spans at most the core's windows"
        );
        // The free row is one no held chunk names; the slots compact, so a free slot exists exactly when a free row does.
        let row = (0..HELD_CHUNKS as u8).find(|row| {
            !serve
                .held_chunks()
                .iter()
                .flatten()
                .any(|held| held.row == *row)
        });
        // The slots compact, so the first free slot follows the held ones.
        let free = usize::from(serve.held);
        match (
            serve.chunks.get_mut(free).filter(|slot| slot.is_none()),
            row,
        ) {
            (Some(free), Some(row)) => {
                let rows =
                    &mut self.window_crcs[usize::from(id.slot()) * HELD_CHUNKS * self.windows..];
                rows[usize::from(row) * self.windows..][..window_crcs.len()]
                    .copy_from_slice(window_crcs);
                let at = usize::from(id.slot()) * HELD_CHUNKS + usize::from(row);
                let mut valid = 0;
                if let Some(digest) = digest
                    && self.fragments > 0
                {
                    let entries = &mut self.digests[at * self.fragments..][..self.fragments];
                    let first = (range.start / u64::from(FRAGMENT_LEN)) as u32;
                    let bytes = chunk.as_ref();
                    for (i, entry) in entries.iter_mut().enumerate() {
                        let index = first + i as u32;
                        if index >= manifest.count() {
                            break;
                        }
                        let fragment = FragmentGeometry::fragment(index, manifest.total());
                        if fragment.start < range.start || fragment.end > range.end {
                            continue;
                        }
                        let within = (fragment.start - range.start) as usize
                            ..(fragment.end - range.start) as usize;
                        if let Some(computed) = digest(&bytes[within]) {
                            *entry = computed;
                            valid |= 1 << i;
                        }
                    }
                }
                self.digest_valid[at] = valid;
                *free = Some(Held { range, chunk, row });
                serve.held += 1;
            }
            _ => debug_assert!(false, "a read holds at most HELD_CHUNKS backing buffers"),
        }
        self.mark(id);
        true
    }

    /// Fixes request `id`'s manifest from its first verified event and queues START; refuses a manifest above the GET's caps.
    #[inline]
    fn bind<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        id: RequestId,
        manifest: Manifest,
        now_us: u64,
    ) -> bool {
        let Some(serve) = requests.serve_mut(id) else {
            return false;
        };
        match serve.manifest {
            Some(bound) if bound == manifest => true,
            Some(_) => {
                // One read verifies one header, so a second manifest means the caller mixed reads.
                self.end(requests, id, Some(Status::IntegrityError), now_us);
                false
            }
            None => {
                let caps = serve.fingerprint;
                if manifest.metadata_len > caps.metadata_cap || manifest.body_len > caps.body_cap {
                    self.end(requests, id, Some(Status::TooLarge), now_us);
                    return false;
                }
                serve.manifest = Some(manifest);
                serve.start_due = true;
                // The request now waits on the START receipt; a disarmed request arms its retry from its last progress.
                if std::mem::take(&mut serve.disarmed) {
                    let retry_at = serve.retry_from_progress(self.config.retry_us);
                    self.arm(id, retry_at);
                }
                self.mark(id);
                true
            }
        }
    }

    /// Takes the end of request `id`'s read; a completed read carries the manifest of its verified header.
    #[inline]
    pub fn read_done<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        id: RequestId,
        end: ReadEnd,
        now_us: u64,
    ) {
        if let ReadEnd::Complete(manifest) = end
            && !self.bind(requests, id, manifest, now_us)
        {
            return;
        }
        let Some(serve) = requests.serve_mut(id) else {
            return;
        };
        serve.commanded = 0;
        if serve.ended {
            return;
        }
        match end {
            ReadEnd::Complete(_) => {
                serve.read_complete = true;
                serve.complete_due |= serve
                    .manifest
                    .is_some_and(|m| serve.base == m.count() && serve.start_acked);
                self.mark(id);
            }
            ReadEnd::Failed(status) => self.end(requests, id, Some(status), now_us),
        }
    }

    /// Whether request `id` may have its read's next command granted: it is live with its read unfinished and fewer than the core's `commands` commands outstanding or granted, its retained chunks and those commands' buffers stay within [`BUFFERS_PER_READ`] plus one per command beyond the first, and the client's grant admits the read's first fragment not yet read: the oldest outstanding command's, or the new command's when none is outstanding.
    ///
    /// A command ahead therefore reads while the client still drains the current command's fragments: its bytes wait in the request's own buffer until the grant reaches them, and a client whose window spans one command still overlaps the device latency of the commands ahead with its own receipt.
    #[inline]
    pub fn wants_grant<C: Chunk, F>(&self, requests: &Requests<C, F>, id: RequestId) -> bool {
        let Some(serve) = requests.serve(id) else {
            return false;
        };
        let commanded = u32::from(serve.commanded);
        let held = u32::from(serve.held);
        let buffers = BUFFERS_PER_READ + u32::from(self.commands) - 1;
        let oldest = (serve.read_to / u64::from(FRAGMENT_LEN)) as u32;
        !serve.ended
            && !serve.read_complete
            && commanded < u32::from(self.commands)
            && held + commanded < buffers
            && oldest < serve.granted
    }

    /// Lets each request hold `ahead` read commands outstanding or granted beyond its current one, for a volume that reads that far ahead; at most [`MAX_READ_AHEAD`].
    pub fn read_ahead(&mut self, ahead: u8) {
        debug_assert!(ahead <= MAX_READ_AHEAD, "attach refuses deeper read-ahead");
        self.commands = 1 + ahead.min(MAX_READ_AHEAD);
    }

    /// Takes an admitted ACK at `now_us`.
    #[inline]
    pub fn ack<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        session: Admitted,
        header: &Header,
        now_us: u64,
    ) {
        let id = RequestId::from_wire(header.request);
        let Route::Same { active, cached } = requests.route(session.peer, id, Operation::Get)
        else {
            self.report.stale_acks += 1;
            return;
        };
        let live = active.and_then(|table| {
            requests
                .serve_mut(table)
                .filter(|serve| !serve.ended && serve.epoch == session.epoch)
                .map(|serve| (table, serve))
        });
        let Some((table, serve)) = live else {
            // A final ACK of an ended request replays its cached COMPLETE.
            if let Some(Outcome::Get(row)) =
                cached.and_then(|row| row.current(session.epoch, now_us))
                && let Terminal::Complete(manifest) = row.terminal
                && matches_manifest(header, &manifest, &row.fingerprint.key)
                && header.index == manifest.count()
            {
                self.report.replays += 1;
                self.queue_reply(Reply {
                    table: active,
                    peer: session.peer,
                    epoch: session.epoch,
                    request: header.request,
                    key: header.key,
                    terminal: row.terminal,
                    first: false,
                });
            } else {
                self.report.stale_acks += 1;
            }
            return;
        };
        let report = &mut self.report;
        let window = session.caps.window;
        let Some(manifest) = serve.manifest else {
            report.stale_acks += 1;
            return;
        };
        // One past the highest fragment the mask shows held; the base itself when the mask is empty.
        let reported = if header.offset == 0 {
            header.index
        } else {
            header
                .index
                .saturating_add(u64::BITS - header.offset.leading_zeros() + 1)
        };
        let accepted = matches_manifest(header, &manifest, &serve.fingerprint.key)
            && header.index >= serve.base
            && reported <= serve.next
            && header.grant >= serve.granted
            && u64::from(header.grant) <= u64::from(header.index) + u64::from(window);
        if !accepted {
            report.stale_acks += 1;
            return;
        }
        let progressed =
            header.index > serve.base || !serve.start_acked || header.grant > serve.granted;
        // Progress at a time earlier than the last, or after retries that lengthened the wait, moves the retry earlier, possibly before the current due time, so the due time is lowered to it.
        let earlier = progressed && (now_us < serve.progress_us || serve.attempts > 0);
        serve.start_acked = true;
        serve.start_due = false;
        if serve.holes != 0 {
            serve.holes = shift_holes(serve.holes, header.index - serve.base);
        }
        serve.base = header.index;
        serve.granted = header.grant;
        serve.resend = serve.resend.max(serve.base);
        if progressed {
            serve.progress_us = now_us;
            serve.attempts = 0;
        }
        if reported > serve.base && now_us >= serve.holes_at_us.saturating_add(HOLE_GUARD_US) {
            serve.holes = holes_below(header.offset, reported - serve.base);
            serve.holes_at_us = now_us;
        }
        let holding = serve.reap();
        if serve.base == manifest.count() && serve.read_complete {
            serve.complete_due = true;
        }
        self.mark(table);
        self.set_holding(usize::from(table.slot()), holding);
        if earlier {
            self.arm(table, now_us.saturating_add(self.config.retry_us));
        }
    }

    /// Sets or clears table slot `slot`'s holding bit.
    #[inline]
    fn set_holding(&mut self, slot: usize, holding: bool) {
        let (word, bit) = (&mut self.holding[slot / 64], 1 << (slot % 64));
        if (*word & bit != 0) != holding {
            *word ^= bit;
            if holding {
                self.holders += 1;
            } else {
                self.holders -= 1;
            }
        }
    }

    /// Drops the passed and ended chunks whose last device reference returned, visiting only requests that hold one, and returns how many requests stopped holding. A request whose chunk dropped may take its read's next command, and an ended one may then drain, with no further ACK.
    /// The scan stops after the last holding request, so a reap with no holder reads only the holder count.
    #[inline]
    pub fn reap<C: Chunk, F>(&mut self, requests: &mut Requests<C, F>) -> u32 {
        if self.holders == 0 {
            return 0;
        }
        self.reap_holders(requests)
    }

    /// Keeping the scan out of line lets [`reap`](Self::reap) handle `self.holders == 0` with only a count check.
    #[inline(never)]
    fn reap_holders<C: Chunk, F>(&mut self, requests: &mut Requests<C, F>) -> u32 {
        let mut reaped = 0;
        let mut left = self.holders;
        let mut word = 0;
        while left > 0
            && let Some(&bits) = self.holding.get(word)
        {
            let mut bits = bits;
            while bits != 0 {
                let bit = bits.isolate_lowest_one();
                bits ^= bit;
                left -= 1;
                let slot = word as u32 * u64::BITS + bit.trailing_zeros();
                let held = requests
                    .live_serve(slot)
                    .is_some_and(|(_, serve)| serve.reap());
                if !held {
                    self.holding[word] ^= bit;
                    self.holders -= 1;
                    reaped += 1;
                }
            }
            word += 1;
        }
        reaped
    }

    /// A CANCEL with a matching key ends the session's live request, caches the CANCEL's status, and drops the request's pending ERROR.
    /// The CANCEL also clears the peer's queued replies for its wire ID and key. A CANCEL with a different key leaves the live request running.
    /// A CANCEL on a fresh identity settles the identity, so a later GET for it is dropped. On a wire slot another request still binds, that GET is refused while the binding lasts and dropped once it frees.
    pub fn cancel<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        session: Admitted,
        header: &Header,
        now_us: u64,
    ) {
        let id = RequestId::from_wire(header.request);
        let active = match requests.route(session.peer, id, Operation::Get) {
            Route::Same { active, .. } => active,
            Route::Fresh => {
                requests.settle(session.peer, id, None);
                return;
            }
            Route::Outside | Route::Older | Route::WrongOperation => return,
        };
        if let Some(table) = active
            && requests.serve(table).is_some_and(|serve| {
                serve.epoch == session.epoch && serve.fingerprint.key == header.key
            })
        {
            let status = Status::from_wire(header.status).unwrap_or(Status::Cancelled);
            self.end_silently(requests, table, Terminal::Error(status), now_us);
        }
        self.clear_replies(session.peer, header.request, &header.key);
    }

    fn clear_replies(&mut self, peer: PeerId, request: u64, key: &[u8; 32]) {
        let Some(ring) = Self::of_peer(&mut self.replies, peer, self.config.replies) else {
            return;
        };
        for entry in ring {
            if let Some(reply) = entry.filter(|reply| {
                reply.request == request
                    && reply.key == *key
                    && !matches!(reply.terminal, Terminal::Invalidated(..))
            }) {
                self.put_results -= u32::from(reply.first);
                *entry = None;
            }
        }
    }

    /// Ends request `id` logically: sends stop except a queued ERROR of `status`, chunks drop, and the request drains.
    fn end<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        id: RequestId,
        status: Option<Status>,
        now_us: u64,
    ) {
        let Some(serve) = requests.serve_mut(id) else {
            return;
        };
        if serve.ended {
            return;
        }
        serve.error_due = status;
        let terminal = Terminal::Error(status.unwrap_or(Status::Cancelled));
        self.mark(id);
        self.finish(requests, id, terminal, now_us);
    }

    /// Ends a live request `id` with `terminal` cached and no frame left to send; for a request that ended earlier, drops its pending ERROR and keeps its cached terminal.
    fn end_silently<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        id: RequestId,
        terminal: Terminal,
        now_us: u64,
    ) {
        let Some(serve) = requests.serve_mut(id) else {
            return;
        };
        serve.error_due = None;
        if !serve.ended {
            self.finish(requests, id, terminal, now_us);
        }
    }

    /// Marks request `id` ended with `terminal` retained on its wire slot.
    fn finish<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        id: RequestId,
        terminal: Terminal,
        now_us: u64,
    ) {
        let linger = self.config.linger_us;
        let Some(serve) = requests.serve_mut(id) else {
            return;
        };
        self.ended_since_scan = true;
        serve.ended = true;
        // Ending clears `disarmed`, so a manifest bound after the end leaves the due time at `u64::MAX`.
        serve.disarmed = false;
        serve.start_due = false;
        self.egress_need = 0;
        if self
            .open_burst
            .is_some_and(|(slot, _)| slot == u32::from(id.slot()))
        {
            self.open_burst = None;
        }
        // Chunks a device still reads stay until their last reference returns; `reap` drops them.
        let holding = serve.reap();
        let (peer, wire) = (serve.peer, RequestId::from_wire(serve.request));
        let cached = Cached {
            epoch: serve.epoch,
            expires_us: serve.deadline_us.max(now_us).saturating_add(linger),
            outcome: Outcome::Get(GetRow {
                fingerprint: serve.fingerprint,
                terminal,
            }),
        };
        requests.begin_drain(id);
        requests.retain(peer, wire.slot(), id, cached);
        let slot = usize::from(id.slot());
        // An ended request's due time is `u64::MAX`, so timer scans pass over it.
        self.due[slot] = u64::MAX;
        self.ended[slot / 64] |= 1 << (slot % 64);
        self.set_holding(usize::from(id.slot()), holding);
    }

    /// Lowers request `id`'s due time, and the tick bound, to at most `at_us`.
    /// Admission, a duplicate's tightened deadline, an ACK whose progress moves the retry earlier, and a disarmed request starting a wait on a receipt call this.
    #[inline]
    fn arm(&mut self, id: RequestId, at_us: u64) {
        self.tick_due_us = self.tick_due_us.min(at_us);
        let due = &mut self.due[usize::from(id.slot())];
        *due = (*due).min(at_us);
    }

    /// Advances timers at `now_us`: deadlines end requests `TimedOut`, and stalled requests retry from their base or end after their last attempt; a cached terminal past its horizon is ignored where it is read.
    /// A tick before the bound returns at once.
    #[inline]
    pub fn tick<C: Chunk, F>(&mut self, requests: &mut Requests<C, F>, now_us: u64) {
        debug_assert_eq!(requests.table().slots() as usize, self.due.len());
        if now_us >= self.tick_due_us {
            self.expire(requests, now_us);
        }
    }

    /// Ends or retries every request whose deadline or retry is due at `now_us`, sets each visited request's next due time, and sets the tick bound to the earliest due time.
    fn expire<C: Chunk, F>(&mut self, requests: &mut Requests<C, F>, now_us: u64) {
        let (retry_us, attempts) = (self.config.retry_us, self.config.attempts);
        let end = requests.table().high_water() as usize;
        let mut from = 0;
        // A request whose due time is later than `now_us` has neither its deadline nor its retry due.
        while let Some(slot) = next_due(&self.due[..end], from, now_us) {
            from = slot + 1;
            let Some((id, serve)) = requests.live_serve(slot as u32) else {
                continue;
            };
            if now_us >= serve.deadline_us {
                self.end(requests, id, Some(Status::TimedOut), now_us);
                continue;
            }
            let retried = serve.retry_at(retry_us).is_some_and(|at| now_us >= at);
            if retried {
                if serve.attempts >= attempts {
                    self.end(requests, id, Some(Status::TimedOut), now_us);
                    continue;
                }
                serve.attempts += 1;
                serve.progress_us = now_us;
                serve.start_due |= !serve.start_acked;
                serve.resend = serve.base;
                serve.holes = 0;
                self.report.retries += 1;
            }
            // A request waiting on nothing keeps its retry from its last progress in the due time until that passes, then disarms.
            let retry_at = serve.retry_from_progress(retry_us);
            self.due[slot] = match serve.retry_at(retry_us) {
                Some(at) => serve.deadline_us.min(at),
                None if retry_at > now_us => serve.deadline_us.min(retry_at),
                None => {
                    serve.disarmed = true;
                    serve.deadline_us
                }
            };
            if retried {
                self.mark(id);
            }
        }
        self.tick_due_us = self.due[..end].iter().copied().fold(u64::MAX, u64::min);
    }

    /// `drained` receives namespace table handles; `true` permits freeing that
    /// request's table slot and peer share. The wire watermark and cached outcome stay,
    /// unless a generation was settled while the request held the binding: the binding's
    /// unbind at a sent terminal, or this release when the request is still bound, raises
    /// the watermark to it and drops the cached outcome.
    /// The scan visits ended slots with clear holding bits in slot order; an ended
    /// request retains chunks exactly while its holding bit is set.
    pub fn release_drained<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        mut drained: impl FnMut(RequestId) -> bool,
    ) -> u32 {
        if requests.census().draining == 0 {
            return 0;
        }
        let mut released = 0;
        let mut from = 0;
        while let Some(slot) = next_clear_of(&self.ended, &self.holding, from) {
            from = slot + 1;
            let Some(id) = requests.table().live_id(slot) else {
                continue;
            };
            let Some(serve) = requests.serve(id) else {
                continue;
            };
            if serve.error_due.is_some() || serve.held != 0 {
                continue;
            }
            let (peer, wire) = (serve.peer, RequestId::from_wire(serve.request));
            if !drained(id) {
                continue;
            }
            if requests.release(id, peer, wire.slot()) {
                self.unmark(slot);
                let at = slot as usize;
                self.ended[at / 64] &= !(1 << (at % 64));
                released += 1;
            }
        }
        released
    }

    /// Ends `peer`'s GETs and clears their pending ERRORs and queued replies.
    pub(super) fn retire_peer<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        peer: PeerId,
        now_us: u64,
    ) {
        for slot in 0..requests.table().high_water() {
            if let Some(id) = requests.table().live_id(slot)
                && requests.table().peer(id) == Some(peer)
            {
                self.end_silently(
                    requests,
                    id,
                    Terminal::Error(Status::SessionMismatch),
                    now_us,
                );
            }
        }
        if let Some(ring) = Self::of_peer(&mut self.replies, peer, self.config.replies) {
            let first = ring.iter().flatten().filter(|reply| reply.first).count();
            self.put_results -= first as u32;
            ring.fill(None);
            let (_, len) = self.reply_heads[usize::from(peer.0)];
            self.queued -= len;
            self.reply_heads[usize::from(peer.0)] = (0, 0);
            self.reply_busy[usize::from(peer.0) / 64] &= !(1 << (peer.0 % 64));
        }
    }

    /// Sends one batch through `send` at `now_us`, capped by `budget` and the batch size. A round stages at most one reply per ready peer and up to `DATA_BURST` frames per visited request, and a request's pending ERROR, START or COMPLETE stages ahead of its next DATA fragment. Replies stage first unless the previous poll left requests waiting, which holds when the shaper refused its data round before the round staged a frame, or when its replies-first batch filled `budget` while a request was marked ready; requests then stage first, replies spending only the bytes above a refused frame's need, and the poll after them returns to replies first unless the shaper refused their round. A `budget` of 0 stages nothing and keeps the staging order.
    /// `send` runs once when the poll staged at least one frame and returns how many of the batch count as sent, in order; the frames after that prefix wait for the next poll, and a COMPLETE ends its request once it is inside the prefix. Returns that count.
    pub fn poll<'a, C, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        now_us: u64,
        budget: usize,
        send: impl FnOnce(&mut dyn Iterator<Item = Out<'_, 'a>>) -> usize,
    ) -> usize
    where
        C: Retained<'a>,
    {
        debug_assert_eq!(requests.table().slots() as usize, self.due.len());
        self.staged.clear();
        let budget = budget.min(self.staged.capacity());
        // A poll without a send leaves the staging order to the next poll that has one.
        if budget == 0 {
            return 0;
        }
        let requests_wait = if self.replies_first {
            self.stage_replies(now_us, budget);
            // Replies that fill the batch leave a ready request no send, so it stages first next poll.
            let crowded = self.staged.len() >= budget && self.ready_count > 0;
            self.stage_requests(requests, now_us, budget) || crowded
        } else {
            let requests_wait = self.stage_requests(requests, now_us, budget);
            self.stage_replies(now_us, budget);
            requests_wait
        };
        self.replies_first = !requests_wait;
        if self.staged.is_empty() {
            return 0;
        }
        let taken = {
            let reader: &Requests<C, F> = requests;
            let replies = &self.replies;
            let mut frames = self
                .staged
                .iter()
                .map(|staged| frame(reader, replies, staged));
            send(&mut frames).min(self.staged.len())
        };
        self.settle(requests, taken, now_us);
        taken
    }

    /// Stages each peer's oldest reply, one per peer per round while its pacer has a token, until `budget` frames are staged, one round stages none, or the shaper throttles a reply; the next poll then starts at the throttled peer.
    #[inline(always)]
    fn stage_replies(&mut self, now_us: u64, budget: usize) {
        let peers = self.reply_heads.len() as u16;
        // Visits since the round last staged or passed an entry, counting the peers with an empty ring that the round steps over; a round ends after `peers` such visits.
        let mut idle = 0;
        // One reply per ready peer per round, so a peer out of pacing tokens holds back only its own replies.
        while self.staged.len() < budget && self.queued > 0 && idle < peers {
            let mut peer = self.reply_cursor;
            if self.reply_heads[usize::from(peer)].1 == 0 {
                // A positive `queued` guarantees a peer with a queued entry; visits before the next such peer stage zero frames.
                let busy = self.next_busy(peer);
                let (from, to, all) = (u32::from(peer), u32::from(busy), u32::from(peers));
                let skipped = if to > from {
                    to - from
                } else {
                    to + all - from
                };
                let left = all - u32::from(idle);
                if skipped >= left {
                    // The round's last `peers` visits staged nothing, so the cursor goes back to the peer where those visits began.
                    self.reply_cursor = ((from + left) % all) as u16;
                    break;
                }
                idle += skipped as u16;
                peer = busy;
            }
            self.reply_cursor = if peer + 1 >= peers { 0 } else { peer + 1 };
            match self.stage_reply(peer, now_us) {
                Step::Sent | Step::Passed => idle = 0,
                Step::Idle | Step::Paced => idle += 1,
                Step::Throttled => {
                    // This visit staged nothing, so the next poll starts here.
                    self.reply_cursor = peer;
                    break;
                }
            }
        }
    }

    /// The shaper ends the round before any visit while its bucket holds fewer bytes than it last refused the cursor's request. With no request marked ready, the round stages nothing and preserves the cursor and `open_burst`.
    /// Returns whether the shaper ended the round before it staged a frame.
    #[inline(always)]
    fn stage_requests<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        now_us: u64,
        budget: usize,
    ) -> bool {
        if !self.shaper.ready(now_us, self.egress_need) {
            return true;
        }
        self.egress_need = 0;
        if self.ready_count == 0 {
            return false;
        }
        self.visit_ready(requests, now_us, budget)
    }

    /// Each visit stages up to [`DATA_BURST`] frames for a ready request, starting at the cursor. The round ends when `budget` frames are staged, when every ready request has staged its last frame or waits on its peer's pacer for this round, or when the shaper throttles a frame. Throttling saves the visit's staged-frame count in `open_burst` and positions the next poll at the throttled slot. The round's first visit continues `open_burst` if the visit reaches that burst's slot.
    /// Returns whether the shaper ended the round before it staged a frame.
    fn visit_ready<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        now_us: u64,
        budget: usize,
    ) -> bool {
        let staged_before = self.staged.len();
        // Moving a paced slot's ready bit to `deferred` limits the slot to one visit per round at `now_us`; `restore` makes it eligible for the next poll.
        let mut moved: Option<(usize, usize)> = None;
        let mut throttled = false;
        let slots = requests.table().slots();
        let mut open = self.open_burst.take();
        'round: while self.staged.len() < budget && self.ready_count > 0 {
            let Some(slot) = self.next_ready(self.cursor) else {
                break;
            };
            let resumed = match open.take() {
                Some((at, sent)) if at == slot => sent,
                _ => 0,
            };
            let found = self.cursor;
            self.cursor = if slot + 1 == slots { 0 } else { slot + 1 };
            let mut burst = resumed;
            while usize::from(burst) < DATA_BURST && self.staged.len() < budget {
                match self.stage_one(requests, slot, burst, now_us) {
                    Step::Sent => burst += 1,
                    Step::Throttled => {
                        // Throttling preserves the request's turn and accumulated burst count across polls.
                        self.cursor = slot;
                        self.open_burst = Some((slot, burst));
                        throttled = true;
                        break 'round;
                    }
                    Step::Idle | Step::Passed => {
                        self.unmark(slot);
                        break;
                    }
                    Step::Paced => {
                        if burst == resumed {
                            // A visit that staged nothing leaves the cursor where it found it, so the request keeps its turn.
                            self.cursor = found;
                            if resumed > 0 {
                                self.open_burst = Some((slot, resumed));
                            }
                        }
                        let word = self.defer(slot);
                        moved =
                            Some(moved.map_or((word, word), |(low, high)| {
                                (low.min(word), high.max(word))
                            }));
                        break;
                    }
                }
            }
        }
        if let Some((low, high)) = moved {
            self.restore(low..=high);
        }
        if open.is_some() {
            self.open_burst = open;
        }
        throttled && self.staged.len() == staged_before
    }

    /// Ends the requests whose COMPLETE is among the first `taken` staged frames and counts their terminals and hole resends; every later frame goes back to where it was staged from, its pacing token and shaper bytes refunded, so the next poll offers it again.
    /// Restoring unaccepted frames newest first restores each request's state before its earliest unaccepted frame. This order leaves `reply_cursor` and `cursor` at the earliest unaccepted reply and request sources, where the next poll starts.
    fn settle<C: Chunk, F>(&mut self, requests: &mut Requests<C, F>, taken: usize, now_us: u64) {
        let staged = std::mem::take(&mut self.staged);
        for frame in &staged[..taken] {
            match frame.source {
                Source::Complete(id) => {
                    self.report.completed += 1;
                    if let Some(manifest) = requests.serve(id).and_then(|serve| serve.manifest) {
                        self.end_silently(requests, id, Terminal::Complete(manifest), now_us);
                    }
                    unbind_sent(requests, id);
                }
                Source::Reply(at) => {
                    if let Some(reply) = self.replies[at as usize].take() {
                        self.put_results -= u32::from(reply.first);
                        // A reply names a record only as the terminal of an
                        // ended request, answering that request's own wire
                        // identity, so the binding to free is at that identity.
                        if let Some(id) = reply.table {
                            let wire = RequestId::from_wire(reply.request);
                            requests.unbind(reply.peer, wire.slot(), id);
                        }
                        if let Terminal::Error(status) = reply.terminal {
                            self.report.errors_by_status[status as usize - 1] += 1;
                        }
                    }
                }
                Source::Error(id, status) => {
                    unbind_sent(requests, id);
                    self.report.errors += 1;
                    self.report.errors_by_status[status as usize - 1] += 1;
                }
                Source::Data { hole: true, .. } => self.report.hole_resends += 1,
                _ => {}
            }
        }
        for frame in staged[taken..].iter().rev() {
            self.pacers[usize::from(frame.peer.0)].refund();
            self.shaper.refund(frame.bytes);
            match frame.source {
                Source::Reply(_) => self.reply_cursor = frame.peer.0,
                Source::Start(id)
                | Source::Complete(id)
                | Source::Error(id, _)
                | Source::Data { id, .. } => {
                    let slot = u32::from(id.slot());
                    self.cursor = slot;
                    self.open_burst = Some((slot, frame.burst));
                    // The round may have cleared the request's ready bit once it had staged every frame it had; the frame it gets back sets it again.
                    self.mark(id);
                }
            }
            match frame.source {
                Source::Reply(at) => self.requeue(frame.peer, at as usize),
                Source::Start(id) => {
                    if let Some(serve) = requests.serve_mut(id) {
                        serve.start_due = true;
                    }
                }
                Source::Complete(id) => {
                    if let Some(serve) = requests.serve_mut(id) {
                        serve.complete_due = true;
                    }
                }
                Source::Error(id, status) => {
                    if let Some(serve) = requests.serve_mut(id) {
                        serve.error_due = Some(status);
                    }
                }
                Source::Data {
                    id,
                    index,
                    prior_next,
                    prior_resend,
                    hole,
                    ..
                } => {
                    if let Some(serve) = requests.serve_mut(id) {
                        if hole {
                            // ACKs run outside the poll that staged and settles this frame, so the base is the one the hole bit was cleared against.
                            serve.holes |= 1 << (index - serve.base);
                        } else {
                            serve.next = prior_next;
                            serve.resend = prior_resend;
                        }
                    }
                }
            }
        }
        self.staged = staged;
    }

    /// Requeuing a peer's unsent replies newest first restores their original order at the ring head.
    fn requeue(&mut self, peer: PeerId, at: usize) {
        let width = self.config.replies;
        let reply = self.replies[at].take();
        let first = u32::from(reply.is_some_and(|reply| reply.first));
        let Some((head, len)) = self.reply_heads.get_mut(usize::from(peer.0)) else {
            self.put_results -= first;
            return;
        };
        if *len >= width {
            self.put_results -= first;
            return;
        }
        *head = if *head == 0 { width - 1 } else { *head - 1 };
        *len += 1;
        self.queued += 1;
        let to = usize::from(peer.0) * width as usize + *head as usize;
        self.replies[to] = reply;
        self.set_busy(peer.0);
    }

    #[inline]
    fn defer(&mut self, slot: u32) -> usize {
        self.unmark(slot);
        let slot = slot as usize;
        self.deferred[slot / 64] |= 1 << (slot % 64);
        slot / 64
    }

    /// Returns the deferred bits of `words` to the ready set; a bit already set counts zero, so `ready_count` stays the set's population.
    fn restore(&mut self, words: std::ops::RangeInclusive<usize>) {
        for word in words {
            let bits = std::mem::take(&mut self.deferred[word]);
            self.ready_count += (bits & !self.ready[word]).count_ones();
            self.ready[word] |= bits;
        }
    }

    /// The cached body digest of fragment `index` of the request at `slot`, when `pieces` locate it whole inside one retained chunk whose row cached it.
    #[inline(always)]
    fn cached_digest<C>(
        &self,
        slot: u32,
        index: u32,
        pieces: &[Piece<'_, C>; MAX_PAYLOAD_SLICES],
    ) -> Option<[u8; DATA_DIGEST_LEN]> {
        if self.fragments == 0 {
            return None;
        }
        let [Some((held, _)), None] = pieces else {
            return None;
        };
        let first = (held.range.start / u64::from(FRAGMENT_LEN)) as u32;
        let i = index.checked_sub(first)? as usize;
        if i >= self.fragments {
            return None;
        }
        let at = slot as usize * HELD_CHUNKS + usize::from(held.row);
        (self.digest_valid[at] & (1 << i) != 0).then(|| self.digests[at * self.fragments + i])
    }

    /// Stages the next frame of the request in table slot `slot`, if it has one and its peer's pacing admits it, advancing the request as its send would.
    #[inline]
    fn stage_one<C: Chunk, F>(
        &mut self,
        requests: &mut Requests<C, F>,
        slot: u32,
        burst: u8,
        now_us: u64,
    ) -> Step {
        #[cfg(test)]
        SEND_VISITS.with(|total| total.set(total.get() + 1));
        let Some((id, serve)) = requests.live_serve(slot) else {
            return Step::Idle;
        };
        let pacer = &mut self.pacers[usize::from(serve.peer.0)];
        let Some(next) = candidate_frame(serve) else {
            return Step::Idle;
        };
        // A DATA fragment stages only while every byte of it is retained. The slice borrows the chunks alone, so the pieces stay usable while the body crc reads the zero runs.
        let held = &serve.chunks[..usize::from(serve.held).min(HELD_CHUNKS)];
        let pieces = match next {
            Next::Data { offset, len, .. } => {
                match cover(held, &(offset..offset + u64::from(len))) {
                    Some(pieces) => Some(pieces),
                    None => return Step::Idle,
                }
            }
            _ => None,
        };
        let bytes = wire_bytes(match next {
            Next::Data { len, .. } => u64::from(len),
            Next::Error(_) | Next::Start | Next::Complete => 0,
        });
        if !pacer.ready(now_us) {
            return Step::Paced;
        }
        if !self.shaper.take(now_us, bytes) {
            self.egress_need = bytes;
            return Step::Throttled;
        }
        let (peer, epoch) = (serve.peer, serve.epoch);
        pacer.spend();
        // The hand-over builds the header and borrows the payload from the retained chunks.
        let source = match next {
            Next::Error(status) => {
                serve.error_due = None;
                Source::Error(id, status)
            }
            Next::Start => {
                serve.start_due = false;
                Source::Start(id)
            }
            Next::Complete => {
                serve.complete_due = false;
                Source::Complete(id)
            }
            Next::Data {
                index,
                offset,
                len,
                hole,
            } => {
                let rows = &self.window_crcs[slot as usize * HELD_CHUNKS * self.windows..]
                    [..HELD_CHUNKS * self.windows];
                let (body_crc, digest) = match pieces {
                    Some(pieces) => (
                        body_crc(self.crc, &mut serve.runs, rows, self.windows, &pieces),
                        self.cached_digest(slot, index, &pieces),
                    ),
                    None => (0, None),
                };
                let (prior_next, prior_resend) = (serve.next, serve.resend);
                if hole {
                    serve.holes &= !(1 << (index - serve.base));
                } else if index == serve.next {
                    // A first send after every earlier fragment was acknowledged starts a wait on its receipt, which arms a disarmed retry.
                    let arms = serve.disarmed && serve.start_acked && serve.base == serve.next;
                    serve.next += 1;
                    serve.resend = serve.next;
                    if arms {
                        serve.disarmed = false;
                        let retry_at = serve.retry_from_progress(self.config.retry_us);
                        self.arm(id, retry_at);
                    }
                } else {
                    serve.resend = index + 1;
                }
                Source::Data {
                    id,
                    index,
                    offset,
                    len,
                    prior_next,
                    prior_resend,
                    hole,
                    body_crc,
                    digest,
                }
            }
        };
        self.stage(Staged {
            peer,
            epoch,
            source,
            bytes,
            burst,
        });
        Step::Sent
    }
}

impl<C, F> Requests<C, F> {
    #[inline]
    pub(super) fn get_is_ended(&self, id: RequestId) -> bool {
        self.serve(id).is_none_or(|serve| serve.ended)
    }

    #[cfg(test)]
    pub(super) fn get_retained(&self, id: RequestId) -> usize {
        self.serve(id).map_or(0, |serve| usize::from(serve.held))
    }

    /// The chunks request `id` retains, in payload order.
    #[cfg(test)]
    pub(super) fn get_chunks(&self, id: RequestId) -> impl Iterator<Item = &C> {
        self.serve(id)
            .into_iter()
            .flat_map(|serve| serve.chunks.iter().flatten().map(|held| &held.chunk))
    }

    #[inline]
    pub(super) fn get_granted(&mut self, id: RequestId) {
        if let Some(serve) = self.serve_mut(id) {
            serve.commanded += 1;
        }
    }
}

/// A datagram's bytes on the wire: the link, network and transport headers, the frame header and `payload` bytes.
#[inline(always)]
fn wire_bytes(payload: u64) -> u64 {
    (FRAME_OVERHEAD + HEADER_LEN) as u64 + payload
}

#[cfg(test)]
thread_local! {
    /// Data-round request visits on this thread, so a test can bound a poll's work.
    static SEND_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn take_send_visits() -> usize {
    SEND_VISITS.with(|total| total.replace(0))
}

/// A copy that keeps the staged batch's capacity, the poll's batch bound,
/// so an empty batch keeps the copy's poll budget; a copy whose allocator
/// returned more capacity panics.
#[cfg(test)]
impl Clone for ServeCore {
    fn clone(&self) -> Self {
        let Self {
            config,
            ended_since_scan,
            pacers,
            shaper,
            egress_need,
            replies_first,
            replies,
            reply_heads,
            queued,
            put_results,
            reply_busy,
            reply_cursor,
            cursor,
            open_burst,
            tick_due_us,
            ready,
            ready_count,
            deferred,
            due,
            ended,
            holding,
            holders,
            staged,
            report,
            commands,
            crc,
            window_crcs,
            windows,
            digests,
            digest_valid,
            fragments,
        } = self;
        let mut copy = Vec::with_capacity(staged.capacity());
        copy.extend_from_slice(staged);
        assert_eq!(copy.capacity(), staged.capacity(), "the copy's batch");
        Self {
            config: *config,
            ended_since_scan: *ended_since_scan,
            pacers: pacers.clone(),
            shaper: *shaper,
            egress_need: *egress_need,
            replies_first: *replies_first,
            replies: replies.clone(),
            reply_heads: reply_heads.clone(),
            queued: *queued,
            put_results: *put_results,
            reply_busy: reply_busy.clone(),
            reply_cursor: *reply_cursor,
            cursor: *cursor,
            open_burst: *open_burst,
            tick_due_us: *tick_due_us,
            ready: ready.clone(),
            ready_count: *ready_count,
            deferred: deferred.clone(),
            due: due.clone(),
            ended: ended.clone(),
            holding: holding.clone(),
            holders: *holders,
            staged: copy,
            report: *report,
            commands: *commands,
            crc: *crc,
            window_crcs: window_crcs.clone(),
            windows: *windows,
            digests: digests.clone(),
            digest_valid: digest_valid.clone(),
            fragments: *fragments,
        }
    }
}

/// Every field, the staged batch's capacity included.
#[cfg(test)]
impl std::fmt::Debug for ServeCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            config,
            ended_since_scan,
            pacers,
            shaper,
            egress_need,
            replies_first,
            replies,
            reply_heads,
            queued,
            put_results,
            reply_busy,
            reply_cursor,
            cursor,
            open_burst,
            tick_due_us,
            ready,
            ready_count,
            deferred,
            due,
            ended,
            holding,
            holders,
            staged,
            report,
            commands,
            crc,
            window_crcs,
            windows,
            digests,
            digest_valid,
            fragments,
        } = self;
        f.debug_struct("ServeCore")
            .field("config", config)
            .field("ended_since_scan", ended_since_scan)
            .field("pacers", pacers)
            .field("shaper", shaper)
            .field("egress_need", egress_need)
            .field("replies_first", replies_first)
            .field("replies", replies)
            .field("reply_heads", reply_heads)
            .field("queued", queued)
            .field("put_results", put_results)
            .field("reply_busy", reply_busy)
            .field("reply_cursor", reply_cursor)
            .field("cursor", cursor)
            .field("open_burst", open_burst)
            .field("tick_due_us", tick_due_us)
            .field("ready", ready)
            .field("ready_count", ready_count)
            .field("deferred", deferred)
            .field("due", due)
            .field("ended", ended)
            .field("holding", holding)
            .field("holders", holders)
            .field("staged", staged)
            .field("batch", &staged.capacity())
            .field("report", report)
            .field("commands", commands)
            .field("crc", crc)
            .field("window_crcs", window_crcs)
            .field("windows", windows)
            .field(
                "digests",
                &CachedDigests {
                    digests,
                    digest_valid,
                    fragments: *fragments,
                },
            )
            .field("digest_valid", digest_valid)
            .field("fragments", fragments)
            .finish()
    }
}

#[cfg(test)]
struct CachedDigests<'a> {
    digests: &'a [[u8; DATA_DIGEST_LEN]],
    digest_valid: &'a [u64],
    fragments: usize,
}

#[cfg(test)]
impl std::fmt::Debug for CachedDigests<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = f.debug_list();
        for (row, valid) in self.digest_valid.iter().enumerate() {
            for i in (0..self.fragments).filter(|i| valid & (1 << i) != 0) {
                list.entry(&(row, i, &self.digests[row * self.fragments + i]));
            }
        }
        list.finish()
    }
}

#[cfg(test)]
impl ServeCore {
    /// The byte cost of the frame the shaper refused last, zero when none
    /// waits.
    pub(super) fn egress_need(&self) -> u64 {
        self.egress_need
    }

    /// Makes the next poll stage replies before requests, so a test can plant the order in which replies that fill the batch leave a ready request unstaged.
    pub(super) fn stage_replies_first(&mut self) {
        self.replies_first = true;
    }

    /// Whether `peer`'s pacer holds `datagrams` tokens at `now_us`.
    pub(super) fn paced(&self, peer: PeerId, now_us: u64, datagrams: u32) -> bool {
        let mut pacer = self.pacers[usize::from(peer.0)];
        (0..datagrams).all(|_| pacer.take(now_us))
    }

    /// Checks the indexes that let ticks, releases and data rounds skip requests: every live request with a frame to send has its ready bit set; every unended request's due time is at most its deadline, the retry of any wait on receipt, and, unless disarmed, its retry from its last progress; a waiting request is armed; an ended request's due time is `u64::MAX`; a slot's ended bit is set exactly when its request ended; a free slot carries no bit and a `u64::MAX` due time; the tick bound is at most every due time; the ready and queued-reply counts match their sets; every deferred bit returned to the ready set; every request's chunks fill from the first slot; every request keeping a passed or ended chunk a device reads has its holding bit set; and an ended request keeps a chunk exactly while its holding bit is set.
    pub(super) fn check_indexes<C: Chunk, F>(&self, requests: &Requests<C, F>) {
        let retry_us = self.config.retry_us;
        let bit = |words: &[u64], slot: usize| words[slot / 64] & (1 << (slot % 64)) != 0;
        for slot in 0..requests.table().slots() as usize {
            let (ready, ended, due) = (
                bit(&self.ready, slot),
                bit(&self.ended, slot),
                self.due[slot],
            );
            assert!(self.tick_due_us <= due, "the tick bound covers slot {slot}");
            let Some(serve) = requests
                .table()
                .live_id(slot as u32)
                .and_then(|id| requests.serve(id))
            else {
                assert!(
                    !ready && !ended && due == u64::MAX,
                    "free slot {slot} carries an index"
                );
                continue;
            };
            assert!(
                ready || next_frame(serve).is_none(),
                "slot {slot} has a frame but no ready bit"
            );
            assert_eq!(ended, serve.ended, "slot {slot}'s ended bit");
            assert!(
                serve.holes == 0
                    || serve.base + (u64::BITS - serve.holes.leading_zeros()) <= serve.next,
                "slot {slot} queues a hole at or past its next fragment"
            );
            assert!(
                serve
                    .chunks
                    .windows(2)
                    .all(|pair| pair[1].is_none() || pair[0].is_some()),
                "slot {slot} holds a later chunk with an earlier slot free"
            );
            assert_eq!(
                usize::from(serve.held),
                serve.chunks.iter().flatten().count(),
                "slot {slot}'s held count matches its chunks"
            );
            let horizon = serve.horizon();
            let holds = serve
                .chunks
                .iter()
                .flatten()
                .any(|held| held.range.end <= horizon && held.chunk.device_held());
            assert!(
                !holds || bit(&self.holding, slot),
                "slot {slot} holds a device-read chunk without its holding bit"
            );
            if serve.ended {
                assert_eq!(
                    serve.chunks.iter().any(Option::is_some),
                    bit(&self.holding, slot),
                    "ended slot {slot} keeps a chunk exactly while its holding bit is set"
                );
                assert_eq!(due, u64::MAX, "ended slot {slot} has no due time");
                continue;
            }
            let mut bound = serve.deadline_us;
            if let Some(at) = serve.retry_at(retry_us) {
                assert!(!serve.disarmed, "slot {slot} waits while disarmed");
                bound = bound.min(at);
            } else if !serve.disarmed {
                bound = bound.min(serve.retry_from_progress(retry_us));
            }
            assert!(due <= bound, "slot {slot}'s due time bounds its timers");
        }
        let ready: u32 = self.ready.iter().map(|word| word.count_ones()).sum();
        assert_eq!(self.ready_count, ready, "the ready count matches the set");
        let holders: u32 = self.holding.iter().map(|word| word.count_ones()).sum();
        assert_eq!(self.holders, holders, "the holder count matches the set");
        assert!(
            self.deferred.iter().all(|&word| word == 0),
            "a poll returns its deferred bits"
        );
        let queued: u32 = self.reply_heads.iter().map(|&(_, len)| len).sum();
        assert_eq!(self.queued, queued, "the queued count matches the rings");
        let results = self.replies.iter().flatten().filter(|reply| reply.first);
        assert_eq!(
            self.put_results as usize,
            results.count(),
            "the first PUT RESULT count matches the rings"
        );
        for (peer, &(_, len)) in self.reply_heads.iter().enumerate() {
            let busy = self.reply_busy[peer / 64] & (1 << (peer % 64)) != 0;
            assert_eq!(busy, len > 0, "peer {peer}'s busy bit matches its ring");
        }
    }
}

enum Step {
    Sent,
    /// The slot holds no live request or its request has no frame to send, or the peer has no reply queued.
    Idle,
    /// The peer is out of pacing tokens.
    Paced,
    /// The core's shaper holds fewer than the frame's bytes, plus the bytes reserved for a waiting request when a reply asks; its round stops for the poll, and the next poll's round starts at this source.
    Throttled,
    /// A reply round's ring passed an emptied entry.
    Passed,
}

/// `frame` builds the header from `staged.source` and borrows DATA payloads from the request's retained chunks. Missing chunks produce an empty payload, which encoding rejects; a source whose request left the table yields a header of its kind with a zero request and key.
/// Always inlined, so the hand-over iterator's `next` builds each `Out` without a further call and copy.
#[inline(always)]
fn frame<'c, 'a, C: Retained<'a>, F>(
    requests: &'c Requests<C, F>,
    replies: &[Option<Reply>],
    staged: &Staged,
) -> Out<'c, 'a> {
    let empty = [Payload::EMPTY; MAX_PAYLOAD_SLICES];
    let bound = |id: RequestId| {
        requests
            .serve(id)
            .and_then(|serve| serve.manifest.map(|manifest| (serve, manifest)))
    };
    let (header, payload, body_crc, digest) = match staged.source {
        Source::Reply(at) => {
            let Some(reply) = replies.get(at as usize).copied().flatten() else {
                debug_assert!(
                    false,
                    "a staged reply's ring entry holds it until it settles"
                );
                return Out {
                    peer: staged.peer,
                    epoch: staged.epoch,
                    header: header(Kind::Error, 0, [0; 32]),
                    payload: empty,
                    body_crc: 0,
                    digest: None,
                };
            };
            let header = match reply.terminal {
                Terminal::Complete(manifest) => Header {
                    index: manifest.count(),
                    ..manifest_header(Kind::Complete, reply.request, reply.key, &manifest)
                },
                Terminal::Error(status) => Header {
                    status: status as u16,
                    ..header(Kind::Error, reply.request, reply.key)
                },
                Terminal::Put(put) => Header {
                    grant: put.grant,
                    status: put.status,
                    index: put.index,
                    offset: put.offset,
                    ..manifest_header(put.kind, reply.request, reply.key, &put.manifest)
                },
                Terminal::Invalidated(low, high) => Header {
                    allocation: low,
                    offset: high,
                    ..header(Kind::Invalidated, reply.request, reply.key)
                },
            };
            (header, empty, 0, None)
        }
        Source::Error(id, status) => {
            let (request, key) = requests
                .serve(id)
                .map_or((0, [0; 32]), |serve| (serve.request, serve.fingerprint.key));
            let header = Header {
                status: status as u16,
                ..header(Kind::Error, request, key)
            };
            (header, empty, 0, None)
        }
        Source::Start(id) => {
            let header = bound(id).map_or_else(
                || header(Kind::Start, 0, [0; 32]),
                |(serve, manifest)| {
                    manifest_header(Kind::Start, serve.request, serve.fingerprint.key, &manifest)
                },
            );
            (header, empty, 0, None)
        }
        Source::Complete(id) => {
            let header = bound(id).map_or_else(
                || header(Kind::Complete, 0, [0; 32]),
                |(serve, manifest)| Header {
                    index: manifest.count(),
                    ..manifest_header(
                        Kind::Complete,
                        serve.request,
                        serve.fingerprint.key,
                        &manifest,
                    )
                },
            );
            (header, empty, 0, None)
        }
        Source::Data {
            id,
            index,
            offset,
            len,
            body_crc,
            digest,
            ..
        } => match bound(id) {
            Some((serve, manifest)) => {
                let header = Header {
                    index,
                    offset,
                    datagram_len: len,
                    ..manifest_header(Kind::Data, serve.request, serve.fingerprint.key, &manifest)
                };
                // Staging took `offset` and `len` from the fragment's geometry under this manifest.
                let range = offset..offset + u64::from(len);
                match pieces(serve.held_chunks(), &range) {
                    Some(payload) => (header, payload, body_crc, digest),
                    None => (header, empty, 0, None),
                }
            }
            None => (header(Kind::Data, 0, [0; 32]), empty, 0, None),
        },
    };
    Out {
        peer: staged.peer,
        epoch: staged.epoch,
        header,
        payload,
        body_crc,
        digest,
    }
}

/// Derives the CRC32C of the fragment `pieces` locate across a request's retained chunks using checksum rows in `rows` and the request's zero runs.
#[inline(always)]
fn body_crc<C: Chunk>(
    crc: Crc32c,
    runs: &mut ZeroRuns,
    rows: &[u32],
    windows: usize,
    pieces: &[Piece<'_, C>; MAX_PAYLOAD_SLICES],
) -> u32 {
    let mut pieces = pieces.iter().flatten();
    let Some((held, within)) = pieces.next() else {
        return 0;
    };
    let row = |held: &Held<C>| &rows[usize::from(held.row) * windows..][..windows];
    let mut body = held.chunk.crc(crc, runs, row(held), within.clone());
    for (held, within) in pieces {
        let len = (within.end - within.start) as u64;
        body = crc.combine(
            body,
            &runs.run(crc, len),
            held.chunk.crc(crc, runs, row(held), within.clone()),
        );
    }
    body
}

/// Whether an ACK names `manifest` and `key`.
fn matches_manifest(header: &Header, manifest: &Manifest, key: &[u8; 32]) -> bool {
    header.allocation == manifest.allocation
        && header.metadata_len == manifest.metadata_len
        && header.body_len == manifest.body_len
        && header.total == manifest.total()
        && header.count == manifest.count()
        && header.key == *key
}

pub(super) fn header(kind: Kind, request: u64, key: [u8; 32]) -> Header {
    Header {
        kind,
        principal: 0,
        key_epoch: 0,
        owner_nonce: [0; 16],
        client_nonce: [0; 16],
        request,
        sequence: 0,
        allocation: 0,
        total: 0,
        metadata_len: 0,
        body_len: 0,
        index: 0,
        count: 0,
        offset: 0,
        datagram_len: 0,
        grant: 0,
        status: 0,
        remaining_ms: 0,
        key,
        epoch: 0,
        tag: [0; 16],
    }
}

pub(super) fn manifest_header(
    kind: Kind,
    request: u64,
    key: [u8; 32],
    manifest: &Manifest,
) -> Header {
    Header {
        allocation: manifest.allocation,
        total: manifest.total(),
        metadata_len: manifest.metadata_len,
        body_len: manifest.body_len,
        count: manifest.count(),
        ..header(kind, request, key)
    }
}

/// The frame a request sends next; a DATA fragment's payload is taken from the retained chunks when the batch is handed over.
#[derive(Clone, Copy)]
enum Next {
    Error(Status),
    Start,
    Complete,
    Data {
        index: u32,
        offset: u64,
        len: u32,
        /// The fragment comes from a hole round.
        hole: bool,
    },
}

fn unbind_sent<C, F>(requests: &mut Requests<C, F>, id: RequestId) {
    if let Some(serve) = requests.serve(id) {
        debug_assert!(serve.ended, "a sent terminal belongs to an ended request");
        if serve.ended {
            let (peer, wire) = (serve.peer, RequestId::from_wire(serve.request));
            requests.unbind(peer, wire.slot(), id);
        }
    }
}

/// The frame request `serve` sends next: an ERROR, then START, then COMPLETE, then the next DATA fragment: the lowest queued hole, else the retransmission round's next, else the first send the grant admits. The caller stages a DATA fragment only once [`cover`] finds its bytes retained.
#[inline(always)]
fn candidate_frame<C: AsRef<[u8]>>(serve: &Serve<C>) -> Option<Next> {
    if let Some(status) = serve.error_due {
        return Some(Next::Error(status));
    }
    if serve.ended {
        return None;
    }
    let manifest = serve.manifest?;
    if serve.start_due {
        return Some(Next::Start);
    }
    if serve.complete_due {
        return Some(Next::Complete);
    }
    let hole = serve.holes != 0;
    let index = if hole {
        serve.base + serve.holes.trailing_zeros()
    } else if serve.resend < serve.next {
        serve.resend.max(serve.base)
    } else {
        serve.next
    };
    if index >= manifest.count() || (index == serve.next && index >= serve.granted) {
        return None;
    }
    let range = FragmentGeometry::fragment(index, manifest.total());
    Some(Next::Data {
        index,
        offset: range.start,
        len: (range.end - range.start) as u32,
        hole,
    })
}

/// The next frame `serve` sends: its candidate frame, a DATA fragment only while its bytes are retained.
#[cfg(test)]
fn next_frame<C: AsRef<[u8]>>(serve: &Serve<C>) -> Option<Next> {
    let next = candidate_frame(serve)?;
    if let Next::Data { offset, len, .. } = next {
        cover(serve.held_chunks(), &(offset..offset + u64::from(len)))?;
    }
    Some(next)
}

/// The queued holes after the base advanced by `by` fragments: bit `i` moves to `i - by`, and the bits the base passed drop.
#[inline(always)]
fn shift_holes(holes: u64, by: u32) -> u64 {
    if by >= u64::BITS { 0 } else { holes >> by }
}

/// The holes a receipt `mask` leaves among the `span` fragments from the base up to the highest held one, bit `i` for the fragment `i` above the base: the base itself and every fragment below the highest whose mask bit is clear.
#[inline(always)]
fn holes_below(mask: u64, span: u32) -> u64 {
    let span = span.min(u64::BITS);
    let within = if span == u64::BITS {
        u64::MAX
    } else {
        (1u64 << span) - 1
    };
    !(mask << 1) & within
}

/// The pieces of retained `chunks` that hold payload bytes `range`, in order, each a transmit source when its chunk can be one, or `None` while any byte is not retained.
#[inline(always)]
fn pieces<'c, 'a, C: Retained<'a>>(
    chunks: &'c [Option<Held<C>>],
    range: &Range<u64>,
) -> Option<[Payload<'c, 'a>; MAX_PAYLOAD_SLICES]> {
    let mut out = [Payload::EMPTY; MAX_PAYLOAD_SLICES];
    for (piece, (held, within)) in out
        .iter_mut()
        .zip(cover(chunks, range)?.into_iter().flatten())
    {
        *piece = match held.chunk.source(within.clone()) {
            Some(source) => Payload::Retained(source),
            None => Payload::Inline(&held.chunk.as_ref()[within]),
        };
    }
    Some(out)
}

/// One piece of a fragment: the retained chunk holding it and the range of the chunk's bytes it covers.
type Piece<'c, C> = Option<(&'c Held<C>, Range<usize>)>;

/// The retained chunks that hold payload bytes `range`, in order, or `None` while any byte is not retained.
/// `chunks` is the request's held prefix: the slots compact, so every slot in it holds a chunk.
#[inline(always)]
fn cover<'c, C>(
    chunks: &'c [Option<Held<C>>],
    range: &Range<u64>,
) -> Option<[Piece<'c, C>; MAX_PAYLOAD_SLICES]> {
    let mut out = [None, None];
    let mut at = range.start;
    let mut used = 0;
    for held in chunks.iter().flatten() {
        if at >= range.end || held.range.end <= at || held.range.start > at {
            continue;
        }
        let end = range.end.min(held.range.end);
        *out.get_mut(used)? = Some((
            held,
            (at - held.range.start) as usize..(end - held.range.start) as usize,
        ));
        used += 1;
        at = end;
    }
    (at == range.end).then_some(out)
}

/// The first slot at or above `from` whose due time in `due` is at or before `now_us`.
pub(super) fn next_due(due: &[u64], from: usize, now_us: u64) -> Option<usize> {
    let rest = due.get(from..)?;
    let (groups, tail) = rest.as_chunks::<8>();
    for (n, group) in groups.iter().enumerate() {
        // Eight slots are tested together so the compares can vectorize.
        if group.iter().fold(false, |any, &at| any | (at <= now_us)) {
            let at = group.iter().position(|&at| at <= now_us)?;
            return Some(from + n * 8 + at);
        }
    }
    let at = tail.iter().position(|&at| at <= now_us)?;
    Some(from + groups.len() * 8 + at)
}

/// The first set bit at or after bit `from` in `words`, wrapping once to the bits before it; `from` is below the bit count, and bits at or past the count stay clear.
#[inline]
pub(super) fn next_set_wrapping(words: &[u64], from: u32) -> Option<u32> {
    if let [word] = words {
        // Rotating `from` to bit 0 orders the bits from `from` on before those below it.
        let bits = word.rotate_right(from);
        return (bits != 0).then(|| (from + bits.trailing_zeros()) % 64);
    }
    next_set(words, from).or_else(|| next_set(words, 0))
}

/// The first bit at or above bit `from` that is set in `words` and clear in `mask`; `mask` holds at least as many words as `words`.
fn next_clear_of(words: &[u64], mask: &[u64], from: u32) -> Option<u32> {
    let start = from as usize / 64;
    let first = words.get(start)? & !mask[start] & (u64::MAX << (from % 64));
    if first != 0 {
        return Some((start * 64) as u32 + first.trailing_zeros());
    }
    let (n, word) = words[start + 1..]
        .iter()
        .zip(&mask[start + 1..])
        .map(|(word, mask)| word & !mask)
        .enumerate()
        .find(|(_, word)| *word != 0)?;
    Some(((start + 1 + n) * 64) as u32 + word.trailing_zeros())
}

#[cfg(test)]
#[path = "serve_chunk_tests.rs"]
mod chunk_tests;
