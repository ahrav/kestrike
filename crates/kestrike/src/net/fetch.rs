//! The client's receive core: one GET per request, fragments received into a bounded window and handed to the application in order as fragment leases, cumulative receipt ACKs, a grant that grows only on application release, and one explicit outcome.
//!
//! Invariants owned by this module:
//!
//! - A request's window holds at most `window` fragments, received or handed out and not yet released; a fragment is accepted only when its index lies at or above the receipt base and below the cumulative grant, so the grant counts every slot the request can fill.
//! - A request reserves its initial grant's receive boxes from the core's `boxes` when it starts and returns them when it closes; leases the application still holds from a closed request stay reserved until dropped, so every granted fragment has a box, given a pool sized as [`FetchConfig::boxes`] requires.
//! - [`ClientRequests`] issues each request's wire ID. A received frame reaches a request only when its wire ID, peer and operation match the request's, and the request acts on it only when its session epoch and key match too.
//! - The cumulative grant starts at the request's initial grant and grows by one for each fragment lease the application drops, counted by [`Releases`]; receipt, duplicates, replays and stale frames add nothing.
//! - DATA that arrives before a matching START is held without exposure or acknowledgement; START binds the manifest, and a held or later fragment naming another manifest is dropped; [`parse`](super::parse) already matched each fragment's index, offset and length to the manifest it names.
//! - The receipt base is the count of contiguous fragments received under the bound manifest, and every ACK names it; only fragments below the base are handed to the application, in order.
//! - Success requires START, every DATA fragment and COMPLETE. An ERROR, a deadline, a cancel or exhausted retries after any fragment was handed out ends the request `Incomplete`; before that, the status decides between miss, pressure and failure. A failed request returns its untaken fragments to their pool when it ends.
//! - A fragment held above the base means the base's fragment is missing, and the request is in a gap. A gap that outlasts [`GAP_WAIT_US`] queues a gap ACK carrying the receipt mask of the fragments held above the base, and one more after each further [`GAP_ACK_US`], outside the retry count; every other ACK carries an empty mask. Fragments the network reorders within the wait fill their gap before any ACK names it, a lost fragment is named within the wait and filled a round trip later, and the deadline and the retry count bound a gap the owner never fills.
//! - GET retries before START and ACK retries after it run on an interval that starts at `retry_us` and doubles with each retry the count holds, up to [`RETRY_DOUBLINGS`](super::RETRY_DOUBLINGS) times, from a clock that restarts on each retry, on START, on a grant advance and on each DATA fragment the window holds, and a finite count, each GET carrying the request's immutable fingerprint and the remaining duration; the count restarts when START binds the manifest or the receipt base or the grant advances, and pauses while every granted fragment has arrived and awaits the application's release, and a resent fragment below the base queues the ACK again.
//! - Application releases raise the grant the next ACK carries. The request tracks the owner's burst, the most fragments received beyond the last acknowledged base; a grant-only ACK becomes due when the grant exceeds the advertised one, fragments remain owed and the advertised grant admits at most a burst beyond the highest fragment received, whether the release or the fragment that ran the credit low came last, so an owner at its credit limit learns of released credit at once, while one held by its own buffers reads the grant from its next receipt ACK.
//! - Each table slot carries its request's timer: the deadline while every granted fragment awaits the application's release, otherwise the earlier of the deadline and the retry; a free slot or a decided request carries none. Every change to a request's progress, retry count, grant, base, manifest or outcome rewrites its timer, so `deadline`, the earliest timer `tick` acts on, is the least timer, and `tick` visits only the slots whose timer has come. `due` holds exactly when the next `poll` sends a frame; a request with a frame to send is marked by the core, or by the release board when the frame carries released credit, so `due` reads only the marked slots. `cancel_all` and `end_session` end every undecided request they cover, and `unsend` puts back a frame the transport refused so it stays due.
//! - A fragment's window entry follows from the base's entry by one offset and one conditional subtraction. `tick` returns at once before the timers' floor, which is at most the least timer: a lower timer becomes the floor, raising the timer at the floor recomputes the bounds on its path, at once for the first raise after a read and at the next `deadline` otherwise, and a scan folds once after its retries. `poll` goes round robin from its cursor, visiting only the slots the core marks as having a frame to send and the slots the release board marks as having a release to fold. It hands the GET frames of one poll to `send` with no other frame between them: the slot of an ACK or CANCEL it selects after a GET waits until the scan ends, and its frame, of the kind selected, is built then. A lease that `send` releases for a waiting request marks its slot on the release board, and the scan folds that release when it reaches the slot again, so a waiting ACK carries the raised grant. Each visit clears the core's mark of its slot, so a slot that reaches a visit with that mark clear and with a CANCEL or an ACK already due is a waiting one, and it keeps its one place. A request's GET is selected ahead of its ACK and never after its CANCEL, so each request's frames reach `send` in the order of their selection.

use std::cell::Cell;

use crate::storage::{EngineBudget, EngineBudgetExceeded};

use super::client_namespace::{ClientRequest, ClientRequests, IdentityPressure};
use super::datagram::{HEADER_LEN, MAX_PACKED_GETS, PeerId};
use super::frame::{Header, Kind, MAX_WINDOW, Status, retry_wait};
use super::geometry::FRAGMENT_LEN;
use super::namespace::Operation;
use super::packet::PacketLease;
use super::requests::{GENERATION_LIMIT, RequestId};
use super::serve::{Manifest, header, manifest_header};
use super::session::Admitted;
use super::slot_index::{Marks, Timers};

/// Microseconds a gap stands before the request names it in a gap ACK: long enough for fragments the network reorders to arrive, so an ACK names only holes that outlasted the reordering, and short against the retry interval.
pub const GAP_WAIT_US: u64 = 500;

/// Microseconds a gap may stand after a gap ACK before the request queues another, so a lost gap ACK or a lost resend costs about this long rather than a retry interval.
pub const GAP_ACK_US: u64 = 1_000;

/// Timing of the client's retries and its window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchConfig {
    /// Microseconds before the first GET retry before START, or ACK retry after it; each retry since the last progress doubles the wait, up to [`RETRY_DOUBLINGS`](super::RETRY_DOUBLINGS) times.
    pub retry_us: u64,
    /// Retries before a silent request ends.
    pub attempts: u32,
    /// Fragments each request's window holds: the receive slots charged per request, clamped to `1..=4096`.
    pub window: u32,
    /// Data boxes the core may promise: each live request reserves its initial grant, and leases the application still holds from closed requests stay counted until dropped. The caller sizes the receive pool's data cap at least `boxes` and dedicates its data boxes to this core; under that condition every granted fragment has a box.
    pub boxes: u32,
}

/// Why a core could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchCoreError {
    Budget(EngineBudgetExceeded),
    /// The release board numbers `board` slots and the request table `slots`.
    Board {
        slots: u32,
        board: u32,
    },
    /// The release board serves one live [`ClientNamespace`](super::ClientNamespace) at a time.
    BoardInUse,
    /// `boxes` holds fewer than one configured window, so a request granted the full window could never start.
    Boxes,
    /// The namespace already serves a core for the operation.
    Paired,
    /// An upload core was given more than the 65,536 source slots a frame's `u16` slot index names.
    Sources {
        count: usize,
    },
}

/// `FetchLimits` specifies byte caps and a deadline interval for one GET.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchLimits {
    pub metadata_cap: u32,
    pub body_cap: u32,
    /// `wait_us` sets the request's deadline to `now_us + wait_us`.
    pub wait_us: u64,
    /// When the caller intended the request to arrive, kept for its terminal observation.
    pub intended_us: u64,
}

/// Why a fetch was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchPressure {
    /// The request namespace refused the request.
    Identity(IdentityPressure),
    /// The receive pool's promised boxes leave too few for the request's initial grant.
    Receive,
}

/// How a request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// START, every DATA fragment and COMPLETE arrived.
    Complete,
    /// The owner holds no live object for the key.
    Missing,
    /// The owner refused under pressure of this kind.
    Pressure(Status),
    /// The request failed before any byte was handed out.
    Failed(Status),
    /// The request failed after bytes were handed out; they are a prefix of one version and must not be spliced with another.
    Incomplete(Status),
}

impl Outcome {
    pub(super) fn of(status: Status, exposed: bool) -> Self {
        match status {
            _ if exposed => Self::Incomplete(status),
            Status::Missing | Status::Expired => Self::Missing,
            Status::Contended
            | Status::LeasePressure
            | Status::ObjectPressure
            | Status::ReceivePressure
            | Status::RequestPressure
            | Status::RetransmissionPressure
            | Status::StoragePressure
            | Status::ReadOpsPressure => Self::Pressure(status),
            _ => Self::Failed(status),
        }
    }
}

/// The board tracks fragment-lease releases by request slot and generation and preserves the wire-generation sequence across [`ClientRequests`] instances. Independent storage lets leases outlive polling, close and the client.
pub struct Releases {
    /// Each slot's live generation and the leases of it the application released; a closed slot holds [`CLOSED`].
    counts: Box<[Cell<(u64, u32)>]>,
    /// The slots where a release credited the live request since the core's `poll` last visited the slot; `poll` folds a slot's releases only when the slot is marked.
    marks: Marks,
    /// Leases of closed requests the application still holds.
    orphans: Cell<u32>,
    /// The board assigns each [`ClientRequests`] a successive `core` number because table handle generations restart with each [`ClientRequests`].
    core: Cell<u64>,
    /// A live [`ClientRequests`] uses the board.
    in_use: Cell<bool>,
    /// The generation the next request's wire ID carries.
    next_wire: Cell<u64>,
    /// The last generation a wire ID carries.
    last_wire: u64,
}

/// The generation a closed slot records, which no request carries.
const CLOSED: u64 = u64::MAX;

impl Releases {
    /// Bytes a board of `slots` request slots charges: each slot's count and its mark bit.
    pub fn charge(slots: u32) -> usize {
        slots as usize * size_of::<Cell<(u64, u32)>>() + Marks::charge(slots)
    }

    /// A board for `slots` request slots issuing wire generations below [`GENERATION_LIMIT`], charging [`charge`](Self::charge) bytes.
    ///
    /// # Errors
    ///
    /// `EngineBudgetExceeded` with `budget` unchanged.
    pub fn new(slots: u32, budget: &mut EngineBudget) -> Result<Self, EngineBudgetExceeded> {
        Self::with_generation_limit(slots, GENERATION_LIMIT - 1, budget)
    }

    /// [`new`](Self::new) issuing wire generations up to `last_wire`.
    pub(super) fn with_generation_limit(
        slots: u32,
        last_wire: u64,
        budget: &mut EngineBudget,
    ) -> Result<Self, EngineBudgetExceeded> {
        budget.charge(Self::charge(slots))?;
        Ok(Self {
            counts: (0..slots).map(|_| Cell::new((CLOSED, 0))).collect(),
            marks: Marks::new(slots),
            orphans: Cell::new(0),
            core: Cell::new(0),
            in_use: Cell::new(false),
            next_wire: Cell::new(0),
            last_wire,
        })
    }

    /// Sets the generation the next admitted request's wire ID carries, at most the board's last, so a test reaches the last wire generation at its actual width.
    #[cfg(test)]
    pub(super) fn start_wire_at(&self, next: u64) {
        assert!(!self.in_use.get(), "a request namespace uses the board");
        assert!(
            (self.next_wire.get()..=self.last_wire).contains(&next),
            "generation {next} rewinds the board or passes its last"
        );
        self.next_wire.set(next);
    }

    pub(super) fn check(&self, slots: u32) -> Result<(), FetchCoreError> {
        if self.in_use.get() {
            return Err(FetchCoreError::BoardInUse);
        }
        let board = self.counts.len() as u32;
        if board < slots {
            return Err(FetchCoreError::Board { slots, board });
        }
        Ok(())
    }

    pub(super) fn attach(&self) {
        self.core.set(self.core.get() + 1);
        self.in_use.set(true);
        self.marks.clear();
    }

    pub(super) fn detach(&self) {
        self.in_use.set(false);
    }

    /// The number of the [`ClientRequests`] attached now, which a core records to pair with it.
    pub(super) fn board(&self) -> u64 {
        self.core.get()
    }

    /// The generation the next admitted request's wire ID carries, or `None` once the last one is issued.
    pub(super) fn next_generation(&self) -> Option<u64> {
        Some(self.next_wire.get()).filter(|&next| next <= self.last_wire)
    }

    /// Records the admission of request `id` under wire generation `generation`, which [`next_generation`](Self::next_generation) returned.
    pub(super) fn issue(&self, generation: u64, id: RequestId) {
        self.next_wire.set(generation + 1);
        self.reset(id);
    }

    fn reset(&self, id: RequestId) {
        if let Some(cell) = self.counts.get(usize::from(id.slot())) {
            cell.set((id.generation(), 0));
        }
    }

    /// The board counts releases of leases for request `id` issued under `core` and marks the slot until the fetch core's `poll` next visits it. A lease release for a closed request or an earlier `core` frees one orphan.
    #[inline]
    fn release(&self, core: u64, id: RequestId) {
        let Some(cell) = self.counts.get(usize::from(id.slot())) else {
            return;
        };
        let (generation, count) = cell.get();
        if core == self.core.get() && generation == id.generation() {
            cell.set((generation, count + 1));
            self.marks.set(id.slot());
        } else {
            debug_assert!(
                self.orphans.get() > 0,
                "every unmatched release has an orphan"
            );
            self.orphans.set(self.orphans.get().saturating_sub(1));
        }
    }

    /// Closes request `id`, `handed` of whose fragments the application took: the leases it still holds become orphans.
    pub(super) fn close(&self, id: RequestId, handed: u32) {
        let held = handed.saturating_sub(self.released(id));
        self.orphans.set(self.orphans.get() + held);
        if let Some(cell) = self.counts.get(usize::from(id.slot())) {
            cell.set((CLOSED, 0));
        }
    }

    fn released(&self, id: RequestId) -> u32 {
        self.counts
            .get(usize::from(id.slot()))
            .map(Cell::get)
            .filter(|(generation, _)| *generation == id.generation())
            .map_or(0, |(_, count)| count)
    }
}

/// One fragment handed to the application: the received datagram's box, its place in the object and the request it belongs to.
///
/// Dropping the lease returns the box to its pool; while its request is live under the core that handed it out, the drop grants that request one more receive slot, and otherwise it frees the box the board reserved for it. The lease stays valid after the request ends or its core closes.
pub struct FragmentLease<'p> {
    lease: PacketLease<'p>,
    releases: &'p Releases,
    core: u64,
    /// The request's table handle, packed by [`RequestId::wire`].
    request: u64,
    manifest: Manifest,
    index: u32,
}

impl FragmentLease<'_> {
    /// The fragment's payload bytes.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.lease.bytes()[HEADER_LEN..]
    }

    /// The payload offset of the fragment's first byte.
    #[inline]
    pub fn offset(&self) -> u64 {
        u64::from(self.index) * u64::from(FRAGMENT_LEN)
    }

    #[inline]
    pub fn index(&self) -> u32 {
        self.index
    }

    #[inline]
    pub fn manifest(&self) -> Manifest {
        self.manifest
    }
}

impl Drop for FragmentLease<'_> {
    #[inline]
    fn drop(&mut self) {
        self.releases
            .release(self.core, RequestId::from_wire(self.request));
    }
}

impl std::fmt::Debug for FragmentLease<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FragmentLease")
            .field("request", &RequestId::from_wire(self.request))
            .field("index", &self.index)
            .field("offset", &self.offset())
            .finish()
    }
}

/// A frame the client sends: its header's request fields, the session epoch it is bound to and the request-table slot of its request.
/// The caller fills the principal, key epoch, boot nonces and sequence, then tags it.
#[derive(Debug, Clone, Copy)]
pub struct Ask {
    pub peer: PeerId,
    /// The request-table slot of the request [`FetchCore::poll`] built the frame from.
    pub slot: u16,
    pub epoch: u64,
    pub header: Header,
}

/// The fields of an [`Ask`] that [`FetchCore::unsend`] needs to put it back, and [`FetchCore::taken`] to find its request: its request-table slot, wire request ID, kind, CANCEL status and whether an ACK carried a receipt mask.
#[derive(Debug, Clone, Copy)]
pub(super) struct Asked {
    slot: u16,
    request: u64,
    kind: Kind,
    status: u16,
    mask: bool,
}

impl Asked {
    /// The live GET this frame was handed out for: the request in the frame's table slot, while that request carries the frame's wire request ID, which names one request for the life of the namespace's release board. A slot that was released since the hand-out, or that another request took, yields `None`, as [`ClientRequests::route`] does for the frame's wire request ID. The frame comes from [`FetchCore::poll`] over `requests`.
    #[inline]
    fn fetch_mut<'r>(&self, requests: &'r mut ClientRequests<'_>) -> Option<&'r mut Fetch> {
        let (_, fetch) = requests.live_fetch_mut(u32::from(self.slot))?;
        (fetch.wire == self.request).then_some(fetch)
    }
}

impl From<&Ask> for Asked {
    fn from(ask: &Ask) -> Self {
        Self {
            slot: ask.slot,
            request: ask.header.request,
            kind: ask.header.kind,
            status: ask.header.status,
            mask: ask.header.kind == Kind::Ack && ask.header.offset != 0,
        }
    }
}

/// One request being fetched.
pub struct Fetch {
    peer: PeerId,
    epoch: u64,
    /// The request ID this request's frames carry.
    wire: u64,
    key: [u8; 32],
    metadata_cap: u32,
    body_cap: u32,
    initial: u32,
    deadline_us: u64,
    manifest: Option<Manifest>,
    base: u32,
    /// The window entry of fragment `base`: `base % window`.
    base_at: u32,
    /// Fragments handed to the application.
    handed: u32,
    /// Fragments placed in the window and not dropped from it; `filled - handed` of them are held.
    filled: u32,
    granted: u32,
    /// The grant the last GET or ACK sent carried, which limits the owner to fragment indices below it until a later ACK raises the grant.
    advertised: u32,
    /// The base the last ACK sent carried, zero until one goes out.
    acked_base: u32,
    /// One past the highest fragment index accepted into the window.
    seen_to: u32,
    /// The most fragments received beyond the base the owner last learned, a lower bound on how far the owner sends ahead of an ACK.
    burst: u32,
    outcome: Option<Outcome>,
    get_due: bool,
    ack_due: bool,
    cancel_due: Option<Status>,
    progress_us: u64,
    attempts: u32,
    /// When the current gap opened, or when its last gap ACK was queued; `None` outside a gap.
    gap_us: Option<u64>,
    /// A gap ACK went out for the current gap, so the next one waits [`GAP_ACK_US`] rather than [`GAP_WAIT_US`].
    gap_reported: bool,
    /// The next ACK carries the receipt mask.
    gap_ack_due: bool,
    /// When the caller intended the request to arrive, which precedes its admission when the caller lagged.
    intended_us: u64,
    /// The `now_us` of the request's admission, held until [`FetchCore::taken`] times the request's first taken GET
    /// frame from it. It is part of every request-table entry, so it counts in
    /// [`RequestTable::metadata_bytes`](super::requests::RequestTable::metadata_bytes).
    admitted_us: Option<u64>,
    /// The time of the client's latest turn or admission when the outcome was decided, and who decided it;
    /// [`decide`](Self::decide) sets both with the outcome, so they hold their initial 0 and `Owner` while
    /// `outcome` is `None`.
    decided_us: u64,
    decided_by: Decider,
}

impl Fetch {
    fn decide(&mut self, outcome: Outcome, by: Decider, now_us: u64) {
        self.outcome = Some(outcome);
        self.decided_us = now_us;
        self.decided_by = by;
    }

    /// Whether the client holds a fragment above the base, so the base's fragment is missing.
    fn in_gap(&self) -> bool {
        self.manifest.is_some() && self.outcome.is_none() && self.base < self.seen_to
    }

    /// Opens the gap at `now_us` when the request is in one and none is open, and closes an open gap once the base caught up with every held fragment.
    fn track_gap(&mut self, now_us: u64) {
        if self.in_gap() {
            if self.gap_us.is_none() {
                self.gap_us = Some(now_us);
            }
        } else if self.gap_us.is_some() {
            self.gap_us = None;
            self.gap_reported = false;
            self.gap_ack_due = false;
        }
    }

    /// When the current gap next queues a gap ACK, or `None` outside a gap.
    fn gap_due(&self) -> Option<u64> {
        let wait = if self.gap_reported {
            GAP_ACK_US
        } else {
            GAP_WAIT_US
        };
        self.gap_us
            .filter(|_| self.in_gap())
            .map(|since| since.saturating_add(wait))
    }

    /// Whether a frame under `session` names this request: it repeats the wire ID, peer, session epoch and key.
    fn names(&self, session: Admitted, header: &Header) -> bool {
        self.wire == header.request
            && self.peer == session.peer
            && self.epoch == session.epoch
            && self.key == header.key
    }

    pub(super) fn peer(&self) -> PeerId {
        self.peer
    }

    pub(super) fn wire(&self) -> u64 {
        self.wire
    }

    pub(super) fn handed(&self) -> u32 {
        self.handed
    }

    /// Fragments of the bound manifest are still owed.
    fn owed(&self) -> bool {
        self.manifest
            .is_some_and(|manifest| self.base < manifest.count())
    }

    /// Every granted fragment arrived and awaits the application's release.
    fn held_back(&self) -> bool {
        self.owed() && self.base == self.granted
    }

    /// The cumulative grant after `released` application releases.
    fn grant(&self, released: u32) -> u32 {
        self.initial + released
    }

    /// The advertised grant admits at most one burst beyond the highest fragment received, so the owner's next burst can reach its credit limit.
    fn credit_low(&self) -> bool {
        self.advertised.saturating_sub(self.seen_to) <= self.burst
    }

    /// The time [`FetchCore::tick`] next acts on an undecided request: its deadline while every granted fragment awaits the application's release, and otherwise the earliest of its deadline, its retry and its next gap ACK.
    fn timer(&self, retry_us: u64) -> u64 {
        let timer = if self.held_back() {
            self.deadline_us
        } else {
            self.deadline_us.min(self.retry_from_progress(retry_us))
        };
        self.gap_due().map_or(timer, |due| timer.min(due))
    }

    /// The request's next retry time from its last progress: `retry_us` doubled once for each retry since then, up to [`RETRY_DOUBLINGS`](super::RETRY_DOUBLINGS) times.
    fn retry_from_progress(&self, retry_us: u64) -> u64 {
        self.progress_us
            .saturating_add(retry_wait(retry_us, self.attempts))
    }

    /// Whether DATA `header`, naming `manifest`, lies in this request's window: the request is undecided, the index lies at or above the base, below the grant and the manifest's count, and the manifest matches the bound one, or none is bound yet.
    fn fits(&self, header: &Header, manifest: Manifest) -> bool {
        self.outcome.is_none()
            && header.index >= self.base
            && header.index < self.granted
            && header.index < manifest.count()
            && self.manifest.is_none_or(|bound| bound == manifest)
    }

    /// The window entry of fragment `index`, which [`fits`](Self::fits) placed within one window above the base.
    fn entry_of(&self, index: u32, window: u32) -> usize {
        wrap(self.base_at + (index - self.base), window) as usize
    }
}

/// A held fragment: its datagram and the manifest its header named.
/// Held indices lie in `handed..granted`, less than a window apart, so an entry's place in the window fixes its index.
struct Held<'p> {
    lease: PacketLease<'p>,
    manifest: Manifest,
}

/// Counters over the core's life.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FetchReport {
    pub get_retries: u64,
    pub ack_retries: u64,
    /// Gap ACKs queued: one when a gap outlasts the wait, and one per interval it outlasts after that.
    pub gap_acks: u64,
    /// Fragments held after a higher fragment of their request: the network delivered them out of order.
    pub reordered: u64,
    /// Fragments dropped as duplicates, outside the window, against the manifest, or naming no live request.
    pub dropped: u64,
    /// Fragments dropped because the pool's data boxes were all held, which happens only when the pool backs fewer data boxes than `boxes` or serves other holders; the owner resends them.
    pub data_pressure: u64,
    /// GETs decided, one count per request by outcome class, counted when the outcome is decided.
    pub outcomes: OutcomeCounts,
    /// Entry `k - 1` counts datagrams that a transport call reported taken and that carried `k` GET frames, a
    /// retried GET's datagram included. The client's send path moves this counter, `first_send_us` and
    /// `first_sends` for each GET datagram the transport reports taken, so a core driven through
    /// [`FetchCore::poll`] alone reads 0 in all three.
    pub gets_per_datagram: [u64; MAX_PACKED_GETS],
    /// Sums the microseconds from each GET's admission to the poll in which the transport took its first GET frame,
    /// saturating at `u64::MAX`; a GET's later taken frames add nothing. A GET decided before the transport takes
    /// one of its GET frames adds nothing here and no count to `first_sends`; in a client's lifetime report whose
    /// GETs are all decided, `outcomes.total()` less the sum of `first_sends` counts those GETs.
    pub first_send_us: u64,
    /// The times `first_send_us` sums, one count per GET at its first taken GET frame. Bucket `k` starts at `2^k`
    /// microseconds; bucket 0 also counts zero, and the last bucket counts every time at or above its start.
    pub first_sends: [u64; FIRST_SEND_BUCKETS],
}

/// Entries of [`FetchReport::first_sends`]. The last entry starts at `2^23` microseconds, about 8.4 s.
pub const FIRST_SEND_BUCKETS: usize = 24;

/// Who decided a GET's outcome. Every decider except `Owner` ends the request on the client while the owner's
/// own terminal observation stays unseen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decider {
    /// The owner's COMPLETE or ERROR.
    Owner,
    /// The client's wait passed or its attempts ran out; the client sends CANCEL `TimedOut`.
    Wait,
    /// The application cancelled, or the manifest exceeded the request's caps; the client sends CANCEL
    /// `Cancelled`.
    Cancel,
    /// The request's session ended, or the client's shard route stopped admitting the session's tenure; the client
    /// sends no CANCEL.
    Session,
}

/// GETs by outcome class. Owner-decided GETs count under their [`Outcome`]; client-decided GETs count under
/// their [`Decider`], whatever their outcome, as the requests whose backend latency stays censored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutcomeCounts {
    pub complete: u64,
    pub missing: u64,
    pub pressure: u64,
    pub failed: u64,
    pub incomplete: u64,
    /// Requests whose client wait passed or whose attempts ran out.
    pub timed_out: u64,
    /// Requests the application or the client's cap check cancelled.
    pub cancelled: u64,
    /// Requests their session's end, or the shard route's refusal of their session's tenure, decided.
    pub session_ended: u64,
}

impl OutcomeCounts {
    pub(super) fn count(&mut self, outcome: Outcome, by: Decider) {
        let class = match (by, outcome) {
            (Decider::Wait, _) => &mut self.timed_out,
            (Decider::Cancel, _) => &mut self.cancelled,
            (Decider::Session, _) => &mut self.session_ended,
            (Decider::Owner, Outcome::Complete) => &mut self.complete,
            (Decider::Owner, Outcome::Missing) => &mut self.missing,
            (Decider::Owner, Outcome::Pressure(_)) => &mut self.pressure,
            (Decider::Owner, Outcome::Failed(_)) => &mut self.failed,
            (Decider::Owner, Outcome::Incomplete(_)) => &mut self.incomplete,
        };
        *class += 1;
    }

    /// Every decided GET, whatever its class.
    pub fn total(&self) -> u64 {
        self.complete
            + self.missing
            + self.pressure
            + self.failed
            + self.incomplete
            + self.timed_out
            + self.cancelled
            + self.session_ended
    }
}

/// One GET's terminal observation on the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Terminal {
    /// The request's attempt identity, distinct from the caller's logical request and from any owner or
    /// device completion.
    pub attempt: RequestId,
    /// When the caller intended the request to arrive.
    pub intended_us: u64,
    /// The time of the client's latest turn or admission when the outcome was decided.
    pub decided_us: u64,
    pub decided_by: Decider,
    pub outcome: Outcome,
}

impl Terminal {
    /// Whether the client ended the request while the owner's work for it may continue, so its backend
    /// latency stays censored until the owner's own terminal observation.
    pub fn censored(&self) -> bool {
        self.decided_by != Decider::Owner
    }
}

/// A handle to the live request [`FetchCore::wants`] selected for a DATA frame. [`FetchCore::data`] consumes the handle and rechecks the request against the frame and its current window.
#[derive(Debug)]
pub struct Wanted {
    /// The request's table handle, packed by [`RequestId::wire`].
    request: u64,
}

/// What the client waits on for its fetches: whether a frame is due now, and the earliest timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Wake {
    pub(super) due: bool,
    pub(super) deadline_us: Option<u64>,
}

/// `FetchCore` receives fetched fragments into leases of pools borrowed for `'p`.
///
/// The core requires the `ClientRequests` namespace used at construction; a pairing mismatch panics.
///
/// [`begin`](Self::begin), [`tick`](Self::tick), [`fetch`](Self::fetch) and [`start`](Self::start) set the core's time for a turn. [`complete`](Self::complete), [`error`](Self::error), [`cancel`](Self::cancel) and [`end_session`](Self::end_session) use that time for outcome decisions.
pub struct FetchCore<'p> {
    config: FetchConfig,
    /// Each request slot's window of held fragments, `window` entries at `slot * window`.
    held: Box<[Option<Held<'p>>]>,
    releases: &'p Releases,
    board: u64,
    /// The slots whose request may have a CANCEL, GET or ACK to send; `poll` visits only these and the slots the board marks.
    marked: Marks,
    /// Boxes the live requests reserve: the sum of their initial grants.
    promised: u32,
    timers: Timers,
    cursor: u32,
    /// The slots whose ACK or CANCEL the running `poll` selected after a GET reached its `send`, in selection order; empty between polls, with a capacity of one entry per slot.
    behind: Vec<u16>,
    /// The time of the client's latest turn or admission, the timing point of the outcomes it decides.
    now_us: u64,
    report: FetchReport,
    /// GETs decided over the core's life, the sum of the classes of `report.outcomes`, which a turn reads at its start and end.
    decided: u64,
}

impl<'p> FetchCore<'p> {
    /// Bytes a core over a table of `slots` request slots charges, or `None` when they overflow `usize`.
    pub fn charge(config: &FetchConfig, slots: u32) -> Option<usize> {
        (config.window.clamp(1, MAX_WINDOW) as usize)
            .checked_mul(slots as usize)?
            .checked_mul(size_of::<Option<Held<'p>>>())?
            .checked_add(Marks::charge(slots))?
            .checked_add(Timers::charge(slots))?
            .checked_add(slots as usize * size_of::<u16>())
    }

    /// Each [`ClientRequests`] supports at most one fetch core.
    ///
    /// # Errors
    ///
    /// `Boxes` when `boxes` holds less than the clamped window, `Paired` when `requests` already serves a fetch core, or `Budget`; `budget` is unchanged on every error.
    pub fn new(
        config: FetchConfig,
        requests: &mut ClientRequests<'p>,
        budget: &mut EngineBudget,
    ) -> Result<Self, FetchCoreError> {
        let config = FetchConfig {
            window: config.window.clamp(1, MAX_WINDOW),
            ..config
        };
        let slots = requests.table().slots();
        if config.boxes < config.window {
            return Err(FetchCoreError::Boxes);
        }
        if requests.serves(Operation::Get) {
            return Err(FetchCoreError::Paired);
        }
        budget
            .charge(Self::charge(&config, slots).unwrap_or(usize::MAX))
            .map_err(FetchCoreError::Budget)?;
        requests.serve(Operation::Get);
        let releases = requests.releases();
        Ok(Self {
            config,
            held: (0..config.window as usize * slots as usize)
                .map(|_| None)
                .collect(),
            releases,
            board: releases.board(),
            marked: Marks::new(slots),
            promised: 0,
            timers: Timers::new(slots),
            cursor: 0,
            behind: Vec::with_capacity(slots as usize),
            now_us: 0,
            report: FetchReport::default(),
            decided: 0,
        })
    }

    pub fn report(&self) -> FetchReport {
        self.report
    }

    /// The count includes every GET the core has decided over its lifetime.
    #[inline]
    pub(super) fn decided(&self) -> u64 {
        debug_assert_eq!(self.decided, self.report.outcomes.total());
        self.decided
    }

    /// Counts one decided GET in its outcome class and in the total.
    #[inline]
    fn count(&mut self, outcome: Outcome, by: Decider) {
        self.report.outcomes.count(outcome, by);
        self.decided += 1;
    }

    /// The core requires the `ClientRequests` namespace used at construction; a pairing mismatch panics.
    fn check_pair(&self, requests: &ClientRequests<'_>) {
        assert!(
            std::ptr::eq(self.releases, requests.releases()) && self.board == self.releases.board(),
            "a fetch core runs over the namespace it was built from"
        );
    }

    /// Request `id`'s retry count.
    #[cfg(test)]
    pub(super) fn attempts(&self, requests: &ClientRequests<'p>, id: RequestId) -> Option<u32> {
        Some(requests.fetch(id)?.attempts)
    }

    /// Sets request `id`'s retry count to `attempts` and rewrites its timer, which the count's backoff moves, so a test reaches the count's limit without that many retries.
    #[cfg(test)]
    pub(super) fn seed_attempts(
        &mut self,
        requests: &mut ClientRequests<'p>,
        id: RequestId,
        attempts: u32,
    ) {
        if let Some(fetch) = requests.fetch_mut(id) {
            fetch.attempts = attempts;
            self.retime(id.slot(), fetch);
        }
    }

    /// Receive boxes reserved: the live requests' initial grants and the leases the application holds from closed requests.
    pub fn reserved(&self) -> u32 {
        self.promised + self.releases.orphans.get()
    }

    /// `fetch` starts a GET for `key` under `session`, caps metadata at `limits.metadata_cap` bytes and the body at `limits.body_cap` bytes, sets the deadline to `now_us + limits.wait_us`, and reserves receive boxes for the initial grant.
    ///
    /// # Errors
    ///
    /// `fetch` returns `Receive` when the reserved receive boxes leave fewer than the initial grant requires.
    pub fn fetch(
        &mut self,
        requests: &mut ClientRequests<'p>,
        session: Admitted,
        key: [u8; 32],
        limits: FetchLimits,
        now_us: u64,
    ) -> Result<RequestId, FetchPressure> {
        let FetchLimits {
            metadata_cap,
            body_cap,
            wait_us,
            intended_us,
        } = limits;
        self.check_pair(requests);
        self.now_us = now_us;
        let initial = self.config.window.min(session.caps.window).max(1);
        if u64::from(self.reserved()) + u64::from(initial) > u64::from(self.config.boxes) {
            return Err(FetchPressure::Receive);
        }
        let id = requests
            .admit(session.peer, session.caps.slots, |wire| {
                ClientRequest::Get(Fetch {
                    peer: session.peer,
                    epoch: session.epoch,
                    wire,
                    key,
                    metadata_cap,
                    body_cap,
                    initial,
                    deadline_us: now_us.saturating_add(wait_us),
                    manifest: None,
                    base: 0,
                    base_at: 0,
                    handed: 0,
                    filled: 0,
                    granted: initial,
                    advertised: initial,
                    acked_base: 0,
                    seen_to: 0,
                    burst: 0,
                    outcome: None,
                    get_due: true,
                    ack_due: false,
                    cancel_due: None,
                    progress_us: now_us,
                    attempts: 0,
                    gap_us: None,
                    gap_reported: false,
                    gap_ack_due: false,
                    intended_us,
                    admitted_us: Some(now_us),
                    decided_us: 0,
                    decided_by: Decider::Owner,
                })
            })
            .map_err(FetchPressure::Identity)?;
        self.marked.set(id.slot());
        self.promised += initial;
        if let Some(fetch) = requests.fetch(id) {
            self.retime(id.slot(), fetch);
        }
        Ok(id)
    }

    /// Takes an admitted START: binds the manifest, refusing one above the GET's caps, and exposes held fragments that match it.
    pub fn start(
        &mut self,
        requests: &mut ClientRequests<'p>,
        session: Admitted,
        header: &Header,
        now_us: u64,
    ) {
        self.check_pair(requests);
        self.begin(now_us);
        let Some((id, fetch)) = named(requests, session, header) else {
            return;
        };
        let manifest = manifest_of(header);
        if fetch.outcome.is_some() {
            return;
        }
        match fetch.manifest {
            Some(bound) if bound != manifest => return,
            Some(_) => {
                // A resent START means the owner missed the ACK that bound it.
                fetch.ack_due = true;
                self.marked.set(id.slot());
                return;
            }
            None => {
                if manifest.metadata_len > fetch.metadata_cap || manifest.body_len > fetch.body_cap
                {
                    self.finish(requests, id, Status::TooLarge, Decider::Cancel);
                    return;
                }
                fetch.manifest = Some(manifest);
            }
        }
        fetch.get_due = false;
        fetch.ack_due = true;
        self.marked.set(id.slot());
        fetch.progress_us = now_us;
        fetch.attempts = 0;
        // Fragments held before binding may name another manifest; `data` holds a later fragment only when it matches.
        let window = &mut self.held[entries(id, self.config.window)];
        let filled = fetch.filled;
        if fetch.filled > fetch.handed {
            for entry in window.iter_mut() {
                if entry.as_ref().is_some_and(|held| held.manifest != manifest) {
                    *entry = None;
                    fetch.filled -= 1;
                    self.report.dropped += 1;
                }
            }
        }
        if fetch.filled < filled {
            // A dropped fragment may have been the highest held; the high-water mark falls to one past the highest surviving fragment.
            let width = window.len() as u32;
            fetch.seen_to = (fetch.base..fetch.seen_to)
                .rev()
                .find(|&index| window[fetch.entry_of(index, width)].is_some())
                .map_or(fetch.base, |index| index + 1);
        }
        advance(fetch, window, &self.marked, id);
        // Fragments held before START may stand above a missing base; binding the manifest fixes the base, so the gap opens here.
        fetch.track_gap(now_us);
        self.retime(id.slot(), fetch);
    }

    /// `wants` returns a [`Wanted`] handle when the admitted DATA frame names a live request under `session`, fits its window, and targets a free entry.
    /// The caller checks the body crc only for a frame the core wants and passes the handle to [`data`](Self::data), which reaches the routed request by it.
    #[inline]
    pub fn wants(
        &self,
        requests: &ClientRequests<'_>,
        session: Admitted,
        header: &Header,
    ) -> Option<Wanted> {
        self.check_pair(requests);
        let (id, fetch) = self.routed(requests, session, header)?;
        let manifest = manifest_of(header);
        let window = self.config.window;
        (fetch.fits(header, manifest)
            && self.held[entries(id, window).start + fetch.entry_of(header.index, window)]
                .is_none())
        .then_some(Wanted { request: id.wire() })
    }

    /// The request a frame names and its state, if live under `session`, read without marking anything.
    fn routed<'r>(
        &self,
        requests: &'r ClientRequests<'_>,
        session: Admitted,
        header: &Header,
    ) -> Option<(RequestId, &'r Fetch)> {
        let id = requests.route(session.peer, header.request, Operation::Get)?;
        let fetch = requests.fetch(id)?;
        fetch.names(session, header).then_some((id, fetch))
    }

    /// Takes an admitted DATA frame that [`parse`](super::parse) accepted and whose body crc verified, received in `lease`, so its index, offset and length match the manifest it names: holds it in the request's window, or drops it as a duplicate, outside the window, against the manifest or for an ended request; a fragment the pool has no data box for counts under `data_pressure`.
    /// `wanted` takes the handle [`wants`](Self::wants) returned for `header`; `None` uses header-based routing.
    pub fn data(
        &mut self,
        requests: &mut ClientRequests<'p>,
        session: Admitted,
        header: &Header,
        wanted: Option<Wanted>,
        lease: PacketLease<'p>,
        now_us: u64,
    ) {
        self.check_pair(requests);
        let routed = match wanted {
            Some(Wanted { request }) => {
                let id = RequestId::from_wire(request);
                requests
                    .fetch_mut(id)
                    .filter(|fetch| fetch.names(session, header))
                    .map(|fetch| (id, fetch))
            }
            None => named(requests, session, header),
        };
        let Some((id, fetch)) = routed else {
            self.report.dropped += 1;
            return;
        };
        let manifest = manifest_of(header);
        let window = self.config.window;
        let held = if fetch.fits(header, manifest) {
            let at = entries(id, window).start + fetch.entry_of(header.index, window);
            hold(&mut self.held[at], lease, manifest)
        } else {
            Hold::Dropped
        };
        match held {
            Hold::Held => {}
            Hold::Dropped => {
                self.report.dropped += 1;
                // A fragment below the base is a resend: the owner missed the ACK that covers it.
                if header.index < fetch.base && fetch.outcome.is_none() {
                    fetch.ack_due = true;
                    self.marked.set(id.slot());
                }
                return;
            }
            Hold::Pressure => {
                self.report.data_pressure += 1;
                return;
            }
        }
        fetch.filled += 1;
        if header.index + 1 < fetch.seen_to {
            self.report.reordered += 1;
        }
        fetch.seen_to = fetch.seen_to.max(header.index + 1);
        fetch.burst = fetch.burst.max(fetch.seen_to - fetch.acked_base);
        // A grant folded while the owner had credit goes out as soon as this fragment leaves the advertised grant within a burst of the highest received.
        if fetch.granted > fetch.advertised && fetch.owed() && fetch.credit_low() {
            fetch.ack_due = true;
            self.marked.set(id.slot());
        }
        fetch.progress_us = now_us;
        // `filled - base` fragments are held at or above the base; when the base's own fragment is the only one, the base moves by one without a scan.
        if fetch.manifest.is_some() && header.index == fetch.base && fetch.filled - fetch.base == 1
        {
            fetch.base += 1;
            fetch.base_at = wrap(fetch.base_at + 1, window);
            fetch.ack_due = true;
            fetch.attempts = 0;
            self.marked.set(id.slot());
        } else {
            advance(fetch, &self.held[entries(id, window)], &self.marked, id);
        }
        fetch.track_gap(now_us);
        self.retime(id.slot(), fetch);
    }

    /// Takes an admitted COMPLETE: success once every fragment arrived under the bound manifest.
    pub fn complete(
        &mut self,
        requests: &mut ClientRequests<'p>,
        session: Admitted,
        header: &Header,
    ) {
        self.check_pair(requests);
        let Some((id, fetch)) = named(requests, session, header) else {
            return;
        };
        let manifest = manifest_of(header);
        if fetch.outcome.is_none()
            && fetch.manifest == Some(manifest)
            && fetch.base == manifest.count()
        {
            fetch.ack_due = false;
            fetch.decide(Outcome::Complete, Decider::Owner, self.now_us);
            self.count(Outcome::Complete, Decider::Owner);
            self.timers.set(usize::from(id.slot()), None);
        }
    }

    /// Takes an admitted ERROR: the request ends with the outcome its status and exposure decide.
    pub fn error(&mut self, requests: &mut ClientRequests<'p>, session: Admitted, header: &Header) {
        self.check_pair(requests);
        let Some((id, _)) = named(requests, session, header) else {
            return;
        };
        let status = Status::from_wire(header.status).unwrap_or(Status::InvalidRequest);
        self.finish(requests, id, status, Decider::Owner);
    }

    /// The application ends request `id`; the owner is told with a CANCEL. The outcome takes the time of the
    /// client's latest turn or admission.
    pub fn cancel(&mut self, requests: &mut ClientRequests<'p>, id: RequestId) {
        self.check_pair(requests);
        self.finish(requests, id, Status::Cancelled, Decider::Cancel);
    }

    /// Ends request `id` with the outcome `status` and its exposure decide, as `by` decided it, queueing the
    /// CANCEL `by` sends (`TimedOut` for `Wait`, `Cancelled` for `Cancel`), and returns its untaken fragments
    /// to their pool at once.
    fn finish(
        &mut self,
        requests: &mut ClientRequests<'p>,
        id: RequestId,
        status: Status,
        by: Decider,
    ) {
        if let Some(fetch) = requests.fetch_mut(id)
            && fetch.outcome.is_none()
        {
            let outcome = Outcome::of(status, fetch.handed > 0);
            fetch.decide(outcome, by, self.now_us);
            self.count(outcome, by);
            let cancel = match by {
                Decider::Wait => Some(Status::TimedOut),
                Decider::Cancel => Some(Status::Cancelled),
                Decider::Owner | Decider::Session => None,
            };
            fetch.cancel_due = cancel;
            if cancel.is_some() {
                self.marked.set(id.slot());
            }
            fetch.get_due = false;
            fetch.ack_due = false;
            if fetch.filled > fetch.handed {
                self.held[entries(id, self.config.window)].fill_with(|| None);
                fetch.filled = fetch.handed;
            }
            // A decided request waits on no timer.
            self.timers.set(usize::from(id.slot()), None);
        }
    }

    /// The next fragment of request `id` in order, if received.
    #[inline]
    pub fn take(
        &mut self,
        requests: &mut ClientRequests<'p>,
        id: RequestId,
    ) -> Option<FragmentLease<'p>> {
        self.check_pair(requests);
        let window = self.config.window;
        let fetch = requests.fetch_mut(id)?;
        if fetch.handed >= fetch.base {
            return None;
        }
        // `handed` lies at most a window below `base`.
        let at = entries(id, window).start
            + wrap(fetch.base_at + window - (fetch.base - fetch.handed), window) as usize;
        let held = self.held[at].take()?;
        let index = fetch.handed;
        fetch.handed += 1;
        Some(FragmentLease {
            lease: held.lease,
            releases: self.releases,
            core: self.board,
            request: id.wire(),
            manifest: held.manifest,
            index,
        })
    }

    /// Request `id`'s outcome once decided.
    pub fn outcome(&self, requests: &ClientRequests<'_>, id: RequestId) -> Option<Outcome> {
        self.check_pair(requests);
        requests.fetch(id)?.outcome
    }

    /// Starts a client turn at `now_us`, the time of the outcomes the turn's received frames decide.
    pub fn begin(&mut self, now_us: u64) {
        self.now_us = now_us;
    }

    /// Request `id`'s terminal observation once its outcome is decided.
    pub fn terminal(&self, requests: &ClientRequests<'_>, id: RequestId) -> Option<Terminal> {
        self.check_pair(requests);
        let fetch = requests.fetch(id)?;
        Some(Terminal {
            attempt: id,
            intended_us: fetch.intended_us,
            decided_us: fetch.decided_us,
            decided_by: fetch.decided_by,
            outcome: fetch.outcome?,
        })
    }

    /// Retires request `id` after its outcome is decided and any CANCEL is sent. Retirement drops unclaimed fragments and frees the wire slot for the peer's next request. Issued leases remain valid. Returns whether the entry was retired.
    pub fn close(&mut self, requests: &mut ClientRequests<'p>, id: RequestId) -> bool {
        self.check_pair(requests);
        let Some(fetch) = requests
            .fetch(id)
            .filter(|fetch| fetch.outcome.is_some() && fetch.cancel_due.is_none())
        else {
            return false;
        };
        let window = &mut self.held[entries(id, self.config.window)];
        debug_assert_eq!(
            window.iter().filter(|entry| entry.is_some()).count(),
            (fetch.filled - fetch.handed) as usize,
            "`filled - handed` counts the request's held fragments"
        );
        if fetch.filled > fetch.handed {
            window.fill_with(|| None);
        }
        let initial = fetch.initial;
        if requests.release(id) {
            self.promised -= initial;
            self.timers.set(usize::from(id.slot()), None);
        }
        true
    }

    /// Rewrites table slot `slot`'s timer from `fetch`, the request it holds.
    #[inline]
    fn retime(&mut self, slot: u16, fetch: &Fetch) {
        let timer = fetch
            .outcome
            .is_none()
            .then(|| fetch.timer(self.config.retry_us));
        self.timers.set(usize::from(slot), timer);
    }

    /// Starts a turn at `now_us` and ends every undecided request whose deadline has come with `TimedOut`, queuing its
    /// CANCEL `TimedOut`; retries and gap ACKs wait for [`tick`](Self::tick). [`Client::poll`](super::Client::poll)
    /// runs it before its receive batch, so a frame received in that turn finds an expired request decided.
    #[inline]
    pub fn expire(&mut self, requests: &mut ClientRequests<'p>, now_us: u64) {
        self.check_pair(requests);
        self.begin(now_us);
        if self.timers.floor().is_some_and(|floor| now_us >= floor) {
            self.tick_timers(requests, now_us, false);
        }
    }

    /// Advances timers at `now_us`: a deadline ends the request and queues CANCEL `TimedOut` for the next `poll`; a silent request resends its GET before START or its ACK after it, at most `attempts` times, then ends.
    #[inline]
    pub fn tick(&mut self, requests: &mut ClientRequests<'p>, now_us: u64) {
        self.check_pair(requests);
        self.begin(now_us);
        if self.timers.floor().is_some_and(|floor| now_us >= floor) {
            self.tick_timers(requests, now_us, true);
        }
    }

    /// The scan stays out of line to keep [`tick`](Self::tick)'s fast path compact when `now_us` precedes the timers' floor. It ends requests at their deadline, and with `retries` it also runs due gap ACKs and retries.
    #[inline(never)]
    fn tick_timers(&mut self, requests: &mut ClientRequests<'p>, now_us: u64, retries: bool) {
        let (retry_us, attempts) = (self.config.retry_us, self.config.attempts);
        let end = requests.table().high_water() as usize;
        let mut from = 0;
        // A timer at or before `now_us` names an undecided request whose deadline or retry has come.
        while let Some(slot) = self.timers.next_due(from, end, now_us) {
            from = slot + 1;
            let Some((id, fetch)) = requests.live_fetch_mut(slot as u32) else {
                self.timers.set(slot, None);
                continue;
            };
            debug_assert!(fetch.outcome.is_none(), "a decided request has no timer");
            if now_us >= fetch.deadline_us {
                self.finish(requests, id, Status::TimedOut, Decider::Wait);
                continue;
            }
            if !retries {
                continue;
            }
            // A timer before the deadline is a due gap ACK or a due retry; a request held back by the application times out only at its deadline, and the release that ends a held-back wait restarts the retry clock in `poll`.
            let gap_due = fetch.gap_due().is_some_and(|due| now_us >= due);
            if gap_due {
                fetch.ack_due = true;
                fetch.gap_ack_due = true;
                fetch.gap_reported = true;
                fetch.gap_us = Some(now_us);
                self.report.gap_acks += 1;
                self.marked.set(id.slot());
            }
            if fetch.held_back() || now_us < fetch.retry_from_progress(retry_us) {
                debug_assert!(
                    gap_due,
                    "a timer before the deadline is a due gap ACK or retry"
                );
                self.timers.set(slot, Some(fetch.timer(retry_us)));
                continue;
            }
            if fetch.attempts >= attempts {
                self.finish(requests, id, Status::OwnerUnavailable, Decider::Wait);
                continue;
            }
            fetch.attempts += 1;
            fetch.progress_us = now_us;
            self.marked.set(id.slot());
            if fetch.manifest.is_none() {
                fetch.get_due = true;
                self.report.get_retries += 1;
            } else {
                fetch.ack_due = true;
                self.report.ack_retries += 1;
            }
            self.timers.set(slot, Some(fetch.timer(retry_us)));
        }
        self.timers.fold(end);
    }

    /// Whether a frame waits for [`poll`](Self::poll): a CANCEL, GET or ACK that is due, or a grant above the advertised one while fragments remain owed and the advertised credit is within a burst of the highest fragment received.
    #[inline]
    pub fn due(&self, requests: &ClientRequests<'_>) -> bool {
        self.check_pair(requests);
        self.marked() && self.marked_due(requests)
    }

    #[inline]
    pub(super) fn marked(&self) -> bool {
        self.marked.maybe_any(&self.releases.marks)
    }

    /// The scan stays out of line to keep [`due`](Self::due)'s empty-mark fast path compact.
    #[inline(never)]
    fn marked_due(&self, requests: &ClientRequests<'_>) -> bool {
        self.marked
            .any_with(&self.releases.marks, |slot| self.has_frame(requests, slot))
    }

    /// The earliest retry or deadline [`tick`](Self::tick) acts on, or `None` with no live request waiting on a timer.
    pub fn deadline(&self, requests: &ClientRequests<'_>) -> Option<u64> {
        self.check_pair(requests);
        self.timers.least(requests.table().high_water() as usize)
    }

    pub(super) fn wake(&self, requests: &ClientRequests<'_>) -> Wake {
        Wake {
            due: self.due(requests),
            deadline_us: self.deadline(requests),
        }
    }

    /// Whether the request in table slot `slot` has a frame for the next `poll`: a decided request its CANCEL, an undecided one its GET or ACK, or a grant above the advertised one while fragments remain owed and the advertised credit is within a burst of the highest fragment received.
    fn has_frame(&self, requests: &ClientRequests<'_>, slot: u32) -> bool {
        let Some(id) = requests.table().live_id(slot) else {
            return false;
        };
        let Some(fetch) = requests.fetch(id) else {
            return false;
        };
        if fetch.outcome.is_some() {
            return fetch.cancel_due.is_some();
        }
        fetch.get_due
            || fetch.ack_due
            || (fetch.owed()
                && fetch.credit_low()
                && fetch.grant(self.releases.released(id)) > fetch.advertised)
    }

    /// Ends every undecided request of session `epoch` with `status` and queues no CANCEL, since a replaced or unrouted session carries none; a decided request keeps its outcome and any CANCEL it queued.
    pub fn end_session(&mut self, requests: &mut ClientRequests<'p>, epoch: u64, status: Status) {
        self.check_pair(requests);
        for slot in 0..requests.table().high_water() {
            if let Some(id) = requests.table().live_id(slot)
                && requests.fetch(id).is_some_and(|fetch| fetch.epoch == epoch)
            {
                self.finish(requests, id, status, Decider::Session);
            }
        }
    }

    /// Ends every undecided request with `Cancelled` and queues its CANCEL `Cancelled`; a decided request keeps its outcome and any CANCEL it queued.
    pub fn cancel_all(&mut self, requests: &mut ClientRequests<'p>) {
        self.check_pair(requests);
        for slot in 0..requests.table().high_water() {
            if let Some(id) = requests.table().live_id(slot) {
                self.finish(requests, id, Status::Cancelled, Decider::Cancel);
            }
        }
    }

    /// Counts one datagram of 1 to [`MAX_PACKED_GETS`] GET frames, `gets`, that the transport took in the poll at
    /// `now_us`, and records the first-send time of each of its requests that still holds its admission time.
    pub(super) fn taken(&mut self, requests: &mut ClientRequests<'p>, gets: &[Asked], now_us: u64) {
        self.check_pair(requests);
        debug_assert!(gets.iter().all(|frame| frame.kind == Kind::Get));
        self.report.gets_per_datagram[gets.len() - 1] += 1;
        for frame in gets {
            let admitted = frame
                .fetch_mut(requests)
                .and_then(|fetch| fetch.admitted_us.take());
            if let Some(admitted) = admitted {
                let waited = now_us.saturating_sub(admitted);
                self.report.first_send_us = self.report.first_send_us.saturating_add(waited);
                self.report.first_sends
                    [(waited.max(1).ilog2() as usize).min(FIRST_SEND_BUCKETS - 1)] += 1;
            }
        }
    }

    /// Puts back a frame [`poll`](Self::poll) handed to its `send` that the transport then refused, so the request's CANCEL, GET or ACK stays due.
    pub(super) fn unsend(&mut self, requests: &mut ClientRequests<'p>, frame: Asked) {
        self.check_pair(requests);
        let Some(fetch) = frame.fetch_mut(requests) else {
            return;
        };
        match frame.kind {
            Kind::Cancel => {
                fetch.cancel_due = fetch.cancel_due.or(Status::from_wire(frame.status));
            }
            Kind::Get => fetch.get_due = true,
            _ => {
                fetch.ack_due = true;
                fetch.gap_ack_due |= frame.mask;
            }
        }
        self.marked.set(frame.slot);
    }

    /// Sends up to `budget` frames at `now_us` through `send`, which returns false once the transport takes no more: each request's CANCEL, GET or ACK, after folding in the grant its released leases add.
    /// The scan selects frames in request-table slot order from the cursor, wrapping. A frame reaches `send` when the scan selects it, except an ACK or CANCEL selected after a GET reached `send`: its slot waits in `behind`, and its frame is built and reaches `send` once the scan has ended, in selection order. The GET frames of one poll therefore reach `send` with no other frame between them. A lease that `send` releases for a request whose frame waits marks the slot on the release board. A scan that reaches the slot again folds the release and keeps the slot's one entry in `behind`, so a waiting ACK carries the raised grant and each waiting frame counts once in `budget`.
    /// Returns how many were sent.
    pub fn poll(
        &mut self,
        requests: &mut ClientRequests<'p>,
        now_us: u64,
        budget: usize,
        mut send: impl FnMut(Ask) -> bool,
    ) -> usize {
        self.check_pair(requests);
        let slots = requests.table().slots();
        let Self {
            config,
            held,
            releases,
            marked,
            timers,
            cursor,
            behind,
            ..
        } = self;
        let marked = &*marked;
        debug_assert!(behind.is_empty());
        let (mut sent, mut idle, mut slot) = (0, 0, *cursor);
        let mut get_sent = false;
        // While `scanning`, each turn of the loop takes the next frame the scan selects; afterwards, the frame of the slot at `behind[waiting]`.
        let (mut scanning, mut waiting) = (true, 0);
        loop {
            let (id, fetch, due) = if scanning {
                if sent + behind.len() >= budget {
                    scanning = false;
                    continue;
                }
                // Visits marked slots in slot order from the cursor, wrapping, until a full round of slots selects nothing; each unmarked slot passed counts as one idle visit, since it has nothing to send or fold.
                let Some(next) = marked.next_with(&releases.marks, slot) else {
                    scanning = false;
                    continue;
                };
                idle += if next >= slot {
                    next - slot
                } else {
                    next + slots - slot
                };
                if idle >= slots {
                    scanning = false;
                    continue;
                }
                idle += 1;
                slot = if next + 1 < slots { next + 1 } else { 0 };
                let was_marked = marked.remove(next as u16);
                // Only a release sets the board's mark, so an unmarked slot has no release to fold.
                let folds = releases.marks.remove(next as u16);
                let Some((id, fetch)) = requests.live_fetch_mut(next) else {
                    continue;
                };
                let grant = if folds {
                    fetch.initial + releases.released(id)
                } else {
                    fetch.granted
                };
                if grant > fetch.granted && fetch.outcome.is_none() {
                    fetch.granted = grant;
                    fetch.progress_us = now_us;
                    fetch.attempts = 0;
                    let timer = fetch.timer(config.retry_us);
                    timers.set(next as usize, Some(timer));
                }
                // A grant above the advertised one queues an ACK while the advertised credit is within a burst of the highest fragment received; otherwise the next receipt ACK carries it.
                let was_ack_due = fetch.ack_due;
                fetch.ack_due |=
                    fetch.owed() && fetch.credit_low() && fetch.granted > fetch.advertised;
                let Some(due) = Due::of(fetch) else {
                    continue;
                };
                *cursor = slot;
                idle = 0;
                if get_sent && !matches!(due, Due::Get) {
                    let waits =
                        folds && !was_marked && (was_ack_due || matches!(due, Due::Cancel(_)));
                    debug_assert_eq!(waits, behind.contains(&id.slot()));
                    if !waits {
                        behind.push(id.slot());
                    }
                    continue;
                }
                get_sent |= matches!(due, Due::Get);
                (id, fetch, due)
            } else {
                let Some(&slot) = behind.get(waiting) else {
                    break;
                };
                waiting += 1;
                // The scan changed no due state of a waiting request after selecting its frame, so `Due::of` returns that frame again.
                let Some((id, fetch)) = requests.live_fetch_mut(u32::from(slot)) else {
                    continue;
                };
                let Some(due) = Due::of(fetch) else {
                    continue;
                };
                (id, fetch, due)
            };
            let mask = if matches!(due, Due::Ack(_)) && fetch.gap_ack_due && fetch.in_gap() {
                receipt_mask(fetch, &held[entries(id, config.window)])
            } else {
                0
            };
            let ask = next_ask(fetch, due, id.slot(), now_us, mask);
            if !send(ask) {
                // The refused frame stays due. `waiting` is 0 while the scan runs, so a refusal there leaves all of `behind` waiting.
                marked.set(id.slot());
                break;
            }
            match due {
                Due::Cancel(_) => fetch.cancel_due = None,
                Due::Get => {
                    fetch.get_due = false;
                    fetch.advertised = ask.header.grant;
                }
                Due::Ack(_) => {
                    fetch.ack_due = false;
                    fetch.gap_ack_due = false;
                    fetch.advertised = ask.header.grant;
                    fetch.acked_base = ask.header.index;
                }
            }
            if fetch.cancel_due.is_some() || fetch.get_due || fetch.ack_due {
                marked.set(id.slot());
            }
            sent += 1;
        }
        // Each slot from `behind[waiting]` on holds a frame that never reached `send`, which stays due for the next poll.
        for slot in &behind[waiting..] {
            marked.set(*slot);
        }
        behind.clear();
        sent
    }
}

#[cfg(test)]
impl FetchCore<'_> {
    pub(super) fn check_timers(&self, requests: &ClientRequests<'_>) {
        self.check_pair(requests);
        let retry_us = self.config.retry_us;
        let (mut due, mut earliest) = (false, None);
        let least = (0..requests.table().slots() as usize)
            .filter_map(|slot| self.timers.get(slot))
            .min();
        assert_eq!(
            self.timers.floor().is_some(),
            least.is_some(),
            "the tick bound exists exactly while a slot carries a timer"
        );
        assert!(
            self.timers.floor() <= least,
            "the tick bound is at most the least timer"
        );
        assert!(
            !self.timers.exact() || self.timers.floor() == least,
            "an exact floor is the least timer"
        );
        for slot in 0..requests.table().slots() {
            let timer = self.timers.get(slot as usize);
            let Some(id) = requests.table().live_id(slot) else {
                assert_eq!(timer, None, "free slot {slot} carries a timer");
                continue;
            };
            let Some(fetch) = requests.fetch(id) else {
                assert_eq!(timer, None, "upload slot {slot} carries a timer");
                continue;
            };
            if fetch.outcome.is_some() {
                assert_eq!(timer, None, "decided slot {slot} carries a timer");
                due |= fetch.cancel_due.is_some();
                continue;
            }
            let at = fetch.timer(retry_us);
            assert_eq!(timer, Some(at), "slot {slot}'s timer");
            due |= fetch.get_due
                || fetch.ack_due
                || (fetch.owed()
                    && fetch.credit_low()
                    && fetch.grant(self.releases.released(id)) > fetch.advertised);
            earliest = Some(earliest.map_or(at, |earliest: u64| earliest.min(at)));
        }
        assert_eq!(
            self.wake(requests),
            Wake {
                due,
                deadline_us: earliest
            },
            "wake from the indexes matches a walk over the requests"
        );
    }
}

/// What became of a received DATA fragment.
enum Hold {
    Held,
    /// The fragment has no free place: its request has ended, its entry already holds a fragment, or it lies outside the request's window, its manifest, or the bound manifest.
    Dropped,
    /// The pool's data boxes are all held.
    Pressure,
}

/// Places `lease` in window `entry`, holding its box as data, when the entry is empty and the pool has a data box free.
fn hold<'p>(entry: &mut Option<Held<'p>>, mut lease: PacketLease<'p>, manifest: Manifest) -> Hold {
    if entry.is_some() {
        return Hold::Dropped;
    }
    if lease.retain_as_data().is_err() {
        return Hold::Pressure;
    }
    // Replacing the empty entry and forgetting the returned `None` writes the fragment without running drop code.
    let empty = entry.replace(Held { lease, manifest });
    debug_assert!(empty.is_none());
    std::mem::forget(empty);
    Hold::Held
}

/// The request a frame names and its state, if live in `requests` under `session`.
fn named<'t>(
    requests: &'t mut ClientRequests<'_>,
    session: Admitted,
    header: &Header,
) -> Option<(RequestId, &'t mut Fetch)> {
    let id = requests.route(session.peer, header.request, Operation::Get)?;
    let fetch = requests.fetch_mut(id)?;
    fetch.names(session, header).then_some((id, fetch))
}

/// Moves `fetch`'s receipt base over the contiguous fragments its `window` entries hold once a manifest is bound, marking the ACK due when the base moves; by then every held fragment matches that manifest.
fn advance(fetch: &mut Fetch, window: &[Option<Held<'_>>], marked: &Marks, id: RequestId) {
    let Some(manifest) = fetch.manifest else {
        return;
    };
    let start = fetch.base;
    // Below the grant, the entry at `base`'s place can hold only fragment `base`.
    let end = manifest.count().min(fetch.granted);
    while fetch.base < end && window[fetch.base_at as usize].is_some() {
        fetch.base += 1;
        fetch.base_at = wrap(fetch.base_at + 1, window.len() as u32);
    }
    if fetch.base > start {
        fetch.ack_due = true;
        fetch.attempts = 0;
        marked.set(id.slot());
    }
}

/// `entry` reduced below `window`, for an entry less than two windows.
fn wrap(entry: u32, window: u32) -> u32 {
    if entry >= window {
        entry - window
    } else {
        entry
    }
}

/// The entries of request `id`'s window in the held array, `window` of them at `slot * window`.
fn entries(id: RequestId, window: u32) -> std::ops::Range<usize> {
    let start = usize::from(id.slot()) * window as usize;
    start..start + window as usize
}

/// The manifest a START, DATA, ACK or COMPLETE header names.
fn manifest_of(header: &Header) -> Manifest {
    Manifest {
        allocation: header.allocation,
        metadata_len: header.metadata_len,
        body_len: header.body_len,
    }
}

/// The frame a request sends next.
#[derive(Clone, Copy)]
enum Due {
    /// A CANCEL carrying this status.
    Cancel(Status),
    Get,
    /// An ACK under the request's bound manifest.
    Ack(Manifest),
}

impl Due {
    /// The frame `fetch` sends next, if one is due: its CANCEL, then a GET before START, then an ACK.
    #[inline(always)]
    fn of(fetch: &Fetch) -> Option<Self> {
        if let Some(status) = fetch.cancel_due {
            return Some(Self::Cancel(status));
        }
        if fetch.outcome.is_some() {
            return None;
        }
        if fetch.get_due {
            return Some(Self::Get);
        }
        let manifest = fetch.manifest?;
        fetch.ack_due.then_some(Self::Ack(manifest))
    }
}

/// Builds the frame `due` of `fetch`, the request in table slot `slot`; an ACK carries `mask` as its receipt mask.
///
/// Inlined into [`FetchCore::poll`], its one caller, so the frame is built where `poll` reads it. Out of line, the `Ask` returns through a stack slot that this function fills with stores of one width and `poll` reads back at once with loads of another, and such a load waits until the stores have left the store buffer.
#[inline(always)]
fn next_ask(fetch: &Fetch, due: Due, slot: u16, now_us: u64, mask: u64) -> Ask {
    let request = fetch.wire;
    let header = match due {
        Due::Cancel(status) => Header {
            status: status as u16,
            ..header(Kind::Cancel, request, fetch.key)
        },
        Due::Get => {
            let remaining_ms = fetch
                .deadline_us
                .saturating_sub(now_us)
                .div_ceil(1000)
                .clamp(1, u64::from(u32::MAX));
            Header {
                metadata_len: fetch.metadata_cap,
                body_len: fetch.body_cap,
                grant: fetch.initial,
                remaining_ms: remaining_ms as u32,
                ..header(Kind::Get, request, fetch.key)
            }
        }
        Due::Ack(manifest) => Header {
            index: fetch.base,
            offset: mask,
            grant: fetch.granted,
            ..manifest_header(Kind::Ack, request, fetch.key, &manifest)
        },
    };
    Ask {
        peer: fetch.peer,
        slot,
        epoch: fetch.epoch,
        header,
    }
}

/// The receipt mask of `fetch` over its `window` entries: bit `i` set when fragment `base + 1 + i` is held, for the fragments up to the highest held one and at most 64 above the base.
fn receipt_mask(fetch: &Fetch, window: &[Option<Held<'_>>]) -> u64 {
    let width = window.len() as u32;
    let above = fetch.seen_to.saturating_sub(fetch.base + 1).min(u64::BITS);
    let mut mask = 0;
    for i in 0..above {
        if window[fetch.entry_of(fetch.base + 1 + i, width)].is_some() {
            mask |= 1 << i;
        }
    }
    mask
}

#[cfg(kani)]
mod releases_kani;
#[cfg(kani)]
mod wire_generation_kani;

#[cfg(test)]
#[path = "fetch_close_tests.rs"]
mod close_tests;
