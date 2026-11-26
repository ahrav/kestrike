//! The client's shard routes: one `(g, a)` high-water per shard over [`HighWater::merge`], shared by every session of
//! every client that holds the table.
//!
//! Invariants owned by this module:
//!
//! - One high-water per shard. Every route change runs in `ShardRoutes::update` under the table's lock, so the sessions
//!   of every [`Client`](super::Client) that holds the table observe one monotone `(g, a)` order. `update` hands each
//!   changed route to `Binding::publish`, which publishes in the shard's slot the tenure a Bound or Candidate route
//!   holds and which of the two states the route is in, and clears the slot's session word for a Conflict or Dark
//!   route.
//! - A response frame is admitted only when the route, after merging the frame's session tenure, is Bound to exactly
//!   that tenure. The merge and the comparison are one step that runs as each frame is admitted, so no frame is
//!   admitted under a tenure that any session has already raised the shard above. The merge returns unchanged a route
//!   Bound to the frame's own tenure, which admits the frame, and a route that holds a tenure above the frame's
//!   `(g, a)`, which refuses it. `ShardRoutes::admit` therefore reads the slot first: a slot that publishes the
//!   frame's tenure as Bound admits the frame, a slot that publishes a tenure above the frame's `(g, a)` refuses it,
//!   and after any other slot read `admit` merges under the lock. Fragments admitted before a raise stay readable: an
//!   undecided GET's until the client's next poll ends it, and a decided GET's until the application takes them.
//! - Successive tenures a slot publishes carry the same or a higher `(g, a)`, and every publish of one `(g, a)`
//!   records the same host. A route leaves the tenure it holds, as a Candidate or Bound, for the other of the two at
//!   the same tenure, a Conflict at that `(g, a)`, a Dark of that generation or a later one, or a higher tenure;
//!   another host at the held `(g, a)` is a Conflict, and from a Conflict or Dark the route holds only a higher
//!   `(g, a)`. With the publish fence and the acquire host loads, a reader that loads the same nonzero session word
//!   before and after the host words therefore reads the host of that word's tenure. A change between Candidate and
//!   Bound at one tenure stores the session word alone, over host words that already hold that tenure's host.
//! - Authentication admits ownership frames, and none needs the session table's epoch and replay checks to raise a
//!   route. Each raises the route to the tenures it names, and a repeated frame merges to the route it
//!   already produced. A tenure below the high-water leaves the route, an equal `(g, a)` naming another host is a
//!   Conflict, and a higher tenure becomes the candidate. An active-volume frame for its responder's own tenure raises
//!   the route as a candidate. One that clears the serving or liveness bit also withdraws a binding to that tenure,
//!   until a READY or an admitted response at that tenure binds it again, under WITHDRAWAL-NEEDS-SESSION on
//!   `ShardRoutes::reply`, and otherwise keeps the binding. A retired volume's frame
//!   darkens its generation, and a frame of a deposed tenure whose volume a successor retained names that volume
//!   active, so it raises the route to the successor's tenure of the same generation and darkens nothing.
//! - KEPT-WITHOUT-LOCK: a route that holds a tenure, as a Candidate or Bound, and the binder of its latest binding
//!   admission stay unchanged under a candidate frame that names the held tenure or a lower `(g, a)`, under a response
//!   at the tenure the route is Bound to, which is admitted, and under a response below the held `(g, a)`, which is
//!   refused. A slot read returns one published tenure whole, which the route held at an instant inside the call, so
//!   a merge that tenure keeps takes effect at that instant and the call returns its result without the table's lock:
//!   `ShardRoutes::reply` reports the route unchanged, and `ShardRoutes::admit` admits or refuses the response.
//! - The table lives in memory and never removes a route. A restarted client starts with every route None; the hosts'
//!   tenure fences enforce their guarantees without it. The high-water rejects deposed responses only and never proves
//!   a response current: a client whose high-water is below the successor may accept the deposed tenure's responses.

use std::num::{NonZeroU32, NonZeroU64};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::failover::identity::Exhid;
use crate::failover::route::{FrameKind, HighWater, HolderFrame, identity, key};
use crate::index::SeqWord;
use crate::net::linear_probe::{probe_by, spread, table_len};
use crate::net::ownership::{
    ActivatedEpoch, OwnershipBody, Shard, ShardGeneration, Tenure, Validity, VolumeState,
};
use crate::storage::{EngineBudget, EngineBudgetExceeded};

/// A session of a client sharing the table: the client's boot nonce and the session's epoch. A withdrawal takes effect
/// only when its receiver's binder and bound tenure both match the route's (`ShardRoutes::reply`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Binder {
    client: [u8; 16],
    epoch: NonZeroU64,
}

impl Binder {
    pub(crate) const fn new(client: [u8; 16], epoch: u64) -> Option<Self> {
        match NonZeroU64::new(epoch) {
            Some(epoch) => Some(Self { client, epoch }),
            None => None,
        }
    }
}

/// What the session that received an ownership frame contributes to its merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Receiver {
    /// The receiving client has no session bound to the frame's shard.
    Unbound,
    /// The receiving session is bound to the frame's shard at this tenure.
    Bound(Tenure),
    /// The receiving session, named by the binder, is bound to the frame's shard at the tenure and admitted the frame
    /// as its own under a sequence above every sequence it had admitted.
    Newest(Tenure, Binder),
}

#[derive(Clone, Copy)]
enum Claim {
    Retired,
    Candidate,
    Withdrawal(Binder),
}

impl Claim {
    #[inline]
    fn of(body: &OwnershipBody<'_>, responder: Exhid, receiver: &Receiver) -> Self {
        let state = body.volume.map(|volume| volume.state);
        if state == Some(VolumeState::Retired) {
            return Self::Retired;
        }
        let asserted = Validity::SERVING | Validity::LIVE;
        if state == Some(VolumeState::Active) && body.validity.bits() & asserted == asserted {
            return Self::Candidate;
        }
        match *receiver {
            Receiver::Newest(tenure, session)
                if body.tenure == Some(tenure) && tenure.host == responder =>
            {
                Self::Withdrawal(session)
            }
            _ => Self::Candidate,
        }
    }
}

/// The routes of at most `capacity` shards, shared by every client of an application through one `Arc`. A shard has no
/// route until a frame reaches it, and a route stays for the table's life, so `capacity` bounds the distinct shards the
/// sharing clients route over that life; [`held`](Self::held) counts them. One lock covers every route change, so each
/// compare and raise is one step. [`route`](Self::route) reads a Bound or Candidate route from the shard's slot
/// without the lock, and `binds` answers from the slot alone. `admit` returns from the slot for a response at the
/// Bound tenure or below the held `(g, a)`, and `reply` returns from the slot for a frame that merges as a candidate
/// and names the held tenure, a lower `(g, a)`, or no tenure (KEPT-WITHOUT-LOCK). Every other admission and ownership
/// frame that names a responder, a read of a route that holds no tenure, and every READY and count wait for the lock.
/// A full table refuses the frames of every shard outside it; [`refused`](Self::refused) counts those frames.
pub struct ShardRoutes {
    table: Mutex<Table>,
    slots: Box<[Slot]>,
    capacity: usize,
}

struct Table {
    /// The route state of the shard in the slot of the same index.
    entries: Box<[Entry]>,
    held: usize,
    /// Frames for shards the full table does not hold.
    refused: u64,
}

/// One shard's route and the session of the route's latest binding admission: a READY at the tenure the route was
/// then Bound to, or a response that moved the route to Bound. The two fill one cache line, which a merge under the
/// lock reads and writes together.
#[derive(Clone, Copy, Default)]
#[repr(align(64))]
struct Entry {
    route: Option<HighWater>,
    binder: Option<Binder>,
}

const _: () = assert!(size_of::<Entry>() == 64);

#[derive(Default)]
struct Slot {
    /// The shard, or 0 while the slot is vacant.
    shard: AtomicU32,
    binding: Binding,
}

/// Bit 0 of a published session word, set while the route is a Candidate of the recorded tenure. Every epoch is even,
/// so the bit is clear in every `(g, a)` session.
const CANDIDATE: u64 = 1;

/// The tenure a Bound or Candidate route holds, published for lock-free readers.
#[derive(Default)]
struct Binding<W = AtomicU64> {
    /// The session `g·2^32 + a` of the tenure the route is Bound to, that session with [`CANDIDATE`] set while the
    /// route is a Candidate of the tenure, or 0 while the route holds no tenure or a publish is storing the host words.
    session: W,
    host: [W; 2],
}

impl<W: SeqWord> Binding<W> {
    /// Publishes the tenure `route` holds, with [`CANDIDATE`] set for a Candidate route, or clears `session` for a
    /// Conflict or Dark route. A tenure that differs from the published words in `(g, a)` or host takes four steps:
    /// clear `session`, release fence, store the host words, store `session` with release ordering. The fence orders
    /// the clearing before the host stores, so a reader whose acquire load returns a new host word then loads 0 or a
    /// later session word. A route that keeps its tenure and changes between Candidate and Bound takes the last step
    /// alone, over host words that already hold that tenure's host. Callers serialize `publish`, as
    /// `ShardRoutes::update` does under the table's lock, so the relaxed loads that compare the published words
    /// return the words earlier publishes stored.
    fn publish(&self, route: HighWater) {
        let (tenure, mark) = match route {
            HighWater::Bound(tenure) => (tenure, 0),
            HighWater::Candidate(tenure) => (tenure, CANDIDATE),
            HighWater::Conflict { .. } | HighWater::Dark { .. } => {
                self.session.store(0, Ordering::Relaxed);
                return;
            }
        };
        let session = key(tenure.generation, tenure.epoch);
        let [low, high] = words(tenure.host);
        let recorded = self.session.load(Ordering::Relaxed) & !CANDIDATE == session
            && self.host[0].load(Ordering::Relaxed) == low
            && self.host[1].load(Ordering::Relaxed) == high;
        if !recorded {
            self.session.store(0, Ordering::Relaxed);
            W::fence_release();
            self.host[0].store(low, Ordering::Relaxed);
            self.host[1].store(high, Ordering::Relaxed);
        }
        self.session.store(session | mark, Ordering::Release);
    }

    /// The published session word and host words of one tenure, taken whole; `None` when the first session load finds
    /// no tenure or the second load returns another word.
    #[inline]
    fn read(&self) -> Option<(u64, [u64; 2])> {
        let session = self.session.load(Ordering::Acquire);
        if session == 0 {
            return None;
        }
        let host = [
            self.host[0].load(Ordering::Acquire),
            self.host[1].load(Ordering::Acquire),
        ];
        (self.session.load(Ordering::Relaxed) == session).then_some((session, host))
    }
}

#[inline]
fn words(host: Exhid) -> [u64; 2] {
    let id = identity(host);
    [id as u64, (id >> 64) as u64]
}

/// The route a published session word and host words record: Bound to their tenure, or a Candidate of it when the
/// word has [`CANDIDATE`] set. Every pair `Binding::read` returns decodes to `Some`.
#[inline]
fn recorded(session: u64, host: [u64; 2]) -> Option<HighWater> {
    let id = u128::from(host[0]) | (u128::from(host[1]) << 64);
    let held = session & !CANDIDATE;
    let tenure = Tenure {
        generation: ShardGeneration::new(held >> 32)?,
        epoch: ActivatedEpoch::new(held as u32)?,
        host: Exhid::new(id.to_ne_bytes()).ok()?,
    };
    Some(if session == held {
        HighWater::Bound(tenure)
    } else {
        HighWater::Candidate(tenure)
    })
}

/// Whether a candidate frame at `tenure` preserves a route that holds the published tenure, as a Candidate or Bound:
/// the frame names the published tenure or a lower `(g, a)`.
#[inline]
fn kept((session, host): (u64, [u64; 2]), tenure: Tenure) -> bool {
    let at = key(tenure.generation, tenure.epoch);
    let held = session & !CANDIDATE;
    at < held || (at == held && words(tenure.host) == host)
}

impl ShardRoutes {
    /// Bytes a table of `capacity` routes charges.
    pub fn charge(capacity: NonZeroU32) -> usize {
        table_len(capacity.get() as usize) * (size_of::<Slot>() + size_of::<Entry>())
    }

    /// A table of at most `capacity` routes, charging [`charge`](Self::charge) bytes.
    ///
    /// # Errors
    ///
    /// `EngineBudgetExceeded` with `budget` unchanged.
    pub fn new(
        capacity: NonZeroU32,
        budget: &mut EngineBudget,
    ) -> Result<Self, EngineBudgetExceeded> {
        budget.charge(Self::charge(capacity))?;
        let capacity = capacity.get() as usize;
        let len = table_len(capacity);
        Ok(Self {
            table: Mutex::new(Table {
                entries: vec![Entry::default(); len].into_boxed_slice(),
                held: 0,
                refused: 0,
            }),
            slots: std::iter::repeat_with(Slot::default).take(len).collect(),
            capacity,
        })
    }

    /// A poisoned lock still holds whole routes: each step stores one whole value.
    fn lock(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The shard's slot, found with relaxed loads: a slot holds one shard for the table's life, and the binding's own
    /// release and acquire order what a lock-free reader takes from it.
    #[inline]
    fn find(&self, shard: Shard) -> Result<usize, usize> {
        probe_by(
            &self.slots,
            spread(shard.get()),
            |slot| slot.shard.load(Ordering::Relaxed),
            |held| held == 0,
            |held| held == shard.get(),
        )
    }

    /// The session word and host words the shard's slot publishes, taken whole.
    #[inline]
    fn published(&self, shard: Shard) -> Option<(u64, [u64; 2])> {
        self.slots[self.find(shard).ok()?].binding.read()
    }

    /// The shard's route; `None` for a shard without one.
    #[inline]
    pub fn route(&self, shard: Shard) -> Option<HighWater> {
        match self
            .published(shard)
            .and_then(|(session, host)| recorded(session, host))
        {
            Some(route) => Some(route),
            None => self.held_route(shard),
        }
    }

    /// The index of the shard's slot, or `None` for a shard without a route. A slot holds one shard for the table's
    /// life, so the index names the shard's slot from then on.
    pub(crate) fn slot(&self, shard: Shard) -> Option<usize> {
        self.find(shard).ok()
    }

    /// Whether the shard's route is Bound to exactly `tenure`, which is whether [`route`](Self::route) returns
    /// `Some(HighWater::Bound(tenure))` for the shard. A slot that publishes a tenure answers from its words, and any
    /// other slot read answers from the route under the lock. The published words equal `tenure`'s exactly when they
    /// record a Bound route of it, since a Candidate's session word carries [`CANDIDATE`].
    ///
    /// `at` must be the index
    /// [`slot`](Self::slot) returned for `shard`; debug builds assert it.
    #[inline]
    pub(crate) fn bound_at(&self, at: usize, shard: Shard, tenure: Tenure) -> bool {
        debug_assert_eq!(self.find(shard), Ok(at));
        match self.slots[at].binding.read() {
            Some(held) => held == (key(tenure.generation, tenure.epoch), words(tenure.host)),
            None => self.held_route(shard) == Some(HighWater::Bound(tenure)),
        }
    }

    #[inline(never)]
    fn held_route(&self, shard: Shard) -> Option<HighWater> {
        let table = self.lock();
        self.find(shard).ok().and_then(|at| table.entries[at].route)
    }

    /// The routes the table holds.
    pub fn held(&self) -> usize {
        self.lock().held
    }

    /// The routes the table can hold.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Frames that reached a shard the full table does not hold, which therefore gets no route.
    pub fn refused(&self) -> u64 {
        self.lock().refused
    }

    /// Runs `step` on the shard's route and the binder of its latest binding admission under the table's lock, and
    /// stores what `step` leaves, publishing the route when `step` changed it. Returns what `step` returned and
    /// whether the route changed; `None`, counted in [`refused`](Self::refused), when the table is full and holds no
    /// route for the shard.
    fn update<R>(
        &self,
        shard: Shard,
        step: impl FnOnce(&mut Option<HighWater>, &mut Option<Binder>) -> R,
    ) -> Option<(R, bool)> {
        let mut table = self.lock();
        let at = match self.find(shard) {
            Ok(at) => at,
            Err(_) if table.held == self.capacity => {
                table.refused += 1;
                return None;
            }
            Err(at) => at,
        };
        let entry = &mut table.entries[at];
        let held = entry.route;
        let mut route = held;
        let out = step(&mut route, &mut entry.binder);
        let changed = route != held;
        if let Some(route) = route.filter(|_| changed) {
            entry.route = Some(route);
            let slot = &self.slots[at];
            slot.binding.publish(route);
            if held.is_none() {
                table.held += 1;
                slot.shard.store(shard.get(), Ordering::Relaxed);
            }
        }
        Some((out, changed))
    }

    /// Merges one authenticated frame of no session into the shard's route and returns the route; `None` for a shard
    /// the full table does not hold.
    #[cfg(test)]
    pub(crate) fn observe(&self, shard: Shard, frame: HolderFrame) -> Option<HighWater> {
        self.update(shard, |route, _| {
            let next = HighWater::merge(*route, frame);
            *route = Some(next);
            next
        })
        .map(|(route, _)| route)
    }

    /// Raises the shard's high-water to the response `tenure` of the session `binder` names and reports, in the same
    /// step, whether the route admits the response: it does when the route is then Bound to exactly `tenure`.
    /// Admission requires a route the table holds. A slot that publishes `tenure` as Bound admits, and a slot that
    /// publishes a tenure above `tenure`'s `(g, a)` refuses, each without the lock and without calling `binder`:
    /// under the lock either response leaves the route and its latest binder unchanged (KEPT-WITHOUT-LOCK). Every
    /// other response merges under the lock, and one that moves the route to Bound is a binding admission and records
    /// its session.
    #[inline]
    pub(crate) fn admit(
        &self,
        shard: Shard,
        tenure: Tenure,
        binder: impl FnOnce() -> Option<Binder>,
    ) -> bool {
        let at = (key(tenure.generation, tenure.epoch), words(tenure.host));
        match self.published(shard) {
            Some(held) if held == at => true,
            Some((session, _)) if at.0 < session & !CANDIDATE => false,
            _ => self.bind(shard, tenure, binder(), false),
        }
    }

    /// Merges the READY that activated the session `binder` names, as [`admit`](Self::admit) merges a response, and
    /// records that session as the route's latest binding admission whenever the route is then Bound to `tenure`,
    /// whether or not the READY moved it.
    pub(crate) fn ready(&self, shard: Shard, tenure: Tenure, binder: Option<Binder>) -> bool {
        self.bind(shard, tenure, binder, true)
    }

    #[inline]
    pub(crate) fn binds(&self, shard: Shard, tenure: Tenure) -> bool {
        self.published(shard) == Some((key(tenure.generation, tenure.epoch), words(tenure.host)))
    }

    #[inline(never)]
    fn bind(&self, shard: Shard, tenure: Tenure, binder: Option<Binder>, ready: bool) -> bool {
        let frame = HolderFrame {
            tenure,
            kind: FrameKind::Ready,
        };
        self.update(shard, |route, latest| {
            let before = *route;
            // `merge` returns a route Bound to `tenure` unchanged for a READY frame at `tenure`. Both a READY and a
            // response merge as that frame; the READY records its session and the response keeps the latest binder.
            if before == Some(HighWater::Bound(tenure)) {
                if ready {
                    *latest = binder;
                }
                return true;
            }
            let next = HighWater::merge(before, frame);
            *route = Some(next);
            let bound = next.response(tenure);
            if bound {
                *latest = binder;
            }
            bound
        })
        .is_some_and(|(bound, _)| bound)
    }

    /// Takes an authenticated ownership frame: a Holder, WrongOwner, Heartbeat or ProbeReply, with what its receiving
    /// session contributes. The frame merges for its responder by its volume and validity:
    ///
    /// - A retired volume merges as a retirement at the responder's tenure. That tenure is the one the frame names, or
    ///   else the route's held tenure or the receiver's bound tenure when either names the responder, since a host
    ///   holds one volume and so one generation.
    /// - An active volume asserting serving and liveness, under a tenure naming its responder, merges as a candidate.
    /// - Any other frame, one that names no volume or an active volume without both serving and liveness, says "do
    ///   not route". It merges as an invalid frame, which withdraws a binding at the tenure it names for its
    ///   responder, only under WITHDRAWAL-NEEDS-SESSION; otherwise it merges as a candidate, which keeps a binding
    ///   at that tenure and still raises a lower route.
    ///
    /// The frame's tenure for another host merges as a candidate. A tenure below the high-water keeps the route,
    /// another host at the held `(g, a)` makes a Conflict, and a higher tenure becomes the candidate unless the route
    /// is Dark at that tenure's generation or a later one. Returns whether the route changed; `None` when the full
    /// table does not hold the shard. A frame that merges as a candidate under any latest binder returns `Some(false)`
    /// without the lock when the shard's slot publishes a tenure and the frame names that tenure, a lower `(g, a)`,
    /// or no tenure (KEPT-WITHOUT-LOCK).
    ///
    /// WITHDRAWAL-NEEDS-SESSION: an invalid merge at the Bound tenure leaves a Candidate of that tenure, which a READY
    /// or an admitted response at the tenure binds again, so the binding's fate depends on the arrival order of the
    /// withdrawal and those binding admissions. A withdrawal takes effect only when the owner sent it after the
    /// route's latest binding admission, the one that arrived last. A
    /// binding admission is a READY at the tenure the route is then Bound to, from any sharing session and whether or
    /// not it moved the route, or a response that moved the route to Bound; the table records its session. The withdrawal's
    /// receiver is [`Receiver::Newest`] of that session, bound to the tenure the frame names for its responder. The
    /// owner numbers a session's frames in send order, so a frame that session admits above every sequence it had
    /// admitted was sent after every frame the session has taken; that it followed the session's READY rests on case
    /// 6 below. A session admits
    /// one READY, so a client regains the withdrawal by opening a session whose READY then arrives last, as a
    /// reopened session and a sharing client's new session each do. A copy, a frame its session overtook, a frame of an earlier session or client boot, and a frame
    /// of a session whose binding admission another session's followed keep the binding.
    ///
    /// The rule leaves seven arrival orders unordered:
    ///
    /// 1. A withdrawal from a session whose READY preceded another session's READY keeps the binding until its client
    ///    opens another session.
    /// 2. When two sessions' READYs arrive in the reverse of their send order, the earlier-sent READY is the latest
    ///    binding admission, so a withdrawal its owner sent between them takes effect.
    /// 3. A response another session receives on a route already Bound leaves the latest binder in place, so a
    ///    withdrawal the latest binder's owner sent before that response still takes effect.
    /// 4. When a response the owner sent before a withdrawal arrives after it, the response binds the withdrawn route
    ///    again, as every admitted response at the route's tenure does. Within one session the withdrawal's sequence
    ///    orders the two, and the route keeps only the binder; a response of another session has no client-side
    ///    order against the withdrawal.
    /// 5. When another session's READY arrives after a withdrawal, the READY binds the withdrawn route again, as every
    ///    READY at the route's tenure does, whatever order the owner sent the two in.
    /// 6. The owner's CONFIRM handler activates the session and then queues its READY, so a WrongOwner answering a
    ///    PROBE of that session can precede the READY and withdraw the binding that READY makes.
    /// 7. A withdrawn owner ends its sessions, so its own-tenure Holder is its last word and merges as a candidate;
    ///    the route stays Bound to a tenure that drops its requests until a higher tenure arrives.
    ///
    /// Ordering every case but the same-session form of case 4 needs the outstanding query the frame answers or a
    /// terminal withdrawal the owner sends; the client sends no query.
    pub(crate) fn reply(&self, body: &OwnershipBody<'_>, receiver: Receiver) -> Option<bool> {
        let Some(responder) = body.responder else {
            return Some(false);
        };
        if matches!(Claim::of(body, responder, &receiver), Claim::Candidate)
            && self
                .published(body.shard)
                .is_some_and(|held| body.tenure.is_none_or(|tenure| kept(held, tenure)))
        {
            return Some(false);
        }
        self.merge_reply(body, responder, &receiver)
    }

    /// Merges the ownership frame `body` of `responder` under the table's lock, as [`reply`](Self::reply) states.
    #[inline(never)]
    fn merge_reply(
        &self,
        body: &OwnershipBody<'_>,
        responder: Exhid,
        receiver: &Receiver,
    ) -> Option<bool> {
        let bound = match *receiver {
            Receiver::Unbound => None,
            Receiver::Bound(tenure) | Receiver::Newest(tenure, _) => Some(tenure),
        };
        let claim = Claim::of(body, responder, receiver);
        let named = body.tenure.filter(|tenure| tenure.host == responder);
        let other = body.tenure.filter(|tenure| tenure.host != responder);
        self.update(body.shard, |route, latest| {
            let kind = match claim {
                Claim::Retired => FrameKind::Retired,
                Claim::Withdrawal(session) if *latest == Some(session) => FrameKind::Invalid,
                Claim::Candidate | Claim::Withdrawal(_) => FrameKind::Candidate,
            };
            let own = match kind {
                FrameKind::Retired => named.or_else(|| {
                    let held = route.and_then(|held| match held {
                        HighWater::Candidate(tenure) | HighWater::Bound(tenure) => Some(tenure),
                        HighWater::Conflict { .. } | HighWater::Dark { .. } => None,
                    });
                    held.into_iter()
                        .chain(bound)
                        .find(|tenure| tenure.host == responder)
                }),
                _ => named,
            };
            if let Some(tenure) = own {
                *route = Some(HighWater::merge(*route, HolderFrame { tenure, kind }));
            }
            if let Some(tenure) = other {
                let candidate = HolderFrame {
                    tenure,
                    kind: FrameKind::Candidate,
                };
                *route = Some(HighWater::merge(*route, candidate));
            }
        })
        .map(|((), changed)| changed)
    }
}

#[cfg(test)]
#[path = "route_tests.rs"]
mod tests;

#[cfg(all(test, loom))]
#[path = "route_model.rs"]
mod route_model;
