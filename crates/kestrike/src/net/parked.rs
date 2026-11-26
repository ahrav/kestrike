//! Parked GETs: requests whose lookup proved the key missing and that joined
//! the key's fill in progress, waiting for its producer's terminal.
//!
//! Invariants owned by this module:
//!
//! - A parked GET is a live request of the one namespace, charged to its
//!   peer's share and the table like every GET, and admitted inside the GET
//!   reserves the owner's PUT caps leave free. Its table slot holds at most
//!   one parked entry, and a request is parked or bound to a read, never
//!   both.
//! - A join succeeds only while three counts are below their caps: the
//!   owner's parked total below `followers`, the peer's parked count below
//!   `peer_followers`, and the fill's observer count below `fill_followers`.
//!   The join raises the observer count under the fill's shard gate, and
//!   parking raises the other two. A GET that finds a
//!   joinable fill with any count at its cap ends `RequestPressure`, the
//!   status of every request-accounting cap the client retries after, and
//!   the report counts the cap. A GET whose lookup misses with no joinable fill
//!   ends `Missing`.
//! - A parked GET's deadline is its request's, `min(remaining, max_wait)`
//!   from admission; a duplicate only tightens it, and the deadline, a
//!   cancellation or a session retirement ends the request with its own
//!   cause. Ending changes only the request: the follower then detaches,
//!   which lowers the fill's observer count and reaches no producer state, so
//!   the producer's deadline and lifetime stay its own.
//! - The wake and detach pass visits only entries owed a visit, in slot
//!   order from a cursor that persists across turns and wraps, each entry at
//!   most once per pass; its visits and its checks of fills together number
//!   at most `wake` per turn. An entry is owed a
//!   visit when it joins, when its request ends, when its fill departs as
//!   the owner sees it (a PUT's publication, failure or abandonment, or a
//!   publication forwarded through the owner), when the owner's read
//!   admission changes, and when its last visit met a busy gate or a short
//!   budget. On turns whose allowance no check spends and while no further
//!   entry becomes owed, every owed entry is visited within
//!   `ceil(owed / wake)` turns, and the cursor reaches any owed entry within
//!   `ceil(slots / wake)` turns. A visit detaches an
//!   ended request's follower, or acquires the version the producer
//!   published and starts the request's read, or ends the request with the
//!   owner's admission status, its deadline, the producer's terminal, or the
//!   observation's, acquisition's or read's refusal, or leaves a pending,
//!   contended or budget-short follower parked in its slot. A visit to a
//!   live request that the owner admits and whose deadline has not passed
//!   observes its follower's fill under the shard gate, unless a check or an
//!   earlier visit of the same pass found that tracked fill pending; such a
//!   follower stays parked without a gate attempt. An ended request's slot is released only after its follower
//!   detached.
//! - The table tracks up to `TRACKED` followed fills with the set of their
//!   followers, so while every entry's fill is tracked a fill's departure
//!   owes visits to its followers alone. The owner sees a live PUT's
//!   departure and a publication forwarded through it; it learns every
//!   other departure by a check. A check falls due `CHECK_US` of turn time
//!   after the previous check's last pass and observes each tracked fill
//!   whose departure the owner does not see, through one of its followers,
//!   before the pass's owed visits. While visits are owed it takes half of
//!   each pass's allowance and the odd unit on every other such pass, so
//!   checks and owed visits both progress; a check whose fills outnumber
//!   its share continues over the following passes. A check owes a fill's
//!   followers a visit once the observation finds the fill no longer
//!   pending or meets a busy gate or a short budget. An entry whose fill is
//!   untracked makes each due check and each departure owe every entry a
//!   visit, and a turn with more PUT departures than one `Departed` names
//!   owes every entry a visit. A turn that unwound owes every entry a
//!   visit. A turn with no visit owed, no check under way or due, an
//!   unchanged admission and no PUT departure makes no visit.

use crate::index::ShardIndex;
use crate::storage::{FillFailure, FillFollower, JoinedReadError, Platform};

use super::datagram::PeerId;
use super::frame::Status;
use super::put::next_set;
use super::requests::RequestId;

/// Followed fills the parked table tracks with their followers, each place
/// costing one slot bitset; a follower of a further fill is untracked, and
/// its fill's departure or a due check owes every entry a visit.
const TRACKED: usize = 4;

/// Microseconds of turn time from a check's last pass to the next check's
/// start: a departure the owner does not see reaches its followers within
/// this period plus the turns the check and their visits take.
pub(super) const CHECK_US: u64 = 1_000;

/// The caps on parked GETs and the wake pass's per-turn visits. Zero
/// `followers` turns joins off: the owner reads with the plain key read, a
/// missed lookup ends `Missing`, and `fits` accepts any other field values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FollowConfig {
    /// Parked GETs the owner holds at once; its request slots bound them too.
    pub followers: u32,
    /// Followers one fill admits.
    pub fill_followers: u32,
    /// Parked GETs one peer holds at once; its request share bounds them too.
    pub peer_followers: u32,
    /// Visits to parked entries and observations of checked fills one
    /// turn's wake and detach pass makes.
    pub wake: u32,
}

impl FollowConfig {
    /// Joins off.
    pub const OFF: Self = Self {
        followers: 0,
        fill_followers: 0,
        peer_followers: 0,
        wake: 0,
    };

    /// Whether the caps are usable: with joins on, every cap and the wake
    /// allowance are positive.
    pub(super) fn fits(&self) -> bool {
        self.followers == 0 || (self.fill_followers > 0 && self.peer_followers > 0 && self.wake > 0)
    }

    fn table(&self, slots: u32, peers: u16) -> (u32, u16) {
        if self.followers == 0 {
            (0, 0)
        } else {
            (slots, peers)
        }
    }
}

/// Counters over the parked GETs' life.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParkedReport {
    /// GETs that joined a fill and parked.
    pub joined: u64,
    /// Parked GETs that acquired the published version and started a read.
    pub woke: u64,
    /// Parked GETs a wake visit ended: by the producer's terminal, the
    /// observation's or the acquisition's refusal, the read's refusal
    /// (`ForeignLease` before the acquisition or the read's own after it),
    /// or the wake-time admission and deadline checks.
    pub ended: u64,
    /// Followers detached because their own request ended first.
    pub detached: u64,
    /// GETs refused `RequestPressure` at the owner's total cap.
    pub total_saturated: u64,
    /// GETs refused `RequestPressure` at their peer's cap.
    pub peer_saturated: u64,
    /// GETs refused `RequestPressure` at their fill's cap.
    pub fill_saturated: u64,
    /// The most GETs parked at once.
    pub high_water: u32,
}

/// Which cap a join met.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Cap {
    Total,
    Peer,
    Fill,
}

/// A fill the parked table tracks.
#[derive(Debug, Clone, Copy)]
struct Tracked {
    /// The fill's shard and attempt serial.
    fill: (ShardIndex, u64),
    /// Parked entries that follow it.
    followers: u32,
    /// Whether its departure always reaches the owner, as a live PUT's does,
    /// so checks skip it; the first follower parked sets it.
    reported: bool,
    /// Whether a check or visit of the current pass found it pending.
    pending: bool,
}

/// The word of a slot bitset that holds `slot`, and `slot`'s bit in it.
fn bit(slot: usize) -> (usize, u64) {
    (slot / 64, 1 << (slot % 64))
}

/// The `k`th of the member bitsets `members` holds, each `words` words.
fn members_of(members: &[u64], words: usize, k: usize) -> &[u64] {
    &members[k * words..][..words]
}

/// [`members_of`], mutably.
fn members_of_mut(members: &mut [u64], words: usize, k: usize) -> &mut [u64] {
    &mut members[k * words..][..words]
}

/// One parked GET: its request, its peer and its follower.
pub(super) struct Entry<'s, P: Platform> {
    pub(super) request: RequestId,
    pub(super) peer: PeerId,
    pub(super) follower: FillFollower<'s, P>,
}

/// The owner's parked GETs, one entry at most per request slot.
pub(super) struct Parked<'s, P: Platform> {
    config: FollowConfig,
    entries: Box<[Option<Entry<'s, P>>]>,
    /// Bit `i` is set exactly while `entries[i]` holds an entry.
    bits: Box<[u64]>,
    count: u32,
    by_peer: Box<[u32]>,
    /// Bit `i` is set exactly while `entries[i]` is owed a visit.
    due: Box<[u64]>,
    /// Set bits in `due`.
    owed: u32,
    /// The tracked fills.
    fills: [Option<Tracked>; TRACKED],
    /// `TRACKED` bitsets of `bits.len()` words: bit `i` of the `k`th is set
    /// exactly while `entries[i]` follows `fills[k]`.
    members: Box<[u64]>,
    /// Parked entries whose fill is untracked.
    untracked: u32,
    /// Tracked fills not reported, plus `untracked`: while zero, no check
    /// falls due.
    watched: u32,
    /// Bit `k` is set while a check under way has yet to observe `fills[k]`.
    checking: u8,
    /// The turn time at which the next check falls due.
    check_at_us: u64,
    /// Which half of the allowance the check takes while visits are owed:
    /// the odd unit goes to the check on every other such pass.
    odd: bool,
    /// The owner's read admission at the last pass.
    admission: Result<(), Status>,
    /// The slot the next owed visit searches from.
    cursor: u32,
    /// The limit on `visits` in the current phase: during checks, the
    /// check's share of `wake` (all of it with no visit owed, else half with
    /// the odd unit alternating), capped at the fills to check; during owed visits, `wake` capped at
    /// the visits made plus the entries owed when the phase began, so the
    /// pass visits each entry at most once.
    pass: u32,
    /// Visits and check observations the current pass made, zero after a
    /// turn without a pass.
    visits: u32,
    report: ParkedReport,
    /// How each parked GET left the table, in order, for a test's view.
    #[cfg(test)]
    ends: Vec<(RequestId, End)>,
}

impl<'s, P: Platform> Parked<'s, P> {
    pub(super) fn new(config: FollowConfig, slots: u32, peers: u16) -> Self {
        let (slots, peers) = config.table(slots, peers);
        let words = (slots as usize).div_ceil(64);
        Self {
            config,
            entries: std::iter::repeat_with(|| None)
                .take(slots as usize)
                .collect(),
            bits: vec![0; words].into_boxed_slice(),
            count: 0,
            by_peer: vec![0; usize::from(peers)].into_boxed_slice(),
            due: vec![0; words].into_boxed_slice(),
            owed: 0,
            fills: [None; TRACKED],
            members: vec![0; TRACKED * words].into_boxed_slice(),
            untracked: 0,
            watched: 0,
            checking: 0,
            check_at_us: 0,
            odd: false,
            admission: Ok(()),
            cursor: 0,
            pass: 0,
            visits: 0,
            report: ParkedReport::default(),
            #[cfg(test)]
            ends: Vec::with_capacity(ENDS),
        }
    }

    /// Bytes [`new`](Self::new) allocates under `config` for `slots` and `peers`.
    pub(super) fn bytes(config: FollowConfig, slots: u32, peers: u16) -> usize {
        let (slots, peers) = config.table(slots, peers);
        slots as usize * size_of::<Option<Entry<'s, P>>>()
            + (2 + TRACKED) * (slots as usize).div_ceil(64) * size_of::<u64>()
            + usize::from(peers) * size_of::<u32>()
    }

    /// The follower limit a join by `peer` passes, and the cap that sets
    /// it to zero: the fill's cap while the owner's total and the peer's
    /// count are below theirs, else zero, which refuses any joinable fill.
    pub(super) fn limit(&self, peer: PeerId) -> (u64, Cap) {
        let peer_count = self.by_peer.get(usize::from(peer.0)).copied();
        if self.count >= self.config.followers {
            (0, Cap::Total)
        } else if peer_count.is_none_or(|count| count >= self.config.peer_followers) {
            (0, Cap::Peer)
        } else {
            (u64::from(self.config.fill_followers), Cap::Fill)
        }
    }

    /// Whether joins are on.
    pub(super) fn enabled(&self) -> bool {
        self.config.followers > 0
    }

    /// Counts a GET refused at `cap`.
    pub(super) fn saturated(&mut self, cap: Cap) {
        match cap {
            Cap::Total => self.report.total_saturated += 1,
            Cap::Peer => self.report.peer_saturated += 1,
            Cap::Fill => self.report.fill_saturated += 1,
        }
    }

    /// Whether no GET is parked.
    pub(super) fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Whether the pass of a turn at `now_us` under the owner's read
    /// `admission` has work: an owed visit, a check under way or due, or a
    /// changed admission.
    pub(super) fn has_work(&self, now_us: u64, admission: Result<(), Status>) -> bool {
        self.owed > 0 || self.checking != 0 || self.check_due(now_us) || admission != self.admission
    }

    /// Whether a check of the watched fills falls due at `now_us`.
    fn check_due(&self, now_us: u64) -> bool {
        self.watched > 0 && now_us >= self.check_at_us
    }

    /// Records a turn that ran no pass, so it made zero visits.
    pub(super) fn rest(&mut self) {
        self.visits = 0;
    }

    /// Parks `entry` in its request's slot, which [`limit`](Self::limit)
    /// admitted, and owes it a visit. `reported` follows
    /// [`put`](Self::put)'s contract.
    pub(super) fn park(
        &mut self,
        entry: Entry<'s, P>,
        reported: impl FnOnce((ShardIndex, u64)) -> bool,
    ) {
        self.report.joined += 1;
        let slot = usize::from(entry.request.slot());
        self.put(entry, reported);
        self.owe(slot);
        self.report.high_water = self.report.high_water.max(self.count);
    }

    /// Stores `entry` in its request's slot and counts it, as a follower of
    /// its tracked fill when the fill is tracked or a tracking place is free;
    /// `reported` says whether the fill's departure always reaches the
    /// owner, and runs only when the fill takes a free place, since a fill
    /// already tracked keeps its first follower's value.
    /// The caller owes the entry any visit it needs.
    pub(super) fn put(
        &mut self,
        entry: Entry<'s, P>,
        reported: impl FnOnce((ShardIndex, u64)) -> bool,
    ) {
        let slot = usize::from(entry.request.slot());
        debug_assert!(self.entries[slot].is_none(), "one entry per slot");
        let fill = (entry.follower.shard(), entry.follower.serial());
        let place = self
            .tracked(fill)
            .or_else(|| self.fills.iter().position(Option::is_none));
        match place {
            Some(k) => {
                let tracked = self.fills[k].get_or_insert_with(|| {
                    let reported = reported(fill);
                    self.watched += u32::from(!reported);
                    Tracked {
                        fill,
                        followers: 0,
                        reported,
                        pending: false,
                    }
                });
                tracked.followers += 1;
                let (word, bit) = bit(slot);
                members_of_mut(&mut self.members, self.bits.len(), k)[word] |= bit;
            }
            None => {
                self.untracked += 1;
                self.watched += 1;
            }
        }
        self.count += 1;
        self.by_peer[usize::from(entry.peer.0)] += 1;
        let (word, bit) = bit(slot);
        self.bits[word] |= bit;
        self.entries[slot] = Some(entry);
    }

    /// The entry parked in `slot`, which [`visit`](Self::visit) or
    /// [`check`](Self::check) returned.
    pub(super) fn entry(&self, slot: usize) -> &Entry<'s, P> {
        self.entries[slot]
            .as_ref()
            .expect("a visited slot holds a parked entry")
    }

    /// Removes the entry parked in `slot`, which [`visit`](Self::visit)
    /// returned, uncounts it and settles any visit it was owed; its fill's
    /// last follower frees the fill's tracking place.
    pub(super) fn take(&mut self, slot: usize) -> Entry<'s, P> {
        let (word, bit) = bit(slot);
        self.bits[word] &= !bit;
        if self.due[word] & bit != 0 {
            self.due[word] &= !bit;
            self.owed -= 1;
        }
        let entry = self.entries[slot]
            .take()
            .expect("a visited slot holds a parked entry");
        self.count -= 1;
        self.by_peer[usize::from(entry.peer.0)] -= 1;
        match self.follows(slot) {
            Some(k) => {
                members_of_mut(&mut self.members, self.bits.len(), k)[word] &= !bit;
                if let Some(tracked) = &mut self.fills[k] {
                    tracked.followers -= 1;
                    if tracked.followers == 0 {
                        self.watched -= u32::from(!tracked.reported);
                        self.fills[k] = None;
                        self.checking &= !(1 << k);
                    }
                }
            }
            None => {
                self.untracked -= 1;
                self.watched -= 1;
            }
        }
        entry
    }

    /// The tracking place of `fill`, a shard and a serial.
    fn tracked(&self, fill: (ShardIndex, u64)) -> Option<usize> {
        self.fills
            .iter()
            .position(|tracked| tracked.is_some_and(|tracked| tracked.fill == fill))
    }

    /// The tracking place of the fill the entry in `slot` follows.
    fn follows(&self, slot: usize) -> Option<usize> {
        let (word, bit) = bit(slot);
        (0..TRACKED).find(|&k| members_of(&self.members, self.bits.len(), k)[word] & bit != 0)
    }

    /// Owes a visit to the entry parked in `slot`; an empty slot stays
    /// unowed.
    pub(super) fn owe(&mut self, slot: usize) {
        let (word, bit) = bit(slot);
        if self.bits[word] & bit != 0 && self.due[word] & bit == 0 {
            self.due[word] |= bit;
            self.owed += 1;
        }
    }

    /// Owes a visit to each parked entry whose bit `slots` sets, one bit per
    /// request slot.
    fn owe_set(due: &mut [u64], owed: &mut u32, parked: &[u64], slots: &[u64]) {
        for ((due, parked), slots) in due.iter_mut().zip(parked).zip(slots) {
            let new = parked & slots & !*due;
            *due |= new;
            *owed += new.count_ones();
        }
    }

    /// Owes a visit to every parked entry whose request ended, as `ended`
    /// marks them, one bit per request slot.
    pub(super) fn owe_ended(&mut self, ended: &[u64]) {
        Self::owe_set(&mut self.due, &mut self.owed, &self.bits, ended);
    }

    /// Owes a visit to every parked entry, after a change that can end any
    /// wait: a changed read admission, a departure while some entry's fill is
    /// untracked, more PUT departures in a turn than one `Departed` names, an
    /// untracked entry's check, or an unwound turn. Ends any check under
    /// way, since the owed visits observe every fill it would.
    pub(super) fn owe_all(&mut self) {
        self.due.copy_from_slice(&self.bits);
        self.owed = self.due.iter().map(|word| word.count_ones()).sum();
        self.checking = 0;
    }

    /// Owes a visit to every follower of `fill`, a shard and a serial, after
    /// its departure: every entry while some entry's fill is untracked, since
    /// that entry can follow `fill` even when a later follower tracks it,
    /// else the tracked fill's followers.
    pub(super) fn departed(&mut self, fill: (ShardIndex, u64)) {
        if self.untracked > 0 {
            self.owe_all();
        } else if let Some(k) = self.tracked(fill) {
            self.owe_followers(k);
        }
    }

    /// Owes a visit to every follower of the fill the entry in `slot`
    /// follows, after a check found that fill no longer pending or met a
    /// busy gate or a short budget: every entry while some entry's fill is
    /// untracked, as [`departed`](Self::departed) owes them.
    pub(super) fn owe_fill_of(&mut self, slot: usize) {
        match self.follows(slot) {
            Some(k) if self.untracked == 0 => self.owe_followers(k),
            _ => self.owe_all(),
        }
    }

    /// Owes a visit to every follower of `fills[k]`.
    fn owe_followers(&mut self, k: usize) {
        let members = members_of(&self.members, self.bits.len(), k);
        Self::owe_set(&mut self.due, &mut self.owed, &self.bits, members);
    }

    /// Starts the pass of a turn at `now_us` under the owner's read
    /// `admission`. A changed admission owes every entry a visit. A check
    /// that falls due at `check_at_us` while none is under way marks every
    /// tracked fill not reported for observation, or owes every entry a
    /// visit while some entry's fill is untracked. The pass then takes its
    /// check observations from [`check`](Self::check) and, after
    /// [`begin_visits`](Self::begin_visits), its owed visits from
    /// [`visit`](Self::visit), all within `wake`; while visits are owed the
    /// check takes half the allowance, the odd unit on every other such
    /// pass. The next check falls due `CHECK_US` after the check's last
    /// pass. Clears the last pass's pending observations.
    pub(super) fn begin_pass(&mut self, now_us: u64, admission: Result<(), Status>) {
        if admission != self.admission {
            self.admission = admission;
            self.owe_all();
        }
        if self.checking == 0 && self.check_due(now_us) {
            self.check_at_us = now_us.saturating_add(CHECK_US);
            if self.untracked == 0 {
                self.checking = (0..TRACKED)
                    .filter(|&k| self.fills[k].is_some_and(|tracked| !tracked.reported))
                    .fold(0, |checking, k| checking | 1 << k);
            } else {
                self.owe_all();
            }
        }
        if self.checking != 0 {
            // The next period starts at the check's last pass, so checks leave every period's later turns to owed visits.
            self.check_at_us = now_us.saturating_add(CHECK_US);
        }
        // With visits owed a check takes half the allowance, and the odd unit on every other pass, so both progress at any `wake`.
        let share = if self.owed == 0 {
            self.config.wake
        } else {
            self.odd = !self.odd;
            let wake = self.config.wake;
            wake / 2 + ((wake % 2) & u32::from(self.odd))
        };
        self.pass = share.min(self.checking.count_ones());
        self.visits = 0;
        for tracked in self.fills.iter_mut().flatten() {
            tracked.pending = false;
        }
    }

    /// The slot of a follower of the next fill the check under way observes,
    /// if the pass has visits left: a tracked fill still not reported. Each
    /// returned slot spends one visit; the caller observes the fill and
    /// records the result with [`note_pending`](Self::note_pending) or
    /// [`owe_fill_of`](Self::owe_fill_of).
    pub(super) fn check(&mut self) -> Option<usize> {
        while self.checking != 0 && self.visits < self.pass {
            let k = self.checking.trailing_zeros() as usize;
            self.checking &= self.checking - 1;
            if self.fills[k].is_some_and(|tracked| !tracked.reported) {
                self.visits += 1;
                let members = members_of(&self.members, self.bits.len(), k);
                return next_set(members, 0).map(|slot| slot as usize);
            }
        }
        None
    }

    /// Starts the pass's owed visits after its checks: they stay within
    /// `wake` together with the checks and at most the entries owed now, so
    /// the pass visits each entry at most once. A check with fills left
    /// resumes at the next pass.
    pub(super) fn begin_visits(&mut self) {
        self.pass = self.config.wake.min(self.visits + self.owed);
    }

    /// The slot of the next owed entry the pass visits, if the pass has
    /// visits left, moving the cursor past it and settling its owed visit.
    /// The entry stays parked until [`take`](Self::take) removes it.
    pub(super) fn visit(&mut self) -> Option<usize> {
        if self.visits >= self.pass {
            return None;
        }
        let slot = next_set(&self.due, self.cursor).or_else(|| next_set(&self.due, 0))?;
        self.cursor = slot + 1;
        self.visits += 1;
        let slot = slot as usize;
        let (word, bit) = bit(slot);
        self.due[word] &= !bit;
        self.owed -= 1;
        Some(slot)
    }

    /// Whether a check or visit of the current pass found the fill that the
    /// entry in `slot` follows pending; `false` for an untracked entry.
    pub(super) fn found_pending(&self, slot: usize) -> bool {
        self.follows(slot)
            .and_then(|k| self.fills[k])
            .is_some_and(|tracked| tracked.pending)
    }

    /// Records that a check or visit of the current pass found the fill that
    /// the entry in `slot` follows pending; a tracked fill alone records it.
    pub(super) fn note_pending(&mut self, slot: usize) {
        if let Some(tracked) = self.follows(slot).and_then(|k| self.fills[k].as_mut()) {
            tracked.pending = true;
        }
    }

    /// Whether `id` is parked.
    pub(super) fn holds(&self, id: RequestId) -> bool {
        self.entries
            .get(usize::from(id.slot()))
            .is_some_and(|entry| entry.as_ref().is_some_and(|entry| entry.request == id))
    }

    #[cfg_attr(not(test), expect(unused_variables))]
    pub(super) fn woke(&mut self, id: RequestId) {
        self.report.woke += 1;
        #[cfg(test)]
        self.end(id, End::Woke);
    }

    /// Counts a visit that ended request `id` with `status`.
    #[cfg_attr(not(test), expect(unused_variables))]
    pub(super) fn ended(&mut self, id: RequestId, status: Status) {
        self.report.ended += 1;
        #[cfg(test)]
        self.end(id, End::Ended(status));
    }

    #[cfg_attr(not(test), expect(unused_variables))]
    pub(super) fn detached(&mut self, id: RequestId) {
        self.report.detached += 1;
        #[cfg(test)]
        self.end(id, End::Detached);
    }

    pub(super) fn report(&self) -> ParkedReport {
        self.report
    }

    /// Records how `id` left the table while the record has room, so the
    /// record never allocates during a turn.
    #[cfg(test)]
    fn end(&mut self, id: RequestId, end: End) {
        if self.ends.len() < ENDS {
            self.ends.push((id, end));
        }
    }

    /// The parked count, for a test's per-turn checks.
    #[cfg(test)]
    pub(super) fn count(&self) -> u32 {
        self.count
    }

    /// Visits and check observations the last pass made, for the
    /// turn-allowance checks.
    #[cfg(test)]
    pub(super) fn visits(&self) -> u32 {
        self.visits
    }

    /// Checks the due set and the fill tracking against the entries: `due`
    /// and every member set lie within the parked bits, `owed` counts `due`,
    /// each entry follows at most one tracked fill and that fill is the
    /// entry's own, each tracked fill's count equals its members, and
    /// `untracked` and `watched` match the entries and fills they count.
    #[cfg(test)]
    pub(super) fn check_tracking(&self) -> Result<(), String> {
        let words = self.bits.len();
        let ones = |set: &[u64]| set.iter().map(|word| word.count_ones()).sum::<u32>();
        let within = |set: &[u64]| {
            set.iter()
                .zip(&self.bits)
                .all(|(set, bits)| set & !bits == 0)
        };
        if !within(&self.due) || ones(&self.due) != self.owed {
            return Err(format!("owed {} beside the due set", self.owed));
        }
        let mut untracked = 0;
        for (slot, entry) in self.entries.iter().enumerate() {
            let Some(entry) = entry else { continue };
            let (word, bit) = bit(slot);
            let places: Vec<usize> = (0..TRACKED)
                .filter(|&k| members_of(&self.members, words, k)[word] & bit != 0)
                .collect();
            let fill = (entry.follower.shard(), entry.follower.serial());
            match places.as_slice() {
                [] => untracked += 1,
                [k] if self.fills[*k].is_some_and(|tracked| tracked.fill == fill) => {}
                _ => return Err(format!("slot {slot} follows places {places:?}")),
            }
        }
        for k in 0..TRACKED {
            let members = members_of(&self.members, words, k);
            let followers = self.fills[k].map_or(0, |tracked| tracked.followers);
            if !within(members) || ones(members) != followers {
                return Err(format!("place {k} counts {followers} followers"));
            }
        }
        let unreported = self
            .fills
            .iter()
            .flatten()
            .filter(|tracked| !tracked.reported)
            .count() as u32;
        if untracked != self.untracked || self.watched != unreported + untracked {
            return Err(format!(
                "untracked {} and watched {} beside {untracked} untracked entries",
                self.untracked, self.watched
            ));
        }
        Ok(())
    }

    /// The parked state a test observes: each entry's request, peer and
    /// fill observer count in slot order, the cursor, the total and each
    /// peer's count, and how each GET that left the table left it; the
    /// owner adds each entry's deadline.
    #[cfg(test)]
    pub(super) fn view(&self) -> ParkedView {
        ParkedView {
            ends: self.ends.clone(),
            deadlines: Vec::new(),
            entries: self
                .entries
                .iter()
                .flatten()
                .map(|entry| (entry.request, entry.peer, entry.follower.observers()))
                .collect(),
            cursor: self.cursor,
            count: self.count,
            owed: self.owed,
            by_peer: self.by_peer.to_vec(),
        }
    }
}

/// The ends a test's view records, the first this many.
#[cfg(test)]
const ENDS: usize = 64;

/// How a parked GET left the table: its read started, a visit ended it
/// with its cause, or its own end detached its follower.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum End {
    Woke,
    Ended(Status),
    Detached,
}

/// See [`Parked::view`].
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ParkedView {
    pub(super) entries: Vec<(RequestId, PeerId, u64)>,
    /// Each entry's request deadline, in the entries' order.
    pub(super) deadlines: Vec<u64>,
    pub(super) ends: Vec<(RequestId, End)>,
    pub(super) cursor: u32,
    pub(super) count: u32,
    /// Entries owed a visit.
    pub(super) owed: u32,
    pub(super) by_peer: Vec<u32>,
}

/// What a wake visit does with a follower's observation or acquisition refusal: `None`
/// leaves it parked for a later pass, else the request ends with this
/// status, and whether a correct owner never sees it.
pub(super) fn joined_status(error: JoinedReadError) -> Option<(Status, bool)> {
    Some(match error {
        // A busy gate can spend a visit's work allowance as it spends its
        // tries; the request's deadline bounds the visits that follow.
        JoinedReadError::Pending
        | JoinedReadError::Contended
        | JoinedReadError::BudgetExhausted => return None,
        JoinedReadError::Missing => (Status::Missing, false),
        JoinedReadError::Failed(failure) => (failure_status(failure), false),
        JoinedReadError::Expired => (Status::Expired, false),
        JoinedReadError::ClockUnavailable => (Status::ClockUnavailable, false),
        JoinedReadError::Closed => (Status::Closed, false),
        // The read credit reserves within no lease limit, so a correct
        // owner never sees it.
        JoinedReadError::LeaseLimit => (Status::LeasePressure, true),
        // The object's rights are full.
        JoinedReadError::RetainLimit => (Status::ObjectPressure, false),
        JoinedReadError::Corrupt => (Status::OwnerUnavailable, true),
    })
}

/// The status a producer's recorded failure carries to its followers: the
/// status the producer's upload ended with, the inverse of
/// [`fill_failure`](super::put::fill_failure).
pub(super) fn failure_status(failure: FillFailure) -> Status {
    match failure {
        FillFailure::DeviceError => Status::DeviceError,
        FillFailure::TimedOut => Status::TimedOut,
        FillFailure::Closed => Status::Closed,
        FillFailure::OwnerUnavailable => Status::OwnerUnavailable,
        FillFailure::ClockUnavailable => Status::ClockUnavailable,
        FillFailure::Contended => Status::Contended,
        FillFailure::StoragePressure => Status::StoragePressure,
        FillFailure::ObjectPressure => Status::ObjectPressure,
    }
}

/// A fault a test plants in the parked path, for the controls that must
/// fail the follower-independence checks.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Plant {
    None,
    /// Detaching a follower also invalidates its key, ending the producer.
    DetachAborts,
    /// A duplicate GET moves its live request's deadline later.
    DuplicateExtends,
    /// An ended request's follower stays parked and its slot releases.
    ReleaseParked,
}

#[cfg(test)]
thread_local! {
    pub(super) static PLANT: std::cell::Cell<Plant> = const { std::cell::Cell::new(Plant::None) };
}

/// Whether `plant` is planted on this thread.
#[cfg(test)]
pub(super) fn planted(plant: Plant) -> bool {
    PLANT.with(|cell| cell.get() == plant)
}
