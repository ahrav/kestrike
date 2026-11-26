//! The mutation suffix of one tenure: the appender that packs membership mutations into delta blocks under the
//! capture mutex and refuses an append before its acknowledgment when the promise it would make cannot be kept.
//!
//! - SEQ-IS-LINEARIZATION: records take dense sequence numbers in append order under the capture mutex, which every
//!   membership change and capture start holds, so a cut sealed at `t0` lies between two records.
//! - UNIQUE-BLOCK: a log opens once, a sealed block takes the next LSN once and keeps its payload, which every
//!   attempt encodes to the same unit bytes, and one write is outstanding at a time, so a valid block proves every
//!   earlier block was written.
//! - BARRIER-GATED-REUSE: the tenure's LSNs lie below `min(floor, start) + J`, `J` the layout's delta blocks and
//!   `floor` the lowest LSN a replay of the settled record reads. LSN `L` reuses the unit of `L - J`, below the floor
//!   and the start: an earlier tenure wrote it and its fence ended that write. A tenure writes at most `J` blocks.
//! - REFUSE-BEFORE-ACK: every refusal precedes any change. An append also refuses once its last block would lie
//!   `uncertified` blocks past the certified end, so the records a replay could count as unflushed tail stay bounded. A
//!   publication is refused when the bound on the set a replay could rebuild after it lies past the layout's entry cap
//!   `N_max` ([`past_entry_cap`](SuffixLog::past_entry_cap)). A replay keeps at most one entry for each slot of the
//!   pool, and the cap counts a checkpoint's extent rows at its placement and its entries, at most one per row, at a
//!   warm load. For a record that names a checkpoint and suffixes of this tenure alone the bound is the extent rows of
//!   the membership the publication leaves. Every entry a replay of that record keeps was a member when the last record
//!   the replay reads was appended, and the tenure's next checkpoint holds every member at its cut, a row for each of
//!   its extents, among them a member whose fill preceded the suffix's open and which the stored record does not hold.
//!   A publication is therefore refused while the membership it leaves holds rows past the cap, also when a replay of
//!   the stored record alone would stay within it. A tenure whose record names a checkpoint or a suffix of another
//!   tenure ([`inherits`](SuffixLog::inherits)) cannot count what a later load rebuilds from them: its warm load omits
//!   entries the record keeps, and it takes a suffix block it misread for the unflushed tail, which a later load can
//!   read with the removals and inserts it holds. Its bound is the slot count until a store step reads a record that
//!   names a checkpoint and suffixes of this tenure alone, and at least the membership's rows, so under an entry cap
//!   below the slot count it records no insert until then. So the set a replay rebuilds after every recorded
//!   publication stays within the entry cap of a checkpoint slot and of the warm load, and a layout whose entry cap
//!   covers the pool's slots refuses no publication of members of one extent under this rule.
//! - ONE-SLOT-COUNT, the deployment's obligation, on which the bound of an inheriting tenure rests: Every tenure that
//!   can write or read a volume's retained history runs one effective pool slot count, and that count is at most the
//!   volume layout's entry cap. No code enforces either half. With pools of different counts a successor can
//!   acknowledge a fill that makes a later load refuse `Entries`, and a smaller successor can refuse a larger writer's
//!   history.
//! - HOLD-UNTIL-DURABLE, the caller's obligation: an append returns the position of its record's last block, and the
//!   caller holds a retired slot until [`reusable`](super::reusable) admits that position against
//!   [`durable`](SuffixLog::durable). A refused removal removes nothing, so its entry stays live.

use std::collections::VecDeque;

use crate::net::ownership::Shard;

use super::super::record::Crc32c;
#[cfg(test)]
use super::delta::Record;
use super::delta::{Block, Change, Frame, Packer, UNIT_LEN, blocks, seal_into};
use super::durable::{LSN_LIMIT, advance, position};
use crate::failover::records::{Layout, Suffix};

/// The admission bounds of a tenure's suffix, in nanoseconds of the clock `record` and `flush_due` read. `queue_blocks`,
/// `uncertified` and the region's `J` are each at least the five blocks a REPLACE of `EXTENT_LIMIT` extents spans
/// from an empty block, or that record refuses `Body` on every attempt; admitting it also needs queue room for the
/// blocks already pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuffixLimits {
    /// An open block is sealed once its oldest record is this old.
    pub flush_ns: u64,
    /// Most blocks not yet durable, the open block included.
    pub queue_blocks: usize,
    /// An append is refused while a block older than this is not durable; above `flush_ns`.
    pub oldest_ns: u64,
    /// Most blocks above the certified end: an append whose last block would lie at or past the certified end plus
    /// this is refused, so the acknowledged records a replay could count as an unflushed tail stay bounded.
    pub uncertified: u64,
}

impl SuffixLimits {
    pub fn bounded(&self) -> bool {
        self.queue_blocks > 0 && self.uncertified > 0 && self.oldest_ns > self.flush_ns
    }
}

/// A tenure's suffix blocks not yet durable, of the queue bound, and the age in nanoseconds of the oldest one's first
/// record on the clock the log's appends read: 0 when every block is durable, `None` when the clock sample failed or
/// read earlier than that record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuffixBacklog {
    pub blocks: u64,
    pub limit: u64,
    pub age_ns: Option<u64>,
}

/// Why an append was refused. A refusal changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuffixRefusal {
    Closed,
    /// The record never fits: no body, more blocks than the queue, the region or the uncertified bound holds, or
    /// parts past `u16::MAX`.
    Body,
    /// The record's last block would pass the tenure's `J` blocks, which a handoff to a new tenure clears, or
    /// `LSN_LIMIT`.
    Exhausted,
    /// The record's last block would reach the capacity; a settled publication raising the floor clears it.
    Capacity,
    /// The record's last block would reach the reserved end; an extension clears it.
    Reserved,
    /// The record's last block would lie `uncertified` or more blocks past the certified end; writing the waiting
    /// blocks and then certifying the durable prefix clears it.
    Uncertified,
    /// The queue holds its bound of blocks; a write clears it.
    Queue,
    /// A record has waited unflushed past the stall bound; sealing the open block and writing it clears it.
    Stalled,
}

/// Whether the planted defect that drops the queue check is set; false outside tests.
fn unbounded_queue() -> bool {
    #[cfg(test)]
    return NO_QUEUE.with(std::cell::Cell::get);
    #[cfg(not(test))]
    false
}

#[cfg(test)]
thread_local! {
    /// A planted defect: an append ignores the queue bound.
    pub(crate) static NO_QUEUE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A planted defect: the capacity ignores the floor, so the tenure's blocks reuse units of history a replay of
    /// the settled record still reads, as a release of that history by elapsed time would allow.
    pub(crate) static FLOORLESS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A sealed block awaiting durability, with the time its first record was appended. The delta writer's
/// [`take_within`](SuffixLog::take_within) encodes the unit from the payload into the buffer of each write attempt.
#[derive(Debug)]
struct Sealed {
    lsn: u64,
    since: u64,
    payload: Vec<u8>,
}

/// The appender; see the module documentation. `Default` is the unopened, unrequired log, which refuses every append
/// and seals a cut at LSN 0. A warm install and a proof `cut_intact` returns require the log, so every logical membership
/// change is recorded or refused from then on, and the tenure opens it once its record names a checkpoint, which
/// for a tenure with none is after its first Publish.
#[derive(Debug, Default)]
pub struct SuffixLog {
    /// The limits and the region's `J`, while admission is open.
    open: Option<(SuffixLimits, u64)>,
    /// Whether the tenure's membership changes need this log: set by [`require`](Self::require) or an open and kept
    /// by a close, so while it is set every logical membership change is recorded or refused.
    required: bool,
    /// The region's `J`, its first prefix unit, `1 + K·S`, and the flush interval, kept after a close so sealed
    /// blocks keep draining at the same pace.
    region: (u64, u64, u64),
    /// The block identity's crc and shard, kept after a close so the sealed blocks still encode.
    identity: Option<(Crc32c, Shard)>,
    /// The entry cap `N_max` of the layout the log opened over; `0` before the open.
    entry_cap: u64,
    /// Whether the store's record names a checkpoint or a suffix of another tenure, whose replay this tenure cannot
    /// count: set by [`inherits`](Self::inherits).
    inherited: bool,
    session: u64,
    /// The tenure's first LSN, the open block's, the reserved end and the capacity.
    start: u64,
    head: u64,
    reserved: u64,
    capacity: u64,
    seq: u64,
    packer: Packer,
    /// The buffer an appended entry's overlap check sorts in, kept for its capacity.
    spans: Vec<u64>,
    /// When the open block's first record was appended.
    opened: Option<u64>,
    sealed: VecDeque<Sealed>,
    outstanding: Option<u64>,
    durable: u64,
    /// The end the store records as certified for this tenure's suffix.
    certified: u64,
}

impl SuffixLog {
    /// Opens an unopened log at `suffix`, the tenure's recorded suffix whose `end` is the reserved end and whose
    /// `certified` is the certified end, over the delta region of `layout` and required history from `floor`, and
    /// returns whether admission opened. Limits with no queue block or no uncertified block, a layout with no delta
    /// block, a stall bound at or below the flush interval, a suffix of session 0 or one certified past its start,
    /// whose blocks this log never wrote, place the log at `suffix.start` with admission closed and leave it
    /// unopened, still required when it was. A used log is unchanged.
    pub fn open(
        &mut self,
        (crc, shard): (Crc32c, Shard),
        (limits, layout): (SuffixLimits, &Layout),
        suffix: Suffix,
        floor: u64,
    ) -> bool {
        if !self.place(suffix.start) {
            return false;
        }
        let j = blocks(layout);
        let bounded = limits.bounded() && j > 0;
        let valid = bounded && suffix.session != 0 && suffix.certified == suffix.start;
        if valid {
            self.open = Some((limits, j));
            self.required = true;
            self.session = suffix.session;
            self.region = (j, layout.units - j, limits.flush_ns);
            self.identity = Some((crc, shard));
            self.entry_cap = u64::from(layout.entries);
        }
        self.covered(floor);
        self.extend(suffix.end);
        valid
    }

    /// Sets the first LSN, head, durable prefix and certified end of a log that never opened to `start` and returns
    /// `true`; returns `false` and changes nothing for a log that opened or holds a block.
    pub fn place(&mut self, start: u64) -> bool {
        let unopened = self.session == 0 && self.sealed.is_empty() && self.outstanding.is_none();
        if unopened {
            (self.start, self.head) = (start, start);
            (self.durable, self.certified) = (start, start);
        }
        unopened
    }

    /// Marks the tenure's history required before the log opens: from now on every logical membership change is
    /// recorded once the log opens, and refused `Closed` until then and after a close.
    pub fn require(&mut self) {
        self.required = true;
    }

    /// Whether every logical membership change must be recorded or refused: the log was required or opened.
    pub fn required(&self) -> bool {
        self.required
    }

    /// Records whether the store's record names a checkpoint or a suffix of another tenure, `inherited`. The
    /// membership of a tenure that loaded such a record warm is what one load restored, and a later load of the
    /// record can rebuild other entries: those the conversion omitted, those of a checkpoint unit that failed its
    /// checks, and those of a suffix block the load took for the unflushed tail. While `inherited`,
    /// [`past_entry_cap`](Self::past_entry_cap) bounds the replayed set by the pool's slot count. For a record
    /// that names a checkpoint and suffixes of this tenure alone the bound is the membership: a replay of it keeps
    /// only entries that were members, and the tenure's next checkpoint holds every member at its cut.
    pub fn inherits(&mut self, inherited: bool) {
        self.inherited = inherited;
    }

    /// Whether the bound on the set a replay could rebuild, after a publication that leaves a membership of `rows`
    /// extent rows in a pool of `slots` slots, lies past the entry cap of the layout the open log records over. The
    /// cap counts rows at a checkpoint's placement and entries, at most one per row, at a warm load; no checkpoint
    /// slot holds a set past it and no warm load admits one, so the publication is refused before any change. The
    /// bound is `rows` for a record of this tenure alone, which covers a replay of the stored record and the
    /// tenure's next checkpoint of its membership. While the record names a checkpoint or a suffix of another
    /// tenure it is also at least `slots`, the entries a replay keeps, which share no slot. False while admission
    /// is not open, when `record` refuses every change.
    pub fn past_entry_cap(&self, rows: u64, slots: usize) -> bool {
        let replayed = if self.inherited {
            rows.max(slots as u64)
        } else {
            rows
        };
        self.open.is_some() && replayed > self.entry_cap
    }

    /// Closes admission and drops the open block with every record in it; the sealed blocks keep draining through
    /// [`take_within`](Self::take_within) and [`written`](Self::written). The log stays required.
    pub fn close(&mut self) {
        (self.open, self.opened, self.packer) = (None, None, Packer::default());
    }

    /// Raises the capacity to `min(floor, start) + J` for `floor`, the floor a settled record names.
    pub fn covered(&mut self, floor: u64) {
        #[cfg(test)]
        let floor = if FLOORLESS.with(std::cell::Cell::get) {
            u64::MAX
        } else {
            floor
        };
        if let Some((_, j)) = self.open {
            let capacity = floor.min(self.start).saturating_add(j);
            self.capacity = self.capacity.max(capacity.min(LSN_LIMIT + 1));
        }
    }

    /// Raises the reserved end to `end`, bounded by the capacity, after the store recorded it.
    pub fn extend(&mut self, end: u64) {
        self.reserved = self.reserved.max(end.min(self.capacity));
    }

    /// The LSN of the open block: the next block sealed takes it.
    pub fn head(&self) -> u64 {
        self.head
    }

    /// The suffix the log admits against: its session, start, certified end and reserved end.
    pub fn recorded(&self) -> Suffix {
        Suffix {
            session: self.session,
            start: self.start,
            certified: self.certified,
            end: self.reserved,
        }
    }

    #[cfg(test)]
    pub fn reserved(&self) -> u64 {
        self.reserved
    }

    /// Every block of the tenure below this LSN is durable.
    pub fn durable(&self) -> u64 {
        self.durable
    }

    /// With admission open, the pending blocks (including the open block), the `queue_blocks` limit, and the oldest
    /// pending block's age at the time `now` samples, a raw difference on the nanosecond clock that `append` and
    /// `flush_due` read, which differs from `take_within`'s poll tick. `now` runs only when a block is pending; with
    /// every block durable the age reads 0, and a failed sample or one earlier than the oldest block's first record
    /// reads the age `None`.
    pub fn backlog(&self, now: impl FnOnce() -> Option<u64>) -> Option<SuffixBacklog> {
        let (limits, _) = self.open?;
        Some(SuffixBacklog {
            blocks: self.sealed.len() as u64 + u64::from(self.opened.is_some()),
            limit: limits.queue_blocks as u64,
            age_ns: match self.oldest_pending() {
                Some(since) => now().and_then(|now| now.checked_sub(since)),
                None => Some(0),
            },
        })
    }

    /// When the oldest block not yet durable took its first record: the front sealed block, else the open block.
    fn oldest_pending(&self) -> Option<u64> {
        (self.sealed.front().map(|block| block.since)).or(self.opened)
    }

    /// Whether admission is open: an append is recorded or refused, never left unrecorded.
    #[cfg(test)]
    pub fn is_open(&self) -> bool {
        self.open.is_some()
    }

    /// The sequence number the next appended record takes.
    #[cfg(test)]
    pub fn next_seq(&self) -> u64 {
        self.seq
    }

    /// Raises the certified end to `end`, at most the durable prefix, after the store recorded it.
    pub fn certified(&mut self, end: u64) {
        self.certified = self.certified.max(end.min(self.durable));
    }

    /// Whether the log holds no record: no open block and no block awaiting durability.
    pub fn idle(&self) -> bool {
        self.opened.is_none() && self.sealed.is_empty()
    }

    /// Whether a sealed block waits for its write and none is outstanding: the delta write goes before any
    /// checkpoint-unit command.
    pub fn pending(&self) -> bool {
        self.outstanding.is_none() && !self.sealed.is_empty()
    }

    /// The prefix unit that holds LSN `lsn`: `1 + K·S + lsn mod J`; `None` for a log that never opened.
    pub fn unit(&self, lsn: u64) -> Option<u64> {
        let (j, first, _) = self.region;
        (j > 0).then(|| first + lsn % j)
    }

    /// When the delta writer must next look at the log: now for a sealed block waiting for its write, the open
    /// block's flush time once it holds records, and `None` while the log holds no record or only the outstanding
    /// write, whose terminal wakes the writer.
    pub fn due(&self) -> Option<u64> {
        if self.pending() {
            return Some(0);
        }
        self.opened
            .map(|opened| opened.saturating_add(self.flush_ns()))
    }

    /// Whether the tenure should publish a checkpoint: the reserved end reached the capacity a settled floor
    /// allows, which lies below `start + J`, and the head is within `margin` blocks of it; only a settled publish
    /// raising the floor clears it.
    pub fn publication_due(&self, margin: u64) -> bool {
        self.open.is_some_and(|(_, j)| {
            self.reserved >= self.capacity
                && self.capacity < self.exhausted(j)
                && self.head.saturating_add(margin) >= self.capacity
        })
    }

    /// The flush interval, `0` for a log that never opened; a close keeps it.
    pub fn flush_ns(&self) -> u64 {
        self.region.2
    }

    /// The highest end the log admits: `min(floor, start) + J` for the settled floor.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Whether the tenure should hand off: the head lies within `margin` blocks of the tenure's bound of `J`
    /// blocks from its start, which only a new tenure clears.
    pub fn handoff_due(&self, margin: u64) -> bool {
        self.open
            .is_some_and(|(_, j)| self.head.saturating_add(margin) >= self.exhausted(j))
    }

    /// The tenure's bound: `J` blocks from its start, at most `LSN_LIMIT + 1`.
    fn exhausted(&self, j: u64) -> u64 {
        self.start.saturating_add(j).min(LSN_LIMIT + 1)
    }

    /// The tenure's bound over the region's `J` blocks, which a close keeps: `J` blocks from the log's start, at most
    /// `LSN_LIMIT + 1`.
    pub fn bound(&self) -> u64 {
        self.exhausted(self.region.0)
    }

    /// Whether the tenure should record a higher reserved end: the head is within `margin` blocks of it and the
    /// capacity admits more.
    pub fn needs_extension(&self, margin: u64) -> bool {
        self.open.is_some()
            && self.reserved < self.capacity
            && self.head.saturating_add(margin) >= self.reserved
    }

    #[cfg(test)]
    pub fn append(&mut self, now: u64, record: &Record) -> Result<u64, SuffixRefusal> {
        let frame = self.frame(record.change())?;
        self.record(now, record.change(), frame)
    }

    pub fn frame(&mut self, change: Change<'_>) -> Result<Frame, SuffixRefusal> {
        self.open.ok_or(SuffixRefusal::Closed)?;
        (change.frame(&mut self.spans)).ok_or(SuffixRefusal::Body)
    }

    /// Appends the record of `change`, whose [`frame`](Self::frame) is `frame`, at time `now`, no earlier than any
    /// earlier call's, and returns the position of its last block.
    ///
    /// # Errors
    ///
    /// `Closed`, `Body`, `Exhausted`, `Capacity`, `Reserved`, `Uncertified`, `Queue`, then `Stalled`; each leaves the
    /// log unchanged.
    pub fn record(
        &mut self,
        now: u64,
        change: Change<'_>,
        frame: Frame,
    ) -> Result<u64, SuffixRefusal> {
        let (limits, j) = self.open.ok_or(SuffixRefusal::Closed)?;
        debug_assert_eq!(change.frame(&mut self.spans), Some(frame));
        let (kind, len) = frame.parts();
        let (span, _) = Packer::plan(0, len).ok_or(SuffixRefusal::Body)?;
        if span >= limits.queue_blocks || span as u64 >= j.min(limits.uncertified) {
            return Err(SuffixRefusal::Body);
        }
        let (offset, _) = Packer::plan(self.packer.open.len(), len).ok_or(SuffixRefusal::Body)?;
        let last = self.head + offset as u64;
        if last >= self.exhausted(j) {
            return Err(SuffixRefusal::Exhausted);
        }
        if last >= self.capacity {
            return Err(SuffixRefusal::Capacity);
        }
        if last >= self.reserved {
            return Err(SuffixRefusal::Reserved);
        }
        if last >= self.certified.saturating_add(limits.uncertified) {
            return Err(SuffixRefusal::Uncertified);
        }
        if self.sealed.len() + 1 + offset > limits.queue_blocks && !unbounded_queue() {
            return Err(SuffixRefusal::Queue);
        }
        if self
            .oldest_pending()
            .is_some_and(|since| now.saturating_sub(since) > limits.oldest_ns)
        {
            return Err(SuffixRefusal::Stalled);
        }
        self.opened.get_or_insert(now);
        self.packer
            .push(self.seq, (kind, len), |out| change.write(out));
        self.seq += 1;
        self.collect(now);
        Ok(position(last, 0))
    }

    /// Moves the packer's sealed payloads into the queue as blocks, each taking the head LSN.
    fn collect(&mut self, now: u64) {
        while let Some(payload) = self.packer.sealed.pop_front() {
            let since = self.opened.replace(now).unwrap_or(now);
            let lsn = self.head;
            self.sealed.push_back(Sealed {
                lsn,
                since,
                payload,
            });
            self.head += 1;
        }
        self.opened = self.opened.filter(|_| !self.packer.open.is_empty());
    }

    /// Seals the open block and returns the cut: the head, which every later record lies at or above.
    pub fn seal_cut(&mut self) -> u64 {
        self.packer.seal();
        self.collect(self.opened.unwrap_or_default());
        self.head
    }

    /// Seals the open block when its oldest record has waited the flush interval.
    pub fn flush_due(&mut self, now: u64) {
        if let (Some((limits, _)), Some(opened)) = (self.open, self.opened)
            && now.saturating_sub(opened) >= limits.flush_ns
        {
            self.seal_cut();
        }
    }

    /// The blocks awaiting durability, the open block counted once it holds a record, and the open block's bytes.
    #[cfg(test)]
    pub(crate) fn queued(&self) -> (usize, usize) {
        let open = self.packer.open.len();
        (self.sealed.len() + usize::from(open > 0), open)
    }

    #[cfg(test)]
    pub fn take(&mut self, unit: &mut [u8; UNIT_LEN]) -> Option<u64> {
        let unlimited = super::HostShare {
            bytes: u64::MAX,
            interval: 1,
            owners: 1,
        };
        let mut share = super::IoShare::of(unlimited, 0)?;
        self.take_within(&mut share, 0, unit)
    }

    /// The next block to write, while no write is outstanding: charges the oldest sealed block to `share` at `now` as
    /// a suffix block, encodes it into `unit`, the buffer of this write attempt, and returns its LSN. The block keeps
    /// its payload, so every attempt encodes the same bytes. `now` is the volume's poll tick, the clock the share's
    /// other charges read, and differs from the nanosecond clock of [`record`](Self::record) and
    /// [`flush_due`](Self::flush_due). The caller holds the block's device write buffer before it calls, releases it on
    /// `None`, and calls [`failed`](Self::failed) for a taken block it does not submit. A block the share refuses stays
    /// queued with its payload. The charge leaves the share by the share's drain alone: a block ended through
    /// [`failed`](Self::failed), submitted or not, keeps its charge, and the share refuses the block's next take while
    /// it cannot hold a second block.
    pub(crate) fn take_within(
        &mut self,
        share: &mut super::IoShare,
        now: u64,
        unit: &mut [u8; UNIT_LEN],
    ) -> Option<u64> {
        if self.outstanding.is_some() {
            return None;
        }
        let (crc, shard) = self.identity?;
        let front = self.sealed.front()?;
        if !share.admit(now, UNIT_LEN as u64, super::IoClass::Suffix) {
            return None;
        }
        let block = Block {
            shard,
            session: self.session,
            lsn: front.lsn,
        };
        seal_into(crc, block, &front.payload, unit);
        self.outstanding = Some(front.lsn);
        Some(front.lsn)
    }

    /// Takes the persisted write of block `lsn`: the block leaves the queue, its payload's allocation returns to
    /// the packer, and the durable prefix advances over it.
    pub fn written(&mut self, lsn: u64) {
        if self.outstanding == Some(lsn) {
            self.outstanding = None;
            if let Some(written) = self.sealed.pop_front() {
                self.packer.recycle(written.payload);
            }
            self.durable = advance(self.durable, lsn);
        }
    }

    /// Takes the failed write of block `lsn`: the block stays queued with its payload for the next `take_within`.
    pub fn failed(&mut self, lsn: u64) {
        self.outstanding = self.outstanding.filter(|&sent| sent != lsn);
    }
}
