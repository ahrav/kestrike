//! The read path: operation handles, events, exposure of verified chunks, and each operation's command, verification and ending.
//!
//! Without read-ahead, one operation runs one command at a time: submit, terminal, verify, hand off, then wait for a grant before the next.
//! On a volume that reads ahead, an operation also holds up to `read_ahead` later commands outstanding, one per grant that asks for one while the current command is outstanding or verifying, the first command included; their bytes wait, unverified, until every command before them handed off, and the oldest then becomes the current command.
//! A command ahead of a first command whose header is unverified starts at the previous command's end window, planned from its extent's end; the header's verification fixes the chunks each command ahead carries, in order.
//! [`Volume::read`](super::Volume::read) submits the first command; each later command needs one [`Volume::grant_read`](super::Volume::grant_read), which submits it, submits it ahead on a volume that reads ahead, or keeps the grant while a command is outstanding or while the pool, the read share, the table or the device queue is full, so the caller decides when the operation may hold another response buffer.
//! Commands read whole record-aligned windows of `chunk_len` bytes, as many as fit the command limit, and the last one ends at the read's end: the locator's record end rounded up to the device block, so a read moves no unit padding past the record's last block.
//! The first command starts at the record's first byte and holds every window of the largest admissible local header, so it carries the header and the chunks of the windows it covers; every later command starts at a window boundary.
//! The layout is fixed when the header, read from those bytes with its lengths checked against the locator's units and the read's end, verifies; the locator's tail only bounds the read, and nothing from RAM supplies a length or a checksum.
//! The header is verified before any chunk, chunks verify in order within the tick's byte budget, and a buffer hands off its verified chunks only once all of them verified or the first failing chunk ended the operation.
//! An object of several extents reads its extents in order under the read's one right, each extent's record read as above with its own local header: the header must name the object's identity, the extent's index and payload offset, and the whole lengths, which size the extent's coverage and match every earlier extent's; the first header's lengths name exactly the read's extent count. A sequence's locators come from its block, read under one quiet pool gate try as the read reaches each extent; a busy or poisoned gate, or a storage past its live phase, keeps that read waiting with its grant while other reads go on submitting. Commands ahead cross into the next extent once the current extent's commands are all submitted, within the same `read_ahead` bound, and their chunks are fixed by the next extent's own header. Chunk ranges are payload offsets in the object, and a later extent's header mismatch ends the read with none of that extent's bytes exposed.
//! Header bytes are never exposed, and a failed or quiesced read command's buffer returns uninspected.

use std::ops::Range;

use super::super::allocation::AllocationId;
use super::super::device::{Buffer, CommandToken, IO_UNIT, ReadDone, SourceRange};
use super::super::extent::ExtentLocator;
use super::super::lease::ExtentLease;
use super::super::os::Platform;
use super::super::record::{
    Crc32c, ExpectedHeader, HeaderMismatch, RecordIdentity, RecordLayout, RunningCrc, ZeroRuns,
    window_crc,
};

/// A live read operation: a slot in the volume's operation array and the generation that slot had when the operation began.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReadOp {
    pub slot: u32,
    pub generation: u64,
}

/// A read of one object's records: its one extent, or the extents of its sequence in order. The header must name the identity the read names and pass the read predicate against the volume's session; the lengths and checksums come from the headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RawRead {
    /// The object's extent, whose units the header's lengths must fill exactly, or its sequence's handle.
    pub locator: ExtentLocator,
    pub key: [u8; 32],
    pub allocation: u64,
    /// The slot's record generation: the session of the tenure that wrote the record.
    pub session: u64,
    /// The slot's cache version.
    pub version: u64,
}

/// Why a read was not admitted; the refusal owns nothing, and every buffer and record it touched is free again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadRefusal {
    /// A direct extent's locator is empty or longer than the largest admissible extent.
    Layout,
    PoolExhausted,
    OpsExhausted,
    /// The lease is over another storage's object.
    ForeignLease,
    /// The volume closed, it has not passed its attach gate, its serving authority refused the read, or the storage left its live phase.
    Closed,
    /// The volume is lost: the device is gone, a tick, a `close` or a submit's driver call unwound, or the refusal of this read's first command lost it.
    Lost,
    /// The table or its driver refused the first command on a live volume.
    Submit(super::super::device::Refusal),
}

/// A refused [`Volume::read`](super::Volume::read) and the lease it was given, when the refusal came before admission.
pub struct ReadRefused<'s, P: Platform> {
    pub refusal: ReadRefusal,
    /// The lease, whole with its right and credit, for every refusal before the read took its right over; `None` after a refused first command, whose right the volume released.
    pub lease: Option<ExtentLease<'s, P>>,
}

/// Why [`Volume::read_key`](super::Volume::read_key) started no read; the right its lookup reserved, if any, was released first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyReadError {
    /// The registration is another storage's.
    ForeignRegistration,
    /// The lookup's refusal. The lookup reserves only a right, so `LeaseLimit` is outside its outcomes.
    Lookup(super::super::lookup::LookupError),
    /// The read's refusal after its lookup.
    Read(ReadRefusal),
    /// The join's refusal after the lookup proved the key missing, from
    /// [`Volume::read_or_join_prepared`](super::Volume::read_or_join_prepared)
    /// alone.
    Join(super::super::join::JoinError),
}

/// What [`Volume::read_or_join_prepared`](super::Volume::read_or_join_prepared)
/// started: the read of the key's visible object, or a follower of the
/// key's fill.
#[derive(Debug)]
pub(crate) enum KeyRead<'s, P: Platform> {
    /// The read of the visible object, begun.
    Started(ReadOp),
    /// The key had no visible object; this follower joined its fill.
    Joined(super::super::join::FillFollower<'s, P>),
}

/// Why [`Volume::read_joined`](super::Volume::read_joined) began no read.
#[derive(Debug)]
pub(crate) enum JoinedRefusal<'s, P: Platform> {
    /// The acquisition refused; the follower is still joined.
    Follower(
        super::super::join::FillFollower<'s, P>,
        super::super::join::JoinedReadError,
    ),
    /// The read refused: `ForeignLease` before the acquisition, or the
    /// read's refusal after it with the right released.
    Read(ReadRefusal),
}

impl<P: Platform> std::fmt::Debug for ReadRefused<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadRefused")
            .field("refusal", &self.refusal)
            .field("lease", &self.lease)
            .finish()
    }
}

/// Why [`Volume::cancel_read`](super::Volume::cancel_read) or [`Volume::grant_read`](super::Volume::grant_read) refused; a refused call changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRefusal {
    /// The handle names no live operation, or its operation already has its outcome.
    Stale,
    Closed,
}

/// How an accepted [`Volume::grant_read`](super::Volume::grant_read) changed, or left unchanged, its read's held grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    /// The read acquired a grant while holding no kept grant; a submit during the call spent it, or it stays kept for a later submit.
    Added,
    /// The grant joins the read's existing kept grant, which admits one command however many grants kept it.
    Merged,
    /// The read's submitted commands reach the end of its last extent, so the grant admits zero commands and stays unkept.
    Exhausted,
}

/// What a read's verified header says: the record's full identity and the whole object's payload lengths.
///
/// The volume builds a `VerifiedReadInfo` after verifying an extent's header crc, its lengths against the extent's units, its verified length, its chunk parameters, its identity under the read predicate, and its extent index, offset and context crc, so a value proves those checks passed for its read. Every later extent's header names the same identity and lengths.
/// The payload is `metadata_len` bytes of metadata followed by `body_len` bytes of body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedReadInfo {
    identity: RecordIdentity,
    metadata_len: u32,
    body_len: u32,
}

impl VerifiedReadInfo {
    /// The information of a read whose header verified under `identity` with `layout`, built only from the layout verification fixed.
    pub(super) fn new(identity: RecordIdentity, layout: &RecordLayout) -> Self {
        Self {
            identity,
            metadata_len: layout.metadata_len(),
            body_len: layout.body_len(),
        }
    }

    pub fn identity(&self) -> &RecordIdentity {
        &self.identity
    }

    pub fn metadata_len(&self) -> u32 {
        self.metadata_len
    }

    pub fn body_len(&self) -> u32 {
        self.body_len
    }

    /// Metadata and body bytes together: the end of the last chunk's range.
    pub fn payload_len(&self) -> u64 {
        u64::from(self.metadata_len) + u64::from(self.body_len)
    }
}

/// How an operation ended; each admitted operation ends exactly once, delivered by the tick that applies its outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadStatus {
    /// Every chunk verified and was handed off.
    Complete,
    /// A device command failed, or a later table refusal ended the read: `TableFull` and `QueueFull` defer the read until the next tick, `Closed` and `Stopped` produce `Quiesced`, `DeviceLost` and `DeviceGone` produce `Lost`, and every remaining refusal produces `DeviceError`.
    DeviceError,
    /// The device transferred fewer bytes than a command asked for.
    Short,
    HeaderMismatch(HeaderMismatch),
    /// Chunk `index` failed its checksum; every earlier chunk was handed off and nothing from it or later.
    ChunkMismatch {
        index: u32,
    },
    /// [`Volume::cancel_read`](super::Volume::cancel_read) ended the operation.
    Cancelled,
    /// A tick at or past the operation's deadline ended it; a command it had outstanding is cancelled while the table holds it pending with admission open or lost, and its record and buffer stay held until that command's terminal.
    TimedOut,
    /// Closure or serving-authority refusal ended the operation before it
    /// could expose its next command's bytes.
    Quiesced,
    /// The volume was lost before the operation could finish.
    Lost,
}

/// One event of [`Volume::poll_storage`](super::Volume::poll_storage).
#[derive(Debug)]
pub enum ReadEvent<'a> {
    /// Verified payload bytes `range` of the object, in order across its extents, under the header `info` describes.
    Chunk {
        op: ReadOp,
        info: VerifiedReadInfo,
        range: Range<u64>,
        chunk: ValidatedChunk<'a>,
    },
    /// The operation's one outcome; its handle is stale from this event on.
    ///
    /// `info` is `Some` exactly when the first extent's header verified, so an empty payload's `Complete` carries the record's identity and lengths with no `Chunk` before it, a later extent's `HeaderMismatch` carries the first extent's, and a first extent's `HeaderMismatch`, or any outcome decided before the first header verified, carries `None`.
    Done {
        op: ReadOp,
        info: Option<VerifiedReadInfo>,
        status: ReadStatus,
    },
}

/// Verified payload bytes that own their response buffer; dropping the chunk returns the buffer to its pool, whether or not its operation is still live.
///
/// Only a chunk makes a transmit [`SourceRange`], and a chunk exposes no
/// mutable view, so a buffer a device reads never changes under it:
///
/// ```compile_fail,E0599
/// fn overwrite(chunk: &mut kestrike::storage::ValidatedChunk<'_>) {
///     chunk.bytes_mut()[0] = 0;
/// }
/// ```
#[derive(Debug)]
pub struct ValidatedChunk<'a> {
    buffer: Buffer<'a>,
    range: Range<usize>,
    /// The record window length; windows start at multiples of it from the buffer's first byte.
    window_len: u32,
}

impl<'a> ValidatedChunk<'a> {
    /// The verified bytes, exactly the event's payload range.
    pub fn bytes(&self) -> &[u8] {
        &self.buffer.bytes()[self.range.clone()]
    }

    /// The record windows the chunk spans, each with a verified checksum in the volume's table for the chunk's buffer.
    pub fn windows(&self) -> usize {
        (self.range.end - 1) / self.window_len as usize
            - self.range.start / self.window_len as usize
            + 1
    }

    /// The index of the chunk's buffer in its pool, under which the volume keeps the chunk's window checksums.
    pub(super) fn buffer_index(&self) -> usize {
        self.buffer.index()
    }

    /// The crc32c of the verified bytes `range` (relative to [`bytes`](Self::bytes)), from the verified checksums `window_crcs` of the [`windows`](Self::windows) the chunk spans and the bytes of the partial windows at the range's ends, so a whole window adds no byte read; `runs` keeps the zero runs of the lengths met for the caller's next range. Panics unless `range` is a forward range inside the bytes.
    pub fn crc(
        &self,
        crc: Crc32c,
        runs: &mut ZeroRuns,
        window_crcs: &[u32],
        range: Range<usize>,
    ) -> u32 {
        assert!(
            range.start <= range.end && range.end <= self.range.len(),
            "a range inside the chunk"
        );
        let within = self.range.start + range.start..self.range.start + range.end;
        window_crc(
            crc,
            runs,
            self.window_len as usize,
            &self.range,
            window_crcs,
            self.buffer.bytes(),
            within,
        )
    }

    /// Whether a device holds a reference to the chunk's buffer.
    pub fn device_held(&self) -> bool {
        self.buffer.device_held()
    }

    /// The verified bytes `range` (relative to [`bytes`](Self::bytes)) as a
    /// transmit source over the buffer's current incarnation, which stays
    /// current while the chunk lives; a chunk exposes no mutable view, so the
    /// bytes stay unchanged while a device reads them.
    pub fn source(&self, range: std::ops::Range<usize>) -> Option<SourceRange<'_, 'a>> {
        let start = self.range.start.checked_add(range.start)?;
        let end = self.range.start.checked_add(range.end)?;
        (end <= self.range.end)
            .then(|| self.buffer.source(start..end))
            .flatten()
    }
}

impl AsRef<[u8]> for ValidatedChunk<'_> {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

/// One read operation's state in the volume's operation array.
pub(super) struct ReadRecord<'a> {
    /// Token captured at read admission and checked before submit and exposure.
    pub(super) authority: Option<crate::failover::serving::Token>,
    pub(super) expected: ExpectedHeader,
    /// The tick value at or past which the operation ends `TimedOut`.
    pub(super) deadline: u64,
    /// The current extent's first unit; zero for a sequence until its first locator is read.
    pub(super) start_unit: u64,
    /// Bytes from the current extent's record start the read covers: its locator's record end rounded up to the device block, within the extent; zero for a sequence until its first locator is read. A header claiming more fails its length check.
    pub(super) end: u64,
    /// First chunk of the current extent's next command, reset to 0 when the read advances. Two writers: every current-extent submit after its
    /// header verified stores its command's end, and submits before it leave 0
    /// because their chunk ranges are unknown before the header arrives; the
    /// header's verification then stores the end of the first command, or of
    /// the newest command ahead in this extent when commands were submitted
    /// before it.
    pub(super) next_chunk: u32,
    /// The current extent's layout, fixed once its header verified and cleared when the read advances; each extent's first command carries its header.
    pub(super) layout: Option<RecordLayout>,
    /// Set by every accepted [`Volume::grant_read`](super::Volume::grant_read) that does not return [`Grant::Exhausted`] and by a read's first submit, under [`Volume::read`](super::Volume::read) or [`Volume::read_key`](super::Volume::read_key), that the read share, the table or the device queue refused as full, and cleared by every submit that succeeds, so it stays set exactly while a grant is kept and any number of kept grants admit one command.
    /// A cancel and the delivery of the operation's `Done` clear it.
    pub(super) granted: bool,
    /// The current command's token, until its terminal arrives.
    pub(super) token: Option<CommandToken>,
    /// Set while a submit's driver call runs. A call that unwound leaves it set: the table keeps the command under a token the volume never mapped, and the first tick after a proven stop, with every taken terminal applied, clears it.
    pub(super) unmapped: bool,
    /// The current command: outstanding while reading, and the one whose bytes are verified after it arrived; zero until the first submit.
    pub(super) command: Command,
    pub(super) stage: Stage<'a>,
    /// The commands submitted ahead of the current one, oldest first, each outstanding or arrived until it becomes the current command.
    pub(super) ahead: Aheads<'a>,
    /// The object whose count holds this operation's right, released when the record frees.
    /// `None` marks a raw read, built only under `cfg(test)` by `read_raw`, whose caller keeps the extent; [`Volume::read`](super::Volume::read) stores its record with the right already taken.
    pub(super) right: Option<AllocationId>,
    /// The object's extent sequence, for an object of several extents; `start_unit`, `end` and the expected header's position and units describe its current extent.
    pub(super) sequence: Option<Sequence>,
}

/// An object of several extents a read moves through in order. The read's right keeps the sequence's block and its extents fixed.
#[derive(Debug, Clone, Copy)]
pub(super) struct Sequence {
    /// The object whose block names the extents.
    pub(super) id: AllocationId,
    pub(super) count: u32,
    /// The extent after the current one, once a command ahead was planned into it.
    pub(super) next: Option<Extent>,
    /// The current extent's locator is still to be read from the block: set at admission and when the read moves to an extent no command was planned into.
    pub(super) locate: bool,
}

/// Where one extent of a read lies: its first unit, the bytes from its record's start the read covers, and its units.
#[derive(Debug, Clone, Copy)]
pub(super) struct Extent {
    pub(super) start_unit: u64,
    pub(super) end: u64,
    pub(super) len_units: u32,
}

impl Extent {
    /// The extent `locator` names, read whole blocks of `block` bytes at a time.
    pub(super) fn of(locator: ExtentLocator, block: u32) -> Self {
        Self {
            start_unit: locator.start_unit(),
            end: super::attach::read_end(locator, block),
            len_units: locator.len_units(),
        }
    }
}

/// Commands one read may hold ahead of its current command.
pub const MAX_READ_AHEAD: u8 = 3;

/// A read's commands submitted ahead of its current one, oldest first, at most [`MAX_READ_AHEAD`], held inline so a read allocates nothing.
pub(super) struct Aheads<'a> {
    slots: [Option<Ahead<'a>>; MAX_READ_AHEAD as usize],
    len: u8,
}

impl<'a> Aheads<'a> {
    pub(super) const fn new() -> Self {
        Self {
            slots: [None, None, None],
            len: 0,
        }
    }

    pub(super) fn len(&self) -> u8 {
        self.len
    }

    /// Appends the newest command ahead. Precondition: fewer than [`MAX_READ_AHEAD`] are held.
    pub(super) fn push(&mut self, ahead: Ahead<'a>) {
        debug_assert!(
            self.len < MAX_READ_AHEAD,
            "a read holds at most MAX_READ_AHEAD commands ahead"
        );
        self.slots[usize::from(self.len)] = Some(ahead);
        self.len += 1;
    }

    /// Removes and returns the oldest command ahead, which becomes the current command.
    pub(super) fn pop_front(&mut self) -> Option<Ahead<'a>> {
        if self.len == 0 {
            return None;
        }
        let front = self.slots[0].take();
        self.slots[..usize::from(self.len)].rotate_left(1);
        self.len -= 1;
        front
    }

    /// The newest command ahead, from whose end the next one is planned.
    pub(super) fn last(&self) -> Option<&Ahead<'a>> {
        self.len
            .checked_sub(1)
            .and_then(|at| self.slots[usize::from(at)].as_ref())
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &Ahead<'a>> {
        self.slots[..usize::from(self.len)].iter().flatten()
    }

    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Ahead<'a>> {
        self.slots[..usize::from(self.len)].iter_mut().flatten()
    }

    /// The tokens of the commands ahead still outstanding.
    pub(super) fn tokens(&self) -> impl Iterator<Item = CommandToken> + '_ {
        self.iter().filter_map(|ahead| ahead.token)
    }

    /// The command ahead whose outstanding token is `token`.
    pub(super) fn find(&mut self, token: CommandToken) -> Option<&mut Ahead<'a>> {
        self.iter_mut().find(|ahead| ahead.token == Some(token))
    }

    /// Drops the command ahead whose token is `token`, returning its bytes uninspected, and keeps the others in order.
    pub(super) fn remove(&mut self, token: CommandToken) {
        let len = usize::from(self.len);
        if let Some(at) = self.slots[..len].iter().position(|ahead| {
            ahead
                .as_ref()
                .is_some_and(|ahead| ahead.token == Some(token))
        }) {
            self.slots[at] = None;
            self.slots[at..len].rotate_left(1);
            self.len -= 1;
        }
    }

    /// Drops every command ahead whose terminal arrived, returning its bytes uninspected, and clears the recorded outcome of the rest, so an ending read keeps only the commands whose terminals it still awaits.
    pub(super) fn keep_outstanding(&mut self) {
        let len = usize::from(self.len);
        let mut kept = 0;
        for at in 0..len {
            if self.slots[at]
                .as_ref()
                .is_some_and(|ahead| ahead.token.is_some())
            {
                self.slots.swap(kept, at);
                kept += 1;
            }
        }
        for slot in &mut self.slots[kept..len] {
            *slot = None;
        }
        for ahead in self.slots[..kept].iter_mut().flatten() {
            ahead.arrived = None;
        }
        self.len = kept as u8;
    }
}

/// A read's command submitted while its current command is outstanding or verifying.
pub(super) struct Ahead<'a> {
    pub(super) command: Command,
    /// The command's token until its terminal arrives.
    pub(super) token: Option<CommandToken>,
    /// The command's outcome once its terminal arrived: its bytes, held unverified, or the status that ends the read once the current command handed off.
    pub(super) arrived: Option<Result<ReadDone<'a>, ReadStatus>>,
}

pub(super) enum Stage<'a> {
    /// Waiting to submit its next command: for a grant, or, with a kept grant, for a buffer, a free table slot, device queue room or its turn in the tick's submit burst.
    Next,
    /// A command is outstanding.
    Reading,
    /// A command's bytes arrived and are being verified.
    Verifying(Verifying<'a>),
    /// The outcome is decided and its `Done` is not yet delivered.
    Ending(ReadStatus),
    /// `Done` was delivered; the record frees when its commands' terminals arrived.
    Ended,
}

/// Which tick set holds a record between volume calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Place {
    Ready,
    Waiting,
    Outside,
}

impl ReadRecord<'_> {
    /// Whether the table holds a command of this operation: the current command's or a command ahead's mapped token, or a submit whose driver call unwound.
    pub(super) fn outstanding(&self) -> bool {
        self.token.is_some() || self.unmapped || self.ahead.tokens().next().is_some()
    }

    pub(super) fn newest(&self) -> &Command {
        self.ahead
            .last()
            .map_or(&self.command, |ahead| &ahead.command)
    }

    /// Whether a command remains for the read to submit after the ones it holds, in any extent from the current one on.
    pub(super) fn more_to_read(&self) -> bool {
        let current = self.expected.position.index;
        let newest = self.newest();
        let Some(sequence) = self.sequence else {
            return self.more_in_current();
        };
        if sequence.locate || newest.extent < current {
            return true;
        }
        if newest.extent == current {
            return self.more_in_current() || self.extent_follows();
        }
        sequence.next.is_some_and(|next| newest.leaves(next.end)) || current + 2 < sequence.count
    }

    /// Whether the read may plan a command ahead now: [`more_to_read`](Self::more_to_read), within the current extent and the one after it, the furthest a command ahead reaches.
    pub(super) fn plans_ahead(&self) -> bool {
        let newest = self.newest();
        match self.sequence {
            Some(sequence) if newest.extent > self.expected.position.index => {
                sequence.next.is_some_and(|next| newest.leaves(next.end))
            }
            _ => self.more_to_read(),
        }
    }

    /// Whether the next command, a command ahead when `ahead`, lies in the current extent with its locator known: always for a direct extent; for a sequence, once the current extent's locator was read and unless a command ahead would follow the current extent's last command.
    #[inline(always)]
    pub(super) fn plans_in_current(&self, ahead: bool) -> bool {
        match self.sequence {
            None => true,
            Some(sequence) => {
                !sequence.locate
                    && (!ahead
                        || (self.newest().extent == self.expected.position.index
                            && self.more_in_current()))
            }
        }
    }

    /// Whether a command remains in the current extent after the newest one.
    pub(super) fn more_in_current(&self) -> bool {
        match self.layout {
            Some(layout) => self.next_chunk < layout.chunk_count(),
            None => self.newest().leaves(self.end),
        }
    }

    /// The next command of the current extent: with `ahead` and the header unverified, the command at the newest command's end window, sized from the extent's end; otherwise the command at chunk `next_chunk`, placed by the verified layout when there is one, else the extent's first command, which carries its header.
    pub(super) fn plan_current(&self, ahead: bool, chunk_len: u32, windows: u32) -> Command {
        let mut command = match self.layout.as_ref() {
            None if ahead => self.newest().following(chunk_len, self.end, windows),
            layout => Command::plan(chunk_len, layout, self.next_chunk, self.end, windows),
        };
        command.extent = self.expected.position.index;
        command.start_unit = self.start_unit;
        command
    }

    /// Makes `extent` the current extent.
    pub(super) fn set_extent(&mut self, extent: Extent) {
        self.start_unit = extent.start_unit;
        self.end = extent.end;
        self.expected.len_units = extent.len_units;
    }

    /// Moves the read past its current extent, whose header verified as `layout`, to the next extent of its sequence: that extent's payload follows the current one's, and its locator is the one a command ahead was planned with, or is read before the read's next command.
    pub(super) fn advance(&mut self, layout: &RecordLayout) {
        let Some(sequence) = self.sequence.as_mut() else {
            unreachable!("only a sequence has a next extent")
        };
        let next = sequence.next.take();
        sequence.locate = next.is_none();
        let position = &mut self.expected.position;
        position.offset += layout.payload_len();
        position.index += 1;
        self.layout = None;
        self.next_chunk = 0;
        if let Some(next) = next {
            self.set_extent(next);
        }
    }

    /// Whether an extent follows the current one.
    pub(super) fn extent_follows(&self) -> bool {
        self.sequence
            .is_some_and(|sequence| self.expected.position.index + 1 < sequence.count)
    }

    /// Whether a tick has work for the operation: bytes to verify, an outcome to deliver, a granted command to submit, or, once the volume `closed`, a next command to end `Quiesced`; a record whose submit unwound waits for the proven stop.
    pub(super) fn has_work(&self, closed: bool) -> bool {
        !matches!(self.place(closed), Place::Outside)
    }

    /// The set a tick leaves the operation in: the ready set for bytes to verify, an outcome to deliver or, once the volume `closed`, a next command to end `Quiesced`; the waiting set for a kept grant whose command found no room. A `Stage::Next` record whose submit unwound waits for the proven stop.
    pub(super) fn place(&self, closed: bool) -> Place {
        match self.stage {
            Stage::Verifying(_) | Stage::Ending(_) => Place::Ready,
            Stage::Next if self.unmapped => Place::Outside,
            Stage::Next if closed => Place::Ready,
            Stage::Next if self.granted => Place::Waiting,
            Stage::Next | Stage::Reading | Stage::Ended => Place::Outside,
        }
    }

    /// The verified header's identity and the object's whole lengths, once the first extent's header verified.
    pub(super) fn info(&self) -> Option<VerifiedReadInfo> {
        let (metadata_len, body_len) = self.expected.lengths?;
        Some(VerifiedReadInfo {
            identity: self.expected.identity,
            metadata_len,
            body_len,
        })
    }
}

/// One command's span: device bytes from `offset` within extent `extent` of its object, which starts at unit `start_unit`, `len` long, carrying chunks `first..end` of that extent.
/// The first command's chunks, and those of a command submitted ahead of it, are known only once its header verified; until then `first` and `end` are zero.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Command {
    pub(super) extent: u32,
    pub(super) start_unit: u64,
    pub(super) offset: u64,
    pub(super) len: u32,
    /// `end_window` uses the command's full window count even when the read's end shortens `len`; [`chunks_end`](Self::chunks_end) clamps the resulting chunk index to the record's chunk count.
    pub(super) end_window: u32,
    pub(super) first: u32,
    pub(super) end: u32,
}

/// The checksum tables one read's verification writes: the operation's copy of its header's chunk table, and the volume's rows of window checksums by buffer, `windows` entries each.
pub(super) struct ChunkTables<'t> {
    pub(super) crcs: &'t mut [u32],
    pub(super) window_crcs: &'t mut [u32],
    pub(super) windows: usize,
}

pub(super) struct Verifying<'a> {
    pub(super) done: ReadDone<'a>,
    /// Next chunk to verify; while the header is unverified, the header is the item in progress.
    pub(super) cursor: u32,
    /// Bytes of the item in progress already folded into `running`.
    pub(super) fed: usize,
    pub(super) running: RunningCrc,
}

impl Command {
    /// The next command of a read covering `end` bytes from the record's start: the first one from the record's start while `layout` is unknown, else the one starting at chunk `next`'s window; `windows` whole `chunk_len` windows, ending early at `end`.
    ///
    /// Attach guarantees `windows` holds every window of the largest header plus one chunk, so every command carries at least one chunk, except the first of an empty payload.
    pub(super) fn plan(
        chunk_len: u32,
        layout: Option<&RecordLayout>,
        next: u32,
        end: u64,
        windows: u32,
    ) -> Self {
        let window = layout.map_or(0, |layout| layout.first_window() as u32 + next);
        let offset = u64::from(window) * u64::from(chunk_len);
        let len = (u64::from(windows) * u64::from(chunk_len)).min(end - offset);
        let mut command = Self {
            offset,
            len: len as u32,
            end_window: window + windows,
            first: next,
            end: next,
            ..Self::default()
        };
        if let Some(layout) = layout {
            command.end = command.chunks_end(layout);
        }
        command
    }

    /// The command that starts at this command's end window of the same extent, sized from the extent's `end` before its header verified; its chunks stay zero until the header fixes them.
    /// Callers hold [`leaves`](Self::leaves)`(end)`, so the command starts inside the read.
    pub(super) fn following(&self, chunk_len: u32, end: u64, windows: u32) -> Self {
        let window = self.end_window;
        let offset = u64::from(window) * u64::from(chunk_len);
        let len = (u64::from(windows) * u64::from(chunk_len)).min(end - offset);
        Self {
            offset,
            len: len as u32,
            end_window: window + windows,
            first: 0,
            end: 0,
            ..*self
        }
    }

    /// Whether the read's `end` lies past this command's bytes.
    pub(super) fn leaves(&self, end: u64) -> bool {
        self.offset + u64::from(self.len) < end
    }

    /// One past the last chunk whose window this command reaches; a command reads whole windows, so it holds each such chunk entirely.
    pub(super) fn chunks_end(&self, layout: &RecordLayout) -> u32 {
        (u64::from(self.end_window).saturating_sub(layout.first_window()) as u32)
            .min(layout.chunk_count())
    }

    /// Units the command's bytes touch: a read that ends at its record's last sector touches its last unit in part.
    pub(super) fn units(&self) -> u32 {
        self.len.div_ceil(IO_UNIT as u32)
    }

    /// Where payload bytes `span`, which this command holds, lie in its buffer.
    pub(super) fn in_buffer(&self, layout: &RecordLayout, span: &Range<u64>) -> Range<usize> {
        let header = layout.header_bytes() as u64;
        (header + span.start - self.offset) as usize..(header + span.end - self.offset) as usize
    }

    /// The payload bytes of chunks `self.first..upto` and where they lie in this command's buffer: what [`Verifying::hand_off`] hands off as one validated chunk.
    pub(super) fn handed_off(
        &self,
        layout: &RecordLayout,
        upto: u32,
    ) -> (Range<u64>, Range<usize>) {
        let range = layout.chunks(self.first, upto);
        let bytes = self.in_buffer(layout, &range);
        (range, bytes)
    }
}

/// Read command geometry in whole windows. The first command's required extent includes the window containing the first payload byte under the largest local header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReadSpan {
    limit: u32,
    windows: u32,
    needed: u64,
}

impl ReadSpan {
    /// Commands read whole `chunk_len` windows, at most `min(response_buffer_len, max_transfer)` bytes each, for records with headers up to `header_max` bytes.
    /// `chunk_len` is nonzero.
    pub(crate) fn new(
        chunk_len: u32,
        response_buffer_len: u32,
        max_transfer: u32,
        header_max: u64,
    ) -> Self {
        let limit = response_buffer_len.min(max_transfer);
        let chunk = u64::from(chunk_len);
        Self {
            limit,
            windows: limit / chunk_len,
            needed: super::super::record::first_window_end(header_max, chunk),
        }
    }

    pub(crate) fn limit(&self) -> u32 {
        self.limit
    }

    pub(crate) fn windows(&self) -> u32 {
        self.windows
    }

    pub(crate) fn needed(&self) -> u64 {
        self.needed
    }

    /// `holds_header` reports whether the first command can hold the largest local header and the window containing the first payload byte.
    /// `needed` is a multiple of `chunk_len`, so it fits `limit` exactly when it fits the `windows * chunk_len` bytes a command reads.
    pub(crate) fn holds_header(&self) -> bool {
        self.needed <= u64::from(self.limit)
    }
}

impl<'a> Verifying<'a> {
    /// Hands off chunks `command.first..upto` of `command`, whose bytes these are, as one validated chunk of the extent whose verified header `expected` describes, with its payload range in the object, storing their verified checksums from the operation's chunk table in the buffer's row of `tables`; when `upto` is `command.first`, the buffer returns to its pool.
    /// The caller builds the event from the parts inside its push, so the event is written once where the output keeps it.
    #[inline(always)]
    pub(super) fn hand_off(
        self,
        command: &Command,
        layout: &RecordLayout,
        expected: &ExpectedHeader,
        upto: u32,
        tables: &mut ChunkTables<'_>,
    ) -> Option<(Range<u64>, ValidatedChunk<'a>)> {
        let first = command.first;
        if upto <= first {
            return None;
        }
        let (range, bytes) = command.handed_off(layout, upto);
        let offset = expected.position.offset;
        let chunk = ValidatedChunk {
            range: bytes,
            buffer: self.done.into_buffer(),
            window_len: layout.chunk_len(),
        };
        let verified = &tables.crcs[first as usize..upto as usize];
        debug_assert_eq!(verified.len(), chunk.windows());
        debug_assert!(verified.len() <= tables.windows);
        tables.window_crcs[chunk.buffer_index() * tables.windows..][..verified.len()]
            .copy_from_slice(verified);
        Some((offset + range.start..offset + range.end, chunk))
    }
}

/// Bounded proofs that the read command planning chain hands off only bytes
/// of the payload its verified header names.
///
/// Each harness runs with `cargo kani -p kestrike --exact --harness <name>`;
/// its cover statements prove the assumptions leave the boundary cases
/// reachable, and Kani's default unwind, overflow and arithmetic checks stay
/// enabled. The layout is the one `claimed_layout` in `storage::record::header`
/// derives and the tick path verifies before it calls [`Verifying::hand_off`],
/// which hands off [`Command::handed_off`] of a command [`Command::plan`] or
/// [`Command::following`] built. The property runs once
/// per band of chunk lengths, in units of [`IO_UNIT`]: the low and high chunk
/// lengths, every power of two and the other bands the measurement proved.
/// The lengths between them are the gaps `verification/kani/expected.json`
/// declares, closed by the Verus lemma `proof::handoff` over every layout
/// `record::arithmetic::extent_counts` returns, and `grant_tests` checks every
/// chunk length's boundary reads; `scripts/test-judge-kani.py` checks that the
/// bands and gaps tile `1..2^20`.
#[cfg(kani)]
mod verification {
    use super::super::super::record::RecordConfig;
    use super::*;

    /// One proof per band: `$name` checks the handoff over chunk lengths of
    /// `$lo..$hi` units.
    macro_rules! bands {
        ($check:ident: $($name:ident => ($lo:literal, $hi:literal)),* $(,)?) => {
            $(
                #[kani::proof]
                fn $name() {
                    $check($lo, $hi)
                }
            )*
        };
    }

    /// For a layout the header check admits (any `u32` lengths, a chunk
    /// length of `lo..hi` units, its header within the first command's
    /// bytes; an admitted extent's layout derives every field from its
    /// coverage `p`, which `layout(0, p)` here reaches), a read ending at or
    /// past the record and commands of `windows`
    /// whole windows that hold the largest admissible header: the first
    /// command, any later planned command and the command submitted ahead
    /// of either each hand off chunks `first..upto` as buffer bytes inside
    /// `0..len`, and those bytes are exactly the chunks' payload bytes. The
    /// expected endpoints come from the record format: the payload is record
    /// bytes `header..header + payload` with `header = 108 + 4 * (ceil(payload
    /// / chunk_len) + 1)`, chunk `i` covers the payload bytes of window
    /// `header / chunk_len + i`, and a buffer read from record byte `offset`
    /// holds record byte `b` at `b - offset`.
    fn handed_off_chunks_lie_inside_the_command_buffer(lo: u32, hi: u32) {
        let units: u32 = kani::any();
        kani::assume(lo <= units && units < hi);
        let chunk_len = units * IO_UNIT as u32;
        let config = RecordConfig { chunk_len }.validate();
        assert!(config.is_ok());
        let config = config.unwrap_or_else(|_| unreachable!("asserted valid"));
        let layout = config.layout(kani::any(), kani::any());
        let header_max = u64::from(kani::any::<u32>());
        let windows: u32 = kani::any();
        kani::assume(u64::from(windows) * u64::from(chunk_len) <= u64::from(u32::MAX));
        let read = ReadSpan::new(chunk_len, windows * chunk_len, u32::MAX, header_max);
        kani::assume(read.windows() == windows && read.holds_header());
        let end: u64 = kani::any();
        kani::assume(layout.record_len() <= end && end <= layout.record_units() * IO_UNIT as u64);

        let mut first = Command::plan(chunk_len, None, 0, end, windows);
        // The header check reads the claimed header from the first command's
        // bytes, so a verified header fits them; its lengths may claim more
        // than the largest admissible extent within the extent's units.
        kani::assume(layout.header_bytes() as u64 <= u64::from(first.len));
        first.end = first.chunks_end(&layout);
        let pick: u8 = kani::any();
        let command = match pick {
            0 => first,
            _ => {
                let next: u32 = kani::any();
                kani::assume(next < layout.chunk_count());
                let planned = Command::plan(chunk_len, Some(&layout), next, end, windows);
                if pick == 1 {
                    planned
                } else {
                    let previous = if kani::any() { first } else { planned };
                    kani::assume(previous.leaves(end));
                    let mut ahead = previous.following(chunk_len, end, windows);
                    ahead.first = previous.end;
                    ahead.end = ahead.chunks_end(&layout);
                    ahead
                }
            }
        };
        kani::cover!(layout.payload_len() == 0 && command.end == 0);
        let upto: u32 = kani::any();
        kani::assume(command.first < upto && upto <= command.end);
        kani::cover!(command.first == 0 && upto == layout.chunk_count());
        kani::cover!(command.first > 0 && upto == layout.chunk_count());
        kani::cover!(command.offset + u64::from(command.len) == end && end > layout.record_len());
        kani::cover!(pick >= 2 && upto == command.end);
        assert!(command.end <= layout.chunk_count());
        assert!(command.offset < end && command.offset + u64::from(command.len) <= end);
        let (range, bytes) = command.handed_off(&layout, upto);
        assert!(bytes.start <= bytes.end && bytes.end <= command.len as usize);
        // Recomputes the handoff's endpoints from the record format with the
        // arithmetic of `grant_tests::contract_span`, which
        // `the_handoff_oracle_matches_a_hand_worked_record` pins to
        // hand-worked values.
        let (c, payload) = (u64::from(chunk_len), layout.payload_len());
        let header = 108 + 4 * (payload.div_ceil(c) + 1);
        assert_eq!(layout.header_bytes() as u64, header);
        let start = ((header / c + u64::from(command.first)) * c).max(header);
        let stop = ((header / c + u64::from(upto)) * c).min(header + payload);
        assert_eq!(range, start - header..stop - header);
        assert_eq!(
            bytes,
            (start - command.offset) as usize..(stop - command.offset) as usize
        );
    }

    include!("read_kani_bands.rs");
}
