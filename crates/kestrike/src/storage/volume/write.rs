//! The fill write path: write sets, their progress, the in-flight write right, and the rule that only a successful terminal completes units.
//!
//! A fill's write set tiles each extent of its object once, in order, with commands of `min(remaining, buffer length, max_transfer)` bytes, each a unit multiple at the unit offset the fill names in the extent it writes now.
//! Every fill's writes share `depth - read_commands - metadata_commands - report_commands` table slots, the write share, and each metadata slot that no staged or outstanding metadata command claims. A command is charged before its driver call and uncharged by a definite refusal, its terminal, or the proven stop after a call that unwound.
//! WRITE-ROOM: a write submits only while the writes hold fewer slots than the write share plus the unclaimed metadata slots, and a metadata command submits only while the writes and the outstanding metadata commands together hold fewer slots than the write and metadata shares. So the two together stay within those two shares, reads and reservation commands keep theirs, and a staged metadata command finds a slot once the writes holding its slot reach their terminals, since no later write takes a claimed slot.
//! `completed_units` advances at a `Written` terminal whose token remains admitted; authority refusal and failed, quiesced or abandoned commands fail the set, and a failed set never becomes ready.
//!
//! In-flight write right: while any command of a set is outstanding, the set holds one right in its slot's count.
//! The submit that finds nothing outstanding installs it first, with [`word::install`]'s compare-exchange from a zero count: the slot is `Filling` and unindexed, so nothing else raises its count.
//! The terminal that leaves nothing outstanding releases it with a `Release` `fetch_sub` before the progress it completes, so a set is never ready while its right is counted.
//! A refused submit that installed the right releases it before returning, so an observer can see the count rise and fall once.
//! A submit counts its command outstanding before the driver call and uncounts it on a refusal, so a call that unwinds leaves it counted: the table keeps that command under a token the volume never mapped, and the set keeps its right until the first tick or `release` after the proven stop fails the set and releases it.
//! Service returns an extent only after an acquire load of a zero count, so every write of the extent reaches its terminal before the extent returns, whether or not its fill still exists.
//!
//! A set outlives its fill: a fill that ends with a command outstanding leaves its set to the volume, which frees it at the last terminal, once the fill's attempt record shows the fill ended.
//! A fill dropped with nothing outstanding ends without the volume, so its set stays in the array until the array is full, when every set with nothing outstanding whose fill ended is reclaimed; live fills hold at most `sum(F[s])` sets and a set whose fill ended with a command outstanding holds a table slot, so the array of `sum(F[s]) + depth` records always has one to give.

use std::sync::atomic::{AtomicU64, Ordering};

use super::super::allocation::AllocationId;
use super::super::device::{Buffer, Disk, IO_UNIT, PoolExhausted, PoolKind, Refusal, Rejected};
use super::super::extent::ExtentLocator;
use super::super::fill::{self, FillSerial};
use super::super::lease::release_right;
use super::super::os::Platform;
use super::super::owner::Storage;
use super::super::record::Crc32c;
use super::super::word;
use super::attach::{Owner, Volume, map_token};

/// A live write set: a slot in the volume's write-set array and the generation that slot had when the set began.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct WriteSet {
    pub(crate) slot: u32,
    pub(crate) generation: u64,
}

/// A write set's progress in units of every extent of the fill's object:
/// `len_units` counts the whole object, and the submitted and completed
/// counts advance through each extent in turn.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriteProgress {
    pub len_units: u32,
    pub submitted_units: u32,
    pub completed_units: u32,
    /// A device terminal failed or the set's authority no longer admits fills.
    pub failed: bool,
    pub outstanding_units: u32,
    /// Write commands submitted and awaiting their terminals.
    pub outstanding_commands: u32,
}

impl WriteProgress {
    /// Every unit reached a successful terminal and none failed: the precondition for publishing the record.
    pub fn is_ready(&self) -> bool {
        !self.failed && self.completed_units == self.len_units
    }
}

pub(super) struct WriteRecord<'s> {
    /// Serving token captured when this write set began.
    pub(super) authority: Option<crate::failover::serving::Token>,
    /// The first unit of the extent the set writes now.
    pub(super) start_unit: u64,
    /// Units of the extent the set writes now; `progress.len_units` counts every extent of the object.
    pub(super) extent_units: u32,
    pub(super) progress: WriteProgress,
    /// The slot whose count holds the set's right while a command is outstanding.
    pub(super) id: AllocationId,
    /// The fill's attempt record and serial: once the record departed or carries another serial, the fill has ended.
    pub(super) attempt: &'s AtomicU64,
    pub(super) serial: FillSerial,
}

impl<'s, 'a, P: Platform, D: Disk> Volume<'s, 'a, P, D> {
    /// Every accepted command's token and its owner, in acceptance order: a write set with its fill's serial, or a read's slot and generation, which the volume mints before its first fallible submit; and whether an acceptance arrived past the record's reserved room.
    #[cfg(test)]
    pub(crate) fn bound_tokens(
        &self,
    ) -> (
        &[(crate::storage::CommandToken, super::attach::Bound)],
        bool,
    ) {
        (&self.bound, self.bound_overflow)
    }

    /// Empties the token record and clears its overflow flag.
    #[cfg(test)]
    pub(crate) fn clear_bound(&mut self) {
        self.bound.clear();
        self.bound_overflow = false;
    }

    /// The volume records read identities in minting order before each read's first fallible submit, retains them if submit unwinds, and releases them on immediate device refusal.
    ///
    /// # Panics
    ///
    /// When the identities overflowed the room reserved at attach, which leaves the census incomplete.
    #[cfg(test)]
    pub(crate) fn minted_reads(&self) -> &[(u32, u64)] {
        assert!(
            !self.minted_overflow,
            "the volume's read identities overflowed their room; the census is incomplete"
        );
        &self.minted
    }

    /// Whether [`close`](Self::close) ran.
    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }

    pub(crate) fn crc(&self) -> Crc32c {
        self.crc
    }

    /// The tenure's session once both bootstrap roots carrying it persisted or the warm bootstrap committed
    /// allocation readiness, which every record this volume writes carries; zero until then.
    pub(crate) fn session(&self) -> u64 {
        self.session
    }

    /// Whether both RESET roots are persisted, or the warm bootstrap opened, so payload writes are admitted.
    pub(crate) fn admits_payload_writes(&self) -> bool {
        self.metadata.is_open()
    }

    /// Whether `storage` is the storage this volume was attached to: the one whose slot table a fill's identity indexes.
    pub(crate) fn serves(&self, storage: &Storage<P>) -> bool {
        std::ptr::eq(self.storage, storage)
    }

    /// Table slots the fills' writes may hold whatever the metadata commands claim: the depth less the read, metadata and reservation shares.
    pub(crate) fn write_share(&self) -> u32 {
        self.write_commands
    }

    /// Write commands the volume admits now: the write share and each metadata slot that no staged or outstanding metadata command claims, less the commands the writes hold.
    /// A metadata cell claims its slot from staging to its command's end, so the room falls as soon as a command is staged.
    pub(crate) fn write_room(&self) -> u32 {
        let claimed = self.metadata.commands.iter().flatten().count() as u32;
        let unclaimed = self.storage.metadata_commands.saturating_sub(claimed);
        (self.write_commands + unclaimed).saturating_sub(self.write_held)
    }

    /// Write commands that ended since attach, by an applied terminal or by the proven stop failing a submit whose driver call unwound. [`write_outstanding`](Self::write_outstanding) of a set falls only when this rises, so a caller that read every set it follows at one value of this count, and reads a set again after each submit it makes on it, holds exact counts for as long as the value stands.
    pub(crate) fn write_ends(&self) -> u64 {
        self.write_ends
    }

    /// Bytes one write command carries at most: `min(receive-write buffer length, max_transfer)`.
    pub(crate) fn segment_len(&self) -> usize {
        self.write_max as usize
    }

    /// A receive-write buffer for a fill to copy into.
    pub(crate) fn acquire_write_buffer(&self) -> Result<Buffer<'a>, PoolExhausted> {
        self.arena.acquire(PoolKind::ReceiveWrite)
    }

    /// Begins the write set of the fill that owns `id`'s object of `units` units, whose first extent is `locator` and whose attempt record is `attempt` under `serial`.
    /// A full array first reclaims every set with nothing outstanding whose fill ended.
    ///
    /// # Panics
    ///
    /// If `id`'s slot is outside this volume's storage: the caller checked [`serves`](Self::serves) for the fill's storage, so every set's slot indexes this storage's slot table, the bound `write_at` and `apply_write` rely on.
    pub(crate) fn begin_fill(
        &mut self,
        id: AllocationId,
        locator: ExtentLocator,
        units: u32,
        attempt: &'s AtomicU64,
        serial: FillSerial,
    ) -> Option<WriteSet> {
        assert!(
            id.slot().0 < self.storage.pool().records().len(),
            "a fill's slot outside the volume's storage"
        );
        let record = WriteRecord {
            authority: self.serving_token(),
            start_unit: locator.start_unit(),
            extent_units: locator.len_units(),
            progress: WriteProgress {
                len_units: units,
                ..WriteProgress::default()
            },
            id,
            attempt,
            serial,
        };
        let record = match self.writes.insert(record) {
            Ok((slot, generation)) => return Some(WriteSet { slot, generation }),
            Err(record) => record,
        };
        for slot in 0..self.writes.len() {
            if let Some((_, set)) = self.writes.slot_mut(slot)
                && set.progress.outstanding_commands == 0
                && fill::ended(set.attempt.load(Ordering::Relaxed), set.serial)
            {
                self.writes.remove(slot);
            }
        }
        let (slot, generation) = self.writes.insert(record).ok()?;
        Some(WriteSet { slot, generation })
    }

    /// Moves the set to the object's next extent, `locator`; commands of earlier extents stay counted until their terminals.
    pub(crate) fn next_extent(&mut self, set: WriteSet, locator: ExtentLocator) {
        if let Some(record) = self.writes.get_mut(set.slot, set.generation) {
            record.start_unit = locator.start_unit();
            record.extent_units = locator.len_units();
        }
    }

    /// Submits the start of `buffer` as the set's command at `offset_units` of its current extent: `min(remaining from there, segment_len)` bytes.
    /// Precondition: `offset_units` is below the extent's units, so the command writes at least one unit.
    /// A command submitted with no [`write_room`](Self::write_room) refuses `TableFull` before its right is installed, and each command is charged before its driver call and uncharged by a definite refusal, its terminal or the proven stop after an unwound call.
    /// The first command of an interval with nothing outstanding installs the set's right first.
    ///
    /// # Errors
    ///
    /// On table refusal, `Closed`, or an invalid command range (`OutOfCapacity`), the call returns the buffer and preserves the set, token map, and slot count.
    pub(crate) fn write_at(
        &mut self,
        set: WriteSet,
        buffer: Buffer<'a>,
        offset_units: u32,
    ) -> Result<(), (Buffer<'a>, Refusal)> {
        let token = self
            .writes
            .get(set.slot, set.generation)
            .and_then(|record| record.authority);
        if self.closed
            || self
                .admit_authority(crate::failover::serving::Operation::Fill, token)
                .is_err()
        {
            return Err((buffer, Refusal::Closed));
        }
        // RESET-BEFORE-OVERWRITE: `receive` refuses `Bootstrapping` before any payload write, so a payload write before the volume opened, by its bootstrap roots or the warm commit, is a caller defect.
        assert!(
            self.metadata.is_open(),
            "a payload write submitted before both RESET roots persisted or the warm commit"
        );
        let room = self.write_room();
        let Some(record) = self.writes.get_mut(set.slot, set.generation) else {
            return Err((buffer, Refusal::Closed));
        };
        if room == 0 {
            return Err((
                buffer,
                Refusal::TableFull {
                    abandoned: self.table.report().abandoned,
                },
            ));
        }
        let remaining = (record.extent_units - offset_units) as usize * IO_UNIT;
        let len = remaining.min(self.write_max as usize) as u32;
        let Some(range) = self.descriptor.device_range(
            record.start_unit,
            u64::from(offset_units) * IO_UNIT as u64,
            len,
        ) else {
            return Err((buffer, Refusal::OutOfCapacity));
        };
        #[cfg(test)]
        super::write_guard::check(self.storage, record.id, range);
        // SAFETY: `begin_fill` asserted the set's slot is below this storage's `O`.
        let slot_word = unsafe { self.storage.pool().slot_word(record.id.slot().0) };
        let installs = record.progress.outstanding_commands == 0;
        if installs && !word::install(slot_word, record.id.incarnation(), 1) {
            panic!("a filling slot's count is nonzero or its word names another object");
        }
        debug_assert!(self.scratch.is_empty(), "terminals apply before submits");
        let units = len / IO_UNIT as u32;
        record.progress.outstanding_commands += 1;
        record.progress.outstanding_units += units;
        self.unwound_writes += 1;
        self.write_held += 1;
        let withdrawal = super::tick::WithdrawOnUnwind(&self.storage.readiness);
        let result = self.table.submit_write(buffer, range);
        withdrawal.returned();
        self.unwound_writes -= 1;
        match result {
            Ok(token) => {
                record.progress.submitted_units += units;
                map_token(&mut self.tokens, token, Owner::Write(set.slot), units);
                #[cfg(test)]
                {
                    let serial = record.serial.get();
                    self.record_bound(token, super::attach::Bound::Write { set, serial });
                }
                self.report.writes_submitted += 1;
                self.recovery.submitted_write(&self.storage.readiness);
                Ok(())
            }
            Err(Rejected { buffer, refusal }) => {
                self.write_held -= 1;
                record.progress.outstanding_commands -= 1;
                record.progress.outstanding_units -= units;
                self.report.writes_refused += 1;
                if installs {
                    release_right(self.storage, record.id);
                }
                Err((buffer, refusal))
            }
        }
    }

    /// The progress of a live set, failed as well once the set's serving token admits no fill at the owner's latest deadline sample.
    pub(crate) fn write_progress(&self, set: WriteSet) -> Option<WriteProgress> {
        self.writes.get(set.slot, set.generation).map(|record| {
            let mut progress = record.progress;
            progress.failed |= self
                .admit_authority_at_sample(
                    crate::failover::serving::Operation::Fill,
                    record.authority,
                )
                .is_err();
            progress
        })
    }

    /// Write commands of a live set that await terminal outcomes.
    pub(crate) fn write_outstanding(&self, set: WriteSet) -> Option<u32> {
        self.writes
            .get(set.slot, set.generation)
            .map(|record| record.progress.outstanding_commands)
    }

    /// Frees a set with nothing outstanding; a set with a command outstanding stays until its last terminal.
    pub(crate) fn end_fill(&mut self, set: WriteSet) {
        if self
            .writes
            .get(set.slot, set.generation)
            .is_some_and(|record| record.progress.outstanding_commands == 0)
        {
            self.writes.remove(set.slot);
        }
    }

    /// Applies one write terminal to the set in `slot`: the right is released at the last outstanding terminal, before the units it completes, and the set is freed there when its fill ended.
    #[inline(never)]
    /// Applies one write terminal. `written` counts only while the set's serving
    /// token admits fills at the owner's latest deadline sample; a write that
    /// completes after its incarnation ended fails the set.
    pub(super) fn apply_write(&mut self, slot: u32, written: bool, units: u32) {
        let Some((_, record)) = self.writes.slot_mut(slot) else {
            return;
        };
        let written = written
            && self
                .authority
                .admit_at_sample(crate::failover::serving::Operation::Fill, record.authority)
                .is_ok();
        record.progress.outstanding_commands -= 1;
        record.progress.outstanding_units -= units;
        self.write_held -= 1;
        self.write_ends += 1;
        if record.progress.outstanding_commands == 0 {
            release_right(self.storage, record.id);
        }
        if written {
            record.progress.completed_units += units;
            self.report.writes_done += 1;
        } else {
            record.progress.failed = true;
            self.report.writes_failed += 1;
        }
        // `Relaxed`: the fill's end ran on this thread, so the load reads its departure or a later word.
        if record.progress.outstanding_commands == 0
            && fill::ended(record.attempt.load(Ordering::Relaxed), record.serial)
        {
            self.writes.remove(slot);
        }
    }

    /// After a proven stop with every taken terminal applied, a set still counting a command holds only submits whose driver call unwound: each such set fails, and its right is released.
    #[inline(never)]
    pub(super) fn fail_unwound_writes(&mut self) {
        if self.unwound_writes == 0 {
            return;
        }
        self.unwound_writes = 0;
        for slot in 0..self.writes.len() {
            let Some((_, record)) = self.writes.slot_mut(slot) else {
                continue;
            };
            if record.progress.outstanding_commands > 0 {
                self.write_held -= record.progress.outstanding_commands;
                self.write_ends += u64::from(record.progress.outstanding_commands);
                record.progress.outstanding_commands = 0;
                record.progress.outstanding_units = 0;
                record.progress.failed = true;
                release_right(self.storage, record.id);
                if fill::ended(record.attempt.load(Ordering::Relaxed), record.serial) {
                    self.writes.remove(slot);
                }
            }
        }
    }

    /// Write sets the array holds.
    #[cfg(test)]
    pub(crate) fn write_sets(&self) -> u32 {
        self.writes.live()
    }

    /// Payload write submits whose driver call unwound, counted until `fail_unwound_writes` clears the count.
    #[cfg(test)]
    pub(crate) fn unwound_writes(&self) -> u32 {
        self.unwound_writes
    }
}
