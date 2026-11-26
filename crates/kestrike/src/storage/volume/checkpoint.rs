//! The tenure's checkpoint-unit commands: a capture's unit writes and read-backs through the metadata owner's journal
//! cell, which holds one checkpoint-unit command at a time, each admitted only while the serving table admits the
//! checkpoint-unit kind, which it does in Serving alone, and a write only of a staged checkpoint's retained unit
//! bytes to the slot the tenure's possibly-named set reserved for that stage, before its Publish
//! (`ReservedBeforeWrite`, `SlotNotOverwrittenWhileNamed`). A unit command runs once: a device failure, a refusal or
//! the volume's end yields `UnitDone::Failed`, and a retry stages the same unit's bytes again.
//!
//! The same cell carries the tenure's suffix blocks, which go first: while a sealed block waits, a unit command
//! refuses `Busy`. A block write is admitted under the checkpoint-unit kind, its failure keeps the block queued with
//! its payload for the next stage, which encodes the same bytes (UNIQUE-BLOCK), and only its `Written` terminal,
//! which the persistence profile makes the block's persistence, advances the log's durable prefix, which the tick
//! then publishes to the journal words' prefix word (HOLD-UNTIL-DURABLE).
//!
//! Prefix unit `u` lies at byte `u * UNIT_LEN` of the metadata area, and the possibly-named set's recorded layout
//! maps unit `j` of slot `k` to prefix unit `1 + k * S + j`.
//!
//! A capture's whole-cut encode runs as one recovery-helper job ([`Volume::encode`]). The owner thread reserves the
//! stage's slot in the tenure's possibly-named set before the dispatch, and the job carries that reservation and
//! the cut alone, so the set stays with the thread that holds it (`PossNamedCoversStore`) while the encode runs.
//! The same pool frees what an ended pass holds, its side list and its stage's units ([`Volume::discard`]).

use std::sync::atomic::Ordering;

use crate::failover::records::Layout;
use crate::failover::serving::MetadataKind;

use super::super::checkpoint::{Cut, PossiblyNamed, Reservation, StageRefusal, StagedCheckpoint};
use super::super::device::{Disk, PoolKind};
use super::super::ledger::EngineBudget;
use super::super::os::Platform;
use super::super::record::Crc32c;
use super::super::recovery::CaptureEntry;
use super::super::recovery::checkpoint::{UNIT_LEN, Units};
use super::attach::Volume;
pub(crate) use super::helpers::Panicked;
use super::helpers::{Charge, Helpers, Job, Output};
use super::metadata::{Command, JOURNAL, Target};

/// A capture pass's whole-cut encode: [`StagedCheckpoint::encode`] of the walk's copy `cut` into the slot
/// `reservation` holds, which the owner thread reserved in the tenure's possibly-named set before the dispatch. The
/// `input` bytes the cut holds outside the capture policy's side-list charge, the encoded units and the kept unit
/// buffers are checked together against `budget`, since the job holds them all.
#[derive(Debug)]
pub(crate) struct Encode {
    pub(crate) reservation: Reservation,
    pub(crate) cut: Cut,
    pub(crate) input: usize,
    pub(crate) budget: EngineBudget,
    /// The unit buffers the tenure kept from its last pass, which the encode writes before it allocates any.
    pub(crate) kept: Units,
}

/// An encode's terminal: the stage, or the refusal with the reservation for the set's holder to release, the cut,
/// emptied, whose chunks the tenure's next walk fills, and the kept unit buffers the stage did not take.
#[derive(Debug)]
pub(crate) struct Encoded {
    pub(crate) staged: Result<StagedCheckpoint, (StageRefusal, Reservation)>,
    pub(crate) cut: Cut,
    /// Empty after a refused stage: a refusal frees the kept buffers on the helper.
    pub(crate) kept: Units,
    /// The name of the thread that ran the encode.
    #[cfg(test)]
    pub(crate) thread: Option<String>,
}

impl Encode {
    /// Runs the encode, then empties the cut on this thread: it frees the side list and the chunks the walk left
    /// unused, and the terminal returns the chunks the walk filled. A refused stage frees the kept unit buffers here.
    pub(super) fn run(mut self, crc: Crc32c) -> Encoded {
        let mut budget = self.budget;
        let staged = match budget.charge(self.input) {
            Ok(()) => StagedCheckpoint::encode(
                crc,
                self.reservation,
                (&self.cut, &mut self.kept),
                &budget,
            ),
            Err(_) => Err((StageRefusal::Memory, self.reservation)),
        };
        if staged.is_err() {
            drop(std::mem::take(&mut self.kept));
        }
        self.cut.trim();
        drop(self.cut.recycle());
        Encoded {
            staged,
            cut: self.cut,
            kept: self.kept,
            #[cfg(test)]
            thread: std::thread::current().name().map(str::to_owned),
        }
    }
}

/// What a capture pass that ended holds to free: the side list of its cut, the unit buffers its tenure kept, or both.
#[derive(Debug, Default)]
pub(crate) struct Leftovers {
    pub(crate) saved: Vec<CaptureEntry>,
    pub(crate) units: Vec<Box<[u8; UNIT_LEN]>>,
}

/// A checkpoint-unit command's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnitDone {
    Written {
        slot: u32,
        unit: u32,
    },
    /// The read-back ended; [`take_unit_for`](Volume::take_unit_for) compares its bytes with the stage's.
    Read {
        slot: u32,
        unit: u32,
    },
    /// The device failed or refused the command, or the volume ended, stopped, closed, was lost or withdrew before
    /// its terminal.
    Failed {
        slot: u32,
        unit: u32,
    },
}

/// Why a checkpoint-unit command was not staged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnitRefused {
    /// The slot is named, quarantined, or reserved by another stage, or the staged checkpoint's Publish was submitted.
    Unreserved,
    /// The volume is not open, is closed or lost, or its readiness stops metadata, or the serving table refuses the
    /// checkpoint-unit kind: no clock sample, no serving token, or a state other than Serving.
    Unadmitted,
    /// A unit command or suffix block write is staged or outstanding, a unit or delta result was not taken, or a
    /// sealed suffix block waits for its write.
    Busy,
    /// The slot or unit lies outside the layout or the metadata area, or the device profile refuses the unit's
    /// range.
    Range,
    /// No maintenance buffer is free.
    Buffer,
}

impl<'s, 'a, P: Platform, D: Disk> Volume<'s, 'a, P, D> {
    /// Stages the write of unit `unit` of `staged` into its reserved slot under `possible`'s layout, and records the
    /// write in `staged` once it is staged.
    ///
    /// # Errors
    ///
    /// `Unreserved` when the slot is named, quarantined, or reserved by another stage, or `staged`'s Publish was
    /// submitted; `Range` for a unit past the stage's units; then as [`stage_unit_read`](Self::stage_unit_read).
    pub(crate) fn stage_unit_write(
        &mut self,
        possible: &PossiblyNamed,
        staged: &mut StagedCheckpoint,
        unit: u32,
    ) -> Result<(), UnitRefused> {
        if !possible.admits(staged) {
            return Err(UnitRefused::Unreserved);
        }
        let bytes = staged
            .units()
            .get(unit as usize)
            .ok_or(UnitRefused::Range)?;
        self.stage_unit(possible.layout(), (staged.slot(), unit), Some(bytes))?;
        staged.wrote(unit);
        Ok(())
    }

    /// Stages the read-back of unit `unit` of slot `slot` under `possible`'s layout.
    ///
    /// # Errors
    ///
    /// `Unadmitted`, `Busy`, `Range` or `Buffer`, in that order.
    pub(crate) fn stage_unit_read(
        &mut self,
        possible: &PossiblyNamed,
        (slot, unit): (u32, u32),
    ) -> Result<(), UnitRefused> {
        self.stage_unit(possible.layout(), (slot, unit), None)
    }

    /// Dispatches `encode` to the volume's capture pool ([`capture_helpers`](Self::capture_helpers)). The job holds no
    /// charge of the pool's byte bounds: [`Encode::run`] checks its input and units against the job's engine budget.
    /// The encode holds the one reservation of the tenure's possibly-named set, so a tenure has one encode in flight,
    /// and [`discard`](Self::discard) leaves it a job of the pool's bound.
    ///
    /// # Errors
    ///
    /// `encode`, undispatched, while the volume is lost or closed, its readiness stops metadata work, or the
    /// metadata is not open; while the pool's job bound is reached; or when the pool cannot start.
    pub(crate) fn encode(&mut self, encode: Encode) -> Result<(), Box<Encode>> {
        let crc = self.crc;
        let helpers = match self.metadata_admits() {
            true => self.capture_helpers(),
            false => None,
        };
        let Some(helpers) = helpers else {
            return Err(Box::new(encode));
        };
        if !helpers.reserve(Charge::default()) {
            return Err(Box::new(encode));
        }
        helpers.dispatch(Charge::default(), Job::Encode(Box::new(encode), crc));
        Ok(())
    }

    /// Frees `leftovers`, what a capture pass that ended holds, on the volume's capture pool, so the owner thread
    /// pays one dispatch for a side list or a stage of any size. The calling thread frees them while the volume
    /// admits no encode (lost, closed, a readiness that stops metadata work, or metadata that is not open), when the
    /// pool cannot start, and when the dispatch would take the last job of the pool's bound, which stays free for
    /// the tenure's next encode. Returns `true` if the pool accepts the discard job, and
    /// [`discarded`](Self::discarded) reports the job's completion. Returns `false` if the calling thread drops
    /// `leftovers`.
    pub(crate) fn discard(&mut self, leftovers: Leftovers) -> bool {
        if (leftovers.saved.is_empty() && leftovers.units.is_empty()) || !self.metadata_admits() {
            return false;
        }
        let Some(helpers) = self.capture_helpers() else {
            return false;
        };
        let taken = helpers.room() >= 2 && helpers.reserve(Charge::default());
        if taken {
            helpers.dispatch(Charge::default(), Job::Discard(Box::new(leftovers)));
        }
        taken
    }

    /// Reports whether the capture pool's helper has finished cleanup for every accepted [`discard`](Self::discard).
    /// The call adopts the terminals that arrived. While the metadata is closed it returns `true` and leaves the
    /// pool's terminals for the warm bootstrap's poll.
    pub(crate) fn discarded(&mut self) -> bool {
        if !self.metadata.is_open() {
            return true;
        }
        (self.metadata.helpers.as_mut()).is_none_or(|helpers| {
            Self::adopt_discards(helpers);
            !helpers.busy()
        })
    }

    /// Adopting completed capture-pool discards releases their jobs. A pass waits for any encode from the same
    /// tenure to finish before dispatching a capture job, so only discard terminals reach this function.
    fn adopt_discards(helpers: &mut Helpers) {
        let mut adopted = 0;
        while let Some(landed) = helpers.poll(&mut adopted) {
            assert!(
                !matches!(landed, Ok(Output::Encoded(_))),
                "a pass dispatches a capture job with no encode in flight"
            );
        }
    }

    /// The pool that runs a serving tenure's encodes and discards, started with one helper when none accepts jobs:
    /// it runs one job at a time. A pool the start replaces, the warm load's cancelled pool, is retired with its
    /// threads still finishing their queued jobs, and the volume's drop joins it; a failed start keeps it retired
    /// and returns `None`. The call adopts the terminals of discards that landed, which releases their jobs: a pass
    /// dispatches a capture job only with no encode of its tenure in flight, so no encode's terminal waits here.
    fn capture_helpers(&mut self) -> Option<&mut Helpers> {
        let accepting = (self.metadata.helpers.as_ref()).is_some_and(Helpers::accepting);
        if !accepting {
            self.record_helper_peaks();
            // Only a pool that exists retires, so a retry after a failed start keeps the retired warm pool; a tenure
            // starts one pool after its warm load's.
            if let Some(replaced) = self.metadata.helpers.take() {
                self.metadata.retired = Some(replaced);
            }
            let limits = super::helpers::RecoveryLimits {
                helpers: 1,
                ..self.storage.recovery
            };
            self.start_helpers(limits).ok()?;
        }
        let helpers = self.metadata.helpers.as_mut()?;
        Self::adopt_discards(helpers);
        Some(helpers)
    }

    /// The terminal of the last [`encode`](Self::encode), once it landed; `Err` when the job panicked, which drops
    /// the reservation it held. `None` while the metadata is not open, so a warm bootstrap's terminals stay for its
    /// own poll. A discard's terminal that lands before it releases its job and yields nothing. A cancel of the
    /// pool leaves the terminal stale, so the encode never lands and the set keeps its reservation: a withheld
    /// readiness and the metadata's end of an open volume each cancel it, and after either no later checkpoint of
    /// the tenure can publish.
    pub(crate) fn take_encoded(&mut self) -> Option<Result<Encoded, Panicked>> {
        if !self.metadata.is_open() {
            return None;
        }
        let helpers = self.metadata.helpers.as_mut()?;
        let mut adopted = 0;
        loop {
            match helpers.poll(&mut adopted)? {
                Ok(Output::Encoded(encoded)) => return Some(Ok(*encoded)),
                Ok(Output::Freed) => {}
                Ok(Output::Slot(_) | Output::Restored(_)) => {
                    unreachable!("a capture pool runs encodes and discards alone")
                }
                Err(Panicked) => return Some(Err(Panicked)),
            }
        }
    }

    /// Releases every terminal a parked test pool holds, in the order the owner receives them.
    #[cfg(test)]
    pub(crate) fn release_parked(&mut self) {
        if let Some((ran, released)) = (self.metadata.helpers.as_mut()).and_then(Helpers::parked) {
            released.extend(ran.drain(..));
        }
    }

    /// Whether `layout` is the layout the volume's checkpoint and suffix writes may use: after a warm load, the
    /// layout the load read under, equal in every field; otherwise a layout over the attached metadata prefix.
    pub(crate) fn admits_layout(&self, layout: &Layout) -> bool {
        match self.metadata.loaded {
            Some(loaded) => loaded == *layout,
            None => layout.units == self.storage.pool().descriptor().geometry.metadata_units(),
        }
    }

    /// The admission a capture's unit command and encode share: the volume is neither lost nor closed, its
    /// readiness admits metadata work, and its metadata is open.
    fn metadata_admits(&self) -> bool {
        !self.lost && !self.closed && !self.readiness().stops_metadata() && self.metadata.is_open()
    }

    /// Records `UnitDone::Failed` for a staged, unsubmitted unit command or one whose submit unwound in the driver. A
    /// staged suffix block write is dropped with no result, so its block stays outstanding in the log, which then
    /// refuses appends once the stall bound passes.
    pub(super) fn fail_unmapped_unit(&mut self) {
        let unwound = std::mem::take(&mut self.metadata.unit_unwound);
        let ends = unwound
            || self.metadata.commands[JOURNAL]
                .as_ref()
                .is_some_and(|command| command.buffer.is_some());
        let ended = ends
            .then(|| self.metadata.commands[JOURNAL].take())
            .flatten();
        // A staged command leaves the cell with its buffer; one whose submit unwound gave its buffer to the driver.
        let staged = ended
            .as_ref()
            .is_some_and(|command| command.buffer.is_some());
        self.metadata.staged -= u32::from(staged);
        if let Some(failed) = ended.and_then(|command| super::metadata::unit_failed(command.target))
        {
            self.metadata.unit = Some(failed);
        }
    }

    /// The result of the last unit command, once it ended.
    #[cfg(test)]
    pub(crate) fn take_unit(&mut self) -> Option<UnitDone> {
        self.metadata.unit.take()
    }

    /// The result of the last unit command, once it ended, with a read-back of `staged`'s slot recorded in `staged`.
    pub(crate) fn take_unit_for(&mut self, staged: &mut StagedCheckpoint) -> Option<UnitDone> {
        let done = self.metadata.unit.take()?;
        if let UnitDone::Read { slot, unit } = done {
            staged.read_back((slot, unit), &self.metadata.unit_bytes);
        }
        Some(done)
    }

    /// Whether a suffix block goes to the journal cell before a checkpoint-unit command: a delta result waits or a
    /// sealed block waits for its write. Read from the published due time, with no mutex try.
    fn delta_due(&self) -> bool {
        self.metadata.delta.is_some()
            || (self.storage.live_pool())
                .is_some_and(|pool| pool.suffix_due.load(Ordering::Relaxed) == 0)
    }

    /// The delta writer's one wake condition, which the tick's readiness and the writer share: a delta result waits,
    /// or the journal cell is empty and the log's published due time, and any retry time, passed. An idle log costs
    /// one relaxed load; a waiting one adds one clock sample and no mutex try.
    pub(super) fn delta_wake(&self) -> bool {
        self.delta_woken().is_some()
    }

    /// [`delta_wake`](Self::delta_wake) with the clock sample it read: `None` when it does not hold, `Some(None)`
    /// when a delta result waits and no sample was read, and `Some(Some(now))` when the due and retry times passed
    /// at `now`.
    fn delta_woken(&self) -> Option<Option<u64>> {
        if self.metadata.delta.is_some() {
            return Some(None);
        }
        let pool = self.storage.live_pool()?;
        let due = pool.suffix_due.load(Ordering::Relaxed);
        if due == u64::MAX || self.metadata.commands[JOURNAL].is_some() {
            return None;
        }
        (self.storage.platform.now_ticks())
            .filter(|&now| now >= due.max(self.metadata.delta_retry.0))
            .map(Some)
    }

    /// The suffix's delta writer, under one try of the capture mutex once [`delta_wake`](Self::delta_wake) holds:
    /// gives the log the last block write's result, publishing its durable prefix to the journal words' prefix word
    /// with release once a write persisted, seals the open block once its flush interval passed, then, while the
    /// serving table admits the checkpoint-unit kind, charges the next sealed block to the recovery I/O share,
    /// encodes it into a maintenance buffer and stages it in the empty journal cell at its prefix unit, and publishes
    /// the log's next due time. A block it cannot stage for want of a buffer, of admission or of room in the share
    /// waits one flush interval before the next try. A failed clock sample reads as the wake's sample, an earlier
    /// time; with neither sample the stage seals and stages nothing and the retry time stands. A block whose
    /// write failed more than `metadata_retries` times, or whose unit the area cannot hold, ends the metadata
    /// `MetadataFailed`, which closes admission; until then appends stay bounded by the queue and the stall bound.
    pub(super) fn stage_delta(&mut self) {
        let Some(woken_at) = self.delta_woken() else {
            return;
        };
        let Some(pool) = self.storage.live_pool() else {
            return;
        };
        let Ok(mut capture) = pool.capture_membership_lock() else {
            return;
        };
        #[cfg(test)]
        DELTA_TRIES.with(|tries| tries.set(tries.get() + 1));
        let log = &mut capture.suffix;
        let mut failures = self.metadata.delta_retry.1;
        if let Some((lsn, written)) = self.metadata.delta.take() {
            if written {
                log.written(lsn);
                failures = 0;
                // Release pairs with service's acquire load: a slot returned on this prefix has its block's
                // persistence ordered before the return. The tick is the word's one writer.
                (self.journal_words.prefix).store(log.durable(), Ordering::Release);
            } else {
                log.failed(lsn);
                failures = failures.saturating_add(1);
            }
        }
        // A failed sample falls back to the wake's, so a retry time set below lies one flush interval past a read time.
        let now = self.storage.platform.now_ticks().or(woken_at);
        let mut retry = match now {
            Some(now) => {
                log.flush_due(now);
                0
            }
            None => self.metadata.delta_retry.0,
        };
        // A block past its retries is not taken again, so the end below drops no outstanding write.
        let mut fatal = failures > self.metadata.retries;
        let staging =
            now.filter(|_| !fatal && self.metadata.commands[JOURNAL].is_none() && log.pending());
        if let Some(now) = staging {
            let buffer = (self.metadata_authorized(MetadataKind::CheckpointUnit))
                .then(|| self.arena.acquire(PoolKind::Maintenance).ok())
                .flatten();
            // The block is taken only with a buffer in hand, so a missing buffer leaves it pending for the next
            // stage; the log charges the block to the recovery I/O share at this tick and encodes its unit into the
            // buffer's first unit, and a block the share refuses stays queued.
            let (share, tick) = (&mut self.recovery_io, self.recovery.now());
            let taken = buffer.and_then(|mut buffer| {
                let unit = buffer.bytes_mut().first_chunk_mut::<UNIT_LEN>()?;
                let lsn = log.take_within(share, tick, unit)?;
                Some((buffer, lsn))
            });
            match taken {
                Some((buffer, lsn)) => {
                    let at = log.unit(lsn);
                    match at.and_then(|at| Some((at, self.metadata.area.unit_range(at)?))) {
                        Some((unit, range)) => {
                            let command = Command::unit(Target::Delta(lsn), unit, range, buffer);
                            self.metadata.stage(JOURNAL, command);
                        }
                        None => {
                            log.failed(lsn);
                            fatal = true;
                        }
                    }
                }
                None => retry = now.saturating_add(log.flush_ns()),
            }
        }
        pool.suffix_wake(log);
        drop(capture);
        self.metadata.delta_retry = (retry, failures);
        if fatal {
            self.end(super::super::recovery::MetadataOutcome::MetadataFailed);
        }
    }

    /// Stages unit `unit` of slot `slot`: a write of `bytes`, or a read-back when `bytes` is `None`.
    fn stage_unit(
        &mut self,
        layout: &Layout,
        (slot, unit): (u32, u32),
        bytes: Option<&[u8; UNIT_LEN]>,
    ) -> Result<(), UnitRefused> {
        if !self.metadata_admits() || !self.metadata_authorized(MetadataKind::CheckpointUnit) {
            return Err(UnitRefused::Unadmitted);
        }
        if self.metadata.commands[JOURNAL].is_some()
            || self.metadata.unit.is_some()
            || self.delta_due()
        {
            return Err(UnitRefused::Busy);
        }
        let prefix = layout.prefix_unit(slot, unit).ok_or(UnitRefused::Range)?;
        let range = self
            .metadata
            .area
            .unit_range(prefix)
            .ok_or(UnitRefused::Range)?;
        let mut buffer = self
            .arena
            .acquire(PoolKind::Maintenance)
            .map_err(|_| UnitRefused::Buffer)?;
        let target = match bytes {
            Some(bytes) => {
                buffer.bytes_mut()[..UNIT_LEN].copy_from_slice(bytes);
                Target::UnitWrite { slot, unit }
            }
            None => {
                // A read-back that moves no bytes then compares unequal: an encoded unit opens with its record
                // header, never all zero, and a reused buffer may still hold the staged write's bytes.
                buffer.bytes_mut()[..UNIT_LEN].fill(0);
                Target::UnitRead { slot, unit }
            }
        };
        (self.metadata).stage(JOURNAL, Command::unit(target, prefix, range, buffer));
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    /// Capture-mutex tries the delta writer took on this thread.
    pub(super) static DELTA_TRIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
