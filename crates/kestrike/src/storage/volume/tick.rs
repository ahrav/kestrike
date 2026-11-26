//! The bounded tick: apply terminals, verify arrived bytes, deliver outcomes, then submit the next commands of kept grants.
//!
//! One call applies at most `terminal_burst` terminals and only while the output has at least two spare slots, folds at most `validate_bytes` bytes into checksums, submits at most `submit_burst` commands, never grows the output and allocates nothing outside the warm bootstrap and an open suffix's delta stage, whose allocations and per-tick work the `volume` module's Tick bounds invariant states.
//! After the terminals, the metadata step submits the bootstrap's staged command, also on a tick with no read and no terminal; reads take the rest of the submit burst.
//! An unmapped terminal is counted stale and changes nothing.
//!
//! A tick at or past an operation's deadline ends it `TimedOut`, also when its command's terminal arrives in that tick, and cancels its current command and every command ahead it has outstanding while the table holds each pending with admission open or lost; an operation with nothing outstanding frees at once.
//! Volume loss ends an operation `Lost` when it has no outstanding command or is verifying arrived bytes, including while a command ahead is outstanding. An operation awaiting its current command ends `Lost` at that command's terminal. An expired deadline takes precedence with `TimedOut`.
//! A command whose submit unwound ends only at the proven stop: the first tick after the table proved a stop, delivered every record and had every taken terminal applied.
//! A tick marks itself armed for its length, so a tick that unwinds leaves the volume lost.
//! A read waiting for a grant waits outside the ready set with its deadline under `next_deadline`; a read whose kept grant's submit found no room, for its next command or for a command ahead, waits in the waiting set, and a tick submits from that set only while reads hold fewer than `read_commands` table slots, stopping at the first submit refused as full.
//! `close` puts both back into the ready set and later ticks end them `Quiesced` as output room allows, and a lost volume's tick with output room visits the live records in slot order from the cursor while two output slots stay spare, which ends each one free to end `Lost`.
//! Reads take the byte budget in slot order from a cursor that moves one slot only on a call that serves them, so a call without output room keeps every read's turn.

use std::mem;
use std::ops::Range;

use super::super::device::{
    Admission, CommandTable, CommandToken, Disk, Failure, PoolKind, Refusal, RefusalReason,
    SubmitRefusal, Terminal, slot_of,
};
use super::super::geometry::extent_count;
use super::super::os::Platform;
use super::super::prefetch::{LINE, hint_read};
use super::super::record::{Crc32c, HeaderMismatch, ValidRecordConfig, check_header, feed_header};
use super::attach::{Owner, TickReport, Volume, VolumeReport};
use super::read::{
    ChunkTables, Place, ReadEvent, ReadOp, ReadRecord, ReadStatus, Stage, VerifiedReadInfo,
    Verifying,
};

const ARRIVAL_HINTS: usize = 2;

/// `WithdrawOnUnwind` withdraws readiness while the call it guards unwinds.
pub(super) struct WithdrawOnUnwind<'w>(pub(super) &'w super::super::readiness::Word);

impl WithdrawOnUnwind<'_> {
    /// `returned` disarms the guard after the guarded call returns.
    pub(super) fn returned(self) {
        std::mem::forget(self);
    }
}

impl Drop for WithdrawOnUnwind<'_> {
    fn drop(&mut self) {
        let _ = self.0.apply(super::super::readiness::Event::Withdraw);
    }
}

fn spare<T>(out: &Vec<T>) -> usize {
    out.capacity() - out.len()
}

impl<'a, P: Platform, D: Disk> Volume<'_, 'a, P, D> {
    /// Advances every operation by one bounded step and pushes its events into `out`.
    ///
    /// The call applies at most `terminal_burst` terminals, folds at most `validate_bytes` bytes into checksums and submits at most `submit_burst` commands.
    /// It works only while `out` has at least two spare slots and pushes at most one `Chunk` and one `Done` per operation, so `out` keeps its capacity; an `out` with fewer than two spare slots gets no events and no terminal applies.
    /// Operations share the byte budget in slot order, starting one slot later each call that serves: a call with at least two spare output slots, a live operation and work to do (a taken terminal, a ready read, a waiting read the share has room for, a sweep, the proven stop, or a metadata command the call submits).
    /// A call with fewer than two spare output slots, or with room and nothing to do, leaves the cursor, so every ready operation is visited within `read_ops` calls that have room, however many calls without room fall between them.
    /// The call visits the operations with work, and every live operation at or past `next_deadline`, after a proven stop or once the volume is lost; on a lost volume every call that serves visits the live operations in slot order while two output slots stay spare, so every live operation free to end, one with nothing outstanding or verifying arrived bytes, ends `Lost` within as many calls with room as operations are live.
    /// `now` is a tick value on the timeline of every read's deadline; an operation whose deadline is at or below it ends `TimedOut` before it verifies or submits.
    /// `now` also drains the recovery I/O share's bucket and opens its report windows, both of which `HostShare::interval` counts in its ticks, so every volume on a host polls with one nondecreasing clock of the same unit and rate.
    pub fn poll_storage(&mut self, now: u64, out: &mut Vec<ReadEvent<'a>>) -> TickReport {
        self.poll_storage_turn(now, out, true)
    }

    /// Applies deadlines and certified terminals before network receives while
    /// output has two spare slots; loss halts metadata before terminals apply.
    pub(crate) fn poll_terminals(&mut self, now: u64, out: &Vec<ReadEvent<'a>>) {
        if self.armed || self.table.report().admission == Admission::Lost {
            self.lost = true;
        }
        self.armed = true;
        let withdrawal = WithdrawOnUnwind(&self.storage.readiness);
        self.authority_deadlines();
        self.recovery.tick_at(now);
        self.observe_transition();
        if self.lost {
            self.halt_metadata();
        }
        if spare(out) >= 2 {
            let picked = self.table.poll(&mut self.scratch);
            self.report.stale += picked.stale as u64;
            // Collected terminals apply after a deadline pass that follows their collection.
            if !self.scratch.is_empty() {
                self.authority_deadlines();
            }
            while let Some(terminal) = self.scratch.pop() {
                self.apply(terminal, now);
            }
        }
        withdrawal.returned();
        self.armed = false;
    }

    /// Requires `poll_terminals` earlier in this turn, whose deadline sample this call keeps. Polls the device again, so a command that completed since `poll_terminals` applies in this turn with the terminals that call collected, then advances work; the work step samples the deadlines again before it applies a terminal or submits a Report.
    pub(crate) fn poll_storage_prepared(
        &mut self,
        now: u64,
        out: &mut Vec<ReadEvent<'a>>,
    ) -> TickReport {
        self.poll_storage_turn(now, out, false)
    }

    fn poll_storage_turn(
        &mut self,
        now: u64,
        out: &mut Vec<ReadEvent<'a>>,
        sample: bool,
    ) -> TickReport {
        if sample {
            self.authority_deadlines();
        }
        self.authority_ready();
        self.recovery.tick_at(now);
        self.observe_transition();
        // Stored only on its transition, so a tick on a live volume reads the flag and writes nothing to it.
        if self.armed || self.table.report().admission == Admission::Lost {
            self.lost = true;
        }
        self.armed = true;
        if self.lost {
            self.halt_metadata();
        }
        let withdrawal = WithdrawOnUnwind(&self.storage.readiness);
        let report = self.tick(now, out);
        withdrawal.returned();
        self.armed = false;
        if self.lost {
            let _ = self
                .storage
                .readiness
                .apply(super::super::readiness::Event::Withdraw);
        }
        self.observe_recovery();
        report
    }

    /// `lose` records a submit refused for the device's loss and withdraws the attempt.
    fn lose(&mut self) {
        self.lost = true;
        let _ = self
            .storage
            .readiness
            .apply(super::super::readiness::Event::Withdraw);
    }

    fn tick(&mut self, now: u64, out: &mut Vec<ReadEvent<'a>>) -> TickReport {
        let room = spare(out) >= 2;
        if room {
            let picked = self.table.poll(&mut self.scratch);
            self.report.stale += picked.stale as u64;
        }
        // Only `close` moves the table toward `Stopped`, so an open volume skips the proof.
        if self.closed && !self.quiesced {
            let table = self.table.report();
            if table.admission == Admission::Stopped && table.pending + table.abandoned == 0 {
                self.quiesced = true;
            }
        }
        if !room
            || !self.scratch.is_empty()
            || self.quiesced
            || (!self.closed && !self.lost && self.metadata_ready())
            || self.has_step(now)
            || self.authority_report_due()
        {
            self.work(now, out)
        } else {
            TickReport::default()
        }
    }

    /// Whether some read has a step to take: a member of the ready set, a member of the waiting set while the share has room, a deadline a record outside the sets may have reached, or any live record of a lost volume.
    fn has_step(&self, now: u64) -> bool {
        self.reads.live() > 0 && (self.sweeps(now) || self.ready.any() || self.room())
    }

    /// Whether a waiting read may submit: one is waiting and reads hold fewer than `read_commands` table slots.
    fn room(&self) -> bool {
        self.waiting.any() && !self.share_full()
    }

    /// Whether a tick visits every live record: at or past `next_deadline`, or once the volume was lost, which ends a read waiting for a grant `Lost`.
    fn sweeps(&self, now: u64) -> bool {
        now >= self.next_deadline || self.lost
    }

    /// Applies the taken terminals, fails the unwound writes once the stop is proven, then, when the call serves, with output room and a live read, advances the cursor and serves the reads from its old value while the output has room.
    /// Out of line so a tick with nothing to do stays a short straight path.
    #[inline(never)]
    fn work(&mut self, now: u64, out: &mut Vec<ReadEvent<'a>>) -> TickReport {
        let taken = !self.scratch.is_empty();
        // Deadlines precede collected terminals and a due Report's submission.
        if taken || self.authority_report_due() {
            self.authority_deadlines();
        }
        // The counts stay in registers and the report is built once at the end: a field read back from a freshly zeroed report waits on store forwarding.
        let mut terminals = 0;
        while terminals < self.tick.terminal_burst && spare(out) >= 2 {
            let Some(terminal) = self.scratch.pop() else {
                break;
            };
            terminals += 1;
            self.apply(terminal, now);
        }
        // After a proven stop every mapped terminal was applied once the scratch vector is empty, so a command whose submit unwound came back unmapped.
        let stopped = self.quiesced && self.scratch.is_empty();
        if stopped {
            self.fail_unwound_writes();
        }
        // Metadata submits share the burst ahead of reads, after every terminal of this tick applied.
        let reports = self.authority_reports();
        let metadata = self.metadata_step(self.tick.submit_burst - reports);
        let (submitted, validated_bytes) = if spare(out) >= 2
            && self.reads.live() > 0
            && (taken || self.quiesced || metadata > 0 || self.has_step(now))
        {
            let (count, first) = (self.reads.len(), self.cursor);
            self.cursor = if first + 1 == count { 0 } else { first + 1 };
            self.serve(
                now,
                first,
                stopped,
                self.tick.submit_burst - metadata - reports,
                out,
            )
        } else {
            (0, 0)
        };
        TickReport {
            submitted: submitted + metadata + reports,
            terminals,
            validated_bytes,
        }
    }

    /// Serves the operations in slot order from `first`, wrapping once, while `out` has at least two spare slots: the ready set, or every live record when `now` reached `next_deadline`, so a `Reading` record, one waiting for a grant or one whose submit unwound can time out, when the volume was lost, so a read waiting for a grant can end, or when `stopped`, so a record whose submit unwound can end.
    /// Then, on an open volume with submit quota left, it submits waiting reads in the same order while reads hold fewer than `read_commands` table slots, until a submit finds no room.
    ///
    /// Each visited slot keeps its ready bit only while its stage still has work and moves to the waiting set when its granted command found no room; the call returns the commands it submitted and the bytes it folded.
    ///
    /// [`Submission::Busy`] ends submission attempts for the call while verification and outcome delivery continue.
    #[inline(always)]
    fn serve(
        &mut self,
        now: u64,
        first: u32,
        stopped: bool,
        mut quota: u32,
        out: &mut Vec<ReadEvent<'a>>,
    ) -> (u32, usize) {
        let mut budget = self.tick.validate_bytes;
        let mut submitted = 0;
        let per_read = self.max_chunks as usize;
        let count = self.reads.len();
        let closed = self.closed;
        let every = stopped || self.sweeps(now);
        let mut unvisited = self.reads.live();
        // The lowest deadline of the live records this scan leaves outside the ready set, exact only when the scan visits every live record.
        let mut bound = if every { u64::MAX } else { self.next_deadline };
        let mut finished = true;
        // Slots from the cursor to the end, then from the start up to the cursor.
        let (mut from, mut end) = (first, count);
        loop {
            if spare(out) < 2 || unvisited == 0 {
                finished = unvisited == 0;
                break;
            }
            let next = if every {
                (from < end).then_some(from)
            } else {
                self.ready.next(from, end)
            };
            let Some(slot) = next else {
                if end == first {
                    break;
                }
                (from, end) = (0, first);
                continue;
            };
            from = slot + 1;
            let verifying = self
                .reads
                .generation_of(slot)
                .and_then(|generation| self.reads.get(slot, generation))
                .filter(|record| matches!(record.stage, Stage::Verifying(_)))
                .map(|record| record.authority);
            let authorized = verifying.is_none_or(|authority| {
                self.admit_authority(crate::failover::serving::Operation::Read, authority)
                    .is_ok()
            });
            let Some((generation, record)) = self.reads.slot_mut(slot) else {
                debug_assert!(every, "a slot with work holds an operation");
                continue;
            };
            unvisited -= 1;
            let deadline = record.deadline;
            if matches!(record.stage, Stage::Reading) && deadline > now {
                debug_assert!(
                    record.token.is_some(),
                    "a reading record holds its command's mapped token"
                );
                bound = bound.min(deadline);
                continue;
            }
            let op = ReadOp { slot, generation };
            record.unmapped &= !stopped;
            let outstanding = record.outstanding();
            match record.stage {
                Stage::Ending(_) => {}
                Stage::Ended => {
                    if !outstanding {
                        self.free_read(slot);
                        continue;
                    }
                }
                _ if deadline <= now => {
                    let token = record.token;
                    record.stage = Stage::Ending(ReadStatus::TimedOut);
                    quarantine(&mut self.table, &mut self.report, token);
                    for ahead in record.ahead.tokens() {
                        quarantine(&mut self.table, &mut self.report, Some(ahead));
                    }
                }
                _ if self.lost && (!outstanding || matches!(record.stage, Stage::Verifying(_))) => {
                    record.stage = Stage::Ending(ReadStatus::Lost);
                }
                Stage::Next if closed && !outstanding => {
                    record.stage = Stage::Ending(ReadStatus::Quiesced);
                }
                Stage::Verifying(_) if !authorized => {
                    record.stage = Stage::Ending(ReadStatus::Quiesced);
                }
                Stage::Verifying(_) => {
                    let mut tables = ChunkTables {
                        crcs: &mut self.crcs[slot as usize * per_read..][..per_read],
                        window_crcs: &mut self.window_crcs,
                        windows: self.read_windows as usize,
                    };
                    verify(
                        record,
                        &mut tables,
                        &self.record,
                        self.crc,
                        &mut budget,
                        op,
                        out,
                    );
                }
                _ => {}
            }
            // A current command that handed off with chunks left hands the read to its oldest command ahead, which keeps the read's order.
            if matches!(record.stage, Stage::Next)
                && let Some(ahead) = record.ahead.pop_front()
            {
                record.command = ahead.command;
                record.token = ahead.token;
                record.stage = match ahead.arrived {
                    Some(Ok(done)) => Stage::Verifying(Verifying {
                        done,
                        cursor: ahead.command.first,
                        fed: 0,
                        running: self.crc.start(),
                    }),
                    Some(Err(status)) => Stage::Ending(status),
                    None => Stage::Reading,
                };
                if record.granted && quota > 0 && self.can_read_ahead(slot) {
                    match self.submit_next_ahead(slot) {
                        Submission::Submitted => {
                            submitted += 1;
                            quota -= 1;
                        }
                        Submission::Busy => quota = 0,
                        Submission::Deferred | Submission::Ended => {}
                    }
                }
                let Some((_, record)) = self.reads.slot_mut(slot) else {
                    continue;
                };
                let place = record.place(closed);
                if matches!(record.stage, Stage::Reading) {
                    bound = bound.min(deadline);
                }
                self.place(slot, place);
                continue;
            }
            match record.stage {
                Stage::Ending(status) => {
                    record.granted = false;
                    let info = record.info();
                    out.push(ReadEvent::Done { op, info, status });
                    let report = &mut self.report;
                    match status {
                        ReadStatus::Cancelled => report.cancelled += 1,
                        ReadStatus::TimedOut => report.timed_out += 1,
                        ReadStatus::HeaderMismatch(mismatch) => {
                            report.header_mismatch += 1;
                            // A first extent's header naming another key: a fingerprint false
                            // positive or a stale record of another key at the extent;
                            // a later extent's locator comes from the object's block.
                            report.lookup_false_positives += u64::from(
                                mismatch == HeaderMismatch::Key
                                    && record.expected.position.index == 0,
                            );
                        }
                        ReadStatus::ChunkMismatch { .. } => report.chunk_mismatch += 1,
                        ReadStatus::Complete => {
                            report.complete += 1;
                            self.recovery.completed_read(&self.storage.readiness);
                        }
                        _ => {}
                    }
                    if outstanding {
                        record.ahead.keep_outstanding();
                        record.stage = Stage::Ended;
                        self.place(slot, Place::Outside);
                    } else {
                        self.free_read(slot);
                    }
                    continue;
                }
                Stage::Next if !closed && record.granted && !record.unmapped && quota > 0 => {
                    let place = match self.submit_next(slot) {
                        Submission::Submitted => {
                            submitted += 1;
                            quota -= 1;
                            // The command is outstanding, so the record waits for its terminal under the bound.
                            bound = bound.min(deadline);
                            Place::Outside
                        }
                        Submission::Busy => {
                            quota = 0;
                            bound = bound.min(deadline);
                            Place::Waiting
                        }
                        Submission::Deferred => {
                            bound = bound.min(deadline);
                            Place::Waiting
                        }
                        // The refusal decided the outcome, which the next tick delivers.
                        Submission::Ended => Place::Ready,
                    };
                    self.place(slot, place);
                    continue;
                }
                _ => {}
            }
            // A suspended verification keeps its ready bit; a granted command past the burst or without room waits in the waiting set; a record waiting for its grant or the proven stop leaves both sets; every record outside the ready set has its deadline in the bound.
            let place = record.place(closed);
            if !matches!(place, Place::Ready) && !matches!(record.stage, Stage::Ended) {
                bound = bound.min(deadline);
            }
            self.place(slot, place);
        }
        if !closed && !self.lost && quota > 0 && self.waiting.any() {
            self.submit_waiting(now, first, &mut quota, &mut bound, &mut submitted);
        }
        // A full scan that stopped early keeps the old bound, which stays at or below the deadline of every unvisited record outside the ready set.
        self.next_deadline = if every && !finished {
            bound.min(self.next_deadline)
        } else {
            bound
        };
        let validated = self.tick.validate_bytes - budget;
        self.report.validated_bytes += validated as u64;
        (submitted, validated)
    }

    /// Submits waiting reads in slot order from `first`, wrapping once, while `quota` and the read share allow, counting each in `submitted`, and stops at the first submit that finds no room.
    /// A submitted read leaves the waiting set with its deadline in `bound`; a refusal that decided the outcome moves the read to the ready set for the next tick to deliver.
    /// A read whose deadline is at or below `now`, one a sweep that stopped for output room left unvisited, submits nothing and keeps its deadline in `bound`, so a later sweep ends it `TimedOut`.
    #[inline(never)]
    fn submit_waiting(
        &mut self,
        now: u64,
        first: u32,
        quota: &mut u32,
        bound: &mut u64,
        submitted: &mut u32,
    ) {
        let count = self.reads.len();
        let (mut from, mut end) = (first, count);
        while *quota > 0 && !self.share_full() {
            let Some(slot) = self.waiting.next(from, end) else {
                if end == first {
                    break;
                }
                (from, end) = (0, first);
                continue;
            };
            from = slot + 1;
            let Some((_, record)) = self.reads.slot_mut(slot) else {
                self.waiting.set(slot, false);
                continue;
            };
            let deadline = record.deadline;
            if deadline <= now {
                *bound = (*bound).min(deadline);
                continue;
            }
            let ahead = !matches!(record.stage, Stage::Next);
            debug_assert!(
                ahead || (record.granted && !record.unmapped),
                "a waiting read holds a kept grant for its next command"
            );
            if ahead && !self.ahead_waits(slot) {
                self.waiting.set(slot, false);
                continue;
            }
            let submission = if ahead {
                self.submit_next_ahead(slot)
            } else {
                self.submit_next(slot)
            };
            match submission {
                Submission::Submitted => {
                    *submitted += 1;
                    *quota -= 1;
                    *bound = (*bound).min(deadline);
                    self.waiting.set(slot, false);
                }
                Submission::Busy => break,
                // The read stays in the waiting set for a later tick.
                Submission::Deferred => {}
                Submission::Ended if ahead => self.waiting.set(slot, false),
                Submission::Ended => {
                    self.place(slot, Place::Ready);
                    if self.lost {
                        break;
                    }
                }
            }
        }
    }

    /// Records `slot`'s membership in the ready and waiting sets; a read whose kept grant waits for its command ahead stays in the waiting set whatever its place, so a tick with room retries that submit.
    #[inline]
    pub(super) fn place(&mut self, slot: u32, place: Place) {
        self.ready.set(slot, matches!(place, Place::Ready));
        self.waiting.set(
            slot,
            matches!(place, Place::Waiting) || self.ahead_waits(slot),
        );
    }

    pub(super) fn ahead_waits(&self, slot: u32) -> bool {
        self.read_ahead > 0
            && self
                .reads
                .generation_of(slot)
                .and_then(|generation| self.reads.get(slot, generation))
                .is_some_and(|record| record.granted)
            && self.can_read_ahead(slot)
    }

    /// Applies one terminal: a Report of the serving machine or a gate command first, else the record its token maps to; a read whose deadline is at or below `now` ends `TimedOut` whatever the terminal says.
    pub(super) fn apply(&mut self, terminal: Terminal<'a>, now: u64) {
        if self.authority_terminal(&terminal) || self.gate_terminal(&terminal) {
            return;
        }
        let token = terminal.token();
        let entry = &mut self.tokens[usize::from(slot_of(token))];
        let Some(mapped) = entry.take_if(|mapped| mapped.token == token) else {
            self.report.stale += 1;
            return;
        };
        match mapped.owner {
            Owner::Read(slot) => self.apply_read(slot, terminal, now),
            Owner::Write(slot) => {
                let written = matches!(terminal, Terminal::Written { .. });
                self.apply_write(slot, written, mapped.units);
            }
            Owner::Metadata(cell) => self.apply_metadata(cell, terminal),
        }
    }

    fn apply_read(&mut self, slot: u32, terminal: Terminal<'a>, now: u64) {
        let Some((_, record)) = self.reads.slot_mut(slot) else {
            return;
        };
        let token = terminal.token();
        if record.ahead.tokens().any(|ahead| ahead == token) {
            self.read_held -= 1;
            let arrived = matches!(terminal, Terminal::Read { .. });
            self.report.reads_done += u64::from(arrived);
            self.report.reads_failed += u64::from(!arrived);
            match record.stage {
                // An ending read returns the bytes uninspected, and an ended one frees once no command of it is outstanding.
                Stage::Ending(_) | Stage::Ended => {
                    record.ahead.remove(token);
                    if matches!(record.stage, Stage::Ended) && !record.outstanding() {
                        self.free_read(slot);
                    }
                }
                _ => {
                    let Some(ahead) = record.ahead.find(token) else {
                        return;
                    };
                    ahead.token = None;
                    ahead.arrived = Some(match terminal {
                        Terminal::Read { done, .. } => Ok(done),
                        Terminal::Failed {
                            failure: Failure::Short { .. },
                            ..
                        } => {
                            self.report.short += 1;
                            Err(ReadStatus::Short)
                        }
                        Terminal::Failed { .. } => Err(ReadStatus::DeviceError),
                        _ => Err(ReadStatus::Quiesced),
                    });
                }
            }
            return;
        }
        record.token = None;
        self.read_held -= 1;
        let arrived = matches!(terminal, Terminal::Read { .. });
        self.report.reads_done += u64::from(arrived);
        self.report.reads_failed += u64::from(!arrived);
        match (&record.stage, terminal) {
            // A deadline that passed first decides the outcome; the buffer returns uninspected, and every command ahead is quarantined.
            (Stage::Reading, _) if record.deadline <= now => {
                record.stage = Stage::Ending(ReadStatus::TimedOut);
                self.ready.set(slot, true);
                for ahead in record.ahead.tokens() {
                    quarantine(&mut self.table, &mut self.report, Some(ahead));
                }
            }
            // A lost volume ends the operation at its command's terminal; the buffer returns uninspected.
            (Stage::Reading, _) if self.lost => {
                record.stage = Stage::Ending(ReadStatus::Lost);
                self.ready.set(slot, true);
            }
            (Stage::Reading, Terminal::Read { done, .. }) => {
                // Verification of these bytes follows the burst's remaining terminals; the hints request the device-written first lines ahead of it.
                let start = done.bytes().as_ptr();
                for line in 0..ARRIVAL_HINTS {
                    hint_read(start.wrapping_add(line * LINE));
                }
                record.stage = Stage::Verifying(Verifying {
                    done,
                    cursor: record.command.first,
                    fed: 0,
                    running: self.crc.start(),
                });
                self.ready.set(slot, true);
            }
            // A failed read's buffer returns uninspected, whatever prefix it holds.
            (Stage::Reading, failed) => {
                record.stage = Stage::Ending(match failed {
                    Terminal::Failed {
                        failure: Failure::Short { .. },
                        ..
                    } => {
                        self.report.short += 1;
                        ReadStatus::Short
                    }
                    Terminal::Failed { .. } => ReadStatus::DeviceError,
                    _ => ReadStatus::Quiesced,
                });
                self.ready.set(slot, true);
            }
            (Stage::Ended, _) if !record.outstanding() => self.free_read(slot),
            // A cancelled read's terminal arrived before its `Done` was delivered; the delivery frees the record.
            _ => {}
        }
    }

    /// Submits the next command of the operation in `slot`, which holds a grant on an open volume, for the grant itself or for a tick spending a kept grant.
    /// Buffer-pool exhaustion, a full read share, `TableFull` or `QueueFull` keeps the operation waiting for room; `Closed` or `Stopped` ends it `Quiesced`, `DeviceLost` or `DeviceGone` `Lost`, and any other refusal `DeviceError`.
    pub(super) fn submit_next(&mut self, slot: u32) -> Submission {
        if self.share_full() {
            return Submission::Busy;
        }
        let Ok(buffer) = self.arena.acquire(PoolKind::ReadResponse) else {
            return Submission::Busy;
        };
        let refusal = match self.submit_read(slot, buffer) {
            Ok(()) => return Submission::Submitted,
            Err(Unsubmitted::Locator) => return Submission::Deferred,
            Err(Unsubmitted::Refused(refusal)) => refusal,
        };
        let status = match refusal {
            refusal if busy(refusal) => return Submission::Busy,
            Refusal::Closed | Refusal::Stopped => ReadStatus::Quiesced,
            refusal if lost(refusal) => {
                self.lose();
                ReadStatus::Lost
            }
            _ => ReadStatus::DeviceError,
        };
        if let Some((_, record)) = self.reads.slot_mut(slot) {
            record.stage = Stage::Ending(status);
        }
        Submission::Ended
    }
}

/// Whether `refusal` leaves a read's command waiting for room: reads hold every slot of their share, the table is full, or the device queue is.
pub(super) fn busy(refusal: Refusal) -> bool {
    matches!(
        refusal,
        Refusal::TableFull { .. }
            | Refusal::Device(SubmitRefusal {
                reason: RefusalReason::QueueFull,
                ..
            })
    )
}

/// Whether `refusal` reports the device lost, which loses the volume.
pub(super) fn lost(refusal: Refusal) -> bool {
    matches!(
        refusal,
        Refusal::DeviceLost
            | Refusal::Device(SubmitRefusal {
                reason: RefusalReason::DeviceGone,
                ..
            })
    )
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Unsubmitted {
    /// The read keeps its command for a later submission while its sequence locator is unavailable.
    Locator,
    Refused(Refusal),
}

impl From<Refusal> for Unsubmitted {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

impl Unsubmitted {
    /// The read keeps its command for later submission while its sequence locator is unavailable or [`busy`] reports a capacity refusal.
    pub(super) fn waits(self) -> bool {
        match self {
            Self::Locator => true,
            Self::Refused(refusal) => busy(refusal),
        }
    }
}

impl<'a, P: Platform, D: Disk> Volume<'_, 'a, P, D> {
    /// Submits the read in `slot`'s next command ahead, after its current command and any already ahead, for a grant or for a kept grant the tick spends.
    /// An empty pool or a submit refused as full is `Busy`; any other refusal is `Ended`, keeps the grant for the read's next command, and `DeviceLost` or `DeviceGone` loses the volume.
    pub(super) fn submit_next_ahead(&mut self, slot: u32) -> Submission {
        let Ok(buffer) = self.arena.acquire(PoolKind::ReadResponse) else {
            return Submission::Busy;
        };
        match self.submit_ahead(slot, buffer) {
            Ok(()) => Submission::Submitted,
            Err(Unsubmitted::Locator) => Submission::Deferred,
            Err(Unsubmitted::Refused(refusal)) if busy(refusal) => Submission::Busy,
            Err(Unsubmitted::Refused(refusal)) if lost(refusal) => {
                self.lose();
                Submission::Ended
            }
            Err(Unsubmitted::Refused(_)) => Submission::Ended,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Submission {
    Submitted,
    /// No command is outstanding and the operation waits for room: the pool was empty, reads hold every slot of their share, or the table or the device queue refused the command as full.
    Busy,
    /// The read awaits its sequence locator before submitting a command.
    Deferred,
    /// No command is outstanding and the refusal decided the operation's outcome; for a command ahead, the refusal ended the attempt and the grant stays kept for the read's next command.
    Ended,
}

/// Where verifying a command's arrived bytes stopped.
enum Verdict {
    /// The byte budget ran out before the item in progress was folded.
    Suspended,
    /// The operation ends with the header-check failure this `HeaderMismatch` identifies.
    Header(HeaderMismatch),
    /// Every chunk the command holds verified.
    Verified,
    /// Chunk `index` failed its checksum.
    Mismatch { index: u32 },
}

/// Verifies the arrived bytes of one operation within `budget`: the header first, then each chunk in order, handing off the buffer's chunks once all of them verified or the first failing one ended the operation; an extent that hands off its last chunk with an extent following advances the read to it.
///
/// The current extent's header fields name its layout, checked against the extent's index and units, any lengths an earlier extent verified, the extent's end, the read's extent count and `config` before its crc is folded over the span they derive; the layout is fixed only once that crc and the identity verified.
fn verify<'a>(
    record: &mut ReadRecord<'a>,
    tables: &mut ChunkTables<'_>,
    config: &ValidRecordConfig,
    crc: Crc32c,
    budget: &mut usize,
    op: ReadOp,
    out: &mut Vec<ReadEvent<'a>>,
) {
    let follows = record.extent_follows();
    let extents = record
        .sequence
        .map_or(1, |sequence| u64::from(sequence.count));
    let ReadRecord {
        expected,
        end,
        layout,
        next_chunk,
        command,
        stage,
        ahead,
        ..
    } = &mut *record;
    let Stage::Verifying(verifying) = stage else {
        return;
    };
    let Verifying {
        done,
        cursor,
        fed,
        running,
    } = verifying;
    let bytes = done.bytes();
    // Folds up to `budget` more bytes of `range` of the arrived bytes into the running crc, reading the header crc field as zero when `header`; yields the finished crc once the whole range is folded.
    let mut fold = |range: Range<usize>, header: bool| {
        let take = (range.len() - *fed).min(*budget);
        let piece = range.start + *fed..range.start + *fed + take;
        if header {
            feed_header(running, &bytes[..range.end], piece);
        } else {
            running.update(&bytes[piece]);
        }
        *fed += take;
        *budget -= take;
        if *fed < range.len() {
            return None;
        }
        *fed = 0;
        Some(mem::replace(running, crc.start()).finish())
    };
    let verdict = 'verdict: {
        let verified = match *layout {
            Some(verified) => verified,
            None => {
                let claimed = match config.claimed_layout(
                    bytes,
                    expected.position.index,
                    expected.len_units,
                    expected.lengths,
                ) {
                    Ok(claimed) => claimed,
                    Err(mismatch) => break 'verdict Verdict::Header(mismatch),
                };
                // The read ends at the locator's record end; a header claiming bytes past it names bytes this read never fetched, and lengths that name another count of extents than the object holds name another object.
                let len = u64::from(claimed.metadata_len()) + u64::from(claimed.body_len());
                if claimed.record_len() > *end || extent_count(len) != extents {
                    break 'verdict Verdict::Header(HeaderMismatch::Lengths {
                        metadata_len: claimed.metadata_len(),
                        body_len: claimed.body_len(),
                    });
                }
                // A header past the arrived bytes folds what arrived and fails `Truncated` below.
                let span = 0..claimed.header_bytes().min(bytes.len());
                let Some(computed) = fold(span, true) else {
                    break 'verdict Verdict::Suspended;
                };
                let header = match check_header(crc, bytes, &claimed, expected, computed) {
                    Ok(header) => header,
                    Err(mismatch) => break 'verdict Verdict::Header(mismatch),
                };
                expected.lengths = Some((claimed.metadata_len(), claimed.body_len()));
                debug_assert!(claimed.chunk_count() as usize <= tables.crcs.len());
                for (slot, index) in tables.crcs.iter_mut().zip(0..claimed.chunk_count()) {
                    *slot = header.chunk_crc(index);
                }
                command.end = command.chunks_end(&claimed);
                *next_chunk = command.end;
                // Commands submitted ahead in this extent before the header verified each start at the previous command's end window, so their chunks follow in order; commands ahead in the next extent wait for its own header.
                let mut end = command.end;
                let extent = command.extent;
                for ahead in ahead
                    .iter_mut()
                    .filter(|ahead| ahead.command.extent == extent)
                {
                    ahead.command.first = end;
                    ahead.command.end = ahead.command.chunks_end(&claimed);
                    end = ahead.command.end;
                }
                *next_chunk = end;
                *layout = Some(claimed);
                claimed
            }
        };
        while *cursor < command.end {
            let index = *cursor;
            let range = command.in_buffer(&verified, &verified.chunks(index, index + 1));
            let Some(computed) = fold(range, false) else {
                break 'verdict Verdict::Suspended;
            };
            if computed != tables.crcs[index as usize] {
                break 'verdict Verdict::Mismatch { index };
            }
            *cursor = index + 1;
        }
        Verdict::Verified
    };
    let (upto, failed) = match verdict {
        Verdict::Suspended => return,
        Verdict::Header(mismatch) => {
            *stage = Stage::Ending(ReadStatus::HeaderMismatch(mismatch));
            return;
        }
        Verdict::Mismatch { index } => (index, Some(ReadStatus::ChunkMismatch { index })),
        Verdict::Verified => (command.end, None),
    };
    let Some(verified) = *layout else {
        unreachable!("chunks verify only under a verified header")
    };
    let last = upto == verified.chunk_count();
    let next = match failed {
        Some(status) => Stage::Ending(status),
        None if last && !follows => Stage::Ending(ReadStatus::Complete),
        None => Stage::Next,
    };
    if let Some((range, chunk)) =
        take(stage, next).and_then(|v| v.hand_off(command, &verified, expected, upto, tables))
    {
        out.push(ReadEvent::Chunk {
            op,
            info: VerifiedReadInfo::new(expected.identity, &verified),
            range,
            chunk,
        });
    }
    // An extent that handed off its last chunk passes the read to the next.
    if failed.is_none() && last && follows {
        record.advance(&verified);
    }
}

/// Cancels `token`'s command in `table`, which quarantines its buffer until its terminal, and counts the quarantine in `report`.
/// The table refuses the cancel once its admission is closed or stopped and for a command whose terminal is already in the scratch vector; that command stays attached, and its terminal ends it the same way.
pub(super) fn quarantine<D: Disk>(
    table: &mut CommandTable<'_, D>,
    report: &mut VolumeReport,
    token: Option<CommandToken>,
) {
    if let Some(token) = token
        && table.cancel(token).is_ok()
    {
        report.quarantines += 1;
    }
}

/// Replaces a verifying stage with `next` and returns what it was verifying.
fn take<'a>(stage: &mut Stage<'a>, next: Stage<'a>) -> Option<Verifying<'a>> {
    match mem::replace(stage, next) {
        Stage::Verifying(verifying) => Some(verifying),
        _ => None,
    }
}
