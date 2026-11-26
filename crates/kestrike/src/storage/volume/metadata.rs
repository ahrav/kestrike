//! The volume's metadata command owner and the attach bootstrap it drives: pass the attach gate (the `fence` module), which admits the driver's medium commands, then probe both root slots, then either refuse, wait for an explicit format, or write a RESET root to each slot in the slot rule's order, and only then admit payload writes, or, under a warm source the attach carried, read the named slot and its suffix blocks through the metadata cells, install the load and commit readiness with no probe and no prefix write (the `warm` module); once open, the owner submits the suffix block write or checkpoint-unit command the `checkpoint` module stages in the journal cell, a sealed suffix block first.
//!
//! Invariants owned by this module:
//!
//! - ONE-WRITER: the owner thread submits every metadata command in the tick's metadata step, once the tick applied every terminal it took; applying a terminal records its outcome and submits nothing.
//! - The owner holds the root cell, the journal cell and the read cells starting at [`READS`], counted by [`cells`]. Each cell holds at most one staged or outstanding command, so each block has at most one outstanding command. Attach reserves table slots for up to `metadata_commands` outstanding metadata commands alongside reads and fills; a fill write holds a reserved slot only while no cell claims it, and a staged command waits for such writes to end (WRITE-ROOM, the `write` module). Each metadata step submits at most the tick's `submit_burst` commands, root and journal cells first. The bootstrap probes and RESETs through the root cell; a warm bootstrap reads through every free cell, at most `metadata_commands` outstanding.
//! - EVIDENCE-ORDER: a RESET's second write is staged only after the first write's [`Persisted`], and the outcome becomes `Open` only after the second's.
//! - A `Failed` write terminal stages the same buffer, with its bytes unchanged, for the next metadata step, at most `metadata_retries` times; a table or device queue refusing the submit as full leaves the command staged and spends no retry. A write whose `Failed` terminals exceed `metadata_retries`, or that the table refuses for good while the device stays live, records `MetadataFailed`. A checkpoint-unit command runs once: its failed terminal, a refusal for good, or the volume's end, stop, close, loss or withdrawal yields `UnitDone::Failed`; a failed terminal and a refusal for good leave the metadata open, and the capture retires its checkpoint. A suffix block write's refusal for good or any terminal other than `Written` parks a failed result and leaves the metadata open: the log keeps the block's bytes, the next delta stage stages them again in a new buffer, and more than `metadata_retries` failures of one block record `MetadataFailed`.
//! - The probe reads slot A and then slot B and writes nothing before both reads ended; a read that ends in a failure or a refusal for good while the device stays live, or that a stop ends within a tick, refuses `SlotUnreadable`; a submit refused `DeviceLost` or `DeviceGone` loses the volume and keeps the outcome.
//! - Every bootstrap that ends without opening closes the storage's admission through [`Storage::close`](super::super::Storage::close), so fills refuse `Closed`: a refusal names its cause in the outcome, and a RESET write that a stop ends, a volume close or the volume's loss keeps the outcome it had, `Bootstrapping` or `Unformatted`, because an interrupted write's persistence remains uncertain.

use std::sync::atomic::Ordering;

#[cfg(test)]
use super::super::cache::coverage::Coverage;
use super::super::device::{Buffer, CommandToken, DeviceRange, Disk, PoolKind, Rejected, Terminal};
use super::super::os::Platform;
use super::super::readiness::{Event, ReadinessError};
use super::super::recovery::{
    Area, Decision, FormatId, IoClass, MetadataOutcome, Persisted, Probed, Recorded, Root, Slot,
    decide, decode, encode,
};
use super::attach::{Owner, Volume, map_token};
use super::fence::{Fenced, GateRefusal, GateStep};
use super::tick::{busy, lost};
use crate::entropy::{EntropyError, nonce_from, os_entropy};

/// The root cell: the bootstrap's probes and RESET writes.
pub(super) const ROOT: usize = 0;
/// The journal cell: one suffix block write or checkpoint-unit command at a time on an open volume.
pub(super) const JOURNAL: usize = 1;
/// The first read cell; a warm bootstrap's reads take any free cell.
pub(super) const READS: usize = 2;

/// The root and journal cells and the read cells: one read cell per metadata command past the first, and at least one.
pub(super) fn cells(metadata_commands: u32) -> usize {
    READS + (metadata_commands as usize).saturating_sub(1).max(1)
}

/// The metadata owner's state; see the module documentation.
pub(super) struct Metadata<'a> {
    pub(super) area: Area,
    pub(super) retries: u32,
    pub(super) commands: Box<[Option<Command<'a>>]>,
    /// The count of cells that hold a staged command, one whose buffer waits for its submit. [`stage`](Self::stage)
    /// and each site that stages a command in place, takes or returns a command's buffer, or drops a staged command
    /// adjust it, and `metadata_ready` reads from it whether a command waits; a debug build checks it against the cells.
    pub(super) staged: u32,
    pub(super) phase: Phase,
    pub(super) outcome: MetadataOutcome,
    /// The warm source the attach carried, which the first metadata step after the gate begins reading.
    pub(super) warm_source: Option<Box<(super::warm::WarmSource, super::warm::Planned)>>,
    /// A warm bootstrap's read, from its begin until the load finished.
    pub(super) reading: Option<Box<super::warm::Read>>,
    /// At read start, the bootstrap captures the warm source's layout to locate the named slot and suffix blocks.
    pub(super) warm_layout: Option<crate::failover::records::Layout>,
    /// A warm bootstrap's state from its stage on.
    pub(super) warm: Option<Box<super::warm::Warm>>,
    /// The finished load and coverage a test assumes for a warm bootstrap, staged at the gate's pass.
    #[cfg(test)]
    pub(super) assumed: Option<Box<Assumed>>,
    /// `helpers` runs the warm bootstrap's slot, conversion and free jobs, and a serving tenure's capture encodes; dropping the helper pool joins its threads. `attempts` counts the helper pools started; each pool takes its count as its tag.
    pub(super) helpers: Option<super::helpers::Helpers>,
    /// The cancelled pool the first encode's pool replaced, its threads finishing the jobs queued before the cancel; the volume's drop joins them.
    pub(super) retired: Option<super::helpers::Helpers>,
    /// The layout a warm load read its source under, from the load's start on.
    pub(super) loaded: Option<crate::failover::records::Layout>,
    pub(super) attempts: u64,
    /// The gate that admits medium commands, held from the gate on.
    pub(super) fenced: Option<Fenced>,
    /// The last checkpoint-unit command's result, until the capture takes it.
    pub(super) unit: Option<super::checkpoint::UnitDone>,
    /// The bytes of the last checkpoint-unit read-back, held from attach so a read-back's terminal allocates nothing.
    pub(super) unit_bytes: Box<[u8; super::super::recovery::checkpoint::UNIT_LEN]>,
    /// `submit` raises this flag before the driver call of a checkpoint-unit command and lowers it after, so an
    /// unwound call leaves it raised.
    pub(super) unit_unwound: bool,
    /// The last suffix block write's LSN and whether its `Written` terminal persisted it, until the next delta stage
    /// gives it to the log under the capture mutex.
    pub(super) delta: Option<(u64, bool)>,
    /// The earliest time the delta writer tries a sealed block it could not stage for want of a maintenance buffer
    /// or of the serving table's admission, and the failed writes of the block at the head of the queue.
    pub(super) delta_retry: (u64, u32),
}

/// A metadata command: staged while it holds its buffer, outstanding once its submit was accepted.
pub(super) struct Command<'a> {
    pub(super) target: Target,
    pub(super) recorded: Recorded,
    pub(super) buffer: Option<Buffer<'a>>,
    /// `Failed` terminals this command's writes took.
    failures: u32,
}

impl<'a> Command<'a> {
    /// A staged command of `target` over `range`, the device range of prefix unit `unit`, reading or writing `buffer`.
    pub(super) fn unit(target: Target, unit: u64, range: DeviceRange, buffer: Buffer<'a>) -> Self {
        Self {
            target,
            recorded: Recorded {
                block: unit,
                generation: 0,
                range,
            },
            buffer: Some(buffer),
            failures: 0,
        }
    }

    /// A staged command of `target` over metadata block `block` of `area`, reading or writing `buffer`, recorded under `generation`.
    pub(super) fn staged(
        area: &Area,
        target: Target,
        (block, generation): (u64, u64),
        buffer: Buffer<'a>,
    ) -> Self {
        let Some(range) = area.range(block) else {
            unreachable!("attach admitted only an area whose every block qualifies")
        };
        let recorded = Recorded {
            block,
            generation,
            range,
        };
        Self {
            target,
            recorded,
            buffer: Some(buffer),
            failures: 0,
        }
    }
}

/// What a metadata command reads or writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Target {
    /// The probe read of a root slot.
    Probe(Slot),
    /// A RESET root write.
    Root,
    /// A warm bootstrap's read of named-slot units or suffix blocks.
    Slot,
    /// The write of the tenure's suffix block of LSN `lsn`.
    Delta(u64),
    /// The write of unit `unit` of checkpoint slot `slot`.
    UnitWrite { slot: u32, unit: u32 },
    /// The read-back of unit `unit` of checkpoint slot `slot`.
    UnitRead { slot: u32, unit: u32 },
}

/// The result a checkpoint-unit command of `target` ends with when it leaves its cell without a device terminal.
pub(super) fn unit_failed(target: Target) -> Option<super::checkpoint::UnitDone> {
    match target {
        Target::UnitWrite { slot, unit } | Target::UnitRead { slot, unit } => {
            Some(super::checkpoint::UnitDone::Failed { slot, unit })
        }
        _ => None,
    }
}

/// The bootstrap's step.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Phase {
    /// Metadata command submission requires the gate to pass.
    Gate {
        step: GateStep,
        pending: Option<CommandToken>,
    },
    /// Reading slot A.
    ProbeA,
    /// Reading slot B, with slot A's probe.
    ProbeB(Probed),
    /// A warm bootstrap reads a named slot, with its state in `Metadata::reading`, then installs the load and commits
    /// readiness, with its state in `Metadata::warm`.
    Warm,
    /// Both slots decode invalid; [`Volume::format`] moves to `Reset`.
    Unformatted,
    /// Writing `slot`'s RESET root of `format` under the tenure's session `session`; `first` is the slot the RESET wrote first.
    Reset {
        slot: Slot,
        first: Slot,
        format: FormatId,
        session: u64,
    },
    /// Both RESET roots persisted, or the warm bootstrap committed with no root write.
    Open,
    /// The bootstrap ended without opening; the outcome names why.
    Ended,
}

impl<'a> Metadata<'a> {
    pub(super) fn new(area: Area, retries: u32, cells: usize) -> Self {
        Self {
            area,
            retries,
            commands: (0..cells).map(|_| None).collect(),
            staged: 0,
            phase: Phase::Gate {
                step: GateStep::Register,
                pending: None,
            },
            outcome: MetadataOutcome::Bootstrapping,
            warm_source: None,
            reading: None,
            warm_layout: None,
            warm: None,
            #[cfg(test)]
            assumed: None,
            helpers: None,
            retired: None,
            loaded: None,
            attempts: 0,
            fenced: None,
            unit: None,
            unit_bytes: Box::new([0; super::super::recovery::checkpoint::UNIT_LEN]),
            unit_unwound: false,
            delta: None,
            delta_retry: (0, 0),
        }
    }

    /// Puts `command`, staged with its buffer, into the empty cell `cell` and counts it in `staged`.
    pub(super) fn stage(&mut self, cell: usize, command: Command<'a>) {
        debug_assert!(self.commands[cell].is_none() && command.buffer.is_some());
        self.commands[cell] = Some(command);
        self.staged += 1;
    }

    pub(super) fn is_open(&self) -> bool {
        matches!(self.phase, Phase::Open)
    }

    /// Whether the bootstrap may still open: it has neither opened nor ended.
    pub(super) fn running(&self) -> bool {
        matches!(
            self.phase,
            Phase::Gate { .. }
                | Phase::ProbeA
                | Phase::ProbeB(_)
                | Phase::Warm
                | Phase::Unformatted
                | Phase::Reset { .. }
        )
    }
}

impl<'s, 'a, P: Platform, D: Disk> Volume<'s, 'a, P, D> {
    /// What the volume's metadata did: its bootstrap's progress or refusal, and `MetadataFailed` once a metadata write failed for good, or a warm bootstrap failed as [`MetadataOutcome::MetadataFailed`] states.
    pub fn metadata_outcome(&self) -> MetadataOutcome {
        self.metadata.outcome
    }

    /// Formats the volume: draws a fresh format ID from the operating system's entropy and RESETs both root slots, slot A first, under the tenure's session.
    ///
    /// `format` accepts a request only in the bootstrap's `Unformatted` phase, after both root slots were read and both decoded invalid. The RESET writes follow in later ticks.
    ///
    /// # Errors
    ///
    /// Once the attempt is withheld, `format` returns the current outcome and leaves the slots as they are.
    /// Outside the `Unformatted` phase, `format` preserves the slots and returns the current outcome. If the entropy draw fails or returns all zeros, `format` returns `EntropyUnavailable`, sets the outcome to `EntropyUnavailable`, and closes admission.
    pub fn format(&mut self) -> Result<(), MetadataOutcome> {
        self.format_from(os_entropy)
    }

    /// [`format`](Self::format), drawing the format ID from `fill`.
    pub(crate) fn format_from(
        &mut self,
        fill: impl FnOnce(&mut [u8; 16]) -> Result<(), EntropyError>,
    ) -> Result<(), MetadataOutcome> {
        if !matches!(self.metadata.phase, Phase::Unformatted) || self.readiness().stops_metadata() {
            return Err(self.metadata.outcome);
        }
        let Ok(format) = nonce_from(fill) else {
            self.end(MetadataOutcome::EntropyUnavailable);
            return Err(self.metadata.outcome);
        };
        let format = FormatId(format);
        self.metadata.outcome = MetadataOutcome::Bootstrapping;
        self.metadata.phase = Phase::Reset {
            slot: Slot::A,
            first: Slot::A,
            format,
            session: self.authority.session().get(),
        };
        Ok(())
    }

    /// Whether the metadata step has a command to stage or submit, a helper terminal to adopt, an open volume's halt to publish, a withdrawn attempt's helpers to cancel, or a suffix block write's parked result or a suffix block due to seal or stage.
    pub(super) fn metadata_ready(&self) -> bool {
        if !self.closed && !self.lost && self.gate_authority_lost() {
            return true;
        }
        if self.readiness().stops_metadata() {
            // An open volume stays ready for the one step that marks its shared words `halted`, and a loading one for the step that cancels its helpers.
            return (self.metadata.is_open() && !self.journal_words.halted.load(Ordering::Relaxed))
                || (self.metadata.helpers.as_ref())
                    .is_some_and(super::helpers::Helpers::accepting);
        }
        let metadata = &self.metadata;
        debug_assert_eq!(
            metadata.staged as usize,
            (metadata.commands.iter().flatten())
                .filter(|command| command.buffer.is_some())
                .count(),
            "the staged count follows the cells"
        );
        metadata.staged > 0
            || match &metadata.phase {
                Phase::Open => self.delta_wake(),
                Phase::Warm => {
                    metadata.reading.is_some()
                        || (metadata.warm.as_ref()).is_some_and(|warm| warm.pending())
                        || (metadata.helpers.as_ref()).is_some_and(super::helpers::Helpers::busy)
                }
                Phase::ProbeA | Phase::ProbeB(_) | Phase::Reset { .. } => {
                    metadata.commands[ROOT].is_none()
                }
                Phase::Gate { pending, .. } => pending.is_none() && self.gate_admitted(),
                Phase::Unformatted | Phase::Ended => false,
            }
    }

    /// The tick's metadata step: before the gate, submits the gate's next reservation command, or passes a restart's fencing-boundary value, and nothing else; from the gate on, stages the bootstrap's next command, with the journal cell's suffix block write staged by `stage_delta` ahead of the checkpoint-unit command `stage_unit` stages, then submits staged cells in cell order, root and journal first, while fewer than `metadata_commands` are outstanding and at most `quota` a call; returns the commands it submitted.
    /// A submit refused `DeviceLost` or `DeviceGone` loses the volume.
    pub(super) fn metadata_step(&mut self, quota: u32) -> u32 {
        if self.closed || self.lost || !self.scratch.is_empty() {
            return 0;
        }
        if self.gate_authority_lost() {
            self.end(MetadataOutcome::Unfenced(GateRefusal::AuthorityLost));
            return 0;
        }
        if self.readiness().stops_metadata() {
            if self.metadata.is_open() {
                self.journal_words.halted.store(true, Ordering::Relaxed);
                self.fail_unmapped_unit();
            }
            // The attempt adopts nothing more, so its helpers end once the jobs already queued ran; the pool stays with the volume, whose drop joins the threads. A warm attempt's installed entries stay anchored (the `warm` module's ENDED-HOLDS).
            self.cancel_helpers();
            return 0;
        }
        if let Phase::Gate { .. } = self.metadata.phase {
            let gated = if quota == 0 || !self.gate_admitted() {
                0
            } else {
                self.gate_step()
            };
            if !matches!(self.metadata.phase, Phase::ProbeA) {
                return gated;
            }
        }
        if !self.metadata_staging_admitted() {
            return 0;
        }
        if let (Phase::ProbeA, Some(source)) =
            (&self.metadata.phase, self.metadata.warm_source.take())
        {
            self.begin_warm(*source);
        }
        #[cfg(test)]
        if let (Phase::ProbeA, Some(assumed)) = (&self.metadata.phase, self.metadata.assumed.take())
        {
            let Assumed { load, coverage } = *assumed;
            self.stage_warm(load, coverage, Vec::new());
        }
        if self.metadata.running() {
            if let Phase::Warm = self.metadata.phase {
                self.warm_step();
            } else if self.metadata.commands[ROOT].is_none()
                && !matches!(self.metadata.phase, Phase::Unformatted)
            {
                self.stage();
            }
        } else if let Phase::Open = self.metadata.phase {
            self.stage_delta();
        }
        let mut submitted = 0;
        for cell in 0..self.metadata.commands.len() {
            if submitted >= quota {
                break;
            }
            let staged = self.metadata.commands[cell]
                .as_ref()
                .is_some_and(|command| command.buffer.is_some());
            if staged {
                submitted += self.submit(cell);
            }
        }
        submitted
    }

    /// Submits `cell`'s staged command once the gate passed, while fewer than `metadata_commands` are outstanding and the fill writes hold no slot it needs. A fill write holding its slot, a full table or a full device queue keeps it staged; any other refusal of a checkpoint-unit command yields `UnitDone::Failed`, of a suffix block write parks its failed result for the next delta stage, and of any other command ends the metadata, a probe as `SlotUnreadable` and a write as `MetadataFailed`.
    fn submit(&mut self, cell: usize) -> u32 {
        use crate::failover::serving::MetadataKind;
        let Some(target) = self.metadata.commands[cell].as_ref().map(|c| c.target) else {
            return 0;
        };
        let kind = match target {
            Target::Delta(_) | Target::UnitWrite { .. } | Target::UnitRead { .. } => {
                MetadataKind::CheckpointUnit
            }
            Target::Probe(_) | Target::Root | Target::Slot => MetadataKind::CheckpointRoot,
        };
        if self.metadata.fenced.is_none() || !self.metadata_authorized(kind) {
            return 0;
        }
        let metadata = &mut self.metadata;
        let outstanding = metadata
            .commands
            .iter()
            .flatten()
            .filter(|command| command.buffer.is_none())
            .count();
        let Some(command) = metadata.commands[cell].as_mut() else {
            return 0;
        };
        if outstanding >= self.storage.metadata_commands as usize {
            return 0;
        }
        // WRITE-ROOM: a write that took this command's slot while no cell claimed it holds the slot until its terminal.
        if self.write_held + outstanding as u32
            >= self.write_commands + self.storage.metadata_commands
        {
            return 0;
        }
        // SHARE-BEFORE-ISSUE: a slot or checkpoint-unit command takes its bytes from the recovery I/O share as it is
        // submitted; one the share cannot hold stays staged with its buffer, and one the device turns away returns its
        // charge below.
        let charged = matches!(
            target,
            Target::Slot | Target::UnitWrite { .. } | Target::UnitRead { .. }
        )
        .then(|| u64::from(command.recorded.range.byte_len()));
        if let Some(bytes) = charged
            && !(self.recovery_io).admit(self.recovery.now(), bytes, IoClass::Bulk)
        {
            return 0;
        }
        let Some(buffer) = command.buffer.take() else {
            return 0;
        };
        metadata.staged -= 1;
        let range = command.recorded.range;
        #[cfg(test)]
        let block = command.recorded.block;
        metadata.unit_unwound =
            matches!(target, Target::UnitWrite { .. } | Target::UnitRead { .. });
        let reads = matches!(
            target,
            Target::Probe(_) | Target::Slot | Target::UnitRead { .. }
        );
        let result = if reads {
            self.table.submit_read(buffer, range)
        } else {
            self.table.submit_write(buffer, range)
        };
        metadata.unit_unwound = false;
        match result {
            Ok(token) => {
                map_token(&mut self.tokens, token, Owner::Metadata(cell as u32), 0);
                #[cfg(test)]
                self.record_bound(token, super::attach::Bound::Metadata { block });
                self.report.metadata_submitted += 1;
                1
            }
            Err(Rejected { buffer, refusal }) => {
                self.report.metadata_refused += 1;
                if let Some(bytes) = charged {
                    self.recovery_io.refund(bytes);
                }
                if busy(refusal) {
                    command.buffer = Some(buffer);
                    metadata.staged += 1;
                    return 0;
                }
                metadata.commands[cell] = None;
                drop(buffer);
                let failed = unit_failed(target);
                let unit_command = failed.is_some();
                if unit_command {
                    metadata.unit = failed;
                }
                if lost(refusal) {
                    self.lost = true;
                    self.halt_metadata();
                    return 0;
                }
                if unit_command {
                    return 0;
                }
                if let Target::Delta(lsn) = target {
                    // The block stays queued with its payload; the next stage takes it again.
                    metadata.delta = Some((lsn, false));
                    return 0;
                }
                if target == Target::Slot {
                    // A read the device refused for good counts as unread; the reader decides the load.
                    self.slot_read(range, None);
                    return 0;
                }
                self.end(match target {
                    Target::Probe(slot) => MetadataOutcome::SlotUnreadable { slot },
                    _ => MetadataOutcome::MetadataFailed,
                });
                0
            }
        }
    }

    /// Stages the bootstrap phase's command into a maintenance buffer: the read of the slot being probed, or the RESET root of the slot being written; staging requires an available maintenance buffer.
    fn stage(&mut self) {
        let metadata = &mut self.metadata;
        let (slot, written) = match &metadata.phase {
            Phase::ProbeA => (Slot::A, None),
            Phase::ProbeB(_) => (Slot::B, None),
            &Phase::Reset {
                slot,
                format,
                session,
                ..
            } => (slot, Some((format, session))),
            _ => unreachable!("only a probe or a RESET stages a bootstrap command"),
        };
        let Ok(mut buffer) = self.arena.acquire(PoolKind::Maintenance) else {
            return;
        };
        let layout = metadata.area.layout();
        let target = if let Some((format, session)) = written {
            let block = &mut buffer.bytes_mut()[..layout.unit as usize];
            encode(
                self.crc,
                layout,
                format,
                &Root::reset(
                    session,
                    self.storage.clock.encode(),
                    self.storage.feed.encode(),
                ),
                slot,
                block,
            );
            Target::Root
        } else {
            Target::Probe(slot)
        };
        let generation = written.map_or(0, |(_, session)| session);
        let command = Command::staged(&metadata.area, target, (slot.block(), generation), buffer);
        metadata.stage(ROOT, command);
    }

    /// Applies the terminal of `cell`'s command: a read's bytes become its slot's probe, a persisted root write advances the RESET, a failed root write is staged again within its retries, a checkpoint-unit command ends once as `Written`, `Read` or `Failed`, a suffix block write parks whether its terminal was `Written` for the next delta stage, a failed or stopped read ends as unreadable, a stopped write during the bootstrap ends it with no evidence, a stopped write once open clears its cell, and a terminal that arrives after its command was dropped only counts.
    pub(super) fn apply_metadata(&mut self, cell: u32, terminal: Terminal<'a>) {
        if matches!(terminal, Terminal::Read { .. } | Terminal::Written { .. }) {
            self.report.metadata_done += 1;
        } else {
            self.report.metadata_failed += 1;
        }
        let metadata = &mut self.metadata;
        let cell = cell as usize;
        let Some(command) = metadata.commands[cell].as_mut() else {
            return;
        };
        let (target, recorded) = (command.target, command.recorded);
        match (terminal, target) {
            (Terminal::Written { .. }, Target::UnitWrite { slot, unit }) => {
                metadata.commands[cell] = None;
                metadata.unit = Some(super::checkpoint::UnitDone::Written { slot, unit });
            }
            (Terminal::Read { done, .. }, Target::UnitRead { slot, unit }) => {
                metadata
                    .unit_bytes
                    .copy_from_slice(&done.bytes()[..super::super::recovery::checkpoint::UNIT_LEN]);
                metadata.commands[cell] = None;
                metadata.unit = Some(super::checkpoint::UnitDone::Read { slot, unit });
            }
            (ended, Target::Delta(lsn)) => {
                // Under the persistence profile a `Written` terminal of the qualified range is the block's
                // persistence; every other ending leaves the block queued for another attempt.
                let written = matches!(ended, Terminal::Written { .. });
                metadata.commands[cell] = None;
                drop(ended);
                metadata.delta = Some((lsn, written));
            }
            (ended, Target::UnitWrite { slot, unit } | Target::UnitRead { slot, unit }) => {
                metadata.commands[cell] = None;
                drop(ended);
                metadata.unit = Some(super::checkpoint::UnitDone::Failed { slot, unit });
            }
            (Terminal::Read { done, .. }, Target::Probe(slot)) => {
                let layout = metadata.area.layout();
                let block = &done.bytes()[..layout.unit as usize];
                let probed = Some(decode(self.crc, layout, block, slot));
                metadata.commands[cell] = None;
                self.probed(slot, probed);
            }
            (Terminal::Read { done, .. }, Target::Slot) => {
                metadata.commands[cell] = None;
                let len = recorded.range.byte_len() as usize;
                self.slot_read(recorded.range, Some(&done.bytes()[..len]));
            }
            (ended, Target::Slot) => {
                metadata.commands[cell] = None;
                drop(ended);
                self.slot_read(recorded.range, None);
            }
            (terminal @ Terminal::Written { .. }, _) => {
                let persisted = Persisted::of(&terminal, &recorded, &metadata.area);
                metadata.commands[cell] = None;
                drop(terminal);
                if let Some(persisted) = persisted {
                    self.persisted(persisted);
                }
            }
            (Terminal::Failed { buffer, .. }, Target::Root) => {
                command.failures += 1;
                if command.failures <= metadata.retries
                    && metadata.outcome != MetadataOutcome::MetadataFailed
                {
                    command.buffer = Some(buffer);
                    metadata.staged += 1;
                } else {
                    metadata.commands[cell] = None;
                    drop(buffer);
                    self.end(MetadataOutcome::MetadataFailed);
                }
            }
            (ended, _) => {
                metadata.commands[cell] = None;
                drop(ended);
                if let Target::Probe(slot) = target {
                    self.end(MetadataOutcome::SlotUnreadable { slot });
                } else if self.metadata.running() {
                    self.stop();
                }
            }
        }
    }

    /// Records `slot`'s probe; slot A's moves the probe to slot B, and slot B's decides the bootstrap.
    fn probed(&mut self, slot: Slot, probed: Probed) {
        match (&self.metadata.phase, slot) {
            (Phase::ProbeA, Slot::A) => {
                self.metadata.phase = Phase::ProbeB(probed);
                return;
            }
            (Phase::ProbeB(_), Slot::B) => {}
            _ => return,
        }
        let Phase::ProbeB(a) = std::mem::replace(&mut self.metadata.phase, Phase::Ended) else {
            unreachable!("slot B's probe follows slot A's")
        };
        match decide(&a, &probed, self.authority.session()) {
            Decision::Reset {
                format,
                session,
                first,
            } => {
                #[cfg(test)]
                let session = match PLANT.with(std::cell::Cell::get) {
                    Some(Plant::GenerationReuse) => {
                        let highest = |probe: &Probed| {
                            probe
                                .as_ref()
                                .and_then(|p| p.as_ref().ok())
                                .map(|(_, root)| root.generation)
                        };
                        highest(&a).max(highest(&probed)).unwrap_or(session)
                    }
                    _ => session,
                };
                // The RESET writes first to the slot without the highest valid root, or to A when both hold the same root.
                self.metadata.phase = Phase::Reset {
                    slot: first,
                    first,
                    format,
                    session,
                };
            }
            Decision::Unformatted => {
                self.metadata.phase = Phase::Unformatted;
                self.metadata.outcome = MetadataOutcome::Unformatted;
            }
            Decision::Refused(outcome) => self.end(outcome),
        }
    }

    /// `persisted` handles completion of a RESET root write: the first stages the second, and the second opens payload writes under the tenure's session. Outside the RESET a persisted write changes nothing.
    fn persisted(&mut self, persisted: Persisted) {
        let Phase::Reset {
            slot,
            first,
            session,
            ..
        } = &mut self.metadata.phase
        else {
            return;
        };
        let recorded = persisted.recorded();
        debug_assert_eq!(
            (recorded.block, recorded.generation),
            (slot.block(), *session)
        );
        if slot != first {
            let session = *session;
            self.open(session);
            self.storage.pool().replaced();
            let _ = self.storage.readiness.apply(Event::LoadComplete);
            return;
        }
        *slot = first.other();
    }

    /// Whether the journal cell holds no command; true when the volume is not open. The cell holds only suffix block
    /// writes and checkpoint-unit commands.
    #[cfg(test)]
    pub(crate) fn journal_settled(&self) -> bool {
        !self.metadata.is_open() || self.metadata.commands[JOURNAL].is_none()
    }

    /// Stops a running bootstrap, or marks an open volume's shared words `halted` and fails its staged or unwound checkpoint-unit command.
    #[cold]
    pub(super) fn halt_metadata(&mut self) {
        // A lost volume can serve nothing more, so its loss withdraws recovered service and fill admission.
        if self.lost {
            let _ = self.storage.readiness.apply(Event::Withdraw);
        }
        if self.metadata.running() {
            self.stop();
        } else if self.metadata.is_open() {
            self.journal_words.halted.store(true, Ordering::Relaxed);
            self.fail_unmapped_unit();
        }
    }

    /// `open` opens payload writes under `session` once both bootstrap roots of it persisted, or once the warm bootstrap committed allocation readiness with no root write.
    pub(super) fn open(&mut self, session: u64) {
        self.session = session;
        self.metadata.phase = Phase::Open;
        self.metadata.outcome = MetadataOutcome::Open;
    }

    /// Ends a bootstrap the volume's loss or a stop cut short and closes the storage's admission; the outcome stays as it was, `Bootstrapping` or `Unformatted`, because a lost or stopped command's persistence remains uncertain.
    pub(super) fn stop(&mut self) {
        self.cancel_helpers();
        // The stop drops the commands the device still holds; the terminals that drain afterward belong to the teardown, and a later stop finds the cells empty.
        for cell in &mut self.metadata.commands {
            if let Some(failed) = cell.take().and_then(|command| unit_failed(command.target)) {
                self.metadata.unit = Some(failed);
            }
        }
        self.metadata.staged = 0;
        self.metadata.phase = Phase::Ended;
        self.storage.close();
    }

    /// `cancel_helpers` cancels an accepting pool once; a pool already cancelled changes nothing.
    pub(super) fn cancel_helpers(&mut self) {
        if let Some(helpers) = self.metadata.helpers.as_mut() {
            helpers.cancel();
        }
    }

    /// An open volume stays open for reads after `end` closes the storage's admission; a staged command is dropped, and an outstanding command still takes its terminal.
    pub(super) fn end(&mut self, outcome: MetadataOutcome) {
        let event = match outcome {
            MetadataOutcome::Unfenced(_) => Event::Withdraw,
            MetadataOutcome::Bootstrapping
            | MetadataOutcome::Unformatted
            | MetadataOutcome::Open
            | MetadataOutcome::SlotUnreadable { .. }
            | MetadataOutcome::Unsupported { .. }
            | MetadataOutcome::FormatMismatch
            | MetadataOutcome::TiedRoots
            | MetadataOutcome::StaleSession
            | MetadataOutcome::EntropyUnavailable
            | MetadataOutcome::MetadataFailed
            | MetadataOutcome::Collided
            | MetadataOutcome::Unloadable(_) => Event::Withhold,
        };
        let applied = self.storage.readiness.apply(event);
        debug_assert_ne!(applied, Err(ReadinessError::Invariant), "{outcome:?}");
        if matches!(
            outcome,
            MetadataOutcome::Unloadable(_)
                | MetadataOutcome::Collided
                | MetadataOutcome::MetadataFailed
        ) {
            self.recovery.warm_refused();
        }
        self.cancel_helpers();
        let metadata = &mut self.metadata;
        if !metadata.is_open() {
            metadata.phase = Phase::Ended;
        }
        metadata.outcome = outcome;
        for cell in &mut metadata.commands {
            let staged = cell
                .as_ref()
                .is_some_and(|command| command.buffer.is_some());
            if !staged {
                continue;
            }
            let dropped = cell.take();
            if let Some(failed) = dropped.and_then(|command| unit_failed(command.target)) {
                metadata.unit = Some(failed);
            }
        }
        metadata.staged = 0;
        self.storage.close();
    }
}

/// What a test assumes for a warm bootstrap: the finished load and the tenure's fenced coverage.
#[cfg(test)]
#[derive(Debug)]
pub(super) struct Assumed {
    pub(super) load: super::super::recovery::checkpoint::SlotLoad,
    pub(super) coverage: Coverage,
}

/// A planted defect for a negative control.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plant {
    /// The RESET writes the highest valid root generation in place of the tenure's session.
    GenerationReuse,
}

#[cfg(test)]
thread_local! {
    pub(crate) static PLANT: std::cell::Cell<Option<Plant>> = const { std::cell::Cell::new(None) };
}
