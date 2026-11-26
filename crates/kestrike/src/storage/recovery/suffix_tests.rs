//! The suffix appender: a refusal before acknowledgment changes nothing, the cut lies between two records, a block
//! is encoded from its retained payload to the same bytes on every attempt, the tenure's capacity follows the
//! settled floor, and a chain of tenures replays each suffix in ancestry order under seeded schedules of fills,
//! replacements, evictions, publishes, lost writes, crashes, stale landings and block damage.

use std::collections::{HashMap, HashSet};

use super::capture::CaptureEntry;
use super::delta::{Cause, Identity, Record, UNIT_LEN, decode, identity_of, room};
use super::delta_replay::{PLANT, Plant, SuffixLoad, replay};
use super::delta_tests::{SESSION, block, remove, shard, wide};
use super::durable::{LSN_LIMIT, position, reusable};
use super::suffix::*;
use crate::failover::records::{Layout, Suffix};
use crate::storage::extent::ExtentLocator;
use crate::storage::record::Crc32c;
use crate::storage::seeded::SplitMix64;

const LIMITS: SuffixLimits = SuffixLimits {
    flush_ns: 100_000_000,
    queue_blocks: 4,
    oldest_ns: 1_000_000_000,
    uncertified: 1 << 40,
};

/// The next block `log` hands its writer, encoded as a write attempt carries it. The buffer starts out filled with
/// a nonzero byte, so the unit shows that the encode writes every byte.
pub(crate) fn take(log: &mut SuffixLog) -> Option<(u64, Box<[u8; UNIT_LEN]>)> {
    let mut unit = Box::new([0xa5; UNIT_LEN]);
    let lsn = log.take(&mut unit)?;
    Some((lsn, unit))
}

/// A layout whose delta region holds `blocks` blocks.
fn layout(blocks: u64) -> Layout {
    Layout {
        units: 1 + blocks,
        slots: 0,
        slot_units: 0,
        entries: 0,
    }
}

fn opened(
    (limits, blocks): (SuffixLimits, u64),
    (start, end): (u64, u64),
    floor: u64,
) -> SuffixLog {
    let mut log = SuffixLog::default();
    let suffix = Suffix {
        session: SESSION,
        start,
        certified: start,
        end,
    };
    let opened = log.open(
        (Crc32c::detect(), shard()),
        (limits, &layout(blocks)),
        suffix,
        floor,
    );
    let valid = blocks > 0
        && limits.queue_blocks > 0
        && limits.uncertified > 0
        && limits.oldest_ns > limits.flush_ns;
    assert_eq!(opened, valid, "open reports whether admission opened");
    log
}

fn open(start: u64, reserved: u64, blocks: u64) -> SuffixLog {
    opened((LIMITS, blocks), (start, reserved), start)
}

fn insert(slot: usize, start: u64) -> Record {
    Record::Insert(wide(slot, start, 1))
}

/// Appends `record` and asserts that the refusal `refusal` leaves the whole log unchanged.
fn refused(log: &mut SuffixLog, now: u64, record: &Record, refusal: SuffixRefusal) {
    let before = format!("{log:?}");
    assert_eq!(log.append(now, record), Err(refusal));
    assert_eq!(format!("{log:?}"), before, "{refusal:?} changes nothing");
}

#[test]
fn a_closed_log_refuses_every_append_and_seals_a_zero_cut() {
    let mut log = SuffixLog::default();
    assert_eq!(log.append(0, &insert(0, 0)), Err(SuffixRefusal::Closed));
    assert_eq!(log.seal_cut(), 0);
    assert_eq!(take(&mut log), None);
    assert!(!log.needs_extension(1));
}

#[test]
fn limits_with_no_queue_or_region_or_a_stall_bound_within_the_flush_interval_leave_the_log_closed()
{
    for limits in [
        (
            SuffixLimits {
                queue_blocks: 0,
                ..LIMITS
            },
            10,
        ),
        (LIMITS, 0),
        (
            SuffixLimits {
                oldest_ns: LIMITS.flush_ns,
                ..LIMITS
            },
            10,
        ),
    ] {
        let mut log = opened(limits, (7, 17), 7);
        assert_eq!(
            log.append(0, &insert(0, 0)),
            Err(SuffixRefusal::Closed),
            "{limits:?}"
        );
        assert_eq!((log.seal_cut(), log.durable()), (7, 7), "{limits:?}");
        let reopened = log.open(
            (Crc32c::detect(), shard()),
            (LIMITS, &layout(10)),
            Suffix {
                session: SESSION,
                start: 7,
                certified: 7,
                end: 17,
            },
            7,
        );
        assert!(reopened, "a refused open leaves the log unused");
    }
    let mut log = SuffixLog::default();
    let session_zero = Suffix {
        session: 0,
        start: 7,
        certified: 7,
        end: 17,
    };
    let crc = (Crc32c::detect(), shard());
    assert!(!log.open(crc, (LIMITS, &layout(10)), session_zero, 7));
    assert_eq!(log.append(0, &insert(0, 0)), Err(SuffixRefusal::Closed));
    assert_eq!((log.seal_cut(), log.durable()), (7, 7));
    assert!(
        !log.required(),
        "a refused open of an unrequired log leaves it unrequired"
    );
    // A suffix recorded as certified past its start names blocks this log never wrote.
    let mut log = SuffixLog::default();
    let certified_ahead = Suffix {
        session: SESSION,
        start: 7,
        certified: 9,
        end: 17,
    };
    assert!(!log.open(crc, (LIMITS, &layout(10)), certified_ahead, 7));
    assert_eq!(log.append(0, &insert(0, 0)), Err(SuffixRefusal::Closed));
    // A record with no extent, or one spanning more blocks than a 3-block region, never fits.
    let mut log = opened(
        (
            SuffixLimits {
                queue_blocks: 10,
                ..LIMITS
            },
            3,
        ),
        (0, 3),
        0,
    );
    let mut empty = wide(0, 0, 1);
    empty.extents.clear();
    refused(&mut log, 0, &Record::Insert(empty), SuffixRefusal::Body);
    refused(
        &mut log,
        0,
        &Record::Insert(wide(0, 0, 2115)),
        SuffixRefusal::Body,
    );
    let widest = Record::Replace {
        old: identity_of(&wide(0, 0, 1)),
        cause: Cause::Evict,
        new: wide(1, 100, 2115),
    };
    let five = SuffixLimits {
        queue_blocks: 5,
        ..LIMITS
    };
    let mut log = opened((five, 5), (0, 5), 0);
    assert_eq!(log.append(0, &widest), Ok(position(4, 0)));
}

/// A required log stays required through a refused open and a close, and a close keeps the flush interval, so a
/// drained block's retry keeps its pace.
#[test]
fn a_required_log_stays_required_and_a_close_keeps_the_flush_interval() {
    let mut log = SuffixLog::default();
    log.require();
    let suffix = Suffix {
        session: SESSION,
        start: 0,
        certified: 0,
        end: 10,
    };
    let crc = (Crc32c::detect(), shard());
    let invalid = SuffixLimits {
        queue_blocks: 0,
        ..LIMITS
    };
    assert!(!log.open(crc, (invalid, &layout(10)), suffix, 0));
    assert!(log.required(), "a refused open keeps the requirement");
    assert_eq!(log.flush_ns(), 0);
    assert!(log.open(crc, (LIMITS, &layout(10)), suffix, 0));
    log.close();
    assert!(log.required() && !log.is_open());
    assert_eq!(log.flush_ns(), LIMITS.flush_ns);
    assert_eq!(log.append(0, &insert(0, 0)), Err(SuffixRefusal::Closed));
}

/// A log opens once: a second open, while a block is queued or after one is written, changes nothing, so no
/// `(session, LSN)` is reissued with other bytes and the durable prefix never moves back.
#[test]
fn a_used_log_refuses_to_reopen_and_keeps_its_blocks() {
    let mut log = open(10, 20, 20);
    log.append(0, &insert(0, 0)).unwrap();
    log.seal_cut();
    let before = format!("{log:?}");
    let reopened = Suffix {
        session: SESSION,
        start: 30,
        certified: 30,
        end: 40,
    };
    let identity = (Crc32c::detect(), shard());
    assert!(!log.open(identity, (LIMITS, &layout(20)), reopened, 30));
    assert_eq!(format!("{log:?}"), before, "a queued block keeps the log");
    let (lsn, _) = take(&mut log).unwrap();
    assert!(!log.open(identity, (LIMITS, &layout(20)), reopened, 30));
    log.written(lsn);
    assert!(!log.open(identity, (LIMITS, &layout(20)), reopened, 30));
    assert_eq!((log.head(), log.durable()), (11, 11));
}

/// A completion of another LSN than the outstanding write changes nothing: the block stays outstanding, so no
/// second write of it is issued, and the matching completion then advances the durable prefix.
#[test]
fn a_stale_completion_leaves_the_outstanding_write_in_place() {
    let mut log = open(0, 20, 20);
    log.append(0, &insert(0, 0)).unwrap();
    log.seal_cut();
    log.append(0, &insert(1, 8)).unwrap();
    log.seal_cut();
    assert_eq!(take(&mut log).map(|(lsn, _)| lsn), Some(0));
    log.written(1);
    assert_eq!(take(&mut log), None, "block 0 is still outstanding");
    assert_eq!(log.durable(), 0);
    log.written(0);
    assert_eq!(log.durable(), 1);
    assert_eq!(take(&mut log).map(|(lsn, _)| lsn), Some(1));
}

/// `Body` depends on the record and the limits alone: a record that fits an empty block but not the room left in the
/// open one is admitted and spills into the next block, and a tenure starting near `LSN_LIMIT` refuses `Exhausted`
/// with no overflow.
#[test]
fn a_partly_filled_block_spills_a_fitting_record_and_the_lsn_limit_is_exhaustion() {
    let limits = SuffixLimits {
        queue_blocks: 2,
        ..LIMITS
    };
    let mut log = opened((limits, 100), (0, 100), 0);
    log.append(0, &insert(0, 0)).unwrap();
    let nearly = Record::Insert(wide(1, 8, (room() - 100) / 8));
    assert_eq!(
        log.append(0, &nearly),
        Ok(position(1, 0)),
        "the record spans into block 1"
    );
    assert_eq!(log.head(), 1);
    let mut limit = open(LSN_LIMIT - 1, LSN_LIMIT + 1, u64::MAX / 2);
    limit.append(0, &insert(0, 0)).unwrap();
    limit.seal_cut();
    limit.append(0, &insert(1, 8)).unwrap();
    limit.seal_cut();
    refused(&mut limit, 0, &insert(2, 16), SuffixRefusal::Exhausted);
}

#[test]
fn the_cut_lies_between_the_records_appended_before_and_after_it() {
    let mut log = open(10, 20, 20);
    let before = log.append(0, &insert(0, 0)).unwrap();
    assert_eq!(before >> 32, 10, "the first record lands in block 10");
    let cut = log.seal_cut();
    assert_eq!(cut, 11, "the sealed block is below the cut");
    let after = log.append(2, &insert(1, 8)).unwrap();
    assert_eq!(
        after >> 32,
        cut,
        "a record after the cut lands at or above it"
    );
    assert_eq!(log.seal_cut(), 12);
    let (lsn, bytes) = take(&mut log).unwrap();
    assert_eq!(lsn, 10);
    let decoded = decode(Crc32c::detect(), block(10), SESSION, &bytes[..], Vec::new()).unwrap();
    assert_eq!(decoded.len(), 1);
}

#[test]
fn a_full_queue_or_stalled_flush_refuses_an_append_before_publication_and_changes_nothing() {
    let mut log = open(0, 100, 100);
    for at in 0..LIMITS.queue_blocks as u64 {
        log.append(at, &insert(at as usize, 8 * at)).unwrap();
        log.seal_cut();
    }
    assert_eq!(log.head(), 4);
    refused(&mut log, 5, &insert(9, 72), SuffixRefusal::Queue);
    let (lsn, first) = take(&mut log).map(|(lsn, bytes)| (lsn, *bytes)).unwrap();
    assert_eq!(lsn, 0);
    assert_eq!(take(&mut log), None, "one write is outstanding at a time");
    log.written(0);
    assert_eq!(log.durable(), 1);
    log.append(5, &insert(9, 72)).unwrap();
    // The oldest sealed block has waited past the stall bound: a store outage or a stalled device.
    refused(
        &mut log,
        LIMITS.oldest_ns + 2,
        &insert(10, 80),
        SuffixRefusal::Stalled,
    );
    let (lsn, bytes) = take(&mut log).map(|(lsn, bytes)| (lsn, *bytes)).unwrap();
    assert_eq!(lsn, 1);
    assert_ne!(bytes, first);
    log.failed(1);
    let (again, retried) = take(&mut log).map(|(lsn, bytes)| (lsn, *bytes)).unwrap();
    assert_eq!(
        (again, retried),
        (1, bytes),
        "a failed write is retried with the same bytes"
    );
}

#[test]
fn an_acknowledged_record_in_the_open_block_bounds_the_stall_age() {
    let mut log = open(0, 100, 100);
    log.append(0, &insert(0, 0)).unwrap();
    refused(
        &mut log,
        LIMITS.oldest_ns + 1,
        &insert(1, 8),
        SuffixRefusal::Stalled,
    );
}

#[test]
fn the_head_refuses_at_the_reserved_end_capacity_and_tenure_bound_and_extends_only_to_the_capacity()
{
    let mut log = opened((LIMITS, 3), (2, 4), 2);
    log.append(0, &insert(0, 0)).unwrap();
    log.seal_cut();
    log.append(0, &insert(1, 8)).unwrap();
    log.seal_cut();
    assert_eq!(log.head(), 4);
    refused(&mut log, 0, &insert(2, 16), SuffixRefusal::Reserved);
    assert!(log.needs_extension(0));
    log.extend(10);
    assert_eq!(
        log.reserved(),
        5,
        "the reserved end is bounded by the capacity"
    );
    log.append(0, &insert(2, 16)).unwrap();
    log.seal_cut();
    refused(&mut log, 0, &insert(3, 24), SuffixRefusal::Exhausted);
    assert!(!log.needs_extension(0), "the capacity admits no more");
    // The widest record spans five blocks from an empty block, more than the four the queue holds, so it never fits.
    let mut wide_log = open(0, 100, 100);
    let wide_record = Record::Insert(wide(3, 24, crate::storage::geometry::EXTENT_LIMIT as usize));
    refused(&mut wide_log, 0, &wide_record, SuffixRefusal::Body);
    let mut limit = open(LSN_LIMIT, LSN_LIMIT + 5, 10);
    assert_eq!(limit.reserved(), LSN_LIMIT + 1);
    limit.append(0, &insert(0, 0)).unwrap();
    limit.seal_cut();
    refused(&mut limit, 0, &insert(1, 8), SuffixRefusal::Exhausted);
}

#[test]
fn a_successor_of_an_exhausted_predecessor_admits_mutations_after_its_first_settled_publish() {
    // The predecessor wrote LSNs 0..8 of an 8-block region, so the floor 0 leaves the successor at 8 no capacity.
    let mut log = opened((LIMITS, 8), (8, 12), 0);
    assert_eq!(log.reserved(), 8);
    refused(&mut log, 0, &insert(0, 0), SuffixRefusal::Capacity);
    // A settled publish whose cut is the successor's head raises the floor to 8.
    assert_eq!(log.seal_cut(), 8);
    log.covered(8);
    log.extend(12);
    assert_eq!(log.reserved(), 12);
    assert_eq!(log.append(0, &insert(0, 0)), Ok(position(8, 0)));
    // The capacity never passes the tenure's start plus the region, whatever the floor.
    log.covered(100);
    log.extend(100);
    assert_eq!(log.reserved(), 16);
}

#[test]
fn a_removed_slot_returns_its_units_only_after_its_last_block_is_durable() {
    let mut log = open(7, 20, 20);
    let x = wide(0, 0, 1);
    let held = log.append(0, &remove(&x, Cause::Evict)).unwrap();
    assert_eq!(held, position(7, 0));
    assert!(!reusable(0, held, log.durable(), false));
    log.seal_cut();
    let (lsn, _) = take(&mut log).unwrap();
    assert!(
        !reusable(0, held, log.durable(), false),
        "an outstanding write holds"
    );
    log.written(lsn);
    assert!(reusable(0, held, log.durable(), false));
    // A REPLACE spanning blocks holds its slot until its last block is durable.
    let replace = Record::Replace {
        old: identity_of(&x),
        cause: Cause::Evict,
        new: wide(1, 8, 700),
    };
    let last = log.append(0, &replace).unwrap();
    assert!(last >> 32 > 8, "the record ends past its first block");
    log.seal_cut();
    while let Some((lsn, _)) = take(&mut log) {
        assert!(!reusable(0, last, log.durable(), false));
        log.written(lsn);
    }
    assert!(reusable(0, last, log.durable(), false));
}

/// A log in steady state allocates nothing for records whose extents lie in ascending order: a written block's
/// payload serves a later open block, and each take encodes into the writer's own buffer. The first blocks
/// allocate what then circulates: two payloads, the spill buffer, the spare list and the two block queues.
#[test]
fn a_written_block_s_payload_serves_a_later_block_so_a_steady_log_allocates_nothing() {
    let limits = SuffixLimits {
        queue_blocks: 4,
        ..LIMITS
    };
    let mut log = opened((limits, 64), (0, 64), 0);
    let record = insert(1, 8);
    let mut unit = Box::new([0; UNIT_LEN]);
    let mut blocks = |log: &mut SuffixLog, count: u64| {
        let until = log.head() + count;
        while log.head() < until {
            log.append(0, &record).unwrap();
            if let Some(lsn) = log.take(&mut unit) {
                log.written(lsn);
            }
        }
    };
    blocks(&mut log, 4);
    let (allocated, freed) = (
        crate::instrument::allocations(),
        crate::instrument::deallocations(),
    );
    blocks(&mut log, 16);
    assert_eq!(log.durable(), 20, "every sealed block was written");
    assert_eq!(
        (
            crate::instrument::allocations(),
            crate::instrument::deallocations()
        ),
        (allocated, freed),
        "sixteen blocks of records allocated or freed"
    );
}

#[test]
fn an_append_whose_extents_need_the_overlap_sort_allocates_nothing_once_the_span_buffer_is_sized() {
    let mut log = open(0, 8, 16);
    let mut descending = wide(1, 8, 4);
    descending.extents.reverse();
    let record = Record::Insert(descending);
    log.append(0, &record).unwrap();
    let allocated = crate::instrument::allocations();
    log.append(0, &record).unwrap();
    assert_eq!(crate::instrument::allocations(), allocated);
}

#[test]
fn the_overlap_check_of_an_entry_reads_only_its_own_spans() {
    let mut log = open(0, 8, 16);
    let unordered = |starts: [u64; 3]| {
        let mut entry = wide(0, 0, 3);
        entry.extents = (starts.iter())
            .map(|&start| ExtentLocator::new(start, 2).unwrap().bits())
            .collect();
        Record::Insert(entry)
    };
    log.append(0, &unordered([40, 20, 0])).unwrap();
    refused(&mut log, 0, &unordered([40, 20, 21]), SuffixRefusal::Body);
    log.append(0, &unordered([41, 22, 2])).unwrap();
}

#[test]
fn the_flush_interval_seals_the_open_block() {
    let mut log = open(0, 10, 10);
    log.append(5, &insert(0, 0)).unwrap();
    log.flush_due(5 + LIMITS.flush_ns - 1);
    assert_eq!(take(&mut log), None);
    log.flush_due(5 + LIMITS.flush_ns);
    assert_eq!(take(&mut log).map(|(lsn, _)| lsn), Some(0));
}

/// The delta region of a volume: `J` units, each holding at most one block, with the write attempts that may still
/// land on them. A write issues an attempt; `land` applies the attempt's bytes, and a fence ends every attempt.
struct Region {
    blocks: u64,
    units: HashMap<u64, (u64, Box<[u8; UNIT_LEN]>)>,
    attempts: Vec<(u64, Box<[u8; UNIT_LEN]>)>,
    damaged: HashSet<u64>,
}

impl Region {
    fn land(&mut self, at: usize) {
        let (lsn, bytes) = self.attempts.remove(at);
        self.damaged.remove(&lsn);
        self.units.insert(lsn % self.blocks, (lsn, bytes));
    }

    /// Whether block `lsn` is on the medium and undamaged.
    fn holds(&self, lsn: u64) -> bool {
        self.units
            .get(&(lsn % self.blocks))
            .is_some_and(|(at, _)| *at == lsn)
            && !self.damaged.contains(&lsn)
    }

    fn read(&self, lsn: u64, bytes: &mut [u8; UNIT_LEN]) -> bool {
        *bytes = self
            .units
            .get(&(lsn % self.blocks))
            .map_or([0; UNIT_LEN], |(_, unit)| **unit);
        if self.damaged.contains(&lsn) {
            bytes[UNIT_LEN / 2] ^= 0xFF;
        }
        true
    }
}

/// The units and slots the simulated pool hands out; each new incarnation takes a fresh key and allocation word.
const UNITS: u64 = 6;

fn incarnation(unit: u64, serial: u64) -> CaptureEntry {
    let mut entry = wide(unit as usize, unit, 1);
    entry.key[8..16].copy_from_slice(&serial.to_le_bytes());
    entry.allocation = (unit << 32) | serial;
    entry.extents = vec![ExtentLocator::new(unit, 1).unwrap().bits()];
    entry
}

/// The removals and inserts a record makes.
fn effects(record: &Record) -> (Option<Identity>, Option<&CaptureEntry>) {
    match record {
        Record::Insert(entry) => (None, Some(entry)),
        Record::Remove { identity, .. } => (Some(*identity), None),
        Record::Replace { old, new, .. } => (Some(*old), Some(new)),
    }
}

/// An identity as a hash key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Id([u8; 32], u64, u64, u64);

fn id_of(id: Identity) -> Id {
    Id(id.key, id.allocation, id.session, id.version)
}

/// The ghost of one run: what was acknowledged and the blocks each record spans, from the LSNs the appender
/// returned, independent of the replay under test.
#[derive(Default)]
struct Ghost {
    ever: HashSet<Id>,
    removed: HashSet<Id>,
    /// The first and last blocks of each removal's record and of each insert's.
    removed_at: HashMap<Id, (u64, u64)>,
    inserted_at: HashMap<Id, (u64, u64)>,
}

/// Checks a recovery against the ghost and the medium alone: one owner per unit and slot (P6), no entry whose
/// removal is whole and undamaged on the medium (FRONTIER), no entry inserted behind a hole of its suffix (NO-SKIP),
/// only acknowledged entries, and every entry of `durable`, the state the last durable block or publish left,
/// recovered unless its removal is on the medium, a recovered entry took its unit or slot after its removal, or a
/// block of its suffix up to its insert's last block is not on the medium (`Retained`).
fn check(
    load: &SuffixLoad,
    (ghost, region): (&Ghost, &Region),
    (cut, chain): (u64, &[Suffix]),
    durable: &[CaptureEntry],
) -> Result<(), String> {
    let mut units = HashSet::new();
    let mut slots = HashSet::new();
    for entry in &load.entries {
        if !units.insert(entry.extents[0]) || !slots.insert(entry.slot()) {
            return Err(format!("two owners of unit or slot of {entry:?}"));
        }
    }
    let recovered: HashSet<Id> = load.entries.iter().map(|e| id_of(identity_of(e))).collect();
    // A removal is on the medium when every block of its record is: a record applies only when whole.
    let tombstoned = |&(first, last): &(u64, u64)| (first..=last).all(|at| region.holds(at));
    // Whether the blocks of `id`'s suffix from the replay's start through its insert's last block are all intact.
    let reaches = |id: &Id| {
        let Some(&(_, last)) = ghost.inserted_at.get(id).filter(|(first, _)| *first >= cut) else {
            return true;
        };
        let suffix = chain.iter().find(|s| (s.start..s.end).contains(&last));
        suffix.is_none_or(|s| (s.start.max(cut)..=last).all(|at| region.holds(at)))
    };
    for id in &recovered {
        if !ghost.ever.contains(id) {
            return Err(format!("{id:?} was never acknowledged"));
        }
        if ghost.removed_at.get(id).is_some_and(tombstoned) {
            return Err(format!(
                "{id:?} resurrected over its tombstone on the medium"
            ));
        }
        if !reaches(id) {
            return Err(format!("{id:?} applied behind a hole of its suffix"));
        }
    }
    if !load.report.withheld.is_empty() {
        return Err(format!(
            "withheld {:?} with no conflict within one level",
            load.report.withheld
        ));
    }
    for entry in durable {
        let id = id_of(identity_of(entry));
        let taken = load
            .entries
            .iter()
            .any(|other| other.extents[0] == entry.extents[0] || other.slot() == entry.slot());
        let removed = ghost.removed.contains(&id);
        let gone = removed && (ghost.removed_at.get(&id).is_some_and(tombstoned) || taken);
        if !recovered.contains(&id) && !gone && reaches(&id) {
            return Err(format!(
                "durable {id:?} lost with no fault naming it: {load:?}"
            ));
        }
        if !ghost.ever.contains(&id) {
            return Err(format!("{id:?} was never acknowledged"));
        }
    }
    Ok(())
}

/// The schedule states a run reached: recoveries with damage, dropped inserts, cross-level supersession, exclusions,
/// a cut above zero, and an entry whose removal's record has its last block on the medium and an earlier block
/// missing; records split across blocks; and handoffs before the tenure bound.
#[derive(Debug, Default, Clone, Copy)]
struct Reach {
    damage: usize,
    dropped: usize,
    superseded: usize,
    excluded: usize,
    cut: usize,
    partial: usize,
    split: usize,
    handoff: usize,
}

/// One seeded run of up to four tenures over one region; the error names the first broken property.
fn simulate(seed: u64, reach: &mut Reach) -> Result<(), String> {
    let mut rng = SplitMix64::new(seed);
    let blocks = 4 + rng.below(6);
    let mut region = Region {
        blocks,
        units: HashMap::new(),
        attempts: Vec::new(),
        damaged: HashSet::new(),
    };
    let mut ghost = Ghost::default();
    let (mut base, mut cut, mut chain) = (Vec::new(), 0u64, Vec::<Suffix>::new());
    let mut durable: Vec<CaptureEntry> = Vec::new();
    let mut serial = 0u64;
    for epoch in [2u64, 4, 6, 8] {
        let reader = (Crc32c::detect(), shard(), (3 << 32) | epoch);
        let loaded = replay(
            reader,
            (&layout(blocks), &super::delta_replay_tests::limits()),
            base.clone(),
            cut,
            &chain,
            |lsn, unit| region.read(lsn, unit),
        )
        .unwrap();
        check(&loaded, (&ghost, &region), (cut, &chain), &durable)
            .map_err(|e| format!("epoch {epoch}: {e}"))?;
        // The suffix-only replay and each checkpoint entry's patch fate compose the batch replay's entries; the ghost's
        // check runs first, so a planted defect it catches reports the ghost's property.
        let (live, _, patch) = super::delta_replay::patch(
            reader,
            (&layout(blocks), &super::delta_replay_tests::limits()),
            cut,
            &chain,
            |lsn, unit| region.read(lsn, unit),
        )
        .unwrap();
        let kept =
            (base.iter()).filter(|entry| patch.fate_of(entry) == super::delta_replay::Fate::Kept);
        if kept.cloned().chain(live).collect::<Vec<_>>() != loaded.entries {
            return Err(format!(
                "epoch {epoch}: the patch composition differs from the batch replay"
            ));
        }
        if !loaded.report.unread.is_empty() {
            return Err(format!("epoch {epoch}: unread {:?}", loaded.report.unread));
        }
        let faulted = |suffix: &Suffix| {
            let lsns = suffix.start.max(cut)..suffix.end.min(suffix.start + blocks);
            let hole = lsns.clone().find(|&lsn| !region.holds(lsn));
            hole.is_some_and(|hole| {
                hole < suffix.certified || lsns.clone().any(|lsn| lsn > hole && region.holds(lsn))
            })
        };
        if loaded.installable() == chain.iter().any(faulted) {
            return Err(format!(
                "epoch {epoch}: installable {} against the medium",
                loaded.installable()
            ));
        }
        reach.damage += usize::from(!loaded.report.damage.is_empty());
        reach.dropped += usize::from(!loaded.report.dropped.is_empty());
        reach.superseded += usize::from(!loaded.report.superseded.is_empty());
        reach.excluded += usize::from(!loaded.report.excluded.is_empty());
        reach.cut += usize::from(cut > 0);
        reach.partial += usize::from(loaded.entries.iter().any(|entry| {
            let removal = ghost.removed_at.get(&id_of(identity_of(entry)));
            removal.is_some_and(|&(first, last)| {
                region.holds(last) && !(first..last).all(|at| region.holds(at))
            })
        }));
        if !loaded.installable() || chain.len() == crate::failover::records::MAX_CHAIN {
            return Ok(());
        }
        // The recovery certifies each predecessor suffix through the blocks it read whole.
        for suffix in &mut chain {
            let whole = (suffix.start.max(cut)..suffix.end).find(|&lsn| !region.holds(lsn));
            suffix.certified = suffix.certified.max(whole.unwrap_or(suffix.end));
        }
        let session = (3 << 32) | epoch;
        let start = chain.last().map_or(cut, |last| last.end);
        let floor = chain.first().map_or(start, |first| first.start.max(cut));
        let mut log = SuffixLog::default();
        let mut own = Suffix {
            session,
            start,
            certified: start,
            end: start + 1 + rng.below(4),
        };
        log.open(
            (Crc32c::detect(), shard()),
            (LIMITS, &layout(blocks)),
            own,
            floor,
        );
        own.end = log.reserved().max(start + 1);
        chain.push(own);
        let mut live = loaded.entries.clone();
        durable = live.clone();
        // The step and live state each sealed block's write makes durable, and units held until a tombstone's block is
        // durable.
        let mut after: HashMap<u64, (u64, Vec<CaptureEntry>)> = HashMap::new();
        // The step whose state `durable` holds; a block sealed before a publish leaves the publish's state.
        let mut durable_at = 0;
        let mut held: HashMap<u64, u64> = HashMap::new();
        for step in 0..(5 + rng.below(25)) {
            let now = step * 10_000_000;
            // The owner hands off to a new tenure before the head reaches the per-tenure bound `start + J`, so no
            // append refuses `Exhausted`.
            if log.head() + 2 >= start + blocks {
                reach.handoff += 1;
                break;
            }
            let owned: HashSet<u64> = live.iter().map(|e| e.extents[0]).collect();
            let free: Vec<u64> = (0..UNITS)
                .filter(|u| {
                    !owned.contains(&ExtentLocator::new(*u, 1).unwrap().bits())
                        && !held.contains_key(u)
                })
                .collect();
            let record = match rng.below(12) {
                0..=4 if !free.is_empty() => {
                    serial += 1;
                    let mut new = incarnation(free[rng.below(free.len() as u64) as usize], serial);
                    new.session = session;
                    if rng.below(6) == 0 {
                        // A record wider than a block, split across two: its first extent is its pool unit and the
                        // rest lie in a range of its own.
                        let own = (1..600)
                            .map(|at| ExtentLocator::new((serial << 10) + at, 1).unwrap().bits());
                        new.extents.extend(own);
                    }
                    match live.iter().position(|_| rng.below(3) == 0) {
                        Some(at) => Record::Replace {
                            old: identity_of(&live[at]),
                            cause: Cause::Evict,
                            new,
                        },
                        None => Record::Insert(new),
                    }
                }
                5..=6 if !live.is_empty() => {
                    remove(&live[rng.below(live.len() as u64) as usize], Cause::Evict)
                }
                7 | 8 => {
                    let head = log.head();
                    if log.seal_cut() > head {
                        after.insert(head, (step, live.clone()));
                    }
                    if let Some((lsn, bytes)) = take(&mut log) {
                        region.attempts.push((lsn, Box::new(*bytes)));
                        if rng.below(3) > 0 {
                            region.land(region.attempts.len() - 1);
                            log.written(lsn);
                            held.retain(|_, at| *at > lsn);
                            if after[&lsn].0 >= durable_at {
                                (durable_at, durable) = after[&lsn].clone();
                            }
                        } else {
                            log.failed(lsn);
                        }
                    }
                    continue;
                }
                9 => {
                    // A settled publish: the checkpoint is the live state and the cut the sealed head.
                    let head = log.head();
                    cut = log.seal_cut();
                    if cut > head {
                        after.insert(head, (step, live.clone()));
                    }
                    base = live.clone();
                    (durable_at, durable) = (step, live.clone());
                    chain.retain(|suffix| suffix.end > cut);
                    // A cut at the tenure's reserved end drops its suffix; the tenure continues it from that end.
                    if chain.last().is_none_or(|last| last.session != session) {
                        chain.push(Suffix {
                            session,
                            start: cut,
                            certified: cut,
                            end: cut,
                        });
                    }
                    let floor = chain.first().map_or(cut, |first| first.start.max(cut));
                    log.covered(floor);
                    continue;
                }
                10 => {
                    if log.needs_extension(1) {
                        log.extend(log.reserved() + 2);
                        chain.last_mut().unwrap().end = log.reserved();
                    }
                    chain.last_mut().unwrap().certified = log.durable();
                    continue;
                }
                _ => {
                    // Damage to a block on the medium below its suffix's certified end, a block holding a removal
                    // when one qualifies.
                    let mut certified: Vec<u64> = region
                        .units
                        .values()
                        .map(|(lsn, _)| *lsn)
                        .filter(|lsn| chain.iter().any(|s| (s.start..s.certified).contains(lsn)))
                        .collect();
                    certified.sort_unstable();
                    let removals: HashSet<u64> =
                        ghost.removed_at.values().map(|&(_, last)| last).collect();
                    if certified.iter().any(|lsn| removals.contains(lsn)) {
                        certified.retain(|lsn| removals.contains(lsn));
                    }
                    if let Some(&lsn) =
                        certified.get(rng.below(certified.len().max(1) as u64) as usize)
                    {
                        region.damaged.insert(lsn);
                    }
                    continue;
                }
            };
            let head = log.head();
            let appended = log.append(now, &record);
            assert_ne!(
                appended,
                Err(SuffixRefusal::Exhausted),
                "the handoff precedes the bound"
            );
            // Blocks the append sealed hold earlier records and the first part of this one, so their writes make
            // durable the state before it.
            for lsn in head..log.head() {
                after.insert(lsn, (step, live.clone()));
            }
            reach.split += usize::from(log.head() > head);
            if let Ok(position) = appended {
                let last = position >> 32;
                let (removed, inserted) = effects(&record);
                if let Some(id) = removed {
                    let unit = live.iter().find(|e| identity_of(e) == id).unwrap().extents[0];
                    live.retain(|e| identity_of(e) != id);
                    held.insert(ExtentLocator::from_bits(unit).start_unit(), last);
                    ghost.removed.insert(id_of(id));
                    ghost.removed_at.insert(id_of(id), (head, last));
                }
                if let Some(entry) = inserted {
                    live.push(entry.clone());
                    ghost.ever.insert(id_of(identity_of(entry)));
                    ghost
                        .inserted_at
                        .insert(id_of(identity_of(entry)), (head, last));
                }
            }
        }
        // Host loss: the outstanding attempt may land; the successor's fence ends it.
        if !region.attempts.is_empty() && rng.below(2) == 0 {
            region.land(0);
        }
        region.attempts.clear();
    }
    Ok(())
}

fn planted_runs(plant: Option<Plant>) -> (Vec<(u64, String)>, Reach) {
    PLANT.with(|cell| cell.set(plant));
    let mut reach = Reach::default();
    let failures = (0..1000)
        .filter_map(|seed| simulate(seed, &mut reach).err().map(|e| (seed, e)))
        .collect();
    PLANT.with(|cell| cell.set(None));
    (failures, reach)
}

/// Seed 1068 splits a REPLACE across blocks 5 and 6 and damages block 5 below the certified end. The record is not
/// whole, so the replay keeps the old entry, and the ghost must not count that entry's tombstone as on the medium.
/// The reach shows that a recovery of this schedule returns an entry under such a record.
#[test]
fn a_split_replace_whose_first_block_is_damaged_keeps_its_old_entry_at_seed_1068() {
    let mut reach = Reach::default();
    assert_eq!(simulate(1068, &mut reach), Ok(()));
    assert!(
        reach.partial > 0,
        "seed 1068 recovers an entry whose removal's record is on the medium in part: {reach:?}"
    );
}

#[test]
fn a_b_c_chain_replays_each_tenures_suffix_in_ancestry_order_under_random_schedules() {
    let (failures, reach) = planted_runs(None);
    assert!(failures.is_empty(), "{:?}", failures.first());
    let Reach {
        damage,
        dropped,
        superseded,
        excluded,
        cut,
        // These seeds reach no such recovery; the seeded test above asserts one.
        partial: _,
        split,
        handoff,
    } = reach;
    assert!(
        [damage, dropped, superseded, excluded, cut, split, handoff]
            .iter()
            .all(|&n| n >= 3),
        "the schedules reach damage, dropped inserts, supersession, exclusion, a cut, split records and handoffs: \
         {reach:?}"
    );
    // Negative controls: each planted defect fails a seed at the check it breaks.
    let broke = |failures: &[(u64, String)], check: &str| {
        failures.iter().any(|(_, error)| error.contains(check))
    };
    let (skipped, _) = planted_runs(Some(Plant::SkipHoles));
    assert!(
        broke(&skipped, "applied behind a hole of its suffix"),
        "SkipHoles breaks NO-SKIP"
    );
    let (unexcluded, _) = planted_runs(Some(Plant::NoExclusion));
    assert!(
        broke(&unexcluded, "resurrected over its tombstone"),
        "NoExclusion breaks FRONTIER"
    );
    let (overdropped, _) = planted_runs(Some(Plant::DropIntact));
    assert!(
        broke(&overdropped, "lost with no fault naming it"),
        "DropIntact breaks fault-local loss"
    );
}

/// An append whose last block would lie `uncertified` blocks past the certified end refuses before its
/// acknowledgment with nothing changed, after the reserved end and before the queue; a certify raises the end only
/// up to the durable prefix, so the write and the store's certify together clear it, and a durable prefix alone
/// does not.
#[test]
fn the_uncertified_backlog_refuses_before_acknowledgment_and_a_certify_clears_it() {
    let limits = SuffixLimits {
        uncertified: 2,
        queue_blocks: 8,
        ..LIMITS
    };
    let mut log = opened((limits, 20), (4, 20), 4);
    assert_eq!(log.recorded().certified, 4);
    for lsn in 4..6 {
        assert_eq!(log.append(0, &insert(0, lsn)), Ok(position(lsn, 0)));
        log.seal_cut();
    }
    refused(&mut log, 0, &insert(0, 6), SuffixRefusal::Uncertified);
    let (lsn, _) = take(&mut log).unwrap();
    log.written(lsn);
    assert_eq!(log.durable(), 5);
    refused(&mut log, 0, &insert(0, 6), SuffixRefusal::Uncertified);
    log.certified(9);
    assert_eq!(
        log.recorded().certified,
        5,
        "a certified end never passes the durable prefix"
    );
    assert_eq!(log.append(0, &insert(0, 6)), Ok(position(6, 0)));
    log.seal_cut();
    refused(&mut log, 0, &insert(0, 7), SuffixRefusal::Uncertified);
    // Reserved precedes the uncertified bound: at the reserved end the reserved refusal names the cure.
    let mut tight = opened((limits, 20), (4, 6), 4);
    tight.append(0, &insert(0, 4)).unwrap();
    tight.seal_cut();
    tight.append(0, &insert(0, 5)).unwrap();
    tight.seal_cut();
    refused(&mut tight, 0, &insert(0, 6), SuffixRefusal::Reserved);
    // A limit of no uncertified block leaves the log closed.
    let closed = opened(
        (
            SuffixLimits {
                uncertified: 0,
                ..LIMITS
            },
            20,
        ),
        (4, 20),
        4,
    );
    assert!(!closed.is_open());
}

/// The handoff is due once the head lies within the margin of the tenure's `start + J`, the bound only a new
/// tenure clears, and never against the reserved end or the capacity; a closed log signals nothing.
#[test]
fn handoff_is_due_within_margin_of_start_plus_j() {
    let limits = SuffixLimits {
        queue_blocks: 16,
        ..LIMITS
    };
    let mut log = opened((limits, 8), (3, 6), 3);
    assert!(!log.handoff_due(2), "head 3, bound 11");
    assert!(
        !log.handoff_due(3),
        "the reserved end 6 is within the margin, the bound 11 is not"
    );
    assert!(
        log.needs_extension(3),
        "the reserved end is near, the bound is not"
    );
    log.extend(11);
    for lsn in 3..9 {
        log.append(0, &insert(0, lsn)).unwrap();
        log.seal_cut();
    }
    assert_eq!(log.head(), 9);
    assert!(!log.handoff_due(1), "9 + 1 < 11");
    assert!(log.handoff_due(2), "9 + 2 reaches 3 + 8");
    log.close();
    assert!(!log.handoff_due(8), "a closed log signals no handoff");
    assert!(!SuffixLog::default().handoff_due(u64::MAX));
}

/// The writer's view: a sealed block is pending until taken, idle holds only with no record, and LSN `L` lies at
/// prefix unit `1 + K·S + L mod J`; a never-opened log names no unit.
#[test]
fn a_sealed_block_is_pending_until_taken_at_its_prefix_unit() {
    let mut log = open(3, 20, 5);
    assert!(log.idle() && !log.pending());
    log.append(0, &insert(0, 3)).unwrap();
    assert!(
        !log.idle() && !log.pending(),
        "the open block is not sealed"
    );
    log.seal_cut();
    assert!(log.pending());
    let (lsn, _) = take(&mut log).unwrap();
    assert!(!log.pending() && !log.idle(), "the write is outstanding");
    assert_eq!(log.unit(lsn), Some(1 + 3));
    assert_eq!(log.unit(7), Some(1 + 2), "LSN 7 reuses the unit of LSN 2");
    log.written(lsn);
    assert!(log.idle());
    assert_eq!(SuffixLog::default().unit(0), None);
}

/// Once the reserved end reached a capacity the settled floor holds below `start + J`, the publication
/// signal rises within the margin of it while the handoff signal stays down.
#[test]
fn a_capacity_below_the_tenure_bound_raises_the_publication_signal() {
    let limits = SuffixLimits {
        queue_blocks: 16,
        ..LIMITS
    };
    let mut log = opened((limits, 8), (5, 6), 2);
    assert_eq!(log.capacity(), 10, "min(floor 2, start 5) + J 8");
    log.extend(10);
    assert!(!log.publication_due(1));
    for lsn in 5..9 {
        log.append(0, &insert(0, lsn)).unwrap();
        log.seal_cut();
    }
    assert!(
        log.publication_due(1),
        "head 9 within one block of capacity 10"
    );
    assert!(!log.handoff_due(1), "start + J is 13");
    log.covered(5);
    assert!(
        !log.publication_due(1),
        "a settled floor at the start raises the capacity to the bound"
    );
}

/// A record spanning more blocks than the uncertified bound can never be admitted, so it refuses
/// `Body`, not the retryable `Uncertified`.
#[test]
fn a_record_wider_than_the_uncertified_bound_never_fits() {
    let widest = Record::Replace {
        old: identity_of(&wide(0, 0, 1)),
        cause: Cause::Evict,
        new: wide(1, 100, 2115),
    };
    let limits = SuffixLimits {
        queue_blocks: 8,
        uncertified: 2,
        ..LIMITS
    };
    let mut log = opened((limits, 20), (0, 20), 0);
    refused(&mut log, 0, &widest, SuffixRefusal::Body);
    assert!(
        log.append(0, &insert(0, 0)).is_ok(),
        "a one-block record fits"
    );
}

/// The backlog counts the blocks not yet durable, the open block included, of the queue bound, and ages from the
/// first record of the oldest of them, the front sealed block before a later one; a durable prefix leaves the count
/// and moves the age to the next block, and a log whose every block is durable reads age 0 without a clock sample.
/// A failed sample loses only the age. A closed log reads none.
#[test]
fn the_backlog_counts_blocks_not_yet_durable_and_ages_from_the_oldest() {
    let at = |now: u64| move || Some(now);
    let unsampled = || -> Option<u64> { panic!("an idle log samples no clock") };
    assert_eq!(SuffixLog::default().backlog(unsampled), None);
    let mut log = open(0, 100, 100);
    let queue = LIMITS.queue_blocks as u64;
    let backlog = |blocks, age_ns| {
        Some(super::suffix::SuffixBacklog {
            blocks,
            limit: queue,
            age_ns,
        })
    };
    assert_eq!(log.backlog(unsampled), backlog(0, Some(0)), "an idle log");
    log.append(10, &insert(0, 0)).unwrap();
    assert_eq!(log.backlog(at(25)), backlog(1, Some(15)), "the open block");
    assert_eq!(
        log.backlog(|| None),
        backlog(1, None),
        "a failed sample keeps the count"
    );
    assert_eq!(
        log.backlog(at(9)),
        backlog(1, None),
        "a sample before the block's first record keeps the count"
    );
    assert_eq!(log.backlog(at(10)), backlog(1, Some(0)));
    log.seal_cut();
    log.append(40, &insert(1, 8)).unwrap();
    assert_eq!(log.backlog(at(50)), backlog(2, Some(40)));
    log.seal_cut();
    assert_eq!(
        log.backlog(at(50)),
        backlog(2, Some(40)),
        "two sealed blocks age from the front one"
    );
    let (lsn, _) = take(&mut log).unwrap();
    log.written(lsn);
    assert_eq!(
        log.backlog(at(50)),
        backlog(1, Some(10)),
        "the durable block leaves the backlog"
    );
    let (lsn, _) = take(&mut log).unwrap();
    log.written(lsn);
    assert_eq!(
        log.backlog(unsampled),
        backlog(0, Some(0)),
        "every block durable"
    );
}
