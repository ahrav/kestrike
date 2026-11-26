//! The persistence contract every [`Disk`] implementation meets under a
//! persistence profile, checked through the trait alone in two halves that
//! a plain [`Expectation`] value joins while the caller stops the device,
//! tears it down and attaches a successor over the same media. The
//! simulated device runs it over shared media in every lane, and the SPDK
//! driver runs it on a bound volume as a hardware row.
//!
//! [`before_stop`] derives the profile from the device's attach facts
//! before any write, refusing with zero writes when there are none or the
//! derivation refuses. It picks three anchors (the first whole unit, the
//! unit at half the capacity and the last whole unit below the capacity)
//! and, at each, a pair of adjacent units the profile qualifies. The first
//! unit of each pair takes one write of its new pattern and the second its
//! old pattern, and every completion is picked. The contract then submits
//! the new pattern over each second unit, calls `progress` once, picks once
//! and proves the stop. A write whose completion that pick delivered with
//! success joins the completed set; every other is outstanding.
//!
//! [`after_reattach`] checks before any read that the successor's identity
//! and profile equal the predecessor's. It then reads every unit: a
//! completed unit reads back exactly, and an outstanding unit reads all old
//! or all new. A second read after the caller's window equals the first.
//! Every pattern mixes in the caller's run nonce, so bytes a previous run
//! under another nonce left on the media match no pattern of this run.
//!
//! The contract makes two assumptions. The backend persists what the device
//! reported complete. No write lands after `Stopped`: NVMe leaves undefined
//! whether a fetched write without a completion lands after the controller
//! stops, so a landing between the two reads fails the contract as a late
//! landing, and a landing between the stop and the first read is invisible
//! to it. Outstanding results are the contract's bookkeeping of completions
//! it did not observe, not a claim the device made. A failed status on a
//! qualified write leaves all old or all new bytes; no simulated fault
//! pairs a failure status with the all-new image. On the simulated device, admission refuses
//! every fault that would tear a qualified write, so its leg checks the
//! contract's bookkeeping and the labeled controls check that the contract
//! tells the outcomes apart.
//!
//! On the EBS volume the stop is a host-side controller disable, which NVMe
//! defines as a controller reset, followed by a detach, which may send a
//! normal shutdown notification, and a fresh attach in the same process.
//! The device stays powered and the EBS backend is untouched; the run is
//! not a power loss, a process crash or an EBS detach, and a run that
//! observes no torn or late write observed nothing of either.
//!
//! A failed wait unwinds while the device may still hold commands over the
//! contract's buffers, so both entry points are `unsafe`, as the disk
//! contract's is.

use std::time::{Duration, Instant};

use super::super::os::Platform;
use super::disk_contract::{PICKS, drain};
use super::{
    AttachedIdentity, Buffer, BufferArena, Classification, CommandToken, CompletionSink,
    DeriveRefusal, DeviceRange, Disk, PersistenceProfile, PoolKind, QuiesceStatus,
};

/// Units an anchor's scan tries before the contract refuses it.
const SCAN: u64 = 64;

/// The byte both patterns of a sector differ by; it differs from the
/// simulated damage pattern `0x5A`, so damage never turns one into the other.
const NEW_XOR: u8 = 0xA5;

/// The pattern versions a unit carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Version {
    Old,
    New,
}

/// Where an anchor's scan starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Anchor {
    First,
    Middle,
    Last,
}

/// A contract failure with its label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Violation {
    /// The device reports no attach facts; nothing was written.
    NoFacts,
    /// The derivation refused the facts; nothing was written.
    Underived(DeriveRefusal),
    /// No pair of adjacent qualified units lies within the anchor's scan above the previous anchor's pair; nothing was written.
    NoQualifyingRange(Anchor),
    /// The successor's identity or profile differs from the predecessor's; nothing was read.
    Successor,
    /// A unit whose write completed reads back other bytes.
    CompletedWriteLost { start: u64 },
    /// An outstanding unit holds neither whole pattern: sectors of its old pattern, its new pattern and neither, counted. A unit whose old write was lost and whose new write never landed reports here too.
    OutstandingWriteTorn {
        start: u64,
        old: usize,
        new: usize,
        other: usize,
    },
    /// A unit changed between the two reads.
    LateLanding { start: u64 },
}

impl Violation {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::NoFacts => "no-attach-facts",
            Self::Underived(_) => "profile-refused",
            Self::NoQualifyingRange(_) => "no-qualifying-range",
            Self::Successor => "successor-differs",
            Self::CompletedWriteLost { .. } => "qualified-completed-write-lost",
            Self::OutstandingWriteTorn { .. } => "qualified-outstanding-write-torn",
            Self::LateLanding { .. } => "qualified-late-landing",
        }
    }
}

/// One unit the contract wrote: its range, its index in the contract's
/// order, which selects its patterns, the token of its last write, and
/// whether that write's completion was observed with success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Unit {
    pub(crate) range: DeviceRange,
    pub(crate) index: usize,
    pub(crate) token: CommandToken,
    pub(crate) completed: bool,
}

/// What the first half leaves for the second: the predecessor's identity
/// and profile, and the six units, each marked by whether its last write's
/// completion was observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Expectation {
    pub(crate) identity: AttachedIdentity,
    pub(crate) profile: PersistenceProfile,
    /// Each anchor's pair: the unit written once with its new pattern, then the unit whose new pattern was outstanding over its old one.
    pub(crate) units: Vec<(Unit, Unit)>,
    /// The run nonce every pattern mixes in.
    pub(crate) nonce: u64,
}

impl Expectation {
    /// The bytes unit `unit` carries in `version`.
    pub(crate) fn bytes(&self, unit: &Unit, version: Version) -> Vec<u8> {
        unit_bytes(unit, version, self.nonce, &self.profile)
    }

    /// Outstanding writes without an observed completion at the stop.
    pub(crate) fn outstanding(&self) -> usize {
        self.units
            .iter()
            .filter(|(_, unit)| !unit.completed)
            .count()
    }
}

/// The bytes `unit` carries in `version` under `nonce` and `profile`'s sector size.
fn unit_bytes(unit: &Unit, version: Version, nonce: u64, profile: &PersistenceProfile) -> Vec<u8> {
    pattern(
        unit.index,
        version,
        nonce,
        profile.sector_size() as usize,
        unit.range.byte_len() as usize,
    )
}

/// What one outstanding unit held after the reattach, by sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Landing {
    pub(crate) token: CommandToken,
    pub(crate) old: usize,
    pub(crate) new: usize,
    pub(crate) other: usize,
}

/// What the second half observed when the contract held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Report {
    /// Outstanding units, in anchor order.
    pub(crate) landings: Vec<Landing>,
    /// Units whose write completed, every one read back exactly.
    pub(crate) completed: usize,
}

/// The token phases: each unit's first write, the outstanding writes, and
/// the two reads.
const FIRST: u64 = 1;
const OUTSTANDING: u64 = 2;
const READ: u64 = 3;
const REREAD: u64 = 4;

/// The tokens of the outstanding writes, in anchor order.
pub(crate) fn outstanding_tokens() -> [CommandToken; 3] {
    [0, 1, 2].map(|k| token(OUTSTANDING, k))
}

/// Whether some run left a write without an observed completion at the
/// stop; a schedule that never does leaves the outstanding checks vacuous.
pub(crate) fn sometimes_outstanding(counts: &[usize]) -> bool {
    counts.iter().any(|&count| count > 0)
}

fn token(phase: u64, index: u64) -> CommandToken {
    CommandToken::from_raw((0x50 + phase) << 32 | index)
}

/// The bytes of unit `index` in `version` under `nonce`, `len` bytes of
/// `sector`-byte sectors: in a unit of at most 251 sectors every sector
/// differs from the unit's other sectors, and each byte of the new pattern
/// is the old byte XORed with [`NEW_XOR`]. Byte `at` also XORs in byte
/// `at % 8` of `nonce`.
pub(crate) fn pattern(
    index: usize,
    version: Version,
    nonce: u64,
    sector: usize,
    len: usize,
) -> Vec<u8> {
    let nonce = nonce.to_le_bytes();
    let flip = match version {
        Version::Old => 0,
        Version::New => NEW_XOR,
    };
    (0..len)
        .map(|at| {
            let (sector, byte) = (at / sector, at % sector);
            ((byte * 31 + sector * 7 + index * 101 + 13) % 251) as u8 ^ flip ^ nonce[at % 8]
        })
        .collect()
}

/// The pair of adjacent qualified units nearest `anchor` within [`SCAN`]
/// units that starts past byte `after`, in increasing order, scanning up
/// from the first and middle anchors and down from the last.
fn pair(
    profile: &PersistenceProfile,
    unit: u64,
    units: u64,
    anchor: Anchor,
    after: Option<u64>,
) -> Option<[DeviceRange; 2]> {
    let range = |k: u64| {
        u32::try_from(unit)
            .ok()
            .and_then(|len| DeviceRange::new(k * unit, len).ok())
            .filter(|range| profile.qualifies(*range))
    };
    let both = |k: u64| {
        Some([range(k)?, range(k + 1)?])
            .filter(|found| after.is_none_or(|after| found[0].start() > after))
    };
    if units < 2 {
        return None;
    }
    match anchor {
        Anchor::First => (0..SCAN.min(units - 1)).find_map(both),
        Anchor::Middle => (units / 2..(units / 2 + SCAN).min(units - 1)).find_map(both),
        Anchor::Last => (units.saturating_sub(SCAN)..units - 1).rev().find_map(both),
    }
}

/// Submits each `(token, range, bytes)` write and returns the buffers, which
/// the caller holds until each command ended.
///
/// # Safety
///
/// As for [`before_stop`].
unsafe fn submit_writes<'a, P: Platform, D: Disk>(
    disk: &mut D,
    arena: &'a BufferArena<P>,
    writes: &[(CommandToken, DeviceRange, Vec<u8>)],
) -> Vec<Buffer<'a>> {
    let mut buffers = Vec::with_capacity(writes.len());
    for (token, range, bytes) in writes {
        let mut buffer = arena
            .acquire(PoolKind::ReceiveWrite)
            .expect("a receive-write buffer per write");
        buffer.bytes_mut()[..bytes.len()].copy_from_slice(bytes);
        // SAFETY: the caller holds `buffer` and forms no view of it until the command ended, by its picked completion or a stop proof, and keeps the arena mapped; on a failed wait the caller's abort covers the commands in flight.
        unsafe { disk.submit_write(*token, *range, buffer.range(range.byte_len()).unwrap()) }
            .expect("the device accepts the contract's write");
        buffers.push(buffer);
    }
    buffers
}

/// Reads every unit, three reads at a time, and returns its bytes, in order.
///
/// # Safety
///
/// As for [`after_reattach`].
unsafe fn read_all<P: Platform, D: Disk>(
    disk: &mut D,
    arena: &BufferArena<P>,
    units: &[Unit],
    phase: u64,
    progress: &mut impl FnMut(),
) -> Vec<Vec<u8>> {
    let mut read = Vec::with_capacity(units.len());
    for batch in units.chunks(3) {
        let mut buffers = Vec::with_capacity(batch.len());
        for unit in batch {
            let buffer = arena
                .acquire(PoolKind::ReadResponse)
                .expect("a read-response buffer per read");
            let len = unit.range.byte_len();
            let at = token(phase, unit.index as u64);
            // SAFETY: as for the writes.
            unsafe { disk.submit_read(at, unit.range, buffer.range(len).unwrap()) }
                .expect("the device accepts the contract's read");
            buffers.push((at, buffer, len as usize));
        }
        let done = drain(disk, batch.len(), progress, "the contract's reads", |_| {});
        for (at, buffer, len) in &buffers {
            let completion = done.iter().find(|done| done.token == *at).unwrap();
            assert_eq!(
                completion.status.classify(*len as u32),
                Classification::Success,
                "{completion:?}"
            );
            read.push(buffer.bytes()[..*len].to_vec());
        }
    }
    read
}

/// The first half: derives the profile, writes the completed units and the
/// outstanding units' old patterns, submits the outstanding new patterns,
/// picks once and proves the stop. Every pattern mixes in `nonce`, which
/// the caller draws afresh for each run on the same media. `progress` lets
/// the device move between picks and quiesce calls.
///
/// # Errors
///
/// `NoFacts`, `Underived` or `NoQualifyingRange`, each before any write.
///
/// # Safety
///
/// When `disk` can access `arena`'s memory outside the program, the caller
/// aborts the process on an unwind out of this call, since a failed wait may
/// leave commands over the contract's buffers.
///
/// # Panics
///
/// When a wait exhausts its bound, a write fails, the device refuses a
/// command, a unit exceeds the maximum transfer or a buffer, or the queue
/// holds fewer than three commands.
pub(crate) unsafe fn before_stop<P: Platform, D: Disk>(
    disk: &mut D,
    arena: &BufferArena<P>,
    nonce: u64,
    mut progress: impl FnMut(),
) -> Result<Expectation, Violation> {
    let facts = disk.attach_facts().ok_or(Violation::NoFacts)?.clone();
    let profile = PersistenceProfile::derive(&facts).map_err(Violation::Underived)?;
    let geometry = disk.geometry();
    let unit = profile.unit() * u64::from(profile.sector_size());
    assert!(
        unit <= u64::from(geometry.max_transfer),
        "a unit fits one transfer"
    );
    assert!(
        geometry.queue_depth >= 3,
        "the queue holds the outstanding writes"
    );
    let units = geometry.capacity / unit;
    let mut pairs: Vec<(Unit, Unit)> = Vec::with_capacity(3);
    let anchors = [Anchor::First, Anchor::Middle, Anchor::Last];
    for (k, (anchor, outstanding)) in anchors.into_iter().zip(outstanding_tokens()).enumerate() {
        let after = pairs.last().map(|(_, earlier)| earlier.range.start());
        let [first, second] = pair(&profile, unit, units, anchor, after)
            .ok_or(Violation::NoQualifyingRange(anchor))?;
        pairs.push((
            Unit {
                range: first,
                index: 2 * k,
                token: token(FIRST, 2 * k as u64),
                completed: true,
            },
            Unit {
                range: second,
                index: 2 * k + 1,
                token: outstanding,
                completed: false,
            },
        ));
    }
    for (completed, outstanding) in &pairs {
        let writes = [
            (
                completed.token,
                completed.range,
                unit_bytes(completed, Version::New, nonce, &profile),
            ),
            (
                token(FIRST, outstanding.index as u64),
                outstanding.range,
                unit_bytes(outstanding, Version::Old, nonce, &profile),
            ),
        ];
        // SAFETY: the buffers stay held until both completions are picked; the caller's abort covers a failed wait.
        let buffers = unsafe { submit_writes(disk, arena, &writes) };
        let done = drain(
            disk,
            writes.len(),
            &mut progress,
            "the contract's completed writes",
            |_| {},
        );
        for completion in &done {
            assert_eq!(
                completion.status.classify(unit as u32),
                Classification::Success,
                "{completion:?}"
            );
        }
        drop(buffers);
    }
    let writes: Vec<_> = pairs
        .iter()
        .map(|(_, outstanding)| {
            (
                outstanding.token,
                outstanding.range,
                unit_bytes(outstanding, Version::New, nonce, &profile),
            )
        })
        .collect();
    // SAFETY: the buffers stay held until the stop proof below; the caller's abort covers a failed wait.
    let buffers = unsafe { submit_writes(disk, arena, &writes) };
    progress();
    let mut observed = Vec::with_capacity(3);
    disk.pick_completions(&mut CompletionSink::new(&mut observed, 3));
    for (_, outstanding) in &mut pairs {
        outstanding.completed = observed.iter().any(|done| {
            done.token == outstanding.token
                && done.status.classify(outstanding.range.byte_len()) == Classification::Success
        });
    }
    let stopped = (0..PICKS).any(|_| {
        progress();
        disk.quiesce() == QuiesceStatus::Stopped
    });
    assert!(stopped, "the device proved its stop");
    drop(buffers);
    Ok(Expectation {
        identity: facts.identity,
        profile,
        units: pairs,
        nonce,
    })
}

/// The second half, over the successor the caller attached on the same
/// media: checks its identity and profile, reads every unit, calls
/// `progress` until `window` passed, and reads every unit again.
///
/// # Errors
///
/// `Successor` before any read; then `CompletedWriteLost`,
/// `OutstandingWriteTorn` and `LateLanding`, in that order.
///
/// # Safety
///
/// As for [`before_stop`].
///
/// # Panics
///
/// When a wait exhausts its bound, a read fails or the device refuses one.
pub(crate) unsafe fn after_reattach<P: Platform, D: Disk>(
    disk: &mut D,
    arena: &BufferArena<P>,
    expectation: &Expectation,
    window: Duration,
    mut progress: impl FnMut(),
) -> Result<Report, Violation> {
    let facts = disk.attach_facts().ok_or(Violation::Successor)?;
    let geometry = disk.geometry();
    let unit = expectation.profile.unit() * u64::from(expectation.profile.sector_size());
    assert!(
        unit <= u64::from(geometry.max_transfer) && geometry.queue_depth >= 3,
        "the successor serves the contract's reads"
    );
    let same = facts.identity == expectation.identity
        && PersistenceProfile::derive(facts).as_ref() == Ok(&expectation.profile);
    if !same {
        return Err(Violation::Successor);
    }
    let units: Vec<Unit> = expectation
        .units
        .iter()
        .flat_map(|(completed, outstanding)| [*completed, *outstanding])
        .collect();
    // SAFETY: the caller's abort covers the commands a failed wait leaves.
    let first = unsafe { read_all(disk, arena, &units, READ, &mut progress) };
    let sector = expectation.profile.sector_size() as usize;
    let mut landings = Vec::with_capacity(3);
    for (unit, read) in units.iter().zip(&first) {
        if unit.completed && *read != expectation.bytes(unit, Version::New) {
            return Err(Violation::CompletedWriteLost {
                start: unit.range.start(),
            });
        }
    }
    for (unit, read) in units.iter().zip(&first) {
        if unit.completed {
            continue;
        }
        let (old, new) = (
            expectation.bytes(unit, Version::Old),
            expectation.bytes(unit, Version::New),
        );
        let mut landing = Landing {
            token: unit.token,
            old: 0,
            new: 0,
            other: 0,
        };
        for ((read, old), new) in read
            .chunks(sector)
            .zip(old.chunks(sector))
            .zip(new.chunks(sector))
        {
            if read == old {
                landing.old += 1;
            } else if read == new {
                landing.new += 1;
            } else {
                landing.other += 1;
            }
        }
        let sectors = read.len() / sector;
        if landing.old != sectors && landing.new != sectors {
            return Err(Violation::OutstandingWriteTorn {
                start: unit.range.start(),
                old: landing.old,
                new: landing.new,
                other: landing.other,
            });
        }
        landings.push(landing);
    }
    let start = Instant::now();
    loop {
        progress();
        if start.elapsed() >= window {
            break;
        }
    }
    // SAFETY: as above.
    let second = unsafe { read_all(disk, arena, &units, REREAD, &mut progress) };
    for ((unit, first), second) in units.iter().zip(&first).zip(&second) {
        if first != second {
            return Err(Violation::LateLanding {
                start: unit.range.start(),
            });
        }
    }
    Ok(Report {
        landings,
        completed: units.iter().filter(|unit| unit.completed).count(),
    })
}
