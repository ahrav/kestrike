//! The simulated device under a persistence profile: scripted attach facts,
//! the faults a qualified write admits, the unqualified landing, and the
//! persistence contract's simulator leg with its labeled controls. Each
//! expected byte is the test's own: the patterns it wrote and the preimage
//! it seeded.

use std::rc::Rc;
use std::time::Duration;

use super::super::ledger::EngineBudget;
use super::super::os::HugepageSize;
use super::super::placement::NodeMask;
use super::super::test_platform::TestPlatform;
use super::identify::AttachFacts;
use super::identify_fixture::{EBS, Fields, facts_sized};
use super::persistence_contract::{
    Expectation, Report, Version, Violation, after_reattach, before_stop, outstanding_tokens,
    pattern, sometimes_outstanding,
};
use super::sim::{
    DAMAGE_XOR, Event, Fault, Media, Mode, Omission, QuiesceMode, SCRIPT, ScriptKind, ScriptReason,
    ScriptRefusal, SimConfig, SimControl, SimDisk, Stage, StatusForm, media, sim, sim_attached,
    sim_over,
};
use super::sim_tests::{arena, pick, submit, token};
use super::{
    BufferArena, BufferConfig, CommandTable, DeriveRefusal, DeviceRange, DeviceStatus, Disk,
    Operation, PoolKind, PoolSpec, ProfileRefusal, QuiesceProgress, QuiesceStatus, SECTOR,
};

const CAPACITY: u64 = 1 << 20;
/// A 16 KiB unit, which the EBS fixture's profile qualifies at every unit-aligned start.
const UNIT: u32 = 16_384;
const WIDE: u32 = 256 << 10;
/// The run nonce of every simulated leg.
const NONCE: u64 = 0x1123_0000_5eed_0001;

fn config(mode: Mode) -> SimConfig {
    SimConfig {
        seed: 41,
        capacity: CAPACITY,
        queue_depth: 8,
        max_transfer: WIDE,
        form: StatusForm::Nvme,
        mode,
        script: SCRIPT,
    }
}

/// The EBS fixture's facts for a device of [`CAPACITY`] bytes.
fn ebs_facts(fields: Fields) -> AttachFacts {
    facts_sized(fields, CAPACITY / 512)
}

fn attached(store: &Media, facts: AttachFacts) -> (SimDisk, SimControl) {
    sim_attached(config(Mode::Direct), Rc::clone(store), facts)
}

/// An arena whose one receive-write buffer holds a 256 KiB write.
fn wide_arena() -> BufferArena<TestPlatform> {
    const POOLS: [PoolSpec; 3] = [
        PoolSpec {
            kind: PoolKind::ReadResponse,
            count: 1,
            buffer_len: 4096,
        },
        PoolSpec {
            kind: PoolKind::ReceiveWrite,
            count: 1,
            buffer_len: WIDE,
        },
        PoolSpec {
            kind: PoolKind::Maintenance,
            count: 1,
            buffer_len: 4096,
        },
    ];
    let validated = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &POOLS,
    }
    .validate()
    .unwrap();
    BufferArena::initialize(
        &validated,
        TestPlatform::heap(4096),
        &mut EngineBudget::new(usize::MAX),
    )
    .unwrap()
}

fn refused(reason: ScriptReason) -> Result<(), ScriptRefusal> {
    Err(ScriptRefusal {
        kind: ScriptKind::Fault,
        reason,
    })
}

/// A device built with scripted facts reports them unchanged before any
/// command, after a command, after its reset and through a stopped table;
/// it derives the facts' profile, and a factless device reports and
/// derives nothing.
#[test]
fn scripted_attach_facts_stay_constant_through_commands_a_reset_and_a_stopped_table() {
    let arena = arena();
    let facts = ebs_facts(EBS);
    let (mut disk, control) = attached(&media(CAPACITY), facts.clone());
    assert_eq!(disk.attach_facts(), Some(&facts));
    assert_eq!(disk.geometry().block_size, 512);
    assert_eq!(
        control.profile().map(|profile| profile.unit()),
        Some(32),
        "the EBS fixture's 32-block unit"
    );
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    submit(
        &mut disk,
        Operation::Write,
        1,
        DeviceRange::new(0, UNIT).unwrap(),
        &buffer,
    )
    .unwrap();
    control.tick(u32::MAX);
    assert_eq!(pick(&mut disk, 1).0.len(), 1);
    assert_eq!(disk.attach_facts(), Some(&facts));
    control.set_quiesce(QuiesceMode::Reset);
    assert_eq!(disk.quiesce(), QuiesceStatus::Stopped);
    assert_eq!(disk.attach_facts(), Some(&facts));
    drop(buffer);

    let (disk, control) = attached(&media(CAPACITY), facts.clone());
    control.set_quiesce(QuiesceMode::Reset);
    let mut table = CommandTable::new(disk, &arena, 8, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap();
    let mut out = Vec::new();
    assert!(matches!(
        table.quiesce(&mut out),
        QuiesceProgress::Quiesced(_)
    ));
    assert_eq!(table.attach_facts(), Some(&facts));

    let (disk, control) = sim(config(Mode::Direct));
    assert_eq!(disk.attach_facts(), None);
    assert_eq!(control.profile(), None);
}

/// Construction refuses an identity whose capacity differs from the device's.
#[test]
#[should_panic(expected = "the identity's capacity is the device's")]
fn construction_refuses_an_identity_of_another_capacity() {
    let mut facts = ebs_facts(EBS);
    facts.identity.capacity /= 2;
    drop(attached(&media(CAPACITY), facts));
}

/// Construction refuses an identity sector size outside 512 to 4096 bytes.
#[test]
#[should_panic(expected = "the identity's sector size is a power of two from 512 to 4096 bytes")]
fn construction_refuses_an_identity_sector_size_outside_the_formats() {
    let mut facts = ebs_facts(EBS);
    facts.identity.sector_size = 256;
    drop(attached(&media(CAPACITY), facts));
}

/// Construction refuses an Identify command limit past the maximum transfer.
#[test]
#[should_panic(expected = "the Identify's command limit fits the device's maximum transfer")]
fn construction_refuses_a_command_limit_past_the_maximum_transfer() {
    drop(sim_attached(
        SimConfig {
            max_transfer: 64 << 10,
            ..config(Mode::Direct)
        },
        media(CAPACITY),
        ebs_facts(EBS),
    ));
}

/// Facts whose Identify disagrees with the identity construct a device that
/// reports them and derives no profile, so `Mismatch` stays reachable.
#[test]
fn facts_whose_identify_disagrees_with_the_identity_derive_no_profile() {
    let mut other = ebs_facts(EBS);
    other.identity.serial = "vol0fedcba9876543210".to_owned();
    let (disk, control) = attached(&media(CAPACITY), other.clone());
    assert_eq!(disk.attach_facts(), Some(&other));
    assert_eq!(control.profile(), None, "the predicate refuses Mismatch");
}

/// The block size of a device with scripted facts is its identity's
/// sector size, which the profile was derived under.
#[test]
#[should_panic(expected = "an attached device's block size is its identity's sector size")]
fn an_attached_device_refuses_a_new_block_size() {
    let (_disk, control) = attached(&media(CAPACITY), ebs_facts(EBS));
    control.set_block_size(4096);
}

/// The media an unqualified landing under `seed` leaves over a seeded
/// preimage, with the sector counts of old, new and other bytes. It posts
/// idle, stays pending as an omitted episode until the reset, logs its
/// token and seed, leaves the device's generator untouched, changes no
/// byte outside its 256 KiB range and is recorded as one attempt for each
/// run of sectors it changed. Landed again over a later write of the range,
/// those attempts restore the changed sectors and leave the kept sectors
/// with the later bytes.
fn unqualified_landing(seed: u64, mode: Mode) -> (Vec<u8>, [usize; 3]) {
    let arena = wide_arena();
    let (mut disk, control) = sim_attached(config(mode), media(CAPACITY), ebs_facts(EBS));
    let old: Vec<u8> = (0..CAPACITY as usize).map(|at| (at % 253) as u8).collect();
    control.write_device(0, &old);
    let mut buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let new: Vec<u8> = (0..WIDE as usize)
        .map(|at| (at % 241) as u8 ^ 0xC3)
        .collect();
    buffer.bytes_mut()[..WIDE as usize].copy_from_slice(&new);
    if let Mode::Modeled { .. } = mode {
        control.write_host(buffer.range(WIDE).unwrap().offset(), &new);
    }
    let range = DeviceRange::new(4 * u64::from(UNIT), WIDE).unwrap();
    control.record_attempts();
    submit(&mut disk, Operation::Write, 7, range, &buffer).unwrap();
    let draw = control.peek_rng();
    control.fault(token(7), Fault::UnqualifiedLanding { seed });
    control.execute(token(7));
    assert_eq!(
        control.peek_rng(),
        draw,
        "the landing draws nothing from the device"
    );
    assert_eq!(control.omitted(), vec![(token(7), Omission::Episode)]);
    assert!(control.ready(Stage::Post).is_empty());
    control.tick(u32::MAX);
    assert!(pick(&mut disk, 8).0.is_empty(), "the landing posts nothing");
    assert_eq!(control.pending(), 1, "the landing stays pending");
    assert!(control.events().contains(&Event::Landed {
        token: token(7),
        seed
    }));
    let after = control.device(0, CAPACITY as usize);
    let (start, end) = (range.start() as usize, range.end() as usize);
    assert!(after[..start] == old[..start] && after[end..] == old[end..]);
    let mut counts = [0; 3];
    // The maximal runs of sectors the landing changed, as device offsets.
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for (index, sector) in after[start..end].chunks(SECTOR).enumerate() {
        let at = index * SECTOR;
        if *sector == old[start + at..start + at + SECTOR] {
            counts[0] += 1;
            continue;
        }
        counts[if *sector == new[at..at + SECTOR] {
            1
        } else {
            2
        }] += 1;
        match runs.last_mut() {
            Some((_, until)) if *until == start + at => *until += SECTOR,
            _ => runs.push((start + at, start + at + SECTOR)),
        }
    }
    let attempts = control.attempts();
    let recorded: Vec<_> = (attempts.iter())
        .map(|attempt| (attempt.start as usize, attempt.bytes.clone()))
        .collect();
    let changed: Vec<_> = (runs.iter())
        .map(|&(from, until)| (from, after[from..until].to_vec()))
        .collect();
    assert_eq!(
        recorded, changed,
        "the attempt record holds each run of sectors the landing changed"
    );
    // Landed again over a later write, the attempts restore the changed sectors and leave the kept ones.
    control.write_device(start, &vec![0x77; end - start]);
    let shared = control.shared_media();
    for attempt in &attempts {
        attempt.land(&shared);
    }
    let relanded = control.device(0, CAPACITY as usize);
    assert!(relanded[..start] == old[..start] && relanded[end..] == old[end..]);
    for (index, sector) in relanded[start..end].chunks(SECTOR).enumerate() {
        let at = start + index * SECTOR;
        if after[at..at + SECTOR] == old[at..at + SECTOR] {
            assert!(
                sector.iter().all(|&byte| byte == 0x77),
                "kept sector {index}"
            );
        } else {
            assert!(*sector == after[at..at + SECTOR], "changed sector {index}");
        }
    }
    control.set_quiesce(QuiesceMode::Reset);
    assert_eq!(disk.quiesce(), QuiesceStatus::Stopped);
    assert_eq!(control.pending(), 0, "the reset drops the landing");
    (after, counts)
}

/// An unqualified landing leaves each 512-byte sector of a 256 KiB write
/// old, new or garbage, each outcome somewhere, and the same seed lands the
/// same media while another seed lands other media.
#[test]
fn an_unqualified_landing_leaves_each_sector_old_new_or_garbage_by_its_seed() {
    let (first, counts) = unqualified_landing(3, Mode::Direct);
    assert!(counts.iter().all(|&count| count > 0), "{counts:?}");
    assert_eq!(counts.iter().sum::<usize>(), WIDE as usize / SECTOR);
    let (again, _) = unqualified_landing(3, Mode::Direct);
    assert!(first == again, "the seed reproduces the landing");
    let (other, other_counts) = unqualified_landing(4, Mode::Direct);
    assert!(
        other_counts.iter().all(|&count| count > 0),
        "{other_counts:?}"
    );
    assert!(first != other, "another seed lands other media");
    let modeled = Mode::Modeled {
        backing_len: 4 << 20,
    };
    let (shadowed, _) = unqualified_landing(3, modeled);
    assert!(
        shadowed == first,
        "the modeled shadow lands the same sectors"
    );
}

/// The landing is refused on a range the profile qualifies and on a read,
/// leaving each command to execute ordinarily; a factless device admits it
/// on any write.
#[test]
fn an_unqualified_landing_is_refused_on_a_qualified_range_and_on_a_read() {
    let arena = arena();
    let landing = Fault::UnqualifiedLanding { seed: 9 };
    let (mut disk, control) = attached(&media(CAPACITY), ebs_facts(EBS));
    let (write, read) = (
        arena.acquire(PoolKind::ReceiveWrite).unwrap(),
        arena.acquire(PoolKind::ReadResponse).unwrap(),
    );
    let unit = DeviceRange::new(0, UNIT).unwrap();
    submit(&mut disk, Operation::Write, 1, unit, &write).unwrap();
    submit(&mut disk, Operation::Read, 2, unit, &read).unwrap();
    let (draw, events) = (control.peek_rng(), control.events());
    assert_eq!(
        control.try_fault(token(1), landing),
        refused(ScriptReason::Qualified(token(1)))
    );
    assert_eq!(
        control.try_fault(token(2), landing),
        refused(ScriptReason::Operation(token(2)))
    );
    assert!(control.omitted().is_empty());
    assert_eq!(
        control.peek_rng(),
        draw,
        "a refusal leaves the device's generator"
    );
    assert_eq!(control.events(), events, "a refusal logs nothing");
    assert_eq!(control.device(0, UNIT as usize), vec![0; UNIT as usize]);
    control.execute(token(1));
    assert!(
        control.device(0, UNIT as usize) == write.bytes()[..UNIT as usize],
        "the refused write executes whole"
    );
    control.tick(u32::MAX);
    assert_eq!(pick(&mut disk, 2).0.len(), 2, "both commands complete");
    drop((write, read));

    let (mut disk, control) = sim(config(Mode::Direct));
    let write = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    submit(&mut disk, Operation::Write, 3, unit, &write).unwrap();
    assert_eq!(control.try_fault(token(3), landing), Ok(()));
    control.execute(token(3));
    assert_eq!(control.omitted(), vec![(token(3), Omission::Episode)]);
    control.set_quiesce(QuiesceMode::Reset);
    assert_eq!(disk.quiesce(), QuiesceStatus::Stopped);
}

/// The media of a 16 KiB write the profile qualifies, over a zero
/// preimage of new bytes `0xE7`, after `fault` and either a tick or a reset,
/// with the completions a pick then delivers.
fn qualified_write(fault: Option<Fault>, reset: bool) -> (Vec<u8>, usize) {
    let arena = arena();
    let (mut disk, control) = attached(&media(CAPACITY), ebs_facts(EBS));
    let mut buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    buffer.bytes_mut().fill(0xE7);
    submit(
        &mut disk,
        Operation::Write,
        1,
        DeviceRange::new(0, UNIT).unwrap(),
        &buffer,
    )
    .unwrap();
    if let Some(fault) = fault {
        control.fault(token(1), fault);
    }
    if !reset {
        control.tick(u32::MAX);
    }
    let picked = pick(&mut disk, 1).0.len();
    control.set_quiesce(QuiesceMode::Reset);
    assert_eq!(disk.quiesce(), QuiesceStatus::Stopped);
    (control.device(0, UNIT as usize), picked)
}

/// On a profile-bearing device every fault that would land part of a
/// qualified write or report success over bytes other than the write's is refused by name
/// at admission; the admitted ones land the write whole or not at all.
#[test]
fn a_qualified_write_lands_whole_or_not_at_all() {
    let arena = arena();
    let (mut disk, control) = attached(&media(CAPACITY), ebs_facts(EBS));
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    submit(
        &mut disk,
        Operation::Write,
        1,
        DeviceRange::new(0, UNIT).unwrap(),
        &buffer,
    )
    .unwrap();
    for fault in [
        Fault::TornWrite { sectors: 8 },
        Fault::PartialReadFailure { sectors: 8 },
        Fault::Short { units: 1 },
        Fault::CorruptSuccess,
        Fault::MisdirectedWrite { target: 1 << 16 },
        Fault::Status(DeviceStatus::Nvme(0x0001)),
    ] {
        assert_eq!(
            control.try_fault(token(1), fault),
            refused(ScriptReason::Qualified(token(1))),
            "{fault:?}"
        );
    }
    assert_eq!(control.device(0, UNIT as usize), vec![0; UNIT as usize]);
    control.execute(token(1));
    assert!(
        control.device(0, UNIT as usize) == buffer.bytes()[..UNIT as usize],
        "the refused faults leave the write to land whole"
    );
    control.set_quiesce(QuiesceMode::Reset);
    assert_eq!(disk.quiesce(), QuiesceStatus::Stopped);
    drop(buffer);

    let whole = vec![0xE7; UNIT as usize];
    let none = vec![0; UNIT as usize];
    assert_eq!(qualified_write(None, false), (whole.clone(), 1));
    assert_eq!(
        qualified_write(Some(Fault::DropCompletion), false),
        (whole.clone(), 0),
        "a dropped completion lands whole and posts nothing"
    );
    assert_eq!(
        qualified_write(Some(Fault::Omit(Omission::Episode)), false),
        (whole, 0),
        "an omission lands whole and posts nothing"
    );
    assert_eq!(
        qualified_write(Some(Fault::DropCommand), false),
        (none.clone(), 0)
    );
    assert_eq!(
        qualified_write(Some(Fault::Status(DeviceStatus::Nvme(0x0004))), false),
        (none.clone(), 1)
    );
    assert_eq!(qualified_write(None, true), (none, 0));
}

/// How the predecessor's device moves while the contract's first half runs.
#[derive(Clone, Copy)]
enum Schedule {
    /// Posts every command except the outstanding writes, and executes, without posting, the outstanding writes whose bit is set.
    Executed(u8),
    /// Posts every command except the outstanding writes whose bit is clear, so the first half observes the completions of the set ones.
    Posted(u8),
    /// Posts every command, so the first half observes every completion.
    PostAll,
}

/// One run of the contract over shared media.
struct Leg {
    before: Result<Expectation, Violation>,
    after: Option<Result<Report, Violation>>,
    /// Writes the predecessor accepted.
    writes: usize,
    /// Reads the successor accepted.
    reads: usize,
}

/// Runs the first half on a device with `facts` under `schedule`, calls
/// `between` after the stop, then builds a successor with `successor` facts over the same media, ticks the
/// predecessor to show its reset left nothing to land, and runs the second
/// half on the successor, calling `window` whenever its device holds no
/// command after the first read of every unit.
fn leg(
    facts: Option<AttachFacts>,
    successor: AttachFacts,
    schedule: Schedule,
    between: impl FnOnce(&SimControl, &Expectation),
    mut window: impl FnMut(&SimControl, &Expectation),
) -> Leg {
    let arena = arena();
    let store = media(CAPACITY);
    let (mut disk, control) = match facts {
        Some(facts) => attached(&store, facts),
        None => sim_over(config(Mode::Direct), Rc::clone(&store)),
    };
    control.set_quiesce(QuiesceMode::Reset);
    let outstanding = outstanding_tokens();
    let progress = || {
        for token in control.ready(Stage::Post) {
            match (schedule, outstanding.iter().position(|&at| at == token)) {
                (Schedule::Executed(subset), Some(k)) => {
                    if subset >> k & 1 == 1 {
                        control.execute(token);
                    }
                }
                (Schedule::Posted(subset), Some(k)) => {
                    if subset >> k & 1 == 1 {
                        control.post(token);
                    }
                }
                _ => control.post(token),
            }
        }
    };
    // SAFETY: the simulated device reaches the buffers only on this thread inside driver and control calls, so an unwind leaves no access in flight.
    let before = unsafe { before_stop(&mut disk, &arena, NONCE, progress) };
    let writes = control.accepted(Operation::Write);
    let Ok(expectation) = &before else {
        return Leg {
            before,
            after: None,
            writes,
            reads: 0,
        };
    };
    between(&control, expectation);
    let (mut next, next_control) = attached(&store, successor);
    control.tick(u32::MAX);
    assert_eq!(control.pending(), 0, "the reset left no command to land");
    // SAFETY: as for the first half.
    let after = unsafe {
        after_reattach(&mut next, &arena, expectation, Duration::ZERO, || {
            let first_read = next_control.accepted(Operation::Read) >= 2 * expectation.units.len();
            if first_read && next_control.outstanding() == 0 {
                window(&next_control, expectation);
            }
            next_control.tick(u32::MAX);
        })
    };
    Leg {
        before,
        after: Some(after),
        writes,
        reads: next_control.accepted(Operation::Read),
    }
}

fn idle(_: &SimControl, _: &Expectation) {}

/// The contract holds over all eight executed-before-stop subsets of the
/// three outstanding writes: each executed write reads whole new, each
/// waiting one whole old, every completed unit exact, and every run leaves
/// all three without an observed completion.
#[test]
fn the_contract_holds_over_every_executed_before_stop_subset() {
    let mut counts = Vec::with_capacity(8);
    for subset in 0..8u8 {
        let run = leg(
            Some(ebs_facts(EBS)),
            ebs_facts(EBS),
            Schedule::Executed(subset),
            idle,
            idle,
        );
        let expectation = run.before.unwrap();
        assert_eq!(expectation.outstanding(), 3, "subset {subset}");
        counts.push(expectation.outstanding());
        let report = run.after.unwrap().unwrap();
        assert_eq!(report.completed, 3);
        for (k, landing) in report.landings.iter().enumerate() {
            let sectors = UNIT as usize / SECTOR;
            let expected = if subset >> k & 1 == 1 {
                (0, sectors, 0)
            } else {
                (sectors, 0, 0)
            };
            assert_eq!(
                (landing.old, landing.new, landing.other),
                expected,
                "subset {subset} write {k}"
            );
        }
    }
    assert!(sometimes_outstanding(&counts));
}

/// A schedule that posts every command lets the first half observe every
/// completion, so the contract passes with nothing outstanding and the
/// witness fails.
#[test]
fn a_schedule_with_every_completion_observed_fails_the_outstanding_witness() {
    let run = leg(
        Some(ebs_facts(EBS)),
        ebs_facts(EBS),
        Schedule::PostAll,
        idle,
        idle,
    );
    let expectation = run.before.unwrap();
    assert_eq!(expectation.outstanding(), 0);
    assert_eq!(run.after.unwrap().unwrap().completed, 6);
    assert!(!sometimes_outstanding(&[expectation.outstanding()]));
}

/// A device without facts and a cache-present device accept no write
/// before the contract refuses.
#[test]
fn the_contract_writes_nothing_before_derivation_refuses() {
    let run = leg(None, ebs_facts(EBS), Schedule::PostAll, idle, idle);
    assert_eq!(run.before, Err(Violation::NoFacts));
    assert_eq!(run.writes, 0);
    let cached = ebs_facts(Fields { vwc: 1, ..EBS });
    let run = leg(Some(cached), ebs_facts(EBS), Schedule::PostAll, idle, idle);
    assert_eq!(
        run.before,
        Err(Violation::Underived(DeriveRefusal::Ineligible(
            ProfileRefusal::VolatileWriteCache
        )))
    );
    assert_eq!(run.writes, 0);
}

/// A successor of another serial or another block format fails before the
/// contract reads anything.
#[test]
fn a_successor_of_another_identity_fails_before_any_read() {
    let mut serial = ebs_facts(EBS);
    serial.identity.serial = "vol0fedcba9876543210".to_owned();
    let format = ebs_facts(Fields { lbads: 12, ..EBS });
    for successor in [serial, format] {
        let run = leg(
            Some(ebs_facts(EBS)),
            successor,
            Schedule::Executed(0),
            idle,
            idle,
        );
        assert_eq!(run.after, Some(Err(Violation::Successor)));
        assert_eq!(run.reads, 0);
    }
}

/// Sector damage on a completed unit between the stop and the reattach
/// fails the contract as a lost completed write.
#[test]
fn damage_on_a_completed_unit_fails_as_a_lost_completed_write() {
    let run = leg(
        Some(ebs_facts(EBS)),
        ebs_facts(EBS),
        Schedule::Executed(0),
        |control, expectation| {
            let (completed, _) = expectation.units[1];
            control.damage(completed.range.start(), SECTOR as u64);
        },
        idle,
    );
    let violation = run.after.unwrap().unwrap_err();
    assert_eq!(violation.label(), "qualified-completed-write-lost");
}

/// Overwriting half of a waiting outstanding unit with its new pattern
/// between the stop and the reattach fails the contract as a torn
/// outstanding write; overwriting the whole unit passes.
#[test]
fn half_of_an_outstanding_unit_fails_as_torn_and_the_whole_unit_passes() {
    let overwrite = |half: bool| {
        leg(
            Some(ebs_facts(EBS)),
            ebs_facts(EBS),
            Schedule::Executed(0),
            move |control, expectation| {
                let (_, outstanding) = expectation.units[0];
                let new = expectation.bytes(&outstanding, Version::New);
                let len = if half { new.len() / 2 } else { new.len() };
                control.write_device(outstanding.range.start() as usize, &new[..len]);
            },
            idle,
        )
        .after
        .unwrap()
    };
    let torn = overwrite(true).unwrap_err();
    assert_eq!(torn.label(), "qualified-outstanding-write-torn");
    assert!(matches!(
        torn,
        Violation::OutstandingWriteTorn {
            old: 16,
            new: 16,
            other: 0,
            ..
        }
    ));
    let whole = overwrite(false).unwrap();
    assert_eq!(whole.landings[0].new, UNIT as usize / SECTOR);
}

/// A raw media write on a completed unit between the two reads fails the
/// contract as a late landing.
#[test]
fn a_store_between_the_two_reads_fails_as_a_late_landing() {
    let run = leg(
        Some(ebs_facts(EBS)),
        ebs_facts(EBS),
        Schedule::Executed(0),
        idle,
        |control, expectation| {
            let start = expectation.units[2].0.range.start() as usize;
            control.write_device(start, &[0xEE; SECTOR]);
        },
    );
    let violation = run.after.unwrap().unwrap_err();
    assert_eq!(violation.label(), "qualified-late-landing");
}

/// Each sector's old and new patterns differ, and neither equals the other
/// XORed with the damage pattern, so damage cannot turn a lost write
/// into a match; within a unit, every sector differs from the others.
#[test]
fn the_patterns_differ_per_sector_and_from_damage() {
    for index in 0..6 {
        let old = pattern(index, Version::Old, NONCE, SECTOR, UNIT as usize);
        let new = pattern(index, Version::New, NONCE, SECTOR, UNIT as usize);
        for (s, (old, new)) in old.chunks(SECTOR).zip(new.chunks(SECTOR)).enumerate() {
            let damaged: Vec<u8> = old.iter().map(|byte| byte ^ DAMAGE_XOR).collect();
            assert!(old != new && damaged != new, "unit {index} sector {s}");
        }
        let mut sectors: Vec<&[u8]> = old.chunks(SECTOR).collect();
        sectors.sort_unstable();
        sectors.dedup();
        assert_eq!(sectors.len(), UNIT as usize / SECTOR, "unit {index}");
    }
}

/// A device that never completes a write exhausts the contract's first wait,
/// which fails by its name.
#[test]
#[should_panic(expected = "the contract's completed writes: 0 of 2 completions arrived")]
fn a_write_that_never_completes_fails_the_named_wait() {
    let arena = arena();
    let (mut disk, _control) = attached(&media(CAPACITY), ebs_facts(EBS));
    // SAFETY: the simulated device reaches the buffers only on this thread inside driver and control calls, so an unwind leaves no access in flight.
    let _ = unsafe { before_stop(&mut disk, &arena, NONCE, || {}) };
}

/// A schedule that posts one outstanding write before the first half's
/// pick moves it to the completed set, whose bytes then read back exactly.
#[test]
fn an_outstanding_write_observed_before_the_stop_joins_the_completed_set() {
    let run = leg(
        Some(ebs_facts(EBS)),
        ebs_facts(EBS),
        Schedule::Posted(0b010),
        idle,
        idle,
    );
    let expectation = run.before.unwrap();
    assert_eq!(expectation.outstanding(), 2);
    assert!(expectation.units[1].1.completed);
    let report = run.after.unwrap().unwrap();
    assert_eq!((report.completed, report.landings.len()), (4, 2));
}

/// An outstanding unit holding neither pattern, as when its old write was
/// lost and its new write never landed, fails as torn with every sector
/// counted as other.
#[test]
fn an_outstanding_unit_of_neither_pattern_fails_as_torn() {
    let run = leg(
        Some(ebs_facts(EBS)),
        ebs_facts(EBS),
        Schedule::Executed(0),
        |control, expectation| {
            let (_, outstanding) = expectation.units[0];
            control.damage(outstanding.range.start(), u64::from(UNIT));
        },
        idle,
    );
    assert!(matches!(
        run.after.unwrap(),
        Err(Violation::OutstandingWriteTorn {
            old: 0,
            new: 0,
            other: 32,
            ..
        })
    ));
}

/// A whole new landing on an outstanding unit between the two reads fails
/// the contract as a late landing, which its assumption of no landing after
/// the stop makes it.
#[test]
fn a_whole_landing_between_the_two_reads_fails_as_a_late_landing() {
    let run = leg(
        Some(ebs_facts(EBS)),
        ebs_facts(EBS),
        Schedule::Executed(0),
        idle,
        |control, expectation| {
            let (_, outstanding) = expectation.units[0];
            let new = expectation.bytes(&outstanding, Version::New);
            control.write_device(outstanding.range.start() as usize, &new);
        },
    );
    let violation = run.after.unwrap().unwrap_err();
    assert_eq!(violation.label(), "qualified-late-landing");
}

/// Bytes a previous run under another nonce left on a completed unit match
/// no pattern of this run, so a lost completed write cannot pass on reused
/// media.
#[test]
fn a_previous_run_s_bytes_fail_as_a_lost_completed_write() {
    let run = leg(
        Some(ebs_facts(EBS)),
        ebs_facts(EBS),
        Schedule::Executed(0),
        |control, expectation| {
            let (completed, _) = expectation.units[0];
            let stale = pattern(
                completed.index,
                Version::New,
                NONCE ^ 1,
                SECTOR,
                UNIT as usize,
            );
            control.write_device(completed.range.start() as usize, &stale);
        },
        idle,
    );
    let violation = run.after.unwrap().unwrap_err();
    assert_eq!(violation.label(), "qualified-completed-write-lost");
}

/// A device that never proves a stop exhausts the contract's stop wait,
/// which fails by its name.
#[test]
#[should_panic(expected = "the device proved its stop")]
fn a_device_that_never_stops_fails_the_named_wait() {
    let arena = arena();
    let (mut disk, control) = attached(&media(CAPACITY), ebs_facts(EBS));
    // SAFETY: the simulated device reaches the buffers only on this thread inside driver and control calls, so an unwind leaves no access in flight.
    let _ = unsafe { before_stop(&mut disk, &arena, NONCE, || control.tick(u32::MAX)) };
}

/// A successor that never completes a read exhausts the contract's read
/// wait, which fails by its name.
#[test]
#[should_panic(expected = "the contract's reads: 0 of 3 completions arrived")]
fn a_read_that_never_completes_fails_the_named_wait() {
    let arena = arena();
    let store = media(CAPACITY);
    let (mut disk, control) = attached(&store, ebs_facts(EBS));
    control.set_quiesce(QuiesceMode::Reset);
    // SAFETY: as above.
    let expectation =
        unsafe { before_stop(&mut disk, &arena, NONCE, || control.tick(u32::MAX)) }.unwrap();
    let (mut next, _control) = attached(&store, ebs_facts(EBS));
    // SAFETY: as above.
    let _ = unsafe { after_reattach(&mut next, &arena, &expectation, Duration::ZERO, || {}) };
}
