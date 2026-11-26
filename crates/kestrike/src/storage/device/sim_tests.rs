//! Harness tests of the simulated device, driving the seam directly with buffers from a heap-backed arena.
//! Byte and ownership oracles are the test's own: device and host patterns it wrote, and the offsets of the buffers it holds.

use std::time::Duration;

use super::super::ledger::EngineBudget;
use super::super::os::HugepageSize;
use super::super::placement::NodeMask;
use super::super::test_platform::TestPlatform;
use super::super::volume_fixture::{BUFFER, Unit, device_with};
use super::sim::{
    Captured, Effect, Event, Fault, Injection, Mode, Origin, QuiesceMode, SCRIPT, ScriptCapacity,
    ScriptKind, ScriptReason, ScriptRefusal, SimConfig, SimControl, SimDisk, Stage, StatusForm,
    sim,
};
use super::{
    Buffer, BufferArena, BufferConfig, Classification, CommandToken, Completion, CompletionSink,
    ControllerEvent, DeviceRange, DeviceStatus, Disk, IO_UNIT, Operation, PersistenceProfile,
    PoolKind, PoolSpec, QuiesceStatus, RefusalReason, ReservationCommand, SECTOR, SubmitRefusal,
};
use crate::sim::choice::{Chooser, Domain, Site};

pub(super) const LEN: u32 = 16384;
pub(super) const TWO_MIB: usize = 2 << 20;

const POOLS: [PoolSpec; 3] = [
    PoolSpec {
        kind: PoolKind::ReadResponse,
        count: 8,
        buffer_len: LEN,
    },
    PoolSpec {
        kind: PoolKind::ReceiveWrite,
        count: 8,
        buffer_len: LEN,
    },
    PoolSpec {
        kind: PoolKind::Maintenance,
        count: 1,
        buffer_len: 4096,
    },
];

pub(super) fn arena() -> BufferArena<TestPlatform> {
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

pub(super) fn config(seed: u64, mode: Mode) -> SimConfig {
    SimConfig {
        seed,
        capacity: 1 << 20,
        queue_depth: 8,
        max_transfer: 4 * LEN,
        form: StatusForm::Kernel,
        mode,
        script: SCRIPT,
    }
}

pub(super) fn modeled(seed: u64) -> (SimDisk, SimControl) {
    sim(config(
        seed,
        Mode::Modeled {
            backing_len: TWO_MIB,
        },
    ))
}

pub(super) fn token(raw: u64) -> CommandToken {
    CommandToken::from_raw(raw)
}

pub(super) fn block(index: u64) -> DeviceRange {
    DeviceRange::new(index * u64::from(LEN), LEN).unwrap()
}

pub(super) fn submit(
    disk: &mut SimDisk,
    op: Operation,
    raw: u64,
    device: DeviceRange,
    buffer: &Buffer<'_>,
) -> Result<(), SubmitRefusal> {
    let memory = buffer.range(device.byte_len()).unwrap();
    // SAFETY: every test holds `buffer`, forms no view of it, and keeps the arena mapped until the command's completion is picked or a quiesce returned `Stopped`.
    unsafe {
        match op {
            Operation::Read => disk.submit_read(token(raw), device, memory),
            Operation::Write => disk.submit_write(token(raw), device, memory),
        }
    }
}

/// Ends every accepted command through a proven stop, so the test may drop the buffers they named.
pub(super) fn stop(disk: &mut SimDisk, control: &SimControl) {
    control.set_quiesce(QuiesceMode::Reset);
    assert_eq!(
        disk.quiesce(),
        QuiesceStatus::Stopped,
        "{}",
        control.describe()
    );
    assert_eq!(control.outstanding(), 0);
}

pub(super) fn pick(disk: &mut SimDisk, capacity: usize) -> (Vec<Completion>, usize) {
    let mut out = Vec::with_capacity(capacity);
    let mut sink = CompletionSink::new(&mut out, capacity);
    disk.pick_completions(&mut sink);
    let refused = sink.refused();
    assert_eq!(out.capacity(), capacity);
    (out, refused)
}

fn executed(control: &SimControl, raw: u64) -> bool {
    control
        .events()
        .iter()
        .any(|event| matches!(event, Event::Executed { token: t, .. } if *t == token(raw)))
}

/// Direct mode moves real bytes: a read fills the buffer from the device and a write copies the buffer to the device, each visible only after its completion is picked.
#[test]
fn direct_mode_reads_and_writes_the_buffer_through_its_range() {
    let arena = arena();
    let (mut disk, control) = sim(config(1, Mode::Direct));
    control.write_device(0, &[0xAB; LEN as usize]);
    let mut read = arena.acquire(PoolKind::ReadResponse).unwrap();
    read.bytes_mut().fill(0x11);
    let mut write = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    write.bytes_mut().fill(0xCD);
    submit(&mut disk, Operation::Read, 1, block(0), &read).unwrap();
    submit(&mut disk, Operation::Write, 2, block(1), &write).unwrap();
    control.tick(2);
    let (done, _) = pick(&mut disk, 4);
    assert_eq!(done.len(), 2, "{}", control.describe());
    for completion in &done {
        assert_eq!(completion.status, DeviceStatus::Kernel(LEN as i32));
    }
    assert!(read.bytes().iter().all(|byte| *byte == 0xAB));
    assert_eq!(
        control.device(LEN as usize, LEN as usize),
        vec![0xCD; LEN as usize]
    );
    drop((read, write));
    assert!(arena.release().is_ok());
}

#[test]
fn submits_past_depth_or_limits_are_refused_and_move_no_bytes() {
    let arena = arena();
    let (mut disk, control) = sim(SimConfig {
        queue_depth: 2,
        ..config(
            2,
            Mode::Modeled {
                backing_len: TWO_MIB,
            },
        )
    });
    control.write_device(0, &[0xEE; 4 * LEN as usize]);
    let buffers: Vec<_> = (0..6)
        .map(|_| arena.acquire(PoolKind::ReadResponse).unwrap())
        .collect();
    for buffer in &buffers {
        control.write_host(buffer.offset(), &[0x11; LEN as usize]);
    }
    let refusal = |reason| SubmitRefusal { reason, code: None };
    assert_eq!(
        submit(&mut disk, Operation::Read, 1, block(0), &buffers[0]),
        Ok(())
    );
    assert_eq!(
        submit(&mut disk, Operation::Read, 2, block(1), &buffers[1]),
        Ok(())
    );
    assert_eq!(
        submit(&mut disk, Operation::Read, 3, block(2), &buffers[2]),
        Err(refusal(RefusalReason::QueueFull))
    );
    control.tick(2);
    let (done, _) = pick(&mut disk, 2);
    assert_eq!(done.len(), 2);
    let beyond = DeviceRange::new(1 << 20, LEN).unwrap();
    assert_eq!(
        submit(&mut disk, Operation::Read, 4, beyond, &buffers[3]),
        Err(refusal(RefusalReason::InvalidRange))
    );
    let scripted = SubmitRefusal {
        reason: RefusalReason::DeviceGone,
        code: Some(-19),
    };
    control.refuse_next(scripted);
    assert_eq!(
        submit(&mut disk, Operation::Read, 5, block(3), &buffers[4]),
        Err(scripted)
    );
    // A scripted `DeviceGone` makes the device refuse all later submissions.
    assert_eq!(
        submit(&mut disk, Operation::Read, 6, block(3), &buffers[5]),
        Err(refusal(RefusalReason::DeviceGone)),
        "{}",
        control.describe()
    );
    control.tick(8);
    for raw in [3, 4, 5, 6] {
        assert!(!executed(&control, raw), "{raw}\n{}", control.describe());
    }
    for buffer in &buffers[2..] {
        assert_eq!(
            control.host(buffer.offset(), LEN as usize),
            vec![0x11; LEN as usize]
        );
    }
    drop(buffers);
    assert!(arena.release().is_ok());
}

/// An accepted command touches exactly its range: a 4 KiB prefix of a 16 KiB buffer moves only that prefix, for a read and a write, and the canaries around it stay.
#[test]
fn an_accepted_command_moves_exactly_its_range() {
    let arena = arena();
    let (mut disk, control) = modeled(13);
    control.write_device(0, &[0xD0; 3 * LEN as usize]);
    let read = arena.acquire(PoolKind::ReadResponse).unwrap();
    let write = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    control.write_host(read.offset(), &[0x11; LEN as usize]);
    control.write_host(write.offset(), &[0x22; LEN as usize]);
    let prefix = |start| DeviceRange::new(start, 4096).unwrap();
    submit(&mut disk, Operation::Read, 1, prefix(u64::from(LEN)), &read).unwrap();
    submit(
        &mut disk,
        Operation::Write,
        2,
        prefix(2 * u64::from(LEN) + 4096),
        &write,
    )
    .unwrap();
    control.tick(2);
    assert_eq!(pick(&mut disk, 2).0.len(), 2);
    let host = control.host(read.offset(), LEN as usize);
    assert!(host[..4096].iter().all(|byte| *byte == 0xD0));
    assert!(host[4096..].iter().all(|byte| *byte == 0x11));
    let device = control.device(2 * LEN as usize, LEN as usize);
    assert!(device[..4096].iter().all(|byte| *byte == 0xD0));
    assert!(device[4096..8192].iter().all(|byte| *byte == 0x22));
    assert!(device[8192..].iter().all(|byte| *byte == 0xD0));
    drop((read, write));
    assert!(arena.release().is_ok());
}

/// A faulted write that moves no byte records no attempt: a short write of zero units and a torn write of zero
/// sectors leave the record empty, and a short write of one unit records that unit.
#[test]
fn a_write_that_moves_no_byte_records_no_attempt() {
    let arena = arena();
    let (mut disk, control) = modeled(17);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let range = DeviceRange::new(u64::from(LEN), 4096).unwrap();
    control.write_host(buffer.offset(), &[0x44; 4096]);
    control.record_attempts();
    for (raw, fault) in [
        (1, Fault::Short { units: 0 }),
        (2, Fault::TornWrite { sectors: 0 }),
    ] {
        submit(&mut disk, Operation::Write, raw, range, &buffer).unwrap();
        control.fault(token(raw), fault);
        control.tick(1);
        assert_eq!(pick(&mut disk, 1).0.len(), 1);
        assert_eq!(control.attempts(), [], "{fault:?}");
    }
    submit(&mut disk, Operation::Write, 3, range, &buffer).unwrap();
    control.fault(token(3), Fault::Short { units: 1 });
    control.tick(1);
    assert_eq!(pick(&mut disk, 1).0.len(), 1);
    let attempts = control.attempts();
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        (attempts[0].start, attempts[0].bytes.len()),
        (u64::from(LEN), 4096)
    );
    drop(buffer);
    assert!(arena.release().is_ok());
}

/// A recorded write attempt keeps the bytes its command landed after the completion is picked and the device is
/// gone: landing it again restores those bytes over a later write of its range, on the media every device shares,
/// and a second landing changes nothing. Reads and writes before the recording started are not recorded. An attempt
/// that starts inside a unit covers that unit and the next one it reaches.
#[test]
fn a_recorded_write_attempt_lands_again_after_its_completion_and_its_device() {
    let arena = arena();
    let (mut disk, control) = modeled(17);
    let media = control.shared_media();
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let range = DeviceRange::new(u64::from(LEN), 4096).unwrap();
    let mut write = |raw: u64, byte: u8| {
        control.write_host(buffer.offset(), &[byte; 4096]);
        submit(&mut disk, Operation::Write, raw, range, &buffer).unwrap();
        control.tick(1);
        assert_eq!(pick(&mut disk, 1).0.len(), 1);
    };
    write(1, 0x11);
    control.record_attempts();
    write(2, 0x22);
    write(3, 0x33);
    submit(&mut disk, Operation::Read, 4, range, &buffer).unwrap();
    control.tick(1);
    assert_eq!(pick(&mut disk, 1).0.len(), 1);
    let attempts = control.attempts();
    assert_eq!(
        attempts
            .iter()
            .map(|a| (a.start, a.bytes[0], a.bytes.len()))
            .collect::<Vec<_>>(),
        [(u64::from(LEN), 0x22, 4096), (u64::from(LEN), 0x33, 4096)]
    );
    let unit = u64::from(LEN) / IO_UNIT as u64;
    assert!(
        attempts[0].covers(unit) && !attempts[0].covers(unit + 1) && !attempts[0].covers(unit - 1)
    );
    let unaligned = super::sim::Attempt {
        start: u64::from(LEN) + 512,
        bytes: vec![0; 4096],
    };
    assert!(unaligned.covers(unit) && unaligned.covers(unit + 1) && !unaligned.covers(unit - 1));
    drop(buffer);
    drop(disk);
    drop(control);
    assert!(arena.release().is_ok());
    let at = LEN as usize;
    assert!(
        media.borrow()[at..at + 4096]
            .iter()
            .all(|byte| *byte == 0x33)
    );
    for _ in 0..2 {
        attempts[0].land(&media);
        assert!(
            media.borrow()[at..at + 4096]
                .iter()
                .all(|byte| *byte == 0x22)
        );
        assert_eq!(media.borrow()[at - 1], 0);
        assert_eq!(media.borrow()[at + 4096], 0);
    }
}

/// A refused write leaves the device untouched, a posted but unpicked completion still counts against the depth, and a range over the maximum transfer is refused.
#[test]
fn refused_writes_touch_nothing_and_posted_completions_hold_queue_room() {
    let arena = arena();
    let (mut disk, control) = sim(SimConfig {
        queue_depth: 1,
        max_transfer: 4096,
        ..config(
            14,
            Mode::Modeled {
                backing_len: TWO_MIB,
            },
        )
    });
    control.write_device(0, &[0xD0; 2 * LEN as usize]);
    let a = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let b = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    control.write_host(a.offset(), &[0x33; LEN as usize]);
    control.write_host(b.offset(), &[0x44; LEN as usize]);
    let unit = |start| DeviceRange::new(start, 4096).unwrap();
    assert_eq!(
        submit(
            &mut disk,
            Operation::Write,
            1,
            DeviceRange::new(0, 8192).unwrap(),
            &a
        )
        .unwrap_err()
        .reason,
        RefusalReason::InvalidRange
    );
    submit(&mut disk, Operation::Write, 2, unit(0), &a).unwrap();
    control.post(token(2));
    assert_eq!(
        submit(&mut disk, Operation::Write, 3, unit(u64::from(LEN)), &b)
            .unwrap_err()
            .reason,
        RefusalReason::QueueFull
    );
    control.tick(4);
    assert_eq!(
        pick(&mut disk, 2)
            .0
            .iter()
            .map(|c| c.token)
            .collect::<Vec<_>>(),
        [token(2)]
    );
    assert!(
        control
            .device(LEN as usize, LEN as usize)
            .iter()
            .all(|byte| *byte == 0xD0)
    );
    assert!(control.device(4096, 4096).iter().all(|byte| *byte == 0xD0));
    submit(&mut disk, Operation::Write, 4, unit(u64::from(LEN)), &b).unwrap();
    stop(&mut disk, &control);
    drop((a, b));
    assert!(arena.release().is_ok());
}

/// One tick of one command posts exactly one completion, and an execute-only tick moves exactly one command's bytes.
#[test]
fn a_tick_runs_at_most_its_count() {
    let arena = arena();
    let (mut disk, control) = modeled(15);
    control.write_device(0, &[0x55; 4 * LEN as usize]);
    let buffers: Vec<_> = (0..4)
        .map(|_| arena.acquire(PoolKind::ReadResponse).unwrap())
        .collect();
    for (raw, buffer) in buffers.iter().enumerate() {
        submit(
            &mut disk,
            Operation::Read,
            raw as u64,
            block(raw as u64),
            buffer,
        )
        .unwrap();
    }
    control.tick(1);
    assert_eq!(pick(&mut disk, 4).0.len(), 1);
    control.execute_tick(1);
    let filled = buffers
        .iter()
        .filter(|buffer| control.host(buffer.offset(), LEN as usize)[0] == 0x55)
        .count();
    assert_eq!(filled, 2, "{}", control.describe());
    assert_eq!(pick(&mut disk, 4).0, []);
    stop(&mut disk, &control);
    drop(buffers);
    assert!(arena.release().is_ok());
}

/// No byte moves before a tick; an execute-only tick moves bytes and posts nothing; a later tick posts.
#[test]
fn bytes_move_at_execution_and_completions_post_separately() {
    let arena = arena();
    let (mut disk, control) = modeled(3);
    control.write_device(0, &[0x77; LEN as usize]);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    submit(&mut disk, Operation::Read, 1, block(0), &buffer).unwrap();
    assert_eq!(
        control.host(buffer.offset(), LEN as usize),
        vec![0; LEN as usize]
    );
    assert_eq!(pick(&mut disk, 4).0, []);
    control.execute_tick(1);
    assert_eq!(
        control.host(buffer.offset(), LEN as usize),
        vec![0x77; LEN as usize]
    );
    assert_eq!(pick(&mut disk, 4).0, []);
    control.tick(1);
    assert_eq!(pick(&mut disk, 4).0.len(), 1);
    // A scripted execution of one named command behaves the same way.
    let second = arena.acquire(PoolKind::ReadResponse).unwrap();
    submit(&mut disk, Operation::Read, 2, block(0), &second).unwrap();
    control.execute(token(2));
    assert_eq!(
        control.host(second.offset(), LEN as usize),
        vec![0x77; LEN as usize]
    );
    assert_eq!(pick(&mut disk, 4).0, []);
    control.post(token(2));
    assert_eq!(pick(&mut disk, 4).0.len(), 1);
    drop((buffer, second));
    assert!(arena.release().is_ok());
}

/// An NVMe-form device reports success with the phase bit set and failure with a non-zero status code, both passed through raw.
#[test]
fn an_nvme_form_device_reports_raw_nvme_status() {
    let arena = arena();
    let (mut disk, control) = sim(SimConfig {
        form: StatusForm::Nvme,
        ..config(
            11,
            Mode::Modeled {
                backing_len: TWO_MIB,
            },
        )
    });
    let a = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let b = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    submit(&mut disk, Operation::Write, 1, block(0), &a).unwrap();
    submit(&mut disk, Operation::Write, 2, block(1), &b).unwrap();
    control.fault(token(2), Fault::TornWrite { sectors: 1 });
    control.post(token(1));
    control.post(token(2));
    assert_eq!(
        pick(&mut disk, 2).0,
        [
            Completion {
                token: token(1),
                status: DeviceStatus::Nvme(0x0001)
            },
            Completion {
                token: token(2),
                status: DeviceStatus::Nvme(0x0004)
            },
        ]
    );
    drop((a, b));
    assert!(arena.release().is_ok());
}

/// The device the shared volume fixture's attach path builds reports kernel
/// results: the transferred byte count for a whole read and `-EIO` for a
/// read that failed part way.
#[test]
fn the_shared_fixture_device_reports_kernel_status() {
    let arena = arena();
    let (mut disk, control) = device_with(7, BUFFER);
    let a = arena.acquire(PoolKind::ReadResponse).unwrap();
    let b = arena.acquire(PoolKind::ReadResponse).unwrap();
    submit(&mut disk, Operation::Read, 1, block(0), &a).unwrap();
    submit(&mut disk, Operation::Read, 2, block(1), &b).unwrap();
    control.fault(token(2), Fault::PartialReadFailure { sectors: 1 });
    control.post(token(1));
    control.post(token(2));
    assert_eq!(
        pick(&mut disk, 2).0,
        [
            Completion {
                token: token(1),
                status: DeviceStatus::Kernel(LEN as i32)
            },
            Completion {
                token: token(2),
                status: DeviceStatus::Kernel(-libc::EIO)
            },
        ]
    );
    drop((a, b));
    assert!(arena.release().is_ok());
}

/// The shared fixture's attach facts derive a persistence profile whose
/// atomic unit is 4096 bytes of 512-byte sectors by default, and 16,384
/// bytes for a device built while a [`Unit`] guard holds that unit.
#[test]
fn the_shared_fixture_device_derives_the_default_and_held_atomic_units() {
    let derived = || {
        let (disk, _control) = device_with(7, BUFFER);
        let facts = disk
            .attach_facts()
            .expect("the fixture device carries facts");
        let profile = PersistenceProfile::derive(facts).unwrap();
        assert_eq!(facts.identity.sector_size, 512);
        profile.unit() * u64::from(facts.identity.sector_size)
    };
    assert_eq!(derived(), 4096);
    {
        let _held = Unit::hold(16_384);
        assert_eq!(derived(), 16_384);
    }
    assert_eq!(derived(), 4096);
}

/// The simulated device keeps the trait's reservation defaults: it reports
/// no reservation limits and refuses a reservation command `Unsupported`.
#[test]
fn a_simulated_device_has_no_reservation_commands() {
    let arena = arena();
    let (mut disk, control) = modeled(44);
    assert_eq!(disk.reservation_limits(), None);
    let buffer = arena.acquire(PoolKind::Maintenance).unwrap();
    let memory = buffer.range(4096).unwrap();
    // SAFETY: the test holds `buffer`, forms no view of it, and keeps the arena mapped; a refusal retains nothing. With no reservation limits there is no validated command length, and the device keeps the trait's default, which refuses without reading or writing `memory`.
    let refused = unsafe {
        disk.submit_reservation(
            token(1),
            ReservationCommand::Report { not_before: 0 },
            memory,
        )
    };
    assert_eq!(refused.unwrap_err().reason, RefusalReason::Unsupported);
    assert_eq!(control.outstanding(), 0);
    drop(buffer);
    assert!(arena.release().is_ok());
}

/// Eight ready completions drain into a sink of capacity three in three picks: 3, 3, then 2, with one refused push counted on each pick that left some behind, and none lost.
#[test]
fn a_burst_drains_across_bounded_picks_without_loss() {
    let arena = arena();
    let (mut disk, control) = modeled(4);
    let buffers: Vec<_> = (0..8)
        .map(|_| arena.acquire(PoolKind::ReadResponse).unwrap())
        .collect();
    for (raw, buffer) in buffers.iter().enumerate() {
        submit(
            &mut disk,
            Operation::Read,
            raw as u64,
            block(raw as u64),
            buffer,
        )
        .unwrap();
    }
    control.tick(8);
    let mut seen = Vec::new();
    for (expected, refused) in [(3, 1), (3, 1), (2, 0)] {
        let (done, counted) = pick(&mut disk, 3);
        assert_eq!(
            (done.len(), counted),
            (expected, refused),
            "{}",
            control.describe()
        );
        seen.extend(done.iter().map(|completion| completion.token.raw()));
    }
    seen.sort_unstable();
    assert_eq!(seen, (0..8).collect::<Vec<_>>());
    assert_eq!(control.outstanding(), 0);
    drop(buffers);
    assert!(arena.release().is_ok());
}

fn posted_order(seed: u64) -> (Vec<u64>, Vec<Event>) {
    let arena = arena();
    let (mut disk, control) = modeled(seed);
    let buffers: Vec<_> = (0..6)
        .map(|_| arena.acquire(PoolKind::ReadResponse).unwrap())
        .collect();
    for (raw, buffer) in buffers.iter().enumerate() {
        submit(
            &mut disk,
            Operation::Read,
            raw as u64,
            block(raw as u64),
            buffer,
        )
        .unwrap();
    }
    for _ in 0..6 {
        control.tick(1);
    }
    let order = pick(&mut disk, 8)
        .0
        .iter()
        .map(|completion| completion.token.raw())
        .collect();
    (order, control.events())
}

#[test]
fn runs_replay_by_seed_and_seeds_reorder_completions() {
    for seed in 1..=8 {
        assert_eq!(posted_order(seed), posted_order(seed), "seed {seed}");
    }
    let orders: Vec<_> = (1..=8).map(|seed| posted_order(seed).0).collect();
    assert!(orders.iter().any(|order| *order != orders[0]), "{orders:?}");
    assert!(
        orders.iter().any(|order| *order != [0, 1, 2, 3, 4, 5]),
        "{orders:?}"
    );
}

/// Each fault's bytes and status, against device and host patterns the test wrote.
#[test]
fn each_fault_produces_its_bytes_and_status() {
    const DEVICE: u8 = 0x44;
    const HOST: u8 = 0x99;
    let full = LEN as usize;
    let cases: [(Operation, Fault, DeviceStatus, usize); 6] = [
        (
            Operation::Read,
            Fault::Status(DeviceStatus::Kernel(-19)),
            DeviceStatus::Kernel(-19),
            0,
        ),
        (
            Operation::Read,
            Fault::Short { units: 1 },
            DeviceStatus::Kernel(4096),
            4096,
        ),
        (
            Operation::Write,
            Fault::Short { units: 3 },
            DeviceStatus::Kernel(3 * 4096),
            3 * 4096,
        ),
        (
            Operation::Read,
            Fault::CorruptSuccess,
            DeviceStatus::Kernel(LEN as i32),
            full,
        ),
        (
            Operation::Write,
            Fault::TornWrite { sectors: 3 },
            DeviceStatus::Kernel(-libc::EIO),
            3 * 512,
        ),
        (
            Operation::Read,
            Fault::PartialReadFailure { sectors: 5 },
            DeviceStatus::Kernel(-libc::EIO),
            5 * 512,
        ),
    ];
    for (op, fault, status, moved) in cases {
        let arena = arena();
        let (mut disk, control) = modeled(5);
        control.write_device(0, &[DEVICE; LEN as usize]);
        let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
        control.write_host(buffer.offset(), &[HOST; LEN as usize]);
        submit(&mut disk, op, 1, block(0), &buffer).unwrap();
        control.fault(token(1), fault);
        control.tick(1);
        let (done, _) = pick(&mut disk, 1);
        assert_eq!(
            done,
            [Completion {
                token: token(1),
                status
            }],
            "{fault:?}"
        );
        let (changed, from, to) = match op {
            Operation::Read => (control.host(buffer.offset(), full), DEVICE, HOST),
            Operation::Write => (control.device(0, full), HOST, DEVICE),
        };
        let written = if fault == Fault::CorruptSuccess {
            from ^ 0x5A
        } else {
            from
        };
        assert!(
            changed[..moved].iter().all(|byte| *byte == written),
            "{fault:?}"
        );
        assert!(changed[moved..].iter().all(|byte| *byte == to), "{fault:?}");
        drop(buffer);
        assert!(arena.release().is_ok());
    }
}

/// A short fault that moves less than its command reports the moved byte
/// count as a kernel result in either status form, and that result
/// classifies `Short`.
#[test]
fn a_short_fault_reports_a_kernel_count_in_either_form() {
    for form in [StatusForm::Kernel, StatusForm::Nvme] {
        let arena = arena();
        let (mut disk, control) = sim(SimConfig {
            form,
            ..config(
                45,
                Mode::Modeled {
                    backing_len: TWO_MIB,
                },
            )
        });
        let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
        submit(&mut disk, Operation::Read, 1, block(0), &buffer).unwrap();
        control.fault(token(1), Fault::Short { units: 1 });
        control.tick(1);
        let (done, _) = pick(&mut disk, 1);
        assert_eq!(
            done,
            [Completion {
                token: token(1),
                status: DeviceStatus::Kernel(IO_UNIT as i32)
            }],
            "{form:?}"
        );
        assert_eq!(
            done[0].status.classify(LEN),
            Classification::Short {
                transferred: IO_UNIT as u32
            },
            "{form:?}"
        );
        drop(buffer);
        assert!(arena.release().is_ok());
    }
}

/// A scripted Command Abort Requested status reaches the caller as the
/// device wrote it, and the device accepts and completes the next command.
#[test]
fn an_abort_status_reaches_the_caller_and_the_device_keeps_serving() {
    let arena = arena();
    let (mut disk, control) = sim(SimConfig {
        form: StatusForm::Nvme,
        ..config(
            46,
            Mode::Modeled {
                backing_len: TWO_MIB,
            },
        )
    });
    let abort = DeviceStatus::Nvme(0x07 << 1);
    assert_eq!(
        ControllerEvent::of_status(abort),
        Some(ControllerEvent::Abort)
    );
    let a = arena.acquire(PoolKind::ReadResponse).unwrap();
    let b = arena.acquire(PoolKind::ReadResponse).unwrap();
    submit(&mut disk, Operation::Read, 1, block(0), &a).unwrap();
    control.fault(token(1), Fault::Status(abort));
    control.tick(1);
    assert_eq!(
        pick(&mut disk, 1).0,
        [Completion {
            token: token(1),
            status: abort
        }]
    );
    submit(&mut disk, Operation::Read, 2, block(1), &b).unwrap();
    control.tick(1);
    assert_eq!(
        pick(&mut disk, 1).0,
        [Completion {
            token: token(2),
            status: DeviceStatus::Nvme(0x0001)
        }]
    );
    drop((a, b));
    assert!(arena.release().is_ok());
}

/// Dropping a command never posts another in its place: with a second command already executed behind it, posting the dropped one posts nothing, and the second still posts once, as itself.
#[test]
fn posting_a_dropped_command_posts_no_other_command() {
    let arena = arena();
    let (mut disk, control) = modeled(12);
    let a = arena.acquire(PoolKind::ReadResponse).unwrap();
    let b = arena.acquire(PoolKind::ReadResponse).unwrap();
    submit(&mut disk, Operation::Read, 1, block(0), &a).unwrap();
    submit(&mut disk, Operation::Read, 2, block(1), &b).unwrap();
    control.execute(token(2));
    control.fault(token(1), Fault::DropCommand);
    control.post(token(1));
    assert_eq!(pick(&mut disk, 4).0, [], "{}", control.describe());
    control.post(token(2));
    let done = pick(&mut disk, 4).0;
    assert_eq!(done.iter().map(|c| c.token).collect::<Vec<_>>(), [token(2)]);
    stop(&mut disk, &control);
    drop((a, b));
    assert!(arena.release().is_ok());
}

/// A dropped command moves nothing and never completes; a dropped completion moves every byte and never completes.
#[test]
fn dropped_commands_and_dropped_completions_never_report() {
    let arena = arena();
    let (mut disk, control) = modeled(6);
    let lost = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let moved = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    control.write_host(lost.offset(), &[1; LEN as usize]);
    control.write_host(moved.offset(), &[2; LEN as usize]);
    submit(&mut disk, Operation::Write, 1, block(0), &lost).unwrap();
    submit(&mut disk, Operation::Write, 2, block(1), &moved).unwrap();
    control.fault(token(1), Fault::DropCommand);
    control.fault(token(2), Fault::DropCompletion);
    for _ in 0..4 {
        control.tick(2);
    }
    assert_eq!(pick(&mut disk, 4).0, [], "{}", control.describe());
    assert_eq!(control.device(0, LEN as usize), vec![0; LEN as usize]);
    assert_eq!(
        control.device(LEN as usize, LEN as usize),
        vec![2; LEN as usize]
    );
    assert!(!executed(&control, 1));
    assert_eq!(control.outstanding(), 0);
    stop(&mut disk, &control);
    drop((lost, moved));
    assert!(arena.release().is_ok());
}

#[test]
fn a_halted_device_executes_nothing_until_resumed_and_a_held_command_waits() {
    let arena = arena();
    let (mut disk, control) = modeled(7);
    let a = arena.acquire(PoolKind::ReadResponse).unwrap();
    let b = arena.acquire(PoolKind::ReadResponse).unwrap();
    submit(&mut disk, Operation::Read, 1, block(0), &a).unwrap();
    submit(&mut disk, Operation::Read, 2, block(1), &b).unwrap();
    control.set_halted(true);
    control.tick(4);
    assert!(!executed(&control, 1) && !executed(&control, 2));
    control.set_halted(false);
    control.hold(token(1));
    control.tick(4);
    assert_eq!(
        pick(&mut disk, 4)
            .0
            .iter()
            .map(|c| c.token.raw())
            .collect::<Vec<_>>(),
        [2]
    );
    control.release(token(1));
    control.tick(4);
    assert_eq!(
        pick(&mut disk, 4)
            .0
            .iter()
            .map(|c| c.token.raw())
            .collect::<Vec<_>>(),
        [1]
    );
    drop((a, b));
    assert!(arena.release().is_ok());
}

#[test]
fn a_gone_device_refuses_submits_and_keeps_accepted_commands() {
    let arena = arena();
    let (mut disk, control) = modeled(8);
    let a = arena.acquire(PoolKind::ReadResponse).unwrap();
    let b = arena.acquire(PoolKind::ReadResponse).unwrap();
    submit(&mut disk, Operation::Read, 1, block(0), &a).unwrap();
    control.set_gone();
    assert_eq!(
        submit(&mut disk, Operation::Read, 2, block(1), &b),
        Err(SubmitRefusal {
            reason: RefusalReason::DeviceGone,
            code: None
        })
    );
    assert_eq!(control.outstanding(), 1);
    control.tick(1);
    assert_eq!(pick(&mut disk, 2).0.len(), 1);
    drop((a, b));
    assert!(arena.release().is_ok());
}

/// Only reset proves `Stopped`: it drops every outstanding command, and later submits are refused; the hostile `FalseStopped` reports `Stopped` while its commands keep executing and posting. The `AllReturned` case runs on the mode the device starts in, so it shows that the construction mode answers `Pending` while commands keep completing.
#[test]
fn quiesce_reports_stopped_only_after_a_reset() {
    for mode in [
        QuiesceMode::AllReturned,
        QuiesceMode::Unproven,
        QuiesceMode::Failed(Some(7)),
        QuiesceMode::Reset,
        QuiesceMode::FalseStopped,
    ] {
        let arena = arena();
        let (mut disk, control) = modeled(9);
        let a = arena.acquire(PoolKind::ReadResponse).unwrap();
        let b = arena.acquire(PoolKind::ReadResponse).unwrap();
        control.write_device(LEN as usize, &[0xBB; LEN as usize]);
        submit(&mut disk, Operation::Read, 1, block(0), &a).unwrap();
        submit(&mut disk, Operation::Read, 2, block(1), &b).unwrap();
        if !matches!(mode, QuiesceMode::AllReturned) {
            control.set_quiesce(mode);
        }
        control.post(token(1));
        let status = disk.quiesce();
        control.tick(4);
        let (done, _) = pick(&mut disk, 4);
        match mode {
            QuiesceMode::AllReturned => {
                assert_eq!(status, QuiesceStatus::Pending);
                assert_eq!(done.len(), 2);
            }
            QuiesceMode::Unproven => {
                assert_eq!(status, QuiesceStatus::Pending);
                assert_eq!(done.len(), 1, "{}", control.describe());
                assert_eq!(control.outstanding(), 1);
            }
            QuiesceMode::Failed(code) => {
                assert_eq!(status, QuiesceStatus::Failed(code));
                assert_eq!(done.len(), 2);
            }
            QuiesceMode::Reset => {
                assert_eq!(status, QuiesceStatus::Stopped);
                assert_eq!(done, []);
                assert_eq!(control.outstanding(), 0);
                assert!(control.events().contains(&Event::Stopped));
                let c = arena.acquire(PoolKind::ReadResponse).unwrap();
                assert_eq!(
                    submit(&mut disk, Operation::Read, 3, block(2), &c)
                        .unwrap_err()
                        .reason,
                    RefusalReason::DeviceGone
                );
            }
            QuiesceMode::FalseStopped => {
                // The hostile stop returns while command 2 is still pending; its access after the return lands in the host shadow of `b`.
                assert_eq!(status, QuiesceStatus::Stopped);
                assert_eq!(done.len(), 2);
                let events = control.events();
                let stopped = events.iter().position(|e| *e == Event::FalseStopped);
                let late = events.iter().position(|e| {
                    *e == Event::Executed {
                        token: token(2),
                        offset: b.offset(),
                        len: LEN as usize,
                    }
                });
                assert!(stopped.is_some() && late.is_some());
                assert_eq!(control.host(b.offset(), LEN as usize), [0xBB; LEN as usize]);
                assert!(stopped < late, "{}", control.describe());
                assert!(!events.contains(&Event::Stopped));
            }
        }
        stop(&mut disk, &control);
        drop((a, b));
        assert!(arena.release().is_ok());
    }
}

/// Reuse of a buffer before its read completed, detected through the modeled host shadow.
/// The second request writes its own bytes into what it believes is its buffer; the first command's read then lands on it.
fn second_request_sees_its_bytes(early_drop: bool, overlap: bool, seed: u64) -> bool {
    let arena = arena();
    let (mut disk, control) = modeled(seed);
    control.write_device(0, &[0xAA; LEN as usize]);
    let first = arena.acquire(PoolKind::ReadResponse).unwrap();
    let memory = first.range(LEN).unwrap();
    // SAFETY: the early-drop case breaks the caller contract on purpose, returning the buffer before the completion.
    // The device is modeled, so it never reads or writes the buffer's memory, and the breach shows only in the shadow the test inspects.
    unsafe { disk.submit_read(token(1), block(0), memory) }.unwrap();
    control.hold(token(1));
    let held = if early_drop {
        // The broken policy returns the buffer right after submitting, before the completion.
        drop(first);
        None
    } else {
        Some(first)
    };
    if !overlap {
        control.release(token(1));
        control.tick(1);
        assert_eq!(pick(&mut disk, 1).0.len(), 1);
    }
    let second = arena.acquire(PoolKind::ReadResponse).unwrap();
    control.write_host(second.offset(), &[0xBB; LEN as usize]);
    if overlap {
        // The forced schedule: the held read executes and posts only after the second request wrote its bytes.
        control.post(token(1));
        assert_eq!(pick(&mut disk, 1).0.len(), 1, "{}", control.describe());
    }
    let intact = control.host(second.offset(), LEN as usize) == vec![0xBB; LEN as usize];
    drop((held, second));
    assert!(arena.release().is_ok());
    intact
}

#[test]
fn early_reuse_is_reported_as_corruption_only_when_it_overlaps_the_command() {
    assert!(!second_request_sees_its_bytes(true, true, 10));
    assert!(second_request_sees_its_bytes(true, false, 10));
    assert!(second_request_sees_its_bytes(false, true, 10));
}

/// A kernel result is an `i32`, so a kernel-form device refuses a transfer limit above `i32::MAX` at construction instead of wrapping a completed transfer into a failure.
#[test]
#[should_panic(expected = "kernel result")]
fn a_kernel_form_device_refuses_a_transfer_limit_it_cannot_report() {
    let _ = sim(SimConfig {
        max_transfer: 1 << 31,
        ..config(3, Mode::Direct)
    });
}

/// Admission bounds every transfer by the capacity as well as the transfer limit, so the misdirection scratch holds the smaller of the two.
#[test]
fn the_misdirection_scratch_is_bounded_by_the_capacity_under_a_larger_transfer_limit() {
    let (_disk, control) = sim(SimConfig {
        capacity: 4096,
        max_transfer: u32::MAX,
        form: StatusForm::Nvme,
        ..config(5, Mode::Direct)
    });
    assert_eq!(control.footprint().reserved.scratch, 4096);
}

/// A modeled device checks a range against its shadow backing at submit, so a shadow shorter than the arena fails on the submit that names the range instead of on whichever tick executes it.
#[test]
#[should_panic(expected = "shadow backing")]
fn a_modeled_device_refuses_a_range_past_its_shadow_at_submit() {
    let arena = arena();
    let (mut disk, _control) = sim(config(4, Mode::Modeled { backing_len: 4096 }));
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let _ = submit(&mut disk, Operation::Read, 1, block(0), &buffer);
}

/// Tokens of `completions`, in delivery order.
fn tokens(completions: &[Completion]) -> Vec<u64> {
    completions
        .iter()
        .map(|completion| completion.token.raw())
        .collect()
}

/// Submits `raw` as a read of block `raw % 8` into `buffer`.
fn read(disk: &mut SimDisk, raw: u64, buffer: &Buffer<'_>) {
    submit(disk, Operation::Read, raw, block(raw % 8), buffer).unwrap();
}

fn raws(list: Vec<CommandToken>) -> Vec<u64> {
    list.into_iter().map(CommandToken::raw).collect()
}

/// The simulator's refusal of a `kind` input for `reason`.
pub(super) fn harness<T>(kind: ScriptKind, reason: ScriptReason) -> Result<T, ScriptRefusal> {
    Err(ScriptRefusal { kind, reason })
}

/// A run of more than 409,600 driver and control calls, 224,000 accepted
/// commands, keeps every store at the capacity it was built with,
/// device records within the queue depth and injected ones within their
/// capacity, while each cycle submits, holds, faults, refuses, injects and
/// delivers; a window of cycles allocates nothing. Accepted commands equal
/// delivered ones plus the ones dropped completions lost.
#[test]
fn metadata_stays_within_the_depth_and_the_script_across_a_long_run() {
    const CYCLES: u64 = 28_000;
    let arena = arena();
    let (mut disk, control) = modeled(31);
    let reserved = control.footprint().reserved;
    let buffers: Vec<_> = (0..8)
        .map(|_| arena.acquire(PoolKind::ReadResponse).unwrap())
        .collect();
    let mut out = Vec::with_capacity(16);
    let (mut raw, mut lost, mut injected, mut calls) = (1u64 << 20, 0, 0, 0);
    let refusal = SubmitRefusal {
        reason: RefusalReason::QueueFull,
        code: None,
    };
    let mut allocated = 0;
    for cycle in 0..CYCLES {
        let before = crate::instrument::allocations();
        for buffer in &buffers {
            read(&mut disk, raw, buffer);
            raw += 1;
        }
        let last = token(raw - 1);
        control.hold(last);
        control.fault(token(raw - 2), Fault::Short { units: 1 });
        calls += 10;
        if cycle % 3 == 0 {
            control.fault(token(raw - 3), Fault::DropCompletion);
            lost += 1;
            calls += 1;
        }
        control.tick(8);
        control.release(last);
        control.tick(8);
        control.inject(
            Completion {
                token: token(raw - 4),
                status: DeviceStatus::Kernel(LEN as i32),
            },
            Injection::Duplicate,
        );
        injected += 1;
        out.clear();
        disk.pick_completions(&mut CompletionSink::new(&mut out, 16));
        calls += 4;
        assert_eq!(
            out.len(),
            if cycle % 3 == 0 { 8 } else { 9 },
            "{}",
            control.describe()
        );
        if cycle % 5 == 0 {
            control.refuse_next(refusal);
            assert!(submit(&mut disk, Operation::Read, raw, block(0), &buffers[0]).is_err());
            calls += 2;
        }
        if cycle >= CYCLES / 2 {
            allocated += crate::instrument::allocations() - before;
        }
    }
    assert!(calls > 409_600, "{calls} calls");
    assert_eq!(allocated, 0, "the cycles allocate nothing");
    let footprint = control.footprint();
    assert_eq!(footprint.reserved, reserved, "no store grew");
    assert_eq!(
        (
            footprint.pending,
            footprint.device,
            footprint.injections,
            footprint.refusals
        ),
        (8, 8, 1, 1),
        "{footprint:?}"
    );
    assert_eq!(footprint.posted, 8 + 1, "{footprint:?}");
    let accepted = control.accepted(Operation::Read);
    assert_eq!(accepted as u64, 8 * CYCLES);
    assert_eq!(control.delivered(Operation::Read) + lost, accepted);
    assert_eq!(control.delivered_injections(), injected);
    assert_eq!(control.refused(Origin::Script) as u64, CYCLES.div_ceil(5));
    assert_eq!(control.refused(Origin::Model), 0);
    assert_eq!(control.outstanding(), 0);
    drop(buffers);
    assert!(arena.release().is_ok());
}

/// Scripted input past its capacity, or naming a command that cannot carry
/// it, is refused with its kind and a typed reason and changes nothing: the
/// footprint, the event ring, the queue and the earlier fault stay as they
/// were.
#[test]
fn excess_or_misdirected_scripted_input_is_refused_by_kind_and_reason() {
    let arena = arena();
    let (mut disk, control) = modeled(32);
    control.write_device(LEN as usize, &[0x11; LEN as usize]);
    control.write_device(2 * LEN as usize, &[0x22; LEN as usize]);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let other = arena.acquire(PoolKind::ReadResponse).unwrap();
    read(&mut disk, 1, &buffer);
    read(&mut disk, 2, &other);
    let refusal = SubmitRefusal {
        reason: RefusalReason::QueueFull,
        code: None,
    };
    for _ in 0..SCRIPT.refusals {
        control.try_refuse_next(refusal).unwrap();
    }
    let completion = |raw| Completion {
        token: token(raw),
        status: DeviceStatus::Kernel(LEN as i32),
    };
    for raw in 0..u64::from(SCRIPT.injections) {
        control
            .try_inject(completion(100 + raw), Injection::Foreign)
            .unwrap();
    }
    control.try_fault(token(1), Fault::CorruptSuccess).unwrap();
    assert_eq!(control.select(Stage::Execute, 1).unwrap().token, token(2));
    let before = (control.footprint(), control.events(), control.outstanding());
    let full = |capacity| ScriptReason::Full { capacity };
    assert_eq!(
        control.try_refuse_next(refusal),
        harness(ScriptKind::Refusal, full(SCRIPT.refusals))
    );
    assert_eq!(
        control.try_inject(completion(200), Injection::Foreign),
        harness(ScriptKind::Injection, full(SCRIPT.injections))
    );
    assert_eq!(
        control.try_inject(completion(1), Injection::Duplicate),
        harness(ScriptKind::Injection, ScriptReason::Pending(token(1)))
    );
    assert_eq!(
        control.try_hold(token(7)),
        harness(ScriptKind::Hold, ScriptReason::NotPending(token(7)))
    );
    assert_eq!(
        control.try_fault(token(7), Fault::CorruptSuccess),
        harness(ScriptKind::Fault, ScriptReason::NotPending(token(7)))
    );
    assert_eq!(
        control.try_fault(token(1), Fault::DropCommand),
        harness(ScriptKind::Fault, ScriptReason::Faulted(token(1)))
    );
    assert_eq!(
        control.try_fault(token(2), Fault::DropCommand),
        harness(ScriptKind::Fault, ScriptReason::Executed(token(2)))
    );
    for (stage, index, ready) in [
        (Stage::Execute, 1, 1),
        (Stage::Post, 2, 2),
        (Stage::Admit, 0, 0),
    ] {
        assert_eq!(
            control.select(stage, index),
            harness(
                ScriptKind::Selection(stage),
                ScriptReason::Selection { index, ready }
            )
        );
    }
    assert_eq!(
        (control.footprint(), control.events(), control.outstanding()),
        before,
        "a refused input changes nothing"
    );
    control.post(token(1));
    control.post(token(2));
    let done = pick(&mut disk, 16).0;
    assert!(
        done.contains(&completion(1)) && done.contains(&completion(2)),
        "{done:?}"
    );
    assert_eq!(
        control.host(buffer.offset(), 4),
        [0x11 ^ 0x5A; 4],
        "the first fault applied"
    );
    assert_eq!(
        control.host(other.offset(), 4),
        [0x22; 4],
        "no fault reached the second read"
    );
    drop((buffer, other));
    assert!(arena.release().is_ok());
}

/// A profile that declares no injection refuses every one, so a healthy run
/// credits no duplicate callback.
#[test]
fn a_device_declaring_no_injection_refuses_every_one() {
    let (_disk, control) = sim(SimConfig {
        script: ScriptCapacity {
            refusals: 0,
            injections: 0,
            damage: 0,
        },
        ..config(38, Mode::Direct)
    });
    let completion = Completion {
        token: token(1),
        status: DeviceStatus::Kernel(LEN as i32),
    };
    assert_eq!(
        control.try_inject(completion, Injection::Duplicate),
        harness(ScriptKind::Injection, ScriptReason::Full { capacity: 0 })
    );
    assert_eq!(
        control.try_refuse_next(SubmitRefusal {
            reason: RefusalReason::QueueFull,
            code: None,
        }),
        harness(ScriptKind::Refusal, ScriptReason::Full { capacity: 0 })
    );
}

/// A submit refusal names its origin, and the device counts each origin over
/// its life: the device model for a bad range, a full queue and a gone
/// device, the script for a scripted refusal. An injected completion holds
/// its own capacity, so it never fills the queue.
#[test]
fn submit_refusals_carry_their_origin_and_injections_hold_no_queue_room() {
    let arena = arena();
    let (mut disk, control) = sim(SimConfig {
        queue_depth: 1,
        ..config(33, Mode::Direct)
    });
    let a = arena.acquire(PoolKind::ReadResponse).unwrap();
    let b = arena.acquire(PoolKind::ReadResponse).unwrap();
    let past = DeviceRange::new(1 << 20, LEN).unwrap();
    assert!(submit(&mut disk, Operation::Read, 1, past, &a).is_err());
    control.refuse_next(SubmitRefusal {
        reason: RefusalReason::QueueFull,
        code: Some(7),
    });
    assert!(submit(&mut disk, Operation::Read, 2, block(0), &a).is_err());
    control.inject(
        Completion {
            token: token(9),
            status: DeviceStatus::Kernel(LEN as i32),
        },
        Injection::Foreign,
    );
    assert!(submit(&mut disk, Operation::Read, 3, block(0), &a).is_ok());
    assert!(submit(&mut disk, Operation::Read, 4, block(1), &b).is_err());
    control.set_gone();
    assert!(submit(&mut disk, Operation::Read, 5, block(1), &b).is_err());
    let refusals: Vec<_> = control
        .events()
        .into_iter()
        .filter_map(|event| match event {
            Event::Refused {
                token,
                reason,
                origin,
            } => Some((token.raw(), reason, origin)),
            _ => None,
        })
        .collect();
    assert_eq!(
        refusals,
        [
            (1, RefusalReason::InvalidRange, Origin::Model),
            (2, RefusalReason::QueueFull, Origin::Script),
            (4, RefusalReason::QueueFull, Origin::Model),
            (5, RefusalReason::DeviceGone, Origin::Model),
        ]
    );
    assert_eq!(
        (
            control.refused(Origin::Model),
            control.refused(Origin::Script)
        ),
        (3, 1)
    );
    control.tick(1);
    assert_eq!(tokens(&pick(&mut disk, 2).0), [9, 3]);
    drop((a, b));
    assert!(arena.release().is_ok());
}

/// Each stage's ready set is in acceptance order, and its candidates are
/// canonical choice descriptors that depend on the accepted commands, not on
/// their tokens; a chooser's draw over them selects the entry it names. An
/// execute selection moves one command's bytes and posts nothing, a post
/// selection posts one completion behind a closed gate, and a pick delivers
/// only completions whose gate an admission opened, in posted order, keeping
/// a refused push in place. Held and halted commands are not ready, and a
/// selection a fault loses reports it.
#[test]
fn selections_follow_the_canonical_ready_set_and_the_delivery_gate() {
    let arena = arena();
    let (mut disk, control) = modeled(34);
    let buffers: Vec<_> = (0..5)
        .map(|_| arena.acquire(PoolKind::ReadResponse).unwrap())
        .collect();
    for (raw, buffer) in [9, 2, 5, 7, 3].into_iter().zip(&buffers) {
        read(&mut disk, raw, buffer);
    }
    assert_eq!(raws(control.ready(Stage::Execute)), [9, 2, 5, 7, 3]);
    let candidates = control.candidates(Stage::Execute);
    assert!(candidates.windows(2).all(|pair| pair[0] < pair[1]));
    let (mut twin, twin_control) = modeled(34);
    for (raw, buffer) in [19, 12, 15, 17, 13].into_iter().zip(&buffers) {
        submit(&mut twin, Operation::Read, raw, block(raw % 10 % 8), buffer).unwrap();
    }
    assert_eq!(
        twin_control.candidates(Stage::Execute),
        candidates,
        "the descriptors name the accepted commands, not their tokens"
    );
    assert_eq!(
        twin_control.candidates(Stage::Post),
        control.candidates(Stage::Post)
    );
    stop(&mut twin, &twin_control);
    let site = Site {
        domain: Domain::Disk,
        actor: 1,
        site: 1,
    };
    let mut chooser = Chooser::record(5, &[site]);
    let incarnation = chooser.launch(1);
    let drawn = chooser.index(site, incarnation, &candidates).unwrap();
    let mut replayer = Chooser::replay(&[site], chooser.finish().unwrap());
    let incarnation = replayer.launch(1);
    assert_eq!(replayer.index(site, incarnation, &candidates), Ok(drawn));
    let named = control.ready(Stage::Execute)[drawn];
    assert_eq!(control.select(Stage::Execute, drawn).unwrap().token, named);
    let rest: Vec<u64> = [9, 2, 5, 7, 3]
        .into_iter()
        .filter(|raw| *raw != named.raw())
        .collect();
    assert_eq!(raws(control.ready(Stage::Execute)), rest);
    stop(&mut disk, &control);

    let (mut disk, control) = modeled(42);
    for (raw, buffer) in [9, 2, 5, 7, 3].into_iter().zip(&buffers) {
        read(&mut disk, raw, buffer);
    }
    control.fault(token(3), Fault::DropCommand);
    let lost = control.select(Stage::Execute, 4).unwrap();
    assert_eq!((lost.token, lost.effect), (token(3), Effect::Lost));
    control.hold(token(7));
    let moved = control.select(Stage::Execute, 2).unwrap();
    assert_eq!((moved.token, moved.effect), (token(5), Effect::Executed));
    assert!(executed(&control, 5) && !executed(&control, 2));
    assert_eq!(raws(control.ready(Stage::Execute)), [9, 2]);
    assert_eq!(raws(control.ready(Stage::Post)), [9, 2, 5]);
    for index in [2, 1, 0] {
        assert_eq!(
            control.select(Stage::Post, index).unwrap().effect,
            Effect::Posted
        );
    }
    let held: Vec<_> = control
        .held()
        .iter()
        .map(|entry| (entry.token.raw(), entry.posted))
        .collect();
    assert_eq!(
        held,
        [(9, true), (2, true), (5, true), (7, false)],
        "the held list keeps acceptance order across posted and pending commands"
    );
    assert_eq!(pick(&mut disk, 4).0, [], "every gate is closed");
    assert_eq!(raws(control.ready(Stage::Admit)), [9, 2, 5]);
    assert_eq!(control.select(Stage::Admit, 1).unwrap().token, token(2));
    assert_eq!(control.select(Stage::Admit, 1).unwrap().token, token(5));
    let (done, refused) = pick(&mut disk, 1);
    assert_eq!(
        (tokens(&done), refused),
        (vec![5], 1),
        "posted order: 5 before 2"
    );
    assert_eq!(tokens(&pick(&mut disk, 4).0), [2]);
    assert_eq!(raws(control.ready(Stage::Admit)), [9]);
    control.set_halted(true);
    control.release(token(7));
    assert_eq!(control.ready(Stage::Post), []);
    assert_eq!(
        raws(control.ready(Stage::Admit)),
        [9],
        "admission touches no device"
    );
    control.set_halted(false);
    control.fault(token(7), Fault::DropCompletion);
    let dropped = control.select(Stage::Post, 0).unwrap();
    assert_eq!((dropped.token, dropped.effect), (token(7), Effect::Lost));
    assert!(control.events().contains(&Event::Lost(token(7))));
    control.select(Stage::Admit, 0).unwrap();
    assert_eq!(tokens(&pick(&mut disk, 4).0), [9]);
    stop(&mut disk, &control);
    drop(buffers);
    assert!(arena.release().is_ok());
}

/// A scripted hold, fault or injection on one command leaves another
/// command's bytes, status and delivery as an unscripted run gives them, and
/// those bytes are the block's.
#[test]
fn scripted_inputs_leave_other_commands_as_an_unscripted_run_leaves_them() {
    const PATTERN: u8 = 0x77;
    let run = |scripted: bool| {
        let arena = arena();
        let (mut disk, control) = modeled(35);
        control.write_device(2 * LEN as usize, &[PATTERN; LEN as usize]);
        let a = arena.acquire(PoolKind::ReadResponse).unwrap();
        let b = arena.acquire(PoolKind::ReadResponse).unwrap();
        read(&mut disk, 1, &a);
        read(&mut disk, 2, &b);
        if scripted {
            control.hold(token(1));
            control.fault(token(1), Fault::Status(DeviceStatus::Kernel(-5)));
            control.inject(
                Completion {
                    token: token(3),
                    status: DeviceStatus::Kernel(LEN as i32),
                },
                Injection::Foreign,
            );
        }
        let at = control
            .ready(Stage::Post)
            .iter()
            .position(|ready| *ready == token(2))
            .unwrap();
        control.select(Stage::Post, at).unwrap();
        control.select(Stage::Admit, 0).unwrap();
        let done: Vec<Completion> = pick(&mut disk, 4)
            .0
            .into_iter()
            .filter(|completion| completion.token == token(2))
            .collect();
        let bytes = control.host(b.offset(), LEN as usize);
        stop(&mut disk, &control);
        drop((a, b));
        assert!(arena.release().is_ok());
        (done, bytes)
    };
    let (done, bytes) = run(false);
    assert_eq!(
        done,
        [Completion {
            token: token(2),
            status: DeviceStatus::Kernel(LEN as i32)
        }]
    );
    assert_eq!(bytes, vec![PATTERN; LEN as usize]);
    assert_eq!(run(true), (done, bytes));
}

/// A reset ends every pending, gated and injected record and delivers
/// nothing afterwards; the gone device refuses later injections.
#[test]
fn a_reset_ends_gated_and_injected_records_and_refuses_later_injections() {
    let arena = arena();
    let (mut disk, control) = modeled(39);
    let a = arena.acquire(PoolKind::ReadResponse).unwrap();
    let b = arena.acquire(PoolKind::ReadResponse).unwrap();
    read(&mut disk, 1, &a);
    read(&mut disk, 2, &b);
    control.select(Stage::Post, 0).unwrap();
    for raw in 0..u64::from(SCRIPT.injections) {
        control.inject(
            Completion {
                token: token(100 + raw),
                status: DeviceStatus::Kernel(LEN as i32),
            },
            Injection::Foreign,
        );
    }
    stop(&mut disk, &control);
    assert_eq!(control.ready(Stage::Admit), []);
    assert_eq!(pick(&mut disk, 16).0, []);
    assert_eq!(
        control.outstanding(),
        0,
        "no gated or injected record survives"
    );
    assert_eq!(
        control.try_inject(
            Completion {
                token: token(200),
                status: DeviceStatus::Kernel(LEN as i32),
            },
            Injection::Foreign,
        ),
        harness(ScriptKind::Injection, ScriptReason::Gone),
        "a gone device posts nothing more"
    );
    drop((a, b));
    assert!(arena.release().is_ok());
}

/// A submit naming a token the device still holds pending breaks the `Disk`
/// precondition, and the simulator panics naming the token and the event
/// ring.
#[test]
#[should_panic(expected = "is outstanding")]
fn a_submit_reusing_a_pending_token_breaks_the_precondition() {
    let arena = arena();
    let (mut disk, _control) = modeled(36);
    let a = arena.acquire(PoolKind::ReadResponse).unwrap();
    let b = arena.acquire(PoolKind::ReadResponse).unwrap();
    read(&mut disk, 1, &a);
    let _ = submit(&mut disk, Operation::Read, 1, block(2), &b);
}

/// A token whose completion is posted and not yet picked is still
/// outstanding, so reusing it breaks the precondition too.
#[test]
#[should_panic(expected = "breaks the Disk precondition")]
fn a_submit_reusing_a_posted_token_breaks_the_precondition() {
    let arena = arena();
    let (mut disk, control) = modeled(40);
    let a = arena.acquire(PoolKind::ReadResponse).unwrap();
    let b = arena.acquire(PoolKind::ReadResponse).unwrap();
    read(&mut disk, 1, &a);
    control.post(token(1));
    let _ = submit(&mut disk, Operation::Read, 1, block(2), &b);
}

/// A token an injected completion names stays outstanding while the
/// injection is posted, so submitting it breaks the precondition.
#[test]
#[should_panic(expected = "breaks the Disk precondition")]
fn a_submit_reusing_an_injected_token_breaks_the_precondition() {
    let arena = arena();
    let (mut disk, control) = modeled(43);
    let a = arena.acquire(PoolKind::ReadResponse).unwrap();
    control.inject(
        Completion {
            token: token(1),
            status: DeviceStatus::Kernel(LEN as i32),
        },
        Injection::Foreign,
    );
    let _ = submit(&mut disk, Operation::Read, 1, block(0), &a);
}

/// A length that is no multiple of the device's block breaks the
/// precondition.
#[test]
#[should_panic(expected = "no multiple of the 4096-byte block")]
fn a_submit_of_a_partial_block_breaks_the_precondition() {
    let arena = arena();
    let (mut disk, control) = modeled(41);
    control.set_block_size(4096);
    let a = arena.acquire(PoolKind::ReadResponse).unwrap();
    let _ = submit(
        &mut disk,
        Operation::Read,
        1,
        DeviceRange::new(0, 512).unwrap(),
        &a,
    );
}

/// The simulated device meets the shared `Disk` contract the SPDK driver's
/// hardware row also runs.
#[test]
fn the_simulated_device_meets_the_disk_contract() {
    meets_the_disk_contract(sim(config(37, Mode::Direct)));
}

/// The device the shared volume fixture's attach path builds meets the
/// contract: attach facts, 512-byte sectors, 4 MiB and the fixture's own
/// transfer limit.
#[test]
fn the_shared_fixture_device_meets_the_disk_contract() {
    meets_the_disk_contract(device_with(7, BUFFER));
}

/// A device that reports NVMe status words meets the contract, which reads
/// every status through `classify`.
#[test]
fn an_nvme_form_device_meets_the_disk_contract() {
    meets_the_disk_contract(sim(SimConfig {
        form: StatusForm::Nvme,
        ..config(37, Mode::Direct)
    }));
}

/// Runs the shared contract over the given device under
/// `QuiesceMode::Reset`, the simulated device's one quiesce mode that proves
/// a stop, as the SPDK driver's disable proof does, with the device moving
/// between picks.
fn meets_the_disk_contract((mut disk, control): (SimDisk, SimControl)) {
    let arena = arena();
    control.set_quiesce(QuiesceMode::Reset);
    // SAFETY: the simulated device reaches the buffers only on this thread inside driver and control calls, so an unwind leaves no access in flight.
    unsafe {
        super::disk_contract::meets_the_disk_contract(&mut disk, &arena, Duration::ZERO, || {
            control.tick(u32::MAX);
        });
    }
    assert!(arena.release().is_ok());
}

/// When the planted store of a [`LateStore`] lands.
#[derive(Clone, Copy)]
enum Late {
    /// The store lands after the pick that reports the target's completion.
    AtCompletion,
    /// The store lands after the first pick that starts with at least this
    /// many completions already reported.
    After(usize),
    /// The target's first byte becomes visible at the pick after the one
    /// that reports its completion: the reporting pick puts back the byte
    /// the memory held at submit, and the next pick stores the delivered byte.
    Landing,
    /// The store lands at the first quiesce call after the pick that reports
    /// the target's completion.
    AtStop,
    /// The store lands at byte `IO_UNIT` of the target's memory, past the
    /// range the target named, after the pick that reports its completion.
    PastRange,
    /// After the first pick that starts with at least this many completions
    /// already reported, the device reads the target's source again and
    /// stores it at the target's block; the target is a write.
    SourceRead(usize),
}

/// `LateStore` wraps the simulated device and injects one late access into
/// `target`'s memory at the point `late` selects: a store of `0xEE`, of the
/// command's own byte under [`Late::Landing`], or a read of the source
/// under [`Late::SourceRead`].
struct LateStore {
    disk: SimDisk,
    control: SimControl,
    /// When set, a command submitted between picks completes at the next pick.
    at_pick: bool,
    target: CommandToken,
    late: Late,
    memory: Option<super::DmaRange>,
    /// The target's first byte as its submit found it.
    before: u8,
    landed: Option<u8>,
    completions: usize,
    reported: bool,
    stored: bool,
}

impl LateStore {
    fn memory(&self) -> *mut u8 {
        self.memory
            .expect("the target was submitted")
            .addr()
            .as_ptr()
    }

    fn store(&mut self, byte: u8) {
        self.store_at(0, byte);
    }

    fn store_at(&mut self, offset: usize, byte: u8) {
        // SAFETY: the range lies in the arena `late_store_contract` declares before `self`, so it outlives this store; `offset` is 0 or, for a read-response buffer, `IO_UNIT`, which stays inside the buffer the range was cut from since the contract requires those buffers longer than `IO_UNIT`; the store runs on the calling thread inside a pick, after the simulated device's pick returned, or inside a quiesce call, before the simulated device's quiesce, and the contract holds no byte view of its buffers during either call.
        unsafe { self.memory().add(offset).write_volatile(byte) };
        self.stored = true;
    }

    /// A late device read of the target's source: the bytes land at the
    /// block indexed by `target`'s low 32 bits.
    fn read_source(&mut self) {
        let mut source = vec![0; IO_UNIT];
        // SAFETY: as for `store_at`; the range covers `IO_UNIT` bytes.
        unsafe { std::ptr::copy_nonoverlapping(self.memory(), source.as_mut_ptr(), IO_UNIT) };
        let block = self.target.raw() as u32 as usize;
        self.control.write_device(block * IO_UNIT, &source);
        self.stored = true;
    }

    /// Takes back the first byte the simulated device delivered for the
    /// target, so the reporting pick returns before that byte is visible.
    fn withhold(&mut self) {
        let memory = self.memory();
        // SAFETY: as for `store_at`.
        unsafe {
            self.landed = Some(memory.read_volatile());
            memory.write_volatile(self.before);
        }
    }

    fn submitted(&mut self, token: CommandToken, memory: super::DmaRange) {
        if token == self.target {
            self.memory = Some(memory);
            // SAFETY: the range lies in the caller's arena, which outlives `self`; the read runs inside the submit, before the simulated device receives the command, while the contract holds no byte view of the buffer.
            self.before = unsafe { self.memory().read_volatile() };
        }
    }
}

// SAFETY: the simulated device upholds the `Disk` guarantees; the store selected by `late` breaks I4 for `target` and runs on the test thread between picks, while the contract under test holds no byte view.
unsafe impl Disk for LateStore {
    fn geometry(&self) -> super::DeviceGeometry {
        self.disk.geometry()
    }

    unsafe fn submit_read(
        &mut self,
        token: CommandToken,
        device: DeviceRange,
        memory: super::DmaRange,
    ) -> Result<(), SubmitRefusal> {
        self.submitted(token, memory);
        // SAFETY: the caller's obligations pass through unchanged.
        unsafe { self.disk.submit_read(token, device, memory) }
    }

    unsafe fn submit_write(
        &mut self,
        token: CommandToken,
        device: DeviceRange,
        memory: super::DmaRange,
    ) -> Result<(), SubmitRefusal> {
        self.submitted(token, memory);
        // SAFETY: the caller's obligations pass through unchanged.
        unsafe { self.disk.submit_write(token, device, memory) }
    }

    fn pick_completions(&mut self, sink: &mut CompletionSink<'_>) {
        if self.at_pick {
            self.control.tick(u32::MAX);
        }
        let due = matches!(self.late, Late::After(after) | Late::SourceRead(after) if self.completions >= after);
        let mut out = Vec::with_capacity(sink.remaining());
        self.disk
            .pick_completions(&mut CompletionSink::new(&mut out, sink.remaining()));
        self.completions += out.len();
        let reported = out.iter().any(|done| done.token == self.target);
        self.reported |= reported;
        for done in out {
            sink.push(done).expect("the sink has room for every pick");
        }
        if self.stored {
            return;
        }
        match self.late {
            Late::AtCompletion if reported => self.store(0xEE),
            Late::After(_) if due => self.store(0xEE),
            Late::SourceRead(_) if due => self.read_source(),
            Late::PastRange if reported => self.store_at(IO_UNIT, 0xEE),
            Late::Landing => match self.landed {
                Some(byte) => self.store(byte),
                None if reported => self.withhold(),
                None => {}
            },
            Late::AtCompletion
            | Late::After(_)
            | Late::AtStop
            | Late::PastRange
            | Late::SourceRead(_) => {}
        }
    }

    fn quiesce(&mut self) -> QuiesceStatus {
        if matches!(self.late, Late::AtStop) && self.reported && !self.stored {
            self.store(0xEE);
        }
        self.disk.quiesce()
    }
}

/// Runs the shared contract over the given device with one late access to
/// `target`'s memory; `late` maps the contract's commands per phase,
/// `min(queue_depth, 4)`, to the access's timing, and `at_pick` moves the
/// device inside each pick, so the read the stop proof covers completes at
/// the pick before the stop.
fn late_store_contract(
    (disk, control): (SimDisk, SimControl),
    target: CommandToken,
    late: impl Fn(usize) -> Late,
    at_pick: bool,
) {
    let arena = arena();
    control.set_quiesce(QuiesceMode::Reset);
    let count = (disk.geometry().queue_depth as usize).min(4);
    let mut disk = LateStore {
        disk,
        control: control.clone(),
        at_pick,
        target,
        late: late(count),
        memory: None,
        before: 0,
        landed: None,
        completions: 0,
        reported: false,
        stored: false,
    };
    // SAFETY: the simulated device and the planted store reach the buffers only on this thread inside driver and control calls, so an unwind leaves no access in flight.
    unsafe {
        super::disk_contract::meets_the_disk_contract(&mut disk, &arena, Duration::ZERO, || {
            control.tick(u32::MAX);
        });
    }
}

/// A device that stores into a write's source as it reports the write's
/// completion fails the contract, which names write 1, `tokens(1, _)[1]`.
#[test]
#[should_panic(expected = "write CommandToken(4294967297) changed its source by its completion")]
fn a_store_into_a_completed_write_source_fails_the_disk_contract() {
    late_store_contract(
        sim(config(37, Mode::Direct)),
        CommandToken::from_raw((1 << 32) + 1),
        |_| Late::AtCompletion,
        false,
    );
}

/// The same store on the shared fixture's device fails the contract through
/// the same check, so the fixture leg detects a completed write's source
/// changing.
#[test]
#[should_panic(expected = "write CommandToken(4294967297) changed its source by its completion")]
fn a_store_into_a_completed_write_source_fails_the_contract_on_the_fixture_device() {
    late_store_contract(
        device_with(7, BUFFER),
        CommandToken::from_raw((1 << 32) + 1),
        |_| Late::AtCompletion,
        false,
    );
}

/// A device that stores into a completed write's buffer at the read drain's
/// pick after the first read completes fails the observation after the
/// reads, which names write 1.
#[test]
#[should_panic(expected = "CommandToken(4294967297) changed its buffer after its completion")]
fn a_store_into_a_completed_write_during_the_reads_fails_the_disk_contract() {
    late_store_contract(
        sim(config(37, Mode::Direct)),
        CommandToken::from_raw((1 << 32) + 1),
        |count| Late::After(count + 1),
        false,
    );
}

/// A device that stores into a queue-depth read's buffer as it reports the
/// read's completion fails the contract, which names read 0 of that phase,
/// `tokens(4, _)[0]`.
#[test]
#[should_panic(expected = "read CommandToken(17179869184) returned block 0 changed")]
fn a_store_into_a_queue_depth_read_at_its_completion_fails_the_disk_contract() {
    late_store_contract(
        sim(config(37, Mode::Direct)),
        CommandToken::from_raw(4 << 32),
        |_| Late::AtCompletion,
        false,
    );
}

/// A device that stores into a read's buffer at the first pick after every
/// write and read drained fails the idle observation, which names read 0,
/// `tokens(2, _)[0]`.
#[test]
#[should_panic(expected = "CommandToken(8589934592) changed its buffer after its completion")]
fn a_store_into_an_idle_buffer_after_the_drain_fails_the_disk_contract() {
    late_store_contract(
        sim(config(37, Mode::Direct)),
        CommandToken::from_raw(2 << 32),
        |count| Late::After(2 * count),
        false,
    );
}

#[test]
#[should_panic(expected = "block 1 reads back as written")]
fn a_read_whose_byte_lands_after_its_completion_fails_the_disk_contract() {
    late_store_contract(
        sim(config(37, Mode::Direct)),
        CommandToken::from_raw((2 << 32) + 1),
        |_| Late::Landing,
        false,
    );
}

/// A device that completes the read the stop proof covers at the pick
/// before the stop and stores nothing late meets the contract; the target
/// is a token the contract never submits.
#[test]
fn a_read_completed_before_the_stop_meets_the_disk_contract() {
    late_store_contract(
        sim(config(37, Mode::Direct)),
        CommandToken::from_raw(7 << 32),
        |_| Late::AtCompletion,
        true,
    );
}

/// A device that stores into the buffer of the read the stop proof covers
/// as it reports that read at the pick before the stop fails the read-back
/// check at that pick.
#[test]
#[should_panic(expected = "read CommandToken(25769803776) returned block 0 changed")]
fn a_store_into_a_read_completed_before_the_stop_fails_the_disk_contract() {
    late_store_contract(
        sim(config(37, Mode::Direct)),
        CommandToken::from_raw(6 << 32),
        |_| Late::AtCompletion,
        true,
    );
}

/// A device that completes the read the stop proof covers at the pick
/// before the stop, then stores into its buffer while it stops, fails the
/// idle check on that read.
#[test]
#[should_panic(expected = "CommandToken(25769803776) changed its buffer after its completion")]
fn a_store_during_the_stop_into_a_completed_read_fails_the_disk_contract() {
    late_store_contract(
        sim(config(37, Mode::Direct)),
        CommandToken::from_raw(6 << 32),
        |_| Late::AtStop,
        true,
    );
}

/// A device that writes past the range of the read the stop proof covers
/// as it reports that read at the pick before the stop fails the guard
/// check at that pick.
#[test]
#[should_panic(expected = "read CommandToken(25769803776) wrote past its range")]
fn a_store_past_the_range_of_a_read_completed_before_the_stop_fails_the_disk_contract() {
    late_store_contract(
        sim(config(37, Mode::Direct)),
        CommandToken::from_raw(6 << 32),
        |_| Late::PastRange,
        true,
    );
}

/// A device that reads write 1's source again after its completion, during
/// the writes' observation, persists the sentinel to block 1, and the read
/// of that block fails the contract.
#[test]
#[should_panic(expected = "block 1 reads back as written")]
fn a_source_read_after_a_writes_completion_fails_the_disk_contract() {
    late_store_contract(
        sim(config(37, Mode::Direct)),
        CommandToken::from_raw((1 << 32) + 1),
        Late::SourceRead,
        false,
    );
}

#[test]
fn the_disk_contract_runs_over_a_capacity_with_a_partial_unit() {
    let arena = arena();
    let mut partial = config(38, Mode::Direct);
    partial.capacity = 5 * IO_UNIT as u64 + SECTOR as u64;
    let (mut disk, control) = sim(partial);
    control.set_quiesce(QuiesceMode::Reset);
    // `ticks` counts `progress` calls, including those of the 2 ms observation loops.
    let ticks = std::cell::Cell::new(0);
    // SAFETY: the simulated device reaches the buffers only on this thread inside driver and control calls, so an unwind leaves no access in flight.
    unsafe {
        super::disk_contract::meets_the_disk_contract(
            &mut disk,
            &arena,
            Duration::from_millis(2),
            || {
                ticks.set(ticks.get() + 1);
                control.tick(u32::MAX);
            },
        );
    }
    assert!(
        ticks.get() > 100,
        "the observation interval kept the device moving: {} ticks",
        ticks.get()
    );
    assert!(arena.release().is_ok());
}

#[test]
fn the_capture_records_only_device_produced_completions() {
    let arena = arena();
    let (mut disk, control) = modeled(41);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    read(&mut disk, 7, &buffer);
    // The real completion is posted but held back from the sink, so the
    // duplicate injected for its token reaches the sink first.
    assert_eq!(
        control.select(Stage::Post, 0).unwrap().effect,
        Effect::Posted
    );
    let status = DeviceStatus::Kernel(LEN as i32);
    control.inject(
        Completion {
            token: token(7),
            status,
        },
        Injection::Duplicate,
    );
    control.inject(
        Completion {
            token: token(99),
            status,
        },
        Injection::Foreign,
    );
    let mut out = Vec::with_capacity(4);
    disk.pick_completions(&mut CompletionSink::new(&mut out, 4));
    assert_eq!(tokens(&out), [7, 99]);
    let delivered = |capture: &super::sim::Capture| {
        capture
            .events
            .iter()
            .filter_map(|event| match *event {
                Captured::Delivered { token, .. } => Some(token.raw()),
                Captured::Submitted { .. } => None,
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        delivered(&control.capture()),
        Vec::<u64>::new(),
        "an injected completion is no device terminal"
    );
    assert_eq!(
        control.select(Stage::Admit, 0).unwrap().effect,
        Effect::Admitted
    );
    out.clear();
    disk.pick_completions(&mut CompletionSink::new(&mut out, 4));
    assert_eq!(tokens(&out), [7]);
    assert_eq!(delivered(&control.capture()), [7]);
    drop(buffer);
    assert!(arena.release().is_ok());
}

/// The disk candidates each stage's ready set offers, a read and a write
/// through execution, posting and admission, name their stage, acceptance
/// ordinal and operation in a narrative's mixed world, and in the cluster
/// world the ordinal's top byte, which a cluster sets to its cell, as the
/// cell.
#[test]
fn disk_candidates_name_their_stage_ordinal_and_operation() {
    use crate::net::world_tests::narrate::{World, tests::turn_line};
    let arena = arena();
    let (mut disk, control) = modeled(34);
    let buffers = [
        arena.acquire(PoolKind::ReadResponse).unwrap(),
        arena.acquire(PoolKind::ReceiveWrite).unwrap(),
    ];
    read(&mut disk, 9, &buffers[0]);
    submit(&mut disk, Operation::Write, 2, block(2), &buffers[1]).unwrap();
    let named = |stage: Stage, name: &str| {
        let candidates = control.candidates(stage);
        assert_eq!(candidates.len(), 2, "{stage:?}");
        for ((ordinal, candidate), op) in candidates.iter().enumerate().zip(["read", "write"]) {
            let line = turn_line(World::Mixed, candidate.0, 0);
            let fields = format!("domain=Disk stage={name} ordinal={ordinal} op={op} ");
            assert!(line.contains(&fields), "{line}");
            let mut celled = candidate.0;
            celled[2] = 1;
            let line = turn_line(World::Cluster, celled, 0);
            let fields = format!("stage={name} cell=1 ordinal={ordinal} op={op} ");
            assert!(line.contains(&fields), "{line}");
        }
    };
    named(Stage::Execute, "execute");
    named(Stage::Post, "post");
    for _ in 0..2 {
        control.select(Stage::Post, 0).unwrap();
    }
    named(Stage::Admit, "admit");
    stop(&mut disk, &control);
    drop(buffers);
    assert!(arena.release().is_ok());
}
