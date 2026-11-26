//! Command table tests through the public table API over the simulated device and a heap-backed arena.
//! Oracles are the test's own: device and buffer patterns it wrote, the buffers it holds by offset, and the tokens it knows are outstanding.
//! Two tests read the table's source text and check what its documentation says of a timed-out Report.

use super::super::ledger::EngineBudget;
use super::super::os::HugepageSize;
use super::super::placement::NodeMask;
use super::super::test_platform::{Log, Op, TestPlatform};
use super::custody::GENERATION_MAX;
use super::sim::{
    Fault, Injection, Mode, QuiesceMode, SimConfig, SimControl, SimDisk, StatusForm, sim,
};
use super::{
    Admission, Buffer, BufferArena, BufferConfig, CommandTable, CommandToken, Completion,
    DeviceRange, DeviceStatus, Failure, Operation, PollReport, PoolKind, PoolSpec, QuiesceProgress,
    Quiesced, Refusal, RefusalReason, Released, Stale, SubmitRefusal, TableError, TableReport,
    Terminal,
};

const LEN: u32 = 16384;
const DEPTH: u16 = 20;

const POOLS: [PoolSpec; 3] = [
    PoolSpec {
        kind: PoolKind::ReadResponse,
        count: 16,
        buffer_len: LEN,
    },
    PoolSpec {
        kind: PoolKind::ReceiveWrite,
        count: 16,
        buffer_len: LEN,
    },
    PoolSpec {
        kind: PoolKind::Maintenance,
        count: 1,
        buffer_len: 4096,
    },
];

fn arena() -> (BufferArena<TestPlatform>, Log) {
    let platform = TestPlatform::heap(4096);
    let log = platform.log();
    let validated = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &POOLS,
    }
    .validate()
    .unwrap();
    let arena =
        BufferArena::initialize(&validated, platform, &mut EngineBudget::new(usize::MAX)).unwrap();
    (arena, log)
}

fn config(seed: u64) -> SimConfig {
    SimConfig {
        seed,
        capacity: 64 * u64::from(LEN),
        queue_depth: u32::from(DEPTH),
        max_transfer: LEN,
        form: StatusForm::Kernel,
        mode: Mode::Direct,
        script: crate::storage::device::sim::SCRIPT,
    }
}

fn table_with(
    arena: &BufferArena<TestPlatform>,
    config: SimConfig,
    depth: u16,
) -> (CommandTable<'_, SimDisk>, SimControl) {
    let (disk, control) = sim(config);
    let table = CommandTable::new(disk, arena, depth, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap();
    (table, control)
}

fn table(arena: &BufferArena<TestPlatform>, seed: u64) -> (CommandTable<'_, SimDisk>, SimControl) {
    table_with(arena, config(seed), DEPTH)
}

fn block(index: u64) -> DeviceRange {
    DeviceRange::new(index * u64::from(LEN), LEN).unwrap()
}

fn events<'a>(table: &mut CommandTable<'a, SimDisk>, capacity: usize) -> Vec<Terminal<'a>> {
    let mut out = Vec::with_capacity(capacity);
    table.poll(&mut out);
    assert_eq!(out.capacity(), capacity);
    out
}

fn conserved(table: &CommandTable<'_, SimDisk>, arena: &BufferArena<TestPlatform>) {
    let report = table.report();
    assert_eq!(
        report.free_slots + report.pending + report.abandoned + report.retired,
        u32::from(report.depth),
        "{report:?}"
    );
    let (storage, quarantined) = PoolKind::ALL.iter().fold((0, 0), |(s, q), kind| {
        let pool = arena.report(*kind);
        assert_eq!(
            pool.free + pool.application + pool.storage + pool.quarantined,
            pool.count
        );
        (s + pool.storage, q + pool.quarantined)
    });
    assert_eq!(
        report.pending + report.abandoned,
        storage + quarantined,
        "{report:?}"
    );
    assert_eq!(report.abandoned, quarantined, "{report:?}");
}

/// Ends every outstanding command through a proven quiesce, a reset if anything is still outstanding, and drops every event, so the arena can release.
fn stop(table: &mut CommandTable<'_, SimDisk>, control: &SimControl) {
    control.set_quiesce(QuiesceMode::Reset);
    let mut out = Vec::with_capacity(usize::from(DEPTH));
    // Each call inspects at most `DEPTH` records, so two calls cover every slot.
    for _ in 0..2 {
        if let QuiesceProgress::Quiesced(_) = table.quiesce(&mut out) {
            let report = table.report();
            assert_eq!((report.pending, report.abandoned), (0, 0));
            return;
        }
        out.clear();
    }
    panic!("no proven quiesce\n{}", control.describe());
}

fn refused<'a>(result: Result<CommandToken, super::Rejected<'a>>) -> (Buffer<'a>, Refusal) {
    let rejected = result.unwrap_err();
    (rejected.buffer, rejected.refusal)
}

#[test]
fn construction_refuses_bad_geometry_zero_depth_excess_depth_and_budget() {
    let (arena, _log) = arena();
    let bad = SimConfig {
        capacity: 100,
        ..config(1)
    };
    let (disk, _) = sim(bad);
    let error = CommandTable::new(disk, &arena, 4, &mut EngineBudget::new(usize::MAX))
        .map(|_| ())
        .unwrap_err()
        .0;
    assert!(matches!(error, TableError::Geometry(_)), "{error:?}");
    for (depth, expected) in [
        (0, TableError::ZeroDepth),
        (
            DEPTH + 1,
            TableError::DepthExceedsDevice {
                depth: DEPTH + 1,
                queue_depth: u32::from(DEPTH),
            },
        ),
    ] {
        let (disk, _) = sim(config(1));
        let error = CommandTable::new(disk, &arena, depth, &mut EngineBudget::new(usize::MAX))
            .map(|_| ())
            .unwrap_err()
            .0;
        assert_eq!(error, expected);
    }
    let charge = CommandTable::<SimDisk>::metadata_bytes(4);
    let mut short = EngineBudget::new(charge - 1);
    let (disk, _) = sim(config(1));
    let error = CommandTable::new(disk, &arena, 4, &mut short)
        .map(|_| ())
        .unwrap_err()
        .0;
    assert!(matches!(error, TableError::Envelope(_)));
    assert_eq!(short.used(), 0);
    let mut exact = EngineBudget::new(charge);
    let (disk, _) = sim(config(1));
    let table = CommandTable::new(disk, &arena, 4, &mut exact)
        .map_err(|(e, _)| e)
        .unwrap();
    assert_eq!(exact.used(), charge);
    assert_eq!(table.report().free_slots, 4);
    assert_eq!(table.geometry().queue_depth(), u32::from(DEPTH));
}

/// Every refusal returns the same buffer, application-owned, with nothing outstanding and no device access; table refusals never reach the driver.
/// A range whose length is not a multiple of the device's block size is refused before any driver call, with its buffer back.
#[test]
fn a_range_off_the_device_block_is_refused_unaligned() {
    let (arena, _log) = arena();
    let (disk, control) = sim(config(3));
    control.set_block_size(4096);
    let mut table = CommandTable::new(disk, &arena, DEPTH, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap();
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let (buffer, refusal) = refused(table.submit_read(buffer, DeviceRange::new(0, 512).unwrap()));
    assert_eq!(refusal, Refusal::Unaligned);
    assert_eq!(control.driver_calls(), 0, "the refusal reaches no driver");
    assert_eq!(arena.report(buffer.kind()).application, 1);
    let token = table.submit_read(buffer, DeviceRange::new(0, 4096).unwrap());
    assert!(token.is_ok(), "a whole-block range is accepted");
}

#[test]
fn every_refusal_returns_the_same_buffer_and_owns_nothing() {
    let (arena, _log) = arena();
    let (other, _other_log) = self::arena();
    let (mut table, control) = table(&arena, 2);
    let driver_calls = || control.driver_calls();
    let before = table.report();

    let check = |buffer: &Buffer<'_>, offset: usize, table: &CommandTable<'_, SimDisk>| {
        assert_eq!(buffer.offset(), offset);
        assert_eq!(arena.report(buffer.kind()).application, 1);
        assert_eq!(arena.report(buffer.kind()).storage, 0);
        owns_no_record(table);
    };

    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let offset = buffer.offset();
    let calls = driver_calls();
    let beyond = DeviceRange::new(64 * u64::from(LEN), LEN).unwrap();
    let (buffer, refusal) = refused(table.submit_read(buffer, beyond));
    assert_eq!(refusal, Refusal::OutOfCapacity);
    check(&buffer, offset, &table);
    let (buffer, refusal) =
        refused(table.submit_read(buffer, DeviceRange::new(0, 2 * LEN).unwrap()));
    assert_eq!(refusal, Refusal::TooLong);
    let small = arena.acquire(PoolKind::Maintenance).unwrap();
    let small_offset = small.offset();
    let (small, refusal) = refused(table.submit_write(small, block(0)));
    assert_eq!(refusal, Refusal::SpanTooLong);
    assert_eq!(small.offset(), small_offset);
    drop(small);
    let foreign = other.acquire(PoolKind::ReadResponse).unwrap();
    let (foreign, refusal) = refused(table.submit_read(foreign, block(0)));
    assert_eq!(refusal, Refusal::ForeignArena);
    drop(foreign);
    assert_eq!(driver_calls(), calls, "table refusals reach no driver");
    assert_eq!(table.report(), before);

    let scripted = SubmitRefusal {
        reason: RefusalReason::QueueFull,
        code: Some(-7),
    };
    control.refuse_next(scripted);
    let (buffer, refusal) = refused(table.submit_read(buffer, block(1)));
    assert_eq!(refusal, Refusal::Device(scripted));
    check(&buffer, offset, &table);
    assert_eq!(table.report().admission, Admission::Open);
    assert!(
        !control
            .events()
            .iter()
            .any(|event| matches!(event, super::sim::Event::Executed { .. }))
    );
    return_buffer(buffer, &mut table, &control, &arena, offset);
    drop(table);
    drop(control);
    assert!(arena.release().is_ok());
    assert!(other.release().is_ok());
}

/// Asserts that the table holds no pending or abandoned record, as it must after a refused submit.
fn owns_no_record(table: &CommandTable<'_, SimDisk>) {
    let report = table.report();
    assert_eq!(
        (report.pending, report.abandoned),
        (0, 0),
        "a refused submit leaves the table owning no record: {report:?}"
    );
}

/// The planted acceptance: with no refusal scripted the sim disk accepts the submit, so the table owns the one pending
/// record a driver refusal that kept its slot would leave, and the refusal walk's ownership check rejects it.
#[test]
#[should_panic(expected = "a refused submit leaves the table owning no record")]
fn negative_control_an_accepted_submit_leaves_the_record_the_ownership_check_rejects() {
    let (arena, _log) = arena();
    let (mut table, _control) = table(&arena, 2);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    table.submit_read(buffer, block(1)).unwrap();
    owns_no_record(&table);
}

/// Continues the refusal walk with a fresh buffer: driver refusals consume a generation, `DeviceGone` makes admission lost, and later submits refuse without a driver call.
fn return_buffer<'a>(
    buffer: Buffer<'a>,
    table: &mut CommandTable<'a, SimDisk>,
    control: &SimControl,
    arena: &'a BufferArena<TestPlatform>,
    offset: usize,
) {
    let scripted = SubmitRefusal {
        reason: RefusalReason::InvalidRange,
        code: None,
    };
    control.refuse_next(scripted);
    let (buffer, _) = refused(table.submit_read(buffer, block(1)));
    let token = table.submit_read(buffer, block(1)).unwrap();
    // Three issues on slot 0's first use, the two refused ones included, so this token carries a later generation.
    assert!(token.raw() >> 16 >= 3, "{token:?}");
    control.post(token);
    let mut out = Vec::with_capacity(1);
    table.poll(&mut out);
    let Some(Terminal::Read { done, .. }) = out.pop() else {
        panic!("{}", control.describe())
    };
    let buffer = done.into_buffer();
    assert_eq!(buffer.offset(), offset);
    let gone = SubmitRefusal {
        reason: RefusalReason::DeviceGone,
        code: None,
    };
    control.refuse_next(gone);
    let (buffer, refusal) = refused(table.submit_read(buffer, block(1)));
    assert_eq!(refusal, Refusal::Device(gone));
    assert_eq!(table.report().admission, Admission::Lost);
    let calls = control.driver_calls();
    let (buffer, refusal) = refused(table.submit_read(buffer, block(1)));
    assert_eq!(refusal, Refusal::DeviceLost);
    assert_eq!(control.driver_calls(), calls);
    assert_eq!(buffer.offset(), offset);
    assert_eq!(arena.report(PoolKind::ReadResponse).application, 1);
    drop(buffer);
}

/// When several refusals apply, the first in the order admission, arena, capacity, maximum transfer, span, slot wins.
#[test]
fn refusals_follow_the_documented_order() {
    let (arena, _log) = arena();
    let (other, _) = self::arena();
    let (mut table, control) = table_with(&arena, config(3), 1);
    let beyond_and_long = DeviceRange::new(64 * u64::from(LEN), 2 * LEN).unwrap();
    let long = DeviceRange::new(0, 2 * LEN).unwrap();

    let foreign = other.acquire(PoolKind::ReadResponse).unwrap();
    let (foreign, refusal) = refused(table.submit_read(foreign, beyond_and_long));
    assert_eq!(refusal, Refusal::ForeignArena);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let (buffer, refusal) = refused(table.submit_read(buffer, beyond_and_long));
    assert_eq!(refusal, Refusal::OutOfCapacity);
    let small = arena.acquire(PoolKind::Maintenance).unwrap();
    let (small, refusal) = refused(table.submit_read(small, long));
    assert_eq!(refusal, Refusal::TooLong);
    let held = arena.acquire(PoolKind::ReadResponse).unwrap();
    let token = table.submit_read(held, block(0)).unwrap();
    let (small, refusal) = refused(table.submit_read(small, block(1)));
    assert_eq!(refusal, Refusal::SpanTooLong);
    let (buffer, refusal) = refused(table.submit_read(buffer, block(1)));
    assert_eq!(refusal, Refusal::TableFull { abandoned: 0 });
    table.close();
    let (foreign, refusal) = refused(table.submit_read(foreign, beyond_and_long));
    assert_eq!(refusal, Refusal::Closed);
    control.post(token);
    drop(events(&mut table, 1));
    drop((foreign, buffer, small, table));
    assert!(arena.release().is_ok());
    assert!(other.release().is_ok());
}

/// An accepted buffer is storage-owned and cannot be acquired; a table dropped in flight leaves it owned forever, which blocks release without an unmap.
#[test]
fn an_accepted_buffer_stays_storage_owned_even_when_the_table_drops() {
    let (arena, log) = arena();
    let (mut table, _control) = table(&arena, 4);
    let buffer = arena.acquire(PoolKind::Maintenance).unwrap();
    let range = DeviceRange::new(0, 4096).unwrap();
    table.submit_write(buffer, range).unwrap();
    let report = arena.report(PoolKind::Maintenance);
    assert_eq!((report.free, report.application, report.storage), (0, 0, 1));
    assert!(arena.acquire(PoolKind::Maintenance).is_err());
    conserved(&table, &arena);
    drop(table);
    let blocked = arena.release().unwrap_err();
    assert_eq!(
        blocked.held,
        [
            (PoolKind::ReadResponse, 0),
            (PoolKind::ReceiveWrite, 0),
            (PoolKind::Maintenance, 1),
            (PoolKind::PacketReceive, 0),
            (PoolKind::PacketHeader, 0),
            (PoolKind::Reservation, 0)
        ]
    );
    assert!(log.calls(Op::Unmap).is_empty());
}

/// Successful reads carry exactly the device's bytes as read-done evidence and writes reach the device, each with the raw status; every failure returns a plain buffer and no read-done or written event.
#[test]
fn completions_classify_into_terminal_events_with_raw_status() {
    let (arena, _log) = arena();
    let (mut table, control) = table(&arena, 5);
    control.write_device(0, &[0xAB; LEN as usize]);
    let read = arena.acquire(PoolKind::ReadResponse).unwrap();
    let mut write = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    write.bytes_mut().fill(0xCD);
    let read_token = table.submit_read(read, block(0)).unwrap();
    let write_token = table.submit_write(write, block(1)).unwrap();
    control.tick(2);
    let mut seen = 0;
    for event in events(&mut table, 4) {
        match event {
            Terminal::Read {
                token,
                done,
                status,
            } => {
                assert_eq!(token, read_token);
                assert_eq!(status, DeviceStatus::Kernel(LEN as i32));
                assert_eq!(done.read_len(), LEN);
                assert!(done.bytes().iter().all(|byte| *byte == 0xAB));
                seen += 1;
            }
            Terminal::Written { token, status, .. } => {
                assert_eq!(token, write_token);
                assert_eq!(status, DeviceStatus::Kernel(LEN as i32));
                seen += 1;
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(seen, 2);
    assert_eq!(
        control.device(LEN as usize, LEN as usize),
        vec![0xCD; LEN as usize]
    );

    let faults = [
        (
            Operation::Read,
            Fault::Status(DeviceStatus::Kernel(-19)),
            DeviceStatus::Kernel(-19),
            Failure::Device,
        ),
        (
            Operation::Read,
            Fault::Short { units: 1 },
            DeviceStatus::Kernel(4096),
            Failure::Short { transferred: 4096 },
        ),
        (
            Operation::Read,
            Fault::PartialReadFailure { sectors: 3 },
            DeviceStatus::Kernel(-libc::EIO),
            Failure::Device,
        ),
        (
            Operation::Write,
            Fault::TornWrite { sectors: 3 },
            DeviceStatus::Kernel(-libc::EIO),
            Failure::Device,
        ),
        (
            Operation::Write,
            Fault::Short { units: 2 },
            DeviceStatus::Kernel(8192),
            Failure::Short { transferred: 8192 },
        ),
    ];
    for (op, fault, raw, failure) in faults {
        control.write_device(2 * LEN as usize, &[0x10; LEN as usize]);
        let mut buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
        buffer.bytes_mut().fill(0x20);
        let offset = buffer.offset();
        let token = match op {
            Operation::Read => table.submit_read(buffer, block(2)),
            Operation::Write => table.submit_write(buffer, block(2)),
        }
        .unwrap();
        control.fault(token, fault);
        control.tick(1);
        let mut out = events(&mut table, 1);
        match out.pop() {
            Some(Terminal::Failed {
                token: t,
                op: o,
                buffer,
                status,
                failure: f,
            }) => {
                assert_eq!((t, o, status, f), (token, op, raw, failure), "{fault:?}");
                assert_eq!(buffer.offset(), offset);
            }
            other => panic!("{fault:?}: {other:?}"),
        }
        if op == Operation::Write {
            // A partial write changed exactly the bytes the device took.
            let moved = match fault {
                Fault::TornWrite { sectors } => sectors as usize * 512,
                Fault::Short { units } => units as usize * 4096,
                _ => 0,
            };
            let device = control.device(2 * LEN as usize, LEN as usize);
            assert!(
                device[..moved].iter().all(|byte| *byte == 0x20),
                "{fault:?}"
            );
            assert!(
                device[moved..].iter().all(|byte| *byte == 0x10),
                "{fault:?}"
            );
        }
    }

    // A corrupted success is still a success to the table: the read-done carries the corrupted bytes, which a validator must reject.
    control.write_device(3 * LEN as usize, &[0x01; LEN as usize]);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let token = table.submit_read(buffer, block(3)).unwrap();
    control.fault(token, Fault::CorruptSuccess);
    control.tick(1);
    match events(&mut table, 1).pop() {
        Some(Terminal::Read { done, .. }) => {
            assert!(done.bytes().iter().all(|b| *b == 0x01 ^ 0x5A))
        }
        other => panic!("{other:?}"),
    }
    conserved(&table, &arena);
    drop(table);
    assert!(arena.release().is_ok());
}

/// Stale completions change nothing: duplicates, a same-batch duplicate, a never-issued slot, an older generation, an out-of-range slot and a driver-refused token.
#[test]
fn stale_completions_are_counted_and_free_nothing() {
    let (arena, _log) = arena();
    let (mut table, control) = table_with(&arena, config(6), 4);
    let status = DeviceStatus::Kernel(LEN as i32);
    let inject = |raw: u64, class| {
        control.inject(
            Completion {
                token: CommandToken::from_raw(raw),
                status,
            },
            class,
        )
    };

    let a = arena.acquire(PoolKind::ReadResponse).unwrap();
    let first = table.submit_read(a, block(0)).unwrap();
    control.post(first);
    let mut delivered = events(&mut table, 4);
    assert_eq!(delivered.len(), 1);
    let Some(Terminal::Read { done, .. }) = delivered.pop() else {
        panic!()
    };
    // The slot is reissued at a newer generation; the old token must not free the new command's buffer.
    let second = table.submit_read(done.into_buffer(), block(1)).unwrap();
    assert_eq!(second.raw() & 0xFFFF, first.raw() & 0xFFFF);
    let refused_token = {
        control.refuse_next(SubmitRefusal {
            reason: RefusalReason::QueueFull,
            code: None,
        });
        let b = arena.acquire(PoolKind::ReadResponse).unwrap();
        let (b, _) = refused(table.submit_read(b, block(2)));
        drop(b);
        // The refused issue took slot 1 at generation 1.
        CommandToken::from_raw(1 << 16 | 1)
    };
    let before_pool = arena.report(PoolKind::ReadResponse);
    let before = table.report();
    inject(first.raw(), Injection::Old);
    inject(refused_token.raw(), Injection::Refused);
    inject(2 << 16 | 3, Injection::Foreign);
    inject(1 << 16 | 9, Injection::OutOfRange);
    assert!(events(&mut table, 8).is_empty());
    assert_eq!(table.report().stale, before.stale + 4);
    assert_eq!(arena.report(PoolKind::ReadResponse), before_pool);
    assert_eq!(table.report().pending, 1);

    // The same token twice in one pick: the first completes the command, the second is stale.
    control.post(second);
    inject(second.raw(), Injection::Duplicate);
    let out = events(&mut table, 8);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].token(), second);
    assert_eq!(table.report().stale, before.stale + 5);
    // After delivery, the same token again is stale.
    drop(out);
    drop(delivered);
    inject(second.raw(), Injection::Duplicate);
    assert!(events(&mut table, 8).is_empty());
    assert_eq!(table.report().stale, before.stale + 6);
    conserved(&table, &arena);
    drop(table);
    assert!(arena.release().is_ok());
}

/// A slot that issues the maximum generation retires when it frees, a refused submit included, and a table whose every slot retired refuses table-full.
#[test]
fn a_slot_at_the_maximum_generation_retires_and_all_retired_is_table_full() {
    let (arena, _log) = arena();
    let (mut table, control) = table_with(&arena, config(7), 2);
    table.set_generation(0, GENERATION_MAX - 1);
    table.set_generation(1, GENERATION_MAX - 1);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let token = table.submit_read(buffer, block(0)).unwrap();
    assert_eq!(token.raw() >> 16, GENERATION_MAX);
    control.post(token);
    let buffer = match events(&mut table, 1).pop() {
        Some(Terminal::Read { done, .. }) => done.into_buffer(),
        other => panic!("{other:?}"),
    };
    assert_eq!(table.report().retired, 1);
    control.refuse_next(SubmitRefusal {
        reason: RefusalReason::QueueFull,
        code: None,
    });
    let (buffer, _) = refused(table.submit_read(buffer, block(0)));
    let report = table.report();
    assert_eq!((report.retired, report.free_slots), (2, 0));
    let (buffer, refusal) = refused(table.submit_read(buffer, block(0)));
    assert_eq!(refusal, Refusal::TableFull { abandoned: 0 });
    let calls = control.driver_calls();
    let (buffer, _) = refused(table.submit_read(buffer, block(0)));
    assert_eq!(control.driver_calls(), calls);
    conserved(&table, &arena);
    drop((buffer, table));
    assert!(arena.release().is_ok());
}

/// Cancel quarantines without freeing; the later completion frees the buffer inside the table with an `Abandoned` event carrying the raw status.
/// Cancel again, after delivery, after close and after stop is stale and changes nothing.
#[test]
fn cancel_quarantines_and_only_the_terminal_event_frees() {
    let (arena, _log) = arena();
    let (mut table, control) = table_with(&arena, config(8), 4);
    let buffer = arena.acquire(PoolKind::Maintenance).unwrap();
    let offset = buffer.offset();
    let unit = DeviceRange::new(0, 4096).unwrap();
    let token = table.submit_read(buffer, unit).unwrap();
    assert_eq!(table.cancel(token), Ok(()));
    let pool = arena.report(PoolKind::Maintenance);
    assert_eq!((pool.free, pool.storage, pool.quarantined), (0, 0, 1));
    assert_eq!(table.report().abandoned, 1);
    assert!(arena.acquire(PoolKind::Maintenance).is_err());
    assert_eq!(table.cancel(token), Err(Stale));
    conserved(&table, &arena);
    control.fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
    control.post(token);
    match events(&mut table, 1).pop() {
        Some(Terminal::Abandoned {
            token: t,
            op,
            status,
        }) => {
            assert_eq!(
                (t, op, status),
                (token, Operation::Read, Some(DeviceStatus::Kernel(-5)))
            );
        }
        other => panic!("{other:?}"),
    }
    let pool = arena.report(PoolKind::Maintenance);
    assert_eq!((pool.free, pool.quarantined), (1, 0));
    assert_eq!(table.report().abandoned, 0);
    assert_eq!(table.cancel(token), Err(Stale));
    let again = arena.acquire(PoolKind::Maintenance).unwrap();
    assert_eq!(again.offset(), offset);

    let delivered = table.submit_read(again, unit).unwrap();
    control.post(delivered);
    let buffer = match events(&mut table, 1).pop() {
        Some(Terminal::Read { done, .. }) => done.into_buffer(),
        other => panic!("{other:?}"),
    };
    assert_eq!(table.cancel(delivered), Err(Stale));
    let pending = table.submit_read(buffer, unit).unwrap();
    table.close();
    let before = (table.report(), arena.report(PoolKind::Maintenance));
    assert_eq!(table.cancel(pending), Err(Stale));
    assert_eq!(
        (table.report(), arena.report(PoolKind::Maintenance)),
        before
    );
    let other = arena.acquire(PoolKind::ReadResponse).unwrap();
    assert_eq!(
        refused(table.submit_read(other, block(1))).1,
        Refusal::Closed
    );
    stop(&mut table, &control);
    assert_eq!(table.cancel(pending), Err(Stale));
    conserved(&table, &arena);
    drop(table);
    assert!(arena.release().is_ok());
}

/// Twenty ready completions drain into an output of capacity four in five polls, with every event accounted and the capacity unchanged; capacity zero picks nothing.
#[test]
fn a_burst_drains_in_bounded_polls_without_loss() {
    let (arena, _log) = arena();
    let (mut table, control) = table(&arena, 9);
    let mut tokens = Vec::new();
    for index in 0..20 {
        let kind = if index % 2 == 0 {
            PoolKind::ReadResponse
        } else {
            PoolKind::ReceiveWrite
        };
        let buffer = arena.acquire(kind).unwrap();
        tokens.push(table.submit_read(buffer, block(index)).unwrap());
    }
    control.tick(20);
    let mut none = Vec::new();
    assert_eq!(table.poll(&mut none).delivered, 0);
    assert_eq!(control.outstanding(), 20);
    let mut out = Vec::with_capacity(4);
    let mut seen = Vec::new();
    for _ in 0..5 {
        let report = table.poll(&mut out);
        assert_eq!(report.delivered, 4);
        assert_eq!(out.capacity(), 4);
        seen.extend(out.drain(..).map(|event| event.token()));
        conserved(&table, &arena);
    }
    assert_eq!(table.poll(&mut out).delivered, 0);
    seen.sort_unstable_by_key(|token| token.raw());
    tokens.sort_unstable_by_key(|token| token.raw());
    assert_eq!(seen, tokens);
    drop((none, out, table));
    assert!(arena.release().is_ok());
}

/// Output capacities smaller than, equal to and larger than the ready count each deliver `min(spare, ready)` events per poll and lose none.
#[test]
fn every_output_capacity_delivers_within_its_spare_room() {
    for capacity in [1, 3, 5, 8] {
        let (arena, _log) = arena();
        let (mut table, control) = table(&arena, 10);
        for index in 0..5 {
            let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
            table.submit_read(buffer, block(index)).unwrap();
        }
        control.tick(5);
        let mut out = Vec::with_capacity(capacity);
        out.extend(events(&mut table, 0));
        let mut total = 0;
        let mut polls = 0;
        while total < 5 {
            assert!(polls < 5, "capacity {capacity} delivers within five polls");
            let delivered = table.poll(&mut out).delivered;
            assert_eq!(delivered, capacity.min(5 - total), "capacity {capacity}");
            total += delivered;
            polls += 1;
            out.clear();
        }
        assert_eq!(polls, 5usize.div_ceil(capacity));
        drop((out, table));
        assert!(arena.release().is_ok());
    }
}

#[test]
fn quiesce_is_all_returned_once_nothing_is_outstanding() {
    let (arena, log) = arena();
    let (mut table, control) = table(&arena, 11);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let token = table.submit_read(buffer, block(0)).unwrap();
    let mut out = Vec::with_capacity(4);
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Draining { outstanding: 1 }
    );
    assert_eq!(table.report().admission, Admission::Closed);
    control.post(token);
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Quiesced(Quiesced::AllReturned)
    );
    assert_eq!(out.len(), 1);
    assert_eq!(table.report().admission, Admission::Closed);
    drop((out, table));
    assert_eq!(arena.release().unwrap(), Released::Complete);
    assert_eq!(log.calls(Op::Unmap).len(), 1);
}

/// A driver swapped in through a loan taken while commands are outstanding could prove a stop for commands the original driver still holds, and the table would return buffers the device can still write.
#[test]
fn the_driver_is_lent_only_after_admission_closed_with_nothing_outstanding() {
    let (arena, _log) = arena();
    let (mut table, control) = table(&arena, 13);
    assert!(table.disk_mut().is_none(), "admission is open");
    let pending = table
        .submit_read(arena.acquire(PoolKind::ReadResponse).unwrap(), block(0))
        .unwrap();
    let abandoned = table
        .submit_read(arena.acquire(PoolKind::ReadResponse).unwrap(), block(1))
        .unwrap();
    table.cancel(abandoned).unwrap();
    table.close();
    assert!(table.disk_mut().is_none(), "two commands are outstanding");
    control.post(pending);
    let mut out = Vec::with_capacity(2);
    table.poll(&mut out);
    assert!(
        table.disk_mut().is_none(),
        "the cancelled command is outstanding"
    );
    control.post(abandoned);
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Quiesced(Quiesced::AllReturned)
    );
    assert!(table.disk_mut().is_some());
    drop((out, table));
    assert_eq!(arena.release().unwrap(), Released::Complete);
}

/// A reset proves the stop: attached commands come back `Quiesced`, detached ones `Abandoned` with no status, across several calls when the output is small, and the arena then releases with one unmap.
#[test]
fn a_proven_stop_delivers_every_record_once_across_calls() {
    let (arena, log) = arena();
    let (mut table, control) = table(&arena, 12);
    let mut tokens = Vec::new();
    for index in 0..5 {
        let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
        tokens.push(table.submit_read(buffer, block(index)).unwrap());
    }
    table.cancel(tokens[1]).unwrap();
    table.cancel(tokens[3]).unwrap();
    control.set_quiesce(QuiesceMode::Reset);
    let mut out = Vec::with_capacity(2);
    let mut seen = Vec::new();
    let mut progress = Vec::new();
    loop {
        assert!(
            progress.len() < 3,
            "the stop delivers within three calls: {progress:?}"
        );
        let step = table.quiesce(&mut out);
        progress.push(step);
        for event in out.drain(..) {
            match event {
                Terminal::Quiesced { token, op, buffer } => {
                    assert_eq!(op, Operation::Read);
                    seen.push((token, true));
                    drop(buffer);
                }
                Terminal::Abandoned { token, status, .. } => {
                    assert_eq!(status, None);
                    seen.push((token, false));
                }
                other => panic!("{other:?}"),
            }
        }
        conserved(&table, &arena);
        if step == QuiesceProgress::Quiesced(Quiesced::DeviceStopped) {
            break;
        }
    }
    assert_eq!(
        progress,
        [
            QuiesceProgress::Delivering { remaining: 3 },
            QuiesceProgress::Delivering { remaining: 1 },
            QuiesceProgress::Quiesced(Quiesced::DeviceStopped),
        ]
    );
    seen.sort_unstable_by_key(|(token, _)| token.raw());
    let expected: Vec<_> = tokens
        .iter()
        .enumerate()
        .map(|(index, token)| (*token, index != 1 && index != 3))
        .collect();
    assert_eq!(seen, expected);
    assert_eq!(table.report().admission, Admission::Stopped);
    let calls = control.driver_calls();
    assert_eq!(table.poll(&mut out).delivered, 0);
    assert_eq!(
        control.driver_calls(),
        calls,
        "no driver call after a proven stop"
    );
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    assert_eq!(
        refused(table.submit_read(buffer, block(0))).1,
        Refusal::Stopped
    );
    drop((out, table));
    assert_eq!(arena.release().unwrap(), Released::Complete);
    assert_eq!(log.calls(Op::Unmap).len(), 1);
}

/// Unproven and failed quiesces prove nothing: every buffer stays owned, no `Quiesced` event appears, and the arena stays blocked after the table drops.
#[test]
fn unproven_and_failed_quiesce_keep_every_buffer_owned() {
    for (mode, expected) in [
        (
            QuiesceMode::Unproven,
            QuiesceProgress::Draining { outstanding: 2 },
        ),
        (
            QuiesceMode::Failed(Some(9)),
            QuiesceProgress::Unproven {
                outstanding: 2,
                code: Some(9),
            },
        ),
    ] {
        let (arena, log) = arena();
        let (mut table, control) = table(&arena, 13);
        for index in 0..2 {
            let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
            table.submit_write(buffer, block(index)).unwrap();
        }
        control.set_quiesce(mode);
        let mut out = Vec::with_capacity(4);
        for _ in 0..3 {
            assert_eq!(table.quiesce(&mut out), expected);
        }
        assert!(out.is_empty());
        assert_eq!(arena.report(PoolKind::ReceiveWrite).storage, 2);
        drop((out, table));
        assert!(arena.release().is_err());
        assert!(log.calls(Op::Unmap).is_empty());
    }
}

/// A completion the device never reports keeps its buffer storage-owned through any number of polls; only a reset reports device-stopped.
#[test]
fn a_dropped_notification_keeps_its_buffer_owned_until_a_reset() {
    let (arena, _log) = arena();
    let (mut table, control) = table(&arena, 14);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let token = table.submit_write(buffer, block(0)).unwrap();
    control.fault(token, Fault::DropCompletion);
    control.tick(1);
    let mut out = Vec::with_capacity(4);
    for _ in 0..4 {
        assert_eq!(table.poll(&mut out).delivered, 0);
        assert_eq!(
            table.quiesce(&mut out),
            QuiesceProgress::Draining { outstanding: 1 }
        );
    }
    assert_eq!(arena.report(PoolKind::ReceiveWrite).storage, 1);
    control.set_quiesce(QuiesceMode::Reset);
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Quiesced(Quiesced::DeviceStopped)
    );
    assert!(matches!(out.pop(), Some(Terminal::Quiesced { token: t, .. }) if t == token));
    drop((out, table));
    assert!(arena.release().is_ok());
}

/// A driver whose submit never returns leaves the reserved record counted pending and admission lost.
#[test]
fn a_panicking_driver_submit_leaves_the_record_pending_and_admission_lost() {
    struct Panics;
    // SAFETY: `submit_read` never returns, so no command is ever accepted; every other method proves nothing.
    unsafe impl super::Disk for Panics {
        fn geometry(&self) -> super::DeviceGeometry {
            super::DeviceGeometry {
                capacity: 1 << 20,
                max_transfer: LEN,
                block_size: 4096,
                queue_depth: 4,
            }
        }
        unsafe fn submit_read(
            &mut self,
            _: CommandToken,
            _: DeviceRange,
            _: super::DmaRange,
        ) -> Result<(), SubmitRefusal> {
            panic!("driver failure")
        }
        unsafe fn submit_write(
            &mut self,
            _: CommandToken,
            _: DeviceRange,
            _: super::DmaRange,
        ) -> Result<(), SubmitRefusal> {
            panic!("driver failure")
        }
        fn pick_completions(&mut self, _: &mut super::CompletionSink<'_>) {}
        fn quiesce(&mut self) -> super::QuiesceStatus {
            super::QuiesceStatus::Pending
        }
    }
    let (arena, log) = arena();
    let mut table = CommandTable::new(Panics, &arena, 4, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap();
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = table.submit_read(buffer, block(0));
    }));
    assert!(caught.is_err());
    let report = table.report();
    assert_eq!(
        (report.pending, report.free_slots, report.admission),
        (1, 3, Admission::Lost)
    );
    assert_eq!(arena.report(PoolKind::ReadResponse).storage, 1);
    // The reserved command was never accepted: its token cannot cancel it.
    assert_eq!(table.cancel(CommandToken::from_raw(1 << 16)), Err(Stale));
    assert_eq!(table.report(), report);
    let other = arena.acquire(PoolKind::ReadResponse).unwrap();
    assert_eq!(
        refused(table.submit_read(other, block(1))).1,
        Refusal::DeviceLost
    );
    drop(table);
    assert!(arena.release().is_err());
    assert!(log.calls(Op::Unmap).is_empty());
}

/// With setup outside the measured window, submit, poll, cancel, close and quiesce allocate nothing.
#[test]
fn the_table_paths_allocate_nothing() {
    let (arena, _log) = arena();
    let (mut table, control) = table(&arena, 15);
    let mut out = Vec::with_capacity(usize::from(DEPTH));
    let before = crate::instrument::allocations();
    for round in 0..200u64 {
        let read = arena.acquire(PoolKind::ReadResponse).unwrap();
        let write = arena.acquire(PoolKind::ReceiveWrite).unwrap();
        let a = table.submit_read(read, block(round % 8)).unwrap();
        let b = table.submit_write(write, block(8 + round % 8)).unwrap();
        if round % 3 == 0 {
            table.cancel(b).unwrap();
        }
        control.tick(2);
        table.poll(&mut out);
        let _ = a;
        out.clear();
    }
    table.close();
    control.set_quiesce(QuiesceMode::Reset);
    let _ = table.quiesce(&mut out);
    out.clear();
    assert_eq!(crate::instrument::allocations(), before);
    drop((out, table));
    assert!(arena.release().is_ok());
}

/// Seeded operation sequences: after every step the pools and the table match the test's model and every conservation equation, no acquire returns a buffer the model holds in storage or quarantine, and every successful read matches the device shadow.
/// Each seed must witness a successful read, a successful write and a reacquired buffer, so an implementation that only refuses fails.
#[test]
fn seeded_sequences_match_the_model_and_make_progress() {
    use std::collections::{BTreeMap, HashMap};

    use super::super::seeded::SplitMix64;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Held {
        App,
        Storage,
        Quarantined,
    }

    for seed in 1..=64u64 {
        let (arena, _log) = arena();
        let (mut table, control) = table(&arena, seed);
        let mut rng = SplitMix64::new(seed ^ 0xA5A5);
        let blocks = 32usize;
        // Each buffer offset maps to its own device block, so no two commands race on one block.
        let block_of = |offset: usize| (offset / LEN as usize) as u64 % blocks as u64;
        let mut shadow = vec![0u8; blocks];
        let mut held: Vec<Buffer<'_>> = Vec::new();
        let mut state: HashMap<usize, Held> = HashMap::new();
        let mut outstanding: BTreeMap<u64, (usize, Operation, u8)> = BTreeMap::new();
        let mut used: Vec<usize> = Vec::new();
        let (mut reads, mut writes, mut reacquired) = (0, 0, 0);
        let describe = |control: &SimControl| format!("seed {seed}\n{}", control.describe());
        for step in 0..500u64 {
            match rng.below(8) {
                0 | 1 => {
                    let kind = if rng.below(2) == 0 {
                        PoolKind::ReadResponse
                    } else {
                        PoolKind::ReceiveWrite
                    };
                    if let Ok(buffer) = arena.acquire(kind) {
                        let offset = buffer.offset();
                        assert_eq!(state.get(&offset), None, "{}", describe(&control));
                        if used.contains(&offset) {
                            reacquired += 1;
                        }
                        state.insert(offset, Held::App);
                        held.push(buffer);
                    }
                }
                2 | 3 if !held.is_empty() => {
                    let mut buffer = held.swap_remove(rng.below(held.len() as u64) as usize);
                    let offset = buffer.offset();
                    let op = if rng.below(2) == 0 {
                        Operation::Read
                    } else {
                        Operation::Write
                    };
                    let pattern = (step as u8).wrapping_mul(7) | 1;
                    if op == Operation::Write {
                        buffer.bytes_mut().fill(pattern);
                    }
                    let device = block(block_of(offset));
                    let result = match op {
                        Operation::Read => table.submit_read(buffer, device),
                        Operation::Write => table.submit_write(buffer, device),
                    };
                    match result {
                        Ok(token) => {
                            state.insert(offset, Held::Storage);
                            outstanding.insert(token.raw(), (offset, op, pattern));
                            used.push(offset);
                            if rng.below(8) == 0 {
                                control.fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
                            }
                        }
                        Err(rejected) => {
                            assert_eq!(rejected.buffer.offset(), offset);
                            held.push(rejected.buffer);
                        }
                    }
                }
                4 if !outstanding.is_empty() => {
                    let tokens: Vec<u64> = outstanding.keys().copied().collect();
                    let raw = tokens[rng.below(tokens.len() as u64) as usize];
                    let offset = outstanding[&raw].0;
                    match (table.cancel(CommandToken::from_raw(raw)), state[&offset]) {
                        (Ok(()), Held::Storage) => {
                            state.insert(offset, Held::Quarantined);
                        }
                        (Err(Stale), Held::Quarantined) => {}
                        other => panic!("{other:?}\n{}", describe(&control)),
                    }
                }
                5 => control.tick(rng.below(4) as u32),
                6 => {
                    let capacity = rng.below(5) as usize;
                    let mut out = Vec::with_capacity(capacity);
                    table.poll(&mut out);
                    for event in out {
                        let raw = event.token().raw();
                        let (offset, op, pattern) = outstanding.remove(&raw).unwrap_or_else(|| {
                            panic!("{raw:x} not outstanding\n{}", describe(&control))
                        });
                        let block = block_of(offset) as usize;
                        match event {
                            Terminal::Reservation { .. } => {
                                panic!("the data history issues data commands")
                            }
                            Terminal::Read { done, .. } => {
                                assert_eq!(op, Operation::Read);
                                assert_eq!(done.read_len(), LEN);
                                assert_eq!(state[&offset], Held::Storage);
                                assert!(
                                    done.bytes().iter().all(|b| *b == shadow[block]),
                                    "{}",
                                    describe(&control)
                                );
                                reads += 1;
                                state.insert(offset, Held::App);
                                let buffer = done.into_buffer();
                                assert_eq!(buffer.offset(), offset, "{}", describe(&control));
                                held.push(buffer);
                            }
                            Terminal::Written { buffer, .. } => {
                                assert_eq!(op, Operation::Write);
                                assert_eq!(buffer.offset(), offset, "{}", describe(&control));
                                shadow[block] = pattern;
                                writes += 1;
                                state.insert(offset, Held::App);
                                held.push(buffer);
                            }
                            Terminal::Failed {
                                buffer, op: failed, ..
                            } => {
                                assert_eq!(
                                    (buffer.offset(), failed),
                                    (offset, op),
                                    "{}",
                                    describe(&control)
                                );
                                assert_eq!(state[&offset], Held::Storage);
                                state.insert(offset, Held::App);
                                held.push(buffer);
                            }
                            Terminal::Abandoned { status, .. } => {
                                assert_eq!(state[&offset], Held::Quarantined);
                                assert!(status.is_some());
                                if op == Operation::Write
                                    && status == Some(DeviceStatus::Kernel(LEN as i32))
                                {
                                    shadow[block] = pattern;
                                }
                                state.remove(&offset);
                            }
                            Terminal::Quiesced { .. } => panic!("no stop was requested"),
                        }
                    }
                }
                7 if !held.is_empty() => {
                    let buffer = held.swap_remove(rng.below(held.len() as u64) as usize);
                    state.remove(&buffer.offset());
                    drop(buffer);
                }
                _ => {}
            }
            for kind in PoolKind::ALL {
                let pool = arena.report(kind);
                let mine = |want: Held| {
                    state
                        .iter()
                        .filter(|(offset, held)| **held == want && pool_kind(**offset) == kind)
                        .count() as u32
                };
                assert_eq!(
                    (pool.application, pool.storage, pool.quarantined),
                    (
                        mine(Held::App),
                        mine(Held::Storage),
                        mine(Held::Quarantined)
                    ),
                    "{kind:?} step {step}\n{}",
                    describe(&control)
                );
            }
            let report = table.report();
            let count = |want: Held| state.values().filter(|held| **held == want).count() as u32;
            assert_eq!(
                (report.pending, report.abandoned),
                (count(Held::Storage), count(Held::Quarantined))
            );
            conserved(&table, &arena);
        }
        assert!(
            reads > 0 && writes > 0 && reacquired > 0,
            "seed {seed}: reads {reads} writes {writes} reacquired {reacquired}"
        );
        drop(held);
        stop(&mut table, &control);
        drop(table);
        assert!(arena.release().is_ok(), "seed {seed}");
    }
}

/// The pool a backing offset belongs to, from the carving order: 16 read buffers, then 16 receive buffers, then maintenance.
fn pool_kind(offset: usize) -> PoolKind {
    match offset / LEN as usize {
        0..16 => PoolKind::ReadResponse,
        16..32 => PoolKind::ReceiveWrite,
        _ => PoolKind::Maintenance,
    }
}

#[test]
fn the_report_counts_slots_and_admission() {
    let (arena, _log) = arena();
    let (mut table, _control) = table_with(&arena, config(16), 3);
    assert_eq!(
        table.report(),
        TableReport {
            depth: 3,
            free_slots: 3,
            pending: 0,
            abandoned: 0,
            retired: 0,
            stale: 0,
            admission: Admission::Open,
        }
    );
    table.close();
    assert_eq!(table.report().admission, Admission::Closed);
}

/// After a stop, delivery walks the records in slot order and steps over free holes at zero cost in room, one event per unit of room, through poll and quiesce alike, and zero room delivers nothing.
#[test]
fn stopped_delivery_skips_holes_and_honours_room() {
    let (arena, _log) = arena();
    let (mut table, control) = table_with(&arena, config(18), 4);
    let mut tokens = Vec::new();
    for index in 0..4 {
        let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
        tokens.push(table.submit_read(buffer, block(index)).unwrap());
    }
    // Slots are issued lowest first, so `tokens[i]` holds slot `i`; finishing slot 2's command leaves a hole.
    let hole = tokens[2];
    control.post(hole);
    assert_eq!(events(&mut table, 1).len(), 1);
    control.set_quiesce(QuiesceMode::Reset);
    let mut none = Vec::new();
    assert_eq!(
        table.quiesce(&mut none),
        QuiesceProgress::Delivering { remaining: 3 }
    );
    let mut one = Vec::with_capacity(1);
    let mut order = Vec::new();
    assert_eq!(table.poll(&mut one).delivered, 1);
    order.extend(one.drain(..).map(|event| event.token().raw() & 0xFFFF));
    assert_eq!(table.report().pending, 2);
    assert_eq!(
        table.quiesce(&mut one),
        QuiesceProgress::Delivering { remaining: 1 }
    );
    order.extend(one.drain(..).map(|event| event.token().raw() & 0xFFFF));
    assert_eq!(table.poll(&mut none).delivered, 0);
    // The hole at slot 2 costs zero room, so this call delivers slot 3.
    assert_eq!(
        table.quiesce(&mut one),
        QuiesceProgress::Quiesced(Quiesced::DeviceStopped)
    );
    order.extend(one.drain(..).map(|event| event.token().raw() & 0xFFFF));
    assert_eq!(order, [0, 1, 3]);
    conserved(&table, &arena);
    drop((none, one, table));
    assert!(arena.release().is_ok());
}

#[test]
fn the_stopped_drain_finds_outstanding_slots_behind_every_empty_run() {
    let (arena, _log) = arena();
    for depth in 1..=DEPTH {
        let slots = usize::from(depth);
        for first in 0..slots {
            for second in first..slots {
                let (mut table, control) = table_with(&arena, config(u64::from(depth)), depth);
                let mut tokens = Vec::new();
                for index in 0..slots {
                    let range = block(index as u64);
                    let token = if index % 2 == 0 {
                        let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
                        table.submit_read(buffer, range).unwrap()
                    } else {
                        let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
                        table.submit_write(buffer, range).unwrap()
                    };
                    tokens.push(token);
                }
                let outstanding: Vec<usize> = if first == second {
                    vec![first]
                } else {
                    vec![first, second]
                };
                for (index, token) in tokens.iter().enumerate() {
                    if !outstanding.contains(&index) {
                        control.post(*token);
                    }
                }
                assert_eq!(events(&mut table, slots).len(), slots - outstanding.len());
                control.set_quiesce(QuiesceMode::Reset);
                let room = 1 + (first + second) % 2;
                let mut out = Vec::with_capacity(room);
                let (mut order, mut calls) = (Vec::new(), 0);
                loop {
                    calls += 1;
                    let progress = table.quiesce(&mut out);
                    for event in out.drain(..) {
                        let Terminal::Quiesced { token, op, .. } = event else {
                            panic!("{event:?}")
                        };
                        let slot = usize::from(super::slot_of(token));
                        assert_eq!(token, tokens[slot]);
                        let expected = if slot % 2 == 0 {
                            Operation::Read
                        } else {
                            Operation::Write
                        };
                        assert_eq!(op, expected);
                        order.push(slot);
                    }
                    if progress == QuiesceProgress::Quiesced(Quiesced::DeviceStopped) {
                        break;
                    }
                    assert!(
                        calls <= slots,
                        "depth {depth}: {outstanding:?} never drained"
                    );
                }
                assert_eq!(order, outstanding, "depth {depth}, room {room}");
                assert_eq!(calls, outstanding.len().div_ceil(room), "depth {depth}");
                conserved(&table, &arena);
                drop((out, table));
            }
        }
    }
    assert!(arena.release().is_ok());
}

/// A slot that issued the maximum generation and is outstanding at a proven stop retires when the stopped drain empties it; every other emptied slot counts as free.
#[test]
fn a_slot_at_the_maximum_generation_retires_in_the_stopped_drain() {
    let (arena, _log) = arena();
    let (mut table, control) = table_with(&arena, config(31), 3);
    table.set_generation(1, GENERATION_MAX - 1);
    let mut tokens = Vec::new();
    for index in 0..3 {
        let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
        tokens.push(table.submit_read(buffer, block(index)).unwrap());
    }
    // Slots are issued lowest first, so `tokens[1]` holds slot 1 at the maximum generation.
    assert_eq!(tokens[1].raw() >> 16, GENERATION_MAX);
    control.set_quiesce(QuiesceMode::Reset);
    let mut out = Vec::with_capacity(2);
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Delivering { remaining: 1 }
    );
    let report = table.report();
    assert_eq!(
        (report.free_slots, report.retired, report.pending),
        (1, 1, 1)
    );
    conserved(&table, &arena);
    out.clear();
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Quiesced(Quiesced::DeviceStopped)
    );
    let report = table.report();
    assert_eq!(
        (report.free_slots, report.retired, report.pending),
        (2, 1, 0)
    );
    conserved(&table, &arena);
    drop((out, table));
    assert!(arena.release().is_ok());
}

/// A stopped drain appends behind the events its output already holds: it fills exactly the spare room in slot order, keeps the earlier events and the output's allocation, delivers nothing into a full output, and continues after the last delivered slot.
#[test]
fn the_stopped_drain_appends_behind_earlier_events_within_spare_room() {
    let (arena, _log) = arena();
    let (mut table, control) = table_with(&arena, config(32), 6);
    let mut tokens = Vec::new();
    for index in 0..6 {
        let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
        tokens.push(table.submit_read(buffer, block(index)).unwrap());
    }
    table.cancel(tokens[3]).unwrap();
    control.post(tokens[0]);
    let mut out = Vec::with_capacity(4);
    assert_eq!(table.poll(&mut out).delivered, 1);
    let address = out.as_ptr();
    control.set_quiesce(QuiesceMode::Reset);
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Delivering { remaining: 2 }
    );
    assert_eq!((out.len(), out.capacity(), out.as_ptr()), (4, 4, address));
    assert!(matches!(&out[0], Terminal::Read { token, .. } if *token == tokens[0]));
    assert!(matches!(&out[1], Terminal::Quiesced { token, .. } if *token == tokens[1]));
    assert!(matches!(&out[2], Terminal::Quiesced { token, .. } if *token == tokens[2]));
    assert!(
        matches!(&out[3], Terminal::Abandoned { token, status: None, .. } if *token == tokens[3])
    );
    assert_eq!(table.poll(&mut out).delivered, 0);
    assert_eq!(out.len(), 4);
    conserved(&table, &arena);
    out.truncate(3);
    assert_eq!(table.poll(&mut out).delivered, 1);
    assert_eq!((out.len(), out.capacity(), out.as_ptr()), (4, 4, address));
    assert!(matches!(&out[0], Terminal::Read { token, .. } if *token == tokens[0]));
    assert!(matches!(&out[3], Terminal::Quiesced { token, .. } if *token == tokens[4]));
    out.clear();
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Quiesced(Quiesced::DeviceStopped)
    );
    assert!(matches!(out.as_slice(), [Terminal::Quiesced { token, .. }] if *token == tokens[5]));
    conserved(&table, &arena);
    drop((out, table));
    assert!(arena.release().is_ok());
}

/// A read of 4 KiB into a 16 KiB buffer presents exactly those 4 KiB as read-done evidence; the rest of the buffer keeps its previous bytes.
#[test]
fn read_done_covers_exactly_the_requested_length() {
    let (arena, _log) = arena();
    let (mut table, control) = table(&arena, 19);
    control.write_device(0, &[0xAB; 4096]);
    let mut buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    buffer.bytes_mut().fill(0x77);
    let token = table
        .submit_read(buffer, DeviceRange::new(0, 4096).unwrap())
        .unwrap();
    control.post(token);
    let Some(Terminal::Read { done, .. }) = events(&mut table, 1).pop() else {
        panic!("{}", control.describe())
    };
    assert_eq!(done.read_len(), 4096);
    assert_eq!(done.bytes(), &[0xAB; 4096][..]);
    let buffer = done.into_buffer();
    assert!(buffer.bytes()[4096..].iter().all(|byte| *byte == 0x77));
    drop((buffer, table));
    assert!(arena.release().is_ok());
}

/// Completions posted in reverse order pair each token with its own buffer, bytes and status.
#[test]
fn reordered_completions_pair_each_token_with_its_own_buffer() {
    let (arena, _log) = arena();
    let (mut table, control) = table(&arena, 20);
    control.write_device(0, &[0x01; LEN as usize]);
    control.write_device(LEN as usize, &[0x02; LEN as usize]);
    let mut expected = Vec::new();
    for index in 0..2u64 {
        let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
        let offset = buffer.offset();
        let token = table.submit_read(buffer, block(index)).unwrap();
        expected.push((token, offset, index as u8 + 1));
    }
    let mut writes = Vec::new();
    for index in 2..4u64 {
        let mut buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
        buffer.bytes_mut().fill(0x40 + index as u8);
        let offset = buffer.offset();
        let token = table.submit_write(buffer, block(index)).unwrap();
        writes.push((token, offset, index));
    }
    control.fault(writes[0].0, Fault::Status(DeviceStatus::Kernel(-28)));
    for (token, _, _) in writes.iter().rev() {
        control.post(*token);
    }
    for (token, _, _) in expected.iter().rev() {
        control.post(*token);
    }
    for event in events(&mut table, 8) {
        match event {
            Terminal::Read {
                token,
                done,
                status,
            } => {
                let (_, offset, pattern) = expected.iter().find(|(t, _, _)| *t == token).unwrap();
                assert_eq!(status, DeviceStatus::Kernel(LEN as i32));
                assert!(done.bytes().iter().all(|byte| byte == pattern));
                assert_eq!(done.into_buffer().offset(), *offset);
            }
            Terminal::Written {
                token,
                buffer,
                status,
            } => {
                assert_eq!(token, writes[1].0);
                assert_eq!(status, DeviceStatus::Kernel(LEN as i32));
                assert_eq!(buffer.offset(), writes[1].1);
            }
            Terminal::Failed {
                token,
                buffer,
                status,
                op,
                ..
            } => {
                assert_eq!(
                    (token, op, status),
                    (writes[0].0, Operation::Write, DeviceStatus::Kernel(-28))
                );
                assert_eq!(buffer.offset(), writes[0].1);
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(
        control.device(3 * LEN as usize, LEN as usize),
        vec![0x43; LEN as usize]
    );
    assert_eq!(
        control.device(2 * LEN as usize, LEN as usize),
        vec![0; LEN as usize]
    );
    drop(table);
    assert!(arena.release().is_ok());
}

/// A table dropped while a cancelled command is still in flight leaves its buffer quarantined forever, which blocks release without an unmap.
#[test]
fn a_dropped_table_keeps_a_quarantined_buffer_held() {
    let (arena, log) = arena();
    let (mut table, _control) = table(&arena, 21);
    let buffer = arena.acquire(PoolKind::Maintenance).unwrap();
    let token = table
        .submit_read(buffer, DeviceRange::new(0, 4096).unwrap())
        .unwrap();
    table.cancel(token).unwrap();
    drop(table);
    assert_eq!(arena.report(PoolKind::Maintenance).quarantined, 1);
    let blocked = arena.release().unwrap_err();
    assert_eq!(blocked.held[2], (PoolKind::Maintenance, 1));
    assert!(log.calls(Op::Unmap).is_empty());
}

/// After a proven stop, an undelivered command cannot be cancelled, and delivering it, servicing the table or admitting the medium makes no driver call; an open table forwards the admission.
#[test]
fn after_a_stop_cancel_is_stale_and_the_driver_is_never_called() {
    let (arena, _log) = arena();
    let (mut table, control) = table(&arena, 22);
    let before_admission = control.driver_calls();
    table.admit_medium(&crate::storage::Fenced::assumed());
    assert_eq!(
        control.driver_calls(),
        before_admission + 1,
        "an open table forwards the admission"
    );
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let token = table.submit_read(buffer, block(0)).unwrap();
    control.set_quiesce(QuiesceMode::Reset);
    let mut none = Vec::new();
    assert_eq!(
        table.quiesce(&mut none),
        QuiesceProgress::Delivering { remaining: 1 }
    );
    let calls = control.driver_calls();
    let before = table.report();
    assert_eq!(table.cancel(token), Err(Stale));
    assert_eq!(table.report(), before);
    assert_eq!(arena.report(PoolKind::ReadResponse).storage, 1);
    let mut out = Vec::with_capacity(1);
    assert_eq!(table.poll(&mut none).delivered, 0);
    makes_no_driver_call(&mut table, &control, calls);
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Quiesced(Quiesced::DeviceStopped)
    );
    assert!(matches!(out.pop(), Some(Terminal::Quiesced { token: t, .. }) if t == token));
    table.service_disk();
    assert_eq!(control.driver_calls(), calls);
    drop((none, out, table));
    assert!(arena.release().is_ok());
}

/// Services the table, then admits the medium, and asserts after each that the driver saw no call beyond the `calls`
/// it had seen.
fn makes_no_driver_call(table: &mut CommandTable<'_, SimDisk>, control: &SimControl, calls: usize) {
    table.service_disk();
    assert_eq!(
        control.driver_calls(),
        calls,
        "a stopped table services no driver"
    );
    table.admit_medium(&crate::storage::Fenced::assumed());
    assert_eq!(
        control.driver_calls(),
        calls,
        "a stopped table admits no medium"
    );
}

/// The planted missing stop: a table that holds an accepted read and made no stop services the sim disk, the driver
/// call a stopped table whose service lost its guard would make, and the stopped table's service check rejects it.
#[test]
#[should_panic(expected = "a stopped table services no driver")]
fn negative_control_a_table_with_no_stop_calls_the_driver() {
    let (arena, _log) = arena();
    let (mut table, control) = table(&arena, 22);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    table.submit_read(buffer, block(0)).unwrap();
    let calls = control.driver_calls();
    makes_no_driver_call(&mut table, &control, calls);
}

/// A submit of a buffer a device still reads stops at its precondition assertion before it takes a slot or calls the driver.
#[test]
fn a_submit_of_a_device_held_buffer_fails_its_precondition_before_the_driver() {
    let (arena, _log) = arena();
    let (mut table, control) = table(&arena, 23);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let held = buffer.source(0..4096).unwrap().hold().unwrap();
    let (calls, before) = (control.driver_calls(), table.report());
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = table.submit_read(buffer, block(0));
    }));
    let message = caught.expect_err("the submit asserts its precondition");
    assert_eq!(
        message.downcast_ref::<&str>(),
        Some(&"a buffer a device reads takes no device write")
    );
    assert_eq!((control.driver_calls(), table.report()), (calls, before));
    drop(held);
    assert_eq!(arena.report(PoolKind::ReadResponse).nic_held, 0);
    drop(table);
    assert!(arena.release().is_ok());
}

/// A table whose only slot holds a cancelled command refuses table-full with its abandoned count, after every earlier check, without a driver call.
#[test]
fn a_quarantine_full_table_refuses_with_its_abandoned_count() {
    let (arena, _log) = arena();
    let (other, _) = self::arena();
    let (mut table, control) = table_with(&arena, config(23), 1);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let token = table.submit_read(buffer, block(0)).unwrap();
    table.cancel(token).unwrap();
    let calls = control.driver_calls();
    let foreign = other.acquire(PoolKind::ReadResponse).unwrap();
    assert_eq!(
        refused(table.submit_read(foreign, block(1))).1,
        Refusal::ForeignArena
    );
    let beyond = DeviceRange::new(64 * u64::from(LEN), LEN).unwrap();
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let (buffer, refusal) = refused(table.submit_read(buffer, beyond));
    assert_eq!(refusal, Refusal::OutOfCapacity);
    let offset = buffer.offset();
    let (buffer, refusal) = refused(table.submit_read(buffer, block(1)));
    assert_eq!(refusal, Refusal::TableFull { abandoned: 1 });
    assert_eq!(buffer.offset(), offset);
    assert_eq!(control.driver_calls(), calls);
    assert_eq!(arena.report(PoolKind::ReadResponse).quarantined, 1);
    conserved(&table, &arena);
    drop(buffer);
    stop(&mut table, &control);
    drop(table);
    assert!(arena.release().is_ok());
    assert!(other.release().is_ok());
}

/// Every driver refusal reason returns the same buffer with its bytes, leaves nothing pending, moves no device bytes, and produces no event.
#[test]
fn every_driver_refusal_owns_nothing_and_moves_nothing() {
    for reason in [
        RefusalReason::QueueFull,
        RefusalReason::InvalidRange,
        RefusalReason::DeviceGone,
    ] {
        let (arena, _log) = arena();
        let (mut table, control) = table(&arena, 24);
        control.write_device(0, &[0xD0; LEN as usize]);
        let mut buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
        buffer.bytes_mut().fill(0x3C);
        let offset = buffer.offset();
        let scripted = SubmitRefusal {
            reason,
            code: Some(-3),
        };
        control.refuse_next(scripted);
        let (buffer, refusal) = refused(table.submit_write(buffer, block(0)));
        assert_eq!(refusal, Refusal::Device(scripted));
        assert_eq!(buffer.offset(), offset);
        assert!(buffer.bytes().iter().all(|byte| *byte == 0x3C));
        let report = table.report();
        assert_eq!((report.pending, report.free_slots), (0, u32::from(DEPTH)));
        assert_eq!(arena.report(PoolKind::ReceiveWrite).application, 1);
        control.tick(4);
        assert!(events(&mut table, 4).is_empty());
        assert_eq!(control.device(0, LEN as usize), vec![0xD0; LEN as usize]);
        let lost = reason == RefusalReason::DeviceGone;
        assert_eq!(table.report().admission == Admission::Lost, lost);
        drop((buffer, table));
        assert!(arena.release().is_ok());
    }
}

/// Poll counts only spare room: with two events already in an output of four, it picks the two completions that room
/// holds and leaves a stale one behind them queued, delivers nothing while the output is full, then the rest.
#[test]
fn poll_uses_spare_room_not_capacity() {
    spare_room_of_an_output_of(4);
}

/// The planted capacity: an output of five has room for three beside the two events it holds, so the second poll
/// picks the two completions and the stale one queued behind them, the pick a poll that took an output of four's
/// capacity for its room makes, and the spare-room check rejects it.
#[test]
#[should_panic(expected = "the second poll picks only up to the output's spare room")]
fn negative_control_an_output_of_five_lets_the_second_poll_pick_the_stale_completion() {
    spare_room_of_an_output_of(5);
}

/// Five reads polled into an output of `capacity`: two complete and deliver; two more complete with a stale
/// completion queued behind them, and the second poll picks the two an output of four has room for; the last read
/// completes and a poll of the full output delivers nothing; after the output is cleared one poll picks the stale
/// completion and delivers the last read. The expected counts are an output of four's for every `capacity`.
fn spare_room_of_an_output_of(capacity: usize) {
    let (arena, _log) = arena();
    let (mut table, control) = table(&arena, 25);
    for index in 0..5 {
        let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
        table.submit_read(buffer, block(index)).unwrap();
    }
    control.tick(2);
    let mut out = Vec::with_capacity(capacity);
    assert_eq!(table.poll(&mut out).delivered, 2);
    control.tick(2);
    control.inject(
        Completion {
            token: CommandToken::from_raw(2 << 16 | 19),
            status: DeviceStatus::Kernel(LEN as i32),
        },
        Injection::Foreign,
    );
    let second = table.poll(&mut out);
    assert_eq!(
        second.delivered, 2,
        "the second poll delivers the two completions posted before it"
    );
    assert_eq!(
        second,
        PollReport {
            delivered: 2,
            stale: 0
        },
        "the second poll picks only up to the output's spare room"
    );
    control.tick(1);
    assert_eq!(table.poll(&mut out).delivered, 0);
    assert_eq!(out.len(), 4);
    out.clear();
    assert_eq!(
        table.poll(&mut out),
        PollReport {
            delivered: 1,
            stale: 1
        }
    );
    assert_eq!(out.capacity(), capacity);
    assert_eq!(control.outstanding(), 0);
    drop((out, table));
    assert!(arena.release().is_ok());
}

/// Through the table: a dropped command, a halted device and bytes executed before their completion posts all keep the buffer storage-owned with no event until a completion or a proven stop.
#[test]
fn undelivered_commands_keep_their_buffers_owned() {
    let (arena, _log) = arena();
    let (mut table, control) = table(&arena, 26);
    let dropped = table
        .submit_read(arena.acquire(PoolKind::ReadResponse).unwrap(), block(0))
        .unwrap();
    let halted = table
        .submit_read(arena.acquire(PoolKind::ReadResponse).unwrap(), block(1))
        .unwrap();
    let executed = table
        .submit_read(arena.acquire(PoolKind::ReadResponse).unwrap(), block(2))
        .unwrap();
    control.fault(dropped, Fault::DropCommand);
    control.post(dropped);
    control.execute(executed);
    control.set_halted(true);
    control.tick(4);
    for _ in 0..3 {
        assert!(events(&mut table, 4).is_empty());
        assert_eq!(table.report().pending, 3);
        assert_eq!(arena.report(PoolKind::ReadResponse).storage, 3);
    }
    control.set_halted(false);
    control.post(executed);
    control.tick(4);
    let tokens: Vec<_> = events(&mut table, 4).iter().map(Terminal::token).collect();
    assert_eq!(tokens.len(), 2);
    assert!(tokens.contains(&halted) && tokens.contains(&executed));
    assert_eq!(table.report().pending, 1);
    stop(&mut table, &control);
    drop(table);
    assert!(arena.release().is_ok());
}

/// Draining after a proven stop allocates nothing, for attached and detached records alike.
#[test]
fn the_stopped_drain_allocates_nothing() {
    let (arena, _log) = arena();
    let (mut table, control) = table(&arena, 27);
    let mut tokens = Vec::new();
    for index in 0..6 {
        let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
        tokens.push(table.submit_write(buffer, block(index)).unwrap());
    }
    for token in tokens.iter().step_by(2) {
        table.cancel(*token).unwrap();
    }
    control.set_quiesce(QuiesceMode::Reset);
    let mut out = Vec::with_capacity(1);
    let before = crate::instrument::allocations();
    let mut progress = table.quiesce(&mut out);
    for _ in 0..8 {
        if progress == QuiesceProgress::Quiesced(Quiesced::DeviceStopped) {
            break;
        }
        out.clear();
        table.poll(&mut out);
        out.clear();
        progress = table.quiesce(&mut out);
    }
    assert_eq!(progress, QuiesceProgress::Quiesced(Quiesced::DeviceStopped));
    out.clear();
    assert_eq!(crate::instrument::allocations(), before);
    drop((out, table));
    assert!(arena.release().is_ok());
}

/// `disk_mut` lends the driver only once admission leaves `Open`, so an open table reaches driver housekeeping through `service_disk`.
#[test]
fn an_open_table_services_its_driver() {
    struct Services {
        calls: usize,
    }
    // SAFETY: every submit is refused, so no command is ever accepted or reported.
    unsafe impl super::Disk for Services {
        fn geometry(&self) -> super::DeviceGeometry {
            super::DeviceGeometry {
                capacity: 1 << 20,
                max_transfer: LEN,
                block_size: 4096,
                queue_depth: 4,
            }
        }
        unsafe fn submit_read(
            &mut self,
            _: CommandToken,
            _: DeviceRange,
            _: super::DmaRange,
        ) -> Result<(), SubmitRefusal> {
            Err(SubmitRefusal {
                reason: RefusalReason::QueueFull,
                code: None,
            })
        }
        unsafe fn submit_write(
            &mut self,
            _: CommandToken,
            _: DeviceRange,
            _: super::DmaRange,
        ) -> Result<(), SubmitRefusal> {
            Err(SubmitRefusal {
                reason: RefusalReason::QueueFull,
                code: None,
            })
        }
        fn pick_completions(&mut self, _: &mut super::CompletionSink<'_>) {}
        fn quiesce(&mut self) -> super::QuiesceStatus {
            super::QuiesceStatus::Pending
        }
        fn service(&mut self) {
            self.calls += 1;
        }
    }
    let (arena, _log) = arena();
    let mut table = CommandTable::new(
        Services { calls: 0 },
        &arena,
        4,
        &mut EngineBudget::new(usize::MAX),
    )
    .map_err(|(error, _)| error)
    .unwrap();
    assert!(table.disk_mut().is_none());
    table.service_disk();
    table.close();
    assert_eq!(table.disk_mut().map(|disk| disk.calls), Some(1));
}

/// A reserved command whose driver call never returned matches no completion, even one carrying its exact token.
#[test]
fn a_reserved_command_ignores_a_completion_with_its_token() {
    struct Reports {
        done: Option<Completion>,
    }
    // SAFETY: `submit_read` never returns, so no command is accepted; the completion it queues first models a device that reports the reserved command anyway, which the table must treat as stale.
    unsafe impl super::Disk for Reports {
        fn geometry(&self) -> super::DeviceGeometry {
            super::DeviceGeometry {
                capacity: 1 << 20,
                max_transfer: LEN,
                block_size: 4096,
                queue_depth: 4,
            }
        }
        unsafe fn submit_read(
            &mut self,
            token: CommandToken,
            _: DeviceRange,
            _: super::DmaRange,
        ) -> Result<(), SubmitRefusal> {
            self.done = Some(Completion {
                token,
                status: DeviceStatus::Kernel(LEN as i32),
            });
            panic!("driver failure")
        }
        unsafe fn submit_write(
            &mut self,
            _: CommandToken,
            _: DeviceRange,
            _: super::DmaRange,
        ) -> Result<(), SubmitRefusal> {
            panic!("driver failure")
        }
        fn pick_completions(&mut self, sink: &mut super::CompletionSink<'_>) {
            if let Some(done) = self.done.take() {
                let _ = sink.push(done);
            }
        }
        fn quiesce(&mut self) -> super::QuiesceStatus {
            super::QuiesceStatus::Pending
        }
    }
    let (arena, _log) = arena();
    let mut table = CommandTable::new(
        Reports { done: None },
        &arena,
        4,
        &mut EngineBudget::new(usize::MAX),
    )
    .map_err(|(error, _)| error)
    .unwrap();
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = table.submit_read(buffer, block(0));
    }));
    assert!(caught.is_err());
    let mut out = Vec::with_capacity(4);
    let report = table.poll(&mut out);
    assert_eq!((report.delivered, report.stale), (0, 1));
    assert_eq!(table.report().pending, 1);
    assert_eq!(arena.report(PoolKind::ReadResponse).storage, 1);
    drop((out, table));
    assert!(arena.release().is_err());
}

/// A pick that unwinds after pushing completions leaves them for no later poll: the next poll delivers only what its own pick returns, within its room, and the unwound pick's commands stay pending with their buffers owned.
#[test]
fn a_pick_that_unwinds_leaves_no_completion_for_the_next_poll() {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    struct Unwinds {
        done: VecDeque<Completion>,
        panic_after_push: Rc<Cell<bool>>,
    }
    // SAFETY: an accepted read touches no memory and queues its one completion; a pick pushes queued completions within the sink's limit, and when armed it unwinds after pushing them, which drops them from the device; nothing is ever stopped.
    unsafe impl super::Disk for Unwinds {
        fn geometry(&self) -> super::DeviceGeometry {
            super::DeviceGeometry {
                capacity: 1 << 20,
                max_transfer: LEN,
                block_size: 4096,
                queue_depth: 4,
            }
        }
        unsafe fn submit_read(
            &mut self,
            token: CommandToken,
            _: DeviceRange,
            _: super::DmaRange,
        ) -> Result<(), SubmitRefusal> {
            self.done.push_back(Completion {
                token,
                status: DeviceStatus::Kernel(LEN as i32),
            });
            Ok(())
        }
        unsafe fn submit_write(
            &mut self,
            _: CommandToken,
            _: DeviceRange,
            _: super::DmaRange,
        ) -> Result<(), SubmitRefusal> {
            Err(SubmitRefusal {
                reason: RefusalReason::InvalidRange,
                code: None,
            })
        }
        fn pick_completions(&mut self, sink: &mut super::CompletionSink<'_>) {
            while let Some(done) = self.done.pop_front() {
                if let Err(kept) = sink.push(done) {
                    self.done.push_front(kept);
                    break;
                }
            }
            if self.panic_after_push.get() {
                panic!("driver failure")
            }
        }
        fn quiesce(&mut self) -> super::QuiesceStatus {
            super::QuiesceStatus::Pending
        }
    }
    let (arena, _log) = arena();
    let armed = Rc::new(Cell::new(false));
    let disk = Unwinds {
        done: VecDeque::with_capacity(4),
        panic_after_push: Rc::clone(&armed),
    };
    let mut table = CommandTable::new(disk, &arena, 4, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap();
    for index in 0..2 {
        let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
        table.submit_read(buffer, block(index)).unwrap();
    }
    armed.set(true);
    let mut out = Vec::with_capacity(4);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        table.poll(&mut out);
    }));
    assert!(caught.is_err());
    assert!(out.is_empty());
    armed.set(false);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let third = table.submit_read(buffer, block(2)).unwrap();
    let mut room = Vec::with_capacity(1);
    let report = table.poll(&mut room);
    assert_eq!((report.delivered, report.stale), (1, 0));
    assert!(matches!(&room[..], [Terminal::Read { token, .. }] if *token == third));
    drop(room);
    let report = table.report();
    assert_eq!((report.pending, report.free_slots), (2, 2));
    assert_eq!(arena.report(PoolKind::ReadResponse).storage, 2);
    assert_eq!(table.poll(&mut Vec::with_capacity(4)).delivered, 0);
    drop((out, table));
    assert!(arena.release().is_err());
}

/// After close and a drained quiesce, a delivered command's token is stale to cancel.
#[test]
fn cancel_after_a_closed_drain_is_stale() {
    let (arena, _log) = arena();
    let (mut table, control) = table(&arena, 28);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let token = table.submit_read(buffer, block(0)).unwrap();
    table.close();
    control.post(token);
    let mut out = Vec::with_capacity(1);
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Quiesced(Quiesced::AllReturned)
    );
    assert_eq!(table.cancel(token), Err(Stale));
    drop((out, table));
    assert!(arena.release().is_ok());
}

/// When a driver declares reservation limits and uses the trait's default Report identity check, the check refuses every Report, so `reservation_report` withholds its entries as ownership evidence.
#[test]
fn a_driver_without_a_report_check_has_every_report_withheld() {
    struct Declares;
    // SAFETY: no method submits a command or touches memory; the test calls only the identity check.
    unsafe impl super::Disk for Declares {
        fn geometry(&self) -> super::DeviceGeometry {
            super::DeviceGeometry {
                capacity: 1 << 20,
                max_transfer: LEN,
                block_size: 4096,
                queue_depth: 4,
            }
        }
        fn reservation_limits(&self) -> Option<super::ReservationLimits> {
            Some(super::ReservationLimits::new(2, 2, 10, 10).unwrap())
        }
        unsafe fn submit_read(
            &mut self,
            _: CommandToken,
            _: DeviceRange,
            _: super::DmaRange,
        ) -> Result<(), SubmitRefusal> {
            unreachable!("the check never submits")
        }
        unsafe fn submit_write(
            &mut self,
            _: CommandToken,
            _: DeviceRange,
            _: super::DmaRange,
        ) -> Result<(), SubmitRefusal> {
            unreachable!("the check never submits")
        }
        fn pick_completions(&mut self, _: &mut super::CompletionSink<'_>) {}
        fn quiesce(&mut self) -> super::QuiesceStatus {
            super::QuiesceStatus::Pending
        }
    }
    assert_eq!(
        super::Disk::check_reservation_report(&Declares, &[0; 64]),
        Err(super::ReportError::Unchecked)
    );
}

/// The command table's source text, for the tests of its documentation.
const TABLE_SOURCE: &str = include_str!("table.rs");

/// The lines of the table's module documentation, without their `//!` markers.
fn module_doc() -> String {
    TABLE_SOURCE
        .lines()
        .take_while(|line| line.starts_with("//!"))
        .map(|line| line.trim_start_matches("//!").trim())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The doc comment lines directly above the first line of the table's source that equals `item` after trimming.
fn doc_above(item: &str) -> String {
    let lines: Vec<&str> = TABLE_SOURCE.lines().map(str::trim).collect();
    let at = lines
        .iter()
        .position(|line| *line == item)
        .unwrap_or_else(|| panic!("the table's source holds no line {item:?}"));
    let first = lines[..at]
        .iter()
        .rposition(|line| !line.starts_with("///"))
        .map_or(0, |before| before + 1);
    lines[first..at].join("\n")
}

/// A completion that matches a timed-out Report frees its slot and counts as delivered, as it does for every accepted or detached command. The test requires the module documentation's exact-token sentence and fails on three literal phrases that except a timed-out Report from it: one that holds the slot until proven stop, one that counts matching late completions as stale, and one that names the exception.
#[test]
fn the_module_doc_excepts_no_timed_out_report_from_the_exact_token_rule() {
    let doc = module_doc();
    assert!(
        doc.contains("A completion changes state only for an accepted or detached command with the exact token"),
        "the module documentation states which completions change state"
    );
    for stale in [
        "A timed-out Report holds its slot and quarantined buffer until proven stop",
        "matching late completions count as stale",
        "except a timed-out Report",
    ] {
        assert!(
            !doc.contains(stale),
            "the module documentation says {stale:?}, and the table delivers a timed-out Report's late terminal and frees its slot"
        );
    }
}

/// A poll counts a completion that matches a timed-out Report as delivered. The test requires the documentation of `PollReport::stale` and of `TableReport::stale` to hold the words `Completions that matched no accepted`, and fails on one literal phrase for each field that adds a timed-out Report's completion to that counter.
#[test]
fn the_stale_counters_do_not_claim_a_timed_out_reports_completion() {
    for (item, stale) in [
        (
            "pub stale: usize,",
            "matching late completions of timed-out Reports",
        ),
        ("pub stale: u64,", "or matched a timed-out Report"),
    ] {
        let doc = doc_above(item);
        assert!(
            doc.contains("Completions that matched no accepted"),
            "the field {item:?} documents what it counts: {doc}"
        );
        assert!(
            !doc.contains(stale),
            "the documentation of {item:?} says {stale:?}, and a poll counts that completion as delivered"
        );
    }
}
