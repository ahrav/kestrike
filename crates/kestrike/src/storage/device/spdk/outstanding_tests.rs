use std::time::Duration;

use super::super::super::ledger::EngineBudget;
use super::super::super::os::HugepageSize;
use super::super::super::placement::NodeMask;
use super::super::super::test_platform::TestPlatform;
use super::super::status::DeviceStatus;
use super::super::{
    BufferArena, BufferConfig, CommandTable, CommandToken, DeviceRange, Operation, PoolKind,
    PoolSpec, Refusal, Terminal,
};
use super::disk::{CanaryError, SpdkDisk};
use super::disk_tests::{SCRIPT, Scripted, limits};
use crate::native::{Environment, registration_tests};

const LEN: u32 = 4096;
const READ: PoolKind = PoolKind::ReadResponse;
const WRITE: PoolKind = PoolKind::ReceiveWrite;
/// `INTERNAL_ERROR` encodes NVMe's generic internal error in completion-status bits.
const INTERNAL_ERROR: u16 = 0x0006 << 1;

pub(super) fn arena() -> BufferArena<TestPlatform> {
    let pools = [READ, WRITE].map(|kind| PoolSpec {
        kind,
        count: 4,
        buffer_len: LEN,
    });
    let validated = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &pools,
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

fn outstanding<'a>(
    arena: &'a BufferArena<TestPlatform>,
    address: &str,
) -> (CommandTable<'a, SpdkDisk<'a, Scripted>>, [CommandToken; 2]) {
    SCRIPT.take();
    let mut disk = SpdkDisk::<Scripted>::scripted(address, limits(2));
    let probe = arena.acquire(READ).unwrap();
    disk.mark_verified(probe.range(LEN).unwrap());
    drop(probe);
    let mut table = CommandTable::new(disk, arena, 2, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap();
    let read = table
        .submit_read(
            arena.acquire(READ).unwrap(),
            DeviceRange::new(0, LEN).unwrap(),
        )
        .unwrap();
    let write = table
        .submit_write(
            arena.acquire(WRITE).unwrap(),
            DeviceRange::new(u64::from(LEN), LEN).unwrap(),
        )
        .unwrap();
    (table, [read, write])
}

fn storage_held(arena: &BufferArena<TestPlatform>) -> (u32, u32) {
    (arena.report(READ).storage, arena.report(WRITE).storage)
}

#[test]
fn a_report_only_timeout_retains_every_command_and_bounds_admission() {
    let arena = arena();
    let (mut table, tokens) = outstanding(&arena, "scripted:report-only-timeout");
    let before = tokens.map(|token| table.evidence(token).unwrap());
    assert_eq!(
        before.map(|evidence| (evidence.operation, evidence.accepted)),
        [(Operation::Read, true), (Operation::Write, true)]
    );
    SCRIPT.with_borrow_mut(|script| script.poll.extend([(0, false), (0, false)]));
    table.driver().report_timeout(7);
    let mut out = Vec::with_capacity(2);
    assert_eq!(table.poll(&mut out).delivered, 0);
    assert_eq!(table.poll(&mut out).delivered, 0);
    let (reports, last) = table.driver().timeouts();
    assert_eq!((reports, last.map(|(_, cid)| cid)), (1, Some(7)));
    assert_eq!(
        tokens.map(|token| table.evidence(token)),
        before.map(Some),
        "a timeout report changes no command's custody"
    );
    assert_eq!(storage_held(&arena), (1, 1));
    let refused = table
        .submit_read(
            arena.acquire(READ).unwrap(),
            DeviceRange::new(0, LEN).unwrap(),
        )
        .unwrap_err();
    assert_eq!(
        refused.refusal,
        Refusal::TableFull { abandoned: 0 },
        "the retained commands bound admission; no DeviceGone is inferred"
    );
    drop(refused);
    assert_eq!(table.poll(&mut out).delivered, 2);
    assert!(matches!(out[0], Terminal::Read { token, .. } if token == tokens[0]));
    assert!(matches!(out[1], Terminal::Written { token, .. } if token == tokens[1]));
    assert_eq!(tokens.map(|token| table.evidence(token)), [None, None]);
}

#[test]
fn an_expired_read_keeps_its_buffer_and_slot_until_the_late_terminal_without_exposing_bytes() {
    let arena = arena();
    let (mut table, [read, write]) = outstanding(&arena, "scripted:application-expiry");
    let incarnation = table.evidence(read).unwrap().buffer;
    SCRIPT.with_borrow_mut(|script| script.poll.extend([(0, false), (0, false)]));
    let mut out = Vec::with_capacity(2);
    assert_eq!(table.poll(&mut out).delivered, 0);
    table.cancel(read).unwrap();
    let expired = table.evidence(read).unwrap();
    assert_eq!(
        (expired.accepted, expired.buffer),
        (false, incarnation),
        "the expired read stays detached on its buffer incarnation"
    );
    assert_eq!(table.poll(&mut out).delivered, 0);
    assert_eq!(arena.report(READ).quarantined, 1);
    let report = table.report();
    assert_eq!(
        (report.pending, report.abandoned),
        (1, 1),
        "the expired read keeps its slot"
    );
    SCRIPT.with_borrow_mut(|script| script.status.push_back(INTERNAL_ERROR));
    table.poll(&mut out);
    assert!(
        matches!(out[0], Terminal::Abandoned { token, op: Operation::Read, status: Some(DeviceStatus::Nvme(raw)) }
            if token == read && raw == INTERNAL_ERROR),
        "the late terminal ends the expired read with its raw status and no read view: {:?}",
        out[0]
    );
    assert!(matches!(out[1], Terminal::Written { token, .. } if token == write));
    out.clear();
    let report = table.report();
    assert_eq!(
        (
            arena.report(READ).quarantined,
            arena.report(READ).storage,
            report.pending,
            report.abandoned
        ),
        (0, 0, 0, 0)
    );
    let reused = table
        .submit_read(
            arena.acquire(READ).unwrap(),
            DeviceRange::new(0, LEN).unwrap(),
        )
        .unwrap();
    let after = table.evidence(reused).unwrap().buffer;
    assert!(
        after.0 != incarnation.0 || after.1 != incarnation.1 || after.2 > incarnation.2,
        "a reused buffer carries a later incarnation"
    );
}

/// The driver delivers each NVMe status word unchanged as `Nvme(raw)`: the
/// rewritten failure word reaches the failed read's terminal, and the
/// scripted success word reaches the write's.
#[test]
fn a_rewritten_status_reaches_the_failed_terminal_unchanged() {
    let arena = arena();
    let (mut table, [read, write]) = outstanding(&arena, "scripted:status-rewrite");
    let raw = INTERNAL_ERROR | 0x8000;
    let success = 0x0001;
    SCRIPT.with_borrow_mut(|script| script.status.extend([raw, success]));
    let mut out = Vec::with_capacity(2);
    assert_eq!(table.poll(&mut out).delivered, 2);
    assert!(
        matches!(out[0], Terminal::Failed { token, op: Operation::Read, status: DeviceStatus::Nvme(found), .. }
            if token == read && found == raw),
        "{:?}",
        out[0]
    );
    assert!(
        matches!(out[1], Terminal::Written { token, status: DeviceStatus::Nvme(found), .. }
            if token == write && found == success),
        "{:?}",
        out[1]
    );
}

#[test]
fn a_canary_timeout_turns_the_driver_gone_and_holds_its_buffer() {
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    SCRIPT.take();
    let mut disk = SpdkDisk::<Scripted>::scripted_leased(
        "scripted:canary-timeout",
        limits(2),
        &mut registration,
    );
    SCRIPT.with_borrow_mut(|script| script.poll.extend(std::iter::repeat_n((0, false), 1 << 22)));
    let before = arena.report(PoolKind::ReceiveWrite).application;
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    assert_eq!(
        disk.canary(&registration, buffer, Duration::from_millis(1))
            .unwrap_err(),
        CanaryError::Timeout
    );
    assert_eq!(
        arena.report(PoolKind::ReceiveWrite).application,
        before + 1,
        "the device may still write the canary's buffer, so it stays held"
    );
    assert!(
        format!("{disk:?}").contains("state: Gone(None)"),
        "the canary timeout, unlike a report-only timeout, ends the driver: {disk:?}"
    );
}

#[test]
fn a_controller_reset_with_reads_and_writes_outstanding_proves_no_stop_until_valid_registers_do() {
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    SCRIPT.take();
    let mut disk =
        SpdkDisk::<Scripted>::scripted_leased("scripted:reset", limits(2), &mut registration);
    let probe = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    disk.mark_verified(probe.range(LEN).unwrap());
    drop(probe);
    let mut table = CommandTable::new(disk, &arena, 2, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap();
    let read = table
        .submit_read(
            arena.acquire(PoolKind::ReadResponse).unwrap(),
            DeviceRange::new(0, LEN).unwrap(),
        )
        .unwrap();
    let write = table
        .submit_write(
            arena.acquire(PoolKind::ReceiveWrite).unwrap(),
            DeviceRange::new(u64::from(LEN), LEN).unwrap(),
        )
        .unwrap();
    let evidence = [read, write].map(|token| table.evidence(token).unwrap());
    let held = |arena: &BufferArena<TestPlatform>| {
        (
            arena.report(PoolKind::ReadResponse).storage,
            arena.report(PoolKind::ReceiveWrite).storage,
        )
    };
    // The reset fails the controller: the disconnect refuses, and every register read returns all ones.
    SCRIPT.with_borrow_mut(|script| {
        script.failed.push_back(true);
        script.poll.push_back((0, false));
        script.disconnect.push_back(-libc::ENODEV);
        script.registers.extend([(u32::MAX, u32::MAX); 6]);
    });
    let mut out = Vec::with_capacity(2);
    assert_eq!(table.poll(&mut out).delivered, 0);
    for call in 0..6 {
        let progress = table.quiesce(&mut out);
        assert!(
            !matches!(progress, super::super::QuiesceProgress::Quiesced(_)),
            "call {call}: all-ones registers prove no stop: {progress:?}"
        );
        assert!(out.is_empty(), "call {call}");
        assert_eq!(held(&arena), (1, 1), "call {call}: both buffers stay held");
        assert!(
            table.driver_witness().leased,
            "call {call}: the lease stays held"
        );
        assert_eq!(
            [read, write].map(|token| table.evidence(token)),
            evidence.map(Some),
            "call {call}"
        );
    }
    assert!(
        table.driver().stop_proof().is_none(),
        "an unproven stop yields no stop proof"
    );
    let progress = (0..4)
        .map(|_| table.quiesce(&mut out))
        .find(|progress| matches!(progress, super::super::QuiesceProgress::Quiesced(_)))
        .expect("valid disabled registers prove the stop");
    assert_eq!(
        progress,
        super::super::QuiesceProgress::Quiesced(super::super::Quiesced::DeviceStopped)
    );
    assert_eq!(out.len(), 2, "valid disabled registers end both commands");
    assert!(
        out.iter()
            .all(|terminal| matches!(terminal, Terminal::Quiesced { .. }))
    );
    out.clear();
    assert_eq!(held(&arena), (0, 0));
    assert!(
        table.driver().stop_proof().is_some(),
        "the proven stop yields its proof"
    );
}

/// A depth-2 table over a scripted driver leased from `registration`,
/// holding one accepted read of block 0 that the next eight polls leave pending.
pub(crate) fn scripted_table<'a>(
    arena: &'a BufferArena<TestPlatform>,
    registration: &mut crate::native::ArenaRegistration<'_>,
) -> (CommandTable<'a, SpdkDisk<'a, Scripted>>, CommandToken) {
    SCRIPT.take();
    let mut disk =
        SpdkDisk::<Scripted>::scripted_leased("scripted:containment", limits(2), registration);
    let probe = arena.acquire(READ).unwrap();
    disk.mark_verified(probe.range(LEN).unwrap());
    drop(probe);
    let mut table = CommandTable::new(disk, arena, 2, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap();
    let token = table
        .submit_read(
            arena.acquire(READ).unwrap(),
            DeviceRange::new(0, LEN).unwrap(),
        )
        .unwrap();
    SCRIPT.with_borrow_mut(|script| script.poll.extend([(0, false); 8]));
    (table, token)
}

pub(crate) fn scripted_silent(
    address: &str,
    registration: &mut crate::native::ArenaRegistration<'_>,
    polls: usize,
) -> SpdkDisk<'static, Scripted> {
    scripted_silent_at(address, registration, polls, 2)
}

/// [`scripted_silent`] over a device of queue depth `depth`.
pub(crate) fn scripted_silent_at(
    address: &str,
    registration: &mut crate::native::ArenaRegistration<'_>,
    polls: usize,
    depth: u32,
) -> SpdkDisk<'static, Scripted> {
    SCRIPT.take();
    let disk = SpdkDisk::<Scripted>::scripted_leased(address, limits(depth), registration);
    SCRIPT.with_borrow_mut(|script| script.poll.extend(std::iter::repeat_n((0, false), polls)));
    disk
}

/// Whether the scripted driver took a device command: a medium submit or a reservation command.
pub(crate) fn scripted_device_commanded() -> bool {
    use super::disk_tests::Call;
    super::disk_tests::calls().iter().any(|call| {
        matches!(
            call,
            Call::Submit | Call::Register | Call::Acquire | Call::Report
        )
    })
}

pub(crate) fn scripted_attached(address: &str) -> bool {
    super::disk::attached().contains(address)
}
