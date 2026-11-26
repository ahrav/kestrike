//! Tests of the custody check over the simulated device under a command table: the held list and what it names, the check's two rules with their controls, and the check across a cancel, an unproven stop and a dropped table.
//! Every device and, but for one arena with no read-response pool, every arena comes from the storage volume fixture; oracles are the tokens and buffer offsets the test recorded and the pool's own obligation sets.

use super::super::ledger::EngineBudget;
use super::super::os::HugepageSize;
use super::super::placement::NodeMask;
use super::super::test_platform::TestPlatform;
use super::super::volume_fixture::{BUFFER, DEPTH, arena_with, attached, config_for, device_with};
use super::custody_witness::{Breach, Rule, check, judge, judged};
use super::sim::{
    HeldCommand, Injection, Mode, QuiesceMode, SimConfig, SimControl, SimDisk, Stage,
};
use super::sim_tests::{stop, submit, token};
use super::{
    BufferArena, BufferConfig, CommandTable, CommandToken, Completion, DeviceRange, DeviceStatus,
    Operation, PoolKind, PoolSpec, QuiesceProgress, Quiesced, Terminal,
};

/// A free set, an application set, a storage set, and a storage set whose caller cancelled.
const FREE: u8 = 0;
const APPLICATION: u8 = 1;
const STORAGE: u8 = 2;
const CANCELLED: u8 = 6;

fn block(index: u64) -> DeviceRange {
    DeviceRange::new(index * u64::from(BUFFER), BUFFER).unwrap()
}

fn table<'a>(arena: &'a BufferArena<TestPlatform>, disk: SimDisk) -> CommandTable<'a, SimDisk> {
    CommandTable::new(disk, arena, DEPTH, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap()
}

/// A fixture device over `arena` that moves bytes against a host shadow of the arena's backing and touches no memory.
fn modeled(arena: &BufferArena<TestPlatform>, seed: u64) -> (SimDisk, SimControl) {
    attached(SimConfig {
        mode: Mode::Modeled {
            backing_len: arena.backing().extent(),
        },
        ..config_for(seed)
    })
}

/// What a call of the check must leave as it was: the footprint, the event ring, the capture, the outstanding count and the generator state.
fn device_state(control: &SimControl) -> impl PartialEq + std::fmt::Debug {
    (
        control.footprint(),
        control.events(),
        control.capture(),
        control.outstanding(),
        control.peek_rng(),
    )
}

/// A command table over a direct device holds a read and a write. The held list names each with its token, operation, host offset and progress, and the check judges both in storage custody: before and after the read's cancel, after the write executes and then posts behind a closed gate, and after the write's cancel, where the pool records each cancelled buffer as storage plus detached.
/// An injected completion names no memory and leaves the list as it was, a call of the check changes nothing on the device, and after release, admission and a poll the device holds nothing.
#[test]
fn every_command_the_device_holds_names_its_own_buffer_in_storage_custody() {
    let arena = arena_with(4, 4);
    let (disk, control) = device_with(41, BUFFER);
    let mut table = table(&arena, disk);
    let read = arena.acquire(PoolKind::ReadResponse).unwrap();
    let write = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let (read_at, write_at) = (read.offset(), write.offset());
    let r = table.submit_read(read, block(0)).unwrap();
    let w = table.submit_write(write, block(1)).unwrap();
    control.hold(r);
    control.hold(w);
    let entry = |token, operation, host, ordinal, posted| HeldCommand {
        token,
        operation,
        host,
        len: BUFFER,
        ordinal,
        moved: posted,
        posted,
    };
    assert_eq!(
        control.held(),
        [
            entry(r, Operation::Read, read_at, 0, false),
            entry(w, Operation::Write, write_at, 1, false),
        ]
    );
    let before = device_state(&control);
    assert_eq!(judged(&control, &arena), (2, vec![r, w]));
    assert_eq!(device_state(&control), before, "the check only reads");

    table.cancel(r).unwrap();
    assert_eq!(
        arena.pools().obligations(PoolKind::ReadResponse, read_at),
        Some(CANCELLED)
    );
    assert_eq!(judged(&control, &arena), (2, vec![r, w]));

    control.release(w);
    control.execute(w);
    assert_eq!(
        control.held(),
        [
            entry(r, Operation::Read, read_at, 0, false),
            HeldCommand {
                moved: true,
                ..entry(w, Operation::Write, write_at, 1, false)
            },
        ],
        "an executed command stays held, with moved true, before its completion posts"
    );
    let at = control.ready(Stage::Post).iter().position(|t| *t == w);
    control.select(Stage::Post, at.unwrap()).unwrap();
    assert_eq!(control.ready(Stage::Admit), [w], "the gate is closed");
    assert_eq!(
        control.held(),
        [
            entry(r, Operation::Read, read_at, 0, false),
            entry(w, Operation::Write, write_at, 1, true),
        ]
    );
    assert_eq!(
        arena.pools().obligations(PoolKind::ReceiveWrite, write_at),
        Some(STORAGE)
    );
    assert_eq!(judged(&control, &arena), (2, vec![r, w]));

    table.cancel(w).unwrap();
    assert_eq!(
        arena.pools().obligations(PoolKind::ReceiveWrite, write_at),
        Some(CANCELLED)
    );
    assert_eq!(judged(&control, &arena), (2, vec![r, w]));

    let listed = control.held();
    control.inject(
        Completion {
            token: token(1 << 40),
            status: DeviceStatus::Kernel(BUFFER as i32),
        },
        Injection::Foreign,
    );
    assert_eq!(
        control.held(),
        listed,
        "an injected completion names no memory"
    );

    control.release(r);
    control.select(Stage::Admit, 0).unwrap();
    control.post(r);
    assert_eq!(
        control.held(),
        [
            entry(r, Operation::Read, read_at, 0, true),
            entry(w, Operation::Write, write_at, 1, true),
        ],
        "both completions are posted, the write's first, and the list keeps acceptance order"
    );
    let mut out = Vec::with_capacity(4);
    table.poll(&mut out);
    let ended: Vec<_> = out
        .iter()
        .map(|terminal| {
            assert!(
                matches!(terminal, Terminal::Abandoned { .. }),
                "{terminal:?}"
            );
            terminal.token()
        })
        .collect();
    assert!(
        ended.len() == 2 && ended.contains(&r) && ended.contains(&w),
        "each cancelled command ends once, abandoned: {ended:?}"
    );
    assert_eq!(judged(&control, &arena), (0, vec![]));
    drop((out, table));
    assert!(arena.release().is_ok());
}

/// Under an unproven stop the device keeps both of the table's commands, and the check judges both in storage custody before the stop, after it and after the table is dropped.
#[test]
fn an_unproven_stop_and_a_dropped_table_leave_each_held_buffer_in_storage_custody() {
    let arena = arena_with(4, 4);
    let (disk, control) = device_with(43, BUFFER);
    let mut table = table(&arena, disk);
    let tokens: Vec<_> = (0..2)
        .map(|index| {
            let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
            table.submit_write(buffer, block(index)).unwrap()
        })
        .collect();
    assert_eq!(judged(&control, &arena), (2, tokens.clone()));
    control.set_quiesce(QuiesceMode::Failed(Some(9)));
    let mut out = Vec::with_capacity(4);
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Unproven {
            outstanding: 2,
            code: Some(9)
        }
    );
    assert!(out.is_empty());
    assert_eq!(judged(&control, &arena), (2, tokens.clone()));
    drop((out, table));
    assert_eq!(judged(&control, &arena), (2, tokens));
}

/// What `observe` reads after a table over a modeled device submits a read and then a write, cancels the read when `cancel` holds, and quiesces under `mode`, with an output whose spare capacity holds both stopped terminals, which the table delivers as stopped; and the read's token.
fn stopped_by<R>(
    mode: QuiesceMode,
    cancel: bool,
    observe: impl FnOnce(&SimControl, &BufferArena<TestPlatform>) -> R,
) -> (R, CommandToken) {
    let arena = arena_with(4, 4);
    let (disk, control) = modeled(&arena, 44);
    let mut table = table(&arena, disk);
    let read = arena.acquire(PoolKind::ReadResponse).unwrap();
    let write = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let first = table.submit_read(read, block(0)).unwrap();
    table.submit_write(write, block(1)).unwrap();
    if cancel {
        table.cancel(first).unwrap();
    }
    control.set_quiesce(mode);
    let mut out = Vec::with_capacity(4);
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Quiesced(Quiesced::DeviceStopped)
    );
    assert_eq!(out.len(), 2);
    let result = observe(&control, &arena);
    drop((out, table));
    (result, first)
}

/// The hostile false stop: the device reports `Stopped` and keeps both commands, and the table, trusting the stop, returns their buffers, so the check fails under rule S at the first held command.
/// The read's buffer leaves custody in the stopped terminal that holds it, or, when its caller cancelled first, freed inside the table.
#[test]
fn negative_control_a_false_stop_returns_buffers_the_device_still_holds() {
    for (cancel, set) in [(false, APPLICATION), (true, FREE)] {
        let (result, first) = stopped_by(QuiesceMode::FalseStopped, cancel, check);
        let breach = result.unwrap_err();
        assert_eq!(breach.rule, Rule::Storage, "cancel {cancel}");
        assert_eq!(
            breach.rule.text(),
            "the device holds a command whose buffer left storage custody"
        );
        assert_eq!(breach.entry.token, first, "cancel {cancel}");
        assert_eq!(breach.kind, Some(PoolKind::ReadResponse), "cancel {cancel}");
        assert_eq!(breach.set, Some(set), "cancel {cancel}");
    }
}

/// A reset ends every command the device held, so after the same stopped drain the check judges none.
#[test]
fn a_reset_stop_leaves_the_device_holding_nothing() {
    let (result, _) = stopped_by(QuiesceMode::Reset, false, check);
    assert_eq!(result, Ok(0));
}

/// A caller that asserts the count through `judged` fails on a breach with the rule's text.
#[test]
#[should_panic(expected = "the device holds a command whose buffer left storage custody")]
fn judged_fails_on_a_breach_with_the_rule_text() {
    stopped_by(QuiesceMode::FalseStopped, false, judged);
}

/// The check reads only the pool kinds the arena configures: over an arena with no read-response pool, a write held on the first receive-write buffer, at host offset 0, is judged in storage custody.
#[test]
fn the_check_judges_a_buffer_at_offset_zero_in_an_arena_without_every_pool_kind() {
    let pools = [PoolSpec {
        kind: PoolKind::ReceiveWrite,
        count: 1,
        buffer_len: BUFFER,
    }];
    let validated = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &pools,
    }
    .validate()
    .unwrap();
    let arena = BufferArena::initialize(
        &validated,
        TestPlatform::heap(4096),
        &mut EngineBudget::new(usize::MAX),
    )
    .unwrap();
    assert_eq!(arena.config().pool(PoolKind::ReadResponse).count, 0);
    let (disk, control) = device_with(46, BUFFER);
    let mut table = table(&arena, disk);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    assert_eq!(buffer.offset(), 0);
    let w = table.submit_write(buffer, block(0)).unwrap();
    assert_eq!(judged(&control, &arena), (1, vec![w]));
    control.tick(8);
    let mut out = Vec::with_capacity(2);
    table.poll(&mut out);
    assert!(
        matches!(out.as_slice(), [Terminal::Written { token, .. }] if *token == w),
        "{out:?}"
    );
    assert_eq!(judged(&control, &arena), (0, vec![]));
    drop((out, table));
    assert!(arena.release().is_ok());
}

/// Two commands submitted at the device trait over one buffer's range: the check judges rule D first and fails under it at the second command, though the application-owned buffer breaks rule S too.
#[test]
fn negative_control_two_commands_over_one_buffer_fail_the_check() {
    let arena = arena_with(4, 4);
    let (mut disk, control) = modeled(&arena, 45);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    submit(&mut disk, Operation::Read, 1, block(0), &buffer).unwrap();
    submit(&mut disk, Operation::Read, 2, block(1), &buffer).unwrap();
    let breach = check(&control, &arena).unwrap_err();
    assert_eq!(breach.rule, Rule::Distinct);
    assert_eq!(
        breach.rule.text(),
        "two device-held commands name one buffer"
    );
    assert_eq!(breach.entry.token, token(2));
    stop(&mut disk, &control);
    drop(buffer);
    assert!(arena.release().is_ok());
}

/// Rule S requires each held command's host offset to equal the start of a buffer in storage custody.
#[test]
fn negative_control_a_held_command_naming_no_buffer_start_fails_the_check() {
    let arena = arena_with(4, 4);
    let (disk, control) = device_with(47, BUFFER);
    let mut table = table(&arena, disk);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    table.submit_write(buffer, block(0)).unwrap();
    let held = control.held();
    assert_eq!(judge(&held, &arena), Ok(1));
    for host in [held[0].host + 1, arena.backing().extent()] {
        let entry = HeldCommand { host, ..held[0] };
        let result = judge(&[entry], &arena);
        assert_eq!(
            result,
            Err(Breach {
                rule: Rule::Storage,
                entry,
                kind: None,
                set: None,
            }),
            "host {host}"
        );
        assert_eq!(
            result.unwrap_err().rule.text(),
            "the device holds a command whose buffer left storage custody"
        );
    }
}
