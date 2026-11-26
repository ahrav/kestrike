//! Scripted stop histories through the command table over the scripted SPDK driver: four 4 KiB read buffers, three accepted reads, and the table's pending records and the arena's storage count as the custody oracle.

use spdk_sys as sys;

use super::super::super::ledger::EngineBudget;
use super::super::super::os::HugepageSize;
use super::super::super::placement::NodeMask;
use super::super::super::test_platform::TestPlatform;
use super::super::{
    BufferArena, BufferConfig, CommandTable, CommandToken, DeviceRange, PoolKind, PoolSpec,
    QuiesceProgress, Quiesced, Terminal,
};
use super::disk::SpdkDisk;
use super::disk_tests::{SCRIPT, Scripted, limits};

const LEN: u32 = 4096;
const READ: PoolKind = PoolKind::ReadResponse;

fn arena() -> BufferArena<TestPlatform> {
    let pools = [PoolSpec {
        kind: READ,
        count: 4,
        buffer_len: LEN,
    }];
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

/// A table over a scripted driver whose registration covers the arena, holding three accepted reads.
fn held<'a>(
    arena: &'a BufferArena<TestPlatform>,
    address: &str,
) -> (CommandTable<'a, SpdkDisk<'a, Scripted>>, Vec<CommandToken>) {
    SCRIPT.take();
    let mut disk = SpdkDisk::<Scripted>::scripted(address, limits(4));
    let probe = arena.acquire(READ).unwrap();
    disk.mark_verified(probe.range(LEN).unwrap());
    drop(probe);
    let mut table = CommandTable::new(disk, arena, 4, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap();
    let tokens = (0..3)
        .map(|block| {
            let buffer = arena.acquire(READ).unwrap();
            let range = DeviceRange::new(block * u64::from(LEN), LEN).unwrap();
            table.submit_read(buffer, range).unwrap()
        })
        .collect();
    (table, tokens)
}

/// The table's custody counts: pending records and the read pool's storage buffers.
fn custody(
    table: &CommandTable<'_, SpdkDisk<'_, Scripted>>,
    arena: &BufferArena<TestPlatform>,
) -> (u32, u32) {
    (table.report().pending, arena.report(READ).storage)
}

/// Drives quiesce until the proven stop and returns the quiesced tokens; each call before the proof keeps every buffer held.
fn stop(
    table: &mut CommandTable<'_, SpdkDisk<'_, Scripted>>,
    arena: &BufferArena<TestPlatform>,
    unproven: usize,
) -> Vec<CommandToken> {
    stop_after(table, arena, unproven, |_| true)
}

/// [`stop`] with the first call's progress also checked by `first`.
fn stop_after(
    table: &mut CommandTable<'_, SpdkDisk<'_, Scripted>>,
    arena: &BufferArena<TestPlatform>,
    unproven: usize,
    first: impl Fn(&QuiesceProgress) -> bool,
) -> Vec<CommandToken> {
    let held = custody(table, arena);
    let mut out = Vec::with_capacity(4);
    for call in 0..=unproven {
        let progress = table.quiesce(&mut out);
        if call < unproven {
            assert!(
                matches!(
                    progress,
                    QuiesceProgress::Draining { .. } | QuiesceProgress::Unproven { .. }
                ),
                "call {call}: the stop stays unproven until a register read proves it: {progress:?}"
            );
            assert!(
                call > 0 || first(&progress),
                "call 0: the disconnect result sets the first progress: {progress:?}"
            );
            assert!(out.is_empty(), "an unproven stop returns nothing");
            assert_eq!(custody(table, arena), held, "call {call}");
        } else {
            assert_eq!(progress, QuiesceProgress::Quiesced(Quiesced::DeviceStopped));
        }
    }
    let mut quiesced: Vec<CommandToken> = out
        .drain(..)
        .map(|event| match event {
            Terminal::Quiesced { token, .. } => token,
            other => panic!("{other:?}"),
        })
        .collect();
    quiesced.sort_unstable_by_key(|token| token.raw());
    quiesced
}

/// Register snapshots a disable reads before it proves the stop: all-ones reads of either register, CC.EN still set, CSTS.RDY still set.
pub(super) fn unproven_registers() -> [(u32, u32); 4] {
    // SAFETY: the mask accessors read native constants.
    let (en, rdy) = unsafe {
        (
            sys::spdk_sys_nvme_cc_en_mask(),
            sys::spdk_sys_nvme_csts_rdy_mask(),
        )
    };
    [(u32::MAX, 0), (0, u32::MAX), (en, 0), (0, rdy)]
}

/// A poll that fails, whether its callbacks ran first or not, certifies nothing: the table delivers no terminal and keeps every buffer until register reads prove the stop, and then quiesces exactly the accepted, undelivered commands.
#[test]
fn a_failed_poll_holds_every_command_until_a_proven_stop_quiesces_them() {
    for runs in [true, false] {
        let arena = arena();
        let address = format!("scripted:failed-poll-{runs}");
        let (mut table, tokens) = held(&arena, &address);
        SCRIPT.with_borrow_mut(|script| {
            script.poll.push_back((-libc::EIO, runs));
            script.registers.extend(unproven_registers());
        });
        let mut out = Vec::with_capacity(4);
        assert_eq!(table.poll(&mut out).delivered, 0);
        assert!(out.is_empty());
        assert_eq!(custody(&table, &arena), (3, 3), "runs {runs}");
        // One disconnect, then one unproven read per snapshot.
        let unproven = 1 + unproven_registers().len();
        assert_eq!(stop(&mut table, &arena, unproven), tokens, "runs {runs}");
        assert_eq!(custody(&table, &arena), (0, 0));
    }
}

/// A successful poll on a controller whose failure flag reads set certifies nothing either.
#[test]
fn a_failed_controller_status_holds_every_command_until_a_proven_stop() {
    let arena = arena();
    let (mut table, tokens) = held(&arena, "scripted:failed-status");
    SCRIPT.with_borrow_mut(|script| script.failed.push_back(true));
    let mut out = Vec::with_capacity(4);
    assert_eq!(table.poll(&mut out).delivered, 0);
    assert_eq!(custody(&table, &arena), (3, 3));
    assert_eq!(stop(&mut table, &arena, 1), tokens);
}

/// With the completions still on the device, a refused disconnect reports an unproven stop with every buffer held, a busy one a pending stop, and only the later register proof returns the buffers.
#[test]
fn disconnect_results_change_no_custody_before_the_register_proof() {
    disconnect_then("disconnect", &[unproven_registers()[2]]);
}

/// The planted proof: with no unproven register read scripted, the disable's first read proves it, so the stop
/// quiesces at call 1, as a stop that waited for no register proof would, and the progress check of call 1 rejects
/// it before the custody check runs.
#[test]
#[should_panic(expected = "call 1: the stop stays unproven until a register read proves it")]
fn negative_control_a_first_read_that_proves_the_disable_quiesces_at_call_1() {
    disconnect_then("disconnect-control", &[]);
}

/// A refused and a busy disconnect, each followed by the register reads `registers` and then a read that proves the
/// disable, over three held reads on a driver at the address `scripted:{name}{rc}`; each call before the proof keeps
/// every buffer held. The stop is expected to stay unproven for two calls, the count one register read gives, for
/// every `registers`.
fn disconnect_then(name: &str, registers: &[(u32, u32)]) {
    for (rc, refused) in [(-libc::EIO, true), (-libc::EBUSY, false)] {
        let arena = arena();
        let (mut table, tokens) = held(&arena, &format!("scripted:{name}{rc}"));
        SCRIPT.with_borrow_mut(|script| {
            script.poll.push_back((0, false));
            script.disconnect.push_back(rc);
            script.registers.extend(registers);
        });
        let first = |progress: &QuiesceProgress| {
            matches!(progress, QuiesceProgress::Unproven { .. }) == refused
        };
        assert_eq!(stop_after(&mut table, &arena, 2, first), tokens, "rc {rc}");
    }
}

/// Certified terminals deliver within the output's room, and the stop quiesces exactly the commands still undelivered.
#[test]
fn quiesced_terminals_are_the_accepted_commands_left_undelivered() {
    let arena = arena();
    let (mut table, tokens) = held(&arena, "scripted:partial");
    let mut out = Vec::with_capacity(1);
    assert_eq!(table.poll(&mut out).delivered, 1);
    let Some(Terminal::Read { token, done, .. }) = out.pop() else {
        panic!("a certified read terminal")
    };
    drop(done);
    let rest: Vec<CommandToken> = tokens.into_iter().filter(|other| *other != token).collect();
    assert_eq!(custody(&table, &arena), (2, 2));
    SCRIPT.with_borrow_mut(|script| {
        script.poll.push_back((0, false));
        script.registers.push_back(unproven_registers()[0]);
    });
    assert_eq!(stop(&mut table, &arena, 2), rest);
}

/// Certified terminals the output had no room for stay in custody through the stop: each accepted command reaches the table exactly once, as a delivered read or a quiesced buffer.
#[test]
fn certified_terminals_held_back_by_room_reach_the_table_once_across_the_stop() {
    let arena = arena();
    let (mut table, tokens) = held(&arena, "scripted:held-certified");
    SCRIPT.with_borrow_mut(|script| {
        script.fanout = true;
        script.registers.push_back(unproven_registers()[1]);
    });
    let mut out = Vec::with_capacity(1);
    assert_eq!(table.poll(&mut out).delivered, 1);
    let Some(Terminal::Read { token, done, .. }) = out.pop() else {
        panic!("a certified read terminal")
    };
    drop(done);
    assert_eq!(
        custody(&table, &arena),
        (2, 2),
        "two certified terminals wait for room"
    );
    let mut full = Vec::new();
    for _ in 0..2 {
        assert!(matches!(
            table.quiesce(&mut full),
            QuiesceProgress::Draining { outstanding: 2 }
        ));
    }
    assert_eq!(
        table.quiesce(&mut full),
        QuiesceProgress::Delivering { remaining: 2 }
    );
    let mut seen = [vec![token], stop(&mut table, &arena, 0)].concat();
    seen.sort_unstable_by_key(|token| token.raw());
    assert_eq!(seen, tokens);
    assert_eq!(custody(&table, &arena), (0, 0));
}
