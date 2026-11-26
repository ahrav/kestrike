//! The consumer sequences the storage engine and a campaign driver run against the substrate, written against public `storage` re-exports only.
//! The simulated device and heap-backed platform are test support; everything the sequences call is public API.

use crate::storage::{
    BufferArena, BufferConfig, CommandTable, DeviceRange, EngineBudget, HugepageSize, NodeMask,
    PoolKind, PoolSpec, QuiesceProgress, Quiesced, Released, Stale, Terminal,
};

use super::super::test_platform::TestPlatform;
use super::sim::{Mode, QuiesceMode, SimConfig, SimControl, SimDisk, StatusForm, sim};

const LEN: u32 = 16384;

const POOLS: [PoolSpec; 3] = [
    PoolSpec {
        kind: PoolKind::ReadResponse,
        count: 2,
        buffer_len: LEN,
    },
    PoolSpec {
        kind: PoolKind::ReceiveWrite,
        count: 2,
        buffer_len: LEN,
    },
    PoolSpec {
        kind: PoolKind::Maintenance,
        count: 1,
        buffer_len: 4096,
    },
];

fn arena() -> BufferArena<TestPlatform> {
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

fn table(arena: &BufferArena<TestPlatform>) -> (CommandTable<'_, SimDisk>, SimControl) {
    let (disk, control) = sim(SimConfig {
        seed: 17,
        capacity: 1 << 20,
        queue_depth: 8,
        max_transfer: LEN,
        form: StatusForm::Nvme,
        mode: Mode::Direct,
        script: crate::storage::device::sim::SCRIPT,
    });
    let table = CommandTable::new(disk, arena, 8, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap();
    (table, control)
}

fn extent(start: u64) -> DeviceRange {
    DeviceRange::new(start, LEN).unwrap()
}

/// S1: an object arrives in two chunks, each written through its own receive buffer; the object is ready only when every required write succeeded.
#[test]
fn s1_fill_write() {
    let arena = arena();
    let (mut table, control) = table(&arena);
    let mut required = Vec::new();
    for (chunk, start) in [(0x11u8, 0u64), (0x22, u64::from(LEN))] {
        let mut buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
        buffer.bytes_mut().fill(chunk);
        required.push(table.submit_write(buffer, extent(start)).unwrap());
    }
    let mut failed = false;
    let mut out = Vec::with_capacity(4);
    while !required.is_empty() && !failed {
        control.tick(1);
        table.poll(&mut out);
        for event in out.drain(..) {
            match event {
                Terminal::Written { token, .. } => required.retain(|t| *t != token),
                _ => failed = true,
            }
        }
    }
    assert!(!failed, "{}", control.describe());
    assert_eq!(control.device(0, LEN as usize), vec![0x11; LEN as usize]);
    assert_eq!(
        control.device(LEN as usize, LEN as usize),
        vec![0x22; LEN as usize]
    );
    drop((out, table));
    assert_eq!(arena.release().unwrap(), Released::Complete);
}

/// S2: a hit reads its extent into a response buffer; only the read-done evidence presents the bytes, and the response keeps the buffer.
#[test]
fn s2_hit_read() {
    let arena = arena();
    let (mut table, control) = table(&arena);
    control.write_device(0, &[0x5C; LEN as usize]);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let token = table.submit_read(buffer, extent(0)).unwrap();
    control.tick(1);
    let mut out = Vec::with_capacity(1);
    table.poll(&mut out);
    let Some(Terminal::Read { token: t, done, .. }) = out.pop() else {
        panic!("{}", control.describe())
    };
    assert_eq!(t, token);
    let valid = done.bytes().iter().all(|byte| *byte == 0x5C);
    assert!(valid);
    let response = done.into_buffer();
    assert_eq!(response.capacity(), LEN as usize);
    drop((response, out, table));
    assert!(arena.release().is_ok());
}

/// S3: a read and a write are cancelled in flight; their buffers stay quarantined until each command's own completion, and only then may the extent the write touched be reused.
#[test]
fn s3_cancel_with_a_read_and_a_write_in_flight() {
    let arena = arena();
    let (mut table, control) = table(&arena);
    let read = arena.acquire(PoolKind::Maintenance).unwrap();
    let write = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let other = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let unit = DeviceRange::new(0, 4096).unwrap();
    let read_token = table.submit_read(read, unit).unwrap();
    let write_token = table.submit_write(write, extent(u64::from(LEN))).unwrap();
    table.cancel(read_token).unwrap();
    table.cancel(write_token).unwrap();
    assert!(arena.acquire(PoolKind::Maintenance).is_err());
    assert!(arena.acquire(PoolKind::ReceiveWrite).is_err());
    control.tick(2);
    let mut out = Vec::with_capacity(4);
    table.poll(&mut out);
    let mut abandoned: Vec<_> = out
        .drain(..)
        .map(|event| match event {
            Terminal::Abandoned { token, status, .. } => {
                assert!(status.is_some());
                token
            }
            other => panic!("{other:?}"),
        })
        .collect();
    abandoned.sort_unstable_by_key(|token| token.raw());
    let mut expected = vec![read_token, write_token];
    expected.sort_unstable_by_key(|token| token.raw());
    assert_eq!(abandoned, expected);
    // The write's extent may be reused only now, after its terminal event.
    assert_eq!(table.cancel(read_token), Err(Stale));
    assert!(arena.acquire(PoolKind::Maintenance).is_ok());
    drop((other, out, table));
    assert!(arena.release().is_ok());
}

/// S4: shutdown closes admission and quiesces; an unproven quiesce leaves the arena blocked, and a proven stop lets it release after every event is dropped.
#[test]
fn s4_shutdown_with_outstanding_commands() {
    for proven in [false, true] {
        let arena = arena();
        let (mut table, control) = table(&arena);
        for kind in [PoolKind::ReadResponse, PoolKind::ReceiveWrite] {
            let buffer = arena.acquire(kind).unwrap();
            table.submit_read(buffer, extent(0)).unwrap();
        }
        table.close();
        control.set_quiesce(if proven {
            QuiesceMode::Reset
        } else {
            QuiesceMode::Unproven
        });
        let mut out = Vec::with_capacity(1);
        let mut done = false;
        for _ in 0..4 {
            match table.quiesce(&mut out) {
                QuiesceProgress::Quiesced(Quiesced::DeviceStopped) => done = true,
                QuiesceProgress::Delivering { .. } | QuiesceProgress::Draining { .. } => {}
                other => panic!("{other:?}"),
            }
            out.clear();
            if done {
                break;
            }
        }
        assert_eq!(done, proven);
        drop((out, table));
        assert_eq!(arena.release().is_ok(), proven);
    }
}

/// S5: a command the device holds does not block a second command's completion, nor the reacquisition of the second buffer.
#[test]
fn s5_independent_completion() {
    let arena = arena();
    let (mut table, control) = table(&arena);
    let a = arena.acquire(PoolKind::ReadResponse).unwrap();
    let b = arena.acquire(PoolKind::ReadResponse).unwrap();
    let b_offset = b.offset();
    let a_token = table.submit_read(a, extent(0)).unwrap();
    let b_token = table.submit_read(b, extent(u64::from(LEN))).unwrap();
    control.hold(a_token);
    control.tick(2);
    let mut out = Vec::with_capacity(2);
    table.poll(&mut out);
    let Some(Terminal::Read { token, done, .. }) = out.pop() else {
        panic!("{}", control.describe())
    };
    assert_eq!(token, b_token);
    drop(done);
    let again = arena.acquire(PoolKind::ReadResponse).unwrap();
    assert_eq!(again.offset(), b_offset);
    assert_eq!(table.report().pending, 1);
    control.release(a_token);
    control.tick(1);
    table.poll(&mut out);
    assert_eq!(out.pop().map(|event| event.token()), Some(a_token));
    drop((again, out, table));
    assert!(arena.release().is_ok());
}
