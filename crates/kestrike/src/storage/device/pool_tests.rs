//! Pool carving, acquire and drop, and release gating, through the arena's public calls over the heap-backed platform.
//! Expected offsets and ledgers come from the test's own arithmetic and model, never from the pools.

use std::collections::HashMap;

use super::super::ledger::EngineBudget;
use super::super::os::HugepageSize;
use super::super::placement::NodeMask;
use super::super::test_platform::{Log, Op, TestPlatform};
use super::{
    BufferArena, BufferConfig, BufferPoolReport, PoolExhausted, PoolKind, PoolSpec, Released,
    SpanError,
};

const TWO_MIB: usize = 2 << 20;

/// Four 4 KiB read buffers, two 8 KiB receive buffers and one 4 KiB maintenance buffer: 36 KiB in one 2 MiB backing page.
const POOLS: [PoolSpec; 3] = [
    PoolSpec {
        kind: PoolKind::Maintenance,
        count: 1,
        buffer_len: 4096,
    },
    PoolSpec {
        kind: PoolKind::ReceiveWrite,
        count: 2,
        buffer_len: 8192,
    },
    PoolSpec {
        kind: PoolKind::ReadResponse,
        count: 4,
        buffer_len: 4096,
    },
];

/// Start offset and buffer length of each pool, computed from the carving order: read, then receive, then maintenance.
fn expected_span(kind: PoolKind) -> (usize, usize, usize) {
    match kind {
        PoolKind::ReadResponse => (0, 4, 4096),
        PoolKind::ReceiveWrite => (4 * 4096, 2, 8192),
        PoolKind::Maintenance => (4 * 4096 + 2 * 8192, 1, 4096),
        PoolKind::Reservation | PoolKind::PacketReceive | PoolKind::PacketHeader => (0, 0, 0),
    }
}

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
    let mut budget = EngineBudget::new(usize::MAX);
    let arena = BufferArena::initialize(&validated, platform, &mut budget).unwrap();
    // A 16-byte record and a 4-byte free-stack entry per buffer, charged with the backing.
    assert_eq!(budget.used(), TWO_MIB + 7 * 20);
    (arena, log)
}

/// The report of a pool with `free` buffers free whose most buffers held at once was `high`.
fn report(kind: PoolKind, free: u32, high: u32) -> BufferPoolReport {
    let (_, count, len) = expected_span(kind);
    let count = count as u32;
    BufferPoolReport {
        kind,
        count,
        buffer_len: len as u32,
        free,
        application: count - free,
        storage: 0,
        quarantined: 0,
        posted: 0,
        nic_held: 0,
        retired: 0,
        mismatched: 0,
        held_bytes: u64::from(count - free) * len as u64,
        held_high_water: high,
    }
}

#[test]
fn pools_are_carved_contiguously_in_kind_order_with_nothing_in_the_tail() {
    let (arena, _log) = arena();
    let mut seen = Vec::new();
    let mut held = Vec::new();
    for kind in PoolKind::ALL {
        let (start, count, len) = expected_span(kind);
        let mut offsets = Vec::new();
        for _ in 0..count {
            let buffer = arena.acquire(kind).unwrap();
            assert_eq!(buffer.kind(), kind);
            assert_eq!(buffer.capacity(), len);
            assert_eq!(buffer.offset() % 4096, 0);
            assert_eq!(buffer.bytes().len(), len);
            assert_eq!(
                buffer.bytes().as_ptr().addr(),
                arena.backing().base().as_ptr().addr() + buffer.offset()
            );
            offsets.push(buffer.offset());
            seen.push((buffer.offset(), len));
            held.push(buffer);
        }
        offsets.sort_unstable();
        let expected: Vec<usize> = (0..count).map(|i| start + i * len).collect();
        assert_eq!(offsets, expected, "{kind:?}");
        assert_eq!(arena.acquire(kind).unwrap_err(), PoolExhausted { kind });
    }
    seen.sort_unstable();
    for pair in seen.windows(2) {
        assert!(pair[0].0 + pair[0].1 <= pair[1].0, "{pair:?} overlap");
    }
    let (last, len) = *seen.last().unwrap();
    assert_eq!(last + len, 4 * 4096 + 2 * 8192 + 4096);
    assert_eq!(arena.config().tail_len(), TWO_MIB - (last + len));
    drop(held);
    assert!(arena.release().is_ok());
}

/// A pattern written through each buffer stays inside it: every buffer reads back its own pattern and nothing else.
#[test]
fn bytes_written_through_one_buffer_never_appear_in_another() {
    let (arena, _log) = arena();
    let mut held = Vec::new();
    for kind in PoolKind::ALL {
        while let Ok(buffer) = arena.acquire(kind) {
            held.push(buffer);
        }
    }
    for (index, buffer) in held.iter_mut().enumerate() {
        buffer.bytes_mut().fill(index as u8 + 1);
    }
    for (index, buffer) in held.iter().enumerate() {
        assert!(buffer.bytes().iter().all(|byte| *byte == index as u8 + 1));
    }
    drop(held);
    assert!(arena.release().is_ok());
}

#[test]
fn exhaustion_refuses_only_that_kind_and_lifo_reacquire_returns_the_last_drop() {
    let (arena, _log) = arena();
    let a = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let mut b = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let before = arena.report(PoolKind::ReceiveWrite);
    assert_eq!(before, report(PoolKind::ReceiveWrite, 0, 2));
    assert_eq!(
        arena.acquire(PoolKind::ReceiveWrite).unwrap_err(),
        PoolExhausted {
            kind: PoolKind::ReceiveWrite
        }
    );
    assert_eq!(arena.report(PoolKind::ReceiveWrite), before);
    let read = arena.acquire(PoolKind::ReadResponse).unwrap();
    let maintenance = arena.acquire(PoolKind::Maintenance).unwrap();
    let a_offset = a.offset();
    b.bytes_mut().fill(0x5A);
    let b_offset = b.offset();
    drop(a);
    drop(b);
    // The last buffer dropped comes back first, still holding its previous tenant's bytes.
    let again = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    assert_eq!(again.offset(), b_offset);
    assert!(again.bytes().iter().all(|byte| *byte == 0x5A));
    let next = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    assert_eq!(next.offset(), a_offset);
    drop((again, next, read, maintenance));
    assert!(arena.release().is_ok());
}

#[test]
fn a_handle_holds_the_application_obligation_until_it_drops() {
    let (arena, _log) = arena();
    let buffer = arena.acquire(PoolKind::Maintenance).unwrap();
    let offset = buffer.offset();
    assert_eq!(
        arena.pools().obligations(PoolKind::Maintenance, offset),
        Some(super::pool::APPLICATION)
    );
    drop(buffer);
    assert_eq!(
        arena.pools().obligations(PoolKind::Maintenance, offset),
        Some(0)
    );
    assert!(arena.release().is_ok());
}

/// A buffer of each pool the arena configures belongs to its own arena's pools and to no other arena's.
/// Of two arenas one's pools lie at the lower address, so the pair checks one foreign pool below a pools array and one above.
#[test]
fn a_buffer_belongs_only_to_the_pools_of_its_own_arena() {
    let (first, _first_log) = arena();
    let (second, _second_log) = arena();
    for spec in POOLS {
        let buffer = first.acquire(spec.kind).unwrap();
        assert!(buffer.belongs_to(first.pools()), "{:?}", spec.kind);
        assert!(!buffer.belongs_to(second.pools()), "{:?}", spec.kind);
        drop(buffer);
        let buffer = second.acquire(spec.kind).unwrap();
        assert!(buffer.belongs_to(second.pools()), "{:?}", spec.kind);
        assert!(!buffer.belongs_to(first.pools()), "{:?}", spec.kind);
    }
    assert!(first.release().is_ok());
    assert!(second.release().is_ok());
}

/// Seeded acquire and drop sequences: after every call each pool's report equals the test's model, and every live handle names a distinct buffer.
#[test]
fn seeded_acquire_and_drop_sequences_match_the_model() {
    for seed in 1..=64u64 {
        let (arena, _log) = arena();
        let mut state = seed;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut held = Vec::new();
        let mut model: HashMap<PoolKind, u32> =
            PoolKind::ALL.iter().map(|kind| (*kind, 0)).collect();
        let mut high = model.clone();
        for _ in 0..500 {
            let kind = PoolKind::ALL[(next() % 3) as usize];
            let (_, count, _) = expected_span(kind);
            if next() % 2 == 0 {
                match arena.acquire(kind) {
                    Ok(buffer) => {
                        assert!(model[&kind] < count as u32, "seed {seed}");
                        *model.get_mut(&kind).unwrap() += 1;
                        let most = high.get_mut(&kind).unwrap();
                        *most = (*most).max(model[&kind]);
                        held.push(buffer);
                    }
                    Err(refused) => {
                        assert_eq!(refused, PoolExhausted { kind });
                        assert_eq!(model[&kind], count as u32, "seed {seed}");
                    }
                }
            } else if !held.is_empty() {
                let buffer = held.swap_remove((next() % held.len() as u64) as usize);
                *model.get_mut(&buffer.kind()).unwrap() -= 1;
                drop(buffer);
            }
            for kind in PoolKind::ALL {
                let (_, count, _) = expected_span(kind);
                assert_eq!(
                    arena.report(kind),
                    report(kind, count as u32 - model[&kind], high[&kind]),
                    "seed {seed}"
                );
                assert_eq!(
                    arena.pools().pool(kind).not_free(),
                    model[&kind],
                    "seed {seed}: not_free matches the held handles"
                );
            }
            let mut offsets: Vec<usize> = held.iter().map(|buffer| buffer.offset()).collect();
            offsets.sort_unstable();
            offsets.dedup();
            assert_eq!(offsets.len(), held.len(), "seed {seed}");
            // Every buffer's obligation set is `{APPLICATION}` exactly when a live handle names it, and empty otherwise.
            for kind in PoolKind::ALL {
                let (start, count, len) = expected_span(kind);
                for offset in (0..count).map(|i| start + i * len) {
                    let live = held.iter().any(|buffer| buffer.offset() == offset);
                    let expected = if live { super::pool::APPLICATION } else { 0 };
                    assert_eq!(
                        arena.pools().obligations(kind, offset),
                        Some(expected),
                        "seed {seed}"
                    );
                }
            }
        }
        drop(held);
        assert!(arena.release().is_ok());
    }
}

#[test]
fn acquire_and_drop_allocate_nothing() {
    let (arena, _log) = arena();
    let before = crate::instrument::allocations();
    for round in 0..10_000 {
        let kind = PoolKind::ALL[round % 3];
        let mut buffer = arena.acquire(kind).unwrap();
        buffer.bytes_mut()[0] = round as u8;
        drop(buffer);
    }
    assert_eq!(crate::instrument::allocations(), before);
    assert!(arena.release().is_ok());
}

/// A forgotten handle of any kind keeps its buffer held forever: release refuses, names exactly that holder, unmaps nothing, and returns the arena.
#[test]
fn a_forgotten_handle_blocks_release_without_an_unmap() {
    for forgotten in PoolKind::STORAGE {
        let (arena, log) = arena();
        std::mem::forget(arena.acquire(forgotten).unwrap());
        for kind in PoolKind::STORAGE {
            if let Ok(buffer) = arena.acquire(kind) {
                drop(buffer);
            }
        }
        let expected = PoolKind::ALL.map(|kind| (kind, u32::from(kind == forgotten)));
        let blocked = arena.release().unwrap_err();
        assert_eq!(blocked.held, expected);
        assert!(log.calls(Op::Unmap).is_empty());
        let arena = blocked.arena;
        let (_, count, _) = expected_span(forgotten);
        let high = (count as u32).min(2);
        assert_eq!(
            arena.report(forgotten),
            report(forgotten, count as u32 - 1, high)
        );
        let blocked = arena.release().unwrap_err();
        assert_eq!(blocked.held, expected);
        drop(blocked);
        assert!(log.calls(Op::Unmap).is_empty(), "{forgotten:?}");
    }
}

/// Pools that fill the backing exactly leave no tail: the last buffer ends at the backing's end and release still unmaps once.
#[test]
fn pools_that_fill_the_backing_exactly_leave_no_tail() {
    let (arena, log) = exact_fill_arena();
    let mut held = Vec::new();
    for kind in PoolKind::ALL {
        while let Ok(buffer) = arena.acquire(kind) {
            held.push(buffer);
        }
    }
    let mut offsets: Vec<usize> = held.iter().map(|buffer| buffer.offset()).collect();
    offsets.sort_unstable();
    assert_eq!(offsets, (0..512).map(|i| i * 4096).collect::<Vec<_>>());
    assert_eq!(held.last().unwrap().offset() + 4096, TWO_MIB);
    drop(held);
    let base = arena.backing().base().as_ptr().addr();
    assert_eq!(arena.release().unwrap(), Released::Complete);
    assert_eq!(log.ranges(Op::Unmap), [(base, TWO_MIB)]);
}

fn exact_fill_arena() -> (BufferArena<TestPlatform>, Log) {
    let pools = [
        PoolSpec {
            kind: PoolKind::ReadResponse,
            count: 510,
            buffer_len: 4096,
        },
        PoolSpec {
            kind: PoolKind::ReceiveWrite,
            count: 1,
            buffer_len: 4096,
        },
        PoolSpec {
            kind: PoolKind::Maintenance,
            count: 1,
            buffer_len: 4096,
        },
    ];
    let platform = TestPlatform::heap(4096);
    let log = platform.log();
    let validated = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &pools,
    }
    .validate()
    .unwrap();
    assert_eq!(validated.tail_len(), 0);
    let arena =
        BufferArena::initialize(&validated, platform, &mut EngineBudget::new(usize::MAX)).unwrap();
    (arena, log)
}

/// A failed `release().expect(..)` includes the arena's debug text in the panic message.
#[test]
fn debug_text_does_not_grow_with_the_buffer_count() {
    let (small, _small_log) = arena();
    let (large, _large_log) = exact_fill_arena();
    let small_text = format!("{small:?}");
    let large_text = format!("{large:?}");
    assert!(
        large_text.len() < small_text.len() + 64,
        "7 buffers format to {} bytes, 512 to {}",
        small_text.len(),
        large_text.len()
    );

    std::mem::forget(large.acquire(PoolKind::Maintenance).unwrap());
    let blocked = large.release().unwrap_err();
    let blocked_text = format!("{blocked:?}");
    assert!(
        blocked_text.len() < large_text.len() + 384,
        "{}",
        blocked_text.len()
    );
}

#[test]
fn release_with_every_buffer_free_unmaps_once() {
    let (arena, log) = arena();
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    drop(buffer);
    let base = arena.backing().base().as_ptr().addr();
    assert_eq!(arena.release().unwrap(), Released::Complete);
    assert_eq!(log.ranges(Op::Unmap), [(base, TWO_MIB)]);
}

/// A buffer's DMA range is its prefix: same address and offset, the requested length, and a refusal for a length it cannot describe.
#[test]
fn a_buffer_range_describes_its_prefix_or_refuses() {
    let (arena, _log) = arena();
    let buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    let range = buffer.range(4096).unwrap();
    assert_eq!(range.offset(), buffer.offset());
    assert_eq!(range.byte_len(), 4096);
    assert_eq!(
        range.addr().as_ptr().addr(),
        arena.backing().base().as_ptr().addr() + buffer.offset()
    );
    assert_eq!(buffer.range(8192).unwrap().byte_len(), 8192);
    assert_eq!(buffer.range(0), Err(SpanError::ZeroLength));
    assert_eq!(buffer.range(4097), Err(SpanError::Misaligned { len: 4097 }));
    assert_eq!(buffer.range(513), Err(SpanError::Misaligned { len: 513 }));
    assert_eq!(buffer.range(512).map(|range| range.byte_len()), Ok(512));
    assert_eq!(
        buffer.range(3 * 4096),
        Err(SpanError::TooLong {
            len: 3 * 4096,
            capacity: 8192
        })
    );
    drop(buffer);
    assert!(arena.release().is_ok());
}
