//! `PacketLease::keep` narrows a lease only to a range of the bytes it holds. A range that is inverted, or that
//! ends past those bytes, inside the data room or past it, panics and leaves the lease as it was.

use std::ops::Range;
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::packet::{PacketLease, PacketUse, test_pool};

/// The bytes the lease holds at the start: fewer than its data room.
const HELD: usize = 32;
/// The bytes written from the start of the data room, each one distinct: more than the lease holds, so a lease that
/// grew past its bytes would show them.
const WRITTEN: usize = 64;

fn pattern() -> Vec<u8> {
    (0..WRITTEN).map(|at| 0xA0 ^ at as u8).collect()
}

/// Keeps `range`, which is inverted or ends past the bytes held, and checks that the call panics at the assertion
/// that states the held-bytes bound, with the lease's length, bytes and capacity unchanged.
fn refused(lease: &mut PacketLease<'_>, range: Range<usize>) {
    let (len, bytes, capacity) = (lease.len(), lease.bytes().to_vec(), lease.capacity());
    let outcome = catch_unwind(AssertUnwindSafe(|| lease.keep(range.clone())));
    let Err(payload) = outcome else {
        panic!("keeping {range:?} of {len} held bytes panics");
    };
    assert_eq!(
        payload.downcast_ref::<&str>().copied(),
        Some("a kept range lies inside the bytes held"),
        "{range:?} is refused by the assertion that states the held-bytes bound"
    );
    assert_eq!(lease.len(), len, "{range:?} leaves the length");
    assert_eq!(lease.bytes(), bytes, "{range:?} leaves the bytes");
    assert_eq!(lease.capacity(), capacity, "{range:?} leaves the capacity");
}

/// Keeps `range` of the bytes held and checks that the lease then holds exactly those bytes, `range.start` further
/// into the data room.
fn narrowed(lease: &mut PacketLease<'_>, range: Range<usize>) {
    let (bytes, capacity) = (lease.bytes().to_vec(), lease.capacity());
    lease.keep(range.clone());
    assert_eq!(lease.len(), range.len(), "{range:?} sets the length");
    assert_eq!(
        lease.bytes(),
        &bytes[range.clone()],
        "{range:?} keeps its bytes"
    );
    assert_eq!(
        lease.capacity(),
        capacity - range.start,
        "{range:?} moves the first byte"
    );
}

/// One lease of each use that holds 32 bytes of a larger data room refuses an inverted range and a range that
/// reaches one byte past the bytes held or past the data room, before its first narrowing and again after a
/// narrowing, and a range one byte past the bytes held after each later one. It narrows to all the bytes held, to a
/// range that ends exactly at them, to a range interior to them, and to empty ranges; a lease of no bytes refuses
/// every range but the empty one at its start.
#[test]
fn keep_narrows_inside_the_held_bytes_and_refuses_a_range_outside_them() {
    let pool = test_pool(8, 1).expect("a packet pool");
    let pattern = pattern();
    for class in [PacketUse::Data, PacketUse::Control] {
        let mut lease = pool.acquire(class).expect("a free buffer");
        let room = lease.capacity();
        assert!(WRITTEN <= room, "the data room is not full");
        lease.buffer_mut()[..WRITTEN].copy_from_slice(&pattern);
        lease.set_len(HELD);
        assert_eq!(lease.bytes(), &pattern[..HELD]);

        refused(&mut lease, 0..HELD + 1);
        refused(&mut lease, HELD..HELD + 1);
        refused(&mut lease, HELD + 1..HELD + 1);
        refused(&mut lease, 0..room + 1);
        refused(&mut lease, Range { start: 5, end: 4 });

        narrowed(&mut lease, 0..HELD);
        assert_eq!(lease.bytes(), &pattern[..HELD]);
        narrowed(&mut lease, 4..HELD);
        assert_eq!(lease.bytes(), &pattern[4..HELD]);

        let held = HELD - 4;
        refused(&mut lease, 0..held + 1);
        refused(&mut lease, held..held + 1);
        refused(&mut lease, held + 1..held + 1);
        refused(&mut lease, 0..room - 4 + 1);
        refused(
            &mut lease,
            Range {
                start: held,
                end: held - 1,
            },
        );

        narrowed(&mut lease, 2..10);
        assert_eq!(lease.bytes(), &pattern[6..14]);
        refused(&mut lease, 0..9);

        narrowed(&mut lease, 8..8);
        assert!(lease.is_empty());
        refused(&mut lease, 0..1);
        refused(&mut lease, 1..1);
        refused(&mut lease, Range { start: 1, end: 0 });
        narrowed(&mut lease, 0..0);
        assert!(lease.is_empty());
    }
}
