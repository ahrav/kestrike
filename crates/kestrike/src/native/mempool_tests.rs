//! The Rust mempool ops over mock native pools.

use std::ffi::c_void;

use super::env::Environment;
use super::mempool::{
    Check, MempoolError, OpsState, PacketMempool, Role, Token, check_object, entries, ops_count,
    prefault,
};
use super::mock::{self, COUNT, MockPool};
use super::registration_tests::ready;
use crate::net::{PacketPool, PacketPoolError};
use crate::storage::{EngineBudget, PoolKind};

const RECEIVE: PoolKind = PoolKind::PacketReceive;
const HEADER: PoolKind = PoolKind::PacketHeader;
const RESPONSE: PoolKind = PoolKind::ReadResponse;

fn dequeue(pool: &MockPool, n: usize) -> (i32, Vec<*mut c_void>) {
    let mut out = vec![std::ptr::null_mut(); n];
    // SAFETY: `out` holds `n` slots and the pool is a mock pool of its role's ops.
    let rc = unsafe { entries(pool.state.role()).1(pool.mp, out.as_mut_ptr(), n as u32) };
    (rc, out)
}

fn enqueue(pool: &MockPool, objs: &[*mut c_void]) {
    // SAFETY: each object is returned to a mock pool of its role's ops.
    assert_eq!(
        unsafe { entries(pool.state.role()).0(pool.mp, objs.as_ptr(), objs.len() as u32) },
        0
    );
}

fn count(pool: &MockPool) -> u32 {
    // SAFETY: a mock pool of the ops.
    unsafe { ops_count(pool.mp) }
}

/// The mbuf of the fixture arena's header buffer `index`.
fn header_object(
    arena: &crate::storage::BufferArena<crate::storage::test_platform::TestPlatform>,
    index: u32,
) -> *mut c_void {
    let layout = crate::storage::PacketLayout::of(4096).unwrap();
    let base =
        arena.backing().base().as_ptr().addr() + arena.config().start(HEADER) + layout.mbuf_offset;
    mock::object(base, 4096, index).cast()
}

/// A receive dequeue posts exactly the requested count or fails with the arena unchanged, from a full pool and from a partly posted one; an armed return ends each posting once, and a second return of a posting, an object inside no slot and a posting the pool never gave out change no custody.
#[test]
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
fn receive_ops_post_all_or_nothing_and_return_each_posting_once() {
    let arena = mock::arena();
    let pool = mock::arena_pool(arena, RECEIVE, Role::Receive);
    assert_eq!(count(&pool), COUNT);
    let (refused, out) = dequeue(&pool, COUNT as usize + 1);
    assert_eq!(refused, -libc::ENOBUFS, "short of the request");
    assert!(out.iter().all(|obj| obj.is_null()));
    assert_eq!(
        arena.report(RECEIVE).posted,
        0,
        "a refused dequeue posts nothing"
    );
    let (rc, posted) = dequeue(&pool, 3);
    assert_eq!(rc, 0);
    assert_eq!(arena.report(RECEIVE).posted, 3);
    let (refused, _) = dequeue(&pool, COUNT as usize - 2);
    assert_eq!(
        (refused, arena.report(RECEIVE).posted),
        (-libc::ENOBUFS, 3),
        "one short after a partial post"
    );
    let (rc, rest) = dequeue(&pool, COUNT as usize - 3);
    assert_eq!((rc, count(&pool)), (0, 0), "exactly the free count");
    enqueue(&pool, &rest);
    let indexes: std::collections::HashSet<_> = posted
        .iter()
        .map(|obj| pool.state.index_of(*obj).unwrap())
        .collect();
    assert_eq!(indexes.len(), 3, "distinct buffers");
    enqueue(&pool, &posted[..2]);
    let report = arena.report(RECEIVE);
    assert_eq!((report.posted, report.free), (1, COUNT - 1));
    enqueue(&pool, &posted[..1]);
    assert_eq!(
        pool.state.report().stray,
        1,
        "a second return of the same posting"
    );
    let foreign = posted[2].cast::<u8>().wrapping_add(8).cast();
    enqueue(&pool, &[foreign]);
    assert_eq!(pool.state.report().stray, 2, "an object inside no slot");
    let elsewhere = arena.pools().post(RECEIVE).unwrap();
    let index = (elsewhere.offset() - arena.config().start(RECEIVE)) / 16384;
    enqueue(&pool, &[pool.state.object(index as u32)]);
    assert_eq!(
        (pool.state.report().stray, arena.report(RECEIVE).posted),
        (3, 2),
        "a posting this pool never gave out stays posted"
    );
    // SAFETY: no device saw the posting above.
    unsafe { elsewhere.unpost() };
    enqueue(&pool, &posted[2..]);
    assert_eq!(arena.report(RECEIVE).free, COUNT);
    assert_eq!(
        pool.state.report(),
        super::OpsReport {
            returned: COUNT as u64,
            stray: 3,
            refused: 2
        }
    );
}

/// Before population ends, an enqueue of a header mbuf whose private area holds an armed-looking token for a live device reference changes no custody; once armed, the same enqueue returns the reference.
#[test]
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
fn population_enqueues_leave_the_arena_unchanged() {
    let arena = mock::arena();
    let pool = mock::unarmed_pool(arena, HEADER, Role::Header);
    let buffer = arena.pools().acquire(HEADER).unwrap();
    let (index, incarnation) = buffer.identity();
    buffer.source(0..64).unwrap().hold().unwrap().into_raw();
    drop(buffer);
    let obj = header_object(arena, index);
    // SAFETY: the mbuf is this fixture's own.
    unsafe { Token::write(obj.cast(), HEADER, index, incarnation) };
    enqueue(&pool, &[obj]);
    assert_eq!(
        arena.report(HEADER).nic_held,
        1,
        "population returned nothing"
    );
    assert_eq!(pool.state.report(), super::OpsReport::default());
    pool.arm();
    enqueue(&pool, &[obj]);
    assert_eq!(
        arena.report(HEADER).free,
        COUNT,
        "the armed return released the reference"
    );
}

/// A header return disarms its token and returns the reference once, freeing the NIC-held buffer; a disarmed token, a token of an older incarnation, a token naming another buffer and a header dequeue change no custody.
#[test]
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
fn header_returns_release_their_token_once() {
    let arena = mock::arena();
    let pool = mock::arena_pool(arena, HEADER, Role::Header);
    let (refused, _) = dequeue(&pool, 1);
    assert_eq!(
        (refused, count(&pool)),
        (-libc::ENOBUFS, 0),
        "headers come from the burst logic, never a device get"
    );
    let buffer = arena.pools().acquire(HEADER).unwrap();
    let (index, incarnation) = buffer.identity();
    let hold = buffer.source(0..64).unwrap().hold().unwrap();
    let obj = header_object(arena, index);
    assert_eq!(pool.state.index_of(obj), Some(index));
    // SAFETY: the mbuf is this pool's, owned here, with no armed token.
    unsafe { Token::arm(obj.cast(), hold) };
    drop(buffer);
    assert_eq!(arena.report(HEADER).nic_held, 1);
    // SAFETY: as above; the token names an incarnation the buffer left.
    unsafe { Token::write(obj.cast(), HEADER, index, incarnation.wrapping_sub(1)) };
    enqueue(&pool, &[obj]);
    let report = arena.report(HEADER);
    assert_eq!(
        (report.nic_held, report.mismatched),
        (1, 1),
        "a stale token returns nothing"
    );
    let other = arena.pools().acquire(HEADER).unwrap();
    let (other_index, other_incarnation) = other.identity();
    other.source(0..64).unwrap().hold().unwrap().into_raw();
    drop(other);
    // SAFETY: as above; the token names another header's live reference.
    unsafe { Token::write(obj.cast(), HEADER, other_index, other_incarnation) };
    enqueue(&pool, &[obj]);
    let report = arena.report(HEADER);
    assert_eq!(
        (report.nic_held, report.mismatched),
        (2, 1),
        "a token naming another buffer returns nothing"
    );
    // SAFETY: as above, the live incarnation of the mbuf's own buffer.
    unsafe { Token::write(obj.cast(), HEADER, index, incarnation) };
    enqueue(&pool, &[obj]);
    assert_eq!(
        arena.report(HEADER).nic_held,
        1,
        "the return freed the buffer"
    );
    enqueue(&pool, &[obj]);
    assert_eq!(
        pool.state.report(),
        super::OpsReport {
            returned: 1,
            stray: 3,
            refused: 1
        }
    );
    // SAFETY: the other header's reference was detached above and no device saw it.
    unsafe {
        arena
            .pools()
            .nic_return(HEADER, other_index, other_incarnation)
    };
    assert_eq!(arena.report(HEADER).free, COUNT);
}

/// Payload descriptors leave the stack all or none; every return of an out descriptor puts it back, releasing its token's reference when armed, a stale token releasing nothing, and a return of a descriptor that is not out changes no custody.
#[test]
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
fn payload_descriptors_return_to_the_stack_once() {
    let arena = mock::arena();
    let pool = mock::payload_pool(arena, 4);
    let (refused, _) = dequeue(&pool, 5);
    assert_eq!((refused, count(&pool)), (-libc::ENOBUFS, 4));
    let (rc, taken) = dequeue(&pool, 3);
    assert_eq!((rc, count(&pool)), (0, 1));
    let source = arena.acquire(PoolKind::ReadResponse).unwrap();
    let (index, incarnation) = source.identity();
    let range = source.source(0..100).unwrap();
    // SAFETY: each descriptor is owned here with no armed token.
    unsafe {
        Token::arm(taken[0].cast(), range.hold().unwrap());
        Token::write(
            taken[1].cast(),
            PoolKind::ReadResponse,
            index,
            incarnation + 1,
        );
    }
    drop(source);
    assert_eq!(arena.report(PoolKind::ReadResponse).nic_held, 1);
    enqueue(&pool, &taken);
    let report = arena.report(PoolKind::ReadResponse);
    assert_eq!(
        (report.free, report.mismatched),
        (COUNT, 1),
        "the armed token returned; the stale one matched nothing"
    );
    assert_eq!(
        count(&pool),
        4,
        "every out descriptor is back, armed, stale or never armed"
    );
    enqueue(&pool, &taken[..1]);
    assert_eq!(
        count(&pool),
        4,
        "a descriptor that is not out stays off the stack"
    );
    assert_eq!(pool.state.report().stray, 1);
}

/// Each entry of one enqueue burst counts as returned or stray; a repeated return counts as stray for receive postings and payload descriptors, as does a receive pointer off every object's mbuf address.
#[test]
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
fn a_mixed_burst_counts_each_object_as_returned_or_stray() {
    let arena = mock::arena();
    let receive = mock::arena_pool(arena, RECEIVE, Role::Receive);
    let (rc, posted) = dequeue(&receive, 2);
    assert_eq!(rc, 0);
    let foreign = posted[0].cast::<u8>().wrapping_add(8).cast();
    enqueue(&receive, &[posted[0], posted[0], foreign, posted[1]]);
    let report = arena.report(RECEIVE);
    assert_eq!((report.posted, report.free), (0, COUNT));
    assert_eq!(
        receive.state.report(),
        super::OpsReport {
            returned: 2,
            stray: 2,
            refused: 0
        }
    );

    let payload = mock::payload_pool(arena, 4);
    let (rc, taken) = dequeue(&payload, 2);
    assert_eq!(rc, 0);
    enqueue(&payload, &[taken[0], taken[1], taken[0]]);
    assert_eq!(
        count(&payload),
        4,
        "each out descriptor is back on the stack"
    );
    assert_eq!(
        payload.state.report(),
        super::OpsReport {
            returned: 2,
            stray: 1,
            refused: 0
        }
    );
}

/// With no state behind the pool every op answers without touching any state; the dequeue, return, refusal and stray paths each role has leave the per-thread allocation count unchanged.
#[test]
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
fn ops_without_state_answer_and_ops_allocate_nothing() {
    let arena = mock::arena();
    let receive = mock::arena_pool(arena, RECEIVE, Role::Receive);
    let header = mock::arena_pool(arena, HEADER, Role::Header);
    let payload = mock::payload_pool(arena, 4);
    // SAFETY: an all-zero pool structure has no state.
    let mut bare: Box<spdk_sys::rte_mempool> = Box::new(unsafe { std::mem::zeroed() });
    let empty = MockPool {
        mp: &mut *bare,
        state: receive.state,
    };
    for role in [Role::Receive, Role::Header, Role::Payload] {
        let (enqueue_of, dequeue_of) = entries(role);
        let mut one = [std::ptr::null_mut(); 1];
        // SAFETY: a bare pool of the ops; nothing behind it is touched.
        unsafe {
            assert_eq!(dequeue_of(empty.mp, one.as_mut_ptr(), 1), -libc::ENOBUFS);
            assert_eq!(enqueue_of(empty.mp, one.as_ptr(), 1), 0);
        }
    }
    assert_eq!(count(&empty), 0);
    let mut slots = [std::ptr::null_mut(); 16];
    let stray = [std::ptr::null_mut::<c_void>()];
    let allocations = crate::instrument::allocations();
    for _ in 0..16 {
        for pool in [&receive, &payload] {
            let (enqueue_of, dequeue_of) = entries(pool.state.role());
            // SAFETY: four slots for four objects of a mock pool, each returned once.
            unsafe {
                assert_eq!(dequeue_of(pool.mp, slots.as_mut_ptr(), 4), 0);
                let short = ops_count(pool.mp) + 1;
                assert_eq!(
                    dequeue_of(pool.mp, slots.as_mut_ptr().add(4), short),
                    -libc::ENOBUFS
                );
                enqueue_of(pool.mp, slots.as_ptr(), 4);
                enqueue_of(pool.mp, stray.as_ptr(), 1);
            }
        }
        let (enqueue_of, dequeue_of) = entries(Role::Header);
        // SAFETY: as above.
        unsafe {
            assert_eq!(dequeue_of(header.mp, slots.as_mut_ptr(), 1), -libc::ENOBUFS);
            enqueue_of(header.mp, stray.as_ptr(), 1);
            ops_count(header.mp);
        }
    }
    assert_eq!(crate::instrument::allocations(), allocations);
}

/// The construction check refuses an object out of its carved place, an object or buffer IOVA that differs from the registration's, and an arena object with no registered IOVA; it accepts a payload descriptor with none.
#[test]
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
fn the_construction_check_refuses_misplaced_or_misaddressed_objects() {
    let arena = mock::arena();
    let receive = mock::arena_pool(arena, RECEIVE, Role::Receive);
    let payload = mock::payload_pool(arena, 2);
    let iova = |addr: usize, _len: usize| Some(addr as u64 + 7);
    let none = |_: usize, _: usize| None;
    let run = |state: &OpsState,
               translate: &dyn Fn(usize, usize) -> Option<u64>,
               index: u32,
               obj: *mut c_void,
               header_iova: u64,
               buf_iova: u64| {
        let header = obj.cast::<spdk_sys::rte_mempool_objhdr>().wrapping_sub(1);
        // SAFETY: the object header and mbuf lie inside the fixture's buffer or descriptor memory.
        unsafe {
            (*header).iova = header_iova;
            (*obj.cast::<spdk_sys::rte_mbuf>()).buf_iova = buf_iova;
        }
        let mut check = Check {
            state,
            iova: translate,
            element: 64,
            ok: true,
        };
        // SAFETY: `check` is live for the call.
        unsafe { check_object(std::ptr::null_mut(), (&raw mut check).cast(), obj, index) };
        check.ok
    };
    let obj = |pool: &MockPool, index: u32| pool.state.object(index);
    let first = obj(&receive, 1);
    // SAFETY: reads the mbuf the fixture initialized.
    let buf = unsafe { (*first.cast::<spdk_sys::rte_mbuf>()).buf_addr.addr() } as u64;
    let good = first.addr() as u64 + 7;
    assert!(run(receive.state, &iova, 1, first, good, buf + 7));
    assert!(
        !run(receive.state, &iova, 2, first, good, buf + 7),
        "object 1 checked as object 2"
    );
    assert!(
        !run(receive.state, &iova, 1, first, good + 64, buf + 7),
        "a wrong object IOVA"
    );
    assert!(
        !run(receive.state, &iova, 1, first, good, buf),
        "a wrong buffer IOVA"
    );
    assert!(
        !run(receive.state, &none, 1, first, good, buf + 7),
        "an arena object with no registered IOVA"
    );
    assert!(
        run(payload.state, &none, 0, obj(&payload, 0), 0, 0),
        "a descriptor the device never reads"
    );
}

/// A receive buffer keeps serving past `u32::MAX` incarnations: its return starts the next incarnation instead of retiring it, so the pool posts every buffer again.
#[test]
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
fn receive_buffers_keep_serving_past_u32_incarnations() {
    let arena = mock::arena();
    let pool = mock::arena_pool(arena, RECEIVE, Role::Receive);
    for index in 0..COUNT as usize {
        arena
            .pools()
            .set_incarnation(RECEIVE, index, u32::MAX.into());
    }
    let (rc, posted) = dequeue(&pool, COUNT as usize);
    assert_eq!(rc, 0);
    enqueue(&pool, &posted);
    let report = arena.report(RECEIVE);
    assert_eq!((report.free, report.retired), (COUNT, 0));
    let (rc, _) = dequeue(&pool, COUNT as usize);
    assert_eq!(rc, 0, "every buffer posts again");
}

/// A header buffer keeps serving past `u32::MAX` incarnations, and its token names the whole incarnation: the return at `u32::MAX` frees the buffer into the next incarnation, whose token then returns its reference as well.
#[test]
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
fn header_tokens_carry_incarnations_past_u32() {
    let arena = mock::arena();
    let pool = mock::arena_pool(arena, HEADER, Role::Header);
    for index in 0..COUNT as usize {
        arena
            .pools()
            .set_incarnation(HEADER, index, u32::MAX.into());
    }
    for round in 0..2u64 {
        let buffer = arena.pools().acquire(HEADER).unwrap();
        let (index, incarnation) = buffer.identity();
        assert_eq!(incarnation, u64::from(u32::MAX) + round);
        let hold = buffer.source(0..64).unwrap().hold().unwrap();
        let obj = header_object(arena, index);
        // SAFETY: the mbuf is this pool's, owned here, with no armed token.
        unsafe { Token::arm(obj.cast(), hold) };
        drop(buffer);
        enqueue(&pool, &[obj]);
        let report = arena.report(HEADER);
        assert_eq!(
            (report.free, report.retired, report.mismatched),
            (COUNT, 0, 0),
            "round {round}: the return freed the buffer into its next incarnation"
        );
    }
}

/// Prefaulting a fresh mapping leaves each page wholly inside the range
/// resident and every byte unchanged: the written pages keep their bytes and
/// the untouched ones read zero.
#[test]
#[cfg_attr(miri, ignore = "mmap, madvise and mincore are system calls")]
fn prefault_keeps_bytes_and_leaves_whole_pages_resident() {
    // SAFETY: `sysconf` reads a constant.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
    let (pages, written) = (16, 4);
    let len = pages * page;
    // SAFETY: a fresh private anonymous mapping the kernel places.
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(base, libc::MAP_FAILED);
    // SAFETY: the mapping is live, readable and writable for `len` bytes.
    let bytes = unsafe { std::slice::from_raw_parts_mut(base.cast::<u8>(), len) };
    let pattern = |at: usize| (at % 251) as u8 | 1;
    for (at, byte) in bytes[..written * page].iter_mut().enumerate() {
        *byte = pattern(at);
    }
    prefault(base.addr() + 3, len - 3 - 100);
    let mut resident = vec![0u8; pages];
    // SAFETY: the page-aligned mapping is live, and `resident` holds a byte per page.
    assert_eq!(
        unsafe { libc::mincore(base, len, resident.as_mut_ptr()) },
        0
    );
    assert!(
        resident[1..pages - 1].iter().all(|state| state & 1 == 1),
        "every page wholly inside the range is resident, which needs MADV_POPULATE_WRITE (Linux 5.14): {resident:?}"
    );
    assert!(
        bytes[..written * page]
            .iter()
            .enumerate()
            .all(|(at, &byte)| byte == pattern(at)),
        "a written byte changed"
    );
    assert!(bytes[written * page..].iter().all(|&byte| byte == 0));
    // SAFETY: the whole mapping, unmapped once, after the last use of `bytes`.
    assert_eq!(unsafe { libc::munmap(base, len) }, 0);
}

/// A header pool holds the header kind as the kind's only view. While a
/// `PacketPool` view holds the kind, a header pool is refused with `Kind`,
/// the budget and the kind's census stay as they were, and the view keeps
/// the kind: the arena's acquire and post and a second view still refuse,
/// after one refused attempt and after a second.
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
#[test]
fn a_header_pool_refused_for_a_live_view_leaves_the_view_its_kind() {
    const KIND: PoolKind = PoolKind::PacketHeader;
    let (env, arena) = (Environment::detached(), mock::arena());
    let mut registration = ready(&env, arena);
    let lease = registration.device_attached();
    let view = PacketPool::new(arena, KIND, 1).unwrap();
    assert_eq!(view.report().free, mock::COUNT, "8 free header buffers");

    let limit = PacketMempool::ARENA_CHARGE * 4;
    let mut budget = EngineBudget::new(limit);
    let census = arena.pools().census(KIND);
    let report = arena.report(KIND);
    for attempt in ["first", "second"] {
        assert_eq!(
            PacketMempool::header(arena, &registration, &lease, c"t", &mut budget).err(),
            Some(MempoolError::Kind),
            "the {attempt} attempt while the view holds the kind"
        );
        assert_eq!(budget, EngineBudget::new(limit), "the budget is unchanged");
        assert_eq!(
            arena.pools().census(KIND),
            census,
            "the census is unchanged"
        );
        assert_eq!(arena.report(KIND), report, "the report is unchanged");
        assert!(arena.acquire(KIND).is_err(), "the view still holds acquire");
        assert!(arena.post(KIND).is_err(), "the view still holds post");
        assert_eq!(
            PacketPool::new(arena, KIND, 1).err(),
            Some(PacketPoolError::InUse),
            "the view still holds the kind against another view"
        );
    }
    assert_eq!(view.report().free, mock::COUNT);
    drop(view);
    registration.device_stopped(lease.stopped()).unwrap();
}

/// The descriptors on the payload pool's stack, in ascending order.
fn stacked(pool: &MockPool) -> Vec<u32> {
    let mut stack = pool.state.descriptor_stack();
    stack.sort_unstable();
    stack
}

/// A payload descriptor's return gives back its token's reference only when the token names a read-response
/// buffer. The control returns a descriptor whose token names its read-response buffer: the device reference comes
/// back. The descriptor dequeued next carries a token that gives the index and incarnation of a read-response
/// buffer the device holds, tagged as a header: its enqueue disarms the token and puts the descriptor back once,
/// and the read-response buffer stays with the device, with no mismatch counted. After each return the stack
/// holds the descriptors it held before the first dequeue, each once.
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
#[test]
fn a_payload_token_tagged_as_another_kind_is_disarmed_and_returns_no_reference() {
    let arena = mock::arena();
    let pool = mock::payload_pool(arena, 4);
    let full = stacked(&pool);

    let (rc, taken) = dequeue(&pool, 1);
    assert_eq!(rc, 0);
    let matching = taken[0];
    let source = arena.acquire(RESPONSE).unwrap();
    // SAFETY: the descriptor is owned here with no armed token.
    unsafe {
        Token::arm(
            matching.cast(),
            source.source(0..100).unwrap().hold().unwrap(),
        )
    };
    drop(source);
    assert_eq!(arena.report(RESPONSE).nic_held, 1);
    enqueue(&pool, &[matching]);
    let report = arena.report(RESPONSE);
    assert_eq!((report.nic_held, report.free, count(&pool)), (0, COUNT, 4));
    assert_eq!(
        stacked(&pool),
        full,
        "the control's descriptor is the one back on the stack"
    );

    let (rc, taken) = dequeue(&pool, 1);
    assert_eq!(rc, 0);
    let tagged = taken[0];
    assert_eq!(count(&pool), 3);
    let source = arena.acquire(RESPONSE).unwrap();
    let (index, incarnation) = source.identity();
    // SAFETY: as above; the second write replaces the armed token in the private area this test owns.
    unsafe {
        Token::arm(
            tagged.cast(),
            source.source(0..100).unwrap().hold().unwrap(),
        );
        assert_eq!(
            Token::read(tagged.cast()),
            (RESPONSE.index() as u16, index, incarnation, true)
        );
        Token::write(tagged.cast(), HEADER, index, incarnation);
    }
    drop(source);
    let before = arena.report(RESPONSE);
    assert_eq!((before.nic_held, before.free), (1, COUNT - 1));
    let header = arena.report(HEADER);

    enqueue(&pool, &[tagged]);
    // SAFETY: the descriptor is back on the stack and nothing else writes it.
    let (.., armed) = unsafe { Token::read(tagged.cast()) };
    assert!(!armed, "the token of another kind is disarmed");
    assert_eq!(count(&pool), 4, "the descriptor is back on the stack");
    assert_eq!(stacked(&pool), full, "the stack holds each descriptor once");
    assert_eq!(
        arena.report(RESPONSE),
        before,
        "the read-response buffer keeps its device reference"
    );
    assert_eq!(arena.report(HEADER), header);

    enqueue(&pool, &[tagged]);
    assert_eq!(count(&pool), 4, "and it went back exactly once");
    assert_eq!(stacked(&pool), full, "a second return adds no descriptor");
    assert_eq!(pool.state.report().stray, 1);
    assert_eq!(arena.report(RESPONSE), before);
}
