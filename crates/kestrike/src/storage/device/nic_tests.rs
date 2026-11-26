//! Device reference counts on arena buffers: counts gate the free stack, returns match only their incarnation, incarnations retire before they wrap, and seeded histories conserve every custody partition against an independent per-buffer oracle.

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::super::ledger::EngineBudget;
use super::super::os::HugepageSize;
use super::super::placement::NodeMask;
use super::super::seeded::SplitMix64;
use super::super::test_platform::TestPlatform;
use super::{Buffer, BufferArena, BufferConfig, HoldError, PoolKind, PoolSpec, RxPosted};

const READ: PoolKind = PoolKind::ReadResponse;
const RECEIVE: PoolKind = PoolKind::PacketReceive;

/// Four 4 KiB read buffers and four 16 KiB packet receive buffers.
fn arena() -> BufferArena<TestPlatform> {
    let pools = [
        PoolSpec {
            kind: READ,
            count: 4,
            buffer_len: 4096,
        },
        PoolSpec {
            kind: RECEIVE,
            count: 4,
            buffer_len: 16384,
        },
    ];
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

/// A dropped handle whose buffer a device still reads leaves it NIC-held, never free: no acquire returns it until the last reference returns, and it then comes back as a new incarnation.
#[test]
fn a_device_reference_keeps_its_buffer_off_the_free_stack() {
    let arena = arena();
    let buffer = arena.acquire(READ).unwrap();
    let (index, incarnation) = buffer.identity();
    let offset = buffer.offset();
    let source = buffer.source(0..4096).unwrap();
    let first = source.hold().unwrap();
    let second = source.hold().unwrap();
    assert_eq!(first.identity(), (READ, index, incarnation));
    assert_eq!(
        arena.report(READ).application,
        1,
        "a handle with device references counts once, as application"
    );
    assert_eq!(arena.report(READ).nic_held, 0);
    drop(buffer);
    let report = arena.report(READ);
    assert_eq!(
        (report.free, report.application, report.nic_held),
        (3, 0, 1)
    );
    assert_eq!(arena.pools().census(READ), [3, 0, 0, 0, 0, 1, 0]);
    let others: Vec<Buffer<'_>> = (0..3).map(|_| arena.acquire(READ).unwrap()).collect();
    assert!(
        others.iter().all(|other| other.offset() != offset),
        "the held buffer is never handed out"
    );
    assert!(arena.acquire(READ).is_err());
    drop(others);
    drop(first);
    assert_eq!(arena.report(READ).nic_held, 1, "one reference remains");
    drop(second);
    assert_eq!(arena.report(READ).free, 4);
    let reused = arena.acquire(READ).unwrap();
    assert_eq!(reused.offset(), offset, "the last return pushed it on top");
    assert_eq!(reused.identity(), (index, incarnation + 1));
}

/// Every custody view of a pool: its report, the census by record, each buffer's class and incarnation, each buffer's device-reference count, the free stack and the ended-hold count.
fn custody_views(arena: &BufferArena<TestPlatform>) -> impl PartialEq + std::fmt::Debug {
    let pools = arena.pools();
    let mut counts = Vec::new();
    pools.device_counts_into(READ, &mut counts);
    (
        arena.report(READ),
        pools.census(READ),
        pools.snapshot(READ),
        counts,
        pools.free_stack(READ),
        pools.holds_ended(READ),
    )
}

/// Handing a buffer to a device in one step leaves every custody view equal to taking a reference through its range, detaching it raw and dropping the handle: the buffer is NIC-held with one reference under the same identity, and the reference's return frees it as a new incarnation in both. A count at its cap refuses the hand-off and returns the handle with nothing changed.
#[test]
fn handing_a_buffer_to_the_device_equals_a_raw_hold_and_the_handles_drop() {
    let (stepwise, fused) = (arena(), arena());
    let identities = [&stepwise, &fused].map(|arena| {
        let buffer = arena.acquire(READ).unwrap();
        let (index, incarnation) = buffer.identity();
        (arena, buffer, index, incarnation)
    });
    let [
        (_, by_steps, index, incarnation),
        (_, by_fusion, fused_index, fused_incarnation),
    ] = identities;
    assert_eq!((index, incarnation), (fused_index, fused_incarnation));
    let raw = by_steps.source(0..4096).unwrap().hold().unwrap().into_raw();
    drop(by_steps);
    let handed = by_fusion
        .into_device()
        .expect("an uncapped count takes the reference");
    assert_eq!(handed, raw, "the same kind, index and incarnation");
    assert_eq!(handed, (READ, index, incarnation));
    assert_eq!(
        custody_views(&stepwise),
        custody_views(&fused),
        "after the hand-off"
    );
    assert_eq!(fused.report(READ).nic_held, 1);
    for arena in [&stepwise, &fused] {
        // SAFETY: the reference was detached once and returns once.
        assert!(unsafe { arena.nic_return(READ, index, incarnation) });
    }
    assert_eq!(
        custody_views(&stepwise),
        custody_views(&fused),
        "after the return"
    );
    assert_eq!(fused.report(READ).free, 4);
    let reused = fused.acquire(READ).unwrap();
    assert_eq!(reused.identity(), (index, incarnation + 1));

    let source = reused.source(0..16).unwrap();
    for _ in 0..u16::MAX {
        source.hold().unwrap().into_raw();
    }
    let before = custody_views(&fused);
    let Err((refused, error)) = reused.into_device() else {
        panic!("a count at its cap refuses the hand-off");
    };
    assert_eq!(error, HoldError::Cap);
    assert_eq!(
        refused.identity(),
        (index, incarnation + 1),
        "the handle comes back"
    );
    assert_eq!(
        custody_views(&fused),
        before,
        "a refused hand-off changes nothing"
    );
    drop(refused);
    for _ in 0..u16::MAX {
        // SAFETY: each reference was detached with `into_raw` and returns once.
        assert!(unsafe { fused.nic_return(READ, index, incarnation + 1) });
    }
    assert_eq!(fused.report(READ).free, 4);
}

/// A count at its cap refuses another reference with nothing changed; a return naming an older incarnation, an index outside the pool, or a buffer with no live reference is counted as mismatched and changes nothing.
#[test]
fn a_count_at_its_cap_refuses_and_mismatched_returns_change_nothing() {
    let arena = arena();
    let buffer = arena.acquire(READ).unwrap();
    let (index, incarnation) = buffer.identity();
    let source = buffer.source(0..16).unwrap();
    for _ in 0..u16::MAX {
        source.hold().unwrap().into_raw();
    }
    assert_eq!(source.hold().err(), Some(HoldError::Cap));
    // SAFETY: each live reference named here was detached with `into_raw` and returns once; any other identity names no live reference.
    assert!(
        !unsafe { arena.nic_return(READ, index, incarnation + 1) },
        "a later incarnation"
    );
    // SAFETY: each live reference named here was detached with `into_raw` and returns once; any other identity names no live reference.
    assert!(
        !unsafe { arena.nic_return(READ, 99, incarnation) },
        "an index outside the pool"
    );
    assert_eq!(arena.report(READ).mismatched, 2);
    drop(buffer);
    assert_eq!(arena.report(READ).nic_held, 1);
    for _ in 0..u16::MAX {
        // SAFETY: each live reference named here was detached with `into_raw` and returns once; any other identity names no live reference.
        assert!(unsafe { arena.nic_return(READ, index, incarnation) });
    }
    assert_eq!(arena.report(READ).free, 4);
    // SAFETY: each live reference named here was detached with `into_raw` and returns once; any other identity names no live reference.
    assert!(
        !unsafe { arena.nic_return(READ, index, incarnation) },
        "a duplicated return after the last"
    );
    let report = arena.report(READ);
    assert_eq!((report.free, report.mismatched), (4, 3));
}

/// The pool counts a return only when it ends a buffer's last device reference, whether the handle still lives or the buffer is NIC-held, through a hold's drop or the raw return; a return that leaves references and a mismatched return leave the count unchanged.
#[test]
fn only_a_last_reference_return_counts_as_a_hold_ended() {
    let arena = arena();
    let ended = || arena.pools().holds_ended(READ);
    let buffer = arena.acquire(READ).unwrap();
    let (index, incarnation) = buffer.identity();
    let source = buffer.source(0..16).unwrap();
    let first = source.hold().unwrap();
    let second = source.hold().unwrap();
    assert_eq!(ended(), 0);
    drop(first);
    assert_eq!(ended(), 0, "one reference remains");
    drop(second);
    assert_eq!(
        ended(),
        1,
        "the last reference returned while the handle lives"
    );
    let (_, raw_index, raw_incarnation) = source.hold().unwrap().into_raw();
    // SAFETY: the later incarnation names no live reference.
    assert!(!unsafe { arena.nic_return(READ, index, incarnation + 1) });
    assert_eq!(ended(), 1, "a mismatched return counts nothing");
    drop(buffer);
    assert_eq!(arena.report(READ).nic_held, 1);
    // SAFETY: the reference detached with `into_raw` above returns once.
    assert!(unsafe { arena.nic_return(READ, raw_index, raw_incarnation) });
    assert_eq!(
        ended(),
        2,
        "the raw return of a NIC-held buffer's last reference counts"
    );
    assert_eq!(arena.report(READ).free, 4);
}

/// A late return naming an older incarnation, arriving while the buffer's next incarnation holds device references, is counted and decrements nothing, so the newer references still keep the buffer off the free stack.
#[test]
fn an_older_incarnations_return_never_frees_a_newer_one() {
    let arena = arena();
    let buffer = arena.acquire(READ).unwrap();
    let (index, old) = buffer.identity();
    drop(buffer.source(0..8).unwrap().hold().unwrap());
    drop(buffer);
    let buffer = arena.acquire(READ).unwrap();
    assert_eq!(buffer.identity(), (index, old + 1));
    let hold = buffer.source(0..8).unwrap().hold().unwrap();
    drop(buffer);
    // SAFETY: the older incarnation names no live reference.
    assert!(!unsafe { arena.nic_return(READ, index, old) });
    let report = arena.report(READ);
    assert_eq!((report.nic_held, report.mismatched), (1, 1));
    drop(hold);
    assert_eq!(arena.report(READ).free, 4);
}

/// A posting the device never wrote returns to the free stack through `unpost` as a new incarnation; a posting that ends without it stays posted.
#[test]
fn an_unposted_buffer_returns_as_a_new_incarnation() {
    let arena = arena();
    let posted = arena.post(RECEIVE).unwrap();
    assert_eq!(arena.report(RECEIVE).posted, 1);
    // SAFETY: no device received the posted buffer's address.
    unsafe { posted.unpost() };
    assert_eq!(arena.pools().census(RECEIVE), [4, 0, 0, 0, 0, 0, 0]);
    let buffer = arena.acquire(RECEIVE).unwrap();
    assert_eq!(
        buffer.identity().1,
        1,
        "the unposted buffer was on top of the free stack, one incarnation on"
    );
    drop(buffer);
    let _ = arena.post(RECEIVE).unwrap();
    assert_eq!(
        arena.report(RECEIVE).posted,
        1,
        "a posting that ends without `unpost` stays posted"
    );
}

/// A run posts all of its buffers, the most recently freed first, or none while too few are free; ending the run returns each by-index posting once, ignores a posting made with `post`, an index past the pool and an absent one, and a buffer out of incarnations retires instead of returning.
#[test]
fn a_posting_run_ends_each_buffer_it_posted_once() {
    let arena = arena();
    let pools = arena.pools();
    let pool = pools.pool(RECEIVE);
    let mut posted = Vec::new();
    // SAFETY: the closure only records the index and returns normally.
    let short = unsafe { pool.post_run(5, |index| posted.push(index)) };
    assert!(!short, "one short of the request");
    assert!(posted.is_empty());
    assert_eq!(pools.census(RECEIVE), [4, 0, 0, 0, 0, 0, 0]);
    // SAFETY: as above.
    assert!(unsafe { pool.post_run(2, |index| posted.push(index)) });
    assert_eq!(posted, [0, 1], "the free stack's top first");
    let report = arena.report(RECEIVE);
    assert_eq!(
        (report.free, report.posted, report.held_high_water),
        (2, 2, 2)
    );
    let elsewhere = arena.post(RECEIVE).unwrap();
    let other = (elsewhere.offset() - arena.config().start(RECEIVE)) as u32 / 16384;
    // SAFETY: no device received any of these postings.
    let ended = unsafe {
        pool.unpost_run([
            Some(posted[0]),
            Some(other),
            None,
            Some(99),
            Some(posted[0]),
        ])
    };
    assert_eq!(ended, 1, "only the by-index posting ends, once");
    assert_eq!(arena.report(RECEIVE).posted, 2);
    // SAFETY: as above.
    unsafe { elsewhere.unpost() };
    pools.set_incarnation(RECEIVE, posted[1] as usize, u64::MAX);
    // SAFETY: as above.
    assert_eq!(unsafe { pool.unpost_run([Some(posted[1])]) }, 1);
    let report = arena.report(RECEIVE);
    assert_eq!(
        (report.free, report.posted, report.retired),
        (3, 0, 1),
        "the exhausted buffer retires"
    );
    assert_eq!(pools.census(RECEIVE), [3, 0, 0, 0, 0, 0, 1]);
}

/// `take_posted` takes a by-index posting once: a second take returns `None`, and a run end of the taken index ends nothing while the taker's `RxPosted` still counts as posted.
#[test]
fn a_by_index_posting_ends_once_through_its_take() {
    let arena = arena();
    let pools = arena.pools();
    let pool = pools.pool(RECEIVE);
    let mut posted = Vec::new();
    // SAFETY: the closure only records the index and returns normally.
    assert!(unsafe { pool.post_run(2, |index| posted.push(index)) });
    let mut counts = Vec::new();
    pools.device_counts_into(RECEIVE, &mut counts);
    assert_eq!(counts, [0; 4], "the mark is no device reference");
    assert_eq!(pools.census(RECEIVE), [2, 0, 0, 0, 2, 0, 0]);
    // SAFETY: no device received either posting, so nothing writes the buffers.
    let taken = unsafe { pool.take_posted(posted[0]) }.expect("a marked posting");
    // SAFETY: no device received the posting of `posted[0]`.
    assert!(unsafe { pool.take_posted(posted[0]) }.is_none());
    // SAFETY: no device received the posting of `posted[0]`.
    assert_eq!(
        unsafe { pool.unpost_run([Some(posted[0])]) },
        0,
        "the take ended the by-index posting"
    );
    assert_eq!(arena.report(RECEIVE).posted, 2);
    // SAFETY: no device wrote the taken buffer.
    let buffer = unsafe { taken.complete() };
    assert_eq!(buffer.identity(), (posted[0], 0));
    assert!(!buffer.device_held());
    drop(buffer);
    // SAFETY: no device received the posting of `posted[1]`.
    assert_eq!(unsafe { pool.unpost_run([Some(posted[1])]) }, 1);
    assert_eq!(pools.census(RECEIVE), [4, 0, 0, 0, 0, 0, 0]);
    let first = arena.acquire(RECEIVE).unwrap();
    let second = arena.acquire(RECEIVE).unwrap();
    assert_eq!(
        (first.identity(), second.identity()),
        ((posted[1], 1), (posted[0], 1)),
        "each ended posting returned once, as a new incarnation, the last on top"
    );
}

/// A handle whose buffer a device reads refuses a mutable view.
#[test]
#[should_panic(expected = "a buffer a device reads has no mutable view")]
fn a_held_buffer_refuses_a_mutable_view() {
    let arena = arena();
    let mut buffer = arena.acquire(READ).unwrap();
    let hold = buffer.source(0..8).unwrap().hold().unwrap();
    buffer.bytes_mut()[0] = 1;
    drop(hold);
}

/// A buffer whose next incarnation would wrap retires instead of returning to the free stack, whether its handle or its last device reference ends it; retired buffers count against neither the free stack nor release.
#[test]
fn incarnations_retire_before_they_wrap() {
    let arena = arena();
    let buffer = arena.acquire(READ).unwrap();
    let (index, _) = buffer.identity();
    drop(buffer);
    arena
        .pools()
        .set_incarnation(READ, index as usize, u64::MAX);
    let buffer = arena.acquire(READ).unwrap();
    assert_eq!(buffer.identity(), (index, u64::MAX));
    drop(buffer);
    let report = arena.report(READ);
    assert_eq!((report.free, report.retired), (3, 1));
    let other = arena.acquire(READ).unwrap();
    let (other_index, _) = other.identity();
    drop(other);
    arena
        .pools()
        .set_incarnation(READ, other_index as usize, u64::MAX);
    let other = arena.acquire(READ).unwrap();
    let hold = other.source(0..8).unwrap().hold().unwrap();
    drop(other);
    assert_eq!(arena.report(READ).nic_held, 1);
    drop(hold);
    let report = arena.report(READ);
    assert_eq!((report.free, report.nic_held, report.retired), (2, 0, 2));
    assert!(arena.release().is_ok(), "retired buffers hold nothing");
}

/// The read pool's free count and its free stack, bottom first.
fn free(arena: &BufferArena<TestPlatform>) -> (u32, Vec<u32>) {
    (arena.report(READ).free, arena.pools().free_stack(READ))
}

/// Acquires `held + 1` read buffers, forgets every handle and releases the last buffer acquired once, as dropping its handle does. Returns the arena, that buffer's index and the free count and stack after the release. The release is legal and returns the buffer once: the `held` buffers stay off the free stack and the released one is on it a single time.
fn released_once(held: u32) -> (BufferArena<TestPlatform>, u32, (u32, Vec<u32>)) {
    let arena = arena();
    for _ in 0..held {
        std::mem::forget(arena.acquire(READ).unwrap());
    }
    let buffer = arena.acquire(READ).unwrap();
    let (index, _) = buffer.identity();
    std::mem::forget(buffer);
    let forgotten = free(&arena);
    assert_eq!(
        forgotten.0,
        3 - held,
        "held {held}: every acquired buffer is off the free stack"
    );
    assert!(
        !forgotten.1.contains(&index),
        "held {held}: the forgotten buffer is off the free stack"
    );
    arena.pools().release_index(READ, index as usize);
    let released = free(&arena);
    assert_eq!(
        released.0,
        4 - held,
        "held {held}: the first release is legal"
    );
    assert_eq!(
        released.1.iter().filter(|&&at| at == index).count(),
        1,
        "held {held}: the first release puts the buffer on the free stack once"
    );
    (arena, index, released)
}

/// A second release of one handle panics before it pushes the buffer on the free stack twice: the planted release follows a legal one of a forgotten handle. With every other buffer free the first release fills the stack, so a second push would land past its end; with one buffer held off the stack a second push would land inside it. In both the panic is the custody core's refusal, and the free count and the free stack stay as the first release left them. The arrangement with room on the stack runs first, so a release that pushes before it checks fails the comparison below.
#[test]
fn a_second_release_of_one_handle_panics() {
    for held in [1, 0] {
        let (arena, index, released) = released_once(held);
        let panic = catch_unwind(AssertUnwindSafe(|| {
            arena.pools().release_index(READ, index as usize);
        }))
        .expect_err("the second release panics");
        let message = panic
            .downcast_ref::<&str>()
            .map(|text| text.to_string())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        assert!(
            message.contains("illegal obligation transition"),
            "held {held}: the second release panics with the illegal transition: {message}"
        );
        assert_eq!(
            free(&arena),
            released,
            "held {held}: the second release leaves the free count and the free stack alone"
        );
    }
}

/// The same steps with one release: the release of a forgotten handle is legal and returns the buffer once, so the panic above is the second release's.
#[test]
fn one_release_of_a_forgotten_handle_returns_the_buffer_once() {
    for held in [0, 1] {
        released_once(held);
    }
}

/// An acquire that reaches a retired buffer panics before it reuses the exhausted incarnation: the planted push offers the retired buffer on the free stack.
#[test]
#[should_panic(expected = "illegal obligation transition")]
fn an_acquire_of_a_retired_buffer_panics() {
    let arena = arena();
    let buffer = arena.acquire(READ).unwrap();
    let (index, _) = buffer.identity();
    drop(buffer);
    arena
        .pools()
        .set_incarnation(READ, index as usize, u64::MAX);
    drop(arena.acquire(READ).unwrap());
    assert_eq!(arena.report(READ).retired, 1);
    arena.pools().push_free(READ, index);
    let _reused = arena.acquire(READ);
}

/// LIFO reuse concentrates incarnation increments on the most recently freed
/// buffer; one million reuses per second exhausts a `u32` in about 72
/// minutes, so the counter is wide enough that such a buffer stays in service.
#[test]
fn a_buffer_past_u32_max_reuses_stays_in_service() {
    let arena = arena();
    let buffer = arena.acquire(READ).unwrap();
    let (index, _) = buffer.identity();
    drop(buffer);
    arena
        .pools()
        .set_incarnation(READ, index as usize, u32::MAX.into());
    drop(arena.acquire(READ).unwrap());
    let report = arena.report(READ);
    assert_eq!((report.free, report.retired), (4, 0));
    let buffer = arena.acquire(READ).unwrap();
    let (reused, incarnation) = buffer.identity();
    assert_eq!(reused, index, "the freed buffer is on top of the stack");
    assert_eq!(incarnation, u64::from(u32::MAX) + 1);
}

/// Release refuses a NIC-held buffer and a posted receive buffer, handing the arena back, and succeeds once both return.
#[test]
fn release_refuses_outstanding_device_custody() {
    let arena = arena();
    let buffer = arena.acquire(READ).unwrap();
    let (kind, index, incarnation) = buffer.source(0..8).unwrap().hold().unwrap().into_raw();
    drop(buffer);
    // A posting that ends without `unpost` stays posted, as for a device that may still write it.
    let _ = arena.post(RECEIVE).unwrap();
    let blocked = arena.release().expect_err("custody is outstanding");
    assert!(
        blocked.held.contains(&(READ, 1)) && blocked.held.contains(&(RECEIVE, 1)),
        "{:?}",
        blocked.held
    );
    let arena = blocked.arena;
    // SAFETY: each live reference named here was detached with `into_raw` and returns once; any other identity names no live reference.
    assert!(unsafe { arena.nic_return(kind, index, incarnation) });
    let blocked = arena
        .release()
        .expect_err("the posted buffer is outstanding");
    assert_eq!(blocked.held.iter().map(|(_, count)| count).sum::<u32>(), 1);
}

/// What the oracle knows of one buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Custody {
    Free,
    /// A live handle, with the device references to its incarnation.
    Application(u32),
    Storage,
    Quarantined,
    Posted,
    /// The handle dropped while device references remained.
    Nic(u32),
    Retired,
}

impl Custody {
    /// The census index of this state: free, application, storage, quarantined, posted, NIC-held, retired.
    fn partition(self) -> usize {
        match self {
            Self::Free => 0,
            Self::Application(_) => 1,
            Self::Storage => 2,
            Self::Quarantined => 3,
            Self::Posted => 4,
            Self::Nic(_) => 5,
            Self::Retired => 6,
        }
    }
}

/// A device reference taken over from its handle with `into_raw` or `into_device`, returned later through the arena.
struct Raw {
    kind: PoolKind,
    index: u32,
    incarnation: u64,
}

/// Over seeded histories of acquire, post, receive completion, storage custody, detach, device holds, out-of-order and stale returns, handle drops and hand-offs of a handle to the device, every pool's census, report and free stack match an independent per-buffer oracle after every call; every partition, and a handle shared with device references, is reached in each history.
#[test]
fn seeded_histories_conserve_every_partition() {
    for seed in 0..32 {
        let arena = arena();
        let pools = arena.pools();
        let mut rng = SplitMix64::new(seed);
        // Two read buffers start near the end of their incarnations, so they retire within the history.
        let near_end: Vec<Buffer<'_>> = (0..2).map(|_| arena.acquire(READ).unwrap()).collect();
        let near: Vec<u32> = near_end.iter().map(|buffer| buffer.identity().0).collect();
        drop(near_end);
        for index in &near {
            pools.set_incarnation(READ, *index as usize, u64::MAX - 3);
        }
        let mut oracle = [[Custody::Free; 4]; 2];
        let mut incarnations = [[0u64; 4]; 2];
        for index in &near {
            incarnations[0][*index as usize] = u64::MAX - 3;
        }
        let mut handles: Vec<Buffer<'_>> = Vec::new();
        let mut posted: Vec<RxPosted<'_>> = Vec::new();
        let mut stored = Vec::new();
        let mut raws: Vec<Raw> = Vec::new();
        let mut mismatched = [0u64; 2];
        let mut reached = [false; 7];
        let mut shared = false;
        let slot = |kind: PoolKind| usize::from(kind == RECEIVE);
        for step in 0..600 {
            match rng.below(10) {
                0 | 1 => {
                    let kind = if rng.below(2) == 0 { READ } else { RECEIVE };
                    if let Ok(buffer) = arena.acquire(kind) {
                        let (index, incarnation) = buffer.identity();
                        assert_eq!(
                            oracle[slot(kind)][index as usize],
                            Custody::Free,
                            "seed {seed} step {step}"
                        );
                        assert_eq!(
                            incarnation,
                            incarnations[slot(kind)][index as usize],
                            "seed {seed} step {step} {kind:?} {index}"
                        );
                        oracle[slot(kind)][index as usize] = Custody::Application(0);
                        handles.push(buffer);
                    } else {
                        assert!(
                            oracle[slot(kind)]
                                .iter()
                                .all(|custody| *custody != Custody::Free)
                        );
                    }
                }
                2 => {
                    if let Ok(buffer) = arena.post(RECEIVE) {
                        posted.push(buffer);
                    }
                }
                3 if !posted.is_empty() => {
                    let buffer = posted.swap_remove(rng.below(posted.len() as u64) as usize);
                    if rng.below(2) == 0 {
                        // SAFETY: no device wrote the posted buffer.
                        handles.push(unsafe { buffer.complete() });
                    } else {
                        // SAFETY: no device received the posted buffer's address.
                        unsafe { buffer.unpost() };
                    }
                }
                4 if !handles.is_empty() => {
                    let at = rng.below(handles.len() as u64) as usize;
                    if let Ok(hold) = handles[at].source(0..64).unwrap().hold() {
                        let (kind, index, incarnation) = hold.into_raw();
                        raws.push(Raw {
                            kind,
                            index,
                            incarnation,
                        });
                    }
                }
                5 if !raws.is_empty() => {
                    let raw = raws.swap_remove(rng.below(raws.len() as u64) as usize);
                    // SAFETY: each live reference named here was taken over once with `into_raw` or `into_device` and returns once; any other identity names no live reference.
                    assert!(unsafe { arena.nic_return(raw.kind, raw.index, raw.incarnation) });
                    let last = !raws.iter().any(|other| {
                        (other.kind, other.index, other.incarnation)
                            == (raw.kind, raw.index, raw.incarnation)
                    });
                    if last && rng.below(4) == 0 {
                        // SAFETY: each live reference named here was taken over once with `into_raw` or `into_device` and returns once; any other identity names no live reference.
                        assert!(
                            !unsafe { arena.nic_return(raw.kind, raw.index, raw.incarnation) },
                            "a stale return"
                        );
                        mismatched[slot(raw.kind)] += 1;
                    }
                }
                6 if !handles.is_empty() => {
                    let at = rng.below(handles.len() as u64) as usize;
                    let (index, _) = handles[at].identity();
                    let kind = handles[at].kind();
                    if oracle[slot(kind)][index as usize] == Custody::Application(0) {
                        stored.push((handles.swap_remove(at).into_storage(), false));
                    }
                }
                7 if !stored.is_empty() => {
                    let at = rng.below(stored.len() as u64) as usize;
                    let (held, detached) = stored.swap_remove(at);
                    match (detached, rng.below(2)) {
                        (false, 0) => {
                            held.detach(pools);
                            stored.push((held, true));
                        }
                        (false, _) => handles.push(held.into_buffer(pools)),
                        (true, _) => held.free(pools),
                    }
                }
                _ if !handles.is_empty() => {
                    let handle = handles.swap_remove(rng.below(handles.len() as u64) as usize);
                    if rng.below(2) == 0 {
                        drop(handle);
                    } else {
                        match handle.into_device() {
                            Ok((kind, index, incarnation)) => raws.push(Raw {
                                kind,
                                index,
                                incarnation,
                            }),
                            Err((handle, _)) => drop(handle),
                        }
                    }
                }
                _ => {}
            }
            // Rebuild the oracle from the test's own records of who holds what.
            let mut live = [[None::<Custody>; 4]; 2];
            for handle in &handles {
                live[slot(handle.kind())][handle.identity().0 as usize] =
                    Some(Custody::Application(0));
            }
            for buffer in &posted {
                let index = (buffer.offset() - arena.config().start(RECEIVE)) / 16384;
                live[1][index] = Some(Custody::Posted);
            }
            for (held, detached) in &stored {
                let kind = held_kind(held, &arena);
                live[slot(kind)][held_index(held, &arena, kind)] = Some(if *detached {
                    Custody::Quarantined
                } else {
                    Custody::Storage
                });
            }
            for raw in &raws {
                let entry = &mut live[slot(raw.kind)][raw.index as usize];
                *entry = Some(match *entry {
                    Some(Custody::Application(n)) => Custody::Application(n + 1),
                    Some(Custody::Nic(n)) => Custody::Nic(n + 1),
                    None => Custody::Nic(1),
                    other => panic!("a device reference to {other:?}"),
                });
            }
            for (kind, at) in [(READ, 0), (RECEIVE, 1)] {
                for index in 0..4 {
                    let before = oracle[at][index];
                    let now = match (live[at][index], before) {
                        (Some(custody), _) => custody,
                        (None, Custody::Retired | Custody::Free) => before,
                        // The buffer left every holder this step: it freed, starting a new incarnation, or retired.
                        (None, _) => match incarnations[at][index].checked_add(1) {
                            Some(next) => {
                                incarnations[at][index] = next;
                                Custody::Free
                            }
                            None => Custody::Retired,
                        },
                    };
                    shared |= matches!(now, Custody::Application(n) if n > 0);
                    oracle[at][index] = now;
                }
                let mut expected = [0u32; 7];
                for custody in oracle[at] {
                    expected[custody.partition()] += 1;
                    reached[custody.partition()] = true;
                }
                assert_eq!(
                    pools.census(kind),
                    expected,
                    "seed {seed} step {step} {kind:?}"
                );
                let report = arena.report(kind);
                assert_eq!(
                    [
                        report.free,
                        report.application,
                        report.storage,
                        report.quarantined,
                        report.posted,
                        report.nic_held,
                        report.retired
                    ],
                    expected,
                    "seed {seed} step {step} {kind:?}"
                );
                assert_eq!(report.mismatched, mismatched[at]);
                // The free stack holds exactly the buffers no holder names, each once.
                let mut stack = pools.free_stack(kind);
                stack.sort_unstable();
                let free: Vec<u32> = (0..4)
                    .filter(|&index| oracle[at][index as usize] == Custody::Free)
                    .collect();
                assert_eq!(stack, free, "seed {seed} step {step} {kind:?}");
            }
        }
        assert_eq!(reached, [true; 7], "seed {seed} reaches every partition");
        assert!(shared, "seed {seed} shares a handle with device references");
        for raw in raws.drain(..) {
            // SAFETY: each live reference named here was taken over once with `into_raw` or `into_device` and returns once; any other identity names no live reference.
            assert!(unsafe { arena.nic_return(raw.kind, raw.index, raw.incarnation) });
        }
        for (held, detached) in stored.drain(..) {
            if detached {
                held.free(pools);
            } else {
                drop(held.into_buffer(pools));
            }
        }
        drop(handles);
        for buffer in posted {
            // SAFETY: no device received the posted buffer's address.
            unsafe { buffer.unpost() };
        }
        assert!(arena.release().is_ok(), "seed {seed}");
    }
}

fn held_kind(held: &super::pool::Held<'_>, arena: &BufferArena<TestPlatform>) -> PoolKind {
    let offset = held.offset();
    if offset >= arena.config().start(RECEIVE) {
        RECEIVE
    } else {
        READ
    }
}

fn held_index(
    held: &super::pool::Held<'_>,
    arena: &BufferArena<TestPlatform>,
    kind: PoolKind,
) -> usize {
    (held.offset() - arena.config().start(kind)) / arena.config().pool(kind).buffer_len as usize
}
