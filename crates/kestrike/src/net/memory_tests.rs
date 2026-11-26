//! Endpoint memory checks: exact charging and refusal, packet lease custody and the control reserve, request generations and census conservation, and the in-memory datagram link.

use crate::storage::owner_fixture::arena_sized;
use crate::storage::test_platform::TestPlatform;
use crate::storage::{
    BufferArena, BufferConfig, EngineBudget, HugepageSize, NodeMask, PacketLayout, PoolKind,
    PoolSpec, ValidatedBufferConfig,
};

use super::datagram::{
    DatagramError, Datagrams, FRAME_OVERHEAD, MAX_DATAGRAM, Outgoing, Payload, PeerId, Received,
};
use super::link::link;
use super::memory::{EndpointConfig, EndpointConfigError, SourcesError, sources};
use super::packet::{PacketExhausted, PacketLease, PacketPool, PacketPoolError, PacketUse};
use super::requests::{
    GENERATION_LIMIT, MAX_REQUEST_SLOTS, PeerCensus, RequestCensus, RequestId, RequestPressure,
    RequestTable,
};
use super::upload::SourceSlot;
use crate::storage::seeded::SplitMix64;

fn config() -> EndpointConfig {
    EndpointConfig {
        peers: 3,
        request_slots: 8,
        peer_requests: 2,
        receive_reserve: 2,
        batch: 2,
    }
}

/// A packet-only arena: `receive` buffers of `stride` bytes and four 4 KiB header buffers.
fn packet_config(receive: u32, stride: u32) -> ValidatedBufferConfig {
    let pools = [
        PoolSpec {
            kind: PoolKind::PacketReceive,
            count: receive,
            buffer_len: stride,
        },
        PoolSpec {
            kind: PoolKind::PacketHeader,
            count: 4,
            buffer_len: 4096,
        },
    ];
    BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &pools,
    }
    .validate()
    .unwrap()
}

fn packet_arena(config: &ValidatedBufferConfig) -> BufferArena<TestPlatform> {
    BufferArena::initialize(
        config,
        TestPlatform::heap(4096),
        &mut EngineBudget::new(usize::MAX),
    )
    .unwrap()
}

/// The arena charges the packet backing, its padding and tail, and the pool records once; a budget one byte short refuses with the budget unchanged. The endpoint then charges exactly its request table once, leaving descriptor memory to the payload pool that allocates it, a budget one byte short refuses with the budget unchanged, and each invalid shape is refused with its documented error.
#[test]
fn initialization_charges_the_computed_total_once_or_nothing() {
    let arena_config = packet_config(6, 16384);
    assert!(
        arena_config.tail_len() > 0,
        "the tail is charged with the backing"
    );
    let records = crate::storage::device::Pools::metadata_bytes(&arena_config);
    let arena_charge = arena_config.backing_len() + records;
    let mut short = EngineBudget::new(arena_charge - 1);
    let before = short;
    assert!(BufferArena::initialize(&arena_config, TestPlatform::heap(4096), &mut short).is_err());
    assert_eq!(short, before, "a refused arena leaves the budget");
    let mut exact = EngineBudget::new(arena_charge);
    let arena =
        BufferArena::initialize(&arena_config, TestPlatform::heap(4096), &mut exact).unwrap();
    assert_eq!(exact.used(), arena_charge);

    let valid = config().validate::<u64>(&arena_config).expect("valid");
    let requests = 8 * RequestTable::<u64>::metadata_bytes(1, 0).unwrap() + 3 * 8;
    assert_eq!(
        valid.charge(),
        requests,
        "each packet and descriptor byte is charged once"
    );
    let mut short = EngineBudget::new(1000 + valid.charge() - 1);
    short.charge(1000).unwrap();
    let before = short;
    assert!(valid.initialize(&arena, &mut short).is_err());
    assert_eq!(short, before, "a refused initialization leaves the budget");
    let mut exact = EngineBudget::new(valid.charge());
    let memory = valid.initialize(&arena, &mut exact).expect("fits");
    assert_eq!(exact.used(), valid.charge());
    assert_eq!(memory.config, config());
    assert_eq!(memory.receive.report().free, 6);
    assert_eq!(memory.requests.slots(), 8);
    drop(memory);

    let refused = |change: fn(&mut EndpointConfig)| {
        let mut shape = config();
        change(&mut shape);
        shape.validate::<u64>(&arena_config).err()
    };
    assert_eq!(refused(|c| c.peers = 0), Some(EndpointConfigError::NoPeers));
    assert_eq!(
        refused(|c| c.request_slots = 0),
        Some(EndpointConfigError::RequestSlots)
    );
    assert_eq!(
        refused(|c| c.request_slots = MAX_REQUEST_SLOTS + 1),
        Some(EndpointConfigError::RequestSlots)
    );
    assert_eq!(
        refused(|c| c.peer_requests = 3),
        Some(EndpointConfigError::PeerRequests),
        "three peers' shares of three exceed eight slots"
    );
    assert_eq!(
        refused(|c| c.peer_requests = 0),
        Some(EndpointConfigError::PeerRequests)
    );
    assert_eq!(refused(|c| c.batch = 3), Some(EndpointConfigError::Batch));
    assert_eq!(refused(|c| c.batch = 0), Some(EndpointConfigError::Batch));
    assert_eq!(
        refused(|c| c.receive_reserve = 6),
        Some(EndpointConfigError::Receive(PacketPoolError::Reserve))
    );
    let short_room = packet_config(6, 8192);
    let room = PacketLayout::of(8192).unwrap().data_room;
    assert!(room < FRAME_OVERHEAD + MAX_DATAGRAM);
    assert_eq!(
        config().validate::<u64>(&short_room).err(),
        Some(EndpointConfigError::ReceiveRoom { data_room: room })
    );
    let storage_only = [PoolSpec {
        kind: PoolKind::ReadResponse,
        count: 4,
        buffer_len: 4096,
    }];
    let storage_only = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &storage_only,
    }
    .validate()
    .unwrap();
    assert_eq!(
        config().validate::<u64>(&storage_only).err(),
        Some(EndpointConfigError::MissingKind(PoolKind::PacketReceive)),
        "an arena without packet kinds is refused"
    );
    drop(arena);
}

/// A 16 KiB receive stride holds the pinned native object header, packet header, headroom and one whole frame, and every populated data room lies inside its own buffer and its own backing page.
#[test]
fn the_receive_stride_holds_a_frame_inside_one_page() {
    let layout = PacketLayout::of(16384).expect("a layout");
    assert!(
        layout.data_room >= FRAME_OVERHEAD + MAX_DATAGRAM,
        "{layout:?}"
    );
    assert!(layout.data_offset + layout.data_room <= 16384);
    let arena_config = packet_config(64, 16384);
    let arena = packet_arena(&arena_config);
    let pool = PacketPool::new(&arena, PoolKind::PacketReceive, 1).unwrap();
    let base = arena.backing().base().as_ptr().addr();
    let page = HugepageSize::TwoMiB.bytes();
    let mut leases: Vec<_> = (0..64)
        .map(|_| pool.acquire(PacketUse::Control).unwrap())
        .collect();
    let mut rooms: Vec<_> = leases
        .iter_mut()
        .map(|lease| {
            let room = lease.buffer_mut();
            (room.as_ptr().addr() - base, room.len())
        })
        .collect();
    rooms.sort_unstable();
    for (at, (offset, len)) in rooms.iter().enumerate() {
        let buffer = arena_config.start(PoolKind::PacketReceive) + at * 16384;
        assert_eq!(*offset, buffer + layout.data_offset, "buffer {at}");
        assert_eq!(*len, layout.data_room);
        assert_eq!(
            offset / page,
            (offset + len - 1) / page,
            "buffer {at} stays in one page"
        );
    }
    drop(leases);
}

/// Initialization takes only the arena the configuration was validated against: another arena with both packet kinds and a fitting reserve, whose receive stride is too short for a frame, is refused.
#[test]
#[should_panic(
    expected = "an endpoint initializes over the arena its configuration was validated against"
)]
fn initialization_refuses_an_arena_other_than_the_validated_one() {
    let valid = config()
        .validate::<()>(&packet_config(6, 16384))
        .expect("a valid shape");
    let other = packet_arena(&packet_config(6, 8192));
    let _ = valid.initialize(&other, &mut EngineBudget::new(1 << 24));
}

/// A lease holds its buffer exclusively and returns it to the pool it came from; a forgotten lease keeps its buffer out of the pool for good, and data never takes the control reserve.
#[test]
fn leases_return_to_their_own_pool_and_data_leaves_the_control_reserve() {
    let first = super::packet::test_pool(4, 2).unwrap();
    let second = super::packet::test_pool(4, 2).unwrap();
    let mut lease = first.acquire(PacketUse::Data).unwrap();
    assert!(lease.belongs_to(&first) && !lease.belongs_to(&second));
    lease.buffer_mut()[..3].copy_from_slice(b"abc");
    lease.set_len(3);
    assert_eq!(lease.bytes(), b"abc");
    let other = first.acquire(PacketUse::Data).unwrap();
    assert_eq!(
        first.acquire(PacketUse::Data).err(),
        Some(PacketExhausted {
            wanted: PacketUse::Data
        })
    );
    let mut control = first.acquire(PacketUse::Control).unwrap();
    assert_eq!(
        control.retain_as_data().err(),
        Some(PacketExhausted {
            wanted: PacketUse::Data
        }),
        "the control reserve is not borrowed by data"
    );
    let report = first.report();
    assert_eq!((report.free, report.data, report.control), (1, 2, 1));
    assert_eq!(first.not_free(), report.count - report.free);
    drop(other);
    control.retain_as_data().expect("room under the data cap");
    drop((lease, control));
    assert_eq!(first.report().free, 4);
    assert_eq!(second.report().free, 4);
    assert_eq!((first.not_free(), second.not_free()), (0, 0));
    let forgotten = first.acquire(PacketUse::Control).unwrap();
    std::mem::forget(forgotten);
    assert_eq!(first.report().free, 3, "a forgotten lease keeps its buffer");
    assert_eq!(first.not_free(), 1, "the census counts a forgotten lease");
    let reused = first.acquire(PacketUse::Control).unwrap();
    assert!(
        reused.bytes().is_empty(),
        "a reacquired buffer starts empty"
    );
}

/// Retirement reduces usable capacity; the data cap shrinks with it so the
/// control reserve keeps both of its buffers for receives.
#[test]
fn a_retired_buffer_comes_out_of_the_data_cap_not_the_control_reserve() {
    let arena_config = packet_config(4, 16384);
    let arena = packet_arena(&arena_config);
    // Buffer 0 is the free stack's top, and its next free ends its last incarnation.
    arena
        .pools()
        .set_incarnation(PoolKind::PacketReceive, 0, u64::MAX);
    let pool = PacketPool::new(&arena, PoolKind::PacketReceive, 2).unwrap();
    drop(pool.acquire(PacketUse::Control).unwrap());
    assert_eq!(arena.report(PoolKind::PacketReceive).retired, 1);
    assert_eq!(
        pool.data_cap(),
        1,
        "three usable buffers less a reserve of two"
    );
    let refused = Some(PacketExhausted {
        wanted: PacketUse::Data,
    });
    let data = pool.acquire(PacketUse::Data).unwrap();
    assert_eq!(pool.acquire(PacketUse::Data).err(), refused);
    let mut control = pool.acquire(PacketUse::Control).unwrap();
    assert_eq!(control.retain_as_data().err(), refused);
    let reserved = pool.acquire(PacketUse::Control).expect("the whole reserve");
    drop((data, control, reserved));
}

/// Witness `live-data-control-retirement`, geometry count 4, control reserve 2: two live data leases, then a control lease on its terminal incarnation drops and retires its buffer. Immediately after, both data leases keep their bytes and identities, the data cap is 1, data admission and conversion refuse, and the reserve is short by exactly 1; returning one data lease clears the shortfall, and admission resumes once data drops below the cap. A second retirement reaches a data cap of 0, which the report shows as lost data capacity, and a third comes out of the reserve with the cap held at 0. The census sums to the count at every snapshot, and no retired buffer is acquired again.
#[test]
fn live_data_survives_a_control_retirement_and_drains_to_the_shrunk_cap() {
    const KIND: PoolKind = PoolKind::PacketReceive;
    let arena_config = packet_config(4, 16384);
    let arena = packet_arena(&arena_config);
    let pool = PacketPool::new(&arena, KIND, 2).unwrap();
    let refused = Some(PacketExhausted {
        wanted: PacketUse::Data,
    });
    let mut retired = Vec::new();
    // Asserts the per-buffer census matches the arena's counters and sums to the count, the free stack holds no duplicate or retired buffer, and no lease in `held` names a retired buffer; returns the view's report.
    let snapshot = |retired: &[u32], held: &[&PacketLease<'_>]| {
        let census = arena.pools().census(KIND);
        let counters = arena.report(KIND);
        assert_eq!(
            census,
            [
                counters.free,
                counters.application,
                counters.storage,
                counters.quarantined,
                counters.posted,
                counters.nic_held,
                counters.retired
            ]
        );
        assert_eq!(census.iter().sum::<u32>(), 4, "{census:?}");
        assert_eq!(counters.retired as usize, retired.len());
        let free = arena.pools().free_stack(KIND);
        let mut distinct = free.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), free.len(), "{free:?}");
        for lease in held {
            assert!(
                !retired.contains(&lease.identity().0),
                "a retired buffer is never leased again"
            );
        }
        assert!(
            free.iter().all(|index| !retired.contains(index)),
            "{free:?}"
        );
        let report = pool.report();
        assert_eq!(report.data + report.control, counters.application);
        report
    };
    // Retires the free stack's top buffer: sets its incarnation to the terminal `u64::MAX`, leases it for control, and drops the lease.
    let retire = |retired: &mut Vec<u32>| {
        let top = *arena.pools().free_stack(KIND).last().unwrap();
        arena.pools().set_incarnation(KIND, top as usize, u64::MAX);
        let control = pool.acquire(PacketUse::Control).unwrap();
        assert_eq!(control.identity(), (top, u64::MAX));
        drop(control);
        retired.push(top);
    };
    let mut first = pool.acquire(PacketUse::Data).unwrap();
    let mut second = pool.acquire(PacketUse::Data).unwrap();
    for (lease, bytes) in [(&mut first, b"first!"), (&mut second, b"second")] {
        lease.buffer_mut()[..6].copy_from_slice(bytes);
        lease.set_len(6);
    }
    let identities = (first.identity(), second.identity());
    let before = snapshot(&retired, &[&first, &second]);
    assert_eq!(
        (before.data, before.data_cap, before.reserve_shortfall()),
        (2, 2, 0)
    );

    retire(&mut retired);
    let after = snapshot(&retired, &[&first, &second]);
    assert_eq!(
        (
            after.free,
            after.data,
            after.data_cap,
            after.reserve_shortfall()
        ),
        (1, 2, 1, 1),
        "the reserve of 2 has one free buffer while data exceeds the shrunk cap"
    );
    assert!(!after.data_capacity_lost());
    assert_eq!(
        (first.bytes(), second.bytes()),
        (&b"first!"[..], &b"second"[..])
    );
    assert_eq!((first.identity(), second.identity()), identities);
    assert_eq!(pool.acquire(PacketUse::Data).err(), refused);
    let mut control = pool.acquire(PacketUse::Control).unwrap();
    assert_eq!(control.retain_as_data().err(), refused);
    snapshot(&retired, &[&first, &second, &control]);
    drop(control);

    drop(first);
    let drained = snapshot(&retired, &[&second]);
    assert_eq!(
        (drained.free, drained.data, drained.reserve_shortfall()),
        (2, 1, 0),
        "data at the cap leaves the whole reserve free"
    );
    assert_eq!(second.bytes(), b"second");
    assert_eq!(second.identity(), identities.1);
    assert_eq!(
        pool.acquire(PacketUse::Data).err(),
        refused,
        "data at the cap admits none"
    );
    drop(second);
    let admitted = pool
        .acquire(PacketUse::Data)
        .expect("data below the cap admits");
    snapshot(&retired, &[&admitted]);
    drop(admitted);

    retire(&mut retired);
    let lost = snapshot(&retired, &[]);
    assert_eq!(
        (
            lost.free,
            lost.data,
            lost.data_cap,
            lost.reserve_shortfall()
        ),
        (2, 0, 0, 0)
    );
    assert!(lost.data_capacity_lost());
    assert_eq!(pool.acquire(PacketUse::Data).err(), refused);
    let mut control = pool.acquire(PacketUse::Control).unwrap();
    assert_eq!(control.retain_as_data().err(), refused);
    drop(control);

    retire(&mut retired);
    let beyond = snapshot(&retired, &[]);
    assert_eq!(
        (beyond.free, beyond.data_cap),
        (1, 0),
        "the third retirement comes out of the reserve"
    );
    assert!(beyond.data_capacity_lost());
    let last = pool.acquire(PacketUse::Control).unwrap();
    snapshot(&retired, &[&last]);
}

#[test]
fn a_view_holds_its_kind_alone_until_it_drops() {
    let arena_config = packet_config(4, 16384);
    let arena = packet_arena(&arena_config);
    let view = PacketPool::new(&arena, PoolKind::PacketReceive, 1).unwrap();
    assert_eq!(
        PacketPool::new(&arena, PoolKind::PacketReceive, 1).err(),
        Some(PacketPoolError::InUse)
    );
    assert!(arena.acquire(PoolKind::PacketReceive).is_err());
    assert!(arena.post(PoolKind::PacketReceive).is_err());
    let header = PacketPool::new(&arena, PoolKind::PacketHeader, 1).unwrap();
    drop(view);
    drop(arena.acquire(PoolKind::PacketReceive).unwrap());
    let again = PacketPool::new(&arena, PoolKind::PacketReceive, 1).unwrap();
    assert_eq!(again.report().free, 4);
    assert_eq!(header.report().free, 4);
}

#[test]
#[should_panic(expected = "a posting completes through its own view")]
fn a_posting_completes_only_through_its_own_kinds_view() {
    let arena_config = packet_config(4, 16384);
    let arena = packet_arena(&arena_config);
    let receive = PacketPool::new(&arena, PoolKind::PacketReceive, 1).unwrap();
    let header = PacketPool::new(&arena, PoolKind::PacketHeader, 1).unwrap();
    let posted = header.post().unwrap();
    // SAFETY: the posting's address reached no device, so nothing writes the buffer.
    let _lease = unsafe { receive.received(posted, 0) };
}

#[test]
fn a_narrowed_lease_writes_where_it_reads() {
    let pool = super::packet::test_pool(2, 1).unwrap();
    let mut lease = pool.acquire(PacketUse::Control).unwrap();
    lease.buffer_mut()[..5].copy_from_slice(b"abcde");
    lease.set_len(5);
    lease.keep(2..5);
    assert_eq!(lease.bytes(), b"cde");
    assert_eq!(lease.buffer_mut().len(), lease.capacity());
    lease.buffer_mut()[..2].copy_from_slice(b"XY");
    lease.set_len(2);
    assert_eq!(lease.bytes(), b"XY");
}

#[test]
fn buffers_are_distinct_zeroed_and_keep_their_bytes() {
    let pool = super::packet::test_pool(5, 1).unwrap();
    let room = pool.layout().data_room;
    let mut leases: Vec<_> = (0..5)
        .map(|_| pool.acquire(PacketUse::Control).unwrap())
        .collect();
    for (i, lease) in leases.iter_mut().enumerate() {
        assert_eq!(lease.capacity(), room);
        assert!(lease.buffer_mut().iter().all(|&byte| byte == 0));
        lease.buffer_mut().fill(i as u8 + 1);
        lease.set_len(room);
    }
    for (i, lease) in leases.iter().enumerate() {
        assert!(lease.bytes().iter().all(|&byte| byte == i as u8 + 1));
    }
    drop(leases);
    let mut seen = [false; 5];
    for _ in 0..5 {
        let mut lease = pool.acquire(PacketUse::Control).unwrap();
        let fill = lease.buffer_mut()[0];
        assert!(lease.buffer_mut().iter().all(|&byte| byte == fill));
        seen[usize::from(fill) - 1] = true;
        std::mem::forget(lease);
    }
    assert_eq!(seen, [true; 5], "every buffer came back exactly once");
}

#[test]
fn lease_holds_no_padding() {
    let fields = size_of::<crate::storage::Buffer<'_>>()
        + size_of::<&PacketPool<'_>>()
        + size_of::<usize>()
        + size_of::<PacketUse>()
        + size_of::<usize>();
    assert_eq!(size_of::<PacketLease<'_>>(), fields);
}

/// An arena whose stride alignment pads a pool past the first hugepage charges the padded backing, a literal 4 MiB, and its records; a budget one byte short refuses with the budget unchanged.
#[test]
fn alignment_padding_is_charged_and_one_byte_short_refuses() {
    let pools = [
        PoolSpec {
            kind: PoolKind::ReadResponse,
            count: 1,
            buffer_len: 4096,
        },
        PoolSpec {
            kind: PoolKind::PacketReceive,
            count: 2,
            buffer_len: 1 << 20,
        },
        PoolSpec {
            kind: PoolKind::PacketHeader,
            count: 4,
            buffer_len: 4096,
        },
    ];
    let config = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &pools,
    }
    .validate()
    .unwrap();
    // 4 KiB, then 1 MiB - 4 KiB of padding before the 1 MiB stride, 2 MiB of receive buffers and 16 KiB of headers: 3 MiB + 16 KiB, rounded to two hugepages.
    assert_eq!(config.backing_len(), 4 << 20);
    let charge = (4 << 20) + 7 * 20;
    let mut short = EngineBudget::new(charge - 1);
    let before = short;
    assert!(BufferArena::initialize(&config, TestPlatform::heap(4096), &mut short).is_err());
    assert_eq!(short, before);
    let mut exact = EngineBudget::new(charge);
    let arena = BufferArena::initialize(&config, TestPlatform::heap(4096), &mut exact).unwrap();
    assert_eq!(exact.used(), charge);
    drop(arena);
}

/// Lease acquire and return, receive posting, device holds and their returns, and request admit, drain and release allocate nothing.
#[test]
fn leases_and_requests_allocate_nothing() {
    let arena_config = packet_config(6, 16384);
    let arena = packet_arena(&arena_config);
    let valid = config().validate::<u64>(&arena_config).unwrap();
    let mut memory = valid
        .initialize(&arena, &mut EngineBudget::new(1 << 24))
        .unwrap();
    let allocations = crate::instrument::allocations();
    for _ in 0..16 {
        let mut lease = memory.receive.acquire(PacketUse::Control).unwrap();
        lease.set_len(10);
        lease.retain_as_data().unwrap();
        drop(lease);
        let posted = memory.receive.post().unwrap();
        // SAFETY: no device wrote the posted buffer, so nothing is in flight.
        drop(unsafe { memory.receive.received(posted, 0) });
        let header = arena.acquire(PoolKind::PacketHeader).unwrap();
        let hold = header.source(0..64).unwrap().hold().unwrap();
        drop(header);
        drop(hold);
        let id = memory.requests.admit(PeerId(1), 7).unwrap();
        assert!(memory.requests.begin_drain(id));
        assert_eq!(memory.requests.release(id), Some(7));
    }
    assert_eq!(crate::instrument::allocations(), allocations);
}

/// Discarding a request in place settles the census, advances the slot's generation and retires the slot as releasing it does, and a stale handle discards nothing.
#[test]
fn discarding_a_request_settles_the_census_like_a_release() {
    let mut table = RequestTable::<u32>::with_generation_limit(1, 2, 1, 1);
    let active = table.admit(PeerId(1), 3).unwrap();
    assert_eq!(table.discard(active), Some(PeerId(1)));
    assert_eq!(table.discard(active), None, "a stale handle");
    assert_eq!(table.census(), RequestCensus::default());
    let draining = table.admit(PeerId(0), 4).unwrap();
    assert_eq!(draining.generation(), 1);
    assert!(table.begin_drain(draining));
    assert_eq!(table.peer_census(PeerId(0)).draining, 1);
    assert_eq!(table.get(active), None);
    assert_eq!(table.discard(draining), Some(PeerId(0)));
    assert_eq!(table.get(draining), None);
    assert_eq!(table.peer_census(PeerId(0)), PeerCensus::default());
    assert_eq!(
        table.census(),
        RequestCensus {
            active: 0,
            draining: 0,
            retired: 1
        },
        "the slot retired at its generation limit"
    );
    assert_eq!(
        table.admit(PeerId(0), 5).err(),
        Some((RequestPressure::Table, 5))
    );
}

/// Discarding through a read returns the peer with what the read saw of the live state, settles the census in the same pass, and a stale handle reads nothing and changes nothing.
#[test]
fn discarding_with_a_read_sees_the_state_once_and_settles() {
    let mut table = RequestTable::<u32>::new(2, 2, 1);
    let first = table.admit(PeerId(1), 3).unwrap();
    let second = table.admit(PeerId(0), 4).unwrap();
    assert!(table.begin_drain(second));
    assert_eq!(
        table.discard_with(first, |state| state * 10),
        Some((PeerId(1), 30))
    );
    assert_eq!(table.get(first), None);
    assert_eq!(table.peer_census(PeerId(1)), PeerCensus::default());
    let mut reads = 0;
    assert_eq!(
        table.discard_with(first, |_| reads += 1),
        None,
        "a stale handle"
    );
    assert_eq!(reads, 0, "the read runs only for a live request");
    assert_eq!(table.census().live(), 1, "the other request is untouched");
    assert_eq!(
        table.discard_with(second, |state| *state),
        Some((PeerId(0), 4))
    );
    assert_eq!(table.census(), RequestCensus::default());
}

/// A released request's handle never names its successor, and a slot whose generation reaches the limit retires.
#[test]
fn released_handles_go_stale_and_an_exhausted_slot_retires() {
    let mut table = RequestTable::<u32>::with_generation_limit(1, 1, 1, 2);
    let mut seen = Vec::new();
    for round in 0..3 {
        let id = table.admit(PeerId(0), round).unwrap();
        assert_eq!((id.slot(), id.generation()), (0, u64::from(round)));
        for old in &seen {
            assert_eq!(table.get(*old), None);
            assert_eq!(table.release(*old), None);
        }
        assert_eq!(table.release(id), Some(round));
        seen.push(id);
    }
    assert_eq!(table.census().retired, 1);
    assert_eq!(
        table.admit(PeerId(0), 9).err(),
        Some((RequestPressure::Table, 9))
    );
    let mut mixed = RequestTable::<u32>::with_generation_limit(3, 1, 3, 0);
    let first = mixed.admit(PeerId(0), 1).unwrap();
    mixed.admit(PeerId(0), 2).unwrap();
    assert_eq!(mixed.release(first), Some(1));
    assert_eq!(
        mixed.census(),
        RequestCensus {
            active: 1,
            draining: 0,
            retired: 1
        },
        "one live, one retired and one free slot"
    );
    let mut shared = RequestTable::<u32>::new(2, 1, 2);
    assert_eq!(
        shared.admit(PeerId(1), 4).err(),
        Some((RequestPressure::Peer, 4)),
        "a peer outside the table has no share"
    );
    assert_eq!(shared.peer_census(PeerId(1)), PeerCensus::default());
    let wire = RequestId::from_wire(0xABCD_0000_0000_1234);
    assert_eq!((wire.slot(), wire.generation()), (0xABCD, 0x1234));
    assert_eq!(wire.wire(), 0xABCD_0000_0000_1234);
    let top = RequestId::from_wire(u64::MAX);
    assert_eq!((top.slot(), top.generation()), (u16::MAX, GENERATION_LIMIT));
}

/// What `table` still answers for `id`, a handle whose request was released, one line per call that treats the handle as live. Every call that takes a handle runs; the mutating ones run last, so a handle that wrongly names a live request is reported by the reads before a mutation changes that request.
fn answers_for_released<T: std::fmt::Debug>(
    table: &mut RequestTable<T>,
    id: RequestId,
) -> Vec<String> {
    let mut answers = Vec::new();
    if let Some(state) = table.get(id) {
        answers.push(format!("get({id:?}) names {state:?}"));
    }
    if let Some(peer) = table.peer(id) {
        answers.push(format!("peer({id:?}) names {peer:?}"));
    }
    if table.draining(id) {
        answers.push(format!("draining({id:?}) is true"));
    }
    if let Some(state) = table.get_mut(id) {
        answers.push(format!("get_mut({id:?}) names {state:?}"));
    }
    if table.begin_drain(id) {
        answers.push(format!("begin_drain({id:?}) moved a request"));
    }
    if let Some(state) = table.release(id) {
        answers.push(format!("release({id:?}) returned {state:?}"));
    }
    if let Some(peer) = table.discard(id) {
        answers.push(format!("discard({id:?}) released a request of {peer:?}"));
    }
    answers
}

/// At the actual 48-bit width, a slot started one below [`GENERATION_LIMIT`] issues that generation and then the limit itself, the last one; the last request drains and releases lawfully, the slot then retires, and the next admission is refused for the table. No handle or wire identity repeats, and every released handle names nothing through any call that takes a handle.
#[test]
fn a_slot_at_the_actual_generation_limit_issues_it_last_drains_and_retires() {
    let mut table = RequestTable::<u32>::new(1, 1, 1);
    table.start_slot_at(0, GENERATION_LIMIT - 1);
    let below = table.admit(PeerId(0), 1).unwrap();
    assert_eq!(below.generation(), GENERATION_LIMIT - 1);
    assert_eq!(table.release(below), Some(1));
    assert_eq!(
        table.census(),
        RequestCensus::default(),
        "a slot below the limit returns to service"
    );
    let last = table.admit(PeerId(0), 2).unwrap();
    assert_eq!(last.generation(), GENERATION_LIMIT);
    assert_eq!(last.wire(), GENERATION_LIMIT);
    assert_ne!(last, below);
    assert_ne!(last.wire(), below.wire());
    assert_eq!(
        RequestId::from_wire(last.wire()),
        last,
        "the limit fits the wire's 48 bits beside the slot"
    );
    assert_eq!(table.get(last), Some(&2));
    assert_eq!(table.get(below), None);
    assert_eq!(
        table.release(below),
        None,
        "a stale handle releases nothing"
    );
    assert!(table.begin_drain(last));
    assert_eq!(table.peer_census(PeerId(0)).draining, 1);
    assert_eq!(
        table.census(),
        RequestCensus {
            active: 0,
            draining: 1,
            retired: 0
        },
        "a draining request holds its slot, which is not retired while it is live"
    );
    assert_eq!(table.release(last), Some(2), "the last request drains");
    assert_eq!(
        table.census(),
        RequestCensus {
            active: 0,
            draining: 0,
            retired: 1
        }
    );
    assert_eq!(table.room(PeerId(0)), Err(RequestPressure::Table));
    assert_eq!(
        table.admit(PeerId(0), 3).err(),
        Some((RequestPressure::Table, 3))
    );
    assert_eq!(table.live_id(0), None);
    for old in [below, last] {
        assert_eq!(answers_for_released(&mut table, old), Vec::<String>::new());
    }
    assert_eq!(table.census().retired, 1, "a stale handle changes nothing");
    assert_eq!(table.peer_census(PeerId(0)), PeerCensus::default());
}

/// The same admissions and releases on a slot started two generations below the limit: the slot returns to service after each release, never retires, and its third request is the first and only holder of the limit. Each released handle names nothing while its successor is live in the same slot.
#[test]
fn a_slot_below_its_last_generation_returns_to_service() {
    let mut table = RequestTable::new(1, 1, 8);
    table.start_slot_at(0, GENERATION_LIMIT - 2);

    let first = table.admit(PeerId(0), "first").expect("the slot is free");
    assert_eq!(table.release(first), Some("first"));
    let second = table
        .admit(PeerId(0), "second")
        .expect("the slot returned to service");
    assert!(table.begin_drain(second));
    assert_eq!(table.release(second), Some("second"));
    assert_eq!(
        table.census(),
        RequestCensus::default(),
        "no slot retires below the limit"
    );

    let third = table
        .admit(PeerId(0), "third")
        .expect("the slot returned to service");
    assert_eq!(
        [first, second, third].map(RequestId::generation),
        [GENERATION_LIMIT - 2, GENERATION_LIMIT - 1, GENERATION_LIMIT],
        "each release advances the generation by one"
    );
    for released in [first, second] {
        assert_eq!(
            answers_for_released(&mut table, released),
            Vec::<String>::new()
        );
    }
    assert_eq!(
        table.get(third),
        Some(&"third"),
        "a stale handle changes nothing"
    );
    assert_eq!(
        table.census(),
        RequestCensus {
            active: 1,
            draining: 0,
            retired: 0
        }
    );
}

/// A slot at the limit beside an ordinary slot. Discarding the request at the limit retires exactly that slot: the table's capacity falls by one, the other slot goes on issuing fresh generations, and no handle the table issues afterwards equals an earlier one.
#[test]
fn a_retired_slot_costs_one_slot_of_capacity_and_no_more() {
    let mut table = RequestTable::new(2, 1, 8);
    table.start_slot_at(0, GENERATION_LIMIT);

    let at_limit = table.admit(PeerId(0), "at limit").expect("slot 0 is free");
    let beside = table.admit(PeerId(0), "beside").expect("slot 1 is free");
    assert_eq!(
        (at_limit.slot(), at_limit.generation()),
        (0, GENERATION_LIMIT)
    );
    assert_eq!((beside.slot(), beside.generation()), (1, 0));

    assert_eq!(table.discard(at_limit), Some(PeerId(0)));
    assert_eq!(
        table.census(),
        RequestCensus {
            active: 1,
            draining: 0,
            retired: 1
        }
    );
    let refused = table.admit(PeerId(0), "no slot");
    assert_eq!(
        refused,
        Err((RequestPressure::Table, "no slot")),
        "the retired slot is not issued again while the other slot is live"
    );

    let mut issued = vec![at_limit, beside];
    let mut live = beside;
    for round in 1..=4u64 {
        assert!(table.release(live).is_some());
        let next = table
            .admit(PeerId(0), "next")
            .expect("slot 1 returns to service");
        assert_eq!((next.slot(), next.generation()), (1, round));
        assert!(!issued.contains(&next), "handle {next:?} repeats");
        issued.push(next);
        live = next;
        let refused = table.admit(PeerId(0), "no slot");
        assert_eq!(refused, Err((RequestPressure::Table, "no slot")));
    }
    assert_eq!(
        table.census(),
        RequestCensus {
            active: 1,
            draining: 0,
            retired: 1
        },
        "exactly the slot at the limit retired"
    );
    assert_eq!(
        answers_for_released(&mut table, at_limit),
        Vec::<String>::new()
    );
    assert_eq!(table.get(live), Some(&"next"));
}

#[test]
fn request_slots_admit_n_minus_one_and_n_and_refuse_n_plus_one() {
    for slots in [2, 4, 16] {
        let mut table = RequestTable::<u32>::new(slots, 1, slots + 1);
        for n in 0..slots {
            assert!(table.admit(PeerId(0), n).is_ok(), "{n} of {slots}");
        }
        assert_eq!(
            table.admit(PeerId(0), slots).err(),
            Some((RequestPressure::Table, slots))
        );
        let mut shared = RequestTable::<u32>::new(slots + 1, 1, slots);
        for n in 0..slots {
            assert!(shared.admit(PeerId(0), n).is_ok(), "{n} of {slots}");
        }
        assert_eq!(
            shared.admit(PeerId(0), slots).err(),
            Some((RequestPressure::Peer, slots))
        );
    }
}

/// Over seeded histories of admits, drains and releases, every peer's active and draining requests stay within its share, the totals equal the sum over peers and the live handles, a refusal names the share that was full, and the high-water mark stays one past the highest slot admitted, so every live request lies below it.
#[test]
fn the_census_is_conserved_across_seeded_histories() {
    for seed in 0..16 {
        let mut rng = SplitMix64::new(seed);
        let mut table = RequestTable::<u64>::new(8, 3, 4);
        let mut live: Vec<(RequestId, PeerId, bool)> = Vec::new();
        let (mut peer_refusals, mut table_refusals) = (0, 0);
        let mut high_water = 0;
        for step in 0..400 {
            match rng.below(4) {
                0 | 1 => {
                    let peer = PeerId(rng.below(3) as u16);
                    let held = live.iter().filter(|(_, p, _)| *p == peer).count();
                    match table.admit(peer, step) {
                        Ok(id) => {
                            high_water = high_water.max(u32::from(id.slot()) + 1);
                            live.push((id, peer, false));
                        }
                        Err((pressure, state)) => {
                            assert_eq!(state, step);
                            if held >= 4 {
                                assert_eq!(pressure, RequestPressure::Peer);
                                peer_refusals += 1;
                            } else {
                                assert_eq!(live.len(), 8);
                                assert_eq!(pressure, RequestPressure::Table);
                                table_refusals += 1;
                            }
                        }
                    }
                }
                2 if !live.is_empty() => {
                    let at = rng.below(live.len() as u64) as usize;
                    let (id, _, draining) = &mut live[at];
                    assert_eq!(table.begin_drain(*id), !*draining);
                    *draining = true;
                }
                _ if !live.is_empty() => {
                    let at = rng.below(live.len() as u64) as usize;
                    let (id, _, _) = live.swap_remove(at);
                    assert!(table.release(id).is_some());
                    assert_eq!(table.get(id), None);
                }
                _ => {}
            }
            let mut total = RequestCensus::default();
            for peer in 0..3 {
                let census = table.peer_census(PeerId(peer));
                let expected = live.iter().filter(|(_, p, _)| p.0 == peer).fold(
                    PeerCensus::default(),
                    |mut census, (_, _, draining)| {
                        if *draining {
                            census.draining += 1;
                        } else {
                            census.active += 1;
                        }
                        census
                    },
                );
                assert_eq!(census, expected, "seed {seed} step {step}");
                assert!(census.active + census.draining <= 4);
                total.active += census.active;
                total.draining += census.draining;
            }
            assert_eq!(table.census(), total);
            for (id, peer, _) in &live {
                assert_eq!(table.peer(*id), Some(*peer));
            }
            assert_eq!(table.high_water(), high_water, "seed {seed} step {step}");
            assert!((high_water..table.slots()).all(|slot| table.live_id(slot).is_none()));
        }
        assert!(peer_refusals > 0 && table_refusals > 0, "seed {seed}");
    }
}

/// A send holds one device reference per retained piece of each datagram it took, and none for a datagram it refused: past a full queue, past a refused later datagram, and when a later piece's source is at its cap. Delivery reads the retained bytes and returns each reference.
#[test]
fn the_link_holds_references_only_for_datagrams_it_took() {
    let arena_config = packet_config(6, 16384);
    let arena = packet_arena(&arena_config);
    let pool = super::packet::test_pool(4, 1).unwrap();
    let mut first = arena.acquire(PoolKind::PacketHeader).unwrap();
    first.bytes_mut()[..4].copy_from_slice(b"abcd");
    let mut second = arena.acquire(PoolKind::PacketHeader).unwrap();
    second.bytes_mut()[..2].copy_from_slice(b"xy");
    let held = || {
        arena.report(PoolKind::PacketHeader).nic_held
            + arena.report(PoolKind::PacketHeader).application
    };
    let references =
        |net: &std::rc::Rc<std::cell::RefCell<super::link::Net<'_>>>| net.borrow().nic_held();
    let (mut near, mut far, net) =
        super::link::network(2, 8384, 0, [super::link::Faults::default(); 2]);
    let a = first.source(0..4).unwrap();
    let b = second.source(0..2).unwrap();
    let datagram = Outgoing {
        peer: PeerId(0),
        header: b"h",
        payload: [Payload::Retained(a), Payload::Retained(b)],
    };
    assert_eq!(near.send(&[datagram; 3]), Ok(2), "the queue holds two");
    assert_eq!(
        references(&net),
        4,
        "two references for each datagram taken, none for the third"
    );
    let oversized = vec![0; 8385];
    let refused = Outgoing {
        peer: PeerId(0),
        header: &oversized,
        payload: [Payload::Retained(a), Payload::EMPTY],
    };
    let mut meta = [Received::default(); 2];
    let mut leases: [Option<PacketLease<'_>>; 2] = [None, None];
    assert_eq!(far.receive(&pool, &mut leases, &mut meta), Ok(2));
    assert_eq!(
        leases[0].as_ref().unwrap().bytes(),
        b"habcdxy",
        "delivery reads the retained bytes"
    );
    assert_eq!(references(&net), 0, "delivered references returned");
    assert_eq!(
        near.send(&[datagram, refused]),
        Ok(1),
        "a refused later datagram ends the prefix"
    );
    assert_eq!(references(&net), 2);
    for _ in 0..u16::MAX - 1 {
        b.hold().unwrap().into_raw();
    }
    assert_eq!(
        near.send(&[datagram]),
        Err(DatagramError::Failed {
            code: Some(libc::ESTALE)
        }),
        "the second piece's source is at its cap"
    );
    assert_eq!(
        references(&net),
        2,
        "the refused datagram released its first piece's reference"
    );
    net.borrow_mut().clear(1);
    assert_eq!(references(&net), 0);
    let (index, incarnation) = second.identity();
    for _ in 0..u16::MAX - 1 {
        // SAFETY: each return names a reference this test detached with `into_raw`, once.
        assert!(unsafe { arena.nic_return(PoolKind::PacketHeader, index, incarnation) });
    }
    drop((first, second, leases));
    assert_eq!(held(), 0, "every reference returned");
    assert_eq!(arena.report(PoolKind::PacketHeader).mismatched, 0);
}

/// A datagram whose payload spans two buffers holds one reference on each; delivered with seeded delayed returns, each buffer's reference returns independently, one while the other is still held, at a turn the schedule draws.
#[test]
fn a_two_buffer_datagram_holds_and_releases_each_buffer_on_its_own() {
    let arena_config = packet_config(6, 16384);
    let arena = packet_arena(&arena_config);
    let pool = super::packet::test_pool(4, 1).unwrap();
    let kind = PoolKind::PacketHeader;
    let mut apart = false;
    for seed in 0..16 {
        let first = arena.acquire(kind).unwrap();
        let second = arena.acquire(kind).unwrap();
        let (mut near, mut far, net) =
            super::link::network(2, 8384, seed, [super::link::Faults::default(); 2]);
        net.borrow_mut()
            .set_tx_release(super::link::TxRelease::Delayed(50));
        let datagram = Outgoing {
            peer: PeerId(0),
            header: b"h",
            payload: [
                Payload::Retained(first.source(0..4).unwrap()),
                Payload::Retained(second.source(0..4).unwrap()),
            ],
        };
        assert_eq!(near.send(&[datagram]), Ok(1));
        drop((first, second));
        assert_eq!(
            arena.report(kind).nic_held,
            2,
            "one reference on each buffer"
        );
        let mut leases: [Option<PacketLease<'_>>; 1] = [None];
        let mut meta = [Received::default(); 1];
        assert_eq!(far.receive(&pool, &mut leases, &mut meta), Ok(1));
        for turn in 0..=50 {
            net.borrow_mut().advance(turn);
            near.reclaim();
            apart |= arena.report(kind).nic_held == 1;
        }
        assert_eq!(arena.report(kind).nic_held, 0, "seed {seed}: both returned");
    }
    assert!(
        apart,
        "some schedule returned one buffer while the other stayed held"
    );
}

/// The link delivers whole datagrams in order into buffers posted from the caller's pool, truncates one longer than the data room, reports a send's accepted prefix when its queue fills or a later datagram is refused, fails a call whose first datagram is refused, receives at most the batch it is given, and refuses after close.
#[test]
fn the_in_memory_link_keeps_the_seam_contract() {
    let pool = super::packet::test_pool_with(4, 2, 4096).unwrap();
    let room = pool.layout().data_room;
    let long = vec![0x5A; room];
    let (mut near, mut far) = link(3, room + 16);
    let mut header = *b"head";
    let batch = [
        Outgoing {
            peer: PeerId(0),
            header: &header,
            payload: [Payload::Inline(b"ab"), Payload::Inline(b"c")],
        },
        Outgoing {
            peer: PeerId(0),
            header: &header,
            payload: [Payload::Inline(&long), Payload::Inline(b"ab")],
        },
        Outgoing {
            peer: PeerId(0),
            header: b"x",
            payload: [Payload::EMPTY; 2],
        },
        Outgoing {
            peer: PeerId(0),
            header: b"y",
            payload: [Payload::EMPTY; 2],
        },
    ];
    assert_eq!(near.send(&batch), Ok(3), "the queue holds three");
    header.copy_from_slice(b"HEAD");
    assert_eq!(far.pending(), 3);
    let mut leases: [Option<PacketLease<'_>>; 2] = [None, None];
    let mut meta = [Received::default(); 2];
    let allocations = crate::instrument::allocations();
    assert_eq!(far.receive(&pool, &mut leases, &mut meta), Ok(2));
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(
        leases[0].as_ref().unwrap().bytes(),
        b"headabc",
        "bytes accepted at send return"
    );
    let truncated = leases[1].as_ref().unwrap().bytes();
    assert_eq!(truncated.len(), room);
    assert_eq!(&truncated[..4], b"head");
    assert_eq!(
        meta,
        [
            Received {
                peer: Some(PeerId(0)),
                truncated: false
            },
            Received {
                peer: Some(PeerId(0)),
                truncated: true
            },
        ]
    );
    assert_eq!(
        pool.report().free,
        2,
        "each delivery took one posted buffer"
    );
    leases = [None, None];
    assert_eq!(
        far.receive(&pool, &mut leases, &mut meta[..1]),
        Ok(1),
        "meta bounds the batch"
    );
    assert_eq!(leases[0].as_ref().unwrap().bytes(), b"x");
    assert_eq!(
        far.receive(&pool, &mut leases[1..], &mut meta),
        Ok(0),
        "nothing ready"
    );
    let foreign = [Outgoing {
        peer: PeerId(1),
        header: b"z",
        payload: [Payload::EMPTY; 2],
    }];
    assert_eq!(
        near.send(&foreign),
        Err(DatagramError::Failed { code: None }),
        "a leading datagram for an unconfigured peer fails the call"
    );
    let wide = vec![0; room + 17];
    let oversized = [
        Outgoing {
            peer: PeerId(0),
            header: &wide,
            payload: [Payload::EMPTY; 2],
        },
        Outgoing {
            peer: PeerId(0),
            header: b"w",
            payload: [Payload::EMPTY; 2],
        },
    ];
    assert_eq!(
        near.send(&oversized),
        Err(DatagramError::Failed {
            code: Some(libc::EMSGSIZE)
        }),
        "a leading datagram past the link's length fails the call"
    );
    assert_eq!(
        near.send(&[oversized[1], oversized[0]]),
        Ok(1),
        "a later one ends the accepted prefix"
    );
    far.close();
    assert_eq!(
        far.receive(&pool, &mut leases[1..], &mut meta),
        Err(DatagramError::Closed)
    );
    assert_eq!(
        leases[0].as_ref().unwrap().bytes(),
        b"x",
        "a refused receive leaves the leases"
    );
    drop(leases);
    assert_eq!(pool.report().free, 4);
}

/// The ReadResponse buffers `arena` still gives out.
fn free_buffers(arena: &BufferArena<TestPlatform>) -> usize {
    let mut taken = Vec::new();
    while let Ok(buffer) = arena.acquire(PoolKind::ReadResponse) {
        taken.push(buffer);
    }
    taken.len()
}

/// The bytes `sources` charges for `count` slots.
fn sources_charge(count: u32) -> usize {
    count as usize * size_of::<SourceSlot<'static>>()
}

/// A pool one buffer larger than a `u16` indexes isolates the width bound: the pool-count bound and the budget admit 65,537, so only the slot index width refuses it. The refusal charges nothing and takes no buffer, and the same pool admits 65,536, charged once, with one buffer left.
#[test]
fn a_count_one_past_the_slot_index_width_is_refused_on_a_pool_that_holds_it() {
    const ADDRESSABLE: u32 = 1 << 16;
    let shared = arena_sized(ADDRESSABLE + 1, 8192);
    assert_eq!(
        shared.config().pool(PoolKind::ReadResponse).count,
        ADDRESSABLE + 1
    );
    let mut budget = EngineBudget::new(1 << 30);
    assert!(sources_charge(ADDRESSABLE + 1) <= (1 << 30) - budget.used());
    let before = budget;
    assert_eq!(
        sources(&shared, ADDRESSABLE + 1, &mut budget).err(),
        Some(SourcesError::Count)
    );
    assert_eq!(budget, before, "a refused count charges nothing");
    let slots = sources(&shared, ADDRESSABLE, &mut budget).unwrap();
    assert_eq!(slots.len(), ADDRESSABLE as usize);
    assert_eq!(
        budget.used() - before.used(),
        sources_charge(ADDRESSABLE),
        "the admitted slots are charged once"
    );
    assert_eq!(free_buffers(&shared), 1, "the refused count took no buffer");
}

/// A pool of 8 buffers isolates the pool-count bound: 9 lies far inside the slot index width and the budget, so only the pool's buffer count refuses it. The refusal charges nothing and takes no buffer, and the pool then admits 8, charged once, with no buffer left.
#[test]
fn a_count_one_past_the_pool_is_refused_far_inside_the_slot_index_width() {
    const POOL: u32 = 8;
    let shared = arena_sized(POOL, 8192);
    assert_eq!(shared.config().pool(PoolKind::ReadResponse).count, POOL);
    let mut budget = EngineBudget::new(1 << 30);
    let before = budget;
    assert_eq!(
        sources(&shared, POOL + 1, &mut budget).err(),
        Some(SourcesError::Count)
    );
    assert_eq!(budget, before, "a refused count charges nothing");
    let slots = sources(&shared, POOL, &mut budget).unwrap();
    assert_eq!(slots.len(), POOL as usize);
    assert_eq!(
        budget.used() - before.used(),
        sources_charge(POOL),
        "the admitted slots are charged once"
    );
    assert_eq!(free_buffers(&shared), 0, "the refused count took no buffer");
}
