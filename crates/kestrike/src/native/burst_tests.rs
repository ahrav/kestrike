//! The burst logic over mock pools and a mock port.

mod custody;

use std::cell::Cell;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use spdk_sys as sys;

use super::burst::{Burst, BurstError, BurstRefusal, Link, Port};
use super::env::Environment;
use super::mempool::{OpsState, PacketMempool, Role};
use super::mock::{self, COUNT, Forged, MockPort, arrive_on, iova, segment_bytes as bytes};
use super::recovery::{RecoveryEpisode, RecoveryStage, RecoveryWatch};
use super::registration::{ArenaRegistration, DeviceId, DeviceLease};
use super::registration_tests::ready;
use super::watchdog::{Rearmable, Shared, State, Supervisor, Timer};
use super::wire::{Refused, RxMeta, Station, Wire};
use crate::net::{
    DatagramError, Datagrams, FRAME_OVERHEAD, Outgoing, PacketLease, PacketPool, Payload, PeerId,
    Received,
};
use crate::storage::test_platform::TestPlatform;
use crate::storage::{Buffer, BufferArena, BufferPoolReport, EngineBudget, PoolKind};

pub(super) const LOCAL: Station = Station {
    mac: [2, 0, 0, 0, 0, 1],
    ip: [10, 0, 0, 1],
    port: 7000,
    ports: 1,
};
const PEER: Station = Station {
    mac: [2, 0, 0, 0, 0, 2],
    ip: [10, 0, 0, 2],
    port: 9000,
    ports: 1,
};
pub(super) const PEERS: [Station; 1] = [PEER];

mod replay;

struct Fixture {
    arena: &'static BufferArena<TestPlatform>,
    burst: Burst<'static, MockPort>,
    receive: &'static PacketPool<'static>,
    receive_ops: mock::MockPool,
    header: mock::MockPool,
    payload: mock::MockPool,
}

fn fixture_with(translate: Box<dyn Fn(usize, usize) -> Option<u64>>) -> Fixture {
    fixture_on(mock::arena(), translate)
}

fn fixture_on(
    arena: &'static BufferArena<TestPlatform>,
    translate: Box<dyn Fn(usize, usize) -> Option<u64>>,
) -> Fixture {
    fixture_over(
        arena,
        Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap(),
        translate,
        Box::new(|| true),
    )
}

fn fixture_over(
    arena: &'static BufferArena<TestPlatform>,
    wire: Wire<'static>,
    translate: Box<dyn Fn(usize, usize) -> Option<u64>>,
    recheck: Box<dyn Fn() -> bool>,
) -> Fixture {
    fixture_watched(arena, wire, translate, recheck, mock::watch())
}

fn fixture_watched(
    arena: &'static BufferArena<TestPlatform>,
    wire: Wire<'static>,
    translate: Box<dyn Fn(usize, usize) -> Option<u64>>,
    recheck: Box<dyn Fn() -> bool>,
    watch: RecoveryWatch,
) -> Fixture {
    fixture_built(arena, wire, translate, recheck, watch, 8, 8)
}

/// [`fixture_watched`] over a payload pool of `descriptors` descriptors, carrying at most `batch` datagrams per call.
fn fixture_built(
    arena: &'static BufferArena<TestPlatform>,
    wire: Wire<'static>,
    translate: Box<dyn Fn(usize, usize) -> Option<u64>>,
    recheck: Box<dyn Fn() -> bool>,
    watch: RecoveryWatch,
    descriptors: u32,
    batch: usize,
) -> Fixture {
    let header = mock::arena_pool(arena, PoolKind::PacketHeader, Role::Header);
    let payload = mock::payload_pool(arena, descriptors);
    let receive_ops = mock::arena_pool(arena, PoolKind::PacketReceive, Role::Receive);
    let receive = Box::leak(Box::new(
        PacketPool::new(arena, PoolKind::PacketReceive, 2).unwrap(),
    ));
    let pools = [header.state, payload.state, receive_ops.state];
    let port = MockPort {
        receive: Some(receive_ops.state),
        ..MockPort::open()
    };
    let registration = Box::leak(Box::new(Forged(translate, recheck)));
    let burst = Burst::new(
        port,
        wire,
        pools,
        registration,
        watch,
        batch,
        &mut EngineBudget::unlimited(),
    )
    .unwrap();
    Fixture {
        arena,
        burst,
        receive,
        receive_ops,
        header,
        payload,
    }
}

fn fixture() -> Fixture {
    fixture_with(Box::new(iova))
}

/// A read-response buffer filled with `fill`, a retained source.
fn source(arena: &'static BufferArena<TestPlatform>, fill: u8) -> Buffer<'static> {
    let mut buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    buffer.bytes_mut().fill(fill);
    buffer
}

fn held(arena: &BufferArena<TestPlatform>, kind: PoolKind) -> u32 {
    let report = arena.report(kind);
    report.count - report.free
}

fn descriptors(f: &Fixture) -> u32 {
    descriptors_of(&f.payload)
}

fn descriptors_of(payload: &mock::MockPool) -> u32 {
    (0..=8)
        .rev()
        .find(|&n| {
            let mut slots = vec![std::mem::MaybeUninit::uninit(); n as usize];
            let taken = payload.state.take(&mut slots);
            if taken {
                for slot in slots {
                    // SAFETY: taken just now, never seen by a device.
                    unsafe { payload.state.give_back(slot.assume_init()) };
                }
            }
            taken
        })
        .unwrap_or(0)
}

/// Pools of the wrong roles, a header stride with no packet layout, whatever the batch, and a zero batch are refused, each refusal handing back the port.
#[test]
fn burst_logic_refuses_misassigned_pools_and_a_zero_batch() {
    let arena = mock::arena();
    let header = mock::arena_pool(arena, PoolKind::PacketHeader, Role::Header);
    let payload = mock::payload_pool(arena, 2);
    let receive = mock::arena_pool(arena, PoolKind::PacketReceive, Role::Receive);
    let mut wire = Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap();
    // A 64-byte header stride holds no mbuf, so it has no packet layout.
    let unshaped: &'static OpsState = Box::leak(Box::new(OpsState::new(
        Role::Header,
        arena.pools().pool(PoolKind::PacketHeader),
        0,
        6,
        1,
    )));
    let swapped = [receive.state, payload.state, header.state];
    let pools = [header.state, payload.state, receive.state];
    let unlaid = [unshaped, payload.state, receive.state];
    let registration = Forged(iova, || true);
    for (pools, batch, expected) in [
        (swapped, 8, BurstError::Pools),
        (unlaid, 8, BurstError::Pools),
        (unlaid, 0, BurstError::Pools),
        (pools, 0, BurstError::Batch),
    ] {
        let port = MockPort {
            ring: 5,
            ..MockPort::open()
        };
        let Err(refused) = Burst::new(
            port,
            wire,
            pools,
            &registration,
            mock::watch(),
            batch,
            &mut EngineBudget::unlimited(),
        ) else {
            panic!("the construction is refused");
        };
        assert_eq!(refused.error, expected);
        assert_eq!(
            (refused.port.ring, refused.port.calls),
            (5, 0),
            "the port comes back untouched"
        );
        wire = refused.wire;
    }
}

/// The header, payload and receive packet mempools of `device` over `arena`, in `Burst::over`'s order; every kind is served once per arena.
fn mempools(
    arena: &'static BufferArena<TestPlatform>,
    device: DeviceId,
) -> [PacketMempool<'static>; 3] {
    let payload = mock::payload_pool(arena, 8);
    [
        mock::mempool(arena, PoolKind::PacketHeader, device),
        PacketMempool::mocked(payload.mp, payload.state, device),
        mock::mempool(arena, PoolKind::PacketReceive, device),
    ]
}

/// The arena's per-kind custody, which a refused construction leaves as it was.
fn custody(arena: &BufferArena<TestPlatform>) -> [BufferPoolReport; 3] {
    [
        PoolKind::ReadResponse,
        PoolKind::PacketReceive,
        PoolKind::PacketHeader,
    ]
    .map(|kind| arena.report(kind))
}

/// Builds over `pools` of `arena` and `registration`, and returns the refusal after checking it allocated nothing, took no buffer and drove no device.
fn refuse<'a>(
    arena: &BufferArena<TestPlatform>,
    port: MockPort,
    pools: [&'a PacketMempool<'static>; 3],
    registration: &'a ArenaRegistration<'_>,
    batch: usize,
    budget: &mut EngineBudget,
) -> BurstRefusal<'a, MockPort> {
    let wire = Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap();
    let watch = mock::watch();
    let (before, unchanged) = (custody(arena), *budget);
    let allocations = crate::instrument::allocations();
    let outcome = Burst::over(port, wire, pools, registration, watch, batch, budget);
    assert_eq!(
        crate::instrument::allocations(),
        allocations,
        "a refusal allocates nothing"
    );
    let Err(refused) = outcome else {
        panic!("the construction is refused");
    };
    assert_eq!(custody(arena), before, "a refusal takes no buffer");
    assert_eq!(*budget, unchanged, "a refusal charges nothing");
    assert!(
        pools.iter().all(|pool| pool.armed()),
        "every pool keeps serving"
    );
    assert_eq!(refused.port.calls, 0, "a refusal drives no device");
    assert_eq!(
        refused.wire.peers(),
        PEERS.len(),
        "the addressing comes back"
    );
    refused
}

/// Stops a refused mock port explicitly and retires its lease, as a caller reclaims a port the constructor handed back.
fn reclaim(mut port: MockPort, registration: &mut ArenaRegistration<'_>) {
    port.stop().unwrap();
    let lease: DeviceLease = port.lease.take().expect("the refused port keeps its lease");
    registration.device_stopped(lease.stopped()).unwrap();
}

/// A port leased for one device is refused over the pools of another, even when both leases are of the same registration, as is a port holding no lease; each refusal returns the port as it came, having allocated nothing and driven no device.
#[test]
fn burst_logic_refuses_a_port_leased_for_another_device() {
    let (env, arena) = (Environment::detached(), mock::arena());
    let mut registration = ready(&env, arena);
    let (a, b) = (
        registration.device_attached(),
        registration.device_attached(),
    );
    let (port_device, pool_device) = (a.device(), b.device());
    let pools = mempools(arena, pool_device);
    let port = MockPort {
        lease: Some(a),
        ..MockPort::open()
    };
    let refused = refuse(
        arena,
        port,
        pools.each_ref(),
        &registration,
        8,
        &mut EngineBudget::unlimited(),
    );
    assert_eq!(refused.error, BurstError::Port);
    assert_eq!(
        refused.port.lease.as_ref().map(DeviceLease::device),
        Some(port_device),
        "the port keeps the lease it came with"
    );
    reclaim(refused.port, &mut registration);
    let refused = refuse(
        arena,
        MockPort::open(),
        pools.each_ref(),
        &registration,
        8,
        &mut EngineBudget::unlimited(),
    );
    assert_eq!(
        refused.error,
        BurstError::Port,
        "a port with no lease is refused"
    );
    drop(pools);
    registration.device_stopped(b.stopped()).unwrap();
}

/// Pools of two devices, pools and a port of another registration's lease, pools of the wrong roles and a zero batch are refused through `over`, each returning the port with its lease, having allocated nothing and driven no device.
#[test]
fn burst_logic_refuses_mixed_pools_another_registration_and_bad_shapes() {
    let env = Environment::detached();
    // Which of the payload and receive pools serves the port's sibling lease.
    for (payload_on_b, receive_on_b) in [(true, false), (false, true)] {
        let arena = mock::arena();
        let mut registration = ready(&env, arena);
        let (a, b) = (
            registration.device_attached(),
            registration.device_attached(),
        );
        let on = |other: bool| if other { b.device() } else { a.device() };
        let payload = mock::payload_pool(arena, 8);
        let mixed = [
            mock::mempool(arena, PoolKind::PacketHeader, a.device()),
            PacketMempool::mocked(payload.mp, payload.state, on(payload_on_b)),
            mock::mempool(arena, PoolKind::PacketReceive, on(receive_on_b)),
        ];
        let port = MockPort {
            lease: Some(a),
            ..MockPort::open()
        };
        let refused = refuse(
            arena,
            port,
            mixed.each_ref(),
            &registration,
            8,
            &mut EngineBudget::unlimited(),
        );
        assert_eq!(
            refused.error,
            BurstError::Pools,
            "a sibling pool serves another device"
        );
        reclaim(refused.port, &mut registration);
        drop(mixed);
        registration.device_stopped(b.stopped()).unwrap();
    }

    let other_arena = mock::arena();
    let mut other = ready(&env, other_arena);
    let lease = other.device_attached();
    let pools = mempools(other_arena, lease.device());
    let port = MockPort {
        lease: Some(lease),
        ..MockPort::open()
    };
    let registration = ready(&env, mock::arena());
    let refused = refuse(
        other_arena,
        port,
        pools.each_ref(),
        &registration,
        8,
        &mut EngineBudget::unlimited(),
    );
    assert_eq!(
        refused.error,
        BurstError::Pools,
        "the device is another registration's"
    );
    let swapped = [&pools[2], &pools[1], &pools[0]];
    let refused = refuse(
        other_arena,
        refused.port,
        swapped,
        &other,
        8,
        &mut EngineBudget::unlimited(),
    );
    assert_eq!(
        refused.error,
        BurstError::Pools,
        "swapped roles are refused through `over`"
    );
    let refused = refuse(
        other_arena,
        refused.port,
        pools.each_ref(),
        &other,
        0,
        &mut EngineBudget::unlimited(),
    );
    assert_eq!(refused.error, BurstError::Batch);
    let mut empty = EngineBudget::new(0);
    let refused = refuse(
        other_arena,
        refused.port,
        pools.each_ref(),
        &other,
        8,
        &mut empty,
    );
    assert!(
        matches!(refused.error, BurstError::Budget(_)),
        "an empty budget refuses through `over` too"
    );
    reclaim(refused.port, &mut other);
}

/// A port over its own lease's pools and registration builds, and carries a datagram whose payload segment takes the registration's IOVA, then leases a received frame.
#[test]
fn burst_logic_over_its_own_leases_pools_sends_and_receives() {
    let (env, arena) = (Environment::detached(), mock::arena());
    let mut registration = ready(&env, arena);
    let lease = registration.device_attached();
    let pools = mempools(arena, lease.device());
    let view = PacketPool::new(arena, PoolKind::PacketReceive, 2).unwrap();
    let port = MockPort {
        lease: Some(lease),
        ..MockPort::open()
    };
    let wire = Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap();
    let Ok(mut burst) = Burst::over(
        port,
        wire,
        [&pools[0], &pools[1], &pools[2]],
        &registration,
        mock::watch(),
        8,
        &mut EngineBudget::unlimited(),
    ) else {
        panic!("matching identities build");
    };
    let retained = source(arena, 0x5A);
    let range = retained.source(64..1064).unwrap();
    let header = [0x22; 32];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Retained(range), Payload::EMPTY],
    };
    assert_eq!(burst.send(&[datagram]), Ok(1));
    let head = burst.port_mut().held[0];
    // SAFETY: the port holds the chain, and the burst logic wrote both segments.
    let (addr, iova) = unsafe {
        let segment = &*(*head).next;
        let off = usize::from(segment.__bindgen_anon_1.__bindgen_anon_1.data_off);
        (segment.buf_addr.addr() + off, segment.buf_iova + off as u64)
    };
    assert_eq!(
        Some(iova),
        registration.iova(addr, 1000),
        "the registration's IOVA"
    );
    burst.port_mut().complete();
    let (frame, meta) = mock::inbound(&LOCAL, &PEER, b"over its own lease");
    let arrived = arrive_on(
        pools[2].ops(),
        view.layout(),
        &frame,
        meta,
        sys::RTE_PKTMBUF_HEADROOM as u16,
    );
    burst.port_mut().arriving.push(arrived);
    let mut leases: [Option<PacketLease<'_>>; 1] = [None];
    let mut meta_out = [Received::default(); 1];
    assert_eq!(burst.receive(&view, &mut leases, &mut meta_out), Ok(1));
    assert_eq!(leases[0].as_ref().unwrap().bytes(), b"over its own lease");
}

/// A failed recheck leaves the registration unverified, so its IOVA lookups refuse; a burst whose link is still up then refuses every send with `ESTALE` and builds nothing, since its cached translations are no longer the registration's. The same send over the verified registration goes out first.
#[test]
fn a_registration_unverified_under_a_live_burst_ends_retained_sends() {
    let (env, arena) = (Environment::detached(), mock::arena());
    let (mut registration, stale) = super::registration_tests::ready_until_stale(&env, arena);
    let lease = registration.device_attached();
    let pools = mempools(arena, lease.device());
    let port = MockPort {
        lease: Some(lease),
        ..MockPort::open()
    };
    let wire = Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap();
    let Ok(mut burst) = Burst::over(
        port,
        wire,
        [&pools[0], &pools[1], &pools[2]],
        &registration,
        mock::watch(),
        8,
        &mut EngineBudget::unlimited(),
    ) else {
        panic!("matching identities build");
    };
    let retained = source(arena, 0x5A);
    let header = [0x22; 32];
    fn datagram<'d>(retained: &'d Buffer<'static>, header: &'d [u8]) -> Outgoing<'d, 'static> {
        Outgoing {
            peer: PeerId(0),
            header,
            payload: [
                Payload::Retained(retained.source(64..1064).unwrap()),
                Payload::EMPTY,
            ],
        }
    }
    assert_eq!(
        burst.send(&[datagram(&retained, &header)]),
        Ok(1),
        "the verified registration sends"
    );
    burst.port_mut().complete();
    stale();
    // Premises: the public recheck fails and leaves the registration unverified, so its lookup refuses the source.
    assert!(registration.recheck().is_err());
    assert!(!registration.is_ready());
    let addr = retained.bytes().as_ptr().addr() + 64;
    assert_eq!(registration.iova(addr, 1000), None);
    assert_eq!(burst.link(), Link::Up);
    let before = (custody(arena), burst.port().calls);
    assert_eq!(
        burst.send(&[datagram(&retained, &header)]),
        Err(DatagramError::Failed {
            code: Some(libc::ESTALE)
        }),
        "no descriptor goes out under an unverified registration"
    );
    assert!(burst.port_mut().held.is_empty());
    assert_eq!(
        (custody(arena), burst.port().calls),
        before,
        "the refusal takes no buffer and drives no device"
    );
}

/// A failed recheck leaves the registration unverified; a burst whose link is still up then refuses every receive with `ESTALE` before it asks the device for frames, so the driver refills its ring with no arena buffer and no frame the device wrote is leased. A receive over the verified registration leases its frame first.
#[test]
fn a_registration_unverified_under_a_live_burst_ends_receives() {
    let (env, arena) = (Environment::detached(), mock::arena());
    let (mut registration, stale) = super::registration_tests::ready_until_stale(&env, arena);
    let lease = registration.device_attached();
    let pools = mempools(arena, lease.device());
    let view = PacketPool::new(arena, PoolKind::PacketReceive, 2).unwrap();
    let port = MockPort {
        lease: Some(lease),
        ..MockPort::open()
    };
    let wire = Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap();
    let Ok(mut burst) = Burst::over(
        port,
        wire,
        [&pools[0], &pools[1], &pools[2]],
        &registration,
        mock::watch(),
        8,
        &mut EngineBudget::unlimited(),
    ) else {
        panic!("matching identities build");
    };
    let arrive = |burst: &mut Burst<'_, MockPort>, payload: &[u8]| {
        let (frame, meta) = mock::inbound(&LOCAL, &PEER, payload);
        let arrived = arrive_on(
            pools[2].ops(),
            view.layout(),
            &frame,
            meta,
            sys::RTE_PKTMBUF_HEADROOM as u16,
        );
        burst.port_mut().arriving.push(arrived);
    };
    let mut leases: [Option<PacketLease<'_>>; 1] = [None];
    let mut meta_out = [Received::default(); 1];
    arrive(&mut burst, b"verified");
    assert_eq!(
        burst.receive(&view, &mut leases, &mut meta_out),
        Ok(1),
        "the verified registration receives"
    );
    leases[0] = None;
    stale();
    // Premises: the public recheck fails and leaves the registration unverified while the link stays up.
    assert!(registration.recheck().is_err());
    assert!(!registration.is_ready());
    assert_eq!(burst.link(), Link::Up);
    // The device wrote a frame into a buffer it took from the receive pool.
    arrive(&mut burst, b"unverified");
    let before = burst.port().calls;
    assert_eq!(
        burst.receive(&view, &mut leases, &mut meta_out),
        Err(DatagramError::Failed {
            code: Some(libc::ESTALE)
        }),
        "no frame is leased under an unverified registration"
    );
    assert!(leases[0].is_none());
    assert_eq!(
        burst.port().calls,
        before,
        "the refusal asks the device for no frame"
    );
}

/// An accepted datagram is one header mbuf holding the wire headers, the frame header and its inline piece, chained to one payload descriptor per retained piece at its source's address and IOVA, each holding one device reference; once the device frees it, every header buffer, reference and descriptor is back.
#[test]
fn accepted_chains_carry_header_inline_and_retained_segments() {
    let mut f = fixture();
    let first = source(f.arena, 0xA1);
    let second = source(f.arena, 0xB2);
    let header = [0x11; 192];
    {
        let datagram = Outgoing {
            peer: PeerId(0),
            header: &header,
            payload: [
                Payload::Retained(first.source(100..8000).unwrap()),
                Payload::Retained(second.source(0..192).unwrap()),
            ],
        };
        let control = Outgoing {
            peer: PeerId(0),
            header: &header,
            payload: [Payload::Inline(b"body"), Payload::EMPTY],
        };
        assert_eq!(f.burst.send(&[datagram, control]), Ok(2));
    }
    drop((first, second));
    assert_eq!(
        f.arena.report(PoolKind::ReadResponse).nic_held,
        2,
        "one reference on each source"
    );
    let held_chains = f.burst.port_mut().held.clone();
    let head = held_chains[0];
    // SAFETY: the port holds the chain.
    let (one, two) = unsafe { ((*head).next, (*(*head).next).next) };
    let wire = bytes(head);
    assert_eq!(wire.len(), FRAME_OVERHEAD + 192);
    assert_eq!(&wire[FRAME_OVERHEAD..], &header);
    let mut headers = [0; FRAME_OVERHEAD];
    Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited())
        .unwrap()
        .encode(&mut headers, &PEER, LOCAL.port, PEER.port, 192 + 7900 + 192);
    assert_eq!(
        wire[..FRAME_OVERHEAD],
        headers,
        "the wire headers lead the header buffer, with a UDP length covering every segment"
    );
    assert_eq!(bytes(one), vec![0xA1; 7900]);
    assert_eq!(bytes(two), vec![0xB2; 192]);
    // SAFETY: as above.
    unsafe {
        let rearm = (*head).__bindgen_anon_1.__bindgen_anon_1;
        assert_eq!(
            (rearm.data_off, rearm.refcnt, rearm.nb_segs, rearm.port),
            (sys::RTE_PKTMBUF_HEADROOM as u16, 1, 3, 0)
        );
        let rearm = (*one).__bindgen_anon_1.__bindgen_anon_1;
        assert_eq!(
            (rearm.data_off, rearm.refcnt, rearm.nb_segs, rearm.port),
            (0, 1, 1, 0)
        );
        assert_eq!(
            (*head).__bindgen_anon_2.__bindgen_anon_1.pkt_len as usize,
            FRAME_OVERHEAD + 192 + 7900 + 192
        );
        assert_eq!((*head).__bindgen_anon_3.tx_offload, 14 | 20 << 7 | 8 << 16);
        for (segment, len) in [(one, 7900), (two, 192)] {
            assert_eq!(
                Some((*segment).buf_iova),
                iova((*segment).buf_addr.addr(), len),
                "the segment's IOVA is the registration's"
            );
        }
        assert!((*two).next.is_null());
    }
    let inline = bytes(held_chains[1]);
    assert_eq!(&inline[FRAME_OVERHEAD + 192..], b"body");
    assert_eq!(
        held(f.arena, PoolKind::PacketHeader),
        2,
        "two header buffers wait for the device"
    );
    f.burst.port_mut().complete();
    assert_eq!(held(f.arena, PoolKind::PacketHeader), 0);
    assert_eq!(
        f.arena.report(PoolKind::ReadResponse).free,
        COUNT,
        "every source reference returned"
    );
    assert_eq!(descriptors(&f), 8);
    let report = f.burst.report();
    assert_eq!((report.sent, report.ring_full), (2, 0));
}

/// A partial or zero accept leaves every datagram the device did not take holding no header buffer and no reference, counted as ring pressure; a prepare that passes a shorter prefix counts a refusal, and one that passes nothing fails the call with its error number.
#[test]
fn unaccepted_datagrams_hold_nothing_after_send() {
    let mut f = fixture();
    let header = [0x22; 192];
    for (prepare, accept, outcome) in [
        (usize::MAX, 1, Ok(1)),
        (usize::MAX, 0, Ok(0)),
        (2, usize::MAX, Ok(2)),
        (
            0,
            usize::MAX,
            Err(DatagramError::Failed {
                code: Some(libc::ENOTSUP),
            }),
        ),
    ] {
        let retained = source(f.arena, 7);
        {
            let datagram = Outgoing {
                peer: PeerId(0),
                header: &header,
                payload: [
                    Payload::Retained(retained.source(0..4000).unwrap()),
                    Payload::EMPTY,
                ],
            };
            *f.burst.port_mut() = MockPort {
                prepare,
                accept,
                prepare_error: libc::ENOTSUP,
                ..MockPort::open()
            };
            assert_eq!(f.burst.send(&[datagram; 3]), outcome);
        }
        drop(retained);
        let sent = outcome.unwrap_or(0) as u32;
        assert_eq!(
            held(f.arena, PoolKind::PacketHeader),
            sent,
            "only accepted datagrams hold headers"
        );
        assert_eq!(
            f.arena.report(PoolKind::ReadResponse).nic_held,
            u32::from(sent > 0),
            "only accepted datagrams hold the source"
        );
        f.burst.port_mut().complete();
        assert_eq!(held(f.arena, PoolKind::PacketHeader), 0);
        assert_eq!(f.arena.report(PoolKind::ReadResponse).free, COUNT);
        assert_eq!(descriptors(&f), 8);
    }
    let report = f.burst.report();
    assert_eq!((report.ring_full, report.prepare_refused), (2 + 3, 2));
    assert_eq!(f.arena.report(PoolKind::ReadResponse).mismatched, 0);
}

/// After a native post that failed past its ownership point, the chain the device may hold is quarantined: its buffers and references stay held until the device returns it once, and the transport refuses later sends.
#[test]
fn an_uncertain_post_quarantines_its_chain_and_poisons_the_transport() {
    let mut f = fixture();
    let retained = source(f.arena, 9);
    let header = [0x33; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Retained(retained.source(0..100).unwrap()),
            Payload::EMPTY,
        ],
    };
    *f.burst.port_mut() = MockPort {
        accept: 1,
        uncertain: true,
        ..MockPort::open()
    };
    assert_eq!(f.burst.send(&[datagram; 3]), Ok(1));
    assert!(f.burst.poisoned());
    let report = f.burst.report();
    assert_eq!((report.quarantined, report.ring_full), (1, 1));
    assert_eq!(
        held(f.arena, PoolKind::PacketHeader),
        2,
        "the accepted chain and the uncertain one stay held"
    );
    assert_eq!(
        f.burst.send(&[datagram]),
        Err(DatagramError::Failed {
            code: Some(libc::EIO)
        })
    );
    f.burst.port_mut().complete();
    assert_eq!(
        held(f.arena, PoolKind::PacketHeader),
        0,
        "the device returned both chains once"
    );
    assert_eq!(f.arena.report(PoolKind::PacketHeader).mismatched, 0);
}

/// A datagram no send can carry fails the call when it leads, and ends the accepted prefix before itself when it follows others: too many segments, an oversized header, an unknown peer. Exhausted header buffers yield an empty prefix the caller resends. Nothing is held after any of them.
#[test]
fn unsendable_and_exhausted_datagrams_hold_nothing() {
    let mut f = fixture();
    let retained = source(f.arena, 3);
    let header = [0x44; 192];
    let single = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Retained(retained.source(0..10).unwrap()),
            Payload::EMPTY,
        ],
    };
    let two = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Retained(retained.source(0..10).unwrap()),
            Payload::Retained(retained.source(10..20).unwrap()),
        ],
    };
    let invalid = Err(DatagramError::Failed {
        code: Some(libc::EINVAL),
    });
    f.burst.port_mut().segments = 2;
    assert_eq!(f.burst.send(&[two]), invalid);
    assert_eq!(
        f.burst.send(&[single, two]),
        Ok(1),
        "a cap break mid-batch ends the prefix"
    );
    f.burst.port_mut().complete();
    *f.burst.port_mut() = MockPort::open();
    let wide = [0u8; 4096];
    let oversized = Outgoing {
        peer: PeerId(0),
        header: &wide,
        payload: [Payload::EMPTY; 2],
    };
    assert_eq!(f.burst.send(&[oversized]), invalid);
    let unknown = Outgoing {
        peer: PeerId(5),
        header: &header,
        payload: [Payload::EMPTY; 2],
    };
    assert_eq!(f.burst.send(&[unknown]), invalid);
    let taken: Vec<_> = (0..COUNT)
        .map(|_| f.arena.pools().acquire(PoolKind::PacketHeader).unwrap())
        .collect();
    assert_eq!(
        f.burst.send(&[single]),
        Ok(0),
        "no header buffer is pressure"
    );
    drop(taken);
    let report = f.burst.report();
    assert_eq!((report.unsendable, report.exhausted), (4, 1));
    drop(retained);
    assert_eq!(held(f.arena, PoolKind::PacketHeader), 0);
    assert_eq!(f.arena.report(PoolKind::ReadResponse).free, COUNT);
    assert_eq!(descriptors(&f), 8);
    assert!(f.burst.port_mut().held.is_empty());
}

/// A payload segment whose bytes have no registered IOVA, as for a range crossing a backing page, is unsendable: its datagram fails the call, and a back piece already built releases its descriptor and reference.
#[test]
fn a_segment_without_a_registered_iova_is_not_built() {
    let arena = mock::arena();
    // The first read-response buffer, which the first acquire hands out.
    let refused = arena.pools().pool(PoolKind::ReadResponse).span().0;
    let mut f = fixture_on(
        arena,
        Box::new(move |addr, len| (addr != refused).then(|| iova(addr, len)).flatten()),
    );
    let first = source(f.arena, 5);
    let second = source(f.arena, 6);
    assert_eq!(first.bytes().as_ptr().addr(), refused);
    let header = [0x45; 192];
    {
        let datagram = Outgoing {
            peer: PeerId(0),
            header: &header,
            payload: [
                Payload::Retained(first.source(0..100).unwrap()),
                Payload::Retained(second.source(0..100).unwrap()),
            ],
        };
        assert_eq!(
            f.burst.send(&[datagram]),
            Err(DatagramError::Failed {
                code: Some(libc::EINVAL)
            })
        );
    }
    drop((first, second));
    assert_eq!(
        f.arena.report(PoolKind::ReadResponse).free,
        COUNT,
        "the back piece's reference returned"
    );
    assert_eq!(descriptors(&f), 8, "its descriptor is back");
    assert_eq!(held(f.arena, PoolKind::PacketHeader), 0);
}

/// The header segment precedes retained segments, so inline bytes after a retained piece would reorder the payload. Such a datagram ends the sendable prefix; the send returns EINVAL if that datagram is first.
#[test]
fn pieces_reach_the_wire_in_order_or_the_datagram_is_unsendable() {
    let mut f = fixture();
    let retained = source(f.arena, 0xC3);
    let header = [0x47; 192];
    let leading = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Inline(b"head"),
            Payload::Retained(retained.source(0..100).unwrap()),
        ],
    };
    let trailing = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Retained(retained.source(0..100).unwrap()),
            Payload::Inline(b"tail"),
        ],
    };
    let invalid = Err(DatagramError::Failed {
        code: Some(libc::EINVAL),
    });
    assert_eq!(f.burst.send(&[trailing]), invalid);
    assert_eq!(f.burst.send(&[leading, trailing]), Ok(1));
    let chain = f.burst.port_mut().held.clone();
    assert_eq!(chain.len(), 1, "only the leading-inline datagram went out");
    let head = bytes(chain[0]);
    assert_eq!(&head[FRAME_OVERHEAD + 192..], b"head");
    // SAFETY: the port holds the chain.
    let segment = unsafe { (*chain[0]).next };
    assert_eq!(bytes(segment), vec![0xC3; 100]);
    f.burst.port_mut().complete();
    let report = f.burst.report();
    assert_eq!((report.sent, report.unsendable), (1, 2));
    drop(retained);
    assert_eq!(held(f.arena, PoolKind::PacketHeader), 0);
    assert_eq!(f.arena.report(PoolKind::ReadResponse).free, COUNT);
    assert_eq!(descriptors(&f), 8);
}

/// The registration translates no empty range, so a datagram with an empty retained piece, leading or after a nonempty one, fails the send with `EINVAL` and holds no header buffer, descriptor or device reference; a datagram of the same source's nonempty bytes then goes out.
#[test]
fn an_empty_retained_piece_is_unsendable() {
    let mut f = fixture();
    let retained = source(f.arena, 0xC5);
    let header = [0x49; 192];
    for payload in [
        [
            Payload::Retained(retained.source(64..64).unwrap()),
            Payload::EMPTY,
        ],
        [
            Payload::Retained(retained.source(0..100).unwrap()),
            Payload::Retained(retained.source(100..100).unwrap()),
        ],
    ] {
        let datagram = Outgoing {
            peer: PeerId(0),
            header: &header,
            payload,
        };
        assert_eq!(
            f.burst.send(&[datagram]),
            Err(DatagramError::Failed {
                code: Some(libc::EINVAL)
            })
        );
        assert!(f.burst.port_mut().held.is_empty());
        assert_eq!(descriptors(&f), 8);
        assert_eq!(held(f.arena, PoolKind::PacketHeader), 0);
    }
    assert_eq!(f.burst.report().unsendable, 2);
    let whole = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Retained(retained.source(0..100).unwrap()),
            Payload::EMPTY,
        ],
    };
    assert_eq!(f.burst.send(&[whole]), Ok(1));
    f.burst.port_mut().complete();
    drop(retained);
    let pool = f.arena.report(PoolKind::ReadResponse);
    assert_eq!((pool.free, pool.nic_held, pool.mismatched), (COUNT, 0, 0));
    assert_eq!(descriptors(&f), 8);
}

/// A retained source must belong to the payload pool's arena because the IOVA table and the token's device return identify buffers by index in that arena.
#[test]
fn a_source_of_another_arena_is_not_built() {
    let arena = mock::arena();
    let (base, extent) = (
        arena.backing().base().as_ptr().addr(),
        arena.backing().extent(),
    );
    let mut f = fixture_on(
        arena,
        Box::new(move |addr, len| {
            (addr >= base && addr + len <= base + extent)
                .then(|| iova(addr, len))
                .flatten()
        }),
    );
    let other = mock::arena();
    let foreign = source(other, 0xD4);
    let header = [0x48; 192];
    {
        let datagram = Outgoing {
            peer: PeerId(0),
            header: &header,
            payload: [
                Payload::Retained(foreign.source(0..100).unwrap()),
                Payload::EMPTY,
            ],
        };
        assert_eq!(
            f.burst.send(&[datagram]),
            Err(DatagramError::Failed {
                code: Some(libc::EINVAL)
            })
        );
    }
    drop(foreign);
    let theirs = other.report(PoolKind::ReadResponse);
    assert_eq!(
        (theirs.free, theirs.nic_held, theirs.mismatched),
        (COUNT, 0, 0),
        "the foreign source's reference count is balanced"
    );
    assert_eq!(f.arena.report(PoolKind::ReadResponse).mismatched, 0);
    assert_eq!(descriptors(&f), 8);
    assert_eq!(held(f.arena, PoolKind::PacketHeader), 0);
    assert!(f.burst.port_mut().held.is_empty());
}

/// In a debug build, a payload descriptor whose IOVA differs from the registration's translation when rechecked stops the send.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "a segment's IOVA is the registration's")]
fn a_debug_build_rechecks_each_segment_iova() {
    let calls = Box::leak(Box::new(std::cell::Cell::new(0u32)));
    let calls: &'static std::cell::Cell<u32> = calls;
    let mut f = fixture_with(Box::new(move |addr, len| {
        calls.set(calls.get() + 1);
        iova(addr, len).map(|at| at + u64::from(calls.get()))
    }));
    let retained = source(f.arena, 8);
    let header = [0x46; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Retained(retained.source(0..100).unwrap()),
            Payload::EMPTY,
        ],
    };
    let _ = f.burst.send(&[datagram]);
}

/// Cleanup's numeric result changes no custody, whether it reports a count, zero or unsupported; returns the device makes during cleanup release exactly their own chains, including the final transmit with no later send.
#[test]
fn cleanup_counts_are_inert_and_its_returns_release_their_chains() {
    let mut f = fixture();
    let header = [0x55; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"x"), Payload::EMPTY],
    };
    assert_eq!(f.burst.send(&[datagram; 3]), Ok(3));
    for report in [5, 0, -libc::ENOTSUP] {
        f.burst.port_mut().cleanup = (report, 0);
        f.burst.reclaim();
        assert_eq!(
            held(f.arena, PoolKind::PacketHeader),
            3,
            "a report of {report} changed nothing"
        );
    }
    f.burst.port_mut().cleanup = (0, 2);
    f.burst.reclaim();
    assert_eq!(
        held(f.arena, PoolKind::PacketHeader),
        1,
        "two returns released two chains"
    );
    f.burst.port_mut().cleanup = (-libc::ENOTSUP, 1);
    f.burst.reclaim();
    assert_eq!(
        held(f.arena, PoolKind::PacketHeader),
        0,
        "the final transmit returned without a later send"
    );
}

/// On an idle device, `reclaim` only services the device. While the device holds any sent chain, `reclaim` requests cleanup every turn, including after a partial return, and stops once every chain is back.
#[test]
fn reclaim_asks_for_cleanup_only_while_the_device_holds_a_transmit() {
    let mut f = fixture();
    let header = [0x56; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"x"), Payload::EMPTY],
    };
    for _ in 0..3 {
        f.burst.reclaim();
    }
    assert_eq!(
        f.burst.port_mut().cleanups,
        0,
        "an idle device sees only service"
    );
    assert_eq!(f.burst.send(&[datagram; 2]), Ok(2));
    f.burst.reclaim();
    f.burst.reclaim();
    assert_eq!(
        f.burst.port_mut().cleanups,
        2,
        "every turn asks while the device holds both"
    );
    f.burst.port_mut().cleanup = (1, 1);
    f.burst.reclaim();
    assert_eq!(held(f.arena, PoolKind::PacketHeader), 1);
    f.burst.reclaim();
    assert_eq!(
        held(f.arena, PoolKind::PacketHeader),
        0,
        "the final transmit returned on the turns after its send"
    );
    f.burst.reclaim();
    assert_eq!(
        f.burst.port_mut().cleanups,
        4,
        "once every chain is back, turns stop asking"
    );
}

/// Takes a receive buffer through the ops as the device's refill does and writes `frame` into it with the descriptor fields `meta`, at `headroom`.
fn arrive_at(
    f: &Fixture,
    frame: &[u8],
    meta: RxMeta,
    next: *mut sys::rte_mbuf,
    headroom: u16,
) -> *mut sys::rte_mbuf {
    let mbuf = arrive_on(
        f.receive_ops.state,
        f.receive.layout(),
        frame,
        meta,
        headroom,
    );
    // SAFETY: the buffer is posted and its descriptor this test's.
    unsafe { (*mbuf).next = next };
    mbuf
}

fn arrive(f: &Fixture, frame: &[u8], meta: RxMeta, next: *mut sys::rte_mbuf) -> *mut sys::rte_mbuf {
    arrive_at(f, frame, meta, next, sys::RTE_PKTMBUF_HEADROOM as u16)
}

/// A valid frame becomes a lease over exactly its UDP payload; a BAD checksum field, a frame spanning two buffers, a single segment with a chained next, a frame off the headroom and a buffer the pool never posted are dropped with their own reasons, and every other buffer this pool posted is back on its free stack by the end of the call, while the foreign buffer stays posted. A receive through another view fails with nothing taken.
#[test]
fn receive_leases_validated_payloads_and_returns_every_other_buffer() {
    let mut f = fixture();
    let (frame, meta) = mock::inbound(&LOCAL, &PEER, b"a v1 datagram");
    let good = arrive(&f, &frame, meta, std::ptr::null_mut());
    let bad_flags = u64::from(sys::RTE_MBUF_F_RX_L4_CKSUM_BAD | sys::RTE_MBUF_F_RX_IP_CKSUM_GOOD);
    let bad = arrive(
        &f,
        &frame,
        RxMeta {
            ol_flags: bad_flags,
            ..meta
        },
        std::ptr::null_mut(),
    );
    let tail = arrive(&f, &frame, meta, std::ptr::null_mut());
    let chained = arrive(&f, &frame, RxMeta { nb_segs: 2, ..meta }, tail);
    let tail = arrive(&f, &frame, meta, std::ptr::null_mut());
    let linked = arrive(&f, &frame, meta, tail);
    let shifted = arrive_at(&f, &frame, meta, std::ptr::null_mut(), 0);
    let foreign = f.arena.pools().post(PoolKind::PacketReceive).unwrap();
    let foreign_index = foreign.into_index();
    let foreign_mbuf = f.receive_ops.state.object(foreign_index).cast();
    f.burst.port_mut().arriving = vec![good, bad, chained, linked, shifted, foreign_mbuf];
    let mut leases: [Option<PacketLease<'_>>; 8] = std::array::from_fn(|_| None);
    let mut meta_out = [Received::default(); 8];
    assert_eq!(
        f.burst.receive(f.receive, &mut leases, &mut meta_out),
        Ok(1)
    );
    assert_eq!(leases[0].as_ref().unwrap().bytes(), b"a v1 datagram");
    assert_eq!(meta_out[0].peer, Some(PeerId(0)));
    let report = f.arena.report(PoolKind::PacketReceive);
    assert_eq!(
        (report.posted, report.application),
        (1, 1),
        "only the lease and the foreign posting hold buffers"
    );
    drop(leases);
    // SAFETY: the foreign posting gave up its handle by index and no device saw it.
    unsafe {
        f.arena
            .pools()
            .pool(PoolKind::PacketReceive)
            .posting(foreign_index)
            .unwrap()
            .unpost()
    };
    assert_eq!(f.arena.report(PoolKind::PacketReceive).free, COUNT);
    let dropped = f.burst.report().dropped;
    let reason = |r: Refused| dropped[r as usize];
    assert_eq!(
        (
            reason(Refused::L4Checksum),
            reason(Refused::Segments),
            reason(Refused::Headroom),
            reason(Refused::Foreign)
        ),
        (1, 2, 1, 1)
    );
    let other = Box::leak(Box::new(
        PacketPool::new(mock::arena(), PoolKind::PacketReceive, 2).unwrap(),
    ));
    let _ = other;
    let mut none: [Option<PacketLease<'_>>; 1] = [None];
    let mut meta_one = [Received::default(); 1];
    let foreign_view: &'static PacketPool<'static> = other;
    assert_eq!(
        f.burst.receive(foreign_view, &mut none, &mut meta_one),
        Err(DatagramError::Failed {
            code: Some(libc::EINVAL)
        })
    );
}

/// Frames whose bytes fail validation between accepted frames leave the accepted leases in the leading slots, in arrival order, with every refused buffer back on the free stack.
#[test]
fn byte_refusals_between_accepted_frames_leave_the_leases_contiguous() {
    let mut f = fixture();
    let (first, meta) = mock::inbound(&LOCAL, &PEER, b"first");
    let (second, _) = mock::inbound(&LOCAL, &PEER, b"second");
    let (third, _) = mock::inbound(&LOCAL, &PEER, b"third");
    let mut elsewhere = first.clone();
    elsewhere[37] ^= 1;
    let mut unknown = first.clone();
    unknown[29] ^= 1;
    let arriving = [
        arrive(&f, &elsewhere, meta, std::ptr::null_mut()),
        arrive(&f, &first, meta, std::ptr::null_mut()),
        arrive(&f, &unknown, meta, std::ptr::null_mut()),
        arrive(&f, &elsewhere, meta, std::ptr::null_mut()),
        arrive(
            &f,
            &second,
            RxMeta {
                data_len: second.len() as u16,
                pkt_len: second.len() as u32,
                ..meta
            },
            std::ptr::null_mut(),
        ),
        arrive(
            &f,
            &third,
            RxMeta {
                data_len: third.len() as u16,
                pkt_len: third.len() as u32,
                ..meta
            },
            std::ptr::null_mut(),
        ),
    ];
    f.burst.port_mut().arriving = arriving.to_vec();
    let mut leases: [Option<PacketLease<'_>>; 8] = std::array::from_fn(|_| None);
    let mut meta_out = [Received::default(); 8];
    assert_eq!(
        f.burst.receive(f.receive, &mut leases, &mut meta_out),
        Ok(3)
    );
    let payloads: Vec<&[u8]> = leases[..3]
        .iter()
        .map(|lease| lease.as_ref().unwrap().bytes())
        .collect();
    assert_eq!(payloads, [b"first".as_slice(), b"second", b"third"]);
    assert!(leases[3..].iter().all(Option::is_none));
    assert!(meta_out[..3].iter().all(|m| m.peer == Some(PeerId(0))));
    let dropped = f.burst.report().dropped;
    assert_eq!(dropped[Refused::Destination as usize], 2);
    assert_eq!(dropped[Refused::Source as usize], 1);
    assert_eq!(
        f.arena.report(PoolKind::PacketReceive).application,
        3,
        "only the three leases hold buffers"
    );
    drop(leases);
    assert_eq!(f.arena.report(PoolKind::PacketReceive).free, COUNT);
}

/// Six received frames produce one read hint per cache line of each frame's wire and frame headers, plus one for the head's last byte, during the receive that validates them.
#[test]
fn every_received_frame_head_is_hinted_line_by_line() {
    let mut f = fixture();
    let (frame, meta) = mock::inbound(&LOCAL, &PEER, b"hinted");
    let arrived: Vec<*mut sys::rte_mbuf> = (0..6)
        .map(|_| arrive(&f, &frame, meta, std::ptr::null_mut()))
        .collect();
    f.burst.port_mut().arriving = arrived;
    let mut leases: [Option<PacketLease<'_>>; 8] = std::array::from_fn(|_| None);
    let mut meta_out = [Received::default(); 8];
    let before = crate::storage::prefetch::READ_HINTS.with(Cell::get);
    assert_eq!(
        f.burst.receive(f.receive, &mut leases, &mut meta_out),
        Ok(6)
    );
    let head = crate::net::FRAME_OVERHEAD + crate::net::HEADER_LEN;
    let per_frame = (0..head).step_by(crate::storage::prefetch::LINE).count() + 1;
    assert_eq!(
        crate::storage::prefetch::READ_HINTS.with(Cell::get) - before,
        6 * per_frame
    );
}

/// Send with a partial accept, an exhausted send, cleanup with a device return, receive, a dropped frame and lease drop leave the per-thread allocation count unchanged.
#[test]
fn burst_paths_allocate_nothing() {
    let mut f = fixture();
    let retained = source(f.arena, 1);
    let range = retained.source(0..1000).unwrap();
    let header = [0x66; 192];
    let batch = [Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Retained(range), Payload::EMPTY],
    }; 2];
    let (frame, meta) = mock::inbound(&LOCAL, &PEER, b"payload");
    let bad = RxMeta {
        ol_flags: 0,
        ..meta
    };
    *f.burst.port_mut() = MockPort {
        accept: 1,
        ..MockPort::open()
    };
    f.burst.port_mut().held.reserve(8);
    f.burst.port_mut().arriving.reserve(8);
    let mut leases: [Option<PacketLease<'_>>; 2] = std::array::from_fn(|_| None);
    let mut meta_out = [Received::default(); 2];
    let mut taken = Vec::with_capacity(COUNT as usize);
    let allocations = crate::instrument::allocations();
    for _ in 0..8 {
        assert_eq!(f.burst.send(&batch), Ok(1));
        f.burst.port_mut().cleanup = (1, 1);
        f.burst.reclaim();
        while let Ok(buffer) = f.arena.pools().acquire(PoolKind::PacketHeader) {
            taken.push(buffer);
        }
        assert_eq!(f.burst.send(&batch), Ok(0));
        taken.clear();
        let arrived = arrive(&f, &frame, meta, std::ptr::null_mut());
        let dropped = arrive(&f, &frame, bad, std::ptr::null_mut());
        f.burst.port_mut().arriving.extend([arrived, dropped]);
        assert_eq!(
            f.burst.receive(f.receive, &mut leases, &mut meta_out),
            Ok(1)
        );
        leases[0] = None;
    }
    assert_eq!(crate::instrument::allocations(), allocations);
}

/// An empty descriptor stack is pressure: the datagram yields an empty prefix with nothing held, and goes out once descriptors return.
#[test]
fn an_empty_descriptor_stack_is_pressure() {
    let mut f = fixture();
    let retained = source(f.arena, 2);
    let header = [0x47; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Retained(retained.source(0..100).unwrap()),
            Payload::EMPTY,
        ],
    };
    let mut slots = vec![std::mem::MaybeUninit::uninit(); 8];
    assert!(f.payload.state.take(&mut slots));
    assert_eq!(f.burst.send(&[datagram]), Ok(0));
    assert_eq!(f.burst.report().exhausted, 1);
    assert_eq!(
        (
            held(f.arena, PoolKind::PacketHeader),
            f.arena.report(PoolKind::ReadResponse).nic_held
        ),
        (0, 0)
    );
    for slot in slots {
        // SAFETY: taken above, never seen by a device.
        unsafe { f.payload.state.give_back(slot.assume_init()) };
    }
    assert_eq!(f.burst.send(&[datagram]), Ok(1));
    f.burst.port_mut().complete();
    assert_eq!(descriptors(&f), 8);
}

/// Pressure after a built prefix ends the prefix: with one header buffer free, two datagrams send one.
#[test]
fn pressure_after_a_built_prefix_ends_it() {
    let mut f = fixture();
    let header = [0x48; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"y"), Payload::EMPTY],
    };
    let taken: Vec<_> = (0..COUNT - 1)
        .map(|_| f.arena.pools().acquire(PoolKind::PacketHeader).unwrap())
        .collect();
    assert_eq!(f.burst.send(&[datagram; 2]), Ok(1));
    assert_eq!(f.burst.report().exhausted, 1);
    drop(taken);
    f.burst.port_mut().complete();
    assert_eq!(held(f.arena, PoolKind::PacketHeader), 0);
}

/// An uncertain post with nothing accepted quarantines the first chain, holding its source reference until the device returns it, and releases the rest; with a prepare refusal as well, the refused chain is released too.
#[test]
fn an_uncertain_post_with_nothing_accepted_holds_only_its_chain() {
    for (prepare, ring_full, refused) in [(usize::MAX, 2, 0), (2, 1, 1)] {
        let mut f = fixture();
        let retained = source(f.arena, 3);
        let header = [0x49; 192];
        {
            let datagram = Outgoing {
                peer: PeerId(0),
                header: &header,
                payload: [
                    Payload::Retained(retained.source(0..64).unwrap()),
                    Payload::EMPTY,
                ],
            };
            *f.burst.port_mut() = MockPort {
                prepare,
                accept: 0,
                uncertain: true,
                ..MockPort::open()
            };
            assert_eq!(f.burst.send(&[datagram; 3]), Ok(0));
        }
        drop(retained);
        let report = f.burst.report();
        assert!(f.burst.poisoned());
        assert_eq!(
            (report.quarantined, report.ring_full, report.prepare_refused),
            (1, ring_full, refused)
        );
        assert_eq!(held(f.arena, PoolKind::PacketHeader), 1);
        assert_eq!(
            f.arena.report(PoolKind::ReadResponse).nic_held,
            1,
            "the quarantined chain keeps its source reference"
        );
        f.burst.port_mut().complete();
        assert_eq!(f.arena.report(PoolKind::ReadResponse).free, COUNT);
        assert_eq!(held(f.arena, PoolKind::PacketHeader), 0);
    }
}

/// A foreign head's chained segments this pool posted return to the free stack, and a frame longer than the data room is refused for its length with the buffer returned.
#[test]
fn a_foreign_head_returns_its_chain_and_an_overlong_frame_is_refused() {
    let mut f = fixture();
    let (frame, meta) = mock::inbound(&LOCAL, &PEER, b"z");
    let tail = arrive(&f, &frame, meta, std::ptr::null_mut());
    let foreign = f.arena.pools().post(PoolKind::PacketReceive).unwrap();
    let index = foreign.into_index();
    let head: *mut sys::rte_mbuf = f.receive_ops.state.object(index).cast();
    // SAFETY: the fixture's mbuf, which this test models the device writing.
    unsafe { (*head).next = tail };
    let room = f.receive.layout().data_room as u16;
    let overlong = arrive(
        &f,
        &frame,
        RxMeta {
            data_len: room + 1,
            pkt_len: u32::from(room) + 1,
            ..meta
        },
        std::ptr::null_mut(),
    );
    f.burst.port_mut().arriving = vec![head, overlong];
    let mut leases: [Option<PacketLease<'_>>; 2] = std::array::from_fn(|_| None);
    let mut meta_out = [Received::default(); 2];
    assert_eq!(
        f.burst.receive(f.receive, &mut leases, &mut meta_out),
        Ok(0)
    );
    let dropped = f.burst.report().dropped;
    assert_eq!(
        (
            dropped[Refused::Foreign as usize],
            dropped[Refused::Length as usize]
        ),
        (1, 1)
    );
    assert_eq!(
        f.arena.report(PoolKind::PacketReceive).posted,
        1,
        "only the foreign head stays posted"
    );
    // SAFETY: the foreign posting gave up its handle by index and no device saw it.
    unsafe {
        f.arena
            .pools()
            .pool(PoolKind::PacketReceive)
            .posting(index)
            .unwrap()
            .unpost()
    };
    assert_eq!(f.arena.report(PoolKind::PacketReceive).free, COUNT);
}

/// A frame refused on its bytes leaves the caller's slots past the count as they were: after a
/// receive fills two slots, a frame from an unknown source port then a valid frame replace only
/// the first slot, the second keeps its lease, and a lone byte-level refusal changes no slot.
#[test]
fn byte_refusals_leave_slots_past_the_count_as_they_were() {
    let mut f = fixture();
    let (first, meta) = mock::inbound(&LOCAL, &PEER, b"first");
    let (second, second_meta) = mock::inbound(&LOCAL, &PEER, b"second");
    let mut stranger = second.clone();
    stranger[34..36].copy_from_slice(&(PEER.port + 1).to_be_bytes());
    let mut leases: [Option<PacketLease<'_>>; 2] = std::array::from_fn(|_| None);
    let mut meta_out = [Received::default(); 2];
    f.burst.port_mut().arriving = vec![
        arrive(&f, &first, meta, std::ptr::null_mut()),
        arrive(&f, &first, meta, std::ptr::null_mut()),
    ];
    assert_eq!(
        f.burst.receive(f.receive, &mut leases, &mut meta_out),
        Ok(2)
    );
    f.burst.port_mut().arriving = vec![
        arrive(&f, &stranger, second_meta, std::ptr::null_mut()),
        arrive(&f, &second, second_meta, std::ptr::null_mut()),
    ];
    assert_eq!(
        f.burst.receive(f.receive, &mut leases, &mut meta_out),
        Ok(1)
    );
    assert_eq!(leases[0].as_ref().unwrap().bytes(), b"second");
    assert_eq!(
        leases[1].as_ref().unwrap().bytes(),
        b"first",
        "a slot past the count keeps its lease"
    );
    f.burst.port_mut().arriving = vec![arrive(&f, &stranger, second_meta, std::ptr::null_mut())];
    assert_eq!(
        f.burst.receive(f.receive, &mut leases, &mut meta_out),
        Ok(0)
    );
    assert_eq!(
        leases[0].as_ref().unwrap().bytes(),
        b"second",
        "a refusal leaves the slot's lease"
    );
    assert_eq!(f.burst.report().dropped[Refused::Source as usize], 2);
    assert_eq!(f.arena.report(PoolKind::PacketReceive).application, 2);
    drop(leases);
    assert_eq!(f.arena.report(PoolKind::PacketReceive).free, COUNT);
}

/// A datagram leaves from the source port its frame's request slot selects, modulo the host's ports, whatever its peer, all to the peer's base port; the report counts datagrams per source port.
#[test]
fn source_ports_follow_the_request_slot() {
    static SPRAY_PEERS: [Station; 2] = [
        PEER,
        Station {
            ip: [10, 0, 0, 3],
            ..PEER
        },
    ];
    let local = Station { ports: 8, ..LOCAL };
    let mut f = fixture_over(
        mock::arena(),
        Wire::new(local, &SPRAY_PEERS, &mut EngineBudget::unlimited()).unwrap(),
        Box::new(iova),
        Box::new(|| true),
    );
    let mut seen = Vec::new();
    for (peer, slot) in [
        (0u16, 0u16),
        (0, 1),
        (1, 3),
        (0, 7),
        (0, 8),
        (0, 0),
        (1, 11),
    ] {
        let mut header = [0x50; 192];
        header[56..64].copy_from_slice(&(u64::from(slot) << 48 | 5).to_be_bytes());
        let datagram = Outgoing {
            peer: PeerId(peer),
            header: &header,
            payload: [Payload::Inline(b"s"), Payload::EMPTY],
        };
        assert_eq!(f.burst.send(&[datagram]), Ok(1));
        let head = *f.burst.port_mut().held.last().unwrap();
        let frame = bytes(head);
        let port = |at: usize| u16::from_be_bytes([frame[at], frame[at + 1]]);
        assert_eq!(port(36), PEER.port, "the peer's base port");
        seen.push(port(34));
        f.burst.port_mut().complete();
    }
    assert_eq!(seen, [7000, 7001, 7003, 7007, 7000, 7000, 7003]);
    assert_eq!(
        f.burst.report().sources,
        [3, 1, 0, 2, 0, 0, 0, 1],
        "datagrams per source port"
    );
}

/// A packed datagram leaves from the source port its first frame's wire slot selects. Over eight source ports, a
/// header of two 192-byte frames whose wire slots are 3 and 6 leaves from the base port plus 3, and the report counts
/// one datagram for that port alone.
#[test]
fn a_packed_datagram_leaves_from_its_first_frames_source_port() {
    let local = Station { ports: 8, ..LOCAL };
    let mut f = fixture_over(
        mock::arena(),
        Wire::new(local, &PEERS, &mut EngineBudget::unlimited()).unwrap(),
        Box::new(iova),
        Box::new(|| true),
    );
    let packed = [frame_header(0x51, 3), frame_header(0x52, 6)].concat();
    assert_eq!(packed.len(), 384);
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &packed,
        payload: [Payload::EMPTY; 2],
    };
    assert_eq!(f.burst.send(&[datagram]), Ok(1));
    let head = *f.burst.port_mut().held.last().unwrap();
    let frame = bytes(head);
    assert_eq!(&frame[FRAME_OVERHEAD..], &packed[..]);
    assert_eq!(u16::from_be_bytes([frame[34], frame[35]]), LOCAL.port + 3);
    f.burst.port_mut().complete();
    assert_eq!(f.burst.report().sources, [0, 0, 0, 1, 0, 0, 0, 0]);
}

/// A frame's source port depends on its request slot alone, so a burst shortened by prepare rejection or ring capacity sends the frame that leaves from the same port every time.
#[test]
fn source_ports_do_not_depend_on_what_leaves() {
    let local = Station { ports: 4, ..LOCAL };
    let mut f = fixture_over(
        mock::arena(),
        Wire::new(local, &PEERS, &mut EngineBudget::unlimited()).unwrap(),
        Box::new(iova),
        Box::new(|| true),
    );
    let mut header = [0x52; 192];
    header[56..64].copy_from_slice(&(6u64 << 48 | 1).to_be_bytes());
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"r"), Payload::EMPTY],
    };
    let mut left = Vec::new();
    for short in [
        "ring", "ring", "ring", "ring", "prepare", "prepare", "prepare", "prepare",
    ] {
        let port = f.burst.port_mut();
        (port.accept, port.prepare) = if short == "ring" {
            (1, usize::MAX)
        } else {
            (usize::MAX, 1)
        };
        assert_eq!(f.burst.send(&[datagram, datagram]), Ok(1), "{short}");
        let frame = bytes(*f.burst.port_mut().held.last().unwrap());
        left.push(u16::from_be_bytes([frame[34], frame[35]]));
        f.burst.port_mut().complete();
    }
    assert_eq!(left, [7002; 8], "slot 6 modulo 4 ports");
}

/// A reset the device reports ends the turn's cleanup: recovery proves the stop, which returns every chain the
/// device held, rechecks the registration once and restarts the device, after which datagrams flow again. The
/// episode reaches the start unrefused, the port runs the stop, the reset, the re-initialization and the start in
/// that order, and the watch asks for no containment. The proven stop returns both header buffers and the source,
/// and the start posts seven receive buffers.
#[test]
fn a_pending_reset_recovers_in_place() {
    let containment = Arc::new(Containment::default());
    let (rechecks, recheck) = counted_recheck();
    let mut f = fixture_watched(
        mock::arena(),
        Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap(),
        Box::new(iova),
        recheck,
        RecoveryWatch::new(
            Duration::from_secs(60),
            Arc::clone(&containment) as Arc<dyn Supervisor>,
        ),
    );
    let retained = source(f.arena, 4);
    let header = [0x51; 192];
    {
        let datagram = Outgoing {
            peer: PeerId(0),
            header: &header,
            payload: [
                Payload::Retained(retained.source(0..64).unwrap()),
                Payload::EMPTY,
            ],
        };
        assert_eq!(f.burst.send(&[datagram; 2]), Ok(2));
    }
    drop(retained);
    assert_eq!(
        f.arena.report(PoolKind::ReadResponse).nic_held,
        1,
        "both chains reference the one source buffer"
    );
    f.burst.port_mut().reset = true;
    let before = census(f.arena);
    f.burst.reclaim();
    let after = census(f.arena);
    assert_eq!(
        std::array::from_fn(|at| i64::from(after[at]) - i64::from(before[at])),
        [-2, 7, -1],
        "the change the reclaim made to the held header buffers, the held receive buffers and the device-held sources"
    );
    let report = f.burst.report();
    assert_eq!((report.resets, report.recoveries), (1, 1));
    assert_eq!(f.burst.link(), Link::Up);
    let port = f.burst.port_mut();
    assert_eq!((port.stops, port.restarts), (1, 1));
    assert_eq!(held(f.arena, PoolKind::PacketHeader), 0);
    assert_eq!(f.arena.report(PoolKind::ReadResponse).free, COUNT);
    assert_eq!(descriptors(&f), 8);
    let inline = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"r"), Payload::EMPTY],
    };
    let calls = f.burst.port().calls;
    assert_eq!(f.burst.send(&[inline]), Ok(1));
    assert!(f.burst.port().calls > calls, "the send reached the port");
    let report = f.burst.report();
    assert_eq!(
        (report.episode.refused, report.episode.reached),
        (false, Some(RecoveryStage::Restart))
    );
    assert_eq!((report.resets, report.recoveries), (1, 1));
    assert_eq!(f.burst.link(), Link::Up);
    let port = f.burst.port();
    assert_eq!(
        port.stages,
        [
            RecoveryStage::Stop,
            RecoveryStage::Reset,
            RecoveryStage::Reinitialize,
            RecoveryStage::Restart
        ]
    );
    assert_eq!(
        (port.stops, port.restarts, *rechecks.lock().unwrap()),
        (1, 1, 1)
    );
    assert_eq!(containment.count(), 0);
}

/// An uncertain post's quarantined chain returns through the next turn's recovery, which clears the poison.
#[test]
fn an_uncertain_post_recovers_on_the_next_turn() {
    let mut f = fixture();
    let header = [0x52; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"u"), Payload::EMPTY],
    };
    *f.burst.port_mut() = MockPort {
        accept: 0,
        uncertain: true,
        ..MockPort::open()
    };
    assert_eq!(f.burst.send(&[datagram]), Ok(0));
    assert_eq!(held(f.arena, PoolKind::PacketHeader), 1);
    f.burst.reclaim();
    assert!(!f.burst.poisoned());
    assert_eq!(f.burst.report().recoveries, 1);
    assert_eq!(held(f.arena, PoolKind::PacketHeader), 0);
}

/// Sends one datagram with `slices` retained payload slices, from one source buffer, into a port that takes nothing and reports the refused chain uncertain, keeping it only when `retain` is set.
/// The fixture has made no earlier call, so the post leaves the transport poisoned and the link up, one chain
/// quarantined and unsettled with its header buffer, source reference and descriptors held, and a port that ran
/// one prepare and one burst and no stop or start.
fn send_uncertain(f: &mut Fixture, retain: bool, slices: usize) {
    let retained = source(f.arena, 6);
    let header = [0x56; 192];
    {
        let piece = |at: usize| Payload::Retained(retained.source(at * 64..at * 64 + 64).unwrap());
        let payload = match slices {
            1 => [piece(0), Payload::EMPTY],
            _ => [piece(0), piece(1)],
        };
        let datagram = Outgoing {
            peer: PeerId(0),
            header: &header,
            payload,
        };
        let port = f.burst.port_mut();
        port.accept = 0;
        port.uncertain = true;
        port.retain_uncertain = retain;
        assert_eq!(f.burst.send(&[datagram]), Ok(0));
    }
    drop(retained);
    assert!(f.burst.poisoned());
    assert_eq!(f.burst.report().quarantined, 1);
    assert_eq!(held(f.arena, PoolKind::PacketHeader), 1);
    assert_eq!(f.arena.report(PoolKind::ReadResponse).nic_held, 1);
    assert_eq!(descriptors(f), 8 - slices as u32);
    assert_eq!(f.burst.link(), Link::Up);
    assert_eq!(settled(f), (1, 0, 0));
    let port = f.burst.port();
    assert_eq!((port.prepares, port.bursts, port.calls), (1, 1, 2));
    assert_eq!((port.stops, port.restarts), (0, 0));
}

/// Asserts that no object returned twice: no header or payload return named a disarmed token or a descriptor not out, and no reference return missed its incarnation.
fn assert_single_returns(f: &Fixture) {
    assert_eq!(
        (
            f.header.state.report().stray,
            f.payload.state.report().stray
        ),
        (0, 0),
        "no segment returned twice"
    );
    assert_eq!(f.arena.report(PoolKind::PacketHeader).mismatched, 0);
    assert_eq!(f.arena.report(PoolKind::ReadResponse).mismatched, 0);
}

/// Asserts that the pools hold nothing: every header buffer, payload descriptor and source reference is back.
fn assert_nothing_held(f: &Fixture) {
    assert_eq!(held(f.arena, PoolKind::PacketHeader), 0);
    assert_eq!(f.arena.report(PoolKind::ReadResponse).free, COUNT);
    assert_eq!(descriptors(f), 8);
    assert_single_returns(f);
}

/// The quarantined, device-returned and locally reconciled chain counts.
fn settled(f: &Fixture) -> (u64, u64, u64) {
    let report = f.burst.report();
    (
        report.quarantined,
        report.quarantine_returned,
        report.quarantine_released,
    )
}

/// An uncertain chain of a header and two payload descriptors that the device kept no reference to returns every header buffer, payload descriptor and source reference exactly once after the next proven stop, counted as one local reconciliation, and a later recovery settles nothing again.
#[test]
fn an_uncertain_chain_the_device_never_took_reconciles_after_a_proven_stop() {
    let mut f = fixture();
    send_uncertain(&mut f, false, 2);
    f.burst.reclaim();
    assert_eq!(f.burst.link(), Link::Up);
    assert!(!f.burst.poisoned());
    assert_eq!(settled(&f), (1, 0, 1));
    assert_nothing_held(&f);
    f.burst.port_mut().reset = true;
    f.burst.reclaim();
    assert_eq!(f.burst.report().recoveries, 2);
    assert_eq!(settled(&f), (1, 0, 1), "each quarantine settles once");
    assert_nothing_held(&f);
}

/// A device that kept the uncertain chain returns it at the proven stop, which counts one device return and no local release.
#[test]
fn a_retained_uncertain_chain_returns_through_the_device_at_the_proven_stop() {
    let mut f = fixture();
    send_uncertain(&mut f, true, 1);
    f.burst.reclaim();
    assert_eq!(f.burst.link(), Link::Up);
    assert_eq!(settled(&f), (1, 1, 0));
    assert_nothing_held(&f);
}

/// A device that returned the uncertain chain before the stop leaves the proven stop nothing to release, which counts one device return.
#[test]
fn an_uncertain_chain_returned_before_the_stop_releases_nothing_locally() {
    let mut f = fixture();
    send_uncertain(&mut f, true, 1);
    f.burst.port_mut().complete();
    assert_nothing_held(&f);
    f.burst.reclaim();
    assert_eq!(f.burst.link(), Link::Up);
    assert_eq!(settled(&f), (1, 1, 0));
    assert_nothing_held(&f);
}

/// Sends one inline datagram over a link that is down or lost, to a port that would take it. The send is closed,
/// and it leaves as they were the link and the poison, the quarantined, device-returned and locally reconciled
/// chain counts, the header buffers, source references and payload descriptors held, the port's prepare, burst
/// and total call counts, and its stops and starts.
fn a_later_send_is_closed(f: &mut Fixture) {
    let observed = |f: &Fixture| {
        let port = f.burst.port();
        (
            (f.burst.link(), f.burst.poisoned(), settled(f)),
            [
                held(f.arena, PoolKind::PacketHeader),
                f.arena.report(PoolKind::ReadResponse).nic_held,
                8 - descriptors(f),
            ],
            (port.prepares, port.bursts, port.calls),
            (port.stops, port.restarts),
        )
    };
    let header = [0x57; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"u"), Payload::EMPTY],
    };
    f.burst.port_mut().accept = usize::MAX;
    let before = observed(f);
    assert_eq!(f.burst.send(&[datagram]), Err(DatagramError::Closed));
    assert_eq!(
        observed(f),
        before,
        "a closed transport hands the port nothing"
    );
}

/// An unproven stop settles nothing: the quarantined chain keeps its header buffer, descriptor and source
/// reference. The link is lost, so a later send is closed.
#[test]
fn an_unproven_stop_leaves_the_quarantined_chain_charged() {
    let mut f = fixture();
    send_uncertain(&mut f, false, 1);
    f.burst.port_mut().proven_stops = 0;
    f.burst.reclaim();
    assert_eq!(f.burst.link(), Link::Lost);
    assert_eq!(settled(&f), (1, 0, 0));
    assert_eq!(held(f.arena, PoolKind::PacketHeader), 1);
    assert_eq!(f.arena.report(PoolKind::ReadResponse).nic_held, 1);
    assert_eq!(descriptors(&f), 7);
    a_later_send_is_closed(&mut f);
}

/// Extracting the port while a chain is quarantined stops the port first. A proven stop settles the chain before the port returns; an unproven stop keeps the chain charged.
#[test]
fn extracting_the_port_settles_the_quarantined_chain_at_a_proven_stop() {
    for proven in [true, false] {
        let mut f = fixture();
        send_uncertain(&mut f, false, 1);
        f.burst.port_mut().proven_stops = u32::from(proven);
        let Fixture {
            arena,
            burst,
            header,
            payload,
            ..
        } = f;
        let port = burst.into_port();
        let charged = u32::from(!proven);
        assert_eq!(
            held(arena, PoolKind::PacketHeader),
            charged,
            "proven stop: {proven}"
        );
        assert_eq!(arena.report(PoolKind::ReadResponse).nic_held, charged);
        assert_eq!(descriptors_of(&payload), 8 - charged);
        assert_eq!(
            (header.state.report().stray, payload.state.report().stray),
            (0, 0),
            "no segment returned twice"
        );
        assert_eq!(port.stops, 1, "proven stop: {proven}");
    }
}

/// A restart that fails after a proven stop, whether the device's start fails or the registration fails its
/// recheck, leaves the quarantined chain reconciled once, the poison cleared and the link down, with no later
/// recovery reviving it. A failed recheck ends the restart with `ESTALE` before the device's start, whether that
/// start would fail or succeed; a passing recheck lets the start run once and fail with `EIO`; either failure runs
/// the second stop. A send is closed and changes nothing, right after the failed restart and after the next reclaim.
#[test]
fn a_failed_restart_after_a_proven_stop_leaves_the_chain_reconciled() {
    let rows = [
        (false, Some(libc::EIO), libc::EIO, 1),
        (true, Some(libc::EIO), libc::ESTALE, 0),
        (true, None, libc::ESTALE, 0),
    ];
    // Each row runs twice: the two reclaims back to back, and with a send between them.
    let cases = rows
        .into_iter()
        .flat_map(|row| [false, true].map(|send_between| (row, send_between)));
    for ((stale, start_error, error, starts), send_between) in cases {
        let case = format!(
            "stale registration: {stale}, start error: {start_error:?}, send between: {send_between}"
        );
        let mut f = fixture_over(
            mock::arena(),
            Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap(),
            Box::new(iova),
            Box::new(move || !stale),
        );
        send_uncertain(&mut f, false, 1);
        f.burst.port_mut().restart_error = start_error;
        f.burst.reclaim();
        assert_eq!(f.burst.link(), Link::Down, "{case}");
        let report = f.burst.report();
        assert_eq!(
            (report.recoveries, report.restart_error),
            (0, Some(error)),
            "{case}"
        );
        assert_eq!(settled(&f), (1, 0, 1), "{case}");
        assert_nothing_held(&f);
        assert!(!f.burst.poisoned(), "{case}");
        assert_eq!(
            (f.burst.port().stops, f.burst.port().restarts),
            (2, starts),
            "{case}"
        );
        if send_between {
            a_later_send_is_closed(&mut f);
        }
        f.burst.reclaim();
        assert_eq!(f.burst.link(), Link::Down);
        assert_eq!(settled(&f), (1, 0, 1));
        assert_nothing_held(&f);
        a_later_send_is_closed(&mut f);
    }
}

/// After a burst whose device took the first datagram and reported the second uncertain without keeping it, recovery reconciles the second chain locally while the device returns the first at the proven stop.
#[test]
fn reconciliation_settles_the_uncertain_chain_after_an_accepted_prefix() {
    let mut f = fixture();
    let retained = source(f.arena, 8);
    let header = [0x57; 192];
    {
        let datagram = Outgoing {
            peer: PeerId(0),
            header: &header,
            payload: [
                Payload::Retained(retained.source(0..64).unwrap()),
                Payload::EMPTY,
            ],
        };
        let port = f.burst.port_mut();
        port.accept = 1;
        port.uncertain = true;
        port.retain_uncertain = false;
        assert_eq!(f.burst.send(&[datagram; 2]), Ok(1));
    }
    drop(retained);
    assert_eq!(held(f.arena, PoolKind::PacketHeader), 2);
    assert_eq!(
        f.burst.port_mut().held.len(),
        1,
        "the device holds only the accepted chain"
    );
    f.burst.reclaim();
    assert_eq!(f.burst.link(), Link::Up);
    assert_eq!(settled(&f), (1, 0, 1));
    assert_nothing_held(&f);
}

/// A stop that cannot be proven loses the link: every call reports the transport closed, the chains the device held stay held, and later turns leave the device alone.
#[test]
fn an_unproven_stop_loses_the_link_and_keeps_memory_held() {
    let mut f = fixture();
    let header = [0x53; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"l"), Payload::EMPTY],
    };
    assert_eq!(f.burst.send(&[datagram]), Ok(1));
    let port = f.burst.port_mut();
    port.reset = true;
    port.proven_stops = 0;
    f.burst.reclaim();
    f.burst.reclaim();
    assert_eq!(f.burst.link(), Link::Lost);
    assert_eq!(
        (f.burst.port_mut().stops, f.burst.port_mut().restarts),
        (1, 0)
    );
    assert_eq!(held(f.arena, PoolKind::PacketHeader), 1);
    assert_eq!(f.burst.send(&[datagram]), Err(DatagramError::Closed));
    let mut leases: [Option<PacketLease<'_>>; 1] = [None];
    let mut meta = [Received::default(); 1];
    assert_eq!(
        f.burst.receive(f.receive, &mut leases, &mut meta),
        Err(DatagramError::Closed)
    );
}

/// Recheck or zero-acquisition restart failure leaves Down after a proven second stop; zero-acquisition restart failure leaves Lost after an unproven one.
#[test]
fn a_failed_recheck_or_restart_leaves_the_link_down() {
    let mut f = fixture_over(
        mock::arena(),
        Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap(),
        Box::new(iova),
        Box::new(|| false),
    );
    f.burst.port_mut().reset = true;
    f.burst.reclaim();
    assert_eq!(f.burst.link(), Link::Down);
    let report = f.burst.report();
    assert_eq!(
        (report.resets, report.restart_error),
        (1, Some(libc::ESTALE))
    );
    assert_eq!(
        (f.burst.port_mut().stops, f.burst.port_mut().restarts),
        (2, 0)
    );

    let mut f = fixture();
    let port = f.burst.port_mut();
    port.reset = true;
    port.restart_error = Some(libc::EIO);
    f.burst.reclaim();
    assert_eq!(f.burst.link(), Link::Down);
    assert_eq!(f.burst.report().recoveries, 0);
    assert_eq!(f.burst.report().restart_error, Some(libc::EIO));
    assert_eq!(
        (f.burst.port_mut().stops, f.burst.port_mut().restarts),
        (2, 1)
    );

    let mut f = fixture();
    let port = f.burst.port_mut();
    port.restart_error = Some(libc::EIO);
    port.proven_stops = 1;
    port.posted.clear();
    let header = [0x55; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"h"), Payload::EMPTY],
    };
    assert_eq!(f.burst.send(&[datagram]), Ok(1));
    // The first proof returns the chain; this restart fails before receive acquisition.
    f.burst.port_mut().reset = true;
    f.burst.reclaim();
    assert_eq!(f.burst.link(), Link::Lost);
    assert_eq!(f.burst.port_mut().stops, 2);
    assert_eq!(f.burst.port().restarts, 1);
    assert!(f.burst.port().posted.is_empty());
    assert_nothing_held(&f);
}

/// A restart refills the receive ring from the receive pool and a stop returns every posted buffer; with the application holding two buffers the pool is short, so the restart fails and the link goes down with every buffer the device held back.
#[test]
fn recovery_reposts_receive_buffers_and_fails_short() {
    let mut f = fixture();
    f.burst.port_mut().reset = true;
    f.burst.reclaim();
    assert_eq!(f.burst.link(), Link::Up);
    assert_eq!(f.arena.report(PoolKind::PacketReceive).free, COUNT - 7);
    let (frame, meta) = mock::inbound(&LOCAL, &PEER, b"held");
    let first = arrive(&f, &frame, meta, std::ptr::null_mut());
    let second = f.burst.port_mut().posted.pop().unwrap();
    f.burst.port_mut().reset = true;
    f.burst.reclaim();
    assert_eq!(f.burst.link(), Link::Down);
    assert_eq!(f.burst.report().restart_error, Some(libc::EFAULT));
    assert!(f.burst.port_mut().posted.is_empty());
    assert_eq!(f.arena.report(PoolKind::PacketReceive).free, COUNT - 2);
    // SAFETY: both buffers are this test's, out of the pool and returned once.
    unsafe {
        mock::device_free(first);
        mock::device_free(second);
    }
    assert_eq!(f.arena.report(PoolKind::PacketReceive).free, COUNT);
}

/// Resets in each link state: two in a row recover twice, a reset with a poisoned transport recovers once, and once the link is down later resets touch the device no more.
#[test]
fn resets_in_each_link_state() {
    let mut f = fixture();
    for _ in 0..2 {
        f.burst.port_mut().reset = true;
        f.burst.reclaim();
    }
    let report = f.burst.report();
    assert_eq!((report.resets, report.recoveries), (2, 2));

    let header = [0x54; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"p"), Payload::EMPTY],
    };
    let port = f.burst.port_mut();
    port.accept = 0;
    port.uncertain = true;
    assert_eq!(f.burst.send(&[datagram]), Ok(0));
    f.burst.port_mut().reset = true;
    f.burst.reclaim();
    assert_eq!(
        f.burst.report().recoveries,
        3,
        "one recovery for both causes"
    );
    assert!(!f.burst.port_mut().reset, "service consumed the reset");

    f.burst.port_mut().restart_error = Some(libc::EIO);
    f.burst.port_mut().reset = true;
    f.burst.reclaim();
    assert_eq!(f.burst.link(), Link::Down);
    let calls = (f.burst.port_mut().stops, f.burst.port_mut().restarts);
    f.burst.port_mut().reset = true;
    f.burst.reclaim();
    assert_eq!(
        (f.burst.port_mut().stops, f.burst.port_mut().restarts),
        calls
    );
}

/// Burst logic charges exactly the bytes it allocates, once: its payload
/// translations, routes and three batch arrays. An exact budget fits, a
/// budget one byte short and a batch whose arrays overflow refuse before
/// allocating, each with the budget unchanged and the port and addressing
/// handed back.
#[test]
fn burst_construction_charges_its_state_exactly_or_leaves_the_budget() {
    let arena = mock::arena();
    let header = mock::arena_pool(arena, PoolKind::PacketHeader, Role::Header);
    let payload = mock::payload_pool(arena, 8);
    let receive = mock::arena_pool(arena, PoolKind::PacketReceive, Role::Receive);
    let pools = [header.state, payload.state, receive.state];
    let translations = arena.config().pool(PoolKind::ReadResponse).count as usize;
    let offset = 1u64 << 40;
    let registration = Forged(
        move |addr: usize, _len: usize| Some(addr as u64 ^ offset),
        || true,
    );
    let charge = Burst::<MockPort>::charge(translations, PEERS.len(), 8).unwrap();
    let wire = || Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap();

    let mut short = EngineBudget::new(charge - 1);
    let addressing = wire();
    let watch = mock::watch();
    let allocations = crate::instrument::allocations();
    let refused = Burst::new(
        MockPort::open(),
        addressing,
        pools,
        &registration,
        watch,
        8,
        &mut short,
    );
    let Err(refused) = refused else {
        panic!("a budget one byte short refuses");
    };
    assert_eq!(crate::instrument::allocations(), allocations);
    assert!(matches!(refused.error, BurstError::Budget(_)));
    assert_eq!(short, EngineBudget::new(charge - 1));
    assert_eq!((refused.port.calls, refused.wire.peers()), (0, PEERS.len()));

    let mut budget = EngineBudget::unlimited();
    let overflow = usize::MAX / 8;
    let watch = mock::watch();
    let allocations = crate::instrument::allocations();
    let Err(refused) = Burst::new(
        refused.port,
        refused.wire,
        pools,
        &registration,
        watch,
        overflow,
        &mut budget,
    ) else {
        panic!("a batch past the address space refuses");
    };
    assert_eq!(refused.error, BurstError::Batch);
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(budget.used(), 0);

    let mut exact = EngineBudget::new(charge);
    let watch = mock::watch();
    let bytes = crate::instrument::allocated_bytes();
    let Ok(burst) = Burst::new(
        refused.port,
        refused.wire,
        pools,
        &registration,
        watch,
        8,
        &mut exact,
    ) else {
        panic!("an exact budget fits");
    };
    assert_eq!(
        crate::instrument::allocated_bytes() - bytes,
        charge,
        "the charge is the bytes the burst logic allocates"
    );
    assert_eq!(exact.used(), charge);
    drop(burst);
}

/// One budget through a composed endpoint: the endpoint's request table,
/// the addressing and the burst logic each charge exactly the bytes they
/// allocate, once, and the payload pool's constructor charges the descriptor
/// memory it allocates.
#[test]
fn a_composed_endpoint_charges_each_allocation_once() {
    use crate::net::EndpointConfig;
    let arena = mock::arena();
    let config = EndpointConfig {
        peers: PEERS.len() as u16,
        request_slots: 4,
        peer_requests: 4,
        receive_reserve: 2,
        batch: 2,
    };
    let header = mock::arena_pool(arena, PoolKind::PacketHeader, Role::Header);
    let payload = mock::payload_pool(arena, 8);
    let receive = mock::arena_pool(arena, PoolKind::PacketReceive, Role::Receive);
    let pools = [header.state, payload.state, receive.state];
    let valid = config.validate::<u64>(arena.config()).unwrap();
    let mut budget = EngineBudget::unlimited();
    use crate::instrument::charged;
    let (memory, _, endpoint) = charged(&mut budget, |b| valid.initialize(arena, b).unwrap());
    let (wire, _, addressing) = charged(&mut budget, |b| Wire::new(LOCAL, &PEERS, b).unwrap());
    let registration = Forged(iova, || true);
    let watch = mock::watch();
    let (burst, _, transport) = charged(&mut budget, |b| {
        Burst::new(MockPort::open(), wire, pools, &registration, watch, 2, b).unwrap()
    });
    let allocated = endpoint + addressing + transport;
    let translations = arena.config().pool(PoolKind::ReadResponse).count as usize;
    let expected = valid.charge()
        + Wire::charge(PEERS.len()).unwrap()
        + Burst::<MockPort>::charge(translations, PEERS.len(), 2).unwrap();
    assert_eq!(budget.used(), expected, "each part's charge, once");
    assert_eq!(allocated, expected, "the charges are the bytes allocated");
    drop((burst, memory));
}

/// A watchdog clock that reads zero until [`StallClock::expire`] moves it
/// past the deadline, and an untimed wait that call wakes, so the watchdog
/// expires only where a test calls it: inside a stalled stage's call, or
/// before a stage begins.
#[derive(Clone, Default)]
pub(super) struct StallClock(Arc<StallState>);

#[derive(Default)]
struct StallState {
    /// The clock's reading once a stall set it.
    reading: Mutex<Option<Duration>>,
    /// The watch's watchdog state, which the stall wakes.
    armed: Mutex<Option<Shared>>,
    /// Watchdog workers the watch started.
    starts: Mutex<u32>,
}

impl Timer for StallClock {
    fn now(&self) -> Duration {
        self.0.reading.lock().unwrap().unwrap_or(Duration::ZERO)
    }

    fn wait<'a>(
        &self,
        state: MutexGuard<'a, State>,
        wake: &Condvar,
        _timeout: Duration,
    ) -> MutexGuard<'a, State> {
        wake.wait(state).unwrap_or_else(PoisonError::into_inner)
    }
}

impl StallClock {
    /// Moves the clock past `deadline` and wakes the episode's worker under its lock.
    pub(super) fn expire(&self, deadline: Duration) {
        let armed = self.0.armed.lock().unwrap().clone();
        let shared = armed.expect("the episode armed its watchdog");
        let guard = shared.0.lock().unwrap_or_else(PoisonError::into_inner);
        *self.0.reading.lock().unwrap() = Some(deadline + Duration::from_millis(1));
        shared.1.notify_all();
        drop(guard);
    }
}

/// Counts containment requests and wakes a stall waiting for the first; it
/// reports a containment verified once it ran when it `verifies`.
#[derive(Default)]
pub(super) struct Containment {
    requests: Mutex<u32>,
    requested: Condvar,
    verifies: bool,
}

impl Supervisor for Containment {
    fn contain(&self) {
        *self.requests.lock().unwrap() += 1;
        self.requested.notify_all();
    }

    fn verified(&self) -> bool {
        self.verifies && self.count() > 0
    }
}

impl Containment {
    fn verifying() -> Arc<Self> {
        Arc::new(Self {
            verifies: true,
            ..Self::default()
        })
    }

    pub(super) fn count(&self) -> u32 {
        *self.requests.lock().unwrap()
    }

    /// Waits, bounded, until the watchdog asked to contain.
    pub(super) fn wait_requested(&self) {
        let requests = self.requests.lock().unwrap();
        let (requests, timeout) = self
            .requested
            .wait_timeout_while(requests, Duration::from_secs(20), |count| *count == 0)
            .unwrap();
        assert!(!timeout.timed_out(), "the watchdog asked to contain");
        drop(requests);
    }
}

pub(super) const RECOVERY_DEADLINE: Duration = Duration::from_secs(5);

/// A recovery watch that arms its watchdog on `clock` over `containment`; the clock keeps the worker's state, which a stall wakes, and counts the workers the watch starts.
pub(super) fn watch_on<S: Supervisor + 'static>(
    clock: &StallClock,
    containment: &Arc<S>,
) -> RecoveryWatch {
    let clock = clock.clone();
    RecoveryWatch::with_start(
        RECOVERY_DEADLINE,
        Arc::clone(containment) as Arc<dyn Supervisor>,
        move |deadline, supervisor| {
            let watchdog = Rearmable::idle_with(deadline, supervisor, clock.clone())?;
            *clock.0.armed.lock().unwrap() = Some(watchdog.shared());
            *clock.0.starts.lock().unwrap() += 1;
            Ok(watchdog)
        },
    )
}

/// A burst whose recovery arms its watchdog on `clock` over `containment`.
fn watched<S: Supervisor + 'static>(
    arena: &'static BufferArena<TestPlatform>,
    clock: &StallClock,
    containment: &Arc<S>,
    recheck: Box<dyn Fn() -> bool>,
) -> Fixture {
    fixture_watched(
        arena,
        Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap(),
        Box::new(iova),
        recheck,
        watch_on(clock, containment),
    )
}

/// The buffers the device and the burst hold: the header and receive pools' held counts and the source buffers chains reference.
fn census(arena: &BufferArena<TestPlatform>) -> [u32; 3] {
    [
        held(arena, PoolKind::PacketHeader),
        held(arena, PoolKind::PacketReceive),
        arena.report(PoolKind::ReadResponse).nic_held,
    ]
}

/// A registration recheck that passes and counts its calls, with the count.
fn counted_recheck() -> (Arc<Mutex<u32>>, Box<dyn Fn() -> bool>) {
    let rechecks = Arc::new(Mutex::new(0));
    let counted = Arc::clone(&rechecks);
    let recheck = Box::new(move || {
        *counted.lock().unwrap() += 1;
        true
    });
    (rechecks, recheck)
}

/// Poisons `f`'s transport with an uncertain post whose chain the mock device keeps, so recovery begins with a
/// quarantined chain to reconcile.
fn quarantine(f: &mut Fixture) {
    let header = [0x53; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"q"), Payload::EMPTY],
    };
    f.burst.port_mut().accept = 0;
    f.burst.port_mut().uncertain = true;
    let _ = f.burst.send(&[datagram]);
    assert!(
        f.burst.poisoned(),
        "the uncertain post quarantined its chain"
    );
}

const RECOVERY_STAGES: [RecoveryStage; 5] = [
    RecoveryStage::Stop,
    RecoveryStage::Recheck,
    RecoveryStage::Reset,
    RecoveryStage::Reinitialize,
    RecoveryStage::Restart,
];

/// A stall at each recovery stage, the recheck's in the registration and every other in the port, holds the
/// owner thread inside that stage's call until the watchdog expires on its own clock and asks to contain. The
/// episode then records that stage as the expiry's and the request once, the port ran exactly the stages up to the
/// stalled one, the link is lost, no restart error is recorded and every buffer the stall saw held stays held
/// afterwards: an uncertain post's quarantined chain stays held with every chain the device had, and buffers the
/// stalled call itself posted stay with the device. A stop that stalls and then proves itself still leaves the
/// quarantine unreconciled; the mock device's proven stop returned the chains it held, so that row asserts its one
/// stop in place of the census. `into_port` hands the port back after the expiry with its stop count unchanged.
///
/// Each row runs under a supervisor that verifies its containment and under one that contains without verifying,
/// and the episode records the verification under the first alone. Every row hands the port back, and the request
/// and recheck counts hold both while the burst has the port and once the port is dropped.
#[test]
fn a_stall_at_each_recovery_stage_expires_the_watchdog_and_holds_every_buffer() {
    let cases = RECOVERY_STAGES
        .iter()
        .map(|stage| (*stage, false))
        .chain([(RecoveryStage::Stop, true)])
        .flat_map(|(stalled, proven)| [true, false].map(|verifies| (stalled, proven, verifies)));
    for (stalled, proven, verifies) in cases {
        let clock = StallClock::default();
        let containment = if verifies {
            Containment::verifying()
        } else {
            Arc::new(Containment::default())
        };
        let arena = mock::arena();
        let seen = Arc::new(Mutex::new(None));
        let stall = {
            let (clock, containment, seen) =
                (clock.clone(), Arc::clone(&containment), Arc::clone(&seen));
            move || {
                *seen.lock().unwrap() = Some(census(arena));
                clock.expire(RECOVERY_DEADLINE);
                containment.wait_requested();
            }
        };
        let rechecks = Arc::new(Mutex::new(0));
        let recheck: Box<dyn Fn() -> bool> = {
            let (rechecks, stall) = (Arc::clone(&rechecks), Mutex::new(Some(stall.clone())));
            Box::new(move || {
                *rechecks.lock().unwrap() += 1;
                if stalled == RecoveryStage::Recheck
                    && let Some(stall) = stall.lock().unwrap().take()
                {
                    stall();
                }
                true
            })
        };
        let mut f = watched(arena, &clock, &containment, recheck);
        quarantine(&mut f);
        // A stalled stop that ends unproven keeps every chain the device held.
        let unproven = stalled == RecoveryStage::Stop && !proven;
        f.burst.port_mut().proven_stops = if unproven { 0 } else { u32::MAX };
        if stalled != RecoveryStage::Recheck {
            f.burst.port_mut().stall = Some((
                stalled,
                Box::new(move || {
                    stall();
                    true
                }),
            ));
        }
        f.burst.reclaim();
        let case = format!("{stalled:?} proven {proven} verifying {verifies}");
        let report = f.burst.report();
        let (link, poisoned) = (f.burst.link(), f.burst.poisoned());
        let stages = f.burst.port_mut().stages.clone();
        let stops = f.burst.port_mut().stops;
        let after = census(f.arena);
        let counts = || (containment.count(), *rechecks.lock().unwrap());
        let (requests, rechecked) = counts();
        let handed_back = f.burst.into_port().stops;
        let dropped = counts();
        assert_eq!(
            report.episode,
            RecoveryEpisode {
                episode: 1,
                reached: Some(stalled),
                expired_at: Some(stalled),
                containment_requested: true,
                containment_verified: verifies,
                refused: false,
            },
            "{case}"
        );
        assert_eq!(link, Link::Lost, "{case}");
        assert_eq!(requests, 1, "{case}: containment requested once");
        assert_eq!(report.recoveries, 0, "{case}");
        let ran: Vec<RecoveryStage> = RECOVERY_STAGES
            .iter()
            .copied()
            .take_while(|stage| *stage != stalled)
            .chain([stalled])
            .filter(|stage| *stage != RecoveryStage::Recheck)
            .collect();
        assert_eq!(
            stages, ran,
            "{case}: the stages up to the stall, and no later one"
        );
        assert_eq!(
            rechecked,
            usize::from(stalled != RecoveryStage::Stop),
            "{case}: the recheck runs only before a later stall"
        );
        assert_eq!(
            dropped,
            (requests, rechecked),
            "{case}: the hand-back asks for no containment and runs no recheck"
        );
        assert_eq!(
            report.restart_error, None,
            "{case}: an episode that expired records no restart error"
        );
        if stalled == RecoveryStage::Stop {
            assert!(
                poisoned,
                "{case}: an expired stop leaves the quarantine unreconciled"
            );
            assert_eq!(
                (report.quarantine_returned, report.quarantine_released),
                (0, 0),
                "{case}"
            );
            assert_eq!(
                handed_back, stops,
                "{case}: the handed-back port is not stopped again to settle the quarantine"
            );
            if proven {
                assert_eq!(
                    (stops, handed_back),
                    (1, 1),
                    "{case}: the port stopped once"
                );
                continue;
            }
        }
        let seen = seen.lock().unwrap().expect("the stall ran");
        assert!(
            after.iter().zip(seen).all(|(after, seen)| *after >= seen),
            "{case}: nothing the stall saw held was released: {seen:?} then {after:?}"
        );
    }
}

/// The episode reports the containment request and the supervisor's verification as separate observations: a
/// supervisor that contains without verifying leaves the request recorded and the verification absent.
#[test]
fn a_containment_the_supervisor_does_not_verify_stays_only_requested() {
    let (clock, containment) = (StallClock::default(), Arc::new(Containment::default()));
    let stall = {
        let (clock, containment) = (clock.clone(), Arc::clone(&containment));
        move || {
            clock.expire(RECOVERY_DEADLINE);
            containment.wait_requested();
        }
    };
    let mut f = watched(mock::arena(), &clock, &containment, Box::new(|| true));
    f.burst.port_mut().stall = Some((
        RecoveryStage::Reset,
        Box::new(move || {
            stall();
            true
        }),
    ));
    f.burst.port_mut().reset = true;
    f.burst.reclaim();
    let episode = f.burst.report().episode;
    assert_eq!(
        (
            episode.expired_at,
            episode.containment_requested,
            episode.containment_verified
        ),
        (Some(RecoveryStage::Reset), true, false)
    );
}

/// A burst whose recovery watch cannot start its watchdog worker, so no episode arms, with the watch's supervisor
/// and the count of the registration's rechecks.
fn unarmed() -> (Fixture, Arc<Containment>, Arc<Mutex<u32>>) {
    let containment = Arc::new(Containment::default());
    let (rechecks, recheck) = counted_recheck();
    let watch = RecoveryWatch::with_start(
        RECOVERY_DEADLINE,
        Arc::clone(&containment) as Arc<dyn Supervisor>,
        |_, _| Err(std::io::Error::other("no watchdog thread")),
    );
    let f = fixture_watched(
        mock::arena(),
        Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap(),
        Box::new(iova),
        recheck,
        watch,
    );
    (f, containment, rechecks)
}

/// Sends one inline datagram over a link a refused arm lost. The send is closed before it reaches the port, and
/// after it the episode still records the refusal alone, with one reset counted and no recovery, the link lost,
/// the poison as `poisoned`, no recovery stage, stop or start on the port, no recheck and no containment asked.
fn a_refused_arm_stays_closed(
    f: &mut Fixture,
    containment: &Containment,
    rechecks: &Mutex<u32>,
    poisoned: bool,
) {
    let header = [0x54; 192];
    let later = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"q"), Payload::EMPTY],
    };
    let calls = f.burst.port().calls;
    assert_eq!(f.burst.send(&[later]), Err(DatagramError::Closed));
    let report = f.burst.report();
    assert_eq!(
        report.episode,
        RecoveryEpisode {
            episode: 1,
            refused: true,
            ..RecoveryEpisode::default()
        }
    );
    assert_eq!((report.resets, report.recoveries), (1, 0));
    assert_eq!(f.burst.link(), Link::Lost);
    assert_eq!(f.burst.poisoned(), poisoned);
    let port = f.burst.port();
    assert_eq!(port.calls, calls, "the closed send made no port call");
    assert!(port.stages.is_empty());
    assert_eq!((port.stops, port.restarts), (0, 0));
    assert_eq!(*rechecks.lock().unwrap(), 0);
    assert_eq!(containment.count(), 0);
}

/// A watchdog that cannot arm refuses the recovery before any device call: no stop, recheck or restart runs, no
/// containment is asked for, an uncertain post's quarantined chain stays unreconciled, the episode records the
/// refusal, and the link is lost with everything the device held still held. A later send is closed before it
/// reaches the port and changes none of that.
#[test]
fn a_watchdog_that_cannot_arm_refuses_recovery_before_any_device_call() {
    let (mut f, containment, rechecks) = unarmed();
    quarantine(&mut f);
    let (before, calls) = (census(f.arena), f.burst.port_mut().calls);
    f.burst.reclaim();
    let report = f.burst.report();
    assert_eq!(
        report.episode,
        RecoveryEpisode {
            episode: 1,
            refused: true,
            ..RecoveryEpisode::default()
        }
    );
    assert_eq!((report.resets, report.recoveries), (1, 0));
    assert_eq!(f.burst.link(), Link::Lost);
    assert!(f.burst.poisoned(), "the quarantine stays unreconciled");
    let port = f.burst.port_mut();
    assert_eq!(
        port.calls,
        calls + 1,
        "only the service call that found the poison ran"
    );
    assert!(port.stages.is_empty());
    assert_eq!(*rechecks.lock().unwrap(), 0);
    assert_eq!(census(f.arena), before);
    a_refused_arm_stays_closed(&mut f, &containment, &rechecks, true);
}

/// A pending reset under a watchdog that cannot arm is refused before any device call: the reclaim makes only
/// the service call that reported the reset, the two chains the device holds stay held, and the link is lost,
/// so a later send is closed before it reaches a device whose reset was never handled.
#[test]
fn a_pending_reset_whose_watchdog_cannot_arm_leaves_the_link_lost_with_everything_held() {
    let (mut f, containment, rechecks) = unarmed();
    let retained = source(f.arena, 4);
    let header = [0x51; 192];
    {
        let datagram = Outgoing {
            peer: PeerId(0),
            header: &header,
            payload: [
                Payload::Retained(retained.source(0..64).unwrap()),
                Payload::EMPTY,
            ],
        };
        assert_eq!(f.burst.send(&[datagram; 2]), Ok(2));
    }
    drop(retained);
    f.burst.port_mut().reset = true;
    let (before, calls) = (census(f.arena), f.burst.port().calls);
    assert_eq!(before[2], 1, "both chains reference the one source buffer");
    f.burst.reclaim();
    assert_eq!(
        f.burst.port().calls,
        calls + 1,
        "only the service call that reported the reset ran"
    );
    assert_eq!(census(f.arena), before);
    a_refused_arm_stays_closed(&mut f, &containment, &rechecks, false);
}

/// A fault-free recovery runs every stage under its watchdog and disarms it: one recovery, the link up, every
/// stage in order and no expiry or containment.
#[test]
fn a_fault_free_recovery_runs_every_stage_and_disarms_its_watchdog() {
    let (clock, containment) = (StallClock::default(), Containment::verifying());
    let mut f = watched(mock::arena(), &clock, &containment, Box::new(|| true));
    f.burst.port_mut().reset = true;
    f.burst.reclaim();
    let report = f.burst.report();
    assert_eq!(
        report.episode,
        RecoveryEpisode {
            episode: 1,
            reached: Some(RecoveryStage::Restart),
            ..RecoveryEpisode::default()
        }
    );
    assert_eq!((report.resets, report.recoveries), (1, 1));
    assert_eq!(f.burst.link(), Link::Up);
    assert_eq!(containment.count(), 0);
    let port = f.burst.port_mut();
    assert_eq!(
        port.stages,
        [
            RecoveryStage::Stop,
            RecoveryStage::Reset,
            RecoveryStage::Reinitialize,
            RecoveryStage::Restart
        ]
    );
    assert_eq!((port.stops, port.restarts), (1, 1));
}

/// A start that fails stops the device again under the same watchdog: a stall in that second stop expires the
/// watchdog there, the episode records the stop as the expiry's stage, and the link is lost.
#[test]
fn a_stall_in_the_stop_after_a_failed_start_expires_the_watchdog_there() {
    let (clock, containment) = (StallClock::default(), Containment::verifying());
    let mut stops = 0;
    let stall = {
        let (clock, containment) = (clock.clone(), Arc::clone(&containment));
        move || {
            stops += 1;
            if stops < 2 {
                return false;
            }
            clock.expire(RECOVERY_DEADLINE);
            containment.wait_requested();
            true
        }
    };
    let mut f = watched(mock::arena(), &clock, &containment, Box::new(|| true));
    let port = f.burst.port_mut();
    port.restart_error = Some(libc::EIO);
    port.stall = Some((RecoveryStage::Stop, Box::new(stall)));
    port.reset = true;
    f.burst.reclaim();
    let report = f.burst.report();
    assert_eq!(
        (
            report.episode.reached,
            report.episode.expired_at,
            report.episode.containment_requested
        ),
        (Some(RecoveryStage::Stop), Some(RecoveryStage::Stop), true)
    );
    assert_eq!(report.restart_error, Some(libc::EIO));
    assert_eq!(f.burst.link(), Link::Lost);
    assert_eq!(
        f.burst.port_mut().stages,
        [
            RecoveryStage::Stop,
            RecoveryStage::Reset,
            RecoveryStage::Reinitialize,
            RecoveryStage::Restart,
            RecoveryStage::Stop
        ]
    );
    assert_eq!(containment.count(), 1);
}

/// Fault-free recoveries disarm the watchdog between episodes.
#[test]
fn successive_recoveries_rearm_the_one_watchdog_worker_the_watch_started() {
    let (clock, containment) = (StallClock::default(), Containment::verifying());
    let mut f = watched(mock::arena(), &clock, &containment, Box::new(|| true));
    for episode in 1..=2 {
        f.burst.port_mut().reset = true;
        f.burst.reclaim();
        assert_eq!(f.burst.link(), Link::Up, "episode {episode}");
        assert_eq!(
            f.burst.report().episode.expired_at,
            None,
            "episode {episode}"
        );
    }
    let stall = {
        let (clock, containment) = (clock.clone(), Arc::clone(&containment));
        move || {
            clock.expire(RECOVERY_DEADLINE);
            containment.wait_requested();
            true
        }
    };
    f.burst.port_mut().stall = Some((RecoveryStage::Reinitialize, Box::new(stall)));
    f.burst.port_mut().reset = true;
    f.burst.reclaim();
    let report = f.burst.report();
    assert_eq!(
        report.episode,
        RecoveryEpisode {
            episode: 3,
            reached: Some(RecoveryStage::Reinitialize),
            expired_at: Some(RecoveryStage::Reinitialize),
            containment_requested: true,
            containment_verified: true,
            refused: false,
        }
    );
    assert_eq!((report.resets, report.recoveries), (3, 2));
    assert_eq!(f.burst.link(), Link::Lost);
    assert_eq!(containment.count(), 1);
    assert_eq!(*clock.0.starts.lock().unwrap(), 1);
}

/// The doc comment of `Burst::recover` in `native/burst.rs` states that recovery runs "under a watchdog armed before
/// the first step" and "at most once per reset or uncertain post", and the doc comment of `Rearmable::rearm` in
/// `native/watchdog.rs` that "each rearm follows a disarm". A port whose stop stage unwinds carries the unwind
/// out of the turn that ran the recovery. The transport is still poisoned by its one uncertain post, so the next
/// turn's reclaim reaches recovery again: it returns without unwinding and begins no second episode for that post.
#[test]
fn a_recovery_whose_stop_stage_unwound_begins_no_second_episode_for_its_uncertain_post() {
    let (clock, containment) = (StallClock::default(), Containment::verifying());
    let mut f = watched(mock::arena(), &clock, &containment, Box::new(|| true));
    quarantine(&mut f);
    f.burst.port_mut().stall = Some((
        RecoveryStage::Stop,
        Box::new(|| panic!("the port's stop stage unwound")),
    ));
    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f.burst.reclaim()));
    assert_eq!(
        (first.is_err(), f.burst.report().resets, f.burst.poisoned()),
        (true, 1, true),
        "premise: the stop stage unwound out of the turn in the first episode, with the uncertain post unreconciled"
    );
    f.burst.port_mut().stall = None;
    let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f.burst.reclaim()));
    assert_eq!(
        (second.is_ok(), f.burst.report().resets),
        (true, 1),
        "the turn after the unwound stage returned, and the one uncertain post began one episode"
    );
}

/// A local station with four source ports and three peers, so one batch mixes destinations and source ports.
const SPREAD_LOCAL: Station = Station {
    mac: [2, 0, 0, 0, 0, 1],
    ip: [10, 0, 0, 1],
    port: 7000,
    ports: 4,
};
const SPREAD_PEERS: [Station; 3] = [
    PEER,
    Station {
        mac: [2, 0, 0, 0, 0, 3],
        ip: [10, 0, 0, 3],
        port: 9100,
        ports: 1,
    },
    Station {
        mac: [2, 0, 0, 0, 0, 4],
        ip: [10, 0, 0, 4],
        port: 9200,
        ports: 1,
    },
];

/// Read-response bytes per source buffer in the characterization fixtures.
const SOURCE_LEN: usize = 16384;

/// Pool sizes and the batch limit of a characterization fixture.
#[derive(Clone, Copy)]
struct Sizing {
    sources: u32,
    headers: u32,
    descriptors: u32,
    batch: usize,
}

/// A fixture of `sizing` over the spread addressing, whose registration translates every source buffer but `refused`.
fn sized(sizing: Sizing, refused: Option<usize>) -> Fixture {
    let arena = mock::arena_sized([sizing.sources, COUNT, sizing.headers]);
    let base = arena.pools().pool(PoolKind::ReadResponse).span().0;
    let translate = move |addr: usize, len: usize| {
        let hit = refused.is_some_and(|at| {
            (base + at * SOURCE_LEN..base + (at + 1) * SOURCE_LEN).contains(&addr)
        });
        if hit { None } else { iova(addr, len) }
    };
    fixture_built(
        arena,
        Wire::new(SPREAD_LOCAL, &SPREAD_PEERS, &mut EngineBudget::unlimited()).unwrap(),
        Box::new(translate),
        Box::new(|| true),
        mock::watch(),
        sizing.descriptors,
        sizing.batch,
    )
}

/// One planned payload piece: empty, inline bytes, or bytes `range` of the driver's source slot `slot`.
#[derive(Clone, Debug)]
enum Piece {
    Empty,
    Inline(Vec<u8>),
    Retained {
        slot: usize,
        range: std::ops::Range<usize>,
    },
}

/// One planned datagram: its peer, frame header and two payload pieces.
#[derive(Clone, Debug)]
struct Plan {
    peer: u16,
    header: Vec<u8>,
    pieces: [Piece; 2],
}

impl Plan {
    fn retained(&self) -> usize {
        self.pieces
            .iter()
            .filter(|piece| matches!(piece, Piece::Retained { .. }))
            .count()
    }
}

/// A frame header of `HEADER_LEN` bytes filled with `fill`, whose wire slot, bytes 56 and 57, is `slot`.
fn frame_header(fill: u8, slot: u16) -> Vec<u8> {
    let mut header = vec![fill; crate::net::HEADER_LEN];
    header[56..58].copy_from_slice(&slot.to_be_bytes());
    header
}

/// How a call's build loop ended: every datagram up to the limit built, or the first unbuilt one met validation, a missing IOVA, the header pool's free count or the descriptor stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    Whole,
    Unsendable,
    Iova,
    Headers,
    Descriptors,
}

/// The prefix one call builds, as the transmit contract defines it from the pre-call counts.
#[derive(Clone, Copy, Debug)]
struct Prefix {
    built: usize,
    stop: Stop,
    /// The stopping datagram already had a descriptor for a later piece when the stack ran short.
    after_take: bool,
    /// The stopping datagram had a fully built segment when a missing IOVA stopped it.
    after_segment: bool,
}

/// The model of what `transmit` builds from `plans` under `limit` chains, `free` free header buffers and `top` free descriptors: datagrams in order, each whole or not at all. A datagram stops the prefix when validation refuses it (an unknown peer, inline bytes after a retained piece, more segments than `segments`, a head past `room`, a total past `u16::MAX`), when no header buffer is left, or when, walking its retained pieces back to front, the stack is empty or a piece's source has no registered IOVA. `unregistered` reports whether a driver source slot's current buffer has no registered IOVA.
fn model_prefix(
    plans: &[Plan],
    limit: usize,
    (free, top): (u32, u32),
    (segments, room, peers): (u16, usize, usize),
    unregistered: &dyn Fn(usize) -> bool,
) -> Prefix {
    let (mut headers, mut descriptors) = (0u32, 0u32);
    for (at, plan) in plans.iter().take(limit).enumerate() {
        let stop = |stop, after_take, after_segment| Prefix {
            built: at,
            stop,
            after_take,
            after_segment,
        };
        let mut retained = 0;
        let mut head = FRAME_OVERHEAD + plan.header.len();
        let mut total = head;
        let mut order = true;
        for piece in &plan.pieces {
            match piece {
                Piece::Inline(bytes) if retained > 0 && !bytes.is_empty() => order = false,
                Piece::Inline(bytes) => {
                    head += bytes.len();
                    total += bytes.len();
                }
                Piece::Retained { range, .. } => {
                    retained += 1;
                    total += range.len();
                }
                Piece::Empty => {}
            }
        }
        if usize::from(plan.peer) >= peers
            || !order
            || retained + 1 > usize::from(segments)
            || head > room
            || total > usize::from(u16::MAX)
        {
            return stop(Stop::Unsendable, false, false);
        }
        if headers + 1 > free {
            return stop(Stop::Headers, false, false);
        }
        let mut taken = 0;
        for piece in plan.pieces.iter().rev() {
            let Piece::Retained { slot, .. } = piece else {
                continue;
            };
            if descriptors + taken + 1 > top {
                return stop(Stop::Descriptors, taken > 0, false);
            }
            if unregistered(*slot) {
                return stop(Stop::Iova, false, taken > 0);
            }
            taken += 1;
        }
        headers += 1;
        descriptors += taken;
    }
    Prefix {
        built: plans.len().min(limit),
        stop: Stop::Whole,
        after_take: false,
        after_segment: false,
    }
}

/// One segment as the probe at prepare entry saw it.
#[derive(Clone, Debug)]
struct SegmentSeen {
    mbuf: *mut sys::rte_mbuf,
    bytes: Vec<u8>,
    data_off: u16,
    data_len: u16,
    pkt_len: u32,
    nb_segs: u16,
    refcnt: u16,
    ol_flags: u64,
    tx_offload: u64,
    buf_addr: usize,
    buf_iova: u64,
    token: (u16, u32, u64, bool),
}

/// One prepare call as its entry probe saw it: each chain's segments, the header pool's application count, the descriptor top, and the incarnations of the header and source buffers.
#[derive(Clone, Debug, Default)]
struct PrepareSeen {
    chains: Vec<Vec<SegmentSeen>>,
    header_application: u32,
    top: u32,
    header_incarnations: Vec<u64>,
    source_incarnations: Vec<u64>,
}

/// Installs a probe on `f`'s port that records every prepare's entry state.
fn probe(f: &mut Fixture) -> std::rc::Rc<std::cell::RefCell<Vec<PrepareSeen>>> {
    let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let log = seen.clone();
    let (arena, payload) = (f.arena, f.payload.state);
    f.burst.port_mut().probe = Some(Box::new(move |packets: &[*mut sys::rte_mbuf]| {
        let chains = packets
            .iter()
            .map(|&head| {
                let mut segments = Vec::new();
                let mut at = head;
                while !at.is_null() {
                    // SAFETY: the chain is one the burst logic built and passes to prepare; nothing writes it during the probe.
                    let segment = unsafe {
                        let m = &*at;
                        SegmentSeen {
                            mbuf: at,
                            bytes: bytes(at),
                            data_off: m.__bindgen_anon_1.__bindgen_anon_1.data_off,
                            data_len: m.__bindgen_anon_2.__bindgen_anon_1.data_len,
                            pkt_len: m.__bindgen_anon_2.__bindgen_anon_1.pkt_len,
                            nb_segs: m.__bindgen_anon_1.__bindgen_anon_1.nb_segs,
                            refcnt: m.__bindgen_anon_1.__bindgen_anon_1.refcnt,
                            ol_flags: m.ol_flags,
                            tx_offload: m.__bindgen_anon_3.tx_offload,
                            buf_addr: m.buf_addr.addr(),
                            buf_iova: m.buf_iova,
                            token: super::mempool::Token::read(at),
                        }
                    };
                    segments.push(segment);
                    // SAFETY: as above.
                    at = unsafe { (*at).next };
                }
                segments
            })
            .collect();
        log.borrow_mut().push(PrepareSeen {
            chains,
            header_application: arena.report(PoolKind::PacketHeader).application,
            top: payload.free_descriptors(),
            header_incarnations: arena
                .pools()
                .snapshot(PoolKind::PacketHeader)
                .into_iter()
                .map(|(_, incarnation)| incarnation)
                .collect(),
            source_incarnations: arena
                .pools()
                .snapshot(PoolKind::ReadResponse)
                .into_iter()
                .map(|(_, incarnation)| incarnation)
                .collect(),
        });
    }));
    seen
}

/// The coverage witnesses the characterization driver must fire, in order, each with the bit mask of its parts that must all fire.
const WITNESSES: [(&str, u8); 15] = [
    (
        "C1 a descriptor shortfall met a datagram that already held a descriptor, after a built prefix",
        1,
    ),
    (
        "C2 a descriptor the device returned was taken again by the next send",
        1,
    ),
    (
        "C3 the device returned a reference while the owner held the source, and the owner dropped a source the device still read",
        0b11,
    ),
    (
        "C4 the header pool refused with descriptors free, after a built prefix",
        1,
    ),
    (
        "C5 an uncertain post with some accepted and one with none accepted",
        0b11,
    ),
    ("C6 prepare passed a nonempty strict prefix", 1),
    (
        "C7 one built batch mixed 0-, 1- and 2-piece datagrams over several peers with distinct bytes and sources",
        1,
    ),
    (
        "C8 a missing IOVA stopped a non-leading datagram after one of its segments was built",
        1,
    ),
    (
        "C9 single returns held after the device returned a re-taken descriptor",
        1,
    ),
    ("C10 a batch past the chain capacity built every chain", 1),
    (
        "C11 reconciliation counted a chain the device returned before the stop, and released one locally",
        0b11,
    ),
    (
        "C12 a send while poisoned and a send with the link not up",
        0b11,
    ),
    (
        "C13 prepare received an empty slice, and prepare refused a nonempty build entirely",
        0b11,
    ),
    (
        "C14 a header buffer was acquired and released within one call because a segment failed to build",
        1,
    ),
    (
        "C15 the quarantine record saw no token because the device returned the chain inside the burst",
        1,
    ),
];

/// One segment the model believes the device or the quarantine holds: its mbuf, and for a payload descriptor the source buffer index the plan gave it.
#[derive(Clone, Copy, Debug)]
struct Live {
    mbuf: *mut sys::rte_mbuf,
    source: Option<usize>,
}

/// Where the model believes the quarantined chain is.
#[derive(Clone, Debug)]
enum Quarantine {
    None,
    /// The device took the chain headed by this mbuf; the held and queued sets say whether it still holds it.
    Device(*mut sys::rte_mbuf),
    /// Only the burst logic's record holds it, so a proven stop releases it locally.
    Burst(Vec<Live>),
}

/// The port's knobs for one send.
#[derive(Clone, Copy, Debug)]
struct Knobs {
    prepare: usize,
    accept: usize,
    uncertain: bool,
    retain: bool,
    free: bool,
}

impl Knobs {
    const OPEN: Self = Self {
        prepare: usize::MAX,
        accept: usize::MAX,
        uncertain: false,
        retain: true,
        free: false,
    };
}

/// The pools' counts and every report a call may move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Counts {
    header: BufferPoolReport,
    sources: BufferPoolReport,
    top: u32,
    header_ops: super::mempool::OpsReport,
    payload_ops: super::mempool::OpsReport,
    report: super::burst::BurstReport,
}

/// The characterization driver over the mock port: a fixture, a test-side model of every object the device, the quarantine and the test hold, and the coverage witnesses. Every check runs at a call's return or a device return, plus the probe at prepare entry.
struct Driver {
    f: Fixture,
    sizing: Sizing,
    seen: std::rc::Rc<std::cell::RefCell<Vec<PrepareSeen>>>,
    wire: Wire<'static>,
    /// Owner source handles by slot; a dropped slot is `None`.
    sources: Vec<Option<Buffer<'static>>>,
    /// The source buffer index whose IOVA the registration does not translate.
    refused: Option<usize>,
    /// Header buffers and payload descriptors the test itself holds, as pressure.
    headers_held: Vec<Buffer<'static>>,
    descriptors_held: Vec<*mut std::ffi::c_void>,
    /// The port's held chains, in the port's order, and the segments it queued to return apart.
    held: Vec<Vec<Live>>,
    queued: Vec<Live>,
    quarantine: Quarantine,
    /// Header high-water bounds over observations: built chains alone, and with each call's transient allowance.
    high_low: u32,
    high_high: u32,
    /// Descriptors the device returned since the last send, and those a send took again since.
    returned: std::collections::HashSet<usize>,
    retaken: std::collections::HashSet<usize>,
    fired: [u8; WITNESSES.len()],
    rng: u64,
}

/// `plans` as datagrams over the driver's `sources`.
fn outgoing<'b>(
    plans: &'b [Plan],
    sources: &'b [Option<Buffer<'static>>],
) -> Vec<Outgoing<'b, 'static>> {
    plans
        .iter()
        .map(|plan| Outgoing {
            peer: PeerId(plan.peer),
            header: &plan.header,
            payload: plan.pieces.each_ref().map(|piece| match piece {
                Piece::Empty => Payload::EMPTY,
                Piece::Inline(bytes) => Payload::Inline(bytes),
                Piece::Retained { slot, range } => Payload::Retained(
                    sources[*slot]
                        .as_ref()
                        .expect("a planned source is live")
                        .source(range.clone())
                        .expect("a planned range lies in its source"),
                ),
            }),
        })
        .collect()
}

impl Driver {
    fn new(sizing: Sizing, refused: Option<usize>, seed: u64) -> Self {
        let mut f = sized(sizing, refused);
        let seen = probe(&mut f);
        f.burst.port_mut().held.reserve(256);
        f.burst.port_mut().segment_returns.reserve(256);
        let mut driver = Self {
            f,
            sizing,
            seen,
            wire: Wire::new(SPREAD_LOCAL, &SPREAD_PEERS, &mut EngineBudget::unlimited()).unwrap(),
            sources: Vec::new(),
            refused,
            headers_held: Vec::new(),
            descriptors_held: Vec::new(),
            held: Vec::new(),
            queued: Vec::new(),
            quarantine: Quarantine::None,
            high_low: 0,
            high_high: 0,
            returned: Default::default(),
            retaken: Default::default(),
            fired: [0; WITNESSES.len()],
            rng: seed,
        };
        for slot in 0..sizing.sources as usize {
            driver.sources.push(None);
            driver.refill(slot);
        }
        driver
    }

    fn next(&mut self) -> u64 {
        // SplitMix64, so each seed replays one history.
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    /// Records part `part` of witness `witness`, numbered from 1 as `WITNESSES` labels them.
    fn fire(&mut self, witness: usize, part: u8) {
        self.fired[witness - 1] |= 1 << part;
    }

    /// The parts of witness `witness` that fired, numbered from 1 as `fire` takes it.
    fn fired(&self, witness: usize) -> u8 {
        self.fired[witness - 1]
    }

    /// Asserts every witness fired every part.
    fn assert_witnessed(&self) {
        for (at, (name, parts)) in WITNESSES.iter().enumerate() {
            assert_eq!(
                self.fired[at] & parts,
                *parts,
                "witness never fired: {name}"
            );
        }
    }

    /// Acquires a source into empty slot `slot`, filled with bytes that depend on the slot and a fresh draw.
    fn refill(&mut self, slot: usize) {
        let draw = self.next() as usize;
        if let Ok(mut buffer) = self.f.arena.acquire(PoolKind::ReadResponse) {
            for (at, byte) in buffer.bytes_mut().iter_mut().enumerate() {
                *byte = draw.wrapping_add(at * 31 + slot * 7) as u8;
            }
            self.sources[slot] = Some(buffer);
        }
    }

    /// Drops the owner's handle in `slot`.
    fn drop_source(&mut self, slot: usize) {
        let Some(buffer) = self.sources[slot].take() else {
            return;
        };
        let index = buffer.index();
        if self.live().iter().any(|seg| seg.source == Some(index)) {
            self.fire(3, 1);
        }
        drop(buffer);
        self.check_census("after an owner drop");
    }

    fn source_index(&self, slot: usize) -> usize {
        self.sources[slot]
            .as_ref()
            .expect("a planned source is live")
            .index()
    }

    fn counts(&self) -> Counts {
        Counts {
            header: self.f.arena.report(PoolKind::PacketHeader),
            sources: self.f.arena.report(PoolKind::ReadResponse),
            top: self.f.payload.state.free_descriptors(),
            header_ops: self.f.header.state.report(),
            payload_ops: self.f.payload.state.report(),
            report: self.f.burst.report(),
        }
    }

    /// Every segment the model believes the device or the quarantine holds.
    fn live(&self) -> Vec<Live> {
        let mut live: Vec<Live> = self.held.iter().flatten().copied().collect();
        live.extend(self.queued.iter().copied());
        if let Quarantine::Burst(chain) = &self.quarantine {
            live.extend(chain.iter().copied());
        }
        live
    }

    /// The model's free header buffers and free descriptors.
    fn model_free(&self) -> (u32, u32) {
        let live = self.live();
        let headers = live.iter().filter(|seg| seg.source.is_none()).count() as u32;
        let descriptors = live.len() as u32 - headers;
        (
            self.sizing.headers - headers - self.headers_held.len() as u32,
            self.sizing.descriptors - descriptors - self.descriptors_held.len() as u32,
        )
    }

    /// Checks the pools against the model and every return single.
    fn check_census(&self, at: &str) {
        let live = self.live();
        let (free, top) = self.model_free();
        let header = self.f.arena.report(PoolKind::PacketHeader);
        let device = live.iter().filter(|seg| seg.source.is_none()).count() as u32;
        let owned = self.headers_held.len() as u32;
        assert_eq!(
            (
                header.free,
                header.application,
                header.nic_held,
                header.retired
            ),
            (free, owned, device, 0),
            "P9 header census {at}"
        );
        assert_eq!(
            self.f.arena.pools().census(PoolKind::PacketHeader),
            [free, owned, 0, 0, 0, device, 0],
            "P9 header census by record {at}"
        );
        assert_eq!(
            self.f.payload.state.free_descriptors(),
            top,
            "P9 descriptor top {at}"
        );
        let count = self.sizing.sources as usize;
        let mut references = vec![0u16; count];
        for seg in &live {
            if let Some(source) = seg.source {
                references[source] += 1;
            }
        }
        let mut counted = Vec::new();
        self.f
            .arena
            .pools()
            .device_counts_into(PoolKind::ReadResponse, &mut counted);
        assert_eq!(counted, references, "P9 source references {at}");
        let owners: std::collections::HashSet<usize> =
            self.sources.iter().flatten().map(Buffer::index).collect();
        let classes: Vec<usize> = self
            .f
            .arena
            .pools()
            .snapshot(PoolKind::ReadResponse)
            .into_iter()
            .map(|(class, _)| class)
            .collect();
        let expected: Vec<usize> = (0..count)
            .map(
                |index| match (owners.contains(&index), references[index] > 0) {
                    (true, _) => 1,
                    (false, true) => 5,
                    (false, false) => 0,
                },
            )
            .collect();
        assert_eq!(classes, expected, "P9 source classes {at}");
        assert_eq!(
            (
                self.f.header.state.report().stray,
                self.f.payload.state.report().stray
            ),
            (0, 0),
            "P4 no stray return {at}"
        );
        assert_eq!(
            (
                header.mismatched,
                self.f.arena.report(PoolKind::ReadResponse).mismatched
            ),
            (0, 0),
            "P4 no mismatched reference {at}"
        );
        assert!(
            (self.high_low..=self.high_high).contains(&header.held_high_water),
            "P9 header high water {} within [{}, {}] {at}",
            header.held_high_water,
            self.high_low,
            self.high_high
        );
    }

    /// Records the header pool's current not-free count as a high-water observation.
    fn observe_high(&mut self) {
        let header = self.f.arena.report(PoolKind::PacketHeader);
        let held = header.count - header.free;
        self.high_low = self.high_low.max(held);
        self.high_high = self.high_high.max(held);
    }

    /// Notes a device return of `seg`.
    fn device_returned(&mut self, seg: Live) {
        let Some(source) = seg.source else {
            return;
        };
        if self.retaken.remove(&seg.mbuf.addr()) {
            self.fire(9, 0);
        }
        self.returned.insert(seg.mbuf.addr());
        if self
            .sources
            .iter()
            .flatten()
            .any(|buffer| buffer.index() == source)
        {
            self.fire(3, 0);
        }
    }

    /// The wire bytes of `plan`'s header segment, and its head and total lengths.
    fn expected_head(&self, plan: &Plan) -> (Vec<u8>, usize, usize) {
        let mut inline = Vec::new();
        let mut retained = 0;
        for piece in &plan.pieces {
            match piece {
                Piece::Inline(bytes) => inline.extend_from_slice(bytes),
                Piece::Retained { range, .. } => retained += range.len(),
                Piece::Empty => {}
            }
        }
        let head = FRAME_OVERHEAD + plan.header.len() + inline.len();
        let total = head + retained;
        let slot = plan
            .header
            .get(56..58)
            .map_or(0, |bytes| u16::from_be_bytes([bytes[0], bytes[1]]));
        let peer = &SPREAD_PEERS[usize::from(plan.peer)];
        let mut headers = [0; FRAME_OVERHEAD];
        self.wire.encode(
            &mut headers,
            peer,
            SPREAD_LOCAL.port + slot % SPREAD_LOCAL.ports,
            peer.port,
            (total - FRAME_OVERHEAD) as u16,
        );
        ([&headers[..], &plan.header, &inline].concat(), head, total)
    }

    /// Checks that `chain`, as prepare saw it, encodes `plan` and carries one armed token per segment naming its own buffer's current incarnation.
    fn check_chain(&self, plan: &Plan, chain: &[SegmentSeen], entry: &PrepareSeen) {
        let retained: Vec<(usize, std::ops::Range<usize>)> = plan
            .pieces
            .iter()
            .filter_map(|piece| match piece {
                Piece::Retained { slot, range } => Some((*slot, range.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(
            chain.len(),
            1 + retained.len(),
            "P21 one segment per retained piece"
        );
        let (bytes, head_len, total) = self.expected_head(plan);
        let head = &chain[0];
        assert_eq!(
            head.bytes, bytes,
            "P21 the header segment encodes its datagram"
        );
        assert_eq!(
            (
                head.data_off,
                head.data_len,
                head.pkt_len,
                head.nb_segs,
                head.refcnt
            ),
            (
                sys::RTE_PKTMBUF_HEADROOM as u16,
                head_len as u16,
                total as u32,
                1 + retained.len() as u16,
                1
            ),
            "P21 header fields"
        );
        assert_eq!(
            head.ol_flags,
            sys::RTE_MBUF_F_TX_IPV4 | sys::RTE_MBUF_F_TX_IP_CKSUM | sys::RTE_MBUF_F_TX_UDP_CKSUM
        );
        assert_eq!(head.tx_offload, 14 | 20 << 7 | 8 << 16);
        let index = self
            .f
            .header
            .state
            .index_of(head.mbuf.cast())
            .expect("a chain's head is a header mbuf");
        assert_eq!(
            head.token,
            (
                PoolKind::PacketHeader.index() as u16,
                index,
                entry.header_incarnations[index as usize],
                true
            ),
            "P6 the header token names its own buffer's incarnation"
        );
        for (segment, (slot, range)) in chain[1..].iter().zip(retained) {
            let source = self.sources[slot]
                .as_ref()
                .expect("a planned source is live");
            let len = range.len();
            let addr = source.bytes().as_ptr().addr() + range.start;
            assert_eq!(
                segment.bytes,
                source.bytes()[range].to_vec(),
                "P21 retained bytes in order"
            );
            assert_eq!(
                (
                    segment.data_off,
                    segment.data_len,
                    segment.pkt_len,
                    segment.nb_segs,
                    segment.refcnt,
                    segment.ol_flags
                ),
                (0, len as u16, len as u32, 1, 1, 0),
                "P21 descriptor fields"
            );
            assert_eq!(
                (segment.buf_addr, Some(segment.buf_iova)),
                (addr, iova(addr, len)),
                "P8 the descriptor's address and registered IOVA"
            );
            assert_eq!(
                segment.token,
                (
                    PoolKind::ReadResponse.index() as u16,
                    source.index() as u32,
                    entry.source_incarnations[source.index()],
                    true
                ),
                "P6 the payload token names its source's incarnation"
            );
        }
    }

    /// Sends `plans` with `knobs` set on the port and checks the call against the model: the built prefix, the prepare and burst cadence and the prepare-entry census, every built chain's encoding and tokens, the chains the device accepted, the result variant, the report counters, the pool census after the call, and the inert sends.
    fn send(&mut self, plans: &[Plan], knobs: Knobs) -> Result<usize, DatagramError> {
        {
            let port = self.f.burst.port_mut();
            port.prepare = knobs.prepare;
            port.accept = knobs.accept;
            port.uncertain = knobs.uncertain;
            port.retain_uncertain = knobs.retain;
            port.free_uncertain = knobs.free;
        }
        let before = self.counts();
        let port = self.f.burst.port();
        let (calls, prepares, bursts, segments, prepare_error) = (
            port.calls,
            port.prepares,
            port.bursts,
            port.segments,
            port.prepare_error,
        );
        let (link, poisoned) = (self.f.burst.link(), self.f.burst.poisoned());
        let limit = plans.len().min(self.sizing.batch);
        let (free, top) = self.model_free();
        let room = crate::storage::PacketLayout::of(4096).unwrap().data_room;
        let unregistered: Vec<bool> = (0..self.sources.len())
            .map(|slot| {
                self.sources[slot]
                    .as_ref()
                    .is_some_and(|buffer| self.refused == Some(buffer.index()))
            })
            .collect();
        let prefix = model_prefix(
            plans,
            limit,
            (free, top),
            (segments, room, SPREAD_PEERS.len()),
            &|slot| unregistered[slot],
        );
        self.seen.borrow_mut().clear();
        let outcome = {
            let batch = outgoing(plans, &self.sources);
            self.f.burst.send(&batch)
        };
        let taken = self.f.burst.port_mut().take_accepted();
        if link != Link::Up || poisoned {
            let expected = if link != Link::Up {
                Err(DatagramError::Closed)
            } else {
                Err(DatagramError::Failed {
                    code: Some(libc::EIO),
                })
            };
            assert_eq!(outcome, expected, "P18 an inert send's result");
            assert_eq!(
                self.f.burst.port().calls,
                calls,
                "P18 an inert send calls no port method"
            );
            assert_eq!(
                self.counts(),
                before,
                "P18 an inert send changes no pool or report"
            );
            self.fire(12, u8::from(link != Link::Up));
            return outcome;
        }
        let leading = prefix.built == 0 && matches!(prefix.stop, Stop::Unsendable | Stop::Iova);
        let entry = {
            let mut seen = self.seen.borrow_mut();
            assert_eq!(
                seen.len(),
                usize::from(!leading),
                "P20 one prepare per call past validation"
            );
            seen.pop()
        };
        let port = self.f.burst.port();
        assert_eq!(port.prepares, prepares + u32::from(!leading));
        let mut expected = before.report;
        match prefix.stop {
            Stop::Whole => {}
            Stop::Unsendable | Stop::Iova => expected.unsendable += 1,
            Stop::Headers | Stop::Descriptors => expected.exhausted += 1,
        }
        let built = prefix.built;
        for plan in &plans[..built] {
            let slot = plan
                .header
                .get(56..58)
                .map_or(0, |bytes| u16::from_be_bytes([bytes[0], bytes[1]]));
            expected.sources[usize::from(slot % SPREAD_LOCAL.ports) % 8] += 1;
        }
        let refused = u64::from(prefix.stop == Stop::Descriptors);
        let not_free = before.header.count - before.header.free;
        let allowance = match prefix.stop {
            Stop::Descriptors => 1,
            Stop::Iova => (limit - built) as u32,
            _ => 0,
        };
        self.high_low = self.high_low.max(not_free + built as u32);
        self.high_high = self.high_high.max(not_free + built as u32 + allowance);
        let retained_built: u32 = plans[..built]
            .iter()
            .map(|plan| plan.retained() as u32)
            .sum();
        if prefix.stop == Stop::Descriptors && prefix.after_take && built > 0 {
            self.fire(1, 0);
        }
        if prefix.stop == Stop::Headers && top > retained_built && built > 0 {
            self.fire(4, 0);
        }
        if prefix.stop == Stop::Iova && prefix.after_segment && built > 0 {
            self.fire(8, 0);
        }
        if prefix.stop == Stop::Iova {
            self.fire(14, 0);
        }
        if plans.len() > self.sizing.batch && built == self.sizing.batch {
            self.fire(10, 0);
        }
        let Some(entry) = entry else {
            assert_eq!(
                outcome,
                Err(DatagramError::Failed {
                    code: Some(libc::EINVAL)
                }),
                "P22 a leading unsendable datagram fails the call"
            );
            assert_eq!(
                self.f.burst.port().calls,
                calls,
                "a leading refusal calls no port method"
            );
            expected.sources = before.report.sources;
            let after = self.counts();
            assert_eq!(after.report, expected, "P19 counters of a leading refusal");
            assert_eq!(after.payload_ops.refused, before.payload_ops.refused);
            self.check_census("after a leading refusal");
            return outcome;
        };
        assert_eq!(
            entry.chains.len(),
            built,
            "P1 P16 the built prefix is the model's"
        );
        assert_eq!(
            entry.header_application,
            self.headers_held.len() as u32,
            "P20 at prepare entry no header handle is live outside the chains"
        );
        assert_eq!(
            entry.top,
            top - retained_built,
            "P20 at prepare entry every descriptor outside the built chains is back"
        );
        for (plan, chain) in plans.iter().zip(&entry.chains) {
            self.check_chain(plan, chain, &entry);
        }
        if built == 0 {
            self.fire(13, 0);
        }
        let ready = knobs.prepare.min(built);
        let port = self.f.burst.port();
        assert_eq!(
            port.bursts,
            bursts + u32::from(ready > 0),
            "P20 a burst iff prepare passed a chain"
        );
        if ready > 0 {
            assert_eq!(
                port.burst_len, ready,
                "P20 the burst carries the prepared prefix"
            );
        } else {
            // The mock clears its uncertain flag only inside a burst.
            self.f.burst.port_mut().uncertain = false;
        }
        if ready == 0 && built > 0 {
            self.fire(13, 1);
        }
        if 0 < ready && ready < built {
            self.fire(6, 0);
        }
        let accepted = knobs.accept.min(ready);
        let prefix: Vec<*mut sys::rte_mbuf> = entry.chains[..accepted]
            .iter()
            .map(|chain| chain[0].mbuf)
            .collect();
        assert_eq!(
            taken, prefix,
            "P3 the device accepted exactly the model's prefix, in order"
        );
        let uncertain = knobs.uncertain && accepted < ready;
        let expected_outcome = if ready == 0 && built > 0 {
            Err(DatagramError::Failed {
                code: Some(prepare_error),
            })
        } else {
            Ok(accepted)
        };
        assert_eq!(outcome, expected_outcome, "P22 the result variant");
        expected.sent += accepted as u64;
        let first = accepted + usize::from(uncertain);
        expected.ring_full += (ready - first) as u64;
        expected.prepare_refused += u64::from(ready < built);
        expected.quarantined += u64::from(uncertain);
        let after = self.counts();
        assert_eq!(after.report, expected, "P19 the call's counters");
        assert_eq!(
            after.payload_ops.refused,
            before.payload_ops.refused + refused,
            "P19 a descriptor shortfall counts one refused dequeue per call"
        );
        assert_eq!(after.header_ops.refused, before.header_ops.refused);
        let chains: Vec<Vec<Live>> = entry
            .chains
            .iter()
            .zip(plans)
            .map(|(chain, plan)| {
                let mut sources = plan.pieces.iter().filter_map(|piece| match piece {
                    Piece::Retained { slot, .. } => Some(self.source_index(*slot)),
                    _ => None,
                });
                chain
                    .iter()
                    .enumerate()
                    .map(|(at, seg)| Live {
                        mbuf: seg.mbuf,
                        source: if at == 0 { None } else { sources.next() },
                    })
                    .collect()
            })
            .collect();
        for seg in chains.iter().flatten() {
            if seg.source.is_some() && self.returned.contains(&seg.mbuf.addr()) {
                self.fire(2, 0);
                self.retaken.insert(seg.mbuf.addr());
            }
        }
        self.returned.clear();
        if self.mixes_every_shape(&plans[..built]) {
            self.fire(7, 0);
        }
        self.held.extend(chains[..accepted].iter().cloned());
        if uncertain {
            self.fire(5, u8::from(accepted == 0));
            let chain = chains[accepted].clone();
            if knobs.free {
                self.fire(15, 0);
                for seg in &chain {
                    self.device_returned(*seg);
                }
                self.quarantine = Quarantine::Device(chain[0].mbuf);
            } else if knobs.retain {
                self.quarantine = Quarantine::Device(chain[0].mbuf);
                self.held.push(chain);
            } else {
                self.quarantine = Quarantine::Burst(chain);
            }
        }
        self.check_census("after a send");
        outcome
    }

    /// Whether `built` mixes 0-, 1- and 2-piece datagrams over at least two peers, with distinct frame headers, distinct inline bytes and no source shared between datagrams.
    fn mixes_every_shape(&self, built: &[Plan]) -> bool {
        let pieces: std::collections::HashSet<usize> = built.iter().map(Plan::retained).collect();
        let peers: std::collections::HashSet<u16> = built.iter().map(|plan| plan.peer).collect();
        let headers: std::collections::HashSet<&[u8]> =
            built.iter().map(|plan| plan.header.as_slice()).collect();
        let inline: Vec<&[u8]> = built
            .iter()
            .flat_map(|plan| &plan.pieces)
            .filter_map(|piece| match piece {
                Piece::Inline(bytes) if !bytes.is_empty() => Some(bytes.as_slice()),
                _ => None,
            })
            .collect();
        let distinct_inline = inline
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            == inline.len();
        let mut seen = std::collections::HashSet::new();
        let disjoint = built.iter().all(|plan| {
            let own: std::collections::HashSet<usize> = plan
                .pieces
                .iter()
                .filter_map(|piece| match piece {
                    Piece::Retained { slot, .. } => Some(self.source_index(*slot)),
                    _ => None,
                })
                .collect();
            own.iter().all(|index| seen.insert(*index))
        });
        pieces.len() == 3
            && peers.len() >= 2
            && headers.len() == built.len()
            && !inline.is_empty()
            && distinct_inline
            && disjoint
    }

    /// One reclaim turn, checked against the model: cleanup runs exactly while the link is up, the device is running, the transport is not poisoned and a header buffer is held or a payload descriptor is out, its returns release their own segments, and a recovery's proven stop returns everything the device held and settles the quarantine once.
    fn reclaim(&mut self) {
        let before = self.counts();
        let port = self.f.burst.port();
        let (cleanups, reset, (_, frees)) = (port.cleanups, port.reset, port.cleanup);
        let (link, poisoned) = (self.f.burst.link(), self.f.burst.poisoned());
        let recovers = link == Link::Up && (reset || poisoned);
        let cleans = link == Link::Up
            && !recovers
            && (before.header.count - before.header.free - before.header.retired > 0
                || before.top < self.sizing.descriptors);
        self.f.burst.reclaim();
        assert_eq!(
            self.f.burst.port().cleanups,
            cleanups + u32::from(cleans),
            "P15 cleanup runs exactly while a header buffer is held or a payload descriptor is out on a healthy link"
        );
        let mut expected = before.report;
        if cleans {
            if !self.queued.is_empty() {
                let seg = self.queued.remove(0);
                self.device_returned(seg);
            }
            for _ in 0..frees.min(self.held.len()) {
                for seg in self.held.remove(0) {
                    self.device_returned(seg);
                }
            }
        }
        if recovers {
            let held_at_stop: Vec<*mut sys::rte_mbuf> = self
                .held
                .iter()
                .map(|chain| chain[0].mbuf)
                .chain(
                    self.queued
                        .iter()
                        .filter(|seg| seg.source.is_none())
                        .map(|seg| seg.mbuf),
                )
                .collect();
            for seg in std::mem::take(&mut self.held).into_iter().flatten() {
                self.device_returned(seg);
            }
            for seg in std::mem::take(&mut self.queued) {
                self.device_returned(seg);
            }
            match std::mem::replace(&mut self.quarantine, Quarantine::None) {
                Quarantine::None => {}
                Quarantine::Device(head) => {
                    expected.quarantine_returned += 1;
                    if !held_at_stop.contains(&head) {
                        self.fire(11, 0);
                    }
                }
                Quarantine::Burst(_) => {
                    expected.quarantine_released += 1;
                    self.fire(11, 1);
                }
            }
            expected.resets += 1;
            expected.recoveries += 1;
            let after = self.f.burst.report();
            expected.episode = after.episode;
            expected.pause_us = after.pause_us;
            assert_eq!(
                self.f.burst.link(),
                Link::Up,
                "a proven stop recovers in place"
            );
        }
        assert_eq!(
            self.f.burst.report(),
            expected,
            "P17 a reclaim turn's counters"
        );
        self.check_census("after a reclaim");
    }

    /// Moves held chain `at` to the queue whose segments return one per cleanup.
    fn return_apart(&mut self, at: usize) {
        self.f.burst.port_mut().return_apart(at);
        let chain = self.held.remove(at);
        self.queued.extend(chain);
    }

    /// Returns every chain and queued segment the device holds.
    fn complete(&mut self) {
        self.f.burst.port_mut().complete();
        for seg in std::mem::take(&mut self.held).into_iter().flatten() {
            self.device_returned(seg);
        }
        for seg in std::mem::take(&mut self.queued) {
            self.device_returned(seg);
        }
        self.check_census("after the device completed");
    }

    /// A random datagram plan; one in forty names an unknown peer and one in forty puts inline bytes after a retained piece.
    fn plan(&mut self, tag: usize) -> Plan {
        let peer = if self.below(40) == 0 {
            7
        } else {
            self.below(3) as u16
        };
        let header = if self.below(12) == 0 {
            vec![self.next() as u8; 40]
        } else {
            let fill = self.next() as u8;
            frame_header(fill, self.next() as u16)
        };
        let inline = |d: &mut Self| {
            let len = 1 + d.below(48);
            let fill = d.next() as u8;
            Piece::Inline(
                (0..len)
                    .map(|at| fill.wrapping_add(at as u8).wrapping_add(tag as u8))
                    .collect(),
            )
        };
        let retained = |d: &mut Self| {
            let live: Vec<usize> = (0..d.sources.len())
                .filter(|&slot| d.sources[slot].is_some())
                .collect();
            if live.is_empty() {
                return Piece::Empty;
            }
            let slot = live[d.below(live.len())];
            let start = d.below(SOURCE_LEN - 1);
            let len = 1 + d.below(4000.min(SOURCE_LEN - start));
            Piece::Retained {
                slot,
                range: start..start + len,
            }
        };
        let pieces = match self.below(40) {
            0 => [retained(self), inline(self)],
            1..=5 => [Piece::Empty, Piece::Empty],
            6..=11 => [inline(self), Piece::Empty],
            12..=19 => [retained(self), Piece::Empty],
            20..=24 => [inline(self), retained(self)],
            25..=26 => [Piece::Empty, retained(self)],
            _ => [retained(self), retained(self)],
        };
        Plan {
            peer,
            header,
            pieces,
        }
    }

    /// Random port knobs for a send of `n` datagrams.
    fn knobs(&mut self, n: usize) -> Knobs {
        let accept = if self.below(2) == 0 {
            usize::MAX
        } else {
            self.below(n + 1)
        };
        let prepare = if self.below(7) == 0 {
            self.below(n + 1)
        } else {
            usize::MAX
        };
        let mode = self.below(3);
        Knobs {
            prepare,
            accept,
            uncertain: self.below(8) == 0,
            retain: mode == 0,
            free: mode == 1,
        }
    }

    /// One random step of the history.
    fn step(&mut self) {
        match self.below(24) {
            0..=8 => {
                let n = match self.below(10) {
                    0 => 0,
                    1 => self.sizing.batch + 1 + self.below(4),
                    _ => 1 + self.below(self.sizing.batch),
                };
                let plans: Vec<Plan> = (0..n).map(|tag| self.plan(tag)).collect();
                let knobs = self.knobs(n);
                let _ = self.send(&plans, knobs);
            }
            9..=10 => {
                let frees = self.below(3);
                self.f.burst.port_mut().cleanup = (self.below(3) as i32 - 1, frees);
                self.reclaim();
            }
            11..=12 => {
                if !self.held.is_empty() {
                    let at = self.below(self.held.len());
                    self.return_apart(at);
                }
                self.f.burst.port_mut().cleanup = (0, 0);
                self.reclaim();
            }
            13 => self.complete(),
            14 => {
                let slot = self.below(self.sources.len());
                self.drop_source(slot);
            }
            15 => {
                if let Some(slot) =
                    (0..self.sources.len()).find(|&slot| self.sources[slot].is_none())
                {
                    self.refill(slot);
                    self.check_census("after a refill");
                }
            }
            16 => {
                for _ in 0..1 + self.below(4) {
                    if let Ok(buffer) = self.f.arena.pools().acquire(PoolKind::PacketHeader) {
                        self.headers_held.push(buffer);
                    }
                }
                self.observe_high();
                self.check_census("after header pressure");
            }
            17 => {
                let keep = self.below(self.headers_held.len() + 1);
                self.headers_held.truncate(keep);
                self.check_census("after header pressure ends");
            }
            18 => {
                let (_, top) = self.model_free();
                let n = self.below(top.min(8) as usize + 1);
                let mut slots = vec![std::mem::MaybeUninit::uninit(); n];
                if n > 0 {
                    assert!(self.f.payload.state.take(&mut slots));
                    // SAFETY: a successful take wrote every slot.
                    self.descriptors_held
                        .extend(slots.into_iter().map(|slot| unsafe { slot.assume_init() }));
                }
                self.check_census("after descriptor pressure");
            }
            19 => {
                let keep = self.below(self.descriptors_held.len() + 1);
                for descriptor in self.descriptors_held.split_off(keep) {
                    // SAFETY: the test took the descriptor and no device saw it.
                    unsafe { self.f.payload.state.give_back(descriptor) };
                }
                self.check_census("after descriptor pressure ends");
            }
            20 => {
                self.f.burst.port_mut().reset = true;
                self.reclaim();
            }
            _ => {
                if self.f.burst.poisoned() {
                    let plan = self.plan(0);
                    let _ = self.send(&[plan], Knobs::OPEN);
                    self.reclaim();
                } else {
                    let n = 2 + self.below(self.sizing.batch - 1);
                    let plans: Vec<Plan> = (0..n).map(|tag| self.plan(tag)).collect();
                    let knobs = Knobs {
                        uncertain: true,
                        accept: self.below(n),
                        ..self.knobs(n)
                    };
                    let _ = self.send(&plans, knobs);
                }
            }
        }
    }

    /// Ends the history: settles any quarantine, lets the device return everything, ends every owner handle and test hold, and asserts quiescence; then loses the link and checks a send reports the transport closed.
    fn finish(&mut self) {
        self.quiesce();
        self.lose_link();
    }

    /// Settles any quarantine, lets the device return everything, ends every owner handle and test hold, and asserts every header buffer, descriptor and source free with every return single.
    fn quiesce(&mut self) {
        if self.f.burst.poisoned() {
            self.reclaim();
        }
        self.complete();
        for slot in 0..self.sources.len() {
            self.drop_source(slot);
        }
        self.headers_held.clear();
        for descriptor in std::mem::take(&mut self.descriptors_held) {
            // SAFETY: the test took the descriptor and no device saw it.
            unsafe { self.f.payload.state.give_back(descriptor) };
        }
        self.check_census("at quiescence");
        let header = self.f.arena.report(PoolKind::PacketHeader);
        assert_eq!(
            header.free, header.count,
            "quiescence: every header buffer is free"
        );
        assert_eq!(
            self.f.payload.state.free_descriptors(),
            self.sizing.descriptors,
            "quiescence: no descriptor is outstanding"
        );
        assert_eq!(
            self.f.arena.report(PoolKind::ReadResponse).free,
            self.sizing.sources,
            "quiescence: every source is free"
        );
    }

    /// Loses the link through an unproven stop, then checks that a send reports the transport closed and changes nothing.
    fn lose_link(&mut self) {
        let port = self.f.burst.port_mut();
        port.proven_stops = port.stops;
        port.reset = true;
        self.f.burst.reclaim();
        assert_eq!(self.f.burst.link(), Link::Lost);
        let plan = Plan {
            peer: 0,
            header: frame_header(1, 0),
            pieces: [Piece::Empty, Piece::Empty],
        };
        let _ = self.send(&[plan], Knobs::OPEN);
    }
}

/// The driver's sizing: pools small enough that held chains and test pressure exhaust them, a batch of eight.
const DRIVEN: Sizing = Sizing {
    sources: 12,
    headers: 24,
    descriptors: 24,
    batch: 8,
};

/// Seeded histories of sends, device returns in and out of order, owner drops, header and descriptor pressure, uncertain posts, prepare refusals and recoveries, each call checked against a test-side model of every live handle and built chain, ending at quiescence with every header buffer, descriptor and source free; every coverage witness fires in every run.
///
/// The mock device returns each segment through its own pool's ops, so the real device's return routing stays
/// outside this test.
#[test]
fn seeded_transmit_histories_match_the_custody_model() {
    for seed in [0x1101, 0x51ED_0001, 0xB0A7_F00D] {
        let mut driver = Driver::new(DRIVEN, Some(0), seed);
        for step in 0..1500 {
            let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| driver.step()));
            if let Err(panic) = ran {
                eprintln!("seeded transmit history failed at seed {seed:#x} step {step}");
                std::panic::resume_unwind(panic);
            }
        }
        driver.finish();
        driver.assert_witnessed();
    }
}

/// Bytes `start..start + len` of the driver's source slot `slot`, as a retained piece.
fn piece(slot: usize, start: usize, len: usize) -> Piece {
    Piece::Retained {
        slot,
        range: start..start + len,
    }
}

/// A datagram to peer `peer` whose frame header is filled with `tag` and names wire slot `tag`.
fn plan_of(tag: u8, peer: u16, pieces: [Piece; 2]) -> Plan {
    Plan {
        peer,
        header: frame_header(tag, u16::from(tag)),
        pieces,
    }
}

/// Eight two-piece datagrams over fifteen free descriptors and ample header buffers build seven whole: the eighth's shortfall after its back piece's take ends the prefix, counts one pressure stop and one refused dequeue, and leaves the eighth holding no header buffer, descriptor or reference. The refused count is read before any probe that takes descriptors.
#[test]
fn a_descriptor_shortfall_after_a_built_prefix_builds_the_longest_whole_prefix() {
    let sizing = Sizing {
        sources: 8,
        headers: 16,
        descriptors: 15,
        batch: 8,
    };
    let mut d = Driver::new(sizing, None, 1);
    let plans: Vec<Plan> = (0..8)
        .map(|at| {
            plan_of(
                at as u8,
                0,
                [piece(at, 0, 100), piece((at + 1) % 8, 200, 50)],
            )
        })
        .collect();
    let before = d.counts();
    assert_eq!(d.send(&plans, Knobs::OPEN), Ok(7));
    let after = d.counts();
    assert_eq!(after.report.exhausted, before.report.exhausted + 1);
    assert_eq!(
        after.payload_ops.refused,
        before.payload_ops.refused + 1,
        "P19 one refused dequeue for the call the shortfall ended"
    );
    assert_eq!(
        sizing.descriptors - after.top,
        14,
        "P1 the seven chains' descriptors are out"
    );
    assert_eq!(d.f.burst.port().held.len(), 7);
    assert_eq!(
        after.header.nic_held, 7,
        "P2 the eighth holds no header buffer"
    );
    assert_eq!(d.fired(1), 1, "C1 fired");
    d.quiesce();
}

/// Eight one-piece datagrams with three header buffers free and ample descriptors build three: the header pool's refusal ends the prefix, counts one pressure stop and no refused dequeue, and no descriptor is out for datagrams four to eight.
#[test]
fn a_header_shortfall_after_a_built_prefix_takes_no_descriptor_for_the_rest() {
    let sizing = Sizing {
        sources: 8,
        headers: 8,
        descriptors: 16,
        batch: 8,
    };
    let mut d = Driver::new(sizing, None, 2);
    for _ in 0..5 {
        let buffer = d.f.arena.pools().acquire(PoolKind::PacketHeader).unwrap();
        d.headers_held.push(buffer);
    }
    d.observe_high();
    let plans: Vec<Plan> = (0..8)
        .map(|at| plan_of(at as u8, 0, [piece(at, 0, 64), Piece::Empty]))
        .collect();
    let before = d.counts();
    assert_eq!(d.send(&plans, Knobs::OPEN), Ok(3));
    let after = d.counts();
    assert_eq!(after.report.exhausted, before.report.exhausted + 1);
    assert_eq!(
        after.payload_ops.refused, before.payload_ops.refused,
        "P19 a header shortfall refuses no dequeue"
    );
    assert_eq!(
        sizing.descriptors - after.top,
        3,
        "P2 only the three built chains hold descriptors"
    );
    assert_eq!(d.fired(4), 1, "C4 fired");
    d.quiesce();
}

/// Sixty-four datagrams mixing zero, one and two retained pieces over three peers, each with its own frame header, inline bytes and sources, of which the port accepts forty: the forty chains each encode their datagram, the header pool holds exactly forty, the descriptors out are exactly the forty's retained pieces, and no return is stray.
#[test]
fn a_mixed_full_round_holds_exactly_the_accepted_chains() {
    let sizing = Sizing {
        sources: 72,
        headers: 80,
        descriptors: 160,
        batch: 64,
    };
    let mut d = Driver::new(sizing, None, 3);
    let mut next = 0;
    let plans: Vec<Plan> = (0..64)
        .map(|at| {
            let mut slot = || {
                next += 1;
                next - 1
            };
            let pieces = match at % 3 {
                0 => [Piece::Inline(vec![at as u8; 1 + at % 5]), Piece::Empty],
                1 => [piece(slot(), at, 100 + at), Piece::Empty],
                _ => [piece(slot(), 0, 300), piece(slot(), at * 3, 77)],
            };
            plan_of(at as u8, (at % 3) as u16, pieces)
        })
        .collect();
    let knobs = Knobs {
        accept: 40,
        ..Knobs::OPEN
    };
    assert_eq!(d.send(&plans, knobs), Ok(40));
    let retained: u32 = plans[..40].iter().map(|plan| plan.retained() as u32).sum();
    assert_eq!(
        held(d.f.arena, PoolKind::PacketHeader),
        40,
        "P3 the header pool holds exactly the accepted chains"
    );
    assert_eq!(
        sizing.descriptors - d.f.payload.state.free_descriptors(),
        retained,
        "P9 the descriptors out are the accepted chains' pieces"
    );
    assert_eq!(d.fired(7), 1, "C7 fired");
    d.quiesce();
}

/// The third chain's segments return before the first's, one segment per cleanup, and a send re-takes exactly those descriptors by identity: each returned once with no stray or mismatched return, each re-taken descriptor's token disarmed at its take and armed once by the new chain, and each returned once again.
#[test]
fn descriptors_returned_out_of_order_are_retaken_and_returned_once() {
    let sizing = Sizing {
        sources: 8,
        headers: 8,
        descriptors: 6,
        batch: 8,
    };
    let mut d = Driver::new(sizing, None, 4);
    let two = |at: usize| plan_of(at as u8, 0, [piece(at, 0, 100), piece(at + 3, 100, 100)]);
    assert_eq!(d.send(&[two(0), two(1), two(2)], Knobs::OPEN), Ok(3));
    let returning: Vec<usize> = [&d.held[2], &d.held[0]]
        .into_iter()
        .flatten()
        .filter(|seg| seg.source.is_some())
        .map(|seg| seg.mbuf.addr())
        .collect();
    d.return_apart(2);
    d.return_apart(0);
    for _ in 0..6 {
        d.f.burst.port_mut().cleanup = (0, 0);
        d.reclaim();
    }
    assert!(d.queued.is_empty(), "one segment returned per cleanup");
    for &descriptor in &returning {
        // SAFETY: a descriptor the device returned, which nothing writes now.
        let (.., armed) = unsafe {
            super::mempool::Token::read(std::ptr::with_exposed_provenance_mut(descriptor))
        };
        assert!(!armed, "P11 a returned descriptor's token is disarmed");
    }
    let returned = d.f.payload.state.report().returned;
    assert_eq!(d.send(&[two(3), two(4)], Knobs::OPEN), Ok(2));
    let mut taken: Vec<usize> = d.held[1..]
        .iter()
        .flatten()
        .filter(|seg| seg.source.is_some())
        .map(|seg| seg.mbuf.addr())
        .collect();
    taken.sort_unstable();
    let mut expected = returning.clone();
    expected.sort_unstable();
    assert_eq!(
        taken, expected,
        "P11 the send re-took exactly the returned descriptors"
    );
    d.complete();
    assert_eq!(
        d.f.payload.state.report().returned,
        returned + 6,
        "P4 each descriptor out returned once"
    );
    assert_eq!((d.fired(2), d.fired(9)), (1, 1), "C2 and C9 fired");
    d.quiesce();
}

/// A missing IOVA on the front piece of a non-leading two-piece datagram, after its back piece built: the first chain goes out intact, the failing datagram's built back descriptor and its reference return, its header buffer returns within the call, and the call returns `Ok(1)` with the descriptor top lowered by the first chain alone and the header pool's application count unchanged.
#[test]
fn a_missing_iova_after_a_built_segment_releases_only_the_failing_datagrams_tail() {
    let sizing = Sizing {
        sources: 8,
        headers: 8,
        descriptors: 8,
        batch: 8,
    };
    let mut d = Driver::new(sizing, Some(0), 5);
    assert_eq!(d.source_index(0), 0, "the first acquire hands out buffer 0");
    let before = d.counts();
    let plans = [
        plan_of(1, 0, [piece(1, 0, 100), Piece::Empty]),
        plan_of(2, 1, [piece(0, 0, 100), piece(2, 0, 100)]),
    ];
    assert_eq!(d.send(&plans, Knobs::OPEN), Ok(1));
    let after = d.counts();
    assert_eq!(
        after.top,
        before.top - 1,
        "P5 only the first chain's descriptor is out"
    );
    assert_eq!(after.header.application, before.header.application);
    assert_eq!(after.report.unsendable, before.report.unsendable + 1);
    assert_eq!(
        d.f.burst.port().held.len(),
        1,
        "P5 the first chain was bursted"
    );
    assert_eq!((d.fired(8), d.fired(14)), (1, 1), "C8 and C14 fired");
    d.quiesce();
}

/// Every held chain carries one armed token per segment: each payload token names its source's kind, index and current incarnation, and the header token its own buffer's; the device's return disarms every one.
#[test]
fn every_held_segment_carries_one_armed_token_naming_its_own_buffer() {
    let mut d = Driver::new(DRIVEN, None, 6);
    let plans = [
        plan_of(1, 0, [piece(0, 0, 10), piece(1, 10, 10)]),
        plan_of(2, 1, [Piece::Inline(b"x".to_vec()), piece(2, 0, 30)]),
        plan_of(3, 2, [Piece::Inline(b"y".to_vec()), Piece::Empty]),
    ];
    assert_eq!(d.send(&plans, Knobs::OPEN), Ok(3));
    let headers = d.f.arena.pools().snapshot(PoolKind::PacketHeader);
    let sources = d.f.arena.pools().snapshot(PoolKind::ReadResponse);
    let mut segments = Vec::new();
    for (chain, plan) in d.held.iter().zip(&plans) {
        let slots: Vec<usize> = plan
            .pieces
            .iter()
            .filter_map(|piece| match piece {
                Piece::Retained { slot, .. } => Some(*slot),
                _ => None,
            })
            .collect();
        for (at, seg) in chain.iter().enumerate() {
            // SAFETY: the port holds the chain, and nothing writes it now.
            let token = unsafe { super::mempool::Token::read(seg.mbuf) };
            let expected = if at == 0 {
                let index = d.f.header.state.index_of(seg.mbuf.cast()).unwrap();
                (
                    PoolKind::PacketHeader.index() as u16,
                    index,
                    headers[index as usize].1,
                    true,
                )
            } else {
                let index = d.source_index(slots[at - 1]);
                (
                    PoolKind::ReadResponse.index() as u16,
                    index as u32,
                    sources[index].1,
                    true,
                )
            };
            assert_eq!(token, expected, "P6 one armed token naming its own buffer");
            segments.push(seg.mbuf);
        }
    }
    d.complete();
    for segment in segments {
        // SAFETY: the device returned the segment, and nothing writes it now.
        let (.., armed) = unsafe { super::mempool::Token::read(segment) };
        assert!(!armed, "P6 the device's return disarms the token");
    }
    d.quiesce();
}

/// In one history the owner drops a source while the device still reads it, and the device returns another while its owner holds it: the first goes from one NIC-held buffer to none at the return, and the second never becomes NIC-held.
#[test]
fn a_source_frees_once_both_owner_and_device_released_it_in_either_order() {
    let mut d = Driver::new(DRIVEN, None, 7);
    let one = |slot: usize| plan_of(slot as u8, 0, [piece(slot, 0, 64), Piece::Empty]);
    assert_eq!(d.send(&[one(0)], Knobs::OPEN), Ok(1));
    d.drop_source(0);
    assert_eq!(
        d.f.arena.report(PoolKind::ReadResponse).nic_held,
        1,
        "P7 the device still reads the dropped source"
    );
    d.complete();
    assert_eq!(
        d.f.arena.report(PoolKind::ReadResponse).nic_held,
        0,
        "P7 the device's return frees it"
    );
    assert_eq!(d.send(&[one(1)], Knobs::OPEN), Ok(1));
    d.complete();
    assert_eq!(
        d.f.arena.report(PoolKind::ReadResponse).nic_held,
        0,
        "P7 returned while its owner holds it"
    );
    d.drop_source(1);
    assert_eq!(d.f.arena.report(PoolKind::ReadResponse).nic_held, 0);
    assert_eq!(d.fired(3), 0b11, "C3 fired in both orders");
    d.quiesce();
}

/// An uncertain post after an accepted prefix of two quarantines exactly the two-piece third chain: one quarantine, three header buffers held, and later sends fail with `EIO` without a port call. The proven stop settles it once, as returned when the device took it, whether it returned before the stop, at the stop or inside the burst, where the record saw no token, and as released when the device never took it; the released case leaves nothing held, so the recorded set was the chain.
#[test]
fn an_uncertain_post_after_an_accepted_prefix_settles_its_quarantine_once() {
    for (retain, free, early, released) in [
        (false, false, false, 1),
        (true, false, true, 0),
        (true, false, false, 0),
        (false, true, false, 0),
    ] {
        let mut d = Driver::new(DRIVEN, None, 8);
        let plans = [
            plan_of(1, 0, [piece(0, 0, 64), Piece::Empty]),
            plan_of(2, 1, [Piece::Inline(b"two".to_vec()), Piece::Empty]),
            plan_of(3, 2, [piece(1, 0, 64), piece(2, 64, 64)]),
        ];
        let knobs = Knobs {
            accept: 2,
            uncertain: true,
            retain,
            free,
            ..Knobs::OPEN
        };
        assert_eq!(d.send(&plans, knobs), Ok(2));
        assert!(d.f.burst.poisoned());
        assert_eq!(d.f.burst.report().quarantined, 1);
        assert_eq!(
            held(d.f.arena, PoolKind::PacketHeader),
            if free { 2 } else { 3 },
            "P10 the accepted chains and the quarantined one stay held"
        );
        assert_eq!(
            d.send(&plans[..1], Knobs::OPEN),
            Err(DatagramError::Failed {
                code: Some(libc::EIO)
            })
        );
        if early {
            d.complete();
        }
        d.reclaim();
        let report = d.f.burst.report();
        assert_eq!(
            (
                report.quarantine_returned + report.quarantine_released,
                report.quarantine_released
            ),
            (1, released),
            "P17 settled once: retained {retain}, freed in the burst {free}, returned early {early}"
        );
        assert!(!d.f.burst.poisoned());
        d.quiesce();
        if free {
            assert_eq!(d.fired(15), 1, "C15 fired");
        }
    }
}

/// A batch five past the chain capacity builds the capacity and leaves the excess uncounted; an empty batch prepares an empty slice and bursts nothing; a prepare refusing every built chain fails the call with its error number and nothing accepted or held; a non-leading unsendable datagram ends the prefix with `Ok`; and at each prepare's entry no header handle is live and the descriptor top is the count less the built chains' pieces.
#[test]
fn oversize_empty_refused_and_truncated_batches_keep_the_send_contract() {
    let mut d = Driver::new(DRIVEN, None, 9);
    let inline =
        |tag: u8, peer: u16| plan_of(tag, peer, [Piece::Inline(vec![tag; 3]), Piece::Empty]);
    let mut plans: Vec<Plan> = (0..8).map(|at| inline(at, (at % 3).into())).collect();
    plans.extend((8..13).map(|at| inline(at, 7)));
    let before = d.counts();
    assert_eq!(d.send(&plans, Knobs::OPEN), Ok(8));
    assert_eq!(
        d.f.burst.report().unsendable,
        before.report.unsendable,
        "P16 the excess stays untouched"
    );
    d.complete();
    let (prepares, bursts) = (d.f.burst.port().prepares, d.f.burst.port().bursts);
    assert_eq!(d.send(&[], Knobs::OPEN), Ok(0));
    let port = d.f.burst.port();
    assert_eq!(
        (port.prepares, port.prepared_len, port.bursts),
        (prepares + 1, 0, bursts)
    );
    let refusing = Knobs {
        prepare: 0,
        ..Knobs::OPEN
    };
    assert_eq!(
        d.send(&plans[..3], refusing),
        Err(DatagramError::Failed {
            code: Some(libc::EINVAL)
        })
    );
    assert_eq!(
        held(d.f.arena, PoolKind::PacketHeader),
        0,
        "P22 a refused prepare holds nothing"
    );
    let truncated = [inline(1, 0), inline(2, 1), inline(3, 7), inline(4, 0)];
    assert_eq!(d.send(&truncated, Knobs::OPEN), Ok(2));
    assert_eq!((d.fired(10), d.fired(13)), (1, 0b11), "C10 and C13 fired");
    d.quiesce();
}

/// Every transmit branch allocates nothing: whole and partial accepts, descriptor and header shortfalls, a missing IOVA after a built segment, a leading unsendable datagram, a refused prepare, an empty and an oversize batch, an uncertain post in each device disposition and a send while poisoned.
#[test]
fn every_transmit_branch_allocates_nothing() {
    let mut f = sized(
        Sizing {
            sources: 8,
            headers: 8,
            descriptors: 8,
            batch: 4,
        },
        Some(0),
    );
    let sources: [Buffer<'static>; 3] = std::array::from_fn(|at| source(f.arena, at as u8));
    assert_eq!(
        sources[0].index(),
        0,
        "the first acquire hands out buffer 0"
    );
    let header = [0x61; 192];
    let datagram = |front: usize, back: Option<usize>| Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Retained(sources[front].source(0..64).unwrap()),
            back.map_or(Payload::EMPTY, |at| {
                Payload::Retained(sources[at].source(64..128).unwrap())
            }),
        ],
    };
    let good = datagram(1, Some(2));
    let unregistered = datagram(0, Some(2));
    let unknown = Outgoing {
        peer: PeerId(9),
        ..good
    };
    {
        let port = f.burst.port_mut();
        port.held.reserve(64);
        port.segment_returns.reserve(64);
    }
    let mut slots = [std::mem::MaybeUninit::uninit(); 8];
    let mut allocations = crate::instrument::allocations();
    let set = |f: &mut Fixture, prepare: usize, accept: usize| {
        let port = f.burst.port_mut();
        (port.prepare, port.accept) = (prepare, accept);
    };
    assert_eq!(f.burst.send(&[good, good]), Ok(2));
    f.burst.port_mut().complete();
    set(&mut f, usize::MAX, 1);
    assert_eq!(f.burst.send(&[good, good, good]), Ok(1));
    f.burst.port_mut().complete();
    set(&mut f, usize::MAX, usize::MAX);
    assert!(f.payload.state.take(&mut slots[..5]));
    assert_eq!(f.burst.send(&[good, good]), Ok(1));
    for slot in &slots[..5] {
        // SAFETY: taken above, never seen by a device.
        unsafe { f.payload.state.give_back(slot.assume_init()) };
    }
    f.burst.port_mut().complete();
    let taken: [_; 7] =
        std::array::from_fn(|_| f.arena.pools().acquire(PoolKind::PacketHeader).unwrap());
    assert_eq!(f.burst.send(&[good, good]), Ok(1));
    drop(taken);
    f.burst.port_mut().complete();
    assert_eq!(f.burst.send(&[good, unregistered]), Ok(1));
    f.burst.port_mut().complete();
    assert!(f.burst.send(&[unregistered]).is_err());
    assert!(f.burst.send(&[unknown]).is_err());
    set(&mut f, 0, usize::MAX);
    assert!(f.burst.send(&[good, good]).is_err());
    set(&mut f, usize::MAX, usize::MAX);
    assert_eq!(f.burst.send(&[]), Ok(0));
    assert_eq!(
        f.burst.send(&[good, good, good, good, good, unknown]),
        Ok(4)
    );
    f.burst.port_mut().complete();
    for (retain, free) in [(true, false), (false, true), (false, false)] {
        let port = f.burst.port_mut();
        (
            port.accept,
            port.uncertain,
            port.retain_uncertain,
            port.free_uncertain,
        ) = (1, true, retain, free);
        assert_eq!(f.burst.send(&[good, good, good]), Ok(1));
        assert!(f.burst.send(&[good]).is_err(), "poisoned");
        assert_eq!(
            crate::instrument::allocations(),
            allocations,
            "P12 retain {retain}, free {free}"
        );
        // Recovery records its stages in the mock, outside the transmit path.
        f.burst.reclaim();
        f.burst.port_mut().complete();
        allocations = crate::instrument::allocations();
    }
    assert_eq!(f.payload.state.free_descriptors(), 8);
}

/// Construction over the characterization fixtures' sizes, sixty-four datagrams over three peers and seventy-two sources among them, charges exactly the bytes it allocates, and a budget one byte short refuses with the budget unchanged and nothing allocated.
#[test]
fn construction_charges_exactly_at_every_characterization_size() {
    for (sources, batch) in [(8u32, 1usize), (12, 8), (72, 64)] {
        let arena = mock::arena_sized([sources, COUNT, 80]);
        let header = mock::arena_pool(arena, PoolKind::PacketHeader, Role::Header);
        let payload = mock::payload_pool(arena, 2 * batch as u32);
        let receive = mock::arena_pool(arena, PoolKind::PacketReceive, Role::Receive);
        let pools = [header.state, payload.state, receive.state];
        let registration = Forged(iova, || true);
        let charge =
            Burst::<MockPort>::charge(sources as usize, SPREAD_PEERS.len(), batch).unwrap();
        let wire =
            || Wire::new(SPREAD_LOCAL, &SPREAD_PEERS, &mut EngineBudget::unlimited()).unwrap();
        let mut short = EngineBudget::new(charge - 1);
        let (addressing, watch) = (wire(), mock::watch());
        let allocations = crate::instrument::allocations();
        let refused = Burst::new(
            MockPort::open(),
            addressing,
            pools,
            &registration,
            watch,
            batch,
            &mut short,
        );
        assert!(matches!(
            refused,
            Err(BurstRefusal {
                error: BurstError::Budget(_),
                ..
            })
        ));
        assert_eq!(
            crate::instrument::allocations(),
            allocations,
            "a refusal allocates nothing"
        );
        assert_eq!(
            short,
            EngineBudget::new(charge - 1),
            "a refusal charges nothing"
        );
        let mut exact = EngineBudget::new(charge);
        let (addressing, watch) = (wire(), mock::watch());
        let bytes = crate::instrument::allocated_bytes();
        let Ok(burst) = Burst::new(
            MockPort::open(),
            addressing,
            pools,
            &registration,
            watch,
            batch,
            &mut exact,
        ) else {
            panic!("an exact budget fits");
        };
        assert_eq!(
            crate::instrument::allocated_bytes() - bytes,
            charge,
            "P13 batch {batch}: the charge is the bytes allocated"
        );
        assert_eq!(exact.used(), charge);
        drop(burst);
    }
}

/// A datagram whose back piece has no registered IOVA is unsendable even when the descriptor stack holds fewer descriptors than the datagram's pieces: the back piece's translation decides before the front piece's descriptor, so a leading one fails with `EINVAL` and a non-leading one ends the prefix with `Ok`, counting no pressure and no refused dequeue.
#[test]
fn a_missing_back_iova_is_unsendable_whatever_the_descriptors_left() {
    let sizing = Sizing {
        sources: 8,
        headers: 8,
        descriptors: 3,
        batch: 8,
    };
    let mut d = Driver::new(sizing, Some(0), 10);
    assert_eq!(d.source_index(0), 0, "the first acquire hands out buffer 0");
    let refused_back = plan_of(2, 0, [piece(1, 0, 64), piece(0, 0, 64)]);
    let lead = plan_of(1, 0, [piece(2, 0, 64), piece(3, 0, 64)]);
    let before = d.counts();
    assert_eq!(d.send(&[lead, refused_back.clone()], Knobs::OPEN), Ok(1));
    let after = d.counts();
    assert_eq!(
        (
            after.report.unsendable,
            after.report.exhausted,
            after.payload_ops.refused
        ),
        (
            before.report.unsendable + 1,
            before.report.exhausted,
            before.payload_ops.refused
        ),
        "P22 one descriptor left, the back piece's missing IOVA decides"
    );
    d.complete();
    let mut slots = [std::mem::MaybeUninit::uninit(); 2];
    assert!(d.f.payload.state.take(&mut slots));
    // SAFETY: a successful take wrote every slot.
    d.descriptors_held
        .extend(slots.map(|slot| unsafe { slot.assume_init() }));
    assert_eq!(
        d.send(&[refused_back], Knobs::OPEN),
        Err(DatagramError::Failed {
            code: Some(libc::EINVAL)
        }),
        "P22 a leading datagram with one descriptor left fails on its back piece"
    );
    d.quiesce();
}

/// The census check refuses a header buffer the model does not account for, so a leaked header buffer fails a history.
#[test]
#[should_panic(expected = "P9 header census")]
fn the_custody_model_rejects_an_unaccounted_header_buffer() {
    let mut d = Driver::new(DRIVEN, None, 11);
    let plan = plan_of(1, 0, [piece(0, 0, 64), Piece::Empty]);
    assert_eq!(d.send(&[plan], Knobs::OPEN), Ok(1));
    let _leaked = d.f.arena.pools().acquire(PoolKind::PacketHeader).unwrap();
    d.check_census("with a leaked header buffer");
}

/// The census check refuses a stray return, so a descriptor returned while not out fails a history.
#[test]
#[should_panic(expected = "P4 no stray return")]
fn the_custody_model_rejects_a_stray_descriptor_return() {
    let d = Driver::new(DRIVEN, None, 12);
    // SAFETY: descriptor 0 is on the stack, so its enqueue is stray and changes no custody.
    unsafe { d.f.payload.state.give_back(d.f.payload.state.object(0)) };
    d.check_census("after a stray return");
}

/// The prefix model refuses a build that differs from it: with a header buffer held outside the model, the send builds one datagram short of the model's prefix.
#[test]
#[should_panic(expected = "P1 P16 the built prefix is the model's")]
fn the_prefix_model_rejects_a_build_one_short() {
    let sizing = Sizing {
        sources: 8,
        headers: 2,
        descriptors: 8,
        batch: 8,
    };
    let mut d = Driver::new(sizing, None, 13);
    let _outside = d.f.arena.pools().acquire(PoolKind::PacketHeader).unwrap();
    let plans: Vec<Plan> = (0..2)
        .map(|at| plan_of(at, 0, [Piece::Inline(vec![at; 2]), Piece::Empty]))
        .collect();
    let _ = d.send(&plans, Knobs::OPEN);
}

/// Swapping header-only chains 1 and 2 across the accepted boundary preserves the header pool's counts, so the acceptance check must compare the accepted chains by identity to fail the send.
#[test]
#[should_panic(expected = "P3 the device accepted exactly the model's prefix, in order")]
fn the_custody_model_rejects_a_swapped_accepted_prefix() {
    let mut d = Driver::new(DRIVEN, None, 15);
    let plans: Vec<Plan> = (0..4)
        .map(|at| plan_of(at, 0, [Piece::Inline(vec![at; 2]), Piece::Empty]))
        .collect();
    d.f.burst.port_mut().swap_accepted = Some((1, 2));
    let knobs = Knobs {
        accept: 2,
        ..Knobs::OPEN
    };
    let _ = d.send(&plans, knobs);
}

/// A history too short to reach every coverage case fails its witness check rather than passing vacuously.
#[test]
#[should_panic(expected = "witness never fired")]
fn a_history_that_misses_a_witness_fails() {
    let mut d = Driver::new(DRIVEN, None, 14);
    let plan = plan_of(1, 0, [Piece::Inline(vec![1]), Piece::Empty]);
    let _ = d.send(&[plan], Knobs::OPEN);
    d.assert_witnessed();
}
/// A device that returns a chain's header before its payload descriptor, one segment per cleanup, still holds the
/// descriptor and its source reference once the header is back. Reclaim keeps asking for cleanup until that
/// descriptor returns, so an idle transport gets the reference back with no later send.
#[test]
fn reclaim_keeps_asking_while_the_device_holds_a_descriptor_whose_header_returned() {
    let mut f = fixture();
    let retained = source(f.arena, 7);
    let header = [0x61; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Retained(retained.source(0..100).unwrap()),
            Payload::EMPTY,
        ],
    };
    assert_eq!(f.burst.send(&[datagram]), Ok(1));
    drop(retained);
    f.burst.port_mut().return_apart(0);
    f.burst.reclaim();
    assert_eq!(
        (
            held(f.arena, PoolKind::PacketHeader),
            held(f.arena, PoolKind::ReadResponse),
            f.burst.port_mut().segment_returns.len(),
        ),
        (0, 1, 1),
        "the header is back and the device still holds the descriptor and its source reference"
    );
    let asked = f.burst.port_mut().cleanups;
    for _ in 0..64 {
        f.burst.reclaim();
    }
    assert_eq!(
        (
            f.burst.port_mut().cleanups > asked,
            f.burst.port_mut().segment_returns.len(),
            held(f.arena, PoolKind::ReadResponse),
        ),
        (true, 0, 0),
        "64 idle turns asked for cleanup and the descriptor's source reference returned"
    );
}

/// A supervisor that contains as [`Containment`] does and unwinds when the episode asks whether the containment took
/// effect.
struct UnwindingVerification(Containment);

impl Supervisor for UnwindingVerification {
    fn contain(&self) {
        self.0.contain();
    }

    fn verified(&self) -> bool {
        panic!("the verification unwound")
    }
}

/// A watchdog that expired inside the stop stage asked the supervisor to contain while an uncertain post's chain sat
/// quarantined; when the supervisor's verification then unwinds and the caller catches it, handing the port back must
/// not stop the contained device again to settle that quarantine. The promise is the doc of `Burst::into_port` ("An
/// unproven stop, or a recovery whose watchdog asked to contain, leaves the chain charged to its pools").
#[test]
fn a_containment_whose_verification_unwinds_settles_no_quarantine() {
    let (clock, containment) = (
        StallClock::default(),
        Arc::new(UnwindingVerification(Containment::default())),
    );
    let stall = {
        let (clock, containment) = (clock.clone(), Arc::clone(&containment));
        move || {
            clock.expire(RECOVERY_DEADLINE);
            containment.0.wait_requested();
        }
    };
    let mut f = watched(mock::arena(), &clock, &containment, Box::new(|| true));
    quarantine(&mut f);
    f.burst.port_mut().proven_stops = u32::MAX;
    f.burst.port_mut().stall = Some((
        RecoveryStage::Stop,
        Box::new(move || {
            stall();
            true
        }),
    ));
    // Premises: the watch expires inside the stop stage and asks to contain once, then the verification unwinds out
    // of the reclaim with the chain still quarantined.
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f.burst.reclaim()));
    assert!(
        unwound.is_err(),
        "the verification unwound out of the reclaim"
    );
    assert_eq!(containment.0.count(), 1);
    assert!(
        f.burst.poisoned(),
        "the expired stop left the quarantine unreconciled"
    );
    // Judgment.
    let stops = f.burst.port_mut().stops;
    let port = f.burst.into_port();
    assert_eq!(
        port.stops, stops,
        "the handed-back port is not stopped again to settle the quarantine of a device the supervisor was asked to contain"
    );
}

/// A stop stage that unwinds, caught by the caller, leaves the episode's watch armed while an uncertain post's chain
/// sits quarantined. When that watch then expires and asks the supervisor to contain, handing the port back must not
/// stop the device to settle that quarantine. The promise is the doc of `Burst::into_port` ("An unproven stop, or a
/// recovery whose watchdog asked to contain, leaves the chain charged to its pools").
#[test]
fn a_containment_after_an_unwound_recovery_stage_settles_no_quarantine() {
    let (clock, containment) = (StallClock::default(), Containment::verifying());
    let mut f = watched(mock::arena(), &clock, &containment, Box::new(|| true));
    quarantine(&mut f);
    f.burst.port_mut().proven_stops = u32::MAX;
    f.burst.port_mut().stall = Some((
        RecoveryStage::Stop,
        Box::new(|| panic!("the stop stage unwound")),
    ));
    // Premises: the stop stage unwinds out of the reclaim with the chain still quarantined, then the armed watch
    // expires and asks to contain once.
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f.burst.reclaim()));
    assert!(
        unwound.is_err(),
        "the stop stage unwound out of the reclaim"
    );
    f.burst.port_mut().stall = None;
    clock.expire(RECOVERY_DEADLINE);
    containment.wait_requested();
    assert_eq!(containment.count(), 1);
    assert!(
        f.burst.poisoned(),
        "the unwound stop left the quarantine unreconciled"
    );
    // Judgment.
    let stops = f.burst.port_mut().stops;
    let port = f.burst.into_port();
    assert_eq!(
        port.stops, stops,
        "the handed-back port is not stopped to settle the quarantine of a device the supervisor was asked to contain"
    );
}

/// A native post that unwinds after the device kept an uncertain packet may
/// leave any chain it was offered with the device, so the link is lost: the
/// next send refuses with `Closed` and reaches no device, and every chain the
/// post was offered stays charged to its pools.
#[test]
fn a_post_that_unwinds_after_an_uncertain_take_loses_the_link() {
    let mut f = fixture();
    let retained = source(f.arena, 9);
    let header = [0x33; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Retained(retained.source(0..100).unwrap()),
            Payload::EMPTY,
        ],
    };
    *f.burst.port_mut() = MockPort {
        accept: 1,
        uncertain: true,
        unwind_after_post: true,
        ..MockPort::open()
    };
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.burst.send(&[datagram; 3])
    }))
    .is_err();
    assert!(unwound, "the post unwinds");
    let _ = f.burst.port_mut().take_accepted();
    let second = f.burst.send(&[datagram]);
    let reached = f.burst.port_mut().take_accepted().len();
    assert_eq!(
        (
            second,
            f.burst.link(),
            reached,
            held(f.arena, PoolKind::PacketHeader)
        ),
        (Err(DatagramError::Closed), Link::Lost, 0, 3),
        "(second send, link, packets the second send posted, headers held) after the unwound post"
    );
}

/// `f` with a pending reset whose restart fails at `stage`, the function reset or the re-initialization, with the
/// error number `code`.
fn pending(mut f: Fixture, stage: RecoveryStage, code: i32) -> Fixture {
    let port = f.burst.port_mut();
    port.reset = true;
    match stage {
        RecoveryStage::Reset => port.reset_error = Some(code),
        RecoveryStage::Reinitialize => port.reinitialize_error = Some(code),
        other => unreachable!("a reset or a re-initialization fails here, not {other:?}"),
    }
    f
}

/// The stages the episode's port ran, with what the recovery left: the link, the recorded restart error, and the
/// starts the port saw.
fn left(burst: &Burst<'static, MockPort>) -> (Vec<RecoveryStage>, Link, Option<i32>, u32) {
    let port = burst.port();
    (
        port.stages.clone(),
        burst.link(),
        burst.report().restart_error,
        port.restarts,
    )
}

/// A function reset that fails with `ENODEV` ends the restart at that stage: the port's stage record is the stop,
/// the reset and a second stop, and its start count stays zero. The report holds `ENODEV` as the restart error and
/// zero recoveries, and the proven second stop leaves the link down, with that stop as the episode's last stage
/// and its expiry unset.
#[test]
fn a_failed_reset_begins_no_later_restart_stage_and_a_proven_stop_leaves_the_link_down() {
    let mut f = pending(fixture(), RecoveryStage::Reset, libc::ENODEV);
    f.burst.reclaim();
    assert_eq!(
        left(&f.burst),
        (
            vec![
                RecoveryStage::Stop,
                RecoveryStage::Reset,
                RecoveryStage::Stop
            ],
            Link::Down,
            Some(libc::ENODEV),
            0
        ),
        "the reset's error ends the restart before the re-initialization and the start"
    );
    let report = f.burst.report();
    assert_eq!(
        (
            report.recoveries,
            report.episode.reached,
            report.episode.expired_at
        ),
        (0, Some(RecoveryStage::Stop), None)
    );
}

/// A re-initialization that fails with `ENOMEM` after the reset succeeded ends the restart at that stage: the
/// port's stage record is the stop, the reset, the re-initialization and a second stop, and its start count stays
/// zero. The report holds `ENOMEM` as the restart error and zero recoveries, and the proven second stop leaves
/// the link down, with that stop as the episode's last stage and its expiry unset.
#[test]
fn a_failed_reinitialization_begins_no_start_and_a_proven_stop_leaves_the_link_down() {
    let mut f = pending(fixture(), RecoveryStage::Reinitialize, libc::ENOMEM);
    f.burst.reclaim();
    assert_eq!(
        left(&f.burst),
        (
            vec![
                RecoveryStage::Stop,
                RecoveryStage::Reset,
                RecoveryStage::Reinitialize,
                RecoveryStage::Stop
            ],
            Link::Down,
            Some(libc::ENOMEM),
            0
        ),
        "the re-initialization's error ends the restart before the start"
    );
    let report = f.burst.report();
    assert_eq!(
        (
            report.recoveries,
            report.episode.reached,
            report.episode.expired_at
        ),
        (0, Some(RecoveryStage::Stop), None)
    );
}

/// An unproven stop after a failed reset or re-initialization loses the link, since the device may still reach
/// memory. The report still holds the failed stage's error number, that stop is the last stage in the port's
/// record, and the port's start count stays zero.
#[test]
fn an_unproven_stop_after_a_failed_reset_or_reinitialization_loses_the_link() {
    for (stage, code) in [
        (RecoveryStage::Reset, libc::ENODEV),
        (RecoveryStage::Reinitialize, libc::ENOMEM),
    ] {
        let mut f = pending(fixture(), stage, code);
        f.burst.port_mut().proven_stops = 1;
        f.burst.reclaim();
        let (stages, link, error, starts) = left(&f.burst);
        assert_eq!(
            (link, error, starts),
            (Link::Lost, Some(code), 0),
            "{stage:?}: the error is recorded and the unproven stop loses the link"
        );
        assert_eq!(stages.last(), Some(&RecoveryStage::Stop));
        assert!(!stages.contains(&RecoveryStage::Restart));
    }
}

/// A stall inside a failing reset or re-initialization holds the owner thread there until the watchdog expires on
/// its own clock and asks to contain. The expiry ends the attempt at that stage: the link is lost, the restart
/// error stays unset, the stalled stage is the last in the port's record, the start count stays zero, and the
/// episode records that stage as the last begun and as the expiry's, with the containment requested.
#[test]
fn a_watchdog_expired_by_the_return_of_a_failed_reset_or_reinitialization_records_no_error() {
    for (stage, code) in [
        (RecoveryStage::Reset, libc::ENODEV),
        (RecoveryStage::Reinitialize, libc::ENOMEM),
    ] {
        let (clock, containment) = (StallClock::default(), Arc::new(Containment::default()));
        let mut f = pending(
            watched(mock::arena(), &clock, &containment, Box::new(|| true)),
            stage,
            code,
        );
        let stall = {
            let containment = Arc::clone(&containment);
            move || {
                clock.expire(RECOVERY_DEADLINE);
                containment.wait_requested();
                true
            }
        };
        f.burst.port_mut().stall = Some((stage, Box::new(stall)));
        f.burst.reclaim();
        let (stages, link, error, starts) = left(&f.burst);
        assert_eq!(
            (link, error, starts),
            (Link::Lost, None, 0),
            "{stage:?}: the expiry ends the attempt before the stage's error is read"
        );
        assert_eq!(
            stages.last(),
            Some(&stage),
            "no stage begins after the expiry"
        );
        let episode = f.burst.report().episode;
        assert_eq!(
            (
                episode.reached,
                episode.expired_at,
                episode.containment_requested
            ),
            (Some(stage), Some(stage), true)
        );
    }
}

/// A reset that stalls until the watchdog expired and then fails, in a recovery an uncertain post's poison began,
/// hands no outcome on. The episode records the reset as the last stage begun and as the expiry's, with the
/// containment requested once and not verified. The port ran the stop and the reset and no settling stop after
/// them, the registration was rechecked once, the link is lost, the restart error stays unset, and every buffer
/// the stall saw held stays held. The request and recheck counts are read once the handed-back port is dropped.
#[test]
fn a_reset_that_fails_after_the_expiry_records_no_restart_error() {
    let (clock, containment) = (StallClock::default(), Arc::new(Containment::default()));
    let arena = mock::arena();
    let seen = Arc::new(Mutex::new(None));
    let stall = {
        let (clock, containment, seen) =
            (clock.clone(), Arc::clone(&containment), Arc::clone(&seen));
        move || {
            *seen.lock().unwrap() = Some(census(arena));
            clock.expire(RECOVERY_DEADLINE);
            containment.wait_requested();
            true
        }
    };
    let (rechecks, recheck) = counted_recheck();
    let mut f = watched(arena, &clock, &containment, recheck);
    quarantine(&mut f);
    let port = f.burst.port_mut();
    port.reset_error = Some(libc::EIO);
    port.stall = Some((RecoveryStage::Reset, Box::new(stall)));
    f.burst.reclaim();
    let report = f.burst.report();
    let link = f.burst.link();
    let stages = f.burst.port_mut().stages.clone();
    let stops = f.burst.port_mut().stops;
    let after = census(f.arena);
    drop(f.burst.into_port());
    assert_eq!(
        report.episode,
        RecoveryEpisode {
            episode: 1,
            reached: Some(RecoveryStage::Reset),
            expired_at: Some(RecoveryStage::Reset),
            containment_requested: true,
            containment_verified: false,
            refused: false,
        }
    );
    assert_eq!(link, Link::Lost);
    assert_eq!(containment.count(), 1, "containment requested once");
    assert_eq!(report.recoveries, 0);
    assert_eq!(
        stages,
        [RecoveryStage::Stop, RecoveryStage::Reset],
        "the port ran the stages up to the stall, and no later one"
    );
    assert_eq!(*rechecks.lock().unwrap(), 1);
    assert_eq!(report.restart_error, None);
    let seen = seen.lock().unwrap().expect("the stall ran");
    assert!(
        after.iter().zip(seen).all(|(after, seen)| *after >= seen),
        "nothing the stall saw held was released: {seen:?} then {after:?}"
    );
    assert_eq!(
        stops, 1,
        "only the episode's first stop ran before the expiry"
    );
}

/// A header of eight 192-byte frames, the largest packed datagram, builds over the smallest header pool: a pool's
/// buffers are at least 4,096 bytes, the length the fixture's header pool has, and its data room holds the wire
/// headers and all 1,536 frame bytes in the chain's header segment. A head one byte past the data room is still
/// unsendable.
#[test]
fn a_header_of_eight_frames_builds_over_the_smallest_header_pool() {
    use crate::net::{HEADER_LEN, MAX_PACKED_GETS};
    use crate::storage::{BufferConfig, BufferConfigError, HugepageSize, NodeMask, PoolSpec};
    let smaller = [PoolSpec {
        kind: PoolKind::PacketHeader,
        count: 1,
        buffer_len: 2048,
    }];
    assert_eq!(
        BufferConfig {
            hugepage: HugepageSize::TwoMiB,
            nodes: NodeMask::from_nodes(&[0]).unwrap(),
            pools: &smaller,
        }
        .validate()
        .err(),
        Some(BufferConfigError::MisalignedBufferLen {
            kind: PoolKind::PacketHeader,
            buffer_len: 2048,
        }),
        "no header pool has buffers below 4,096 bytes"
    );
    let room = crate::storage::PacketLayout::of(4096).unwrap().data_room;
    let mut f = fixture();
    let frames: Vec<u8> = (0..MAX_PACKED_GETS * HEADER_LEN)
        .map(|at| (at / HEADER_LEN) as u8 + 1)
        .collect();
    assert_eq!(frames.len(), 1536);
    assert!(FRAME_OVERHEAD + frames.len() <= room, "{room}");
    let packed = Outgoing {
        peer: PeerId(0),
        header: &frames,
        payload: [Payload::EMPTY; 2],
    };
    assert_eq!(f.burst.send(&[packed]), Ok(1));
    let head = *f.burst.port_mut().held.last().unwrap();
    let wire = bytes(head);
    assert_eq!(wire.len(), FRAME_OVERHEAD + 1536);
    assert_eq!(&wire[FRAME_OVERHEAD..], &frames[..]);
    f.burst.port_mut().complete();
    let past = vec![0u8; room - FRAME_OVERHEAD + 1];
    let overlong = Outgoing {
        peer: PeerId(0),
        header: &past,
        payload: [Payload::EMPTY; 2],
    };
    assert_eq!(
        f.burst.send(&[overlong]),
        Err(DatagramError::Failed {
            code: Some(libc::EINVAL),
        })
    );
    assert_eq!(f.burst.report().unsendable, 1);
}
