//! A chain the device may have kept after a failed native post is
//! quarantined instead of released, and the transport refuses later sends with
//! `EIO` while the link stays up, until a proven stop settles the chain.
//!
//! Each test drives a `Burst` over the mock port and the mock pools through
//! `Datagrams::send` and `Datagrams::reclaim`. The first send goes to a port
//! that takes nothing and reports the chain it refused as uncertain. The tests
//! then read the pools, the report and the port's call counters. Each test
//! computes what it saw into plain values, lets its fixture go, and asserts
//! last.

use std::mem::MaybeUninit;

use super::burst::{Burst, Link};
use super::burst_tests::{LOCAL, PEERS};
use super::mempool::Role;
use super::mock::{self, Forged, MockPort, iova};
use super::wire::Wire;
use crate::net::{DatagramError, Datagrams, Outgoing, Payload, PeerId};
use crate::storage::test_platform::TestPlatform;
use crate::storage::{BufferArena, EngineBudget, PoolKind};

/// The payload pool's descriptors.
const DESCRIPTORS: u32 = 8;

/// The refusal of a poisoned transport.
const EIO: Result<usize, DatagramError> = Err(DatagramError::Failed {
    code: Some(libc::EIO),
});

struct Fixture {
    arena: &'static BufferArena<TestPlatform>,
    burst: Burst<'static, MockPort>,
    _header: mock::MockPool,
    payload: mock::MockPool,
    _receive: mock::MockPool,
}

/// A burst over an open mock port, a verified registration whose recheck passes, and mock pools of eight header
/// buffers and eight payload descriptors.
fn fixture() -> Fixture {
    let arena = mock::arena();
    let header = mock::arena_pool(arena, PoolKind::PacketHeader, Role::Header);
    let payload = mock::payload_pool(arena, DESCRIPTORS);
    let receive = mock::arena_pool(arena, PoolKind::PacketReceive, Role::Receive);
    let port = MockPort {
        receive: Some(receive.state),
        ..MockPort::open()
    };
    let registration = Box::leak(Box::new(Forged(iova, || true)));
    let wire = Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap();
    let pools = [header.state, payload.state, receive.state];
    let budget = &mut EngineBudget::unlimited();
    let Ok(burst) = Burst::new(port, wire, pools, registration, mock::watch(), 8, budget) else {
        panic!("the burst is built over pools of the right roles");
    };
    Fixture {
        arena,
        burst,
        _header: header,
        payload,
        _receive: receive,
    }
}

/// The payload descriptors the pool still has: the most it hands out at once, each handed back.
fn free_descriptors(payload: &mock::MockPool) -> u32 {
    (0..=DESCRIPTORS)
        .rev()
        .find(|&n| {
            let mut slots = vec![MaybeUninit::uninit(); n as usize];
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

/// What a test reads after a step: the pools' custody, the transport's state and what the port was handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seen {
    link: Link,
    poisoned: bool,
    /// Chains quarantined, returned by the device, and reconciled locally.
    quarantine: (u64, u64, u64),
    /// Header buffers out of their pool.
    headers: u32,
    /// Source references the transport holds on read-response buffers.
    sources: u32,
    /// Payload descriptors out of their pool.
    descriptors: u32,
    /// Prepare calls, burst calls, and every call the port received.
    port: (u32, u32, u32),
    /// Stops and starts the port ran.
    recovery: (u32, u32),
}

fn seen(f: &mut Fixture) -> Seen {
    let report = f.burst.report();
    let headers = f.arena.report(PoolKind::PacketHeader);
    let (link, poisoned) = (f.burst.link(), f.burst.poisoned());
    let port = f.burst.port_mut();
    Seen {
        link,
        poisoned,
        quarantine: (
            report.quarantined,
            report.quarantine_returned,
            report.quarantine_released,
        ),
        headers: headers.count - headers.free,
        sources: f.arena.report(PoolKind::ReadResponse).nic_held,
        descriptors: DESCRIPTORS - free_descriptors(&f.payload),
        port: (port.prepares, port.bursts, port.calls),
        recovery: (port.stops, port.restarts),
    }
}

/// The state right after the uncertain post of one datagram with one retained slice: the chain's header buffer,
/// payload descriptor and source reference are held, one quarantine is counted, and the link is up.
const QUARANTINED: Seen = Seen {
    link: Link::Up,
    poisoned: true,
    quarantine: (1, 0, 0),
    headers: 1,
    sources: 1,
    descriptors: 1,
    port: (1, 1, 2),
    recovery: (0, 0),
};

/// Sends one datagram with one retained payload slice into a port that takes nothing and reports the chain it
/// refused as uncertain without keeping it, drops the caller's own hold on the source buffer, and returns the
/// send's result with the state after it.
fn post_uncertain(f: &mut Fixture) -> (Result<usize, DatagramError>, Seen) {
    let mut retained = f.arena.acquire(PoolKind::ReadResponse).unwrap();
    retained.bytes_mut().fill(6);
    let header = [0x56; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Retained(retained.source(0..64).unwrap()),
            Payload::EMPTY,
        ],
    };
    let port = f.burst.port_mut();
    (port.accept, port.uncertain, port.retain_uncertain) = (0, true, false);
    let sent = f.burst.send(&[datagram]);
    drop(retained);
    (sent, seen(f))
}

/// Sends one datagram with an inline payload byte to a port that would take it.
fn send_inline(f: &mut Fixture) -> Result<usize, DatagramError> {
    let header = [0x57; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"u"), Payload::EMPTY],
    };
    f.burst.port_mut().accept = usize::MAX;
    f.burst.send(&[datagram])
}

/// After an uncertain post the chain stays held and counted once, and each later send while the link is up is
/// refused `EIO` before the port sees it: no prepare, no burst, no call at all, and no buffer leaves a pool.
#[test]
fn each_send_after_an_uncertain_post_is_refused_eio_and_hands_the_port_nothing() {
    let mut f = fixture();
    let (posted, quarantined) = post_uncertain(&mut f);
    let later: Vec<_> = (0..3)
        .map(|_| (send_inline(&mut f), seen(&mut f)))
        .collect();
    drop(f);
    assert_eq!(posted, Ok(0), "the port took nothing");
    assert_eq!(quarantined, QUARANTINED);
    assert_eq!(later, [(EIO, QUARANTINED); 3]);
}

/// The control without the fault: the same port takes nothing and reports no uncertain chain, so the chain is
/// released, nothing is quarantined, and the next send reaches the port and is accepted.
#[test]
fn a_refused_post_that_is_not_uncertain_releases_its_chain_and_the_next_send_is_accepted() {
    let mut f = fixture();
    let mut retained = f.arena.acquire(PoolKind::ReadResponse).unwrap();
    retained.bytes_mut().fill(6);
    let header = [0x56; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Retained(retained.source(0..64).unwrap()),
            Payload::EMPTY,
        ],
    };
    f.burst.port_mut().accept = 0;
    let posted = f.burst.send(&[datagram]);
    drop(retained);
    let refused = seen(&mut f);
    let next = send_inline(&mut f);
    let accepted = seen(&mut f);
    drop(f);
    assert_eq!(posted, Ok(0), "the port took nothing");
    let released = Seen {
        poisoned: false,
        quarantine: (0, 0, 0),
        headers: 0,
        sources: 0,
        descriptors: 0,
        ..QUARANTINED
    };
    assert_eq!(refused, released);
    assert_eq!(next, Ok(1));
    let sent = Seen {
        headers: 1,
        port: (2, 2, 4),
        ..released
    };
    assert_eq!(accepted, sent, "the port prepared and took the datagram");
}

/// The next reclaim runs recovery: the stop is proven, the chain the device never took is reconciled locally with
/// every buffer and reference back, the port restarts, and a send is accepted again.
#[test]
fn a_proven_stop_and_restart_settle_the_chain_and_a_send_is_accepted_again() {
    let mut f = fixture();
    let (posted, quarantined) = post_uncertain(&mut f);
    f.burst.reclaim();
    let recovered = seen(&mut f);
    let next = send_inline(&mut f);
    let accepted = seen(&mut f);
    drop(f);
    assert_eq!((posted, quarantined), (Ok(0), QUARANTINED));
    let settled = Seen {
        poisoned: false,
        quarantine: (1, 0, 1),
        headers: 0,
        sources: 0,
        descriptors: 0,
        recovery: (1, 1),
        ..recovered
    };
    assert_eq!(recovered, settled);
    assert_eq!(recovered.link, Link::Up);
    assert_eq!(next, Ok(1));
    assert_eq!(
        (accepted.headers, accepted.port.1),
        (1, recovered.port.1 + 1),
        "the port took the datagram in one more burst"
    );
    assert!(!accepted.poisoned);
}
