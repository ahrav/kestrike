//! Identity witnesses for uncertain sends, proven stops and failed restarts.
//! Possible chains retain armed header and source references, allocated descriptors
//! and NIC-held census entries. Recovery's proven stop and reconciliation end
//! each epoch's segment and source holders before receive acquisition.
//! Failed restart keeps its acquired set held until its own stop proves quiescence.
//! The frozen thirteen-case inventory gives each witness a ten-second deadline.
//!
//! A short post the port reports certain holds its accepted chains alone: every other chain returns each
//! segment once, the transport is not poisoned, and the reclaim after it stops nothing and leaves the link Up.
//! The two tests of that property run outside the inventory and have no deadline.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_void;
use std::sync::mpsc;
use std::time::Duration;

use super::super::mock::ChainSegment;
use super::*;

const FREE: usize = 0;
const POSTED: usize = 4;
const NIC_HELD: usize = 5;

const DEADLINE: Duration = Duration::from_secs(10);
const REQUIRED: [&str; 13] = [
    "short-retained-unproven",
    "short-unretained-unproven",
    "zero-retained-unproven",
    "zero-unretained-unproven",
    "short-retained-proven",
    "short-unretained-proven",
    "zero-retained-proven",
    "zero-unretained-proven",
    "restart-acquired-lost",
    "restart-acquired-down",
    "restart-empty-lost",
    "restart-empty-down",
    "restart-success",
];
const CASES: [(&str, fn()); 13] = [
    ("short-retained-unproven", || uncertain(1, true, false)),
    ("short-unretained-unproven", || uncertain(1, false, false)),
    ("zero-retained-unproven", || uncertain(0, true, false)),
    ("zero-unretained-unproven", || uncertain(0, false, false)),
    ("short-retained-proven", || uncertain(1, true, true)),
    ("short-unretained-proven", || uncertain(1, false, true)),
    ("zero-retained-proven", || uncertain(0, true, true)),
    ("zero-unretained-proven", || uncertain(0, false, true)),
    ("restart-acquired-lost", || restart(3, false, true)),
    ("restart-acquired-down", || restart(3, true, true)),
    ("restart-empty-lost", || restart(0, false, true)),
    ("restart-empty-down", || restart(0, true, true)),
    ("restart-success", || restart(7, true, false)),
];

#[derive(Clone)]
struct Epoch {
    built: Vec<Vec<ChainSegment>>,
    possible: BTreeSet<usize>,
    source: (u16, u32, u64),
}

impl Epoch {
    fn capture(f: &Fixture, accepted: usize, retain: bool, source: (u32, u64)) -> Self {
        let port = f.burst.port();
        let built = port.built.clone();
        assert_eq!(built.len(), 4);
        assert!(built.iter().all(|chain| chain.len() == 2));
        let head = |at: usize| built[at][0].mbuf.addr();
        let accepted_set: BTreeSet<_> = (0..accepted).map(head).collect();
        let possible: BTreeSet<_> = (0..=accepted).map(head).collect();
        let actual = if retain {
            possible.clone()
        } else {
            accepted_set.clone()
        };
        assert_eq!(
            port.accepted
                .logged()
                .iter()
                .map(|p| p.addr())
                .collect::<BTreeSet<_>>(),
            accepted_set
        );
        assert_eq!(
            port.held.iter().map(|p| p.addr()).collect::<BTreeSet<_>>(),
            actual
        );
        let source = (PoolKind::ReadResponse.index() as u16, source.0, source.1);
        for chain in &built {
            assert_eq!(chain[1].reference, Some(source));
            assert_eq!(
                f.header.state.index_of(chain[0].mbuf.cast()),
                Some(chain[0].reference.unwrap().1)
            );
            assert_eq!(
                chain[0].reference.unwrap().0,
                PoolKind::PacketHeader.index() as u16
            );
        }
        Self {
            built,
            possible,
            source,
        }
    }

    fn check(&self, header: &OpsState, payload: &OpsState, proven: bool) {
        let descriptor_stack = payload.descriptor_stack();
        let free_descriptors: BTreeSet<_> = descriptor_stack.iter().copied().collect();
        assert_eq!(
            free_descriptors.len(),
            descriptor_stack.len(),
            "epoch 1 descriptor stack contains duplicate identities"
        );
        let live_descriptors: BTreeSet<_> = self
            .built
            .iter()
            .filter(|chain| !proven && self.possible.contains(&chain[0].mbuf.addr()))
            .map(|chain| payload.index_of(chain[1].mbuf.cast()).unwrap())
            .collect();
        let expected_free: BTreeSet<_> = (0..payload.count())
            .filter(|index| !live_descriptors.contains(index))
            .collect();
        assert_eq!(
            free_descriptors, expected_free,
            "epoch 1 exact descriptor free-stack census"
        );
        for chain in &self.built {
            let ended = proven || !self.possible.contains(&chain[0].mbuf.addr());
            for (at, segment) in chain.iter().enumerate() {
                let pool = if at == 0 { header } else { payload };
                assert_eq!(
                    pool.returns(segment.mbuf.cast()),
                    usize::from(ended),
                    "epoch 1 segment {:?} return count",
                    segment
                );
                // SAFETY: scripts and assertions share one owner thread; every segment remains in its leaked pool.
                let reference = unsafe { pool.reference(segment.mbuf.cast()) };
                assert_eq!(
                    reference,
                    if ended { None } else { segment.reference },
                    "epoch 1 segment {:?} reference",
                    segment
                );
                if at == 1 {
                    assert_eq!(pool.descriptor_out(segment.mbuf.cast()), !ended);
                    let index = pool.index_of(segment.mbuf.cast()).unwrap();
                    assert_eq!(
                        descriptor_stack.iter().filter(|&&at| at == index).count(),
                        usize::from(ended),
                        "epoch 1 descriptor {index} stack membership"
                    );
                }
            }
        }
    }
}

/// Asserts this custody over the pools and the arena: the chains of `built` at the indices in `live` are held
/// by the device, and every other chain ended. It counts returns across chains that reuse a segment, which
/// [`Epoch::check`] does not accept: an ended chain's header buffer and descriptor are free for a later
/// chain, so one segment can carry several ended chains and at most one live chain. Each segment returned
/// once for each ended chain built on it and never for its live chain. A live chain's segments keep the
/// tokens they were built with, and its descriptor is out and off the descriptor stack; a segment with no
/// live chain is disarmed, and such a descriptor is on the stack once. In the arena, a header buffer or the
/// source `source` is device-held and off its free stack exactly while a live chain names it, the source
/// once for each live descriptor.
fn chain_census(
    f: &Fixture,
    built: &[Vec<ChainSegment>],
    live: &BTreeSet<usize>,
    source: u32,
    stage: &str,
) {
    let stack = f.payload.state.descriptor_stack();
    // Each segment by address: whether it leads its chains, the chains that ended on it, its segment in the
    // live chain on it, and its object.
    let mut segments: BTreeMap<usize, (bool, usize, Option<&ChainSegment>, *mut c_void)> =
        BTreeMap::new();
    for (chain_at, chain) in built.iter().enumerate() {
        for (at, segment) in chain.iter().enumerate() {
            let entry = segments.entry(segment.mbuf.addr()).or_insert((
                at == 0,
                0,
                None,
                segment.mbuf.cast(),
            ));
            assert_eq!(
                entry.0,
                at == 0,
                "premise: headers lead and descriptors follow"
            );
            if live.contains(&chain_at) {
                assert!(entry.2.is_none(), "premise: one live chain to a segment");
                entry.2 = Some(segment);
            } else {
                entry.1 += 1;
            }
        }
    }
    let mut live_descriptors = BTreeSet::new();
    let mut live_headers = BTreeSet::new();
    for &(leads, ended, holder, obj) in segments.values() {
        let pool = if leads {
            f.header.state
        } else {
            f.payload.state
        };
        let index = pool.index_of(obj).unwrap();
        let name = if leads { "header" } else { "descriptor" };
        let held = holder.is_some();
        assert_eq!(
            pool.returns(obj),
            ended,
            "{stage}: {name} {index} return count for its ended chains, held {held}"
        );
        // SAFETY: scripts and assertions share one owner thread; every segment remains in its leaked pool.
        let token = unsafe { pool.reference(obj) };
        let expected = holder.and_then(|segment| segment.reference);
        assert_eq!(token, expected, "{stage}: {name} {index} token");
        if leads {
            if let Some(token) = expected {
                live_headers.insert(token.1);
            }
            continue;
        }
        if held {
            live_descriptors.insert(index);
        }
        assert_eq!(
            pool.descriptor_out(obj),
            held,
            "{stage}: descriptor {index} out flag"
        );
        assert_eq!(
            stack.iter().filter(|&&free| free == index).count(),
            usize::from(!held),
            "{stage}: descriptor {index} stack membership, held {held}"
        );
    }
    let free_descriptors: BTreeSet<u32> = stack.iter().copied().collect();
    assert_eq!(
        free_descriptors.len(),
        stack.len(),
        "{stage}: descriptor stack contains duplicate identities"
    );
    let expected_free: BTreeSet<u32> = (0..f.payload.state.count())
        .filter(|index| !live_descriptors.contains(index))
        .collect();
    assert_eq!(
        free_descriptors, expected_free,
        "{stage}: exact descriptor free-stack census"
    );
    for kind in [PoolKind::PacketHeader, PoolKind::ReadResponse] {
        let snapshot = f.arena.pools().snapshot(kind);
        let free = f.arena.pools().free_stack(kind);
        let mut counts = Vec::new();
        f.arena.pools().device_counts_into(kind, &mut counts);
        assert_eq!(
            free.iter().copied().collect::<BTreeSet<_>>().len(),
            free.len(),
            "{stage}: {kind:?} free stack repeats an index"
        );
        for (index, &(class, _)) in snapshot.iter().enumerate() {
            let index = index as u32;
            let expected = if kind == PoolKind::PacketHeader {
                usize::from(live_headers.contains(&index))
            } else if index == source {
                live_descriptors.len()
            } else {
                0
            };
            assert_eq!(
                (
                    counts[index as usize] as usize,
                    class,
                    free.contains(&index)
                ),
                (
                    expected,
                    if expected == 0 { FREE } else { NIC_HELD },
                    expected == 0
                ),
                "{stage}: {kind:?} buffer {index} (device references, class, free)"
            );
        }
    }
}

fn recording(f: &mut Fixture) {
    f.header.state.record_returns();
    f.payload.state.record_returns();
    f.receive_ops.state.record_returns();
    f.burst.port_mut().record_build = true;
}

fn closed(f: &mut Fixture) {
    let calls = f.burst.port().calls;
    let header = [0x58; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"closed"), Payload::EMPTY],
    };
    assert_eq!(f.burst.send(&[datagram]), Err(DatagramError::Closed));
    let mut leases = [None];
    let mut meta = [Received::default()];
    assert_eq!(
        f.burst.receive(f.receive, &mut leases, &mut meta),
        Err(DatagramError::Closed)
    );
    f.burst.reclaim();
    assert_eq!(f.burst.port().calls, calls);
}

fn free_census(arena: &BufferArena<TestPlatform>, epoch: &Epoch, ended: bool) {
    for kind in [PoolKind::PacketHeader, PoolKind::ReadResponse] {
        let snapshot = arena.pools().snapshot(kind);
        let free = arena.pools().free_stack(kind);
        let mut counts = Vec::new();
        arena.pools().device_counts_into(kind, &mut counts);
        for (index, &(class, incarnation)) in snapshot.iter().enumerate() {
            let expected = if ended {
                0
            } else if kind == PoolKind::PacketHeader {
                usize::from(epoch.built.iter().any(|chain| {
                    epoch.possible.contains(&chain[0].mbuf.addr())
                        && chain[0].reference.unwrap().1 as usize == index
                }))
            } else if epoch.source.1 as usize == index {
                epoch.possible.len()
            } else {
                0
            };
            assert_eq!(counts[index] as usize, expected);
            assert_eq!(class, if expected == 0 { FREE } else { NIC_HELD });
            assert_eq!(free.contains(&(index as u32)), expected == 0);
            if ended && kind == PoolKind::ReadResponse && index == epoch.source.1 as usize {
                assert_ne!(incarnation, epoch.source.2);
            }
        }
        assert_eq!(
            free.iter().copied().collect::<BTreeSet<_>>().len(),
            free.len()
        );
    }
}

fn post_old_receive(f: &mut Fixture) -> Vec<(u32, u64)> {
    let rx = f.receive_ops.state;
    let mut slots = [std::mem::MaybeUninit::uninit(); 2];
    assert!(rx.take(&mut slots));
    let snapshot = f.arena.pools().snapshot(PoolKind::PacketReceive);
    slots
        .into_iter()
        .map(|slot| {
            // SAFETY: the successful take initialized each slot in the leaked receive pool.
            let mbuf = unsafe { slot.assume_init() }.cast();
            f.burst.port_mut().posted.push(mbuf);
            let index = rx.index_of(mbuf.cast()).unwrap();
            assert_eq!(snapshot[index as usize].0, POSTED);
            assert_eq!(rx.returns(mbuf.cast()), 0);
            (index, snapshot[index as usize].1)
        })
        .collect()
}

fn old_receive_ended(arena: &BufferArena<TestPlatform>, rx: &OpsState, old: &[(u32, u64)]) {
    let snapshot = arena.pools().snapshot(PoolKind::PacketReceive);
    let free = arena.pools().free_stack(PoolKind::PacketReceive);
    for &(index, incarnation) in old {
        assert_eq!(
            rx.returns(rx.object(index)),
            1,
            "epoch 1 receive return count"
        );
        assert_eq!(snapshot[index as usize], (FREE, incarnation + 1));
        assert!(free.contains(&index));
    }
}

fn distinct_receive_epoch(
    arena: &BufferArena<TestPlatform>,
    rx: &OpsState,
    acquired: &[*mut sys::rte_mbuf],
    old: &[(u32, u64)],
) {
    let snapshot = arena.pools().snapshot(PoolKind::PacketReceive);
    assert_eq!(
        acquired
            .iter()
            .map(|p| p.addr())
            .collect::<BTreeSet<_>>()
            .len(),
        acquired.len(),
        "each acquisition is its own buffer"
    );
    let mut reused = 0;
    for &mbuf in acquired {
        let index = rx.index_of(mbuf.cast()).unwrap();
        let identity = (index, snapshot[index as usize].1);
        assert!(
            !old.contains(&identity),
            "epoch 1 proof cannot cover epoch 2 posting"
        );
        reused += usize::from(old.iter().any(|&(at, _)| at == index));
    }
    if !acquired.is_empty() {
        assert_eq!(reused, old.len());
    }
}

fn uncertain(accepted: usize, retain: bool, proven: bool) {
    let mut f = fixture();
    recording(&mut f);
    let old_receive = post_old_receive(&mut f);
    let retained = source(f.arena, 0x59);
    let source_id = retained.identity();
    let header = [0x59; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Retained(retained.source(0..64).unwrap()),
            Payload::EMPTY,
        ],
    };
    let port = f.burst.port_mut();
    port.accept = accepted;
    port.prepare = 3;
    port.uncertain = true;
    port.retain_uncertain = retain;
    port.proven_stops = u32::from(proven);
    assert_eq!(f.burst.send(&[datagram; 4]), Ok(accepted));
    drop(retained);
    let epoch = Epoch::capture(&f, accepted, retain, source_id);
    epoch.check(f.header.state, f.payload.state, false);
    free_census(f.arena, &epoch, false);
    assert!(f.burst.poisoned());
    assert_eq!(f.burst.report().prepare_refused, 1);
    assert_eq!(f.burst.report().quarantined, 1);
    let calls = f.burst.port().calls;
    let inline = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"poisoned"), Payload::EMPTY],
    };
    assert_eq!(
        f.burst.send(&[inline]),
        Err(DatagramError::Failed {
            code: Some(libc::EIO)
        })
    );
    assert_eq!(f.burst.port().calls, calls);
    let port = f.burst.port_mut();
    port.cleanup = (99, 0);
    epoch.check(f.header.state, f.payload.state, false);
    let boundary = std::rc::Rc::new(Cell::new(false));
    if proven {
        let seen = boundary.clone();
        let ledger = epoch.clone();
        let old = old_receive.clone();
        let (h, p, rx) = (f.header.state, f.payload.state, f.receive_ops.state);
        let arena = f.arena;
        f.burst.port_mut().before_restart = Some(Box::new(move || {
            ledger.check(h, p, true);
            free_census(arena, &ledger, true);
            assert_eq!(h.report().stray, 0);
            assert_eq!(p.report().stray, 0);
            old_receive_ended(arena, rx, &old);
            assert_eq!(rx.pool().report().posted, 0);
            seen.set(true);
        }));
    }
    f.burst.reclaim();
    assert_eq!(f.burst.port().stops, 1);
    assert_eq!(f.burst.port().cleanups, 0);
    assert_eq!(f.burst.report().recoveries, u64::from(proven));
    assert_eq!(boundary.get(), proven);
    if proven {
        assert_eq!(f.burst.link(), Link::Up);
        assert!(!f.burst.poisoned());
        assert_eq!(f.burst.port().restarts, 1);
        let report = f.burst.report();
        assert_eq!(
            (
                report.quarantined,
                report.quarantine_returned,
                report.quarantine_released
            ),
            (1, u64::from(retain), u64::from(!retain)),
            "the quarantined chain settles once: returned by the device's stop when the device kept it, released by reconciliation otherwise"
        );
        assert_eq!(f.burst.port().acquired.len(), 7);
        distinct_receive_epoch(
            f.arena,
            f.receive_ops.state,
            &f.burst.port().acquired,
            &old_receive,
        );
        epoch.check(f.header.state, f.payload.state, true);
        free_census(f.arena, &epoch, true);
        let reused = source(f.arena, 0x60);
        assert_eq!(reused.identity().0, source_id.0);
        assert_ne!(reused.identity().1, source_id.1);
        let next = Outgoing {
            peer: PeerId(0),
            header: &header,
            payload: [
                Payload::Retained(reused.source(0..64).unwrap()),
                Payload::EMPTY,
            ],
        };
        assert_eq!(f.burst.send(&[next]), Ok(accepted.min(1)));
        let next_header = &f.burst.port().built[4][0];
        let old_header = epoch
            .built
            .iter()
            .map(|chain| &chain[0])
            .find(|segment| segment.mbuf == next_header.mbuf)
            .expect("header address reused");
        assert_eq!(
            next_header.reference.unwrap().1,
            old_header.reference.unwrap().1
        );
        assert_ne!(
            next_header.reference.unwrap().2,
            old_header.reference.unwrap().2
        );
        let mut reused_segments = 0;
        for new in &f.burst.port().built[4] {
            for old in epoch.built.iter().flatten() {
                if new.mbuf == old.mbuf {
                    reused_segments += 1;
                    assert_ne!(new.reference, old.reference);
                }
            }
        }
        assert!(reused_segments > 0);
    } else {
        assert_eq!(f.burst.link(), Link::Lost);
        // The unproven stop settles nothing: the custody census holds before any call on the Lost link.
        assert!(f.burst.poisoned());
        assert_eq!(f.burst.port().restarts, 0);
        epoch.check(f.header.state, f.payload.state, false);
        free_census(f.arena, &epoch, false);
        closed(&mut f);
        assert!(f.burst.poisoned());
        assert_eq!(f.burst.port().restarts, 0);
        epoch.check(f.header.state, f.payload.state, false);
        free_census(f.arena, &epoch, false);
        assert_eq!(
            (
                f.header.state.report().stray,
                f.payload.state.report().stray
            ),
            (0, 0)
        );
        let snapshot = f.arena.pools().snapshot(PoolKind::PacketReceive);
        let free = f.arena.pools().free_stack(PoolKind::PacketReceive);
        for &(index, incarnation) in &old_receive {
            assert_eq!(snapshot[index as usize], (POSTED, incarnation));
            assert!(!free.contains(&index));
            assert_eq!(
                f.receive_ops
                    .state
                    .returns(f.receive_ops.state.object(index)),
                0
            );
        }
    }
}

fn restart(acquisitions: usize, second_proven: bool, fails: bool) {
    let mut f = fixture();
    recording(&mut f);
    let old_receive = post_old_receive(&mut f);
    let retained = source(f.arena, 0x5a);
    let source_id = retained.identity();
    let header = [0x5a; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Retained(retained.source(0..64).unwrap()),
            Payload::EMPTY,
        ],
    };
    let port = f.burst.port_mut();
    port.prepare = 3;
    port.accept = 1;
    port.uncertain = true;
    assert_eq!(f.burst.send(&[datagram; 4]), Ok(1));
    drop(retained);
    assert!(f.burst.poisoned());
    assert_eq!(f.burst.report().quarantined, 1);
    let epoch = Epoch::capture(&f, 1, true, source_id);
    epoch.check(f.header.state, f.payload.state, false);
    let seen = std::rc::Rc::new(Cell::new(false));
    let boundary = seen.clone();
    let (h, p, rx) = (f.header.state, f.payload.state, f.receive_ops.state);
    let arena = f.arena;
    let old = old_receive.clone();
    f.burst.port_mut().before_restart = Some(Box::new(move || {
        epoch.check(h, p, true);
        free_census(arena, &epoch, true);
        assert_eq!(h.report().stray, 0);
        assert_eq!(p.report().stray, 0);
        assert_eq!(arena.report(PoolKind::PacketHeader).mismatched, 0);
        assert_eq!(arena.report(PoolKind::ReadResponse).mismatched, 0);
        old_receive_ended(arena, rx, &old);
        assert_eq!(rx.pool().report().posted, 0);
        assert_eq!(rx.pool().report().free, COUNT);
        boundary.set(true);
    }));
    let acquired_epoch = std::rc::Rc::new(std::cell::RefCell::new(None));
    let acquisition_log = acquired_epoch.clone();
    let arena = f.arena;
    f.burst.port_mut().after_acquire = Some(Box::new(move || {
        let snapshot = arena.pools().snapshot(PoolKind::PacketReceive);
        let identities: Vec<_> = snapshot
            .iter()
            .enumerate()
            .filter_map(|(index, &(class, incarnation))| {
                (class == POSTED).then_some((index as u32, incarnation))
            })
            .collect();
        assert_eq!(identities.len(), acquisitions);
        *acquisition_log.borrow_mut() = Some(identities);
    }));
    let port = f.burst.port_mut();
    port.proven_stops = if second_proven { 2 } else { 1 };
    if fails {
        port.restart_error = Some(libc::EIO);
        port.restart_acquire = acquisitions;
    }
    f.burst.reclaim();
    assert!(seen.get());
    assert!(!f.burst.poisoned());
    if fails {
        closed(&mut f);
    }
    let acquired_ids = acquired_epoch
        .borrow_mut()
        .take()
        .expect("restart acquisition boundary reached");
    let port = f.burst.port();
    assert_eq!((port.stops, port.restarts), (if fails { 2 } else { 1 }, 1));
    assert_eq!(port.acquired.len(), acquisitions);
    let acquired: BTreeSet<_> = port.acquired.iter().map(|p| p.addr()).collect();
    assert_eq!(acquired.len(), acquisitions);
    let old_identities: BTreeSet<_> = old_receive.iter().copied().collect();
    let new_identities: BTreeSet<_> = acquired_ids.iter().copied().collect();
    assert!(old_identities.is_disjoint(&new_identities));
    if acquisitions > 0 {
        assert_eq!(
            old_receive
                .iter()
                .filter(|&&(old_index, _)| acquired_ids
                    .iter()
                    .any(|&(index, _)| index == old_index))
                .count(),
            old_receive.len()
        );
    }
    let held = !fails || !second_proven;
    assert_eq!(
        port.posted
            .iter()
            .map(|p| p.addr())
            .collect::<BTreeSet<_>>(),
        if held {
            acquired.clone()
        } else {
            BTreeSet::new()
        }
    );
    for &mbuf in &port.acquired {
        assert_eq!(
            rx.returns(mbuf.cast()),
            usize::from(!held)
                + usize::from(
                    old_receive
                        .iter()
                        .any(|&(index, _)| rx.object(index) == mbuf.cast())
                ),
            "restart epoch 2 receive {:?} return count",
            mbuf
        );
    }
    let snapshot = f.arena.pools().snapshot(PoolKind::PacketReceive);
    let free = f.arena.pools().free_stack(PoolKind::PacketReceive);
    assert_eq!(acquired_ids.len(), acquisitions);
    for &(index, incarnation) in acquired_ids.iter() {
        assert!(acquired.contains(&rx.object(index).addr()));
        assert_eq!(
            free.contains(&index),
            !held,
            "epoch 2 acquisition reached free stack"
        );
        assert_eq!(snapshot[index as usize].0, if held { POSTED } else { FREE });
        assert_eq!(snapshot[index as usize].1, incarnation + u64::from(!held));
    }
    assert_eq!(
        free.iter().copied().collect::<BTreeSet<_>>().len(),
        free.len()
    );
    assert_eq!(
        free.len(),
        COUNT as usize - if held { acquisitions } else { 0 }
    );
    assert_eq!(
        rx.pool().report().posted,
        if held { acquisitions as u32 } else { 0 }
    );
    assert_eq!(rx.report().stray, 0);
    assert_eq!(f.arena.report(PoolKind::PacketReceive).mismatched, 0);
    assert_eq!(f.burst.report().recoveries, u64::from(!fails));
    assert_eq!(f.burst.report().restart_error, fails.then_some(libc::EIO));
    assert_eq!(
        f.burst.link(),
        if !fails {
            Link::Up
        } else if second_proven {
            Link::Down
        } else {
            Link::Lost
        }
    );
}

/// Runs the burst of the uncertain cases on a port that reports no uncertain post, then a second send and a
/// reclaim. Four datagrams share one retained source; the port prepares three and accepts `accepted`. Only
/// the accepted chains stay in custody, the transport is not poisoned, the second send reaches the port,
/// and the reclaim stops nothing and leaves the link Up.
fn certain(accepted: usize) {
    let mut f = fixture();
    recording(&mut f);
    let retained = source(f.arena, 0x59);
    let source_id = retained.identity();
    let header = [0x59; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [
            Payload::Retained(retained.source(0..64).unwrap()),
            Payload::EMPTY,
        ],
    };
    let port = f.burst.port_mut();
    port.accept = accepted;
    port.prepare = 3;
    port.uncertain = false;
    port.retain_uncertain = false;
    port.proven_stops = 0;
    assert_eq!(f.burst.send(&[datagram; 4]), Ok(accepted));
    drop(retained);

    // Premises: the port saw four chains of a header and one descriptor, each descriptor naming the shared
    // source and each header its own buffer, and the mock device holds and logged the accepted prefix.
    let mut built = f.burst.port().built.clone();
    assert_eq!(built.len(), 4);
    let source_token = (
        PoolKind::ReadResponse.index() as u16,
        source_id.0,
        source_id.1,
    );
    for chain in &built {
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].reference, Some(source_token));
        let token = chain[0].reference.expect("an armed header token");
        assert_eq!(token.0, PoolKind::PacketHeader.index() as u16);
        assert_eq!(f.header.state.index_of(chain[0].mbuf.cast()), Some(token.1));
    }
    let head = |at: usize| built[at][0].mbuf.addr();
    let accepted_set: BTreeSet<_> = (0..accepted).map(head).collect();
    assert_eq!(
        f.burst
            .port()
            .held
            .iter()
            .map(|p| p.addr())
            .collect::<BTreeSet<_>>(),
        accepted_set
    );
    assert_eq!(
        f.burst
            .port()
            .accepted
            .logged()
            .iter()
            .map(|p| p.addr())
            .collect::<BTreeSet<_>>(),
        accepted_set
    );

    let mut live: BTreeSet<usize> = (0..accepted).collect();
    chain_census(&f, &built, &live, source_id.0, "after the send");
    let report = f.burst.report();
    assert_eq!((report.quarantined, report.prepare_refused), (0, 1));
    assert!(!f.burst.poisoned());

    // The transport is not poisoned, so the next send goes to the port, which accepts as many as before.
    let inline = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(b"after"), Payload::EMPTY],
    };
    let calls = f.burst.port().calls;
    assert_eq!(f.burst.send(&[inline]), Ok(accepted));
    assert_ne!(f.burst.port().calls, calls);
    built = f.burst.port().built.clone();
    assert_eq!(built.len(), 5, "the inline datagram is a fifth chain");
    if accepted == 1 {
        live.insert(4);
    }

    // The cleanup reports 99 finished transmits and frees none, so a reclaim that trusted the number would
    // release chains the device still holds.
    f.burst.port_mut().cleanup = (99, 0);
    f.burst.reclaim();
    let port = f.burst.port();
    assert_eq!(
        (
            port.stops,
            port.cleanups,
            port.restarts,
            f.burst.report().recoveries,
            f.burst.link(),
            f.burst.poisoned()
        ),
        (0, u32::from(accepted > 0), 0, 0, Link::Up, false)
    );
    chain_census(&f, &built, &live, source_id.0, "after the reclaim");
    assert_eq!(
        (
            f.header.state.report().stray,
            f.payload.state.report().stray
        ),
        (0, 0)
    );
}

fn run_case(name: &str) {
    let &(name, run) = CASES
        .iter()
        .find(|case| case.0 == name)
        .expect("case declared in frozen inventory");
    let (sent, received) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        run();
        sent.send(()).unwrap();
    });
    match received.recv_timeout(DEADLINE) {
        Ok(()) => thread.join().unwrap(),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            std::panic::resume_unwind(thread.join().unwrap_err())
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("{name} missing witness within {DEADLINE:?}")
        }
    }
}

#[test]
fn short_retained_uncertainty_keeps_each_identity_until_proof() {
    run_case("short-retained-unproven");
}
#[test]
fn short_unretained_uncertainty_keeps_each_identity_until_proof() {
    run_case("short-unretained-unproven");
}
#[test]
fn zero_retained_uncertainty_keeps_each_identity_until_proof() {
    run_case("zero-retained-unproven");
}
#[test]
fn zero_unretained_uncertainty_keeps_each_identity_until_proof() {
    run_case("zero-unretained-unproven");
}
#[test]
fn proven_stop_returns_short_retained_epoch_once() {
    run_case("short-retained-proven");
}
#[test]
fn proven_stop_returns_short_unretained_epoch_once() {
    run_case("short-unretained-proven");
}
#[test]
fn proven_stop_returns_zero_retained_epoch_once() {
    run_case("zero-retained-proven");
}
#[test]
fn proven_stop_returns_zero_unretained_epoch_once() {
    run_case("zero-unretained-proven");
}
#[test]
fn failed_restart_keeps_nonempty_acquisitions_after_unproven_second_stop() {
    run_case("restart-acquired-lost");
}
#[test]
fn failed_restart_returns_nonempty_acquisitions_after_proven_second_stop() {
    run_case("restart-acquired-down");
}
#[test]
fn empty_failed_restart_leaves_lost_after_unproven_second_stop() {
    run_case("restart-empty-lost");
}
#[test]
fn empty_failed_restart_leaves_down_after_proven_second_stop() {
    run_case("restart-empty-down");
}
#[test]
fn successful_restart_acquires_its_own_epoch() {
    run_case("restart-success");
}
#[test]
fn ena_case_inventory_is_frozen() {
    assert_eq!(
        REQUIRED.iter().copied().collect::<BTreeSet<_>>().len(),
        REQUIRED.len()
    );
    assert_eq!(CASES.map(|case| case.0), REQUIRED);
}
#[test]
fn every_required_ena_case_is_witnessed() {
    let mut witnessed = BTreeSet::new();
    for case in &CASES {
        run_case(case.0);
        assert!(witnessed.insert(case.0));
    }
    assert!(REQUIRED.iter().all(|case| witnessed.contains(case)));
}

/// One chain accepted and the short post certain: the accepted chain alone stays in custody, and the three
/// refused chains return once.
#[test]
fn a_certain_short_post_after_one_accepted_chain_holds_that_chain_alone() {
    certain(1);
}

/// Nothing accepted and the refusal certain: every chain returns once and nothing stays in custody.
#[test]
fn a_certain_post_with_nothing_accepted_holds_nothing() {
    certain(0);
}
