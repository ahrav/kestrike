//! Every child owns its environment, registered arena and pools through final teardown.

#[cfg(kestrike_asan)]
use std::num::NonZeroU32;
#[cfg(kestrike_asan)]
use std::path::Path;
#[cfg(kestrike_asan)]
use std::sync::Arc;
#[cfg(kestrike_asan)]
use std::time::{Duration, Instant};

#[cfg(kestrike_asan)]
use spdk_sys as sys;

use super::*;
use crate::exact_child;
#[cfg(kestrike_asan)]
use crate::exact_child::{ExactChild, Outcome};
#[cfg(kestrike_asan)]
use crate::native::{
    ArenaRegistration, Burst, DeviceLease, DmaPolicy, EnvConfig, Environment, Health,
    PacketMempool, Port, Prepared, Station, Supervisor, TxBurst, Unproven, Watchdog, Wire,
};
#[cfg(kestrike_asan)]
use crate::net::{Datagrams, Outgoing, PacketPool, Payload, PeerId};
#[cfg(kestrike_asan)]
use crate::storage::{
    BufferArena, BufferConfig, EngineBudget, HugepageSize, LinuxPlatform, NodeMask, PoolKind,
    PoolSpec, Released,
};

#[cfg(kestrike_asan)]
const DEADLINE: Duration = Duration::from_secs(60);
const PREFIX: &str = "native::chain_tests::real::";
const REQUIRED: [&str; 12] = [
    "inline_only",
    "one_retained",
    "two_retained",
    "mixed_pools",
    "shared_source",
    "prepare_partial",
    "burst_partial",
    "uncertain_retained",
    "uncertain_unretained",
    "application_holder",
    "reuse",
    "invalid_contract_double_free",
];
#[cfg(kestrike_asan)]
const POOLS: [PoolSpec; 5] = [
    PoolSpec {
        kind: PoolKind::ReadResponse,
        count: 8,
        buffer_len: 16384,
    },
    PoolSpec {
        kind: PoolKind::ReceiveWrite,
        count: 1,
        buffer_len: 2097152,
    },
    PoolSpec {
        kind: PoolKind::Maintenance,
        count: 1,
        buffer_len: 4096,
    },
    PoolSpec {
        kind: PoolKind::PacketReceive,
        count: 8,
        buffer_len: 16384,
    },
    PoolSpec {
        kind: PoolKind::PacketHeader,
        count: 8,
        buffer_len: 4096,
    },
];
#[cfg(kestrike_asan)]
const LOCAL: Station = Station {
    mac: [2, 0, 0, 0, 0, 1],
    ip: [10, 0, 0, 1],
    port: 7000,
    ports: 1,
};
#[cfg(kestrike_asan)]
const PEERS: [Station; 1] = [Station {
    mac: [2, 0, 0, 0, 0, 2],
    ip: [10, 0, 0, 2],
    port: 9000,
    ports: 1,
}];

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    pieces: usize,
    sources: usize,
    chains: usize,
    prepared: usize,
    accepted: usize,
    uncertain: bool,
    retained: bool,
    application: bool,
    episodes: u32,
}

fn cases() -> [Case; 11] {
    let base = Case {
        name: "inline_only",
        pieces: 0,
        sources: 0,
        chains: 1,
        prepared: 1,
        accepted: 1,
        uncertain: false,
        retained: false,
        application: false,
        episodes: 1,
    };
    let one = Case {
        name: "one_retained",
        pieces: 1,
        sources: 1,
        ..base
    };
    let two = Case {
        name: "two_retained",
        pieces: 2,
        ..one
    };
    let shared = Case {
        name: "shared_source",
        chains: 4,
        prepared: 4,
        accepted: 4,
        ..two
    };
    let uncertain = Case {
        name: "uncertain_retained",
        prepared: 3,
        accepted: 1,
        uncertain: true,
        retained: true,
        ..shared
    };
    [
        base,
        one,
        two,
        Case {
            name: "mixed_pools",
            sources: 2,
            ..two
        },
        shared,
        Case {
            name: "prepare_partial",
            prepared: 3,
            accepted: 3,
            ..shared
        },
        Case {
            name: "burst_partial",
            accepted: 2,
            ..shared
        },
        uncertain,
        Case {
            name: "uncertain_unretained",
            retained: false,
            ..uncertain
        },
        Case {
            name: "application_holder",
            application: true,
            chains: 2,
            prepared: 2,
            accepted: 2,
            ..one
        },
        Case {
            name: "reuse",
            episodes: 2,
            ..two
        },
    ]
}

#[cfg(kestrike_asan)]
struct Contain;
#[cfg(kestrike_asan)]
impl Supervisor for Contain {
    fn contain(&self) {
        panic!("native chain teardown deadline");
    }
}

#[cfg(kestrike_asan)]
struct NativePort {
    lease: DeviceLease,
    case: Case,
    episode: u32,
    built: Vec<Segment>,
    held: Vec<*mut sys::rte_mbuf>,
    frees: usize,
}

#[cfg(kestrike_asan)]
impl NativePort {
    fn return_one(&mut self) {
        let head = self.held.remove(0);
        self.frees += 1;
        // SAFETY: the scripted device owns this accepted chain and returns it exactly once through DPDK.
        unsafe { sys::spdk_sys_rte_pktmbuf_free(head) };
    }
}

// SAFETY: prepare preserves every pointer; acceptance and uncertainty match held chains. A proven stop returns all held chains through their real pools before it answers. This port posts zero receive buffers and drives its one lease.
#[cfg(kestrike_asan)]
unsafe impl Port for NativePort {
    fn device_lease(&self) -> Option<&DeviceLease> {
        Some(&self.lease)
    }
    fn rx_burst(&mut self, _: &mut [*mut sys::rte_mbuf]) -> usize {
        0
    }
    unsafe fn tx_prepare(&mut self, packets: &mut [*mut sys::rte_mbuf]) -> Prepared {
        for (chain, &head) in packets.iter().enumerate() {
            let mut at = head;
            let mut position = 0;
            while !at.is_null() {
                // SAFETY: the sending burst owns the chain, and each real pool's pool_data names its live OpsState on this thread.
                let (ops, next) = unsafe {
                    (
                        &*(*(*at).pool)
                            .__bindgen_anon_1
                            .pool_data
                            .cast::<crate::native::OpsState>(),
                        (*at).next,
                    )
                };
                // SAFETY: prepare owns exclusive readable access to every segment's private area.
                let token = unsafe { ops.reference(at.cast()) }.unwrap();
                self.built.push(Segment {
                    episode: self.episode,
                    chain,
                    address: at.addr(),
                    pool: usize::from(position > 0),
                    index: ops.index_of(at.cast()).unwrap(),
                    token: Identity(token.0, token.1, token.2),
                    baseline: ops.returns(at.cast()),
                });
                at = next;
                position += 1;
                assert!(position <= 3);
            }
            assert_eq!(position, self.case.pieces + 1);
        }
        let count = packets.len().min(self.case.prepared);
        Prepared {
            count,
            error: (count < packets.len()).then_some(libc::EINVAL),
        }
    }
    unsafe fn tx_burst(&mut self, packets: &mut [*mut sys::rte_mbuf]) -> TxBurst {
        let accepted = packets.len().min(self.case.accepted);
        self.held.extend_from_slice(&packets[..accepted]);
        if self.case.uncertain && self.case.retained {
            self.held.push(packets[accepted]);
        }
        TxBurst {
            accepted,
            uncertain: self.case.uncertain,
        }
    }
    fn tx_cleanup(&mut self, _: NonZeroU32) -> i32 {
        99
    }
    fn max_segments(&self) -> u16 {
        3
    }
    fn rx_ring(&self) -> u32 {
        0
    }
    fn service(&mut self) -> Health {
        Health::Running
    }
    fn stop(&mut self) -> Result<(), Unproven> {
        while !self.held.is_empty() {
            self.return_one();
        }
        Ok(())
    }
    fn reset(&mut self) -> Result<(), i32> {
        Ok(())
    }
    fn reinitialize(&mut self) -> Result<(), i32> {
        Ok(())
    }
    fn start(&mut self) -> Result<(), i32> {
        Ok(())
    }
}

#[cfg(kestrike_asan)]
fn observe(
    ledger: &Ledger,
    arena: &BufferArena<LinuxPlatform>,
    header: &PacketMempool<'_>,
    payload: &PacketMempool<'_>,
) -> Boundary {
    let mut seen = Boundary {
        descriptors: payload.ops().descriptor_stack(),
        ..Boundary::default()
    };
    for segment in &ledger.segments {
        let ops = if segment.pool == 0 {
            header.ops()
        } else {
            payload.ops()
        };
        let object = ops.object(segment.index);
        assert_eq!(object.addr(), segment.address);
        // SAFETY: observations run on the owner thread between scripted device calls, with all pool memory live.
        let token = unsafe { ops.reference(object) }.map(|id| Identity(id.0, id.1, id.2));
        seen.segments.insert(
            segment.address,
            Observation {
                returns: ops.returns(object),
                token,
                out: segment.pool == 1 && ops.descriptor_out(object),
            },
        );
    }
    for kind in [PoolKind::PacketHeader, PoolKind::ReadResponse] {
        let snapshot = arena.pools().snapshot(kind);
        let free = arena.pools().free_stack(kind);
        assert_eq!(
            free.iter().copied().collect::<BTreeSet<_>>().len(),
            free.len()
        );
        let mut counts = Vec::new();
        arena.pools().device_counts_into(kind, &mut counts);
        for (index, (class, incarnation)) in snapshot.into_iter().enumerate() {
            seen.buffers.insert(
                (kind.index() as u16, index as u32),
                Census {
                    class,
                    incarnation,
                    nic: counts[index],
                    free: free.contains(&(index as u32)),
                },
            );
        }
    }
    assert_eq!(header.report().stray, 0);
    assert_eq!(payload.report().stray, 0);
    seen
}

#[cfg(kestrike_asan)]
fn report_ledger(ledger: &Ledger) {
    exact_child::report(&format!(
        "ledger {} {} {} {}",
        ledger.segments[0].episode, ledger.headers, ledger.descriptors, ledger.source_count
    ));
    for id in &ledger.sources {
        exact_child::report(&format!("source {} {} {}", id.0, id.1, id.2));
    }
    for s in &ledger.segments {
        exact_child::report(&format!(
            "segment {} {} {} {} {} {} {} {}",
            s.chain, s.address, s.pool, s.index, s.token.0, s.token.1, s.token.2, s.baseline
        ));
    }
}

#[cfg(kestrike_asan)]
fn report_boundary(phase: usize, seen: &Boundary, frees: usize) {
    exact_child::report(&format!("boundary {phase} {frees}"));
    for (address, o) in &seen.segments {
        let Identity(kind, index, incarnation) = o.token.unwrap_or(Identity(0, 0, 0));
        exact_child::report(&format!(
            "observed {address} {} {} {kind} {index} {incarnation} {}",
            o.returns,
            usize::from(o.token.is_some()),
            usize::from(o.out)
        ));
    }
    for ((kind, index), c) in &seen.buffers {
        exact_child::report(&format!(
            "census {kind} {index} {} {} {} {}",
            c.class,
            c.incarnation,
            c.nic,
            usize::from(c.free)
        ));
    }
    exact_child::report(&format!(
        "stack {}",
        seen.descriptors
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    ));
}

fn held(case: Case) -> BTreeSet<usize> {
    (0..case.accepted + usize::from(case.uncertain)).collect()
}

#[cfg(kestrike_asan)]
fn execute(case: Case, invalid: bool) {
    assert_eq!(
        std::env::var("ASAN_OPTIONS").as_deref(),
        Ok("detect_leaks=0")
    );
    // SAFETY: sched_getcpu reads the calling thread's processor.
    let core = u32::try_from(unsafe { libc::sched_getcpu() }).unwrap();
    let config = EnvConfig {
        core,
        hugepage_dir: Path::new("/dev/hugepages"),
        allowed: &[],
    };
    let node = std::env::var("KESTRIKE_CHAIN_NODE")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .unwrap();
    let buffers = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[node]).unwrap(),
        pools: &POOLS,
    };
    let buffers = buffers.validate().unwrap();
    exact_child::report(&format!(
        "inputs core={core} node={node} page=2097152 backing={} hugedir=/dev/hugepages no_pci=true",
        buffers.backing_len()
    ));
    let env = Environment::initialize(&config).unwrap();
    let mut budget = EngineBudget::unlimited();
    let arena = BufferArena::initialize(&buffers, LinuxPlatform, &mut budget).unwrap();
    let mut registration = ArenaRegistration::register(
        &env,
        &arena,
        DmaPolicy {
            allow_no_iommu: true,
        },
    )
    .unwrap();
    registration.map().unwrap();
    registration.verify().unwrap();
    let lease = registration.device_attached();
    let view = PacketPool::new(&arena, PoolKind::PacketReceive, 2).unwrap();
    let receive =
        PacketMempool::receive(&view, &registration, &lease, c"chain-rx", &mut budget).unwrap();
    let header =
        PacketMempool::header(&arena, &registration, &lease, c"chain-header", &mut budget).unwrap();
    let payload = PacketMempool::payload(
        &arena,
        &registration,
        &lease,
        c"chain-payload",
        16,
        &mut budget,
    )
    .unwrap();
    for pool in [&header, &payload] {
        pool.ops().record_returns();
    }
    let wire = Wire::new(LOCAL, &PEERS, &mut budget).unwrap();
    let port = NativePort {
        lease,
        case,
        episode: 1,
        built: Vec::new(),
        held: Vec::new(),
        frees: 0,
    };
    let mut burst = Burst::over(
        port,
        wire,
        [&header, &payload, &receive],
        &registration,
        crate::native::mock::watch(),
        4,
        &mut budget,
    )
    .unwrap();
    let mut previous: Option<Ledger> = None;
    let mut duplicate: *mut sys::rte_mbuf = std::ptr::null_mut();
    for episode in 1..=case.episodes {
        burst.port_mut().episode = episode;
        burst.port_mut().built.clear();
        burst.port_mut().frees = 0;
        let mut sources: Vec<_> = (0..case.sources)
            .map(|_| arena.acquire(PoolKind::ReadResponse).unwrap())
            .collect();
        for source in &mut sources {
            source.bytes_mut()[..128].fill(0x59);
        }
        let identities = sources
            .iter()
            .map(|source| {
                let (index, incarnation) = source.identity();
                Identity(0, index, incarnation)
            })
            .collect();
        let piece = |at: usize| sources[at % sources.len()].source(0..64).unwrap();
        let datagram = Outgoing {
            peer: PeerId(0),
            header: &[0x58; 192],
            payload: match case.pieces {
                0 => [Payload::Inline(b"inline"), Payload::EMPTY],
                1 => [Payload::Retained(piece(0)), Payload::EMPTY],
                2 => [Payload::Retained(piece(0)), Payload::Retained(piece(1))],
                _ => unreachable!(),
            },
        };
        assert_eq!(burst.send(&vec![datagram; case.chains]), Ok(case.accepted));
        let ledger = Ledger {
            segments: burst.port().built.clone(),
            sources: identities,
            headers: 8,
            descriptors: 16,
            source_count: 8,
        };
        assert_eq!(ledger.segments.len(), case.chains * (case.pieces + 1));
        if let Some(old) = previous.take() {
            for next in &ledger.segments {
                let old = old
                    .segments
                    .iter()
                    .find(|old| old.address == next.address)
                    .expect("reuse occupies the same segment address");
                assert_eq!(old.pool, next.pool);
                assert_ne!(old.episode, next.episode);
                assert_ne!(old.token, next.token);
                assert_eq!(next.baseline, old.baseline + 1);
            }
        }
        duplicate = ledger
            .segments
            .iter()
            .find(|s| s.pool == 1)
            .map_or(std::ptr::null_mut(), |s| {
                payload.ops().object(s.index).cast()
            });
        report_ledger(&ledger);
        let pending = held(case);
        let seen = observe(&ledger, &arena, &header, &payload);
        ledger.judge(&pending, true, &seen).unwrap();
        report_boundary(0, &seen, 0);
        if !case.application {
            sources.clear();
        }
        let seen = observe(&ledger, &arena, &header, &payload);
        ledger.judge(&pending, case.application, &seen).unwrap();
        report_boundary(1, &seen, 0);
        if case.uncertain {
            assert!(burst.poisoned());
            burst.reclaim();
            assert!(!burst.poisoned());
            assert_eq!(burst.report().quarantine_returned, u64::from(case.retained));
            assert_eq!(
                burst.report().quarantine_released,
                u64::from(!case.retained)
            );
            let seen = observe(&ledger, &arena, &header, &payload);
            ledger
                .judge(&BTreeSet::new(), case.application, &seen)
                .unwrap();
            report_boundary(2, &seen, burst.port().frees);
        } else {
            for returned in 0..case.accepted {
                burst.port_mut().return_one();
                let pending = (returned + 1..case.accepted).collect();
                let seen = observe(&ledger, &arena, &header, &payload);
                ledger.judge(&pending, case.application, &seen).unwrap();
                report_boundary(returned + 2, &seen, burst.port().frees);
            }
        }
        sources.clear();
        let seen = observe(&ledger, &arena, &header, &payload);
        ledger.judge(&BTreeSet::new(), false, &seen).unwrap();
        report_boundary(99, &seen, burst.port().frees);
        previous = Some(ledger);
    }
    let mut port = burst.into_port();
    port.stop().unwrap();
    let stopped = port.lease.stopped();
    let stopped = payload.release(stopped).ok().unwrap();
    if invalid {
        assert!(!duplicate.is_null());
        exact_child::report(
            "invalid-contract ready: returned descriptor backing released; second native free",
        );
        // SAFETY: deliberately violated contract: duplicate names a returned descriptor whose pool and heap backing ended. ASan must stop this second native free inside the production shim.
        unsafe { sys::spdk_sys_rte_pktmbuf_free(duplicate) };
        panic!("invalid-contract free escaped sanitizer");
    }
    let stopped = header.release(stopped).ok().unwrap();
    let stopped = receive.release(stopped).ok().unwrap();
    registration.device_stopped(stopped).unwrap();
    drop(view);
    let watchdog = Watchdog::arm(Duration::from_secs(10), Arc::new(Contain)).unwrap();
    registration.unregister(&watchdog).unwrap();
    env.finish(&watchdog).unwrap();
    assert_eq!(arena.release().unwrap(), Released::Complete);
    exact_child::report(&format!("complete {}", case.name));
}

type BoundaryReport = (usize, usize, Boundary);
type EpisodeReport = (u32, Ledger, Vec<BoundaryReport>);

fn judge_episode(
    case: Case,
    episode: u32,
    ledger: &Ledger,
    boundaries: &[BoundaryReport],
) -> Result<(), String> {
    if ledger.sources.len() != case.sources
        || ledger
            .sources
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != case.sources
        || ledger.sources.iter().any(|id| id.0 != 0)
    {
        return Err("acquired source inventory".into());
    }
    if (ledger.headers, ledger.descriptors, ledger.source_count) != (8, 16, 8) {
        return Err("pool geometry".into());
    }
    for chain in 0..case.chains {
        let segments: Vec<_> = ledger
            .segments
            .iter()
            .filter(|s| s.chain == chain)
            .collect();
        if segments.len() != case.pieces + 1
            || segments[0].pool != 0
            || segments[1..].iter().any(|s| s.pool != 1)
        {
            return Err("production chain shape".into());
        }
        for (piece, segment) in segments[1..].iter().enumerate() {
            if segment.token != ledger.sources[piece % case.sources] {
                return Err("datagram source token".into());
            }
        }
    }
    if ledger.segments.len() != case.chains * (case.pieces + 1)
        || ledger
            .segments
            .iter()
            .any(|s| s.episode != episode || s.chain >= case.chains)
    {
        return Err("episode segment inventory".into());
    }
    let mut expected = vec![
        (0, held(case), true, 0),
        (1, held(case), case.application, 0),
    ];
    if case.uncertain {
        expected.push((
            2,
            BTreeSet::new(),
            case.application,
            case.accepted + usize::from(case.retained),
        ));
    } else {
        for returned in 0..case.accepted {
            expected.push((
                returned + 2,
                (returned + 1..case.accepted).collect(),
                case.application,
                returned + 1,
            ));
        }
    }
    expected.push((
        99,
        BTreeSet::new(),
        false,
        case.accepted + usize::from(case.uncertain && case.retained),
    ));
    if boundaries.len() != expected.len() {
        return Err("missing or repeated boundary".into());
    }
    for ((phase, frees, seen), (wanted, held, app, c_calls)) in boundaries.iter().zip(expected) {
        if *phase != wanted || *frees != c_calls {
            return Err("boundary order or native invocation count".into());
        }
        ledger.judge(&held, app, seen)?;
    }
    Ok(())
}

fn judge_reports(case: Case, reports: &[String]) -> Result<(), String> {
    let id = format!("{PREFIX}{}", case.name);
    if reports
        .iter()
        .filter(|s| **s == exact_child::entered(&id))
        .count()
        != 1
        || reports
            .iter()
            .filter(|s| **s == format!("complete {}", case.name))
            .count()
            != 1
        || reports.iter().filter(|s| s.starts_with("inputs ")).count() != 1
    {
        return Err("entry, inputs or completion witness".into());
    }
    let mut episodes: Vec<EpisodeReport> = Vec::new();
    for line in reports {
        if line.starts_with("entered ")
            || line.starts_with("inputs ")
            || line.starts_with("complete ")
        {
            continue;
        }
        let (tag, rest) = line.split_once(' ').ok_or("malformed report")?;
        let nums: Vec<u64> = rest
            .split_whitespace()
            .map(str::parse)
            .collect::<Result<_, _>>()
            .map_err(|_| "malformed number")?;
        match (tag, nums.as_slice()) {
            ("ledger", &[episode, headers, descriptors, source_count]) => {
                episodes.push((
                    episode as u32,
                    Ledger {
                        segments: Vec::new(),
                        sources: Vec::new(),
                        headers: headers as u32,
                        descriptors: descriptors as u32,
                        source_count: source_count as u32,
                    },
                    Vec::new(),
                ));
            }
            ("source", &[kind, index, incarnation]) => episodes
                .last_mut()
                .ok_or("source before ledger")?
                .1
                .sources
                .push(Identity(kind as u16, index as u32, incarnation)),
            (
                "segment",
                &[
                    chain,
                    address,
                    pool,
                    index,
                    kind,
                    source,
                    incarnation,
                    baseline,
                ],
            ) => {
                let (episode, ledger, _) = episodes.last_mut().ok_or("segment before ledger")?;
                ledger.segments.push(Segment {
                    episode: *episode,
                    chain: chain as usize,
                    address: address as usize,
                    pool: pool as usize,
                    index: index as u32,
                    token: Identity(kind as u16, source as u32, incarnation),
                    baseline: baseline as usize,
                });
            }
            ("boundary", &[phase, frees]) => episodes
                .last_mut()
                .ok_or("boundary before ledger")?
                .2
                .push((phase as usize, frees as usize, Boundary::default())),
            ("observed", &[address, returns, armed, kind, index, incarnation, out])
                if armed <= 1 && out <= 1 =>
            {
                let seen = &mut episodes
                    .last_mut()
                    .ok_or("observation before ledger")?
                    .2
                    .last_mut()
                    .ok_or("observation before boundary")?
                    .2;
                if seen
                    .segments
                    .insert(
                        address as usize,
                        Observation {
                            returns: returns as usize,
                            token: (armed == 1).then_some(Identity(
                                kind as u16,
                                index as u32,
                                incarnation,
                            )),
                            out: out == 1,
                        },
                    )
                    .is_some()
                {
                    return Err("duplicate observation".into());
                }
            }
            ("census", &[kind, index, class, incarnation, nic, free]) if free <= 1 => {
                let seen = &mut episodes
                    .last_mut()
                    .ok_or("census before ledger")?
                    .2
                    .last_mut()
                    .ok_or("census before boundary")?
                    .2;
                if seen
                    .buffers
                    .insert(
                        (kind as u16, index as u32),
                        Census {
                            class: class as usize,
                            incarnation,
                            nic: nic as u16,
                            free: free == 1,
                        },
                    )
                    .is_some()
                {
                    return Err("duplicate census".into());
                }
            }
            ("stack", _) => {
                let seen = &mut episodes
                    .last_mut()
                    .ok_or("stack before ledger")?
                    .2
                    .last_mut()
                    .ok_or("stack before boundary")?
                    .2;
                if !seen.descriptors.is_empty() {
                    return Err("duplicate stack".into());
                }
                seen.descriptors = nums.iter().map(|&n| n as u32).collect();
            }
            _ => return Err(format!("unexpected report {line}")),
        }
    }
    if episodes.len() != case.episodes as usize {
        return Err("episode count".into());
    }
    for (at, (episode, ledger, boundaries)) in episodes.iter().enumerate() {
        if *episode != at as u32 + 1 {
            return Err("episode order".into());
        }
        judge_episode(case, *episode, ledger, boundaries)?;
        if at > 0 {
            let old = &episodes[at - 1].1;
            for segment in &ledger.segments {
                let prior = old
                    .segments
                    .iter()
                    .find(|old| old.address == segment.address)
                    .ok_or("missing address reuse")?;
                if segment.pool != prior.pool
                    || segment.token == prior.token
                    || segment.baseline != prior.baseline + 1
                {
                    return Err("reuse episode".into());
                }
            }
        }
    }
    Ok(())
}

#[cfg(kestrike_asan)]
fn run(name: &str) {
    let id = format!("{PREFIX}{name}");
    let invalid = name == "invalid_contract_double_free";
    let case = cases()
        .into_iter()
        .find(|case| case.name == if invalid { "one_retained" } else { name })
        .unwrap();
    assert_eq!(std::thread::current().name(), Some(id.as_str()));
    if exact_child::is_child(&id) {
        exact_child::report(&exact_child::entered(&id));
        execute(case, invalid);
        return;
    }
    let (outcome, stderr) = ExactChild::spawn_under("env", &[], &id, &[])
        .unwrap()
        .finish_observed(Instant::now() + DEADLINE);
    if invalid {
        assert!(
            super::sanitizer_control(&id, &outcome, &stderr),
            "invalid-contract native double-free: {outcome:?}"
        );
    } else {
        let Outcome::Completed { reports } = &outcome else {
            panic!("{id}: {outcome:?}")
        };
        assert!(
            stderr.iter().all(|line| !line.contains("AddressSanitizer")),
            "sanitizer diagnostics: {stderr:?}"
        );
        assert_eq!(judge_reports(case, reports), Ok(()), "{id}: {outcome:?}");
    }
}

#[cfg(kestrike_asan)]
#[test]
#[ignore = "needs root, reserved 2 MiB hugepages and a supported VFIO posture under the sanitized SPDK install"]
fn inline_only() {
    run("inline_only");
}
#[cfg(kestrike_asan)]
#[test]
#[ignore = "needs root, reserved 2 MiB hugepages and a supported VFIO posture under the sanitized SPDK install"]
fn one_retained() {
    run("one_retained");
}
#[cfg(kestrike_asan)]
#[test]
#[ignore = "needs root, reserved 2 MiB hugepages and a supported VFIO posture under the sanitized SPDK install"]
fn two_retained() {
    run("two_retained");
}
#[cfg(kestrike_asan)]
#[test]
#[ignore = "needs root, reserved 2 MiB hugepages and a supported VFIO posture under the sanitized SPDK install"]
fn mixed_pools() {
    run("mixed_pools");
}
#[cfg(kestrike_asan)]
#[test]
#[ignore = "needs root, reserved 2 MiB hugepages and a supported VFIO posture under the sanitized SPDK install"]
fn shared_source() {
    run("shared_source");
}
#[cfg(kestrike_asan)]
#[test]
#[ignore = "needs root, reserved 2 MiB hugepages and a supported VFIO posture under the sanitized SPDK install"]
fn prepare_partial() {
    run("prepare_partial");
}
#[cfg(kestrike_asan)]
#[test]
#[ignore = "needs root, reserved 2 MiB hugepages and a supported VFIO posture under the sanitized SPDK install"]
fn burst_partial() {
    run("burst_partial");
}
#[cfg(kestrike_asan)]
#[test]
#[ignore = "needs root, reserved 2 MiB hugepages and a supported VFIO posture under the sanitized SPDK install"]
fn uncertain_retained() {
    run("uncertain_retained");
}
#[cfg(kestrike_asan)]
#[test]
#[ignore = "needs root, reserved 2 MiB hugepages and a supported VFIO posture under the sanitized SPDK install"]
fn uncertain_unretained() {
    run("uncertain_unretained");
}
#[cfg(kestrike_asan)]
#[test]
#[ignore = "needs root, reserved 2 MiB hugepages and a supported VFIO posture under the sanitized SPDK install"]
fn application_holder() {
    run("application_holder");
}
#[cfg(kestrike_asan)]
#[test]
#[ignore = "needs root, reserved 2 MiB hugepages and a supported VFIO posture under the sanitized SPDK install"]
fn reuse() {
    run("reuse");
}
#[cfg(kestrike_asan)]
#[test]
#[ignore = "needs root, reserved 2 MiB hugepages and a supported VFIO posture under the sanitized SPDK install"]
fn invalid_contract_double_free() {
    run("invalid_contract_double_free");
}
#[test]
fn the_real_case_inventory_is_frozen() {
    assert_eq!(cases().map(|case| case.name).as_slice(), &REQUIRED[..11]);
    assert!(cases().iter().all(|case| {
        case.accepted + usize::from(case.uncertain) <= case.prepared && case.prepared <= case.chains
    }));
    assert_eq!(
        REQUIRED.iter().copied().collect::<BTreeSet<_>>().len(),
        REQUIRED.len()
    );
    assert_eq!(REQUIRED[11], "invalid_contract_double_free");
}
fn inline_reports() -> Vec<String> {
    let case = cases()[0];
    let mut reports = vec![
        exact_child::entered(&format!("{PREFIX}{}", case.name)),
        "inputs recorded".into(),
        "ledger 1 8 16 8".into(),
        "segment 0 100 0 0 4 0 9 0".into(),
    ];
    for phase in [0, 1, 2, 99] {
        let returned = usize::from(phase >= 2);
        reports.push(format!("boundary {phase} {returned}"));
        reports.push(if returned == 0 {
            "observed 100 0 1 4 0 9 0".into()
        } else {
            "observed 100 1 0 0 0 0 0".into()
        });
        reports.push(if returned == 0 {
            "census 4 0 5 9 1 0".into()
        } else {
            "census 4 0 0 10 0 1".into()
        });
        for index in 1..8 {
            reports.push(format!("census 4 {index} 0 0 0 1"));
        }
        for index in 0..8 {
            reports.push(format!("census 0 {index} 0 0 0 1"));
        }
        reports.push("stack 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15".into());
    }
    reports.push("complete inline_only".into());
    reports
}

#[test]
fn the_native_judge_accepts_exact_boundaries_and_rejects_changed_custody() {
    let case = cases()[0];
    let reports = inline_reports();
    assert_eq!(judge_reports(case, &reports), Ok(()));
    for (old, replacement) in [
        ("observed 100 1 0 0 0 0 0", "observed 100 2 0 0 0 0 0"),
        ("census 4 0 5 9 1 0", "census 4 0 0 10 0 1"),
        ("boundary 2 1", "boundary 2 0"),
        ("boundary 99 1", "boundary 99 2"),
        (
            "stack 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15",
            "stack 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 14",
        ),
    ] {
        let mut wrong = reports.clone();
        let at = wrong.iter().position(|line| line == old).unwrap();
        wrong[at] = replacement.into();
        assert!(judge_reports(case, &wrong).is_err(), "{replacement}");
    }
}

#[test]
fn the_native_judge_refuses_aggregate_completion_missing_boundaries_and_duplicates() {
    let case = cases()[0];
    let reports = inline_reports();
    assert_eq!(judge_reports(case, &reports), Ok(()));
    let aggregate = vec![
        reports[0].clone(),
        reports[1].clone(),
        reports.last().unwrap().clone(),
    ];
    assert_eq!(judge_reports(case, &aggregate), Err("episode count".into()));
    let mut repeated = reports.clone();
    repeated.push(reports[0].clone());
    assert_eq!(
        judge_reports(case, &repeated),
        Err("entry, inputs or completion witness".into())
    );
    let mut missing = reports;
    let start = missing
        .iter()
        .position(|line| line == "boundary 2 1")
        .unwrap();
    let end = missing
        .iter()
        .position(|line| line == "boundary 99 1")
        .unwrap();
    missing.drain(start..end);
    assert_eq!(
        judge_reports(case, &missing),
        Err("missing or repeated boundary".into())
    );
}
