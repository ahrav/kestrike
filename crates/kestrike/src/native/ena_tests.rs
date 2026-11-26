use std::cell::RefCell;
use std::ptr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use spdk_sys as sys;

use super::burst::Port;
use super::dataplane::{StopFailure, stop_port_watched};
use super::dma::DmaPolicy;
use super::ena::{
    CAUSE_TURNS, Cadence, EnaPort, Llq, PortError, RESET_CAUSES, Written, errno_of, llq, on_reset,
    qualify, received, reset_due, rx_ring_for, uncertain,
};
use super::env::Environment;
use super::mempool::{PacketMempool, Role};
use super::mock;
use super::pci::Function;
use super::pci_tests::Dir;
use super::registration::ArenaRegistration;
use super::registration_tests::{Fake, Recorder, new_arena, ready, register, undone, watchdog};
use super::watchdog::{Supervisor, Watchdog};
use crate::storage::PoolKind;

const IOMMU: DmaPolicy = DmaPolicy {
    allow_no_iommu: false,
};

struct Quiet;

impl Supervisor for Quiet {
    fn contain(&self) {
        panic!("a port without a lease asks for no containment");
    }
}

/// Dropping a port before `start` leaves bus mastering on: nothing of the arena is posted yet, and DPDK enabled bus mastering once at probe. Dropping a port after `start` clears it, since its queues may still name arena memory.
#[test]
fn only_a_started_port_stops_on_drop() {
    const COMMAND: u16 = 0x0406;
    let (env, arena) = (Environment::detached(), new_arena());
    let registration = register(&env, &arena, &Fake::iommu(), IOMMU).unwrap();
    let never_started = Dir::new(COMMAND, None);
    drop(EnaPort::detached(
        Function::open(&never_started.0).unwrap(),
        None,
        registration.id(),
        false,
        std::sync::Arc::new(Quiet),
    ));
    assert_eq!(never_started.command(), COMMAND, "bus mastering stays on");

    let started = Dir::new(COMMAND, None);
    drop(EnaPort::detached(
        Function::open(&started.0).unwrap(),
        Some(ptr::NonNull::dangling()),
        registration.id(),
        false,
        std::sync::Arc::new(Quiet),
    ));
    assert_eq!(started.command(), COMMAND & !0x0004, "bus mastering off");
}

/// A stopped port closes only on the undo proof of the registration that leased it; another registration's proof hands the port back.
#[test]
fn close_requires_the_leasing_registrations_undo_proof() {
    let (env, arena) = (Environment::detached(), new_arena());
    let verified = |registration: &mut ArenaRegistration<'_>| {
        registration.map().unwrap();
        registration.verify().unwrap();
    };
    let mut own = register(&env, &arena, &Fake::iommu(), IOMMU).unwrap();
    let mut other = register(&env, &arena, &Fake::iommu(), IOMMU).unwrap();
    verified(&mut own);
    verified(&mut other);
    let dir = Dir::new(0x0402, None);
    let port = EnaPort::detached(
        Function::open(&dir.0).unwrap(),
        None,
        own.id(),
        true,
        std::sync::Arc::new(Quiet),
    );
    let other_undone = other.unregister(&watchdog()).unwrap();
    let (port, error) = *port.close(&other_undone).unwrap_err();
    assert_eq!(error, PortError::State);
    let own_undone = own.unregister(&watchdog()).unwrap();
    assert!(port.close(&own_undone).is_ok());
}

fn leased_port(
    dir: &Dir,
    registration: &mut ArenaRegistration<'_>,
    supervisor: Arc<Recorder>,
) -> EnaPort<'static> {
    let lease = registration.device_attached();
    EnaPort::detached(
        Function::open(&dir.0).unwrap(),
        None,
        registration.id(),
        true,
        supervisor,
    )
    .leased(lease)
}

#[test]
fn a_stop_proven_within_its_watchdog_certifies() {
    let (env, arena) = (Environment::detached(), new_arena());
    let mut registration = ready(&env, &arena);
    let dir = Dir::new(0x0406, None);
    let supervisor = Arc::new(Recorder::new());
    let mut port = leased_port(&dir, &mut registration, Arc::clone(&supervisor));
    let deadline = Watchdog::arm(Duration::from_secs(60), supervisor.clone()).unwrap();
    let stopped = stop_port_watched(&mut port, &deadline).expect("the stop is proven in time");
    drop(deadline);
    assert_eq!(dir.command(), 0x0402, "the stop cleared bus mastering");
    assert_eq!(supervisor.requests(), 0);
    registration.device_stopped(stopped).unwrap();
    let _undone = undone(registration);
}

#[test]
fn a_stop_returning_after_its_watchdog_expired_is_late() {
    let (env, arena) = (Environment::detached(), new_arena());
    let mut registration = ready(&env, &arena);
    let dir = Dir::new(0x0406, None);
    let supervisor = Arc::new(Recorder::new());
    let mut port = leased_port(&dir, &mut registration, Arc::clone(&supervisor));
    let deadline = Watchdog::arm(Duration::ZERO, supervisor.clone()).unwrap();
    while !deadline.expired() {
        std::thread::yield_now();
    }
    assert_eq!(
        stop_port_watched(&mut port, &deadline).unwrap_err(),
        StopFailure::Late
    );
    drop(deadline);
    assert_eq!(dir.command(), 0x0402, "the driver's stop still ran");
    assert_eq!(supervisor.requests(), 1, "the expiry asked for containment");
    assert!(
        registration.unregister(&watchdog()).is_err(),
        "the withheld proof keeps the registration held"
    );
}

#[test]
fn an_unproven_stop_returns_with_its_lease_and_containment_asked() {
    let (env, arena) = (Environment::detached(), new_arena());
    let mut registration = ready(&env, &arena);
    let dir = Dir::new(0, None);
    let supervisor = Arc::new(Recorder::new());
    let mut port = leased_port(&dir, &mut registration, Arc::clone(&supervisor));
    let deadline = Watchdog::arm(Duration::from_secs(60), Arc::new(Recorder::new())).unwrap();
    assert_eq!(
        stop_port_watched(&mut port, &deadline).unwrap_err(),
        StopFailure::Unproven
    );
    drop(deadline);
    assert!(port.device_lease().is_some(), "the port keeps its lease");
    assert_eq!(
        supervisor.requests(),
        1,
        "the lost port asked for containment"
    );
}

/// `seen` records the PCI command register at each driver-stop call. `leased`
/// and `command` reflect state after both stops. `contained` counts
/// containment requests.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StopOutcome {
    seen: Vec<u16>,
    stops: Vec<bool>,
    proof: bool,
    leased: bool,
    contained: u32,
    command: u16,
}

/// The driver-stop contract for two stops in a row of a configured, leased
/// port: the driver's stop callback runs once and returns `rc`, with bus
/// mastering already clear (command register `0x0402`), and the register
/// still reads `0x0402` after both stops; a nonzero result leaves the lease
/// held, withholds the proof and asks for containment once; zero grants the
/// one proof, which takes the lease.
fn expected(rc: i32) -> StopOutcome {
    StopOutcome {
        seen: vec![0x0402],
        stops: vec![rc == 0, rc == 0],
        proof: rc == 0,
        leased: rc != 0,
        contained: u32::from(rc != 0),
        command: 0x0402,
    }
}

fn stop_twice(first: i32, retry: i32) -> StopOutcome {
    let (env, arena) = (Environment::detached(), new_arena());
    let mut registration = ready(&env, &arena);
    let dir = Dir::new(0x0406, None);
    let supervisor = Arc::new(Recorder::new());
    let lease = registration.device_attached();
    let seen = Rc::new(RefCell::new(Vec::new()));
    let calls = Rc::clone(&seen);
    let mut port = EnaPort::detached(
        Function::open(&dir.0).unwrap(),
        None,
        registration.id(),
        false,
        supervisor.clone(),
    )
    .leased(lease)
    .driver_stop(move |pci| {
        let mut calls = calls.borrow_mut();
        calls.push(pci.command().unwrap());
        if calls.len() == 1 { first } else { retry }
    });
    let first_stop = Port::stop(&mut port).is_ok();
    let contained = supervisor.requests();
    let stops = vec![first_stop, Port::stop(&mut port).is_ok()];
    assert_eq!(
        supervisor.requests(),
        contained,
        "the first stop makes every containment request"
    );
    let proof = port.stop_proof();
    let leased = port.device_lease().is_some();
    let outcome = StopOutcome {
        seen: seen.borrow().clone(),
        stops,
        proof: proof.is_some(),
        leased,
        contained,
        command: dir.command(),
    };
    match proof {
        Some(proof) => {
            assert!(port.stop_proof().is_none(), "a stop grants one proof");
            registration.device_stopped(proof).unwrap();
            let _undone = undone(registration);
        }
        None => {
            assert!(
                port.stop_proof().is_none(),
                "a second request on the lost port finds the proof still withheld"
            );
            assert!(
                registration.unregister(&watchdog()).is_err(),
                "the held lease keeps the registration held"
            );
        }
    }
    outcome
}

#[test]
fn a_failed_driver_stop_keeps_the_lease_withholds_the_proof_and_contains_once() {
    for rc in [-libc::EIO, 1] {
        assert_eq!(stop_twice(rc, rc), expected(rc), "{rc}");
    }
}

#[test]
fn a_lost_port_stays_lost_when_its_driver_would_stop_on_a_retry() {
    assert_eq!(stop_twice(-libc::EIO, 0), expected(-libc::EIO));
}

#[test]
fn a_successful_driver_stop_grants_one_proof_that_takes_the_lease() {
    assert_eq!(stop_twice(0, 0), expected(0));
}

/// The placement comes from the probe's one low-latency report and its entry size, the push prefix two descriptors shorter; a regular placement, a missing size, two probes or a descriptor fallback prove nothing.
#[test]
fn llq_placement_is_read_from_one_probe_report() {
    let probe = "ENA_DRIVER: eth_ena_dev_init(): LLQ entry size 128B\nENA_DRIVER: eth_ena_dev_init(): Placement policy: Low latency\n";
    assert_eq!(
        llq(probe),
        Some(Llq {
            entry: 128,
            push: 96
        })
    );
    let large = probe.replace("128B", "256B");
    assert_eq!(
        llq(&large),
        Some(Llq {
            entry: 256,
            push: 224
        })
    );
    assert_eq!(llq("Placement policy: Regular\n"), None);
    assert_eq!(llq("Placement policy: Low latency\n"), None);
    assert_eq!(llq(&format!("{probe}{probe}")), None);
    assert_eq!(llq(""), None);
    let fallback = format!(
        "[ENA_COM: ena_com_config_llq_info]Default llq num descs before header is not supported, performing fallback, default: 0x2, supported: 0x1, used: 0x1\n{probe}"
    );
    assert_eq!(llq(&fallback), None, "a fallback changes the prefix");
}

/// The receive ring is the largest power of two at most half the pool, capped at the device's maximum.
#[test]
fn the_receive_ring_is_half_the_pool_rounded_down() {
    assert_eq!(rx_ring_for(4096, 8192), 2048);
    assert_eq!(rx_ring_for(3000, 8192), 1024);
    assert_eq!(rx_ring_for(1 << 20, 8192), 8192);
    assert_eq!(rx_ring_for(1, 8192), 0);
}

/// The reset callback raises exactly its argument's flag and reports success.
#[test]
fn the_reset_callback_raises_its_flag() {
    let flag = AtomicBool::new(false);
    // SAFETY: the argument is a live flag, as registration passes the port's leaked one.
    let rc = unsafe {
        on_reset(
            0,
            sys::rte_eth_event_type_RTE_ETH_EVENT_INTR_RESET,
            ptr::from_ref(&flag).cast_mut().cast(),
            ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);
    assert!(flag.load(Ordering::Acquire));
}

fn capable() -> sys::rte_eth_dev_info {
    // SAFETY: the info structure is plain data; all zeroes is a valid value.
    let mut info: sys::rte_eth_dev_info = unsafe { std::mem::zeroed() };
    info.rx_offload_capa = u64::MAX;
    info.tx_offload_capa = u64::MAX;
    info.max_mtu = 9216;
    info.tx_desc_lim.nb_seg_max = 4;
    info
}

/// Qualification refuses, in order, another driver or MAC, each missing offload, an MTU below 9001, and a scatter list too short for a three-segment chain; four entries, one more than the chain, pass.
#[test]
fn qualification_refuses_each_missing_capability() {
    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 9];
    assert_eq!(qualify(&capable(), c"net_ena", MAC, MAC), Ok(()));
    assert_eq!(
        qualify(&capable(), c"net_ixgbe", MAC, MAC),
        Err(PortError::Identity)
    );
    assert_eq!(
        qualify(&capable(), c"net_ena", [2, 0, 0, 0, 0, 8], MAC),
        Err(PortError::Identity)
    );
    let rx = [
        sys::RTE_ETH_RX_OFFLOAD_IPV4_CKSUM,
        sys::RTE_ETH_RX_OFFLOAD_UDP_CKSUM,
    ];
    let tx = [
        sys::RTE_ETH_TX_OFFLOAD_IPV4_CKSUM,
        sys::RTE_ETH_TX_OFFLOAD_UDP_CKSUM,
        sys::RTE_ETH_TX_OFFLOAD_MULTI_SEGS,
    ];
    for bit in rx {
        let mut info = capable();
        info.rx_offload_capa &= !u64::from(bit);
        assert_eq!(
            qualify(&info, c"net_ena", MAC, MAC),
            Err(PortError::Capability("offloads"))
        );
    }
    for bit in tx {
        let mut info = capable();
        info.tx_offload_capa &= !u64::from(bit);
        assert_eq!(
            qualify(&info, c"net_ena", MAC, MAC),
            Err(PortError::Capability("offloads"))
        );
    }
    let mut info = capable();
    info.max_mtu = 9000;
    assert_eq!(
        qualify(&info, c"net_ena", MAC, MAC),
        Err(PortError::Capability("mtu"))
    );
    let mut info = capable();
    info.tx_desc_lim.nb_seg_max = 3;
    assert_eq!(
        qualify(&info, c"net_ena", MAC, MAC),
        Err(PortError::Capability("segments"))
    );
}

/// A reset is due when announced, when any one reset-cause counter rose alone, or when the counters are unreadable, and not otherwise.
#[test]
fn every_reset_cause_counter_makes_a_reset_due() {
    let seen = [5; 6];
    assert!(!reset_due(false, Some(&seen), &seen));
    assert!(reset_due(true, Some(&seen), &seen));
    assert!(reset_due(false, None, &seen));
    for at in 0..6 {
        let mut now = seen;
        now[at] += 1;
        assert!(reset_due(false, Some(&now), &seen), "counter {at}");
    }
}

/// `EnaPort` runs timers and reads reset-cause counters on the first turn after a start and every `CAUSE_TURNS` turns thereafter.
#[test]
fn the_reset_causes_are_read_once_every_cause_turns() {
    let mut cadence = Cadence::START;
    let reads: Vec<u32> = (0..3 * CAUSE_TURNS)
        .filter(|_| cadence.check_due())
        .collect();
    assert_eq!(reads, [0, CAUSE_TURNS, 2 * CAUSE_TURNS]);
}

/// A receive fault holds every later receive burst until the next service turn, which checks the reset causes at once; that check releases receives and restarts the `CAUSE_TURNS` countdown.
#[test]
fn a_receive_fault_holds_receives_until_the_next_check() {
    let mut cadence = Cadence::START;
    assert!(
        cadence.receives(),
        "a started port receives before its first check"
    );
    assert!(cadence.check_due());
    for _ in 0..CAUSE_TURNS / 2 {
        assert!(!cadence.check_due());
    }
    cadence.fault();
    assert!(
        !cadence.receives(),
        "the burst after a fault returns nothing"
    );
    assert!(cadence.check_due(), "the service turn after a fault checks");
    assert!(cadence.receives(), "the check releases receives");
    let reads: Vec<u32> = (0..2 * CAUSE_TURNS)
        .filter(|_| cadence.check_due())
        .collect();
    assert_eq!(
        reads,
        [CAUSE_TURNS - 1, 2 * CAUSE_TURNS - 1],
        "the countdown restarts from the check"
    );
}

/// Service's receive-only read takes every cause after the first two, so the transmit causes come first and every later cause is a receive cause.
#[test]
fn the_two_transmit_reset_causes_lead_the_receive_causes() {
    let names: Vec<&str> = RESET_CAUSES.iter().map(|c| c.to_str().unwrap()).collect();
    assert!(
        names[..2].iter().all(|n| n.starts_with("tx_q0_")),
        "{names:?}"
    );
    assert!(
        names[2..].iter().all(|n| n.starts_with("rx_q0_")),
        "{names:?}"
    );
}

/// A short burst is uncertain only when the preparation error counter rose or the counters are unreadable; another counter's rise is certain, and a full burst is certain without reading the counters.
#[test]
fn only_a_preparation_error_makes_a_short_burst_uncertain() {
    let seen = [5; 6];
    let mut prepare = seen;
    prepare[0] += 1;
    let mut other = seen;
    other[1] += 1;
    assert!(uncertain(true, || Some(prepare), &seen));
    assert!(uncertain(true, || None, &seen));
    assert!(!uncertain(true, || Some(other), &seen));
    assert!(!uncertain(true, || Some(seen), &seen));
    assert!(!uncertain(
        false,
        || unreachable!("a full burst reads no counters"),
        &seen
    ));
}

/// A failed restart reports the native step's error number, `EIO` for the function's configuration space, `ENOTSUP` for a lost low-latency placement, `ENODATA` for missing counters, and `EINVAL` otherwise.
#[test]
fn restart_errors_map_to_error_numbers() {
    assert_eq!(
        errno_of(PortError::Native("start", -libc::EBUSY)),
        libc::EBUSY
    );
    assert_eq!(errno_of(PortError::Native("start", i32::MIN)), libc::EIO);
    assert_eq!(
        errno_of(PortError::Pci(std::io::ErrorKind::InvalidData)),
        libc::EIO
    );
    assert_eq!(errno_of(PortError::Llq), libc::ENOTSUP);
    assert_eq!(errno_of(PortError::Counters), libc::ENODATA);
    assert_eq!(errno_of(PortError::State), libc::EINVAL);
}

/// A synthetic packet address, used only for identity comparisons.
fn packet(at: usize) -> *mut sys::rte_mbuf {
    ptr::without_provenance_mut(0x1000 + at * 0x100)
}

fn driver(wrote: usize, returns: usize) -> impl FnOnce(&mut [*mut sys::rte_mbuf]) -> usize {
    move |slots| {
        for (at, slot) in slots[..wrote].iter_mut().enumerate() {
            *slot = packet(at);
        }
        returns
    }
}

#[test]
fn a_receive_burst_keeps_every_written_packet_and_flags_an_undercounted_return() {
    for (wrote, returns) in [(3, 0), (3, 1), (3, 3), (0, 0), (8, 8)] {
        let mut out = [ptr::without_provenance_mut(0xdead_0000); 8];
        let written = received(&mut out, driver(wrote, returns));
        assert_eq!(
            written,
            Written {
                count: wrote,
                uncommitted: returns < wrote,
            },
            "wrote {wrote}, returned {returns}"
        );
        assert!(
            out[..written.count]
                .iter()
                .enumerate()
                .all(|(at, &p)| p == packet(at)),
            "{out:?}"
        );
    }
}

/// A detached port over `dir`, leased from `registration`, holding a receive pool as `start` leaves it, stopped when `stopped`, whose driver stop returns zero.
fn restartable(
    dir: &Dir,
    registration: &mut ArenaRegistration<'_>,
    stopped: bool,
    supervisor: Arc<Recorder>,
) -> EnaPort<'static> {
    let lease = registration.device_attached();
    EnaPort::detached(
        Function::open(&dir.0).unwrap(),
        Some(ptr::NonNull::dangling()),
        registration.id(),
        stopped,
        supervisor,
    )
    .leased(lease)
}

/// What a refused or completed restart step leaves behind: its result, the restart error it recorded, the command register, and what the function's reset control holds.
#[derive(Debug, PartialEq, Eq)]
struct Step {
    result: Result<(), i32>,
    error: Option<PortError>,
    command: u16,
    reset: String,
}

fn reset_step(port: &mut EnaPort<'_>, dir: &Dir) -> Step {
    let result = Port::reset(port);
    Step {
        result,
        error: port.restart_error(),
        command: dir.command(),
        reset: dir.reset_written(),
    }
}

/// What re-initialization leaves on a reset port attached with a 128-byte low-latency entry when the driver's probe logs `log`: the step's result, the restart error it recorded, and the result of the start that follows.
fn reinitialized_over(log: &str) -> (Result<(), i32>, Option<PortError>, Result<(), i32>) {
    let (env, arena) = (Environment::detached(), new_arena());
    let mut registration = ready(&env, &arena);
    let dir = Dir::new(0x0402, Some(true));
    let supervisor = Arc::new(Recorder::new());
    let attached = Llq {
        entry: 128,
        push: 96,
    };
    let mut port = restartable(&dir, &mut registration, true, Arc::clone(&supervisor))
        .driver_reset(attached, 0, log);
    assert_eq!(Port::reset(&mut port), Ok(()));
    let step = Port::reinitialize(&mut port);
    let error = port.restart_error();
    let start = Port::start(&mut port);
    assert!(Port::stop(&mut port).is_ok());
    let proof = port.stop_proof().expect("the stop proves again");
    registration.device_stopped(proof).unwrap();
    let _undone = undone(registration);
    assert_eq!(supervisor.requests(), 0);
    (step, error, start)
}

/// Re-initialization echoes the driver's probe log to standard error and acts on the reset's result, so a standard error that refuses every write changes nothing else: the step returns as it does with a writable one, recording the configure failure of a detached port. Runs in a child of the test executable, whose descriptor 2 the echo writes; the child points it at `/dev/full` for the step and first checks that a write there fails.
#[test]
fn reinitialization_returns_its_result_when_standard_error_cannot_be_written() {
    crate::exact_child::run(
        "native::ena_tests::reinitialization_returns_its_result_when_standard_error_cannot_be_written",
        Duration::from_secs(60),
        || {
            let probe = "ENA_DRIVER: eth_ena_dev_init(): LLQ entry size 128B\nENA_DRIVER: eth_ena_dev_init(): Placement policy: Low latency\n";
            // SAFETY: plain descriptor calls on this child's own table; descriptor 2 is restored below.
            let saved = unsafe {
                let saved = libc::dup(2);
                let full = libc::open(c"/dev/full".as_ptr(), libc::O_WRONLY);
                assert!(saved >= 0 && full >= 0);
                assert_eq!(libc::dup2(full, 2), 2);
                libc::close(full);
                saved
            };
            // SAFETY: writes one byte from a live buffer to this child's descriptor 2.
            let refused = unsafe { libc::write(2, c"x".as_ptr().cast(), 1) };
            let outcome = std::panic::catch_unwind(|| reinitialized_over(probe));
            // SAFETY: as for the swap above.
            unsafe {
                assert_eq!(libc::dup2(saved, 2), 2);
                libc::close(saved);
            }
            assert_eq!(refused, -1, "standard error took a write");
            let (step, error, start) = outcome.expect("the step returned");
            assert!(
                matches!(error, Some(PortError::Native("configure", _))),
                "{error:?}"
            );
            assert!(step.is_err());
            assert_eq!(start, Err(libc::EINVAL), "a port not configured");
        },
    );
}

/// A stopped, leased port whose registration then fails its recheck refuses the restart's reset `NotReady`, with no reset written and bus mastering off, since from the reset on the device may reach arena memory the registration no longer vouches for. The same port over a registration that stays ready is admitted.
#[test]
fn a_restart_reset_refuses_while_the_registration_is_not_ready() {
    let (env, arena) = (Environment::detached(), new_arena());
    let supervisor = Arc::new(Recorder::new());

    let (mut registration, stale) = super::registration_tests::ready_until_stale(&env, &arena);
    let dir = Dir::new(0x0402, Some(true));
    let mut port = restartable(&dir, &mut registration, true, Arc::clone(&supervisor));
    stale();
    assert!(registration.recheck().is_err());
    assert!(!registration.is_ready());
    assert_eq!(
        reset_step(&mut port, &dir),
        Step {
            result: Err(libc::EINVAL),
            error: Some(PortError::NotReady),
            command: 0x0402,
            reset: String::new(),
        },
        "unverified registration"
    );

    let (mut registration, _stale) = super::registration_tests::ready_until_stale(&env, &arena);
    let dir = Dir::new(0x0402, Some(true));
    let mut port = restartable(&dir, &mut registration, true, Arc::clone(&supervisor));
    assert!(registration.recheck().is_ok());
    assert_eq!(
        reset_step(&mut port, &dir),
        Step {
            result: Ok(()),
            error: None,
            command: 0x0406,
            reset: "1".into(),
        },
        "ready registration"
    );
}

/// The attach-time start runs only on a port no restart step has touched. A function reset that fails, here on a function with no function-level reset, leaves the port needing a fresh stop proof, so the attach-time start refuses it `State` as it refuses the stopped port, with bus mastering left off: it would otherwise set up the queues and start a driver over a function that was not reset.
#[test]
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
fn a_failed_function_reset_refuses_the_attach_time_start() {
    let env = Environment::detached();
    let arena = super::mock::arena();
    let supervisor = Arc::new(Recorder::new());
    let mut registration = ready(&env, arena);
    let dir = Dir::new(0x0402, Some(false));
    let mut port = restartable(&dir, &mut registration, true, Arc::clone(&supervisor));
    let device = port.device_lease().unwrap().device();
    let receive = super::mock::mempool(arena, PoolKind::PacketReceive, device);

    assert_eq!(
        port.start(&receive, &registration),
        Err(PortError::State),
        "control: stopped"
    );
    assert_eq!(Port::reset(&mut port), Err(libc::EIO), "no function reset");
    assert_eq!(
        port.start(&receive, &registration),
        Err(PortError::State),
        "after a refused function reset"
    );
    assert_eq!(dir.command(), 0x0402, "bus mastering stays off");
    assert!(Port::stop(&mut port).is_ok());
    assert_eq!(supervisor.requests(), 0);
}

/// A driver re-initialization that fails leaves the reset port needing a fresh stop proof, so the attach-time start refuses it `State` as it refuses the reset port before the re-initialization ran: it would otherwise start a driver whose re-initialization failed, or ran with a placement the low-latency check refused.
#[test]
#[cfg_attr(
    miri,
    ignore = "the packet layout comes from a native size computation"
)]
fn a_failed_reinitialization_refuses_the_attach_time_start() {
    let env = Environment::detached();
    let arena = super::mock::arena();
    let supervisor = Arc::new(Recorder::new());
    let mut registration = ready(&env, arena);
    let dir = Dir::new(0x0402, Some(true));
    let mut port = restartable(&dir, &mut registration, true, Arc::clone(&supervisor));
    let device = port.device_lease().unwrap().device();
    let receive = super::mock::mempool(arena, PoolKind::PacketReceive, device);

    assert_eq!(Port::reset(&mut port), Ok(()));
    assert_eq!(
        port.start(&receive, &registration),
        Err(PortError::State),
        "control: reset"
    );
    assert!(
        Port::reinitialize(&mut port).is_err(),
        "a detached port has no driver to re-initialize"
    );
    assert_eq!(
        port.start(&receive, &registration),
        Err(PortError::State),
        "after a failed re-initialization"
    );
    assert!(Port::stop(&mut port).is_ok());
    assert_eq!(supervisor.requests(), 0);
}

/// The data room of the receive pool: the headroom, then more than an MTU frame.
const ROOM: u16 = 16384;

/// A native pool structure with the packet-pool private header that follows it when the pool has no per-lcore cache.
#[repr(C)]
struct NativePool {
    pool: sys::rte_mempool,
    private: sys::rte_pktmbuf_pool_private,
}

/// Initializes the EAL with no PCI, no hugepages, 64 MiB and no shared memory, which gives the calling thread an lcore without a device, a hugepage or root.
fn initialize_eal() {
    let mut opts = sys::spdk_env_opts {
        opts_size: size_of::<sys::spdk_env_opts>(),
        // SAFETY: the options are plain data that `spdk_env_opts_init` fills.
        ..unsafe { std::mem::zeroed() }
    };
    // SAFETY: `opts` is a valid, sized options structure, and the name is a static C string.
    let rc = unsafe {
        sys::spdk_env_opts_init(&mut opts);
        opts.name = c"ena-port-start".as_ptr();
        opts.no_pci = true;
        opts.no_huge = true;
        opts.mem_size = 64;
        opts.shm_id = -1;
        sys::spdk_env_init(&opts)
    };
    assert_eq!(rc, 0, "the EAL initializes with no PCI and no hugepages");
}

/// A configured, leased port on a thread with a valid lcore, over its own registration and a receive pool with room for an MTU frame, refuses `start` with `NotReady` while the registration is registered but unverified, and again after a failed recheck: no descriptor may name arena memory the registration does not vouch for. Over the verified registration the same start passes its checks and fails in a native step, since no port stands behind a detached one, so the refusals are the registration's. Runs in a child of the test executable, which initializes a no-PCI, no-hugepages EAL so that its thread holds an lcore.
#[test]
fn start_refuses_not_ready_until_the_registration_verified_and_after_a_failed_recheck() {
    crate::exact_child::run(
        "native::ena_tests::start_refuses_not_ready_until_the_registration_verified_and_after_a_failed_recheck",
        Duration::from_secs(120),
        || {
            initialize_eal();
            // SAFETY: reads the calling thread's lcore identity.
            let lcore = unsafe { sys::spdk_sys_rte_lcore_id() };
            assert!(
                lcore < sys::RTE_MAX_LCORE,
                "the thread that initialized the EAL holds a valid lcore"
            );

            let (env, arena) = (Environment::detached(), mock::arena());
            let fake = Fake::iommu();
            let mut registration = register(&env, arena, &fake, IOMMU).unwrap();
            let lease = registration.device_attached();
            let device = lease.device();
            let dir = Dir::new(0x0406, None);
            let supervisor = Arc::new(Recorder::new());
            let mut port = EnaPort::detached(
                Function::open(&dir.0).unwrap(),
                None,
                registration.id(),
                false,
                supervisor.clone(),
            )
            .leased(lease);

            // The leased device's receive pool: the mock pool's state under a native structure whose private header is real memory.
            assert!(arena.pools().pool(PoolKind::PacketReceive).claim_served());
            let mocked = mock::arena_pool(arena, PoolKind::PacketReceive, Role::Receive);
            // SAFETY: all zeroes is a valid empty pool and private header.
            let native: &'static mut NativePool =
                Box::leak(Box::new(unsafe { std::mem::zeroed() }));
            native.private.mbuf_data_room_size = ROOM;
            let private = (&raw mut native.private).addr();
            let mp = &raw mut native.pool;
            // SAFETY: `mp` names the leaked pool structure, which has no cache.
            assert_eq!(
                unsafe { sys::spdk_sys_rte_mempool_get_priv(mp) }.addr(),
                private,
                "the pool's private area is the header the test wrote"
            );
            let receive = PacketMempool::mocked(mp, mocked.state, device);

            // The registration is registered only, so `is_ready` reads false.
            assert!(!registration.is_ready());
            assert_eq!(
                port.start(&receive, &registration),
                Err(PortError::NotReady),
                "no start before the registration verified"
            );

            // Ready: the start passes its checks and reaches the native calls, which find no port behind a detached one.
            registration.map().unwrap();
            registration.verify().unwrap();
            assert!(registration.is_ready());
            let started = port.start(&receive, &registration);
            assert!(
                matches!(started, Err(PortError::Native(..))),
                "a ready registration takes the start to the driver: {started:?}"
            );

            // A failed recheck revokes readiness.
            fake.mistranslate(true);
            registration.recheck().unwrap_err();
            assert!(!registration.is_ready());
            assert_eq!(
                port.start(&receive, &registration),
                Err(PortError::NotReady),
                "no start after a failed recheck: no descriptor names arena memory under an unverified registration"
            );

            // A later verify readmits the start.
            fake.mistranslate(false);
            registration.verify().unwrap();
            let restarted = port.start(&receive, &registration);
            assert!(
                matches!(restarted, Err(PortError::Native(..))),
                "{restarted:?}"
            );

            assert!(Port::stop(&mut port).is_ok());
            let stopped = port.stop_proof().expect("a proven stop returns the lease");
            registration.device_stopped(stopped).unwrap();
            assert_eq!(supervisor.requests(), 0, "no containment was asked");
            drop(receive);
        },
    );
}
