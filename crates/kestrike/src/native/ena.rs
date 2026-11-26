//! The ENA poll-mode driver's one port and queue pair behind the burst
//! logic's [`Port`] boundary.
//!
//! Invariants owned by this module:
//!
//! - The port runs only as qualified: the `net_ena` driver at the recorded
//!   MAC, receive IPv4 and UDP checksum offloads, transmit IPv4 and UDP
//!   checksum offloads with multi-segment packets, a segment limit holding a
//!   header buffer and two payload descriptors, MTU 9001, power-of-two rings,
//!   and the low-latency queue placement the driver's probe reported. RSS,
//!   receive scatter and fast mbuf free stay off.
//! - No descriptor names arena memory before the shared registration
//!   verified: receive buffers post only at [`EnaPort::start`], which
//!   requires a ready registration and runs on a thread with a valid lcore,
//!   so the driver's watchdog timer runs there, on the service turns that
//!   read the counters, and at the restart's [`Port::start`]. Each restart
//!   step, the reset that returns bus mastering included, refuses `NotReady`
//!   while the lease reads its registration as not ready, so a failed verify
//!   or recheck keeps a stopped port stopped until a later verify passes.
//! - Every reset cause reaches [`Port::service`]: the reset event the
//!   watchdog delivers on the polling thread sets a flag whose context lives
//!   for the process, and the driver's per-queue error counters record the
//!   datapath causes after which the watchdog stays silent. A post the driver
//!   refused after recording its packet shows as a rise of the transmit
//!   preparation error counter, which marks the packet uncertain.
//! - Service runs the driver's timers and reads the counters on every
//!   [`CAUSE_TURNS`]th turn, the first included: all six counters when a
//!   transmit burst or cleanup ran since the last read and the four receive
//!   counters otherwise, which relies on the driver raising its transmit
//!   counters only inside those calls. A datapath cause therefore reaches the
//!   burst logic within [`CAUSE_TURNS`] turns. The watchdog announces a
//!   reset only from inside that timer run, on this thread, so the flag is
//!   set and read on the same turn, and each of the watchdog's one-second
//!   checks runs at most [`CAUSE_TURNS`] turns after it falls due.
//! - A receive burst whose driver call wrote more packets than it returned
//!   makes the next service run that check. The driver returns early that
//!   way only on a receive fault, which raises a receive counter and leaves
//!   its ring index short of the packets written; a later receive on that
//!   ring can repost a buffer the device still holds. Receive bursts
//!   return nothing until that check runs, whatever order the caller
//!   receives and services in, so recovery runs before the next receive.
//! - A stop clears the function's bus-master enable and confirms it on
//!   read-back before the driver stops and frees its queues, so neither
//!   packet nor native queue memory is recycled while the device can still
//!   reach it. A stop that cannot clear it, or whose driver stop fails, asks
//!   the supervisor to contain the host and keeps the device lease, so the
//!   arena stays registered and held.
//!   The stop holds the polling thread while the driver's first queue-destroy
//!   admin command, whose completion the device cannot write with bus
//!   mastering off, waits out one admin timeout (the device's, or 3 s when it
//!   advertises none), plus the device reset's register-read timeouts when a
//!   reset is pending; that pause is the quiesced recovery's, outside every
//!   steady-state turn bound.
//! - A restart after a proven stop resets the function, which clears the
//!   device's queues, before bus mastering returns, then re-initializes,
//!   reconfigures and starts the driver; it requires function-level reset
//!   and the port's lease. Every stop clears bus mastering before it reports
//!   proof, so a failed restart is followed by a fresh proof.

use std::ffi::{CStr, CString, c_int, c_void};
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use spdk_sys as sys;

use super::burst::{Health, Port, Prepared, TxBurst, Unproven};
use super::env::{Environment, capture, echo};
use super::mempool::PacketMempool;
use super::pci::Function;
use super::registration::{
    ArenaRegistration, DeviceLease, DeviceStopped, RegistrationId, Unregistered,
};
use super::watchdog::Supervisor;
use crate::bind::Host;

/// The MTU of every port.
pub const MTU: u16 = 9001;
/// Transmit descriptors requested.
const TX_RING: u16 = 1024;
/// Segments of the longest chain the burst logic builds.
const CHAIN_SEGMENTS: u16 = 3;
const ETHERNET_HEADER: u32 = 14;
const RX_OFFLOADS: u64 =
    (sys::RTE_ETH_RX_OFFLOAD_IPV4_CKSUM | sys::RTE_ETH_RX_OFFLOAD_UDP_CKSUM) as u64;
const TX_OFFLOADS: u64 = (sys::RTE_ETH_TX_OFFLOAD_IPV4_CKSUM
    | sys::RTE_ETH_TX_OFFLOAD_UDP_CKSUM
    | sys::RTE_ETH_TX_OFFLOAD_MULTI_SEGS) as u64;
const DRIVER: &CStr = c"net_ena";
/// Descriptor bytes ahead of the pushed header in each low-latency queue entry: two 16-byte descriptors.
const LLQ_DESCRIPTORS: u16 = 32;
/// The driver's counters of datapath reset causes, the ones its watchdog
/// can leave unannounced; [`PREPARE_ERROR`] indexes the transmit preparation error.
/// The two transmit causes lead, so a receive-only read takes the last four.
pub(crate) const RESET_CAUSES: [&CStr; 6] = [
    c"tx_q0_prepare_ctx_err",
    c"tx_q0_bad_req_id",
    c"rx_q0_bad_desc_num",
    c"rx_q0_bad_req_id",
    c"rx_q0_bad_desc",
    c"rx_q0_unknown_error",
];
const PREPARE_ERROR: usize = 0;
/// The ENI's allowance-exceeded counters, read for reports through the admin queue.
pub const ALLOWANCES: [&CStr; 5] = [
    c"bw_in_allowance_exceeded",
    c"bw_out_allowance_exceeded",
    c"pps_allowance_exceeded",
    c"conntrack_allowance_exceeded",
    c"linklocal_allowance_exceeded",
];

/// What the port is configured for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnaConfig {
    /// The dataplane ENI's MAC, as the bind inventory records it.
    pub mac: [u8; 6],
    /// Buffers of the receive pool, half of which the receive ring may post.
    pub rx_buffers: u32,
}

/// The low-latency queue placement: the entry size, and the packet prefix
/// the driver pushes through the device's memory BAR. A prefix longer than
/// the first segment is copied from the segments after it; the bytes past
/// the prefix stay referenced where they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Llq {
    pub entry: u16,
    pub push: u16,
}

/// The port's effective configuration, for the startup report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortReport {
    pub port: u16,
    pub mac: [u8; 6],
    pub mtu: u16,
    pub max_mtu: u16,
    pub rx_offloads: u64,
    pub tx_offloads: u64,
    pub rx_ring: u16,
    pub tx_ring: u16,
    /// Segments one transmit packet may have.
    pub segments: u16,
    /// The receive buffers' data room and headroom, once started.
    pub data_room: u16,
    pub headroom: u16,
    pub llq: Llq,
    /// Whether the function supports the function-level reset a restart needs.
    pub flr: bool,
}

/// Why the port was refused or failed to set up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortError {
    /// No port has the address, or its driver or MAC is not the recorded ENA's.
    Identity,
    /// A required offload, the MTU, the segment limit or a power-of-two ring is unavailable.
    Capability(&'static str),
    /// The driver's probe did not report the expected low-latency placement.
    Llq,
    /// A reset-cause counter is missing or unreadable.
    Counters,
    /// The registration is not verified, the thread has no lcore, or a receive buffer cannot hold a frame.
    NotReady,
    /// The function's configuration space refused.
    Pci(io::ErrorKind),
    /// A native step failed with this error number.
    Native(&'static str, i32),
    /// The call does not fit the port's state.
    State,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Attached and configured, and never started since: the one state the attach-time start admits.
    Configured,
    /// A restart step began and did not complete. The device may reach memory, so stop and drop treat the port as live, and only a stop leaves this state.
    Restarting,
    /// The function reset with bus mastering back on, ready for the driver's re-initialization.
    Reset,
    /// The driver re-initialized and the port configured, ready to start.
    Reinitialized,
    Started,
    /// Stopped with bus mastering off.
    Stopped,
    /// A stop was not proven.
    Lost,
}

/// Turns from one service turn that runs the driver's timers and reads the
/// reset-cause counters to the next. The timer run reads the cycle counter
/// and the counter read runs the driver's extended-statistics lookup, so
/// spacing them keeps both off most turns while a datapath cause is still
/// found, and the one-second watchdog still runs, within this many turns.
pub(crate) const CAUSE_TURNS: u32 = 64;

/// When the next service turn runs the timers and reads the reset-cause
/// counters, and whether a receive fault holds receives until it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cadence {
    /// Service turns before the next check.
    wait: u32,
    /// A receive burst ended early since the last check, so receives return nothing until it runs.
    faulted: bool,
}

impl Cadence {
    pub(crate) const START: Self = Self {
        wait: 0,
        faulted: false,
    };

    pub(crate) fn check_due(&mut self) -> bool {
        if self.wait == 0 {
            self.wait = CAUSE_TURNS - 1;
            self.faulted = false;
            return true;
        }
        self.wait -= 1;
        false
    }

    pub(crate) fn fault(&mut self) {
        self.wait = 0;
        self.faulted = true;
    }

    pub(crate) fn receives(&self) -> bool {
        !self.faulted
    }
}

/// The driver's queue stop, which [`Port::stop`] calls after bus mastering
/// is off and read back clear, and its re-initialization, which a restart
/// runs over the reset function.
enum Driver {
    /// `rte_eth_dev_stop` and `rte_eth_dev_reset` on the port.
    Native,
    /// A test's scripts.
    #[cfg(test)]
    Scripted {
        /// Sees the port's PCI function at the moment of the stop and
        /// returns the driver's result.
        stop: Box<dyn FnMut(&Function) -> c_int>,
        /// Returns the re-initialization's result and the log its probe
        /// wrote.
        reset: Box<dyn FnMut() -> (c_int, String)>,
    },
}

/// One ENA port and its single queue pair, owned by the polling thread.
pub struct EnaPort<'e> {
    id: u16,
    bdf: String,
    pci: Function,
    /// Set by the reset event; leaked so it outlives every callback.
    reset: &'static AtomicBool,
    causes: [u64; RESET_CAUSES.len()],
    seen: [u64; RESET_CAUSES.len()],
    /// Whether a transmit burst or cleanup ran since the last counter read.
    transmitted: bool,
    cadence: Cadence,
    receive: Option<NonNull<sys::rte_mempool>>,
    report: PortReport,
    state: State,
    /// Why the last restart failed.
    restart_error: Option<PortError>,
    /// The registration that leased the port; its pools, restart and undo proof name it.
    registration: RegistrationId,
    lease: Option<DeviceLease>,
    supervisor: Arc<dyn Supervisor>,
    driver: Driver,
    _env: PhantomData<&'e Environment>,
}

impl fmt::Debug for EnaPort<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnaPort")
            .field("report", &self.report)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

fn native(step: &'static str, rc: c_int) -> Result<(), PortError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(PortError::Native(step, rc))
    }
}

/// The placement the driver's probe logged, when exactly one probe reported
/// low-latency placement and its entry size with the default two
/// descriptors ahead of the header.
pub(crate) fn llq(log: &str) -> Option<Llq> {
    let placements: Vec<&str> = log
        .lines()
        .filter_map(|line| {
            line.split_once("Placement policy: ")
                .map(|(_, policy)| policy.trim())
        })
        .collect();
    if placements != ["Low latency"] || log.contains("performing fallback") {
        return None;
    }
    let entry = log.lines().find_map(|line| {
        let (_, size) = line.split_once("LLQ entry size ")?;
        size.trim().strip_suffix('B')?.parse::<u16>().ok()
    })?;
    Some(Llq {
        entry,
        push: entry.checked_sub(LLQ_DESCRIPTORS)?,
    })
}

/// Checks a port's identity and capabilities, in this order: the driver and
/// MAC, the offloads, the MTU, then the segment limit.
pub(crate) fn qualify(
    info: &sys::rte_eth_dev_info,
    driver: &CStr,
    mac: [u8; 6],
    expected: [u8; 6],
) -> Result<(), PortError> {
    if driver != DRIVER || mac != expected {
        return Err(PortError::Identity);
    }
    if info.rx_offload_capa & RX_OFFLOADS != RX_OFFLOADS
        || info.tx_offload_capa & TX_OFFLOADS != TX_OFFLOADS
    {
        return Err(PortError::Capability("offloads"));
    }
    if info.max_mtu < MTU {
        return Err(PortError::Capability("mtu"));
    }
    // The driver's prepare refuses a packet with as many segments as its scatter list holds unless its first segment fits the low-latency push; one spare entry satisfies both placements.
    if info.tx_desc_lim.nb_seg_max.saturating_sub(1) < CHAIN_SEGMENTS {
        return Err(PortError::Capability("segments"));
    }
    Ok(())
}

/// Whether a reset is due: one was announced, a reset-cause counter rose
/// since `seen`, or the counters could not be read.
pub(crate) fn reset_due<const N: usize>(
    announced: bool,
    now: Option<&[u64; N]>,
    seen: &[u64; N],
) -> bool {
    announced || now.is_none_or(|now| now.iter().zip(seen).any(|(now, seen)| now > seen))
}

/// Whether a short transmit burst's first refused packet may be held by
/// the driver: the preparation error counter, which `read` reads only for a
/// short burst, rose since `seen`, or the counters could not be read.
pub(crate) fn uncertain<const N: usize>(
    short: bool,
    read: impl FnOnce() -> Option<[u64; N]>,
    seen: &[u64; N],
) -> bool {
    short && read().is_none_or(|now| now[PREPARE_ERROR] > seen[PREPARE_ERROR])
}

/// The IDs of the port's extended statistics `names`.
fn xstat_ids<const N: usize>(id: u16, names: [&CStr; N]) -> Option<[u64; N]> {
    let mut ids = [0; N];
    for (slot, name) in ids.iter_mut().zip(names) {
        // SAFETY: `name` is a C string and `slot` a valid output.
        if unsafe { sys::rte_eth_xstats_get_id_by_name(id, name.as_ptr(), slot) } != 0 {
            return None;
        }
    }
    Some(ids)
}

/// The values of the port's extended statistics `ids`; driver statistics
/// read by ID allocate nothing.
fn xstats<const N: usize>(id: u16, ids: &[u64; N]) -> Option<[u64; N]> {
    let mut values = [0; N];
    // SAFETY: both arrays hold `N` entries.
    let n =
        unsafe { sys::rte_eth_xstats_get_by_id(id, ids.as_ptr(), values.as_mut_ptr(), N as u32) };
    (usize::try_from(n) == Ok(N)).then_some(values)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Written {
    pub(crate) count: usize,
    pub(crate) uncommitted: bool,
}

/// Clearing `out` ensures each non-null slot after `burst` contains a pointer
/// written by that call.
pub(crate) fn received(
    out: &mut [*mut sys::rte_mbuf],
    burst: impl FnOnce(&mut [*mut sys::rte_mbuf]) -> usize,
) -> Written {
    out.fill(std::ptr::null_mut());
    let reported = burst(out).min(out.len());
    let unreported = out[reported..].iter().take_while(|p| !p.is_null()).count();
    Written {
        count: reported + unreported,
        uncommitted: unreported > 0,
    }
}

/// The error number a failed restart reports for `error`.
pub(crate) fn errno_of(error: PortError) -> i32 {
    match error {
        PortError::Native(_, rc) => rc.checked_neg().unwrap_or(libc::EIO),
        PortError::Pci(_) => libc::EIO,
        PortError::Llq => libc::ENOTSUP,
        PortError::Counters => libc::ENODATA,
        _ => libc::EINVAL,
    }
}

/// The receive ring wanted from `buffers` receive buffers: the largest power of two at most half of them, within the device's maximum.
pub(crate) fn rx_ring_for(buffers: u32, max: u16) -> u16 {
    let half = buffers / 2;
    let ring = if half == 0 { 0 } else { 1 << half.ilog2() };
    u16::try_from(ring.min(u32::from(max))).unwrap_or(u16::MAX)
}

/// Raises the reset flag the callback argument names; its body cannot unwind.
pub(crate) unsafe extern "C" fn on_reset(
    _port: u16,
    _event: sys::rte_eth_event_type,
    flag: *mut c_void,
    _ret: *mut c_void,
) -> c_int {
    // SAFETY: the argument is the port's leaked flag, which lives for the process.
    unsafe { &*flag.cast::<AtomicBool>() }.store(true, Ordering::Release);
    0
}

impl<'e> EnaPort<'e> {
    /// Qualifies and configures the ENA port at `bdf`, opening its PCI
    /// function under `host`'s sysfs at the same address, and leases it from
    /// `registration`. Descriptors name arena memory only once the port starts.
    ///
    /// # Errors
    ///
    /// [`PortError`] naming the first failed check.
    pub fn attach(
        env: &'e Environment,
        registration: &mut ArenaRegistration<'_>,
        host: &Host,
        bdf: &str,
        config: EnaConfig,
        supervisor: Arc<dyn Supervisor>,
    ) -> Result<Self, PortError> {
        let name = CString::new(bdf).map_err(|_| PortError::Identity)?;
        let mut id = 0;
        // SAFETY: `name` is a C string and `id` a valid output.
        if unsafe { sys::rte_eth_dev_get_port_by_name(name.as_ptr(), &mut id) } != 0 {
            return Err(PortError::Identity);
        }
        let info = info(id)?;
        // SAFETY: a successful info call points the driver name at a static string.
        let driver = unsafe { CStr::from_ptr(info.driver_name) };
        let mut mac = sys::rte_ether_addr::default();
        // SAFETY: `id` names a port and `mac` is writable.
        native("mac", unsafe { sys::rte_eth_macaddr_get(id, &mut mac) })?;
        qualify(&info, driver, mac.addr_bytes, config.mac)?;
        let llq = llq(env.probe_log()).ok_or(PortError::Llq)?;
        let pci = Function::open(&host.pci(bdf)).map_err(|e| PortError::Pci(e.kind()))?;
        let flr = pci.flr();
        let mut port = Self {
            id,
            bdf: bdf.to_owned(),
            pci,
            reset: Box::leak(Box::new(AtomicBool::new(false))),
            causes: [0; RESET_CAUSES.len()],
            seen: [0; RESET_CAUSES.len()],
            transmitted: false,
            cadence: Cadence::START,
            receive: None,
            report: PortReport {
                port: id,
                mac: config.mac,
                mtu: MTU,
                max_mtu: info.max_mtu,
                rx_offloads: RX_OFFLOADS,
                tx_offloads: TX_OFFLOADS,
                rx_ring: rx_ring_for(config.rx_buffers, info.rx_desc_lim.nb_max),
                tx_ring: TX_RING,
                segments: CHAIN_SEGMENTS,
                data_room: 0,
                headroom: 0,
                llq,
                flr,
            },
            state: State::Configured,
            restart_error: None,
            registration: registration.id(),
            lease: None,
            supervisor,
            driver: Driver::Native,
            _env: PhantomData,
        };
        port.configure()?;
        // SAFETY: the callback only stores to the leaked flag, which outlives every delivery.
        native("callback", unsafe {
            sys::rte_eth_dev_callback_register(
                id,
                sys::rte_eth_event_type_RTE_ETH_EVENT_INTR_RESET,
                Some(on_reset),
                std::ptr::from_ref(port.reset).cast_mut().cast(),
            )
        })?;
        port.lease = Some(registration.device_attached());
        Ok(port)
    }

    /// Configures one queue pair with the qualified offloads, the MTU and the effective rings.
    fn configure(&mut self) -> Result<(), PortError> {
        // SAFETY: the configuration is plain data; all zeroes is the driver default.
        let mut conf: sys::rte_eth_conf = unsafe { std::mem::zeroed() };
        conf.rxmode.mq_mode = sys::rte_eth_rx_mq_mode_RTE_ETH_MQ_RX_NONE;
        conf.rxmode.offloads = RX_OFFLOADS;
        conf.txmode.mq_mode = sys::rte_eth_tx_mq_mode_RTE_ETH_MQ_TX_NONE;
        conf.txmode.offloads = TX_OFFLOADS;
        let id = self.id;
        let (mut rx, mut tx, mut mtu) = (self.report.rx_ring, TX_RING, 0);
        // SAFETY: the port is stopped, and every argument is valid for its call.
        unsafe {
            native("configure", sys::rte_eth_dev_configure(id, 1, 1, &conf))?;
            native("mtu", sys::rte_eth_dev_set_mtu(id, MTU))?;
            native("mtu", sys::rte_eth_dev_get_mtu(id, &mut mtu))?;
            native(
                "rings",
                sys::rte_eth_dev_adjust_nb_rx_tx_desc(id, &mut rx, &mut tx),
            )?;
        }
        if mtu != MTU {
            return Err(PortError::Capability("mtu"));
        }
        if !rx.is_power_of_two() || !tx.is_power_of_two() {
            return Err(PortError::Capability("rings"));
        }
        self.report.rx_ring = rx;
        self.report.tx_ring = tx;
        // The per-queue counters exist once the queues are configured.
        self.causes = xstat_ids(id, RESET_CAUSES).ok_or(PortError::Counters)?;
        Ok(())
    }

    /// Sets up both queues, the receive queue over `receive`, then starts the
    /// port on the calling thread, where the driver's watchdog timer runs.
    ///
    /// # Errors
    ///
    /// `NotReady` before the registration verified, off an lcore, or when a
    /// receive buffer cannot hold an MTU frame; `State` unless configured; a
    /// failed native step.
    pub(crate) fn start(
        &mut self,
        receive: &PacketMempool<'_>,
        registration: &ArenaRegistration<'_>,
    ) -> Result<(), PortError> {
        // The pool and the registration must be the leased device's own: another lease's registration may undo while this port's queues still name its arena.
        let Some(lease) = &self.lease else {
            return Err(PortError::State);
        };
        if self.state != State::Configured
            || registration.id() != self.registration
            || receive.device() != lease.device()
        {
            return Err(PortError::State);
        }
        // SAFETY: reads the calling thread's lcore identity.
        let lcore = unsafe { sys::spdk_sys_rte_lcore_id() };
        let mp = receive.as_ptr();
        // SAFETY: a packet pool's private area is its packet-pool header.
        let room = unsafe {
            (*sys::spdk_sys_rte_mempool_get_priv(mp).cast::<sys::rte_pktmbuf_pool_private>())
                .mbuf_data_room_size
        };
        let headroom = sys::RTE_PKTMBUF_HEADROOM as u16;
        if !registration.is_ready()
            || lcore >= sys::RTE_MAX_LCORE
            || u32::from(room.saturating_sub(headroom)) < u32::from(MTU) + ETHERNET_HEADER
        {
            return Err(PortError::NotReady);
        }
        self.receive = NonNull::new(mp);
        self.report.data_room = room;
        self.report.headroom = headroom;
        self.run()
    }

    /// Sets up the queues and starts the configured port.
    fn run(&mut self) -> Result<(), PortError> {
        let id = self.id;
        let receive = self.receive.ok_or(PortError::State)?;
        let info = info(id)?;
        let mut tx = info.default_txconf;
        tx.offloads = TX_OFFLOADS;
        let mut rx = info.default_rxconf;
        rx.offloads = RX_OFFLOADS;
        // SAFETY: reads the calling thread's socket.
        let socket = unsafe { sys::rte_socket_id() };
        let (rx_ring, tx_ring) = (self.report.rx_ring, self.report.tx_ring);
        // SAFETY: the port is configured and stopped and holds its lease; the receive pool is the one `start` was given, which teardown releases only after this port's stop proof.
        unsafe {
            native(
                "tx queue",
                sys::rte_eth_tx_queue_setup(id, 0, tx_ring, socket, &tx),
            )?;
            native(
                "rx queue",
                sys::rte_eth_rx_queue_setup(id, 0, rx_ring, socket, &rx, receive.as_ptr()),
            )?;
            native("start", sys::rte_eth_dev_start(id))?;
        }
        self.state = State::Started;
        self.seen = self.read_causes().ok_or(PortError::Counters)?;
        // The first service after a start reads the reset-cause counters against this baseline; receives may reach the new ring at once.
        self.cadence = Cadence::START;
        self.transmitted = false;
        Ok(())
    }

    fn read_causes(&self) -> Option<[u64; RESET_CAUSES.len()]> {
        xstats(self.id, &self.causes)
    }

    pub fn report(&self) -> PortReport {
        self.report
    }

    /// The PCI address the port attached at.
    pub fn bdf(&self) -> &str {
        &self.bdf
    }

    /// Raises the reset flag as the driver's reset event does, for the host-pair recovery test; service reads it on its next counter-read turn.
    #[cfg(test)]
    pub(crate) fn request_reset(&self) {
        self.reset.store(true, Ordering::Release);
    }

    /// The function's command register as it reads now, for a stop certificate.
    ///
    /// # Errors
    ///
    /// As for [`Function::command`].
    #[cfg(test)]
    pub(crate) fn command(&self) -> io::Result<u16> {
        self.pci.command()
    }

    /// The ENI's allowance-exceeded counters, in [`ALLOWANCES`]' order,
    /// where the driver exposes them; each read uses the admin queue.
    pub fn allowances(&self) -> Option<[u64; ALLOWANCES.len()]> {
        xstats(self.id, &xstat_ids(self.id, ALLOWANCES)?)
    }

    /// Why the last restart failed.
    pub fn restart_error(&self) -> Option<PortError> {
        self.restart_error
    }

    /// The stop proof for the registration, once a stop was proven.
    pub fn stop_proof(&mut self) -> Option<DeviceStopped> {
        (self.state == State::Stopped)
            .then(|| self.lease.take().map(DeviceLease::stopped))
            .flatten()
    }

    /// Unregisters the reset callback and closes the port after its registration was undone.
    ///
    /// # Errors
    ///
    /// `State`, with the port back, unless its stop was proven and `undone` undid its registration.
    pub fn close(self, undone: &Unregistered<'_>) -> Result<(), Box<(Self, PortError)>> {
        if self.state != State::Stopped || !undone.undid(self.registration) {
            return Err(Box::new((self, PortError::State)));
        }
        // SAFETY: the port is stopped; the flag stays allocated whatever the unregister returns.
        unsafe {
            sys::rte_eth_dev_callback_unregister(
                self.id,
                sys::rte_eth_event_type_RTE_ETH_EVENT_INTR_RESET,
                Some(on_reset),
                std::ptr::from_ref(self.reset).cast_mut().cast(),
            );
            sys::rte_eth_dev_close(self.id);
        }
        Ok(())
    }
}

fn info(id: u16) -> Result<sys::rte_eth_dev_info, PortError> {
    // SAFETY: the info structure is plain data the call fills; all zeroes is a valid start.
    let mut info: sys::rte_eth_dev_info = unsafe { std::mem::zeroed() };
    // SAFETY: `id` names a port and `info` is writable.
    native("info", unsafe { sys::rte_eth_dev_info_get(id, &mut info) })?;
    Ok(info)
}

// SAFETY: receive heads come from the receive pool the queue was set up
// over and return through the driver's free, segment by segment, through
// each pool's ops; bursts leave the slices as they were and report counts
// within them; the driver's prepare refuses permanently; `uncertain` is set
// only when the preparation error counter rose or cannot be read, which
// covers the driver recording the packet before its post failed; a proven
// stop cleared bus mastering before the driver stopped and freed its queues,
// returning every held packet. A start that fails inside the driver frees
// the receive buffers it posted itself, with bus mastering on, relying on
// the driver's queue-destroy command. The port's lease comes from `attach`,
// which leases this port's own function, and leaves only through
// `stop_proof`.
unsafe impl Port for EnaPort<'_> {
    /// The port holds its device lease until `stop_proof` consumes it.
    fn device_lease(&self) -> Option<&DeviceLease> {
        self.lease.as_ref()
    }

    fn rx_burst(&mut self, out: &mut [*mut sys::rte_mbuf]) -> usize {
        if self.state != State::Started || !self.cadence.receives() {
            return 0;
        }
        let id = self.id;
        let written = received(out, |slots| {
            let n = slots.len().min(usize::from(u16::MAX)) as u16;
            // SAFETY: the port is started and `slots` holds `n` slots.
            usize::from(unsafe { sys::spdk_sys_rte_eth_rx_burst(id, 0, slots.as_mut_ptr(), n) })
        });
        if written.uncommitted {
            self.cadence.fault();
        }
        written.count
    }

    unsafe fn tx_prepare(&mut self, packets: &mut [*mut sys::rte_mbuf]) -> Prepared {
        let n = packets.len().min(usize::from(u16::MAX)) as u16;
        // SAFETY: the caller's contract; the error number is this thread's.
        let count = unsafe {
            sys::spdk_sys_rte_errno_clear();
            sys::spdk_sys_rte_eth_tx_prepare(self.id, 0, packets.as_mut_ptr(), n)
        };
        // SAFETY: reads this thread's error number.
        let error = (count < n).then(|| unsafe { sys::spdk_sys_rte_errno() });
        Prepared {
            count: usize::from(count),
            error,
        }
    }

    unsafe fn tx_burst(&mut self, packets: &mut [*mut sys::rte_mbuf]) -> TxBurst {
        if self.state != State::Started {
            return TxBurst {
                accepted: 0,
                uncertain: false,
            };
        }
        let n = packets.len().min(usize::from(u16::MAX)) as u16;
        self.transmitted = true;
        // SAFETY: the caller's contract.
        let accepted =
            unsafe { sys::spdk_sys_rte_eth_tx_burst(self.id, 0, packets.as_mut_ptr(), n) };
        let uncertain = uncertain(accepted < n, || self.read_causes(), &self.seen);
        TxBurst {
            accepted: usize::from(accepted),
            uncertain,
        }
    }

    fn tx_cleanup(&mut self, budget: NonZeroU32) -> i32 {
        self.transmitted = true;
        // SAFETY: the port's queue 0; the driver frees only packets it finished.
        unsafe { sys::rte_eth_tx_done_cleanup(self.id, 0, budget.get()) }
    }

    fn max_segments(&self) -> u16 {
        self.report.segments
    }

    fn rx_ring(&self) -> u32 {
        u32::from(self.report.rx_ring)
    }

    fn egress_exceeded(&self) -> Option<u64> {
        xstats(self.id, &xstat_ids(self.id, [ALLOWANCES[1]])?).map(|[count]| count)
    }

    #[inline(always)]
    fn service(&mut self) -> Health {
        if self.cadence.check_due() {
            self.check()
        } else {
            Health::Running
        }
    }

    fn stop(&mut self) -> Result<(), Unproven> {
        if self.state == State::Lost {
            return Err(Unproven);
        }
        if self.pci.set_bus_master(false).is_err() {
            self.lost();
            return Err(Unproven);
        }
        // A failed start can leave the driver started under the Configured or Reinitialized state, and a failed restart step leaves the port Restarting; the driver's stop returns zero for a port it never started.
        // SAFETY: `set_bus_master(false)` succeeded, so bus mastering is off and read back clear.
        if self.state != State::Stopped && unsafe { self.stop_driver() } != 0 {
            // The driver kept its queues and the packets on them; bus mastering stays off.
            self.lost();
            return Err(Unproven);
        }
        self.state = State::Stopped;
        Ok(())
    }

    fn reset(&mut self) -> Result<(), i32> {
        self.staged(Self::reset_function)
    }

    fn reinitialize(&mut self) -> Result<(), i32> {
        self.staged(Self::reinitialize_driver)
    }

    fn start(&mut self) -> Result<(), i32> {
        self.staged(Self::start_reinitialized)
    }
}

impl EnaPort<'_> {
    #[inline(never)]
    fn check(&mut self) -> Health {
        // SAFETY: the timer subsystem is initialized and this is the lcore the port started on.
        unsafe { sys::rte_timer_manage() };
        let announced =
            self.reset.load(Ordering::Acquire) && self.reset.swap(false, Ordering::AcqRel);
        let due = if std::mem::take(&mut self.transmitted) {
            let now = self.read_causes();
            let due = reset_due(announced, now.as_ref(), &self.seen);
            if let Some(now) = now {
                self.seen = now;
            }
            due
        } else {
            let [_, _, receive @ ..] = &self.causes;
            let now = xstats(self.id, receive);
            let [_, _, seen @ ..] = &mut self.seen;
            let due = reset_due(announced, now.as_ref(), seen);
            if let Some(now) = now {
                *seen = now;
            }
            due
        };
        if due { Health::Reset } else { Health::Running }
    }

    /// Runs one restart step and records its outcome as the restart's error: the step's error, or none.
    fn staged(&mut self, step: impl FnOnce(&mut Self) -> Result<(), PortError>) -> Result<(), i32> {
        let outcome = step(self);
        self.restart_error = outcome.err();
        outcome.map_err(errno_of)
    }

    /// Resets the stopped function and returns bus mastering.
    fn reset_function(&mut self) -> Result<(), PortError> {
        // A handed-off stop proof may have let the registration undo, so only a leased port restarts.
        if self.state != State::Stopped || self.receive.is_none() {
            return Err(PortError::State);
        }
        self.leased_ready()?;
        let pci = |e: io::Error| PortError::Pci(e.kind());
        // From here the device may reach memory again, so only a later stop proves it stopped.
        self.state = State::Restarting;
        self.pci.reset().map_err(pci)?;
        self.pci.set_bus_master(true).map_err(pci)?;
        self.state = State::Reset;
        Ok(())
    }

    /// Re-initializes the driver over the reset function with the attach-time low-latency placement, then configures the port.
    fn reinitialize_driver(&mut self) -> Result<(), PortError> {
        if self.state != State::Reset {
            return Err(PortError::State);
        }
        self.leased_ready()?;
        self.state = State::Restarting;
        let (rc, log) = match &mut self.driver {
            // SAFETY: the port is stopped and its function was reset, so no stale queue survives re-initialization.
            Driver::Native => capture(|| unsafe { sys::rte_eth_dev_reset(self.id) }),
            #[cfg(test)]
            Driver::Scripted { reset, .. } => reset(),
        };
        echo(&log);
        native("reset", rc)?;
        if llq(&log) != Some(self.report.llq) {
            return Err(PortError::Llq);
        }
        self.configure()?;
        self.state = State::Reinitialized;
        Ok(())
    }

    /// Starts the port re-initialized by [`reinitialize_driver`](Self::reinitialize_driver).
    fn start_reinitialized(&mut self) -> Result<(), PortError> {
        if self.state != State::Reinitialized {
            return Err(PortError::State);
        }
        self.leased_ready()?;
        self.run()
    }

    /// `State` without the lease, `NotReady` while the leasing registration
    /// is not ready: a restart step may let the device reach memory, which
    /// the registration vouches for only while it is ready.
    fn leased_ready(&self) -> Result<(), PortError> {
        match &self.lease {
            None => Err(PortError::State),
            Some(lease) if !lease.ready() => Err(PortError::NotReady),
            Some(_) => Ok(()),
        }
    }
}

impl EnaPort<'_> {
    /// Runs the driver's queue stop and returns its result.
    ///
    /// # Safety
    ///
    /// The caller must have cleared bus mastering and read the clear back.
    unsafe fn stop_driver(&mut self) -> c_int {
        match &mut self.driver {
            // SAFETY: bus mastering is off, as the caller guarantees, so the driver's queue release recycles memory the device can no longer reach.
            Driver::Native => unsafe { sys::rte_eth_dev_stop(self.id) },
            #[cfg(test)]
            Driver::Scripted { stop, .. } => stop(&self.pci),
        }
    }

    /// Marks the stop unproven and, when the port's queues may name arena memory, asks the supervisor to contain.
    fn lost(&mut self) {
        self.state = State::Lost;
        if self.lease.is_some() {
            self.supervisor.contain();
        }
    }
}

#[cfg(test)]
impl EnaPort<'_> {
    /// A port of `registration` over `pci` with no DPDK port behind it, configured or stopped, with `receive` as `start` would leave it.
    pub(crate) fn detached(
        pci: Function,
        receive: Option<NonNull<sys::rte_mempool>>,
        registration: RegistrationId,
        stopped: bool,
        supervisor: Arc<dyn Supervisor>,
    ) -> Self {
        let flr = pci.flr();
        Self {
            id: u16::MAX,
            bdf: String::new(),
            pci,
            reset: Box::leak(Box::new(AtomicBool::new(false))),
            causes: [0; RESET_CAUSES.len()],
            seen: [0; RESET_CAUSES.len()],
            transmitted: false,
            cadence: Cadence::START,
            receive,
            report: PortReport {
                port: u16::MAX,
                mac: [0; 6],
                mtu: MTU,
                max_mtu: MTU,
                rx_offloads: RX_OFFLOADS,
                tx_offloads: TX_OFFLOADS,
                rx_ring: 0,
                tx_ring: TX_RING,
                segments: CHAIN_SEGMENTS,
                data_room: 0,
                headroom: 0,
                llq: Llq { entry: 0, push: 0 },
                flr,
            },
            state: if stopped {
                State::Stopped
            } else {
                State::Configured
            },
            restart_error: None,
            registration,
            lease: None,
            supervisor,
            driver: Driver::Scripted {
                stop: Box::new(|_| 0),
                reset: Box::new(|| (-libc::ENODEV, String::new())),
            },
            _env: PhantomData,
        }
    }

    pub(crate) fn leased(mut self, lease: DeviceLease) -> Self {
        self.lease = Some(lease);
        self
    }

    /// Makes the port's driver stop run `stop`, which sees the port's PCI
    /// function when called and returns the driver's result. A detached
    /// port's driver stop otherwise returns zero.
    pub(crate) fn driver_stop(mut self, stop: impl FnMut(&Function) -> c_int + 'static) -> Self {
        let Driver::Scripted { stop: scripted, .. } = &mut self.driver else {
            unreachable!("a detached port's driver is scripted");
        };
        *scripted = Box::new(stop);
        self
    }

    /// Makes the port's driver re-initialization return `rc` and `log` as
    /// the log its probe wrote, and gives the port `attached` as its
    /// attach-time placement. A detached port's re-initialization otherwise
    /// finds no device.
    pub(crate) fn driver_reset(mut self, attached: Llq, rc: c_int, log: &str) -> Self {
        let Driver::Scripted { reset, .. } = &mut self.driver else {
            unreachable!("a detached port's driver is scripted");
        };
        let log = log.to_owned();
        *reset = Box::new(move || (rc, log.clone()));
        self.report.llq = attached;
        self
    }

    /// Makes the next stop run `stall` after it clears bus mastering and before it reads the clear back.
    pub(crate) fn stall_before_proof(&self, stall: impl FnOnce() + Send + 'static) {
        self.pci.stall_before_readback(stall);
    }
}

impl Drop for EnaPort<'_> {
    /// Stops a port dropped while it may reach memory; the lease, never returned, keeps the registration held. A port `start` never gave a receive pool posted nothing, and keeps the bus mastering DPDK enabled at probe.
    fn drop(&mut self) {
        if matches!(
            self.state,
            State::Started
                | State::Configured
                | State::Restarting
                | State::Reset
                | State::Reinitialized
        ) && self.receive.is_some()
        {
            let _ = Port::stop(self);
        }
    }
}
