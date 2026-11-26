//! The burst logic between the datagram seam and a device queue pair,
//! behind one narrow port boundary that tests mock.
//!
//! Invariants owned by this module:
//!
//! - Burst logic serves one device lease. [`Burst::over`] checks once,
//!   before it allocates anything, that the port's lease and the device every
//!   pool serves name one device, and that `registration` leased it,
//!   comparing the full device identity: registration and lease number.
//!   Packet paths rely on that single check. A refused construction returns
//!   the untouched port and its addressing to the caller, who chooses how the
//!   port stops.
//! - A transmit chain is one header mbuf from the header pool, holding the
//!   wire headers, the frame headers and any inline pieces, followed by at
//!   most two payload descriptors, each holding one device reference to a
//!   retained source at the shared registration's IOVA for its bytes, which
//!   lie inside one backing page. A datagram with an empty retained piece
//!   is unsendable, since the registration translates no empty range. The
//!   chain's segments never exceed the
//!   port's negotiated limit. A segment's IOVA comes from a per-buffer table
//!   the burst logic reads from the registration once, at construction,
//!   since the registration's translations are fixed while it is borrowed.
//!   The registration's readiness is not fixed: a failed recheck clears it
//!   under a shared borrow. So every send reads it once and refuses with
//!   `ESTALE`, building nothing, while the registration is unverified.
//! - A chain's segment order is its datagram's byte order, so a send requires
//!   every inline piece with bytes to precede every retained piece. It also
//!   requires every retained source to belong to the payload pool's arena,
//!   which the IOVA table and the token's device return both name by buffer
//!   index.
//! - A send takes a datagram's header buffer before its descriptors, so a
//!   datagram the header pool refuses holds no descriptor. Each peer's wire
//!   headers are encoded once, at construction; a send copies them and
//!   writes the source port its first frame's wire slot selects and the two
//!   length fields.
//! - A send prepares the chains it built, bursts the prepared prefix, and
//!   before it returns releases every chain the device definitely did not
//!   accept, so an unaccepted datagram holds no header buffer and no device
//!   reference. A chain the device may have kept after a failed native post
//!   is quarantined instead of released, and the transport refuses later
//!   sends with `EIO` while the link stays up, until a proven stop settles
//!   the chain. Quarantine records the chain's segments and its header's
//!   armed token. A post that unwinds instead of returning loses the link,
//!   so every chain it was offered stays held.
//! - A send separates pressure from refusal: a full ring or empty pools stop
//!   the accepted prefix, and a leading datagram that meets them yields an
//!   empty prefix the caller resends; a datagram no send can carry, or one
//!   the device's prepare refuses, fails the call when it leads.
//! - Every received buffer this receive pool posted ends its call either as
//!   a lease over a validated frame's UDP payload or back on its pool's free
//!   stack; a frame spanning several buffers returns every one. A receive
//!   while the registration is unverified refuses with `ESTALE` before it
//!   asks the device for frames, since asking lets the driver refill its
//!   ring with arena buffers. A packet the
//!   receive pool never posted is counted foreign and left with the device's
//!   pool, untouched. A receive checks every frame's descriptor fields
//!   first, returning a refused buffer without leasing it, and starts
//!   fetching each passing frame's first line while the frame stays posted
//!   by buffer index. It then checks the frames' bytes, so a burst's frame
//!   lines, which the device wrote, are fetched together. Only a frame whose
//!   bytes pass becomes a lease in the caller's next slot; a frame refused
//!   on its bytes returns its buffer to the free stack, and slots past the
//!   count keep what they held.
//! - Cleanup asks the device to return finished transmits within a nonzero
//!   budget; its numeric result changes no custody, and the returns it causes
//!   release exactly their own tokens through the ops. A port may return a
//!   chain's segments in separate cleanups, so reclaim asks while a header
//!   buffer is held or a payload descriptor is out, and an idle transport
//!   gets back a descriptor whose header returned before it.
//! - Debug builds recheck each payload segment's IOVA against the
//!   registration once the descriptor is written.
//! - A datagram to a peer leaves from the source port its first frame's wire
//!   slot selects, to the peer's base port: one request's lone datagrams share
//!   one flow and keep their order through per-flow paths and queues, while a
//!   peer's requests whose wire slots differ modulo the host's source-port
//!   count leave from different source ports. A packed datagram leaves on the
//!   flow of its first frame's wire slot, so a GET packed behind another
//!   request's GET leaves on that request's flow, and its request's CANCEL or
//!   retry can overtake it on the path. When that flow differs from the flow
//!   of the packed GET's own wire slot, the GET can also arrive ahead of the
//!   CANCEL of that slot's previous request, and the owner refuses a GET
//!   whose wire slot a request still holds. Packed datagrams whose first
//!   frames' wire slots are equal modulo the source-port count leave from one
//!   source port.
//! - An uncertain post ends admission. Each turn's reclaim services the
//!   device first and runs quiesced recovery instead of cleanup when a reset
//!   is pending or a post was uncertain. Recovery first proves the device
//!   stopped its DMA, which returns every packet it held, then reconciles the
//!   quarantined chain: a header token the device's return disarmed counts a
//!   device return, and a header token still armed shows the device never
//!   took the chain, whose recorded segments then return locally, each once.
//!   Recovery then rechecks the shared registration and restarts the device;
//!   a registration that fails its recheck counts as a failed restart, with
//!   `ESTALE`. A stop that cannot be proven leaves the link lost, with
//!   everything the device held kept off every free stack. A link left down
//!   or lost stays so for the burst logic: transmit and receive report the
//!   transport closed, and the endpoint decides what follows.

use std::alloc::Layout;
use std::ffi::c_void;
use std::fmt;
use std::iter;
use std::mem::MaybeUninit;
use std::num::NonZeroU32;
use std::ptr;
use std::time::Instant;

use spdk_sys as sys;

use super::mempool::{OpsState, PacketMempool, Role, Token};
use super::recovery::{RecoveryEpisode, RecoveryStage, RecoveryWatch};
use super::registration::{ArenaRegistration, DeviceLease};
use super::wire::{ETH_LEN, IPV4_LEN, Refused, RxMeta, UDP_LEN, Wire};
use crate::net::MAX_PAYLOAD_SLICES;
use crate::net::{
    DatagramError, Datagrams, FRAME_OVERHEAD, HEADER_LEN, Outgoing, PacketLease, PacketPool,
    Payload, PeerId, Received,
};
use crate::storage::prefetch;
use crate::storage::{Buffer, EngineBudget, EngineBudgetExceeded, PacketLayout, SourceRange};

/// Finished transmits one turn's cleanup asks the device to return.
const CLEANUP_BUDGET: NonZeroU32 = NonZeroU32::new(64).unwrap();

/// One transmit burst's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxBurst {
    /// Packets the device took.
    pub accepted: usize,
    /// The device may hold the first packet it did not take, after a native post failed past its ownership point.
    pub uncertain: bool,
}

/// One prepare's outcome: the prefix that passed, and the error number of the first packet it refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prepared {
    pub count: usize,
    pub error: Option<i32>,
}

/// What one turn's device service found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Running,
    /// A cause the device's driver resets for is pending.
    Reset,
}

/// A device stop that did not prove the device can no longer reach memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unproven;

/// Whether the transport carries datagrams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    Up,
    /// The device stopped with its DMA proven off and did not restart; it holds nothing.
    Down,
    /// Either no stop is proven since the device last could reach memory, a
    /// recovery's watchdog asked its supervisor to contain, or a native post
    /// unwound; every buffer the device may hold stays held.
    Lost,
}

/// One device queue pair, the boundary the burst logic drives.
///
/// # Safety
///
/// An implementation upholds what the burst logic's unsafe code relies on:
///
/// - `rx_burst` writes only mbufs the device finished writing, each one a
///   head some mempool's dequeue gave the device, chained only through mbufs
///   of that pool, and returns the count of leading slots it wrote in that
///   call. The burst logic's out-tracking, not this trait, establishes that a
///   packet is the receive pool's.
/// - `tx_prepare` and `tx_burst` leave the slice's pointers as they were and
///   report counts within it. A prepare's short prefix is a permanent refusal
///   of the packet after it, never pressure.
/// - `tx_burst` reports exactly the packets the device took. It reports
///   `uncertain` when the device may hold the first packet it did not take,
///   such as a native post that failed after the driver recorded the packet,
///   which a driver error counter or reset state shows; a plain short count
///   from a full ring is not uncertain. The device may or may not have taken
///   an uncertain packet. The device returns every packet it took, an
///   uncertain one included when it took it, once, through the pools' ops,
///   never in bulk across pools.
/// - `stop` returns `Ok` only once the device can no longer issue DMA and has
///   returned every packet it held, transmit and receive, through the pools'
///   ops; it may hold the thread for the device's command timeouts.
///   `start` posts receive buffers only from the receive pool.
/// - `device_lease` returns `Some` only with the lease of the device whose
///   queues this port drives, while the port holds that lease. The burst
///   logic matches pools and a registration to the port by that lease's
///   device identity, which names both the registration and the lease, so two
///   leases of one registration name two devices. The burst logic checks
///   once, at construction, so the port keeps that lease and drives that
///   lease's device with every method from the first call that returns
///   `Some` until the burst logic gives the port back.
pub unsafe trait Port {
    /// The lease of the device this port drives, while the port holds it.
    /// [`Burst::over`] accepts only pools and a registration of this device.
    fn device_lease(&self) -> Option<&DeviceLease>;

    /// Received packets, at most `out.len()`.
    fn rx_burst(&mut self, out: &mut [*mut sys::rte_mbuf]) -> usize;

    /// Prepares `packets` for transmit.
    ///
    /// # Safety
    ///
    /// Each pointer heads a chain the caller owns, built from the pools whose ops serve this port's device.
    unsafe fn tx_prepare(&mut self, packets: &mut [*mut sys::rte_mbuf]) -> Prepared;

    /// Hands `packets` to the device.
    ///
    /// # Safety
    ///
    /// As for [`tx_prepare`](Self::tx_prepare), each chain prepared; the accepted prefix passes to the device, and an uncertain packet may.
    unsafe fn tx_burst(&mut self, packets: &mut [*mut sys::rte_mbuf]) -> TxBurst;
    /// Asks the device to return at most `budget` finished transmits; the count it reports is advisory.
    fn tx_cleanup(&mut self, budget: NonZeroU32) -> i32;
    /// The most segments one packet may have, as the device negotiated.
    fn max_segments(&self) -> u16;
    /// Receive buffers the device keeps posted: its effective ring size.
    fn rx_ring(&self) -> u32;
    /// The count of outbound packets the host's bandwidth allowance has queued or dropped so far, where the device reports it. Each read may use the device's admin queue.
    fn egress_exceeded(&self) -> Option<u64> {
        None
    }
    /// `service` runs the device's timers and checks its reset causes. It returns [`Health::Reset`] when the device announces a reset, a checked reset-cause counter rises, or the counters cannot be read, and [`Health::Running`] otherwise. [`EnaPort`](super::EnaPort) runs the timers and checks on the first call after each start, on the first call after a receive burst its driver ended early, during which its receive bursts return nothing, and then every `CAUSE_TURNS` calls.
    fn service(&mut self) -> Health;
    /// Stops the device and proves its DMA off.
    ///
    /// # Errors
    ///
    /// [`Unproven`] when the device may still reach memory.
    fn stop(&mut self) -> Result<(), Unproven>;
    /// Resets the function of a device whose stop was proven. From the reset
    /// on, the device may reach memory until a later stop proves it stopped.
    ///
    /// # Errors
    ///
    /// The native error number of the failed step.
    fn reset(&mut self) -> Result<(), i32>;
    /// Re-initializes the driver over the reset device with its attach-time
    /// placement and reconfigures it.
    ///
    /// # Errors
    ///
    /// The native error number of the failed step.
    fn reinitialize(&mut self) -> Result<(), i32>;
    /// Starts the reconfigured device.
    ///
    /// # Errors
    ///
    /// The native error number of the failed step.
    fn start(&mut self) -> Result<(), i32>;
}

/// Counters of the burst logic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BurstReport {
    pub sent: u64,
    /// Prepared datagrams the ring did not take, which stayed with the caller.
    pub ring_full: u64,
    /// Datagrams the device's prepare refused.
    pub prepare_refused: u64,
    /// Chains the device may hold after an uncertain post, each kept off every free stack until a proven stop settles it as `quarantine_returned` or `quarantine_released`.
    pub quarantined: u64,
    /// Quarantined chains a proven stop found the device returned through the pools' ops.
    pub quarantine_returned: u64,
    /// Quarantined chains a proven stop found the device never took, released locally.
    pub quarantine_released: u64,
    /// Datagrams not built for want of a header buffer, a descriptor or a source reference.
    pub exhausted: u64,
    /// Datagrams send validation rejects: an unknown peer, excessive length or segment count, inline bytes after a retained piece, a source outside the payload pool's arena, or a missing registered IOVA.
    pub unsendable: u64,
    pub received: u64,
    /// Received frames dropped, by [`Refused`] reason.
    pub dropped: [u64; Refused::COUNT],
    /// Recoveries started, and the ones that left the link up: every stage succeeded and the episode disarmed its
    /// watchdog before it expired.
    pub resets: u64,
    pub recoveries: u64,
    /// The last recovery's pause, in microseconds, whatever its outcome.
    pub pause_us: u64,
    /// The error number of the last failed restart.
    pub restart_error: Option<i32>,
    /// The last recovery episode: its stages, any expiry and the containment it requested.
    pub episode: RecoveryEpisode,
    /// Datagrams built per source port, by offset from the base port modulo eight.
    pub sources: [u64; 8],
}

/// One peer's transmit addressing: the headers every datagram to it shares,
/// from this host's base port to the peer's base port with the length fields
/// zero.
struct Route {
    headers: [u8; FRAME_OVERHEAD],
}

/// The offset from the base port of the source port a datagram leaves from: its
/// first frame's wire slot, the high 16 bits of the wire ID at byte 56 of `header`,
/// modulo the host's `ports`. A header too short to carry a wire slot leaves
/// from the base port.
#[inline(always)]
fn source_offset(header: &[u8], ports: u16) -> u16 {
    let slot = match header.get(56..58) {
        Some(bytes) => u16::from_be_bytes([bytes[0], bytes[1]]),
        None => 0,
    };
    slot % ports.max(1)
}

/// Writes the source port and the IPv4 and UDP lengths of a datagram of `payload_len` UDP payload bytes into a [`Route`]'s headers; `build` bounds the payload below the IPv4 limit.
#[inline(always)]
fn stamp(out: &mut [u8; FRAME_OVERHEAD], src_port: u16, payload_len: u16) {
    out[16..18].copy_from_slice(&(20 + 8 + payload_len).to_be_bytes());
    out[34..36].copy_from_slice(&src_port.to_be_bytes());
    out[38..40].copy_from_slice(&(8 + payload_len).to_be_bytes());
}

/// A chain's dimensions: the header segment's bytes, the packet's bytes and its segment count.
#[derive(Clone, Copy)]
struct Shape {
    head_len: usize,
    total: usize,
    segments: u16,
}

/// Why a datagram was not built.
enum Unbuilt {
    Exhausted,
    Unsendable,
}

/// Why burst logic was not built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BurstError {
    /// The port holds no device lease, or its lease is not the device the header pool serves.
    Port,
    /// A pool is not of the role its argument names or of its siblings' device, the device is not `registration`'s lease, or the header pool's stride has no packet layout.
    Pools,
    /// The batch is zero, or the retained state's size exceeds the address space.
    Batch,
    /// The engine budget cannot hold the burst logic's retained state.
    Budget(EngineBudgetExceeded),
}

/// A refused construction: why, and the untouched port and addressing it was
/// given. The port may still hold a device lease and native queues, so the
/// caller stops it and retires its lease.
#[must_use = "the refusal holds a port the caller must stop"]
pub struct BurstRefusal<'a, P> {
    pub error: BurstError,
    pub port: P,
    pub wire: Wire<'a>,
}

impl<P> fmt::Debug for BurstRefusal<'_, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BurstRefusal")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// Burst caches the registration's per-buffer IOVA offsets at construction,
/// rechecks segment IOVAs in debug builds, and rechecks every page before
/// recovery restarts the port.
pub(crate) trait Translation {
    /// The device-facing address of the `len` bytes at `addr`, or `None` when
    /// the bytes have no single device address.
    fn iova(&self, addr: usize, len: usize) -> Option<u64>;

    /// The offset from each buffer's address to the IOVA `iova` returns for
    /// the whole buffer, or `None`.
    fn offsets(&self, span: usize, len: usize, count: usize) -> Box<[Option<u64>]>;

    /// Whether every page's translation still matches the registration's
    /// verified translation.
    fn recheck(&self) -> bool;

    /// Whether the registration still vouches for the translations
    /// `offsets` returned: every page verified and no check since failed.
    fn ready(&self) -> bool;
}

impl Translation for ArenaRegistration<'_> {
    fn iova(&self, addr: usize, len: usize) -> Option<u64> {
        ArenaRegistration::iova(self, addr, len)
    }

    fn offsets(&self, span: usize, len: usize, count: usize) -> Box<[Option<u64>]> {
        ArenaRegistration::offsets(self, span, len, count)
    }

    fn recheck(&self) -> bool {
        ArenaRegistration::recheck(self).is_ok()
    }

    fn ready(&self) -> bool {
        self.is_ready()
    }
}

/// The transmit and receive halves over one owned port, its pools and its addressing.
pub struct Burst<'a, P: Port> {
    port: P,
    wire: Wire<'a>,
    header: &'a OpsState,
    payload: &'a OpsState,
    receive: &'a OpsState,
    /// The shared registration: debug builds check each segment's IOVA through it, and recovery rechecks every page through it before restarting the port.
    registration: &'a dyn Translation,
    /// Caching per-buffer IOVA offsets of the payload pool reduces address translation in `segment` to one wrapping addition.
    translations: Box<[Option<u64>]>,
    /// Per peer, indexed by [`PeerId`]: the headers every datagram to it shares.
    routes: Box<[Route]>,
    link: Link,
    /// The header buffers' layout.
    layout: PacketLayout,
    chains: Box<[*mut sys::rte_mbuf]>,
    rx: Box<[*mut sys::rte_mbuf]>,
    /// The buffer index of each frame in `rx` whose descriptor passed, kept posted by index between a receive's two passes.
    posted: Box<[u32]>,
    /// The chain the last uncertain post quarantined, until a proven stop reconciles it; while it is set, the transport is poisoned.
    quarantine: Option<Quarantined>,
    /// The deadline and supervisor of the watchdog worker each recovery episode arms.
    watch: RecoveryWatch,
    report: BurstReport,
}

/// A quarantined chain's identity, recorded when the uncertain post returned:
/// its segments, header first, and the header mbuf's armed token, which
/// `reconcile` compares with the header's token after a proven stop.
struct Quarantined {
    segments: [*mut sys::rte_mbuf; 1 + MAX_PAYLOAD_SLICES],
    /// Leading entries of `segments` the chain fills.
    len: usize,
    /// `None` when the header's token was already disarmed at record time, which a device return through the header pool's ops does; `reconcile` then releases nothing.
    token: Option<Token>,
}

impl<'a, P: Port> Burst<'a, P> {
    /// Burst logic over `port` and the header, payload and receive pools, carrying at most `batch` datagrams per call, its payload IOVAs from `registration`.
    ///
    /// # Errors
    ///
    /// [`BurstRefusal`], holding the port and `wire`, before anything is
    /// allocated, with:
    ///
    /// - [`BurstError::Port`] when the port holds no lease or its lease is
    ///   not the header pool's device.
    /// - [`BurstError::Pools`] when the payload or receive pool serves another
    ///   device than the header pool, `registration` did not lease that
    ///   device, a pool is not of the role its position names, or the header
    ///   stride has no packet layout.
    /// - [`BurstError::Batch`] when `batch` is zero or the retained state's
    ///   size exceeds the address space, and every check above passes.
    /// - [`BurstError::Budget`] when `budget` cannot hold the retained state,
    ///   with `budget` unchanged.
    pub fn over(
        port: P,
        wire: Wire<'a>,
        pools: [&'a PacketMempool<'_>; 3],
        registration: &'a ArenaRegistration<'_>,
        watch: RecoveryWatch,
        batch: usize,
        budget: &mut EngineBudget,
    ) -> Result<Self, BurstRefusal<'a, P>> {
        let [header, payload, receive] = pools;
        let device = header.device();
        let error = if port.device_lease().map(DeviceLease::device) != Some(device) {
            Some(BurstError::Port)
        } else if payload.device() != device
            || receive.device() != device
            || device.registration() != registration.id()
        {
            Some(BurstError::Pools)
        } else {
            None
        };
        if let Some(error) = error {
            return Err(BurstRefusal { error, port, wire });
        }
        Self::new(
            port,
            wire,
            [header.ops(), payload.ops(), receive.ops()],
            registration,
            watch,
            batch,
            budget,
        )
    }

    /// Burst logic over the ops states of the header, payload and receive
    /// pools, where `registration` translates payload bytes and repeats its
    /// verification, charging its retained state to `budget`:
    /// [`charge`](Self::charge) bytes.
    ///
    /// The caller vouches that the pools and `registration` serve the port's
    /// leased device; [`Burst::over`] is the entry point that checks it.
    ///
    /// # Errors
    ///
    /// [`BurstRefusal`], holding the port and `wire`, before anything is
    /// allocated, with:
    ///
    /// - [`BurstError::Pools`] when a pool is not of the role its position
    ///   names or the header stride has no packet layout.
    /// - [`BurstError::Batch`] when `batch` is zero or the retained state's
    ///   size exceeds the address space, and the roles and the header layout
    ///   pass.
    /// - [`BurstError::Budget`] when `budget` cannot hold the charge, with
    ///   `budget` unchanged.
    pub(crate) fn new(
        port: P,
        wire: Wire<'a>,
        pools: [&'a OpsState; 3],
        registration: &'a dyn Translation,
        watch: RecoveryWatch,
        batch: usize,
        budget: &mut EngineBudget,
    ) -> Result<Self, BurstRefusal<'a, P>> {
        let [header, payload, receive] = pools;
        let roles = [header.role(), payload.role(), receive.role()]
            == [Role::Header, Role::Payload, Role::Receive];
        let layout = if roles {
            PacketLayout::of(header.served().1)
        } else {
            None
        };
        let Some(layout) = layout else {
            let error = BurstError::Pools;
            return Err(BurstRefusal { error, port, wire });
        };
        let (span, spec) = payload.pool().span();
        let charge = (batch > 0)
            .then(|| Self::charge(spec.count as usize, wire.peers(), batch))
            .flatten();
        let Some(charge) = charge else {
            let error = BurstError::Batch;
            return Err(BurstRefusal { error, port, wire });
        };
        let mut staged = *budget;
        if let Err(exceeded) = staged.charge(charge) {
            let error = BurstError::Budget(exceeded);
            return Err(BurstRefusal { error, port, wire });
        }
        let len = spec.buffer_len as usize;
        let translations = registration.offsets(span, len, spec.count as usize);
        let routes = (0..wire.peers())
            .map(|at| {
                let mut headers = [0; FRAME_OVERHEAD];
                // Every index below `peers()` names a peer, so the template exists.
                wire.headers(&mut headers, PeerId(at as u16), 0);
                Route { headers }
            })
            .collect();
        let burst = Self {
            port,
            wire,
            header,
            payload,
            receive,
            registration,
            translations,
            routes,
            link: Link::Up,
            layout,
            chains: iter::repeat_n(ptr::null_mut(), batch).collect(),
            rx: iter::repeat_n(ptr::null_mut(), batch).collect(),
            posted: iter::repeat_n(0, batch).collect(),
            quarantine: None,
            watch,
            report: BurstReport::default(),
        };
        *budget = staged;
        Ok(burst)
    }

    /// The heap bytes burst logic over `translations` payload buffers,
    /// `peers` peers and batches of `batch` keeps: the payload translations,
    /// the routes and the three batch arrays; `None` when they exceed the
    /// address space.
    pub(crate) fn charge(translations: usize, peers: usize, batch: usize) -> Option<usize> {
        [
            Layout::array::<Option<u64>>(translations),
            Layout::array::<Route>(peers),
            Layout::array::<*mut sys::rte_mbuf>(batch),
            Layout::array::<*mut sys::rte_mbuf>(batch),
            Layout::array::<u32>(batch),
        ]
        .into_iter()
        .try_fold(0usize, |total, layout| {
            total.checked_add(layout.ok()?.size())
        })
    }

    pub fn report(&self) -> BurstReport {
        self.report
    }

    /// Whether an uncertain native post poisoned the transport.
    pub fn poisoned(&self) -> bool {
        self.quarantine.is_some()
    }

    pub fn link(&self) -> Link {
        self.link
    }

    /// The port, for its stop proof and teardown once the endpoint is done.
    /// A pending quarantine settles first: the port stops, and a proven stop
    /// reconciles the chain. An unproven stop, or a recovery whose watchdog
    /// asked to contain, leaves the chain charged to its pools. The watch
    /// itself answers whether it asked: a stage that unwound left its deadline
    /// running, so the expiry may postdate every episode. Disarming first ends
    /// a deadline still running and waits out a containment in progress, so
    /// no request follows the settling stop.
    pub fn into_port(mut self) -> P {
        if self.poisoned() && !self.watch.disarm() {
            let _unproven = self.settle();
        }
        self.port
    }

    /// Quiesced recovery under a watchdog armed before the first step: proves
    /// the device stopped, settles the quarantined chain, rechecks the shared
    /// registration, then resets, re-initializes and starts the device,
    /// leaving the link down or lost at the first step that fails. A watchdog
    /// that expires before the episode disarms it asks its supervisor to
    /// contain once; the episode skips every later step and loses the link,
    /// so every buffer the device may hold stays held. A watchdog that cannot
    /// arm leaves the device untouched and the link lost with everything
    /// held. Recovery runs at most once per reset or uncertain post: a stage
    /// that unwinds leaves the link lost and the episode's deadline running.
    #[cold]
    fn recover(&mut self) {
        let start = Instant::now();
        self.report.resets += 1;
        let mut episode = RecoveryEpisode {
            episode: self.report.resets,
            ..RecoveryEpisode::default()
        };
        self.link = if self.watch.arm() {
            // A stage that unwinds skips the disarm below. The link is lost first, so no later turn rearms the running deadline, whose expiry still asks to contain.
            self.link = Link::Lost;
            let link = self.restore(&mut episode);
            if self.watch.disarm() {
                // An expiry after the last stage's own check falls on that stage.
                episode.expired_at = episode.expired_at.or(episode.reached);
                episode.containment_requested = true;
                episode.containment_verified = self.watch.verified();
                Link::Lost
            } else {
                link
            }
        } else {
            episode.refused = true;
            Link::Lost
        };
        if self.link == Link::Up {
            self.report.recoveries += 1;
        }
        self.report.episode = episode;
        self.report.pause_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    }

    pub fn port(&self) -> &P {
        &self.port
    }

    #[cfg(test)]
    pub(crate) fn port_mut(&mut self) -> &mut P {
        &mut self.port
    }

    #[cfg(test)]
    pub(super) fn quarantine_header(&self) -> Option<*mut sys::rte_mbuf> {
        self.quarantine.as_ref().map(|chain| chain.segments[0])
    }

    /// The link after one recovery attempt under the armed watch, recording
    /// in `episode` each stage the attempt begins. A watchdog found expired
    /// before a stage begins or when a stage returns ends the attempt with the
    /// link lost. A failed restart stage stops the device again, and a proven
    /// stop leaves the link down.
    fn restore(&mut self, episode: &mut RecoveryEpisode) -> Link {
        match self.staged(episode, RecoveryStage::Stop, |burst| burst.port.stop()) {
            Some(Ok(())) => self.reconcile(),
            None | Some(Err(Unproven)) => return Link::Lost,
        }
        let restarted = self.restart_under(episode);
        let Some(restarted) = restarted else {
            return Link::Lost;
        };
        let Err(code) = restarted else {
            return Link::Up;
        };
        self.report.restart_error = Some(code);
        match self.staged(episode, RecoveryStage::Stop, |burst| burst.port.stop()) {
            Some(Ok(())) => Link::Down,
            None | Some(Err(Unproven)) => Link::Lost,
        }
    }

    /// The recheck, reset, re-initialization and start in order under the
    /// armed watch: `None` when the watchdog expired before a stage began or
    /// by the time a stage returned, else the first failed stage's error
    /// number, or success.
    fn restart_under(&mut self, episode: &mut RecoveryEpisode) -> Option<Result<(), i32>> {
        let rechecked = self.staged(episode, RecoveryStage::Recheck, |burst| {
            burst.registration.recheck()
        })?;
        if !rechecked {
            return Some(Err(libc::ESTALE));
        }
        if let Err(code) = self.staged(episode, RecoveryStage::Reset, |burst| burst.port.reset())? {
            return Some(Err(code));
        }
        if let Err(code) = self.staged(episode, RecoveryStage::Reinitialize, |burst| {
            burst.port.reinitialize()
        })? {
            return Some(Err(code));
        }
        self.staged(episode, RecoveryStage::Restart, |burst| burst.port.start())
    }

    /// Records `stage` as begun, runs `step`, and returns its outcome. When
    /// the watchdog has expired before `step` begins, `step` stays unrun and
    /// the expiry falls on the last stage begun; when it has expired by the
    /// time `step` returns, the expiry falls on `stage`. Either way the
    /// result is `None`.
    fn staged<T>(
        &mut self,
        episode: &mut RecoveryEpisode,
        stage: RecoveryStage,
        step: impl FnOnce(&mut Self) -> T,
    ) -> Option<T> {
        if self.watch.expired() {
            episode.expired_at = episode.reached;
            return None;
        }
        episode.reached = Some(stage);
        let outcome = step(self);
        if self.watch.expired() {
            episode.expired_at = Some(stage);
            return None;
        }
        Some(outcome)
    }

    fn transmit(&mut self, batch: &[Outgoing<'_, 'a>]) -> Result<usize, DatagramError> {
        if self.link != Link::Up {
            return Err(DatagramError::Closed);
        }
        if self.poisoned() {
            return Err(DatagramError::Failed {
                code: Some(libc::EIO),
            });
        }
        // The cached translations are the registration's only while it is verified.
        if !self.registration.ready() {
            return Err(DatagramError::Failed {
                code: Some(libc::ESTALE),
            });
        }
        let limit = batch.len().min(self.chains.len());
        let mut built = 0;
        for datagram in &batch[..limit] {
            match self.build(datagram) {
                Ok(chain) => {
                    self.chains[built] = chain;
                    built += 1;
                }
                Err(reason) => {
                    let unsendable = matches!(reason, Unbuilt::Unsendable);
                    let counter = if unsendable {
                        &mut self.report.unsendable
                    } else {
                        &mut self.report.exhausted
                    };
                    *counter += 1;
                    if built == 0 && unsendable {
                        return Err(DatagramError::Failed {
                            code: Some(libc::EINVAL),
                        });
                    }
                    break;
                }
            }
        }
        // SAFETY: each chain is one this call built from its own pools and holds.
        let prepared = unsafe { self.port.tx_prepare(&mut self.chains[..built]) };
        let ready = prepared.count.min(built);
        if ready < built {
            self.report.prepare_refused += 1;
        }
        let burst = if ready > 0 {
            // A post that unwinds may leave any chain it was offered with the device, so the link is lost until it returns.
            self.link = Link::Lost;
            // SAFETY: as above, each chain prepared.
            let burst = unsafe { self.port.tx_burst(&mut self.chains[..ready]) };
            self.link = Link::Up;
            burst
        } else {
            TxBurst {
                accepted: 0,
                uncertain: false,
            }
        };
        let accepted = burst.accepted.min(ready);
        let mut first = accepted;
        if burst.uncertain && accepted < ready {
            self.report.quarantined += 1;
            // SAFETY: the chain is one this call built, and the device's ops run only inside port calls on this thread, none of which is running.
            self.quarantine = Some(unsafe { self.record_quarantine(self.chains[accepted]) });
            first += 1;
        }
        for at in first..built {
            // SAFETY: the device did not take this chain, so its references and buffers are still ours to return once.
            unsafe { self.release(self.chains[at]) };
        }
        self.report.sent += accepted as u64;
        self.report.ring_full += (ready - first) as u64;
        if ready == 0 && built > 0 {
            return Err(DatagramError::Failed {
                code: prepared.error.or(Some(libc::EINVAL)),
            });
        }
        Ok(accepted)
    }

    /// Builds one datagram's chain, or the reason with nothing held.
    fn build(&mut self, datagram: &Outgoing<'_, 'a>) -> Result<*mut sys::rte_mbuf, Unbuilt> {
        if self.wire.peer(datagram.peer).is_none() {
            return Err(Unbuilt::Unsendable);
        }
        let mut retained = 0u16;
        let mut head_len = FRAME_OVERHEAD + datagram.header.len();
        let mut total = head_len;
        let pool = self.payload.pool();
        for piece in &datagram.payload {
            match piece {
                // The header segment carries inline bytes ahead of every descriptor, so inline bytes after a retained piece would reach the wire before it.
                Payload::Inline(bytes) if retained > 0 && !bytes.is_empty() => {
                    return Err(Unbuilt::Unsendable);
                }
                Payload::Inline(bytes) => {
                    head_len += bytes.len();
                    total += bytes.len();
                }
                Payload::Retained(source) if !source.is_of(pool) => {
                    return Err(Unbuilt::Unsendable);
                }
                // The registration translates no empty range, so an empty retained piece has no IOVA for a descriptor.
                Payload::Retained(source) if source.bytes().is_empty() => {
                    return Err(Unbuilt::Unsendable);
                }
                Payload::Retained(source) => {
                    retained += 1;
                    total += source.bytes().len();
                }
            }
        }
        if retained + 1 > self.port.max_segments()
            || head_len > self.layout.data_room
            || total > usize::from(u16::MAX)
        {
            return Err(Unbuilt::Unsendable);
        }
        let buffer = self
            .header
            .pool()
            .acquire()
            .map_err(|_| Unbuilt::Exhausted)?;
        let mut tail: *mut sys::rte_mbuf = ptr::null_mut();
        // Payload descriptors are built back to front, so each points at the one after it.
        for piece in datagram.payload.iter().rev() {
            let Payload::Retained(source) = piece else {
                continue;
            };
            match self.segment(source, tail) {
                Ok(segment) => tail = segment,
                Err(reason) => {
                    // SAFETY: the partial tail is this call's own, never given to a device.
                    unsafe { self.release(tail) };
                    return Err(reason);
                }
            }
        }
        let shape = Shape {
            head_len,
            total,
            segments: retained + 1,
        };
        self.head(buffer, datagram, shape, tail).inspect_err(|_| {
            // SAFETY: as above.
            unsafe { self.release(tail) };
        })
    }

    /// One payload descriptor over `source`, holding its device reference, chained before `next`.
    fn segment(
        &self,
        source: &SourceRange<'_, 'a>,
        next: *mut sys::rte_mbuf,
    ) -> Result<*mut sys::rte_mbuf, Unbuilt> {
        let mut taken = [MaybeUninit::uninit(); 1];
        if !self.payload.take_payload(&mut taken) {
            return Err(Unbuilt::Exhausted);
        }
        // SAFETY: a successful take wrote every slot.
        let descriptor: *mut c_void = unsafe { taken[0].assume_init() };
        let mbuf = descriptor.cast::<sys::rte_mbuf>();
        let Ok(hold) = source.hold() else {
            // SAFETY: the descriptor is out, carries no token, and no device saw it.
            unsafe { self.payload.give_back(descriptor) };
            return Err(Unbuilt::Exhausted);
        };
        let (_, index, _) = hold.identity();
        let translation = self.translations.get(index as usize).copied().flatten();
        let Some(translation) = translation else {
            drop(hold);
            // SAFETY: the descriptor is out, carries no token, and no device saw it.
            unsafe { self.payload.give_back(descriptor) };
            return Err(Unbuilt::Unsendable);
        };
        let (kind, index, incarnation) = hold.into_raw();
        let bytes = source.bytes();
        let (addr, len) = (bytes.as_ptr().addr(), bytes.len());
        // SAFETY: the descriptor is this pool's mbuf, owned by the caller until it reaches the device.
        unsafe {
            let m = &mut *mbuf;
            m.buf_addr = bytes.as_ptr().cast_mut().cast();
            m.buf_iova = (addr as u64).wrapping_add(translation);
            m.__bindgen_anon_2.__bindgen_anon_1.buf_len = len as u16;
            set_lengths(m, 0, len as u16, len as u32, 1);
            m.next = next;
            m.ol_flags = 0;
            debug_assert_eq!(
                self.registration.iova(m.buf_addr.addr(), len),
                Some(m.buf_iova),
                "a segment's IOVA is the registration's"
            );
            Token::write(mbuf, kind, index, incarnation);
        }
        Ok(mbuf)
    }

    /// The header mbuf of `datagram` in `buffer`, the first segment of a chain of `shape`, chained before `next`.
    fn head(
        &mut self,
        mut buffer: Buffer<'a>,
        datagram: &Outgoing<'_, 'a>,
        shape: Shape,
        next: *mut sys::rte_mbuf,
    ) -> Result<*mut sys::rte_mbuf, Unbuilt> {
        let Shape {
            head_len,
            total,
            segments,
        } = shape;
        let layout = self.layout;
        let bytes = buffer.bytes_mut();
        let room = &mut bytes[layout.data_offset..layout.data_offset + head_len];
        // `build` counts `FRAME_OVERHEAD` in `head_len`, so the room holds the headers.
        let Some(wire) = room.first_chunk_mut::<FRAME_OVERHEAD>() else {
            return Err(Unbuilt::Unsendable);
        };
        // `build` checked the peer, so its route exists.
        let route = self
            .routes
            .get(usize::from(datagram.peer.0))
            .ok_or(Unbuilt::Unsendable)?;
        let local = self.wire.local();
        *wire = route.headers;
        let offset = source_offset(datagram.header, local.ports);
        stamp(wire, local.port + offset, (total - FRAME_OVERHEAD) as u16);
        let mut at = FRAME_OVERHEAD + datagram.header.len();
        // A lone frame header, `HEADER_LEN` bytes long, copies as one fixed-size block; a packed or short header copies by its length.
        match (
            <&[u8; HEADER_LEN]>::try_from(datagram.header),
            room[FRAME_OVERHEAD..].first_chunk_mut::<HEADER_LEN>(),
        ) {
            (Ok(header), Some(into)) => *into = *header,
            _ => room[FRAME_OVERHEAD..at].copy_from_slice(datagram.header),
        }
        for piece in &datagram.payload {
            if let Payload::Inline(bytes) = piece
                && !bytes.is_empty()
            {
                room[at..at + bytes.len()].copy_from_slice(bytes);
                at += bytes.len();
            }
        }
        let mbuf = bytes[layout.mbuf_offset..]
            .as_mut_ptr()
            .cast::<sys::rte_mbuf>();
        // SAFETY: the buffer's mbuf, which population initialized, lies at the header layout's mbuf offset, and the handle gives exclusive access.
        unsafe {
            let m = &mut *mbuf;
            set_lengths(
                m,
                sys::RTE_PKTMBUF_HEADROOM as u16,
                head_len as u16,
                total as u32,
                segments,
            );
            m.next = next;
            m.ol_flags = sys::RTE_MBUF_F_TX_IPV4
                | sys::RTE_MBUF_F_TX_IP_CKSUM
                | sys::RTE_MBUF_F_TX_UDP_CKSUM;
            // The offload bitfields pack l2_len in 7 bits, l3_len in 9 and l4_len in 8.
            m.__bindgen_anon_3.tx_offload = ETH_LEN | IPV4_LEN << 7 | UDP_LEN << 16;
        }
        let (kind, index, incarnation) = buffer.into_device().map_err(|_| Unbuilt::Exhausted)?;
        // SAFETY: the mbuf is the caller's until it reaches the device, and its private area holds no armed token.
        unsafe { Token::write(mbuf, kind, index, incarnation) };
        self.report.sources[usize::from(offset) % 8] += 1;
        Ok(mbuf)
    }

    /// Returns a chain the device never took, segment by segment, as the device's free would.
    ///
    /// # Safety
    ///
    /// `head` is null or a chain this burst built and no device holds.
    unsafe fn release(&self, head: *mut sys::rte_mbuf) {
        let mut at = head;
        while !at.is_null() {
            // SAFETY: the caller's contract; each segment is read before its pool takes it back.
            let next = unsafe { (*at).next };
            // SAFETY: each segment of the chain is returned once.
            unsafe { self.release_segment(at) };
            at = next;
        }
    }

    /// Returns `segment` through the header pool's ops when it is a header mbuf, and through the payload pool's ops otherwise.
    ///
    /// # Safety
    ///
    /// `segment` is a segment of a chain this burst built, no device holds it, and it returns once.
    unsafe fn release_segment(&self, segment: *mut sys::rte_mbuf) {
        let state = if self.header.index_of(segment.cast()).is_some() {
            self.header
        } else {
            self.payload
        };
        // SAFETY: the caller's contract.
        unsafe { state.give_back(segment.cast()) };
    }

    /// The identity of chain `head`, saved for reconciliation after an uncertain post.
    ///
    /// # Safety
    ///
    /// `head` heads a chain this burst built, and no device or other thread writes its segments during the call.
    #[cold]
    unsafe fn record_quarantine(&self, head: *mut sys::rte_mbuf) -> Quarantined {
        let mut chain = Quarantined {
            segments: [ptr::null_mut(); 1 + MAX_PAYLOAD_SLICES],
            len: 0,
            // SAFETY: the caller's contract.
            token: unsafe { self.header.armed_token(head.cast()) },
        };
        let mut at = head;
        while !at.is_null() && chain.len < chain.segments.len() {
            chain.segments[chain.len] = at;
            chain.len += 1;
            // SAFETY: the caller's contract; `build` links at most one header and `MAX_PAYLOAD_SLICES` descriptors.
            at = unsafe { (*at).next };
        }
        debug_assert!(at.is_null(), "`build` bounds every chain's segments");
        chain
    }

    /// Stops the port and, once the stop is proven, settles the quarantined
    /// chain. The chain stays charged while the device may hold it.
    fn settle(&mut self) -> Result<(), Unproven> {
        self.port.stop()?;
        self.reconcile();
        Ok(())
    }

    /// Settles the quarantined chain, when one is recorded, after a proven stop
    /// returned every packet the device held.
    ///
    /// A header token that differs from the saved one shows the device took the
    /// chain and its return through the header pool's ops disarmed the token;
    /// this counts `quarantine_returned` and releases nothing. A header token
    /// that still equals the saved one shows the device never took the chain;
    /// the recorded segments return locally, each once, counting
    /// `quarantine_released`.
    /// A chain recorded without a token counts `quarantine_returned`. Each
    /// quarantine settles once.
    fn reconcile(&mut self) {
        let Some(chain) = self.quarantine.take() else {
            return;
        };
        let head = chain.segments[0];
        // SAFETY: the proven stop ended the device's access, and its ops ran only inside port calls that returned.
        let armed = unsafe { self.header.armed_token(head.cast()) };
        if chain.token.is_none() || armed != chain.token {
            self.report.quarantine_returned += 1;
            return;
        }
        for &segment in &chain.segments[..chain.len] {
            // SAFETY: `Port::stop` returned `Ok` only after the device returned every packet it took through the pools' ops, which disarms the header's token; the token still matches, so the chain is this burst's and each recorded segment returns once.
            unsafe { self.release_segment(segment) };
        }
        self.report.quarantine_released += 1;
    }

    fn take_received<'p>(
        &mut self,
        pool: &'p PacketPool<'a>,
        into: &mut [Option<PacketLease<'p>>],
        meta: &mut [Received],
    ) -> Result<usize, DatagramError> {
        if self.link != Link::Up {
            return Err(DatagramError::Closed);
        }
        if !std::ptr::eq(pool.served(), self.receive.pool()) {
            return Err(DatagramError::Failed {
                code: Some(libc::EINVAL),
            });
        }
        // A receive burst refills the ring with arena buffers, which the registration vouches for only while verified.
        if !self.registration.ready() {
            return Err(DatagramError::Failed {
                code: Some(libc::ESTALE),
            });
        }
        let room = into.len().min(meta.len()).min(self.rx.len());
        let got = self.port.rx_burst(&mut self.rx[..room]).min(room);
        self.report.received += got as u64;
        // Every frame's descriptor is checked first; prefetching passing frames' head lines allows cache misses to overlap across the burst. A passing frame stays posted by index until its frame check, and only an accepted frame reaches a slot.
        let mut passed = 0;
        for at in 0..got {
            let mbuf = self.rx[at];
            // SAFETY: the port returned this packet, a head the device finished writing.
            match unsafe { self.check(mbuf, pool) } {
                Ok(index) => {
                    self.rx[passed] = mbuf;
                    self.posted[passed] = index;
                    passed += 1;
                }
                Err(reason) => self.report.dropped[reason as usize] += 1,
            }
        }
        let mut count = 0;
        for at in 0..passed {
            // SAFETY: `check` gave up this posting's handle by index and nothing rebuilt it since.
            let Some(posted) = (unsafe { self.receive.pool().posting(self.posted[at]) }) else {
                unreachable!("a passing frame stays posted until its frame check")
            };
            // SAFETY: the port returned this packet, and its data length is a plain field the device wrote.
            let len =
                usize::from(unsafe { (*self.rx[at]).__bindgen_anon_2.__bindgen_anon_1.data_len });
            // SAFETY: the device finished writing the buffer, a posting of `pool`'s arena and kind, checked once per call.
            let mut lease = unsafe { pool.received(posted, len) };
            match self.wire.accept_frame(lease.bytes()) {
                Ok((peer, payload)) => {
                    lease.keep(payload);
                    into[count] = Some(lease);
                    meta[count] = Received {
                        peer: Some(peer),
                        truncated: false,
                    };
                    count += 1;
                }
                Err(reason) => self.report.dropped[reason as usize] += 1,
            }
        }
        Ok(count)
    }

    /// The descriptor check hints the frame's head and returns the buffer's posted index on success; on failure, it returns every segment this pool posted and the reason.
    ///
    /// # Safety
    ///
    /// The device finished writing `mbuf` and its chain and returned them.
    unsafe fn check(
        &self,
        mbuf: *mut sys::rte_mbuf,
        pool: &PacketPool<'a>,
    ) -> Result<u32, Refused> {
        // SAFETY: the caller's contract.
        let Some(posted) = (unsafe { self.receive.received(mbuf.cast()) }) else {
            // SAFETY: the caller's contract; segments this pool posted return, any other is counted and left.
            unsafe { self.drop_chain((*mbuf).next) };
            return Err(Refused::Foreign);
        };
        // SAFETY: the caller's contract; the fields are plain integers and pointers in the mbuf header the device returned.
        let (meta, headroom, next, room) = unsafe {
            (
                rx_meta(&*mbuf),
                (*mbuf).__bindgen_anon_1.__bindgen_anon_1.data_off,
                (*mbuf).next,
                (*mbuf).buf_addr.cast::<u8>(),
            )
        };
        let len = usize::from(meta.data_len);
        let refused = if meta.nb_segs != 1 || !next.is_null() {
            Err(Refused::Segments)
        } else if headroom != sys::RTE_PKTMBUF_HEADROOM as u16 {
            Err(Refused::Headroom)
        } else if len > pool.layout().data_room {
            Err(Refused::Length)
        } else {
            Wire::accept_descriptor(&meta, len)
        };
        if let Err(reason) = refused {
            // SAFETY: the device finished writing the head and returned it; the rest of the chain returns to its free stack.
            unsafe {
                posted.unpost();
                self.drop_chain(next);
            }
            return Err(reason);
        }
        hint_head(room.wrapping_add(usize::from(headroom)));
        Ok(posted.into_index())
    }

    /// Returns every segment of a received chain to its free stack.
    ///
    /// # Safety
    ///
    /// As for [`check`](Self::check).
    unsafe fn drop_chain(&self, head: *mut sys::rte_mbuf) {
        let mut at = head;
        while !at.is_null() {
            // SAFETY: the caller's contract.
            let next = unsafe { (*at).next };
            // SAFETY: the device returned the segment.
            unsafe { self.receive.give_back(at.cast()) };
            at = next;
        }
    }
}

impl<'a, P: Port> Datagrams<'a> for Burst<'a, P> {
    fn receive<'p>(
        &mut self,
        pool: &'p PacketPool<'a>,
        into: &mut [Option<PacketLease<'p>>],
        meta: &mut [Received],
    ) -> Result<usize, DatagramError> {
        self.take_received(pool, into, meta)
    }

    fn rx_ring(&self) -> u32 {
        self.port.rx_ring()
    }

    fn egress_exceeded(&mut self) -> Option<u64> {
        self.port.egress_exceeded()
    }

    /// While the link is up, services the device once, then runs recovery when
    /// a reset is pending or a post was uncertain. Otherwise, while the device
    /// holds a transmit segment, a header buffer or a payload descriptor, asks
    /// it to return finished transmits within one turn's budget, whose returns
    /// release their tokens through the ops.
    fn reclaim(&mut self) {
        if self.link != Link::Up {
            return;
        }
        if self.port.service() == Health::Reset || self.poisoned() {
            self.recover();
            return;
        }
        if self.header.outstanding() > 0 || self.payload.outstanding() > 0 {
            let _advisory = self.port.tx_cleanup(CLEANUP_BUDGET);
        }
    }

    fn send(&mut self, batch: &[Outgoing<'_, 'a>]) -> Result<usize, DatagramError> {
        self.transmit(batch)
    }
}

const HEAD: usize = FRAME_OVERHEAD + HEADER_LEN;

/// Prefetching the wire and frame headers allows their cache misses to overlap.
fn hint_head(data: *const u8) {
    for at in (0..HEAD).step_by(prefetch::LINE) {
        prefetch::hint_read(data.wrapping_add(at));
    }
    prefetch::hint_read(data.wrapping_add(HEAD - 1));
}

/// The receive fields validation reads.
///
/// # Safety
///
/// `m` is an mbuf the device finished writing.
unsafe fn rx_meta(m: &sys::rte_mbuf) -> RxMeta {
    // SAFETY: the caller's contract; the unions' fields are the mbuf's plain integer layout.
    unsafe {
        let lengths = &m.__bindgen_anon_2.__bindgen_anon_1;
        RxMeta {
            ol_flags: m.ol_flags,
            packet_type: lengths.__bindgen_anon_1.packet_type,
            nb_segs: m.__bindgen_anon_1.__bindgen_anon_1.nb_segs,
            pkt_len: lengths.pkt_len,
            data_len: lengths.data_len,
        }
    }
}

/// Sets a transmit segment's offset, lengths and segment count, with one reference.
///
/// # Safety
///
/// `m` is an mbuf the caller owns exclusively.
unsafe fn set_lengths(
    m: &mut sys::rte_mbuf,
    data_off: u16,
    data_len: u16,
    pkt_len: u32,
    nb_segs: u16,
) {
    // SAFETY: the caller's contract; writes plain integer union fields.
    unsafe {
        let fields = &mut m.__bindgen_anon_1.__bindgen_anon_1;
        fields.data_off = data_off;
        fields.refcnt = 1;
        fields.nb_segs = nb_segs;
        let lengths = &mut m.__bindgen_anon_2.__bindgen_anon_1;
        lengths.data_len = data_len;
        lengths.pkt_len = pkt_len;
    }
}

#[cfg(test)]
#[path = "burst_expiry_tests.rs"]
mod expiry_tests;
