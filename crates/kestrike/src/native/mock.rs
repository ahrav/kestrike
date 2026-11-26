//! A heap-backed arena with packet kinds, mock native pools served by the Rust ops, and a mock port, for the ops and burst tests.

use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::time::Duration;

use spdk_sys as sys;

use std::num::NonZeroU32;

use super::burst::{Health, Port, Prepared, Translation, TxBurst, Unproven};
use super::wire::{RxMeta, Station, Wire};
use crate::net::FRAME_OVERHEAD;

use super::mempool::{OpsState, Role, entries};
use super::recovery::{RecoveryStage, RecoveryWatch};
use super::registration::DeviceLease;
use super::watchdog::Supervisor;
use crate::storage::device::PRIVATE;
use crate::storage::test_platform::TestPlatform;
use crate::storage::{
    BufferArena, BufferConfig, EngineBudget, HugepageSize, NodeMask, PacketLayout, PoolKind,
    PoolSpec,
};

/// Buffers of each pool kind the fixture arena holds.
pub(crate) const COUNT: u32 = 8;

/// A supervisor that panics on containment, on the watchdog's thread; the interrupted recovery loses the link,
/// which the test's link assertions report.
struct NoContainment;

impl Supervisor for NoContainment {
    fn contain(&self) {
        panic!("containment requested");
    }
}

/// A recovery watch with a one-minute deadline, longer than any mock recovery runs.
pub(crate) fn watch() -> RecoveryWatch {
    RecoveryWatch::new(Duration::from_secs(60), Arc::new(NoContainment))
}

/// A leaked heap arena: read-response sources, packet receive buffers of 16 KiB and header buffers of 4 KiB.
pub(crate) fn arena() -> &'static BufferArena<TestPlatform> {
    arena_sized([COUNT; 3])
}

/// [`arena`] with `sources` read-response buffers, `receives` packet receive buffers and `headers` header buffers.
pub(crate) fn arena_sized(
    [sources, receives, headers]: [u32; 3],
) -> &'static BufferArena<TestPlatform> {
    let pools = [
        PoolSpec {
            kind: PoolKind::ReadResponse,
            count: sources,
            buffer_len: 16384,
        },
        PoolSpec {
            kind: PoolKind::PacketReceive,
            count: receives,
            buffer_len: 16384,
        },
        PoolSpec {
            kind: PoolKind::PacketHeader,
            count: headers,
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
    let arena = BufferArena::initialize(
        &config,
        TestPlatform::heap(4096),
        &mut EngineBudget::new(usize::MAX),
    )
    .unwrap();
    let arena = Box::leak(Box::new(arena));
    arena.backing().base().as_ptr().expose_provenance();
    arena
}

/// A mock native pool and its state, both leaked; `pool_data` names the state once armed.
pub(crate) struct MockPool {
    pub(super) mp: *mut sys::rte_mempool,
    pub(crate) state: &'static OpsState,
}

impl MockPool {
    /// Arms the ops once population ended, so enqueues are device returns.
    pub(super) fn arm(&self) {
        // SAFETY: the mock pool is leaked and live.
        unsafe {
            (*self.mp).__bindgen_anon_1.pool_data =
                std::ptr::from_ref(self.state).cast_mut().cast();
        }
    }
}

/// A mock pool of `role` over `arena`'s `kind`, with the mbuf fields the ops read, armed.
pub(crate) fn arena_pool(
    arena: &'static BufferArena<TestPlatform>,
    kind: PoolKind,
    role: Role,
) -> MockPool {
    let pool = unarmed_pool(arena, kind, role);
    pool.arm();
    pool
}

/// [`arena_pool`] before population ends: its ops are not armed.
pub(super) fn unarmed_pool(
    arena: &'static BufferArena<TestPlatform>,
    kind: PoolKind,
    role: Role,
) -> MockPool {
    let spec = arena.config().pool(kind);
    let layout = PacketLayout::of(spec.buffer_len as usize).unwrap();
    let base =
        arena.backing().base().as_ptr().addr() + arena.config().start(kind) + layout.mbuf_offset;
    let state: &'static OpsState = Box::leak(Box::new(OpsState::new(
        role,
        arena.pools().pool(kind),
        base,
        spec.buffer_len.trailing_zeros(),
        spec.count,
    )));
    let pool = mock(state);
    for index in 0..spec.count {
        // SAFETY: each object's mbuf lies at its buffer's mbuf offset inside the live arena.
        unsafe {
            init_mbuf(
                object(base, spec.buffer_len as usize, index),
                pool.mp,
                (layout.data_room + sys::RTE_PKTMBUF_HEADROOM as usize) as u16,
            )
        };
    }
    pool
}

/// A mock pool of `count` payload descriptors in leaked memory.
pub(crate) fn payload_pool(arena: &'static BufferArena<TestPlatform>, count: u32) -> MockPool {
    let stride = (64 + size_of::<sys::rte_mbuf>() + PRIVATE).next_power_of_two();
    let memory: &'static mut [u64] =
        Box::leak(vec![0u64; stride / 8 * count as usize + 8].into_boxed_slice());
    let base = memory.as_mut_ptr().expose_provenance().next_multiple_of(64) + 64;
    let state: &'static OpsState = Box::leak(Box::new(OpsState::new(
        Role::Payload,
        arena.pools().pool(PoolKind::ReadResponse),
        base,
        stride.trailing_zeros(),
        count,
    )));
    let pool = mock(state);
    for index in 0..count {
        // SAFETY: each descriptor lies inside the leaked memory.
        unsafe { init_mbuf(object(base, stride, index), pool.mp, 0) };
    }
    pool.arm();
    pool
}

fn mock(state: &'static OpsState) -> MockPool {
    // SAFETY: an all-zero pool structure is a valid empty value.
    let mp: Box<sys::rte_mempool> = Box::new(unsafe { std::mem::zeroed() });
    MockPool {
        mp: Box::leak(mp),
        state,
    }
}

pub(super) fn object(base: usize, stride: usize, index: u32) -> *mut sys::rte_mbuf {
    std::ptr::with_exposed_provenance_mut(base + index as usize * stride)
}

/// Writes the mbuf fields the ops read: `pool`, `buf_addr`, `priv_size`, `buf_len`, `nb_segs`, `refcnt`, and a zeroed private area.
///
/// # Safety
///
/// `mbuf` names writable memory for an mbuf and its private area.
unsafe fn init_mbuf(mbuf: *mut sys::rte_mbuf, mp: *mut sys::rte_mempool, buf_len: u16) {
    // SAFETY: the caller's contract; an all-zero mbuf is a valid start.
    unsafe {
        mbuf.write(std::mem::zeroed());
        let m = &mut *mbuf;
        m.pool = mp;
        m.buf_addr = mbuf
            .cast::<u8>()
            .wrapping_add(size_of::<sys::rte_mbuf>() + PRIVATE)
            .cast();
        m.priv_size = PRIVATE as u16;
        m.__bindgen_anon_2.__bindgen_anon_1.buf_len = buf_len;
        m.__bindgen_anon_1.__bindgen_anon_1.nb_segs = 1;
        m.__bindgen_anon_1.__bindgen_anon_1.refcnt = 1;
        mbuf.wrapping_add(1)
            .cast::<[u8; PRIVATE]>()
            .write([0; PRIVATE]);
    }
}

/// A receive or header [`PacketMempool`](super::PacketMempool) of `device` over a mock native pool of `arena`'s `kind`, serving the kind and armed.
pub(super) fn mempool(
    arena: &'static BufferArena<TestPlatform>,
    kind: PoolKind,
    device: super::registration::DeviceId,
) -> super::PacketMempool<'static> {
    let role = if kind == PoolKind::PacketReceive {
        Role::Receive
    } else {
        Role::Header
    };
    assert!(arena.pools().pool(kind).claim_served());
    let pool = arena_pool(arena, kind, role);
    super::PacketMempool::mocked(pool.mp, pool.state, device)
}

/// Returns `head`'s chain to its pools as the device's free does: each segment's enqueue through its own pool's ops.
///
/// # Safety
///
/// The chain is one the device holds and returns once.
pub(super) unsafe fn device_free(head: *mut sys::rte_mbuf) {
    let mut at = head;
    while !at.is_null() {
        // SAFETY: the caller's contract.
        let (next, mp) = unsafe { ((*at).next, (*at).pool) };
        let obj: *mut c_void = at.cast();
        // SAFETY: `mp` is an armed mock pool of the Rust ops, so `pool_data` names its live state, and the segment is returned once through the enqueue its role registers.
        let rc = unsafe {
            let state = &*(*mp).__bindgen_anon_1.pool_data.cast::<OpsState>();
            (entries(state.role()).0)(mp, &obj, 1)
        };
        assert_eq!(rc, 0);
        at = next;
    }
}

/// A scripted registration translation: `iova` delegates to `.0`, `recheck` to `.1`, `offsets` applies `.0` to each whole buffer, and `ready` always holds.
pub(crate) struct Forged<T, R>(pub(crate) T, pub(crate) R);

impl<T: Fn(usize, usize) -> Option<u64>, R: Fn() -> bool> Translation for Forged<T, R> {
    fn iova(&self, addr: usize, len: usize) -> Option<u64> {
        (self.0)(addr, len)
    }

    fn offsets(&self, span: usize, len: usize, count: usize) -> Box<[Option<u64>]> {
        (0..count)
            .map(|index| {
                let addr = span + index * len;
                self.iova(addr, len)
                    .map(|iova| iova.wrapping_sub(addr as u64))
            })
            .collect()
    }

    fn recheck(&self) -> bool {
        (self.1)()
    }

    fn ready(&self) -> bool {
        true
    }
}

/// The forged translation of one address range: the address with bit 40 flipped, and none for a range crossing a 2 MiB page.
pub(crate) fn iova(addr: usize, len: usize) -> Option<u64> {
    let page = 2 << 20;
    (len > 0 && addr / page == (addr + len - 1) / page).then_some((addr as u64) ^ (1 << 40))
}

/// The bytes of one mbuf segment the port holds, which the burst logic wrote.
pub(super) fn segment_bytes(mbuf: *mut sys::rte_mbuf) -> Vec<u8> {
    // SAFETY: a segment this test's port holds; the burst logic wrote its buffer and lengths.
    unsafe {
        let m = &*mbuf;
        let len = usize::from(m.__bindgen_anon_2.__bindgen_anon_1.data_len);
        let off = usize::from(m.__bindgen_anon_1.__bindgen_anon_1.data_off);
        std::slice::from_raw_parts(m.buf_addr.cast::<u8>().add(off), len).to_vec()
    }
}

/// The bytes of a whole chain the port holds, every segment in order.
pub(crate) fn chain_bytes(head: *mut sys::rte_mbuf) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = head;
    while !at.is_null() {
        out.extend(segment_bytes(at));
        // SAFETY: a chain segment the port holds; `next` is the link the burst logic wrote.
        at = unsafe { (*at).next };
    }
    out
}

/// Takes a receive buffer through the ops `receive`, whose buffers have `layout`, as the device's refill does, and writes `frame` into it with the descriptor fields `meta` at `headroom`, with no next segment. `frame` fits the buffer's data room past `headroom`.
pub(crate) fn arrive_on(
    receive: &OpsState,
    layout: PacketLayout,
    frame: &[u8],
    meta: RxMeta,
    headroom: u16,
) -> *mut sys::rte_mbuf {
    let mut slot = [MaybeUninit::uninit(); 1];
    assert!(receive.take(&mut slot));
    // SAFETY: a successful take wrote the slot.
    let mbuf: *mut sys::rte_mbuf = unsafe { slot[0].assume_init() }.cast();
    let room = mbuf
        .cast::<u8>()
        .wrapping_sub(layout.mbuf_offset)
        .wrapping_add(layout.data_offset);
    // SAFETY: the posted buffer is the device's, and this models the device's write into it.
    unsafe {
        std::ptr::copy_nonoverlapping(frame.as_ptr(), room, frame.len());
        let m = &mut *mbuf;
        m.ol_flags = meta.ol_flags;
        m.__bindgen_anon_2
            .__bindgen_anon_1
            .__bindgen_anon_1
            .packet_type = meta.packet_type;
        m.__bindgen_anon_2.__bindgen_anon_1.pkt_len = meta.pkt_len;
        m.__bindgen_anon_2.__bindgen_anon_1.data_len = meta.data_len;
        m.__bindgen_anon_1.__bindgen_anon_1.nb_segs = meta.nb_segs;
        m.__bindgen_anon_1.__bindgen_anon_1.data_off = headroom;
        m.next = std::ptr::null_mut();
    }
    mbuf
}

/// A valid inbound frame from `peer` to `local` carrying `payload`, and the descriptor fields a device reports for it.
pub(crate) fn inbound(local: &Station, peer: &Station, payload: &[u8]) -> (Vec<u8>, RxMeta) {
    let wire = Wire::new(
        *peer,
        std::slice::from_ref(local),
        &mut EngineBudget::unlimited(),
    )
    .unwrap();
    let mut headers = [0; FRAME_OVERHEAD];
    wire.encode(
        &mut headers,
        local,
        peer.port,
        local.port,
        payload.len() as u16,
    );
    let frame = [headers.as_slice(), payload].concat();
    let ol = u64::from(sys::RTE_MBUF_F_RX_IP_CKSUM_GOOD | sys::RTE_MBUF_F_RX_L4_CKSUM_GOOD);
    let meta = RxMeta {
        ol_flags: ol,
        packet_type: sys::RTE_PTYPE_L3_IPV4 | sys::RTE_PTYPE_L4_UDP,
        nb_segs: 1,
        pkt_len: frame.len() as u32,
        data_len: frame.len() as u16,
    };
    (frame, meta)
}

/// A test's observer of each prepare's entry, given the slice the prepare received.
pub(crate) type Probe = Box<dyn FnMut(&[*mut sys::rte_mbuf])>;

/// A fixed log of 128 accepted chains with its count, so logging allocates nothing on a measured path; a test that accepts more drains the log between bursts.
pub(crate) struct Accepted {
    chains: [*mut sys::rte_mbuf; 128],
    len: usize,
}

impl Default for Accepted {
    fn default() -> Self {
        Self {
            chains: [std::ptr::null_mut(); 128],
            len: 0,
        }
    }
}

impl Accepted {
    /// The chains logged since a test last drained the log, in acceptance order.
    pub(crate) fn logged(&self) -> &[*mut sys::rte_mbuf] {
        &self.chains[..self.len]
    }
}

/// Separates immutable witness identity from the mutable mbuf token.
#[derive(Clone, Debug)]
pub(crate) struct ChainSegment {
    pub(crate) mbuf: *mut sys::rte_mbuf,
    pub(crate) reference: Option<(u16, u32, u64)>,
}

/// A port whose limits a test sets, holding every chain it accepts until the test frees it.
#[derive(Default)]
pub(crate) struct MockPort {
    /// Packets one prepare passes at most, and the error number it reports for the first it refuses.
    pub(crate) prepare: usize,
    pub(crate) prepare_error: i32,
    /// Packets one burst takes at most.
    pub(crate) accept: usize,
    /// The next burst reports its first refused packet uncertain when it stops short, and clears the flag either way.
    pub(crate) uncertain: bool,
    /// Whether an uncertain burst keeps the packet it reports uncertain; [`open`](Self::open) sets it, and `Default` leaves it clear.
    pub(crate) retain_uncertain: bool,
    /// Whether an uncertain burst's device returns the packet it reports uncertain through the pools' ops before the burst returns, as a driver that freed a failed post's chain does; it then keeps nothing of it.
    pub(crate) free_uncertain: bool,
    /// A planted defect for one burst: the device takes a prefix other than the one prepare saw, while each chain
    /// stays in the slice exactly once.
    pub(crate) swap_accepted: Option<(usize, usize)>,
    pub(crate) segments: u16,
    pub(crate) ring: u32,
    pub(crate) held: Vec<*mut sys::rte_mbuf>,
    /// Chains accepted since a test last drained this log, in acceptance order; a kept uncertain chain is held and not accepted.
    pub(crate) accepted: Accepted,
    /// Packets the next receive returns.
    pub(crate) arriving: Vec<*mut sys::rte_mbuf>,
    /// What the next cleanup reports, and how many held chains it frees first.
    pub(crate) cleanup: (i32, usize),
    /// Cleanups asked for.
    pub(crate) cleanups: u32,
    /// Single segments the device returns one per cleanup, in order, before the cleanup frees any held chain; [`return_apart`](Self::return_apart) fills it.
    pub(crate) segment_returns: Vec<*mut sys::rte_mbuf>,
    /// Prepare and burst calls, and the slice length the latest of each received.
    pub(crate) prepares: u32,
    pub(crate) bursts: u32,
    pub(crate) prepared_len: usize,
    pub(crate) burst_len: usize,
    /// Runs at each prepare's entry with the slice the prepare received, before it acts.
    pub(crate) probe: Option<Probe>,
    /// Whether service reports a pending reset.
    pub(crate) reset: bool,
    /// Stops proven before every later stop is unproven.
    pub(crate) proven_stops: u32,
    /// What a function reset fails with, once the port recorded the stage and ran any stall planted in it.
    pub(crate) reset_error: Option<i32>,
    /// What a re-initialization fails with, once the port recorded the stage and ran any stall planted in it.
    pub(crate) reinitialize_error: Option<i32>,
    /// What a start fails with.
    pub(crate) restart_error: Option<i32>,
    /// Selects receive acquisition count for a scripted failure. Zero skips dequeue.
    /// Positive counts require `restart_error` and must fit the usable `ring - 1` slots.
    pub(crate) restart_acquire: usize,
    /// Keeps acquisition witnesses across the stop that drains `posted`.
    pub(crate) acquired: Vec<*mut sys::rte_mbuf>,
    /// Reads pool state at restart entry before the refill changes receive custody.
    pub(crate) before_restart: Option<Box<dyn FnMut()>>,
    /// Samples a successful receive-pool acquisition and the scripted zero-acquisition error.
    /// A refused dequeue returns EFAULT before this observer runs.
    pub(crate) after_acquire: Option<Box<dyn FnMut()>>,
    /// Allocation-backed chain snapshots require fixture opt-in.
    pub(crate) record_build: bool,
    /// Snapshots header and payload references at prepare entry while the sending burst owns every built chain.
    pub(crate) built: Vec<Vec<ChainSegment>>,
    /// Stops and starts called.
    pub(crate) stops: u32,
    pub(crate) restarts: u32,
    /// Each stop, reset, re-initialization and start call the port ran, as its recovery stage, in order.
    pub(crate) stages: Vec<RecoveryStage>,
    /// Supplies `ring - 1` buffers for successful restart and `restart_acquire` for an error script.
    pub(crate) receive: Option<&'static OpsState>,
    pub(crate) posted: Vec<*mut sys::rte_mbuf>,
    /// The lease the port reports.
    pub(crate) lease: Option<DeviceLease>,
    /// Receive, prepare, burst, cleanup, service, stop, reset, re-initialization and start calls.
    pub(crate) calls: u32,
    /// Runs inside each call of the named recovery stage before the call acts, as a stalled native call would hold
    /// the thread there, until it returns `true` after the call it stalled.
    pub(crate) stall: Option<(RecoveryStage, Box<dyn FnMut() -> bool>)>,
    /// The next burst unwinds after the device took and kept its packets, as a post that panics past its ownership point.
    pub(crate) unwind_after_post: bool,
}

impl MockPort {
    pub(crate) fn open() -> Self {
        Self {
            prepare: usize::MAX,
            prepare_error: libc::EINVAL,
            accept: usize::MAX,
            segments: 3,
            ring: 8,
            proven_stops: u32::MAX,
            retain_uncertain: true,
            ..Self::default()
        }
    }

    /// Records `stage` and runs the stall a test planted in it, which stays planted until it reports a stall.
    fn stall_in(&mut self, stage: RecoveryStage) {
        self.stages.push(stage);
        if let Some((at, stall)) = &mut self.stall
            && *at == stage
            && stall()
        {
            self.stall = None;
        }
    }

    /// Takes the chains accepted since the last take, in acceptance order.
    pub(crate) fn take_accepted(&mut self) -> Vec<*mut sys::rte_mbuf> {
        let taken = self.accepted.chains[..self.accepted.len].to_vec();
        self.accepted.len = 0;
        taken
    }

    /// Moves held chain `at` out of the held set and queues its segments, header first, for the device to return one per cleanup, so its segments return apart and after any chain queued before it.
    pub(crate) fn return_apart(&mut self, at: usize) {
        let mut segment = self.held.remove(at);
        while !segment.is_null() {
            self.segment_returns.push(segment);
            // SAFETY: the port holds the chain, and its segments' links are the ones the burst logic wrote; each is read before any segment returns.
            segment = unsafe { (*segment).next };
        }
    }

    /// Frees every held chain as the device would after transmit, and returns every queued segment.
    pub(crate) fn complete(&mut self) {
        for head in self.held.drain(..) {
            // SAFETY: the port holds the chain and returns it once.
            unsafe { device_free(head) };
        }
        while !self.segment_returns.is_empty() {
            self.return_segment();
        }
    }

    /// Returns the first queued segment through its own pool's ops.
    fn return_segment(&mut self) {
        let segment = self.segment_returns.remove(0);
        let obj: *mut c_void = segment.cast();
        // SAFETY: `return_apart` queued a segment of a chain the device took, which it returns once through its own pool's ops.
        let rc = unsafe {
            let mp = (*segment).pool;
            let state = &*(*mp).__bindgen_anon_1.pool_data.cast::<OpsState>();
            (entries(state.role()).0)(mp, &obj, 1)
        };
        assert_eq!(rc, 0);
    }
}

// SAFETY: a proven stop frees every held chain; the mock returns only mbufs a test took through the receive ops and wrote as a device would, leaves every slice as it was but for the exchange `swap_accepted` plants, which keeps each chain in the slice once so the burst logic still releases or keeps each built chain once, reports exactly the packets it takes, keeps an uncertain packet only when it reports it uncertain and `retain_uncertain` is set, returns an uncertain packet inside the burst only when it took it and `free_uncertain` is set, and frees each kept chain or queued segment once through its pools' ops. Its lease is the one a test leased for the device the mock stands in for.
unsafe impl Port for MockPort {
    fn device_lease(&self) -> Option<&DeviceLease> {
        self.lease.as_ref()
    }

    fn rx_burst(&mut self, out: &mut [*mut sys::rte_mbuf]) -> usize {
        self.calls += 1;
        let n = out.len().min(self.arriving.len());
        for (slot, mbuf) in out.iter_mut().zip(self.arriving.drain(..n)) {
            *slot = mbuf;
        }
        n
    }

    unsafe fn tx_prepare(&mut self, packets: &mut [*mut sys::rte_mbuf]) -> Prepared {
        self.calls += 1;
        self.prepares += 1;
        self.prepared_len = packets.len();
        if let Some(probe) = &mut self.probe {
            probe(packets);
        }
        if self.record_build {
            for &head in packets.iter() {
                let mut segments = Vec::new();
                let mut at = head;
                while !at.is_null() {
                    // SAFETY: fixture chains use armed, leaked mock pools whose pool_data names a live OpsState; each segment belongs to that carving and this owner-thread call excludes concurrent private-area and next writes.
                    let (reference, next) = unsafe {
                        let state = &*(*(*at).pool).__bindgen_anon_1.pool_data.cast::<OpsState>();
                        (state.reference(at.cast()), (*at).next)
                    };
                    segments.push(ChainSegment {
                        mbuf: at,
                        reference,
                    });
                    at = next;
                }
                self.built.push(segments);
            }
        }
        let count = packets.len().min(self.prepare);
        Prepared {
            count,
            error: (count < packets.len()).then_some(self.prepare_error),
        }
    }

    unsafe fn tx_burst(&mut self, packets: &mut [*mut sys::rte_mbuf]) -> TxBurst {
        self.calls += 1;
        self.bursts += 1;
        self.burst_len = packets.len();
        if let Some((a, b)) = self.swap_accepted.take() {
            packets.swap(a, b);
        }
        let accepted = packets.len().min(self.accept);
        self.held.extend_from_slice(&packets[..accepted]);
        for &packet in &packets[..accepted] {
            let log = &mut self.accepted;
            assert!(
                log.len < log.chains.len(),
                "drain the acceptance log between bursts"
            );
            log.chains[log.len] = packet;
            log.len += 1;
        }
        let uncertain = std::mem::take(&mut self.uncertain) && accepted < packets.len();
        if uncertain && self.free_uncertain {
            // SAFETY: the device took the uncertain packet and returns it once, inside this call.
            unsafe { device_free(packets[accepted]) };
        } else if uncertain && self.retain_uncertain {
            // The device kept the refused packet, as a native post that failed past its ownership point does.
            self.held.push(packets[accepted]);
        }
        if std::mem::take(&mut self.unwind_after_post) {
            panic!("tx_burst unwound after the post");
        }
        TxBurst {
            accepted,
            uncertain,
        }
    }

    fn tx_cleanup(&mut self, _budget: NonZeroU32) -> i32 {
        self.calls += 1;
        self.cleanups += 1;
        if !self.segment_returns.is_empty() {
            self.return_segment();
        }
        let (report, frees) = self.cleanup;
        for _ in 0..frees.min(self.held.len()) {
            let head = self.held.remove(0);
            // SAFETY: as in `complete`.
            unsafe { device_free(head) };
        }
        report
    }

    fn max_segments(&self) -> u16 {
        self.segments
    }

    fn rx_ring(&self) -> u32 {
        self.ring
    }

    fn service(&mut self) -> Health {
        self.calls += 1;
        if std::mem::take(&mut self.reset) {
            Health::Reset
        } else {
            Health::Running
        }
    }

    fn stop(&mut self) -> Result<(), Unproven> {
        self.calls += 1;
        self.stall_in(RecoveryStage::Stop);
        self.stops += 1;
        if self.stops > self.proven_stops {
            return Err(Unproven);
        }
        self.complete();
        for mbuf in self.posted.drain(..) {
            // SAFETY: the mock device holds the posted buffer and returns it once.
            unsafe { device_free(mbuf) };
        }
        Ok(())
    }

    fn reset(&mut self) -> Result<(), i32> {
        self.calls += 1;
        self.stall_in(RecoveryStage::Reset);
        self.reset_error.map_or(Ok(()), Err)
    }

    fn reinitialize(&mut self) -> Result<(), i32> {
        self.calls += 1;
        self.stall_in(RecoveryStage::Reinitialize);
        self.reinitialize_error.map_or(Ok(()), Err)
    }

    fn start(&mut self) -> Result<(), i32> {
        self.calls += 1;
        self.stall_in(RecoveryStage::Restart);
        self.restarts += 1;
        assert!(self.restart_error.is_some() || self.restart_acquire == 0);
        if let Some(observer) = self.before_restart.as_mut() {
            observer();
        }
        if let Some(code) = self.restart_error
            && self.restart_acquire == 0
        {
            if let Some(observer) = self.after_acquire.as_mut() {
                observer();
            }
            return Err(code);
        }
        let Some(receive) = self.receive else {
            assert_eq!(self.restart_acquire, 0);
            return Ok(());
        };
        let count = if self.restart_error.is_some() {
            assert!(self.restart_acquire < self.ring as usize);
            self.restart_acquire
        } else {
            self.ring as usize - 1
        };
        let mut slots = vec![MaybeUninit::uninit(); count];
        if !receive.take(&mut slots) {
            // The driver's start fails a short refill with its fault code.
            return Err(libc::EFAULT);
        }
        // SAFETY: a successful take wrote every slot.
        self.posted = slots
            .into_iter()
            .map(|slot| unsafe { slot.assume_init() }.cast())
            .collect();
        self.acquired.extend_from_slice(&self.posted);
        if let Some(observer) = self.after_acquire.as_mut() {
            observer();
        }
        self.restart_error.map_or(Ok(()), Err)
    }
}
