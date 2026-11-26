//! DPDK packet mempools served from the arena through Rust mempool ops.
//!
//! Three ops register by name before environment init: one for receive
//! pools, one for transmit header pools and one for transmit payload
//! descriptors. A pool starts with zero objects and a per-core cache of
//! zero, which sends every get and put to these ops; its single-producer
//! and single-consumer flags declare the owner-thread contract its callers
//! keep. Each role registers its own enqueue and dequeue, so each entry
//! serves one role. The ops resolve their state through the pool's
//! `pool_data`, which names the state only while the pool is armed.
//!
//! Invariants owned by this module:
//!
//! - The ops never allocate, block or unwind. Population enqueues every
//!   object once before the pool is armed, while `pool_data` is null, so
//!   those enqueues touch no state and the arena's free stack keeps every
//!   buffer. After arming, an enqueue is a device's return.
//! - One mempool serves an arena kind, built while every buffer of the kind
//!   is free, and a view keeps arena-level acquire and post off the kind for
//!   the pool's life: the receive pool borrows the endpoint's receive view,
//!   and the header pool holds the header kind's view itself. So no handle
//!   reaches an object's header, mbuf or token while the pool serves it.
//! - A receive dequeue posts exactly the requested count from the arena's
//!   free stack by index, or fails with the arena unchanged; a receive
//!   enqueue ends the posting of a buffer this pool's dequeue gave the device
//!   and the device never wrote into a lease. The arena marks each posting by
//!   index, and only the pool serving the kind posts by index, so a posting
//!   made any other way is stray.
//! - Each transmit mbuf's private area holds at most one armed
//!   device-reference token: one raw reference to the buffer incarnation
//!   it names. Enqueuing the transmit mbuf
//!   disarms the token and returns the reference once. A header's token
//!   holds its own buffer's reference; a header mbuf with a disarmed token,
//!   a token naming another buffer or a stale incarnation, or an object
//!   outside the pool, is counted as stray and changes no custody.
//! - A payload descriptor is out from its dequeue to its enqueue, and every
//!   enqueue of an out descriptor puts it back on the descriptor stack,
//!   returning its token's reference when one is armed and names a
//!   read-response buffer.
//! - Every object lies where the pool's carving puts it, and an arena
//!   object carries the IOVA the shared registration assigns its page;
//!   construction checks every object and the object count before arming.
//! - Each pool serves the one device whose lease built it, and a built pool
//!   is freed only through that device's stop proof once the device holds
//!   none of its objects; another device's proof, or one offered while the
//!   device holds an object, comes back with the pool unchanged. Construction
//!   frees a pool that failed before any device saw it. Its ops are disarmed
//!   first, so the native free's drain of its object list leaves the arena
//!   unchanged. A pool dropped without the proof is disarmed and its state
//!   detached from the native pool, which stays allocated for the life of
//!   the process.
//! - Each constructor charges its pool's retained heap state, the boxed ops
//!   state and, for a payload pool, its descriptor stack, out flags and
//!   descriptor memory, to a copy of the engine budget after its shape
//!   checks, and an arena pool's registration and device checks, and before
//!   it claims the kind, allocates or creates the native pool; it commits
//!   the copy only when it returns the pool. A failure after the charge
//!   frees what the constructor allocated, and every refusal or failure
//!   leaves the budget unchanged. DPDK allocates the native pool structure
//!   outside the budget.

use std::alloc::Layout;
use std::cell::Cell;
use std::ffi::{CStr, c_int, c_uint, c_void};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ptr::{self, NonNull};

use spdk_sys as sys;

use super::registration::{ArenaRegistration, DeviceId, DeviceLease, DeviceStopped};
use crate::net::PacketPool;
use crate::storage::device::{PRIVATE, Pool, object_overhead};
use crate::storage::{
    BufferArena, EngineBudget, EngineBudgetExceeded, PacketLayout, Platform, PoolKind,
};

/// The ops names each pool resolves at creation.
pub(crate) const RECEIVE_OPS: &CStr = c"kestrike-rx";
pub(crate) const HEADER_OPS: &CStr = c"kestrike-tx-header";
pub(crate) const PAYLOAD_OPS: &CStr = c"kestrike-tx-payload";

/// The mempool flags every packet pool uses.
const FLAGS: u32 =
    crate::storage::device::MEMPOOL_FLAGS | sys::RTE_MEMPOOL_F_SP_PUT | sys::RTE_MEMPOOL_F_SC_GET;

/// Registers the three ops; the environment runs this before its init.
pub(crate) fn register() -> Result<(), i32> {
    for (name, role) in [
        (RECEIVE_OPS, Role::Receive),
        (HEADER_OPS, Role::Header),
        (PAYLOAD_OPS, Role::Payload),
    ] {
        let (enqueue, dequeue) = entries(role);
        let mut table = sys::rte_mempool_ops {
            name: [0; 32],
            alloc: Some(ops_alloc),
            free: Some(ops_free),
            enqueue: Some(enqueue),
            dequeue: Some(dequeue),
            get_count: Some(ops_count),
            calc_mem_size: None,
            populate: None,
            get_info: None,
            dequeue_contig_blocks: None,
        };
        for (slot, byte) in table.name.iter_mut().zip(name.to_bytes_with_nul()) {
            *slot = *byte as std::ffi::c_char;
        }
        // SAFETY: `table` is a complete ops table whose name fits; DPDK copies it.
        let rc = unsafe { sys::rte_mempool_register_ops(&table) };
        if rc < 0 {
            return Err(-rc);
        }
    }
    Ok(())
}

/// An op's enqueue entry, as DPDK calls it.
pub(super) type Enqueue =
    unsafe extern "C" fn(*mut sys::rte_mempool, *const *mut c_void, c_uint) -> c_int;
/// An op's dequeue entry, as DPDK calls it.
pub(super) type Dequeue =
    unsafe extern "C" fn(*mut sys::rte_mempool, *mut *mut c_void, c_uint) -> c_int;

/// The enqueue and dequeue the ops of `role` register.
pub(super) fn entries(role: Role) -> (Enqueue, Dequeue) {
    match role {
        Role::Receive => (enqueue_receive, dequeue_receive),
        Role::Header => (enqueue_header, dequeue_header),
        Role::Payload => (enqueue_payload, dequeue_payload),
    }
}

/// Which objects a pool's ops serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Receive,
    Header,
    Payload,
}

/// One device reference held in an mbuf's private area: the buffer's whole
/// 64-bit incarnation, its index, and its kind's [`PoolKind::index`].
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Token {
    incarnation: u64,
    index: u32,
    kind: u16,
    armed: u16,
}

const _: () = assert!(size_of::<Token>() == PRIVATE);

impl Token {
    /// Writes an armed token naming buffer `index` of `kind`'s `incarnation` into `mbuf`'s private area.
    ///
    /// # Safety
    ///
    /// `mbuf` names an mbuf whose private area the caller owns.
    pub(crate) unsafe fn write(
        mbuf: *mut sys::rte_mbuf,
        kind: PoolKind,
        index: u32,
        incarnation: u64,
    ) {
        let token = Self {
            incarnation,
            index,
            kind: kind.index() as u16,
            armed: 1,
        };
        // SAFETY: the caller's contract; the private area follows the mbuf.
        unsafe { private(mbuf).write(token) };
    }
}

#[cfg(test)]
impl Token {
    /// Detaches `hold` into an armed token in `mbuf`'s private area.
    ///
    /// # Safety
    ///
    /// `mbuf` is a transmit mbuf the caller owns, whose private area holds no armed token.
    pub(crate) unsafe fn arm(mbuf: *mut sys::rte_mbuf, hold: crate::storage::NicHold<'_>) {
        let (kind, index, incarnation) = hold.into_raw();
        // SAFETY: the caller's contract.
        unsafe { Self::write(mbuf, kind, index, incarnation) };
    }

    /// The token in `mbuf`'s private area: its kind's [`PoolKind::index`], buffer index, incarnation, and whether it is armed.
    ///
    /// # Safety
    ///
    /// `mbuf` names a transmit mbuf no device or other thread writes during the call.
    pub(crate) unsafe fn read(mbuf: *mut sys::rte_mbuf) -> (u16, u32, u64, bool) {
        // SAFETY: the caller's contract; the private area follows the mbuf.
        let token = unsafe { private(mbuf).read() };
        (token.kind, token.index, token.incarnation, token.armed == 1)
    }
}

/// Counters of what a pool's ops did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpsReport {
    /// Device returns that ended a posting, released a reference or put back a descriptor.
    pub returned: u64,
    /// Enqueued objects outside the pool, receive buffers this pool did not post, payload descriptors not out, or header mbufs with no armed token for their own buffer's live incarnation; none changed custody.
    pub stray: u64,
    /// Dequeues refused: short of the requested count, or of a pool that serves none.
    pub refused: u64,
}

/// Where a pool's objects lie: `count` objects `1 << shift` bytes apart from the mbuf at `base`.
#[derive(Debug, Clone, Copy)]
struct Carving {
    base: usize,
    shift: u32,
    count: u32,
}

impl Carving {
    fn index_of(self, obj: *mut c_void) -> Option<u32> {
        let offset = obj.addr().checked_sub(self.base)?;
        let index = offset >> self.shift;
        (offset & ((1 << self.shift) - 1) == 0 && index < self.count as usize)
            .then_some(index as u32)
    }

    fn object(self, index: u32) -> *mut c_void {
        ptr::with_exposed_provenance_mut(self.base + ((index as usize) << self.shift))
    }
}

/// `Tracking` gives a payload state's loops access to its `out` flags and descriptor stack, one entry per carving object.
#[derive(Clone, Copy)]
struct Tracking {
    out: *const Cell<bool>,
    stack: *const Cell<u32>,
    count: u32,
}

impl Tracking {
    /// Whether descriptor `index` is out; `index` is below `count`, as every index from [`Carving::index_of`] and the descriptor stack is.
    #[inline(always)]
    fn out(self, index: u32) -> &'static Cell<bool> {
        debug_assert!(index < self.count);
        // SAFETY: a payload state's `out` holds `count` flags, the state outlives the call, and `index` is below `count`.
        unsafe { &*self.out.add(index as usize) }
    }

    /// Descriptor stack slot `at`, below `count`: the stack holds one slot per descriptor, and the top never exceeds `count` because every descriptor is either on the stack or out.
    #[inline(always)]
    fn slot(self, at: u32) -> &'static Cell<u32> {
        debug_assert!(at < self.count);
        // SAFETY: a payload state's `stack` holds `count` slots, the state outlives the call, and `at` is below `count`.
        unsafe { &*self.stack.add(at as usize) }
    }
}

/// What one pool's ops act on; lives at a fixed address, which the pool's `pool_data` names while the pool is armed.
pub(crate) struct OpsState {
    role: Role,
    /// The arena pool whose buffers the objects are, or, for payload descriptors, whose buffers their tokens reference.
    pool: NonNull<Pool>,
    carving: Carving,
    /// The payload descriptor stack: free indices at `0..top`.
    stack: Box<[Cell<u32>]>,
    top: Cell<u32>,
    /// Which payload descriptors are out, from this pool's dequeue to its enqueue; empty for an arena pool.
    out: Box<[Cell<bool>]>,
    returned: Cell<u64>,
    stray: Cell<u64>,
    refused: Cell<u64>,
    #[cfg(test)]
    returns: std::cell::RefCell<Option<Vec<usize>>>,
}

impl OpsState {
    /// The state of a pool of `count` objects `1 << shift` bytes apart from the mbuf at `base`.
    pub(crate) fn new(role: Role, pool: &Pool, base: usize, shift: u32, count: u32) -> Self {
        let descriptors = if role == Role::Payload { count } else { 0 };
        let tracked = if role == Role::Payload { count } else { 0 };
        Self {
            role,
            pool: NonNull::from(pool),
            carving: Carving { base, shift, count },
            stack: (0..descriptors).map(Cell::new).collect(),
            top: Cell::new(descriptors),
            out: (0..tracked).map(|_| Cell::new(false)).collect(),
            returned: Cell::new(0),
            stray: Cell::new(0),
            refused: Cell::new(0),
            #[cfg(test)]
            returns: std::cell::RefCell::new(None),
        }
    }

    pub(crate) fn pool(&self) -> &Pool {
        // SAFETY: the arena outlives the state while the pool serves; a dropped pool's state is detached from the native pool first.
        unsafe { self.pool.as_ref() }
    }

    /// Which objects the pool's ops serve.
    pub(crate) fn role(&self) -> Role {
        self.role
    }

    pub(crate) fn served(&self) -> (PoolKind, usize) {
        (self.pool().kind(), self.stride())
    }

    pub(crate) fn report(&self) -> OpsReport {
        OpsReport {
            returned: self.returned.get(),
            stray: self.stray.get(),
            refused: self.refused.get(),
        }
    }

    /// Bytes from one object to the next.
    pub(crate) fn stride(&self) -> usize {
        1 << self.carving.shift
    }

    /// Payload descriptors on the stack, free for a take.
    #[cfg(test)]
    pub(crate) fn free_descriptors(&self) -> u32 {
        self.top.get()
    }

    /// Objects in the pool's carving.
    pub(crate) fn count(&self) -> u32 {
        self.carving.count
    }

    /// The index of the object whose mbuf is at `obj`, when it is one of this pool's.
    pub(crate) fn index_of(&self, obj: *mut c_void) -> Option<u32> {
        self.carving.index_of(obj)
    }

    /// `armed_token` returns the token from header mbuf `obj`'s private area when the token is armed and identifies `obj`'s own buffer.
    ///
    /// # Safety
    ///
    /// No device or other thread writes `obj`'s private area during the call.
    pub(crate) unsafe fn armed_token(&self, obj: *mut c_void) -> Option<Token> {
        debug_assert_eq!(self.role, Role::Header);
        let index = self.index_of(obj)?;
        // SAFETY: `obj` is this pool's mbuf, whose private area holds its token; the caller's contract excludes concurrent writes.
        let held = unsafe { private(obj.cast()).read() };
        let own = held.armed == 1
            && held.kind == self.pool().kind().index() as u16
            && held.index == index;
        own.then_some(held)
    }

    #[cfg(test)]
    pub(crate) fn record_returns(&self) {
        *self.returns.borrow_mut() = Some(Vec::new());
    }

    /// Counts enqueue attempts for one object, including stray returns.
    ///
    /// # Panics
    ///
    /// Panics when `record_returns` has yet to arm the log.
    #[cfg(test)]
    pub(crate) fn returns(&self, obj: *mut c_void) -> usize {
        self.returns
            .borrow()
            .as_ref()
            .unwrap()
            .iter()
            .filter(|&&at| at == obj.addr())
            .count()
    }

    #[cfg(test)]
    fn observe_returns(&self, objs: &[*mut c_void]) {
        if let Some(log) = self.returns.borrow_mut().as_mut() {
            log.extend(objs.iter().map(|obj| obj.addr()));
        }
    }

    /// Returns the armed token's kind, index and incarnation, or `None` for a disarmed token.
    /// Header tokens name their own buffer; payload tokens name their source.
    ///
    /// # Safety
    ///
    /// The caller must exclude device and other-thread writes to `obj`'s private area during the read.
    ///
    /// # Panics
    ///
    /// Panics when `obj` lies outside this pool's carving.
    #[cfg(test)]
    pub(crate) unsafe fn reference(&self, obj: *mut c_void) -> Option<(u16, u32, u64)> {
        assert!(self.index_of(obj).is_some());
        // SAFETY: carving membership places the private Token inside the live pool; the caller excludes concurrent writes.
        let token = unsafe { private(obj.cast()).read() };
        (token.armed == 1).then_some((token.kind, token.index, token.incarnation))
    }

    /// Reads the payload descriptor's dequeue-to-enqueue custody flag.
    ///
    /// # Panics
    ///
    /// Panics for a role other than `Payload` or an object outside this pool's carving.
    #[cfg(test)]
    pub(crate) fn descriptor_out(&self, obj: *mut c_void) -> bool {
        assert_eq!(self.role, Role::Payload);
        self.out[self.index_of(obj).unwrap() as usize].get()
    }

    #[cfg(test)]
    pub(crate) fn descriptor_stack(&self) -> Vec<u32> {
        self.stack[..self.top.get() as usize]
            .iter()
            .map(Cell::get)
            .collect()
    }

    /// The mbuf of object `index`, in memory whose provenance construction exposed.
    #[cfg(test)]
    pub(crate) fn object(&self, index: u32) -> *mut c_void {
        self.carving.object(index)
    }

    /// A payload state's out flags and descriptor stack as raw pointers, read once per call so a loop keeps them in registers across its stores; a payload state alone holds `count` entries in each, and the payload ops alone call this.
    #[inline(always)]
    fn tracking(&self) -> Tracking {
        debug_assert_eq!(self.role, Role::Payload);
        Tracking {
            out: self.out.as_ptr(),
            stack: self.stack.as_ptr(),
            count: self.carving.count,
        }
    }

    /// Counts `returned` of `len` enqueued objects as returned and the rest as stray.
    #[inline(always)]
    fn tally(&self, returned: u64, len: usize) {
        self.returned.set(self.returned.get() + returned);
        let stray = len as u64 - returned;
        if stray != 0 {
            self.stray.set(self.stray.get() + stray);
        }
    }

    /// Ends the posting of each receive buffer the device returned and counts each object as returned or stray.
    ///
    /// # Safety
    ///
    /// Each of `objs` that names a buffer this pool posted by index is one the device returned once and no longer writes.
    #[inline(always)]
    unsafe fn give_back_receive(&self, objs: &[*mut c_void]) {
        #[cfg(test)]
        self.observe_returns(objs);
        let carving = self.carving;
        let ours = objs.iter().map(|&obj| carving.index_of(obj));
        // SAFETY: the pool serves its kind alone, so a buffer of it posted by index is one this pool's dequeue gave the device; the device returned it once and no longer writes it.
        let ended = unsafe { self.pool().unpost_run(ours) };
        self.tally(u64::from(ended), objs.len());
    }

    /// Disarms each returned header mbuf's token and returns its reference, counting each object as returned or stray.
    ///
    /// # Safety
    ///
    /// Each of `objs` inside this pool's carving is a transmit mbuf the device returned once and whose token it no longer reads.
    #[inline(always)]
    unsafe fn give_back_header(&self, objs: &[*mut c_void]) {
        #[cfg(test)]
        self.observe_returns(objs);
        // The one-object return, the device's free of a transmit segment, stays a leaf with nothing live across a call; a burst loops out of line.
        if let [obj] = objs {
            // SAFETY: the caller's contract.
            let returned = unsafe { return_header(self.carving, self.pool(), *obj) };
            self.tally(u64::from(returned), 1);
        } else {
            // SAFETY: the caller's contract.
            unsafe { self.return_headers(objs) }
        }
    }

    /// [`return_header`] for each of `objs`, counting the burst.
    ///
    /// # Safety
    ///
    /// As for [`give_back_header`](Self::give_back_header).
    #[inline(never)]
    unsafe fn return_headers(&self, objs: &[*mut c_void]) {
        let (carving, pool) = (self.carving, self.pool());
        let mut returned = 0u64;
        for &obj in objs {
            // SAFETY: the caller's contract.
            returned += u64::from(unsafe { return_header(carving, pool, obj) });
        }
        self.tally(returned, objs.len());
    }

    /// Puts each returned out descriptor back on the stack, returning its token's reference when armed, and counts each object as returned or stray.
    ///
    /// # Safety
    ///
    /// As for [`give_back_header`](Self::give_back_header).
    #[inline(always)]
    unsafe fn give_back_payload(&self, objs: &[*mut c_void]) {
        #[cfg(test)]
        self.observe_returns(objs);
        if let [obj] = objs {
            let before = self.top.get();
            let mut top = before;
            // SAFETY: the caller's contract.
            unsafe {
                return_descriptor(self.carving, self.pool(), self.tracking(), &mut top, *obj)
            };
            self.top.set(top);
            // A returned descriptor went back on the stack.
            self.tally(u64::from(top - before), 1);
        } else {
            // SAFETY: the caller's contract.
            unsafe { self.return_descriptors(objs) }
        }
    }

    /// [`return_descriptor`] for each of `objs`, counting the burst.
    ///
    /// # Safety
    ///
    /// As for [`give_back_payload`](Self::give_back_payload).
    #[inline(never)]
    unsafe fn return_descriptors(&self, objs: &[*mut c_void]) {
        let (carving, pool, tracking) = (self.carving, self.pool(), self.tracking());
        let before = self.top.get();
        let mut top = before;
        for &obj in objs {
            // SAFETY: the caller's contract.
            unsafe { return_descriptor(carving, pool, tracking, &mut top, obj) };
        }
        self.top.set(top);
        self.tally(u64::from(top - before), objs.len());
    }

    /// Fills every slot with a posted receive buffer's object and returns true, or counts the refusal and returns false with the arena unchanged.
    #[inline(always)]
    fn take_receive(&self, slots: &mut [MaybeUninit<*mut c_void>]) -> bool {
        let carving = self.carving;
        let mut slots = slots.iter_mut();
        // SAFETY: the closure writes only the dequeue's slots and returns normally.
        let posted = unsafe {
            self.pool().post_run(slots.len() as u32, |index| {
                if let Some(slot) = slots.next() {
                    slot.write(carving.object(index));
                }
            })
        };
        posted || self.refuse()
    }

    /// Fills every slot with a descriptor off the stack and returns true, or counts the refusal and returns false with the stack unchanged.
    #[inline(always)]
    pub(crate) fn take_payload(&self, slots: &mut [MaybeUninit<*mut c_void>]) -> bool {
        let mut top = self.top.get();
        if top < slots.len() as u32 {
            return self.refuse();
        }
        // The one-descriptor take, the burst logic's call per segment, stays a leaf; a bulk take loops out of line.
        if let [slot] = slots {
            top -= 1;
            slot.write(take_descriptor(self.carving, self.tracking(), top));
            self.top.set(top);
        } else {
            self.take_descriptors(top, slots);
        }
        true
    }

    /// Takes one descriptor per slot from the stack below `top`, marking each out, and lowers the top.
    #[inline(never)]
    fn take_descriptors(&self, mut top: u32, slots: &mut [MaybeUninit<*mut c_void>]) {
        let (carving, tracking) = (self.carving, self.tracking());
        for slot in slots.iter_mut() {
            top -= 1;
            slot.write(take_descriptor(carving, tracking, top));
        }
        self.top.set(top);
    }

    /// Counts a refused dequeue and returns false.
    #[cold]
    fn refuse(&self) -> bool {
        self.refused.set(self.refused.get() + 1);
        false
    }

    /// `give_back` returns a device-released object through the enqueue for this pool's role.
    ///
    /// # Safety
    ///
    /// As for the enqueue of this pool's role: a receive buffer this pool posted by index that the device returned once and no longer writes, or a transmit mbuf the device returned once and whose token it no longer reads.
    pub(crate) unsafe fn give_back(&self, obj: *mut c_void) {
        let objs = [obj];
        // SAFETY: `give_back`'s caller satisfies the enqueue safety requirements for this pool's role.
        unsafe {
            match self.role {
                Role::Receive => self.give_back_receive(&objs),
                Role::Header => self.give_back_header(&objs),
                Role::Payload => self.give_back_payload(&objs),
            }
        }
    }

    /// `received` returns the posting for `obj` when this pool's dequeue supplied it to the device.
    ///
    /// # Safety
    ///
    /// The device finished writing `obj` and returned it from a receive burst.
    #[inline]
    pub(crate) unsafe fn received(&self, obj: *mut c_void) -> Option<crate::storage::RxPosted<'_>> {
        let index = self.index_of(obj)?;
        // SAFETY: the pool serves its kind alone, so a buffer of it posted by index is one this pool's dequeue gave the device, and `received`'s caller has the device done writing it.
        unsafe { self.pool().take_posted(index) }
    }

    /// `take` supplies all `slots.len()` objects or refuses the entire request, through the dequeue of this pool's role.
    #[cfg(test)]
    pub(crate) fn take(&self, slots: &mut [MaybeUninit<*mut c_void>]) -> bool {
        match self.role {
            Role::Receive => self.take_receive(slots),
            Role::Payload => self.take_payload(slots),
            Role::Header => self.refuse(),
        }
    }

    /// Objects a dequeue can take now; the header pool serves none.
    fn available(&self) -> u32 {
        match self.role {
            Role::Receive => self.pool().free_count(),
            Role::Header => 0,
            Role::Payload => self.top.get(),
        }
    }

    /// Objects the device holds: payload descriptors off the stack, or served-kind buffers outside the free and retired sets.
    pub(crate) fn outstanding(&self) -> u32 {
        let count = self.carving.count;
        match self.role {
            Role::Payload => count - self.top.get(),
            Role::Receive | Role::Header => self.pool().held(),
        }
    }
}

/// Takes the descriptor at stack slot `at`, marking it out.
#[inline(always)]
fn take_descriptor(carving: Carving, tracking: Tracking, at: u32) -> *mut c_void {
    let index = tracking.slot(at).get();
    tracking.out(index).set(true);
    carving.object(index)
}

/// The private area of the mbuf at `mbuf`.
fn private(mbuf: *mut sys::rte_mbuf) -> *mut Token {
    mbuf.wrapping_add(1).cast()
}

/// Returns one header mbuf `obj` a device gave back: false for an object outside the carving, a disarmed token, a token naming another buffer or a stale incarnation; the stale case alone disarms the token and counts a mismatch, and none changes custody.
///
/// # Safety
///
/// As for [`OpsState::give_back_header`].
#[inline(always)]
unsafe fn return_header(carving: Carving, pool: &Pool, obj: *mut c_void) -> bool {
    let Some(index) = carving.index_of(obj) else {
        return false;
    };
    let token = private(obj.cast());
    // SAFETY: the caller's contract: `obj` is this pool's mbuf, whose private area holds its token; native init zeroed it, and only the owner thread touches it.
    let held = unsafe { token.read() };
    // A header's token holds the header buffer's own reference.
    if held.armed != 1 || held.kind != pool.kind().index() as u16 || held.index != index {
        return false;
    }
    // SAFETY: as above.
    unsafe { token.write(Token::default()) };
    // SAFETY: the header token holds the one reference its buffer's `into_device` took, and the device returns each mbuf once, so this is its only return.
    unsafe { pool.nic_return(index, held.incarnation) }
}

/// Returns one payload descriptor `obj` a device gave back onto the stack at `top`, disarming its token; an object outside the carving or a descriptor not out changes nothing.
///
/// # Safety
///
/// As for [`OpsState::give_back_payload`].
#[inline(always)]
unsafe fn return_descriptor(
    carving: Carving,
    pool: &Pool,
    tracking: Tracking,
    top: &mut u32,
    obj: *mut c_void,
) {
    let Some(index) = carving.index_of(obj) else {
        return;
    };
    if !tracking.out(index).replace(false) {
        return;
    }
    // The descriptor was out, so the stack has room for it.
    tracking.slot(*top).set(index);
    *top += 1;
    // SAFETY: the caller's contract; a descriptor returned without a token holds a disarmed one, which `disarm` skips.
    unsafe { disarm(pool, obj) };
}

/// Disarms the token in `obj`'s private area and returns its reference to `pool`; false for a disarmed token, a token of another kind or a reference that no longer matches.
///
/// # Safety
///
/// `obj` is a transmit mbuf whose token references `pool`'s buffers, and its token's reference is the device's, returned once.
#[inline(always)]
unsafe fn disarm(pool: &Pool, obj: *mut c_void) -> bool {
    let token = private(obj.cast());
    // SAFETY: the private area follows the mbuf inside the object; native init zeroed it, and only the owner thread touches it.
    let held = unsafe { token.read() };
    if held.armed != 1 {
        return false;
    }
    // SAFETY: as above.
    unsafe { token.write(Token::default()) };
    if held.kind != pool.kind().index() as u16 {
        return false;
    }
    // SAFETY: the token was detached once with `into_raw` and the device returns each mbuf once, so this is its only return.
    unsafe { pool.nic_return(held.index, held.incarnation) }
}

/// The armed state behind `mp`: `None` until construction arms the pool, and after `free`, a release or a detach.
///
/// # Safety
///
/// `mp` is a pool created with these ops, and the state it names stays live for `'s`.
#[inline(always)]
unsafe fn state<'s>(mp: *const sys::rte_mempool) -> Option<&'s OpsState> {
    // SAFETY: the caller's contract; `pool_data` is null or names a live state.
    unsafe { (*mp).__bindgen_anon_1.pool_data.cast::<OpsState>().as_ref() }
}

/// The armed state behind `mp` and the `n` objects DPDK enqueues; `None` for an unarmed pool, `n == 0` or a null `objs`.
///
/// # Safety
///
/// As for [`state`], and a non-null `objs` names `n` initialized object pointers that stay valid for `'s`.
#[inline(always)]
unsafe fn returns<'s>(
    mp: *const sys::rte_mempool,
    objs: *const *mut c_void,
    n: c_uint,
) -> Option<(&'s OpsState, &'s [*mut c_void])> {
    // SAFETY: the caller's contract.
    let state = unsafe { state(mp) }?;
    if n == 0 || objs.is_null() {
        return None;
    }
    // SAFETY: the caller's contract for the non-null `objs`.
    Some((state, unsafe {
        std::slice::from_raw_parts(objs, n as usize)
    }))
}

/// The armed state behind `mp` and the `n` slots DPDK dequeues into, or the code to return now: `-ENOBUFS` for an unarmed pool or a null `objs`, and 0 for an armed pool asked for none.
///
/// # Safety
///
/// As for [`state`], and a non-null `objs` names room for `n` object pointers that stays valid and unaliased for `'s`.
#[inline(always)]
unsafe fn requests<'s>(
    mp: *const sys::rte_mempool,
    objs: *mut *mut c_void,
    n: c_uint,
) -> Result<(&'s OpsState, &'s mut [MaybeUninit<*mut c_void>]), c_int> {
    // SAFETY: the caller's contract.
    let state = unsafe { state(mp) }.ok_or(-libc::ENOBUFS)?;
    if n == 0 {
        return Err(0);
    }
    if objs.is_null() {
        return Err(-libc::ENOBUFS);
    }
    // SAFETY: the caller's contract for the non-null `objs`; the slots may be uninitialized, which `MaybeUninit` admits.
    let slots = unsafe {
        std::slice::from_raw_parts_mut(objs.cast::<MaybeUninit<*mut c_void>>(), n as usize)
    };
    Ok((state, slots))
}

/// Leaves `pool_data` null, so population enqueues find no state; construction arms the pool once its checks pass.
extern "C" fn ops_alloc(_mp: *mut sys::rte_mempool) -> c_int {
    0
}

unsafe extern "C" fn ops_free(mp: *mut sys::rte_mempool) {
    // SAFETY: DPDK passes a pool created with these ops; the state stays owned by its `PacketMempool`.
    unsafe { (*mp).__bindgen_anon_1.pool_data = ptr::null_mut() };
}

unsafe extern "C" fn enqueue_receive(
    mp: *mut sys::rte_mempool,
    objs: *const *mut c_void,
    n: c_uint,
) -> c_int {
    // SAFETY: DPDK passes a pool of these ops and `n` object pointers; an armed pool's enqueue is a device's return of each object, once.
    if let Some((state, objs)) = unsafe { returns(mp, objs, n) } {
        // SAFETY: as above.
        unsafe { state.give_back_receive(objs) };
    }
    0
}

unsafe extern "C" fn enqueue_header(
    mp: *mut sys::rte_mempool,
    objs: *const *mut c_void,
    n: c_uint,
) -> c_int {
    // SAFETY: as for `enqueue_receive`.
    if let Some((state, objs)) = unsafe { returns(mp, objs, n) } {
        // SAFETY: as above.
        unsafe { state.give_back_header(objs) };
    }
    0
}

unsafe extern "C" fn enqueue_payload(
    mp: *mut sys::rte_mempool,
    objs: *const *mut c_void,
    n: c_uint,
) -> c_int {
    // SAFETY: as for `enqueue_receive`.
    if let Some((state, objs)) = unsafe { returns(mp, objs, n) } {
        // SAFETY: as above.
        unsafe { state.give_back_payload(objs) };
    }
    0
}

unsafe extern "C" fn dequeue_receive(
    mp: *mut sys::rte_mempool,
    objs: *mut *mut c_void,
    n: c_uint,
) -> c_int {
    // SAFETY: DPDK passes a pool of these ops and room for `n` object pointers.
    match unsafe { requests(mp, objs, n) } {
        Ok((state, slots)) => {
            if state.take_receive(slots) {
                0
            } else {
                -libc::ENOBUFS
            }
        }
        Err(rc) => rc,
    }
}

/// Refuses every nonempty request, counting each one an armed pool receives with slots: header mbufs come from the burst logic.
unsafe extern "C" fn dequeue_header(
    mp: *mut sys::rte_mempool,
    objs: *mut *mut c_void,
    n: c_uint,
) -> c_int {
    // SAFETY: as for `dequeue_receive`.
    match unsafe { requests(mp, objs, n) } {
        Ok((state, _)) => {
            state.refuse();
            -libc::ENOBUFS
        }
        Err(rc) => rc,
    }
}

unsafe extern "C" fn dequeue_payload(
    mp: *mut sys::rte_mempool,
    objs: *mut *mut c_void,
    n: c_uint,
) -> c_int {
    // SAFETY: as for `dequeue_receive`.
    match unsafe { requests(mp, objs, n) } {
        Ok((state, slots)) => {
            if state.take_payload(slots) {
                0
            } else {
                -libc::ENOBUFS
            }
        }
        Err(rc) => rc,
    }
}

pub(super) unsafe extern "C" fn ops_count(mp: *const sys::rte_mempool) -> c_uint {
    // SAFETY: DPDK passes a pool of these ops.
    unsafe { state(mp) }.map_or(0, OpsState::available)
}

/// Why a packet mempool was not built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolError {
    /// The kind is absent or its count is zero, its stride has no packet layout or a data room past an mbuf's `u16` room, its view is another kind's, or a buffer of it is held or another mempool serves it.
    Kind,
    /// The ops are not registered, which they are once the environment initialized.
    Unregistered,
    /// The registration has not verified every page.
    Unverified,
    /// The device's lease is another registration's.
    Device,
    /// A native call failed with this code.
    Native(i32),
    /// An object's address, IOVA or the object count differs from the pool's carving.
    Layout,
    /// The descriptor count is zero, or its descriptor memory exceeds the address space.
    Count,
    /// The engine budget cannot hold the pool's retained heap state.
    Budget(EngineBudgetExceeded),
}

/// One DPDK mempool whose objects are arena buffers or payload descriptors, served by the Rust ops.
///
/// Each pool serves the one leased device it was built for, and
/// [`release`](Self::release) frees it only for that device's
/// [`DeviceStopped`] proof.
///
/// A pool borrows the arena and, through the registration that built it, the
/// [`Environment`](super::Environment), for `'a`. The environment therefore
/// cannot finish while a pool lives, whether or not its registration still
/// does:
///
/// ```compile_fail,E0505
/// use kestrike::native::{
///     ArenaRegistration, DmaPolicy, Environment, PacketMempool, Watchdog,
/// };
/// use kestrike::storage::{BufferArena, EngineBudget, LinuxPlatform};
///
/// fn finish_under_a_pool(
///     env: Environment,
///     arena: &BufferArena<LinuxPlatform>,
///     watchdog: &Watchdog,
///     budget: &mut EngineBudget,
/// ) {
///     let policy = DmaPolicy { allow_no_iommu: false };
///     let mut registration = ArenaRegistration::register(&env, arena, policy).unwrap();
///     let lease = registration.device_attached();
///     let pool = PacketMempool::header(arena, &registration, &lease, c"hdr", budget);
///     drop(registration);
///     let _ = env.finish(watchdog);
///     drop(pool);
/// }
/// ```
pub struct PacketMempool<'a> {
    mp: NonNull<sys::rte_mempool>,
    state: NonNull<OpsState>,
    /// Payload descriptor memory, cache-line aligned and uninitialized when
    /// allocated, which the native pool's objects occupy.
    descriptors: NonNull<[MaybeUninit<Line>]>,
    /// The device the pool serves, whose stop proof alone releases it.
    device: DeviceId,
    /// The borrow of the arena and of the environment.
    arena: PhantomData<&'a ()>,
}

#[repr(C, align(64))]
struct Line([u8; 64]);

impl<'a> PacketMempool<'a> {
    /// The receive pool of `device` over the buffers of `view`, the endpoint's receive view, each object at its buffer's mbuf offset with its registered IOVA, charging its retained state to `budget`.
    ///
    /// # Errors
    ///
    /// [`MempoolError`] naming the failed check or native call; nothing native remains and `budget` is unchanged.
    pub fn receive(
        view: &'a PacketPool<'a>,
        registration: &ArenaRegistration<'a>,
        device: &DeviceLease,
        name: &CStr,
        budget: &mut EngineBudget,
    ) -> Result<Self, MempoolError> {
        Self::arena_pool(
            view.served(),
            registration,
            device,
            name,
            Role::Receive,
            budget,
        )
    }

    /// The transmit header pool of `device` over `arena`'s `PacketHeader` buffers, which it holds as their only view, charging its retained state to `budget`.
    ///
    /// # Errors
    ///
    /// As for [`receive`](Self::receive), and `Kind` while another view holds the kind.
    pub fn header<P: Platform>(
        arena: &'a BufferArena<P>,
        registration: &ArenaRegistration<'a>,
        device: &DeviceLease,
        name: &CStr,
        budget: &mut EngineBudget,
    ) -> Result<Self, MempoolError> {
        let pool = arena.pools().pool(PoolKind::PacketHeader);
        Self::arena_pool(pool, registration, device, name, Role::Header, budget)
    }

    /// The bytes an arena pool keeps on the heap: its boxed ops state.
    pub(crate) const ARENA_CHARGE: usize = size_of::<OpsState>();

    /// The bytes a payload pool of `count` descriptors keeps on the heap: its
    /// boxed ops state, the descriptor stack, the out flags and its padded
    /// descriptor memory; `None` for no descriptors or a total past the
    /// address space.
    #[cfg(test)]
    pub(crate) fn payload_charge(count: u32) -> Option<usize> {
        let (_, _, _, backing) = Self::payload_shape(count).ok()?;
        Self::payload_retained(count, backing)
    }

    /// The boxed ops state, the descriptor stack and out flags of `count`
    /// descriptors, and `backing` bytes of descriptor memory.
    fn payload_retained(count: u32, backing: usize) -> Option<usize> {
        let state = Layout::new::<OpsState>().size();
        let count = count as usize;
        [
            Layout::array::<Cell<u32>>(count).ok()?.size(),
            Layout::array::<Cell<bool>>(count).ok()?.size(),
            backing,
        ]
        .into_iter()
        .try_fold(state, usize::checked_add)
    }

    /// The shape of a payload pool of `count` descriptors: the element bytes
    /// past each object's header, the stride from one object to the next,
    /// and the cache lines and bytes of its descriptor memory. Each
    /// descriptor takes a power-of-two stride, so the ops index it by shift,
    /// and a whole number of lines, since the mbuf alone spans two.
    fn payload_shape(count: u32) -> Result<(u32, usize, usize, usize), MempoolError> {
        let (header, trailer) = object_overhead();
        let stride = (header + size_of::<sys::rte_mbuf>() + PRIVATE + trailer).next_power_of_two();
        let element = u32::try_from(stride - header - trailer).map_err(|_| MempoolError::Layout)?;
        let lines = (stride / 64)
            .checked_mul(count as usize)
            .filter(|&lines| lines > 0)
            .ok_or(MempoolError::Count)?;
        let backing = Layout::array::<Line>(lines)
            .map_err(|_| MempoolError::Count)?
            .size();
        Ok((element, stride, lines, backing))
    }

    fn arena_pool(
        arena: &'a Pool,
        registration: &ArenaRegistration<'a>,
        device: &DeviceLease,
        name: &CStr,
        role: Role,
        budget: &mut EngineBudget,
    ) -> Result<Self, MempoolError> {
        let (span, spec) = arena.span();
        let kind = spec.kind;
        let layout = PacketLayout::of(spec.buffer_len as usize).ok_or(MempoolError::Kind)?;
        if role == Role::Receive && kind != PoolKind::PacketReceive {
            return Err(MempoolError::Kind);
        }
        if !registration.is_ready() {
            return Err(MempoolError::Unverified);
        }
        if device.registration() != registration.id() {
            return Err(MempoolError::Device);
        }
        let room = u16::try_from(layout.data_room + sys::RTE_PKTMBUF_HEADROOM as usize)
            .map_err(|_| MempoolError::Kind)?;
        if spec.count == 0 {
            return Err(MempoolError::Kind);
        }
        let mut staged = *budget;
        staged
            .charge(Self::ARENA_CHARGE)
            .map_err(MempoolError::Budget)?;
        // The header pool holds its kind's view itself. A failure below ends
        // the claims made before it; `discard` ends both, and ending a claim
        // twice leaves it ended.
        let viewed = role == Role::Header;
        if viewed && !arena.claim_view() {
            return Err(MempoolError::Kind);
        }
        let end = |served: bool| {
            if served {
                arena.end_served();
            }
            if viewed {
                arena.end_view();
            }
        };
        if !arena.claim_served() {
            end(false);
            return Err(MempoolError::Kind);
        }
        let stride = spec.buffer_len as usize;
        let (header, trailer) = object_overhead();
        let state = OpsState::new(
            role,
            arena,
            span + layout.mbuf_offset,
            spec.buffer_len.trailing_zeros(),
            spec.count,
        );
        let ops = if viewed { HEADER_OPS } else { RECEIVE_OPS };
        let pool = Self::create(
            name,
            ops,
            state,
            (stride - header - trailer) as u32,
            room,
            NonNull::from(Box::leak(Box::<[MaybeUninit<Line>]>::default())),
            device.device(),
        )
        .inspect_err(|_| end(true))?;
        match pool.populate_arena(registration, span, spec.count as usize * stride) {
            Ok(()) => {
                pool.arm();
                *budget = staged;
                Ok(pool)
            }
            Err(error) => {
                pool.discard();
                Err(error)
            }
        }
    }

    /// Populates the pool from the arena span at `span`, page by page with each page's registered IOVA, then initializes and checks every object.
    fn populate_arena(
        &self,
        registration: &ArenaRegistration<'_>,
        span: usize,
        len: usize,
    ) -> Result<(), MempoolError> {
        let page = registration.report().page_size;
        let end = span + len;
        let mut at = span;
        while at < end {
            let chunk = ((at / page + 1) * page - at).min(end - at);
            let iova = registration
                .iova(at, chunk)
                .ok_or(MempoolError::Unverified)?;
            // SAFETY: `at..at + chunk` is arena memory registered with DPDK and inside one backing page; the arena outlives the pool, and no handle reaches a buffer of the served kind.
            let added = unsafe {
                sys::rte_mempool_populate_iova(
                    self.mp.as_ptr(),
                    ptr::with_exposed_provenance_mut(at),
                    iova,
                    chunk,
                    None,
                    ptr::null_mut(),
                )
            };
            if added < 0 {
                return Err(MempoolError::Native(-added));
            }
            at += chunk;
        }
        self.initialize_and_check(&|addr, len| registration.iova(addr, len))
    }

    /// The payload descriptor pool of `device` with `count` descriptors, mbufs with no data room whose memory the pool owns, charging the descriptor memory and the pool's other retained state to `budget`. The pool reads nothing of `registration`; it borrows it as the arena pools do, so the environment outlives the pool.
    ///
    /// # Errors
    ///
    /// `Layout` when the descriptor element exceeds `u32`, `Count` when
    /// `count` is zero or the descriptor memory overflows `usize`, then
    /// `Budget`, each before anything is allocated; then
    /// `Unregistered`, `Native` or `Layout`, after freeing any allocated
    /// native pool, the ops state and the descriptor memory. `budget` is
    /// unchanged on every error.
    pub fn payload<P: Platform>(
        arena: &'a BufferArena<P>,
        _registration: &ArenaRegistration<'a>,
        device: &DeviceLease,
        name: &CStr,
        count: u32,
        budget: &mut EngineBudget,
    ) -> Result<Self, MempoolError> {
        let (header, _) = object_overhead();
        let (element, stride, lines, backing) = Self::payload_shape(count)?;
        let charge = Self::payload_retained(count, backing).ok_or(MempoolError::Count)?;
        let mut staged = *budget;
        staged.charge(charge).map_err(MempoolError::Budget)?;
        let descriptors = NonNull::from(Box::leak(Box::<[Line]>::new_uninit_slice(lines)));
        let base = descriptors.as_ptr().cast::<Line>().expose_provenance();
        let state = OpsState::new(
            Role::Payload,
            arena.pools().pool(PoolKind::ReadResponse),
            base + header,
            stride.trailing_zeros(),
            count,
        );
        let pool = Self::create(
            name,
            PAYLOAD_OPS,
            state,
            element,
            0,
            descriptors,
            device.device(),
        )?;
        prefault(base, backing);
        // SAFETY: the descriptor memory is the pool's own and outlives it; the device reads no descriptor bytes, so it has no IOVA.
        let added = unsafe {
            sys::rte_mempool_populate_iova(
                pool.mp.as_ptr(),
                ptr::with_exposed_provenance_mut(base),
                sys::RTE_BAD_IOVA as u64,
                backing,
                None,
                ptr::null_mut(),
            )
        };
        let populated = if added < 0 {
            Err(MempoolError::Native(-added))
        } else {
            pool.initialize_and_check(&|_, _| None)
        };
        if let Err(error) = populated {
            pool.discard();
            return Err(error);
        }
        pool.arm();
        *budget = staged;
        Ok(pool)
    }

    /// An empty pool of these ops for `device` over objects of `element` bytes past the object header whose mbufs carry `room` bytes of buffer.
    /// `descriptors` came from `Box::leak` and the pool takes it over.
    fn create(
        name: &CStr,
        ops: &CStr,
        state: OpsState,
        element: u32,
        room: u16,
        descriptors: NonNull<[MaybeUninit<Line>]>,
        device: DeviceId,
    ) -> Result<Self, MempoolError> {
        let flags = FLAGS
            | if state.role == Role::Payload {
                sys::RTE_MEMPOOL_F_NO_IOVA_CONTIG
            } else {
                0
            };
        let count = state.count();
        let state = NonNull::from(Box::leak(Box::new(state)));
        // SAFETY: plain arguments; DPDK allocates the pool structure.
        let mp = unsafe {
            sys::rte_mempool_create_empty(
                name.as_ptr(),
                count,
                element,
                0,
                size_of::<sys::rte_pktmbuf_pool_private>() as u32,
                sys::rte_socket_id() as c_int,
                flags,
            )
        };
        let Some(mp) = NonNull::new(mp) else {
            // SAFETY: both came from leaked boxes no native pool references.
            unsafe { reclaim(state, descriptors) };
            // SAFETY: reads this thread's error number.
            return Err(MempoolError::Native(unsafe { sys::spdk_sys_rte_errno() }));
        };
        let pool = Self {
            mp,
            state,
            descriptors,
            device,
            arena: PhantomData,
        };
        // SAFETY: a fresh pool; the ops reach the state only once `arm` points `pool_data` at it.
        let rc =
            unsafe { sys::rte_mempool_set_ops_byname(mp.as_ptr(), ops.as_ptr(), ptr::null_mut()) };
        if rc != 0 {
            pool.discard();
            return Err(if rc == -libc::EINVAL {
                MempoolError::Unregistered
            } else {
                MempoolError::Native(-rc)
            });
        }
        let mut private = sys::rte_pktmbuf_pool_private {
            mbuf_data_room_size: room,
            mbuf_priv_size: PRIVATE as u16,
            flags: 0,
        };
        // SAFETY: the pool's private area holds one `rte_pktmbuf_pool_private`, which init copies from `private`.
        unsafe { sys::rte_pktmbuf_pool_init(mp.as_ptr(), (&raw mut private).cast()) };
        Ok(pool)
    }

    /// Initializes every object's mbuf with `rte_pktmbuf_init` and checks the object against the carving and, through `iova`, the registration, in one walk of the pool's object list.
    ///
    /// # Errors
    ///
    /// `Layout` unless every object passes the check and the walk visits exactly the carving's count.
    fn initialize_and_check(
        &self,
        iova: &dyn Fn(usize, usize) -> Option<u64>,
    ) -> Result<(), MempoolError> {
        let (header, trailer) = object_overhead();
        let state = self.ops();
        let mut check = Check {
            state,
            iova,
            element: state.stride() - header - trailer,
            ok: true,
        };
        // SAFETY: every populated object is an mbuf-sized element of this unarmed pool, and `check` outlives the walk; the callback initializes each mbuf once, then the check reads the header population wrote and the mbuf the callback just initialized.
        let visited = unsafe {
            sys::rte_mempool_obj_iter(
                self.mp.as_ptr(),
                Some(init_and_check_object),
                (&raw mut check).cast(),
            )
        };
        if check.ok && visited == state.count() {
            Ok(())
        } else {
            Err(MempoolError::Layout)
        }
    }

    /// The device this pool serves.
    pub(crate) fn device(&self) -> DeviceId {
        self.device
    }

    pub(crate) fn ops(&self) -> &OpsState {
        // SAFETY: the state lives until `discard` or for the process.
        unsafe { self.state.as_ref() }
    }

    /// The native pool, for a device queue's setup.
    pub fn as_ptr(&self) -> *mut sys::rte_mempool {
        self.mp.as_ptr()
    }

    pub fn report(&self) -> OpsReport {
        self.ops().report()
    }

    /// The flags and cache size the native pool reports.
    pub fn native_shape(&self) -> (u32, u32) {
        // SAFETY: the pool is live.
        unsafe { ((*self.mp.as_ptr()).flags, (*self.mp.as_ptr()).cache_size) }
    }

    /// Whether this pool serves its objects: population and its checks finished.
    pub fn armed(&self) -> bool {
        // SAFETY: the pool is live.
        !unsafe { (*self.mp.as_ptr()).__bindgen_anon_1.pool_data }.is_null()
    }

    /// Points the native pool at its state once population and its checks finished, so enqueues are device returns.
    fn arm(&self) {
        // SAFETY: the pool is live and the state outlives every op on it: `discard` and `drop` disarm first.
        unsafe { (*self.mp.as_ptr()).__bindgen_anon_1.pool_data = self.state.as_ptr().cast() };
    }

    /// Detaches the state from the native pool; every op then answers without touching it.
    fn disarm(&self) {
        // SAFETY: the pool is live.
        unsafe { (*self.mp.as_ptr()).__bindgen_anon_1.pool_data = ptr::null_mut() };
    }

    /// `release` frees the native pool when `stopped` identifies the pool's device and `outstanding()` is zero, then returns `stopped` for that device's other pools and the registration.
    ///
    /// # Errors
    ///
    /// `release` returns `Err((self, stopped))` when `stopped` identifies another device or `outstanding()` is nonzero; the pool stays armed and serving.
    pub fn release(self, stopped: DeviceStopped) -> Result<DeviceStopped, (Self, DeviceStopped)> {
        if stopped.device() != self.device || self.ops().outstanding() != 0 {
            return Err((self, stopped));
        }
        self.discard();
        Ok(stopped)
    }

    /// Frees the native pool, the state and the descriptors, which no device can reach.
    fn discard(self) {
        let pool = std::mem::ManuallyDrop::new(self);
        let state = pool.ops();
        // Freeing drains the native object list through dequeue; a disarmed pool refuses it, so the arena stays as it is.
        pool.disarm();
        // SAFETY: no device reaches the pool, and this is the pool's one free.
        unsafe { sys::rte_mempool_free(pool.mp.as_ptr()) };
        if state.role != Role::Payload {
            state.pool().end_served();
        }
        if state.role == Role::Header {
            state.pool().end_view();
        }
        // SAFETY: the native pool is freed, so nothing reads the state or the descriptors again.
        unsafe { reclaim(pool.state, pool.descriptors) };
    }
}

#[cfg(test)]
impl PacketMempool<'static> {
    /// A pool over a mock native pool and its leaked state, serving `device`; dropping it disarms the mock.
    pub(crate) fn mocked(
        mp: *mut sys::rte_mempool,
        state: &'static OpsState,
        device: DeviceId,
    ) -> Self {
        Self {
            mp: NonNull::new(mp).expect("a mock pool"),
            state: NonNull::from(state),
            descriptors: NonNull::from(Box::leak(Box::<[MaybeUninit<Line>]>::default())),
            device,
            arena: PhantomData,
        }
    }
}

impl Drop for PacketMempool<'_> {
    /// Disarms the ops and detaches the state from the native pool, which stays allocated under its name, and its kind stays served: a device that still reaches it finds no state and changes no custody, and no handle reaches its objects.
    fn drop(&mut self) {
        self.disarm();
    }
}

/// Frees a leaked state and descriptor memory.
///
/// # Safety
///
/// Both came from `Box::leak` and no native pool references them.
unsafe fn reclaim(state: NonNull<OpsState>, descriptors: NonNull<[MaybeUninit<Line>]>) {
    // SAFETY: the caller's contract.
    unsafe {
        drop(Box::from_raw(state.as_ptr()));
        drop(Box::from_raw(descriptors.as_ptr()));
    }
}

/// Populates every whole page inside `addr..addr + len` for writing with one
/// `madvise(MADV_POPULATE_WRITE)` call, keeping the bytes already there.
///
/// The call covers `addr` rounded up to the `sysconf(_SC_PAGESIZE)` page
/// size through `addr + len` rounded down, and returns at once when no whole
/// page lies inside or `sysconf` reports no power-of-two page size. The
/// advice result is discarded: on refusal, the caller's later writes fault
/// the pages in.
pub(crate) fn prefault(addr: usize, len: usize) {
    // SAFETY: `sysconf` reads a constant and has no memory arguments.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let Some(page) = usize::try_from(page)
        .ok()
        .filter(|page| page.is_power_of_two())
    else {
        return;
    };
    let (Some(start), Some(end)) = (addr.checked_next_multiple_of(page), addr.checked_add(len))
    else {
        return;
    };
    let end = end & !(page - 1);
    if start < end {
        // SAFETY: `MADV_POPULATE_WRITE` prefaults page tables inside `start..end`, which lies within `addr..addr + len`, and preserves every byte there; a range that is unmapped or not writable makes the call fail, and `prefault` discards that error.
        unsafe {
            libc::madvise(
                ptr::with_exposed_provenance_mut(start),
                end - start,
                libc::MADV_POPULATE_WRITE,
            )
        };
    }
}

/// What the construction check walks.
pub(crate) struct Check<'s> {
    pub(crate) state: &'s OpsState,
    /// The registration's translation, or none for objects the device never reads.
    pub(crate) iova: &'s dyn Fn(usize, usize) -> Option<u64>,
    /// Bytes of each object after its header.
    pub(crate) element: usize,
    pub(crate) ok: bool,
}

/// Checks object `index` at `obj`: it lies where the carving puts object `index`, and an arena object carries its page's registered IOVA, as does its buffer.
pub(crate) unsafe extern "C" fn check_object(
    _mp: *mut sys::rte_mempool,
    opaque: *mut c_void,
    obj: *mut c_void,
    index: c_uint,
) {
    // SAFETY: `opaque` is the caller's live `Check`.
    let check = unsafe { &mut *opaque.cast::<Check<'_>>() };
    let header = obj.cast::<sys::rte_mempool_objhdr>().wrapping_sub(1);
    let mbuf = obj.cast::<sys::rte_mbuf>();
    // SAFETY: population wrote the object header before the object, and init wrote the mbuf.
    let (iova, buf_addr, buf_iova) =
        unsafe { ((*header).iova, (*mbuf).buf_addr, (*mbuf).buf_iova) };
    let placed = check.state.index_of(obj) == Some(index);
    let addressed = match (
        (check.iova)(obj.addr(), check.element),
        (check.iova)(buf_addr.addr(), 1),
    ) {
        (Some(object), Some(room)) => object == iova && room == buf_iova,
        (None, None) => check.state.role == Role::Payload,
        _ => false,
    };
    check.ok &= placed && addressed;
}

/// The `rte_mempool_obj_iter` callback that initializes object `index`'s mbuf at `obj` with `rte_pktmbuf_init`, then checks the object with [`check_object`].
unsafe extern "C" fn init_and_check_object(
    mp: *mut sys::rte_mempool,
    opaque: *mut c_void,
    obj: *mut c_void,
    index: c_uint,
) {
    // SAFETY: `obj` is a populated mbuf-sized object of `mp`, and `opaque` is the caller's live `Check`.
    unsafe {
        sys::rte_pktmbuf_init(mp, ptr::null_mut(), obj, index);
        check_object(mp, opaque, obj, index);
    }
}
