//! Test doubles for [`Platform`]: a recorder that logs every kernel call and
//! can fail the n-th call of one kind, over either the real Linux binding or a
//! heap backing that runs under Miri.
//!
//! The heap backing proves control construction and offset code with
//! production code paths; it proves nothing about the kernel. Tests that need
//! kernel behavior use the Linux backing and are skipped under Miri.

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::collections::VecDeque;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::budget::WorkBudget;
use super::finalize::{Blockers, Finalization, FinalizeError};
use super::init::InitPhase;
use super::mapping::Region;
use super::os::{HugepageSize, LinuxPlatform, OsCode, Platform};
use super::owner::Storage;
use super::placement::{NodeMask, Topology};

/// One finalization call with an allowance that covers every inspection
/// visit and every release of a test-sized owner.
pub(super) fn finalize(storage: &mut Storage<TestPlatform>) -> Result<Finalization, FinalizeError> {
    storage.finalize(&mut WorkBudget::new(1 << 20))
}

/// The blockers a fully funded finalization names, or a panic if it did
/// anything but block.
pub(super) fn blocked(storage: &mut Storage<TestPlatform>) -> Blockers {
    match finalize(storage) {
        Ok(Finalization::Blocked(blockers)) => blockers,
        other => panic!("expected a blocked finalization, got {other:?}"),
    }
}

/// One kernel call kind, without arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    PageSize,
    Topology,
    Map,
    MapHuge(HugepageSize),
    AdviseHuge,
    AdviseNormal,
    Bind,
    Protect,
    Populate,
    Residency,
    CheckBound,
    PageNode,
    Unmap,
    ClockResolution,
    Cut(InitPhase),
}

thread_local! {
    /// Runs once inside the next sample this thread takes, after the sample's
    /// value is fixed and before `now_ticks` returns, so a test can act between
    /// a caller's sample and the loads the caller makes next.
    pub(crate) static IN_SAMPLE: std::cell::Cell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::Cell::new(None) };
}

/// Deterministic ticks for the heap and Linux backings alike: a queue of
/// samples handed out in order, then the last one handed out repeated.
/// Nothing queued reads as an unavailable clock, so a test that never sets
/// the clock cannot pass a deadline check by accident.
#[derive(Default)]
struct Clock {
    queue: VecDeque<Option<u64>>,
    sticky: Option<u64>,
    taken: usize,
    after_stores: usize,
}

/// The heap backing's fake topology: nodes 0..4 exist, 0..3 have memory,
/// 0..2 are allowed. Node 3 is memoryless, node 2 is disallowed, node 4 and
/// above do not exist.
pub(crate) fn heap_topology() -> Topology {
    Topology {
        possible: NodeMask::from_nodes(&[0, 1, 2, 3]).unwrap(),
        has_memory: NodeMask::from_nodes(&[0, 1, 2]).unwrap(),
        allowed: NodeMask::from_nodes(&[0, 1]).unwrap(),
    }
}

/// One recorded call with the range it targeted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Call {
    pub op: Op,
    pub base: usize,
    pub len: usize,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Fail {
    pub op: Op,
    /// This 1-based ordinal selects a call of `op`; `region` takes precedence.
    pub ordinal: usize,
    pub code: OsCode,
    /// When set, selects every call of `op` that names this region.
    pub region: Option<Region>,
}

/// The call log, shared so a test can read it after the platform was moved
/// into a transaction that failed, and thread-safe so a storage built on the
/// platform can be shared across test threads.
#[derive(Clone, Default)]
pub(crate) struct Log(Arc<Mutex<LogInner>>);

struct LogInner {
    calls: Vec<Call>,
    /// Heap ranges mapped and not yet released: a refused release keeps its
    /// range here, and so does an owner dropped without finalizing. The
    /// platform frees what is left when it drops, so nothing leaks.
    live: Vec<LiveRange>,
    /// The mask each bind and bound check received, in call order.
    masks: Vec<(Op, NodeMask)>,
    /// The status buffer length each residency query received, in call
    /// order.
    status_lens: Vec<usize>,
    /// Heap allocation count sampled when the first armed failure fired.
    allocations_at_fail: Option<usize>,
}

/// One heap range handed out as a mapping: the integer base and extent the
/// caller sees, and the allocation it lies in, freed with its own layout.
#[derive(Debug, Clone, Copy)]
struct LiveRange {
    base: usize,
    len: usize,
    allocation: usize,
    layout: Layout,
}

const LOG_CAPACITY: usize = 256;

impl Default for LogInner {
    fn default() -> Self {
        Self {
            calls: Vec::with_capacity(LOG_CAPACITY),
            live: Vec::with_capacity(8),
            masks: Vec::with_capacity(LOG_CAPACITY),
            status_lens: Vec::with_capacity(LOG_CAPACITY),
            allocations_at_fail: None,
        }
    }
}

impl Log {
    /// Heap allocations counted when the armed failure fired.
    pub(crate) fn allocations_at_fail(&self) -> Option<usize> {
        self.0.lock().unwrap().allocations_at_fail
    }

    pub(crate) fn all(&self) -> Vec<Call> {
        self.0.lock().unwrap().calls.clone()
    }

    pub(crate) fn calls(&self, op: Op) -> Vec<Call> {
        self.0
            .lock()
            .unwrap()
            .calls
            .iter()
            .copied()
            .filter(|call| call.op == op)
            .collect()
    }

    pub(crate) fn masks(&self) -> Vec<(Op, NodeMask)> {
        self.0.lock().unwrap().masks.clone()
    }

    pub(crate) fn status_lens(&self) -> Vec<usize> {
        self.0.lock().unwrap().status_lens.clone()
    }

    /// Bases and extents of every successful mapping of either kind, in
    /// order, for release oracles that cover hugepage mappings too.
    pub(crate) fn mapped(&self) -> Vec<(usize, usize)> {
        self.0
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|call| matches!(call.op, Op::Map | Op::MapHuge(_)) && call.base != 0)
            .map(|call| (call.base, call.len))
            .collect()
    }

    /// Bases and extents of every call of `op`, in order. Excludes a `Map`
    /// that failed and therefore has no base.
    pub(crate) fn ranges(&self, op: Op) -> Vec<(usize, usize)> {
        self.calls(op)
            .into_iter()
            .filter(|call| call.base != 0)
            .map(|call| (call.base, call.len))
            .collect()
    }

    fn push(&self, call: Call) -> usize {
        let mut log = self.0.lock().unwrap();
        log.calls.push(call);
        log.calls.iter().filter(|c| c.op == call.op).count()
    }
}

pub(crate) enum Backing {
    Linux(LinuxPlatform),
    Heap { page_size: usize },
}

pub(crate) struct TestPlatform {
    backing: Backing,
    log: Log,
    fails: Mutex<Vec<Fail>>,
    /// Residency bytes to report instead of the backing's, indexed by page
    /// within the queried mapping and cycled past the end.
    fake_residency: Mutex<Option<Vec<u8>>>,
    /// Page-node answers to report instead of the backing's, indexed the
    /// same way: a node, or a negative `errno` to fail that page. The range
    /// check refuses a range holding any answer that is not a node inside
    /// the mask.
    fake_page_nodes: Mutex<Option<Vec<i32>>>,
    /// When set, a heap hugepage mapping starts one base page past a
    /// hugepage boundary, so a caller's alignment check must refuse it.
    misalign_hugepages: AtomicBool,
    clock: Mutex<Clock>,
    counted: Arc<std::sync::atomic::AtomicUsize>,
    before_unmap: Mutex<Option<Box<dyn Fn() + Send>>>,
}

impl TestPlatform {
    pub(crate) fn linux() -> Self {
        Self::new(Backing::Linux(LinuxPlatform))
    }

    pub(crate) fn heap(page_size: usize) -> Self {
        Self::new(Backing::Heap { page_size })
    }

    fn new(backing: Backing) -> Self {
        Self {
            backing,
            log: Log::default(),
            fails: Mutex::new(Vec::new()),
            fake_residency: Mutex::new(None),
            fake_page_nodes: Mutex::new(None),
            misalign_hugepages: AtomicBool::new(false),
            clock: Mutex::new(Clock::default()),
            counted: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            before_unmap: Mutex::new(None),
        }
    }

    /// A shared count of the samples `now_ticks` handed out, readable apart from the platform.
    pub(crate) fn sample_counter(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        self.counted.clone()
    }

    /// Queues the samples `now_ticks` hands out next, in order; after the
    /// queue is spent the last sample repeats. Replaces any earlier queue.
    pub(crate) fn ticks(&self, samples: &[Option<u64>]) {
        let mut clock = self.clock.lock().unwrap();
        clock.queue = samples.iter().copied().collect();
    }

    pub(crate) fn last_sample(&self) -> Option<u64> {
        self.clock.lock().unwrap().sticky
    }

    /// Samples taken so far.
    pub(crate) fn samples_taken(&self) -> usize {
        self.clock.lock().unwrap().taken
    }

    pub(crate) fn samples_after_stores(&self) -> usize {
        self.clock.lock().unwrap().after_stores
    }

    pub(crate) fn log(&self) -> Log {
        self.log.clone()
    }

    /// Arms one failure; several may be armed at once.
    pub(crate) fn fail_at(&self, fail: Fail) {
        self.fails.lock().unwrap().push(fail);
    }

    pub(crate) fn before_unmap(&self, observer: impl Fn() + Send + 'static) {
        *self.before_unmap.lock().unwrap() = Some(Box::new(observer));
    }

    pub(crate) fn fake_residency(&self, status: Vec<u8>) {
        *self.fake_residency.lock().unwrap() = Some(status);
    }

    pub(crate) fn fake_page_nodes(&self, status: Vec<i32>) {
        *self.fake_page_nodes.lock().unwrap() = Some(status);
    }

    pub(crate) fn misalign_hugepages(&self) {
        self.misalign_hugepages.store(true, Ordering::Relaxed);
    }

    fn backing_page_size(&self) -> Result<usize, OsCode> {
        match self.backing {
            Backing::Linux(linux) => linux.page_size(),
            Backing::Heap { page_size } => Ok(page_size),
        }
    }

    /// The base and page unit of the mapping containing `address`: the
    /// hugepage size for a hugepage mapping, the backing's page size
    /// otherwise, and `address` itself as the base when no mapping holds it.
    fn containing_mapping(&self, address: usize) -> Result<(usize, usize), OsCode> {
        let found = self
            .log
            .0
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|call| call.base != 0 && call.base <= address && address < call.base + call.len)
            .find_map(|call| match call.op {
                Op::Map => Some((call.base, None)),
                Op::MapHuge(size) => Some((call.base, Some(size.bytes()))),
                _ => None,
            });
        match found {
            Some((base, Some(unit))) => Ok((base, unit)),
            Some((base, None)) => Ok((base, self.backing_page_size()?)),
            None => Ok((address, self.backing_page_size()?)),
        }
    }

    /// Page index of `address` within the mapping that contains it, in that
    /// mapping's page unit.
    fn page_within_mapping(&self, address: usize) -> Result<usize, OsCode> {
        let (base, unit) = self.containing_mapping(address)?;
        Ok((address - base) / unit)
    }

    fn record(
        &self,
        op: Op,
        region: Option<Region>,
        base: usize,
        len: usize,
    ) -> Result<(), OsCode> {
        let count = self.log.push(Call { op, base, len });
        let armed = self
            .fails
            .lock()
            .unwrap()
            .iter()
            .find(|fail| {
                fail.op == op
                    && match fail.region {
                        Some(wanted) => region == Some(wanted),
                        None => fail.ordinal == count,
                    }
            })
            .map(|fail| fail.code);
        match armed {
            Some(code) => Err(self.fire(code)),
            None => Ok(()),
        }
    }

    fn fire(&self, code: OsCode) -> OsCode {
        let mut log = self.log.0.lock().unwrap();
        if log.allocations_at_fail.is_none() {
            log.allocations_at_fail = Some(crate::instrument::allocations());
        }
        code
    }
}

// SAFETY: every kernel-shaped method forwards to `LinuxPlatform` or to a
// heap-backed range of `len` bytes that starts `skew` bytes past an aligned
// address inside one `alloc_zeroed` allocation of `len + skew + align`
// bytes, so the heap-backed range reads as zero until its holder writes it.
unsafe impl Platform for TestPlatform {
    fn page_size(&self) -> Result<usize, OsCode> {
        self.record(Op::PageSize, None, 0, 0)?;
        match self.backing {
            Backing::Linux(linux) => linux.page_size(),
            Backing::Heap { page_size } => Ok(page_size),
        }
    }

    fn map_inaccessible(&self, len: usize) -> Result<NonNull<u8>, OsCode> {
        // A failed map is logged with base 0 and maps nothing, so the log's
        // `Map` entries with a base are exactly the ranges that exist.
        self.record(Op::Map, None, 0, len)?;
        match self.backing {
            Backing::Linux(linux) => self.note_mapped(linux.map_inaccessible(len)?, None),
            Backing::Heap { page_size } => self.heap_map(len, page_size, 0),
        }
    }

    fn map_hugepages(&self, len: usize, size: HugepageSize) -> Result<NonNull<u8>, OsCode> {
        self.record(Op::MapHuge(size), None, 0, len)?;
        match self.backing {
            Backing::Linux(linux) => self.note_mapped(linux.map_hugepages(len, size)?, None),
            Backing::Heap { page_size } => {
                let skew = if self.misalign_hugepages.load(Ordering::Relaxed) {
                    page_size
                } else {
                    0
                };
                self.heap_map(len, size.bytes(), skew)
            }
        }
    }

    unsafe fn advise_huge_pages(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode> {
        self.record(Op::AdviseHuge, None, base.as_ptr() as usize, len)?;
        match self.backing {
            // SAFETY: forwarded unchanged from a caller holding the same guarantee.
            Backing::Linux(linux) => unsafe { linux.advise_huge_pages(base, len) },
            Backing::Heap { .. } => Ok(()),
        }
    }

    unsafe fn advise_normal_pages(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode> {
        self.record(Op::AdviseNormal, None, base.as_ptr() as usize, len)?;
        match self.backing {
            // SAFETY: forwarded unchanged from a caller holding the same guarantee.
            Backing::Linux(linux) => unsafe { linux.advise_normal_pages(base, len) },
            Backing::Heap { .. } => Ok(()),
        }
    }

    unsafe fn protect_read_write(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode> {
        self.record(Op::Protect, None, base.as_ptr() as usize, len)?;
        match self.backing {
            // SAFETY: forwarded unchanged from a caller holding the same guarantee.
            Backing::Linux(linux) => unsafe { linux.protect_read_write(base, len) },
            Backing::Heap { .. } => Ok(()),
        }
    }

    unsafe fn populate_write(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode> {
        self.record(Op::Populate, None, base.as_ptr() as usize, len)?;
        match self.backing {
            // SAFETY: forwarded unchanged from a caller holding the same guarantee.
            Backing::Linux(linux) => unsafe { linux.populate_write(base, len) },
            Backing::Heap { .. } => Ok(()),
        }
    }

    unsafe fn residency(
        &self,
        base: NonNull<u8>,
        len: usize,
        status: &mut [u8],
    ) -> Result<(), OsCode> {
        let start = base.as_ptr() as usize;
        self.log.0.lock().unwrap().status_lens.push(status.len());
        self.record(Op::Residency, None, start, len)?;
        // One status byte per base page, whatever pages back the mapping, so
        // a caller that sizes the buffer by a larger unit is caught here
        // before the kernel would write past it.
        assert!(
            status.len() >= len.div_ceil(self.backing_page_size()?),
            "residency over {len} bytes needs a byte per base page, got {}",
            status.len()
        );
        if let Some(fake) = self.fake_residency.lock().unwrap().as_ref() {
            // Fake bytes are indexed by page within the queried mapping, so a
            // test can place a non-resident page in a later chunk.
            let first_page = self.page_within_mapping(start)?;
            for (index, slot) in status.iter_mut().enumerate() {
                *slot = fake[(first_page + index) % fake.len()];
            }
            return Ok(());
        }
        match self.backing {
            // SAFETY: forwarded unchanged from a caller holding the same guarantee.
            Backing::Linux(linux) => unsafe { linux.residency(base, len, status) },
            Backing::Heap { .. } => {
                status.fill(1);
                Ok(())
            }
        }
    }

    unsafe fn unmap(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode> {
        if let Some(observer) = self.before_unmap.lock().unwrap().as_ref() {
            observer();
        }
        // A refused release leaves the heap range live; the platform frees it
        // when it drops.
        self.record(Op::Unmap, None, base.as_ptr() as usize, len)?;
        // SAFETY: forwarded unchanged from a caller holding the same guarantee.
        unsafe { self.unmap_backing(base, len) }
    }

    fn topology(&self) -> Result<Topology, OsCode> {
        self.record(Op::Topology, None, 0, 0)?;
        match self.backing {
            Backing::Linux(linux) => linux.topology(),
            Backing::Heap { .. } => Ok(heap_topology()),
        }
    }

    unsafe fn bind(&self, base: NonNull<u8>, len: usize, nodes: &NodeMask) -> Result<(), OsCode> {
        self.log.0.lock().unwrap().masks.push((Op::Bind, *nodes));
        self.record(Op::Bind, None, base.as_ptr() as usize, len)?;
        match self.backing {
            // SAFETY: forwarded unchanged from a caller holding the same guarantee.
            Backing::Linux(linux) => unsafe { linux.bind(base, len, nodes) },
            Backing::Heap { .. } => Ok(()),
        }
    }

    unsafe fn check_bound(
        &self,
        base: NonNull<u8>,
        len: usize,
        nodes: &NodeMask,
    ) -> Result<(), OsCode> {
        let start = base.as_ptr() as usize;
        self.log
            .0
            .lock()
            .unwrap()
            .masks
            .push((Op::CheckBound, *nodes));
        self.record(Op::CheckBound, None, start, len)?;
        if let Some(fake) = self.fake_page_nodes.lock().unwrap().as_ref() {
            // The kernel refuses a range holding any page outside the mask;
            // the fake refuses for any answer that is not such a node, so
            // every faked defect reaches per-page attribution.
            let (mapping_base, unit) = self.containing_mapping(start)?;
            let first_page = (start - mapping_base) / unit;
            let pages = len / unit;
            let clean = (first_page..first_page + pages)
                .map(|page| fake[page % fake.len()])
                .all(|answer| usize::try_from(answer).is_ok_and(|node| nodes.contains(node)));
            return if clean {
                Ok(())
            } else {
                Err(OsCode(libc::EIO))
            };
        }
        match self.backing {
            // SAFETY: forwarded unchanged from a caller holding the same guarantee.
            Backing::Linux(linux) => unsafe { linux.check_bound(base, len, nodes) },
            // Heap pages answer node 0 below, so a mask without it refuses.
            Backing::Heap { .. } if nodes.contains(0) => Ok(()),
            Backing::Heap { .. } => Err(OsCode(libc::EIO)),
        }
    }

    unsafe fn page_node(&self, page: NonNull<u8>) -> Result<usize, OsCode> {
        let start = page.as_ptr() as usize;
        let (_, unit) = self.containing_mapping(start)?;
        self.record(Op::PageNode, None, start, unit)?;
        if let Some(fake) = self.fake_page_nodes.lock().unwrap().as_ref() {
            let answer = fake[self.page_within_mapping(start)? % fake.len()];
            return usize::try_from(answer).map_err(|_| OsCode(-answer));
        }
        match self.backing {
            // SAFETY: forwarded unchanged from a caller holding the same guarantee.
            Backing::Linux(linux) => unsafe { linux.page_node(page) },
            Backing::Heap { .. } => Ok(0),
        }
    }

    fn clock_resolution(&self) -> Result<u64, OsCode> {
        self.record(Op::ClockResolution, None, 0, 0)?;
        match self.backing {
            Backing::Linux(linux) => linux.clock_resolution(),
            Backing::Heap { .. } => Ok(1),
        }
    }

    /// The next queued sample, else the last one. The sample is a queued
    /// value, not a counter read, and the clock's mutex gives only its own
    /// acquire and release, so this platform does not supply the trait's
    /// ordering contract; tests place samples by queue order instead.
    fn now_ticks(&self) -> Option<u64> {
        let sample = {
            let mut clock = self.clock.lock().unwrap();
            clock.taken += 1;
            self.counted
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(sample) = clock.queue.pop_front() {
                clock.sticky = sample;
            }
            clock.sticky
        };
        if let Ok(Some(hook)) = IN_SAMPLE.try_with(std::cell::Cell::take) {
            hook();
        }
        sample
    }

    fn now_ticks_after_stores(&self) -> Option<u64> {
        self.clock.lock().unwrap().after_stores += 1;
        self.now_ticks()
    }

    fn cut(&self, phase: InitPhase, region: Region) -> Result<(), OsCode> {
        self.record(Op::Cut(phase), Some(region), 0, 0)
    }
}

impl super::Storage<TestPlatform> {
    /// Offers the tenure's suffix log one REMOVE record of a planted entry at `now` in nanoseconds, so a test reads
    /// the log's own verdict on an append: the LSN it took, or its refusal. `None` when the storage is closed or its
    /// capture mutex is busy or poisoned.
    pub(crate) fn probe_append(&self, now: u64) -> Option<Result<u64, super::SuffixRefusal>> {
        use super::recovery::delta::Cause;
        use super::recovery::delta_tests::{remove, wide};
        let record = remove(&wide(0, 8, 1), Cause::Invalidate);
        self.with_suffix(|log| log.append(now, &record)).ok()
    }
}

impl TestPlatform {
    /// Records the base of the mapping just logged.
    fn note_mapped(
        &self,
        base: NonNull<u8>,
        live: Option<LiveRange>,
    ) -> Result<NonNull<u8>, OsCode> {
        let mut log = self.log.0.lock().unwrap();
        if let Some(call) = log.calls.last_mut() {
            call.base = base.as_ptr() as usize;
        }
        log.live.extend(live);
        Ok(base)
    }

    /// A zeroed heap range of `len` bytes starting `skew` bytes past an
    /// address aligned to `align`, standing in for a fresh mapping.
    fn heap_map(&self, len: usize, align: usize, skew: usize) -> Result<NonNull<u8>, OsCode> {
        let size = len.checked_add(skew).ok_or(OsCode(libc::EINVAL))?;
        let aligned = Layout::from_size_align(size, align).map_err(|_| OsCode(libc::EINVAL))?;
        let padded = (aligned.size().checked_add(aligned.align())).ok_or(OsCode(libc::EINVAL))?;
        let layout = Layout::array::<u8>(padded).map_err(|_| OsCode(libc::EINVAL))?;
        // SAFETY: `align` is at least 1, so the layout of `size + align` bytes
        // has a non-zero size.
        let allocation =
            NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(OsCode(libc::ENOMEM))?;
        let address = allocation.as_ptr() as usize;
        let pad = address.next_multiple_of(align) - address;
        // SAFETY: `pad < align` and the allocation holds `size + align`
        // bytes, so the offset and the `len` bytes after it stay inside the
        // allocation.
        let base = unsafe { allocation.add(pad + skew) };
        self.note_mapped(
            base,
            Some(LiveRange {
                base: base.as_ptr() as usize,
                len,
                allocation: allocation.as_ptr() as usize,
                layout,
            }),
        )
    }

    /// # Safety
    ///
    /// As for [`Platform::unmap`].
    unsafe fn unmap_backing(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode> {
        match self.backing {
            // SAFETY: forwarded unchanged.
            Backing::Linux(linux) => unsafe { linux.unmap(base, len) },
            Backing::Heap { .. } => {
                let range = (base.as_ptr() as usize, len);
                let mut log = self.log.0.lock().unwrap();
                let position = log
                    .live
                    .iter()
                    .position(|live| (live.base, live.len) == range)
                    .expect("a heap unmap names a live range");
                let live = log.live.swap_remove(position);
                // The allocation starts `base - allocation` bytes before the
                // mapping, inside the same allocation, so the pointer keeps
                // the caller's provenance.
                let allocation = base.as_ptr().wrapping_sub(live.base - live.allocation);
                // SAFETY: `allocation` came from `alloc_zeroed` with this
                // layout and the caller guarantees no surviving reference.
                unsafe { dealloc(allocation, live.layout) };
                Ok(())
            }
        }
    }
}

impl Drop for TestPlatform {
    fn drop(&mut self) {
        for live in self.log.0.lock().unwrap().live.drain(..) {
            // SAFETY: the heap backing allocated this range with this layout
            // and nothing released it: an armed failure refused it or its
            // owner was dropped unreleased, and the owner is gone with this
            // platform. The integer round trip is test bookkeeping for a
            // pointer the backing itself produced.
            unsafe { dealloc(live.allocation as *mut u8, live.layout) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 4096;

    #[test]
    fn a_heap_mapping_is_zeroed_and_starts_at_its_alignment_plus_its_skew() {
        let platform = TestPlatform::heap(PAGE);
        let len = 3 * PAGE;
        for _ in 0..2 {
            let base = platform.map_inaccessible(len).unwrap();
            assert_eq!(base.as_ptr() as usize % PAGE, 0);
            // SAFETY: the heap backing hands out `len` readable and writable bytes that this test alone refers to.
            let bytes = unsafe { std::slice::from_raw_parts_mut(base.as_ptr(), len) };
            assert!(bytes.iter().all(|&byte| byte == 0));
            bytes.fill(0xA5);
            // SAFETY: `base` and `len` name the live mapping, and `bytes` is used no further.
            unsafe { platform.unmap(base, len) }.unwrap();
        }
        let huge = HugepageSize::TwoMiB;
        for skew in [0, PAGE] {
            if skew == PAGE {
                platform.misalign_hugepages();
            }
            let base = platform.map_hugepages(huge.bytes(), huge).unwrap();
            assert_eq!(base.as_ptr() as usize % huge.bytes(), skew);
            let last = huge.bytes() - 1;
            // SAFETY: the first and the last byte lie inside the live mapping of `huge.bytes()` bytes.
            let ends = unsafe { (base.as_ptr().read(), base.as_ptr().add(last).read()) };
            assert_eq!(ends, (0, 0));
            // SAFETY: `base` and its length name the live mapping.
            unsafe { platform.unmap(base, huge.bytes()) }.unwrap();
        }
    }
}
