//! Per-thread heap counters for allocation-free hot-path tests.
//!
//! [`CountingAlloc`] forwards every call to the system allocator and counts
//! `alloc`, `alloc_zeroed` and `realloc` as allocations and `dealloc` as
//! frees, on the calling thread, with the bytes each call requests. The
//! crate's tests install it as the global allocator.
//!
//! Per-thread counters prevent concurrent tests from affecting one another.
//! A hit path is allocation-free when the count around it is unchanged on
//! the thread that ran it. An uninstalled allocator leaves every count zero.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

/// A system allocator that counts allocations per thread.
pub struct CountingAlloc;

thread_local! {
    // Const-initialized with types that have no destructor, so the first
    // access neither allocates nor registers a TLS destructor on a target
    // whose thread locals are native (`#[thread_local]`). A target that
    // emulates them through OS keys boxes the value on first access, but
    // `std` takes that box from `System` directly, not from the global
    // allocator, so the count is not re-entered there either.
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static DEALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static REALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
    static DEALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
    static LIVE_BYTES: Cell<usize> = const { Cell::new(0) };
    static PEAK_BYTES: Cell<usize> = const { Cell::new(0) };
}

fn live(grown: usize, shrunk: usize) {
    LIVE_BYTES.with(|live| {
        let now = live.get().wrapping_add(grown).wrapping_sub(shrunk);
        live.set(now);
        PEAK_BYTES.with(|peak| peak.set(peak.get().max(now)));
    });
}

fn bump(bytes: usize) {
    ALLOCATIONS.with(|count| count.set(count.get() + 1));
    ALLOCATED_BYTES.with(|total| total.set(total.get().wrapping_add(bytes)));
}

/// Heap allocation calls (`alloc`, `alloc_zeroed`, `realloc`) made so far by
/// the current thread through [`CountingAlloc`]; zero if it is not the
/// global allocator. A call counts whether or not it succeeds, and a
/// `realloc` counts here and not in [`deallocations`].
pub fn allocations() -> usize {
    ALLOCATIONS.with(Cell::get)
}

/// Heap `dealloc` calls made so far by the current thread through
/// [`CountingAlloc`]; zero if it is not the global allocator.
pub fn deallocations() -> usize {
    DEALLOCATIONS.with(Cell::get)
}

/// Reallocations, also counted as allocations.
pub fn reallocations() -> usize {
    REALLOCATIONS.with(Cell::get)
}

/// Bytes the current thread's allocations requested so far, a `realloc`
/// counting its new size; the count wraps at `usize::MAX`.
pub fn allocated_bytes() -> usize {
    ALLOCATED_BYTES.with(Cell::get)
}

/// Bytes the current thread's `dealloc` calls freed so far; the count wraps
/// at `usize::MAX`.
pub fn deallocated_bytes() -> usize {
    DEALLOCATED_BYTES.with(Cell::get)
}

/// Net bytes this thread's successful allocations and reallocations took
/// less those its frees returned, a `realloc` replacing its old size with its
/// new one; a block freed on another thread counts there. The count wraps at
/// `usize::MAX`, so two readings compare by `wrapping_sub`.
pub fn live_bytes() -> usize {
    LIVE_BYTES.with(Cell::get)
}

/// The most [`live_bytes`] reached on the current thread since the last
/// [`reset_peak`], or since the thread began. Live bytes compare as
/// unsigned values, so a thread that frees another thread's allocations
/// reads a wrapped peak; the measuring thread calls `reset_peak` first.
pub fn peak_bytes() -> usize {
    PEAK_BYTES.with(Cell::get)
}

/// Restarts [`peak_bytes`] at the current live bytes.
pub fn reset_peak() {
    PEAK_BYTES.with(|peak| peak.set(live_bytes()));
}

/// Runs `work` and leaves the current thread's allocation count as it was
/// before, so a test fixture standing in for a device keeps its own
/// allocations out of a measured path; the byte counters keep what `work`
/// allocates and frees.
#[cfg(test)]
pub(crate) fn unmeasured<R>(work: impl FnOnce() -> R) -> R {
    let before = allocations();
    let result = work();
    ALLOCATIONS.with(|count| count.set(before));
    result
}

/// Sets every counter of the current thread to zero. A forked child
/// inherits its parent's counts; resetting them before its first measured
/// window keeps the parent's prefix out of the child's readings.
#[cfg(test)]
pub(crate) fn rebaseline() {
    for counter in [
        &ALLOCATIONS,
        &DEALLOCATIONS,
        &REALLOCATIONS,
        &ALLOCATED_BYTES,
        &DEALLOCATED_BYTES,
        &LIVE_BYTES,
    ] {
        counter.with(|count| count.set(0));
    }
}

/// Runs `work` against `budget` and returns its result with the bytes it
/// charged and the bytes it allocated on this thread.
#[cfg(test)]
pub(crate) fn charged<R>(
    budget: &mut crate::storage::EngineBudget,
    work: impl FnOnce(&mut crate::storage::EngineBudget) -> R,
) -> (R, usize, usize) {
    let (used, bytes) = (budget.used(), allocated_bytes());
    let result = work(budget);
    (result, budget.used() - used, allocated_bytes() - bytes)
}

#[cfg(test)]
#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

// SAFETY: every method forwards its exact arguments to `System` and returns
// its result unchanged; the counter updates touch only thread-local `Cell`s
// and never allocate. The allocator's contract is therefore `System`'s.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump(layout.size());
        let block = unsafe { System.alloc(layout) };
        if !block.is_null() {
            live(layout.size(), 0);
        }
        block
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        bump(layout.size());
        let block = unsafe { System.alloc_zeroed(layout) };
        if !block.is_null() {
            live(layout.size(), 0);
        }
        block
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        bump(new_size);
        REALLOCATIONS.with(|count| count.set(count.get() + 1));
        let block = unsafe { System.realloc(ptr, layout, new_size) };
        if !block.is_null() {
            live(new_size, layout.size());
        }
        block
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOCATIONS.with(|count| count.set(count.get() + 1));
        DEALLOCATED_BYTES.with(|total| total.set(total.get().wrapping_add(layout.size())));
        live(0, layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn heap_allocation_advances_the_counter() {
        let before = super::allocations();
        // An optimized build may elide a heap allocation whose box escapes nowhere.
        let boxed = std::hint::black_box(Box::new(0u8));
        assert!(super::allocations() > before);
        drop(boxed);
    }

    #[test]
    fn a_free_advances_the_deallocation_counter_and_not_the_allocation_counter() {
        let boxed = std::hint::black_box(Box::new(0u8));
        let (allocated, freed) = (super::allocations(), super::deallocations());
        drop(boxed);
        assert_eq!(super::allocations(), allocated);
        assert_eq!(super::deallocations(), freed + 1);
    }

    #[test]
    fn a_spawned_thread_counts_its_own_allocations_and_frees() {
        std::thread::spawn(|| {
            let (allocated, freed) = (super::allocations(), super::deallocations());
            drop(std::hint::black_box(Box::new([0u8; 64])));
            assert!(super::allocations() > allocated && super::deallocations() > freed);
        })
        .join()
        .expect("the counting thread");
    }

    #[test]
    fn byte_counters_add_each_layout_s_size() {
        let (allocated, freed) = (super::allocated_bytes(), super::deallocated_bytes());
        let boxed = std::hint::black_box(Box::new([0u8; 40]));
        assert_eq!(super::allocated_bytes() - allocated, 40);
        drop(boxed);
        assert_eq!(super::deallocated_bytes() - freed, 40);
    }

    #[test]
    fn live_bytes_follow_allocations_reallocations_and_frees() {
        let before = super::live_bytes();
        let boxed = std::hint::black_box(Box::new([0u8; 40]));
        assert_eq!(super::live_bytes().wrapping_sub(before), 40);
        let mut grown: Vec<u8> = Vec::with_capacity(8);
        grown.reserve_exact(64);
        let grown = std::hint::black_box(grown);
        assert_eq!(
            super::live_bytes().wrapping_sub(before),
            40 + grown.capacity()
        );
        drop((boxed, grown));
        assert_eq!(super::live_bytes(), before);
    }
}
