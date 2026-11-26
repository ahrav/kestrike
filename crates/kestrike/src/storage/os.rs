//! Tests inject failing kernel operations through the [`Platform`] trait;
//! production initialization and finalization run the same code against the
//! 64-bit Linux binding.
//!
//! Every method that takes a base and length is `unsafe` because the kernel
//! trusts those arguments: the caller must pass a range inside a mapping this
//! platform returned and not yet unmapped, page aligned, and for mapping-wide
//! operations (advice, binding, protection, release) its original base and
//! full extent. Each production caller takes its range from a live
//! [`Mapping`](super::mapping::Mapping): the initialization transaction in
//! `init`, the buffer arena's bring-up in `device::arena`, `verify_chunk` in
//! `placement`, which both run, and `Mapping::release`.
//!
//! The platform also supplies the engine's live clock: one `CLOCK_MONOTONIC`
//! sample as nanoseconds, the clock `std::time::Instant` reads on Linux,
//! served through the vDSO on the assumed targets. It counts elapsed time as
//! the host reports it, frequency-adjusted and not counting suspend; its
//! resolution is read once at initialization and recorded in the root
//! descriptor. Nothing here caches, restarts or converts a deadline: a
//! caller that must expire across suspend gates or invalidates on resume.
//!
//! Kernel requirement: population requires `MADV_POPULATE_WRITE` (Linux
//! 5.14); an older kernel's `EINVAL` fails initialization. Placement needs
//! `CONFIG_NUMA`: it calls `mbind` and `get_mempolicy` directly through
//! `libc::syscall`,
//! since the C library exposes no wrappers for them, and reads node topology
//! from sysfs into a stack buffer. A kernel without NUMA support has neither
//! the sysfs node directory nor the system calls, and initialization fails
//! with the topology error carrying `ENOENT`.
//!
//! Process requirement: the default seccomp profiles of Docker and containerd
//! allow `mbind` and `get_mempolicy` only to a process holding
//! `CAP_SYS_NICE`, which is not in the default capability set; without it
//! both return `EPERM` and initialization fails with the topology error
//! carrying `EPERM`. Run the process with `CAP_SYS_NICE` or a profile that
//! allows the two calls. Placement never calls `move_pages`, which those
//! profiles deny regardless of capabilities.

use std::ffi::CStr;
use std::ptr::NonNull;

use super::init::InitPhase;
use super::mapping::Region;
use super::placement::{MAX_NODES, NodeMask, Topology};

/// An `errno` value from a failed kernel call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsCode(pub i32);

/// A hugetlb page size the kernel can back a mapping with.
/// The global free pool of this size is checked at [`Platform::map_hugepages`]; a node with no free page of this size fails at population.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HugepageSize {
    TwoMiB,
    OneGiB,
}

impl HugepageSize {
    pub const fn bytes(self) -> usize {
        match self {
            Self::TwoMiB => 2 << 20,
            Self::OneGiB => 1 << 30,
        }
    }
}

/// Storage initialization and finalization use these kernel operations.
/// Lookup, publication, expiry and PUT deadline checks sample the platform's
/// monotonic clock.
///
/// Implementations must be faithful: a returned `Ok` from
/// [`populate_write`](Self::populate_write) is the population evidence the
/// transaction relies on, and [`residency`](Self::residency) must report the
/// kernel's view, not a cached one.
///
/// # Safety
///
/// A shared storage shares its platform (`Sync`), so the methods may run concurrently on several threads, and every
/// result requirement below holds for each concurrent call.
///
/// Callers dereference and unmap memory based on these results. A
/// [`map_inaccessible`](Self::map_inaccessible) result must be live,
/// page-aligned, private, exactly `len` bytes long, zero-filled, and disjoint
/// from every other unreleased mapping this implementation handed out. A
/// [`map_hugepages`](Self::map_hugepages) result must meet the same
/// requirements with alignment to the requested hugepage size.
///
/// A safe `impl` does not compile:
///
/// ```compile_fail,E0200
/// use std::ptr::NonNull;
/// use kestrike::storage::{HugepageSize, NodeMask, OsCode, Platform, Topology};
///
/// struct Bogus;
///
/// impl Platform for Bogus {
///     fn page_size(&self) -> Result<usize, OsCode> {
///         Ok(4096)
///     }
///     fn map_inaccessible(&self, _len: usize) -> Result<NonNull<u8>, OsCode> {
///         Ok(NonNull::dangling())
///     }
///     fn map_hugepages(&self, _: usize, _: HugepageSize) -> Result<NonNull<u8>, OsCode> {
///         Ok(NonNull::dangling())
///     }
///     unsafe fn advise_huge_pages(&self, _: NonNull<u8>, _: usize) -> Result<(), OsCode> {
///         Ok(())
///     }
///     unsafe fn advise_normal_pages(&self, _: NonNull<u8>, _: usize) -> Result<(), OsCode> {
///         Ok(())
///     }
///     unsafe fn protect_read_write(&self, _: NonNull<u8>, _: usize) -> Result<(), OsCode> {
///         Ok(())
///     }
///     unsafe fn populate_write(&self, _: NonNull<u8>, _: usize) -> Result<(), OsCode> {
///         Ok(())
///     }
///     unsafe fn residency(&self, _: NonNull<u8>, _: usize, s: &mut [u8]) -> Result<(), OsCode> {
///         s.fill(1);
///         Ok(())
///     }
///     unsafe fn unmap(&self, _: NonNull<u8>, _: usize) -> Result<(), OsCode> {
///         Ok(())
///     }
///     fn topology(&self) -> Result<Topology, OsCode> {
///         Ok(Topology {
///             possible: NodeMask::default(),
///             has_memory: NodeMask::default(),
///             allowed: NodeMask::default(),
///         })
///     }
///     unsafe fn bind(&self, _: NonNull<u8>, _: usize, _: &NodeMask) -> Result<(), OsCode> {
///         Ok(())
///     }
///     unsafe fn check_bound(&self, _: NonNull<u8>, _: usize, _: &NodeMask) -> Result<(), OsCode> {
///         Ok(())
///     }
///     unsafe fn page_node(&self, _: NonNull<u8>) -> Result<usize, OsCode> {
///         Ok(0)
///     }
///     fn clock_resolution(&self) -> Result<u64, OsCode> {
///         Ok(1)
///     }
///     fn now_ticks(&self) -> Option<u64> {
///         Some(0)
///     }
/// }
/// ```
///
/// The same signatures under `unsafe impl` compile:
///
/// ```
/// use std::ptr::NonNull;
/// use kestrike::storage::{HugepageSize, NodeMask, OsCode, Platform, Topology};
///
/// struct Bogus;
///
/// // SAFETY: never called; the block checks signatures only.
/// unsafe impl Platform for Bogus {
///     fn page_size(&self) -> Result<usize, OsCode> {
///         Ok(4096)
///     }
///     fn map_inaccessible(&self, _len: usize) -> Result<NonNull<u8>, OsCode> {
///         Ok(NonNull::dangling())
///     }
///     fn map_hugepages(&self, _: usize, _: HugepageSize) -> Result<NonNull<u8>, OsCode> {
///         Ok(NonNull::dangling())
///     }
///     unsafe fn advise_huge_pages(&self, _: NonNull<u8>, _: usize) -> Result<(), OsCode> {
///         Ok(())
///     }
///     unsafe fn advise_normal_pages(&self, _: NonNull<u8>, _: usize) -> Result<(), OsCode> {
///         Ok(())
///     }
///     unsafe fn protect_read_write(&self, _: NonNull<u8>, _: usize) -> Result<(), OsCode> {
///         Ok(())
///     }
///     unsafe fn populate_write(&self, _: NonNull<u8>, _: usize) -> Result<(), OsCode> {
///         Ok(())
///     }
///     unsafe fn residency(&self, _: NonNull<u8>, _: usize, s: &mut [u8]) -> Result<(), OsCode> {
///         s.fill(1);
///         Ok(())
///     }
///     unsafe fn unmap(&self, _: NonNull<u8>, _: usize) -> Result<(), OsCode> {
///         Ok(())
///     }
///     fn topology(&self) -> Result<Topology, OsCode> {
///         Ok(Topology {
///             possible: NodeMask::default(),
///             has_memory: NodeMask::default(),
///             allowed: NodeMask::default(),
///         })
///     }
///     unsafe fn bind(&self, _: NonNull<u8>, _: usize, _: &NodeMask) -> Result<(), OsCode> {
///         Ok(())
///     }
///     unsafe fn check_bound(&self, _: NonNull<u8>, _: usize, _: &NodeMask) -> Result<(), OsCode> {
///         Ok(())
///     }
///     unsafe fn page_node(&self, _: NonNull<u8>) -> Result<usize, OsCode> {
///         Ok(0)
///     }
///     fn clock_resolution(&self) -> Result<u64, OsCode> {
///         Ok(1)
///     }
///     fn now_ticks(&self) -> Option<u64> {
///         Some(0)
///     }
/// }
/// ```
pub unsafe trait Platform: Sync {
    /// Runtime page size in bytes.
    ///
    /// # Errors
    ///
    /// The kernel's code if the size cannot be queried.
    fn page_size(&self) -> Result<usize, OsCode>;

    /// Acquires `len` bytes of private anonymous memory with no access
    /// permissions and no populated pages. `len` is a positive page multiple.
    /// Every byte reads as zero once access is enabled, until the caller
    /// writes that byte. The zero fill supplies the initial value of each
    /// element whose store `Field::init` skips.
    ///
    /// # Errors
    ///
    /// The kernel's code if the mapping cannot be created.
    fn map_inaccessible(&self, len: usize) -> Result<NonNull<u8>, OsCode>;

    /// Maps `len` bytes of private anonymous hugetlb memory with no access
    /// permissions. `len` is a positive multiple of `size`, the hugepage size
    /// requested; no normal page ever substitutes for a hugepage.
    ///
    /// # Errors
    ///
    /// `ENOMEM` when the free hugepage pool cannot cover `len`, `EINVAL`
    /// when `size` is not a configured hugepage size, or another kernel code.
    fn map_hugepages(&self, len: usize, size: HugepageSize) -> Result<NonNull<u8>, OsCode>;

    /// Requests transparent huge pages for the faults that populate the
    /// mapping. An EINVAL result is accepted when access observes ENOENT
    /// for the transparent huge page control path. Any other advice failure
    /// is an error. The kernel backs a
    /// populating fault with a PMD-sized huge page when that size's
    /// transparent huge page control is `always` or `madvise` (directly or
    /// through `inherit`), the process permits transparent huge pages, the
    /// aligned huge-page range around the fault lies inside the mapping, and
    /// it can allocate a huge page on a node of the mapping's bound mask; every
    /// other fault takes base pages, or a smaller transparent huge page size
    /// the system enables. When the `defrag` control is `always`, `madvise`
    /// or `defer+madvise`, a huge-page fault in the advised mapping can run
    /// direct reclaim and compaction before it falls back to base pages.
    ///
    /// # Safety
    ///
    /// `base` and `len` are the original base and full extent of a live
    /// mapping from [`map_inaccessible`](Self::map_inaccessible).
    ///
    /// # Errors
    ///
    /// The kernel's code on an unexplained failure.
    unsafe fn advise_huge_pages(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode>;

    /// Requests normal pages for any later fault in the mapping and disables
    /// huge-page collapse of its normal pages. An EINVAL result is accepted
    /// when access observes ENOENT for the transparent huge page control
    /// path. Huge pages already backing the mapping stay in place. Any other
    /// advice failure is an error.
    ///
    /// # Safety
    ///
    /// `base` and `len` are the original base and full extent of a live
    /// mapping from [`map_inaccessible`](Self::map_inaccessible).
    ///
    /// # Errors
    ///
    /// The kernel's code on an unexplained failure.
    unsafe fn advise_normal_pages(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode>;

    /// Enables read and write access.
    ///
    /// # Safety
    ///
    /// `base` and `len` are the original base and full extent of a live
    /// mapping from [`map_inaccessible`](Self::map_inaccessible) or
    /// [`map_hugepages`](Self::map_hugepages).
    ///
    /// # Errors
    ///
    /// The kernel's code if permissions cannot be changed.
    unsafe fn protect_read_write(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode>;

    /// Populates every page of the range for writing. Success means every page
    /// in the range was faulted in; failure may leave a prefix populated. The
    /// kernel holds the address-space lock for the whole call, so callers
    /// bound `len`.
    ///
    /// # Safety
    ///
    /// `base..base + len` is a page-aligned range inside a live, readable and
    /// writable mapping from [`map_inaccessible`](Self::map_inaccessible), or
    /// a range of whole hugepages inside one from
    /// [`map_hugepages`](Self::map_hugepages).
    ///
    /// # Errors
    ///
    /// The kernel's code, including `EINVAL` when population advice is not
    /// supported.
    unsafe fn populate_write(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode>;

    /// Writes one residency byte per page of the range into `status`, whose
    /// low bit is set for a resident page. `status.len()` is at least the
    /// count of base pages ([`page_size`](Self::page_size)) in the range,
    /// whatever page size backs the mapping.
    /// The query never faults or migrates pages.
    /// It is a point-in-time view: a page populated moments ago can already
    /// have been reclaimed under memory pressure, and initialization treats
    /// that as failure rather than promising residence.
    ///
    /// # Safety
    ///
    /// `base..base + len` is a page-aligned range inside a live mapping from
    /// [`map_inaccessible`](Self::map_inaccessible) or
    /// [`map_hugepages`](Self::map_hugepages).
    ///
    /// # Errors
    ///
    /// The kernel's code if residency cannot be queried.
    unsafe fn residency(
        &self,
        base: NonNull<u8>,
        len: usize,
        status: &mut [u8],
    ) -> Result<(), OsCode>;

    /// Releases the whole mapping.
    ///
    /// # Safety
    ///
    /// As for [`protect_read_write`](Self::protect_read_write), and no
    /// reference into the mapping survives the call.
    ///
    /// # Errors
    ///
    /// The kernel's code if the mapping could not be released; the caller
    /// treats the mapping as still owned.
    unsafe fn unmap(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode>;

    /// Which nodes exist, have memory and are allowed to this task.
    ///
    /// # Errors
    ///
    /// The kernel's code if any part of the topology cannot be read; an
    /// unreadable topology never defaults to "everything allowed".
    fn topology(&self) -> Result<Topology, OsCode>;

    /// Binds the mapping's future pages strictly to `nodes` before any of
    /// them is touched. Allocation outside the mask is refused by the kernel,
    /// never redirected to another node.
    ///
    /// # Safety
    ///
    /// As for [`protect_read_write`](Self::protect_read_write).
    ///
    /// # Errors
    ///
    /// The kernel's code if the policy cannot be installed.
    unsafe fn bind(&self, base: NonNull<u8>, len: usize, nodes: &NodeMask) -> Result<(), OsCode>;

    /// Checks that every resident page of the range lies on a node in
    /// `nodes`, the mask already bound to it. One kernel walk over the range;
    /// moves nothing and leaves the bound policy unchanged.
    ///
    /// # Safety
    ///
    /// `base..base + len` is a page-aligned range inside a live mapping.
    ///
    /// # Errors
    ///
    /// `EIO` if some page present during the walk lies outside `nodes`, or,
    /// from Linux 6.7, if some page's migration is in flight; kernels before
    /// 6.7 skip a page in flight. Every kernel skips a page not present when
    /// the walk reaches it, so success covers the pages present at that
    /// moment, not the whole range. The kernel's code if the check itself
    /// fails.
    unsafe fn check_bound(
        &self,
        base: NonNull<u8>,
        len: usize,
        nodes: &NodeMask,
    ) -> Result<(), OsCode>;

    /// The node holding the page at `page`, after waiting for any migration
    /// of that page in flight. Used for every page of a chunk the range check
    /// refused. Moves nothing; a page that was reclaimed since population is
    /// faulted back in to be answered.
    ///
    /// # Safety
    ///
    /// `page` is a page start inside a live, readable mapping.
    ///
    /// # Errors
    ///
    /// The kernel's code if the page cannot be answered.
    unsafe fn page_node(&self, page: NonNull<u8>) -> Result<usize, OsCode>;

    /// Resolution of the monotonic clock in nanoseconds, read once at
    /// initialization and recorded in the root descriptor.
    ///
    /// # Errors
    ///
    /// The kernel's code if the clock cannot be queried; initialization then
    /// fails, since a lookup could never take a witness.
    fn clock_resolution(&self) -> Result<u64, OsCode>;

    /// One live sample of the monotonic clock as nanoseconds:
    /// `seconds * 1_000_000_000 + nanoseconds` with checked arithmetic.
    /// `None` when the sample fails or the sum does not fit, which the caller
    /// reports as an unavailable clock; nothing is cached or retried.
    /// A publisher calls this while holding a shard gate with the sequence odd, so implementations must not block, allocate, or call back into storage.
    ///
    /// Loads sequenced after the call start only after the counter read
    /// completes.
    fn now_ticks(&self) -> Option<u64>;

    /// Stores sequenced before the call complete before the counter read
    /// starts.
    #[inline]
    fn now_ticks_after_stores(&self) -> Option<u64> {
        serialize_before_sample();
        self.now_ticks()
    }

    /// Fault-injection point for phases that are not kernel calls (control
    /// initialization, transfer). The production platform always succeeds; a
    /// test platform may refuse to exercise rollback at that cut.
    ///
    /// # Errors
    ///
    /// Only from an injecting implementation.
    fn cut(&self, _phase: InitPhase, _region: Region) -> Result<(), OsCode> {
        Ok(())
    }
}

/// The 64-bit Linux binding.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxPlatform;

/// Completes every earlier store before the clock call starts. On x86-64,
/// `mfence` makes the stores globally visible and `lfence` holds the call
/// until the `mfence` completes; that second step needs `lfence` to be
/// dispatch serializing, as it is on Intel and on AMD processors that report
/// `LFenceAlwaysSerializing` or have the MSR bit set. On AArch64, `dsb sy`
/// waits until the stores complete in the full system domain and `isb`
/// starts the call after it. Under Miri and on other targets the body is
/// empty. The assembly reads and writes memory as far as the compiler
/// knows, so no access moves across it either.
#[inline(always)]
fn serialize_before_sample() {
    // SAFETY: the instructions take no operands, touch no register and only
    // order memory and execution.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    unsafe {
        core::arch::asm!("mfence", "lfence", options(nostack, preserves_flags))
    };
    // SAFETY: as above.
    #[cfg(all(target_arch = "aarch64", not(miri)))]
    unsafe {
        core::arch::asm!("dsb sy", "isb", options(nostack, preserves_flags))
    };
}

/// Holds later instructions behind the clock call. On x86-64, `lfence`,
/// dispatch serializing under the condition above, starts no later
/// instruction, loads included, until the call and its counter read
/// complete. On AArch64, `isb` is a context synchronization event, so later
/// instructions are fetched after the call returns; the order of the counter
/// read itself before later loads comes from the vDSO, whose counter read
/// feeds an address dependency and the read barrier of its seqcount retry,
/// and on the system-call path from the exception return, and is assumed
/// there rather than proved by the `isb`. Under Miri and on other targets
/// the body is empty.
#[inline(always)]
fn serialize_after_sample() {
    // SAFETY: as for `serialize_before_sample`.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    unsafe {
        core::arch::asm!("lfence", options(nostack, preserves_flags))
    };
    // SAFETY: as above.
    #[cfg(all(target_arch = "aarch64", not(miri)))]
    unsafe {
        core::arch::asm!("isb", options(nostack, preserves_flags))
    };
}

/// On x86-64 and AArch64, orders this CPU's earlier loads before its later
/// loads and stores. On AArch64 outside Miri, `dmb ishld` orders the loads this CPU issued before
/// the barrier in program order, at any exception level, before its loads
/// and stores after the barrier in the inner-shareable domain. The assembly
/// keeps the default memory model: the compiler treats it as reading and
/// writing memory and as having side effects, which constrains compiler
/// reordering around it and keeps it in the program. On x86-64 the body is
/// empty: the memory model orders earlier loads before later loads and
/// stores, and compiler order comes from the caller, for example from calls
/// the compiler cannot see into. Under Miri and on other targets the body is
/// empty.
#[inline(always)]
pub(crate) fn order_loads() {
    // SAFETY: the instruction takes no operands, touches no register and only
    // orders memory accesses.
    #[cfg(all(target_arch = "aarch64", not(miri)))]
    unsafe {
        core::arch::asm!("dmb ishld", options(nostack, preserves_flags))
    };
}

#[cfg(all(test, target_os = "linux"))]
mod fault_tests;

#[inline(always)]
fn linux_open(path: &CStr, flags: i32) -> i32 {
    #[cfg(all(test, target_os = "linux"))]
    if let Some(result) = fault_tests::open(path, flags) {
        return result;
    }
    // SAFETY: `CStr` guarantees a NUL-terminated path.
    unsafe { libc::open(path.as_ptr(), flags) }
}

#[inline(always)]
fn linux_read(fd: i32, buffer: &mut [u8]) -> isize {
    #[cfg(all(test, target_os = "linux"))]
    if let Some(result) = fault_tests::read(fd, buffer) {
        return result;
    }
    // SAFETY: the slice is writable for its length; callers own the open fd.
    unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) }
}

#[inline(always)]
fn linux_close(fd: i32) -> i32 {
    #[cfg(all(test, target_os = "linux"))]
    if let Some(result) = fault_tests::close(fd) {
        return result;
    }
    // SAFETY: callers own this fd and make one close attempt.
    unsafe { libc::close(fd) }
}

#[inline(always)]
unsafe fn linux_advice(base: NonNull<u8>, len: usize, advice: i32) -> i32 {
    #[cfg(all(test, target_os = "linux"))]
    if let Some(result) = fault_tests::advice(base, len, advice) {
        return result;
    }
    // SAFETY: the caller supplies a live mapping's base and extent.
    unsafe { libc::madvise(base.as_ptr().cast(), len, advice) }
}

#[inline(always)]
fn linux_access(path: &CStr, mode: i32) -> i32 {
    #[cfg(all(test, target_os = "linux"))]
    if let Some(result) = fault_tests::access(path, mode) {
        return result;
    }
    // SAFETY: `CStr` guarantees a NUL-terminated path.
    unsafe { libc::access(path.as_ptr(), mode) }
}

fn last_os_code() -> OsCode {
    OsCode(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

/// Applies transparent huge page advice. An `EINVAL` result is accepted when
/// access observes `ENOENT` for the control path. Advice success describes
/// kernel acceptance; page placement requires its own observation.
///
/// # Safety
///
/// A live mapping spans `base..base + len`.
unsafe fn advise_page_size(
    base: NonNull<u8>,
    len: usize,
    advice: libc::c_int,
) -> Result<(), OsCode> {
    // SAFETY: the caller guarantees a live mapping at `base..base + len`.
    let result = unsafe { linux_advice(base, len, advice) };
    if result == 0 {
        return Ok(());
    }
    let code = last_os_code();
    let control_missing = code == OsCode(libc::EINVAL)
        && linux_access(THP_CONTROL_PATH, libc::F_OK) != 0
        && last_os_code() == OsCode(libc::ENOENT);
    if control_missing { Ok(()) } else { Err(code) }
}

/// Control path whose observed absence permits the `EINVAL` fallback.
const THP_CONTROL_PATH: &CStr = c"/sys/kernel/mm/transparent_hugepage/enabled";

const POSSIBLE_NODES_PATH: &CStr = c"/sys/devices/system/node/possible";
const MEMORY_NODES_PATH: &CStr = c"/sys/devices/system/node/has_memory";

/// `get_mempolicy` flag: return the nodes this task may allocate from.
const MPOL_F_MEMS_ALLOWED: libc::c_long = 1 << 2;

/// `get_mempolicy` flags: report the node of the page at the given address
/// instead of a policy.
const MPOL_F_NODE: libc::c_long = 1 << 0;
const MPOL_F_ADDR: libc::c_long = 1 << 1;

/// `mbind` flag: refuse with `EIO` if a resident page in the range is on a
/// node outside the mask or is being migrated. Without a move flag the walk
/// stops at the first such page and installs nothing.
const MPOL_MF_STRICT: libc::c_long = 1 << 0;

/// `maxnode` argument for the mask syscalls. The kernel reads `maxnode - 1`
/// bits, so one more than the mask width covers every bit of the mask.
const MAXNODE: libc::c_long = MAX_NODES as libc::c_long + 1;

/// Largest sysfs node list accepted; sysfs attributes never exceed one page.
const NODE_LIST_BUFFER: usize = 4096;

/// Reads a sysfs node list such as `0-3,5` into a mask without allocating.
/// A list that does not fit the buffer is refused rather than truncated.
fn read_node_list(path: &CStr) -> Result<NodeMask, OsCode> {
    let fd = linux_open(path, libc::O_RDONLY | libc::O_CLOEXEC);
    if fd < 0 {
        return Err(last_os_code());
    }
    let mut buffer = [0u8; NODE_LIST_BUFFER + 1];
    let mut filled = 0;
    let outcome = loop {
        let read = linux_read(fd, &mut buffer[filled..]);
        match usize::try_from(read) {
            Err(_) => break Err(last_os_code()),
            Ok(0) => break Ok(filled),
            Ok(count) => {
                filled += count;
                if filled > NODE_LIST_BUFFER {
                    break Err(OsCode(libc::EINVAL));
                }
            }
        }
    };
    #[cfg(all(test, target_os = "linux"))]
    fault_tests::before_close(fd, &buffer[..filled]);
    linux_close(fd);
    let len = outcome?;
    parse_node_list(&buffer[..len]).ok_or(OsCode(libc::EINVAL))
}

/// Parses `a-b,c,...` with an optional trailing newline; `None` on any
/// malformed byte or a node outside the mask.
fn parse_node_list(text: &[u8]) -> Option<NodeMask> {
    let mut mask = NodeMask::default();
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    if text.is_empty() {
        return Some(mask);
    }
    for range in text.split(|byte| *byte == b',') {
        let mut bounds = range.splitn(2, |byte| *byte == b'-');
        let first = parse_node(bounds.next()?)?;
        let last = match bounds.next() {
            Some(last) => parse_node(last)?,
            None => first,
        };
        if last < first {
            return None;
        }
        for node in first..=last {
            if !mask.insert(node) {
                return None;
            }
        }
    }
    Some(mask)
}

fn parse_node(digits: &[u8]) -> Option<usize> {
    if digits.is_empty() || digits.len() > 5 {
        return None;
    }
    digits.iter().try_fold(0usize, |acc, byte| {
        byte.is_ascii_digit()
            .then(|| acc * 10 + usize::from(byte - b'0'))
    })
}

/// One sample of `clock` in nanoseconds, or `None` when the call fails or the value does not fit `u64`.
#[inline]
#[expect(
    clippy::disallowed_methods,
    reason = "this host read backs Platform::now_ticks, PhysicalClock and ServingClock"
)]
pub(crate) fn clock_ticks(clock: libc::clockid_t) -> Option<u64> {
    let mut spec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `spec` is a live, writable `timespec`; `clock_gettime` writes only through that pointer and refuses an unknown `clock` with `EINVAL`, so every `clock` value is sound.
    if unsafe { libc::clock_gettime(clock, &mut spec) } != 0 {
        return None;
    }
    ticks_of(&spec)
}

/// `seconds * 1_000_000_000 + nanoseconds` of a kernel time value, or `None`
/// when a field is negative or the sum does not fit `u64`.
fn ticks_of(spec: &libc::timespec) -> Option<u64> {
    let seconds = u64::try_from(spec.tv_sec).ok()?;
    let nanoseconds = u64::try_from(spec.tv_nsec).ok()?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanoseconds)
}

/// Reads into `bytes` from offset `at` of `file` with one `pread64` system
/// call; the byte count, or `None` when the call fails or `at` exceeds
/// `i64::MAX`. The call goes through `libc::syscall` because glibc's `pread`
/// is a thread cancellation point and wraps its system call in per-call
/// cancellation bookkeeping; `libc::syscall` invokes the kernel directly.
#[inline]
pub(crate) fn read_at(file: &std::fs::File, bytes: &mut [u8], at: u64) -> Option<usize> {
    let at = libc::c_long::try_from(at).ok()?;
    // SAFETY: `bytes` is writable for its length and the kernel writes at
    // most that many bytes through its pointer; `file` keeps the descriptor
    // open for the call. Every argument is passed at register width.
    let read = unsafe {
        libc::syscall(
            libc::SYS_pread64,
            libc::c_long::from(std::os::fd::AsRawFd::as_raw_fd(file)),
            bytes.as_mut_ptr(),
            bytes.len(),
            at,
        )
    };
    usize::try_from(read).ok()
}

/// A fresh private anonymous mapping of `len` bytes with no access, with
/// `flags` added to `MAP_PRIVATE | MAP_ANONYMOUS`.
/// `flags` selects backing pages only and never holds `MAP_FIXED`, so the kernel never replaces an existing mapping.
fn map_anonymous(len: usize, flags: libc::c_int) -> Result<NonNull<u8>, OsCode> {
    // SAFETY: an anonymous private mapping with a null hint, no file descriptor and no `MAP_FIXED` has no memory preconditions.
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | flags,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return Err(last_os_code());
    }
    NonNull::new(base.cast::<u8>()).ok_or(OsCode(0))
}

/// `mbind(base, len, MPOL_BIND, nodes, flags)`.
///
/// # Safety
///
/// `base..base + len` is a live mapping.
unsafe fn mbind(
    base: NonNull<u8>,
    len: usize,
    nodes: &NodeMask,
    flags: libc::c_long,
) -> Result<(), OsCode> {
    // SAFETY: the caller guarantees a live mapping at `base..base + len`;
    // the mask buffer holds `MAX_NODES` bits, one fewer than `MAXNODE`.
    // Every argument is passed at register width.
    let result = unsafe {
        libc::syscall(
            libc::SYS_mbind,
            base.as_ptr(),
            len,
            libc::c_long::from(libc::MPOL_BIND),
            nodes.words().as_ptr(),
            MAXNODE,
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(last_os_code())
    }
}

// SAFETY: every method passes its arguments to the kernel unchanged and
// reports the kernel's own result; `mmap` yields a fresh page-aligned private
// mapping of exactly `len` bytes, and `munmap` releases exactly its range.
// The kernel zero-fills an anonymous mapping, hugetlb pages included.
// A hugetlb mapping begins on a boundary of its page size.
unsafe impl Platform for LinuxPlatform {
    fn page_size(&self) -> Result<usize, OsCode> {
        // SAFETY: `sysconf` reads a constant and has no memory arguments.
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(size)
            .ok()
            .filter(|size| *size > 0)
            .ok_or_else(last_os_code)
    }

    fn map_inaccessible(&self, len: usize) -> Result<NonNull<u8>, OsCode> {
        map_anonymous(len, 0)
    }

    fn map_hugepages(&self, len: usize, size: HugepageSize) -> Result<NonNull<u8>, OsCode> {
        let encoding = match size {
            HugepageSize::TwoMiB => libc::MAP_HUGE_2MB,
            HugepageSize::OneGiB => libc::MAP_HUGE_1GB,
        };
        map_anonymous(len, libc::MAP_HUGETLB | encoding)
    }

    unsafe fn advise_huge_pages(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode> {
        // SAFETY: forwarded from the caller, who guarantees a live mapping at
        // `base..base + len`.
        unsafe { advise_page_size(base, len, libc::MADV_HUGEPAGE) }
    }

    unsafe fn advise_normal_pages(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode> {
        // SAFETY: as for `advise_huge_pages`.
        unsafe { advise_page_size(base, len, libc::MADV_NOHUGEPAGE) }
    }

    unsafe fn protect_read_write(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode> {
        // SAFETY: the caller guarantees a live mapping at `base..base + len`.
        let result = unsafe {
            libc::mprotect(
                base.as_ptr().cast(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(last_os_code())
        }
    }

    unsafe fn populate_write(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode> {
        // SAFETY: the caller guarantees a live writable mapping at
        // `base..base + len`.
        let result = unsafe { libc::madvise(base.as_ptr().cast(), len, libc::MADV_POPULATE_WRITE) };
        if result == 0 {
            Ok(())
        } else {
            Err(last_os_code())
        }
    }

    unsafe fn residency(
        &self,
        base: NonNull<u8>,
        len: usize,
        status: &mut [u8],
    ) -> Result<(), OsCode> {
        // SAFETY: the caller guarantees a live mapping at `base..base + len`
        // and a status buffer with one byte per page of that range.
        let result = unsafe { libc::mincore(base.as_ptr().cast(), len, status.as_mut_ptr()) };
        if result == 0 {
            Ok(())
        } else {
            Err(last_os_code())
        }
    }

    unsafe fn unmap(&self, base: NonNull<u8>, len: usize) -> Result<(), OsCode> {
        // SAFETY: the caller guarantees the original base and full extent of a
        // live mapping with no surviving references.
        let result = unsafe { libc::munmap(base.as_ptr().cast(), len) };
        if result == 0 {
            Ok(())
        } else {
            Err(last_os_code())
        }
    }

    fn topology(&self) -> Result<Topology, OsCode> {
        let possible = read_node_list(POSSIBLE_NODES_PATH)?;
        let has_memory = read_node_list(MEMORY_NODES_PATH)?;
        let mut allowed = NodeMask::default();
        // SAFETY: the mask buffer holds `MAX_NODES` bits, one fewer than
        // `MAXNODE`, and the mode and address arguments are null, which this
        // flag permits. Every argument is passed at register width.
        let result = unsafe {
            libc::syscall(
                libc::SYS_get_mempolicy,
                std::ptr::null_mut::<libc::c_int>(),
                allowed.words_mut().as_mut_ptr(),
                MAXNODE,
                std::ptr::null::<libc::c_void>(),
                MPOL_F_MEMS_ALLOWED,
            )
        };
        if result != 0 {
            return Err(last_os_code());
        }
        Ok(Topology {
            possible,
            has_memory,
            allowed,
        })
    }

    unsafe fn bind(&self, base: NonNull<u8>, len: usize, nodes: &NodeMask) -> Result<(), OsCode> {
        // SAFETY: forwarded from a caller holding the same guarantee.
        unsafe { mbind(base, len, nodes, 0) }
    }

    unsafe fn check_bound(
        &self,
        base: NonNull<u8>,
        len: usize,
        nodes: &NodeMask,
    ) -> Result<(), OsCode> {
        // The policy equals the one already bound, so a passing check
        // replaces nothing; a refused check returns before installing.
        // SAFETY: forwarded from a caller holding the same guarantee.
        unsafe { mbind(base, len, nodes, MPOL_MF_STRICT) }
    }

    fn clock_resolution(&self) -> Result<u64, OsCode> {
        let mut spec = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `spec` is a live, writable `timespec`.
        if unsafe { libc::clock_getres(libc::CLOCK_MONOTONIC, &mut spec) } != 0 {
            return Err(last_os_code());
        }
        ticks_of(&spec).ok_or(OsCode(libc::EOVERFLOW))
    }

    #[inline]
    fn now_ticks(&self) -> Option<u64> {
        let ticks = clock_ticks(libc::CLOCK_MONOTONIC);
        serialize_after_sample();
        ticks
    }

    unsafe fn page_node(&self, page: NonNull<u8>) -> Result<usize, OsCode> {
        let mut node: libc::c_int = -1;
        // SAFETY: the caller guarantees a page start inside a live readable
        // mapping; with these flags the kernel writes only the node integer
        // and ignores the null mask. Every argument is passed at register
        // width.
        let result = unsafe {
            libc::syscall(
                libc::SYS_get_mempolicy,
                &mut node,
                std::ptr::null_mut::<libc::c_ulong>(),
                0 as libc::c_long,
                page.as_ptr(),
                MPOL_F_NODE | MPOL_F_ADDR,
            )
        };
        if result != 0 {
            return Err(last_os_code());
        }
        usize::try_from(node).map_err(|_| OsCode(libc::EIO))
    }
}

#[cfg(test)]
mod tests {
    use super::{LinuxPlatform, Platform, parse_node_list, read_at, ticks_of};

    #[test]
    fn ticks_use_checked_arithmetic_and_reject_negative_fields() {
        let spec = |tv_sec, tv_nsec| libc::timespec { tv_sec, tv_nsec };
        assert_eq!(ticks_of(&spec(3, 5)), Some(3_000_000_005));
        assert_eq!(ticks_of(&spec(0, 0)), Some(0));
        assert_eq!(ticks_of(&spec(-1, 0)), None);
        assert_eq!(ticks_of(&spec(0, -1)), None);
        assert_eq!(ticks_of(&spec(libc::time_t::MAX, 0)), None);
        assert_eq!(
            ticks_of(&spec(
                u64::MAX.div_euclid(1_000_000_000) as libc::time_t,
                999_999_999
            )),
            None
        );
    }

    /// A smoke test of the live clock: the reported resolution is positive
    /// and 1001 consecutive samples never decrease, equal values allowed.
    /// The run records the environment it had, architecture, OS, kernel
    /// release and clocksource, read after the samples; that does not
    /// identify the path any one call took, and nothing here tests a sample
    /// against an atomic access.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot call clock_getres")]
    fn the_linux_clock_is_monotonic_with_a_positive_resolution() {
        let resolution = LinuxPlatform.clock_resolution().unwrap();
        assert!(resolution > 0);
        let mut last = LinuxPlatform.now_ticks().unwrap();
        for _ in 0..1000 {
            let next = LinuxPlatform.now_ticks().unwrap();
            assert!(next >= last);
            last = next;
        }
        // SAFETY: `uname` fills the struct it is given and reads nothing else.
        let release = unsafe {
            let mut name: libc::utsname = std::mem::zeroed();
            assert_eq!(libc::uname(&mut name), 0);
            std::ffi::CStr::from_ptr(name.release.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        let clocksource = std::fs::read_to_string(
            "/sys/devices/system/clocksource/clocksource0/current_clocksource",
        )
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "unreadable".to_owned());
        eprintln!(
            "clock environment: arch {} os {} kernel {release} clocksource {clocksource} resolution {resolution}ns",
            std::env::consts::ARCH,
            std::env::consts::OS
        );
    }

    #[test]
    fn node_lists_parse_ranges_singletons_and_reject_garbage() {
        let mask = parse_node_list(b"0-2,5\n").unwrap();
        assert_eq!(mask.nodes().collect::<Vec<_>>(), [0, 1, 2, 5]);
        assert_eq!(
            parse_node_list(b"0").unwrap().nodes().collect::<Vec<_>>(),
            [0]
        );
        assert!(parse_node_list(b"").unwrap().is_empty());
        assert!(parse_node_list(b"0-").is_none());
        assert!(parse_node_list(b"3-1").is_none());
        assert!(parse_node_list(b"a").is_none());
        assert!(parse_node_list(b"1024").is_none());
        assert!(parse_node_list(b"0,,1").is_none());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot call syscall(SYS_pread64)")]
    fn positioned_reads_count_their_bytes_and_refuse_failed_calls() {
        let path = std::env::temp_dir().join(format!("os-read-at-{}", std::process::id()));
        std::fs::write(&path, b"0123456789").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let write_only = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let mut bytes = [0; 4];
        assert_eq!(read_at(&file, &mut bytes, 3), Some(4));
        assert_eq!(&bytes, b"3456");
        assert_eq!(read_at(&file, &mut bytes, 8), Some(2));
        assert_eq!(&bytes[..2], b"89");
        assert_eq!(read_at(&file, &mut bytes, 10), Some(0));
        assert_eq!(read_at(&write_only, &mut bytes, 0), None);
        assert_eq!(read_at(&file, &mut bytes, 1 << 63), None);
    }
}
