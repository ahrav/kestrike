//! The DMA posture of the process and the native calls the arena
//! registration makes, behind the [`DmaPort`] seam.
//!
//! [`DmaMode::select`] admits two postures: VA IOVAs with a guest IOMMU and
//! VFIO in IOMMU mode, or PA IOVAs on an allowlisted host with no guest IOMMU
//! and VFIO in no-IOMMU mode. Every other combination is contradictory or
//! unsupported and refused, so the mode is observed, never inferred.

use std::ffi::c_void;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

use spdk_sys as sys;

use crate::bind::Host;
use crate::storage::{LinuxPlatform, Platform};

/// DPDK's effective IOVA mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IovaMode {
    Va,
    Pa,
    /// DPDK has not chosen, which no running environment reports.
    Undecided,
}

/// The device-facing posture the registration runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaMode {
    /// IOVA is the virtual address; one checked VFIO container mapping covers the arena.
    Iommu,
    /// IOVA is each hugepage's physical address; no IOMMU mapping exists and
    /// the devices get no DMA isolation.
    NoIommu,
}

/// Which postures this host may run in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaPolicy {
    /// Whether this host is on the no-IOMMU allowlist.
    pub allow_no_iommu: bool,
}

/// The startup report of a registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaReport {
    pub iova_mode: IovaMode,
    pub guest_iommu: bool,
    /// VFIO's no-IOMMU mode as observed; `None` when it could not be read.
    pub vfio_no_iommu: Option<bool>,
    pub mode: DmaMode,
    /// Registered bytes, a whole number of backing pages.
    pub extent: usize,
    pub page_size: usize,
    /// VFIO container mappings in place: one in IOMMU mode once mapped, else zero.
    pub mappings: u32,
    /// Backing pages whose SPDK and DPDK translations verified.
    pub verified_pages: usize,
    /// Backing pages whose page-map entry gave a present, nonzero physical
    /// address, which serves as the page's IOVA: every page in no-IOMMU
    /// mode, none in IOMMU mode, which derives each IOVA from the page's
    /// virtual address. In no-IOMMU mode registration requires a present,
    /// nonzero physical address for each page. `physical_pages` equals
    /// `extent / page_size` in no-IOMMU mode and zero in IOMMU mode.
    pub physical_pages: usize,
    /// The contiguous lengths SPDK returned at the last passing verify,
    /// summed, which together cover every page; zero after a failed one.
    /// `translated_bytes` equals `extent` after a passing verify.
    pub translated_bytes: usize,
}

impl DmaMode {
    /// The posture the observed environment supports under `policy`, if any.
    pub fn select(
        iova: IovaMode,
        guest_iommu: bool,
        vfio_no_iommu: Option<bool>,
        policy: DmaPolicy,
    ) -> Option<Self> {
        match (iova, guest_iommu, vfio_no_iommu) {
            (IovaMode::Va, true, Some(false)) => Some(Self::Iommu),
            (IovaMode::Pa, false, Some(true)) if policy.allow_no_iommu => Some(Self::NoIommu),
            _ => None,
        }
    }
}

/// The native calls of the registration. A result is evidence the
/// registration acts on, so an implementation reports exactly what the
/// native layer returned. Native call errors carry the error number;
/// [`physical_addresses`](Self::physical_addresses) reports the failing page index.
pub(crate) trait DmaPort {
    fn iova_mode(&self) -> IovaMode;
    /// Whether the kernel's IOMMU class lists a guest IOMMU unit; `None`
    /// when the class cannot be read.
    fn guest_iommu(&self) -> Option<bool>;
    /// Whether VFIO runs in no-IOMMU mode; `None` when the mode cannot be read.
    fn vfio_no_iommu(&self) -> Option<bool>;
    /// External memseg lists DPDK can still create.
    fn free_memseg_lists(&self) -> u32;
    /// The locked-memory ceiling for this process that an IOMMU mapping made
    /// by the calling thread is charged against; memory the process already
    /// locked counts against the same ceiling.
    fn memlock_limit(&self) -> u64;
    /// The physical address backing each of `pages` addresses `page` bytes
    /// apart from `va`. An error holds the index of the first address
    /// without one, or 0 when the lookup cannot start.
    fn physical_addresses(&self, va: usize, page: usize, pages: usize) -> Result<Vec<u64>, usize>;
    /// # Safety
    /// `va..va + len` is live hugepage memory of `page`-byte pages that stays
    /// mapped until [`extmem_unregister`](Self::extmem_unregister) succeeds,
    /// and `iovas` holds each page's IOVA.
    unsafe fn extmem_register(
        &mut self,
        va: usize,
        len: usize,
        iovas: &[u64],
        page: usize,
    ) -> Result<(), i32>;
    fn extmem_unregister(&mut self, va: usize, len: usize) -> Result<(), i32>;
    /// # Safety
    /// The range is registered as external memory and stays mapped until
    /// [`spdk_unregister`](Self::spdk_unregister) succeeds.
    unsafe fn spdk_register(&mut self, va: usize, len: usize) -> Result<(), i32>;
    fn spdk_unregister(&mut self, va: usize, len: usize) -> Result<(), i32>;
    /// # Safety
    /// The range is registered and stays mapped until
    /// [`container_unmap`](Self::container_unmap) succeeds.
    unsafe fn container_map(&mut self, va: usize, iova: u64, len: usize) -> Result<(), i32>;
    fn container_unmap(&mut self, va: usize, iova: u64, len: usize) -> Result<(), i32>;
    /// SPDK's IOVA for `va` and the contiguous length it translates, capped at `len`.
    fn spdk_translate(&self, va: usize, len: usize) -> Option<(u64, usize)>;
    /// Writes to `out[i]` the IOVA DPDK's external memseg table holds for
    /// `va + i * page`; `None` for an address outside external memory.
    fn dpdk_translations(&self, va: usize, page: usize, out: &mut [Option<u64>]);
}

/// The production [`DmaPort`]: the native calls of the initialized environment.
pub(crate) struct NativeDma;

/// A DPDK result: zero, or -1 with the error number in `rte_errno`.
fn dpdk_status(rc: i32) -> Result<(), i32> {
    if rc == 0 {
        return Ok(());
    }
    // SAFETY: reads the calling thread's DPDK error number.
    Err(unsafe { sys::spdk_sys_rte_errno() })
}

/// A VFIO container result: zero, or -1 with the error in `errno` when the
/// ioctl failed or in `rte_errno` when DPDK refused first; [`vfio_call`]
/// cleared both before the call, so zero means neither recorded one.
fn vfio_status(rc: i32) -> Result<(), i32> {
    if rc == 0 {
        return Ok(());
    }
    let os = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    // SAFETY: reads the calling thread's DPDK error number.
    Err(if os != 0 {
        os
    } else {
        unsafe { sys::spdk_sys_rte_errno() }
    })
}

fn clear_errors() {
    // SAFETY: writes the calling thread's `errno` and `rte_errno`.
    unsafe {
        *libc::__errno_location() = 0;
        sys::spdk_sys_rte_errno_clear();
    }
}

/// Runs one VFIO container call with `errno` and `rte_errno` cleared first,
/// so a failure's error number comes from this call, and decodes its result.
fn vfio_call(call: impl FnOnce() -> i32) -> Result<(), i32> {
    clear_errors();
    vfio_status(call())
}

/// An SPDK result: zero, or a negative error number.
fn spdk_status(rc: i32) -> Result<(), i32> {
    if rc == 0 { Ok(()) } else { Err(-rc) }
}

/// A translation, absent at the all-ones value DPDK and SPDK return for none.
fn iova(value: u64) -> Option<u64> {
    (value != u64::MAX).then_some(value)
}

/// The physical address of `va` from its `/proc/self/pagemap` entry. Bit 63
/// marks a present page and bits 0 to 54 hold its frame number, in units of
/// `base_page`. An absent page or a zero frame yields no address.
fn frame_address(entry: u64, va: usize, base_page: usize) -> Option<u64> {
    const PRESENT: u64 = 1 << 63;
    const FRAME: u64 = (1 << 55) - 1;
    let frame = entry & FRAME;
    if entry & PRESENT == 0 || frame == 0 {
        return None;
    }
    frame
        .checked_mul(base_page as u64)?
        .checked_add((va % base_page) as u64)
}

/// The locked-memory ceiling VFIO enforces on a mapping thread with soft
/// `RLIMIT_MEMLOCK` `soft` and `/proc` status `status`. The kernel lifts the
/// ceiling when the thread holds `CAP_IPC_LOCK` effective in the initial user
/// namespace, which `initial_user_ns` reports; otherwise the soft limit applies.
fn lock_limit(soft: u64, status: &str, initial_user_ns: bool) -> u64 {
    const CAP_IPC_LOCK: u32 = 14;
    let ipc_lock = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|caps| u64::from_str_radix(caps.trim(), 16).ok())
        .is_some_and(|caps| caps & (1 << CAP_IPC_LOCK) != 0);
    if initial_user_ns && ipc_lock {
        u64::MAX
    } else {
        soft
    }
}

/// The segment of the memseg list `list` that holds `va`; null for a null
/// list or an address outside it.
///
/// # Safety
///
/// `list` is null or points into DPDK's memseg list table.
unsafe fn segment_in(list: *const sys::rte_memseg_list, va: usize) -> *const sys::rte_memseg {
    if list.is_null() {
        return std::ptr::null();
    }
    // SAFETY: `list` is non-null, so the caller's contract places it in
    // DPDK's list table; `rte_mem_virt2memseg` returns null for a `va`
    // outside the list.
    unsafe { sys::rte_mem_virt2memseg(va as *const c_void, list) }
}

impl DmaPort for NativeDma {
    fn iova_mode(&self) -> IovaMode {
        // SAFETY: reads EAL configuration.
        match unsafe { sys::rte_eal_iova_mode() } {
            sys::rte_iova_mode_RTE_IOVA_VA => IovaMode::Va,
            sys::rte_iova_mode_RTE_IOVA_PA => IovaMode::Pa,
            _ => IovaMode::Undecided,
        }
    }

    fn guest_iommu(&self) -> Option<bool> {
        Host::system().guest_iommu()
    }

    fn vfio_no_iommu(&self) -> Option<bool> {
        // SAFETY: reads a VFIO module parameter.
        match unsafe { sys::rte_vfio_noiommu_is_enabled() } {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    fn free_memseg_lists(&self) -> u32 {
        unsafe extern "C" fn count(_: *const sys::rte_memseg_list, arg: *mut c_void) -> i32 {
            // SAFETY: `arg` is the `u32` counter below, live for the walk.
            unsafe { *arg.cast::<u32>() += 1 };
            0
        }
        let mut used = 0u32;
        // SAFETY: the callback only increments the counter it is given.
        unsafe { sys::rte_memseg_list_walk(Some(count), (&raw mut used).cast()) };
        sys::RTE_MAX_MEMSEG_LISTS.saturating_sub(used)
    }

    fn memlock_limit(&self) -> u64 {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: writes the limit into `limit`.
        let soft = if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } == 0 {
            limit.rlim_cur
        } else {
            0
        };
        let status = fs::read_to_string("/proc/thread-self/status").unwrap_or_default();
        // The initial user namespace has the fixed proc inode number 0xEFFFFFFD.
        let initial_user_ns =
            fs::metadata("/proc/thread-self/ns/user").is_ok_and(|ns| ns.ino() == 0xEFFF_FFFD);
        lock_limit(soft, &status, initial_user_ns)
    }

    fn physical_addresses(&self, va: usize, page: usize, pages: usize) -> Result<Vec<u64>, usize> {
        let (Ok(pagemap), Ok(base_page)) =
            (File::open("/proc/self/pagemap"), LinuxPlatform.page_size())
        else {
            return Err(0);
        };
        let fd = pagemap.as_raw_fd();
        (0..pages)
            .map(|index| {
                let va = va + index * page;
                // The page map holds one 8-byte entry per base page.
                let offset = (va / base_page * size_of::<u64>()) as i64;
                let mut entry = 0u64;
                // SAFETY: `entry` is a live 8-byte buffer the read fills, and `fd` is the open page map.
                let read =
                    unsafe { libc::pread64(fd, (&raw mut entry).cast(), size_of::<u64>(), offset) };
                if read != size_of::<u64>() as isize {
                    return Err(index);
                }
                frame_address(entry, va, base_page).ok_or(index)
            })
            .collect()
    }

    unsafe fn extmem_register(
        &mut self,
        va: usize,
        len: usize,
        iovas: &[u64],
        page: usize,
    ) -> Result<(), i32> {
        let pages = u32::try_from(iovas.len()).map_err(|_| libc::E2BIG)?;
        // SAFETY: the caller's contract; DPDK copies the IOVA table.
        dpdk_status(unsafe {
            sys::rte_extmem_register(
                va as *mut c_void,
                len,
                iovas.as_ptr().cast_mut(),
                pages,
                page,
            )
        })
    }

    fn extmem_unregister(&mut self, va: usize, len: usize) -> Result<(), i32> {
        // SAFETY: DPDK reads and edits only its own memseg tables and never dereferences the range.
        dpdk_status(unsafe { sys::rte_extmem_unregister(va as *mut c_void, len) })
    }

    unsafe fn spdk_register(&mut self, va: usize, len: usize) -> Result<(), i32> {
        // SAFETY: the caller's contract.
        spdk_status(unsafe { sys::spdk_mem_register(va as *mut c_void, len) })
    }

    fn spdk_unregister(&mut self, va: usize, len: usize) -> Result<(), i32> {
        // SAFETY: SPDK edits only its own translation maps and never dereferences the range.
        spdk_status(unsafe { sys::spdk_mem_unregister(va as *mut c_void, len) })
    }

    unsafe fn container_map(&mut self, va: usize, iova: u64, len: usize) -> Result<(), i32> {
        // SAFETY: the caller's contract.
        vfio_call(|| unsafe {
            sys::rte_vfio_container_dma_map(
                sys::RTE_VFIO_DEFAULT_CONTAINER_FD,
                va as u64,
                iova,
                len as u64,
            )
        })
    }

    fn container_unmap(&mut self, va: usize, iova: u64, len: usize) -> Result<(), i32> {
        // SAFETY: the unmap edits only the IOMMU's page tables and never dereferences the range.
        vfio_call(|| unsafe {
            sys::rte_vfio_container_dma_unmap(
                sys::RTE_VFIO_DEFAULT_CONTAINER_FD,
                va as u64,
                iova,
                len as u64,
            )
        })
    }

    fn spdk_translate(&self, va: usize, len: usize) -> Option<(u64, usize)> {
        let mut size = len as u64;
        // SAFETY: reads SPDK's translation map.
        iova(unsafe { sys::spdk_vtophys(va as *const c_void, &mut size) })
            .map(|iova| (iova, usize::try_from(size).unwrap_or(0)))
    }

    fn dpdk_translations(&self, va: usize, page: usize, out: &mut [Option<u64>]) {
        // DPDK reserves each internal memseg list's address range, and each
        // external list is one arena registration over that arena's own
        // mapping, so a list holding a segment for `at` is the list
        // `rte_mem_virt2memseg_list` returns for `at`.
        let (mut list, mut external) = (std::ptr::null(), false);
        let mut at = va;
        for slot in out {
            // SAFETY: `list` is null or a list `rte_mem_virt2memseg_list`
            // returned, which stays in DPDK's list table until the
            // environment finishes and so meets `segment_in`'s contract on
            // every iteration; a non-null segment points into its list's
            // segment array, which stays in place while the range is
            // registered; the packed segment's fields are read unaligned.
            *slot = unsafe {
                let mut segment = segment_in(list, at);
                if segment.is_null() {
                    list = sys::rte_mem_virt2memseg_list(at as *const c_void);
                    external = list.as_ref().is_some_and(|list| list.external != 0);
                    segment = segment_in(list, at);
                }
                match segment.as_ref() {
                    Some(segment) if external => {
                        let base =
                            std::ptr::addr_of!(segment.__bindgen_anon_1.addr_64).read_unaligned();
                        let iova = std::ptr::addr_of!(segment.iova).read_unaligned();
                        (at as u64)
                            .checked_sub(base)
                            .and_then(|offset| iova.checked_add(offset))
                    }
                    _ => None,
                }
            };
            at = at.wrapping_add(page);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;

    fn errno() -> i32 {
        // SAFETY: reads the calling thread's `errno`.
        unsafe { *libc::__errno_location() }
    }

    fn set_errno(code: i32) {
        // SAFETY: writes the calling thread's `errno`.
        unsafe { *libc::__errno_location() = code };
    }

    fn rte_errno() -> i32 {
        // SAFETY: reads the calling thread's DPDK error number.
        unsafe { sys::spdk_sys_rte_errno() }
    }

    /// Makes DPDK record `EINVAL` in this thread's `rte_errno`: external
    /// memory refuses a null, empty range before it reads any EAL state.
    fn set_rte_errno() {
        // SAFETY: a null, empty range fails DPDK's argument check.
        assert_eq!(
            unsafe { sys::rte_extmem_unregister(std::ptr::null_mut(), 0) },
            -1
        );
        assert_eq!(rte_errno(), libc::EINVAL);
    }

    fn clear_rte_errno() {
        // SAFETY: writes the calling thread's `rte_errno`.
        unsafe { sys::spdk_sys_rte_errno_clear() };
    }

    /// Runs `f` with stale `errno` and `rte_errno`, then restores the
    /// caller's `errno` and leaves `rte_errno` clear, as before the seeding.
    fn with_stale_errors<T>(f: impl FnOnce() -> T) -> T {
        let saved = errno();
        clear_rte_errno();
        set_rte_errno();
        set_errno(libc::EINTR);
        assert_eq!((errno(), rte_errno()), (libc::EINTR, libc::EINVAL));
        let out = f();
        set_errno(saved);
        clear_rte_errno();
        out
    }

    #[test]
    fn the_vfio_wrapper_clears_both_errors_before_the_call_and_prefers_the_os_error() {
        let entered = |result: i32, os: i32, dpdk: bool| {
            with_stale_errors(|| {
                let mut seen = None;
                let outcome = vfio_call(|| {
                    seen = Some((errno(), rte_errno()));
                    if dpdk {
                        set_rte_errno();
                    }
                    set_errno(os);
                    result
                });
                (seen, outcome)
            })
        };
        let clear = Some((0, 0));
        assert_eq!(entered(0, 0, false), (clear, Ok(())));
        assert_eq!(entered(0, libc::EIO, true), (clear, Ok(())));
        assert_eq!(entered(-1, libc::EBADF, true), (clear, Err(libc::EBADF)));
        assert_eq!(entered(-1, 0, true), (clear, Err(libc::EINVAL)));
        assert_eq!(
            entered(-1, 0, false),
            (clear, Err(0)),
            "a failure that recorded neither error reports zero, which the registration reports as no code"
        );
        assert_eq!(rte_errno(), 0);
        assert_eq!(
            with_stale_errors(|| NativeDma.container_unmap(0, 0, 0)),
            Err(libc::EINVAL),
            "the production unmap clears the stale errno, so DPDK's refusal of an empty range reports rte_errno"
        );
        let saved = errno();
        clear_rte_errno();
        set_errno(0);
        assert_eq!((errno(), rte_errno()), (0, 0));
        let clean = NativeDma.container_unmap(0, 0, 0);
        set_errno(saved);
        clear_rte_errno();
        assert_eq!(
            clean,
            Err(libc::EINVAL),
            "with both errors clear at entry the same refusal reports the same rte_errno"
        );
    }

    #[test]
    fn a_real_ioctl_refusal_reports_enotty_and_the_test_restores_its_errors() {
        let null = std::fs::File::open("/dev/null").unwrap();
        let saved = errno();
        let refused = with_stale_errors(|| {
            vfio_call(|| {
                // SAFETY: `null` is an open descriptor this test owns, and
                // `/dev/null` answers `FIONREAD` with ENOTTY before the
                // kernel reads the argument.
                unsafe {
                    libc::ioctl(
                        null.as_raw_fd(),
                        libc::FIONREAD,
                        std::ptr::null_mut::<i32>(),
                    )
                }
            })
        });
        assert_eq!(refused, Err(libc::ENOTTY));
        assert_eq!((errno(), rte_errno()), (saved, 0));
    }

    #[test]
    fn dpdk_and_spdk_results_decode_their_own_error_domains() {
        let saved = errno();
        assert_eq!(dpdk_status(0), Ok(()));
        set_errno(libc::EBADF);
        assert_eq!(
            NativeDma.extmem_unregister(0, 0),
            Err(libc::EINVAL),
            "the DPDK wrapper reports rte_errno over a stale errno"
        );
        clear_rte_errno();
        set_errno(saved);
        assert_eq!(spdk_status(0), Ok(()));
        assert_eq!(spdk_status(-libc::ENOMEM), Err(libc::ENOMEM));
        assert_eq!(spdk_status(-libc::EBUSY), Err(libc::EBUSY));
    }

    const BASE_PAGE: usize = 4096;
    const PRESENT: u64 = 1 << 63;

    #[test]
    fn a_present_entry_yields_its_frame_plus_the_offset_in_the_page() {
        assert_eq!(
            frame_address(PRESENT | 0x1234, 0x7f00_0000_0000, BASE_PAGE),
            Some(0x1234 * 4096)
        );
        assert_eq!(
            frame_address(PRESENT | 0x1234, 0x7f00_0000_0010, BASE_PAGE),
            Some(0x1234 * 4096 + 0x10)
        );
    }

    #[test]
    fn flag_bits_above_the_frame_number_do_not_change_the_address() {
        let flags = PRESENT | (1 << 61) | (1 << 56) | (1 << 55);
        assert_eq!(frame_address(flags | 0x40, 0, BASE_PAGE), Some(0x40 * 4096));
    }

    #[test]
    fn an_absent_page_or_a_zero_frame_has_no_address() {
        assert_eq!(frame_address(0x1234, 0, BASE_PAGE), None);
        assert_eq!(frame_address((1 << 62) | 0x1234, 0, BASE_PAGE), None);
        assert_eq!(frame_address(PRESENT, 0, BASE_PAGE), None);
    }

    /// With the privilege to read frame numbers, every queried page's page-map
    /// address is present, nonzero and equal to DPDK's translation, which
    /// maps DPDK's all-ones answer to `None` so a missing translation fails
    /// the comparison; the test prints the positive count the prerequisites
    /// role's witness requires.
    #[test]
    #[ignore = "needs root, which exposes physical frame numbers in /proc/self/pagemap"]
    fn privileged_page_map_addresses_are_present_and_match_dpdk() {
        const PAGES: usize = 4;
        let buffer = vec![1u8; (PAGES + 1) * BASE_PAGE];
        let mut physical = Vec::new();
        // Two starting offsets 101 bytes short of one page apart, so the queried addresses fall at different in-page offsets.
        for offset in [100, BASE_PAGE - 1] {
            let va = buffer.as_ptr().addr() + offset;
            physical = NativeDma
                .physical_addresses(va, BASE_PAGE, PAGES)
                .unwrap_or_else(|page| {
                    panic!(
                        "page {page} at offset {offset} has no present, nonzero page-map address"
                    )
                });
            for (index, address) in physical.iter().enumerate() {
                let page = (va + index * BASE_PAGE) as *const c_void;
                // SAFETY: `rte_mem_virt2phy` reads this process's page map for `page` without dereferencing it, and `page` lies inside the live `buffer`.
                let native = iova(unsafe { sys::rte_mem_virt2phy(page) });
                assert_eq!(native, Some(*address), "page {index} at offset {offset}");
            }
        }
        eprintln!(
            "observe: physical-query {} pages present nonzero and equal to rte_mem_virt2phy",
            physical.len()
        );
    }

    #[test]
    fn page_map_addresses_match_dpdk_for_every_page() {
        const PAGES: usize = 4;
        let buffer = vec![1u8; (PAGES + 1) * BASE_PAGE];
        let va = buffer.as_ptr().addr() + 100;
        let dpdk: Option<Vec<u64>> = (0..PAGES)
            .map(|index| {
                let page = (va + index * BASE_PAGE) as *const c_void;
                // SAFETY: `page` points into `buffer`, which stays allocated for the call.
                iova(unsafe { sys::rte_mem_virt2phy(page) })
            })
            .collect();
        assert_eq!(
            NativeDma.physical_addresses(va, BASE_PAGE, PAGES).ok(),
            dpdk
        );
    }

    /// A status with the given effective capability set, as `/proc` formats it.
    fn status(caps: u64) -> String {
        format!(
            "Name:\tcache\nCapInh:\t0000000000000000\nCapEff:\t{caps:016x}\nCapBnd:\t000001ffffffffff\n"
        )
    }

    #[test]
    fn an_effective_ipc_lock_capability_lifts_the_lock_limit() {
        assert_eq!(lock_limit(8 << 20, &status(1 << 14), true), u64::MAX);
        assert_eq!(
            lock_limit(8 << 20, &status(0x1ff_ffff_ffff), true),
            u64::MAX
        );
    }

    #[test]
    fn without_ipc_lock_the_soft_limit_bounds_locked_memory() {
        assert_eq!(lock_limit(8 << 20, &status(!(1 << 14)), true), 8 << 20);
        assert_eq!(lock_limit(8 << 20, "", true), 8 << 20);
        assert_eq!(lock_limit(8 << 20, "CapEff:\tnot-hex\n", true), 8 << 20);
    }

    #[test]
    fn ipc_lock_in_a_child_user_namespace_keeps_the_soft_limit() {
        assert_eq!(lock_limit(8 << 20, &status(1 << 14), false), 8 << 20);
    }
}
