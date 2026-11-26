//! [`SpdkDisk`](super::SpdkDisk) makes its controller calls through
//! [`Native`]: the connect, then configuration, submit, pick, service,
//! quiesce and detach. Attach parses the address through `spdk_sys`
//! directly, and `Native::connect_options` fills the controller options the
//! connect takes.

use std::ffi::c_void;

use spdk_sys as sys;

use super::limits::NamespaceFacts;

/// # Safety
///
/// An implementation keeps the contract of the SPDK function each method
/// names, as SPDK v25.05.1, the install `spdk_sys` binds, defines it: a
/// nonzero submit result ends SPDK's access to the command and its callback
/// argument; each command a submit accepted gets exactly one callback, which
/// is SPDK's last use of that command's callback argument, and the driver
/// trusts this finality when it reuses the argument's staging record;
/// callbacks run on the calling thread, inside a submit,
/// a completion poll, an admin poll, a qpair free, which completes every
/// outstanding command with an abort status, or a detach; and the register
/// reads report the controller's live CC and CSTS values, or all ones when a
/// read failed.
pub unsafe trait Native {
    /// `spdk_nvme_ctrlr_get_default_ctrlr_opts` fills defaults, then the persisted EXHID replaces the default host ID.
    ///
    /// # Safety
    ///
    /// `opts` is writable and fully sized.
    unsafe fn connect_options(opts: &mut sys::spdk_nvme_ctrlr_opts, exhid: [u8; 16]);

    /// `spdk_nvme_connect` connects the controller at `trid` synchronously with `opts`, and returns it, or null when
    /// the connect failed. A non-null controller belongs to the caller, which ends it through
    /// [`detach`](Self::detach).
    ///
    /// # Safety
    ///
    /// `trid` and `opts` are valid, fully sized structures, `opts` filled by
    /// [`connect_options`](Self::connect_options). The SPDK environment is initialized, the caller does not
    /// connect concurrently from another thread, and no other driver of this process holds the controller at
    /// `trid`.
    unsafe fn connect(
        trid: &sys::spdk_nvme_transport_id,
        opts: &sys::spdk_nvme_ctrlr_opts,
    ) -> *mut sys::spdk_nvme_ctrlr;

    /// `spdk_nvme_ns_cmd_reservation_register` checks the current key (`ignore_key` false) and preserves PTPL (`cptpl` 0).
    ///
    /// # Safety
    ///
    /// `ns` and `qpair` belong to the live controller on this thread. `payload` has 16 readable bytes holding the current and new keys; `action` is Register (0), and `cptpl` preserves PTPL (0).
    /// The buffer and callback argument stay exclusive and alive until a certified terminal or proven stop. A nonzero submit result ends SPDK's access to the command and callback argument; a zero result produces one callback on this thread inside a Native call, and the driver delivers the terminal only when a healthy poll observed it.
    unsafe fn reservation_register(
        ns: *mut sys::spdk_nvme_ns,
        qpair: *mut sys::spdk_nvme_qpair,
        payload: *mut sys::spdk_nvme_reservation_register_data,
        action: u32,
        cptpl: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32;

    /// `spdk_nvme_ns_cmd_reservation_report` selects EDS from CTRATT bit 0; the caller qualifies that bit before submitting.
    /// SPDK uses a 4096-aligned DMA bounce buffer for reservation commands; bounce or request allocation can return -ENOMEM. Report copies reach the destination before callbacks, including failed statuses; evidence requires Success.
    ///
    /// # Safety
    ///
    /// The queue, callback and finality contract is the Register contract. `payload` has `len` exclusive writable bytes, with `len` positive and divisible by four; they stay alive through the command's terminal or proven stop.
    unsafe fn reservation_report(
        ns: *mut sys::spdk_nvme_ns,
        qpair: *mut sys::spdk_nvme_qpair,
        payload: *mut c_void,
        len: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32;

    /// `spdk_nvme_ns_cmd_reservation_acquire` checks the current key (`ignore_key` false) for Acquire, Preempt or Preempt-and-Abort with Exclusive Access, type 2.
    ///
    /// # Safety
    ///
    /// The queue, buffer, callback and finality contract is the Register contract. The 16 payload bytes contain current and preempt keys; `action` is Acquire (0), Preempt (1) or Preempt-and-Abort (2), and `rtype` is Exclusive Access (2).
    unsafe fn reservation_acquire(
        ns: *mut sys::spdk_nvme_ns,
        qpair: *mut sys::spdk_nvme_qpair,
        payload: *mut sys::spdk_nvme_reservation_acquire_data,
        action: u32,
        rtype: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32;

    /// `spdk_nvme_ctrlr_get_data`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK function's requirements.
    unsafe fn controller_data(ctrlr: *mut sys::spdk_nvme_ctrlr)
    -> *const sys::spdk_nvme_ctrlr_data;

    /// The PCI vendor and device IDs of `spdk_nvme_ctrlr_get_pci_device`'s
    /// device, or `None` when the controller reports no PCI device.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK functions' requirements.
    unsafe fn pci_ids(ctrlr: *mut sys::spdk_nvme_ctrlr) -> Option<(u16, u16)>;

    /// `spdk_nvme_ctrlr_get_ns`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK function's requirements.
    unsafe fn namespace(ctrlr: *mut sys::spdk_nvme_ctrlr, nsid: u32) -> *mut sys::spdk_nvme_ns;

    /// `spdk_nvme_ns_get_data`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK function's requirements.
    unsafe fn namespace_data(ns: *mut sys::spdk_nvme_ns) -> *const sys::spdk_nvme_ns_data;

    /// Fills `opts` with `spdk_nvme_ctrlr_get_default_io_qpair_opts` and
    /// reads the namespace through the `spdk_nvme_ns_get_*` accessors and
    /// `spdk_nvme_ns_is_active`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK functions' requirements.
    unsafe fn namespace_facts(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
        ns: *mut sys::spdk_nvme_ns,
        opts: &mut sys::spdk_nvme_io_qpair_opts,
    ) -> NamespaceFacts;

    /// `spdk_nvme_ctrlr_alloc_io_qpair`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK function's requirements.
    unsafe fn alloc_io_qpair(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
        opts: &sys::spdk_nvme_io_qpair_opts,
    ) -> *mut sys::spdk_nvme_qpair;

    /// `spdk_nvme_ctrlr_register_timeout_callback`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK function's requirements.
    unsafe fn register_timeout(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
        io_us: u64,
        admin_us: u64,
        callback: sys::spdk_nvme_timeout_cb,
        arg: *mut c_void,
    );

    /// `spdk_nvme_ns_cmd_read` with I/O flags `0`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK function's requirements.
    unsafe fn read(
        ns: *mut sys::spdk_nvme_ns,
        qpair: *mut sys::spdk_nvme_qpair,
        payload: *mut c_void,
        lba: u64,
        count: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32;

    /// `spdk_nvme_ns_cmd_write` with I/O flags `0`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK function's requirements.
    unsafe fn write(
        ns: *mut sys::spdk_nvme_ns,
        qpair: *mut sys::spdk_nvme_qpair,
        payload: *mut c_void,
        lba: u64,
        count: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32;

    /// `spdk_nvme_qpair_process_completions`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK function's requirements.
    unsafe fn process_completions(qpair: *mut sys::spdk_nvme_qpair, limit: u32) -> i32;

    /// `spdk_nvme_ctrlr_is_failed`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK function's requirements.
    unsafe fn is_failed(ctrlr: *mut sys::spdk_nvme_ctrlr) -> bool;

    /// `spdk_nvme_ctrlr_disconnect`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK function's requirements.
    unsafe fn disconnect(ctrlr: *mut sys::spdk_nvme_ctrlr) -> i32;

    /// `spdk_nvme_ctrlr_process_admin_completions`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK function's requirements.
    unsafe fn process_admin_completions(ctrlr: *mut sys::spdk_nvme_ctrlr) -> i32;

    /// The raw CC and CSTS values from `spdk_nvme_ctrlr_get_regs_cc` and
    /// `spdk_nvme_ctrlr_get_regs_csts`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK functions' requirements.
    unsafe fn registers(ctrlr: *mut sys::spdk_nvme_ctrlr) -> (u32, u32);

    /// `spdk_nvme_ctrlr_free_io_qpair`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK function's requirements.
    unsafe fn free_io_qpair(qpair: *mut sys::spdk_nvme_qpair) -> i32;

    /// `spdk_nvme_detach`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK function's requirements.
    unsafe fn detach(ctrlr: *mut sys::spdk_nvme_ctrlr) -> i32;

    /// `spdk_nvme_ctrlr_cmd_get_feature`: Get Features for `feature` with `cdw11`, reading `len` bytes into
    /// `payload`.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK function's requirements. `callback` is `Some`, `payload` stays writable for
    /// `len` bytes, and `arg` stays alive until the callback ran or the controller detached. A nonzero submit result
    /// ends SPDK's access to the payload and callback argument. The callback runs under the trait-level rules,
    /// which include a qpair free and a detach.
    unsafe fn get_feature(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
        feature: u8,
        cdw11: u32,
        payload: *mut c_void,
        len: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32;

    /// `spdk_nvme_ctrlr_cmd_get_log_page` at offset 0.
    ///
    /// # Safety
    ///
    /// The caller meets the named SPDK function's requirements.
    unsafe fn get_log_page(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
        log_page: u8,
        nsid: u32,
        payload: *mut c_void,
        len: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32;
}

#[derive(Debug)]
pub struct Spdk;

// SAFETY: each method calls only the SPDK functions it names.
unsafe impl Native for Spdk {
    unsafe fn connect_options(opts: &mut sys::spdk_nvme_ctrlr_opts, exhid: [u8; 16]) {
        // SAFETY: the caller supplies a fully sized writable options structure.
        unsafe {
            sys::spdk_nvme_ctrlr_get_default_ctrlr_opts(opts, size_of_val(opts));
        }
        opts.extended_host_id = exhid;
    }

    unsafe fn connect(
        trid: &sys::spdk_nvme_transport_id,
        opts: &sys::spdk_nvme_ctrlr_opts,
    ) -> *mut sys::spdk_nvme_ctrlr {
        // SAFETY: the caller supplies valid, fully sized structures.
        unsafe { sys::spdk_nvme_connect(trid, opts, size_of_val(opts)) }
    }

    unsafe fn reservation_register(
        ns: *mut sys::spdk_nvme_ns,
        qpair: *mut sys::spdk_nvme_qpair,
        payload: *mut sys::spdk_nvme_reservation_register_data,
        action: u32,
        cptpl: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32 {
        // SAFETY: the caller meets the queue, payload and callback lifetime contract.
        unsafe {
            sys::spdk_nvme_ns_cmd_reservation_register(
                ns, qpair, payload, false, action, cptpl, callback, arg,
            )
        }
    }

    unsafe fn reservation_report(
        ns: *mut sys::spdk_nvme_ns,
        qpair: *mut sys::spdk_nvme_qpair,
        payload: *mut c_void,
        len: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32 {
        // SAFETY: the caller qualifies CTRATT and meets the queue, payload and callback lifetime contract.
        unsafe { sys::spdk_nvme_ns_cmd_reservation_report(ns, qpair, payload, len, callback, arg) }
    }

    unsafe fn reservation_acquire(
        ns: *mut sys::spdk_nvme_ns,
        qpair: *mut sys::spdk_nvme_qpair,
        payload: *mut sys::spdk_nvme_reservation_acquire_data,
        action: u32,
        rtype: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32 {
        // SAFETY: the caller meets the queue, payload and callback lifetime contract.
        unsafe {
            sys::spdk_nvme_ns_cmd_reservation_acquire(
                ns, qpair, payload, false, action, rtype, callback, arg,
            )
        }
    }

    unsafe fn controller_data(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
    ) -> *const sys::spdk_nvme_ctrlr_data {
        // SAFETY: the caller meets the SPDK function's requirements.
        unsafe { sys::spdk_nvme_ctrlr_get_data(ctrlr) }
    }

    unsafe fn pci_ids(ctrlr: *mut sys::spdk_nvme_ctrlr) -> Option<(u16, u16)> {
        // SAFETY: the caller meets the SPDK functions' requirements, and the device is read only when SPDK returned one.
        unsafe {
            let device = sys::spdk_nvme_ctrlr_get_pci_device(ctrlr);
            (!device.is_null()).then(|| {
                (
                    sys::spdk_pci_device_get_vendor_id(device),
                    sys::spdk_pci_device_get_device_id(device),
                )
            })
        }
    }

    unsafe fn namespace(ctrlr: *mut sys::spdk_nvme_ctrlr, nsid: u32) -> *mut sys::spdk_nvme_ns {
        // SAFETY: the caller meets the SPDK function's requirements.
        unsafe { sys::spdk_nvme_ctrlr_get_ns(ctrlr, nsid) }
    }

    unsafe fn namespace_data(ns: *mut sys::spdk_nvme_ns) -> *const sys::spdk_nvme_ns_data {
        // SAFETY: the caller meets the SPDK function's requirements.
        unsafe { sys::spdk_nvme_ns_get_data(ns) }
    }

    unsafe fn namespace_facts(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
        ns: *mut sys::spdk_nvme_ns,
        opts: &mut sys::spdk_nvme_io_qpair_opts,
    ) -> NamespaceFacts {
        // SAFETY: the caller meets the SPDK functions' requirements, and `opts` is sized.
        unsafe {
            sys::spdk_nvme_ctrlr_get_default_io_qpair_opts(ctrlr, opts, size_of_val(opts));
            NamespaceFacts {
                active: sys::spdk_nvme_ns_is_active(ns),
                sector_size: sys::spdk_nvme_ns_get_sector_size(ns),
                sectors: sys::spdk_nvme_ns_get_num_sectors(ns),
                metadata_size: sys::spdk_nvme_ns_get_md_size(ns),
                protection_type: sys::spdk_nvme_ns_get_pi_type(ns),
                max_transfer: sys::spdk_nvme_ns_get_max_io_xfer_size(ns),
                boundary: sys::spdk_nvme_ns_get_optimal_io_boundary(ns),
                max_queue_size: opts.io_queue_size,
            }
        }
    }

    unsafe fn alloc_io_qpair(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
        opts: &sys::spdk_nvme_io_qpair_opts,
    ) -> *mut sys::spdk_nvme_qpair {
        // SAFETY: the caller meets the SPDK function's requirements, and `opts` is sized.
        unsafe { sys::spdk_nvme_ctrlr_alloc_io_qpair(ctrlr, opts, size_of_val(opts)) }
    }

    unsafe fn register_timeout(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
        io_us: u64,
        admin_us: u64,
        callback: sys::spdk_nvme_timeout_cb,
        arg: *mut c_void,
    ) {
        // SAFETY: the caller meets the SPDK function's requirements.
        unsafe {
            sys::spdk_nvme_ctrlr_register_timeout_callback(ctrlr, io_us, admin_us, callback, arg);
        }
    }

    #[inline(always)]
    unsafe fn read(
        ns: *mut sys::spdk_nvme_ns,
        qpair: *mut sys::spdk_nvme_qpair,
        payload: *mut c_void,
        lba: u64,
        count: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32 {
        // SAFETY: the caller meets the SPDK function's requirements.
        unsafe { sys::spdk_nvme_ns_cmd_read(ns, qpair, payload, lba, count, callback, arg, 0) }
    }

    #[inline(always)]
    unsafe fn write(
        ns: *mut sys::spdk_nvme_ns,
        qpair: *mut sys::spdk_nvme_qpair,
        payload: *mut c_void,
        lba: u64,
        count: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32 {
        // SAFETY: the caller meets the SPDK function's requirements.
        unsafe { sys::spdk_nvme_ns_cmd_write(ns, qpair, payload, lba, count, callback, arg, 0) }
    }

    #[inline(always)]
    unsafe fn process_completions(qpair: *mut sys::spdk_nvme_qpair, limit: u32) -> i32 {
        // SAFETY: the caller meets the SPDK function's requirements.
        unsafe { sys::spdk_nvme_qpair_process_completions(qpair, limit) }
    }

    #[inline(always)]
    unsafe fn is_failed(ctrlr: *mut sys::spdk_nvme_ctrlr) -> bool {
        // SAFETY: the caller meets the SPDK function's requirements.
        unsafe { sys::spdk_nvme_ctrlr_is_failed(ctrlr) }
    }

    #[inline(always)]
    unsafe fn disconnect(ctrlr: *mut sys::spdk_nvme_ctrlr) -> i32 {
        // SAFETY: the caller meets the SPDK function's requirements.
        unsafe { sys::spdk_nvme_ctrlr_disconnect(ctrlr) }
    }

    #[inline(always)]
    unsafe fn process_admin_completions(ctrlr: *mut sys::spdk_nvme_ctrlr) -> i32 {
        // SAFETY: the caller meets the SPDK function's requirements.
        unsafe { sys::spdk_nvme_ctrlr_process_admin_completions(ctrlr) }
    }

    #[inline(always)]
    unsafe fn registers(ctrlr: *mut sys::spdk_nvme_ctrlr) -> (u32, u32) {
        // SAFETY: the caller meets the SPDK functions' requirements.
        unsafe {
            (
                sys::spdk_nvme_ctrlr_get_regs_cc(ctrlr).raw,
                sys::spdk_nvme_ctrlr_get_regs_csts(ctrlr).raw,
            )
        }
    }

    #[inline(always)]
    unsafe fn free_io_qpair(qpair: *mut sys::spdk_nvme_qpair) -> i32 {
        // SAFETY: the caller meets the SPDK function's requirements.
        unsafe { sys::spdk_nvme_ctrlr_free_io_qpair(qpair) }
    }

    #[inline(always)]
    unsafe fn detach(ctrlr: *mut sys::spdk_nvme_ctrlr) -> i32 {
        // SAFETY: the caller meets the SPDK function's requirements.
        unsafe { sys::spdk_nvme_detach(ctrlr) }
    }

    unsafe fn get_feature(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
        feature: u8,
        cdw11: u32,
        payload: *mut c_void,
        len: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32 {
        // SAFETY: the caller meets the SPDK function's requirements.
        unsafe {
            sys::spdk_nvme_ctrlr_cmd_get_feature(ctrlr, feature, cdw11, payload, len, callback, arg)
        }
    }

    unsafe fn get_log_page(
        ctrlr: *mut sys::spdk_nvme_ctrlr,
        log_page: u8,
        nsid: u32,
        payload: *mut c_void,
        len: u32,
        callback: sys::spdk_nvme_cmd_cb,
        arg: *mut c_void,
    ) -> i32 {
        // SAFETY: the caller meets the SPDK function's requirements.
        unsafe {
            sys::spdk_nvme_ctrlr_cmd_get_log_page(
                ctrlr, log_page, nsid, payload, len, 0, callback, arg,
            )
        }
    }
}
