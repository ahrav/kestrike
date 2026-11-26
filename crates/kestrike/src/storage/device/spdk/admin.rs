//! The completion record of one admin command the driver submits: the payload SPDK copies the result into and the
//! raw status word the completion callback records. The callback argument is null or points to the command's live
//! record.

use std::ffi::c_void;
use std::ptr::NonNull;

/// One outstanding admin command: the `LEN`-byte payload SPDK copies the result into, and the status its callback
/// records.
pub(super) struct AdminRequest<const LEN: usize> {
    pub(super) payload: [u8; LEN],
    pub(super) status: Option<u16>,
}

impl<const LEN: usize> AdminRequest<LEN> {
    pub(super) fn new() -> Self {
        Self {
            payload: [0; LEN],
            status: None,
        }
    }

    /// # Safety
    ///
    /// `request` points to a live `AdminRequest<LEN>`.
    pub(super) unsafe fn command(
        request: NonNull<Self>,
    ) -> (*mut c_void, u32, spdk_sys::spdk_nvme_cmd_cb, *mut c_void) {
        const { assert!(LEN <= u32::MAX as usize) };
        // SAFETY: the caller guarantees a live `AdminRequest<LEN>`; the projection produces a raw pointer to its
        // payload.
        let payload = unsafe { &raw mut (*request.as_ptr()).payload };
        (
            payload.cast(),
            LEN as u32,
            Some(admin_done::<LEN>),
            request.as_ptr().cast(),
        )
    }
}

/// Records the completion of an admin command into the [`AdminRequest`] at `arg`. A null `arg` or a null `cpl`
/// records nothing.
///
/// # Safety
///
/// `arg` is null or points to the live `AdminRequest<LEN>` the command was submitted with, and `cpl` is null or a
/// valid completion.
pub(super) unsafe extern "C" fn admin_done<const LEN: usize>(
    arg: *mut c_void,
    cpl: *const spdk_sys::spdk_nvme_cpl,
) {
    let request = arg.cast::<AdminRequest<LEN>>();
    if request.is_null() {
        return;
    }
    // SAFETY: the caller guarantees that a non-null `cpl` is a valid completion.
    let Some(cpl) = (unsafe { cpl.as_ref() }) else {
        return;
    };
    // SAFETY: the caller guarantees that a non-null `arg` points to the live `AdminRequest<LEN>` submitted with the
    // command.
    unsafe { (*request).status = Some(cpl.__bindgen_anon_1.status_raw) };
}

#[cfg(test)]
mod tests {
    use super::super::statistics::PAGE_LEN;
    use super::{AdminRequest, admin_done};

    #[test]
    fn a_null_argument_or_completion_records_no_status() {
        let mut page = AdminRequest::<PAGE_LEN>::new();
        let mut host_id = AdminRequest::<16>::new();
        let cpl = spdk_sys::spdk_nvme_cpl::default();
        // SAFETY: each call passes a null argument or a null completion, which the callback refuses before any
        // dereference of that pointer.
        unsafe {
            admin_done::<PAGE_LEN>(std::ptr::null_mut(), &cpl);
            admin_done::<16>(std::ptr::null_mut(), &cpl);
            admin_done::<PAGE_LEN>(std::ptr::from_mut(&mut page).cast(), std::ptr::null());
            admin_done::<16>(std::ptr::from_mut(&mut host_id).cast(), std::ptr::null());
        }
        assert_eq!((page.status, host_id.status), (None, None));
    }
}
