//! The assertion GenMC reports as a safety violation. Rust's `assert!`
//! reaches `core::panicking`, which the interpreter cannot execute, so a
//! failed check calls `__VERIFIER_assert_fail`, the symbol `genmc-std`
//! exports and the interpreter intercepts. The macro expands the call at
//! each check with the check's own debug location, so the violation's
//! `ERROR file:line` event names the check that failed.

unsafe extern "C" {
    pub(crate) fn __VERIFIER_assert_fail(
        msg: *const core::ffi::c_char,
        file: *const core::ffi::c_char,
        line: i32,
    );
}

/// `check!(cond, c"message")` reports a violation at this call site when
/// `cond` is false. Collapsing the macro's debug info gives the error call
/// its invocation's location.
#[collapse_debuginfo(yes)]
macro_rules! check {
    ($cond:expr, $msg:literal) => {
        if !($cond) {
            // SAFETY: both arguments are NUL-terminated static strings.
            unsafe {
                $crate::check::__VERIFIER_assert_fail(
                    $msg.as_ptr(),
                    c"genmc-kernels".as_ptr(),
                    line!() as i32,
                )
            }
        }
    };
}
pub(crate) use check;
