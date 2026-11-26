//! The binder's steps, each a point at which a test may hold the calling
//! process. Outside tests, each step invokes its call directly.
//!
//! Under test, a thread that connected a supervisor reports each step and
//! blocks twice: before the step's call until the supervisor lets it run,
//! and after the call until the supervisor lets the thread go on. A thread
//! blocked after a step holds exactly the locks, guards and files the step
//! left. A thread with no supervisor makes each call unchanged.

use std::fs::File;

/// Runs `call` as the binder step `phase` on `device`, the PCI address the
/// step names or the empty string.
#[inline(always)]
pub(super) fn step<T, E>(
    _phase: &str,
    _device: &str,
    call: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    #[cfg(test)]
    super::replay_control::before(_phase, _device);
    let result = call();
    #[cfg(test)]
    super::replay_control::after(_phase, _device, result.is_ok());
    result
}

/// Runs `call` as the step that opens the group guard of `device`. Each
/// later report of the thread names the guard while its descriptor stays
/// open.
#[inline(always)]
pub(super) fn guard<E>(_device: &str, call: impl FnOnce() -> Result<File, E>) -> Result<File, E> {
    #[cfg(test)]
    super::replay_control::before("groupGuard", _device);
    let result = call();
    #[cfg(test)]
    {
        if let Ok(guard) = &result {
            super::replay_control::guarded(_device, guard);
        }
        super::replay_control::after("groupGuard", _device, result.is_ok());
    }
    result
}
