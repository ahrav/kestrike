//! A bound on a probe that blocks when the rule it tests breaks, so such a case fails at the bound
//! where it would hang the run.

use std::sync::mpsc::{RecvTimeoutError, channel};
use std::thread;
use std::time::Duration;

/// The bound: long enough that a probe that does not block ends within it on a loaded host.
pub(super) const BOUND: Duration = Duration::from_secs(10);

/// Runs `probe` on a thread of its own and gives its result, failing the case with `what` when the
/// probe has not ended within [`BOUND`]; a probe left blocked holds only what it was given.
pub(super) fn within<T: Send + 'static>(
    what: &str,
    probe: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (sender, receiver) = channel();
    thread::spawn(move || {
        let _ = sender.send(probe());
    });
    match receiver.recv_timeout(BOUND) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => panic!("{what} did not end within {BOUND:?}"),
        Err(RecvTimeoutError::Disconnected) => panic!("{what} panicked"),
    }
}
