//! The watchdog over in-place recovery and the record of each recovery
//! episode.
//!
//! In-place recovery stops a device, rechecks the registration, then resets,
//! re-initializes and restarts the device. Each of those steps is a call that
//! can stall the owner thread, and the device may reach memory during the stop
//! and again from the reset on, so every episode runs under the watch's
//! [`Rearmable`] watchdog, armed before the first step and disarmed after the
//! last. The watch starts that watchdog's worker once and each episode
//! rearms it. An
//! expiry leaves the stalled call in place and requests containment once
//! through the supervisor; the episode then begins no further step and keeps
//! every buffer the device may hold.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use super::watchdog::{Rearmable, Supervisor};

/// A step of in-place recovery, in the order an episode runs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStage {
    /// The device's stop and the proof that its DMA is off, both first and
    /// after a later stage fails.
    Stop,
    /// The registration's recheck of every page's translation.
    Recheck,
    /// The function reset, after which the device may reach memory again.
    Reset,
    /// The driver's re-initialization with the attach-time placement.
    Reinitialize,
    /// The device's start, which posts receive buffers.
    Restart,
}

/// One recovery episode as the burst logic observed it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryEpisode {
    /// The episode's number: the burst's reset count when it began.
    pub episode: u64,
    /// The last stage the episode began, or `None` before the first.
    pub reached: Option<RecoveryStage>,
    /// The stage an expiry fell on: the first stage that returned after the
    /// watchdog expired, or the last stage begun when the expiry followed that
    /// stage's return; `None` when the watchdog expired before the first
    /// stage began.
    pub expired_at: Option<RecoveryStage>,
    /// The watchdog asked the supervisor to contain, which an expiry does once.
    pub containment_requested: bool,
    /// The supervisor's own report, read after the request, that the
    /// containment took effect.
    pub containment_verified: bool,
    /// The watchdog could not arm, so the episode began no stage.
    pub refused: bool,
}

/// The deadline every in-place recovery runs under and the supervisor its
/// expiry escalates to, over one watchdog worker that each episode rearms.
pub struct RecoveryWatch {
    deadline: Duration,
    supervisor: Arc<dyn Supervisor>,
    /// `None` when the worker could not start, so every episode refuses.
    watchdog: Option<Rearmable>,
}

impl RecoveryWatch {
    /// Starts the watchdog worker of `deadline` over `supervisor`, idle until
    /// an episode arms it. A worker that cannot start leaves every episode
    /// refused.
    pub fn new(deadline: Duration, supervisor: Arc<dyn Supervisor>) -> Self {
        let watchdog = Rearmable::idle(deadline, Arc::clone(&supervisor)).ok();
        Self {
            deadline,
            supervisor,
            watchdog,
        }
    }

    /// [`new`](Self::new) with `start` in place of [`Rearmable::idle`], for a
    /// test's scripted timer or a worker that cannot start.
    #[cfg(test)]
    pub(crate) fn with_start(
        deadline: Duration,
        supervisor: Arc<dyn Supervisor>,
        start: impl FnOnce(Duration, Arc<dyn Supervisor>) -> std::io::Result<Rearmable>,
    ) -> Self {
        let watchdog = start(deadline, Arc::clone(&supervisor)).ok();
        Self {
            deadline,
            supervisor,
            watchdog,
        }
    }

    /// Starts one episode's deadline and returns `true`. `arm` returns
    /// `false` when the worker failed to start or an earlier episode's
    /// deadline expired.
    pub(crate) fn arm(&self) -> bool {
        self.watchdog.as_ref().is_some_and(Rearmable::rearm)
    }

    pub(crate) fn expired(&self) -> bool {
        self.watchdog.as_ref().is_some_and(Rearmable::expired)
    }

    /// Ends the episode's deadline and returns whether it expired first, in
    /// which case the supervisor's containment has ended.
    pub(crate) fn disarm(&mut self) -> bool {
        self.watchdog.as_mut().is_some_and(Rearmable::disarm)
    }

    /// Whether the supervisor verified the containment it was asked for.
    pub(crate) fn verified(&self) -> bool {
        self.supervisor.verified()
    }
}

impl fmt::Debug for RecoveryWatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryWatch")
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}
