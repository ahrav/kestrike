//! The caller's surface of the readiness machine over an attached volume: `begin_replay` and `complete_replay` from the owner thread, and the storage's `withdraw` from any thread.
//!
//! ALLOCATION-READY: the RESET path has zero admitted bindings, so a matching subscription moves the volume from `Loaded` to `Live` at `begin_replay`; a warm bootstrap's restored bindings move it to `Replaying`, and `complete_replay` at the feed's tip reaches `Live`. Until `Live`, every fill reservation and builder promise refuses `Bootstrapping`.

use super::super::coverage::FeedContract;
use super::super::device::Disk;
use super::super::os::Platform;
use super::super::owner::Storage;
use super::super::readiness::{Event, ReadinessError, State};
use super::attach::Volume;
use super::report::RecoveryPhase;

impl<'s, 'a, P: Platform, D: Disk> Volume<'s, 'a, P, D> {
    /// `readiness` reads the volume's recovery readiness.
    pub fn readiness(&self) -> State {
        self.storage.readiness.state()
    }

    /// `begin_replay` begins replay under a subscription to `feed` resuming after feed position `from`, zero before the first event. The volume recovers no feed position, so a subscription of another feed contract, or one resuming past zero, withholds the attempt; a matching one over zero admitted bindings reaches `Live`, and one over the warm bootstrap's restored bindings enters `Replaying`, which [`complete_replay`](Self::complete_replay) ends.
    ///
    /// # Errors
    ///
    /// `NotReady` before the load completed, `AlreadyLive` after replay began, `Ended` once withheld or closed.
    pub fn begin_replay(&mut self, feed: FeedContract, from: u64) -> Result<State, ReadinessError> {
        let rows = self.restored_rows();
        let matches = feed == self.storage.feed && from == 0;
        let began = self
            .storage
            .readiness
            .apply(Event::BeginReplay { matches, rows });
        if began.is_ok_and(|state| matches!(state, State::Replaying | State::Live)) {
            self.recovery.count(RecoveryPhase::Replay, (1, rows));
        }
        if began.is_ok() {
            self.authority_ready();
            self.observe_recovery();
        }
        began
    }

    /// The restored bindings replay accounts for: the warm bootstrap's.
    pub(super) fn restored_rows(&self) -> u64 {
        self.metadata.warm.as_ref().map_or(0, |warm| warm.rows())
    }

    /// `complete_replay` reports that replay reached the feed's tip under the subscription `begin_replay` began, which reaches `Live`.
    ///
    /// # Errors
    ///
    /// `NotReady` before replay began, `AlreadyLive` once live, `Ended` once withheld or closed.
    pub fn complete_replay(&mut self) -> Result<State, ReadinessError> {
        let completed = self.storage.readiness.apply(Event::CompleteReplay);
        if completed == Ok(State::Live) {
            self.authority_ready();
            self.recovery.count(RecoveryPhase::Replay, (1, 0));
            self.observe_recovery();
        }
        completed
    }
}

impl<P: Platform> Storage<P> {
    /// `feed_contract` is the feed whose subscription `begin_replay` matches.
    pub fn feed_contract(&self) -> FeedContract {
        self.feed
    }

    /// The caller holds no pool gate: the call waits for it.
    ///
    /// `withdraw` handles health loss or serving-authority withdrawal: one compare-and-swap moves the readiness to `Withheld`, then the call passes the pool gate once, so every fill reservation that read `Live` under the gate completed before it returns and every later one refuses. Granted leases keep their rights, no count changes and no in-flight fill is cancelled.
    /// `withdraw` returns the word's state after the gate pass, so a close that lands while the call waits reads `Closed`.
    ///
    /// Calling `withdraw` before the attach makes the volume start `Withheld`.
    pub fn withdraw(&self) -> State {
        let _ = self.readiness.apply(Event::Withdraw);
        if let Some(access) = self.live_pool().and_then(|pool| pool.lock()) {
            access.release();
        }
        self.readiness.state()
    }

    /// [`withdraw`](Self::withdraw) for a caller that must not wait: the compare-and-swap to `Withheld`, then one nonblocking attempt at the pool gate. `true` means the gate passed, a poisoned gate or an absent pool included, so every fill reservation that read `Live` under the gate completed; on `false` the caller retries.
    pub(crate) fn try_withdraw(&self) -> bool {
        let _ = self.readiness.apply(Event::Withdraw);
        match self.live_pool().map(|pool| pool.try_lock_quiet()) {
            Some(Ok(access)) => {
                access.release();
                true
            }
            Some(Err(super::super::gate::GateError::Contended)) => false,
            Some(Err(super::super::gate::GateError::Poisoned)) | None => true,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_pool_gate_held<R>(&self, during: impl FnOnce() -> R) -> R {
        let access = self
            .live_pool()
            .and_then(|pool| pool.try_lock_quiet().ok())
            .expect("an uncontended live pool gate");
        let result = during();
        access.release();
        result
    }
}
