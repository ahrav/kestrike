//! The caller's advance of the applied feed position.

use std::sync::atomic::Ordering;

use super::super::os::Platform;
use super::super::owner::Storage;
use super::super::readiness::State;
use super::exhausted;

/// How an accepted advance changed the applied position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advance {
    /// The position rose to the advanced value.
    Advanced,
    /// The position already equaled the advanced value.
    Unchanged,
}

/// Why an advance changed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageError {
    /// Position zero names no event.
    Zero,
    /// Storage admission or coverage admission is closed, or the attached volume's attempt is withheld or closed.
    Closed,
    /// The attached volume's attach gate has not passed, its load has not completed, or its replay has not begun.
    NotReady,
    /// The applied position already exceeds the advanced value.
    Regressed { applied: u64 },
}

impl<P: Platform> Storage<P> {
    /// Advances the applied coverage position to `position`.
    ///
    /// The caller promises that every feed event at or below `position` reached [`invalidate`](Self::invalidate) and returned `Ok`, each return happening before this call, and serializes its advances for its feed contract. The advance is one `Release` `fetch_max` and acknowledges nothing: an invalidation's acknowledgment is its coverage page write.
    ///
    /// # Errors
    ///
    /// `Zero`, then `Closed` when storage admission or coverage admission is closed, then `NotReady` before the attached volume's replay began, its attach gate included, and `Closed` once its attempt is withheld or closed, then `Regressed` when the applied position is higher; none changes the position.
    pub fn advance_coverage(&self, position: u64) -> Result<Advance, CoverageError> {
        if position == 0 {
            return Err(CoverageError::Zero);
        }
        let Some(pool) = self.live_pool() else {
            return Err(CoverageError::Closed);
        };
        let words = pool.journal_words();
        if self.is_closed() || exhausted(&words.epochs) {
            return Err(CoverageError::Closed);
        }
        let (state, awaiting_gate) = self.readiness.state_and_attach_gate();
        match state {
            State::Detached if awaiting_gate => {
                return Err(CoverageError::NotReady);
            }
            State::Loading | State::Loaded => return Err(CoverageError::NotReady),
            State::Withheld | State::Closed => {
                return Err(CoverageError::Closed);
            }
            State::Detached | State::Replaying | State::Live => {}
        }
        let applied = words.applied.fetch_max(position, Ordering::Release);
        match applied.cmp(&position) {
            std::cmp::Ordering::Less => Ok(Advance::Advanced),
            std::cmp::Ordering::Equal => Ok(Advance::Unchanged),
            std::cmp::Ordering::Greater => Err(CoverageError::Regressed { applied }),
        }
    }
}
