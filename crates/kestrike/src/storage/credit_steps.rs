//! One record's credit words and the per-record steps the parked-credit
//! models run over them: the Loom `credit_model` uses loom atomics and the
//! GenMC credit kernel uses `std` atomics. Each step calls the production
//! `credit` steps at the model's [`Strength`], so the two checkers explore
//! the same owner take and return. The GenMC kernel runs the per-record
//! scan here; the Loom model runs the `lease` module's production scan.

use std::sync::atomic::Ordering;

use super::credit::{BitWord, CreditWord, Strength, credits, drain, park, take};
#[cfg(not(loom))]
use super::credit::{clear, reset};

/// The record's bit in its map word.
pub(crate) const BIT: u64 = 1;

/// One record's pool and return line and its map word.
pub(crate) struct Record<W, M> {
    pub(crate) pool: W,
    pub(crate) line: W,
    pub(crate) map: M,
}

impl<W: CreditWord, M: BitWord> Record<W, M> {
    /// The credits both words hold.
    pub(crate) fn held(&self) -> usize {
        credits(&self.pool, Ordering::Acquire) + credits(&self.line, Ordering::Acquire)
    }

    /// Whether neither word is left below zero.
    pub(crate) fn owes_nothing(&self) -> bool {
        (self.pool.load(Ordering::Acquire) as isize) >= 0
            && (self.line.load(Ordering::Acquire) as isize) >= 0
    }

    /// Whether a record holding credits has its bit set, so the next scan
    /// finds them.
    pub(crate) fn discoverable(&self) -> bool {
        self.held() == 0 || self.map.load(Ordering::Acquire) & BIT == BIT
    }

    /// The returner's steps: `returns` parks of one credit on the line.
    pub(crate) fn give_back<S: Strength>(&self, returns: usize) {
        for _ in 0..returns {
            park::<S, _, _>(&self.line, &self.map, BIT, 1);
        }
    }

    #[cfg(not(loom))]
    fn try_both<S: Strength>(&self) -> usize {
        let taken = take::<S, _, _>(&self.line, &self.map, BIT, 1);
        if taken > 0 {
            taken
        } else {
            take::<S, _, _>(&self.pool, &self.map, BIT, 1)
        }
    }

    /// The scan's per-record steps, returning the credits taken: a flagged
    /// record's return line, then its pool; a record that showed nothing
    /// has its bit cleared and both words reloaded, and one found holding
    /// credits after the clear gets its bit back and is tried again.
    #[cfg(not(loom))]
    pub(crate) fn scan<S: Strength>(&self) -> usize {
        if self.map.load(Ordering::Acquire) & BIT == 0 {
            return 0;
        }
        let taken = self.try_both::<S>();
        if taken > 0 {
            return taken;
        }
        clear::<S, _>(&self.map, BIT);
        if credits(&self.pool, S::RELOAD) + credits(&self.line, S::RELOAD) == 0 {
            return 0;
        }
        reset(&self.map, BIT);
        self.try_both::<S>()
    }

    /// The owner's take: its pool first, then its return line drained into
    /// the pool.
    pub(crate) fn owner_take<S: Strength>(&self) -> usize {
        if credits(&self.pool, Ordering::Relaxed) > 0
            && take::<S, _, _>(&self.pool, &self.map, BIT, 1) == 1
        {
            return 1;
        }
        if credits(&self.line, Ordering::Relaxed) == 0 {
            return 0;
        }
        let returned = drain::<S, _, _>(&self.line, &self.map, BIT);
        if returned == 0 {
            return 0;
        }
        if returned > 1 {
            park::<S, _, _>(&self.pool, &self.map, BIT, returned - 1);
        }
        1
    }
}
