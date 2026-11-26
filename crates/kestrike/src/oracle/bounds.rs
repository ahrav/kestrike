//! Finite history and search limits; exhausting the search budget yields
//! `Inconclusive::SearchBound` naming the limit.

use super::verdict::Inconclusive;

pub(crate) const MAX_KEYS: usize = 2;
pub(crate) const MAX_LABELS_PER_KEY: usize = 2;
pub(crate) const MAX_HOLDERS: usize = 2;
pub(crate) const HISTORY_BOUND: usize = 128;
pub(crate) const SEARCH_BOUND: u32 = 4096;
/// Largest metadata plus body length one label may declare.
pub(crate) const MAX_CONTENT_BYTES: usize = 16 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SearchBudget {
    limit: u32,
    spent: u32,
    high_water: u32,
}

impl SearchBudget {
    pub(crate) const fn new(limit: u32) -> Self {
        Self {
            limit,
            spent: 0,
            high_water: 0,
        }
    }

    pub(crate) const fn per_key() -> Self {
        Self::new(SEARCH_BOUND)
    }

    pub(crate) fn expand(&mut self) -> Result<(), Inconclusive> {
        if self.spent >= self.limit {
            return Err(Inconclusive::SearchBound { limit: self.limit });
        }
        self.spent += 1;
        self.high_water = self.high_water.max(self.spent);
        Ok(())
    }

    pub(crate) const fn high_water(&self) -> u32 {
        self.high_water
    }

    pub(crate) fn start_key(&mut self) {
        self.spent = 0;
    }
}
