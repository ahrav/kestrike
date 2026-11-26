//! Disjoint accounting arithmetic for the storage and the engine budget.
//!
//! Every byte and every slot has exactly one accounting owner. The volume's
//! raw bytes partition as the extent module's `RawPartition` states; the slot
//! count `O` partitions into [`SlotPartition`]'s `free + filling + resident +
//! retired + quarantined`. A total past `usize::MAX` is [`LedgerOverflow`].

/// Charging `bytes` would push engine memory use past its limit `E`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineBudgetExceeded {
    pub limit: usize,
    pub used: usize,
    pub requested: usize,
}

pub use super::extent::LedgerOverflow;

/// Engine memory limit `E` and the bytes charged against it.
///
/// Invariant: `used <= limit`. [`charge`](Self::charge) is the only mutation;
/// nothing here refunds, so `used` never decreases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineBudget {
    limit: usize,
    used: usize,
}

impl EngineBudget {
    pub fn new(limit: usize) -> Self {
        Self { limit, used: 0 }
    }

    /// Charges `bytes`, or refuses without changing the budget.
    ///
    /// # Errors
    ///
    /// `EngineBudgetExceeded` if `used + bytes` overflows `usize` or exceeds
    /// `limit`; both carry the same `limit`, `used` and `requested` values.
    pub fn charge(&mut self, bytes: usize) -> Result<(), EngineBudgetExceeded> {
        let exceeded = || EngineBudgetExceeded {
            limit: self.limit,
            used: self.used,
            requested: bytes,
        };
        let used = self.used.checked_add(bytes).ok_or_else(exceeded)?;
        if used > self.limit {
            return Err(exceeded());
        }
        self.used = used;
        Ok(())
    }

    pub fn used(&self) -> usize {
        self.used
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    /// A budget of `usize::MAX`, which holds every test charge.
    #[cfg(test)]
    pub(crate) fn unlimited() -> Self {
        Self::new(usize::MAX)
    }
}

/// Count partition of the storage's object slots `O`.
///
/// A quarantined slot exhausted its incarnation counter and is never reissued.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SlotPartition {
    pub free: usize,
    pub filling: usize,
    pub resident: usize,
    pub retired: usize,
    pub quarantined: usize,
}

impl SlotPartition {
    /// Sum of all five terms, which equals `O` for a conserved ledger.
    ///
    /// # Errors
    ///
    /// `LedgerOverflow` if the sum exceeds `usize::MAX`.
    pub fn total(&self) -> Result<usize, LedgerOverflow> {
        checked_sum(&[
            self.free,
            self.filling,
            self.resident,
            self.retired,
            self.quarantined,
        ])
    }
}

/// Both partitions of the storage: its volume's raw bytes by phase and `O`
/// by slot state.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoolLedger {
    pub raw: super::extent::RawPartition,
    pub slots: SlotPartition,
    /// Free runs the extent allocator's full run index has left out since
    /// initialization. Each stays free and reachable through first fit; a
    /// count that keeps rising shows free runs outnumbering the index's
    /// `slot_count.div_ceil(8)` entries.
    /// A request that only unindexed runs fit is placed by address-ordered
    /// first fit through the summaries.
    pub index_drops: u64,
}

pub(super) fn checked_sum(terms: &[usize]) -> Result<usize, LedgerOverflow> {
    terms
        .iter()
        .try_fold(0usize, |acc, term| acc.checked_add(*term))
        .ok_or(LedgerOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_budget_refuses_past_limit_without_charging() {
        let mut e = EngineBudget::new(10);
        assert_eq!(e.charge(6), Ok(()));
        assert_eq!(
            e.charge(5),
            Err(EngineBudgetExceeded {
                limit: 10,
                used: 6,
                requested: 5,
            })
        );
        assert_eq!(e.used(), 6);
        assert_eq!(e.charge(4), Ok(()));
        assert_eq!(e.used(), 10);
        assert_eq!(e.charge(usize::MAX).unwrap_err().used, 10);
    }

    #[test]
    fn partitions_sum_with_checked_arithmetic() {
        let o = SlotPartition {
            free: 1,
            filling: 1,
            resident: 1,
            retired: 1,
            quarantined: 1,
        };
        assert_eq!(o.total(), Ok(5));
        let wrap = SlotPartition {
            quarantined: usize::MAX,
            free: 1,
            ..SlotPartition::default()
        };
        assert_eq!(wrap.total(), Err(LedgerOverflow));
    }
}
