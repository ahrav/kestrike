//! Finite allowances for storage operations, in three dimensions.
//!
//! A [`WorkBudget`] carries CPU steps, planned storage operations and aligned
//! transfer bytes. Each dimension is conserved on its own: its used and
//! remaining amounts always sum to the amount the budget was built with.
//!
//! ## Debit before work
//!
//! A budgeted operation debits its steps before it performs the work, one at
//! a time or all at once for work of known fixed cost. A budget with zero
//! CPU steps therefore performs zero CPU-budgeted work, and exhaustion is
//! its own outcome, [`BudgetExhausted`], separate from success and from a
//! miss. Counters record spent steps by [`WorkKind`]. The reader's scan,
//! which runs between two sequence loads, preflights its geometry's whole
//! bound before the first load, so every debit inside that window succeeds;
//! the snapshot module documents the bound.
//!
//! ## Bundles and preflight
//!
//! An operation whose work comes in indivisible bundles calls
//! [`WorkBudget::preflight`] for the whole bundle and debits it only on
//! success. A refusal leaves the allowance, the operation's next action and
//! its cursor where they were. A failed [`WorkBudget::debit_n`] spends the
//! remaining steps. Prepayment is final: an action charged and then skipped
//! stays charged.
//!
//! ## Storage commands
//!
//! A planned storage command is a compound charge: one operation, its aligned
//! transfer bytes and the CPU steps that issue it.
//! [`WorkBudget::debit_command`] checks all three dimensions before it debits
//! any, so a refusal names the short dimension and leaves every dimension
//! unchanged. [`WorkBudget::new`] grants CPU steps with zero operations and
//! zero bytes, so a budget built for CPU-only work, such as allocator return
//! and coalescing, refuses every command. A budget that funds storage
//! commands is built with [`WorkBudget::with_io`].
//!
//! ## Debiting at the end of a bounded run
//!
//! A bounded run that tracks how far the remaining allowance pays for it,
//! such as a fill table scan or a service pass, may debit its totals when it
//! ends: a fill table scan when it returns, a service pass when it returns
//! or unwinds. It takes only steps the allowance pays
//! for, and it leaves the counters and the remainder exactly as per-step
//! debits would.

/// The allowance cannot fund the requested step or bundle.
///
/// This outcome is separate from success and from every capacity refusal. The
/// caller's inputs stay intact and are reusable with a fresh budget. Each
/// operation documents whether its refusal spent the remaining steps, as a
/// failed [`WorkBudget::debit_n`] does, or left the allowance unchanged, as
/// [`WorkBudget::preflight`] does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetExhausted;

/// One independently conserved dimension of a [`WorkBudget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetDimension {
    /// CPU steps, counted by [`WorkKind`].
    Cpu,
    /// Planned storage commands, one per read or write.
    Operations,
    /// Aligned transfer bytes of planned storage commands.
    Bytes,
}

/// A compound charge refused because `dimension` could not fund it.
///
/// A refusal changes no dimension of the budget. When more than one
/// dimension is short, the first in the order CPU, operations, bytes is
/// named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetShort {
    /// The dimension that could not fund the charge.
    pub dimension: BudgetDimension,
}

/// The kind of work one step pays for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkKind {
    /// One ordering comparison, such as a key or predicate test.
    Comparison,
    /// One nonblocking coordination attempt, such as a pool `try_lock`.
    CoordinationAttempt,
    /// One allocation-record, slot or search-node visit.
    Visit,
    /// One fixed state update.
    Update,
    /// One step of a hash derivation, charged before the pass it
    /// pays for.
    Hash,
}

/// Steps spent so far, one field per [`WorkKind`] variant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkCounters {
    pub comparisons: usize,
    pub coordination_attempts: usize,
    pub visits: usize,
    pub updates: usize,
    pub hashes: usize,
}

/// A finite allowance that is debited before each unit of work.
///
/// Invariant: in the CPU dimension, `spent + remaining` equals the initial
/// steps and the sum of the counters equals `spent`. In each I/O dimension,
/// `used + remaining` equals the initial amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct WorkBudget {
    operations: Allowance,
    bytes: Allowance,
    counters: WorkCounters,
    remaining: usize,
}

/// One I/O dimension of a [`WorkBudget`]. Each `spend` that meets its
/// precondition keeps `remaining <= initial`, so `used() <= initial` and
/// `used() + remaining == initial`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Allowance {
    initial: usize,
    remaining: usize,
}

impl Allowance {
    fn new(amount: usize) -> Self {
        Self {
            initial: amount,
            remaining: amount,
        }
    }

    /// The caller must ensure `amount <= remaining`; `debit_command` ensures
    /// it through `preflight_command`.
    fn spend(&mut self, amount: usize) {
        self.remaining -= amount;
    }

    fn used(&self) -> usize {
        self.initial - self.remaining
    }
}

impl WorkBudget {
    /// An allowance of `steps` CPU steps, zero operations and zero bytes,
    /// with every counter at zero.
    pub fn new(steps: usize) -> Self {
        Self::with_io(steps, 0, 0)
    }

    /// An allowance of `steps` CPU steps, `operations` planned storage
    /// commands and `bytes` aligned transfer bytes, every counter at zero.
    pub fn with_io(steps: usize, operations: usize, bytes: usize) -> Self {
        Self {
            operations: Allowance::new(operations),
            bytes: Allowance::new(bytes),
            counters: WorkCounters::default(),
            remaining: steps,
        }
    }

    /// Debits one step of `kind`, or refuses without changing anything when the
    /// allowance is already spent. Callers debit before doing the work.
    ///
    /// # Errors
    ///
    /// `BudgetExhausted` if `remaining` is zero; the counters stay unchanged.
    #[inline]
    pub fn debit(&mut self, kind: WorkKind) -> Result<(), BudgetExhausted> {
        self.debit_n(kind, 1)
    }

    /// Debits `steps` steps of `kind` at once, with exactly the outcome of
    /// `steps` single debits: an allowance short of `steps` is spent to zero
    /// and the call refuses. Callers use this for work of known fixed cost.
    ///
    /// # Errors
    ///
    /// `BudgetExhausted` if fewer than `steps` remained; those that remained
    /// are debited.
    #[inline]
    pub fn debit_n(&mut self, kind: WorkKind, steps: usize) -> Result<(), BudgetExhausted> {
        let counter = self.counters.of_kind(kind);
        match self.remaining.checked_sub(steps) {
            Some(remaining) => {
                self.remaining = remaining;
                *counter += steps;
                Ok(())
            }
            None => Err(spend_rest(&mut self.remaining, counter)),
        }
    }

    /// Whether `steps` more steps could be debited. Nothing is debited and
    /// nothing changes either way.
    ///
    /// # Errors
    ///
    /// `BudgetExhausted` if fewer than `steps` remain.
    #[inline]
    pub fn preflight(&self, steps: usize) -> Result<(), BudgetExhausted> {
        if self.remaining >= steps {
            Ok(())
        } else {
            Err(BudgetExhausted)
        }
    }

    /// Whether one planned storage command moving `bytes` aligned transfer
    /// bytes, issued with `steps` CPU steps, is affordable in every
    /// dimension. Nothing changes either way.
    ///
    /// # Errors
    ///
    /// [`BudgetShort`] naming the first short dimension.
    #[inline]
    pub fn preflight_command(&self, steps: usize, bytes: usize) -> Result<(), BudgetShort> {
        let short = if self.remaining < steps {
            BudgetDimension::Cpu
        } else if self.operations.remaining == 0 {
            BudgetDimension::Operations
        } else if self.bytes.remaining < bytes {
            BudgetDimension::Bytes
        } else {
            return Ok(());
        };
        Err(BudgetShort { dimension: short })
    }

    /// Debits one planned storage command: one operation, its `bytes`
    /// aligned transfer bytes and `steps` CPU steps of `kind`, all or none.
    /// Callers debit before submitting the command.
    ///
    /// # Errors
    ///
    /// [`BudgetShort`] naming the first short dimension, as
    /// [`WorkBudget::preflight_command`] reports it. Every dimension and
    /// every counter stays unchanged.
    #[inline]
    pub fn debit_command(
        &mut self,
        kind: WorkKind,
        steps: usize,
        bytes: usize,
    ) -> Result<(), BudgetShort> {
        self.preflight_command(steps, bytes)?;
        self.remaining -= steps;
        *self.counters.of_kind(kind) += steps;
        self.operations.spend(1);
        self.bytes.spend(bytes);
        Ok(())
    }

    /// CPU steps left.
    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// CPU steps spent so far, by kind.
    pub fn counters(&self) -> WorkCounters {
        self.counters
    }

    /// Planned storage commands left.
    pub fn operations_remaining(&self) -> usize {
        self.operations.remaining
    }

    /// Planned storage commands debited so far.
    pub fn operations_used(&self) -> usize {
        self.operations.used()
    }

    /// Aligned transfer bytes left.
    pub fn bytes_remaining(&self) -> usize {
        self.bytes.remaining
    }

    /// Aligned transfer bytes debited so far.
    pub fn bytes_used(&self) -> usize {
        self.bytes.used()
    }
}

impl WorkCounters {
    fn of_kind(&mut self, kind: WorkKind) -> &mut usize {
        match kind {
            WorkKind::Comparison => &mut self.comparisons,
            WorkKind::CoordinationAttempt => &mut self.coordination_attempts,
            WorkKind::Visit => &mut self.visits,
            WorkKind::Update => &mut self.updates,
            WorkKind::Hash => &mut self.hashes,
        }
    }
}

/// The refusing arm of [`WorkBudget::debit_n`]: moves every remaining step
/// into `counter` and returns the refusal.
///
/// `#[cold]` asks the compiler to lay this block out after the success
/// path. `#[inline]` lets the refusal inline at the call site, because
/// loops that debit until refusal and zero-budget calls reach this arm as a
/// routine outcome.
#[cold]
#[inline]
fn spend_rest(remaining: &mut usize, counter: &mut usize) -> BudgetExhausted {
    *counter += *remaining;
    *remaining = 0;
    BudgetExhausted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_is_the_last_field() {
        assert_eq!(
            std::mem::offset_of!(WorkBudget, remaining),
            std::mem::size_of::<WorkBudget>() - std::mem::size_of::<usize>()
        );
    }

    #[test]
    fn zero_budget_refuses_before_any_work() {
        let mut budget = WorkBudget::new(0);
        assert_eq!(budget.debit(WorkKind::Comparison), Err(BudgetExhausted));
        assert_eq!(budget.remaining(), 0);
        assert_eq!(budget.counters(), WorkCounters::default());
    }

    #[test]
    fn each_debit_moves_one_step_into_its_kind() {
        let mut budget = WorkBudget::new(3);
        assert_eq!(budget.debit(WorkKind::Comparison), Ok(()));
        assert_eq!(budget.debit(WorkKind::Visit), Ok(()));
        assert_eq!(budget.debit(WorkKind::Visit), Ok(()));
        assert_eq!(budget.debit(WorkKind::Update), Err(BudgetExhausted));
        assert_eq!(budget.remaining(), 0);
        assert_eq!(
            budget.counters(),
            WorkCounters {
                comparisons: 1,
                coordination_attempts: 0,
                visits: 2,
                updates: 0,
                hashes: 0,
            }
        );
    }

    #[test]
    fn bulk_debit_matches_single_debits_and_spends_a_short_rest() {
        let mut singles = WorkBudget::new(5);
        for _ in 0..3 {
            singles.debit(WorkKind::Visit).unwrap();
        }
        let mut bulk = WorkBudget::new(5);
        assert_eq!(bulk.debit_n(WorkKind::Visit, 3), Ok(()));
        assert_eq!(bulk, singles);
        // Three steps asked of two remaining: the two are spent, as three
        // single debits would have spent them, and the call refuses.
        assert_eq!(bulk.debit_n(WorkKind::Update, 3), Err(BudgetExhausted));
        assert_eq!(singles.debit(WorkKind::Update), Ok(()));
        assert_eq!(singles.debit(WorkKind::Update), Ok(()));
        assert_eq!(singles.debit(WorkKind::Update), Err(BudgetExhausted));
        assert_eq!(bulk, singles);
        assert_eq!(bulk.remaining(), 0);
        assert_eq!(bulk.counters().updates, 2);
        // Zero steps is a no-op, even on an exhausted budget.
        assert_eq!(bulk.debit_n(WorkKind::Visit, 0), Ok(()));
        assert_eq!(bulk.counters().visits, 3);
    }

    /// A preflight refuses a bundle the allowance cannot cover and changes
    /// nothing either way, where the same request through `debit_n` spends
    /// the rest.
    #[test]
    fn preflight_refuses_without_spending() {
        let mut budget = WorkBudget::new(2);
        assert_eq!(budget.preflight(3), Err(BudgetExhausted));
        assert_eq!(budget.preflight(2), Ok(()));
        assert_eq!(budget.preflight(0), Ok(()));
        assert_eq!(budget, WorkBudget::new(2));
        assert_eq!(budget.debit_n(WorkKind::Visit, 3), Err(BudgetExhausted));
        assert_eq!(budget.remaining(), 0);
        assert_eq!(budget.preflight(0), Ok(()));
        assert_eq!(budget.preflight(1), Err(BudgetExhausted));
    }

    #[test]
    fn maximum_budget_debits_without_overflow() {
        let mut budget = WorkBudget::new(usize::MAX);
        assert_eq!(budget.debit(WorkKind::CoordinationAttempt), Ok(()));
        assert_eq!(budget.remaining(), usize::MAX - 1);
        assert_eq!(budget.counters().coordination_attempts, 1);
        assert_eq!(budget.debit_n(WorkKind::Visit, usize::MAX - 1), Ok(()));
        assert_eq!(budget.remaining(), 0);
        assert_eq!(budget.counters().visits, usize::MAX - 1);
    }

    #[test]
    fn bulk_debit_matches_single_debits_including_the_short_case() {
        let mut bulk = WorkBudget::new(2);
        assert_eq!(bulk.debit_n(WorkKind::Comparison, 3), Err(BudgetExhausted));
        let mut single = WorkBudget::new(2);
        assert_eq!(single.debit(WorkKind::Comparison), Ok(()));
        assert_eq!(single.debit(WorkKind::Comparison), Ok(()));
        assert_eq!(single.debit(WorkKind::Comparison), Err(BudgetExhausted));
        assert_eq!(bulk, single);
        assert_eq!(bulk.remaining(), 0);
        assert_eq!(bulk.counters().comparisons, 2);

        let mut exact = WorkBudget::new(3);
        assert_eq!(exact.debit_n(WorkKind::Comparison, 3), Ok(()));
        assert_eq!(exact.remaining(), 0);
        assert_eq!(exact.counters().comparisons, 3);
        assert_eq!(exact.debit_n(WorkKind::Update, 0), Ok(()));
        assert_eq!(exact.debit_n(WorkKind::Update, 1), Err(BudgetExhausted));
        assert_eq!(exact.counters().updates, 0);
    }

    /// Checks `used + remaining == initial` per dimension with checked
    /// arithmetic, so a wrapped counter fails instead of passing.
    fn assert_conserved(budget: &WorkBudget, steps: usize, operations: usize, bytes: usize) {
        let c = budget.counters();
        let spent = [
            c.comparisons,
            c.coordination_attempts,
            c.visits,
            c.updates,
            c.hashes,
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add);
        assert_eq!(
            spent.and_then(|s| s.checked_add(budget.remaining())),
            Some(steps)
        );
        assert_eq!(
            budget
                .operations_used()
                .checked_add(budget.operations_remaining()),
            Some(operations)
        );
        assert_eq!(
            budget.bytes_used().checked_add(budget.bytes_remaining()),
            Some(bytes)
        );
    }

    #[test]
    fn exact_allowances_debit_one_command_to_zero() {
        let mut budget = WorkBudget::with_io(3, 1, 4096);
        assert_eq!(budget.preflight_command(3, 4096), Ok(()));
        assert_eq!(budget.debit_command(WorkKind::Hash, 3, 4096), Ok(()));
        assert_eq!(budget.remaining(), 0);
        assert_eq!(
            budget.counters(),
            WorkCounters {
                hashes: 3,
                ..WorkCounters::default()
            }
        );
        assert_eq!(
            (budget.operations_remaining(), budget.operations_used()),
            (0, 1)
        );
        assert_eq!((budget.bytes_remaining(), budget.bytes_used()), (0, 4096));
        assert_conserved(&budget, 3, 1, 4096);
    }

    /// With each dimension one short in turn, the compound charge names
    /// that dimension and every dimension and counter is unchanged, where
    /// `debit_n` would have spent the CPU rest.
    #[test]
    fn a_short_dimension_refuses_the_command_and_changes_nothing() {
        let cases = [
            (WorkBudget::with_io(2, 1, 8), BudgetDimension::Cpu),
            (WorkBudget::with_io(3, 0, 8), BudgetDimension::Operations),
            (WorkBudget::with_io(3, 1, 7), BudgetDimension::Bytes),
        ];
        for (budget, short) in cases {
            let mut charged = budget;
            let refusal = Err(BudgetShort { dimension: short });
            assert_eq!(charged.preflight_command(3, 8), refusal);
            assert_eq!(charged.debit_command(WorkKind::Visit, 3, 8), refusal);
            assert_eq!(charged, budget);
        }
        // Several short dimensions name the first in CPU, operations, bytes
        // order.
        let none = WorkBudget::new(0);
        assert_eq!(
            none.preflight_command(1, 1),
            Err(BudgetShort {
                dimension: BudgetDimension::Cpu
            })
        );
        assert_eq!(
            WorkBudget::with_io(1, 0, 0).preflight_command(1, 1),
            Err(BudgetShort {
                dimension: BudgetDimension::Operations
            })
        );
    }

    /// `new` grants CPU steps only: any command, even one moving zero bytes
    /// with zero steps, needs an operation and is refused, while CPU debits,
    /// preflight and spend-rest behave as on any CPU budget.
    #[test]
    fn a_cpu_only_budget_has_no_io_authority() {
        let mut budget = WorkBudget::new(usize::MAX);
        assert_eq!(
            (budget.operations_remaining(), budget.bytes_remaining()),
            (0, 0)
        );
        assert_eq!(
            budget.debit_command(WorkKind::Update, 0, 0),
            Err(BudgetShort {
                dimension: BudgetDimension::Operations
            })
        );
        assert_eq!(budget, WorkBudget::new(usize::MAX));
        assert_eq!(budget.preflight(usize::MAX), Ok(()));
        assert_eq!(budget.debit(WorkKind::Visit), Ok(()));
        assert_eq!(
            budget.debit_n(WorkKind::Visit, usize::MAX),
            Err(BudgetExhausted)
        );
        assert_eq!(budget.remaining(), 0);
        assert_eq!(budget.counters().visits, usize::MAX);
        assert_eq!((budget.operations_used(), budget.bytes_used()), (0, 0));
        assert_conserved(&budget, usize::MAX, 0, 0);
    }

    /// Every dimension conserves across a mixed sequence at maximum values:
    /// commands, CPU debits, a spend-rest refusal and preflights.
    #[test]
    fn every_dimension_conserves_at_the_extrema() {
        let max = usize::MAX;
        let mut budget = WorkBudget::with_io(max, max, max);
        assert_eq!(budget.debit_command(WorkKind::Update, 1, max - 1), Ok(()));
        assert_conserved(&budget, max, max, max);
        assert_eq!(budget.debit_command(WorkKind::Update, 0, 1), Ok(()));
        assert_eq!(budget.bytes_remaining(), 0);
        assert_eq!(
            budget.debit_command(WorkKind::Update, 0, 1),
            Err(BudgetShort {
                dimension: BudgetDimension::Bytes
            })
        );
        // A zero-byte command still needs and spends one operation.
        assert_eq!(budget.debit_command(WorkKind::Visit, 0, 0), Ok(()));
        assert_eq!(budget.operations_used(), 3);
        assert_eq!(budget.preflight(max - 1), Ok(()));
        assert_eq!(
            budget.debit_n(WorkKind::Comparison, max),
            Err(BudgetExhausted)
        );
        assert_eq!(budget.remaining(), 0);
        assert_conserved(&budget, max, max, max);
        assert_eq!(
            budget.debit_command(WorkKind::Visit, 1, 0),
            Err(BudgetShort {
                dimension: BudgetDimension::Cpu
            })
        );
        assert_conserved(&budget, max, max, max);
        assert_eq!((budget.operations_used(), budget.bytes_used()), (3, max));
    }
}
