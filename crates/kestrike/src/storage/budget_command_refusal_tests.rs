//! A storage command is a compound charge of CPU steps, one operation and aligned transfer bytes. A refusal
//! names the first short dimension in the order CPU, operations, bytes, and changes no dimension of the budget.
//!
//! Every budget here starts from the same history, a few steps of two kinds and one earlier command, so the
//! counters, the used amounts and the remainders are all nonzero before the command under test and an equality
//! against the copy taken before the call compares values a partial debit would move.

use super::budget::{BudgetDimension, BudgetShort, WorkBudget, WorkCounters, WorkKind};

/// CPU steps the command under test is issued with.
const STEPS: usize = 3;
/// Aligned transfer bytes the command under test moves.
const BYTES: usize = 4096;
/// Steps and bytes of the history every budget carries before the command under test.
const EARLIER_COMPARISONS: usize = 2;
const EARLIER_COMMAND_STEPS: usize = 1;
const EARLIER_COMMAND_BYTES: usize = 512;

/// Which dimensions leave the command under test one unit short.
#[derive(Debug, Clone, Copy)]
struct Short {
    cpu: bool,
    operations: bool,
    bytes: bool,
}

impl Short {
    /// The dimension a refusal names: the first short one in the order CPU, operations, bytes.
    fn first(self) -> Option<BudgetDimension> {
        if self.cpu {
            Some(BudgetDimension::Cpu)
        } else if self.operations {
            Some(BudgetDimension::Operations)
        } else if self.bytes {
            Some(BudgetDimension::Bytes)
        } else {
            None
        }
    }
}

/// A budget whose history is spent and whose remainders fund the command under test exactly, less one unit in
/// each dimension `short` names.
fn budget_after_history(short: Short) -> WorkBudget {
    let steps = EARLIER_COMPARISONS + EARLIER_COMMAND_STEPS + STEPS - usize::from(short.cpu);
    let operations = 1 + 1 - usize::from(short.operations);
    let bytes = EARLIER_COMMAND_BYTES + BYTES - usize::from(short.bytes);
    let mut budget = WorkBudget::with_io(steps, operations, bytes);
    budget
        .debit_n(WorkKind::Comparison, EARLIER_COMPARISONS)
        .expect("the history's comparisons are funded");
    budget
        .debit_command(
            WorkKind::Visit,
            EARLIER_COMMAND_STEPS,
            EARLIER_COMMAND_BYTES,
        )
        .expect("the history's command is funded in every dimension");
    budget
}

/// What the accessors report of `budget`: remaining steps, the counters, operations used and remaining, bytes
/// used and remaining.
fn observed(budget: &WorkBudget) -> (usize, WorkCounters, [usize; 4]) {
    (
        budget.remaining(),
        budget.counters(),
        [
            budget.operations_used(),
            budget.operations_remaining(),
            budget.bytes_used(),
            budget.bytes_remaining(),
        ],
    )
}

/// The seven budgets short in one, two or three dimensions.
fn shortfalls() -> Vec<Short> {
    let mut all = Vec::new();
    for mask in 1..8u8 {
        all.push(Short {
            cpu: mask & 1 != 0,
            operations: mask & 2 != 0,
            bytes: mask & 4 != 0,
        });
    }
    all
}

/// For each of the seven shortfalls, the preflight and the debit both refuse naming the first short dimension, and
/// the refused debit leaves the budget equal to the copy taken before it: remaining steps, every counter,
/// operations and bytes used and remaining.
#[test]
fn a_refused_command_names_the_first_short_dimension_and_changes_nothing() {
    let mut failures = Vec::new();
    for short in shortfalls() {
        let dimension = short.first().expect("every shortfall names a dimension");
        let expected = Err(BudgetShort { dimension });
        let mut budget = budget_after_history(short);
        let before = budget;
        let before_observed = observed(&before);

        let preflight = budget.preflight_command(STEPS, BYTES);
        if preflight != expected {
            failures.push(format!(
                "{short:?}: preflight returned {preflight:?}, expected {expected:?}"
            ));
        }
        if budget != before {
            failures.push(format!(
                "{short:?}: the preflight changed the budget to {budget:?}"
            ));
        }

        let debit = budget.debit_command(WorkKind::Update, STEPS, BYTES);
        if debit != expected {
            failures.push(format!(
                "{short:?}: debit returned {debit:?}, expected {expected:?}"
            ));
        }
        if budget != before {
            failures.push(format!(
                "{short:?}: the refused debit changed the budget from {before:?} to {budget:?}"
            ));
        }
        let after_observed = observed(&budget);
        if after_observed != before_observed {
            failures.push(format!(
                "{short:?}: the refused debit changed what the accessors report from {before_observed:?} to {after_observed:?}"
            ));
        }
        // The history's own amounts, stated by the test, not read back from the budget alone.
        let history = (
            STEPS - usize::from(short.cpu),
            WorkCounters {
                comparisons: EARLIER_COMPARISONS,
                visits: EARLIER_COMMAND_STEPS,
                ..WorkCounters::default()
            },
            [
                1,
                1 - usize::from(short.operations),
                EARLIER_COMMAND_BYTES,
                BYTES - usize::from(short.bytes),
            ],
        );
        if after_observed != history {
            failures.push(format!(
                "{short:?}: after the refusal the accessors report {after_observed:?}, the history left {history:?}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "a refused storage command must name the first short dimension and change nothing:\n{}",
        failures.join("\n")
    );
}

/// The control: with exact allowances the same command is funded, the preflight accepts and changes nothing, and
/// the debit takes every dimension to zero, adding the steps to the command's kind alone.
#[test]
fn a_command_with_exact_allowances_debits_every_dimension_to_zero() {
    let funded = Short {
        cpu: false,
        operations: false,
        bytes: false,
    };
    assert_eq!(funded.first(), None);
    let mut budget = budget_after_history(funded);
    let before = budget;

    assert_eq!(budget.preflight_command(STEPS, BYTES), Ok(()));
    assert_eq!(budget, before, "an accepted preflight debits nothing");

    assert_eq!(budget.debit_command(WorkKind::Update, STEPS, BYTES), Ok(()));
    assert_eq!(
        observed(&budget),
        (
            0,
            WorkCounters {
                comparisons: EARLIER_COMPARISONS,
                visits: EARLIER_COMMAND_STEPS,
                updates: STEPS,
                ..WorkCounters::default()
            },
            [2, 0, EARLIER_COMMAND_BYTES + BYTES, 0],
        ),
        "the funded command spends its steps, one operation and its bytes, each to zero"
    );

    // With every dimension at zero, one more command of nonzero steps is short everywhere and names CPU.
    let spent = budget;
    assert_eq!(
        budget.debit_command(WorkKind::Update, STEPS, BYTES),
        Err(BudgetShort {
            dimension: BudgetDimension::Cpu
        })
    );
    assert_eq!(budget, spent, "the refusal at zero changes nothing");
}
