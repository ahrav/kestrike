//! Batch lookup: `n` ready keys into `n` caller-owned result slots, one
//! independent scalar outcome per key, on one exclusively borrowed
//! registration.
//!
//! The batch is the scalar lookup applied in input order: each element
//! pins its own interval, makes its own attempts within
//! `retries`, reserves its own credit and right, takes its own witness and
//! stores its own result after its pin has ended. Repeated keys acquire
//! distinct rights, never a shared lease. A later element's refusal never
//! touches an earlier element's lease; close or invalidation may land between
//! elements and the elements after it see it as the scalar path does. Each
//! element runs the scalar path in full, in input order, on the reused
//! scalar scratch, so `BatchMax` bounds the batch width alone.
//!
//! Before any element runs, the call is checked as a whole: the width
//! against `BatchMax` (zero without an index) and the output length against
//! the key count, both fixed-size argument checks that cost no budget; then
//! the admission cutoff, so an empty batch after close is `Closed` and an
//! empty batch before it succeeds without hashing or pinning; then the slot
//! checks, prepaid at one comparison each and refused at the first occupied
//! slot without dropping or replacing the lease it holds; then the result
//! writes, prepaid at one update each. A budget that cannot pay either
//! prepayment refuses with the outputs untouched, and a structural refusal
//! reads no key byte and writes no output. The prepayment is accounting: it
//! is what makes the result writes free of any later budget decision.
//!
//! Once the shared budget is spent, each remaining element's lookup refuses
//! `Contended` before hashing anything, or `Closed` once admission has
//! closed, and its result is written like any other; the batch never returns
//! fewer results than keys.
//!
//! What the batch adds is the lookup preparation of the `prepare` module,
//! a [`Preparation`] on the call's stack over this storage: it derives
//! element `i + DEPTH`'s route and stages element
//! `i + STAGE`'s search lines before element `i` runs, keys are hashed in
//! aligned groups of the hasher's lane width, and each element takes the
//! entry derived for its own index and key. Element `i`'s ordinal is `i`.
//! The prologue primes the first `DEPTH` routes and stages the first
//! `STAGE` before element 0 runs, so element 0's reads wait on the misses
//! its own search would take and the elements after it arrive alongside.
//! Each element's key is copied into its context, and its lease carries
//! that copy; the caller's key slice is read only during the call. The
//! element still reads its summary, copies, validates and acquires under
//! its own pin exactly as the scalar path does. Each element debits its
//! guard bundle and its hash charge where the scalar path does, so a budget
//! that cannot pay them refuses `Contended` with the same counters. Routes
//! are derived ahead only while the remaining budget covers one element's
//! guard bundle and hash charge (`AHEAD`), so the routes derived ahead go
//! unused when an earlier element spends the last of that budget.

use super::budget::{WorkBudget, WorkKind};
use super::lease::ExtentLease;
use super::lookup::LookupError;
use super::os::Platform;
use super::prepare::{AHEAD, Preparation};
use super::register::Registration;
use crate::index::Key;

/// One caller-owned result slot: empty on entry, one scalar outcome on a
/// completed batch. A lease is not `Clone`, so a buffer is built as
/// `[const { None }; N]` or with `std::iter::repeat_with(|| None)`.
pub type BatchSlot<'s, P> = Option<Result<ExtentLease<'s, P>, LookupError>>;

/// Why no element of a batch ran. No key byte was read, no output written,
/// no interval pinned and nothing reserved; only the budget may have moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchError {
    /// More keys than `BatchMax`, which is zero without an index.
    TooWide { width: usize, max: usize },
    /// The output slice is not as long as the key slice.
    LengthMismatch { keys: usize, outputs: usize },
    /// Admission is closed.
    Closed,
    /// The budget could not prepay the slot checks and result writes.
    BudgetExhausted,
    /// The output at `index` already holds a result.
    Occupied { index: usize },
}

impl From<super::budget::BudgetExhausted> for BatchError {
    fn from(_: super::budget::BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

impl<'s, P: Platform> Registration<'s, P> {
    /// Looks up every key of `keys` in order into the matching slot of
    /// `outputs`, each through the scalar lookup's path with its own
    /// `retries`, the shared `budget` and its route from the lookahead. See
    /// the module documentation for the checks
    /// that precede the first element and the fill that follows a spent
    /// budget.
    ///
    /// # Errors
    ///
    /// [`BatchError`] before any element runs; every output is then as the
    /// caller passed it.
    pub fn lookup_batch(
        &mut self,
        keys: &[Key],
        outputs: &mut [BatchSlot<'s, P>],
        retries: usize,
        budget: &mut WorkBudget,
    ) -> Result<(), BatchError> {
        let storage = self.storage();
        let max = storage
            .index()
            .map_or(0, |index| index.geometry.batch_max());
        let width = keys.len();
        if width > max {
            return Err(BatchError::TooWide { width, max });
        }
        if outputs.len() != width {
            return Err(BatchError::LengthMismatch {
                keys: width,
                outputs: outputs.len(),
            });
        }
        if storage.is_closed() {
            return Err(BatchError::Closed);
        }
        budget.debit_n(WorkKind::Comparison, width)?;
        if let Some(index) = outputs.iter().position(Option::is_some) {
            return Err(BatchError::Occupied { index });
        }
        budget.debit_n(WorkKind::Update, width)?;
        // `live`: a later element can still pay its guard bundle and a
        // route. Budgets never refill and `close` is permanent, so once less
        // than that remains or an outcome is `Closed`, subsequent elements
        // are refused before reading a route.
        let mut live = budget.remaining() >= AHEAD;
        let mut preparation = Preparation::new(storage);
        if live {
            preparation.prime(keys, 0);
        }
        for (i, (key, slot)) in keys.iter().zip(outputs.iter_mut()).enumerate() {
            #[cfg(test)]
            super::lookup::interpose(super::lookup::Pause::Element);
            let prepared = preparation.take(i, key);
            if live {
                preparation.advance(keys, i);
            }
            let outcome = self.lookup_prepared(&prepared, retries, budget);
            live = budget.remaining() >= AHEAD && !matches!(outcome, Err(LookupError::Closed));
            *slot = Some(outcome);
        }
        Ok(())
    }
}
