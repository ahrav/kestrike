//! The extent allocator of one volume: a free-unit bitmap under radix run summaries, a capped best-fit index of the bitmap's maximal free runs in one B+ tree per run length below 256 units and one for longer runs, and the raw-byte ledger.
//!
//! Invariants owned by this module:
//!
//! - Bitmap truth: one bit per [`IO_UNIT`](super::IO_UNIT), set while the unit is free; bits past the volume stay clear, and the set bits count the ledger's free units.
//!   Held extents are clear runs, pairwise disjoint and inside the volume; a return sets its extent's bits, so the extent and its free neighbours form one run.
//! - Summary agreement: after every call each summary node holds the free run at its start, its longest free run and the free run at its end, over the bitmap below it.
//! - Index: every entry is a maximal free run keyed `(len.min(2^24 - 1), start)`, and the index holds at most [`index_capacity`] entries.
//!   While it has dropped none it holds every maximal free run; an offer to a full index keeps the larger key of the offered run and the smallest entry, and a dropped run stays free in the bitmap.
//! - Fit rule: a reservation of `n` units takes the smallest indexed key at least `(n, 0)`, the exact best fit among indexed runs shorter than `2^24 - 1` units and the lowest start among indexed runs of at least `2^24 - 1` units, and keeps the run's low `n` units.
//!   When the index holds no fitting run, address-ordered first fit through the summaries places it; a root whose longest run is below `n` refuses after one read.
//! - Bounded work: a reservation or a return counts every bitmap word and summary node its searches and its held check read, the reads a full recomputation of the summaries over its marked units makes, and every index node its lookups, insertions and removals read or rebalance, and [`work_bound`] bounds that count from the volume, the slot count and the largest extent.
//!   A reservation preflights the limit its caller passes, refuses `NoFit` before any change when its search's visits exceed the limit, and debits its visits capped at the limit; a return counts its visits and debits nothing; a release or a service call charges the count to its caller's budget, and a reservation rollback returns uncharged within the bound the reservation preflighted.
//! - Placeable count: the root holds the full-extent charge `c`, fixed at initialization and kept by a restore, and the sum over the maximal free runs of each run's largest multiple of `c`, at most the free units.
//!   A reservation of `n` units from the low end of a run of `L` units changes it by `f(L - n) - f(L)`, a return joining `low..start` and `end..high` by `f(high - low) - f(start - low) - f(high - end)`, and a bulk fill sets it to the sum of `f` over the runs it frees, with `f(L) = L - L mod c`; each update takes maximal free-run lengths from the bitmap, from an index entry that names one, or from the runs a bulk fill marks, so the count is the same whichever runs the index drops.
//! - Ledger conservation: [`RawPartition`] transitions keep metadata fixed; metadata, free, reserved, resident, retired, and waste sum to the volume's raw bytes after every call.
//! - Fixed tables: the allocator borrows its root record, its space words and its index nodes ([`index_table_nodes`] for the slot count) from the caller, initializes them in place and keeps their sizes fixed; every call runs without heap allocation.
//! - Every refusal leaves the bitmap, the summaries, the index, the placeable count and the ledger unchanged; a `NoFit` or `Ledger` refusal debits its search's visits capped at the limit, and a `Length` or `BudgetExhausted` refusal debits nothing.
//! - An [`ExtentLocator`] packs a start below `2^37` and a length below `2^24` units and decodes to exactly those values; its record-end tail changes neither.

mod allocator;
#[cfg(test)]
mod allocator_tests;
mod bitmap;
#[cfg(test)]
mod bitmap_tests;
#[cfg(test)]
mod free_runs;
mod index;
#[cfg(test)]
mod index_tests;
mod locator;
mod partition;
#[cfg(test)]
mod partition_tests;
mod plan;
#[cfg(test)]
mod replay_tests;
mod summary;
#[cfg(test)]
mod summary_tests;

pub(crate) use allocator::{
    ExtentAllocator, ExtentRefusal, ExtentRoot, empty_placeable, index_capacity, index_table_nodes,
    space_words, work_bound,
};
pub(crate) use index::RunNode;
pub use locator::{ExtentLocator, LOCATOR_LEN_LIMIT, LOCATOR_START_LIMIT, LocatorError};
pub(crate) use partition::HeldPhase;
pub use partition::{LedgerOverflow, RawPartition};
