//! The production modules the join kernel runs, included by path: the fill
//! record word and the fill row's terminal word.

#[path = "../../../../../crates/kestrike/src/storage/fill.rs"]
pub(crate) mod fill;
#[path = "../../../../../crates/kestrike/src/storage/row.rs"]
pub(crate) mod row;
