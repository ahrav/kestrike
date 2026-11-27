//! A game-day controller and `scripts/gameday-judge.py` share the GD-2 package rules.
//!
//! Each rule returns a value or a [`Refusal`] that holds the judge's sentence; where several refusals
//! apply, the rule returns the one the judge raises first.

mod catalog;
mod constants;
mod evidence;
mod exact;
mod layout;
mod listing;
mod order;
mod package;
mod parse;
mod reach;
mod read;
mod refusal;
mod schema;
mod seal;
#[cfg(test)]
mod test_support;

pub use crate::decimal::Decimal;
pub use catalog::gd2_entry;
pub use constants::{CATALOG, FILE_LIMIT, TBD};
pub use evidence::{
    Evidence, admit, collected, layout_of, load_evidence, package_of, read_evidence,
};
pub use exact::{exact, shown};
pub use layout::{LAYOUT, REQUEST, VERSION, VERSION_FIELDS, layout};
pub use listing::{entries, open_dir};
pub use order::{ends_observation, later, ordered};
pub use package::{FleetBounds, check_package};
pub use parse::{decode, parsed};
pub use reach::roles_reach;
pub use read::{ReadError, read_file};
pub use refusal::{Refusal, need};
pub use schema::{Each, Names, Scalar, Schema, conform, encodable, finite};
