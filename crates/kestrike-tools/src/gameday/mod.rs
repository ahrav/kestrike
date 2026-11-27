//! A game-day controller and `scripts/gameday-judge.py` share the GD-2 package rules.
//!
//! Each rule returns a value or a [`Refusal`] that holds the judge's sentence; where several refusals
//! apply, the rule returns the one the judge raises first.

mod catalog;
mod constants;
mod exact;
mod layout;
mod package;
mod parse;
mod reach;
mod read;
mod refusal;
mod schema;
#[cfg(test)]
mod test_support;

pub use catalog::gd2_entry;
pub use constants::{
    ATTEMPTS_MAX, CATALOG, CAUSES, FILE_LIMIT, FLEET_BOUNDS, KINDS, MAX_INTERVALS, MIN_OWNED,
    MIN_STOOD, OBSERVATION_FILES, OUTCOMES, PACKAGE, TBD, WITNESS, WRITTEN_CLAUSES,
    WRITTEN_EXPECTED, WRITTEN_GUARDRAILS, WRITTEN_REACH,
};
pub use exact::{Decimal, exact, shown};
pub use layout::{LAYOUT, PACKAGE_SCHEMA, REQUEST, VERSION, WINDOW, layout};
pub use package::{FleetBounds, check_package};
pub use parse::{decode, parsed};
pub use reach::roles_reach;
pub use read::{ReadError, read_file};
pub use refusal::{Refusal, need};
pub use schema::{Each, Names, Scalar, Schema, calendar, conform, encodable, finite};
