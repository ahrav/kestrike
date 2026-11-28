//! The rules that read a game-day package for GD-2: a file's bytes, strict JSON, the layout's schemas, the
//! package, GD-2's catalog entry and the reach's conditions before the stop. The evidence layout is
//! stated in the section "The evidence layout, the rules and the record" of `docs/agents/ci.md`. A caller checks the package, reads the roles mark against the names the
//! package gives, and then reads the reach's conditions from the two.
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

pub use crate::decimal::Decimal;
pub use catalog::gd2_entry;
pub use constants::{CATALOG, FILE_LIMIT, TBD};
pub use exact::{exact, shown};
pub use layout::{LAYOUT, REQUEST, VERSION, VERSION_FIELDS, layout};
pub use package::{FleetBounds, check_package};
pub use parse::{decode, parsed};
pub use reach::roles_reach;
pub use read::{ReadError, read_file};
pub use refusal::{Refusal, need};
pub use schema::{Each, Names, Scalar, Schema, conform, encodable, finite};
