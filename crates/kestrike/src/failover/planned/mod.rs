//! Planned exits of a serving owner. The [`request`] codec authenticates each request under a [`RequestKey`], and
//! [`Ledger::admit`] classifies an authenticated request against one owner tenure and its serving state.
//!
//! Each planned exit machine governs one serving tenure.

pub mod machine;
pub mod request;

pub use machine::{
    Certified, Deadline, DeadlineError, ExitKind, Input, Planned, Position, Published, StartError,
    State, Step, Then, Transferred,
};
pub use request::{
    AuthenticatedRequest, Binding, Kind, Ledger, OPERATIONS_MAX, PlannedRequest, REQUEST_LEN,
    RequestError, RequestKey, SCHEMA, Sequence, decode, encode,
};
