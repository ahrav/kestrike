//! The host stop controller's `run` command over the library of [`host_stop`](crate::host_stop).
//!
//! [`entry`] reads the game-day catalog and the operator file, then [`Controller::run`] takes the
//! run's seven steps through one [`Context`]: the call, the two clocks and the sleep, the file steps,
//! the signal record, the environment read at the tool's start, the two output streams, the
//! catalog's path, the tree's top and the two size limits.
//!
//! The run holds these invariants. No call precedes a refusal of the first step, and
//! `sts get-caller-identity` is the first call. `ec2 stop-instances` leaves at most once, with the
//! CLI's retries off, and only while no cause of an abort is set. Every call of the seven steps is
//! cut at [`CALL_SECONDS`](crate::host_stop::CALL_SECONDS), at the run's deadline and at the end of
//! the window it reads for, each on the monotonic clock; the abort path runs with no deadline, so its
//! one status read is cut at [`CALL_SECONDS`](crate::host_stop::CALL_SECONDS) alone. Once `roles.json`
//! counts as written, the run ends in the abort path or with exit 0, and a panic in the steps takes
//! the abort path with cause `exception`; a panic inside the abort path itself reaches [`entry`],
//! which exits 2 and names the marks that stand. The panic's path needs the unwinding strategy, and
//! the module refuses to build under any other.
//!
//! A signal raises at a read of the record: after arming, before each call starts, before the stop
//! request counts as sent, in each slice of a call's wait, after each call returns and before its
//! reply is used, in each slice of a pause, before each mark's write takes its hold, at the end of
//! each mark's write, and at the end of each armed span. Before `injection/` is made it ends the run
//! with exit 2; from there to the end of the roles' write it waits; later it takes the abort path.
//! The abort path and the final `stopped.json` run unarmed, after a panic as well.
//!
//! [`entry`] is the command's one path. The other public items are the steps the cases take alone,
//! and each assumes the state the run's earlier steps set. The run acts with its starter's authority
//! in the evidence directory and trusts that directory and the package file it names.

#[cfg(not(panic = "unwind"))]
::core::compile_error!(
    "the host stop controller's abort path after a panic needs panic = \"unwind\""
);

mod context;
mod controller;
mod fault;
mod restore;
mod run;
mod seal;

pub use context::{Command, Context};
pub use controller::{Controller, Preflight};
pub use fault::{Aborted, Fault, Halt};
pub use run::entry;
