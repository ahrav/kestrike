//! The host stop controller's commands `run`, `restore` and `seal` over the library of
//! [`host_stop`](crate::host_stop).
//!
//! [`entry`] reads the game-day catalog and the operator file, then runs one command through one
//! [`Context`]: the call, the two clocks and the sleep, the file steps, the signal record, the
//! environment read at the tool's start, the two output streams, the catalog's path, the tree's top
//! and the two size limits. [`Controller::run`] takes the run's seven steps; [`Controller::restore`]
//! and [`Controller::seal`] state their own signal points and lock spans: `restore` holds the lock
//! of `injection/` from after its stop and identity checks through its mark's write and raises a
//! signal in its caller check and its poll (exit 1), and `seal` makes no call, holds the lock through
//! its collection and its mark's write, and raises a signal from the lock to the mark's write, which
//! writes nothing (exit 2).
//!
//! The run holds these invariants. No call precedes a refusal of the first step, and
//! `sts get-caller-identity` is the first call. `ec2 stop-instances` leaves at most once, with the
//! CLI's retries off, and only while no cause of an abort is set. Every call of the seven steps is
//! cut at [`CALL_SECONDS`](crate::host_stop::CALL_SECONDS), at the run's deadline and at the end of
//! the window it reads for, each on the monotonic clock; the abort path runs with no deadline, so its
//! one status read is cut at [`CALL_SECONDS`](crate::host_stop::CALL_SECONDS) alone. Each `until` a
//! step takes applies only where the step supplies one; the observation's end decides which alarm
//! read is the last and caps the pause before it, and cuts no read. Once `roles.json` counts as
//! written, the run enters the abort path or ends with exit 0, and a panic in the steps enters the
//! abort path with cause `exception`. A mark counts as written once its write returns with the mark
//! standing; a panic between a mark's link and that return leaves the mark standing and uncounted.
//! In the abort path a panic in a mark's write or in the status read and its line is caught and
//! reported, and the path returns 1; a panic elsewhere in it reaches [`entry`], which exits 2 and
//! names the marks the run counted. The panic's path needs the unwinding strategy, and the module
//! refuses to build under any other.
//!
//! A stored signal raises at a read of the record made while the record is armed and unheld: at
//! the run's start, which also ends a hold an earlier run left, before each call starts, before the
//! stop request counts as sent, after each call returns and before its reply is used, after the stop
//! request's return reading, before the stop is taken as shown, before each mark's write takes its
//! hold, at the end of each mark's write that succeeds, and at the end of each armed span that
//! returns, refuses or aborts. The system seam also reads it before the child starts, in each slice
//! of a call's wait and in each slice of a sleep. A failed mark write or a failed or panicking span
//! keeps its own end and leaves the signal stored. A signal raised before `injection/` is made ends
//! the run with exit 2; one stored after the last read before `injection/` waits to the end of the
//! roles' write, and later ones take the abort path. The abort path and the final `stopped.json` run
//! unarmed, after a panic as well.
//!
//! [`entry`] is each command's one path. The other public items, [`Controller::restore`] and
//! [`Controller::seal`] included, are the steps the cases take alone: each assumes the state the
//! earlier steps set, and leaves to [`entry`] the disarm of the record and the end of its hold after
//! a panic. The run acts with its starter's authority
//! in the evidence directory and trusts that directory, every directory above it, and the package
//! file it names: it reaches the evidence root and `injection/` by name at each step, and the lock
//! of `injection/` excludes another run, restore or seal of the directory it opened, and keeps no
//! directory under its name. The process that starts a command ignores `SIGXFSZ` so a write past
//! the file size limit returns an error to the step.
//!
//! A run holds the lock while removing `injection/`.

#[cfg(not(panic = "unwind"))]
::core::compile_error!(
    "the host stop controller's abort path after a panic needs panic = \"unwind\""
);

mod checks;
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
