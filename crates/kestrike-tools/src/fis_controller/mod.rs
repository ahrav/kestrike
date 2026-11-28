//! What every phase of the FIS controller records and waits on, as a library: the receipt's `fis`
//! section with its verdict rules, the write of a file whole or not at all, the custody marker, the
//! marks, the deadline rules and the seam a phase takes. The controller starts
//! `scripts/hardware-lane.py`, which reads the marks and writes the observer log this module appends
//! to.
//!
//! - [`Section`] records a failure only while none stands, and its two replacing rules keep the
//!   replaced reason as `diagnostic`.
//! - [`write_file`] leaves at a path's name the previous version or the new text whole, and syncs the
//!   directories it changes.
//! - [`Marker`] names what is in doubt and is durable while the fault is in doubt.
//! - [`Marks`] appends each mark's event before it writes the mark.
//! - [`Deadlines`] reads the monotonic clock for each deadline it cuts at, so no wait or call passes
//!   the earliest of them.
//!
//! Each function returns a value or a [`Failure`] and prints nothing. The module makes no call and
//! starts no process of its own; a phase makes those through a [`Seam`].
//!
//! The module trusts the directories its caller names: it writes and removes the marks, the marker
//! and the files under them by name with the caller's authority and checks no owner.

mod deadline;
mod failure;
mod marker;
mod marks;
mod seam;
mod section;
mod whole;

pub use deadline::{Deadlines, call, duration, now, seconds};
pub use failure::{Failure, SystemError};
pub use marker::{Marker, Moment, Progress};
pub use marks::{FAULT_END, FAULT_START, Marks, OBSERVER_SECONDS, ROLE, event, observer};
pub use seam::{Case, Launch, Seam};
pub use section::{NVME_IO_TIMEOUT, Opening, Owned, Section, Status, Verdict, kernel_timeout};
pub use whole::{create_partial, make_directory, write_file, write_file_by};
