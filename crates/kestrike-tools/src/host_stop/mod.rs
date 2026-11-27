//! The host stop controller's layer over the system: a mark's write, the evidence lock, the probe and
//! the lookup, the one `aws` child of a call, the two clocks, the sleep and the signal record. Each
//! failure is a typed value that carries the system's error, and a command composes its sentence from
//! that value.
//!
//! The file steps are the methods of [`Files`], and the call, the clocks and the sleep the methods of
//! [`Seam`]; a command takes each as a value, so a test substitutes one step. The module starts `aws`
//! and no other program. A signal raises at a read of the [`Record`], which a command makes between
//! its steps and which a wait or a sleep makes at least once a [`SLICE`].

mod evidence;
mod files;
mod launch;
mod mark;
mod record;
mod seam;

pub use evidence::{Lock, LockError, ProbeError, lock, probe, stands};
pub use files::{Disk, Files, Links, proc_path};
pub use launch::{AWS, Call, CallFailed, Ended, launch};
pub use mark::{Step, Unwritten, publish, sync_directory};
pub use record::{DELIVERED, Delivered, Interrupted, Record, SLICE, Signal, install};
pub use seam::{Seam, System, sleep};
