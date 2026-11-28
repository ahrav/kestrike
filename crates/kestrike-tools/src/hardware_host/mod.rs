//! The host-side records of a hardware campaign: the observer log of an episode, the host reservation,
//! the custody markers that quarantine the host, and the identity of a launch. The FIS controller
//! starts `scripts/hardware-lane.py`, which writes the same log and markers.
//!
//! - [`Observer::append`] writes one JSON object per line under an exclusive `flock` and numbers each
//!   event one past the count of nonblank lines it read under that lock, so two writers never assign
//!   one ordinal twice; a caller's field named `ordinal` takes the place of the assigned one.
//!   [`Observer::events`] reads under a shared `flock`. Every open of the log refuses a link at its
//!   name.
//! - A lock is taken by nonblocking attempts. One reading of the monotonic clock before the first
//!   attempt fixes the deadline; each attempt another holder refuses is followed by one reading, which
//!   ends the wait at or past the deadline, and else by a sleep of [`POLL`] that reads the signal
//!   record.
//! - [`reserve_host`] takes `fis.lock` exclusively, and [`Reservation::spawn_holding`] passes its
//!   descriptor to a child, which then holds the lock after the parent's value drops while it keeps
//!   that descriptor open. A caller reserves the host before it reads the custody markers.
//! - [`held_custody`] removes a marker only when it names another boot, or a group none of whose
//!   processes reads as holding memory: a zombie or a dead task counts as ended, a thread group
//!   leader whose other threads run included, and a `stat` record that cannot be read counts as no
//!   process.
//!
//! The locks are `flock` locks of an open file description, which exclude each other across processes and
//! threads on a local filesystem; where a filesystem emulates `flock` with POSIX record locks, as NFS
//! does, they exclude processes alone, so a caller then appends from one thread of a process at a time.
//!
//! Each function returns a value or a typed error and prints nothing. The clocks and the sleep are one
//! [`Clocks`] value; [`held_custody`] takes `/proc` and the boot identity's path as arguments, and
//! [`Observer::append`] reads the node name from the fixed path [`NODE`].
//!
//! The module trusts the directories and paths its caller names: it opens the observer directory, the
//! custody directory and the mappings file by name with the caller's authority and checks no owner.

mod clock;
mod custody;
mod launch;
mod observer;
mod reservation;
#[cfg(test)]
#[path = "within_tests.rs"]
mod within;

pub use clock::{Clocks, System};
pub use custody::{BOOT_ID, CustodyError, boot_id, held_custody};
pub use launch::{RevisionError, git_revision, mappings_facts};
pub use observer::{EventError, NODE, Observer, ObserverError, POLL};
pub use reservation::{Reservation, reserve_host};
