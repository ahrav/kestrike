//! [`store`] is the record store over one state directory, which one
//! controller holds under an exclusive lock; [`record`] encodes and
//! verifies the records it holds and derives their identities;
//! [`protocol`] parses the simulation worker's output; [`archive`] builds
//! the worker once into an immutable archive and verifies the archive
//! before and after each use; [`sim`] runs and inspects the archived
//! worker under the launch contract and records each command's class; and
//! [`exit`] enumerates the exit codes of every command family.
//! The `campaign` binary maps each outcome to its exit code; the mechanisms
//! live in this library. The store's raw system call numbers are those of
//! 64-bit Linux.
//!
//! # Trust boundary
//!
//! - Trusted: the kernel, this crate's own binary, and the records the
//!   controller wrote under its lock.
//! - Accidentally faulty: launcher and worker output. The fault model
//!   covers truncated, oversized, stale, mistyped or wrong-attempt output.
//! - Out of scope: deliberate forgery by other code running as the
//!   controller's user, which could already trace the controller. Such code
//!   may still leave faulty state by accident, which the store's checks
//!   cover. The state directory is mode 0700 and owned by the running
//!   user.
//!
//! - Toolchain and host inputs: Cargo's, git's and the program
//!   interpreter's output, and the host's libraries and interpreter, are
//!   accidentally faulty like worker output. `sim archive` refuses output
//!   it cannot parse into one result, and an archive pins the host files
//!   by digest and checks them before each use.
//!
//! State-directory record reads are bounded regular-file reads beneath
//! the store's or a [`store::View`]'s handles, and a [`record::Verified`]
//! record comes only from such a read that passes the record read rule.
//! An archive's digests stream each archived or host file to its end, and
//! [`store::open_host`], [`store::read_host`] and [`store::canonical_host`] follow symlinks.
//! Child-process output is read up to a byte bound. The store's authority
//! types carry private
//! fields, and code outside their modules obtains them through the store's
//! constructors. A unit test checks that only `store` and the system call
//! module call the filesystem, and `deny(unsafe_code)` in the library and
//! the binary confines `unsafe` to that module.
//!
//! [`attempt::Completed`] has private fields and carries the verified finish
//! with its optional bound artifact. Settlement consumes it and re-reads the
//! frozen manifest and complete attempt history before selecting a result.
//!
//! # Exit codes
//!
//! [`exit::Exit`] tags each exit with its command family. Each code's
//! meaning is documented on its variant.
//!
//! | Code | [`exit::Sim`] | [`exit::Supervisor`] |
//! | --- | --- | --- |
//! | 0 | `Counts` | `Success` |
//! | 1 | `Complete` | `Verdict` |
//! | 2 | `Rejected` | `Rejected` |
//! | 3 | `BuildFailure` | `Busy` |
//! | 4 | `Incomplete` | `Held` |
//! | 5 | `Interrupted` | |
//! | 6 | `Watchdog` | |

#![deny(unsafe_code)]

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod archive;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod attempt;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod custody;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod campaign;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod hardware;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod layout;

pub mod exit;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod protocol;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod record;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod sim;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod store;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod step;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[allow(unsafe_code)]
mod sys;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod choke_point_tests;

/// The most entries one listing reads, and the total entry budget of one
/// whole-tree storage measurement. The charged census applies it to each
/// directory it lists. A listing of more entries is refused, and a write
/// whose projected entry count would exceed it holds.
pub const SCAN_BOUND: usize = 65_536;

/// The scan bound every listing, census and projection in the crate uses:
/// [`SCAN_BOUND`], or the lower bound a test's step script sets.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) fn scan_bound() -> usize {
    step::scan_bound(SCAN_BOUND)
}
