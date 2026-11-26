//! `sim archive` and archive verification: one immutable worker build,
//! pinned with everything it runs with, and checked before and after each
//! use.
//!
//! An archive is a directory a [store](crate::store) wrote, holding:
//!
//! - `worker`, the executable's bytes, mode 0500;
//! - `Cargo.lock`, the exact lockfile the build resolved from, mode 0400;
//! - `lib/`, each shared library the program interpreter resolves for the
//!   executable by name, mode 0400;
//! - `build`, the [build record](crate::record::Build), written last.
//!
//! Beside them sit the store's own `.state` marker and `.staging`
//! directory, which every directory a store opens holds. The archive's
//! directory meets the store's filesystem contract: an ext4 or xfs mount,
//! owned by the running user with mode 0700.
//!
//! The record names the digest of every file above, the host program
//! interpreter's path and digest, the machine, the toolchain, the target,
//! the build-affecting environment, the checkout's revision and whether it
//! was dirty, and the native SPDK build.
//! The program interpreter stays on the host, pinned by its digest. The
//! archive's identity is the SHA-256 of the record's bytes.
//!
//! An archive path holding `:`, `;` or `$` is refused, since the loader's
//! library search path splits on `:` and `;` and expands `$` tokens, and
//! the library directory is that path's one entry. So is an executable
//! for another machine, one whose dynamic section requests an audit
//! module, and one whose interpreter maps a library by path rather than
//! resolving it by name.
//!
//! The archive's files are records the controller wrote under the
//! archive store's lock, so the [trust boundary](crate#trust-boundary)
//! applies: verification detects accidental change, and deliberate
//! same-user forgery is out of scope.
//!
//! [`archive`] is the one command that reads Cargo or the checkout; every
//! use of an archive reads only the archive and the host interpreter and
//! never builds. [`Archive::verify`] runs before each use and
//! [`Approved::finish`] after it; a failed finish is [`Unfinished`].
//!
//! # SIGCHLD
//!
//! [`build`], [`archive`], [`publish`] and [`Archive::verify`] run child
//! processes, rustc, Cargo and, for a dynamically linked executable, the
//! program interpreter's listing, and each child run sets the process's
//! SIGCHLD disposition to its default so the child's exit stays waitable:
//! an inherited `SIG_IGN` would discard it. The
//! caller gives these functions ownership of SIGCHLD for the rest of the
//! process, as [`crate::sim::sim`] takes it; the `campaign` binary is that
//! caller.
//!
//! Exit codes, from [`Error::exit`]: 0 for a published, verified archive;
//! 2 for a refused output, executable or library resolution; 3 for a
//! build failure; 4 for a failed closing checkout probe, or a build input or output that changed or vanished
//! during the command, an output directory that could not be created or
//! removed, a failed write, a host fault such as `EIO` while a check reads
//! a file, a loader listing past its deadline, or a published archive that
//! fails its verification. A use whose archive fails [`Archive::verify`]
//! exits by the same rule, `Invalid::exit` before a worker ran.

mod build;
mod command;
mod elf;
mod error;
mod loader;
mod path;
mod publish;
mod run;
mod verify;

#[cfg(test)]
mod build_tests;
#[cfg(test)]
mod elf_tests;
#[cfg(test)]
mod loader_tests;
#[cfg(test)]
pub(crate) mod publish_tests;
#[cfg(test)]
mod run_tests;

pub use self::build::build;
pub use self::error::{Error, Invalid, Unfinished};
use self::path::{LIBRARIES, LIBRARY_BOUND, LOCK, RECORD, WORKER, host, name, searchable, vacant};
pub use self::publish::{Built, archive, publish};
pub(crate) use self::run::{Unsuccessful, output};
pub use self::verify::{Approved, Archive};
