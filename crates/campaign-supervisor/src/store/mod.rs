//! The campaign record store: one controller's durable, confined view of
//! its state directory.
//!
//! [`Store::open`] locks the state directory's own handle with an exclusive
//! `flock`, so a second controller on the directory, or a controller started
//! while a report snapshot holds the lock shared, gets [`Error::Busy`] and
//! exits 3. It refuses a directory that breaks the filesystem contract
//! below, then makes the directory and its parent durable and checks the
//! state marker before it writes anything. It then sweeps the staging
//! directory, probes no-replace rename, and writes the marker into a
//! directory that holds nothing but the staging directory.
//!
//! The first failed mutation, an `fsync` or `close` error included,
//! poisons the store: every later one fails with [`Error::Poisoned`], and
//! the controller exits 4. Only `EINTR` is retried.
//!
//! [`View::open`] resolves its root path and confines child opens beneath the pinned directory.
//! [`open_host`] and [`read_host`] read regular files such as a build's
//! executable and libraries, and archive publication copies them through create-once.
//!
//! The store's own entries are dot-named, so no [`Name`] addresses them:
//! the `.state` marker and the `.staging` directory. Records are staged in
//! `.staging` under one deterministic name per target, unlinked before it
//! is written, which is safe because one store has one writer: [`Store`]
//! is neither `Sync` nor `Clone`.
//!
//! `Store::unmark` removes the marks of a nested state directory. The
//! caller excludes writers on the nested directory while its parent
//! store removes the marks.
//!
//! # Durability
//!
//! The state directory lies on a read-write ext4 mount with a journal in
//! ordered or journal data mode and barriers enabled, or on a read-write
//! xfs mount, on Linux 5.8 or later; the running user owns it, with mode
//! 0700; and the process umask clears no owner permission bit.
//! `Store::open` refuses any other directory or umask. It checks the umask
//! once, so the umask stays so while the store is open. On such a mount an acknowledged mutation
//! survives a process crash. It survives a VM reset only when the storage
//! completes a flush after prior writes are stable, which admission cannot
//! observe. Power-loss durability is unproven.
//!
//! ```no_run
//! use campaign_supervisor::store::{Creation, Dir, Name, Read, Store};
//!
//! let store = Store::open("/var/lib/campaign".as_ref()).expect("the store opens");
//! let root: &Dir = store.root();
//! let name = Name::new("record").expect("the name is valid");
//! let created = store.create_once(root, &name, b"bytes").expect("the create runs");
//! assert_eq!(created, Creation::Created);
//! let read: Read = store.read(root, &name, 64).expect("the read runs").expect("it exists");
//! assert_eq!(read.bytes(), b"bytes");
//! store.barrier(&read).expect("the barrier runs");
//! ```
//!
//! ```compile_fail,E0603
//! // The lock token is private to the store.
//! use campaign_supervisor::store::open::Lock;
//! ```
//!
//! ```compile_fail,E0432
//! // The store exports no lock token.
//! use campaign_supervisor::store::Lock;
//! ```
//!
//! ```compile_fail,E0277
//! let store: campaign_supervisor::store::Store = Default::default();
//! ```
//!
//! ```compile_fail,E0308
//! // A store has one owner; it has no copy that a second writer could hold.
//! fn copy(store: &campaign_supervisor::store::Store) -> campaign_supervisor::store::Store {
//!     store.clone()
//! }
//! ```
//!
//! ```compile_fail,E0277
//! // A store is never shared between threads, so its staging names have
//! // one writer.
//! fn shared<T: Sync>() {}
//! shared::<campaign_supervisor::store::Store>();
//! ```
//!
//! ```compile_fail,E0308
//! // A directory handle comes only from the store's confined opens.
//! let dir = campaign_supervisor::store::Dir::from(std::fs::File::open("/").unwrap());
//! ```

pub(crate) mod cgroup;
mod dir;
mod error;
pub(crate) use error::bound_text;
mod evidence;
mod file;
mod holders;
mod host;
mod mount;
mod name;
mod open;
mod publish;
mod read;
mod reader;
mod usage;
mod view;

#[cfg(test)]
pub(crate) mod fixture;
#[cfg(test)]
mod mount_tests;
#[cfg(test)]
mod open_tests;
#[cfg(test)]
mod publish_tests;
#[cfg(test)]
mod read_tests;
#[cfg(test)]
mod usage_tests;

use std::cell::Cell;
use std::ffi::CStr;
use std::path::PathBuf;

pub use self::dir::Dir;
pub use self::error::{Error, Refusal, Unreadable};
pub(crate) use self::evidence::retained_entries;
pub use self::file::{Identity, Opened};
pub use self::holders::Holder;
pub(crate) use self::host::HardwareCustody;
pub use self::host::PrivateDir;
pub(crate) use self::host::{
    absolute_host, cgroup_present, hardware_markers, launch_paths, open_evidence, vacant_evidence,
};
pub use self::host::{
    append_host, canonical_host, create_dir, create_dirs, create_host, lexical, new_path,
    open_host, present_host, private_dir, read_host, regular_files, remove_dir, remove_host,
    remove_tree, rename_host, replace_host, subdirectories, sync_filesystem_host, sync_parent,
    trim_host,
};
pub use self::host::{names_host, typed_host};
pub use self::name::Name;
#[cfg(test)]
pub(crate) use self::publish::COPY_CHUNK;
pub use self::publish::Creation;
pub use self::read::Read;
pub(crate) use self::reader::ReadStore;
pub use self::usage::Usage;
pub use self::view::View;
pub(crate) use self::view::{ancestors, given_ancestors};

/// The staging directory's name in the state directory.
const STAGING: &CStr = c".staging";

/// The startup rename probe's file names.
const PROBE: &CStr = c"probe";
const PROBED: &CStr = c"probed";

/// The state marker's name and its exact bytes.
const MARKER: &CStr = c".state";
pub(crate) const MARKER_BYTES: &[u8] = b"campaign-supervisor state 1\n";
pub(crate) const HOUSEKEEPING_ENTRIES: [&CStr; 2] = [MARKER, STAGING];

/// The most entries the startup sweep removes from the staging directory.
/// After a crash the directory may hold the staged file of an interrupted
/// mutation, the rename probe's files, and a staged file whose unlink a VM
/// reset undid before the journal committed it; each startup empties it.
/// On ext4 and xfs a rename out of the staging directory commits its source
/// removal and its target entry in one journal transaction, so the target
/// directory's `fsync` makes both durable; on xfs the next staged file's
/// `fsync` also commits earlier cleanup unlinks.
const SWEEP_BOUND: usize = 16;

/// One controller's store over its locked state directory.
#[derive(Debug)]
pub struct Store {
    lock: open::Lock,
    path: PathBuf,
    staging: Dir,
    poisoned: Cell<bool>,
}

pub(crate) use evidence::ATTEMPT_RECORDS;
pub use evidence::EVIDENCE_BOUND;
