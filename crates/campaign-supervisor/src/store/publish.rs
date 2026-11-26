//! The durable mutations: create-once, replace, directory creation, delete,
//! directory removal, targeted staging cleanup, nested state marks removal, and
//! the prerequisite barrier. Each runs under [`Store::guard`], so the
//! state directory's identity is checked before and after it, and its
//! failure poisons the store. The reads of a nested state directory,
//! [`Store::marks_removable`], run outside the guard and leave the store unpoisoned when they fail.
//!
//! Create-once and replace stage the bytes under the target's one
//! deterministic staging name: unlink a stale one, create it exclusively,
//! write, `fsync`, `close`, rename it onto the target, then `fsync` the
//! target's directory. Create-once renames with `RENAME_NOREPLACE`, so an
//! existing target keeps its bytes and the call reports
//! [`Creation::Existing`]; it still syncs the directory, so a target an
//! earlier controller linked before its sync is durable when this call
//! returns. A filesystem without no-replace rename fails the startup probe,
//! so [`Store::open`] refuses it before any create-once runs. Directory
//! creation, delete, directory removal and the removal of a nested state
//! directory's marks end with the parent directory's `fsync`. Each
//! create passes its exact mode, 0600 for a record file, the caller's
//! owner bits for a copy, and 0700 for a directory, which
//! [`Store::open`]'s umask check leaves unnarrowed.
//!
//! Only the target directory is synced after a rename out of `.staging`:
//! on ext4 and xfs the rename's source removal and target entry commit in
//! one journal transaction, which that `fsync` makes durable. A staged
//! name that a crash or VM reset leaves behind is never read as a record,
//! since no [`Name`] addresses `.staging`, and the next startup removes
//! it.
//!
//! A publication is durable as far as its directory's own entry is. The
//! state directory is synced at startup, and [`Store::mkdir`] syncs the
//! parent whether or not it created the directory, so a target directory
//! obtained through `mkdir` in this process is durable before anything is
//! published into it.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Write as _};

use super::dir::{changed, sync};
use super::{Dir, Error, Name, Opened, Read, Store};
use crate::step::{self, Step};
use crate::sys;

pub(crate) const COPY_CHUNK: usize = 64 << 10;

/// The permission bits of a published record file.
pub(super) const FILE_MODE: u32 = 0o600;

/// The bytes a publication stages: a slice written whole, or a stream
/// copied through a buffer.
pub(super) enum Source<'a> {
    Bytes(&'a [u8]),
    Stream(&'a mut dyn io::Read),
}

/// Whether a create-once or directory creation made its entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Creation {
    /// This call created the entry.
    Created,
    /// The entry existed, and this call left it unchanged.
    Existing,
}

impl Store {
    pub(crate) fn launcher_output(
        &self,
        dir: &Dir,
        name: &Name,
    ) -> Result<Option<std::process::Stdio>, Error> {
        self.guard(dir, || {
            let flags =
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NONBLOCK | libc::O_NOCTTY;
            let file = match step::call(Step::Open, || {
                sys::open_beneath(&dir.file, name.as_c_str(), flags, FILE_MODE)
            }) {
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(None),
                result => result?,
            };
            step::call(Step::Sync, || file.sync_all())?;
            sync(dir)?;
            Ok(Some(std::process::Stdio::from(file)))
        })
    }

    /// Publishes `bytes` as the new file `name` in `dir` unless an entry
    /// has that name. An acknowledged [`Creation::Created`] in a durable
    /// directory, the root or one from [`Store::mkdir`], is durable as the
    /// [store's durability contract](super#durability) states and reads
    /// back exactly `bytes`.
    ///
    /// # Errors
    ///
    /// [`Error::Poisoned`] after an earlier failure, [`Error::Replaced`]
    /// when the state directory was replaced, [`Error::Refused`] when its
    /// owner or mode changed, and [`Error::Io`] for a failed call; each but
    /// the first poisons the store.
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub fn create_once(&self, dir: &Dir, name: &Name, bytes: &[u8]) -> Result<Creation, Error> {
        self.guard(dir, || {
            self.publish(dir, name.as_c_str(), Source::Bytes(bytes), FILE_MODE, true)
        })
    }

    /// Releases the target's interrupted staging file before an allocation
    /// preflight. The store lock excludes concurrent publication, and the
    /// staging-directory sync makes the release durable, including a retry
    /// whose staged name is already absent.
    ///
    /// # Errors
    ///
    /// As [`Store::create_once`]; a failed lookup, unlink or sync poisons
    /// the store.
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub(crate) fn clear_staged(&self, dir: &Dir, name: &Name) -> Result<(), Error> {
        self.guard(dir, || {
            let staged = staging_name(dir, name.as_c_str());
            match step::call(Step::Open, || {
                sys::open_beneath(&self.staging.file, &staged, libc::O_PATH, 0)
            }) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return sync(&self.staging);
                }
                opened => drop(opened?),
            }
            step::call(Step::Unlink, || sys::unlink(&self.staging.file, &staged))?;
            sync(&self.staging)
        })
    }

    pub(crate) fn create_once_if(
        &self,
        dir: &Dir,
        name: &Name,
        bytes: &[u8],
        commit: impl FnOnce() -> bool,
    ) -> Result<Option<Creation>, Error> {
        self.guard(dir, || {
            let staged = self.stage(dir, name.as_c_str(), Source::Bytes(bytes), FILE_MODE)?;
            if !commit() {
                step::call(Step::Unlink, || sys::unlink(&self.staging.file, &staged))?;
                sync(&self.staging)?;
                return Ok(None);
            }
            self.commit(dir, name.as_c_str(), &staged, true).map(Some)
        })
    }

    /// Publishes every byte `source` yields as the new file `name` in `dir`
    /// with permission bits `mode`, as [`Store::create_once`] publishes
    /// bytes. `mode` holds owner bits only, such as 0400 or 0500, which
    /// the umask contract leaves unnarrowed. `source` runs while the
    /// mutation is live, so it reads only files and bytes and never calls
    /// the store.
    ///
    /// # Errors
    ///
    /// As [`Store::create_once`]; a failed read of `source` is
    /// [`Error::Io`] and poisons the store.
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory, or `mode` holds a
    /// bit outside the owner's.
    pub(crate) fn copy_once(
        &self,
        dir: &Dir,
        name: &Name,
        source: &mut dyn io::Read,
        mode: u32,
    ) -> Result<Creation, Error> {
        assert_eq!(mode & !0o700, 0, "a copy takes owner permission bits only");
        self.guard(dir, || {
            self.publish(dir, name.as_c_str(), Source::Stream(source), mode, true)
        })
    }

    /// Publishes `bytes` as file `name` in `dir`, replacing any file of
    /// that name in one rename.
    ///
    /// # Errors
    ///
    /// As [`Store::create_once`].
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub fn replace(&self, dir: &Dir, name: &Name, bytes: &[u8]) -> Result<(), Error> {
        self.guard(dir, || {
            self.publish(dir, name.as_c_str(), Source::Bytes(bytes), FILE_MODE, false)
                .map(|_| ())
        })
    }

    /// Creates directory `name` in `dir` with mode 0700 unless an entry has
    /// that name, then makes `dir`'s entries durable.
    ///
    /// # Errors
    ///
    /// As [`Store::create_once`].
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub fn mkdir(&self, dir: &Dir, name: &Name) -> Result<Creation, Error> {
        self.guard(dir, || {
            let made = step::call(Step::Mkdir, || {
                sys::mkdir(&dir.file, name.as_c_str(), 0o700)
            });
            let creation = if changed(made, io::ErrorKind::AlreadyExists)? {
                Creation::Created
            } else {
                Creation::Existing
            };
            sync(dir)?;
            Ok(creation)
        })
    }

    /// Removes file `name` from `dir` when it exists, then makes `dir`'s
    /// entries durable.
    ///
    /// # Errors
    ///
    /// As [`Store::create_once`].
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub fn delete(&self, dir: &Dir, name: &Name) -> Result<(), Error> {
        self.guard(dir, || {
            let unlinked = step::call(Step::Unlink, || sys::unlink(&dir.file, name.as_c_str()));
            changed(unlinked, io::ErrorKind::NotFound)?;
            sync(dir)
        })
    }

    /// Removes the empty directory `name` from `dir` when it exists, then
    /// makes `dir`'s entries durable.
    ///
    /// # Errors
    ///
    /// As [`Store::create_once`]. A directory that still holds entries
    /// fails with `ENOTEMPTY` and stays in place.
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub fn rmdir(&self, dir: &Dir, name: &Name) -> Result<(), Error> {
        self.guard(dir, || {
            let removed = step::call(Step::Unlink, || sys::rmdir(&dir.file, name.as_c_str()));
            changed(removed, io::ErrorKind::NotFound)?;
            sync(dir)
        })
    }

    /// Removes the staging directory and the marker of `dir`, a state
    /// directory nested in this one, after the caller has deleted its other
    /// entries, so [`Store::rmdir`] can then remove `dir`. No [`Name`]
    /// addresses these two entries, so only this call removes them. The
    /// call takes no lock on `dir`: the caller ensures no store is open on
    /// it. Absent entries are tolerated. Returns `false`, changing nothing,
    /// when [`Store::marks_removable`] refuses the marks or `dir` holds an
    /// entry other than its marks.
    ///
    /// # Errors
    ///
    /// As [`Store::marks_removable`] for the check of the marks, which
    /// leaves the store unpoisoned; then as [`Store::create_once`].
    ///
    /// # Panics
    ///
    /// When `dir` is this store's own state directory or lies under another
    /// state directory.
    pub(crate) fn unmark(&self, dir: &Dir) -> Result<bool, Error> {
        assert_ne!(dir.ino, self.root().ino, "a store never unmarks itself");
        if !self.marks_removable(dir)?
            || !super::read::holds_only(dir, &[super::STAGING, super::MARKER])?
        {
            return Ok(false);
        }
        self.guard(dir, || {
            let staging = step::call(Step::Unlink, || sys::rmdir(&dir.file, super::STAGING));
            changed(staging, io::ErrorKind::NotFound)?;
            let marker = step::call(Step::Unlink, || sys::unlink(&dir.file, super::MARKER));
            changed(marker, io::ErrorKind::NotFound)?;
            sync(dir)
        })?;
        Ok(true)
    }

    /// Whether [`Store::unmark`] may remove the marks of `dir`, a state
    /// directory nested in this one: its marker is absent or a regular file
    /// holding the marker bytes, and its staging directory is absent or an
    /// empty directory. A symlink, another entry kind or other bytes at
    /// either name refuses the marks. The reads run outside
    /// [`Store::guard`], so a failure leaves the store unpoisoned.
    ///
    /// # Errors
    ///
    /// [`Error::Unreadable`] or [`Error::Io`] for an open, read or listing
    /// that fails through a host fault.
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub(crate) fn marks_removable(&self, dir: &Dir) -> Result<bool, Error> {
        self.owns(dir);
        removable_marks(dir)
    }

    /// Makes the file `read` came from and its directory durable, as a
    /// record that depends on its bytes requires before it is published.
    /// The `fsync` runs on the read's own open file, whose writeback-error
    /// cursor starts when it opens: it reports an error recorded while it
    /// is open, and an error recorded before it opened only when no open
    /// file has reported that error yet. The barrier therefore covers a
    /// file whose writer checked its own `fsync`, as this store's
    /// publications do. A file whose writeback failed and was reported
    /// under an earlier controller, which then stopped poisoned, is
    /// outside it.
    ///
    /// # Errors
    ///
    /// As [`Store::create_once`].
    ///
    /// # Panics
    ///
    /// When `read` lies under another state directory.
    pub fn barrier(&self, read: &Read) -> Result<(), Error> {
        self.guard(&read.dir, || {
            step::call(Step::Sync, || read.file.sync_all())?;
            sync(&read.dir)
        })
    }

    /// Makes `file`, opened beneath `dir` by [`Store::open_file`], and
    /// `dir`'s entries durable, so a record naming a file another process
    /// wrote is published only after that file is durable.
    ///
    /// # Errors
    ///
    /// As [`Store::barrier`].
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub fn sync_file(&self, dir: &Dir, file: &Opened) -> Result<(), Error> {
        self.guard(dir, || {
            step::call(Step::Sync, || file.file.sync_all())?;
            sync(dir)
        })
    }

    /// Syncs an evidence file, its directory and that directory's parent after
    /// checking the writable mount contract. The fresh descriptor uses the
    /// writeback-error cursor described by [`Store::barrier`]. This covers
    /// unsynced bytes and a writer's successful removal or truncation after a
    /// failed sync. Bytes left visible after a reported failure have unknown durability.
    ///
    /// # Errors
    ///
    /// A mount refusal, mount-ID status failure or failed kernel-table read
    /// returns with the store writable. A later state-directory identity check,
    /// sync or ancestor-open error poisons the store.
    pub(crate) fn sync_evidence(&self, dir: &File, file: &Opened) -> Result<(), Error> {
        super::mount::writable(dir)?;
        self.guard(self.root(), || {
            step::call(Step::Sync, || file.file.sync_all())?;
            step::call(Step::Sync, || dir.sync_all())?;
            let ancestor = step::call(Step::Open, || sys::open_parent(dir))?;
            step::call(Step::Sync, || ancestor.sync_all()).map_err(Error::Io)
        })
    }

    /// Stages the bytes of `source` in a file of permission bits `mode`
    /// and renames it onto `name` in `dir`, with `RENAME_NOREPLACE` when
    /// `once`.
    pub(super) fn publish(
        &self,
        dir: &Dir,
        name: &CStr,
        source: Source<'_>,
        mode: u32,
        once: bool,
    ) -> Result<Creation, Error> {
        let staged = self.stage(dir, name, source, mode)?;
        self.commit(dir, name, &staged, once)
    }

    fn stage(
        &self,
        dir: &Dir,
        name: &CStr,
        source: Source<'_>,
        mode: u32,
    ) -> Result<CString, Error> {
        let staged = staging_name(dir, name);
        let staging = &self.staging.file;
        changed(
            step::call(Step::Unlink, || sys::unlink(staging, &staged)),
            io::ErrorKind::NotFound,
        )?;
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL;
        let file = step::call(Step::Open, || {
            sys::open_beneath(staging, &staged, flags, mode)
        })?;
        match source {
            Source::Bytes(bytes) => write_all(&file, bytes)?,
            Source::Stream(reader) => write_from(&file, reader)?,
        }
        step::call(Step::Sync, || file.sync_all())?;
        step::last(Step::Close, || sys::close(file))?;
        Ok(staged)
    }

    fn commit(&self, dir: &Dir, name: &CStr, staged: &CStr, once: bool) -> Result<Creation, Error> {
        let staging = &self.staging.file;
        let creation = match step::call(Step::Rename, || {
            sys::rename(staging, staged, &dir.file, name, once)
        }) {
            Ok(()) => Creation::Created,
            // The staged file's unlink stays unsynced: a VM reset that
            // undoes it leaves a staged name, which the next startup sweeps.
            Err(error) if once && error.kind() == io::ErrorKind::AlreadyExists => {
                step::call(Step::Unlink, || sys::unlink(staging, staged))?;
                Creation::Existing
            }
            Err(error) => return Err(error.into()),
        };
        sync(dir)?;
        Ok(creation)
    }
}

/// The one staging name of target `name` in `dir`: the directory's inode
/// number, unique on the store's one mount, in 16 hex digits, a dot, then
/// the name.
pub(super) fn staging_name(dir: &Dir, name: &CStr) -> CString {
    let mut staged = format!("{:016x}.", dir.ino).into_bytes();
    staged.extend_from_slice(name.to_bytes());
    CString::new(staged).expect("a staging name holds no NUL")
}

/// Writes every byte `source` yields to `file`, one seam step per
/// `write`.
fn write_from(file: &File, source: &mut dyn io::Read) -> Result<(), Error> {
    let mut buffer = vec![0; COPY_CHUNK];
    loop {
        match source.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(filled) => write_all(file, &buffer[..filled])?,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

/// Writes all of `bytes` to `file`, one seam step per `write`.
pub(super) fn write_all(file: &File, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let written = step::write(bytes.len(), |len| (&*file).write(&bytes[..len]))?;
        if written == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

pub(super) fn removable_marks(dir: &Dir) -> Result<bool, Error> {
    let refused = |error: super::Unreadable| {
        if error.faulted() {
            Err(Error::Unreadable(error))
        } else {
            Ok(false)
        }
    };
    let marker_bound = super::MARKER_BYTES.len() as u64;
    match super::read::bounded(dir, super::MARKER, marker_bound) {
        Ok(Some(marker)) if marker.bytes() != super::MARKER_BYTES => return Ok(false),
        Ok(Some(_)) => {}
        Ok(None) if super::read::holds_only(dir, &[super::STAGING])? => {}
        Ok(None) => return Ok(false),
        Err(error) => return refused(error),
    }
    let staging = match super::read::absent_as_none(super::dir::open_dir(dir, super::STAGING)) {
        Ok(Some(staging)) => staging,
        Ok(None) => return Ok(true),
        Err(error) => return refused(error),
    };
    // A zero bound ends the listing with `ScanBound` at the first
    // entry, so that error means the staging directory holds one.
    match super::read::entries(&staging, 0) {
        Ok(_) => Ok(true),
        Err(Error::ScanBound) => Ok(false),
        Err(error) => Err(error),
    }
}
