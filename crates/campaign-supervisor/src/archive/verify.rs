//! Loading and verifying an archive before and after each use.
//!
//! [`Archive::load`] reads the build record once; the SHA-256 of its bytes
//! is the archive's identity. [`Archive::verify`] checks the archive
//! against that record before a use and returns the [`Approved`] use. A
//! full check confirms the record's bytes, every file's digest, the
//! library set, the executable's owner execute permission, this host's
//! machine, the interpreter the executable requests and its digest, and
//! the interpreter's resolution of every library into the archive, all
//! between two readings of the files' [identities](Identity), which must
//! agree. The file checks are cached by those identities: a later
//! `verify` whose files keep them skips the digests, and any changed
//! identity, a restored modification time included, runs the full check
//! again. The interpreter's resolution also reads host files outside the
//! archive. System preload entries are refused on every `verify`.
//! Every reading of the identities also requires the archive's path to
//! name the directory the archive was loaded from, whose own identity is
//! among them, since a use runs the files at that path. The view checks
//! that every ancestor is a directory the running user or root owns, is
//! group- and world-unwritable or sticky, and is no symlink, at load and
//! at every identity reading.
//! [`Approved::finish`] repeats the full check after the use and requires
//! the identities the use began with.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{
    Invalid, LIBRARIES, LIBRARY_BOUND, LOCK, RECORD, Unfinished, WORKER, elf, host, loader, name,
    searchable,
};
use crate::record::{BOUND, Build, Digest, Pins, Text};
use crate::store::{self, Dir, Identity, Name, Opened, Unreadable, View};
use crate::sys;

/// A loaded archive: its view, its build record and its identity.
#[derive(Debug)]
pub struct Archive {
    view: View,
    record: Build,
    /// The record's libraries as names, with their digests, in name order.
    libraries: Vec<(Name, Digest)>,
    id: Digest,
    approved: Option<Vec<Identity>>,
}

/// A use of an archive that passed verification. Its executable and
/// library directory are those the verification approved, and
/// [`Approved::finish`] checks them again after the use.
#[derive(Debug)]
#[must_use = "a use ends with `finish`, the check after it"]
pub struct Approved<'a> {
    archive: &'a mut Archive,
}

impl Archive {
    /// Loads the archive at `path` and reads its build record.
    ///
    /// # Errors
    ///
    /// [`Invalid::Path`] for a path the loader's search path cannot carry,
    /// [`Invalid::Missing`] when it holds no build record,
    /// [`Invalid::Record`] for a held record, [`Invalid::Libraries`] for a
    /// record naming a library no archive file can hold,
    /// [`Invalid::Unreadable`] when the directory cannot be opened,
    /// [`Invalid::Refused`] for a directory on another filesystem type
    /// than ext4 or xfs or with no mount record, or that the running user
    /// does not own with mode 0700, and [`Invalid::Io`] when the mount
    /// table cannot be read or the build record or the archive's directory
    /// fails its `fsync`.
    pub fn load(path: &Path) -> Result<Self, Invalid> {
        let view = View::open(path).map_err(|error| match error {
            store::Error::Unreadable(why) => Invalid::Unreadable(path.display().to_string(), why),
            error => Invalid::store(error),
        })?;
        searchable(view.path())?;
        let verified = view
            .read_record::<Build>(view.root(), &name(RECORD))
            .map_err(Invalid::Record)?
            .ok_or_else(|| Invalid::Missing(RECORD.to_owned()))?;
        view.barrier(verified.read()).map_err(Invalid::store)?;
        let record = verified.record().clone();
        let libraries = record
            .libraries
            .iter()
            .map(|(library, digest)| Some((Name::new(library.as_str())?, *digest)))
            .collect::<Option<_>>()
            .ok_or(Invalid::Libraries)?;
        Ok(Self {
            id: Digest::of(verified.read().bytes()),
            record,
            libraries,
            view,
            approved: None,
        })
    }

    /// The archive's canonical path.
    pub fn path(&self) -> &Path {
        self.view.path()
    }

    /// The archive's identity: the SHA-256 of its build record's bytes.
    pub fn id(&self) -> Digest {
        self.id
    }

    pub fn record(&self) -> &Build {
        &self.record
    }

    /// The values a manifest run under this archive pins.
    pub fn pins(&self) -> Pins {
        let text = |text: &str| Text::new(text).expect("record text and digests are ASCII");
        Pins {
            build: text(&self.id.to_string()),
            executable: text(&self.record.executable.to_string()),
            platform: text(&format!("{}-linux", self.record.machine.as_str())),
            toolchain: self.record.provenance.toolchain.clone(),
        }
    }

    /// Verifies the archive for one use. The file checks run unless every
    /// file keeps the identity the latest verification approved; the
    /// interpreter's resolution runs every time. The caller gives this
    /// method ownership of the process's SIGCHLD disposition, as the
    /// [module doc](super#sigchld) states.
    ///
    /// # Errors
    ///
    /// The [`Invalid`] reason the archive fails verification; `Invalid::exit`
    /// gives the use's exit: 2 before a worker ran, or 4 for a host fault
    /// or after a worker ran.
    pub fn verify(&mut self) -> Result<Approved<'_>, Invalid> {
        let current = self.identities()?;
        if self.approved.as_ref() == Some(&current) {
            self.resolution()?;
            if self.identities()? != current {
                return Err(Invalid::Changed);
            }
        } else {
            // A failed check leaves no approval cached, so the next use
            // runs the full check.
            self.approved = None;
            self.approved = Some(self.check(current)?);
        }
        Ok(Approved { archive: self })
    }

    /// The identities of the archive's directory, the record, the
    /// executable, the lockfile, the library directory, each library in
    /// name order, and the host's interpreter through its symlinks.
    ///
    /// # Errors
    ///
    /// [`Invalid::Changed`] when the archive's path names another
    /// directory than the one loaded; [`Invalid::Refused`] when its owner
    /// or mode changed.
    fn identities(&self) -> Result<Vec<Identity>, Invalid> {
        if !self.view.current().map_err(Invalid::Io)? {
            return Err(Invalid::Changed);
        }
        let mut identities = vec![self.view.status().map_err(Invalid::store)?];
        let root = self.view.root();
        for entry in [RECORD, WORKER, LOCK, LIBRARIES] {
            identities.push(self.identity(root, &name(entry))?);
        }
        let directory = self.library_dir()?;
        for (library, _) in &self.libraries {
            identities.push(self.identity(&directory, library)?);
        }
        if let Some(loader) = &self.record.loader {
            identities.push(host(Path::new(loader.path.as_str()))?.identity());
        }
        Ok(identities)
    }

    /// The full check, from the opening identities `before`, which it
    /// returns.
    fn check(&self, before: Vec<Identity>) -> Result<Vec<Identity>, Invalid> {
        let root = self.view.root();
        let read = self.view.read(root, &name(RECORD), BOUND);
        let read = present(read, RECORD)?;
        if Digest::of(read.bytes()) != self.id {
            return Err(Invalid::Digest(RECORD.to_owned()));
        }
        let host_machine = sys::machine().map_err(Invalid::Io)?;
        if host_machine != self.record.machine.as_str() {
            return Err(Invalid::Machine(self.record.machine.as_str().to_owned()));
        }
        self.check_digest(root, &name(WORKER), self.record.executable)?;
        self.check_digest(root, &name(LOCK), self.record.lock)?;
        let directory = self.library_dir()?;
        let listed = self
            .view
            .list(&directory, LIBRARY_BOUND)
            .map_err(|error| match error {
                store::Error::Io(error) => Invalid::Io(error),
                _ => Invalid::Libraries,
            })?;
        if !listed
            .iter()
            .eq(self.libraries.iter().map(|(library, _)| library))
        {
            return Err(Invalid::Libraries);
        }
        for (library, digest) in &self.libraries {
            self.check_digest(&directory, library, *digest)?;
            elf::library(&self.open(&directory, library)?)?;
        }
        let worker = self.open(root, &name(WORKER))?;
        if worker.mode() & 0o100 == 0 {
            let why = "it has no owner execute permission".to_owned();
            return Err(Invalid::Elf(why));
        }
        let requested = elf::interpreter(&worker)?;
        let recorded = self.record.loader.as_ref();
        if requested.as_deref() != recorded.map(|loader| loader.path.as_str()) {
            let why = format!("it requests the interpreter {requested:?}");
            return Err(Invalid::Elf(why));
        }
        if let Some(recorded) = recorded {
            let digest =
                Digest::read(host(Path::new(recorded.path.as_str()))?).map_err(Invalid::Io)?;
            if digest != recorded.sha256 {
                return Err(Invalid::Digest(recorded.path.as_str().to_owned()));
            }
        }
        self.resolution()?;
        if self.identities()? != before {
            return Err(Invalid::Changed);
        }
        Ok(before)
    }

    /// Checks that the recorded interpreter resolves every library into
    /// the archive's library directory, as a use runs it.
    fn resolution(&self) -> Result<(), Invalid> {
        let Some(recorded) = &self.record.loader else {
            return Ok(());
        };
        let directory = self.library_path();
        let found = loader::resolve(
            recorded.path.as_str(),
            &self.worker_path(),
            Some(directory.as_os_str()),
        )?;
        resolves_into(found, &directory, &self.libraries)
    }

    /// The path a use runs the archived executable at.
    fn worker_path(&self) -> PathBuf {
        self.view.path().join(WORKER)
    }

    /// The archived library directory's path, a use's whole
    /// `LD_LIBRARY_PATH`.
    fn library_path(&self) -> PathBuf {
        self.view.path().join(LIBRARIES)
    }

    fn identity(&self, dir: &Dir, entry: &Name) -> Result<Identity, Invalid> {
        present(self.view.identity(dir, entry), entry.as_str())
    }

    fn library_dir(&self) -> Result<Dir, Invalid> {
        present(
            self.view.open_dir(self.view.root(), &name(LIBRARIES)),
            LIBRARIES,
        )
    }

    fn open(&self, dir: &Dir, entry: &Name) -> Result<Opened, Invalid> {
        present(self.view.open_file(dir, entry), entry.as_str())
    }

    /// Checks that the regular file `entry` beneath `dir` hashes to
    /// `expected`.
    fn check_digest(&self, dir: &Dir, entry: &Name, expected: Digest) -> Result<(), Invalid> {
        if Digest::read(self.open(dir, entry)?).map_err(Invalid::Io)? != expected {
            return Err(Invalid::Digest(entry.as_str().to_owned()));
        }
        Ok(())
    }
}

/// The entry `entry` a view lookup found, refusing a missing or
/// unreadable one.
fn present<T>(found: Result<Option<T>, Unreadable>, entry: &str) -> Result<T, Invalid> {
    found
        .map_err(|why| Invalid::Unreadable(entry.to_owned(), why))?
        .ok_or_else(|| Invalid::Missing(entry.to_owned()))
}

/// Checks that a listing `found` resolves exactly the archive's
/// `libraries`, each to its file in `directory`.
///
/// # Errors
///
/// [`Invalid::Resolution`] for any other name or path.
pub(super) fn resolves_into(
    found: BTreeMap<String, String>,
    directory: &Path,
    libraries: &[(Name, Digest)],
) -> Result<(), Invalid> {
    let expected = libraries.iter().map(|(library, _)| {
        let path = directory.join(library.as_str()).display().to_string();
        (library.as_str().to_owned(), path)
    });
    if !found.into_iter().eq(expected) {
        let why = "a library resolves outside the archive".to_owned();
        return Err(Invalid::Resolution(why));
    }
    Ok(())
}

impl Approved<'_> {
    /// A command running the archived executable in the environment the
    /// verification resolved its libraries in: this process's environment
    /// minus every `LD_*` variable and `GLIBC_TUNABLES`, the archived library directory as the
    /// whole `LD_LIBRARY_PATH`, and the null device as standard input.
    pub fn command(&self) -> Command {
        let libraries = self.archive.library_path();
        loader::command(
            &self.archive.worker_path(),
            Some(libraries.as_os_str()),
            std::env::vars_os(),
        )
    }

    /// Verifies the archive in full after the use.
    ///
    /// # Errors
    ///
    /// [`Unfinished`] holding [`Invalid::Changed`] when a file's identity
    /// differs from the one the use began with, even when its bytes match
    /// the record again, or any other [`Invalid`] reason. A failure
    /// leaves no approval cached, so the next use runs the full check.
    pub fn finish(self) -> Result<(), Unfinished> {
        let began = self.archive.approved.take();
        let now = self
            .archive
            .identities()
            .and_then(|now| self.archive.check(now))
            .map_err(Unfinished)?;
        if began.as_ref() != Some(&now) {
            return Err(Unfinished(Invalid::Changed));
        }
        self.archive.approved = Some(now);
        Ok(())
    }
}
