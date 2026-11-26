//! The state directory: the store client's durable watermark (`watermark`, a `storage::store::FileLog`) and the
//! files the service publishes there. A [`State`] holds the directory open and its exclusive `flock` for its life,
//! so one process at a time uses a state directory (ONE-WRITER, which `FileLog` requires of its log).
//!
//! LOCKED-DIRECTORY: every file operation in the directory names it through the descriptor `State` holds, the path
//! `/proc/self/fd/<descriptor>`, so it reaches the directory `State::open` checked and locked even after the
//! configured path is renamed or rebound. `State` keeps the configured path for messages. [`State::log`] consumes
//! the `State` into the [`Watermarks`] that hold the log, so the lock and the descriptor last as long as the log.
//!
//! WATERMARK: [`State::init`] keeps an existing watermark. When `watermark` is missing, it records the empty one
//! only in a directory whose one possible entry is a leftover `watermark.tmp`; any other entry causes it to refuse.
//! [`State::log`] requires a recorded watermark, since a client that opened over a lost log would accept a
//! regressed store as current.

use std::fmt;
use std::fs::{DirBuilder, File, OpenOptions, TryLockError};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use kestrike::storage::store::{FileLog, Key, Watermark, WatermarkLog};

/// The watermark file's name in the state directory.
pub const WATERMARK: &str = "watermark";
/// The staging name `FileLog` writes a whole watermark record under before it renames it over [`WATERMARK`].
const STAGED_WATERMARK: &str = "watermark.tmp";

#[derive(Debug)]
pub enum StateError {
    Io(io::Error),
    /// The directory belongs to another user or grants a permission to its group or to others.
    Shared,
    /// Another open of the directory holds its lock.
    Busy,
    /// The directory holds no watermark entry.
    Uninitialized,
    /// `init` found a watermark already recorded.
    Initialized,
    /// `init` found no `watermark` and an entry other than `watermark.tmp`. A file of an earlier run and an entry
    /// that preceded the service, such as a file system root's `lost+found`, look alike, and an empty watermark
    /// could reset the one an earlier run raised.
    Used,
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Shared => f.write_str(
                "the directory must belong to this process's user and grant no group or other permission",
            ),
            Self::Busy => f.write_str("another process holds the directory's lock"),
            Self::Uninitialized => f.write_str(
                "no watermark is recorded; run `init` for a new state directory, and restore the watermark of one \
                 that has run before",
            ),
            Self::Initialized => f.write_str("a watermark is already recorded"),
            Self::Used => f.write_str(
                "the directory holds no watermark and an entry other than `watermark.tmp`, and `init` records the \
                 empty watermark only in a directory without such an entry; restore the watermark of a directory \
                 that has run before, and give a first initialization an empty directory",
            ),
        }
    }
}

/// An open, locked state directory.
#[derive(Debug)]
pub struct State {
    /// The configured path, for messages.
    path: PathBuf,
    /// The open directory, whose `flock` lasts until this value drops and closes it.
    handle: File,
}

/// Syncs the directory that holds the entry `path`, so the entry's creation is durable. The root has no parent, and
/// for it the call returns at once.
fn sync_parent(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(parent)?
        .sync_all()
}

/// The path of `name` inside the directory `handle` holds open, through the process's descriptor table. The path
/// names that directory while `handle` stays open.
pub(crate) fn within(handle: &File, name: &str) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", handle.as_raw_fd())).join(name)
}

impl State {
    /// Opens the directory at `path` and takes its exclusive lock.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] for a failed open or metadata read, a symlink or a non-directory at `path` included, then
    /// [`StateError::Shared`], then [`StateError::Busy`] or the lock call's [`StateError::Io`].
    pub fn open(path: &Path) -> Result<Self, StateError> {
        // `O_NOFOLLOW` covers the final component only, and Linux follows a symlink named with a trailing `/` or
        // `/.`. The path's components drop both endings, so the flag applies to the directory's own name.
        let named: PathBuf = path.components().collect();
        let handle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(named)
            .map_err(StateError::Io)?;
        let meta = handle.metadata().map_err(StateError::Io)?;
        if !crate::file::private(&meta).map_err(StateError::Io)? {
            return Err(StateError::Shared);
        }
        match handle.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(StateError::Busy),
            Err(TryLockError::Error(error)) => return Err(StateError::Io(error)),
        }
        Ok(Self {
            path: path.to_owned(),
            handle,
        })
    }

    /// Makes the directory at `path` with mode 0700 when it is missing (its parent must exist), syncs its parent so
    /// the directory's entry is durable, whether this call or an earlier one made it, then opens it as
    /// [`State::open`] does.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] for a failed create or parent sync, then [`State::open`]'s errors.
    pub fn create(path: &Path) -> Result<Self, StateError> {
        match DirBuilder::new().mode(0o700).create(path) {
            Err(error) if error.kind() != io::ErrorKind::AlreadyExists => {
                return Err(StateError::Io(error));
            }
            _ => {}
        }
        sync_parent(path).map_err(StateError::Io)?;
        Self::open(path)
    }

    /// The configured path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The returned descriptor shares the locked directory's open file description, so the lock lasts while either
    /// descriptor is open.
    pub(crate) fn directory(&self) -> Result<File, StateError> {
        self.handle.try_clone().map_err(StateError::Io)
    }

    /// The path of `name` in the locked directory.
    fn at(&self, name: &str) -> PathBuf {
        within(&self.handle, name)
    }

    fn watermark(&self) -> Result<bool, StateError> {
        match self.at(WATERMARK).symlink_metadata() {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(StateError::Io(error)),
        }
    }

    /// Whether the directory lists an entry whose name differs from `watermark.tmp`.
    fn used(&self) -> Result<bool, StateError> {
        for entry in std::fs::read_dir(self.at("")).map_err(StateError::Io)? {
            if entry.map_err(StateError::Io)?.file_name() != STAGED_WATERMARK {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Records the empty watermark, the one record a host makes before its store client first opens.
    ///
    /// # Errors
    ///
    /// [`StateError::Initialized`] when the directory holds a watermark entry of any kind. [`StateError::Used`] when
    /// `watermark` is missing and the directory lists an entry other than `watermark.tmp`. [`StateError::Io`] when
    /// listing the directory or recording the empty watermark fails.
    pub fn init(&self) -> Result<(), StateError> {
        if self.watermark()? {
            return Err(StateError::Initialized);
        }
        if self.used()? {
            return Err(StateError::Used);
        }
        let mut log = self.file_log()?;
        log.record(&Watermark::default()).map_err(StateError::Io)
    }

    /// The log of the recorded watermark, for `storage::store::Client::open`, which reloads and checks it. The
    /// returned [`Watermarks`] own this `State`, so the directory stays locked while the log is in use.
    ///
    /// # Errors
    ///
    /// [`StateError::Uninitialized`] when the directory holds no watermark entry, or a metadata read's
    /// [`StateError::Io`].
    pub fn log(self) -> Result<Watermarks, StateError> {
        if !self.watermark()? {
            return Err(StateError::Uninitialized);
        }
        let log = self.file_log()?;
        Ok(Watermarks { log, _state: self })
    }

    fn file_log(&self) -> Result<FileLog, StateError> {
        FileLog::new(self.at(WATERMARK)).map_err(StateError::Io)
    }
}

/// The watermark log of a locked state directory: a `FileLog` that names the watermark through the directory's
/// descriptor, beside the [`State`] that holds that descriptor and its lock.
pub struct Watermarks {
    log: FileLog,
    _state: State,
}

impl WatermarkLog for Watermarks {
    fn load(&self) -> io::Result<Watermark> {
        self.log.load()
    }

    fn record(&mut self, mark: &Watermark) -> io::Result<()> {
        self.log.record(mark)
    }

    fn raise(&mut self, mark: &Watermark, keys: &[Key]) -> io::Result<()> {
        self.log.raise(mark, keys)
    }

    fn reload(&mut self) -> io::Result<Watermark> {
        self.log.reload()
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
