//! The run directory: the lock of the artifacts directory, and the directories that
//! [`crate::temp_dir::make_temp_dir`] names, whose failures become the run's faults.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::pieces::text;
use super::stop::{Fault, Stop};
use crate::ownership::{PrivateError, make_private, real_uid};
use crate::temp_dir::{self, TempDirError};

/// `make_temp_dir` creates `parent/PREFIX` and eight random letters as a directory of mode 0700, drawing
/// a new name while one is taken.
///
/// # Errors
///
/// The random bytes cannot be read, a `mkdir` fails with another error than a taken name, which the
/// fault states with the attempted path, or every name drawn is taken.
pub(super) fn make_temp_dir(prefix: &str, parent: &Path) -> Result<PathBuf, Fault> {
    temp_dir::make_temp_dir(prefix, parent).map_err(|error| match error {
        TempDirError::Random(error) => Fault::os(&error, None),
        TempDirError::Create(error) => Fault::os(error.error(), Some(error.path().as_os_str())),
        TempDirError::Exhausted => {
            let exhausted = io::Error::new(
                io::ErrorKind::AlreadyExists,
                "no usable temporary directory name found",
            );
            Fault::os(&exhausted, None)
        }
    })
}

/// `utc_stamp` writes the UTC wall clock as [`utc_stamp_at`] does.
fn utc_stamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    utc_stamp_at(seconds)
}

/// `utc_stamp_at` writes `seconds` after the Unix epoch as the UTC time `YYYYmmddTHHMMSSZ-`.
pub(super) fn utc_stamp_at(seconds: u64) -> String {
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    let days = i64::try_from(days).expect("the day count fits i64") + 719_468;
    let era = days.div_euclid(146_097);
    let of_era = days.rem_euclid(146_097);
    let year_of_era = (of_era - of_era / 1460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * of_year + 2) / 153;
    let day = of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 {
        shifted + 3
    } else {
        shifted - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let (hour, minute, second) = (rest / 3600, rest / 60 % 60, rest % 60);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z-")
}

/// `take_lock` locks `path` for the life of the returned file. The open follows no link and waits on no
/// FIFO; the lock must be a regular file this user owns and no other run may hold it.
fn take_lock(path: &Path) -> Result<File, OpenError> {
    let opened = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path);
    let lock = opened.map_err(|error| {
        let fault = Fault::os(&error, Some(path.as_os_str()));
        OpenError::Stop(Stop::rejected(text!(
            path,
            " cannot be opened as a lock file: ",
            fault.text()
        )))
    })?;
    let status = lock
        .metadata()
        .map_err(|error| OpenError::Fault(Fault::os(&error, Some(path.as_os_str()))))?;
    if !status.is_file() || status.uid() != real_uid() {
        return Err(OpenError::Stop(Stop::rejected(text!(
            path,
            " is not a regular file the invoking user owns"
        ))));
    }
    // SAFETY: `flock` takes the descriptor of `lock`, which stays open across the call, and two flags.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(OpenError::Stop(Stop::rejected(text!(
                "another run holds ",
                path
            ))));
        }
        return Err(OpenError::Fault(Fault::os(&error, None)));
    }
    Ok(lock)
}

fn private_fault(error: &PrivateError) -> Fault {
    match error {
        PrivateError::Io(error) => Fault::os(error.error(), Some(error.path().as_os_str())),
        PrivateError::Shared(_) => Fault::library("PrivateError", error),
    }
}

/// The run directory could not be made: an unexpected error, or a lock the run refuses.
pub(super) enum OpenError {
    Fault(Fault),
    Stop(Stop),
}

impl OpenError {
    /// `into_stop` is the stop of a failure inside the run's steps.
    pub(super) fn into_stop(self) -> Stop {
        match self {
            Self::Fault(fault) => Stop::failed(&fault),
            Self::Stop(stop) => stop,
        }
    }

    /// `text` is the failure as the report's refusal states it.
    pub(super) fn text(&self) -> crate::text::Text {
        match self {
            Self::Fault(fault) => fault.text().clone(),
            Self::Stop(stop) => stop.reason().clone(),
        }
    }
}

/// `open` makes `artifacts` private, takes its lock into `lock` unless it holds one, and creates a new run
/// directory named by the UTC wall clock after the lock is held.
pub(super) fn open(artifacts: &Path, lock: &mut Option<File>) -> Result<PathBuf, OpenError> {
    make_private(artifacts).map_err(|error| OpenError::Fault(private_fault(&error)))?;
    if lock.is_none() {
        *lock = Some(take_lock(&artifacts.join("build.lock"))?);
    }
    make_temp_dir(&utc_stamp(), artifacts).map_err(OpenError::Fault)
}
