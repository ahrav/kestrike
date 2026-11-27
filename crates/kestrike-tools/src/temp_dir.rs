//! New directories named as Python's `tempfile.mkdtemp` names them: a prefix and eight letters of `a` to
//! `z`, `0` to `9` and `_` drawn from the kernel's random bytes, made with mode 0700 under the umask and
//! drawn again while a name is taken.

use std::ffi::OsStr;
use std::fmt;
use std::fs::DirBuilder;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use crate::ownership::PathError;

const NAME_LETTERS: &[u8; 37] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
const NAME_LENGTH: usize = 8;
const NAME_ATTEMPTS: usize = 10_000;

/// Why [`make_temp_dir`] made no directory.
#[derive(Debug)]
pub enum TempDirError {
    /// The kernel's random bytes could not be read.
    Random(io::Error),
    /// A `mkdir` failed with another error than a taken name; the path is the one attempted.
    Create(PathError),
    /// 10,000 names were drawn and each was taken.
    Exhausted,
}

impl fmt::Display for TempDirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random(error) => error.fmt(f),
            Self::Create(error) => error.fmt(f),
            Self::Exhausted => f.write_str("no usable temporary directory name found"),
        }
    }
}

/// The `Display` text holds the I/O error's text, so the error reports no `source`.
impl std::error::Error for TempDirError {}

/// `random_letters` fills `letters` with letters of [`NAME_LETTERS`] drawn uniformly from the kernel's
/// random bytes.
fn random_letters(letters: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < letters.len() {
        let mut byte = 0u8;
        // SAFETY: `getrandom` writes at most one byte into `byte`, a valid, writable local.
        let read = unsafe { libc::getrandom((&raw mut byte).cast(), 1, 0) };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let span = u8::try_from(NAME_LETTERS.len()).expect("the letters fit a byte");
        if read == 1 && byte < span * (u8::MAX / span) {
            letters[filled] = NAME_LETTERS[usize::from(byte % span)];
            filled += 1;
        }
    }
    Ok(())
}

/// `make_temp_dir` creates `parent/PREFIX` and eight random letters as a directory of mode 0700, drawing
/// a new name while one is taken.
///
/// # Errors
///
/// The random bytes cannot be read, a `mkdir` fails with another error than a taken name, or
/// 10,000 names are all taken.
pub fn make_temp_dir(prefix: &str, parent: &Path) -> Result<PathBuf, TempDirError> {
    for _ in 0..NAME_ATTEMPTS {
        let mut letters = [0u8; NAME_LENGTH];
        random_letters(&mut letters).map_err(TempDirError::Random)?;
        let mut name = prefix.as_bytes().to_vec();
        name.extend_from_slice(&letters);
        let path = parent.join(OsStr::from_bytes(&name));
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(TempDirError::Create(PathError::new(&path, error))),
        }
    }
    Err(TempDirError::Exhausted)
}

#[cfg(test)]
#[path = "temp_dir_tests.rs"]
mod tests;
