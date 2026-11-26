//! `read` opens a path once with `O_NONBLOCK`, so a FIFO opens immediately even when it has no writer, and accepts
//! only a regular file of at most its limit that belongs to root or to the process's user and whose group and other
//! write bits are clear. A key file ([`Access::Private`]) must belong to the process's user and give no permission
//! to its group or to others. The checks read the opened file, the inode whose bytes `read` returns; the
//! directories above it are the deployment's to protect.

use std::fmt;
use std::fs::{Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

#[derive(Debug)]
pub enum FileError {
    Relative,
    /// Opening the path, reading its metadata or reading its contents failed.
    Io(io::Error),
    NotRegular,
    /// The file belongs to a user other than root and the process's user.
    Owner,
    /// The file's group or others may write it.
    Writable,
    /// A key file belongs to another user or grants a permission to its group or to others.
    Shared,
    /// The file holds more bytes than this limit.
    TooLarge(u64),
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Relative => f.write_str("the path is not absolute"),
            Self::Io(error) => write!(f, "{error}"),
            Self::NotRegular => f.write_str("not a regular file"),
            Self::Owner => f.write_str("it belongs to a user other than root and this process's user"),
            Self::Writable => f.write_str("its group or others may write it"),
            Self::Shared => f.write_str(
                "a key file must belong to this process's user and grant no group or other permission",
            ),
            Self::TooLarge(limit) => write!(f, "larger than {limit} bytes"),
        }
    }
}

/// Who may read an input file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// A file without secrets: root or the process's user owns it, and neither its group nor others may write it.
    Readable,
    /// A key file: the process's user owns it, and it grants no permission to its group or to others.
    Private,
}

/// The process's effective user, the owner of `/proc/self` as the store client's watermark log also reads it.
pub(crate) fn user() -> io::Result<u32> {
    Ok(std::fs::metadata("/proc/self")?.uid())
}

/// Whether `meta` names an entry of the process's effective user with no group or other permission bit set.
pub(crate) fn private(meta: &Metadata) -> io::Result<bool> {
    Ok(meta.uid() == user()? && meta.mode() & 0o077 == 0)
}

/// Whether a file of `owner` is one a process of `user` trusts for input: root's or its own.
fn trusted(owner: u32, user: u32) -> bool {
    owner == 0 || owner == user
}

/// The bytes of the regular file at the absolute `path`, at most `limit` of them, under the rule `access` names.
///
/// # Errors
///
/// `read` checks the path, opens it, checks the file's type, its owner, its group and other write bits and, for a
/// key file, that it is private, then reads, and returns the first failure: [`FileError::Relative`],
/// [`FileError::NotRegular`], [`FileError::Owner`], [`FileError::Writable`], [`FileError::Shared`],
/// [`FileError::TooLarge`], or [`FileError::Io`] for a failed open, metadata read or read.
pub fn read(path: &Path, limit: u64, access: Access) -> Result<Vec<u8>, FileError> {
    if !path.is_absolute() {
        return Err(FileError::Relative);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(FileError::Io)?;
    let meta = file.metadata().map_err(FileError::Io)?;
    if !meta.is_file() {
        return Err(FileError::NotRegular);
    }
    if !trusted(meta.uid(), user().map_err(FileError::Io)?) {
        return Err(FileError::Owner);
    }
    if meta.mode() & 0o022 != 0 {
        return Err(FileError::Writable);
    }
    if access == Access::Private && !private(&meta).map_err(FileError::Io)? {
        return Err(FileError::Shared);
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(FileError::Io)?;
    if bytes.len() as u64 > limit {
        return Err(FileError::TooLarge(limit));
    }
    Ok(bytes)
}

/// The `format` field of the JSON object `bytes` holds, read with every other field ignored, so a file of another
/// format reports its format before its shape is checked.
///
/// # Errors
///
/// The parser's error for text that is not a JSON object with an unsigned 32-bit `format`.
pub fn format(bytes: &[u8]) -> Result<u32, serde_json::Error> {
    #[derive(serde::Deserialize)]
    struct Format {
        format: u32,
    }
    serde_json::from_slice::<Format>(bytes).map(|probe| probe.format)
}

/// The 32 bytes that `text`, 64 lowercase hexadecimal digits, spells, `None` for any other text.
pub fn key(text: &str) -> Option<[u8; 32]> {
    let digits = text.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let nibble = |digit: u8| match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    };
    let mut key = [0; 32];
    for (byte, [high, low]) in key.iter_mut().zip(digits.as_chunks::<2>().0) {
        *byte = (nibble(*high)? << 4) | nibble(*low)?;
    }
    Some(key)
}

#[cfg(test)]
#[path = "file_tests.rs"]
mod tests;
