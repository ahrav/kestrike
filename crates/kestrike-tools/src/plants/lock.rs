//! The checkout's `Cargo.lock`, read once, so every archive of a run resolves the same dependencies.

use std::fs;
use std::path::Path;

use super::files::strerror;
use super::stop::Stop;
use crate::ownership::{PathError, is_file, is_link};

/// `lock` returns the bytes of `top/Cargo.lock`, which must be a regular file and no link.
///
/// # Errors
///
/// The file is missing, a link or no regular file (`no regular file`), or cannot be read (the operating
/// system's text).
pub(super) fn lock(top: &Path) -> Result<Vec<u8>, Stop> {
    let path = top.join("Cargo.lock");
    let read = || -> Result<Vec<u8>, String> {
        let failed = |error: PathError| strerror(error.error());
        if is_link(&path).map_err(failed)? || !is_file(&path).map_err(failed)? {
            return Err("no regular file".to_owned());
        }
        fs::read(&path).map_err(|error| strerror(&error))
    };
    read().map_err(|why| {
        Stop::rejected(format!(
            "the checkout holds no readable Cargo.lock ({why}); build it once to resolve the \
             dependencies every archive of the run shares"
        ))
    })
}
