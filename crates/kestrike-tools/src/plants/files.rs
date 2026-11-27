//! The operating system's text of an error, as Python's `OSError.strerror` holds it.

use std::io;

/// `strerror` is the operating system's text for `error`, without the code the standard library adds.
pub(crate) fn strerror(error: &io::Error) -> String {
    let shown = error.to_string();
    match error.raw_os_error() {
        Some(code) => shown
            .strip_suffix(&format!(" (os error {code})"))
            .map_or_else(|| shown.clone(), str::to_owned),
        None => shown,
    }
}
