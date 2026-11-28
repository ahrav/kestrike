//! The score's file: the run's settings, and the bytes written to a staging file beside
//! `verification/plants/score.json` and renamed over it.
//!
//! The staging file is `.score.json.` and eight letters, created new with mode 0600 and then given mode
//! 0666 less the umask; the rename replaces a link at the score's path, whose target stays. A write that
//! fails removes the staging file. The write makes no sync.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::entry::Finished;
use super::prepare::Inputs;
use super::run::Run;
use super::score;
use crate::json::{Object, Value};
use crate::ownership::PathError;
use crate::temp_dir::{TempDirError, fresh, random_letters};
use crate::text::Text;

impl Run<'_> {
    /// `settings` are the run's settings in the score: the workers, the floor, the seconds and rounds of
    /// a sweep, the base archive's build digest, the `campaign` binary's digest and the plants `--plant`
    /// selected, `null` for the whole store.
    pub fn settings(&self) -> Object {
        let inputs: &Inputs = self.inputs;
        let options = inputs.options();
        let mut settings = Object::new();
        for (name, value) in [
            ("workers", options.workers()),
            ("runs", options.runs()),
            ("seconds", options.seconds()),
            ("rounds", options.rounds()),
        ] {
            settings.insert(name, Value::Integer(value.clone()));
        }
        let base = match &self.base {
            Some(Ok((_, pins))) => Value::String(pins.build().clone()),
            _ => Value::Null,
        };
        settings.insert("base_archive", base);
        settings.insert(
            "campaign_sha256",
            Value::String(Text::from(inputs.campaign_sha256())),
        );
        let plants = if options.plants().is_empty() {
            Value::Null
        } else {
            Value::Array(
                options
                    .plants()
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            )
        };
        settings.insert("plants", plants);
        settings
    }
}

fn umask() -> io::Result<u32> {
    let status = fs::read_to_string("/proc/self/status")?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Umask:"))
        .and_then(|mask| u32::from_str_radix(mask.trim(), 8).ok())
        .ok_or_else(|| io::Error::other("/proc/self/status names no umask"))
}

/// `staging` creates a new staging file beside `target`.
fn staging(target: &Path) -> io::Result<(PathBuf, File)> {
    staging_with(target, random_letters)
}

/// `staging_with` creates a new staging file beside `target`, drawing each name's eight letters from
/// `letters`; a name that is taken is left as it is and another is drawn.
fn staging_with(
    target: &Path,
    letters: impl FnMut(&mut [u8]) -> io::Result<()>,
) -> io::Result<(PathBuf, File)> {
    let parent = target.parent().unwrap_or(Path::new("."));
    let mut prefix = b".".to_vec();
    prefix.extend_from_slice(target.file_name().unwrap_or_default().as_bytes());
    prefix.push(b'.');
    let create = |path: &Path| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    };
    fresh(&prefix, parent, letters, create).map_err(|error| match error {
        TempDirError::Random(error) => error,
        TempDirError::Create(error) => error.into_error(),
        TempDirError::Exhausted => {
            io::Error::new(io::ErrorKind::AlreadyExists, "no usable staging name found")
        }
    })
}

/// `publish` replaces `target` with `written` through a staging file it creates beside it.
///
/// # Errors
///
/// The staging file cannot be created, given its mode, written, closed or renamed; the text names the
/// path.
pub fn publish(target: &Path, written: &str) -> Result<(), PathError> {
    let (staged, mut file) = staging(target).map_err(|error| PathError::new(target, error))?;
    let written = crate::fixtures::fits(written.len())
        .and_then(|()| umask())
        .and_then(|mask| file.set_permissions(fs::Permissions::from_mode(0o666 & !mask)))
        .and_then(|()| file.write_all(written.as_bytes()));
    let closed = crate::fixtures::close(file);
    let done = written
        .and(closed)
        .and_then(|()| fs::rename(&staged, target));
    done.map_err(|error| {
        let _ = fs::remove_file(&staged);
        PathError::new(target, error)
    })
}

/// `conclude` takes the run's last two steps, which read no signal record: `write` writes the score's
/// `bytes` to `target`, and the score's lines go to `out`, with the run's exit returned. A failed write
/// prints `plant-runner wrote no score: ` with its text, then each plant's result line, on `err`, and
/// returns 4.
pub fn conclude<E: std::fmt::Display>(
    head: &str,
    target: &Path,
    entries: &[Finished],
    bytes: &str,
    write: impl FnOnce(&Path, &str) -> Result<(), E>,
    out: &mut impl Write,
    err: &mut impl Write,
) -> u8 {
    if let Err(error) = write(target, bytes) {
        let _ = writeln!(err, "plant-runner wrote no score: {error}");
        for entry in entries {
            let _ = writeln!(err, "{}", score::result_line(entry));
        }
        let _ = err.flush();
        return 4;
    }
    announce(head, entries, out)
}

pub const UNANNOUNCED: u8 = 120;

fn announce(head: &str, entries: &[Finished], out: &mut impl Write) -> u8 {
    let printed = score::lines(head, entries)
        .iter()
        .try_for_each(|line| writeln!(out, "{line}"))
        .and_then(|()| out.flush());
    match printed {
        Ok(()) => score::exit_code(entries),
        Err(_) => UNANNOUNCED,
    }
}

#[cfg(test)]
#[path = "publish_tests.rs"]
mod tests;
