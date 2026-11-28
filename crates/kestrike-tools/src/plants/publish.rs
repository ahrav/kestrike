//! The score's file: the run's settings, and the bytes written to a staging file beside
//! `verification/plants/score.json` and renamed over it. [`publish_with`] writes another tool's file,
//! such as `mutants-diff`'s `report.json`, the same way.
//!
//! The staging file is `.NAME.` and eight letters beside the target. The score's is created new with mode
//! 0600 and then given mode 0666 less the umask the caller read with [`umask`]; a file published with
//! [`Creation::Mode`] is created new with that mode, which the kernel lessens by the umask or, in a
//! directory with a default ACL, sets from that ACL. The rename replaces a link at
//! the target's path, whose target stays. A write, close or rename that fails leads to an attempt to
//! remove the staging file. The write makes no sync.

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

/// The status file of the calling thread, whose `Umask:` line holds the thread's mask.
pub const THREAD_STATUS: &str = "/proc/thread-self/status";

/// `umask` is the calling thread's file mode creation mask, read from the `Umask:` line of
/// [`THREAD_STATUS`] (Linux 4.7 or later), which reports the mask and leaves it as it stands; the mask
/// is that of the thread's file system context, which a thread may hold apart from the process's.
///
/// # Errors
///
/// The status file cannot be read, or it holds no `Umask:` line of an octal mask.
pub fn umask() -> io::Result<u32> {
    let status = fs::read_to_string(THREAD_STATUS)?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Umask:"))
        .and_then(|mask| u32::from_str_radix(mask.trim(), 8).ok())
        .ok_or_else(|| io::Error::other("it names no umask"))
}

/// How a published file takes its permission bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Creation {
    /// Created with mode 0600 and then given mode 0666 less this mask, which the caller read with
    /// [`umask`].
    Masked(u32),
    /// Created with this mode, which the kernel lessens by the umask at creation or, in a directory with
    /// a default ACL, sets from that ACL, as for any file a process creates there.
    Mode(u32),
}

/// `staging_with` creates a new staging file beside `target`, drawing each name's eight letters from
/// `letters`; a name that is taken is left as it is and another is drawn.
fn staging_with(
    target: &Path,
    mode: u32,
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
            .mode(mode)
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

/// `publish` replaces `target` with `written` as [`publish_with`] does with [`Creation::Masked`] of
/// `mask`, so the file takes mode 0666 less `mask`.
///
/// # Errors
///
/// As [`publish_with`].
pub fn publish(target: &Path, written: &str, mask: u32) -> Result<(), PathError> {
    publish_with(target, written, Creation::Masked(mask))
}

/// `publish_with` replaces `target` with `written` through a staging file it creates beside it, whose
/// permission bits `creation` decides.
///
/// # Errors
///
/// The staging file cannot be created, given its mode, written, closed or renamed, or `written` is
/// longer than the soft file size limit allows (`EFBIG`, before any byte is written); the text names
/// the target's path.
pub fn publish_with(target: &Path, written: &str, creation: Creation) -> Result<(), PathError> {
    let at_target = |error| PathError::new(target, error);
    let created = match creation {
        Creation::Masked(_) => 0o600,
        Creation::Mode(mode) => mode,
    };
    let (staged, mut file) = staging_with(target, created, random_letters).map_err(at_target)?;
    let written = crate::fixtures::fits(written.len())
        .and_then(|()| match creation {
            Creation::Masked(mask) => {
                file.set_permissions(fs::Permissions::from_mode(0o666 & !mask))
            }
            Creation::Mode(_) => Ok(()),
        })
        .and_then(|()| file.write_all(written.as_bytes()))
        .map_err(at_target);
    let closed = crate::fixtures::close(file).map_err(at_target);
    let done = written
        .and(closed)
        .and_then(|()| fs::rename(&staged, target).map_err(at_target));
    done.inspect_err(|_| {
        let _ = fs::remove_file(&staged);
    })
}

/// `conclude` takes the run's last two steps, which read no signal record: `write` writes the score's
/// `bytes` to `target`, and the score's lines go to `out`, with the run's exit returned. A failed write
/// prints `plant-runner wrote no score: ` with its text, then each plant's result line, on `err`, and
/// returns 4. A write of the score's lines to `out` that fails returns [`UNANNOUNCED`], with the score
/// written.
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

/// The exit of a run whose standard output refused its last lines: the score's lines, after the score
/// is written, or the help, when no score is written.
pub(crate) const UNANNOUNCED: u8 = 120;

/// `announce` prints the score's lines on `out` and returns the run's exit, or [`UNANNOUNCED`] when a
/// line or the flush fails.
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
