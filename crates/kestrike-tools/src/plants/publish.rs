//! The score's file: the run's settings, and the bytes written to a staging file beside
//! `verification/plants/score.json` and renamed over it. [`publish_with`] writes another tool's file,
//! such as `mutants-diff`'s `report.json`, the same way.
//!
//! The staging file is `.NAME.`, eight letters and the [`Staging`]'s suffix, empty for the score, beside
//! the target. The score's is created new with mode 0600 and then given mode 0666 less the umask the
//! caller read with [`umask`]; a file published with [`Creation::Mode`] is created new with that mode,
//! which the kernel lessens by the umask or, in a directory with a default ACL, sets from that ACL; one
//! published with [`Creation::Exact`] is created new with mode 0600, written, and then given that mode as
//! it stands, so the write leaves its set-id bits. A [`Staging`] with a modification time gives the
//! written file that time, as its access time too, through its descriptor. The rename replaces a link at
//! the target's path, whose target stays. A [`Staging`] with a gate hands the rename to that gate once
//! the staging file is written and closed. A write, close or rename that fails, or a gate that returns an
//! error with the rename not done, leads to an attempt to remove the staging file. The write makes no
//! sync.

use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use super::child::suffixed;
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
    /// Created with mode 0600 and given this mode once the bytes are written, the set-id and sticky bits
    /// included, whatever the umask.
    Exact(u32),
}

/// A gate of [`Staging::gate`]: called with the rename, it runs that rename at most once and returns its
/// result, or returns an error of its own with the rename not run.
pub type Gate<'a> = &'a dyn Fn(&mut dyn FnMut() -> io::Result<()>) -> io::Result<()>;

/// How [`publish_staged`] stages a file: its [`Creation`], the suffix of the staging file's name, the
/// modification time it gives the file, in nanoseconds since the epoch, and the gate its rename runs in.
#[derive(Clone, Copy)]
pub struct Staging<'a> {
    creation: Creation,
    suffix: &'a str,
    modified: Option<i128>,
    gate: Option<Gate<'a>>,
}

impl<'a> Staging<'a> {
    /// A staging of `creation` with no suffix and the time of the write.
    pub const fn new(creation: Creation) -> Self {
        Self {
            creation,
            suffix: "",
            modified: None,
            gate: None,
        }
    }

    /// The staging whose rename runs inside `gate`, called once the staging file is written and closed,
    /// so the gate can run its own last check and the rename as one stretch. A gate that returns an error
    /// with the rename not run leaves the target as it stood and leads to an attempt to remove the
    /// staging file.
    #[must_use]
    pub const fn gate(mut self, gate: Gate<'a>) -> Self {
        self.gate = Some(gate);
        self
    }

    /// The staging with `suffix` after the letters of the staging file's name; `suffix` holds no `/`.
    #[must_use]
    pub const fn suffix(mut self, suffix: &'a str) -> Self {
        self.suffix = suffix;
        self
    }

    /// The staging that gives the written file the modification and access time `nanoseconds` after the
    /// epoch.
    #[must_use]
    pub const fn modified(mut self, nanoseconds: i128) -> Self {
        self.modified = Some(nanoseconds);
        self
    }
}

/// `staging_with` creates a new staging file beside `target`, drawing each name's eight letters from
/// `letters`, with `suffix` after them; a name that is taken is left as it is and another is drawn.
fn staging_with(
    target: &Path,
    mode: u32,
    suffix: &str,
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
            .open(suffixed(path, suffix))
    };
    let made =
        fresh(&prefix, parent, letters, create).map(|(path, file)| (suffixed(&path, suffix), file));
    made.map_err(|error| match error {
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
    publish_staged(target, written.as_bytes(), Staging::new(creation))
}

/// `times` gives the file open as `file` the access and modification time `nanoseconds` after the epoch,
/// a time before it where negative.
fn times(file: &File, nanoseconds: i128) -> io::Result<()> {
    let past = || io::Error::new(io::ErrorKind::InvalidInput, "a time past the clock's range");
    let seconds = nanoseconds.div_euclid(1_000_000_000);
    let rest = u64::try_from(nanoseconds.rem_euclid(1_000_000_000)).map_err(|_| past())?;
    let whole = Duration::from_secs(u64::try_from(seconds.unsigned_abs()).map_err(|_| past())?);
    let at = if seconds < 0 {
        UNIX_EPOCH.checked_sub(whole)
    } else {
        UNIX_EPOCH.checked_add(whole)
    }
    .and_then(|at| at.checked_add(Duration::from_nanos(rest)))
    .ok_or_else(past)?;
    file.set_times(FileTimes::new().set_accessed(at).set_modified(at))
}

/// `publish_staged` replaces `target` with `written` through a staging file it creates beside it, as
/// `staging` names, gives its mode and its modification time, and renames it over `target`, inside
/// `staging`'s gate where it has one.
///
/// # Errors
///
/// The staging file cannot be created, given its mode or its time, written, closed or renamed, `written`
/// is longer than the soft file size limit allows (`EFBIG`, before any byte is written), or the gate
/// returns an error, which is returned as it stands with the rename not run and the target as it stood;
/// the text names the target's path. Where the error comes before the rename, removal of the staging
/// file is attempted and its own failure is not reported.
pub fn publish_staged(
    target: &Path,
    written: &[u8],
    staging: Staging<'_>,
) -> Result<(), PathError> {
    let at_target = |error| PathError::new(target, error);
    let created = match staging.creation {
        Creation::Masked(_) | Creation::Exact(_) => 0o600,
        Creation::Mode(mode) => mode,
    };
    let (staged, mut file) =
        staging_with(target, created, staging.suffix, random_letters).map_err(at_target)?;
    let written = crate::fixtures::fits(written.len())
        .and_then(|()| match staging.creation {
            Creation::Masked(mask) => {
                file.set_permissions(fs::Permissions::from_mode(0o666 & !mask))
            }
            Creation::Exact(_) | Creation::Mode(_) => Ok(()),
        })
        .and_then(|()| file.write_all(written))
        .and_then(|()| match staging.creation {
            Creation::Exact(mode) => file.set_permissions(fs::Permissions::from_mode(mode)),
            Creation::Masked(_) | Creation::Mode(_) => Ok(()),
        })
        .and_then(|()| match staging.modified {
            Some(nanoseconds) => times(&file, nanoseconds),
            None => Ok(()),
        })
        .map_err(at_target);
    let closed = crate::fixtures::close(file).map_err(at_target);
    let renamed = std::cell::Cell::new(false);
    let mut rename = || {
        fs::rename(&staged, target)?;
        renamed.set(true);
        Ok(())
    };
    let done = written.and(closed).and_then(|()| {
        match staging.gate {
            Some(gate) => gate(&mut rename),
            None => rename(),
        }
        .map_err(at_target)
    });
    if done.is_err() && !renamed.get() {
        let _ = fs::remove_file(&staged);
    }
    done
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

/// The exit of a tool whose standard output refused its last lines: for the plant runner the score's
/// lines, after the score is written, or the help, when no score is written; for another tool its help,
/// its report or its result line.
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
