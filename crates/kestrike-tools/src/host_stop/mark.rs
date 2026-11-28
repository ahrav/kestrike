//! A mark's write: the bytes stand at their name whole and synced, or the result says what stands.
//!
//! [`publish`] opens the directory without following a link and makes every later step on that open
//! directory: it opens a file there that has no name (`O_TMPFILE`, mode 0644), writes every byte, syncs
//! the file, links it to the name, then syncs the file and directory. A failure or process kill before
//! the link leaves the destination unchanged; an entry already at the name fails the link and keeps
//! its bytes. If a sync fails after the link, the function tries to remove the name. If removal
//! succeeds, the function syncs the directory. The result says whether that sync returned success,
//! returned an error, or the removal failed with the mark standing.

use std::ffi::OsStr;
use std::io;
use std::path::Path;

use super::files::{Files, Links, proc_path};
use crate::plants::files::strerror;
use crate::text::Text;

/// The step of a write that failed, up to and including the link. [`Step::Link`] with `EEXIST`
/// reports an entry already at the name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The name is other than one path component; no step ran.
    Name,
    OpenDirectory,
    /// The open of the file with no name.
    OpenUnnamed,
    Write,
    /// The file's sync before the link.
    Sync,
    Link,
}

/// A mark the write left other than standing whole and synced.
#[derive(Debug)]
pub enum Unwritten {
    /// A failure through the link step leaves the destination unchanged: an absent name stays absent,
    /// and an existing entry keeps its bytes.
    Failed { step: Step, error: io::Error },
    /// A write returned `0` before the link, leaving the destination unchanged.
    Stalled,
    /// After a post-link sync fails with `error`, `publish` removes the name and successfully syncs
    /// the directory. If the directory sync returned `error`, `publish` syncs the same descriptor after
    /// removal.
    Removed { error: io::Error },
    /// A sync after the link failed with `error`; the name is removed, and the directory's sync after
    /// the removal failed with `removal`, so the mark may stand again after a crash.
    RemovalUnsynced {
        error: io::Error,
        removal: io::Error,
    },
    /// A sync after the link failed with `error`, and the removal failed with `removal`: the mark
    /// stands whole, its durability unknown.
    Stands {
        error: io::Error,
        removal: io::Error,
    },
}

impl Unwritten {
    /// Whether the mark was linked to its name before the failure.
    pub fn linked(&self) -> bool {
        matches!(
            self,
            Self::Removed { .. } | Self::RemovalUnsynced { .. } | Self::Stands { .. }
        )
    }

    /// Whether the mark stands at its name.
    pub fn stands(&self) -> bool {
        matches!(self, Self::Stands { .. })
    }

    /// The sentence that names this failure of the mark at `path`: the system's text of the error for
    /// a failed step, and for a failure after the link what stands and whether a crash may change it.
    pub fn sentence(&self, path: &Path) -> Text {
        let mut sentence = Text::new();
        let shown = Text::from_os(path.as_os_str());
        match self {
            Self::Failed { error, .. } => sentence.push_str(&strerror(error)),
            Self::Stalled => {
                sentence.push_str("a write of ");
                sentence.push_text(&Text::from_os(path.file_name().unwrap_or(path.as_os_str())));
                sentence.push_str(" made no progress");
            }
            Self::Removed { error } => {
                sentence.push_text(&shown);
                sentence.push_str(" cannot be synced, so the mark is removed: ");
                sentence.push_str(&strerror(error));
            }
            Self::RemovalUnsynced { error, .. } => {
                sentence.push_text(&shown);
                sentence.push_str(&format!(
                    " cannot be synced ({}), so it is removed; the removal is unsynced, so the mark \
                     may stand again after a crash",
                    strerror(error)
                ));
            }
            Self::Stands { error, .. } => {
                sentence.push_text(&shown);
                sentence.push_str(&format!(
                    " stands, but it cannot be synced ({}) and cannot be removed, so it may not \
                     survive a crash",
                    strerror(error)
                ));
            }
        }
        sentence
    }
}

/// `publish` writes `data` to `name` in `directory` only if `name` is vacant. On storage that honors
/// file and directory syncs, a mark `publish` returns `Ok` for survives a crash within `directory`;
/// the directory's own entry is the caller's to sync.
///
/// # Errors
///
/// [`Unwritten`] names the step that failed and what this write left at the name.
pub fn publish(
    files: &impl Files,
    directory: &Path,
    name: &OsStr,
    data: &[u8],
) -> Result<(), Unwritten> {
    let failed = |step| move |error| Unwritten::Failed { step, error };
    if !one_component(name) {
        let error = io::Error::new(
            io::ErrorKind::InvalidInput,
            "a mark's name is one path component",
        );
        return Err(Unwritten::Failed {
            step: Step::Name,
            error,
        });
    }
    let held = files
        .open_directory(directory, Links::Refuse)
        .map_err(failed(Step::OpenDirectory))?;
    let unnamed = files
        .open_unnamed(&proc_path(&held))
        .map_err(failed(Step::OpenUnnamed))?;
    let mut rest = data;
    while !rest.is_empty() {
        let written = match files.write(&unnamed, rest) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            written => written.map_err(failed(Step::Write))?,
        };
        if written == 0 {
            return Err(Unwritten::Stalled);
        }
        rest = rest.get(written..).unwrap_or_default();
    }
    files.fsync(&unnamed).map_err(failed(Step::Sync))?;
    files
        .link(&unnamed, &held, name)
        .map_err(failed(Step::Link))?;
    if let Err(error) = files
        .fsync(&unnamed)
        .and_then(|()| files.fsync_directory(&held))
    {
        return Err(match files.unlink(&held, name) {
            Err(removal) => Unwritten::Stands { error, removal },
            Ok(()) => match files.fsync_directory(&held) {
                Err(removal) => Unwritten::RemovalUnsynced { error, removal },
                Ok(()) => Unwritten::Removed { error },
            },
        });
    }
    Ok(())
}

fn one_component(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    !bytes.is_empty()
        && bytes != b"."
        && bytes != b".."
        && !bytes.contains(&b'/')
        && !bytes.contains(&0)
}

/// Syncs the entries of `directory`, opened following a link. On storage that honors a directory's
/// sync, entry creation and removal survive a crash.
///
/// # Errors
///
/// The open or the sync fails.
pub fn sync_directory(files: &impl Files, directory: &Path) -> io::Result<()> {
    let held = files.open_directory(directory, Links::Follow)?;
    files.fsync_directory(&held)
}
