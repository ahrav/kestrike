//! The run's work directory: a new directory outside the checkout, under ancestors only this user or
//! root owns and can write, so no other user can configure the Cargo builds of its worktrees.
//!
//! `--work DIR` names it, from the invoking directory, with `.`, `..` and repeated slashes read lexically
//! and its parent's links resolved; the directory itself must be new, and each missing ancestor is made
//! with mode 0700 under the umask. Without `--work` it is `plant-runner-` and eight letters, mode 0700,
//! under `TMPDIR`, from the invoking directory, or under `/tmp` when `TMPDIR` is unset or empty.

use std::ffi::OsStr;
use std::fs::DirBuilder;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use super::prepare::Stop;
use crate::ownership::{PathError, foreign_toolchain_paths, make_private, status};
use crate::paths::{self, normalize};
use crate::temp_dir::make_temp_dir;
use crate::text::Text;

const PREFIX: &str = "plant-runner-";
const DEFAULT_PARENT: &str = "/tmp";

/// `absolute` joins `path` to the invoking directory `here` and reads it lexically.
fn absolute(here: &Path, path: &OsStr) -> PathBuf {
    let joined = here.join(path);
    PathBuf::from(OsStr::from_bytes(&normalize(joined.as_os_str().as_bytes())))
}

fn failed(error: &PathError) -> Stop {
    Stop::Failed(Text::from(format!(
        "an ancestor of the work directory cannot be read: {error}"
    )))
}

fn rejected(reason: String) -> Stop {
    Stop::Rejected(Text::from(reason))
}

/// `work_directory` makes the run's work directory and returns its path.
///
/// # Errors
///
/// The parent cannot be resolved, the directory lies inside `top`, another user owns or can write an
/// ancestor or a Cargo or rustup entry of one, or the directory cannot be made: each refuses the run. An
/// ancestor whose `stat` fails otherwise than as an absent path is a failure.
pub(super) fn work_directory(
    work: Option<&OsStr>,
    tmpdir: Option<&OsStr>,
    here: &Path,
    top: &Path,
) -> Result<PathBuf, Stop> {
    let chosen = work.map(|work| absolute(here, work));
    let unresolved = match &chosen {
        Some(chosen) => chosen.parent().unwrap_or(chosen).to_path_buf(),
        None => match tmpdir.filter(|tmpdir| !tmpdir.is_empty()) {
            Some(tmpdir) => absolute(here, tmpdir),
            None => PathBuf::from(DEFAULT_PARENT),
        },
    };
    let parent = paths::resolve(&unresolved).map_err(|error| {
        rejected(format!(
            "the work directory's parent cannot be resolved: {error}"
        ))
    })?;
    let place = match chosen.as_deref().and_then(Path::file_name) {
        Some(name) => parent.join(name),
        None => parent.clone(),
    };
    if place.starts_with(top) {
        return Err(Stop::Rejected(Text::from(format!(
            "the work directory {} lies inside the checkout",
            Text::from_os(place.as_os_str())
        ))));
    }
    let mut existing = &*parent;
    for ancestor in parent.ancestors() {
        if status(ancestor).map_err(|error| failed(&error))?.is_some() {
            existing = ancestor;
            break;
        }
    }
    let foreign = foreign_toolchain_paths(existing).map_err(|error| failed(&error))?;
    if !foreign.is_empty() {
        let way = if chosen.is_none() {
            "pass --work DIR or set TMPDIR, naming a directory only you control on xfs or journaled ext4"
        } else {
            "choose a work directory under a directory only you control"
        };
        let shown: Vec<String> = foreign
            .iter()
            .map(|path| Text::from_os(path.as_os_str()).to_string())
            .collect();
        return Err(rejected(format!(
            "another user owns or can write {}, and so can configure Cargo in the run's worktrees; {way}",
            shown.join(", ")
        )));
    }
    let made = if chosen.is_none() {
        make_temp_dir(PREFIX, &parent).map_err(|error| error.to_string())
    } else {
        make_private(&parent)
            .map_err(|error| error.to_string())
            .and_then(|()| {
                DirBuilder::new()
                    .mode(0o700)
                    .create(&place)
                    .map_err(|error| PathError::new(&place, error).to_string())
            })
            .map(|()| place)
    };
    made.map_err(|error| rejected(format!("the work directory: {error}")))
}
