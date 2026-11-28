//! The scan reads a mode from the tree entry whose blob it reads: both name the same full commit id and path.

use std::collections::HashMap;

use crate::git::git_text;
use crate::text::Text;

use super::Failure;
use super::finding::short;
use super::hunks::DIFF_BATCH;

const TREE: &str = "040000";

/// `entries` returns `(mode, path)` for each record that `git --literal-pathspecs ls-tree -t -z --full-tree`
/// prints for `paths` at `commit`, every entry under them when `recursive` is set; each path names itself
/// from the top level. `-t` prints each tree that Git enters on the way to a deeper requested path, so a
/// requested path that is a tree has its record whatever else the batch requests. A record that is not
/// `<mode> <type> <id>`, a tab and a path is refused.
fn entries(
    commit: &str,
    paths: &[&str],
    recursive: bool,
) -> Result<Vec<(String, String)>, Failure> {
    let mut args = vec![
        "-c",
        "core.precomposeUnicode=false",
        "--literal-pathspecs",
        "ls-tree",
        "-t",
        "-z",
    ];
    if recursive {
        args.push("-r");
    }
    args.extend(["--full-tree", commit, "--"]);
    args.extend(paths);
    records(commit, &git_text(&args)?)
}

/// `records` reads each NUL-ended record of `listed` as `(mode, path)`, the path being all of the record
/// after its first tab, and names `commit` in the refusal of a record of another form.
pub(super) fn records(commit: &str, listed: &str) -> Result<Vec<(String, String)>, Failure> {
    let mut found = Vec::new();
    if !listed.is_empty() && !listed.ends_with('\0') {
        return Err(Failure::Refused(format!(
            "git ls-tree at {}: the listing ends inside a record",
            short(commit)
        )));
    }
    for record in listed.split_terminator('\0') {
        let parsed = record.split_once('\t').and_then(|(head, path)| {
            match head.split(' ').collect::<Vec<_>>().as_slice() {
                [mode, kind, id] if ![mode, kind, id].iter().any(|word| word.is_empty()) => {
                    Some(((*mode).to_owned(), path.to_owned()))
                }
                _ => None,
            }
        });
        found.push(parsed.ok_or_else(|| {
            Failure::Refused(format!(
                "git ls-tree at {}: the record {} has another form",
                short(commit),
                Text::from(record).repr()
            ))
        })?);
    }
    Ok(found)
}

/// `redirect` names the kind of an entry that a checkout reads another place through: `a link` for mode
/// `120000` and `a submodule` for mode `160000`.
fn redirect(mode: Option<&String>) -> Option<&'static str> {
    match mode.map(String::as_str) {
        Some("120000") => Some("a link"),
        Some("160000") => Some("a submodule"),
        _ => None,
    }
}

/// `regular` holds for the modes of a regular file, `100644` and `100755`.
pub fn regular(mode: &str) -> bool {
    matches!(mode, "100644" | "100755")
}

/// `ancestors` returns each directory above `path`, from the top level down: `a/b/c.rs` gives `a` and `a/b`.
fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/').map(|(at, _)| &path[..at])
}

/// `modes` returns the mode of each entry of `paths` that `commit` holds, and of each tree that Git enters on
/// the way to one, keyed by path. If a missing path has ancestors with a missing or non-`TREE` listed mode,
/// `modes` probes the topmost of them. If that ancestor is a link or a submodule, `modes` refuses the path
/// with `<path> at <short id> lies under <ancestor>, which is a link` (or `a submodule`), since a checkout
/// reads the path through that entry; an ancestor that is a regular file or absent leaves the path absent.
/// Each listing covers the batch's requested entries and the trees Git traverses to reach them.
fn modes(commit: &str, paths: &[&str]) -> Result<HashMap<String, String>, Failure> {
    let mut modes: HashMap<String, String> = HashMap::new();
    let list = |asked: &[&str], modes: &mut HashMap<String, String>| -> Result<(), Failure> {
        for (mode, path) in entries(commit, asked, false)? {
            if modes.get(&path).is_some_and(|known| *known != mode) {
                return Err(Failure::Refused(format!(
                    "git ls-tree at {}: the path {} has two entries",
                    short(commit),
                    Text::from(path.as_str()).repr()
                )));
            }
            modes.insert(path, mode);
        }
        Ok(())
    };
    for batch in paths.chunks(DIFF_BATCH) {
        let below = |path: &str| {
            batch.iter().any(|other| {
                other
                    .strip_prefix(path)
                    .is_some_and(|rest| rest.starts_with('/'))
            })
        };
        let leaves: Vec<&str> = batch.iter().copied().filter(|path| !below(path)).collect();
        list(&leaves, &mut modes)?;
        let probed: Vec<(&str, &str)> = batch
            .iter()
            .filter(|path| !modes.contains_key(**path))
            .filter_map(|&path| {
                ancestors(path)
                    .find(|ancestor| modes.get(*ancestor).map(String::as_str) != Some(TREE))
                    .map(|ancestor| (path, ancestor))
            })
            .collect();
        let mut asked: Vec<&str> = probed.iter().map(|&(_, ancestor)| ancestor).collect();
        asked.sort_unstable();
        asked.dedup();
        if !asked.is_empty() {
            list(&asked, &mut modes)?;
        }
        for (path, ancestor) in probed {
            if let Some(kind) = redirect(modes.get(ancestor)) {
                return Err(Failure::Refused(format!(
                    "{path} at {} lies under {ancestor}, which is {kind}",
                    short(commit)
                )));
            }
        }
    }
    Ok(modes)
}

/// A directory that [`directory`] found to be no link or submodule, and to lie under none, at one commit.
/// Its listing reads that same commit.
pub struct Directory<'c> {
    commit: &'c str,
    path: &'static str,
}

impl Directory<'_> {
    /// `listing` returns `(mode, path)` for the directory and every entry under it, as [`entries`] reads them.
    pub fn listing(&self) -> Result<Vec<(String, String)>, Failure> {
        entries(self.commit, &[self.path], true)
    }
}

/// `directory` refuses `dir` at `commit` when its entry is a link or a submodule, as
/// `<dir> at <short id> is a link` (or `a submodule`), and when it has no entry under such an ancestor, as
/// [`modes`] refuses a path.
pub fn directory<'c>(commit: &'c str, dir: &'static str) -> Result<Directory<'c>, Failure> {
    match redirect(modes(commit, &[dir])?.get(dir)) {
        Some(kind) => Err(Failure::Refused(format!(
            "{dir} at {} is {kind}",
            short(commit)
        ))),
        None => Ok(Directory { commit, path: dir }),
    }
}

/// `files` returns the paths of `paths` that `commit` holds, and refuses the first whose entry has a mode
/// other than `100644` and `100755` as `<path> at <short id> is not a file`. A path with no entry is an added
/// or deleted file unless [`modes`] refuses it for an ancestor.
pub fn files<'p>(commit: &str, paths: &[&'p str]) -> Result<Vec<&'p str>, Failure> {
    let modes = modes(commit, paths)?;
    let mut held = Vec::new();
    for &path in paths {
        match modes.get(path).map(String::as_str) {
            None => {}
            Some(mode) if regular(mode) => held.push(path),
            Some(_) => {
                return Err(Failure::Refused(format!(
                    "{path} at {} is not a file",
                    short(commit)
                )));
            }
        }
    }
    Ok(held)
}
