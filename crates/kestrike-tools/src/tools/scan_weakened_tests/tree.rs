//! The scan reads a mode from the tree entry whose blob it reads: both name the same full commit id and path.

use std::collections::{HashMap, HashSet};

use crate::git::git_text;
use crate::text::Text;

use super::Failure;
use super::finding::short;
use super::hunks::DIFF_BATCH;

/// `entries` returns `(mode, path)` for each record that `git --literal-pathspecs ls-tree -t -z --full-tree`
/// prints for `paths` at `commit`, every entry under them when `recursive` is set; each path names itself
/// from the top level. `-t` prints each tree that Git enters on the way to a deeper requested path, so a
/// requested path that is a tree has its record whatever else the batch requests. A record that is not
/// `<mode> <type> <id>`, a tab and a path is refused.
pub fn entries(
    commit: &str,
    paths: &[&str],
    recursive: bool,
) -> Result<Vec<(String, String)>, Failure> {
    let mut args = vec!["--literal-pathspecs", "ls-tree", "-t", "-z"];
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
pub fn redirect(mode: Option<&String>) -> Option<&'static str> {
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

/// `modes` returns the mode of each entry that `commit` holds among `paths` and their ancestors, keyed by path.
/// Each batch of the diff's size lists its paths and their ancestors by their literal names in one
/// `git ls-tree` call; the listing also holds the entries beside each ancestor, which no caller asks for. A
/// path with no entry is refused when an ancestor is a link or a submodule, as
/// `<path> at <short id> lies under <ancestor>, which is a link` (or `a submodule`): a checkout reads the path
/// through that entry. An ancestor that is a directory, a regular file or absent leaves the path absent.
pub fn modes(commit: &str, paths: &[&str]) -> Result<HashMap<String, String>, Failure> {
    let mut modes = HashMap::new();
    for batch in paths.chunks(DIFF_BATCH) {
        let mut asked: Vec<&str> = batch.to_vec();
        let mut seen: HashSet<&str> = batch.iter().copied().collect();
        for path in batch {
            asked.extend(ancestors(path).filter(|ancestor| seen.insert(ancestor)));
        }
        modes.extend(
            entries(commit, &asked, false)?
                .into_iter()
                .map(|(mode, path)| (path, mode)),
        );
    }
    for &path in paths.iter().filter(|path| !modes.contains_key(**path)) {
        if let Some((ancestor, kind)) = ancestors(path)
            .find_map(|ancestor| redirect(modes.get(ancestor)).map(|kind| (ancestor, kind)))
        {
            return Err(Failure::Refused(format!(
                "{path} at {} lies under {ancestor}, which is {kind}",
                short(commit)
            )));
        }
    }
    Ok(modes)
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
