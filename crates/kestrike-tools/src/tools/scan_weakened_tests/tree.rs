//! The scan reads a mode from the tree entry whose blob it reads: both name the same full commit id and path.

use std::collections::HashMap;

use crate::environ::Environ;
use crate::git::git_text;
use crate::text::{Text, escaped};

use super::Failure;
use super::finding::short;
use super::hunks::DIFF_BATCH;

/// `entries` returns `(mode, path)` for each record that `git --literal-pathspecs ls-tree -t -z --full-tree`
/// prints for `paths` at `commit`, every entry under them when `recursive` is set; each path names itself
/// from the top level. `-t` prints each tree that Git enters on the way to a deeper requested path, so a
/// requested path that is a tree has its record whatever else the batch requests. A record that is not
/// `<mode> <type> <id>`, a tab and a path is refused.
pub fn entries(
    environ: &Environ,
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
    records(commit, &git_text(environ, &args)?)
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

/// `regular` holds for the modes of a regular file, `100644` and `100755`.
pub fn regular(mode: &str) -> bool {
    matches!(mode, "100644" | "100755")
}

/// `files` returns the paths of `paths` that `commit` holds, and refuses the first whose entry has a mode
/// other than `100644` and `100755` as `<path> at <short id> is not a file`, the path written through
/// [`escaped`]. A path with no entry is an
/// added or deleted file. It lists the paths in batches of the diff's size.
pub fn files<'p>(
    environ: &Environ,
    commit: &str,
    paths: &[&'p str],
) -> Result<Vec<&'p str>, Failure> {
    let mut modes = HashMap::new();
    for batch in paths.chunks(DIFF_BATCH) {
        modes.extend(
            entries(environ, commit, batch, false)?
                .into_iter()
                .map(|(mode, path)| (path, mode)),
        );
    }
    let mut held = Vec::new();
    for &path in paths {
        match modes.get(path).map(String::as_str) {
            None => {}
            Some(mode) if regular(mode) => held.push(path),
            Some(_) => {
                return Err(Failure::Refused(format!(
                    "{} at {} is not a file",
                    escaped(path),
                    short(commit)
                )));
            }
        }
    }
    Ok(held)
}
