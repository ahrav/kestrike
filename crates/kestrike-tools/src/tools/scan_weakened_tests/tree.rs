//! The scan reads a mode from the tree entry whose blob it reads: both name the same full commit id and path.

use std::collections::HashMap;

use crate::git::git_text;
use crate::text::Text;

use super::Failure;
use super::hunks::DIFF_BATCH;
use super::scan::short;

/// `entries` returns `(mode, path)` for each record that `git ls-tree -z --full-tree` prints for `paths` at
/// `commit`, every blob under them when `recursive` is set. A tree above a requested path is entered and not
/// printed, so a requested path that is such a tree has no record. A record that is not
/// `<mode> <type> <id>`, a tab and a path is refused.
pub fn entries(
    commit: &str,
    paths: &[&str],
    recursive: bool,
) -> Result<Vec<(String, String)>, Failure> {
    let mut args = vec![
        "--no-literal-pathspecs".to_owned(),
        "ls-tree".to_owned(),
        "-z".to_owned(),
    ];
    if recursive {
        args.push("-r".to_owned());
    }
    args.extend(["--full-tree", commit, "--"].map(str::to_owned));
    args.extend(paths.iter().map(|path| format!(":(top,literal){path}")));
    let listed = git_text(&args)?;
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

/// `files` returns the paths of `paths` that `commit` holds, and refuses the first whose entry has a mode
/// other than `100644` and `100755` as `<path> at <short id> is not a file`. A path with no entry is an
/// added or deleted file. It lists the paths in batches of the diff's size.
pub fn files<'p>(commit: &str, paths: &[&'p str]) -> Result<Vec<&'p str>, Failure> {
    let mut modes = HashMap::new();
    for batch in paths.chunks(DIFF_BATCH) {
        modes.extend(
            entries(commit, batch, false)?
                .into_iter()
                .map(|(mode, path)| (path, mode)),
        );
    }
    let mut held = Vec::new();
    for &path in paths {
        match modes.get(path).map(String::as_str) {
            None => {}
            Some("100644" | "100755") => held.push(path),
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
