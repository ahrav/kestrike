//! A case of the tools crate is a top-level entry of its test directory: a regular file `<id>.rs`, or a
//! directory `<id>` whose root file is regular, with `<id>` matching `[a-z][a-z0-9_]*` and other than `tools`.
//! A directory's root is `mod.rs`, or also `main.rs` at a commit without the regular file `tools.rs`, the root
//! of the one test executable, where each case was a test executable of its own. The scan reads both
//! commits' trees, and a case of the base that the head lacks under its id blocks.

use std::collections::HashSet;

use super::tree::entries;
use super::{Change, Class, Failure, Finding, Shown};

pub const CASES: &str = "crates/kestrike-tools/tests";

/// `cases` returns the id and the entry path of each case at `commit`, in tree order.
fn cases(commit: &str) -> Result<Vec<(String, String)>, Failure> {
    let listed = entries(commit, &[CASES], true)?;
    let regular = |mode: &str| matches!(mode, "100644" | "100755");
    let single = listed
        .iter()
        .any(|(mode, path)| regular(mode) && *path == format!("{CASES}/tools.rs"));
    let roots: &[&str] = if single {
        &["mod.rs"]
    } else {
        &["mod.rs", "main.rs"]
    };
    let mut found: Vec<(String, String)> = Vec::new();
    for (mode, path) in listed {
        let Some(rest) = path
            .strip_prefix(CASES)
            .and_then(|rest| rest.strip_prefix('/'))
        else {
            continue;
        };
        let case = match rest.split_once('/') {
            None => rest.strip_suffix(".rs").map(|id| (id, path.clone())),
            Some((id, root)) if roots.contains(&root) => Some((id, format!("{CASES}/{id}"))),
            Some(_) => None,
        };
        let Some((id, entry)) = case else {
            continue;
        };
        let named = id.starts_with(|c: char| c.is_ascii_lowercase())
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if named && regular(&mode) && id != "tools" && !found.iter().any(|(_, seen)| *seen == entry)
        {
            found.push((id.to_owned(), entry));
        }
    }
    Ok(found)
}

/// `removed` returns a finding for each case at `base` whose id names no case at `head`. A case renamed to
/// another id is the absence of its old id.
pub fn removed(base: &str, head: &str) -> Result<Vec<Finding>, Failure> {
    let present: HashSet<String> = cases(head)?.into_iter().map(|(id, _)| id).collect();
    Ok(cases(base)?
        .into_iter()
        .filter(|(id, _)| !present.contains(id))
        .map(|(id, path)| Finding {
            path,
            change: Change::new(
                Class::CaseRemoved,
                format!("case {id}"),
                Shown::Word("present".to_owned()),
                Shown::absent(),
            ),
        })
        .collect())
}
