//! The chaos record guard: the entries of a tip's chaos tree, the records pushed commits add or change, and
//! the read of each record for what may be an AWS account number.

use std::collections::HashSet;
use std::ffi::OsString;
use std::sync::LazyLock;

use regex::Regex;

use crate::classes::compiled;
use crate::environ::Environ;
use crate::git::{blob_bytes, git};
use crate::json::{Value, parse_members};
use crate::text::Text;

use super::{Failure, argument, short, shown};

/// The directories that hold chaos records.
pub(super) const RECORD_DIRS: [&str; 4] = [
    "chaos/receipts",
    "chaos/runs",
    "chaos/tests/receipts",
    "chaos/tests/runs",
];

/// `record_pathspecs` names each record directory from the top level.
pub(super) fn record_pathspecs() -> impl Iterator<Item = OsString> {
    RECORD_DIRS
        .iter()
        .map(|dir| OsString::from(format!(":(top){dir}")))
}

const CHAOS_TREES: [&str; 6] = [
    "chaos",
    "chaos/tests",
    RECORD_DIRS[0],
    RECORD_DIRS[1],
    RECORD_DIRS[2],
    RECORD_DIRS[3],
];

/// A receipt, any `.json` path under a receipts directory, or a run record, `run.json` of a run directory.
/// The whole path must match, and `.` matches a line feed too.
pub(super) static CHAOS_RECORD: LazyLock<Regex> = LazyLock::new(|| {
    compiled(
        r"(?s)\A(?:chaos/(?:tests/)?receipts/.+\.json|chaos/(?:tests/)?runs/[^/]+/run\.json)\z",
    )
});

const REGULAR: [&str; 2] = ["100644", "100755"];
const LINKS_OR_SUBMODULES: [&str; 2] = ["120000", "160000"];

/// A chaos record: the commit that names it, its path, and the id of its blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub commit: Text,
    pub path: String,
    pub oid: String,
}

/// `form` is the refusal of a Git line of a form its manual does not give.
fn form(command: &str, commit: &Text, line: &str) -> Failure {
    Failure::Form(format!(
        "git {command} at {}: the record {} has another form",
        short(commit),
        Text::from(line).repr()
    ))
}

/// `tip_records` returns the failures of the chaos tree at `commit` and the records it holds. An entry
/// that is a link or a submodule, a chaos tree that is no directory, and a record path that is no regular
/// file each fail, so the records read are the ones the tree itself holds.
pub(super) fn tip_records(
    environ: &Environ,
    commit: &Text,
) -> Result<(Vec<String>, Vec<Record>), Failure> {
    let mut args = vec![
        OsString::from("ls-tree"),
        "-r".into(),
        "-t".into(),
        "-z".into(),
        "--full-tree".into(),
    ];
    args.extend([argument(commit), "--".into(), "chaos".into()]);
    let listed = git(environ, &args)?;
    let (mut failures, mut records) = (Vec::new(), Vec::new());
    for entry in listed.split('\0').filter(|entry| !entry.is_empty()) {
        let parsed = entry.split_once('\t').and_then(|(meta, path)| {
            let fields: Vec<&str> = crate::text::words(meta).collect();
            match fields.as_slice() {
                [mode, kind, oid] => Some((*mode, *kind, *oid, path)),
                _ => None,
            }
        });
        let (mode, kind, oid, path) = parsed.ok_or_else(|| form("ls-tree", commit, entry))?;
        let at = format!("{} at {}", shown(path), short(commit));
        if LINKS_OR_SUBMODULES.contains(&mode) {
            failures.push(format!("{at} is a link or a submodule"));
        } else if CHAOS_TREES.contains(&path) && kind != "tree" {
            failures.push(format!("{at} is not a directory"));
        } else if CHAOS_RECORD.is_match(path) {
            if REGULAR.contains(&mode) {
                records.push(Record {
                    commit: commit.clone(),
                    path: path.to_owned(),
                    oid: oid.to_owned(),
                });
            } else {
                failures.push(format!("{at} is a chaos record that is not a regular file"));
            }
        }
    }
    Ok((failures, records))
}

/// `pushed_records` returns the failures of the chaos records that `commits` add or change, and those
/// records. Each merge's change against each of its parents counts, and a root commit adds each record it
/// holds. A record that a commit deletes is skipped, and a commit that makes a record path a link or a
/// submodule fails: Git sends that entry with the commit, and it is no JSON record to read.
pub(super) fn pushed_records(
    environ: &Environ,
    commits: &[Text],
) -> Result<(Vec<String>, Vec<Record>), Failure> {
    let (mut failures, mut records) = (Vec::new(), Vec::new());
    for commit in commits {
        let mut args: Vec<OsString> = [
            "diff-tree",
            "-r",
            "-z",
            "-m",
            "--root",
            "--no-renames",
            "--no-commit-id",
        ]
        .map(OsString::from)
        .to_vec();
        args.extend([argument(commit), "--".into()]);
        args.extend(record_pathspecs());
        let listed = git(environ, &args)?;
        let fields: Vec<&str> = listed.split('\0').collect();
        for at in (0..fields.len().saturating_sub(1)).step_by(2) {
            let words: Vec<&str> = crate::text::words(fields[at]).collect();
            let [_, mode, _, oid, status] = words.as_slice() else {
                return Err(form("diff-tree", commit, fields[at]));
            };
            let path = fields[at + 1];
            if *status == "D" || !CHAOS_RECORD.is_match(path) {
                continue;
            }
            if REGULAR.contains(mode) {
                records.push(Record {
                    commit: commit.clone(),
                    path: path.to_owned(),
                    oid: (*oid).to_owned(),
                });
            } else {
                failures.push(format!(
                    "{} at {} is a chaos record that is not a regular file",
                    shown(path),
                    short(commit)
                ));
            }
        }
    }
    Ok((failures, records))
}

/// `account_numbers` returns a failure for each of `records` that holds what may be an AWS account number,
/// that is not JSON, or that Git cannot read, read with every byte sequence outside UTF-8 replaced by
/// U+FFFD. Each blob is read once and named by the first record that holds it.
///
/// # Errors
///
/// The batch read of the blobs fails.
pub fn account_numbers(environ: &Environ, records: &[Record]) -> Result<Vec<String>, Failure> {
    let mut seen = HashSet::new();
    let unique: Vec<&Record> = records
        .iter()
        .filter(|record| seen.insert(record.oid.as_str()))
        .collect();
    if unique.is_empty() {
        return Ok(Vec::new());
    }
    let oids: Vec<String> = unique.iter().map(|record| record.oid.clone()).collect();
    let blobs = blob_bytes(environ, &oids)?;
    let mut failures = Vec::new();
    for (record, blob) in unique.iter().zip(blobs) {
        let at = format!("{} at {}", shown(&record.path), short(&record.commit));
        let Some(bytes) = blob else {
            failures.push(format!("{at} is a chaos record Git could not read"));
            continue;
        };
        match record_values(&String::from_utf8_lossy(&bytes)) {
            None => failures.push(format!("{at} is a chaos record that is not JSON")),
            Some(values) if values.iter().any(account_number) => {
                failures.push(format!("{at} holds what may be an AWS account number"));
            }
            Some(_) => {}
        }
    }
    Ok(failures)
}

/// `record_values` returns each key, string and integer of the JSON document `text` as text, a repeated
/// key's earlier members included, and `None` when `text` is no JSON document. The decoded text is matched,
/// so a JSON escape before a number ends a match as the decoded character does. A float is no account
/// number, so it is skipped, and so are Booleans and `null`.
pub fn record_values(text: &str) -> Option<Vec<Text>> {
    let mut pending = vec![parse_members(text).ok()?];
    let mut found = Vec::new();
    while let Some(value) = pending.pop() {
        match value {
            Value::Array(items) => pending.extend(items),
            Value::String(text) => found.push(text),
            Value::Integer(integer) => found.push(Text::from(integer.to_string())),
            Value::Object(_) => {
                unreachable!("a read that keeps every member reads objects as arrays")
            }
            Value::Float(_) | Value::Bool(_) | Value::Null => {}
        }
    }
    Some(found)
}

/// `account_number` holds when `value` holds 12 ASCII digits with no ASCII letter or digit beside them, so a
/// digit run inside a SHA-256 digest is no match, or three groups of 4 ASCII digits joined by `-` with no
/// ASCII letter, digit or `-` beside them.
pub fn account_number(value: &Text) -> bool {
    let codes: Vec<u32> = value.code_points().collect();
    let digit = |at: usize| {
        codes
            .get(at)
            .is_some_and(|&code| (0x30..=0x39).contains(&code))
    };
    let word = |at: Option<usize>| {
        at.and_then(|at| codes.get(at))
            .and_then(|&code| char::from_u32(code))
            .is_some_and(|c| c.is_ascii_alphanumeric())
    };
    let dash = |at: Option<usize>| at.and_then(|at| codes.get(at)) == Some(&0x2d);
    let digits = |from: usize, count: usize| (from..from + count).all(digit);
    (0..codes.len()).any(|at| {
        let before = at.checked_sub(1);
        let twelve = !word(before) && digits(at, 12) && !word(Some(at + 12));
        let grouped = !word(before)
            && !dash(before)
            && digits(at, 4)
            && dash(Some(at + 4))
            && digits(at + 5, 4)
            && dash(Some(at + 9))
            && digits(at + 10, 4)
            && !word(Some(at + 14))
            && !dash(Some(at + 14));
        twelve || grouped
    })
}
