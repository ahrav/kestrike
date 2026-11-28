//! The Git reads of one ref line, each in the push's environment, and the two pure functions they feed:
//! the remote-tracking refs a destination selects, and the ignore spans of Rust source.

use std::ffi::{OsStr, OsString};
use std::process::Output;

use crate::environ::Environ;
use crate::git::{self as library, GitError};
use crate::rust_text::{FUNCTION, IGNORE};
use crate::text::Text;

use super::members::{Members, link_inputs, verus_sources};
use super::table::LINKS_REGISTRY;
use super::{Check, Failure, argument};

pub(super) const ZERO: &str = "0000000000000000000000000000000000000000";

/// A probe the caller runs once each Git read of the plan returns; `Err` carries the exit code of the
/// push, which ends as [`Failure::Cancelled`].
pub type Probe = fn() -> Result<(), u8>;

/// `Reads` is the environment of a plan's Git reads and the probe that runs once each read returns.
#[derive(Clone, Copy)]
pub(super) struct Reads<'a> {
    pub(super) environ: &'a Environ,
    pub(super) probe: Probe,
}

/// `probed` runs the probe of `reads` after `read` returned, and then gives `read`'s result, so a probe
/// that reports `Err` ends the plan before the result is used and before any later read starts.
fn probed<T>(reads: Reads<'_>, read: Result<T, GitError>) -> Result<T, Failure> {
    (reads.probe)().map_err(Failure::Cancelled)?;
    Ok(read?)
}

/// `git` is the library's read of Git's UTF-8 output, followed by the probe.
pub(super) fn git<S: AsRef<OsStr>>(reads: Reads<'_>, args: &[S]) -> Result<String, Failure> {
    probed(reads, library::git(reads.environ, args))
}

/// `output` is the library's run of Git that returns its output whatever its status, followed by the
/// probe.
fn output<S: AsRef<OsStr>>(reads: Reads<'_>, args: &[S]) -> Result<Output, Failure> {
    probed(reads, library::output(reads.environ, args))
}

/// `blob_bytes` is the library's batch read of objects, followed by the probe.
pub(super) fn blob_bytes(
    reads: Reads<'_>,
    names: &[String],
) -> Result<Vec<Option<Vec<u8>>>, Failure> {
    probed(reads, library::blob_bytes(reads.environ, names))
}

/// `revision` is `commit` followed by `suffix`, as one Git argument.
fn revision(commit: &Text, suffix: &str) -> OsString {
    let mut revision = argument(commit);
    revision.push(suffix);
    revision
}

/// `holds` holds when `git cat-file -e` of `path` at `commit` passes; a lookup that runs and exits
/// nonzero, for an object the clone lacks among other reasons, reads as `path` absent, and Git that cannot
/// start or a recorded signal ends the plan.
fn holds(reads: Reads<'_>, commit: &Text, path: &str) -> Result<bool, Failure> {
    let spec = revision(commit, &format!(":{path}"));
    Ok(
        output(reads, &[OsString::from("cat-file"), "-e".into(), spec])?
            .status
            .success(),
    )
}

/// `holds_check` holds when the tree of `commit` holds the file `check` asks for.
pub(super) fn holds_check(reads: Reads<'_>, commit: &Text, check: Check) -> Result<bool, Failure> {
    let path = check
        .row()
        .held
        .expect("a check whose presence the plan reads names the file it asks for");
    holds(reads, commit, path)
}

/// `comparison_base` returns the commit a tip's changes are read against: `remote` when this clone holds it
/// as a commit, else the merge base of `origin/main` and `local`, and `None` when the clone has no
/// `origin/main` or it shares no history with `local`.
pub(super) fn comparison_base(
    reads: Reads<'_>,
    local: &Text,
    remote: &Text,
) -> Result<Option<Text>, Failure> {
    if remote.to_str() != Some(ZERO) {
        let held = output(
            reads,
            &[
                OsString::from("cat-file"),
                "-e".into(),
                revision(remote, "^{commit}"),
            ],
        )?;
        if held.status.success() {
            return Ok(Some(remote.clone()));
        }
    }
    let listed = git(
        reads,
        &[
            "for-each-ref",
            "--format=%(refname)",
            "refs/remotes/origin/main",
        ],
    )?;
    if listed.is_empty() {
        return Ok(None);
    }
    let base = library::merge_base(
        reads.environ,
        OsString::from("origin/main"),
        argument(local),
    );
    Ok(probed(reads, base)?.map(Text::from))
}

/// `shown_file` returns the bytes `git show <commit>:<path>` prints, and `None` when it runs and exits
/// nonzero, for an object the clone lacks among other reasons; the callers read `None` as an absent file.
/// Git that cannot start or a recorded signal ends the plan.
fn shown_file(reads: Reads<'_>, commit: &Text, path: &str) -> Result<Option<Vec<u8>>, Failure> {
    let shown = output(
        reads,
        &[
            OsString::from("show"),
            revision(commit, &format!(":{path}")),
        ],
    )?;
    Ok(shown.status.success().then_some(shown.stdout))
}

/// `sources` returns the paths the Verus inventory at `commit` names: none for an inventory `git show`
/// cannot print, which reads as absent, and `None` for bytes [`verus_sources`] cannot iterate, on which
/// reconciliation runs and reports the defect.
pub(super) fn sources(reads: Reads<'_>, commit: &Text) -> Result<Option<Members>, Failure> {
    Ok(
        match shown_file(reads, commit, "verification/verus/inventory.json")? {
            None => Some(Members::default()),
            Some(bytes) => verus_sources(&bytes),
        },
    )
}

/// `links` returns the paths whose change needs the links check at `commit`. A commit that holds the check
/// without the registry returns the registry alone, so a push that removes the registry runs the check,
/// which refuses that tree; a commit with neither returns none. A registry `git show` cannot print reads as
/// absent, and bytes [`link_inputs`] cannot iterate return `None`, on which the check runs and reports the
/// defect.
pub(super) fn links(reads: Reads<'_>, commit: &Text) -> Result<Option<Members>, Failure> {
    let Some(bytes) = shown_file(reads, commit, LINKS_REGISTRY)? else {
        return Ok(Some(if holds_check(reads, commit, Check::Links)? {
            [LINKS_REGISTRY].into_iter().collect()
        } else {
            Members::default()
        }));
    };
    Ok(link_inputs(&bytes))
}

/// `destination_refs` returns the `git rev-list` arguments that select the remote-tracking refs of the
/// remote `name`, where `remotes` are the clone's remotes. The last argument globs over `refs/remotes/`, so
/// a name that is empty or holds a glob character selects nothing: it could select the refs of another
/// remote. The glob `name/*` also matches the refs of each remote whose name starts with `name/`, so an
/// exclusion of each such remote comes first. A name that starts with another remote's name and `/`
/// selects nothing: that remote's branches under the rest of the name have this remote's ref names.
pub fn destination_refs(name: &Text, remotes: &[Text]) -> Vec<Text> {
    let under = |text: &Text, prefix: &Text| {
        let mut prefix = prefix.clone();
        prefix.push_str("/");
        text.as_bytes().starts_with(prefix.as_bytes())
    };
    let glob = name
        .code_points()
        .any(|code| matches!(code, 0x2a | 0x3f | 0x5b | 0x5c));
    if name.is_empty() || glob || remotes.iter().any(|other| under(name, other)) {
        return Vec::new();
    }
    let mut refs: Vec<Text> = remotes
        .iter()
        .filter(|other| under(other, name))
        .map(|other| {
            let mut exclusion = Text::from("--exclude=");
            exclusion.push_text(other);
            exclusion.push_str("/*");
            exclusion
        })
        .collect();
    let mut selected = Text::from("--remotes=");
    selected.push_text(name);
    refs.push(selected);
    refs
}

/// `ignored_tests` returns the text of each ignore attribute of `text` through the name of the fn it
/// precedes, skipping the attributes between the two, so a `should_panic` string that holds no `]` cannot
/// stand in for the fn name. The search reads the raw text: a `fn <name>` inside a comment or a string, and
/// a `]` inside an attribute's string, end a span where they stand. A span with no fn after its attribute
/// runs to the end of the text.
pub fn ignored_tests(text: &str) -> Vec<&str> {
    spans(text, |from| FUNCTION.find_at(text, from))
}

/// `spans` is [`ignored_tests`] with `search` finding the first fn at or after an offset. A fn found after
/// one attribute is the next attribute's fn too while its match starts at or after that attribute's end,
/// and once no fn follows an attribute none follows a later one, so the attributes that end before one fn's
/// match share one search.
pub(super) fn spans<'t>(
    text: &'t str,
    mut search: impl FnMut(usize) -> Option<regex::Match<'t>>,
) -> Vec<&'t str> {
    let mut spans = Vec::new();
    // Each attribute `IGNORE` matches holds the word `ignore`, so a text without it has no span.
    if !text.contains("ignore") {
        return spans;
    }
    let mut function = None;
    let mut searched = false;
    for found in IGNORE.find_iter(text) {
        let stale =
            function.is_some_and(|function: regex::Match<'_>| function.start() < found.end());
        if !searched || stale {
            function = search(found.end());
            searched = true;
        }
        spans.push(&text[found.start()..function.map_or(text.len(), |function| function.end())]);
    }
    spans
}

/// `changes_ignore` holds when the push changes an ignore attribute of Rust source or the name of the fn it
/// precedes, at `base` against `local`. A renamed ignored test changes its span as an edited attribute
/// does, and an edit elsewhere in a file leaves each span equal. A Rust path that holds a line feed, which a
/// batch name cannot carry, holds without a read. Each file is read with every byte sequence outside UTF-8
/// replaced by U+FFFD, and an absent file or an object other than a blob reads as an empty text.
pub(super) fn changes_ignore(
    reads: Reads<'_>,
    base: &Text,
    local: &Text,
    paths: &[String],
) -> Result<bool, Failure> {
    let rust: Vec<&String> = paths.iter().filter(|path| path.ends_with(".rs")).collect();
    if rust.iter().any(|path| path.contains('\n')) {
        return Ok(true);
    }
    if rust.is_empty() {
        return Ok(false);
    }
    let (Some(base), Some(local)) = (base.to_str(), local.to_str()) else {
        let named = if base.to_str().is_none() { base } else { local };
        return Err(Failure::Unencodable(named.clone()));
    };
    let names: Vec<String> = rust
        .iter()
        .flat_map(|path| [base, local].map(|commit| format!("{commit}:{path}")))
        .collect();
    let texts: Vec<String> = blob_bytes(reads, &names)?
        .into_iter()
        .map(|bytes| {
            String::from_utf8(bytes.unwrap_or_default())
                .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned())
        })
        .collect();
    Ok(texts
        .chunks(2)
        .any(|pair| ignored_tests(&pair[0]) != ignored_tests(&pair[1])))
}
