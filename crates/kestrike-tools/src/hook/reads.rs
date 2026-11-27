//! The Git reads of one ref line, each in the push's environment, and the two pure functions they feed:
//! the remote-tracking refs a destination selects, and the ignore spans of Rust source.

use std::ffi::OsString;

use crate::environ::Environ;
use crate::git::{blob_bytes, git, merge_base, output};
use crate::rust_text::{FUNCTION, IGNORE};
use crate::text::Text;

use super::Failure;
use super::members::{Members, link_inputs, verus_sources};
use super::table::{LINKS_REGISTRY, ORDER};

pub(super) const ZERO: &str = "0000000000000000000000000000000000000000";

/// `revision` is `commit` followed by `suffix`, as one Git argument.
fn revision(commit: &Text, suffix: &str) -> OsString {
    let mut argument = commit
        .to_os()
        .expect("a ref line's field is read from bytes, which it encodes");
    argument.push(suffix);
    argument
}

/// `holds` holds when the tree of `commit` holds `path`, as `git cat-file -e` reports it.
pub(super) fn holds(environ: &Environ, commit: &Text, path: &str) -> Result<bool, Failure> {
    let spec = revision(commit, &format!(":{path}"));
    Ok(
        output(environ, &[OsString::from("cat-file"), "-e".into(), spec])?
            .status
            .success(),
    )
}

/// `comparison_base` returns the commit a tip's changes are read against: `remote` when this clone holds it
/// as a commit, else the merge base of `origin/main` and `local`, and `None` when the clone has no
/// `origin/main` or it shares no history with `local`.
pub(super) fn comparison_base(
    environ: &Environ,
    local: &Text,
    remote: &Text,
) -> Result<Option<Text>, Failure> {
    if remote.to_str() != Some(ZERO) {
        let held = output(
            environ,
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
        environ,
        &[
            "for-each-ref",
            "--format=%(refname)",
            "refs/remotes/origin/main",
        ],
    )?;
    if listed.is_empty() {
        return Ok(None);
    }
    let local = revision(local, "");
    Ok(merge_base(environ, OsString::from("origin/main"), local)?.map(Text::from))
}

/// `shown_file` returns the bytes `git show <commit>:<path>` prints, and `None` when it fails.
fn shown_file(environ: &Environ, commit: &Text, path: &str) -> Result<Option<Vec<u8>>, Failure> {
    let shown = output(
        environ,
        &[
            OsString::from("show"),
            revision(commit, &format!(":{path}")),
        ],
    )?;
    Ok(shown.status.success().then_some(shown.stdout))
}

/// `sources` returns the paths the Verus inventory at `commit` names: none for an absent inventory, and
/// `None` for one that cannot be read, on which reconciliation runs and reports the defect.
pub(super) fn sources(environ: &Environ, commit: &Text) -> Result<Option<Members>, Failure> {
    Ok(
        match shown_file(environ, commit, "verification/verus/inventory.json")? {
            None => Some(Members::default()),
            Some(bytes) => verus_sources(&bytes),
        },
    )
}

/// `links` returns the paths whose change needs the links check at `commit`. A commit that holds the check
/// without the registry returns the registry alone, so a push that removes the registry runs the check,
/// which refuses that tree; a commit with neither returns none. A registry that cannot be read returns
/// `None`, on which the check runs and reports the defect.
pub(super) fn links(environ: &Environ, commit: &Text) -> Result<Option<Members>, Failure> {
    let Some(bytes) = shown_file(environ, commit, LINKS_REGISTRY)? else {
        let check = ORDER[3]
            .held
            .expect("the links check names the script it asks for");
        return Ok(Some(if holds(environ, commit, check)? {
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
/// precedes, skipping the attributes between the two, so a string inside `should_panic` cannot stand in for
/// the fn name. A span with no fn after its attribute runs to the end of the text. A fn found after one
/// attribute is the next attribute's fn too while it starts before that attribute's end, and once no fn
/// follows an attribute none follows a later one, so each search runs once per fn.
pub fn ignored_tests(text: &str) -> Vec<&str> {
    let mut spans = Vec::new();
    // Each attribute `IGNORE` matches holds the word `ignore`, so a text without it has no span and skips
    // the search, whose Unicode word boundaries run slowly on text outside ASCII.
    if !text.contains("ignore") {
        return spans;
    }
    let mut function = None;
    let mut searched = false;
    for found in IGNORE.find_iter(text) {
        let stale =
            function.is_some_and(|function: regex::Match<'_>| function.start() < found.end());
        if !searched || stale {
            function = FUNCTION.find_at(text, found.end());
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
    environ: &Environ,
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
    let texts: Vec<String> = blob_bytes(environ, &names)?
        .into_iter()
        .map(|bytes| String::from_utf8_lossy(&bytes.unwrap_or_default()).into_owned())
        .collect();
    Ok(texts
        .chunks(2)
        .any(|pair| ignored_tests(&pair[0]) != ignored_tests(&pair[1])))
}
