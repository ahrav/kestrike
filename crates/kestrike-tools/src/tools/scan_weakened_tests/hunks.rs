//! A Rust or workflow budget is a line pattern, read from the zero-context diff of each changed path.

use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;

use regex::bytes::{Captures, NoExpand};

use crate::git::git_text;
use crate::json::Integer;
use crate::rust_text::code;

use super::Failure;
use super::digits::integer;
use super::patterns::{CONSTANT, CONSTANT_END, DIGITS, HUNK, NAMED_BOUND, Pattern, text_of};

const DIFF_BATCH: usize = 256;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hunk {
    pub removed: Vec<String>,
    pub added: Vec<(u64, String)>,
}

impl Hunk {
    fn is_empty(&self) -> bool {
        self.removed.is_empty() && self.added.is_empty()
    }
}

fn patch(base: &str, head: &str, paths: &[&str]) -> Result<String, Failure> {
    let mut args: Vec<OsString> = [
        "--no-literal-pathspecs",
        "-c",
        "core.quotePath=false",
        "diff",
        "--no-relative",
        "--no-renames",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--text",
        "--diff-algorithm=myers",
        "--indent-heuristic",
        "-U0",
        "--inter-hunk-context=0",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        base,
        head,
        "--",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    args.extend(
        paths
            .iter()
            .map(|path| OsString::from(format!(":(top,literal){path}"))),
    );
    Ok(git_text(&args)?)
}

pub fn hunks<'a>(lines: impl IntoIterator<Item = &'a str>) -> Result<Vec<Hunk>, Failure> {
    let mut found = Vec::new();
    let mut hunk = Hunk::default();
    let mut number: Option<u64> = None;
    for line in lines {
        if let Some(header) = HUNK.captures(line.as_bytes()).next() {
            if !hunk.is_empty() {
                found.push(std::mem::take(&mut hunk));
            }
            let start = text_of(header.get(1).expect("the hunk pattern captures its start"));
            number = Some(integer(start)?.to_string().parse().map_err(|_| {
                Failure::Refused(format!("the hunk header {line} names a line past 2^64"))
            })?);
        } else if let Some(at) = number.as_mut() {
            if let Some(text) = line.strip_prefix('-') {
                hunk.removed.push(text.to_owned());
            } else if let Some(text) = line.strip_prefix('+') {
                hunk.added.push((*at, text.to_owned()));
                *at = at.saturating_add(1);
            }
        }
    }
    if !hunk.is_empty() {
        found.push(hunk);
    }
    Ok(found)
}

/// `path_hunks` reads up to `DIFF_BATCH` paths in one diff. It assigns the diff's sections to the paths in
/// order when the `diff --git` headers equal the expected headers of `paths`; otherwise it reads each path of
/// the batch in a diff of its own.
pub fn path_hunks(
    base: &str,
    head: &str,
    paths: &[&str],
) -> Result<HashMap<String, Vec<Hunk>>, Failure> {
    let mut found = HashMap::new();
    for batch in paths.chunks(DIFF_BATCH) {
        let text = patch(base, head, batch)?;
        let mut headers = Vec::new();
        let mut sections: Vec<Vec<&str>> = Vec::new();
        for line in text.split('\n') {
            if line.starts_with("diff --git ") {
                headers.push(line);
                sections.push(Vec::new());
            } else if let Some(section) = sections.last_mut() {
                section.push(line);
            }
        }
        let expected = batch
            .iter()
            .map(|path| format!("diff --git a/{path} b/{path}"));
        if headers.iter().copied().eq(expected) {
            for (path, lines) in batch.iter().zip(sections) {
                found.insert((*path).to_owned(), hunks(lines)?);
            }
        } else {
            for path in batch {
                let text = patch(base, head, &[path])?;
                found.insert((*path).to_owned(), hunks(text.split('\n'))?);
            }
        }
    }
    Ok(found)
}

/// `keyed` yields each match of `pattern` in `text` with its pairing key: the text through the match, each run
/// of digits and underscores replaced by `#`.
pub fn keyed<'h>(
    pattern: &'h Pattern,
    text: &'h str,
) -> impl Iterator<Item = (String, Captures<'h>)> + 'h {
    pattern.captures(text.as_bytes()).map(move |found| {
        let end = found.get(0).expect("group 0 is the match").end();
        let key = DIGITS
            .regex()
            .replace_all(&text.as_bytes()[..end], NoExpand(b"#"));
        (String::from_utf8_lossy(&key).into_owned(), found)
    })
}

/// The pairs of old and new items, and the old items left unpaired with their keys.
pub type Paired<K, T> = (Vec<(T, T)>, Vec<(K, T)>);

/// `paired` pairs each new item with the earliest unpaired old item of its key, in order. It returns the
/// pairs and the old items left unpaired, grouped by key in the order each key first appears.
pub fn paired<K: Eq + std::hash::Hash + Clone, T>(
    old: impl IntoIterator<Item = (K, T)>,
    new: impl IntoIterator<Item = (K, T)>,
) -> Paired<K, T> {
    let mut order: Vec<K> = Vec::new();
    let mut queues: HashMap<K, VecDeque<T>> = HashMap::new();
    for (key, item) in old {
        queues
            .entry(key.clone())
            .or_insert_with(|| {
                order.push(key);
                VecDeque::new()
            })
            .push_back(item);
    }
    let mut pairs = Vec::new();
    for (key, item) in new {
        if let Some(earlier) = queues.get_mut(&key).and_then(VecDeque::pop_front) {
            pairs.push((earlier, item));
        }
    }
    let mut unpaired = Vec::new();
    for key in order {
        let queue = queues.remove(&key).expect("each ordered key has a queue");
        unpaired.extend(queue.into_iter().map(|item| (key.clone(), item)));
    }
    (pairs, unpaired)
}

fn value_of<'h>(found: &Captures<'h>) -> &'h str {
    text_of(
        found
            .name("value")
            .expect("a budget pattern captures its value"),
    )
}

/// `line_changes` returns `(name, old, new)` for each added budget match paired with a removed match of the
/// same pattern and key within a hunk. `name` includes the added line number.
pub fn line_changes(
    changes: &[Hunk],
    patterns: &[&Pattern],
) -> Result<Vec<(String, Integer, Integer)>, Failure> {
    let mut found = Vec::new();
    for hunk in changes {
        for &pattern in patterns {
            let old = hunk
                .removed
                .iter()
                .flat_map(|text| keyed(pattern, text).map(|(key, found)| (key, (0, found))));
            let new = hunk.added.iter().flat_map(|(number, text)| {
                keyed(pattern, text).map(move |(key, found)| (key, (*number, found)))
            });
            let (pairs, _) = paired(old, new);
            for ((_, before), (number, after)) in pairs {
                let name = text_of(
                    after
                        .name("name")
                        .expect("a budget pattern captures its name"),
                );
                let name = format!("{name} at line {number}");
                let old = integer(value_of(&before))?;
                found.push((name, old, integer(value_of(&after))?));
            }
        }
    }
    Ok(found)
}

fn constants(text: &str) -> HashMap<String, String> {
    let view = code(text);
    let haystack = view.as_bytes();
    let mut values: HashMap<String, Vec<Option<String>>> = HashMap::new();
    let mut at = 0;
    while let Some(found) = CONSTANT.captures_at(haystack, at) {
        let whole = found.get(0).expect("group 0 is the match");
        let name = text_of(found.name("name").expect("the pattern captures a name"));
        let mut value = None;
        at = whole.end();
        if let Some(typed) = found.name("typed") {
            let literal = found
                .name("value")
                .expect("a typed constant captures its value");
            if CONSTANT_END.is_match(&haystack[literal.end()..]) {
                value = Some(text_of(literal).to_owned());
            } else {
                at = typed.start();
            }
        }
        let seen = values.entry(name.to_owned()).or_default();
        if !seen.contains(&value) {
            seen.push(value);
        }
    }
    values
        .into_iter()
        .filter_map(|(name, seen)| match seen.as_slice() {
            [Some(value)] => Some((name, value.clone())),
            _ => None,
        })
        .collect()
}

fn valued(text: &str, values: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for found in NAMED_BOUND.captures(text.as_bytes()) {
        let whole = found.get(0).expect("group 0 is the match");
        let name = text_of(found.name("name").expect("the pattern captures a name"));
        out.push_str(&text[at..whole.start()]);
        out.push_str(text_of(
            found.name("site").expect("the pattern captures a site"),
        ));
        out.push_str(values.get(name).map_or(name, String::as_str));
        at = whole.end();
    }
    out.push_str(&text[at..]);
    out
}

/// `named_bounds` substitutes the constant's literal in `preemption_bound = Some(NAME)` when the lookup
/// succeeds and preserves `NAME` otherwise: a removed line looks up the constants of `old`, an added line
/// those of `new`.
pub fn named_bounds(changes: Vec<Hunk>, old: &str, new: &str) -> Vec<Hunk> {
    let named = changes.iter().any(|hunk| {
        let added = hunk.added.iter().map(|(_, text)| text);
        hunk.removed
            .iter()
            .chain(added)
            .any(|text| NAMED_BOUND.is_match(text.as_bytes()))
    });
    if !named {
        return changes;
    }
    let (before, after) = (constants(old), constants(new));
    changes
        .into_iter()
        .map(|hunk| Hunk {
            removed: hunk
                .removed
                .iter()
                .map(|text| valued(text, &before))
                .collect(),
            added: hunk
                .added
                .iter()
                .map(|(number, text)| (*number, valued(text, &after)))
                .collect(),
        })
        .collect()
}
