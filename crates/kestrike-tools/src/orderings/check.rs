//! The checker validates the ordering catalog, `verification/orderings/expected.json`, against its
//! scoped files.
//!
//! A row's `find` must occur exactly once in its file's production text and hold exactly one site, of
//! the row's `op`. Applying one weakening step to that site in `find` must yield `replace`; a
//! fence row deletes the call with a `;` directly after it. Each site takes one row per step. When the
//! checker skips a listed file, its rows stay unmatched and the refusal names the file.
//!
//! The steps: `SeqCst` goes to `Acquire` for a `load`, `Release` for a `store` and `AcqRel` for an
//! `rmw`; an `AcqRel` `rmw` goes to `Acquire` and to `Release`; a `Release` `store` or `rmw` and an
//! `Acquire` `load` or `rmw` go to `Relaxed`.
//!
//! The checker counts non-overlapping occurrences of `find` and matches the row at the first one. It
//! reads `find` against the production text with one space per code point of a blanked test-only
//! element.
//!
//! A matched row without a binding names its enclosing item in `scope`; a bound row's enclosing item is
//! its binding's production scope. Either must resolve to one body that holds the `find`, with the site
//! outside every `fn` or `impl` nested in it. A bound row whose binding's production scope is an empty
//! list passes the enclosing-item check. Every accepted row, matched or not, holds exactly one
//! well-formed disposition, names a run unless it is one of [`UNMODELED`], records a 40-digit lowercase
//! hex revision when it is decided, and names only positive tests of its lanes, whose model sources or
//! kernel files hold its failures. Its binding and twins must be ones the declarations hold. A value
//! these checks read that has another shape makes the row malformed, and the checks of that row stop
//! there.
//!
//! The report is a JSON object of six members in this order: `refusals`, each `refusal` and
//! `message` in the order refused; `rows`, the id of each row that `row_defect` accepts with its one
//! disposition's name, or null for none or several, in catalog order; `unrun`, the ids of the unrun
//! rows in code point order; `sites`, the count of sites in the files read; `excluded`, the files
//! the kernel package includes that every chain of declarations loads through a test-only item, in
//! code point order; and `credited`. `credited` is true exactly when both `refusals` and `unrun` are
//! empty. The exit code is 0 for an empty `refusals` list and 1 for a nonempty one. The refusals
//! follow the check's passes in order: the include defects, the scope rule, the listed and included
//! files, each read file's spellings and loaders, the rows in catalog order, then each file's sites.
//!
//! An unreadable or misshapen catalog, declaration, litmus list or obligation record, and a kernel
//! package that cannot be walked or resolved, give exit 2 and a report of one member, `error`. An
//! unreadable listed file or model source is a refusal.
//!
//! The word class at the edges of `include`, `mod`, `fn` and `impl` uses the `regex` crate's Unicode
//! tables, which can assign letters and numbers that the Python interpreter's Unicode tables leave
//! unassigned.
//!
//! Offsets are byte offsets of a scoped file's text, which its production and scanned texts share.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use super::sites::{self, Kind, Op, Pin, Strength, body_open, line_of};
use super::sources::{
    INCLUDE, PackageWalk, Reader, References, c_literals, diagnostics, include_defects,
    mod_keywords, module_source, path_attributes, references, scope_files, stem,
};
use crate::classes::{bounded_iter, compiled};
use crate::genmc::{self, normalized};
use crate::json::{Integer, Object, Text, UniqueError, Value, parse_unique};
use crate::production_text::closing;
use crate::python::{repr, str_of};
use crate::text::{text, words};

/// The check reads `CATALOG`, `GENMC`, `RC11` and `OBLIGATIONS` in that order.
pub const CATALOG: &str = "verification/orderings/expected.json";
/// The GenMC declaration, which holds the bindings, the positive cases and the kernel package.
pub const GENMC: &str = "verification/genmc/expected.json";
/// The litmus list, which names the `rc11` twins.
pub const RC11: &str = "verification/rc11/expected.json";
/// The obligation records, which name the positive loom tests and their controls.
pub const OBLIGATIONS: &str = "verification/obligations.json";

/// Only rows listed in `UNMODELED` may have an empty run list.
pub const UNMODELED: [&str; 4] = [
    "word-install",
    "fill-depart-held",
    "sequence-begin-store",
    "sequence-commit",
];

const OPS: [&str; 4] = ["load", "store", "rmw", "fence"];

const REQUIRED: [&str; 5] = ["id", "path", "op", "find", "replace"];

const ROW_KEYS: [&str; 12] = [
    "id", "path", "find", "replace", "op", "binding", "scope", "twin", "revision", "kill",
    "survives", "unrun",
];

/// `steps` returns the permitted one-step weakenings in code point order.
fn steps(strength: Strength, op: Op) -> &'static [&'static str] {
    match (strength, op) {
        (Strength::SeqCst, Op::Load) => &["Acquire"],
        (Strength::SeqCst, Op::Store) => &["Release"],
        (Strength::SeqCst, Op::Rmw) => &["AcqRel"],
        (Strength::AcqRel, Op::Rmw) => &["Acquire", "Release"],
        (Strength::Release, Op::Store | Op::Rmw) | (Strength::Acquire, Op::Load | Op::Rmw) => {
            &["Relaxed"]
        }
        _ => &[],
    }
}

#[derive(Default)]
struct Refusals(Vec<Value>);

impl Refusals {
    fn refuse(&mut self, name: &'static str, message: Text) {
        let mut entry = Object::new();
        entry.insert("refusal", Value::String(Text::from(name)));
        entry.insert("message", Value::String(message));
        self.0.push(Value::Object(entry));
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A well-formed row: its object and the five fields every row holds as strings.
struct Row<'v> {
    object: &'v Object,
    id: &'v Text,
    path: &'v Text,
    op: &'v Text,
    find: &'v Text,
    replace: &'v Text,
}

/// A scoped file the check read: its repository path, its site reading, its production text as
/// [`normalized`] reads it and, for each of its sites, the steps of the rows matched to it.
struct Scoped {
    path: String,
    reading: sites::Reading,
    matched: Matched,
    normal: String,
    targets: Vec<Vec<&'static str>>,
}

/// The text a row's `find` is matched in: a scoped file's production text with one space for each code
/// point a test-only element blanks, and for each byte offset of the production text at a code point's
/// start, or at its end, the offset in `text`.
struct Matched {
    text: String,
    offsets: Vec<usize>,
}

impl Matched {
    fn new(source: &str, production: &str) -> Self {
        let (raw, blanked) = (source.as_bytes(), production.as_bytes());
        let mut text = String::with_capacity(production.len());
        let mut offsets = vec![0; production.len() + 1];
        for (at, code) in source.char_indices() {
            offsets[at] = text.len();
            let end = at + code.len_utf8();
            text.push(if raw[at..end] == blanked[at..end] {
                code
            } else {
                ' '
            });
        }
        offsets[production.len()] = text.len();
        Self { text, offsets }
    }
}

fn strings<'t>(names: impl IntoIterator<Item = &'t str>) -> Value {
    Value::Array(
        names
            .into_iter()
            .map(|name| Value::String(Text::from(name)))
            .collect(),
    )
}

/// Whether `value` is a list of strings.
fn all_strings(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Array(items))
        if items.iter().all(|item| matches!(item, Value::String(_))))
}

/// `row` as a [`Row`], or the defect that makes it malformed.
fn row_defect<'v>(row: &'v Value, ids: &BTreeSet<Text>, files: &[Text]) -> Result<Row<'v>, Text> {
    let Value::Object(object) = row else {
        return Err(Text::from("it is no object"));
    };
    let missing: Vec<&str> = REQUIRED
        .into_iter()
        .filter(|key| object.get(key).is_none())
        .collect();
    if !missing.is_empty() {
        return Err(text!("it lacks ", repr(&strings(missing))));
    }
    let unknown: BTreeSet<&Text> = object
        .iter()
        .map(|(key, _)| key)
        .filter(|key| !ROW_KEYS.iter().any(|known| *key == known))
        .collect();
    if !unknown.is_empty() {
        let listed = Value::Array(unknown.into_iter().cloned().map(Value::String).collect());
        return Err(text!("it holds the unknown keys ", repr(&listed)));
    }
    let string = |key: &str| match object.get(key) {
        Some(Value::String(text)) => Some(text),
        _ => None,
    };
    let binding = object
        .get("binding")
        .is_none_or(|binding| matches!(binding, Value::String(_)));
    let scope = object
        .get("scope")
        .is_none_or(|scope| all_strings(Some(scope)));
    let wrong = || Text::from("a field has the wrong type");
    if !binding || !scope {
        return Err(wrong());
    }
    let (Some(id), Some(path), Some(op), Some(find), Some(replace)) = (
        string("id"),
        string("path"),
        string("op"),
        string("find"),
        string("replace"),
    ) else {
        return Err(wrong());
    };
    if id.strip().is_empty() {
        return Err(Text::from("its id is blank"));
    }
    if ids.contains(id) {
        return Err(Text::from("its id is repeated"));
    }
    if !files.contains(path) {
        return Err(Text::from("it names an unlisted path"));
    }
    if !OPS.iter().any(|known| op == known) {
        return Err(text!(
            "its op ",
            op.repr(),
            " is none of ",
            repr(&strings(OPS))
        ));
    }
    if object.get("binding").is_some() && object.get("scope").is_some() {
        return Err(Text::from("it holds both a binding and a scope"));
    }
    Ok(Row {
        object,
        id,
        path,
        op,
        find,
        replace,
    })
}

/// Records `row` against the one site its `find` holds in `scoped` and returns the site's offset in the
/// `find`, or refuses the row.
fn match_row(row: &Row<'_>, scoped: &mut Scoped, refusals: &mut Refusals) -> Option<usize> {
    let name = row.id;
    let Matched { text, offsets } = &scoped.matched;
    let find = row.find.to_str();
    let count = find.map_or(0, |find| text.matches(find).count());
    let Some(find) = find.filter(|_| count == 1) else {
        refusals.refuse(
            "find",
            text!(name, ": its find occurs ", count, " times in ", row.path),
        );
        return None;
    };
    let start = text
        .find(find)
        .expect("a find that occurs once has a first offset");
    let held: Vec<usize> = (0..scoped.reading.sites().len())
        .filter(|&index| {
            let site = scoped.reading.sites()[index];
            start <= offsets[site.start()] && offsets[site.end()] <= start + find.len()
        })
        .collect();
    let [index] = held[..] else {
        refusals.refuse(
            "find",
            text!(name, ": its find holds ", held.len(), " sites"),
        );
        return None;
    };
    let site = scoped.reading.sites()[index];
    let (low, high) = (offsets[site.start()] - start, offsets[site.end()] - start);
    let (before, after) = (&find[..low], &find[high..]);
    let op = site.op_name();
    if op == "unread" {
        refusals.refuse(
            "step",
            text!(name, ": the matcher reads no op for its site"),
        );
        return None;
    }
    if *row.op != op {
        refusals.refuse(
            "step",
            text!(name, ": its site is a ", op, ", the row says ", row.op),
        );
        return None;
    }
    let target = match site.kind() {
        Kind::Fence { .. } => {
            (*row.replace == format!("{before}{after}").as_str()).then_some("delete")
        }
        Kind::Ordering { strength, op } => steps(strength, op)
            .iter()
            .copied()
            .find(|step| *row.replace == format!("{before}Ordering::{step}{after}").as_str()),
    };
    let Some(target) = target else {
        refusals.refuse(
            "step",
            text!(
                name,
                ": its replace is not its find after one ",
                row.op,
                " step"
            ),
        );
        return None;
    };
    scoped.targets[index].push(target);
    Some(low)
}

/// The `(start, end)` of each place in `code`, a scoped file's production text with comments and literals
/// blanked, that can load source: the word `include`, the keyword `mod` after no `#`, and each path
/// attribute as [`path_attributes`] finds it, in order. A word inside a path attribute belongs to it.
fn loaders(code: &str) -> Vec<(usize, usize)> {
    let attributes = path_attributes(code);
    let includes = bounded_iter(&INCLUDE, code).map(|found| {
        let word = found.get_match();
        (word.start(), word.end())
    });
    let mods = mod_keywords(code).map(|offset| (offset, offset + "mod".len()));
    let words: Vec<(usize, usize)> = includes
        .chain(mods)
        .filter(|&(offset, _)| {
            !attributes
                .iter()
                .any(|&(start, end)| start < offset && offset < end)
        })
        .collect();
    let mut found = attributes;
    found.extend(words);
    found.sort_unstable();
    found
}

/// What makes an accepted row's checks stop short: the reason a value they read has another shape.
struct Malformed(&'static str);

/// The production entry of the binding `id` among `references`, `None` when the declaration binds no
/// such id or the entry holds no `production`, or the defect of a `production` that is no object.
fn production<'r>(references: &'r References, id: &Text) -> Result<Option<&'r Object>, Malformed> {
    let Some(entry) = references.binding(id) else {
        return Ok(None);
    };
    let Value::Object(entry) = entry else {
        unreachable!("the references keep each binding entry as an object");
    };
    match entry.get("production") {
        None => Ok(None),
        Some(Value::Object(production)) => Ok(Some(production)),
        Some(_) => Err(Malformed("its binding's production is no object")),
    }
}

/// `entry` when it is an object that names a model lane (`loom` or `genmc`) and a nonempty list of
/// tests, all strings, and, when `failure`, a nonblank `failure` string.
fn entry_fields(entry: &Value, failure: bool) -> Option<&Object> {
    let Value::Object(entry) = entry else {
        return None;
    };
    let lane = matches!(entry.get("lane"), Some(Value::String(lane)) if *lane == "loom" || *lane == "genmc");
    let tests = matches!(entry.get("tests"), Some(Value::Array(tests))
        if !tests.is_empty() && tests.iter().all(|test| matches!(test, Value::String(_))));
    let failed = !failure || nonblank(entry.get("failure"));
    (lane && tests && failed).then_some(entry)
}

fn nonblank(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::String(text)) if !text.strip().is_empty())
}

/// The entries of a well-formed disposition `value` of `kind`, or `None`: a `survives` object with a
/// nonblank `reason` and a `passed` list of entries without a failure; a `kill` list, or an `unrun`
/// object's `needs` list, of entries with a failure, an empty one only beside a nonblank `reason`, and a
/// `kill` naming each lane once.
fn disposition_entries<'v>(kind: &str, value: &'v Value) -> Option<Vec<&'v Object>> {
    if kind == "survives" {
        let Value::Object(value) = value else {
            return None;
        };
        let Some(Value::Array(passed)) = value.get("passed") else {
            return None;
        };
        if !nonblank(value.get("reason")) {
            return None;
        }
        return passed
            .iter()
            .map(|entry| entry_fields(entry, false))
            .collect();
    }
    let (entries, reason) = match value {
        _ if kind == "kill" => (Some(value), None),
        Value::Object(value) => (value.get("needs"), value.get("reason")),
        _ => return None,
    };
    let Some(Value::Array(entries)) = entries else {
        return None;
    };
    let entries: Vec<&Object> = entries
        .iter()
        .map(|entry| entry_fields(entry, true))
        .collect::<Option<_>>()?;
    if entries.is_empty() && !nonblank(reason) {
        return None;
    }
    let lanes: BTreeSet<&Text> = entries
        .iter()
        .filter_map(|entry| match entry.get("lane") {
            Some(Value::String(lane)) => Some(lane),
            _ => None,
        })
        .collect();
    if kind == "kill" && lanes.len() != entries.len() {
        return None;
    }
    Some(entries)
}

/// The result a run of each entry must give, by disposition: `killed` for `kill`, `survived` for
/// `survives`, and none for `unrun`.
pub const WANTED: [(&str, Option<&str>); 3] = [
    ("kill", Some("killed")),
    ("survives", Some("survived")),
    ("unrun", None),
];

/// The lane entries a run of `row`, a row the check accepts, executes, with the result each must give,
/// or `None` when no result is decided.
///
/// # Errors
///
/// `row_entries` refuses a row that holds no disposition, and one whose first disposition, in the
/// order `kill`, `survives`, `unrun`, is malformed.
pub fn row_entries(row: &Object) -> Result<(Vec<&Object>, Option<&'static str>), Text> {
    let id = row.get("id").map(str_of).unwrap_or_default();
    let Some((kind, wanted)) = WANTED.into_iter().find(|(kind, _)| row.get(kind).is_some()) else {
        return Err(text!(id, ": it holds no disposition"));
    };
    let value = row.get(kind).expect("the disposition is held");
    disposition_entries(kind, value)
        .map(|entries| (entries, wanted))
        .ok_or_else(|| text!(id, ": its ", kind, " disposition is malformed"))
}

/// The package-relative path and the text of the one kernel file of `case`'s family among `kernels`, the
/// source named `<family>_kernel.rs`, the family being the leading lowercase ASCII letters of the case name:
/// `src/join_kernel.rs` for `join-production`. `None` when the package holds none or several.
pub fn family_kernel<'k>(
    case: &Text,
    kernels: &'k BTreeMap<String, String>,
) -> Option<(&'k str, &'k str)> {
    let family: String = case
        .code_points()
        .map_while(char::from_u32)
        .take_while(char::is_ascii_lowercase)
        .collect();
    let wanted = format!("{family}_kernel");
    let mut found = kernels.iter().filter(|(path, _)| stem(path) == wanted);
    match (found.next(), found.next()) {
        (Some((path, text)), None) => Some((path, text)),
        _ => None,
    }
}

/// Whether `failure` is one of `messages`, a model source's message literals, the text of one before its
/// first `{` with trailing spaces and colons cut, or the text after one of that head's `: ` separators.
fn is_loom_failure(failure: &str, messages: &[String]) -> bool {
    messages.iter().any(|content| {
        let head = content
            .split('{')
            .next()
            .unwrap_or_default()
            .trim_end_matches([' ', ':']);
        let parts: Vec<&str> = head.split(": ").collect();
        failure == content
            || failure == head
            || (1..parts.len()).any(|index| failure == parts[index..].join(": "))
    })
}

fn is_revision(revision: &Text) -> bool {
    revision.code_points().count() == 40
        && revision
            .code_points()
            .all(|code| matches!(code, 0x30..=0x39 | 0x61..=0x66))
}

/// Refuses the disposition of `row`, which holds the disposition keys `held`: a count other than one, a
/// malformed one, no run outside [`UNMODELED`], a decided one without its revision, and each entry
/// whose tests or failure the references and model sources do not hold.
fn check_disposition(
    row: &Row<'_>,
    held: &[&'static str],
    refusals: &mut Refusals,
    references: &References,
    read: Reader<'_>,
) {
    let name = row.id;
    let &[kind] = held else {
        refusals.refuse(
            "disposition",
            text!(
                name,
                ": it holds ",
                held.len(),
                " dispositions ",
                repr(&strings(held.iter().copied()))
            ),
        );
        return;
    };
    let value = row.object.get(kind).expect("the row holds its disposition");
    let Some(entries) = disposition_entries(kind, value) else {
        refusals.refuse(
            "disposition",
            text!(
                name,
                ": its ",
                kind,
                " disposition lacks a field, holds an empty one or has the wrong shape"
            ),
        );
        return;
    };
    if entries.is_empty() && !UNMODELED.iter().any(|id| name == id) {
        refusals.refuse(
            "disposition",
            text!(
                name,
                ": its ",
                kind,
                " disposition names no run, and the row is outside ",
                repr(&strings(UNMODELED))
            ),
        );
    }
    let revision = row.object.get("revision");
    if kind != "unrun"
        && !matches!(revision, Some(Value::String(revision)) if is_revision(revision))
    {
        refusals.refuse(
            "revision",
            text!(name, ": its ", kind, " disposition records no revision"),
        );
    }
    for entry in entries {
        let Some(Value::String(lane)) = entry.get("lane") else {
            unreachable!("a well-formed entry names its lane");
        };
        let lane = lane.to_str().expect("a well-formed lane is loom or genmc");
        let Some(Value::Array(listed)) = entry.get("tests") else {
            unreachable!("a well-formed entry lists its tests");
        };
        let mut tests = Vec::new();
        for test in listed {
            let Value::String(test) = test else {
                unreachable!("a well-formed entry's tests are strings");
            };
            if references
                .positive(lane)
                .is_some_and(|positive| positive.contains(test))
            {
                tests.push(test);
            } else {
                refusals.refuse(
                    "reference",
                    text!(name, ": ", test, " is no positive ", lane, " test"),
                );
            }
        }
        if kind == "survives" {
            continue;
        }
        check_failure(row, entry, lane, &tests, refusals, references, read);
    }
}

/// Refuses each of `tests`, the positive tests of a `kill` or `unrun` entry of `row` in `lane`, whose
/// model source or kernel file cannot be found, and an entry `failure` that those sources do not hold:
/// for `loom` as a message literal of each, or held by more than one of a source's literals, for `genmc`
/// as one `check!` message of each.
fn check_failure(
    row: &Row<'_>,
    entry: &Object,
    lane: &str,
    tests: &[&Text],
    refusals: &mut Refusals,
    references: &References,
    read: Reader<'_>,
) {
    let name = row.id;
    let mut sources: Vec<String> = Vec::new();
    for test in tests {
        let source = if lane == "loom" {
            lookup_name(test).and_then(|test| module_source(&test, read))
        } else {
            family_kernel(test, references.kernels()).map(|(_, text)| text.to_owned())
        };
        match source {
            None if lane == "loom" => refusals.refuse(
                "reference",
                text!(name, ": no model source of ", *test, " can be read"),
            ),
            None => refusals.refuse(
                "reference",
                text!(name, ": ", *test, " has no kernel file of its family"),
            ),
            Some(text) if !sources.contains(&text) => sources.push(text),
            Some(_) => {}
        }
    }
    let Some(Value::String(failure)) = entry.get("failure") else {
        unreachable!("a well-formed entry with a failure names it");
    };
    let wanted = failure.to_str();
    if lane == "loom" {
        let messages: Vec<Vec<String>> = sources.iter().map(|text| diagnostics(text)).collect();
        if !messages
            .iter()
            .all(|held| wanted.is_some_and(|wanted| is_loom_failure(wanted, held)))
        {
            refusals.refuse(
                "reference",
                text!(
                    name,
                    ": the failure ",
                    failure.repr(),
                    " is no message literal of a model source of its tests"
                ),
            );
        } else if messages.iter().any(|held| {
            held.iter()
                .filter(|content| wanted.is_some_and(|wanted| content.contains(wanted)))
                .count()
                > 1
        }) {
            refusals.refuse(
                "reference",
                text!(
                    name,
                    ": the failure ",
                    failure.repr(),
                    " lies in more than one message literal of a model source of its tests, so a \
                     panic holding it names no one assertion"
                ),
            );
        }
    } else if !sources.iter().all(|text| {
        c_literals(text)
            .iter()
            .filter(|literal| wanted == Some(literal.as_str()))
            .count()
            == 1
    }) {
        refusals.refuse(
            "reference",
            text!(
                name,
                ": the failure ",
                failure.repr(),
                " is no one check! message of its cases' kernel file"
            ),
        );
    }
}

/// Refuses the references of `row`: a binding that binds no operation in the row's file, holds no call
/// or scope, or binds a call the row's `find` lacks, as [`normalized`] reads both; and a twin list that
/// is no list of lane entries, names no lane, names a lane twice, or holds an entry whose `test` is no
/// twin of its lane or whose `steps` is no positive integer.
fn check_references(
    row: &Row<'_>,
    refusals: &mut Refusals,
    references: &References,
) -> Result<(), Malformed> {
    let name = row.id;
    if let Some(Value::String(binding)) = row.object.get("binding") {
        let production = production(references, binding)?;
        let field = |key: &str| production.and_then(|production| production.get(key));
        let (call, scope) = (field("call"), field("scope"));
        let bound = matches!(field("file"), Some(Value::String(file)) if file == row.path);
        let headers = all_strings(scope);
        if !bound {
            refusals.refuse(
                "reference",
                text!(
                    name,
                    ": binding ",
                    binding.repr(),
                    " binds no operation in ",
                    row.path
                ),
            );
        } else if !(nonblank(call) && headers) {
            refusals.refuse(
                "reference",
                text!(
                    name,
                    ": binding ",
                    binding.repr(),
                    " holds no call or scope"
                ),
            );
        } else if let Some(Value::String(call)) = call {
            let held = normal_forms(row.find)
                .iter()
                .zip(normal_forms(call))
                .all(|(find, call)| find.contains(&call));
            if !held {
                refusals.refuse(
                    "reference",
                    text!(
                        name,
                        ": binding ",
                        binding.repr(),
                        " binds ",
                        call.repr(),
                        ", which its find lacks"
                    ),
                );
            }
        }
    }
    let entries: Option<Vec<&Object>> = match row.object.get("twin") {
        None => Some(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Object(entry) => Some(entry),
                _ => None,
            })
            .collect(),
        Some(_) => None,
    };
    let Some(entries) = entries else {
        refusals.refuse(
            "reference",
            text!(name, ": its twin is no list of lane entries"),
        );
        return Ok(());
    };
    let lanes: Option<Vec<&Text>> = entries
        .iter()
        .map(|entry| match entry.get("lane") {
            Some(Value::String(lane)) => Some(lane),
            _ => None,
        })
        .collect();
    let Some(lanes) = lanes else {
        refusals.refuse("reference", text!(name, ": a twin names no lane"));
        return Ok(());
    };
    if lanes.iter().collect::<BTreeSet<_>>().len() != lanes.len() {
        refusals.refuse("reference", text!(name, ": its twins name a lane twice"));
    }
    let one = Integer::from(1_usize);
    for (entry, lane) in entries.into_iter().zip(lanes) {
        let twins = lane.to_str().and_then(|lane| references.twins(lane));
        let test = matches!(entry.get("test"), Some(Value::String(test))
            if twins.is_some_and(|twins| twins.contains(test)));
        let steps = matches!(entry.get("steps"), Some(Value::Integer(steps)) if *steps >= one);
        if !(test && steps) {
            refusals.refuse(
                "reference",
                text!(
                    name,
                    ": twin ",
                    repr(&Value::Object(entry.clone())),
                    " is no ",
                    lane,
                    " twin with its steps"
                ),
            );
        }
    }
    Ok(())
}

static ITEM: LazyLock<Regex> = LazyLock::new(|| compiled("fn|impl"));

/// Whether `position` of `body` lies in the body of an `fn` or `impl` nested in it.
fn nested(body: &str, position: usize) -> bool {
    bounded_iter(&ITEM, body).any(|item| {
        body_open(body, item.get_match().end()).is_some_and(|brace| {
            brace < position && position < closing(body, brace).unwrap_or(body.len())
        })
    })
}

/// Refuses `row` unless `scope`, its enclosing item's headers, resolves in `normal`, its file's
/// [`normalized`] production text, to one body that holds its `find`, with its site, `offset` bytes into
/// the find, outside every `fn` or `impl` nested in that body.
fn check_enclosing(
    row: &Row<'_>,
    refusals: &mut Refusals,
    normal: &str,
    scope: Option<&Value>,
    offset: usize,
) -> Result<(), Malformed> {
    let name = row.id;
    let headers = match scope {
        Some(Value::Array(headers)) if !headers.is_empty() => headers,
        _ => {
            refusals.refuse(
                "enclosing item",
                text!(name, ": it names no enclosing item"),
            );
            return Ok(());
        }
    };
    let Some(headers) = headers
        .iter()
        .map(|header| match header {
            Value::String(header) => Some(header),
            _ => None,
        })
        .collect::<Option<Vec<&Text>>>()
    else {
        return Err(Malformed("a header of its binding's scope is no string"));
    };
    let mut bodies = vec![normal.to_owned()];
    for header in &headers {
        if bodies.is_empty() {
            break;
        }
        let [header, other] = normal_forms(header);
        bodies = if header == other {
            bodies
                .iter()
                .flat_map(|text| genmc::bodies(text, &header))
                .collect()
        } else {
            Vec::new()
        };
    }
    let find = row.find.to_str().unwrap_or_default();
    let start = match &bodies[..] {
        [body] => body.find(&normalized(find)),
        _ => None,
    };
    let joined = Text::join(" > ", headers);
    match start {
        None => refusals.refuse(
            "enclosing item",
            text!(
                name,
                ": ",
                joined,
                " resolves to ",
                bodies.len(),
                " bodies, or its body lacks the find"
            ),
        ),
        Some(start) => {
            if nested(&bodies[0], start + normalized(&find[..offset]).len()) {
                refusals.refuse(
                    "enclosing item",
                    text!(name, ": its site lies in an item nested in ", joined),
                );
            }
        }
    }
    Ok(())
}

/// Checks the accepted `row`, whose disposition keys are `held`: its match against `file`, its scoped
/// file when the check read it, with its enclosing item, then its disposition and its references.
fn check_row(
    row: &Row<'_>,
    held: &[&'static str],
    file: Option<&mut Scoped>,
    refusals: &mut Refusals,
    references: &References,
    read: Reader<'_>,
) -> Result<(), Malformed> {
    if let Some(file) = file {
        let offset = match_row(row, file, refusals);
        let binding = match row.object.get("binding") {
            Some(Value::String(binding)) => Some(production(references, binding)?),
            _ => None,
        };
        let scope = match binding {
            Some(production) => production.and_then(|production| production.get("scope")),
            None => row.object.get("scope"),
        };
        let enclosed = binding.is_none()
            || matches!(scope, Some(Value::Array(headers)) if !headers.is_empty());
        if let Some(offset) = offset.filter(|_| enclosed) {
            check_enclosing(row, refusals, &file.normal, scope, offset)?;
        }
    }
    check_disposition(row, held, refusals, references, read);
    check_references(row, refusals, references)
}

/// The `repr` of each key of `runs`, a run of one key and its count standing for that many keys, joined
/// by `, `.
fn listed(runs: &[(Text, usize)]) -> String {
    let mut out = String::new();
    for (key, count) in runs {
        let shown = key.repr();
        for _ in 0..*count {
            if !out.is_empty() {
                out.push_str(", ");
            }
            out.push_str(&shown);
        }
    }
    out
}

/// `text` with each lone surrogate U+D800 + k written as the private use code point `plane` * 0x10000 + k,
/// for `plane` 15 or 16.
fn surrogates_in(text: &Text, plane: u32) -> String {
    text.code_points()
        .map(|code| match code {
            0xd800..=0xdfff => (plane << 16) + code - 0xd800,
            _ => code,
        })
        .map(|code| char::from_u32(code).expect("a code point of a text or a private use plane"))
        .collect()
}

/// The [`normalized`] form of `text` with its lone surrogates written in private use plane 15, then in
/// plane 16. A surrogate inside a comment or a literal leaves the two forms equal.
fn normal_forms(text: &Text) -> [String; 2] {
    [15, 16].map(|plane| normalized(&surrogates_in(text, plane)))
}

/// The name that finds loom test `test`'s model source: its modules, each `::` they end in, and an empty
/// test name, read up to the last `::` of a left-to-right split, or the empty name when it holds none.
fn lookup_name(test: &Text) -> Option<String> {
    let codes: Vec<u32> = test.code_points().collect();
    let (mut at, mut last) = (0, None);
    while at + 1 < codes.len() {
        if codes[at] == u32::from(b':') && codes[at + 1] == u32::from(b':') {
            last = Some(at);
            at += 2;
        } else {
            at += 1;
        }
    }
    let Some(last) = last else {
        return Some(String::new());
    };
    let modules = Text::from_code_points(codes[..last].iter().copied())?;
    modules.to_str().map(|modules| format!("{modules}::"))
}

fn failed(prefix: &str, reason: &str) -> (Value, u8) {
    let mut report = Object::new();
    report.insert("error", Value::String(text!(prefix, reason)));
    (Value::Object(report), 2)
}

/// The catalog's files and rows, the references of the three declarations, and the kernel package's
/// path under the checkout, `None` for a package name with no form as a path, which names no directory
/// to walk: such a package holds no sources and no kernel texts, and the scope rule still reads the
/// crate's path holders.
struct Inputs {
    files: Vec<Text>,
    rows: Vec<Value>,
    references: References,
    package: Option<PathBuf>,
}

/// The inputs `read` gives, or the reason one cannot be read or has another shape.
fn inputs(read: Reader<'_>, root: &Path) -> Result<Inputs, String> {
    let load = |path: &str| {
        let source = read(path).map_err(|error| format!("{path}: {error}"))?;
        parse_unique(&source).map_err(|error| match error {
            UniqueError::Repeated(_, keys) => {
                format!("an object repeats a key among [{}]", listed(&keys))
            }
            UniqueError::Syntax(error) => format!("{path}: {error}"),
        })
    };
    let catalog = load(CATALOG)?;
    let declared = load(GENMC)?;
    let litmus = load(RC11)?;
    let records = load(OBLIGATIONS)?;
    let Value::Object(catalog) = catalog else {
        return Err("the catalog is no object".to_owned());
    };
    let member = |key: &str| {
        catalog
            .get(key)
            .ok_or_else(|| format!("the catalog has no member {key}"))
    };
    let (files, rows) = (member("files")?, member("rows")?);
    let files = match files {
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(path) => Some(path.clone()),
                _ => None,
            })
            .collect::<Option<Vec<Text>>>(),
        _ => None,
    }
    .filter(|files| files.iter().collect::<BTreeSet<_>>().len() == files.len());
    let (Some(files), Value::Array(rows)) = (files, rows) else {
        return Err("files is no list of distinct paths, or rows is no list".to_owned());
    };
    let references =
        references(&declared, &litmus, &records, root).map_err(|error| error.to_string())?;
    let package = match declared {
        Value::Object(declared) => match declared.get("package") {
            Some(Value::String(package)) => package.to_os(),
            _ => None,
        },
        _ => None,
    };
    Ok(Inputs {
        files,
        rows: rows.clone(),
        references,
        package: package.map(|package| root.join(package)),
    })
}

/// The report and the exit code of the catalog check: the catalog, the declarations, the scoped
/// files, the crate's module files and path holders, and each loom test's model source come from
/// `read`, the kernel package is walked under the checkout `root`, and the crate sources that can
/// declare an included file are found under `tree`. `package_walk` lists the sources the scope rule
/// classifies; the kernel texts and the include defects are read on disk under `root`. A strength
/// constant with no `S::NAME` mention in its file takes its op from its pin in `pins`.
///
/// The check acts with the authority of its caller and trusts the directories it is given; it reads
/// each input whole.
pub fn check(
    read: Reader<'_>,
    root: &Path,
    tree: &Path,
    pins: &[Pin],
    package_walk: PackageWalk<'_>,
) -> (Value, u8) {
    let Inputs {
        files,
        rows,
        references,
        package,
    } = match inputs(read, root) {
        Ok(inputs) => inputs,
        Err(reason) => return failed("unreadable catalog or declaration: ", &reason),
    };
    let mut refusals = Refusals::default();
    let scope = match package {
        None => scope_files(root, root, read, tree, &|_: &Path| Ok(Vec::new())),
        Some(package) => include_defects(&package, references.kernels()).and_then(|defects| {
            for defect in defects {
                refusals.refuse(defect.name(), Text::from(defect.message()));
            }
            scope_files(&package, root, read, tree, package_walk)
        }),
    };
    let scope = match scope {
        Ok(scope) => scope,
        Err(error) => return failed("unreadable kernel package: ", &error.to_string()),
    };
    for refusal in scope.refusals() {
        refusals.refuse(refusal.name(), Text::from(refusal.message()));
    }
    let included: BTreeSet<&str> = scope.included().iter().map(String::as_str).collect();
    for path in &included {
        if !files.iter().any(|file| file == path) {
            refusals.refuse(
                "scope file",
                text!(
                    *path,
                    " is a production file the kernel package includes and files lacks"
                ),
            );
        }
    }
    for path in files.iter().collect::<BTreeSet<_>>() {
        if !path.to_str().is_some_and(|path| included.contains(path)) {
            refusals.refuse(
                "scope file",
                text!(
                    path,
                    " is listed and the kernel package includes no production file there"
                ),
            );
        }
    }

    let mut scoped = Vec::new();
    for path in files.iter().filter_map(Text::to_str) {
        if !included.contains(path) {
            continue;
        }
        let Ok(text) = read(path) else {
            refusals.refuse("scope file", text!(path, " cannot be read"));
            continue;
        };
        let reading = sites::read(path, &text, pins);
        for defect in reading.defects() {
            refusals.refuse("spelling", Text::from(defect.as_str()));
        }
        let code = reading.scanned();
        for (start, end) in loaders(code) {
            let loader = words(&code[start..end]).collect::<Vec<_>>().join(" ");
            refusals.refuse(
                "scope file",
                text!(
                    path,
                    ":",
                    line_of(&text, start),
                    ": ",
                    loader,
                    " can load source that the catalog does not scope"
                ),
            );
        }
        let targets = vec![Vec::new(); reading.sites().len()];
        let normal = normalized(reading.production());
        let matched = Matched::new(&text, reading.production());
        scoped.push(Scoped {
            path: path.to_owned(),
            reading,
            matched,
            normal,
            targets,
        });
    }

    let mut ids = BTreeSet::new();
    let mut dispositions = Object::new();
    for row in &rows {
        let row = match row_defect(row, &ids, &files) {
            Ok(row) => row,
            Err(defect) => {
                let id = match row {
                    Value::Object(object) => object.get("id").unwrap_or(&Value::Null),
                    _ => row,
                };
                refusals.refuse("row", text!("row ", repr(id), " is malformed: ", defect));
                continue;
            }
        };
        ids.insert(row.id.clone());
        let held: Vec<&str> = WANTED
            .into_iter()
            .map(|(key, _)| key)
            .filter(|key| row.object.get(key).is_some())
            .collect();
        let disposition = match held[..] {
            [kind] => Value::String(Text::from(kind)),
            _ => Value::Null,
        };
        dispositions.insert(row.id.clone(), disposition);
        let file = scoped
            .iter_mut()
            .find(|file| *row.path == file.path.as_str());
        if let Err(Malformed(reason)) =
            check_row(&row, &held, file, &mut refusals, &references, read)
        {
            refusals.refuse(
                "row",
                text!("row ", row.id.repr(), " is malformed: ", reason),
            );
        }
    }

    for file in &scoped {
        let production = file.reading.production();
        for (site, targets) in file.reading.sites().iter().zip(&file.targets) {
            let token = &production[site.start()..site.end()];
            let place = format!("{}:{}", file.path, line_of(production, site.start()));
            if targets.is_empty() {
                refusals.refuse(
                    "unrowed site",
                    text!(place, ": ", token, " lies in no row's find"),
                );
                continue;
            }
            let expected: &[&str] = match site.kind() {
                Kind::Fence { .. } => &["delete"],
                Kind::Ordering { strength, op } => steps(strength, op),
            };
            let mut matched = targets.clone();
            matched.sort_unstable();
            if matched != expected {
                refusals.refuse(
                    "site rows",
                    text!(
                        place,
                        ": ",
                        token,
                        " has rows to ",
                        repr(&strings(matched)),
                        ", its steps are ",
                        repr(&strings(expected.iter().copied()))
                    ),
                );
            }
        }
    }

    let unrun: BTreeSet<Text> = dispositions
        .iter()
        .filter(|(_, disposition)| matches!(disposition, Value::String(kind) if *kind == "unrun"))
        .map(|(id, _)| id.clone())
        .collect();
    let mut excluded = scope.excluded().to_vec();
    excluded.sort_unstable();
    let count: usize = scoped.iter().map(|file| file.reading.sites().len()).sum();
    let credited = refusals.is_empty() && unrun.is_empty();
    let code = u8::from(!refusals.is_empty());
    let mut report = Object::new();
    report.insert("refusals", Value::Array(refusals.0));
    report.insert("rows", Value::Object(dispositions));
    report.insert(
        "unrun",
        Value::Array(unrun.into_iter().map(Value::String).collect()),
    );
    report.insert("sites", Value::Integer(Integer::from(count)));
    report.insert("excluded", strings(excluded.iter().map(String::as_str)));
    report.insert("credited", Value::Bool(credited));
    (Value::Object(report), code)
}

#[cfg(test)]
#[path = "check_tests.rs"]
mod tests;
