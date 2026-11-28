//! The checker validates the ordering catalog, `verification/orderings/expected.json`, against its
//! scoped files.
//!
//! A row's `find` must occur exactly once in its file's production text and hold exactly one site, of
//! the row's `op`. Applying one weakening from [`steps`] to that site in `find` must yield `replace`; a
//! fence row deletes the call with a `;` directly after it. Each site takes one row per step. When the
//! checker skips a listed file, its rows stay unmatched and the refusal names the file.
//!
//! The report is a JSON object of six members in this order: `refusals`, each `refusal` and `message`
//! in the order refused; `rows`, each well-formed row's id with its one disposition's name, or null for
//! none or several, in catalog order; `unrun`, the ids of the unrun rows in code point order; `sites`,
//! the count of sites in the files read; `excluded`, the files the kernel package includes that every
//! chain of declarations loads through a test-only item, in code point order; and `credited`.
//! `credited` is true exactly when both `refusals` and `unrun` are empty. The exit code is 0 for an
//! empty `refusals` list and 1 for a nonempty one. An input that cannot be read gives exit 2 and a
//! report of one member, `error`.
//!
//! Offsets are byte offsets of a scoped file's text, which its production and scanned texts share.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::sites::{self, Kind, Pin, Strength, line_of};
use super::sources::{
    Reader, References, include_defects, path_attributes, references, scope_files,
};
use crate::classes::is_word;
use crate::json::{Integer, Object, Text, Value, parse_unique};
use crate::python::repr;
use crate::rust_text::code;
use crate::text::{text, words};

/// The check reads `CATALOG`, `GENMC`, `RC11` and `OBLIGATIONS` in that order.
pub const CATALOG: &str = "verification/orderings/expected.json";
pub const GENMC: &str = "verification/genmc/expected.json";
pub const RC11: &str = "verification/rc11/expected.json";
pub const OBLIGATIONS: &str = "verification/obligations.json";

/// Only rows listed in `UNMODELED` may have an empty run list.
pub const UNMODELED: [&str; 4] = [
    "word-install",
    "fill-depart-held",
    "sequence-begin-store",
    "sequence-commit",
];

const OPS: [&str; 4] = ["load", "store", "rmw", "fence"];

const DISPOSITIONS: [&str; 3] = ["kill", "survives", "unrun"];

const REQUIRED: [&str; 5] = ["id", "path", "op", "find", "replace"];

const ROW_KEYS: [&str; 12] = [
    "id", "path", "find", "replace", "op", "binding", "scope", "twin", "revision", "kill",
    "survives", "unrun",
];

/// `steps` returns the permitted one-step weakenings in code point order.
fn steps(strength: Strength, op: &str) -> &'static [&'static str] {
    match (strength, op) {
        (Strength::SeqCst, "load") => &["Acquire"],
        (Strength::SeqCst, "store") => &["Release"],
        (Strength::SeqCst, "rmw") => &["AcqRel"],
        (Strength::AcqRel, "rmw") => &["Acquire", "Release"],
        (Strength::Release, "store" | "rmw") | (Strength::Acquire, "load" | "rmw") => &["Relaxed"],
        _ => &[],
    }
}

#[derive(Default)]
struct Refusals(Vec<(&'static str, Text)>);

impl Refusals {
    fn refuse(&mut self, name: &'static str, message: Text) {
        self.0.push((name, message));
    }

    fn value(&self) -> Value {
        Value::Array(
            self.0
                .iter()
                .map(|(name, message)| {
                    let mut entry = Object::new();
                    entry.insert("refusal", Value::String(Text::from(*name)));
                    entry.insert("message", Value::String(message.clone()));
                    Value::Object(entry)
                })
                .collect(),
        )
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

/// A scoped file the check read: its repository path, its site reading and, for each of its sites, the
/// steps of the rows matched to it.
struct Scoped {
    path: String,
    reading: sites::Reading,
    targets: Vec<Vec<&'static str>>,
}

fn strings<'t>(names: impl IntoIterator<Item = &'t str>) -> Value {
    Value::Array(
        names
            .into_iter()
            .map(|name| Value::String(Text::from(name)))
            .collect(),
    )
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
    let scope = object.get("scope").is_none_or(|scope| {
        matches!(scope, Value::Array(headers) if headers.iter().all(|header| matches!(header, Value::String(_))))
    });
    let (Some(id), Some(path), Some(op), Some(find), Some(replace), true, true) = (
        string("id"),
        string("path"),
        string("op"),
        string("find"),
        string("replace"),
        binding,
        scope,
    ) else {
        return Err(Text::from("a field has the wrong type"));
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

/// Records `row` against the one site its `find` holds in `scoped` and returns that site's index, or
/// refuses the row.
fn match_row(row: &Row<'_>, scoped: &mut Scoped, refusals: &mut Refusals) -> Option<usize> {
    let name = row.id;
    let production = scoped.reading.production();
    let find = row.find.to_str();
    let count = find.map_or(0, |find| production.matches(find).count());
    let Some(find) = find.filter(|_| count == 1) else {
        refusals.refuse(
            "find",
            text!(name, ": its find occurs ", count, " times in ", row.path),
        );
        return None;
    };
    let start = production
        .find(find)
        .expect("a find that occurs once has a first offset");
    let held: Vec<usize> = (0..scoped.reading.sites().len())
        .filter(|&index| {
            let site = scoped.reading.sites()[index];
            start <= site.start() && site.end() <= start + find.len()
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
    let (before, after) = (&find[..site.start() - start], &find[site.end() - start..]);
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
        Kind::Ordering { strength, .. } => steps(strength, op)
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
    Some(index)
}

/// The `(start, end)` of each place in `code`, a scoped file's production text with comments and literals
/// blanked, that can load source: the word `include`, the keyword `mod` after no `#`, and each path
/// attribute as [`path_attributes`] finds it, in order. A word inside a path attribute belongs to it.
fn loaders(code: &str) -> Vec<(usize, usize)> {
    let attributes = path_attributes(code);
    let mut found = attributes.clone();
    for (word, after_hash) in [("include", true), ("mod", false)] {
        for (offset, _) in code.match_indices(word) {
            let before = code[..offset].chars().next_back();
            let next = code[offset + word.len()..].chars().next();
            let bounded = !before.is_some_and(|c| is_word(c) || (!after_hash && c == '#'))
                && !next.is_some_and(is_word);
            let inside = attributes
                .iter()
                .any(|&(start, end)| start < offset && offset < end);
            if bounded && !inside {
                found.push((offset, offset + word.len()));
            }
        }
    }
    found.sort_unstable();
    found
}

fn failed(prefix: &str, reason: &str) -> (Value, u8) {
    let mut report = Object::new();
    report.insert("error", Value::String(text!(prefix, reason)));
    (Value::Object(report), 2)
}

/// The catalog's files and rows, the references of the three declarations, and the kernel package's
/// path under the checkout.
struct Inputs {
    files: Vec<Text>,
    rows: Vec<Value>,
    references: References,
    package: PathBuf,
}

/// The inputs `read` gives, or the reason one cannot be read or has another shape.
fn inputs(read: Reader<'_>, root: &Path) -> Result<Inputs, String> {
    let mut documents = Vec::new();
    for path in [CATALOG, GENMC, RC11, OBLIGATIONS] {
        let source = read(path).map_err(|error| format!("{path}: {error}"))?;
        documents.push(parse_unique(&source).map_err(|error| format!("{path}: {error}"))?);
    }
    let [catalog, declared, litmus, records] = <[Value; 4]>::try_from(documents)
        .unwrap_or_else(|_| unreachable!("one document is read for each of four paths"));
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
    }
    .ok_or_else(|| "the GenMC declaration's package is no path".to_owned())?;
    Ok(Inputs {
        files,
        rows: rows.clone(),
        references,
        package: root.join(package),
    })
}

/// The report and the exit code of the catalog check: the catalog, the declarations and the scoped
/// files come from `read`, the kernel package is walked under the checkout `root`, and the crate
/// sources that can declare an included file are found under `tree`. A strength constant with no
/// `S::NAME` mention in its file takes its op from its pin in `pins`.
///
/// The check acts with the authority of its caller and trusts the directories it is given; it reads
/// each input whole.
pub fn check(read: Reader<'_>, root: &Path, tree: &Path, pins: &[Pin]) -> (Value, u8) {
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
    let scope = include_defects(&package, references.kernels()).and_then(|defects| {
        for defect in defects {
            refusals.refuse(defect.name(), Text::from(defect.message()));
        }
        scope_files(&package, root, read, tree)
    });
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
        let code = code(reading.production());
        for (start, end) in loaders(&code) {
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
        scoped.push(Scoped {
            path: path.to_owned(),
            reading,
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
        let held: Vec<&str> = DISPOSITIONS
            .into_iter()
            .filter(|key| row.object.get(key).is_some())
            .collect();
        let disposition = match held[..] {
            [kind] => Value::String(Text::from(kind)),
            _ => Value::Null,
        };
        dispositions.insert(row.id.clone(), disposition);
        if let Some(file) = scoped
            .iter_mut()
            .find(|file| *row.path == file.path.as_str())
        {
            match_row(&row, file, &mut refusals);
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
                Kind::Ordering { strength, op } => steps(strength, op.name()),
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
    let credited = refusals.0.is_empty() && unrun.is_empty();
    let code = u8::from(!refusals.0.is_empty());
    let mut report = Object::new();
    report.insert("refusals", refusals.value());
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
