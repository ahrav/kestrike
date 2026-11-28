//! [`transcription_drift`] records drift when a named `before` or `after` anchor lacks a site entry on
//! the referencing site's `side`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use super::refusal::{Error, Refusal, listed, lookup, member, read_error, string, strings};
use crate::classes::{WORD, compiled, is_word};
use crate::genmc::{bodies, normalized, read_source};
use crate::json::{Integer, Object, Text, Value};
use crate::orderings::sources::joined;
use crate::python::{equal, repr, str_of, truthy};

static ORDERING: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r"^(?:{WORD}+::)*Ordering::({WORD}+)$")));

static STRENGTH: LazyLock<Regex> = LazyLock::new(|| compiled(&format!(r"^S::({WORD}+)$")));

static CONSTANT: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r"const ({WORD}+):Ordering=Ordering::({WORD}+);")));

const KINDS: [&str; 6] = ["load", "store", "rmw", "cas", "fence", "call"];

fn kind_holds(kind: &str, method: &str) -> bool {
    match kind {
        "load" => method == "load",
        "store" => method == "store",
        "rmw" => method == "swap" || method.starts_with("fetch_"),
        "cas" => matches!(
            method,
            "compare_exchange" | "compare_exchange_weak" | "fetch_update" | "try_update"
        ),
        "fence" => matches!(method, "fence" | "$fence" | "fence_release"),
        _ => true,
    }
}

fn texts(value: &Value, what: &str) -> Result<Vec<String>, Error> {
    listed(value, what)?
        .iter()
        .map(|item| string(item, what).map(str::to_owned))
        .collect()
}

fn present<'v>(value: &'v Value, key: &str) -> Result<Option<&'v Value>, Error> {
    Ok(lookup(value, key)?.filter(|found| !matches!(found, Value::Null)))
}

fn count_is(count: usize, wanted: Option<&Value>) -> bool {
    let count = Value::Integer(Integer::from(count));
    match wanted {
        Some(wanted) => equal(&count, wanted),
        None => equal(&count, &Value::Integer(Integer::from(1_u64))),
    }
}

fn contains(container: &Value, needle: &Value) -> Result<bool, Error> {
    match container {
        Value::Array(items) => Ok(items.iter().any(|item| equal(item, needle))),
        _ => Err(Error::Type("the transcribed files are no array".into())),
    }
}

fn arguments(text: &str, start: usize) -> Option<Vec<String>> {
    let bytes = text.as_bytes();
    let mut depth = 0_usize;
    let mut args = Vec::new();
    let mut begun = start + 1;
    for index in start..bytes.len() {
        match bytes[index] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    args.push(text[begun..index].to_owned());
                    return Some(args.into_iter().filter(|arg| !arg.is_empty()).collect());
                }
            }
            b',' if depth == 1 => {
                args.push(text[begun..index].to_owned());
                begun = index + 1;
            }
            _ => {}
        }
    }
    None
}

struct Sources<'r> {
    root: &'r Path,
    read: HashMap<String, String>,
}

impl Sources<'_> {
    fn normalized(&mut self, path: &str) -> Result<String, Error> {
        if let Some(text) = self.read.get(path) {
            return Ok(text.clone());
        }
        let text = normalized(&read_source(self.root, path).map_err(read_error)?);
        self.read.insert(path.to_owned(), text.clone());
        Ok(text)
    }
}

type Strengths = BTreeMap<String, BTreeMap<String, String>>;

fn strengths(
    declared: &Value,
    package: &str,
    sources: &mut Sources<'_>,
) -> Result<(Strengths, Vec<String>), Error> {
    let mut found = BTreeMap::new();
    let mut drift = Vec::new();
    let Some(listed_strengths) = lookup(declared, "strengths")? else {
        return Ok((found, drift));
    };
    for strength in listed(listed_strengths, "the declared strengths")? {
        let file = member(&strength, "file")?;
        let path = package_path(package, string(file, "a strength's file")?);
        let source = sources.normalized(&path)?;
        let implementation = member(&strength, "impl")?;
        let header = normalized(string(implementation, "a strength's impl")?);
        let blocks = bodies(&source, &header);
        if blocks.len() != 1 {
            drift.push(format!(
                "{} declares {} {} times",
                str_of(file),
                str_of(implementation),
                blocks.len()
            ));
            continue;
        }
        let constants = CONSTANT
            .captures_iter(&blocks[0])
            .map(|found| (found[1].to_owned(), found[2].to_owned()))
            .collect();
        found.insert(path, constants);
    }
    Ok((found, drift))
}

struct Located {
    scope: String,
    offset: usize,
    orderings: Vec<String>,
    constants: BTreeSet<String>,
}

fn calls(scope: &str, call: &str) -> Vec<usize> {
    let pattern = compiled(&format!(r"{}(?:::<[^>]*>)?\(", regex::escape(call)));
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(matched) = pattern.find_at(scope, at) {
        let before = scope[..matched.start()].chars().next_back();
        if before.is_some_and(|c| is_word(c) || c == '.' || c == '$') {
            at = matched.start()
                + scope[matched.start()..]
                    .chars()
                    .next()
                    .map_or(1, char::len_utf8);
            continue;
        }
        found.push(matched.end() - 1);
        at = matched.end();
    }
    found
}

fn locate(
    entry: &Value,
    side: &str,
    site: &Value,
    sources: &mut Sources<'_>,
    strength: Option<&BTreeMap<String, String>>,
) -> Result<Result<Located, String>, Error> {
    let id = str_of(member(entry, "id")?);
    let scope_value = member(site, "scope")?;
    let headers = texts(scope_value, "a site's scope")?;
    let joined_headers = headers.join(" > ");
    let where_ = if joined_headers.is_empty() {
        "the file"
    } else {
        joined_headers.as_str()
    };
    let file = member(site, "file")?;
    let mut scopes = vec![sources.normalized(string(file, "a site's file")?)?];
    for header in &headers {
        let header = normalized(header);
        scopes = scopes
            .iter()
            .flat_map(|scope| bodies(scope, &header))
            .collect();
    }
    if scopes.len() != 1 {
        return Ok(Err(format!(
            "{id}: the {side} scope {where_} in {} appears {} times",
            str_of(file),
            scopes.len()
        )));
    }
    let scope = scopes.remove(0);
    let call_value = member(site, "call")?;
    let call_text = string(call_value, "a site's call")?;
    let call = normalized(call_text);
    let operands = match lookup(site, "operands")? {
        Some(operands) if truthy(operands) => operands,
        _ => member(entry, "operands")?,
    };
    let bound: Vec<String> = texts(operands, "a binding's operands")?
        .iter()
        .map(|text| normalized(text))
        .collect();
    let found = calls(&scope, &call);
    if !count_is(found.len(), lookup(site, "among")?) {
        return Ok(Err(format!(
            "{id}: the {side} {call_text} appears {} times in {where_}",
            found.len()
        )));
    }
    let mut candidates = Vec::new();
    for offset in found {
        let (mut operands, mut orderings, mut constants) =
            (Vec::new(), Vec::new(), BTreeSet::new());
        for arg in arguments(&scope, offset).unwrap_or_default() {
            if let Some(ordering) = ORDERING.captures(&arg) {
                orderings.push(ordering[1].to_owned());
            } else if let Some(constant) = STRENGTH.captures(&arg).filter(|_| side == "kernel") {
                let name = &constant[1];
                let Some(ordering) = strength.and_then(|strength| strength.get(name)) else {
                    return Ok(Err(format!(
                        "{id}: the kernel names {arg}, which no declared strength of {} defines",
                        str_of(file)
                    )));
                };
                orderings.push(ordering.clone());
                constants.insert(name.to_owned());
            } else {
                operands.push(arg);
            }
        }
        candidates.push((operands, orderings, constants, offset));
    }
    let matching: Vec<usize> = (0..candidates.len())
        .filter(|&index| candidates[index].0 == bound)
        .collect();
    if !count_is(matching.len(), lookup(site, "matching")?) {
        let found_operands = Value::Array(
            candidates
                .iter()
                .map(|candidate| strings(&candidate.0))
                .collect(),
        );
        return Ok(Err(format!(
            "{id}: the {side} {call_text} operands are {}, bound {}",
            repr(&found_operands),
            repr(&strings(&bound))
        )));
    }
    let Some(&first) = matching.first() else {
        return Err(Error::Index(format!(
            "{id}: the {side} {call_text} has no matching occurrence"
        )));
    };
    let (_, orderings, constants, offset) = candidates.swap_remove(first);
    Ok(Ok(Located {
        scope,
        offset,
        orderings,
        constants,
    }))
}

fn package_path(package: &str, file: &str) -> String {
    joined(if package.is_empty() { "." } else { package }, file)
}

type Sites = BTreeMap<(Text, &'static str), (Value, Located)>;

fn anchor_drift(
    name: &Text,
    side: &str,
    site: &Value,
    found: &Located,
    sites: &Sites,
    ids: &[Value],
    drift: &mut Vec<String>,
) -> Result<(), Error> {
    for relation in ["before", "after"] {
        let anchors = match lookup(site, relation)? {
            Some(anchors) => listed(anchors, "a site's anchors")?,
            None => Vec::new(),
        };
        for anchor in &anchors {
            if matches!(anchor, Value::Array(_) | Value::Object(_)) {
                return Err(Error::Type("an anchor is unhashable".into()));
            }
            let places = if ids.iter().any(|id| equal(id, anchor)) {
                let other = match anchor {
                    Value::String(anchor) => sites.get(&(anchor.clone(), side)),
                    _ => None,
                };
                let Some((other_site, other)) = other else {
                    drift.push(format!(
                        "{name}: the {side} anchor entry {} was not located",
                        str_of(anchor)
                    ));
                    continue;
                };
                let same = equal(member(other_site, "file")?, member(site, "file")?)
                    && equal(member(other_site, "scope")?, member(site, "scope")?);
                if !same {
                    drift.push(format!(
                        "{name}: the {side} anchor entry {} sits in another scope",
                        str_of(anchor)
                    ));
                    continue;
                }
                vec![other.offset]
            } else {
                let text = normalized(string(anchor, "an anchor")?);
                found
                    .scope
                    .match_indices(text.as_str())
                    .map(|(start, _)| start)
                    .collect()
            };
            if places.len() != 1 {
                drift.push(format!(
                    "{name}: the {side} anchor {} appears {} times in its scope",
                    repr(anchor),
                    places.len()
                ));
            } else if (found.offset < places[0]) != (relation == "before") {
                drift.push(format!(
                    "{name}: the {side} operation no longer comes {relation} {}",
                    repr(anchor)
                ));
            }
        }
    }
    Ok(())
}

pub fn transcription_drift(declared: &Value, root: &Path) -> Result<Vec<String>, Error> {
    let package = string(member(declared, "package")?, "the declared package")?;
    let bindings = match lookup(declared, "bindings")? {
        Some(bindings) => listed(bindings, "the declared bindings")?,
        None => Vec::new(),
    };
    let mut ids = Vec::new();
    for entry in &bindings {
        let id = member(entry, "id")?;
        if matches!(id, Value::Array(_) | Value::Object(_)) {
            return Err(Error::Type("a binding's id is unhashable".into()));
        }
        ids.push(id.clone());
    }
    let mut sources = Sources {
        root,
        read: HashMap::new(),
    };
    let (declared_strengths, mut drift) = strengths(declared, package, &mut sources)?;
    let mut sites: Sites = BTreeMap::new();
    let mut bound: BTreeMap<String, BTreeSet<String>> = declared_strengths
        .keys()
        .map(|path| (path.clone(), BTreeSet::new()))
        .collect();
    for entry in &bindings {
        let id = member(entry, "id")?;
        let kind_value = member(entry, "kind")?;
        let kind = match kind_value {
            Value::String(kind) if KINDS.iter().any(|known| *kind == *known) => kind.to_string(),
            Value::Array(_) | Value::Object(_) => {
                return Err(Error::Type("a binding's kind is unhashable".into()));
            }
            _ => {
                drift.push(format!("{}: unknown kind {}", str_of(id), repr(kind_value)));
                continue;
            }
        };
        for side in ["production", "kernel"] {
            let Some(site) = present(entry, side)? else {
                continue;
            };
            let file = member(site, "file")?;
            if side == "production" && !contains(member(declared, "transcribed")?, file)? {
                drift.push(format!(
                    "{}: {} is not among the transcribed files",
                    str_of(id),
                    str_of(file)
                ));
                continue;
            }
            let site = if side == "kernel" {
                let Value::Object(object) = site else {
                    return Err(Error::Type("a kernel site is no object".into()));
                };
                let mut object: Object = object.clone();
                let path = package_path(package, string(file, "a site's file")?);
                object.insert("file", Value::String(path.into()));
                Value::Object(object)
            } else {
                site.clone()
            };
            let call_value = member(&site, "call")?;
            let call = string(call_value, "a site's call")?;
            let method = call.rsplit('.').next().unwrap_or(call);
            let method = method.rsplit("::").next().unwrap_or(method);
            if !kind_holds(&kind, method) {
                drift.push(format!("{}: the {side} {call} is no {kind}", str_of(id)));
                continue;
            }
            let path = str_of(member(&site, "file")?).to_string();
            let located = match locate(
                entry,
                side,
                &site,
                &mut sources,
                declared_strengths.get(&path),
            )? {
                Ok(located) => located,
                Err(problem) => {
                    drift.push(problem);
                    continue;
                }
            };
            if !located.constants.is_empty() {
                bound
                    .entry(path.clone())
                    .or_default()
                    .extend(located.constants.iter().cloned());
            }
            let orderings = member(entry, "orderings")?;
            if !equal(&strings(&located.orderings), orderings) {
                drift.push(format!(
                    "{}: the {side} orderings are {}, bound {}",
                    str_of(id),
                    repr(&strings(&located.orderings)),
                    str_of(orderings)
                ));
            }
            let Value::String(key) = id else {
                return Err(Error::Type("a located binding's id is no string".into()));
            };
            sites.insert((key.clone(), side), (site, located));
        }
    }
    for ((name, side), (site, found)) in &sites {
        anchor_drift(name, side, site, found, &sites, &ids, &mut drift)?;
    }
    for (path, names) in &bound {
        for constant in declared_strengths[path].keys() {
            if !names.contains(constant) {
                drift.push(format!(
                    "{path} transcribes {constant} in its strength and no binding entry binds it"
                ));
            }
        }
    }
    Ok(drift)
}

pub fn check_transcription(root: &Path, expected: &Value) -> Result<(), Error> {
    let drift = transcription_drift(expected, root)?;
    if drift.is_empty() {
        Ok(())
    } else {
        Err(Error::Refusal(Refusal::drift(&drift)))
    }
}

#[cfg(test)]
#[path = "transcription_tests.rs"]
mod tests;
