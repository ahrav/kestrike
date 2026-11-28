//! The check of a hardware manifest and its reader.

use std::fs;
use std::path::Path;

use super::constants::{
    CASE_KEYS, CHANNEL, DISPOSITIONS, ENVELOPE_FIELDS, OPTIONAL_PROFILE_KEYS, PROFILE_KEYS,
    ROLE_KEYS, UNREAD, identity_lines, is_device_identity, is_environment_name, is_episode_name,
};
use super::error::{Error, need};
use super::shape::{
    self, Fault, compare, contains, count, distinct, equals, get, holds_all, index_by, is_integer,
    items, keys, limit, members, object, within,
};
use crate::json::{self, Object, Value};
use crate::python::{repr, str_of, truthy};
use crate::text::{Text, text};

const UTF8_MARK: &[u8] = b"\xef\xbb\xbf";

/// `read_manifest` reads the file at `path` once, decodes it as JSON, checks the whole document with
/// [`check_manifest`] and returns its platform rows in document order.
///
/// # Errors
///
/// [`Error::System`] with the read's error, and [`Error::Refused`] after `malformed hardware manifest: ` for
/// bytes that are no UTF-8 JSON document and for a failed check.
pub fn read_manifest(path: &Path) -> Result<Object, Error> {
    let bytes = fs::read(path).map_err(Error::System)?;
    let document = decode(&bytes)?;
    check_manifest(&document)?;
    match document {
        Value::Object(mut top) => match top.remove("platforms") {
            Some(Value::Object(platforms)) => Ok(platforms),
            _ => unreachable!("a checked manifest's platforms are an object"),
        },
        _ => unreachable!("a checked manifest is an object"),
    }
}

/// `decode` drops one leading UTF-8 byte order mark and reads the rest as strict UTF-8 holding one JSON
/// document: objects keep their members in document order, a repeated key keeps its last value, and
/// `NaN`, `Infinity` and `-Infinity` are floats.
fn decode(bytes: &[u8]) -> Result<Value, Error> {
    let skipped = if bytes.starts_with(UTF8_MARK) {
        UTF8_MARK.len()
    } else {
        0
    };
    let text = std::str::from_utf8(&bytes[skipped..]).map_err(|error| {
        Error::malformed(&text!(
            "the bytes are not UTF-8 from byte ",
            skipped + error.valid_up_to()
        ))
    })?;
    json::parse(text).map_err(|error| {
        Error::malformed(&text!(
            "the bytes are no JSON document: ",
            error.reason(),
            " at byte ",
            skipped + error.offset()
        ))
    })
}

/// The refusal at a point where the item `at` holds a value of a kind the check cannot read.
fn shaped(at: &Text, fault: &Fault) -> Error {
    Error::malformed(&text!(at, ": ", fault.to_string()))
}

/// The value of a key the check has found in `object`.
///
/// # Panics
///
/// `member` panics when the key is absent; each caller reads a key that a passed check of the object's keys
/// requires.
fn member<'a>(object: &'a Object, key: &str) -> &'a Value {
    object
        .get(key)
        .unwrap_or_else(|| panic!("the key check found the key {key}"))
}

/// The repr of a Python list or tuple of texts, between `open` and `close`.
fn list_repr<'a>(items: impl IntoIterator<Item = &'a Text>, open: char, close: char) -> Text {
    let items: Vec<String> = items.into_iter().map(Text::repr).collect();
    text!(open.to_string(), items.join(", "), close.to_string())
}

fn texts(names: &[&str]) -> Vec<Text> {
    names.iter().map(|name| Text::from(*name)).collect()
}

/// `check_manifest` makes the 35 checks of a hardware manifest in order and returns its platform rows.
///
/// # Errors
///
/// [`Error::Refused`] after `malformed hardware manifest: `, naming the first check that fails, or the
/// first point where a value's kind is one the check cannot read, with a statement of that shape.
pub fn check_manifest(document: &Value) -> Result<&Object, Error> {
    let refused = || Error::malformed(&Text::from("top-level keys"));
    let Value::Object(top) = document else {
        return Err(refused());
    };
    let optional_object = |key: &str| {
        top.get(key)
            .is_none_or(|value| matches!(value, Value::Object(_)))
    };
    let names = keys(top);
    let keyed = holds_all(&names, &["version", "platforms", "profiles"])
        && within(
            &names,
            &[
                "version",
                "platforms",
                "profiles",
                "qualification",
                "packages",
            ],
        )
        && optional_object("qualification")
        && optional_object("packages");
    if !keyed {
        return Err(refused());
    }
    let version = member(top, "version");
    need(equals(version, 1), || text!("version ", repr(version)))?;
    let (Value::Object(platforms), Value::Object(profiles)) =
        (member(top, "platforms"), member(top, "profiles"))
    else {
        return Err(Error::malformed(&Text::from(
            "platforms and profiles must be objects",
        )));
    };
    for (name, row) in platforms.iter() {
        check_platform(name, row)?;
    }
    let mut killer = None;
    for (name, profile) in profiles.iter() {
        killer = check_profile(name, profile, platforms, killer)?;
    }
    Ok(platforms)
}

/// The checks of one platform row, in order.
fn check_platform(name: &Text, row: &Value) -> Result<(), Error> {
    need(is_episode_name(name), || {
        text!(
            "platform name ",
            name.repr(),
            " is not an episode name of letters, digits, '.', '_' and '-' starting with a letter or \
             digit, which a CI episode needs"
        )
    })?;
    let at = text!("platform ", name);
    let keys = members(row).map_err(|fault| shaped(&at, &fault))?;
    need(
        holds_all(&keys, &["machine", "supported", "owner"])
            && within(&keys, &["machine", "supported", "owner", "envelope"]),
        || at.clone(),
    )?;
    let row = object(row).map_err(|fault| shaped(&at, &fault))?;
    let Value::Bool(supported) = *member(row, "supported") else {
        return Err(Error::malformed(&at));
    };
    let machine = member(row, "machine");
    let lines = match machine {
        Value::String(machine) => identity_lines(machine),
        _ => &[],
    };
    need(!lines.is_empty(), || {
        text!(
            "platform ",
            name,
            " names machine ",
            repr(machine),
            ", which has no CPU identity lines"
        )
    })?;
    let no_envelope = Object::new();
    let envelope = match row.get("envelope") {
        None => Some(&no_envelope),
        Some(Value::Object(envelope))
            if envelope
                .iter()
                .all(|(key, _)| ENVELOPE_FIELDS.iter().any(|field| key == field)) =>
        {
            Some(envelope)
        }
        Some(_) => None,
    };
    let Some(envelope) = envelope else {
        return Err(Error::malformed(&text!("platform ", name, " envelope")));
    };
    let short: Vec<Text> = ENVELOPE_FIELDS
        .iter()
        .filter(|field| {
            let value = envelope.get(field);
            empty(value) || !shaped_field(field, value, lines)
        })
        .map(|field| Text::from(*field))
        .collect();
    need(!supported || short.is_empty(), || {
        text!(
            "platform ",
            name,
            " is supported with an envelope short of ",
            list_repr(&short, '[', ']')
        )
    })
}

/// Whether an envelope's field is `in (None, "", [], {}, "unreadable")`, an absent field included.
fn empty(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.is_empty() || UNREAD.iter().any(|unread| text == unread),
        Some(Value::Array(items)) => items.is_empty(),
        Some(Value::Object(object)) => object.is_empty(),
        Some(_) => false,
    }
}

/// Whether an envelope's `devices`, `cpu_family` or `cpu_features` has its shape: PCI identities, the
/// machine's identity lines with stripped, read values, and features of one word each. Every other field
/// has its shape.
fn shaped_field(field: &str, value: Option<&Value>, lines: &[&str]) -> bool {
    match (field, value) {
        ("devices", Some(Value::Object(devices))) => devices.iter().all(
            |(_, identity)| matches!(identity, Value::String(identity) if is_device_identity(identity)),
        ),
        ("cpu_family", Some(Value::Object(family))) => {
            family.len() == lines.len()
                && family
                    .iter()
                    .all(|(key, _)| lines.iter().any(|line| key == line))
                && family.iter().all(|(_, value)| match value {
                    Value::String(value) => {
                        !value.is_empty()
                            && *value == value.strip()
                            && !UNREAD.iter().any(|unread| value == unread)
                    }
                    _ => false,
                })
        }
        ("cpu_features", Some(Value::Array(features))) => {
            features.iter().all(|feature| match feature {
                Value::String(feature) => {
                    !feature.is_empty() && feature.split() == [feature.clone()]
                }
                _ => false,
            })
        }
        ("devices" | "cpu_family" | "cpu_features", _) => false,
        _ => true,
    }
}

/// The checks of one profile, its roles and their cases; it returns the profile's name when one of its
/// roles is killed.
fn check_profile<'a>(
    name: &'a Text,
    profile: &Value,
    platforms: &Object,
    killer: Option<&Text>,
) -> Result<Option<&'a Text>, Error> {
    let at = text!("profile ", name);
    let keys = members(profile).map_err(|fault| shaped(&at, &fault))?;
    let optional: Vec<&str> = PROFILE_KEYS
        .iter()
        .chain(&OPTIONAL_PROFILE_KEYS)
        .copied()
        .collect();
    need(
        holds_all(&keys, &PROFILE_KEYS) && within(&keys, &optional),
        || at.clone(),
    )?;
    let profile = object(profile).map_err(|fault| shaped(&at, &fault))?;
    let disposed = match member(profile, "platforms") {
        Value::Object(rows) => {
            rows.len() == platforms.len()
                && rows
                    .iter()
                    .all(|(row, _)| platforms.get_text(row).is_some())
                && rows.iter().all(|(_, disposition)| {
                    matches!(disposition, Value::String(disposition)
                        if DISPOSITIONS.iter().any(|known| disposition == known))
                })
        }
        _ => false,
    };
    need(disposed, || {
        text!(
            "profile ",
            name,
            " needs one disposition of ",
            list_repr(&texts(&DISPOSITIONS), '(', ')'),
            " per platform row"
        )
    })?;
    need(killer.is_none(), || {
        text!(
            "profile ",
            name,
            " follows the kill profile ",
            killer.cloned().unwrap_or_default(),
            ", whose host awaits containment"
        )
    })?;
    let roles = object(member(profile, "roles"))
        .map_err(|fault| shaped(&text!("profile ", name, " roles"), &fault))?;
    let kills = kills_a_role(name, roles)?;
    need(equals(member(profile, "retries"), 0), || {
        text!("profile ", name, " declares retries")
    })?;
    need(!roles.is_empty(), || {
        text!("profile ", name, " has no roles")
    })?;
    need(conjunction(profile, roles), || {
        text!("profile ", name, " conjunction")
    })?;
    let evidence = profile.get("evidence").is_none_or(|evidence| {
        matches!(evidence, Value::String(evidence) if evidence.starts_with(&Text::from("KESTRIKE_")))
    });
    need(evidence, || text!("profile ", name, " evidence"))?;
    need(profile.get("evidence").is_some() || !kills, || {
        text!("profile ", name, " kills a role without an evidence gate")
    })?;
    let mut clients: Vec<&Text> = Vec::new();
    for (role_name, role) in roles.iter() {
        clients.extend(check_role(name, role_name, role, roles)?);
    }
    let count = clients.len();
    clients.sort_unstable();
    clients.dedup();
    need(clients.len() == count, || {
        text!("profile ", name, " declares one client index for two roles")
    })?;
    Ok(kills.then_some(name))
}

/// Whether `"kill" in role` holds for a role, read in order up to the first that holds.
fn kills_a_role(name: &Text, roles: &Object) -> Result<bool, Error> {
    for (role_name, role) in roles.iter() {
        if contains(role, "kill")
            .map_err(|fault| shaped(&text!("role ", name, "/", role_name), &fault))?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `conjunction` accepts an omitted field or an array of non-empty chains. Each entry is a string whose
/// first `:` separates a key in `roles` from a non-empty case name.
fn conjunction(profile: &Object, roles: &Object) -> bool {
    let Some(chains) = profile.get("conjunction") else {
        return true;
    };
    let Value::Array(chains) = chains else {
        return false;
    };
    chains.iter().all(|chain| match chain {
        Value::Array(entries) if !entries.is_empty() => entries.iter().all(|entry| match entry {
            Value::String(entry) => {
                let bytes = entry.as_bytes();
                let (role, case) = match bytes.iter().position(|&byte| byte == b':') {
                    Some(at) => (&bytes[..at], &bytes[at + 1..]),
                    None => (bytes, &bytes[bytes.len()..]),
                };
                roles.iter().any(|(key, _)| key.as_bytes() == role) && !case.is_empty()
            }
            _ => false,
        }),
        _ => false,
    })
}

/// `check_role` validates the role and its cases in order and returns `env.KESTRIKE_CLIENT` if present.
fn check_role<'a>(
    name: &Text,
    role_name: &Text,
    entry: &'a Value,
    roles: &'a Object,
) -> Result<Option<&'a Text>, Error> {
    let at = text!("role ", name, "/", role_name);
    let fault = |fault: Fault| shaped(&at, &fault);
    need(within(&members(entry).map_err(fault)?, &ROLE_KEYS), || {
        at.clone()
    })?;
    let role = object(entry).map_err(fault)?;
    need(role.get("cases").is_some_and(truthy), || at.clone())?;
    let env = match role.get("env") {
        None => None,
        Some(Value::Object(env))
            if env.iter().all(|(key, value)| {
                is_environment_name(key) && matches!(value, Value::String(_))
            }) =>
        {
            Some(env)
        }
        Some(_) => return Err(Error::malformed(&text!(at, " env"))),
    };
    let unknown = || Error::malformed(&text!(at, " waits on an unknown role"));
    let predecessor = match role.get("after") {
        None | Some(Value::Null) => None,
        Some(Value::String(after)) => Some((after, roles.get_text(after).ok_or_else(unknown)?)),
        Some(_) => return Err(unknown()),
    };
    if let Some((after, predecessor)) = predecessor {
        let ready = get(predecessor, "ready")
            .map_err(|fault| shaped(&text!("role ", name, "/", after), &fault))?;
        need(
            matches!(ready, Some(Value::String(ready)) if !ready.is_empty()),
            || {
                text!(
                    at,
                    " waits on ",
                    after,
                    ", which declares no readiness line"
                )
            },
        )?;
    }
    let depth = predecessors(roles, role_name, entry)
        .map_err(|(holder, fault)| shaped(&text!("role ", name, "/", holder), &fault))?;
    need(depth.is_some(), || text!(at, " waits on itself"))?;
    let lines = ["ready", "closing"].iter().all(|key| match role.get(key) {
        None => true,
        Some(Value::String(line)) => !line.is_empty(),
        Some(_) => false,
    });
    need(lines, || {
        text!(at, " readiness and closing lines are non-empty strings")
    })?;
    let cases = member(role, "cases");
    let ready = role.get("ready").is_some_and(truthy);
    let closes = ready && role.get("closing").is_some_and(truthy)
        || !closes_on_sigterm(cases).map_err(fault)?;
    need(closes, || {
        text!(
            at,
            " closes on SIGTERM without a readiness and a closing line"
        )
    })?;
    let killed = role.get("kill");
    let delay = match killed {
        None => true,
        Some(kill) => limit(kill, false).map_err(fault)? && ready,
    };
    need(delay, || text!(at, " kill"))?;
    need(
        killed.is_none() || count(cases).map_err(fault)? == 1,
        || text!(at, " kill role runs one case"),
    )?;
    let listed = items(cases).map_err(fault)?;
    let read = listed
        .iter()
        .map(|case| object(case))
        .collect::<Result<Vec<_>, _>>()
        .map_err(fault)?;
    let ids: Vec<Option<&Value>> = read.iter().map(|case| case.get("id")).collect();
    need(distinct(&ids).map_err(fault)? == ids.len(), || {
        text!(at, " names a case twice")
    })?;
    for case in read {
        check_case(case, env)?;
    }
    Ok(env
        .and_then(|env| env.get("KESTRIKE_CLIENT"))
        .and_then(|client| match client {
            Value::String(client) => Some(client),
            _ => None,
        }))
}

/// Whether a case's `closes_on_sigterm` is true, read in order up to the first that is.
fn closes_on_sigterm(cases: &Value) -> Result<bool, Fault> {
    for case in items(cases)? {
        if get(&case, "closes_on_sigterm")?.is_some_and(truthy) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `predecessors` counts the roles the role `name` waits on through its `after` chain, or gives `None` once
/// the count passes the number of roles, which only a loop reaches. A fault comes with the name of the role
/// whose entry or `after` was read.
fn predecessors<'a>(
    roles: &'a Object,
    mut name: &'a Text,
    mut role: &'a Value,
) -> Result<Option<usize>, (&'a Text, Fault)> {
    let mut depth = 0;
    loop {
        let after = shape::get(role, "after").map_err(|fault| (name, fault))?;
        let Some(after) = after.filter(|after| **after != Value::Null) else {
            return Ok(Some(depth));
        };
        depth += 1;
        if depth > roles.len() {
            return Ok(None);
        }
        (name, role) = index_by(roles, after).map_err(|fault| (name, fault))?;
    }
}

/// The checks of one case, in order; `env` is its role's `env`, where the role holds one.
fn check_case(case: &Object, env: Option<&Object>) -> Result<(), Error> {
    let names = keys(case);
    need(
        holds_all(&names, &CASE_KEYS) && within(&names, &CASE_KEYS),
        || {
            let mut sorted: Vec<&Text> = case.iter().map(|(key, _)| key).collect();
            sorted.sort();
            text!(
                "case ",
                repr(case.get("id").unwrap_or(&Value::Null)),
                " keys ",
                list_repr(sorted, '[', ']')
            )
        },
    )?;
    let at = text!("case ", str_of(member(case, "id")));
    let fault = |fault: Fault| shaped(&at, &fault);
    let expected = member(case, "expected");
    need(
        is_integer(expected) && compare(expected, 1).is_some_and(|order| order.is_ge()),
        || text!(at, " expects no test"),
    )?;
    let limits = limit(member(case, "deadline"), true).map_err(fault)?
        && limit(member(case, "grace"), true).map_err(fault)?;
    need(limits, || {
        text!(at, " needs a finite positive deadline and grace")
    })?;
    let inputs = member(case, "inputs");
    let mut prefixed = true;
    for input in items(inputs).map_err(fault)? {
        match &*input {
            Value::String(input) if input.starts_with(&Text::from("KESTRIKE_")) => {}
            Value::String(_) => {
                prefixed = false;
                break;
            }
            other => return Err(fault(Fault::Text(shape::kind(other)))),
        }
    }
    need(prefixed, || text!(at, " inputs"))?;
    let names = members(inputs).map_err(fault)?;
    let channel = CHANNEL
        .iter()
        .filter(|end| holds_all(&names, &[end]))
        .count();
    need(channel == 0 || channel == 2, || {
        text!(at, " names half a channel")
    })?;
    let parked = contains(inputs, CHANNEL[0]).map_err(fault)?
        && case.get("closes_on_sigterm").is_some_and(truthy);
    need(!parked, || {
        text!(
            at,
            " closes on SIGTERM while parked on its containment channel"
        )
    })?;
    let episode = contains(inputs, "KESTRIKE_EPISODE").map_err(fault)?
        || env.is_some_and(|env| env.get("KESTRIKE_EPISODE").is_some());
    need(!episode, || {
        text!(at, " names KESTRIKE_EPISODE, which the lane sets itself")
    })?;
    need(
        matches!(member(case, "closes_on_sigterm"), Value::Bool(_)),
        || text!(at, " closes_on_sigterm"),
    )
}

#[cfg(test)]
#[path = "manifest_tests.rs"]
mod tests;
