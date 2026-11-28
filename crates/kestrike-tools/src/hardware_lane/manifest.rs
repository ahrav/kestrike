use std::fs;
use std::io;
use std::path::Path;

use super::constants::{
    CASE_KEYS, CHANNEL, DISPOSITIONS, ENVELOPE_FIELDS, OPTIONAL_PROFILE_KEYS, PROFILE_KEYS,
    ROLE_KEYS, UNREAD, identity_lines, is_device_identity, is_environment_name, is_episode_name,
};
use super::refusal::{Refusal, need};
use super::shape::{
    self, Fault, Member, compare, contains, count, distinct, equals, finite, get, holds_all,
    index_by, is_integer, is_real, items, members, object, within,
};
use crate::json::{self, Object, Value};
use crate::python::{repr, str_of, truthy};
use crate::text::{Text, text};

const UTF8_MARK: &[u8] = b"\xef\xbb\xbf";

#[derive(Debug)]
pub enum ManifestError {
    Read(io::Error),
    Document(Refusal),
    Check(Refusal),
}

pub fn read_manifest(path: &Path) -> Result<Object, ManifestError> {
    let bytes = fs::read(path).map_err(ManifestError::Read)?;
    let document = decode(&bytes).map_err(ManifestError::Document)?;
    check_manifest(&document)
        .cloned()
        .map_err(ManifestError::Check)
}

fn decode(bytes: &[u8]) -> Result<Value, Refusal> {
    let skipped = if bytes.starts_with(UTF8_MARK) {
        UTF8_MARK.len()
    } else {
        0
    };
    let text = std::str::from_utf8(&bytes[skipped..]).map_err(|error| {
        Refusal::malformed(&text!(
            "the bytes are not UTF-8 from byte ",
            skipped + error.valid_up_to()
        ))
    })?;
    json::parse(text).map_err(|error| {
        Refusal::malformed(&text!("the bytes are no JSON document: ", error.to_string()))
    })
}

fn shaped(at: &Text, fault: &Fault) -> Refusal {
    Refusal::malformed(&text!(at, ": ", fault.to_string()))
}

fn member<'a>(object: &'a Object, key: &str) -> &'a Value {
    object
        .get(key)
        .unwrap_or_else(|| panic!("the key check found the key {key}"))
}

fn list_repr<'a>(items: impl IntoIterator<Item = &'a Text>, open: char, close: char) -> Text {
    let items: Vec<String> = items.into_iter().map(Text::repr).collect();
    text!(open.to_string(), items.join(", "), close.to_string())
}

fn texts(names: &[&str]) -> Vec<Text> {
    names.iter().map(|name| Text::from(*name)).collect()
}

pub fn check_manifest(document: &Value) -> Result<&Object, Refusal> {
    let optional_object = |top: &Object, key: &str| {
        top.get(key)
            .is_none_or(|value| matches!(value, Value::Object(_)))
    };
    let top = match document {
        Value::Object(top) => Some(top),
        _ => None,
    }
    .filter(|top| {
        let keys = members(document).unwrap_or_default();
        holds_all(&keys, &["version", "platforms", "profiles"])
            && within(
                &keys,
                &["version", "platforms", "profiles", "qualification", "packages"],
            )
            && optional_object(top, "qualification")
            && optional_object(top, "packages")
    });
    let Some(top) = top else {
        return Err(Refusal::malformed(&Text::from("top-level keys")));
    };
    let version = member(top, "version");
    need(equals(version, 1), || text!("version ", repr(version)))?;
    let (Value::Object(platforms), Value::Object(profiles)) =
        (member(top, "platforms"), member(top, "profiles"))
    else {
        return Err(Refusal::malformed(&Text::from(
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

fn check_platform(name: &Text, row: &Value) -> Result<(), Refusal> {
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
    let keyed = holds_all(&keys, &["machine", "supported", "owner"])
        && within(&keys, &["machine", "supported", "owner", "envelope"]);
    let row = if keyed {
        Some(object(row).map_err(|fault| shaped(&at, &fault))?)
    } else {
        None
    };
    let supported = row.and_then(|row| match member(row, "supported") {
        Value::Bool(flag) => Some(*flag),
        _ => None,
    });
    let (Some(row), Some(supported)) = (row, supported) else {
        return Err(Refusal::malformed(&at));
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
        return Err(Refusal::malformed(&text!("platform ", name, " envelope")));
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

fn empty(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.is_empty() || UNREAD.iter().any(|unread| text == unread),
        Some(Value::Array(items)) => items.is_empty(),
        Some(Value::Object(object)) => object.is_empty(),
        Some(_) => false,
    }
}

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

fn check_profile<'a>(
    name: &'a Text,
    profile: &Value,
    platforms: &Object,
    killer: Option<&Text>,
) -> Result<Option<&'a Text>, Refusal> {
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
    need(!roles.is_empty(), || text!("profile ", name, " has no roles"))?;
    need(conjunction(profile, roles), || {
        text!("profile ", name, " conjunction")
    })?;
    let evidence = profile
        .get("evidence")
        .is_none_or(|evidence| str_of(evidence).starts_with(&Text::from("KESTRIKE_")));
    need(evidence, || text!("profile ", name, " evidence"))?;
    need(
        profile.get("evidence").is_some() || !kills_a_role(name, roles)?,
        || text!("profile ", name, " kills a role without an evidence gate"),
    )?;
    for (role_name, role) in roles.iter() {
        check_role(name, role_name, role, roles)?;
    }
    let clients: Vec<&Text> = roles
        .iter()
        .filter_map(|(_, role)| match role {
            Value::Object(role) => match role.get("env") {
                Some(Value::Object(env)) => match env.get("KESTRIKE_CLIENT") {
                    Some(Value::String(client)) => Some(client),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        })
        .collect();
    let distinct_clients = clients
        .iter()
        .enumerate()
        .filter(|(at, client)| !clients[..*at].contains(client))
        .count();
    need(clients.len() == distinct_clients, || {
        text!("profile ", name, " declares one client index for two roles")
    })?;
    Ok(kills.then_some(name))
}

fn kills_a_role(name: &Text, roles: &Object) -> Result<bool, Refusal> {
    for (role_name, role) in roles.iter() {
        if contains(role, "kill").map_err(|fault| shaped(&text!("role ", name, "/", role_name), &fault))? {
            return Ok(true);
        }
    }
    Ok(false)
}

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
                let (role, case) = partition(entry, ':');
                roles.get_text(&role).is_some() && !case.is_empty()
            }
            _ => false,
        }),
        _ => false,
    })
}

fn partition(text: &Text, separator: char) -> (Text, Text) {
    let codes: Vec<u32> = text.code_points().collect();
    let separator = u32::from(separator);
    let (before, after) = match codes.iter().position(|&code| code == separator) {
        Some(at) => (&codes[..at], &codes[at + 1..]),
        None => (&codes[..], &codes[codes.len()..]),
    };
    let rebuilt = |codes: &[u32]| {
        Text::from_code_points(codes.iter().copied())
            .expect("the code points of a text are at most U+10FFFF")
    };
    (rebuilt(before), rebuilt(after))
}

fn check_role(
    name: &Text,
    role_name: &Text,
    entry: &Value,
    roles: &Object,
) -> Result<(), Refusal> {
    let at = text!("role ", name, "/", role_name);
    let fault = |fault: Fault| shaped(&at, &fault);
    let keys = members(entry).map_err(fault)?;
    let role = if within(&keys, &ROLE_KEYS) {
        let role = object(entry).map_err(fault)?;
        role.get("cases").is_some_and(truthy).then_some(role)
    } else {
        None
    };
    let Some(role) = role else {
        return Err(Refusal::malformed(&at));
    };
    let no_env = Value::Object(Object::new());
    let env = role.get("env").unwrap_or(&no_env);
    let env_named = match env {
        Value::Object(env) => env.iter().all(|(key, value)| {
            is_environment_name(key) && matches!(value, Value::String(_))
        }),
        _ => false,
    };
    need(env_named, || text!(at, " env"))?;
    let after = role.get("after").filter(|after| **after != Value::Null);
    need(
        match after {
            None => true,
            Some(Value::String(after)) => roles.get_text(after).is_some(),
            Some(_) => false,
        },
        || text!(at, " waits on an unknown role"),
    )?;
    let ready_after = match after {
        None => true,
        Some(after) => {
            let predecessor = index_by(roles, after).map_err(fault)?;
            let ready = get(predecessor, "ready")
                .map_err(|fault| shaped(&text!("role ", name, "/", str_of(after)), &fault))?;
            matches!(ready, Some(Value::String(ready)) if !ready.is_empty())
        }
    };
    need(ready_after, || {
        text!(
            at,
            " waits on ",
            after.map_or_else(|| Text::from("None"), str_of),
            ", which declares no readiness line"
        )
    })?;
    need(predecessors(roles, entry).map_err(fault)?.is_some(), || {
        text!(at, " waits on itself")
    })?;
    let lines = ["ready", "closing"]
        .iter()
        .all(|key| match role.get(key) {
            None => true,
            Some(Value::String(line)) => !line.is_empty(),
            Some(_) => false,
        });
    need(lines, || {
        text!(at, " readiness and closing lines are non-empty strings")
    })?;
    let cases = member(role, "cases");
    let closes = role.get("ready").is_some_and(truthy) && role.get("closing").is_some_and(truthy)
        || !closes_on_sigterm(cases).map_err(fault)?;
    need(closes, || {
        text!(at, " closes on SIGTERM without a readiness and a closing line")
    })?;
    let killed = role.get("kill");
    let delay = match killed {
        None => true,
        Some(kill) => {
            is_real(kill)
                && finite(kill).map_err(fault)?
                && compare(kill, 0).is_some_and(|order| order.is_ge())
                && role.get("ready").is_some_and(truthy)
        }
    };
    need(delay, || text!(at, " kill"))?;
    need(
        killed.is_none() || count(cases).map_err(fault)? == 1,
        || text!(at, " kill role runs one case"),
    )?;
    let listed = items(cases).map_err(fault)?;
    let ids = listed
        .iter()
        .map(|case| get(case, "id"))
        .collect::<Result<Vec<_>, _>>()
        .map_err(fault)?;
    need(distinct(&ids).map_err(fault)? == ids.len(), || {
        text!(at, " names a case twice")
    })?;
    for case in &listed {
        check_case(object(case).map_err(fault)?, env)?;
    }
    Ok(())
}

fn closes_on_sigterm(cases: &Value) -> Result<bool, Fault> {
    for case in items(cases)? {
        if get(&case, "closes_on_sigterm")?.is_some_and(truthy) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `predecessors` counts the roles `role` waits on through its `after` chain, or gives `None` once the
/// count passes the number of roles, which only a loop reaches.
fn predecessors<'a>(roles: &'a Object, mut role: &'a Value) -> Result<Option<usize>, Fault> {
    let mut depth = 0;
    loop {
        let Some(after) = shape::get(role, "after")?.filter(|after| **after != Value::Null) else {
            return Ok(Some(depth));
        };
        depth += 1;
        if depth > roles.len() {
            return Ok(None);
        }
        role = index_by(roles, after)?;
    }
}

fn check_case(case: &Object, env: &Value) -> Result<(), Refusal> {
    let keys: Vec<Member> = case
        .iter()
        .map(|(key, _)| Member::Text(key.clone()))
        .collect();
    need(
        holds_all(&keys, &CASE_KEYS) && within(&keys, &CASE_KEYS),
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
    let mut limits = true;
    for limit in [member(case, "deadline"), member(case, "grace")] {
        if !(is_real(limit)
            && finite(limit).map_err(fault)?
            && compare(limit, 0).is_some_and(|order| order.is_gt()))
        {
            limits = false;
            break;
        }
    }
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
        || contains(env, "KESTRIKE_EPISODE").map_err(fault)?;
    need(!episode, || {
        text!(at, " names KESTRIKE_EPISODE, which the lane sets itself")
    })?;
    need(
        matches!(member(case, "closes_on_sigterm"), Value::Bool(_)),
        || text!(at, " closes_on_sigterm"),
    )
}
