//! The `campaign sweep-status` document of a plant's root: each profile's counters and run range, each
//! profile's suspect count, and whether the status may hide a differing replay that `suspects.jsonl` does
//! not list.
//!
//! The sweep counts each suspect once under its key, a class and a failure identity, or under
//! [`OTHER`] once its profile holds the most keys, and lists the first eight suspects of each key.

use std::collections::BTreeMap;

use super::suspects::REPLAY_DIFFERS;
use super::values::natural_integer;
use super::verdict::NoVerdict;
use crate::json::{Integer, Object, Value};
use crate::python::{repr, truthy};
use crate::text::{Text, text};

/// The counters of a profile, in the order its record lists them.
const COUNTERS: [&str; 4] = ["next", "runs", "pass", "suspects"];
/// The key a sweep counts a suspect under once its profile holds the most keys;
/// crates/campaign-supervisor/src/campaign/seeds.rs holds the same word.
pub(crate) const OTHER: &str = "other";

/// A profile's counters, each an integer of at least zero with `pass` ≤ `runs` ≤ `next`, its run range
/// and the evidence members `replays` and `uncredited`, as its record holds them.
#[derive(Clone, Debug, PartialEq)]
pub struct Runs {
    next: Integer,
    runs: Integer,
    members: Object,
}

impl Runs {
    /// The first run a next sweep runs.
    pub fn next(&self) -> &Integer {
        &self.next
    }

    /// The runs counted.
    pub fn runs(&self) -> &Integer {
        &self.runs
    }

    /// The members `next`, `runs`, `pass`, `suspects`, `range`, `replays` and `uncredited`, in that order.
    pub(crate) fn members(&self) -> &Object {
        &self.members
    }
}

fn profiles(status: &Object) -> Option<&Object> {
    match status.get("profiles") {
        Some(Value::Object(profiles)) => Some(profiles),
        _ => None,
    }
}

/// `profile_runs` reads the counters of `profile` in `status`.
///
/// # Errors
///
/// The status names no such profile, a counter is no integer of at least zero, or the counters are out
/// of order.
pub fn profile_runs(status: &Object, profile: &Text) -> Result<Runs, NoVerdict> {
    let named = "`campaign sweep-status` ";
    let totals = match profiles(status).and_then(|profiles| profiles.get_text(profile)) {
        Some(Value::Object(totals)) => totals,
        _ => {
            return Err(NoVerdict::plain(text!(named, "names no profile ", profile)));
        }
    };
    let counter = |name: &str| totals.get(name).and_then(natural_integer);
    let (Some(following), Some(ran), Some(passed), Some(suspects)) = (
        counter("next"),
        counter("runs"),
        counter("pass"),
        counter("suspects"),
    ) else {
        return Err(NoVerdict::plain(text!(
            named,
            "gives ",
            profile,
            " no count of ",
            COUNTERS.join(", ")
        )));
    };
    if !(passed <= ran && ran <= following) {
        return Err(NoVerdict::plain(text!(
            named,
            "gives ",
            profile,
            " counts out of order: pass ",
            passed,
            ", runs ",
            ran,
            ", next ",
            following
        )));
    }
    let range = if *following == Integer::from(0u64) {
        Value::Null
    } else {
        let last = following
            .minus_one()
            .expect("one below a positive integer has no more digits");
        Value::Array(vec![
            Value::Integer(Integer::from(0u64)),
            Value::Integer(last),
        ])
    };
    let mut members = Object::new();
    members.insert("next", Value::Integer(following.clone()));
    members.insert("runs", Value::Integer(ran.clone()));
    members.insert("pass", Value::Integer(passed.clone()));
    members.insert("suspects", Value::Integer(suspects.clone()));
    members.insert("range", range);
    for name in ["replays", "uncredited"] {
        members.insert(name, totals.get(name).cloned().unwrap_or(Value::Null));
    }
    Ok(Runs {
        next: following.clone(),
        runs: ran.clone(),
        members,
    })
}

/// `held_suspects` is each profile of `status` with its suspect count, in the status's order, controls
/// and histories included.
///
/// # Errors
///
/// The status names no profiles, or gives a profile no suspect count that is an integer of at least zero;
/// the refusal names every such profile, in code point order.
pub(crate) fn held_suspects(status: &Object) -> Result<Vec<(Text, Integer)>, NoVerdict> {
    let profiles = profiles(status)
        .ok_or_else(|| NoVerdict::plain("`campaign sweep-status` names no profiles"))?;
    let mut held = Vec::with_capacity(profiles.len());
    let mut unread = Vec::new();
    for (name, totals) in profiles.iter() {
        let count = match totals {
            Value::Object(totals) => totals.get("suspects"),
            _ => None,
        };
        match count.and_then(natural_integer) {
            Some(number) => held.push((name.clone(), number.clone())),
            _ => unread.push(name),
        }
    }
    if !unread.is_empty() {
        unread.sort();
        return Err(NoVerdict::plain(text!(
            "`campaign sweep-status` gives ",
            Text::join(", ", unread),
            " no suspect count"
        )));
    }
    Ok(held)
}

/// `unlisted_replay` says why a differing replay of a run of `profile` may be absent from
/// `suspects.jsonl`, or returns `None`. `shown` counts the lines the list holds of each profile and key.
/// A key of class [`REPLAY_DIFFERS`], or [`OTHER`], whose count passes its lines holds a suspect the list
/// does not name. So does a profile without a count of its suspects by key, each an integer of at least
/// zero, and a count by key that does not sum to the profile's suspects or that counts fewer suspects
/// under a key than the list holds.
///
/// # Errors
///
/// The status's `profiles` is a true value that is no object, or the sum by key has more digits than an
/// integer holds.
pub(crate) fn unlisted_replay(
    status: &Object,
    profile: &Text,
    shown: &BTreeMap<(Text, Text), usize>,
) -> Result<Option<Text>, NoVerdict> {
    let named = "`campaign sweep-status` ";
    let totals = match status.get("profiles") {
        Some(Value::Object(profiles)) => profiles.get_text(profile),
        Some(other) if truthy(other) => {
            return Err(NoVerdict::failed(
                "`campaign sweep-status` profiles is no object",
            ));
        }
        _ => None,
    };
    let Some(Value::Object(totals)) = totals else {
        return Ok(Some(text!(named, "names no profile ", profile)));
    };
    let total = totals.get("suspects").unwrap_or(&Value::Null);
    let keys: Option<Vec<(&Text, &Integer)>> = match totals.get("suspect_keys") {
        Some(Value::Object(counted)) => counted
            .iter()
            .map(|(key, number)| Some((key, natural_integer(number)?)))
            .collect(),
        _ => None,
    };
    let Some(mut keys) = keys else {
        return Ok(Some(text!(
            named,
            "gives ",
            profile,
            " no count of its suspects by key"
        )));
    };
    let sum = Integer::sum(keys.iter().map(|(_, count)| *count)).ok_or_else(|| {
        NoVerdict::failed("the sum of the suspects by key has more digits than an integer holds")
    })?;
    if Value::Integer(sum.clone()) != *total {
        return Ok(Some(text!(
            named,
            "counts ",
            repr(total),
            " suspects of ",
            profile,
            " and ",
            sum,
            " by key"
        )));
    }
    let counted = |key: &Text| {
        keys.iter()
            .find(|(name, _)| *name == key)
            .map_or_else(|| Integer::from(0u64), |(_, count)| (*count).clone())
    };
    for ((name, key), lines) in shown {
        if name == profile && Integer::from(*lines) > counted(key) {
            return Ok(Some(text!(
                "`suspects.jsonl` lists ",
                *lines,
                " suspects of ",
                profile,
                " under `",
                key,
                "` and `campaign sweep-status` counts ",
                counted(key)
            )));
        }
    }
    keys.sort_by(|left, right| left.0.cmp(right.0));
    let differs = Text::from(format!("{REPLAY_DIFFERS}: "));
    for (key, number) in keys {
        let lines = shown
            .get(&(profile.clone(), key.clone()))
            .copied()
            .unwrap_or(0);
        if (*key == OTHER || key.starts_with(&differs)) && *number > Integer::from(lines) {
            return Ok(Some(text!(
                named,
                "counts ",
                number,
                " suspects of ",
                profile,
                " under `",
                key,
                "` and `suspects.jsonl` lists ",
                lines
            )));
        }
    }
    Ok(None)
}
