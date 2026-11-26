//! The watch's decision step derives the writes of a cycle's last three
//! steps from the cycle's report document and its failure groups, the
//! known failure identities, the open alerts, the day whose summary is
//! known stored and the cycle's clock reading, so the same inputs give the
//! same writes. It serializes one failure group for each record it
//! creates, so a cycle copies the counts of at most [`RECORDS`] groups
//! however many identities are due.
//!
//! A failure identity is a profile and a suspect key, across builds. Its
//! id is the SHA-256 of the profile, a zero byte and the key, and this
//! derivation is part of the stored contract. An alert is a host state of
//! `unhealthy`, `silent` or `missing` and an instance. It opens at the
//! first document that shows it and closes at the first that omits it.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::hosts::State;
use crate::report::{FAILURES, FINDINGS, UNKEYED};

/// The most failure records one cycle creates.
pub const RECORDS: usize = 16;
const ALERTED: [State; 3] = [State::Missing, State::Silent, State::Unhealthy];
const LISTS: [&str; 3] = [FAILURES, FINDINGS, UNKEYED];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Alert {
    pub flag: String,
    pub instance: String,
}

/// One build's listing of a failure identity: the build's id, the
/// identity's profile and key, and the build's failure group for them.
/// [`decide`] copies the `count`, `roots` and `rerun` members of the
/// object the group serializes to; a member that object lacks is `null`
/// in the record.
pub struct Listing<'a, G> {
    pub build: &'a str,
    pub profile: &'a str,
    pub key: &'a str,
    pub group: G,
}

/// The writes of one cycle's steps 4 to 6, in the order the cycle makes
/// them.
pub struct Writes {
    /// The key and body of the host event, when at least one alert opened.
    pub hosts: Option<(String, Value)>,
    /// The alerts open after this cycle, saved once the event is stored.
    pub open: BTreeSet<Alert>,
    /// Up to [`RECORDS`] failure records, lowest id first.
    pub failures: Vec<Record>,
    /// The identities still due after `failures`.
    pub waiting: usize,
    /// The day's summary, for a day whose summary the watch has yet to see
    /// stored.
    pub digest: Option<Summary>,
}

/// The record of one failure identity, stored at [`failure_key`] of `id`.
#[derive(Debug, PartialEq)]
pub struct Record {
    pub id: String,
    pub body: Value,
}

/// The summary of one UTC day, stored at [`digest_key`] of `day`.
#[derive(Debug, PartialEq)]
pub struct Summary {
    pub day: String,
    pub body: Value,
}

pub fn identity(profile: &str, key: &str) -> String {
    let mut bytes = profile.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(key.as_bytes());
    crate::file::sha256(&bytes)
}

pub fn failure_key(id: &str) -> String {
    format!("events/failure-{id}.json")
}

pub fn digest_key(day: &str) -> String {
    format!("events/digest-{day}.json")
}

pub fn failure_id(key: &str) -> Option<&str> {
    key.strip_prefix("events/failure-")?
        .strip_suffix(".json")
        .filter(|id| crate::file::is_sha256(id))
}

pub fn day(now: u64) -> String {
    // A day count from the Unix epoch to a proleptic Gregorian date, by
    // 400-year eras of 146,097 days (Hinnant, *chrono-Compatible
    // Low-Level Date Algorithms*, `civil_from_days`). The count is never
    // negative, so the arithmetic stays in `u64`, and `now / 86_400` is
    // small enough that no step overflows.
    let z = now / 86_400 + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn alerts(document: &Value) -> BTreeMap<Alert, Value> {
    let mut shown = BTreeMap::new();
    for (instance, row) in document["hosts"].as_object().into_iter().flatten() {
        if let Some(flag) = row["state"]
            .as_str()
            .filter(|state| ALERTED.iter().any(|alerted| alerted.name() == *state))
        {
            let alert = Alert {
                flag: flag.to_owned(),
                instance: instance.clone(),
            };
            shown.insert(alert, row["reasons"].clone());
        }
    }
    shown
}

/// Each identity `listings` name that `known` lacks, with its listing of
/// the lowest build id.
fn due<'a, G>(
    listings: impl IntoIterator<Item = Listing<'a, G>>,
    known: &BTreeSet<String>,
) -> BTreeMap<String, Listing<'a, G>> {
    let mut due = BTreeMap::new();
    for listing in listings {
        let id = identity(listing.profile, listing.key);
        if known.contains(&id) {
            continue;
        }
        match due.entry(id) {
            Entry::Vacant(first) => {
                first.insert(listing);
            }
            Entry::Occupied(mut lowest) => {
                if listing.build < lowest.get().build {
                    lowest.insert(listing);
                }
            }
        }
    }
    due
}

fn summary(document: &Value, identities: usize, today: &str, now: u64) -> Value {
    let mut builds = Map::new();
    for (build, entry) in document["builds"].as_object().into_iter().flatten() {
        let totals: Map<String, Value> = entry
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(name, _)| !LISTS.contains(&name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        builds.insert(build.clone(), Value::Object(totals));
    }
    let mut flags: BTreeMap<&str, u64> = BTreeMap::new();
    for flag in document["flags"].as_array().into_iter().flatten() {
        if let Some(name) = flag["flag"].as_str() {
            *flags.entry(name).or_default() += 1;
        }
    }
    json!({
        "format": 1, "day": today, "written": now, "host_counts": document["host_counts"],
        "builds": builds, "failure_identities": identities, "flags": flags,
    })
}

/// The writes of a cycle whose report document shows `document`'s
/// `hosts`, `host_counts`, `flags` and `builds`, and whose builds list
/// the failure groups of `listings`. `decide` serializes one group for
/// each record, in id order, up to [`RECORDS`]. The first group that fails
/// to serialize is the error, returned in place of the writes.
pub fn decide<'a, G: Serialize>(
    document: &Value,
    listings: impl IntoIterator<Item = Listing<'a, G>>,
    known: &BTreeSet<String>,
    open: &BTreeSet<Alert>,
    digested: Option<&str>,
    now: u64,
) -> Result<Writes, serde_json::Error> {
    let shown = alerts(document);
    let opened: Vec<Value> = shown
        .iter()
        .filter(|(alert, _)| !open.contains(alert))
        .map(|(alert, reasons)| {
            json!({"flag": alert.flag, "instance": alert.instance, "reasons": reasons})
        })
        .collect();
    let hosts = (!opened.is_empty()).then(|| {
        let key = format!("events/hosts-{now}.json");
        (key, json!({"format": 1, "written": now, "alerts": opened}))
    });
    let due = due(listings, known);
    let waiting = due.len().saturating_sub(RECORDS);
    let failures = due
        .into_iter()
        .take(RECORDS)
        .map(|(id, listing)| {
            let mut group = serde_json::to_value(&listing.group)?;
            let mut member = |name| group.get_mut(name).map(Value::take).unwrap_or_default();
            let body = json!({
                "format": 1, "id": id, "build": listing.build, "profile": listing.profile,
                "key": listing.key, "count": member("count"), "roots": member("roots"),
                "rerun": member("rerun"),
            });
            Ok(Record { id, body })
        })
        .collect::<Result<Vec<Record>, serde_json::Error>>()?;
    let today = day(now);
    let digest = (digested != Some(today.as_str())).then(|| Summary {
        body: summary(document, known.len() + failures.len(), &today, now),
        day: today,
    });
    Ok(Writes {
        hosts,
        open: shown.into_keys().collect(),
        failures,
        waiting,
        digest,
    })
}

#[cfg(test)]
#[path = "decide_tests.rs"]
mod tests;
