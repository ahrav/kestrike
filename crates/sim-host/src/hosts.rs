//! The report's host section: every host's stored health record under
//! `hosts/`, classified against the report's clock.
//!
//! Each host takes exactly one [`State`], from the first rule that
//! matches:
//!
//! 1. A key whose instance part is no instance id raises `missing` from
//!    its listing entry alone, and the flag carries the key.
//! 2. A record past [`health::BOUND`], one that is no JSON object, does
//!    not parse, names no instance or another instance than its key, or is
//!    written more than [`CLOCK_SKEW_S`] ahead of the clock read right
//!    after its download is `missing`.
//! 3. A record with a stint length of 1 to [`assignment::SECONDS_MAX`]
//!    that is older than two of them is `silent`, in any phase. A
//!    `written` ahead of the clock is age 0.
//! 4. A record in phase `stopped` with such a stint length and a
//!    `written` is stopped: listed with no flag and counted apart from
//!    active hosts.
//! 5. Every other record takes the verdict `sim-host status` gives it at
//!    its age: critical is `unhealthy`, warning is `degraded` and ok is
//!    active. A record whose stint length is absent or outside 1 to
//!    [`assignment::SECONDS_MAX`] is `unhealthy` at any age.
//! 6. A host whose newest root snapshot is at most two of that snapshot's
//!    stint lengths old and that stores no record is `missing`.
//!
//! Ages are judged at one reading of the clock, taken before the listing.
//! A record the read finds gone counts as no record. The section is a
//! function of the records, the clock readings stored with them, each
//! host's newest snapshot and the judging clock, so every listing order
//! and every `--build` give the same section.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use serde_json::{Value, json};

use crate::health::{self, HOSTS, NAME, Phase};
use crate::report::kept_text;
use crate::store::{Bounded, Bucket, Error, SHORT};
use crate::{assignment, host, instance, status};

/// The most seconds a record or a snapshot may be written ahead of the
/// report's clock and still be judged, at age 0.
pub const CLOCK_SKEW_S: u64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Missing,
    Stopped,
    Silent,
    Unhealthy,
    Degraded,
    Active,
}

impl State {
    pub const ALL: [Self; 6] = [
        Self::Missing,
        Self::Stopped,
        Self::Silent,
        Self::Unhealthy,
        Self::Degraded,
        Self::Active,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Stopped => "stopped",
            Self::Silent => "silent",
            Self::Unhealthy => "unhealthy",
            Self::Degraded => "degraded",
            Self::Active => "active",
        }
    }
}

/// One object of the `hosts/` listing, as the report read it.
#[derive(Clone, Debug, PartialEq)]
pub enum Record {
    /// A key whose instance part is no instance id, known from the
    /// listing alone.
    Unnamed {
        key: String,
    },
    Unread {
        instance: String,
        size: Option<u64>,
    },
    Judged {
        instance: String,
        row: Box<Row>,
    },
}

impl Record {
    pub fn read(instance: String, bytes: &[u8], observed: u64, now: u64) -> Self {
        let row = Box::new(classify(&instance, bytes, observed, now));
        Self::Judged { instance, row }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Row {
    pub build: Value,
    pub error: Option<String>,
    pub phase: Value,
    pub reason: Value,
    pub reasons: Vec<String>,
    pub root: Value,
    pub share: Value,
    pub state: State,
    pub stint_seconds: Value,
    pub written: Value,
}

#[derive(Debug, Default, PartialEq)]
pub struct Section {
    pub rows: BTreeMap<String, Row>,
    /// The flag detail of each key whose instance part is no instance id.
    pub unnamed: Vec<Value>,
}

impl Section {
    /// One count per [`State`], zero included.
    pub fn counts(&self) -> BTreeMap<&'static str, u64> {
        let mut counts: BTreeMap<&'static str, u64> =
            State::ALL.iter().map(|state| (state.name(), 0)).collect();
        for row in self.rows.values() {
            *counts.entry(row.state.name()).or_default() += 1;
        }
        counts
    }
}

/// The instance part of a key under `hosts/`, with whether the key is
/// that instance's record; `None` when the part is no instance id.
fn named(key: &str) -> Option<(&str, bool)> {
    let rest = key.strip_prefix(HOSTS)?;
    let (part, tail) = rest.split_once('/').unwrap_or((rest, ""));
    instance::is_instance_id(part).then_some((part, tail == NAME))
}

pub fn fetch(
    bucket: &Bucket,
    scratch: &Path,
    limit: usize,
    now: u64,
) -> Result<Vec<Record>, String> {
    let mut listed = bucket
        .list(HOSTS, limit)
        .map_err(|error| format!("listing {HOSTS}: {error}"))?;
    listed.sort_by(|left, right| left.key.cmp(&right.key));
    let mut records = Vec::new();
    for object in listed {
        if object.key == HOSTS {
            continue;
        }
        let Some((instance, record)) = named(&object.key) else {
            records.push(Record::Unnamed { key: object.key });
            continue;
        };
        if !record {
            continue;
        }
        let instance = instance.to_owned();
        let size = match object.size {
            0 => match bucket.head(&object.key) {
                Ok(head) => head.length,
                Err(Error::Missing) => continue,
                Err(error) => return Err(format!("{}: {error}", object.key)),
            },
            size => size,
        };
        if size > health::BOUND {
            records.push(Record::Unread {
                instance,
                size: Some(size),
            });
            continue;
        }
        let bytes = if size == 0 {
            Vec::new()
        } else {
            let path = scratch.join(format!("host-{instance}"));
            let read = bucket
                .read_bounded(&object.key, &path, health::BOUND, SHORT)
                .map_err(|error| format!("{}: {error}", object.key))?;
            match read {
                Bounded::Read(bytes) => bytes,
                Bounded::Gone => continue,
                Bounded::Past => {
                    records.push(Record::Unread {
                        instance,
                        size: None,
                    });
                    continue;
                }
            }
        };
        records.push(Record::read(instance, &bytes, host::now_s(), now));
    }
    Ok(records)
}

fn known<T: Into<Value>>(value: Option<T>) -> Value {
    value.map_or_else(|| Value::from("unknown"), Into::into)
}

fn text(value: Option<&str>) -> Value {
    known(value.map(kept_text))
}

fn missing(error: String) -> Row {
    let unknown = || known(None::<u64>);
    let error = kept_text(&error);
    Row {
        build: unknown(),
        error: Some(error.clone()),
        phase: unknown(),
        reason: unknown(),
        reasons: vec![error],
        root: unknown(),
        share: unknown(),
        state: State::Missing,
        stint_seconds: unknown(),
        written: unknown(),
    }
}

fn unread(size: Option<u64>) -> Row {
    missing(match size {
        Some(size) => format!("the record holds {size} bytes, more than {}", health::BOUND),
        None => format!("the record holds more than {} bytes", health::BOUND),
    })
}

/// Rules 2 to 5 for the record `bytes` stored under `instance`'s key.
fn classify(instance: &str, bytes: &[u8], observed: u64, now: u64) -> Row {
    if bytes.len() as u64 > health::BOUND {
        return unread(Some(bytes.len() as u64));
    }
    let health = match health::parse(bytes) {
        Ok(health) => health,
        Err(error) => return missing(format!("the record {error}")),
    };
    match health.instance.as_deref() {
        None => return missing("the record names no instance".into()),
        Some(named) if named != instance => {
            return missing("the record names another instance than its key".into());
        }
        Some(_) => {}
    }
    if health
        .written
        .is_some_and(|written| written > observed.saturating_add(CLOCK_SKEW_S))
    {
        return missing("the record is written ahead of the report's clock".into());
    }
    let stint = health
        .stint_seconds
        .filter(|seconds| (1..=assignment::SECONDS_MAX).contains(seconds));
    let at = health.written.map_or(now, |written| written.max(now));
    let verdict = status::judge(&health, at);
    let mut reasons: Vec<String> = verdict.report["reasons"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|reason| reason.as_str().map(kept_text))
        .collect();
    let stopped = health.phase.as_deref() == Some(Phase::Stopped.name());
    let state = match (stint, health.written) {
        (Some(stint), Some(written)) if status::stale(written, stint, now) => State::Silent,
        (Some(_), Some(_)) if stopped => State::Stopped,
        (None, _) => {
            reasons.push(match health.stint_seconds {
                None => "stint_seconds unknown".to_owned(),
                Some(seconds) => format!(
                    "stint_seconds {seconds} outside 1 to {}",
                    assignment::SECONDS_MAX
                ),
            });
            State::Unhealthy
        }
        _ => match verdict.code {
            0 => State::Active,
            1 => State::Degraded,
            _ => State::Unhealthy,
        },
    };
    let share = status::share(health.stint_cpu_usec, health.stint_capacity_usec);
    Row {
        build: text(health.build.as_deref()),
        error: None,
        phase: text(health.phase.as_deref()),
        reason: text(health.reason.as_deref()),
        reasons,
        root: text(health.root.as_deref()),
        share: known(share),
        state,
        stint_seconds: known(health.stint_seconds),
        written: known(health.written),
    }
}

/// Classifies `records` at `now`. `newest` maps each host with a root
/// snapshot to its newest snapshot's `written` and stint length.
pub fn section(
    records: impl IntoIterator<Item = Record>,
    newest: &BTreeMap<String, (u64, Option<u64>)>,
    now: u64,
) -> Section {
    let mut out = Section::default();
    for record in records {
        match record {
            Record::Unnamed { key } => out
                .unnamed
                .push(json!({"key": key, "error": "its instance part is no instance id"})),
            Record::Unread { instance, size } => {
                out.rows.insert(instance, unread(size));
            }
            Record::Judged { instance, row } => {
                out.rows.insert(instance, *row);
            }
        }
    }
    for (host, (written, stint)) in newest {
        if let Some(stint) = stint.filter(|seconds| (1..=assignment::SECONDS_MAX).contains(seconds))
            && !out.rows.contains_key(host)
            && !status::stale(*written, stint, now)
        {
            let error = "the host stores root snapshots and no health record".to_owned();
            out.rows.insert(host.clone(), missing(error));
        }
    }
    out.unnamed.sort_by_cached_key(Value::to_string);
    out
}

#[cfg(test)]
#[path = "hosts_tests.rs"]
mod tests;
