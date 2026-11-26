//! `sim-host report`: the host set's totals, failures and flags, read from
//! the bucket alone. The fold holds one root's objects at a time. From
//! each root's suspect list it keeps at most [`ELEMENTS`] failure keys and
//! [`ELEMENTS`] keyless lines, which share one copy of the root's counts.
//! `sim-host watch` reads roots through [`list`] and [`read_root`] and
//! folds them with the same [`Report`], so its document has this
//! command's shape.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufWriter, Write as _};
use std::marker::PhantomData;
use std::path::Path;
use std::rc::Rc;

use serde::de::{Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};

use crate::hosts::{self, CLOCK_SKEW_S, Record, State};
use crate::lenient::{ELEMENTS, Lenient, Shape, object as typed};
use crate::snapshot::{self, LIST_BOUND, OBJECTS, OUTPUT_BOUND};
use crate::store::{Bounded, Bucket, Error, LONG};
use crate::{assignment, file, host, instance, signal, status};

const EXAMPLES: u64 = 8;
const OTHER: &str = "other";
/// `campaign` caps the JSON encoding of each suspect-line `key` and
/// `sweep-status` window name at 256 bytes. Decoding preserves that upper
/// bound.
const KEY_MAX: usize = 256;

/// A name the report shows from a `status.json`: the name itself up to
/// `max` bytes, the bound its producer applies, or the length of a longer
/// one. Two longer names of one length show as the same text.
fn named(name: &str, max: usize) -> String {
    if name.len() <= max {
        name.to_owned()
    } else {
        format!("a name of {} bytes", name.len())
    }
}

fn kept(text: &str) -> Value {
    Value::from(kept_text(text))
}

/// A text the report keeps from a stored object: the text itself up to
/// [`crate::health::TEXT_MAX`] bytes, or the length of a longer one.
pub(crate) fn kept_text(text: &str) -> String {
    if text.len() <= crate::health::TEXT_MAX {
        text.to_owned()
    } else {
        format!("a text of {} bytes", text.len())
    }
}
/// `LISTED` is the largest number of objects one listing of `roots/`,
/// `hosts/` or `events/failure-` returns, each prefix bounded on its own.
/// A report or a watch cycle whose `roots/` or `hosts/` listing passes it
/// fails, and a watch whose first `events/failure-` listing passes it
/// refuses to start.
pub(crate) const LISTED: usize = 1 << 20;
/// The members of a build's entry that list failure groups, findings and
/// keyless lines. Every other member of the entry is a total.
pub(crate) const FAILURES: &str = "failures";
pub(crate) const FINDINGS: &str = "findings";
pub(crate) const UNKEYED: &str = "unkeyed";

#[derive(Deserialize, Default)]
#[serde(default)]
struct Envelope {
    format: Lenient<u64>,
    build: Lenient<String>,
    host: Lenient<String>,
    campaign: Lenient<String>,
    stint: Lenient<u64>,
    stint_seconds: Lenient<u64>,
    written: Lenient<u64>,
    cpu_usec: Lenient<u64>,
    capacity_usec: Lenient<u64>,
    sweep_status: Lenient<Swept>,
}

type Numbers = BTreeMap<String, Lenient<u64>>;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Swept {
    campaign: Lenient<String>,
    counts: Lenient<Numbers>,
    runs: Lenient<u64>,
    pass: Lenient<u64>,
    uncredited: Lenient<u64>,
    suspects: Lenient<u64>,
    replays: Lenient<u64>,
    elapsed_s: Lenient<f64>,
    controls: Lenient<Missed>,
    histories: Lenient<Missed>,
    alarm: Lenient<String>,
    no_pass: Lenient<Vec<Lenient<String>>>,
    #[serde(deserialize_with = "name_lists")]
    unreached: Lenient<NameLists<Events>>,
    #[serde(deserialize_with = "name_lists")]
    no_window: Lenient<NameLists<Windows>>,
    profiles: Lenient<BTreeMap<String, Lenient<Totals>>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Missed {
    missed: Lenient<u64>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Totals {
    suspect_keys: Lenient<Numbers>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Findings {
    findings: Lenient<Vec<Lenient<Row>>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Row {
    id: Lenient<String>,
    resolved: Lenient<bool>,
    dispositions: Lenient<Vec<Lenient<Disposition>>>,
    held: Lenient<String>,
    held_code: Lenient<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Disposition {
    decision: Lenient<String>,
}

type Counts = BTreeMap<String, u64>;

/// A field of another type refuses the whole line.
#[derive(Deserialize)]
struct Line {
    campaign: String,
    build: String,
    profile: String,
    run: u64,
    counts: Lenient<Numbers>,
    #[serde(rename = "seed")]
    _seed: u64,
    key: Option<String>,
}

macro_rules! objects {
    ($($name:ty),*) => {$(
        impl Shape for $name {
            fn of_map<'de, A: MapAccess<'de>>(map: A) -> Result<Option<Self>, A::Error> {
                typed(map)
            }
        }
    )*};
}

objects!(
    Envelope,
    Swept,
    Missed,
    Totals,
    Findings,
    Row,
    Disposition,
    Line
);

type Read = fn(&Swept) -> Option<u64>;

const COUNTS: [(&str, Read); 6] = [
    ("runs", |swept| swept.runs.get().copied()),
    ("uncredited", |swept| swept.uncredited.get().copied()),
    ("suspects", |swept| swept.suspects.get().copied()),
    ("replays", |swept| swept.replays.get().copied()),
    ("missed_controls", |swept| {
        swept.controls.get().and_then(|c| c.missed.get().copied())
    }),
    ("missed_histories", |swept| {
        swept.histories.get().and_then(|h| h.missed.get().copied())
    }),
];
const RUNS: usize = 0;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Object<T> {
    Read(T),
    Absent,
    Unreadable(String),
}

impl<T> Object<T> {
    fn read(&self) -> Result<&T, &str> {
        match self {
            Self::Read(value) => Ok(value),
            Self::Absent => Err("absent"),
            Self::Unreadable(reason) => Err(reason),
        }
    }
}

pub(crate) struct Root {
    campaign: String,
    observed: u64,
    status: Object<Envelope>,
    payload: Option<Payload>,
}

struct Payload {
    suspects: Object<Vec<u8>>,
    findings: Object<Findings>,
}

/// The three objects of one root as a listing showed them, by name, with
/// each one's length and ETag.
pub(crate) type Objects = BTreeMap<String, (u64, Option<String>)>;

/// Lists `roots/` into each root's listed objects. A listing past
/// [`LISTED`] objects is an error.
pub(crate) fn list(bucket: &Bucket) -> Result<BTreeMap<String, Objects>, String> {
    let listed = bucket
        .list("roots/", LISTED)
        .map_err(|error| format!("listing roots/: {error}"))?;
    let mut roots: BTreeMap<String, Objects> = BTreeMap::new();
    for object in listed {
        let Some((campaign, name)) = object
            .key
            .strip_prefix("roots/")
            .and_then(|rest| rest.split_once('/'))
        else {
            continue;
        };
        if !campaign.is_empty() {
            let objects = roots.entry(campaign.to_owned()).or_default();
            if OBJECTS.contains(&name) {
                objects.insert(name.to_owned(), (object.size, object.etag));
            }
        }
    }
    Ok(roots)
}

/// What one read of a root produced, before any parse: `status.json` and,
/// for a root whose envelope the reported build selects, the suspect list
/// and `findings.json`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Raw {
    pub(crate) status: Bytes,
    /// The suspect list and `findings.json`.
    pub(crate) payload: Option<(Bytes, Bytes)>,
}

pub(crate) type Bytes = Object<Vec<u8>>;

/// How [`read_root`] conditions its downloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Condition {
    /// Each download reads whatever object the key holds.
    Any,
    /// Each download of an object the listing showed with 1 byte or more
    /// and an ETag names that ETag.
    Listed,
}

/// A root's [`Raw`] read, the clock reading taken right after its
/// `status.json` download, and whether every call agreed with the
/// listing. Under [`Condition::Listed`], agreement means each download of
/// an object listed with 1 byte or more named its listed ETag and matched
/// it, and each object the listing showed absent or empty was still so
/// when asked. An object listed without an ETag, a download that found
/// the object replaced, an object gone at its download, and an object
/// listed absent or empty that is no longer so when asked each clear it.
/// Under [`Condition::Any`] no download names an ETag, so `agreed` does
/// not show that a download matched the listing. `cacheable` holds for a
/// read under [`Condition::Listed`] with no build filter, the reads whose
/// [`Raw`] stands for the root for every reader of its listing.
pub(crate) struct Reading {
    pub(crate) raw: Raw,
    pub(crate) observed: u64,
    pub(crate) agreed: bool,
    pub(crate) cacheable: bool,
}

struct Reader<'a> {
    bucket: &'a Bucket,
    scratch: &'a Path,
    campaign: &'a str,
    listed: &'a Objects,
    condition: Condition,
    agreed: bool,
}

impl Reader<'_> {
    /// The length to read of `name` and the ETag that conditions its
    /// download. A listed length of 1 byte or more comes from the
    /// listing; for an object the listing shows absent or empty the
    /// bucket is asked again.
    fn current(&mut self, name: &str) -> Result<Option<(u64, Option<String>)>, String> {
        match self.listed.get(name) {
            Some((size, etag)) if *size > 0 => Ok(Some((*size, etag.clone()))),
            shown => {
                let now = stored(self.bucket, &snapshot::key(self.campaign, name))?;
                let still = matches!((shown, now), (None, None) | (Some((0, _)), Some(0)));
                self.agreed &= still;
                Ok(now.map(|size| (size, None)))
            }
        }
    }

    fn download(
        &mut self,
        name: &str,
        target: Option<(u64, Option<String>)>,
        bound: u64,
    ) -> Result<Object<Vec<u8>>, String> {
        let Some((size, etag)) = target else {
            return Ok(Object::Absent);
        };
        if size > bound {
            return Ok(Object::Unreadable(format!(
                "holds {size} bytes, more than {bound}"
            )));
        }
        if size == 0 {
            return Ok(Object::Read(Vec::new()));
        }
        let conditioned = self.condition == Condition::Listed;
        let etag = etag.filter(|_| conditioned);
        if conditioned && etag.is_none() {
            self.agreed = false;
        }
        let key = snapshot::key(self.campaign, name);
        let path = self
            .scratch
            .join(format!("{}-{name}", file::sha256(self.campaign.as_bytes())));
        let mut got = self
            .bucket
            .read_bounded_of(&key, etag.as_deref(), &path, bound, LONG);
        if got == Err(Error::Present) {
            self.agreed = false;
            got = self.bucket.read_bounded_of(&key, None, &path, bound, LONG);
        }
        match got {
            Ok(Bounded::Read(bytes)) => Ok(Object::Read(bytes)),
            Ok(Bounded::Gone) => {
                self.agreed = false;
                Ok(Object::Absent)
            }
            Ok(Bounded::Past) => Ok(Object::Unreadable(format!("holds more than {bound} bytes"))),
            Err(error) => Err(format!("{key}: {error}")),
        }
    }
}

/// Reads one listed root in the report's order, `status.json` first, and
/// takes the clock reading that judges the root right after the status
/// download. An object listed with 1 byte up to its bound is downloaded
/// as a range of at most one byte past the bound, and one listed past its
/// bound is flagged unread with no call. For an object listed absent or
/// empty the bucket is asked its length first, except the suspect list of
/// a root whose status counts no suspect key, which is taken from the
/// listing alone. Under [`Condition::Listed`] each download of an object
/// listed with bytes and an ETag names that ETag, and a download that
/// finds the object replaced reads it again with no condition. An object
/// listed without an ETag, and one listed absent or empty that holds bytes
/// when asked, is downloaded with no condition. Object lengths can change
/// between the listing and a download.
///
/// The watch's cache folds a stored read of an unchanged listing until the
/// cache's entry format changes, so a change to what this returns for the
/// same listed objects changes that format.
pub(crate) fn read_root(
    bucket: &Bucket,
    scratch: &Path,
    campaign: &str,
    listed: &Objects,
    only: Option<&str>,
    condition: Condition,
) -> Result<Reading, String> {
    if !printable(campaign) {
        let reason = "is not read: its root's name holds a byte outside printable ASCII";
        let raw = Raw {
            status: Object::Unreadable(reason.into()),
            payload: None,
        };
        return Ok(Reading {
            raw,
            observed: host::now_s(),
            agreed: true,
            cacheable: condition == Condition::Listed && only.is_none(),
        });
    }
    let mut reader = Reader {
        bucket,
        scratch,
        campaign,
        listed,
        condition,
        agreed: true,
    };
    let [status_name, list_name, findings_name] = OBJECTS;
    let target = reader.current(status_name)?;
    let status = reader.download(status_name, target, OUTPUT_BOUND)?;
    let observed = host::now_s();
    let parsed = parse::<Envelope>(&status);
    let wanted = parsed
        .read()
        .ok()
        .filter(|envelope| matches!(selected(campaign, envelope, only), Ok(Some(_))));
    let payload = match wanted {
        Some(envelope) => {
            let list = if counts_suspects(envelope) {
                reader.current(list_name)?
            } else {
                reader.listed.get(list_name).cloned()
            };
            let suspects = reader.download(list_name, list, LIST_BOUND)?;
            let target = reader.current(findings_name)?;
            let findings = reader.download(findings_name, target, OUTPUT_BOUND)?;
            Some((suspects, findings))
        }
        None => None,
    };
    let agreed = reader.agreed;
    Ok(Reading {
        raw: Raw { status, payload },
        observed,
        agreed,
        cacheable: condition == Condition::Listed && only.is_none(),
    })
}

impl Root {
    /// The root `raw` holds, judged as read at `observed`.
    pub(crate) fn of(campaign: String, observed: u64, raw: Raw) -> Self {
        Self {
            campaign,
            observed,
            status: parse(&raw.status),
            payload: raw.payload.map(|(suspects, findings)| Payload {
                findings: parse(&findings),
                suspects,
            }),
        }
    }
}

fn fetch(
    bucket: &Bucket,
    scratch: &Path,
    only: Option<&str>,
    mut each: impl FnMut(&Root),
) -> Result<(), String> {
    for (campaign, listed) in list(bucket)? {
        let read = read_root(bucket, scratch, &campaign, &listed, only, Condition::Any)?;
        each(&Root::of(campaign, read.observed, read.raw));
    }
    Ok(())
}

fn counts_suspects(envelope: &Envelope) -> bool {
    let profiles = envelope
        .sweep_status
        .get()
        .and_then(|swept| swept.profiles.get());
    profiles.into_iter().flatten().any(|(_, totals)| {
        totals
            .get()
            .and_then(|totals| totals.suspect_keys.get())
            .is_some_and(|keys| !keys.is_empty())
    })
}

fn stored(bucket: &Bucket, key: &str) -> Result<Option<u64>, String> {
    match bucket.head(key) {
        Ok(head) => Ok(Some(head.length)),
        Err(Error::Missing) => Ok(None),
        Err(error) => Err(format!("{key}: {error}")),
    }
}

fn parse<T: Shape>(object: &Object<Vec<u8>>) -> Object<T> {
    match object {
        Object::Read(bytes) => match serde_json::from_slice::<Lenient<T>>(bytes) {
            Ok(Lenient::Typed(value)) => Object::Read(value),
            Ok(_) => Object::Unreadable("is not a JSON object".into()),
            Err(error) => Object::Unreadable(format!("does not parse: {error}")),
        },
        Object::Absent => Object::Absent,
        Object::Unreadable(reason) => Object::Unreadable(reason.clone()),
    }
}

fn selected<'e>(
    campaign: &str,
    envelope: &'e Envelope,
    only: Option<&str>,
) -> Result<Option<&'e str>, &'static str> {
    if envelope.format.get() != Some(&1) {
        return Err("its format is not 1");
    }
    if envelope.campaign.get().map(String::as_str) != Some(campaign) {
        return Err("it names another campaign");
    }
    let Some(build) = envelope.build.get().filter(|build| file::is_sha256(build)) else {
        return Err("it names no build SHA-256");
    };
    if let Lenient::Typed(host) = &envelope.host
        && !(instance::is_instance_id(host) && campaign.split('.').nth(1) == Some(host.as_str()))
    {
        return Err("its host is not the instance its campaign names");
    }
    match &envelope.sweep_status {
        Lenient::Typed(swept) if swept.campaign.get().map(String::as_str) != Some(campaign) => {
            return Err("its sweep_status does not name its campaign");
        }
        Lenient::Other => return Err("its sweep_status is not an object"),
        _ => {}
    }
    Ok(only.is_none_or(|only| only == build).then_some(build))
}

#[derive(Clone, Copy)]
enum Flag {
    Silent,
    Unhealthy,
    Degraded,
    Alarm,
    NoPass,
    Unreached,
    NoWindow,
    Other,
    Missing,
    Held,
}

impl Flag {
    fn name(self) -> &'static str {
        match self {
            Self::Silent => "silent",
            Self::Unhealthy => "unhealthy",
            Self::Degraded => "degraded",
            Self::Alarm => "alarm",
            Self::NoPass => "no_pass",
            Self::Unreached => "unreached",
            Self::NoWindow => "no_window",
            Self::Other => "other",
            Self::Missing => "missing",
            Self::Held => "held",
        }
    }

    fn critical(self) -> bool {
        matches!(
            self,
            Self::Silent
                | Self::Unhealthy
                | Self::Alarm
                | Self::NoPass
                | Self::Unreached
                | Self::NoWindow
        )
    }
}

#[derive(Default)]
struct Flags {
    raised: BTreeMap<String, Value>,
    critical: bool,
}

impl Flags {
    fn raise(&mut self, root: Option<&str>, flag: Flag, detail: Value) {
        let entry = json!({"root": root, "flag": flag.name(), "detail": detail});
        self.critical |= flag.critical();
        self.raised.insert(entry.to_string(), entry);
    }

    fn code(&self) -> u8 {
        if self.critical {
            2
        } else if self.raised.is_empty() {
            0
        } else {
            1
        }
    }
}

fn unknown() -> Value {
    Value::from("unknown")
}

fn object(name: &str, reason: &str) -> Value {
    json!({"object": name, "error": reason})
}

#[derive(Default)]
struct Count {
    value: Option<u64>,
    incomplete: bool,
    overflowed: bool,
}

impl Count {
    fn add(&mut self, value: Option<u64>) -> bool {
        let Some(value) = value else {
            self.incomplete = true;
            return false;
        };
        match self.value.unwrap_or(0).checked_add(value) {
            Some(sum) => self.value = Some(sum),
            None => self.overflowed = true,
        }
        true
    }

    fn whole(&self) -> Option<u64> {
        self.value.filter(|_| !self.incomplete && !self.overflowed)
    }

    fn print_with(&self, show: impl Fn(u64) -> Value) -> Value {
        match self.value {
            _ if self.overflowed => unknown(),
            Some(value) => show(value),
            None if self.incomplete => unknown(),
            None => Value::from(0),
        }
    }

    fn print(&self) -> Value {
        self.print_with(Value::from)
    }
}

#[derive(Default)]
struct Build {
    roots: u64,
    hosts: BTreeSet<String>,
    hostless: bool,
    counts: [Count; COUNTS.len()],
    elapsed_ms: Count,
    pass: Count,
    unproven: Count,
    cpu: Count,
    capacity: Count,
    failures: BTreeMap<(String, String), Failure>,
    unkeyed: BTreeMap<(String, String, u64), Rc<Counts>>,
    findings: Vec<((String, String), Value)>,
}

#[derive(Default)]
struct Failure {
    count: Count,
    roots: BTreeSet<String>,
    rerun: Option<(String, u64, Rc<Counts>)>,
}

#[derive(Default)]
struct Listed {
    keys: BTreeSet<String>,
    other: u64,
    keyless: bool,
}

struct Seen<'a> {
    campaign: &'a str,
    flags: &'a mut Flags,
    row: Map<String, Value>,
}

impl Seen<'_> {
    fn flag(&mut self, flag: Flag, detail: Value) {
        self.flags.raise(Some(self.campaign), flag, detail);
    }

    fn put(&mut self, name: &str, value: Option<Value>) {
        if value.is_none() {
            self.flag(Flag::Missing, json!(name));
        }
        self.row
            .insert(name.to_owned(), value.unwrap_or_else(unknown));
    }

    fn sum(&mut self, name: &str, sum: &mut Count, value: Option<u64>) {
        if !sum.add(value) {
            self.flag(Flag::Missing, json!(name));
        }
        self.row
            .insert(name.to_owned(), value.map_or_else(unknown, Value::from));
    }
}

type Newest = (u64, String, Option<u64>);

pub(crate) struct Report<'a> {
    only: Option<&'a str>,
    now: u64,
    builds: BTreeMap<String, Build>,
    rows: Map<String, Value>,
    flags: Flags,
    newest: BTreeMap<String, Newest>,
}

impl<'a> Report<'a> {
    /// A report whose host section [`Report::finish`] judges at `now`.
    pub(crate) fn new(only: Option<&'a str>, now: u64) -> Self {
        Self {
            only,
            now,
            builds: BTreeMap::new(),
            rows: Map::new(),
            flags: Flags::default(),
            newest: BTreeMap::new(),
        }
    }

    pub(crate) fn add(&mut self, root: &Root) {
        let campaign = root.campaign.as_str();
        let flags = &mut self.flags;
        let envelope = match root.status.read() {
            Ok(envelope) => envelope,
            Err(reason) => {
                return flags.raise(Some(campaign), Flag::Missing, object(OBJECTS[0], reason));
            }
        };
        let build = match selected(campaign, envelope, self.only) {
            Ok(build) => build,
            Err(reason) => {
                return flags.raise(Some(campaign), Flag::Missing, object(OBJECTS[0], reason));
            }
        };
        let host = envelope.host.get();
        let written = envelope.written.get().copied();
        let stint_seconds = envelope
            .stint_seconds
            .get()
            .copied()
            .filter(|seconds| (1..=assignment::SECONDS_MAX).contains(seconds));
        for (name, present) in [
            ("host", host.is_some()),
            ("written", written.is_some()),
            ("stint_seconds", stint_seconds.is_some()),
        ] {
            if !present {
                flags.raise(Some(campaign), Flag::Missing, json!(name));
            }
        }
        if let (Some(host), Some(written)) = (host, written) {
            if written > root.observed.saturating_add(CLOCK_SKEW_S) {
                flags.raise(
                    Some(campaign),
                    Flag::Missing,
                    json!({"field": "written", "error": "ahead of the report's clock"}),
                );
            } else {
                let candidate = (written, campaign.to_owned(), stint_seconds);
                let newest = self
                    .newest
                    .entry(host.clone())
                    .or_insert_with(|| candidate.clone());
                if (candidate.0, &candidate.1) > (newest.0, &newest.1) {
                    *newest = candidate;
                }
            }
        }
        let (Some(build), Some(payload)) = (build, &root.payload) else {
            return;
        };
        let entry = self.builds.entry(build.to_owned()).or_default();
        let mut seen = Seen {
            campaign,
            flags,
            row: Map::new(),
        };
        seen.row.insert("build".into(), json!(build));
        entry.roots += 1;
        match host {
            Some(host) => {
                entry.hosts.insert(host.clone());
            }
            None => entry.hostless = true,
        }
        seen.put("host", host.map(|host| json!(host)));
        seen.put("stint", envelope.stint.get().map(|stint| json!(stint)));
        seen.put("written", written.map(Value::from));
        seen.put("stint_seconds", stint_seconds.map(Value::from));
        seen.sum("cpu_usec", &mut entry.cpu, envelope.cpu_usec.get().copied());
        seen.sum(
            "capacity_usec",
            &mut entry.capacity,
            envelope.capacity_usec.get().copied(),
        );
        let (profiles, counts) = sweep(&mut seen, entry, envelope);
        suspects(&mut seen, entry, build, profiles, counts, &payload.suspects);
        findings(&mut seen, entry, &payload.findings);
        let row = seen.row;
        self.rows.insert(campaign.to_owned(), Value::Object(row));
    }

    pub(crate) fn finish(mut self, records: Vec<Record>) -> (u8, Document) {
        let newest = self
            .newest
            .iter()
            .map(|(host, (written, _, stint))| (host.clone(), (*written, *stint)))
            .collect();
        let section = hosts::section(records, &newest, self.now);
        for detail in &section.unnamed {
            self.flags.raise(None, Flag::Missing, detail.clone());
        }
        for (instance, row) in &section.rows {
            let flag = match row.state {
                State::Missing => Flag::Missing,
                State::Silent => Flag::Silent,
                State::Unhealthy => Flag::Unhealthy,
                State::Degraded => Flag::Degraded,
                State::Stopped | State::Active => continue,
            };
            let detail = json!({"host": instance, "reasons": row.reasons});
            self.flags.raise(None, flag, detail);
        }
        if let Some(only) = self.only
            && !self.builds.contains_key(only)
        {
            self.flags.raise(
                None,
                Flag::Missing,
                json!({"build": only, "error": "no root names the build"}),
            );
        }
        let mut builds = BTreeMap::new();
        for (build, entry) in self.builds {
            let rendered = entry.render(&build, &mut self.flags);
            builds.insert(build, rendered);
        }
        let code = self.flags.code();
        let document = Document {
            builds,
            exit: code,
            flags: self.flags.raised.into_values().collect(),
            format: 1,
            host_counts: section.counts(),
            hosts: section.rows,
            roots: self.rows,
        };
        (code, document)
    }
}

/// The report's document. Each struct of it declares its fields in name
/// order, the order in which a [`Value`] prints an object's members. A
/// rerun serializes its root's one copy of the counts, so the document is
/// written from the fold's own data.
#[derive(Serialize)]
pub(crate) struct Document {
    builds: BTreeMap<String, BTreeMap<String, Member>>,
    exit: u8,
    flags: Vec<Value>,
    format: u8,
    host_counts: BTreeMap<&'static str, u64>,
    hosts: BTreeMap<String, hosts::Row>,
    roots: Map<String, Value>,
}

impl Document {
    /// The members the watch's decision step reads as JSON: `hosts`,
    /// `host_counts`, `flags` and each build's totals. The per-root rows
    /// and each build's failure groups, findings and keyless lines stay in
    /// the document alone, so the view's size follows the hosts, the flags
    /// and the builds; [`Document::failures`] lends the failure groups.
    pub(crate) fn decision_view(&self) -> Value {
        let mut builds = Map::new();
        for (build, members) in &self.builds {
            let mut totals = Map::new();
            for (name, member) in members {
                if let Member::Value(total) = member
                    && name != FINDINGS
                {
                    totals.insert(name.clone(), total.clone());
                }
            }
            builds.insert(build.clone(), Value::Object(totals));
        }
        json!({
            "builds": builds, "flags": self.flags, "host_counts": self.host_counts,
            "hosts": self.hosts,
        })
    }

    /// Each build's failure groups with the build's id, builds in id
    /// order. A group serializes to the object the document prints for it.
    pub(crate) fn failures(&self) -> impl Iterator<Item = (&str, &Group)> {
        self.builds.iter().flat_map(|(build, members)| {
            let groups = members.values().filter_map(|member| match member {
                Member::Failures(groups) => Some(groups),
                _ => None,
            });
            groups.flatten().map(move |group| (build.as_str(), group))
        })
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum Member {
    Value(Value),
    Failures(Vec<Group>),
    Unkeyed(Vec<Rerun>),
}

/// One failure group of a build: the roots that list the profile's key,
/// their summed count and the line to run again.
#[derive(Serialize)]
pub(crate) struct Group {
    count: Value,
    pub(crate) key: String,
    pub(crate) profile: String,
    rerun: Option<Rerun>,
    roots: BTreeSet<String>,
}

#[derive(Serialize)]
struct Rerun {
    campaign: String,
    #[serde(serialize_with = "shared")]
    counts: Rc<Counts>,
    profile: String,
    run: u64,
}

fn shared<S: Serializer>(counts: &Rc<Counts>, serializer: S) -> Result<S::Ok, S::Error> {
    counts.as_ref().serialize(serializer)
}

type Profiles = BTreeMap<String, Lenient<Totals>>;
/// A `sweep-status` member that maps each profile to an array of names.
trait Listing {
    /// The flag a nonempty array raises. The flag and the member share a
    /// name.
    const FLAG: Flag;
    /// The key of a profile's names in the flag's detail.
    const NAMES: &'static str;
    /// The word for one name in the `missing` detail of a malformed member.
    const NOUN: &'static str;
    /// The longest name the detail shows in full.
    const NAME_MAX: usize;
}

struct Events;

impl Listing for Events {
    const FLAG: Flag = Flag::Unreached;
    const NAMES: &'static str = "events";
    const NOUN: &'static str = "event";
    const NAME_MAX: usize = assignment::PROFILE_MAX;
}

struct Windows;

impl Listing for Windows {
    const FLAG: Flag = Flag::NoWindow;
    const NAMES: &'static str = "windows";
    const NOUN: &'static str = "window";
    const NAME_MAX: usize = KEY_MAX;
}

/// `NameLists` stores the nonempty effective arrays of one member in
/// profile order. Each member of a root has its own budget of [`ELEMENTS`]
/// names, and a repeated key contributes only its last value to it.
/// The raw values borrow a serde_json slice or string. A source that
/// cannot lend those spans returns a document error.
struct NameLists<K>(Vec<Value>, PhantomData<K>);

impl<K: Listing> Shape for NameLists<K> {
    fn of_map<'de, A: MapAccess<'de>>(map: A) -> Result<Option<Self>, A::Error> {
        let Some(effective) = crate::lenient::entries::<&RawValue, _>(map)? else {
            return Ok(None);
        };
        let mut rows = Vec::new();
        let mut remaining = ELEMENTS;
        for (profile, raw) in effective {
            if !raw.get().starts_with('[') {
                return Ok(None);
            }
            let Ok(names) = serde_json::Deserializer::from_str(raw.get()).deserialize_seq(Names {
                room: remaining,
                max: K::NAME_MAX,
            }) else {
                return Ok(None);
            };
            remaining -= names.len();
            if !names.is_empty() {
                rows.push(Value::Object(Map::from_iter([
                    (
                        "profile".into(),
                        named(&profile, assignment::PROFILE_MAX).into(),
                    ),
                    (K::NAMES.into(), Value::Array(names)),
                ])));
            }
        }
        Ok(Some(Self(rows, PhantomData)))
    }
}

/// When `serde_json` cannot decode a syntactically valid value of the
/// member, such as a number past the `f64` range, only that member becomes
/// [`Lenient::Other`]. Invalid JSON syntax or invalid UTF-8 fails the whole
/// document.
fn name_lists<'de, D: Deserializer<'de>, K: Listing>(
    deserializer: D,
) -> Result<Lenient<NameLists<K>>, D::Error> {
    let raw = <&RawValue>::deserialize(deserializer)?;
    Ok(serde_json::from_str(raw.get()).unwrap_or(Lenient::Other))
}

fn listed<K: Listing>(seen: &mut Seen<'_>, lists: &Lenient<NameLists<K>>) {
    match lists {
        Lenient::Typed(NameLists(rows, _)) if !rows.is_empty() => {
            seen.flag(K::FLAG, Value::Array(rows.clone()));
        }
        Lenient::Other => {
            let error = format!(
                "expected at most {ELEMENTS} distinct profiles mapped to arrays of {} names, with at most {ELEMENTS} names per array and in total for this root",
                K::NOUN
            );
            seen.flag(
                Flag::Missing,
                json!({"field": K::FLAG.name(), "error": error}),
            );
        }
        _ => {}
    }
}

/// `Names` formats names with [`named`] as it decodes one array. `room`
/// is the rest of the member's budget in the root that supplied the
/// array. [`named`] shows names of length `max` or less in full.
struct Names {
    room: usize,
    max: usize,
}

impl<'de> Visitor<'de> for Names {
    type Value = Vec<Value>;

    fn expecting(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_str("an array of names within the root's remaining budget")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut names = Vec::new();
        while names.len() < self.room {
            let Some(name) = seq.next_element::<String>()? else {
                return Ok(names);
            };
            names.push(named(&name, self.max).into());
        }
        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom("too many names"));
        }
        Ok(names)
    }
}

fn names(list: &[Lenient<String>]) -> Option<Vec<Value>> {
    list.iter()
        .map(|entry| {
            entry
                .get()
                .map(|name| Value::String(named(name, assignment::PROFILE_MAX)))
        })
        .collect()
}

/// Adds the root's sweep sums and returns its profiles and its counts.
/// The counts are those whose every name is printable and whose every
/// value is a whole number.
fn sweep<'e>(
    seen: &mut Seen<'_>,
    entry: &mut Build,
    envelope: &'e Envelope,
) -> (Option<&'e Profiles>, Option<&'e Numbers>) {
    let Some(swept) = envelope.sweep_status.get() else {
        seen.flag(Flag::Missing, object("sweep_status", "absent or null"));
        for ((name, _), count) in COUNTS.iter().zip(&mut entry.counts) {
            count.add(None);
            seen.row.insert((*name).into(), unknown());
        }
        for count in [&mut entry.elapsed_ms, &mut entry.pass, &mut entry.unproven] {
            count.add(None);
        }
        for name in ["elapsed_s", "pass", "alarmed"] {
            seen.row.insert(name.into(), unknown());
        }
        return (None, None);
    };
    for ((name, read), count) in COUNTS.iter().zip(&mut entry.counts) {
        seen.sum(name, count, read(swept));
    }
    let elapsed = swept
        .elapsed_s
        .get()
        .copied()
        .filter(|seconds| seconds.is_finite() && *seconds >= 0.0 && *seconds < 1e15);
    if !entry
        .elapsed_ms
        .add(elapsed.map(|seconds| (seconds * 1000.0).round() as u64))
    {
        seen.flag(Flag::Missing, json!("elapsed_s"));
    }
    seen.row.insert(
        "elapsed_s".into(),
        elapsed.map_or_else(unknown, Value::from),
    );
    let alarmed = !swept.alarm.is_none();
    if alarmed {
        let detail = swept
            .alarm
            .get()
            .map_or_else(|| json!("a value that is not text"), |alarm| kept(alarm));
        seen.flag(Flag::Alarm, detail);
    }
    let unnamed = json!({
        "field": "no_pass",
        "error": format!("not an array of at most {ELEMENTS} profile names"),
    });
    match &swept.no_pass {
        Lenient::Typed(profiles) if !profiles.is_empty() => match names(profiles) {
            Some(names) => seen.flag(Flag::NoPass, Value::Array(names)),
            None => seen.flag(Flag::Missing, unnamed),
        },
        Lenient::Other => seen.flag(Flag::Missing, unnamed),
        _ => {}
    }
    listed(seen, &swept.unreached);
    listed(seen, &swept.no_window);
    let partition = if alarmed {
        &mut entry.unproven
    } else {
        &mut entry.pass
    };
    seen.sum("pass", partition, swept.pass.get().copied());
    seen.row.insert("alarmed".into(), json!(alarmed));
    let profiles = swept.profiles.get();
    if profiles.is_none() {
        seen.flag(Flag::Missing, json!("profiles"));
    }
    let counts = swept.counts.get().filter(|counts| whole(counts));
    if counts.is_none() {
        seen.flag(Flag::Missing, json!("counts"));
    }
    (profiles, counts)
}

/// Whether `counts` holds whole numbers under printable names of at most
/// one argument's length, whose lengths sum to at most the assignment's
/// argument budget.
fn whole(counts: &Numbers) -> bool {
    counts.keys().map(String::len).sum::<usize>() <= assignment::ARGUMENTS_MAX
        && counts.iter().all(|(name, count)| {
            name.len() <= assignment::ARGUMENT_MAX && printable(name) && count.get().is_some()
        })
}

fn counted(profiles: Option<&Profiles>, profile: &str, key: &str) -> Option<u64> {
    let keys = profiles?.get(profile)?.get()?.suspect_keys.get()?;
    keys.get(key).map_or(Some(0), |count| count.get().copied())
}

fn printable(text: &str) -> bool {
    text.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

/// Folds the lines of a root's list that carry the root's campaign, build
/// and `counts`. One root adds at most [`ELEMENTS`] keys to the build's
/// failures and [`ELEMENTS`] keyless lines.
fn suspects(
    seen: &mut Seen<'_>,
    entry: &mut Build,
    build: &str,
    profiles: Option<&Profiles>,
    counts: Option<&Numbers>,
    list: &Object<Vec<u8>>,
) {
    let name = OBJECTS[1];
    let bytes = match list.read() {
        Ok(bytes) => bytes,
        Err(reason) => return seen.flag(Flag::Missing, object(name, reason)),
    };
    let Some(counts) = counts else {
        return;
    };
    let campaign = seen.campaign;
    let mut listed: BTreeMap<String, Listed> = BTreeMap::new();
    let (mut unreadable, mut foreign, mut keyless, mut past) = (0u64, 0u64, 0u64, 0u64);
    let (mut keys, mut unkeyed) = (0, 0);
    // A root binds one set of counts, so its lines share one copy.
    let mut copy: Option<Rc<Counts>> = None;
    let mut shared = || {
        let numbers = counts
            .iter()
            .filter_map(|(name, count)| Some((name.clone(), *count.get()?)));
        Rc::clone(copy.get_or_insert_with(|| Rc::new(numbers.collect())))
    };
    // A line ends with its newline, so the bytes after the last newline
    // are an unfinished record.
    let mut lines = bytes.split(|byte| *byte == b'\n');
    if lines.next_back().is_some_and(|tail| !tail.is_empty()) {
        let reason = "ends in a record without its newline";
        seen.flag(Flag::Missing, object(name, reason));
    }
    for text in lines {
        let line = match serde_json::from_slice::<Lenient<Line>>(text) {
            Ok(Lenient::Typed(line))
                if line.profile.len() <= assignment::PROFILE_MAX
                    && printable(&line.profile)
                    && line.key.as_ref().is_none_or(|key| key.len() <= KEY_MAX)
                    && line.counts.get().is_some_and(whole) =>
            {
                line
            }
            _ => {
                unreadable += 1;
                continue;
            }
        };
        if line.campaign != campaign || line.build != build || line.counts.get() != Some(counts) {
            foreign += 1;
            continue;
        }
        let Line {
            profile, run, key, ..
        } = line;
        let Some(key) = key else {
            keyless += 1;
            let line = (campaign.to_owned(), profile, run);
            if entry.unkeyed.contains_key(&line) {
                continue;
            }
            if unkeyed == ELEMENTS {
                past += 1;
                continue;
            }
            unkeyed += 1;
            listed.entry(line.1.clone()).or_default().keyless = true;
            entry.unkeyed.insert(line, shared());
            continue;
        };
        let known = listed
            .get(&profile)
            .is_some_and(|shown| shown.keys.contains(&key));
        if !known && keys == ELEMENTS {
            past += 1;
            continue;
        }
        let shown = listed.entry(profile.clone()).or_default();
        if key == OTHER {
            shown.other += 1;
        }
        if !known {
            keys += 1;
            shown.keys.insert(key.clone());
        }
        let count = counted(profiles, &profile, &key);
        let failure = entry.failures.entry((profile.clone(), key)).or_default();
        if failure.roots.insert(campaign.to_owned()) && !failure.count.add(count) {
            seen.flag(
                Flag::Missing,
                json!(format!("profiles.{profile}.suspect_keys")),
            );
        }
        if failure
            .rerun
            .as_ref()
            .is_none_or(|rerun| (campaign, run) < (rerun.0.as_str(), rerun.1))
        {
            failure.rerun = Some((campaign.to_owned(), run, shared()));
        }
    }
    let bound =
        format!("lines pass the {ELEMENTS} keys or the {ELEMENTS} keyless lines one root lists");
    for (lines, what) in [
        (unreadable, "lines do not parse as suspect lines"),
        (foreign, "lines name another campaign, build or counts"),
        (keyless, "lines carry no key"),
        (past, bound.as_str()),
    ] {
        if lines > 0 {
            seen.flag(Flag::Missing, object(name, &format!("{lines} {what}")));
        }
    }
    for (profile, totals) in profiles.into_iter().flatten() {
        let shown_profile = named(profile, assignment::PROFILE_MAX);
        let Some(keys) = totals.get().and_then(|totals| totals.suspect_keys.get()) else {
            seen.flag(
                Flag::Missing,
                json!(format!("profiles.{shown_profile}.suspect_keys")),
            );
            continue;
        };
        let shown = listed.get(profile);
        // Keyless lines and lines past the bound belong to keys this
        // list shows in part.
        let partial = past > 0 || shown.is_some_and(|shown| shown.keyless);
        let (mut mistyped, mut unlisted) = (Vec::new(), Vec::new());
        for (key, count) in keys {
            let Some(&count) = count.get() else {
                mistyped.push(key);
                continue;
            };
            if key == OTHER {
                let lines = shown.map_or(0, |shown| shown.other);
                let limit = if partial {
                    EXAMPLES
                } else {
                    lines.min(EXAMPLES)
                };
                if count > limit {
                    seen.flag(
                        Flag::Other,
                        json!({"profile": shown_profile, "counted": count, "listed": lines}),
                    );
                }
            } else if count > 0 && !partial && !shown.is_some_and(|shown| shown.keys.contains(key))
            {
                unlisted.push(key);
            }
        }
        // Grouping a profile's keys by error limits the copies of its
        // name in the flags to one per error.
        for (keys, error) in [
            (mistyped, "the count is not a whole number"),
            (unlisted, "counted with no listed line"),
        ] {
            if let Some(first) = keys.first() {
                let first = named(first, KEY_MAX);
                seen.flag(
                    Flag::Missing,
                    json!({"profile": shown_profile, "keys": keys.len(), "first": first, "error": error}),
                );
            }
        }
    }
}

fn findings(seen: &mut Seen<'_>, entry: &mut Build, findings: &Object<Findings>) {
    let name = OBJECTS[2];
    let document = match findings.read() {
        Ok(document) => document,
        Err(reason) => return seen.flag(Flag::Missing, object(name, reason)),
    };
    let Some(rows) = document.findings.get() else {
        let reason = format!("holds no array of at most {ELEMENTS} findings");
        return seen.flag(Flag::Missing, object(name, &reason));
    };
    for row in rows {
        let Some(row) = row.get() else {
            seen.flag(Flag::Missing, object(name, "a row is not an object"));
            continue;
        };
        let id = row.id.get();
        if id.is_none() {
            seen.flag(Flag::Missing, object(name, "a row without a text id"));
        }
        let id = id.map_or_else(unknown, |id| kept(id));
        let mut out = json!({"root": seen.campaign, "id": id});
        if row.held.is_none() {
            let resolved = row.resolved.get().copied();
            let decision = row.dispositions.get().map(|dispositions| {
                dispositions.last().map(|latest| {
                    latest
                        .get()
                        .and_then(|latest| latest.decision.get())
                        .map(|decision| kept(decision))
                })
            });
            if resolved.is_none() || !matches!(decision, Some(None | Some(Some(_)))) {
                seen.flag(
                    Flag::Missing,
                    object(
                        name,
                        "a row without resolved, dispositions or a latest decision",
                    ),
                );
            }
            out["resolved"] = resolved.map_or_else(unknown, Value::from);
            out["disposition"] = match decision {
                Some(None) => Value::Null,
                Some(Some(Some(decision))) => decision,
                _ => unknown(),
            };
        } else {
            let code = row.held_code.get().map(|code| kept(code));
            if code.is_none() {
                seen.flag(
                    Flag::Missing,
                    object(name, "a held row without a text held_code"),
                );
            }
            let code = code.unwrap_or_else(unknown);
            seen.flag(Flag::Held, json!({"id": out["id"], "held_code": code}));
            out["held"] = row.held.get().map_or_else(unknown, |held| kept(held));
            out["held_code"] = code;
            out["resolved"] = unknown();
            out["disposition"] = Value::Null;
        }
        let order = (seen.campaign.to_owned(), out["id"].to_string());
        entry.findings.push((order, out));
    }
}

impl Build {
    fn render(mut self, build: &str, flags: &mut Flags) -> BTreeMap<String, Member> {
        let overflow = |flags: &mut Flags, field: Value| {
            flags.raise(
                None,
                Flag::Missing,
                json!({"build": build, "field": field, "error": "the build's sum passes 2^64 - 1"}),
            );
        };
        let mut out = Map::new();
        out.insert("roots".into(), json!(self.roots));
        out.insert(
            "hosts".into(),
            if self.hostless {
                unknown()
            } else {
                json!(self.hosts.len())
            },
        );
        let named = COUNTS
            .iter()
            .map(|(name, _)| *name)
            .zip(&self.counts)
            .chain([
                ("elapsed_s", &self.elapsed_ms),
                ("pass", &self.pass),
                ("unproven", &self.unproven),
                ("cpu_usec", &self.cpu),
                ("capacity_usec", &self.capacity),
            ]);
        for (name, count) in named {
            if count.overflowed {
                overflow(flags, json!(name));
            }
            let printed = if name == "elapsed_s" {
                count.print_with(|ms| Value::from(ms as f64 / 1000.0))
            } else {
                count.print()
            };
            out.insert(name.into(), printed);
        }
        out.insert(
            "runs_per_s".into(),
            match (self.counts[RUNS].whole(), self.elapsed_ms.whole()) {
                (Some(runs), Some(ms)) if ms > 0 => Value::from(runs as f64 * 1000.0 / ms as f64),
                _ => unknown(),
            },
        );
        out.insert(
            "cpu_share".into(),
            status::share(self.cpu.whole(), self.capacity.whole())
                .map_or_else(unknown, Value::from),
        );
        let mut failures = Vec::new();
        for ((profile, key), failure) in self.failures {
            if failure.count.overflowed {
                overflow(flags, json!({"profile": profile, "key": key}));
            }
            let rerun = failure.rerun.map(|(campaign, run, counts)| Rerun {
                campaign,
                counts,
                profile: profile.clone(),
                run,
            });
            failures.push(Group {
                count: failure.count.print(),
                key,
                profile,
                rerun,
                roots: failure.roots,
            });
        }
        let unkeyed = self.unkeyed.into_iter();
        let unkeyed = unkeyed.map(|((campaign, profile, run), counts)| Rerun {
            campaign,
            counts,
            profile,
            run,
        });
        self.findings.sort_by(|one, two| one.0.cmp(&two.0));
        let findings: Vec<Value> = self.findings.into_iter().map(|(_, row)| row).collect();
        out.insert(FINDINGS.into(), findings.into());
        let mut out: BTreeMap<String, Member> = out
            .into_iter()
            .map(|(name, value)| (name, Member::Value(value)))
            .collect();
        out.insert(FAILURES.into(), Member::Failures(failures));
        out.insert(UNKEYED.into(), Member::Unkeyed(unkeyed.collect()));
        out
    }
}

/// Exit codes are listed in the guide's `report` section.
pub fn run(bucket: &str, only: Option<&str>) -> u8 {
    if let Err(error) = signal::install() {
        eprintln!("sim-host report: signal handlers: {error}");
        return 3;
    }
    let bucket = Bucket::new(bucket);
    let scratch = match file::fresh_dir(&std::env::temp_dir(), "sim-host-report-") {
        Ok(scratch) => scratch,
        Err(error) => {
            eprintln!("sim-host report: a scratch directory: {error}");
            return 3;
        }
    };
    let now = host::now_s();
    let mut report = Report::new(only, now);
    let fetched = fetch(&bucket, &scratch, only, |root| report.add(root))
        .and_then(|()| hosts::fetch(&bucket, &scratch, LISTED, now));
    let _ = std::fs::remove_dir_all(&scratch);
    let records = match fetched {
        Ok(records) => records,
        Err(error) => {
            eprintln!("sim-host report: {error}");
            return 3;
        }
    };
    let (code, document) = report.finish(records);
    let mut out = BufWriter::new(std::io::stdout().lock());
    let written = serde_json::to_writer_pretty(&mut out, &document)
        .map_err(std::io::Error::from)
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush());
    if let Err(error) = written {
        eprintln!("sim-host report: standard output: {error}");
        return 3;
    }
    code
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
