//! The snapshot a run reads after its caller check: one line per shard of the package at one cut and at
//! most one line per host, every time within the snapshot's age before the read and none after it; and
//! `roles.json`, built from it at the cut.

use std::collections::{BTreeMap, BTreeSet};

use super::constants::health;
use super::forms::instance_id;
use super::inputs::read_bytes;
use super::number::Number;
use super::operator::Operator;
use super::words::{sentence, sorted_numbers, sorted_texts};
use crate::gameday::{
    Names, Refusal, Scalar, Schema, VERSION_FIELDS, conform, finite, layout, need, parsed,
};
use crate::json::{Object, Value};
use crate::text::Text;

/// A shard line: the shard, its read time and its version.
const SHARD_LINE: Schema = Schema::Object(&[
    ("shard", Schema::scalar(Scalar::Shard)),
    ("time", Schema::scalar(Scalar::Time)),
    VERSION_FIELDS[0],
    VERSION_FIELDS[1],
    VERSION_FIELDS[2],
    VERSION_FIELDS[3],
    VERSION_FIELDS[4],
]);

/// A host's latest report.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Report {
    time: Number,
    healthy: bool,
}

impl Report {
    pub fn time(&self) -> Number {
        self.time
    }

    pub fn healthy(&self) -> bool {
        self.healthy
    }
}

/// A host line: the host's instance and its latest report, or none.
#[derive(Clone, Debug, PartialEq)]
pub struct HostLine {
    instance: Text,
    report: Option<Report>,
}

impl HostLine {
    /// The host's instance, an instance ID.
    pub fn instance(&self) -> &Text {
        &self.instance
    }

    pub fn report(&self) -> Option<Report> {
        self.report
    }
}

/// A snapshot that [`read_snapshot`] admitted.
#[derive(Clone, Debug)]
pub struct Snapshot {
    records: Object,
    reports: BTreeMap<Text, HostLine>,
    cut: Number,
    oldest: Number,
}

impl Snapshot {
    /// `{shard: version}` in the order of `shards.jsonl`, the version's keys in the layout's order.
    pub fn records(&self) -> &Object {
        &self.records
    }

    /// `{host: line}` of `hosts.jsonl`.
    pub fn reports(&self) -> &BTreeMap<Text, HostLine> {
        &self.reports
    }

    /// The shard lines' one read time, as the first line that holds it writes it.
    pub fn cut(&self) -> Number {
        self.cut
    }

    /// The snapshot's earliest time among the cut and the host reports.
    pub fn oldest(&self) -> Number {
        self.oldest
    }
}

/// Numbers no two of which are equal; of equal values the first stays, as a Python set keeps it.
#[derive(Default)]
struct Distinct(Vec<Number>);

impl Distinct {
    fn add(&mut self, number: Number) {
        if !self.0.contains(&number) {
            self.0.push(number);
        }
    }

    /// The least, or `None` for none.
    fn least(&self) -> Option<Number> {
        self.0
            .iter()
            .copied()
            .reduce(|least, number| if number < least { number } else { least })
    }
}

/// `read_snapshot` reads `shards.jsonl` and then `hosts.jsonl` of the operator's snapshot directory,
/// each at most `limit` bytes, at the wall time `now`, for the package `package` and its `names`.
///
/// # Errors
///
/// The first refusal in this order. For each shard line: off its shape; a repeated shard; a time before
/// `now` less the snapshot's age bound or after `now`. Then a shard of the package with no line;
/// lines of more than one time; a cut before the baseline window starts. For each host line: keys other
/// than `host`, `instance` and `report`; a host outside the package or repeated; an instance that is no
/// ID; a report that is neither null nor `{time, healthy}`, or whose time lies outside the same bounds.
/// Then two hosts that name one instance; a target host whose line lacks the target instance; an owned
/// shard with no witness key; a witness key of a shard the target does not own. A file's read refuses
/// as [`read_bytes`] and [`parsed`] do.
///
/// # Panics
///
/// When `package` or `names` is other than the package check made them.
pub fn read_snapshot(
    operator: &Operator,
    package: &Object,
    names: &Names,
    now: f64,
    limit: u64,
) -> Result<Snapshot, Refusal> {
    let now = Number::from(now);
    let oldest = now.minus(operator.snapshot_max_age_seconds());
    let fresh = |t: Number, what: Text| {
        need(oldest <= t && t <= now, || {
            sentence!(
                what,
                " ",
                t,
                " lies outside [",
                oldest,
                ", ",
                now,
                "]: the snapshot is stale or ahead"
            )
        })
        .map(|()| t)
    };
    let lines = |name: &str| -> Result<Vec<Value>, Refusal> {
        let what = Text::from(name);
        let data = read_bytes(&operator.snapshot().join(name), &what, limit)?;
        match parsed(&data, &what)? {
            Value::Array(lines) => Ok(lines),
            _ => unreachable!("a .jsonl file reads as a list of lines"),
        }
    };
    let (mut records, mut times) = (Object::new(), Distinct::default());
    for (at, row) in lines("shards.jsonl")?.iter().enumerate() {
        let what = sentence!("shards.jsonl line ", (at + 1).to_string());
        conform(row, &SHARD_LINE, &what, names)?;
        let Value::Object(row) = row else {
            unreachable!("the schema made a shard line an object")
        };
        let shard = text(row.get("shard"));
        need(member(&records, shard).is_none(), || {
            sentence!(what, " repeats shard ", shard)
        })?;
        times.add(fresh(number(row.get("time")), sentence!(what, " time"))?);
        let mut version = Object::new();
        for (key, _) in VERSION_FIELDS {
            version.insert(key, row.get(key).cloned().unwrap_or(Value::Null));
        }
        records.insert(shard.clone(), Value::Object(version));
    }
    let shards = texts(package.get("shards"));
    let missing: BTreeSet<&Text> = shards
        .iter()
        .copied()
        .filter(|shard| member(&records, shard).is_none())
        .collect();
    need(missing.is_empty(), || {
        sentence!(
            "shards.jsonl misses shards ",
            sorted_texts(missing.iter().copied())
        )
    })?;
    need(times.0.len() == 1, || {
        sentence!(
            "shards.jsonl holds read times ",
            sorted_numbers(&times.0),
            ", not one cut"
        )
    })?;
    let cut = times.0[0];
    let mut earliest = Distinct(times.0);
    need(window_start(package) <= cut, || {
        sentence!(
            "shards.jsonl's cut ",
            cut,
            " lies before the baseline window starts"
        )
    })?;
    let hosts = names
        .get("host")
        .expect("the package check names the hosts");
    let mut reports = BTreeMap::new();
    for (at, row) in lines("hosts.jsonl")?.iter().enumerate() {
        let what = sentence!("hosts.jsonl line ", (at + 1).to_string());
        let row = match row {
            Value::Object(row)
                if row.len() == 3
                    && ["host", "instance", "report"]
                        .iter()
                        .all(|key| row.get(key).is_some()) =>
            {
                row
            }
            _ => {
                return Err(Refusal::new(sentence!(
                    what,
                    " holds other keys than host, instance and report"
                )));
            }
        };
        let host = match row.get("host") {
            Some(Value::String(host)) if hosts.contains(host) && !reports.contains_key(host) => {
                host
            }
            _ => {
                return Err(Refusal::new(sentence!(
                    what,
                    " names no host of the package or repeats one"
                )));
            }
        };
        let instance = instance_id(field(row, "instance"), &sentence!(what, " instance"))?;
        let report = match field(row, "report") {
            Value::Null => None,
            report => {
                let report = match report {
                    Value::Object(report)
                        if report.len() == 2
                            && report.get("time").is_some_and(finite)
                            && matches!(report.get("healthy"), Some(Value::Bool(_))) =>
                    {
                        Report {
                            time: number(report.get("time")),
                            healthy: matches!(report.get("healthy"), Some(Value::Bool(true))),
                        }
                    }
                    _ => {
                        return Err(Refusal::new(sentence!(
                            what,
                            " report is neither null nor {time, healthy}"
                        )));
                    }
                };
                earliest.add(fresh(report.time, sentence!(what, " report time"))?);
                Some(report)
            }
        };
        reports.insert(host.clone(), HostLine { instance, report });
    }
    let named: BTreeSet<&Text> = reports.values().map(HostLine::instance).collect();
    need(named.len() == reports.len(), || {
        sentence!("hosts.jsonl names one instance twice")
    })?;
    let target = object(package.get("target"));
    let (target_host, target_instance) = (text(target.get("host")), text(target.get("instance")));
    let named = reports
        .get(target_host)
        .is_some_and(|line| line.instance == *target_instance);
    need(named, || {
        sentence!("hosts.jsonl does not name the package's target instance for the target host")
    })?;
    let owned: BTreeSet<&Text> = shards
        .iter()
        .copied()
        .filter(|shard| is_text(owner(&records, shard), target_host))
        .collect();
    let keyed: BTreeSet<&Text> = list(package.get("witness"))
        .iter()
        .map(|entry| text(object(Some(entry)).get("shard")))
        .collect();
    need(owned.is_subset(&keyed), || {
        sentence!(
            "owned shards ",
            sorted_texts(owned.difference(&keyed).copied()),
            " have no witness key in the package, so the judge would refuse the run's evidence"
        )
    })?;
    need(keyed.is_subset(&owned), || {
        sentence!(
            "the package's witness keys name shards ",
            sorted_texts(keyed.difference(&owned).copied()),
            " the target does not own, so the judge would refuse the run's evidence"
        )
    })?;
    let oldest = earliest.least().expect("the cut is one of the times");
    Ok(Snapshot {
        records,
        reports,
        cut,
        oldest,
    })
}

/// A status of an instance that `build_roles` reads: the instance's state.
pub trait InstanceState {
    fn state(&self) -> &Text;
}

/// `build_roles` is `roles.json` at the snapshot's cut `cut`: the package's digest, the time, the
/// version of each shard, and in `standbys` each standby host of a shard the target owns, other than
/// the target, whose snapshot line names an instance `states` holds, with that instance's state and the
/// word of its host's report.
///
/// # Errors
///
/// The mark off the judge's layout under `names`, as `conform` refuses it.
///
/// # Panics
///
/// When `records` lacks a shard of `package`: the caller passes the records [`read_snapshot`] read.
pub fn build_roles<S: InstanceState>(
    package: &Object,
    names: &Names,
    package_sha256: &str,
    records: &Object,
    reports: &BTreeMap<Text, HostLine>,
    states: &BTreeMap<Text, S>,
    cut: Number,
) -> Result<Value, Refusal> {
    let target = text(object(package.get("target")).get("host"));
    let mut standbys = Object::new();
    for shard in texts(package.get("shards")) {
        let version = object(member(records, shard));
        let Some(Value::String(host)) = version.get("standby") else {
            continue;
        };
        let Some(line) = reports.get(host) else {
            continue;
        };
        let Some(state) = states.get(&line.instance) else {
            continue;
        };
        if is_text(owner(records, shard), target) && host != target {
            let mut standby = Object::new();
            standby.insert("instance", Value::String(line.instance.clone()));
            standby.insert("instance_state", Value::String(state.state().clone()));
            standby.insert(
                "host_report",
                Value::String(Text::from(health(line.report.map(|report| report.healthy)))),
            );
            standbys.insert(host.clone(), Value::Object(standby));
        }
    }
    let mut roles = Object::new();
    roles.insert("package_sha256", Value::String(Text::from(package_sha256)));
    roles.insert("time", cut.value());
    roles.insert("shards", Value::Object(records.clone()));
    roles.insert("standbys", Value::Object(standbys));
    let roles = Value::Object(roles);
    let (schema, _) = layout("injection/roles.json").expect("the layout holds roles.json");
    conform(&roles, schema, &Text::from("injection/roles.json"), names)?;
    Ok(roles)
}

fn owner<'a>(records: &'a Object, shard: &Text) -> &'a Value {
    object(member(records, shard))
        .get("owner")
        .unwrap_or(&Value::Null)
}

/// The member `key` of `object`, whatever code points the key holds.
fn member<'a>(object: &'a Object, key: &Text) -> Option<&'a Value> {
    object
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

fn is_text(value: &Value, text: &Text) -> bool {
    matches!(value, Value::String(found) if found == text)
}

fn window_start(package: &Object) -> Number {
    number(object(package.get("baseline")).get("start"))
}

fn field<'a>(row: &'a Object, key: &str) -> &'a Value {
    row.get(key).unwrap_or(&Value::Null)
}

fn number(value: Option<&Value>) -> Number {
    value
        .and_then(Number::of)
        .unwrap_or_else(|| panic!("the check made {value:?} a finite number"))
}

fn text(value: Option<&Value>) -> &Text {
    match value {
        Some(Value::String(text)) => text,
        _ => panic!("the check made {value:?} a string"),
    }
}

fn object(value: Option<&Value>) -> &Object {
    match value {
        Some(Value::Object(object)) => object,
        _ => panic!("the check made {value:?} an object"),
    }
}

fn list(value: Option<&Value>) -> &[Value] {
    match value {
        Some(Value::Array(items)) => items,
        _ => panic!("the check made {value:?} a list"),
    }
}

fn texts(value: Option<&Value>) -> Vec<&Text> {
    list(value).iter().map(|item| text(Some(item))).collect()
}
