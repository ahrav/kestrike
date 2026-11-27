//! The snapshot a run reads after its caller check: one line per shard of the package at one cut and at
//! most one line per host, every time within the snapshot's age before the read and none after it; and
//! `roles.json`, built from it at the cut.

use std::collections::{BTreeMap, BTreeSet};

use super::checked::{get, list, member, number_at, object, object_at, text, text_at};
use super::constants::health;
use super::forms::instance_id;
use super::inputs::read_bytes;
use super::number::Number;
use super::operator::Operator;
use super::replies::Status;
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
#[derive(Clone, Default)]
struct Distinct(Vec<Number>);

impl Distinct {
    fn add(&mut self, number: Number) {
        if !self.0.contains(&number) {
            self.0.push(number);
        }
    }

    fn as_slice(&self) -> &[Number] {
        &self.0
    }

    /// The least, or `None` for none.
    fn least(&self) -> Option<Number> {
        self.0
            .iter()
            .copied()
            .reduce(|least, number| if number < least { number } else { least })
    }
}

/// The bounds a time of the snapshot lies in: from `now` less the age bound to `now`.
#[derive(Clone, Copy)]
struct Fresh {
    oldest: Number,
    now: Number,
}

impl Fresh {
    /// `t` when it lies in the bounds, else the refusal that names it by `what`.
    fn check(self, t: Number, what: Text) -> Result<Number, Refusal> {
        let Self { oldest, now } = self;
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
        })?;
        Ok(t)
    }
}

/// The lines of the snapshot file `name`, each a decoded value.
fn lines(operator: &Operator, name: &str, limit: u64) -> Result<Vec<Value>, Refusal> {
    let what = Text::from(name);
    let data = read_bytes(&operator.snapshot().join(name), &what, limit)?;
    Ok(list(&parsed(&data, &what)?).to_vec())
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
    now: Number,
    limit: u64,
) -> Result<Snapshot, Refusal> {
    let fresh = Fresh {
        oldest: now.minus(operator.snapshot_max_age_seconds()),
        now,
    };
    let (records, cut) = shard_lines(operator, package, names, fresh, limit)?;
    let mut earliest = Distinct::default();
    earliest.add(cut);
    let reports = host_lines(operator, names, fresh, &mut earliest, limit)?;
    let target = object_at(package, "target");
    let (target_host, target_instance) = (text_at(target, "host"), text_at(target, "instance"));
    let named = reports
        .get(target_host)
        .is_some_and(|line| line.instance == *target_instance);
    need(named, || {
        sentence!("hosts.jsonl does not name the package's target instance for the target host")
    })?;
    let shards: Vec<&Text> = list(get(package, "shards")).iter().map(text).collect();
    let owned: BTreeSet<&Text> = shards
        .iter()
        .copied()
        .filter(|shard| is_text(owner(&records, shard), target_host))
        .collect();
    let keyed: BTreeSet<&Text> = list(get(package, "witness"))
        .iter()
        .map(|entry| text_at(object(entry), "shard"))
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

/// The shard lines as `{shard: version}` in line order and their one read time.
fn shard_lines(
    operator: &Operator,
    package: &Object,
    names: &Names,
    fresh: Fresh,
    limit: u64,
) -> Result<(Object, Number), Refusal> {
    let (mut records, mut times) = (Object::new(), Distinct::default());
    for (at, row) in lines(operator, "shards.jsonl", limit)?.iter().enumerate() {
        let what = sentence!("shards.jsonl line ", (at + 1).to_string());
        conform(row, &SHARD_LINE, &what, names)?;
        let row = object(row);
        let shard = text_at(row, "shard");
        need(member(&records, shard).is_none(), || {
            sentence!(what, " repeats shard ", shard)
        })?;
        times.add(fresh.check(number_at(row, "time"), sentence!(what, " time"))?);
        let mut version = Object::new();
        for (key, _) in VERSION_FIELDS {
            version.insert(key, get(row, key).clone());
        }
        records.insert(shard.clone(), Value::Object(version));
    }
    let missing: BTreeSet<&Text> = list(get(package, "shards"))
        .iter()
        .map(text)
        .filter(|shard| member(&records, shard).is_none())
        .collect();
    need(missing.is_empty(), || {
        sentence!(
            "shards.jsonl misses shards ",
            sorted_texts(missing.iter().copied())
        )
    })?;
    need(times.as_slice().len() == 1, || {
        sentence!(
            "shards.jsonl holds read times ",
            sorted_numbers(times.as_slice()),
            ", not one cut"
        )
    })?;
    let cut = times.as_slice()[0];
    need(
        number_at(object_at(package, "baseline"), "start") <= cut,
        || {
            sentence!(
                "shards.jsonl's cut ",
                cut,
                " lies before the baseline window starts"
            )
        },
    )?;
    Ok((records, cut))
}

/// The host lines as `{host: line}`, each report's time added to `earliest`; two hosts that name one
/// instance are refused once every line is read.
fn host_lines(
    operator: &Operator,
    names: &Names,
    fresh: Fresh,
    earliest: &mut Distinct,
    limit: u64,
) -> Result<BTreeMap<Text, HostLine>, Refusal> {
    let hosts = names
        .get("host")
        .expect("the package check names the hosts");
    let mut reports = BTreeMap::new();
    for (at, row) in lines(operator, "hosts.jsonl", limit)?.iter().enumerate() {
        let what = sentence!("hosts.jsonl line ", (at + 1).to_string());
        let keyed = matches!(row, Value::Object(row)
            if row.len() == 3 && ["host", "instance", "report"].iter().all(|key| row.get(key).is_some()));
        need(keyed, || {
            sentence!(what, " holds other keys than host, instance and report")
        })?;
        let row = object(row);
        let host = match get(row, "host") {
            Value::String(host) if hosts.contains(host) && !reports.contains_key(host) => host,
            _ => {
                return Err(Refusal::new(sentence!(
                    what,
                    " names no host of the package or repeats one"
                )));
            }
        };
        let instance = instance_id(get(row, "instance"), &sentence!(what, " instance"))?;
        let report = match get(row, "report") {
            Value::Null => None,
            Value::Object(report)
                if report.len() == 2
                    && report.get("time").is_some_and(finite)
                    && matches!(report.get("healthy"), Some(Value::Bool(_))) =>
            {
                let time =
                    fresh.check(number_at(report, "time"), sentence!(what, " report time"))?;
                earliest.add(time);
                let healthy = matches!(report.get("healthy"), Some(Value::Bool(true)));
                Some(Report { time, healthy })
            }
            _ => {
                return Err(Refusal::new(sentence!(
                    what,
                    " report is neither null nor {time, healthy}"
                )));
            }
        };
        reports.insert(host.clone(), HostLine { instance, report });
    }
    let named: BTreeSet<&Text> = reports.values().map(HostLine::instance).collect();
    need(named.len() == reports.len(), || {
        sentence!("hosts.jsonl names one instance twice")
    })?;
    Ok(reports)
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
/// When `records` lacks a shard of `package` or a version's `owner` or `standby`: the caller passes
/// the records [`read_snapshot`] read.
pub fn build_roles(
    package: &Object,
    names: &Names,
    package_sha256: &str,
    records: &Object,
    reports: &BTreeMap<Text, HostLine>,
    states: &BTreeMap<Text, Status>,
    cut: Number,
) -> Result<Value, Refusal> {
    let target = text_at(object_at(package, "target"), "host");
    let mut standbys = Object::new();
    for shard in list(get(package, "shards")).iter().map(text) {
        let standby = get(version(records, shard), "standby");
        if is_text(owner(records, shard), target)
            && let Value::String(host) = standby
            && host != target
            && let Some(line) = reports.get(host)
            && let Some(state) = states.get(&line.instance)
        {
            let mut entry = Object::new();
            entry.insert("instance", Value::String(line.instance.clone()));
            entry.insert("instance_state", Value::String(state.state().clone()));
            let word = health(line.report.map(|report| report.healthy));
            entry.insert("host_report", Value::String(Text::from(word)));
            standbys.insert(host.clone(), Value::Object(entry));
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

fn version<'a>(records: &'a Object, shard: &Text) -> &'a Object {
    object(member(records, shard).unwrap_or_else(|| panic!("the records hold the shard {shard}")))
}

fn owner<'a>(records: &'a Object, shard: &Text) -> &'a Value {
    get(version(records, shard), "owner")
}

fn is_text(value: &Value, text: &Text) -> bool {
    matches!(value, Value::String(found) if found == text)
}
