//! The evidence checks validate row and mark order and stop timing. Each time compares as the exact
//! decimal value its digits state.

use std::collections::{BTreeMap, BTreeSet};

use super::exact::exact;
use super::layout::VERSION_FIELDS;
use super::package::number;
use super::refusal::{Refusal, need, said};
use super::schema::{checked_field, checked_list, checked_object, checked_text};
use crate::decimal::Decimal;
use crate::json::{Integer, Object, Value};
use crate::python::repr;
use crate::text::Text;

fn time(row: &Value) -> Decimal {
    number(checked_field(row, "time"))
}

/// # Panics
///
/// `ordered` panics if an examined pair contains a row that lacks a numeric `time` field.
pub fn ordered(rows: &[Value]) -> bool {
    rows.windows(2).all(|pair| time(&pair[0]) <= time(&pair[1]))
}

/// `later` tells whether the stamp `t` is at or after the stamp `mark` of another writer. With a nonzero
/// clock error `error`, a gap of at most `error` either way gives `None`.
///
/// # Panics
///
/// `later` panics if `t` or `mark` is no finite JSON number.
pub fn later(t: &Value, mark: &Value, error: &Decimal) -> Option<bool> {
    let (t, mark) = (number(t), number(mark));
    if error.is_zero() {
        return Some(t >= mark);
    }
    let (ahead, behind) = (&t - &mark, &mark - &t);
    (ahead > *error || behind > *error).then(|| ahead > behind)
}

/// `ends_observation` holds for a restoration of package `p` stamped `time` at or after the run
/// window's start and strictly before the run window's end plus `clock_error_seconds`, so a row of
/// another writer stamped before the end may follow the return. `None` gives false.
///
/// # Panics
///
/// When `time` is `Some(t)`, `ends_observation` panics if `t` is not a finite JSON number or `p` lacks
/// its run window or `clock_error_seconds`.
pub fn ends_observation(p: &Object, time: Option<&Value>) -> bool {
    let Some(time) = time else {
        return false;
    };
    let time = exact(time).expect("a mark's time is a finite number");
    let run = p.get("run").expect("the package names its run window");
    let error = number(
        p.get("clock_error_seconds")
            .expect("the package names its clock error"),
    );
    number(checked_field(run, "start")) <= time
        && &time - &error < number(checked_field(run, "end"))
}

/// `check_order` returns the anchors of [`check_roles`] for package `p` and its parsed `files`.
///
/// # Errors
///
/// `check_order` returns the first refusal, starting with [`check_roles`], then the stop against the
/// windows, [`check_restoration`], the witness rows, the seal's time, [`check_coverage`], the hosts
/// of `activations.jsonl` and the abort mark's guardrail.
///
/// # Panics
///
/// `check_order` panics if a required package key or file is missing when accessed.
pub(super) fn check_order(
    p: &Object,
    files: &BTreeMap<Text, Value>,
) -> Result<BTreeMap<Text, Option<usize>>, Refusal> {
    let package = |key: &str| p.get(key).expect("the package's schema holds the key");
    let file = |rel: &str| files.get(&Text::from(rel));
    let required = |rel: &str| file(rel).expect("the layout requires the file");
    let error = number(package("clock_error_seconds"));
    let anchors = check_roles(p, files, &error)?;
    let (stop, abort) = (file("injection/stop.json"), file("injection/abort.json"));
    let run = package("run");
    let (start, end) = (
        number(checked_field(run, "start")),
        number(checked_field(run, "end")),
    );
    if let Some(stop) = stop {
        let baseline_end = number(checked_field(package("baseline"), "end"));
        need(baseline_end <= time(stop), || {
            said!("the baseline window ends after the stop")
        })?;
        need(start <= time(stop) && time(stop) < end, || {
            said!("the run window does not hold the stop")
        })?;
    }
    if let Some(restoration) = file("injection/restoration.json") {
        let stopped = file("injection/stopped.json");
        check_restoration(package("target"), restoration, [stop, stopped, abort], &end)?;
    }
    let witness = checked_list(required("witness.jsonl"));
    need(ordered(witness), || {
        said!("witness.jsonl is not in send order")
    })?;
    for (at, row) in witness.iter().enumerate() {
        let line = (at + 1).to_string();
        let hit = *checked_field(row, "outcome") == Value::String(Text::from("hit"));
        need(!hit || *checked_field(row, "sha256") != Value::Null, || {
            said!(
                "witness.jsonl line ",
                line,
                " is a hit with no digest (a hit needs one; another outcome may read null)"
            )
        })?;
        let after = |stop: &Value| {
            later(
                checked_field(row, "time"),
                checked_field(stop, "time"),
                &error,
            ) != Some(false)
        };
        need(stop.is_none_or(after), || {
            said!("witness.jsonl line ", line, " precedes the stop")
        })?;
    }
    let sealed = checked_field(required("injection/collected.json"), "time");
    need(end <= number(sealed), || {
        said!(
            "injection/collected.json seals the collections at ",
            repr(sealed),
            ", before the run window's end ",
            repr(checked_field(run, "end")),
        )
    })?;
    check_coverage(files, sealed)?;
    let activations = checked_list(required("activations.jsonl"));
    let hosts: BTreeSet<&Text> = activations
        .iter()
        .map(|row| checked_text(checked_field(row, "host")))
        .collect();
    need(hosts.len() == activations.len(), || {
        said!("activations.jsonl repeats a host")
    })?;
    let named = |abort: &Value| {
        let cause = *checked_field(abort, "cause") == Value::String(Text::from("guardrail"));
        cause == (*checked_field(abort, "guardrail") != Value::Null)
    };
    need(abort.is_none_or(named), || {
        said!(
            "injection/abort.json guardrail is not a GD-2 guardrail text with cause guardrail and null \
             otherwise"
        )
    })?;
    Ok(anchors)
}

/// `check_roles` anchors each shard at the first record in commit order that matches the role pin on
/// `VERSION_FIELDS` and qualifies under the read-time rule: the last commit definitely before the read,
/// or a commit whose order relative to the read is uncertain under nonzero `error`.
fn check_roles(
    p: &Object,
    files: &BTreeMap<Text, Value>,
    error: &Decimal,
) -> Result<BTreeMap<Text, Option<usize>>, Refusal> {
    let roles = files
        .get(&Text::from("injection/roles.json"))
        .expect("the layout requires the roles");
    let read_at = checked_field(roles, "time");
    let mut anchors = BTreeMap::new();
    for shard in checked_list(p.get("shards").expect("the package names its shards")) {
        let shard = checked_text(shard);
        let rel = said!("records/", shard, ".jsonl");
        let rows = checked_list(
            files
                .get(&rel)
                .expect("the layout requires each shard's records"),
        );
        let name = shard.to_str().expect("a shard's name is ASCII");
        let pin = checked_field(checked_field(roles, "shards"), name);
        need(ordered(rows), || said!(rel, " is not in commit order"))?;
        let before = rows
            .iter()
            .filter(|row| later(read_at, checked_field(row, "time"), error) == Some(true))
            .count();
        let last = before.checked_sub(1);
        let read: Vec<usize> = (0..rows.len())
            .filter(|&at| {
                let row = &rows[at];
                let near =
                    !error.is_zero() && later(checked_field(row, "time"), read_at, error).is_none();
                (Some(at) == last || near)
                    && VERSION_FIELDS
                        .iter()
                        .all(|(key, _)| checked_field(row, key) == checked_field(pin, key))
            })
            .collect();
        need(last.is_none() || !read.is_empty(), || {
            said!(
                "injection/roles.json reads shard ",
                shard,
                " other than its last version committed before the read or one within the clock \
                 error of it",
            )
        })?;
        anchors.insert(shard.clone(), read.first().copied());
    }
    Ok(anchors)
}

fn check_restoration(
    target: &Value,
    restoration: &Value,
    [stop, stopped, abort]: [Option<&Value>; 3],
    end: &Decimal,
) -> Result<(), Refusal> {
    let reviewed = *checked_field(restoration, "reviewed_sha256") != Value::Null;
    need(abort.is_some() == reviewed, || {
        said!(
            "injection/restoration.json names a reviewed record without an abort mark, or none after \
             one"
        )
    })?;
    let instance = checked_field(restoration, "instance");
    need(
        instance == checked_field(stop.unwrap_or(target), "instance"),
        || said!("injection/restoration.json names another instance than the stop request's"),
    )?;
    need(
        *checked_field(restoration, "state") == Value::String(Text::from("running")),
        || said!("injection/restoration.json reads a state other than running"),
    )?;
    let shown = stopped.filter(|stopped| time(stopped) < *end);
    let at = time(restoration);
    let follows = [stop, shown, abort].into_iter().flatten().all(|mark| {
        let other = checked_object(mark)
            .get("instance")
            .is_some_and(|named| named != instance);
        other || at >= time(mark)
    });
    need(follows, || {
        said!(
            "injection/restoration.json precedes the stop request, the stopped report or the abort \
             mark"
        )
    })
}

fn check_coverage(files: &BTreeMap<Text, Value>, sealed: &Value) -> Result<(), Refusal> {
    let coverage = files
        .get(&Text::from("coverage.json"))
        .expect("the layout requires the coverage");
    for (rel, span) in checked_object(coverage).iter() {
        let lines = checked_list(files.get(rel).expect("a span names a collected file")).len();
        let counted = checked_field(span, "lines");
        let (from, to) = (checked_field(span, "from"), checked_field(span, "to"));
        need(
            number(from) <= number(to) && *counted == Value::Integer(Integer::from(lines)),
            || {
                said!(
                    "coverage.json spans ",
                    rel,
                    " backwards or counts ",
                    repr(counted),
                    " lines, not its ",
                    lines.to_string(),
                )
            },
        )?;
        need(number(to) <= number(sealed), || {
            said!(
                "coverage.json spans ",
                rel,
                " to ",
                repr(to),
                ", after the seal's time ",
                repr(sealed),
            )
        })?;
    }
    Ok(())
}
