//! The alarm catalog `failover/report/alarms.json`, its validator and a test-only reference evaluator.
//!
//! The catalog pins the host report contract and the reconciler status contract by path, schema and SHA-256, lists
//! the closed route classes and holds one row per alarm in a closed row shape. The validator checks the catalog
//! against that shape and the pinned contracts. Rows specify alarm conditions and routing; the validator rejects
//! rows containing `action`. A number's basis is `derived` only for a window of one report, a delta of at least one
//! or a ratio above zero, which follow from the condition's form; every other number is a threshold, whose basis is
//! `assumed` or `owner`. A runbook that is a route class's guide, `RB-route-<class>`, names the row's own route.
//!
//! The reference evaluator reads accepted reports and statuses through their contract views, one row and one source
//! at a time, and accepts a record only if its sequence exceeds the highest sequence seen for that writer boot. A
//! row fires once when its condition holds for its window on one series: an entry (writer host, shard, volume), a
//! host (writer host and boot) or a zone part (writer host, zone). For run conditions, the evaluator also applies
//! `missing` when a writer's record omits an entry or zone part. A `guard` filter on a hold flag
//! (`zones.flags.warm-up`, `zones.flags.zone-host`, `zones.flags.operator`) holds every record it matches. Among the
//! records a guard filter on a source-completeness flag (`zones.flags.reports`, `zones.flags.instances`,
//! `zones.flags.volumes`, `zones.flags.store`) matches, the evaluator holds those that fail the row's condition and
//! evaluates those that meet it as any other record. A held record leaves its series unchanged. A record outside the
//! row's `where` filter ends the run. The evaluator caps severity at `ticket` for rows with an assumed number. A
//! counter forms deltas within the reset identity its contract names, as `rise` states. The evaluator measures `us`
//! windows and absence using input timestamps from its receive clock. Absence checks cover previously seen series,
//! so an external evaluator needs the list of expected writers and zones.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::LazyLock;

use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) mod controls;
mod emitters;

pub(crate) const CATALOG: &str = include_str!("../alarms.json");
const REPORT_CONTRACT: &str = include_str!("../contract.json");
const STATUS_CONTRACT: &str = include_str!("../status_contract.json");

/// The closed row shape.
const ROW_KEYS: [&str; 15] = [
    "id",
    "class",
    "source",
    "signal",
    "where",
    "condition",
    "window",
    "guard",
    "missing",
    "severity",
    "route",
    "runbook",
    "basis",
    "control",
    "clean",
];
const BASES: [&str; 3] = ["assumed", "owner", "derived"];
/// The conditions a run counts: the row fires when one holds on its window of consecutive records.
const RUNS: [&str; 4] = ["in", "positive", "full", "ratio"];
/// The zone flags that read false when a tick's source answered only in part. Among records matching a guard filter
/// on one of them, the evaluator holds those that fail the row's condition; a guard filter on another field holds
/// every record it matches.
const COMPLETENESS: [&str; 4] = [
    "zones.flags.reports",
    "zones.flags.instances",
    "zones.flags.volumes",
    "zones.flags.store",
];

pub(crate) fn catalog() -> Value {
    serde_json::from_str(CATALOG).unwrap()
}

/// The pinned contracts, each with its source name, its text and the path the catalog names it by.
static CONTRACTS: LazyLock<[(&str, Value, &str, &str); 2]> = LazyLock::new(|| {
    let parse = |text| serde_json::from_str(text).unwrap();
    [
        (
            "report",
            parse(REPORT_CONTRACT),
            REPORT_CONTRACT,
            "failover/report/contract.json",
        ),
        (
            "status",
            parse(STATUS_CONTRACT),
            STATUS_CONTRACT,
            "failover/report/status_contract.json",
        ),
    ]
});

/// The host report contract the catalog pins.
pub(crate) fn report_contract() -> &'static Value {
    &CONTRACTS[0].1
}

fn sha256(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What a contract's fixture views show a field to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Label,
    Flag,
    Number,
    Gauge,
    Object,
}

/// One pinned contract: its field paths, the kind each fixture shows, its label tables and its counters.
struct Contract {
    fields: BTreeSet<String>,
    counters: BTreeMap<String, String>,
    kinds: BTreeMap<String, Kind>,
    labels: BTreeMap<String, Vec<String>>,
    /// The label tables whose first code is 0.
    zero_based: BTreeSet<String>,
    arrays: BTreeSet<String>,
}

fn kinds_of(
    value: &Value,
    prefix: &str,
    out: &mut BTreeMap<String, Kind>,
    arrays: &mut BTreeSet<String>,
) {
    let mut note = |path: &str, kind: Kind| {
        out.entry(path.to_owned()).or_insert(kind);
    };
    match value {
        Value::Object(map) if map.contains_key("used") && map.contains_key("limit") => {
            note(prefix, Kind::Gauge)
        }
        Value::Object(map) => {
            if !prefix.is_empty() {
                note(prefix, Kind::Object);
            }
            for (key, inner) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                kinds_of(inner, &path, out, arrays);
            }
        }
        Value::Array(items) => {
            arrays.insert(prefix.to_owned());
            items
                .iter()
                .for_each(|item| kinds_of(item, prefix, out, arrays))
        }
        Value::String(_) => note(prefix, Kind::Label),
        Value::Bool(_) => note(prefix, Kind::Flag),
        Value::Number(_) => note(prefix, Kind::Number),
        Value::Null => {}
    }
}

fn table_name(field: &str) -> &str {
    let local = field
        .strip_prefix("entries.")
        .or(field.strip_prefix("zones."))
        .unwrap_or(field);
    match local {
        "exit.status" => "exit",
        "rows.class" => "class",
        "rows.standby" => "standby",
        other => other,
    }
}

impl Contract {
    fn of(contract: &Value) -> Self {
        let fields: BTreeSet<String> = (contract["fields"].as_array().unwrap().iter())
            .map(|field| field.as_str().unwrap().to_owned())
            .collect();
        let mut kinds = BTreeMap::new();
        let mut arrays = BTreeSet::new();
        for case in contract["cases"].as_object().unwrap().values() {
            let view = if case["view"].is_null() {
                &case["report"]
            } else {
                &case["view"]
            };
            kinds_of(view, "", &mut kinds, &mut arrays);
        }
        let labels = (contract["labels"].as_object().unwrap().iter())
            .map(|(name, table)| {
                let names = table
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| n.as_str().unwrap().to_owned());
                (name.clone(), names.collect())
            })
            .collect();
        let identities = contract["reset_identities"].as_object();
        let named = |identity: &Value| {
            (identity.as_str())
                .filter(|name| identities.is_some_and(|i| i.contains_key(*name)))
                .map(str::to_owned)
        };
        let naming = |family: &str| {
            (identities.into_iter().flatten())
                .find(|(_, identity)| {
                    (identity["rule"].as_str()).is_some_and(|r| r.contains(family))
                })
                .map(|(name, _)| name.clone())
        };
        let below = |field: &str, path: &str| {
            (field.strip_prefix(path)).is_some_and(|rest| rest.starts_with('.'))
        };
        let leaf = |field: &String| !fields.iter().any(|other| below(other, field));
        let resets = contract["resets"].as_object().into_iter().flatten();
        let counters = (resets.filter(|(path, _)| path.as_str() != "sequence"))
            .flat_map(|(path, value)| match (named(value), naming(path)) {
                (Some(identity), _) if path == RETENTION || leaf(path) => {
                    vec![(path.clone(), identity)]
                }
                (Some(identity), _) | (None, Some(identity)) => (fields.iter())
                    .filter(|field| below(field, path) && leaf(field))
                    .map(|field| (field.clone(), identity.clone()))
                    .collect(),
                (None, None) => vec![],
            })
            .collect();
        let first_codes = contract["label_first_code"].as_object();
        let zero_based = (first_codes.into_iter().flatten())
            .filter(|(_, code)| code.as_u64() == Some(0))
            .map(|(name, _)| name.clone())
            .collect();
        Self {
            fields,
            counters,
            kinds,
            labels,
            zero_based,
            arrays,
        }
    }

    fn inner_array(&self, path: &str) -> Option<&str> {
        (self.arrays.iter())
            .filter(|array| !matches!(array.as_str(), "entries" | "zones"))
            .find(|array| {
                path.strip_prefix(array.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
            })
            .map(String::as_str)
    }

    /// The label table of a label field: the field's path below `entries.` or `zones.`, or the table of its parent
    /// for the exit status and the row labels.
    fn table(&self, field: &str) -> Option<&Vec<String>> {
        self.labels.get(table_name(field))
    }

    /// In a zero-based table, code 0 supplies the label for an unavailable producer value.
    fn unavailable_label(&self, field: &str) -> Option<&str> {
        let name = table_name(field);
        let first = self.labels.get(name)?.first()?;
        self.zero_based.contains(name).then_some(first.as_str())
    }

    /// The kind the fixtures show, or a label for a field no fixture holds a value of whose label table exists.
    fn kind(&self, field: &str) -> Option<Kind> {
        let labelled = self.table(field).map(|_| Kind::Label);
        self.kinds.get(field).copied().or(labelled)
    }
}

/// Why the validator refused a catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) row: String,
    pub(crate) reason: String,
}

fn refuse(out: &mut Vec<Refusal>, row: &str, reason: String) {
    out.push(Refusal {
        row: row.to_owned(),
        reason,
    });
}

/// The keys of a JSON object, or none for another value.
fn keys_of(value: &Value) -> BTreeSet<&str> {
    (value.as_object().into_iter().flatten())
        .map(|(key, _)| key.as_str())
        .collect()
}

/// The validator: every refusal of `catalog` against the pinned contracts and the registered control histories.
pub(crate) fn validate(catalog: &Value, histories: &BTreeSet<String>) -> Vec<Refusal> {
    let mut out = Vec::new();
    if !catalog.is_object() {
        refuse(&mut out, "head", "the catalog is not an object".into());
        return out;
    }
    let keys = keys_of(catalog);
    if keys != BTreeSet::from(["record", "version", "contracts", "routes", "rows"]) {
        refuse(&mut out, "head", format!("keys {keys:?}"));
    }
    if catalog["record"] != "alarm-catalog" || catalog["version"] != 1 {
        refuse(&mut out, "head", "record or version".into());
    }
    let sources = keys_of(&catalog["contracts"]);
    if sources != BTreeSet::from(["report", "status"]) {
        refuse(&mut out, "head", format!("contracts {sources:?}"));
    }
    let mut pinned = BTreeMap::new();
    for (source, contract, text, path) in CONTRACTS.iter() {
        let pin = &catalog["contracts"][source];
        let pin_keys = keys_of(pin);
        if pin_keys != BTreeSet::from(["path", "schema", "sha256"]) {
            refuse(&mut out, "head", format!("{source} pin keys {pin_keys:?}"));
        }
        if pin["path"] != *path {
            refuse(&mut out, "head", format!("{source} contract path"));
        }
        if pin["sha256"] != sha256(text) {
            refuse(&mut out, "head", format!("stale {source} contract digest"));
        }
        if pin["schema"] != contract["schema"] {
            refuse(&mut out, "head", format!("{source} contract schema"));
        }
        pinned.insert(*source, Contract::of(contract));
    }
    let named = |route: &Value| route.as_str().is_some_and(|route| !route.is_empty());
    let routes: BTreeSet<&str> = match catalog["routes"].as_array() {
        Some(routes) if routes.iter().all(named) => {
            routes.iter().filter_map(Value::as_str).collect()
        }
        _ => {
            refuse(&mut out, "head", "routes is not a list of names".into());
            BTreeSet::new()
        }
    };
    let Some(rows) = catalog["rows"].as_array() else {
        refuse(&mut out, "head", "rows is not a list".into());
        return out;
    };
    let mut ids = BTreeSet::new();
    let mut used = BTreeMap::<String, usize>::new();
    for (at, row) in rows.iter().enumerate() {
        let kebab = |id: &&str| {
            *id != "head"
                && !id.is_empty()
                && (id.bytes()).all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        let id = match row["id"].as_str().filter(kebab) {
            Some(id) => {
                if !ids.insert(id) {
                    refuse(&mut out, id, "repeated id".into());
                }
                id.to_owned()
            }
            None => {
                let id = format!("rows[{at}]");
                refuse(&mut out, &id, "id is not a name".into());
                id
            }
        };
        for history in [&row["control"], &row["clean"]] {
            match history.as_str() {
                Some(name) if histories.contains(name) => {
                    *used.entry(name.to_owned()).or_default() += 1
                }
                Some(name) => refuse(&mut out, &id, format!("no history {name}")),
                None => refuse(&mut out, &id, "no control or clean twin".into()),
            }
        }
        if row["control"] == row["clean"] {
            refuse(&mut out, &id, "the clean twin is the control".into());
        }
        let twin = (row["control"].as_str()).map(|control| format!("{control}.clean"));
        if twin.is_some_and(|twin| row["clean"] != twin.as_str()) {
            refuse(
                &mut out,
                &id,
                "the clean history is not the control's twin".into(),
            );
        }
        validate_row(row, &id, &pinned, &routes, &mut out);
    }
    for name in histories {
        let count = used.get(name).copied().unwrap_or_default();
        if count != 1 {
            refuse(&mut out, name, format!("history used {count} times"));
        }
    }
    out
}

fn validate_row(
    row: &Value,
    id: &str,
    pinned: &BTreeMap<&str, Contract>,
    routes: &BTreeSet<&str>,
    out: &mut Vec<Refusal>,
) {
    if !row.is_object() {
        return refuse(out, id, "not an object".into());
    }
    let keys = keys_of(row);
    for key in keys.difference(&ROW_KEYS.into_iter().collect()) {
        refuse(out, id, format!("key {key} outside the row shape"));
    }
    for key in ROW_KEYS.into_iter().filter(|key| !keys.contains(key)) {
        refuse(out, id, format!("missing key {key}"));
    }
    if !matches!(
        row["class"].as_str(),
        Some("protocol-event" | "paging-rule")
    ) {
        refuse(out, id, "class".into());
    }
    let Some(contract) = row["source"].as_str().and_then(|source| pinned.get(source)) else {
        return refuse(out, id, "source".into());
    };
    let signal = row["signal"].as_str().unwrap_or_default();
    if !contract.fields.contains(signal) {
        return refuse(out, id, format!("signal {signal} outside the contract"));
    }
    if let Some(array) = contract.inner_array(signal) {
        return refuse(
            out,
            id,
            format!("signal {signal} lies below the array {array}"),
        );
    }
    let op = row["condition"]["op"].as_str();
    match (op, contract.counters.contains_key(signal)) {
        (Some("delta"), false) => {
            refuse(out, id, format!("delta on {signal}, which is no counter"))
        }
        (Some("positive" | "above" | "in"), true) => refuse(
            out,
            id,
            format!("{signal} is a counter, which only delta reads"),
        ),
        _ => {}
    }
    validate_filters(row, contract, signal, id, out);
    let mut numbers = validate_condition(row, contract, signal, id, out);
    numbers.extend(validate_window(row, op, signal, id, out));
    validate_missing(row, op, id, out);
    let basis = row["basis"].as_object();
    let basis_keys = keys_of(&row["basis"]);
    let expected: BTreeSet<&str> = numbers.iter().map(String::as_str).collect();
    if basis_keys != expected {
        refuse(
            out,
            id,
            format!("basis names {basis_keys:?} for numbers {expected:?}"),
        );
    }
    if basis.is_some_and(|b| {
        b.values()
            .any(|v| !BASES.contains(&v.as_str().unwrap_or_default()))
    }) {
        refuse(out, id, "basis label".into());
    }
    let derived = (basis.into_iter().flatten()).filter(|(_, label)| *label == "derived");
    for (name, _) in derived.filter(|(name, _)| !structural(row, name)) {
        refuse(
            out,
            id,
            format!(
                "{name} is derived and is no window of one report, count of one or fraction above zero"
            ),
        );
    }
    match row["severity"].as_str() {
        Some("page") if assumed(row) => {
            refuse(out, id, "a page row rests on an assumed number".into())
        }
        Some("page" | "ticket") => {}
        _ => refuse(out, id, "severity".into()),
    }
    if !row["route"]
        .as_str()
        .is_some_and(|route| routes.contains(route))
    {
        refuse(out, id, "route outside the routes".into());
    }
    let runbook = row["runbook"].as_str().unwrap_or_default();
    let slug = runbook.strip_prefix("RB-").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    if !slug {
        refuse(out, id, format!("runbook slug {runbook}"));
    }
    let guide = runbook.strip_prefix("RB-route-");
    if guide.is_some_and(|class| row["route"].as_str() != Some(class)) {
        refuse(
            out,
            id,
            format!("runbook {runbook} is the guide of another route"),
        );
    }
}

/// Whether the number `name` of `row` follows from the form of the row's condition, so no owner chooses it: a window
/// of one report, a delta of at least one, or a ratio above zero. Every other number is a threshold, whose basis is
/// `assumed` or `owner`.
fn structural(row: &Value, name: &str) -> bool {
    let condition = &row["condition"];
    match (name, condition["op"].as_str()) {
        ("window.reports", _) => row["window"]["reports"] == 1,
        ("condition.at_least", Some("delta")) => condition["at_least"] == 1,
        ("condition.above", Some("ratio")) => condition["above"].as_f64() == Some(0.0),
        _ => false,
    }
}

/// Refuses a `where` or `guard` that is not a list of filters, each an object of exactly a contract `field` and the
/// labels or flag values `in` it. A field at or below a nested array, and an entry or zone field on a row whose
/// signal reads another series, also trigger a refusal.
fn validate_filters(
    row: &Value,
    contract: &Contract,
    signal: &str,
    id: &str,
    out: &mut Vec<Refusal>,
) {
    for name in ["where", "guard"] {
        let Some(filters) = row[name].as_array() else {
            refuse(out, id, format!("{name} is not a list of filters"));
            continue;
        };
        for filter in filters {
            let keys = keys_of(filter);
            if keys != BTreeSet::from(["field", "in"]) {
                refuse(out, id, format!("{name} filter keys {keys:?}"));
                continue;
            }
            let field = filter["field"].as_str().unwrap_or_default();
            if !contract.fields.contains(field) {
                refuse(out, id, format!("field {field} outside the contract"));
                continue;
            }
            if let Some(array) = contract.inner_array(field) {
                refuse(
                    out,
                    id,
                    format!("{name} field {field} lies below the array {array}"),
                );
                continue;
            }
            if scope_of(field).is_some_and(|scope| scope_of(signal) != Some(scope)) {
                refuse(
                    out,
                    id,
                    format!("{name} field {field} is outside the series of {signal}"),
                );
                continue;
            }
            label_values(contract, field, &filter["in"], id, out);
        }
    }
}

/// Refuses a condition outside the closed shape of its operator or the kind of its signal, and returns the basis
/// names of its numbers. A ratio takes exactly one of `at_least` in (0, 1] and `above` in [0, 1).
fn validate_condition(
    row: &Value,
    contract: &Contract,
    signal: &str,
    id: &str,
    out: &mut Vec<Refusal>,
) -> Vec<String> {
    let condition = &row["condition"];
    let op = condition["op"].as_str();
    let allowed: &[&str] = match op {
        Some("in") => &["op", "values"],
        Some("ratio") => &["op", "at_least", "above"],
        Some("above") => &["op", "value"],
        Some("delta") => &["op", "at_least"],
        _ => &["op"],
    };
    let keys = keys_of(condition);
    if !keys.iter().all(|key| allowed.contains(key)) {
        refuse(out, id, format!("condition keys {keys:?}"));
    }
    if signal.ends_with(".used") || signal.ends_with(".limit") {
        refuse(
            out,
            id,
            format!("{} reads an absolute gauge value", op.unwrap_or("?")),
        );
        return vec![];
    }
    match (op, contract.kind(signal)) {
        (Some("in"), Some(Kind::Label | Kind::Flag)) => {
            label_values(contract, signal, &condition["values"], id, out);
            vec![]
        }
        (Some("positive"), Some(Kind::Number)) => vec![],
        (Some("full"), Some(Kind::Gauge)) => vec![],
        (Some("ratio"), Some(Kind::Gauge)) => {
            let fraction = |value: &Value, range: fn(f64) -> bool| {
                (value.as_f64()).is_some_and(|f| range(f) && decimal(f).is_some())
            };
            match (condition.get("at_least"), condition.get("above")) {
                (Some(at_least), None) if fraction(at_least, |f| f > 0.0 && f <= 1.0) => {
                    vec!["condition.at_least".into()]
                }
                (None, Some(above)) if fraction(above, |f| (0.0..1.0).contains(&f)) => {
                    vec!["condition.above".into()]
                }
                _ => {
                    refuse(out, id, "a ratio takes one fraction".into());
                    vec![]
                }
            }
        }
        (Some("above"), Some(Kind::Number)) if scope_of(signal) != Some("entries") => {
            refuse(
                out,
                id,
                "above reads an entry field, once per shard and tenure".into(),
            );
            vec![]
        }
        (Some("above"), Some(Kind::Number)) if condition["value"].is_u64() => {
            vec!["condition.value".into()]
        }
        (Some("delta"), Some(Kind::Number))
            if condition["at_least"].as_u64().is_some_and(|n| n >= 1) =>
        {
            vec!["condition.at_least".into()]
        }
        (Some("absent"), _) if scope_of(signal).is_none() => {
            refuse(out, id, "absent reads an entry or zone series".into());
            vec![]
        }
        (Some("absent"), _) => vec![],
        (Some(op), Some(Kind::Gauge)) => {
            refuse(out, id, format!("{op} reads an absolute gauge value"));
            vec![]
        }
        (op, kind) => {
            refuse(out, id, format!("condition {op:?} on a {kind:?} signal"));
            vec![]
        }
    }
}

/// Refuses a window other than one positive count of `reports` or `us`, or one its operator does not take: a run
/// condition counts reports, `above` reads one report, and `absent` counts microseconds. Returns the window's
/// basis name.
fn validate_window(
    row: &Value,
    op: Option<&str>,
    signal: &str,
    id: &str,
    out: &mut Vec<Refusal>,
) -> Option<String> {
    let window = row["window"].as_object();
    let entries: Vec<(&String, &Value)> = window.into_iter().flatten().collect();
    let [(key, value)] = entries.as_slice() else {
        refuse(out, id, "window".into());
        return None;
    };
    let key = key.as_str();
    if !matches!(key, "reports" | "us") || !value.as_u64().is_some_and(|n| n >= 1) {
        refuse(out, id, "window".into());
        return None;
    }
    let one = key == "reports" && *value == 1;
    match (op, key) {
        (Some(op), "us") if RUNS.contains(&op) => {
            refuse(out, id, "a run condition counts reports".into())
        }
        (Some("above"), _) if !one => refuse(out, id, "above reads one report".into()),
        (Some("absent"), "reports") => refuse(out, id, "absent counts microseconds".into()),
        _ if signal.starts_with(RETENTION) && !one => {
            refuse(out, id, "a retention account reads one report".into())
        }
        _ => {}
    }
    Some(format!("window.{key}"))
}

/// Refuses a missing policy other than `breach` or `quiet`, or one its operator does not take: `absent` breaches on
/// a missing record and takes no filters, and `above` and `delta` read a missing value as quiet.
fn validate_missing(row: &Value, op: Option<&str>, id: &str, out: &mut Vec<Refusal>) {
    let missing = row["missing"].as_str();
    if !matches!(missing, Some("breach" | "quiet")) {
        refuse(out, id, "missing".into());
    }
    match (op, missing) {
        (Some("absent"), Some("quiet")) => {
            refuse(out, id, "absent breaches on a missing record".into())
        }
        (Some(op @ ("above" | "delta")), Some("breach")) => {
            refuse(out, id, format!("{op} reads a missing value as quiet"))
        }
        _ => {}
    }
    let filtered = ["where", "guard"]
        .iter()
        .any(|name| !filters(&row[*name]).is_empty());
    if op == Some("absent") && filtered {
        refuse(out, id, "absent takes no filters".into());
    }
    if op == Some("delta") && !filters(&row["where"]).is_empty() {
        refuse(out, id, "delta takes no where filter".into());
    }
    let partial = |filter: &Value| COMPLETENESS.iter().any(|flag| filter["field"] == *flag);
    if op == Some("delta") && filters(&row["guard"]).iter().any(partial) {
        refuse(out, id, "delta takes no completeness guard".into());
    }
}

/// Refuses each value of `values` that the label table, or the flag values, of `field` lack.
fn label_values(
    contract: &Contract,
    field: &str,
    values: &Value,
    id: &str,
    out: &mut Vec<Refusal>,
) {
    let Some(values) = values.as_array().filter(|values| !values.is_empty()) else {
        return refuse(out, id, format!("no values for {field}"));
    };
    for value in values {
        let known = match (contract.kind(field), value) {
            (Some(Kind::Flag), Value::Bool(_)) => true,
            (Some(Kind::Label), Value::String(name)) => {
                contract.table(field).is_some_and(|t| t.contains(name))
            }
            _ => false,
        };
        if !known {
            refuse(
                out,
                id,
                format!("label {value} outside the table of {field}"),
            );
        }
    }
}

/// Whether any number of `row` rests on an assumed basis.
pub(crate) fn assumed(row: &Value) -> bool {
    row["basis"]
        .as_object()
        .is_some_and(|basis| basis.values().any(|v| v == "assumed"))
}

/// The severity the evaluator gives `row`: `ticket` at most when a number of the row is assumed.
pub(crate) fn severity(row: &Value) -> &'static str {
    match (row["severity"].as_str(), assumed(row)) {
        (Some("page"), false) => "page",
        _ => "ticket",
    }
}

/// An accepted record's contract view with the contract its reader follows, or an evaluation instant with no record.
#[derive(Debug, Clone)]
pub(crate) enum Input {
    Record {
        at_us: u64,
        source: &'static str,
        view: Value,
    },
    Tick {
        at_us: u64,
    },
}

/// One firing of a row on one series.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fired {
    pub(crate) row: String,
    pub(crate) series: String,
    pub(crate) at_us: u64,
    pub(crate) severity: &'static str,
}

/// How the evaluator computes a counter's rise: within one reset identity, as the reference does, or as the plain
/// difference of successive readings, a planted defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Deltas {
    ResetAware,
    ResetBlind,
}

static PINNED: LazyLock<BTreeMap<&'static str, Contract>> = LazyLock::new(|| {
    (CONTRACTS.iter())
        .map(|(source, contract, ..)| (*source, Contract::of(contract)))
        .collect()
});

/// The report field whose account the report contract fixes once known within a tenure, so a monitor keeps it over a
/// later null.
const RETENTION: &str = "entries.retention";

/// A counter's reading within one reset identity and the tick of the zone part that carried it.
#[derive(Debug, Clone, Copy)]
struct Held {
    reading: u64,
    tick: u64,
}

/// A report count, or a status count with its zone part's tick.
#[derive(Debug, Clone, Copy)]
enum Counter {
    Report,
    Status { tick: u64 },
}

/// The evaluator's state for one series of one row.
#[derive(Default)]
struct Series {
    /// Consecutive records the condition held on.
    run: u64,
    /// The row fired on this run and has not cleared since.
    fired: bool,
    /// The tenures an `above` row fired on.
    tenures: BTreeSet<String>,
    /// A counter's reading within each reset identity.
    held: BTreeMap<String, Held>,
    /// A counter's last reading whatever its identity, which the reset-blind defect differences.
    previous: Option<u64>,
    /// A counter's rises, each with its record's time.
    rises: VecDeque<(u64, i128)>,
    /// `known` preserves each tenure's last known `entries.retention` account across later null readings.
    known: BTreeMap<String, Value>,
    damaged: BTreeSet<String>,
}

impl Series {
    /// Records whether the row's condition holds on this record, and returns true when that starts a firing: the
    /// row fires once when it starts to hold and again only after it stops holding.
    fn latch(&mut self, holds: bool) -> bool {
        let starts = holds && !self.fired;
        self.fired = holds;
        starts
    }

    /// Ends the run and clears the latch, as a record outside the row's `where` filter or a record the condition
    /// does not hold on does. A record the row's guard holds on leaves the series as it stands.
    fn end_run(&mut self) {
        self.run = 0;
        self.fired = false;
    }
}

fn lookup<'a>(scope: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(scope, |value, key| value.get(key))
}

fn scope_of(path: &str) -> Option<&str> {
    match path.split_once('.') {
        Some((scope @ ("entries" | "zones"), _)) => Some(scope),
        _ => None,
    }
}

/// The value at `field` for one series: entry fields read the entry, zone fields the zone part, and the rest the
/// record.
fn field<'a>(record: &'a Value, scope: &'a Value, field: &str) -> Option<&'a Value> {
    match field.split_once('.') {
        Some((_, rest)) if scope_of(field).is_some() => lookup(scope, rest),
        _ => lookup(record, field),
    }
}

/// Whether a value reads unavailable: absent or null, or, for a gauge, the report view's `"unavailable"` string. A
/// label field's `unavailable` label, such as the store class of an unavailable store, is a value.
fn unavailable(value: Option<&Value>, gauge: bool) -> bool {
    matches!(value, None | Some(Value::Null))
        || (gauge && value.is_some_and(|v| v == "unavailable"))
}

/// Whether one filter holds for one series: its field holds one of its values.
fn filter_holds(record: &Value, scope: &Value, filter: &Value) -> bool {
    let held = field(record, scope, filter["field"].as_str().unwrap());
    let values = filter["in"].as_array().unwrap();
    held.is_some_and(|held| values.contains(held))
}

fn filters(list: &Value) -> &[Value] {
    list.as_array().map_or(&[][..], Vec::as_slice)
}

/// A gauge's used and limit counts.
fn gauge(value: &Value) -> Option<(u64, u64)> {
    Some((value.get("used")?.as_u64()?, value.get("limit")?.as_u64()?))
}

/// A capacity fraction as decimal digits over `10^places`, read from the shortest decimal that round-trips its
/// `f64`. A formatted decimal with more than 15 digits after leading zeros, or more than 19 decimal places, reads
/// `None`.
fn decimal(fraction: f64) -> Option<(u128, u32)> {
    let text = format!("{fraction}");
    let (whole, places) = text.split_once('.').unwrap_or((&text, ""));
    let digits = format!("{whole}{places}");
    if places.len() > 19 || digits.trim_start_matches('0').len() > 15 {
        return None;
    }
    Some((digits.parse().ok()?, places.len() as u32))
}

/// Whether `used / limit` reaches `fraction` (`inclusive`) or passes it, computed exactly against the fraction's
/// decimal: `used * 10^places` against `digits * limit`, which fit in `u128` for any `u64` counts.
fn reaches(used: u64, limit: u64, fraction: f64, inclusive: bool) -> bool {
    let (digits, places) = decimal(fraction).unwrap();
    let left = u128::from(used) * 10u128.pow(places);
    let right = digits * u128::from(limit);
    left > right || (inclusive && left == right)
}

/// The series of `record` that a row on `signal` reads: one per entry (writer host, shard, volume), one per zone
/// part (writer host, zone), or the record itself (writer host and boot).
fn series_of<'a>(signal: &str, record: &'a Value) -> Vec<(String, &'a Value)> {
    let host = record["writer"]["host"].to_string();
    let parts = |name: &str| record[name].as_array().into_iter().flatten();
    match scope_of(signal) {
        Some("entries") => parts("entries")
            .map(|entry| {
                (
                    format!("{host}/{}/{}", entry["shard"], entry["volume"]),
                    entry,
                )
            })
            .collect(),
        Some(_) => parts("zones")
            .map(|zone| (format!("{host}/{}", zone["zone"]), zone))
            .collect(),
        None => vec![(format!("{host}/{}", record["writer"]["boot"]), record)],
    }
}

/// An entry's activated tenure `(g, a)`, or `None` for an entry with no tenure or at epoch 0.
fn activated(scope: &Value) -> Option<String> {
    let tenure = &scope["tenure"];
    let a = tenure["a"].as_u64().filter(|a| *a > 0)?;
    Some(format!("{}/{a}", tenure["g"]))
}

/// The reset identity of a counter reading, as the contracts name it: an entry count the report contract resets at
/// the tenure forms its series within the entry's activated tenure, and `None` for an entry with no activated
/// tenure; every other count forms it within its writer's boot, which for a status count of a zone part makes the
/// identity (writer host, writer boot, zone).
fn identity(record: &Value, scope: &Value, source: &str, signal: &str) -> Option<String> {
    match PINNED[source].counters.get(signal).map(String::as_str) {
        Some("tenure") => activated(scope),
        Some("writer.boot") => Some(record["writer"]["boot"].to_string()),
        _ => None,
    }
}

/// The rise a counter reading adds to its series. Under `ResetAware` a report count's first reading of an identity
/// is its baseline, and the identity keeps its highest reading, so a late report of an earlier boot adds nothing.
/// A status count's first reading of a zone counts from zero at tick 1 and becomes the baseline at any tick after 1.
/// When a status count or its tick falls below the reading held, the whole new reading counts as its rise.
fn rise(
    state: &mut Series,
    identity: String,
    reading: u64,
    counter: Counter,
    deltas: Deltas,
) -> i128 {
    let now = i128::from(reading);
    let previous = state.previous.replace(reading);
    if deltas == Deltas::ResetBlind {
        return previous.map_or(0, |before| now - i128::from(before));
    }
    let held = state.held.get(&identity).copied();
    let (rise, kept) = match (counter, held) {
        (Counter::Report, None) => (0, Held { reading, tick: 0 }),
        (Counter::Report, Some(before)) => (
            now - i128::from(before.reading.min(reading)),
            Held {
                reading: reading.max(before.reading),
                tick: 0,
            },
        ),
        (Counter::Status { tick }, None) => {
            (if tick == 1 { now } else { 0 }, Held { reading, tick })
        }
        (Counter::Status { tick }, Some(before))
            if tick < before.tick || reading < before.reading =>
        {
            (now, Held { reading, tick })
        }
        (Counter::Status { tick }, Some(before)) => {
            (now - i128::from(before.reading), Held { reading, tick })
        }
    };
    state.held.insert(identity, kept);
    rise
}

/// What one row reads: its source, signal, condition, window and missing policy.
struct Rule<'r> {
    row: &'r Value,
    source: &'r str,
    signal: &'r str,
    condition: &'r Value,
    op: &'r str,
    breach: bool,
    reports: Option<u64>,
    us: Option<u64>,
}

impl<'r> Rule<'r> {
    fn of(row: &'r Value) -> Self {
        Self {
            row,
            source: row["source"].as_str().unwrap(),
            signal: row["signal"].as_str().unwrap(),
            condition: &row["condition"],
            op: row["condition"]["op"].as_str().unwrap(),
            breach: row["missing"] == "breach",
            reports: row["window"]["reports"].as_u64(),
            us: row["window"]["us"].as_u64(),
        }
    }

    /// Whether the condition is a run over consecutive records: `in`, `positive`, `full` or `ratio`.
    fn is_run(&self) -> bool {
        RUNS.contains(&self.op)
    }

    fn retention(&self) -> bool {
        self.signal.starts_with(RETENTION)
    }

    /// The count a `delta` row's rises reach.
    fn threshold(&self) -> i128 {
        i128::from(self.condition["at_least"].as_u64().unwrap())
    }

    /// Whether a present value meets an `in`, `positive`, `full` or `ratio` condition.
    fn meets(&self, value: &Value) -> bool {
        let c = self.condition;
        match self.op {
            "in" => c["values"].as_array().unwrap().contains(value),
            "positive" => value.as_f64().is_some_and(|n| n > 0.0),
            "full" => gauge(value).is_some_and(|(used, limit)| limit > 0 && used >= limit),
            "ratio" => gauge(value).is_some_and(|(used, limit)| {
                limit > 0
                    && match c.get("at_least") {
                        Some(at_least) => reaches(used, limit, at_least.as_f64().unwrap(), true),
                        None => reaches(used, limit, c["above"].as_f64().unwrap(), false),
                    }
            }),
            _ => false,
        }
    }

    /// The value the row reads for one series. A retention field reads the series' known account: an account the
    /// entry carries becomes known for its activated tenure, and a later null keeps it.
    fn value(&self, state: &mut Series, record: &Value, scope: &Value) -> Option<Value> {
        let present = field(record, scope, self.signal).cloned();
        let Some(rest) = self
            .signal
            .strip_prefix(RETENTION)
            .and_then(|r| r.strip_prefix('.'))
        else {
            return present;
        };
        let tenure = activated(scope)?;
        if let Some(account) = scope["retention"].as_object() {
            (state.known).insert(tenure.clone(), Value::Object(account.clone()));
        }
        lookup(state.known.get(&tenure)?, rest).cloned()
    }

    fn holds(&self, value: Option<&Value>) -> bool {
        match unavailable(value, matches!(self.op, "full" | "ratio")) {
            true => self.breach,
            false => self.meets(value.unwrap()),
        }
    }

    fn guarded(&self, record: &Value, scope: &Value) -> Option<bool> {
        let mut partial = false;
        let matched = filters(&self.row["guard"]).iter();
        for filter in matched.filter(|filter| filter_holds(record, scope, filter)) {
            if !COMPLETENESS.contains(&filter["field"].as_str().unwrap()) {
                return None;
            }
            partial = true;
        }
        Some(partial)
    }

    fn wanted(&self, record: &Value, scope: &Value, reads: impl Fn(&str) -> bool) -> bool {
        (filters(&self.row["where"]).iter())
            .filter(|filter| reads(filter["field"].as_str().unwrap()))
            .all(|filter| filter_holds(record, scope, filter))
    }

    /// Advances a run condition by one record: the run counts the records it held on, and the row fires when the
    /// run first reaches its window of reports.
    fn run(&self, state: &mut Series, holds: bool) -> bool {
        if !holds {
            state.end_run();
            return false;
        }
        state.run += 1;
        let met = self.reports.is_some_and(|n| state.run >= n);
        state.latch(met)
    }

    /// Drops the rises of a `us` window older than the window at `at_us`, and clears the latch when the rises left
    /// fall below the row's count, so a later burst fires again.
    fn expire(&self, state: &mut Series, at_us: u64) {
        let Some(us) = self.us else {
            return;
        };
        state
            .rises
            .retain(|(at, _)| at_us.saturating_sub(*at) <= us);
        if state.rises.iter().map(|(_, rise)| rise).sum::<i128>() < self.threshold() {
            state.fired = false;
        }
    }

    /// Advances a `delta` condition by one record: the rises within the window sum to at least the row's count. A
    /// reading that is unavailable adds no rise and still counts as a report of a `reports` window.
    fn delta(
        &self,
        state: &mut Series,
        record: &Value,
        scope: &Value,
        at_us: u64,
        deltas: Deltas,
    ) -> bool {
        let reading = field(record, scope, self.signal).and_then(Value::as_u64);
        let counter = match self.source {
            "status" => Counter::Status {
                tick: scope["tick"].as_u64().unwrap_or_default(),
            },
            _ => Counter::Report,
        };
        let rise = match (reading, identity(record, scope, self.source, self.signal)) {
            (Some(reading), Some(identity)) => rise(state, identity, reading, counter, deltas),
            _ => 0,
        };
        self.slot(state, at_us, rise)
    }

    fn slot(&self, state: &mut Series, at_us: u64, rise: i128) -> bool {
        state.rises.push_back((at_us, rise));
        if let Some(n) = self.reports {
            let excess = state.rises.len().saturating_sub(n as usize);
            state.rises.drain(..excess);
        }
        let sum: i128 = state.rises.iter().map(|(_, rise)| rise).sum();
        state.latch(sum >= self.threshold())
    }

    fn over(&self, value: Option<&Value>) -> bool {
        value
            .and_then(Value::as_u64)
            .is_some_and(|n| n > self.condition["value"].as_u64().unwrap())
    }

    /// Advances an `above` condition: the row fires once per shard and tenure on a value above its number. The
    /// tenure is the entry's as read, and a null tenure and a tenure whose epoch no session activated are each one
    /// key of the entry: a recovery that runs before its tenure's activation reads `recovery-stuck` beside one.
    fn above(&self, state: &mut Series, scope: &Value, over: bool) -> bool {
        over && state.tenures.insert(scope["tenure"].to_string())
    }

    fn damaged(&self, state: &mut Series, scope: &Value, holds: bool) -> bool {
        holds && activated(scope).is_some_and(|tenure| state.damaged.insert(tenure))
    }
}

/// Evaluates `row` over `inputs`, in order, and returns each firing. A record of the other source is skipped. A
/// record at or below the highest sequence held of its writer boot is dropped, an exact repeat among them.
pub(crate) fn evaluate(row: &Value, inputs: &[Input], deltas: Deltas) -> Vec<Fired> {
    let rule = Rule::of(row);
    let mut fired = Vec::new();
    let mut series: BTreeMap<String, Series> = BTreeMap::new();
    let mut highest: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut last_seen: BTreeMap<String, u64> = BTreeMap::new();
    let id = row["id"].as_str().unwrap();
    let mut fire = |key: &str, at_us: u64| {
        fired.push(Fired {
            row: id.to_owned(),
            series: key.to_owned(),
            at_us,
            severity: severity(rule.row),
        })
    };
    for input in inputs {
        let (at_us, record) = match input {
            Input::Record { source, .. } if *source != rule.source => continue,
            Input::Record { at_us, view, .. } => (*at_us, Some(view)),
            Input::Tick { at_us } => (*at_us, None),
        };
        if let Some(record) = record {
            let writer = &record["writer"];
            let boot = (writer["host"].to_string(), writer["boot"].to_string());
            let sequence = record["sequence"].as_u64().unwrap_or_default();
            let high = highest.entry(boot).or_default();
            if sequence <= *high {
                continue;
            }
            *high = sequence;
        }
        if rule.op == "absent" {
            let window = rule.us.unwrap();
            for (key, last) in &last_seen {
                let absent = at_us.saturating_sub(*last) > window;
                if series.entry(key.clone()).or_default().latch(absent) {
                    fire(key, at_us);
                }
            }
            let carried = record.map(|record| series_of(rule.signal, record));
            for (key, _) in carried.unwrap_or_default() {
                series.entry(key.clone()).or_default().latch(false);
                last_seen.insert(key, at_us);
            }
            continue;
        }
        if rule.op == "delta" {
            series
                .values_mut()
                .for_each(|state| rule.expire(state, at_us));
        }
        let Some(record) = record else {
            continue;
        };
        let present = series_of(rule.signal, record);
        let keys: BTreeSet<String> = present.iter().map(|(key, _)| key.clone()).collect();
        for (key, scope) in present {
            let Some(partial) = rule.guarded(record, scope) else {
                continue;
            };
            if !rule.wanted(record, scope, |_| true) {
                if let Some(state) = series.get_mut(&key).filter(|_| !partial) {
                    state.end_run();
                }
                continue;
            }
            let state = series.entry(key.clone()).or_default();
            let starts = match rule.op {
                "delta" if partial => continue,
                "delta" => rule.delta(state, record, scope, at_us, deltas),
                "above" => {
                    let over = rule.over(field(record, scope, rule.signal));
                    if partial && !over {
                        continue;
                    }
                    rule.above(state, scope, over)
                }
                _ => {
                    let value = rule.value(state, record, scope);
                    let holds = rule.holds(value.as_ref());
                    if partial && !holds {
                        continue;
                    }
                    match rule.retention() {
                        true => rule.damaged(state, scope, holds),
                        false => rule.run(state, holds),
                    }
                }
            };
            if starts {
                fire(&key, at_us);
            }
        }
        let carries = (rule.is_run() && !rule.retention()) || rule.reports.is_some();
        let held = rule.guarded(record, &Value::Null).is_none();
        if scope_of(rule.signal).is_some() && carries && rule.op != "above" && !held {
            let wanted = rule.wanted(record, &Value::Null, |field| scope_of(field).is_none());
            let host = format!("{}/", record["writer"]["host"]);
            let omitted = (series.iter_mut())
                .filter(|(key, _)| key.starts_with(&host) && !keys.contains(*key));
            for (key, state) in omitted {
                let starts = match rule.op {
                    "delta" => rule.slot(state, at_us, 0),
                    _ if !wanted => {
                        state.end_run();
                        false
                    }
                    _ => rule.run(state, rule.breach),
                };
                if starts {
                    fire(key, at_us);
                }
            }
        }
    }
    fired
}

fn row(catalog: &Value, id: &str) -> Value {
    let rows = catalog["rows"].as_array().unwrap();
    rows.iter().find(|row| row["id"] == id).unwrap().clone()
}

/// The firings of `row` over the sealed `steps`, every record of which the readers accept.
fn fired(row: &Value, steps: &[controls::Step]) -> Vec<Fired> {
    let (inputs, refused) = controls::sealed(steps);
    assert_eq!(refused, [], "{}: every record is accepted", row["id"]);
    evaluate(row, &inputs, Deltas::ResetAware)
}

/// The held restart's diagnostic entry, at the tenure `(g, 2E)` of the record its restart read and with every count
/// its tenure keys null, sealed in one report more than the longest report window: of the report rows only
/// `unknown-recovery-write` fires, once, and
/// no row that reads a counter forms a series from it.
#[test]
fn a_held_restart_entry_pages_unknown_recovery_write_alone_and_starts_no_counter_series() {
    let read = crate::host::agent::tests::record(1, crate::host::agent::tests::OWN, None);
    let entry = crate::host::agent::tests::held_final(&read, 7)
        .entry
        .expect("the held restart's entry");
    let catalog = catalog();
    let rows = catalog["rows"].as_array().unwrap();
    let longest = (rows.iter())
        .filter(|row| row["source"] == "report")
        .filter_map(|row| row["window"]["reports"].as_u64())
        .max()
        .unwrap();
    let steps: Vec<controls::Step> = (0..=longest)
        .map(|_| controls::Step::Report {
            host: 1,
            state: Box::new(controls::host_state()),
            entries: vec![entry],
        })
        .collect();
    let mut firing = Vec::new();
    for row in rows {
        if row["source"] != "report" {
            continue;
        }
        let fired = fired(row, &steps);
        if !fired.is_empty() {
            firing.push((row["id"].as_str().unwrap().to_owned(), fired.len()));
        }
    }
    assert_eq!(firing, [("unknown-recovery-write".to_owned(), 1)]);
    let (inputs, _) = controls::sealed(&steps);
    let Input::Record { view, .. } = &inputs[0] else {
        panic!("a report record");
    };
    let scope = &view["entries"][0];
    assert!(
        activated(scope).is_some(),
        "the entry carries the read tenure"
    );
    let counters = &PINNED["report"].counters;
    let tenured: Vec<&String> = (counters.iter())
        .filter(|(_, reset)| reset.as_str() == "tenure")
        .map(|(signal, _)| signal)
        .collect();
    assert!(tenured.len() >= 9, "{tenured:?}");
    for signal in tenured {
        let path = signal.strip_prefix("entries.").unwrap();
        let value = path.split('.').fold(scope, |at, key| &at[key]);
        assert!(value.is_null(), "{signal} reads {value}");
    }
}

/// The shipped row `id`, checked to read `source` over a window counted in records: the helpers below reseal what
/// a producer published one fixture step apart, so they judge no row whose window or rate is measured in time.
fn record_row(id: &str, source: &str) -> Value {
    let row = row(&catalog(), id);
    assert_eq!(row["source"], source, "{id} reads {source} records");
    assert!(
        row["window"]["reports"].is_u64(),
        "{id}: a window counted in records"
    );
    row
}

/// How many times the shipped report row `id` fires over `entries`, each sealed in order as one report of host 1
/// by one fixture writer, one fixture step apart, and accepted. The emitter tests beside the deciding code judge
/// with it the entries that code published.
pub(crate) fn fired_on_entries(
    id: &str,
    entries: &[crate::failover::report::VolumeEntry],
) -> usize {
    let steps: Vec<controls::Step> = entries.iter().map(|entry| report(*entry)).collect();
    fired(&record_row(id, "report"), &steps).len()
}

/// How many times the shipped status row `id` fires over `parts`, each sealed in order as one status of its own by
/// one fixture writer, one fixture step apart, and accepted. The emitter tests beside the deciding code judge with it
/// the zone parts that code built.
pub(crate) fn fired_on_parts(
    id: &str,
    parts: &[crate::failover::report::status::ZonePart],
) -> usize {
    let steps: Vec<controls::Step> = (parts.iter())
        .map(|part| controls::Step::Status(vec![part.clone()]))
        .collect();
    fired(&record_row(id, "status"), &steps).len()
}

/// The value the shipped report row `id` reads from `entry`, sealed as one report of host 1 and accepted: the
/// contract view's field at the row's signal, which the entry must hold.
pub(crate) fn signal_on_entry(id: &str, entry: crate::failover::report::VolumeEntry) -> Value {
    let row = record_row(id, "report");
    let (inputs, refused) = controls::sealed(&[report(entry)]);
    assert_eq!(refused, [], "{id}: the report is accepted");
    let Input::Record { view, .. } = &inputs[0] else {
        panic!("{id}: a report")
    };
    let signal = row["signal"].as_str().unwrap();
    assert_eq!(scope_of(signal), Some("entries"), "{id}: an entry signal");
    let entry = view["entries"].get(0).expect("the sealed entry");
    field(view, entry, signal)
        .expect("the entry holds the signal")
        .clone()
}

/// The window of the shipped row `id`, in records.
pub(crate) fn window_of(id: &str) -> usize {
    let window = &row(&catalog(), id)["window"]["reports"];
    usize::try_from(window.as_u64().expect("a window in records")).unwrap()
}

/// The shipped catalog validates against the pinned contracts: every route is in `routes`, each row has one control
/// and one clean twin, every registered history is used once, and the catalog pins both contracts' digests.
#[test]
fn the_shipped_catalog_validates() {
    let catalog = catalog();
    assert_eq!(validate(&catalog, &controls::names()), []);
    assert_eq!(catalog["rows"].as_array().unwrap().len(), 56);
    let routes = catalog["routes"].as_array().unwrap();
    assert_eq!(routes.len(), 9, "nine route classes");
}

/// The rows that page, a chosen subset of the protocol events whose numbers are all derived; the other such rows
/// ship at `ticket`. A row a later change adds as a paging row joins this list.
const PAGING: &[&str] = &[
    "store-regression",
    "store-instance-change",
    "retirement-requested",
    "hold-recorded-holder",
    "hold-no-holder",
    "hold-device",
    "hold-store",
    "unknown-recovery-write",
    "suffix-only",
    "enumeration-foreign",
    "registrant-foreign",
    "self-suspect-host",
    "replacement-held",
    "replacement-exhausted",
    "quorum-unreachable",
    "volume-lost",
    "report-forged",
    "stale-serving",
    "store-regression-reconciler",
    "store-instance-change-reconciler",
];

/// The rows of the shipped catalog that page are exactly the listed ones, so a row demoted to `ticket` or promoted
/// to `page` fails here. No paging row breaches on missing data: each reads `missing = quiet`, and its control with
/// the signal unavailable in every record raises nothing.
/// An unavailable signal reads null. A label field of a zero-based table reads that table's first label for an
/// unavailable value. A planted paging row matching that label therefore fires on missing data.
#[test]
fn the_paging_rows_are_the_listed_ones_and_none_pages_on_missing_data() {
    let catalog = catalog();
    let rows = catalog["rows"].as_array().unwrap();
    let paging: BTreeSet<&str> = (rows.iter())
        .filter(|row| row["severity"] == "page")
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(paging, PAGING.iter().copied().collect());
    for row in rows.iter().filter(|row| row["severity"] == "page") {
        let id = row["id"].as_str().unwrap();
        assert_eq!(row["missing"], "quiet", "{id}");
        let control = controls::history(row, row["control"].as_str().unwrap());
        let (inputs, _) = controls::sealed(&control);
        let signal = row["signal"].as_str().unwrap();
        let label = PINNED[row["source"].as_str().unwrap()].unavailable_label(signal);
        for reading in [Value::Null].into_iter().chain(label.map(Value::from)) {
            let missing = with_value(&inputs, signal, &reading);
            assert_eq!(
                evaluate(row, &missing, Deltas::ResetAware),
                [],
                "{id} with its signal reading {reading}"
            );
        }
    }
    let mut planted = row(&catalog, "store-regression");
    let signal = "entries.watermark";
    let unavailable = Value::from(PINNED["report"].unavailable_label(signal).unwrap());
    let values = planted["condition"]["values"].as_array_mut().unwrap();
    values.push(unavailable.clone());
    let control = controls::history(&planted, "store_regression");
    let (inputs, _) = controls::sealed(&control);
    let missing = with_value(&inputs, signal, &unavailable);
    assert_eq!(
        evaluate(&planted, &missing, Deltas::ResetAware).len(),
        1,
        "a paging row that names the unavailable label pages on a missing watermark"
    );
}

/// For each label field that a row's `in` condition or `where` filter names, the labels no row names. A label a
/// contract adds to one of these tables joins a row or this list.
const QUIET_LABELS: &[(&str, &str, &[&str])] = &[
    ("report", "entries.watermark", &["unavailable", "clear"]),
    (
        "report",
        "entries.serving",
        &["pre-boundary", "recovering", "withdrawn", "closed"],
    ),
    (
        "report",
        "entries.enumeration",
        &["unavailable", "matches", "missing"],
    ),
    (
        "report",
        "entries.registrants",
        &[
            "sole",
            "recorded",
            "excess",
            "unreadable",
            "reservation-type",
            "duplicate-own-record",
            "not-holder",
        ],
    ),
    (
        "report",
        "entries.exit.status",
        &[
            "received",
            "draining",
            "exited",
            "resumed-deadline",
            "resumed-cut",
            "resumed-standby",
            "resumed-store",
        ],
    ),
    (
        "report",
        "entries.recovery.check",
        &[
            "records",
            "deposed",
            "fresh",
            "volume",
            "exhausted",
            "local",
            "bump",
            "coverage",
            "stale",
            "restart",
            "predecessor",
            "take-over",
            "unparsed",
            "holder",
            "register",
            "second-unparsed",
            "superseded",
            "origin",
            "persist",
            "enroll-write",
            "enroll-refused",
            "acquire",
            "report",
            "hold",
            "write",
            "read",
            "activation",
            "confirm",
            "named",
            "fencing",
            "fence",
            "unresolved-page",
            "release",
            "retention",
        ],
    ),
    ("report", "entries.recovery.store", &[]),
    ("report", "entries.recovery.outcome", &["completed"]),
    (
        "report",
        "entries.recovery.next",
        &["flip", "restart", "stop"],
    ),
    ("report", "entries.load_refusal", &[]),
    ("report", "entries.retention.first_damage", &[]),
    (
        "report",
        "entries.role",
        &["standby", "replacement", "unrecorded"],
    ),
    ("report", "entries.withdrawal", &[]),
    ("status", "zones.store.alarm", &["clear"]),
];

/// Every label of a table that a row's `in` condition or `where` filter names is named by some row or listed in
/// [`QUIET_LABELS`], so a label dropped from a row, and a label a contract adds, fails here until a row names it or
/// the list holds it. Each listed label is one of its table, and every label field the rows name has an entry.
/// The row-named labels and the listed quiet labels form disjoint sets.
#[test]
fn each_label_of_a_named_table_is_named_by_a_row_or_listed_quiet() {
    let catalog = catalog();
    let mut named = BTreeMap::<(&str, &str), BTreeSet<&str>>::new();
    for row in catalog["rows"].as_array().unwrap() {
        let source = row["source"].as_str().unwrap();
        let condition = (row["condition"]["op"] == "in")
            .then(|| (row["signal"].as_str().unwrap(), &row["condition"]["values"]));
        let wheres = (filters(&row["where"]).iter())
            .map(|filter| (filter["field"].as_str().unwrap(), &filter["in"]));
        for (field, values) in condition.into_iter().chain(wheres) {
            let labels = values.as_array().unwrap().iter().filter_map(Value::as_str);
            named.entry((source, field)).or_default().extend(labels);
        }
    }
    named.retain(|_, labels| !labels.is_empty());
    let listed: BTreeSet<(&str, &str)> = (QUIET_LABELS.iter())
        .map(|(source, field, _)| (*source, *field))
        .collect();
    assert_eq!(listed, named.keys().copied().collect());
    for (source, field, quiet) in QUIET_LABELS {
        let table = PINNED[source].table(field).unwrap();
        for label in *quiet {
            assert!(table.iter().any(|l| l == label), "{field}: {label}");
        }
        let rows = &named[&(*source, *field)];
        let both: Vec<&&str> = quiet
            .iter()
            .filter(|label| rows.contains(**label))
            .collect();
        assert_eq!(both, Vec::<&&str>::new(), "{field}: named by a row");
        let neither: Vec<&String> = (table.iter())
            .filter(|label| !rows.contains(label.as_str()) && !quiet.contains(&label.as_str()))
            .collect();
        assert_eq!(neither, Vec::<&String>::new(), "{field}");
    }
}

/// The histories that prove each `where` filter and each guard on a hold flag: the row's control with the filter's
/// field at a value the filter excludes, or with the hold flag set, raises nothing. A filter or hold guard that a
/// later change adds to a row gains an entry here.
fn filter_twins() -> Vec<(&'static str, &'static str, Value)> {
    let hold = |row| (row, "zones.flags.warm-up", Value::Bool(true));
    vec![
        ("retirement-requested", "entries.role", "standby".into()),
        (
            "retirement-requested",
            "entries.withdrawal",
            "planned".into(),
        ),
        ("registrant-foreign", "entries.withdrawal", Value::Null),
        (
            "hold-recorded-holder",
            "entries.recovery.outcome",
            "completed".into(),
        ),
        (
            "hold-no-holder",
            "entries.recovery.outcome",
            "completed".into(),
        ),
        ("hold-device", "entries.recovery.next", "stop".into()),
        ("hold-store", "entries.recovery.next", "stop".into()),
        ("handoff-due", "entries.role", "standby".into()),
        ("registrant-ended", "entries.serving", "withdrawn".into()),
        (
            "recovery-stuck",
            "entries.recovery.outcome",
            "completed".into(),
        ),
        ("publication-stuck", "entries.role", "standby".into()),
        ("census-near-cap", "zones.flags.cap-below", false.into()),
        ("sources-unread", "zones.flags.reports", true.into()),
        ("sources-unread", "zones.flags.instances", true.into()),
        ("sources-unread", "zones.flags.volumes", true.into()),
        hold("no-standby-past-target"),
        hold("census-refused-full"),
        hold("attach-closed"),
        hold("shard-silent"),
        hold("host-silent"),
    ]
}

/// Each row's `where` filters and hold guards do their work: the control with one filtered field outside its
/// filter, or with one hold flag set, raises nothing, while the unchanged control fires. The listed twins cover
/// every `where` filter and every hold guard of the shipped catalog, so a row that loses a filter fails on its twin.
#[test]
fn each_filter_and_hold_guard_keeps_its_twin_silent() {
    let catalog = catalog();
    let twins = filter_twins();
    for (id, field, value) in &twins {
        let row = row(&catalog, id);
        let control = controls::history(&row, row["control"].as_str().unwrap());
        let (inputs, _) = controls::sealed(&control);
        assert_eq!(evaluate(&row, &inputs, Deltas::ResetAware).len(), 1, "{id}");
        let twin = with_value(&inputs, field, value);
        assert_eq!(
            evaluate(&row, &twin, Deltas::ResetAware),
            [],
            "{id} with {field} = {value}"
        );
    }
    let mut filtered = BTreeSet::new();
    for row in catalog["rows"].as_array().unwrap() {
        let id = row["id"].as_str().unwrap();
        let guards = (filters(&row["guard"]).iter())
            .filter(|guard| !COMPLETENESS.contains(&guard["field"].as_str().unwrap()));
        for filter in filters(&row["where"]).iter().chain(guards) {
            filtered.insert((id, filter["field"].as_str().unwrap()));
        }
    }
    let proven: BTreeSet<(&str, &str)> = twins.iter().map(|(id, field, _)| (*id, *field)).collect();
    assert_eq!(proven, filtered);
}

/// Deferral and refusal share the `foreign-registrant` value. Only refusal should trigger `registrant-foreign`.
#[test]
fn a_registrant_the_owner_defers_raises_nothing_and_its_refusal_fires() {
    use crate::failover::report::{VolumeEntry, Withdrawal};
    let foreign = row(&catalog(), "registrant-foreign");
    let (registrants, withdrawal) = controls::registrant_deferred();
    let deferred = VolumeEntry {
        registrants,
        withdrawal,
        ..controls::owner()
    };
    assert_eq!(fired(&foreign, &[report(deferred)]), []);
    let refused = VolumeEntry {
        serving: Some(crate::failover::serving::State::Withdrawn),
        flip: true,
        withdrawal: Some(Withdrawal::Report),
        ..deferred
    };
    assert_eq!(fired(&foreign, &[report(refused)]).len(), 1);
}

/// Check each row separately: a union masks a missing cause when the other row still names it.
#[test]
fn the_withdrawal_filters_name_their_causes() {
    let catalog = catalog();
    let causes = PINNED["report"].table("entries.withdrawal").unwrap();
    let named = |id: &str| -> Vec<String> {
        let row = row(&catalog, id);
        let on_cause = (filters(&row["where"]).iter())
            .filter(|filter| filter["field"] == "entries.withdrawal")
            .flat_map(|filter| filter["in"].as_array().unwrap());
        on_cause
            .map(|label| label.as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(named("registrant-foreign"), *causes);
    let unplanned: Vec<String> = (causes.iter())
        .filter(|cause| *cause != "planned")
        .cloned()
        .collect();
    assert_eq!(named("retirement-requested"), unplanned);
}

/// Every row fires exactly once on its control history and never on its clean twin, each built with the thresholds
/// and windows the row states, sealed by the writers, accepted by the readers and evaluated over the contract views.
#[test]
fn each_alarm_fires_on_its_control_and_stays_silent_on_its_clean_twin() {
    let catalog = catalog();
    for row in catalog["rows"].as_array().unwrap() {
        let id = row["id"].as_str().unwrap();
        let control = controls::history(row, row["control"].as_str().unwrap());
        let clean = controls::history(row, row["clean"].as_str().unwrap());
        let (inputs, refused) = controls::sealed(&control);
        assert_eq!(refused, [], "{id}: every control record is accepted");
        let on_control = evaluate(row, &inputs, Deltas::ResetAware);
        assert_eq!(
            on_control.len(),
            1,
            "{id} fires once on its control: {on_control:?}"
        );
        assert_eq!(
            Some(on_control[0].severity),
            row["severity"].as_str(),
            "{id}"
        );
        let (clean_inputs, clean_refused) = controls::sealed(&clean);
        assert_eq!(clean_refused, [], "{id}: every clean record is accepted");
        assert_eq!(
            evaluate(row, &clean_inputs, Deltas::ResetAware),
            [],
            "{id} stays silent on its clean twin"
        );
        let run = RUNS.contains(&row["condition"]["op"].as_str().unwrap_or_default());
        if let Some(n) = row["window"]["reports"].as_u64().filter(|&n| run && n >= 2) {
            let short = &inputs[..n as usize - 1];
            assert_eq!(
                evaluate(row, short, Deltas::ResetAware),
                [],
                "{id}: a run one short of its window"
            );
        }
        if row["condition"]["op"] == "ratio" {
            let reading = |inputs: &[Input]| {
                let Input::Record { view, .. } = &inputs[0] else {
                    panic!("a record")
                };
                let signal = row["signal"].as_str().unwrap();
                let (_, scope) = series_of(signal, view).remove(0);
                gauge(field(view, scope, signal).unwrap()).unwrap()
            };
            let ((fault, limit), (clean, clean_limit)) = (reading(&inputs), reading(&clean_inputs));
            assert_eq!(
                (clean + 1, clean_limit),
                (fault, limit),
                "{id}: one step apart"
            );
        }
        for value in row["condition"]["values"].as_array().into_iter().flatten() {
            let each = with_value(&inputs, row["signal"].as_str().unwrap(), value);
            assert_eq!(
                evaluate(row, &each, Deltas::ResetAware).len(),
                1,
                "{id} fires on {value}"
            );
        }
    }
}

/// `inputs` with `signal` set to `value` in every entry, zone part or record that holds it.
fn with_value(inputs: &[Input], signal: &str, value: &Value) -> Vec<Input> {
    let set = |scope: &mut Value, path: &str| {
        let mut at = scope;
        let keys: Vec<&str> = path.split('.').collect();
        for key in &keys[..keys.len() - 1] {
            at = &mut at[*key];
        }
        at[keys[keys.len() - 1]] = value.clone();
    };
    (inputs.iter())
        .map(|input| match input {
            Input::Record {
                at_us,
                source,
                view,
            } => {
                let mut view = view.clone();
                match signal.split_once('.') {
                    Some((parts @ ("entries" | "zones"), rest)) => {
                        for scope in view[parts].as_array_mut().into_iter().flatten() {
                            set(scope, rest);
                        }
                    }
                    _ => set(&mut view, signal),
                }
                Input::Record {
                    at_us: *at_us,
                    source,
                    view,
                }
            }
            tick => tick.clone(),
        })
        .collect()
}

/// The validator's controls: each planted edit of the shipped catalog yields the named refusal on the named row.
/// The edits cover the row shape and its closed nested shapes (an `action` key, a condition or filter key outside
/// its operator's shape, a `where` or `guard` that is no list, an id that is no name), the pinned contracts (a stale
/// digest, a swapped or missing path, an extra pin or contract key), the head (a root that is no object, null rows,
/// a route that is no name), the contract tables (a signal, filter field or label outside them, a delta of a per-tick
/// count, a level condition on a counter), the thresholds (an absolute gauge value, a ratio with no single valid
/// fraction, a page row whose number is assumed or names no basis or an unlisted basis label, a threshold or a
/// window past one report labelled `derived`), each operator's
/// window and missing policy, a ratio of at least zero or above one, a fractional `above` value, a delta of at least
/// zero, the class, source, severity, route and runbook, and the histories (no clean twin, a
/// clean twin equal to its control or another control's twin, a registered history no row uses).
/// The table also plants a repeated id, which the validator refuses as `repeated id`, a runbook slug with no name
/// or with a space, and a route class's guide on a row of another route. A delta row with a guard on a hold flag
/// validates.
#[test]
fn each_planted_row_fails_validation() {
    use serde_json::json;
    let names = controls::names();
    let first = |catalog: &mut Value| catalog["rows"][0].as_object_mut().unwrap().clone();
    let replace = |catalog: &mut Value, row: serde_json::Map<String, Value>| {
        catalog["rows"][0] = Value::Object(row)
    };
    let set = |catalog: &mut Value, id: &str, key: &str, value: Value| {
        let at = row_at(catalog, id);
        catalog["rows"][at][key] = value;
    };
    type Plant<'a> = (&'a str, &'a str, &'a dyn Fn(&mut Value));
    let first_row = "store-regression";
    let swap_clean = |c: &mut Value| {
        let clean = c["rows"][0]["clean"].clone();
        c["rows"][0]["clean"] = c["rows"][1]["clean"].clone();
        c["rows"][1]["clean"] = clean;
    };
    let swap_paths = |c: &mut Value| {
        let report = c["contracts"]["report"]["path"].clone();
        c["contracts"]["report"]["path"] = c["contracts"]["status"]["path"].clone();
        c["contracts"]["status"]["path"] = report;
    };
    let drop_path = |c: &mut Value| {
        (c["contracts"]["report"].as_object_mut().unwrap()).remove("path");
    };
    let entry_filter = json!([{"field": "entries.role", "in": ["owner"]}]);
    let rows_filter = json!([{"field": "zones.rows.class", "in": ["blocked"]}]);
    let above = |c: &mut Value, id: &str, signal: &str| {
        set(c, id, "signal", signal.into());
        set(c, id, "condition", json!({"op": "above", "value": 5}));
        let basis = json!({"condition.value": "assumed", "window.reports": "derived"});
        set(c, id, "basis", basis);
        set(c, id, "severity", "ticket".into());
    };
    let cases: &[Plant<'_>] = &[
        (
            "head",
            "keys {\"contracts\", \"extra\", \"record\", \"routes\", \"rows\", \"version\"}",
            &|c| c["extra"] = 1.into(),
        ),
        ("head", "record or version", &|c| c["version"] = 2.into()),
        ("head", "report contract schema", &|c| {
            c["contracts"]["report"]["schema"] = 9.into()
        }),
        (first_row, "no history nothing", &|c| {
            c["rows"][0]["control"] = "nothing".into();
            c["rows"][0]["clean"] = "nothing.clean".into();
        }),
        ("rows[0]", "not an object", &|c| c["rows"][0] = 3.into()),
        (first_row, "missing key runbook", &|c| {
            (c["rows"][0].as_object_mut().unwrap()).remove("runbook");
        }),
        (
            first_row,
            "condition Some(\"positive\") on a Some(Label) signal",
            &|c| c["rows"][0]["condition"] = json!({"op": "positive"}),
        ),
        ("hold-store", "no values for entries.recovery.next", &|c| {
            let at = row_at(c, "hold-store");
            c["rows"][at]["where"][0]["in"] = json!([]);
        }),
        ("rows[0]", "id is not a name", &|c| {
            c["rows"][0]["id"] = "head".into()
        }),
        ("rows[0]", "id is not a name", &|c| {
            c["rows"][0]["id"] = "rows[3]".into()
        }),
        (
            "self-suspect-host",
            "where field entries.role is outside the series of detector.self_suspect_us",
            &|c| set(c, "self-suspect-host", "where", entry_filter.clone()),
        ),
        (
            "self-suspect-host",
            "guard field entries.role is outside the series of detector.self_suspect_us",
            &|c| set(c, "self-suspect-host", "guard", entry_filter.clone()),
        ),
        (
            "shard-blocked",
            "signal zones.rows.class lies below the array zones.rows",
            &|c| {
                set(c, "shard-blocked", "signal", "zones.rows.class".into());
                let condition = json!({"op": "in", "values": ["blocked"]});
                set(c, "shard-blocked", "condition", condition);
            },
        ),
        (
            "shard-blocked",
            "where field zones.rows.class lies below the array zones.rows",
            &|c| set(c, "shard-blocked", "where", rows_filter.clone()),
        ),
        (
            "stale-serving",
            "above reads an entry field, once per shard and tenure",
            &|c| above(c, "stale-serving", "zones.stale_oldest_us"),
        ),
        (
            "self-suspect-host",
            "above reads an entry field, once per shard and tenure",
            &|c| above(c, "self-suspect-host", "detector.self_suspect_us"),
        ),
        (
            "status-absent",
            "absent reads an entry or zone series",
            &|c| set(c, "status-absent", "signal", "sequence".into()),
        ),
        (
            "store-unknown-rate-reconciler",
            "delta takes no where filter",
            &|c| {
                let filter = json!([{"field": "zones.flags.warm-up", "in": [false]}]);
                set(c, "store-unknown-rate-reconciler", "where", filter);
            },
        ),
        (
            "store-unknown-rate-reconciler",
            "delta takes no completeness guard",
            &|c| {
                let filter = json!([{"field": "zones.flags.store", "in": [false]}]);
                set(c, "store-unknown-rate-reconciler", "guard", filter);
            },
        ),
        (
            "retention-damage",
            "a retention account reads one report",
            &|c| set(c, "retention-damage", "window", json!({"reports": 3})),
        ),
        ("census-near-cap", "a ratio takes one fraction", &|c| {
            let at = row_at(c, "census-near-cap");
            c["rows"][at]["condition"]["at_least"] = 0.1234567890123456.into();
        }),
        (first_row, "key action outside the row shape", &|c| {
            let mut row = first(c);
            row.insert("action".into(), "release-hold".into());
            replace(c, row);
        }),
        (
            first_row,
            "signal entries.owner_name outside the contract",
            &|c| c["rows"][0]["signal"] = "entries.owner_name".into(),
        ),
        (
            first_row,
            "label \"rewound\" outside the table of entries.watermark",
            &|c| c["rows"][0]["condition"]["values"][0] = "rewound".into(),
        ),
        (
            "chain-at-cap",
            "above reads an absolute gauge value",
            &|c| {
                set(
                    c,
                    "chain-at-cap",
                    "condition",
                    json!({"op": "above", "value": 3}),
                );
                let at = row_at(c, "chain-at-cap");
                c["rows"][at]["basis"]["condition.value"] = "assumed".into();
            },
        ),
        (
            "chain-at-cap",
            "positive reads an absolute gauge value",
            &|c| {
                set(
                    c,
                    "chain-at-cap",
                    "signal",
                    "entries.pressure.ancestry.used".into(),
                );
                set(c, "chain-at-cap", "condition", json!({"op": "positive"}));
            },
        ),
        (first_row, "no control or clean twin", &|c| {
            let mut row = first(c);
            row.remove("clean");
            replace(c, row);
        }),
        (
            "first-hit-slow",
            "a page row rests on an assumed number",
            &|c| set(c, "first-hit-slow", "severity", "page".into()),
        ),
        ("head", "stale report contract digest", &|c| {
            c["contracts"]["report"]["sha256"] = "00".repeat(32).into()
        }),
        ("head", "stale status contract digest", &|c| {
            c["contracts"]["status"]["sha256"] = "00".repeat(32).into()
        }),
        (
            "shard-blocked",
            "delta on zones.classes.blocked, which is no counter",
            &|c| {
                set(
                    c,
                    "shard-blocked",
                    "condition",
                    json!({"op": "delta", "at_least": 1}),
                );
                let at = row_at(c, "shard-blocked");
                c["rows"][at]["basis"]["condition.at_least"] = "derived".into();
            },
        ),
        (
            "report-forged",
            "zones.events.refused.tag is a counter, which only delta reads",
            &|c| {
                set(c, "report-forged", "condition", json!({"op": "positive"}));
                set(
                    c,
                    "report-forged",
                    "basis",
                    json!({"window.reports": "derived"}),
                );
            },
        ),
        (first_row, "route outside the routes", &|c| {
            c["rows"][0]["route"] = "pager".into()
        }),
        (first_row, "runbook slug Runbook 7", &|c| {
            c["rows"][0]["runbook"] = "Runbook 7".into()
        }),
        (
            first_row,
            "runbook RB-route-store is the guide of another route",
            &|c| c["rows"][0]["route"] = "deploy".into(),
        ),
        (first_row, "runbook slug RB-", &|c| {
            c["rows"][0]["runbook"] = "RB-".into()
        }),
        (first_row, "runbook slug RB-Route Store", &|c| {
            c["rows"][0]["runbook"] = "RB-Route Store".into()
        }),
        (first_row, "repeated id", &|c| {
            c["rows"][1]["id"] = c["rows"][0]["id"].clone()
        }),
        (first_row, "the clean twin is the control", &|c| {
            c["rows"][0]["clean"] = c["rows"][0]["control"].clone()
        }),
        (
            "report-forged",
            "basis names {\"window.reports\"} for numbers {\"condition.at_least\", \"window.reports\"}",
            &|c| {
                set(
                    c,
                    "report-forged",
                    "basis",
                    json!({"window.reports": "derived"}),
                )
            },
        ),
        (
            "no-standby-past-target",
            "window.reports is derived and is no window of one report, count of one or fraction above zero",
            &|c| set(c, "no-standby-past-target", "window", json!({"reports": 2})),
        ),
        (
            "store-unknown-rate",
            "condition.at_least is derived and is no window of one report, count of one or fraction above zero",
            &|c| {
                let basis = json!({"condition.at_least": "derived", "window.us": "assumed"});
                set(c, "store-unknown-rate", "basis", basis);
            },
        ),
        (
            "store-unknown-rate",
            "window.us is derived and is no window of one report, count of one or fraction above zero",
            &|c| {
                let basis = json!({"condition.at_least": "assumed", "window.us": "derived"});
                set(c, "store-unknown-rate", "basis", basis);
            },
        ),
        (
            "census-near-cap",
            "condition.at_least is derived and is no window of one report, count of one or fraction above zero",
            &|c| {
                let at = row_at(c, "census-near-cap");
                c["rows"][at]["basis"]["condition.at_least"] = "derived".into();
            },
        ),
        (
            "first-hit-slow",
            "condition.value is derived and is no window of one report, count of one or fraction above zero",
            &|c| {
                let at = row_at(c, "first-hit-slow");
                c["rows"][at]["basis"]["condition.value"] = "derived".into();
            },
        ),
        (
            "host-silent",
            "condition.above is derived and is no window of one report, count of one or fraction above zero",
            &|c| {
                let at = row_at(c, "host-silent");
                c["rows"][at]["condition"]["above"] = 0.5.into();
            },
        ),
        (
            "report-forged",
            "condition.at_least is derived and is no window of one report, count of one or fraction above zero",
            &|c| {
                let at = row_at(c, "report-forged");
                c["rows"][at]["condition"]["at_least"] = 2.into();
            },
        ),
        ("census-near-cap", "a ratio takes one fraction", &|c| {
            let at = row_at(c, "census-near-cap");
            c["rows"][at]["condition"]["at_least"] = 0.into();
        }),
        ("census-near-cap", "a ratio takes one fraction", &|c| {
            let at = row_at(c, "census-near-cap");
            c["rows"][at]["condition"]["at_least"] = 1.5.into();
        }),
        ("host-silent", "a ratio takes one fraction", &|c| {
            let at = row_at(c, "host-silent");
            c["rows"][at]["condition"]["above"] = 1.into();
        }),
        (
            "first-hit-slow",
            "condition Some(\"above\") on a Some(Number) signal",
            &|c| {
                let at = row_at(c, "first-hit-slow");
                c["rows"][at]["condition"]["value"] = 1.5.into();
            },
        ),
        (
            "read-defect",
            "condition Some(\"delta\") on a Some(Number) signal",
            &|c| {
                let at = row_at(c, "read-defect");
                c["rows"][at]["condition"]["at_least"] = 0.into();
            },
        ),
        ("first-hit-slow", "basis label", &|c| {
            let at = row_at(c, "first-hit-slow");
            c["rows"][at]["basis"]["condition.value"] = "tbd".into();
            c["rows"][at]["severity"] = "page".into();
        }),
        ("census-near-cap", "a ratio takes one fraction", &|c| {
            let at = row_at(c, "census-near-cap");
            c["rows"][at]["condition"]["above"] = 0.5.into();
        }),
        ("host-silent", "a ratio takes one fraction", &|c| {
            let at = row_at(c, "host-silent");
            c["rows"][at]["condition"]["at_least"] = (-1).into();
        }),
        ("budget-attempts", "a ratio takes one fraction", &|c| {
            let at = row_at(c, "budget-attempts");
            c["rows"][at]["condition"]["above"] = 1.5.into();
        }),
        (first_row, "window", &|c| {
            c["rows"][0]["window"] = json!({"reports": 0})
        }),
        (first_row, "window", &|c| {
            c["rows"][0]["window"] = json!({"reports": 1, "us": 5})
        }),
        ("handoff-due", "a run condition counts reports", &|c| {
            set(c, "handoff-due", "window", json!({"us": 5}));
            set(c, "handoff-due", "basis", json!({"window.us": "assumed"}));
        }),
        ("first-hit-slow", "above reads one report", &|c| {
            set(c, "first-hit-slow", "window", json!({"reports": 3}))
        }),
        ("status-absent", "absent counts microseconds", &|c| {
            set(c, "status-absent", "window", json!({"reports": 3}));
            set(
                c,
                "status-absent",
                "basis",
                json!({"window.reports": "assumed"}),
            );
        }),
        (first_row, "missing", &|c| {
            c["rows"][0]["missing"] = "sometimes".into()
        }),
        (
            "status-absent",
            "absent breaches on a missing record",
            &|c| set(c, "status-absent", "missing", "quiet".into()),
        ),
        (
            "first-hit-slow",
            "above reads a missing value as quiet",
            &|c| set(c, "first-hit-slow", "missing", "breach".into()),
        ),
        (
            "read-defect",
            "delta reads a missing value as quiet",
            &|c| set(c, "read-defect", "missing", "breach".into()),
        ),
        ("status-absent", "absent takes no filters", &|c| {
            set(
                c,
                "status-absent",
                "where",
                json!([{"field": "zones.flags.warm-up", "in": [true]}]),
            )
        }),
        (first_row, "severity", &|c| {
            c["rows"][0]["severity"] = "info".into()
        }),
        (first_row, "class", &|c| {
            c["rows"][0]["class"] = "advice".into()
        }),
        (first_row, "source", &|c| {
            c["rows"][0]["source"] = "metrics".into()
        }),
        (
            "hold-store",
            "field entries.nothing outside the contract",
            &|c| {
                let at = row_at(c, "hold-store");
                c["rows"][at]["where"][0]["field"] = "entries.nothing".into();
            },
        ),
        (
            "hold-store",
            "label \"sometime\" outside the table of entries.recovery.next",
            &|c| {
                let at = row_at(c, "hold-store");
                c["rows"][at]["where"][0]["in"] = json!(["sometime"]);
            },
        ),
        ("hold-store", "where is not a list of filters", &|c| {
            let at = row_at(c, "hold-store");
            c["rows"][at]["where"] = c["rows"][at]["where"][0].clone();
        }),
        ("host-silent", "guard is not a list of filters", &|c| {
            let at = row_at(c, "host-silent");
            c["rows"][at]["guard"] = c["rows"][at]["guard"][0].clone();
        }),
        (
            "hold-store",
            "where filter keys {\"field\", \"in\", \"note\"}",
            &|c| {
                let at = row_at(c, "hold-store");
                c["rows"][at]["where"][0]["note"] = "held".into();
            },
        ),
        (
            first_row,
            "condition keys {\"at_least\", \"op\", \"values\"}",
            &|c| c["rows"][0]["condition"]["at_least"] = 1.into(),
        ),
        ("rows[0]", "id is not a name", &|c| {
            c["rows"][0]["id"] = 7.into()
        }),
        ("rows[0]", "id is not a name", &|c| {
            c["rows"][0]["id"] = "".into()
        }),
        (
            first_row,
            "the clean history is not the control's twin",
            &swap_clean,
        ),
        (
            "store-instance-change",
            "the clean history is not the control's twin",
            &swap_clean,
        ),
        ("head", "report contract path", &swap_paths),
        ("head", "status contract path", &swap_paths),
        (
            "head",
            "report pin keys {\"schema\", \"sha256\"}",
            &drop_path,
        ),
        ("head", "report contract path", &drop_path),
        (
            "head",
            "status pin keys {\"note\", \"path\", \"schema\", \"sha256\"}",
            &|c| c["contracts"]["status"]["note"] = "pinned".into(),
        ),
        (
            "head",
            "contracts {\"extra\", \"report\", \"status\"}",
            &|c| c["contracts"]["extra"] = json!({}),
        ),
        ("head", "routes is not a list of names", &|c| {
            c["routes"][0] = 3.into()
        }),
        ("head", "routes is not a list of names", &|c| {
            c.as_object_mut().unwrap().remove("routes");
        }),
        ("head", "rows is not a list", &|c| c["rows"] = Value::Null),
        ("head", "the catalog is not an object", &|c| *c = json!([])),
    ];
    for (row, reason, edit) in cases {
        let mut catalog = catalog();
        edit(&mut catalog);
        let refusals = validate(&catalog, &names);
        let expected = Refusal {
            row: (*row).to_owned(),
            reason: (*reason).to_owned(),
        };
        assert!(
            refusals.contains(&expected),
            "{row}: {reason}: {refusals:?}"
        );
    }
    let mut extra = names.clone();
    extra.insert("an_unused_history".into());
    let refusals = validate(&catalog(), &extra);
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0].reason, "history used 0 times");
    let mut held = catalog();
    let hold = json!([{"field": "zones.flags.warm-up", "in": [true]}]);
    set(&mut held, "report-forged", "guard", hold);
    assert_eq!(
        validate(&held, &names),
        [],
        "a delta row takes a guard on a hold flag"
    );
}

/// A contract's counters come from its `resets` table: the status contract's event and store outcome leaves are
/// counters, its per-tick fields are not, the report contract's counters are the paths its table names, and a status
/// contract whose table drops the event family has no event counter, so a delta row on one is refused.
/// Every counter names a reset identity declared by its contract. When `resets` maps `zones.events` to
/// `writer.boot`, `validate_row` accepts the `zones.events.refused.tag` delta.
#[test]
fn the_counters_follow_each_contract_resets_table() {
    let report = Contract::of(&CONTRACTS[0].1);
    let resets = CONTRACTS[0].1["resets"].as_object().unwrap();
    let named: BTreeMap<String, String> = (resets.iter())
        .filter(|(path, _)| path.as_str() != "sequence")
        .map(|(path, identity)| (path.clone(), identity.as_str().unwrap().to_owned()))
        .collect();
    assert_eq!(report.counters, named);
    let status = Contract::of(&CONTRACTS[1].1);
    let of = |contract: &Contract, path: &str| contract.counters.get(path).cloned();
    let boot = Some("writer.boot".to_owned());
    assert_eq!(of(&status, "zones.events.refused.tag"), boot);
    assert_eq!(of(&status, "zones.store.outcomes.unknown"), boot);
    assert_eq!(of(&status, "zones.events.refused"), None);
    assert_eq!(of(&status, "zones.tick"), None);
    for (contract, text) in [(&report, &CONTRACTS[0].1), (&status, &CONTRACTS[1].1)] {
        let identities = text["reset_identities"].as_object().unwrap();
        assert!(
            contract
                .counters
                .values()
                .all(|i| identities.contains_key(i))
        );
    }
    let forged = row(&catalog(), "report-forged");
    let refusals = |contract: Value| {
        let pinned = BTreeMap::from([("status", Contract::of(&contract))]);
        let mut out = Vec::new();
        let routes = BTreeSet::from(["telemetry"]);
        validate_row(&forged, "report-forged", &pinned, &routes, &mut out);
        out
    };
    let mut dropped = CONTRACTS[1].1.clone();
    let resets = dropped["resets"].as_object_mut().unwrap();
    resets.remove("zones.events");
    let without = Contract::of(&dropped);
    assert_eq!(of(&without, "zones.events.refused.tag"), None);
    assert_eq!(of(&without, "zones.store.outcomes.unknown"), boot);
    let out = refusals(dropped);
    assert!(
        out.iter()
            .any(|r| r.reason == "delta on zones.events.refused.tag, which is no counter"),
        "{out:?}"
    );
    let mut named = CONTRACTS[1].1.clone();
    named["resets"]["zones.events"] = "writer.boot".into();
    assert_eq!(of(&Contract::of(&named), "zones.events.refused.tag"), boot);
    assert_eq!(refusals(named), []);
}

fn row_at(catalog: &Value, id: &str) -> usize {
    let rows = catalog["rows"].as_array().unwrap();
    rows.iter().position(|row| row["id"] == id).unwrap()
}

/// A tenure whose `first_hit_us` is the row's threshold plus one microsecond, sealed in six reports, fires
/// `first-hit-slow` once for that shard and tenure, and a second tenure of the shard fires once more; the twin at
/// the threshold is silent. One damaged unit sealed in six successive reports fires `retention-damage` once.
#[test]
fn a_slow_first_hit_and_a_damaged_unit_fire_once_per_tenure() {
    let catalog = catalog();
    let slow = row(&catalog, "first-hit-slow");
    let threshold = slow["condition"]["value"].as_u64().unwrap();
    let at = |first_hit_us: u64, epoch: u32| controls::Step::Report {
        host: 1,
        state: Box::new(controls::host_state()),
        entries: vec![crate::failover::report::VolumeEntry {
            tenure: Some((
                crate::net::ownership::ShardGeneration::new(1).unwrap(),
                crate::net::ownership::ActivatedEpoch::new(epoch).unwrap(),
            )),
            times: crate::failover::report::RecoveryTimes {
                first_hit_us: Some(first_hit_us),
                ..crate::failover::report::RecoveryTimes::UNAVAILABLE
            },
            ..controls::owner()
        }],
    };
    let six: Vec<controls::Step> = (0..6).map(|_| at(threshold + 1, 2)).collect();
    assert_eq!(fired(&slow, &six).len(), 1);
    let at_threshold: Vec<controls::Step> = (0..6).map(|_| at(threshold, 2)).collect();
    assert_eq!(fired(&slow, &at_threshold), []);
    let two: Vec<controls::Step> = (0..6)
        .map(|n| at(threshold + 1, if n < 3 { 2 } else { 4 }))
        .collect();
    assert_eq!(fired(&slow, &two).len(), 2, "once per tenure");
    let damage = row(&catalog, "retention-damage");
    let history = controls::history(&damage, "retention_damage");
    assert_eq!(history.len(), 6);
    assert_eq!(fired(&damage, &history).len(), 1);
}

/// An `above` row keys on the entry's tenure as read. Six reports of a first hit one microsecond past the threshold
/// fire `first-hit-slow` once beside a null tenure and once beside a tenure at epoch 0, and six reports of a running
/// takeover one microsecond past its threshold fire `recovery-stuck` the same way; each twin at the threshold is
/// silent.
#[test]
fn an_above_row_fires_once_beside_a_tenure_no_session_activated() {
    use crate::failover::report::{
        Recovery, RecoveryKind, RecoveryOutcome, RecoveryTimes, VolumeEntry,
    };
    use crate::net::ownership::{ActivatedEpoch, ShardGeneration};
    let catalog = catalog();
    let slow = row(&catalog, "first-hit-slow");
    let stuck = row(&catalog, "recovery-stuck");
    let threshold = |row: &Value| row["condition"]["value"].as_u64().unwrap();
    let unactivated = Some((
        ShardGeneration::new(1).unwrap(),
        ActivatedEpoch::new(0).unwrap(),
    ));
    for tenure in [None, unactivated] {
        let hit = |first_hit_us| VolumeEntry {
            tenure,
            times: RecoveryTimes {
                first_hit_us: Some(first_hit_us),
                ..RecoveryTimes::UNAVAILABLE
            },
            ..controls::owner()
        };
        let running = |age_us| VolumeEntry {
            tenure,
            recovery: Recovery {
                kind: Some(RecoveryKind::Takeover),
                outcome: Some(RecoveryOutcome::Running),
                attempts: Some(1),
                age_us: Some(age_us),
                ..Recovery::UNAVAILABLE
            },
            ..controls::owner()
        };
        let six = |entry: VolumeEntry| (0..6).map(|_| report(entry)).collect::<Vec<_>>();
        let cases = [
            (
                &slow,
                six(hit(threshold(&slow) + 1)),
                six(hit(threshold(&slow))),
            ),
            (
                &stuck,
                six(running(threshold(&stuck) + 1)),
                six(running(threshold(&stuck))),
            ),
        ];
        for (row, over, at) in cases {
            assert_eq!(fired(row, &over).len(), 1, "{} {tenure:?}", row["id"]);
            assert_eq!(fired(row, &at), [], "{} {tenure:?}", row["id"]);
        }
    }
}

fn unknown_count(count: u64, epoch: u32) -> crate::failover::report::VolumeEntry {
    crate::failover::report::VolumeEntry {
        tenure: Some((
            crate::net::ownership::ShardGeneration::new(1).unwrap(),
            crate::net::ownership::ActivatedEpoch::new(epoch).unwrap(),
        )),
        store: crate::failover::report::StoreOutcomes {
            unknown: Some(count),
            ..crate::failover::report::StoreOutcomes::UNAVAILABLE
        },
        ..controls::owner()
    }
}

fn report(entry: crate::failover::report::VolumeEntry) -> controls::Step {
    controls::Step::Report {
        host: 1,
        state: Box::new(controls::host_state()),
        entries: vec![entry],
    }
}

/// A count of 5 in tenure A, then 3 in tenure B, fires a `delta >= 3` row: as the report contract states, the first
/// reading of tenure B, 0, is its baseline, and B's rise to 3 counts. Control: the reset-blind evaluator computes
/// 0 - 5, a negative delta, and stays silent. A first reading of a tenure forms no delta, so tenure A at 1 then
/// tenure B first read at 4 stays silent where a rule that reads any rise across tenures would fire. An entry with
/// no tenure, or at epoch 0, forms no series.
#[test]
fn a_delta_counts_from_each_reset_and_a_reset_blind_evaluator_misses_it() {
    let catalog = catalog();
    let rate = row(&catalog, "store-unknown-rate");
    assert_eq!(rate["condition"]["at_least"], 3);
    let steps =
        [5, 5, 0, 3].map(|count| report(unknown_count(count, if count == 5 { 2 } else { 4 })));
    let (inputs, _) = controls::sealed(&steps);
    assert_eq!(evaluate(&rate, &inputs, Deltas::ResetAware).len(), 1);
    assert_eq!(
        evaluate(&rate, &inputs, Deltas::ResetBlind),
        [],
        "the reset-blind evaluator stays silent on a negative delta"
    );
    let baseline = [
        report(unknown_count(1, 2)),
        report(unknown_count(4, 4)),
        report(unknown_count(4, 4)),
    ];
    assert_eq!(
        fired(&rate, &baseline),
        [],
        "a tenure's first reading is its baseline"
    );
    let unactivated = [0, 3, 6].map(|count| {
        let mut entry = unknown_count(count, 2);
        entry.tenure = None;
        report(entry)
    });
    assert_eq!(
        fired(&rate, &unactivated),
        [],
        "an entry with no tenure forms no series"
    );
    let epoch_zero = [0, 3, 6].map(|count| {
        let mut entry = unknown_count(count, 2);
        let (generation, _) = entry.tenure.unwrap();
        let zero = crate::net::ownership::ActivatedEpoch::new(0).unwrap();
        entry.tenure = Some((generation, zero));
        report(entry)
    });
    assert_eq!(
        fired(&rate, &epoch_zero),
        [],
        "an entry at epoch 0 forms no series"
    );
}

/// Within one tenure a counter's series keeps its high-water across the owner's boots: a late report of an earlier
/// boot that reads below it adds nothing, so boot 1 at 5, boot 2 at 6, a late boot-1 report at 5 and boot 2 at 6
/// again rise by one, which a `delta >= 2` row does not reach. A status count of a new writer boot rises from zero
/// at its loop's tick 1, so a forged tag on the reconciler's first tick after a restart fires `report-forged`. A
/// count that falls while the tick rises counts from zero, and the lower reading is the new baseline: 0, 4, 1, 2
/// rises by 4, then 1, then 1, which fires a `delta >= 2` row once where a kept high-water of 4 would read the 2
/// as a second fall and fire twice.
#[test]
fn a_counter_keeps_its_high_water_across_boots_and_a_new_status_boot_rises_from_zero() {
    let mut rate = row(&catalog(), "store-unknown-rate");
    rate["condition"]["at_least"] = 2.into();
    let boot = |boot| controls::Step::Boot { host: 1, boot };
    let steps = [
        boot(1),
        report(unknown_count(5, 2)),
        boot(2),
        report(unknown_count(6, 2)),
        boot(1),
        report(unknown_count(5, 2)),
        boot(2),
        report(unknown_count(6, 2)),
    ];
    let (inputs, refused) = controls::sealed(&steps);
    assert_eq!((inputs.len(), refused), (4, vec![]));
    assert_eq!(evaluate(&rate, &inputs, Deltas::ResetAware), []);
    rate["condition"]["at_least"] = 1.into();
    assert_eq!(evaluate(&rate, &inputs, Deltas::ResetAware).len(), 1);
    let forged = row(&catalog(), "report-forged");
    let restarted = [
        tagged(1, 0),
        tagged(2, 0),
        controls::Step::StatusBoot(7),
        tagged(1, 1),
    ];
    assert_eq!(
        fired(&forged, &restarted).len(),
        1,
        "the new boot's first count rises from zero"
    );
    let restarted_loop = [tagged(1, 0), tagged(2, 4), tagged(3, 4), tagged(4, 1)];
    let on_drop = fired(&forged, &restarted_loop);
    assert_eq!(
        on_drop.len(),
        2,
        "a count that falls within a boot rises from zero: {on_drop:?}"
    );
    let mut two = forged.clone();
    two["condition"]["at_least"] = 2.into();
    let after_fall = [tagged(1, 0), tagged(2, 4), tagged(3, 1), tagged(4, 2)];
    assert_eq!(
        fired(&two, &after_fall).len(),
        1,
        "after a fall the lower reading is the new baseline"
    );
    let steady = [
        tagged(1, 0),
        tagged(2, 0),
        controls::Step::StatusBoot(7),
        tagged(1, 0),
        tagged(2, 0),
    ];
    assert_eq!(fired(&forged, &steady), []);
}

/// A status count's reset identity is (writer host, writer boot, zone), and one series holds each identity's
/// reading: boots A and B of one writer interleaved at tag counts A1 = 0, B1 = 0, A2 = 0 and B2 = 1 fire
/// `report-forged` once, at B2. A report count's identity is the activated tenure: tenure X at 0, a late report of
/// an earlier boot at tenure Y, then X at 3 fire `store-unknown-rate` at the second X report.
#[test]
fn interleaved_boots_and_tenures_keep_their_own_baselines() {
    let forged = row(&catalog(), "report-forged");
    let boot = controls::Step::StatusBoot;
    let steps = [
        boot(1),
        tagged(1, 0),
        boot(2),
        tagged(1, 0),
        boot(1),
        tagged(2, 0),
        boot(2),
        tagged(2, 1),
    ];
    let (inputs, refused) = controls::sealed(&steps);
    assert_eq!((inputs.len(), refused), (4, vec![]));
    let on_b2 = evaluate(&forged, &inputs, Deltas::ResetAware);
    assert_eq!(
        on_b2.iter().map(|f| f.at_us).collect::<Vec<_>>(),
        [at(&inputs[3])]
    );
    let rate = row(&catalog(), "store-unknown-rate");
    let boot = |boot| controls::Step::Boot { host: 1, boot };
    let steps = [
        boot(2),
        report(unknown_count(0, 4)),
        boot(1),
        report(unknown_count(7, 2)),
        boot(2),
        report(unknown_count(3, 4)),
    ];
    let (inputs, refused) = controls::sealed(&steps);
    assert_eq!((inputs.len(), refused), (3, vec![]));
    let on_x = evaluate(&rate, &inputs, Deltas::ResetAware);
    assert_eq!(
        on_x.iter().map(|f| f.at_us).collect::<Vec<_>>(),
        [at(&inputs[2])]
    );
}

/// The status contract's loop rules: a part whose tick is below the last one held of its boot and zone starts a new
/// loop whose counts rise from zero, so tag counts 0, 1 and 1 at ticks 1 to 3, then 1 at tick 1, fire
/// `report-forged` on the first rise and on the restart, although the count does not fall. The first part a monitor
/// holds of a zone rises from zero only at tick 1: a status whose zone part was lost, then a part at tick 2 reading
/// 1, is the baseline, and the rise to 2 at tick 3 fires; a part of that zone first held at tick 1 fires on its count,
/// even when an earlier status of the boot held another zone only. A second part at the tick already held continues
/// the loop, so its rise counts from the reading held.
#[test]
fn a_lower_tick_starts_a_new_loop_and_a_later_first_tick_is_the_baseline() {
    let forged = row(&catalog(), "report-forged");
    let restarted = [tagged(1, 0), tagged(2, 1), tagged(3, 1), tagged(1, 1)];
    let (inputs, _) = controls::sealed(&restarted);
    let on_restart = fired(&forged, &restarted);
    assert_eq!(
        on_restart.iter().map(|f| f.at_us).collect::<Vec<_>>(),
        [at(&inputs[1]), at(&inputs[3])]
    );
    let (mut inputs, refused) = controls::sealed(&[tagged(1, 1), tagged(2, 1), tagged(3, 2)]);
    assert_eq!(refused, []);
    inputs.remove(0);
    let late = evaluate(&forged, &inputs, Deltas::ResetAware);
    assert_eq!(
        late.iter().map(|f| f.at_us).collect::<Vec<_>>(),
        [at(&inputs[1])]
    );
    let other_zone = controls::Step::Status(vec![part(2, 1)]);
    let first_at_tick_1 = [other_zone, tagged(1, 1)];
    assert_eq!(fired(&forged, &first_at_tick_1).len(), 1);
    let mut three = forged.clone();
    three["condition"]["at_least"] = 3.into();
    let same_tick = [tagged(4, 0), tagged(5, 2), tagged(5, 3)];
    assert_eq!(
        fired(&three, &same_tick),
        [],
        "a second part at the tick held continues its loop: the rises are 2 and 1"
    );
}

/// A status at or below the highest sequence held of its writer boot is dropped: statuses of one boot at tag counts
/// 1, 1, 2 and 2, delivered in the order 1, 3, 4, 2 with rising receive times, fire `report-forged` once, on the
/// third status, where reading the late second status would count its fall from 2 to 1 as a restart.
#[test]
fn a_late_status_of_its_boot_counts_nothing() {
    let forged = row(&catalog(), "report-forged");
    let steps = [tagged(10, 1), tagged(11, 1), tagged(12, 2), tagged(13, 2)];
    let (inputs, refused) = controls::sealed(&steps);
    assert_eq!(refused, []);
    let mut reordered: Vec<Input> = [0, 2, 3, 1].map(|at| inputs[at].clone()).to_vec();
    for (input, time) in reordered.iter_mut().zip(inputs.iter().map(at)) {
        retime(input, time);
    }
    let on_late = evaluate(&forged, &reordered, Deltas::ResetAware);
    assert_eq!(
        on_late.iter().map(|f| f.at_us).collect::<Vec<_>>(),
        [at(&reordered[1])]
    );
}

/// Within one boot, a late report preserves the `read-defect` latch even when its receive time advances.
#[test]
fn a_late_report_of_its_boot_counts_nothing() {
    let defect = row(&catalog(), "read-defect");
    let defects = |count: u64| {
        report(VolumeEntry {
            read_defects: Some(count),
            ..controls::owner()
        })
    };
    let (inputs, refused) = controls::sealed(&[defects(0), defects(0), defects(1), defects(2)]);
    assert_eq!(refused, []);
    let mut reordered: Vec<Input> = [0, 2, 1, 3].map(|at| inputs[at].clone()).to_vec();
    for (input, time) in reordered.iter_mut().zip(inputs.iter().map(at)) {
        retime(input, time);
    }
    let on_late = evaluate(&defect, &reordered, Deltas::ResetAware);
    assert_eq!(
        on_late.iter().map(|f| f.at_us).collect::<Vec<_>>(),
        [at(&reordered[1])]
    );
}

/// A `reports` window consumes one slot per record of its series, so an untenured count or an omission ages old
/// rises out.
#[test]
fn a_report_window_ages_on_every_record_of_its_series() {
    let defect = row(&catalog(), "read-defect");
    let defects = |count: u64, tenure: bool| {
        let mut entry = VolumeEntry {
            read_defects: Some(count),
            ..controls::owner()
        };
        if !tenure {
            entry.tenure = None;
        }
        report(entry)
    };
    let steps = [
        defects(0, true),
        defects(1, true),
        defects(1, false),
        defects(2, true),
    ];
    let (inputs, _) = controls::sealed(&steps);
    let times: Vec<u64> = fired(&defect, &steps).iter().map(|f| f.at_us).collect();
    assert_eq!(times, [at(&inputs[1]), at(&inputs[3])]);
    let mut two = defect.clone();
    two["window"]["reports"] = 2.into();
    two["condition"]["at_least"] = 2.into();
    let without = controls::Step::Report {
        host: 1,
        state: Box::new(controls::host_state()),
        entries: Vec::new(),
    };
    let rising = [defects(0, true), defects(1, true), defects(2, true)];
    assert_eq!(fired(&two, &rising).len(), 1);
    let omitted = [
        defects(0, true),
        defects(1, true),
        without,
        defects(2, true),
    ];
    assert_eq!(fired(&two, &omitted), []);
    let mut forged = row(&catalog(), "report-forged");
    forged["window"]["reports"] = 2.into();
    forged["condition"]["at_least"] = 2.into();
    let other = controls::Step::Status(vec![part(2, 3)]);
    assert_eq!(
        fired(&forged, &[tagged(1, 0), tagged(2, 1), tagged(3, 2)]).len(),
        1
    );
    let gap = [tagged(1, 0), tagged(2, 1), other, tagged(4, 2)];
    assert_eq!(fired(&forged, &gap), []);
}

/// `status-absent` judges a zone's deadline before the arriving status refreshes it, and rearms once the zone
/// recovers.
#[test]
fn a_status_after_a_long_gap_fires_the_absence_once() {
    let absent = row(&catalog(), "status-absent");
    let window = absent["window"]["us"].as_u64().unwrap();
    let (inputs, refused) = controls::sealed(&[tagged(1, 0), tagged(2, 0), tagged(3, 0)]);
    assert_eq!(refused, []);
    let spaced = |gaps: [u64; 2]| {
        let mut history = inputs.clone();
        retime(&mut history[1], at(&inputs[0]) + gaps[0]);
        retime(&mut history[2], at(&inputs[0]) + gaps[0] + gaps[1]);
        let on: Vec<u64> = (evaluate(&absent, &history, Deltas::ResetAware).iter())
            .map(|f| f.at_us)
            .collect();
        (on, history.iter().map(at).collect::<Vec<u64>>())
    };
    let (on, _) = spaced([window, window]);
    assert_eq!(on, Vec::<u64>::new());
    let (on, at) = spaced([window + 1, 1]);
    assert_eq!(on, [at[1]]);
    let (on, at) = spaced([window + 1, window + 1]);
    assert_eq!(on, [at[1], at[2]]);
}

/// A record-field guard that holds a report also leaves the runs of the entries that report omits unchanged.
#[test]
fn a_guarded_report_that_omits_an_entry_leaves_its_run() {
    let due = || {
        report(VolumeEntry {
            roll_due: Some(true),
            ..controls::owner()
        })
    };
    let mut state = controls::host_state();
    state.health = Some(crate::failover::report::Health::Unhealthy);
    let held = controls::Step::Report {
        host: 1,
        state: Box::new(state),
        entries: Vec::new(),
    };
    let steps = [due(), due(), held, due()];
    let (inputs, _) = controls::sealed(&steps);
    for missing in ["quiet", "breach"] {
        let mut handoff = row(&catalog(), "handoff-due");
        handoff["guard"] = serde_json::json!([{"field": "health", "in": ["unhealthy"]}]);
        handoff["missing"] = missing.into();
        let times: Vec<u64> = fired(&handoff, &steps).iter().map(|f| f.at_us).collect();
        assert_eq!(times, [at(&inputs[3])], "{missing}");
    }
}

/// A loop's counts only rise, so a status count that falls at an unchanged tick marks a new loop.
#[test]
fn a_status_count_that_falls_at_its_tick_counts_from_zero() {
    for id in ["report-forged", "store-unknown-rate-reconciler"] {
        let mut rate = row(&catalog(), id);
        rate["condition"]["at_least"] = 3.into();
        rate["window"] = serde_json::json!({"reports": 1});
        rate["basis"] =
            serde_json::json!({"condition.at_least": "derived", "window.reports": "derived"});
        let steps = [(7, 4), (7, 1), (8, 4), (9, 5)].map(|(tick, count)| {
            let mut part = part(1, tick);
            match id {
                "report-forged" => {
                    part.events.refused[controls::slot(REFUSED, Refused::Tag)] = count
                }
                _ => part.store.outcomes[0] = count,
            }
            controls::Step::Status(vec![part])
        });
        let (inputs, _) = controls::sealed(&steps);
        let times: Vec<u64> = fired(&rate, &steps).iter().map(|f| f.at_us).collect();
        assert_eq!(times, [at(&inputs[2])], "{id}");
    }
}

/// One sealed report delivered twice: the reader refuses the second with `ReportError::Duplicate`, and the row's
/// count rises once, so a `delta >= 2` row stays silent. The evaluator also drops a repeated view it reaches
/// directly: two reports and a repeat do not meet a three-report window.
/// Two statuses and a repeat do not meet `shard-blocked`'s three-status window either.
#[test]
fn a_duplicate_report_counts_once() {
    let mut defect = row(&catalog(), "read-defect");
    defect["condition"]["at_least"] = 2.into();
    let defects = |count: u64| {
        report(crate::failover::report::VolumeEntry {
            read_defects: Some(count),
            ..controls::owner()
        })
    };
    let steps = [defects(0), defects(1), controls::Step::Again { host: 1 }];
    let (inputs, refused) = controls::sealed(&steps);
    assert_eq!(refused, [crate::failover::report::ReportError::Duplicate]);
    assert_eq!(inputs.len(), 2);
    let mut repeated = inputs.clone();
    repeated.push(inputs[1].clone());
    assert_eq!(evaluate(&defect, &repeated, Deltas::ResetAware), []);
    defect["condition"]["at_least"] = 1.into();
    assert_eq!(evaluate(&defect, &repeated, Deltas::ResetAware).len(), 1);
    let handoff = row(&catalog(), "handoff-due");
    assert_eq!(handoff["window"]["reports"], 3);
    let due = || {
        report(VolumeEntry {
            roll_due: Some(true),
            ..controls::owner()
        })
    };
    let (inputs, refused) = controls::sealed(&[due(), due(), due()]);
    assert_eq!(refused, []);
    let mut repeated = inputs[..2].to_vec();
    repeated.push(inputs[1].clone());
    retime(&mut repeated[2], at(&inputs[2]));
    assert_eq!(evaluate(&handoff, &repeated, Deltas::ResetAware), []);
    let on_three = evaluate(&handoff, &inputs, Deltas::ResetAware);
    assert_eq!(
        on_three.iter().map(|f| f.at_us).collect::<Vec<_>>(),
        [at(&inputs[2])]
    );
    let blocked = row(&catalog(), "shard-blocked");
    assert_eq!(blocked["window"]["reports"], 3);
    let history = controls::history(&blocked, "shard_blocked");
    let (inputs, _) = controls::sealed(&history[..2]);
    let mut repeated = inputs.clone();
    repeated.push(inputs[1].clone());
    assert_eq!(evaluate(&blocked, &repeated, Deltas::ResetAware), []);
}

/// A record outside a row's `where` filter ends the row's run and clears its latch, and a record its `guard` holds
/// on is skipped: a window-1 `hold-device` row over a held refusal, a refusal whose next step stops, and a held
/// refusal fires twice, as it does over a held refusal, a completed restart and a held refusal. Five silent-shard
/// statuses, one under warm-up, then one more join one run of six and fire `shard-silent` on the seventh status,
/// while the five and the guarded status alone stay silent.
#[test]
fn a_where_filter_ends_a_run_and_a_guard_skips_its_record() {
    let catalog = catalog();
    let device = row(&catalog, "hold-device");
    let held = || {
        report(VolumeEntry {
            recovery: controls::hold_device().fault,
            ..controls::owner()
        })
    };
    let stopped = report(VolumeEntry {
        recovery: crate::failover::report::Recovery {
            next: Some(crate::failover::report::RecoveryNext::Stop),
            ..controls::hold_device().fault
        },
        ..controls::owner()
    });
    let completed = report(VolumeEntry {
        recovery: controls::completed(),
        ..controls::owner()
    });
    for between in [stopped, completed] {
        let steps = [held(), between, held()];
        let (inputs, _) = controls::sealed(&steps);
        let times: Vec<u64> = fired(&device, &steps).iter().map(|f| f.at_us).collect();
        assert_eq!(times, [at(&inputs[0]), at(&inputs[2])]);
    }
    let silent = row(&catalog, "shard-silent");
    assert_eq!(silent["window"]["reports"], 6);
    let status = |tick: u64, warm_up: bool| {
        let mut part = part(1, tick);
        part.classes[controls::slot(CLASSES, Class::Silent)] = 1;
        part.flags.warm_up = warm_up;
        controls::Step::Status(vec![part])
    };
    let mut steps: Vec<controls::Step> = (1..=5).map(|tick| status(tick, false)).collect();
    steps.push(status(6, true));
    assert_eq!(
        fired(&silent, &steps),
        [],
        "a guarded record advances no run"
    );
    steps.push(status(7, false));
    let (inputs, _) = controls::sealed(&steps);
    let times: Vec<u64> = fired(&silent, &steps).iter().map(|f| f.at_us).collect();
    assert_eq!(
        times,
        [at(&inputs[6])],
        "the records around the guard join one run"
    );
}

/// One silent host of three, one forged tag, then no status for the row's window fire `host-silent`,
/// `report-forged` and `status-absent`, the last through `missing = breach`. The absence fires on the first input
/// past the last status plus the row's window and is silent on an input at that instant.
#[test]
fn a_silent_host_a_forged_tag_and_an_absent_status_fire() {
    let catalog = catalog();
    let absent = row(&catalog, "status-absent");
    let window = absent["window"]["us"].as_u64().unwrap();
    let step = |tag: u32, silent: u64| {
        let mut part = part(1, 1);
        part.hosts.silent = crate::failover::report::Members::Known {
            used: silent,
            limit: 3,
        };
        part.events.refused[controls::slot(REFUSED, Refused::Tag)] = tag;
        controls::Step::Status(vec![part])
    };
    let mut steps = vec![step(0, 0), step(1, 1)];
    steps.extend((0..window / 10_000_000 + 2).map(|_| controls::Step::Tick));
    let (inputs, _) = controls::sealed(&steps);
    for id in ["host-silent", "report-forged", "status-absent"] {
        let row = row(&catalog, id);
        assert_eq!(evaluate(&row, &inputs, Deltas::ResetAware).len(), 1, "{id}");
    }
    let last = at(&inputs[1]);
    let mut boundary = inputs[..2].to_vec();
    boundary.push(Input::Tick {
        at_us: last + window,
    });
    assert_eq!(
        evaluate(&absent, &boundary, Deltas::ResetAware),
        [],
        "silent at the window"
    );
    boundary.push(Input::Tick {
        at_us: last + window + 1,
    });
    let on_absent = evaluate(&absent, &boundary, Deltas::ResetAware);
    assert_eq!(
        on_absent.iter().map(|f| f.at_us).collect::<Vec<_>>(),
        [last + window + 1]
    );
}

use crate::failover::report::VolumeEntry;
use crate::failover::report::status::{
    CLASSES, Class, RECEIPTS, REFUSED, ReceiptCount, Refused, ZonePart,
};

/// A signal that reads unavailable follows `missing`: a page row whose policy is `breach` fires on a detector with
/// no source, so it never reads the missing value as healthy, and the shipped `self-suspect-host` row, whose policy
/// is `quiet` because a host seals reports before its detector's first tick, stays silent. A row reads its own
/// source only: a status among the reports adds no firing to the breach copy, and a status that carries a report's
/// writer and sequence leaves that report to fire at its own time.
#[test]
fn an_unavailable_signal_follows_the_missing_policy() {
    let catalog = catalog();
    let quiet = row(&catalog, "self-suspect-host");
    assert_eq!(
        (quiet["severity"].as_str(), quiet["missing"].as_str()),
        (Some("page"), Some("quiet"))
    );
    let steps: Vec<controls::Step> = (0..3)
        .map(|_| controls::Step::Report {
            host: 1,
            state: Box::new(controls::host_state()),
            entries: Vec::new(),
        })
        .collect();
    assert_eq!(fired(&quiet, &steps), []);
    let mut breach = quiet.clone();
    breach["missing"] = "breach".into();
    let on_unavailable = fired(&breach, &steps);
    assert_eq!(on_unavailable.len(), 1);
    assert_eq!(on_unavailable[0].severity, "page");
    let mut mixed = vec![controls::Step::Status(vec![part(1, 1)])];
    mixed.extend(steps.iter().cloned());
    let (inputs, refused) = controls::sealed(&mixed);
    assert_eq!((inputs.len(), refused), (4, vec![]));
    let on_mixed = evaluate(&breach, &inputs, Deltas::ResetAware);
    assert_eq!(
        on_mixed.iter().map(|f| f.at_us).collect::<Vec<_>>(),
        [at(&inputs[1])]
    );
    let Input::Record { view, .. } = &inputs[1] else {
        panic!("a report")
    };
    let forged = Input::Record {
        at_us: at(&inputs[0]),
        source: "status",
        view: view.clone(),
    };
    let shadowed = [vec![forged], inputs[1..].to_vec()].concat();
    let on_shadowed = evaluate(&breach, &shadowed, Deltas::ResetAware);
    assert_eq!(
        on_shadowed.iter().map(|f| f.at_us).collect::<Vec<_>>(),
        [at(&inputs[1])]
    );
}

/// No row whose number is assumed is evaluated above `ticket`: each such row of the catalog ships at `ticket`, and a
/// copy raised to `page` still fires once on its control at `ticket` while the validator refuses it.
#[test]
fn no_row_with_an_assumed_number_is_evaluated_above_ticket() {
    let catalog = catalog();
    let rows = catalog["rows"].as_array().unwrap();
    let assumed_rows: Vec<&Value> = rows.iter().filter(|row| assumed(row)).collect();
    assert!(assumed_rows.len() >= 10);
    for row in &assumed_rows {
        assert_eq!(
            (row["severity"].as_str(), severity(row)),
            (Some("ticket"), "ticket"),
            "{}",
            row["id"]
        );
        let mut raised = (*row).clone();
        raised["severity"] = "page".into();
        assert_eq!(severity(&raised), "ticket");
        let control = controls::history(&raised, raised["control"].as_str().unwrap());
        let on_control = fired(&raised, &control);
        assert_eq!(on_control.len(), 1, "{}", row["id"]);
        assert_eq!(on_control[0].severity, "ticket", "{}", row["id"]);
    }
    assert!(rows.iter().any(|row| severity(row) == "page"));
}

/// A zone part of `zone` at `tick` from a tick that read the census and every shard's records.
fn part(zone: u16, tick: u64) -> ZonePart {
    let mut part = ZonePart {
        tick,
        ..ZonePart::blank(crate::failover::standbys::Zone(zone))
    };
    part.flags.store = true;
    part
}

/// A status of zone 1 at `tick` whose tag refusal count is `tag`.
fn tagged(tick: u64, tag: u32) -> controls::Step {
    let mut part = part(1, tick);
    part.events.refused[controls::slot(REFUSED, Refused::Tag)] = tag;
    controls::Step::Status(vec![part])
}

fn at(input: &Input) -> u64 {
    match input {
        Input::Record { at_us, .. } | Input::Tick { at_us } => *at_us,
    }
}

fn retime(input: &mut Input, to: u64) {
    match input {
        Input::Record { at_us, .. } | Input::Tick { at_us } => *at_us = to,
    }
}

/// Counts compare over the whole `u64` range: `read-defect` fires on a rise from 0 to 2^63, a copy whose assumed
/// threshold is 2^63 validates and fires on the same rise, and rises of 2^62 and 2^62 reach a `store-unknown-rate` threshold
/// of `i64::MAX` on the second. Capacity comparisons use the catalog's exact decimal threshold.
#[test]
fn counts_and_fractions_compare_exactly() {
    let defect = row(&catalog(), "read-defect");
    let defects = |count: u64| {
        report(VolumeEntry {
            read_defects: Some(count),
            ..controls::owner()
        })
    };
    let steps = [defects(0), defects(1 << 63)];
    assert_eq!(fired(&defect, &steps).len(), 1);
    let mut high = catalog();
    let at_row = row_at(&high, "read-defect");
    high["rows"][at_row]["condition"]["at_least"] = (1_u64 << 63).into();
    high["rows"][at_row]["basis"]["condition.at_least"] = "assumed".into();
    assert_eq!(validate(&high, &controls::names()), []);
    assert_eq!(fired(&high["rows"][at_row], &steps).len(), 1);
    let mut rate = row(&catalog(), "store-unknown-rate");
    rate["condition"]["at_least"] = i64::MAX.into();
    let counts = [0, 1 << 62, 1 << 63].map(|count| report(unknown_count(count, 2)));
    let (inputs, _) = controls::sealed(&counts);
    let on_rate = fired(&rate, &counts);
    assert_eq!(
        on_rate.iter().map(|f| f.at_us).collect::<Vec<_>>(),
        [at(&inputs[2])]
    );
    for (used, limit) in [(9, 10), (90, 100), (54, 60), (9 << 56, 10 << 56)] {
        assert!(reaches(used, limit, 0.9, true), "{used} of {limit}");
        assert!(
            !reaches(used - 1, limit, 0.9, true),
            "{used} - 1 of {limit}"
        );
        assert!(!reaches(used, limit, 0.9, false), "{used} of {limit}");
        assert!(
            reaches(used + 1, limit, 0.9, false),
            "{used} + 1 of {limit}"
        );
    }
    assert!(!reaches(8, 10, 0.9, true) && !reaches(1, 2, 0.5, false));
    assert!(reaches(1, 3, 0.0, false) && !reaches(0, 3, 0.0, false));
    assert!(reaches(4, 4, 1.0, true) && !reaches(3, 4, 1.0, true));
    assert!(reaches(u64::MAX, u64::MAX, 1.0, true));
    assert_eq!((decimal(1e-20), decimal(0.1234567890123456)), (None, None));
    let empty = serde_json::json!({"used": 0, "limit": 0});
    for id in ["chain-at-cap", "census-near-cap"] {
        let row = row(&catalog(), id);
        assert!(
            !Rule::of(&row).meets(&empty),
            "{id}: a gauge of 0 of 0 is neither full nor at a fraction of its limit"
        );
    }
    assert_eq!(decimal(1e-19), Some((1, 19)), "nineteen decimal places");
    assert_eq!(
        decimal(0.123456789012345),
        Some((123_456_789_012_345, 15)),
        "fifteen digits"
    );
    for key in ["\"at_least\": ", "\"above\": "] {
        for token in CATALOG.split(key).skip(1) {
            let token = &token[..token.find([',', '}']).unwrap()];
            assert_eq!(format!("{}", token.parse::<f64>().unwrap()), token);
        }
    }
    let near = row(&catalog(), "census-near-cap");
    let census = |used: u64| {
        let mut part = part(1, 1);
        part.census = crate::failover::report::Members::Known { used, limit: 10 };
        part.flags.cap_below = true;
        controls::Step::Status(vec![part])
    };
    let steps = [census(8), census(9), census(10)];
    let (inputs, _) = controls::sealed(&steps);
    let times: Vec<u64> = fired(&near, &steps).iter().map(|f| f.at_us).collect();
    assert_eq!(times, [at(&inputs[1])]);
}

/// A record of the row's source that omits a tracked entry or zone applies the row's missing policy to it, so the
/// quiet `handoff-due` row over a due roll, a report without the entry, then three due rolls fires on the fifth
/// report, and `shard-blocked` over a blocked zone, a status without that zone, then three blocked statuses fires on
/// the fifth status. Another host's report leaves host 1's run standing.
/// Breach copies count the omitted entry or zone as holding and fire on the third record, and a breach copy of
/// `chain-at-cap` fires on an unavailable ancestry gauge that the shipped quiet row leaves silent.
#[test]
fn an_omitted_entry_or_zone_follows_the_missing_policy() {
    let catalog = catalog();
    let handoff = row(&catalog, "handoff-due");
    assert_eq!(
        (
            handoff["window"]["reports"].as_u64(),
            handoff["missing"].as_str()
        ),
        (Some(3), Some("quiet"))
    );
    let due = || {
        report(VolumeEntry {
            roll_due: Some(true),
            ..controls::owner()
        })
    };
    let without = |host| controls::Step::Report {
        host,
        state: Box::new(controls::host_state()),
        entries: Vec::new(),
    };
    let steps = [due(), without(1), due(), due(), due()];
    let (inputs, _) = controls::sealed(&steps);
    let times: Vec<u64> = fired(&handoff, &steps).iter().map(|f| f.at_us).collect();
    assert_eq!(times, [at(&inputs[4])]);
    let steps = [due(), due(), without(2), due()];
    let (inputs, _) = controls::sealed(&steps);
    let times: Vec<u64> = fired(&handoff, &steps).iter().map(|f| f.at_us).collect();
    assert_eq!(times, [at(&inputs[3])], "another host's report");
    let blocked = row(&catalog, "shard-blocked");
    assert_eq!(blocked["window"]["reports"], 3);
    let status = |tick: u64, zone: u16| {
        let mut part = part(zone, tick);
        part.classes[controls::slot(CLASSES, Class::Blocked)] = u32::from(zone == 1);
        controls::Step::Status(vec![part])
    };
    let steps = [
        status(1, 1),
        status(2, 2),
        status(3, 1),
        status(4, 1),
        status(5, 1),
    ];
    let (inputs, _) = controls::sealed(&steps);
    let times: Vec<u64> = fired(&blocked, &steps).iter().map(|f| f.at_us).collect();
    assert_eq!(times, [at(&inputs[4])]);
    let breach = |row: &Value| {
        let mut copy = row.clone();
        copy["missing"] = "breach".into();
        copy
    };
    let tracked = fired(&handoff, &[due(), due(), due()]);
    let steps = [due(), without(1), due()];
    let (inputs, _) = controls::sealed(&steps);
    assert_eq!(fired(&handoff, &steps), []);
    let on_breach = fired(&breach(&handoff), &steps);
    assert_eq!(
        on_breach
            .iter()
            .map(|f| (f.series.as_str(), f.at_us))
            .collect::<Vec<_>>(),
        [(tracked[0].series.as_str(), at(&inputs[2]))]
    );
    let steps = [status(1, 1), status(2, 2), status(3, 1)];
    let (inputs, _) = controls::sealed(&steps);
    assert_eq!(fired(&blocked, &steps), []);
    let on_breach = fired(&breach(&blocked), &steps);
    let zone_1 = fired(&blocked, &[status(1, 1), status(2, 1), status(3, 1)]);
    assert_eq!(
        on_breach
            .iter()
            .map(|f| (f.series.as_str(), f.at_us))
            .collect::<Vec<_>>(),
        [(zone_1[0].series.as_str(), at(&inputs[2]))]
    );
    let chain = row(&catalog, "chain-at-cap");
    let unread = [report(VolumeEntry {
        pressure: crate::failover::report::Pressure {
            ancestry: crate::failover::report::Gauge::Unavailable,
            ..controls::owner().pressure
        },
        ..controls::owner()
    })];
    assert_eq!(fired(&chain, &unread), []);
    assert_eq!(fired(&breach(&chain), &unread).len(), 1);
}

/// A `us` window expires its rises before each input, a record or an evaluation instant, so `store-unknown-rate`
/// over a rise of 3 and a second rise of 3 more than the window later fires twice, with or without an instant in
/// the gap, and once when the second rise falls within the window. The reconciler's rate row does the same over
/// status counts.
#[test]
fn a_rate_row_fires_again_after_its_window_expires() {
    let catalog = catalog();
    for id in ["store-unknown-rate", "store-unknown-rate-reconciler"] {
        let rate = row(&catalog, id);
        let window = rate["window"]["us"].as_u64().unwrap();
        let steps = rate_steps(id, &[0, 3, 6]);
        let (inputs, refused) = controls::sealed(&steps);
        assert_eq!(refused, []);
        let burst = at(&inputs[1]);
        let firings = |third: u64, tick: Option<u64>| {
            let mut history = inputs.clone();
            retime(&mut history[2], third);
            if let Some(tick) = tick {
                history.insert(2, Input::Tick { at_us: tick });
            }
            evaluate(&rate, &history, Deltas::ResetAware).len()
        };
        assert_eq!(
            firings(burst + window + 1, None),
            2,
            "{id}: no input in the gap"
        );
        assert_eq!(
            firings(burst + window + 2, Some(burst + window + 1)),
            2,
            "{id}: an instant in the gap"
        );
        assert_eq!(
            firings(burst + window, None),
            1,
            "{id}: the second rise within the window"
        );
    }
}

/// The sealed steps of one series of a rate row whose counts read `counts`: host 1's owner entry, or zone 1's
/// reconciler unknown count at rising ticks.
fn rate_steps(id: &str, counts: &[u64]) -> Vec<controls::Step> {
    (counts.iter().zip(1..))
        .map(|(count, tick)| match id {
            "store-unknown-rate" => report(unknown_count(*count, 2)),
            _ => {
                let mut part = part(1, tick);
                part.store.outcomes[0] = u32::try_from(*count).unwrap();
                controls::Step::Status(vec![part])
            }
        })
        .collect()
}

/// Each rate row sums the rises within its `us` window, inclusive: rises of 1, 1 and 1 whose first and last lie
/// exactly one window apart reach the row's 3, and the same rises one microsecond wider stay silent.
#[test]
fn a_rate_row_sums_the_rises_within_its_window() {
    let catalog = catalog();
    for id in ["store-unknown-rate", "store-unknown-rate-reconciler"] {
        let rate = row(&catalog, id);
        assert_eq!(rate["condition"]["at_least"], 3, "{id}");
        let window = rate["window"]["us"].as_u64().unwrap();
        let (inputs, refused) = controls::sealed(&rate_steps(id, &[0, 1, 2, 3]));
        assert_eq!(refused, []);
        let first = at(&inputs[1]);
        let spread = |last: u64| {
            let mut history = inputs.clone();
            retime(&mut history[3], last);
            evaluate(&rate, &history, Deltas::ResetAware)
        };
        let exact = spread(first + window);
        assert_eq!(
            exact.iter().map(|f| f.at_us).collect::<Vec<_>>(),
            [first + window],
            "{id}"
        );
        assert_eq!(
            spread(first + window + 1),
            [],
            "{id}: the first rise has left the window"
        );
    }
}

/// `retention-damage` fires once per activated tenure on a known damaged account: within one tenure a later report
/// whose account is null keeps the known account, so damaged, null and damaged fire once, at the first report, and
/// a damaged account of a new tenure fires again on the fourth report with no clean report between.
/// A tenure that already fired stays silent after an omitted entry and after an interleaved tenure of another boot.
#[test]
fn a_known_retention_account_fires_once_per_tenure() {
    let damage = row(&catalog(), "retention-damage");
    let damaged = controls::retention_damage().fault;
    let account = |retention, epoch| {
        let mut entry = unknown_count(0, epoch);
        entry.retention = retention;
        report(entry)
    };
    let steps = [
        account(damaged, 2),
        account(None, 2),
        account(damaged, 2),
        account(damaged, 4),
    ];
    let (inputs, _) = controls::sealed(&steps);
    let times: Vec<u64> = fired(&damage, &steps).iter().map(|f| f.at_us).collect();
    assert_eq!(times, [at(&inputs[0]), at(&inputs[3])]);
    let without = || controls::Step::Report {
        host: 1,
        state: Box::new(controls::host_state()),
        entries: Vec::new(),
    };
    for after in [None, damaged] {
        let steps = [account(damaged, 2), without(), account(after, 2)];
        let (inputs, _) = controls::sealed(&steps);
        let times: Vec<u64> = fired(&damage, &steps).iter().map(|f| f.at_us).collect();
        assert_eq!(times, [at(&inputs[0])], "{after:?}");
    }
    let boot = |boot| controls::Step::Boot { host: 1, boot };
    let steps = [
        boot(1),
        account(damaged, 2),
        boot(2),
        account(damaged, 4),
        boot(1),
        account(damaged, 2),
    ];
    let (inputs, refused) = controls::sealed(&steps);
    assert_eq!((inputs.len(), refused), (3, vec![]));
    let times: Vec<u64> = fired(&damage, &steps).iter().map(|f| f.at_us).collect();
    assert_eq!(times, [at(&inputs[0]), at(&inputs[1])]);
}

/// A row keeps one series per entry and per zone part: two entries of one host and tenure on different shards whose
/// constant unknown counts, 0 and 3, differ by the row's threshold leave `store-unknown-rate` silent, and two zones
/// blocked in each of three statuses fire `shard-blocked` once each, on the third status.
/// Two entries on one shard that differ only in volume also stay silent, so the volume is part of the entry key.
#[test]
fn each_entry_and_zone_is_its_own_series() {
    let catalog = catalog();
    let rate = row(&catalog, "store-unknown-rate");
    let mut second = unknown_count(rate["condition"]["at_least"].as_u64().unwrap(), 2);
    let mut same_shard = second;
    same_shard.volume = crate::failover::records::VolumeId::new("vol-0b").unwrap();
    let pair = controls::Step::Report {
        host: 1,
        state: Box::new(controls::host_state()),
        entries: vec![unknown_count(0, 2), same_shard],
    };
    assert_eq!(fired(&rate, &[pair.clone(), pair]), []);
    second.shard = crate::net::ownership::Shard::new(2).unwrap();
    second.volume = crate::failover::records::VolumeId::new("vol-0b").unwrap();
    let sample = controls::Step::Report {
        host: 1,
        state: Box::new(controls::host_state()),
        entries: vec![unknown_count(0, 2), second],
    };
    assert_eq!(fired(&rate, &[sample.clone(), sample]), []);
    let blocked = row(&catalog, "shard-blocked");
    let both = |tick| {
        let zones = [1, 2].map(|zone| {
            let mut part = part(zone, tick);
            part.classes[controls::slot(CLASSES, Class::Blocked)] = 1;
            part
        });
        controls::Step::Status(zones.to_vec())
    };
    let steps = [both(1), both(2), both(3)];
    let (inputs, _) = controls::sealed(&steps);
    let on_both = fired(&blocked, &steps);
    let mut series: Vec<&str> = on_both.iter().map(|f| f.series.as_str()).collect();
    series.dedup();
    assert_eq!(series.len(), 2, "{on_both:?}");
    assert!(
        on_both.iter().all(|f| f.at_us == at(&inputs[2])),
        "{on_both:?}"
    );
}

/// When `zones.flags.store` is false, an observed held receipt can trigger `replacement-held`; a zero count preserves
/// the row's firing state. An unavailable census on such a tick preserves `census-near-cap` the same way.
/// `shard-silent` fires once across six consecutive store-false ticks that each report one `Class::Silent`.
#[test]
fn an_incomplete_tick_fires_on_a_proven_count_and_holds_the_rest() {
    let held = row(&catalog(), "replacement-held");
    let status = |count: u32, store: bool| {
        let mut part = part(1, 1);
        part.receipts[controls::slot(RECEIPTS, ReceiptCount::Held)] = count;
        part.flags.store = store;
        controls::Step::Status(vec![part])
    };
    let times = |row: &Value, steps: &[controls::Step]| {
        let (inputs, _) = controls::sealed(steps);
        let on: Vec<u64> = fired(row, steps).iter().map(|f| f.at_us).collect();
        (on, inputs.iter().map(at).collect::<Vec<u64>>())
    };
    let (on, at) = times(&held, &[status(1, true), status(1, false), status(1, true)]);
    assert_eq!(on, [at[0]]);
    let (on, at) = times(&held, &[status(0, true), status(1, false), status(0, true)]);
    assert_eq!(on, [at[1]]);
    let (on, at) = times(
        &held,
        &[status(1, false), status(1, false), status(1, false)],
    );
    assert_eq!(on, [at[0]]);
    let gap = [status(1, true), status(0, false), status(1, true)];
    assert_eq!(fired(&held, &gap).len(), 1);
    let mut unguarded = held.clone();
    unguarded["guard"] = serde_json::json!([]);
    assert_eq!(fired(&unguarded, &gap).len(), 2);
    let near = row(&catalog(), "census-near-cap");
    let census = |census, store| {
        let mut part = part(1, 1);
        (part.census, part.flags.cap_below, part.flags.store) = (census, true, store);
        controls::Step::Status(vec![part])
    };
    let full = controls::census_near_cap().fault;
    let unread = crate::failover::report::Members::Unavailable;
    let steps = [
        census(full, true),
        census(unread, false),
        census(full, true),
    ];
    assert_eq!(fired(&near, &steps).len(), 1);
    let mut unguarded = near.clone();
    unguarded["guard"] = serde_json::json!([]);
    assert_eq!(fired(&unguarded, &steps).len(), 2);
    let silent = row(&catalog(), "shard-silent");
    let unread = |tick| {
        let mut part = part(1, tick);
        part.classes[controls::slot(CLASSES, Class::Silent)] = 1;
        part.flags.store = false;
        controls::Step::Status(vec![part])
    };
    let six: Vec<controls::Step> = (1..=6).map(unread).collect();
    assert_eq!(fired(&silent, &six).len(), 1);
    let mut guarded = silent.clone();
    guarded["guard"] = serde_json::json!([{"field": "zones.flags.store", "in": [false]}]);
    assert_eq!(fired(&guarded, &six).len(), 1);
}

fn record_fed() -> Vec<String> {
    let text = CONTRACTS[1].1["units"]["zones.flags.store"]
        .as_str()
        .unwrap();
    let listed = &text[text.find('(').unwrap() + 1..text.find(')').unwrap()];
    let mut families: Vec<String> = (listed.split(',').flat_map(|part| part.split(" and ")))
        .map(|part| format!("zones.{}", part.split_whitespace().next().unwrap()))
        .collect();
    families.push("zones.census".into());
    families
}

/// For the record-fed status rows tested here, the store guard preserves the firing state across a store-false tick
/// that reports the clean value, as the instance guard does across an instances-false tick for a row that carries
/// it: the row fires once, and twice without its completeness guards.
#[test]
fn each_record_fed_status_row_holds_an_inconclusive_tick() {
    let families = record_fed();
    assert!(families.len() >= 10, "{families:?}");
    let unread = ["zones.classes.silent", "zones.blockers.store-unavailable"];
    let catalog = catalog();
    let mut covered = Vec::new();
    for row in catalog["rows"].as_array().unwrap() {
        let signal = row["signal"].as_str().unwrap();
        let fed = (families.iter())
            .any(|family| signal == family || signal.starts_with(&format!("{family}.")));
        if row["source"] != "status" || !fed || unread.contains(&signal) {
            continue;
        }
        let control = controls::history(row, row["control"].as_str().unwrap());
        let mut gap = controls::history(row, row["clean"].as_str().unwrap()).remove(0);
        let controls::Step::Status(parts) = &mut gap else {
            panic!("a status row")
        };
        parts[0].flags.store = false;
        let steps = [control.clone(), vec![gap], control.clone()].concat();
        assert_eq!(fired(row, &steps).len(), 1, "{signal}");
        if filters(&row["guard"])
            .iter()
            .any(|f| f["field"] == "zones.flags.instances")
        {
            let mut gap = controls::history(row, row["clean"].as_str().unwrap()).remove(0);
            let controls::Step::Status(parts) = &mut gap else {
                panic!("a status row")
            };
            parts[0].flags.instances = false;
            let unlisted = [control.clone(), vec![gap], control.clone()].concat();
            assert_eq!(fired(row, &unlisted).len(), 1, "{signal} instances unread");
        }
        let mut unguarded = row.clone();
        let store = |filter: &&Value| !COMPLETENESS.contains(&filter["field"].as_str().unwrap());
        let kept: Vec<Value> = filters(&row["guard"])
            .iter()
            .filter(store)
            .cloned()
            .collect();
        unguarded["guard"] = Value::Array(kept);
        assert_eq!(fired(&unguarded, &steps).len(), 2, "{signal} unguarded");
        covered.push(row["id"].as_str().unwrap());
    }
    assert_eq!(covered.len(), 13, "{covered:?}");
    for signal in unread {
        let rows = catalog["rows"].as_array().unwrap();
        let row = rows.iter().find(|row| row["signal"] == signal).unwrap();
        let guards = filters(&row["guard"]).iter();
        assert!(
            guards.clone().all(|f| f["field"] != "zones.flags.store"),
            "{signal}"
        );
    }
}

/// `census-near-cap` reads only a zone whose census cap is below its shard count: a census at its limit under a cap
/// at the shard count, the default, stays silent, and the same census under a cap below the shard count fires.
#[test]
fn a_full_census_under_the_default_cap_is_not_near_its_cap() {
    let near = row(&catalog(), "census-near-cap");
    let status = |cap_below: bool| {
        let mut part = part(1, 1);
        part.census = crate::failover::report::Members::Known {
            used: 64,
            limit: 64,
        };
        part.flags.cap_below = cap_below;
        controls::Step::Status(vec![part])
    };
    assert_eq!(fired(&near, &[status(false), status(false)]), []);
    assert_eq!(fired(&near, &[status(true), status(true)]).len(), 1);
}

/// `registrant-ended` under a window of one, two and six reports: the control fires once and the clean twin, which
/// clears one report short of the window, raises nothing; six serving reports of an ended registrant whose sixth
/// entry reads withdrawn raise nothing, and since a record outside the serving filter ends the run, five more
/// serving reports after it stay silent and the sixth fires.
#[test]
fn an_ended_registrant_fires_at_its_window_and_a_withdrawn_entry_ends_the_run() {
    let shipped = row(&catalog(), "registrant-ended");
    assert_eq!(shipped["window"]["reports"], 6);
    for window in [1, 2, 6] {
        let mut row = shipped.clone();
        row["window"]["reports"] = window.into();
        let control = controls::history(&row, "registrant_ended");
        assert_eq!(fired(&row, &control).len(), 1, "window {window}");
        let clean = controls::history(&row, "registrant_ended.clean");
        assert_eq!(fired(&row, &clean), [], "window {window}");
    }
    let mut withdrawn = controls::history(&shipped, "registrant_ended");
    let Some(controls::Step::Report { entries, .. }) = withdrawn.last_mut() else {
        panic!("the control ends with a report");
    };
    entries[0].serving = Some(crate::failover::serving::State::Withdrawn);
    assert_eq!(fired(&shipped, &withdrawn), []);
    // Five serving reports, a withdrawn one, then serving reports again: a run the withdrawn entry only paused
    // would reach six at the first of them, and a run it ended reaches six at the sixth.
    let serving = controls::history(&shipped, "registrant_ended");
    let resumed = |after: usize| {
        let mut steps = withdrawn.clone();
        steps.extend(serving.iter().take(after).cloned());
        fired(&shipped, &steps).len()
    };
    assert_eq!((resumed(1), resumed(5), resumed(6)), (0, 0, 1));
}

/// A healthy waiting standby fires no report row: a run of reports of a host whose one entry is the waiting
/// standby's, as `host::recover::standing` builds it with the phase `Standby` the host agent seals, and whose host
/// part is the zone loop fixture's, keeps every report row silent. The run is one report longer than the longest
/// report-count window of any report row, so each run row could reach its window. The same run with the entry's
/// watermark read `regression` fires `store-regression`, so the rows read the entry.
#[test]
fn a_healthy_waiting_standby_fires_no_report_row() {
    use crate::failover::report::{RecordedRole, Watermark};
    use crate::failover::takeover::tests::{c_host, holder_of, shard_record, with_c};
    let catalog = catalog();
    let record = shard_record();
    let status =
        crate::host::recover::standing((&holder_of(c_host()), record.shard, 7), &with_c(), &record);
    let entry = VolumeEntry {
        phase: Some(status.phase),
        ended: status.ended,
        ..status.entry.unwrap()
    };
    assert_eq!(
        (entry.role, entry.named),
        (Some(RecordedRole::Standby), Some(true))
    );
    let rows = catalog["rows"].as_array().unwrap();
    let report_rows: Vec<_> = rows
        .iter()
        .filter(|row| row["source"] == "report")
        .collect();
    assert!(!report_rows.is_empty());
    let longest = (report_rows.iter())
        .filter_map(|row| row["window"]["reports"].as_u64())
        .max()
        .unwrap();
    let reports = |entry: VolumeEntry| -> Vec<controls::Step> {
        (0..=longest).map(|_| report(entry)).collect()
    };
    for row in report_rows {
        assert_eq!(fired(row, &reports(entry)), [], "{}", row["id"]);
    }
    let regressed = VolumeEntry {
        watermark: Watermark::Regression,
        ..entry
    };
    let store = row(&catalog, "store-regression");
    assert!(!fired(&store, &reports(regressed)).is_empty());
}
