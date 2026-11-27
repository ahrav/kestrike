//! The refusals of a run's first step, one row each, in the self-test's order: the operator file, the
//! package against its approval and windows, GD-2's texts and prerequisites, the package's read and
//! the evidence directory. A row names the reader that decides it, the part of the refusal's line the
//! self-test checks, and for a reader's row the whole sentence that reader returns.

use kestrike_tools::json::{Object, Text, Value};

use super::{BLOCKS, items_mut, json, operator, remove, set, string};

/// GD-2's guardrail texts that a row changes, in the catalog's order.
pub(crate) const TEXTS: [&str; 4] = [
    "any generation change",
    "any CreateVolume by the reconciler principal",
    "any replacement receipt written by the reconciler principal",
    "a takeover of a shard with no role on the stopped host",
];

/// What decides a row: the operator file's read and then the package's check at [`super::START`],
/// GD-2's entry of the catalog, the package's read, or the run itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reader {
    Operator,
    Catalog,
    PackageRead,
    Run,
}

/// The evidence directory a row plants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Evidence {
    /// It holds an entry `injection`.
    InjectionExists,
    Missing,
    /// It is named by a link to it.
    Linked,
    /// It is named by an empty path from inside it.
    EmptyPath,
}

/// How a row changes the fixtures.
#[derive(Clone, Copy)]
pub(crate) enum Change {
    /// The operator file holds this text.
    OperatorText(fn() -> String),
    /// The operator file's value changes.
    Operator(fn(&mut Value)),
    /// The package's value changes and the approval names its new digest.
    Package(fn(&mut Value)),
    /// The package and its copy hold these bytes.
    PackageBytes(&'static str),
    /// GD-2's entry changes.
    Catalog(fn(&mut Object)),
    /// The package grows past a file size limit by that many spaces, the limit being
    /// [`super::past_limit`], one byte more than the catalog and the operator file hold.
    PackagePastLimit,
    Evidence(Evidence),
}

#[derive(Clone, Copy)]
pub(crate) struct Row {
    pub(crate) name: &'static str,
    pub(crate) change: Change,
    pub(crate) reader: Reader,
    /// The part of the refusal's line the self-test checks.
    pub(crate) reason: &'static str,
    /// The sentence the reader returns; `None` for a row the run decides and for the package past
    /// the limit, whose sentence names the limit. The words after `is not strict JSON: ` are the
    /// library's reader's.
    pub(crate) sentence: Option<&'static str>,
}

const fn row(
    name: &'static str,
    change: Change,
    reader: Reader,
    reason: &'static str,
    sentence: Option<&'static str>,
) -> Row {
    Row {
        name,
        change,
        reader,
        reason,
        sentence,
    }
}

fn strings(items: &[&str]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|item| Value::String(Text::from(*item)))
            .collect(),
    )
}

fn text(item: &str) -> Value {
    Value::String(Text::from(item))
}

fn number(digits: &str) -> Value {
    super::value(digits)
}

/// The operator file's text with a second member `region`, after the one it holds.
fn repeated_region() -> String {
    let text = json(&operator());
    format!(
        "{}, \"region\": \"us-east-1\"}}\n",
        text.trim_end().trim_end_matches('}')
    )
}

fn renamed_first_alarm(o: &mut Value) {
    let alarm = remove(o, &["alarms", TEXTS[0]]);
    set(o, &["alarms", &format!("{} ", TEXTS[0])], alarm);
}

fn many_instances(o: &mut Value) {
    let ids: Vec<String> = (0..101).map(|n| format!("i-{n:x}")).collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    set(o, &["instances"], strings(&ids));
}

fn prerequisites(gd2: &mut Object) -> &mut Vec<Value> {
    items_mut(
        gd2.get_mut("prerequisites")
            .expect("GD-2 lists its prerequisites"),
    )
}

/// The rows, in the self-test's order.
pub(crate) const ROWS: &[Row] = &[
    row(
        "an operator file that is no JSON",
        Change::OperatorText(|| "not json".to_owned()),
        Reader::Operator,
        "not strict JSON",
        Some("the operator file is not strict JSON: expected a value at byte 0"),
    ),
    row(
        "a repeated key",
        Change::OperatorText(repeated_region),
        Reader::Operator,
        "repeats a key",
        Some("the operator file is not strict JSON: an object repeats a key"),
    ),
    row(
        "a missing key",
        Change::Operator(|o| {
            remove(o, &["observe_seconds"]);
        }),
        Reader::Operator,
        "refused: ",
        Some(
            "the operator file holds the keys ['alarms', 'approval', 'deadline_seconds', 'effect_timeout_seconds', 'identity', 'instances', 'region', 'snapshot', 'snapshot_max_age_seconds'], not ['alarms', 'approval', 'deadline_seconds', 'effect_timeout_seconds', 'identity', 'instances', 'observe_seconds', 'region', 'snapshot', 'snapshot_max_age_seconds']",
        ),
    ),
    row(
        "an extra key",
        Change::Operator(|o| set(o, &["extra"], number("1"))),
        Reader::Operator,
        "refused: ",
        Some(
            "the operator file holds the keys ['alarms', 'approval', 'deadline_seconds', 'effect_timeout_seconds', 'extra', 'identity', 'instances', 'observe_seconds', 'region', 'snapshot', 'snapshot_max_age_seconds'], not ['alarms', 'approval', 'deadline_seconds', 'effect_timeout_seconds', 'identity', 'instances', 'observe_seconds', 'region', 'snapshot', 'snapshot_max_age_seconds']",
        ),
    ),
    row(
        "no approval",
        Change::Operator(|o| set(o, &["approval"], Value::Null)),
        Reader::Operator,
        "holds no approval",
        Some("the operator file holds no approval of this run"),
    ),
    row(
        "an approval of another instance",
        Change::Operator(|o| set(o, &["approval", "instance"], text("i-h2"))),
        Reader::Operator,
        "names instance i-h2",
        Some("the approval names instance i-h2, not the target i-h1"),
    ),
    row(
        "an approval of another package",
        Change::Operator(|o| set(o, &["approval", "package_sha256"], text(&"0".repeat(64)))),
        Reader::Operator,
        "another package",
        Some("the approval names another package digest"),
    ),
    row(
        "an approval past not_after",
        Change::Operator(|o| set(o, &["approval", "not_after"], text("1970-01-01T00:01:44Z"))),
        Reader::Operator,
        "lapses",
        Some("the approval lapses at 1970-01-01T00:01:44Z, less than 5 s after the run's deadline"),
    ),
    row(
        "a target outside the declared set",
        Change::Operator(|o| set(o, &["instances"], strings(&["i-h2", "i-h3", "i-h4"]))),
        Reader::Operator,
        "outside the declared set",
        Some("the target i-h1 is outside the declared set"),
    ),
    row(
        "alarms missing a guardrail",
        Change::Operator(|o| {
            remove(o, &["alarms", TEXTS[3]]);
        }),
        Reader::Operator,
        "refused: ",
        Some(
            "the operator file alarms names ['a shard that changes hands twice', 'a shard without a standby or a named blocker past the re-enrollment drain', 'any CreateVolume by the reconciler principal', 'any generation change', 'any replacement receipt written by the reconciler principal', \"the zone's origin request rate above its baseline past the origin-load budget\", 'two hosts activating one tenure of a shard'], not exactly the guardrails ['a shard that changes hands twice', 'a shard without a standby or a named blocker past the re-enrollment drain', 'a takeover of a shard with no role on the stopped host', 'any CreateVolume by the reconciler principal', 'any generation change', 'any replacement receipt written by the reconciler principal', \"the zone's origin request rate above its baseline past the origin-load budget\", 'two hosts activating one tenure of a shard']",
        ),
    ),
    row(
        "alarms keyed by another text",
        Change::Operator(renamed_first_alarm),
        Reader::Operator,
        "refused: ",
        Some(
            "the operator file alarms names ['a shard that changes hands twice', 'a shard without a standby or a named blocker past the re-enrollment drain', 'a takeover of a shard with no role on the stopped host', 'any CreateVolume by the reconciler principal', 'any generation change ', 'any replacement receipt written by the reconciler principal', \"the zone's origin request rate above its baseline past the origin-load budget\", 'two hosts activating one tenure of a shard'], not exactly the guardrails ['a shard that changes hands twice', 'a shard without a standby or a named blocker past the re-enrollment drain', 'a takeover of a shard with no role on the stopped host', 'any CreateVolume by the reconciler principal', 'any generation change', 'any replacement receipt written by the reconciler principal', \"the zone's origin request rate above its baseline past the origin-load budget\", 'two hosts activating one tenure of a shard']",
        ),
    ),
    row(
        "one alarm for two guardrails",
        Change::Operator(|o| set(o, &["alarms", TEXTS[1]], text("gd2-guardrail-1"))),
        Reader::Operator,
        "one alarm for two",
        Some("alarms names one alarm for two guardrails"),
    ),
    row(
        "an alarm name read as an option",
        Change::Operator(|o| set(o, &["alarms", TEXTS[1]], text("--debug"))),
        Reader::Operator,
        "is no alarm name",
        Some(
            "the alarm of 'any CreateVolume by the reconciler principal' is no alarm name: '--debug'",
        ),
    ),
    row(
        "a deadline shorter than the wait and the observation",
        Change::Operator(|o| set(o, &["deadline_seconds"], number("100"))),
        Reader::Operator,
        "holds less",
        Some(
            "deadline_seconds holds less than effect_timeout_seconds and observe_seconds together",
        ),
    ),
    row(
        "a bound past its limit",
        Change::Operator(|o| set(o, &["deadline_seconds"], number("86401"))),
        Reader::Operator,
        "past its limit",
        Some("deadline_seconds 86401 is past its limit of 86400 s"),
    ),
    row(
        "a bound that is no number",
        Change::Operator(|o| set(o, &["observe_seconds"], text("60"))),
        Reader::Operator,
        "no positive",
        Some("the operator file observe_seconds is no positive of the layout: '60'"),
    ),
    row(
        "an instance ID read as an option",
        Change::Operator(|o| set(o, &["instances"], strings(&["i-h1", "--dry-run"]))),
        Reader::Operator,
        "no instance ID",
        Some("instances[1] is no instance ID: '--dry-run'"),
    ),
    row(
        "an instance ID with an option after it",
        Change::Operator(|o| set(o, &["instances"], strings(&["i-h1", "i-h2 --force"]))),
        Reader::Operator,
        "no instance ID",
        Some("instances[1] is no instance ID: 'i-h2 --force'"),
    ),
    row(
        "a region that is no region name",
        Change::Operator(|o| set(o, &["region"], text("us-west-2 --debug"))),
        Reader::Operator,
        "no AWS region name",
        Some("region 'us-west-2 --debug' is no AWS region name"),
    ),
    row(
        "a repeated instance",
        Change::Operator(|o| set(o, &["instances"], strings(&["i-h1", "i-h2", "i-h2"]))),
        Reader::Operator,
        "repeats an instance",
        Some("instances repeats an instance"),
    ),
    row(
        "more instances than one status read names",
        Change::Operator(many_instances),
        Reader::Operator,
        "not 1 to 100",
        Some("instances holds 101 IDs, not 1 to 100"),
    ),
    row(
        "an alarm name past 255 characters",
        Change::Operator(|o| set(o, &["alarms", TEXTS[2]], text(&"a".repeat(256)))),
        Reader::Operator,
        "is no alarm name",
        Some(
            "the alarm of 'any replacement receipt written by the reconciler principal' is no alarm name: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
        ),
    ),
    row(
        "a snapshot path with a NUL",
        Change::Operator(|o| set(o, &["snapshot"], text("snap\u{0}shot"))),
        Reader::Operator,
        "control character",
        Some("snapshot holds a control character or text with no UTF-8 form: 'snap\\x00shot'"),
    ),
    row(
        "an alarm name with a lone surrogate",
        Change::Operator(|o| set(o, &["alarms", TEXTS[2]], string("gd2-", Some(0xd800)))),
        Reader::Operator,
        "is no name of the layout",
        Some(
            "the operator file alarms any replacement receipt written by the reconciler principal is no name of the layout: 'gd2-\\ud800'",
        ),
    ),
    row(
        "an approval that lapses before the deadline",
        Change::Operator(|o| set(o, &["approval", "not_after"], text("1970-01-01T00:06:33Z"))),
        Reader::Operator,
        "after the run's deadline",
        Some("the approval lapses at 1970-01-01T00:06:33Z, less than 5 s after the run's deadline"),
    ),
    row(
        "an approval that lapses within the skew after the deadline",
        Change::Operator(|o| set(o, &["approval", "not_after"], text("1970-01-01T00:06:36Z"))),
        Reader::Operator,
        "after the run's deadline",
        Some("the approval lapses at 1970-01-01T00:06:36Z, less than 5 s after the run's deadline"),
    ),
    row(
        "a not_after without zero padding",
        Change::Operator(|o| set(o, &["approval", "not_after"], text("1970-1-1T01:00:00Z"))),
        Reader::Operator,
        "is no time",
        Some("approval not_after '1970-1-1T01:00:00Z' is no time YYYY-MM-DDTHH:MM:SSZ"),
    ),
    row(
        "a not_after on a day no calendar holds",
        Change::Operator(|o| set(o, &["approval", "not_after"], text("1970-02-30T00:00:00Z"))),
        Reader::Operator,
        "is no calendar time",
        Some("approval not_after '1970-02-30T00:00:00Z' is no calendar time"),
    ),
    row(
        "an empty declared set",
        Change::Operator(|o| set(o, &["instances"], strings(&[]))),
        Reader::Operator,
        "not 1 to 100",
        Some("instances holds 0 IDs, not 1 to 100"),
    ),
    row(
        "a not_after at second 61, which would read 01:00:01",
        Change::Operator(|o| set(o, &["approval", "not_after"], text("1970-01-01T00:59:61Z"))),
        Reader::Operator,
        "is no time",
        Some("approval not_after '1970-01-01T00:59:61Z' is no time YYYY-MM-DDTHH:MM:SSZ"),
    ),
    row(
        "a deadline past the run window",
        Change::Operator(|o| set(o, &["deadline_seconds"], number("297"))),
        Reader::Operator,
        "outside the package's run window",
        Some(
            "the run from 104.0 to its deadline 401.0 lies outside the package's run window {'start': 100, 'end': 400}",
        ),
    ),
    row(
        "a run that starts inside the baseline window",
        Change::Package(|p| set(p, &["baseline", "end"], number("105"))),
        Reader::Operator,
        "inside the package's baseline window",
        Some(
            "the run's start 104.0 lies inside the package's baseline window {'start': 0, 'end': 105}",
        ),
    ),
    row(
        "a run that starts before the run window",
        Change::Package(|p| {
            set(p, &["run", "start"], number("130"));
            set(p, &["baseline", "end"], number("130"));
        }),
        Reader::Operator,
        "baseline window",
        Some(
            "the run's start 104.0 lies inside the package's baseline window {'start': 0, 'end': 130}",
        ),
    ),
    row(
        "another injection action",
        Change::Catalog(|gd2| set_member(gd2, &["injection", "action"], text("stop two hosts"))),
        Reader::Catalog,
        "GD-2's injection action differs",
        Some("GD-2's injection action differs from the action this controller was written for"),
    ),
    row(
        "another restoration class",
        Change::Catalog(|gd2| set_member(gd2, &["restoration", "class"], text("automatic"))),
        Reader::Catalog,
        "GD-2's restoration is not of class",
        Some("GD-2's restoration is not of class persistent-manual with its steps"),
    ),
    row(
        "restoration steps with no UTF-8 form",
        Change::Catalog(|gd2| {
            set_member(
                gd2,
                &["restoration", "steps"],
                string("start ", Some(0xd800)),
            )
        }),
        Reader::Catalog,
        "GD-2's restoration is not of class",
        Some("GD-2's restoration is not of class persistent-manual with its steps"),
    ),
    row(
        "one prerequisite that is not met",
        Change::Catalog(|gd2| {
            let unmet = format!("a change freeze over the target zone: {BLOCKS}");
            prerequisites(gd2).push(text(&unmet));
        }),
        Reader::Run,
        "a change freeze over the target zone: TBD - BLOCKS EXECUTION']",
        None,
    ),
    row(
        "no list of prerequisites",
        Change::Catalog(|gd2| {
            gd2.remove("prerequisites");
        }),
        Reader::Run,
        "execution: None",
        None,
    ),
    row(
        "a prerequisite that is no text",
        Change::Catalog(|gd2| prerequisites(gd2).push(Value::Null)),
        Reader::Run,
        ", None]",
        None,
    ),
    row(
        "a malformed package",
        Change::PackageBytes("{"),
        Reader::Operator,
        "refused: ",
        Some("package.json is not strict JSON: expected a key at byte 1"),
    ),
    row(
        "a package off the judge's layout",
        Change::PackageBytes(r#"{"id": "GD-2"}"#),
        Reader::Operator,
        "refused: ",
        Some("package.json hosts is no list"),
    ),
    row(
        "a package that is no object",
        Change::PackageBytes("[]"),
        Reader::Operator,
        "refused: ",
        Some("the package is no object"),
    ),
    row(
        "a simulation package",
        Change::Package(|p| set(p, &["kind"], text("simulation"))),
        Reader::Operator,
        "only a staging run stops an instance",
        Some("the package is of kind simulation: only a staging run stops an instance"),
    ),
    row(
        "a package past the judge's file size",
        Change::PackagePastLimit,
        Reader::PackageRead,
        "the package holds more than ",
        None,
    ),
    row(
        "an existing injection directory",
        Change::Evidence(Evidence::InjectionExists),
        Reader::Run,
        "exists: a run's marks are written once",
        None,
    ),
    row(
        "a missing evidence directory",
        Change::Evidence(Evidence::Missing),
        Reader::Run,
        "is no directory",
        None,
    ),
    row(
        "a linked evidence directory",
        Change::Evidence(Evidence::Linked),
        Reader::Run,
        "is no directory",
        None,
    ),
    row(
        "an evidence directory named by an empty path, which reads as the working directory",
        Change::Evidence(Evidence::EmptyPath),
        Reader::Run,
        "refused: '' is no directory",
        None,
    ),
];

/// Sets the member of GD-2's entry at `path` to `new`.
fn set_member(gd2: &mut Object, path: &[&str], new: Value) {
    let mut entry = Value::Object(std::mem::take(gd2));
    set(&mut entry, path, new);
    let Value::Object(entry) = entry else {
        unreachable!("the entry stays an object")
    };
    *gd2 = entry;
}
