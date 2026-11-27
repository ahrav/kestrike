//! The operator file: its shape, its bounds and its names, checked in one order, and the snapshot
//! path it names made absolute against the file's own directory.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use super::constants::{ALARM_NAME_MAX, BOUNDS, LIMIT_SECONDS, MAX_INSTANCES, REGION};
use super::forms::{instance_id, iso_time, matches, plain};
use super::inputs::read_json;
use super::number::Number;
use super::words::sentence;
use crate::gameday::{Each, Names, Refusal, Scalar, Schema, conform, need};
use crate::json::{Object, Value};
use crate::paths::normalize;
use crate::plants::files::strerror;
use crate::text::Text;

const fn s(scalar: Scalar) -> Schema {
    Schema::scalar(scalar)
}

/// The operator file's shape, in the order its keys are checked.
const OPERATOR: Schema = Schema::Object(&[
    ("region", s(Scalar::Name)),
    ("identity", s(Scalar::Name)),
    ("instances", Schema::List(&s(Scalar::Name))),
    ("snapshot", s(Scalar::Name)),
    (
        "approval",
        Schema::Object(&[
            ("approver", s(Scalar::Name)),
            ("package_sha256", s(Scalar::Digest)),
            ("instance", s(Scalar::Name)),
            ("not_after", s(Scalar::Name)),
        ]),
    ),
    (
        "alarms",
        Schema::Each(Each {
            keys: "guardrail",
            value: &s(Scalar::Name),
            exact: true,
        }),
    ),
    (BOUNDS[0], s(Scalar::Positive)),
    (BOUNDS[1], s(Scalar::Positive)),
    (BOUNDS[2], s(Scalar::Positive)),
    (BOUNDS[3], s(Scalar::Positive)),
]);

/// The owner's recorded approval of one run.
#[derive(Clone, Debug, PartialEq)]
pub struct Approval {
    approver: Text,
    package_sha256: Text,
    instance: Text,
    not_after: Text,
}

impl Approval {
    pub fn approver(&self) -> &Text {
        &self.approver
    }

    /// The SHA-256 of the filled package's bytes, 64 lowercase hexadecimal digits.
    pub fn package_sha256(&self) -> &Text {
        &self.package_sha256
    }

    /// The target instance, an instance ID.
    pub fn instance(&self) -> &Text {
        &self.instance
    }

    /// The ISO time at which the approval lapses, a calendar second.
    pub fn not_after(&self) -> &Text {
        &self.not_after
    }
}

/// `Operator` is an operator file that [`read_operator`] admitted: every value of the shape and the
/// bounds that function states.
#[derive(Clone, Debug, PartialEq)]
pub struct Operator {
    region: Text,
    identity: Text,
    approval: Approval,
    instances: Vec<Text>,
    snapshot: PathBuf,
    alarms: Vec<(Text, Text)>,
    bounds: [Number; 4],
}

impl Operator {
    /// The AWS region name.
    pub fn region(&self) -> &Text {
        &self.region
    }

    /// The ARN the run's caller has.
    pub fn identity(&self) -> &Text {
        &self.identity
    }

    pub fn approval(&self) -> &Approval {
        &self.approval
    }

    /// The declared instance set: 1 to 100 distinct instance IDs, in the file's order.
    pub fn instances(&self) -> &[Text] {
        &self.instances
    }

    /// The snapshot directory, an absolute path.
    pub fn snapshot(&self) -> &Path {
        &self.snapshot
    }

    /// Each guardrail text with its distinct alarm name, in the file's order.
    pub fn alarms(&self) -> &[(Text, Text)] {
        &self.alarms
    }

    /// The alarm name of the guardrail `text`.
    pub fn alarm(&self, text: &Text) -> Option<&Text> {
        self.alarms
            .iter()
            .find(|(guardrail, _)| guardrail == text)
            .map(|(_, alarm)| alarm)
    }

    pub fn snapshot_max_age_seconds(&self) -> Number {
        self.bounds[0]
    }

    pub fn effect_timeout_seconds(&self) -> Number {
        self.bounds[1]
    }

    pub fn observe_seconds(&self) -> Number {
        self.bounds[2]
    }

    pub fn deadline_seconds(&self) -> Number {
        self.bounds[3]
    }
}

/// `read_operator` reads the operator file at `path`, at most `limit` bytes, against GD-2's entry
/// `gd2`, whose `guardrail` texts key `alarms`. The snapshot path is joined to the directory of
/// `path` made absolute against the working directory, which a relative `path` reads.
///
/// # Errors
///
/// The first refusal in this order: each of [`read_json`]; `the operator file holds no approval of this
/// run`; the shape off its schema; the region; the approval's instance and its time; each declared
/// instance; `instances holds <n> IDs, not 1 to 100`; `instances repeats an instance`; each bound past
/// 86,400 s; a deadline that holds less than the effect timeout and the observation together; each
/// alarm name of more than 255 characters, with a leading `-` or outer white space; one alarm for two
/// guardrails; the snapshot path and each alarm name with a control character; and
/// `the working directory cannot be read: <reason>` for a relative `path`.
///
/// # Panics
///
/// When `gd2` holds no list of guardrail texts: the caller passes the entry `gd2_of` returned.
pub fn read_operator(path: &Path, gd2: &Object, limit: u64) -> Result<Operator, Refusal> {
    let o = read_json(path, &Text::from("the operator file"), limit)?;
    let shaped =
        matches!(&o, Value::Object(o) if matches!(o.get("approval"), Some(Value::Object(_))));
    need(shaped, || {
        sentence!("the operator file holds no approval of this run")
    })?;
    let mut names = Names::new();
    names.insert("guardrail", guardrails(gd2));
    conform(&o, &OPERATOR, &Text::from("the operator file"), &names)?;
    let Value::Object(o) = o else {
        unreachable!("the schema made the operator file an object")
    };
    let text = |key: &str| checked_text(o.get(key));
    let region = text("region");
    need(matches(&REGION, region), || {
        sentence!("region ", region.repr(), " is no AWS region name")
    })?;
    let Some(Value::Object(approval)) = o.get("approval") else {
        unreachable!("the schema made the approval an object")
    };
    instance_id(
        field(approval, "instance"),
        &Text::from("approval instance"),
    )?;
    iso_time(
        field(approval, "not_after"),
        &Text::from("approval not_after"),
    )?;
    let Some(Value::Array(listed)) = o.get("instances") else {
        unreachable!("the schema made the instances a list")
    };
    let instances = listed
        .iter()
        .enumerate()
        .map(|(at, value)| instance_id(value, &sentence!("instances[", at.to_string(), "]")))
        .collect::<Result<Vec<_>, _>>()?;
    need(
        !instances.is_empty() && instances.len() <= MAX_INSTANCES,
        || {
            sentence!(
                "instances holds ",
                instances.len().to_string(),
                " IDs, not 1 to ",
                MAX_INSTANCES.to_string()
            )
        },
    )?;
    let distinct: BTreeSet<&Text> = instances.iter().collect();
    need(distinct.len() == instances.len(), || {
        sentence!("instances repeats an instance")
    })?;
    let bounds =
        BOUNDS.map(|bound| Number::of(field(&o, bound)).expect("the schema made a bound a number"));
    for (bound, value) in BOUNDS.iter().zip(bounds) {
        need(value <= Number::from(LIMIT_SECONDS), || {
            sentence!(
                bound,
                " ",
                value,
                " is past its limit of ",
                LIMIT_SECONDS.to_string(),
                " s"
            )
        })?;
    }
    need(bounds[1].plus(bounds[2]) <= bounds[3], || {
        sentence!(
            "deadline_seconds holds less than effect_timeout_seconds and observe_seconds together"
        )
    })?;
    let Some(Value::Object(keyed)) = o.get("alarms") else {
        unreachable!("the schema made the alarms an object")
    };
    let alarms: Vec<(Text, Text)> = keyed
        .iter()
        .map(|(key, alarm)| (key.clone(), checked_text(Some(alarm)).clone()))
        .collect();
    for (key, alarm) in &alarms {
        let named = alarm.len() <= ALARM_NAME_MAX
            && alarm.code_points().next() != Some(u32::from('-'))
            && alarm.strip() == *alarm;
        need(named, || {
            sentence!(
                "the alarm of ",
                key.repr(),
                " is no alarm name: ",
                alarm.repr()
            )
        })?;
    }
    let distinct: BTreeSet<&Text> = alarms.iter().map(|(_, alarm)| alarm).collect();
    need(distinct.len() == alarms.len(), || {
        sentence!("alarms names one alarm for two guardrails")
    })?;
    let snapshot = text("snapshot");
    let named = std::iter::once((Text::from("snapshot"), snapshot)).chain(
        alarms
            .iter()
            .map(|(key, alarm)| (sentence!("the alarm of ", key.repr()), alarm)),
    );
    for (what, text) in named {
        need(plain(text), || {
            sentence!(
                what,
                " holds a control character or text with no UTF-8 form: ",
                text.repr()
            )
        })?;
    }
    Ok(Operator {
        region: region.clone(),
        identity: text("identity").clone(),
        approval: Approval {
            approver: checked_text(approval.get("approver")).clone(),
            package_sha256: checked_text(approval.get("package_sha256")).clone(),
            instance: checked_text(approval.get("instance")).clone(),
            not_after: checked_text(approval.get("not_after")).clone(),
        },
        instances,
        snapshot: snapshot_path(path, snapshot)?,
        alarms,
        bounds,
    })
}

/// The guardrail texts of GD-2's entry.
fn guardrails(gd2: &Object) -> BTreeSet<Text> {
    let Some(Value::Array(texts)) = gd2.get("guardrail") else {
        panic!("GD-2's entry holds its list of guardrail texts");
    };
    texts
        .iter()
        .map(|text| checked_text(Some(text)).clone())
        .collect()
}

fn field<'a>(object: &'a Object, key: &str) -> &'a Value {
    object
        .get(key)
        .unwrap_or_else(|| panic!("the schema holds the key {key}"))
}

fn checked_text(value: Option<&Value>) -> &Text {
    match value {
        Some(Value::String(text)) => text,
        _ => panic!("the schema made {value:?} a string"),
    }
}

/// The snapshot path `snapshot` joined to the directory of the operator file at `path`, which is
/// made absolute and normalized lexically first: an absolute `snapshot` stands for itself.
fn snapshot_path(path: &Path, snapshot: &Text) -> Result<PathBuf, Refusal> {
    let path = path.as_os_str().as_bytes();
    let absolute = if path.starts_with(b"/") {
        normalize(path)
    } else {
        let cwd = std::env::current_dir().map_err(|error| {
            Refusal::new(sentence!(
                "the working directory cannot be read: ",
                strerror(&error)
            ))
        })?;
        let mut joined = cwd.into_os_string().into_vec();
        if !joined.ends_with(b"/") {
            joined.push(b'/');
        }
        joined.extend_from_slice(path);
        normalize(&joined)
    };
    let cut = absolute
        .iter()
        .rposition(|&byte| byte == b'/')
        .map_or(0, |at| at + 1);
    let mut directory = absolute[..cut].to_vec();
    if directory.iter().any(|&byte| byte != b'/') {
        while directory.ends_with(b"/") {
            directory.pop();
        }
    }
    let snapshot = snapshot
        .to_str()
        .expect("a plain text has a UTF-8 form")
        .as_bytes();
    let joined = if snapshot.starts_with(b"/") {
        snapshot.to_vec()
    } else {
        let mut joined = directory;
        if !joined.is_empty() && !joined.ends_with(b"/") {
            joined.push(b'/');
        }
        joined.extend_from_slice(snapshot);
        joined
    };
    Ok(PathBuf::from(OsStr::from_bytes(&joined)))
}
