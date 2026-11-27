//! The checks `restore` makes of the marks a run left: a reviewed record tied to its abort by the
//! SHA-256 of `abort.json`'s bytes and by the steps digest that ends the abort's detail, and a
//! `stopped.json` tied to its request by holding `stop.json`'s value whole.

use std::path::Path;

use super::constants::{STEPS_PREFIX, STEPS_TAIL};
use super::forms::{matches, steps_tail};
use super::inputs::read_bytes;
use super::number::Number;
use super::words::sentence;
use crate::gameday::{Names, Refusal, Scalar, Schema, conform, layout, need, parsed};
use crate::json::{Object, Value};
use crate::paths::resolve;
use crate::plants::files::strerror;
use crate::python::hexdigest;
use crate::text::Text;

/// The operator's reviewed record of an abort.
const REVIEWED: Schema = Schema::Object(&[
    ("abort_sha256", Schema::scalar(Scalar::Digest)),
    ("steps", Schema::scalar(Scalar::Name)),
    ("reviewer", Schema::scalar(Scalar::Name)),
    ("time", Schema::scalar(Scalar::Time)),
]);

/// `check_reviewed` is the SHA-256 of the reviewed record at `reviewed` and the abort's time. The
/// record lies outside `evidence`, both paths resolved with their links, and names the bytes of the
/// abort mark at `abort_path` and the steps whose digest ends that mark's detail, at a time from the
/// abort's to `now`; the abort is dated no earlier than `stop`, the stop mark it closes. Each file is
/// read at most `limit` bytes.
///
/// # Errors
///
/// The first refusal in this order: no `reviewed`; a path that cannot be resolved; a record inside
/// the evidence directory; each read of the record, then of `abort.json`; the record off its schema;
/// the abort off the judge's layout; a guardrail named without cause `guardrail` or none with it;
/// another abort's digest; a detail that does not end with a steps digest; other steps; an abort dated
/// before the stop; a record dated before the abort or after `now`.
///
/// # Panics
///
/// When `stop` is other than `stop.json`'s value checked against the judge's request schema.
pub fn check_reviewed(
    reviewed: Option<&Path>,
    abort_path: &Path,
    evidence: &Path,
    now: f64,
    stop: &Object,
    limit: u64,
) -> Result<(String, Number), Refusal> {
    let Some(reviewed) = reviewed else {
        return Err(Refusal::new(sentence!(
            "an abort stands: restore needs --reviewed, the operator's record that GD-2's restoration \
             steps were done"
        )));
    };
    let root = resolved(evidence, "the evidence directory")?;
    need(
        !resolved(reviewed, "the reviewed record")?.starts_with(&root),
        || {
            sentence!(
                "the reviewed record lies inside the evidence directory, where the judge admits no file \
             outside its layout; keep it outside"
            )
        },
    )?;
    let raw = read_bytes(reviewed, &Text::from("the reviewed record"), limit)?;
    let abort_raw = read_bytes(abort_path, &Text::from("abort.json"), limit)?;
    let record = parsed(&raw, &Text::from("the reviewed record"))?;
    conform(
        &record,
        &REVIEWED,
        &Text::from("the reviewed record"),
        &Names::new(),
    )?;
    let abort_name = Text::from("injection/abort.json");
    let abort = parsed(&abort_raw, &abort_name)?;
    let (schema, _) = layout("injection/abort.json").expect("the layout holds abort.json");
    conform(&abort, schema, &abort_name, &Names::new())?;
    let (Value::Object(record), Value::Object(abort)) = (&record, &abort) else {
        unreachable!("the schemas made both values objects")
    };
    let guardrail =
        matches!(abort.get("cause"), Some(Value::String(cause)) if *cause == "guardrail");
    need(
        guardrail == (abort.get("guardrail") != Some(&Value::Null)),
        || {
            sentence!(
                "injection/abort.json names a guardrail without cause guardrail, or none with it, which \
             the judge refuses"
            )
        },
    )?;
    need(
        *text(record.get("abort_sha256")) == hexdigest(&abort_raw).as_str(),
        || sentence!("the reviewed record names another abort"),
    )?;
    let detail = match abort.get("detail") {
        Some(Value::String(detail)) => detail.clone(),
        _ => Text::new(),
    };
    let tail = last(&detail, STEPS_PREFIX.len() + 64);
    need(matches(&STEPS_TAIL, &tail), || {
        sentence!(
            "injection/abort.json's detail does not end with the digest of the restoration steps its \
             run printed, so no review can be compared with it"
        )
    })?;
    let steps = text(record.get("steps"))
        .to_str()
        .expect("a name has a UTF-8 form");
    need(tail == steps_tail(steps).as_str(), || {
        sentence!("the reviewed record names steps other than those the aborted run printed")
    })?;
    let (aborted, reviewed_at) = (time(abort.get("time")), time(record.get("time")));
    need(aborted >= time(stop.get("time")), || {
        sentence!("injection/abort.json is dated before the stop it would close")
    })?;
    need(reviewed_at >= aborted, || {
        sentence!("the reviewed record is dated before the abort it reviews")
    })?;
    let now = Number::from(now);
    need(reviewed_at <= now, || {
        sentence!(
            "the reviewed record is dated ",
            reviewed_at,
            ", after restore's start ",
            now
        )
    })?;
    Ok((hexdigest(&raw), aborted))
}

/// `check_stopped` is the time of the `stopped.json` at `stopped_path`, read at most `limit` bytes: a
/// report of `stop`'s instance stopped for exactly the request `stop` holds, read at or after that
/// request's time and no later than `now`.
///
/// # Errors
///
/// Each read of the file; the mark off the judge's layout; a mark of another instance, state or
/// request, or read before the request; a mark read after `now`.
///
/// # Panics
///
/// When `stop` is other than `stop.json`'s value checked against the judge's request schema.
pub fn check_stopped(
    stopped_path: &Path,
    stop: &Object,
    now: f64,
    limit: u64,
) -> Result<Number, Refusal> {
    let name = Text::from("injection/stopped.json");
    let stopped = parsed(&read_bytes(stopped_path, &name, limit)?, &name)?;
    let (schema, _) = layout("injection/stopped.json").expect("the layout holds stopped.json");
    conform(&stopped, schema, &name, &Names::new())?;
    let Value::Object(stopped) = &stopped else {
        unreachable!("the schema made stopped.json an object")
    };
    let at = time(stopped.get("time"));
    let shows = text(stopped.get("instance")) == text(stop.get("instance"))
        && *text(stopped.get("state")) == "stopped"
        && same_request(object(stopped.get("request")), stop)
        && at >= time(stop.get("time"));
    need(shows, || {
        sentence!(
            "injection/stopped.json shows no stop of injection/stop.json's request read at or after it"
        )
    })?;
    let now = Number::from(now);
    need(at <= now, || {
        sentence!(
            "injection/stopped.json is dated ",
            at,
            ", after restore's start ",
            now
        )
    })?;
    Ok(at)
}

/// Whether two requests of the judge's schema are equal as Python compares them: the same instance
/// and identity, and times of one value whatever their kinds.
fn same_request(one: &Object, other: &Object) -> bool {
    text(one.get("instance")) == text(other.get("instance"))
        && text(one.get("identity")) == text(other.get("identity"))
        && time(one.get("time")) == time(other.get("time"))
}

/// `path` resolved with its links and made absolute.
fn resolved(path: &Path, what: &str) -> Result<std::path::PathBuf, Refusal> {
    resolve(path)
        .map_err(|error| Refusal::new(sentence!(what, " cannot be resolved: ", strerror(&error))))
}

/// The last `count` code points of `text`, or all of them when it holds fewer.
fn last(text: &Text, count: usize) -> Text {
    let codes: Vec<u32> = text.code_points().collect();
    Text::from_code_points(codes[codes.len().saturating_sub(count)..].iter().copied())
        .expect("code points of a text form a text")
}

fn time(value: Option<&Value>) -> Number {
    value
        .and_then(Number::of)
        .unwrap_or_else(|| panic!("the schema made {value:?} a time"))
}

fn text(value: Option<&Value>) -> &Text {
    match value {
        Some(Value::String(text)) => text,
        _ => panic!("the schema made {value:?} a string"),
    }
}

fn object(value: Option<&Value>) -> &Object {
    match value {
        Some(Value::Object(object)) => object,
        _ => panic!("the schema made {value:?} an object"),
    }
}
