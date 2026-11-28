//! The lane's close over hardware manifests: the checked-in one, copies that change the lane role's
//! cases, and paths whose read fails, each rejection naming the profile's lane before the reason; and
//! the read of the manifest anew at each call.

use std::fs;
use std::path::Path;

use kestrike_tools::fis_controller::{Error, close_seconds};
use kestrike_tools::json::{self, Text, Value};

use crate::fis_support::{Scratch, hardware_manifest, profile, value};

const OWNER: &str = "{'profile': 'fis-read', 'role': 'owner'}";

/// `fis-read-latency`'s checked-in profile, whose lane is the owner role of `fis-read`, with the lane
/// `lane`, a JSON text, or none.
fn with_lane(lane: Option<&str>) -> Value {
    let mut profile = profile("fis-read-latency");
    let Value::Object(fields) = &mut profile else {
        panic!("a checked-in profile is an object");
    };
    match lane {
        Some(lane) => fields.insert("lane", value(lane)),
        None => {
            fields.remove("lane");
        }
    }
    profile
}

/// The checked-in hardware manifest with `change` applied to the cases of `fis-read`'s owner role.
fn hardware_with(change: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    let mut manifest = value(&fs::read_to_string(hardware_manifest()).expect("the manifest reads"));
    let mut at = &mut manifest;
    for key in ["profiles", "fis-read", "roles", "owner", "cases"] {
        at = match at {
            Value::Object(object) => object
                .get_mut(key)
                .expect("the checked-in role holds cases"),
            other => panic!("{other:?} holds no member {key}"),
        };
    }
    let Value::Array(cases) = at else {
        panic!("the role's cases are a list");
    };
    change(cases);
    json::dump(&manifest).into_bytes()
}

/// The close's seconds, or the sentence of its rejection.
fn close(profile: &Value, hardware: &Path) -> Result<f64, String> {
    close_seconds(profile, hardware).map_err(|error| match error {
        Error::Rejected(rejected) => rejected.sentence().to_string(),
        other => panic!("the close of {hardware:?} fails with {other:?}"),
    })
}

fn rejected(lane: &str, reason: &str) -> Result<f64, String> {
    Err(format!(
        "the hardware manifest names no lane role for {lane}: {reason}"
    ))
}

#[test]
fn the_close_is_the_lane_roles_longest_grace_plus_the_stop_and_controller_windows() {
    let checked_in = hardware_manifest();
    assert_eq!(close(&profile("fis-read-latency"), &checked_in), Ok(100.0));
    assert_eq!(close(&profile("fis-family-stop"), &checked_in), Ok(100.0));
    let scratch = Scratch::new("close");
    let mixed = scratch.file(
        "mixed.json",
        &hardware_with(|cases| {
            let first = cases[0].clone();
            for grace in ["60.5", "true", "61"] {
                let mut case = first.clone();
                if let Value::Object(fields) = &mut case {
                    fields.insert("grace", value(grace));
                }
                cases.push(case);
            }
        }),
    );
    assert_eq!(close(&profile("fis-read-latency"), &mixed), Ok(101.0));
}

#[test]
fn a_read_that_fails_names_the_system_error_and_the_path_in_its_pure_form() {
    let scratch = Scratch::new("close-read");
    let read = profile("fis-read-latency");
    let absent = scratch.0.join("absent").join("hardware-profiles.json");
    let shown = Text::from_os(absent.as_os_str()).repr();
    let expected = rejected(
        OWNER,
        &format!("[Errno 2] No such file or directory: {shown}"),
    );
    assert_eq!(close(&read, &absent), expected);
    let spelled = format!("{}/./absent//hardware-profiles.json", scratch.0.display());
    assert_eq!(close(&read, Path::new(&spelled)), expected);
    let folder = scratch.0.join("folder");
    fs::create_dir(&folder).expect("the directory is made");
    let shown = Text::from_os(folder.as_os_str()).repr();
    assert_eq!(
        close(&read, &folder),
        rejected(OWNER, &format!("[Errno 21] Is a directory: {shown}"))
    );
}

#[test]
fn a_manifest_without_the_lane_role_or_its_graces_is_rejected_with_the_reason() {
    let scratch = Scratch::new("close-role");
    let checked_in = hardware_manifest();
    let nobody = with_lane(Some(r#"{"profile": "fis-read", "role": "nobody"}"#));
    assert_eq!(
        close(&nobody, &checked_in),
        rejected("{'profile': 'fis-read', 'role': 'nobody'}", "'nobody'")
    );
    let string_lane = with_lane(Some(r#""fis-read""#));
    assert_eq!(
        close(&string_lane, &checked_in),
        rejected(
            "fis-read",
            "a value that is not an object has no member 'profile'"
        )
    );
    let read = profile("fis-read-latency");
    let text_grace = scratch.file(
        "text-grace.json",
        &hardware_with(|cases| {
            if let Value::Object(fields) = &mut cases[0] {
                fields.insert("grace", value(r#""60""#));
            }
        }),
    );
    assert_eq!(
        close(&read, &text_grace),
        rejected(OWNER, "a case's grace '60' is not a number")
    );
    let no_case = scratch.file("no-case.json", &hardware_with(Vec::clear));
    assert_eq!(
        close(&read, &no_case),
        rejected(OWNER, "the role holds no case")
    );
    let broken = scratch.file("broken.json", b"{");
    assert_eq!(
        close(&read, &broken),
        rejected(OWNER, "expected a key at byte 1")
    );
    let latin = scratch.file("latin.json", b"\xff{}");
    assert_eq!(
        close(&read, &latin),
        rejected(OWNER, "the file is not UTF-8")
    );
}

/// A profile without a lane is rejected for its lane whatever the manifest holds, a manifest whose read
/// fails included; with the lane present, that read's failure is the reason.
#[test]
fn a_profile_without_a_lane_is_rejected_before_the_manifest_is_judged() {
    let scratch = Scratch::new("close-lane");
    let absent = scratch.0.join("absent.json");
    let no_lane = with_lane(None);
    let expected = Err("a FIS profile holds no lane".to_owned());
    assert_eq!(close(&no_lane, &hardware_manifest()), expected);
    assert_eq!(close(&no_lane, &absent), expected);
    let shown = Text::from_os(absent.as_os_str()).repr();
    assert_eq!(
        close(&profile("fis-read-latency"), &absent),
        rejected(
            OWNER,
            &format!("[Errno 2] No such file or directory: {shown}")
        )
    );
}

/// The close reads the manifest's file at each call, beside the controller's checked read of it: a file
/// replaced between two calls gives each call the grace the file held at that call.
#[test]
fn each_call_reads_the_manifest_anew() {
    let scratch = Scratch::new("close-anew");
    let read = profile("fis-read-latency");
    let path = scratch.file("hardware-profiles.json", &hardware_with(|_| {}));
    assert_eq!(close(&read, &path), Ok(100.0));
    let longer = scratch.file(
        "longer.json",
        &hardware_with(|cases| {
            if let Value::Object(fields) = &mut cases[0] {
                fields.insert("grace", value("70"));
            }
        }),
    );
    fs::rename(&longer, &path).expect("the manifest is replaced");
    assert_eq!(close(&read, &path), Ok(110.0));
}

/// A lane's whole number or boolean names an item of a list of the manifest, a negative one counted from
/// the end; one past the end is [`Error::OutOfRange`], and a float or a string names no item.
#[test]
fn a_lane_of_whole_numbers_names_items_of_the_manifests_lists() {
    let scratch = Scratch::new("close-lists");
    let lists = scratch.file(
        "lists.json",
        br#"{"profiles": [{"roles": [{"cases": [{"grace": 7}]}]}]}"#,
    );
    let rows = [
        (r#"{"profile": 0, "role": 0}"#, Ok(47.0)),
        (r#"{"profile": false, "role": -1}"#, Ok(47.0)),
        (
            r#"{"profile": 0.0, "role": 0}"#,
            rejected(
                "{'profile': 0.0, 'role': 0}",
                "a value that is not an object has no member 0.0",
            ),
        ),
        (
            r#"{"profile": "fis-read", "role": 0}"#,
            rejected(
                "{'profile': 'fis-read', 'role': 0}",
                "a value that is not an object has no member 'fis-read'",
            ),
        ),
    ];
    for (lane, expected) in rows {
        assert_eq!(close(&with_lane(Some(lane)), &lists), expected, "{lane}");
    }
    let past = with_lane(Some(r#"{"profile": 5, "role": 0}"#));
    assert_eq!(close_seconds(&past, &lists), Err(Error::OutOfRange));
    let string = scratch.file("string.json", br#"{"profiles": "abc"}"#);
    assert_eq!(
        close(
            &with_lane(Some(r#"{"profile": 1, "role": "owner"}"#)),
            &string
        ),
        rejected(
            "{'profile': 1, 'role': 'owner'}",
            "a string has no member 1"
        )
    );
    let past = with_lane(Some(r#"{"profile": 9, "role": "owner"}"#));
    assert_eq!(close_seconds(&past, &string), Err(Error::OutOfRange));
}

/// The longest grace keeps the first case's until a later one is above it, so a first `nan` stands and
/// a later `nan` is passed over.
#[test]
fn a_nan_grace_stands_first_and_is_passed_over_later() {
    let scratch = Scratch::new("close-nan");
    let read = profile("fis-read-latency");
    let first = scratch.file(
        "nan-first.json",
        &hardware_with(|cases| {
            let mut later = cases[0].clone();
            if let Value::Object(fields) = &mut cases[0] {
                fields.insert("grace", Value::Float(f64::NAN));
            }
            if let Value::Object(fields) = &mut later {
                fields.insert("grace", value("60"));
            }
            cases.push(later);
        }),
    );
    assert!(close(&read, &first).is_ok_and(f64::is_nan));
    let last = scratch.file(
        "nan-last.json",
        &hardware_with(|cases| {
            let mut later = cases[0].clone();
            if let Value::Object(fields) = &mut later {
                fields.insert("grace", Value::Float(f64::NAN));
            }
            cases.push(later);
        }),
    );
    assert_eq!(close(&read, &last), Ok(100.0));
}
