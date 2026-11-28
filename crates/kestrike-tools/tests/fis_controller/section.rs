//! The section's rules: each verdict a section can reach under each rule, with and without an
//! `effect_window` and an earlier `diagnostic`, and the section before any phase.

use std::fs;

use kestrike_tools::fis_controller::{
    Failure, Opening, Owned, Section, Status, Verdict, kernel_timeout,
};
use kestrike_tools::json::{self, Integer, Object, Text, Value};
use kestrike_tools::python::repr;

use crate::fis_support::Scratch;

/// Each row: the verdict before, whether an `effect_window` stands, the diagnostic before (`None` for
/// none), the rule, then the verdict, `first_failure`, `diagnostic` and `status` after. The rule
/// `fail` is `fail(INCONCLUSIVE, "new")`, `fail-status` is `fail(INVALID, "new", HALTED)`, and
/// `contaminate` and `disprove` take `"new"`. The rows of a `HELD` or `INVALID` verdict with a
/// diagnostic before stand in the table and are passed over: no sequence of the rules reaches them.
const ROWS: &str = "\
HELD|-|None|fail|INCONCLUSIVE|'new'|'<absent>'|NOT_STARTED
HELD|-|None|fail-status|INVALID|'new'|'<absent>'|HALTED
HELD|-|None|contaminate|INCONCLUSIVE|'new'|'<absent>'|NOT_STARTED
HELD|-|None|disprove|DISPROVEN|'new'|'<absent>'|NOT_STARTED
HELD|-|''|fail|INCONCLUSIVE|'new'|''|NOT_STARTED
HELD|-|''|fail-status|INVALID|'new'|''|HALTED
HELD|-|''|contaminate|INCONCLUSIVE|'new'|''|NOT_STARTED
HELD|-|''|disprove|DISPROVEN|'new'|''|NOT_STARTED
HELD|-|'older'|fail|INCONCLUSIVE|'new'|'older'|NOT_STARTED
HELD|-|'older'|fail-status|INVALID|'new'|'older'|HALTED
HELD|-|'older'|contaminate|INCONCLUSIVE|'new'|'older'|NOT_STARTED
HELD|-|'older'|disprove|DISPROVEN|'new'|'older'|NOT_STARTED
HELD|window|None|fail|INCONCLUSIVE|'new'|'<absent>'|NOT_STARTED
HELD|window|None|fail-status|INVALID|'new'|'<absent>'|HALTED
HELD|window|None|contaminate|INCONCLUSIVE|'new'|'<absent>'|NOT_STARTED
HELD|window|None|disprove|DISPROVEN|'new'|'<absent>'|NOT_STARTED
HELD|window|''|fail|INCONCLUSIVE|'new'|''|NOT_STARTED
HELD|window|''|fail-status|INVALID|'new'|''|HALTED
HELD|window|''|contaminate|INCONCLUSIVE|'new'|''|NOT_STARTED
HELD|window|''|disprove|DISPROVEN|'new'|''|NOT_STARTED
HELD|window|'older'|fail|INCONCLUSIVE|'new'|'older'|NOT_STARTED
HELD|window|'older'|fail-status|INVALID|'new'|'older'|HALTED
HELD|window|'older'|contaminate|INCONCLUSIVE|'new'|'older'|NOT_STARTED
HELD|window|'older'|disprove|DISPROVEN|'new'|'older'|NOT_STARTED
INVALID|-|None|fail|INVALID|'earlier'|'<absent>'|NOT_STARTED
INVALID|-|None|fail-status|INVALID|'earlier'|'<absent>'|NOT_STARTED
INVALID|-|None|contaminate|INVALID|'earlier'|'<absent>'|NOT_STARTED
INVALID|-|None|disprove|INVALID|'earlier'|'<absent>'|NOT_STARTED
INVALID|-|''|fail|INVALID|'earlier'|''|NOT_STARTED
INVALID|-|''|fail-status|INVALID|'earlier'|''|NOT_STARTED
INVALID|-|''|contaminate|INVALID|'earlier'|''|NOT_STARTED
INVALID|-|''|disprove|INVALID|'earlier'|''|NOT_STARTED
INVALID|-|'older'|fail|INVALID|'earlier'|'older'|NOT_STARTED
INVALID|-|'older'|fail-status|INVALID|'earlier'|'older'|NOT_STARTED
INVALID|-|'older'|contaminate|INVALID|'earlier'|'older'|NOT_STARTED
INVALID|-|'older'|disprove|INVALID|'earlier'|'older'|NOT_STARTED
INVALID|window|None|fail|INVALID|'earlier'|'<absent>'|NOT_STARTED
INVALID|window|None|fail-status|INVALID|'earlier'|'<absent>'|NOT_STARTED
INVALID|window|None|contaminate|INVALID|'earlier'|'<absent>'|NOT_STARTED
INVALID|window|None|disprove|INVALID|'earlier'|'<absent>'|NOT_STARTED
INVALID|window|''|fail|INVALID|'earlier'|''|NOT_STARTED
INVALID|window|''|fail-status|INVALID|'earlier'|''|NOT_STARTED
INVALID|window|''|contaminate|INVALID|'earlier'|''|NOT_STARTED
INVALID|window|''|disprove|INVALID|'earlier'|''|NOT_STARTED
INVALID|window|'older'|fail|INVALID|'earlier'|'older'|NOT_STARTED
INVALID|window|'older'|fail-status|INVALID|'earlier'|'older'|NOT_STARTED
INVALID|window|'older'|contaminate|INVALID|'earlier'|'older'|NOT_STARTED
INVALID|window|'older'|disprove|INVALID|'earlier'|'older'|NOT_STARTED
INCONCLUSIVE|-|None|fail|INCONCLUSIVE|'earlier'|'<absent>'|NOT_STARTED
INCONCLUSIVE|-|None|fail-status|INCONCLUSIVE|'earlier'|'<absent>'|NOT_STARTED
INCONCLUSIVE|-|None|contaminate|INCONCLUSIVE|'earlier'|'<absent>'|NOT_STARTED
INCONCLUSIVE|-|None|disprove|INCONCLUSIVE|'earlier'|'<absent>'|NOT_STARTED
INCONCLUSIVE|-|''|fail|INCONCLUSIVE|'earlier'|''|NOT_STARTED
INCONCLUSIVE|-|''|fail-status|INCONCLUSIVE|'earlier'|''|NOT_STARTED
INCONCLUSIVE|-|''|contaminate|INCONCLUSIVE|'earlier'|''|NOT_STARTED
INCONCLUSIVE|-|''|disprove|INCONCLUSIVE|'earlier'|''|NOT_STARTED
INCONCLUSIVE|-|'older'|fail|INCONCLUSIVE|'earlier'|'older'|NOT_STARTED
INCONCLUSIVE|-|'older'|fail-status|INCONCLUSIVE|'earlier'|'older'|NOT_STARTED
INCONCLUSIVE|-|'older'|contaminate|INCONCLUSIVE|'earlier'|'older'|NOT_STARTED
INCONCLUSIVE|-|'older'|disprove|INCONCLUSIVE|'earlier'|'older'|NOT_STARTED
INCONCLUSIVE|window|None|fail|INCONCLUSIVE|'earlier'|'<absent>'|NOT_STARTED
INCONCLUSIVE|window|None|fail-status|INCONCLUSIVE|'earlier'|'<absent>'|NOT_STARTED
INCONCLUSIVE|window|None|contaminate|INCONCLUSIVE|'earlier'|'<absent>'|NOT_STARTED
INCONCLUSIVE|window|None|disprove|DISPROVEN|'new'|'earlier'|NOT_STARTED
INCONCLUSIVE|window|''|fail|INCONCLUSIVE|'earlier'|''|NOT_STARTED
INCONCLUSIVE|window|''|fail-status|INCONCLUSIVE|'earlier'|''|NOT_STARTED
INCONCLUSIVE|window|''|contaminate|INCONCLUSIVE|'earlier'|''|NOT_STARTED
INCONCLUSIVE|window|''|disprove|DISPROVEN|'new'|'earlier'|NOT_STARTED
INCONCLUSIVE|window|'older'|fail|INCONCLUSIVE|'earlier'|'older'|NOT_STARTED
INCONCLUSIVE|window|'older'|fail-status|INCONCLUSIVE|'earlier'|'older'|NOT_STARTED
INCONCLUSIVE|window|'older'|contaminate|INCONCLUSIVE|'earlier'|'older'|NOT_STARTED
INCONCLUSIVE|window|'older'|disprove|DISPROVEN|'new'|'earlier'|NOT_STARTED
DISPROVEN|-|None|fail|DISPROVEN|'earlier'|'<absent>'|NOT_STARTED
DISPROVEN|-|None|fail-status|DISPROVEN|'earlier'|'<absent>'|NOT_STARTED
DISPROVEN|-|None|contaminate|INCONCLUSIVE|'new'|'earlier'|NOT_STARTED
DISPROVEN|-|None|disprove|DISPROVEN|'earlier'|'<absent>'|NOT_STARTED
DISPROVEN|-|''|fail|DISPROVEN|'earlier'|''|NOT_STARTED
DISPROVEN|-|''|fail-status|DISPROVEN|'earlier'|''|NOT_STARTED
DISPROVEN|-|''|contaminate|INCONCLUSIVE|'new'|'earlier'|NOT_STARTED
DISPROVEN|-|''|disprove|DISPROVEN|'earlier'|''|NOT_STARTED
DISPROVEN|-|'older'|fail|DISPROVEN|'earlier'|'older'|NOT_STARTED
DISPROVEN|-|'older'|fail-status|DISPROVEN|'earlier'|'older'|NOT_STARTED
DISPROVEN|-|'older'|contaminate|INCONCLUSIVE|'older'|'earlier'|NOT_STARTED
DISPROVEN|-|'older'|disprove|DISPROVEN|'earlier'|'older'|NOT_STARTED
DISPROVEN|window|None|fail|DISPROVEN|'earlier'|'<absent>'|NOT_STARTED
DISPROVEN|window|None|fail-status|DISPROVEN|'earlier'|'<absent>'|NOT_STARTED
DISPROVEN|window|None|contaminate|INCONCLUSIVE|'new'|'earlier'|NOT_STARTED
DISPROVEN|window|None|disprove|DISPROVEN|'earlier'|'<absent>'|NOT_STARTED
DISPROVEN|window|''|fail|DISPROVEN|'earlier'|''|NOT_STARTED
DISPROVEN|window|''|fail-status|DISPROVEN|'earlier'|''|NOT_STARTED
DISPROVEN|window|''|contaminate|INCONCLUSIVE|'new'|'earlier'|NOT_STARTED
DISPROVEN|window|''|disprove|DISPROVEN|'earlier'|''|NOT_STARTED
DISPROVEN|window|'older'|fail|DISPROVEN|'earlier'|'older'|NOT_STARTED
DISPROVEN|window|'older'|fail-status|DISPROVEN|'earlier'|'older'|NOT_STARTED
DISPROVEN|window|'older'|contaminate|INCONCLUSIVE|'older'|'earlier'|NOT_STARTED
DISPROVEN|window|'older'|disprove|DISPROVEN|'earlier'|'older'|NOT_STARTED";

fn text(value: &str) -> Text {
    Text::from(value)
}

fn opening(kernel: Option<Text>) -> Opening {
    Opening {
        profile: text("fis-read-latency"),
        episode: text("e1"),
        action: Value::String(text("aws:ebs:volume-io-latency")),
        attachment: Value::String(text("single")),
        targets: Value::Array(vec![
            Value::String(text("vol-1")),
            Value::String(text("vol-2")),
        ]),
        test_timeout_io_us: Value::Integer(Integer::from(200_000u64)),
        production_timeout_io_us: Value::Integer(Integer::from(30_000_000u64)),
        kernel_nvme_io_timeout: kernel,
    }
}

/// A section in the state a row names, reached through the rules alone, or none where no sequence
/// of the rules reaches it.
fn reached(verdict: &str, window: bool, diagnostic: Option<&str>) -> Option<Section> {
    let mut section = Section::new(opening(None));
    match (verdict, diagnostic) {
        ("HELD", None) => {}
        ("INVALID", None) => section.fail(Verdict::Invalid, text("earlier"), None),
        ("INCONCLUSIVE", None) => section.fail(Verdict::Inconclusive, text("earlier"), None),
        ("DISPROVEN", None) => section.fail(Verdict::Disproven, text("earlier"), None),
        ("INCONCLUSIVE", Some(diagnostic)) => {
            section.fail(Verdict::Disproven, text(diagnostic), None);
            section.contaminate(text("earlier"));
        }
        ("DISPROVEN", Some(diagnostic)) => {
            section.fail(Verdict::Inconclusive, text(diagnostic), None);
            section
                .insert("effect_window", Value::Object(Object::new()))
                .expect("effect_window is the caller's");
            section.disprove(text("earlier"));
            section
                .remove("effect_window")
                .expect("effect_window is the caller's");
        }
        _ => return None,
    }
    if window {
        let mut start = Object::new();
        start.insert("start_ordinal", Value::Integer(Integer::from(1u64)));
        section
            .insert("effect_window", Value::Object(start))
            .expect("effect_window is the caller's");
    }
    Some(section)
}

fn shown(section: &Section, key: &str) -> String {
    section
        .get(key)
        .map_or_else(|| "'<absent>'".to_owned(), repr)
}

/// Each rule records, replaces and keeps the failure by its own condition:
/// `fail` only while none stands, `contaminate` turning a `DISPROVEN` into `INCONCLUSIVE` with an
/// earlier nonempty diagnostic back in its place, and `disprove` replacing an `INCONCLUSIVE` once a
/// fault's window stands.
#[test]
fn each_verdict_under_each_rule_records_the_rule_s_outcome() {
    let mut checked = 0;
    for row in ROWS.lines() {
        let cells: Vec<&str> = row.split('|').collect();
        let [verdict, window, before, rule, after @ ..] = cells.as_slice() else {
            panic!("{row} has eight cells");
        };
        let diagnostic = match *before {
            "None" => None,
            quoted => Some(quoted.trim_matches('\'')),
        };
        let Some(mut section) = reached(verdict, *window == "window", diagnostic) else {
            continue;
        };
        match *rule {
            "fail" => section.fail(Verdict::Inconclusive, text("new"), None),
            "fail-status" => section.fail(Verdict::Invalid, text("new"), Some(Status::Halted)),
            "contaminate" => section.contaminate(text("new")),
            "disprove" => section.disprove(text("new")),
            other => panic!("{other} is a rule"),
        }
        let verdict_after = match section.get("verdict") {
            Some(Value::String(verdict)) => verdict.to_string(),
            other => panic!("{other:?} is a verdict"),
        };
        let status = match section.get("status") {
            Some(Value::String(status)) => status.to_string(),
            other => panic!("{other:?} is a status"),
        };
        let got = [
            verdict_after,
            shown(&section, "first_failure"),
            shown(&section, "diagnostic"),
            status,
        ];
        assert_eq!(got.as_slice(), after, "{row}");
        checked += 1;
    }
    assert_eq!(checked, 64, "every reachable row is checked");
}

/// The receipt before any phase holds the opening members and the three timeouts, written with sorted
/// keys and an indent of two, the kernel's timeout stripped and its line ends read as `\n`.
#[test]
fn the_section_before_any_phase_holds_its_opening_members() {
    let scratch = Scratch::new("opening");
    let kernel = scratch.path().join("io_timeout");
    for (bytes, timeout) in [
        (None, "null"),
        (Some(&b"30\n"[..]), "\"30\""),
        (Some(&b"\t 42 \r\n"[..]), "\"42\""),
        (Some(&b"a\rb\n"[..]), "\"a\\nb\""),
    ] {
        match bytes {
            Some(bytes) => fs::write(&kernel, bytes).expect("the timeout is written"),
            None => {
                let _ = fs::remove_file(&kernel);
            }
        }
        let read = kernel_timeout(&kernel).expect("the timeout reads");
        let receipt = json::indented(&Section::new(opening(read)).receipt())
            .expect("the receipt is finite")
            + "\n";
        assert_eq!(receipt, opening_receipt(timeout), "{bytes:?}");
    }
    fs::write(&kernel, b"\xff30\n").expect("the timeout is written");
    assert!(
        matches!(kernel_timeout(&kernel), Err(Failure::Unreadable(_))),
        "bytes that are no UTF-8 are refused"
    );
}

fn opening_receipt(timeout: &str) -> String {
    format!(
        "{{\n  \"envelope\": {{\n    \"section\": \"fis\",\n    \"version\": 1\n  }},\n  \"fis\": {{\n    \
         \"abort\": null,\n    \"action\": \"aws:ebs:volume-io-latency\",\n    \"attachment\": \"single\",\n    \
         \"episode\": \"e1\",\n    \"first_failure\": null,\n    \"profile\": \"fis-read-latency\",\n    \
         \"release_proof\": false,\n    \"status\": \"NOT_STARTED\",\n    \"targets\": [\n      \"vol-1\",\n      \
         \"vol-2\"\n    ],\n    \"timeouts\": {{\n      \"kernel_nvme_io_timeout\": {timeout},\n      \
         \"production_timeout_io_us\": 30000000,\n      \"test_timeout_io_us\": 200000\n    }},\n    \
         \"verdict\": \"HELD\"\n  }}\n}}\n"
    )
}

/// The rules own `verdict`, `first_failure`, `diagnostic` and `status`: a caller's insert or removal
/// of one is refused and leaves the section as it was, while a key of the caller's is set.
#[test]
fn a_caller_cannot_set_what_the_rules_own() {
    let mut section = Section::new(opening(None));
    let before = section.clone();
    for key in ["verdict", "first_failure", "diagnostic", "status"] {
        assert_eq!(
            section
                .insert(key, Value::Null)
                .map_err(|Owned(owned)| owned),
            Err(key)
        );
        assert!(section.remove(key).is_err(), "{key}");
        assert!(section.get_mut(key).is_none(), "{key}");
    }
    assert_eq!(section, before, "a refused change changes nothing");
    section
        .insert("experiment_id", Value::String(text("EXP1")))
        .expect("a caller's key is set");
    assert_eq!(
        section.get("experiment_id"),
        Some(&Value::String(text("EXP1")))
    );
    section.set_status(Status::ControllerLost);
    assert_eq!(
        section.get("status"),
        Some(&Value::String(text("CONTROLLER_LOST")))
    );
}
