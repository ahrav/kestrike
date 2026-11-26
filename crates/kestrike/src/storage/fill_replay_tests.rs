//! Replays committed traces of the fill-authority model `quint/fill.qnt`
//! against one shard's fill table: [`Storage::begin_fill`],
//! [`Storage::invalidate`], [`FillAttempt::abort`] and
//! [`Storage::service_fills`] on the heap-backed platform, single-threaded.
//!
//! Each model step runs its production call, and the replay then requires the
//! call's outcome to equal the step's recorded outcome and the decoded record
//! table and next serial to equal the model's state. Model keys 0 and 1 are
//! two keys of the one shard. The key stored beside each occupied record must
//! equal the key of the model's record. A trace replays with the shard's serial counter
//! as initialized, where model serial `s` is production serial `s`, and with
//! the counter planted so that the model's maximum of 3 falls on
//! [`SERIAL_MAX`]; a trace that records `AttemptExhausted` replays only
//! planted, since the unplanted counter is far from its maximum.
//!
//! The replay checks gate-ordered sequences only. Every production call runs
//! with the test helpers' budget of 1024 units and two gate tries, which
//! funds each call's whole bound, so every outcome follows the protocol's
//! rules. The replay publishes nothing, so production's pass releases every
//! departed record, as the model's does.

use std::collections::BTreeSet;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::attempt::{BeginError, FillAttempt};
use super::attempt_tests::{
    begin, departed, invalidate, live, next_serial, plant_serial, ready, records, revoked, service,
};
use super::fill::{FillSerial, Record, SERIAL_MAX};
use super::owner::Storage;
use super::publish_tests::key;
use super::test_platform::TestPlatform;
use crate::index::Key;

const MODEL: &[u8] = include_bytes!("../../../../quint/fill.qnt");
/// The model's serial maximum.
const MODEL_MAX: u64 = 3;
const STATE: &str = "fillCase::fill::st";
const FIXTURES: [(&str, &str); 9] = [
    (
        "replacement",
        include_str!("fill_replay_fixtures/replacement.itf.json"),
    ),
    (
        "exhausted",
        include_str!("fill_replay_fixtures/exhausted.itf.json"),
    ),
    ("full", include_str!("fill_replay_fixtures/full.itf.json")),
    (
        "in_progress",
        include_str!("fill_replay_fixtures/in_progress.itf.json"),
    ),
    (
        "second_record",
        include_str!("fill_replay_fixtures/second_record.itf.json"),
    ),
    (
        "step_a",
        include_str!("fill_replay_fixtures/step_a.itf.json"),
    ),
    (
        "step_b",
        include_str!("fill_replay_fixtures/step_b.itf.json"),
    ),
    (
        "step_c",
        include_str!("fill_replay_fixtures/step_c.itf.json"),
    ),
    (
        "step_d",
        include_str!("fill_replay_fixtures/step_d.itf.json"),
    ),
];

/// How the replay maps a model step to production calls.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Driver {
    /// Every model action runs its production call.
    Faithful,
    /// The model's invalidation runs nothing.
    RevokeDropped,
    /// The model's departure keeps the owner alive.
    DepartureDropped,
    /// The model's pass runs nothing.
    ServiceDropped,
}

/// Replaces every ITF big integer with a JSON number.
fn plain(v: &mut Value) {
    match v {
        Value::Object(map) if map.contains_key("#bigint") => {
            *v = map["#bigint"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                .into();
        }
        Value::Object(map) => map.values_mut().for_each(plain),
        Value::Array(list) => list.iter_mut().for_each(plain),
        _ => {}
    }
}

fn n(v: &Value, key: &str) -> u64 {
    v[key].as_u64().unwrap()
}

fn stored_keys(storage: &Storage<TestPlatform>) -> Vec<Key> {
    let table = storage.root_image.fills[0].as_ref().unwrap();
    // SAFETY: the mapping is live and this single-threaded replay holds no
    // fill gate while it copies the keys.
    unsafe { table.keys.as_slice(&storage.root) }.to_vec()
}

/// The record table the model's state names, with model serial `s` as
/// production serial `base + s`.
fn modeled(state: &Value, base: u64) -> Result<Vec<(Record, Option<Key>)>, String> {
    let rows = state["recs"]["#map"].as_array().ok_or("model records")?;
    let mut table = vec![(Record::Free, None); rows.len()];
    for row in rows {
        let (at, record) = (row[0].as_u64().ok_or("record index")? as usize, &row[1]);
        let (departed, revoked) = (
            record["departed"].as_bool().ok_or("departed flag")?,
            record["revoked"].as_bool().ok_or("revoked flag")?,
        );
        *table.get_mut(at).ok_or("record index range")? = match n(record, "serial") {
            0 if departed || revoked => return Err("a flag on a Free record".into()),
            0 => (Record::Free, None),
            serial => (
                Record::Occupied {
                    serial: base
                        .checked_add(serial)
                        .and_then(FillSerial::new)
                        .ok_or("record serial")?,
                    departed,
                    revoked,
                },
                Some(key(u8::try_from(n(record, "key"))
                    .map_err(|_| "record key")?
                    + 1)),
            ),
        };
    }
    Ok(table)
}

/// Returns the text the replay compares with a recipe entry.
fn recorded_action(act: &str, ev: &Value) -> String {
    match act {
        "begin" | "revoke" => format!("{act}({})", ev["key"]),
        "depart" => format!("depart({})", ev["serial"]),
        act => act.into(),
    }
}

/// Replays one trace with model serial `s` as production serial `base + s`
/// and returns the `(action, outcome)` of every state, `init` first.
///
/// # Errors
///
/// A trace whose model digest or length is wrong; otherwise the first step
/// whose production outcome, record table or next serial differs from the
/// model's state, named with its index, or whose event or record table is
/// malformed.
///
/// The first state in which an occupied record stores another key than the
/// model's record fails as `keys at {i}`.
///
/// A nonempty recipe must contain one entry for each state after `init`;
/// the replay reports a length mismatch as `fixture recipe length` and an
/// entry that differs from the state's recorded action as
/// `action {i}: recipe`.
///
/// # Panics
///
/// If a number the trace records is missing or is not an unsigned integer.
fn replay(json: &str, base: u64, driver: Driver) -> Result<Vec<(String, String)>, String> {
    let mut trace: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["fill"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    plain(&mut trace);
    let states = trace["states"].as_array().ok_or("fixture states")?;
    if states.len() as u64 != n(&trace["#meta"]["fill"], "steps") + 1 {
        return Err("fixture length".into());
    }
    let recipe = trace["#meta"]["fill"]["recipe"]
        .as_array()
        .ok_or("fixture recipe")?;
    if !recipe.is_empty() && recipe.len() + 1 != states.len() {
        return Err("fixture recipe length".into());
    }
    let storage = ready(2);
    if base != 0 {
        plant_serial(&storage, base + 1);
    }
    let mut owners: Vec<(u64, FillAttempt<'_, TestPlatform>)> = Vec::new();
    let mut reached = Vec::new();
    for (i, state) in states.iter().enumerate() {
        let model = &state[STATE];
        let ev = &model["ev"];
        let (act, res) = (
            ev["act"].as_str().ok_or("event action")?,
            ev["res"].as_str().ok_or("event outcome")?,
        );
        if state["mbt::actionTaken"] != act {
            return Err(format!("action {i}: the event names another action"));
        }
        if i > 0 && !recipe.is_empty() && recipe[i - 1] != recorded_action(act, ev).as_str() {
            return Err(format!("action {i}: recipe"));
        }
        let model_key = key(u8::try_from(n(ev, "key")).map_err(|_| "event key")? + 1);
        let outcome = match act {
            "init" if i == 0 => String::new(),
            "begin" => match begin(&storage, &model_key) {
                Ok(attempt) => {
                    if attempt.serial() != base + n(ev, "serial") || *attempt.key() != model_key {
                        return Err(format!("begin at {i}: serial {}", attempt.serial()));
                    }
                    owners.push((attempt.serial(), attempt));
                    "Granted".into()
                }
                Err(BeginError::InProgress) => "InProgress".into(),
                Err(BeginError::FillSlotsFull) => "FillSlotsFull".into(),
                Err(BeginError::AttemptExhausted) => "AttemptExhausted".into(),
                Err(error) => return Err(format!("begin at {i}: {error:?}")),
            },
            "revoke" if driver == Driver::RevokeDropped => res.into(),
            "revoke" => match invalidate(&storage, &model_key)
                .map_err(|error| format!("revoke at {i}: {error:?}"))?
                .revoked
            {
                Some(serial) if serial == base + n(ev, "serial") => "Revoked".into(),
                Some(serial) => return Err(format!("revoke at {i}: serial {serial}")),
                None => "None".into(),
            },
            "depart" => {
                let serial = base + n(ev, "serial");
                let at = owners
                    .iter()
                    .position(|(held, _)| *held == serial)
                    .ok_or(format!("depart at {i}: no live owner of serial {serial}"))?;
                let (_, attempt) = owners.swap_remove(at);
                if driver == Driver::DepartureDropped {
                    std::mem::forget(attempt);
                } else {
                    attempt.abort();
                }
                "Departed".into()
            }
            "service" if driver == Driver::ServiceDropped => res.into(),
            "service" => {
                let released = service(&storage).released as u64;
                if released != n(ev, "serial") {
                    return Err(format!("service at {i}: released {released}"));
                }
                if released == 0 { "Idle" } else { "Released" }.into()
            }
            action => return Err(format!("action {i}: unknown action {action}")),
        };
        if outcome != res {
            return Err(format!("{act} at {i}: {outcome}, recorded {res}"));
        }
        let (expected, keys): (Vec<_>, Vec<_>) = modeled(model, base)?.into_iter().unzip();
        if records(&storage) != expected {
            return Err(format!("records at {i}: {:?}", records(&storage)));
        }
        let stored = stored_keys(&storage);
        if keys
            .iter()
            .zip(&stored)
            .any(|(key, stored)| key.is_some_and(|key| key != *stored))
        {
            return Err(format!("keys at {i}: {stored:?}"));
        }
        let next = next_serial(&storage);
        if next != base + n(model, "next") {
            return Err(format!("next serial at {i}: {next}"));
        }
        reached.push((act.to_owned(), res.to_owned()));
    }
    Ok(reached)
}

fn exhausted(reached: &[(String, String)]) -> bool {
    reached.iter().any(|(_, res)| res == "AttemptExhausted")
}

/// The base that puts the model's serial maximum on [`SERIAL_MAX`].
const PLANTED: u64 = SERIAL_MAX - MODEL_MAX;

#[test]
fn committed_fill_traces_replay_and_reach_every_step_choice() {
    let mut reached = BTreeSet::new();
    for (name, json) in FIXTURES {
        let planted = replay(json, PLANTED, Driver::Faithful)
            .unwrap_or_else(|error| panic!("{name}, planted: {error}"));
        if !exhausted(&planted) {
            assert_eq!(
                replay(json, 0, Driver::Faithful),
                Ok(planted.clone()),
                "{name}, unplanted"
            );
        }
        reached.extend(planted);
    }
    // `init` and every choice of the model's `step`.
    assert!(
        std::str::from_utf8(MODEL)
            .unwrap()
            .contains("    any {begin(key), revoke(key), depart(serial), service}\n"),
        "the model's step chooses among other actions than the replay drives"
    );
    let actions: BTreeSet<&str> = reached.iter().map(|(act, _)| act.as_str()).collect();
    assert_eq!(
        actions,
        BTreeSet::from(["begin", "depart", "init", "revoke", "service"])
    );
    let outcomes: BTreeSet<&str> = reached.iter().map(|(_, res)| res.as_str()).collect();
    assert_eq!(
        outcomes,
        BTreeSet::from([
            "",
            "AttemptExhausted",
            "Departed",
            "FillSlotsFull",
            "Granted",
            "Idle",
            "InProgress",
            "None",
            "Released",
            "Revoked",
        ])
    );
}

fn fixture(name: &str) -> &'static str {
    FIXTURES
        .iter()
        .find(|(fixture, _)| *fixture == name)
        .unwrap()
        .1
}

#[test]
fn only_a_replayed_refusal_at_the_serial_maximum_skips_the_unplanted_replay() {
    let json = fixture("replacement");
    let meta = r##""#meta":{"fill":{"##;
    assert_eq!(json.matches(meta).count(), 1);
    let noted = json.replace(meta, r##""#meta":{"fill":{"note":"AttemptExhausted","##);
    let reached = replay(&noted, PLANTED, Driver::Faithful).unwrap();
    assert!(!exhausted(&reached));
    assert_eq!(replay(&noted, 0, Driver::Faithful), Ok(reached));
    assert!(exhausted(
        &replay(fixture("exhausted"), PLANTED, Driver::Faithful).unwrap()
    ));
}

/// Each wrong driver drops one production call the model's step stands for,
/// and the replay refuses it at the first state the missing effect shows in,
/// through the record table: the invalidation's or departure's own state, or
/// for a dropped pass the pass's state, where the model frees a record
/// production keeps.
#[test]
fn negative_control_a_driver_that_drops_a_call_fails_the_replay_at_that_step() {
    // replacement: begin(0), revoke(0), begin(0), depart(1), service, ...
    let json = fixture("replacement");
    for base in [0, PLANTED] {
        assert_eq!(
            replay(json, base, Driver::RevokeDropped).unwrap_err(),
            format!("records at 2: {:?}", [live(base + 1), Record::Free])
        );
        assert_eq!(
            replay(json, base, Driver::DepartureDropped).unwrap_err(),
            format!("records at 4: {:?}", [revoked(base + 1), live(base + 2)])
        );
    }
    // in_progress: ..., depart(1) at 5, begin(1) refused at 6, revoke(1) at
    // 7, begin(1) granted at 8, service at 9: the model's pass frees the
    // departed record 0, and without the pass both records stay occupied.
    assert_eq!(
        replay(fixture("in_progress"), PLANTED, Driver::ServiceDropped).unwrap_err(),
        format!(
            "records at 9: {:?}",
            [departed(PLANTED + 1, true), live(PLANTED + 2)]
        )
    );
}

/// A trace altered in one state's recorded field fails at that state, through
/// the comparison that reads the field; a stale model digest or a missing
/// state fails the trace before any state replays.
#[test]
fn negative_control_an_altered_trace_fails_at_the_altered_state() {
    let json = fixture("replacement");
    let altered = |from: &str, to: &str| {
        assert_eq!(json.matches(from).count(), 1, "{from}");
        json.replace(from, to)
    };
    // State 2's event, the revocation, is the only one that records
    // `Revoked`, so recording `None` there fails the outcome comparison.
    let outcome = altered(r#""res":"Revoked""#, r#""res":"None""#);
    assert_eq!(
        replay(&outcome, 0, Driver::Faithful).unwrap_err(),
        "revoke at 2: Revoked, recorded None"
    );
    let stale = json.replacen(r#""model_sha256":""#, r#""model_sha256":"0"#, 1);
    assert_eq!(
        replay(&stale, 0, Driver::Faithful).unwrap_err(),
        "fixture model digest"
    );
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"][3][STATE]["recs"]["#map"][1][1]["revoked"] = true.into();
    assert!(
        replay(&trace.to_string(), 0, Driver::Faithful)
            .unwrap_err()
            .starts_with("records at 3: ")
    );
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"][3][STATE]["next"] = serde_json::json!({"#bigint": "4"});
    assert_eq!(
        replay(&trace.to_string(), 0, Driver::Faithful).unwrap_err(),
        "next serial at 3: 3"
    );
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"][4]["mbt::actionTaken"] = "service".into();
    assert_eq!(
        replay(&trace.to_string(), 0, Driver::Faithful).unwrap_err(),
        "action 4: the event names another action"
    );
    for (name, state, row) in [
        ("second_record", 2, 1),
        ("second_record", 4, 1),
        ("in_progress", 5, 0),
    ] {
        let mut trace: Value = serde_json::from_str(fixture(name)).unwrap();
        trace["states"][state][STATE]["recs"]["#map"][row][1]["key"] =
            serde_json::json!({"#bigint": "0"});
        assert!(
            replay(&trace.to_string(), PLANTED, Driver::Faithful)
                .unwrap_err()
                .starts_with(&format!("keys at {state}: ")),
            "{name}"
        );
    }
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"].as_array_mut().unwrap().pop();
    assert_eq!(
        replay(&trace.to_string(), 0, Driver::Faithful).unwrap_err(),
        "fixture length"
    );
}

/// A directed trace whose state records another action, key or serial than
/// its recipe entry fails at that state, as does a trace that holds the
/// states of another recipe of the same length; a recipe of another length
/// fails the trace before any state replays.
#[test]
fn a_trace_off_its_declared_recipe_fails_at_that_action() {
    // full: begin(0), revoke(0), begin(1), begin(0), revoke(0), depart(2),
    // service, begin(0), depart(1), depart(3), service.
    let off = |edit: &dyn Fn(&mut Value)| {
        let mut trace: Value = serde_json::from_str(fixture("full")).unwrap();
        edit(&mut trace);
        replay(&trace.to_string(), PLANTED, Driver::Faithful).unwrap_err()
    };
    for (index, entry, error) in [
        (0, "begin(1)", "action 1: recipe"),
        (1, "revoke(1)", "action 2: recipe"),
        (5, "depart(1)", "action 6: recipe"),
        (6, "begin(0)", "action 7: recipe"),
    ] {
        assert_eq!(
            off(&|trace| trace["#meta"]["fill"]["recipe"][index] = entry.into()),
            error
        );
    }
    // `in_progress` holds eleven steps, as `full` does, and begins with a pass.
    let other: Value = serde_json::from_str(fixture("in_progress")).unwrap();
    assert_eq!(
        off(&|trace| trace["states"] = other["states"].clone()),
        "action 1: recipe"
    );
    assert_eq!(
        off(&|trace| {
            trace["#meta"]["fill"]["recipe"]
                .as_array_mut()
                .unwrap()
                .pop();
        }),
        "fixture recipe length"
    );
}
