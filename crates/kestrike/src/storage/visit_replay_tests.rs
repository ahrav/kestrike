//! Replays committed traces of the visit model `quint/visit.qnt` against one
//! volume, through the storage facade and the simulated device,
//! single-threaded, with objects a fill streamed to the device and
//! published.
//!
//! The model's `publish` reserves a fill for an object of one to three
//! extents, streams it, publishes it and keeps or drops the publisher's
//! lease; `invalidate` is `Storage::invalidate`, which retires the key's
//! object; `certify` is the grace certification; `release` drops the retired
//! object's lease; `read` reads the whole retired object under that lease;
//! and `visit` is one `Storage::service` call funded at the service minimum.
//! After every step the replay requires the call's outcome to equal the
//! step's recorded outcome, a visit's from the report's serviced and partial
//! counts, and then reads the volume: the raw ledger's resident bytes equal
//! the lengths of the model's visible objects, its retired bytes the length
//! of the extents the retired object still holds, its reserved bytes are
//! zero, its free bytes are the volume less the record units of every
//! visible object's extents and of the extents the retired object still
//! holds, and a lookup of each key hits the identity the model's visible
//! version was published as, or misses. A `read` step compares the bytes
//! with the payload of the retired version.
//!
//! A version's payload is `sequence_write_tests::payload` for its extent
//! count, seeded with the version. A publication runs with the test
//! helpers' budget and two gate tries, and the fill pass follows it so the
//! fill's record is free. Between steps only that fill pass runs, so every
//! return of an extent is a model `visit`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::attempt_tests::invalidate;
use super::attempt_tests::service as fill_pass;
use super::device::IO_UNIT;
use super::geometry::EXTENT_PAYLOAD;
use super::lookup_tests::lookup;
use super::owner::Storage;
use super::publish_tests::{RETRIES, TRIES, budget};
use super::sequence_write_tests::{payload, reserve, storage, stream};
use super::test_platform::TestPlatform;
use super::volume_fixture::{BUFFER, Device, arena_with, read_back, settle};
use super::{AllocationId, ExtentLease, LookupError, ReadStatus, WorkBudget};
use crate::index::Key;

const MODEL: &[u8] = include_bytes!("../../../../quint/visit.qnt");
const STATE: &str = "visitCase::visit::st";
/// Metadata bytes of every object, as `sequence_write_tests` reserves them.
const METADATA: usize = 24;
const FIXTURES: [(&str, &str); 8] = [
    (
        "three_extents",
        include_str!("visit_replay_fixtures/three_extents.itf.json"),
    ),
    (
        "right_held",
        include_str!("visit_replay_fixtures/right_held.itf.json"),
    ),
    (
        "beside",
        include_str!("visit_replay_fixtures/beside.itf.json"),
    ),
    (
        "direct",
        include_str!("visit_replay_fixtures/direct.itf.json"),
    ),
    (
        "step_a",
        include_str!("visit_replay_fixtures/step_a.itf.json"),
    ),
    (
        "step_b",
        include_str!("visit_replay_fixtures/step_b.itf.json"),
    ),
    (
        "step_c",
        include_str!("visit_replay_fixtures/step_c.itf.json"),
    ),
    (
        "step_d",
        include_str!("visit_replay_fixtures/step_d.itf.json"),
    ),
];

/// How the replay maps a model step to production calls.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Driver {
    /// Every model action runs its production calls.
    Faithful,
    /// The model's visit runs two service calls.
    VisitTwice,
    /// Each publication drops the lease the model records as kept.
    LeaseDropped,
}

/// Replaces every ITF big integer with a JSON number.
fn plain(v: &mut Value) {
    match v {
        Value::Object(map) if map.contains_key("#bigint") => {
            *v = map["#bigint"]
                .as_str()
                .unwrap()
                .parse::<i64>()
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

/// The record the model's map `name` holds for `key`.
fn of<'v>(state: &'v Value, name: &str, key: u64) -> Result<&'v Value, String> {
    state[name]["#map"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row[0] == key))
        .map(|row| &row[1])
        .ok_or(format!("model {name} of key {key}"))
}

fn fill_key(model_key: u64) -> Key {
    [u8::try_from(model_key).unwrap() + 1; 32]
}

/// The payload of version `version`, an object of `extents` extents.
fn bytes_of(extents: u64, version: u64) -> Vec<u8> {
    payload(usize::try_from(extents).unwrap(), version)
}

/// Units and write commands each extent's record takes, for a payload of
/// `len` bytes, from the record layout.
fn extent_records(storage: &Storage<TestPlatform>, len: usize) -> Vec<(usize, usize)> {
    let (m, b) = (METADATA as u32, (len - METADATA) as u32);
    (0..len.div_ceil(EXTENT_PAYLOAD as usize))
        .map(|index| {
            let start = index as u64 * EXTENT_PAYLOAD;
            let coverage = (len as u64 - start).min(EXTENT_PAYLOAD);
            let units = storage.record.extent_layout(m, b, coverage).record_units() as usize;
            (units, (units * IO_UNIT).div_ceil(BUFFER as usize))
        })
        .collect()
}

/// Whether a read of the whole object under `lease` completes with `expected`.
fn reads<'s>(
    dev: &mut Device<'s, '_>,
    lease: &ExtentLease<'s, TestPlatform>,
    expected: &[u8],
) -> bool {
    let delivered = read_back(&mut dev.volume, &dev.control, lease);
    delivered.status == ReadStatus::Complete && delivered.bytes == expected
}

/// Replays one trace and returns the `(action, outcome)` of every state,
/// `init` first.
///
/// # Errors
///
/// A trace whose model digest or length is wrong; otherwise the first step
/// whose production outcome, bytes, ledger or visible identity differs from
/// the model's state, named with its index; a malformed event or state; a
/// production call that fails outside the model's outcomes; or an action
/// the replay drives no call for.
///
/// # Panics
///
/// If a number the trace records is missing or is not an integer, or a
/// reservation, a stream, a read or a pass fails.
fn replay(json: &str, driver: Driver) -> Result<Vec<(String, String)>, String> {
    let mut trace: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["visit"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    plain(&mut trace);
    let states = trace["states"].as_array().ok_or("fixture states")?;
    if states.len() as u64 != n(&trace["#meta"]["visit"], "steps") + 1 {
        return Err("fixture length".into());
    }
    let storage = storage();
    let storage = &storage;
    let buffers = arena_with(4, 4);
    let mut dev = Device::new(storage, &buffers);
    let volume = storage.pool_report().unwrap().ledger.unwrap().raw.free;
    let mut objects: BTreeMap<u64, AllocationId> = BTreeMap::new();
    let mut leases: BTreeMap<u64, ExtentLease<'_, TestPlatform>> = BTreeMap::new();
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
        let model_key = n(ev, "key");
        let key = fill_key(model_key);
        let retired = &model["ret"];
        let outcome = match act {
            "init" if i == 0 => String::new(),
            "publish" => {
                let visible = of(model, "vis", model_key)?;
                let (version, streamed) =
                    (n(visible, "ver"), bytes_of(n(ev, "n"), n(visible, "ver")));
                let mut fill = reserve(storage, &key, &streamed);
                stream(&mut dev, &mut fill, &streamed, |_, _, _| {});
                let lease = fill
                    .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
                    .map_err(|error| format!("publish at {i}: {error:?}"))?;
                objects.insert(version, lease.id());
                settle(&mut dev.volume, &dev.control);
                fill_pass(storage);
                if res == "Leased" && driver != Driver::LeaseDropped {
                    leases.insert(version, lease);
                }
                res.into()
            }
            "invalidate" => {
                let ended = invalidate(storage, &key)
                    .map_err(|error| format!("invalidate at {i}: {error:?}"))?;
                if ended.removed.is_none() {
                    return Err(format!("invalidate at {i}: no object was removed"));
                }
                "Retired".into()
            }
            "certify" => {
                let _ = storage
                    .certify(&mut budget())
                    .map_err(|error| format!("certify at {i}: {error:?}"))?;
                "Certified".into()
            }
            "release" => {
                leases
                    .remove(&n(retired, "ver"))
                    .ok_or(format!("release at {i}: no retained lease"))?;
                "Dropped".into()
            }
            "read" => {
                let version = n(retired, "ver");
                let lease = leases
                    .get(&version)
                    .ok_or(format!("read at {i}: no retained lease"))?;
                if !reads(&mut dev, lease, &bytes_of(n(retired, "n"), version)) {
                    return Err(format!(
                        "read at {i}: the lease read other bytes than version {version}'s"
                    ));
                }
                "Read".into()
            }
            "visit" => {
                let visit = || {
                    let mut minimum = WorkBudget::new(storage.service_minimum());
                    storage
                        .service(&mut minimum)
                        .map(|report| (report.serviced, report.partial))
                        .map_err(|error| format!("visit at {i}: {error:?}"))
                };
                let first = visit()?;
                if driver == Driver::VisitTwice {
                    visit()?;
                }
                match first {
                    (0, 0) => "Idle".into(),
                    (0, 1) => "Partial".into(),
                    (1, 0) => "Returned".into(),
                    other => return Err(format!("visit at {i}: serviced and partial {other:?}")),
                }
            }
            action => return Err(format!("action {i}: unknown action {action}")),
        };
        if outcome != res {
            return Err(format!("{act} at {i}: {outcome}, recorded {res}"));
        }
        let (mut resident, mut units) = (0, 0);
        let mut reader = storage.register().unwrap();
        for model_key in 0..2 {
            let visible = of(model, "vis", model_key)?;
            let hit = lookup(&mut reader, &fill_key(model_key), RETRIES).map(|lease| lease.id());
            match n(visible, "ver") {
                0 if hit == Err(LookupError::Missing) => {}
                version if version != 0 && hit.as_ref().ok() == objects.get(&version) => {
                    let held = bytes_of(n(visible, "n"), 0).len();
                    resident += held;
                    units += extent_records(storage, held)
                        .iter()
                        .map(|r| r.0)
                        .sum::<usize>();
                }
                _ => return Err(format!("visible at {i}: key {model_key} {hit:?}")),
            }
        }
        // The retired object holds a prefix of its extents: whole extents,
        // and its short last extent only while it holds them all.
        let (count, held) = (n(retired, "n"), n(retired, "held") as usize);
        let mut prefix = 0;
        if held != 0 {
            let whole = bytes_of(count, 0).len();
            prefix = if held as u64 == count {
                whole
            } else {
                held * EXTENT_PAYLOAD as usize
            };
            units += extent_records(storage, whole)[..held]
                .iter()
                .map(|r| r.0)
                .sum::<usize>();
        }
        let raw = storage.pool_report().unwrap().ledger.unwrap().raw;
        let ledger = (raw.free, raw.reserved, raw.resident, raw.retired);
        if ledger != (volume - units * IO_UNIT, 0, resident, prefix) {
            return Err(format!("ledger at {i}: {ledger:?}"));
        }
        reached.push((act.to_owned(), res.to_owned()));
    }
    Ok(reached)
}

#[test]
fn committed_visit_traces_replay_and_reach_every_step_choice() {
    let mut reached = BTreeSet::new();
    for (name, json) in FIXTURES {
        reached.extend(
            replay(json, Driver::Faithful).unwrap_or_else(|error| panic!("{name}: {error}")),
        );
    }
    // `init` and every choice of the model's `step`.
    assert!(
        std::str::from_utf8(MODEL).unwrap().contains(
            "    any {publish(key, n, keep), invalidate(key), certify, release, read, visit}\n"
        ),
        "the model's step chooses among other actions than the replay drives"
    );
    let outcomes: BTreeSet<(&str, &str)> = reached
        .iter()
        .map(|(act, res)| (act.as_str(), res.as_str()))
        .collect();
    assert_eq!(
        outcomes,
        BTreeSet::from([
            ("certify", "Certified"),
            ("init", ""),
            ("invalidate", "Retired"),
            ("publish", "Leased"),
            ("publish", "Published"),
            ("read", "Read"),
            ("release", "Dropped"),
            ("visit", "Idle"),
            ("visit", "Partial"),
            ("visit", "Returned"),
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

/// Each wrong driver changes one production call a model step stands for,
/// and the replay refuses it: a second service call in one model visit
/// returns a second extent, which the ledger comparison refuses, and a
/// publication that drops the lease the model keeps lets a visit return an
/// extent the model holds, which the outcome comparison refuses.
#[test]
fn negative_control_a_wrong_visit_driver_fails_the_replay_at_its_step() {
    // three_extents: publish(0, 3), invalidate(0), visit, certify, visit at
    // 5: the model's visit returns the last extent, 3,000 bytes, and two
    // calls return a whole extent more.
    assert_eq!(
        replay(fixture("three_extents"), Driver::VisitTwice).unwrap_err(),
        format!(
            "ledger at 5: {:?}",
            (2_887_680, 0, 0, EXTENT_PAYLOAD as usize)
        )
    );
    // right_held: publish(0, 2, kept), invalidate(0), certify, visit at 4:
    // the model's lease holds the object.
    assert_eq!(
        replay(fixture("right_held"), Driver::LeaseDropped).unwrap_err(),
        "visit at 4: Partial, recorded Idle"
    );
}

/// A trace altered in one state's recorded field fails at that state, through
/// the comparison that reads the field; a stale model digest or a missing
/// state fails the trace before any state replays.
#[test]
fn negative_control_an_altered_visit_trace_fails_at_the_altered_state() {
    let json = fixture("three_extents");
    // State 7's event, the final return, is the only one that records
    // `Returned`.
    assert_eq!(json.matches(r#""res":"Returned""#).count(), 1);
    let outcome = json.replace(r#""res":"Returned""#, r#""res":"Partial""#);
    assert_eq!(
        replay(&outcome, Driver::Faithful).unwrap_err(),
        "visit at 7: Returned, recorded Partial"
    );
    let stale = json.replacen(r#""model_sha256":""#, r#""model_sha256":"0"#, 1);
    assert_eq!(
        replay(&stale, Driver::Faithful).unwrap_err(),
        "fixture model digest"
    );
    // State 5 holds two of the retired object's three extents; recorded as
    // holding all three, the retired bytes differ.
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"][5][STATE]["ret"]["held"] = serde_json::json!({"#bigint": "3"});
    assert!(
        replay(&trace.to_string(), Driver::Faithful)
            .unwrap_err()
            .starts_with("ledger at 5: ")
    );
    // State 2 retires key 0's object; recorded as still visible, the lookup
    // misses where the model hits.
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"][2][STATE]["vis"] = trace["states"][1][STATE]["vis"].clone();
    assert_eq!(
        replay(&trace.to_string(), Driver::Faithful).unwrap_err(),
        "visible at 2: key 0 Err(Missing)"
    );
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"][4]["mbt::actionTaken"] = "visit".into();
    assert_eq!(
        replay(&trace.to_string(), Driver::Faithful).unwrap_err(),
        "action 4: the event names another action"
    );
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"].as_array_mut().unwrap().pop();
    assert_eq!(
        replay(&trace.to_string(), Driver::Faithful).unwrap_err(),
        "fixture length"
    );
}
