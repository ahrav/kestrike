//! Replays committed traces of the builder-escrow model `quint/escrow.qnt`
//! against a heap-backed [`Storage`], single-threaded.
//!
//! The storage has the trace's `VOLUME`, 316 or 315 units, and six slots,
//! and every object's body is a whole number of extent payloads, so each
//! extent, a builder's and a direct claim's alike, is the model's `E` of 63
//! units. Every claim and return moves whole extents, so the free units less
//! the escrow stay `VOLUME` modulo 63: at 316 a promise can meet the charge
//! plus the clean reserve exactly, and at 315 the clean reserve alone can
//! refuse a promise or a claim.
//! Each model step runs one production call: `promise(k, n)` is
//! [`Storage::promise`] of an `n`-extent body held as builder `k`,
//! `place(k)` is one [`Builder::place`] funded for one extent, `cancel(k)` is
//! [`Builder::cancel`], the model's drop (`release(k)`) drops the builder,
//! `service` is one [`Storage::service`] funded at
//! [`Storage::service_minimum`], `claim` is a [`Storage::reserve`] of one
//! extent and `unclaim` cancels the latest claim. The replay then requires
//! the call's outcome to equal the model event's, and the storage to equal
//! the model's state: the escrow under the gate and in the pool report, the
//! free units, the free slots, and each builder's extents, placed extents
//! and remaining charge.

use std::collections::BTreeSet;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::super::ExtentReservation;
use super::{
    Builder, EXTENT_PAYLOAD, PromiseError, ReserveError, SLOTS, TestPlatform, budget, one,
};
use super::{Storage, WorkBudget, counts, snapshot, storage_with};

const MODEL: &[u8] = include_bytes!("../../../../../quint/escrow.qnt");
const STATE: &str = "escrowCase::escrow::st";
const EVENT: &str = "escrowCase::escrow::ev";
const FIXTURES: [(&str, &str); 14] = [
    (
        "an_exact_promise_succeeds_and_a_short_one_refuses",
        include_str!(
            "escrow_replay_fixtures/an_exact_promise_succeeds_and_a_short_one_refuses.itf.json"
        ),
    ),
    (
        "a_claim_beside_a_promise_spares_the_promised_units",
        include_str!(
            "escrow_replay_fixtures/a_claim_beside_a_promise_spares_the_promised_units.itf.json"
        ),
    ),
    (
        "two_builders_interleave_and_each_exit_refunds_once",
        include_str!(
            "escrow_replay_fixtures/two_builders_interleave_and_each_exit_refunds_once.itf.json"
        ),
    ),
    (
        "the_reserve_refuses_a_promise_of_exactly_the_allocatable_units",
        include_str!(
            "escrow_replay_fixtures/the_reserve_refuses_a_promise_of_exactly_the_allocatable_units.itf.json"
        ),
    ),
    (
        "every_exit_at_every_cut",
        include_str!("escrow_replay_fixtures/every_exit_at_every_cut.itf.json"),
    ),
    (
        "refusals_beside_promises_and_claims",
        include_str!("escrow_replay_fixtures/refusals_beside_promises_and_claims.itf.json"),
    ),
    (
        "step_e50",
        include_str!("escrow_replay_fixtures/step_e50.itf.json"),
    ),
    (
        "step_e51",
        include_str!("escrow_replay_fixtures/step_e51.itf.json"),
    ),
    (
        "step_e52",
        include_str!("escrow_replay_fixtures/step_e52.itf.json"),
    ),
    (
        "step_e53",
        include_str!("escrow_replay_fixtures/step_e53.itf.json"),
    ),
    (
        "step_e54",
        include_str!("escrow_replay_fixtures/step_e54.itf.json"),
    ),
    (
        "step_e55",
        include_str!("escrow_replay_fixtures/step_e55.itf.json"),
    ),
    (
        "step_e56",
        include_str!("escrow_replay_fixtures/step_e56.itf.json"),
    ),
    (
        "step_e57",
        include_str!("escrow_replay_fixtures/step_e57.itf.json"),
    ),
];

/// How the replay maps a model step to production calls.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Driver {
    /// Every model action runs its production call.
    Faithful,
    /// The model's cancel drops the builder instead, which parks its slot.
    CancelDrops,
    /// The model's promise asks for one extent more than the model names.
    PromiseLarger,
}

/// One model event: the action, its builder, its outcome, the charge it
/// names (a promise's object, a builder's whole charge or a claim's extent),
/// the builder's remaining charge and the free units and escrow before it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Event {
    act: String,
    who: usize,
    res: String,
    charge: u64,
    rem0: u64,
    free0: u64,
    u0: u64,
}

/// One model builder: its phase, extents, placed extents and remaining
/// charge.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Modeled {
    phase: String,
    extents: u32,
    placed: u32,
    rem: u64,
}

fn int(v: &Value, what: &str) -> Result<u64, String> {
    v["#bigint"]
        .as_str()
        .and_then(|digits| digits.parse().ok())
        .ok_or_else(|| format!("{what}: not a natural ITF big integer"))
}

fn event(ev: &Value) -> Result<Event, String> {
    Ok(Event {
        act: ev["act"].as_str().ok_or("event action")?.to_owned(),
        who: usize::try_from(int(&ev["who"], "event builder")?).map_err(|e| e.to_string())?,
        res: ev["res"].as_str().ok_or("event outcome")?.to_owned(),
        charge: int(&ev["charge"], "event charge")?,
        rem0: int(&ev["rem0"], "event remaining")?,
        free0: int(&ev["free0"], "event free")?,
        u0: int(&ev["u0"], "event escrow")?,
    })
}

/// The model's builders `1` and `2`, in order.
fn builders(st: &Value) -> Result<[Modeled; 2], String> {
    let mut out: [Option<Modeled>; 2] = [None, None];
    for pair in st["b"]["#map"].as_array().ok_or("builder map")? {
        let k = usize::try_from(int(&pair[0], "builder")?).map_err(|e| e.to_string())?;
        let b = &pair[1];
        let small = |v: &Value, what: &str| {
            int(v, what).and_then(|n| u32::try_from(n).map_err(|e| e.to_string()))
        };
        let slot = out
            .get_mut(k.wrapping_sub(1))
            .ok_or("builder outside the instance")?;
        *slot = Some(Modeled {
            phase: b["phase"].as_str().ok_or("builder phase")?.to_owned(),
            extents: small(&b["extents"], "extents")?,
            placed: small(&b["placed"], "placed")?,
            rem: int(&b["rem"], "rem")?,
        });
    }
    let [Some(first), Some(second)] = out else {
        return Err("builder map misses a builder".into());
    };
    Ok([first, second])
}

/// The production objects the replay holds for the model.
struct Held<'s> {
    builders: [Option<Builder<'s, TestPlatform>>; 2],
    claims: Vec<ExtentReservation<'s, TestPlatform>>,
}

fn refused(at: &str, error: PromiseError) -> Result<String, String> {
    match error {
        PromiseError::Reserve(ReserveError::CleanReserve) => Ok("clean_reserve".to_owned()),
        other => Err(format!("{at}: refused {other:?}")),
    }
}

/// Runs one model step's production call and returns its outcome in the
/// model's words.
fn run<'s>(
    storage: &'s Storage<TestPlatform>,
    held: &mut Held<'s>,
    ev: &Event,
    driver: Driver,
) -> Result<String, String> {
    let at = format!("{} of {}", ev.act, ev.who);
    let slot = |held: &mut Held<'s>| -> Result<usize, String> {
        ev.who
            .checked_sub(1)
            .filter(|&k| k < held.builders.len())
            .ok_or_else(|| format!("{at}: builder outside the instance"))
    };
    match ev.act.as_str() {
        "promise" => {
            let k = slot(held)?;
            let mut extents = usize::try_from(ev.charge / 63).map_err(|e| e.to_string())?;
            if driver == Driver::PromiseLarger {
                extents += 1;
            }
            let body = extents * EXTENT_PAYLOAD as usize;
            match storage.promise(Some(0), Some(body), &mut budget()) {
                Ok(builder) => {
                    held.builders[k] = Some(builder);
                    Ok("ok".to_owned())
                }
                Err(error) => refused(&at, error),
            }
        }
        "place" => {
            let k = slot(held)?;
            let builder = held.builders[k]
                .as_mut()
                .ok_or_else(|| format!("{at}: the replay holds no builder"))?;
            let complete = builder
                .place(&mut one(builder))
                .map_err(|error| format!("{at}: refused {error:?}"))?;
            Ok(if complete { "complete" } else { "partial" }.to_owned())
        }
        "cancel" | "drop" => {
            let k = slot(held)?;
            let builder = held.builders[k]
                .take()
                .ok_or_else(|| format!("{at}: the replay holds no builder"))?;
            if ev.act == "cancel" && driver != Driver::CancelDrops {
                builder.cancel();
            } else {
                drop(builder);
            }
            Ok("ok".to_owned())
        }
        "service" => {
            let mut funded = WorkBudget::new(storage.service_minimum());
            let report = storage
                .service(&mut funded)
                .map_err(|error| format!("{at}: refused {error:?}"))?;
            match (report.serviced, report.partial) {
                (0, 0) => Ok("idle".to_owned()),
                (0, 1) => Ok("partial".to_owned()),
                (1, 0) => Ok("serviced".to_owned()),
                other => Err(format!("{at}: (serviced, partial) {other:?}")),
            }
        }
        "claim" => match storage.reserve(Some(0), Some(EXTENT_PAYLOAD as usize), &mut budget()) {
            Ok(claim) => {
                held.claims.push(claim);
                Ok("ok".to_owned())
            }
            Err(ReserveError::CleanReserve) => Ok("clean_reserve".to_owned()),
            Err(other) => Err(format!("{at}: refused {other:?}")),
        },
        "unclaim" => {
            let claim = held
                .claims
                .pop()
                .ok_or_else(|| format!("{at}: the replay holds no claim"))?;
            claim
                .cancel()
                .map_err(|error| format!("{at}: refused {error:?}"))?;
            Ok("ok".to_owned())
        }
        act => Err(format!("unknown model action {act}")),
    }
}

/// Replays one committed trace and returns the events it reached.
fn replay(json: &str, driver: Driver) -> Result<Vec<Event>, String> {
    let trace: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["escrow"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    let states = trace["states"].as_array().ok_or("fixture states")?;
    if Some(states.len() as u64)
        != trace["#meta"]["escrow"]["steps"]
            .as_u64()
            .map(|steps| steps + 1)
    {
        return Err("fixture length".into());
    }
    let volume = trace["#meta"]["escrow"]["volume"]
        .as_u64()
        .ok_or("fixture volume")?;
    let first = event(&states[0][EVENT])?;
    if first.act != "init" || int(&states[0][STATE]["free"], "free")? != volume {
        return Err("the trace does not start at init".into());
    }

    let units = usize::try_from(volume).map_err(|e| e.to_string())?;
    let storage = storage_with(units, 1, 3 * EXTENT_PAYLOAD as usize);
    let mut held = Held {
        builders: [None, None],
        claims: Vec::new(),
    };
    let mut reached = vec![first];
    for (i, state) in states.iter().enumerate().skip(1) {
        let st = &state[STATE];
        let ev = event(&state[EVENT])?;
        let at = format!("{} at {i}", ev.act);
        let res = run(&storage, &mut held, &ev, driver)?;
        if res != ev.res {
            return Err(format!("{at}: outcome {res}, model {}", ev.res));
        }
        let (escrow, free, _) = counts(&storage);
        let reported = storage.pool_report().ok_or("pool report")?.escrow_units;
        let slots = snapshot(&storage).0;
        let parked = usize::from(st["parked"].as_bool().ok_or("parked")?);
        let modeled = builders(st)?;
        let building = modeled.iter().filter(|b| b.phase == "building").count();
        let direct = usize::try_from(int(&st["direct"], "direct")?).map_err(|e| e.to_string())?;
        let seen = (escrow, reported, free, slots);
        let want = (
            int(&st["u"], "u")?,
            int(&st["u"], "u")?,
            int(&st["free"], "free")?,
            SLOTS - building - direct - parked,
        );
        if seen != want {
            return Err(format!(
                "{at}: (escrow, reported escrow, free, free slots) {seen:?}, model {want:?}"
            ));
        }
        for (k, (model, builder)) in modeled.iter().zip(&held.builders).enumerate() {
            let seen = builder
                .as_ref()
                .map(|b| (b.extents(), b.placed(), b.remaining()));
            let want =
                (model.phase == "building").then_some((model.extents, model.placed, model.rem));
            if seen != want {
                return Err(format!(
                    "{at}: builder {} (extents, placed, remaining) {seen:?}, model {want:?}",
                    k + 1
                ));
            }
        }
        if held.claims.len() != direct {
            return Err(format!(
                "{at}: {} claims, model {direct}",
                held.claims.len()
            ));
        }
        reached.push(ev);
    }
    Ok(reached)
}

fn fixture(name: &str) -> &'static str {
    FIXTURES
        .iter()
        .find(|(fixture, _)| *fixture == name)
        .map(|(_, json)| *json)
        .unwrap()
}

/// The cut an exit ran at: before any placement, between placements, or
/// after the last.
fn cut(ev: &Event) -> &'static str {
    match ev.act.as_str() {
        "cancel" | "drop" if ev.rem0 == ev.charge => "unplaced",
        "cancel" | "drop" if ev.rem0 == 0 => "complete",
        "cancel" | "drop" => "partial",
        _ => "",
    }
}

#[test]
fn committed_escrow_traces_replay_and_reach_every_step_choice() {
    let mut reached = BTreeSet::new();
    for (name, json) in FIXTURES {
        let events = replay(json, Driver::Faithful).unwrap_or_else(|e| panic!("{name}: {e}"));
        reached.extend(events);
    }
    assert!(reached.iter().any(|ev| ev.act == "init"));
    // Every choice of the model's step: a promise of each size by each
    // builder, each builder's placement, cancel and drop, and the calls
    // that name no builder.
    let choices: BTreeSet<(&str, usize, u64)> = reached
        .iter()
        .filter(|ev| ev.act != "init")
        .map(|ev| match ev.act.as_str() {
            "promise" => (ev.act.as_str(), ev.who, ev.charge / 63),
            _ => (ev.act.as_str(), ev.who, 0),
        })
        .collect();
    let mut every: BTreeSet<(&str, usize, u64)> = [1, 2]
        .into_iter()
        .flat_map(|k| {
            [
                ("promise", k, 2),
                ("promise", k, 3),
                ("place", k, 0),
                ("cancel", k, 0),
                ("drop", k, 0),
            ]
        })
        .collect();
    every.extend([("service", 0, 0), ("claim", 0, 0), ("unclaim", 0, 0)]);
    assert_eq!(choices, every);
    // Every outcome of every action, and each exit at each cut.
    let outcomes: BTreeSet<(&str, &str, &str)> = reached
        .iter()
        .filter(|ev| ev.act != "init")
        .map(|ev| (ev.act.as_str(), ev.res.as_str(), cut(ev)))
        .collect();
    let expected: BTreeSet<(&str, &str, &str)> = [
        ("promise", "ok", ""),
        ("promise", "clean_reserve", ""),
        ("place", "partial", ""),
        ("place", "complete", ""),
        ("cancel", "ok", "unplaced"),
        ("cancel", "ok", "partial"),
        ("cancel", "ok", "complete"),
        ("drop", "ok", "unplaced"),
        ("drop", "ok", "partial"),
        ("drop", "ok", "complete"),
        ("service", "idle", ""),
        ("service", "partial", ""),
        ("service", "serviced", ""),
        ("claim", "ok", ""),
        ("claim", "clean_reserve", ""),
        ("unclaim", "ok", ""),
    ]
    .into_iter()
    .collect();
    assert_eq!(outcomes, expected);
    // The clean reserve's boundary from both sides: a promise and a claim
    // that leave exactly the reserve free succeed, and ones that would
    // spend it refuse.
    let edges: BTreeSet<(&str, &str, i64)> = reached
        .iter()
        .filter(|ev| ev.act == "promise" || ev.act == "claim")
        .map(|ev| {
            let left = ev.free0 as i64 - ev.u0 as i64 - ev.charge as i64;
            (ev.act.as_str(), ev.res.as_str(), left)
        })
        .filter(|(_, _, left)| *left == 0 || *left == 1)
        .collect();
    let both: BTreeSet<(&str, &str, i64)> = [
        ("promise", "ok", 1),
        ("promise", "clean_reserve", 0),
        ("claim", "ok", 1),
        ("claim", "clean_reserve", 0),
    ]
    .into_iter()
    .collect();
    assert_eq!(edges, both);
}

#[test]
fn negative_control_a_wrong_escrow_driver_fails_the_replay_at_that_step() {
    assert_eq!(
        replay(fixture("every_exit_at_every_cut"), Driver::CancelDrops),
        Err(
            "cancel at 2: (escrow, reported escrow, free, free slots) (0, 0, 316, 5), \
             model (0, 0, 316, 6)"
                .into()
        )
    );
    assert_eq!(
        replay(
            fixture("two_builders_interleave_and_each_exit_refunds_once"),
            Driver::PromiseLarger,
        ),
        Err(
            "promise at 1: (escrow, reported escrow, free, free slots) (189, 189, 316, 5), \
             model (126, 126, 316, 5)"
                .into()
        )
    );
}

#[test]
fn negative_control_an_altered_escrow_trace_fails_at_the_altered_state() {
    let json = fixture("an_exact_promise_succeeds_and_a_short_one_refuses");
    let altered = json.replacen(r#""res":"clean_reserve""#, r#""res":"ok""#, 1);
    assert_ne!(altered, json);
    assert_eq!(
        replay(&altered, Driver::Faithful),
        Err("promise at 4: outcome clean_reserve, model ok".into())
    );
    let stale = json.replacen(r#""model_sha256":""#, r#""model_sha256":"0"#, 1);
    assert_eq!(
        replay(&stale, Driver::Faithful),
        Err("fixture model digest".into())
    );
    let short = json.replacen(r#""steps":5"#, r#""steps":6"#, 1);
    assert_ne!(short, json);
    assert_eq!(
        replay(&short, Driver::Faithful),
        Err("fixture length".into())
    );
}
