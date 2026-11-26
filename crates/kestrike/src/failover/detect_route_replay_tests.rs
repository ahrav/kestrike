//! Detector timestamps are shifted by 20 so evidence stamps precede nominations. Probers a and b map to partitions
//! and classes 1 and 2. Placement is caller evidence. A route frame's model epoch `a` is the activated epoch `2a`.
//! A probe step is the model's alone: no Rust core runs for it, and a nomination builds its votes from the
//! recorded evidence flags. Every other detect step runs the cores and compares the result and, after each step,
//! the peer's stored suspicion kind, window health flag and declared count, capped at the model's 3.

use super::{arbiter::*, detect::*, identity::Exhid, route::*};
use crate::net::ownership::{ActivatedEpoch, ShardGeneration, Tenure};
use serde_json::Value;
use sha2::{Digest, Sha256};

const DETECT: [(&str, &str); 2] = [
    (
        "incident",
        include_str!("detect_route_fixtures/incident.itf.json"),
    ),
    ("gray", include_str!("detect_route_fixtures/gray.itf.json")),
];
const ROUTE: [(&str, &str); 2] = [
    (
        "conflict_ab",
        include_str!("detect_route_fixtures/conflict_ab.itf.json"),
    ),
    (
        "conflict_ba",
        include_str!("detect_route_fixtures/conflict_ba.itf.json"),
    ),
];

fn plain(v: &mut Value) {
    match v {
        Value::Object(map) if map.contains_key("#bigint") => {
            *v = map["#bigint"]
                .as_str()
                .unwrap()
                .parse::<i64>()
                .unwrap()
                .into()
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                plain(v);
            }
        }
        Value::Array(list) => {
            for v in list {
                plain(v);
            }
        }
        _ => {}
    }
}
fn n(v: &Value, key: &str) -> u64 {
    v[key].as_u64().unwrap()
}
fn b(v: &Value, key: &str) -> bool {
    v[key].as_bool().unwrap()
}
fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap()
}
fn field<'a>(v: &'a Value, family: &str, key: &str) -> &'a Value {
    &v[format!("coreCase::{family}::{key}")]
}

fn validate_trace(trace: &Value, model: &[u8]) -> Result<(), String> {
    let digest: String = Sha256::digest(model)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["cores"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    let states = trace["states"].as_array().ok_or("fixture states")?;
    let recipe = trace["#meta"]["cores"]["recipe"]
        .as_array()
        .ok_or("fixture recipe")?;
    if states.len() != recipe.len() + 1 {
        return Err("fixture recipe length".into());
    }
    Ok(())
}

/// `recorded_action` emits recipe entries in the driver's grammar. Nomination
/// evidence uses the initial state's evidence as `ready`, with changed fields
/// overlaid.
fn recorded_action(trace: &Value, state: &Value, family: &str) -> String {
    let ev = field(state, family, "ev");
    let frame = |f: &Value| {
        format!(
            "{{ g: {}, a: {}, x: {}, bound: {}, dark: {} }}",
            f["g"], f["a"], f["x"], f["bound"], f["dark"]
        )
    };
    match text(state, "mbt::actionTaken") {
        "beat" => format!("beat({}, {}, {})", ev["seq"], ev["progress"], ev["healthy"]),
        "closeWindow" => format!("closeWindow({}, {})", ev["observed"], ev["exhausted"]),
        "probe" => format!("probe({})", ev["who"]),
        "nominate" => {
            let ready = &field(&trace["states"][0], family, "ev")["evidence"];
            let changed: Vec<String> = ev["evidence"]
                .as_object()
                .unwrap()
                .iter()
                .filter(|(key, value)| ready[key] != **value)
                .map(|(key, value)| format!("{key}: {value}"))
                .collect();
            let evidence = if changed.is_empty() {
                "ready".into()
            } else {
                format!("{{ ...ready, {} }}", changed.join(", "))
            };
            format!("nominate({}, {evidence})", ev["who"])
        }
        action @ ("receive" | "response") => format!("{action}({})", frame(&ev["frame"])),
        action => action.into(),
    }
}

/// State `i` follows recipe entry `i - 1`; `states[0]` is the initial state.
fn declared_action(trace: &Value, i: usize, family: &str) -> Result<(), String> {
    let state = &trace["states"][i];
    let taken = text(state, "mbt::actionTaken");
    let act = if taken == "closeWindow" {
        "window"
    } else {
        taken
    };
    if field(state, family, "ev")["act"] != act
        || trace["#meta"]["cores"]["recipe"][i - 1] != recorded_action(trace, state, family)
    {
        return Err(format!("action {i}: recipe"));
    }
    Ok(())
}

fn decline_name(d: Decline) -> String {
    match d {
        Decline::SelfSuspect { .. } => "SelfSuspect".into(),
        d => format!("{d:?}"),
    }
}

fn replay_route(json: &str) -> Result<usize, String> {
    let mut trace: Value = serde_json::from_str(json).unwrap();
    validate_trace(&trace, include_bytes!("../../../../quint/route.qnt"))?;
    plain(&mut trace);
    let mut hw = None;
    for (i, state) in trace["states"].as_array().unwrap().iter().enumerate() {
        let e = field(state, "route", "ev");
        if i > 0 {
            declared_action(&trace, i, "route")?;
            let frame = || -> Result<HolderFrame, String> {
                let f = &e["frame"];
                let epoch = u32::try_from(n(f, "a"))
                    .ok()
                    .and_then(|a| a.checked_mul(2))
                    .and_then(ActivatedEpoch::new)
                    .ok_or(format!("frame epoch at {i}"))?;
                let host = u8::try_from(n(f, "x"))
                    .ok()
                    .and_then(|x| Exhid::new([x; 16]).ok())
                    .ok_or(format!("frame host at {i}"))?;
                Ok(HolderFrame {
                    tenure: Tenure {
                        generation: ShardGeneration::new(n(f, "g"))
                            .ok_or(format!("frame generation at {i}"))?,
                        epoch,
                        host,
                    },
                    kind: super::route_tests::kind(b(f, "bound"), b(f, "dark")),
                })
            };
            match text(e, "act") {
                "receive" => hw = Some(HighWater::merge(hw, frame()?)),
                "request" => {
                    if hw.is_some_and(HighWater::requests) != b(e, "sent") {
                        return Err(format!("request at {i}"));
                    }
                }
                "response" => {
                    let tenure = frame()?.tenure;
                    if hw.is_some_and(|h| h.response(tenure)) != b(e, "accepted") {
                        return Err(format!("response at {i}"));
                    }
                }
                action => return Err(format!("unknown action {action}")),
            }
        }
        let want = field(state, "route", "hw");
        let actual: (u64, u64, Option<[u8; 16]>, String) = hw
            .map(|h| {
                let kind = match h {
                    HighWater::Candidate(_) => "Candidate",
                    HighWater::Bound(_) => "Bound",
                    HighWater::Conflict { .. } => "Conflict",
                    HighWater::Dark { .. } => "Dark",
                };
                (
                    h.generation().get(),
                    u64::from(h.epoch().get() / 2),
                    h.host().map(|x| x.bytes()),
                    kind.into(),
                )
            })
            .unwrap_or((0, 0, None, "None".into()));
        if actual
            != (
                n(want, "g"),
                n(want, "a"),
                match n(want, "x") {
                    0 => None,
                    x => Some([u8::try_from(x).map_err(|_| format!("model host at {i}"))?; 16]),
                },
                text(want, "kind").into(),
            )
        {
            return Err(format!("high-water at {i}"));
        }
    }
    Ok(trace["states"].as_array().unwrap().len() - 1)
}

fn replay_detect(json: &str) -> Result<usize, String> {
    let mut trace: Value = serde_json::from_str(json).unwrap();
    validate_trace(&trace, include_bytes!("../../../../quint/detect.qnt"))?;
    plain(&mut trace);
    let mut peer = Peer::new(ObservationGeneration(1), 20);
    let mut nominated = false;
    let mut liveness = Liveness::Alive;
    for (i, state) in trace["states"].as_array().unwrap().iter().enumerate() {
        if i > 0 {
            declared_action(&trace, i, "detect")?;
        }
        let ev = field(state, "detect", "ev");
        let now = n(state, "coreCase::detect::now");
        let mut result = text(ev, "res").to_string();
        match text(ev, "act") {
            "init" => {}
            "beat" => {
                let before = peer;
                peer.heartbeat(n(ev, "seq"), n(ev, "progress"), b(ev, "healthy"));
                result = if peer == before {
                    "Duplicate"
                } else {
                    "Heartbeat"
                }
                .into();
            }
            "window" => {
                liveness = peer
                    .window(
                        &super::detect_tests::bounds(),
                        now + 20,
                        b(ev, "observed"),
                        b(ev, "exhausted"),
                    )
                    .unwrap();
                if let Liveness::Dead(s) = liveness {
                    let p = field(state, "detect", "peer");
                    if s.generation.0 != n(p, "generation") || s.since != n(p, "since") + 20 {
                        return Err(format!("suspicion at {i}"));
                    }
                }
                result = match liveness {
                    Liveness::Alive => "Alive",
                    Liveness::Unknown => "Unknown",
                    Liveness::Dead(s) => match s.failure {
                        Failure::Silent => "Silent",
                        Failure::Gray => "Gray",
                        Failure::Declared => "Declared",
                    },
                }
                .into();
            }
            // The model records the probe; the nomination below builds the votes from its evidence flags.
            "probe" => {}
            "nominate" => {
                let evidence = &ev["evidence"];
                let mut suspicion = match liveness {
                    Liveness::Dead(s) => s,
                    _ => return Err(format!("nomination lacks suspicion at {i}")),
                };
                if !b(evidence, "suspicionFresh") {
                    suspicion.since = now + 21;
                }
                let votes: Vec<_> = (0..n(evidence, "answers"))
                    .map(|j| Vote {
                        partition: Partition(if b(evidence, "distinct") {
                            j as u32 + 1
                        } else {
                            1
                        }),
                        class: ObserverClass(if b(evidence, "second") {
                            j as u32 + 1
                        } else {
                            1
                        }),
                        round: if b(evidence, "roundsValid") { 1 } else { 0 },
                        reading: if b(evidence, "alive") && j == 0 {
                            Liveness::Alive
                        } else if (b(evidence, "unknown") && j == 0) || j >= n(evidence, "dead") {
                            Liveness::Unknown
                        } else {
                            // The vote kinds follow the evidence flags alone: a declared vote first, then gray
                            // votes, silent ones when neither flag is set.
                            Liveness::Dead(Suspicion {
                                failure: if b(evidence, "declaredVotes") && j == 0 {
                                    Failure::Declared
                                } else if b(evidence, "grayVotes") {
                                    Failure::Gray
                                } else if b(evidence, "declaredVotes") {
                                    Failure::Declared
                                } else {
                                    Failure::Silent
                                },
                                ..suspicion
                            })
                        },
                    })
                    .collect();
                let t = now + 20;
                let at = |key: &str| (t as i64 - evidence[key].as_i64().unwrap()) as u64;
                let nomination = Nomination {
                    now: t,
                    suspicion,
                    observation: Observation {
                        generation: ObservationGeneration(n(evidence, "observation")),
                        target: super::arbiter_tests::target(),
                    },
                    holder_since: at("age"),
                    votes: &votes,
                    observer_healthy: b(evidence, "healthy"),
                    clock: if b(evidence, "clock") {
                        Clock::Trusted {
                            sampled_at: at("clockAge"),
                        }
                    } else {
                        Clock::Untrusted
                    },
                };
                let mut bounds = super::arbiter_tests::bounds();
                if !b(evidence, "boundsValid") {
                    bounds.k = 1;
                }
                if !b(evidence, "dwellValid") {
                    bounds.h = 3;
                }
                result = match nominate(&bounds, &nomination) {
                    Ok(_) => {
                        nominated = true;
                        "Nominate".into()
                    }
                    Err(d) => decline_name(d),
                };
            }
            "retrack" => {
                let p = field(state, "detect", "peer");
                peer.retrack(ObservationGeneration(n(p, "generation")), now + 20)
                    .unwrap();
                liveness = Liveness::Alive;
                result = "Retracked".into();
            }
            action => return Err(format!("unknown action {action}")),
        }
        if result != text(ev, "res") {
            return Err(format!("result at {i}: {result} != {}", text(ev, "res")));
        }
        if nominated != b(state, "coreCase::detect::nominated") {
            return Err(format!("nomination at {i}"));
        }
        let model = field(state, "detect", "peer");
        let kind = peer.suspicion().map_or("Alive", |s| match s.failure {
            Failure::Silent => "Silent",
            Failure::Gray => "Gray",
            Failure::Declared => "Declared",
        });
        let (affirmed, declared) = peer.declared_state();
        if (kind, affirmed, u64::from(declared.min(3)))
            != (
                text(model, "kind"),
                b(model, "affirmed"),
                n(model, "declared"),
            )
        {
            return Err(format!("peer state at {i}"));
        }
    }
    Ok(trace["states"].as_array().unwrap().len() - 1)
}

#[test]
fn committed_detect_traces_replay() {
    let actions: usize = DETECT
        .iter()
        .map(|(_, json)| replay_detect(json).unwrap())
        .sum();
    println!("core replay: traces=2 actions={actions} agreement=all");
}
#[test]
fn committed_route_traces_replay() {
    let actions: usize = ROUTE
        .iter()
        .map(|(_, json)| replay_route(json).unwrap())
        .sum();
    println!("core replay: traces=2 actions={actions} agreement=all");
}

/// `traces` holds Quint's regeneration of each declared trace; the committed
/// fixture must equal the model's states, so the workspace replay of committed
/// fixtures checks the model's traces.
fn generated_traces_replay(
    traces: ReplayScratch,
    fixtures: &[(&str, &str)],
    replay: fn(&str) -> Result<usize, String>,
) {
    let states = |text: &str| serde_json::from_str::<Value>(text).unwrap()["states"].take();
    let mut actions = 0;
    for (name, committed) in fixtures {
        let generated = traces.trace(name);
        assert_eq!(
            states(&generated),
            states(committed),
            "{name}: the committed trace differs from the model's"
        );
        actions += replay(&generated).unwrap();
    }
    println!(
        "core replay: traces={} actions={actions} agreement=all",
        fixtures.len()
    );
}
#[test]
#[ignore = "generated detect traces; the quint lane runs it with Quint on PATH"]
fn generated_detect_traces_replay() {
    generated_traces_replay(ReplayScratch::generate("detect"), &DETECT, replay_detect);
}
#[test]
#[ignore = "generated route traces; the quint lane runs it with Quint on PATH"]
fn generated_route_traces_replay() {
    generated_traces_replay(ReplayScratch::generate("route"), &ROUTE, replay_route);
}
#[test]
fn altered_route_and_nomination_results_fail_at_their_action() {
    let mut detect: Value = serde_json::from_str(DETECT[0].1).unwrap();
    detect["states"][6]["coreCase::detect::ev"]["res"] = "Quorum".into();
    assert!(
        replay_detect(&detect.to_string())
            .unwrap_err()
            .contains("result at 6")
    );
    let mut route: Value = serde_json::from_str(ROUTE[0].1).unwrap();
    route["states"][2]["coreCase::route::hw"]["kind"] = "Bound".into();
    assert!(
        replay_route(&route.to_string())
            .unwrap_err()
            .contains("high-water at 2")
    );
}

#[test]
fn stale_models_truncation_and_each_comparator_refuse() {
    let mut d: Value = serde_json::from_str(DETECT[0].1).unwrap();
    d["#meta"]["cores"]["model_sha256"] = "stale".into();
    assert_eq!(
        replay_detect(&d.to_string()).unwrap_err(),
        "fixture model digest"
    );
    let mut d: Value = serde_json::from_str(DETECT[0].1).unwrap();
    d["states"].as_array_mut().unwrap().pop();
    assert_eq!(
        replay_detect(&d.to_string()).unwrap_err(),
        "fixture recipe length"
    );
    let mut d: Value = serde_json::from_str(DETECT[0].1).unwrap();
    d["states"][6]["coreCase::detect::nominated"] = false.into();
    assert_eq!(
        replay_detect(&d.to_string()).unwrap_err(),
        "nomination at 6"
    );
    let mut d: Value = serde_json::from_str(DETECT[0].1).unwrap();
    d["states"][3]["coreCase::detect::peer"]["since"] = 99.into();
    assert_eq!(replay_detect(&d.to_string()).unwrap_err(), "suspicion at 3");
    for (i, key, error) in [
        (6, "sent", "request at 6"),
        (8, "accepted", "response at 8"),
    ] {
        let mut r: Value = serde_json::from_str(ROUTE[1].1).unwrap();
        r["states"][i]["coreCase::route::ev"][key] = false.into();
        assert_eq!(replay_route(&r.to_string()).unwrap_err(), error);
    }
    for key in ["g", "a", "x"] {
        let mut r: Value = serde_json::from_str(ROUTE[0].1).unwrap();
        r["states"][1]["coreCase::route::hw"][key] = 99.into();
        assert_eq!(
            replay_route(&r.to_string()).unwrap_err(),
            "high-water at 1",
            "a changed high-water {key} fails at its state"
        );
    }
}

#[test]
fn a_trace_off_its_declared_recipe_fails_at_that_action() {
    for (fixture, index, entry, error) in [
        (ROUTE[0].1, 0, "request", "action 1: recipe"),
        (
            ROUTE[0].1,
            1,
            "receive({ g: 2, a: 2, x: 1, bound: true, dark: false })",
            "action 2: recipe",
        ),
        (
            DETECT[0].1,
            0,
            "closeWindow(false, false)",
            "action 1: recipe",
        ),
        (DETECT[0].1, 3, "probe(\"b\")", "action 4: recipe"),
        (
            DETECT[0].1,
            5,
            "nominate(\"a\", { ...ready, answers: 0 })",
            "action 6: recipe",
        ),
        (DETECT[0].1, 6, "nominate(\"a\", ready)", "action 7: recipe"),
        (DETECT[1].1, 0, "beat(2, 1, true)", "action 1: recipe"),
        (DETECT[1].1, 0, "beat(1, 1, false)", "action 1: recipe"),
    ] {
        let mut trace: Value = serde_json::from_str(fixture).unwrap();
        trace["#meta"]["cores"]["recipe"][index] = entry.into();
        let replay = if fixture.contains("coreCase::route") {
            replay_route
        } else {
            replay_detect
        };
        assert_eq!(replay(&trace.to_string()).unwrap_err(), error);
    }
    for (fixture, index, act, error) in [
        (DETECT[1].1, 1, "window", "action 1: recipe"),
        (DETECT[0].1, 4, "init", "action 4: recipe"),
        (ROUTE[0].1, 3, "receive", "action 3: recipe"),
    ] {
        let mut trace: Value = serde_json::from_str(fixture).unwrap();
        let family = if fixture.contains("coreCase::route") {
            "route"
        } else {
            "detect"
        };
        trace["states"][index][format!("coreCase::{family}::ev")]["act"] = act.into();
        let replay = if fixture.contains("coreCase::route") {
            replay_route
        } else {
            replay_detect
        };
        assert_eq!(replay(&trace.to_string()).unwrap_err(), error);
    }
}

pub(in crate::failover) struct ReplayScratch(std::path::PathBuf);
impl ReplayScratch {
    /// A directory left by an interrupted run is replaced.
    fn create(path: std::path::PathBuf) -> ReplayScratch {
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        ReplayScratch(path)
    }

    /// Runs `quint/detect_route_check.py --family family --quint quint --output`
    /// into the scratch directory, named for the family and the process id.
    fn generate(family: &str) -> Self {
        Self::run(family, "detect_route_check.py", &["--family", family])
    }

    /// Runs `quint/<script> <args> --quint quint --output` into the scratch
    /// directory, named for `name` and the process id.
    pub(in crate::failover) fn run(name: &str, script: &str, args: &[&str]) -> Self {
        let out = std::env::temp_dir().join(format!("{name}-replay-{}", std::process::id()));
        let scratch = Self::create(out);
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let status = std::process::Command::new("python3")
            .arg(root.join("quint").join(script))
            .args(args)
            .args(["--quint", "quint"])
            .arg("--output")
            .arg(&scratch.0)
            .status()
            .unwrap();
        assert!(status.success(), "trace generation completed");
        scratch
    }

    pub(in crate::failover) fn trace(&self, name: &str) -> String {
        std::fs::read_to_string(self.0.join(format!("{name}.itf.json"))).unwrap()
    }
}
impl Drop for ReplayScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn a_scratch_directory_left_by_an_interrupted_run_is_replaced() {
    let out =
        std::env::temp_dir().join(format!("detect-route-replay-stale-{}", std::process::id()));
    std::fs::create_dir_all(out.join("stale")).unwrap();
    let scratch = ReplayScratch::create(out.clone());
    assert!(!out.join("stale").exists(), "stale contents are gone");
    drop(scratch);
    assert!(!out.exists(), "the scratch directory is removed on drop");
}

mod witness;
