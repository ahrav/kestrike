//! Replay of one detect trace per replayable reach recipe, and of an exhausted-then-observed recipe, against
//! the detector and arbiter cores.
//!
//! Each trace under `detect_witness_fixtures` runs one legal recipe of `quint/detect.qnt`, recorded by
//! `quint/detect_witness_fixtures.py`, and replays through [`replay_detect`]. The driver checks the model
//! digest and the recipe length, checks every recorded action against its declared recipe entry, and after
//! every action compares the core's result (a heartbeat or a duplicate, the window reading, the nomination
//! result, a retrack), the suspicion a dead reading names and the nominated flag with the model's state.
//!
//! Together the traces take `init` and every choice of the model's `step`: an observed window, a gap, an
//! exhausted window, a heartbeat, both probes, a nomination and a retrack. They end a nomination in the
//! admitted result and in every [`Decline`]. Three exhausted windows read `Unknown` while their counters
//! advance, so the observed window after them reads `Silent`. Three windows of unhealthy heartbeats read `Declared`;
//! a window after them with no heartbeat reads `Gray` while the suspicion stays declared, and one with a healthy
//! heartbeat turns the suspicion gray; three windows of unhealthy heartbeats after a gray suspicion turn it
//! declared. A declared suspicion nominates on one observer class, and mixed declared and gray evidence refuses
//! with the gray kind local and with it in a counted vote. A silent suspicion ends at its second window with a
//! healthy heartbeat when a window of unhealthy heartbeats separates the two.
//!
//! The model's `NotSuspect` result answers a nomination issued while the peer reads `Alive` or `Unknown`.
//! [`nominate`] takes a [`Suspicion`], and [`replay_detect`] takes it from the preceding dead reading, so
//! that result stays with the model's own reach case.

use std::collections::BTreeSet;

use super::*;

const WITNESSES: [(&str, &str); 32] = [
    (
        "Alive",
        include_str!("../detect_witness_fixtures/Alive.itf.json"),
    ),
    (
        "AliveWindow",
        include_str!("../detect_witness_fixtures/AliveWindow.itf.json"),
    ),
    (
        "Bounds",
        include_str!("../detect_witness_fixtures/Bounds.itf.json"),
    ),
    (
        "ClockUntrusted",
        include_str!("../detect_witness_fixtures/ClockUntrusted.itf.json"),
    ),
    (
        "Declared",
        include_str!("../detect_witness_fixtures/Declared.itf.json"),
    ),
    (
        "DeclaredAged",
        include_str!("../detect_witness_fixtures/DeclaredAged.itf.json"),
    ),
    (
        "DeclaredDemoted",
        include_str!("../detect_witness_fixtures/DeclaredDemoted.itf.json"),
    ),
    (
        "DeclaredKindGrayVotes",
        include_str!("../detect_witness_fixtures/DeclaredKindGrayVotes.itf.json"),
    ),
    (
        "DeclaredNominate",
        include_str!("../detect_witness_fixtures/DeclaredNominate.itf.json"),
    ),
    (
        "Duplicate",
        include_str!("../detect_witness_fixtures/Duplicate.itf.json"),
    ),
    (
        "Dwell",
        include_str!("../detect_witness_fixtures/Dwell.itf.json"),
    ),
    (
        "ExhaustedThenSilent",
        include_str!("../detect_witness_fixtures/ExhaustedThenSilent.itf.json"),
    ),
    (
        "Gap",
        include_str!("../detect_witness_fixtures/Gap.itf.json"),
    ),
    (
        "Gray",
        include_str!("../detect_witness_fixtures/Gray.itf.json"),
    ),
    (
        "GrayKindDeclaredVotes",
        include_str!("../detect_witness_fixtures/GrayKindDeclaredVotes.itf.json"),
    ),
    (
        "GrayNeedsSecondClass",
        include_str!("../detect_witness_fixtures/GrayNeedsSecondClass.itf.json"),
    ),
    (
        "GrayPromoted",
        include_str!("../detect_witness_fixtures/GrayPromoted.itf.json"),
    ),
    (
        "Heartbeat",
        include_str!("../detect_witness_fixtures/Heartbeat.itf.json"),
    ),
    (
        "HolderGrace",
        include_str!("../detect_witness_fixtures/HolderGrace.itf.json"),
    ),
    (
        "Nominate",
        include_str!("../detect_witness_fixtures/Nominate.itf.json"),
    ),
    (
        "ObserverUnhealthy",
        include_str!("../detect_witness_fixtures/ObserverUnhealthy.itf.json"),
    ),
    (
        "Probe",
        include_str!("../detect_witness_fixtures/Probe.itf.json"),
    ),
    (
        "ProbeBound",
        include_str!("../detect_witness_fixtures/ProbeBound.itf.json"),
    ),
    (
        "Quorum",
        include_str!("../detect_witness_fixtures/Quorum.itf.json"),
    ),
    (
        "Retracked",
        include_str!("../detect_witness_fixtures/Retracked.itf.json"),
    ),
    (
        "SelfSuspect",
        include_str!("../detect_witness_fixtures/SelfSuspect.itf.json"),
    ),
    (
        "Silent",
        include_str!("../detect_witness_fixtures/Silent.itf.json"),
    ),
    (
        "SilentExitAcrossUnhealthy",
        include_str!("../detect_witness_fixtures/SilentExitAcrossUnhealthy.itf.json"),
    ),
    (
        "StaleSuspicion",
        include_str!("../detect_witness_fixtures/StaleSuspicion.itf.json"),
    ),
    (
        "Time",
        include_str!("../detect_witness_fixtures/Time.itf.json"),
    ),
    (
        "Unknown",
        include_str!("../detect_witness_fixtures/Unknown.itf.json"),
    ),
    (
        "UnknownWindow",
        include_str!("../detect_witness_fixtures/UnknownWindow.itf.json"),
    ),
];

/// Every choice of the model's `step`, as a recipe entry with a heartbeat's and a nomination's arguments
/// removed.
const CHOICES: [&str; 8] = [
    "beat",
    "closeWindow(false, false)",
    "closeWindow(true, false)",
    "closeWindow(true, true)",
    "nominate",
    "probe(\"a\")",
    "probe(\"b\")",
    "retrack",
];

/// The admitted nomination and the name [`decline_name`] gives each decline.
fn result_name(result: Result<(), Decline>) -> &'static str {
    match result {
        Ok(()) => "Nominate",
        Err(Decline::Bounds) => "Bounds",
        Err(Decline::Dwell) => "Dwell",
        Err(Decline::ObserverUnhealthy) => "ObserverUnhealthy",
        Err(Decline::StaleSuspicion) => "StaleSuspicion",
        Err(Decline::HolderGrace) => "HolderGrace",
        Err(Decline::Alive) => "Alive",
        Err(Decline::Unknown) => "Unknown",
        Err(Decline::Quorum) => "Quorum",
        Err(Decline::SelfSuspect { .. }) => "SelfSuspect",
        Err(Decline::Time) => "Time",
        Err(Decline::ProbeBound) => "ProbeBound",
        Err(Decline::GrayNeedsSecondClass) => "GrayNeedsSecondClass",
        Err(Decline::ClockUntrusted) => "ClockUntrusted",
    }
}

/// Every nomination result the cores return.
fn results() -> BTreeSet<&'static str> {
    [
        Ok(()),
        Err(Decline::Bounds),
        Err(Decline::Dwell),
        Err(Decline::ObserverUnhealthy),
        Err(Decline::StaleSuspicion),
        Err(Decline::HolderGrace),
        Err(Decline::Alive),
        Err(Decline::Unknown),
        Err(Decline::Quorum),
        Err(Decline::SelfSuspect { until: 0 }),
        Err(Decline::Time),
        Err(Decline::ProbeBound),
        Err(Decline::GrayNeedsSecondClass),
        Err(Decline::ClockUntrusted),
    ]
    .map(result_name)
    .into()
}

fn witness(name: &str) -> Value {
    let (_, json) = WITNESSES
        .iter()
        .find(|(witness, _)| *witness == name)
        .unwrap();
    serde_json::from_str(json).unwrap()
}

fn event(trace: &mut Value, index: usize) -> &mut Value {
    &mut trace["states"][index]["coreCase::detect::ev"]
}

#[test]
fn committed_detect_witness_traces_replay() {
    let mut choices = BTreeSet::new();
    let mut nominations = BTreeSet::new();
    let mut actions = 0;
    for (name, json) in WITNESSES {
        actions += replay_detect(json).unwrap_or_else(|error| panic!("{name}: {error}"));
        let trace: Value = serde_json::from_str(json).unwrap();
        for entry in trace["#meta"]["cores"]["recipe"].as_array().unwrap() {
            let entry = entry.as_str().unwrap();
            let choice = ["beat", "nominate"]
                .into_iter()
                .find(|action| entry.starts_with(action))
                .unwrap_or(entry);
            choices.insert(choice.to_string());
        }
        for state in trace["states"].as_array().unwrap() {
            let ev = field(state, "detect", "ev");
            if ev["act"] == "nominate" {
                nominations.insert(text(ev, "res").to_string());
            }
        }
    }
    assert_eq!(
        choices.iter().map(String::as_str).collect::<Vec<_>>(),
        CHOICES,
        "the traces take every choice of the model's step"
    );
    assert_eq!(
        nominations
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        results(),
        "the traces end a nomination in every result the cores return"
    );
    println!(
        "witness replay: traces={} actions={actions} agreement=all",
        WITNESSES.len()
    );
}

/// Quint regenerates each trace `quint/detect_witness_fixtures.py` declares; the committed fixture must equal the
/// model's states, so the workspace replay of the committed fixtures replays the model's traces.
#[test]
#[ignore = "generated detect witness traces; the quint lane runs it with Quint on PATH"]
fn generated_detect_witness_traces_replay() {
    let traces = ReplayScratch::run("detect-witness", "detect_witness_fixtures.py", &[]);
    generated_traces_replay(traces, &WITNESSES, replay_detect);
}

#[test]
fn an_altered_witness_trace_fails_at_the_action_it_changes() {
    let mut unknown = witness("UnknownWindow");
    event(&mut unknown, 1)["res"] = "Alive".into();
    assert_eq!(
        replay_detect(&unknown.to_string()).unwrap_err(),
        "result at 1: Unknown != Alive",
        "an exhausted window reads Unknown"
    );

    let mut masked = witness("ExhaustedThenSilent");
    event(&mut masked, 4)["res"] = "Alive".into();
    assert_eq!(
        replay_detect(&masked.to_string()).unwrap_err(),
        "result at 4: Silent != Alive",
        "exhausted windows advance the empty count"
    );

    let mut gap = witness("Gap");
    event(&mut gap, 1)["res"] = "Silent".into();
    assert_eq!(
        replay_detect(&gap.to_string()).unwrap_err(),
        "result at 1: Alive != Silent"
    );

    for name in results() {
        let mut trace = witness(name);
        let last = trace["states"].as_array().unwrap().len() - 1;
        let other = if name == "Quorum" { "Alive" } else { "Quorum" };
        event(&mut trace, last)["res"] = other.into();
        assert_eq!(
            replay_detect(&trace.to_string()).unwrap_err(),
            format!("result at {last}: {name} != {other}"),
            "a nomination recorded as {other} where the cores return {name}"
        );
    }

    let mut aged = witness("DeclaredAged");
    event(&mut aged, 7)["res"] = "Declared".into();
    assert_eq!(
        replay_detect(&aged.to_string()).unwrap_err(),
        "result at 7: Gray != Declared",
        "a window with no heartbeat reads a declared suspicion gray"
    );

    let mut declined = witness("Quorum");
    declined["states"][4]["coreCase::detect::nominated"] = true.into();
    assert_eq!(
        replay_detect(&declined.to_string()).unwrap_err(),
        "nomination at 4",
        "a decline leaves the nominated flag false"
    );

    let mut shortened = witness("ExhaustedThenSilent");
    shortened["states"].as_array_mut().unwrap().remove(2);
    assert_eq!(
        replay_detect(&shortened.to_string()).unwrap_err(),
        "fixture recipe length"
    );

    let mut observed = witness("UnknownWindow");
    observed["#meta"]["cores"]["recipe"][0] = "closeWindow(true, false)".into();
    assert_eq!(
        replay_detect(&observed.to_string()).unwrap_err(),
        "action 1: recipe",
        "a recipe entry names the window kind the trace took"
    );
}
