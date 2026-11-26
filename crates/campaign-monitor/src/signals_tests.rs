//! Detector tests over hand-built format-1 snapshots.

use serde_json::{Value, json};

use super::*;

fn snapshot(value: Value) -> Snapshot {
    let mut base = json!({
        "format": 1, "observed_ms": 10_000_000, "state": "/state", "config": null, "probes": 0,
        "held_probes": [],
        "jobs": [], "findings": [], "failure_groups": [],
        "space": {"free_bytes": 1u64 << 40, "free_inodes": 1_000_000},
    });
    for (key, field) in value.as_object().unwrap() {
        base[key] = field.clone();
    }
    serde_json::from_value(base).unwrap()
}

fn space_facts(free_bytes: u64) -> Value {
    json!({"free_bytes": free_bytes, "free_inodes": 1_000_000})
}

fn job(id: &str, profile: &str, run: u64, class: &str, cause: Option<&str>) -> Value {
    json!({
        "id": id, "profile": profile, "campaign": "c", "run": run, "build": "b1", "variant": "v1",
        "state": "settled",
        "result": {"attempt": 1, "class": class},
        "attempts": [{
            "number": 1, "attempt": format!("{id}-0001"), "intent_ms": 1_000, "finished_ms": 6_000,
            "finished": {"class": class, "binding": "matching",
                         "kernel": {"cpu_usage_usec": 1_000, "cpu_throttled_usec": 0}},
            "sim": {"terminal": "complete", "cause": cause},
        }],
    })
}

fn detectors(signals: &[Signal]) -> Vec<&'static str> {
    signals.iter().map(|signal| signal.detector).collect()
}

fn of<'a>(signals: &'a [Signal], detector: &str) -> Vec<&'a Signal> {
    signals
        .iter()
        .filter(|signal| signal.detector == detector)
        .collect()
}

fn group(identity: Option<&str>) -> Value {
    json!({
        "kind": "violation", "identity": identity, "cause": "violation, violating Progress",
        "findings": ["a-0001", "b-0001"], "profiles": ["get"], "runs": [0, 2], "unresolved": 2,
    })
}

#[test]
fn an_unresolved_failure_group_is_new_when_the_newest_earlier_sample_lacks_its_identity() {
    let shown = snapshot(json!({"failure_groups": [group(Some("02aa"))]}));
    let earlier = Sample {
        observed_ms: 1,
        ..Sample::default()
    };
    let signals = detect(&shown, std::slice::from_ref(&earlier));
    assert_eq!(signals[0].severity, Severity::Critical);
    assert_eq!(signals[0].domain, Domain::Service);
    assert!(
        signals[0]
            .title
            .starts_with("NEW violation, violating Progress in get")
    );
    assert_eq!(signals[0].subjects, vec!["a-0001", "b-0001"]);

    let recorded = Sample::of(&shown);
    assert_eq!(
        *recorded.identities,
        BTreeSet::from(["9:violation=02aa".to_owned()])
    );
    assert_eq!(recorded.free_bytes, Some(1 << 40));
    let seen = Sample {
        observed_ms: 2,
        ..recorded.clone()
    };
    assert!(
        !detect(&shown, std::slice::from_ref(&seen))[0]
            .title
            .starts_with("NEW")
    );
    assert!(
        detect(
            &shown,
            &[
                seen,
                Sample {
                    observed_ms: 3,
                    ..earlier
                }
            ]
        )[0]
        .title
        .starts_with("NEW")
    );
    let other = snapshot(json!({"failure_groups": [group(Some("03bb"))]}));
    assert!(
        detect(
            &other,
            &[Sample {
                observed_ms: 2,
                ..recorded
            }]
        )[0]
        .title
        .starts_with("NEW")
    );
    assert!(
        detect(&shown, &[])
            .iter()
            .all(|signal| !signal.title.starts_with("NEW"))
    );

    let unnamed = snapshot(json!({"failure_groups": [group(None)]}));
    assert_eq!(
        *Sample::of(&unnamed).identities,
        BTreeSet::from(["9:violation#a-0001".to_owned()])
    );
}

#[test]
fn a_failure_group_is_new_unless_history_holds_its_kind_identity_or_finding() {
    let unnamed = |finding: &str| {
        json!({"kind": "watchdog", "identity": null, "cause": "watchdog", "findings": [finding],
               "profiles": ["get"], "runs": [0], "unresolved": 1})
    };
    let new_subjects = |earlier: Value, later: Value| {
        let earlier = Sample::of(&snapshot(
            json!({"observed_ms": 1, "failure_groups": earlier}),
        ));
        let signals = detect(
            &snapshot(json!({"failure_groups": later})),
            std::slice::from_ref(&earlier),
        );
        of(&signals, "failure-group")
            .into_iter()
            .filter(|signal| signal.title.starts_with("NEW"))
            .flat_map(|signal| signal.subjects.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        new_subjects(
            json!([unnamed("a-0001")]),
            json!([unnamed("a-0001"), unnamed("b-0001")])
        ),
        ["b-0001"]
    );
    let mut abort = group(Some("02aa"));
    abort["kind"] = json!("abort");
    assert_eq!(
        new_subjects(json!([group(Some("02aa"))]), json!([abort])),
        ["a-0001", "b-0001"]
    );
}

#[test]
fn the_failure_group_detail_quotes_the_state_path_and_names_the_cgroup_root() {
    let shown = snapshot(json!({"state": "/a b/it's", "failure_groups": [group(Some("02aa"))]}));
    let detail = &detect(&shown, &[])[0].detail;
    assert!(
        detail.contains(r"campaign triage --state '/a b/it'\''s' --cgroup-root <dir>"),
        "{detail}"
    );
    assert!(detail.contains("CAMPAIGN_CGROUP_ROOT"), "{detail}");
    assert!(
        detail.contains(r"campaign dispose --state '/a b/it'\''s' --finding"),
        "{detail}"
    );
}

#[test]
fn a_finished_attempt_count_is_recorded_from_rows_with_a_finish_time() {
    let mut running = job("r", "get", 1, "pass", None);
    running["attempts"][0]["finished_ms"] = Value::Null;
    let shown = snapshot(json!({"jobs": [job("f", "get", 0, "pass", None), running]}));
    assert_eq!(Sample::of(&shown).attempts, 1);
}

#[test]
fn a_profile_that_passes_under_one_seed_and_fails_under_another_is_a_service_warning() {
    let shown = snapshot(json!({"jobs": [
        job("a", "get", 0, "violation", None),
        job("b", "get", 1, "pass", None),
        job("c", "put", 0, "pass", None),
        job("d", "put", 1, "pass", None),
    ]}));
    let signals = detect(&shown, &[]);
    let signals = of(&signals, "seed-sensitive");
    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].severity, Severity::Warning);
    assert_eq!(signals[0].domain, Domain::Service);
    assert_eq!(
        signals[0].detail,
        "campaign c, build b1, variant v1: pass in runs 1; violation in runs 0"
    );
    assert_eq!(signals[0].subjects, vec![r#"["c","get","b1","v1"]"#]);
}

#[test]
fn seed_sensitivity_compares_one_campaign_and_keys_slash_names_apart() {
    let mut other = job("b", "get", 1, "pass", None);
    other["campaign"] = json!("d");
    let shown = snapshot(json!({"jobs": [job("a", "get", 0, "violation", None), other]}));
    assert!(!detectors(&detect(&shown, &[])).contains(&"seed-sensitive"));

    let workload = |campaign: &str, profile: &str| {
        let mut failed = job("a", profile, 0, "violation", None);
        let mut passed = job("b", profile, 1, "pass", None);
        failed["campaign"] = json!(campaign);
        passed["campaign"] = json!(campaign);
        let signals = detect(&snapshot(json!({"jobs": [failed, passed]})), &[]);
        of(&signals, "seed-sensitive")[0].key()
    };
    assert_ne!(workload("a/b", "c"), workload("a", "b/c"));
}

#[test]
fn seed_sensitivity_compares_one_build() {
    let mut old = job("a", "get", 0, "violation", None);
    old["build"] = json!("b1");
    let mut fixed = job("b", "get", 1, "pass", None);
    fixed["build"] = json!("b2");
    let shown = snapshot(json!({"jobs": [old, fixed]}));
    assert!(!detectors(&detect(&shown, &[])).contains(&"seed-sensitive"));
}

#[test]
fn inconclusive_stops_at_admitted_counts_report_once_per_profile_and_limit() {
    let waiting = json!({
        "id": "w", "profile": "long", "campaign": "c", "run": 2, "state": "waiting",
        "attempts": [{"number": 1, "attempt": "w-0001", "intent_ms": 1_000, "finished_ms": 6_000,
                      "finished": {"class": "inconclusive"},
                      "sim": {"cause": "inconclusive, stop limit turns"}}],
    });
    let shown = snapshot(json!({"jobs": [
        job("a", "long", 0, "inconclusive", Some("inconclusive, stop limit turns")),
        job("b", "long", 1, "inconclusive", Some("inconclusive, stop limit turns")),
        job("c", "recovery", 0, "inconclusive", Some("inconclusive, ledger Bound { cut: 1 }")),
        waiting,
    ]}));
    let signals = detect(&shown, &[]);
    let undersized = of(&signals, "undersized-counts");
    assert_eq!(undersized.len(), 1);
    assert_eq!(
        undersized[0].title,
        "long: inconclusive: limit turns in 3 job(s)"
    );
    assert_eq!(undersized[0].subjects, vec!["a", "b", "w"]);
    assert!(undersized[0].detail.contains("raise `turns` at admit"));
    let outcome = of(&signals, "outcome");
    assert_eq!(outcome.len(), 1);
    assert_eq!(outcome[0].domain, Domain::Simulator);
    assert_eq!(outcome[0].severity, Severity::Info);
}

#[test]
fn an_outcome_is_covered_only_by_a_finding_on_the_attempt_it_reads() {
    let retried = |id: &str, finding_on: u64| {
        let row = |number: u64, class: &str| {
            json!({"number": number, "attempt": format!("{id}-{number:04}"),
                   "intent_ms": 1_000, "finished_ms": 6_000, "finished": {"class": class},
                   "finding": (number == finding_on).then(|| format!("{id}-{finding_on:04}"))})
        };
        json!({"id": id, "profile": "get", "campaign": "c", "run": 0, "state": "settled",
               "result": {"attempt": 2, "class": "oom"},
               "attempts": [row(1, "watchdog"), row(2, "oom")]})
    };
    let mut stray = retried("stray", 2);
    stray["attempts"][1]["finding"] = json!("stray-0001");
    let shown = snapshot(json!({"jobs": [retried("early", 1), retried("late", 2), stray]}));
    let signals = detect(&shown, &[]);
    let outcome = of(&signals, "outcome");
    assert_eq!(outcome.len(), 1);
    assert_eq!(outcome[0].title, "oom in 2 job(s)");
    assert_eq!(outcome[0].subjects, vec!["early", "stray"]);
}

#[test]
fn an_attempt_running_past_the_wall_limit_is_critical_and_one_at_the_limit_is_not() {
    let limit = 1_800_000 + STUCK_GRACE_MS;
    let running = |id: &str, intent_ms: u64| {
        json!({"id": id, "profile": "long", "campaign": "c", "run": 0, "state": "running",
               "attempts": [{"number": 1, "attempt": format!("{id}-0001"), "intent_ms": intent_ms}]})
    };
    let mut late = running("late", 10_000_000 - limit - 100_000);
    late["attempts"][0]["started_ms"] = json!(10_000_000 - limit);
    let mut drained = running("drained", 1_000);
    drained["attempts"][0]["finished_ms"] = json!(2_000);
    drained["attempts"]
        .as_array_mut()
        .unwrap()
        .push(json!({"held": "attempt record unreadable"}));
    let shown = snapshot(json!({
        "config": {"verified": {"config": {"wall": 1800}}},
        "jobs": [running("old", 10_000_000 - limit - 1), running("young", 10_000_000 - limit),
                 late, drained],
    }));
    let signals = detect(&shown, &[]);
    let stuck = of(&signals, "stuck-attempt");
    assert_eq!(stuck.len(), 1);
    assert_eq!(stuck[0].subjects, vec!["old-0001"]);
    assert!(
        stuck[0].detail.contains("wall limit is 1800 s"),
        "{}",
        stuck[0].detail
    );
}

#[test]
fn a_queue_with_nothing_running_warns_once_ten_minutes_pass_without_a_finish() {
    let queued = json!({"id": "q", "profile": "get", "campaign": "c", "run": 0, "state": "queued"});
    let mut finished = job("f", "get", 0, "pass", None);
    finished["attempts"][0]["finished_ms"] = json!(10_000_000 - IDLE_MS + 1);
    let recent = snapshot(json!({"jobs": [queued.clone(), finished.clone()]}));
    assert!(!detectors(&detect(&recent, &[])).contains(&"idle-queue"));
    finished["attempts"][0]["finished_ms"] = json!(10_000_000 - IDLE_MS);
    let idle = snapshot(json!({"jobs": [queued, finished]}));
    assert!(detectors(&detect(&idle, &[])).contains(&"idle-queue"));
}

#[test]
fn a_queue_with_no_controller_warns_at_once_and_a_running_controller_waits_the_idle_time() {
    let queued = json!({"id": "q", "profile": "get", "campaign": "c", "run": 0, "state": "queued"});
    let finished_at = |ms: u64| {
        let mut finished = job("f", "get", 0, "pass", None);
        finished["attempts"][0]["finished_ms"] = json!(ms);
        finished
    };
    let recent = finished_at(10_000_000 - IDLE_MS + 1);
    let expired = finished_at(10_000_000 - IDLE_MS);
    let live = json!({"id": "r", "profile": "get", "campaign": "c", "run": 0, "state": "running",
                      "attempts": [{"number": 1, "attempt": "r-0001", "intent_ms": 1_000,
                                    "started_ms": 2_000}]});
    let idle = |jobs: Value, lock: Option<Value>| {
        let mut fields = json!({"jobs": jobs});
        if let Some(lock) = lock {
            fields["lock"] = lock;
        }
        let shown = snapshot(fields);
        of(&detect(&shown, &[]), "idle-queue")
            .first()
            .map(|signal| (signal.title.clone(), signal.detail.clone()))
    };
    let none = json!({"holders": []});
    let report = json!({"holders": [{"command": "report", "mode": "shared", "pid": 7}]});
    let dispatch = json!({"holders": [{"command": "dispatch", "mode": "exclusive", "pid": 9}]});
    let unknowns = [
        json!({"unknown": "/proc/locks is absent"}),
        json!({"holders": [], "unknown": "/proc/locks is absent"}),
        json!({"holders": [{"mode": "new"}]}),
    ];
    let warned = "1 unsettled job(s) and no visible controller runs";
    let delayed = "1 job(s) wait and nothing runs";

    let (title, detail) = idle(json!([queued, recent]), Some(none.clone())).unwrap();
    assert_eq!(title, warned);
    assert!(detail.starts_with("No visible process holds"), "{detail}");
    let (title, detail) = idle(json!([queued, recent]), Some(report)).unwrap();
    assert_eq!(title, warned);
    assert!(detail.starts_with("Only report snapshots hold"), "{detail}");

    let shown = snapshot(json!({"jobs": [queued, live]}));
    assert_eq!(
        shown.jobs[1].state,
        JobState::Running,
        "the producer's running row"
    );
    let (title, _) = idle(json!([queued, live]), Some(none.clone())).unwrap();
    assert_eq!(
        title, "2 unsettled job(s) and no visible controller runs",
        "a known missing controller outranks a running row"
    );
    for lock in unknowns
        .iter()
        .cloned()
        .map(Some)
        .chain([Some(dispatch.clone()), None])
    {
        assert_eq!(
            idle(json!([queued, live, expired]), lock.clone()),
            None,
            "a running row past the idle time with {lock:?}"
        );
    }

    for lock in unknowns
        .iter()
        .cloned()
        .map(Some)
        .chain([Some(dispatch.clone()), None])
    {
        assert_eq!(
            idle(json!([queued, recent]), lock.clone()),
            None,
            "{lock:?}"
        );
        let (title, detail) = idle(json!([queued, expired]), lock.clone()).unwrap();
        assert_eq!(title, delayed, "{lock:?}");
        let advice = if lock.as_ref() == Some(&dispatch) {
            "a controller holds the state directory"
        } else {
            "check that a dispatch window is running"
        };
        assert!(detail.contains(advice), "{lock:?}: {detail}");
    }
    let settling = json!({"id": "s", "profile": "get", "campaign": "c", "run": 0, "state": "settling",
                          "pin": {"attempt": 1, "class": "pass", "exit": 0, "signal": null,
                                  "watchdog": false}});
    let (title, _) = idle(json!([settling, recent]), Some(none.clone())).unwrap();
    assert_eq!(title, warned, "a settling job waits for the controller");
    let (title, _) = idle(json!([settling, expired]), Some(dispatch)).unwrap();
    assert_eq!(title, delayed, "a settling job under an idle controller");
    let (title, _) = idle(json!([live]), Some(none.clone())).unwrap();
    assert_eq!(title, warned, "a running job whose controller is gone");
    assert_eq!(idle(json!([recent]), Some(none)), None, "no queued job");
}

#[test]
fn free_space_projects_a_fill_time_from_the_sample_an_hour_back() {
    let projected = |free: u64, history: &[Sample]| {
        let shown = snapshot(json!({"observed_ms": 7_200_000, "space": space_facts(free)}));
        detect(&shown, history)
            .into_iter()
            .find(|signal| signal.detector == "space")
    };
    let hour_ago = |free: u64| Sample {
        observed_ms: 3_600_000,
        free_bytes: Some(free),
        ..Sample::default()
    };
    let space_signal = projected(100 << 30, &[hour_ago(110 << 30)]).unwrap();
    assert_eq!(space_signal.title, "state filesystem fills in about 10h00m");
    let at_horizon = projected(24 << 30, &[hour_ago(25 << 30)]).unwrap();
    assert_eq!(at_horizon.title, "state filesystem fills in about 1d00h");
    let past_horizon = (24 << 30) + (1 << 20);
    assert!(projected(past_horizon, &[hour_ago(past_horizon + (1 << 30))]).is_none());
    let stepped = Sample {
        observed_ms: 7_300_000,
        ..hour_ago(25 << 30)
    };
    assert!(projected(24 << 30, &[hour_ago(25 << 30), stepped]).is_none());
}

#[test]
fn space_under_the_floor_or_no_free_inodes_is_critical() {
    let low = snapshot(json!({"space": space_facts(LOW_SPACE - 1)}));
    let signals = detect(&low, &[]);
    assert_eq!(signals[0].severity, Severity::Critical);
    assert_eq!(signals[0].detector, "space");
    assert!(
        signals[0].detail.contains("under 5.0 GiB"),
        "{}",
        signals[0].detail
    );
    let floor = snapshot(json!({"space": space_facts(LOW_SPACE)}));
    assert!(!detectors(&detect(&floor, &[])).contains(&"space"));
    let inodes = snapshot(json!({"space": {"free_bytes": 1u64 << 40, "free_inodes": 0}}));
    let signals = detect(&inodes, &[]);
    assert_eq!(signals[0].title, "no free inodes on the state filesystem");
    assert_eq!(signals[0].severity, Severity::Critical);
}

#[test]
fn a_snapshot_without_space_facts_raises_no_space_signal_and_names_the_gap() {
    let mut shown = snapshot(json!({}));
    shown.space = None;
    let signals = detect(&shown, &[]);
    assert!(!detectors(&signals).contains(&"space"));
    assert_eq!(of(&signals, "held-record")[0].subjects, vec!["space"]);
}

#[test]
fn healthy_verified_records_raise_no_held_record_or_triage_signal() {
    let shown = snapshot(json!({
        "config": {"verified": {"config": {"wall": 1800}}},
        "jobs": [job("ok", "get", 0, "pass", None)],
        "findings": [{"id": "ok-0001", "resolved": false,
                      "verified": {"kind": "violation",
                                   "admission": {"job": {"experiment": {"profile": "get"}}}},
                      "triage": {"latest": {"state": "complete", "status": "reproduced"},
                                 "stalled": false, "limit_hit": null}}],
    }));
    let signals = detect(&shown, &[]);
    assert!(!detectors(&signals).contains(&"held-record"));
    assert!(!detectors(&signals).contains(&"triage"));
}

#[test]
fn a_finding_kind_this_monitor_does_not_know_is_held_rather_than_a_failure_group() {
    let verified = |kind: Value| json!({"kind": kind, "admission": {"job": {"experiment": {"profile": "get"}}}});
    let mut unknown = group(Some("02aa"));
    unknown["kind"] = json!("reshaped");
    unknown["findings"] = json!(["a-0001"]);
    let mut truncated = group(Some("02bb"));
    truncated["kind"] = json!("truncated");
    truncated["findings"] = json!(["t-0001"]);
    let mut no_kind = verified(Value::Null);
    no_kind.as_object_mut().unwrap().remove("kind");
    let shown = snapshot(json!({
        "findings": [
            {"id": "a-0001", "verified": verified("reshaped".into())},
            {"id": "t-0001", "verified": verified("truncated".into())},
            {"id": "n-0001", "verified": no_kind},
        ],
        "failure_groups": [unknown, truncated],
    }));
    let signals = detect(&shown, &[]);
    let groups = of(&signals, "failure-group");
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].subjects, vec!["t-0001"]);
    assert_eq!(groups[0].domain, Domain::Campaign);
    let held = of(&signals, "held-record");
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].subjects, vec!["a-0001", "n-0001"]);
    assert!(
        held[0]
            .detail
            .contains("a-0001 (verified record lacks a known finding kind)"),
        "{}",
        held[0].detail
    );
}

#[test]
fn a_failure_group_without_a_known_kind_is_a_held_record_for_its_findings() {
    let shown = snapshot(json!({
        "findings": [{"id": "a-0001", "triage": null,
                      "verified": {"kind": "violation",
                                   "admission": {"job": {"experiment": {"profile": "get"}}}}}],
        "failure_groups": [
            {"identity": "02aa", "findings": ["a-0001"], "profiles": ["get"], "runs": [0],
             "unresolved": 1},
            {"kind": "reshaped", "identity": "02bb", "findings": ["a-0001"], "unresolved": 0},
        ],
    }));
    let signals = detect(&shown, &[]);
    assert!(
        !detectors(&signals).contains(&"failure-group"),
        "{signals:?}"
    );
    let held = of(&signals, "held-record");
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].subjects, vec!["a-0001"]);
    assert!(
        held[0]
            .detail
            .contains("a-0001 (failure group lacks a known kind)"),
        "{}",
        held[0].detail
    );
}

#[test]
fn verified_rows_missing_the_facts_detectors_read_are_held() {
    let mut zero = job("z", "get", 0, "pass", None);
    zero["attempts"][0]["number"] = json!(0);
    let shown = snapshot(json!({
        "config": {"verified": {"config": {}}},
        "jobs": [zero, {"id": "r", "profile": "get", "campaign": "c", "run": 0, "state": "running"},
                 {"id": "p", "profile": "get", "campaign": "c", "run": 0, "state": "settled",
                  "result": {"class": "pass"}}],
        "findings": [{"id": "v-0001", "verified": {}, "triage": null}],
    }));
    let signals = detect(&shown, &[]);
    let held = of(&signals, "held-record");
    assert_eq!(
        held[0].subjects,
        vec!["config.json", "jobs/z", "jobs/r", "jobs/p", "v-0001"]
    );
    assert!(
        held[0]
            .detail
            .contains("v-0001 (verified record lacks its profile)")
    );
}

#[test]
fn a_running_row_whose_attempt_finished_leaves_the_idle_queue_warning() {
    let queued = json!({"id": "q", "profile": "get", "campaign": "c", "run": 0, "state": "queued"});
    let mut stale = job("s", "get", 0, "pass", None);
    stale["state"] = json!("running");
    stale["result"] = Value::Null;
    let shown = snapshot(json!({"jobs": [queued, stale]}));
    assert!(detectors(&detect(&shown, &[])).contains(&"idle-queue"));
}

#[test]
fn a_recorder_cap_stop_advises_raising_records_bytes_and_turns() {
    let shown = snapshot(json!({"jobs": [
        job("a", "long", 0, "inconclusive", Some("infrastructure cap, stop unavailable")),
    ]}));
    let signals = detect(&shown, &[]);
    let undersized = of(&signals, "undersized-counts");
    assert_eq!(
        undersized[0].title,
        "long: inconclusive: recorder cap in 1 job(s)"
    );
    assert!(
        undersized[0]
            .detail
            .contains("raise `records` and `bytes` together with `turns` at admit")
    );
}

#[test]
fn simulator_faults_and_campaign_outcomes_are_critical() {
    let shown = snapshot(json!({"jobs": [
        job("e", "get", 0, "engine-failure", None),
        job("r", "get", 1, "rejected", None),
    ]}));
    let signals = detect(&shown, &[]);
    let outcome = of(&signals, "outcome");
    assert_eq!(outcome.len(), 2);
    assert!(
        outcome
            .iter()
            .all(|signal| signal.severity == Severity::Critical)
    );
}

#[test]
fn the_new_marker_waits_while_a_history_sample_is_newer_than_the_snapshot() {
    let shown = snapshot(json!({"failure_groups": [group(Some("02aa"))]}));
    let earlier = Sample {
        observed_ms: 1,
        ..Sample::default()
    };
    let future = Sample {
        observed_ms: 20_000_000,
        ..Sample::default()
    };
    assert!(
        !detect(&shown, &[earlier, future])[0]
            .title
            .starts_with("NEW")
    );
}

#[test]
fn held_rows_of_every_kind_raise_one_critical_campaign_signal() {
    let mut misbound = job("m", "get", 0, "pass", None);
    misbound["attempts"][0]["sim"] = json!({"held": "artifact differs from the bound digest"});
    let mut bad = job("bad", "get", 2, "violation", None);
    bad["held"] = json!("job binding differs");
    let shown = snapshot(json!({
        "jobs": [bad, misbound, job("ok", "get", 1, "pass", None)],
        "findings": [{"id": "x-0001", "held": "authoritative outcome awaits capture"}],
    }));
    let signals = detect(&shown, &[]);
    let held = of(&signals, "held-record");
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].severity, Severity::Critical);
    assert_eq!(held[0].subjects, vec!["jobs/bad", "jobs/m", "x-0001"]);
    assert!(
        held[0]
            .detail
            .contains("x-0001 (authoritative outcome awaits capture)")
    );
    assert!(!detectors(&signals).contains(&"seed-sensitive"));
    assert!(
        !signals
            .iter()
            .any(|signal| signal.detector == "outcome" && signal.title.contains("held"))
    );
}

#[test]
fn held_attempt_histories_pins_and_probe_entries_are_held_records() {
    let held = json!({"held": "attempt history has gaps or duplicates", "held_code": "binding"});
    let verified_pin = json!({"attempt": 1, "class": "pass", "exit": 0, "signal": null,
                              "watchdog": false});
    let mut gapped = job("g", "get", 0, "pass", None);
    gapped["attempts_held"] = held.clone();
    let mut pinned = job("p", "get", 1, "pass", None);
    pinned["pin"] = held.clone();
    let unlisted = json!({"id": "u", "profile": "get", "campaign": "c", "run": 0, "state": "settling",
                          "pin": verified_pin, "attempts": [], "attempts_held": held});
    let mut ok = job("ok", "get", 2, "pass", None);
    ok["pin"] = verified_pin;
    ok["attempts_held"] = Value::Null;
    let shown = snapshot(json!({
        "jobs": [gapped, pinned, unlisted, ok],
        "held_probes": [{"entry": "stray", "held": "not a directory", "held_code": "binding"}],
    }));
    let signals = detect(&shown, &[]);
    let held = of(&signals, "held-record");
    assert_eq!(
        held[0].subjects,
        vec!["probes/stray", "jobs/g", "jobs/p", "jobs/u"]
    );
}

#[test]
fn records_outside_the_producer_shapes_are_held() {
    let mut unnumbered = job("n", "get", 0, "pass", None);
    unnumbered["attempts"][0]["number"] = Value::Null;
    let shown = snapshot(json!({
        "config": {},
        "jobs": [{"id": "u", "profile": "get", "campaign": "c", "run": 0, "state": "reshaped"},
                 {"id": "s", "profile": "get", "campaign": "c", "run": 0, "state": "settled"}, unnumbered],
        "findings": [{"id": "y-0001"}],
    }));
    let signals = detect(&shown, &[]);
    let held = of(&signals, "held-record");
    assert_eq!(
        held[0].subjects,
        vec!["config.json", "jobs/u", "jobs/s", "jobs/n", "y-0001"]
    );
    assert!(
        held[0]
            .detail
            .contains("y-0001 (neither verified nor held)")
    );
}

#[test]
fn a_resolved_finding_with_a_held_triage_record_still_raises_the_held_triage_signal() {
    let verified =
        json!({"kind": "violation", "admission": {"job": {"experiment": {"profile": "get"}}}});
    let shown = snapshot(json!({"findings": [
        {"id": "a-0001", "resolved": true, "verified": verified,
         "triage": {"held": "triage record unreadable", "held_code": "binding"}},
        {"id": "b-0001", "resolved": true, "verified": verified},
        {"id": "c-0001", "resolved": true, "verified": verified,
         "triage": {"latest": {"state": "complete", "status": "reproduced"}, "stalled": true,
                    "limit_hit": null}},
    ]}));
    let signals = detect(&shown, &[]);
    let triage = of(&signals, "triage");
    assert_eq!(triage.len(), 2, "{triage:?}");
    assert!(
        triage
            .iter()
            .all(|signal| signal.title == "triage history held for get")
    );
    let subjects: Vec<&str> = triage
        .iter()
        .map(|signal| signal.subjects[0].as_str())
        .collect();
    assert_eq!(subjects, ["a-0001", "b-0001"]);
}

#[test]
fn a_replay_that_diverges_is_a_critical_simulator_signal() {
    let finding = |triage: Value| {
        json!({"id": "a-0001", "triage": triage,
               "verified": {"kind": "violation",
                            "admission": {"job": {"experiment": {"profile": "get"}}}}})
    };
    let shown = snapshot(json!({"findings": [finding(json!(
        {"latest": {"state": "complete", "status": "diverged"}, "stalled": false, "limit_hit": null}
    ))]}));
    let signals = detect(&shown, &[]);
    assert_eq!(signals[0].detector, "triage");
    assert_eq!(signals[0].domain, Domain::Simulator);
    assert_eq!(signals[0].severity, Severity::Critical);

    let shown = snapshot(json!({"findings": [finding(json!(
        {"latest": {"state": "complete", "status": null}, "stalled": false, "limit_hit": 7}
    ))]}));
    let signals = detect(&shown, &[]);
    assert_eq!(signals[0].title, "triage history held for get");
    assert_eq!(signals[0].severity, Severity::Critical);

    let shown = snapshot(json!({"findings": [finding(json!(
        {"latest": {"state": "complete"}, "stalled": false, "limit_hit": null}
    ))]}));
    assert_eq!(detect(&shown, &[])[0].title, "triage history held for get");

    let shown = snapshot(json!({"findings": [finding(json!(
        {"latest": {"state": "interrupted", "status": null}, "stalled": false, "limit_hit": "oom"}
    ))]}));
    let signals = detect(&shown, &[]);
    assert_eq!(signals[0].title, "triage of get hit oom");
    assert_eq!(signals[0].severity, Severity::Warning);
    assert_eq!(signals[0].domain, Domain::Host);
}

#[test]
fn a_triage_label_outside_the_known_sets_is_unattributed() {
    let finding = |latest: Value, limit_hit: Value| {
        json!({"id": "a-0001",
               "verified": {"kind": "violation",
                            "admission": {"job": {"experiment": {"profile": "get"}}}},
               "triage": {"latest": latest, "stalled": false, "limit_hit": limit_hit}})
    };
    let shown = snapshot(json!({"findings": [
        finding(json!({"state": "complete", "status": "reclassified"}), Value::Null),
    ]}));
    assert_eq!(shown.findings[0].triage_state(), "unknown");
    assert!(!detectors(&detect(&shown, &[])).contains(&"triage"));

    let shown = snapshot(json!({"findings": [
        finding(json!({"state": "resumed", "status": null}), json!("oom")),
    ]}));
    assert_eq!(shown.findings[0].triage_state(), "unknown");
    let signals = detect(&shown, &[]);
    let triage = of(&signals, "triage");
    assert_eq!(triage.len(), 1);
    assert_eq!(triage[0].title, "triage of get hit oom");
    assert_eq!(triage[0].severity, Severity::Warning);

    let shown = snapshot(json!({"findings": [
        finding(json!({"state": "complete", "status": "reproduced"}), json!("gpu-limit")),
    ]}));
    assert!(!detectors(&detect(&shown, &[])).contains(&"triage"));
}

#[test]
fn an_unknown_class_on_an_earlier_attempt_holds_the_job() {
    let mut retried = job("r", "get", 0, "pass", None);
    retried["result"]["attempt"] = json!(2);
    retried["attempts"] = json!([
        {"number": 1, "attempt": "r-0001", "intent_ms": 1, "finished_ms": 2,
         "finished": {"class": "reshaped"}},
        {"number": 2, "attempt": "r-0002", "intent_ms": 3, "finished_ms": 4,
         "finished": {"class": "pass"}},
    ]);
    let shown = snapshot(json!({"jobs": [retried, job("ok", "get", 1, "pass", None)]}));
    let signals = detect(&shown, &[]);
    let held = of(&signals, "held-record");
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].subjects, vec!["jobs/r"]);
}

#[test]
fn a_held_running_row_raises_no_stuck_attempt() {
    let finished = json!({"id": "f", "profile": "long", "campaign": "c", "run": 0, "state": "running",
                          "attempts": [{"number": 1, "attempt": "f-0001", "intent_ms": 1_000,
                                        "finished_ms": 2_000, "finished": {"class": "pass"}}]});
    let shown = snapshot(json!({
        "config": {"verified": {"config": {"wall": 1800}}},
        "jobs": [finished],
    }));
    let signals = detect(&shown, &[]);
    assert!(
        !detectors(&signals).contains(&"stuck-attempt"),
        "{signals:?}"
    );
    assert_eq!(of(&signals, "held-record")[0].subjects, vec!["jobs/f"]);
}

#[test]
fn a_running_job_with_a_held_attempt_history_raises_no_stuck_attempt() {
    let gapped = json!({"id": "g", "profile": "long", "campaign": "c", "run": 0, "state": "running",
                        "attempts": [{"number": 1, "attempt": "g-0001", "intent_ms": 1_000}],
                        "attempts_held": {"held": "attempt history has gaps or duplicates"}});
    let shown = snapshot(json!({
        "config": {"verified": {"config": {"wall": 1800}}},
        "jobs": [gapped],
    }));
    let signals = detect(&shown, &[]);
    assert!(
        !detectors(&signals).contains(&"stuck-attempt"),
        "{signals:?}"
    );
    assert_eq!(of(&signals, "held-record")[0].subjects, vec!["jobs/g"]);
}

#[test]
fn a_zero_wall_limit_raises_no_stuck_attempt() {
    let running = json!({"id": "old", "profile": "long", "campaign": "c", "run": 0, "state": "running",
                         "attempts": [{"number": 1, "attempt": "old-0001", "intent_ms": 1_000}]});
    let shown = snapshot(json!({
        "config": {"verified": {"config": {"wall": 0}}},
        "jobs": [running],
    }));
    let signals = detect(&shown, &[]);
    assert!(
        !detectors(&signals).contains(&"stuck-attempt"),
        "{signals:?}"
    );
    assert_eq!(of(&signals, "held-record")[0].subjects, vec!["config.json"]);
}

#[test]
fn an_attempt_row_without_its_identity_is_a_held_record() {
    let mut unnamed = job("u", "get", 0, "pass", None);
    unnamed["attempts"][0]
        .as_object_mut()
        .unwrap()
        .remove("attempt");
    let shown = snapshot(json!({"jobs": [unnamed, job("ok", "get", 1, "pass", None)]}));
    let signals = detect(&shown, &[]);
    let held = of(&signals, "held-record");
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].subjects, vec!["jobs/u"]);
}

#[test]
fn a_verified_job_without_its_run_is_held_and_leaves_the_matrix() {
    let mut unnumbered = job("n", "get", 0, "pass", None);
    unnumbered.as_object_mut().unwrap().remove("run");
    let shown = snapshot(json!({"jobs": [unnumbered, job("ok", "get", 1, "pass", None)]}));
    assert_eq!(Outcome::of_job(&shown.jobs[0]).label, "held");
    let signals = detect(&shown, &[]);
    assert_eq!(of(&signals, "held-record")[0].subjects, vec!["jobs/n"]);
    let built = crate::model::matrix(&shown);
    assert_eq!(built.runs, vec![1]);
}

#[test]
fn a_verified_job_without_its_profile_is_held() {
    let mut blank = job("b", "get", 0, "pass", None);
    blank.as_object_mut().unwrap().remove("profile");
    let shown = snapshot(json!({"jobs": [blank, job("ok", "get", 1, "pass", None)]}));
    assert_eq!(Outcome::of_job(&shown.jobs[0]).label, "held");
    let signals = detect(&shown, &[]);
    let held = of(&signals, "held-record");
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].subjects, vec!["jobs/b"]);
}

#[test]
fn attempts_throttled_past_a_quarter_of_their_usage_raise_one_host_info() {
    let throttle = |id: &str, profile: &str, usage: u64, throttled: u64| {
        let mut row = job(id, profile, 0, "pass", None);
        row["attempts"][0]["finished"]["kernel"] =
            json!({"cpu_usage_usec": usage, "cpu_throttled_usec": throttled});
        row
    };
    let shown = snapshot(json!({"jobs": [
        throttle("t", "busy", 1_000, 251),
        throttle("x", "busy", 1_000, u64::MAX),
        throttle("m", "busy", u64::MAX, 1 << 62),
        throttle("q", "calm", 1_000, 250),
        throttle("n", "calm", u64::MAX, (1 << 62) - 1),
    ]}));
    let signals = detect(&shown, &[]);
    let signals = of(&signals, "throttling");
    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].domain, Domain::Host);
    assert!(
        signals[0].title.starts_with("3 attempt(s)"),
        "{}",
        signals[0].title
    );
    assert!(signals[0].detail.ends_with("profiles busy"));
    let calm = snapshot(json!({"jobs": [job("c", "calm", 0, "pass", None)]}));
    assert!(!detectors(&detect(&calm, &[])).contains(&"throttling"));
}

#[test]
fn a_thousand_retained_probes_raise_an_info_and_fewer_do_not() {
    let many = snapshot(json!({"probes": 1000}));
    assert!(detectors(&detect(&many, &[])).contains(&"probes"));
    let few = snapshot(json!({"probes": 999}));
    assert!(!detectors(&detect(&few, &[])).contains(&"probes"));
}

#[test]
fn a_projection_past_u64_or_against_a_future_sample_raises_no_warning() {
    let shown = snapshot(json!({"observed_ms": 1u64 << 24, "space": space_facts(1 << 40)}));
    let past = Sample {
        observed_ms: 0,
        free_bytes: Some((1 << 40) + 1),
        ..Sample::default()
    };
    assert!(!detectors(&detect(&shown, std::slice::from_ref(&past))).contains(&"space"));
    let future = Sample {
        observed_ms: u64::MAX,
        free_bytes: Some(u64::MAX),
        ..Sample::default()
    };
    assert!(!detectors(&detect(&shown, &[past, future])).contains(&"space"));
}

#[test]
fn signal_keys_ignore_subject_order_and_change_with_the_subjects_and_detector() {
    let signal = |detector: &'static str, subjects: &[&str]| Signal {
        severity: Severity::Info,
        domain: Domain::Host,
        detector,
        title: String::new(),
        detail: String::new(),
        subjects: subjects
            .iter()
            .map(|subject| (*subject).to_owned())
            .collect(),
    };
    let keyed = |subjects: &[&str]| signal("space", subjects);
    assert_eq!(keyed(&["a", "b"]).key(), keyed(&["b", "a"]).key());
    assert_ne!(keyed(&["a", "b"]).key(), keyed(&["a", "c"]).key());
    assert_eq!(keyed(&[]).key(), "space:cbf29ce484222325");
    assert_ne!(keyed(&["a\nb"]).key(), keyed(&["a", "b"]).key());
    assert_ne!(keyed(&[]).key(), keyed(&[""]).key());
    assert_eq!(signal("probes", &[]).key(), "probes:cbf29ce484222325");
}

#[test]
fn lists_name_six_items_then_print_the_total() {
    assert_eq!(list(Vec::<u64>::new()), "");
    assert_eq!(list(1..=6), "1, 2, 3, 4, 5, 6");
    assert_eq!(list(1..=7), "1, 2, 3, 4, 5, 6, ... (7 total)");
}

#[test]
fn durations_and_sizes_print_in_the_largest_whole_unit() {
    assert_eq!(duration(5_150), "5.1s");
    assert_eq!(duration(125_000), "2m05s");
    assert_eq!(duration(3_660_000), "1h01m");
    assert_eq!(duration(90_000_000), "1d01h");
    assert_eq!(bytes(512), "512 B");
    assert_eq!(bytes(119 << 20), "119.0 MiB");
}
