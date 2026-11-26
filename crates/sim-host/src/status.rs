//! `sim-host status`: the local health record with its shares, its age and
//! a verdict. Exit 2 is critical, 1 a warning and 0 healthy.

use std::path::Path;

use serde_json::{Map, Value, json};

use crate::health::{Health, Phase};

pub const SHARE_FLOOR: f64 = 0.9;

#[derive(Debug, PartialEq)]
pub struct Verdict {
    pub code: u8,
    pub report: Value,
}

pub fn status(state: &Path, now: u64) -> Verdict {
    let health = match crate::file::read(&crate::health::path(state), crate::health::BOUND) {
        Ok(Some(bytes)) => crate::health::parse(&bytes),
        Ok(None) => Err("no health record".to_owned()),
        Err(error) => Err(error.to_string()),
    };
    match health {
        Ok(health) => judge(&health, now),
        Err(error) => Verdict {
            code: 2,
            report: json!({"error": error, "verdict": "unknown"}),
        },
    }
}

pub fn share(cpu: Option<u64>, capacity: Option<u64>) -> Option<f64> {
    match (cpu, capacity) {
        (Some(cpu), Some(capacity)) if capacity > 0 => Some(cpu as f64 / capacity as f64),
        _ => None,
    }
}

/// A record written after `now` is of age 0.
pub fn stale(written: u64, stint_seconds: u64, now: u64) -> bool {
    now.saturating_sub(written) > stint_seconds.saturating_mul(2)
}

pub fn judge(health: &Health, now: u64) -> Verdict {
    let fields = match serde_json::to_value(health) {
        Ok(Value::Object(fields)) => fields,
        _ => Map::new(),
    };
    let mut report: Map<String, Value> = fields
        .into_iter()
        .map(|(key, value)| {
            let value = if value.is_null() && !key.ends_with("_error") {
                Value::from("unknown")
            } else {
                value
            };
            (key, value)
        })
        .collect();
    let stint_share = share(health.stint_cpu_usec, health.stint_capacity_usec);
    let root_share = share(health.cpu_usec, health.capacity_usec);
    report.insert(
        "share".into(),
        stint_share.map_or("unknown".into(), Value::from),
    );
    report.insert(
        "root_share".into(),
        root_share.map_or("unknown".into(), Value::from),
    );
    let stale = match (health.written, health.stint_seconds) {
        (Some(written), Some(stint))
            if written <= now && (1..=crate::assignment::SECONDS_MAX).contains(&stint) =>
        {
            Some(stale(written, stint, now))
        }
        _ => None,
    };
    report.insert("stale".into(), stale.map_or("unknown".into(), Value::from));
    let mut critical = Vec::new();
    let mut warning = Vec::new();
    if health.format != Some(1) {
        critical.push("format unknown".to_owned());
    }
    match (health.alarm, health.root.is_some()) {
        (Some(true), _) => critical.push("alarm".to_owned()),
        (None, true) => critical.push("alarm unknown".to_owned()),
        _ => {}
    }
    if health.held_roots.is_some_and(|held| held > 0) {
        critical.push("earlier root held".to_owned());
    }
    match health
        .phase
        .as_deref()
        .map(|name| (name, Phase::parse(name)))
    {
        Some((_, Some(phase))) if !phase.critical() => {}
        Some((name, _)) => critical.push(format!("phase {name}")),
        None => critical.push("phase unknown".to_owned()),
    }
    match stale {
        Some(true) => critical.push("stale".to_owned()),
        None => critical.push("stale unknown".to_owned()),
        Some(false) => {}
    }
    if health.sweep_overdue == Some(true) {
        critical.push("sweep overdue".to_owned());
    }
    match health.confirmation.as_deref() {
        None if health.root.is_some() => critical.push("confirmation unknown".to_owned()),
        None | Some("idle" | "running") => {}
        Some("held") => critical.push("confirmation held".to_owned()),
        Some(name @ ("backlog" | "failed")) => warning.push(format!("confirmation {name}")),
        Some(name) => critical.push(format!("confirmation {name}")),
    }
    if let Some(share) = stint_share
        && share < SHARE_FLOOR
    {
        warning.push(format!("share {share:.4} below {SHARE_FLOOR}"));
    }
    for (name, error) in [
        ("assignment", &health.assignment_error),
        ("upload", &health.upload_error),
        ("fetch", &health.fetch_error),
        ("cleanup", &health.cleanup_error),
    ] {
        if error.is_some() {
            warning.push(format!("{name} error"));
        }
    }
    let (code, verdict) = if !critical.is_empty() {
        (2, "critical")
    } else if !warning.is_empty() {
        (1, "warning")
    } else {
        (0, "ok")
    };
    report.insert("verdict".into(), verdict.into());
    report.insert(
        "reasons".into(),
        critical
            .into_iter()
            .chain(warning)
            .collect::<Vec<_>>()
            .into(),
    );
    Verdict {
        code,
        report: Value::Object(report),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> Health {
        Health {
            format: Some(1),
            written: Some(1_000),
            stint_seconds: Some(100),
            phase: Some("sweeping".into()),
            alarm: Some(false),
            confirmation: Some("idle".into()),
            stint_cpu_usec: Some(95),
            stint_capacity_usec: Some(100),
            ..Health::default()
        }
    }

    #[test]
    fn each_confirmation_state_sets_its_exit_code() {
        use crate::state::Confirmation;
        for (confirmation, code) in [
            (Confirmation::Idle, 0),
            (Confirmation::Backlog(String::new()), 1),
            (Confirmation::Failed(String::new()), 1),
            (Confirmation::Held(String::new()), 2),
        ] {
            let mut health = healthy();
            health.confirmation = Some(confirmation.name().to_owned());
            assert_eq!(judge(&health, 1_100).code, code, "{confirmation:?}");
        }
    }

    #[test]
    fn a_named_root_needs_its_alarm_and_confirmation() {
        let mut health = healthy();
        health.root = Some("sim.i-0123abcd.00".into());
        assert_eq!(judge(&health, 1_100).code, 0);
        for change in [
            (|health: &mut Health| health.alarm = None) as fn(&mut Health),
            |health| health.confirmation = None,
        ] {
            let mut named = health.clone();
            change(&mut named);
            assert_eq!(judge(&named, 1_100).code, 2, "{named:?}");
        }
        let mut rootless = healthy();
        rootless.alarm = None;
        rootless.confirmation = None;
        assert_eq!(judge(&rootless, 1_100).code, 0);
    }

    #[test]
    fn each_condition_sets_its_exit_code() {
        assert_eq!(judge(&healthy(), 1_100).code, 0);
        type Change = fn(&mut Health);
        let cases: [(Change, u8); 24] = [
            (|health| health.held_roots = Some(1), 2),
            (|health| health.alarm = Some(true), 2),
            (|health| health.sweep_overdue = Some(true), 2),
            (|health| health.sweep_overdue = Some(false), 0),
            (|health| health.phase = Some("waiting".into()), 2),
            (|health| health.phase = Some("held".into()), 2),
            (|health| health.phase = Some("full".into()), 2),
            (|health| health.phase = Some("blocked".into()), 2),
            (|health| health.phase = Some("stopped".into()), 2),
            (|health| health.phase = Some("swept".into()), 2),
            (|health| health.phase = None, 2),
            (|health| health.format = Some(2), 2),
            (|health| health.written = Some(700), 2),
            (|health| health.written = Some(2_000), 2),
            (|health| health.confirmation = Some("held".into()), 2),
            (|health| health.confirmation = Some("other".into()), 2),
            (|health| health.confirmation = Some("backlog".into()), 1),
            (|health| health.confirmation = Some("failed".into()), 1),
            (|health| health.stint_cpu_usec = Some(89), 1),
            (|health| health.stint_cpu_usec = Some(90), 0),
            (|health| health.upload_error = Some("put failed".into()), 1),
            (|health| health.fetch_error = Some("get failed".into()), 1),
            (|health| health.cleanup_error = Some("busy".into()), 1),
            (
                |health| health.assignment_error = Some("current.json".into()),
                1,
            ),
        ];
        for (change, code) in cases {
            let mut health = healthy();
            change(&mut health);
            assert_eq!(judge(&health, 1_100).code, code, "{health:?}");
        }
        let mut health = healthy();
        health.phase = Some("starting".into());
        health.confirmation = Some("running".into());
        assert_eq!(judge(&health, 1_100).code, 0);
    }

    #[test]
    fn a_record_is_stale_past_two_stint_lengths() {
        for (now, stale) in [
            (1_000, false),
            (1_150, false),
            (1_200, false),
            (1_201, true),
        ] {
            let verdict = judge(&healthy(), now);
            assert_eq!(verdict.report["stale"], stale, "at {now}");
            assert_eq!(verdict.code, if stale { 2 } else { 0 }, "at {now}");
            let reasons = if stale { json!(["stale"]) } else { json!([]) };
            assert_eq!(verdict.report["reasons"], reasons, "at {now}");
        }
        let verdict = judge(&healthy(), 999);
        assert_eq!(
            verdict.report["stale"], "unknown",
            "a record from the future"
        );
        assert_eq!(verdict.code, 2);
        assert_eq!(verdict.report["reasons"], json!(["stale unknown"]));
        for change in [
            (|health: &mut Health| health.written = None) as fn(&mut Health),
            |health| health.stint_seconds = None,
            |health| health.stint_seconds = Some(0),
            |health| health.stint_seconds = Some(crate::assignment::SECONDS_MAX + 1),
            |health| health.stint_seconds = Some(u64::MAX),
        ] {
            let mut health = healthy();
            change(&mut health);
            let verdict = judge(&health, 1_100);
            assert_eq!(verdict.report["stale"], "unknown");
            assert_eq!(verdict.code, 2);
            assert_eq!(verdict.report["reasons"], json!(["stale unknown"]));
        }
    }

    /// The local reader refuses the positional array of a healthy record,
    /// as the report does.
    #[test]
    fn a_record_that_is_no_json_object_reads_unknown() {
        let dir = crate::file::scratch("status-array");
        std::fs::write(
            crate::health::path(&dir),
            crate::health::positional(&healthy()),
        )
        .expect("an array record");
        let verdict = status(&dir, 1_000);
        assert_eq!(verdict.code, 2);
        assert_eq!(verdict.report["verdict"], "unknown");
        assert_eq!(verdict.report["error"], "is not a JSON object");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_missing_field_prints_unknown() {
        let mut health = healthy();
        health.build = None;
        health.stint_capacity_usec = None;
        let verdict = judge(&health, 1_100);
        assert_eq!(verdict.report["build"], "unknown");
        assert_eq!(verdict.report["share"], "unknown");
        assert_eq!(verdict.code, 0);
    }
}
