//! `check`: one fetch, its signals as text or one JSON object, and an exit
//! code for the worst signal. Text from the snapshot or a remote host is
//! printed with its control characters escaped.

use std::io::Write;

use serde_json::{Value, json};

use crate::cli::{EXIT_CRITICAL, EXIT_HISTORY, EXIT_SNAPSHOT, EXIT_WARNING, Mode, Options};
use crate::history::{History, Sample};
use crate::model::totals;
use crate::signals::{Severity, Signal, detect};
use crate::snapshot::Snapshot;

/// Version of both `check --json` objects, [`json_report`] and
/// [`json_failure`].
pub const REPORT_FORMAT: u64 = 1;

/// Writes `text`, ignoring a write error such as a pipe whose reader exited,
/// so the exit code still reports the signals.
fn emit(out: &mut dyn Write, text: &str) {
    let _ = out.write_all(text.as_bytes());
}

/// Reports `error` on `err`, and for `check --json` also as the
/// [`json_failure`] object on `out`.
pub fn fail(mode: Mode, error: &str, out: &mut dyn Write, err: &mut dyn Write) {
    if mode == (Mode::Check { json: true }) {
        emit(out, &format!("{}\n", json_failure(error)));
    }
    emit(err, &format!("campaign-monitor: {}\n", printable(error)));
}

/// Opens the history `options` names, in memory when it names none.
///
/// # Errors
///
/// [`EXIT_HISTORY`], after reporting the failure through [`fail`], when the
/// history file does not open.
pub fn open_history(
    options: &Options,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<History, u8> {
    match &options.history {
        Some(path) => History::open(path).map_err(|error| {
            fail(
                options.mode,
                &format!("history unusable: {error}"),
                out,
                err,
            );
            EXIT_HISTORY
        }),
        None => Ok(History::in_memory()),
    }
}

/// Runs `check` once: fetches a snapshot, records its sample in `history`,
/// detects against the samples `history` then holds, prints the report to
/// `out`, and returns the exit code. A failed
/// fetch prints the failure through [`fail`] and returns [`EXIT_SNAPSHOT`];
/// a failed record prints the full report and returns [`EXIT_HISTORY`]
/// instead of the signals' code.
pub fn check(
    options: &Options,
    mut history: History,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let snapshot = match options.source.fetch(options.limits) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            fail(options.mode, &format!("snapshot failed: {error}"), out, err);
            return EXIT_SNAPSHOT;
        }
    };
    let recorded = history.record(Sample::of(&snapshot));
    let signals = detect(&snapshot, history.samples());
    if options.mode == (Mode::Check { json: true }) {
        emit(out, &format!("{}\n", json_report(&snapshot, &signals)));
    } else {
        emit(out, &text_report(&signals));
    }
    match recorded {
        Ok(()) => exit_code(&signals),
        Err(error) => {
            emit(
                err,
                &format!(
                    "campaign-monitor: history not recorded: {}\n",
                    printable(&error)
                ),
            );
            EXIT_HISTORY
        }
    }
}

fn worst(signals: &[Signal]) -> Option<Severity> {
    signals.iter().map(|signal| signal.severity).min()
}

pub fn exit_code(signals: &[Signal]) -> u8 {
    match worst(signals) {
        Some(Severity::Critical) => EXIT_CRITICAL,
        Some(Severity::Warning) => EXIT_WARNING,
        _ => 0,
    }
}

/// `text` with every control character escaped, so that strings from a
/// remote host or a saved snapshot print without driving the terminal.
pub fn printable(text: &str) -> String {
    let mut shown = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            shown.extend(c.escape_default());
        } else {
            shown.push(c);
        }
    }
    shown
}

pub fn text_report(signals: &[Signal]) -> String {
    signals
        .iter()
        .map(|signal| {
            format!(
                "{:<9} {:<10} {}\n                     {}\n",
                signal.severity.name(),
                signal.domain.name(),
                printable(&signal.title),
                printable(&signal.detail)
            )
        })
        .collect()
}

/// The `check --json` object for a fetched snapshot. Keys: `format`
/// ([`REPORT_FORMAT`]); `observed_ms` and `state` from the snapshot;
/// `worst`, the highest severity name or null without signals; `totals`,
/// with the job count `jobs`, job counts `by_state`, settled counts
/// `by_domain` (`pass` for no domain) and `by_outcome`, finished
/// `attempts`, `finished_last_hour`, `findings`, `release_blockers` and
/// nullable `free_bytes`; and `signals`, each with `key` (stable while its
/// detector and sorted subjects stay the same), `severity`, `domain`,
/// `detector`, `title`, `detail` and `subjects`. [`check`] prints it with
/// exit 0, [`EXIT_WARNING`] or [`EXIT_CRITICAL`], or with [`EXIT_HISTORY`]
/// when recording the sample failed after the fetch.
pub fn json_report(snapshot: &Snapshot, signals: &[Signal]) -> Value {
    let counted = totals(snapshot);
    json!({
        "format": REPORT_FORMAT,
        "observed_ms": snapshot.observed_ms,
        "state": snapshot.state,
        "worst": worst(signals).map(Severity::name),
        "totals": {
            "jobs": snapshot.jobs.len(),
            "by_state": counted.by_state.iter().map(|(state, n)| (state.name().to_owned(), json!(n))).collect::<serde_json::Map<_, _>>(),
            "by_domain": counted.by_domain.iter().map(|(domain, n)| (domain.map_or("pass", |d| d.name()).to_owned(), json!(n))).collect::<serde_json::Map<_, _>>(),
            "by_outcome": counted.by_label,
            "attempts": counted.attempts,
            "finished_last_hour": counted.finished_last_hour,
            "findings": snapshot.findings.len(),
            "release_blockers": snapshot.release_blockers.len(),
            "free_bytes": snapshot.space.map(|space| space.free_bytes),
        },
        "signals": signals.iter().map(|signal| json!({
            "key": signal.key(),
            "severity": signal.severity.name(),
            "domain": signal.domain.name(),
            "detector": signal.detector,
            "title": signal.title,
            "detail": signal.detail,
            "subjects": signal.subjects,
        })).collect::<Vec<_>>(),
    })
}

/// The `check --json` object when no report exists: `format`, the `error`
/// text, a null `worst` and no `signals`. [`check`] prints it with exit
/// [`EXIT_SNAPSHOT`] when the fetch fails, and [`open_history`] with
/// [`EXIT_HISTORY`] when the history file does not open.
pub fn json_failure(error: &str) -> Value {
    json!({"format": REPORT_FORMAT, "error": error, "worst": null, "signals": []})
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cli::parse;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    fn signal(severity: Severity, subjects: &[&str]) -> Signal {
        Signal {
            severity,
            domain: crate::outcome::Domain::Service,
            detector: "test",
            title: "title".into(),
            detail: "detail".into(),
            subjects: subjects
                .iter()
                .map(|subject| (*subject).to_owned())
                .collect(),
        }
    }

    #[test]
    fn the_exit_code_follows_the_worst_signal() {
        use Severity::{Critical, Info, Warning};
        for (severities, expected) in [
            (vec![], 0),
            (vec![Info], 0),
            (vec![Info, Warning], 1),
            (vec![Info, Warning, Critical], 2),
            (vec![Critical, Info], 2),
        ] {
            let signals: Vec<Signal> = severities.iter().map(|s| signal(*s, &[])).collect();
            assert_eq!(exit_code(&signals), expected, "{severities:?}");
        }
    }

    #[test]
    fn the_text_report_escapes_control_characters() {
        let mut flagged = signal(Severity::Warning, &[]);
        flagged.title = "bad\u{1b}[31m\u{7}".into();
        flagged.detail = "line\rmore\nend".into();
        assert_eq!(
            text_report(&[flagged]),
            "warning   service    bad\\u{1b}[31m\\u{7}\n                     line\\rmore\\nend\n"
        );
    }

    #[test]
    fn the_json_report_carries_every_signal_with_its_key_and_subjects() {
        let snapshot: Snapshot = crate::state::tests::parsed(json!({
            "format": 1, "observed_ms": 7, "state": "/s",
            "jobs": [{"id": "a", "profile": "get", "campaign": "c", "run": 0, "variant": "v",
                      "state": "settled", "result": {"attempt": 1, "class": "violation"},
                      "attempts": [{"number": 1, "attempt": "a-0001"}]}],
            "findings": [{"id": "a-0001"}],
            "failure_groups": [{"kind": "violation", "identity": "02aa",
                                "findings": ["a-0001"], "profiles": ["get"], "runs": [0],
                                "unresolved": 1}],
        }));
        let signals = crate::signals::detect(&snapshot, &[]);
        let report = json_report(&snapshot, &signals);
        assert_eq!(report["format"], REPORT_FORMAT);
        assert_eq!(report["observed_ms"], 7);
        assert_eq!(report["state"], "/s");
        let totals = &report["totals"];
        assert_eq!(totals["jobs"], 1);
        assert_eq!(totals["by_outcome"]["violation"], 1);
        assert_eq!(totals["by_state"]["settled"], 1);
        assert_eq!(totals["by_domain"]["service"], 1);
        assert_eq!(totals["attempts"], 0);
        assert_eq!(totals["finished_last_hour"], 0);
        assert_eq!(totals["findings"], 1);
        assert_eq!(totals["release_blockers"], 0);
        assert_eq!(totals["free_bytes"], 1u64 << 40);
        assert_eq!(report["worst"], "critical");
        let listed = report["signals"].as_array().unwrap();
        assert_eq!(listed.len(), signals.len());
        let group = listed
            .iter()
            .find(|signal| signal["detector"] == "failure-group")
            .unwrap_or_else(|| panic!("{listed:?}"));
        assert_eq!(group["severity"], "critical");
        assert_eq!(group["domain"], "service");
        assert_eq!(group["subjects"], json!(["a-0001"]));
        let source = signals
            .iter()
            .find(|signal| signal.detector == "failure-group")
            .unwrap();
        assert_eq!(group["key"], json!(source.key()));
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cm-check-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Runs `check --json` for `line` with `history` and returns the exit
    /// code and the parsed stdout object.
    fn run_check(line: &str, history: History) -> (u8, Value) {
        let options = parse(&args(line), None).unwrap();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = check(&options, history, &mut out, &mut err);
        (code, serde_json::from_slice(&out).unwrap())
    }

    #[test]
    fn a_failed_snapshot_exits_3_with_the_failure_object() {
        let (code, report) = run_check(
            "check --json --file /nonexistent/s.json",
            History::in_memory(),
        );
        assert_eq!(code, EXIT_SNAPSHOT);
        assert_eq!(report["signals"], json!([]));
        assert!(
            report["error"]
                .as_str()
                .unwrap()
                .contains("snapshot failed")
        );
    }

    #[test]
    fn an_unopenable_history_exits_4_with_the_failure_object() {
        let dir = scratch("open");
        std::fs::write(dir.join("file"), "").unwrap();
        let options = parse(
            &args(&format!(
                "check --json --file {}/s.json --history {}/file/h.jsonl",
                dir.display(),
                dir.display()
            )),
            None,
        )
        .unwrap();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            open_history(&options, &mut out, &mut err).err(),
            Some(EXIT_HISTORY)
        );
        let report: Value = serde_json::from_slice(&out).unwrap();
        assert!(
            report["error"]
                .as_str()
                .unwrap()
                .contains("history unusable")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Two monitors on one history: a sample the other monitor recorded
    /// while this one was fetching decides whether a group is NEW.
    #[test]
    fn check_detects_against_the_sample_another_monitor_recorded_during_its_fetch() {
        let dir = scratch("shared-history");
        let path = dir.join("h.jsonl");
        let group = json!({"kind": "violation", "identity": "02aa", "findings": ["a-0001"],
                           "profiles": ["get"], "runs": [0], "unresolved": 1});
        let with_group = |observed_ms: u64| {
            crate::state::tests::complete(json!({
                "observed_ms": observed_ms, "state": "/s", "failure_groups": [group],
            }))
        };
        let mut stale = History::open(&path).unwrap();
        let empty: Snapshot = serde_json::from_value(crate::state::tests::complete(
            json!({"observed_ms": 3, "state": "/s"}),
        ))
        .unwrap();
        stale.record(Sample::of(&empty)).unwrap();
        let mut other = History::open(&path).unwrap();
        let earlier: Snapshot = serde_json::from_value(with_group(5)).unwrap();
        other.record(Sample::of(&earlier)).unwrap();
        std::fs::write(dir.join("s.json"), with_group(7).to_string()).unwrap();
        let (code, report) = run_check(
            &format!("check --json --file {}/s.json", dir.display()),
            stale,
        );
        assert_eq!(code, EXIT_CRITICAL);
        let titles: Vec<&str> = report["signals"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|signal| signal["detector"] == "failure-group")
            .map(|signal| signal["title"].as_str().unwrap())
            .collect();
        assert_eq!(titles.len(), 1, "{titles:?}");
        assert!(!titles[0].starts_with("NEW "), "{titles:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_record_prints_the_full_report_and_exits_4() {
        let dir = scratch("record");
        let snapshot = crate::state::tests::complete(json!({
            "observed_ms": 7, "state": "/s",
            "jobs": [{"id": "a", "state": "settled",
                      "result": {"attempt": 1, "class": "violation"}}],
        }));
        std::fs::write(dir.join("s.json"), snapshot.to_string()).unwrap();
        let history = History::open(&dir.join("later/h.jsonl")).unwrap();
        std::fs::write(dir.join("later"), "").unwrap();
        let (code, report) = run_check(
            &format!("check --json --file {}/s.json", dir.display()),
            history,
        );
        assert_eq!(code, EXIT_HISTORY);
        assert_eq!(report["totals"]["jobs"], 1);
        assert!(report.get("error").is_none(), "{report}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn check_exits_with_the_worst_signal_in_json_and_text() {
        let dir = scratch("codes");
        let violating = crate::state::tests::complete(json!({
            "jobs": [{"id": "a", "state": "settled",
                      "result": {"attempt": 1, "class": "violation"}}],
            "failure_groups": [{"kind": "violation", "identity": "02aa",
                                "findings": ["a-0001"], "profiles": ["get"], "runs": [0],
                                "unresolved": 1}],
        }));
        std::fs::write(dir.join("bad.json"), violating.to_string()).unwrap();
        std::fs::write(
            dir.join("clean.json"),
            crate::state::tests::complete(json!({})).to_string(),
        )
        .unwrap();
        let (code, report) = run_check(
            &format!("check --json --file {}/bad.json", dir.display()),
            History::in_memory(),
        );
        assert_eq!(code, EXIT_CRITICAL);
        assert_eq!(report["worst"], "critical");
        let (code, report) = run_check(
            &format!("check --json --file {}/clean.json", dir.display()),
            History::in_memory(),
        );
        assert_eq!(code, 0);
        assert_eq!(report["worst"], Value::Null);
        let options = parse(
            &args(&format!("check --file {}/bad.json", dir.display())),
            None,
        )
        .unwrap();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            check(&options, History::in_memory(), &mut out, &mut err),
            EXIT_CRITICAL
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("critical"), "{text}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_signal_key_ignores_subject_order_and_changes_with_the_subjects() {
        let key = signal(Severity::Info, &["a", "b"]).key();
        assert_eq!(key, signal(Severity::Info, &["b", "a"]).key());
        assert_ne!(key, signal(Severity::Info, &["a", "c"]).key());
        assert!(key.starts_with("test"), "{key}");
    }

    #[test]
    fn the_json_failure_names_the_error_and_no_signals() {
        assert_eq!(
            json_failure("ssh: refused"),
            json!({"format": 1, "error": "ssh: refused", "worst": null, "signals": []})
        );
    }
}
