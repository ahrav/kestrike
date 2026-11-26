//! The types of a `campaign status` snapshot, deserialized from its JSON.
//! Deserialization ignores unknown fields, so snapshots can gain fields
//! under the same format. The fields whose absence would silence a
//! detector are required, because the producer always writes them:
//! `state`, `config`, `space`, `probes`, `held_probes`, `jobs`, `findings`,
//! `failure_groups`, each group's `unresolved`, and a verified
//! configuration's `config` map. A verified finding row without `triage`
//! reads as held. A snapshot without `lock` comes from a producer that
//! does not report the state directory's lock holders.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

/// The one snapshot format this monitor reads.
pub const FORMAT: u64 = 1;

#[derive(Debug, Clone, Deserialize)]
pub struct Snapshot {
    pub format: u64,
    /// The observed host's wall clock, in milliseconds since the Unix
    /// epoch, when the snapshot was taken. Elapsed times between
    /// snapshots compare only snapshots read on one host.
    pub observed_ms: u64,
    pub state: String,
    #[serde(deserialize_with = "Option::deserialize")]
    pub config: Option<ConfigRow>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub space: Option<Space>,
    pub probes: u64,
    pub held_probes: Vec<HeldEntry>,
    #[serde(default)]
    pub variants: BTreeMap<String, BTreeMap<String, u64>>,
    pub jobs: Vec<Job>,
    pub findings: Vec<FindingRow>,
    #[serde(default)]
    pub release_blockers: Vec<String>,
    pub failure_groups: Vec<FailureGroup>,
    #[serde(default)]
    pub lock: Option<Lock>,
}

impl Snapshot {
    /// Parses one snapshot. Job rows and finding rows each parse on up to
    /// eight threads, the two arrays at once. A snapshot that the
    /// row-parallel reader refuses is read once more by the derived serial
    /// reader, whose error names the first refusal in document order.
    ///
    /// # Errors
    ///
    /// A message when `text` carries a `format` other than [`FORMAT`], or
    /// is no JSON of the snapshot shape.
    pub fn parse(text: &str) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Format {
            format: u64,
        }
        let unsupported = |format: u64| {
            format!("status format {format} is unsupported; this monitor reads format {FORMAT}")
        };
        let snapshot = match crate::rows::read(text) {
            Some(snapshot) => snapshot,
            None => match serde_json::from_str::<Self>(text) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    return Err(match serde_json::from_str::<Format>(text) {
                        Ok(Format { format }) if format != FORMAT => unsupported(format),
                        _ => format!("status is not a format-{FORMAT} snapshot: {error}"),
                    });
                }
            },
        };
        if snapshot.format != FORMAT {
            return Err(unsupported(snapshot.format));
        }
        Ok(snapshot)
    }

    /// The verified configuration's value for `key`; `None` for a held or
    /// absent configuration.
    pub fn config_value(&self, key: &str) -> Option<u64> {
        self.config
            .as_ref()?
            .verified
            .as_ref()?
            .config
            .get(key)
            .copied()
    }
}

/// The rows per thread that a snapshot's drop aims for.
const DROPPED_PER_THREAD: usize = 1024;

impl Drop for Snapshot {
    /// Frees the job and finding rows on up to eight threads once a row
    /// array holds 2048 rows. Each row owns a few dozen small allocations,
    /// so the frees of a large snapshot spread across the threads.
    fn drop(&mut self) {
        crate::parallel::drop_in_runs(std::mem::take(&mut self.jobs), DROPPED_PER_THREAD);
        crate::parallel::drop_in_runs(std::mem::take(&mut self.findings), DROPPED_PER_THREAD);
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConfigRow {
    #[serde(default)]
    pub verified: Option<Configuration>,
    #[serde(default)]
    pub held: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Configuration {
    pub config: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct HeldEntry {
    #[serde(default)]
    pub entry: String,
    #[serde(default)]
    pub held: Option<String>,
}

/// The processes holding the state directory's lock: `holders` when the
/// producer read them, `unknown` with its reason when it could not. An
/// empty `holders` list means no process visible in the PID namespace of
/// the producer's procfs holds the lock.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Lock {
    #[serde(default)]
    pub holders: Option<Vec<LockHolder>>,
    #[serde(default)]
    pub unknown: Option<String>,
}

/// One lock holder. A `mode` of `exclusive` is a controller such as
/// `dispatch`; `shared` is a report snapshot; any other mode is unknown.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct LockHolder {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub pid: Option<u64>,
}

/// Who holds the state directory, as the monitor reads a reported `lock`.
#[derive(Debug, Clone, Copy)]
pub enum Controller<'a> {
    /// The first listed exclusive holder.
    Running(&'a LockHolder),
    /// No visible exclusive holder: the list is empty, `shared: false`, or
    /// holds only `shared` holders, `shared: true`.
    None { shared: bool },
    /// The lock carries an `unknown` reason or no `holders` list, or, with
    /// no exclusive holder, a holder whose mode this monitor does not know.
    Unknown,
}

impl Snapshot {
    /// The state directory's controller; `None` for a snapshot without
    /// `lock`.
    pub fn controller(&self) -> Option<Controller<'_>> {
        let lock = self.lock.as_ref()?;
        let holders = match (&lock.unknown, &lock.holders) {
            (None, Some(holders)) => holders,
            _ => return Some(Controller::Unknown),
        };
        if let Some(holder) = holders.iter().find(|holder| holder.mode == "exclusive") {
            return Some(Controller::Running(holder));
        }
        Some(if holders.iter().all(|holder| holder.mode == "shared") {
            Controller::None {
                shared: !holders.is_empty(),
            }
        } else {
            Controller::Unknown
        })
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct Space {
    pub free_bytes: u64,
    pub free_inodes: u64,
}

/// A job row's `state`. A held job row carries no state and reads as
/// [`JobState::Held`], as does any state name this monitor does not know.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    Queued,
    Running,
    Waiting,
    Settling,
    Settled,
    #[default]
    #[serde(other)]
    Held,
}

impl JobState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Waiting => "waiting",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Held => "held",
        }
    }

    /// A job the controller has yet to start or settle: queued, waiting or
    /// settling, with no attempt in flight.
    pub fn awaits_controller(self) -> bool {
        matches!(self, Self::Queued | Self::Waiting | Self::Settling)
    }

    /// Unsettled work only a controller advances: [`Self::awaits_controller`]
    /// or an attempt in flight, whose finish a later controller reconciles
    /// when the one that started it exits.
    pub fn needs_controller(self) -> bool {
        self.awaits_controller() || self == Self::Running
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Job {
    pub id: String,
    #[serde(default)]
    pub held: Option<String>,
    #[serde(default)]
    pub profile: String,
    #[serde(default)]
    pub campaign: String,
    #[serde(default)]
    pub run: Option<u64>,
    #[serde(default)]
    pub seed: u64,
    #[serde(default)]
    pub class: Option<String>,
    #[serde(default)]
    pub attempts_allowed: u64,
    #[serde(default)]
    pub build: String,
    #[serde(default)]
    pub variant: String,
    #[serde(default)]
    pub state: JobState,
    #[serde(default)]
    pub result: Option<Settled>,
    #[serde(default)]
    pub pin: Option<Settled>,
    #[serde(default)]
    pub attempts: Vec<AttemptRow>,
    #[serde(default)]
    pub attempts_held: Option<Held>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Held {
    #[serde(default)]
    pub held: Option<String>,
}

impl Job {
    /// The highest-numbered attempt row; held rows carry no `number` and
    /// are skipped. The producer derives `state` from the last listed row
    /// instead, held rows included, so a detector that judges a running
    /// job's attempt reads `attempts.last()`.
    pub fn last_attempt(&self) -> Option<&AttemptRow> {
        self.attempts
            .iter()
            .filter(|row| row.number.is_some())
            .max_by_key(|row| row.number)
    }

    /// The attempt row this job's outcome reads: the row its settled
    /// result names, else the last attempt of a waiting job.
    pub fn outcome_attempt(&self) -> Option<&AttemptRow> {
        match (&self.result, self.state) {
            (Some(result), _) => {
                let number = result.attempt?;
                self.attempts.iter().find(|row| row.number == Some(number))
            }
            (None, JobState::Waiting) => self.last_attempt(),
            (None, _) => None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Settled {
    #[serde(default)]
    pub attempt: Option<u64>,
    #[serde(default)]
    pub class: Option<String>,
    #[serde(default)]
    pub exit: Option<u64>,
    #[serde(default)]
    pub signal: Option<u64>,
    #[serde(default)]
    pub watchdog: bool,
    #[serde(default)]
    pub held: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AttemptRow {
    #[serde(default)]
    pub number: Option<u64>,
    #[serde(default)]
    pub entry: Option<String>,
    #[serde(default)]
    pub attempt: Option<String>,
    #[serde(default)]
    pub intent_ms: Option<u64>,
    #[serde(default)]
    pub started_ms: Option<u64>,
    #[serde(default)]
    pub finished_ms: Option<u64>,
    #[serde(default)]
    pub finished: Option<Finish>,
    #[serde(default)]
    pub sim: Option<Sim>,
    #[serde(default)]
    pub finding: Option<String>,
    #[serde(default)]
    pub held: Option<String>,
}

impl AttemptRow {
    /// The time from the intent record's write to the finish record's
    /// write; `None` until both exist, or when the finish predates the
    /// intent.
    pub fn wall_ms(&self) -> Option<u64> {
        self.finished_ms?.checked_sub(self.intent_ms?)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Finish {
    #[serde(default)]
    pub class: String,
    #[serde(default)]
    pub exit: Option<u64>,
    #[serde(default)]
    pub signal: Option<u64>,
    #[serde(default)]
    pub watchdog: bool,
    #[serde(default)]
    pub interruption: Option<u64>,
    #[serde(default)]
    pub binding: String,
    #[serde(default)]
    pub residual_members: bool,
    #[serde(default)]
    pub kernel: Kernel,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Kernel {
    #[serde(default)]
    pub cpu_usage_usec: Option<u64>,
    #[serde(default)]
    pub cpu_throttled_usec: Option<u64>,
    #[serde(default)]
    pub cpu_nr_throttled: Option<u64>,
    #[serde(default)]
    pub memory: BTreeMap<String, u64>,
    #[serde(default)]
    pub pids: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Sim {
    #[serde(default)]
    pub class: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub terminal: Option<String>,
    #[serde(default)]
    pub cause: Option<String>,
    #[serde(default)]
    pub identity: Option<String>,
    #[serde(default)]
    pub decisions: Option<u64>,
    #[serde(default)]
    pub ledger: Option<String>,
    #[serde(default)]
    pub failure_virtual_us: Option<u64>,
    #[serde(default)]
    pub unsuccessful: Option<String>,
    #[serde(default)]
    pub held: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FindingRow {
    pub id: String,
    #[serde(default)]
    pub held: Option<String>,
    #[serde(default)]
    pub blocker: bool,
    #[serde(default)]
    pub resolved: bool,
    #[serde(default)]
    pub verified: Option<Value>,
    /// `None` when the JSON member is absent; `Some(Value::Null)` for an
    /// explicit null.
    #[serde(default, deserialize_with = "present")]
    pub triage: Option<Value>,
    #[serde(default)]
    pub dispositions: Vec<Value>,
}

fn present<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

const STATUSES: [&str; 6] = [
    "reproduced",
    "reduced",
    "diverged",
    "unreproduced",
    "unreducible",
    "insufficient-evidence",
];

impl FindingRow {
    pub fn profile(&self) -> Option<&str> {
        self.verified.as_ref()?["admission"]["job"]["experiment"]["profile"].as_str()
    }

    pub fn kind(&self) -> Option<&str> {
        self.verified.as_ref()?["kind"].as_str()
    }

    pub fn run(&self) -> Option<u64> {
        self.verified.as_ref()?["admission"]["job"]["experiment"]["run"].as_u64()
    }

    pub fn decision(&self) -> Option<&str> {
        self.dispositions.last()?["decision"].as_str()
    }

    pub fn limit_hit(&self) -> Option<&str> {
        self.triage.as_ref()?["limit_hit"].as_str()
    }

    /// The triage column: `none`, `held`, `pending`, a `diverged` or
    /// `unreproduced` latest status, `stalled`, then the latest step's
    /// status, `interrupted`, or `unknown`. A replay that shows
    /// nondeterminism outranks a stall. A latest step with an unrecognized
    /// state or status label is `unknown`. A triage record outside the
    /// producer's shapes is `held`: a verified row without a `triage`
    /// member, or a latest-step record without a boolean `stalled`, a string
    /// or null `limit_hit`, and a string `state`, with a string status for a
    /// `complete` state, a null status for an `interrupted` state, and a
    /// string or null status for any other state.
    pub fn triage_state(&self) -> &str {
        let Some(triage) = &self.triage else {
            return if self.verified.is_some() {
                "held"
            } else {
                "none"
            };
        };
        if triage.is_null() {
            return "none";
        }
        if triage.get("held").is_some() {
            return "held";
        }
        if triage["state"] == "pending" {
            return "pending";
        }
        let latest = &triage["latest"];
        let limit = matches!(
            triage.get("limit_hit"),
            Some(Value::Null | Value::String(_))
        );
        let status = match (latest["state"].as_str(), latest.get("status")) {
            (Some("complete"), Some(Value::String(status))) => {
                if STATUSES.contains(&status.as_str()) {
                    status.as_str()
                } else {
                    "unknown"
                }
            }
            (Some("interrupted"), Some(Value::Null)) => "interrupted",
            (Some("complete" | "interrupted"), _) => return "held",
            (Some(_), Some(Value::String(_) | Value::Null)) => "unknown",
            _ => return "held",
        };
        let Some(stalled) = triage["stalled"].as_bool().filter(|_| limit) else {
            return "held";
        };
        match status {
            "diverged" | "unreproduced" => status,
            _ if stalled => "stalled",
            _ => status,
        }
    }
}
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FailureGroup {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub identity: Option<String>,
    #[serde(default)]
    pub cause: Option<String>,
    #[serde(default)]
    pub failure_virtual_us: Option<u64>,
    #[serde(default)]
    pub findings: Vec<String>,
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub runs: Vec<u64>,
    pub unresolved: u64,
}

impl FailureGroup {
    /// The group's history key: the kind's byte length, `:`, the kind, then
    /// `=` and the identity, or `#` and the first finding. The length prefix
    /// and marker make the key decode to one (kind, identity-or-finding)
    /// pair.
    pub fn key(&self) -> String {
        use std::fmt::Write as _;
        let (marker, rest) = match &self.identity {
            Some(identity) => ('=', identity.as_str()),
            None => ('#', self.findings.first().map_or("", String::as_str)),
        };
        let mut key = String::with_capacity(self.kind.len() + rest.len() + 22);
        write!(key, "{}:{}{marker}{rest}", self.kind.len(), self.kind)
            .expect("writing to a String succeeds");
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> Value {
        serde_json::json!({
            "format": 1, "observed_ms": 5, "state": "/s", "config": null, "probes": 0,
            "held_probes": [],
            "jobs": [], "findings": [], "failure_groups": [],
            "space": {"free_bytes": 1, "free_inodes": 1},
        })
    }

    #[test]
    fn parse_refuses_another_format_and_ignores_unknown_fields() {
        let mut added = complete();
        added["added"] = serde_json::json!({"x": 1});
        let parsed = Snapshot::parse(&added.to_string());
        assert_eq!(parsed.unwrap().observed_ms, 5);
        let error = Snapshot::parse(r#"{"format": 2, "observed_ms": 5}"#).unwrap_err();
        assert!(error.contains("format 2 is unsupported"), "{error}");
        let error = Snapshot::parse(r#"{"format": 2, "jobs": "reshaped"}"#).unwrap_err();
        assert!(error.contains("format 2 is unsupported"), "{error}");
        let error = Snapshot::parse("[").unwrap_err();
        assert!(error.contains("not a format-1 snapshot"), "{error}");
    }

    #[test]
    fn parse_refuses_a_snapshot_missing_any_field_the_producer_always_writes() {
        let outer = [
            "state",
            "config",
            "space",
            "probes",
            "held_probes",
            "jobs",
            "findings",
            "failure_groups",
        ];
        for field in outer {
            let mut missing = complete();
            missing.as_object_mut().unwrap().remove(field);
            let error = Snapshot::parse(&missing.to_string()).unwrap_err();
            assert!(
                error.contains(&format!("missing field `{field}`")),
                "{error}"
            );
        }
        for field in ["free_bytes", "free_inodes"] {
            let mut missing = complete();
            missing["space"].as_object_mut().unwrap().remove(field);
            let error = Snapshot::parse(&missing.to_string()).unwrap_err();
            assert!(
                error.contains(&format!("missing field `{field}`")),
                "{error}"
            );
        }
        let mut group = complete();
        group["failure_groups"] = serde_json::json!([{"kind": "violation"}]);
        let error = Snapshot::parse(&group.to_string()).unwrap_err();
        assert!(error.contains("missing field `unresolved`"), "{error}");
        let mut config = complete();
        config["config"] = serde_json::json!({"verified": {}});
        let error = Snapshot::parse(&config.to_string()).unwrap_err();
        assert!(error.contains("missing field `config`"), "{error}");
    }

    #[test]
    fn a_finish_without_a_class_and_a_group_without_a_kind_parse_as_held() {
        let mut shown = complete();
        shown["jobs"] = serde_json::json!([{
            "id": "j", "state": "waiting",
            "attempts": [{"number": 1, "finished_ms": 2, "finished": {"kernel": {}}}],
        }]);
        shown["failure_groups"] = serde_json::json!([{"unresolved": 1, "findings": ["a-0001"]}]);
        let snapshot = Snapshot::parse(&shown.to_string()).unwrap();
        let row = snapshot.jobs[0].last_attempt().unwrap();
        assert_eq!(row.finished.as_ref().unwrap().class, "");
        assert_eq!(crate::outcome::Outcome::of_attempt(row).label, "held");
        assert_eq!(snapshot.failure_groups[0].kind, "");
    }

    #[test]
    fn triage_state_ranks_nondeterminism_over_a_stall_and_names_an_interrupted_step() {
        let finding = |triage: Value| FindingRow {
            verified: Some(serde_json::json!({})),
            triage: Some(triage),
            ..FindingRow::default()
        };
        let step = |state: &str, status: Value, stalled: Value| {
            finding(serde_json::json!(
                {"latest": {"state": state, "status": status}, "stalled": stalled,
                 "limit_hit": null}
            ))
        };
        let complete =
            |status: &str, stalled: bool| step("complete", status.into(), stalled.into());
        assert_eq!(complete("diverged", true).triage_state(), "diverged");
        assert_eq!(complete("reproduced", true).triage_state(), "stalled");
        assert_eq!(complete("reproduced", false).triage_state(), "reproduced");
        let interrupted = step("interrupted", Value::Null, false.into());
        assert_eq!(interrupted.triage_state(), "interrupted");
        assert_eq!(finding(Value::Null).triage_state(), "none");
        assert_eq!(
            finding(serde_json::json!({"state": "pending"})).triage_state(),
            "pending"
        );
        let unverified = FindingRow::default();
        assert_eq!(unverified.triage_state(), "none");
        let absent = FindingRow {
            verified: Some(serde_json::json!({})),
            ..FindingRow::default()
        };
        assert_eq!(absent.triage_state(), "held");

        let no_status = finding(serde_json::json!(
            {"latest": {"state": "complete"}, "stalled": false, "limit_hit": null}
        ));
        let no_limit = finding(serde_json::json!(
            {"latest": {"state": "complete", "status": "reproduced"}, "stalled": false}
        ));
        let malformed = [
            finding(serde_json::json!("complete")),
            finding(serde_json::json!({"stalled": false, "limit_hit": null})),
            no_status,
            no_limit,
            complete_with(Value::Null),
            complete_with(serde_json::json!(["diverged"])),
            step("interrupted", "reproduced".into(), false.into()),
            step("interrupted", "diverged".into(), false.into()),
            step("reshaped", serde_json::json!(7), false.into()),
            step("complete", "reproduced".into(), "true".into()),
            finding(serde_json::json!(
                {"latest": {"state": "complete", "status": "reproduced"}, "stalled": false,
                 "limit_hit": 7}
            )),
        ];
        for row in malformed {
            assert_eq!(row.triage_state(), "held", "{:?}", row.triage);
        }
        let unknown = [
            complete_with(serde_json::json!("reshaped")),
            step("reshaped", Value::Null, false.into()),
            step("reshaped", "diverged".into(), false.into()),
        ];
        for row in unknown {
            assert_eq!(row.triage_state(), "unknown", "{:?}", row.triage);
        }

        fn complete_with(status: Value) -> FindingRow {
            FindingRow {
                verified: Some(serde_json::json!({})),
                triage: Some(serde_json::json!(
                    {"latest": {"state": "complete", "status": status}, "stalled": false,
                     "limit_hit": null}
                )),
                ..FindingRow::default()
            }
        }
    }

    #[test]
    fn last_attempt_is_the_highest_number_in_any_listing_order() {
        let row = |number: Option<u64>| AttemptRow {
            number,
            ..AttemptRow::default()
        };
        let job = Job {
            attempts: vec![row(Some(10)), row(Some(9)), row(None)],
            ..Job::default()
        };
        assert_eq!(job.last_attempt().unwrap().number, Some(10));
    }

    #[test]
    fn a_finish_written_before_its_intent_has_no_wall_time() {
        let row = |intent_ms, finished_ms| AttemptRow {
            intent_ms: Some(intent_ms),
            finished_ms: Some(finished_ms),
            ..AttemptRow::default()
        };
        assert_eq!(row(1_000, 4_000).wall_ms(), Some(3_000));
        assert_eq!(row(4_000, 1_000).wall_ms(), None);
    }
}
