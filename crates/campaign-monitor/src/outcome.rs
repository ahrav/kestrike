//! Attribution of finished attempts and settled jobs. Every finished
//! attempt maps to one [`Outcome`]. An outcome's domain identifies where an
//! operator investigates first. Passes and state-only outcomes such as
//! `running` or `queued` have `domain: None`. The supervisor's finish class
//! already folds binding and custody faults in, so attribution reads the
//! class and the sim facts of the attempt it belongs to.

use crate::snapshot::{AttemptRow, Job, JobState, Sim};

/// Where an operator investigates an outcome first: the service under
/// test, the simulator, the campaign supervisor and its admitted counts,
/// the host's cgroup limits and custody, or controller interruptions.
/// Declaration order is the order signals sort by, so a derived `min()`
/// picks the domain listed first; [`Outcome::rank`] orders investigation
/// priority separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Domain {
    Service,
    Simulator,
    Campaign,
    Host,
    Chaos,
}

impl Domain {
    pub const ALL: [Self; 5] = [
        Self::Service,
        Self::Simulator,
        Self::Campaign,
        Self::Host,
        Self::Chaos,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Simulator => "simulator",
            Self::Campaign => "campaign",
            Self::Host => "host",
            Self::Chaos => "chaos",
        }
    }
}

/// The attributed outcome of one attempt or job. `label` is one of:
/// `pass`; `held` for a held job, result or attempt row, for a job row
/// outside the producer's shapes and for a finish class this monitor does
/// not know; `artifact held` for a held sim artifact; `inconclusive`,
/// `inconclusive: ledger`, `inconclusive: recorder cap` or `inconclusive:
/// limit <name>`; `unsuccessful` or `unsuccessful: <rule>`; another finish
/// class name this monitor knows; or a state name such as `running` or
/// `queued`, whose domain is `None`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Outcome {
    pub label: String,
    pub domain: Option<Domain>,
}

impl Outcome {
    fn new(label: impl Into<String>, domain: Option<Domain>) -> Self {
        Self {
            label: label.into(),
            domain,
        }
    }

    fn held() -> Self {
        Self::new("held", Some(Domain::Campaign))
    }

    pub fn is_pass(&self) -> bool {
        self.label == "pass"
    }

    /// A held record or sim artifact, which the held-record detector
    /// reports.
    pub fn is_held(&self) -> bool {
        matches!(self.label.as_str(), "held" | "artifact held")
    }

    pub fn is_inconclusive(&self) -> bool {
        self.label.starts_with("inconclusive")
    }

    pub fn is_violation(&self) -> bool {
        self.label == "violation"
    }

    /// The stop of an inconclusive run that ended at a count the campaign
    /// admitted: `recorder cap` or `limit <name>`.
    pub fn admitted_stop(&self) -> Option<&str> {
        match self.domain {
            Some(Domain::Campaign) => self.label.strip_prefix("inconclusive: "),
            _ => None,
        }
    }

    /// Returns `<name>` for a campaign-admitted `limit <name>` stop.
    pub fn admitted_limit(&self) -> Option<&str> {
        self.admitted_stop()?.strip_prefix("limit ")
    }

    /// The rank of an outcome with no domain, the lowest priority.
    pub const UNRANKED: u8 = 6;

    /// Investigation priority, where a smaller rank is more urgent: 0 the
    /// service, 1 a simulator fault, 2 the campaign, 3 the host, 4 an
    /// inconclusive simulator stop, 5 chaos. An inconclusive simulator stop
    /// leaves fault attribution unresolved, so it is less urgent than the
    /// faults the campaign and host can show.
    pub fn rank(&self) -> u8 {
        match self.domain {
            Some(Domain::Service) => 0,
            Some(Domain::Simulator) if !self.is_inconclusive() => 1,
            Some(Domain::Campaign) => 2,
            Some(Domain::Host) => 3,
            Some(Domain::Simulator) => 4,
            Some(Domain::Chaos) => 5,
            None => Self::UNRANKED,
        }
    }

    /// The outcome of `job`: its settled result's class, read with the sim
    /// facts of [`Job::outcome_attempt`]; that attempt's outcome for a
    /// waiting job; or its state name. A held job or result is `held` in
    /// the campaign domain, and so is a row outside the producer's shapes:
    /// a verified row without its profile, campaign or run, a held or unknown state, a
    /// result on a job that is not settled, a settled job without a result,
    /// with a result missing its attempt or class, or whose named attempt
    /// has no row and no held row stands in for it, a settling job whose
    /// pin is absent, held, missing its attempt or class, or names a class
    /// this monitor does not know, a queued job with attempt rows, a waiting
    /// job whose highest-numbered attempt has no finish record, and a
    /// running job whose highest-numbered attempt has one or that has no
    /// attempt rows.
    pub fn of_job(job: &Job) -> Self {
        if job.held.is_some()
            || job.profile.is_empty()
            || job.campaign.is_empty()
            || job.run.is_none()
        {
            return Self::held();
        }
        match (&job.result, job.state) {
            (Some(result), JobState::Settled) => {
                let (None, Some(class), Some(_)) =
                    (&result.held, result.class.as_deref(), result.attempt)
                else {
                    return Self::held();
                };
                let sim = match job.outcome_attempt() {
                    Some(row) => row.sim.as_ref(),
                    None if job.attempts.iter().any(|row| row.held.is_some()) => None,
                    None => return Self::held(),
                };
                Self::of_class(class, sim)
            }
            (Some(_), _) | (None, JobState::Settled | JobState::Held) => Self::held(),
            (None, JobState::Running)
                if job.last_attempt().is_none_or(|row| row.finished.is_some()) =>
            {
                Self::held()
            }
            (None, JobState::Settling)
                if job.pin.as_ref().is_none_or(|pin| {
                    pin.held.is_some()
                        || pin.attempt.is_none()
                        || pin
                            .class
                            .as_deref()
                            .is_none_or(|class| Self::of_class(class, None).is_held())
                }) =>
            {
                Self::held()
            }
            (None, JobState::Queued) if !job.attempts.is_empty() => Self::held(),
            (None, JobState::Waiting) => match job.outcome_attempt() {
                Some(row) if row.finished.is_some() => Self::of_attempt(row),
                _ => Self::held(),
            },
            (None, state) => Self::new(state.name(), None),
        }
    }

    /// The outcome of one attempt row: `held` for a held row, the finish
    /// class read with the row's sim facts, or `running` with no domain
    /// while the row has no finish record.
    pub fn of_attempt(row: &AttemptRow) -> Self {
        if row.held.is_some() {
            return Self::held();
        }
        match &row.finished {
            Some(finish) => Self::of_class(&finish.class, row.sim.as_ref()),
            None => Self::new("running", None),
        }
    }

    fn of_class(class: &str, sim: Option<&Sim>) -> Self {
        if sim.is_some_and(|sim| sim.held.is_some()) {
            return Self::new("artifact held", Some(Domain::Campaign));
        }
        let domain = match class {
            "pass" => return Self::new("pass", None),
            "inconclusive" => return inconclusive(sim),
            "unsuccessful" => return unsuccessful(sim),
            "violation" => Domain::Service,
            "engine-failure" | "signal" | "incomplete" | "disagreement" => Domain::Simulator,
            "rejected" | "malformed-evidence" | "misbound-evidence" | "infrastructure" => {
                Domain::Campaign
            }
            "oom" | "pid-limit" | "cpu-limit" | "output-limit" | "mixed-limits" | "watchdog" => {
                Domain::Host
            }
            "interrupted" => Domain::Chaos,
            _ => return Self::held(),
        };
        Self::new(class, Some(domain))
    }
}

/// Splits `unsuccessful` by the rule the sim summary names, so a run
/// short of its profile's coverage minima and a run whose liveness check
/// failed form separate outcomes. A summary that names no rule stays
/// `unsuccessful`.
fn unsuccessful(sim: Option<&Sim>) -> Outcome {
    match sim.and_then(|sim| sim.unsuccessful.as_deref()) {
        Some(rule) => Outcome::new(format!("unsuccessful: {rule}"), Some(Domain::Service)),
        None => Outcome::new("unsuccessful", Some(Domain::Service)),
    }
}

/// Splits `inconclusive` by the stop the sim summary reports. A recorder
/// cap (`infrastructure cap`) and a `stop limit` both end the run at a
/// count the campaign admitted, such as `records` or `turns`; these stops
/// belong to the campaign domain because the campaign admitted their
/// limits. Every other inconclusive stop, ledger verdicts included,
/// belongs to the simulator.
fn inconclusive(sim: Option<&Sim>) -> Outcome {
    let terminal = sim.and_then(|sim| sim.terminal.as_deref()).unwrap_or("");
    let cause = sim.and_then(|sim| sim.cause.as_deref()).unwrap_or("");
    if terminal == "infrastructure cap" || cause.starts_with("infrastructure cap") {
        return Outcome::new("inconclusive: recorder cap", Some(Domain::Campaign));
    }
    if let Some(rest) = cause.split("stop limit ").nth(1) {
        let limit = rest.split([',', ' ']).next().unwrap_or(rest);
        return Outcome::new(
            format!("inconclusive: limit {limit}"),
            Some(Domain::Campaign),
        );
    }
    if cause.contains("ledger") {
        return Outcome::new("inconclusive: ledger", Some(Domain::Simulator));
    }
    Outcome::new("inconclusive", Some(Domain::Simulator))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sim(terminal: &str, cause: &str) -> Sim {
        Sim {
            terminal: Some(terminal.into()),
            cause: Some(cause.into()),
            ..Sim::default()
        }
    }

    #[test]
    fn inconclusive_stops_at_admitted_bounds_are_attributed_to_the_campaign() {
        let cases = [
            (
                "complete inconclusive fired=03 required=03",
                "inconclusive, stop limit turns",
                "inconclusive: limit turns",
                Domain::Campaign,
            ),
            (
                "complete inconclusive fired=03 required=03",
                "inconclusive, stop limit same_time",
                "inconclusive: limit same_time",
                Domain::Campaign,
            ),
            (
                "infrastructure cap",
                "infrastructure cap, stop unavailable",
                "inconclusive: recorder cap",
                Domain::Campaign,
            ),
            (
                "complete inconclusive fired=10 required=10",
                "inconclusive, ledger Bound { cut: 1 }, stages",
                "inconclusive: ledger",
                Domain::Simulator,
            ),
            (
                "complete inconclusive",
                "inconclusive",
                "inconclusive",
                Domain::Simulator,
            ),
        ];
        for (terminal, cause, label, domain) in cases {
            let outcome = Outcome::of_class("inconclusive", Some(&sim(terminal, cause)));
            assert_eq!(outcome.label, label, "{cause}");
            assert_eq!(outcome.domain, Some(domain), "{cause}");
        }
    }

    #[test]
    fn unsuccessful_runs_split_by_the_rule_their_summary_names() {
        let named = |rule: &str| Sim {
            unsuccessful: Some(rule.into()),
            ..Sim::default()
        };
        let short = Outcome::of_class(
            "unsuccessful",
            Some(&named("fewer exact reads than the profile requir")),
        );
        let stalled = Outcome::of_class(
            "unsuccessful",
            Some(&named("healthy work made no progress after the f")),
        );
        assert_eq!(
            short.label,
            "unsuccessful: fewer exact reads than the profile requir"
        );
        assert_eq!(
            stalled.label,
            "unsuccessful: healthy work made no progress after the f"
        );
        assert_ne!(short, stalled);
        assert_eq!(short.domain, Some(Domain::Service));
        assert_eq!(stalled.domain, Some(Domain::Service));
        let unnamed = Outcome::of_class("unsuccessful", Some(&Sim::default()));
        assert_eq!(unnamed.label, "unsuccessful");
        assert_eq!(unnamed.domain, Some(Domain::Service));
    }

    #[test]
    fn every_finish_class_maps_to_one_domain_and_pass_to_none() {
        let expected = [
            ("pass", None),
            ("violation", Some(Domain::Service)),
            ("unsuccessful", Some(Domain::Service)),
            ("engine-failure", Some(Domain::Simulator)),
            ("signal", Some(Domain::Simulator)),
            ("incomplete", Some(Domain::Simulator)),
            ("disagreement", Some(Domain::Simulator)),
            ("rejected", Some(Domain::Campaign)),
            ("malformed-evidence", Some(Domain::Campaign)),
            ("misbound-evidence", Some(Domain::Campaign)),
            ("infrastructure", Some(Domain::Campaign)),
            ("oom", Some(Domain::Host)),
            ("pid-limit", Some(Domain::Host)),
            ("cpu-limit", Some(Domain::Host)),
            ("output-limit", Some(Domain::Host)),
            ("mixed-limits", Some(Domain::Host)),
            ("watchdog", Some(Domain::Host)),
            ("interrupted", Some(Domain::Chaos)),
        ];
        for (class, domain) in expected {
            assert_eq!(Outcome::of_class(class, None).domain, domain, "{class}");
        }
    }

    #[test]
    fn a_finish_class_this_monitor_does_not_know_is_held_in_the_campaign_domain() {
        for class in ["reshaped", ""] {
            let outcome = Outcome::of_class(class, None);
            assert_eq!(outcome.label, "held", "{class:?}");
            assert_eq!(outcome.domain, Some(Domain::Campaign), "{class:?}");
            assert!(outcome.is_held(), "{class:?}");
        }
        let job: Job = serde_json::from_value(serde_json::json!({
            "id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "settled",
            "result": {"attempt": 1, "class": "reshaped"},
            "attempts": [{"number": 1, "finished": {"class": "reshaped"}}],
        }))
        .unwrap();
        assert_eq!(Outcome::of_job(&job).label, "held");
    }

    #[test]
    fn a_held_sim_artifact_overrides_the_finish_class() {
        let held = Sim {
            held: Some("artifact differs".into()),
            ..Sim::default()
        };
        let outcome = Outcome::of_class("pass", Some(&held));
        assert_eq!(outcome.label, "artifact held");
        assert_eq!(outcome.domain, Some(Domain::Campaign));
    }

    #[test]
    fn a_settled_job_reads_only_the_sim_facts_of_the_attempt_its_result_names() {
        let job: Job = serde_json::from_value(serde_json::json!({
            "id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "settled",
            "result": {"attempt": 2, "class": "inconclusive"},
            "attempts": [
                {"number": 1, "sim": {"cause": "inconclusive, stop limit turns"}},
                {"held": "attempt record unreadable"},
            ],
        }))
        .unwrap();
        let outcome = Outcome::of_job(&job);
        assert_eq!(outcome.label, "inconclusive");
        assert_eq!(outcome.domain, Some(Domain::Simulator));
    }

    #[test]
    fn producer_shaped_running_and_settling_jobs_read_as_their_state() {
        let finished =
            serde_json::json!({"number": 1, "finished_ms": 2, "finished": {"class": "oom"}});
        let shapes = [
            (
                serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "running",
                                   "attempts": [finished, {"number": 2, "intent_ms": 3}]}),
                "running",
            ),
            (
                serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "settling",
                                   "pin": {"attempt": 1, "class": "oom"}, "attempts": [finished]}),
                "settling",
            ),
            (
                serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0,
                                   "state": "queued"}),
                "queued",
            ),
        ];
        for (shape, state) in shapes {
            let job: Job = serde_json::from_value(shape.clone()).unwrap();
            assert_eq!(Outcome::of_job(&job), Outcome::new(state, None), "{shape}");
        }
    }

    #[test]
    fn job_rows_outside_the_producer_shapes_are_held_in_the_campaign_domain() {
        let row = serde_json::json!({"number": 1, "finished_ms": 2, "finished": {"class": "pass"}});
        let shapes = [
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "reshaped",
                               "result": {"class": "pass"}}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "settled"}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "settled",
                               "result": {"class": "pass"}}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "settled",
                               "result": {"attempt": 1}}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "settled",
                               "result": {"attempt": 1, "class": "pass"}}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "settled",
                               "result": {"attempt": 2, "class": "pass"}, "attempts": [row]}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "settled",
                               "result": {"attempt": 1, "class": "pass"},
                               "attempts": [{"number": null, "finished": {"class": "pass"}}]}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "running",
                               "result": {"attempt": 1, "class": "pass"}, "attempts": [row]}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "running"}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "waiting",
                               "attempts": [{"held": "unreadable"}]}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "waiting",
                               "attempts": [{"number": 1, "intent_ms": 1_000}]}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "settling"}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "settling",
                               "pin": {"class": "pass"}}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "settling",
                               "pin": {"attempt": 1}}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "settling",
                               "pin": {"attempt": 1, "class": "future"}}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "running",
                               "attempts": [row]}),
            serde_json::json!({"id": "j", "profile": "get", "campaign": "c", "run": 0, "state": "queued",
                               "attempts": [row]}),
            serde_json::json!({"id": "j", "campaign": "c", "run": 0, "state": "queued"}),
            serde_json::json!({"id": "j", "profile": "get", "run": 0, "state": "queued"}),
        ];
        for shape in shapes {
            let job: Job = serde_json::from_value(shape.clone()).unwrap();
            let outcome = Outcome::of_job(&job);
            assert_eq!(outcome.label, "held", "{shape}");
            assert_eq!(outcome.domain, Some(Domain::Campaign), "{shape}");
        }
    }
}
