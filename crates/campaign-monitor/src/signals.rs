//! Detectors that turn one snapshot and its history into [`Signal`]s.
//! Detector arithmetic on snapshot and history values saturates or is
//! checked, so no value from either source panics or wraps a comparison.

use std::collections::{BTreeMap, BTreeSet};

use crate::history::Sample;
use crate::outcome::{Domain, Outcome};
use crate::parallel;
use crate::snapshot::{Controller, Job, JobState, Snapshot};
use crate::source::shell_quote;

/// How urgent a signal is. Declaration order is most severe first, so the
/// derived `Ord` sorts `Critical` first and `min()` is the worst signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }
}

/// One finding of one detector. `detector` names it: `failure-group`,
/// `held-record`, `triage`, `seed-sensitive`, `undersized-counts`,
/// `outcome`, `stuck-attempt`, `idle-queue`, `space`, `throttling` or
/// `probes`. `subjects` holds identifiers only, by detector: finding ids
/// for `failure-group` and `triage`; `space`, `config.json`,
/// `probes/<entry>`, `jobs/<id>` and finding ids for `held-record`; a JSON
/// array of campaign, profile, build and variant for `seed-sensitive`; job
/// ids for `undersized-counts` and `outcome`; attempt ids, or the job id of
/// an unnamed attempt, for `stuck-attempt`; none for `idle-queue`, `space`,
/// `throttling` and `probes`. Title, detail and subjects carry snapshot
/// text unfiltered, so a renderer filters control characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    pub severity: Severity,
    pub domain: Domain,
    pub detector: &'static str,
    pub title: String,
    pub detail: String,
    pub subjects: Vec<String>,
}

impl Signal {
    /// Stable across polls while the detector and its sorted subjects stay
    /// the same; a signal without subjects keys on its detector alone. Each
    /// subject's length is hashed before its bytes, so distinct subject
    /// lists hash distinct byte streams.
    pub fn key(&self) -> String {
        let mut subjects: Vec<&str> = self.subjects.iter().map(String::as_str).collect();
        subjects.sort_unstable();
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for subject in subjects {
            let length = (subject.len() as u64).to_le_bytes();
            for byte in length.iter().chain(subject.as_bytes()) {
                hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
            }
        }
        format!("{}:{hash:016x}", self.detector)
    }
}

/// The inputs every detector reads. `history` holds samples of the
/// snapshot's state directory read on the snapshot's host, oldest first;
/// detectors neither sort nor check it. [`Context::new`] computes
/// `outcomes`, one per job in snapshot order.
pub struct Context<'a> {
    pub snapshot: &'a Snapshot,
    pub history: &'a [Sample],
    pub outcomes: Vec<(&'a Job, Outcome)>,
}

impl<'a> Context<'a> {
    pub fn new(snapshot: &'a Snapshot, history: &'a [Sample]) -> Self {
        let outcomes = parallel::runs(&snapshot.jobs, JOBS_PER_THREAD, |jobs| {
            jobs.iter()
                .map(|job| (job, Outcome::of_job(job)))
                .collect::<Vec<_>>()
        })
        .concat();
        Self {
            snapshot,
            history,
            outcomes,
        }
    }

    /// The NEW marker compares against the newest history sample strictly
    /// older than the snapshot. `previous()` returns `None` when no such
    /// sample exists or the last history sample is newer than the snapshot.
    fn previous(&self) -> Option<&Sample> {
        if self
            .history
            .last()
            .is_some_and(|sample| sample.observed_ms > self.snapshot.observed_ms)
        {
            return None;
        }
        self.history
            .iter()
            .rev()
            .find(|sample| sample.observed_ms < self.snapshot.observed_ms)
    }
}

type Detector = fn(&Context) -> Vec<Signal>;

/// Every detector, in the order [`detect`] runs them. Each reads a
/// [`Context`] under its history precondition.
pub const DETECTORS: &[Detector] = &[
    failure_groups,
    held_records,
    triage,
    seed_sensitive,
    undersized_counts,
    outcomes,
    stuck_attempts,
    idle_queue,
    space,
    throttling,
    probes,
];

/// Unsettled jobs warn at once when no visible controller holds the state
/// directory; otherwise a queue with nothing running warns once no attempt
/// finished this long.
const IDLE_MS: u64 = 600_000;
/// Running attempts raise `stuck-attempt` when their age exceeds the
/// configured wall limit plus `STUCK_GRACE_MS`.
const STUCK_GRACE_MS: u64 = 60_000;
/// The least age of the history sample a fill projection compares against.
const PROJECTION_WINDOW_MS: u64 = 3_600_000;
/// A projected fill within this long raises a space warning.
const FILL_HORIZON_MS: u64 = 24 * 3_600_000;
/// The most items [`list`] names before it prints the total.
const LISTED: usize = 6;
/// Free space below this is critical.
const LOW_SPACE: u64 = 5 << 30;
/// An attempt whose throttled time exceeds `1 / THROTTLE_RATIO` of its CPU
/// usage time counts as throttled.
const THROTTLE_RATIO: u64 = 4;
/// Retained probe directories at and past this count raise a signal.
const MANY_PROBES: u64 = 1000;

/// The jobs per thread that outcome, matrix and totals runs aim for, and
/// the job count from which [`detect`] runs its detectors on more than one
/// thread.
pub(crate) const JOBS_PER_THREAD: usize = 1024;

/// Runs every detector over `snapshot` and `history`, on up to eight
/// threads once the snapshot holds 1024 jobs. `history` holds samples of
/// the same state directory read on the same host, oldest first
/// as [`History::samples`](crate::history::History::samples) returns it.
/// Signals sort by severity, then triage signals ahead of others of
/// equal severity, then by domain in [`Domain`] declaration order, then by
/// title.
pub fn detect(snapshot: &Snapshot, history: &[Sample]) -> Vec<Signal> {
    let context = Context::new(snapshot, history);
    let least = if snapshot.jobs.len() < JOBS_PER_THREAD {
        DETECTORS.len()
    } else {
        1
    };
    let mut signals: Vec<Signal> = parallel::runs(DETECTORS, least, |detectors| {
        detectors
            .iter()
            .flat_map(|detector| detector(&context))
            .collect::<Vec<_>>()
    })
    .concat();
    signals.sort_by(|a, b| {
        (a.severity, a.detector != "triage", a.domain, &a.title).cmp(&(
            b.severity,
            b.detector != "triage",
            b.domain,
            &b.title,
        ))
    });
    signals
}

fn signal(
    severity: Severity,
    domain: Domain,
    detector: &'static str,
    title: String,
    detail: String,
    subjects: Vec<String>,
) -> Signal {
    Signal {
        severity,
        domain,
        detector,
        title,
        detail,
        subjects,
    }
}

fn list<T: ToString>(items: impl IntoIterator<Item = T>) -> String {
    let mut items = items.into_iter();
    let shown: Vec<String> = items
        .by_ref()
        .take(LISTED)
        .map(|item| item.to_string())
        .collect();
    let rest = items.count();
    if rest > 0 {
        format!("{}, ... ({} total)", shown.join(", "), shown.len() + rest)
    } else {
        shown.join(", ")
    }
}

/// Jobs whose outcome is final or awaits its next attempt, which the
/// count and outcome detectors read so an admitted stop is reported by
/// exactly one of them.
fn settled_or_waiting<'a>(context: &'a Context) -> impl Iterator<Item = &'a (&'a Job, Outcome)> {
    context
        .outcomes
        .iter()
        .filter(|(job, _)| matches!(job.state, JobState::Settled | JobState::Waiting))
}

/// The held-record detector reports findings with unrecognized kinds.
fn kind_domain(kind: &str) -> Option<Domain> {
    Some(match kind {
        "violation" => Domain::Service,
        "panic" | "abort" | "harness" => Domain::Simulator,
        "watchdog" => Domain::Host,
        "truncated" => Domain::Campaign,
        _ => return None,
    })
}

/// `failure_groups` emits one critical signal per unresolved failure group
/// with a recognized kind. A group is NEW when an older history sample
/// exists and the newest such sample lacks the group's key.
fn failure_groups(context: &Context) -> Vec<Signal> {
    let previous = context.previous();
    let state = shell_quote(&context.snapshot.state);
    context
        .snapshot
        .failure_groups
        .iter()
        .filter(|group| group.unresolved > 0)
        .filter_map(|group| {
            let domain = kind_domain(&group.kind)?;
            let new = previous.is_some_and(|sample| !sample.identities.contains(&group.key()));
            let cause = group.cause.as_deref().unwrap_or(&group.kind);
            let at = group
                .failure_virtual_us
                .map(|us| format!(" at virtual_us {us}"))
                .unwrap_or_default();
            let runs: BTreeSet<u64> = group.runs.iter().copied().collect();
            Some(signal(
                Severity::Critical,
                domain,
                "failure-group",
                format!(
                    "{}{cause} in {}",
                    if new { "NEW " } else { "" },
                    list(&group.profiles)
                ),
                format!(
                    "{} unresolved of {} finding(s) with one failure identity across {} {}{at}. \
                     Replay with `campaign triage --state {state} --cgroup-root <dir> --from-run \
                     <finding> --step replay`, or set CAMPAIGN_CGROUP_ROOT in place of \
                     --cgroup-root; dispose with `campaign dispose --state {state} --finding \
                     <finding> --disposition <disposition> --evidence <path>`.",
                    group.unresolved,
                    group.findings.len(),
                    if runs.len() == 1 { "run" } else { "runs" },
                    list(&runs),
                ),
                group.findings.clone(),
            ))
        })
        .collect()
}

/// A job the held-record detector reports: a held outcome, a held attempt
/// history or pin, or an attempt row that is held, unnumbered, unnamed,
/// carries a held sim artifact, or whose own outcome is held.
fn held_job(job: &Job, outcome: &Outcome) -> bool {
    outcome.is_held()
        || job.attempts_held.is_some()
        || job.pin.as_ref().is_some_and(|pin| pin.held.is_some())
        || job.attempts.iter().any(|row| {
            row.held.is_some()
                || row.number.is_none_or(|number| number == 0)
                || row.attempt.is_none()
                || row.sim.as_ref().is_some_and(|sim| sim.held.is_some())
                || Outcome::of_attempt(row).is_held()
        })
}

fn held_records(context: &Context) -> Vec<Signal> {
    let snapshot = context.snapshot;
    let mut subjects = Vec::new();
    if snapshot.space.is_none() {
        subjects.push("space".to_owned());
    }
    if snapshot.config.as_ref().is_some_and(|config| {
        config.held.is_some() || snapshot.config_value("wall").is_none_or(|wall| wall == 0)
    }) {
        subjects.push("config.json".to_owned());
    }
    for probe in &snapshot.held_probes {
        subjects.push(format!("probes/{}", probe.entry));
    }
    for (job, outcome) in &context.outcomes {
        if held_job(job, outcome) {
            subjects.push(format!("jobs/{}", job.id));
        }
    }
    let mut described = subjects.clone();
    for finding in &snapshot.findings {
        let reason = match (&finding.held, &finding.verified) {
            (Some(reason), _) => reason.as_str(),
            (None, None) => "neither verified nor held",
            (None, Some(_)) if finding.profile().is_none() => "verified record lacks its profile",
            (None, Some(_))
                if finding
                    .kind()
                    .is_none_or(|kind| kind_domain(kind).is_none()) =>
            {
                "verified record lacks a known finding kind"
            }
            (None, Some(_)) => continue,
        };
        subjects.push(finding.id.clone());
        described.push(format!("{} ({reason})", finding.id));
    }
    let mut listed: BTreeSet<&str> = subjects.iter().map(String::as_str).collect();
    let mut members = Vec::new();
    for group in &snapshot.failure_groups {
        if kind_domain(&group.kind).is_some() {
            continue;
        }
        for member in &group.findings {
            if listed.insert(member) {
                members.push(member.clone());
                described.push(format!("{member} (failure group lacks a known kind)"));
            }
        }
    }
    subjects.extend(members);
    if subjects.is_empty() {
        return Vec::new();
    }
    vec![signal(
        Severity::Critical,
        Domain::Campaign,
        "held-record",
        format!(
            "{} record(s) fail the read rule or await capture",
            subjects.len()
        ),
        format!("Held rows carry no verified outcome: {}", list(&described)),
        subjects,
    )]
}

/// The `limit_hit` labels the producer writes.
const LIMITS: [&str; 8] = [
    "output-limit",
    "cpu-limit",
    "pid-limit",
    "oom",
    "mixed-limits",
    "watchdog",
    "file-size-limit",
    "stream-output-cap",
];

fn triage(context: &Context) -> Vec<Signal> {
    let mut signals = Vec::new();
    for finding in &context.snapshot.findings {
        if finding.verified.is_none() {
            continue;
        }
        let profile = finding.profile().unwrap_or("?");
        let state = finding.triage_state();
        if finding.resolved && state != "held" {
            continue;
        }
        let (severity, domain, title) = match state {
            "held" => (
                Severity::Critical,
                Domain::Campaign,
                format!("triage history held for {profile}"),
            ),
            "diverged" | "unreproduced" => (
                Severity::Critical,
                Domain::Simulator,
                format!("replay {state} for {profile}: the run is not deterministic"),
            ),
            "insufficient-evidence" => (
                Severity::Warning,
                Domain::Simulator,
                format!("triage lacks evidence for {profile}"),
            ),
            "stalled" => (
                Severity::Warning,
                Domain::Campaign,
                format!("triage stalled for {profile}"),
            ),
            _ => match finding.limit_hit() {
                Some(limit) if LIMITS.contains(&limit) => (
                    Severity::Warning,
                    Domain::Host,
                    format!("triage of {profile} hit {limit}"),
                ),
                _ => continue,
            },
        };
        signals.push(signal(
            severity,
            domain,
            "triage",
            title,
            format!("finding {}", finding.id),
            vec![finding.id.clone()],
        ));
    }
    signals
}

fn settled<'a>(context: &'a Context) -> impl Iterator<Item = &'a (&'a Job, Outcome)> {
    context
        .outcomes
        .iter()
        .filter(|(job, _)| job.state == JobState::Settled)
}

fn seed_sensitive(context: &Context) -> Vec<Signal> {
    type Workload<'a> = (&'a str, &'a str, &'a str, &'a str);
    let mut by_workload: BTreeMap<Workload, BTreeMap<&Outcome, BTreeSet<u64>>> = BTreeMap::new();
    for (job, outcome) in settled(context) {
        let Some(run) = job.run else {
            continue;
        };
        if outcome.admitted_stop().is_some()
            || outcome.is_held()
            || outcome.domain == Some(Domain::Chaos)
        {
            continue;
        }
        by_workload
            .entry((&job.campaign, &job.profile, &job.build, &job.variant))
            .or_default()
            .entry(outcome)
            .or_default()
            .insert(run);
    }
    let mut signals = Vec::new();
    for ((campaign, profile, build, variant), outcomes) in by_workload {
        if outcomes.len() < 2 {
            continue;
        }
        let domain = outcomes
            .keys()
            .filter_map(|outcome| outcome.domain)
            .min()
            .unwrap_or(Domain::Simulator);
        let severity = if domain == Domain::Service {
            Severity::Warning
        } else {
            Severity::Info
        };
        let detail = outcomes
            .iter()
            .map(|(outcome, runs)| format!("{} in runs {}", outcome.label, list(runs)))
            .collect::<Vec<_>>()
            .join("; ");
        signals.push(signal(
            severity,
            domain,
            "seed-sensitive",
            format!("{profile} changes outcome with the seed"),
            format!("campaign {campaign}, build {build}, variant {variant}: {detail}"),
            vec![serde_json::json!([campaign, profile, build, variant]).to_string()],
        ));
    }
    signals
}

fn undersized_counts(context: &Context) -> Vec<Signal> {
    let mut by_stop: BTreeMap<(&str, &Outcome), Vec<&str>> = BTreeMap::new();
    for (job, outcome) in settled_or_waiting(context) {
        if outcome.admitted_stop().is_some() {
            by_stop
                .entry((&job.profile, outcome))
                .or_default()
                .push(&job.id);
        }
    }
    by_stop
        .into_iter()
        .map(|((profile, outcome), jobs)| {
            let advice = match outcome.admitted_limit() {
                Some(limit) => format!("raise `{limit}` at admit"),
                None => "raise `records` and `bytes` together with `turns` at admit".to_owned(),
            };
            signal(
                Severity::Warning,
                Domain::Campaign,
                "undersized-counts",
                format!("{profile}: {} in {} job(s)", outcome.label, jobs.len()),
                format!(
                    "The admitted counts end the run before its verdict; {advice}. These jobs \
                     prove nothing about the service."
                ),
                jobs.into_iter().map(str::to_owned).collect(),
            )
        })
        .collect()
}

/// Dedicated detectors report findings minted on `job.outcome_attempt()`,
/// violations, held outcomes, and admitted stops. A finding covers the
/// attempt it names.
fn outcomes(context: &Context) -> Vec<Signal> {
    let mut groups: BTreeMap<(Domain, &Outcome), Vec<&Job>> = BTreeMap::new();
    for (job, outcome) in settled_or_waiting(context) {
        let Some(domain) = outcome.domain else {
            continue;
        };
        let found = job
            .outcome_attempt()
            .is_some_and(|row| row.finding.is_some() && row.finding == row.attempt);
        let covered = found
            || outcome.is_violation()
            || outcome.is_held()
            || outcome.admitted_stop().is_some();
        if !covered {
            groups.entry((domain, outcome)).or_default().push(job);
        }
    }
    groups
        .into_iter()
        .map(|((domain, outcome), jobs)| {
            let severity = match domain {
                Domain::Simulator if !outcome.is_inconclusive() => Severity::Critical,
                Domain::Campaign => Severity::Critical,
                Domain::Service | Domain::Host => Severity::Warning,
                Domain::Simulator | Domain::Chaos => Severity::Info,
            };
            let label = &outcome.label;
            let profiles: BTreeSet<&str> = jobs.iter().map(|job| job.profile.as_str()).collect();
            signal(
                severity,
                domain,
                "outcome",
                format!("{label} in {} job(s)", jobs.len()),
                format!("profiles {}", list(profiles)),
                jobs.iter().map(|job| job.id.clone()).collect(),
            )
        })
        .collect()
}

fn stuck_attempts(context: &Context) -> Vec<Signal> {
    let Some(wall) = context
        .snapshot
        .config_value("wall")
        .filter(|wall| *wall > 0)
    else {
        return Vec::new();
    };
    let limit_ms = wall.saturating_mul(1000).saturating_add(STUCK_GRACE_MS);
    let now = context.snapshot.observed_ms;
    context
        .outcomes
        .iter()
        .filter(|(job, outcome)| job.state == JobState::Running && !held_job(job, outcome))
        .filter_map(|(job, _)| {
            let row = job.attempts.last()?;
            let age = now.saturating_sub(row.started_ms.or(row.intent_ms)?);
            (age > limit_ms).then(|| {
                signal(
                    Severity::Critical,
                    Domain::Campaign,
                    "stuck-attempt",
                    format!("{} attempt running {}", job.profile, duration(age)),
                    format!(
                        "The configured wall limit is {wall} s; an attempt this far past it \
                         likely means the controller stopped or custody lost the attempt, \
                         unless a long kill wait or evidence publication is still draining. \
                         Check the controller process and the cgroup root."
                    ),
                    vec![row.attempt.clone().unwrap_or_else(|| job.id.clone())],
                )
            })
        })
        .collect()
}

fn idle_queue(context: &Context) -> Vec<Signal> {
    let jobs = &context.snapshot.jobs;
    let controller = context.snapshot.controller();
    if let Some(Controller::None { shared }) = controller {
        let unsettled = jobs
            .iter()
            .filter(|job| job.state.needs_controller())
            .count();
        if unsettled == 0 {
            return Vec::new();
        }
        let detail = if shared {
            "Only report snapshots hold the state directory's lock; start `campaign dispatch` \
             once they finish."
        } else {
            "No visible process holds the state directory's lock; start `campaign dispatch`."
        };
        return vec![signal(
            Severity::Warning,
            Domain::Campaign,
            "idle-queue",
            format!("{unsettled} unsettled job(s) and no visible controller runs"),
            detail.into(),
            Vec::new(),
        )];
    }
    let queued = jobs
        .iter()
        .filter(|job| job.state.awaits_controller())
        .count();
    if queued == 0 {
        return Vec::new();
    }
    let running = jobs.iter().any(|job| {
        job.state == JobState::Running
            && job
                .attempts
                .last()
                .is_some_and(|row| row.finished_ms.is_none())
    });
    if running {
        return Vec::new();
    }
    let last = jobs
        .iter()
        .flat_map(|job| job.attempts.iter())
        .filter_map(|row| row.finished_ms)
        .max();
    let now = context.snapshot.observed_ms;
    let idle = last.map(|last| now.saturating_sub(last));
    if idle.is_some_and(|idle| idle < IDLE_MS) {
        return Vec::new();
    }
    let since = idle.map_or("no attempt has finished".to_owned(), |idle| {
        format!("no attempt finished in {}", duration(idle))
    });
    let advice = if matches!(controller, Some(Controller::Running(_))) {
        "a controller holds the state directory, so check that it is making progress"
    } else {
        "check that a dispatch window is running"
    };
    vec![signal(
        Severity::Warning,
        Domain::Campaign,
        "idle-queue",
        format!("{queued} job(s) wait and nothing runs"),
        format!("{since}; {advice}."),
        Vec::new(),
    )]
}

fn space(context: &Context) -> Vec<Signal> {
    let snapshot = context.snapshot;
    let Some(space) = snapshot.space else {
        return Vec::new();
    };
    let free = space.free_bytes;
    if space.free_inodes == 0 {
        return vec![signal(
            Severity::Critical,
            Domain::Host,
            "space",
            "no free inodes on the state filesystem".to_owned(),
            "Dispatch pauses because no attempt can create its records. Collect retained \
             builds and probes."
                .to_owned(),
            Vec::new(),
        )];
    }
    if free < LOW_SPACE {
        return vec![signal(
            Severity::Critical,
            Domain::Host,
            "space",
            format!("{} free on the state filesystem", bytes(free)),
            format!(
                "Free space is under {}; dispatch pauses once it cannot reserve storage \
                 for the next attempts. Collect retained builds and probes.",
                bytes(LOW_SPACE)
            ),
            Vec::new(),
        )];
    }
    if context
        .history
        .last()
        .is_some_and(|sample| sample.observed_ms > snapshot.observed_ms)
    {
        return Vec::new();
    }
    let Some((elapsed, old_free)) = context.history.iter().rev().find_map(|sample| {
        let elapsed = snapshot.observed_ms.checked_sub(sample.observed_ms)?;
        (elapsed >= PROJECTION_WINDOW_MS).then_some((elapsed, sample.free_bytes?))
    }) else {
        return Vec::new();
    };
    let used = old_free.saturating_sub(free);
    if used == 0 {
        return Vec::new();
    }
    let left_ms = u128::from(free) * u128::from(elapsed) / u128::from(used);
    let Ok(left_ms) = u64::try_from(left_ms) else {
        return Vec::new();
    };
    if left_ms > FILL_HORIZON_MS {
        return Vec::new();
    }
    vec![signal(
        Severity::Warning,
        Domain::Host,
        "space",
        format!("state filesystem fills in about {}", duration(left_ms)),
        format!(
            "{} used in the last {}; {} free.",
            bytes(used),
            duration(elapsed),
            bytes(free)
        ),
        Vec::new(),
    )]
}

fn throttling(context: &Context) -> Vec<Signal> {
    let mut profiles = BTreeSet::new();
    let mut attempts = 0;
    for job in &context.snapshot.jobs {
        for row in &job.attempts {
            let Some(kernel) = row.finished.as_ref().map(|finish| &finish.kernel) else {
                continue;
            };
            let (Some(usage), Some(throttled)) = (kernel.cpu_usage_usec, kernel.cpu_throttled_usec)
            else {
                continue;
            };
            if usage > 0 && throttled > usage / THROTTLE_RATIO {
                attempts += 1;
                profiles.insert(job.profile.as_str());
            }
        }
    }
    if attempts == 0 {
        return Vec::new();
    }
    vec![signal(
        Severity::Info,
        Domain::Host,
        "throttling",
        format!(
            "{attempts} attempt(s) throttled for over 1/{THROTTLE_RATIO} of their CPU usage time"
        ),
        format!(
            "Each slot's cpu.max quota throttles a multi-threaded worker; profiles {}",
            list(&profiles)
        ),
        Vec::new(),
    )]
}

fn probes(context: &Context) -> Vec<Signal> {
    let probes = context.snapshot.probes;
    if probes < MANY_PROBES {
        return Vec::new();
    }
    vec![signal(
        Severity::Info,
        Domain::Campaign,
        "probes",
        format!("{probes} admission probe directories retained"),
        "Each admit leaves one probe directory under probes/.".to_owned(),
        Vec::new(),
    )]
}

pub fn duration(ms: u64) -> String {
    let seconds = ms / 1000;
    match seconds {
        0..60 => format!("{}.{}s", seconds, (ms % 1000) / 100),
        60..3600 => format!("{}m{:02}s", seconds / 60, seconds % 60),
        3600..86_400 => format!("{}h{:02}m", seconds / 3600, (seconds % 3600) / 60),
        _ => format!("{}d{:02}h", seconds / 86_400, (seconds % 86_400) / 3600),
    }
}

pub fn bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut scaled = value as f64;
    let mut unit = 0;
    while scaled >= 1024.0 && unit + 1 < UNITS.len() {
        scaled /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} B")
    } else {
        format!("{scaled:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
#[path = "signals_tests.rs"]
mod tests;
