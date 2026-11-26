//! Listing verifies retained snapshots and holds incomplete capture histories.
//! Dispositions append numbered decisions under the controller lock.

use super::{Error, name};
use crate::record::{
    Binding, Class, Decision, Digest, Disposition, Finding, FindingKind, Text, Verified,
};
use crate::store::{Dir, ReadStore, Store, View};
use std::collections::HashMap;
use std::path::Path;

pub(super) fn directory(view: &impl ReadStore, id: &str) -> Result<Dir, Error> {
    let root = view
        .open_dir(view.root(), &name("findings"))?
        .ok_or_else(|| Error::Rejected("no findings".into()))?;
    let entry =
        crate::store::Name::new(id).ok_or_else(|| Error::Rejected("invalid finding id".into()))?;
    view.open_dir(&root, &entry)?
        .ok_or_else(|| Error::Rejected("unknown finding".into()))
}

pub(super) fn history(
    view: &impl ReadStore,
    directory: &Dir,
    id: &str,
    finding: &Finding,
) -> Result<Vec<Verified<Disposition>>, Error> {
    numbered(view, directory, id, finding, |record| record)
}

/// Validates numbered dispositions, reducing each record before the next read.
fn numbered<T>(
    view: &impl ReadStore,
    directory: &Dir,
    id: &str,
    finding: &Finding,
    mut keep: impl FnMut(Verified<Disposition>) -> T,
) -> Result<Vec<T>, Error> {
    let dependencies =
        crate::attempt::dependencies(finding).map_err(|error| Error::Held(error.to_string()))?;
    let mut entries = Vec::new();
    for entry in view
        .list(directory, crate::scan_bound())
        .map_err(|error| Error::listing(&format!("findings/{id}"), error))?
    {
        if let Some(number) = entry.as_str().strip_suffix(".disposition.json") {
            let number = number
                .parse::<u64>()
                .map_err(|_| Error::Held("invalid disposition number".into()))?;
            if number == 0 || entry.as_str() != format!("{number:04}.disposition.json") {
                return Err(Error::Held("noncanonical disposition number".into()));
            }
            let record = view
                .read_record::<Disposition>(directory, &entry)?
                .ok_or_else(|| Error::Held("disposition vanished".into()))?;
            if record.record().finding().as_str() != id || record.record().number() != number {
                return Err(Error::Held("disposition binding differs".into()));
            }
            entries.push((number, keep(record)));
        } else if entry.as_str() != "finding.json"
            && !dependencies.iter().any(|(name, _, _)| name == &entry)
        {
            return Err(Error::Held("unknown finding entry".into()));
        }
    }
    entries.sort_by_key(|(number, _)| *number);
    if entries
        .iter()
        .enumerate()
        .any(|(index, (number, _))| *number != index as u64 + 1)
    {
        return Err(Error::Held("disposition history has gaps".into()));
    }
    Ok(entries.into_iter().map(|(_, kept)| kept).collect())
}

/// Whether a retained finding's latest validated disposition is resolved.
/// Missing directories or dispositions count as unresolved. Damaged finding
/// identity, lineage, dependencies or history holds; read errors propagate.
pub(in crate::campaign) fn resolved(
    view: &impl ReadStore,
    root: Option<&Dir>,
    id: &str,
) -> Result<bool, Error> {
    let Some(root) = root else {
        return Ok(false);
    };
    let entry =
        crate::store::Name::new(id).ok_or_else(|| Error::Held("invalid finding id".into()))?;
    let Some(directory) = view.open_dir(root, &entry)? else {
        return Ok(false);
    };
    let finding = load(view, &directory, id)?;
    Ok(latest(view, &directory, id, finding.record())? == Some(Decision::Resolved))
}

/// The latest validated disposition, read with a constant descriptor budget.
pub(super) fn latest(
    view: &impl ReadStore,
    directory: &Dir,
    id: &str,
    finding: &Finding,
) -> Result<Option<Decision>, Error> {
    Ok(numbered(view, directory, id, finding, |entry| {
        entry.record().decision()
    })?
    .pop())
}

pub(super) fn load(
    view: &impl ReadStore,
    directory: &Dir,
    id: &str,
) -> Result<Verified<Finding>, Error> {
    load_among(view, directory, id, &super::lineage::Parents::default())
}

/// Loads one finding of a listing or selection that shares `parents` across
/// its findings.
pub(super) fn load_among(
    view: &impl ReadStore,
    directory: &Dir,
    id: &str,
    parents: &super::lineage::Parents,
) -> Result<Verified<Finding>, Error> {
    let record = view
        .read_record::<Finding>(directory, &name("finding.json"))?
        .ok_or_else(|| Error::Held("finding record missing".into()))?;
    validate(record.record(), id)?;
    super::lineage::verify(view, record.record(), parents)?;
    for (entry, expected, bound) in crate::attempt::dependencies(record.record())
        .map_err(|error| Error::Held(error.to_string()))?
    {
        let digest = view
            .evidence_digest(directory, &entry, bound)?
            .ok_or_else(|| Error::Held("finding dependency missing".into()))?;
        if digest != expected {
            return Err(Error::Held("finding dependency differs".into()));
        }
    }
    Ok(record)
}

pub(super) fn validate(finding: &Finding, id: &str) -> Result<(), Error> {
    let job = finding.admission.job();
    let parent = finding
        .parent_attempt
        .as_ref()
        .map_or(id, |parent| parent.as_str());
    if (finding.child.is_some() || finding.parent_attempt.is_some())
        && (finding.id().as_str() != id
            || finding
                .child
                .as_ref()
                .is_some_and(|child| child.kind != finding.kind)
            || finding.parent_attempt.is_some() && finding.child.is_none())
    {
        return Err(Error::Held("child finding identity differs".into()));
    }
    let calibration = finding.admission.purpose() == crate::record::Purpose::Calibration;
    let replay = calibration
        && finding.calibration_root == Some(job.id().digest())
        && (1..=2).contains(&finding.attempt.number)
        && id
            == format!(
                "{}-calibration-replay-{:04}",
                job.id(),
                finding.attempt.number
            );
    if finding.calibration_root.is_some() && !calibration
        || finding.attempt.attempt.as_str() != parent
        || !replay && parent != format!("{}-{:04}", job.id(), finding.attempt.number)
        || finding.attempt.number == 0
        || finding.attempt.number > job.experiment().attempts
        || finding.attempt.job != job.id().digest()
        || finding.attempt.manifest != job.manifest_sha256()
        || finding.finished.attempt.as_str() != parent
    {
        return Err(Error::Held("finding binding differs".into()));
    }
    let command = if replay {
        "replay"
    } else {
        finding.admission.command()
    };
    let matching = match &finding.artifact {
        Some(artifact) => {
            artifact.run_id.as_str() == parent
                && artifact.command.as_str() == command
                && artifact.manifest == Some(job.manifest_sha256())
                && artifact.archive.is_some()
                && artifact.archive == Digest::parse(job.experiment().pins.build.as_str())
                && finding.finished.binding == Binding::Matching
                && finding.finished.bound.as_ref().is_some_and(|bound| {
                    bound.attempt.as_str() == parent && bound.bundle == artifact.bundle
                })
        }
        None => {
            finding.kind == FindingKind::Watchdog
                && finding.finished.class == Class::Watchdog
                && finding.finished.binding == Binding::Missing
                && finding.finished.bound.is_none()
        }
    };
    if !matching {
        return Err(Error::Held("finding artifact binding differs".into()));
    }
    Ok(())
}

pub(super) fn artifact_record(
    view: &impl ReadStore,
    attempt: &Dir,
    id: &str,
    what: &str,
) -> Result<Verified<crate::record::Artifact>, Error> {
    let artifacts = view
        .open_dir(attempt, &name("artifacts"))?
        .ok_or_else(|| Error::Held(format!("{what} artifacts missing")))?;
    let directory = view
        .open_dir(&artifacts, &name(id))?
        .ok_or_else(|| Error::Held(format!("{what} artifact missing")))?;
    view.read_record::<crate::record::Artifact>(&directory, &name("artifact"))?
        .ok_or_else(|| Error::Held(format!("{what} artifact record missing")))
}

pub(in crate::campaign) fn verify_stop_witnesses(
    view: &impl ReadStore,
    directory: &Dir,
    step: &crate::record::TriageStep,
    result: &crate::record::TriageResult,
) -> Result<(), Error> {
    let (output_limited, file_limited) = match &result.finished.bound {
        None => (false, false),
        Some(bound) => {
            let artifact = artifact_record(view, directory, step.attempt.attempt.as_str(), "step")?;
            if Digest::of(artifact.read().bytes()) != bound.artifact
                || bound.attempt != step.attempt.attempt
            {
                return Err(Error::Held("step stop witness binding differs".into()));
            }
            (
                artifact
                    .record()
                    .workers
                    .values()
                    .any(|worker| worker.ended.as_str() == "oversized"),
                artifact
                    .record()
                    .workers
                    .values()
                    .any(|worker| worker.signal == Some(crate::sys::OUTPUT_SIGNAL as u64)),
            )
        }
    };
    if output_limited != result.output_limited || file_limited != result.file_limited {
        return Err(Error::Held(
            "step stop witnesses differ from evidence".into(),
        ));
    }
    Ok(())
}

/// A finding whose newest minted step lacks a result reports `pending`.
fn triage_state(
    view: &impl ReadStore,
    id: &str,
    finding: &Finding,
) -> Result<serde_json::Value, Error> {
    let Some(root) = view.open_dir(view.root(), &name("triage"))? else {
        return Ok(serde_json::Value::Null);
    };
    let Some(history) = view.open_dir(&root, &name(id))? else {
        return Ok(serde_json::Value::Null);
    };
    let Some(steps) = view.open_dir(&history, &name("steps"))? else {
        return Ok(serde_json::Value::Null);
    };
    let mut numbers = Vec::new();
    for entry in super::triage::step_entries(view, &steps, id)? {
        let number = entry
            .as_str()
            .parse::<u64>()
            .map_err(|_| Error::Held("invalid triage step number".into()))?;
        if number == 0 || entry.as_str() != format!("{number:04}") {
            return Err(Error::Held("noncanonical triage step number".into()));
        }
        view.open_dir(&steps, &entry)?
            .ok_or_else(|| Error::Held("triage step directory missing".into()))?;
        numbers.push(number);
    }
    numbers.sort_unstable();
    if numbers
        .iter()
        .enumerate()
        .any(|(index, number)| *number != index as u64 + 1)
    {
        return Err(Error::Held("triage step history has gaps".into()));
    }
    let mut records = Vec::new();
    for number in &numbers {
        let directory = view
            .open_dir(&steps, &name(&format!("{number:04}")))?
            .ok_or_else(|| Error::Held("triage step vanished".into()))?;
        let step = view
            .read_record::<crate::record::TriageStep>(&directory, &name("step"))?
            .ok_or_else(|| Error::Held("minted triage step lacks record".into()))?;
        super::triage::bound_step(step.record(), finding, *number)?;
        let Some(result) =
            view.read_record::<crate::record::TriageResult>(&directory, &name("result"))?
        else {
            if Some(number) == numbers.last() {
                return Ok(serde_json::json!({"state": "pending"}));
            }
            return Err(Error::Held("step result missing".into()));
        };
        let finished = view
            .read_record::<crate::record::Finished>(&directory, &name("finished"))?
            .ok_or_else(|| Error::Held("step finish missing".into()))?;
        if result.record().finding.as_str() != id
            || result.record().number != *number
            || result.record().finished != *finished.record()
            || finished.record().attempt != step.record().attempt.attempt
        {
            return Err(Error::Held("triage status binding differs".into()));
        }
        verify_stop_witnesses(view, &directory, step.record(), result.record())?;
        records.push((step.record().clone(), result.record().clone()));
    }
    let Some((step, result)) = records.last() else {
        return Ok(serde_json::json!({"state": "pending"}));
    };
    if super::triage::facts_settled(finding, &records) {
        return Ok(
            serde_json::json!({"state": "waiting", "reason": "stored replay digest or terminal is absent", "latest": result}),
        );
    }
    let config = view
        .read_record::<crate::record::Configuration>(view.root(), &name("config.json"))?
        .ok_or_else(|| Error::Held("triage configuration missing".into()))?;
    Ok(serde_json::json!({"latest": result, "limits": step.limits,
        "output_limited": result.output_limited,
        "file_limited": result.file_limited,
        "stream_output_bytes": result.output_limited.then_some(crate::sim::OUTPUT),
        "limit_hit": match result.finished.class {
            Class::OutputLimit | Class::CpuLimit | Class::PidLimit | Class::Oom | Class::MixedLimits | Class::Watchdog => Some(result.finished.class.name()),
            _ if result.file_limited => Some("file-size-limit"),
            _ if result.output_limited => Some("stream-output-cap"),
            _ => None,
        },
        "stalled": super::triage::stalled_for(finding, &records, config.record(), step.kind),
        "stall_reason": super::triage::targeted_stall_reason(finding, &records, config.record(), step.kind)}))
}

pub(super) struct FindingRow {
    pub data: serde_json::Value,
    pub job: Digest,
    pub attempt: u64,
    pub invalidates: bool,
    pub ordinary_attempt: bool,
    pub targeted: bool,
    pub finished: crate::record::Finished,
    pub blocker: bool,
    pub resolved: bool,
    pub triage_code: Option<&'static str>,
    pub finding: Finding,
}

pub(super) fn row(
    view: &impl ReadStore,
    root: &Dir,
    entry: &crate::store::Name,
    parents: &super::lineage::Parents,
) -> Result<FindingRow, Error> {
    let id = entry.as_str();
    let directory = view
        .open_dir(root, entry)?
        .ok_or_else(|| Error::Held("finding directory vanished".into()))?;
    let finding = load_among(view, &directory, id, parents)?;
    let entries = history(view, &directory, id, finding.record())?;
    view.barrier(finding.read())?;
    for entry in &entries {
        view.barrier(entry.read())?;
    }
    let resolved = entries
        .last()
        .is_some_and(|entry| entry.record().decision() == Decision::Resolved);
    let blocker = !resolved
        && (finding.record().kind.release_blocker()
            || entries
                .iter()
                .any(|entry| entry.record().decision() == Decision::ReleaseBlocker));
    let triage = if let Some(reason) = finding.record().bundle_wait_reason() {
        (
            serde_json::json!({"state": "waiting", "reason": reason}),
            None,
        )
    } else {
        match triage_state(view, id, finding.record()) {
            Ok(triage) => (triage, None),
            Err(error) if error.at_scan_bound() || error.host_fault() => return Err(error),
            Err(error) => (
                serde_json::json!({"held": error.to_string()}),
                Some(error.held_code()),
            ),
        }
    };
    Ok(FindingRow {
        data: serde_json::json!({"id": id, "verified": finding.record(), "dispositions": entries.iter().map(|entry| entry.record()).collect::<Vec<_>>(), "resolved": resolved, "blocker": blocker, "triage": triage.0}),
        job: finding.record().attempt.job,
        attempt: finding.record().attempt.number,
        finished: finding.record().finished.clone(),
        targeted: finding.record().admission.target().is_some(),
        ordinary_attempt: finding.record().attempt.attempt.as_str()
            == format!(
                "{}-{:04}",
                finding.record().attempt.job,
                finding.record().attempt.number
            ),
        invalidates: finding.record().kind == FindingKind::Harness
            || entries
                .iter()
                .any(|entry| entry.record().decision() == Decision::Harness),
        blocker,
        resolved,
        triage_code: triage.1,
        finding: finding.into_record(),
    })
}

/// Lists verified findings and held release blockers through a read-only view.
pub fn findings(path: &Path) -> Result<serde_json::Value, Error> {
    let view = View::open(path)?;
    view.require_state_marker()?;
    let listed = listing(&view, Known::default())?;
    if !view.current().map_err(crate::store::Error::Io)? {
        return Err(Error::Held("state moved during findings".into()));
    }
    let mut output = serde_json::Map::new();
    output.insert("findings".into(), listed.findings.into());
    output.insert(
        "release_blockers".into(),
        listed
            .release_blockers
            .into_iter()
            .map(serde_json::Value::String)
            .collect(),
    );
    Ok(output.into())
}

/// The `findings` listing of a state directory: its rows, the ids of its
/// release blockers, and the verified finding of each row that has one.
pub(super) struct Listing {
    pub(super) findings: Vec<serde_json::Value>,
    pub(super) release_blockers: Vec<String>,
    pub(super) retained: Vec<Retained>,
}

/// One verified finding of a [`Listing`], in listing order.
pub(super) struct Retained {
    /// The index of the finding's row in [`Listing::findings`].
    pub(super) row: usize,
    pub(super) id: String,
    pub(super) finding: Finding,
    pub(super) resolved: bool,
    pub(super) triage_code: Option<&'static str>,
}

/// The settled finish of one settlement entry: its class and the attempt
/// it names, `None` for an absent record, or the read or binding error.
pub(super) type Settled = Result<Option<(Class, String)>, Error>;

/// What a caller already read of the state directory the capture scan of
/// [`listing`] would read again: the listings of `jobs/` and `attempts/`,
/// the settled finish of `jobs/` entries by name, the listing of attempt
/// histories by job, and the capture state of attempts by identity, each
/// from a directory the caller opened. The scan takes each entry in place
/// of its own read, so the listing agrees with the caller's reads; it
/// reads every entry the caller left out.
#[derive(Default)]
pub(super) struct Known {
    pub(super) jobs: Option<Vec<crate::store::Name>>,
    pub(super) attempt_histories: Option<Vec<crate::store::Name>>,
    /// Paths the caller holds outside its listings; each is a held blocker row.
    pub(super) held: Vec<(String, Error)>,
    pub(super) settlements: HashMap<String, Settled>,
    pub(super) histories: HashMap<String, Vec<crate::store::Name>>,
    pub(super) attempts: HashMap<String, Result<bool, Error>>,
}

/// The entries one job contributes to [`Known`], in read order.
#[derive(Default)]
pub(super) struct Reads {
    pub(super) settlements: Vec<(String, Settled)>,
    pub(super) histories: Vec<(String, Vec<crate::store::Name>)>,
    pub(super) attempts: Vec<(String, Result<bool, Error>)>,
}

impl Known {
    /// Adds `reads`, which name other entries than `self` holds.
    pub(super) fn join(&mut self, reads: Reads) {
        self.settlements.extend(reads.settlements);
        self.histories.extend(reads.histories);
        self.attempts.extend(reads.attempts);
    }
}

/// The listing of `view`'s state directory, with `known` in place of the
/// capture scan's own reads of those entries. Check [`View::current`]
/// after the last read through `view`; [`findings`] does so for a listing
/// alone.
///
/// # Errors
///
/// Returns a host fault from reading a finding, and any error from opening
/// or listing `findings/` or from `uncaptured`.
pub(super) fn listing(view: &View, known: Known) -> Result<Listing, Error> {
    let mut rows = Vec::new();
    let mut captured = std::collections::BTreeSet::new();
    let mut blockers = Vec::new();
    let mut retained = Vec::new();
    if let Some(root) = view.open_dir(view.root(), &name("findings"))? {
        let entries: Vec<_> = view
            .list(&root, crate::scan_bound())
            .map_err(|error| Error::listing("findings", error))?
            .into_iter()
            .enumerate()
            .collect();
        let parents = super::lineage::Parents::default();
        let read = super::threads::read_all(&entries, |(index, entry)| {
            match row(view, &root, entry, &parents) {
                Ok(row) => Ok((
                    row.data,
                    row.blocker,
                    Some(Retained {
                        row: *index,
                        id: entry.as_str().to_owned(),
                        finding: row.finding,
                        resolved: row.resolved,
                        triage_code: row.triage_code,
                    }),
                )),
                Err(error) if error.at_scan_bound() || error.host_fault() => Err(error),
                Err(error) => Ok((
                    serde_json::json!({"id": entry.as_str(), "held": error.to_string(), "held_code": error.held_code(), "blocker": true}),
                    true,
                    None,
                )),
            }
        })?;
        for ((_, entry), (row, blocker, verified)) in entries.iter().zip(read) {
            let id = entry.as_str();
            captured.insert(id.to_owned());
            retained.extend(verified);
            if blocker {
                blockers.push(id.to_owned());
            }
            rows.push(row);
        }
    }
    uncaptured(view, known, &captured, &mut rows, &mut blockers)?;
    if let Err(error) = super::corpus::Catalog::load(view) {
        if error.host_fault() || error.at_scan_bound() {
            return Err(error);
        }
        rows.push(serde_json::json!({"id": "corpus", "held": error.to_string(), "held_code": error.held_code(), "blocker": true}));
        blockers.push("corpus".into());
    }
    Ok(Listing {
        findings: rows,
        release_blockers: blockers,
        retained,
    })
}

/// The number of attempt directory `entry`, which must be a nonzero
/// decimal number with at least four digits and no other leading zeros.
pub(super) fn attempt_number(entry: &crate::store::Name) -> Result<u64, Error> {
    let number = entry
        .as_str()
        .parse::<u64>()
        .map_err(|_| Error::Held("invalid attempt name".into()))?;
    if number == 0 || entry.as_str() != format!("{number:04}") {
        return Err(Error::Held("noncanonical attempt name".into()));
    }
    Ok(number)
}

/// Appends evidence while holding two descriptors per history entry.
/// Descriptor exhaustion returns a named limit error and preserves history.
pub fn dispose(
    path: &Path,
    id: Text,
    decision: Decision,
    evidence: Text,
) -> Result<serde_json::Value, Error> {
    Disposition::new(id.clone(), 1, decision, evidence.clone())
        .map_err(|error| Error::Rejected(error.into()))?;
    crate::sys::controller_file_limit().map_err(crate::store::Error::Io)?;
    crate::store::given_ancestors(path).map_err(Error::input_path)?;
    let view = View::open(path)?;
    view.require_state_marker()?;
    let store = Store::open(path)?;
    store.check_path()?;
    append(&store, &view, id, decision, evidence)
}

pub(super) fn append(
    store: &Store,
    view: &View,
    id: Text,
    decision: Decision,
    evidence: Text,
) -> Result<serde_json::Value, Error> {
    if view.root().identity() != store.root().identity() {
        return Err(Error::Held("state changed before disposition".into()));
    }
    let directory = directory(store, id.as_str())?;
    let finding = load(store, &directory, id.as_str())?;
    let entries = history(store, &directory, id.as_str(), finding.record())?;
    store.barrier(finding.read())?;
    for entry in &entries {
        store.barrier(entry.read())?;
    }
    let root = format!("findings/{}", id.as_str());
    let listed = view.list(&directory, crate::scan_bound())?.len();
    if listed >= crate::scan_bound() {
        return Err(Error::bound(&root, listed));
    }
    let number = entries.len() as u64 + 1;
    drop(entries);
    drop(finding);
    let record = Disposition::new(id, number, decision, evidence)
        .map_err(|error| Error::Rejected(error.into()))?;
    let entry = name(&format!("{:04}.disposition.json", record.number()));
    store.create_record(&directory, &entry, &record)?;
    let found = store
        .read_record::<Disposition>(&directory, &entry)?
        .ok_or_else(|| Error::Held("disposition vanished".into()))?;
    if found.record() != &record {
        return Err(Error::Held("disposition publication differs".into()));
    }
    store.barrier(found.read())?;
    Ok(serde_json::json!({"disposition": found.record()}))
}

pub(super) fn uncaptured(
    view: &View,
    mut known: Known,
    captured: &std::collections::BTreeSet<String>,
    rows: &mut Vec<serde_json::Value>,
    blockers: &mut Vec<String>,
) -> Result<(), Error> {
    let mut seen = captured.clone();
    for (path, error) in std::mem::take(&mut known.held) {
        pending_row(rows, blockers, &mut seen, path, Some(error))?;
    }
    let entries = match known.jobs.take() {
        Some(listing) => listing,
        None => sharded_entries(view, crate::layout::JOBS)?,
    };
    {
        for entry in entries {
            let Some(id) = super::admission::job_id(entry.as_str()) else {
                continue;
            };
            let settled = known.settlements.remove(entry.as_str()).unwrap_or_else(|| {
                let jobs = crate::layout::jobs(view, id)?
                    .ok_or_else(|| Error::Held("job shard vanished".into()))?;
                settled_finish(view, &jobs, &entry)
            });
            match settled {
                Ok(Some((Class::Violation | Class::EngineFailure, attempt))) => {
                    pending_row(rows, blockers, &mut seen, attempt, None)?
                }
                Ok(_) => {}
                Err(error) => pending_row(
                    rows,
                    blockers,
                    &mut seen,
                    crate::layout::job_file(id, entry.as_str())
                        .display()
                        .to_string(),
                    Some(error),
                )?,
            }
        }
    }
    {
        let histories = match known.attempt_histories.take() {
            Some(listing) => listing,
            None => sharded_entries(view, crate::layout::ATTEMPTS)?,
        };
        for job in histories {
            let listed = match known.histories.remove(job.as_str()) {
                Some(attempts) => Ok((None, attempts)),
                None => match crate::layout::attempts(view, job.as_str()).map_err(Error::from) {
                    Ok(Some(directory)) => view
                        .list(&directory, crate::scan_bound())
                        .map_err(|error| Error::listing("attempt history", error))
                        .map(|attempts| (Some(directory), attempts)),
                    Ok(None) => Err(Error::Held("attempt history vanished".into())),
                    Err(error) => Err(error),
                },
            };
            let (mut directory, attempts) = match listed {
                Ok(listed) => listed,
                Err(error) if error.at_scan_bound() => return Err(error),
                Err(error) => {
                    pending_row(
                        rows,
                        blockers,
                        &mut seen,
                        format!(
                            "attempts/{}/{}",
                            crate::layout::shard(job.as_str()).as_str(),
                            job.as_str()
                        ),
                        Some(error),
                    )?;
                    continue;
                }
            };
            for attempt in attempts {
                let id = format!("{}-{}", job.as_str(), attempt.as_str());
                let result = (|| -> Result<bool, Error> {
                    if Digest::parse(job.as_str()).is_none() {
                        return Err(Error::Held("invalid job identity filename".into()));
                    }
                    attempt_number(&attempt)?;
                    if let Some(state) = known.attempts.remove(&id)
                        && !captured.contains(&id)
                    {
                        return state;
                    }
                    let history = match &mut directory {
                        Some(history) => history,
                        None => directory.insert(
                            crate::layout::attempts(view, job.as_str())?
                                .ok_or_else(|| Error::Held("attempt history vanished".into()))?,
                        ),
                    };
                    let directory = view
                        .open_dir(history, &attempt)?
                        .ok_or_else(|| Error::Held("attempt directory vanished".into()))?;
                    if captured.contains(&id) {
                        let retained = view
                            .open_dir(view.root(), &name("findings"))?
                            .and_then(|root| view.open_dir(&root, &name(&id)).transpose())
                            .transpose()?;
                        let retained = match retained {
                            Some(retained) => {
                                view.read_record::<Finding>(&retained, &name("finding.json"))
                            }
                            None => return Ok(false),
                        };
                        match retained.map_err(Error::from) {
                            Ok(Some(record)) if record.record().admission.target().is_some() => {}
                            Err(error) if error.host_fault() => return Err(error),
                            _ => return Ok(false),
                        }
                    }
                    let mut finished =
                        view.read_record::<crate::record::Finished>(&directory, &name("finished"))?;
                    let marker =
                        view.read_record::<crate::record::Captured>(&directory, &name("captured"))?;
                    if marker.is_some() && finished.is_none() {
                        finished = view.read_record::<crate::record::Finished>(
                            &directory,
                            &name("finished"),
                        )?;
                    }
                    let jobs = crate::layout::jobs(view, job.as_str())?
                        .ok_or_else(|| Error::Held("finding admission missing".into()))?;
                    let admission = view
                        .read_record::<crate::record::Admission>(
                            &jobs,
                            &name(&format!("{}.json", job.as_str())),
                        )?
                        .ok_or_else(|| Error::Held("finding admission missing".into()))?;
                    let targeted = admission.record().target().is_some();
                    let needs = capture_state(&id, finished.as_ref(), marker.as_ref(), targeted)?;
                    let Some(finished) = finished else {
                        return Ok(false);
                    };
                    let pending = marker.as_ref().is_none();
                    if captured.contains(&id) {
                        if pending {
                            return Err(Error::Held(
                                "finding capture marker missing or mismatched".into(),
                            ));
                        }
                        if admission.record().target().is_some() {
                            let attempt = view
                                .read_record::<crate::record::Attempt>(
                                    &directory,
                                    &name("attempt"),
                                )?
                                .ok_or_else(|| Error::Held("finding attempt missing".into()))?;
                            let done = crate::attempt::read_completed(
                                view,
                                &directory,
                                attempt.record(),
                                admission.record().command(),
                            )?;
                            if done.bound().and_then(|bound| bound.targeted()).is_some_and(
                                |judged| {
                                    judged.children.iter().any(|child| {
                                        !captured.contains(
                                            child.finding_id(&finished.record().attempt).as_str(),
                                        )
                                    })
                                },
                            ) {
                                return Err(Error::Held("finding child capture missing".into()));
                            }
                        }
                        return Ok(false);
                    }
                    Ok(needs)
                })();
                match result {
                    Ok(true) => pending_row(rows, blockers, &mut seen, id, None)?,
                    Ok(false) => {}
                    Err(error) => pending_row(rows, blockers, &mut seen, id, Some(error))?,
                }
            }
        }
    }
    if let Some(calibrations) = view.open_dir(view.root(), &name("calibrations"))? {
        for root_name in view
            .list(&calibrations, crate::scan_bound())
            .map_err(|error| Error::listing("calibrations", error))?
        {
            let opened = (|| -> Result<Option<Dir>, Error> {
                let root = view
                    .open_dir(&calibrations, &root_name)?
                    .ok_or_else(|| Error::Held("calibration root vanished".into()))?;
                Ok(view.open_dir(&root, &name("replays"))?)
            })();
            let replays = match opened {
                Ok(Some(replays)) => replays,
                Ok(None) => continue,
                Err(error) => {
                    pending_row(
                        rows,
                        blockers,
                        &mut seen,
                        format!("calibrations/{}", root_name.as_str()),
                        Some(error),
                    )?;
                    continue;
                }
            };
            for entry in view
                .list(&replays, crate::scan_bound())
                .map_err(|error| Error::listing("calibration replays", error))?
            {
                let id = format!(
                    "{}-calibration-replay-{}",
                    root_name.as_str(),
                    entry.as_str()
                );
                if captured.contains(&id) {
                    continue;
                }
                let pending = (|| -> Result<bool, Error> {
                    let directory = view
                        .open_dir(&replays, &entry)?
                        .ok_or_else(|| Error::Held("calibration replay vanished".into()))?;
                    let mut finished =
                        view.read_record::<crate::record::Finished>(&directory, &name("finished"))?;
                    let marker =
                        view.read_record::<crate::record::Captured>(&directory, &name("captured"))?;
                    if marker.is_some() && finished.is_none() {
                        finished = view.read_record::<crate::record::Finished>(
                            &directory,
                            &name("finished"),
                        )?;
                    }
                    if finished
                        .as_ref()
                        .is_some_and(|finished| finished.record().attempt.as_str() != id)
                    {
                        return Err(Error::Held("calibration replay finish differs".into()));
                    }
                    capture_state(&id, finished.as_ref(), marker.as_ref(), false)
                })();
                match pending {
                    Ok(true) => pending_row(rows, blockers, &mut seen, id, None)?,
                    Ok(false) => {}
                    Err(error) => pending_row(rows, blockers, &mut seen, id, Some(error))?,
                }
            }
        }
    }
    Ok(())
}

/// Whether attempt `id`, with its finish and capture marker as read, holds
/// an outcome that awaits a retained finding: a violation or engine
/// failure, a marker that names a finding, or, with no marker, a watchdog
/// finish or a matching-binding finish of a class other than `Pass` or
/// `Unsuccessful`.
///
/// # Errors
///
/// [`Error::Held`] for a marker without a finish, a finish or bound
/// evidence naming another attempt, a finish binding that differs from its
/// evidence, or a marker that differs from the finish.
pub(super) fn capture_state(
    id: &str,
    finished: Option<&Verified<crate::record::Finished>>,
    marker: Option<&Verified<crate::record::Captured>>,
    targeted: bool,
) -> Result<bool, Error> {
    let Some(finished) = finished else {
        if marker.is_some() {
            return Err(Error::Held("capture marker without a finish".into()));
        }
        return Ok(false);
    };
    let finish = finished.record();
    if finish.attempt.as_str() != id
        || finish
            .bound
            .as_ref()
            .is_some_and(|bound| bound.attempt.as_str() != id)
    {
        return Err(Error::Held("attempt record names another attempt".into()));
    }
    if (finish.binding == Binding::Matching) != finish.bound.is_some() {
        return Err(Error::Held(
            "finish binding differs from its evidence".into(),
        ));
    }
    if marker.is_some_and(|marker| !marker.record().matches(finished)) {
        return Err(Error::Held("capture marker differs from the finish".into()));
    }
    let pending = marker.is_none();
    Ok(
        matches!(finish.class, Class::Violation | Class::EngineFailure)
            || marker.is_some_and(|marker| marker.record().finding.is_some())
            || (pending
                && (finish.class == Class::Watchdog
                    || (finish.binding == Binding::Matching
                        && finish.class != Class::Pass
                        && (targeted || finish.class != Class::Unsuccessful)))),
    )
}

fn settled_finish(view: &View, jobs: &Dir, entry: &crate::store::Name) -> Settled {
    let value = entry.as_str();
    if let Some(id) = value.strip_suffix(crate::record::Pin::SUFFIX) {
        let Some(pin) = view.read_record::<crate::record::Pin>(jobs, entry)? else {
            return Ok(None);
        };
        return bound_finish(id, &pin.record().result).map(Some);
    }
    if let Some(id) = value.strip_suffix(crate::record::JobResult::SUFFIX) {
        let Some(result) = view.read_record::<crate::record::JobResult>(jobs, entry)? else {
            return Ok(None);
        };
        return bound_finish(id, result.record()).map(Some);
    }
    if let Some(id) = value
        .strip_suffix(".json")
        .filter(|id| Digest::parse(id).is_some())
    {
        super::show::verified_job(view, jobs, id)?;
    }
    Ok(None)
}

pub(in crate::campaign) fn bound_finish(
    id: &str,
    result: &crate::record::JobResult,
) -> Result<(Class, String), Error> {
    let expected = format!("{id}-{:04}", result.attempt);
    let finished = &result.finished;
    if Digest::parse(id) != Some(result.job)
        || result.attempt == 0
        || (finished.binding == Binding::Matching) != finished.bound.is_some()
        || finished.attempt.as_str() != expected
        || finished
            .bound
            .as_ref()
            .is_some_and(|bound| bound.attempt.as_str() != expected)
    {
        return Err(Error::Held("settlement binding differs".into()));
    }
    Ok((finished.class, expected))
}

fn pending_row(
    rows: &mut Vec<serde_json::Value>,
    blockers: &mut Vec<String>,
    seen: &mut std::collections::BTreeSet<String>,
    id: String,
    error: Option<Error>,
) -> Result<(), Error> {
    let error = match error {
        Some(error) if error.host_fault() => return Err(error),
        error => error,
    };
    if seen.contains(&id) {
        if let Some(error) = error {
            let row = serde_json::json!({"id": id, "held": error.to_string(), "held_code": error.held_code(), "blocker": true});
            if let Some(existing) = rows
                .iter_mut()
                .find(|row| row["id"] == id && row.get("held").is_some())
            {
                *existing = row;
            } else {
                rows.push(row);
            }
            if !blockers.contains(&id) {
                blockers.push(id);
            }
        }
        return Ok(());
    }
    if seen.insert(id.clone()) {
        let (reason, code) = error.as_ref().map_or(
            (
                "authoritative outcome awaits capture".into(),
                "capture-missing",
            ),
            |error| (error.to_string(), error.held_code()),
        );
        rows.push(
            serde_json::json!({"id": id, "held": reason, "held_code": code, "blocker": true}),
        );
        blockers.push(id);
    }
    Ok(())
}

/// The entries of every shard of `root`, each shard's listing held at the
/// scan bound on its own.
///
/// # Errors
///
/// [`crate::store::Error::Foreign`] for an entry outside its job's shard,
/// and the listing's error.
fn sharded_entries(view: &View, root: &str) -> Result<Vec<crate::store::Name>, Error> {
    let mut entries = Vec::new();
    for shard in crate::campaign::sharded(view, root)? {
        let shard = shard?;
        let listed = super::shard_entries(view, &shard)?;
        if let Some(entry) = listed.iter().find(|entry| !placed(&shard, entry.as_str())) {
            let path = format!("{}/{}", shard.path, entry.as_str());
            return Err(crate::store::Error::Foreign(path).into());
        }
        entries.extend(listed);
    }
    Ok(entries)
}

/// Whether `entry` of `shard` belongs there: an `attempts/` entry is a job
/// id, a `jobs/` entry names its job through its record suffix, and an
/// entry that names no job belongs to no shard in particular.
pub(super) fn placed(shard: &crate::layout::Shard, entry: &str) -> bool {
    let id = if shard.path.starts_with(crate::layout::ATTEMPTS) {
        Some(entry)
    } else {
        super::admission::job_id(entry)
    };
    id.is_none_or(|id| shard.holds(id))
}
