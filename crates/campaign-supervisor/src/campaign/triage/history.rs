//! Append-only steps preserve consecutive tokens and finding-scoped holds.
//! Custody and store faults hold every admission.

use super::{Error, Step, name};
use crate::custody::Custody;
use crate::record::{
    Configuration, Decision, Digest, Finding, ReplayStatus, StepKind, TriageResult, TriageStep,
    Verified,
};
use crate::store::{Dir, ReadStore, Store, View};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn finding(store: &impl ReadStore, id: &str) -> Result<Verified<Finding>, Error> {
    let view = View::open(store.path())?;
    if view.root().identity() != store.root().identity() {
        return Err(Error::Store(crate::store::Error::Replaced));
    }
    let directory = super::super::findings::directory(store, id)?;
    let found = super::super::findings::load(store, &directory, id)?;
    store.barrier(found.read())?;
    if !view.current().map_err(crate::store::Error::Io)? {
        return Err(Error::Store(crate::store::Error::Replaced));
    }
    Ok(found)
}

pub(super) fn root(store: &impl ReadStore, id: &str) -> Result<Option<Dir>, Error> {
    let Some(root) = store.open_dir(store.root(), &name("triage"))? else {
        return Ok(None);
    };
    let Some(root) = store.open_dir(&root, &name(id))? else {
        return Ok(None);
    };
    Ok(store.open_dir(&root, &name("steps"))?)
}

pub(in crate::campaign) fn step_entries(
    store: &impl ReadStore,
    steps: &Dir,
    id: &str,
) -> Result<Vec<crate::store::Name>, Error> {
    store
        .list(steps, crate::scan_bound())
        .map_err(|error| Error::listing(&format!("triage/{id}/steps"), error))
}

pub(super) fn numbers(store: &impl ReadStore, root: &Dir, id: &str) -> Result<Vec<u64>, Error> {
    let mut numbers = Vec::new();
    for entry in step_entries(store, root, id)? {
        let number = entry
            .as_str()
            .parse::<u64>()
            .map_err(|_| Error::Held("invalid triage step number".into()))?;
        if number == 0 || entry.as_str() != format!("{number:04}") {
            return Err(Error::Held("noncanonical triage step number".into()));
        }
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
    Ok(numbers)
}

#[cfg(test)]
pub(super) fn load(
    store: &impl ReadStore,
    root: &Dir,
    finding: Verified<Finding>,
    number: u64,
) -> Result<Step, Error> {
    let step = pending(store, root, finding, number)?;
    step.dependencies(store)?;
    Ok(step)
}

pub(super) fn pending(
    store: &impl ReadStore,
    root: &Dir,
    finding: Verified<Finding>,
    number: u64,
) -> Result<Step, Error> {
    let (directory, record) = step_record(store, root, finding.record(), number)?;
    let step = Step {
        directory,
        finding,
        record,
    };
    Ok(step)
}

fn step_record(
    store: &impl ReadStore,
    root: &Dir,
    finding: &Finding,
    number: u64,
) -> Result<(Dir, Verified<TriageStep>), Error> {
    let directory = store
        .open_dir(root, &name(&format!("{number:04}")))?
        .ok_or_else(|| Error::Held("triage step missing".into()))?;
    let record = store
        .read_record::<TriageStep>(&directory, &name("step"))?
        .ok_or_else(|| Error::Held("triage step record missing".into()))?;
    bound_step(record.record(), finding, number)?;
    store.barrier(record.read())?;
    Ok((directory, record))
}

pub(in crate::campaign) fn bound_step(
    step: &TriageStep,
    finding: &Finding,
    number: u64,
) -> Result<(), Error> {
    if step.finding != finding.id()
        || step.attempt.number != number
        || step.attempt.attempt.as_str() != format!("{}-triage-{number:04}", step.finding.as_str())
        || step.attempt.manifest != finding.attempt.manifest
        || step.attempt.job != finding.attempt.job
        || step.limits.get(&name_text("attempt_output")) != Some(&step.attempt.file_bytes)
    {
        return Err(Error::Held("triage step binding differs".into()));
    }
    Ok(())
}

fn metadata_finding(store: &Store, id: &str) -> Result<Verified<Finding>, Error> {
    let directory = super::executor::retained(store, id)?;
    let found = store
        .read_record::<Finding>(&directory, &name("finding.json"))?
        .ok_or_else(|| Error::Held("finding record missing".into()))?;
    super::super::findings::validate(found.record(), id)?;
    store.barrier(found.read())?;
    Ok(found)
}

pub(super) fn summaries(
    store: &Store,
    id: &str,
    finding: &Finding,
) -> Result<Vec<(TriageStep, TriageResult)>, Error> {
    let Some(root) = root(store, id)? else {
        return Ok(Vec::new());
    };
    let mut results = Vec::new();
    let view = View::open(store.path())?;
    if view.root().identity() != store.root().identity() {
        return Err(Error::Store(crate::store::Error::Replaced));
    }
    for number in numbers(store, &root, id)? {
        let (directory, step) = step_record(store, &root, finding, number)?;
        let result = store
            .read_record::<TriageResult>(&directory, &name("result"))?
            .ok_or_else(|| Error::Held("step result missing".into()))?;
        let finished = store
            .read_record::<crate::record::Finished>(&directory, &name("finished"))?
            .ok_or_else(|| Error::Held("step finish missing".into()))?;
        if result.record().finding != step.record().finding
            || result.record().number != number
            || result.record().finished != *finished.record()
            || finished.record().attempt != step.record().attempt.attempt
        {
            return Err(Error::Held("step summary binding differs".into()));
        }
        store.barrier(finished.read())?;
        store.barrier(result.read())?;
        super::super::findings::verify_stop_witnesses(
            &view,
            &directory,
            step.record(),
            result.record(),
        )?;
        results.push((step.record().clone(), result.record().clone()));
    }
    Ok(results)
}

#[cfg(test)]
pub(super) fn results(store: &Store, id: &str) -> Result<Vec<(TriageStep, TriageResult)>, Error> {
    let Some(root) = root(store, id)? else {
        return Ok(Vec::new());
    };
    let mut results = Vec::new();
    for number in numbers(store, &root, id)? {
        let step = load(store, &root, finding(store, id)?, number)?;
        let completed = step.execution().read_finished(store)?;
        let result = step.read_result(store, &completed)?;
        results.push((step.record.record().clone(), result));
    }
    Ok(results)
}

#[cfg(test)]
pub(crate) fn reconcile(
    store: &Store,
    custody: &mut Custody,
) -> Result<BTreeMap<String, String>, Error> {
    reconcile_counted(store, custody, &mut None)
}

/// Reconciles retained steps, sharing the command's census slot with later
/// storage decisions. Triage writes leave its charged roots unchanged.
pub(crate) fn reconcile_counted(
    store: &Store,
    custody: &mut Custody,
    census: &mut Option<crate::campaign::census::Census>,
) -> Result<BTreeMap<String, String>, Error> {
    let mut skipped = BTreeMap::new();
    let Some(root) = store.open_dir(store.root(), &name("triage"))? else {
        return Ok(skipped);
    };
    let mut fatal = None;
    // Reconciliation writes only beneath `triage/`, which the census leaves
    // uncharged, so one count serves every step it stages.
    let mut staging_hold = false;
    for entry in store
        .list(&root, crate::scan_bound())
        .map_err(|error| Error::listing("triage", error))?
    {
        if let Err(error) =
            reconcile_finding(store, custody, entry.as_str(), census, &mut staging_hold)
        {
            let custodial = match custodial_records(store, custody, entry.as_str()) {
                Ok(custodial) => custodial,
                Err(error) => {
                    if fatal.is_none() {
                        fatal = Some(error);
                    }
                    continue;
                }
            };
            if global(&error) || custodial {
                let error = match error {
                    Error::Store(_)
                    | Error::Census { .. }
                    | Error::Bound { .. }
                    | Error::Unreadable(_)
                    | Error::Record(_)
                    | Error::Custody(_) => error,
                    _ => Error::Custody(error.to_string()),
                };
                if fatal.is_none() {
                    fatal = Some(error);
                }
                continue;
            }
            skipped.insert(entry.as_str().to_owned(), error.to_string());
        }
    }
    match fatal {
        Some(error) => Err(error),
        None => Ok(skipped),
    }
}
fn reconcile_finding(
    store: &Store,
    custody: &mut Custody,
    id: &str,
    census: &mut Option<crate::campaign::census::Census>,
    staging_hold: &mut bool,
) -> Result<(), Error> {
    let Some(steps) = root(store, id)? else {
        return Ok(());
    };
    let mut failed = None;
    for number in numbers(store, &steps, id)? {
        let outcome = (|| -> Result<(), Error> {
            let step = pending(store, &steps, finding(store, id)?, number)?;
            let intent =
                store.read_record::<crate::record::Intent>(&step.directory, &name("intent"))?;
            let finished =
                store.read_record::<crate::record::Finished>(&step.directory, &name("finished"))?;
            if store
                .read_record::<crate::record::ReplayDependencies>(
                    &step.directory,
                    &name("dependencies"),
                )?
                .is_none()
            {
                if intent.is_some() || finished.is_some() {
                    return Err(Error::Held(
                        "launched step lacks input commit marker".into(),
                    ));
                }
                if *staging_hold {
                    return Err(Error::Custody(
                        "input staging waits for an earlier state-wide hold".into(),
                    ));
                }
                if let Err(error) = step.stage_inputs(store, census) {
                    if global(&error) {
                        *staging_hold = true;
                    }
                    return Err(error);
                }
            }
            step.dependencies(store)?;
            let charged =
                crate::custody::charged(store, &step.directory, step.identity())?.is_some();
            if finished.is_none() && !charged {
                if intent.is_some() {
                    return Err(Error::Held("unfinished step lacks reservation".into()));
                }
                crate::custody::charge(store, &step.directory, step.identity())?;
            }
            let completed = step
                .execution()
                .reconcile(store, custody, crate::attempt::EVIDENCE_BOUND)
                .map_err(|error| match error {
                    crate::custody::Error::Held(_) if finished.is_some() && !charged => {
                        Error::Held(error.to_string())
                    }
                    crate::custody::Error::Record(held) if finished.is_some() && !charged => {
                        Error::Record(held)
                    }
                    error => Error::Custody(error.to_string()),
                })?;
            step.conclude(store, completed, None)?;
            Ok(())
        })();
        // A state-wide error outranks a finding-local one, so a later
        // step's store or census fault holds the pass; among errors of one
        // scope the first is kept.
        if let Err(error) = outcome
            && failed
                .as_ref()
                .is_none_or(|earlier| global(&error) && !global(earlier))
        {
            failed = Some(error);
        }
    }
    match failed {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
pub(crate) fn global(error: &Error) -> bool {
    match error {
        Error::Store(_) | Error::Census { .. } | Error::Custody(_) | Error::Bound { .. } => true,
        Error::Unreadable(error) | Error::Record(crate::record::Held::Unreadable(error)) => {
            error.faulted()
        }
        _ => false,
    }
}

/// One insufficient replay settles automatic targeted triage when stored child facts are absent.
pub(in crate::campaign) fn facts_settled(
    finding: &Finding,
    records: &[(TriageStep, TriageResult)],
) -> bool {
    finding.admission.target().is_some()
        && finding
            .child
            .as_ref()
            .and_then(|child| child.replay_facts())
            .is_none()
        && records.iter().any(|(step, result)| {
            step.kind == StepKind::Replay
                && result.status == Some(ReplayStatus::InsufficientEvidence)
        })
}

pub(super) fn next(
    finding: &Finding,
    records: &[(TriageStep, TriageResult)],
    can_reduce: bool,
) -> Option<StepKind> {
    if finding.bundle_wait_reason().is_some() {
        return None;
    }
    if facts_settled(finding, records) {
        return None;
    }
    let settled = records.iter().rev().find(|(step, result)| {
        step.kind != StepKind::Reduce
            && (step.kind == StepKind::Rerun
                && result.status == Some(ReplayStatus::InsufficientEvidence)
                || matches!(
                    result.status,
                    Some(
                        ReplayStatus::Reproduced
                            | ReplayStatus::Unreproduced
                            | ReplayStatus::Diverged
                    )
                ))
    });
    if let Some((_, result)) = settled {
        if result.status == Some(ReplayStatus::Reproduced)
            && can_reduce
            && !records.iter().any(|(step, result)| {
                step.kind == StepKind::Reduce
                    && matches!(
                        result.status,
                        Some(ReplayStatus::Reduced | ReplayStatus::Unreducible)
                    )
            })
        {
            return Some(StepKind::Reduce);
        }
        return None;
    }
    if finding.admission.target().is_some() {
        return finding.bundle().map(|_| StepKind::Replay);
    }
    if finding
        .artifact
        .as_ref()
        .is_none_or(|artifact| artifact.bundle.is_none())
        || records
            .iter()
            .rev()
            .find(|(step, _)| step.kind != StepKind::Reduce)
            .is_some_and(|(step, result)| {
                step.kind == StepKind::Rerun
                    || result.status == Some(ReplayStatus::InsufficientEvidence)
            })
    {
        Some(StepKind::Rerun)
    } else {
        Some(StepKind::Replay)
    }
}

pub(crate) struct Selection {
    pub next: Option<(String, StepKind)>,
    pub skipped: BTreeMap<String, String>,
    /// Findings with no admissible step under this build and configuration.
    pub ineligible: BTreeSet<String>,
}
pub(crate) fn select(
    store: &Store,
    build: Digest,
    config: &Configuration,
    skip: &BTreeSet<String>,
) -> Result<Selection, Error> {
    let view = View::open(store.path())?;
    if view.root().identity() != store.root().identity() {
        return Err(Error::Store(crate::store::Error::Replaced));
    }
    let mut selection = Selection {
        next: None,
        skipped: BTreeMap::new(),
        ineligible: BTreeSet::new(),
    };
    let Some(root) = view.open_dir(view.root(), &name("findings"))? else {
        return Ok(selection);
    };
    let mut eligible = Vec::new();
    let parents = super::super::lineage::Parents::default();
    for entry in view
        .list(&root, crate::scan_bound())
        .map_err(|error| Error::listing("findings", error))?
    {
        let id = entry.as_str();
        if skip.contains(id) {
            continue;
        }
        let candidate = (|| {
            let directory = super::super::findings::directory(&view, id)?;
            let finding = metadata_finding(store, id)?;
            if super::super::findings::latest(&view, &directory, id, finding.record())?
                == Some(Decision::Resolved)
            {
                super::super::findings::load_among(&view, &directory, id, &parents)?;
                return Ok(None);
            }
            if Digest::parse(
                finding
                    .record()
                    .admission
                    .job()
                    .experiment()
                    .pins
                    .build
                    .as_str(),
            ) != Some(build)
            {
                return Ok(None);
            }
            let records = summaries(store, id, finding.record())?;
            let can_reduce = super::verdict::reduction(store, finding.record())?.is_none();
            Ok(next(finding.record(), &records, can_reduce)
                .filter(|kind| !stalled_for(finding.record(), &records, config, *kind))
                .map(|kind| (records.len(), id.to_owned(), kind)))
        })();
        match candidate {
            Ok(Some(candidate)) => eligible.push(candidate),
            Ok(None) => {
                selection.ineligible.insert(id.to_owned());
            }
            Err(error) => {
                if global(&error) {
                    return Err(error);
                }
                selection.skipped.insert(id.to_owned(), error.to_string());
            }
        }
    }
    eligible.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    for (_, id, kind) in eligible {
        match finding(store, &id) {
            Ok(_) => {
                selection.next = Some((id, kind));
                break;
            }
            Err(error) => {
                if global(&error) {
                    return Err(error);
                }
                selection.skipped.insert(id, error.to_string());
            }
        }
    }
    Ok(selection)
}

pub(super) fn reserved(store: &Store) -> Result<u64, Error> {
    let Some(root) = store.open_dir(store.root(), &name("triage"))? else {
        return Ok(0);
    };
    let mut charged = 0;
    for finding in store
        .list(&root, crate::scan_bound())
        .map_err(|error| Error::listing("triage", error))?
    {
        let Some(steps) = self::root(store, finding.as_str())? else {
            continue;
        };
        for entry in step_entries(store, &steps, finding.as_str())? {
            let directory = store
                .open_dir(&steps, &entry)?
                .ok_or_else(|| Error::Held("step directory missing".into()))?;
            let Some(reservation) = store
                .read_record::<crate::record::Reservation>(&directory, &name("reservation"))?
            else {
                continue;
            };
            if crate::custody::charged(store, &directory, &reservation.record().attempt)?.is_some()
            {
                charged += 1;
            }
        }
    }
    Ok(charged)
}

fn name_text(value: &str) -> crate::record::Text {
    crate::record::Text::new(value).expect("limit names are ASCII")
}

pub(super) fn stalled(
    records: &[(TriageStep, TriageResult)],
    config: &Configuration,
    kind: StepKind,
) -> bool {
    if records.len() < 2 {
        return false;
    }
    let tail = &records[records.len() - 2..];
    if !same_limits(tail, config) {
        return false;
    }
    tail.iter().all(|(_, result)| result.status.is_none())
        || kind == StepKind::Reduce
            && tail.iter().all(|(step, result)| {
                step.kind == StepKind::Reduce
                    && result.status == tail[0].1.status
                    && !matches!(
                        result.status,
                        Some(ReplayStatus::Reduced | ReplayStatus::Unreducible)
                    )
            })
}
/// Combines ordinary stall rules with the targeted replay budget.
pub(crate) fn stalled_for(
    finding: &Finding,
    records: &[(TriageStep, TriageResult)],
    config: &Configuration,
    kind: StepKind,
) -> bool {
    targeted_stall_reason(finding, records, config, kind).is_some()
        || stalled(records, config, kind)
}

/// Names the targeted replay stall since the latest limit change or settled result.
pub(in crate::campaign) fn targeted_stall_reason(
    finding: &Finding,
    records: &[(TriageStep, TriageResult)],
    config: &Configuration,
    kind: StepKind,
) -> Option<&'static str> {
    if finding.admission.target().is_none() || kind != StepKind::Replay {
        return None;
    }
    let current: Vec<_> = records
        .iter()
        .rev()
        .take_while(|record| {
            same_limits(std::slice::from_ref(*record), config)
                && !matches!(
                    record.1.status,
                    Some(
                        ReplayStatus::Reproduced
                            | ReplayStatus::Unreproduced
                            | ReplayStatus::Diverged
                    )
                )
        })
        .collect();
    if current.len() >= 2
        && current[..2].iter().all(|(step, result)| {
            step.kind == StepKind::Replay && result.state == crate::record::StepState::Interrupted
        })
    {
        return Some("two consecutive interrupted targeted replays at unchanged limits");
    }
    if current
        .iter()
        .filter(|(step, result)| {
            step.kind == StepKind::Replay
                && result.state == crate::record::StepState::Complete
                && result.status == Some(ReplayStatus::InsufficientEvidence)
        })
        .take(2)
        .count()
        == 2
    {
        return Some("two insufficient targeted replays at unchanged limits");
    }
    None
}

fn same_limits(tail: &[(TriageStep, TriageResult)], config: &Configuration) -> bool {
    tail.iter().all(|(step, _)| {
        [
            "cpu",
            "tree_memory",
            "processes",
            "wall",
            "attempt_output",
            "attempt_inodes",
        ]
        .iter()
        .all(|key| step.limits.get(&name_text(key)) == Some(&config.value(key)))
    })
}

pub(super) fn step_path(store: &impl ReadStore, id: &str, number: u64) -> std::path::PathBuf {
    store
        .path()
        .join("triage")
        .join(id)
        .join("steps")
        .join(format!("{number:04}"))
}

pub(crate) fn custodial_records(store: &Store, custody: &Custody, id: &str) -> Result<bool, Error> {
    let Some(root) = root(store, id)? else {
        return Ok(false);
    };
    for entry in step_entries(store, &root, id)? {
        let directory = store
            .open_dir(&root, &entry)?
            .ok_or_else(|| Error::Held("step directory missing".into()))?;
        if store.open_file(&directory, &name("reservation"))?.is_some() {
            return Ok(true);
        }
        if let Some(intent) =
            store.read_record::<crate::record::Intent>(&directory, &name("intent"))?
            && (!custody.inactive(intent.record()).map_err(Error::custody)?
                || store
                    .read_record::<crate::record::Finished>(&directory, &name("finished"))?
                    .is_none())
        {
            return Ok(true);
        }
    }
    Ok(false)
}
