//! Collection preflights the store, report and hardware before deleting.
//! Root and state-wide holds gate all deletion. Subtree holds allow the
//! admission sweep and stop attempt deletion, except verified settled
//! untargeted campaign jobs and queued targeted jobs pin only their own job.
//! Remaining probe diagnostics stop attempt deletion. Each removal checks
//! its pinned identities. A bound capture naming a finding keeps its attempt.
//! Reclaim markers are barriered before bulk unlinks, and reruns finish them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{Value, json};

use super::report::{VerifiedAttempt, VerifiedHistory};
use super::{Error, name};
use crate::record::{Admission, Purpose};
use crate::store::{Dir, Identity, Name, Store, View};

struct Removal {
    directory: Vec<Name>,
    directory_identity: (u64, u64),
    entry: Name,
    identity: Identity,
    bytes: u64,
    path: String,
}

/// A launcher-only group or an attempt reclaim whose marker precedes its removals.
type Planned = (Option<Reclaim>, Vec<Removal>);

/// A settled attempt whose bulk the pass deletes, and the `reclaimed`
/// record written in its directory before the first deletion.
struct Reclaim {
    directory: Vec<Name>,
    directory_identity: (u64, u64),
    record: crate::record::Reclaimed,
    /// A verified marker already exists, so this group can reclaim space first.
    marked: bool,
    path: String,
}

struct Unit {
    directory: Dir,
    finished: crate::record::Verified<crate::record::Finished>,
    logs: Vec<Removal>,
}

pub(super) fn collect(path: &Path, dry_run: bool) -> Result<Value, Error> {
    crate::store::given_ancestors(path).map_err(Error::input_path)?;
    let store = Store::for_collection(path)?;
    let before = measured(&store)?;
    let mut collected = pass(&store, dry_run, usize::MAX, &mut || false)?.report;
    collected["before"] = before;
    collected["after"] = measured(&store)?;
    Ok(collected)
}

/// The bytes and inodes of the whole tree of `store`; `null` for a tree
/// whose walk passes the scan bound, which collect then collects
/// unmeasured.
///
/// # Errors
///
/// The census's errors other than its bound hold.
fn measured(store: &Store) -> Result<Value, Error> {
    match store.usage(crate::scan_bound()) {
        Ok(usage) => Ok(json!({"bytes": usage.bytes, "inodes": usage.inodes})),
        Err(crate::store::Error::ScanBound) => Ok(Value::Null),
        Err(error) => Err(error.into()),
    }
}

/// One collect pass's report and outcome.
pub(super) struct Pass {
    /// `reclaimed` names groups whose marker publication or first removal
    /// ran or was simulated, including partial and marker-only reclaims.
    pub report: Value,
    /// The probe directories and files the pass removed, or would remove
    /// in a dry run.
    pub deletions: usize,
    /// Deletions or a new reclaim marker require a fresh storage census;
    /// a dry run reports the changes it would make.
    pub changed: bool,
    /// The first held row, falling back to the first kept probe diagnostic
    /// whose code differs from the verified listing-source code.
    pub held: Option<String>,
    /// The permitted sweep and plan reached their end with sufficient
    /// marker headroom and clear limit/interruption checks. A hold that skips
    /// the sweep or blocks attempt planning leaves this false.
    pub finished: bool,
}

/// One collect pass over `store`, whose lock the caller holds: the probe
/// sweep, then the planned removals, in that order, stopping after
/// `limit` deletions, a probe directory counting as one, or once
/// `interrupted` returns true before a deletion. A stopped pass leaves the
/// tree a rerun finishes. The snapshot and the plan read the whole store
/// whatever `limit` is. A real pass releases a target’s interrupted stage
/// before measuring marker headroom, and stops with a held row if allocation
/// requires more free bytes or inodes. Dry runs preserve staged files.
///
/// # Errors
///
/// A hold or store error of the snapshot, the sweep, staging cleanup or
/// a removal. A failed guarded cleanup poisons the store.
pub(super) fn pass(
    store: &Store,
    dry_run: bool,
    limit: usize,
    interrupted: &mut dyn FnMut() -> bool,
) -> Result<Pass, Error> {
    let view = View::open(store.path())?;
    if view.root().identity() != store.root().identity() {
        return Err(crate::store::Error::Replaced.into());
    }
    let snapshot = super::report::snapshot(&view)?;
    let hardware = snapshot.hardware.as_ref();
    check_snapshot(store, &view, hardware)?;
    let mut held = snapshot.projection["held"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if let Some(row) = held.iter().find(|row| row["held_code"] == "store") {
        return Err(Error::Held(format!("{}: {}", row["path"], row["reason"])));
    }
    let others: Vec<Value> = held
        .iter()
        .filter(|row| held_probe(row).is_none())
        .cloned()
        .collect();
    if let Some(row) = held
        .iter()
        .find(|row| row["reason"] == super::report::UNDECLARED)
    {
        return Err(Error::Held(format!("{}: {}", row["path"], row["reason"])));
    }
    let pinned = scoped_holds(&view, &others)?;
    let swept = !others
        .iter()
        .any(|row| row["path"].as_str().is_none_or(|path| !path.contains('/')));
    let mut probes = super::sweep::Sweep::default();
    let mut plans = Vec::new();
    let mut finished = false;
    if swept {
        probes = super::sweep::probes(store, dry_run, limit, interrupted)?;
        // Every probes/ diagnostic stays until its probe is removed.
        // Corpus and profile rows remain, as do holds on kept admission
        // probes, and each remaining row keeps all attempt files in place.
        let removed: BTreeSet<&str> = probes.removed.iter().map(String::as_str).collect();
        held.retain(|row| held_probe(row).is_none_or(|probe| !removed.contains(probe)));
        if !probes.stopped
            && probes.removed.len() < limit
            && !held.iter().any(|row| held_probe(row).is_some())
            && let Some(pinned) = pinned
        {
            finished = true;
            mark(
                &view,
                &snapshot.projection,
                &snapshot.histories,
                &pinned,
                &mut plans,
                &mut held,
            )?;
        }
    }
    check_snapshot(store, &view, hardware)?;
    let mut bytes = 0u64;
    let mut rows = Vec::new();
    let mut changed = !probes.removed.is_empty();
    // Marker-free groups release space before a new marker requires allocation.
    plans.sort_by_key(|(reclaim, _)| reclaim.as_ref().is_some_and(|reclaim| !reclaim.marked));
    let mut reclaims = Vec::new();
    let left = limit.saturating_sub(probes.removed.len());
    // The check before a plan stands for its first removal, so each
    // deletion sees one check and a stopped plan writes no marker.
    'plans: for (reclaim, removals) in plans {
        if rows.len() >= left || interrupted() {
            finished = false;
            break;
        }
        check_snapshot(store, &view, hardware)?;
        if let Some(reclaim) = &reclaim {
            if !dry_run {
                let directory = opened(store, &reclaim.directory, reclaim.directory_identity)?;
                if !reclaim.marked {
                    store.clear_staged(&directory, &name("reclaimed"))?;
                    let (free_bytes, free_inodes, fragment) = store.root().free_space()?;
                    let marker_bytes = crate::record::Record::encoded_len(&reclaim.record) as u64;
                    let needed = marker_bytes
                        .div_ceil(fragment.get())
                        .saturating_mul(fragment.get());
                    // Preflight the staged inode and record allocation before
                    // publication, whose write errors poison the store.
                    if free_inodes == 0 || free_bytes < needed {
                        super::report::held(
                            &mut held,
                            &reclaim.path,
                            Error::Held(format!(
                                "reclaimed marker needs {needed} free bytes and 1 free inode; available {free_bytes} bytes and {free_inodes} inodes; free disk space"
                            )),
                        )?;
                        finished = false;
                        break;
                    }
                }
                super::once(store, &directory, "reclaimed", &reclaim.record)?;
            }
            changed |= !reclaim.marked;
            reclaims.push(reclaim.path.clone());
        }
        for (index, removal) in removals.into_iter().enumerate() {
            if index > 0 && (rows.len() >= left || interrupted()) {
                finished = false;
                break 'plans;
            }
            check_snapshot(store, &view, hardware)?;
            let directory = opened(store, &removal.directory, removal.directory_identity)?;
            let found = store
                .open_file(&directory, &removal.entry)?
                .ok_or_else(|| Error::Held("collection entry vanished".into()))?;
            if found.identity() != removal.identity {
                return Err(Error::Held("collection entry changed".into()));
            }
            if !dry_run {
                store.delete(&directory, &removal.entry)?;
                crate::step::call(crate::step::Step::Removed, || Ok(()))
                    .map_err(crate::store::Error::Io)?;
            }
            bytes = bytes
                .checked_add(removal.bytes)
                .ok_or_else(|| Error::Held("collection byte count overflow".into()))?;
            rows.push(json!({"path": removal.path, "bytes": removal.bytes, "inodes": 1}));
        }
    }
    check_snapshot(store, &view, hardware)?;
    let inodes = rows.len() as u64;
    let deletions = rows.len() + probes.removed.len();
    changed |= deletions > 0;
    let diagnostic = held
        .iter()
        .filter_map(|row| {
            Some(format!(
                "{}: {}",
                row["path"].as_str()?,
                row["reason"].as_str()?
            ))
        })
        .next()
        .or_else(|| {
            probes
                .kept
                .iter()
                .find(|probe| probe.code != super::sweep::SOURCE)
                .map(|probe| format!("probes/{}: {}", probe.probe, probe.reason))
        });
    let report = json!({
        "dry_run": dry_run,
        "entries": rows,
        "held": held,
        "freed_bytes": if dry_run { 0 } else { bytes },
        "freed_inodes": if dry_run { 0 } else { inodes },
        "projected_bytes": bytes,
        "projected_inodes": inodes,
        "reclaimed": reclaims,
        "probes": {
            "swept": swept,
            "removed": probes.removed,
            "kept": probes
                .kept
                .iter()
                .map(|kept| json!({"probe": kept.probe, "code": kept.code, "reason": kept.reason}))
                .collect::<Vec<_>>(),
        },
    });
    Ok(Pass {
        report,
        deletions,
        changed,
        held: diagnostic,
        finished,
    })
}

/// The directory `components` names under the state directory, checked
/// against the identity the plan recorded.
fn opened(store: &Store, components: &[Name], identity: (u64, u64)) -> Result<Dir, Error> {
    let mut directory = store.root().duplicate()?;
    for component in components {
        directory = store
            .open_dir(&directory, component)?
            .ok_or_else(|| Error::Held("collection directory vanished".into()))?;
    }
    if directory.identity() != identity {
        return Err(Error::Held("collection directory changed".into()));
    }
    Ok(directory)
}

/// The suffix of any diagnostic path under `probes/`, including corpus
/// probes and build/profile declarations the admission sweep leaves intact.
fn held_probe(row: &Value) -> Option<&str> {
    row["path"].as_str()?.strip_prefix("probes/")
}

fn scoped_holds(view: &View, held: &[Value]) -> Result<Option<BTreeSet<String>>, Error> {
    if held.iter().any(|row| {
        row["path"].as_str().is_none_or(|path| {
            path.strip_prefix("jobs/")
                .is_none_or(|id| crate::record::Digest::parse(id).is_none())
        })
    }) {
        return Ok(None);
    }
    let mut pinned = BTreeSet::new();
    if held.is_empty() {
        return Ok(Some(pinned));
    }
    for row in held {
        let Some(id) = row["path"]
            .as_str()
            .and_then(|path| path.strip_prefix("jobs/"))
        else {
            return Ok(None);
        };
        let Some(jobs) = crate::layout::jobs(view, id)? else {
            return Ok(None);
        };
        let checked = (|| -> Result<bool, Error> {
            let job = view
                .read_record::<Admission>(&jobs, &name(&format!("{id}.json")))?
                .ok_or_else(|| Error::Held("job record missing".into()))?;
            if job.record().job().id().to_string() != id {
                return Ok(false);
            }
            view.barrier(job.read())?;
            if job.record().purpose() == Purpose::Campaign
                && job.record().target().is_none()
                && view
                    .open_file(
                        &jobs,
                        &name(&format!("{id}{}", crate::record::JobResult::SUFFIX)),
                    )?
                    .is_some()
                && crate::attempt::settlement_entries(view, job.record())?
            {
                return Ok(true);
            }
            if !crate::attempt::queued_target(view, job.record())? {
                return Ok(false);
            }
            match crate::attempt::frozen_manifest(view, &jobs, job.record()).map_err(Error::from) {
                Err(Error::Held(_)) => Ok(true),
                Err(error) => Err(error),
                Ok(()) => Ok(false),
            }
        })();
        match checked {
            Ok(true) => {
                pinned.insert(id.to_owned());
            }
            Err(error) if matches!(error, Error::Store(_)) || error.host_fault() => {
                return Err(error);
            }
            _ => return Ok(None),
        }
    }
    Ok(Some(pinned))
}

fn mark(
    view: &View,
    projection: &Value,
    histories: &BTreeMap<String, VerifiedHistory>,
    pinned: &BTreeSet<String>,
    plans: &mut Vec<Planned>,
    held: &mut Vec<Value>,
) -> Result<(), Error> {
    let finding_jobs: BTreeSet<_> = projection["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| {
            row["verified"]["attempt"]["job"]
                .as_str()
                .map(str::to_owned)
        })
        .collect();
    for (id, history) in histories {
        if pinned.contains(id)
            || history.purpose == Purpose::Calibration
            || history.attempts.is_empty()
        {
            continue;
        }
        let root = crate::layout::attempts(view, id)?
            .ok_or_else(|| Error::Held("job attempt root vanished".into()))?;
        let settled = settled(view, id)?;
        let mut candidates = Vec::new();
        let mut rooted = false;
        for (number, attempt) in (1u64..).zip(&history.attempts) {
            let path = crate::layout::attempt_path(id, number)
                .to_str()
                .expect("attempt paths are ASCII")
                .to_owned();
            let planned_unit =
                unit(view, &root, id, number, attempt, &path).and_then(|unit| {
                    match (unit, settled) {
                        (None, _) => Ok(None),
                        (Some(unit), None) => {
                            if !history.targeted {
                                super::reclaim::prepare(
                                    view,
                                    &unit.directory,
                                    id,
                                    number,
                                    &unit.finished,
                                    &path,
                                )?;
                            }
                            Ok(Some((None, unit.logs)))
                        }
                        (Some(_), Some(Some(pin))) if pin == number => Ok(Some((None, Vec::new()))),
                        (Some(unit), Some(_)) => reclaim(view, unit, id, number, &path).map(Some),
                    }
                });
            match planned_unit {
                Ok(Some((Some(reclaim), files))) => plans.push((Some(reclaim), files)),
                Ok(Some((None, mut logs))) => candidates.append(&mut logs),
                Ok(None) => rooted = true,
                Err(error) if matches!(error, Error::Store(_)) || error.host_fault() => {
                    return Err(error);
                }
                Err(error) => super::report::held(held, &path, error)?,
            }
        }
        if !rooted && !finding_jobs.contains(id) && !candidates.is_empty() {
            plans.push((None, candidates));
        }
    }
    Ok(())
}

/// Matching finishes outside the snapshot roots and named captures allow log planning.
fn unit(
    view: &View,
    root: &Dir,
    job: &str,
    number: u64,
    attempt: &VerifiedAttempt,
    path: &str,
) -> Result<Option<Unit>, Error> {
    if attempt.rooted {
        return Ok(None);
    }
    let directory = view
        .open_dir(root, &name(&format!("{number:04}")))?
        .ok_or_else(|| Error::Held("attempt vanished".into()))?;
    if directory.identity() != attempt.directory {
        return Err(Error::Held("attempt directory changed".into()));
    }
    let Some(finished) =
        view.read_record::<crate::record::Finished>(&directory, &name("finished"))?
    else {
        return Ok(None);
    };
    if finished.record().binding != crate::record::Binding::Matching {
        return Ok(None);
    }
    super::reclaim::check_entries(view, &directory, path)?;
    if view
        .read_record::<crate::record::Captured>(&directory, &name("captured"))?
        .is_some_and(|captured| captured.record().finding.is_some())
    {
        return Ok(None);
    }
    let mut logs = Vec::new();
    for output in crate::custody::LAUNCHER_OUTPUTS {
        let entry = name(output);
        if let Some(file) = view.open_file(&directory, &entry)? {
            logs.push(Removal {
                directory: vec![
                    name(crate::layout::ATTEMPTS),
                    crate::layout::shard(job),
                    name(job),
                    name(&format!("{number:04}")),
                ],
                directory_identity: attempt.directory,
                entry,
                identity: file.identity(),
                bytes: file.len(),
                path: format!("{path}/{output}"),
            });
        }
    }
    Ok(Some(Unit {
        directory,
        finished,
        logs,
    }))
}

/// Whether job `id` is a settled campaign job whose attempts' bulk collect
/// reclaims, and then the attempt its pin names. A targeted job keeps its
/// bulk: its judgment is read from its fork's output.
fn settled(view: &View, id: &str) -> Result<Option<Option<u64>>, Error> {
    let jobs =
        crate::layout::jobs(view, id)?.ok_or_else(|| Error::Held("job shard vanished".into()))?;
    let result = name(&format!("{id}{}", crate::record::JobResult::SUFFIX));
    if view.open_file(&jobs, &result)?.is_none() {
        return Ok(None);
    }
    let job = view
        .read_record::<Admission>(&jobs, &name(&format!("{id}.json")))?
        .ok_or_else(|| Error::Held("job record missing".into()))?;
    if job.record().target().is_some() {
        return Ok(None);
    }
    let pin = view.read_record::<crate::record::Pin>(
        &jobs,
        &name(&format!("{id}{}", crate::record::Pin::SUFFIX)),
    )?;
    Ok(Some(pin.map(|pin| pin.record().result.attempt)))
}

fn reclaim(view: &View, unit: Unit, job: &str, number: u64, path: &str) -> Result<Planned, Error> {
    let identity = format!("{job}-{number:04}");
    for kept in ["findings", "triage"] {
        if let Some(directory) = view.open_dir(view.root(), &name(kept))?
            && view.open_dir(&directory, &name(&identity))?.is_some()
        {
            return Ok((None, Vec::new()));
        }
    }
    let Unit {
        directory,
        finished,
        mut logs,
    } = unit;
    let prepared = super::reclaim::prepare(view, &directory, job, number, &finished, path)?;
    let evidence = prepared.directory;
    let record = prepared.marker;
    let bulk = prepared.bulk;
    let number_name = name(&format!("{number:04}"));
    if crate::record::Record::encoded_len(&record) as u64 > crate::record::BOUND {
        return Err(Error::Held("reclaim record exceeds its byte bound".into()));
    }
    let marker = view.read_record::<crate::record::Reclaimed>(&directory, &name("reclaimed"))?;
    if marker
        .as_ref()
        .is_some_and(|marker| marker.record() != &record)
    {
        return Err(Error::Held(
            "reclaim record differs from the attempt's records".into(),
        ));
    }
    let attempt_directory = vec![
        name(crate::layout::ATTEMPTS),
        crate::layout::shard(job),
        name(job),
        number_name,
    ];
    let mut components = attempt_directory.clone();
    components.extend([name("artifacts"), name(&identity)]);
    for file in bulk {
        if let Some(found) = view.open_file(&evidence, &file)? {
            logs.push(Removal {
                directory: components.clone(),
                directory_identity: evidence.identity(),
                path: format!("{path}/artifacts/{identity}/{}", file.as_str()),
                entry: file,
                identity: found.identity(),
                bytes: found.len(),
            });
        }
    }
    if logs.is_empty() && marker.is_some() {
        return Ok((None, logs));
    }
    Ok((
        Some(Reclaim {
            directory: attempt_directory,
            directory_identity: directory.identity(),
            record,
            marked: marker.is_some(),
            path: path.to_owned(),
        }),
        logs,
    ))
}

fn check_snapshot(store: &Store, view: &View, hardware: Option<&View>) -> Result<(), Error> {
    store.writable(store.root())?;
    store.check_path()?;
    view.check_faults()?;
    if let Some(hardware) = hardware {
        hardware.check_faults()?;
    }
    if let Some(hardware) = hardware
        && !hardware.current().map_err(crate::store::Error::Io)?
    {
        return Err(crate::store::Error::Replaced.into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "collect_tests.rs"]
mod tests;
