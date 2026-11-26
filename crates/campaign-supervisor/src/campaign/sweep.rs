//! The probe sweep of `collect`: it removes each empty probe directory and
//! each finished, released admission probe directory except one removable
//! listing source per build. Release removes the cgroup and then the
//! reservation.
//! `report` declares each archive build's profiles from the capability
//! listing of the last completed probe of the build, by name, whose
//! listing verifies. The sweep keeps the last removable probe per build
//! whose listing passes those checks, as a verified source for the report.
//! The sweep deletes only the names the probe's records list, in an
//! order whose every prefix probe reconciliation accepts: the artifact
//! streams, the artifact record and the nested evidence store, the launcher
//! streams, then `started`, `intent` and `finished`, then the directory. A
//! rerun after a kill at any step finishes the same removal. A probe with a
//! reservation, a live cgroup, no `finished` record, records that
//! reconciliation holds, an unreadable record or an entry its records do
//! not list, a foreign mark, staged evidence, evidence beside a missing
//! nested marker, `artifacts` with no `started` record, a stream missing
//! after an earlier listed stream, an oversized stream or a
//! stream digest mismatch keeps its directory and is reported; the sweep
//! decides each keep before its first deletion. Corpus probes belong to
//! corpus assets and are left in place. Lifecycle and reachability records
//! decide eligibility. Each deletion rechecks the file version through
//! [`Identity`] (device, inode, size, mtime and ctime), independently of file
//! age or a clock reading.
//!
//! The sweep preserves the probe when `started` and `launcher.stdout` exist
//! and `launcher.stderr` is missing, and when `artifacts` exists and either
//! launcher stream is missing.

use std::collections::BTreeMap;

use super::{Error, name};
use crate::record::{Artifact, Digest, ProbeFinished};
use crate::store::{Dir, Identity, Name, Store};

/// The probe directories one sweep removed, or would remove in a dry run,
/// and those it kept.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Sweep {
    pub removed: Vec<String>,
    pub kept: Vec<Kept>,
    /// The sweep stopped at its limit or an interruption before its last
    /// removable probe.
    pub stopped: bool,
}

/// A probe directory the sweep keeps.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Kept {
    pub probe: String,
    /// [`SOURCE`] for a verified listing source kept for `report`; otherwise
    /// the held code of the reason, as `report` gives it for a held row.
    pub code: &'static str,
    pub reason: String,
}

/// The [`Kept::code`] of a verified listing source kept for `report`.
pub(crate) const SOURCE: &str = "listing-source";

const MARKS: &str =
    "probe evidence holds staged entries, a foreign mark or entries beside a missing mark";

/// The lifecycle records and launcher streams of a probe directory, in
/// deletion order.
const RECORDS: [&str; 5] = [
    crate::custody::LAUNCHER_STDOUT,
    crate::custody::LAUNCHER_STDERR,
    "started",
    "intent",
    "finished",
];

/// Sweeps `probes/` of `store`, deleting nothing when `dry_run` is set.
/// The caller holds the state lock and completes collect's report,
/// root/store refusal and hardware preflight before allowing deletion.
/// Each removed probe directory uses one unit of `limit`. The sweep stops
/// before the next probe when the limit or `interrupted` fires, and sets
/// [`Sweep::stopped`]. A dry run uses the same budget without mutating the tree.
///
/// # Errors
///
/// [`Error::Bound`] for a `probes/` listing past the scan bound, and a
/// store or host fault, which stops the sweep. An error while removing a
/// probe stops the sweep after the probes already removed; a rerun
/// finishes the removal.
pub(crate) fn probes(
    store: &Store,
    dry_run: bool,
    limit: usize,
    interrupted: &mut dyn FnMut() -> bool,
) -> Result<Sweep, Error> {
    let mut sweep = Sweep::default();
    let Some(root) = store.open_dir(store.root(), &name("probes"))? else {
        return Ok(sweep);
    };
    let mut removable = Vec::new();
    for entry in store
        .list(&root, crate::scan_bound())
        .map_err(|error| Error::listing("probes", error))?
    {
        if super::corpus::is_probe(entry.as_str()) {
            continue;
        }
        match planned(store, &root, &entry) {
            Ok(Some(plan)) => {
                let build = plan.build();
                removable.push((entry, build));
            }
            Ok(None) => {}
            Err(error) if fatal(&error) => return Err(error),
            Err(error) => sweep.kept.push(Kept {
                probe: entry.as_str().to_owned(),
                code: error.held_code(),
                reason: error.to_string(),
            }),
        }
    }
    let sources = sources(store, &root, &removable)?;
    for (entry, build) in removable {
        if sweep.removed.len() >= limit || interrupted() {
            sweep.stopped = true;
            break;
        }
        let source = build.and_then(|build| sources.get(&build));
        if source == Some(&entry) {
            sweep.kept.push(Kept {
                probe: entry.as_str().to_owned(),
                code: SOURCE,
                reason: "probe holds a verified listing source for its build".into(),
            });
            continue;
        }
        if !dry_run {
            // Plans release their descriptors between probes. Reopening and
            // planning here checks the current tree before its first deletion;
            // a probe changed since the first pass stops the sweep.
            let plan = planned(store, &root, &entry)?
                .ok_or_else(|| Error::Held("probe directory vanished".into()))?;
            if plan.build() != build {
                return Err(Error::Held("probe build changed since planning".into()));
            }
            if let (Some(build), Some(source)) = (build, source) {
                reverified(store, &root, source, build)?;
            }
            remove(store, &root, &entry, plan)?;
        }
        sweep.removed.push(entry.as_str().to_owned());
    }
    sweep.kept.sort();
    Ok(sweep)
}

/// Whether `error` stops the sweep: a store or host fault, where a hold
/// keeps only its own probe.
fn fatal(error: &Error) -> bool {
    error.host_fault() || matches!(error, Error::Store(_))
}

/// A verified listing source among the removable probes of `root`: for
/// each build, the last by name whose capability listing verifies. The walk
/// runs from the last name back and verifies a probe only while its build
/// has no source.
fn sources(
    store: &Store,
    root: &Dir,
    removable: &[(Name, Option<Digest>)],
) -> Result<BTreeMap<Digest, Name>, Error> {
    let mut found = BTreeMap::new();
    for (entry, build) in removable.iter().rev() {
        let Some(build) = build else {
            continue;
        };
        if found.contains_key(build) {
            continue;
        }
        let directory = store
            .open_dir(root, entry)?
            .ok_or_else(|| Error::Held("probe directory vanished".into()))?;
        match super::text(entry.as_str())
            .and_then(|attempt| super::probe::build_listing(store, &directory, &attempt))
        {
            Ok((verified, _)) => {
                if verified != *build {
                    return Err(Error::Held("probe build changed since planning".into()));
                }
                found.insert(verified, entry.clone());
            }
            Err(error) if fatal(&error) => return Err(error),
            Err(_) => {}
        }
    }
    Ok(found)
}

fn reverified(store: &Store, root: &Dir, source: &Name, build: Digest) -> Result<(), Error> {
    let directory = store
        .open_dir(root, source)?
        .ok_or_else(|| Error::Held("probe directory vanished".into()))?;
    match super::text(source.as_str())
        .and_then(|attempt| super::probe::build_listing(store, &directory, &attempt))
    {
        Ok((verified, _)) if verified == build => Ok(()),
        Ok(_) => Err(Error::Held("probe build changed since planning".into())),
        Err(error) if fatal(&error) => Err(error),
        Err(error) => Err(Error::Held(format!(
            "listing source {} changed since planning: {error}",
            source.as_str()
        ))),
    }
}

/// The plan for the probe directory `entry` of `root`, `None` when it is
/// absent.
fn planned(store: &Store, root: &Dir, entry: &Name) -> Result<Option<Plan>, Error> {
    store
        .open_dir(root, entry)?
        .map(|directory| plan(store, directory, entry))
        .transpose()
}

/// The deletions that remove one probe directory.
struct Plan {
    /// `artifacts/` and, inside it, the nested evidence store
    /// `artifacts/probe` with the stream names its artifact record lists.
    artifacts: Option<(Dir, Option<Evidence>)>,
    /// The present entries of [`RECORDS`], in deletion order.
    records: Vec<(Name, Identity)>,
    directory: Dir,
}

impl Plan {
    /// The archive build the probe's artifact record names.
    fn build(&self) -> Option<Digest> {
        self.artifacts
            .as_ref()
            .and_then(|(_, evidence)| evidence.as_ref())
            .and_then(|evidence| evidence.build)
    }
}

/// The nested evidence store of a probe and the names it deletes, the
/// artifact record last.
struct Evidence {
    directory: Dir,
    listed: Vec<(Name, Identity)>,
    /// The archive build the artifact record names.
    build: Option<Digest>,
}

/// A listing of the probe tree. A name outside the store's name rules
/// holds the probe as an unlisted entry, and a listing past the scan bound
/// holds it as holding too many entries.
fn tree(list: Result<Vec<Name>, crate::store::Error>) -> Result<Vec<Name>, Error> {
    list.map_err(|error| match error {
        crate::store::Error::Foreign(found) => Error::Held(format!(
            "probe holds unlisted entry {}",
            found.escape_debug()
        )),
        crate::store::Error::ScanBound => Error::Held("probe holds too many entries".into()),
        error => error.into(),
    })
}

/// The removal of the probe directory `directory`, or the reason it stays.
fn plan(store: &Store, directory: Dir, entry: &Name) -> Result<Plan, Error> {
    let entries = tree(store.list(&directory, crate::scan_bound()))?;
    if entries.iter().any(|entry| entry.as_str() == "reservation") {
        return Err(Error::Held("probe holds a reservation".into()));
    }
    if !entries.is_empty() {
        terminal(store, &directory, entry, &entries)?;
    }
    let present = |name: &str| entries.iter().any(|entry| entry.as_str() == name);
    let streams = crate::custody::LAUNCHER_OUTPUTS.map(present);
    if streams == [true, false] && present("started") {
        return Err(Error::Held(
            "probe launcher.stderr is missing after launcher.stdout".into(),
        ));
    }
    if present("artifacts") && streams != [true, true] {
        return Err(Error::Held("probe artifacts lack a launcher stream".into()));
    }
    let mut artifacts = None;
    let mut records = BTreeMap::new();
    for entry in &entries {
        if entry.as_str() == "artifacts" {
            let found = store
                .open_dir(&directory, entry)?
                .ok_or_else(|| Error::Held("probe artifacts vanished".into()))?;
            let evidence = probe_evidence(store, &found)?;
            artifacts = Some((found, evidence));
        } else if RECORDS.contains(&entry.as_str()) {
            records.insert(entry.clone(), file(store, &directory, entry)?);
        } else {
            return Err(Error::Held(format!(
                "probe holds unlisted entry {}",
                entry.as_str()
            )));
        }
    }
    Ok(Plan {
        artifacts,
        records: RECORDS
            .into_iter()
            .map(name)
            .filter_map(|entry| records.remove(&entry).map(|identity| (entry, identity)))
            .collect(),
        directory,
    })
}

/// Requires the records of the probe directory `entry` to show a finished,
/// released probe in a state probe reconciliation accepts: `finished` names
/// this attempt; `started` lies only beside an `intent`; and an `intent`
/// names this attempt, agrees with `started`, and records a cgroup that is
/// gone. An `artifacts` entry requires a `started` record. With no intent,
/// only the finished-only deletion tail is eligible.
fn terminal(store: &Store, directory: &Dir, entry: &Name, entries: &[Name]) -> Result<(), Error> {
    let attempt = super::text(entry.as_str())?;
    let finished = store
        .read_record::<ProbeFinished>(directory, &name("finished"))?
        .ok_or_else(|| Error::Held("probe has no finished record".into()))?;
    if finished.record().attempt != attempt {
        return Err(Error::Held(
            "probe finished record names another attempt".into(),
        ));
    }
    let super::probe::LaunchRecords { intent, started } =
        super::probe::launch_records(store, directory, &attempt)?;
    let Some(intent) = intent else {
        // Deletion removes intent after every entry except finished, so
        // finished alone is the released tail whose cgroup is already gone.
        if entries.iter().any(|entry| entry.as_str() != "finished") {
            return Err(Error::Held("probe without intent holds evidence".into()));
        }
        return Ok(());
    };
    if started.is_none() && entries.iter().any(|entry| entry.as_str() == "artifacts") {
        return Err(Error::Held("probe artifacts lack a started record".into()));
    }
    if crate::store::cgroup_present(std::path::Path::new(intent.record().cgroup.as_str()))
        .map_err(|error| Error::Unreadable(error.into()))?
    {
        return Err(Error::Held("probe cgroup is live".into()));
    }
    Ok(())
}

/// The evidence store `artifacts/probe` and the names its artifact record
/// lists; `None` for an empty `artifacts/`. Present streams must satisfy
/// the byte bound and their recorded digests; nested marks must be removable.
fn probe_evidence(store: &Store, artifacts: &Dir) -> Result<Option<Evidence>, Error> {
    let entries = tree(store.list(artifacts, crate::scan_bound()))?;
    match entries.as_slice() {
        [] => return Ok(None),
        [entry] if entry.as_str() == "probe" => {}
        _ => return Err(Error::Held("probe artifacts hold an unlisted entry".into())),
    }
    let evidence = store
        .open_dir(artifacts, &name("probe"))?
        .ok_or_else(|| Error::Held("probe evidence vanished".into()))?;
    if !store.marks_removable(&evidence)? {
        return Err(Error::Held(MARKS.into()));
    }
    let present = tree(store.list_nested(&evidence, crate::scan_bound()))?;
    let mut listed = Vec::new();
    let mut build = None;
    if present.iter().any(|entry| entry.as_str() == "artifact") {
        let artifact = store
            .read_record::<Artifact>(&evidence, &name("artifact"))?
            .ok_or_else(|| Error::Held("probe artifact vanished".into()))?;
        build = artifact.record().archive;
        for (phase, stream, digest) in artifact.record().streams() {
            let entry = Artifact::stream_name(phase, stream)
                .ok_or_else(|| Error::Held("invalid probe stream name".into()))?;
            // Missing streams ahead of every present stream are a durable
            // deletion prefix; a present stream must match the artifact
            // before it is removed.
            if let Some(found) =
                store.evidence_digest(&evidence, &entry, super::probe::OUTPUT_BYTES)?
                && found != digest
            {
                return Err(Error::Held(format!(
                    "probe stream {} digest differs",
                    entry.as_str()
                )));
            }
            listed.push(entry);
        }
        listed.push(name("artifact"));
    }
    for entry in &present {
        if !listed.contains(entry) {
            return Err(Error::Held(format!(
                "probe evidence holds unlisted entry {}",
                entry.as_str()
            )));
        }
    }
    if let Some(gap) = listed
        .iter()
        .skip_while(|entry| !present.contains(entry))
        .find(|entry| !present.contains(entry))
    {
        return Err(Error::Held(format!(
            "probe stream {} is missing after an earlier stream",
            gap.as_str()
        )));
    }
    let listed = listed
        .into_iter()
        .filter(|entry| present.contains(entry))
        .map(|entry| file(store, &evidence, &entry).map(|identity| (entry, identity)))
        .collect::<Result<_, _>>()?;
    Ok(Some(Evidence {
        directory: evidence,
        listed,
        build,
    }))
}

/// The regular-file version of `entry` in `directory`, pinned for the
/// recheck before deletion.
fn file(store: &Store, directory: &Dir, entry: &Name) -> Result<Identity, Error> {
    let file = store
        .open_file(directory, entry)
        .map_err(|error| {
            if error.faulted() {
                Error::Unreadable(error)
            } else {
                Error::Held(format!("probe entry {} is no regular file", entry.as_str()))
            }
        })?
        .ok_or_else(|| Error::Held(format!("probe entry {} vanished", entry.as_str())))?;
    Ok(file.identity())
}

/// Reopens the planned child by name and verifies that its directory
/// identity still matches before a deletion uses the handle.
fn reopened(store: &Store, parent: &Dir, entry: &Name, planned: &Dir) -> Result<Dir, Error> {
    let current = store
        .open_dir(parent, entry)?
        .ok_or_else(|| Error::Held("probe directory vanished".into()))?;
    if current.identity() != planned.identity() {
        return Err(Error::Held("probe directory changed".into()));
    }
    Ok(current)
}

/// Reopens the probe through the state root, checking both directory
/// identities so a moved subtree keeps its evidence.
fn current(store: &Store, root: &Dir, entry: &Name, plan: &Plan) -> Result<Dir, Error> {
    let probes = reopened(store, store.root(), &name("probes"), root)?;
    reopened(store, &probes, entry, &plan.directory)
}

/// Deletes a planned file after checking the current entry's identity.
fn delete(store: &Store, directory: &Dir, entry: &(Name, Identity)) -> Result<(), Error> {
    if file(store, directory, &entry.0)? != entry.1 {
        return Err(Error::Held("probe entry changed".into()));
    }
    store.delete(directory, &entry.0)?;
    Ok(())
}

/// Performs `plan`, removing the probe directory `entry` of `root`.
fn remove(store: &Store, root: &Dir, entry: &Name, plan: Plan) -> Result<(), Error> {
    if let Some((artifacts, evidence)) = &plan.artifacts {
        let open_artifacts = || {
            reopened(
                store,
                &current(store, root, entry, &plan)?,
                &name("artifacts"),
                artifacts,
            )
        };
        if let Some(evidence) = evidence {
            let open_evidence = || {
                reopened(
                    store,
                    &open_artifacts()?,
                    &name("probe"),
                    &evidence.directory,
                )
            };
            for entry in &evidence.listed {
                delete(store, &open_evidence()?, entry)?;
            }
            // Finished release fences the launcher, and the state lock
            // excludes another controller, so the nested store has no writer.
            if !store.unmark(&open_evidence()?)? {
                return Err(Error::Held(
                    "probe evidence changed before its marks were removed".into(),
                ));
            }
            open_evidence()?;
            store.rmdir(&open_artifacts()?, &name("probe"))?;
        }
        open_artifacts()?;
        store.rmdir(&current(store, root, entry, &plan)?, &name("artifacts"))?;
    }
    for record in &plan.records {
        delete(store, &current(store, root, entry, &plan)?, record)?;
    }
    current(store, root, entry, &plan)?;
    store.rmdir(
        &reopened(store, store.root(), &name("probes"), root)?,
        entry,
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "sweep_tests.rs"]
mod tests;
