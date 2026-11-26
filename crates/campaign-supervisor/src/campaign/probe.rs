use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{Error, name};
use crate::archive::Archive;
use crate::custody::{Custody, Launch, Limits, Stopped, Timing};
use crate::protocol::Listing;
use crate::record::{Artifact, BOUND, Digest, Intent, Pins, ProbeFinished, ProbeOutcome, Started};
use crate::store::{Creation, Dir, Store};

/// The custody output bytes of one admission probe, which the census
/// charges for each admission probe directory.
pub(super) const OUTPUT_BYTES: u64 = 8 * BOUND;
/// The custody output inodes of one admission probe, which the census
/// charges for each admission probe directory.
pub(super) const OUTPUT_INODES: u64 = 16;

pub(super) struct Probed {
    pub listing: Listing,
    pub pins: Pins,
    pub archive: PathBuf,
}

fn reconcile(store: &Store, custody: &mut Custody) -> Result<(), Error> {
    reconcile_records(store, custody)?;
    if !custody.unrecorded(&[], crate::scan_bound())?.is_empty() {
        return Err(Error::Held("custody contains unrecorded probes".into()));
    }
    Ok(())
}

pub(super) fn reconcile_records(store: &Store, custody: &mut Custody) -> Result<(), Error> {
    if let Some(probes) = store.open_dir(store.root(), &name("probes"))? {
        let entries = store
            .list(&probes, crate::scan_bound())
            .map_err(|error| Error::listing("probes", error))?;
        let mut first_error = None;
        for entry in &entries {
            if let Err(error) = reconcile_one(store, custody, &probes, entry) {
                if store.writable(store.root()).is_err() {
                    return Err(error);
                }
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        if entries.len() >= crate::scan_bound() {
            return Err(Error::bound("probes", entries.len()));
        }
    }
    Ok(())
}

fn reconcile_one(
    store: &Store,
    custody: &mut Custody,
    probes: &Dir,
    entry: &crate::store::Name,
) -> Result<(), Error> {
    let directory = store
        .open_dir(probes, entry)?
        .ok_or_else(|| Error::Held("probe directory vanished".into()))?;
    let reservation = crate::custody::charged(store, &directory, &super::text(entry.as_str())?);
    let LaunchRecords { intent, started } =
        launch_records(store, &directory, &super::text(entry.as_str())?)?;
    let Some(intent) = intent else {
        if reservation?.is_some() {
            custody.pending(store, &directory, &super::text(entry.as_str())?)?;
            return reconcile_one(store, custody, probes, entry);
        }
        return Ok(());
    };
    let finished = store.read_record::<ProbeFinished>(&directory, &name("finished"))?;
    if finished
        .as_ref()
        .is_some_and(|finished| finished.record().attempt != intent.record().attempt)
    {
        return Err(Error::Held(
            "probe finished record names another attempt".into(),
        ));
    }
    if matches!(&reservation, Ok(None)) && finished.is_some() {
        if crate::store::cgroup_present(Path::new(intent.record().cgroup.as_str()))
            .map_err(|error| Error::Held(error.to_string()))?
        {
            return Err(Error::Held("released probe has an existing cgroup".into()));
        }
        return Ok(());
    }
    let stopped = custody.reconcile(store, &intent, started.as_ref())?;
    if reservation?.is_none() {
        return Err(Error::Held("probe lacks reservation".into()));
    }
    release(
        store,
        &directory,
        stopped,
        &finished.map_or_else(
            || ProbeFinished {
                attempt: intent.record().attempt.clone(),
                outcome: ProbeOutcome::Held,
            },
            |finished| finished.record().clone(),
        ),
    )?;
    Ok(())
}

pub(super) fn probe(
    store: &Store,
    archive: &Path,
    root: &Path,
    watchdog: Duration,
) -> Result<Probed, Error> {
    let archive = Archive::load(archive).map_err(|error| {
        if error.exit(false) == crate::exit::Sim::Rejected {
            Error::Rejected(error.to_string())
        } else {
            Error::Held(error.to_string())
        }
    })?;
    let cpu_seconds = (watchdog
        .as_secs()
        .saturating_add(u64::from(watchdog.subsec_nanos() != 0)))
    .min(
        crate::sys::cpu_limit()
            .map_err(|error| Error::Held(error.to_string()))?
            .saturating_sub(1),
    )
    .min(crate::sys::CPU_HARD_MAX - 1);
    crate::sys::dispatch_limits(cpu_seconds, BOUND).map_err(|error| {
        if error.raw_os_error().is_some() {
            Error::Held(error.to_string())
        } else {
            Error::Rejected(error.to_string())
        }
    })?;
    let mut custody = Custody::open(
        root,
        Timing {
            poll: Duration::from_millis(10),
            kill_wait: Duration::from_secs(5),
            watchdog,
        },
    )
    .map_err(|error| {
        if error.exit() == crate::exit::Supervisor::Rejected {
            Error::Rejected(error.to_string())
        } else {
            Error::Held(error.to_string())
        }
    })?;
    reconcile(store, &mut custody)?;
    if custody.interruption()?.is_some() {
        return Err(Error::Held("controller interruption requires drain".into()));
    }
    let (id, directory) = directory(store, "probe")?;
    crate::custody::charge(store, &directory, &id)?;
    let path = store.path().join("probes").join(id.as_str());
    let executable = crate::store::canonical_host(Path::new("/proc/self/exe"))
        .map_err(|e| Error::Held(e.to_string()))?;
    let running = custody.launch(
        store,
        &directory,
        Launch {
            attempt: id.clone(),
            name: name(id.as_str()),
            gate: executable.clone(),
            launcher: executable,
            args: vec![
                "admission-probe".into(),
                "--archive".into(),
                archive.path().into(),
                "--artifacts".into(),
                path.join("artifacts").into(),
                "--run-id".into(),
                "probe".into(),
                "--watchdog".into(),
                watchdog.as_secs_f64().to_string().into(),
            ],
            directory: path.clone(),
            environment: Default::default(),
            limits: Limits {
                cpu_quota_us: crate::store::cgroup::CPU_PERIOD_US,
                memory_bytes: 1 << 30,
                pids: 64,
                file_bytes: BOUND,
                cpu_seconds,
                output_bytes: OUTPUT_BYTES,
                output_inodes: OUTPUT_INODES,
            },
        },
    )?;
    let stopped = custody.wait_any(vec![running])?.stopped;
    let result = verify(&stopped, store, &directory, &archive);
    release(
        store,
        &directory,
        stopped,
        &ProbeFinished {
            attempt: id,
            outcome: if result.is_ok() {
                ProbeOutcome::Complete
            } else {
                ProbeOutcome::Held
            },
        },
    )?;
    result
}

pub(super) fn directory(store: &Store, prefix: &str) -> Result<(crate::record::Text, Dir), Error> {
    store.mkdir(store.root(), &name("probes"))?;
    let probes = store
        .open_dir(store.root(), &name("probes"))?
        .ok_or_else(|| Error::Held("probes directory vanished".into()))?;
    let entries = store
        .list(&probes, crate::scan_bound())
        .map_err(|error| Error::listing("probes", error))?
        .len();
    if entries >= crate::scan_bound() {
        return Err(Error::bound("probes", entries));
    }
    let id = super::text(&format!(
        "{prefix}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Held(e.to_string()))?
            .as_nanos()
    ))?;
    if store.mkdir(&probes, &name(id.as_str()))? != Creation::Created {
        return Err(Error::Held("probe directory already present".into()));
    }
    let directory = store
        .open_dir(&probes, &name(id.as_str()))?
        .ok_or_else(|| Error::Held("probe directory vanished".into()))?;
    Ok((id, directory))
}

pub(super) fn release(
    store: &Store,
    directory: &Dir,
    stopped: Stopped,
    finished: &ProbeFinished,
) -> Result<(), Error> {
    let existing = store.read_record::<ProbeFinished>(directory, &name("finished"))?;
    let finished = existing.as_ref().map_or(finished, |record| record.record());
    let tree = stopped.evidence(store, directory, crate::attempt::EVIDENCE_BOUND)?;
    tree.complete_probe(store, finished)?;
    Ok(())
}

/// The validated launch records of an admission probe. A started witness
/// names and agrees with the intent that precedes it.
pub(super) struct LaunchRecords {
    pub intent: Option<crate::record::Verified<Intent>>,
    pub started: Option<crate::record::Verified<Started>>,
}

/// The probe's intent and started witness, with the attempt identity and
/// their agreement checked. A started witness requires an intent. The
/// intent is checked before reading started, matching reconciliation's
/// refusal order.
pub(super) fn launch_records(
    store: &impl crate::store::ReadStore,
    directory: &Dir,
    attempt: &crate::record::Text,
) -> Result<LaunchRecords, Error> {
    let intent = store.read_record::<Intent>(directory, &name("intent"))?;
    if intent
        .as_ref()
        .is_some_and(|intent| intent.record().attempt != *attempt)
    {
        return Err(Error::Held("probe intent names another attempt".into()));
    }
    let started = store.read_record::<Started>(directory, &name("started"))?;
    match (&intent, &started) {
        (None, Some(_)) => return Err(Error::Held("started probe requires an intent".into())),
        (Some(intent), Some(started)) if !started.record().agrees_with(intent.record()) => {
            return Err(Error::Held(
                "probe started record differs from its intent".into(),
            ));
        }
        _ => {}
    }
    Ok(LaunchRecords { intent, started })
}

pub(super) fn released(
    store: &impl crate::store::ReadStore,
    directory: &Dir,
    attempt: &crate::record::Text,
) -> Result<(), Error> {
    let finish = store
        .read_record::<ProbeFinished>(directory, &name("finished"))?
        .ok_or_else(|| Error::Held("probe unfinished".into()))?;
    let LaunchRecords { intent, started } = launch_records(store, directory, attempt)?;
    let intent = intent.ok_or_else(|| Error::Held("probe intent missing".into()))?;
    let started = started.ok_or_else(|| Error::Held("probe started witness missing".into()))?;
    if finish.record().attempt != *attempt
        || finish.record().outcome != ProbeOutcome::Complete
        || crate::custody::charged(store, directory, attempt)?.is_some()
        || crate::store::cgroup_present(Path::new(intent.record().cgroup.as_str()))
            .map_err(|error| Error::Unreadable(error.into()))?
    {
        return Err(Error::Held("probe lifecycle is held or incomplete".into()));
    }
    for read in [finish.read(), intent.read(), started.read()] {
        store.barrier(read)?;
    }
    Ok(())
}

fn verify(
    stopped: &Stopped,
    store: &Store,
    directory: &Dir,
    archive: &Archive,
) -> Result<Probed, Error> {
    verify_exit(stopped)?;
    Ok(Probed {
        listing: read_listing(store, directory, archive.id())?,
        pins: archive.pins(),
        archive: archive.path().to_path_buf(),
    })
}

fn verify_exit(stopped: &Stopped) -> Result<(), Error> {
    if stopped.watchdog() || stopped.interruption().is_some() {
        return Err(Error::Held(
            "capabilities probe interrupted or timed out".into(),
        ));
    }
    if !stopped.status().is_some_and(|status| status.success()) {
        return Err(if stopped.status().and_then(|s| s.code()) == Some(2) {
            Error::Rejected("archive capability probe rejected".into())
        } else {
            Error::Held("archive capability probe incomplete".into())
        });
    }
    Ok(())
}

pub(super) fn read_listing(
    store: &impl crate::store::ReadStore,
    directory: &Dir,
    archive: Digest,
) -> Result<Listing, Error> {
    listing(store, directory, Some(archive)).map(|(_, listing)| listing)
}

/// Reads and binds a capability listing once. An expected archive is
/// checked before the evidence barriers; a report source requires the
/// artifact to name an archive.
fn listing(
    store: &impl crate::store::ReadStore,
    directory: &Dir,
    expected: Option<Digest>,
) -> Result<(Digest, Listing), Error> {
    let artifacts = store
        .open_dir(directory, &name("artifacts"))?
        .ok_or_else(|| Error::Held("probe artifacts missing".into()))?;
    let evidence = store
        .open_dir(&artifacts, &name("probe"))?
        .ok_or_else(|| Error::Held("probe evidence missing".into()))?;
    let artifact = store
        .read_record::<Artifact>(&evidence, &name("artifact"))?
        .ok_or_else(|| Error::Held("probe artifact missing".into()))?;
    let archive = expected
        .or(artifact.record().archive)
        .ok_or_else(|| Error::Held("probe build missing".into()))?;
    let phase = super::text("capabilities")?;
    let stdout_name = Artifact::stream_name(&phase, "stdout")
        .expect("the fixed capability stream name satisfies the store's name rules");
    let stdout = store
        .read(&evidence, &stdout_name, BOUND)?
        .ok_or_else(|| Error::Held("probe listing missing".into()))?;
    let worker = artifact
        .record()
        .workers
        .get(&phase)
        .ok_or_else(|| Error::Held("probe worker missing".into()))?;
    if artifact.record().archive != Some(archive)
        || artifact.record().class.as_str() != "counts"
        || artifact.record().command.as_str() != "capabilities"
        || artifact.record().run_id.as_str() != "probe"
        || worker.ended.as_str() != "exited"
        || worker.stdout != Digest::of(stdout.bytes())
        || worker.exit != Some(0)
        || worker.signal.is_some()
    {
        return Err(Error::Held("capability artifact binding differs".into()));
    }
    store.barrier(artifact.read())?;
    store.barrier(&stdout)?;
    let listing =
        std::str::from_utf8(stdout.bytes()).map_err(|e| Error::Rejected(e.to_string()))?;
    Listing::parse(listing)
        .map(|listing| (archive, listing))
        .map_err(|error| Error::Rejected(error.to_string()))
}

/// The archive build and capability listing of the completed, released
/// probe `directory` of `attempt`, which `report` declares the build's
/// profiles from.
///
/// # Errors
///
/// As [`released`] and [`read_listing`], and [`Error::Held`] for missing
/// evidence or an artifact record that names no build.
pub(super) fn build_listing(
    store: &impl crate::store::ReadStore,
    directory: &Dir,
    attempt: &crate::record::Text,
) -> Result<(Digest, Listing), Error> {
    released(store, directory, attempt)?;
    listing(store, directory, None)
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod tests;
