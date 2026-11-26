//! `campaign confirm`: the supervised jobs of a sweep's suspects.
//!
//! A sweep root's `suspects.jsonl` names runs by campaign, profile, run and
//! counts, each with the root the sweep ran and the build of its archive.
//! `confirm` admits each one the root has not confirmed yet as an ordinary
//! campaign job in the state directory `confirm/state` under the root and
//! dispatches them, so each listed suspect runs as a supervised job, which
//! records a bundle and, when it fails, a finding that triage reads. The
//! job of a suspect whose replay differs runs the same manifest in a new
//! process, as the replay did, so it passes when the run passes there, and
//! the disagreement stays in the sweep's list and totals. A
//! job's seed depends on its archive, so `confirm` rejects a list whose
//! suspects name another build than its archive's, and holds on one
//! whose job has another seed than the swept root, before it admits any. A
//! suspect admission refuses, such as a run of a control profile, is
//! reported and passed over. The first call configures that state
//! directory with its slot count; later calls keep the stored
//! configuration. `confirm/confirmed` holds the number of suspect lines
//! read so far and is replaced after each dispatch, so a rerun admits only
//! later suspects. A dispatch that a refusal or a rejection stopped fails
//! the command, and its admitted jobs stay queued for the next call's
//! dispatch. A job admitted twice is one job: admission of an existing job
//! changes nothing.
//!
//! The controller needs a delegated cgroup. With none given, the command
//! line runs the command again in a delegated systemd scope, as
//! [`super::scope`] describes, and the controller uses that scope's cgroup.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use super::dispatch::Report;
use super::seeds::Suspect;
use super::{Error, Request, name};
use crate::protocol::Listing;
use crate::record::{Configuration, Pins, Purpose, Text};
use crate::store::Store;

fn held(error: std::io::Error) -> Error {
    Error::Held(error.to_string())
}

/// Whether `error` is custody's refusal to start work after a signal.
fn interrupted(error: &Error) -> bool {
    matches!(error, Error::Held(reason) | Error::Custody(reason) if reason.contains("interruption"))
}

/// The configuration of a state directory with `slots` attempts and one
/// triage step, one core and 2 GiB each.
///
/// # Errors
///
/// [`Error::Rejected`] for a slot count whose cores or memory pass a
/// `u64`, and for a configuration [`prepare`](super::configuration::prepare)
/// refuses.
fn configuration(slots: u64) -> Result<Configuration, Error> {
    let tree_memory = 2 << 30;
    let shares = slots.checked_add(1);
    let memory = shares.and_then(|shares| shares.checked_mul(tree_memory));
    let (Some(shares), Some(memory)) = (shares, memory) else {
        return Err(Error::Rejected(format!(
            "{slots} slots need more cores or memory than a configuration holds"
        )));
    };
    let settings = [
        ("slots", slots),
        ("reserve_slots", 1),
        ("cores", shares),
        ("memory", memory),
        ("tree_memory", tree_memory),
        ("cpu", 600),
        ("wall", 600),
        ("processes", 256),
        ("attempt_output", 256 << 20),
        ("attempt_inodes", 1000),
        ("artifact_bytes", 6 << 40),
        ("artifact_inodes", 50_000_000),
        ("backlog", 64),
        ("retained_builds", 2),
    ];
    super::configuration::prepare(
        settings
            .into_iter()
            .map(|(key, value)| Ok((super::text(key)?, value)))
            .collect::<Result<_, Error>>()?,
    )
}

/// What `confirm` did, as the command prints it, and the failure of a
/// dispatch that a refusal or a rejection stopped.
pub(super) struct Confirmed {
    pub value: Value,
    pub stopped: Option<Error>,
}

/// The reasons of refused suspects the output lists.
const REASONS: usize = 16;

/// Admits each of `suspects` as a campaign job of the archive whose
/// listing and pins are given, and returns the reason of each one
/// admission refuses, such as a suspect of a control profile, which a
/// campaign cannot hold. The archive is checked against `swept`, the
/// build the sweep root is bound to, whatever the suspects, and every
/// suspect is checked against the archive before the first is admitted:
/// it names the archive's build, and the job the archive freezes for it
/// has the root the sweep ran as its seed.
///
/// # Errors
///
/// [`Error::Rejected`] when the archive is of another build than the
/// root's, or a suspect names the build of another archive,
/// whose jobs for the same runs have other seeds; [`Error::Held`] when a
/// suspect's job has another seed than its swept root; or a store error.
/// The first two admit nothing.
fn admit_suspects(
    store: &Store,
    listing: &Listing,
    pins: &Pins,
    archive: &Text,
    swept: &Text,
    suspects: &[Suspect],
) -> Result<Vec<String>, Error> {
    if *swept != pins.build {
        return Err(Error::Rejected(format!(
            "this root holds the sweeps of an archive of build {}; this archive is build {}",
            swept.as_str(),
            pins.build.as_str()
        )));
    }
    let named = |suspect: &Suspect| {
        let Request { profile, run, .. } = &suspect.request;
        format!("run {run} of {}", profile.as_str())
    };
    for suspect in suspects {
        if suspect.build != pins.build {
            return Err(Error::Rejected(format!(
                "{} was swept from another archive, of build {}; this archive is build {}",
                named(suspect),
                suspect.build.as_str(),
                pins.build.as_str()
            )));
        }
        // A request the archive does not freeze is refused by its admission.
        if let Ok((job, _)) = super::freeze::freeze(listing, pins.clone(), &suspect.request)
            && job.seed() != suspect.seed
        {
            return Err(Error::Held(format!(
                "{} ran root {} in the sweep, and its job has seed {}",
                named(suspect),
                suspect.seed,
                job.seed()
            )));
        }
    }
    let mut refused = Vec::new();
    for suspect in suspects {
        let admitted = super::admit(
            store,
            listing,
            pins.clone(),
            archive.clone(),
            &suspect.request,
            Purpose::Campaign,
        );
        match admitted {
            Ok(_) => {}
            Err(Error::Rejected(reason)) => refused.push(format!("{}: {reason}", named(suspect))),
            Err(error) => return Err(error),
        }
    }
    Ok(refused)
}

/// One window on `store`: one admission probe, the admission of each of
/// `suspects`, and one dispatch that runs until its queue is empty.
/// Returns the reasons of the suspects admission refused and the dispatch
/// report, or `None` when a signal arrived before the probe started.
///
/// # Errors
///
/// An archive the admission probe refuses, the errors of
/// [`admit_suspects`], or a store or custody error.
fn window_of(
    store: &Store,
    archive: &Path,
    cgroup: &Path,
    executable: &Path,
    swept: &Text,
    suspects: &[Suspect],
) -> Result<Option<(Vec<String>, Report)>, Error> {
    let probed = match super::probe::probe(store, archive, cgroup, Duration::from_secs(300)) {
        Err(error) if interrupted(&error) => return Ok(None),
        probed => probed?,
    };
    let path = super::text(
        probed
            .archive
            .to_str()
            .ok_or_else(|| Error::Rejected("archive path must be ASCII".into()))?,
    )?;
    let refused = admit_suspects(store, &probed.listing, &probed.pins, &path, swept, suspects)?;
    let mut custody = crate::custody::Custody::open(
        cgroup,
        crate::custody::Timing {
            poll: Duration::from_millis(50),
            kill_wait: Duration::from_secs(5),
            watchdog: Duration::from_secs(300),
        },
    )?;
    let report = super::dispatch::dispatch(
        store,
        &mut custody,
        &super::dispatch::Options {
            archive: archive.to_owned(),
            gate: executable.to_owned(),
            launcher: executable.to_owned(),
            environment: BTreeMap::new(),
            deadline: None,
            max_attempts: None,
        },
    )?;
    Ok(Some((refused, report)))
}

/// The output of a `confirm` whose window admitted `admitted` suspects,
/// refused those of `refused` and ended with `report`, over the state
/// directory `state` and its `findings`. It lists the first [`REASONS`]
/// refused suspects.
fn outcome(
    state: &Path,
    admitted: usize,
    refused: &[String],
    report: &Report,
    findings: Value,
) -> Confirmed {
    Confirmed {
        value: json!({
            "state": state,
            "suspects": admitted,
            "refused": refused.len(),
            "refused_reasons": refused.iter().take(REASONS).collect::<Vec<_>>(),
            "counts": report.counts,
            "dispatch": report.state,
            "refusals": report.refusals,
            "rejections": report.rejections,
            "findings": findings,
        }),
        stopped: report.failure(),
    }
}

/// Admits every suspect of the sweep root `root` that no earlier call
/// read as a supervised job in `root/confirm/state`, dispatches them, and
/// returns the dispatch counts with the state's findings and the suspects
/// admission refused. `slots` configures the state directory when it holds
/// no configuration. A signal that arrives before the admission probe
/// starts returns `"dispatch": "interrupted"` and admits nothing. One
/// that stops the running probe fails the command with the probe's hold,
/// as it fails `admit`, and admits nothing. A dispatch that
/// a refusal or a rejection stopped leaves its admitted jobs queued for
/// the next call's dispatch and is the returned value's `stopped`.
///
/// # Errors
///
/// A root no sweep has written or a root a sweep's failed closing
/// verification marked ([`Error::Rejected`]), a root that fails the rules
/// of [`crate::store::private_dir`], a
/// `confirm/confirmed` or suspect list that does not parse, a suspect
/// list another archive's sweep wrote ([`Error::Rejected`]) or whose job
/// has another seed than its swept root ([`Error::Held`]), an archive the
/// admission probe refuses, or a store or custody error.
/// Confirmation propagates errors from the sweep checkpoint reader.
pub(super) fn confirm(
    root: &Path,
    archive: &Path,
    cgroup: PathBuf,
    slots: u64,
) -> Result<Confirmed, Error> {
    // A sweep writes `sweep.json` before its first worker starts, so a
    // root without one holds no suspect, and nothing is created under it.
    let unswept = || Error::Rejected("the root holds no sweep".into());
    let bound = super::seeds::CHECKPOINT_BOUND;
    if crate::store::read_host(&root.join("sweep.json"), bound)?.is_none() {
        return Err(unswept());
    }
    drop(crate::store::private_dir(root).map_err(Error::input_path)?);
    let swept = super::seeds::build(root)?.ok_or_else(unswept)?;
    crate::custody::Custody::check_root(&cgroup)?;
    let dir = root.join("confirm");
    let state = dir.join("state");
    crate::store::create_dirs(&state).map_err(held)?;
    let confirmed = match crate::store::read_host(&dir.join("confirmed"), 64)? {
        None => 0,
        Some(bytes) => String::from_utf8_lossy(&bytes)
            .trim()
            .parse::<usize>()
            .map_err(|error| Error::Held(format!("confirm/confirmed: {error}")))?,
    };
    let (suspects, lines) = super::seeds::suspects(root, confirmed)?;
    let store = Store::open(&state)?;
    store.check_path()?;
    if store
        .read_record::<Configuration>(store.root(), &name("config.json"))?
        .is_none()
    {
        super::configure(&store, configuration(slots)?)?;
    }
    let executable = crate::store::canonical_host(Path::new("/proc/self/exe")).map_err(held)?;
    let window = window_of(&store, archive, &cgroup, &executable, &swept, &suspects)?;
    drop(store);
    let Some((refused, report)) = window else {
        return Ok(Confirmed {
            value: json!({"state": state, "dispatch": "interrupted"}),
            stopped: None,
        });
    };
    crate::store::replace_host(&dir.join("confirmed"), lines.to_string().as_bytes())
        .map_err(held)?;
    let findings = super::findings(&state)?;
    Ok(outcome(
        &state,
        suspects.len() - refused.len(),
        &refused,
        &report,
        findings,
    ))
}

#[cfg(test)]
#[path = "confirm_tests.rs"]
mod tests;
