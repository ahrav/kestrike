use std::collections::BTreeSet;

use super::{Error, name};
use crate::custody::{Custody, Limits};
use crate::record::{Admission, Configuration, Digest};
use crate::store::{Store, Usage};

pub(super) fn builds(
    queue: &[&Admission],
    running: bool,
    build: Digest,
    maximum: u64,
) -> (Vec<&'static str>, bool) {
    let selected = build.to_string();
    let mut seen = BTreeSet::new();
    let mut ordered = Vec::new();
    if running {
        seen.insert(selected.clone());
        ordered.push(selected.clone());
    }
    for job in queue {
        let build = job.job().experiment().pins.build.as_str();
        if seen.insert(build.to_owned()) {
            ordered.push(build.to_owned());
        }
    }
    let allowed: Vec<_> = ordered.iter().take(maximum as usize).collect();
    let mut reasons = Vec::new();
    if ordered.len() > allowed.len() {
        reasons.push("retained_builds");
    }
    if allowed.iter().any(|build| *build != &selected) {
        reasons.push("archive");
    }
    (reasons, allowed.contains(&&selected))
}

/// The storage dimensions that pause a start. `usage` carries the counted
/// bytes and inodes the `artifact_*` limits bound, the charged census for
/// dispatch and triage and a measured walk for hardware admission, with
/// measured free space. `charged` counts the fork shares already running or
/// committed beside the start, each at the in-flight charge, with
/// `reserve_slots` more reserved.
pub(crate) fn storage_pauses(
    config: &Configuration,
    usage: Usage,
    charged: u64,
    reserve_slots: u64,
) -> BTreeSet<String> {
    let mut full = BTreeSet::new();
    let charge = config.charge();
    let share = charge.bytes;
    let inodes = charge.inodes;
    let disk = charge.disk(usage.fragment_bytes);
    let reserve = u128::from(reserve_slots);
    let need_bytes = (u128::from(charged) + 1) * share;
    let need_inodes = (u128::from(charged) + 1) * inodes;
    for (reason, pause) in [
        (
            "artifact_bytes",
            u128::from(usage.bytes) + need_bytes + reserve * share
                >= u128::from(config.value("artifact_bytes")),
        ),
        (
            "artifact_inodes",
            u128::from(usage.inodes) + need_inodes + reserve * inodes
                >= u128::from(config.value("artifact_inodes")),
        ),
        (
            "disk",
            u128::from(usage.free_bytes) <= (u128::from(charged) + 1 + reserve) * disk,
        ),
        (
            "disk_inodes",
            u128::from(usage.free_inodes) <= need_inodes + reserve * inodes,
        ),
    ] {
        if pause {
            full.insert(reason.to_owned());
        }
    }
    full
}

/// Counts failure pins whose finding lacks a latest `resolved` disposition.
/// Each pin's file name selects its job; a missing finding directory counts.
///
/// # Errors
///
/// A named hold for a misbound pin, damaged finding or disposition history,
/// a `jobs/` listing past the bound, or the underlying read error.
pub(crate) fn backlog(store: &Store) -> Result<u64, Error> {
    let findings = store.open_dir(store.root(), &name("findings"))?;
    let mut count = 0;
    for shard in crate::campaign::sharded(store, crate::layout::JOBS)? {
        let shard = shard?;
        let directory = &shard.dir;
        for entry in crate::campaign::shard_entries(store, &shard)? {
            let Some(id) = entry.as_str().strip_suffix(crate::record::Pin::SUFFIX) else {
                continue;
            };
            let (_, finding) = store
                .read_record::<crate::record::Pin>(directory, &entry)
                .map_err(Error::from)
                .and_then(|pin| pin.ok_or_else(|| Error::Held("failure pin vanished".into())))
                .and_then(|pin| crate::campaign::findings::bound_finish(id, &pin.record().result))
                .map_err(|error| error.about(format_args!("failure pin {}", entry.as_str())))?;
            if !crate::campaign::findings::resolved(store, findings.as_ref(), &finding)
                .map_err(|error| error.about(format_args!("finding {finding}")))?
            {
                count += 1;
            }
        }
    }
    Ok(count)
}

/// The hold for `backlog` failure pins without a resolved disposition at or
/// past the configured limit.
pub(in crate::campaign) fn backlog_hold(config: &Configuration, backlog: u64) -> Result<(), Error> {
    let limit = config.value("backlog");
    if backlog >= limit {
        return Err(Error::Held(format!(
            "backlog holds {backlog} failure pins without a resolved disposition at limit {limit}; dispose findings or raise backlog"
        )));
    }
    Ok(())
}

pub(in crate::campaign) fn ancestor_fit(
    custody: &Custody,
    limits: Limits,
    config: &Configuration,
) -> Result<(), Error> {
    let shares = u128::from(config.value("slots")) + u128::from(config.value("reserve_slots"));
    custody
        .validate_limits(limits, shares)
        .map_err(|error| match error {
            crate::store::cgroup::FitError::Limit { resource, ancestor } => {
                Error::Rejected(format!(
                    "{resource} limit must be strictly below ancestor {}",
                    ancestor.display()
                ))
            }
            crate::store::cgroup::FitError::Io(error) => {
                Error::Store(crate::store::Error::Io(error))
            }
        })
}

/// Requests every running tree stop when the aggregate no longer fits its
/// ancestor.
pub(in crate::campaign) fn fit_or_stop(
    custody: &Custody,
    limits: Limits,
    config: &Configuration,
    running: &mut [crate::custody::Running],
    steps: usize,
) -> Result<(), Error> {
    let reserve = config.value("reserve_slots").saturating_sub(steps as u64);
    let aggregate = aggregate(
        limits,
        running.iter().map(|process| process.limits()),
        reserve,
        config.value("slots") + config.value("reserve_slots"),
    )?;
    let fitted = custody
        .validate_limits(aggregate, 1)
        .map_err(|error| match error {
            crate::store::cgroup::FitError::Limit { resource, ancestor } => {
                Error::Rejected(format!(
                    "{resource} limit must be strictly below ancestor {}",
                    ancestor.display()
                ))
            }
            crate::store::cgroup::FitError::Io(error) => {
                Error::Store(crate::store::Error::Io(error))
            }
        });
    if matches!(fitted, Err(Error::Rejected(_))) {
        for process in running.iter_mut() {
            process.request_stop();
        }
    }
    fitted
}

/// Sums installed resource limits and the unoccupied reserve, preserving the configured floor.
pub(in crate::campaign) fn aggregate(
    base: Limits,
    installed: impl Iterator<Item = Limits>,
    reserve: u64,
    floor: u64,
) -> Result<Limits, Error> {
    let mut cpu = u128::from(reserve) * u128::from(base.cpu_quota_us);
    let mut memory = u128::from(reserve) * u128::from(base.memory_bytes);
    let mut pids = u128::from(reserve) * u128::from(base.pids);
    for limits in installed {
        cpu += u128::from(limits.cpu_quota_us);
        memory += u128::from(limits.memory_bytes);
        pids += u128::from(limits.pids);
    }
    let mut limits = base;
    limits.cpu_quota_us = u64::try_from(cpu.max(u128::from(floor) * u128::from(base.cpu_quota_us)))
        .map_err(|_| Error::Rejected("aggregate CPU overflows".into()))?;
    limits.memory_bytes =
        u64::try_from(memory.max(u128::from(floor) * u128::from(base.memory_bytes)))
            .map_err(|_| Error::Rejected("aggregate memory overflows".into()))?;
    limits.pids = u64::try_from(pids.max(u128::from(floor) * u128::from(base.pids)))
        .map_err(|_| Error::Rejected("aggregate pids overflows".into()))?;
    Ok(limits)
}
