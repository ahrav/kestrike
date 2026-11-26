//! The charged census of a state directory: the entries `dispatch` and
//! admission plan storage against. It counts the entries of each `jobs/`
//! shard, the attempt directories under each `attempts/` shard and the
//! directories of `probes/`, and charges each at a declared rate, so its cost follows
//! the count of those listed entries, with bounded retained-layout listings,
//! record reads and bulk-name opens for marked attempts. Free bytes and inodes are measured.
//! The census charges only `jobs/`, `attempts/` and `probes/`; the measured
//! `disk` and `disk_inodes` dimensions cover every other root and root
//! file, `findings/` and `triage/` among them.
//!
//! Custody samples output. An attempt or probe stopped for output limits
//! retains the data written between samples, which can exceed its declared
//! charge; measured `disk` and `disk_inodes` cover that excess.

use super::{Error, name};
use crate::record::{Admission, Configuration};
use crate::store::{Dir, ReadStore, Unreadable, Usage};

/// The counted entries of one census.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Census {
    /// Entries of each `jobs/` shard, by shard name.
    jobs: std::collections::BTreeMap<String, u64>,
    /// The file lengths of those entries.
    job_bytes: u128,
    /// Concluded attempt directories, each counted at its job's fork
    /// shares.
    attempt_shares: u64,
    /// Reclaimed attempt directories, each counted at its job's fork
    /// shares and charged for their records and retained report streams.
    reclaimed_shares: u64,
    /// Admission probe directories of `probes/`.
    probes: u64,
    /// Corpus probe directories of `probes/`.
    corpus_probes: u64,
}

impl Census {
    /// A caller counts while all its attempts are released.
    pub(crate) fn count(view: &impl ReadStore) -> Result<Self, Error> {
        let mut census = Self {
            jobs: std::collections::BTreeMap::new(),
            job_bytes: 0,
            attempt_shares: 0,
            reclaimed_shares: 0,
            probes: 0,
            corpus_probes: 0,
        };
        let jobs = crate::layout::JOBS;
        for shard in crate::layout::shards(view, jobs).map_err(|error| unlisted(jobs, error))? {
            let shard = shard.map_err(|error| failed(jobs, error.into()))?;
            for entry in listed(view, &shard.dir, &shard.path)? {
                let file = opened(view.open_file(&shard.dir, &entry), || {
                    format!("{}/{}", shard.path, entry.as_str())
                })?;
                if let Some(file) = file {
                    census.published(shard.name.as_str(), file.len())?;
                }
            }
        }
        let marker_name = name("reclaimed");
        let attempts = crate::layout::ATTEMPTS;
        for shard in
            crate::layout::shards(view, attempts).map_err(|error| unlisted(attempts, error))?
        {
            let shard = shard.map_err(|error| failed(attempts, error.into()))?;
            for entry in listed(view, &shard.dir, &shard.path)? {
                let root = format!("{}/{}", shard.path, entry.as_str());
                if !shard.holds(entry.as_str()) {
                    let error = crate::store::Error::Foreign(root.clone()).into();
                    return Err(failed(&root, error));
                }
                let Some(history) = opened(view.open_dir(&shard.dir, &entry), || root.clone())?
                else {
                    continue;
                };
                let numbers = listed(view, &history, &root)?;
                if numbers.is_empty() {
                    continue;
                }
                let shares = shares(view, entry.as_str())?;
                let mut reclaimed = 0u64;
                for number in &numbers {
                    let path = format!("{root}/{}", number.as_str());
                    let attempt = match view.open_dir(&history, number) {
                        Ok(attempt) => attempt,
                        Err(error) if !error.faulted() => continue,
                        Err(error) => return Err(failed(&path, error.into())),
                    };
                    if let Some(attempt) = attempt
                        && reclaim_complete(
                            view,
                            &attempt,
                            entry.as_str(),
                            number,
                            &marker_name,
                            &path,
                        )?
                    {
                        reclaimed += 1;
                    }
                }
                let concluded = numbers.len() as u64 - reclaimed;
                census.attempt_shares = census
                    .attempt_shares
                    .saturating_add(concluded.saturating_mul(shares));
                census.reclaimed_shares = census
                    .reclaimed_shares
                    .saturating_add(reclaimed.saturating_mul(shares));
            }
        }
        let probes = opened(view.open_dir(view.root(), &name("probes")), || {
            "probes".into()
        })?;
        if let Some(probes) = probes {
            for entry in listed(view, &probes, "probes")? {
                if super::corpus::is_probe(entry.as_str()) {
                    census.corpus_probes += 1;
                } else {
                    census.probes += 1;
                }
            }
        }
        Ok(census)
    }

    /// The session census in `slot`, counted on `view` and kept there when
    /// `slot` holds none, so every storage decision of one session reads
    /// the cached count. A productive dispatch collect pass invalidates it.
    ///
    /// # Errors
    ///
    /// [`Census::count`]'s errors; a failed count leaves `slot` empty.
    pub(crate) fn cached(slot: &mut Option<Self>, view: &impl ReadStore) -> Result<Self, Error> {
        Ok(match slot {
            Some(census) => census.clone(),
            None => slot.insert(Self::count(view)?).clone(),
        })
    }

    /// The charged bytes and inodes under `config`, with the free space
    /// measured now on `view`'s filesystem.
    ///
    /// # Errors
    ///
    /// [`Error::Bound`] when the counted entries of a `jobs/` shard reach the
    /// scan bound,
    /// and a state-wide [`Error::Store`] naming `fstatvfs` when the
    /// free-space query fails.
    pub(crate) fn usage(
        &self,
        view: &impl ReadStore,
        config: &Configuration,
    ) -> Result<Usage, Error> {
        for (shard, entries) in &self.jobs {
            if *entries >= crate::scan_bound() as u64 {
                return Err(Error::bound(&format!("jobs/{shard}"), *entries as usize));
            }
        }
        let attempt = config.retained_charge();
        let reclaimed = config.reclaimed_charge();
        let corpus = config.charge();
        let attempts = u128::from(self.attempt_shares);
        let reclaimed_attempts = u128::from(self.reclaimed_shares);
        let corpus_probes = u128::from(self.corpus_probes);
        let probes = u128::from(self.probes);
        let bytes = self.job_bytes
            + attempts * attempt.bytes
            + reclaimed_attempts * reclaimed.bytes
            + corpus_probes * corpus.bytes
            + probes * u128::from(super::probe::OUTPUT_BYTES);
        let inodes = u128::from(self.jobs.values().sum::<u64>())
            + attempts * attempt.inodes
            + reclaimed_attempts * reclaimed.inodes
            + corpus_probes * corpus.inodes
            + probes * u128::from(super::probe::OUTPUT_INODES);
        let (free_bytes, free_inodes, fragment_bytes) =
            view.root().free_space().map_err(|error| {
                Error::Store(crate::store::Error::Io(std::io::Error::new(
                    error.kind(),
                    format!("fstatvfs of the state directory failed: {error}"),
                )))
            })?;
        Ok(Usage {
            bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
            inodes: u64::try_from(inodes).unwrap_or(u64::MAX),
            free_bytes,
            free_inodes,
            fragment_bytes,
        })
    }

    /// Charges one attempt of a job with `shares` fork shares that left the
    /// running set.
    pub(crate) fn concluded(&mut self, shares: u64) {
        self.attempt_shares = self.attempt_shares.saturating_add(shares);
    }

    /// Charges one `jobs/` record of `bytes` bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Bound`] when the shard's updated count reaches the scan
    /// bound.
    pub(crate) fn published(&mut self, shard: &str, bytes: u64) -> Result<(), Error> {
        let entries = self.jobs.entry(shard.to_owned()).or_insert(0);
        *entries += 1;
        let entries = *entries;
        self.job_bytes += u128::from(bytes);
        if entries >= crate::scan_bound() as u64 {
            return Err(Error::bound(&format!("jobs/{shard}"), entries as usize));
        }
        Ok(())
    }
}

/// The reduced charge applies after a canonical, bound reclaim has removed
/// every bulk file. Record and file opens preserve the store's confinement.
fn reclaim_complete(
    view: &impl ReadStore,
    attempt: &Dir,
    job: &str,
    number: &crate::store::Name,
    marker_name: &crate::store::Name,
    path: &str,
) -> Result<bool, Error> {
    let checked = (|| -> Result<bool, Error> {
        let Some(number_value) = number
            .as_str()
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0 && format!("{value:04}") == number.as_str())
        else {
            return Ok(false);
        };
        let Some(marker) = super::reclaim::checked(
            view.read_record::<crate::record::Reclaimed>(attempt, marker_name),
            &format!("{path}/reclaimed"),
        )?
        else {
            return Ok(false);
        };
        let Some(finished) = super::reclaim::checked(
            view.read_record::<crate::record::Finished>(attempt, &name("finished")),
            &format!("{path}/finished"),
        )?
        else {
            return Ok(false);
        };
        super::reclaim::check_entries(view, attempt, path)?;
        let prepared = super::reclaim::prepare(view, attempt, job, number_value, &finished, path)?;
        if marker.record() != &prepared.marker {
            return Ok(false);
        }
        let evidence_path = format!("{path}/artifacts/{}", finished.record().attempt.as_str());
        for entry in &prepared.bulk {
            let entry_path = format!("{evidence_path}/{}", entry.as_str());
            if super::reclaim::checked(view.open_file(&prepared.directory, entry), &entry_path)?
                .is_some()
            {
                return Ok(false);
            }
        }
        for entry in crate::custody::LAUNCHER_OUTPUTS {
            let entry_path = format!("{path}/{entry}");
            if super::reclaim::checked(view.open_file(attempt, &name(entry)), &entry_path)?
                .is_some()
            {
                return Ok(false);
            }
        }
        Ok(true)
    })();
    match checked {
        Err(error) if !error.host_fault() => Ok(false),
        result => result,
    }
}

/// The census of `view` under `config`, counted afresh.
pub(crate) fn census(view: &impl ReadStore, config: &Configuration) -> Result<Usage, Error> {
    Census::count(view)?.usage(view, config)
}

/// Holds when attempt `number` of job `id` fills that job's attempt
/// listing to the scan bound, as a fresh count of the tree would. Attempt
/// histories are dense from 1, so `number` is the listing's length.
///
/// # Errors
///
/// [`Error::Bound`] naming `attempts/<xx>/<id>` at the bound.
pub(crate) fn minted(id: &str, number: u64) -> Result<(), Error> {
    if number >= crate::scan_bound() as u64 {
        return Err(Error::bound(&history(id), number as usize));
    }
    Ok(())
}

/// The fork shares each attempt of the nonempty history of job `id` is
/// charged at, read from `<id>.json` in the job's `jobs/` shard, the
/// admission record bound to `id`.
///
/// # Errors
///
/// A state-wide [`Error::Census`] naming the record when its read fails,
/// and naming the history when the shard or the record is absent, the
/// record name is invalid, or the record admits another job.
fn shares(view: &impl ReadStore, id: &str) -> Result<u64, Error> {
    let file = format!("{id}.json");
    let path = crate::layout::job_file(id, &file).display().to_string();
    let unbound = || {
        failed(
            &history(id),
            Error::Held(format!(
                "history has no admission record {path} bound to its job"
            )),
        )
    };
    let jobs = opened(crate::layout::jobs(view, id), || {
        format!(
            "{}/{}",
            crate::layout::JOBS,
            crate::layout::shard(id).as_str()
        )
    })?;
    let (Some(jobs), Some(record)) = (jobs, crate::store::Name::new(&file)) else {
        return Err(unbound());
    };
    let job = view
        .read_record::<Admission>(&jobs, &record)
        .map_err(|error| failed(&path, error.into()))?
        .filter(|job| job.record().job().id().to_string() == id)
        .ok_or_else(unbound)?;
    Ok(job.record().shares())
}

/// `attempts/<xx>/<id>`, the attempt history of job `id`.
fn history(id: &str) -> String {
    format!(
        "{}/{}/{id}",
        crate::layout::ATTEMPTS,
        crate::layout::shard(id).as_str()
    )
}

/// A census failure while reading `path`: a state-wide contextual error, so
/// every caller holds on it, whose text names `path`.
fn failed(path: &str, cause: Error) -> Error {
    Error::Census {
        path: path.to_owned(),
        cause: Box::new(cause),
    }
}

/// A failed listing of `root`: the bound hold past the scan bound, and a
/// census failure naming `root` otherwise.
fn unlisted(root: &str, error: crate::store::Error) -> Error {
    match error {
        crate::store::Error::ScanBound => Error::over(root),
        error => failed(root, error.into()),
    }
}

/// `open`'s result, with a failed open made a state-wide contextual error naming
/// the entry `path` returns.
fn opened<T>(open: Result<T, Unreadable>, path: impl FnOnce() -> String) -> Result<T, Error> {
    open.map_err(|error| failed(&path(), error.into()))
}

/// The entries of `directory`, the root named `root`, held at the scan
/// bound.
fn listed(
    view: &impl ReadStore,
    directory: &Dir,
    root: &str,
) -> Result<Vec<crate::store::Name>, Error> {
    let entries = view
        .list(directory, crate::scan_bound())
        .map_err(|error| unlisted(root, error))?;
    if entries.len() >= crate::scan_bound() {
        return Err(Error::bound(root, entries.len()));
    }
    Ok(entries)
}

#[cfg(test)]
#[path = "census_tests.rs"]
mod tests;
