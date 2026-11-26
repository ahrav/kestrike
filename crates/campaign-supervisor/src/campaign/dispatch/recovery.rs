use std::collections::{BTreeMap, BTreeSet};

use super::{Error, Report, name};
use crate::attempt::{self, Attempt};
use crate::custody::Custody;
use crate::record::{Admission, Digest, JobResult, Verified};
use crate::store::{Dir, Store};

/// The lengths of the records one settlement published in `jobs/`.
pub(super) struct Published {
    pub pin: Option<u64>,
    pub result: Option<u64>,
}

/// The jobs of a dispatch session. Records are read for unsettled jobs
/// only; a job with a result record is settled by its name, and its records
/// and attempts are left unread. `settled` names the jobs this session
/// settled.
pub(super) struct Jobs {
    pub records: BTreeMap<String, Admission>,
    pub counts: BTreeMap<String, u64>,
    pub settled: BTreeSet<String>,
    pub excluded: BTreeSet<String>,
}

impl Jobs {
    /// Loads the jobs one shard at a time, so memory holds one shard's
    /// names beside the unsettled jobs.
    pub fn load(store: &Store, report: &mut Report) -> Result<Option<Self>, Error> {
        let present = store.open_dir(store.root(), &name("jobs"))?.is_some();
        let mut jobs = Self {
            records: BTreeMap::new(),
            counts: BTreeMap::new(),
            settled: BTreeSet::new(),
            excluded: BTreeSet::new(),
        };
        let mut listed = BTreeSet::new();
        for shard in crate::campaign::sharded(store, crate::layout::JOBS)? {
            let shard = match shard {
                Err(crate::store::Error::Foreign(path)) => {
                    report.refuse(format!("unknown job entry {path}"));
                    continue;
                }
                shard => shard?,
            };
            let mut ids = BTreeSet::new();
            let mut settled = BTreeSet::new();
            for entry in crate::campaign::shard_entries(store, &shard)? {
                let value = entry.as_str();
                match crate::campaign::admission::job_id(value) {
                    Some(id) if !shard.holds(id) => {
                        report.refuse(format!(
                            "job entry {}/{value} outside its shard",
                            shard.path
                        ));
                    }
                    Some(id) => {
                        if value.ends_with(JobResult::SUFFIX) && Digest::parse(id).is_some() {
                            settled.insert(id.to_owned());
                        }
                        ids.insert(id.to_owned());
                    }
                    None => report.refuse(format!("unknown job entry {value}")),
                }
            }
            let unsettled: Vec<_> = ids.difference(&settled).cloned().collect();
            for id in unsettled {
                let result = (|| -> Result<Option<Verified<Admission>>, Error> {
                    let job = jobs.admission(store, &id)?;
                    match crate::attempt::frozen_manifest(
                        store,
                        &directory(store, &id)?,
                        job.record(),
                    )
                    .map_err(Error::from)
                    {
                        Ok(()) => Ok(Some(job)),
                        Err(error @ Error::Held(_)) => {
                            if crate::attempt::queued_target(store, job.record())? {
                                report.unfit.insert(id.clone(), error.to_string());
                                jobs.excluded.insert(id.clone());
                                Ok(None)
                            } else {
                                Err(error)
                            }
                        }
                        Err(error) => Err(error),
                    }
                })();
                match result {
                    Ok(Some(job)) => {
                        jobs.records.insert(id, job.record().clone());
                    }
                    Ok(None) => {}
                    Err(error) => report.refuse(format!("job {id}: {error}")),
                }
            }
            let name = shard.name.clone();
            match crate::layout::shard_dir(store, crate::layout::ATTEMPTS, name.as_str()) {
                Ok(Some(dir)) => {
                    let path = format!("attempts/{}", name.as_str());
                    let attempts = crate::layout::Shard { name, dir, path };
                    jobs.check_histories(store, &attempts, &settled, report)?;
                }
                Err(error) if error.faulted() => return Err(error.into()),
                // The `attempts/` pass below refuses an entry that is no directory.
                _ => {}
            }
            listed.insert(shard.name);
        }
        for shard in crate::campaign::sharded(store, crate::layout::ATTEMPTS)? {
            let shard = match shard {
                Err(crate::store::Error::Foreign(path)) => {
                    report.refuse(format!("attempts without readable job {path}"));
                    continue;
                }
                shard => shard?,
            };
            if !listed.contains(&shard.name) {
                jobs.check_histories(store, &shard, &BTreeSet::new(), report)?;
            }
        }
        Ok(present.then_some(jobs))
    }

    /// Refuses every attempt history in `shard` whose job is neither loaded,
    /// excluded, nor among the shard's `settled` names, or that sits outside
    /// its job's shard.
    fn check_histories(
        &self,
        store: &Store,
        shard: &crate::layout::Shard,
        settled: &BTreeSet<String>,
        report: &mut Report,
    ) -> Result<(), Error> {
        for entry in crate::campaign::shard_entries(store, shard)? {
            let id = entry.as_str();
            let readable =
                self.records.contains_key(id) || self.excluded.contains(id) || settled.contains(id);
            if !readable || !shard.holds(id) {
                report.refuse(format!("attempts without readable job {id}"));
            }
        }
        Ok(())
    }

    pub fn read(&self, store: &Store, id: &str) -> Result<Verified<Admission>, Error> {
        let found = self.admission(store, id)?;
        crate::attempt::frozen_manifest(store, &directory(store, id)?, found.record())?;
        Ok(found)
    }

    fn admission(&self, store: &Store, id: &str) -> Result<Verified<Admission>, Error> {
        if Digest::parse(id).is_none() {
            return Err(Error::Held("invalid job identity filename".into()));
        }
        let found = store
            .read_record::<Admission>(&directory(store, id)?, &name(&format!("{id}.json")))?
            .ok_or_else(|| Error::Held("job record missing".into()))?;
        if found.record().job().id().to_string() != id {
            return Err(Error::Held("job binding differs".into()));
        }
        store.barrier(found.read())?;
        Ok(found)
    }

    pub fn reconcile(
        &mut self,
        store: &Store,
        custody: &mut Custody,
        report: &mut Report,
        census: &mut Option<crate::campaign::census::Census>,
    ) {
        let ids: Vec<_> = self.records.keys().cloned().collect();
        let mut pending = Vec::new();
        for id in ids {
            match self.reconcile_job(store, custody, &id) {
                Ok(Some((completed, emit))) => {
                    pending.push((id, completed.finished().record().clone(), emit))
                }
                Ok(None) => {}
                Err(error) => report.refuse(format!("job {id}: {error}")),
            }
        }
        let mut capture_ready = custody.held_identity().is_none();
        match custody.unrecorded(&[], crate::scan_bound()) {
            Ok(groups) if groups.is_empty() => {}
            Ok(_) => {
                capture_ready = false;
                report.refuse("attempt cgroup remains after reconciliation".into());
            }
            Err(error) => {
                capture_ready = false;
                report.refuse(error.to_string());
            }
        }
        let held = !capture_ready;
        for (id, finished, emit) in pending {
            if held {
                if emit {
                    report.complete(finished);
                }
                continue;
            }
            let result = (|| -> Result<(), Error> {
                let current = Attempt::current(store, self.read(store, &id)?)?
                    .ok_or_else(|| Error::Held("pending attempt vanished".into()))?;
                let completed = current.read_finished(store)?;
                if completed.finished().record() != &finished {
                    return Err(Error::Held("pending finish changed".into()));
                }
                let published = self.settle(store, report, &id, completed, emit)?;
                if let Some(census) = census.as_mut() {
                    for bytes in [published.pin, published.result].into_iter().flatten() {
                        let shard = crate::layout::shard(&id);
                        if let Err(error) = census.published(shard.as_str(), bytes) {
                            report.error(error);
                        }
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                report.error(error.about(format_args!("job {id}")));
            }
        }
    }

    pub(super) fn reconcile_job(
        &mut self,
        store: &Store,
        custody: &mut Custody,
        id: &str,
    ) -> Result<Option<(crate::attempt::Completed, bool)>, Error> {
        let current = Attempt::current(store, self.read(store, id)?)?;
        let Some(current) = current else {
            if crate::attempt::settlement_entries(
                store,
                self.records
                    .get(id)
                    .ok_or_else(|| Error::Held("job missing from table".into()))?,
            )? {
                return Err(Error::Held(
                    "settlement entry has no attempt history".into(),
                ));
            }
            self.counts.insert(id.to_owned(), 0);
            return Ok(None);
        };
        let count = current.number();
        let charged = current.reservation(store);
        let completed = current.reconcile(store, custody, attempt::EVIDENCE_BOUND)?;
        self.counts.insert(id.to_owned(), count);
        Ok(Some((completed, charged?)))
    }

    /// Settles job `id` from `completed`, returning the records this call
    /// published in `jobs/`.
    ///
    /// # Errors
    ///
    /// The job record's read and settlement's errors; a settlement that
    /// fails after publishing the pin returns its error, and the next
    /// session's count includes that pin.
    pub(super) fn settle(
        &mut self,
        store: &Store,
        report: &mut Report,
        id: &str,
        completed: crate::attempt::Completed,
        emit: bool,
    ) -> Result<Published, Error> {
        let finished = completed.finished().record().clone();
        if emit {
            report.complete(finished.clone());
        }
        let settlement = attempt::settle_pinning(store, self.read(store, id)?, completed)?;
        if settlement.result.is_some() {
            self.settled.insert(id.to_owned());
            if !emit {
                report.complete(finished);
            }
        }
        Ok(Published {
            pin: settlement.pin_bytes,
            result: settlement.result_bytes,
        })
    }

    pub(super) fn queued(&self) -> impl Iterator<Item = (&String, &Admission)> {
        self.records.iter().filter(|(id, job)| {
            job.purpose() == crate::record::Purpose::Campaign
                && !self.settled.contains(*id)
                && !self.excluded.contains(*id)
        })
    }

    pub fn next(&self, running: &BTreeMap<String, Attempt>, build: Digest) -> Option<String> {
        let build = build.to_string();
        let mut profiles = BTreeMap::new();
        for (id, job) in self
            .records
            .iter()
            .filter(|(id, _)| !self.settled.contains(*id))
        {
            let count = profiles
                .entry(&job.job().experiment().profile)
                .or_insert(0u64);
            *count = count.saturating_add(self.counts.get(id).copied().unwrap_or(0));
        }
        self.queued()
            .filter(|(id, job)| {
                !running.contains_key(*id) && job.job().experiment().pins.build.as_str() == build
            })
            .min_by_key(|(id, job)| {
                (
                    profiles[&job.job().experiment().profile],
                    self.counts.get(*id).copied().unwrap_or(0),
                    *id,
                )
            })
            .map(|(id, _)| id.clone())
    }
}

/// The directory of job `id`'s records.
fn directory(store: &Store, id: &str) -> Result<Dir, Error> {
    crate::layout::jobs(store, id)?.ok_or_else(|| Error::Held("job record missing".into()))
}
