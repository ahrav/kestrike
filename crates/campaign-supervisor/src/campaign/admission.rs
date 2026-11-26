use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use super::{Error, Request, name};
use crate::protocol::Listing;
use crate::record::{Admission, BOUND, JobResult, Pin, Pins, Purpose, Record, Text};
use crate::store::{Creation, Name, Store};

pub struct Outcome {
    pub record: Admission,
    pub existing: bool,
}

pub(crate) fn admit_campaign(
    store: &Store,
    archive: &Path,
    cgroup_root: &Path,
    watchdog: Duration,
    request: &Request,
) -> Result<Outcome, Error> {
    request.validate(Purpose::Campaign)?;
    let probed = super::probe::probe(store, archive, cgroup_root, watchdog)?;
    let archive = probed
        .archive
        .to_str()
        .ok_or_else(|| Error::Rejected("archive path must be ASCII".into()))?;
    super::admit(
        store,
        &probed.listing,
        probed.pins,
        super::text(archive)?,
        request,
        Purpose::Campaign,
    )
}

pub(crate) fn admit(
    store: &Store,
    listing: &Listing,
    pins: Pins,
    archive: Text,
    request: &Request,
    purpose: Purpose,
) -> Result<Outcome, Error> {
    admit_scoped(store, listing, pins, archive, request, purpose, None)
}

pub(crate) fn admit_control(
    store: &Store,
    listing: &Listing,
    pins: Pins,
    archive: Text,
    request: &Request,
    scope: crate::record::Digest,
) -> Result<Outcome, Error> {
    admit_scoped(
        store,
        listing,
        pins,
        archive,
        request,
        Purpose::Calibration,
        Some(scope),
    )
}

fn admit_scoped(
    store: &Store,
    listing: &Listing,
    pins: Pins,
    archive: Text,
    request: &Request,
    purpose: Purpose,
    scope: Option<crate::record::Digest>,
) -> Result<Outcome, Error> {
    request.validate(purpose)?;
    campaign_profile(listing, &request.profile, purpose)?;
    let (job, manifest) = match scope {
        Some(scope) => super::freeze::freeze_scoped(listing, pins, request, Some(scope))?,
        None => super::freeze::freeze(listing, pins, request)?,
    };
    let record =
        Admission::new(archive, job, purpose).map_err(|e| Error::Rejected(e.to_string()))?;
    publish(store, record, &manifest, None)
}

/// Publishes frozen replay inputs before their create-once admission record.
pub(in crate::campaign) fn publish(
    store: &Store,
    record: Admission,
    manifest: &str,
    bundle: Option<(&crate::store::Dir, &crate::record::Target)>,
) -> Result<Outcome, Error> {
    if manifest.len() as u64 > BOUND || record.encoded_len() as u64 > BOUND {
        return Err(Error::Rejected(
            "job or manifest exceeds the reader bound".into(),
        ));
    }
    let id = record.job().id().to_string();
    let jobs = crate::layout::make_shard(store, crate::layout::JOBS, &id)?;
    let record_name = name(&format!("{id}.json"));
    let manifest_name = name(&format!("{id}.manifest"));
    let old = store.read_record::<Admission>(&jobs, &record_name)?;
    let old_manifest = store.read(&jobs, &manifest_name, BOUND)?;
    let shard = format!("jobs/{}", crate::layout::shard(&id).as_str());
    let entries = store
        .list(&jobs, crate::scan_bound())
        .map_err(|error| Error::listing(&shard, error))?;
    let suffixes: &[&str] = if bundle.is_some() {
        &[".json", ".manifest", ".bundle"]
    } else {
        &[".json", ".manifest"]
    };
    let additions = suffixes
        .iter()
        .filter(|suffix| {
            !entries
                .iter()
                .any(|entry| entry.as_str() == format!("{id}{suffix}"))
        })
        .count();
    if old.is_none() {
        let projected = settled_entries(&entries, &id) + additions;
        if projected > crate::scan_bound() {
            return Err(Error::bound(&shard, projected));
        }
    }
    if let Some((source, target)) = bundle {
        if old_manifest
            .as_ref()
            .is_some_and(|found| found.bytes() != manifest.as_bytes())
            || old
                .as_ref()
                .is_some_and(|found| found.record().job() != record.job())
        {
            return Err(Error::Held("frozen target job or manifest differs".into()));
        }
        let entry = name(&format!("{id}.bundle"));
        let missing_bundle = store.open_file(&jobs, &entry)?.is_none();
        let bytes = u128::from(target.bytes) * u128::from(missing_bundle)
            + manifest.len() as u128 * u128::from(old_manifest.is_none())
            + record.encoded_len() as u128 * u128::from(old.is_none());
        let inodes = u128::from(missing_bundle)
            + u128::from(old_manifest.is_none())
            + u128::from(old.is_none());
        if inodes > 0 {
            target_storage(store, bytes, inodes)?;
        }
        if store.evidence_digest(&jobs, &entry, target.bytes)? != Some(target.bundle) {
            if old.is_some() || store.open_file(&jobs, &entry)?.is_some() {
                return Err(Error::Held("frozen target bundle differs".into()));
            }
            let file = store
                .open_file(source, &name("bundle"))?
                .ok_or_else(|| Error::Held("target bundle vanished".into()))?;
            if file.len() != target.bytes {
                return Err(Error::Held("target bundle size differs".into()));
            }
            if target.bytes
                > crate::sys::controller_file_limit().map_err(crate::store::Error::Io)?
            {
                return Err(Error::Rejected(
                    "target bundle exceeds controller file limit".into(),
                ));
            }
            let mut copied = crate::record::Hashing::new(std::io::Read::take(file, target.bytes));
            store.copy_once(&jobs, &entry, &mut copied, 0o600)?;
            if copied.finish() != target.bundle {
                return Err(Error::Held("target copy digest differs".into()));
            }
        }
        let file = store
            .open_file(&jobs, &entry)?
            .ok_or_else(|| Error::Held("frozen target vanished".into()))?;
        store.sync_file(&jobs, &file)?;
    }
    match (old, old_manifest) {
        (Some(old), Some(found))
            if old.record().job() == record.job() && found.bytes() == manifest.as_bytes() =>
        {
            store.barrier(old.read())?;
            store.barrier(&found)?;
            return Ok(Outcome {
                record: old.record().clone(),
                existing: true,
            });
        }
        (Some(_), _) => {
            return Err(Error::Held(
                "existing job or manifest differs from the frozen experiment".into(),
            ));
        }
        (None, Some(found)) if found.bytes() == manifest.as_bytes() => store.barrier(&found)?,
        (None, Some(_)) => {
            return Err(Error::Held(
                "orphan manifest differs from the frozen experiment".into(),
            ));
        }
        (None, None) => {
            if store.create_once(&jobs, &manifest_name, manifest.as_bytes())? != Creation::Created {
                return Err(Error::Held("manifest appeared during admission".into()));
            }
        }
    }
    if store.create_record(&jobs, &record_name, &record)? != Creation::Created {
        return Err(Error::Held("job appeared during admission".into()));
    }
    Ok(Outcome {
        record,
        existing: false,
    })
}

/// The projected entry count of `jobs/` reserves room for the pin and result
/// files that settlement creates for each admitted job and for `id`. A job
/// whose result exists is settled, so its reservation is zero.
fn settled_entries(entries: &[Name], id: &str) -> usize {
    let present: BTreeSet<&str> = entries.iter().map(Name::as_str).collect();
    let unpublished = |id: &str| {
        let published = |suffix: &str| present.contains(format!("{id}{suffix}").as_str());
        if published(JobResult::SUFFIX) {
            0
        } else {
            2 - usize::from(published(Pin::SUFFIX))
        }
    };
    let admitted = present.iter().filter_map(|entry| {
        entry
            .strip_suffix(".json")
            .filter(|_| !entry.ends_with(JobResult::SUFFIX))
    });
    entries.len() + admitted.chain([id]).map(unpublished).sum::<usize>()
}

pub(in crate::campaign) fn job_id(entry: &str) -> Option<&str> {
    [
        JobResult::SUFFIX,
        Pin::SUFFIX,
        ".manifest",
        ".bundle",
        ".json",
    ]
    .into_iter()
    .find_map(|suffix| entry.strip_suffix(suffix))
}

/// Refuses campaign profiles whose contract expects a control failure.
pub(in crate::campaign) fn campaign_profile(
    listing: &Listing,
    profile: &Text,
    purpose: Purpose,
) -> Result<(), Error> {
    if purpose == Purpose::Campaign
        && listing.profile(profile.as_str()).is_some_and(|profile| {
            profile.class == crate::protocol::Class::Control
                || (profile.class == crate::protocol::Class::History
                    && profile.expected != Some(crate::protocol::Expected::Pass))
        })
    {
        return Err(Error::Rejected(
            "campaign profile must expect a pass".into(),
        ));
    }
    Ok(())
}

/// Charges every missing frozen input and admission file before a targeted write.
fn target_storage(store: &Store, bytes: u128, inodes: u128) -> Result<(), Error> {
    let config = store
        .read_record::<crate::record::Configuration>(store.root(), &name("config.json"))?
        .ok_or_else(|| Error::Rejected("target admission requires configuration".into()))?;
    store.barrier(config.read())?;
    let usage = crate::campaign::census::census(store, config.record())?;
    let units = u128::from(config.record().value("slots") + config.record().value("reserve_slots"));
    let reserve = config.record().charge();
    if u128::from(usage.bytes) + bytes + units * reserve.bytes
        >= u128::from(config.record().value("artifact_bytes"))
    {
        return Err(Error::Rejected(
            "target copies leave insufficient attempt output capacity".into(),
        ));
    }
    if u128::from(usage.inodes) + inodes + units * reserve.inodes
        >= u128::from(config.record().value("artifact_inodes"))
        || u128::from(usage.free_bytes)
            <= bytes
                + inodes * u128::from(usage.fragment_bytes.get())
                + units * reserve.disk(usage.fragment_bytes)
        || u128::from(usage.free_inodes) <= inodes + units * reserve.inodes
    {
        return Err(Error::Rejected(
            "target copies leave insufficient storage capacity".into(),
        ));
    }
    Ok(())
}
