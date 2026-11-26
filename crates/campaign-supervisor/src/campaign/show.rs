//! The `show` listing of a state directory's configuration and job
//! records, read through a view without the lock. A job row is verified
//! when its record, its manifest and their identities agree. Targeted rows
//! also verify the frozen bundle. Any other row
//! is held with the failing step's code. `storage.roots` gives each root's
//! entry count against the scan bound: the fullest shard for jobs and
//! attempts, top-level entries for other roots. `storage.free_bytes` and
//! `storage.free_inodes` give measured free space; the census that holds
//! `dispatch` also lists each `attempts/<xx>/<id>` history, which these
//! root counts omit.
//! `status` reads jobs and the configuration through the same functions.

use std::collections::BTreeSet;
use std::path::Path;

use super::{Error, name};
use crate::record::{Admission, BOUND, Configuration, Digest, JobResult, Verified};
use crate::store::{Dir, View};

pub fn show(path: &Path) -> Result<serde_json::Value, Error> {
    let view = View::open(path)?;
    view.require_state_marker()?;
    let config = config(view.read_record::<Configuration>(view.root(), &name("config.json")));
    let mut rows = Vec::new();
    for shard in crate::campaign::sharded(&view, crate::layout::JOBS)? {
        let shard = match shard {
            Err(crate::store::Error::Foreign(path)) => {
                rows.push(held(
                    &path,
                    &Error::Held("root entry is not a shard".into()),
                ));
                continue;
            }
            shard => shard?,
        };
        let (entries, misplaced): (Vec<_>, Vec<_>) = super::shard_entries(&view, &shard)?
            .into_iter()
            .partition(|entry| super::findings::placed(&shard, entry.as_str()));
        for entry in misplaced {
            let path = format!("{}/{}", shard.path, entry.as_str());
            rows.push(held(
                &path,
                &Error::Held("entry outside its job's shard".into()),
            ));
        }
        for id in job_ids(&entries) {
            rows.push(match checked(&view, &shard.dir, &id) {
                Ok(record) => serde_json::json!({"id": id, "verified": record.record()}),
                Err(error) => held(&id, &error),
            });
        }
    }
    let calibrations = super::calibration::status(&view)?;
    let storage = super::storage::measure(&view)?;
    if !view.current().map_err(crate::store::Error::Io)? {
        return Err(Error::Held("state directory moved during show".into()));
    }
    let mut result = serde_json::Map::new();
    result.insert(
        "calibrations".into(),
        serde_json::Value::Array(calibrations),
    );
    result.insert("config".into(), config);
    result.insert("jobs".into(), serde_json::Value::Array(rows));
    result.insert(
        "storage".into(),
        serde_json::to_value(storage).expect("storage encodes"),
    );
    Ok(serde_json::Value::Object(result))
}

/// The configuration row: `{"verified": ...}`, a held row, or null when no
/// configuration exists.
pub(super) fn config(
    read: Result<Option<Verified<Configuration>>, crate::record::Held>,
) -> serde_json::Value {
    match read {
        Ok(None) => serde_json::Value::Null,
        Ok(Some(config)) => serde_json::json!({"verified": config.record()}),
        Err(error) => serde_json::json!({"held": error.to_string(), "held_code": error.code()}),
    }
}

/// The job identities the job directory names through a record or a
/// manifest, sorted.
fn job_ids(entries: &[crate::store::Name]) -> BTreeSet<String> {
    entries
        .iter()
        .filter_map(|entry| {
            let name = entry.as_str();
            if name.ends_with(JobResult::SUFFIX) {
                return None;
            }
            super::admission::job_id(name).map(str::to_owned)
        })
        .collect()
}

/// The verified admission of job `id`: its record and manifest exist, and
/// the record names `id` and the manifest's digest.
///
/// # Errors
///
/// [`Error::Held`] for an `id` that is no digest, a missing record or
/// manifest, or a binding mismatch, and the read's error otherwise.
pub(super) fn checked(view: &View, jobs: &Dir, id: &str) -> Result<Verified<Admission>, Error> {
    if Digest::parse(id).is_none() {
        return Err(Error::Held("invalid job identity filename".into()));
    }
    verified_job(view, jobs, id)
}

pub(super) fn held_code(id: &str, error: &Error) -> &'static str {
    if Digest::parse(id).is_none() {
        "identity"
    } else {
        error.held_code()
    }
}

fn held(id: &str, error: &Error) -> serde_json::Value {
    serde_json::json!({"id": id, "held": error.to_string(), "held_code": held_code(id, error)})
}

pub(super) fn verified_job(
    view: &impl crate::store::ReadStore,
    jobs: &Dir,
    id: &str,
) -> Result<Verified<Admission>, Error> {
    let record = view
        .read_record::<Admission>(jobs, &name(&format!("{id}.json")))?
        .ok_or_else(|| Error::Held("job dependency without job record".into()))?;
    let manifest = view
        .read(jobs, &name(&format!("{id}.manifest")), BOUND)?
        .ok_or_else(|| Error::Held("job manifest missing".into()))?;
    if record.record().job().id().to_string() != id
        || record.record().job().manifest_sha256() != Digest::of(manifest.bytes())
    {
        return Err(Error::Held("job binding differs".into()));
    }
    view.barrier(record.read())?;
    view.barrier(&manifest)?;
    if record.record().target().is_some() {
        crate::attempt::frozen_manifest(view, jobs, record.record()).map_err(Error::from)?;
    }
    Ok(record)
}
