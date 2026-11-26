//! Reclamation verifies record digests, manifest bytes and entry bounds.

use super::{Error, name};
use crate::record::{Artifact, Binding, Digest, Finished, Reclaimed, Verified};
use crate::store::{Dir, Name, ReadStore};

/// A bound artifact with its checked retained layout and canonical reclaim marker.
pub(super) struct Evidence {
    pub directory: Dir,
    pub bulk: Vec<Name>,
    pub marker: Reclaimed,
}

/// Holds unknown, unreadable or oversized controller entries before planning.
pub(super) fn check_entries(
    view: &impl ReadStore,
    directory: &Dir,
    path: &str,
) -> Result<(), Error> {
    for entry in listed(view.list(directory, crate::scan_bound()), path)? {
        if crate::store::ATTEMPT_RECORDS.contains(&entry.as_str()) {
            let file = checked(
                view.open_file(directory, &entry),
                &format!("{path}/{}", entry.as_str()),
            )?
            .ok_or_else(|| Error::Held("attempt record vanished".into()))?;
            if file.len() > crate::record::BOUND {
                return Err(Error::Held("attempt record exceeds its byte bound".into()));
            }
        } else if !crate::custody::LAUNCHER_OUTPUTS.contains(&entry.as_str())
            && entry.as_str() != "artifacts"
        {
            return Err(Error::Held("unknown attempt entry pins its subtree".into()));
        }
    }
    Ok(())
}

pub(super) fn prepare(
    view: &impl ReadStore,
    directory: &Dir,
    job: &str,
    number: u64,
    finished: &Verified<Finished>,
    path: &str,
) -> Result<Evidence, Error> {
    let identity = format!("{job}-{number:04}");
    let identity_name =
        Name::new(&identity).ok_or_else(|| Error::Held("attempt identity is invalid".into()))?;
    if finished.record().attempt.as_str() != identity
        || finished.record().binding != Binding::Matching
    {
        return Err(Error::Held(
            "finish differs from the reclaim identity".into(),
        ));
    }
    let artifacts_path = format!("{path}/artifacts");
    let artifacts = checked(
        view.open_dir(directory, &name("artifacts")),
        &artifacts_path,
    )?
    .ok_or_else(|| Error::Held("attempt lacks its artifact record".into()))?;
    if listed(view.list(&artifacts, crate::scan_bound()), &artifacts_path)?
        != [identity_name.clone()]
    {
        return Err(Error::Held(
            "unknown artifacts entry pins its subtree".into(),
        ));
    }
    let evidence_path = format!("{artifacts_path}/{identity}");
    let evidence = checked(view.open_dir(&artifacts, &identity_name), &evidence_path)?
        .ok_or_else(|| Error::Held("attempt lacks its artifact record".into()))?;
    let artifact = checked(
        view.read_record::<Artifact>(&evidence, &name("artifact")),
        &format!("{evidence_path}/artifact"),
    )?
    .ok_or_else(|| Error::Held("attempt lacks its artifact record".into()))?;
    if finished.record().bound.as_ref().is_none_or(|bound| {
        bound.artifact != Digest::of(artifact.read().bytes())
            || bound.attempt.as_str() != identity
            || bound.bundle != artifact.record().bundle
    }) {
        return Err(Error::Held("artifact differs from the bound finish".into()));
    }
    let manifest_path = format!("{evidence_path}/manifest");
    let manifest = checked(
        view.read(&evidence, &name("manifest"), crate::record::BOUND),
        &manifest_path,
    )?
    .ok_or_else(|| Error::Held(format!("{manifest_path}: retained manifest is missing")))?;
    if artifact.record().manifest != Some(Digest::of(manifest.bytes())) {
        return Err(Error::Held(format!(
            "{manifest_path}: retained manifest differs"
        )));
    }
    let bulk = artifact
        .record()
        .bulk()
        .ok_or_else(|| Error::Held("artifact stream name is invalid".into()))?;
    let reported: Vec<_> = artifact
        .record()
        .streams()
        .filter_map(|(phase, stream, _)| {
            Artifact::stream_name(phase, stream)
                .filter(|entry| Artifact::REPORTED_STREAMS.contains(&entry.as_str()))
        })
        .collect();
    let entries = checked(
        crate::store::retained_entries(&evidence, crate::scan_bound())
            .map_err(|error| Error::listing(&evidence_path, error)),
        &evidence_path,
    )?
    .ok_or_else(|| Error::Held("staged evidence or a foreign marker pins its subtree".into()))?;
    for entry in entries {
        if Artifact::RECLAIMED_RECORDS.contains(&entry.as_str()) || bulk.contains(&entry) {
            continue;
        }
        if !reported.contains(&entry) {
            return Err(Error::Held(
                "unknown evidence entry pins its subtree".into(),
            ));
        }
        let file_path = format!("{evidence_path}/{}", entry.as_str());
        let file = checked(view.open_file(&evidence, &entry), &file_path)?
            .ok_or_else(|| Error::Held(format!("{file_path}: retained file vanished")))?;
        if file.len() > crate::sim::OUTPUT as u64 {
            return Err(Error::Held(format!(
                "{file_path}: retained file exceeds its byte bound"
            )));
        }
    }
    Ok(Evidence {
        directory: evidence,
        marker: Reclaimed::new(number, finished, &bulk),
        bulk,
    })
}

pub(super) fn checked<T, E: Into<Error>>(result: Result<T, E>, path: &str) -> Result<T, Error> {
    result.map_err(|error| {
        let error = error.into();
        if error.host_fault() {
            Error::Census {
                path: path.to_owned(),
                cause: Box::new(error),
            }
        } else if error.at_scan_bound() {
            error
        } else {
            Error::Held(format!("{path}: {error}"))
        }
    })
}

fn listed(result: Result<Vec<Name>, crate::store::Error>, path: &str) -> Result<Vec<Name>, Error> {
    checked(result.map_err(|error| Error::listing(path, error)), path)
}
