//! Capture publishes retained replay inputs before its completion marker.

use super::lifecycle::held_read;
use super::{Completed, Error, classify, name};
use crate::record::{Admission, Digest, Finding, Verified};
use crate::store::{Dir, Name, Store};
use std::io::Read;

/// The findings root's listing, refused past the scan bound as the bound
/// hold that names `findings`.
fn listed_findings(store: &Store, root: &Dir) -> Result<Vec<Name>, Error> {
    store
        .list(root, crate::scan_bound())
        .map_err(|error| match error {
            crate::store::Error::ScanBound => Error::bound("findings", None),
            error => error.into(),
        })
}

pub(crate) fn capture(
    store: &Store,
    admission: &Admission,
    completed: &Completed,
    directory: &Dir,
    attempt: &Verified<crate::record::Attempt>,
    calibration_root: Option<Digest>,
) -> Result<(), Error> {
    let Some(kind) = classify::finding_kind(completed.finished().record(), completed.bound())
    else {
        return mark(store, directory, completed.finished(), None);
    };
    let source = match completed.bound() {
        Some(bound) => {
            let artifacts = store
                .open_dir(directory, &name("artifacts"))
                .map_err(|error| held_read(error, "finding artifacts unreadable"))?
                .ok_or(Error::Held("finding artifacts missing"))?;
            Some(
                store
                    .open_dir(&artifacts, &name(bound.binding().attempt.as_str()))
                    .map_err(|error| held_read(error, "finding evidence unreadable"))?
                    .ok_or(Error::Held("finding evidence missing"))?,
            )
        }
        None => None,
    };
    let output = if completed
        .bound()
        .and_then(|bound| bound.targeted())
        .is_some_and(|judged| !judged.children.is_empty())
    {
        match &source {
            Some(source) => store
                .open_dir(source, &name(admission.command()))
                .map_err(|error| held_read(error, "child output unreadable"))?,
            None => None,
        }
    } else {
        None
    };
    let calibration_root = match calibration_root {
        Some(root) => Some(root),
        None => calibration_root_for(store, admission)?,
    };
    let capture = Capture {
        store,
        admission,
        completed,
        attempt,
        calibration_root,
        kind,
        source,
        output,
    };
    let mut findings = Vec::new();
    if let Some(judged) = completed.bound().and_then(|bound| bound.targeted()) {
        for child in &judged.children {
            findings.push(capture.snapshot(Some(capture.child_fact(child.clone())?))?);
        }
    }
    findings.push(capture.snapshot(None)?);
    capture.preflight(&findings)?;
    for finding in findings {
        capture.retain(finding)?;
    }
    mark(
        store,
        directory,
        completed.finished(),
        Some(completed.finished().record().attempt.clone()),
    )
}

struct Capture<'a> {
    store: &'a Store,
    admission: &'a Admission,
    completed: &'a Completed,
    attempt: &'a Verified<crate::record::Attempt>,
    calibration_root: Option<Digest>,
    kind: crate::record::FindingKind,
    source: Option<Dir>,
    output: Option<Dir>,
}

impl Capture<'_> {
    fn child_fact(
        &self,
        mut child: crate::record::ChildEvidence,
    ) -> Result<crate::record::ChildEvidence, Error> {
        child.bundle = match (&self.output, &child.file) {
            (Some(output), Some(file)) => self
                .store
                .evidence_digest(
                    output,
                    &name(file.as_str()),
                    self.attempt.record().file_bytes,
                )
                .map_err(|error| held_read(error, "child bundle unreadable"))?,
            _ => None,
        };
        Ok(child)
    }
    fn snapshot(&self, child: Option<crate::record::ChildEvidence>) -> Result<Finding, Error> {
        let admission = self.admission;
        let completed = self.completed;
        let attempt = self.attempt;
        let calibration_root = self.calibration_root;
        let kind = self.kind;
        let finished = completed.finished();
        let bound = completed.bound();
        let parent_attempt = child.as_ref().map(|_| finished.record().attempt.clone());
        let child = match child {
            Some(child) => Some(child),
            None => bound
                .and_then(|bound| bound.targeted())
                .and_then(|judged| judged.children.iter().find(|child| child.kind == kind))
                .cloned()
                .map(|child| self.child_fact(child))
                .transpose()?,
        };
        let kind = child.as_ref().map(|child| child.kind).unwrap_or(kind);
        let finding = Finding {
            child,
            parent_attempt,
            calibration_root,
            admission: admission.clone(),
            artifact: bound.map(|bound| bound.artifact().clone()),
            attempt: attempt.record().clone(),
            finished: finished.record().clone(),
            kind,
        };
        Ok(finding)
    }
    /// Names the directory and entry a missing dependency copies from: the
    /// frozen job manifest, a child's bundle in the fork output, or the bound
    /// attempt's own file. Preflight sizes the same file that retention copies.
    fn dependency_source<'d>(
        &'d self,
        jobs: &'d Dir,
        finding: &Finding,
        entry: &Name,
    ) -> Result<(&'d Dir, Name), Error> {
        if entry.as_str() == "manifest" {
            return Ok((
                jobs,
                name(&format!("{}.manifest", self.admission.job().id())),
            ));
        }
        if entry.as_str() == "bundle"
            && let Some(child) = &finding.child
        {
            let output = self
                .output
                .as_ref()
                .ok_or(Error::Held("child bundle directory missing"))?;
            let file = child
                .file
                .as_ref()
                .ok_or(Error::Held("child bundle name missing"))?;
            return Ok((output, name(file.as_str())));
        }
        let source = self
            .source
            .as_ref()
            .ok_or(Error::Held("finding source missing"))?;
        let source_name = match &finding.artifact {
            Some(artifact) if entry.as_str() == "bundle" => {
                super::binding::bundle_entry(artifact.command.as_str())
            }
            _ => entry.clone(),
        };
        Ok((source, source_name))
    }
    fn retain(&self, mut finding: Finding) -> Result<(), Error> {
        let store = self.store;
        let hard = crate::sys::controller_file_limit().map_err(crate::store::Error::Io)?;
        let id = finding.id().as_str().to_owned();
        let encoded_len = crate::record::Record::encoded_len(&finding) as u64;
        if encoded_len > <Finding as crate::record::Record>::BOUND {
            return Err(Error::Held("finding record exceeds the record bound"));
        }
        if encoded_len > hard {
            return Err(Error::Held(
                "finding record exceeds controller RLIMIT_FSIZE",
            ));
        }
        store.mkdir(store.root(), &name("findings"))?;
        let root = store
            .open_dir(store.root(), &name("findings"))
            .map_err(|error| held_read(error, "finding dependency unreadable"))?
            .ok_or(Error::Held("finding root vanished"))?;
        if store
            .open_dir(&root, &name(&id))
            .map_err(|error| held_read(error, "finding dependency unreadable"))?
            .is_none()
        {
            let entries = listed_findings(store, &root)?.len();
            if entries >= crate::scan_bound() {
                return Err(Error::bound("findings", Some(entries)));
            }
        }
        store.mkdir(&root, &name(&id))?;
        let retained = store
            .open_dir(&root, &name(&id))
            .map_err(|error| held_read(error, "finding dependency unreadable"))?
            .ok_or(Error::Held("finding directory vanished"))?;
        let jobs = crate::layout::jobs(store, &self.admission.job().id().to_string())
            .map_err(|error| held_read(error, "frozen manifest directory unreadable"))?
            .ok_or(Error::Held("frozen manifest directory vanished"))?;
        let existing = store.read_record::<Finding>(&retained, &name("finding.json"))?;
        if let Some(existing) = &existing
            && (finding.calibration_root.is_none() || existing.record().calibration_root.is_none())
        {
            finding.calibration_root = existing.record().calibration_root;
        }
        if existing
            .as_ref()
            .is_some_and(|record| record.record() != &finding)
        {
            return Err(Error::Held("retained finding differs"));
        }
        for (entry, digest, cap) in dependencies(&finding)? {
            let present = store
                .open_file(&retained, &entry)
                .map_err(|error| held_read(error, "retained dependency unreadable"))?;
            if let Some(file) = present {
                store.sync_file(&retained, &file)?;
            } else if existing.is_none() {
                let (origin, source_name) = self.dependency_source(&jobs, &finding, &entry)?;
                let file = store
                    .open_file(origin, &source_name)
                    .map_err(|error| held_read(error, "finding dependency unreadable"))?
                    .ok_or(Error::Held("bound file vanished"))?;
                if file.len() > hard {
                    return Err(Error::Held("finding copy exceeds controller RLIMIT_FSIZE"));
                }
                if file.len() > cap {
                    return Err(Error::Held("finding copy exceeds its byte bound"));
                }
                let mut copied = crate::record::Hashing::new(file.take(cap.min(hard)));
                let creation = store.copy_once(&retained, &entry, &mut copied, 0o600)?;
                if copied.finish() != digest {
                    return Err(Error::Held("finding source digest differs"));
                }
                if creation == crate::store::Creation::Created {
                    continue;
                }
            }
            if store
                .evidence_digest(&retained, &entry, cap)
                .map_err(|error| held_read(error, "retained dependency unreadable"))?
                != Some(digest)
            {
                return Err(Error::Held("retained finding dependency differs"));
            }
        }

        let record = match existing {
            Some(record) => record,
            None => {
                store.create_record(&retained, &name("finding.json"), &finding)?;
                store
                    .read_record::<Finding>(&retained, &name("finding.json"))?
                    .ok_or(Error::Held("finding publication vanished"))?
            }
        };
        if record.record() != &finding {
            return Err(Error::Held("retained finding differs"));
        }
        store.barrier(record.read())?;
        Ok(())
    }
}

fn mark(
    store: &Store,
    directory: &Dir,
    finished: &Verified<crate::record::Finished>,
    finding: Option<crate::record::Text>,
) -> Result<(), Error> {
    let marker = crate::record::Captured {
        attempt: finished.record().attempt.clone(),
        finding,
        finished: Digest::of(finished.read().bytes()),
    };
    if let Some(found) =
        store.read_record::<crate::record::Captured>(directory, &name("captured"))?
    {
        if found.record() != &marker {
            return Err(Error::Held("capture marker differs"));
        }
        store.barrier(found.read())?;
        return Ok(());
    }
    store.create_record(directory, &name("captured"), &marker)?;
    let found = store
        .read_record::<crate::record::Captured>(directory, &name("captured"))?
        .ok_or(Error::Held("capture marker vanished"))?;
    if found.record() != &marker {
        return Err(Error::Held("capture marker differs"));
    }
    store.barrier(found.read())?;
    Ok(())
}

pub(crate) fn recorded(
    store: &impl crate::store::ReadStore,
    directory: &Dir,
    finished: &Verified<crate::record::Finished>,
) -> Result<Option<bool>, Error> {
    let Some(marker) =
        store.read_record::<crate::record::Captured>(directory, &name("captured"))?
    else {
        return Ok(None);
    };
    if !marker.record().matches(finished) {
        return Err(Error::Held("capture marker binding differs"));
    }
    store.barrier(marker.read())?;
    Ok(Some(marker.record().finding.is_some()))
}

pub(crate) fn dependencies(finding: &Finding) -> Result<Vec<(Name, Digest, u64)>, Error> {
    let mut files = vec![(
        name("manifest"),
        finding.admission.job().manifest_sha256(),
        crate::record::BOUND,
    )];
    if let Some(artifact) = &finding.artifact {
        if let Some(bundle) = finding.bundle() {
            files.push((
                name(
                    if finding.child.is_none() && artifact.command.as_str() == "replay" {
                        "input"
                    } else {
                        "bundle"
                    },
                ),
                bundle,
                finding.attempt.file_bytes,
            ));
        }
        for (phase, stream, digest) in artifact.streams() {
            let entry = crate::record::Artifact::stream_name(phase, stream)
                .ok_or(Error::Held("invalid finding stream name"))?;
            files.push((entry, digest, crate::sim::OUTPUT as u64));
        }
    }
    Ok(files)
}

fn calibration_root_for(store: &Store, admission: &Admission) -> Result<Option<Digest>, Error> {
    if admission.purpose() != crate::record::Purpose::Calibration {
        return Ok(None);
    }
    let Some(roots) = store
        .open_dir(store.root(), &name("calibrations"))
        .map_err(|error| held_read(error, "calibration roots unreadable"))?
    else {
        return Ok(None);
    };
    for entry in store.list(&roots, crate::scan_bound())? {
        let directory = match store.open_dir(&roots, &entry) {
            Ok(Some(directory)) => directory,
            Ok(None) => continue,
            Err(error) if !error.faulted() => continue,
            Err(error) => return Err(held_read(error, "calibration root unreadable")),
        };
        let plan =
            match store.read_record::<crate::record::CalibrationPlan>(&directory, &name("plan")) {
                Ok(Some(plan)) => plan,
                Ok(None) => continue,
                Err(crate::record::Held::Unreadable(error)) if error.faulted() => {
                    return Err(crate::record::Held::Unreadable(error).into());
                }
                Err(_) => continue,
            };
        if plan.record().healthy == *admission
            || plan
                .record()
                .controls
                .values()
                .any(|control| control == admission)
        {
            store.barrier(plan.read())?;
            return Ok(Some(plan.record().healthy.job().id().digest()));
        }
    }
    Ok(None)
}

impl Capture<'_> {
    /// Holds targeted capture before writes when its missing footprint exceeds current configuration or free space.
    fn preflight(&self, findings: &[Finding]) -> Result<(), Error> {
        if self.admission.target().is_none() {
            return Ok(());
        }
        let config = self
            .store
            .read_record::<crate::record::Configuration>(self.store.root(), &name("config.json"))?
            .ok_or(Error::Held("target capture configuration missing"))?;
        self.store.barrier(config.read())?;
        let jobs = crate::layout::jobs(self.store, &self.admission.job().id().to_string())
            .map_err(|error| held_read(error, "finding jobs unreadable"))?
            .ok_or(Error::Held("frozen manifest directory vanished"))?;
        let root = self
            .store
            .open_dir(self.store.root(), &name("findings"))
            .map_err(|error| held_read(error, "finding root unreadable"))?;
        let mut copies = crate::record::Charge {
            bytes: 0,
            inodes: u128::from(root.is_none()),
        };
        let hard = crate::sys::controller_file_limit().map_err(crate::store::Error::Io)?;
        let mut missing_directories = 0usize;
        for finding in findings {
            let directory = match &root {
                Some(root) => self
                    .store
                    .open_dir(root, &name(finding.id().as_str()))
                    .map_err(|error| held_read(error, "finding directory unreadable"))?,
                None => None,
            };
            missing_directories += usize::from(directory.is_none());
            copies.inodes += u128::from(directory.is_none());
            let length = crate::record::Record::encoded_len(finding) as u64;
            if length > <Finding as crate::record::Record>::BOUND || length > hard {
                return Err(Error::Held("finding record exceeds its byte bound"));
            }
            if directory
                .as_ref()
                .map(|dir| self.store.open_file(dir, &name("finding.json")))
                .transpose()
                .map_err(|error| held_read(error, "finding dependency unreadable"))?
                .flatten()
                .is_none()
            {
                copies.bytes += u128::from(length);
                copies.inodes += 1;
            }
            for (entry, _, cap) in dependencies(finding)? {
                if directory
                    .as_ref()
                    .map(|dir| self.store.open_file(dir, &entry))
                    .transpose()
                    .map_err(|error| held_read(error, "finding dependency unreadable"))?
                    .flatten()
                    .is_some()
                {
                    continue;
                }
                let (source, source_name) = self.dependency_source(&jobs, finding, &entry)?;
                let file = self
                    .store
                    .open_file(source, &source_name)
                    .map_err(|error| held_read(error, "finding source unreadable"))?
                    .ok_or(Error::Held("bound file vanished"))?;
                if file.len() > cap || file.len() > hard {
                    return Err(Error::Held("finding copy exceeds its byte bound"));
                }
                copies.bytes += u128::from(file.len());
                copies.inodes += 1;
            }
        }
        if copies.bytes == 0 && copies.inodes == 0 {
            return Ok(());
        }
        if let Some(root) = &root {
            let projected = listed_findings(self.store, root)?.len() + missing_directories;
            if projected > crate::scan_bound() {
                return Err(Error::bound("findings", Some(projected)));
            }
        }
        let (free_bytes, free_inodes, fragment) = self
            .store
            .root()
            .free_space()
            .map_err(crate::store::Error::Io)?;
        let mut reserved = crate::record::retention_charge(
            config.record().file_bytes(),
            config.record().value("attempt_inodes"),
        );
        reserved.bytes *= u128::from(self.admission.shares());
        reserved.inodes *= u128::from(self.admission.shares());
        if !retention_fits(&copies, &reserved, free_bytes, free_inodes, fragment) {
            return Err(Error::Held(
                "target finding retention exceeds reserved capacity",
            ));
        }
        Ok(())
    }
}

fn retention_fits(
    copies: &crate::record::Charge,
    reserved: &crate::record::Charge,
    free_bytes: u64,
    free_inodes: u64,
    fragment: std::num::NonZeroU64,
) -> bool {
    let controller = crate::record::resource_charge(0, 0);
    let footprint = crate::record::Charge {
        bytes: copies.bytes + controller.bytes,
        inodes: copies.inodes + controller.inodes,
    };
    footprint.bytes <= reserved.bytes
        && footprint.inodes <= reserved.inodes
        && footprint.disk(fragment) < u128::from(free_bytes)
        && footprint.inodes < u128::from(free_inodes)
}

#[cfg(test)]
mod retention_tests {
    #[test]
    fn retention_budget_includes_fragments_and_controller_allowance() {
        let copies = crate::record::Charge {
            bytes: 1000,
            inodes: 4,
        };
        let controller = crate::record::resource_charge(0, 0);
        let reserved = crate::record::Charge {
            bytes: copies.bytes + controller.bytes,
            inodes: copies.inodes + controller.inodes,
        };
        let fragment = std::num::NonZeroU64::new(4096).unwrap();
        let free_bytes = u64::try_from(reserved.disk(fragment)).unwrap() + 1;
        let free_inodes = u64::try_from(reserved.inodes).unwrap() + 1;
        let fits = |reserved, free_bytes, free_inodes| {
            super::retention_fits(&copies, reserved, free_bytes, free_inodes, fragment)
        };
        assert!(fits(&reserved, free_bytes, free_inodes));
        assert!(!fits(&reserved, free_bytes - 1, free_inodes));
        assert!(!fits(&reserved, free_bytes, free_inodes - 1));
        let smaller = crate::record::Charge {
            bytes: reserved.bytes - 1,
            inodes: reserved.inodes + 100,
        };
        assert!(!fits(&smaller, free_bytes, free_inodes));
    }
}
