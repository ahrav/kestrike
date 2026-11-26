//! Live evidence binds artifact, manifest, bundle and stream bytes. Reclaimed
//! evidence binds the retained artifact and manifest to recorded digests and
//! to the attempt record.

use crate::record::{Artifact, Attempt, BOUND, Binding, BoundEvidence, Digest, Held};
#[cfg(test)]
use crate::store::Store;
use crate::store::{Dir, ReadStore, Unreadable};

use super::{Error, name};

/// ```compile_fail,E0616
/// use campaign_supervisor::attempt::BoundArtifact;
/// fn swap(a: &mut BoundArtifact, b: &mut BoundArtifact) {
///     std::mem::swap(&mut a.binding, &mut b.binding);
/// }
/// ```
pub struct BoundArtifact {
    artifact: Artifact,
    binding: BoundEvidence,
    panic: bool,
    targeted: Option<super::targeted::Judgment>,
}

pub(super) enum Evidence {
    Bound(Box<BoundArtifact>),
    Missing,
    Malformed,
    Misbound,
}

impl Evidence {
    pub(super) fn state(&self) -> Binding {
        match self {
            Self::Bound(_) => Binding::Matching,
            Self::Missing => Binding::Missing,
            Self::Malformed => Binding::Malformed,
            Self::Misbound => Binding::Misbound,
        }
    }
    pub(super) fn binding(&self) -> Option<&BoundEvidence> {
        match self {
            Self::Bound(bound) => Some(bound.binding()),
            _ => None,
        }
    }
    pub(super) fn into_bound(self) -> Option<Box<BoundArtifact>> {
        match self {
            Self::Bound(bound) => Some(bound),
            _ => None,
        }
    }
}

impl BoundArtifact {
    pub(crate) fn targeted(&self) -> Option<&super::targeted::Judgment> {
        self.targeted.as_ref()
    }
    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }
    pub fn binding(&self) -> &BoundEvidence {
        &self.binding
    }
    pub(super) fn panic(&self) -> bool {
        self.panic
    }
}

enum Rejected {
    Missing,
    Malformed,
    Misbound,
    Fault(Error),
}

impl From<Unreadable> for Rejected {
    fn from(error: Unreadable) -> Self {
        if error.faulted() {
            Self::Fault(Error::Store(crate::store::Error::Unreadable(error)))
        } else {
            Self::Malformed
        }
    }
}
impl From<Held> for Rejected {
    fn from(error: Held) -> Self {
        match error {
            Held::Unreadable(error) => error.into(),
            _ => Self::Malformed,
        }
    }
}

#[cfg(test)]
pub(super) fn read(store: &Store, directory: &Dir, attempt: &Attempt) -> Result<Evidence, Error> {
    read_command(store, directory, attempt, "run")
}

pub(super) fn read_command(
    store: &impl ReadStore,
    directory: &Dir,
    attempt: &Attempt,
    command: &str,
) -> Result<Evidence, Error> {
    match bind(store, directory, attempt, command) {
        Ok(bound) => Ok(Evidence::Bound(Box::new(bound))),
        Err(Rejected::Missing) => Ok(Evidence::Missing),
        Err(Rejected::Malformed) => Ok(Evidence::Malformed),
        Err(Rejected::Misbound) => Ok(Evidence::Misbound),
        Err(Rejected::Fault(error)) => Err(error),
    }
}

pub(super) fn bundle_entry(command: &str) -> crate::store::Name {
    name(Artifact::bundle_name(command))
}

pub(super) fn reclaimed(
    store: &impl ReadStore,
    directory: &Dir,
    attempt: &Attempt,
    bound: &BoundEvidence,
    command: &str,
) -> Result<Evidence, Error> {
    let missing = || Error::Held("reclaimed attempt lacks its artifact record");
    let held = |error| super::lifecycle::held_read(error, "reclaimed artifact record unreadable");
    let artifacts = store
        .open_dir(directory, &name("artifacts"))
        .map_err(held)?
        .ok_or_else(missing)?;
    let evidence = store
        .open_dir(&artifacts, &name(attempt.attempt.as_str()))
        .map_err(held)?
        .ok_or_else(missing)?;
    let artifact = store
        .read_record::<Artifact>(&evidence, &name("artifact"))?
        .ok_or_else(missing)?;
    let binding = BoundEvidence {
        artifact: Digest::of(artifact.read().bytes()),
        attempt: attempt.attempt.clone(),
        bundle: artifact.record().bundle,
    };
    if binding.artifact != bound.artifact {
        return Err(Error::Held("reclaimed artifact record differs"));
    }
    if !names_attempt(artifact.record(), attempt, command) {
        return Err(Error::Held("reclaimed artifact binding differs"));
    }
    let manifest = store
        .read(&evidence, &name("manifest"), BOUND)
        .map_err(|error| super::lifecycle::held_read(error, "reclaimed manifest unreadable"))?
        .ok_or(Error::Held("reclaimed manifest missing"))?;
    if artifact.record().manifest != Some(Digest::of(manifest.bytes())) {
        return Err(Error::Held("reclaimed manifest differs"));
    }
    if names_build(artifact.record(), manifest.bytes()) != Some(true) {
        return Err(Error::Held("reclaimed artifact binding differs"));
    }
    store.binding_barrier(&manifest)?;
    store.binding_barrier(artifact.read())?;
    Ok(Evidence::Bound(Box::new(BoundArtifact {
        artifact: artifact.record().clone(),
        binding,
        panic: false,
        targeted: None,
    })))
}

fn names_attempt(artifact: &Artifact, attempt: &Attempt, command: &str) -> bool {
    artifact.run_id == attempt.attempt
        && artifact.manifest == Some(attempt.manifest)
        && artifact.command.as_str() == command
}

/// `None` reports manifest bytes outside UTF-8. `Some(true)` requires exactly
/// one `build = ` line whose value parses as a digest equal to
/// `artifact.archive`. Every other UTF-8 manifest returns `Some(false)`.
fn names_build(artifact: &Artifact, manifest: &[u8]) -> Option<bool> {
    let frozen = std::str::from_utf8(manifest).ok()?;
    let mut builds = frozen
        .lines()
        .filter_map(|line| line.strip_prefix("build = "));
    let build = builds.next().and_then(Digest::parse);
    Some(build.is_some() && builds.next().is_none() && artifact.archive == build)
}

fn bind(
    store: &impl ReadStore,
    directory: &Dir,
    attempt: &Attempt,
    command: &str,
) -> Result<BoundArtifact, Rejected> {
    let artifacts = store
        .open_dir(directory, &name("artifacts"))?
        .ok_or(Rejected::Missing)?;
    let directory = store
        .open_dir(&artifacts, &name(attempt.attempt.as_str()))?
        .ok_or(Rejected::Missing)?;
    let artifact = store
        .read_record::<Artifact>(&directory, &name("artifact"))?
        .ok_or(Rejected::Missing)?;
    store
        .binding_barrier(artifact.read())
        .map_err(|error| Rejected::Fault(error.into()))?;
    if !names_attempt(artifact.record(), attempt, command) {
        return Err(Rejected::Misbound);
    }
    let bundle_name = bundle_entry(command);
    let bundle = if artifact.record().bundle.is_none() {
        if store.open_file(&directory, &bundle_name)?.is_some() {
            return Err(Rejected::Misbound);
        }
        None
    } else {
        store.evidence_digest(&directory, &bundle_name, attempt.file_bytes)?
    };
    if artifact.record().bundle != bundle {
        return Err(Rejected::Misbound);
    }
    let manifest = store
        .read(&directory, &name("manifest"), BOUND)?
        .ok_or(Rejected::Malformed)?;
    store
        .binding_barrier(&manifest)
        .map_err(|error| Rejected::Fault(error.into()))?;
    if Digest::of(manifest.bytes()) != attempt.manifest {
        return Err(Rejected::Misbound);
    }
    if !names_build(artifact.record(), manifest.bytes()).ok_or(Rejected::Malformed)? {
        return Err(Rejected::Misbound);
    }
    let mut panic = false;
    let mut fork_output = None;
    for (phase, stream, digest) in artifact.record().streams() {
        let entry =
            crate::record::Artifact::stream_name(phase, stream).ok_or(Rejected::Malformed)?;
        let output = store
            .read(&directory, &entry, crate::sim::OUTPUT as u64)?
            .ok_or(Rejected::Malformed)?;
        store
            .binding_barrier(&output)
            .map_err(|error| Rejected::Fault(error.into()))?;
        if Digest::of(output.bytes()) != digest {
            return Err(Rejected::Misbound);
        }
        panic |= output.bytes().split(|byte| *byte == b'\n').any(|line| {
            if stream == "stdout" {
                phase.as_str() == "run" && line.starts_with(b"run: the run panicked at ")
            } else {
                panic_header(line)
            }
        });
        if matches!(command, "branch" | "explore")
            && phase.as_str() == command
            && stream == "stdout"
        {
            fork_output = Some(output);
        }
    }
    let targeted = if matches!(command, "branch" | "explore") {
        let jobs =
            crate::layout::jobs(store, &attempt.job.to_string())?.ok_or(Rejected::Misbound)?;
        // The live Admission read detects damage since the caller verified the job.
        let job = store
            .read_record::<crate::record::Admission>(
                &jobs,
                &name(&format!("{}.json", attempt.job)),
            )?
            .ok_or(Rejected::Misbound)?;
        let target = job.record().target().ok_or(Rejected::Misbound)?;
        if job.record().job().id().digest() != attempt.job
            || target.manifest != attempt.manifest
            || target.form.command() != command
            || artifact.record().bundle != Some(target.bundle)
        {
            return Err(Rejected::Misbound);
        }
        match fork_output {
            Some(output) => Some(
                std::str::from_utf8(output.bytes())
                    .ok()
                    .and_then(|output| super::targeted::judge(target, output).ok())
                    .unwrap_or_else(super::targeted::Judgment::malformed),
            ),
            None if store
                .open_file(&directory, &name(&format!("{command}.stdout")))?
                .is_some() =>
            {
                return Err(Rejected::Misbound);
            }
            None => Some(super::targeted::Judgment::malformed()),
        }
    } else {
        None
    };
    let binding = BoundEvidence {
        artifact: Digest::of(artifact.read().bytes()),
        attempt: attempt.attempt.clone(),
        bundle,
    };
    Ok(BoundArtifact {
        artifact: artifact.record().clone(),
        binding,
        panic,
        targeted,
    })
}

fn panic_header(line: &[u8]) -> bool {
    let Some(rest) = line.strip_prefix(b"thread '") else {
        return false;
    };
    rest.iter().enumerate().any(|(end, byte)| {
        if *byte != b'\'' {
            return false;
        }
        let rest = &rest[end + 1..];
        if rest.starts_with(b" panicked at ") {
            return true;
        }
        let Some(rest) = rest.strip_prefix(b" (") else {
            return false;
        };
        let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
        digits > 0 && rest[digits..].starts_with(b") panicked at ")
    })
}
