//! Regression commands bind frozen inputs and their verified failure identity.

use super::{Error, Step, executor, history, name, text, verdict};
use crate::attempt::Completed;
use crate::record::{RegressionCandidate, ReplayStatus, StepKind, TriageResult};
use crate::store::{ReadStore, Store};
use std::io::Read;

fn build(
    store: &impl ReadStore,
    step: &Step,
    result: &TriageResult,
    completed: &Completed,
    mode: Mode<'_>,
) -> Result<(), Error> {
    if !matches!(
        result.status,
        Some(ReplayStatus::Reproduced | ReplayStatus::Reduced)
    ) {
        return Ok(());
    }
    let deps = step.dependencies(store)?;
    let path = history::step_path(store, step.finding_id(), result.number);
    let source = path.join(step.finding_id());
    let reduced = result.status == Some(ReplayStatus::Reduced);
    let inputs = if reduced {
        reduced_inputs(store, step, completed, mode, &path)?
    } else {
        original_inputs(store, step, &deps, &source)?
    };
    let Inputs {
        bundle,
        bytes,
        manifest,
        input,
        mut command,
    } = inputs;
    let launcher = step.record.record().launcher.clone();
    let mut full = vec![
        text("sh")?,
        text("-c")?,
        text("out=$(mktemp -d \"$0/replay.XXXXXXXX\") && exec \"$@\" --artifacts \"$out\"")?,
        path_text(store.path())?,
        launcher,
    ];
    full.append(&mut command);
    let candidate = RegressionCandidate {
        archive: deps.archive,
        bundle,
        bytes,
        command: full,
        expected_exit: result.finished.exit,
        failure_identity: verdict::original_identity(store, step.finding.record())?,
        failure_kind: step.finding.record().kind,
        finding: result.finding.clone(),
        input,
        manifest,
        number: result.number,
        step_ms: if reduced { None } else { result.elapsed_ms },
        tier: text(
            if !reduced
                && result.elapsed_ms.is_some_and(|ms| ms <= 60_000)
                && bytes.is_some_and(|bytes| bytes <= 1 << 20)
            {
                "regression-pr"
            } else {
                "pinned-corpus"
            },
        )?,
    };
    check_record(
        store,
        &step.directory,
        "candidate",
        &candidate,
        mode,
        same_location,
    )
}

/// A sealed candidate may name the state directory through a spelling with
/// `..` components. The `input` path and each absolute `command` argument
/// that differs from `expected` match when they collapse lexically to the
/// expected path and the host resolves them to it, so a `..` that follows a
/// symlink is refused; every other field must be equal.
///
/// # Errors
///
/// [`Error::Store`] when the host resolution of a recorded path fails
/// through a fault such as `EIO` or `EMFILE`; any other resolution failure
/// is a mismatch.
pub(super) fn same_location(
    found: &RegressionCandidate,
    expected: &RegressionCandidate,
) -> Result<bool, Error> {
    let mut normalized = found.clone();
    normalized.input = expected.input.clone();
    normalized.command = expected.command.clone();
    if normalized != *expected || found.command.len() != expected.command.len() {
        return Ok(false);
    }
    for (found, expected) in std::iter::once((&found.input, &expected.input))
        .chain(found.command.iter().zip(&expected.command))
    {
        if !located(found, expected)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn located(found: &crate::record::Text, expected: &crate::record::Text) -> Result<bool, Error> {
    if found == expected {
        return Ok(true);
    }
    let path = std::path::Path::new(found.as_str());
    if !found.as_str().starts_with('/')
        || crate::store::lexical(path).to_str() != Some(expected.as_str())
    {
        return Ok(false);
    }
    match crate::store::canonical_host(path) {
        Ok(canonical) => Ok(canonical.to_str() == Some(expected.as_str())),
        Err(error) => {
            let error = crate::store::Unreadable::from(error);
            if error.faulted() {
                Err(Error::Store(crate::store::Error::Unreadable(error)))
            } else {
                Ok(false)
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Mode<'a> {
    Verify,
    Publish(&'a Store),
}
struct Inputs {
    bundle: Option<crate::record::Digest>,
    bytes: Option<u64>,
    manifest: crate::record::Digest,
    input: crate::record::Text,
    command: Vec<crate::record::Text>,
}
/// Publishes `value` once, or verifies that the sealed record `matches` it.
fn check_record<R: crate::record::Record + PartialEq>(
    store: &impl ReadStore,
    directory: &crate::store::Dir,
    name_value: &str,
    value: &R,
    mode: Mode<'_>,
    matches: fn(&R, &R) -> Result<bool, Error>,
) -> Result<(), Error> {
    if let Mode::Publish(writer) = mode {
        return super::super::once(writer, directory, name_value, value);
    }
    let found = store
        .read_record::<R>(directory, &name(name_value))?
        .ok_or_else(|| Error::Held("candidate dependency missing".into()))?;
    if !matches(found.record(), value)? {
        return Err(Error::Held("candidate differs from sealed step".into()));
    }
    store.barrier(found.read())?;
    Ok(())
}
pub(super) fn write(
    store: &Store,
    step: &Step,
    result: &TriageResult,
    completed: &Completed,
) -> Result<(), Error> {
    let mode = if store
        .read_record::<RegressionCandidate>(&step.directory, &name("candidate"))?
        .is_some()
    {
        Mode::Verify
    } else {
        Mode::Publish(store)
    };
    build(store, step, result, completed, mode)
}
pub(super) fn verify(
    store: &impl ReadStore,
    step: &Step,
    result: &TriageResult,
    completed: &Completed,
) -> Result<(), Error> {
    if store
        .read_record::<RegressionCandidate>(&step.directory, &name("candidate"))?
        .is_some()
    {
        if !matches!(
            result.status,
            Some(ReplayStatus::Reproduced | ReplayStatus::Reduced)
        ) {
            return Err(Error::Held(
                "candidate belongs to an ineligible step".into(),
            ));
        }
        build(store, step, result, completed, Mode::Verify)?;
    }
    Ok(())
}

/// The step's reduced output: its directory, the bundle digest verified against
/// `comparison.candidate`, and the candidate manifest.
pub(super) struct Reduced {
    directory: crate::store::Dir,
    digest: crate::record::Digest,
    manifest: crate::store::Read,
}

pub(super) fn verified_manifest(
    store: &impl ReadStore,
    step: &Step,
    comparison: &crate::record::Comparison,
) -> Result<Reduced, Error> {
    let reduced = store
        .open_dir(&step.directory, &name("reduced"))?
        .ok_or_else(|| Error::Held("reduction output missing".into()))?;
    if store
        .open_file(&reduced, &name("regression.bundle"))?
        .is_none()
    {
        return Err(Error::Held("reduced bundle missing".into()));
    }
    let expected = crate::store::canonical_host(
        &history::step_path(
            store,
            step.finding_id(),
            step.record.record().attempt.number,
        )
        .join("reduced/regression.bundle"),
    )
    .map_err(crate::store::Error::Io)?;
    if comparison.output.as_ref().map(|value| value.as_str()) != expected.to_str() {
        return Err(Error::Held("reduced candidate path differs".into()));
    }
    let digest = store.evidence_digest(
        &reduced,
        &name("regression.bundle"),
        step.record.record().attempt.file_bytes,
    )?;
    let Some(digest) = digest.filter(|digest| Some(*digest) == comparison.candidate) else {
        return Err(Error::Held("reduced candidate digest differs".into()));
    };
    let artifacts = store
        .open_dir(&step.directory, &name("artifacts"))?
        .ok_or_else(|| Error::Held("step artifacts missing".into()))?;
    let directory = store
        .open_dir(&artifacts, &name(step.identity().as_str()))?
        .ok_or_else(|| Error::Held("step artifact missing".into()))?;
    let manifest = store
        .read(
            &directory,
            &name("candidate.manifest"),
            crate::record::BOUND,
        )?
        .ok_or_else(|| Error::Held("verified candidate manifest missing".into()))?;
    let file = store
        .open_file(&reduced, &name("regression.bundle"))?
        .ok_or_else(|| Error::Held("reduced bundle missing".into()))?;
    let mut stager = crate::sim::Stager::new(
        file.take(step.record.record().attempt.file_bytes.saturating_add(1)),
    );
    std::io::copy(&mut stager, &mut std::io::sink()).map_err(crate::store::Error::Io)?;
    if let Some(error) = stager.read_error() {
        return Err(Error::Store(crate::store::Error::Io(
            match error.raw_os_error() {
                Some(errno) => std::io::Error::from_raw_os_error(errno),
                None => std::io::Error::new(error.kind(), error.to_string()),
            },
        )));
    }
    let staged = stager.finish().map_err(Error::Held)?;
    let experiment = step.finding.record().admission.job().experiment();
    let values = crate::sim::Values::parse(&staged.manifest, "candidate").map_err(Error::Held)?;
    values
        .pinned(&experiment.pins, "candidate")
        .map_err(Error::Held)?;
    let version = experiment
        .manifest_version
        .as_str()
        .parse::<u32>()
        .map_err(|_| Error::Held("original manifest version invalid".into()))?;
    values
        .versioned(version, "candidate")
        .map_err(Error::Held)?;
    let derived = crate::sim::worker_manifest(&staged.manifest);
    if Some(staged.digest) != comparison.candidate
        || crate::record::Digest::of(&derived) != crate::record::Digest::of(manifest.bytes())
    {
        return Err(Error::Held(
            "candidate manifest differs from reduced bundle".into(),
        ));
    }
    store.barrier(&manifest)?;
    Ok(Reduced {
        directory: reduced,
        digest,
        manifest,
    })
}

fn reduced_inputs(
    store: &impl ReadStore,
    step: &Step,
    completed: &Completed,
    mode: Mode<'_>,
    path: &std::path::Path,
) -> Result<Inputs, Error> {
    let comparison = completed
        .bound()
        .and_then(|bound| bound.artifact().comparison.as_ref())
        .ok_or_else(|| Error::Held("reduced step lacks comparison".into()))?;
    let Reduced {
        directory,
        digest,
        manifest,
    } = verified_manifest(store, step, comparison)?;
    let file = store
        .open_file(&directory, &name("regression.bundle"))?
        .ok_or_else(|| Error::Held("reduced candidate missing".into()))?;
    let bytes = file.len();
    let manifest_digest = crate::record::Digest::of(manifest.bytes());
    let candidate_id = format!("{}-candidate", step.identity().as_str());
    if let Mode::Publish(writer) = mode {
        writer.mkdir(&step.directory, &name(&candidate_id))?;
    }
    let candidate_dir = store
        .open_dir(&step.directory, &name(&candidate_id))?
        .ok_or_else(|| Error::Held("candidate input directory missing".into()))?;
    if let Mode::Publish(writer) = mode {
        let file = store
            .open_file(&directory, &name("regression.bundle"))?
            .ok_or_else(|| Error::Held("reduced bundle missing".into()))?;

        if store
            .evidence_digest(
                &candidate_dir,
                &name("input"),
                step.record.record().attempt.file_bytes,
            )?
            .is_none()
        {
            if file.len() > crate::sys::controller_file_limit().map_err(crate::store::Error::Io)? {
                return Err(Error::Held(
                    "candidate copy exceeds controller RLIMIT_FSIZE".into(),
                ));
            }
            writer.copy_once(
                &candidate_dir,
                &name("input"),
                &mut file.take(step.record.record().attempt.file_bytes.saturating_add(1)),
                0o400,
            )?;
        }
        if store
            .read(&candidate_dir, &name("manifest"), crate::record::BOUND)?
            .is_none()
        {
            if manifest.bytes().len() as u64 > executor::controller_limit()? {
                return Err(Error::Held(
                    "candidate manifest exceeds controller RLIMIT_FSIZE".into(),
                ));
            }
            writer.create_once(&candidate_dir, &name("manifest"), manifest.bytes())?;
        }
    }
    if store.evidence_digest(
        &candidate_dir,
        &name("input"),
        step.record.record().attempt.file_bytes,
    )? != Some(digest)
        || store.evidence_digest(&candidate_dir, &name("manifest"), crate::record::BOUND)?
            != Some(manifest_digest)
    {
        return Err(Error::Held("candidate frozen inputs differ".into()));
    }
    let mut artifact = completed
        .bound()
        .expect("reduction has bound evidence")
        .artifact()
        .clone();
    artifact.run_id = text(&candidate_id)?;
    artifact.bundle = Some(digest);
    artifact.manifest = Some(manifest_digest);
    artifact.summary = comparison.observed.clone();
    artifact.workers.clear();
    let baseline = artifact
        .comparison
        .as_mut()
        .expect("reduction has comparison");
    baseline.original = comparison.observed.clone();
    check_record(
        store,
        &candidate_dir,
        "artifact",
        &artifact,
        mode,
        |found, expected| Ok(found == expected),
    )?;
    let source = path.join(candidate_id);
    let input = path_text(&source)?;
    Ok(Inputs {
        bundle: Some(digest),
        bytes: Some(bytes),
        manifest: manifest_digest,
        input: input.clone(),
        command: vec![text("sim")?, text("replay")?, text("--from-run")?, input],
    })
}
fn original_inputs(
    store: &impl ReadStore,
    step: &Step,
    deps: &crate::record::ReplayDependencies,
    source: &std::path::Path,
) -> Result<Inputs, Error> {
    let directory = store
        .open_dir(&step.directory, &name(step.finding_id()))?
        .ok_or_else(|| Error::Held("candidate source missing".into()))?;
    let bytes = if deps.bundle.is_some() {
        let file = store
            .open_file(
                &directory,
                &name(
                    if step
                        .finding
                        .record()
                        .artifact
                        .as_ref()
                        .is_some_and(|artifact| artifact.command.as_str() == "replay")
                    {
                        "input"
                    } else {
                        "bundle"
                    },
                ),
            )?
            .ok_or_else(|| Error::Held("candidate bundle missing".into()))?;
        Some(file.len())
    } else {
        None
    };
    let input = path_text(source)?;
    let args = if step.finding.record().admission.target().is_some() {
        vec![
            text("sim")?,
            text("replay")?,
            path_text(&source.join("bundle"))?,
            text("--archive")?,
            deps.archive_path.clone(),
        ]
    } else {
        original_command(
            step.record.record().kind,
            step.finding
                .record()
                .artifact
                .as_ref()
                .map(|artifact| &artifact.command),
            source,
            &deps.archive_path,
        )?
    };
    Ok(Inputs {
        bundle: deps.bundle,
        bytes,
        manifest: deps.manifest,
        input,
        command: args,
    })
}

fn path_text(path: &std::path::Path) -> Result<crate::record::Text, Error> {
    text(
        path.to_str()
            .ok_or_else(|| Error::Held("candidate input path is not UTF-8".into()))?,
    )
}

fn original_command(
    kind: StepKind,
    source_command: Option<&crate::record::Text>,
    source: &std::path::Path,
    archive: &crate::record::Text,
) -> Result<Vec<crate::record::Text>, Error> {
    if kind == StepKind::Replay
        || kind == StepKind::Reduce
            && source_command.is_some_and(|command| command.as_str() == "replay")
    {
        Ok(vec![
            text("sim")?,
            text("replay")?,
            text("--from-run")?,
            path_text(source)?,
        ])
    } else {
        Ok(vec![
            text("sim")?,
            text("run")?,
            text("--archive")?,
            archive.clone(),
            text("--manifest")?,
            path_text(&source.join("manifest"))?,
        ])
    }
}

#[cfg(test)]
mod command_tests {
    use super::*;
    #[test]
    fn replay_source_reduce_candidate_preserves_the_replay_command() {
        let source = std::path::Path::new("/source");
        for (kind, command, replay) in [
            (StepKind::Reduce, "replay", true),
            (StepKind::Replay, "replay", true),
            (StepKind::Rerun, "replay", false),
            (StepKind::Reduce, "run", false),
        ] {
            let args = original_command(
                kind,
                Some(&text(command).unwrap()),
                source,
                &text("/archive").unwrap(),
            )
            .unwrap();
            let actual = args.iter().map(|arg| arg.as_str()).collect::<Vec<_>>();
            if replay {
                assert_eq!(actual, ["sim", "replay", "--from-run", "/source"]);
            } else {
                assert_eq!(
                    actual,
                    [
                        "sim",
                        "run",
                        "--archive",
                        "/archive",
                        "--manifest",
                        "/source/manifest"
                    ]
                );
            }
        }
    }
}
