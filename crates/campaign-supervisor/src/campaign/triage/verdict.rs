//! Triage outcomes compare frozen facts and full failure identities.

use super::{Error, Step, executor, history, name, text};
use crate::attempt::Completed;
use crate::record::{
    Artifact, Class, FindingKind, ReplayStatus, StepKind, StepState, Text, TriageResult,
};
use crate::store::{Dir, ReadStore, Store};

#[derive(PartialEq, Eq)]
enum Identity {
    Absent,
    Unavailable,
    Known(Text),
}

impl Identity {
    fn bounded(identity: Option<Text>) -> Self {
        match identity {
            Some(identity) if identity.as_str().len() as u64 <= crate::record::BOUND / 16 => {
                Self::Known(identity)
            }
            Some(_) => Self::Unavailable,
            None => Self::Absent,
        }
    }

    fn known(&self) -> Option<Text> {
        match self {
            Self::Known(identity) => Some(identity.clone()),
            Self::Absent | Self::Unavailable => None,
        }
    }
}

fn identity(
    store: &impl ReadStore,
    directory: &Dir,
    artifact: Option<&Artifact>,
    kind: FindingKind,
) -> Result<Identity, Error> {
    let Some(artifact) = artifact else {
        return Ok(Identity::Absent);
    };
    if artifact
        .summary
        .as_ref()
        .and_then(|summary| summary.identity.clone())
        .is_some_and(|identity| Identity::bounded(Some(identity)) == Identity::Unavailable)
    {
        return Ok(Identity::Unavailable);
    }
    if kind != FindingKind::Panic {
        return Ok(Identity::bounded(
            artifact
                .outcome_summary()
                .and_then(|summary| summary.identity.clone()),
        ));
    }
    if !matches!(artifact.command.as_str(), "replay" | "reduce")
        && let Some(comparison) = &artifact.comparison
        && comparison
            .failure_kind
            .as_ref()
            .is_some_and(|kind| kind.as_str() == "panic")
    {
        return Ok(Identity::bounded(comparison.failure_identity.clone()));
    }
    panic_line(
        store,
        directory,
        artifact,
        match artifact.command.as_str() {
            "replay" => "replay",
            "reduce" => "baseline",
            _ => "run",
        },
    )
}

fn panic_line(
    store: &impl ReadStore,
    directory: &Dir,
    artifact: &Artifact,
    phase: &str,
) -> Result<Identity, Error> {
    let read = |phase: &str| -> Result<Option<String>, Error> {
        let Some(worker) = artifact
            .workers
            .iter()
            .find(|(key, _)| key.as_str() == phase)
            .map(|(_, worker)| worker)
        else {
            return Ok(None);
        };
        let Some(read) = store.read(
            directory,
            &name(&format!("{phase}.stdout")),
            crate::sim::OUTPUT as u64,
        )?
        else {
            return Ok(None);
        };
        store.barrier(&read)?;
        if crate::record::Digest::of(read.bytes()) != worker.stdout {
            return Err(Error::Held("panic stream digest differs".into()));
        }
        Ok(String::from_utf8(read.bytes().to_vec()).ok())
    };
    let Some(capabilities) = read("capabilities")? else {
        return Ok(Identity::Unavailable);
    };
    let Some(listing) = crate::protocol::Listing::parse(&capabilities).ok() else {
        return Ok(Identity::Unavailable);
    };
    let Some(run) = read(phase)? else {
        return Ok(Identity::Unavailable);
    };
    let panic = if matches!(phase, "replay" | "baseline") {
        match crate::protocol::ReplayResult::parse(&run).ok() {
            Some(crate::protocol::ReplayResult::Panicked(identity)) => Some(identity),
            _ => None,
        }
    } else {
        match crate::protocol::Run::parse(&run, &listing).ok() {
            Some(crate::protocol::Run::Panicked(identity)) => Some(identity),
            _ => None,
        }
    };
    match panic {
        Some(identity) => {
            if identity.len() > crate::sim::REASON {
                return Ok(Identity::Unavailable);
            }
            let escaped = identity
                .chars()
                .flat_map(char::escape_default)
                .collect::<String>();
            if escaped.len() as u64 > crate::record::BOUND / 16 {
                return Ok(Identity::Unavailable);
            }
            Ok(Identity::Known(text(&escaped)?))
        }
        None => Ok(Identity::Unavailable),
    }
}

/// A violation or panic of the expected kind reproduces only when both
/// failure identities are known and equal.
fn replay_source_status(
    step: StepKind,
    comparison: Option<&crate::record::Comparison>,
    finished: &crate::record::Finished,
    retained: Option<&crate::record::Comparison>,
    expected: (FindingKind, &Identity),
    observed_kind: Option<FindingKind>,
    observed: &Identity,
) -> ReplayStatus {
    let (expected_kind, expected) = expected;
    let Some(comparison) = comparison else {
        return ReplayStatus::InsufficientEvidence;
    };
    if step == StepKind::Reduce && comparison.status.as_str() == "unreducible" {
        return if finished.exit == Some(1)
            && retained
                .and_then(|retained| retained.original.as_ref())
                .is_some()
            && comparison.original.as_ref()
                == retained.and_then(|retained| retained.original.as_ref())
            && comparison.observed == comparison.original
            && comparison.divergence.is_none()
        {
            ReplayStatus::Unreducible
        } else {
            ReplayStatus::Diverged
        };
    }
    if finished.class == Class::Pass {
        return ReplayStatus::Unreproduced;
    }
    if !matches!(finished.exit, Some(0 | 1))
        || !matches!(comparison.status.as_str(), "diverged" | "reproduced")
    {
        return ReplayStatus::InsufficientEvidence;
    }
    if observed_kind.is_none()
        || expected == &Identity::Unavailable
        || observed == &Identity::Unavailable
        || observed_kind == Some(expected_kind)
            && matches!(expected_kind, FindingKind::Violation | FindingKind::Panic)
            && (expected == &Identity::Absent || observed == &Identity::Absent)
        || comparison.observed.is_none()
            && expected_kind != FindingKind::Panic
            && expected_kind != FindingKind::Abort
    {
        return ReplayStatus::InsufficientEvidence;
    }
    if comparison.observed.as_ref() != retained.and_then(|retained| retained.observed.as_ref()) {
        return ReplayStatus::Diverged;
    }
    if observed_kind == Some(expected_kind) && observed == expected {
        ReplayStatus::Reproduced
    } else {
        ReplayStatus::Diverged
    }
}

pub(super) fn judge(
    store: &impl ReadStore,
    step: &Step,
    completed: &Completed,
    elapsed_ms: Option<u64>,
) -> Result<TriageResult, Error> {
    let dependencies = step.dependencies(store)?;
    let original = history::finding(store, step.finding_id())?;
    if original.record() != step.finding.record() {
        return Err(Error::Held("finding changed during triage".into()));
    }
    let finished = completed.finished().record();
    let output_limited = completed.bound().is_some_and(|bound| {
        bound
            .artifact()
            .workers
            .values()
            .any(|worker| worker.ended.as_str() == "oversized")
    });
    let file_limited = completed.bound().is_some_and(|bound| {
        bound
            .artifact()
            .workers
            .values()
            .any(|worker| worker.signal == Some(crate::sys::OUTPUT_SIGNAL as u64))
    });
    let interrupted = finished.interrupted_step() || output_limited || file_limited;
    let mut result = TriageResult {
        comparison: None,
        elapsed_ms,
        file_limited,
        finding: step.record.record().finding.clone(),
        finished: finished.clone(),
        number: step.record.record().attempt.number,
        output_limited,
        state: if interrupted {
            StepState::Interrupted
        } else {
            StepState::Complete
        },
        status: None,
    };
    if interrupted {
        return Ok(result);
    }
    let artifact = completed.bound().map(|bound| bound.artifact());
    if step.record.record().kind == StepKind::Rerun && finished.class == Class::Pass {
        result.status = Some(ReplayStatus::Unreproduced);
        return Ok(result);
    }
    let Some(artifact) = artifact.filter(|artifact| artifact.archive == Some(dependencies.archive))
    else {
        result.status = Some(ReplayStatus::InsufficientEvidence);
        return Ok(result);
    };
    if step.record.record().kind == StepKind::Rerun
        && crate::attempt::finding_kind(finished, completed.bound())
            .is_some_and(|kind| kind != step.finding.record().kind)
    {
        result.status = Some(ReplayStatus::Diverged);
        return Ok(result);
    }
    if step.finding.record().admission.target().is_some()
        && step.record.record().kind == StepKind::Replay
    {
        result.status = Some(child_replay(
            step.finding.record().child.as_ref(),
            completed.bound().map(|bound| bound.artifact()),
            finished,
            dependencies.bundle,
        ));
        result.comparison = completed
            .bound()
            .and_then(|bound| bound.artifact().comparison.clone());
        return Ok(result);
    }
    let expected_identity = original_evidence(store, step.finding.record())?;
    if expected_identity == Identity::Unavailable
        || (expected_identity == Identity::Absent
            && step.finding.record().kind == FindingKind::Panic)
    {
        result.status = Some(ReplayStatus::InsufficientEvidence);
        return Ok(result);
    }
    let expected = expected_identity.known();
    result.comparison = artifact.comparison.clone();
    if step
        .finding
        .record()
        .artifact
        .as_ref()
        .is_some_and(|source| source.command.as_str() == "replay")
        && step.record.record().kind != StepKind::Rerun
        && !(step.record.record().kind == StepKind::Replay
            && step.finding.record().kind == FindingKind::Abort)
    {
        let reduce = step.record.record().kind == StepKind::Reduce;
        let observed_kind = if reduce
            && artifact
                .comparison
                .as_ref()
                .and_then(|comparison| comparison.observed.as_ref())
                .is_some_and(complete_violation)
        {
            Some(FindingKind::Violation)
        } else {
            crate::attempt::finding_kind(finished, completed.bound())
        };
        let observed_identity = match observed_kind {
            Some(kind) => {
                let artifacts = store
                    .open_dir(&step.directory, &name("artifacts"))?
                    .ok_or_else(|| Error::Held("step artifacts missing".into()))?;
                let directory = store
                    .open_dir(&artifacts, &name(step.identity().as_str()))?
                    .ok_or_else(|| Error::Held("step artifact missing".into()))?;
                if reduce && kind == FindingKind::Violation {
                    Identity::bounded(
                        artifact
                            .comparison
                            .as_ref()
                            .and_then(|comparison| comparison.observed.as_ref())
                            .and_then(|summary| summary.identity.clone()),
                    )
                } else {
                    identity(store, &directory, Some(artifact), kind)?
                }
            }
            None => Identity::Absent,
        };
        result.status = Some(replay_source_status(
            step.record.record().kind,
            artifact.comparison.as_ref(),
            finished,
            step.finding
                .record()
                .artifact
                .as_ref()
                .and_then(|artifact| artifact.comparison.as_ref()),
            (step.finding.record().kind, &expected_identity),
            observed_kind,
            &observed_identity,
        ));
        return Ok(result);
    }
    let original = step
        .finding
        .record()
        .artifact
        .as_ref()
        .and_then(|artifact| artifact.outcome_summary().cloned());
    let candidate_panics = step.record.record().kind == StepKind::Reduce
        && step.finding.record().kind == FindingKind::Panic
        && panic_line(
            store,
            &step_artifact(store, step)?,
            artifact,
            "panic-candidate",
        )? == expected_identity;
    result.status = Some(match step.record.record().kind {
        StepKind::Rerun => {
            if let Some(kind) = crate::attempt::finding_kind(finished, completed.bound()) {
                let observed = identity(store, &step_artifact(store, step)?, Some(artifact), kind)?;
                let declared = artifact
                    .summary
                    .as_ref()
                    .is_some_and(|summary| summary.identity.is_some())
                    || artifact
                        .comparison
                        .as_ref()
                        .is_some_and(|comparison| comparison.failure_identity.is_some());
                if observed == Identity::Unavailable
                    || (observed == Identity::Absent
                        && (declared
                            || kind == FindingKind::Violation
                            || kind == FindingKind::Panic))
                {
                    ReplayStatus::InsufficientEvidence
                } else if kind == step.finding.record().kind && observed == expected_identity {
                    ReplayStatus::Reproduced
                } else {
                    ReplayStatus::Diverged
                }
            } else if artifact.summary.is_some()
                && matches!(finished.class, Class::Unsuccessful | Class::Inconclusive)
            {
                ReplayStatus::Diverged
            } else {
                ReplayStatus::InsufficientEvidence
            }
        }
        StepKind::Replay if step.finding.record().kind == FindingKind::Abort => {
            if original.is_some()
                && matches!(finished.exit, Some(1 | 4))
                && artifact
                    .workers
                    .get(&text("replay")?)
                    .is_some_and(|worker| {
                        worker.ended.as_str() == "signaled"
                            && worker.exit.is_none()
                            && worker
                                .signal
                                .is_some_and(|signal| signal > 0 && signal <= 64)
                    })
                && crate::attempt::finding_kind(finished, completed.bound())
                    == Some(FindingKind::Abort)
                && identity(
                    store,
                    &step_artifact(store, step)?,
                    Some(artifact),
                    FindingKind::Abort,
                )? == expected_identity
            {
                ReplayStatus::Reproduced
            } else {
                ReplayStatus::InsufficientEvidence
            }
        }
        StepKind::Replay | StepKind::Reduce => match artifact.comparison.as_ref() {
            Some(comparison) => match comparison.status.as_str() {
                "reproduced"
                    if step.record.record().kind == StepKind::Replay
                        && matches!(finished.exit, Some(0 | 1))
                        && comparison.divergence.is_none()
                        && comparison.observed == comparison.original
                        && (step.finding.record().kind != FindingKind::Panic
                            || (expected.is_some()
                                && comparison.failure_kind.as_ref().map(Text::as_str)
                                    == Some("panic")
                                && comparison.failure_identity == expected))
                        && comparison.original == original
                        && (step.finding.record().kind != FindingKind::Abort
                            || comparison.failure_kind.as_ref().map(Text::as_str)
                                == Some("abort")) =>
                {
                    ReplayStatus::Reproduced
                }
                "reduced"
                    if step.record.record().kind == StepKind::Reduce
                        && finished.exit == Some(1)
                        && comparison.failure_kind.as_ref().map(Text::as_str)
                            == Some(step.finding.record().kind.name())
                        && comparison.failure_identity == expected
                        && expected.is_some()
                        && comparison.candidate.is_some()
                        && comparison.output.is_some()
                        && comparison.divergence.is_none()
                        && comparison.original == original
                        && (step.finding.record().kind != FindingKind::Panic
                            || candidate_panics)
                        && (step.finding.record().kind != FindingKind::Violation
                            || comparison.observed.as_ref().is_some_and(|summary| {
                                summary.identity == expected && complete_violation(summary)
                            })) =>
                {
                    super::candidate::verified_manifest(store, step, comparison)?;
                    ReplayStatus::Reduced
                }
                "unreproduced" => ReplayStatus::Unreproduced,
                "diverged" => ReplayStatus::Diverged,
                "unreducible"
                    if step.record.record().kind == StepKind::Reduce
                        && finished.exit == Some(1)
                        && expected.is_some()
                        && comparison.failure_kind.as_ref().map(Text::as_str)
                            == Some(step.finding.record().kind.name())
                        && comparison.failure_identity == expected
                        && comparison.original == original
                        && comparison.observed == original
                        && comparison.divergence.is_none() =>
                {
                    ReplayStatus::Unreducible
                }
                "unreducible" => ReplayStatus::Diverged,
                "reduced" | "reproduced" => ReplayStatus::Diverged,
                _ => ReplayStatus::InsufficientEvidence,
            },
            None => ReplayStatus::InsufficientEvidence,
        },
    });
    Ok(result)
}

fn step_artifact(store: &impl ReadStore, step: &Step) -> Result<Dir, Error> {
    let artifacts = store
        .open_dir(&step.directory, &name("artifacts"))?
        .ok_or_else(|| Error::Held("step artifact root missing".into()))?;
    store
        .open_dir(&artifacts, &name(step.identity().as_str()))?
        .ok_or_else(|| Error::Held("step artifact missing".into()))
}

pub(super) fn complete_violation(summary: &crate::record::Summarized) -> bool {
    matches!(
        crate::protocol::Terminal::parse(summary.terminal.as_str(), "terminal"),
        Ok(crate::protocol::Terminal::Complete {
            outcome: crate::protocol::Outcome::Violation,
            ..
        })
    )
}
pub(super) fn original_identity(
    store: &impl ReadStore,
    finding: &crate::record::Finding,
) -> Result<Option<Text>, Error> {
    Ok(original_evidence(store, finding)?.known())
}

fn original_evidence(
    store: &impl ReadStore,
    finding: &crate::record::Finding,
) -> Result<Identity, Error> {
    identity(
        store,
        &executor::retained(store, finding.id().as_str())?,
        finding.artifact.as_ref(),
        finding.kind,
    )
}
pub(super) fn reduction(
    store: &Store,
    finding: &crate::record::Finding,
) -> Result<Option<&'static str>, Error> {
    if !matches!(finding.kind, FindingKind::Violation | FindingKind::Panic) {
        return Ok(Some("reduction needs a complete original failure identity"));
    }
    if finding
        .artifact
        .as_ref()
        .is_none_or(|artifact| artifact.bundle.is_none())
    {
        return Ok(Some("triage step needs a retained bundle"));
    }
    if original_identity(store, finding)?.is_none() {
        return Ok(Some("reduction needs a complete original failure identity"));
    }
    if finding.kind == FindingKind::Violation
        && finding
            .artifact
            .as_ref()
            .and_then(|artifact| artifact.outcome_summary())
            .is_none_or(|summary| !complete_violation(summary))
    {
        return Ok(Some("reduction needs a complete original violation"));
    }
    Ok(None)
}

/// Compares the child's semantic digest and terminal with bound replay observations.
fn child_replay(
    child: Option<&crate::record::ChildEvidence>,
    artifact: Option<&Artifact>,
    finished: &crate::record::Finished,
    bundle: Option<crate::record::Digest>,
) -> ReplayStatus {
    let Some((digest, terminal)) = child.and_then(|child| child.replay_facts()) else {
        return ReplayStatus::InsufficientEvidence;
    };
    if bundle.is_none() || artifact.is_none_or(|artifact| artifact.bundle != bundle) {
        return ReplayStatus::InsufficientEvidence;
    }
    let Some(comparison) = artifact.and_then(|artifact| artifact.comparison.as_ref()) else {
        return ReplayStatus::InsufficientEvidence;
    };
    let Some(observed) = &comparison.observed else {
        return ReplayStatus::InsufficientEvidence;
    };
    if finished.class == Class::Pass
        || (comparison.status.as_str() == "unreproduced"
            && matches!(finished.exit, Some(0 | 1))
            && crate::protocol::Terminal::parse(observed.terminal.as_str(), "terminal")
                .is_ok_and(|terminal| terminal.passes()))
    {
        return ReplayStatus::Unreproduced;
    }
    if observed.digest != digest || &observed.terminal != terminal {
        return ReplayStatus::Diverged;
    }
    if comparison.status.as_str() == "reproduced"
        && matches!(finished.exit, Some(0 | 1))
        && comparison.divergence.is_none()
        && comparison.original.as_ref() == Some(observed)
    {
        ReplayStatus::Reproduced
    } else if comparison.status.as_str() == "diverged" {
        ReplayStatus::Diverged
    } else {
        ReplayStatus::InsufficientEvidence
    }
}

#[cfg(test)]
mod replay_source_tests {
    use super::*;
    pub(super) fn facts() -> crate::record::Summarized {
        crate::record::Summarized {
            cause: None,
            counts: false,
            decisions: Some(3),
            digest: crate::record::Digest::of(b"original"),
            first_failure: Some(crate::record::Event {
                node: None,
                operation: None,
                record: text("01").unwrap(),
                semantic_record: 1,
                virtual_us: Some(10),
            }),
            identity: Some(text("v1:failure").unwrap()),
            ledger: None,
            terminal: text("complete violation fired=03 required=03").unwrap(),
            unsuccessful: None,
        }
    }
    pub(super) fn comparison() -> crate::record::Comparison {
        crate::record::Comparison {
            candidate: None,
            divergence: None,
            failure_identity: None,
            failure_kind: None,
            observed: Some(facts()),
            original: Some(facts()),
            output: None,
            status: text("diverged").unwrap(),
        }
    }
    pub(super) fn finish(exit: Option<u64>) -> crate::record::Finished {
        crate::record::Finished {
            attempt: text("step").unwrap(),
            binding: crate::record::Binding::Matching,
            bound: None,
            class: Class::Violation,
            exit,
            interruption: None,
            kernel: Default::default(),
            residual_members: false,
            signal: None,
            watchdog: false,
        }
    }
    #[test]
    fn replay_source_unreducible_requires_the_retained_baseline_and_exit_one() {
        let identity = Identity::Known(text("v1:failure").unwrap());
        let retained = comparison();
        let mut current = retained.clone();
        current.status = text("unreducible").unwrap();
        assert_eq!(
            replay_source_status(
                StepKind::Reduce,
                Some(&current),
                &finish(Some(1)),
                Some(&retained),
                (FindingKind::Violation, &identity),
                Some(FindingKind::Violation),
                &identity
            ),
            ReplayStatus::Unreducible
        );
        for mutation in [
            "original",
            "observed",
            "missing-baseline",
            "exit",
            "divergence",
        ] {
            let mut changed = current.clone();
            let mut stopped = finish(Some(1));
            let mut original = retained.clone();
            match mutation {
                "original" => {
                    changed.original.as_mut().unwrap().digest =
                        crate::record::Digest::of(b"changed")
                }
                "observed" => changed.observed.as_mut().unwrap().decisions = Some(4),
                "missing-baseline" => original.original = None,
                "exit" => stopped.exit = Some(4),
                "divergence" => {
                    changed.divergence = Some(crate::record::Difference {
                        committed: None,
                        replayed: None,
                    })
                }
                _ => unreachable!(),
            }
            assert_eq!(
                replay_source_status(
                    StepKind::Reduce,
                    Some(&changed),
                    &stopped,
                    Some(&original),
                    (FindingKind::Violation, &identity),
                    Some(FindingKind::Violation),
                    &identity
                ),
                ReplayStatus::Diverged,
                "{mutation}"
            );
        }
    }
}

#[cfg(test)]
#[path = "child_tests.rs"]
mod child_tests;

#[cfg(test)]
mod panic_tests {
    use super::*;
    #[test]
    fn replay_panic_identity_uses_the_replay_grammar_and_preserves_limits() {
        let case = crate::store::fixture::Case::new();
        let store = Store::open(&case.state).unwrap();
        let mut artifact =
            crate::attempt::tests::artifact("panic", crate::record::Digest::of(b"manifest"));
        artifact.command = text("replay").unwrap();
        let capabilities = include_bytes!("../../../testdata/admission-listing.txt");
        store
            .create_once(store.root(), &name("capabilities.stdout"), capabilities)
            .unwrap();
        let mut worker = artifact.workers[&text("run").unwrap()].clone();
        worker.stdout = crate::record::Digest::of(capabilities);
        artifact
            .workers
            .insert(text("capabilities").unwrap(), worker);
        for (line, expected) in [
            (
                "replay: the run panicked at same\n".to_owned(),
                Some("same"),
            ),
            (
                "replay: the run panicked at other\n".to_owned(),
                Some("other"),
            ),
            (
                "replay: diverged at the result: different\n".to_owned(),
                None,
            ),
            (
                format!(
                    "replay: the run panicked at {}\n",
                    "x".repeat(crate::sim::REASON + 1)
                ),
                None,
            ),
        ] {
            store
                .replace(store.root(), &name("replay.stdout"), line.as_bytes())
                .unwrap();
            let mut worker = artifact.workers[&text("run").unwrap()].clone();
            worker.stdout = crate::record::Digest::of(line.as_bytes());
            artifact.workers.insert(text("replay").unwrap(), worker);
            let observed =
                identity(&store, store.root(), Some(&artifact), FindingKind::Panic).unwrap();
            match expected {
                Some(expected) => assert!(observed == Identity::Known(text(expected).unwrap())),
                None => assert!(observed == Identity::Unavailable),
            }
        }
    }
}

#[cfg(test)]
mod replay_fact_tests {
    use super::replay_source_tests::{comparison, finish};
    use super::*;
    #[test]
    fn replay_source_reproduction_preserves_all_retained_observation_facts() {
        let identity = Identity::Known(text("v1:failure").unwrap());
        let retained = comparison();
        let stopped = finish(Some(1));
        assert_eq!(
            replay_source_status(
                StepKind::Replay,
                Some(&retained),
                &stopped,
                Some(&retained),
                (FindingKind::Violation, &identity),
                Some(FindingKind::Violation),
                &identity
            ),
            ReplayStatus::Reproduced
        );
        for mutation in ["digest", "decisions", "first-failure"] {
            let mut current = retained.clone();
            let observed = current.observed.as_mut().unwrap();
            match mutation {
                "digest" => observed.digest = crate::record::Digest::of(b"different"),
                "decisions" => observed.decisions = Some(4),
                "first-failure" => observed.first_failure.as_mut().unwrap().virtual_us = Some(11),
                _ => unreachable!(),
            }
            assert_eq!(
                replay_source_status(
                    StepKind::Replay,
                    Some(&current),
                    &stopped,
                    Some(&retained),
                    (FindingKind::Violation, &identity),
                    Some(FindingKind::Violation),
                    &identity
                ),
                ReplayStatus::Diverged,
                "{mutation}"
            );
        }
        let other = Identity::Known(text("v1:other").unwrap());
        assert_eq!(
            replay_source_status(
                StepKind::Replay,
                Some(&retained),
                &stopped,
                Some(&retained),
                (FindingKind::Violation, &identity),
                Some(FindingKind::Violation),
                &other
            ),
            ReplayStatus::Diverged
        );
        for (kind, expected) in [
            (FindingKind::Violation, ReplayStatus::InsufficientEvidence),
            (FindingKind::Panic, ReplayStatus::InsufficientEvidence),
            (FindingKind::Abort, ReplayStatus::Reproduced),
        ] {
            assert_eq!(
                replay_source_status(
                    StepKind::Replay,
                    Some(&retained),
                    &stopped,
                    Some(&retained),
                    (kind, &Identity::Absent),
                    Some(kind),
                    &Identity::Absent
                ),
                expected,
                "{kind:?}"
            );
        }
        assert_eq!(
            replay_source_status(
                StepKind::Replay,
                Some(&retained),
                &stopped,
                Some(&retained),
                (FindingKind::Violation, &identity),
                Some(FindingKind::Violation),
                &Identity::Absent
            ),
            ReplayStatus::InsufficientEvidence
        );
        assert_eq!(
            replay_source_status(
                StepKind::Replay,
                None,
                &stopped,
                Some(&retained),
                (FindingKind::Violation, &identity),
                Some(FindingKind::Violation),
                &identity
            ),
            ReplayStatus::InsufficientEvidence
        );
        assert_eq!(
            replay_source_status(
                StepKind::Replay,
                Some(&retained),
                &stopped,
                Some(&retained),
                (FindingKind::Violation, &identity),
                Some(FindingKind::Violation),
                &Identity::Unavailable
            ),
            ReplayStatus::InsufficientEvidence
        );
        let mut passed = stopped.clone();
        passed.class = Class::Pass;
        assert_eq!(
            replay_source_status(
                StepKind::Replay,
                Some(&retained),
                &passed,
                Some(&retained),
                (FindingKind::Violation, &identity),
                None,
                &Identity::Absent
            ),
            ReplayStatus::Unreproduced
        );
    }
    #[test]
    fn replay_source_reduce_retries_once_then_stalls_on_equal_results() {
        let identity = Identity::Known(text("v1:failure").unwrap());
        let retained = comparison();
        let status = replay_source_status(
            StepKind::Reduce,
            Some(&retained),
            &finish(Some(1)),
            Some(&retained),
            (FindingKind::Violation, &identity),
            Some(FindingKind::Violation),
            &identity,
        );
        assert_eq!(status, ReplayStatus::Reproduced);
        let config = crate::campaign::calibration::tests::config();
        let limits = [
            "cpu",
            "tree_memory",
            "processes",
            "wall",
            "attempt_output",
            "attempt_inodes",
        ]
        .into_iter()
        .map(|key| (text(key).unwrap(), config.value(key)))
        .collect::<std::collections::BTreeMap<_, _>>();
        let mut records = Vec::new();
        for number in 1..=2 {
            let attempt = text(&format!("finding-triage-{number:04}")).unwrap();
            let mut finished = finish(Some(1));
            finished.attempt = attempt.clone();
            records.push((
                crate::record::TriageStep {
                    attempt: crate::record::Attempt {
                        attempt,
                        number,
                        job: crate::record::Digest::of(b"job"),
                        manifest: crate::record::Digest::of(b"manifest"),
                        file_bytes: 1024,
                    },
                    finding: text("finding").unwrap(),
                    kind: StepKind::Reduce,
                    launcher: text("/campaign").unwrap(),
                    limits: limits.clone(),
                },
                TriageResult {
                    comparison: Some(retained.clone()),
                    elapsed_ms: Some(1),
                    file_limited: false,
                    finding: text("finding").unwrap(),
                    finished,
                    number,
                    output_limited: false,
                    state: StepState::Complete,
                    status: Some(status),
                },
            ));
            assert_eq!(
                history::stalled(&records, &config, StepKind::Reduce),
                number == 2
            );
        }
    }
}

#[cfg(test)]
mod replay_completion_tests {
    use super::replay_source_tests::{comparison, finish};
    use super::*;
    #[test]
    fn replay_source_reproduction_requires_a_completed_fresh_replay() {
        let retained = comparison();
        let identity = Identity::Known(text("v1:failure").unwrap());
        for kind in [StepKind::Replay, StepKind::Reduce] {
            assert_eq!(
                replay_source_status(
                    kind,
                    Some(&retained),
                    &finish(Some(1)),
                    Some(&retained),
                    (FindingKind::Violation, &identity),
                    Some(FindingKind::Violation),
                    &identity
                ),
                ReplayStatus::Reproduced
            );
            for exit in [None, Some(2), Some(4)] {
                assert_eq!(
                    replay_source_status(
                        kind,
                        Some(&retained),
                        &finish(exit),
                        Some(&retained),
                        (FindingKind::Violation, &identity),
                        Some(FindingKind::Violation),
                        &identity
                    ),
                    ReplayStatus::InsufficientEvidence,
                    "{kind:?} {exit:?}"
                );
            }
            for status in ["incomplete", "rejected", "interrupted", "watchdog"] {
                let mut current = retained.clone();
                current.status = text(status).unwrap();
                assert_eq!(
                    replay_source_status(
                        kind,
                        Some(&current),
                        &finish(Some(1)),
                        Some(&retained),
                        (FindingKind::Violation, &identity),
                        Some(FindingKind::Violation),
                        &identity
                    ),
                    ReplayStatus::InsufficientEvidence,
                    "{kind:?} {status}"
                );
            }
        }
    }
}

#[cfg(test)]
mod panic_binding_tests {
    use super::*;
    #[test]
    fn panic_candidate_identity_requires_declared_digest_bound_streams() {
        let case = crate::store::fixture::Case::new();
        let store = Store::open(&case.state).unwrap();
        let mut artifact =
            crate::attempt::tests::artifact("panic", crate::record::Digest::of(b"manifest"));
        let capabilities = include_bytes!("../../../testdata/admission-listing.txt");
        let line = b"run: the run panicked at same\n";
        store
            .create_once(store.root(), &name("capabilities.stdout"), capabilities)
            .unwrap();
        store
            .create_once(store.root(), &name("panic-candidate.stdout"), line)
            .unwrap();
        let mut worker = artifact.workers[&text("run").unwrap()].clone();
        worker.stdout = crate::record::Digest::of(capabilities);
        artifact
            .workers
            .insert(text("capabilities").unwrap(), worker.clone());
        assert!(
            panic_line(&store, store.root(), &artifact, "panic-candidate").unwrap()
                == Identity::Unavailable
        );
        worker.stdout = crate::record::Digest::of(line);
        artifact
            .workers
            .insert(text("panic-candidate").unwrap(), worker);
        assert!(
            panic_line(&store, store.root(), &artifact, "panic-candidate").unwrap()
                == Identity::Known(text("same").unwrap())
        );
        let mut missing_capabilities = artifact.clone();
        missing_capabilities
            .workers
            .remove(&text("capabilities").unwrap());
        assert!(
            panic_line(
                &store,
                store.root(),
                &missing_capabilities,
                "panic-candidate"
            )
            .unwrap()
                == Identity::Unavailable
        );
        store
            .replace(
                store.root(),
                &name("panic-candidate.stdout"),
                b"run: the run panicked at changed\n",
            )
            .unwrap();
        assert!(panic_line(&store, store.root(), &artifact, "panic-candidate").is_err());
    }
}

#[cfg(test)]
mod reduce_panic_tests {
    use super::*;
    #[test]
    fn replay_source_reduce_panic_identity_uses_bound_baseline_observation() {
        let case = crate::store::fixture::Case::new();
        let store = Store::open(&case.state).unwrap();
        let mut artifact =
            crate::attempt::tests::artifact("panic", crate::record::Digest::of(b"manifest"));
        artifact.command = text("reduce").unwrap();
        let mut comparison = super::replay_source_tests::comparison();
        comparison.failure_kind = Some(text("panic").unwrap());
        comparison.failure_identity = Some(text("expected").unwrap());
        artifact.comparison = Some(comparison);
        let capabilities = include_bytes!("../../../testdata/admission-listing.txt");
        store
            .create_once(store.root(), &name("capabilities.stdout"), capabilities)
            .unwrap();
        let mut worker = artifact.workers[&text("run").unwrap()].clone();
        worker.stdout = crate::record::Digest::of(capabilities);
        artifact
            .workers
            .insert(text("capabilities").unwrap(), worker);
        for (line, expected) in [
            ("replay: the run panicked at same\n", Some("same")),
            ("replay: the run panicked at other\n", Some("other")),
            ("replay: diverged at the result: changed\n", None),
        ] {
            store
                .replace(store.root(), &name("baseline.stdout"), line.as_bytes())
                .unwrap();
            let mut worker = artifact.workers[&text("run").unwrap()].clone();
            worker.stdout = crate::record::Digest::of(line.as_bytes());
            artifact.workers.insert(text("baseline").unwrap(), worker);
            let observed =
                identity(&store, store.root(), Some(&artifact), FindingKind::Panic).unwrap();
            match expected {
                Some(expected) => assert!(observed == Identity::Known(text(expected).unwrap())),
                None => assert!(observed == Identity::Unavailable),
            }
        }
    }
}

#[cfg(test)]
mod reduce_fact_tests {
    use super::replay_source_tests::{comparison, finish};
    use super::*;
    #[test]
    fn replay_source_reduce_preserves_retained_observation_facts() {
        let retained = comparison();
        let identity = Identity::Known(text("v1:failure").unwrap());
        assert_eq!(
            replay_source_status(
                StepKind::Reduce,
                Some(&retained),
                &finish(Some(1)),
                Some(&retained),
                (FindingKind::Violation, &identity),
                Some(FindingKind::Violation),
                &identity
            ),
            ReplayStatus::Reproduced
        );
        for mutation in ["digest", "decisions", "first-failure"] {
            let mut current = retained.clone();
            let observed = current.observed.as_mut().unwrap();
            match mutation {
                "digest" => observed.digest = crate::record::Digest::of(b"changed"),
                "decisions" => observed.decisions = Some(4),
                "first-failure" => observed.first_failure.as_mut().unwrap().virtual_us = Some(11),
                _ => unreachable!(),
            }
            assert_eq!(
                replay_source_status(
                    StepKind::Reduce,
                    Some(&current),
                    &finish(Some(1)),
                    Some(&retained),
                    (FindingKind::Violation, &identity),
                    Some(FindingKind::Violation),
                    &identity
                ),
                ReplayStatus::Diverged,
                "{mutation}"
            );
        }
    }
}
