use crate::exit::Sim;
use crate::protocol::{Infrastructure, Outcome, Terminal};
use crate::record::{Class, Finished, Kernel};

use super::binding::Evidence;

const WORKER_EXITS: &[u64] = &[0, 1, 2, 3, 101];
/// Kernel counters are trusted; artifact bytes can be faulty.
/// Kernel limit classes take priority while Finished retains the binding result.
pub(super) fn classify(finished: &Finished, evidence: &Evidence) -> Class {
    let worker_signal = |signal| matches!(evidence, Evidence::Bound(bound) if bound.artifact().workers.values().any(|worker| worker.signal == Some(signal)));
    let cpu = finished.interruption == Some(crate::sys::CPU_SIGNAL as u64)
        || finished.signal == Some(crate::sys::CPU_SIGNAL as u64)
        || worker_signal(crate::sys::CPU_SIGNAL as u64);
    if let Some(class) = limit_class(&finished.kernel, cpu) {
        return class;
    }
    let output = finished.interruption == Some(crate::sys::OUTPUT_SIGNAL as u64)
        || finished.signal == Some(crate::sys::OUTPUT_SIGNAL as u64)
        || worker_signal(crate::sys::OUTPUT_SIGNAL as u64);
    let bound = match evidence {
        Evidence::Malformed => {
            return if output {
                Class::OutputLimit
            } else {
                Class::MalformedEvidence
            };
        }
        Evidence::Misbound => {
            return if output {
                Class::OutputLimit
            } else {
                Class::MisboundEvidence
            };
        }
        Evidence::Missing => None,
        Evidence::Bound(bound) => Some(bound),
    };
    let crash = bound.is_some_and(|bound| bound.panic() || crashed(bound.artifact()));
    let targeted = bound.and_then(|bound| bound.targeted());
    let terminal = match bound
        .and_then(|bound| bound.artifact().outcome_summary())
        .filter(|_| targeted.is_none())
        .map(|summary| Terminal::parse(summary.terminal.as_str(), "terminal"))
        .transpose()
    {
        Ok(terminal) => terminal,
        Err(_) => {
            if crash {
                return Class::EngineFailure;
            }
            return if output {
                Class::OutputLimit
            } else {
                Class::MalformedEvidence
            };
        }
    };
    if matches!(
        terminal,
        Some(Terminal::Complete {
            outcome: Outcome::Violation,
            ..
        })
    ) || targeted.is_some_and(|judged| judged.class == Class::Violation)
    {
        return Class::Violation;
    }
    if crash
        || terminal.is_some_and(|terminal| terminal.defect())
        || targeted.is_some_and(|judged| judged.class == Class::EngineFailure)
    {
        return Class::EngineFailure;
    }
    if output {
        return Class::OutputLimit;
    }
    if finished.interruption.is_some() {
        return Class::Interrupted;
    }
    if finished.watchdog {
        return Class::Watchdog;
    }
    if finished.signal.is_some() {
        return Class::Signal;
    }
    let Some(exit) = finished.exit else {
        return Class::Interrupted;
    };
    let Some(sim) = Sim::from_code(exit) else {
        return Class::Infrastructure;
    };
    if let Some(bound) = bound {
        let artifact = bound.artifact();
        if artifact.class.as_str() != sim.name() {
            return Class::Disagreement;
        }
        if artifact
            .workers
            .values()
            .any(|worker| worker.signal.is_some())
        {
            return Class::Signal;
        }
    }
    if let Some(judged) = targeted {
        return match sim {
            Sim::Rejected => Class::Rejected,
            Sim::Interrupted => Class::Interrupted,
            Sim::Watchdog => Class::Watchdog,
            Sim::BuildFailure => Class::Infrastructure,
            Sim::Counts
                if judged.class == Class::Pass
                    && !finished.residual_members
                    && bound.is_some_and(|b| {
                        b.artifact().workers.values().all(|worker| {
                            worker.ended.as_str() == "exited" && worker.exit == Some(0)
                        })
                    }) =>
            {
                Class::Pass
            }
            Sim::Counts if judged.class == Class::Pass => Class::Disagreement,
            _ => {
                if judged.class == Class::Pass {
                    Class::Incomplete
                } else {
                    judged.class
                }
            }
        };
    }
    match sim {
        Sim::Counts => {
            let Some(artifact) = bound.map(|bound| bound.artifact()) else {
                return Class::Incomplete;
            };
            let Some(summary) = artifact.outcome_summary() else {
                return Class::Incomplete;
            };
            let phases: &[&str] = match artifact.command.as_str() {
                "replay" => &["replay", "inspect-original", "inspect-replay"],
                _ => &["run", "inspect"],
            };
            if !phases
                .iter()
                .all(|name| artifact.workers.keys().any(|phase| phase.as_str() == *name))
                || artifact
                    .workers
                    .values()
                    .any(|worker| worker.ended.as_str() != "exited" || worker.exit != Some(0))
            {
                return Class::Disagreement;
            }
            if artifact.bundle.is_none() || finished.residual_members {
                return Class::Incomplete;
            }
            if artifact
                .session
                .as_ref()
                .is_some_and(|session| !session.complete || !session.counts)
            {
                return Class::Incomplete;
            }
            if terminal.is_some_and(|terminal| terminal.passes())
                && summary.counts
                && summary.decisions.is_some_and(|count| count > 0)
            {
                Class::Pass
            } else {
                Class::Incomplete
            }
        }
        Sim::Complete => match terminal {
            Some(Terminal::Complete {
                outcome: Outcome::Unsuccessful,
                ..
            }) => Class::Unsuccessful,
            Some(Terminal::Complete {
                outcome: Outcome::Inconclusive | Outcome::Pass,
                ..
            })
            | Some(Terminal::Infrastructure(Infrastructure::Cap)) => Class::Inconclusive,
            _ => Class::Incomplete,
        },
        Sim::Rejected => {
            if bound.is_some_and(|bound| {
                bound
                    .artifact()
                    .workers
                    .iter()
                    .any(|(phase, worker)| phase.as_str() == "run" && worker.exit == Some(2))
            }) {
                Class::Rejected
            } else {
                Class::Infrastructure
            }
        }
        Sim::BuildFailure => Class::Infrastructure,
        Sim::Incomplete => {
            if terminal == Some(Terminal::Infrastructure(Infrastructure::Cap)) {
                Class::Inconclusive
            } else {
                Class::Incomplete
            }
        }
        Sim::Interrupted => Class::Interrupted,
        Sim::Watchdog => Class::Watchdog,
    }
}

/// Bound artifact findings take precedence over the watchdog class.
pub(crate) fn finding_kind(
    finished: &Finished,
    bound: Option<&super::BoundArtifact>,
) -> Option<crate::record::FindingKind> {
    use crate::record::FindingKind;
    if let Some(bound) = bound {
        let artifact = bound.artifact();
        if let Some(judged) = bound.targeted() {
            if finished.class == Class::Violation || judged.class == Class::Violation {
                return Some(FindingKind::Violation);
            }
            if bound.panic() {
                return Some(FindingKind::Panic);
            }
            if finished.class == Class::EngineFailure
                && judged
                    .children
                    .iter()
                    .any(|child| child.kind == FindingKind::Abort)
            {
                return Some(FindingKind::Abort);
            }
            if crashed(artifact) {
                return Some(FindingKind::Abort);
            }
            if judged.class == Class::EngineFailure {
                return Some(FindingKind::Engine);
            }
            if let Some(kind) = super::targeted::kind(finished.class) {
                return Some(kind);
            }
            if !judged.children.is_empty() {
                return Some(FindingKind::Incomplete);
            }
        }
        let terminal = artifact
            .outcome_summary()
            .and_then(|summary| Terminal::parse(summary.terminal.as_str(), "terminal").ok());
        if matches!(
            terminal,
            Some(Terminal::Complete {
                outcome: Outcome::Violation,
                ..
            })
        ) {
            return Some(FindingKind::Violation);
        }
        if bound.panic() {
            return Some(FindingKind::Panic);
        }
        let killed = finished.kernel.memory.iter().any(|(name, count)| {
            *count > 0 && ["oom_kill", "oom_group_kill"].contains(&name.as_str())
        });
        let cpu = finished.class == Class::CpuLimit
            || finished.interruption == Some(crate::sys::CPU_SIGNAL as u64)
            || finished.signal == Some(crate::sys::CPU_SIGNAL as u64)
            || artifact
                .workers
                .values()
                .any(|worker| worker.signal == Some(crate::sys::CPU_SIGNAL as u64));
        let output = finished.class == Class::OutputLimit
            || finished.interruption == Some(crate::sys::OUTPUT_SIGNAL as u64)
            || finished.signal == Some(crate::sys::OUTPUT_SIGNAL as u64)
            || artifact
                .workers
                .values()
                .any(|worker| worker.signal == Some(crate::sys::OUTPUT_SIGNAL as u64));
        let control = finished.watchdog
            || finished.class == Class::Watchdog
            || finished.interruption.is_some();
        let stopped = |signal| {
            (signal == crate::sys::KILL_SIGNAL
                && (control || cpu || output || killed || finished.class == Class::Interrupted))
                || (signal == crate::sys::CPU_SIGNAL as u64 && cpu)
                || (signal == crate::sys::OUTPUT_SIGNAL as u64 && output)
                || (finished.interruption == Some(signal)
                    && crate::sys::STOP_SIGNALS.contains(&signal))
        };
        if crashed(artifact)
            || artifact
                .workers
                .values()
                .any(|worker| worker.signal.is_some_and(|signal| !stopped(signal)))
        {
            return Some(FindingKind::Abort);
        }
        if truncated(artifact) {
            return Some(FindingKind::Truncated);
        }
        if terminal.is_some_and(|terminal| terminal.defect()) {
            return Some(FindingKind::Harness);
        }
    }
    (finished.class == Class::Watchdog).then_some(FindingKind::Watchdog)
}

fn truncated(artifact: &crate::record::Artifact) -> bool {
    artifact
        .workers
        .values()
        .any(|worker| worker.ended.as_str() == "oversized")
        || artifact.outcome_summary().is_some_and(|summary| {
            Terminal::parse(summary.terminal.as_str(), "terminal")
                == Ok(Terminal::Infrastructure(Infrastructure::Truncated))
        })
}

fn crashed(artifact: &crate::record::Artifact) -> bool {
    artifact.workers.values().any(|worker| {
        worker
            .exit
            .is_some_and(|code| !WORKER_EXITS.contains(&code))
            || worker
                .signal
                .is_some_and(|signal| crate::sys::CRASH_SIGNALS.contains(&signal))
    })
}

fn kernel_limits(kernel: &Kernel, cpu: bool) -> [(bool, &'static str); 3] {
    let counter = |map: &std::collections::BTreeMap<crate::record::Text, u64>, name: &str| {
        map.iter()
            .find(|(key, _)| key.as_str() == name)
            .map_or(0, |(_, value)| *value)
    };
    let oom = ["oom", "oom_kill", "oom_group_kill"]
        .iter()
        .any(|name| counter(&kernel.memory, name) > 0);
    let pids = counter(&kernel.pids, "max") > 0;
    [(oom, "tree_memory"), (pids, "processes"), (cpu, "cpu")]
}

fn limit_class(kernel: &Kernel, cpu: bool) -> Option<Class> {
    let [(oom, _), (pids, _), (cpu, _)] = kernel_limits(kernel, cpu);
    match (oom, pids, cpu) {
        (true, false, false) => Some(Class::Oom),
        (false, true, false) => Some(Class::PidLimit),
        (false, false, true) => Some(Class::CpuLimit),
        (true, true, _) | (true, _, true) | (_, true, true) => Some(Class::MixedLimits),
        (false, false, false) => None,
    }
}

pub(crate) fn classify_stopped(
    stopped: &crate::custody::Stopped,
) -> Result<(Class, Vec<&'static str>, bool), crate::custody::Error> {
    let finished = stopped.finished(Class::Incomplete, crate::record::Binding::Missing, None)?;
    let class = classify(&finished, &Evidence::Missing);
    let cpu = finished.interruption == Some(crate::sys::CPU_SIGNAL as u64)
        || finished.signal == Some(crate::sys::CPU_SIGNAL as u64);
    let limits = kernel_limits(&finished.kernel, cpu)
        .into_iter()
        .filter_map(|(reached, name)| reached.then_some(name))
        .collect();
    Ok((class, limits, finished.residual_members))
}
