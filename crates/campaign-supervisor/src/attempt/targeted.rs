//! Targeted credit and child failures derive from the bound fork phase's strict output.

use crate::protocol::{Branch, ChildClass, Explore, Milestone, Outcome, Terminal, Witness};
use crate::record::{ChildEvidence, Class, FindingKind, ForkForm, Target, Text};

/// Fork credit requires the frozen witness, complete child census and worker agreement.
/// Product failures take precedence over incomplete children.
pub(crate) struct Judgment {
    pub class: Class,
    pub children: Vec<ChildEvidence>,
    /// Branch children or exploration nodes represented by the output.
    pub printed: usize,
    /// Passing branch children or successful exploration nodes.
    pub credited: usize,
    /// Exploration leaf counts as (printed, counting).
    pub leaves: Option<(usize, usize)>,
}

fn child_class(class: ChildClass, terminal: Option<&Terminal>, counts: bool) -> Class {
    match class {
        ChildClass::Signaled => Class::EngineFailure,
        ChildClass::Failed => Class::Incomplete,
        ChildClass::Watchdog => Class::Watchdog,
        ChildClass::Success => match terminal {
            Some(Terminal::Complete {
                outcome: Outcome::Violation,
                ..
            }) => Class::Violation,
            Some(Terminal::Complete {
                outcome: Outcome::Unsuccessful,
                ..
            }) => Class::Unsuccessful,
            Some(Terminal::Complete {
                outcome: Outcome::Inconclusive,
                ..
            }) => Class::Inconclusive,
            Some(t) if t.defect() => Class::EngineFailure,
            Some(t) if counts && t.passes() => Class::Pass,
            _ => Class::Incomplete,
        },
        _ => Class::Incomplete,
    }
}

/// Maps targeted outcomes to retained finding kinds.
pub(crate) fn kind(class: Class) -> Option<FindingKind> {
    match class {
        Class::Violation => Some(FindingKind::Violation),
        Class::EngineFailure => Some(FindingKind::Engine),
        Class::Watchdog => Some(FindingKind::Watchdog),
        Class::Unsuccessful => Some(FindingKind::Unsuccessful),
        Class::Inconclusive => Some(FindingKind::Inconclusive),
        Class::Incomplete | Class::Disagreement => Some(FindingKind::Incomplete),
        _ => None,
    }
}

fn witnessed(target: &Target, milestone: &Milestone, witness: &Witness) -> bool {
    milestone.name == target.milestone.as_str()
        && milestone.prefix == target.prefix
        && milestone.semantic == target.semantic
        && milestone.boundary == target.boundary
        && milestone.decisions == target.decisions
        && witness.holds
        && (target.milestone.as_str() != "pending-put"
            || witness
                .upload
                .is_some_and(|u| u.attempt > 0 && u.grant > 0 && u.held > 0 && u.outcome == 0))
}

impl Judgment {
    pub(super) fn malformed() -> Self {
        Self::empty(Class::MalformedEvidence)
    }

    fn empty(class: Class) -> Self {
        Self {
            class,
            children: Vec::new(),
            printed: 0,
            credited: 0,
            leaves: None,
        }
    }
    fn child(
        &mut self,
        label: String,
        class: Class,
        bundle: Option<String>,
        abort: bool,
        report: Option<(crate::record::Digest, Terminal)>,
    ) {
        self.printed += 1;
        if class == Class::Pass {
            self.credited += 1;
            return;
        }
        self.children.push(ChildEvidence {
            bundle: None,
            class,
            digest: report.map(|(digest, _)| digest),
            terminal: report
                .map(|(_, terminal)| Text::new(&terminal.to_string()).expect("terminal is ASCII")),
            kind: if abort {
                FindingKind::Abort
            } else {
                kind(class).expect("failed child has a finding kind")
            },
            file: bundle.and_then(|s| {
                crate::store::Name::new(&s).map(|_| Text::new(&s).expect("child filename is ASCII"))
            }),
            label: Text::new(&label).expect("child label is ASCII"),
        });
    }
    pub(super) fn conclude(&mut self, complete: bool, engine: bool) {
        self.class = [
            Class::Violation,
            Class::EngineFailure,
            Class::Unsuccessful,
            Class::Watchdog,
            Class::Incomplete,
            Class::Inconclusive,
        ]
        .into_iter()
        .find(|class| {
            (*class == Class::EngineFailure && engine)
                || self.children.iter().any(|child| child.class == *class)
        })
        .unwrap_or(if complete {
            Class::Pass
        } else {
            Class::Incomplete
        });
    }
}

/// Derives fork outcomes under the target's frozen prefix and bounds.
pub(crate) fn judge(target: &Target, output: &str) -> Result<Judgment, crate::protocol::Error> {
    let mut result = Judgment::empty(Class::Incomplete);
    match target.form {
        ForkForm::Branch { suffixes, siblings } => {
            let Some(branch) = Branch::parse(output)? else {
                return Ok(Judgment::empty(Class::EngineFailure));
            };
            let exact = branch.children.len() as u64 == suffixes * siblings
                && branch
                    .children
                    .iter()
                    .all(|c| c.suffix < suffixes && c.sibling < siblings);
            let disagree = (0..suffixes).any(|suffix| {
                let reports: Vec<_> = branch
                    .children
                    .iter()
                    .filter(|c| c.suffix == suffix)
                    .filter_map(|c| c.report.as_ref())
                    .collect();
                reports.windows(2).any(|pair| pair[0] != pair[1])
            });
            for child in branch
                .children
                .iter()
                .filter(|child| child.suffix < suffixes && child.sibling < siblings)
            {
                let mut class = child_class(
                    child.class,
                    child.report.as_ref().map(|(_, t)| t),
                    child.report.is_some(),
                );
                let prefix = format!("suffix {} sibling {}: ", child.suffix, child.sibling);
                let checks: Vec<_> = branch
                    .problems
                    .iter()
                    .filter(|_| class == Class::Pass)
                    .filter_map(|p| crate::protocol::child_check(p, &prefix))
                    .collect();
                if class == Class::Pass && !checks.is_empty() {
                    class = if checks
                        .iter()
                        .any(|check| crate::protocol::missing_child_evidence(check))
                    {
                        Class::Incomplete
                    } else {
                        Class::EngineFailure
                    };
                }
                result.child(
                    format!("c{}-{}", child.suffix, child.sibling),
                    class,
                    Some(format!("suffix-{}-{}.bundle", child.suffix, child.sibling)),
                    child.class == ChildClass::Signaled,
                    child.report,
                );
            }
            result.conclude(
                exact
                    && witnessed(target, &branch.milestone, &branch.witness)
                    && branch.reproduced
                    && branch.problems.is_empty()
                    && result.children.is_empty(),
                disagree || !branch.reproduced,
            );
        }
        ForkForm::Explore {
            advances,
            children,
            depth,
            faults,
        } => {
            let Some(tree) = Explore::parse(output)? else {
                return Ok(Judgment::empty(Class::EngineFailure));
            };
            let bound = target.form.children().unwrap_or(0) as usize;
            for (index, node) in tree.nodes.iter().take(bound).enumerate() {
                let class = if node.class == ChildClass::Success {
                    Class::Pass
                } else {
                    child_class(node.class, None, false)
                };
                result.child(
                    format!("n{index}"),
                    class,
                    None,
                    node.class == ChildClass::Signaled,
                    None,
                );
            }
            let node_credit = result.credited;
            for (index, leaf) in tree.leaves.iter().take(bound).enumerate() {
                let prefix = format!("leaf {}: ", leaf.path);
                let mut class = child_class(ChildClass::Success, Some(&leaf.verdict), leaf.counts);
                if class == Class::Pass {
                    let checks: Vec<_> = tree
                        .problems
                        .iter()
                        .filter_map(|p| crate::protocol::child_check(p, &prefix))
                        .collect();
                    if !checks.is_empty() {
                        class = if checks
                            .iter()
                            .any(|check| crate::protocol::missing_child_evidence(check))
                        {
                            Class::Incomplete
                        } else {
                            Class::EngineFailure
                        };
                    }
                }
                result.child(
                    format!("l{index}"),
                    class,
                    Some(ForkForm::leaf_name(&leaf.path)),
                    false,
                    Some((leaf.digest, leaf.verdict)),
                );
            }
            result.leaves = Some((tree.leaves.len(), result.credited - node_credit));
            result.printed = tree.nodes.len();
            result.credited = node_credit;
            let leaf_paths: std::collections::HashSet<_> =
                tree.leaves.iter().map(|leaf| leaf.path.as_str()).collect();
            let parents: std::collections::HashSet<_> = tree
                .nodes
                .iter()
                .filter_map(|node| node.path.rsplit_once('.').map(|(parent, _)| parent))
                .collect();
            let shape = tree.nodes.len() <= bound
                && tree.leaves.len() <= 128
                && !tree.leaves.is_empty()
                && tree.nodes.iter().all(|node| {
                    leaf_paths.contains(node.path.as_str()) != parents.contains(node.path.as_str())
                });
            result.conclude(
                shape
                    && tree.nodes.iter().all(|node| {
                        node.path.split('.').count() as u64 <= depth
                            && node.path.split('.').all(|index| {
                                index.parse::<u64>().is_ok_and(|index| index < children)
                            })
                    })
                    && tree.nodes.len() <= bound
                    && tree.leaves.len() <= 128
                    && tree.limits
                        == crate::protocol::Limits {
                            advances,
                            children,
                            depth,
                            faults,
                        }
                    && witnessed(target, &tree.milestone, &tree.witness)
                    && tree.reproduced
                    && tree.problems.is_empty()
                    && result.children.is_empty(),
                !tree.reproduced,
            );
        }
    }
    Ok(result)
}

#[cfg(test)]
#[path = "targeted_tests.rs"]
mod tests;
