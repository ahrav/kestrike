//! Branch and exploration credit requires milestone reproduction and complete, passing terminal reports.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::Path;

use super::class::{Stop, incomplete, rejected};
use super::command::{Command, new_output, text};
use super::input::{Values, worker_manifest};
use crate::exit::Sim;
use crate::protocol::{Branch, ChildClass, Explore};

const BRANCH_PHASE: &str = "branch";

impl Command {
    pub(super) fn forked(
        &mut self,
        archive: &Path,
        bundle: &Path,
        milestone: &str,
        children: Option<(u32, u32)>,
        output: Option<&Path>,
    ) -> Result<Stop, Stop> {
        if milestone.is_empty() || crate::record::Text::new(milestone).is_none() {
            return Err(rejected("the milestone must be printable ASCII"));
        }
        if children.is_some_and(|(suffixes, siblings)| {
            !(1..=16).contains(&suffixes) || !(1..=4).contains(&siblings)
        }) {
            return Err(rejected(
                "suffixes must be from 1 to 16 and siblings from 1 to 4",
            ));
        }
        let form = if children.is_some() {
            BRANCH_PHASE
        } else {
            "explore"
        };
        let target = new_output(
            &self.store,
            output.unwrap_or(&self.path(form)),
            form,
            Some(&self.path(form)),
        )?;
        self.output = Some(text(
            target.to_str().expect("the output path is printable ASCII"),
        ));
        let given = self.watchdog.is_some();
        let mut archive = self.load(archive)?;
        let staged = self.stage(bundle)?;
        let limits = if children.is_none() {
            Some(
                Values::parse(&staged.manifest, "bundle")
                    .and_then(|values| values.suffix_limits())
                    .map_err(rejected)?,
            )
        } else {
            None
        };
        self.admit(
            &mut archive,
            &staged.manifest,
            &worker_manifest(&staged.manifest),
            "bundle",
        )?;
        if !given {
            self.watchdog = self.watchdog.map(fork_wait);
        }
        let input = self.path("input");
        let flag = format!("--{form}");
        let suffixes_text = children.map(|(count, _)| count.to_string());
        let siblings_text = children.map(|(_, count)| count.to_string());
        let mut args = vec![
            OsStr::new(&flag),
            input.as_os_str(),
            OsStr::new("--milestone"),
            OsStr::new(milestone),
            OsStr::new("--output"),
            target.as_os_str(),
        ];
        if let Some(count) = &suffixes_text {
            args.extend([OsStr::new("--suffixes"), OsStr::new(count)]);
        }
        if let Some(count) = &siblings_text {
            args.extend([OsStr::new("--siblings"), OsStr::new(count)]);
        }
        let ran = self.phase(&mut archive, form, &args)?;
        if ran.code == 2 {
            return Err(if ran.stdout.is_empty() {
                rejected(format!("the worker refused the {form}"))
            } else {
                incomplete(format!("the refused {form} printed a result"))
            });
        }
        let counts = if let Some((suffixes, siblings)) = children {
            match Branch::parse(&ran.stdout)
                .map_err(|error| incomplete(format!("the branch output: {error}")))?
            {
                None => false,
                Some(branch) => {
                    if branch.milestone.name != milestone
                        || branch.children.len() != (suffixes * siblings) as usize
                        // Pair uniqueness and exact length make bounded pairs the exact requested set.
                        || branch.children.iter().any(|child| child.suffix >= u64::from(suffixes)
                            || child.sibling >= u64::from(siblings))
                    {
                        return Err(incomplete(
                            "the branch reports another milestone or child set",
                        ));
                    }
                    let agree = (0..u64::from(suffixes)).all(|suffix| {
                        let reports: Vec<_> = branch
                            .children
                            .iter()
                            .filter(|child| child.suffix == suffix)
                            .map(|child| &child.report)
                            .collect();
                        reports.windows(2).all(|pair| pair[0] == pair[1])
                    });
                    agree
                        && branch.reproduced
                        && branch.problems.is_empty()
                        && branch.children.iter().all(|child| {
                            child.class == ChildClass::Success
                                && child
                                    .report
                                    .as_ref()
                                    .is_some_and(|(_, terminal)| terminal.passes())
                        })
                }
            }
        } else {
            match Explore::parse(&ran.stdout)
                .map_err(|error| incomplete(format!("the exploration output: {error}")))?
            {
                None => false,
                Some(tree) => {
                    if tree.milestone.name != milestone {
                        return Err(incomplete("the exploration reports another milestone"));
                    }
                    if Some(tree.limits) != limits {
                        return Err(incomplete(
                            "the exploration limits differ from the frozen manifest",
                        ));
                    }
                    let leaves: HashSet<_> =
                        tree.leaves.iter().map(|leaf| leaf.path.as_str()).collect();
                    let interiors: HashSet<_> = tree
                        .nodes
                        .iter()
                        .filter_map(|node| node.path.rsplit_once('.').map(|(parent, _)| parent))
                        .collect();
                    tree.reproduced
                        && tree.nodes.iter().all(|node| {
                            node.path.split('.').count() as u64 <= tree.limits.depth
                                && node.path.split('.').all(|index| {
                                    index
                                        .parse::<u64>()
                                        .is_ok_and(|index| index < tree.limits.children)
                                })
                        })
                        && tree.nodes.iter().all(|node| {
                            leaves.contains(node.path.as_str())
                                != interiors.contains(node.path.as_str())
                        })
                        && tree.problems.is_empty()
                        && !tree.leaves.is_empty()
                        && tree
                            .nodes
                            .iter()
                            .all(|node| node.class == ChildClass::Success)
                        && tree
                            .leaves
                            .iter()
                            .all(|leaf| leaf.counts && leaf.verdict.passes())
                }
            }
        };
        let class = if counts { Sim::Counts } else { Sim::Complete };
        if ran.code != if counts { 0 } else { 1 } {
            return Err(incomplete(
                "the worker exit disagrees with its child summaries",
            ));
        }
        Ok(Stop(
            class,
            format!(
                "{form}: {}; milestone={milestone}; {}",
                class.name(),
                match children {
                    Some((suffixes, siblings)) =>
                        format!("suffixes={suffixes}; siblings={siblings}"),
                    None => "exploration".to_owned(),
                }
            ),
        ))
    }
}

// The fork phase includes prefix replay and bounded child runs under one watchdog.
fn fork_wait(duration: std::time::Duration) -> std::time::Duration {
    duration
        .saturating_mul(3)
        .min(std::time::Duration::from_secs(u64::from(u32::MAX)))
}
pub(crate) fn branch_probe_charge(bundle_bytes: u64) -> crate::record::Charge {
    let phases = [super::command::CAPABILITIES_PHASE, BRANCH_PHASE];
    let streams = phases.len() * super::command::OUTPUT_STREAMS.len();
    let entries = [
        "artifacts",
        "artifacts/run",
        "artifacts/run/.state",
        "artifacts/run/.staging",
        "artifacts/run/manifest",
        "artifacts/run/artifact",
        "branch",
        "branch/suffix-0-0.bundle",
    ];
    crate::record::probe_charge(
        bundle_bytes,
        streams as u64 * super::OUTPUT as u64,
        (streams + entries.len()) as u64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn branch_probe_capacity_covers_bundle_streams_files_and_controller_reserves() {
        for bytes in [0, 1, u64::MAX] {
            let charge = branch_probe_charge(bytes);
            assert_eq!(charge.bytes, 2 * u128::from(bytes) + 11 * (1 << 20));
            assert_eq!(charge.inodes, 26);
        }
    }

    #[test]
    fn the_fork_wait_triples_and_caps_the_manifest_watchdog() {
        assert_eq!(fork_wait(Duration::from_secs(1)), Duration::from_secs(3));
        assert_eq!(
            fork_wait(Duration::from_secs(u64::from(u32::MAX))),
            Duration::from_secs(u64::from(u32::MAX))
        );
    }
}
