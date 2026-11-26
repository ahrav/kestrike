//! Drill-down: the job set Enter opens from a profile, signal or failure
//! group, the Jobs filter it replaces, and the back stack, at most
//! `BACK_DEPTH` deep, that `^o` returns through.

use std::collections::BTreeSet;

use super::nav::Mark;
use super::search::JobQuery;
use super::{App, Tab};
use crate::snapshot::JobState;
use crate::tui::text::prefix;

/// Back-stack entries kept; a deeper drill-down drops the oldest.
pub(super) const BACK_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobFilter {
    /// Jobs whose outcome has a failure domain or that a signal names.
    Problems,
    All,
    /// Every job not yet settled, held rows included.
    Unsettled,
}

impl JobFilter {
    pub fn name(self) -> &'static str {
        match self {
            Self::Problems => "problems",
            Self::All => "all",
            Self::Unsettled => "unsettled",
        }
    }

    pub(super) fn next(self) -> Self {
        match self {
            Self::Problems => Self::All,
            Self::All => Self::Unsettled,
            Self::Unsettled => Self::Problems,
        }
    }
}

/// The item a drill-down opened, resolved to its jobs on every snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    Profile {
        campaign: String,
        profile: String,
        build: String,
        variant: String,
    },
    /// A signal, by [`Signal::key`], and its detector for when the key
    /// changes with the signal's subjects.
    Signal { key: String, detector: &'static str },
    /// A failure group, by [`crate::snapshot::FailureGroup::key`].
    Group { key: String },
}

/// The job set Enter opened from a profile, signal or failure group. While
/// set it replaces the Jobs filter, and each snapshot re-resolves `jobs`
/// from the target, so jobs that join or leave the target follow it. `f`
/// clears it, as does Esc on Jobs once the Jobs query is empty; `^o`
/// restores the focus that was active before the drill-down. The Jobs
/// title shows `label` after the row count.
#[derive(Debug, Clone)]
pub struct Focus {
    pub(crate) label: String,
    target: Target,
    pub(crate) jobs: BTreeSet<String>,
}

/// A drill-down's return point: the tab left, its selected item, and the
/// focus active before the drill-down, which `go_back` re-resolves against
/// the snapshot shown.
#[derive(Debug)]
pub(super) struct Back {
    pub(super) tab: Tab,
    pub(super) mark: Mark,
    pub(super) focus: Option<Focus>,
}

impl App {
    /// Whether `^o` has a drill-down to return from.
    pub fn can_go_back(&self) -> bool {
        !self.back.is_empty()
    }

    /// Whether Enter on the selected row opens jobs.
    pub fn can_drill(&self) -> bool {
        let Some(d) = self.derived() else {
            return false;
        };
        match self.tab {
            Tab::Profiles => self.selected() < d.matrix.rows.len(),
            Tab::Signals | Tab::Findings => d.drillable[self.tab.index()]
                .get(self.selected())
                .copied()
                .unwrap_or(false),
            Tab::Overview | Tab::Jobs => false,
        }
    }

    /// `focus` with its jobs re-resolved against the snapshot shown. A
    /// signal whose key changed with its subjects is found again as the
    /// first signal of the same detector that names one of the focused
    /// jobs; with none, the focus keeps its jobs.
    pub(super) fn refocus(&self, mut focus: Focus) -> Focus {
        if let Some(jobs) = self.resolve(&focus.target) {
            focus.jobs = jobs;
            return focus;
        }
        if let (Target::Signal { detector, .. }, Some(d)) = (&focus.target, self.derived()) {
            let detector = *detector;
            let found = d.signals.iter().enumerate().find(|(index, signal)| {
                signal.detector == detector && focus.jobs.iter().any(|id| d.names(*index, id))
            });
            if let Some((index, _)) = found {
                focus.target = Target::Signal {
                    key: d.keys[Tab::Signals.index()][index].clone(),
                    detector,
                };
                focus.jobs = self.resolve(&focus.target).unwrap_or_default();
            }
        }
        focus
    }

    pub(super) fn relist(&mut self) {
        let Some(d) = self.derived.clone() else {
            self.listed.clear();
            self.listed_query = self.searches[Tab::Jobs.index()].to_lowercase();
            return;
        };
        let snapshot = &d.snapshot;
        let mut query = JobQuery::new(&self.searches[Tab::Jobs.index()], &d);
        let focused = self.focus.as_ref().map(|focus| d.job_mask(&focus.jobs));
        let mut listed: Vec<usize> = d
            .order
            .iter()
            .map(|&index| index as usize)
            .filter(|&index| match (&focused, self.filter) {
                (Some(focused), _) => focused[index],
                (None, JobFilter::All) => true,
                (None, JobFilter::Problems) => {
                    d.outcomes[index].domain.is_some() || d.flags[index].is_some()
                }
                (None, JobFilter::Unsettled) => snapshot.jobs[index].state != JobState::Settled,
            })
            .collect();
        query.retain(&mut listed);
        self.listed = listed;
        self.listed_query = query.query;
        self.selections[Tab::Jobs.index()] =
            self.selections[Tab::Jobs.index()].min(self.listed.len().saturating_sub(1));
    }

    /// The jobs `target` names in the snapshot shown, or `None` when the
    /// target's signal or group is gone.
    pub(super) fn resolve(&self, target: &Target) -> Option<BTreeSet<String>> {
        let d = self.derived()?;
        let snapshot = &d.snapshot;
        match target {
            Target::Profile {
                campaign,
                profile,
                build,
                variant,
            } => Some(
                d.populations
                    .jobs(&snapshot.jobs, |job| {
                        job.campaign == *campaign
                            && job.profile == *profile
                            && job.build == *build
                            && job.variant == *variant
                    })
                    .map(|index| snapshot.jobs[index].id.clone())
                    .collect(),
            ),
            Target::Signal { key, .. } => {
                let index = d.keys[Tab::Signals.index()]
                    .iter()
                    .position(|candidate| candidate == key)?;
                Some(
                    d.named[index]
                        .iter()
                        .map(|&job| snapshot.jobs[job].id.clone())
                        .collect(),
                )
            }
            Target::Group { key } => {
                let index = d.keys[Tab::Findings.index()]
                    .iter()
                    .position(|candidate| candidate == key)?;
                Some(d.group_jobs(&snapshot.failure_groups[index]))
            }
        }
    }

    pub(super) fn drill(&mut self) -> Result<(), &'static str> {
        let Some(d) = self.derived.clone() else {
            return Err("no snapshot yet");
        };
        let selected = self.selected();
        let found = match self.tab {
            Tab::Profiles => d.matrix.rows.get(selected).map(|row| {
                let build = if row.build.is_empty() {
                    String::new()
                } else {
                    format!(" {}", row.build)
                };
                (
                    format!(
                        "{} {}{build} {}",
                        row.campaign,
                        row.profile,
                        prefix(&row.variant, usize::from(crate::view::VARIANT_WIDTH))
                    ),
                    Target::Profile {
                        campaign: row.campaign.clone(),
                        profile: row.profile.clone(),
                        build: row.build.clone(),
                        variant: row.variant.clone(),
                    },
                )
            }),
            Tab::Signals => d.signals.get(selected).map(|signal| {
                (
                    signal.title.clone(),
                    Target::Signal {
                        key: d.keys[Tab::Signals.index()][selected].clone(),
                        detector: signal.detector,
                    },
                )
            }),
            Tab::Findings => self.groups().get(selected).map(|group| {
                (
                    format!("{} in {}", group.kind, group.profiles.join(",")),
                    Target::Group {
                        key: d.keys[Tab::Findings.index()][selected].clone(),
                    },
                )
            }),
            Tab::Overview | Tab::Jobs => None,
        };
        let Some((label, target)) = found else {
            return Err("no row is selected");
        };
        let jobs = self.resolve(&target).unwrap_or_default();
        if jobs.is_empty() {
            return Err("the selected row names no job in this snapshot");
        }
        if self.back.len() == BACK_DEPTH {
            self.back.remove(0);
        }
        let back = Back {
            tab: self.tab,
            mark: self.mark(self.tab),
            focus: self.focus.take(),
        };
        self.back.push(back);
        self.focus = Some(Focus {
            label,
            target,
            jobs,
        });
        self.tab = Tab::Jobs;
        self.relist_from_top();
        Ok(())
    }

    pub(super) fn relist_from_top(&mut self) {
        self.selections[Tab::Jobs.index()] = 0;
        self.relist();
    }

    /// Relists Jobs after a focus change, keeping the selected job selected
    /// while it is still listed.
    pub(super) fn relist_keeping(&mut self) {
        let kept = self.mark(Tab::Jobs);
        self.relist();
        let row = self.locate(Tab::Jobs, &kept);
        self.selections[Tab::Jobs.index()] = row.min(self.listed.len().saturating_sub(1));
    }

    pub(super) fn go_back(&mut self) {
        let Some(back) = self.back.pop() else {
            return;
        };
        self.focus = back.focus.map(|focus| self.refocus(focus));
        self.relist_keeping();
        self.tab = back.tab;
        let row = self.locate(back.tab, &back.mark);
        self.select(row);
    }
}
