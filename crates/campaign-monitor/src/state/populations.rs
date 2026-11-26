//! The (campaign, profile, build, variant) population of every job in one
//! snapshot. Populations are numbered in (profile, campaign, build,
//! variant) order, so comparing two jobs' numbers compares those names, and
//! `rank` numbers them by (profile, campaign) alone, equal for populations
//! that differ only in build or variant.

use std::collections::HashMap;

use crate::parallel;
use crate::signals::JOBS_PER_THREAD;
use crate::snapshot::Job;

/// A population's names in numbering order: profile, campaign, build,
/// variant.
type Names<'a> = (&'a str, &'a str, &'a str, &'a str);

fn names(job: &Job) -> Names<'_> {
    (&job.profile, &job.campaign, &job.build, &job.variant)
}

/// `of` holds each job's population number; `first` the index of each
/// population's first job, which carries its names; `rank` each
/// population's (profile, campaign) rank.
#[derive(Debug, Default)]
pub(crate) struct Populations {
    of: Vec<u32>,
    first: Vec<usize>,
    rank: Vec<u32>,
}

impl Populations {
    /// Numbers the populations of `jobs`, on up to
    /// [`parallel::THREADS`] threads.
    pub(crate) fn new(jobs: &[Job]) -> Self {
        let parts = parallel::runs(jobs, JOBS_PER_THREAD, |run| {
            let mut seen: HashMap<Names, u32> = HashMap::new();
            let mut distinct = Vec::new();
            let of: Vec<u32> = run
                .iter()
                .map(|job| {
                    *seen.entry(names(job)).or_insert_with_key(|key| {
                        distinct.push(*key);
                        number(distinct.len() - 1)
                    })
                })
                .collect();
            (distinct, of)
        });
        let mut all: Vec<Names> = parts
            .iter()
            .flat_map(|(distinct, _)| distinct.iter().copied())
            .collect();
        all.sort_unstable();
        all.dedup();
        let mut of = Vec::with_capacity(jobs.len());
        for (distinct, local) in &parts {
            let global: Vec<u32> = distinct
                .iter()
                .map(|key| number(all.binary_search(key).expect("every key was collected")))
                .collect();
            of.extend(local.iter().map(|&local| global[local as usize]));
        }
        let mut first = vec![usize::MAX; all.len()];
        for (index, &population) in of.iter().enumerate() {
            let first = &mut first[population as usize];
            if *first == usize::MAX {
                *first = index;
            }
        }
        let mut rank = Vec::with_capacity(all.len());
        let mut current = 0;
        for (index, key) in all.iter().enumerate() {
            if index > 0 && (all[index - 1].0, all[index - 1].1) != (key.0, key.1) {
                current += 1;
            }
            rank.push(current);
        }
        Self { of, first, rank }
    }

    /// The (profile, campaign) rank of the job at `job`: jobs compare by
    /// rank as they compare by profile, then campaign.
    pub(crate) fn rank(&self, job: usize) -> u32 {
        self.rank[self.of[job] as usize]
    }

    /// The population number of the job at `job`.
    pub(crate) fn of(&self, job: usize) -> usize {
        self.of[job] as usize
    }

    /// `test` asked of each population's names, by population number, as
    /// carried by the population's first job in `jobs`, the slice these
    /// populations were numbered from.
    pub(crate) fn tested(&self, jobs: &[Job], test: impl Fn(&Job) -> bool) -> Vec<bool> {
        self.first.iter().map(|&first| test(&jobs[first])).collect()
    }

    /// The indices in `jobs`, ascending, of the jobs whose names satisfy
    /// `wanted`, which is asked once per population. `jobs` is the slice
    /// these populations were numbered from.
    pub(crate) fn jobs<'a>(
        &'a self,
        jobs: &[Job],
        wanted: impl Fn(&Job) -> bool,
    ) -> impl Iterator<Item = usize> + 'a {
        let chosen = self.tested(jobs, wanted);
        self.of
            .iter()
            .enumerate()
            .filter(move |&(_, &population)| chosen[population as usize])
            .map(|(index, _)| index)
    }
}

fn number(index: usize) -> u32 {
    u32::try_from(index).expect("populations fit in u32")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(profile: &str, campaign: &str, build: &str, variant: &str) -> Job {
        Job {
            profile: profile.into(),
            campaign: campaign.into(),
            build: build.into(),
            variant: variant.into(),
            ..Job::default()
        }
    }

    /// Ranks order jobs as (profile, campaign) does and tie on build and
    /// variant, for jobs in the same and in different runs of those that
    /// number populations on separate threads.
    #[test]
    fn ranks_order_jobs_by_profile_then_campaign_and_tie_on_build_and_variant() {
        let names = [
            ("b", "c1", "", "v"),
            ("a", "c2", "", "v"),
            ("a", "c1", "x", "v"),
            ("a", "c1", "", "w"),
            ("b", "c0", "", "v"),
        ];
        let jobs: Vec<Job> = (0..4 * JOBS_PER_THREAD)
            .map(|n| {
                let (p, c, b, v) = names[n % names.len()];
                job(p, c, b, v)
            })
            .collect();
        let populations = Populations::new(&jobs);
        let probes: Vec<usize> = [0, JOBS_PER_THREAD + 3, 3 * JOBS_PER_THREAD + 1]
            .into_iter()
            .flat_map(|start| start..start + names.len())
            .collect();
        for &left in &probes {
            for &right in &probes {
                let key = |n: usize| (jobs[n].profile.as_str(), jobs[n].campaign.as_str());
                assert_eq!(
                    populations.rank(left).cmp(&populations.rank(right)),
                    key(left).cmp(&key(right)),
                    "{left} {right}"
                );
            }
        }
        let wanted: Vec<usize> = populations
            .jobs(&jobs, |job| job.profile == "a" && job.campaign == "c1")
            .collect();
        let expected: Vec<usize> = (0..jobs.len())
            .filter(|&n| jobs[n].profile == "a" && jobs[n].campaign == "c1")
            .collect();
        assert_eq!(wanted, expected);
    }
}
