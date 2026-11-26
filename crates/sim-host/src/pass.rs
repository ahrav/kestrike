//! The store pass: one background walk over this runner's roots that
//! uploads each changed snapshot and names the roots that may be deleted.
//! A root is a candidate only when this instance created it, it is not the
//! current root, its build is known not to be the assigned build, its last
//! confirm exited 0 with no admitted job left, `confirm/confirmed` covers
//! every complete suspect line, every finding is resolved, and the three
//! stored objects match its local copies. A root that holds no
//! `sweep.json`, no suspect list and no `confirm/` holds no evidence and is
//! a candidate under the same ownership and build conditions. Each
//! candidate carries the [`Stamp`] taken before the pass read it; the
//! runner checks the confirmation conditions again and compares the stamp
//! under the root's lock before it marks the root deleting.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::assignment::Document;
use crate::build::Commit;
use crate::snapshot::{self, Observation, Stamp};
use crate::state::{self, Confirmation, Root};
use crate::store::{Bucket, SHORT};

pub struct Input {
    pub bucket: Bucket,
    pub state: PathBuf,
    pub instance: String,
    pub roots: BTreeMap<String, Root>,
    pub current: Option<String>,
    /// The build the host is assigned, when a document read or the stored
    /// copy names one.
    pub assigned: Option<String>,
    /// The root a confirm was running on when the pass started.
    pub confirming: Option<String>,
    pub observed: Option<Result<Observation, String>>,
    pub at_rest: bool,
    pub stint_seconds: Option<u64>,
}

#[derive(Debug, Default)]
pub struct Output {
    pub errors: Vec<String>,
    /// Each candidate root and its stamp from before the pass read it.
    pub deletable: Vec<(String, Stamp)>,
}

/// Reads `assignment.json` and `current.json`.
pub fn docs(bucket: &Bucket, scratch: &Path) -> Result<(Document, Commit), String> {
    crate::file::private_dir(scratch).map_err(|error| format!("{}: {error}", scratch.display()))?;
    let read = |key: &str| {
        bucket
            .read(key, scratch, crate::assignment::BOUND, SHORT)
            .map_err(|error| format!("{key}: {error}"))
    };
    let document = Document::parse(&read("assignment.json")?)?;
    let commit =
        Commit::parse(&read("current.json")?).map_err(|error| format!("current.json: {error}"))?;
    Ok((document, commit))
}

/// Whether the root directory `dir` holds nothing a sweep or a confirm
/// wrote: it is absent, or it has no `sweep.json`, `suspects.jsonl` or
/// `confirm`. A directory that cannot be read holds evidence.
fn holds_no_evidence(dir: &Path) -> bool {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => return error.kind() == std::io::ErrorKind::NotFound,
    };
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        if ["sweep.json", "suspects.jsonl", "confirm"]
            .contains(&entry.file_name().to_str().unwrap_or(""))
        {
            return false;
        }
    }
    true
}

pub fn pass(input: &mut Input) -> Output {
    let mut output = Output::default();
    let mut order: Vec<&String> = input.roots.keys().collect();
    order.sort_by_key(|campaign| input.current.as_deref() != Some(campaign.as_str()));
    for campaign in order {
        let root = &input.roots[campaign];
        if root.instance != input.instance || root.deleting {
            continue;
        }
        if input.bucket.halt.halted() {
            if !input.at_rest {
                break;
            }
            output.errors.push(format!(
                "{campaign}: the stop's upload time ran out before its upload"
            ));
            continue;
        }
        let old = input.current.as_deref() != Some(campaign.as_str());
        let retirable = old
            && input.confirming.as_deref() != Some(campaign.as_str())
            && input
                .assigned
                .as_deref()
                .is_some_and(|assigned| assigned != root.build);
        let dir = state::roots(&input.state).join(campaign);
        match crate::file::exists(&dir.join("sweep.json")) {
            Ok(true) => {}
            Ok(false) => {
                let stamp = snapshot::stamp(&dir);
                if retirable && holds_no_evidence(&dir) {
                    output.deletable.push((campaign.clone(), stamp));
                }
                continue;
            }
            Err(error) => {
                output
                    .errors
                    .push(format!("{campaign}: {}: {error}", dir.display()));
                continue;
            }
        }
        let observed = if old || input.at_rest {
            let reused = input
                .observed
                .take_if(|observed| {
                    observed
                        .as_ref()
                        .is_ok_and(|observed| observed.root.campaign() == *campaign)
                })
                .filter(|observed| {
                    observed
                        .as_ref()
                        .is_ok_and(|observed| observed.root.stints == root.stints)
                });
            match reused {
                Some(observed) => observed,
                None => snapshot::observe(&input.state, root, input.bucket.halt),
            }
        } else {
            match input.observed.take() {
                Some(observed) => observed,
                None => continue,
            }
        };
        let taken = observed.and_then(|observed| {
            snapshot::take(
                &input.state,
                &input.instance,
                &observed,
                input.stint_seconds,
                input.bucket.halt,
            )
            .map(|snapshot| (snapshot, observed.stamp))
        });
        let (snapshot, stamp) = match taken {
            Ok(taken) => taken,
            Err(error) => {
                output.errors.push(format!("{campaign}: {error}"));
                continue;
            }
        };
        let drained = root.confirmation == Confirmation::Idle
            && !root.pending
            && snapshot.confirmed >= snapshot.suspects.lines
            && snapshot.resolved;
        let candidate = retirable && drained;
        let current =
            snapshot::receipt(&input.state, campaign).as_deref() == Some(snapshot.inner.as_str());
        let mut stored = (candidate && current)
            .then(|| snapshot::in_store(&input.bucket, &input.state, campaign));
        if !current || stored == Some(Ok(false)) {
            if let Err(error) = snapshot::upload(&input.bucket, &input.state, &snapshot) {
                output.errors.push(format!("{campaign}: {error}"));
                continue;
            }
            stored = candidate.then(|| snapshot::in_store(&input.bucket, &input.state, campaign));
        }
        match stored {
            Some(Ok(true)) => output.deletable.push((campaign.clone(), stamp)),
            Some(Err(error)) => output.errors.push(format!("{campaign}: {error}")),
            _ => {}
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Instant;

    use super::{Input, pass};
    use crate::capture::Halt;
    use crate::state::{Confirmation, Root};
    use crate::store::Bucket;

    const INSTANCE: &str = "i-0123abcd";

    fn root(instance: &str, nonce: &str, deleting: bool) -> Root {
        Root {
            name: "sim".into(),
            instance: instance.into(),
            nonce: nonce.repeat(16),
            build: crate::file::sha256(b"b"),
            counts: BTreeMap::new(),
            confirm_slots: 1,
            stints: 1,
            failures: 0,
            cpu_usec: 0,
            capacity_usec: 0,
            alarm: false,
            confirmation: Confirmation::Idle,
            pending: false,
            retry: None,
            deleting,
        }
    }

    /// A pass at rest over one root whose cursor counts more lines than its
    /// list holds, given an observation of the root at `observed_stint`.
    fn rest_with_observation(name: &str, observed_stint: u64) -> Vec<String> {
        let state = crate::file::scratch(name);
        let mut kept = root(INSTANCE, "00", false);
        kept.stints = 2;
        let build = &kept.build;
        let archive = crate::build::archive(&state, build);
        std::fs::create_dir_all(&archive).expect("the archive directory");
        std::fs::write(archive.join("build"), "b").expect("the build record");
        std::fs::write(crate::build::campaign(&state, build), "c").expect("the binary");
        let commit = crate::build::Commit {
            format: 1,
            commit: "a".repeat(40),
            build: build.clone(),
            campaign: crate::file::sha256(b"c"),
        };
        std::fs::write(
            crate::build::record(&state, build),
            serde_json::to_vec(&commit).expect("the commit record"),
        )
        .expect("the commit record");
        let dir = crate::state::roots(&state).join(kept.campaign());
        std::fs::create_dir_all(dir.join("confirm")).expect("the confirm directory");
        std::fs::write(dir.join("sweep.json"), "{}").expect("the sweep state");
        std::fs::write(dir.join("confirm/confirmed"), "5").expect("the cursor");
        let mut earlier = kept.clone();
        earlier.stints = observed_stint;
        let observation = crate::snapshot::Observation {
            root: earlier,
            sweep_status: serde_json::json!({}),
            list_length: 0,
            stamp: crate::snapshot::stamp(&dir),
        };
        let mut input = Input {
            bucket: Bucket::new("bucket"),
            state: state.clone(),
            instance: INSTANCE.into(),
            roots: [(kept.campaign(), kept.clone())].into_iter().collect(),
            current: Some(kept.campaign()),
            assigned: None,
            confirming: None,
            observed: Some(Ok(observation)),
            at_rest: true,
            stint_seconds: None,
        };
        let errors = pass(&mut input).errors;
        std::fs::remove_dir_all(&state).expect("cleanup");
        errors
    }

    #[test]
    fn an_observation_of_an_earlier_stint_is_taken_again_at_rest() {
        let reused = rest_with_observation("rest-current", 2);
        assert!(
            reused.len() == 1 && reused[0].contains("confirm counts 5 lines"),
            "{reused:?}"
        );
        let observed = rest_with_observation("rest-earlier", 1);
        assert!(
            observed.len() == 1 && observed[0].contains("sweep-status"),
            "the root is observed again: {observed:?}"
        );
    }

    #[test]
    fn a_stop_out_of_time_names_each_unstored_root_of_this_instance() {
        let first = root(INSTANCE, "00", false);
        let foreign = root("i-0000000f", "11", false);
        let marked = root(INSTANCE, "22", true);
        let last = root(INSTANCE, "33", false);
        let named = [first.campaign(), last.campaign()];
        let roots = [first, foreign, marked, last]
            .into_iter()
            .map(|root| (root.campaign(), root))
            .collect();
        let mut input = Input {
            bucket: Bucket::new("bucket").halted_by(Halt::At(Instant::now())),
            state: PathBuf::from("/nonexistent"),
            instance: INSTANCE.into(),
            roots,
            current: None,
            assigned: None,
            confirming: None,
            observed: None,
            at_rest: true,
            stint_seconds: None,
        };
        let errors = pass(&mut input).errors;
        assert_eq!(errors.len(), 2, "{errors:?}");
        for (error, campaign) in errors.iter().zip(&named) {
            assert!(error.starts_with(campaign.as_str()), "{error}");
        }
        input.at_rest = false;
        assert!(pass(&mut input).errors.is_empty());
    }
}
