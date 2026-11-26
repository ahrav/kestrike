//! Job settlement and attempt reclamation records retain durable outcomes.
//! Settlement publishes the failure pin before its equal job result.
//! Collection publishes the reclaim marker before deleting the named bulk.

use serde::{Deserialize, Serialize};

use super::{Digest, Finished, Text};

/// The job-level outcome selected by settlement.
/// `attempt` numbers the selected finish, including an earlier pinned failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobResult {
    pub attempt: u64,
    pub finished: Finished,
    pub job: Digest,
    pub manifest: Digest,
}

impl JobResult {
    pub(crate) const SUFFIX: &str = ".result.json";
}

/// Collect writes this record create-once in a settled attempt's directory
/// before it deletes the attempt's bulk: `attempt` numbers the attempt,
/// `finished` is the digest of its `finished` record, and `names` lists
/// the bulk files, relative to the attempt directory, the reclaim deletes.
/// Readers of the attempt take its outcome from its records once this
/// record exists and read none of the named files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reclaimed {
    pub attempt: u64,
    pub finished: Digest,
    pub names: Vec<Text>,
}

impl Reclaimed {
    /// Canonical names keep a rerun's marker equal to its first publication.
    /// `bulk` contains the artifact's validated ASCII components.
    pub(crate) fn new(
        attempt: u64,
        finished: &super::Verified<Finished>,
        bulk: &[crate::store::Name],
    ) -> Self {
        let identity = finished.record().attempt.as_str();
        let names = bulk
            .iter()
            .map(|entry| format!("artifacts/{identity}/{}", entry.as_str()))
            .chain(crate::custody::LAUNCHER_OUTPUTS.map(str::to_owned))
            .map(|entry| {
                Text::new(&entry)
                    .expect("bulk components and the finish identity are printable ASCII")
            })
            .collect();
        Self {
            attempt,
            finished: Digest::of(finished.read().bytes()),
            names,
        }
    }
}

/// Settlement creates this pin before the failure result, with equal JobResult values.
/// Recovery verifies the retained pin and publishes its matching result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub result: JobResult,
}

impl Pin {
    pub(crate) const SUFFIX: &str = ".pin";
}
