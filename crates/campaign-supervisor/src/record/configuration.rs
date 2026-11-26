//! Declared storage charges reserve controller records and bounded retained evidence.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::{FORMAT, Text};

const CONTROLLER_RECORDS: [super::Kind; 8] = [
    super::Kind::Attempt,
    super::Kind::Reservation,
    super::Kind::Intent,
    super::Kind::Started,
    super::Kind::Bound,
    super::Kind::Finished,
    super::Kind::Pin,
    super::Kind::JobResult,
];
// Reservation removal precedes pin and result publication.
const PEAK_CONTROLLER_RECORDS: usize = CONTROLLER_RECORDS.len() - 1;
const CONTROLLER_RECORD_BYTES: u128 = PEAK_CONTROLLER_RECORDS as u128 * super::BOUND as u128;
const CONTROLLER_INODES: u128 = PEAK_CONTROLLER_RECORDS as u128 + 2 + 3;
const RETENTION_RECORDS: [super::Kind; 3] = [
    super::Kind::Captured,
    super::Kind::Finding,
    super::Kind::Reclaimed,
];
const MANIFEST_COPY_BYTES: u128 = super::BOUND as u128;
const RETENTION_RECORD_BYTES: u128 = {
    let mut bytes = MANIFEST_COPY_BYTES;
    let mut index = 0;
    while index < RETENTION_RECORDS.len() {
        bytes += RETENTION_RECORDS[index].bound() as u128;
        index += 1;
    }
    bytes
};
const RECLAIMED_EVIDENCE_BYTES: u64 = super::Artifact::RECLAIMED_RECORDS.len() as u64
    * super::BOUND
    + super::Artifact::REPORTED_STREAMS.len() as u64 * crate::sim::OUTPUT as u64;
// Housekeeping entries stay in the evidence directory after reclaim.
const RECLAIMED_EVIDENCE_INODES: u64 = (super::Artifact::RECLAIMED_RECORDS.len()
    + super::Artifact::REPORTED_STREAMS.len()
    + crate::store::HOUSEKEEPING_ENTRIES.len()) as u64;
const RETENTION_INODES: u128 = RETENTION_RECORDS.len() as u128 + 2;
pub(crate) const COMPLETION_RECORD_BYTES: u128 = 2 * super::BOUND as u128;

pub(crate) struct Charge {
    pub bytes: u128,
    pub inodes: u128,
}
impl Charge {
    pub(crate) fn disk(&self, fragment: std::num::NonZeroU64) -> u128 {
        self.bytes + self.inodes * u128::from(fragment.get())
    }
}
pub(crate) fn probe_charge(bundle_bytes: u64, stream_bytes: u64, branch_files: u64) -> Charge {
    Charge {
        bytes: 2 * u128::from(bundle_bytes) + u128::from(stream_bytes) + CONTROLLER_RECORD_BYTES,
        inodes: 2 + u128::from(branch_files) + CONTROLLER_INODES,
    }
}

pub(crate) fn resource_charge(output: u64, inodes: u64) -> Charge {
    Charge {
        bytes: 2 * u128::from(output) + CONTROLLER_RECORD_BYTES + RETENTION_RECORD_BYTES,
        inodes: 2 * u128::from(inodes) + CONTROLLER_INODES + RETENTION_INODES,
    }
}

const KEYS: [&str; 14] = [
    "slots",
    "reserve_slots",
    "cores",
    "memory",
    "cpu",
    "tree_memory",
    "attempt_output",
    "attempt_inodes",
    "wall",
    "processes",
    "artifact_bytes",
    "artifact_inodes",
    "backlog",
    "retained_builds",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Stored")]
pub struct Configuration {
    config: BTreeMap<Text, u64>,
    enforcement: Text,
    format: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    config: BTreeMap<Text, u64>,
    enforcement: Text,
    format: u64,
}

#[derive(Debug)]
pub enum ConfigurationError {
    Fields,
    Capacity,
    Header,
    CpuLimit,
    OutputLimit,
    InodeLimit,
}

impl std::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fields => f.write_str(
                "configuration requires every positive dispatch setting and paired corpus limits",
            ),
            Self::Capacity => f.write_str("configuration budgets must cover every slot"),
            Self::Header => {
                f.write_str("configuration header must select format 1 and census enforcement")
            }
            Self::CpuLimit => write!(
                f,
                "cpu exceeds largest installable limit {}",
                crate::sys::CPU_HARD_MAX - 1
            ),
            Self::InodeLimit => write!(
                f,
                "attempt inode budget exceeds {}",
                crate::store::EVIDENCE_BOUND - 2
            ),
            Self::OutputLimit => write!(
                f,
                "output exceeds largest installable limit {}",
                crate::sys::LIMIT_MAX
            ),
        }
    }
}

impl std::error::Error for ConfigurationError {}

impl Configuration {
    pub fn new(config: BTreeMap<Text, u64>) -> Result<Self, ConfigurationError> {
        let get = |key: &str| {
            u128::from(
                config
                    .get(&Text::new(key).expect("configuration key is ASCII"))
                    .copied()
                    .unwrap_or(0),
            )
        };
        if KEYS.iter().any(|key| get(key) == 0)
            || config.iter().any(|(key, value)| {
                *value == 0
                    || !KEYS.contains(&key.as_str())
                        && !["corpus_count", "corpus_bytes"].contains(&key.as_str())
            })
            || (get("corpus_count") == 0) != (get("corpus_bytes") == 0)
        {
            return Err(ConfigurationError::Fields);
        }
        if get("cpu") >= u128::from(crate::sys::CPU_HARD_MAX) {
            return Err(ConfigurationError::CpuLimit);
        }
        if get("attempt_output") > u128::from(crate::sys::LIMIT_MAX) {
            return Err(ConfigurationError::OutputLimit);
        }
        if get("attempt_inodes") > (crate::store::EVIDENCE_BOUND - 2) as u128 {
            return Err(ConfigurationError::InodeLimit);
        }
        let charge = resource_charge(get("attempt_output") as u64, get("attempt_inodes") as u64);
        let bytes = charge.bytes;
        let inodes = charge.inodes;
        let shares = get("slots") + get("reserve_slots");
        if shares > get("cores")
            || shares * get("tree_memory") > get("memory")
            || shares
                .checked_mul(bytes)
                .and_then(|total| total.checked_add(get("corpus_bytes")))
                .is_none_or(|total| total >= get("artifact_bytes"))
            || shares * inodes >= get("artifact_inodes")
        {
            return Err(ConfigurationError::Capacity);
        }
        Ok(Self {
            config,
            enforcement: Text::new("census").expect("enforcement is ASCII"),
            format: FORMAT,
        })
    }

    pub fn config(&self) -> &BTreeMap<Text, u64> {
        &self.config
    }
    pub(crate) fn charge(&self) -> Charge {
        resource_charge(self.value("attempt_output"), self.value("attempt_inodes"))
    }
    /// The charge per fork share of a concluded attempt: controller and
    /// retention records plus one output budget for bulk. The census
    /// multiplies this rate by the job's fork shares.
    pub(crate) fn retained_charge(&self) -> Charge {
        retention_charge(self.value("attempt_output"), self.value("attempt_inodes"))
    }
    /// The charge per fork share of a reclaimed attempt: its controller and
    /// retention records and the part of its output budget the files its
    /// evidence store keeps can fill, so it never exceeds the retained
    /// charge.
    pub(crate) fn reclaimed_charge(&self) -> Charge {
        retention_charge(
            self.value("attempt_output").min(RECLAIMED_EVIDENCE_BYTES),
            self.value("attempt_inodes").min(RECLAIMED_EVIDENCE_INODES),
        )
    }
    pub fn file_bytes(&self) -> u64 {
        self.value("attempt_output")
    }

    pub fn value(&self, key: &str) -> u64 {
        Text::new(key)
            .and_then(|key| self.config.get(&key))
            .copied()
            .unwrap_or(0)
    }
}

impl TryFrom<Stored> for Configuration {
    type Error = ConfigurationError;

    fn try_from(stored: Stored) -> Result<Self, Self::Error> {
        if stored.format != FORMAT || stored.enforcement.as_str() != "census" {
            return Err(ConfigurationError::Header);
        }
        Self::new(stored.config)
    }
}

/// Reserves one retained output population and its controller records.
pub(crate) fn retention_charge(output: u64, inodes: u64) -> Charge {
    Charge {
        bytes: u128::from(output) + CONTROLLER_RECORD_BYTES + RETENTION_RECORD_BYTES,
        inodes: u128::from(inodes) + CONTROLLER_INODES + RETENTION_INODES,
    }
}

#[cfg(test)]
mod charge_tests {
    #[test]
    fn every_kind_declares_its_per_attempt_controller_role() {
        use super::super::Kind;
        for kind in Kind::ALL {
            let per_attempt = match kind {
                Kind::Attempt
                | Kind::Reservation
                | Kind::Intent
                | Kind::Started
                | Kind::Bound
                | Kind::Finished
                | Kind::Pin
                | Kind::JobResult
                | Kind::Captured
                | Kind::Finding
                | Kind::Reclaimed => true,
                Kind::Hardware
                | Kind::HardwareDisposition
                | Kind::Job
                | Kind::Build
                | Kind::Artifact
                | Kind::Admission
                | Kind::Configuration
                | Kind::Capacity
                | Kind::Calibration
                | Kind::CalibrationPlan
                | Kind::CalibrationReplay
                | Kind::ResourceBounds
                | Kind::ProbeFinished
                | Kind::CorpusProbe
                | Kind::CorpusAsset
                | Kind::CorpusVersion
                | Kind::CorpusRetirement
                | Kind::Disposition
                | Kind::TriageStep
                | Kind::TriageResult
                | Kind::ReplayDependencies
                | Kind::RegressionCandidate => false,
            };
            assert_eq!(
                super::CONTROLLER_RECORDS.contains(kind) || super::RETENTION_RECORDS.contains(kind),
                per_attempt
            );
        }
        assert_eq!(super::PEAK_CONTROLLER_RECORDS, 7);
    }
}
