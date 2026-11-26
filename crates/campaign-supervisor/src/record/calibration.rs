use super::{Admission, Artifact, Attempt, Configuration, Digest, Finished, Text};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationContract {
    pub build: Digest,
    pub counts: BTreeMap<Text, u64>,
    pub profile: Text,
}
impl CalibrationContract {
    pub fn key(&self) -> Digest {
        Digest::of(&serde_json::to_vec(self).expect("calibration contract encodes"))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationPlan {
    pub config: Configuration,
    pub controls: BTreeMap<Text, Admission>,
    pub deduplicated: bool,
    pub healthy: Admission,
    pub missing: Vec<Text>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationReplay {
    pub attempt: Attempt,
    pub original: Digest,
    pub source: Text,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBounds {
    pub cpu_us: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub pids: Option<u64>,
    pub wall_us: Option<u64>,
}
impl ResourceBounds {
    pub fn fits(&self, config: &Configuration, slots: u64) -> bool {
        let (Some(cpu), Some(memory), Some(pids), Some(wall)) =
            (self.cpu_us, self.memory_bytes, self.pids, self.wall_us)
        else {
            return false;
        };
        let shares = u128::from(slots) + u128::from(config.value("reserve_slots"));
        cpu > 0
            && memory > 0
            && pids > 0
            && wall > 0
            && u128::from(cpu) <= u128::from(config.value("cpu")) * 1_000_000
            && memory <= config.value("tree_memory")
            && pids <= config.value("processes")
            && u128::from(wall) <= u128::from(config.value("wall")) * 1_000_000
            && u128::from(cpu.div_ceil(wall)) * shares <= u128::from(config.value("cores"))
            && u128::from(config.value("tree_memory")) * shares
                <= u128::from(config.value("memory"))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationEvidence {
    pub artifact: Option<Artifact>,
    pub finished: Finished,
    pub job: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<super::FindingKind>,
    pub resources: ResourceBounds,
}
super::attempt::labels! { CalibrationVerdict;
    Calibrated => "calibrated",
    Uncalibrated => "uncalibrated",
    Refused => "refused",
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Calibration {
    pub contract: CalibrationContract,
    pub controls: BTreeMap<Text, CalibrationEvidence>,
    pub defects: Vec<Text>,
    pub detected: Vec<Text>,
    pub healthy: CalibrationEvidence,
    pub lost: Finished,
    pub missing: Vec<Text>,
    pub reasons: Vec<Text>,
    pub replays: Vec<CalibrationEvidence>,
    pub root: Digest,
    pub verdict: CalibrationVerdict,
}
