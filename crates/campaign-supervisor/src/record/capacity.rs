use serde::{Deserialize, Serialize};

use super::{CalibrationContract, Configuration, Digest, ResourceBounds};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Stored")]
pub struct Capacity {
    budget: Configuration,
    contract: CalibrationContract,
    evidence: Digest,
    resources: ResourceBounds,
    root: Digest,
    slots: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    budget: Configuration,
    contract: CalibrationContract,
    evidence: Digest,
    resources: ResourceBounds,
    root: Digest,
    slots: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityError {
    Fields,
}
impl std::fmt::Display for CapacityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("capacity requires a profile and positive slots")
    }
}
impl std::error::Error for CapacityError {}

impl Capacity {
    pub fn new(
        contract: CalibrationContract,
        evidence: Digest,
        resources: ResourceBounds,
        root: Digest,
        slots: u64,
        budget: Configuration,
    ) -> Result<Self, CapacityError> {
        if contract.profile.as_str().is_empty() || slots == 0 {
            return Err(CapacityError::Fields);
        }
        Ok(Self {
            budget,
            contract,
            evidence,
            resources,
            root,
            slots,
        })
    }
    pub fn budget(&self) -> &Configuration {
        &self.budget
    }
    pub fn contract(&self) -> &CalibrationContract {
        &self.contract
    }
    pub fn slots(&self) -> u64 {
        self.slots
    }
    pub fn evidence(&self) -> Digest {
        self.evidence
    }
    pub fn resources(&self) -> &ResourceBounds {
        &self.resources
    }
    pub fn root(&self) -> Digest {
        self.root
    }
}
impl TryFrom<Stored> for Capacity {
    type Error = CapacityError;
    fn try_from(value: Stored) -> Result<Self, Self::Error> {
        Self::new(
            value.contract,
            value.evidence,
            value.resources,
            value.root,
            value.slots,
            value.budget,
        )
    }
}
