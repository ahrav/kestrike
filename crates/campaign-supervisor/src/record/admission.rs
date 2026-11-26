use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{Job, Text};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Campaign,
    Calibration,
}

impl Purpose {
    pub(crate) fn matches_campaign(self, campaign: &Text) -> bool {
        (self == Self::Calibration) == (campaign.as_str() == "calibration")
    }
}

impl Serialize for Purpose {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::Campaign => "campaign",
            Self::Calibration => "calibration",
        })
    }
}

impl<'de> Deserialize<'de> for Purpose {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Text::deserialize(deserializer)?.as_str() {
            "campaign" => Ok(Self::Campaign),
            "calibration" => Ok(Self::Calibration),
            _ => Err(serde::de::Error::custom("invalid admission purpose")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Stored")]
pub struct Admission {
    archive: Text,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Catalog version at admission; semantic identity derives from the nested job.
    corpus_version: Option<u64>,
    job: Job,
    purpose: Purpose,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    archive: Text,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    corpus_version: Option<u64>,
    job: Job,
    purpose: Purpose,
}

#[derive(Debug)]
pub enum AdmissionError {
    PurposeMismatch,
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("admission purpose must match the frozen campaign")
    }
}

impl std::error::Error for AdmissionError {}

impl Admission {
    pub fn new(archive: Text, job: Job, purpose: Purpose) -> Result<Self, AdmissionError> {
        if job.experiment().target.is_some()
            || !purpose.matches_campaign(&job.experiment().campaign)
            || purpose == Purpose::Campaign && job.experiment().calibration_scope.is_some()
        {
            return Err(AdmissionError::PurposeMismatch);
        }
        Ok(Self {
            archive,
            corpus_version: None,
            job,
            purpose,
        })
    }

    pub(crate) fn targeted(archive: Text, job: Job, version: u64) -> Result<Self, AdmissionError> {
        if version == 0
            || job.experiment().target.is_none()
            || !Purpose::Campaign.matches_campaign(&job.experiment().campaign)
            || job.experiment().calibration_scope.is_some()
        {
            return Err(AdmissionError::PurposeMismatch);
        }
        Ok(Self {
            archive,
            corpus_version: Some(version),
            job,
            purpose: Purpose::Campaign,
        })
    }
    pub fn corpus_version(&self) -> Option<u64> {
        self.corpus_version
    }
    pub fn target(&self) -> Option<&super::Target> {
        self.job.experiment().target.as_ref()
    }
    pub fn command(&self) -> &str {
        self.target().map_or("run", |t| t.form.command())
    }
    pub fn shares(&self) -> u64 {
        self.target().map_or(1, |t| t.shares())
    }

    pub fn archive(&self) -> &Text {
        &self.archive
    }
    pub fn job(&self) -> &Job {
        &self.job
    }
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
}

impl TryFrom<Stored> for Admission {
    type Error = AdmissionError;

    fn try_from(stored: Stored) -> Result<Self, Self::Error> {
        match stored.corpus_version {
            Some(version) if stored.purpose == Purpose::Campaign => {
                Self::targeted(stored.archive, stored.job, version)
            }
            None if stored.job.experiment().target.is_none() => {
                Self::new(stored.archive, stored.job, stored.purpose)
            }
            _ => Err(AdmissionError::PurposeMismatch),
        }
    }
}
