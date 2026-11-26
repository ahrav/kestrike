use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::Text;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub attempt: Text,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeFinished {
    pub attempt: Text,
    pub outcome: ProbeOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    Complete,
    Held,
    OutputLimit,
    Oom,
    PidLimit,
    CpuLimit,
    MixedLimits,
}

impl Serialize for ProbeOutcome {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::Complete => "complete",
            Self::Held => "held",
            Self::OutputLimit => "output-limit",
            Self::Oom => "oom",
            Self::PidLimit => "pid-limit",
            Self::CpuLimit => "cpu-limit",
            Self::MixedLimits => "mixed-limits",
        })
    }
}

impl<'de> Deserialize<'de> for ProbeOutcome {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Text::deserialize(deserializer)?.as_str() {
            "complete" => Ok(Self::Complete),
            "held" => Ok(Self::Held),
            "output-limit" => Ok(Self::OutputLimit),
            "oom" => Ok(Self::Oom),
            "pid-limit" => Ok(Self::PidLimit),
            "cpu-limit" => Ok(Self::CpuLimit),
            "mixed-limits" => Ok(Self::MixedLimits),
            _ => Err(serde::de::Error::custom("invalid probe outcome")),
        }
    }
}
