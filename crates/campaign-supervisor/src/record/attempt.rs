use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{Digest, Text};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub attempt: Text,
    pub file_bytes: u64,
    pub job: Digest,
    pub manifest: Digest,
    pub number: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundEvidence {
    pub artifact: Digest,
    pub attempt: Text,
    pub bundle: Option<Digest>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kernel {
    pub cpu: BTreeMap<Text, u64>,
    pub memory: BTreeMap<Text, u64>,
    pub pids: BTreeMap<Text, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finished {
    pub attempt: Text,
    pub binding: Binding,
    pub bound: Option<BoundEvidence>,
    pub class: Class,
    pub exit: Option<u64>,
    pub interruption: Option<u64>,
    pub kernel: Kernel,
    pub residual_members: bool,
    pub signal: Option<u64>,
    pub watchdog: bool,
}

macro_rules! labels {
    ($enum:ident; $($variant:ident => $name:literal),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $enum { $($variant),+ }
        impl $enum {
            pub const ALL: &[Self] = &[$(Self::$variant),+];
            pub fn name(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }
        }
        impl Serialize for $enum {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.name())
            }
        }
        impl<'de> Deserialize<'de> for $enum {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                match Text::deserialize(deserializer)?.as_str() {
                    $($name => Ok(Self::$variant),)+
                    _ => Err(serde::de::Error::custom(concat!("invalid ", stringify!($enum), " label"))),
                }
            }
        }
    };
}

pub(super) use labels;

labels! { Class;
    Pass => "pass",
    Violation => "violation",
    Unsuccessful => "unsuccessful",
    Inconclusive => "inconclusive",
    Incomplete => "incomplete",
    EngineFailure => "engine-failure",
    Rejected => "rejected",
    Interrupted => "interrupted",
    Watchdog => "watchdog",
    Signal => "signal",
    Oom => "oom",
    PidLimit => "pid-limit",
    CpuLimit => "cpu-limit",
    OutputLimit => "output-limit",
    MixedLimits => "mixed-limits",
    MalformedEvidence => "malformed-evidence",
    MisboundEvidence => "misbound-evidence",
    Disagreement => "disagreement",
    Infrastructure => "infrastructure",
}

labels! { Binding;
    Matching => "matching",
    Missing => "missing",
    Malformed => "malformed",
    Misbound => "misbound",
}

impl Finished {
    /// Controller stops, launcher interruptions and resource limits keep triage unresolved.
    pub(crate) fn interrupted_step(&self) -> bool {
        self.interruption.is_some()
            || self.signal.is_some()
            || self.watchdog
            || self.exit.is_none()
            || matches!(self.exit, Some(5 | 6))
            || match self.class {
                Class::Interrupted
                | Class::Oom
                | Class::PidLimit
                | Class::CpuLimit
                | Class::OutputLimit
                | Class::MixedLimits
                | Class::Watchdog => true,
                Class::Pass
                | Class::Violation
                | Class::Unsuccessful
                | Class::Inconclusive
                | Class::Incomplete
                | Class::EngineFailure
                | Class::Rejected
                | Class::Signal
                | Class::MalformedEvidence
                | Class::MisboundEvidence
                | Class::Disagreement
                | Class::Infrastructure => false,
            }
    }
}
