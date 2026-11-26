use super::Text;
use super::attempt::labels;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

labels! { HardwareKind; Sweep => "sweep", Fleet => "fleet", Episode => "episode" }
labels! { HardwareClass; Gated => "gated", Unrun => "unrun", Completed => "completed", Uncredited => "uncredited", Interrupted => "interrupted", Rejected => "rejected", Infrastructure => "infrastructure", Held => "held" }
labels! { HardwarePhase; Intent => "intent", Started => "started", Finished => "finished" }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hardware {
    pub argv: Vec<Text>,
    pub class: Option<HardwareClass>,
    pub custody_directory: Option<Text>,
    pub directory: Text,
    pub exit: Option<u64>,
    pub kind: HardwareKind,
    pub number: u64,
    pub phase: HardwarePhase,
    pub platform: Text,
    pub profile: Text,
    pub reason: Text,
    pub signal: Option<u64>,
    pub stopped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DispositionWire")]
pub struct HardwareDisposition {
    evidence: Text,
    run: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DispositionWire {
    evidence: Text,
    run: u64,
}

impl HardwareDisposition {
    pub fn run(&self) -> u64 {
        self.run
    }
    pub fn new(run: u64, evidence: Text) -> Option<Self> {
        (run > 0 && !evidence.as_str().trim().is_empty()).then_some(Self { evidence, run })
    }
}

impl TryFrom<DispositionWire> for HardwareDisposition {
    type Error = &'static str;
    fn try_from(wire: DispositionWire) -> Result<Self, Self::Error> {
        Self::new(wire.run, wire.evidence)
            .ok_or("a disposition requires a run and nonempty evidence")
    }
}
