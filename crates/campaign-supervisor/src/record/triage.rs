//! Record types for triage steps and their results. Reading a `TriageResult`
//! refuses a `state` that disagrees with the stopped execution, a `status` or
//! `comparison` on an interrupted result, and a complete result without a
//! `status`.
use super::{Attempt, Comparison, Digest, FindingKind, Finished, Text};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

super::attempt::labels! { StepKind;
    Replay => "replay", Rerun => "rerun", Reduce => "reduce",
}
impl StepKind {
    pub fn command(self) -> &'static str {
        match self {
            Self::Rerun => "run",
            _ => self.name(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// A durable step token binds the finding, command and execution limits.
pub struct TriageStep {
    pub attempt: Attempt,
    pub finding: Text,
    pub kind: StepKind,
    pub launcher: Text,
    pub limits: BTreeMap<Text, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Frozen archive, manifest and bundle digests remain replay and collection roots.
pub struct ReplayDependencies {
    pub archive: Digest,
    pub archive_path: Text,
    pub bundle: Option<Digest>,
    pub finding: Text,
    pub manifest: Digest,
}

super::attempt::labels! { ReplayStatus;
    Reproduced => "reproduced", Reduced => "reduced", Diverged => "diverged", Unreproduced => "unreproduced", Unreducible => "unreducible", InsufficientEvidence => "insufficient-evidence",
}
super::attempt::labels! { StepState;
    Complete => "complete", Interrupted => "interrupted",
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ResultFields")]
/// A stopped step retains bound facts; an interrupted step carries an absent status.
pub struct TriageResult {
    pub comparison: Option<Comparison>,
    pub elapsed_ms: Option<u64>,
    /// A bound worker file-size signal keeps the step unresolved.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub file_limited: bool,
    pub finding: Text,
    pub finished: Finished,
    pub number: u64,
    /// A bound oversized worker stream keeps the triage outcome unresolved.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub output_limited: bool,
    pub state: StepState,
    pub status: Option<ReplayStatus>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultFields {
    comparison: Option<Comparison>,
    elapsed_ms: Option<u64>,
    #[serde(default)]
    file_limited: bool,
    finding: Text,
    finished: Finished,
    number: u64,
    #[serde(default)]
    output_limited: bool,
    state: StepState,
    status: Option<ReplayStatus>,
}

impl TryFrom<ResultFields> for TriageResult {
    type Error = &'static str;
    fn try_from(fields: ResultFields) -> Result<Self, Self::Error> {
        let interrupted =
            fields.finished.interrupted_step() || fields.output_limited || fields.file_limited;
        if (fields.state == StepState::Interrupted) != interrupted
            || interrupted && (fields.status.is_some() || fields.comparison.is_some())
            || !interrupted && fields.status.is_none()
        {
            return Err("triage outcome differs from stopped execution");
        }
        Ok(Self {
            comparison: fields.comparison,
            elapsed_ms: fields.elapsed_ms,
            file_limited: fields.file_limited,
            finding: fields.finding,
            finished: fields.finished,
            number: fields.number,
            output_limited: fields.output_limited,
            state: fields.state,
            status: fields.status,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// A replay command binds the candidate inputs and full original failure identity.
/// A null step time is unmeasured and selects the conservative corpus tier.
pub struct RegressionCandidate {
    pub archive: Digest,
    pub bundle: Option<Digest>,
    pub bytes: Option<u64>,
    pub command: Vec<Text>,
    pub expected_exit: Option<u64>,
    pub failure_identity: Option<Text>,
    pub failure_kind: FindingKind,
    pub finding: Text,
    pub input: Text,
    pub manifest: Digest,
    pub number: u64,
    pub step_ms: Option<u64>,
    pub tier: Text,
}
