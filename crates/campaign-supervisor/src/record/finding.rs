//! Findings retain replay inputs. Dispositions preserve numbered decisions.

use super::{Admission, Artifact, Finished, Text};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

super::attempt::labels! { FindingKind;
    Engine => "engine", Unsuccessful => "unsuccessful", Inconclusive => "inconclusive", Incomplete => "incomplete",
    Violation => "violation", Panic => "panic", Abort => "abort", Truncated => "truncated", Watchdog => "watchdog", Harness => "harness",
}

impl FindingKind {
    pub fn release_blocker(self) -> bool {
        matches!(self, Self::Violation | Self::Panic | Self::Abort)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "StoredFinding")]
/// A frozen failure snapshot with independently retained replay dependencies.
/// A child snapshot appends its label to the actual parent attempt identifier.
/// Each child-bearing snapshot verifies against its parent attempt and live Admission.
/// Both remain retention roots while the finding is retained.
pub struct Finding {
    pub admission: Admission,
    pub artifact: Option<Artifact>,
    pub attempt: super::Attempt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration_root: Option<super::Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child: Option<ChildEvidence>,
    pub finished: Finished,
    pub kind: FindingKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_attempt: Option<Text>,
}

/// Failure facts from a branch child, exploration node or leaf.
/// `bundle` hashes the retained bytes; `digest` and `terminal` describe the child run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildEvidence {
    pub bundle: Option<super::Digest>,
    pub class: super::Class,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<super::Digest>,
    pub file: Option<Text>,
    pub kind: FindingKind,
    pub label: Text,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<Text>,
}

impl ChildEvidence {
    pub(crate) fn replay_facts(&self) -> Option<(super::Digest, &Text)> {
        Some((self.digest?, self.terminal.as_ref()?))
    }

    pub(crate) fn finding_id(&self, parent: &Text) -> Text {
        Text::new(&format!("{}-{}", parent.as_str(), self.label.as_str()))
            .expect("finding identity is ASCII")
    }
}

impl Finding {
    pub fn id(&self) -> Text {
        match (&self.child, &self.parent_attempt) {
            (Some(child), Some(parent)) => child.finding_id(parent),
            _ => self.attempt.attempt.clone(),
        }
    }
    pub(crate) fn bundle_wait_reason(&self) -> Option<&'static str> {
        (self.admission.target().is_some() && self.bundle().is_none()).then_some(
            if self.child.is_some() {
                "no retained child bundle"
            } else {
                "no retained bundle"
            },
        )
    }
    pub fn bundle(&self) -> Option<super::Digest> {
        self.child.as_ref().map_or_else(
            || self.artifact.as_ref().and_then(|artifact| artifact.bundle),
            |child| child.bundle,
        )
    }
}

super::attempt::labels! { Decision;
    ReleaseBlocker => "release-blocker", Harness => "harness", Resolved => "resolved",
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Fields")]
/// A numbered operator decision with nonempty evidence.
pub struct Disposition {
    decision: Decision,
    evidence: Text,
    finding: Text,
    number: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fields {
    decision: Decision,
    evidence: Text,
    finding: Text,
    number: u64,
}

impl TryFrom<Fields> for Disposition {
    type Error = &'static str;
    fn try_from(value: Fields) -> Result<Self, Self::Error> {
        Self::new(value.finding, value.number, value.decision, value.evidence)
    }
}

impl Disposition {
    pub fn new(
        finding: Text,
        number: u64,
        decision: Decision,
        evidence: Text,
    ) -> Result<Self, &'static str> {
        if number == 0 || evidence.as_str().trim().is_empty() {
            return Err("disposition requires a positive number and nonempty evidence");
        }
        Ok(Self {
            decision,
            evidence,
            finding,
            number,
        })
    }
    pub fn decision(&self) -> Decision {
        self.decision
    }
    pub fn finding(&self) -> &Text {
        &self.finding
    }
    pub fn number(&self) -> u64 {
        self.number
    }
}

/// A durable capture completion bound to an attempt and its finished bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Captured {
    pub attempt: Text,
    pub finding: Option<Text>,
    pub finished: super::Digest,
}

impl Captured {
    pub(crate) fn matches(&self, finished: &super::Verified<Finished>) -> bool {
        self.attempt == finished.record().attempt
            && self.finished == super::Digest::of(finished.read().bytes())
            && self
                .finding
                .as_ref()
                .is_none_or(|id| id == &finished.record().attempt)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFinding {
    admission: Admission,
    artifact: Option<Artifact>,
    attempt: super::Attempt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    calibration_root: Option<super::Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    child: Option<ChildEvidence>,
    finished: Finished,
    kind: FindingKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_attempt: Option<Text>,
}

impl TryFrom<StoredFinding> for Finding {
    type Error = &'static str;
    fn try_from(value: StoredFinding) -> Result<Self, Self::Error> {
        if value.parent_attempt.is_some() && value.child.is_none()
            || value
                .child
                .as_ref()
                .is_some_and(|child| child.kind != value.kind)
        {
            return Err("finding lineage differs");
        }
        Ok(Self {
            admission: value.admission,
            artifact: value.artifact,
            attempt: value.attempt,
            calibration_root: value.calibration_root,
            child: value.child,
            finished: value.finished,
            kind: value.kind,
            parent_attempt: value.parent_attempt,
        })
    }
}
