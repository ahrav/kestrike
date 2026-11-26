use super::{Digest, Text};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusProbe {
    pub archive: Digest,
    pub archive_path: Text,
    pub attempt: Text,
    pub bundle: Digest,
    pub bytes: u64,
    pub manifest: Digest,
    pub milestone: Text,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusAsset {
    pub boundary: u64,
    pub decisions: u64,
    pub prefix: Digest,
    pub probe: CorpusProbe,
    pub profile: Text,
    pub root: u64,
    pub semantic: u64,
    pub state: Digest,
}

impl CorpusAsset {
    pub fn id(&self) -> Digest {
        Digest::of(
            &serde_json::to_vec(&serde_json::json!({
                "kind": "corpus-asset", "build": self.probe.archive,
                "manifest_sha256": self.probe.manifest, "prefix": self.prefix,
                "semantic": self.semantic, "milestone": self.probe.milestone,
            }))
            .expect("corpus identity is serializable"),
        )
    }
    pub fn semantic_key(&self) -> Digest {
        Digest::of(
            &serde_json::to_vec(&serde_json::json!({
                "kind": "corpus-state", "build": self.probe.archive,
                "milestone": self.probe.milestone, "state": self.state,
            }))
            .expect("corpus state is serializable"),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusVersion {
    pub asset: Digest,
    pub number: u64,
    pub retired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusRetirement {
    pub asset: Digest,
}
