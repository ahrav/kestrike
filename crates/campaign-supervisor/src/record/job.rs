//! The job record: one frozen experiment with the identity, root seed and
//! manifest digest derived from it.
//!
//! [`Job::derive`] computes the identity, the seed and the manifest bytes
//! the worker runs. Decoding a job re-derives its identity and seed and
//! refuses a job that holds others. A targeted job keeps the corpus root seed
//! and the frozen worker manifest digest; its target owns those values.
//! An ordinary job's manifest digest is the one its
//! writer stored, since the manifest's key order comes from the capability
//! listing.
//!
//! The read rule verifies identity and seed. Targeted jobs also require format 2,
//! a valid target, and a build pin and manifest digest matching that target.
//! Admission and execution check ordinary job values against their listed bounds.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::identity::{JobId, seed};
use super::{Digest, Text};

/// The archive pins of an experiment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pins {
    /// The archive build's digest, as text.
    pub build: Text,
    /// The archived executable's digest, as text.
    pub executable: Text,
    /// The target platform the archive was built for.
    pub platform: Text,
    /// The compiler version the archive was built with.
    pub toolchain: Text,
}

/// The frozen fields of one experiment. Each field is part of the job
/// identity, so changing any of them names another job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Experiment {
    /// The most attempts the job may take.
    pub attempts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration_scope: Option<Digest>,
    /// The campaign the experiment belongs to.
    pub campaign: Text,
    /// The capability listing version the experiment was frozen from.
    pub capabilities: Text,
    /// The profile's class, when the listing declares one.
    pub class: Option<Text>,
    /// The manifest's count keys with their values.
    pub counts: BTreeMap<Text, u64>,
    /// The experiment record's own format, an identity field that is
    /// independent of the envelope's [`FORMAT`](super::FORMAT).
    pub format: u64,
    /// The cluster generator, for a profile with a cluster entry.
    pub generator: Option<Text>,
    /// The manifest schema version, the manifest's `version` value.
    pub manifest_version: Text,
    /// The cluster minima, for a profile with a cluster entry.
    pub minima: Option<Text>,
    pub pins: Pins,
    /// The workload profile the worker runs, the manifest's `profile`.
    pub profile: Text,
    /// The run number, which tells repeated admissions of one experiment
    /// apart as separate jobs.
    pub run: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Corpus inputs and fork form for a targeted experiment.
    pub target: Option<super::Target>,
}

impl Experiment {
    /// The job identity: the SHA-256 of the experiment's canonical
    /// encoding.
    pub fn id(&self) -> JobId {
        // Serialization fails only on a non-string map key or a failing
        // `Serialize` impl, and an experiment holds neither.
        JobId::of(&serde_json::to_vec(self).expect("an experiment encodes"))
    }
}

/// A job record: an experiment with its identity, root seed and manifest
/// digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Stored")]
pub struct Job {
    experiment: Experiment,
    id: JobId,
    manifest_sha256: Digest,
    seed: u64,
}

/// A job's fields as a file holds them, before its identity and seed are
/// checked.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    experiment: Experiment,
    id: Digest,
    manifest_sha256: Digest,
    seed: u64,
}

impl TryFrom<Stored> for Job {
    type Error = &'static str;

    fn try_from(stored: Stored) -> Result<Self, Self::Error> {
        let id = stored.experiment.id();
        if stored.id != id.digest()
            || stored.seed
                != stored
                    .experiment
                    .target
                    .as_ref()
                    .map_or_else(|| seed(&id), |target| target.root)
        {
            return Err("the job's identity or seed does not derive from its experiment");
        }
        if stored.experiment.format
            != if stored.experiment.target.is_some() {
                2
            } else {
                1
            }
        {
            return Err("experiment format differs from its target form");
        }
        if stored.experiment.target.is_some()
            && targeted_inputs(&stored.experiment)?.manifest != stored.manifest_sha256
        {
            return Err("targeted manifest differs");
        }
        Ok(Self {
            experiment: stored.experiment,
            id,
            manifest_sha256: stored.manifest_sha256,
            seed: stored.seed,
        })
    }
}

fn targeted_inputs(experiment: &Experiment) -> Result<&super::Target, &'static str> {
    experiment
        .target
        .as_ref()
        .filter(|target| {
            target.valid()
                && experiment.format == 2
                && experiment.pins.build.as_str() == target.build.to_string()
        })
        .ok_or("invalid targeted inputs")
}

impl Job {
    /// Constructs a job preserving its valid target's root seed and manifest digest.
    pub(crate) fn targeted(experiment: Experiment) -> Result<Self, &'static str> {
        let target = targeted_inputs(&experiment)?;
        Ok(Self {
            id: experiment.id(),
            seed: target.root,
            manifest_sha256: target.manifest,
            experiment,
        })
    }

    /// The job of `experiment` and the manifest bytes it runs, with the
    /// manifest keys in the listing's order `keys`, as [`Job::manifest`]
    /// spells them.
    ///
    /// # Errors
    ///
    /// [`ManifestError::TargetedInputs`] for a targeted experiment, and
    /// [`ManifestError::Unfilled`] when `keys` repeats a key or names one
    /// with no value, and [`ManifestError::Unlisted`] when `keys` leaves
    /// out a value key.
    pub fn derive(experiment: Experiment, keys: &[&str]) -> Result<(Self, String), ManifestError> {
        if experiment.target.is_some() || experiment.format != 1 {
            return Err(ManifestError::TargetedInputs);
        }
        let id = experiment.id();
        let seed = seed(&id);
        let manifest = manifest(&experiment, seed, keys)?;
        let job = Self {
            manifest_sha256: Digest::of(manifest.as_bytes()),
            experiment,
            id,
            seed,
        };
        Ok((job, manifest))
    }

    /// The manifest the worker runs for this job: one `key = value` line
    /// for each of `keys`, in that order. The values are the counts and
    /// the named keys `version`, `profile`, `root` (the job's seed), the
    /// four pins, `cpu = unrecorded` and `scenario = base`; a named key
    /// takes its named value even when a count shares its name. The worker
    /// records its CPU and never compares it, so `cpu = unrecorded` keeps
    /// the manifest independent of the host, and `scenario = base` runs the
    /// profile unreduced. Both lie outside the identity, and the stored
    /// manifest digest covers them, so every job keeps both values.
    ///
    /// # Errors
    ///
    /// As [`Job::derive`], and [`ManifestError::Digest`] when `keys`
    /// orders the lines into bytes whose SHA-256 is not the job's manifest
    /// digest.
    pub fn manifest(&self, keys: &[&str]) -> Result<String, ManifestError> {
        if self.experiment.target.is_some() {
            return Err(ManifestError::TargetedInputs);
        }
        let text = manifest(&self.experiment, self.seed, keys)?;
        if Digest::of(text.as_bytes()) == self.manifest_sha256 {
            Ok(text)
        } else {
            Err(ManifestError::Digest)
        }
    }

    pub fn experiment(&self) -> &Experiment {
        &self.experiment
    }

    pub fn id(&self) -> JobId {
        self.id
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }

    pub fn manifest_sha256(&self) -> Digest {
        self.manifest_sha256
    }
}

/// Why a listing's keys give no manifest for a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// Targeted jobs use their retained frozen worker manifest.
    TargetedInputs,
    /// The keys repeat this key or name it with no value to give it.
    Unfilled(String),
    /// The keys leave out these value keys, in byte order.
    Unlisted(Vec<String>),
    /// The manifest bytes hash to another digest than the job's.
    Digest,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetedInputs => {
                f.write_str("targeted jobs require their retained frozen worker manifest")
            }
            Self::Unfilled(key) => {
                write!(f, "the manifest key {key:?} is repeated or has no value")
            }
            Self::Unlisted(keys) => write!(f, "the manifest keys leave out {keys:?}"),
            Self::Digest => f.write_str("the manifest bytes differ from the job's digest"),
        }
    }
}

impl std::error::Error for ManifestError {}

fn manifest(experiment: &Experiment, root: u64, keys: &[&str]) -> Result<String, ManifestError> {
    let mut values: BTreeMap<&str, String> = experiment
        .counts
        .iter()
        .map(|(key, value)| (key.as_str(), value.to_string()))
        .collect();
    let root = root.to_string();
    let pins = &experiment.pins;
    for (key, value) in [
        ("version", experiment.manifest_version.as_str()),
        ("profile", experiment.profile.as_str()),
        ("root", root.as_str()),
        ("executable", pins.executable.as_str()),
        ("toolchain", pins.toolchain.as_str()),
        ("build", pins.build.as_str()),
        ("platform", pins.platform.as_str()),
        ("cpu", "unrecorded"),
        ("scenario", "base"),
    ] {
        values.insert(key, value.to_owned());
    }
    let mut text = String::new();
    for &key in keys {
        let value = values
            .remove(key)
            .ok_or_else(|| ManifestError::Unfilled(key.to_owned()))?;
        for part in [key, " = ", &value, "\n"] {
            text.push_str(part);
        }
    }
    if values.is_empty() {
        Ok(text)
    } else {
        Err(ManifestError::Unlisted(
            values.into_keys().map(str::to_owned).collect(),
        ))
    }
}
