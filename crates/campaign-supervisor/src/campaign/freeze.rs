use std::collections::BTreeMap;

use super::{Error, text};
use crate::protocol::{Form, Listing};
use crate::record::{Experiment, Job, Pins, Purpose, Text};

/// The attempt limit of a job admitted without `--attempts`. The limit is
/// part of the job's identity, so a sweep freezes its runs at this value
/// to draw the seeds `admit` derives for them.
pub(crate) const ATTEMPTS: u64 = 3;

pub struct Request {
    pub profile: Text,
    pub campaign: Text,
    pub run: u64,
    pub attempts: u64,
    pub counts: BTreeMap<Text, u64>,
}

impl Request {
    pub(crate) fn validate(&self, purpose: Purpose) -> Result<(), Error> {
        if self.attempts == 0
            || self.attempts > crate::scan_bound() as u64
            || self.campaign.as_str().is_empty()
            || self.campaign.as_str().trim() != self.campaign.as_str()
            || self.profile.as_str().is_empty()
            || !purpose.matches_campaign(&self.campaign)
            || self.counts.keys().any(|key| key.as_str() == "root")
        {
            return Err(Error::Rejected(
                "invalid campaign, profile, attempts or root override".into(),
            ));
        }
        Ok(())
    }
}

pub(super) fn freeze(
    listing: &Listing,
    pins: Pins,
    request: &Request,
) -> Result<(Job, String), Error> {
    freeze_scoped(listing, pins, request, None)
}

pub(super) fn freeze_scoped(
    listing: &Listing,
    pins: Pins,
    request: &Request,
    calibration_scope: Option<crate::record::Digest>,
) -> Result<(Job, String), Error> {
    if listing.manifest != 2 || listing.constraints != CONSTRAINTS {
        return Err(Error::Rejected(
            "unsupported manifest or recorder constraints".into(),
        ));
    }
    let profile = listing
        .profile(request.profile.as_str())
        .ok_or_else(|| Error::Rejected("profile has no listed held bounds".into()))?;
    if profile.support != "implemented" || profile.campaign != "unqualified" {
        return Err(Error::Rejected(
            "profile must be implemented and unqualified".into(),
        ));
    }
    let counts = resolved_counts(listing, &profile.held, &request.counts)?;
    let cluster = listing.cluster(&profile.name);
    let field = |key: &str| -> Result<Option<Text>, Error> {
        cluster
            .map(|cluster| {
                cluster
                    .field(key)
                    .ok_or_else(|| Error::Rejected(format!("cluster requires {key}")))
                    .and_then(text)
            })
            .transpose()
    };
    let minima = field("minima")?;
    if let Some(minima) = &minima {
        super::minima::parse(minima)
            .map_err(|error| Error::Rejected(format!("invalid minimum declaration: {error}")))?;
    }
    let experiment = Experiment {
        target: None,
        calibration_scope,
        attempts: request.attempts,
        campaign: request.campaign.clone(),
        capabilities: text(&listing.capabilities.to_string())?,
        class: Some(text(profile.class.name())?),
        counts,
        format: 1,
        generator: field("generator")?,
        manifest_version: text(&listing.manifest.to_string())?,
        minima,
        pins,
        profile: request.profile.clone(),
        run: request.run,
    };
    let keys: Vec<_> = listing.keys.iter().map(|key| key.name.as_str()).collect();
    let (job, manifest) =
        Job::derive(experiment, &keys).map_err(|e| Error::Rejected(e.to_string()))?;
    for (key, line) in listing.keys.iter().zip(manifest.lines()) {
        let value = line.split_once(" = ").expect("derived manifest line").1;
        let fits = match key.form {
            Form::Text => !value.is_empty() && value.trim() == value,
            Form::Sha256 => crate::record::Digest::parse(value).is_some(),
            Form::Version(v) => value == v.to_string(),
            Form::Count { min, max } => value
                .parse::<u64>()
                .is_ok_and(|n| n >= min && n <= max && n > 0),
        };
        if !fits {
            return Err(Error::Rejected(format!(
                "{} fails its listed form",
                key.name
            )));
        }
    }
    recorder_fits(&job, &manifest)?;
    Ok((job, manifest))
}

/// Each count key of `listing` but `root`, valued for a profile that holds
/// `held`: its override, or else its default raised to the listing's and
/// the profile's least value. Refuses an override of an unlisted count, a
/// least value of 0, and a value below the least or above the listed
/// maximum.
pub(super) fn resolved_counts(
    listing: &Listing,
    held: &[(String, u64)],
    overrides: &BTreeMap<Text, u64>,
) -> Result<BTreeMap<Text, u64>, Error> {
    for key in overrides.keys() {
        if !listing
            .keys
            .iter()
            .any(|k| k.name == key.as_str() && matches!(k.form, Form::Count { .. }))
        {
            return Err(Error::Rejected(format!("unlisted count {}", key.as_str())));
        }
    }
    let mut counts = BTreeMap::new();
    for key in &listing.keys {
        if let Form::Count { min, max } = key.form {
            if key.name == "root" {
                continue;
            }
            let least = min.max(
                held.iter()
                    .find(|(name, _)| name == &key.name)
                    .map_or(1, |(_, n)| *n),
            );
            let value = overrides
                .get(&text(&key.name)?)
                .copied()
                .unwrap_or(default_count(&key.name).max(least));
            if least == 0 || value < least || value > max {
                return Err(Error::Rejected(format!(
                    "{} lies outside {least}..={max}",
                    key.name
                )));
            }
            counts.insert(text(&key.name)?, value);
        }
    }
    Ok(counts)
}

const RECORD_BYTES: u64 = 48;
const FIELD_BYTES: u128 = 43;
const CONSTRAINTS: [&str; 2] = [
    "min(records, bytes/48) >= ring+6 (+1 when every=1)",
    "min(records, bytes/48) >= c + c/every + ring+5, c = ceil(canonical bytes/43) <= 65536",
];

fn recorder_fits(job: &Job, manifest: &str) -> Result<(), Error> {
    let count = |key: &str| {
        job.experiment()
            .counts
            .get(&text(key).expect("count key is ASCII"))
            .copied()
            .ok_or_else(|| Error::Rejected(format!("missing recorder count {key}")))
    };
    let room = count("records")?.min(count("bytes")? / RECORD_BYTES);
    let ring = count("ring")?;
    let every = count("every")?;
    let chunks = manifest
        .lines()
        .filter(|line| !line.starts_with("cpu = "))
        .map(|line| line.len() as u128 + 1)
        .sum::<u128>()
        .div_ceil(FIELD_BYTES);
    if chunks > 65_536
        || count("pending")?.checked_mul(RECORD_BYTES).is_none()
        || u128::from(room) < u128::from(ring) + 6 + u128::from(every == 1)
        || u128::from(room) < chunks + chunks / u128::from(every) + u128::from(ring) + 5
    {
        return Err(Error::Rejected(
            "recorder counts cannot hold the manifest".into(),
        ));
    }
    Ok(())
}

fn default_count(key: &str) -> u64 {
    match key {
        "turns" => 20000,
        "same_time" => 400,
        "no_progress" => 5000,
        "actors" => 16,
        "disk_depth" => 8,
        "scripted" => 32,
        "link_copy_bytes" => 1048576,
        "tx_slots" => 1024,
        "rules" => 32,
        "taps" => 8,
        "captures" | "registry" => 4096,
        "audit_records" | "source_bytes" => 65536,
        "upload_attempts" | "suffix_depth" => 2,
        "suffix_children" => 3,
        "suffix_faults" => 12,
        "suffix_advances" => 16,
        "pending" | "ring" => 64,
        "records" => 1000000,
        "bytes" => 48000000,
        "every" => 256,
        "watchdog" => 600,
        _ => 1,
    }
}
