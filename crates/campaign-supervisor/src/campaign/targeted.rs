//! Target admission freezes verified corpus inputs before publishing a campaign job.

use super::{Error, Request, admission, corpus, text};
use crate::protocol::Form;
use crate::record::{Admission, Digest, ForkForm, Job, Purpose, Target};
use crate::store::Store;
use std::path::Path;
use std::time::Duration;

pub(super) fn admit(
    store: &Store,
    archive: &Path,
    root: &Path,
    watchdog: Duration,
    request: &Request,
    asset: Digest,
    branch: Option<(u64, u64)>,
) -> Result<admission::Outcome, Error> {
    request.validate(Purpose::Campaign)?;
    if !request.counts.is_empty() {
        return Err(Error::Rejected(
            "targeted counts come from the asset".into(),
        ));
    }
    let branch = branch.map(|(suffixes, siblings)| ForkForm::Branch { siblings, suffixes });
    if branch
        .as_ref()
        .is_some_and(|form| form.children().is_none())
    {
        return Err(Error::Rejected(
            "targeted branch bounds exceed worker limits".into(),
        ));
    }
    let (asset, manifest, source, version) = corpus::target_input(store, asset)?;
    let probed = super::probe::probe(store, archive, root, watchdog)?;
    admission::campaign_profile(&probed.listing, &asset.profile, Purpose::Campaign)?;
    if probed.pins.build.as_str() != asset.probe.archive.to_string() {
        return Err(Error::Rejected(
            "archive differs from the target build".into(),
        ));
    }
    let values: std::collections::BTreeMap<_, _> = manifest
        .lines()
        .filter_map(|line| line.split_once(" = "))
        .collect();
    let mut counts = std::collections::BTreeMap::new();
    for key in &probed.listing.keys {
        if let Form::Count { min, max } = key.form {
            let value = values
                .get(key.name.as_str())
                .and_then(|v| crate::sim::input::count(v))
                .filter(|n| *n >= min && *n <= max)
                .ok_or_else(|| {
                    Error::Rejected(format!(
                        "target manifest count {} differs from listing",
                        key.name
                    ))
                })?;
            if key.name != "root" {
                counts.insert(text(&key.name)?, value);
            }
        }
    }
    let frozen = Request {
        profile: asset.profile.clone(),
        campaign: request.campaign.clone(),
        run: request.run,
        attempts: request.attempts,
        counts,
    };
    let (job, _) = super::freeze::freeze(&probed.listing, probed.pins, &frozen)?;
    let mut experiment = job.experiment().clone();
    let form = match branch {
        Some(form) => form,
        None => {
            let limits = crate::sim::input::Values::parse(&manifest, "target")
                .and_then(|v| v.suffix_limits())
                .map_err(Error::Rejected)?;
            ForkForm::Explore {
                advances: limits.advances,
                children: limits.children,
                depth: limits.depth,
                faults: limits.faults,
            }
        }
    };
    if form.children().is_none() {
        return Err(Error::Rejected(
            "target exploration exceeds the worker tree bound".into(),
        ));
    }
    let frozen_manifest = crate::sim::input::worker_manifest(&manifest);
    let target = Target {
        asset: asset.id(),
        boundary: asset.boundary,
        build: asset.probe.archive,
        bundle: asset.probe.bundle,
        bytes: asset.probe.bytes,
        decisions: asset.decisions,
        form,
        manifest: Digest::of(&frozen_manifest),
        milestone: asset.probe.milestone.clone(),
        prefix: asset.prefix,
        root: asset.root,
        semantic: asset.semantic,
    };
    experiment.format = 2;
    experiment.target = Some(target.clone());
    let job = Job::targeted(experiment).map_err(|e| Error::Rejected(e.into()))?;
    let record = Admission::targeted(
        text(
            probed
                .archive
                .to_str()
                .ok_or_else(|| Error::Rejected("archive path must be ASCII".into()))?,
        )?,
        job,
        version,
    )
    .map_err(|e| Error::Rejected(e.to_string()))?;
    // Publication keeps the admitted bundle rooted independently of corpus retirement.
    let manifest = std::str::from_utf8(&frozen_manifest).map_err(|e| Error::Held(e.to_string()))?;
    admission::publish(store, record, manifest, Some((&source, &target)))
}
