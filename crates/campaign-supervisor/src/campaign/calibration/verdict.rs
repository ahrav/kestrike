use super::{Error, text};
use crate::record::{Calibration, CalibrationEvidence, CalibrationVerdict, Class, Summarized};

fn facts(summary: &Summarized) -> (&crate::record::Digest, Option<u64>, &crate::record::Text) {
    (&summary.digest, summary.decisions, &summary.terminal)
}

pub(super) fn agrees(original: &CalibrationEvidence, replay: &CalibrationEvidence) -> bool {
    let Some(original_artifact) = &original.artifact else {
        return false;
    };
    let Some(original_summary) = &original_artifact.summary else {
        return false;
    };
    let Some(artifact) = &replay.artifact else {
        return false;
    };
    let Some(comparison) = &artifact.comparison else {
        return false;
    };
    let (Some(replay_original), Some(observed)) = (&comparison.original, &comparison.observed)
    else {
        return false;
    };
    original.finished.class == Class::Pass
        && original.finished.exit == Some(0)
        && original_summary.counts
        && original_summary.decisions.is_some_and(|count| count > 0)
        && !original_summary.terminal.as_str().is_empty()
        && original_artifact.bundle.is_some()
        && original_artifact.archive.is_some()
        && replay.finished.class == Class::Pass
        && replay.finished.exit == Some(0)
        && artifact.archive == original_artifact.archive
        && artifact.manifest == original_artifact.manifest
        && artifact.bundle == original_artifact.bundle
        && artifact.command.as_str() == "replay"
        && comparison.status.as_str() == "reproduced"
        && comparison.divergence.is_none()
        && facts(replay_original) == facts(original_summary)
        && facts(observed) == facts(original_summary)
        && observed.counts
}

pub(super) fn product_class(class: Class) -> bool {
    matches!(
        class,
        Class::Violation | Class::EngineFailure | Class::Unsuccessful | Class::Disagreement
    )
}

pub(super) fn null_original(evidence: &CalibrationEvidence) -> bool {
    evidence.finished.class == Class::Pass
        && evidence
            .artifact
            .as_ref()
            .and_then(|artifact| artifact.summary.as_ref())
            .is_none_or(|summary| {
                !summary.counts
                    || summary.decisions.is_none_or(|count| count == 0)
                    || summary.terminal.as_str().is_empty()
            })
}

pub(super) fn replay_defect(original: Option<&Summarized>, replay: &CalibrationEvidence) -> bool {
    let comparison = replay
        .artifact
        .as_ref()
        .and_then(|artifact| artifact.comparison.as_ref());
    (product_class(replay.finished.class) || replay.product.is_some())
        || original.is_some_and(|original| {
            comparison.is_some_and(|comparison| {
                comparison
                    .original
                    .as_ref()
                    .is_some_and(|summary| facts(summary) != facts(original))
                    || comparison
                        .observed
                        .as_ref()
                        .is_some_and(|summary| facts(summary) != facts(original))
                    || comparison.status.as_str() == "diverged"
                    || comparison.divergence.is_some()
            })
        })
}

pub(in crate::campaign) fn product_defects(record: &Calibration) -> Vec<crate::record::Text> {
    let mut defects = Vec::new();
    if product_class(record.lost.class) {
        defects.push(
            text("lost attempt recorded a product failure or disagreement")
                .expect("defect reason is ASCII"),
        );
    }
    if product_class(record.healthy.finished.class) || record.healthy.product.is_some() {
        defects.push(
            text("healthy control recorded a product failure or disagreement")
                .expect("defect reason is ASCII"),
        );
    }
    let original = record
        .healthy
        .artifact
        .as_ref()
        .and_then(|artifact| artifact.summary.as_ref());
    if null_original(&record.healthy) {
        defects.push(
            text("original counting summary has a missing or non-counting field")
                .expect("defect reason is ASCII"),
        );
    }
    for (profile, evidence) in &record.controls {
        if evidence.finished.class == Class::Disagreement
            || !record.detected.contains(profile)
                && (product_class(evidence.finished.class)
                    || evidence.product.is_some()
                    || evidence.finished.class == Class::Pass)
        {
            defects.push(
                text(&format!(
                    "fault control {} recorded an unintended product outcome",
                    profile.as_str()
                ))
                .expect("control profile is ASCII"),
            );
        }
    }
    for (index, replay) in record.replays.iter().enumerate() {
        if replay_defect(original, replay) {
            defects.push(
                text(&format!(
                    "fresh replay {} recorded a product disagreement",
                    index + 1
                ))
                .expect("defect reason is ASCII"),
            );
        }
    }
    defects
}

pub(super) fn finish(record: &mut Calibration) -> Result<(), Error> {
    if record.healthy.finished.class != Class::Pass {
        record.reasons.push(text(&format!(
            "healthy control is {}",
            record.healthy.finished.class.name()
        ))?);
    }
    if record.lost.class != Class::Interrupted
        || record.healthy.finished.attempt == record.lost.attempt
    {
        record.missing.push(text(
            "lost attempt was not reconciled as interrupted before a fresh healthy attempt",
        )?);
    }
    if record.replays.len() != 2 {
        record
            .missing
            .push(text("two fresh replay checks are missing")?);
    }
    if record.replays.len() == 2
        && record.replays[0].finished.attempt == record.replays[1].finished.attempt
    {
        record.reasons.push(text("fresh replay identity repeats")?);
    }
    for (index, replay) in record.replays.iter().enumerate() {
        if !agrees(&record.healthy, replay) {
            record.reasons.push(text(&format!(
                "fresh replay {} disagrees with the original or was refused",
                index + 1
            ))?);
        }
    }
    record.defects.extend(product_defects(record));
    record.verdict = if !record.reasons.is_empty() || !record.defects.is_empty() {
        CalibrationVerdict::Refused
    } else if !record.missing.is_empty() {
        CalibrationVerdict::Uncalibrated
    } else {
        CalibrationVerdict::Calibrated
    };
    Ok(())
}

pub(super) fn complete(record: &Calibration) -> bool {
    record.verdict == CalibrationVerdict::Calibrated
        && record.reasons.is_empty()
        && record.defects.is_empty()
        && record.missing.is_empty()
        && record.lost.class == Class::Interrupted
        && record.healthy.finished.attempt != record.lost.attempt
        && record.replays.len() == 2
        && record
            .replays
            .iter()
            .all(|replay| agrees(&record.healthy, replay))
        && record.replays[0].finished.attempt != record.replays[1].finished.attempt
}
