//! A sealed calibration result bears on its contract's capacity only after
//! every stored snapshot binds to the verified attempt evidence it names.

use super::{Error, contract, controls, execution, name, replay, text, verdict};
use crate::attempt::Completed;
use crate::record::{Admission, Calibration, CalibrationEvidence, CalibrationPlan, ResourceBounds};
use crate::store::{Dir, ReadStore};

/// How one sealed calibration root bears on its contract's capacity.
pub(in crate::campaign) enum Sealed {
    /// The result, a retained finding, a launched replay or a control
    /// attempt records a product defect.
    Withheld,
    /// The bound result passes product-defect screening but fails at least
    /// one capacity eligibility requirement.
    Ineligible,
    /// The bound result passes product-defect screening and every capacity
    /// eligibility requirement.
    Eligible,
}

/// The result must name the plan's root and contract, and its healthy, lost,
/// control and replay snapshots must equal the finished, bound and measured
/// evidence of the attempts they name. Every launched replay on disk must
/// appear among the sealed replays of an eligible result.
///
/// # Errors
///
/// [`Error::Held`] when the result binding, an attempt's evidence or a
/// launched replay differs from the record, and when a job, attempt, plan or
/// resources record a snapshot depends on is absent; store and record errors
/// from the reads.
pub(in crate::campaign) fn assess(
    store: &impl ReadStore,
    directory: &Dir,
    plan: &CalibrationPlan,
    result: &Calibration,
) -> Result<Sealed, Error> {
    if result.root != plan.healthy.job().id().digest() || result.contract != contract(plan)? {
        return Err(Error::Held("calibration result binding differs".into()));
    }
    bound(store, directory, plan, result)?;
    let launched = replay::partial(store, plan)?;
    if !result.defects.is_empty()
        || !verdict::product_defects(result).is_empty()
        || history_defect(store, plan, result, &launched)?
    {
        return Ok(Sealed::Withheld);
    }
    if !eligible_record(plan, result) {
        return Ok(Sealed::Ineligible);
    }
    if launched.iter().any(|replay| {
        !result.replays.iter().any(|stored| {
            stored.finished == replay.finished
                && stored.artifact == replay.artifact
                && stored.product == replay.product
        })
    }) {
        return Err(Error::Held("sealed calibration replay differs".into()));
    }
    Ok(Sealed::Eligible)
}

fn eligible_record(plan: &CalibrationPlan, result: &Calibration) -> bool {
    plan.deduplicated
        && verdict::complete(result)
        && plan.missing.is_empty()
        && result.healthy.job == plan.healthy.job().id().digest()
        && result.healthy.finished.attempt.as_str() == format!("{}-0002", result.root)
        && result.lost.attempt.as_str() == format!("{}-0001", result.root)
        && result.detected.iter().eq(plan.controls.keys())
        && result.controls.keys().eq(plan.controls.keys())
        && plan.controls.values().all(|control| {
            control.job().experiment().calibration_scope
                == Some(execution::control_scope(&result.contract, &plan.config))
        })
        && controls::declared(result.contract.profile.as_str())
            .iter()
            .all(|control| {
                result
                    .controls
                    .contains_key(&text(control.profile).expect("control profile is ASCII"))
            })
}

/// Reports a product defect that a retained finding, a sealed or launched
/// replay, or a control attempt records.
fn history_defect(
    store: &impl ReadStore,
    plan: &CalibrationPlan,
    result: &Calibration,
    launched: &[CalibrationEvidence],
) -> Result<bool, Error> {
    let original = result
        .healthy
        .artifact
        .as_ref()
        .and_then(|artifact| artifact.summary.as_ref());
    if execution::retained_product(store, &result.healthy.finished)?
        || execution::retained_product(store, &result.lost)?
        || result
            .replays
            .iter()
            .chain(launched)
            .any(|replay| verdict::replay_defect(original, replay))
    {
        return Ok(true);
    }
    for control in plan.controls.values() {
        if execution::control_disagreed(store, control)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Verifies that every snapshot of `result` equals the attempt evidence it names.
fn bound(
    store: &impl ReadStore,
    directory: &Dir,
    plan: &CalibrationPlan,
    result: &Calibration,
) -> Result<(), Error> {
    attempt(store, &plan.healthy, &result.healthy)?;
    for (profile, observed) in &result.controls {
        let admission = plan
            .controls
            .get(profile)
            .ok_or_else(|| Error::Held("calibration control undeclared".into()))?;
        attempt(store, admission, observed)?;
    }
    let (root, _) = crate::attempt::history(store, &plan.healthy)?
        .ok_or_else(|| Error::Held("lost attempt missing".into()))?;
    let (_, _, lost) = crate::attempt::completed_at(store, &plan.healthy, &root, 1)?;
    if lost.finished().record() != &result.lost {
        return Err(Error::Held("lost attempt snapshot differs".into()));
    }
    for (index, observed) in result.replays.iter().enumerate() {
        let found = store
            .read_record::<CalibrationPlan>(directory, &name("plan"))?
            .ok_or_else(|| Error::Held("calibration plan missing".into()))?;
        let (directory, done) = replay::verified_completion(store, found, index as u64 + 1)?;
        if observed.job != result.root {
            return Err(Error::Held("calibration replay job differs".into()));
        }
        evidence(store, &directory, &done, observed)?;
    }
    Ok(())
}

fn attempt(
    store: &impl ReadStore,
    admission: &Admission,
    expected: &CalibrationEvidence,
) -> Result<(), Error> {
    let jobs = crate::layout::jobs(store, &admission.job().id().to_string())?
        .ok_or_else(|| Error::Held("calibration jobs missing".into()))?;
    let verified =
        super::super::show::verified_job(store, &jobs, &admission.job().id().to_string())?;
    if verified.record() != admission || expected.job != admission.job().id().digest() {
        return Err(Error::Held("calibration admission differs".into()));
    }
    let (root, maximum) = crate::attempt::history(store, admission)?
        .ok_or_else(|| Error::Held("calibration attempts missing".into()))?;
    let number = expected
        .finished
        .attempt
        .as_str()
        .rsplit_once('-')
        .and_then(|(_, n)| n.parse::<u64>().ok())
        .filter(|n| *n > 0 && *n <= maximum)
        .ok_or_else(|| Error::Held("calibration attempt number invalid".into()))?;
    let (directory, _, done) = crate::attempt::completed_at(store, admission, &root, number)?;
    evidence(store, &directory, &done, expected)
}

fn evidence(
    store: &impl ReadStore,
    directory: &Dir,
    completed: &Completed,
    expected: &CalibrationEvidence,
) -> Result<(), Error> {
    if completed.finished().record() != &expected.finished
        || completed.bound().map(|b| b.artifact()) != expected.artifact.as_ref()
    {
        return Err(Error::Held(
            "calibration snapshot differs from bound evidence".into(),
        ));
    }
    let resources = store
        .read_record::<ResourceBounds>(directory, &name("resources"))?
        .ok_or_else(|| Error::Held("calibration resources missing".into()))?;
    store.barrier(resources.read())?;
    if resources.record() != &expected.resources
        || execution::measured(completed, resources.record().wall_us) != *resources.record()
    {
        return Err(Error::Held("calibration resource binding differs".into()));
    }
    Ok(())
}
