pub(in crate::campaign) mod controls;
mod execution;
mod replay;
mod sealed;
mod status;
pub(in crate::campaign) mod uncaught;
mod verdict;

#[cfg(test)]
#[path = "calibration_tests.rs"]
pub(crate) mod tests;

use super::{Error, name, text};
use crate::record::{Calibration, CalibrationContract, CalibrationPlan, Capacity, Digest};
use crate::store::Dir;
#[cfg(test)]
use crate::store::Store;

pub(super) use execution::execute;
pub(in crate::campaign) use execution::{measured, partial_defect};
pub(in crate::campaign) use replay::partial;
pub(crate) use replay::reconcile;
pub(in crate::campaign) use sealed::{Sealed, assess};
pub(in crate::campaign) use status::status;

pub(in crate::campaign) type Eligible =
    std::collections::BTreeMap<Digest, (Calibration, crate::record::Configuration)>;

/// The calibration results of the contract `scoped` a capacity record may
/// cite: each sealed, eligible result by its root, with the configuration
/// its plan ran under. The set is empty when a plan's healthy job differs
/// from its directory's name, when an unsealed root of the contract holds
/// a product defect, or when one result withholds the contract. Tests
/// compare this reading with the report's projection.
#[cfg(test)]
pub(in crate::campaign) fn eligible(
    store: &impl crate::store::ReadStore,
    scoped: &CalibrationContract,
) -> Result<Eligible, Error> {
    let Some(roots) = store.open_dir(store.root(), &name("calibrations"))? else {
        return Ok(std::collections::BTreeMap::new());
    };
    let mut eligible = std::collections::BTreeMap::new();
    for entry in store.list(&roots, crate::scan_bound())? {
        let root = store
            .open_dir(&roots, &entry)?
            .ok_or_else(|| Error::Held("calibration root vanished".into()))?;
        let Some(plan) = store.read_record::<CalibrationPlan>(&root, &name("plan"))? else {
            if store.list(&root, crate::scan_bound())?.is_empty() {
                continue;
            }
            return Err(Error::Held("calibration plan missing".into()));
        };
        store.barrier(plan.read())?;
        if plan.record().healthy.job().id().to_string() != entry.as_str() {
            return Ok(std::collections::BTreeMap::new());
        }
        if contract(plan.record())? != *scoped {
            continue;
        }
        let Some(result) = store.read_record::<Calibration>(&root, &name("result"))? else {
            if execution::partial_defect(store, plan.record())? {
                return Ok(std::collections::BTreeMap::new());
            }
            continue;
        };
        store.barrier(result.read())?;
        let result = result.record();
        match assess(store, &root, plan.record(), result)? {
            Sealed::Withheld => return Ok(std::collections::BTreeMap::new()),
            Sealed::Ineligible => continue,
            Sealed::Eligible => {}
        }
        eligible.insert(result.root, (result.clone(), plan.record().config.clone()));
    }
    Ok(eligible)
}

pub(in crate::campaign) fn matches_capacity(capacity: &Capacity, roots: &Eligible) -> bool {
    roots.get(&capacity.root()).is_some_and(|(record, budget)| {
        record.healthy.resources == *capacity.resources()
            && *budget == *capacity.budget()
            && Digest::of(&serde_json::to_vec(record).expect("calibration encodes"))
                == capacity.evidence()
            && capacity
                .resources()
                .fits(capacity.budget(), capacity.slots())
    })
}

#[cfg(test)]
fn qualify(store: &Store, capacity: &Capacity) -> Result<bool, Error> {
    Ok(matches_capacity(
        capacity,
        &eligible(store, capacity.contract())?,
    ))
}

fn directory(
    store: &impl crate::store::ReadStore,
    root: crate::record::Digest,
) -> Result<Dir, Error> {
    let parent = store
        .open_dir(store.root(), &name("calibrations"))?
        .ok_or_else(|| Error::Held("calibration roots missing".into()))?;
    store
        .open_dir(&parent, &name(&root.to_string()))?
        .ok_or_else(|| Error::Held("calibration root missing".into()))
}

pub(in crate::campaign) fn contract(plan: &CalibrationPlan) -> Result<CalibrationContract, Error> {
    let experiment = plan.healthy.job().experiment();
    Ok(CalibrationContract {
        build: crate::record::Digest::parse(experiment.pins.build.as_str())
            .ok_or_else(|| Error::Held("calibration build digest invalid".into()))?,
        counts: experiment.counts.clone(),
        profile: experiment.profile.clone(),
    })
}
