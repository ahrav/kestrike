//! Calibration rows qualify capacity through bound attempts, replays and resources.

use super::super::calibration::Sealed;
use super::{Error, held, name};
use crate::record::{Calibration, CalibrationPlan, Capacity};
use crate::store::View;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// The calibration rows, the qualified capacities, and for each contract
/// whose stored capacity is held or fits no configuration, the reason it is
/// unqualified; a qualified capacity of the same contract takes precedence.
pub(super) struct Calibrations {
    pub(super) rows: Vec<Value>,
    pub(super) qualified: Vec<Capacity>,
    pub(super) refused: BTreeMap<crate::record::Digest, &'static str>,
}

/// Projects every calibration root and qualifies each stored capacity that
/// matches its calibrated evidence and fits `config`, the current
/// configuration, at its configured slots, which dispatch runs; an absent or held
/// configuration qualifies nothing.
pub(super) fn project(
    view: &View,
    config: Option<&crate::record::Configuration>,
    held_rows: &mut Vec<Value>,
) -> Result<Calibrations, Error> {
    let mut rows = BTreeMap::new();
    let mut eligibility =
        BTreeMap::<crate::record::Digest, super::super::calibration::Eligible>::new();
    let mut withheld = BTreeSet::new();
    let mut unattributed = false;
    if let Some(root) = super::root(view, "calibrations", held_rows)? {
        for entry in super::super::projection::entries(view, &root, "calibrations", held_rows)? {
            let scanned = (|| -> Result<_, Error> {
                let directory = view
                    .open_dir(&root, &entry)?
                    .ok_or_else(|| Error::Held("calibration vanished".into()))?;
                let entries = view.list(&directory, crate::scan_bound())?;
                Ok((directory, entries))
            })();
            if scanned
                .as_ref()
                .is_ok_and(|(_, entries)| entries.is_empty())
            {
                // A root retained before its plan was published qualifies
                // nothing and scopes nothing, as `eligible` reads it.
                let row = if crate::record::Digest::parse(entry.as_str()).is_some() {
                    json!({"id": entry.as_str(), "qualified": false, "verdict": "uncalibrated", "reason": "calibration plan is missing"})
                } else {
                    let error = Error::Held("calibration identity filename invalid".into());
                    let reason = error.to_string();
                    held(
                        held_rows,
                        &format!("calibrations/{}", entry.as_str()),
                        error,
                    )?;
                    json!({"id": entry.as_str(), "qualified": false, "verdict": "held", "reason": reason})
                };
                rows.insert(entry.as_str().to_owned(), row);
                continue;
            }
            let mut scope = None;
            let checked = (|| -> Result<Value, Error> {
                let (directory, _) = scanned?;
                let plan = view
                    .read_record::<CalibrationPlan>(&directory, &name("plan"))?
                    .ok_or_else(|| Error::Held("calibration plan missing".into()))?;
                view.barrier(plan.read())?;
                if plan.record().healthy.job().id().to_string() != entry.as_str() {
                    return Err(Error::Held("calibration plan identity differs".into()));
                }
                let contract = super::super::calibration::contract(plan.record())?;
                scope = Some(contract.key());
                let Some(record) = view.read_record::<Calibration>(&directory, &name("result"))?
                else {
                    super::super::calibration::partial(view, plan.record())?;
                    if super::super::calibration::partial_defect(view, plan.record())? {
                        withheld.insert(contract.key());
                    }
                    return Ok(
                        json!({"id": entry.as_str(), "contract": contract, "qualified": false, "verdict": "unsealed", "reason": "calibration result missing"}),
                    );
                };
                view.barrier(record.read())?;
                let record = record.record();
                match super::super::calibration::assess(view, &directory, plan.record(), record)? {
                    Sealed::Withheld => {
                        withheld.insert(contract.key());
                    }
                    Sealed::Ineligible => {}
                    Sealed::Eligible => {
                        eligibility
                            .entry(contract.key())
                            .or_default()
                            .insert(record.root, (record.clone(), plan.record().config.clone()));
                    }
                }
                Ok(
                    json!({"id": entry.as_str(), "contract": contract, "qualified": false, "verdict": record.verdict, "verified": record, "reason": if matches!(record.verdict, crate::record::CalibrationVerdict::Calibrated) { "capacity record required" } else { "calibration verdict withholds qualification" }}),
                )
            })();
            match checked {
                Ok(row) => {
                    rows.insert(entry.as_str().to_owned(), row);
                }
                Err(error) => {
                    if let Some(scope) = scope {
                        withheld.insert(scope);
                    } else {
                        unattributed = true;
                    }
                    let reason = error.to_string();
                    held(
                        held_rows,
                        &format!("calibrations/{}", entry.as_str()),
                        error,
                    )?;
                    rows.insert(entry.as_str().to_owned(), json!({"id": entry.as_str(), "qualified": false, "verdict": "held", "reason": reason}));
                }
            }
        }
    }
    let mut qualified = Vec::new();
    let mut refused = BTreeMap::new();
    unattributed |= held_rows.iter().any(|row| row["path"] == "calibrations");
    if let Some(root) = super::root(view, "capacity", held_rows)? {
        for scope in super::super::projection::entries(view, &root, "capacity", held_rows)? {
            let directory = match view.open_dir(&root, &scope) {
                Ok(Some(directory)) => directory,
                Ok(None) => continue,
                Err(error) => {
                    if let Some(key) = crate::record::Digest::parse(scope.as_str()) {
                        refused.entry(key).or_insert("capacity record is held");
                    }
                    held(
                        held_rows,
                        &format!("capacity/{}", scope.as_str()),
                        error.into(),
                    )?;
                    continue;
                }
            };
            let entries = match view.list(&directory, crate::scan_bound()) {
                Ok(entries) => entries,
                Err(error) => {
                    if let Some(key) = crate::record::Digest::parse(scope.as_str()) {
                        refused.entry(key).or_insert("capacity record is held");
                    }
                    held(
                        held_rows,
                        &format!("capacity/{}", scope.as_str()),
                        error.into(),
                    )?;
                    continue;
                }
            };
            for entry in entries {
                let checked = (|| -> Result<Capacity, Error> {
                    let capacity = view
                        .read_record::<Capacity>(&directory, &entry)?
                        .ok_or_else(|| Error::Held("capacity missing".into()))?;
                    view.barrier(capacity.read())?;
                    let capacity = capacity.record();
                    if capacity.contract().key().to_string() != scope.as_str()
                        || capacity.root().to_string() != entry.as_str()
                    {
                        return Err(Error::Held("capacity filename binding differs".into()));
                    }
                    let roots = eligibility.get(&capacity.contract().key()).ok_or_else(|| {
                        Error::Held("capacity lacks eligible calibration roots".into())
                    })?;
                    if unattributed {
                        return Err(Error::Held("calibration root scope is unknown".into()));
                    }
                    if withheld.contains(&capacity.contract().key()) {
                        return Err(Error::Held(
                            "scoped calibration history withholds capacity".into(),
                        ));
                    }
                    if !super::super::calibration::matches_capacity(capacity, roots) {
                        return Err(Error::Held(
                            "capacity differs from verified calibrated evidence".into(),
                        ));
                    }
                    Ok(capacity.clone())
                })();
                match checked {
                    Ok(capacity) => {
                        let fits = config.is_some_and(|config| {
                            capacity.resources().fits(config, config.value("slots"))
                        });
                        let reason = if fits {
                            "capacity matches calibrated evidence"
                        } else if config.is_some() {
                            "capacity measurements exceed configuration or are missing"
                        } else {
                            "configuration is unavailable"
                        };
                        if let Some(row) = rows.get_mut(&capacity.root().to_string()) {
                            row["capacity"] = json!(capacity);
                            row["reason"] = json!(reason);
                            if fits {
                                row["qualified"] = json!(true);
                            }
                        }
                        if fits {
                            qualified.push(capacity);
                        } else {
                            refused.insert(capacity.contract().key(), reason);
                        }
                    }
                    Err(error) => {
                        if let Some(key) = crate::record::Digest::parse(scope.as_str()) {
                            refused.entry(key).or_insert("capacity record is held");
                        }
                        held(
                            held_rows,
                            &format!("capacity/{}/{}", scope.as_str(), entry.as_str()),
                            error,
                        )?;
                    }
                }
            }
        }
    }
    Ok(Calibrations {
        rows: rows.into_values().collect(),
        qualified,
        refused,
    })
}
