//! Triage history projects bound steps and regression candidates.

use super::{Error, Step, history, name};
use crate::record::RegressionCandidate;
use crate::store::View;
use serde_json::{Value, json};

pub(in crate::campaign) fn project(
    view: &View,
    held: &mut Vec<Value>,
) -> Result<(Vec<Value>, Vec<Value>), Error> {
    let mut rows = Vec::new();
    let mut candidates = Vec::new();
    let Some(root) = super::super::projection::root(view, "triage", held)? else {
        return Ok((rows, candidates));
    };
    for entry in super::super::projection::entries(view, &root, "triage", held)? {
        let id = entry.as_str();
        let checked = (|| -> Result<(), Error> {
            let Some(steps) = history::root(view, id)? else {
                return unstepped(view, id, &mut rows);
            };
            let numbers = history::numbers(view, &steps, id)?;
            if numbers.is_empty() {
                return unstepped(view, id, &mut rows);
            }
            let newest = numbers.last().copied();
            for number in numbers {
                let checked = (|| -> Result<(), Error> {
                    let step = history::pending(view, &steps, history::finding(view, id)?, number)?;
                    let launched = view
                        .read_record::<crate::record::Intent>(&step.directory, &name("intent"))?
                        .is_some();
                    let bound_inputs = |required: bool| -> Result<(), Error> {
                        match view.read_record::<crate::record::ReplayDependencies>(
                            &step.directory,
                            &name("dependencies"),
                        )? {
                            Some(_) => step.dependencies(view).map(drop),
                            None if required => Err(Error::Held(
                                "launched step lacks input commit marker".into(),
                            )),
                            None => Ok(()),
                        }
                    };
                    if view
                        .read_record::<crate::record::Finished>(&step.directory, &name("finished"))?
                        .is_none()
                    {
                        if Some(number) != newest {
                            return Err(Error::Held(
                                "unfinished step precedes a later step".into(),
                            ));
                        }
                        bound_inputs(launched)?;
                        for later in ["result", "candidate"] {
                            if view.open_file(&step.directory, &name(later))?.is_some() {
                                return Err(Error::Held(format!(
                                    "unfinished step holds a {later} record"
                                )));
                            }
                        }
                        if launched
                            && crate::custody::charged(view, &step.directory, step.identity())?
                                .is_none()
                        {
                            return Err(Error::Held("unfinished step lacks reservation".into()));
                        }
                        crate::attempt::pending_started(
                            view,
                            &step.directory,
                            &step.record.record().attempt,
                        )?;
                        rows.push(json!({"finding": id, "number": number, "step": step.record.record(), "state": "inconclusive", "reason": "step is unfinished"}));
                        return Ok(());
                    }
                    let completed = crate::attempt::read_completed(
                        view,
                        &step.directory,
                        &step.record.record().attempt,
                        step.record.record().kind.command(),
                    )?;
                    if Some(number) == newest
                        && view
                            .read_record::<crate::record::TriageResult>(
                                &step.directory,
                                &name("result"),
                            )?
                            .is_none()
                    {
                        bound_inputs(true)?;
                        if view
                            .open_file(&step.directory, &name("candidate"))?
                            .is_some()
                        {
                            return Err(Error::Held(
                                "unpublished step holds a candidate record".into(),
                            ));
                        }
                        rows.push(json!({"finding": id, "number": number, "step": step.record.record(), "state": "inconclusive", "reason": "step result is unpublished"}));
                        return Ok(());
                    }
                    let result = step.verified_result(view, &completed)?;
                    let candidate = candidate(view, &step, &result, &completed)?;
                    rows.push(json!({"finding": id, "number": number, "step": step.record.record(), "result": result, "candidate_state": if candidate.is_some() { "published" } else if matches!(result.status, Some(crate::record::ReplayStatus::Reproduced | crate::record::ReplayStatus::Reduced)) { "pending" } else { "unneeded" }}));
                    if let Some(candidate) = candidate {
                        candidates.push(json!(candidate));
                    }
                    Ok(())
                })();
                if let Err(error) = checked {
                    let reason = error.to_string();
                    super::super::projection::held(
                        held,
                        &format!("triage/{id}/steps/{number:04}"),
                        error,
                    )?;
                    rows.push(
                        json!({"finding": id, "number": number, "state": "held", "reason": reason}),
                    );
                }
            }
            Ok(())
        })();
        if let Err(error) = checked {
            super::super::projection::held(held, &format!("triage/{id}"), error)?;
        }
    }
    Ok((rows, candidates))
}

/// A triage root whose finding exists and whose step history is empty is
/// the state a launch leaves between creating the root and its first step.
fn unstepped(view: &View, id: &str, rows: &mut Vec<Value>) -> Result<(), Error> {
    history::finding(view, id)?;
    rows.push(
        json!({"finding": id, "state": "inconclusive", "reason": "triage root holds no step"}),
    );
    Ok(())
}

fn candidate(
    view: &View,
    step: &Step,
    result: &crate::record::TriageResult,
    completed: &crate::attempt::Completed,
) -> Result<Option<RegressionCandidate>, Error> {
    let Some(found) =
        view.read_record::<RegressionCandidate>(&step.directory, &name("candidate"))?
    else {
        return Ok(None);
    };
    super::candidate::verify(view, step, result, completed)?;
    view.barrier(found.read())?;
    Ok(Some(found.record().clone()))
}
