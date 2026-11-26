//! Settlement retains findings and publishes the selected pin and result.
//! Pin and result publications check the current attempt maximum.

use super::lifecycle::{completed_at, frozen_manifest, held_read, history, prior_finish};
use super::{Attempt, Completed, Error, name};
use crate::record::{Admission, Class, Finished, JobResult, Pin, Record, Verified};
use crate::store::{Dir, Name, Store};

/// Settlement requires a verified frozen manifest and complete attempt history.
/// Capture completes before settlement returns. Matching durable markers let
/// historical attempts contribute their verified finishes. Missing markers
/// backfill newest-first. The current attempt and selected failure are revalidated.
/// Pin and result publications recheck the current attempt maximum.
/// Violation and EngineFailure select the lowest-numbered failure for the pin.
/// Retained records must match the selected outcome and pass their barriers.
/// Returns `None` when the current outcome can retry within the frozen limit,
/// the history has no Violation or EngineFailure, and no result is retained.
/// Existing results are verified and returned. A retained pin selects its result.
/// The completion must name the current publisher and equal its stored finish.
/// Settlement publishes a failure pin before its matching job result.
/// Missing required records, inconsistent retained values and stale completions
/// return errors. Store errors abort settlement.
///
/// ```compile_fail,E0382
/// use campaign_supervisor::{attempt::{settle, Completed}, record::{Admission, Verified}, store::Store};
/// fn twice(store: &Store, job: Verified<Admission>, completed: Completed) {
///     let _ = settle(store, job, completed);
///     let _ = completed.finished();
/// }
/// ```
pub fn settle(
    store: &Store,
    job: Verified<Admission>,
    completed: Completed,
) -> Result<Option<Verified<JobResult>>, Error> {
    settle_pinning(store, job, completed).map(|settled| settled.result)
}

/// The verified result and lengths of the job records this settlement published.
pub(crate) struct Settlement {
    pub result: Option<Verified<JobResult>>,
    pub pin_bytes: Option<u64>,
    pub result_bytes: Option<u64>,
}

/// [`settle`], with the lengths of the pin and result this call published.
pub(crate) fn settle_pinning(
    store: &Store,
    job: Verified<Admission>,
    completed: Completed,
) -> Result<Settlement, Error> {
    let id = job.record().job().id();
    let jobs = crate::layout::jobs(store, &id.to_string())
        .map_err(|error| held_read(error, "jobs unreadable"))?
        .ok_or(Error::Held("jobs vanished"))?;
    let fresh = store
        .read_record::<Admission>(&jobs, &name(&format!("{id}.json")))?
        .ok_or(Error::Held("admission vanished"))?;
    if fresh.record() != job.record() {
        return Err(Error::Held("admission differs from publisher"));
    }
    let admission = fresh.record().clone();
    frozen_manifest(store, &jobs, &admission)?;
    let publisher = Attempt::current(store, fresh)?.ok_or(Error::Held("job has no attempts"))?;
    publisher.current_token(store)?;
    if completed.finished().record().attempt != *publisher.identity() {
        return Err(Error::Held("completion belongs to another publisher"));
    }
    let (root, maximum) =
        history(store, &admission)?.ok_or(Error::Held("attempt history vanished"))?;
    if maximum == 0 {
        return Err(Error::Held("empty attempt history"));
    }
    let result_at = |number, finished: &Verified<Finished>| JobResult {
        attempt: number,
        finished: finished.record().clone(),
        job: admission.job().id().digest(),
        manifest: admission.job().manifest_sha256(),
    };
    let (directory, record, found) = completed_at(store, &admission, &root, maximum)?;
    if found.finished().record() != completed.finished().record() {
        return Err(Error::Held("completion differs from finished record"));
    }
    let current = result_at(maximum, found.finished());
    let current_has_finding = found.has_finding();
    if current_has_finding {
        super::capture::capture(store, &admission, &found, &directory, &record, None)?;
    }
    let mut outcomes = Vec::new();
    let mut missing = Vec::new();
    for number in (1..maximum).rev() {
        let (directory, finish) = prior_finish(store, &admission, &root, number)?;
        let class = finish.record().class;
        outcomes.push((number, class));
        if super::capture::recorded(store, &directory, &finish)?.is_none() {
            missing.push(number);
        }
    }
    outcomes.reverse();
    outcomes.push((maximum, current.finished.class));
    let failed = selected_failure(outcomes)?.filter(|number| *number < maximum);
    let selected_failure = failed
        .map(|number| completed_at(store, &admission, &root, number))
        .transpose()?;
    let first_failure = match &selected_failure {
        Some((_, _, failure)) => Some(Pin {
            result: result_at(failed.expect("failure has a number"), failure.finished()),
        }),
        None => pins(current.finished.class).then(|| Pin {
            result: current.clone(),
        }),
    };
    let pin_name = name(&format!("{id}{}", Pin::SUFFIX));
    let result_name = name(&format!("{id}{}", JobResult::SUFFIX));
    let pin = store.read_record::<Pin>(&jobs, &pin_name)?;
    let result = store.read_record::<JobResult>(&jobs, &result_name)?;
    if let Some(pin) = &pin {
        if Some(pin.record()) != first_failure.as_ref() {
            return Err(Error::Held("retained pin differs from failure history"));
        }
        store.barrier(pin.read())?;
    }
    let selected = first_failure.as_ref().map_or(&current, |pin| &pin.result);
    if let Some(result) = &result {
        if result.record() != selected {
            return Err(Error::Held("result differs from selected outcome"));
        }
        if first_failure.is_some() && pin.is_none() {
            return Err(Error::Held("failure result lacks retained pin"));
        }
        publisher.current_token(store)?;
        store.barrier(result.read())?;
    }
    for number in missing {
        if Some(number) == failed {
            let (directory, record, found) = selected_failure
                .as_ref()
                .expect("selected failure was validated");
            super::capture::capture(store, &admission, found, directory, record, None)?;
        } else {
            let (directory, record, found) = completed_at(store, &admission, &root, number)?;
            super::capture::capture(store, &admission, &found, &directory, &record, None)?;
        }
    }
    if !current_has_finding {
        super::capture::capture(store, &admission, &found, &directory, &record, None)?;
    }
    if let Some(result) = result {
        return Ok(Settlement {
            result: Some(result),
            pin_bytes: None,
            result_bytes: None,
        });
    }
    let mut pin_bytes = None;
    if let Some(failure) = &first_failure {
        if pin.is_none() {
            let pin = publish(store, &publisher, &jobs, &pin_name, failure)?;
            pin_bytes = Some(pin.read().bytes().len() as u64);
        }
    } else if retryable(current.finished.class) && maximum < admission.job().experiment().attempts {
        return Ok(Settlement {
            result: None,
            pin_bytes: None,
            result_bytes: None,
        });
    }
    let result = publish(store, &publisher, &jobs, &result_name, selected)?;
    let result_bytes = Some(result.read().bytes().len() as u64);
    Ok(Settlement {
        result: Some(result),
        pin_bytes,
        result_bytes,
    })
}

fn publish<R: Record + PartialEq>(
    store: &Store,
    publisher: &Attempt,
    jobs: &Dir,
    name: &Name,
    expected: &R,
) -> Result<Verified<R>, Error> {
    publisher.current_token(store)?;
    store.create_record(jobs, name, expected)?;
    let found = store
        .read_record::<R>(jobs, name)?
        .ok_or(Error::Held("publication vanished"))?;
    if found.record() != expected {
        return Err(Error::Held("publication differs from selected record"));
    }
    store.barrier(found.read())?;
    Ok(found)
}

/// Selects the first failure from a consecutive history. A prior verdict holds later retries when the history contains no retained failure.
pub(crate) fn selected_failure(
    outcomes: impl IntoIterator<Item = (u64, Class)>,
) -> Result<Option<u64>, Error> {
    let mut outcomes = outcomes.into_iter().peekable();
    let mut failure = None;
    let mut prior_verdict = false;
    let mut expected_number = 1;
    while let Some((number, class)) = outcomes.next() {
        if number != expected_number {
            return Err(Error::Held("outcome history has gaps or duplicates"));
        }
        expected_number += 1;
        if pins(class) && failure.is_none() {
            failure = Some(number);
        }
        if outcomes.peek().is_some() {
            prior_verdict |= !pins(class) && !retryable(class);
        }
    }
    if prior_verdict && failure.is_none() {
        return Err(Error::Held("attempt history continues past a verdict"));
    }
    Ok(failure)
}

pub(crate) fn pins(class: Class) -> bool {
    matches!(class, Class::Violation | Class::EngineFailure)
}

/// Pass, Violation, EngineFailure, Unsuccessful and Inconclusive provide a verdict.
/// Other classes seek a verdict through retries.
pub(super) fn retryable(class: Class) -> bool {
    match class {
        Class::Incomplete
        | Class::Interrupted
        | Class::Watchdog
        | Class::Rejected
        | Class::Infrastructure
        | Class::Signal
        | Class::Oom
        | Class::PidLimit
        | Class::CpuLimit
        | Class::OutputLimit
        | Class::MixedLimits
        | Class::MalformedEvidence
        | Class::MisboundEvidence
        | Class::Disagreement => true,
        Class::Pass
        | Class::Violation
        | Class::EngineFailure
        | Class::Unsuccessful
        | Class::Inconclusive => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{Class, retryable};
    #[test]
    fn selection_pins_the_first_failure_and_holds_past_verdicts_or_number_gaps() {
        use super::selected_failure;
        assert_eq!(
            selected_failure([(1, Class::Watchdog), (2, Class::Pass)]).unwrap(),
            None
        );
        assert_eq!(
            selected_failure([(1, Class::Violation), (2, Class::Pass)]).unwrap(),
            Some(1)
        );
        assert_eq!(
            selected_failure([(1, Class::EngineFailure), (2, Class::Violation)]).unwrap(),
            Some(1)
        );
        assert!(selected_failure([(1, Class::Pass), (2, Class::Pass)]).is_err());
        assert!(selected_failure([(1, Class::Watchdog), (3, Class::Pass)]).is_err());
        assert!(selected_failure([(0, Class::Pass)]).is_err());
    }
    #[test]
    fn every_class_has_explicit_retry_policy() {
        let retry = [
            Class::Incomplete,
            Class::Interrupted,
            Class::Watchdog,
            Class::Rejected,
            Class::Infrastructure,
            Class::Signal,
            Class::Oom,
            Class::PidLimit,
            Class::CpuLimit,
            Class::OutputLimit,
            Class::MixedLimits,
            Class::MalformedEvidence,
            Class::MisboundEvidence,
            Class::Disagreement,
        ];
        for &class in Class::ALL {
            assert_eq!(retryable(class), retry.contains(&class), "{class:?}");
        }
    }
}
