//! The bounds of one episode in seconds, sums over a profile, the contract's effect timeout, the seconds
//! one AWS call may take and the hardware lane's waits, and the two checks that hold a profile's bounds
//! against its case's declared seconds and against the caller's kill grace.
//!
//! A bound is a sum and starts no timer: [`run_bound`] is what the run's deadline is later counted from at
//! the case's spawn, [`phase_bound`] rounded up is the deadline the case is given, [`episode_bound`] is
//! summed for the campaign's budget, and [`cleanup_bound`] plus [`CLOSE_OUT_SECONDS`] is held against the
//! kill grace. The sums run left to right as written in each function's documentation, with the
//! arithmetic of [`super::seconds`], so a bound is the float those additions give.

use std::path::Path;

use super::constants::{
    CLEANUP_CALLS, CLEANUP_PATH_WINDOWS, CLEANUP_WINDOWS, CLOSE_OUT_SECONDS, OBSERVER_OPERATIONS,
    RUN_CALLS, RUN_WINDOWS,
};
use super::error::{Error, Rejected};
use super::lane_role::close_seconds;
use super::operator::Operator;
use super::profiles::{Manifest, member};
use super::seconds::{Seconds, plus, whole_float, whole_sum};
use crate::hardware_lane::OBSERVER_SECONDS;
use crate::json::Value;
use crate::python::{format_g, repr, str_of};
use crate::text::{Text, text};

/// `run_bound` is the seconds from the case's spawn by which the run's phases have ended:
/// `ready_seconds + duration_seconds + RUN_WINDOWS × effect + RUN_CALLS × aws_seconds`, the readiness, the
/// action's duration, the run's effect-timeout windows, and the target checks after readiness and after
/// the template and the stop request of a proven stop, one AWS call each.
///
/// # Errors
///
/// A profile that holds no `ready_seconds`, then no `duration_seconds`, then one of them that is no number;
/// and [`Error::Overflow`].
pub fn run_bound(profile: &Value, operator: &Operator, aws_seconds: f64) -> Result<f64, Error> {
    let ready = member(profile, "ready_seconds")?;
    let duration = member(profile, "duration_seconds")?;
    let ready = number(ready, "ready_seconds")?;
    let duration = number(duration, "duration_seconds")?;
    let effect = operator.effect_timeout_seconds();
    let windows = [effect; RUN_WINDOWS as usize];
    // Two whole terms and the windows sum in one exact sum, whose partial sums stay within the reader's
    // digits wherever the total does, before the one conversion to a float.
    let run = match (&ready, &duration) {
        (Seconds::Whole(ready), Seconds::Whole(duration)) => {
            let mut terms = vec![ready, duration];
            terms.extend(windows);
            whole_float(&whole_sum(&terms)?)?
        }
        _ => plus(&ready, &duration)?.float()? + whole_float(&whole_sum(&windows)?)?,
    };
    Ok(run + f64::from(RUN_CALLS) * aws_seconds)
}

/// `phase_bound` is the seconds one episode's controller phases can take before the case must have ended:
/// `run_bound + CLEANUP_CALLS × aws_seconds + CLEANUP_WINDOWS × (effect + aws_seconds) +
/// OBSERVER_OPERATIONS × OBSERVER_SECONDS`, the run, the cleanup's calls outside its windows, its windows,
/// each ending in one AWS call, and the observer log reads and marks that run past a window or between
/// windows, each waiting at most the lane's observer bound.
///
/// # Errors
///
/// Those of [`run_bound`].
pub fn phase_bound(profile: &Value, operator: &Operator, aws_seconds: f64) -> Result<f64, Error> {
    let run = run_bound(profile, operator, aws_seconds)?;
    let effect = whole_float(operator.effect_timeout_seconds())?;
    Ok(run
        + f64::from(CLEANUP_CALLS) * aws_seconds
        + f64::from(CLEANUP_WINDOWS) * (effect + aws_seconds)
        + f64::from(OBSERVER_OPERATIONS) * OBSERVER_SECONDS)
}

/// `episode_bound` is the seconds one episode can take from the controller's first call:
/// `aws_seconds + phase_bound + case_seconds + close_seconds`, the target check before the case is
/// spawned, the phases from the spawn, the case's declared seconds, and the lane's close after a case that
/// outlived them is terminated. The campaign budget sums it over the chosen profiles.
///
/// # Errors
///
/// Those of [`phase_bound`], then a profile that holds no `case_seconds` or one that is no number, then
/// those of [`close_seconds`].
pub fn episode_bound(
    profile: &Value,
    operator: &Operator,
    aws_seconds: f64,
    hardware_manifest: &Path,
) -> Result<f64, Error> {
    Ok(aws_seconds
        + phase_bound(profile, operator, aws_seconds)?
        + number(member(profile, "case_seconds")?, "case_seconds")?.float()?
        + close_seconds(profile, hardware_manifest)?)
}

/// `cleanup_bound` is the seconds the controller's cleanup after a signal can take on its longest path, a
/// start whose outcome is unknown: `CLEANUP_PATH_WINDOWS × (effect + aws_seconds) + CLEANUP_CALLS ×
/// aws_seconds + close_seconds`, the discovery listing, the stop's end, its restoration poll, the abandon
/// wait and the template's deletion, each an effect window ending in one AWS call, the stop request and
/// the listing after the deletion, then the lane's close.
///
/// # Errors
///
/// [`Error::Overflow`], then those of [`close_seconds`].
pub fn cleanup_bound(
    profile: &Value,
    operator: &Operator,
    aws_seconds: f64,
    hardware_manifest: &Path,
) -> Result<f64, Error> {
    let effect = whole_float(operator.effect_timeout_seconds())?;
    let windows = f64::from(CLEANUP_PATH_WINDOWS) * (effect + aws_seconds)
        + f64::from(CLEANUP_CALLS) * aws_seconds;
    Ok(windows + close_seconds(profile, hardware_manifest)?)
}

/// `check_profiles` admits chosen profiles whose cases' declared seconds hold the controller's phases under
/// this contract: for each name of `names` in order, [`phase_bound`] is at most `case_seconds`.
///
/// # Errors
///
/// The first profile whose phases pass its case; before its comparison, a name the file declares no
/// profile under, the errors of [`phase_bound`], and a `case_seconds` that is absent or no number.
pub fn check_profiles(
    manifest: &Manifest<'_>,
    names: &[Text],
    operator: &Operator,
    aws_seconds: f64,
) -> Result<(), Error> {
    for name in names {
        let profile = manifest.profile(name)?;
        let bound = phase_bound(profile, operator, aws_seconds)?;
        let case = member(profile, "case_seconds")?;
        if Seconds::Real(bound).exceeds(&number(case, "case_seconds")?) {
            return Err(Rejected::new(text!(
                "profile ",
                name,
                " needs up to ",
                format_g(bound),
                " s before its case ends, past its ",
                str_of(case),
                " s case; lower effect_timeout_seconds"
            ))
            .into());
        }
    }
    Ok(())
}

/// `check_grace` admits chosen profiles whose cleanup after a signal, with the close-out that writes the
/// quarantine marker and the receipt after it, the caller's kill grace `grace` holds: for each name of
/// `names` in order, [`cleanup_bound`] plus [`CLOSE_OUT_SECONDS`] is at most `grace`.
///
/// # Errors
///
/// The first profile whose cleanup passes the grace; before its comparison, a name the file declares no
/// profile under and the errors of [`cleanup_bound`].
pub fn check_grace(
    manifest: &Manifest<'_>,
    names: &[Text],
    operator: &Operator,
    aws_seconds: f64,
    grace: f64,
    hardware_manifest: &Path,
) -> Result<(), Error> {
    for name in names {
        let profile = manifest.profile(name)?;
        let cleanup = cleanup_bound(profile, operator, aws_seconds, hardware_manifest)?
            + f64::from(CLOSE_OUT_SECONDS);
        if cleanup > grace {
            return Err(Rejected::new(text!(
                "profile ",
                name,
                " needs up to ",
                format_g(cleanup),
                " s of cleanup and close-out after a signal, past the ",
                format_g(grace),
                " s kill grace; lower effect_timeout_seconds or --aws-seconds"
            ))
            .into());
        }
    }
    Ok(())
}

fn number(value: &Value, key: &str) -> Result<Seconds, Rejected> {
    Seconds::of(value).ok_or_else(|| {
        Rejected::new(text!(
            "a FIS profile's ",
            key,
            " ",
            repr(value),
            " is not a number of seconds"
        ))
    })
}
