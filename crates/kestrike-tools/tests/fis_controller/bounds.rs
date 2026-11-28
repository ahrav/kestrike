//! Each bound of a profile, as the controller's sums give it: for the seven checked-in profiles under
//! one contract, for fractional call seconds and profile seconds, for whole numbers that a float cannot
//! hold exactly, and for whole numbers past the largest float, which stop the bound that converts them.

use kestrike_tools::fis_controller::{
    Error, Operator, check_operator, cleanup_bound, episode_bound, phase_bound, run_bound,
};
use kestrike_tools::json::Value;

use crate::fis_support::{hardware_manifest, operator, profile, value};

/// The contract of the base with an effect timeout of `effect`, a JSON number.
fn contract(effect: &str) -> Operator {
    check_operator(&operator(effect)).expect("the contract is admitted")
}

/// `run_bound`, `phase_bound`, `episode_bound` and `cleanup_bound` of `profile`.
fn bounds(profile: &Value, operator: &Operator, aws_seconds: f64) -> [Result<f64, Error>; 4] {
    let hardware = hardware_manifest();
    [
        run_bound(profile, operator, aws_seconds),
        phase_bound(profile, operator, aws_seconds),
        episode_bound(profile, operator, aws_seconds, &hardware),
        cleanup_bound(profile, operator, aws_seconds, &hardware),
    ]
}

/// `name`'s checked-in profile with each member of `changes` set to its JSON text.
fn changed(name: &str, changes: &[(&str, &str)]) -> Value {
    let mut profile = profile(name);
    let Value::Object(fields) = &mut profile else {
        panic!("a checked-in profile is an object");
    };
    for (key, new) in changes {
        fields.insert(*key, value(new));
    }
    profile
}

#[test]
fn each_bound_of_the_checked_in_profiles_under_a_minute_of_effect_timeout_and_calls() {
    let rows = [
        ("fis-read-latency", [900.0, 1295.0, 3255.0, 820.0]),
        ("fis-write-latency", [900.0, 1295.0, 3255.0, 820.0]),
        ("fis-pause", [840.0, 1235.0, 3195.0, 820.0]),
        ("fis-family-stop", [840.0, 1235.0, 3195.0, 820.0]),
        (
            "fis-read-latency-multi-attach",
            [900.0, 1295.0, 3255.0, 820.0],
        ),
        (
            "fis-write-latency-multi-attach",
            [900.0, 1295.0, 3255.0, 820.0],
        ),
        (
            "fis-family-stop-multi-attach",
            [840.0, 1235.0, 3195.0, 820.0],
        ),
    ];
    let operator = contract("60");
    for (name, expected) in rows {
        assert_eq!(
            bounds(&profile(name), &operator, 60.0),
            expected.map(Ok),
            "{name}"
        );
    }
}

#[test]
fn fractional_seconds_sum_left_to_right_as_floats() {
    let rows = [
        (
            "fis-read-latency under a 2 s effect timeout and 0.25 s calls",
            profile("fis-read-latency"),
            contract("2"),
            0.25,
            [430.75, 470.75, 2371.0, 111.75],
        ),
        (
            "fis-pause under a 7 s effect timeout and 1.1 s calls",
            profile("fis-pause"),
            contract("7"),
            1.1,
            [398.3, 451.7, 2352.8, 142.7],
        ),
        (
            "fis-read-latency with a readiness of 300.5 s and a case of 1800.25 s",
            changed(
                "fis-read-latency",
                &[("ready_seconds", "300.5"), ("case_seconds", "1800.25")],
            ),
            contract("60"),
            60.0,
            [900.5, 1295.5, 3255.75, 820.0],
        ),
    ];
    for (case, profile, operator, aws, expected) in rows {
        assert_eq!(bounds(&profile, &operator, aws), expected.map(Ok), "{case}");
    }
}

/// The readiness, the duration and the five effect windows of the run sum as whole numbers before the
/// one conversion to a float: 2⁵³ + 1 + 5 is the float 2⁵³ + 6, where converting each term first would
/// give 2⁵³ + 4.
#[test]
fn whole_seconds_sum_exactly_before_they_meet_a_float() {
    let profile = changed(
        "fis-read-latency",
        &[
            ("ready_seconds", "9007199254740992"),
            ("duration_seconds", "1"),
        ],
    );
    assert_eq!(
        bounds(&profile, &contract("1"), 0.0),
        [
            9007199254740998.0,
            9007199254741036.0,
            9007199254742936.0,
            105.0
        ]
        .map(Ok)
    );
}

/// A readiness and a duration of 4300 nines below zero and an effect timeout of 4 × 10⁴²⁹⁹ sum to 2, as
/// Python's integers give it, though the readiness and the duration alone sum past the integers the
/// reader holds; the phase, episode and cleanup bounds convert the effect timeout itself, which is past
/// the largest float.
#[test]
fn whole_seconds_that_cancel_sum_to_their_total_and_a_converted_one_past_every_float_overflows() {
    let nines = format!("-{}", "9".repeat(4300));
    let profile = changed(
        "fis-read-latency",
        &[("ready_seconds", &nines), ("duration_seconds", &nines)],
    );
    let effect = format!("4{}", "0".repeat(4299));
    assert_eq!(
        bounds(&profile, &contract(&effect), 60.0),
        [
            Ok(182.0),
            Err(Error::Overflow),
            Err(Error::Overflow),
            Err(Error::Overflow)
        ]
    );
    let past = format!("1{}", "0".repeat(400));
    let profile = changed("fis-read-latency", &[("case_seconds", &past)]);
    assert_eq!(
        bounds(&profile, &contract("60"), 60.0),
        [Ok(900.0), Ok(1295.0), Err(Error::Overflow), Ok(820.0)]
    );
}
