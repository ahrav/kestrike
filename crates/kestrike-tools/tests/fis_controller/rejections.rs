//! Each row of the rejection table, run through the checks in the controller's order, stops at the
//! sentence the row records, and the base inputs pass every check, so each row's rejection comes from its
//! change. Each check is a function of the decoded inputs that returns before any call, process or
//! clock reading of the controller, so a rejected input precedes every call.

use kestrike_tools::fis_controller::positive_seconds;
use kestrike_tools::json::Text;

use super::{Check, Stop, checks};
use crate::fis_support::Input::{Grace, Profiles};
use crate::fis_support::rejections::REJECTIONS;
use crate::fis_support::{Inputs, hardware_manifest};

#[test]
fn each_row_of_the_rejection_table_stops_the_checks_with_its_sentence() {
    for row in REJECTIONS {
        let stopped = checks(&Inputs::changed(row.changes), &hardware_manifest());
        match stopped {
            Err((_, Stop::Rejected(sentence))) => {
                assert_eq!(sentence, row.sentence, "{}", row.case);
            }
            other => panic!("{}: {other:?}", row.case),
        }
    }
}

#[test]
fn the_base_inputs_pass_every_check() {
    assert_eq!(checks(&Inputs::base(), &hardware_manifest()), Ok(()));
}

/// A part of each of the controller's twenty rejections and of the poll's refusal, with the check that
/// gives it.
const SENTENCES: [(&str, Check); 21] = [
    ("is not a duration above zero", Check::Poll),
    ("is not an episode name of letters", Check::Manifest),
    ("declares attachment mode", Check::Manifest),
    (
        "which the manifest's eligible_types does not list",
        Check::Manifest,
    ),
    ("not a JSON boolean", Check::Manifest),
    ("enables no direction", Check::Manifest),
    ("not a whole number of milliseconds", Check::Manifest),
    ("one volume serves one mode", Check::Attachments),
    (
        "a multi-attach-one profile takes exactly one instance",
        Check::Attachments,
    ),
    ("too long for the template's episode tag", Check::Episode),
    ("too long for the receipt file name", Check::Episode),
    ("the hardware manifest names no lane role for", Check::Grace),
    ("before its case ends", Check::Profiles),
    (
        "s kill grace; lower effect_timeout_seconds or --aws-seconds",
        Check::Grace,
    ),
    ("the operator contract is", Check::Operator),
    ("operator contract keys [", Check::Operator),
    ("is not a string", Check::Operator),
    ("is not an IAM role ARN", Check::Operator),
    ("is not a list of strings", Check::Operator),
    (
        "is not a map from volume ID to a list of instance IDs",
        Check::Operator,
    ),
    ("is not a positive whole number of seconds", Check::Operator),
];

#[test]
fn the_table_holds_each_rejection_at_the_check_that_gives_it() {
    let stopped: Vec<_> = REJECTIONS
        .iter()
        .map(|row| checks(&Inputs::changed(row.changes), &hardware_manifest()))
        .collect();
    for (part, check) in SENTENCES {
        let found = stopped.iter().any(|stopped| {
            matches!(stopped, Err((at, Stop::Rejected(sentence)))
                if *at == check && sentence.to_string().contains(part))
        });
        assert!(found, "no row gives {part:?} at {check:?}");
    }
}

/// The base's phases take 889 s and its cleanup with the close-out 590 s: a case of exactly 889 s and a
/// kill grace of exactly 590 s admit the run, and a case a float's step below 889 s is rejected.
#[test]
fn a_case_at_its_phase_bound_and_a_grace_at_its_cleanup_pass() {
    let at_bounds = Inputs::changed(&[
        (
            Profiles,
            &["profiles", "fis-read-latency", "case_seconds"],
            Some("889"),
        ),
        (Grace, &[], Some("590.0")),
    ]);
    assert_eq!(checks(&at_bounds, &hardware_manifest()), Ok(()));
    let below = Inputs::changed(&[(
        Profiles,
        &["profiles", "fis-read-latency", "case_seconds"],
        Some("888.9999999999999"),
    )]);
    assert_eq!(
        checks(&below, &hardware_manifest()),
        Err((
            Check::Profiles,
            Stop::Rejected(Text::from(
                "profile fis-read-latency needs up to 889 s before its case ends, past its \
                 888.9999999999999 s case; lower effect_timeout_seconds"
            ))
        ))
    );
}

/// The poll's reader returns the seconds the text spells, the smallest float above zero included.
#[test]
fn a_poll_above_zero_reads_as_its_seconds() {
    for (poll, seconds) in [("2.5", 2.5), ("5e-324", 5e-324), (" 7 ", 7.0)] {
        let read = positive_seconds(&Text::from(poll));
        assert_eq!(read.ok(), Some(seconds), "{poll:?}");
    }
}
