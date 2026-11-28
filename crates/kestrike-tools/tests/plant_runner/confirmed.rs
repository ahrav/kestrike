//! Tests of `campaign confirm`: which findings confirm a suspect, and how a held or paused queue and
//! an output past the reader leave the plant.

use super::fixture::Fixture;
use super::swept::{exited, suspect};

const NONE_OF_RUN_7: &str = "made no finding of violation: a rule in run 7 of a";

#[test]
fn a_finding_of_another_run_or_class_confirms_nothing() {
    let mut fx = Fixture::new();
    fx.run(&["p-mismatch", "p-watchdog"], &[]);
    fx.verdict("p-mismatch", "no verdict", NONE_OF_RUN_7);
    fx.verdict("p-watchdog", "no verdict", NONE_OF_RUN_7);
    assert!(fx.calls(&["sim", "run"]).is_empty());
}

#[test]
fn a_finding_of_another_profile_or_seed_confirms_nothing() {
    let mut fx = Fixture::new();
    fx.run(&["p-otherprofile", "p-otherseed"], &[]);
    fx.verdict("p-otherprofile", "no verdict", NONE_OF_RUN_7);
    fx.verdict("p-otherseed", "no verdict", NONE_OF_RUN_7);
    assert!(fx.calls(&["sim", "run"]).is_empty());
}

#[test]
fn a_finding_without_an_id_or_an_integer_run_confirms_nothing() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-noid", "p-badrun"], &[]);
    exited(&done, 3);
    for name in ["p-noid", "p-badrun"] {
        fx.verdict(
            name,
            "no verdict",
            "`campaign confirm` made no finding of violation: a rule in run 7 of a",
        );
    }
    assert!(fx.calls(&["sim", "run"]).is_empty());
}

#[test]
fn a_finding_without_an_id_or_with_a_boolean_run_confirms_nothing() {
    let mut fx = Fixture::new();
    fx.run(&["p-noid", "p-boolrun"], &[]);
    for name in ["p-noid", "p-boolrun"] {
        fx.verdict(name, "no verdict", NONE_OF_RUN_7);
    }
    assert!(fx.calls(&["sim", "run"]).is_empty());
}

#[test]
fn a_finding_of_another_shape_after_a_catch_leaves_the_catch_standing() {
    let mut fx = Fixture::new();
    fx.run(&["p-oddfinding"], &[]);
    let caught = fx.verdict("p-oddfinding", "caught", "violation: a rule in run 7 of a");
    assert_eq!(suspect(&caught, "finding"), "\"finding-0\"");
}

#[test]
fn a_later_confirmed_suspect_is_caught_after_an_unconfirmed_one() {
    let mut fx = Fixture::new();
    fx.run(&["p-laterfinding"], &[]);
    let caught = fx.verdict("p-laterfinding", "caught", "run 8 of a");
    assert_eq!(suspect(&caught, "finding"), "\"finding-1\"");
}

#[test]
fn a_confirm_that_leaves_jobs_queued_leaves_no_verdict() {
    let mut fx = Fixture::new();
    fx.run(&["p-queued"], &[]);
    fx.verdict(
        "p-queued",
        "no verdict",
        "left its queue at dispatch 'paused'",
    );
}

#[test]
fn a_confirm_held_at_its_backlog_keeps_the_findings_it_made() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-held", "p-heldnone", "p-heldother"], &[]);
    exited(&done, 3);
    fx.verdict("p-held", "caught", "violation: a rule in run 7 of a");
    fx.verdict(
        "p-heldnone",
        "no verdict",
        "`campaign confirm` held its queue: backlog holds 64",
    );
    fx.verdict(
        "p-heldother",
        "no verdict",
        "`campaign confirm` exited 4 at dispatch 'held'",
    );
    assert_eq!(fx.calls(&["sim", "run"]).len(), 1);
}

#[test]
fn a_confirm_held_for_more_than_its_backlog_keeps_no_finding() {
    let names = [
        "p-heldrejected",
        "p-heldomitted",
        "p-heldmixed",
        "p-heldpaused",
    ];
    let mut fx = Fixture::new();
    let done = fx.run(&names, &[]);
    exited(&done, 3);
    for name in names {
        let dispatch = if name == "p-heldpaused" {
            "paused"
        } else {
            "held"
        };
        let reason = format!("`campaign confirm` exited 4 at dispatch '{dispatch}'");
        fx.verdict(name, "no verdict", &reason);
    }
    assert!(fx.calls(&["sim", "run"]).is_empty());
}

#[test]
fn an_output_nested_past_the_parser_leaves_no_verdict_and_the_run_goes_on() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-deepconfirm", "p-miss"], &[]);
    exited(&done, 3);
    fx.verdict(
        "p-deepconfirm",
        "no verdict",
        "`campaign confirm` printed no JSON object",
    );
    fx.verdict("p-miss", "missed", "each expected profile reached 300 runs");
}

#[test]
fn a_panic_is_a_catch() {
    let mut fx = Fixture::new();
    fx.run(&["p-panic"], &[]);
    fx.verdict("p-panic", "caught", "panic: a rule in run 7 of a");
}
