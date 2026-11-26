//! The class a parsed summary earns: credit needs a counting summary with
//! decisions and a worker exit that agrees.

use super::class::{Stop, credit};
use crate::exit::Sim;
use crate::protocol::{Listing, Summary};

const LISTING: &str = include_str!("../../testdata/listing.txt");
const COUNTING: &str = include_str!("../../testdata/counting.summary");

fn summary(edits: &[(&str, &str)]) -> Summary {
    let mut text = COUNTING.to_owned();
    for (from, to) in edits {
        assert!(text.contains(from), "{from}");
        text = text.replacen(from, to, 1);
    }
    let listing = Listing::parse(LISTING).expect("the listing parses");
    Summary::parse(&text, &listing).expect("the summary parses")
}

fn class(summary: &Summary, exit: Option<i32>) -> Sim {
    let Stop(class, _) = credit(summary, exit);
    class
}

const VIOLATION: [(&str, &str); 3] = [
    ("complete pass", "complete violation"),
    ("counts: true", "counts: false"),
    ("stop: goal\n", "stop: goal\ncause: violation\n"),
];

const CAPPED: [(&str, &str); 3] = [
    ("complete pass fired=03 required=03", "infrastructure cap"),
    ("counts: true", "counts: false"),
    ("stop: goal\n", "stop: goal\ncause: cap\n"),
];

/// Each summary earns its class only beside the run form's agreeing
/// exit, and the inspection alone takes the summary's class.
#[test]
fn the_class_needs_the_summary_and_an_agreeing_exit() {
    let counting = summary(&[]);
    let violation = summary(&VIOLATION);
    let capped = summary(&CAPPED);
    for (summary, earned, agreed) in [
        (&counting, Sim::Counts, 0),
        (&violation, Sim::Complete, 1),
        (&capped, Sim::Incomplete, 3),
    ] {
        assert_eq!(class(summary, None), earned);
        assert_eq!(class(summary, Some(agreed)), earned);
        for exit in [0, 1, 2, 3, 101] {
            if exit != agreed {
                assert_eq!(
                    class(summary, Some(exit)),
                    Sim::Incomplete,
                    "{earned:?} {exit}"
                );
            }
        }
    }
}

/// A counting summary with no decision never counts.
#[test]
fn counts_without_a_decision_is_incomplete() {
    let summary = summary(&[("decisions: 61", "decisions: 0")]);
    assert!(summary.counts);
    assert_eq!(class(&summary, Some(0)), Sim::Incomplete);
    assert_eq!(class(&summary, None), Sim::Incomplete);
}

/// A truncated terminal, whose work counts print unavailable, is
/// incomplete beside the run form's exit 3 and any other.
#[test]
fn a_truncated_summary_is_incomplete() {
    let truncated = summary(&[
        (
            "complete pass fired=03 required=03",
            "infrastructure truncated",
        ),
        ("counts: true", "counts: false"),
        ("stop: goal\n", "stop: goal\ncause: truncated\n"),
        ("decisions: 61", "decisions: unavailable"),
        ("turns: 57", "turns: unavailable"),
        ("progress: 10", "progress: unavailable"),
        ("virtual_us: 600", "virtual_us: unavailable"),
        ("skipped_us: 0", "skipped_us: unavailable"),
    ]);
    assert_eq!(truncated.decisions, None);
    for exit in [Some(3), None, Some(0), Some(1)] {
        assert_eq!(class(&truncated, exit), Sim::Incomplete, "{exit:?}");
    }
}
