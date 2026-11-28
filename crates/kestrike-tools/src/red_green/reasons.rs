//! The judgment of a leg: a red base, a green head, or the reason of the refusal. Accepting a base failure
//! or head pass requires complete evidence from that leg, including both attempt output streams.

use super::evidence::Evidence;
use super::expected;
use super::runner::{self, BUILD_FAILURE, CRASH, NOT_REPRODUCED, REJECTED, REPRODUCED, WATCHDOG};
use crate::text::{Text, text};

pub const NO_EVIDENCE: &str =
    "left no readable artifact.json or attempt output of its own in the receipt";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseJudgment {
    /// `None` for a red base.
    pub reason: Option<Text>,
    /// The streams that hold the expected text, set after a reported failure with both streams read.
    pub expect_streams: Option<Vec<&'static str>>,
}

fn quoted(code: i32, verdict: &Text) -> Text {
    text!("exit ", code.to_string(), ", verdict ", verdict.repr())
}

/// A red base requires an `expect` match in attempt output outside `test` framing and backtrace lines.
pub fn base_reason(
    code: i32,
    verdict: &Text,
    evidence: &Evidence,
    expect: &[u8],
    test: &[u8],
) -> BaseJudgment {
    let refused = |reason| BaseJudgment {
        reason: Some(reason),
        expect_streams: None,
    };
    if code == REPRODUCED && runner::reported(code, verdict) {
        let Some(readings) = evidence.readings().filter(|readings| readings.complete()) else {
            return refused(text!(
                "the base leg failed but ",
                NO_EVIDENCE,
                ": ",
                verdict
            ));
        };
        let matched = expected::expect_streams(&readings.outputs, expect, test);
        let reason = matched.is_empty().then(|| {
            text!(
                "the test failed on the base without the expected text: ",
                verdict,
                "; the search skips framing and backtrace lines"
            )
        });
        return BaseJudgment {
            reason,
            expect_streams: Some(matched),
        };
    }
    refused(
        if code == NOT_REPRODUCED && runner::reported(code, verdict) {
            text!("the test passes on the base: ", verdict)
        } else if code == BUILD_FAILURE {
            text!(
                "the base is red for the wrong reason, a build failure: ",
                verdict
            )
        } else if code == REJECTED && super::holds(verdict.as_bytes(), runner::ABSENT.as_bytes()) {
            text!("the test is absent on the base: ", verdict)
        } else if code == CRASH {
            text!("the test crashed on the base: ", verdict)
        } else if code == WATCHDOG && runner::reported(code, verdict) {
            text!("the test hung on the base: ", verdict)
        } else {
            text!(
                "the runner did not complete the base leg: ",
                quoted(code, verdict)
            )
        },
    )
}

/// `None` for a green head.
pub fn head_reason(code: i32, verdict: &Text, evidence: &Evidence) -> Option<Text> {
    if code == REPRODUCED && runner::reported(code, verdict) {
        return Some(text!("the test fails on the head: ", verdict));
    }
    if !(code == NOT_REPRODUCED && runner::reported(code, verdict)) {
        return Some(text!("the head leg did not pass: ", quoted(code, verdict)));
    }
    if !evidence
        .readings()
        .is_some_and(|readings| readings.complete())
    {
        return Some(text!(
            "the head leg passed but ",
            NO_EVIDENCE,
            ": ",
            verdict
        ));
    }
    None
}

pub fn tree_reason(leg: &str, path: &Text) -> Text {
    text!(
        "the ",
        leg,
        " leg's tree differs from its commit at ",
        path.repr(),
        "; Git configuration such as a filter or a line-ending conversion changes what a checkout writes"
    )
}

#[cfg(test)]
#[path = "reasons_tests.rs"]
mod tests;
