//! The judgment of a leg: a red base, a green head, or the reason of the refusal. Accepting a base failure
//! or head pass requires complete evidence from that leg, including both attempt output streams.

use super::expected;
use super::options::Options;
use super::record::Leg;
use super::runner::{self, BUILD_FAILURE, CRASH, NOT_REPRODUCED, REJECTED, REPRODUCED, WATCHDOG};
use crate::text::{Text, text};

pub const NO_EVIDENCE: &str =
    "left no readable artifact.json or attempt output of its own in the receipt";

fn quoted(code: i32, verdict: &Text) -> Text {
    text!("exit ", code.to_string(), ", verdict ", verdict.repr())
}

fn complete(leg: &Leg) -> bool {
    leg.evidence
        .readings()
        .is_some_and(|readings| readings.complete())
}

/// A red base requires a match of `options.expect` in attempt output outside the framing and backtrace
/// lines of `options.test`. `base_reason` sets `leg.expect_streams` after a reported failure with both
/// streams read.
#[must_use = "a dropped judgment leaves the refusal unrecorded"]
pub fn base_reason(leg: &mut Leg, options: &Options) -> Option<Text> {
    let (code, verdict) = (leg.exit, &leg.verdict);
    let reported = runner::reported(code, verdict);
    let reason = match code {
        REPRODUCED if reported => {
            let Some(readings) = leg
                .evidence
                .readings()
                .filter(|readings| readings.complete())
            else {
                return Some(text!(
                    "the base leg failed but ",
                    NO_EVIDENCE,
                    ": ",
                    verdict
                ));
            };
            let matched =
                expected::expect_streams(&readings.outputs, &options.expect, &options.test);
            let found = !matched.is_empty();
            leg.expect_streams = Some(matched);
            if found {
                return None;
            }
            text!(
                "the test failed on the base without the expected text: ",
                &leg.verdict,
                "; the search skips framing and backtrace lines"
            )
        }
        NOT_REPRODUCED if reported => text!("the test passes on the base: ", verdict),
        BUILD_FAILURE => text!(
            "the base is red for the wrong reason, a build failure: ",
            verdict
        ),
        REJECTED if super::holds(verdict.as_bytes(), runner::ABSENT.as_bytes()) => {
            text!("the test is absent on the base: ", verdict)
        }
        CRASH => text!("the test crashed on the base: ", verdict),
        WATCHDOG if reported => text!("the test hung on the base: ", verdict),
        _ => text!(
            "the runner did not complete the base leg: ",
            quoted(code, verdict)
        ),
    };
    Some(reason)
}

/// `None` for a green head.
#[must_use = "a dropped judgment leaves the refusal unrecorded"]
pub fn head_reason(leg: &Leg) -> Option<Text> {
    let (code, verdict) = (leg.exit, &leg.verdict);
    if code == REPRODUCED && runner::reported(code, verdict) {
        return Some(text!("the test fails on the head: ", verdict));
    }
    if !(code == NOT_REPRODUCED && runner::reported(code, verdict)) {
        return Some(text!("the head leg did not pass: ", quoted(code, verdict)));
    }
    if !complete(leg) {
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
pub(crate) mod tests;
