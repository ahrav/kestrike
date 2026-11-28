//! The reads a check makes of a member without a check of its own: where the member is absent or of a
//! kind the read cannot take, the check that reads it stops the run with the library's sentence; where
//! Python's operation reads it, as `in` finds an action in an array or a string of eligible types and as
//! arithmetic takes a boolean, an infinity or `nan`, the run goes on as that operation does. A whole
//! number past the largest float stops the bound that converts it. The rows that pass beside the rows
//! that stop differ from them in one value.

use kestrike_tools::json::Text;

use super::{Check, Stop, checks};
use crate::fis_support::{Change, Input::*, Inputs, hardware_manifest};

/// A whole number of 401 digits, past the largest float.
const PAST_FLOAT: &str = concat!(
    "1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000"
);

type Read = (&'static str, &'static [Change], Result<(), (Check, Stop)>);

/// The run stops at `check` with `sentence`.
fn stops(check: Check, sentence: &str) -> Result<(), (Check, Stop)> {
    Err((check, Stop::Rejected(Text::from(sentence))))
}

fn reads() -> Vec<Read> {
    vec![
        (
            "a profiles file without profiles",
            &[(Profiles, &["profiles"], None)],
            stops(
                Check::Manifest,
                "the FIS profiles file holds no object under profiles",
            ),
        ),
        (
            "a profiles file whose profiles is a list",
            &[(Profiles, &["profiles"], Some("[]"))],
            stops(
                Check::Manifest,
                "the FIS profiles file holds no object under profiles",
            ),
        ),
        (
            "a profiles file that is a list",
            &[(Profiles, &[], Some("[]"))],
            stops(Check::Manifest, "the FIS profiles file is not an object"),
        ),
        (
            "a profile that is a number",
            &[(Profiles, &["profiles", "fis-pause"], Some("7"))],
            stops(
                Check::Manifest,
                "manifest profile 'fis-pause' is not an object",
            ),
        ),
        (
            "a profiles file without eligible_types",
            &[(Profiles, &["eligible_types"], None)],
            stops(
                Check::Manifest,
                "the FIS profiles file holds no eligible_types",
            ),
        ),
        (
            "a profiles file whose eligible_types is a list",
            &[(
                Profiles,
                &["eligible_types"],
                Some("[\"aws:ebs:pause-volume-io\", \"aws:ebs:volume-io-latency\"]"),
            )],
            Ok(()),
        ),
        (
            "a profiles file whose eligible_types is a string",
            &[(
                Profiles,
                &["eligible_types"],
                Some("\"aws:ebs:pause-volume-io aws:ebs:volume-io-latency\""),
            )],
            Ok(()),
        ),
        (
            "a profiles file whose eligible_types is a number",
            &[(Profiles, &["eligible_types"], Some("7"))],
            stops(
                Check::Manifest,
                "the manifest's eligible_types 7 lists no action",
            ),
        ),
        (
            "an action of 1.0 that a list of eligible_types holds as 1",
            &[
                (
                    Profiles,
                    &["eligible_types"],
                    Some("[1, \"aws:ebs:volume-io-latency\"]"),
                ),
                (Profiles, &["profiles", "fis-pause", "action"], Some("1.0")),
            ],
            stops(
                Check::Manifest,
                "manifest profile 'fis-family-stop' names action 'aws:ebs:pause-volume-io', which the manifest's eligible_types does not list",
            ),
        ),
        (
            "an action of true that a list of eligible_types holds as 1",
            &[
                (
                    Profiles,
                    &["eligible_types"],
                    Some("[1, \"aws:ebs:volume-io-latency\"]"),
                ),
                (Profiles, &["profiles", "fis-pause", "action"], Some("true")),
            ],
            stops(
                Check::Manifest,
                "manifest profile 'fis-family-stop' names action 'aws:ebs:pause-volume-io', which the manifest's eligible_types does not list",
            ),
        ),
        (
            "an absent action that a list of eligible_types holds as null",
            &[
                (
                    Profiles,
                    &["eligible_types"],
                    Some("[null, \"aws:ebs:volume-io-latency\"]"),
                ),
                (Profiles, &["profiles", "fis-pause", "action"], None),
            ],
            stops(
                Check::Manifest,
                "manifest profile 'fis-pause' holds no action",
            ),
        ),
        (
            "an action that is no string beside eligible_types that is a string",
            &[
                (
                    Profiles,
                    &["eligible_types"],
                    Some("\"aws:ebs:volume-io-latency\""),
                ),
                (Profiles, &["profiles", "fis-pause", "action"], Some("7")),
            ],
            stops(
                Check::Manifest,
                "manifest profile 'fis-pause' names action 7, which is no string to find in the manifest's eligible_types",
            ),
        ),
        (
            "an action of nan that a list of eligible_types holds",
            &[
                (
                    Profiles,
                    &["eligible_types"],
                    Some("[NaN, \"aws:ebs:volume-io-latency\", \"aws:ebs:pause-volume-io\"]"),
                ),
                (Profiles, &["profiles", "fis-pause", "action"], Some("NaN")),
            ],
            Ok(()),
        ),
        (
            "an action of [nan] that a list of eligible_types holds as [nan]",
            &[
                (
                    Profiles,
                    &["eligible_types"],
                    Some("[[NaN], \"aws:ebs:volume-io-latency\", \"aws:ebs:pause-volume-io\"]"),
                ),
                (
                    Profiles,
                    &["profiles", "fis-pause", "action"],
                    Some("[NaN]"),
                ),
            ],
            Ok(()),
        ),
        (
            "a single profile whose volume declares two instances",
            &[(
                Operator,
                &["attachments"],
                Some("{\"vol-0123456789abcdef0\": [\"i-1\", \"i-2\"]}"),
            )],
            Ok(()),
        ),
        (
            "an episode at the receipt name's bound",
            &[(
                Episode,
                &[],
                Some(
                    "\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"",
                ),
            )],
            Ok(()),
        ),
        (
            "an action that is a list",
            &[(
                Profiles,
                &["profiles", "fis-pause", "action"],
                Some("[\"aws:ebs:pause-volume-io\"]"),
            )],
            stops(
                Check::Manifest,
                "manifest profile 'fis-pause' names action ['aws:ebs:pause-volume-io'], which the manifest's eligible_types does not list",
            ),
        ),
        (
            "a profiles file with no profile",
            &[(Profiles, &["profiles"], Some("{}"))],
            stops(Check::Episode, "the FIS profiles file declares no profile"),
        ),
        (
            "a profile without ready_seconds",
            &[(
                Profiles,
                &["profiles", "fis-read-latency", "ready_seconds"],
                None,
            )],
            stops(Check::Profiles, "a FIS profile holds no ready_seconds"),
        ),
        (
            "a ready_seconds that is a string",
            &[(
                Profiles,
                &["profiles", "fis-read-latency", "ready_seconds"],
                Some("\"300\""),
            )],
            stops(
                Check::Profiles,
                "a FIS profile's ready_seconds '300' is not a number of seconds",
            ),
        ),
        (
            "a ready_seconds string beside an absent duration",
            &[
                (
                    Profiles,
                    &["profiles", "fis-read-latency", "ready_seconds"],
                    Some("\"300\""),
                ),
                (
                    Profiles,
                    &["profiles", "fis-read-latency", "duration_seconds"],
                    None,
                ),
            ],
            stops(Check::Profiles, "a FIS profile holds no duration_seconds"),
        ),
        (
            "a profile without duration_seconds",
            &[(
                Profiles,
                &["profiles", "fis-read-latency", "duration_seconds"],
                None,
            )],
            stops(Check::Profiles, "a FIS profile holds no duration_seconds"),
        ),
        (
            "a duration_seconds of null",
            &[(
                Profiles,
                &["profiles", "fis-read-latency", "duration_seconds"],
                Some("null"),
            )],
            stops(
                Check::Profiles,
                "a FIS profile's duration_seconds None is not a number of seconds",
            ),
        ),
        (
            "a profile without case_seconds",
            &[(
                Profiles,
                &["profiles", "fis-read-latency", "case_seconds"],
                None,
            )],
            stops(Check::Profiles, "a FIS profile holds no case_seconds"),
        ),
        (
            "a case_seconds that is a string",
            &[(
                Profiles,
                &["profiles", "fis-read-latency", "case_seconds"],
                Some("\"1800\""),
            )],
            stops(
                Check::Profiles,
                "a FIS profile's case_seconds '1800' is not a number of seconds",
            ),
        ),
        (
            "a profile without lane",
            &[(Profiles, &["profiles", "fis-read-latency", "lane"], None)],
            stops(Check::Grace, "a FIS profile holds no lane"),
        ),
        (
            "a lane that is a string",
            &[(
                Profiles,
                &["profiles", "fis-read-latency", "lane"],
                Some("\"fis-read\""),
            )],
            stops(
                Check::Grace,
                "the hardware manifest names no lane role for fis-read: a value that is not an object has no member 'profile'",
            ),
        ),
        (
            "an effect timeout past every float",
            &[(Operator, &["effect_timeout_seconds"], Some(PAST_FLOAT))],
            Err((Check::Profiles, Stop::Overflow)),
        ),
        (
            "a ready_seconds past every float",
            &[(
                Profiles,
                &["profiles", "fis-read-latency", "ready_seconds"],
                Some(PAST_FLOAT),
            )],
            Err((Check::Profiles, Stop::Overflow)),
        ),
        (
            "a ready_seconds that is true",
            &[(
                Profiles,
                &["profiles", "fis-read-latency", "ready_seconds"],
                Some("true"),
            )],
            Ok(()),
        ),
        (
            "a ready_seconds of infinity",
            &[(
                Profiles,
                &["profiles", "fis-read-latency", "ready_seconds"],
                Some("Infinity"),
            )],
            stops(
                Check::Profiles,
                "profile fis-read-latency needs up to inf s before its case ends, past its 1800 s case; lower effect_timeout_seconds",
            ),
        ),
        (
            "a ready_seconds of nan",
            &[(
                Profiles,
                &["profiles", "fis-read-latency", "ready_seconds"],
                Some("NaN"),
            )],
            Ok(()),
        ),
        (
            "a case_seconds of nan",
            &[(
                Profiles,
                &["profiles", "fis-read-latency", "case_seconds"],
                Some("NaN"),
            )],
            Ok(()),
        ),
        (
            "a poll that is no number",
            &[(Poll, &[], Some("\"x\""))],
            Err((Check::Poll, Stop::NoNumber)),
        ),
        (
            "a poll of 1_0",
            &[(Poll, &[], Some("\"1_0\""))],
            Err((Check::Poll, Stop::NoNumber)),
        ),
    ]
}

#[test]
fn each_read_without_a_check_of_its_own_stops_at_the_check_that_reads_it() {
    assert_eq!(PAST_FLOAT.len(), 401);
    for (case, changes, expected) in reads() {
        let stopped = checks(&Inputs::changed(changes), &hardware_manifest());
        assert_eq!(stopped, expected, "{case}");
    }
}
