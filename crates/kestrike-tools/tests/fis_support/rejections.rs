//! The rejections of a run's inputs, each a change of [`super::Inputs::base`] and the sentence of the
//! controller's first rejection. The rows hold each of the controller's twenty rejections of its operator
//! contract, its FIS profiles file, its episode name and the bounds of the chosen profiles, and the
//! refusal of a poll that is no duration above zero; two failing fields give the first. Each sentence is
//! the one `scripts/fis-controller.py` gives for the same inputs.

use super::{Change, Input::*};

/// One rejected run.
pub(crate) struct Row {
    /// What the change makes of the inputs.
    pub(crate) case: &'static str,
    pub(crate) changes: &'static [Change],
    pub(crate) sentence: &'static str,
}

/// The checked-in profile `fis-read-latency`, which a row declares under another name.
const READ_LATENCY: &str = r#"{"action": "aws:ebs:volume-io-latency", "read": true, "write": false, "latency_ms": 2000, "timeout_io_us": 1000000, "duration_seconds": 120, "attachment": "single", "ready_seconds": 300, "case_seconds": 1800, "lane": {"profile": "fis-read", "role": "owner"}}"#;

/// An episode of 226 characters, one past what the template's tag holds beside the widest profile name.
const PAST_TAG: &str = concat!(
    "\"",
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "\""
);

/// An episode of 177 characters, one past what the receipt's file name holds.
const PAST_RECEIPT: &str = concat!(
    "\"",
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeex",
    "\""
);

pub(crate) const REJECTIONS: &[Row] = &[
    Row {
        case: "an operator document of null",
        changes: &[(Operator, &[], Some("null"))],
        sentence: "the operator contract is NoneType, not an object",
    },
    Row {
        case: "an operator document that is a list",
        changes: &[(Operator, &[], Some("[]"))],
        sentence: "the operator contract is list, not an object",
    },
    Row {
        case: "an operator document that is a string",
        changes: &[(Operator, &[], Some("\"contract\""))],
        sentence: "the operator contract is str, not an object",
    },
    Row {
        case: "an operator document that is a whole number",
        changes: &[(Operator, &[], Some("7"))],
        sentence: "the operator contract is int, not an object",
    },
    Row {
        case: "an operator document that is a float",
        changes: &[(Operator, &[], Some("7.5"))],
        sentence: "the operator contract is float, not an object",
    },
    Row {
        case: "an operator document that is a boolean",
        changes: &[(Operator, &[], Some("true"))],
        sentence: "the operator contract is bool, not an object",
    },
    Row {
        case: "an operator contract without stop_alarms",
        changes: &[(Operator, &["stop_alarms"], None)],
        sentence: "operator contract keys ['account', 'attachments', 'effect_timeout_seconds', 'region', 'role_arn', 'volumes']",
    },
    Row {
        case: "an operator contract with an extra key",
        changes: &[(Operator, &["extra"], Some("1"))],
        sentence: "operator contract keys ['account', 'attachments', 'effect_timeout_seconds', 'extra', 'region', 'role_arn', 'stop_alarms', 'volumes']",
    },
    Row {
        case: "an account of null",
        changes: &[(Operator, &["account"], Some("null"))],
        sentence: "account None is not a string",
    },
    Row {
        case: "a region that is a number",
        changes: &[(Operator, &["region"], Some("7"))],
        sentence: "region 7 is not a string",
    },
    Row {
        case: "a role_arn that is a list",
        changes: &[(Operator, &["role_arn"], Some("[]"))],
        sentence: "role_arn [] is not a string",
    },
    Row {
        case: "a role_arn of a user",
        changes: &[(Operator, &["role_arn"], Some("\"arn:aws:iam::1:user/fis\""))],
        sentence: "role_arn 'arn:aws:iam::1:user/fis' is not an IAM role ARN; the target ARNs take its partition",
    },
    Row {
        case: "a role_arn without a partition",
        changes: &[(Operator, &["role_arn"], Some("\"arn::iam::1:role/fis\""))],
        sentence: "role_arn 'arn::iam::1:role/fis' is not an IAM role ARN; the target ARNs take its partition",
    },
    Row {
        case: "a role_arn with a region",
        changes: &[(
            Operator,
            &["role_arn"],
            Some("\"arn:aws:iam:us-east-1:1:role/fis\""),
        )],
        sentence: "role_arn 'arn:aws:iam:us-east-1:1:role/fis' is not an IAM role ARN; the target ARNs take its partition",
    },
    Row {
        case: "a role_arn of seven fields",
        changes: &[(
            Operator,
            &["role_arn"],
            Some("\"arn:aws:iam::1:role/fis:x\""),
        )],
        sentence: "role_arn 'arn:aws:iam::1:role/fis:x' is not an IAM role ARN; the target ARNs take its partition",
    },
    Row {
        case: "a role_arn of another service",
        changes: &[(Operator, &["role_arn"], Some("\"arn:aws:sts::1:role/fis\""))],
        sentence: "role_arn 'arn:aws:sts::1:role/fis' is not an IAM role ARN; the target ARNs take its partition",
    },
    Row {
        case: "volumes that is a string",
        changes: &[(Operator, &["volumes"], Some("\"vol-0123456789abcdef0\""))],
        sentence: "volumes 'vol-0123456789abcdef0' is not a list of strings",
    },
    Row {
        case: "volumes that holds a number",
        changes: &[(Operator, &["volumes"], Some("[1]"))],
        sentence: "volumes [1] is not a list of strings",
    },
    Row {
        case: "stop_alarms that is a string",
        changes: &[(Operator, &["stop_alarms"], Some("\"alarm\""))],
        sentence: "stop_alarms 'alarm' is not a list of strings",
    },
    Row {
        case: "attachments of null",
        changes: &[(Operator, &["attachments"], Some("null"))],
        sentence: "attachments None is not a map from volume ID to a list of instance IDs",
    },
    Row {
        case: "attachments that is a list",
        changes: &[(
            Operator,
            &["attachments"],
            Some("[\"vol-0123456789abcdef0\"]"),
        )],
        sentence: "attachments ['vol-0123456789abcdef0'] is not a map from volume ID to a list of instance IDs",
    },
    Row {
        case: "attachments that maps to a string",
        changes: &[(
            Operator,
            &["attachments"],
            Some("{\"vol-0123456789abcdef0\": \"i-1\"}"),
        )],
        sentence: "attachments {'vol-0123456789abcdef0': 'i-1'} is not a map from volume ID to a list of instance IDs",
    },
    Row {
        case: "an effect timeout of zero",
        changes: &[(Operator, &["effect_timeout_seconds"], Some("0"))],
        sentence: "effect_timeout_seconds 0 is not a positive whole number of seconds",
    },
    Row {
        case: "a negative effect timeout",
        changes: &[(Operator, &["effect_timeout_seconds"], Some("-3"))],
        sentence: "effect_timeout_seconds -3 is not a positive whole number of seconds",
    },
    Row {
        case: "an effect timeout that is a string",
        changes: &[(Operator, &["effect_timeout_seconds"], Some("\"60\""))],
        sentence: "effect_timeout_seconds '60' is not a positive whole number of seconds",
    },
    Row {
        case: "an effect timeout that is a boolean",
        changes: &[(Operator, &["effect_timeout_seconds"], Some("true"))],
        sentence: "effect_timeout_seconds True is not a positive whole number of seconds",
    },
    Row {
        case: "an effect timeout that is a float",
        changes: &[(Operator, &["effect_timeout_seconds"], Some("2.0"))],
        sentence: "effect_timeout_seconds 2.0 is not a positive whole number of seconds",
    },
    Row {
        case: "a region and a role_arn that are no strings",
        changes: &[
            (Operator, &["region"], Some("7")),
            (Operator, &["role_arn"], Some("[]")),
        ],
        sentence: "region 7 is not a string",
    },
    Row {
        case: "attachments and an effect timeout that fail",
        changes: &[
            (Operator, &["attachments"], Some("null")),
            (Operator, &["effect_timeout_seconds"], Some("0")),
        ],
        sentence: "attachments None is not a map from volume ID to a list of instance IDs",
    },
    Row {
        case: "a malformed contract beside a malformed profile",
        changes: &[
            (Operator, &["volumes"], Some("[1]")),
            (
                Profiles,
                &["profiles", "fis-pause", "attachment"],
                Some("\"shared\""),
            ),
        ],
        sentence: "volumes [1] is not a list of strings",
    },
    Row {
        case: "a profile named ../escape",
        changes: &[(Profiles, &["profiles", "../escape"], Some(READ_LATENCY))],
        sentence: "manifest profile '../escape' is not an episode name of letters, digits, '.', '_' and '-' starting with a letter or digit",
    },
    Row {
        case: "a profile named .hidden",
        changes: &[(Profiles, &["profiles", ".hidden"], Some(READ_LATENCY))],
        sentence: "manifest profile '.hidden' is not an episode name of letters, digits, '.', '_' and '-' starting with a letter or digit",
    },
    Row {
        case: "an attachment mode shared",
        changes: &[(
            Profiles,
            &["profiles", "fis-read-latency", "attachment"],
            Some("\"shared\""),
        )],
        sentence: "manifest profile 'fis-read-latency' declares attachment mode 'shared'; the controller implements ['single', 'multi-attach-one']",
    },
    Row {
        case: "no attachment mode",
        changes: &[(Profiles, &["profiles", "fis-pause", "attachment"], None)],
        sentence: "manifest profile 'fis-pause' declares attachment mode None; the controller implements ['single', 'multi-attach-one']",
    },
    Row {
        case: "an unlisted action",
        changes: &[(
            Profiles,
            &["profiles", "fis-pause", "action"],
            Some("\"aws:ebs:detach-volume\""),
        )],
        sentence: "manifest profile 'fis-pause' names action 'aws:ebs:detach-volume', which the manifest's eligible_types does not list",
    },
    Row {
        case: "no action",
        changes: &[(Profiles, &["profiles", "fis-pause", "action"], None)],
        sentence: "manifest profile 'fis-pause' names action None, which the manifest's eligible_types does not list",
    },
    Row {
        case: "a write flag that is a string",
        changes: &[(
            Profiles,
            &["profiles", "fis-read-latency", "write"],
            Some("\"false\""),
        )],
        sentence: "manifest profile 'fis-read-latency' has write 'false', not a JSON boolean",
    },
    Row {
        case: "no read flag",
        changes: &[(Profiles, &["profiles", "fis-read-latency", "read"], None)],
        sentence: "manifest profile 'fis-read-latency' has read None, not a JSON boolean",
    },
    Row {
        case: "no direction",
        changes: &[(
            Profiles,
            &["profiles", "fis-read-latency", "read"],
            Some("false"),
        )],
        sentence: "manifest profile 'fis-read-latency' enables no direction; the template takes 100 percent of the direction under test",
    },
    Row {
        case: "a latency that is a string",
        changes: &[(
            Profiles,
            &["profiles", "fis-read-latency", "latency_ms"],
            Some("\"10\""),
        )],
        sentence: "manifest profile 'fis-read-latency' has latency_ms '10', not a whole number of milliseconds",
    },
    Row {
        case: "a latency that is a boolean",
        changes: &[(
            Profiles,
            &["profiles", "fis-read-latency", "latency_ms"],
            Some("true"),
        )],
        sentence: "manifest profile 'fis-read-latency' has latency_ms True, not a whole number of milliseconds",
    },
    Row {
        case: "no latency",
        changes: &[(
            Profiles,
            &["profiles", "fis-read-latency", "latency_ms"],
            None,
        )],
        sentence: "manifest profile 'fis-read-latency' has latency_ms None, not a whole number of milliseconds",
    },
    Row {
        case: "a latency that is a float",
        changes: &[(
            Profiles,
            &["profiles", "fis-write-latency", "latency_ms"],
            Some("2000.0"),
        )],
        sentence: "manifest profile 'fis-write-latency' has latency_ms 2000.0, not a whole number of milliseconds",
    },
    Row {
        case: "an episode one character past the tag",
        changes: &[(Episode, &[], Some(PAST_TAG))],
        sentence: "episode 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' is 1 characters too long for the template's episode tag",
    },
    Row {
        case: "an episode one character past the receipt name",
        changes: &[(Episode, &[], Some(PAST_RECEIPT))],
        sentence: "episode 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeex' is 1 characters too long for the receipt file name derived from it",
    },
    Row {
        case: "an effect timeout of 600 s",
        changes: &[(Operator, &["effect_timeout_seconds"], Some("600"))],
        sentence: "profile fis-read-latency needs up to 5075 s before its case ends, past its 1800 s case; lower effect_timeout_seconds",
    },
    Row {
        case: "a case of 888 s",
        changes: &[(
            Profiles,
            &["profiles", "fis-read-latency", "case_seconds"],
            Some("888"),
        )],
        sentence: "profile fis-read-latency needs up to 889 s before its case ends, past its 888 s case; lower effect_timeout_seconds",
    },
    Row {
        case: "a case of 888.5 s",
        changes: &[(
            Profiles,
            &["profiles", "fis-read-latency", "case_seconds"],
            Some("888.5"),
        )],
        sentence: "profile fis-read-latency needs up to 889 s before its case ends, past its 888.5 s case; lower effect_timeout_seconds",
    },
    Row {
        case: "profiles of both modes",
        changes: &[(
            Names,
            &[],
            Some("[\"fis-read-latency\", \"fis-read-latency-multi-attach\"]"),
        )],
        sentence: "the chosen profiles name the attachment modes ['multi-attach-one', 'single']; one volume serves one mode",
    },
    Row {
        case: "a multi-attach-one profile with no instance",
        changes: &[
            (Names, &[], Some("[\"fis-read-latency-multi-attach\"]")),
            (
                Operator,
                &["attachments"],
                Some("{\"vol-0123456789abcdef0\": []}"),
            ),
        ],
        sentence: "attachments declares [] for vol-0123456789abcdef0; a multi-attach-one profile takes exactly one instance",
    },
    Row {
        case: "a multi-attach-one profile with two instances",
        changes: &[
            (Names, &[], Some("[\"fis-read-latency-multi-attach\"]")),
            (
                Operator,
                &["attachments"],
                Some("{\"vol-0123456789abcdef0\": [\"i-1\", \"i-2\"]}"),
            ),
        ],
        sentence: "attachments declares ['i-1', 'i-2'] for vol-0123456789abcdef0; a multi-attach-one profile takes exactly one instance",
    },
    Row {
        case: "a multi-attach-one profile with an undeclared volume",
        changes: &[
            (Names, &[], Some("[\"fis-read-latency-multi-attach\"]")),
            (Operator, &["attachments"], Some("{}")),
        ],
        sentence: "attachments declares [] for vol-0123456789abcdef0; a multi-attach-one profile takes exactly one instance",
    },
    Row {
        case: "a lane role the hardware manifest lacks",
        changes: &[(
            Profiles,
            &["profiles", "fis-read-latency", "lane", "role"],
            Some("\"nobody\""),
        )],
        sentence: "the hardware manifest names no lane role for {'profile': 'fis-read', 'role': 'nobody'}: 'nobody'",
    },
    Row {
        case: "a lane profile the hardware manifest lacks",
        changes: &[(
            Profiles,
            &["profiles", "fis-read-latency", "lane", "profile"],
            Some("\"nobody\""),
        )],
        sentence: "the hardware manifest names no lane role for {'profile': 'nobody', 'role': 'owner'}: 'nobody'",
    },
    Row {
        case: "a kill grace one second short",
        changes: &[(Grace, &[], Some("589.0"))],
        sentence: "profile fis-read-latency needs up to 590 s of cleanup and close-out after a signal, past the 589 s kill grace; lower effect_timeout_seconds or --aws-seconds",
    },
    Row {
        case: "a kill grace of 589.5 s",
        changes: &[(Grace, &[], Some("589.5"))],
        sentence: "profile fis-read-latency needs up to 590 s of cleanup and close-out after a signal, past the 589.5 s kill grace; lower effect_timeout_seconds or --aws-seconds",
    },
    Row {
        case: "a poll of zero",
        changes: &[(Poll, &[], Some("\"0\""))],
        sentence: "'0' is not a duration above zero",
    },
    Row {
        case: "a poll of -0.0",
        changes: &[(Poll, &[], Some("\"-0.0\""))],
        sentence: "'-0.0' is not a duration above zero",
    },
    Row {
        case: "a negative poll",
        changes: &[(Poll, &[], Some("\"-1\""))],
        sentence: "'-1' is not a finite duration of zero or more seconds",
    },
    Row {
        case: "a poll of nan",
        changes: &[(Poll, &[], Some("\"nan\""))],
        sentence: "'nan' is not a finite duration of zero or more seconds",
    },
    Row {
        case: "a poll of inf",
        changes: &[(Poll, &[], Some("\"inf\""))],
        sentence: "'inf' is not a finite duration of zero or more seconds",
    },
];
