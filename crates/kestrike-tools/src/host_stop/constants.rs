//! Each pattern here matches a whole text of ASCII characters, so a text that holds a surrogate matches
//! none, and each bound named in seconds is a whole number of them.

use std::sync::LazyLock;

use regex::Regex;

use crate::classes::compiled;

/// GD-2's injection action this controller was written for.
pub const ACTION: &str =
    "stop the instance of one host that owns several shards and is the named standby of others";
/// GD-2's restoration class this controller was written for.
pub const RESTORATION: &str = "persistent-manual";
/// The operator file's four bounds in seconds, in the order the controller checks them.
pub const BOUNDS: [&str; 4] = [
    "snapshot_max_age_seconds",
    "effect_timeout_seconds",
    "observe_seconds",
    "deadline_seconds",
];
/// The longest bound an operator file may set, in seconds.
pub const LIMIT_SECONDS: i64 = 86_400;
/// The pause between two polls, in seconds.
pub const POLL_SECONDS: i64 = 5;
/// The longest one call of the AWS CLI may take, in seconds.
pub const CALL_SECONDS: i64 = 60;
/// The clock difference admitted between the controller and the control plane, in seconds.
pub const SKEW_SECONDS: i64 = 5;
/// The most characters of an abort mark's detail.
pub const DETAIL_MAX: usize = 4_000;
/// The most instances an operator file declares.
pub const MAX_INSTANCES: usize = 100;
/// The most characters of an alarm name.
pub const ALARM_NAME_MAX: usize = 255;
/// The ways a metric alarm may treat missing data, stated in its row, and still read `ALARM` or
/// `INSUFFICIENT_DATA` without data.
pub const MISSING_DATA: [&str; 2] = ["missing", "breaching"];
/// The state reason code of an instance a user's request stopped.
pub const USER_SHUTDOWN: &str = "Client.UserInitiatedShutdown";
/// The words before the steps' digest at the end of an abort mark's detail.
pub const STEPS_PREFIX: &str = "; restoration steps sha256 ";

/// An AWS region name: two letters, one or more `-` and letters, then `-` and digits.
pub static REGION: LazyLock<Regex> = LazyLock::new(|| compiled(r"\A[a-z]{2}(-[a-z]+)+-[0-9]+\z"));
/// An instance ID: `i-` and 1 to 17 lowercase letters or digits.
pub static INSTANCE: LazyLock<Regex> = LazyLock::new(|| compiled(r"\Ai-[0-9a-z]{1,17}\z"));
/// An ISO time `YYYY-MM-DDTHH:MM:SSZ` with seconds 00 to 59.
pub static ISO: LazyLock<Regex> =
    LazyLock::new(|| compiled(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9]Z\z"));
/// A stop's transition reason, capturing its second `YYYY-MM-DD HH:MM:SS`.
pub static USER_STOP: LazyLock<Regex> = LazyLock::new(|| {
    compiled(
        r"\AUser initiated \(([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-5][0-9]) GMT\)\z",
    )
});
/// The end of an abort mark's detail: [`STEPS_PREFIX`] and 64 lowercase hexadecimal digits.
pub static STEPS_TAIL: LazyLock<Regex> =
    LazyLock::new(|| compiled(r"\A; restoration steps sha256 [0-9a-f]{64}\z"));
/// A record's `LaunchTime`, capturing its second `YYYY-MM-DDTHH:MM:SS` and its fraction of up to nine
/// digits with the point.
pub static LAUNCH: LazyLock<Regex> = LazyLock::new(|| {
    compiled(
        r"\A([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9])(\.[0-9]{1,9})?(?:Z|\+00:00)\z",
    )
});

/// The word a standby's `host_report` holds for its snapshot report: `healthy`, `unhealthy`, or
/// `no report` for a host whose line holds none.
pub fn health(healthy: Option<bool>) -> &'static str {
    match healthy {
        Some(true) => "healthy",
        Some(false) => "unhealthy",
        None => "no report",
    }
}
