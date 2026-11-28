//! The counts and limits of one episode that the bounds sum, and the keys and modes the checks admit.

/// The effect-timeout windows of one episode's run, each an operator's effect timeout long: the template,
/// the start, the first timeout, the terminal state or stop, and the restoration status.
pub const RUN_WINDOWS: u32 = 5;

/// The effect-timeout windows of one episode's cleanup: the abandon wait and the template's deletion.
pub const CLEANUP_WINDOWS: u32 = 2;

/// The AWS calls of a run outside its windows: the target checks after readiness and after the template,
/// and the stop request before a proven stop's window.
pub const RUN_CALLS: u32 = 3;

/// The AWS calls of a cleanup outside its windows: one stop request for an experiment a cut run left live,
/// or for one the deleted template's listing names after a lost start, and that listing after the windows.
pub const CLEANUP_CALLS: u32 = 2;

/// The observer log reads and marks of one episode that run past a window or between windows.
pub const OBSERVER_OPERATIONS: u32 = 7;

/// The kill grace a run has for its cleanup after a signal when the caller names none, in seconds.
pub const KILL_GRACE_SECONDS: u32 = 900;

/// The effect-timeout windows of the cleanup's longest path after a signal.
pub const CLEANUP_PATH_WINDOWS: u32 = 5;

/// The seconds reserved after the cleanup, within the kill grace, for the quarantine marker and the
/// receipt.
pub const CLOSE_OUT_SECONDS: u32 = 60;

/// The most characters FIS takes in a tag value.
pub const TAG_VALUE_MAX: usize = 256;

/// The most bytes Linux takes in one file name component.
pub const NAME_MAX: usize = 255;

/// The campaign budget a run receives when the caller names none, in seconds.
pub const DEFAULT_BUDGET_SECONDS: u32 = 13000;

/// The keys an operator contract holds, and no other.
pub const OPERATOR_KEYS: [&str; 7] = [
    "account",
    "region",
    "role_arn",
    "volumes",
    "attachments",
    "effect_timeout_seconds",
    "stop_alarms",
];

/// The attachment modes the controller implements, in the order a rejection lists them: `single` admits a
/// volume with Multi-Attach disabled and at most one attachment, and `multi-attach-one` a volume with
/// Multi-Attach enabled and exactly one settled attachment, the declared one.
pub const ATTACHMENT_MODES: [&str; 2] = ["single", "multi-attach-one"];
