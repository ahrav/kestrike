//! The tool envelope's declared values. Runs of real tools against it
//! spawn processes, so they live in the `kernel_tools` test process.

use std::time::Duration;

use super::tool::{LIMITS, Limits};

/// The production envelope is 1 MiB of each stream, 30 seconds from spawn
/// and 5 seconds of reaping.
#[test]
fn the_tool_envelope_is_one_mib_streams_thirty_seconds_and_a_five_second_reap() {
    assert_eq!(
        LIMITS,
        Limits {
            stdout: 1 << 20,
            stderr: 1 << 20,
            total: Duration::from_secs(30),
            cleanup: Duration::from_secs(5),
        }
    );
}
