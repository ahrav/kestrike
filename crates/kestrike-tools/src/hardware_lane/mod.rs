//! The rules a hardware run's controller applies to its inputs: the check of a hardware manifest and its
//! platform rows, an episode name, a seconds value, and the constants of the hardware lane, which is the
//! program `scripts/hardware-lane.py` that the controller starts.
//!
//! A failed rule returns an [`Error`]: the read's system error, text that is no number, or a refusal with
//! its sentence. Where several checks of a manifest fail, the refusal names the first in the check's
//! order, which visits the platform rows, then the profiles, in document order. Inside a profile the
//! profile's own checks run before each role and each of its cases; one of them reads the roles in order
//! up to the first that holds `kill`, so a later role's shape can refuse the profile first.
//!
//! The check reads a decoded value by Python's rules: `==` compares integers, floats and booleans by their
//! numeric values, exactly where an integer meets a float, and a boolean counts as an integer in rules
//! that accept the boolean type. A key read acts on an object alone. An iteration, a set and a count take
//! an object's keys, an array's items and a string's code points, and `in` takes an object's keys, an
//! array's items and a string's substrings. Where a value's kind is one Python cannot read at a point of
//! the check, such as an array read by key, the check refuses at that point with a statement of the shape
//! after `malformed hardware manifest: `.
//!
//! The module's one effect is the read in [`read_manifest`] of the file its caller names.

mod arguments;
mod constants;
mod error;
mod manifest;
mod shape;

pub use arguments::{PLATFORM_NAMED_BY, episode_name, finite_seconds, platform_refusal};
pub use constants::{
    CASE_KEYS, CHANNEL, CONTROLLER_SECONDS, CUSTODY_DIR, DISPOSITIONS, ENVELOPE_FIELDS,
    ENVIRONMENT_NAME, EPISODE_NAME, HELD, IDENTITY_LINES, INTERRUPTED, MANIFEST, OBSERVED,
    OBSERVER_SECONDS, OPTIONAL_PROFILE_KEYS, PROFILE_KEYS, ROLE_KEYS, STOP_SECONDS, UNREAD,
    identity_lines, is_environment_name, is_episode_name, manifest_path,
};
pub use error::Error;
pub use manifest::{check_manifest, read_manifest};
