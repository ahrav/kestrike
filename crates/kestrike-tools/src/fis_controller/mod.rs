//! The checks the FIS controller makes of its inputs before any call, and the bounds of one episode.
//! The controller runs each episode's case under the hardware lane, the program
//! `scripts/hardware-lane.py` that it starts, and reads the lane's seconds and episode names through
//! [`crate::hardware_lane`].
//!
//! Each check and bound is a function of decoded values: the operator contract, the FIS profiles file,
//! the names of the chosen profiles, the episode name and the seconds the caller names. It returns a
//! value or a [`Rejected`] with the controller's sentence, and where several checks fail, the first in
//! its documented order. The checks read a decoded value by Python's rules: a key read, a count and an
//! iteration act on an object's keys in document order, an array's items and a string's code points,
//! and a list in a sentence is written as Python's `repr` writes a list of strings. A member a check
//! reads without a check of its own and finds absent or of another kind is a rejection where it is
//! read.
//!
//! [`check_operator`] admits the contract as an [`Operator`] and [`check_manifest`] the profiles file
//! as a [`Manifest`]; the checks and bounds after them take those. A bound is a sum of seconds and
//! starts no timer. [`Error::Overflow`] stands for a whole number of seconds that converts to a float
//! past the largest, and [`Error::OutOfRange`] for a lane whose whole number names no item of a
//! list.
//! The module makes no call, starts no process, reads no clock and writes nothing; its one effect is
//! the read in [`close_seconds`] of the hardware manifest its caller names.

mod arguments;
mod bounds;
mod constants;
mod error;
mod lane_role;
mod operator;
mod profiles;
mod seconds;

pub use arguments::positive_seconds;
pub use bounds::{
    check_grace, check_profiles, cleanup_bound, episode_bound, phase_bound, run_bound,
};
pub use constants::{
    ATTACHMENT_MODES, CLEANUP_CALLS, CLEANUP_PATH_WINDOWS, CLEANUP_WINDOWS, CLOSE_OUT_SECONDS,
    DEFAULT_BUDGET_SECONDS, KILL_GRACE_SECONDS, NAME_MAX, OBSERVER_OPERATIONS, OPERATOR_KEYS,
    RUN_CALLS, RUN_WINDOWS, TAG_VALUE_MAX,
};
pub use error::{Error, Rejected};
pub use lane_role::close_seconds;
pub use operator::{Operator, check_operator, strings};
pub use profiles::{Manifest, check_attachments, check_episode, check_manifest};
