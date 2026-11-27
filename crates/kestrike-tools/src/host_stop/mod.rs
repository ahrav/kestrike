//! The host stop controller's layer over the system: a mark's write, the evidence lock, the probe and
//! the lookup, the one `aws` child of a call, the two clocks, the sleep and the signal record. Each
//! failure is a typed value. A file step's failure carries the system's error and the step it ended;
//! a call that gives no answer carries its reason as text, and one that exits carries its code and
//! the tail of its standard error. A command composes its refusal from that value; a failed call's
//! sentence is the `Display` of [`CallFailed`], and a mark's write states its failure with
//! [`Unwritten::sentence`].
//!
//! The file steps are the methods of [`Files`], and the call, the clocks and the sleep the methods of
//! [`Seam`]; a command takes each as a value, so a test substitutes one step. The module starts `aws`
//! and no other program. A signal raises at a read of the [`Record`], which a command makes between
//! its steps and which a wait or a sleep makes at least once a [`SLICE`].

mod calendar;
mod call;
mod constants;
mod encoded;
mod evidence;
mod files;
mod forms;
mod inputs;
mod launch;
mod mark;
mod number;
mod operator;
mod preflight;
mod record;
mod replies;
mod review;
mod seam;
mod snapshot;
mod words;

pub use calendar::posix_seconds;
pub use call::{CallError, reply};
pub use constants::{
    ACTION, ALARM_NAME_MAX, BOUNDS, CALL_SECONDS, DETAIL_MAX, INSTANCE, ISO, LAUNCH, LIMIT_SECONDS,
    MAX_INSTANCES, MISSING_DATA, POLL_SECONDS, REGION, RESTORATION, SKEW_SECONDS, STEPS_PREFIX,
    STEPS_TAIL, USER_SHUTDOWN, USER_STOP, health,
};
pub use encoded::encoded;
pub use evidence::{Lock, LockError, ProbeError, lock, probe, stands};
pub use files::{Disk, Files, Links};
pub use forms::{instance_id, iso_time, plain, steps_tail};
pub use inputs::{read_bytes, read_json};
pub use launch::{AWS, Call, CallFailed, Ended, Failure, launch};
pub use mark::{Step, Unwritten, publish, sync_directory};
pub use number::Number;
pub use operator::{Approval, Operator, read_operator};
pub use preflight::{Run, check_run, gd2_of};
pub use record::{DELIVERED, Delivered, Interrupted, Record, SLICE, Signal, install};
pub use replies::{
    Alarm, FailedCall, InstanceRecord, Status, launch_time, read_alarms, read_record, read_statuses,
};
pub use review::{check_reviewed, check_stopped};
pub use seam::{Seam, System, sleep};
pub use snapshot::{HostLine, InstanceState, Report, Snapshot, build_roles, read_snapshot};
