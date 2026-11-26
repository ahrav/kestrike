//! The outer command's result for each end of a scoped run.

use super::*;

/// A scoped command ends in the class its run exited with when that is a
/// rejection or a busy state, so the command exits alike with and
/// without a cgroup root. Every other end than success is a hold: a
/// verdict or a hold of the run, a panic's exit, a signal, and with them a
/// `systemd-run` that fails before it runs the command.
#[test]
fn a_scoped_command_ends_in_the_class_of_its_run() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    use crate::exit::{Exit, Supervisor};

    let exited =
        |class: Supervisor| ExitStatus::from_raw(i32::from(Exit::Supervisor(class).code()) << 8);
    assert!(ended("confirm", exited(Supervisor::Success)).is_ok());
    for class in [Supervisor::Rejected, Supervisor::Busy] {
        assert_eq!(ended("confirm", exited(class)).unwrap_err().exit(), class);
    }
    for status in [
        exited(Supervisor::Verdict),
        exited(Supervisor::Held),
        ExitStatus::from_raw(101 << 8),
        ExitStatus::from_raw(9),
    ] {
        assert_eq!(ended("sweep", status).unwrap_err().exit(), Supervisor::Held);
    }
}
