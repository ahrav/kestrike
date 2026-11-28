use super::process::Interrupt;

#[test]
fn an_empty_command_fails_and_leaves_both_output_files_unchanged() {
    let scratch = crate::paths::tests::Scratch::new("empty-command");
    let (stdout, stderr) = (scratch.0.join("out"), scratch.0.join("err"));
    std::fs::write(&stdout, "out before").expect("written");
    std::fs::write(&stderr, "err before").expect("written");
    let stop = super::process::supervise(&Interrupt::new(), &[], &stdout, &stderr, None, &[])
        .expect_err("an empty command fails");
    assert_eq!(stop.code(), 1);
    assert_eq!(
        (
            std::fs::read_to_string(&stdout).expect("read"),
            std::fs::read_to_string(&stderr).expect("read")
        ),
        ("out before".to_owned(), "err before".to_owned())
    );
}

/// Each output file is created new: an entry at either path, a link to a file included, fails the start
/// and leaves the entry and the file it names as they were.
#[test]
fn an_output_file_that_exists_fails_the_start_and_stays_as_it_was() {
    let scratch = crate::paths::tests::Scratch::new("taken-output");
    let (target, link, err) = (
        scratch.0.join("target"),
        scratch.0.join("out"),
        scratch.0.join("err"),
    );
    std::fs::write(&target, "target before").expect("written");
    std::os::unix::fs::symlink(&target, &link).expect("the link is made");
    let argv = [std::ffi::OsStr::new("true")];
    let stop = super::process::supervise(&Interrupt::new(), &argv, &link, &err, None, &[])
        .expect_err("a taken output path fails the start");
    assert_eq!(stop.code(), 1);
    assert!(
        std::fs::symlink_metadata(&link).is_ok_and(|status| status.is_symlink()),
        "the link stays"
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("read"),
        "target before"
    );
    std::fs::write(&err, "err before").expect("written");
    let out = scratch.0.join("out2");
    let stop = super::process::supervise(&Interrupt::new(), &argv, &out, &err, None, &[])
        .expect_err("a taken error path fails the start");
    assert_eq!(stop.code(), 1);
    assert_eq!(std::fs::read_to_string(&err).expect("read"), "err before");
}

/// A supervised run's result takes a failed stop first, then a failed wait, then the stop's outcome: a
/// reap gives the exit code, a leader reaped elsewhere fails as a wait with `ECHILD`, and a leader that
/// outlived its stop fails as a wait that timed out.
#[test]
fn a_supervised_run_concludes_from_its_wait_and_then_its_stop() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    use super::process::concluded;
    use super::stop::{Fault, Stop};
    use crate::process::GroupStopped;
    let failed = |error: std::io::Error| Stop::failed(&Fault::os(&error, None));
    let reaped = |raw: i32| Ok(GroupStopped::Reaped(ExitStatus::from_raw(raw)));
    assert_eq!(concluded(Ok(()), reaped(3 << 8)), Ok(3));
    assert_eq!(concluded(Ok(()), reaped(libc::SIGKILL)), Ok(-libc::SIGKILL));
    let probe = failed(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "the state reads no state",
    ));
    assert_eq!(concluded(Err(probe.clone()), reaped(0)), Err(probe.clone()));
    let refused = || std::io::Error::from_raw_os_error(libc::EPERM);
    assert_eq!(
        concluded(Err(probe), Err(refused())),
        Err(failed(refused()))
    );
    assert_eq!(
        concluded(Ok(()), Ok(GroupStopped::ReapedElsewhere)),
        Err(failed(std::io::Error::from_raw_os_error(libc::ECHILD)))
    );
    let outlived = concluded(Ok(()), Ok(GroupStopped::Running)).expect_err("a leader still runs");
    assert_eq!(
        outlived,
        failed(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the child outlived its stop"
        ))
    );
    assert_eq!(
        concluded(Err(Stop::interrupted(libc::SIGTERM)), Ok(GroupStopped::Running)),
        Err(Stop::interrupted(libc::SIGTERM))
    );
}
