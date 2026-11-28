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
