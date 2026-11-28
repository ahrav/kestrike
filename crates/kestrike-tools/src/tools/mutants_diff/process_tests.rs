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
