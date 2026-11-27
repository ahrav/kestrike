//! Every case under `tests/` is a module of this one test executable: a file `<case>.rs`, or a directory
//! `<case>/` with a `mod.rs`. The generated `cases.rs` declares each case module and the constant `CASES`,
//! the entry names listed when the package was built.

include!(concat!(env!("OUT_DIR"), "/cases.rs"));

/// The test applies the build script's case filters to `tests/` at run time and compares the names with
/// `CASES`, so the test fails if the build script missed a case.
#[test]
fn every_entry_of_tests_is_a_case() {
    let tests = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut entries: Vec<String> = std::fs::read_dir(&tests)
        .expect("tests/ lists")
        .map(|entry| entry.expect("tests/ lists"))
        .filter(|entry| {
            let name = entry.file_name();
            let bytes = name.as_encoded_bytes();
            !bytes.starts_with(b".")
                && (bytes.ends_with(b".rs")
                    || match std::fs::metadata(entry.path()) {
                        Ok(to) => to.is_dir(),
                        Err(error) => {
                            assert!(
                                matches!(
                                    error.kind(),
                                    std::io::ErrorKind::NotFound
                                        | std::io::ErrorKind::NotADirectory
                                ),
                                "{}: {error}",
                                entry.path().display()
                            );
                            false
                        }
                    })
        })
        .map(|entry| {
            let name = entry.file_name();
            name.into_string()
                .expect("each case of tests/ is named in UTF-8")
        })
        .filter(|name| name != "tools.rs")
        .collect();
    entries.sort_unstable();
    assert_eq!(
        entries,
        CASES,
        "the build listed {CASES:?} in {}",
        tests.display()
    );
}
