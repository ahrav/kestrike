//! Every case under `tests/` is a module of this one test executable: a file `<case>.rs`, or a directory
//! `<case>/` with a `mod.rs`. The generated `cases.rs` declares each case module and the constant `CASES`,
//! the entry names listed when the package was built.

use std::fs;
use std::path::Path;

include!(concat!(env!("OUT_DIR"), "/cases.rs"));

/// The entries of `tests/` at run time, other than this file, are exactly `CASES`, so a case that the last
/// listing missed fails this test.
#[test]
fn every_entry_of_tests_is_a_case() {
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut entries: Vec<String> = fs::read_dir(&tests)
        .expect("tests/ lists")
        .map(|entry| {
            let name = entry.expect("tests/ lists").file_name();
            name.into_string()
                .expect("each entry of tests/ is named in UTF-8")
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
