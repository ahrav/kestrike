//! Every case under `tests/` is a module of this one test executable: a file `<case>.rs`, or a directory
//! `<case>/` with a `mod.rs`. The generated `cases.rs` declares each case module and the constant `CASES`,
//! the entry names listed when the package was built.

include!(concat!(env!("OUT_DIR"), "/cases.rs"));

/// `case_id` is the test id of the fn `name` of the module `module`, as `module_path!` writes it: the
/// path without the test executable's own name.
pub fn case_id(module: &str, name: &str) -> String {
    let (_, path) = module
        .split_once("::")
        .expect("a case module lies under the test executable");
    format!("{path}::{name}")
}

const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut at = 0;
    while at < a.len() {
        if a[at] != b[at] {
            return false;
        }
        at += 1;
    }
    true
}

/// The test applies the build script's case filters to `tests/` at run time and compares the names with
/// `CASES`, so the test fails if the build script missed a case.
#[test]
fn every_entry_of_tests_is_a_case() {
    let tests = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut entries: Vec<String> = std::fs::read_dir(&tests)
        .expect("tests/ lists")
        .filter_map(|entry| {
            let entry = entry.expect("tests/ lists");
            let name = entry.file_name();
            let bytes = name.as_encoded_bytes();
            let checked = !bytes.starts_with(b".")
                && bytes != b"tools.rs"
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
                    });
            checked.then(|| {
                name.into_string()
                    .expect("each case of tests/ is named in UTF-8")
            })
        })
        .collect();
    entries.sort_unstable();
    assert_eq!(
        entries,
        CASES,
        "the build listed {CASES:?} in {}",
        tests.display()
    );
}
