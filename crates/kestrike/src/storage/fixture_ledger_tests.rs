//! The fixture ledger, `format-fixtures.sha256` at the crate root, pins the
//! bytes of every file in the covered fixture directories. It holds one
//! `<digest>  <path>` line per file, in the form `sha256sum` prints, with the
//! path relative to the crate, so `sha256sum -c format-fixtures.sha256` run
//! from the crate checks the same rows with an independent implementation.
//!
//! The covered fixture files and the ledger lines are append-only: a change
//! adds a fixture file together with its ledger line, and keeps every existing
//! file's bytes and every existing line unchanged. A stored generation is a
//! covered fixture file for which the test source fixes the expected outcome:
//! the decoded value, or the typed refusal that names the version in its
//! bytes. A row of the record `VECTORS` table is one such expected outcome,
//! and it is append-only on the same terms. The one exception is a change that
//! removes a format's decoder, which removes that format's fixtures, ledger
//! lines and expected outcomes with it.
//!
//! A round-trip test can pass after an incompatible format change when the
//! encoder and decoder agree on the new format. The decoder tests over bytes an
//! earlier build wrote show what current code does with those bytes, so
//! rewriting a fixture in place discards that evidence.
//!
//! The committed-tree test observes one snapshot of the crate: every file of a
//! covered directory has one row whose digest matches its bytes, and every row
//! names a listed file. The other tests run `check` and `listing` on fixed
//! inputs. A change that rewrites a fixture file and its ledger row together
//! passes these tests, so review holds the append-only rule.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::store_tests::fresh_directory;

const LEDGER: &str = "format-fixtures.sha256";

/// The directories whose files the ledger lists, relative to the crate.
const COVERED: [&str; 4] = [
    "src/storage/record/fixtures",
    "src/sim/fixtures",
    "src/storage/recovery/fixtures",
    "src/failover/fixtures",
];

/// Checks `ledger` against `files`, each a crate-relative path with its bytes.
///
/// Each line's first pair of consecutive spaces separates the digest from the
/// path. A file matches its row when the row's digest text equals the lowercase
/// hex SHA-256 of the file's bytes, so a malformed digest reports as a mismatch.
///
/// # Errors
///
/// Returns the first failure, checked in this order:
///
/// - Ledger lines, top to bottom: `line <n> is not ...` for a line missing the
///   separator, and `<path> has two rows` for a path an earlier line already
///   named.
/// - `files`, in slice order: `<path> has no row` for a file missing from the
///   rows, and `<path> differs from its row` for a digest mismatch.
/// - Rows left after every file matched: `<path> names no file` for the
///   lexicographically smallest remaining path.
fn check(ledger: &str, files: &[(String, Vec<u8>)]) -> Result<(), String> {
    let mut rows = BTreeMap::new();
    for (at, line) in ledger.lines().enumerate() {
        let (digest, path) = (line.split_once("  "))
            .ok_or_else(|| format!("line {} is not `<digest>  <path>`", at + 1))?;
        if rows.insert(path, digest).is_some() {
            return Err(format!("{path} has two rows"));
        }
    }
    for (path, bytes) in files {
        let row = rows
            .remove(path.as_str())
            .ok_or_else(|| format!("{path} has no row"))?;
        let digest: String = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if digest != row {
            return Err(format!("{path} differs from its row"));
        }
    }
    match rows.keys().next() {
        Some(path) => Err(format!("{path} names no file")),
        None => Ok(()),
    }
}

/// Returns each regular file directly inside a `covered` directory with its
/// `root`-relative path and bytes, in `covered` order and in `read_dir` order
/// within each directory. A directory whose
/// `read_dir` reports `NotFound` lists as empty.
///
/// # Errors
///
/// - Any other `read_dir`, entry, file-type, or file read failure, prefixed with
///   the directory or entry path.
/// - An entry name that contains invalid UTF-8.
/// - An entry that fails the regular-file check. A symbolic link fails it
///   because `DirEntry::file_type` reports the link itself.
fn listing(root: &Path, covered: &[&str]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut files = Vec::new();
    for dir in covered {
        let entries = match std::fs::read_dir(root.join(dir)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("{dir}: {error}")),
        };
        for entry in entries {
            let entry = entry.map_err(|error| format!("{dir}: {error}"))?;
            let name = (entry.file_name().into_string())
                .map_err(|name| format!("{dir}: {name:?} is not UTF-8"))?;
            let path = format!("{dir}/{name}");
            let kind = entry
                .file_type()
                .map_err(|error| format!("{path}: {error}"))?;
            if !kind.is_file() {
                return Err(format!("{path} is not a regular file"));
            }
            let bytes = std::fs::read(entry.path()).map_err(|error| format!("{path}: {error}"))?;
            files.push((path, bytes));
        }
    }
    Ok(files)
}

/// The covered files and the ledger rows are the same set of paths, and each
/// row's digest equals the SHA-256 of its file's bytes.
#[test]
fn every_fixture_file_matches_its_ledger_row_and_every_row_names_a_file() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let ledger = std::fs::read_to_string(root.join(LEDGER)).unwrap();
    let mut files = listing(root, &COVERED).unwrap();
    files.sort();
    assert_eq!(check(&ledger, &files), Ok(()));
}

/// The SHA-256 of `abc` and of the empty input, from the published SHA-256
/// test vectors, so the control ledger's digests come from outside `check`.
const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// `check` reports each mismatch with the affected path or the malformed line
/// number. Rows are unique by path, so a second row for a path fails whether
/// its digest differs or repeats the first.
#[test]
fn a_changed_missing_or_unlisted_fixture_fails_the_ledger_check() {
    let abc = "src/sim/fixtures/abc.bin";
    let empty = "src/storage/record/fixtures/empty.bin";
    let ledger = format!("{ABC}  {abc}\n{EMPTY}  {empty}\n");
    let files = vec![
        (abc.to_string(), b"abc".to_vec()),
        (empty.to_string(), Vec::new()),
    ];
    assert_eq!(check(&ledger, &files), Ok(()));

    let mut flipped = files.clone();
    flipped[0].1[0] ^= 0x01;
    assert_eq!(
        check(&ledger, &flipped),
        Err(format!("{abc} differs from its row"))
    );

    assert_eq!(
        check(&ledger, &files[1..]),
        Err(format!("{abc} names no file"))
    );

    let mut extra = files.clone();
    extra.push(("src/sim/fixtures/unlisted.bin".into(), vec![0x5A; 16]));
    assert_eq!(
        check(&ledger, &extra),
        Err("src/sim/fixtures/unlisted.bin has no row".into())
    );

    let conflicting = format!("{ledger}{EMPTY}  {abc}\n");
    assert_eq!(
        check(&conflicting, &files),
        Err(format!("{abc} has two rows"))
    );

    let copied = format!("{ledger}{ABC}  {abc}\n");
    assert_eq!(check(&copied, &files), Err(format!("{abc} has two rows")));

    for digest in [ABC.to_uppercase(), ABC[..63].to_string()] {
        let respelled = format!("{digest}  {abc}\n{EMPTY}  {empty}\n");
        assert_eq!(
            check(&respelled, &files),
            Err(format!("{abc} differs from its row"))
        );
    }

    let leftovers = format!("{EMPTY}  {empty}\n{ABC}  {abc}\n");
    assert_eq!(check(&leftovers, &[]), Err(format!("{abc} names no file")));

    let outside = format!("{ledger}{ABC}  src/lib.rs\n");
    assert_eq!(
        check(&outside, &files),
        Err("src/lib.rs names no file".into())
    );

    let malformed = format!("{ledger}{ABC}\n");
    assert_eq!(
        check(&malformed, &files),
        Err("line 3 is not `<digest>  <path>`".into())
    );
}

/// Ledger rows cover regular files with UTF-8 names directly inside each
/// covered directory. `listing` rejects other entries, and a covered path that
/// is a file fails its `read_dir`. `listing` treats an absent covered directory
/// as empty and continues with the remaining directories.
#[test]
fn the_listing_refuses_a_non_file_entry_and_lists_an_absent_directory_as_empty() {
    let root = fresh_directory("fixture-ledger");
    std::fs::create_dir_all(root.join("covered/nested")).unwrap();
    std::fs::create_dir(root.join("linked")).unwrap();
    std::fs::write(root.join("plain"), [0x5A; 16]).unwrap();
    std::os::unix::fs::symlink(root.join("plain"), root.join("linked/plain")).unwrap();
    std::fs::create_dir(root.join("named")).unwrap();
    std::fs::write(
        root.join("named").join(OsStr::from_bytes(b"\xFF")),
        [0x5A; 16],
    )
    .unwrap();
    assert_eq!(
        listing(&root, &["absent", "covered"]).err(),
        Some("covered/nested is not a regular file".into())
    );
    assert_eq!(
        listing(&root, &["linked"]).err(),
        Some("linked/plain is not a regular file".into())
    );
    assert_eq!(
        listing(&root, &["named"]).err(),
        Some(r#"named: "\xFF" is not UTF-8"#.into())
    );
    let plain = listing(&root, &["plain"]).unwrap_err();
    assert!(plain.starts_with("plain: "), "{plain}");
    assert_eq!(listing(&root, &["absent"]), Ok(Vec::new()));
    std::fs::remove_dir_all(&root).unwrap();
}

/// A file in the recovery fixture directory needs a ledger row. Over a scratch
/// tree that holds only such a file, `listing` with `COVERED` reports the file
/// and `check` fails it against an empty ledger.
#[test]
fn the_covered_directories_include_the_recovery_fixture_directory() {
    let root = fresh_directory("fixture-ledger-covered");
    std::fs::create_dir_all(root.join("src/storage/recovery/fixtures")).unwrap();
    std::fs::write(
        root.join("src/storage/recovery/fixtures/probe.bin"),
        [0x5A; 16],
    )
    .unwrap();
    assert_eq!(
        listing(&root, &COVERED).and_then(|files| check("", &files)),
        Err("src/storage/recovery/fixtures/probe.bin has no row".into())
    );
    std::fs::remove_dir_all(&root).unwrap();
}
