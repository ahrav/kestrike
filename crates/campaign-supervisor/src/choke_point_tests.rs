//! The filesystem choke point: outside `store` and `sys`, no production
//! source names the standard filesystem API, a `Path` filesystem query, the
//! process's working directory or executable path, a raw or owned
//! descriptor, a Unix socket, or libc, and `unsafe` appears only in `sys`.

use std::fs;
use std::path::Path;

/// Identifiers that name a filesystem or system call entry point: the
/// filesystem module and its types, `Path`'s filesystem queries, the
/// working-directory, path-resolution and executable-path calls, the descriptor traits and
/// types, the Unix socket types, and libc.
const FILESYSTEM: [&str; 31] = [
    "fs",
    "File",
    "OpenOptions",
    "DirBuilder",
    "read_dir",
    "metadata",
    "symlink_metadata",
    "exists",
    "try_exists",
    "canonicalize",
    "read_link",
    "is_file",
    "is_dir",
    "is_symlink",
    "fd",
    "libc",
    "syscall",
    "current_dir",
    "set_current_dir",
    "current_exe",
    "absolute",
    "AsRawFd",
    "IntoRawFd",
    "AsFd",
    "FromRawFd",
    "OwnedFd",
    "BorrowedFd",
    "RawFd",
    "UnixStream",
    "UnixListener",
    "UnixDatagram",
];

/// The forbidden identifiers `source` uses outside comments, in order, then
/// `unsafe`.
fn flagged(source: &str) -> Vec<&'static str> {
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let tokens: Vec<&str> = code
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .collect();
    let mut found: Vec<&'static str> = FILESYSTEM
        .into_iter()
        .filter(|name| tokens.contains(name))
        .collect();
    if tokens.contains(&"unsafe") {
        found.push("unsafe");
    }
    found
}

/// Every production source of the crate, test files left out, by path
/// relative to `src`.
fn sources(dir: &Path, relative: &Path, found: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(dir).expect("the source directory lists") {
        let entry = entry.expect("the entry reads");
        let (path, relative) = (entry.path(), relative.join(entry.file_name()));
        if path.is_dir() {
            sources(&path, &relative, found);
        } else if !relative.to_string_lossy().ends_with("_tests.rs")
            && relative != Path::new("store/fixture.rs")
        {
            let text = fs::read_to_string(&path).expect("the source reads");
            found.push((relative.to_string_lossy().into_owned(), text));
        }
    }
}

/// The matcher flags an aliased grouped import, a `Path` query, a libc call
/// and `unsafe`; separately, a working-directory change, a Unix socket and
/// a descriptor import, each by a token no other control holds; and it
/// passes a process extension import and the attribute that denies unsafe
/// code.
#[test]
fn the_search_flags_planted_filesystem_calls() {
    let planted =
        "use std::{fs as f};\nfn g() { Path::new(\"/\").exists(); libc::close(0); unsafe {} }";
    assert_eq!(flagged(planted), ["fs", "exists", "libc", "unsafe"]);
    assert_eq!(
        flagged("fn g() { std::env::set_current_dir(\"/\"); }"),
        ["set_current_dir"]
    );
    assert_eq!(
        flagged("fn g() { std::path::absolute(\"a\"); }"),
        ["absolute"]
    );
    assert_eq!(
        flagged("use std::os::unix::net::UnixListener;"),
        ["UnixListener"]
    );
    assert_eq!(flagged("use std::os::unix::io::OwnedFd;"), ["OwnedFd"]);
    assert_eq!(
        flagged("use std::os::unix::process::CommandExt;"),
        Vec::<&str>::new()
    );
    assert_eq!(
        flagged("#![deny(unsafe_code)]\n// File and fs in a comment\n"),
        Vec::<&str>::new()
    );
}

/// The search covers every production file, and finds filesystem calls
/// only in `store/` and `sys.rs` and `unsafe` only in `sys.rs`.
#[test]
fn only_the_store_and_sys_modules_call_the_filesystem() {
    let mut found = Vec::new();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    sources(&src, Path::new(""), &mut found);
    let names: Vec<&str> = found.iter().map(|(name, _)| name.as_str()).collect();
    for expected in [
        "lib.rs",
        "main.rs",
        "exit.rs",
        "step.rs",
        "sys.rs",
        "store/mod.rs",
        "store/open.rs",
    ] {
        assert!(
            names.contains(&expected),
            "the search misses {expected}: {names:?}"
        );
    }
    for (name, text) in &found {
        if name == "sys.rs" {
            continue;
        }
        let flagged = flagged(text);
        if name.starts_with("store/") {
            assert!(!flagged.contains(&"unsafe"), "{name} holds unsafe code");
        } else {
            assert!(flagged.is_empty(), "{name} names {flagged:?}");
        }
    }
}

fn gate_access(source: &str) -> bool {
    let code = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|token| token == "Gate")
}

#[test]
fn gate_capability_stays_in_the_exit_owner_and_binary_dispatch() {
    assert!(gate_access(
        "use crate::exit::Gate as G; fn f() { G::run(&[]); }"
    ));
    let mut found = Vec::new();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    sources(&src, Path::new(""), &mut found);
    let mut owners = Vec::new();
    for (name, text) in found {
        if gate_access(&text) {
            owners.push(name);
        }
    }
    owners.sort();
    assert_eq!(owners, ["exit.rs", "main.rs"]);
}

/// Whether `source` names the scan bound constant as a whole token.
fn names_scan_bound(source: &str) -> bool {
    source
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|token| token == "SCAN_BOUND")
}

/// The matcher flags a path and an aliased import of the constant and
/// passes a longer identifier and the accessor.
#[test]
fn the_search_flags_planted_scan_bound_names() {
    assert!(names_scan_bound("store.list(&dir, crate::SCAN_BOUND)"));
    assert!(names_scan_bound("use crate::SCAN_BOUND as SCAN_MAX;"));
    assert!(!names_scan_bound("const SCAN_BOUND_X: usize = 1;"));
    assert!(!names_scan_bound("store.list(&dir, crate::scan_bound())"));
}

/// Outside `lib.rs`, no production source names the scan bound constant,
/// so every listing, census and projection reads it through
/// `scan_bound`, which a test's step script can lower.
#[test]
fn only_scan_bound_reads_the_scan_bound_constant() {
    let mut found = Vec::new();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    sources(&src, Path::new(""), &mut found);
    let named: Vec<&str> = found
        .iter()
        .filter(|(name, text)| name != "lib.rs" && names_scan_bound(text))
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(
        found
            .iter()
            .any(|(name, _)| name == "campaign/dispatch/policy.rs")
    );
    assert_eq!(named, Vec::<&str>::new());
}
