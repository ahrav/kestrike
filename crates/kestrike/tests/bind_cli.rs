//! `kestrike-bind` validates its arguments before any effect. These tests
//! spawn the built binary through `CARGO_BIN_EXE_kestrike-bind`.
#![cfg(all(target_os = "linux", target_pointer_width = "64"))]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bind-cli-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn bind(args: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kestrike-bind"))
        .env_clear()
        .args(args)
        .output()
        .unwrap()
}

/// `--release` accepts `--other-state-dir`: the request passes argument
/// validation and stops at a later check, the privilege check or the state
/// directory's trust check, with status 1 rather than usage status 2.
#[test]
fn release_accepts_other_owners_state_directories() {
    let dir = scratch("release-others");
    let (own, other) = (dir.join("own"), dir.join("other"));
    let output = bind(&[
        "--release".as_ref(),
        "--state-dir".as_ref(),
        own.as_os_str(),
        "--other-state-dir".as_ref(),
        other.as_os_str(),
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(!stderr.contains("choose one action"), "{stderr}");
    let _ = fs::remove_dir_all(&dir);
}

/// Every invalid request exits 2 with the usage line before the privilege
/// check, so the isolated state directory it names stays absent and the
/// process exits ahead of every kernel and metadata step: a bind with a
/// volume or an ENI but no manifest, a release with a volume, an ENI, a
/// manifest, `--allow-no-iommu` or a peer, a missing
/// action, an ENI without peers or peers without an ENI, a missing value
/// for a path or textual option, an unknown option, a non-UTF-8 option name,
/// volume, ENI or peer, a volume, ENI or peer outside its grammar, and a
/// single-valued option given twice. Every case names the isolated state
/// directory first, so every case runs against that directory.
#[test]
fn every_invalid_request_exits_with_usage_before_any_effect() {
    let dir = scratch("invalid");
    let state = dir.join("state");
    let manifest = dir.join("manifest.json");
    let non_utf8 = OsStr::from_bytes(b"\xff");
    let common: [&OsStr; 2] = ["--state-dir".as_ref(), state.as_os_str()];
    let cases: Vec<Vec<&OsStr>> = vec![
        vec!["--volume".as_ref(), "vol-0123456789abcdef0".as_ref()],
        vec![
            "--eni".as_ref(),
            "eni-0123456789abcdef0".as_ref(),
            "--peer".as_ref(),
            "10.0.0.2".as_ref(),
        ],
        vec![
            "--release".as_ref(),
            "--volume".as_ref(),
            "vol-0123456789abcdef0".as_ref(),
        ],
        vec![
            "--release".as_ref(),
            "--wc-manifest".as_ref(),
            manifest.as_os_str(),
        ],
        vec!["--release".as_ref(), "--allow-no-iommu".as_ref()],
        vec![
            "--release".as_ref(),
            "--eni".as_ref(),
            "eni-0123456789abcdef0".as_ref(),
            "--peer".as_ref(),
            "10.0.0.2".as_ref(),
        ],
        vec!["--release".as_ref(), "--peer".as_ref(), "10.0.0.2".as_ref()],
        vec![],
        vec![
            "--wc-manifest".as_ref(),
            manifest.as_os_str(),
            "--eni".as_ref(),
            "eni-0123456789abcdef0".as_ref(),
        ],
        vec![
            "--wc-manifest".as_ref(),
            manifest.as_os_str(),
            "--volume".as_ref(),
            "vol-0123456789abcdef0".as_ref(),
            "--peer".as_ref(),
            "10.0.0.2".as_ref(),
        ],
        vec!["--release".as_ref(), "--other-state-dir".as_ref()],
        vec![
            "--wc-manifest".as_ref(),
            manifest.as_os_str(),
            "--volume".as_ref(),
        ],
        vec![
            "--wc-manifest".as_ref(),
            manifest.as_os_str(),
            "--eni".as_ref(),
            "eni-0123456789abcdef0".as_ref(),
            "--peer".as_ref(),
        ],
        vec![
            "--volume".as_ref(),
            "vol-0123456789abcdef0".as_ref(),
            "--wc-manifest".as_ref(),
        ],
        vec![
            "--wc-manifest".as_ref(),
            manifest.as_os_str(),
            "--volume".as_ref(),
            "foo".as_ref(),
        ],
        vec![
            "--wc-manifest".as_ref(),
            manifest.as_os_str(),
            "--volume".as_ref(),
            "--release".as_ref(),
        ],
        vec![
            "--wc-manifest".as_ref(),
            manifest.as_os_str(),
            "--eni".as_ref(),
            "eni-xyz".as_ref(),
            "--peer".as_ref(),
            "10.0.0.2".as_ref(),
        ],
        vec![
            "--wc-manifest".as_ref(),
            manifest.as_os_str(),
            "--volume".as_ref(),
            "vol-0123456789abcdef0".as_ref(),
            "--volume".as_ref(),
            "vol-0fedcba9876543210".as_ref(),
        ],
        vec![
            "--release".as_ref(),
            "--state-dir".as_ref(),
            state.as_os_str(),
        ],
        vec!["--release".as_ref(), "--bogus".as_ref()],
        vec!["--release".as_ref(), non_utf8],
        vec![
            "--wc-manifest".as_ref(),
            manifest.as_os_str(),
            "--volume".as_ref(),
            non_utf8,
        ],
        vec![
            "--wc-manifest".as_ref(),
            manifest.as_os_str(),
            "--eni".as_ref(),
            non_utf8,
            "--peer".as_ref(),
            "10.0.0.2".as_ref(),
        ],
        vec![
            "--wc-manifest".as_ref(),
            manifest.as_os_str(),
            "--eni".as_ref(),
            "eni-0123456789abcdef0".as_ref(),
            "--peer".as_ref(),
            non_utf8,
        ],
        vec![
            "--wc-manifest".as_ref(),
            manifest.as_os_str(),
            "--eni".as_ref(),
            "eni-0123456789abcdef0".as_ref(),
            "--peer".as_ref(),
            "not-an-address".as_ref(),
        ],
    ];
    for case in cases {
        let args: Vec<&OsStr> = common.iter().copied().chain(case.iter().copied()).collect();
        let output = bind(&args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{case:?}: {stderr}");
        assert!(
            stderr.contains("; give --wc-manifest"),
            "{case:?}: {stderr}"
        );
        assert!(!state.exists(), "{case:?} created the state directory");
    }
    let _ = fs::remove_dir_all(&dir);
}

/// A non-UTF-8 path value passes argument validation as a path: a release
/// whose state directory names bytes that are not UTF-8, and a bind whose
/// manifest and state directory do, each stop at a later check with status
/// 1, with the privilege check's message when the test runs unprivileged.
#[test]
fn non_utf8_paths_and_valid_requests_pass_argument_validation() {
    let dir = scratch("paths");
    let state = dir.join(OsString::from_vec(b"state-\xff".to_vec()));
    let manifest = dir.join(OsString::from_vec(b"manifest-\xfe.json".to_vec()));
    for args in [
        vec![
            "--release".as_ref(),
            "--state-dir".as_ref(),
            state.as_os_str(),
        ],
        vec![
            "--wc-manifest".as_ref(),
            manifest.as_os_str(),
            "--volume".as_ref(),
            "vol-0123456789abcdef0".as_ref(),
            "--state-dir".as_ref(),
            state.as_os_str(),
        ],
    ] {
        let output = bind(&args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(
            !stderr.contains("; give --wc-manifest"),
            "{args:?}: {stderr}"
        );
        // SAFETY: reads the effective user ID.
        if unsafe { libc::geteuid() } != 0 {
            assert!(stderr.contains("must run as root"), "{args:?}: {stderr}");
            assert!(!state.exists());
        }
    }
    let _ = fs::remove_dir_all(&dir);
}
