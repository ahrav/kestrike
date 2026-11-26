//! `kestrike-inspect` reads its image path as OS bytes and exits 0, 1 or 2
//! by its documented contract, leaving the image's bytes unchanged. These
//! tests spawn the built binary through `CARGO_BIN_EXE_kestrike-inspect`.
#![cfg(all(target_os = "linux", target_pointer_width = "64"))]
#![allow(
    clippy::disallowed_methods,
    reason = "these integration tests launch the host image inspector"
)]

use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

/// The record fixture whose 3,000-byte body occupies one 4 KiB chunk.
const BODY: &[u8] = include_bytes!("../src/storage/record/fixtures/body.rec");
/// The record unit and the chunk length the fixture was written under.
const UNIT: usize = 4096;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("inspect-cli-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A one-record image: the fixture padded to a whole unit.
fn golden() -> Vec<u8> {
    let mut image = BODY.to_vec();
    image.resize(UNIT, 0);
    image
}

fn inspect(args: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kestrike-inspect"))
        .env_clear()
        .args(args)
        .output()
        .unwrap()
}

fn status(output: &Output) -> Option<i32> {
    output.status.code()
}

/// The arguments that scan `image` with the fixture's chunk length.
fn scan(image: &Path) -> Output {
    inspect(&[
        "--image".as_ref(),
        image.as_os_str(),
        "--chunk-len".as_ref(),
        "4096".as_ref(),
    ])
}

/// A verified image at a path whose bytes are not UTF-8 is read through
/// those bytes, exits 0 and keeps its contents.
#[test]
fn a_non_utf8_image_path_is_read_unchanged_and_verifies() {
    let dir = scratch("non-utf8");
    let image = dir.join(OsString::from_vec(b"image-\xff\xfe.img".to_vec()));
    fs::write(&image, golden()).unwrap();
    let output = scan(&image);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(status(&output), Some(0), "{stderr}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("image \"") && stdout.contains("\\xFF\\xFE"),
        "the header names the path's bytes exactly: {stdout}"
    );
    assert_eq!(
        fs::read(&image).unwrap(),
        golden(),
        "the image keeps its bytes"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Each documented exit class has its own case: a verified image and an empty
/// window exit 0, a corrupted candidate exits 1, and a missing path, a
/// directory, a character device, a range past the image's end and malformed
/// textual arguments, each with its own message, exit 2.
#[test]
fn every_exit_class_is_reached_by_a_deterministic_case() {
    let dir = scratch("exits");
    let image = dir.join("golden.img");
    fs::write(&image, golden()).unwrap();
    assert_eq!(status(&scan(&image)), Some(0));
    let empty = inspect(&[
        "--image".as_ref(),
        image.as_os_str(),
        "--chunk-len".as_ref(),
        "4096".as_ref(),
        "--range".as_ref(),
        "0:0".as_ref(),
    ]);
    assert_eq!(status(&empty), Some(0), "an empty window verifies");

    let corrupted = dir.join("corrupted.img");
    let mut bytes = golden();
    bytes[BODY.len() - 1] ^= 0xff;
    fs::write(&corrupted, &bytes).unwrap();
    assert_eq!(status(&scan(&corrupted)), Some(1), "a candidate fails");
    assert_eq!(fs::read(&corrupted).unwrap(), bytes);

    let stderr = |output: &Output| String::from_utf8_lossy(&output.stderr).into_owned();
    let missing = scan(&dir.join("missing.img"));
    assert_eq!(status(&missing), Some(2), "open error");
    assert!(
        stderr(&missing).contains(": opening "),
        "{}",
        stderr(&missing)
    );
    for path in [dir.as_path(), Path::new("/dev/null")] {
        let output = scan(path);
        assert_eq!(status(&output), Some(2), "{path:?}: {}", stderr(&output));
        assert!(
            stderr(&output).contains(": not a regular file or block device"),
            "{path:?}: {}",
            stderr(&output)
        );
    }
    let past = inspect(&[
        "--image".as_ref(),
        image.as_os_str(),
        "--chunk-len".as_ref(),
        "4096".as_ref(),
        "--range".as_ref(),
        "0:8192".as_ref(),
    ]);
    assert_eq!(status(&past), Some(2), "a range past the image");
    assert!(
        stderr(&past).contains("the range needs"),
        "{}",
        stderr(&past)
    );
    let non_utf8 = OsStr::from_bytes(b"\xff");
    for args in [
        vec!["--image".as_ref(), image.as_os_str()],
        vec![
            "--image".as_ref(),
            image.as_os_str(),
            "--chunk-len".as_ref(),
            non_utf8,
        ],
        vec![
            "--image".as_ref(),
            image.as_os_str(),
            "--chunk-len".as_ref(),
            "4096".as_ref(),
            "--range".as_ref(),
            non_utf8,
        ],
        vec![
            "--image".as_ref(),
            image.as_os_str(),
            "--chunk-len".as_ref(),
            "four".as_ref(),
        ],
        vec![non_utf8, image.as_os_str()],
        vec!["--image".as_ref()],
        vec!["--bogus".as_ref()],
        vec!["--bogus".as_ref(), "x".as_ref()],
    ]
    .into_iter()
    .chain(["0-10", "a:b", "8:4"].map(|range| {
        vec![
            "--image".as_ref(),
            image.as_os_str(),
            "--chunk-len".as_ref(),
            "4096".as_ref(),
            "--range".as_ref(),
            range.as_ref(),
        ]
    })) {
        let output = inspect(&args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(status(&output), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains("give --image"), "{args:?}: {stderr}");
    }
    assert_eq!(
        fs::read(&image).unwrap(),
        golden(),
        "no case changed the image"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// `open(2)` on a FIFO with no writer waits for one unless the open is
/// non-blocking, so this wait is bounded: a scan still running after ten
/// seconds is killed and the test fails instead of hanging the suite.
#[test]
fn a_writerless_fifo_is_refused_without_blocking() {
    let dir = scratch("fifo");
    let fifo = dir.join("image.fifo");
    let c_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c_path` is a NUL-terminated string that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    let mut child = Command::new(env!("CARGO_BIN_EXE_kestrike-inspect"))
        .env_clear()
        .args([
            "--image".as_ref(),
            fifo.as_os_str(),
            "--chunk-len".as_ref(),
            "4096".as_ref(),
        ])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the open of a writerless FIFO blocked");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(status(&output), Some(2), "{stderr}");
    assert!(
        stderr.contains(": not a regular file or block device"),
        "{stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}
