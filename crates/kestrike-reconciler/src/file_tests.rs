use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use super::{Access, FileError, key, read, trusted};
use crate::fixture::Scratch;

fn mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn a_file_of_the_limit_reads_and_one_byte_more_is_too_large() {
    let scratch = Scratch::new("limit");
    let path = scratch.write("input", "abcd");
    assert_eq!(read(&path, 4, Access::Readable).unwrap(), b"abcd");
    assert!(matches!(
        read(&path, 3, Access::Readable),
        Err(FileError::TooLarge(3))
    ));
}

#[test]
fn a_relative_path_and_a_directory_are_refused() {
    let scratch = Scratch::new("shape");
    assert!(matches!(
        read(Path::new("input"), 4, Access::Readable),
        Err(FileError::Relative)
    ));
    assert!(matches!(
        read(scratch.path(), 4, Access::Readable),
        Err(FileError::NotRegular)
    ));
}

/// `O_NONBLOCK` opens a FIFO with no writer at once, so the type check refuses it without the read waiting. The
/// five-second timeout turns a blocking FIFO open into a test failure.
#[test]
fn a_fifo_without_a_writer_is_refused_at_once() {
    let scratch = Scratch::new("fifo");
    let path = scratch.path().join("fifo");
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `name` is a NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let (send, receive) = mpsc::channel();
    let reader = path.clone();
    std::thread::spawn(move || {
        let _ = send.send(read(&reader, 4, Access::Readable));
    });
    let result = receive
        .recv_timeout(Duration::from_secs(5))
        .expect("the read of a FIFO without a writer returns within 5 s");
    assert!(matches!(result, Err(FileError::NotRegular)), "{result:?}");
}

#[test]
fn an_input_others_may_write_is_refused_and_a_key_file_must_be_private() {
    let scratch = Scratch::new("modes");
    let path = scratch.write("input", "abcd");
    mode(&path, 0o644);
    assert_eq!(read(&path, 4, Access::Readable).unwrap(), b"abcd");
    assert!(matches!(
        read(&path, 4, Access::Private),
        Err(FileError::Shared)
    ));
    mode(&path, 0o620);
    assert!(matches!(
        read(&path, 4, Access::Readable),
        Err(FileError::Writable)
    ));
    mode(&path, 0o602);
    assert!(matches!(
        read(&path, 4, Access::Readable),
        Err(FileError::Writable)
    ));
    mode(&path, 0o600);
    assert_eq!(read(&path, 4, Access::Private).unwrap(), b"abcd");
}

#[test]
fn an_input_of_root_or_the_process_user_is_trusted_and_one_of_a_third_user_is_not() {
    assert!(trusted(0, 1000));
    assert!(trusted(1000, 1000));
    assert!(!trusted(1001, 1000));
}

#[test]
fn a_key_is_64_lowercase_hexadecimal_digits() {
    let digits = "0f".repeat(32);
    assert_eq!(key(&digits), Some([0x0f; 32]));
    assert_eq!(key(&digits.to_uppercase()), None);
    assert_eq!(key(&digits[..62]), None);
    assert_eq!(key(&format!("{digits}0")), None);
    assert_eq!(key(&"0g".repeat(32)), None);
}

/// Distinct expected bytes expose any reordering; asymmetric digit pairs expose reversed nibble order.
#[test]
fn a_key_decodes_each_digit_pair_to_the_byte_at_its_position() {
    let digits: String = (0u8..32)
        .map(|byte| format!("{:02x}", byte * 7 + 3))
        .collect();
    let expected: [u8; 32] = std::array::from_fn(|at| at as u8 * 7 + 3);
    assert_eq!(key(&digits), Some(expected));
}
