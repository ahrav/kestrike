use std::ffi::OsStr;
use std::io;

use super::runner::ascii_strip;
use super::stop::{Fault, Stop};

#[test]
fn a_fault_is_the_error_kind_then_its_text_and_its_path() {
    let error = io::Error::from_raw_os_error(libc::ENOENT);
    let fault = Fault::os(&error, Some(OsStr::new("/x")));
    assert_eq!(
        fault.to_text().to_string(),
        "NotFound: No such file or directory (os error 2): /x"
    );
    assert_eq!(
        Stop::failed(&fault).reason().to_string(),
        "the runner failed: NotFound: No such file or directory (os error 2): /x"
    );
    assert_eq!(
        Fault::library("Utf8Error", &"a text").to_text().to_string(),
        "Utf8Error: a text"
    );
}

#[test]
fn git_output_is_stripped_of_the_six_ascii_whitespace_bytes_alone() {
    assert_eq!(
        ascii_strip(b"\x0b\x0c x \r\n"),
        b"x",
        "b'\\x0b\\x0c x \\r\\n'.strip()"
    );
    assert_eq!(
        ascii_strip(b"\x1cx\x1c"),
        b"\x1cx\x1c",
        "b'\\x1cx\\x1c'.strip()"
    );
}
