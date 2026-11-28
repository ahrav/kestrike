use std::fs;
use std::io::Read;
use std::sync::mpsc;
use std::time::Duration;

use super::{Opened, opened};
use crate::paths::tests::Scratch;

#[test]
fn the_descriptor_decides_what_an_open_entry_is() {
    let scratch = Scratch::new("ownership-opened");
    let root = &scratch.0;
    fs::write(root.join("file"), "bytes").expect("the file is written");
    fs::create_dir(root.join("dir")).expect("the directory is made");
    let fifo = root.join("fifo");
    let named =
        std::ffi::CString::new(fifo.clone().into_os_string().into_encoded_bytes()).expect("no NUL");
    // SAFETY: `mkfifo` reads the NUL-terminated path, which outlives the call.
    assert_eq!(unsafe { libc::mkfifo(named.as_ptr(), 0o600) }, 0);

    let Ok(Opened::File(mut file)) = opened(&root.join("file")) else {
        panic!("a regular file opens as one");
    };
    let mut read = String::new();
    file.read_to_string(&mut read).expect("the file reads");
    assert_eq!(read, "bytes");
    assert!(matches!(opened(&root.join("dir")), Ok(Opened::Other)));

    let (sender, receiver) = mpsc::channel();
    let path = fifo.clone();
    let opener = std::thread::spawn(move || {
        let _ = sender.send(matches!(opened(&path), Ok(Opened::Other)));
    });
    let other = receiver.recv_timeout(Duration::from_secs(10));
    if other.is_err() {
        let _ = fs::OpenOptions::new().write(true).open(&fifo);
    }
    opener.join().expect("the opener ends");
    assert_eq!(
        other,
        Ok(true),
        "a FIFO with no writer opens at once as Other"
    );

    let missing = root.join("missing");
    let error = opened(&missing).expect_err("a removed file is an error");
    assert_eq!(error.error().kind(), std::io::ErrorKind::NotFound);
    assert!(error.to_string().contains(missing.to_str().expect("UTF-8")));
}
