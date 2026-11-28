use std::fs;
use std::io::Read;
use std::sync::mpsc;
use std::time::Duration;

use super::{Opened, open_regular_with, opened};
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
    let rescue = other.is_err().then(|| {
        use std::os::unix::fs::OpenOptionsExt;
        let nonblocking = || {
            let mut options = fs::OpenOptions::new();
            options.custom_flags(libc::O_NONBLOCK);
            options
        };
        let reader = nonblocking().read(true).open(&fifo);
        let writer = nonblocking().write(true).open(&fifo);
        (reader, writer)
    });
    opener.join().expect("the opener ends");
    drop(rescue);
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

/// `open_regular` decides by the status read first: it opens a path that read finds a regular file, so
/// a file removed after that read and before the open is an error that names the path, and it never
/// opens a directory or a FIFO that the read finds, while a missing path is absent.
#[test]
fn the_status_read_decides_before_the_open() {
    let scratch = Scratch::new("ownership-status");
    let root = &scratch.0;
    let file = root.join("file");
    fs::write(&file, "bytes").expect("the file is written");
    let error = open_regular_with(&file, |path| {
        fs::remove_file(path).expect("the file is removed before the open");
        opened(path)
    })
    .expect_err("the file is gone at the open");
    assert_eq!(error.error().kind(), std::io::ErrorKind::NotFound);
    assert!(error.to_string().contains(file.to_str().expect("UTF-8")));
    fs::write(&file, "bytes").expect("the file is written");
    let mut calls = 0;
    assert!(matches!(
        open_regular_with(&file, |path| {
            calls += 1;
            opened(path)
        }),
        Ok(Opened::File(_))
    ));
    assert_eq!(calls, 1, "a regular file is opened");
    fs::create_dir(root.join("dir")).expect("the directory is made");
    let fifo = std::ffi::CString::new(root.join("fifo").into_os_string().into_encoded_bytes())
        .expect("no NUL");
    // SAFETY: `mkfifo` reads the NUL-terminated path, which outlives the call.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    for name in ["dir", "fifo"] {
        let found = open_regular_with(&root.join(name), |_| panic!("{name} is opened"));
        assert!(matches!(found, Ok(Opened::Other)), "{name}");
    }
    let missing = open_regular_with(&root.join("missing"), |_| {
        panic!("a missing path is opened")
    });
    assert!(matches!(missing, Ok(Opened::Absent)));
}
