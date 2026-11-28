//! The module's source names no way to make a call, start a process, read a clock or write output, and
//! names a file read in one place, the lane's close; so each check returns its rejection before any call
//! of the controller.

use std::fs;
use std::path::PathBuf;

use crate::fis_support::tree;

/// The names through which Rust code starts a process, reads a clock, opens a socket, writes a file or
/// a stream, reads the environment, or escapes the compiler's checks.
const EFFECTS: [&str; 21] = [
    "std::process",
    "Command",
    "std::time",
    "Instant",
    "SystemTime",
    "std::net",
    "TcpStream",
    "UdpSocket",
    "print!",
    "println!",
    "eprint",
    "stdout",
    "stderr",
    "libc::",
    "unsafe",
    "std::thread",
    "File::create",
    "OpenOptions",
    "fs::write",
    "std::env",
    "env::var",
];

/// The names through which Rust code opens or reads a file.
const FILE_READS: [&str; 3] = ["File::open", "fs::read", "read_to_"];

/// Each file of the module's directory with its text.
fn sources() -> Vec<(PathBuf, String)> {
    let directory = tree().join("crates/kestrike-tools/src/fis_controller");
    let mut files: Vec<PathBuf> = fs::read_dir(&directory)
        .expect("the module's directory lists")
        .map(|entry| entry.expect("the module's directory lists").path())
        .collect();
    files.sort();
    assert!(files.len() >= 8, "the module's files list: {files:?}");
    files
        .into_iter()
        .map(|path| {
            let text = fs::read_to_string(&path).expect("a module file reads");
            (path, text)
        })
        .collect()
}

/// The names of `names` that `text` holds.
fn named<'a>(text: &str, names: &[&'a str]) -> Vec<&'a str> {
    names
        .iter()
        .copied()
        .filter(|name| text.contains(name))
        .collect()
}

#[test]
fn the_module_names_no_process_clock_socket_or_output() {
    for (path, text) in sources() {
        assert_eq!(
            named(&text, &EFFECTS),
            Vec::<&str>::new(),
            "{}",
            path.display()
        );
    }
    let (_, first) = &sources()[0];
    let planted = format!("{first}\nuse std::process::Command;\n");
    assert_eq!(
        named(&planted, &EFFECTS),
        ["std::process", "Command"],
        "the scan finds a planted process start"
    );
    let planted = format!("{first}\nlet _ = std::fs::write(path, bytes);\n");
    assert_eq!(
        named(&planted, &EFFECTS),
        ["fs::write"],
        "the scan finds a planted file write"
    );
}

#[test]
fn the_lane_close_is_the_one_file_that_reads_a_file() {
    let readers: Vec<String> = sources()
        .into_iter()
        .filter(|(_, text)| !named(text, &FILE_READS).is_empty())
        .map(|(path, _)| {
            path.file_name()
                .expect("a module file has a name")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(readers, ["lane_role.rs"]);
}
