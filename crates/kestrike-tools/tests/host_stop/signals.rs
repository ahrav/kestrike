//! The installed handlers, in a process of their own: a real SIGTERM reaches the record, and a signal
//! ignored at the start gets no handler and stays ignored, also for the `aws` child.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use kestrike_tools::host_stop::{Call, DELIVERED, Record, Signal, install, launch};

use super::launch::Standin;
use super::{MARKER_LIMIT, PLACE, ROLE, passed, start_window};

const CASE: &str =
    "host_stop::signals::a_real_sigterm_reaches_the_record_and_an_ignored_hangup_stays_ignored";

/// The mask of a `Sig...:` line of a `/proc/<pid>/status` text.
fn mask(status: &str, field: &str) -> u64 {
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .unwrap_or_else(|| panic!("the status holds {field}"));
    u64::from_str_radix(line.trim(), 16).expect("a hexadecimal mask")
}

#[test]
fn the_signals_are_the_system_numbers_under_their_names() {
    for (signal, number, name) in [
        (Signal::Interrupt, libc::SIGINT, "SIGINT"),
        (Signal::Terminate, libc::SIGTERM, "SIGTERM"),
        (Signal::Hangup, libc::SIGHUP, "SIGHUP"),
    ] {
        assert_eq!((signal.number(), signal.name()), (number, name));
        assert_eq!(
            kestrike_tools::host_stop::Interrupted(signal).to_string(),
            name
        );
    }
    assert_eq!(
        Signal::ALL,
        [Signal::Interrupt, Signal::Terminate, Signal::Hangup]
    );
}

fn bit(signal: Signal) -> u64 {
    1 << (signal.number() - 1)
}

/// `signal_self` sends `signal` to this process through a `kill` the shell runs.
fn signal_self(name: &str) {
    let status = Command::new("/bin/sh")
        .args([
            "-c",
            "kill -s \"$1\" \"$2\"",
            "sh",
            name,
            &std::process::id().to_string(),
        ])
        .env_clear()
        .status()
        .expect("the shell starts");
    assert!(status.success());
}

/// `installed` runs in a process started with SIGHUP ignored: it installs the handlers, checks the
/// dispositions, sends itself SIGHUP and SIGTERM, and starts the stand-in to read the child's own.
fn installed(place: &Path) {
    let own = || fs::read_to_string("/proc/self/status").expect("the status reads");
    assert_ne!(
        mask(&own(), "SigIgn:") & bit(Signal::Hangup),
        0,
        "the window starts with SIGHUP ignored"
    );
    let thread = || fs::read_to_string("/proc/thread-self/status").expect("the status reads");
    let blocked = mask(&thread(), "SigBlk:");
    install(&DELIVERED).expect("the handlers install");
    assert_eq!(
        mask(&thread(), "SigBlk:"),
        blocked,
        "the registrations leave the thread's mask as they found it"
    );
    let status = own();
    let (caught, ignored) = (mask(&status, "SigCgt:"), mask(&status, "SigIgn:"));
    assert_ne!(caught & bit(Signal::Interrupt), 0);
    assert_ne!(caught & bit(Signal::Terminate), 0);
    assert_eq!(
        caught & bit(Signal::Hangup),
        0,
        "an ignored signal gets no handler"
    );
    assert_ne!(ignored & bit(Signal::Hangup), 0, "and stays ignored");
    signal_self("HUP");
    thread::sleep(Duration::from_millis(200));
    assert_eq!(
        DELIVERED.stored(),
        None,
        "an ignored SIGHUP reaches nothing"
    );
    signal_self("TERM");
    let start = Instant::now();
    while DELIVERED.stored().is_none() && start.elapsed() < MARKER_LIMIT {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        DELIVERED.stored(),
        Some(Signal::Terminate),
        "a real SIGTERM reaches the record"
    );
    let standin = Standin::new("signals-child");
    let env = standin.env("status");
    let mut record = Record::new(&DELIVERED);
    let argv = ["sts", "get-caller-identity"];
    let call = Call {
        argv: &argv,
        retry: true,
        cut: Duration::from_secs(10),
        env: &env,
    };
    let child =
        launch(&mut record, &call).expect("an unarmed record leaves the call to its answer");
    let ignored = mask(&child, "SigIgn:");
    assert_ne!(
        ignored & bit(Signal::Hangup),
        0,
        "the child keeps SIGHUP ignored"
    );
    assert_eq!(
        ignored & (bit(Signal::Interrupt) | bit(Signal::Terminate)),
        0
    );
    fs::write(place.join("done"), b"").expect("the window records its end");
}

/// In a process of its own started with SIGHUP ignored, the handlers catch SIGINT and SIGTERM and leave
/// SIGHUP ignored; a SIGTERM the process sends itself stands in the record, and the `aws` child starts
/// with SIGHUP ignored and SIGINT and SIGTERM not ignored.
#[test]
fn a_real_sigterm_reaches_the_record_and_an_ignored_hangup_stays_ignored() {
    if let (Some(_), Some(place)) = (std::env::var_os(ROLE), std::env::var_os(PLACE)) {
        installed(Path::new(&place));
        return;
    }
    let scratch = super::Scratch::new("signals");
    let output = start_window(CASE, "install", &scratch.0, "trap '' HUP;")
        .output()
        .expect("the window starts");
    passed("install", &output);
    assert!(scratch.0.join("done").exists(), "the window ran its checks");
}
