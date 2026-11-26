//! Forked children judged by their frame and their exit status. The
//! process checks fork and so run only in the single-threaded worker; the
//! frame codec and the refusal on a second thread run under libtest too.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use super::fork::{
    Boundary, Classified, REPORT_FD, Refusal, Report, Spawned, Verdict, collect, descriptors,
    eligible, exit, frame, spawn, unframe,
};

/// Forks a child that runs `body` over its report and exits with the code
/// it returns, 101 when it panics, and collects it within `wait`.
fn child(wait: Duration, body: impl FnOnce(&mut Report) -> i32) -> Result<Classified, String> {
    let deadline = Instant::now() + wait;
    // SAFETY: the child runs `body` under `catch_unwind` and ends through
    // `exit`; `body` uses no inherited descriptor owner but its report.
    match unsafe { spawn(deadline) }? {
        Spawned::Parent(child) => Ok(collect(child, deadline)),
        Spawned::Child(mut report) => {
            let code = catch_unwind(AssertUnwindSafe(|| body(&mut report))).unwrap_or(101);
            exit(code)
        }
    }
}

/// A child's body over its report, returning its exit code.
type Body<'a> = Box<dyn FnOnce(&mut Report) -> i32 + 'a>;

/// Sets its flag when it drops, as a world's teardown audit does.
struct Teardown<'f>(&'f mut bool);

impl Drop for Teardown<'_> {
    fn drop(&mut self) {
        *self.0 = true;
    }
}

/// Each way a child can end, with the class its parent gives it: only a
/// success frame at exit 0 read to end of file is credited. A child whose
/// body panics runs its destructors during the unwind, reports that in a
/// failure frame and exits nonzero; a signal death, a pipe closed with no
/// frame, a cut or trailing frame, garbage, and a verdict at odds with the
/// exit status are each unsuccessful. The success child changes its copy
/// of a parent value, and the parent's stays as it was.
pub(crate) fn credited_only_on_framed_success() -> Result<(), String> {
    let mut value = 7u64;
    let wait = Duration::from_secs(20);
    let whole = frame(Verdict::Success, b"done");
    let cases: Vec<(&str, Body<'_>, Classified)> = vec![
        (
            "success",
            Box::new(|report| {
                value = 99;
                i32::from(!report.send(Verdict::Success, b"done"))
            }),
            Classified::Success(b"done".to_vec()),
        ),
        (
            "panic",
            Box::new(|report| {
                let mut dropped = false;
                let unwound = catch_unwind(AssertUnwindSafe(|| {
                    let _audit = Teardown(&mut dropped);
                    panic!("a planted child panic");
                }));
                let said: &[u8] = if dropped {
                    b"panicked, torn down"
                } else {
                    b"panicked"
                };
                report.send(Verdict::Failure, said);
                if unwound.is_err() { 101 } else { 0 }
            }),
            Classified::Failed {
                code: 101,
                payload: b"panicked, torn down".to_vec(),
            },
        ),
        (
            "signal",
            Box::new(|report| {
                report.send(Verdict::Success, b"done");
                // SAFETY: `raise` takes a plain signal number.
                unsafe { libc::raise(libc::SIGKILL) };
                0
            }),
            Classified::Signaled(libc::SIGKILL),
        ),
        ("silent", Box::new(|_| 0), Classified::Silent(0)),
        (
            "garbage",
            Box::new(|report| {
                report.write(b"not a frame");
                0
            }),
            Classified::Malformed(0),
        ),
        (
            "cut",
            Box::new(move |report| {
                report.write(&whole[..whole.len() - 1]);
                0
            }),
            Classified::Malformed(0),
        ),
        (
            "trailing",
            Box::new(|report| {
                report.send(Verdict::Success, b"done");
                report.write(b"x");
                0
            }),
            Classified::Malformed(0),
        ),
        (
            "success at exit 1",
            Box::new(|report| {
                report.send(Verdict::Success, b"done");
                1
            }),
            Classified::Mismatch {
                code: 1,
                verdict: Verdict::Success,
            },
        ),
        (
            "failure at exit 0",
            Box::new(|report| {
                report.send(Verdict::Failure, b"broken");
                0
            }),
            Classified::Mismatch {
                code: 0,
                verdict: Verdict::Failure,
            },
        ),
    ];
    for (name, body, expected) in cases {
        let classified = child(wait, body)?;
        if classified != expected {
            return Err(format!("{name}: {classified:?}, not {expected:?}"));
        }
        if classified.credited() != (name == "success") {
            return Err(format!("{name}: credited {}", classified.credited()));
        }
    }
    if value != 7 {
        return Err(format!("a child changed the parent's value to {value}"));
    }
    Ok(())
}

/// A child holds its standard streams and its report and nothing else: a
/// file and a pipe the parent opened before the fork are closed in the
/// child and stay open in the parent.
pub(crate) fn inherited_descriptors_close() -> Result<(), String> {
    let file = std::fs::File::open("/dev/null").map_err(|error| error.to_string())?;
    let (reader, writer) = std::io::pipe().map_err(|error| error.to_string())?;
    let before = descriptors()?;
    let classified = child(Duration::from_secs(20), |report| {
        let held = descriptors()
            .map(|fds| format!("{fds:?}"))
            .unwrap_or_default();
        i32::from(!report.send(Verdict::Success, held.as_bytes()))
    })?;
    let expected = format!("{:?}", [0, 1, 2, REPORT_FD]);
    if classified != Classified::Success(expected.clone().into_bytes()) {
        return Err(format!("the child held {classified:?}, not {expected}"));
    }
    if descriptors()? != before {
        return Err("the parent's descriptors changed".into());
    }
    drop((file, reader, writer));
    Ok(())
}

/// Waits until child `pid` exits and leaves it unreaped for [`collect`].
fn exited(pid: i32) -> Result<(), String> {
    loop {
        // SAFETY: `siginfo_t` is plain data, valid when zeroed.
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        // SAFETY: `waitid` writes the child's state into a live local, and
        // `WNOWAIT` leaves the child for a later wait to reap.
        let waited = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &raw mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if waited == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(format!("waitid: {error}"));
        }
    }
}

/// A child still running at its deadline is killed, reaped and classified
/// by the watchdog, never credited; a child that sent its success frame and
/// then hangs is classified the same. A child that finished before its
/// deadline passed is read to its end and credited even when collected
/// late.
pub(crate) fn watchdog_classifies_a_hung_child() -> Result<(), String> {
    let far = || Instant::now() + Duration::from_secs(20);
    // SAFETY: the child touches only its report and ends through `exit`.
    match unsafe { spawn(far()) }? {
        Spawned::Parent(child) => {
            exited(child.pid())?;
            let late = collect(child, Instant::now());
            if late != Classified::Success(b"done".to_vec()) {
                return Err(format!(
                    "a finished child collected late classified {late:?}"
                ));
            }
        }
        Spawned::Child(mut report) => {
            std::thread::sleep(Duration::from_millis(300));
            exit(i32::from(!report.send(Verdict::Success, b"done")))
        }
    }
    for hang in ["silent", "reported", "flooding"] {
        let started = Instant::now();
        let deadline = started + Duration::from_millis(300);
        // SAFETY: the child touches only its report and loops forever in
        // its arm, so it drops no inherited value.
        let (pid, classified) = match unsafe { spawn(far()) }? {
            Spawned::Parent(child) => (child.pid(), collect(child, deadline)),
            Spawned::Child(mut report) => match hang {
                "flooding" => loop {
                    report.write(&[0; 1 << 16]);
                },
                _ => {
                    if hang == "reported" {
                        report.send(Verdict::Success, b"done");
                        drop(report);
                    }
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            },
        };
        let late = Instant::now().saturating_duration_since(deadline);
        if classified != Classified::Watchdog || late > Duration::from_millis(500) {
            return Err(format!(
                "a {hang} hung child classified {classified:?} {late:?} past its deadline"
            ));
        }
        // SAFETY: `kill` with signal 0 only checks that the process exists.
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        if alive || started.elapsed() > Duration::from_secs(10) {
            return Err(format!("the hung child {pid} survived its deadline"));
        }
    }
    let deadline = Instant::now() + Duration::from_millis(300);
    // SAFETY: the child touches only its report and ends through `exit`.
    match unsafe { spawn(deadline) }? {
        Spawned::Parent(child) => {
            std::thread::sleep(Duration::from_secs(1));
            let slow = collect(child, deadline);
            if slow != Classified::Watchdog {
                return Err(format!(
                    "a child that finished past its deadline while its parent was busy classified {slow:?}"
                ));
            }
        }
        Spawned::Child(mut report) => {
            std::thread::sleep(Duration::from_millis(600));
            exit(i32::from(!report.send(Verdict::Success, b"done")))
        }
    }
    Ok(())
}

/// A fork is refused between a turn's actions, while a second thread
/// runs, when the predicate is false at the boundary, and while the prefix
/// sits unflushed; it is admitted at a stopped boundary of one thread with
/// the predicate true and the prefix flushed. A branch asks only from the
/// controller's stopped-boundary hook, after it flushed, so these
/// refusals are checked here on the boundaries a caller reports.
pub(crate) fn refused_off_its_boundary() -> Result<(), String> {
    let at = |stopped, holds, flushed| {
        eligible(Boundary {
            stopped,
            holds,
            flushed,
        })
    };
    let checks = [
        (at(false, true, true), Err(Refusal::Unstopped)),
        (at(true, false, true), Err(Refusal::Predicate)),
        (at(true, true, false), Err(Refusal::Unflushed)),
        (at(true, true, true), Ok(())),
    ];
    for (got, expected) in checks {
        if got != expected {
            return Err(format!("{got:?}, not {expected:?}"));
        }
    }
    let (stop, wait) = std::sync::mpsc::channel::<()>();
    let second = std::thread::spawn(move || wait.recv());
    let refused = at(true, true, true);
    drop(stop);
    let _ = second.join();
    if refused != Err(Refusal::Threads(2)) {
        return Err(format!("a second thread admitted {refused:?}"));
    }
    // A joined thread can stay listed for a moment; later cases fork.
    let started = Instant::now();
    while at(true, true, true) != Ok(()) {
        if started.elapsed() > Duration::from_secs(10) {
            return Err("the joined thread stayed listed".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

/// A frame decodes to its verdict and payload; a cut, extended, flipped or
/// relabelled frame, and one claiming more than the payload bound, decode
/// to nothing.
#[test]
fn a_frame_decodes_only_whole_and_unchanged() {
    let whole = frame(Verdict::Success, b"payload");
    assert_eq!(unframe(&whole), Some((Verdict::Success, &b"payload"[..])));
    assert_eq!(
        unframe(&frame(Verdict::Failure, b"")),
        Some((Verdict::Failure, &b""[..]))
    );
    assert_eq!(unframe(&whole[..whole.len() - 1]), None);
    assert_eq!(unframe(&[whole.as_slice(), b"x"].concat()), None);
    for at in 0..whole.len() {
        let mut changed = whole.clone();
        changed[at] ^= 1;
        assert_eq!(unframe(&changed), None, "byte {at}");
    }
    let mut relabelled = whole.clone();
    relabelled[8] = Verdict::Failure as u8;
    assert_eq!(unframe(&relabelled), None);
    let mut huge = whole;
    huge[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(unframe(&huge), None);
}

/// Each class prints its own name and only success is credited.
#[test]
fn only_success_is_credited_and_every_class_is_named_apart() {
    let classes = [
        Classified::Success(Vec::new()),
        Classified::Failed {
            code: 1,
            payload: Vec::new(),
        },
        Classified::Mismatch {
            code: 0,
            verdict: Verdict::Failure,
        },
        Classified::Signaled(9),
        Classified::Silent(0),
        Classified::Malformed(0),
        Classified::Watchdog,
        Classified::Lost(String::new()),
    ];
    let names: std::collections::BTreeSet<&str> = classes.iter().map(Classified::name).collect();
    assert_eq!(names.len(), classes.len());
    let credited: Vec<bool> = classes.iter().map(Classified::credited).collect();
    assert_eq!(
        credited,
        [true, false, false, false, false, false, false, false]
    );
}

/// Libtest runs each test on a thread beside its main one, so a fork from
/// a library test is refused for its threads at a stopped boundary, and
/// each of the worker's fork cases fails under libtest.
#[test]
fn a_library_test_cannot_fork() {
    let refused = eligible(Boundary {
        stopped: true,
        holds: true,
        flushed: true,
    });
    assert!(
        matches!(refused, Err(Refusal::Threads(count)) if count > 1),
        "{refused:?}"
    );
    // SAFETY: the thread check refuses before any fork, so no child runs.
    let spawned = unsafe { spawn(Instant::now()) };
    assert!(matches!(spawned, Err(error) if error.starts_with("a fork needs one thread")));
    for case in [
        credited_only_on_framed_success,
        inherited_descriptors_close,
        watchdog_classifies_a_hung_child,
        refused_off_its_boundary,
    ] {
        assert!(case().is_err());
    }
}
