//! `SysfsKernel` starts, feeds, finishes and reaps the host's tools. These tests
//! spawn processes, so they run in their own test process: a child between
//! its clone and its exec holds copies of every open descriptor, including
//! any lock another test in the same process is about to release.
#![cfg(all(target_os = "linux", target_pointer_width = "64"))]
#![allow(
    clippy::disallowed_methods,
    reason = "these integration tests exercise host processes and their deadlines"
)]

use std::fs;
use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kestrike::bind::{Kernel, SysfsKernel};

/// The PIDs of this thread's children the kernel still lists, running or unreaped.
fn children() -> Vec<u32> {
    fs::read_to_string("/proc/thread-self/children")
        .unwrap()
        .split_whitespace()
        .map(|pid| pid.parse().unwrap())
        .collect()
}

#[test]
fn a_started_tool_runs_on_the_input_it_is_fed() {
    let started = SysfsKernel.start("cat", &[]).unwrap();
    assert_eq!(started.feed("addr show\n").finish().unwrap(), "addr show\n");
    assert_eq!(
        SysfsKernel.run("cat", &[], "route show\n").unwrap(),
        "route show\n"
    );
}

#[test]
fn a_tool_reads_an_input_larger_than_its_pipe_holds() {
    let input = "x".repeat(4 << 20);
    let started = SysfsKernel.start("wc", &["-c"]).unwrap();
    assert_eq!(started.feed(&input).finish().unwrap(), "4194304\n");
}

/// `cat` exits at its input's end, so its exit before `finish` shows the
/// feed delivered the input and its end.
#[test]
fn a_fed_tool_reads_its_whole_input_before_its_finish() {
    let before = children();
    let started = SysfsKernel.start("cat", &[]).unwrap();
    let pid = children()
        .into_iter()
        .find(|pid| !before.contains(pid))
        .unwrap();
    let fed = started.feed("link show\n");
    let exited = || {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        stat.rsplit_once(") ").unwrap().1.starts_with('Z')
    };
    let until = Instant::now() + Duration::from_secs(10);
    while !exited() {
        assert!(Instant::now() < until, "{pid} is still running");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(fed.finish().unwrap(), "link show\n");
    assert_eq!(children(), before);
}

#[test]
fn a_tool_s_failure_reports_its_standard_error() {
    let error = SysfsKernel
        .run("cat", &["/a-file-this-host-lacks"], "")
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Other);
    // The tool names itself by the path it was started through.
    assert!(
        error
            .to_string()
            .ends_with("cat: /a-file-this-host-lacks: No such file or directory\n"),
        "{error}"
    );
}

#[test]
fn a_missing_tool_is_not_found() {
    let missing = SysfsKernel
        .start("a-tool-this-host-lacks", &[])
        .map(|_| ())
        .unwrap_err();
    assert_eq!(missing.kind(), io::ErrorKind::NotFound);
}

#[test]
fn a_started_tool_dropped_unfinished_is_killed_and_reaped() {
    let before = children();
    let started = SysfsKernel.start("cat", &[]).unwrap();
    assert_eq!(children().len(), before.len() + 1);
    drop(started);
    assert_eq!(children(), before);
}

#[test]
fn a_deferred_run_delivers_its_input_at_the_instant() {
    let kernel = SysfsKernel;
    let stamp_input = [
        "-c",
        "IFS= read -r line; date +%s%N; printf '%s\\n' \"$line\"",
    ];
    let wait = Duration::from_millis(30);
    // The wall-clock sample precedes the monotonic baseline even if the
    // thread pauses between the readings.
    let system = SystemTime::now();
    let instant = Instant::now();
    let output = kernel
        .run_at("sh", &stamp_input, "neigh show\n", instant + wait)
        .unwrap();
    let (received, line) = output.split_once('\n').unwrap();
    let received = Duration::from_nanos(received.trim().parse().unwrap());
    let earliest = (system + wait).duration_since(UNIX_EPOCH).unwrap();
    assert!(received >= earliest, "{received:?} < {earliest:?}");
    assert_eq!(line, "neigh show\n");

    let echoed = kernel.run_at("cat", &[], "now\n", Instant::now() - wait);
    assert_eq!(echoed.unwrap(), "now\n");

    let failed = kernel.run_at("cat", &["--no-such-option"], "", Instant::now());
    assert!(failed.unwrap_err().to_string().contains("no-such-option"));
}

/// Runs of tools that stall, ignore their input, flood a stream or fail,
/// each inside the production envelope: 1 MiB of each stream, 30 seconds
/// from spawn and 5 seconds of reaping after a kill.
mod envelope {
    use std::io;
    use std::time::{Duration, Instant};

    use kestrike::bind::{Kernel, SysfsKernel};

    use super::children;

    /// Runs `script` under `sh -c` with `input` inside the production tool
    /// envelope, and returns its result and its duration from before the
    /// spawn.
    fn sh(script: &str, input: &str) -> (io::Result<String>, Duration) {
        let started = Instant::now();
        (
            SysfsKernel.run("sh", &["-c", script], input),
            started.elapsed(),
        )
    }

    /// The PID a stop refusal names, after checking that it records a
    /// completed reap, that the PID is no longer this thread's child and that
    /// the refusal leaves the tool's host effect unknown.
    fn reaped(error: &io::Error, bound: &str) -> u32 {
        let text = error.to_string();
        let pid: u32 = text
            .strip_prefix("tool ")
            .and_then(|rest| rest.split(' ').next())
            .and_then(|pid| pid.parse().ok())
            .unwrap_or_else(|| panic!("no PID in {text:?}"));
        assert!(text.contains(bound), "{text}");
        assert!(text.contains("killed and reaped"), "{text}");
        assert!(text.ends_with("its host effect is unknown"), "{text}");
        assert!(!children().contains(&pid), "{pid} is still a child");
        pid
    }

    /// A tool that prints exactly 1 MiB of standard output, or of standard
    /// error under a zero exit, returns its output.
    #[test]
    fn ib_tool_envelope_bounded_successful_child() {
        let (exact, _) = sh("head -c 1048576 /dev/zero", "");
        assert_eq!(exact.unwrap().len(), 1 << 20);
        let (quiet, _) = sh("head -c 1048576 /dev/zero >&2; echo done", "");
        assert_eq!(quiet.unwrap(), "done\n");
    }

    /// A tool that prints one byte past 1 MiB of standard output is killed at
    /// that byte and reaped, and the refusal is `FileTooLarge`, whatever the
    /// tool would do after.
    #[test]
    fn ib_tool_envelope_stdout_flood() {
        let (result, elapsed) = sh("head -c 1048577 /dev/zero; sleep 60", "");
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
        reaped(&error, "standard-output bound");
        assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    }

    /// A tool that floods standard error past 1 MiB is stopped the same way.
    #[test]
    fn ib_tool_envelope_stderr_flood() {
        let (result, elapsed) = sh("cat /dev/zero >&2", "");
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
        reaped(&error, "standard-error bound");
        assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    }

    /// A nonzero exit keeps its `Other` refusal carrying the tool's standard
    /// error, ahead of the short write a tool that exits without reading its
    /// input leaves, and a zero exit with its input unread refuses the short
    /// write.
    #[test]
    fn ib_tool_envelope_nonzero_exit() {
        let input = "x".repeat(1 << 20);
        let (failed, _) = sh("echo boom >&2; exit 3", &input);
        let error = failed.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), "boom\n");
        let (short, _) = sh("exec 0<&-; exit 0", &input);
        let error = short.unwrap_err();
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::WriteZero
            ),
            "{error:?}"
        );
    }

    /// A tool that exits 5 seconds inside the 30-second deadline returns
    /// its output.
    #[test]
    fn a_tool_that_exits_inside_its_deadline_succeeds() {
        let (result, elapsed) = sh("sleep 25; echo ok", "");
        assert_eq!(result.unwrap(), "ok\n");
        assert!(elapsed >= Duration::from_secs(25), "{elapsed:?}");
    }

    /// How often this thread has blocked, its voluntary context switches,
    /// and the CPU time it has used.
    fn waits() -> (i64, Duration) {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        // SAFETY: `usage` is writable, aligned storage for one `rusage`,
        // and a zero return means `getrusage` filled it.
        let usage = unsafe {
            assert_eq!(libc::getrusage(libc::RUSAGE_THREAD, usage.as_mut_ptr()), 0);
            usage.assume_init()
        };
        let time = |value: libc::timeval| {
            Duration::from_secs(value.tv_sec as u64) + Duration::from_micros(value.tv_usec as u64)
        };
        (usage.ru_nvcsw, time(usage.ru_utime) + time(usage.ru_stime))
    }

    #[test]
    fn a_tool_that_outlives_its_outputs_is_awaited_asleep() {
        let (blocks, cpu) = waits();
        let (result, elapsed) = sh("exec >&- 2>&-; sleep 1", "");
        let (blocked, used) = waits();
        let (blocked, used) = (blocked - blocks, used - cpu);
        assert_eq!(result.unwrap(), "");
        assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");
        assert!(blocked < 20, "the run blocked {blocked} times");
        assert!(used < Duration::from_millis(500), "the run used {used:?}");
    }

    /// A tool that exits 0 while a background child it started holds its
    /// output pipes open runs to the deadline: the run waits for its pipes
    /// to close, and the refusal comes at the deadline with the tool
    /// reaped.
    #[test]
    fn a_tool_whose_background_child_holds_its_output_runs_to_the_deadline() {
        let (result, elapsed) = sh("sleep 40 & exit 0", "");
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        reaped(&error, "passed its deadline");
        assert!(
            elapsed >= Duration::from_secs(30) && elapsed < Duration::from_secs(35),
            "{elapsed:?}"
        );
    }

    /// A tool that never exits is killed at the 30-second deadline and
    /// reaped, and the refusal is `TimedOut`, within the deadline and the
    /// 5-second cleanup bound.
    #[test]
    fn ib_tool_envelope_stalled_child() {
        let (result, elapsed) = sh("sleep 60", "");
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        reaped(&error, "passed its deadline");
        assert!(
            elapsed >= Duration::from_secs(30) && elapsed < Duration::from_secs(35),
            "{elapsed:?}"
        );
    }

    /// A tool that leaves 4 MiB of input unread and never exits fills its
    /// input pipe; the run ends at the deadline with the write pending.
    #[test]
    fn ib_tool_envelope_stdin_blockage() {
        let (result, elapsed) = sh("sleep 60", &"x".repeat(4 << 20));
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        reaped(&error, "passed its deadline");
        assert!(elapsed < Duration::from_secs(35), "{elapsed:?}");
    }

    /// A tool whose background child keeps the output pipes open after the
    /// tool is killed: the refusal comes at the deadline with the tool
    /// reaped while the grandchild still runs and holds the pipes.
    #[test]
    fn a_grandchild_holding_the_pipes_delays_no_refusal() {
        let (result, elapsed) = sh("sleep 40 & sleep 60", "");
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        reaped(&error, "passed its deadline");
        assert!(elapsed < Duration::from_secs(35), "{elapsed:?}");
    }
}
