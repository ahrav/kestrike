use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use super::{Launch, execute, stop};
use crate::orderings::verdicts::{Verdict, loom_result};
use crate::paths::tests::Scratch;
use crate::process::{GroupStopped, INTERRUPT, Interrupt, install_handlers};
use crate::tools::weaken_orderings::halt::Halt;

/// `running` holds while `pid` names a live process that is no zombie.
fn running(pid: &str) -> bool {
    std::fs::read_to_string(format!("/proc/{}/stat", pid.trim())).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .is_some_and(|state| state != "Z")
    })
}

/// `gone` holds once `pid` stops running within 30 seconds; a process that SIGKILL reached while the host
/// is loaded can take seconds to leave its last state.
fn gone(pid: &str) -> bool {
    let start = Instant::now();
    while running(pid) && start.elapsed() < Duration::from_secs(30) {
        std::thread::sleep(Duration::from_millis(10));
    }
    !running(pid)
}

fn words(argv: &[&str]) -> Vec<OsString> {
    argv.iter().map(OsString::from).collect()
}

/// `group` is a command whose leader writes `leader` once its same-group worker, which ignores SIGTERM,
/// has written its pid to `worker`. Each of the two runs until a signal ends it or `marker` is gone, so a
/// case's group ends with the case's scratch directory and the teardown signals no process.
fn group(marker: &Path, leader_ignores_term: bool) -> Vec<OsString> {
    let trap = if leader_ignores_term {
        "trap '' TERM; "
    } else {
        ""
    };
    let m = marker.display();
    words(&[
        "sh",
        "-c",
        &format!(
            "{trap}sh -c 'trap \"\" TERM; echo $$ > {m}/worker; while [ -d {m} ]; do sleep 0.1; done' & \
             while [ ! -s {m}/worker ]; do sleep 0.05; done; echo $$ > {m}/leader; \
             while [ -d {m} ]; do sleep 0.1; done"
        ),
    ])
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn wait_for(path: &Path) {
    let start = Instant::now();
    while !std::fs::metadata(path).is_ok_and(|status| status.len() > 0) {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "{} within 30 s",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

const ROLE: &str = "KESTRIKE_WEAKEN_EXECUTE_ROLE";

/// A run whose handlers stand gets SIGTERM while its test runs; the test's group is stopped before the
/// run ends, so no process of it stays, its worker that ignores SIGTERM included. The run is this test
/// executable started again in that role.
#[test]
fn an_interrupted_command_leaves_no_process_behind() {
    if let Some(marker) = std::env::var_os(ROLE) {
        let marker = PathBuf::from(marker);
        install_handlers().expect("the handlers stand");
        let argv = group(&marker, false);
        let ran = execute(
            &Launch::new(&INTERRUPT),
            &argv,
            Path::new("."),
            None,
            Duration::from_secs(120),
            &marker.join("out"),
        );
        std::process::exit(if matches!(ran, Err(Halt::Interrupted(libc::SIGTERM))) {
            0
        } else {
            3
        });
    }
    let scratch = Scratch::new("weaken-execute");
    let name = module_path!()
        .split_once("::")
        .map_or("", |(_, rest)| rest)
        .to_owned()
        + "::an_interrupted_command_leaves_no_process_behind";
    let mut child = Command::new(std::env::current_exe().expect("the test executable"))
        .args([name.as_str(), "--exact", "--nocapture", "--test-threads=1"])
        .env(ROLE, &scratch.0)
        .spawn()
        .expect("the role starts");
    wait_for(&scratch.0.join("leader"));
    let (pid, worker) = (
        read(&scratch.0.join("leader")),
        read(&scratch.0.join("worker")),
    );
    let role = libc::pid_t::try_from(child.id()).expect("a pid");
    // SAFETY: `kill` takes two integers and touches no memory of the caller.
    assert_eq!(unsafe { libc::kill(role, libc::SIGTERM) }, 0);
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("the wait runs") {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "the run ends within 30 s"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(
        status.code(),
        Some(0),
        "the run ended by its signal's interruption"
    );
    assert!(gone(&pid), "the test's leader {pid} is gone");
    assert!(
        gone(&worker),
        "the test's worker {worker}, which ignores SIGTERM, is gone"
    );
}

/// A deadline ends the wait with no exit code, the stop ends the worker that ignores SIGTERM, and the
/// loom judgment of a run with no exit code is a timeout.
#[test]
fn a_deadline_ends_the_whole_process_group() {
    let scratch = Scratch::new("weaken-deadline");
    let interrupt = Interrupt::new();
    let (code, seconds) = execute(
        &Launch::new(&interrupt),
        &group(&scratch.0, false),
        Path::new("."),
        None,
        Duration::from_secs(2),
        &scratch.0.join("out"),
    )
    .expect("the run ends");
    assert!(scratch.0.join("leader").is_file());
    assert_eq!(code, None);
    assert!(seconds < 30.0, "{seconds}");
    assert!(gone(&read(&scratch.0.join("worker"))));
    assert_eq!(
        loom_result(
            "",
            code,
            "a departed record whose owner had not ended",
            true,
            None
        )
        .expect("judged"),
        (Verdict::NoVerdict, "timeout".to_owned())
    );
}

/// `leader` starts the group with a leader that ignores SIGTERM in a session of its own and returns once
/// the leader has written its pid.
fn leader(marker: &Path) -> Child {
    let argv = group(marker, true);
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    super::lead_session(&mut command);
    let child = command.spawn().expect("the leader starts");
    wait_for(&marker.join("leader"));
    child
}

/// A signal delivered half a second into a 30-second grace ends it: the group gets SIGKILL, the leader is
/// reaped and the worker is gone well before the grace would end.
#[test]
fn a_second_signal_during_the_grace_still_kills_the_group() {
    let scratch = Scratch::new("weaken-grace");
    let mut child = leader(&scratch.0);
    let interrupt = Interrupt::new();
    let launch = Launch {
        grace: Duration::from_secs(30),
        ..Launch::new(&interrupt)
    };
    let start = Instant::now();
    let stopped = std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(500));
            interrupt.record(libc::SIGTERM);
        });
        stop(&mut child, &launch, 0).expect("the stop runs")
    });
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "{:?}",
        start.elapsed()
    );
    assert!(matches!(stopped, GroupStopped::Reaped(_)), "{stopped:?}");
    assert_eq!(interrupt.recorded(), Some(libc::SIGTERM));
    assert!(gone(&read(&scratch.0.join("worker"))));
}

/// A signal recorded just after the child starts ends the wait at once: the child is stopped and reaped,
/// the run ends by the signal and its hold is released.
#[test]
fn a_signal_while_a_child_starts_stops_that_child() {
    let scratch = Scratch::new("weaken-spawn");
    let interrupt = Interrupt::new();
    let started = std::cell::RefCell::new(None);
    let on_start = |child: &Child| {
        *started.borrow_mut() = Some(child.id());
        interrupt.record(libc::SIGTERM);
    };
    let launch = Launch {
        started: &on_start,
        ..Launch::new(&interrupt)
    };
    let start = Instant::now();
    let ran = execute(
        &launch,
        &words(&["sleep", "60"]),
        Path::new("."),
        None,
        Duration::from_secs(120),
        &scratch.0.join("out"),
    );
    assert!(
        matches!(ran, Err(Halt::Interrupted(libc::SIGTERM))),
        "{ran:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "the wait ended at once: {:?}",
        start.elapsed()
    );
    assert!(!interrupt.held());
    let pid = started.borrow().expect("the child started").to_string();
    assert!(!running(&pid), "the child {pid} is gone");
}

/// A signal recorded after a test's group has ended still ends the run, and the hold is released; a
/// command that cannot start releases the hold too.
#[test]
fn a_signal_after_the_stop_is_raised_and_the_hold_is_released() {
    let scratch = Scratch::new("weaken-release");
    let interrupt = Interrupt::new();
    let after = || interrupt.record(libc::SIGTERM);
    let launch = Launch {
        stopped: &after,
        ..Launch::new(&interrupt)
    };
    let ran = execute(
        &launch,
        &words(&["true"]),
        Path::new("."),
        None,
        Duration::from_secs(120),
        &scratch.0.join("out"),
    );
    assert!(
        matches!(ran, Err(Halt::Interrupted(libc::SIGTERM))),
        "{ran:?}"
    );
    assert!(!interrupt.held());
    let quiet = Interrupt::new();
    let absent = scratch.0.join("absent");
    let ran = execute(
        &Launch::new(&quiet),
        &[absent.into_os_string()],
        Path::new("."),
        None,
        Duration::from_secs(120),
        &scratch.0.join("absent.out"),
    );
    assert!(matches!(ran, Err(Halt::Failed(_))), "{ran:?}");
    assert!(!quiet.held());
}

/// A hold records signals: a hold with none releases quietly, a nested hold shares the outer one's record
/// and leaves the report to it, and the outermost release reports the first signal, in place of the
/// block's own failure but after the block's own interruption.
#[test]
fn a_hold_records_signals_and_raises_one_at_its_release() {
    let interrupt = Interrupt::new();
    let quiet: Result<(), Halt> = super::holding(&interrupt, || Ok(()));
    assert!(quiet.is_ok());
    assert!(!interrupt.held());
    let mut reached = Vec::new();
    let failed: Result<(), Halt> = super::holding(&interrupt, || {
        let inner: Result<(), Halt> = super::holding(&interrupt, || {
            interrupt.record(libc::SIGTERM);
            Ok(())
        });
        assert!(
            inner.is_ok(),
            "a nested hold leaves the report to the outer one"
        );
        assert!(interrupt.held());
        interrupt.record(libc::SIGTERM);
        reached.push(interrupt.deliveries());
        Err(Halt::failed("the block's own failure"))
    });
    assert_eq!(reached, [2]);
    assert!(
        matches!(failed, Err(Halt::Interrupted(libc::SIGTERM))),
        "{failed:?}"
    );
    assert!(!interrupt.held());
    let other = Interrupt::new();
    let own: Result<(), Halt> = super::holding(&other, || {
        other.record(libc::SIGHUP);
        Err(Halt::Interrupted(libc::SIGINT))
    });
    assert!(
        matches!(own, Err(Halt::Interrupted(libc::SIGINT))),
        "{own:?}"
    );
}

/// A row of the grace case: its name, the signals delivered as the child starts, a signal delivered a
/// second into the stop, the deadline in seconds and the bounds of the seconds from the start to the end.
type Further = (&'static str, &'static [i32], Option<i32>, u64, f64, f64);

/// With a leader that ignores SIGTERM and a 6-second grace: the signal that ends the wait keeps the
/// grace; a second one ends it, whether both arrive before the wait reads them or the second arrives
/// during the grace; and after a deadline the first signal ends it.
#[test]
fn a_further_signal_ends_the_grace_and_the_one_that_ended_the_wait_keeps_it() {
    #[rustfmt::skip]
    let rows: [Further; 4] = [
        ("one", &[libc::SIGINT], None, 120, 6.0, 12.0),
        ("two at once", &[libc::SIGINT, libc::SIGHUP], None, 120, 0.0, 4.0),
        ("a second later", &[libc::SIGINT], Some(libc::SIGHUP), 120, 0.0, 5.0),
        ("one after a deadline", &[], Some(libc::SIGHUP), 1, 0.0, 5.0),
    ];
    for (name, at_once, later, deadline, least, most) in rows {
        let scratch = Scratch::new("weaken-further");
        let interrupt = Interrupt::new();
        let sent = std::cell::Cell::new(None);
        let leader_file = scratch.0.join("leader");
        let on_start = |_: &Child| {
            wait_for(&leader_file);
            for &signal in at_once {
                interrupt.record(signal);
            }
            sent.set(Some(Instant::now()));
        };
        std::thread::scope(|scope| {
            let on_stop = || {
                if let Some(signal) = later {
                    let interrupt = &interrupt;
                    scope.spawn(move || {
                        std::thread::sleep(Duration::from_secs(1));
                        interrupt.record(signal);
                    });
                }
            };
            let launch = Launch {
                grace: Duration::from_secs(6),
                started: &on_start,
                stopping: &on_stop,
                ..Launch::new(&interrupt)
            };
            let ran = execute(
                &launch,
                &group(&scratch.0, true),
                Path::new("."),
                None,
                Duration::from_secs(deadline),
                &scratch.0.join("out"),
            );
            let took = sent
                .get()
                .expect("the child started")
                .elapsed()
                .as_secs_f64();
            assert!(matches!(ran, Err(Halt::Interrupted(_))), "{name}: {ran:?}");
            assert!(least <= took && took < most, "{name}: {took}");
        });
        let worker = read(&scratch.0.join("worker"));
        assert!(
            gone(&worker),
            "{name}: the worker {} stays: {:?}",
            worker.trim(),
            std::fs::read_to_string(format!("/proc/{}/status", worker.trim()))
        );
        assert!(!interrupt.held(), "{name}");
    }
}

/// An output name a link already takes is refused before the child starts: the link's target keeps its
/// bytes and the command never runs.
#[test]
fn an_output_name_already_taken_is_refused_before_the_child_starts() {
    let scratch = Scratch::new("weaken-taken");
    let outside = scratch.0.join("outside");
    std::fs::write(&outside, "kept").expect("written");
    std::os::unix::fs::symlink(&outside, scratch.0.join("out")).expect("linked");
    let interrupt = Interrupt::new();
    let ran = execute(
        &Launch::new(&interrupt),
        &words(&["sh", "-c", &format!("touch {}/ran", scratch.0.display())]),
        Path::new("."),
        None,
        Duration::from_secs(10),
        &scratch.0.join("out"),
    );
    assert!(
        matches!(&ran, Err(Halt::Failed(message)) if message.contains("exists")),
        "{ran:?}"
    );
    assert_eq!(read(&outside), "kept");
    assert!(!scratch.0.join("ran").exists());
}

/// A test whose exit is first seen after its deadline counts as an exit, not a timeout: the poll reads the
/// leader's state before the clock, as the script's loop polls the child before its clock. The child has
/// exited before the wait starts, with a budget already spent.
#[test]
fn an_exit_first_seen_after_the_deadline_counts_as_an_exit() {
    let scratch = Scratch::new("weaken-late-exit");
    let interrupt = Interrupt::new();
    let on_start = |child: &Child| {
        let stat = format!("/proc/{}/stat", child.id());
        let start = Instant::now();
        while running(&child.id().to_string()) && start.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            std::fs::metadata(stat).is_ok(),
            "the child is held unreaped"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let launch = Launch {
        started: &on_start,
        ..Launch::new(&interrupt)
    };
    let (code, _) = execute(
        &launch,
        &words(&["sh", "-c", "exit 3"]),
        Path::new("."),
        None,
        Duration::from_millis(10),
        &scratch.0.join("out"),
    )
    .expect("the run ends");
    assert_eq!(code, Some(3));
}

/// A signal recorded once the deadline has passed, before the wait reads the record, finds the wait ended
/// by the deadline: no delivery is spent, so that signal ends the stop's grace at once.
#[test]
fn a_signal_after_the_deadline_ends_the_grace() {
    let scratch = Scratch::new("weaken-after-deadline");
    let interrupt = Interrupt::new();
    let leader_file = scratch.0.join("leader");
    let on_start = |_: &Child| {
        wait_for(&leader_file);
        std::thread::sleep(Duration::from_millis(1500));
        interrupt.record(libc::SIGHUP);
    };
    let launch = Launch {
        grace: Duration::from_secs(30),
        started: &on_start,
        ..Launch::new(&interrupt)
    };
    let start = Instant::now();
    let ran = execute(
        &launch,
        &group(&scratch.0, true),
        Path::new("."),
        None,
        Duration::from_secs(1),
        &scratch.0.join("out"),
    );
    assert!(
        matches!(ran, Err(Halt::Interrupted(libc::SIGHUP))),
        "{ran:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "the signal ended the 30 s grace: {:?}",
        start.elapsed()
    );
    assert!(gone(&read(&scratch.0.join("worker"))));
}

/// A test whose leader ends by its own signal gives the negated signal number as its exit code.
#[test]
fn a_test_that_its_own_signal_ends_gives_the_negated_number() {
    let scratch = Scratch::new("weaken-own-signal");
    let interrupt = Interrupt::new();
    let (code, _) = execute(
        &Launch::new(&interrupt),
        &words(&["sh", "-c", "kill -9 $$"]),
        Path::new("."),
        None,
        Duration::from_secs(60),
        &scratch.0.join("out"),
    )
    .expect("the run ends");
    assert_eq!(code, Some(-libc::SIGKILL));
}
