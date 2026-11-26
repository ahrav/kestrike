use std::io::{self, BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use super::burst::Port;
use super::containment::{ControllerSupervisor, EndpointError, FRAME};
use super::dataplane::{StopFailure, stop_port_watched};
use super::ena::EnaPort;
use super::pci::Function;
use super::pci_tests;
use super::registration::ArenaRegistration;
use super::registration::RegistrationStep;
use super::watchdog::{Supervisor, Watchdog};
use super::{Environment, registration_tests};
use crate::storage::device::scripted_table;

use crate::storage::test_platform::TestPlatform;
use crate::storage::{BufferArena, PoolKind, QuiesceProgress};

const CHILD: &str = "native::containment_tests::a_containment_child";
const SCENARIO: &str = "KESTRIKE_CONTAINMENT_SCENARIO";
const PREFIX: &str = "containment: ";
const ENDPOINT: &str = "endpoint-0";

fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{PREFIX}{line}").unwrap();
    out.flush().unwrap();
}

#[test]
fn a_containment_child() {
    let Ok(scenario) = std::env::var(SCENARIO) else {
        return;
    };
    if scenario == "panic" {
        panic!("the child fails before its witness");
    }
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    if scenario == "port" {
        port_child(registration);
        say(&release(arena));
        return;
    }
    let (mut table, _read) = scripted_table(&arena, &mut registration);
    say(&format!(
        "census pending {} storage {}",
        table.report().pending,
        arena.report(PoolKind::ReadResponse).storage
    ));
    let supervisor = Arc::new(
        ControllerSupervisor::new(
            ENDPOINT,
            std::io::stdout(),
            BufReader::new(std::io::stdin()),
        )
        .unwrap(),
    );
    if scenario == "disarm" {
        drop(Watchdog::arm(Duration::from_secs(30), supervisor.clone()).unwrap());
        say(&format!("disarmed {}", supervisor.calls()));
        return;
    }
    if scenario == "exit" {
        std::process::exit(0);
    }
    let mut out = Vec::with_capacity(1);
    assert!(
        !matches!(table.quiesce(&mut out), QuiesceProgress::Quiesced(_)),
        "the first stop call only starts the disable"
    );
    let watchdog = Watchdog::arm(Duration::from_millis(50), supervisor.clone()).unwrap();
    let waited = supervisor.clone();
    table.driver().stall_before_proof(move || {
        let start = Instant::now();
        while !waited.requested() && start.elapsed() < Duration::from_secs(20) {
            std::thread::sleep(Duration::from_millis(5));
        }
        say(if waited.requested() {
            "stalled until the request"
        } else {
            "stall timed out"
        });
    });
    if scenario == "late-panic" {
        let _ = table.quiesce(&mut out);
        panic!("the child fails after its request");
    }
    let stopped = (0..8)
        .map(|_| table.quiesce(&mut out))
        .any(|progress| matches!(progress, QuiesceProgress::Quiesced(_)));
    assert!(
        stopped && out.len() == 1,
        "the stalled disable proves the stop"
    );
    assert!(watchdog.expired(), "the watchdog expired during the stall");
    drop(out);
    let proof = table.driver().stop_proof().unwrap();
    registration.device_stopped(proof).unwrap();
    let retained = registration.unregister(&watchdog).unwrap_err();
    assert_eq!(retained.error.step, RegistrationStep::Watchdog);
    drop(retained);
    drop(table);
    say(&format!("retained Watchdog {}", release(arena)));
    drop(watchdog);
    say(&format!(
        "done {} {}",
        supervisor.calls(),
        supervisor.acknowledged()
    ));
}

fn release(arena: BufferArena<TestPlatform>) -> String {
    match arena.release() {
        Ok(_) => "release freed".to_owned(),
        Err(blocked) => format!("release blocked registrations {}", blocked.registrations),
    }
}

/// The port's stop clears bus mastering, stalls before reading the clear back until the expired watchdog's request arrives, and withholds its proof.
fn port_child(mut registration: ArenaRegistration<'_>) {
    let dir = pci_tests::Dir::new(0x0406, None);
    let lease = registration.device_attached();
    let mut port = EnaPort::detached(
        Function::open(&dir.0).unwrap(),
        None,
        registration.id(),
        true,
        Arc::new(registration_tests::Recorder::new()),
    )
    .leased(lease);
    say(&format!("census lease {}", port.device_lease().is_some()));
    let supervisor = Arc::new(
        ControllerSupervisor::new(
            ENDPOINT,
            std::io::stdout(),
            BufReader::new(std::io::stdin()),
        )
        .unwrap(),
    );
    let watchdog = Watchdog::arm(Duration::from_millis(50), supervisor.clone()).unwrap();
    let waited = supervisor.clone();
    port.stall_before_proof(move || {
        let start = Instant::now();
        while !waited.requested() && start.elapsed() < Duration::from_secs(20) {
            std::thread::sleep(Duration::from_millis(5));
        }
        say(if waited.requested() {
            "stalled until the request"
        } else {
            "stall timed out"
        });
    });
    assert_eq!(
        stop_port_watched(&mut port, &watchdog).unwrap_err(),
        StopFailure::Late
    );
    assert_eq!(dir.command(), 0x0402, "the stop cleared bus mastering");
    let retained = registration.unregister(&watchdog).unwrap_err();
    say(&format!("retained {:?}", retained.error.step));
    drop(retained);
    drop(watchdog);
    say(&format!(
        "done {} {}",
        supervisor.calls(),
        supervisor.acknowledged()
    ));
}

struct Controller {
    child: Child,
    lines: Receiver<String>,
    acknowledgements: Option<ChildStdin>,
}

impl Controller {
    fn start(scenario: &str) -> Self {
        let spawning = crate::bind::fixture::spawn_quiet();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD, "--nocapture", "--test-threads=1"])
            .env(SCENARIO, scenario)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        drop(spawning);
        let stdout = child.stdout.take().unwrap();
        let (send, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                // libtest prints `test NAME ... ` without a newline before a test's own output.
                let kept = match (line.split_once(PREFIX), line.find("contain ")) {
                    (Some((_, rest)), _) => rest.to_owned(),
                    (None, Some(at)) => line[at..].to_owned(),
                    (None, None) => continue,
                };
                if send.send(kept).is_err() {
                    break;
                }
            }
        });
        let acknowledgements = child.stdin.take();
        Self {
            child,
            lines,
            acknowledgements,
        }
    }

    fn collect(&self, until: &str, within: Duration) -> Vec<String> {
        let mut lines = Vec::new();
        let start = Instant::now();
        while start.elapsed() < within {
            if let Ok(line) = self.lines.recv_timeout(Duration::from_millis(50)) {
                let last = line.starts_with(until);
                lines.push(line);
                if last {
                    break;
                }
            }
        }
        lines
    }

    /// Collects lines through the request and asserts it names the endpoint.
    fn await_request(&self) -> Vec<String> {
        let lines = self.collect("contain ", Duration::from_secs(20));
        assert_eq!(
            lines.last().map(String::as_str),
            Some("contain endpoint-0"),
            "{lines:?}"
        );
        lines
    }

    fn acknowledge(&mut self) {
        let stdin = self.acknowledgements.as_mut().unwrap();
        writeln!(stdin, "contained {ENDPOINT}").unwrap();
        stdin.flush().unwrap();
    }

    fn exit(&mut self, within: Duration) -> Option<ExitStatus> {
        let start = Instant::now();
        while start.elapsed() < within {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn credited(lines: &[String], exit: Option<ExitStatus>) -> bool {
    let requests = lines
        .iter()
        .filter(|line| line.starts_with("contain "))
        .count();
    lines
        .iter()
        .any(|line| line == "census pending 1 storage 1")
        && requests == 1
        && lines.iter().any(|line| line == "stalled until the request")
        && lines
            .iter()
            .any(|line| line == "retained Watchdog release blocked registrations 1")
        && lines.iter().any(|line| line == "done 1 true")
        && exit.is_some_and(|status| status.success())
}

#[test]
fn an_acknowledged_request_from_a_pre_proof_stall_earns_credit_once() {
    let mut controller = Controller::start("acknowledge");
    let mut lines = controller.await_request();
    controller.acknowledge();
    lines.extend(controller.collect("done", Duration::from_secs(20)));
    let exit = controller.exit(Duration::from_secs(20));
    assert!(credited(&lines, exit), "{lines:?} {exit:?}");
}

#[test]
fn a_delayed_acknowledgement_keeps_the_child_alive_and_its_teardown_parked() {
    let mut controller = Controller::start("delay");
    let mut lines = controller.await_request();
    lines.extend(controller.collect("retained", Duration::from_secs(20)));
    assert!(
        lines
            .last()
            .is_some_and(|line| line == "retained Watchdog release blocked registrations 1"),
        "the retained registration keeps the arena unreleasable before any acknowledgement: {lines:?}"
    );
    let held = controller.collect("done", Duration::from_millis(500));
    assert!(
        held.iter().all(|line| !line.starts_with("done")),
        "the watchdog's drop waits for the acknowledgement: {held:?}"
    );
    assert!(
        controller.exit(Duration::from_millis(100)).is_none(),
        "the child stays alive"
    );
    lines.extend(held);
    controller.acknowledge();
    lines.extend(controller.collect("done", Duration::from_secs(20)));
    let exit = controller.exit(Duration::from_secs(20));
    assert!(credited(&lines, exit), "{lines:?} {exit:?}");
}

#[test]
fn a_lost_acknowledgement_channel_leaves_the_child_parked_and_uncredited() {
    let mut controller = Controller::start("lose");
    let mut lines = controller.await_request();
    lines.extend(controller.collect("retained", Duration::from_secs(20)));
    drop(controller.acknowledgements.take());
    lines.extend(controller.collect("done", Duration::from_secs(1)));
    assert!(
        lines.iter().all(|line| !line.starts_with("done")),
        "{lines:?}"
    );
    assert!(
        controller.exit(Duration::from_millis(300)).is_none(),
        "custody stays unproven, so the child stays parked"
    );
}

#[test]
fn a_child_that_ends_before_or_fails_after_its_witness_earns_no_credit() {
    for scenario in ["panic", "exit", "late-panic"] {
        let mut controller = Controller::start(scenario);
        let mut lines = Vec::new();
        if scenario == "late-panic" {
            lines = controller.await_request();
            controller.acknowledge();
        }
        let exit = controller.exit(Duration::from_secs(20));
        lines.extend(controller.collect("never", Duration::from_millis(300)));
        assert!(exit.is_some(), "{scenario}");
        assert!(!credited(&lines, exit), "{scenario}: {lines:?} {exit:?}");
    }
}

#[test]
fn a_port_stall_before_the_bus_master_read_back_escalates_once_and_withholds_its_proof() {
    let mut controller = Controller::start("port");
    let mut lines = controller.await_request();
    controller.acknowledge();
    lines.extend(controller.collect("release", Duration::from_secs(20)));
    let exit = controller.exit(Duration::from_secs(20));
    assert!(exit.is_some_and(|status| status.success()), "{lines:?}");
    let expected = [
        "census lease true",
        "contain endpoint-0",
        "stalled until the request",
        "retained DeviceStop",
        "done 1 true",
        "release blocked registrations 1",
    ];
    assert_eq!(lines, expected, "{lines:?}");
}

#[test]
fn every_caller_returns_only_after_the_one_request_is_acknowledged() {
    let (acks, mut controller) = std::io::pipe().unwrap();
    let supervisor =
        Arc::new(ControllerSupervisor::new(ENDPOINT, Vec::new(), BufReader::new(acks)).unwrap());
    let returned = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let callers: Vec<_> = (0..2)
        .map(|_| {
            let (supervisor, returned) = (supervisor.clone(), returned.clone());
            std::thread::spawn(move || {
                supervisor.contain();
                returned.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            })
        })
        .collect();
    let start = Instant::now();
    while !supervisor.requested() && start.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(50));
    assert!(supervisor.requested());
    assert_eq!(returned.load(std::sync::atomic::Ordering::Acquire), 0);
    assert!(
        !supervisor.verified(),
        "an unacknowledged request verifies no containment"
    );
    writeln!(controller, "contained {ENDPOINT}").unwrap();
    for caller in callers {
        caller.join().unwrap();
    }
    assert_eq!(supervisor.calls(), 2);
    assert!(supervisor.acknowledged());
    assert!(
        supervisor.requested(),
        "the acknowledged request stays on record"
    );
    assert!(
        supervisor.verified(),
        "the controller's acknowledgement is the containment the supervisor verified"
    );
}

#[test]
fn an_acknowledgement_frame_past_the_limit_refuses_the_channel() {
    let (acks, mut controller) = std::io::pipe().unwrap();
    let supervisor =
        Arc::new(ControllerSupervisor::new(ENDPOINT, Vec::new(), BufReader::new(acks)).unwrap());
    let caller = {
        let supervisor = supervisor.clone();
        std::thread::spawn(move || supervisor.contain())
    };
    let start = Instant::now();
    while !supervisor.requested() && start.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(supervisor.requested());
    controller.write_all(&[b'x'; 8192]).unwrap();
    writeln!(controller, "\ncontained {ENDPOINT}").unwrap();
    drop(controller);
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !supervisor.acknowledged() && !caller.is_finished(),
        "an oversized frame refuses the channel; the caller stays parked"
    );
}

#[test]
fn an_acknowledgement_matches_an_endpoint_ending_in_whitespace() {
    let (acks, mut controller) = std::io::pipe().unwrap();
    let id = format!("{ENDPOINT} \t");
    let supervisor =
        Arc::new(ControllerSupervisor::new(id.clone(), Vec::new(), BufReader::new(acks)).unwrap());
    let caller = {
        let supervisor = supervisor.clone();
        std::thread::spawn(move || supervisor.contain())
    };
    writeln!(controller, "contained {id}").unwrap();
    let start = Instant::now();
    while !caller.is_finished() && start.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        supervisor.acknowledged() && caller.is_finished(),
        "the acknowledgement names the endpoint byte for byte"
    );
}

/// Starts `contain` on another thread and returns once the request is written.
fn requested<R: BufRead + Send + 'static>(
    id: &str,
    acks: R,
) -> (
    Arc<ControllerSupervisor<Vec<u8>, R>>,
    std::thread::JoinHandle<()>,
) {
    let supervisor = Arc::new(ControllerSupervisor::new(id, Vec::new(), acks).unwrap());
    let caller = {
        let supervisor = supervisor.clone();
        std::thread::spawn(move || supervisor.contain())
    };
    let start = Instant::now();
    while !supervisor.requested() && start.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(supervisor.requested());
    (supervisor, caller)
}

fn settled(caller: &std::thread::JoinHandle<()>) -> bool {
    let start = Instant::now();
    while !caller.is_finished() && start.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    caller.is_finished()
}

#[test]
fn a_frame_that_is_not_utf_8_is_skipped_like_any_other_foreign_frame() {
    let (acks, mut controller) = std::io::pipe().unwrap();
    let (supervisor, caller) = requested(ENDPOINT, BufReader::new(acks));
    controller.write_all(b"note \xff\n").unwrap();
    writeln!(controller, "contained {ENDPOINT}").unwrap();
    assert!(
        settled(&caller) && supervisor.acknowledged(),
        "the acknowledgement after a foreign frame is seen"
    );
}

#[test]
fn an_acknowledgement_is_one_line_feed_terminated_frame_of_at_most_frame_bytes() {
    let (acks, mut controller) = std::io::pipe().unwrap();
    let (supervisor, caller) = requested(ENDPOINT, BufReader::new(acks));
    write!(controller, "contained {ENDPOINT}\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !supervisor.acknowledged() && !caller.is_finished(),
        "a frame ending in CR LF names another endpoint"
    );
    writeln!(controller, "contained {ENDPOINT}").unwrap();
    assert!(settled(&caller) && supervisor.acknowledged());

    let (acks, mut controller) = std::io::pipe().unwrap();
    let longest = "x".repeat(FRAME - "contained ".len() - 1);
    let (supervisor, caller) = requested(&longest, BufReader::new(acks));
    writeln!(controller, "contained {longest}").unwrap();
    assert!(
        settled(&caller) && supervisor.acknowledged(),
        "the longest endpoint fills a frame exactly"
    );
}

#[test]
fn an_endpoint_that_cannot_frame_as_one_line_is_refused() {
    fn refusal(id: &str) -> Option<EndpointError> {
        ControllerSupervisor::new(id, Vec::new(), BufReader::new(std::io::empty())).err()
    }
    assert_eq!(refusal(""), Some(EndpointError::Empty));
    assert_eq!(refusal("a\ncontain b"), Some(EndpointError::LineBreak));
    assert_eq!(refusal("a\rcontain b"), Some(EndpointError::LineBreak));
    let longest = "x".repeat(FRAME - "contained ".len() - 1);
    assert_eq!(refusal(&longest), None);
    assert_eq!(refusal(&format!("{longest}x")), Some(EndpointError::Long));
}

const REQUEST: &[u8] = b"contain endpoint-0\n";

/// Where the controller's channel breaks.
#[derive(Clone, Copy, Debug)]
enum Break {
    /// The first write fails and takes no byte.
    Write,
    /// The first write takes part of the request and the next write fails.
    PartialWrite,
    /// Every byte is taken and the flush fails.
    Flush,
}

/// A controller channel that breaks at `at` and raises `broke` when it
/// returns the error.
struct BrokenChannel {
    at: Break,
    taken: Wire,
    broke: Arc<AtomicBool>,
}

impl BrokenChannel {
    fn fail(&self) -> io::Error {
        self.broke.store(true, Ordering::Release);
        io::Error::from(io::ErrorKind::BrokenPipe)
    }
}

impl Write for BrokenChannel {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut taken = self.taken.0.lock().unwrap();
        let take = match self.at {
            Break::Write => return Err(self.fail()),
            Break::PartialWrite if !taken.is_empty() => return Err(self.fail()),
            Break::PartialWrite => bytes.len().min(3),
            Break::Flush => bytes.len(),
        };
        taken.extend_from_slice(&bytes[..take]);
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        // The flush break took every byte, so its flush follows the whole request line; the flush returns the channel's error for every break.
        if matches!(self.at, Break::Flush) {
            assert_eq!(
                *self.taken.0.lock().unwrap(),
                REQUEST,
                "the flush follows the whole request line"
            );
        }
        Err(self.fail())
    }
}

/// One caller's `contain` over a channel that breaks at `at`, with a
/// controller that sends nothing: after the channel's error the caller is
/// unparked repeatedly for `OBSERVED` and must neither return nor leave a
/// request or an acknowledgement on record.
fn the_caller_stays_parked_when_the_channel_breaks_at(at: Break) {
    const OBSERVED: Duration = Duration::from_millis(300);
    const STEP: Duration = Duration::from_millis(10);

    let broke = Arc::new(AtomicBool::new(false));
    let taken = Wire::default();
    let channel = BrokenChannel {
        at,
        taken: taken.clone(),
        broke: broke.clone(),
    };
    let supervisor = Arc::new(ControllerSupervisor::new(ENDPOINT, channel, io::empty()).unwrap());
    let (returned, returns) = mpsc::channel();
    let caller = {
        let supervisor = supervisor.clone();
        thread::spawn(move || {
            supervisor.contain();
            // The receiver may be gone when a caller returns after the observation.
            let _ = returned.send(());
        })
    };

    let start = Instant::now();
    while !broke.load(Ordering::Acquire) {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "{at:?}: the first call sends the request"
        );
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(supervisor.calls(), 1, "{at:?}");

    let observed = Instant::now();
    while observed.elapsed() < OBSERVED {
        caller.thread().unpark();
        assert_eq!(
            returns.recv_timeout(STEP),
            Err(RecvTimeoutError::Timeout),
            "{at:?}: the caller returned without an acknowledgement"
        );
        assert!(
            !supervisor.requested(),
            "{at:?}: the request was not written and flushed"
        );
        assert!(
            !supervisor.acknowledged() && !supervisor.verified(),
            "{at:?}: the controller acknowledged nothing"
        );
    }
    assert!(!caller.is_finished(), "{at:?}: the caller stays parked");
    let took = match at {
        Break::Write => 0,
        Break::PartialWrite => 3,
        Break::Flush => REQUEST.len(),
    };
    assert_eq!(
        *taken.0.lock().unwrap(),
        REQUEST[..took],
        "{at:?}: the channel holds exactly the request's bytes up to its break"
    );
}

/// A channel whose first write fails takes no byte of the request, so the
/// controller has nothing to acknowledge: through 300 ms of unparks the
/// caller stays inside `contain`, and the supervisor reports the request
/// unsent and unacknowledged.
#[test]
fn a_request_that_fails_at_the_write_keeps_the_caller_parked() {
    the_caller_stays_parked_when_the_channel_breaks_at(Break::Write);
}

/// A channel that takes three bytes of the request and fails the next write
/// leaves the request line incomplete: through 300 ms of unparks the caller
/// stays inside `contain`, and the supervisor reports the request unsent and
/// unacknowledged.
#[test]
fn a_request_that_fails_after_a_partial_write_keeps_the_caller_parked() {
    the_caller_stays_parked_when_the_channel_breaks_at(Break::PartialWrite);
}

/// A channel that takes the whole request line and fails the flush leaves
/// the request unflushed, which the supervisor counts as unsent: through
/// 300 ms of unparks the caller stays inside `contain`, and the supervisor
/// reports the request unsent and unacknowledged.
#[test]
fn a_request_that_fails_at_the_flush_keeps_the_caller_parked() {
    the_caller_stays_parked_when_the_channel_breaks_at(Break::Flush);
}

#[test]
fn disarming_before_the_deadline_sends_no_request() {
    let mut controller = Controller::start("disarm");
    let lines = controller.collect("disarmed", Duration::from_secs(20));
    let exit = controller.exit(Duration::from_secs(20));
    assert!(exit.is_some_and(|status| status.success()), "{lines:?}");
    assert_eq!(lines.last().map(String::as_str), Some("disarmed 0"));
    assert!(
        lines.iter().all(|line| !line.starts_with("contain ")),
        "{lines:?}"
    );
}

/// A controller channel that keeps every byte the supervisor wrote where the
/// test can read it while the supervisor still owns the writer.
#[derive(Clone, Default)]
struct Wire(Arc<std::sync::Mutex<Vec<u8>>>);

impl Wire {
    /// The frames written so far, each without its line break.
    fn frames(&self) -> Vec<String> {
        let bytes = self.0.lock().unwrap();
        bytes
            .split_inclusive(|byte| *byte == b'\n')
            .map(|frame| {
                String::from_utf8_lossy(frame)
                    .trim_end_matches('\n')
                    .to_owned()
            })
            .collect()
    }
}

impl Write for Wire {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A supervisor whose controller acknowledges the first request and then
/// closes its stream, after `calls` calls of `contain` on this thread;
/// `calls` is at least one.
fn contained(calls: u32) -> (Wire, ControllerSupervisor<Wire, std::io::Cursor<Vec<u8>>>) {
    let wire = Wire::default();
    let acknowledgement = format!("contained {ENDPOINT}\n").into_bytes();
    assert!(acknowledgement.len() <= FRAME);
    let supervisor = ControllerSupervisor::new(
        ENDPOINT,
        wire.clone(),
        std::io::Cursor::new(acknowledgement),
    )
    .unwrap();
    for _ in 0..calls {
        supervisor.contain();
    }
    assert!(supervisor.acknowledged());
    (wire, supervisor)
}

/// Only the first `contain` call sends a request: the calls that follow the
/// controller's acknowledgement are each counted and leave the channel
/// holding that one frame.
#[test]
fn calls_after_the_acknowledgement_send_no_second_request() {
    let (wire, supervisor) = contained(1 << 16);
    assert_eq!(supervisor.calls(), 1 << 16);
    assert_eq!(wire.frames(), [format!("contain {ENDPOINT}")]);
}

/// Only the first `contain` call sends a request, however many calls
/// follow. The count of calls is a `u32`, which 2^32 - 1 calls bring to
/// `u32::MAX`; the test sets it there after the acknowledged first call.
/// The two calls that follow are past what the count can hold: each
/// leaves the channel holding that one frame, so the controller receives
/// one request for the containment it acknowledges, and the count stays at
/// `u32::MAX`.
#[test]
fn a_call_past_the_range_of_the_call_count_sends_no_second_request() {
    let (wire, supervisor) = contained(1);
    supervisor.set_calls(u32::MAX);
    supervisor.contain();
    assert_eq!(wire.frames(), [format!("contain {ENDPOINT}")]);
    supervisor.contain();
    assert_eq!(
        wire.frames(),
        [format!("contain {ENDPOINT}")],
        "only the first call of `contain` sends a request"
    );
    assert_eq!(supervisor.calls(), u32::MAX);
}
