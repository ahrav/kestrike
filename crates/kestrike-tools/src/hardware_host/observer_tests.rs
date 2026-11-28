//! Each case writes its own log in a scratch directory and takes its lock alone; a case that expects an
//! attempt to pass reads a clock under which a refusal waits for the next attempt. A case whose probe
//! would block if a lock attempt blocked runs the probe under [`within`].

use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use super::{EventError, Observer, ObserverError};
use crate::hardware_host::within::within;
use crate::hardware_host::{Clocks, System, reserve_host};
use crate::host_stop::{Delivered, Interrupted, Record, Signal};
use crate::json::{self, Integer, Object, Text, Value};
use crate::paths::tests::Scratch;

/// Clocks that give scripted monotonic readings in order, then `beyond` at each later read when it is
/// set, one nanosecond more each time unless `still` holds, record each reading, count the sleeps, and
/// run `on_sleep` at each sleep.
struct Scripted {
    readings: RefCell<VecDeque<u64>>,
    beyond: RefCell<Option<u64>>,
    still: std::cell::Cell<bool>,
    seen: RefCell<Vec<u64>>,
    sleeps: usize,
    on_sleep: Box<dyn FnMut(usize)>,
}

impl Scripted {
    /// Clocks that read `reading` at every read, so an attempt refused by a fork's brief copy of an
    /// earlier descriptor waits under a deadline that never comes.
    fn constant(reading: u64) -> Self {
        let clocks = Self::new(&[]);
        *clocks.beyond.borrow_mut() = Some(reading);
        clocks.still.set(true);
        clocks
    }

    fn new(readings: &[u64]) -> Self {
        Self {
            readings: RefCell::new(readings.iter().copied().collect()),
            beyond: RefCell::new(None),
            still: std::cell::Cell::new(false),
            seen: RefCell::new(Vec::new()),
            sleeps: 0,
            on_sleep: Box::new(|_| {}),
        }
    }
}

impl Clocks for Scripted {
    fn monotonic_ns(&self) -> io::Result<u64> {
        let scripted = self.readings.borrow_mut().pop_front();
        let reading = scripted.unwrap_or_else(|| {
            let mut beyond = self.beyond.borrow_mut();
            let next = beyond.expect("the script holds a reading for every read");
            if !self.still.get() {
                *beyond = Some(next + 1);
            }
            next
        });
        self.seen.borrow_mut().push(reading);
        Ok(reading)
    }

    fn wall(&self) -> f64 {
        1_700_000_000.25
    }

    /// Each sleep between attempts lasts 50 ms.
    fn sleep(&mut self, _: &mut Record<'_>, length: Duration) -> Result<(), Interrupted> {
        assert_eq!(length, Duration::from_millis(50));
        assert!(self.sleeps < 10_000, "the wait ends within 10,000 sleeps");
        std::thread::sleep(Duration::from_millis(1));
        self.sleeps += 1;
        (self.on_sleep)(self.sleeps);
        Ok(())
    }
}

const READING: u64 = 123_456_789_012_345;
const LIMIT: Duration = Duration::from_secs(5);

fn observer(directory: &OsStr, episode: &str) -> Observer {
    limited(directory, episode, LIMIT)
}

fn limited(directory: &OsStr, episode: &str, limit: Duration) -> Observer {
    Observer::new(
        directory,
        OsStr::new(episode),
        Text::from("prof"),
        Text::from("fis"),
        limit,
    )
}

/// The kernel's node name, read from its file less the final line feed.
fn node() -> String {
    let name = fs::read_to_string("/proc/sys/kernel/hostname").expect("the node name reads");
    name.strip_suffix('\n').unwrap_or(&name).to_owned()
}

fn experiment() -> Object {
    let mut fields = Object::new();
    fields.insert("experiment", Value::String(Text::from("EXP1")));
    fields.insert(
        "note",
        json::parse(r#"[1, 2.5, null, "\u00e9"]"#).expect("JSON"),
    );
    fields
}

/// An append writes one line of the event with its keys sorted, `, ` and `: ` between items, and the
/// readings it takes under the lock, at least two per append (one before the first attempt and one
/// under the lock, more where another case's fork briefly holds a copy of the first append's
/// descriptor), and returns that event; a field of the caller takes the place of the member of the same key. A directory spelled
/// with `//./` names the log by its pure path.
#[test]
fn an_append_writes_one_sorted_line_for_fixed_readings() {
    let scratch = Scratch::new("observer-append");
    let directory = scratch.0.join("deep/er");
    let mut slashed = directory.as_os_str().to_owned();
    slashed.push("//./");
    let log = directory.join("ep1.jsonl");
    assert_eq!(
        observer(&slashed, "ep1").path().map(Path::as_os_str),
        Some(log.as_os_str())
    );
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let mut clocks = Scripted::constant(READING);
    let event = observer(&slashed, "ep1")
        .append(&mut clocks, &mut record, "fault-start", experiment())
        .expect("the append succeeds")
        .expect("a log stands");
    let mut fields = Object::new();
    fields.insert("ordinal", Value::Integer(Integer::from(99u64)));
    observer(directory.as_os_str(), "ep1")
        .append(&mut clocks, &mut record, "fault-end", fields)
        .expect("the second append succeeds");
    let host = node();
    let first = format!(
        "{{\"episode\": \"ep1\", \"experiment\": \"EXP1\", \"host\": \"{host}\", \"kind\": \"fault-start\", \
         \"monotonic_ns\": 123456789012345, \"note\": [1, 2.5, null, \"\\u00e9\"], \"ordinal\": 1, \
         \"profile\": \"prof\", \"role\": \"fis\", \"wall_diagnostic\": 1700000000.25}}\n"
    );
    let second = format!(
        "{{\"episode\": \"ep1\", \"host\": \"{host}\", \"kind\": \"fault-end\", \"monotonic_ns\": \
         123456789012345, \"ordinal\": 99, \"profile\": \"prof\", \"role\": \"fis\", \
         \"wall_diagnostic\": 1700000000.25}}\n"
    );
    assert_eq!(
        fs::read_to_string(&log).expect("the log reads"),
        first.clone() + &second
    );
    assert_eq!(json::line_sorted(&Value::Object(event)) + "\n", first);
    assert!(clocks.seen.borrow().len() >= 4);
}

/// A caller's `ordinal` takes the place of the assigned one, so it can repeat the ordinal the next
/// append assigns: two events of one log then both hold 2.
#[test]
fn a_caller_ordinal_can_repeat_an_assigned_one() {
    let scratch = Scratch::new("observer-repeat");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let mut clocks = Scripted::constant(READING);
    let observer = observer(scratch.0.as_os_str(), "e");
    let mut fields = Object::new();
    fields.insert("ordinal", Value::Integer(Integer::from(2u64)));
    observer
        .append(&mut clocks, &mut record, "x", fields)
        .expect("the first append succeeds");
    observer
        .append(&mut clocks, &mut record, "y", Object::new())
        .expect("the second append succeeds");
    let ordinals: Vec<String> = observer
        .events(&mut clocks, &mut record)
        .expect("reads")
        .iter()
        .map(|event| match event {
            Value::Object(event) => json::text(event.get("ordinal").expect("an ordinal")),
            other => panic!("an event is an object: {other:?}"),
        })
        .collect();
    assert_eq!(ordinals, ["2", "2"]);
}

/// Runs in a child of [`created_files_take_mode_0644`] alone, under umask 0, and returns at once in any
/// other run: it makes a control file of mode 0666, the observer log by an append and `fis.lock` by a
/// reservation in the directory the child is given.
#[test]
fn mode_probe() {
    let Some(directory) = std::env::var_os("KESTRIKE_TOOLS_MODE_PROBE") else {
        return;
    };
    let directory = PathBuf::from(directory);
    File::options()
        .write(true)
        .create_new(true)
        .mode(0o666)
        .open(directory.join("control"))
        .expect("the control is made");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    observer(directory.as_os_str(), "e")
        .append(
            &mut Scripted::constant(READING),
            &mut record,
            "x",
            Object::new(),
        )
        .expect("the append succeeds");
    let reservation = reserve_host(&directory).expect("the lock opens");
    assert!(reservation.is_some());
}

/// The log and `fis.lock` are made with mode 0644: a child under umask 0 makes both beside a control
/// of mode 0666, whose mode shows that neither the umask nor a default ACL of the directory lessens
/// what a creation asks.
#[test]
fn created_files_take_mode_0644() {
    let scratch = Scratch::new("observer-modes");
    let status = Command::new("/bin/sh")
        .args(["-c", "umask 0; exec \"$0\" \"$@\""])
        .arg(std::env::current_exe().expect("the test executable"))
        .args([
            "--exact",
            "hardware_host::observer::tests::mode_probe",
            "--test-threads=1",
            "-q",
        ])
        .env("KESTRIKE_TOOLS_MODE_PROBE", &scratch.0)
        .stdout(Stdio::null())
        .status()
        .expect("the child starts");
    assert!(status.success());
    let mode = |name: &str| {
        fs::metadata(scratch.0.join(name))
            .unwrap_or_else(|error| panic!("{name} stands: {error}"))
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode("control"), 0o666);
    assert_eq!(mode("e.jsonl"), 0o644);
    assert_eq!(mode("fis.lock"), 0o644);
}

/// The ordinal counts the lines another writer left that are not blank between `\n`, a U+2028 inside a
/// string included, while a read splits at every one of Python's line boundaries, so a log whose one
/// line holds a raw U+2028 inside a string refuses the read.
#[test]
fn an_ordinal_follows_the_nonblank_lines_of_another_writer() {
    let scratch = Scratch::new("observer-behind");
    let log = scratch.0.join("ep2.jsonl");
    fs::write(
        &log,
        b"{\"a\": 1}\r\n\n   \r{\"b\": 2}\r{\"c\": \"\xe2\x80\xa8\"}\n",
    )
    .expect("written");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let mut clocks = Scripted::constant(READING);
    let observer = observer(scratch.0.as_os_str(), "ep2");
    let event = observer
        .append(&mut clocks, &mut record, "stop", Object::new())
        .expect("the append succeeds")
        .expect("a log stands");
    assert_eq!(
        event.get("ordinal"),
        Some(&Value::Integer(Integer::from(4u64)))
    );
    fs::write(&log, b"{\"c\": \"\xe2\x80\xa8\"}\n").expect("written");
    let refused = observer
        .events(&mut clocks, &mut record)
        .expect_err("a read refuses");
    let path = log.display();
    assert!(
        refused
            .to_string()
            .starts_with(&format!("the observer log {path} is malformed: ")),
        "{refused}"
    );
}

/// A read skips an empty line alone: a line of spaces is no JSON value and refuses the read, while an
/// append skips it.
#[test]
fn a_read_refuses_a_line_of_spaces_that_an_append_skips() {
    let scratch = Scratch::new("observer-spaces");
    fs::write(scratch.0.join("e.jsonl"), "{\"a\": 1}\n \n\n").expect("written");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let mut clocks = Scripted::constant(READING);
    let observer = observer(scratch.0.as_os_str(), "e");
    assert!(matches!(
        observer.events(&mut clocks, &mut record),
        Err(ObserverError::Malformed { .. })
    ));
    let event = observer
        .append(&mut clocks, &mut record, "x", Object::new())
        .expect("the append succeeds")
        .expect("a log stands");
    assert_eq!(
        event.get("ordinal"),
        Some(&Value::Integer(Integer::from(2u64)))
    );
}

/// A read gives each event in order, each line's JSON value as the line spells it, across `\r\n`, a
/// U+0085 boundary and an empty line between two events.
#[test]
fn a_read_gives_every_event_in_order() {
    let scratch = Scratch::new("observer-read");
    fs::write(
        scratch.0.join("e.jsonl"),
        "{\"a\": 1}\r\n[2]\u{85}4\n\n\"three\"\n",
    )
    .expect("written");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let events = observer(scratch.0.as_os_str(), "e")
        .events(&mut Scripted::constant(READING), &mut record)
        .expect("the read succeeds");
    let expected =
        ["{\"a\": 1}", "[2]", "4", "\"three\""].map(|text| json::parse(text).expect("JSON"));
    assert_eq!(events, expected);
}

/// A log whose last line is a whole event without its line feed takes an append on the same line, so
/// the two events stand joined, the read refuses that line and the next append refuses the log; the
/// same event with its line feed leaves two events.
#[test]
fn an_append_after_an_unterminated_line_joins_it() {
    let scratch = Scratch::new("observer-unterminated");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let mut clocks = Scripted::constant(READING);
    for (episode, earlier, joined) in [
        ("open", "{\"a\": 1}", true),
        ("closed", "{\"a\": 1}\n", false),
    ] {
        let log = scratch.0.join(format!("{episode}.jsonl"));
        fs::write(&log, earlier).expect("written");
        let observer = observer(scratch.0.as_os_str(), episode);
        let event = observer
            .append(&mut clocks, &mut record, "x", Object::new())
            .expect("the append succeeds")
            .expect("a log stands");
        assert_eq!(
            event.get("ordinal"),
            Some(&Value::Integer(Integer::from(2u64)))
        );
        let line = json::line_sorted(&Value::Object(event)) + "\n";
        assert_eq!(
            fs::read_to_string(&log).expect("reads"),
            format!("{earlier}{line}")
        );
        let read = observer.events(&mut clocks, &mut record);
        if joined {
            assert!(
                matches!(read, Err(ObserverError::Malformed { .. })),
                "{read:?}"
            );
            let refused = observer.append(&mut clocks, &mut record, "y", Object::new());
            assert!(
                matches!(refused, Err(ObserverError::Line { .. })),
                "{refused:?}"
            );
        } else {
            assert_eq!(read.expect("reads").len(), 2);
        }
    }
}

/// A field that nests one level short of the reader's limit, the event's own object counted, is
/// written and read back; one level more refuses the append before any write, and a shallow append
/// then succeeds.
#[test]
fn an_append_refuses_a_field_nested_past_the_reader_limit() {
    let nested = |depth: usize| {
        let mut value = Value::Null;
        for _ in 0..depth {
            value = Value::Array(vec![value]);
        }
        value
    };
    let scratch = Scratch::new("observer-depth");
    let log = scratch.0.join("e.jsonl");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let mut clocks = Scripted::constant(READING);
    let observer = observer(scratch.0.as_os_str(), "e");
    let mut fields = Object::new();
    fields.insert("deep", nested(json::MAX_DEPTH - 1));
    observer
        .append(&mut clocks, &mut record, "x", fields)
        .expect("the deepest field is written");
    assert_eq!(
        observer
            .events(&mut clocks, &mut record)
            .expect("reads")
            .len(),
        1
    );
    let before = fs::read(&log).expect("reads");
    let mut fields = Object::new();
    fields.insert("deep", nested(json::MAX_DEPTH));
    match observer.append(&mut clocks, &mut record, "x", fields) {
        Err(ObserverError::Depth { key }) => assert_eq!(key, Text::from("deep")),
        other => panic!("the field is refused: {other:?}"),
    }
    assert_eq!(fs::read(&log).expect("reads"), before);
    observer
        .append(&mut clocks, &mut record, "x", Object::new())
        .expect("a shallow append succeeds");
}

/// A FIFO at the log's name refuses the append with the seek's `ESPIPE` before the lock, so the append
/// does not wait on the FIFO and leaves no lock held.
#[test]
fn an_append_refuses_a_fifo_at_the_log_name() {
    let scratch = Scratch::new("observer-fifo");
    let fifo = scratch.0.join("e.jsonl");
    let made = Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo starts");
    assert!(made.success());
    let directory = scratch.0.clone();
    let refused = within("an append to a FIFO", move || {
        let delivered = Delivered::new();
        let mut record = Record::new(&delivered);
        observer(directory.as_os_str(), "e")
            .append(
                &mut Scripted::constant(READING),
                &mut record,
                "x",
                Object::new(),
            )
            .map(drop)
    });
    match refused {
        Err(ObserverError::Open(error)) => assert_eq!(error.raw_os_error(), Some(libc::ESPIPE)),
        other => panic!("the FIFO is refused: {other:?}"),
    }
    let probe = File::options()
        .read(true)
        .write(true)
        .open(&fifo)
        .expect("the FIFO opens for reading and writing");
    probe.try_lock().expect("no lock of the FIFO is held");
}

/// A malformed line refuses a read with a sentence that names the log, and refuses an append, which
/// then writes nothing; the same log without that line takes the append.
#[test]
fn a_malformed_line_refuses_a_read_and_an_append() {
    let scratch = Scratch::new("observer-malformed");
    let log = scratch.0.join("ep3.jsonl");
    fs::write(&log, "{\"a\": 1}\n{oops\n").expect("written");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let mut clocks = Scripted::constant(READING);
    let observer = observer(scratch.0.as_os_str(), "ep3");
    let refused = observer
        .events(&mut clocks, &mut record)
        .expect_err("the read refuses");
    assert_eq!(
        refused.to_string(),
        format!(
            "the observer log {} is malformed: expected a key at byte 1",
            log.display()
        )
    );
    let refused = observer
        .append(&mut clocks, &mut record, "stop", Object::new())
        .expect_err("the append refuses");
    assert!(matches!(refused, ObserverError::Line { .. }), "{refused:?}");
    assert_eq!(
        fs::read_to_string(&log).expect("reads"),
        "{\"a\": 1}\n{oops\n"
    );
    fs::write(&log, "{\"a\": 1}\n").expect("written");
    observer
        .append(&mut clocks, &mut record, "stop", Object::new())
        .expect("the control append succeeds");
    assert_ne!(fs::read_to_string(&log).expect("reads"), "{\"a\": 1}\n");
}

/// A byte outside UTF-8 inside a string of the log refuses a read and an append, and the append writes
/// nothing; the same log in UTF-8 reads.
#[test]
fn a_log_outside_utf8_refuses_a_read_and_an_append() {
    let scratch = Scratch::new("observer-undecodable");
    let log = scratch.0.join("e.jsonl");
    fs::write(&log, b"{\"a\": \"\xff\"}\n").expect("written");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let mut clocks = Scripted::constant(READING);
    let observer = observer(scratch.0.as_os_str(), "e");
    assert!(matches!(
        observer.events(&mut clocks, &mut record),
        Err(ObserverError::Undecodable { .. })
    ));
    assert!(matches!(
        observer.append(&mut clocks, &mut record, "x", Object::new()),
        Err(ObserverError::Undecodable { .. })
    ));
    assert_eq!(fs::read(&log).expect("reads"), b"{\"a\": \"\xff\"}\n");
    fs::write(&log, "{\"a\": \"\u{ff}\"}\n").expect("written");
    assert_eq!(
        observer
            .events(&mut clocks, &mut record)
            .expect("reads")
            .len(),
        1
    );
}

/// A link at the log's name refuses the read and the append with `ELOOP`, and the append writes nothing
/// through it; an append to the link's target by its own name writes there.
#[test]
fn a_link_at_the_log_name_is_refused() {
    let scratch = Scratch::new("observer-link");
    let target = scratch.0.join("target.jsonl");
    fs::write(&target, "").expect("written");
    symlink("target.jsonl", scratch.0.join("link.jsonl")).expect("linked");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let mut clocks = Scripted::constant(READING);
    let link = observer(scratch.0.as_os_str(), "link");
    for refused in [
        link.events(&mut clocks, &mut record).map(drop),
        link.append(&mut clocks, &mut record, "x", Object::new())
            .map(drop),
    ] {
        match refused {
            Err(ObserverError::Open(error)) => assert_eq!(error.raw_os_error(), Some(libc::ELOOP)),
            other => panic!("the link is refused: {other:?}"),
        }
    }
    assert_eq!(fs::read_to_string(&target).expect("reads"), "");
    observer(scratch.0.as_os_str(), "target")
        .append(&mut clocks, &mut record, "x", Object::new())
        .expect("the control append succeeds");
    assert_ne!(fs::read_to_string(&target).expect("reads"), "");
}

/// An absent log gives no events and makes no file; an empty directory text names no log, gives no
/// events and no append, and makes nothing, while the same append under a directory makes the log.
#[test]
fn an_absent_log_and_no_log_give_nothing() {
    let scratch = Scratch::new("observer-absent");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let mut clocks = Scripted::new(&[]);
    let absent = observer(scratch.0.as_os_str(), "none");
    assert_eq!(absent.events(&mut clocks, &mut record).expect("reads"), []);
    assert!(!scratch.0.join("none.jsonl").exists());
    let none = observer(OsStr::new(""), "none");
    assert_eq!(none.path(), None);
    assert_eq!(none.events(&mut clocks, &mut record).expect("reads"), []);
    assert_eq!(
        none.append(&mut clocks, &mut record, "x", Object::new())
            .expect("no log is no error"),
        None
    );
    assert!(clocks.seen.borrow().is_empty());
    let mut clocks = Scripted::constant(READING);
    absent
        .append(&mut clocks, &mut record, "x", Object::new())
        .expect("the control append succeeds");
    assert!(scratch.0.join("none.jsonl").exists());
}

/// Holds an exclusive lock of `path` through a file description of its own until it drops.
fn holder(path: &Path) -> File {
    let file = opened(path);
    file.lock().expect("the holder locks");
    file
}

fn opened(path: &Path) -> File {
    File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .expect("the holder opens")
}

/// A shared holder lets a read pass at its first attempt and holds an append off until the deadline,
/// so an append's lock is exclusive and a read's shared.
#[test]
fn a_shared_holder_admits_a_read_and_holds_off_an_append() {
    let scratch = Scratch::new("observer-shared");
    let log = scratch.0.join("e.jsonl");
    let shared = opened(&log);
    shared.lock_shared().expect("the holder locks");
    let directory: OsString = scratch.0.as_os_str().to_owned();
    let (events, sleeps, appended) =
        within("a read and an append beside a shared holder", move || {
            let delivered = Delivered::new();
            let mut record = Record::new(&delivered);
            let observer = observer(&directory, "e");
            let mut clocks = Scripted::constant(READING);
            let events = observer
                .events(&mut clocks, &mut record)
                .map_err(|error| error.to_string());
            let limit = u64::try_from(LIMIT.as_nanos()).expect("the limit fits");
            let mut held = Scripted::new(&[READING, READING + limit]);
            let appended = observer.append(&mut held, &mut record, "x", Object::new());
            (
                events,
                clocks.sleeps,
                matches!(appended, Err(ObserverError::Held { .. })),
            )
        });
    assert_eq!(events.expect("reads"), []);
    assert_eq!(sleeps, 0);
    assert!(appended);
    assert_eq!(fs::read_to_string(&log).expect("reads"), "");
}

/// Eight threads, each with an observer and opens of its own, append 25 events each to one log under
/// the system's clocks; the log then holds 200 lines whose ordinals are 1 to 200 in the order of the
/// lines.
#[test]
fn writers_at_once_give_each_ordinal_once() {
    let scratch = Scratch::new("observer-writers");
    let directory = scratch.0.as_os_str().to_owned();
    let writers: Vec<_> = (0..8)
        .map(|_| {
            let directory = directory.clone();
            std::thread::spawn(move || {
                let delivered = Delivered::new();
                let mut record = Record::new(&delivered);
                let observer = observer(&directory, "e");
                for _ in 0..25 {
                    observer
                        .append(&mut System, &mut record, "x", Object::new())
                        .expect("the append succeeds");
                }
            })
        })
        .collect();
    for writer in writers {
        writer.join().expect("the writer ends");
    }
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let ordinals: Vec<String> = observer(&directory, "e")
        .events(&mut System, &mut record)
        .expect("reads")
        .iter()
        .map(|event| match event {
            Value::Object(event) => json::text(event.get("ordinal").expect("an ordinal")),
            other => panic!("an event is an object: {other:?}"),
        })
        .collect();
    let expected: Vec<String> = (1..=200).map(|ordinal: u32| ordinal.to_string()).collect();
    assert_eq!(ordinals, expected);
}

/// A lock freed before the limit is taken: the wait reads the clock once before the first attempt and
/// once after each refusal, sleeps after each refusal under the deadline, and the append then counts
/// the lines under its lock, the holder's line written while it held the lock included, and takes its
/// own reading. A fork of another case can hold a copy of the holder's descriptor for a moment after
/// the holder drops, so the count of refusals past the second is left open and each later reading lies
/// below the deadline.
#[test]
fn a_lock_freed_before_the_limit_is_taken() {
    let scratch = Scratch::new("observer-freed");
    let held = holder(&scratch.0.join("e.jsonl"));
    let directory = scratch.0.clone();
    let (event, seen, sleeps) = within("the wait for a freed lock", move || {
        let mut held = Some(held);
        let delivered = Delivered::new();
        let mut record = Record::new(&delivered);
        let mut clocks = Scripted::new(&[1_000, 2_000, 3_000]);
        *clocks.beyond.borrow_mut() = Some(4_000);
        clocks.on_sleep = Box::new(move |sleeps| {
            if sleeps == 2
                && let Some(mut file) = held.take()
            {
                file.write_all(b"{\"a\": 1}\n").expect("the holder writes");
            }
        });
        let event = observer(directory.as_os_str(), "e")
            .append(&mut clocks, &mut record, "x", Object::new())
            .map_err(|error| error.to_string());
        let seen = clocks.seen.borrow().clone();
        (event, seen, clocks.sleeps)
    });
    let event = event.expect("the append succeeds").expect("a log stands");
    assert!(sleeps >= 2);
    assert_eq!(seen.len(), sleeps + 2);
    assert_eq!(seen[..3], [1_000, 2_000, 3_000]);
    let last = *seen.last().expect("a reading under the lock");
    assert_eq!(
        event.get("monotonic_ns"),
        Some(&Value::Integer(Integer::from(last)))
    );
    assert_eq!(
        event.get("ordinal"),
        Some(&Value::Integer(Integer::from(2u64)))
    );
}

/// The readings of one held wait of an observer of `limit`: whether it ended held with `EWOULDBLOCK`
/// and `limit`, its sentence, its sleeps and the readings the script had left.
fn held_wait(
    directory: PathBuf,
    limit: Duration,
    readings: Vec<u64>,
) -> (bool, String, usize, usize) {
    within("a held wait", move || {
        let delivered = Delivered::new();
        let mut record = Record::new(&delivered);
        let mut clocks = Scripted::new(&readings);
        let refused = limited(directory.as_os_str(), "e", limit)
            .events(&mut clocks, &mut record)
            .expect_err("the wait ends");
        let held = matches!(
            &refused,
            ObserverError::Held { errno, limit: named, .. }
                if *errno == libc::EWOULDBLOCK && *named == limit
        );
        let left = clocks.readings.borrow().len();
        (held, refused.to_string(), clocks.sleeps, left)
    })
}

/// A lock held past the limit ends the wait at the first reading at or past the first reading plus
/// the limit, and a reading one nanosecond before it sleeps and tries again, for a limit of 5 s and of
/// 2 s alike; the error names the refusal's `EWOULDBLOCK` and the limit in Python's float form.
#[test]
fn a_lock_held_past_the_limit_ends_at_the_deadline() {
    let scratch = Scratch::new("observer-held");
    let log = scratch.0.join("e.jsonl");
    let _held = holder(&log);
    let start = 100_000_000_000;
    for (seconds, text) in [(5, "5.0"), (2, "2.0")] {
        let limit = Duration::from_secs(seconds);
        let nanoseconds = seconds * 1_000_000_000;
        let readings = vec![start, start + nanoseconds - 1, start + nanoseconds];
        let (held, sentence, sleeps, left) = held_wait(scratch.0.clone(), limit, readings);
        assert!(held, "{sentence}");
        assert_eq!(sleeps, 1);
        assert_eq!(left, 0);
        assert_eq!(
            sentence,
            format!(
                "the observer log {} stayed locked for {text} s",
                log.display()
            )
        );
    }
}

/// A deadline past the range of `u64` stands whole: a first reading one second below the top of the
/// range and a limit of 5 s leave a reading at the top of the range below the deadline, so the wait
/// sleeps and takes the lock once the holder frees it.
#[test]
fn a_deadline_past_the_range_of_a_reading_stands_whole() {
    let scratch = Scratch::new("observer-top");
    let held = holder(&scratch.0.join("e.jsonl"));
    let directory = scratch.0.clone();
    let (read, sleeps) = within("a wait near the top of the range", move || {
        let mut held = Some(held);
        let delivered = Delivered::new();
        let mut record = Record::new(&delivered);
        let mut clocks = Scripted::new(&[u64::MAX - 1_000_000_000, u64::MAX]);
        *clocks.beyond.borrow_mut() = Some(u64::MAX);
        clocks.still.set(true);
        clocks.on_sleep = Box::new(move |_| drop(held.take()));
        let read = observer(directory.as_os_str(), "e")
            .events(&mut clocks, &mut record)
            .map_err(|error| error.to_string());
        (read, clocks.sleeps)
    });
    assert_eq!(read.expect("the lock is taken"), []);
    assert!(sleeps >= 1);
}

/// A signal stored before the wait raises at the sleep's first read of an armed record, and the wait
/// ends with it; the same wait with the record unarmed runs to its limit.
#[test]
fn a_signal_during_the_wait_ends_it() {
    let scratch = Scratch::new("observer-signal");
    let _held = holder(&scratch.0.join("e.jsonl"));
    let directory = scratch.0.clone();
    let (armed, unarmed) = within("a wait under a signal", move || {
        let observer = limited(directory.as_os_str(), "e", Duration::from_millis(200));
        let delivered = Delivered::new();
        delivered.deliver(Signal::Terminate);
        let mut record = Record::new(&delivered);
        record.arm();
        let armed = matches!(
            observer.events(&mut System, &mut record),
            Err(ObserverError::Interrupted(Interrupted(Signal::Terminate)))
        );
        let quiet = Delivered::new();
        quiet.deliver(Signal::Terminate);
        let mut unarmed = Record::new(&quiet);
        let unarmed = matches!(
            observer.events(&mut System, &mut unarmed),
            Err(ObserverError::Held { .. })
        );
        (armed, unarmed)
    });
    assert!(armed, "the signal ends the wait");
    assert!(unarmed, "the unarmed wait runs to its limit");
}

fn ready_log(scratch: &Scratch, episode: &str, lines: &str) -> Observer {
    fs::write(scratch.0.join(format!("{episode}.jsonl")), lines).expect("written");
    observer(scratch.0.as_os_str(), episode)
}

fn ready(observer: &Observer, after: &str) -> Result<Option<Object>, ObserverError> {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    observer.ready(
        &mut Scripted::constant(READING),
        &mut record,
        &Text::from("lane"),
        &json::parse(after).expect("JSON"),
    )
}

fn ordinal_past(observer: &Observer, after: &str) -> Option<String> {
    ready(observer, after)
        .expect("the read succeeds")
        .map(|event| json::text(event.get("ordinal").expect("an ordinal")))
}

/// The first ready event of the role and the observer's profile past `after`: another profile's event,
/// another role's ready event and a start event pass, a float ordinal compares by value and `true`
/// counts as 1.
#[test]
fn ready_is_the_first_ready_event_past_the_frontier() {
    let scratch = Scratch::new("observer-ready");
    let observer = ready_log(
        &scratch,
        "ep4",
        "{\"profile\": \"other\", \"kind\": \"ready\", \"ordinal\": 9}\n\
         {\"profile\": \"prof\", \"role\": \"lane\", \"kind\": \"ready\", \"ordinal\": 1}\n\
         {\"profile\": \"prof\", \"role\": \"lane\", \"kind\": \"start\", \"ordinal\": 2}\n\
         {\"profile\": \"prof\", \"role\": \"lane\", \"kind\": \"ready\", \"ordinal\": 2.5}\n\
         {\"profile\": \"prof\", \"role\": \"lane\", \"kind\": \"ready\", \"ordinal\": true}\n\
         {\"profile\": \"prof\", \"role\": \"lane\", \"kind\": \"ready\", \"ordinal\": 4}\n\
         {\"profile\": \"prof\", \"role\": \"fis\", \"kind\": \"ready\", \"ordinal\": 5}\n",
    );
    let found: Vec<Option<String>> = ["0", "1", "2", "3", "4"]
        .iter()
        .map(|after| ordinal_past(&observer, after))
        .collect();
    let expected = [Some("1"), Some("2.5"), Some("2.5"), Some("4"), None];
    assert_eq!(found, expected.map(|ordinal| ordinal.map(str::to_owned)));
}

/// An ordinal and a frontier compare by exact value whatever their types: a float frontier passes an
/// equal float and admits a larger integer, a whole float equals an integer, a NaN is past nothing and
/// nothing is past it, infinities order beyond every integer, and booleans count as 0 or 1.
#[test]
fn ready_compares_numbers_by_value() {
    let scratch = Scratch::new("observer-ready-numbers");
    for (at, (ordinal, after, found)) in [
        ("2.5", "2.5", false),
        ("3", "2.5", true),
        ("2", "2.5", false),
        ("-2", "-2.5", true),
        ("-3", "-2.5", false),
        ("2.0", "2", false),
        ("2.0", "1", true),
        ("2", "1.0", true),
        ("2", "2.0", false),
        ("NaN", "0", false),
        ("1", "NaN", false),
        ("Infinity", "9", true),
        ("-Infinity", "0", false),
        ("9", "-Infinity", true),
        ("9", "Infinity", false),
        ("false", "-1", true),
        ("1", "true", false),
        ("2", "true", true),
        ("100000000000000000000001", "1e23", true),
    ]
    .into_iter()
    .enumerate()
    {
        let observer = ready_log(
            &scratch,
            &format!("e{at}"),
            &format!(
                "{{\"profile\": \"prof\", \"role\": \"lane\", \"kind\": \"ready\", \"ordinal\": {ordinal}}}\n"
            ),
        );
        assert_eq!(
            ready(&observer, after).expect("reads").is_some(),
            found,
            "{ordinal} past {after}"
        );
    }
    let observer = ready_log(
        &scratch,
        "two",
        "{\"profile\": \"prof\", \"role\": \"lane\", \"kind\": \"ready\", \"ordinal\": 2.5}\n\
         {\"profile\": \"prof\", \"role\": \"lane\", \"kind\": \"ready\", \"ordinal\": 3}\n",
    );
    assert_eq!(ordinal_past(&observer, "2.5"), Some("3".to_owned()));
}

/// An event that is no object, an event of the profile without `role`, a ready event of the role whose
/// ordinal is no number, and a frontier that is no number each refuse the read.
#[test]
fn ready_refuses_an_event_it_cannot_judge() {
    let scratch = Scratch::new("observer-ready-refused");
    let found =
        "{\"profile\": \"prof\", \"role\": \"lane\", \"kind\": \"ready\", \"ordinal\": 1}\n";
    let cases = [
        (
            format!("{found}[1]\n"),
            "0",
            EventError::NotObject(json::parse("[1]").expect("JSON")),
        ),
        (
            "{\"profile\": \"prof\", \"kind\": \"ready\", \"ordinal\": 1}\n".to_owned(),
            "0",
            EventError::Missing("role"),
        ),
        (
            "{\"profile\": \"prof\", \"role\": \"lane\", \"kind\": \"ready\", \"ordinal\": \"x\"}\n"
                .to_owned(),
            "0",
            EventError::Unordered(Value::String(Text::from("x"))),
        ),
        (
            found.to_owned(),
            "\"x\"",
            EventError::Unordered(Value::String(Text::from("x"))),
        ),
    ];
    for (at, (lines, after, expected)) in cases.into_iter().enumerate() {
        let observer = ready_log(&scratch, &format!("e{at}"), &lines);
        match ready(&observer, after) {
            Err(ObserverError::Event(error)) => assert_eq!(error, expected),
            other => panic!("the event is refused: {other:?}"),
        }
    }
    let other = ready_log(
        &scratch,
        "control",
        "{\"profile\": \"other\", \"kind\": \"ready\", \"ordinal\": 1}\n",
    );
    assert_eq!(
        ready(&other, "0").expect("another profile's event needs no role"),
        None
    );
}

/// The read judges `kind` and `ordinal` of the role's events up to the one it finds: an event of the
/// role without `kind` or `ordinal` after the found one leaves the result, and the same event before it
/// refuses the read.
#[test]
fn ready_judges_the_role_events_up_to_the_one_found() {
    let scratch = Scratch::new("observer-ready-lazy");
    let found = r#"{"profile": "prof", "role": "lane", "kind": "ready", "ordinal": 1}"#;
    for (name, lacking, missing) in [
        (
            "kind",
            r#"{"profile": "prof", "role": "lane", "ordinal": 2}"#,
            "kind",
        ),
        (
            "ordinal",
            r#"{"profile": "prof", "role": "lane", "kind": "ready"}"#,
            "ordinal",
        ),
    ] {
        let after = ready_log(
            &scratch,
            &format!("after-{name}"),
            &format!("{found}\n{lacking}\n"),
        );
        let event = ready(&after, "0").expect("the found event ends the judging");
        assert!(event.is_some());
        let before = ready_log(
            &scratch,
            &format!("before-{name}"),
            &format!("{lacking}\n{found}\n"),
        );
        match ready(&before, "0") {
            Err(ObserverError::Event(EventError::Missing(member))) => assert_eq!(member, missing),
            other => panic!("the event before is judged: {other:?}"),
        }
    }
}

/// An ordinal `true` counts as 1: past 0 and not past 1.
#[test]
fn ready_counts_a_true_ordinal_as_one() {
    let scratch = Scratch::new("observer-ready-true");
    let observer = ready_log(
        &scratch,
        "e",
        "{\"profile\": \"prof\", \"role\": \"lane\", \"kind\": \"ready\", \"ordinal\": true}\n",
    );
    assert!(ready(&observer, "0").expect("reads").is_some());
    assert_eq!(ready(&observer, "1").expect("reads"), None);
}
