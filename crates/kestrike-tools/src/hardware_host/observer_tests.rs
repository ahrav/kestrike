//! Each expected text and line was recorded from the hardware lane's observer on the same bytes and
//! readings, with the log's path and the host's node name put in their places.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::time::Duration;

use super::{EventError, NODE, Observer, ObserverError, POLL};
use crate::hardware_host::{Clocks, System};
use crate::host_stop::{Delivered, Interrupted, Record, Signal};
use crate::json::{self, Integer, Object, Text, Value};
use crate::paths::tests::Scratch;

/// Clocks that give scripted monotonic readings in order, then `beyond` at each later read when it is
/// set, one nanosecond more each time unless `still` holds, record each reading, count the sleeps, and run `on_sleep` at each sleep.
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

    fn sleep(&mut self, _: &mut Record<'_>, length: Duration) -> Result<(), Interrupted> {
        assert_eq!(length, POLL);
        std::thread::sleep(Duration::from_millis(1));
        self.sleeps += 1;
        (self.on_sleep)(self.sleeps);
        Ok(())
    }
}

const READING: u64 = 123_456_789_012_345;
const LIMIT: Duration = Duration::from_secs(5);

fn observer(directory: &OsStr, episode: &str) -> Observer {
    Observer::new(
        directory,
        OsStr::new(episode),
        Text::from("prof"),
        Text::from("fis"),
        LIMIT,
    )
}

fn node() -> String {
    let name = fs::read_to_string(NODE).expect("the node name reads");
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
/// readings it takes under the lock, and returns that event; a field of the caller takes the place of
/// the member of the same key.
#[test]
fn an_append_writes_the_lane_line_for_fixed_readings() {
    let scratch = Scratch::new("observer-append");
    let directory = scratch.0.join("deep/er");
    let mut slashed = directory.as_os_str().to_owned();
    slashed.push("//./");
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
    let log = directory.join("ep1.jsonl");
    assert_eq!(
        fs::read_to_string(&log).expect("the log reads"),
        first.clone() + &second
    );
    assert_eq!(json::line_sorted(&Value::Object(event)) + "\n", first);
    assert!(
        clocks
            .seen
            .borrow()
            .iter()
            .all(|&reading| reading == READING)
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(&log)
        .expect("the log stands")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o022,
        0,
        "the log is made with mode 0644 under the test's umask"
    );
}

/// The ordinal counts the lines another writer left that are not blank once `\r\n` and `\r` end a
/// line, while a read splits at every one of Python's line boundaries, so a U+2028 inside a string
/// leaves a line that is no JSON value.
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

/// A read gives each event in order, each line's JSON value as the line spells it.
#[test]
fn a_read_gives_every_event_in_order() {
    let scratch = Scratch::new("observer-read");
    fs::write(
        scratch.0.join("e.jsonl"),
        "{\"a\": 1}\r\n[2]\r\n\"three\"\n",
    )
    .expect("written");
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let events = observer(scratch.0.as_os_str(), "e")
        .events(&mut Scripted::constant(READING), &mut record)
        .expect("the read succeeds");
    let expected = ["{\"a\": 1}", "[2]", "\"three\""].map(|text| json::parse(text).expect("JSON"));
    assert_eq!(events, expected);
}

/// A malformed line refuses a read with the lane's sentence up to `is malformed: `, and refuses an
/// append, which then writes nothing; the same log without that line takes the append.
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

/// Holds an exclusive lock of `path` through a file description of its own until `release`.
fn holder(path: &Path) -> File {
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .expect("the holder opens");
    file.lock().expect("the holder locks");
    file
}

/// A lock freed before the limit is taken: the wait reads the clock once before the first attempt and
/// once after each refusal, sleeps [`POLL`] after each refusal under the deadline, and the append then
/// takes its own reading under the lock. A fork of another case can hold a copy of the holder's
/// descriptor for a moment after the holder drops, so the count of refusals past the second is left
/// open and each later reading lies below the deadline.
#[test]
fn a_lock_freed_before_the_limit_is_taken() {
    let scratch = Scratch::new("observer-freed");
    let log = scratch.0.join("e.jsonl");
    let held = std::rc::Rc::new(RefCell::new(Some(holder(&log))));
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let mut clocks = Scripted::new(&[1_000, 2_000, 3_000]);
    *clocks.beyond.borrow_mut() = Some(4_000);
    let freed = held.clone();
    clocks.on_sleep = Box::new(move |sleeps| {
        if sleeps == 2 {
            freed.borrow_mut().take();
        }
    });
    let event = observer(scratch.0.as_os_str(), "e")
        .append(&mut clocks, &mut record, "x", Object::new())
        .expect("the append succeeds")
        .expect("a log stands");
    let seen = clocks.seen.borrow();
    assert!(clocks.sleeps >= 2);
    assert_eq!(seen.len(), clocks.sleeps + 2);
    assert_eq!(seen[..3], [1_000, 2_000, 3_000]);
    let last = *seen.last().expect("a reading under the lock");
    assert_eq!(
        event.get("monotonic_ns"),
        Some(&Value::Integer(Integer::from(last)))
    );
    assert!(held.borrow().is_none());
}

/// A lock held past the limit ends the wait at the first reading at or past the first reading plus
/// the limit, and a reading one nanosecond before it sleeps and tries again; the error names the
/// refusal's `EWOULDBLOCK` and the lane's sentence with the limit in Python's float form.
#[test]
fn a_lock_held_past_the_limit_ends_at_the_deadline() {
    let scratch = Scratch::new("observer-held");
    let log = scratch.0.join("e.jsonl");
    let _held = holder(&log);
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let start = 100_000_000_000;
    let limit = u64::try_from(LIMIT.as_nanos()).expect("the limit fits");
    let mut clocks = Scripted::new(&[start, start + limit - 1, start + limit]);
    let refused = observer(scratch.0.as_os_str(), "e")
        .events(&mut clocks, &mut record)
        .expect_err("the wait ends");
    assert_eq!(clocks.sleeps, 1);
    assert!(clocks.readings.borrow().is_empty());
    match &refused {
        ObserverError::Held { errno, limit, .. } => {
            assert_eq!(*errno, libc::EWOULDBLOCK);
            assert_eq!(*limit, LIMIT);
        }
        other => panic!("the wait ends held: {other:?}"),
    }
    assert_eq!(
        refused.to_string(),
        format!("the observer log {} stayed locked for 5.0 s", log.display())
    );
}

/// A signal stored before the wait raises at the sleep's first read of an armed record, and the wait
/// ends with it; the same wait with the record unarmed runs to its limit.
#[test]
fn a_signal_during_the_wait_ends_it() {
    let scratch = Scratch::new("observer-signal");
    let _held = holder(&scratch.0.join("e.jsonl"));
    let observer = Observer::new(
        scratch.0.as_os_str(),
        OsStr::new("e"),
        Text::from("prof"),
        Text::from("fis"),
        Duration::from_millis(200),
    );
    let delivered = Delivered::new();
    delivered.deliver(Signal::Terminate);
    let mut record = Record::new(&delivered);
    record.arm();
    match observer.events(&mut System, &mut record) {
        Err(ObserverError::Interrupted(Interrupted(Signal::Terminate))) => {}
        other => panic!("the signal ends the wait: {other:?}"),
    }
    let quiet = Delivered::new();
    quiet.deliver(Signal::Terminate);
    let mut unarmed = Record::new(&quiet);
    match observer.events(&mut System, &mut unarmed) {
        Err(ObserverError::Held { .. }) => {}
        other => panic!("the unarmed wait runs to its limit: {other:?}"),
    }
}

fn ready_log(scratch: &Scratch, episode: &str, lines: &str) -> Observer {
    fs::write(scratch.0.join(format!("{episode}.jsonl")), lines).expect("written");
    observer(scratch.0.as_os_str(), episode)
}

fn ready(observer: &Observer, after: u64) -> Result<Option<Object>, ObserverError> {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    observer.ready(
        &mut Scripted::constant(READING),
        &mut record,
        &Text::from("lane"),
        &Integer::from(after),
    )
}

/// The first ready event of the role and the observer's profile past `after`: another profile's event
/// and a start event pass, a float ordinal compares by value and `true` counts as 1.
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
         {\"profile\": \"prof\", \"role\": \"lane\", \"kind\": \"ready\", \"ordinal\": 4}\n",
    );
    let ordinal = |after| {
        ready(&observer, after)
            .expect("the read succeeds")
            .map(|event| json::text(event.get("ordinal").expect("an ordinal")))
    };
    let found: Vec<Option<String>> = (0..=4).map(ordinal).collect();
    let expected = [Some("1"), Some("2.5"), Some("2.5"), Some("4"), None];
    assert_eq!(found, expected.map(|ordinal| ordinal.map(str::to_owned)));
}

/// An event that is no object, an event of the profile without `role`, and a ready event of the role
/// whose ordinal has no order beside an integer each refuse the read.
#[test]
fn ready_refuses_an_event_it_cannot_judge() {
    let scratch = Scratch::new("observer-ready-refused");
    let cases = [
        (
            "{\"profile\": \"prof\", \"role\": \"lane\", \"kind\": \"ready\", \"ordinal\": 1}\n[1]\n",
            EventError::NotObject(json::parse("[1]").expect("JSON")),
        ),
        (
            "{\"profile\": \"prof\", \"kind\": \"ready\", \"ordinal\": 1}\n",
            EventError::Missing("role"),
        ),
        (
            "{\"profile\": \"prof\", \"role\": \"lane\", \"kind\": \"ready\", \"ordinal\": \"x\"}\n",
            EventError::Unordered(Value::String(Text::from("x"))),
        ),
    ];
    for (at, (lines, expected)) in cases.into_iter().enumerate() {
        let observer = ready_log(&scratch, &format!("e{at}"), lines);
        match ready(&observer, 0) {
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
        ready(&other, 0).expect("another profile's event needs no role"),
        None
    );
}
