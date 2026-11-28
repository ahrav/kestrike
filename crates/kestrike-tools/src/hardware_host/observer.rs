//! The observer log of an episode: one JSON object per line, appended under an exclusive `flock`, read
//! under a shared one, each lock's wait cut off at a deadline on the monotonic clock.

use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::clock::Clocks;
use crate::fixtures::close;
use crate::host_stop::{Interrupted, Record};
use crate::json::{self, Integer, Object, Value};
use crate::paths;
use crate::python::{self, repr_float};
use crate::text::{Text, newlines, strip_str};

/// The sleep between two attempts at a lock that another holder keeps.
pub const POLL: Duration = Duration::from_millis(50);

/// The path of the kernel's node name, which an append reads at each event for its `host`.
pub const NODE: &str = "/proc/sys/kernel/hostname";

/// The log of one episode under one profile and role, or no log when the directory text is empty.
#[derive(Clone, Debug)]
pub struct Observer {
    log: Option<Log>,
    episode: Text,
    profile: Text,
    role: Text,
    limit: Duration,
}

/// The log's path as it is opened, and its text as an error names it.
#[derive(Clone, Debug)]
struct Log {
    path: PathBuf,
    text: Text,
}

/// Why a read or an append of the log ended without a result.
#[derive(Debug)]
pub enum ObserverError {
    /// Making the log's directory and its parents failed.
    Directory(io::Error),
    /// Opening the log failed, a link at its name included, or the opened log cannot seek, as a FIFO
    /// cannot.
    Open(io::Error),
    /// A lock attempt failed other than by a lock another holder keeps.
    Lock(io::Error),
    /// Another holder kept the lock until the deadline; `errno` is the refused attempt's.
    Held {
        log: Text,
        errno: i32,
        limit: Duration,
    },
    /// The signal record raised during the wait.
    Interrupted(Interrupted),
    /// Reading the monotonic clock failed.
    Clock(io::Error),
    /// Reading the opened log failed.
    Read(io::Error),
    /// The log's bytes are no UTF-8.
    Undecodable { log: Text },
    /// A nonempty line of a read is no JSON value.
    Malformed { log: Text, error: json::Error },
    /// A nonblank line under an append is no JSON value, so no ordinal follows from the count.
    Line { log: Text, error: json::Error },
    /// Reading [`NODE`] failed.
    Node(io::Error),
    /// Writing the event's line, or closing the log after it, failed; the line may stand whole, in part
    /// or not at all.
    Write(io::Error),
    /// A field nests arrays and objects so deep that the event's line would pass [`json::MAX_DEPTH`],
    /// which a read refuses; nothing is written.
    Depth { key: Text },
    /// An event of [`Observer::ready`]'s read lacks a shape the read needs.
    Event(EventError),
}

/// An event that [`Observer::ready`] cannot judge.
#[derive(Clone, Debug, PartialEq)]
pub enum EventError {
    /// The event is no object.
    NotObject(Value),
    /// The event lacks this member.
    Missing(&'static str),
    /// The event's `ordinal`, or the frontier it is compared with, is no integer, boolean or float, so
    /// it has no order beside a number.
    Unordered(Value),
}

impl fmt::Display for ObserverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory(error) => {
                write!(f, "the observer log's directory cannot be made: {error}")
            }
            Self::Open(error) => write!(f, "the observer log cannot be opened: {error}"),
            Self::Lock(error) => write!(f, "the observer log cannot be locked: {error}"),
            Self::Held { log, limit, .. } => write!(
                f,
                "the observer log {log} stayed locked for {} s",
                repr_float(limit.as_secs_f64())
            ),
            Self::Interrupted(signal) => {
                write!(f, "{signal} arrived during the observer log's wait")
            }
            Self::Clock(error) => write!(f, "the monotonic clock cannot be read: {error}"),
            Self::Read(error) => write!(f, "the observer log cannot be read: {error}"),
            Self::Undecodable { log } => write!(f, "the observer log {log} is no UTF-8"),
            Self::Malformed { log, error } => {
                write!(f, "the observer log {log} is malformed: {error}")
            }
            Self::Line { log, error } => {
                write!(f, "a line of the observer log {log} is no JSON: {error}")
            }
            Self::Node(error) => write!(f, "{NODE} cannot be read: {error}"),
            Self::Write(error) => write!(f, "the observer log cannot be written: {error}"),
            Self::Depth { key } => write!(
                f,
                "the observer event's field {} nests past {} levels",
                key.repr(),
                json::MAX_DEPTH
            ),
            Self::Event(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ObserverError {}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotObject(event) => {
                write!(f, "an observer event is no object: {}", python::repr(event))
            }
            Self::Missing(member) => write!(f, "an observer event has no member {member:?}"),
            Self::Unordered(ordinal) => write!(
                f,
                "an observer event's ordinal or its frontier {} has no order beside a number",
                python::repr(ordinal)
            ),
        }
    }
}

impl Observer {
    /// The log `<directory>/<episode>.jsonl`, its path text in the form of [`paths::pure_bytes`], or no
    /// log when `directory` is empty. `limit` sets the deadline of each wait for the log's lock.
    ///
    /// The episode is joined as a path and checked nowhere here: an episode that starts with `/`
    /// replaces the directory and a `..` component stays, so a caller passes an episode of one file
    /// name component, and validates an episode it takes from outside before passing it.
    pub fn new(
        directory: &OsStr,
        episode: &OsStr,
        profile: Text,
        role: Text,
        limit: Duration,
    ) -> Self {
        let log = (!directory.is_empty()).then(|| {
            let mut name = episode.as_bytes().to_vec();
            name.extend_from_slice(b".jsonl");
            let pure = paths::pure_bytes(&paths::join(directory.as_bytes(), &name));
            let path = OsStr::from_bytes(&pure);
            Log {
                path: PathBuf::from(path),
                text: Text::from_os(path),
            }
        });
        Self {
            log,
            episode: Text::from_os(episode),
            profile,
            role,
            limit,
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.log.as_ref().map(|log| log.path.as_path())
    }

    /// Every event of the log, in order, from one read under the shared lock: the nonempty lines, split
    /// at Python's line boundaries once `\r\n` and `\r` read as `\n`. No log and an absent file give none.
    ///
    /// # Errors
    ///
    /// A failed open, the lock's errors, a failed read, bytes that are no
    /// UTF-8, and [`ObserverError::Malformed`] for the first line that is no JSON value.
    pub fn events(
        &self,
        clocks: &mut impl Clocks,
        record: &mut Record<'_>,
    ) -> Result<Vec<Value>, ObserverError> {
        let Some(log) = &self.log else {
            return Ok(Vec::new());
        };
        let mut file = match log.open(OpenOptions::new().read(true)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(ObserverError::Open(error)),
        };
        self.lock(&file, Share::Shared, log, clocks, record)?;
        let text = read_text(&mut file, log)?;
        drop(file);
        let mut events = Vec::new();
        for line in Text::from(text).splitlines() {
            let Some(line) = line.to_str().filter(|line| !line.is_empty()) else {
                continue;
            };
            events.push(json::parse(line).map_err(|error| ObserverError::Malformed {
                log: log.text.clone(),
                error,
            })?);
        }
        Ok(events)
    }

    /// Appends one event and returns it, or returns none when there is no log. A field whose nesting
    /// would pass [`json::MAX_DEPTH`] in the event's line refuses the append before anything is made.
    /// The directory is made with its parents; the log is opened for reading and appending, made with
    /// mode 0644 when absent, refused when it cannot seek, and locked exclusively. The event's
    /// `ordinal` is one past the count of nonblank lines between `\n`, each of which must decode;
    /// `monotonic_ns`, `wall_diagnostic` and `host` are read under the lock. The event holds `episode`,
    /// `ordinal`, `profile`, `role`, `kind`, the readings and `host`, then each member of `fields`,
    /// which takes the place of a member of the same key, `ordinal` included. The line is the event as
    /// `json.dumps(event, sort_keys=True)` writes it, and a newline, written after the log's last byte
    /// whatever that byte is; the log is closed once and the close checked, and nothing is synced.
    ///
    /// # Errors
    ///
    /// [`ObserverError::Depth`], the directory, the open, the lock, the read,
    /// [`ObserverError::Undecodable`], [`ObserverError::Line`] for the first nonblank line that is no
    /// JSON value, the clock, [`NODE`]'s read, and the write or the close.
    pub fn append(
        &self,
        clocks: &mut impl Clocks,
        record: &mut Record<'_>,
        kind: &str,
        fields: Object,
    ) -> Result<Option<Object>, ObserverError> {
        let Some(log) = &self.log else {
            return Ok(None);
        };
        if let Some((key, _)) = fields
            .iter()
            .find(|(_, value)| nesting(value) >= json::MAX_DEPTH)
        {
            return Err(ObserverError::Depth { key: key.clone() });
        }
        if let Some(parent) = log.path.parent() {
            fs::create_dir_all(parent).map_err(ObserverError::Directory)?;
        }
        let mut file = log
            .open(
                OpenOptions::new()
                    .read(true)
                    .append(true)
                    .create(true)
                    .mode(0o644),
            )
            .map_err(ObserverError::Open)?;
        file.stream_position().map_err(ObserverError::Open)?;
        self.lock(&file, Share::Exclusive, log, clocks, record)?;
        let mut count: usize = 0;
        for line in read_text(&mut file, log)?.split('\n') {
            if strip_str(line).is_empty() {
                continue;
            }
            json::parse(line).map_err(|error| ObserverError::Line {
                log: log.text.clone(),
                error,
            })?;
            count += 1;
        }
        let monotonic = clocks.monotonic_ns().map_err(ObserverError::Clock)?;
        let wall = clocks.wall();
        let host = node()?;
        let mut event = Object::new();
        event.insert("episode", Value::String(self.episode.clone()));
        event.insert("ordinal", Value::Integer(Integer::from(count + 1)));
        event.insert("profile", Value::String(self.profile.clone()));
        event.insert("role", Value::String(self.role.clone()));
        event.insert("kind", Value::String(Text::from(kind)));
        event.insert("monotonic_ns", Value::Integer(Integer::from(monotonic)));
        event.insert("wall_diagnostic", Value::Float(wall));
        event.insert("host", Value::String(host));
        for (key, value) in fields.iter() {
            event.insert(key.clone(), value.clone());
        }
        let mut line = json::line_sorted(&Value::Object(event.clone()));
        line.push('\n');
        file.write_all(line.as_bytes())
            .map_err(ObserverError::Write)?;
        close(file).map_err(ObserverError::Write)?;
        Ok(Some(event))
    }

    /// The first event of one read of the log whose `profile` is the observer's, whose `role` is
    /// `role`, whose `kind` is `"ready"` and whose `ordinal` is past `after`. The frontier `after` is
    /// the value a caller took from the log, such as its highest ordinal. An ordinal or a frontier that
    /// is a boolean counts as 0 or 1, an integer and a float compare by their exact values, and a NaN is
    /// past nothing and nothing is past it.
    ///
    /// # Errors
    ///
    /// The errors of [`Observer::events`], and [`ObserverError::Event`]: any event that is no object, an
    /// event of the profile without `role`, an event of the role, up to the one found, without `kind`,
    /// and a ready event of the role, up to the one found, without `ordinal`, or whose `ordinal` or the
    /// frontier is no integer, boolean or float.
    pub fn ready(
        &self,
        clocks: &mut impl Clocks,
        record: &mut Record<'_>,
        role: &Text,
        after: &Value,
    ) -> Result<Option<Object>, ObserverError> {
        let profile = Value::String(self.profile.clone());
        let role = Value::String(role.clone());
        let mut ours = Vec::new();
        for event in self.events(clocks, record)? {
            let Value::Object(event) = event else {
                return Err(ObserverError::Event(EventError::NotObject(event)));
            };
            if event.get("profile") == Some(&profile) && member(&event, "role")? == &role {
                ours.push(event);
            }
        }
        for event in ours {
            if !matches!(member(&event, "kind")?, Value::String(kind) if *kind == "ready") {
                continue;
            }
            if past(member(&event, "ordinal")?, after)? {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }

    /// Takes the lock under the observer's deadline, one monotonic reading before the first attempt plus
    /// the limit, summed without overflow. Each attempt refused by another holder is followed by one
    /// reading: a reading at or past the deadline ends the wait, and one below it sleeps [`POLL`] and
    /// tries again. The deadline is read after refusals alone, so a sleep that starts just below it
    /// runs whole and the attempt after it can take the lock up to one [`POLL`], and the sleep's own
    /// lateness, past the deadline. A `flock` that a signal interrupts runs again at once. Closing
    /// `file` frees the lock.
    fn lock(
        &self,
        file: &File,
        share: Share,
        log: &Log,
        clocks: &mut impl Clocks,
        record: &mut Record<'_>,
    ) -> Result<(), ObserverError> {
        let start = clocks.monotonic_ns().map_err(ObserverError::Clock)?;
        let deadline = u128::from(start) + self.limit.as_nanos();
        loop {
            let attempt = match share {
                Share::Shared => file.try_lock_shared(),
                Share::Exclusive => file.try_lock(),
            };
            match attempt {
                Ok(()) => return Ok(()),
                Err(TryLockError::WouldBlock) => {
                    let reading = clocks.monotonic_ns().map_err(ObserverError::Clock)?;
                    if u128::from(reading) >= deadline {
                        return Err(ObserverError::Held {
                            log: log.text.clone(),
                            errno: libc::EWOULDBLOCK,
                            limit: self.limit,
                        });
                    }
                    clocks
                        .sleep(record, POLL)
                        .map_err(ObserverError::Interrupted)?;
                }
                Err(TryLockError::Error(error)) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(TryLockError::Error(error)) => return Err(ObserverError::Lock(error)),
            }
        }
    }
}

impl Log {
    /// Opens the log with `options` and `O_NOFOLLOW`, so a link at its name is refused.
    fn open(&self, options: &mut OpenOptions) -> io::Result<File> {
        options.custom_flags(libc::O_NOFOLLOW).open(&self.path)
    }
}

/// The deepest nesting of arrays and objects in `value`, the value itself counted when it is one;
/// the walk keeps its own stack, so a value of any depth is measured.
fn nesting(value: &Value) -> usize {
    let mut deepest = 0;
    let mut pending = vec![(value, 1)];
    while let Some((value, depth)) = pending.pop() {
        match value {
            Value::Array(items) => pending.extend(items.iter().map(|item| (item, depth + 1))),
            Value::Object(members) => {
                pending.extend(members.iter().map(|(_, member)| (member, depth + 1)));
            }
            _ => continue,
        }
        deepest = deepest.max(depth);
    }
    deepest
}

#[derive(Clone, Copy)]
enum Share {
    Shared,
    Exclusive,
}

/// The whole file from its start as UTF-8, with `\r\n` and `\r` read as `\n`.
fn read_text(file: &mut File, log: &Log) -> Result<String, ObserverError> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(ObserverError::Read)?;
    String::from_utf8(bytes)
        .map(newlines)
        .map_err(|_| ObserverError::Undecodable {
            log: log.text.clone(),
        })
}

/// The kernel's node name: [`NODE`] less its final line feed.
fn node() -> Result<Text, ObserverError> {
    let mut bytes = fs::read(NODE).map_err(ObserverError::Node)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    Ok(Text::from_os(OsStr::from_bytes(&bytes)))
}

fn member<'a>(event: &'a Object, name: &'static str) -> Result<&'a Value, ObserverError> {
    event
        .get(name)
        .ok_or(ObserverError::Event(EventError::Missing(name)))
}

/// Whether `ordinal` is greater than `after` by value; a NaN on either side is greater than nothing
/// and nothing is greater than it.
fn past(ordinal: &Value, after: &Value) -> Result<bool, ObserverError> {
    let unordered = |value: &Value| ObserverError::Event(EventError::Unordered(value.clone()));
    let ordinal_number = number(ordinal).ok_or_else(|| unordered(ordinal))?;
    let after_number = number(after).ok_or_else(|| unordered(after))?;
    Ok(compare(&ordinal_number, &after_number) == Some(Ordering::Greater))
}

/// A JSON number, a boolean read as the integer 0 or 1.
enum Number {
    Integer(Integer),
    Float(f64),
}

fn number(value: &Value) -> Option<Number> {
    match value {
        Value::Integer(integer) => Some(Number::Integer(integer.clone())),
        Value::Bool(flag) => Some(Number::Integer(Integer::from(u64::from(*flag)))),
        Value::Float(value) => Some(Number::Float(*value)),
        _ => None,
    }
}

/// The order of two numbers by their exact values, none where either is a NaN.
fn compare(left: &Number, right: &Number) -> Option<Ordering> {
    match (left, right) {
        (Number::Integer(left), Number::Integer(right)) => Some(left.cmp(right)),
        (Number::Float(left), Number::Float(right)) => left.partial_cmp(right),
        (Number::Integer(left), Number::Float(right)) => integer_float(left, *right),
        (Number::Float(left), Number::Integer(right)) => {
            integer_float(right, *left).map(Ordering::reverse)
        }
    }
}

/// The order of `integer` beside `float` by exact value: the integer against the float's whole part
/// toward zero, and on a tie against the fraction's sign.
fn integer_float(integer: &Integer, float: f64) -> Option<Ordering> {
    if float.is_nan() {
        return None;
    }
    if float.is_infinite() {
        return Some(if float > 0.0 {
            Ordering::Less
        } else {
            Ordering::Greater
        });
    }
    let whole = python::int(&Value::Float(float)).ok()?;
    match integer.cmp(&whole) {
        Ordering::Equal => 0.0_f64.partial_cmp(&(float - float.trunc())),
        unequal => Some(unequal),
    }
}

#[cfg(test)]
#[path = "observer_tests.rs"]
mod tests;
