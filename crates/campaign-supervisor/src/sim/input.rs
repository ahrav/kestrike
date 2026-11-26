//! The frozen inputs of a launcher command: a manifest's pinned values,
//! and a bundle's leading manifest.
//!
//! A bundle is a sequence of 48-byte records. Each record's first byte is
//! its tag and its second its sub-tag. A run's leading records are its
//! `Begin` record (tag 1) and the field (tag 2) and checkpoint (tag 9)
//! records before any record of another tag. The field records of sub-tag
//! 1 carry the canonical manifest in order: each chunk's length is the
//! record's byte 4, at most 43, and its bytes follow from byte 5. The
//! format permits tags 1 through 10. Tags 1 through 8 form the semantic
//! record sequence.

use std::collections::BTreeMap;
use std::io;
use std::time::Duration;

use crate::record::{Digest, Hashing, Pins};

/// Adds the worker’s CPU declaration to a recorded canonical manifest.
pub(crate) fn worker_manifest(manifest: &str) -> Vec<u8> {
    format!("{manifest}cpu = unrecorded\n").into_bytes()
}

/// Bytes of every bundle record.
pub(crate) const RECORD: usize = 48;
const BEGIN: u8 = 1;
const FIELD: u8 = 2;
const TERMINAL: u8 = 8;
const CHECKPOINT: u8 = 9;
const DIAGNOSTIC: u8 = 10;
/// The field sub-tag of the manifest's chunks.
const MANIFEST: u8 = 1;
/// A chunk's length byte, and its first byte after it.
const LENGTH: usize = 4;
const CHUNK: usize = 5;
/// The most bytes one chunk holds.
const CHUNK_MAX: usize = RECORD - CHUNK;
/// The bytes leading records may span: a field of 65536 chunks with a
/// checkpoint after each. Leading records past it end the scan.
const HEAD: u64 = 2 * 65536 * RECORD as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tag {
    Semantic,
    Skipped,
    Unknown,
}

impl Tag {
    pub(crate) fn of(tag: u8) -> Self {
        match tag {
            BEGIN..=TERMINAL => Self::Semantic,
            CHECKPOINT | DIAGNOSTIC => Self::Skipped,
            _ => Self::Unknown,
        }
    }
}

/// The archive pins a manifest names, in the order of [`Pins`]' fields.
const PINS: [&str; 4] = ["build", "executable", "platform", "toolchain"];

/// The other manifest keys a launcher command reads.
const READ: [&str; 10] = [
    "version",
    "profile",
    "watchdog",
    "records",
    "bytes",
    "scenario",
    "suffix_depth",
    "suffix_children",
    "suffix_faults",
    "suffix_advances",
];

/// The values a manifest's text assigns the keys a launcher command reads.
#[derive(Debug)]
pub(crate) struct Values<'a>(BTreeMap<&'a str, &'a str>);

impl<'a> Values<'a> {
    /// The read keys' values among the `key = value` lines of `text`, the
    /// manifest `what` names.
    ///
    /// # Errors
    ///
    /// The refusal of a key named twice or a pin named nowhere.
    pub(crate) fn parse(text: &'a str, what: &str) -> Result<Self, String> {
        let mut values = BTreeMap::new();
        for line in text.lines() {
            if let Some((key, value)) = line.split_once(" = ")
                && (PINS.contains(&key) || READ.contains(&key))
                && values.insert(key, value).is_some()
            {
                return Err(format!("the {what} names {key} twice"));
            }
        }
        let missing: Vec<&str> = PINS
            .iter()
            .copied()
            .filter(|key| !values.contains_key(key))
            .collect();
        if !missing.is_empty() {
            return Err(format!("the {what} pins no {}", missing.join(", ")));
        }
        Ok(Self(values))
    }

    /// Refuses pins that name another build than `pins`, the archive's.
    pub(crate) fn pinned(&self, pins: &Pins, what: &str) -> Result<(), String> {
        let archived = [
            &pins.build,
            &pins.executable,
            &pins.platform,
            &pins.toolchain,
        ];
        for (key, archived) in PINS.iter().zip(archived) {
            let named = self.0[key];
            if named != archived.as_str() {
                let archived = archived.as_str();
                return Err(format!(
                    "the {what} pins {key} {named:?}; the archive is {archived:?}"
                ));
            }
        }
        Ok(())
    }

    /// Refuses a manifest whose `version` names another schema than
    /// `version`, the one the archived worker's listing reads.
    pub(crate) fn versioned(&self, version: u32, what: &str) -> Result<(), String> {
        let named = self.0.get("version").copied();
        if named == Some(version.to_string().as_str()) {
            Ok(())
        } else {
            Err(format!(
                "the {what} names version {named:?}; the archived worker reads version {version}"
            ))
        }
    }

    /// The profile the manifest names.
    pub(crate) fn profile(&self) -> Option<&'a str> {
        self.0.get("profile").copied()
    }

    pub(crate) fn scenario(&self) -> Option<&'a str> {
        self.0.get("scenario").copied()
    }

    /// The manifest's positive canonical integer watchdog in seconds.
    pub(crate) fn watchdog(&self) -> Result<Option<Duration>, String> {
        self.0
            .get("watchdog")
            .map(|value| {
                let count = count(value)
                    .filter(|count| *count <= u64::from(u32::MAX))
                    .ok_or_else(|| "the manifest watchdog is no positive u32 count".to_owned())?;
                Ok(Duration::from_secs(count))
            })
            .transpose()
    }

    /// The session's callback-record and file-byte budgets.
    pub(crate) fn session_budget(&self) -> Result<(u64, u64), String> {
        let named = |key| {
            self.0
                .get(key)
                .and_then(|value| count(value))
                .ok_or_else(|| format!("the session names no {key} count"))
        };
        Ok((named("records")?, named("bytes")?))
    }

    /// The frozen manifest's positive exploration bounds.
    pub(crate) fn suffix_limits(&self) -> Result<crate::protocol::Limits, String> {
        let named = |key| {
            self.0
                .get(key)
                .and_then(|value| count(value))
                .ok_or_else(|| format!("the bundle names no positive {key} count"))
        };
        Ok(crate::protocol::Limits {
            depth: named("suffix_depth")?,
            children: named("suffix_children")?,
            faults: named("suffix_faults")?,
            advances: named("suffix_advances")?,
        })
    }

    /// The whole bundle's record limit, within its byte limit.
    pub(crate) fn maximum(&self) -> Result<u64, String> {
        let named = |key| {
            self.0
                .get(key)
                .and_then(|value| count(value))
                .ok_or_else(|| format!("the bundle's manifest names no {key} count"))
        };
        Ok(named("records")?.min(named("bytes")? / RECORD as u64))
    }
}

/// A positive canonical decimal u64 count.
pub(crate) fn count(value: &str) -> Option<u64> {
    let count = value.parse::<u64>().ok()?;
    (count > 0 && count.to_string() == value).then_some(count)
}

/// The longest watchdog, in seconds: the most a manifest's `watchdog`
/// count admits.
const WATCHDOG_MAX: f64 = 4_294_967_295.0;

/// `value` as a positive number of seconds a watchdog can wait, at most
/// 4294967295, the most a manifest's `watchdog` count admits.
///
/// # Errors
///
/// The refusal of any other value.
pub fn seconds(value: &str) -> Result<Duration, String> {
    value
        .parse::<f64>()
        .ok()
        .filter(|seconds| *seconds > 0.0 && *seconds <= WATCHDOG_MAX)
        .and_then(|seconds| Duration::try_from_secs_f64(seconds).ok())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| format!("{value:?} is no positive number of seconds up to {WATCHDOG_MAX}"))
}

/// A bundle read: the digest of every byte read and the leading manifest.
#[derive(Debug)]
pub(crate) struct Staged {
    pub(crate) digest: Digest,
    /// The number of bytes staged and hashed.
    pub(crate) bytes: u64,
    /// The leading manifest's text, decoded lossily.
    pub(crate) manifest: String,
}

/// A reader over a raw bundle that hashes every byte it passes on and
/// collects the leading manifest chunks within a separate scan bound.
/// Whole-bundle accounting includes the leading records. Body reads stop
/// after at most one extra 48-byte record beyond the manifest's limit.
/// A source read error ends staging and remains available to the caller.
pub(crate) struct Stager<R> {
    source: Hashing<R>,
    record: [u8; RECORD],
    filled: usize,
    manifest: Vec<u8>,
    read: u64,
    state: State,
    error: Option<io::Error>,
}

enum State {
    /// Reading the leading records.
    Head,
    /// Past them, with the bytes the record maximum allows.
    Body { limit: u64 },
    /// The bundle is refused, for this reason, and nothing more is read.
    Refused(String),
}

impl<R: io::Read> Stager<R> {
    pub(crate) fn new(source: R) -> Self {
        Self {
            source: Hashing::new(source),
            record: [0; RECORD],
            filled: 0,
            manifest: Vec::new(),
            read: 0,
            state: State::Head,
            error: None,
        }
    }

    /// The first failed source read, which ends staging.
    pub(crate) fn read_error(&self) -> Option<&io::Error> {
        self.error.as_ref()
    }

    /// The staged bundle, once the reader passed on every byte it reads.
    ///
    /// # Errors
    ///
    /// A failed source read, repeated read key, missing pin, missing or
    /// invalid positive records/bytes count, or whole-bundle size past its limit.
    pub(crate) fn finish(mut self) -> Result<Staged, String> {
        if let Some(error) = self.error {
            return Err(format!("the bundle read failed: {error}"));
        }
        if matches!(self.state, State::Head) {
            self.end_head();
        }
        match self.state {
            State::Refused(reason) => Err(reason),
            State::Head | State::Body { .. } => Ok(Staged {
                digest: self.source.finish(),
                bytes: self.read,
                manifest: String::from_utf8_lossy(&self.manifest).into_owned(),
            }),
        }
    }

    /// Scans the record just filled.
    fn scan(&mut self) {
        let record = &self.record;
        if self.read > HEAD {
            self.end_head();
        } else if record[0] == FIELD && record[1] == MANIFEST {
            let length = usize::from(record[LENGTH]).min(CHUNK_MAX);
            self.manifest
                .extend_from_slice(&record[CHUNK..CHUNK + length]);
        } else if ![BEGIN, FIELD, CHECKPOINT].contains(&record[0]) {
            self.end_head();
        }
    }

    /// Ends the leading records: reads the record maximum from the
    /// manifest they hold.
    fn end_head(&mut self) {
        let text = String::from_utf8_lossy(&self.manifest);
        let limit = Values::parse(&text, "bundle")
            .and_then(|values| values.maximum())
            .map(|maximum| maximum.saturating_mul(RECORD as u64));
        self.state = match limit {
            Ok(limit) => State::Body { limit },
            Err(reason) => State::Refused(reason),
        };
        self.state.over(self.read);
    }
}

impl State {
    /// This state after `read` bytes: refused past the limit.
    fn over(&mut self, read: u64) {
        if let Self::Body { limit } = self
            && read > *limit
        {
            let maximum = *limit / RECORD as u64;
            *self = Self::Refused(format!(
                "the bundle holds more than {maximum} records, its manifest's maximum"
            ));
        }
    }
}

impl<R: io::Read> io::Read for Stager<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let want = match self.state {
            State::Head => RECORD - self.filled,
            State::Body { limit } => {
                let left = limit
                    .saturating_add(RECORD as u64)
                    .saturating_sub(self.read);
                usize::try_from(left).unwrap_or(usize::MAX)
            }
            State::Refused(_) => 0,
        }
        .min(buffer.len());
        if want == 0 {
            return Ok(0);
        }
        if self.error.is_some() {
            return Ok(0);
        }
        let filled = match self.source.read(&mut buffer[..want]) {
            Ok(filled) => filled,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Err(error),
            Err(error) => {
                self.error = Some(error);
                return Ok(0);
            }
        };
        self.read += filled as u64;
        match self.state {
            State::Head if filled == 0 => self.end_head(),
            State::Head => {
                self.record[self.filled..self.filled + filled].copy_from_slice(&buffer[..filled]);
                self.filled += filled;
                if self.filled == RECORD {
                    self.filled = 0;
                    self.scan();
                }
            }
            _ => self.state.over(self.read),
        }
        Ok(filled)
    }
}
