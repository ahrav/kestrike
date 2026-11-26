//! The evidence a replay or reduction compares: the frozen inputs and the recorded run.

use super::class::{Stop, incomplete};
use super::command::text;
use super::input::{RECORD, Stager, Tag};
use crate::record::{BOUND, Difference, Digest, Event};
use crate::store::{Identity, open_evidence, open_host};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

pub(super) struct Frozen {
    path: PathBuf,
    digest: Digest,
    identity: Identity,
    bundle: bool,
    bound: u64,
    confined: bool,
}
impl Frozen {
    pub(super) fn bounded_file(path: PathBuf, digest: Digest) -> Result<Self, Stop> {
        Self::new(path, digest, false, BOUND, true)
    }
    pub(super) fn bundle(path: PathBuf, digest: Digest) -> Result<Self, Stop> {
        Self::new(path, digest, true, BOUND, false)
    }
    pub(super) fn worker_bundle(path: PathBuf, digest: Digest) -> Result<Self, Stop> {
        Self::new(path, digest, true, BOUND, true)
    }
    pub(super) fn raw_file(path: PathBuf, digest: Digest, bound: u64) -> Result<Self, Stop> {
        Self::new(path, digest, false, bound, false)
    }
    pub(super) fn worker_file(path: PathBuf, digest: Digest, bound: u64) -> Result<Self, Stop> {
        Self::new(path, digest, false, bound, true)
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn digest(&self) -> Digest {
        self.digest
    }

    fn new(
        path: PathBuf,
        digest: Digest,
        bundle: bool,
        bound: u64,
        confined: bool,
    ) -> Result<Self, Stop> {
        let identity = open_frozen(&path, confined)?.identity();
        let frozen = Self {
            path,
            digest,
            identity,
            bundle,
            bound,
            confined,
        };
        frozen.check()?;
        Ok(frozen)
    }
    pub(super) fn check(&self) -> Result<(), Stop> {
        let mut opened = open_frozen(&self.path, self.confined).map_err(|stop| {
            incomplete(format!(
                "{} cannot be read after admission: {}",
                self.path.display(),
                stop.1
            ))
        })?;
        let identity = opened.identity();
        let changed = || {
            incomplete(format!(
                "the frozen {} changed after admission: {}",
                if self.bundle { "bundle" } else { "file" },
                self.path.display()
            ))
        };
        if identity != self.identity {
            return Err(changed());
        }
        let unreadable = |error: &dyn std::fmt::Display| {
            incomplete(format!(
                "{} cannot be read after admission: {error}",
                self.path.display()
            ))
        };
        let digest = if self.bundle {
            let mut staged = Stager::new(opened);
            io::copy(&mut staged, &mut io::sink()).map_err(|error| unreadable(&error))?;
            if let Some(error) = staged.read_error() {
                return Err(unreadable(error));
            }
            staged.finish().map_err(|_| changed())?.digest
        } else {
            Digest::read((&mut opened).take(self.bound.saturating_add(1)))
                .map_err(|error| unreadable(&error))?
        };
        if digest != self.digest {
            return Err(changed());
        }
        let reopened =
            open_frozen(&self.path, self.confined).map_err(|stop| unreadable(&stop.1))?;
        if reopened.identity() != identity {
            return Err(changed());
        }
        Ok(())
    }
}
fn open_frozen(path: &Path, confined: bool) -> Result<crate::store::Opened, Stop> {
    if confined {
        open_evidence(path)
            .map(|(file, _)| file)
            .map_err(|error| evidence_read_error(path, error))
    } else {
        open_host(path)
            .map_err(|error| incomplete(format!("{} cannot be read: {error:?}", path.display())))
    }
}

/// Describes an evidence-path failure while preserving its incomplete class.
pub(super) fn evidence_read_error(path: &Path, error: crate::store::Error) -> Stop {
    match error {
        crate::store::Error::Io(error) if error.kind() == io::ErrorKind::NotFound => {
            incomplete(format!("{} is missing", path.display()))
        }
        crate::store::Error::Io(error) => {
            incomplete(format!("{} cannot be read: {error}", path.display()))
        }
        crate::store::Error::Refused(error) => incomplete(format!(
            "{} evidence path is refused: {error:?}",
            path.display()
        )),
        error => incomplete(format!(
            "{} evidence is unreadable: {error:?}",
            path.display()
        )),
    }
}

const TURN: u8 = 4;
const CLOCK: u8 = 5;
const VIOLATION: u8 = 7;
const CLOCK_BYTES: std::ops::Range<usize> = 4..12;

#[derive(PartialEq, Eq)]
struct Recorded {
    bytes: [u8; RECORD],
    at: u64,
    clock: Option<u64>,
}
impl Recorded {
    fn event(self) -> Event {
        Event {
            node: None,
            operation: None,
            record: text(
                &self
                    .bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            ),
            semantic_record: self.at,
            virtual_us: self.clock,
        }
    }
}

struct Records {
    path: PathBuf,
    expected: Digest,
    source: BufReader<Stager<crate::store::Opened>>,
    at: u64,
    clock: Option<u64>,
}
impl Records {
    fn open(path: &Path, expected: Digest) -> Result<Self, Stop> {
        let (source, _) = open_evidence(path)
            .map_err(|error| incomplete(format!("{}: {error:?}", path.display())))?;
        Ok(Self {
            path: path.to_owned(),
            expected,
            source: BufReader::new(Stager::new(source)),
            at: 0,
            clock: None,
        })
    }
    fn unreadable(&self, error: &io::Error) -> Stop {
        match self.source.get_ref().read_error() {
            Some(fault) => incomplete(format!("{} cannot be read: {fault}", self.path.display())),
            None => incomplete(format!("{}: {error}", self.path.display())),
        }
    }
    fn next(&mut self) -> Result<Option<Recorded>, Stop> {
        loop {
            let mut record = [0; RECORD];
            let filled = self
                .source
                .read(&mut record[..1])
                .map_err(|error| self.unreadable(&error))?;
            if filled == 0 {
                return Ok(None);
            }
            self.source
                .read_exact(&mut record[1..])
                .map_err(|error| self.unreadable(&error))?;
            match Tag::of(record[0]) {
                Tag::Skipped => continue,
                Tag::Unknown => {
                    return Err(incomplete(format!(
                        "the bundle has unknown record tag {}",
                        record[0]
                    )));
                }
                Tag::Semantic => {}
            }
            if matches!(record[0], TURN | CLOCK) {
                self.clock = Some(u64::from_le_bytes(
                    record[CLOCK_BYTES].try_into().expect("eight clock bytes"),
                ));
            }
            let event = Recorded {
                bytes: record,
                at: self.at,
                clock: self.clock,
            };
            self.at += 1;
            return Ok(Some(event));
        }
    }
    fn finish(self) -> Result<(), Stop> {
        let digest = self
            .source
            .into_inner()
            .finish()
            .map_err(|reason| incomplete(format!("{}: {reason}", self.path.display())))?
            .digest;
        if digest == self.expected {
            Ok(())
        } else {
            Err(incomplete(
                "the scanned bundle differs from its frozen digest",
            ))
        }
    }
}
pub(super) fn first_failure(path: &Path, expected: Digest) -> Result<Option<Event>, Stop> {
    let mut records = Records::open(path, expected)?;
    let mut first = None;
    while let Some(event) = records.next()? {
        if first.is_none() && event.bytes[0] == VIOLATION {
            first = Some(event.event());
        }
    }
    records.finish()?;
    Ok(first)
}
pub(super) fn difference(
    committed: &Path,
    replayed: &Path,
    committed_digest: Digest,
    replayed_digest: Digest,
) -> Result<Option<Difference>, Stop> {
    let mut left = Records::open(committed, committed_digest)?;
    let mut right = Records::open(replayed, replayed_digest)?;
    let mut first = None;
    loop {
        let committed = left.next()?;
        let replayed = right.next()?;
        if committed.is_none() && replayed.is_none() {
            break;
        }
        if first.is_none() && committed != replayed {
            first = Some(Difference {
                committed: committed.map(Recorded::event),
                replayed: replayed.map(Recorded::event),
            });
        }
    }
    left.finish()?;
    right.finish()?;
    Ok(first)
}
