//! A read-only scan of an image for current-format records, reporting what
//! each candidate's bytes claim and which verification step they fail.
//!
//! - Every read lies inside the caller's window `[start, end)`, which
//!   [`Window::new`] accepts only within the image length `len` the caller
//!   states: `0 <= start <= end <= len`. Offset arithmetic is
//!   checked, so a header whose lengths reach past the window is reported
//!   truncated and its bytes past the window are never read.
//! - The scan reads through [`Image`], whose only operation is a read, so it
//!   leaves the image's bytes unchanged.
//! - A candidate is a unit-aligned offset whose bytes start with the record
//!   magic. The scan verifies its header against the header's own lengths, the
//!   identity it names and the extent index and offset it records, then
//!   verifies each chunk against the header's table. The read predicate
//!   compares a header against an index entry and a reader's session and runs
//!   on a volume read alone, so a volume read can refuse a record the scan
//!   reports valid.
//! - A finding is an observation of bytes. A record that verifies is
//!   reported valid with the identity it names; whether it is live or
//!   recoverable needs the recovery owner's separate authority.

use std::io;
use std::os::unix::fs::FileExt;

use super::super::layout::IO_UNIT;
use super::crc32c::Crc32c;
use super::header::{
    HEADER_MAGIC, HeaderMismatch, RecordIdentity, claim_header, claimed_extent, claimed_lengths,
};
use super::layout::{CHUNK_TABLE, ValidRecordConfig};
use crate::bind::RELEASE_SCOPE;

const UNIT: u64 = IO_UNIT as u64;

/// Bytes the scan reads by offset.
pub trait Image {
    /// Fills `buf` with the image's bytes at `offset`; the caller keeps
    /// `offset + buf.len()` within the image.
    ///
    /// # Errors
    ///
    /// The I/O error that stopped the read.
    fn read_into(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;
}

impl Image for [u8] {
    fn read_into(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let bytes = usize::try_from(offset)
            .ok()
            .and_then(|start| self.get(start..start.checked_add(buf.len())?))
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        buf.copy_from_slice(bytes);
        Ok(())
    }
}

impl Image for std::fs::File {
    fn read_into(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        FileExt::read_exact_at(self, buf, offset)
    }
}

/// The part of an image a scan may read: `[start, end)` within `len` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    start: u64,
    end: u64,
}

/// Why a window does not lie within its image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowError {
    pub start: u64,
    pub end: u64,
    pub len: u64,
}

impl Window {
    /// Accepts `[start, end)` when `start <= end <= len`.
    ///
    /// # Errors
    ///
    /// [`WindowError`] naming the three bounds otherwise.
    pub fn new(start: u64, end: u64, len: u64) -> Result<Self, WindowError> {
        if start <= end && end <= len {
            Ok(Self { start, end })
        } else {
            Err(WindowError { start, end, len })
        }
    }
}

/// What a candidate's verification established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The header and every chunk verified.
    Valid,
    /// A header check failed; `Truncated` here means the window ends inside the header.
    Header(HeaderMismatch),
    /// The verified header's record ends at `end`, past the window.
    Truncated { end: u64 },
    /// Chunk `index` holds bytes whose crc32c differs from the header's table.
    Chunk {
        index: u32,
        stored: u32,
        computed: u32,
    },
}

/// One candidate record: its offset, the facts its header bytes claim and
/// the first verification step its bytes failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub offset: u64,
    pub verdict: Verdict,
    /// The identity a verified header names.
    pub identity: Option<RecordIdentity>,
    /// The metadata and body lengths the fixed fields claim, when the window holds them.
    pub lengths: Option<(u32, u32)>,
    /// The record's bytes from header start to its last payload byte, once its header verified.
    pub record_len: Option<u64>,
    /// The header crc32c a verified header stores.
    pub header_crc: Option<u32>,
    /// The chunk-table crc32c of each chunk checked, in order, ending at the first mismatch.
    pub chunk_crcs: Vec<u32>,
}

/// A scan's totals over its window; each finding goes to the scan's sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub window: Window,
    /// Unit-aligned offsets the scan examined.
    pub units: u64,
    /// Candidates the scan passed to its sink.
    pub candidates: u64,
    /// Candidates whose verdict is [`Verdict::Valid`].
    pub valid: u64,
}

impl Report {
    /// Whether every candidate verified.
    pub fn verified(&self) -> bool {
        self.valid == self.candidates
    }
}

/// Calls `sink` with each candidate's finding in offset order, before
/// reading the next unit.
///
/// A candidate whose bytes verify advances the scan past the record's
/// units; any other candidate advances it by one unit, so a damaged record
/// cannot hide a later one.
///
/// # Errors
///
/// The scan returns the first read or `sink` error; `sink` has received
/// every preceding finding.
pub fn inspect<I: Image + ?Sized>(
    image: &I,
    window: Window,
    crc: Crc32c,
    config: &ValidRecordConfig,
    mut sink: impl FnMut(Finding) -> io::Result<()>,
) -> io::Result<Report> {
    let mut report = Report {
        window,
        units: 0,
        candidates: 0,
        valid: 0,
    };
    let Some(mut offset) = window.start.checked_next_multiple_of(UNIT) else {
        return Ok(report);
    };
    while offset < window.end {
        report.units += 1;
        let room = window.end - offset;
        let mut fixed = vec![0; CHUNK_TABLE.min(room as usize)];
        image.read_into(&mut fixed, offset)?;
        if fixed.get(..8) != Some(&HEADER_MAGIC.to_le_bytes()[..]) {
            let Some(next) = offset.checked_add(UNIT) else {
                break;
            };
            offset = next;
            continue;
        }
        let finding = candidate(image, offset, room, &fixed, crc, config)?;
        let advance = match (finding.verdict, finding.record_len) {
            (Verdict::Valid, Some(len)) => len.div_ceil(UNIT) * UNIT,
            _ => UNIT,
        };
        report.candidates += 1;
        report.valid += u64::from(finding.verdict == Verdict::Valid);
        sink(finding)?;
        let Some(next) = offset.checked_add(advance) else {
            break;
        };
        offset = next;
    }
    Ok(report)
}

/// Verifies the candidate at `offset`, whose first bytes `fixed` holds and
/// after which the window has `room` bytes.
fn candidate<I: Image + ?Sized>(
    image: &I,
    offset: u64,
    room: u64,
    fixed: &[u8],
    crc: Crc32c,
    config: &ValidRecordConfig,
) -> io::Result<Finding> {
    let lengths = claimed_lengths(fixed);
    let mut finding = Finding {
        offset,
        verdict: Verdict::Valid,
        identity: None,
        lengths,
        record_len: None,
        header_crc: None,
        chunk_crcs: Vec::new(),
    };
    let header_len = claimed_extent(config, fixed)
        .map_or(fixed.len() as u64, |layout| layout.header_bytes() as u64);
    let mut header = vec![0; header_len.min(room) as usize];
    image.read_into(&mut header, offset)?;
    let claimed = match claim_header(crc, config, &header) {
        Ok(claimed) => claimed,
        Err(mismatch) => {
            finding.verdict = Verdict::Header(mismatch);
            return Ok(finding);
        }
    };
    let layout = claimed.layout;
    finding.identity = Some(claimed.identity);
    finding.header_crc = Some(claimed.header_crc);
    finding.record_len = Some(layout.record_len());
    if layout.record_len() > room {
        finding.verdict = Verdict::Truncated {
            end: offset.saturating_add(layout.record_len()),
        };
        return Ok(finding);
    }
    let payload = offset + layout.header_bytes() as u64;
    // A claimed layout's payload is one extent's coverage, at most
    // `EXTENT_PAYLOAD` bytes, so every chunk fits one read.
    let mut buf = vec![0; layout.payload_len().min(u64::from(layout.chunk_len())) as usize];
    for index in 0..layout.chunk_count() {
        let range = layout.chunks(index, index + 1);
        let chunk = &mut buf[..(range.end - range.start) as usize];
        image.read_into(chunk, payload + range.start)?;
        let (stored, computed) = (claimed.verified.chunk_crc(index), crc.checksum(chunk));
        finding.chunk_crcs.push(stored);
        if stored != computed {
            finding.verdict = Verdict::Chunk {
                index,
                stored,
                computed,
            };
            return Ok(finding);
        }
    }
    Ok(finding)
}

/// The authority the report's findings carry, printed with every report.
pub(super) const AUTHORITY: &str = "findings are observations of these bytes; a valid record has no live or \
recoverable status, which only the recovery owner's separate authority grants";

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "record at {}", self.offset)?;
        if let Some((metadata, body)) = self.lengths {
            write!(f, " metadata {metadata} body {body}")?;
        }
        if let Some(len) = self.record_len {
            write!(f, " len {len}")?;
        }
        if let Some(identity) = self.identity {
            f.write_str(" key ")?;
            for byte in identity.key {
                write!(f, "{byte:02x}")?;
            }
            write!(
                f,
                " slot {} incarnation {} session {} version {}",
                identity.allocation >> 32,
                identity.allocation & u64::from(u32::MAX),
                identity.session,
                identity.version
            )?;
        }
        if let Some(crc) = self.header_crc {
            write!(f, " header-crc {crc:08x}")?;
        }
        f.write_str(" chunk-crcs [")?;
        for (index, crc) in self.chunk_crcs.iter().enumerate() {
            let gap = if index == 0 { "" } else { " " };
            write!(f, "{gap}{crc:08x}")?;
        }
        f.write_str("]")?;
        match self.verdict {
            Verdict::Valid => f.write_str(" valid"),
            verdict => write!(f, " failed {verdict:?}"),
        }
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "scanned [{}, {}) read-only: {} units, {} of {} candidates verified",
            self.window.start, self.window.end, self.units, self.valid, self.candidates,
        )?;
        writeln!(f, "authority: {AUTHORITY}")?;
        write!(f, "mapper: {RELEASE_SCOPE}")
    }
}
