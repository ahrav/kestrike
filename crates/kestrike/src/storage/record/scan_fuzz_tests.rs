//! The record target's scan modes: one geometry-selected extent record,
//! mutated raw or resealed, placed at a unit-aligned offset of an image,
//! followed by that extent's valid record, and scanned by [`inspect`]
//! over a window around it through an image that logs every read and
//! fails the read or sink call an input names.
//!
//! [`literal_scan`] scans the same image from the format alone: each
//! unit's fixed-field read, the header a candidate's fixed fields claim,
//! clipped to the window, the literal parser's claim, the chunks of a
//! verified header that fits the window and its advance. The judge checks
//! the observed reads before comparing the two scans whole:
//!
//! - every read lies inside the window, `start <= offset` and
//!   `offset + len <= end`;
//! - each unit's fixed read and a candidate's header read are at most the
//!   fixed fields or the header its lengths claim, clipped to the window,
//!   and a chunk read is at most `min(1 MiB, chunk_len)` bytes;
//! - each finding after the first lies at least one unit, or the rounded
//!   units of a valid record, past the one before;
//! - the scan examines at most the window's unit-aligned offsets, and a
//!   finding retains at most its claimed chunk count of table crcs;
//! - the reads, findings, their order and the scan's end equal the
//!   literal scan's.

use std::cell::{Cell, RefCell};
use std::io;

use super::fuzz_tests::{
    apply, claimed_payload, crc32c, header_len, literal_claim, read_bytes, u32_at,
};
use super::geometry_fuzz_tests::Geometry;
use super::{Crc32c, Finding, Image, RecordConfig, Report, Verdict, Window, inspect};
use crate::sim::fuzz::Class;

const UNIT: u64 = 4096;

const FIXED: u64 = super::fuzz_tests::FIXED as u64;

/// The envelope's cap on the bytes of one chunk read.
const CHUNK_READ: u64 = 1 << 20;

/// What a scan did, in order: a read of `len` bytes at `offset`, or a
/// finding handed to its sink.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Read { offset: u64, len: u64 },
    Sink(Finding),
}

/// An image of `len` bytes, zero except for `bytes` at `base`.
struct Sparse {
    base: u64,
    bytes: Vec<u8>,
    len: u64,
}

impl Sparse {
    /// The `len` bytes at `offset`, or `None` past the image's end.
    fn slice(&self, offset: u64, len: u64) -> Option<Vec<u8>> {
        let end = offset.checked_add(len).filter(|&end| end <= self.len)?;
        let mut out = vec![0; len as usize];
        let (from, to) = (
            offset.max(self.base),
            end.min(self.base + self.bytes.len() as u64),
        );
        if from < to {
            let at = (from - self.base) as usize..(to - self.base) as usize;
            out[(from - offset) as usize..(to - offset) as usize].copy_from_slice(&self.bytes[at]);
        }
        Some(out)
    }
}

/// The scan's image: every read logged into `events`; the `fail`-th read,
/// counting from one, and any read past `budget` reads fail.
struct Logged<'a> {
    image: &'a Sparse,
    events: &'a RefCell<Vec<Event>>,
    reads: Cell<usize>,
    fail: Option<usize>,
    budget: usize,
}

impl Image for Logged<'_> {
    fn read_into(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let len = buf.len() as u64;
        self.events.borrow_mut().push(Event::Read { offset, len });
        let reads = self.reads.get() + 1;
        self.reads.set(reads);
        if Some(reads) == self.fail || reads > self.budget {
            return Err(io::ErrorKind::Other.into());
        }
        let bytes = self
            .image
            .slice(offset, len)
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        buf.copy_from_slice(&bytes);
        Ok(())
    }
}

/// How a scan ended: its report, or the kind of the error that stopped it.
type Outcome = Result<Report, io::ErrorKind>;

/// One scan input: the image, the window, the chunk length, and the read
/// and sink call, counting from one, that fail.
struct Case {
    image: Sparse,
    window: (u64, u64),
    chunk_len: u32,
    fail_read: Option<usize>,
    fail_sink: Option<usize>,
}

/// A scan's events and end.
#[derive(Debug, PartialEq, Eq)]
struct Scanned {
    events: Vec<Event>,
    outcome: Outcome,
}

impl Case {
    fn window(&self) -> Window {
        Window::new(self.window.0, self.window.1, self.image.len)
            .expect("a window inside its image")
    }

    /// [`inspect`] over the logged image, at most `budget` reads.
    fn inspected(&self, budget: usize) -> Scanned {
        let config = RecordConfig {
            chunk_len: self.chunk_len,
        }
        .validate()
        .expect("an admitted chunk length");
        let events = RefCell::new(Vec::new());
        let image = Logged {
            image: &self.image,
            events: &events,
            reads: Cell::new(0),
            fail: self.fail_read,
            budget,
        };
        let sinks = Cell::new(0);
        let outcome = inspect(
            &image,
            self.window(),
            Crc32c::detect(),
            &config,
            |finding| {
                events.borrow_mut().push(Event::Sink(finding));
                sinks.set(sinks.get() + 1);
                if Some(sinks.get()) == self.fail_sink {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                Ok(())
            },
        )
        .map_err(|error| error.kind());
        Scanned {
            events: events.into_inner(),
            outcome,
        }
    }
}

/// A candidate the literal scan found: its offset, its claimed chunk
/// count and how far the scan advances past it.
#[derive(Clone, Copy, Debug)]
struct Candidate {
    offset: u64,
    chunks: u32,
    advance: u64,
}

/// The literal scan: its events and end, and each candidate it examined.
struct Literal {
    scanned: Scanned,
    candidates: Vec<Candidate>,
}

/// Whether the image bytes at `offset` start with the record magic inside
/// the case's window.
fn magic_at(case: &Case, offset: u64) -> bool {
    let end = case.window.1;
    end - offset >= 8 && case.image.slice(offset, 8).as_deref() == Some(&b"IMGCREC1"[..])
}

/// The header bytes the fixed fields at `offset` claim, clipped to the
/// case's window, or the fixed fields themselves when the window ends
/// inside them.
fn header_read(case: &Case, offset: u64) -> u64 {
    let room = case.window.1 - offset;
    match case.image.slice(offset, FIXED).filter(|_| room >= FIXED) {
        Some(fixed) => header_len(claimed_payload(&fixed), case.chunk_len).min(room),
        None => room.min(FIXED),
    }
}

/// Scans `case` from the format's documentation alone; see the module
/// documentation.
fn literal_scan(case: &Case) -> Literal {
    let mut scan = LiteralScan {
        case,
        events: Vec::new(),
        candidates: Vec::new(),
        reads: 0,
        report: Report {
            window: case.window(),
            units: 0,
            candidates: 0,
            valid: 0,
        },
    };
    let outcome = scan.run().map(|()| scan.report);
    Literal {
        scanned: Scanned {
            events: scan.events,
            outcome,
        },
        candidates: scan.candidates,
    }
}

/// The literal scan's state while it runs.
struct LiteralScan<'c> {
    case: &'c Case,
    events: Vec<Event>,
    candidates: Vec<Candidate>,
    reads: usize,
    report: Report,
}

impl LiteralScan<'_> {
    /// Reads `len` bytes at `offset`, failing the read the case names.
    fn read(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, io::ErrorKind> {
        self.events.push(Event::Read { offset, len });
        self.reads += 1;
        if Some(self.reads) == self.case.fail_read {
            return Err(io::ErrorKind::Other);
        }
        Ok(self
            .case
            .image
            .slice(offset, len)
            .expect("a read inside the image"))
    }

    fn run(&mut self) -> Result<(), io::ErrorKind> {
        let (start, end) = self.case.window;
        let Some(mut offset) = start.checked_next_multiple_of(UNIT) else {
            return Ok(());
        };
        while offset < end {
            self.report.units += 1;
            let fixed = self.read(offset, (end - offset).min(FIXED))?;
            let advance = if fixed.get(..8) == Some(&b"IMGCREC1"[..]) {
                self.candidate(offset)?
            } else {
                UNIT
            };
            match offset.checked_add(advance) {
                Some(next) => offset = next,
                None => break,
            }
        }
        Ok(())
    }

    /// Examines the candidate at `offset`, hands its finding to the sink
    /// and returns its advance.
    fn candidate(&mut self, offset: u64) -> Result<u64, io::ErrorKind> {
        let (end, chunk) = (self.case.window.1, u64::from(self.case.chunk_len));
        let room = end - offset;
        let header = self.read(offset, header_read(self.case, offset))?;
        let mut finding = Finding {
            offset,
            verdict: Verdict::Valid,
            identity: None,
            lengths: (room >= FIXED).then(|| (u32_at(&header, 72), u32_at(&header, 76))),
            record_len: None,
            header_crc: None,
            chunk_crcs: Vec::new(),
        };
        let mut chunks = 0;
        match literal_claim(&header, self.case.chunk_len) {
            Err(mismatch) => finding.verdict = Verdict::Header(mismatch),
            Ok(claim) => {
                chunks = claim.chunk_count;
                let record_len = claim.header as u64 + claim.payload;
                finding.identity = Some(claim.identity);
                finding.header_crc = Some(claim.header_crc);
                finding.record_len = Some(record_len);
                if record_len > room {
                    finding.verdict = Verdict::Truncated {
                        end: offset.saturating_add(record_len),
                    };
                } else {
                    let first = claim.header as u64 / chunk;
                    for (index, stored) in (0..).zip(claim.chunk_crcs) {
                        let window = first + u64::from(index);
                        let at = (window * chunk).max(claim.header as u64);
                        let to = ((window + 1) * chunk).min(record_len);
                        let bytes = self.read(offset + at, to - at)?;
                        finding.chunk_crcs.push(stored);
                        let computed = crc32c(&bytes);
                        if computed != stored {
                            finding.verdict = Verdict::Chunk {
                                index,
                                stored,
                                computed,
                            };
                            break;
                        }
                    }
                }
            }
        }
        let advance = match (finding.verdict, finding.record_len) {
            (Verdict::Valid, Some(len)) => len.div_ceil(UNIT) * UNIT,
            _ => UNIT,
        };
        self.candidates.push(Candidate {
            offset,
            chunks,
            advance,
        });
        self.report.candidates += 1;
        self.report.valid += u64::from(finding.verdict == Verdict::Valid);
        self.events.push(Event::Sink(finding));
        if Some(self.report.candidates as usize) == self.case.fail_sink {
            return Err(io::ErrorKind::BrokenPipe);
        }
        Ok(advance)
    }
}

/// The read a scan makes next: a unit's fixed-field read, a candidate's
/// header read, or one of its chunk reads.
#[derive(Clone, Copy)]
enum Next {
    Fixed,
    Header { at: u64 },
    Chunk,
}

/// Checks `actual`'s reads and findings against the envelope the format
/// and the literal scan `literal` derive for `case`, then against the
/// literal scan whole; the first property that fails names itself.
fn envelope(case: &Case, literal: &Literal, actual: &Scanned) -> Result<(), String> {
    let (start, end) = case.window;
    let chunk_read = CHUNK_READ.min(u64::from(case.chunk_len));
    let mut next = Next::Fixed;
    // The previous finding's offset and the advance the literal scan takes
    // past it.
    let mut previous: Option<(u64, u64)> = None;
    for event in &actual.events {
        match *event {
            Event::Read { offset, len } => {
                if offset < start || u128::from(offset) + u128::from(len) > u128::from(end) {
                    return Err(format!(
                        "a read of {len} bytes at {offset} leaves the window [{start}, {end})"
                    ));
                }
                // A read at an unexamined candidate's offset after its
                // fixed read is its header read; any later read before its
                // finding is a chunk read.
                let (kind, bound) = match next {
                    Next::Header { at } if at == offset => {
                        next = Next::Chunk;
                        ("header", header_read(case, offset))
                    }
                    Next::Chunk | Next::Header { .. } => ("chunk", chunk_read),
                    Next::Fixed => {
                        if magic_at(case, offset) {
                            next = Next::Header { at: offset };
                        }
                        ("fixed", (end - offset).min(FIXED))
                    }
                };
                if len > bound {
                    return Err(format!(
                        "a {kind} read of {len} bytes at {offset} passes its envelope of {bound}"
                    ));
                }
            }
            Event::Sink(ref finding) => {
                next = Next::Fixed;
                let candidate = literal
                    .candidates
                    .iter()
                    .find(|c| c.offset == finding.offset);
                if let Some((before, floor)) = previous
                    && u128::from(finding.offset) < u128::from(before) + u128::from(floor)
                {
                    return Err(format!(
                        "the finding at {} follows the one at {before} by less than its advance of {floor}",
                        finding.offset
                    ));
                }
                let claimed = candidate.map_or(0, |c| c.chunks);
                if finding.chunk_crcs.len() > claimed as usize {
                    return Err(format!(
                        "the finding at {} retains {} chunk crcs of {claimed} claimed",
                        finding.offset,
                        finding.chunk_crcs.len()
                    ));
                }
                previous = Some((finding.offset, candidate.map_or(UNIT, |c| c.advance)));
            }
        }
    }
    let aligned = end.div_ceil(UNIT).saturating_sub(start.div_ceil(UNIT));
    if let Ok(report) = &actual.outcome
        && report.units > aligned
    {
        return Err(format!(
            "the scan examined {} units of the window's {aligned}",
            report.units
        ));
    }
    if *actual != literal.scanned {
        return Err(scan_disagreement(actual, &literal.scanned));
    }
    Ok(())
}

fn scan_disagreement(actual: &Scanned, literal: &Scanned) -> String {
    let first = actual
        .events
        .iter()
        .zip(&literal.events)
        .position(|(ours, theirs)| ours != theirs);
    let ours = first.and_then(|index| actual.events.get(index));
    let theirs = first.and_then(|index| literal.events.get(index));
    format!(
        "the scan ended {:?} after {} events; the literal scan {:?} after {}; first differing event {first:?}: {ours:?} against {theirs:?}",
        actual.outcome,
        actual.events.len(),
        literal.outcome,
        literal.events.len()
    )
}

/// The scan case `input` names: a geometry byte, a placement byte, a
/// fault byte, then the ops that mutate the candidate, resealed when
/// `reseal` is set; `None` when `input` holds fewer than three bytes or
/// more ops than the bound.
///
/// The placement byte's low bit puts the image's content at the top of
/// the offset space, its next two bits start the window 0, 1, 4096 or
/// 12,295 bytes before the candidate, its fourth bit picks the extent of
/// a two-extent object, and its top four bits end the window at one of
/// [`cut`]'s offsets past the candidate. The fault byte's low and high
/// four bits name the read and sink call that fail, zero for none.
fn case(input: &[u8], reseal: bool) -> Option<Case> {
    let [geometry, placement, fault, ops @ ..] = input else {
        return None;
    };
    let geometry = Geometry::of(*geometry);
    let index = u32::from(placement >> 3 & 1) % geometry.extents();
    let (_, valid) = geometry.record(index);
    let mut bytes = apply(valid.clone(), reseal, ops, geometry.chunk_len)?;
    bytes.resize(bytes.len().next_multiple_of(UNIT as usize), 0);
    let padded = bytes.len() as u64;
    bytes.extend_from_slice(&valid);
    let total = bytes.len() as u64;
    let (header, record) = geometry.record_len(index);
    let cut = cut(placement >> 4, header, record, padded, total);
    let pre = [0, 1, UNIT, 3 * UNIT + 7][usize::from(placement >> 1 & 3)];
    let (base, len) = if placement & 1 == 1 {
        ((u64::MAX - total) & !(UNIT - 1), u64::MAX)
    } else {
        (4 * UNIT, 5 * UNIT + total)
    };
    let end = base.saturating_add(cut).min(len);
    let nonzero = |nibble: u8| (nibble != 0).then_some(usize::from(nibble));
    Some(Case {
        image: Sparse { base, bytes, len },
        window: (base - pre, end),
        chunk_len: geometry.chunk_len,
        fail_read: nonzero(fault & 15),
        fail_sink: nonzero(fault >> 4),
    })
}

fn cut(code: u8, header: u64, record: u64, padded: u64, total: u64) -> u64 {
    [
        total + UNIT,
        1,
        11,
        12,
        FIXED - 1,
        FIXED,
        FIXED + 1,
        header - 1,
        header,
        record - 1,
        record,
        padded,
        padded + FIXED - 1,
        padded + FIXED,
        total - 1,
        total,
    ][usize::from(code & 15)]
}

/// The scan modes: [`case`]'s scan judged by [`envelope`]. [`inspect`]
/// runs with a budget of 64 reads past the literal scan's, and every read
/// beyond it fails. A pass's run is the geometry, placement and fault
/// bytes and the whole ops.
pub(crate) fn scan_mode(input: &[u8], reseal: bool) -> Class {
    let Some(case) = case(input, reseal) else {
        return Class::Invalid("the scan input holds no placement or passes its op bound");
    };
    let literal = literal_scan(&case);
    let reads = literal
        .scanned
        .events
        .iter()
        .filter(|event| matches!(event, Event::Read { .. }))
        .count();
    let actual = case.inspected(reads + 64);
    match envelope(&case, &literal, &actual) {
        Ok(()) => Class::Pass {
            run: read_bytes(input, 3),
        },
        Err(claim) => Class::Failure {
            claim,
            bundle: Vec::new(),
        },
    }
}

/// The scan witnesses' seeds: raw, a damaged record followed by a valid
/// one, a maximal claim in a window that ends one byte past its fixed
/// fields, a valid record and a maximal claim at the top of the offset
/// space, and a failing read and a failing sink call; resealed, an offset
/// change the context crc refuses.
pub(crate) fn seeds() -> Vec<(String, Vec<u8>)> {
    let maximal: &[u8] = &[1, 2, 0, 1, 1, 2, 0xff, 0, 1, 3, 0, 1, 1, 3, 0xff, 0];
    let witnesses: [(&str, [u8; 3], &[u8]); 6] = [
        ("damaged-then-valid", [0x8c, 0, 0], &[3, 0, 100, 1]),
        ("maximal-claim-short-window", [0, 0x60, 0], maximal),
        ("near-u64-max", [0b0010_0101, 1, 0], &[]),
        ("near-u64-max-maximal", [0b1101_1011, 0x09, 0], maximal),
        ("read-failure", [0b0010_0101, 0, 3], &[]),
        ("sink-failure", [0x8c, 0, 0x10], &[3, 0, 100, 1]),
    ];
    let mut seeds: Vec<_> = witnesses
        .iter()
        .map(|(name, head, ops)| {
            let mut input = vec![super::fuzz_tests::FORMAT, 3];
            input.extend_from_slice(head);
            input.extend_from_slice(ops);
            (format!("ib-scan-envelope-{name}-3.input"), input)
        })
        .collect();
    // A resealed offset change fails the context crc behind a fresh header
    // crc, then the valid record follows.
    let resealed = vec![super::fuzz_tests::FORMAT, 4, 0x8c, 0, 0, 1, 8, 1, 0];
    seeds.push(("ib-scan-envelope-resealed-context-4.input".into(), resealed));
    seeds
}

#[cfg(test)]
mod tests {
    //! The scan witnesses each reached, through the record target, with
    //! the scan's own observations.

    use super::super::HeaderMismatch;
    use super::super::fuzz_tests::{FORMAT, RECORD};
    use super::*;

    fn seed(name: &str) -> Vec<u8> {
        let name = format!("ib-scan-envelope-{name}.input");
        seeds()
            .into_iter()
            .find(|(seed, _)| *seed == name)
            .map(|(_, input)| input)
            .expect("a scan seed")
    }

    /// The seed's case, its scan and the literal scan, after the target
    /// passes it.
    fn seed_scan(name: &str) -> (Case, Scanned) {
        let input = seed(name);
        assert!(matches!((RECORD.run)(&input), Class::Pass { .. }), "{name}");
        let case = case(&input[2..], input[1] == 4).expect("a scan case");
        let scanned = case.inspected(usize::MAX);
        assert_eq!(scanned, literal_scan(&case).scanned, "{name}");
        (case, scanned)
    }

    #[test]
    fn a_scan_disagreement_names_the_first_differing_event() {
        let (_, scanned) = seed_scan("damaged-then-valid-3");
        let index = scanned
            .events
            .iter()
            .position(|event| matches!(event, Event::Sink(f) if f.verdict == Verdict::Valid))
            .expect("a valid finding");
        let mut other = Scanned {
            events: scanned.events.clone(),
            outcome: scanned.outcome,
        };
        let Event::Sink(finding) = &mut other.events[index] else {
            panic!("a sink event");
        };
        finding.verdict = Verdict::Truncated { end: 0 };
        let claim = scan_disagreement(&scanned, &other);
        assert!(claim.len() < 4096, "claim of {} bytes", claim.len());
        assert!(
            claim.contains(&format!("first differing event Some({index})")),
            "{claim}"
        );
        assert!(claim.contains("Truncated { end: 0 }"), "{claim}");
    }

    fn findings(scanned: &Scanned) -> Vec<&Finding> {
        scanned
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Sink(finding) => Some(finding),
                Event::Read { .. } => None,
            })
            .collect()
    }

    /// A record whose chunk is damaged, or whose resealed offset fails the
    /// context crc, is reported at that check, and the scan advances one
    /// unit past it and finds the valid record after it.
    #[test]
    fn ib_scan_envelope_damaged_record_then_valid_record() {
        let (_, scanned) = seed_scan("damaged-then-valid-3");
        let found = findings(&scanned);
        assert_eq!(found.len(), 2, "{found:#?}");
        assert!(matches!(found[0].verdict, Verdict::Chunk { .. }));
        assert_eq!(found[1].verdict, Verdict::Valid);
        assert!(found[1].offset > found[0].offset);
        assert!(scanned.outcome.is_ok());
        let (_, resealed) = seed_scan("resealed-context-4");
        let found = findings(&resealed);
        assert!(matches!(
            found[0].verdict,
            Verdict::Header(HeaderMismatch::ContextCrc { .. })
        ));
        assert_eq!(found[1].verdict, Verdict::Valid);
    }

    #[test]
    fn ib_scan_envelope_maximal_claim_in_short_window() {
        let (case, scanned) = seed_scan("maximal-claim-short-window-3");
        assert_eq!(case.window.1 - case.image.base, FIXED + 1);
        let found = findings(&scanned);
        assert_eq!(
            found[0].verdict,
            Verdict::Header(HeaderMismatch::Lengths {
                metadata_len: u32::MAX,
                body_len: u32::MAX
            })
        );
        let reads: Vec<_> = scanned
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Read { offset, len } => Some((*offset, *len)),
                Event::Sink(_) => None,
            })
            .collect();
        assert_eq!(
            reads,
            [(case.image.base, FIXED), (case.image.base, FIXED + 1)]
        );
    }

    /// A window ending at `u64::MAX` scans its last aligned unit, whose
    /// next offset is unrepresentable, without a read past the window, and
    /// a maximal claim there refuses at its lengths.
    #[test]
    fn ib_scan_envelope_offset_near_u64_max() {
        let (case, scanned) = seed_scan("near-u64-max-3");
        assert_eq!(case.window.1, u64::MAX);
        let last = u64::MAX - (UNIT - 1);
        assert!(scanned.events.contains(&Event::Read {
            offset: last,
            len: FIXED
        }));
        assert_eq!(findings(&scanned)[0].verdict, Verdict::Valid);
        let (case, scanned) = seed_scan("near-u64-max-maximal-3");
        assert!(case.image.base > u64::MAX - (1 << 20));
        assert!(matches!(
            findings(&scanned)[0].verdict,
            Verdict::Header(HeaderMismatch::Lengths { .. })
        ));
    }

    /// The third read fails inside the first candidate: the scan returns
    /// that error after three reads and no finding.
    #[test]
    fn ib_scan_envelope_read_failure() {
        let (_, scanned) = seed_scan("read-failure-3");
        assert_eq!(scanned.outcome, Err(io::ErrorKind::Other));
        assert!(findings(&scanned).is_empty());
        assert_eq!(scanned.events.len(), 3);
    }

    /// The sink fails on the first finding: the scan returns that error
    /// and reads nothing after it.
    #[test]
    fn ib_scan_envelope_sink_failure() {
        let (_, scanned) = seed_scan("sink-failure-3");
        assert_eq!(scanned.outcome, Err(io::ErrorKind::BrokenPipe));
        assert!(matches!(scanned.events.last(), Some(Event::Sink(_))));
        assert_eq!(findings(&scanned).len(), 1);
    }

    /// Every placement of the valid two-extent and one-extent records
    /// scans in agreement with the literal scan, resealed and raw.
    #[test]
    fn every_placement_of_a_valid_record_passes() {
        for geometry in [0b1101_1011u8, 0b0010_0101] {
            for placement in 0..=255 {
                for mode in [3, 4] {
                    let input = [FORMAT, mode, geometry, placement, 0];
                    assert!(
                        matches!((RECORD.run)(&input), Class::Pass { .. }),
                        "{input:?}"
                    );
                }
            }
        }
    }
}
