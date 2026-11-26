//! `claim_header`, which serves diagnostic scans that carry no authority, reports the identity it finds and
//! skips the reader check. The read predicate refuses a session whose epoch part is odd or zero for every
//! reader, so a record sealed under such a session separates the two paths: a volume read of it
//! (`verify_header`) ends `ForeignSession`, and a scan of the same bytes (`claim_header`, and `inspect` above
//! it) reports the record whole, with the session its header names.

use super::super::layout::IO_UNIT;
use super::vector_tests::IDENTITY;
use super::{
    Crc32c, ExpectedHeader, ExtentPosition, HeaderMismatch, RecordConfig, RecordIdentity, Verdict,
    Window, claim_header, encode_header, inspect, verify_header,
};

const CHUNK: u32 = 4096;
const METADATA_LEN: u32 = 5;
/// A body that spreads the payload over three chunks.
const BODY_LEN: u32 = 9000;

/// Generation 1 with an even, nonzero epoch: a session the read predicate accepts from its own reader.
const WELL_FORMED: u64 = (1 << 32) | 2;
/// Generation 1 with an odd epoch.
const ODD_EPOCH: u64 = (1 << 32) | 3;
/// Generation 1 with a zero epoch.
const ZERO_EPOCH: u64 = 1 << 32;
/// A reader of generation 1 at a later even epoch than every session above.
const LATER_READER: u64 = (1 << 32) | 4;

/// What the scan path and the read path each made of one record.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    /// The identity `claim_header` reported, or its refusal.
    claimed: Result<RecordIdentity, HeaderMismatch>,
    /// Each finding of `inspect` over the record: its offset, verdict and identity.
    findings: Vec<(u64, Verdict, Option<RecordIdentity>)>,
    /// The candidates `inspect` counted, and those it counted valid.
    counted: (u64, u64),
    /// `verify_header` for the record's own identity, read by the record's own session.
    own_reader: Result<(), HeaderMismatch>,
    /// `verify_header` for the record's own identity, read by [`LATER_READER`].
    later_reader: Result<(), HeaderMismatch>,
}

/// Seals one whole record under `session` and takes it through `claim_header`, `inspect` and `verify_header`.
fn seen(session: u64) -> Seen {
    let crc = Crc32c::detect();
    let config = RecordConfig { chunk_len: CHUNK }.validate().expect("valid");
    let identity = RecordIdentity {
        session,
        ..IDENTITY
    };
    let layout = config.layout(METADATA_LEN, BODY_LEN);
    let mut record = vec![0; layout.record_units() as usize * IO_UNIT];
    let header = layout.header_bytes();
    for (at, byte) in record[header..header + layout.payload_len() as usize]
        .iter_mut()
        .enumerate()
    {
        *byte = (at % 251) as u8;
    }
    encode_header(crc, &layout, &identity, ExtentPosition::FIRST, &mut record).expect("fits");

    let claimed = claim_header(crc, &config, &record).map(|claim| claim.identity);
    let len = record.len() as u64;
    let window = Window::new(0, len, len).expect("the whole image");
    let mut findings = Vec::new();
    let report = inspect(&record[..], window, crc, &config, |finding| {
        findings.push((finding.offset, finding.verdict, finding.identity));
        Ok(())
    })
    .expect("a slice reads");
    let read_by = |reader: u64| {
        let expected = ExpectedHeader {
            identity,
            reader,
            position: ExtentPosition::FIRST,
            len_units: layout.record_units() as u32,
            lengths: None,
        };
        verify_header(crc, &config, &record, &expected).map(drop)
    };
    Seen {
        claimed,
        findings,
        counted: (report.candidates, report.valid),
        own_reader: read_by(session),
        later_reader: read_by(LATER_READER),
    }
}

/// A record whose session no reader accepts is refused by a volume read and reported whole by a scan: the scan
/// carries no reader, so it names the identity the header holds and applies no session check.
#[test]
fn a_scan_reports_a_record_whose_session_every_reader_refuses() {
    for session in [ODD_EPOCH, ZERO_EPOCH] {
        let identity = RecordIdentity {
            session,
            ..IDENTITY
        };
        let foreign = |reader: u64| {
            Err(HeaderMismatch::ForeignSession {
                found: session,
                reader,
            })
        };
        assert_eq!(
            seen(session),
            Seen {
                claimed: Ok(identity),
                findings: vec![(0, Verdict::Valid, Some(identity))],
                counted: (1, 1),
                own_reader: foreign(session),
                later_reader: foreign(LATER_READER),
            },
            "session {session:#x}: the scan reports the identity the header names, the read refuses the session"
        );
    }
}

/// The same record under a well-formed session: the scan reports it as before, and its own reader and a later
/// reader of its generation both accept it.
#[test]
fn a_scan_and_a_read_agree_on_a_record_of_a_well_formed_session() {
    let identity = RecordIdentity {
        session: WELL_FORMED,
        ..IDENTITY
    };
    assert_eq!(
        seen(WELL_FORMED),
        Seen {
            claimed: Ok(identity),
            findings: vec![(0, Verdict::Valid, Some(identity))],
            counted: (1, 1),
            own_reader: Ok(()),
            later_reader: Ok(()),
        }
    );
}
