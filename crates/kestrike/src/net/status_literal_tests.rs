//! Wire statuses against `LITERAL`, a table from each wire number to its
//! named meaning written apart from the enum's discriminants and
//! `Status::from_wire`, so it is an independent oracle for both, and the
//! frame target's committed seeds, one per status in the narrowest carrier
//! that admits it: GET's ERROR for 1 through 23 and PUT ERROR for 24
//! through 28. The version 2 seeds of those statuses are rejection vectors.

use std::path::PathBuf;

use super::frame::tests::CORPUS;
use super::frame::{Field, FrameError, Kind, Status, parse};
use super::frame_tests::{Raw, crc};

/// The wire numbers GET's ERROR carries.
const GET_CODES: std::ops::RangeInclusive<u16> = 1..=23;

const LITERAL: [(u16, Status); 28] = [
    (1, Status::Missing),
    (2, Status::Expired),
    (3, Status::Contended),
    (4, Status::LeasePressure),
    (5, Status::ObjectPressure),
    (6, Status::ReceivePressure),
    (7, Status::RequestPressure),
    (8, Status::RetransmissionPressure),
    (9, Status::StoragePressure),
    (10, Status::ReadOpsPressure),
    (11, Status::TooLarge),
    (12, Status::ClockUnavailable),
    (13, Status::Closed),
    (14, Status::DeviceError),
    (15, Status::Short),
    (16, Status::IntegrityError),
    (17, Status::TimedOut),
    (18, Status::Cancelled),
    (19, Status::OwnerUnavailable),
    (20, Status::SessionMismatch),
    (21, Status::ConflictingRequest),
    (22, Status::CounterExhausted),
    (23, Status::InvalidRequest),
    (24, Status::UnknownOutcome),
    (25, Status::InProgress),
    (26, Status::PermissionDenied),
    (27, Status::AttemptExhausted),
    (28, Status::ConflictingData),
];

/// A GET ERROR carrying `status` on the golden GET's session and request.
fn get_error(status: u16) -> Raw {
    let mut error = Raw::get();
    error.kind = 10;
    error.status = status;
    error.metadata = 0;
    error.body = 0;
    error.grant = 0;
    error.remaining = 0;
    error
}

/// The committed seed of status `code` whose file name starts with `prefix`,
/// and the frame it holds: the GET ERROR for a GET status, the PUT ERROR
/// under serial 5 for a PUT-only one.
fn seed(prefix: &str, code: u16) -> (PathBuf, Raw) {
    let corpus = PathBuf::from(CORPUS);
    if GET_CODES.contains(&code) {
        (
            corpus.join(format!("{prefix}error-status-{code:02}")),
            get_error(code),
        )
    } else {
        (
            corpus.join(format!("{prefix}put-error-status-{code:02}")),
            Raw::put_status(19, code, 5),
        )
    }
}

/// Maps each number 1 through 28 to its literal status and 0, 29 and
/// `u16::MAX` to none; `is_get` holds for exactly 1 through 23.
#[test]
fn ib_wire_status_literals_name_their_specified_statuses() {
    for (code, status) in LITERAL {
        assert_eq!(Status::from_wire(code), Some(status), "{code}");
        assert_eq!(status.is_get(), GET_CODES.contains(&code), "{status:?}");
    }
    for code in [0, 29, u16::MAX] {
        assert_eq!(Status::from_wire(code), None, "{code}");
    }
}

/// GET's ERROR parses each GET status to its literal meaning and refuses
/// the PUT statuses and the unlisted numbers at the status field; PUT
/// ERROR parses every status 1 through 28 and refuses the unlisted ones.
#[test]
fn ib_wire_status_literals_parse_in_their_carriers() {
    fn refused<T>(kind: Kind) -> Result<T, FrameError> {
        Err(FrameError::Field {
            kind,
            field: Field::Status,
        })
    }
    for (code, status) in LITERAL {
        let get = parse(crc(), &get_error(code).bytes(), false).map(|frame| frame.header().status);
        if GET_CODES.contains(&code) {
            assert_eq!(get.map(Status::from_wire), Ok(Some(status)), "{code}");
        } else {
            assert_eq!(get, refused(Kind::Error), "{code}");
        }
        let put = parse(crc(), &Raw::put_status(19, code, 5).bytes(), false)
            .map(|frame| frame.header().status);
        assert_eq!(put.map(Status::from_wire), Ok(Some(status)), "{code}");
    }
    for code in [0, 29, u16::MAX] {
        let get = parse(crc(), &get_error(code).bytes(), false).map(|_| ());
        assert_eq!(get, refused(Kind::Error), "{code}");
        let put = parse(crc(), &Raw::put_status(19, code, 5).bytes(), false).map(|_| ());
        assert_eq!(put, refused(Kind::PutError), "{code}");
    }
}

/// The frame target's corpus holds one committed version 3 seed per status,
/// each exactly the canonical frame of that status in its admissible carrier,
/// so the target's seed pass parses every status.
#[test]
fn ib_wire_status_literals_every_status_has_an_admissible_seed() {
    for (code, status) in LITERAL {
        let (path, frame) = seed("v3-", code);
        let bytes = std::fs::read(&path).unwrap_or_else(|error| panic!("{path:?}: {error}"));
        // The seed carries its tag, which lies outside both crcs.
        let tag = bytes[176..192].try_into().unwrap();
        assert_eq!(bytes, Raw { tag, ..frame }.bytes(), "{path:?}");
        let parsed = parse(crc(), &bytes, false).expect("a canonical seed");
        let kind = match GET_CODES.contains(&code) {
            true => Kind::Error,
            false => Kind::PutError,
        };
        assert_eq!(parsed.header().kind, kind, "{path:?}");
        assert_eq!(
            Status::from_wire(parsed.header().status),
            Some(status),
            "{path:?}"
        );
    }
}

/// Each version 2 status seed is the version 2 encoding of its status frame and
/// refuses as an unknown version, so its status never reaches a carrier check.
#[test]
fn version_2_status_seeds_refuse_as_unknown_versions() {
    for (code, _) in LITERAL {
        let (path, frame) = seed("", code);
        let bytes = std::fs::read(&path).unwrap_or_else(|error| panic!("{path:?}: {error}"));
        assert_eq!(
            bytes,
            Raw {
                version: 2,
                ..frame
            }
            .bytes(),
            "{path:?}"
        );
        assert_eq!(
            parse(crc(), &bytes, false).err(),
            Some(FrameError::Version { found: 2 }),
            "{path:?}"
        );
    }
}
