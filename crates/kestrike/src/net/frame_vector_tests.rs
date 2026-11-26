//! Fixed frame vectors: the version 3 corpus files, ERROR, CANCEL, PUT ERROR
//! and PUT CANCEL status frames, and the goldens. `INVENTORY` maps each kind
//! and required shape to the version 3 vectors, goldens and status frames that
//! cover it, and every referenced frame must parse to the row's kind and
//! satisfy the row's shape predicate over its header. The twenty-two version 2
//! corpus files and the version 2 HMAC tags derived outside the crate are
//! rejection vectors: each keeps its literal bytes and refuses as an unknown
//! version before authentication.

use super::auth::{AuthError, KeyEntry, KeyRing};
use super::auth_tests::crc_preserving_flip;
use super::datagram::{HEADER_LEN, PeerId};
use super::frame::tests::vector as v3;
use super::frame::{Direction, Field, FrameError, Header, Kind, Status, mac_input_for, parse};
use super::frame_tests::{Raw, bitwise_crc32c, crc, goldens, reseal};
use crate::storage::EngineBudget;

const ENDPOINT: u32 = 0x00E1_0001;
const PRINCIPAL: u32 = 0x0102_0304;
const KEY_EPOCH: u32 = 9;
const PLACEHOLDER: [u8; 16] = [0x5A; 16];

const ERROR_STATUSES: &str = "status 1 to 23";
const CANCEL_STATUSES: &str = "status 17 and 18";
const PUT_ERROR_STATUSES: &str = "put status 1 to 28";
const PUT_CANCEL_STATUSES: &str = "put status 17 and 18";

#[derive(Clone, Copy)]
struct Row {
    shape: &'static str,
    kind: u8,
    holds: fn(&Header) -> bool,
    vectors: &'static [&'static str],
}

const fn row(shape: &'static str, kind: u8, vectors: &'static [&'static str]) -> Row {
    shaped(shape, kind, |_| true, vectors)
}

/// A row whose every vector must also satisfy `holds`, the header property that defines the shape.
const fn shaped(
    shape: &'static str,
    kind: u8,
    holds: fn(&Header) -> bool,
    vectors: &'static [&'static str],
) -> Row {
    Row {
        shape,
        kind,
        holds,
        vectors,
    }
}

const INVENTORY: [Row; 43] = [
    row("HELLO", 1, &["v3 v3-hello", "golden hello"]),
    row("CHALLENGE", 2, &["v3 v3-challenge", "golden challenge"]),
    row("CONFIRM", 3, &["v3 v3-confirm", "golden confirm"]),
    row("READY", 4, &["v3 v3-ready", "golden ready"]),
    row("GET", 5, &["v3 v3-get", "golden get"]),
    shaped(
        "GET zero key",
        5,
        |header| header.key == [0; 32],
        &["golden get zero key"],
    ),
    row("START", 6, &["v3 v3-start", "golden start"]),
    shaped("START empty", 6, empty_object, &["golden start empty"]),
    shaped(
        "DATA first",
        7,
        |header| header.index == 0 && header.count > 1,
        &["v3 v3-data-first", "golden data first"],
    ),
    shaped(
        "DATA final",
        7,
        |header| last_fragment(header) && header.datagram_len < 8192,
        &["v3 v3-data-final", "golden data final"],
    ),
    shaped(
        "DATA exact",
        7,
        |header| last_fragment(header) && header.datagram_len == 8192,
        &["golden data exact"],
    ),
    shaped(
        "DATA two slices",
        7,
        |header| header.datagram_len >= 2,
        &[
            "golden data first",
            "golden data final",
            "golden data exact",
        ],
    ),
    row("ACK", 8, &["v3 v3-ack", "golden ack"]),
    row("COMPLETE", 9, &["v3 v3-complete", "golden complete"]),
    shaped(
        "COMPLETE empty",
        9,
        empty_object,
        &["v3 v3-complete-empty", "golden complete empty"],
    ),
    row(
        "ERROR",
        10,
        &["v3 v3-error", "golden error", ERROR_STATUSES],
    ),
    row(
        "CANCEL",
        11,
        &["v3 v3-cancel", "golden cancel", CANCEL_STATUSES],
    ),
    row("PUT BEGIN", 12, &["v3 v3-put-begin", "golden put begin"]),
    row(
        "PUT AUTHORITY",
        13,
        &["v3 v3-put-authority", "golden put authority"],
    ),
    row(
        "PUT PREPARE",
        14,
        &["v3 v3-put-prepare", "golden put prepare"],
    ),
    shaped(
        "PUT PREPARE empty",
        14,
        empty_object,
        &["golden put prepare empty"],
    ),
    row("PUT READY", 15, &["v3 v3-put-ready", "golden put ready"]),
    shaped(
        "PUT READY empty",
        15,
        |header| empty_object(header) && header.grant == 0,
        &["golden put ready empty"],
    ),
    shaped(
        "PUT DATA first",
        16,
        |header| header.index == 0 && header.count > 1,
        &["golden put data first"],
    ),
    shaped(
        "PUT DATA final",
        16,
        |header| last_fragment(header) && header.datagram_len < 8192,
        &["v3 v3-put-data", "golden put data final"],
    ),
    shaped(
        "PUT DATA exact",
        16,
        |header| last_fragment(header) && header.datagram_len == 8192,
        &["golden put data exact"],
    ),
    shaped(
        "PUT DATA two slices",
        16,
        |header| header.datagram_len >= 2,
        &[
            "golden put data first",
            "golden put data final",
            "golden put data exact",
        ],
    ),
    shaped(
        "PUT ACK holding a fragment",
        17,
        |header| header.offset != 0,
        &["v3 v3-put-ack", "golden put ack"],
    ),
    shaped(
        "PUT ACK final",
        17,
        |header| header.index == header.count && header.grant == header.count,
        &["golden put ack final"],
    ),
    row("PUT RESULT", 18, &["v3 v3-put-result", "golden put result"]),
    shaped(
        "PUT RESULT empty",
        18,
        empty_object,
        &["golden put result empty"],
    ),
    row(
        "PUT ERROR",
        19,
        &["v3 v3-put-error", "golden put error", PUT_ERROR_STATUSES],
    ),
    shaped(
        "PUT ERROR before authority",
        19,
        |header| header.allocation == 0,
        &["golden put error before authority"],
    ),
    shaped(
        "PUT CANCEL",
        20,
        |header| header.allocation == 0,
        &["v3 v3-put-cancel", "golden put cancel", PUT_CANCEL_STATUSES],
    ),
    shaped(
        "PUT BEGIN versioned",
        12,
        |h| h.offset != 0,
        &["v3 v3-put-begin-versioned"],
    ),
    row("WHO HOLDS", 21, &["v3 v3-who-holds"]),
    row("HOLDER", 22, &["v3 v3-holder"]),
    row("WRONG OWNER", 23, &["v3 v3-wrong-owner"]),
    row("HEARTBEAT", 24, &["v3 v3-heartbeat"]),
    row("PROBE", 25, &["v3 v3-probe"]),
    row("PROBE REPLY", 26, &["v3 v3-probe-reply"]),
    row("INVALIDATE", 27, &["v3 v3-invalidate"]),
    row("INVALIDATED", 28, &["v3 v3-invalidated"]),
];

fn empty_object(header: &Header) -> bool {
    header.metadata_len == 0 && header.body_len == 0
}

fn last_fragment(header: &Header) -> bool {
    header.count > 1 && header.index + 1 == header.count
}

struct Corpus {
    name: &'static str,
    bytes: &'static [u8],
    kind: u8,
    len: usize,
    header_crc: u32,
    body_crc: u32,
    golden: Option<&'static str>,
}

const CORPUS: [Corpus; 22] = [
    Corpus {
        name: "hello",
        bytes: include_bytes!("../../fuzz/corpus/frame/hello"),
        kind: 1,
        len: 200,
        header_crc: 0x6178_3F7D,
        body_crc: 0x0834_A4A7,
        golden: Some("hello"),
    },
    Corpus {
        name: "challenge",
        bytes: include_bytes!("../../fuzz/corpus/frame/challenge"),
        kind: 2,
        len: 200,
        header_crc: 0xDB81_111D,
        body_crc: 0x0834_A4A7,
        golden: Some("challenge"),
    },
    Corpus {
        name: "confirm",
        bytes: include_bytes!("../../fuzz/corpus/frame/confirm"),
        kind: 3,
        len: 200,
        header_crc: 0x1E4F_7A38,
        body_crc: 0x0834_A4A7,
        golden: Some("confirm"),
    },
    Corpus {
        name: "ready",
        bytes: include_bytes!("../../fuzz/corpus/frame/ready"),
        kind: 4,
        len: 200,
        header_crc: 0x4CFC_8621,
        body_crc: 0x0834_A4A7,
        golden: None,
    },
    Corpus {
        name: "get",
        bytes: include_bytes!("../../fuzz/corpus/frame/get"),
        kind: 5,
        len: 192,
        header_crc: 0xCA13_B45D,
        body_crc: 0,
        golden: Some("get"),
    },
    Corpus {
        name: "start",
        bytes: include_bytes!("../../fuzz/corpus/frame/start"),
        kind: 6,
        len: 192,
        header_crc: 0x4FC3_B6AA,
        body_crc: 0,
        golden: Some("start"),
    },
    Corpus {
        name: "data-first",
        bytes: include_bytes!("../../fuzz/corpus/frame/data-first"),
        kind: 7,
        len: 8384,
        header_crc: 0x5BC7_3F60,
        body_crc: 0x5372_B398,
        golden: None,
    },
    Corpus {
        name: "data-final",
        bytes: include_bytes!("../../fuzz/corpus/frame/data-final"),
        kind: 7,
        len: 3818,
        header_crc: 0x012A_6086,
        body_crc: 0xDA88_9EEB,
        golden: None,
    },
    Corpus {
        name: "ack",
        bytes: include_bytes!("../../fuzz/corpus/frame/ack"),
        kind: 8,
        len: 192,
        header_crc: 0xF1D5_0E2D,
        body_crc: 0,
        golden: Some("ack"),
    },
    Corpus {
        name: "complete",
        bytes: include_bytes!("../../fuzz/corpus/frame/complete"),
        kind: 9,
        len: 192,
        header_crc: 0xE47E_F88C,
        body_crc: 0,
        golden: Some("complete"),
    },
    Corpus {
        name: "complete-empty",
        bytes: include_bytes!("../../fuzz/corpus/frame/complete-empty"),
        kind: 9,
        len: 192,
        header_crc: 0x2CF8_0C36,
        body_crc: 0,
        golden: Some("complete empty"),
    },
    Corpus {
        name: "error",
        bytes: include_bytes!("../../fuzz/corpus/frame/error"),
        kind: 10,
        len: 192,
        header_crc: 0x1A83_DBF3,
        body_crc: 0,
        golden: Some("error"),
    },
    Corpus {
        name: "cancel",
        bytes: include_bytes!("../../fuzz/corpus/frame/cancel"),
        kind: 11,
        len: 192,
        header_crc: 0x27B3_653E,
        body_crc: 0,
        golden: Some("cancel"),
    },
    Corpus {
        name: "put-begin",
        bytes: include_bytes!("../../fuzz/corpus/frame/put-begin"),
        kind: 12,
        len: 192,
        header_crc: 0x38A5_5463,
        body_crc: 0,
        golden: Some("put begin"),
    },
    Corpus {
        name: "put-authority",
        bytes: include_bytes!("../../fuzz/corpus/frame/put-authority"),
        kind: 13,
        len: 192,
        header_crc: 0xFBF2_820A,
        body_crc: 0,
        golden: Some("put authority"),
    },
    Corpus {
        name: "put-prepare",
        bytes: include_bytes!("../../fuzz/corpus/frame/put-prepare"),
        kind: 14,
        len: 192,
        header_crc: 0x5BE0_79A3,
        body_crc: 0,
        golden: Some("put prepare"),
    },
    Corpus {
        name: "put-ready",
        bytes: include_bytes!("../../fuzz/corpus/frame/put-ready"),
        kind: 15,
        len: 192,
        header_crc: 0xFD6B_8C93,
        body_crc: 0,
        golden: Some("put ready"),
    },
    Corpus {
        name: "put-data",
        bytes: include_bytes!("../../fuzz/corpus/frame/put-data"),
        kind: 16,
        len: 3818,
        header_crc: 0x43D8_9275,
        body_crc: 0x8913_D420,
        golden: Some("put data final"),
    },
    Corpus {
        name: "put-ack",
        bytes: include_bytes!("../../fuzz/corpus/frame/put-ack"),
        kind: 17,
        len: 192,
        header_crc: 0xFB4A_207C,
        body_crc: 0,
        golden: Some("put ack"),
    },
    Corpus {
        name: "put-result",
        bytes: include_bytes!("../../fuzz/corpus/frame/put-result"),
        kind: 18,
        len: 192,
        header_crc: 0xFCFD_E68A,
        body_crc: 0,
        golden: Some("put result"),
    },
    Corpus {
        name: "put-error",
        bytes: include_bytes!("../../fuzz/corpus/frame/put-error"),
        kind: 19,
        len: 192,
        header_crc: 0x06A8_3FFC,
        body_crc: 0,
        golden: Some("put error"),
    },
    Corpus {
        name: "put-cancel",
        bytes: include_bytes!("../../fuzz/corpus/frame/put-cancel"),
        kind: 20,
        len: 192,
        header_crc: 0x232E_2835,
        body_crc: 0,
        golden: Some("put cancel"),
    },
];

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

fn header_crc_of(bytes: &[u8]) -> u32 {
    let mut covered = bytes[..176].to_vec();
    covered[160..164].fill(0);
    bitwise_crc32c(&covered)
}

/// Each version 2 corpus file keeps its literal length, crcs and fields, and is the version 2 encoding of its golden
/// where the golden's body is the same; `parse` refuses every one as an unknown version, so none reaches
/// authentication or a session.
#[test]
fn version_2_corpus_files_keep_their_literal_fields_and_refuse_as_unknown_versions() {
    let goldens = goldens();
    for file in &CORPUS {
        let name = file.name;
        let bytes = file.bytes;
        assert_eq!(bytes.len(), file.len, "{name}");
        assert_eq!(bytes[..8], *b"IMGNET01", "{name}");
        assert_eq!(bytes[8..10], 2u16.to_be_bytes(), "{name}");
        assert_eq!(bytes[10], file.kind, "{name}");
        assert_eq!(be32(bytes, 16), PRINCIPAL, "{name}");
        assert_eq!(be32(bytes, 20), KEY_EPOCH, "{name}");
        assert_eq!(be32(bytes, 112) as usize, file.len - HEADER_LEN, "{name}");
        assert_eq!(be32(bytes, 160), file.header_crc, "{name}");
        assert_eq!(header_crc_of(bytes), file.header_crc, "{name}");
        assert_eq!(be32(bytes, 164), file.body_crc, "{name}");
        assert_eq!(
            bitwise_crc32c(&bytes[HEADER_LEN..]),
            file.body_crc,
            "{name}"
        );
        assert_eq!(bytes[176..192], PLACEHOLDER, "{name}: placeholder tag");
        assert_eq!(
            parse(crc(), bytes, false).err(),
            Some(FrameError::Version { found: 2 }),
            "{name}"
        );
        if let Some(golden) = file.golden {
            let (_, raw) = goldens
                .iter()
                .find(|(label, _)| *label == golden)
                .expect("a golden");
            let v2 = Raw {
                version: 2,
                ..raw.clone()
            };
            assert_eq!(
                v2.bytes(),
                bytes,
                "{name} equals golden {golden} at version 2"
            );
        }
    }
    assert_eq!(
        CORPUS.iter().filter(|file| file.golden.is_some()).count(),
        19
    );
}

#[test]
fn the_data_corpus_files_carry_their_fragment_fields() {
    for (name, index, offset) in [("v3-data-first", 0u32, 0u64), ("v3-data-final", 2, 16_384)] {
        let bytes = v3(name);
        let header = parse(crc(), &bytes, false).expect("canonical").header();
        assert_eq!(
            (
                header.metadata_len,
                header.body_len,
                header.index,
                header.count,
                header.offset
            ),
            (10, 20_000, index, 3, offset),
            "{name}"
        );
        assert_eq!(header.total, 20_010, "{name}");
    }
}

fn status_frame(kind: u8, status: u16) -> Vec<u8> {
    let mut raw = Raw::get();
    raw.kind = kind;
    raw.status = status;
    raw.metadata = 0;
    raw.body = 0;
    raw.grant = 0;
    raw.remaining = 0;
    raw.bytes()
}

#[test]
fn error_and_cancel_statuses_parse_only_inside_their_ranges() {
    for status in 1..=23u16 {
        let header = parse(crc(), &status_frame(10, status), false)
            .unwrap_or_else(|error| panic!("ERROR {status}: {error:?}"))
            .header();
        assert_eq!(header.status, status);
        assert_eq!(
            Status::from_wire(header.status).map(|s| s as u16),
            Some(status)
        );
    }
    for status in [0, 24] {
        assert_eq!(
            parse(crc(), &status_frame(10, status), false).err(),
            Some(FrameError::Field {
                kind: Kind::Error,
                field: Field::Status
            }),
            "ERROR {status}"
        );
    }
    for status in [17, 18] {
        let header = parse(crc(), &status_frame(11, status), false)
            .unwrap_or_else(|error| panic!("CANCEL {status}: {error:?}"))
            .header();
        assert_eq!(header.status, status);
    }
    for status in (0..=29).filter(|status| !matches!(status, 17 | 18)) {
        assert_eq!(
            parse(crc(), &status_frame(11, status), false).err(),
            Some(FrameError::Field {
                kind: Kind::Cancel,
                field: Field::Status
            }),
            "CANCEL {status}"
        );
    }
}

#[test]
fn put_error_and_put_cancel_statuses_parse_only_inside_their_ranges() {
    for status in 1..=28u16 {
        let frame = status_frame(19, status);
        let header = parse(crc(), &frame, false)
            .unwrap_or_else(|error| panic!("PUT ERROR {status}: {error:?}"))
            .header();
        assert_eq!(header.status, status);
    }
    for status in 24..=28u16 {
        assert_eq!(
            parse(crc(), &status_frame(10, status), false).err(),
            Some(FrameError::Field {
                kind: Kind::Error,
                field: Field::Status
            }),
            "GET's ERROR refuses PUT status {status}"
        );
    }
    for status in [0, 29] {
        assert_eq!(
            parse(crc(), &status_frame(19, status), false).err(),
            Some(FrameError::Field {
                kind: Kind::PutError,
                field: Field::Status
            }),
            "PUT ERROR {status}"
        );
    }
    for status in (0..=29).filter(|status| !matches!(status, 17 | 18)) {
        assert_eq!(
            parse(crc(), &status_frame(20, status), false).err(),
            Some(FrameError::Field {
                kind: Kind::PutCancel,
                field: Field::Status
            }),
            "PUT CANCEL {status}"
        );
    }
}

/// Each PUT corpus file carries the fields its kind requires: BEGIN the authority duration and no serial, every later kind serial 5, PREPARE the time to live, READY and ACK their grants, RESULT a zero duration, and PUT ERROR ConflictingData.
#[test]
fn the_put_corpus_files_carry_their_canonical_fields() {
    let header = |name: &str| {
        parse(crc(), &v3(&format!("v3-{name}")), false)
            .expect("canonical")
            .header()
    };
    let begin = header("put-begin");
    assert_eq!(
        (
            begin.allocation,
            begin.total,
            begin.count,
            begin.grant,
            begin.remaining_ms
        ),
        (0, 0, 0, 0, 30_000)
    );
    assert_eq!(begin.key, [0x07; 32]);
    for name in [
        "put-authority",
        "put-prepare",
        "put-ready",
        "put-data",
        "put-ack",
        "put-result",
        "put-error",
    ] {
        assert_eq!(header(name).allocation, 5, "{name}");
    }
    for name in [
        "put-prepare",
        "put-ready",
        "put-data",
        "put-ack",
        "put-result",
    ] {
        let header = header(name);
        assert_eq!(
            (
                header.metadata_len,
                header.body_len,
                header.total,
                header.count
            ),
            (10, 20_000, 20_010, 3),
            "{name}"
        );
    }
    assert_eq!(header("put-prepare").remaining_ms, 3_600_000);
    assert_eq!(header("put-ready").grant, 3);
    let data = header("put-data");
    assert_eq!(
        (data.index, data.offset, data.datagram_len),
        (2, 16_384, 3626)
    );
    let ack = header("put-ack");
    assert_eq!((ack.index, ack.offset, ack.grant), (0, 0b10, 3));
    assert_eq!(header("put-result").remaining_ms, 0);
    assert_eq!(
        Status::from_wire(header("put-error").status),
        Some(Status::ConflictingData)
    );
    let cancel = header("put-cancel");
    assert_eq!(
        (cancel.allocation, Status::from_wire(cancel.status)),
        (0, Some(Status::Cancelled))
    );
}

/// A PUT RESULT carries no retention horizon: the retained outcome's evidence window stays on the owner, so a nonzero duration rejects.
#[test]
fn a_put_result_with_a_duration_rejects() {
    let mut bytes = v3("v3-put-result");
    bytes[124..128].copy_from_slice(&1u32.to_be_bytes());
    reseal(&mut bytes);
    assert_eq!(
        parse(crc(), &bytes, false).err(),
        Some(FrameError::Field {
            kind: Kind::PutResult,
            field: Field::Remaining
        })
    );
}

const PRIMARY: [u8; 32] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
];
const OTHER: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
];
const STRANGER: u32 = 0x0C0F_FEE0;

/// Version 2 tags under `PRIMARY` and `ENDPOINT` in each frame's own
/// direction, derived outside the crate and named by version 2 corpus file or,
/// for the block-aligned PUT DATA body, by golden.
const TAGGED: [(&str, Direction, [u8; 16]); 15] = [
    (
        "hello",
        Direction::ClientToOwner,
        hex16(b"53da0a5ee1f2184f7cc2a5ac57d12a6e"),
    ),
    (
        "challenge",
        Direction::OwnerToClient,
        hex16(b"6525dbda9d6aea2a640adbcef031c400"),
    ),
    (
        "get",
        Direction::ClientToOwner,
        hex16(b"5c142981554d259f2d71ee3b6d96d38a"),
    ),
    (
        "data-first",
        Direction::OwnerToClient,
        hex16(b"4a06e56b90baf886c21f077599772cff"),
    ),
    (
        "data-final",
        Direction::OwnerToClient,
        hex16(b"73950c579e7438a79a18f0f6d9508a28"),
    ),
    (
        "put-begin",
        Direction::ClientToOwner,
        hex16(b"d0e26511d51a81cb69d996f88ad61dad"),
    ),
    (
        "put-authority",
        Direction::OwnerToClient,
        hex16(b"e90f8ef96db3abe69ec23ec757c51848"),
    ),
    (
        "put-prepare",
        Direction::ClientToOwner,
        hex16(b"dac199c94ff2d01dccc3735018e22607"),
    ),
    (
        "put-ready",
        Direction::OwnerToClient,
        hex16(b"eafe87d9062d50c4d69bf0cb5037b37b"),
    ),
    (
        "put-data",
        Direction::ClientToOwner,
        hex16(b"d44528d21509876039702fb0b5949470"),
    ),
    (
        "put data first",
        Direction::ClientToOwner,
        hex16(b"23ac785f851d5e1bd7d7914ec14497b7"),
    ),
    (
        "put-ack",
        Direction::OwnerToClient,
        hex16(b"23940bd58e1a6cc1d4931d4cb4de833f"),
    ),
    (
        "put-result",
        Direction::OwnerToClient,
        hex16(b"d3a0e750bc20a16b3a633f47873c41eb"),
    ),
    (
        "put-error",
        Direction::OwnerToClient,
        hex16(b"eeadd607873d1ae0bbeb394190e28307"),
    ),
    (
        "put-cancel",
        Direction::ClientToOwner,
        hex16(b"544d7a1a4be56f672bdd8e5ac0cde814"),
    ),
];

const fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => panic!("a lowercase hex digit"),
    }
}

const fn hex16(text: &[u8; 32]) -> [u8; 16] {
    let mut out = [0; 16];
    let mut at = 0;
    while at < 16 {
        out[at] = nibble(text[2 * at]) << 4 | nibble(text[2 * at + 1]);
        at += 1;
    }
    out
}

fn ring(peers: &[(u32, &[u8; 32])], epoch: u32) -> KeyRing {
    let principals: Vec<u32> = peers.iter().map(|(principal, _)| *principal).collect();
    let entries: Vec<KeyEntry<'_>> = peers
        .iter()
        .map(|(principal, key)| KeyEntry {
            principal: *principal,
            key: &key[..],
        })
        .collect();
    KeyRing::load(
        &principals,
        &entries,
        epoch,
        &mut EngineBudget::new(1 << 20),
    )
    .expect("a ring")
}

/// The bytes of the golden `name`.
fn golden(name: &str) -> Option<Vec<u8>> {
    goldens()
        .into_iter()
        .find(|(label, _)| *label == name)
        .map(|(_, raw)| raw.bytes())
}

/// The version 2 corpus file `name`, or the version 2 encoding of the golden
/// `name` when no corpus file has it, carrying `tag`.
fn tagged(name: &str, tag: [u8; 16]) -> Vec<u8> {
    let mut bytes = CORPUS
        .iter()
        .find(|file| file.name == name)
        .map(|file| file.bytes.to_vec())
        .or_else(|| {
            goldens()
                .into_iter()
                .find(|(label, _)| *label == name)
                .map(|(_, raw)| Raw { version: 2, ..raw }.bytes())
        })
        .expect("a corpus file or golden");
    bytes[176..192].copy_from_slice(&tag);
    bytes
}

/// The key every version 3 vector's tag is computed under, for principal
/// [`PRINCIPAL`] at [`KEY_EPOCH`] and endpoint [`ENDPOINT`].
const V3_KEY: [u8; 32] = [0x11; 32];

/// Each version 2 frame carrying its fixed tag refuses as an unknown version at
/// parse, so no key ring authenticates it, though each tag is the HMAC under
/// `PRIMARY` of the frame's header and its covered body: the whole body, or for
/// DATA the body's digest under the session's data key. The same bytes recast
/// to version 3 parse.
#[test]
fn fixed_version_2_tags_refuse_before_authentication() {
    let primary = ring(&[(PRINCIPAL, &PRIMARY)], KEY_EPOCH);
    for (name, direction, tag) in TAGGED {
        let bytes = tagged(name, tag);
        assert_eq!(bytes[8..10], 2u16.to_be_bytes(), "{name}");
        let (head, body) = bytes.split_first_chunk::<HEADER_LEN>().expect("a header");
        let mut digest = [0; 16];
        let input = if head[10] == Kind::Data as u8 {
            primary
                .mac_input(
                    PeerId(0),
                    head,
                    [body, &[]],
                    (ENDPOINT, direction),
                    &mut digest,
                )
                .expect("a DATA MAC input")
        } else {
            super::frame::MacInput {
                endpoint: ENDPOINT,
                direction,
                header: head[..176].try_into().expect("176 header bytes"),
                body: [body, &[]],
            }
        };
        assert_eq!(primary.tag(PeerId(0), &input), Some(tag), "{name}");
        assert_eq!(
            parse(crc(), &bytes, false).err(),
            Some(FrameError::Version { found: 2 }),
            "{name}"
        );
        let mut recast = bytes.clone();
        recast[8..10].copy_from_slice(&3u16.to_be_bytes());
        reseal(&mut recast);
        if let Err(error) = parse(crc(), &recast, false) {
            panic!("{name}: {error:?}");
        }
    }
}

fn flipped(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut edited = bytes.to_vec();
    edited[at] ^= 0x01;
    edited
}

fn swapped(direction: Direction) -> Direction {
    match direction {
        Direction::ClientToOwner => Direction::OwnerToClient,
        Direction::OwnerToClient => Direction::ClientToOwner,
    }
}

/// Version 3 vector `bytes` with its tag: a non-DATA vector's fixed tag as
/// stored, and a DATA vector, which stores the placeholder, sealed under
/// `ring`'s key for peer 0 at [`ENDPOINT`] in its kind's direction.
fn signed(ring: &KeyRing, mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes[10] == Kind::Data as u8 {
        assert_eq!(bytes[176..192], PLACEHOLDER);
        let (head, body) = bytes.split_first_chunk::<HEADER_LEN>().expect("a header");
        let mut digest = [0; 16];
        let input = ring
            .mac_input(
                PeerId(0),
                head,
                [body, &[]],
                (ENDPOINT, Direction::OwnerToClient),
                &mut digest,
            )
            .expect("a DATA MAC input");
        let tag = ring.tag(PeerId(0), &input).expect("a ring peer");
        bytes[176..192].copy_from_slice(&tag);
    }
    bytes
}

/// `bytes` with five body bytes changed so that the body's crc stays the same,
/// at the first body offset where the changed frame parses and passes its body
/// crc, so that the tag alone tells the changed body from the vector's; `None`
/// when no offset yields such a frame.
fn body_altered(bytes: &[u8]) -> Option<Vec<u8>> {
    (HEADER_LEN..bytes.len().saturating_sub(4)).find_map(|at| {
        let mut altered = bytes.to_vec();
        crc_preserving_flip(&mut altered, at);
        parse(crc(), &altered, false)
            .is_ok_and(|frame| frame.check_body(crc()).is_ok())
            .then_some(altered)
    })
}

/// Every version 3 vector's tag, the fixed tag of each non-DATA vector and the
/// sealed tag of each DATA vector, verifies under its key, principal, key
/// epoch, endpoint and direction, and under no other: another key, direction,
/// endpoint, header bit or tag bit fails the tag, and so does a body changed
/// under the same crc, for each vector whose changed body parses; a ring at
/// any other key epoch refuses the frame's key epoch, and the peer of another
/// principal is refused for the principal before the key epoch.
#[test]
fn fixed_tags_verify_only_under_their_key_principal_and_direction() {
    let primary = ring(&[(PRINCIPAL, &V3_KEY)], KEY_EPOCH);
    let foreign = ring(&[(PRINCIPAL, &OTHER)], KEY_EPOCH);
    let other_epochs = [KEY_EPOCH + 1, KEY_EPOCH - 1, 0, u32::MAX]
        .map(|epoch| (epoch, ring(&[(PRINCIPAL, &V3_KEY)], epoch)));
    let two = ring(&[(STRANGER, &OTHER), (PRINCIPAL, &V3_KEY)], KEY_EPOCH);
    let two_later = ring(&[(STRANGER, &OTHER), (PRINCIPAL, &V3_KEY)], KEY_EPOCH + 1);
    // Of the vectors that carry a body: whether each one judged with a changed body is DATA, and the ones no
    // changed body of which parses and passes its body crc.
    let (mut body_judged, mut body_unparsed) = (Vec::new(), Vec::new());
    for (name, bytes) in super::frame::tests::vectors() {
        let data = bytes[10] == Kind::Data as u8;
        let bytes = signed(&primary, bytes);
        let frame = parse(crc(), &bytes, false).expect("canonical");
        assert_eq!(
            (frame.header().principal, frame.header().key_epoch),
            (PRINCIPAL, KEY_EPOCH),
            "{name}"
        );
        let direction = frame.header().kind.direction();
        assert!(
            primary
                .authenticate(&frame, PeerId(0), ENDPOINT, direction)
                .is_ok(),
            "{name}"
        );
        assert!(
            two.authenticate(&frame, PeerId(1), ENDPOINT, direction)
                .is_ok(),
            "{name}"
        );
        let refused = |result: Result<_, AuthError>| result.err();
        assert_eq!(
            refused(foreign.authenticate(&frame, PeerId(0), ENDPOINT, direction)),
            Some(AuthError::Tag),
            "{name}: other key"
        );
        assert_eq!(
            refused(primary.authenticate(&frame, PeerId(0), ENDPOINT, swapped(direction))),
            Some(AuthError::Tag),
            "{name}: swapped direction"
        );
        assert_eq!(
            refused(primary.authenticate(&frame, PeerId(0), ENDPOINT + 1, direction)),
            Some(AuthError::Tag),
            "{name}: other endpoint"
        );
        assert_eq!(
            refused(two.authenticate(&frame, PeerId(0), ENDPOINT, direction)),
            Some(AuthError::Principal {
                principal: PRINCIPAL
            }),
            "{name}: wrong peer"
        );
        assert_eq!(
            refused(two_later.authenticate(&frame, PeerId(0), ENDPOINT, direction)),
            Some(AuthError::Principal {
                principal: PRINCIPAL
            }),
            "{name}: wrong peer at another key epoch"
        );
        for (epoch, other) in &other_epochs {
            assert_eq!(
                refused(other.authenticate(&frame, PeerId(0), ENDPOINT, direction)),
                Some(AuthError::KeyEpoch { found: KEY_EPOCH }),
                "{name}: a ring at key epoch {epoch}"
            );
        }
        let mut tampered = bytes.clone();
        tampered[64] ^= 1;
        reseal(&mut tampered);
        let edited = parse(crc(), &tampered, false).expect("resealed");
        assert_eq!(
            refused(primary.authenticate(&edited, PeerId(0), ENDPOINT, direction)),
            Some(AuthError::Tag),
            "{name}: tampered header"
        );
        let tag_edit = flipped(&bytes, 191);
        let tag_flipped =
            parse(crc(), &tag_edit, false).expect("the tag lies outside the header crc");
        assert_eq!(
            refused(primary.authenticate(&tag_flipped, PeerId(0), ENDPOINT, direction)),
            Some(AuthError::Tag),
            "{name}: tampered tag"
        );
        if bytes.len() > HEADER_LEN {
            let Some(body_edit) = body_altered(&bytes) else {
                body_unparsed.push(name);
                continue;
            };
            body_judged.push(data);
            let body_changed = parse(crc(), &body_edit, false).expect("the body crc holds");
            assert_eq!(
                refused(primary.authenticate(&body_changed, PeerId(0), ENDPOINT, direction)),
                Some(AuthError::Tag),
                "{name}: a body changed under the same crc"
            );
        }
    }
    assert!(
        body_judged.contains(&true) && body_judged.contains(&false),
        "a DATA vector and a vector of another kind are each judged with a changed body"
    );
    assert_eq!(
        body_unparsed,
        ["v3-challenge", "v3-confirm", "v3-hello"],
        "parse refuses every changed body of the HELLO, CHALLENGE and CONFIRM vectors alone"
    );
}

/// Body splits the two-slice MAC input is checked at: every
/// `SPLIT_STRIDE` bytes and the end. The prime stride lands splits at
/// varied offsets within the hash's 64-byte blocks.
const SPLIT_STRIDE: usize = 1021;

/// The golden PUT DATA first fragment, an 8192-byte body at index 0 of 3,
/// carrying its tag under [`V3_KEY`] toward the owner, computed outside the
/// crate with a standard HMAC-SHA256 over the domain block, the header's first
/// 176 bytes and the whole body.
fn tagged_put_data_first() -> (&'static str, Vec<u8>) {
    let mut bytes = golden("put data first").expect("the golden");
    bytes[176..192].copy_from_slice(&hex16(b"e6628bfc837048e93ea74f39805999b7"));
    ("golden put data first", bytes)
}

/// A fixed PUT tag covers the whole body.
/// The same tag computes from the body in two slices split every
/// `SPLIT_STRIDE` bytes and at the end, and from two empty slices for an
/// empty body.
#[test]
fn a_fixed_put_tag_covers_every_body_byte() {
    let primary = ring(&[(PRINCIPAL, &V3_KEY)], KEY_EPOCH);
    let (mut empty, mut bodies) = (0, 0);
    let fixed = super::frame::tests::vectors().into_iter();
    for (name, bytes) in fixed.chain([tagged_put_data_first()]) {
        let frame = parse(crc(), &bytes, false).expect("canonical");
        if !frame.header().kind.is_put() {
            continue;
        }
        let (direction, tag) = (frame.header().kind.direction(), frame.header().tag);
        let body = &bytes[HEADER_LEN..];
        let header = bytes.first_chunk::<HEADER_LEN>().expect("a header");
        let splits = (0..=body.len()).step_by(SPLIT_STRIDE).chain([body.len()]);
        for split in splits {
            let (first, second) = body.split_at(split);
            let input = mac_input_for(header, [first, second], ENDPOINT, direction)
                .expect("the declared body");
            assert_eq!(
                primary.tag(PeerId(0), &input),
                Some(tag),
                "{name} split {split}"
            );
        }
        assert!(
            primary
                .authenticate(&frame, PeerId(0), ENDPOINT, direction)
                .is_ok(),
            "{name}"
        );
        if body.is_empty() {
            empty += 1;
            continue;
        }
        bodies += 1;
        for at in [HEADER_LEN, HEADER_LEN + body.len() / 2, bytes.len() - 1] {
            let edited = flipped(&bytes, at);
            let frame = parse(crc(), &edited, false).expect("the header verifies");
            assert!(frame.check_body(crc()).is_err(), "{name} byte {at}");
            assert_eq!(
                primary
                    .authenticate(&frame, PeerId(0), ENDPOINT, direction)
                    .err(),
                Some(AuthError::Tag),
                "{name} byte {at}"
            );
        }
    }
    assert_eq!(
        (empty, bodies),
        (14, 2),
        "every PUT kind, the versioned BEGIN, the PUT ERROR statuses and the two PUT DATA bodies"
    );
}

/// A GET DATA tag covers its body through the body digest under the session's data key: each DATA vector's sealed tag verifies, and a flipped body byte at the start, middle or end fails the tag before the body crc is read.
#[test]
fn a_sealed_get_data_tag_covers_every_body_byte() {
    let primary = ring(&[(PRINCIPAL, &V3_KEY)], KEY_EPOCH);
    for name in ["v3-data-first", "v3-data-final"] {
        let bytes = signed(&primary, v3(name));
        let frame = parse(crc(), &bytes, false).expect("canonical");
        assert_eq!(frame.header().kind, Kind::Data);
        let direction = frame.header().kind.direction();
        assert!(
            primary
                .authenticate(&frame, PeerId(0), ENDPOINT, direction)
                .is_ok(),
            "{name}"
        );
        let body = bytes.len() - HEADER_LEN;
        for at in [HEADER_LEN, HEADER_LEN + body / 2, bytes.len() - 1] {
            let edited = flipped(&bytes, at);
            let frame = parse(crc(), &edited, false).expect("the header verifies");
            assert_eq!(
                primary
                    .authenticate(&frame, PeerId(0), ENDPOINT, direction)
                    .err(),
                Some(AuthError::Tag),
                "{name} byte {at}"
            );
        }
    }
}

#[test]
fn placeholder_tags_never_authenticate() {
    let primary = ring(&[(PRINCIPAL, &V3_KEY)], KEY_EPOCH);
    for (name, raw) in goldens() {
        assert_eq!(raw.tag, PLACEHOLDER, "{name}");
        let bytes = raw.bytes();
        let frame = parse(crc(), &bytes, false).expect("canonical");
        for direction in [Direction::ClientToOwner, Direction::OwnerToClient] {
            assert!(
                primary
                    .authenticate(&frame, PeerId(0), ENDPOINT, direction)
                    .is_err(),
                "{name}"
            );
        }
    }
}

#[test]
fn each_edit_to_a_fixed_vector_yields_its_own_rejection() {
    let get = &v3("v3-get")[..];
    assert_eq!(parse(crc(), get, true).err(), Some(FrameError::Truncated));
    assert_eq!(
        parse(crc(), &get[..HEADER_LEN - 1], false).err(),
        Some(FrameError::Short {
            len: HEADER_LEN - 1
        })
    );
    let edit = |at: usize, value: u8| {
        let mut bytes = get.to_vec();
        bytes[at] = value;
        reseal(&mut bytes);
        parse(crc(), &bytes, false).err()
    };
    assert_eq!(edit(0, b'X'), Some(FrameError::Magic));
    assert_eq!(edit(9, 1), Some(FrameError::Version { found: 1 }));
    assert_eq!(edit(14, 1), Some(FrameError::Reserved));
    assert_eq!(edit(122, 1), Some(FrameError::Reserved));
    let mut stale = get.to_vec();
    stale[60] ^= 1;
    assert!(matches!(
        parse(crc(), &stale, false),
        Err(FrameError::HeaderCrc {
            stored: 0xDF9A_E0F4,
            ..
        })
    ));
    let data = &v3("v3-data-first")[..];
    let mut body = data.to_vec();
    body[HEADER_LEN] ^= 1;
    let frame = parse(crc(), &body, false).expect("the header verifies");
    assert!(matches!(
        frame.check_body(crc()),
        Err(FrameError::BodyCrc {
            stored: 0x5372_B398,
            ..
        })
    ));
}

/// Every version 3 vector, of every kind, rejects a version field of 1 with
/// its headers otherwise intact, so no frame naming version 1 reaches
/// authentication.
#[test]
fn every_corpus_kind_rejects_version_one() {
    for (name, mut bytes) in super::frame::tests::vectors() {
        bytes[9] = 1;
        reseal(&mut bytes);
        assert_eq!(
            parse(crc(), &bytes, false).err(),
            Some(FrameError::Version { found: 1 }),
            "{name}"
        );
    }
}

fn frames_of(vector: &str) -> Option<Vec<Vec<u8>>> {
    match vector.split_once(' ') {
        Some(("golden", name)) => golden(name).map(|bytes| vec![bytes]),
        Some(("v3", name)) => (super::frame::tests::vectors().into_iter())
            .find(|(vector, _)| *vector == name)
            .map(|(_, bytes)| vec![bytes]),
        _ if vector == ERROR_STATUSES => {
            Some((1..=23).map(|status| status_frame(10, status)).collect())
        }
        _ if vector == CANCEL_STATUSES => Some(
            [17, 18]
                .into_iter()
                .map(|status| status_frame(11, status))
                .collect(),
        ),
        _ if vector == PUT_ERROR_STATUSES => {
            Some((1..=28).map(|status| status_frame(19, status)).collect())
        }
        _ if vector == PUT_CANCEL_STATUSES => Some(
            [17, 18]
                .into_iter()
                .map(|status| status_frame(20, status))
                .collect(),
        ),
        _ => None,
    }
}

fn check_inventory(rows: &[Row]) -> Result<(), String> {
    for kind in 1..=28u8 {
        if !rows.iter().any(|row| row.kind == kind) {
            return Err(format!("kind {kind} has no row"));
        }
    }
    let shapes = [
        "GET zero key",
        "START empty",
        "DATA first",
        "DATA final",
        "DATA exact",
        "DATA two slices",
        "COMPLETE empty",
        "PUT PREPARE empty",
        "PUT READY empty",
        "PUT DATA first",
        "PUT DATA final",
        "PUT DATA exact",
        "PUT DATA two slices",
        "PUT ACK final",
        "PUT RESULT empty",
        "PUT ERROR before authority",
        "PUT BEGIN versioned",
    ];
    for shape in shapes {
        if !rows.iter().any(|row| row.shape == shape) {
            return Err(format!("{shape} has no row"));
        }
    }
    for row in rows {
        let shape = row.shape;
        if row.vectors.is_empty() {
            return Err(format!("{shape} names no vector"));
        }
        for &vector in row.vectors {
            let frames = frames_of(vector).ok_or_else(|| format!("{shape}: no {vector}"))?;
            for bytes in &frames {
                let frame = parse(crc(), bytes, false)
                    .map_err(|error| format!("{shape}: {vector}: {error:?}"))?;
                if frame.header().kind as u8 != row.kind {
                    return Err(format!("{shape}: {vector} is another kind"));
                }
                if !(row.holds)(&frame.header()) {
                    return Err(format!("{shape}: {vector} lacks the shape"));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn the_inventory_names_every_kind_and_shape_by_an_existing_vector() {
    assert_eq!(check_inventory(&INVENTORY), Ok(()));
}

#[test]
fn an_inventory_row_naming_a_vector_of_another_shape_fails_the_check() {
    let swaps: [(&str, &'static [&'static str]); 12] = [
        ("GET zero key", &["golden get"]),
        ("START empty", &["golden start"]),
        ("COMPLETE empty", &["golden complete"]),
        ("DATA first", &["golden data final"]),
        ("DATA final", &["golden data exact"]),
        ("DATA exact", &["golden data final"]),
        ("PUT DATA first", &["golden put data final"]),
        ("PUT DATA final", &["golden put data exact"]),
        ("PUT DATA exact", &["golden put data final"]),
        ("PUT READY empty", &["golden put ready"]),
        ("PUT ACK final", &["golden put ack"]),
        ("PUT ERROR before authority", &["golden put error"]),
    ];
    for (shape, wrong) in swaps {
        let mut rows = INVENTORY;
        rows.iter_mut()
            .find(|row| row.shape == shape)
            .expect("an inventory row")
            .vectors = wrong;
        assert_eq!(
            check_inventory(&rows),
            Err(format!("{shape}: {} lacks the shape", wrong[0])),
            "{shape}"
        );
    }
}
