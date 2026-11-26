//! Codec checks against frames assembled byte by byte at the specification's offsets, with a bitwise crc32c independent of the crate's.

use crate::storage::Crc32c;

use super::datagram::HEADER_LEN;
use super::frame::{
    AUTHENTICATED_LEN, Direction, Field, FrameError, Header, Kind, Status, canonical, checked,
    encode, encode_with_body_crc, mac_input_for, parse, seal,
};

pub(super) use super::frame_reference::bitwise_crc32c;

/// One frame's fields by name, written at literal offsets.
#[derive(Clone)]
pub(super) struct Raw {
    pub(super) version: u16,
    pub(super) kind: u8,
    pub(super) principal: u32,
    pub(super) key_epoch: u32,
    pub(super) owner: [u8; 16],
    pub(super) client: [u8; 16],
    pub(super) request: u64,
    pub(super) sequence: u64,
    pub(super) allocation: u64,
    pub(super) total: u64,
    pub(super) metadata: u32,
    pub(super) body: u32,
    pub(super) index: u32,
    pub(super) count: u32,
    pub(super) offset: u64,
    pub(super) grant: u32,
    pub(super) status: u16,
    pub(super) remaining: u32,
    pub(super) key: [u8; 32],
    pub(super) epoch: u64,
    pub(super) tag: [u8; 16],
    pub(super) payload: Vec<u8>,
}

impl Raw {
    /// A GET of key `0x07..` from a live session.
    pub(super) fn get() -> Self {
        Self {
            version: 3,
            kind: 5,
            principal: 0x0102_0304,
            key_epoch: 9,
            owner: [0xA0; 16],
            client: [0xC0; 16],
            request: 0x0003_0000_0000_0011,
            sequence: 41,
            allocation: 0,
            total: 0,
            metadata: 64,
            body: 1 << 20,
            index: 0,
            count: 0,
            offset: 0,
            grant: 16,
            status: 0,
            remaining: 250,
            key: [0x07; 32],
            epoch: 3,
            tag: [0x5A; 16],
            payload: Vec::new(),
        }
    }

    fn hello() -> Self {
        Self {
            kind: 1,
            owner: [0; 16],
            epoch: 0,
            request: 0,
            metadata: 0,
            body: 0,
            grant: 0,
            remaining: 0,
            key: [0; 32],
            payload: [0, 0, 0, 8, 0, 0, 0, 64].to_vec(),
            ..Self::get()
        }
    }

    pub(super) fn manifest(kind: u8, metadata: u32, body: u32) -> Self {
        let total = u64::from(metadata) + u64::from(body);
        Self {
            kind,
            allocation: 0x0000_0005_0000_0002,
            total,
            metadata,
            body,
            count: total.div_ceil(8192) as u32,
            grant: 0,
            remaining: 0,
            ..Self::get()
        }
    }

    fn data(metadata: u32, body: u32, index: u32) -> Self {
        let total = u64::from(metadata) + u64::from(body);
        let start = u64::from(index) * 8192;
        let len = (total - start).min(8192) as usize;
        Self {
            index,
            offset: start,
            payload: (0..len).map(|n| (n as u8) ^ (index as u8)).collect(),
            ..Self::manifest(7, metadata, body)
        }
    }

    /// A PUT BEGIN for the GET's request and key, asking 30 seconds of authority.
    fn put_begin() -> Self {
        Self {
            kind: 12,
            metadata: 0,
            body: 0,
            grant: 0,
            remaining: 30_000,
            ..Self::get()
        }
    }

    /// A PUT kind after BEGIN carrying fill serial 5 and the manifest of `metadata` and `body` bytes.
    pub(super) fn put(kind: u8, metadata: u32, body: u32) -> Self {
        Self {
            allocation: 5,
            ..Self::manifest(kind, metadata, body)
        }
    }

    /// A PUT ERROR or PUT CANCEL with `status` under `serial`, zero before any authority.
    pub(super) fn put_status(kind: u8, status: u16, serial: u64) -> Self {
        Self {
            kind,
            status,
            allocation: serial,
            ..Self::put(kind, 0, 0)
        }
    }

    fn put_data(metadata: u32, body: u32, index: u32) -> Self {
        Self {
            kind: 16,
            allocation: 5,
            ..Self::data(metadata, body, index)
        }
    }

    pub(super) fn bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; 192];
        out[0..8].copy_from_slice(b"IMGNET01");
        out[8..10].copy_from_slice(&self.version.to_be_bytes());
        out[10] = self.kind;
        out[12..14].copy_from_slice(&192u16.to_be_bytes());
        out[16..20].copy_from_slice(&self.principal.to_be_bytes());
        out[20..24].copy_from_slice(&self.key_epoch.to_be_bytes());
        out[24..40].copy_from_slice(&self.owner);
        out[40..56].copy_from_slice(&self.client);
        out[56..64].copy_from_slice(&self.request.to_be_bytes());
        out[64..72].copy_from_slice(&self.sequence.to_be_bytes());
        out[72..80].copy_from_slice(&self.allocation.to_be_bytes());
        out[80..88].copy_from_slice(&self.total.to_be_bytes());
        out[88..92].copy_from_slice(&self.metadata.to_be_bytes());
        out[92..96].copy_from_slice(&self.body.to_be_bytes());
        out[96..100].copy_from_slice(&self.index.to_be_bytes());
        out[100..104].copy_from_slice(&self.count.to_be_bytes());
        out[104..112].copy_from_slice(&self.offset.to_be_bytes());
        out[112..116].copy_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out[116..120].copy_from_slice(&self.grant.to_be_bytes());
        out[120..122].copy_from_slice(&self.status.to_be_bytes());
        out[124..128].copy_from_slice(&self.remaining.to_be_bytes());
        out[128..160].copy_from_slice(&self.key);
        out[164..168].copy_from_slice(&bitwise_crc32c(&self.payload).to_be_bytes());
        out[168..176].copy_from_slice(&self.epoch.to_be_bytes());
        out[176..192].copy_from_slice(&self.tag);
        let crc = bitwise_crc32c(&out[..176]);
        out[160..164].copy_from_slice(&crc.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// The golden bytes after `edit`, with the header crc over `[0, 176)` recomputed; an edit inside the crc field `[160, 164)` is overwritten.
    pub(super) fn edited(&self, edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut bytes = self.bytes();
        edit(&mut bytes);
        reseal(&mut bytes);
        bytes
    }
}

/// `base` recast as a canonical frame of PUT `kind` and its body, keeping its session and request fields: serial 5 after BEGIN, an empty manifest except PUT DATA's one 100-byte fragment, a one-second duration on BEGIN and PREPARE, and `Cancelled` on the status kinds.
pub(super) fn put_frame(kind: Kind, base: &Header) -> (Header, Vec<u8>) {
    let bare = Header {
        kind,
        allocation: 5,
        total: 0,
        metadata_len: 0,
        body_len: 0,
        index: 0,
        count: 0,
        offset: 0,
        datagram_len: 0,
        grant: 0,
        status: 0,
        remaining_ms: 0,
        ..*base
    };
    let header = match kind {
        Kind::PutBegin => Header {
            allocation: 0,
            remaining_ms: 1_000,
            ..bare
        },
        Kind::PutPrepare => Header {
            remaining_ms: 1_000,
            ..bare
        },
        Kind::PutData => {
            let body = vec![0x3C; 100];
            let header = Header {
                total: 100,
                body_len: 100,
                count: 1,
                datagram_len: 100,
                ..bare
            };
            return (header, body);
        }
        Kind::PutError | Kind::PutCancel => Header {
            status: Status::Cancelled as u16,
            ..bare
        },
        _ => bare,
    };
    (header, Vec::new())
}

pub(super) fn reseal(bytes: &mut [u8]) {
    bytes[160..164].fill(0);
    let crc = bitwise_crc32c(&bytes[..176]);
    bytes[160..164].copy_from_slice(&crc.to_be_bytes());
}

/// Non-DATA `datagram`, sealed under `ring`'s key for `peer` at owner `endpoint` and `direction`, recast to version
/// 2: the version field holds 2, and the header crc and the whole-body tag are recomputed over the recast header, so
/// only the version differs from a canonical, authentic frame.
pub(super) fn recast_to_version_2(
    ring: &super::auth::KeyRing,
    peer: super::datagram::PeerId,
    endpoint: u32,
    datagram: &[u8],
    direction: Direction,
) -> Vec<u8> {
    assert_ne!(
        datagram[10],
        Kind::Data as u8,
        "a DATA tag covers a body digest"
    );
    let mut bytes = datagram.to_vec();
    bytes[8..10].copy_from_slice(&2u16.to_be_bytes());
    reseal(&mut bytes);
    let (head, body) = bytes.split_at(HEADER_LEN);
    let input = super::frame::MacInput {
        endpoint,
        direction,
        header: head[..AUTHENTICATED_LEN].try_into().unwrap(),
        body: [body, &[]],
    };
    let tag = ring.tag(peer, &input).unwrap();
    bytes[AUTHENTICATED_LEN..HEADER_LEN].copy_from_slice(&tag);
    bytes
}

pub(super) fn crc() -> Crc32c {
    Crc32c::detect()
}

/// The READY body of `caps`, shard 7 and `tenure`, or the tenure `(11, 10, 0xa1..)` when `tenure` is `None`.
pub(super) fn ready_body(
    caps: super::session::Caps,
    tenure: Option<super::ownership::Tenure>,
) -> Vec<u8> {
    use super::ownership::{ActivatedEpoch, ReadyBody, Shard, ShardGeneration, Tenure};
    ReadyBody {
        caps,
        shard: Shard::new(7).unwrap(),
        tenure: tenure.unwrap_or(Tenure {
            generation: ShardGeneration::new(11).unwrap(),
            epoch: ActivatedEpoch::new(10).unwrap(),
            host: crate::failover::identity::Exhid::new([0xa1; 16]).unwrap(),
        }),
    }
    .encode()
    .unwrap()
    .to_vec()
}

/// The body of bootstrap step `step`: a READY's [`ready_body`] of the step's caps and tenure, and the caps alone for
/// every other bootstrap kind.
pub(super) fn bootstrap_body(step: &super::session::Bootstrap) -> Vec<u8> {
    if step.kind == Kind::Ready {
        ready_body(step.caps, step.tenure)
    } else {
        step.caps.body().to_vec()
    }
}

/// One golden frame of every kind and shape.
pub(super) fn goldens() -> Vec<(&'static str, Raw)> {
    let mut challenge = Raw::hello();
    challenge.kind = 2;
    challenge.owner = [0xA0; 16];
    challenge.epoch = 1;
    let mut confirm = challenge.clone();
    confirm.kind = 3;
    let mut ready = challenge.clone();
    ready.kind = 4;
    ready.payload = ready_body(
        super::session::Caps {
            slots: 8,
            window: 64,
        },
        None,
    );
    let mut ack = Raw::manifest(8, 10, 20_000);
    ack.index = 2;
    ack.grant = 7;
    let mut gap = Raw::manifest(8, 10, 20_000);
    gap.index = 0;
    gap.grant = 7;
    gap.offset = 0b10;
    let mut complete = Raw::manifest(9, 10, 20_000);
    complete.index = complete.count;
    let mut error = Raw::get();
    error.kind = 10;
    error.status = 1;
    error.metadata = 0;
    error.body = 0;
    error.grant = 0;
    error.remaining = 0;
    let mut cancel = error.clone();
    cancel.kind = 11;
    cancel.status = 18;
    let mut empty_complete = Raw::manifest(9, 0, 0);
    empty_complete.index = 0;
    let mut zero_key = Raw::get();
    zero_key.key = [0; 32];
    let mut prepare = Raw::put(14, 10, 20_000);
    prepare.remaining = 3_600_000;
    let mut empty_prepare = Raw::put(14, 0, 0);
    empty_prepare.remaining = 1;
    let mut put_ready = Raw::put(15, 10, 20_000);
    put_ready.grant = 3;
    let mut put_ack = Raw::put(17, 10, 20_000);
    put_ack.offset = 0b10;
    put_ack.grant = 3;
    let mut final_put_ack = Raw::put(17, 10, 20_000);
    final_put_ack.index = final_put_ack.count;
    final_put_ack.grant = final_put_ack.count;
    vec![
        ("hello", Raw::hello()),
        ("challenge", challenge),
        ("confirm", confirm),
        ("ready", ready),
        ("get", Raw::get()),
        ("get zero key", zero_key),
        ("start", Raw::manifest(6, 10, 20_000)),
        ("start empty", Raw::manifest(6, 0, 0)),
        ("data first", Raw::data(10, 20_000, 0)),
        ("data final", Raw::data(10, 20_000, 2)),
        ("data exact", Raw::data(0, 16_384, 1)),
        ("ack", ack),
        ("ack holding fragment 2", gap),
        ("complete", complete),
        ("complete empty", empty_complete),
        ("error", error),
        ("cancel", cancel),
        ("put begin", Raw::put_begin()),
        ("put authority", Raw::put(13, 0, 0)),
        ("put prepare", prepare),
        ("put prepare empty", empty_prepare),
        ("put ready", put_ready),
        ("put ready empty", Raw::put(15, 0, 0)),
        ("put data first", Raw::put_data(10, 20_000, 0)),
        ("put data final", Raw::put_data(10, 20_000, 2)),
        ("put data exact", Raw::put_data(0, 16_384, 1)),
        ("put ack", put_ack),
        ("put ack final", final_put_ack),
        ("put result", Raw::put(18, 10, 20_000)),
        ("put result empty", Raw::put(18, 0, 0)),
        ("put error", Raw::put_status(19, 28, 5)),
        ("put error before authority", Raw::put_status(19, 25, 0)),
        ("put cancel", Raw::put_status(20, 18, 0)),
    ]
}

/// The bitwise crc32c meets the standard check value, and the crate's crc agrees with it.
#[test]
fn the_reference_crc_meets_the_check_value_and_matches_the_crate() {
    assert_eq!(bitwise_crc32c(b"123456789"), 0xE306_9283);
    for len in [0, 1, 7, 64, 1000] {
        let bytes: Vec<u8> = (0..len).map(|n| (n * 31 + 7) as u8).collect();
        assert_eq!(crc().checksum(&bytes), bitwise_crc32c(&bytes));
    }
}

/// Every golden frame parses to its fields, passes its body crc, and re-encodes to the same bytes, with DATA bodies split across two slices at sampled points and each control body in one slice.
#[test]
fn golden_frames_parse_to_their_fields_and_reencode_identically() {
    for (name, raw) in goldens() {
        let bytes = raw.bytes();
        let frame = parse(crc(), &bytes, false).unwrap_or_else(|error| panic!("{name}: {error:?}"));
        let header = frame.header();
        assert_eq!(header.kind as u8, raw.kind, "{name}");
        assert_eq!(
            (
                header.principal,
                header.key_epoch,
                header.owner_nonce,
                header.client_nonce
            ),
            (raw.principal, raw.key_epoch, raw.owner, raw.client),
            "{name}"
        );
        assert_eq!(
            (
                header.request,
                header.sequence,
                header.allocation,
                header.total
            ),
            (raw.request, raw.sequence, raw.allocation, raw.total),
            "{name}"
        );
        assert_eq!(
            (
                header.metadata_len,
                header.body_len,
                header.index,
                header.count,
                header.offset
            ),
            (raw.metadata, raw.body, raw.index, raw.count, raw.offset),
            "{name}"
        );
        assert_eq!(
            (
                header.grant,
                header.status,
                header.remaining_ms,
                header.key,
                header.epoch,
                header.tag
            ),
            (
                raw.grant,
                raw.status,
                raw.remaining,
                raw.key,
                raw.epoch,
                raw.tag
            ),
            "{name}"
        );
        assert_eq!(frame.check_body(crc()), Ok(&raw.payload[..]), "{name}");
        // A bootstrap control body travels as one slice; other bodies may split anywhere.
        let splits = if raw.payload.is_empty() || (1..=4).contains(&raw.kind) {
            vec![raw.payload.len()]
        } else {
            (0..=raw.payload.len()).step_by(997).collect()
        };
        for split in splits {
            let (first, second) = raw.payload.split_at(split);
            let mut out = [0u8; HEADER_LEN];
            encode(crc(), &header, [first, second], &mut out)
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            assert_eq!(&out[..], &bytes[..HEADER_LEN], "{name} split {split}");
        }
    }
}

/// The branch-light path changes cost, not results: every golden frame, with any one of its bytes up to the first 200 (the header and up to 8 body bytes) replaced and then resealed, parses exactly as the checks in the processing order parse it, and the branch-light check accepts it exactly when the ordered checks do, so no canonical frame falls back to them.
#[test]
fn parsing_matches_the_ordered_checks_on_every_single_byte_edit() {
    let crc = crc();
    for (name, raw) in goldens() {
        let golden = raw.bytes();
        for at in 0..golden.len().min(HEADER_LEN + 8) {
            for value in [0x00, 0x01, 0x80, 0xFF, golden[at] ^ 0x01] {
                let mut bytes = golden.clone();
                bytes[at] = value;
                reseal(&mut bytes);
                let fast = parse(crc, &bytes, false).map(|frame| frame.header());
                let ordered = checked(crc, &bytes, false).map(|frame| frame.header());
                assert_eq!(fast, ordered, "{name} byte {at} = {value:#04x}");
                let (head, body) = bytes.split_first_chunk::<HEADER_LEN>().unwrap();
                assert_eq!(
                    canonical(head, body),
                    ordered.ok().map(|header| header.kind),
                    "the branch-light path takes exactly what the ordered checks accept: {name} byte {at} = {value:#04x}"
                );
            }
        }
    }
}

/// Every length below the header fails `Short`, and the receive's truncation flag fails first at any length.
#[test]
fn every_truncation_below_the_header_is_short_and_the_truncation_flag_wins() {
    let bytes = Raw::get().bytes();
    for len in 0..HEADER_LEN {
        assert_eq!(
            parse(crc(), &bytes[..len], false).err(),
            Some(FrameError::Short { len })
        );
    }
    assert_eq!(
        parse(crc(), &bytes, true).err(),
        Some(FrameError::Truncated)
    );
    assert_eq!(
        parse(crc(), &bytes[..10], true).err(),
        Some(FrameError::Truncated)
    );
}

/// The fixed fields fail in order: magic, header length, version, kind, flags, then each reserved field; a frame whose version field holds 1 or 2 fails at the version, after the magic and header length.
#[test]
fn fixed_field_faults_fail_in_the_processing_order() {
    let raw = Raw::get();
    let cases: Vec<(Vec<u8>, FrameError)> = vec![
        (raw.edited(|b| b[0] = b'X'), FrameError::Magic),
        (
            raw.edited(|b| b[13] = 191),
            FrameError::HeaderLen { found: 191 },
        ),
        (
            raw.edited(|b| {
                b[13] = 0;
                b[9] = 1
            }),
            FrameError::HeaderLen { found: 0 },
        ),
        (raw.edited(|b| b[9] = 1), FrameError::Version { found: 1 }),
        (raw.edited(|b| b[9] = 2), FrameError::Version { found: 2 }),
        (
            raw.edited(|b| {
                b[9] = 2;
                b[10] = 29
            }),
            FrameError::Version { found: 2 },
        ),
        (
            raw.edited(|b| b[8] = 1),
            FrameError::Version { found: 0x0103 },
        ),
        (raw.edited(|b| b[10] = 0), FrameError::Kind { found: 0 }),
        (raw.edited(|b| b[10] = 29), FrameError::Kind { found: 29 }),
        (
            raw.edited(|b| b[10] = 0xFF),
            FrameError::Kind { found: 0xFF },
        ),
        (raw.edited(|b| b[11] = 1), FrameError::Flags { found: 1 }),
        (raw.edited(|b| b[14] = 1), FrameError::Reserved),
        (raw.edited(|b| b[15] = 1), FrameError::Reserved),
        (raw.edited(|b| b[122] = 1), FrameError::Reserved),
        (raw.edited(|b| b[123] = 1), FrameError::Reserved),
        (
            raw.edited(|b| b[11] = 0x80),
            FrameError::Flags { found: 0x80 },
        ),
        (
            raw.edited(|b| {
                b[9] = 1;
                b[160] ^= 1
            }),
            FrameError::Version { found: 1 },
        ),
    ];
    for (bytes, expected) in cases {
        assert_eq!(parse(crc(), &bytes, false).err(), Some(expected));
    }
}

/// A body length field that claims bytes that never arrived fails before any body byte is read, and a header crc fault surfaces only for an otherwise canonical header.
#[test]
fn length_claims_are_checked_against_received_bytes_before_the_crc() {
    let raw = Raw::get();
    let claimed = raw.edited(|b| b[112..116].copy_from_slice(&8192u32.to_be_bytes()));
    assert_eq!(
        parse(crc(), &claimed, false).err(),
        Some(FrameError::DatagramLen {
            declared: 8192,
            received: 0
        })
    );
    let mut extra = raw.bytes();
    extra.push(0);
    assert_eq!(
        parse(crc(), &extra, false).err(),
        Some(FrameError::DatagramLen {
            declared: 0,
            received: 1
        })
    );
    // Stale crcs: the length and field checks come before the header crc.
    let mut stale = raw.bytes();
    stale[116..120].fill(0);
    assert_eq!(
        parse(crc(), &stale, false).err(),
        Some(FrameError::Field {
            kind: Kind::Get,
            field: Field::Grant
        })
    );
    let mut stale = raw.bytes();
    stale[112..116].copy_from_slice(&8192u32.to_be_bytes());
    assert_eq!(
        parse(crc(), &stale, false).err(),
        Some(FrameError::DatagramLen {
            declared: 8192,
            received: 0
        })
    );
    let mut flipped = raw.bytes();
    flipped[60] ^= 1;
    assert!(matches!(
        parse(crc(), &flipped, false),
        Err(FrameError::HeaderCrc { .. })
    ));
    let mut tag = raw.bytes();
    tag[190] ^= 1;
    assert!(
        parse(crc(), &tag, false).is_ok(),
        "the header crc stops before the tag"
    );
    let data = Raw::data(10, 20_000, 1).bytes();
    let mut body = data.clone();
    body[HEADER_LEN + 5] ^= 1;
    let frame = parse(crc(), &body, false).expect("the header is intact");
    assert!(matches!(
        frame.check_body(crc()),
        Err(FrameError::BodyCrc { .. })
    ));
}

/// Expects `bytes` to fail on `field` of `kind`.
fn fails(bytes: &[u8], kind: Kind, field: Field) {
    assert_eq!(
        parse(crc(), bytes, false).err(),
        Some(FrameError::Field { kind, field }),
        "{kind:?} {field:?}"
    );
}

/// Each zero-required field of the bootstrap, GET, manifest, ERROR and CANCEL kinds fails when set, and the nonce, epoch, grant, remaining, cap and status fields fail when out of range.
#[test]
fn every_constrained_field_of_every_kind_is_checked() {
    let set = |raw: &Raw, at: usize, len: usize| raw.edited(|b| b[at + len - 1] = 1);
    let bootstrap = [
        (1u8, Kind::Hello),
        (2, Kind::Challenge),
        (3, Kind::Confirm),
        (4, Kind::Ready),
    ];
    for (code, kind) in bootstrap {
        let mut raw = goldens()[usize::from(code - 1)].1.clone();
        raw.kind = code;
        for (at, len, field) in [
            (56, 8, Field::Request),
            (72, 8, Field::Allocation),
            (80, 8, Field::Total),
            (88, 4, Field::MetadataLen),
            (92, 4, Field::BodyLen),
            (96, 4, Field::Index),
            (100, 4, Field::Count),
            (104, 8, Field::Offset),
            (116, 4, Field::Grant),
            (120, 2, Field::Status),
            (124, 4, Field::Remaining),
            (128, 32, Field::Key),
        ] {
            fails(&set(&raw, at, len), kind, field);
        }
        if kind == Kind::Ready {
            continue;
        }
        let mut long = raw.clone();
        long.payload.push(0);
        fails(&long.bytes(), kind, Field::DatagramLen);
        for (body, field) in [
            ([0, 0, 0, 0, 0, 0, 0, 1], Field::SlotCap),
            ([0, 1, 0, 1, 0, 0, 0, 1], Field::SlotCap),
            ([0, 0, 0, 1, 0, 0, 0, 0], Field::WindowCap),
            ([0, 0, 0, 1, 0, 0, 0x10, 1], Field::WindowCap),
        ] {
            let mut capped = raw.clone();
            capped.payload = body.to_vec();
            fails(&capped.bytes(), kind, field);
        }
        let mut caps = raw.clone();
        caps.payload = [0, 1, 0, 0, 0, 0, 0x10, 0].to_vec();
        assert!(
            parse(crc(), &caps.bytes(), false).is_ok(),
            "65536 slots and 4096 fragments are the caps"
        );
    }
    let hello = Raw::hello();
    fails(&set(&hello, 24, 16), Kind::Hello, Field::OwnerNonce);
    fails(&set(&hello, 168, 8), Kind::Hello, Field::Epoch);
    let get = Raw::get();
    fails(
        &get.edited(|b| b[24..40].fill(0)),
        Kind::Get,
        Field::OwnerNonce,
    );
    fails(
        &get.edited(|b| b[40..56].fill(0)),
        Kind::Get,
        Field::ClientNonce,
    );
    fails(
        &get.edited(|b| b[168..176].fill(0)),
        Kind::Get,
        Field::Epoch,
    );
    for (at, len, field) in [
        (72, 8, Field::Allocation),
        (80, 8, Field::Total),
        (96, 4, Field::Index),
        (100, 4, Field::Count),
        (104, 8, Field::Offset),
        (120, 2, Field::Status),
    ] {
        fails(&set(&get, at, len), Kind::Get, field);
    }
    for grant in [0u32, 4097] {
        fails(
            &get.edited(|b| b[116..120].copy_from_slice(&grant.to_be_bytes())),
            Kind::Get,
            Field::Grant,
        );
    }
    for grant in [1u32, 4096] {
        let bytes = get.edited(|b| b[116..120].copy_from_slice(&grant.to_be_bytes()));
        assert!(parse(crc(), &bytes, false).is_ok(), "grant {grant}");
    }
    fails(
        &get.edited(|b| b[124..128].fill(0)),
        Kind::Get,
        Field::Remaining,
    );
    let mut with_body = get.clone();
    with_body.payload = vec![1];
    fails(&with_body.bytes(), Kind::Get, Field::DatagramLen);
    for (code, kind) in [(6u8, Kind::Start), (9, Kind::Complete), (8, Kind::Ack)] {
        let mut raw = Raw::manifest(code, 10, 20_000);
        if code == 9 {
            raw.index = raw.count;
        }
        fails(
            &raw.edited(|b| b[80..88].copy_from_slice(&20_011u64.to_be_bytes())),
            kind,
            Field::Total,
        );
        fails(
            &raw.edited(|b| b[100..104].copy_from_slice(&4u32.to_be_bytes())),
            kind,
            Field::Count,
        );
        if code == 8 {
            // Bit 2 of the mask names fragment 3, the count.
            fails(
                &raw.edited(|b| b[104..112].copy_from_slice(&4u64.to_be_bytes())),
                kind,
                Field::Offset,
            );
            let held = raw.edited(|b| b[104..112].copy_from_slice(&3u64.to_be_bytes()));
            assert!(parse(crc(), &held, false).is_ok(), "fragments 1 and 2 held");
            let mut final_ack = raw.clone();
            final_ack.index = raw.count;
            fails(&set(&final_ack, 104, 8), kind, Field::Offset);
        } else {
            fails(&set(&raw, 104, 8), kind, Field::Offset);
        }
        fails(&set(&raw, 124, 4), kind, Field::Remaining);
        fails(&set(&raw, 120, 2), kind, Field::Status);
        let mut body = raw.clone();
        body.payload = vec![0];
        fails(&body.bytes(), kind, Field::DatagramLen);
        if code != 8 {
            fails(&set(&raw, 116, 4), kind, Field::Grant);
        }
    }
    fails(
        &set(&Raw::manifest(6, 10, 20_000), 96, 4),
        Kind::Start,
        Field::Index,
    );
    let mut early = Raw::manifest(9, 10, 20_000);
    early.index = 2;
    fails(&early.bytes(), Kind::Complete, Field::Index);
    let mut past = Raw::manifest(8, 10, 20_000);
    past.index = 4;
    fails(&past.bytes(), Kind::Ack, Field::Index);
    for (code, kind, status) in [
        (10u8, Kind::Error, 0u16),
        (10, Kind::Error, 24),
        (11, Kind::Cancel, 1),
        (11, Kind::Cancel, 0),
    ] {
        let mut raw = goldens()[15].1.clone();
        raw.kind = code;
        raw.status = status;
        fails(&raw.bytes(), kind, Field::Status);
    }
    for (code, kind) in [(10u8, Kind::Error), (11, Kind::Cancel)] {
        let mut raw = goldens()[15].1.clone();
        raw.kind = code;
        raw.status = 17;
        assert!(parse(crc(), &raw.bytes(), false).is_ok());
        for (at, len, field) in [
            (72, 8, Field::Allocation),
            (80, 8, Field::Total),
            (88, 4, Field::MetadataLen),
            (92, 4, Field::BodyLen),
            (96, 4, Field::Index),
            (100, 4, Field::Count),
            (104, 8, Field::Offset),
            (116, 4, Field::Grant),
            (124, 4, Field::Remaining),
        ] {
            fails(&set(&raw, at, len), kind, field);
        }
    }
}

/// A frame with two faults reports the first in its kind's check order, so the order is part of the contract.
#[test]
fn a_frame_with_two_faults_reports_the_first_in_order() {
    let set = |bytes: &mut Vec<u8>, at: usize| bytes[at] = 1;
    let mut error = goldens()[15].1.clone();
    error.metadata = 1;
    error.grant = 1;
    let mut cancel = goldens()[16].1.clone();
    cancel.status = 1;
    cancel.grant = 1;
    let cases: Vec<(Vec<u8>, Kind, Field)> = vec![
        (
            Raw::get().edited(|b| {
                b[40..56].fill(0);
                b[121] = 1;
            }),
            Kind::Get,
            Field::ClientNonce,
        ),
        (
            Raw::hello().edited(|b| {
                set(b, 63);
                set(b, 119);
            }),
            Kind::Hello,
            Field::Request,
        ),
        (
            Raw::get().edited(|b| {
                set(b, 79);
                b[116..120].fill(0);
            }),
            Kind::Get,
            Field::Allocation,
        ),
        (
            Raw::manifest(6, 10, 20_000).edited(|b| {
                set(b, 111);
                set(b, 99);
            }),
            Kind::Start,
            Field::Offset,
        ),
        (
            {
                let mut complete = Raw::manifest(9, 10, 20_000);
                complete.index = complete.count;
                complete.edited(|b| {
                    set(b, 127);
                    set(b, 119);
                })
            },
            Kind::Complete,
            Field::Remaining,
        ),
        (
            Raw::manifest(8, 10, 20_000).edited(|b| {
                set(b, 111);
                b[96..100].copy_from_slice(&9u32.to_be_bytes());
            }),
            Kind::Ack,
            Field::Offset,
        ),
        (
            Raw::data(10, 20_000, 0).edited(|b| {
                set(b, 127);
                b[96..100].copy_from_slice(&9u32.to_be_bytes());
            }),
            Kind::Data,
            Field::Remaining,
        ),
        (error.bytes(), Kind::Error, Field::MetadataLen),
        (cancel.bytes(), Kind::Cancel, Field::Status),
        (
            Raw::put(14, 10, 20_000).edited(|b| {
                b[72..80].fill(0);
                b[80..88].copy_from_slice(&1u64.to_be_bytes());
            }),
            Kind::PutPrepare,
            Field::Allocation,
        ),
        (
            {
                let mut ack = Raw::put(17, 10, 20_000);
                ack.grant = 4;
                ack.offset = 0b1000;
                ack.bytes()
            },
            Kind::PutAck,
            Field::Grant,
        ),
        (
            {
                let mut ack = Raw::put(17, 10, 20_000);
                ack.index = 4;
                ack.grant = 4;
                ack.bytes()
            },
            Kind::PutAck,
            Field::Index,
        ),
        (
            Raw::put_begin().edited(|b| {
                set(b, 79);
                b[124..128].fill(0);
            }),
            Kind::PutBegin,
            Field::Allocation,
        ),
    ];
    for (bytes, kind, field) in cases {
        assert_eq!(
            parse(crc(), &bytes, false).err(),
            Some(FrameError::Field { kind, field }),
            "{kind:?}"
        );
    }
}

/// DATA fragments: index below the count; a wrong offset fails on the first and last fragments, including `u64::MAX`; 8192 bytes except an exact final remainder; and a count overflow.
#[test]
fn data_fragments_match_their_manifest() {
    let first = Raw::data(10, 20_000, 0);
    let last = Raw::data(10, 20_000, 2);
    assert!(parse(crc(), &first.bytes(), false).is_ok());
    assert!(parse(crc(), &last.bytes(), false).is_ok());
    for offset in [8192u64, 16_384 + 1, u64::MAX] {
        fails(
            &last.edited(|b| b[104..112].copy_from_slice(&offset.to_be_bytes())),
            Kind::Data,
            Field::Offset,
        );
    }
    fails(
        &first.edited(|b| b[104..112].copy_from_slice(&u64::MAX.to_be_bytes())),
        Kind::Data,
        Field::Offset,
    );
    let mut beyond = last.clone();
    beyond.index = 3;
    beyond.offset = 3 * 8192;
    fails(&beyond.bytes(), Kind::Data, Field::Index);
    let mut short = first.clone();
    short.payload.pop();
    fails(&short.bytes(), Kind::Data, Field::DatagramLen);
    let mut long = last.clone();
    long.payload.push(0);
    fails(&long.bytes(), Kind::Data, Field::DatagramLen);
    let mut empty = Raw::data(10, 20_000, 0);
    empty.metadata = 0;
    empty.body = 0;
    empty.total = 0;
    empty.count = 0;
    empty.payload.clear();
    fails(&empty.bytes(), Kind::Data, Field::Index);
    let mut huge = Raw::manifest(6, u32::MAX, u32::MAX);
    huge.count = u32::MAX;
    fails(&huge.bytes(), Kind::Start, Field::Count);
    let mut largest = Raw::manifest(6, u32::MAX, u32::MAX);
    largest.count = (2 * u64::from(u32::MAX)).div_ceil(8192) as u32;
    assert!(parse(crc(), &largest.bytes(), false).is_ok());
    for grant in [1u32, 9] {
        let mut data = first.clone();
        data.grant = grant;
        fails(&data.bytes(), Kind::Data, Field::Grant);
    }
    let mut remaining = first.clone();
    remaining.remaining = 5;
    fails(&remaining.bytes(), Kind::Data, Field::Remaining);
    let mut status = first.clone();
    status.status = 1;
    fails(&status.bytes(), Kind::Data, Field::Status);
}

/// The encoder refuses a header with a kind constraint fault and a slice total other than the declared body length, and leaves its output untouched in both cases.
#[test]
fn the_encoder_refuses_noncanonical_headers() {
    let bytes = Raw::get().bytes();
    let get = parse(crc(), &bytes, false).unwrap();
    let header = get.header();
    let mut out = [0xEEu8; HEADER_LEN];
    let mut bad = header;
    bad.grant = 0;
    assert_eq!(
        encode(crc(), &bad, [&[], &[]], &mut out),
        Err(FrameError::Field {
            kind: Kind::Get,
            field: Field::Grant
        })
    );
    assert_eq!(
        encode(crc(), &header, [b"x", &[]], &mut out),
        Err(FrameError::DatagramLen {
            declared: 0,
            received: 1
        })
    );
    assert_eq!(out, [0xEE; HEADER_LEN]);
}

/// The MAC input is the 16-byte domain block, the header's first 176 bytes and the covered body: the whole body of every kind but DATA, empty for a kind whose body is empty, and for DATA a body digest under its session's data key, which neither builder makes.
#[test]
fn the_mac_input_is_the_domain_block_the_header_and_the_control_body() {
    let hello = Raw::hello().bytes();
    let frame = parse(crc(), &hello, false).unwrap();
    let input = frame
        .mac_input(0x0A0B_0C0D, Direction::ClientToOwner)
        .unwrap();
    assert_eq!(
        input.domain(),
        [0x0A, 0x0B, 0x0C, 0x0D, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(input.header[..], hello[..176]);
    assert_eq!(input.body, [&hello[192..200], &[][..]]);
    let data = Raw::data(10, 20_000, 1).bytes();
    let frame = parse(crc(), &data, false).unwrap();
    assert!(
        frame.mac_input(7, Direction::OwnerToClient).is_none(),
        "a DATA frame's input needs its session's data key"
    );
    let mut ack = Raw::manifest(8, 10, 20_000);
    ack.index = 2;
    ack.grant = 7;
    let ack = ack.bytes();
    let frame = parse(crc(), &ack, false).unwrap();
    let input = frame.mac_input(7, Direction::ClientToOwner).unwrap();
    assert_eq!(input.domain()[..5], [0, 0, 0, 7, 1]);
    assert_eq!(input.body_len(), 0, "an ACK's input covers no body");
    let mut encoded = [0u8; HEADER_LEN];
    encoded.copy_from_slice(&hello[..HEADER_LEN]);
    let built = mac_input_for(
        &encoded,
        [&hello[192..], &[]],
        0x0A0B_0C0D,
        Direction::ClientToOwner,
    )
    .unwrap();
    let mut expected = vec![0x0A, 0x0B, 0x0C, 0x0D, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    expected.extend_from_slice(&hello[..176]);
    expected.extend_from_slice(&hello[192..200]);
    let mut covered = built.domain().to_vec();
    covered.extend_from_slice(built.header);
    covered.extend_from_slice(built.body[0]);
    assert!(built.body[1].is_empty());
    assert_eq!(covered, expected);
    assert_eq!(AUTHENTICATED_LEN, 176);
    assert!(
        mac_input_for(
            &encoded,
            [&hello[192..196], &[]],
            0x0A0B_0C0D,
            Direction::ClientToOwner
        )
        .is_none(),
        "a payload shorter than the declared body is no MAC input"
    );
    let mut data_header = [0u8; HEADER_LEN];
    data_header.copy_from_slice(&data[..HEADER_LEN]);
    assert!(
        mac_input_for(
            &data_header,
            [&data[HEADER_LEN..], &[]],
            7,
            Direction::OwnerToClient,
        )
        .is_none(),
        "an encoded DATA header's input needs its session's data key"
    );
    let put = Raw::put_data(10, 20_000, 2).bytes();
    let frame = parse(crc(), &put, false).unwrap();
    let input = frame.mac_input(7, Direction::ClientToOwner).unwrap();
    assert_eq!(
        input.body,
        [&put[HEADER_LEN..], &[][..]],
        "a PUT body is covered whole"
    );
    let mut put_header = [0u8; HEADER_LEN];
    put_header.copy_from_slice(&put[..HEADER_LEN]);
    let (first, second) = put[HEADER_LEN..].split_at(1000);
    let split = mac_input_for(&put_header, [first, second], 7, Direction::ClientToOwner).unwrap();
    assert_eq!(
        split.body,
        [first, second],
        "a PUT body is covered in its slices"
    );
    assert!(
        mac_input_for(&put_header, [first, &[]], 7, Direction::ClientToOwner).is_none(),
        "a PUT body shorter than its declared length is no MAC input"
    );
    let begin = Raw::put_begin().bytes();
    let mut begin_header = [0u8; HEADER_LEN];
    begin_header.copy_from_slice(&begin);
    assert!(
        mac_input_for(&begin_header, [&[1], &[]], 7, Direction::ClientToOwner).is_none(),
        "a bodiless PUT kind covers no stray byte"
    );
    let header = parse(crc(), &hello, false).unwrap().header();
    let mut out = [0u8; HEADER_LEN];
    assert_eq!(
        encode(
            crc(),
            &header,
            [&hello[192..196], &hello[196..200]],
            &mut out
        ),
        Err(FrameError::Field {
            kind: Kind::Hello,
            field: Field::DatagramLen
        }),
        "a control body travels as one slice"
    );
}

/// Sealing writes the tag into an encoded header and leaves the bytes the header crc and the MAC cover unchanged.
#[test]
fn sealing_writes_only_the_tag() {
    let bytes = Raw::get().bytes();
    let header = parse(crc(), &bytes, false).unwrap().header();
    let mut out = [0u8; HEADER_LEN];
    encode(crc(), &header, [&[], &[]], &mut out).unwrap();
    let covered = out[..AUTHENTICATED_LEN].to_vec();
    seal(&mut out, [0x33; 16]);
    assert_eq!(&out[..AUTHENTICATED_LEN], &covered[..]);
    let sealed = parse(crc(), &out, false).expect("still canonical");
    assert_eq!(sealed.header().tag, [0x33; 16]);
}

/// Parse, body check and encode allocate nothing.
#[test]
fn parse_and_encode_allocate_nothing() {
    let frames: Vec<Vec<u8>> = goldens().iter().map(|(_, raw)| raw.bytes()).collect();
    let crc = crc();
    let mut out = [0u8; HEADER_LEN];
    let allocations = crate::instrument::allocations();
    for bytes in &frames {
        let frame = parse(crc, bytes, false).unwrap();
        let body = frame.check_body(crc).unwrap();
        encode(crc, &frame.header(), [body, &[]], &mut out).unwrap();
    }
    assert_eq!(crate::instrument::allocations(), allocations);
}

/// Status codes round-trip, only 1 through 28 name a status, and only 1 through 23 are GET's.
#[test]
fn statuses_cover_one_through_twenty_eight() {
    assert_eq!(Status::from_wire(0), None);
    assert_eq!(Status::from_wire(29), None);
    assert_eq!(Status::from_wire(u16::MAX), None);
    for code in 1..=28u16 {
        let status = Status::from_wire(code).expect("a listed status");
        assert_eq!(status as u16, code);
        assert_eq!(status.is_get(), code <= 23, "{status:?}");
    }
}

/// The goldens of kinds 1 through 20 parse with their wire numbers, every kind keeps its wire number from 1 through 28, and 0 and 29 through 255 reject as kinds, so the kind set is closed; 12 through 20 are the PUT kinds.
#[test]
fn kinds_cover_one_through_twenty_eight() {
    let mut seen = [false; 21];
    for (name, raw) in goldens() {
        let kind = parse(crc(), &raw.bytes(), false)
            .unwrap_or_else(|error| panic!("{name}: {error:?}"))
            .header()
            .kind;
        assert_eq!(kind as u8, raw.kind, "{name}");
        assert_eq!(kind.is_put(), (12..=20).contains(&raw.kind), "{name}");
        seen[usize::from(raw.kind)] = true;
    }
    assert!(seen[1..].iter().all(|&seen| seen), "a golden of every kind");
    let raw = Raw::get();
    for kind in (0..=255u8).filter(|kind| !(1..=28).contains(kind)) {
        assert_eq!(
            parse(crc(), &raw.edited(|b| b[10] = kind), false).err(),
            Some(FrameError::Kind { found: kind })
        );
    }
    for (kind, code) in Kind::ALL.into_iter().zip(1u8..) {
        assert_eq!(kind as u8, code);
    }
}

/// Each zero-required field of every PUT kind fails when set; every PUT kind after BEGIN fails on a zero serial, except PUT ERROR and PUT CANCEL, which take a zero serial before any authority; BEGIN, whose offset field carries its cache version, fails on a nonzero allocation and a zero authority duration, and PREPARE on a zero time to live.
#[test]
fn every_constrained_field_of_every_put_kind_is_checked() {
    let set = |raw: &Raw, at: usize, len: usize| raw.edited(|b| b[at + len - 1] = 1);
    let named = |name: &str| {
        goldens()
            .into_iter()
            .find(|(label, _)| *label == name)
            .expect("a golden")
            .1
    };
    let lengths = [
        (80, 8, Field::Total),
        (88, 4, Field::MetadataLen),
        (92, 4, Field::BodyLen),
    ];
    let begin = Raw::put_begin();
    for (at, len, field) in [
        (72, 8, Field::Allocation),
        (80, 8, Field::Total),
        (88, 4, Field::MetadataLen),
        (92, 4, Field::BodyLen),
        (96, 4, Field::Index),
        (100, 4, Field::Count),
        (116, 4, Field::Grant),
        (120, 2, Field::Status),
    ] {
        fails(&set(&begin, at, len), Kind::PutBegin, field);
    }
    fails(
        &begin.edited(|b| b[124..128].fill(0)),
        Kind::PutBegin,
        Field::Remaining,
    );
    let mut long = begin.clone();
    long.payload = vec![0];
    fails(&long.bytes(), Kind::PutBegin, Field::DatagramLen);
    let authority = named("put authority");
    for (at, len, field) in lengths.into_iter().chain([
        (96, 4, Field::Index),
        (100, 4, Field::Count),
        (104, 8, Field::Offset),
        (116, 4, Field::Grant),
        (120, 2, Field::Status),
        (124, 4, Field::Remaining),
    ]) {
        fails(&set(&authority, at, len), Kind::PutAuthority, field);
    }
    let prepare = named("put prepare");
    for (at, len, field) in [
        (96, 4, Field::Index),
        (104, 8, Field::Offset),
        (116, 4, Field::Grant),
        (120, 2, Field::Status),
    ] {
        fails(&set(&prepare, at, len), Kind::PutPrepare, field);
    }
    fails(
        &prepare.edited(|b| b[124..128].fill(0)),
        Kind::PutPrepare,
        Field::Remaining,
    );
    let ready = named("put ready");
    for (at, len, field) in [
        (96, 4, Field::Index),
        (104, 8, Field::Offset),
        (120, 2, Field::Status),
        (124, 4, Field::Remaining),
    ] {
        fails(&set(&ready, at, len), Kind::PutReady, field);
    }
    let result = named("put result");
    for (at, len, field) in [
        (96, 4, Field::Index),
        (104, 8, Field::Offset),
        (116, 4, Field::Grant),
        (120, 2, Field::Status),
        (124, 4, Field::Remaining),
    ] {
        fails(&set(&result, at, len), Kind::PutResult, field);
    }
    let data = named("put data final");
    for (at, len, field) in [
        (116, 4, Field::Grant),
        (120, 2, Field::Status),
        (124, 4, Field::Remaining),
    ] {
        fails(&set(&data, at, len), Kind::PutData, field);
    }
    let ack = named("put ack");
    for (at, len, field) in [(120, 2, Field::Status), (124, 4, Field::Remaining)] {
        fails(&set(&ack, at, len), Kind::PutAck, field);
    }
    for (code, kind) in [(19u8, Kind::PutError), (20, Kind::PutCancel)] {
        let raw = Raw::put_status(code, 18, 0);
        assert!(
            parse(crc(), &raw.bytes(), false).is_ok(),
            "{kind:?} before authority"
        );
        let raw = Raw::put_status(code, 18, 5);
        assert!(
            parse(crc(), &raw.bytes(), false).is_ok(),
            "{kind:?} under a serial"
        );
        for (at, len, field) in lengths.into_iter().chain([
            (96, 4, Field::Index),
            (100, 4, Field::Count),
            (104, 8, Field::Offset),
            (116, 4, Field::Grant),
            (124, 4, Field::Remaining),
        ]) {
            fails(&set(&raw, at, len), kind, field);
        }
        let mut body = raw.clone();
        body.payload = vec![0];
        fails(&body.bytes(), kind, Field::DatagramLen);
    }
    for (name, kind) in [
        ("put authority", Kind::PutAuthority),
        ("put prepare", Kind::PutPrepare),
        ("put ready", Kind::PutReady),
        ("put data final", Kind::PutData),
        ("put ack", Kind::PutAck),
        ("put result", Kind::PutResult),
    ] {
        fails(
            &named(name).edited(|b| b[72..80].fill(0)),
            kind,
            Field::Allocation,
        );
        let mut body = named(name);
        if kind != Kind::PutData {
            body.payload = vec![0];
            fails(&body.bytes(), kind, Field::DatagramLen);
        }
    }
}

/// The PUT kinds that carry a manifest refuse a total other than the lengths' sum and a count other than the total's fragment count; PUT DATA keeps DATA's fragment rules, including the 8192-byte cap on a fragment.
#[test]
fn put_manifests_and_fragments_match_their_lengths() {
    let named = |name: &str| {
        goldens()
            .into_iter()
            .find(|(label, _)| *label == name)
            .expect("a golden")
            .1
    };
    for (name, kind) in [
        ("put prepare", Kind::PutPrepare),
        ("put ready", Kind::PutReady),
        ("put data final", Kind::PutData),
        ("put ack", Kind::PutAck),
        ("put result", Kind::PutResult),
    ] {
        let raw = named(name);
        fails(
            &raw.edited(|b| b[80..88].copy_from_slice(&20_011u64.to_be_bytes())),
            kind,
            Field::Total,
        );
        for count in [2u32, 4] {
            fails(
                &raw.edited(|b| b[100..104].copy_from_slice(&count.to_be_bytes())),
                kind,
                Field::Count,
            );
        }
    }
    let mut largest = Raw::put(14, u32::MAX, u32::MAX);
    largest.remaining = 1;
    assert!(
        parse(crc(), &largest.bytes(), false).is_ok(),
        "the largest lengths"
    );
    let mut huge = largest.clone();
    huge.count = u32::MAX;
    fails(&huge.bytes(), Kind::PutPrepare, Field::Count);
    let first = Raw::put_data(10, 20_000, 0);
    let mut over = first.clone();
    over.payload.push(0);
    fails(&over.bytes(), Kind::PutData, Field::DatagramLen);
    let mut short = Raw::put_data(10, 20_000, 2);
    short.payload.pop();
    fails(&short.bytes(), Kind::PutData, Field::DatagramLen);
    fails(
        &first.edited(|b| b[104..112].copy_from_slice(&8192u64.to_be_bytes())),
        Kind::PutData,
        Field::Offset,
    );
    let mut beyond = Raw::put_data(10, 20_000, 2);
    beyond.index = 3;
    beyond.offset = 3 * 8192;
    fails(&beyond.bytes(), Kind::PutData, Field::Index);
    let mut empty = Raw::put_data(0, 0, 0);
    empty.payload.clear();
    fails(&empty.bytes(), Kind::PutData, Field::Index);
}

/// PUT READY's and PUT ACK's cumulative grant runs from the receipt base to the count and at most 4096 fragments past the base, and a PUT ACK's receipt mask names only fragments below the grant.
#[test]
fn put_grants_and_receipt_masks_stay_within_their_bounds() {
    let mut big_ready = Raw::put(15, 0, 4096 * 8192 + 1);
    for grant in [0u32, 1, 4096] {
        big_ready.grant = grant;
        assert!(
            parse(crc(), &big_ready.bytes(), false).is_ok(),
            "grant {grant}"
        );
    }
    big_ready.grant = 4097;
    fails(&big_ready.bytes(), Kind::PutReady, Field::Grant);
    let mut ready = Raw::put(15, 10, 20_000);
    ready.grant = 4;
    fails(&ready.bytes(), Kind::PutReady, Field::Grant);
    let mut empty = Raw::put(15, 0, 0);
    empty.grant = 1;
    fails(&empty.bytes(), Kind::PutReady, Field::Grant);
    let ack = |base: u32, grant: u32, mask: u64| {
        let mut raw = Raw::put(17, 0, 5000 * 8192);
        raw.index = base;
        raw.grant = grant;
        raw.offset = mask;
        parse(crc(), &raw.bytes(), false).map(|frame| frame.header())
    };
    let refused = |field| {
        Err(FrameError::Field {
            kind: Kind::PutAck,
            field,
        })
    };
    assert!(ack(0, 0, 0).is_ok());
    assert!(ack(10, 10, 0).is_ok());
    assert!(ack(10, 4106, 0).is_ok());
    assert!(ack(5000, 5000, 0).is_ok(), "every fragment received");
    assert_eq!(
        ack(10, 9, 0),
        refused(Field::Grant),
        "a grant below the base"
    );
    assert_eq!(ack(10, 4107, 0), refused(Field::Grant), "past the window");
    assert_eq!(ack(4999, 5001, 0), refused(Field::Grant), "past the count");
    assert_eq!(
        ack(5001, 5001, 0),
        refused(Field::Index),
        "a base past the count"
    );
    // Bit 1 names fragment 2, the last below a grant of 3.
    assert!(ack(0, 3, 0b10).is_ok());
    assert_eq!(ack(0, 3, 0b100), refused(Field::Offset));
    assert_eq!(ack(0, 0, 1), refused(Field::Offset));
    assert_eq!(ack(5000, 5000, 1), refused(Field::Offset));
    assert!(
        ack(0, 100, u64::MAX).is_ok(),
        "64 fragments below the grant"
    );
}

/// Every golden with 1 in its version field fails at the version check, after the magic and header length, and the encoder writes version 3 into every header.
#[test]
fn version_one_frames_fail_after_magic_and_header_length() {
    for (name, raw) in goldens() {
        let old = Raw {
            version: 1,
            ..raw.clone()
        }
        .bytes();
        assert_eq!(
            parse(crc(), &old, false).err(),
            Some(FrameError::Version { found: 1 }),
            "{name}"
        );
        assert_eq!(
            checked(crc(), &old, false).err(),
            Some(FrameError::Version { found: 1 }),
            "{name}"
        );
        let mut bad_magic = old.clone();
        bad_magic[0] = b'J';
        reseal(&mut bad_magic);
        assert_eq!(
            parse(crc(), &bad_magic, false).err(),
            Some(FrameError::Magic)
        );
        let mut bad_len = old.clone();
        bad_len[13] = 0;
        reseal(&mut bad_len);
        assert_eq!(
            parse(crc(), &bad_len, false).err(),
            Some(FrameError::HeaderLen { found: 0 })
        );
        let bytes = raw.bytes();
        let header = parse(crc(), &bytes, false).expect("canonical").header();
        let mut out = [0u8; HEADER_LEN];
        encode(crc(), &header, [&raw.payload, &[]], &mut out).expect("canonical");
        assert_eq!(out[8..10], [0, 3], "{name}");
    }
}

/// Every PUT frame recast from a GET encodes canonically, PUT DATA with its body.
#[test]
fn put_frames_recast_from_a_get_are_canonical() {
    let bytes = Raw::get().bytes();
    let get = parse(crc(), &bytes, false).unwrap().header();
    for kind in Kind::ALL.into_iter().filter(|kind| kind.is_put()) {
        let (header, body) = put_frame(kind, &get);
        let mut out = [0u8; HEADER_LEN];
        encode(crc(), &header, [&body, &[]], &mut out).unwrap_or_else(|error| panic!("{error:?}"));
        let mut datagram = out.to_vec();
        datagram.extend_from_slice(&body);
        assert_eq!(parse(crc(), &datagram, false).unwrap().header().kind, kind);
    }
}

/// The encoder refuses every PUT header the parser refuses, leaving its output untouched: a zero serial, a TTL of zero, a grant past the count and a GET status on PUT CANCEL.
#[test]
fn the_encoder_refuses_noncanonical_put_headers() {
    let header_of = |raw: &Raw| {
        parse(crc(), &raw.bytes(), false)
            .expect("canonical")
            .header()
    };
    let mut prepare = Raw::put(14, 10, 20_000);
    prepare.remaining = 1;
    let prepare = header_of(&prepare);
    let ready = header_of(&Raw::put(15, 10, 20_000));
    let cancel = header_of(&Raw::put_status(20, 18, 0));
    let cases = [
        (
            Header {
                allocation: 0,
                ..prepare
            },
            Kind::PutPrepare,
            Field::Allocation,
        ),
        (
            Header {
                remaining_ms: 0,
                ..prepare
            },
            Kind::PutPrepare,
            Field::Remaining,
        ),
        (Header { grant: 4, ..ready }, Kind::PutReady, Field::Grant),
        (
            Header {
                status: 1,
                ..cancel
            },
            Kind::PutCancel,
            Field::Status,
        ),
    ];
    for (header, kind, field) in cases {
        let mut out = [0xEEu8; HEADER_LEN];
        assert_eq!(
            encode(crc(), &header, [&[], &[]], &mut out),
            Err(FrameError::Field { kind, field })
        );
        assert_eq!(out, [0xEE; HEADER_LEN]);
    }
}

/// A header carrying `raw`'s fields, its datagram length the payload's.
pub(super) fn header_of(raw: &Raw) -> Header {
    Header {
        kind: Kind::ALL[usize::from(raw.kind) - 1],
        principal: raw.principal,
        key_epoch: raw.key_epoch,
        owner_nonce: raw.owner,
        client_nonce: raw.client,
        request: raw.request,
        sequence: raw.sequence,
        allocation: raw.allocation,
        total: raw.total,
        metadata_len: raw.metadata,
        body_len: raw.body,
        index: raw.index,
        count: raw.count,
        offset: raw.offset,
        datagram_len: raw.payload.len() as u32,
        grant: raw.grant,
        status: raw.status,
        remaining_ms: raw.remaining,
        key: raw.key,
        epoch: raw.epoch,
        tag: raw.tag,
    }
}

/// The encoder's combined test of the common kinds changes cost, not results: every golden with one constrained field set on either side of its bounds encodes exactly when its bytes parse, to those bytes, and otherwise fails on the field the parser names.
#[test]
fn the_encoder_accepts_exactly_the_headers_the_parser_accepts() {
    let edits: [fn(&mut Raw, u64); 13] = [
        |raw, value| raw.allocation = value,
        |raw, value| raw.total = value,
        |raw, value| raw.metadata = value as u32,
        |raw, value| raw.body = value as u32,
        |raw, value| raw.index = value as u32,
        |raw, value| raw.count = value as u32,
        |raw, value| raw.offset = value,
        |raw, value| raw.grant = value as u32,
        |raw, value| raw.status = value as u16,
        |raw, value| raw.remaining = value as u32,
        |raw, value| raw.request = value,
        |raw, value| raw.epoch = value,
        |raw, value| raw.owner = [value as u8; 16],
    ];
    for (name, golden) in goldens() {
        let near = [golden.index, golden.count, golden.grant].map(u64::from);
        let values: Vec<u64> = [0, 1, 2, 17, 18, 23, 24, 28, 29, 4096, 4097, 8192, u64::MAX]
            .into_iter()
            .chain(near.into_iter().flat_map(|at| [at.wrapping_sub(1), at + 1]))
            .collect();
        for (field, edit) in edits.iter().enumerate() {
            for &value in &values {
                let mut raw = golden.clone();
                edit(&mut raw, value);
                let bytes = raw.bytes();
                // A control body travels as one slice; other bodies split at their middle.
                let (first, second) = if (1..=4).contains(&raw.kind) {
                    (&raw.payload[..], &[][..])
                } else {
                    raw.payload.split_at(raw.payload.len() / 2)
                };
                let mut out = [0u8; HEADER_LEN];
                let encoded = encode(crc(), &header_of(&raw), [first, second], &mut out);
                let parsed = parse(crc(), &bytes, false).map(|_| ());
                assert_eq!(encoded, parsed, "{name} field {field} = {value:#x}");
                if encoded.is_ok() {
                    assert_eq!(
                        &out[..],
                        &bytes[..HEADER_LEN],
                        "{name} field {field} = {value:#x}"
                    );
                }
                // The zeroed buffers expose a difference in output bytes even when both encoders return the same error.
                let mut supplied = [0u8; HEADER_LEN];
                let with_crc = encode_with_body_crc(
                    crc(),
                    &header_of(&raw),
                    [first, second],
                    bitwise_crc32c(&raw.payload),
                    &mut supplied,
                );
                assert_eq!(
                    (with_crc, &supplied[..]),
                    (encoded, &out[..]),
                    "{name} field {field} = {value:#x}"
                );
            }
        }
    }
}

/// Every golden frame encodes, with its body split at the start, after one byte, at the middle and at the end, into a header placed at every alignment within a 16-byte line, to the bytes assembled with the bitwise crc, parses from every alignment to its own fields and body, and with the low bit of any one sequence byte flipped parses to a header crc refusal whose computed value is the bitwise crc of the flipped bytes.
fn every_golden_header_encodes_and_parses_as_the_bitwise_crc() {
    let crc = crc();
    let goldens = goldens();
    let longest = goldens
        .iter()
        .map(|(_, raw)| raw.bytes().len())
        .max()
        .unwrap();
    let mut line = vec![0u8; 16 + longest];
    for (name, raw) in goldens {
        let golden = raw.bytes();
        let header = parse(crc, &golden, false)
            .unwrap_or_else(|error| panic!("{name}: {error:?}"))
            .header();
        let splits = if raw.payload.is_empty() || (1..=4).contains(&raw.kind) {
            vec![raw.payload.len()]
        } else {
            vec![0, 1, raw.payload.len() / 2, raw.payload.len()]
        };
        for at in 0..16 {
            for &split in &splits {
                let (first, second) = raw.payload.split_at(split);
                let out = line[at..].first_chunk_mut::<HEADER_LEN>().unwrap();
                out.fill(0xA5);
                encode(crc, &header, [first, second], out)
                    .unwrap_or_else(|error| panic!("{name}: {error:?}"));
                assert_eq!(
                    &out[..],
                    &golden[..HEADER_LEN],
                    "{name} at {at} split {split}"
                );
            }
            let placed = &mut line[at..at + golden.len()];
            placed.copy_from_slice(&golden);
            let frame = parse(crc, placed, false)
                .unwrap_or_else(|error| panic!("{name} at {at}: {error:?}"));
            assert_eq!(frame.header(), header, "{name} at {at}");
            assert_eq!(
                frame.check_body(crc),
                Ok(&raw.payload[..]),
                "{name} at {at}"
            );
        }
        for flip in 64..72 {
            let mut bytes = golden.clone();
            bytes[flip] ^= 0x01;
            let stored = u32::from_be_bytes(bytes[160..164].try_into().unwrap());
            let mut zeroed = bytes[..AUTHENTICATED_LEN].to_vec();
            zeroed[160..164].fill(0);
            let computed = bitwise_crc32c(&zeroed);
            assert_eq!(
                parse(crc, &bytes, false).map(|frame| frame.header()),
                Err(FrameError::HeaderCrc { stored, computed }),
                "{name} byte {flip}"
            );
        }
    }
}

/// The aarch64 lane fold computes every golden frame's header crc on encode and on parse; on a host without `crc` and `aes` the fold reports itself unreached.
#[test]
fn the_lane_fold_encodes_and_parses_every_golden_header_as_the_bitwise_crc() {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    witness(
        "crc-lanes",
        detected!(aarch64: "crc", "aes"),
        || runs(Kernel::CrcLanes),
        every_golden_header_encodes_and_parses_as_the_bitwise_crc,
    );
}

/// The x86_64 chain join computes every golden frame's header crc on encode and on parse; on a host without `sse4.2` and `pclmulqdq` the join reports itself unreached.
#[test]
fn the_chain_join_encodes_and_parses_every_golden_header_as_the_bitwise_crc() {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    witness(
        "crc-chains",
        detected!(x86_64: "sse4.2", "pclmulqdq"),
        || runs(Kernel::CrcChains),
        every_golden_header_encodes_and_parses_as_the_bitwise_crc,
    );
}

/// The encoded header of `header` as one received datagram.
fn encoded(header: &Header) -> Vec<u8> {
    let mut out = [0u8; HEADER_LEN];
    encode(crc(), header, [&[], &[]], &mut out).unwrap_or_else(|error| panic!("{error:?}"));
    out.to_vec()
}

/// A PUT BEGIN carries the FILL's version big-endian at bytes 104..112, and an INVALIDATE and its acknowledgment carry
/// the interval's low end at 72..80 and its high end at 104..112. Each round-trips through the encoder and the parser,
/// which hosts and the repository client share; the MAC input holds the header bytes that carry the fields, so a
/// changed version or interval fails authentication. A version 2 copy refuses as an unknown version, and an inverted
/// interval, the empty case of an inclusive interval, refuses at parse, so no handler sees it.
#[test]
fn put_begin_version_and_invalidate_kind_vectors() {
    let get = parse(crc(), &Raw::get().bytes(), false).unwrap().header();
    let (begin, _) = put_frame(Kind::PutBegin, &get);
    let begin = Header {
        offset: 0x0102_0304_0506_0708,
        ..begin
    };
    let bytes = encoded(&begin);
    assert_eq!(bytes[104..112], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(parse(crc(), &bytes, false).unwrap().header(), begin);
    let interval = |kind: Kind, low: u64, high: u64| Header {
        kind,
        allocation: low,
        offset: high,
        total: 0,
        metadata_len: 0,
        body_len: 0,
        index: 0,
        count: 0,
        grant: 0,
        remaining_ms: 0,
        ..get
    };
    for kind in [Kind::Invalidate, Kind::Invalidated] {
        let header = interval(kind, 7, 9);
        let bytes = encoded(&header);
        assert_eq!(bytes[72..80], 7u64.to_be_bytes());
        assert_eq!(bytes[104..112], 9u64.to_be_bytes());
        let frame = parse(crc(), &bytes, false).unwrap();
        assert_eq!(frame.header(), header);
        let input = frame.mac_input(7, kind.direction()).unwrap();
        assert_eq!(
            input.header[..],
            bytes[..176],
            "the MAC input holds the interval's fields"
        );
        assert_eq!(
            parse(crc(), &encoded(&interval(kind, 4, 4)), false)
                .unwrap()
                .header(),
            interval(kind, 4, 4)
        );
        let mut inverted = bytes.clone();
        inverted[72..80].copy_from_slice(&10u64.to_be_bytes());
        reseal(&mut inverted);
        fails(&inverted, kind, Field::Offset);
        let mut v2 = bytes.clone();
        v2[8..10].copy_from_slice(&2u16.to_be_bytes());
        reseal(&mut v2);
        assert_eq!(
            parse(crc(), &v2, false).err(),
            Some(FrameError::Version { found: 2 })
        );
        let mut out = [0x5Au8; HEADER_LEN];
        assert_eq!(
            encode(crc(), &interval(kind, 10, 9), [&[], &[]], &mut out).err(),
            Some(FrameError::Field {
                kind,
                field: Field::Offset
            })
        );
        assert_eq!(out, [0x5A; HEADER_LEN], "a refused encode writes nothing");
    }
}
