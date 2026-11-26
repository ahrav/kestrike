//! Tests of the version 3 grammar against the byte-assembled corpus in `fuzz/corpus/frame`: the literal fields of each vector, the exact error of each refusal, and the bytes the MAC covers.

use super::{
    Direction, Field, FrameError, Header, Kind, VERSION, canonical, checked, encode, mac_input_for,
    parse,
};
use crate::failover::identity::{Exhid, MAX_VOLUME_LEN, is_volume};
use crate::net::datagram::HEADER_LEN;
use crate::net::frame_tests::{crc, reseal};
use crate::net::ownership::{
    ActivatedEpoch, OwnershipBody, OwnershipError, ReadyBody, Shard, ShardGeneration, Tenure,
    Validity, Volume, VolumeState,
};
use crate::net::session::Caps;

/// The version 3 vector inventory, one file per kind and shape.
pub(in crate::net) const V3_VECTORS: [&str; 59] = [
    "v3-ack",
    "v3-cancel",
    "v3-challenge",
    "v3-complete",
    "v3-complete-empty",
    "v3-confirm",
    "v3-data-final",
    "v3-data-first",
    "v3-error",
    "v3-error-status-01",
    "v3-error-status-02",
    "v3-error-status-03",
    "v3-error-status-04",
    "v3-error-status-05",
    "v3-error-status-06",
    "v3-error-status-07",
    "v3-error-status-08",
    "v3-error-status-09",
    "v3-error-status-10",
    "v3-error-status-11",
    "v3-error-status-12",
    "v3-error-status-13",
    "v3-error-status-14",
    "v3-error-status-15",
    "v3-error-status-16",
    "v3-error-status-17",
    "v3-error-status-18",
    "v3-error-status-19",
    "v3-error-status-20",
    "v3-error-status-21",
    "v3-error-status-22",
    "v3-error-status-23",
    "v3-get",
    "v3-heartbeat",
    "v3-hello",
    "v3-holder",
    "v3-invalidate",
    "v3-invalidated",
    "v3-probe",
    "v3-probe-reply",
    "v3-put-ack",
    "v3-put-authority",
    "v3-put-begin",
    "v3-put-begin-versioned",
    "v3-put-cancel",
    "v3-put-data",
    "v3-put-error",
    "v3-put-error-status-24",
    "v3-put-error-status-25",
    "v3-put-error-status-26",
    "v3-put-error-status-27",
    "v3-put-error-status-28",
    "v3-put-prepare",
    "v3-put-ready",
    "v3-put-result",
    "v3-ready",
    "v3-start",
    "v3-who-holds",
    "v3-wrong-owner",
];

pub(in crate::net) const CORPUS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus/frame");

pub(in crate::net) fn corpus_names(prefix: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(CORPUS)
        .unwrap_or_else(|error| panic!("{CORPUS}: {error}"))
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with(prefix))
        .collect();
    names.sort();
    names
}

/// Every vector of [`V3_VECTORS`] read from the corpus, after asserting that the corpus holds exactly those `v3-` files.
pub(in crate::net) fn vectors() -> Vec<(&'static str, Vec<u8>)> {
    assert_eq!(corpus_names("v3-"), V3_VECTORS);
    V3_VECTORS
        .iter()
        .map(|&name| {
            let bytes = std::fs::read(format!("{CORPUS}/{name}"))
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            (name, bytes)
        })
        .collect()
}

/// The version 3 vector `name` of [`V3_VECTORS`].
pub(in crate::net) fn vector(name: &str) -> Vec<u8> {
    vectors()
        .into_iter()
        .find(|(vector, _)| *vector == name)
        .unwrap()
        .1
}

const VOLUME: &str = "vol-0123456789abcdef0";
const HOST: [u8; 16] = [0xa1; 16];
const RESPONDER: [u8; 16] = [0xb2; 16];

fn tenure() -> Tenure {
    Tenure {
        generation: ShardGeneration::new(11).unwrap(),
        epoch: ActivatedEpoch::new(10).unwrap(),
        host: Exhid::new(HOST).unwrap(),
    }
}

/// The envelope each ownership vector's bytes spell: shard 7, the tenure `(11, 10, HOST)` where present, responder `RESPONDER` on replies, and per kind the volume, validity bits and Report age.
fn expected(kind: Kind) -> OwnershipBody<'static> {
    let volume = |state| {
        Some(Volume {
            name: VOLUME,
            state,
        })
    };
    let body = |volume, tenure, bits, report_age_us, responder: Option<[u8; 16]>| OwnershipBody {
        shard: Shard::new(7).unwrap(),
        volume,
        tenure,
        report_age_us,
        responder: responder.map(|bytes| Exhid::new(bytes).unwrap()),
        validity: Validity::new(bits).unwrap(),
    };
    let active = volume(VolumeState::Active);
    match kind {
        Kind::WhoHolds => body(None, Some(tenure()), 0, 0, None),
        Kind::Holder => body(active, Some(tenure()), 7, 123, Some(RESPONDER)),
        Kind::WrongOwner => body(
            volume(VolumeState::Retired),
            Some(tenure()),
            4,
            0,
            Some(RESPONDER),
        ),
        Kind::Heartbeat => body(active, Some(tenure()), 3, 123, Some(RESPONDER)),
        Kind::Probe => body(active, Some(tenure()), 0, 0, None),
        Kind::ProbeReply => body(None, None, 0, 0, Some(RESPONDER)),
        _ => unreachable!("only ownership kinds carry an envelope"),
    }
}

/// Every version 3 kind round-trips through its vector: the header re-encodes byte for byte, READY decodes to caps `(8, 64)`, shard 7 and the tenure `(11, 10, HOST)`, and each ownership body decodes to the literal fields of its bytes and re-encodes to them. Kinds 1 to 28 all appear, exactly kinds 12 to 20 are PUT kinds and exactly kinds 21 to 26 are ownership kinds. A reply naming a retired volume with no tenure round-trips with an all-zero tenure.
#[test]
fn v3_vectors_round_trip() {
    let mut seen = [false; 28];
    for (name, bytes) in vectors() {
        let parsed = parse(crc(), &bytes, false).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let kind = parsed.header().kind;
        seen[kind as usize - 1] = true;
        assert_eq!(bytes[8..10], VERSION.to_be_bytes(), "{name}");
        assert_eq!(kind.is_put(), (12..=20).contains(&(kind as u8)), "{name}");
        assert_eq!(
            kind.is_ownership(),
            (21..=26).contains(&(kind as u8)),
            "{name}"
        );
        parsed.check_body(crc()).unwrap();
        let mut out = [0; HEADER_LEN];
        encode(crc(), &parsed.header(), [parsed.raw_body(), &[]], &mut out).unwrap();
        assert_eq!(out, bytes[..HEADER_LEN], "{name}");
        let body = parsed.raw_body();
        if kind == Kind::Ready {
            let ready = ReadyBody::decode(body).unwrap();
            let want = ReadyBody {
                caps: Caps {
                    slots: 8,
                    window: 64,
                },
                shard: Shard::new(7).unwrap(),
                tenure: tenure(),
            };
            assert_eq!(ready, want);
            assert_eq!(ready.encode().unwrap(), body);
        } else if kind.is_ownership() {
            let decoded = OwnershipBody::decode(kind, body).unwrap();
            assert_eq!(decoded, expected(kind), "{name}");
            let mut out = vec![0; decoded.encoded_len()];
            decoded.encode(kind, &mut out).unwrap();
            assert_eq!(out, body, "{name}");
        }
    }
    assert!(seen.into_iter().all(|kind| kind));
    let retired = OwnershipBody {
        volume: Some(Volume {
            name: VOLUME,
            state: VolumeState::Retired,
        }),
        tenure: None,
        validity: Validity::new(Validity::REPORT).unwrap(),
        ..expected(Kind::WrongOwner)
    };
    let mut out = vec![0x5a; retired.encoded_len()];
    retired.encode(Kind::WrongOwner, &mut out).unwrap();
    assert!(out[8..36].iter().all(|&b| b == 0));
    assert_eq!(OwnershipBody::decode(Kind::WrongOwner, &out), Ok(retired));
}

/// Kind 29 and every higher byte are unknown kinds under version 3, and the codec's sources name neither the export body and its length error nor a persistence-profile input.
#[test]
fn no_export_kind() {
    assert!((29..=u8::MAX).all(|byte| Kind::from_wire(byte).is_none()));
    let mut bytes = vector("v3-holder");
    bytes[10] = 29;
    reseal(&mut bytes);
    assert_eq!(
        parse(crc(), &bytes, false).err(),
        Some(FrameError::Kind { found: 29 })
    );
    for source in [include_str!("../ownership.rs"), include_str!("../frame.rs")] {
        for name in ["ExportBody", "ExportUnitTooLarge", "PersistenceProfile"] {
            assert!(!source.contains(name), "{name}");
        }
    }
}

/// A resealed copy of `bytes` whose body `edit` changed, with the datagram length set to the new body length.
pub(in crate::net) fn rebody(bytes: &[u8], edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut body = bytes[HEADER_LEN..].to_vec();
    edit(&mut body);
    let mut out = bytes[..HEADER_LEN].to_vec();
    out[112..116].copy_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    reseal(&mut out);
    out
}

fn refusal(bytes: &[u8]) -> Option<FrameError> {
    parse(crc(), bytes, false).err()
}

fn body_refusal(kind: Kind, error: OwnershipError) -> Option<FrameError> {
    Some(FrameError::Field {
        kind,
        field: Field::Body(error),
    })
}

type Edit = Box<dyn FnOnce(&mut Vec<u8>)>;

/// Unknown kinds, statuses, flags and reserved values, unknown versions (version 2 among them), oversized bodies, each ownership kind's header-field constraints and each malformed ownership or READY body refuse with their exact error. Every vector recast to version 2 refuses as an unknown version and `mac_input_for` yields no input for its header, so parsing yields no frame to act on; the same vector recast back to version 3 parses, so the version field alone refuses it. An encoder that refuses leaves its destination untouched.
#[test]
fn v3_rejects_before_state_change() {
    let base = vector("v3-get");
    for (at, value, want) in [
        (10, 29, FrameError::Kind { found: 29 }),
        (11, 1, FrameError::Flags { found: 1 }),
        (14, 1, FrameError::Reserved),
        (122, 1, FrameError::Reserved),
    ] {
        let mut bytes = base.clone();
        bytes[at] = value;
        reseal(&mut bytes);
        assert_eq!(refusal(&bytes), Some(want));
    }
    let error = vector("v3-error");
    for status in [0u16, 24, 29] {
        let mut bytes = error.clone();
        bytes[120..122].copy_from_slice(&status.to_be_bytes());
        reseal(&mut bytes);
        assert_eq!(
            refusal(&bytes),
            Some(FrameError::Field {
                kind: Kind::Error,
                field: Field::Status
            }),
            "status {status}"
        );
    }
    let data = vector("v3-data-first");
    assert_eq!(data.len(), HEADER_LEN + 8192);
    let oversized = rebody(&data, |body| body.push(0));
    assert_eq!(
        refusal(&oversized),
        Some(FrameError::Field {
            kind: Kind::Data,
            field: Field::DatagramLen
        })
    );
    for found in [0u16, 1, 2, 4, u16::MAX] {
        let mut bytes = vector("v3-holder");
        bytes[8..10].copy_from_slice(&found.to_be_bytes());
        reseal(&mut bytes);
        assert_eq!(refusal(&bytes), Some(FrameError::Version { found }));
    }
    for (name, bytes) in vectors() {
        let kind = Kind::from_wire(bytes[10]).unwrap();
        let mut recast = bytes.clone();
        recast[8..10].copy_from_slice(&2u16.to_be_bytes());
        reseal(&mut recast);
        assert_eq!(
            refusal(&recast),
            Some(FrameError::Version { found: 2 }),
            "{name}"
        );
        let head: &[u8; HEADER_LEN] = recast[..HEADER_LEN].try_into().unwrap();
        let body = &bytes[HEADER_LEN..];
        assert!(
            mac_input_for(head, [body, &[]], 1, kind.direction()).is_none(),
            "{name}"
        );
        recast[8..10].copy_from_slice(&VERSION.to_be_bytes());
        reseal(&mut recast);
        assert!(parse(crc(), &recast, false).is_ok(), "{name}");
        if !kind.is_ownership() {
            continue;
        }
        let header = parse(crc(), &bytes, false).unwrap().header();
        let mut out = [0x5a; HEADER_LEN];
        let (first, second) = body.split_at(1);
        assert_eq!(
            encode(crc(), &header, [first, second], &mut out).err(),
            Some(FrameError::Field {
                kind: header.kind,
                field: Field::DatagramLen
            }),
            "{name}"
        );
        assert!(out.iter().all(|&b| b == 0x5a), "{name}");
    }

    for (name, vector) in vectors()
        .into_iter()
        .filter(|(_, b)| Kind::from_wire(b[10]).is_some_and(Kind::is_ownership))
    {
        let kind = Kind::from_wire(vector[10]).unwrap();
        for (at, len, value, field) in [
            (24, 16, 0, Field::OwnerNonce),
            (168, 8, 0, Field::Epoch),
            (72, 1, 1, Field::Allocation),
            (80, 1, 1, Field::Total),
            (88, 1, 1, Field::MetadataLen),
            (92, 1, 1, Field::BodyLen),
            (96, 1, 1, Field::Index),
            (100, 1, 1, Field::Count),
            (104, 1, 1, Field::Offset),
            (116, 1, 1, Field::Grant),
            (121, 1, 1, Field::Status),
            (124, 1, 1, Field::Remaining),
            (128, 1, 1, Field::Key),
        ] {
            let mut bytes = vector.clone();
            bytes[at..at + len].fill(value);
            reseal(&mut bytes);
            assert_eq!(
                refusal(&bytes),
                Some(FrameError::Field { kind, field }),
                "{name} offset {at}"
            );
        }
    }

    for name in ["v3-invalidate", "v3-invalidated"] {
        let base = vector(name);
        let kind = Kind::from_wire(base[10]).unwrap();
        for (at, field) in [
            (80, Field::Total),
            (88, Field::MetadataLen),
            (92, Field::BodyLen),
            (96, Field::Index),
            (100, Field::Count),
            (116, Field::Grant),
            (124, Field::Remaining),
        ] {
            let mut bytes = base.clone();
            bytes[at] = 1;
            reseal(&mut bytes);
            assert_eq!(
                refusal(&bytes),
                Some(FrameError::Field { kind, field }),
                "{name} offset {at}"
            );
        }
    }

    let holder = vector("v3-holder");
    let who_holds = vector("v3-who-holds");
    let volume_end = OwnershipBody::FIXED_LEN + VOLUME.len();
    let probe_reply = vector("v3-probe-reply");
    let cases: [(&str, &Vec<u8>, Edit, OwnershipError); 24] = [
        (
            "odd epoch",
            &holder,
            Box::new(|b| b[19] = 9),
            OwnershipError::Tenure,
        ),
        (
            "epoch past max",
            &holder,
            Box::new(|b| b[16..20].copy_from_slice(&0xFFFF_FFFEu32.to_be_bytes())),
            OwnershipError::Tenure,
        ),
        (
            "generation 2^32",
            &holder,
            Box::new(|b| b[8..16].copy_from_slice(&(1u64 << 32).to_be_bytes())),
            OwnershipError::Tenure,
        ),
        (
            "report without volume",
            &probe_reply,
            Box::new(|b| b[1] = Validity::REPORT),
            OwnershipError::Flags,
        ),
        (
            "live without tenure",
            &probe_reply,
            Box::new(|b| b[1] = Validity::LIVE),
            OwnershipError::Flags,
        ),
        (
            "reply age",
            &probe_reply,
            Box::new(|b| b[43] = 1),
            OwnershipError::ReportAge,
        ),
        (
            "short",
            &holder,
            Box::new(|b| b.truncate(59)),
            OwnershipError::Length,
        ),
        (
            "past end",
            &holder,
            Box::new(move |b| b.truncate(volume_end - 1)),
            OwnershipError::Length,
        ),
        (
            "trailing",
            &holder,
            Box::new(|b| b.push(b'0')),
            OwnershipError::Length,
        ),
        (
            "flags",
            &holder,
            Box::new(|b| b[1] = 8),
            OwnershipError::Flags,
        ),
        (
            "query flags",
            &who_holds,
            Box::new(|b| b[1] = Validity::LIVE),
            OwnershipError::Flags,
        ),
        (
            "state",
            &holder,
            Box::new(|b| b[2] = 3),
            OwnershipError::Volume,
        ),
        (
            "absent state",
            &who_holds,
            Box::new(|b| b[2] = 1),
            OwnershipError::Volume,
        ),
        (
            "reserved",
            &holder,
            Box::new(|b| b[3] = 1),
            OwnershipError::Reserved,
        ),
        (
            "shard",
            &holder,
            Box::new(|b| b[4..8].fill(0)),
            OwnershipError::Shard,
        ),
        (
            "partial tenure",
            &holder,
            Box::new(|b| b[8..16].fill(0)),
            OwnershipError::Tenure,
        ),
        (
            "epoch",
            &holder,
            Box::new(|b| b[16..20].fill(0xff)),
            OwnershipError::Tenure,
        ),
        (
            "host",
            &holder,
            Box::new(|b| b[20..36].fill(0)),
            OwnershipError::Tenure,
        ),
        (
            "age",
            &who_holds,
            Box::new(|b| b[43] = 1),
            OwnershipError::ReportAge,
        ),
        (
            "no responder",
            &holder,
            Box::new(|b| b[44..60].fill(0)),
            OwnershipError::Responder,
        ),
        (
            "query responder",
            &who_holds,
            Box::new(|b| b[44] = 1),
            OwnershipError::Responder,
        ),
        (
            "utf8",
            &holder,
            Box::new(|b| b[64] = 0xff),
            OwnershipError::Volume,
        ),
        (
            "alphabet",
            &holder,
            Box::new(|b| b[64] = b'g'),
            OwnershipError::Volume,
        ),
        (
            "22 bytes",
            &holder,
            Box::new(|b| {
                b[0] = 22;
                b.push(b'0');
            }),
            OwnershipError::Volume,
        ),
    ];
    for (name, bytes, edit, want) in cases {
        let kind = Kind::from_wire(bytes[10]).unwrap();
        let edited = rebody(bytes, edit);
        assert_eq!(
            OwnershipBody::decode(kind, &edited[HEADER_LEN..]).err(),
            Some(want),
            "{name}"
        );
        assert_eq!(refusal(&edited), body_refusal(kind, want), "{name}");
    }

    let base = OwnershipBody::decode(Kind::Holder, &holder[HEADER_LEN..]).unwrap();
    for name in [
        "vol-",
        "vol-A",
        "vol-a/",
        "vol012",
        "vol-0123456789abcdef01",
    ] {
        let body = OwnershipBody {
            volume: Some(Volume {
                name,
                state: VolumeState::Active,
            }),
            ..base
        };
        let mut out = vec![0x5a; OwnershipBody::FIXED_LEN + name.len()];
        assert_eq!(
            body.encode(Kind::Holder, &mut out),
            Err(OwnershipError::Volume),
            "{name}"
        );
        assert!(out.iter().all(|&b| b == 0x5a), "{name}");
    }
    assert_eq!(MAX_VOLUME_LEN, VOLUME.len());
    let mut out = vec![0x5a; base.encoded_len() + 1];
    assert_eq!(
        base.encode(Kind::Holder, &mut out),
        Err(OwnershipError::Length)
    );
    let mut out = vec![0x5a; base.encoded_len()];
    assert_eq!(
        base.encode(Kind::WhoHolds, &mut out),
        Err(OwnershipError::Flags)
    );
    assert_eq!(base.encode(Kind::Get, &mut out), Err(OwnershipError::Kind));
    assert!(out.iter().all(|&b| b == 0x5a));

    let ready = vector("v3-ready");
    for len in [0, 8, 39, 41] {
        let edited = rebody(&ready, |b| b.resize(len, 0));
        assert_eq!(
            refusal(&edited),
            body_refusal(Kind::Ready, OwnershipError::Length),
            "{len}"
        );
    }
    let cases: [(&str, Edit, OwnershipError); 9] = [
        (
            "unactivated",
            Box::new(|b| b[20..24].fill(0)),
            OwnershipError::Tenure,
        ),
        (
            "slots past cap",
            Box::new(|b| b[0..4].copy_from_slice(&((1u32 << 16) + 1).to_be_bytes())),
            OwnershipError::Caps,
        ),
        (
            "window zero",
            Box::new(|b| b[4..8].fill(0)),
            OwnershipError::Caps,
        ),
        (
            "window past cap",
            Box::new(|b| b[4..8].copy_from_slice(&4097u32.to_be_bytes())),
            OwnershipError::Caps,
        ),
        ("odd epoch", Box::new(|b| b[23] = 9), OwnershipError::Tenure),
        ("caps", Box::new(|b| b[0..4].fill(0)), OwnershipError::Caps),
        (
            "shard",
            Box::new(|b| b[8..12].fill(0)),
            OwnershipError::Shard,
        ),
        (
            "absent tenure",
            Box::new(|b| b[12..40].fill(0)),
            OwnershipError::Tenure,
        ),
        (
            "generation",
            Box::new(|b| b[12..20].fill(0)),
            OwnershipError::Tenure,
        ),
    ];
    for (name, edit, want) in cases {
        let edited = rebody(&ready, edit);
        assert_eq!(refusal(&edited), body_refusal(Kind::Ready, want), "{name}");
    }
    let good = ReadyBody::decode(&ready[HEADER_LEN..]).unwrap();
    for (slots, window) in [(0, 64), ((1 << 16) + 1, 64), (8, 0), (8, 4097)] {
        let caps = Caps { slots, window };
        assert_eq!(
            ReadyBody { caps, ..good }.encode(),
            Err(OwnershipError::Caps)
        );
    }
    let unactivated = Tenure {
        epoch: ActivatedEpoch::new(0).unwrap(),
        ..good.tenure
    };
    assert_eq!(
        ReadyBody {
            tenure: unactivated,
            ..good
        }
        .encode(),
        Err(OwnershipError::Tenure)
    );
}

#[test]
fn v3_fast_and_ordered_parsing_agree_and_the_codec_allocates_nothing() {
    let crc = crc();
    let vectors = vectors();
    for (name, bytes) in &vectors {
        for at in 0..bytes.len() {
            let mut edited = bytes.clone();
            edited[at] ^= 1;
            reseal(&mut edited);
            let fast = parse(crc, &edited, false).map(|f| f.header());
            let ordered = checked(crc, &edited, false).map(|f| f.header());
            assert_eq!(fast, ordered, "{name} byte {at}");
            let (head, body) = edited.split_first_chunk::<HEADER_LEN>().unwrap();
            assert_eq!(
                canonical(head, body),
                ordered.ok().map(|h| h.kind),
                "{name} byte {at}"
            );
        }
    }
    let mut out = [0; HEADER_LEN];
    let allocations = crate::instrument::allocations();
    for (_, bytes) in &vectors {
        let parsed = parse(crc, bytes, false).unwrap();
        encode(crc, &parsed.header(), [parsed.raw_body(), &[]], &mut out).unwrap();
    }
    assert_eq!(crate::instrument::allocations(), allocations);
}

/// The version 3 MAC input covers the whole declared body of every kind but DATA, from both the parsed frame and the sender's slices; both refuse DATA, whose digest input the key ring builds, and WHO HOLDS and PROBE travel client to owner.
#[test]
fn v3_mac_inputs_cover_whole_non_data_bodies_and_data_keeps_its_digest() {
    for (name, bytes) in vectors() {
        let parsed = parse(crc(), &bytes, false).unwrap();
        let direction = parsed.header().kind.direction();
        let encoded = bytes[..HEADER_LEN].try_into().unwrap();
        if parsed.header().kind == Kind::Data {
            assert!(parsed.mac_input(1, direction).is_none());
            assert!(mac_input_for(encoded, [parsed.raw_body(), &[]], 1, direction).is_none());
        } else {
            let input = parsed.mac_input(1, direction).unwrap();
            assert_eq!(input.body_len(), parsed.raw_body().len(), "{name}");
            let sent = mac_input_for(encoded, [parsed.raw_body(), &[]], 1, direction).unwrap();
            assert_eq!(sent.body, input.body);
        }
    }
    assert_eq!(Kind::WhoHolds.direction(), Direction::ClientToOwner);
    assert_eq!(Kind::Probe.direction(), Direction::ClientToOwner);
}

fn edited_bodies() -> Vec<(String, Vec<u8>)> {
    let mut bodies = Vec::new();
    for (name, bytes) in vectors() {
        let kind = Kind::from_wire(bytes[10]).unwrap();
        if !kind.is_ownership() && kind != Kind::Ready {
            continue;
        }
        let body = &bytes[HEADER_LEN..];
        bodies.push((name.to_string(), body.to_vec()));
        for at in 0..body.len() {
            for value in [
                0x00,
                0x01,
                0x02,
                0x04,
                0x08,
                0x2d,
                0x30,
                0x39,
                0x3a,
                0x60,
                0x61,
                0x66,
                0x67,
                0x80,
                0xff,
                body[at] ^ 1,
            ] {
                let mut edited = body.to_vec();
                edited[at] = value;
                bodies.push((format!("{name} byte {at} = {value:#04x}"), edited));
            }
        }
        for len in 0..=body.len() + 2 {
            let mut resized = body.to_vec();
            resized.resize(len, b'0');
            bodies.push((format!("{name} length {len}"), resized));
        }
    }
    bodies
}

#[test]
fn body_admission_and_decoding_match_the_ordered_checks_on_every_edit() {
    let kinds: Vec<Kind> = (1..=26)
        .map(|byte| Kind::from_wire(byte).unwrap())
        .collect();
    for (name, body) in edited_bodies() {
        let ready = ReadyBody::ordered(&body);
        assert_eq!(ReadyBody::decode(&body), ready, "{name}");
        assert_eq!(ReadyBody::admits(&body), ready.is_ok(), "{name}");
        for &kind in &kinds {
            let ordered = OwnershipBody::ordered(kind, &body);
            assert_eq!(
                OwnershipBody::decode(kind, &body),
                ordered,
                "{name} as {kind:?}"
            );
            assert_eq!(
                OwnershipBody::admits(kind, &body),
                ordered.is_ok(),
                "{name} as {kind:?}"
            );
        }
    }
}

fn layout(body: &OwnershipBody<'_>) -> Vec<u8> {
    let mut bytes = vec![0; OwnershipBody::FIXED_LEN];
    if let Some(volume) = body.volume {
        bytes[0] = volume.name.len() as u8;
        bytes[2] = volume.state as u8;
    }
    bytes[1] = body.validity.bits();
    bytes[4..8].copy_from_slice(&body.shard.get().to_be_bytes());
    if let Some(tenure) = body.tenure {
        bytes[8..16].copy_from_slice(&tenure.generation.get().to_be_bytes());
        bytes[16..20].copy_from_slice(&tenure.epoch.get().to_be_bytes());
        bytes[20..36].copy_from_slice(&tenure.host.bytes());
    }
    bytes[36..44].copy_from_slice(&body.report_age_us.to_be_bytes());
    if let Some(responder) = body.responder {
        bytes[44..60].copy_from_slice(&responder.bytes());
    }
    if let Some(volume) = body.volume {
        bytes.extend_from_slice(volume.name.as_bytes());
    }
    bytes
}

#[test]
fn volume_admission_agrees_with_the_identity_grammar_at_every_name_length_and_byte() {
    let base = expected(Kind::Holder);
    for len in 0..=MAX_VOLUME_LEN + 3 {
        let name = format!("vol-{}", "a".repeat(len.saturating_sub(4)))[..len].to_owned();
        let bytes = layout(&OwnershipBody {
            volume: Some(Volume {
                name: &name,
                state: VolumeState::Active,
            }),
            ..base
        });
        for at in 0..len {
            for byte in 0..=u8::MAX {
                let mut edited = bytes.clone();
                edited[OwnershipBody::FIXED_LEN + at] = byte;
                let name = &edited[OwnershipBody::FIXED_LEN..];
                assert_eq!(
                    OwnershipBody::admits(Kind::Holder, &edited),
                    core::str::from_utf8(name).is_ok_and(is_volume),
                    "length {len} byte {at} = {byte:#04x}"
                );
            }
        }
    }
}

#[test]
fn typed_encoders_refuse_exactly_what_decoding_their_bytes_refuses() {
    let names = [
        "vol-0",
        "vol-a",
        VOLUME,
        "vol-",
        "vol-g",
        "VOL-1",
        "vol-0123456789abcdef01",
        "vol-\u{e9}",
    ];
    let mut volumes = vec![None];
    for name in names {
        for state in [VolumeState::Active, VolumeState::Retired] {
            volumes.push(Some(Volume { name, state }));
        }
    }
    let unactivated = Tenure {
        epoch: ActivatedEpoch::new(0).unwrap(),
        ..tenure()
    };
    for kind in (1..=26).map(|byte| Kind::from_wire(byte).unwrap()) {
        for &volume in &volumes {
            for tenure in [None, Some(tenure()), Some(unactivated)] {
                for report_age_us in [0, 123] {
                    for responder in [None, Some(Exhid::new(RESPONDER).unwrap())] {
                        for bits in 0..=Validity::ALL {
                            let body = OwnershipBody {
                                shard: Shard::new(7).unwrap(),
                                volume,
                                tenure,
                                report_age_us,
                                responder,
                                validity: Validity::new(bits).unwrap(),
                            };
                            let bytes = layout(&body);
                            for len in [bytes.len() - 1, bytes.len(), bytes.len() + 1] {
                                let want = if volume.is_some_and(|v| !is_volume(v.name)) {
                                    Err(OwnershipError::Volume)
                                } else if len != bytes.len() {
                                    Err(OwnershipError::Length)
                                } else {
                                    OwnershipBody::decode(kind, &bytes).map(|decoded| {
                                        assert_eq!(decoded, body);
                                    })
                                };
                                let mut out = vec![0x5a; len];
                                assert_eq!(body.encode(kind, &mut out), want, "{body:?} {kind:?}");
                                if want.is_ok() {
                                    assert_eq!(out, bytes);
                                } else {
                                    assert!(out.iter().all(|&b| b == 0x5a));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let caps = [
        (0, 64),
        (1, 1),
        (8, 64),
        (super::MAX_SLOT_CAP, super::MAX_WINDOW),
        (super::MAX_SLOT_CAP + 1, 64),
        (8, super::MAX_WINDOW + 1),
    ];
    for (slots, window) in caps {
        for tenure in [tenure(), unactivated] {
            let ready = ReadyBody {
                caps: Caps { slots, window },
                shard: Shard::new(7).unwrap(),
                tenure,
            };
            let mut bytes = [0; ReadyBody::LEN];
            bytes[..4].copy_from_slice(&slots.to_be_bytes());
            bytes[4..8].copy_from_slice(&window.to_be_bytes());
            bytes[8..12].copy_from_slice(&7u32.to_be_bytes());
            bytes[12..20].copy_from_slice(&tenure.generation.get().to_be_bytes());
            bytes[20..24].copy_from_slice(&tenure.epoch.get().to_be_bytes());
            bytes[24..40].copy_from_slice(&tenure.host.bytes());
            let want = ReadyBody::decode(&bytes).map(|decoded| {
                assert_eq!(decoded, ready);
                bytes
            });
            assert_eq!(ready.encode(), want, "{ready:?}");
        }
    }
}

#[test]
fn encoder_admission_matches_the_per_field_checks() {
    for (name, bytes) in vectors() {
        let parsed = parse(crc(), &bytes, false).unwrap();
        let h = parsed.header();
        let body = parsed.raw_body();
        let mut headers = vec![h];
        for v in [0, 1, u64::MAX] {
            headers.push(Header { request: v, ..h });
            headers.push(Header { allocation: v, ..h });
            headers.push(Header { total: v, ..h });
            headers.push(Header { offset: v, ..h });
            headers.push(Header { epoch: v, ..h });
        }
        for v in [0, 1, u32::MAX] {
            headers.push(Header {
                metadata_len: v,
                ..h
            });
            headers.push(Header { body_len: v, ..h });
            headers.push(Header { index: v, ..h });
            headers.push(Header { count: v, ..h });
            headers.push(Header { grant: v, ..h });
            headers.push(Header {
                datagram_len: v,
                ..h
            });
            headers.push(Header {
                remaining_ms: v,
                ..h
            });
        }
        for status in [0, 1, 24] {
            headers.push(Header { status, ..h });
        }
        headers.push(Header {
            owner_nonce: [0; 16],
            ..h
        });
        headers.push(Header {
            client_nonce: [0; 16],
            ..h
        });
        headers.push(Header { key: [1; 32], ..h });
        let mut bodies = vec![body.to_vec()];
        for at in 0..body.len().min(96) {
            let mut edited = body.to_vec();
            edited[at] ^= 1;
            bodies.push(edited);
        }
        for header in &headers {
            // For these kinds the predicate decides alone: it accepts exactly the headers `check_kind` accepts.
            let covered = header.kind.is_ownership()
                || matches!(
                    header.kind,
                    Kind::Ready
                        | Kind::PutBegin
                        | Kind::PutAuthority
                        | Kind::PutPrepare
                        | Kind::PutReady
                        | Kind::PutResult
                );
            for b in &bodies {
                let fast = super::encodable(header, b);
                let slow = super::check_kind(header, b).is_ok();
                assert!(!fast || slow, "{name} {header:?}");
                if covered {
                    assert_eq!(fast, slow, "{name} {header:?}");
                }
            }
        }
    }
}

/// The byte-assembled INVALIDATE and INVALIDATED vectors carry the interval `[3, 5]` big-endian at bytes 72..80 and
/// 104..112 under version 3, and the versioned PUT BEGIN carries version `0x0102030405060708` at 104..112.
#[test]
fn invalidate_and_versioned_begin_vectors_hold_their_fields() {
    for (name, kind, low, high) in [
        ("v3-invalidate", Kind::Invalidate, 3, 5),
        ("v3-invalidated", Kind::Invalidated, 3, 5),
        (
            "v3-put-begin-versioned",
            Kind::PutBegin,
            0,
            0x0102_0304_0506_0708,
        ),
    ] {
        let bytes = vector(name);
        assert_eq!(
            [bytes[8], bytes[9], bytes[10]],
            [0, 3, kind as u8],
            "{name}"
        );
        assert_eq!(bytes[72..80], u64::to_be_bytes(low), "{name}");
        assert_eq!(bytes[104..112], u64::to_be_bytes(high), "{name}");
        let header = parse(crc(), &bytes, false).unwrap().header();
        assert_eq!(
            (header.kind, header.allocation, header.offset),
            (kind, low, high),
            "{name}"
        );
    }
}
