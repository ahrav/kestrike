//! One seed per refusal reason of the frame decoder, `parse` followed by [`Frame::check_body`](super::frame::Frame::check_body): the decoder refuses each seed, and the label of the returned error equals the seed's declared label.
//!
//! Each label names a leaf of [`FrameError`]: [`reason`] follows `FrameError::Field` into [`Field`] and `Field::Body` into [`OwnershipError`]. Each arm names one leaf, with `..` only over payload fields, so its exhaustive match requires an arm for each new leaf before this module compiles. The macro refuses an arm joined by a top-level `|`, and review checks that no variant position holds `_`, a binding or a nested `|`. [`check`] requires a row or an [`EXEMPT`] entry for each label. A label identifies the leaf alone, and the frame tests check the payloads, such as `found` and the kind a field refusal carries.
//!
//! Each row starts from a committed `v3-` vector. A header edit reseals the header crc with the frame tests' bitwise reference crc, and a body edit also rewrites the datagram length; the body crc stays stale because every body refusal precedes the body crc check. The unedited `truncated` seed and the `short`, `datagram-len`, `header-crc` and `body-crc` seeds keep the vector's stored header crc.
//!
//! The decoder returns the first failing check of the processing order, so the seed for a reason passes every earlier check and fails that one. Obligations `frame-parse-never-panics-and-reencodes`, `v3-ownership-frame-grammar` and `v3-whole-body-tag-and-version-refusal` require the decoder's typed refusals that these seeds reach.
//!
//! Every row except `truncated` is also the frame fuzz corpus file `fuzz/corpus/frame/reject-<label>`, named by its declared label; the truncation flag belongs to the receive, and the fuzz target's truncated parse of every input reaches it. `fuzz/frame.dict` holds the frame constants as libFuzzer dictionary entries. From `crates/kestrike`, `KESTRIKE_WRITE_FRAME_SEEDS=1 cargo test --lib -- net::frame_seed_tests` checks the table, deletes every `reject-` file, writes each row's `reject-` file from the table and `fuzz/frame.dict` from [`dictionary`], and then compares them.

use std::collections::HashSet;
use std::path::Path;

use super::datagram::HEADER_LEN;
use super::frame::tests::{CORPUS, corpus_names, rebody, vector, vectors};
use super::frame::{
    BOOTSTRAP_BODY_LEN, Field, FrameError, Kind, MAGIC, MAX_SLOT_CAP, MAX_WINDOW, Status, VERSION,
    parse,
};
use super::frame_tests::{crc, reseal};
use super::geometry::FRAGMENT_LEN;
use super::ownership::{OwnershipBody, OwnershipError, ReadyBody};

/// Generating [`reason`] and [`REASONS`] from the same pairs makes every label `reason` returns subject to [`check`]'s row-or-[`EXEMPT`] requirement.
macro_rules! labels {
    ($($pattern:pat_param => $label:literal,)*) => {
        fn reason(error: FrameError) -> &'static str {
            match error {
                $($pattern => $label,)*
            }
        }

        const REASONS: &[&str] = &[$($label,)*];
    };
}

labels! {
    FrameError::Truncated => "truncated",
    FrameError::Short { .. } => "short",
    FrameError::Magic => "magic",
    FrameError::HeaderLen { .. } => "header-len",
    FrameError::Version { .. } => "version",
    FrameError::Kind { .. } => "kind",
    FrameError::Flags { .. } => "flags",
    FrameError::Reserved => "reserved",
    FrameError::DatagramLen { .. } => "datagram-len",
    FrameError::HeaderCrc { .. } => "header-crc",
    FrameError::BodyCrc { .. } => "body-crc",
    FrameError::Field { field: Field::OwnerNonce, .. } => "field-owner-nonce",
    FrameError::Field { field: Field::ClientNonce, .. } => "field-client-nonce",
    FrameError::Field { field: Field::Request, .. } => "field-request",
    FrameError::Field { field: Field::Allocation, .. } => "field-allocation",
    FrameError::Field { field: Field::Total, .. } => "field-total",
    FrameError::Field { field: Field::MetadataLen, .. } => "field-metadata-len",
    FrameError::Field { field: Field::BodyLen, .. } => "field-body-len",
    FrameError::Field { field: Field::Index, .. } => "field-index",
    FrameError::Field { field: Field::Count, .. } => "field-count",
    FrameError::Field { field: Field::Offset, .. } => "field-offset",
    FrameError::Field { field: Field::DatagramLen, .. } => "field-datagram-len",
    FrameError::Field { field: Field::Grant, .. } => "field-grant",
    FrameError::Field { field: Field::Status, .. } => "field-status",
    FrameError::Field { field: Field::Remaining, .. } => "field-remaining",
    FrameError::Field { field: Field::Key, .. } => "field-key",
    FrameError::Field { field: Field::Epoch, .. } => "field-epoch",
    FrameError::Field { field: Field::SlotCap, .. } => "field-slot-cap",
    FrameError::Field { field: Field::WindowCap, .. } => "field-window-cap",
    FrameError::Field { field: Field::Body(OwnershipError::Kind), .. } => "body-kind",
    FrameError::Field { field: Field::Body(OwnershipError::Length), .. } => "body-length",
    FrameError::Field { field: Field::Body(OwnershipError::Caps), .. } => "body-caps",
    FrameError::Field { field: Field::Body(OwnershipError::Shard), .. } => "body-shard",
    FrameError::Field { field: Field::Body(OwnershipError::Tenure), .. } => "body-tenure",
    FrameError::Field { field: Field::Body(OwnershipError::Volume), .. } => "body-volume",
    FrameError::Field { field: Field::Body(OwnershipError::Flags), .. } => "body-flags",
    FrameError::Field { field: Field::Body(OwnershipError::ReportAge), .. } => "body-report-age",
    FrameError::Field { field: Field::Body(OwnershipError::Responder), .. } => "body-responder",
    FrameError::Field { field: Field::Body(OwnershipError::Reserved), .. } => "body-reserved",
}

/// The labels of unreachable leaves, which [`check`] refuses as a row's declared label. The decoder decodes an ownership body only for the six ownership kinds, and `OwnershipError::Kind` names any other kind.
const EXEMPT: &[&str] = &["body-kind"];

/// A datagram and its truncation flag, which the decoder refuses first for the `declared` label. `name` is unique within a table, and `declared` gives the corpus file `reject-<declared>` of each row with its truncation flag clear.
#[derive(Clone)]
pub(super) struct Row {
    pub(super) name: &'static str,
    pub(super) bytes: Vec<u8>,
    pub(super) truncated: bool,
    pub(super) declared: &'static str,
}

/// The seed table: for each label outside [`EXEMPT`], one row named by that label.
pub(super) fn table() -> Vec<Row> {
    let vectors = vectors();
    let base = |name: &str| {
        let (_, bytes) = vectors
            .iter()
            .find(|(vector, _)| *vector == name)
            .expect("a committed v3 vector");
        bytes.clone()
    };
    let header = |name: &str, edit: fn(&mut Vec<u8>)| {
        let mut bytes = base(name);
        edit(&mut bytes);
        reseal(&mut bytes);
        bytes
    };
    let unsealed = |name: &str, edit: fn(&mut Vec<u8>)| {
        let mut bytes = base(name);
        edit(&mut bytes);
        bytes
    };
    let body = |name: &str, edit: fn(&mut Vec<u8>)| rebody(&base(name), edit);
    let seed = |name: &'static str, bytes: Vec<u8>| Row {
        name,
        bytes,
        truncated: false,
        declared: name,
    };
    vec![
        Row {
            truncated: true,
            ..seed("truncated", base("v3-get"))
        },
        seed("short", unsealed("v3-get", |b| b.truncate(HEADER_LEN - 1))),
        seed("magic", header("v3-get", |b| b[0] = b'X')),
        seed("header-len", header("v3-get", |b| b[13] = 191)),
        seed("version", header("v3-get", |b| b[9] = 1)),
        seed("kind", header("v3-get", |b| b[10] = 29)),
        seed("flags", header("v3-get", |b| b[11] = 1)),
        seed("reserved", header("v3-get", |b| b[14] = 1)),
        seed("datagram-len", unsealed("v3-get", |b| b.push(0))),
        seed("header-crc", unsealed("v3-get", |b| b[60] ^= 1)),
        seed(
            "field-client-nonce",
            header("v3-get", |b| b[40..56].fill(0)),
        ),
        seed("body-crc", unsealed("v3-hello", |b| b[195] = 9)),
        seed("field-request", header("v3-hello", |b| b[63] = 1)),
        seed("field-datagram-len", body("v3-hello", |b| b.push(0))),
        seed("field-slot-cap", body("v3-hello", |b| b[0..4].fill(0))),
        seed("field-window-cap", body("v3-hello", |b| b[4..8].fill(0))),
        seed(
            "field-owner-nonce",
            header("v3-holder", |b| b[24..40].fill(0)),
        ),
        seed("field-epoch", header("v3-holder", |b| b[168..176].fill(0))),
        seed("field-allocation", header("v3-holder", |b| b[72] = 1)),
        seed("field-total", header("v3-holder", |b| b[80] = 1)),
        seed("field-metadata-len", header("v3-holder", |b| b[88] = 1)),
        seed("field-body-len", header("v3-holder", |b| b[92] = 1)),
        seed("field-index", header("v3-holder", |b| b[96] = 1)),
        seed("field-count", header("v3-holder", |b| b[100] = 1)),
        seed("field-offset", header("v3-holder", |b| b[104] = 1)),
        seed("field-grant", header("v3-holder", |b| b[116] = 1)),
        seed("field-status", header("v3-holder", |b| b[121] = 1)),
        seed("field-remaining", header("v3-holder", |b| b[124] = 1)),
        seed("field-key", header("v3-holder", |b| b[128] = 1)),
        seed("body-length", body("v3-holder", |b| b.truncate(59))),
        seed("body-shard", body("v3-holder", |b| b[4..8].fill(0))),
        seed("body-tenure", body("v3-holder", |b| b[19] = 9)),
        seed("body-volume", body("v3-holder", |b| b[2] = 3)),
        seed("body-flags", body("v3-holder", |b| b[1] = 8)),
        seed("body-responder", body("v3-holder", |b| b[44..60].fill(0))),
        seed("body-reserved", body("v3-holder", |b| b[3] = 1)),
        seed("body-report-age", body("v3-who-holds", |b| b[43] = 1)),
        seed("body-caps", body("v3-ready", |b| b[4..8].fill(0))),
    ]
}

/// The first failure of `rows`, in row order and then label order: a repeated name, a row declaring an exempt label, a row the decoder accepts or refuses for another label, or a label outside [`EXEMPT`] with no row.
fn check(rows: &[Row]) -> Result<(), String> {
    let mut names = HashSet::new();
    for row in rows {
        let (name, declared) = (row.name, row.declared);
        if !names.insert(name) {
            return Err(format!("{name}: duplicate name"));
        }
        if EXEMPT.contains(&declared) {
            return Err(format!("{name}: declares exempt label {declared}"));
        }
        let refused = match parse(crc(), &row.bytes, row.truncated)
            .and_then(|frame| frame.check_body(crc()))
        {
            Ok(_) => return Err(format!("{name}: accepted, declared {declared}")),
            Err(error) => reason(error),
        };
        if refused != declared {
            return Err(format!("{name}: refused {refused}, declared {declared}"));
        }
    }
    for &label in REASONS {
        if !EXEMPT.contains(&label) && !rows.iter().any(|row| row.declared == label) {
            return Err(format!("{label} has no seed"));
        }
    }
    Ok(())
}

/// The libFuzzer dictionary text: frame constants big-endian as on the wire, with the retired version 2 and one above each cap as refusal boundaries.
fn dictionary() -> String {
    let mut entries: Vec<(String, Vec<u8>)> = vec![
        ("magic".into(), MAGIC.to_vec()),
        ("version".into(), VERSION.to_be_bytes().to_vec()),
        ("version_2".into(), 2u16.to_be_bytes().to_vec()),
        (
            "header_len".into(),
            u16::try_from(HEADER_LEN).unwrap().to_be_bytes().to_vec(),
        ),
    ];
    let [high, low] = VERSION.to_be_bytes();
    for kind in Kind::ALL {
        let byte = kind as u8;
        entries.push((format!("kind_{byte:02}"), vec![high, low, byte, 0]));
    }
    for status in (1..=u16::MAX).filter_map(Status::from_wire) {
        let value = status as u16;
        entries.push((format!("status_{value:02}"), value.to_be_bytes().to_vec()));
    }
    let len = |len: usize| u32::try_from(len).unwrap();
    for (name, value) in [
        ("max_window", MAX_WINDOW),
        ("max_window_plus_1", MAX_WINDOW + 1),
        ("max_slot_cap", MAX_SLOT_CAP),
        ("max_slot_cap_plus_1", MAX_SLOT_CAP + 1),
        ("fragment_len", FRAGMENT_LEN),
        ("bootstrap_body_len", len(BOOTSTRAP_BODY_LEN)),
        ("ready_body_len", len(ReadyBody::LEN)),
        ("ownership_body_len", len(OwnershipBody::FIXED_LEN)),
    ] {
        entries.push((name.into(), value.to_be_bytes().to_vec()));
    }
    entries.push(("volume_prefix".into(), b"vol-".to_vec()));
    let mut text = String::from(
        "# Frame constants for the frame fuzz target, written by the frame seed tests in crates/kestrike/src/net/frame_seed_tests.rs.\n",
    );
    for (name, bytes) in entries {
        let value: String = bytes
            .iter()
            .map(|&byte| {
                if byte.is_ascii_alphanumeric() || byte == b'-' {
                    char::from(byte).to_string()
                } else {
                    format!("\\x{byte:02X}")
                }
            })
            .collect();
        text.push_str(&format!("{name}=\"{value}\"\n"));
    }
    text
}

#[test]
fn every_refusal_reason_has_a_seed_refused_for_exactly_it() {
    let rows = table();
    assert_eq!(check(&rows), Ok(()));
    assert_eq!(rows.len(), 38);
    assert!(rows.iter().all(|row| row.name == row.declared));
    assert_eq!(REASONS.len(), 39);
    assert_eq!(REASONS.iter().collect::<HashSet<_>>().len(), REASONS.len());
    assert!(EXEMPT.iter().all(|label| REASONS.contains(label)));
}

/// Each table copy carries one planted fault, one per failure kind of [`check`], so each assertion shows the check names that fault.
#[test]
fn a_seed_table_with_a_wrong_missing_or_accepted_row_fails_the_check() {
    let rows = table();
    let at = |name: &str| {
        rows.iter()
            .position(|row| row.name == name)
            .expect("a table row")
    };
    let magic = at("magic");

    let mut wrong = rows.clone();
    wrong[magic].declared = "header-len";
    assert_eq!(
        check(&wrong),
        Err("magic: refused magic, declared header-len".into())
    );

    let mut missing = rows.clone();
    missing.remove(at("body-reserved"));
    assert_eq!(check(&missing), Err("body-reserved has no seed".into()));

    let mut accepted = rows.clone();
    accepted[magic].bytes = vector("v3-get");
    assert_eq!(
        check(&accepted),
        Err("magic: accepted, declared magic".into())
    );

    let mut duplicate = rows.clone();
    duplicate.push(rows[magic].clone());
    assert_eq!(check(&duplicate), Err("magic: duplicate name".into()));

    let mut exempt = rows.clone();
    exempt.push(Row {
        name: "body-kind",
        declared: "body-kind",
        ..rows[magic].clone()
    });
    assert_eq!(
        check(&exempt),
        Err("body-kind: declares exempt label body-kind".into())
    );
}

/// Rows with a clear truncation flag are exactly the `reject-<declared>` corpus files, byte for byte, and `fuzz/frame.dict` is [`dictionary`]'s text.
#[test]
fn the_committed_seeds_and_dictionary_equal_the_table() {
    let corpus = Path::new(CORPUS);
    let dict = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/frame.dict");
    let table = table();
    let rows: Vec<&Row> = table.iter().filter(|row| !row.truncated).collect();
    let file = |row: &&Row| format!("reject-{}", row.declared);
    let mut expected: Vec<String> = rows.iter().map(file).collect();
    expected.sort();
    if let Some(pair) = expected.windows(2).find(|pair| pair[0] == pair[1]) {
        panic!("two rows name {}", pair[0]);
    }
    if std::env::var_os("KESTRIKE_WRITE_FRAME_SEEDS").is_some_and(|value| value == "1") {
        assert_eq!(check(&table), Ok(()));
        for name in corpus_names("reject-") {
            std::fs::remove_file(corpus.join(&name))
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        }
        for row in &rows {
            let name = file(row);
            std::fs::write(corpus.join(&name), &row.bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        }
        std::fs::write(&dict, dictionary())
            .unwrap_or_else(|error| panic!("{}: {error}", dict.display()));
    }
    let present = corpus_names("reject-");
    let missing: Vec<&String> = expected
        .iter()
        .filter(|name| !present.contains(name))
        .collect();
    let unexpected: Vec<&String> = present
        .iter()
        .filter(|name| !expected.contains(name))
        .collect();
    assert!(
        missing.is_empty() && unexpected.is_empty(),
        "missing reject- files {missing:?}, unexpected reject- files {unexpected:?}"
    );
    for row in &rows {
        let name = file(row);
        let committed =
            std::fs::read(corpus.join(&name)).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(committed == row.bytes, "{name} differs from its row");
    }
    let committed =
        std::fs::read(&dict).unwrap_or_else(|error| panic!("{}: {error}", dict.display()));
    assert!(
        committed == dictionary().as_bytes(),
        "{} differs from the dictionary builder's text",
        dict.display()
    );
}
