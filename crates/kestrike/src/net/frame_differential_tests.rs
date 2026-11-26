//! Byte-assembled goldens supply expected fields for `decode`; the edit table supplies expected decode outcomes. The judge reports agreement on every vector and golden. Their selected single-byte edits, at every header byte and the first eight body bytes where the body holds them, raw and resealed, yield agreement or `Unjudged`. Planted references exercise each failing verdict. Each refusal seed of the frame seed table gets the verdict its label declares.

use crate::storage::Crc32c;

use super::frame::tests::{vector, vectors};
use super::frame::{Field, FrameError, Kind, parse};
use super::frame_differential::{Verdict, classify, judge, judge_with};
use super::frame_reference::{BODY_START, Fields, Refusal, bitwise_crc32c, decode};
use super::frame_seed_tests::{Row as SeedRow, table};
use super::frame_tests::{Raw, crc, goldens, reseal};
use crate::oracle::guard_tests::{FORBIDDEN_TOKENS, attribute_names_path, tokens};

fn assembled(raw: &Raw) -> Fields {
    Fields {
        kind: raw.kind,
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
        body_crc: bitwise_crc32c(&raw.payload),
    }
}

/// `Raw` writes fields at literal offsets, so the expected values check `decode`'s offsets and the byte order of its integer reads. Every golden array repeats one byte, so the order of an array read is checked by the edit table.
#[test]
fn the_reference_reads_every_golden_to_the_fields_that_assembled_it() {
    for (name, raw) in goldens() {
        assert_eq!(decode(&raw.bytes(), false), Ok(assembled(&raw)), "{name}");
    }
}

type Row = (&'static str, Vec<u8>, bool, Result<Fields, Refusal>);

/// Each row, an edit of the golden GET or an empty datagram, makes `decode` return the row's refusal or fields, without `parse`. Rows built with `Raw::edited` reseal the header crc after the edit; rows built with `unsealed` keep the golden's stored crc, so an edit under the crc leaves it stale, while an appended byte or a tag edit leaves it valid. The `high` row sets to 1 the first byte of each integer field from offset 20 except the datagram length and the two crcs, which the golden holds at zero, so a read narrower than the field's width misses it, and the first byte of the two nonces and the key, so an array read keeps its first byte first. The `distinct` row writes a different byte at every array position, so any reordering of whole bytes in an array read changes its result. The stored body crc row holds a value other than the crc of the golden's empty body, so `decode` passes it only by returning the stored crc unchecked.
#[test]
fn the_reference_names_each_fixed_field_fault() {
    const STORED_BODY_CRC: u32 = 0x1234_5678;
    let get = Raw::get();
    assert_ne!(bitwise_crc32c(&get.payload), STORED_BODY_CRC);
    let golden = get.bytes();
    let fields = assembled(&get);
    let unsealed = |edit: fn(&mut Vec<u8>)| {
        let mut bytes = golden.clone();
        edit(&mut bytes);
        bytes
    };
    let mut tag = fields.tag;
    tag[0] ^= 1;
    let (mut owner_nonce, mut client_nonce, mut key) =
        (fields.owner_nonce, fields.client_nonce, fields.key);
    owner_nonce[0] = 1;
    client_nonce[0] = 1;
    key[0] = 1;
    let high = Fields {
        key_epoch: fields.key_epoch | 1 << 24,
        owner_nonce,
        client_nonce,
        request: fields.request | 1 << 56,
        body_len: fields.body_len | 1 << 24,
        key,
        sequence: fields.sequence | 1 << 56,
        allocation: fields.allocation | 1 << 56,
        total: fields.total | 1 << 56,
        metadata_len: fields.metadata_len | 1 << 24,
        index: fields.index | 1 << 24,
        count: fields.count | 1 << 24,
        offset: fields.offset | 1 << 56,
        grant: fields.grant | 1 << 24,
        status: fields.status | 1 << 8,
        remaining_ms: fields.remaining_ms | 1 << 24,
        epoch: fields.epoch | 1 << 56,
        ..fields
    };
    let distinct = Fields {
        owner_nonce: std::array::from_fn(|i| 0x40 + i as u8),
        client_nonce: std::array::from_fn(|i| 0x50 + i as u8),
        key: std::array::from_fn(|i| 0x60 + i as u8),
        tag: std::array::from_fn(|i| 0x90 + i as u8),
        ..fields
    };
    let rows: Vec<Row> = vec![
        ("unedited", golden.clone(), false, Ok(fields)),
        ("truncated", golden.clone(), true, Err(Refusal::Truncated)),
        (
            "truncated and empty",
            Vec::new(),
            true,
            Err(Refusal::Truncated),
        ),
        ("empty", Vec::new(), false, Err(Refusal::Short)),
        ("short", golden[..191].to_vec(), false, Err(Refusal::Short)),
        (
            "magic byte 0",
            get.edited(|b| b[0] = b'X'),
            false,
            Err(Refusal::Magic),
        ),
        (
            "magic byte 7",
            get.edited(|b| b[7] = b'2'),
            false,
            Err(Refusal::Magic),
        ),
        (
            "header length 191",
            get.edited(|b| b[13] = 191),
            false,
            Err(Refusal::HeaderLen),
        ),
        (
            "header length high byte",
            get.edited(|b| b[12] = 1),
            false,
            Err(Refusal::HeaderLen),
        ),
        (
            "version 2",
            get.edited(|b| b[9] = 2),
            false,
            Err(Refusal::Version),
        ),
        (
            "version high byte",
            get.edited(|b| b[8] = 1),
            false,
            Err(Refusal::Version),
        ),
        (
            "kind 0",
            get.edited(|b| b[10] = 0),
            false,
            Err(Refusal::Kind),
        ),
        (
            "kind 1",
            get.edited(|b| b[10] = 1),
            false,
            Ok(Fields { kind: 1, ..fields }),
        ),
        (
            "kind 28",
            get.edited(|b| b[10] = 28),
            false,
            Ok(Fields { kind: 28, ..fields }),
        ),
        (
            "kind 29",
            get.edited(|b| b[10] = 29),
            false,
            Err(Refusal::Kind),
        ),
        (
            "flags 1",
            get.edited(|b| b[11] = 1),
            false,
            Err(Refusal::Flags),
        ),
        (
            "flags 0x80",
            get.edited(|b| b[11] = 0x80),
            false,
            Err(Refusal::Flags),
        ),
        (
            "reserved byte 14",
            get.edited(|b| b[14] = 1),
            false,
            Err(Refusal::Reserved),
        ),
        (
            "reserved byte 15",
            get.edited(|b| b[15] = 1),
            false,
            Err(Refusal::Reserved),
        ),
        (
            "reserved byte 122",
            get.edited(|b| b[122] = 1),
            false,
            Err(Refusal::Reserved),
        ),
        (
            "reserved byte 123",
            get.edited(|b| b[123] = 1),
            false,
            Err(Refusal::Reserved),
        ),
        (
            "datagram length 1",
            get.edited(|b| b[115] = 1),
            false,
            Err(Refusal::DatagramLen),
        ),
        (
            "datagram length high byte",
            get.edited(|b| b[112] = 1),
            false,
            Err(Refusal::DatagramLen),
        ),
        (
            "datagram length 0xFFFF_FFFF",
            get.edited(|b| b[112..116].fill(0xFF)),
            false,
            Err(Refusal::DatagramLen),
        ),
        (
            "appended byte",
            unsealed(|b| b.push(0)),
            false,
            Err(Refusal::DatagramLen),
        ),
        (
            "header crc byte 160",
            unsealed(|b| b[160] ^= 1),
            false,
            Err(Refusal::HeaderCrc),
        ),
        (
            "header crc byte 163",
            unsealed(|b| b[163] ^= 1),
            false,
            Err(Refusal::HeaderCrc),
        ),
        (
            "request byte under the header crc",
            unsealed(|b| b[56] ^= 1),
            false,
            Err(Refusal::HeaderCrc),
        ),
        (
            "body crc byte under the header crc",
            unsealed(|b| b[164] ^= 1),
            false,
            Err(Refusal::HeaderCrc),
        ),
        (
            "the first byte of each field from offset 20 set to 1",
            get.edited(|b| {
                for at in [
                    20, 24, 40, 56, 64, 72, 80, 88, 92, 96, 100, 104, 116, 120, 124, 128, 168,
                ] {
                    b[at] = 1;
                }
            }),
            false,
            Ok(high),
        ),
        (
            "distinct bytes at every array position",
            get.edited(|b| {
                b[24..40].copy_from_slice(&distinct.owner_nonce);
                b[40..56].copy_from_slice(&distinct.client_nonce);
                b[128..160].copy_from_slice(&distinct.key);
                b[176..192].copy_from_slice(&distinct.tag);
            }),
            false,
            Ok(distinct),
        ),
        (
            "a stored body crc that differs from the body's crc",
            get.edited(|b| b[164..168].copy_from_slice(&STORED_BODY_CRC.to_be_bytes())),
            false,
            Ok(Fields {
                body_crc: STORED_BODY_CRC,
                ..fields
            }),
        ),
        (
            "tag byte after the header crc",
            unsealed(|b| b[176] ^= 1),
            false,
            Ok(Fields { tag, ..fields }),
        ),
    ];
    for (name, bytes, truncated, expected) in rows {
        assert_eq!(decode(&bytes, truncated), expected, "{name}");
    }
}

fn names_the_crate(source: &str) -> bool {
    let tokens = tokens(source);
    source
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|word| word == "crate" || word == "super")
        || tokens.iter().enumerate().any(|(i, &token)| {
            FORBIDDEN_TOKENS.contains(&token)
                || (token == "#" && attribute_names_path(&tokens[i + 1..]))
                || (token == "mod" && tokens.get(i + 2) == Some(&";"))
        })
}

/// `names_the_crate` matches the whole words `crate` and `super`, even in comments and literals. In code, it flags possible file loads: `include!`, `include_str!`, `include_bytes!`, `mod name;`, and `path` attributes, including those inside `cfg_attr`. It also flags `macro_rules!` because an expansion can declare a module. Resolving crate aliases and inherited macros requires context from the enclosing crate.
#[test]
fn the_reference_decoder_imports_nothing_from_the_crate() {
    assert!(
        names_the_crate("use super::frame::KIND_AT;"),
        "the predicate refuses a line that imports a frame constant"
    );
    assert!(
        names_the_crate("use crate::net::frame::KIND_AT;"),
        "the predicate refuses a line that imports a frame constant by its crate path"
    );
    assert!(
        names_the_crate("use crate as root;"),
        "the predicate refuses an aliased crate root"
    );
    assert!(
        names_the_crate("include!(\"frame.rs\");"),
        "the predicate refuses a file inclusion"
    );
    assert!(
        names_the_crate("#[path = \"frame.rs\"] mod production;"),
        "the predicate refuses a path module"
    );
    assert!(
        names_the_crate("#[cfg_attr(test, path = \"frame.rs\")] mod production;"),
        "the predicate refuses a path module chosen by a conditional attribute"
    );
    assert!(
        names_the_crate("mod helpers;"),
        "the predicate refuses a module loaded from another file"
    );
    assert!(
        !names_the_crate("mod helpers {}"),
        "the predicate admits an inline module, whose text the check reads"
    );
    assert!(
        names_the_crate("macro_rules! load { ($n:ident) => { mod $n; }; } load!(helpers);"),
        "the predicate refuses a macro, which can expand to a module loaded from another file"
    );
    assert!(
        !names_the_crate("crates/kestrike"),
        "the predicate refuses whole words only"
    );
    assert!(
        !names_the_crate(include_str!("frame_reference.rs")),
        "frame_reference.rs holds the word crate or super, a macro definition, an inclusion macro, a path attribute or an out-of-line module"
    );
}

fn inputs() -> Vec<(String, Vec<u8>)> {
    let vectors = vectors();
    let goldens = goldens();
    assert_eq!((vectors.len(), goldens.len()), (59, 33));
    vectors
        .into_iter()
        .map(|(name, bytes)| (name.to_string(), bytes))
        .chain(
            goldens
                .into_iter()
                .map(|(name, raw)| (format!("golden {name}"), raw.bytes())),
        )
        .collect()
}

/// The vectors and goldens establish a baseline for `judge`: `parse` and the reference agree on acceptance for intact frames and on refusal for frames marked truncated.
#[test]
fn every_vector_and_golden_is_accepted_alike_by_parse_and_the_reference() {
    let crc = crc();
    for (name, bytes) in inputs() {
        assert_eq!(
            judge(crc, &bytes, false),
            Verdict::Agree { accepted: true },
            "{name}"
        );
        assert_eq!(
            judge(crc, &bytes, true),
            Verdict::Agree { accepted: false },
            "{name} truncated"
        );
    }
}

/// Verdict counts over one half of the sweep, one judgment per selected edit. `accepted_covered` and `unjudged_covered` count edits of a byte the header crc covers outside the crc field, `[0, 160)` and `[164, 176)`, whose change resealing keeps; `unrefused_crc_field` counts accepted or `Unjudged` edits of the stored crc `[160, 164)`, which resealing overwrites; `furthest` is the highest offset judged.
#[derive(Debug, Default)]
struct Tally {
    accepted: usize,
    accepted_covered: usize,
    refused: usize,
    unjudged: usize,
    unjudged_covered: usize,
    unrefused_crc_field: usize,
    furthest: usize,
}

impl Tally {
    fn judged(&self) -> usize {
        self.accepted + self.refused + self.unjudged
    }

    fn count(&mut self, verdict: Verdict, at: usize, edit: impl FnOnce() -> String) {
        let covered = usize::from(at < 160 || (164..176).contains(&at));
        let crc_field = usize::from((160..164).contains(&at));
        self.furthest = self.furthest.max(at);
        match verdict {
            Verdict::Agree { accepted: true } => {
                self.accepted += 1;
                self.accepted_covered += covered;
                self.unrefused_crc_field += crc_field;
            }
            Verdict::Agree { accepted: false } => self.refused += 1,
            Verdict::Unjudged => {
                self.unjudged += 1;
                self.unjudged_covered += covered;
                self.unrefused_crc_field += crc_field;
            }
            failing => panic!("{}: {failing:?}", edit()),
        }
    }
}

/// For each selected byte edit, both raw and resealed inputs must yield agreement or `Unjudged`. Each half judges every selected edit, through the last of the eight body bytes. The raw half accepts some edit and refuses every edit below offset 176, which a stale crc fails; the resealed half accepts an edit of a byte the crc covers, refuses some edit and leaves an edit of such a byte `Unjudged`. On aarch64 hosts with `crc` and `aes`, the witness checks that `Kernel::CrcLanes` runs during the sweep.
#[test]
fn no_single_byte_edit_is_over_lenient_over_strict_or_read_differently() {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    witness(
        "crc-lanes",
        detected!(aarch64: "crc", "aes"),
        || runs(Kernel::CrcLanes),
        sweep,
    );
}

fn sweep() {
    let crc = crc();
    const SWEPT: usize = BODY_START + 8;
    let (mut raw, mut resealed) = (Tally::default(), Tally::default());
    let mut selected = 0;
    for (name, input) in inputs() {
        for at in 0..input.len().min(SWEPT) {
            let values = [0x00, 0x01, 0x80, 0xFF, input[at] ^ 0x01];
            for (n, &value) in values.iter().enumerate() {
                if value == input[at] || values[..n].contains(&value) {
                    continue;
                }
                selected += 1;
                let mut bytes = input.clone();
                bytes[at] = value;
                raw.count(judge(crc, &bytes, false), at, || {
                    format!("{name} byte {at} = {value:#04x}")
                });
                reseal(&mut bytes);
                resealed.count(judge(crc, &bytes, false), at, || {
                    format!("{name} byte {at} = {value:#04x} resealed")
                });
            }
        }
    }
    println!("raw: {raw:?}\nresealed: {resealed:?}");
    for (half, tally) in [("raw", &raw), ("resealed", &resealed)] {
        assert_eq!(
            (tally.judged(), tally.furthest + 1),
            (selected, SWEPT),
            "the {half} half judges every selected edit: {tally:?}"
        );
    }
    assert!(
        raw.accepted > 0
            && raw.accepted_covered + raw.unjudged_covered + raw.unrefused_crc_field == 0,
        "the raw half judges unsealed edits and refuses each below offset 176: {raw:?}"
    );
    assert!(
        resealed.accepted_covered > 0 && resealed.refused > 0 && resealed.unjudged_covered > 0,
        "the resealed half reaches every non-failing verdict on edits of bytes the crc covers: {resealed:?}"
    );
}

fn refusing_kind_28(bytes: &[u8], truncated: bool) -> Result<Fields, Refusal> {
    match decode(bytes, truncated) {
        Ok(fields) if fields.kind == 28 => Err(Refusal::Kind),
        outcome => outcome,
    }
}

/// `decode` without its flags check: after a `Flags` refusal it decodes a resealed copy with the flags cleared, then refuses with `HeaderCrc` when the original's stored header crc fails.
fn skipping_the_flags_check(bytes: &[u8], truncated: bool) -> Result<Fields, Refusal> {
    match decode(bytes, truncated) {
        Err(Refusal::Flags) => {
            let mut cleared = bytes.to_vec();
            cleared[11] = 0;
            reseal(&mut cleared);
            let fields = decode(&cleared, truncated)?;
            let mut original = bytes.to_vec();
            reseal(&mut original);
            if original[160..164] == bytes[160..164] {
                Ok(fields)
            } else {
                Err(Refusal::HeaderCrc)
            }
        }
        outcome => outcome,
    }
}

fn reading_the_sequence_at_56(bytes: &[u8], truncated: bool) -> Result<Fields, Refusal> {
    decode(bytes, truncated).map(|fields| Fields {
        sequence: u64::from_be_bytes(bytes[56..64].try_into().unwrap()),
        ..fields
    })
}

/// The control shows the judge can return `OverLenient`, so the sweep's agreement comes from a judge that detects a reference stricter than `parse`.
#[test]
fn control_a_reference_refusing_kind_28_makes_parse_over_lenient() {
    let bytes = vector("v3-invalidated");
    assert_eq!(bytes[10], 28);
    assert_eq!(
        judge(crc(), &bytes, false),
        Verdict::Agree { accepted: true }
    );
    assert_eq!(
        judge_with(refusing_kind_28, crc(), &bytes, false),
        Verdict::OverLenient
    );
}

/// The control checks the sweep's judge against a known `OverStrict` case.
#[test]
fn control_a_reference_skipping_the_flags_check_makes_parse_over_strict() {
    let mut bytes = vector("v3-get");
    bytes[11] = 1;
    reseal(&mut bytes);
    assert_eq!(
        judge(crc(), &bytes, false),
        Verdict::Agree { accepted: false }
    );
    assert_eq!(
        judge_with(skipping_the_flags_check, crc(), &bytes, false),
        Verdict::OverStrict
    );
    bytes[160] ^= 1;
    assert_eq!(
        skipping_the_flags_check(&bytes, false),
        Err(Refusal::HeaderCrc)
    );
    assert_eq!(
        judge_with(skipping_the_flags_check, crc(), &bytes, false),
        Verdict::Agree { accepted: false }
    );
}

/// The control checks the sweep's judge against a known `FieldsDiffer` case.
#[test]
fn control_a_reference_reading_the_sequence_at_56_makes_the_fields_differ() {
    let bytes = vector("v3-get");
    assert_ne!(bytes[56..64], bytes[64..72]);
    assert_eq!(
        judge(crc(), &bytes, false),
        Verdict::Agree { accepted: true }
    );
    assert_eq!(
        judge_with(reading_the_sequence_at_56, crc(), &bytes, false),
        Verdict::FieldsDiffer
    );
}

fn flipped<const N: usize>(mut bytes: [u8; N]) -> [u8; N] {
    bytes[0] ^= 1;
    bytes
}

/// The control checks that the sweep's judge compares every `Fields` member.
#[test]
fn control_a_difference_in_any_one_component_of_the_fields_makes_them_differ() {
    let bytes = vector("v3-data-first");
    let body = &bytes[BODY_START..];
    let fields = decode(&bytes, false).unwrap();
    let production = parse(crc(), &bytes, false);
    assert_eq!(
        classify(production, Ok((fields, body))),
        Verdict::Agree { accepted: true }
    );
    // Adding a field to `Fields` requires updating the pattern, prompting a corresponding case in `plants`.
    let Fields {
        kind,
        principal,
        key_epoch,
        owner_nonce,
        client_nonce,
        request,
        sequence,
        allocation,
        total,
        metadata_len,
        body_len,
        index,
        count,
        offset,
        datagram_len,
        grant,
        status,
        remaining_ms,
        key,
        epoch,
        tag,
        body_crc,
    } = fields;
    let plant = |change: &dyn Fn(&mut Fields)| {
        let mut planted = fields;
        change(&mut planted);
        planted
    };
    let plants = [
        ("kind", plant(&|f| f.kind = kind ^ 1)),
        ("principal", plant(&|f| f.principal = principal ^ 1)),
        ("key epoch", plant(&|f| f.key_epoch = key_epoch ^ 1)),
        (
            "owner nonce",
            plant(&|f| f.owner_nonce = flipped(owner_nonce)),
        ),
        (
            "client nonce",
            plant(&|f| f.client_nonce = flipped(client_nonce)),
        ),
        ("request", plant(&|f| f.request = request ^ 1)),
        ("sequence", plant(&|f| f.sequence = sequence ^ 1)),
        ("allocation", plant(&|f| f.allocation = allocation ^ 1)),
        ("total", plant(&|f| f.total = total ^ 1)),
        (
            "metadata length",
            plant(&|f| f.metadata_len = metadata_len ^ 1),
        ),
        ("body length", plant(&|f| f.body_len = body_len ^ 1)),
        ("index", plant(&|f| f.index = index ^ 1)),
        ("count", plant(&|f| f.count = count ^ 1)),
        ("offset", plant(&|f| f.offset = offset ^ 1)),
        (
            "datagram length",
            plant(&|f| f.datagram_len = datagram_len ^ 1),
        ),
        ("grant", plant(&|f| f.grant = grant ^ 1)),
        ("status", plant(&|f| f.status = status ^ 1)),
        ("remaining", plant(&|f| f.remaining_ms = remaining_ms ^ 1)),
        ("key", plant(&|f| f.key = flipped(key))),
        ("epoch", plant(&|f| f.epoch = epoch ^ 1)),
        ("tag", plant(&|f| f.tag = flipped(tag))),
        ("body crc", plant(&|f| f.body_crc = body_crc ^ 1)),
    ];
    for (component, planted) in plants {
        assert_eq!(
            classify(production, Ok((planted, body))),
            Verdict::FieldsDiffer,
            "{component}"
        );
    }
    let mut planted_body = body.to_vec();
    planted_body[0] ^= 1;
    assert_eq!(
        classify(production, Ok((fields, &planted_body))),
        Verdict::FieldsDiffer,
        "body"
    );
    assert_eq!(
        classify(production, Ok((fields, &body[..body.len() - 1]))),
        Verdict::FieldsDiffer,
        "body one byte shorter"
    );
    let mut longer_body = body.to_vec();
    longer_body.push(0);
    assert_eq!(
        classify(production, Ok((fields, &longer_body))),
        Verdict::FieldsDiffer,
        "body one byte longer"
    );
}

/// `classify` maps each refusal of either decoder by the verdict table: every `parse` error beside reference acceptance is `OverStrict` except `FrameError::Field`, which is `Unjudged`; every error beside every reference refusal is agreement; and every reference refusal beside `parse` acceptance is `OverLenient`. The outcomes are built by hand, so the test pins the mapping and not which errors `parse` returns.
#[test]
fn classify_maps_every_refusal_of_either_decoder_to_its_verdict() {
    let bytes = vector("v3-get");
    let body = &bytes[BODY_START..];
    let fields = decode(&bytes, false).unwrap();
    let production = parse(crc(), &bytes, false);
    let errors = [
        FrameError::Truncated,
        FrameError::Short { len: 0 },
        FrameError::Magic,
        FrameError::HeaderLen { found: 0 },
        FrameError::Version { found: 2 },
        FrameError::Kind { found: 0 },
        FrameError::Flags { found: 1 },
        FrameError::Reserved,
        FrameError::DatagramLen {
            declared: 0,
            received: 1,
        },
        FrameError::Field {
            kind: Kind::Get,
            field: Field::ClientNonce,
        },
        FrameError::HeaderCrc {
            stored: 0,
            computed: 1,
        },
        FrameError::BodyCrc {
            stored: 0,
            computed: 1,
        },
    ];
    for (position, error) in errors.into_iter().enumerate() {
        // The match has no wildcard, so a variant added to `FrameError` stops the build here; its sample joins the list above by hand, at the position its arm names.
        let (listed, expected) = match error {
            FrameError::Truncated => (0, Verdict::OverStrict),
            FrameError::Short { .. } => (1, Verdict::OverStrict),
            FrameError::Magic => (2, Verdict::OverStrict),
            FrameError::HeaderLen { .. } => (3, Verdict::OverStrict),
            FrameError::Version { .. } => (4, Verdict::OverStrict),
            FrameError::Kind { .. } => (5, Verdict::OverStrict),
            FrameError::Flags { .. } => (6, Verdict::OverStrict),
            FrameError::Reserved => (7, Verdict::OverStrict),
            FrameError::DatagramLen { .. } => (8, Verdict::OverStrict),
            FrameError::Field { .. } => (9, Verdict::Unjudged),
            FrameError::HeaderCrc { .. } => (10, Verdict::OverStrict),
            FrameError::BodyCrc { .. } => (11, Verdict::OverStrict),
        };
        assert_eq!(listed, position, "{error:?}");
        assert_eq!(
            classify(Err(error), Ok((fields, body))),
            expected,
            "{error:?}"
        );
    }
    let refusals = [
        Refusal::Truncated,
        Refusal::Short,
        Refusal::Magic,
        Refusal::HeaderLen,
        Refusal::Version,
        Refusal::Kind,
        Refusal::Flags,
        Refusal::Reserved,
        Refusal::DatagramLen,
        Refusal::HeaderCrc,
    ];
    for (position, refusal) in refusals.into_iter().enumerate() {
        // The match has no wildcard, so a variant added to `Refusal` stops the build here; its sample joins the list above by hand, at the position its arm names.
        let listed = match refusal {
            Refusal::Truncated => 0,
            Refusal::Short => 1,
            Refusal::Magic => 2,
            Refusal::HeaderLen => 3,
            Refusal::Version => 4,
            Refusal::Kind => 5,
            Refusal::Flags => 6,
            Refusal::Reserved => 7,
            Refusal::DatagramLen => 8,
            Refusal::HeaderCrc => 9,
        };
        assert_eq!(listed, position, "{refusal:?}");
        assert_eq!(
            classify(production, Err(refusal)),
            Verdict::OverLenient,
            "{refusal:?}"
        );
        for error in errors {
            assert_eq!(
                classify(Err(error), Err(refusal)),
                Verdict::Agree { accepted: false },
                "{error:?} beside {refusal:?}"
            );
        }
    }
}

/// The verdict `judge` owes a refusal seed row with `label`, or `None` for a label outside the declared sets. The ten fixed-field labels owe agreement on refusal, whichever check the reference refuses on. `body-crc` owes agreement on acceptance, because only `Frame::check_body` checks the body crc. Every other `field-` and `body-` label owes `Unjudged`: its row carries a valid header crc and datagram length, so the reference accepts it and `parse` refuses it on a per-kind rule.
fn verdict_for_label(label: &str) -> Option<Verdict> {
    match label {
        "truncated" | "short" | "magic" | "header-len" | "version" | "kind" | "flags"
        | "reserved" | "datagram-len" | "header-crc" => Some(Verdict::Agree { accepted: false }),
        "body-crc" => Some(Verdict::Agree { accepted: true }),
        _ if label.starts_with("field-") || label.starts_with("body-") => Some(Verdict::Unjudged),
        _ => None,
    }
}

fn check_seed(crc: Crc32c, row: &SeedRow) -> Result<(), String> {
    let expected = verdict_for_label(row.declared)
        .ok_or_else(|| format!("{}: label {} declares no verdict", row.name, row.declared))?;
    let verdict = judge(crc, &row.bytes, row.truncated);
    if verdict == expected {
        Ok(())
    } else {
        Err(format!(
            "{} ({}): {verdict:?}, declared {expected:?}",
            row.name, row.declared
        ))
    }
}

/// The row count fails the test when the table changes size. A new `field-` or `body-` label takes `Unjudged` from its prefix, and any other new label fails the check. A row with an unknown label and a `field-` row with a stale header crc each fail the check.
#[test]
fn every_refusal_seed_gets_the_verdict_its_reason_declares() {
    let crc = crc();
    let rows = table();
    assert_eq!(rows.len(), 38);
    for row in &rows {
        if let Err(failure) = check_seed(crc, row) {
            panic!("{failure}");
        }
    }
    let row = |label: &str| {
        rows.iter()
            .find(|row| row.declared == label)
            .unwrap_or_else(|| panic!("the seed table has a {label} row"))
            .clone()
    };
    let mut unknown = row("magic");
    unknown.declared = "trailer";
    assert_eq!(
        check_seed(crc, &unknown),
        Err("magic: label trailer declares no verdict".to_owned())
    );
    let mut stale = row("field-request");
    stale.bytes[160] ^= 1;
    assert_eq!(
        check_seed(crc, &stale),
        Err(
            "field-request (field-request): Agree { accepted: false }, declared Unjudged"
                .to_owned()
        )
    );
}

/// `k` canonical GET frames back to back, for `k` from 2 to 9, each accepted alike by `parse` and the reference on its
/// own, form one datagram that both refuse under the datagram length rule: a GET's header declares an empty body, so
/// every byte past its 192-byte header is a body the header does not declare.
#[test]
fn parse_and_the_reference_refuse_get_frames_back_to_back() {
    let crc = crc();
    for k in 2..=9usize {
        let mut datagram = Vec::new();
        for n in 0..k {
            let mut get = Raw::get();
            get.sequence = n as u64 + 1;
            let frame = get.bytes();
            assert_eq!(
                judge(crc, &frame, false),
                Verdict::Agree { accepted: true },
                "frame {n} of {k}"
            );
            datagram.extend_from_slice(&frame);
        }
        assert_eq!(datagram.len(), 192 * k);
        assert_eq!(
            parse(crc, &datagram, false).err(),
            Some(FrameError::DatagramLen {
                declared: 0,
                received: 192 * (k - 1)
            }),
            "{k} frames"
        );
        assert_eq!(
            decode(&datagram, false),
            Err(Refusal::DatagramLen),
            "{k} frames"
        );
        assert_eq!(
            judge(crc, &datagram, false),
            Verdict::Agree { accepted: false },
            "{k} frames"
        );
    }
}
