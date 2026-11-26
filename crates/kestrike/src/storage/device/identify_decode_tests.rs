//! `IdentifyFacts::decode` returns exactly the facts a literal reading of the two Identify
//! pages gives at their NVMe base specification offsets, or that reading's first refusal.
//!
//! The scenario writes its own pages: noise from a fixed seed, then the decoded fields as literal bytes. The
//! function `literal` reads the same pages through byte offsets and shifts alone, never through the typed
//! bindings the decode uses, so the two readings share nothing but the pages. Each test also states a few
//! outcomes as constants, so a mistake in `literal` cannot hide one in the decode.

use super::identify::{
    IDENTIFY_LEN, IdentifyFacts, IdentifyMalformed, IdentifyRaw, NamespaceAtomics, NvmeVersion,
    VolatileWriteCache,
};

type Page = [u8; IDENTIFY_LEN];

// Controller offsets (Identify Controller data structure).
const VID: usize = 0;
const SN: usize = 4;
const MN: usize = 24;
const FR: usize = 64;
const MDTS: usize = 77;
const VER: usize = 80;
const CTRATT: usize = 96;
const ONCS: usize = 520;
const VWC: usize = 525;
const AWUN: usize = 526;
const AWUPF: usize = 528;
const ACWU: usize = 532;

// Namespace offsets (Identify Namespace data structure, NVM command set).
const NSZE: usize = 0;
const NSFEAT: usize = 24;
const NLBAF: usize = 25;
const FLBAS: usize = 26;
const NAWUN: usize = 34;
const NAWUPF: usize = 36;
const NACWU: usize = 38;
const NABSN: usize = 40;
const NABO: usize = 42;
const NABSPF: usize = 44;
const NOIOB: usize = 46;
const LBAF: usize = 128;

/// The NLBAF values the sweep covers: both sides of the 16-format boundary, and at and past the table's 64
/// entries.
const NLBAFS: [u8; 9] = [0, 1, 15, 16, 17, 47, 63, 64, 255];

/// A page of noise from `seed`: a 64-bit linear congruential sequence, one high byte a step.
fn noise(seed: u64) -> Box<Page> {
    let mut state = seed;
    let mut page = Box::new([0u8; IDENTIFY_LEN]);
    for byte in page.iter_mut() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *byte = (state >> 56) as u8;
    }
    page
}

fn put(page: &mut Page, at: usize, bytes: &[u8]) {
    page[at..at + bytes.len()].copy_from_slice(bytes);
}

fn le16(page: &Page, at: usize) -> u16 {
    u16::from(page[at]) | u16::from(page[at + 1]) << 8
}

fn le32(page: &Page, at: usize) -> u32 {
    u32::from(le16(page, at)) | u32::from(le16(page, at + 2)) << 16
}

fn le64(page: &Page, at: usize) -> u64 {
    u64::from(le32(page, at)) | u64::from(le32(page, at + 4)) << 32
}

/// The metadata size the scenario gives LBA format entry `index`: no two indexes share one, and each has a
/// nonzero high byte.
fn metadata_of(index: u8) -> u16 {
    0x4000 + 0x0101 * u16::from(index)
}

/// The block size exponent the scenario gives entry `index`: inside `9..=31` for most, with four entries
/// outside it, two on each side.
fn exponent_of(index: u8) -> u8 {
    match index {
        5 => 8,
        21 => 32,
        40 => 0,
        62 => 255,
        _ => 9 + index % 23,
    }
}

/// A controller page: noise, then printable text fields of the full 20, 40 and 8 bytes, a serial that ends
/// in padding spaces, and distinct values with nonzero high bytes in every decoded integer.
fn controller(seed: u64) -> Box<Page> {
    let mut page = noise(seed);
    put(&mut page, VID, &0x1d0fu16.to_le_bytes());
    put(&mut page, SN, b"vol0fedcba987654    ");
    put(&mut page, MN, b"Literal Offsets Model 0123456789 ABCDEFG");
    put(&mut page, FR, b"fw-7.5~9");
    page[MDTS] = 0x09;
    put(&mut page, VER, &0x0002_0401u32.to_le_bytes());
    put(&mut page, CTRATT, &0xa1b2_c3d5u32.to_le_bytes());
    put(&mut page, ONCS, &0x7e5fu16.to_le_bytes());
    put(&mut page, AWUN, &0x1122u16.to_le_bytes());
    put(&mut page, AWUPF, &0x3344u16.to_le_bytes());
    put(&mut page, ACWU, &0x5566u16.to_le_bytes());
    page
}

/// A namespace page with NLBAF `nlbaf` and FLBAS `flbas`: noise, then NSZE, the seven atomic fields, and all
/// 64 LBA format entries, entry `index` holding [`metadata_of`] in bits 15:0 and [`exponent_of`] in bits
/// 23:16. Bits 31:24 of each entry, the relative performance and reserved bits, stay noise, as does NSFEAT.
fn namespace(seed: u64, nlbaf: u8, flbas: u8) -> Box<Page> {
    let mut page = noise(seed);
    put(&mut page, NSZE, &0x0123_4567_89ab_cdefu64.to_le_bytes());
    page[NLBAF] = nlbaf;
    page[FLBAS] = flbas;
    for (at, value) in [NAWUN, NAWUPF, NACWU, NABSN, NABO, NABSPF, NOIOB]
        .into_iter()
        .zip([0x9101u16, 0x9202, 0x9303, 0x9404, 0x9505, 0x9606, 0x9707])
    {
        put(&mut page, at, &value.to_le_bytes());
    }
    for index in 0..64u8 {
        let at = LBAF + 4 * usize::from(index);
        put(&mut page, at, &metadata_of(index).to_le_bytes());
        page[at + 2] = exponent_of(index);
    }
    page
}

/// A fixed-width ASCII field without its trailing NULs and spaces; `Text` when a byte before them is outside
/// `0x20..=0x7e`.
fn text(field: &[u8]) -> Result<String, IdentifyMalformed> {
    let kept = match field.iter().rposition(|&byte| byte != 0x00 && byte != 0x20) {
        Some(last) => &field[..=last],
        None => &field[..0],
    };
    let mut out = String::new();
    for &byte in kept {
        if !(0x20..=0x7e).contains(&byte) {
            return Err(IdentifyMalformed::Text);
        }
        out.push(char::from(byte));
    }
    Ok(out)
}

/// The format index the FLBAS byte selects under `nlbaf`, by the specification's rule: bits 3:0, with bits
/// 6:5 as the two high bits when NLBAF, a zero-based count, is 16 or more.
fn selected(nlbaf: u8, flbas: u8) -> u8 {
    let low = flbas & 0b0000_1111;
    let high = (flbas & 0b0110_0000) >> 5;
    if nlbaf >= 16 { high << 4 | low } else { low }
}

/// The literal reading of the two pages: the serial, model and firmware in that order, then the format
/// index, then the block size, each refusing before the next is read.
fn literal(nsid: u32, c: &Page, n: &Page) -> Result<IdentifyFacts, IdentifyMalformed> {
    let serial = text(&c[SN..SN + 20])?;
    let model = text(&c[MN..MN + 40])?;
    let firmware = text(&c[FR..FR + 8])?;
    let index = selected(n[NLBAF], n[FLBAS]);
    if index > n[NLBAF] {
        return Err(IdentifyMalformed::LbaFormat {
            index,
            last: n[NLBAF],
        });
    }
    let entry = LBAF + 4 * usize::from(index);
    let exponent = n[entry + 2];
    if !(9..=31).contains(&exponent) {
        return Err(IdentifyMalformed::SectorSize(exponent));
    }
    Ok(IdentifyFacts {
        vendor_id: le16(c, VID),
        serial,
        model,
        firmware,
        version: NvmeVersion {
            major: le16(c, VER + 2),
            minor: c[VER + 1],
            tertiary: c[VER],
        },
        volatile_write_cache: VolatileWriteCache {
            present: c[VWC] & 0b001 != 0,
            flush_broadcast: (c[VWC] & 0b110) >> 1,
        },
        oncs: le16(c, ONCS),
        ctratt: le32(c, CTRATT),
        mdts: c[MDTS],
        awun: le16(c, AWUN),
        awupf: le16(c, AWUPF),
        acwu: le16(c, ACWU),
        nsid,
        sectors: le64(n, NSZE),
        lba_format: index,
        sector_size: 1u32 << exponent,
        metadata_size: le16(n, entry),
        atomics: NamespaceAtomics {
            applies: n[NSFEAT] & 0b0000_0010 != 0,
            nawun: le16(n, NAWUN),
            nawupf: le16(n, NAWUPF),
            nacwu: le16(n, NACWU),
            nabsn: le16(n, NABSN),
            nabo: le16(n, NABO),
            nabspf: le16(n, NABSPF),
            noiob: le16(n, NOIOB),
        },
        atomicity_mode: n[NSFEAT] & 0b0100_0000 != 0,
    })
}

fn decode(nsid: u32, c: &Page, n: &Page) -> Result<IdentifyFacts, IdentifyMalformed> {
    IdentifyFacts::decode(&IdentifyRaw::from_parts(nsid, Box::new(*c), Box::new(*n)))
}

/// Decodes the two pages and requires the literal reading's facts or refusal; returns the outcome.
fn agree(nsid: u32, c: &Page, n: &Page, what: &str) -> Result<IdentifyFacts, IdentifyMalformed> {
    let decoded = decode(nsid, c, n);
    assert_eq!(
        decoded,
        literal(nsid, c, n),
        "the decode (left) is not the literal reading (right) of {what}"
    );
    decoded
}

/// Every FLBAS byte under each NLBAF of the bounds decodes to the entry the specification's rule selects,
/// with that entry's own sizes, or refuses the index or the size as the literal reading does.
#[test]
fn every_format_selection_decodes_to_the_selected_entry_or_names_its_refusal() {
    let c = controller(0x1d);
    let (mut formats, mut indexes, mut sizes) = (0usize, 0usize, 0usize);
    for nlbaf in NLBAFS {
        for flbas in 0..=255u8 {
            let n = namespace(0x2e, nlbaf, flbas);
            let what = format!("NLBAF {nlbaf} with FLBAS {flbas:#04x}");
            match agree(9, &c, &n, &what) {
                Ok(facts) => {
                    formats += 1;
                    // The entry's own values, from the scenario's table and not from the page.
                    let index = facts.lba_format;
                    assert_eq!(
                        (facts.sector_size, facts.metadata_size),
                        (1u32 << exponent_of(index), metadata_of(index)),
                        "{what} decodes format {index} with another entry's sizes"
                    );
                    assert!(index <= nlbaf, "{what} decodes format {index} past NLBAF");
                }
                Err(IdentifyMalformed::LbaFormat { index, last }) => {
                    indexes += 1;
                    assert!(
                        index > nlbaf && last == nlbaf,
                        "{what} refuses index {index} of last {last}"
                    );
                }
                Err(IdentifyMalformed::SectorSize(exponent)) => {
                    sizes += 1;
                    assert!(
                        [8, 32, 0, 255].contains(&exponent),
                        "{what} refuses the size exponent {exponent}"
                    );
                }
                Err(IdentifyMalformed::Text) => panic!("{what} refuses printable text"),
            }
        }
    }
    assert!(
        formats > 0 && indexes > 0 && sizes > 0,
        "the sweep reaches a format, an index refusal and a size refusal: {formats} {indexes} {sizes}"
    );

    // The 16-format boundary, as constants. FLBAS 0x20 has bits 6:5 = 01 and bits 3:0 = 0.
    let at = |nlbaf: u8, flbas: u8| {
        decode(9, &c, &namespace(0x2e, nlbaf, flbas))
            .map(|facts| (facts.lba_format, facts.sector_size, facts.metadata_size))
    };
    assert_eq!(
        at(16, 0x20),
        Ok((16, 1 << 25, 0x5010)),
        "seventeen formats select format 16 through FLBAS bits 6:5"
    );
    assert_eq!(
        at(15, 0x23),
        Ok((3, 1 << 12, 0x4303)),
        "sixteen formats ignore FLBAS bits 6:5"
    );
    assert_eq!(
        at(16, 0x21),
        Err(IdentifyMalformed::LbaFormat {
            index: 17,
            last: 16
        }),
        "a selection past NLBAF names the index and the last format"
    );
    assert_eq!(
        at(63, 0x6f),
        Ok((63, 1 << 26, 0x7f3f)),
        "the table's last entry"
    );
    assert_eq!(
        at(255, 0xff),
        Ok((63, 1 << 26, 0x7f3f)),
        "FLBAS bit 7 and bit 4 are not part of the index"
    );
}

/// Every field decodes from its literal offset, and every NSFEAT byte and every VWC byte decodes to its flag
/// bits alone.
#[test]
fn every_field_and_every_nsfeat_and_vwc_byte_decode_from_their_literal_offsets() {
    let c = controller(0x3a);
    let n = namespace(0x4b, 1, 0x01);
    let facts = agree(0xfeed_0007, &c, &n, "the base pages").expect("the base pages decode");
    let mut expected = IdentifyFacts {
        vendor_id: 0x1d0f,
        serial: "vol0fedcba987654".to_owned(),
        model: "Literal Offsets Model 0123456789 ABCDEFG".to_owned(),
        firmware: "fw-7.5~9".to_owned(),
        version: NvmeVersion {
            major: 2,
            minor: 4,
            tertiary: 1,
        },
        volatile_write_cache: VolatileWriteCache {
            present: c[VWC] & 1 == 1,
            flush_broadcast: c[VWC] >> 1 & 3,
        },
        oncs: 0x7e5f,
        ctratt: 0xa1b2_c3d5,
        mdts: 9,
        awun: 0x1122,
        awupf: 0x3344,
        acwu: 0x5566,
        nsid: 0xfeed_0007,
        sectors: 0x0123_4567_89ab_cdef,
        lba_format: 1,
        sector_size: 1 << 10,
        metadata_size: 0x4101,
        atomics: NamespaceAtomics {
            applies: n[NSFEAT] >> 1 & 1 == 1,
            nawun: 0x9101,
            nawupf: 0x9202,
            nacwu: 0x9303,
            nabsn: 0x9404,
            nabo: 0x9505,
            nabspf: 0x9606,
            noiob: 0x9707,
        },
        atomicity_mode: n[NSFEAT] >> 6 & 1 == 1,
    };
    assert_eq!(facts, expected, "the base pages' fields, as constants");

    for nsfeat in 0..=255u8 {
        let mut n = n.clone();
        n[NSFEAT] = nsfeat;
        expected.atomics.applies = nsfeat & 0x02 != 0;
        expected.atomicity_mode = nsfeat & 0x40 != 0;
        let facts = agree(0xfeed_0007, &c, &n, &format!("NSFEAT {nsfeat:#04x}"));
        assert_eq!(facts.as_ref(), Ok(&expected), "NSFEAT {nsfeat:#04x}");
    }
    expected.atomics.applies = n[NSFEAT] >> 1 & 1 == 1;
    expected.atomicity_mode = n[NSFEAT] >> 6 & 1 == 1;
    for vwc in 0..=255u8 {
        let mut c = c.clone();
        c[VWC] = vwc;
        expected.volatile_write_cache = VolatileWriteCache {
            present: vwc & 0x01 != 0,
            flush_broadcast: (vwc & 0x06) >> 1,
        };
        let facts = agree(0xfeed_0007, &c, &n, &format!("VWC {vwc:#04x}"));
        assert_eq!(facts.as_ref(), Ok(&expected), "VWC {vwc:#04x}");
    }
}

/// One page per refusal: a text byte of 0x7f, 0x1f, 0x01 or 0x80 refuses `Text` while `~` is text; a selection
/// past NLBAF refuses `LbaFormat` with the index and the last format; an exponent of 8 or 32 refuses
/// `SectorSize`; and `Text` comes before `LbaFormat`, which comes before `SectorSize`.
#[test]
fn each_refusal_is_named_and_comes_in_its_order() {
    let c = controller(0x5c);
    // NLBAF 4 makes format 4 the last. Entry 5 holds exponent 8, so FLBAS 5 is past NLBAF and names an entry a
    // size check made first would refuse.
    let past = namespace(0x6d, 4, 0x05);
    assert_eq!(exponent_of(5), 8);
    assert_eq!(
        agree(
            3,
            &c,
            &past,
            "a selection past NLBAF whose entry has exponent 8"
        ),
        Err(IdentifyMalformed::LbaFormat { index: 5, last: 4 }),
        "LbaFormat comes before SectorSize"
    );
    // The serial, the model twice and the firmware, each with one byte outside printable ASCII, over a
    // namespace that would refuse its index: Text comes first.
    for (at, byte) in [
        (SN + 6, 0x7fu8),
        (MN + 6, 0x1f),
        (MN + 16, 0x01),
        (FR + 2, 0x80),
    ] {
        let mut c = c.clone();
        c[at] = byte;
        assert_eq!(
            agree(
                3,
                &c,
                &past,
                &format!("byte {byte:#04x} at controller offset {at}")
            ),
            Err(IdentifyMalformed::Text),
            "Text comes before LbaFormat, for byte {byte:#04x} at {at}"
        );
    }
    // A selected entry inside NLBAF with exponent 8, then 32, and the two neighbors 9 and 31 that decode.
    let mut n = namespace(0x6d, 4, 0x02);
    for (exponent, outcome) in [
        (8u8, Err(IdentifyMalformed::SectorSize(8))),
        (32, Err(IdentifyMalformed::SectorSize(32))),
        (9, Ok(1u32 << 9)),
        (31, Ok(1u32 << 31)),
    ] {
        n[LBAF + 4 * 2 + 2] = exponent;
        let decoded = agree(3, &c, &n, &format!("exponent {exponent}"));
        assert_eq!(
            decoded.map(|facts| facts.sector_size),
            outcome,
            "exponent {exponent}"
        );
    }
    // `~` (0x7e) is the last printable byte and a space inside a field is text; trailing NULs and spaces pad.
    let mut c = c.clone();
    put(&mut c, FR, b"~ 2\0 \0  ");
    put(&mut c, SN, &[0x20; 20]);
    let facts =
        agree(3, &c, &namespace(0x6d, 4, 0x04), "padded text").expect("padded text decodes");
    assert_eq!(
        (facts.firmware.as_str(), facts.serial.as_str()),
        ("~ 2", ""),
        "`~` is text and padding is not"
    );
}
