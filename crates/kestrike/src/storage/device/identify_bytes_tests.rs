//! Identify decoding over raw 4096-byte controller and namespace pages.
//!
//! Each page starts as noise from a fixed seed, and the builders write the
//! decoded fields as literal bytes at their NVMe base specification offsets.
//! [`expected`] reads the same pages through those byte offsets alone.
//! `IdentifyFacts::decode` returns exactly that reading's facts or its first
//! refusal.

use super::super::seeded::SplitMix64;
use super::identify::{
    IDENTIFY_LEN, IdentifyFacts, IdentifyMalformed, IdentifyRaw, NamespaceAtomics, NvmeVersion,
    VolatileWriteCache,
};

type Page = [u8; IDENTIFY_LEN];

/// A page of noise from `seed`.
fn noise(seed: u64) -> Box<Page> {
    let mut rng = SplitMix64::new(seed);
    let mut page = Box::new([0; IDENTIFY_LEN]);
    for word in page.as_chunks_mut::<8>().0 {
        *word = rng.next_u64().to_le_bytes();
    }
    page
}

fn put(page: &mut Page, at: usize, bytes: &[u8]) {
    page[at..at + bytes.len()].copy_from_slice(bytes);
}

/// `text` padded with spaces to `width` bytes.
fn padded(text: &str, width: usize) -> Vec<u8> {
    let mut field = text.as_bytes().to_vec();
    field.resize(width, b' ');
    field
}

/// A controller page whose serial reads `serial`, whose model and firmware
/// are padded constants, and whose VER, MDTS, ONCS, AWUN, AWUPF and ACWU
/// hold distinct values. The VWC byte stays noise.
fn controller(seed: u64, serial: &str) -> Box<Page> {
    let mut page = noise(seed);
    put(&mut page, 4, &padded(serial, 20));
    put(&mut page, 24, &padded("Amazon Elastic Block Store", 40));
    put(&mut page, 64, b"2.0\0\0\0\0\0");
    page[77] = 6;
    put(&mut page, 80, &0x0102_0304u32.to_le_bytes());
    put(&mut page, 520, &0x015du16.to_le_bytes());
    put(&mut page, 526, &0x0b01u16.to_le_bytes());
    put(&mut page, 528, &0x0b02u16.to_le_bytes());
    put(&mut page, 532, &0x0b03u16.to_le_bytes());
    page
}

/// A namespace page with NLBAF `nlbaf`, FLBAS `flbas`, NSFEAT bit 1 set,
/// and distinct NSZE and atomic field values.
///
/// LBA format entry `index` holds metadata size `0x0100 + index` and block
/// size exponent `(7 * index + 3) % 40`, so each index decodes to distinct
/// facts and some exponents fall outside `9..=31`. Each entry's top byte,
/// which holds relative performance, stays noise.
fn namespace(seed: u64, nlbaf: u8, flbas: u8) -> Box<Page> {
    let mut page = noise(seed);
    put(&mut page, 0, &0x8123_4567_89ab_cdefu64.to_le_bytes());
    page[24] = 0xf2;
    page[25] = nlbaf;
    page[26] = flbas;
    for (at, value) in [34, 36, 38, 40, 42, 44, 46].into_iter().zip(0x0a01u16..) {
        put(&mut page, at, &value.to_le_bytes());
    }
    for index in 0..64u32 {
        let entry = ((7 * index + 3) % 40) << 16 | (0x0100 + index);
        let noisy = entry | u32::from(page[128 + 4 * index as usize + 3]) << 24;
        put(&mut page, 128 + 4 * index as usize, &noisy.to_le_bytes());
    }
    page
}

fn u16_at(page: &Page, at: usize) -> u16 {
    u16::from_le_bytes([page[at], page[at + 1]])
}

fn u32_at(page: &Page, at: usize) -> u32 {
    u32::from_le_bytes(page[at..at + 4].try_into().expect("four bytes"))
}

/// A fixed-width ASCII field without its trailing NULs and spaces, or
/// `Text` for a byte before them outside `0x20..=0x7e`.
fn text(field: &[u8]) -> Result<String, IdentifyMalformed> {
    let mut end = field.len();
    while end > 0 && matches!(field[end - 1], 0 | b' ') {
        end -= 1;
    }
    let kept = &field[..end];
    if kept.iter().any(|&byte| !(0x20..=0x7e).contains(&byte)) {
        return Err(IdentifyMalformed::Text);
    }
    Ok(kept.iter().map(|&byte| char::from(byte)).collect())
}

/// The facts the two pages hold at the specification's offsets, refusing
/// text, then the format index, then the block size.
fn expected(nsid: u32, c: &Page, n: &Page) -> Result<IdentifyFacts, IdentifyMalformed> {
    let (serial, model, firmware) = (text(&c[4..24])?, text(&c[24..64])?, text(&c[64..72])?);
    let (nlbaf, flbas) = (n[25], n[26]);
    // FLBAS bits 3:0 hold the format index; bits 6:5 hold its two high bits
    // once NLBAF, a zero-based count, reports more than sixteen formats, so
    // index 16 and above are reachable only through them.
    let high = if nlbaf >= 16 {
        (flbas >> 5 & 3) << 4
    } else {
        0
    };
    let index = flbas & 0x0f | high;
    if index > nlbaf {
        return Err(IdentifyMalformed::LbaFormat { index, last: nlbaf });
    }
    let format = u32_at(n, 128 + 4 * usize::from(index));
    let lbads = (format >> 16 & 0xff) as u8;
    if !(9..=31).contains(&lbads) {
        return Err(IdentifyMalformed::SectorSize(lbads));
    }
    let version = u32_at(c, 80);
    Ok(IdentifyFacts {
        vendor_id: u16_at(c, 0),
        serial,
        model,
        firmware,
        version: NvmeVersion {
            major: (version >> 16) as u16,
            minor: (version >> 8) as u8,
            tertiary: version as u8,
        },
        volatile_write_cache: VolatileWriteCache {
            present: c[525] & 1 == 1,
            flush_broadcast: c[525] >> 1 & 3,
        },
        oncs: u16_at(c, 520),
        ctratt: u32::from_le_bytes(c[96..100].try_into().expect("four bytes")),
        mdts: c[77],
        awun: u16_at(c, 526),
        awupf: u16_at(c, 528),
        acwu: u16_at(c, 532),
        nsid,
        sectors: u64::from_le_bytes(n[0..8].try_into().expect("eight bytes")),
        lba_format: index,
        sector_size: 1 << lbads,
        metadata_size: format as u16,
        atomics: NamespaceAtomics {
            applies: n[24] >> 1 & 1 == 1,
            nawun: u16_at(n, 34),
            nawupf: u16_at(n, 36),
            nacwu: u16_at(n, 38),
            nabsn: u16_at(n, 40),
            nabo: u16_at(n, 42),
            nabspf: u16_at(n, 44),
            noiob: u16_at(n, 46),
        },
        atomicity_mode: n[24] >> 6 & 1 == 1,
    })
}

/// Decodes the two pages, asserts the result equals [`expected`], and
/// returns it.
fn agree(nsid: u32, c: &Page, n: &Page) -> Result<IdentifyFacts, IdentifyMalformed> {
    let raw = IdentifyRaw::from_parts(nsid, Box::new(*c), Box::new(*n));
    let decoded = IdentifyFacts::decode(&raw);
    assert_eq!(decoded, expected(nsid, c, n));
    decoded
}

/// Raw pages decode every field at its literal offset: the 20-, 40- and
/// 8-byte text fields, the version's three parts, ONCS, MDTS, the three
/// atomic units, NSZE, the active format and every namespace atomic field.
/// Each multi-byte integer holds a distinct value with a nonzero high byte.
/// Every NSFEAT byte and every VWC byte decodes to its flag bits.
#[test]
fn raw_identify_pages_decode_to_their_literal_fields() {
    let c = controller(1, "vol0123456789abcdef0");
    let n = namespace(2, 1, 0x01);
    let facts = agree(7, &c, &n).expect("valid pages");
    assert_eq!(
        (
            facts.serial.as_str(),
            facts.model.as_str(),
            facts.firmware.as_str()
        ),
        ("vol0123456789abcdef0", "Amazon Elastic Block Store", "2.0")
    );
    assert_eq!(
        facts.version,
        NvmeVersion {
            major: 0x0102,
            minor: 3,
            tertiary: 4
        }
    );
    assert_eq!((facts.oncs, facts.mdts), (0x015d, 6));
    assert_eq!(
        (facts.awun, facts.awupf, facts.acwu),
        (0x0b01, 0x0b02, 0x0b03)
    );
    assert_eq!(
        (facts.nsid, facts.sectors, facts.lba_format),
        (7, 0x8123_4567_89ab_cdef, 1)
    );
    assert_eq!((facts.sector_size, facts.metadata_size), (1 << 10, 0x0101));
    assert_eq!(
        facts.atomics,
        NamespaceAtomics {
            applies: true,
            nawun: 0x0a01,
            nawupf: 0x0a02,
            nacwu: 0x0a03,
            nabsn: 0x0a04,
            nabo: 0x0a05,
            nabspf: 0x0a06,
            noiob: 0x0a07,
        }
    );
    for nsfeat in 0..=255u8 {
        let mut n = n.clone();
        n[24] = nsfeat;
        let facts = agree(7, &c, &n).expect("valid pages");
        assert_eq!(facts.atomics.applies, nsfeat & 2 == 2, "{nsfeat:#04x}");
    }
    for vwc in 0..=255u8 {
        let mut c = c.clone();
        c[525] = vwc;
        let facts = agree(7, &c, &n).expect("valid pages");
        assert_eq!(
            facts.volatile_write_cache,
            VolatileWriteCache {
                present: vwc & 1 == 1,
                flush_broadcast: vwc >> 1 & 3
            }
        );
    }
}

/// Every FLBAS byte, under NLBAF values on both sides of the 16-format
/// boundary and at and past the 64-entry table end, decodes or refuses as
/// [`expected`] does. The sweep reaches a decoded format, an index refusal
/// and a size refusal.
#[test]
fn every_format_selection_decodes_or_refuses_as_the_literal_table_says() {
    let c = controller(3, "vol0123456789abcdef0");
    let (mut formats, mut indexes, mut sizes) = (0, 0, 0);
    for nlbaf in [0, 1, 15, 16, 17, 47, 63, 64, 255] {
        for flbas in 0..=255u8 {
            let n = namespace(4, nlbaf, flbas);
            match agree(1, &c, &n) {
                Ok(_) => formats += 1,
                Err(IdentifyMalformed::LbaFormat { .. }) => indexes += 1,
                Err(IdentifyMalformed::SectorSize(_)) => sizes += 1,
                Err(IdentifyMalformed::Text) => unreachable!("printable text fields"),
            }
        }
    }
    assert!(
        formats > 0 && indexes > 0 && sizes > 0,
        "{formats} {indexes} {sizes}"
    );
}

/// Each refusal is reached in its order: a nonprintable byte in the
/// serial, model or firmware refuses `Text` before a bad format index,
/// which refuses `LbaFormat` before a block size outside `9..=31`, which
/// refuses `SectorSize` naming the exponent.
#[test]
fn each_identify_refusal_is_reached_in_its_order() {
    let c = controller(5, "vol0123456789abcdef0");
    // NLBAF 1 makes index 1 the last, so index 2 refuses its index.
    // Overwriting index 1's entry, exponent 10, with exponent 8 refuses its
    // size.
    let bad_index = namespace(6, 1, 0x02);
    let mut bad_size = namespace(6, 1, 0x01);
    put(&mut bad_size, 132, &(8u32 << 16).to_le_bytes());
    // Index 2's own entry holds exponent 8, so a size check made before the
    // index check would refuse `SectorSize` here.
    let mut both = bad_index.clone();
    put(&mut both, 136, &(8u32 << 16).to_le_bytes());
    for (at, byte) in [(10, 0x7f), (30, 0x1f), (40, 0x01), (66, 0x80)] {
        let mut c = c.clone();
        c[at] = byte;
        assert_eq!(agree(1, &c, &bad_index), Err(IdentifyMalformed::Text));
    }
    assert_eq!(
        agree(1, &c, &both),
        Err(IdentifyMalformed::LbaFormat { index: 2, last: 1 })
    );
    assert_eq!(
        agree(1, &c, &bad_size),
        Err(IdentifyMalformed::SectorSize(8))
    );
    let mut wide = bad_size.clone();
    put(&mut wide, 132, &(32u32 << 16).to_le_bytes());
    assert_eq!(agree(1, &c, &wide), Err(IdentifyMalformed::SectorSize(32)));
    // Trailing NULs and spaces pad a field; a space inside it and `~`, the
    // last printable byte, are text.
    let mut c = c.clone();
    put(&mut c, 64, b"~ 2\0 \0  ");
    assert_eq!(agree(1, &c, &namespace(6, 1, 1)).unwrap().firmware, "~ 2");
}
