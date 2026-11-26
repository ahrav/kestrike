use super::assignment_tests::{other_record, record};
use super::record::{LocalRecord, RECORD_BYTES, RecordError};

fn resealed(mut sector: [u8; RECORD_BYTES]) -> [u8; RECORD_BYTES] {
    let crc = crate::storage::Crc32c::detect().checksum(&sector[..RECORD_BYTES - 4]);
    sector[RECORD_BYTES - 4..].copy_from_slice(&crc.to_le_bytes());
    sector
}

/// The record round-trips through its one sector, and a torn 512-byte sector refuses: every distinct 4-byte-aligned prefix of a record with another binding, host ID and key over the stored record, a flip of each stored crc byte, and a single-bit flip at every 61st body bit refuse `Torn`; a wrong length, including the 283-byte length of a format-1 record, or a wrong version refuses before the crc.
#[test]
fn local_record_roundtrip_and_torn_refuses() {
    let r = record();
    let sector = r.encode().unwrap();
    assert_eq!(LocalRecord::decode(&sector), Ok(r.clone()));
    let next = other_record().encode().unwrap();
    let mut seen = std::collections::HashSet::new();
    for torn in (4..RECORD_BYTES).step_by(4) {
        let mut mixed = sector;
        mixed[..torn].copy_from_slice(&next[..torn]);
        if mixed != sector && seen.insert(mixed) {
            assert_eq!(
                LocalRecord::decode(&mixed),
                Err(RecordError::Torn),
                "torn at {torn}"
            );
        }
    }
    assert!(seen.len() >= 6, "tears inside every differing field");
    for at in RECORD_BYTES - 4..RECORD_BYTES {
        let mut damaged = sector;
        damaged[at] ^= 1;
        assert_eq!(
            LocalRecord::decode(&damaged),
            Err(RecordError::Torn),
            "crc byte {at}"
        );
    }
    for bit in (32..(RECORD_BYTES - 4) * 8).step_by(61) {
        let mut flipped = sector;
        flipped[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(
            LocalRecord::decode(&flipped),
            Err(RecordError::Torn),
            "bit {bit}"
        );
    }
    for len in [0, 4, 283, RECORD_BYTES - 1, RECORD_BYTES + 1] {
        let mut bytes = sector.to_vec();
        bytes.resize(len, 0);
        assert_eq!(LocalRecord::decode(&bytes), Err(RecordError::Length));
    }
    let mut old = sector;
    old[0] = 1;
    assert_eq!(LocalRecord::decode(&old), Err(RecordError::Version));
}

/// Format 2 lays the record out at fixed offsets: the version, three 64-byte zero-padded identifiers, the host ID, the little-endian key with the incarnation in its low word, zero padding to byte 508, and the crc32c of bytes 0 to 508 in the last four bytes.
#[test]
fn local_record_layout_is_fixed() {
    let sector = record().encode().unwrap();
    assert_eq!(sector.len(), 512);
    assert_eq!(&sector[..4], &[2, 0, 0, 0]);
    assert_eq!(&sector[4..23], b"i-0123456789abcdef0");
    assert_eq!(&sector[68..89], b"vol-0123456789abcdef0");
    assert_eq!(&sector[132..140], b"attach-1");
    assert_eq!(&sector[196..212], &[9; 16]);
    assert_eq!(&sector[212..220], &[2, 0, 0, 0, 1, 0, 0, 0]);
    for padding in [23..68, 89..132, 140..196, 220..508] {
        assert!(
            sector[padding.clone()].iter().all(|&b| b == 0),
            "{padding:?}"
        );
    }
    assert_eq!(
        &sector[508..512],
        &crate::storage::Crc32c::detect()
            .checksum(&sector[..508])
            .to_le_bytes()
    );
}

/// The crc-first witness over `decode`: each of seven field edits refuses `Torn` under the stored crc and `Field`
/// once the crc is resealed over it.
fn field_checks_follow_the_crc(decode: impl Fn(&[u8]) -> Result<LocalRecord, RecordError>) {
    let sector = record().encode().unwrap();
    type Sector = [u8; RECORD_BYTES];
    fn volume(s: &mut Sector, text: &[u8]) {
        s[68..132].fill(0);
        s[68..68 + text.len()].copy_from_slice(text);
    }
    let edits: [fn(&mut Sector); 7] = [
        |s| s[300] = 1,
        |s| s[196..212].fill(0),
        |s| s[216..220].fill(0),
        |s| s[4] = 0xff,
        |s| s[5] = b'@',
        |s| volume(s, b"vol0123456789abcdef0"),
        |s| volume(s, b"disk-1"),
    ];
    for (at, edit) in edits.iter().enumerate() {
        let mut bad = sector;
        edit(&mut bad);
        assert_eq!(decode(&bad), Err(RecordError::Torn), "{at}");
        assert_eq!(decode(&resealed(bad)), Err(RecordError::Field), "{at}");
    }
}

/// A sector whose crc matches its bytes still refuses `Field` for a nonzero padding byte, a zero host ID, a zero key epoch, an invalid UTF-8 identifier byte, an ASCII identifier byte outside the alphabet, a dashless volume ID and a volume that is not a volume ID; under the stored crc the same edits refuse `Torn`. Encoding refuses the two malformed volumes and an instance with a byte outside the alphabet.
#[test]
fn local_record_field_refusals_follow_the_crc() {
    field_checks_follow_the_crc(LocalRecord::decode);
    for text in ["vol0123456789abcdef0", "disk-1"] {
        let mut binding = record().binding().clone();
        binding.volume = text.into();
        let bad = LocalRecord::fresh(binding, record().pair().key, || Some([9; 16])).unwrap();
        assert_eq!(bad.encode(), Err(RecordError::Field), "{text}");
    }
    let mut binding = record().binding().clone();
    binding.instance = "i-@123".into();
    let bad = LocalRecord::fresh(binding, record().pair().key, || Some([9; 16])).unwrap();
    assert_eq!(bad.encode(), Err(RecordError::Field));
}

/// The negative control "fields before the crc": a decoder that reseals the sector's crc before it decodes never
/// sees a mismatch, so a torn sector whose damaged byte also breaks a field refuses by that field, not as `Torn`.
#[test]
#[should_panic(expected = "0\n  left: Err(Field)\n right: Err(Torn)")]
fn negative_control_a_decode_that_skips_the_crc_refuses_a_torn_sector_by_field() {
    field_checks_follow_the_crc(|bytes| match <[u8; RECORD_BYTES]>::try_from(bytes) {
        Ok(sector) => LocalRecord::decode(&resealed(sector)),
        Err(_) => LocalRecord::decode(bytes),
    });
}
