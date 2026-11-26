use super::identity::{
    Epoch, Exhid, Field, IdentityError, Incarnation, Key, MAX_VOLUME_LEN, is_az, is_volume,
    is_volume_field,
};

/// The largest usable epoch and incarnation.
const FIELD_MAX: u32 = 0xFFFF_FFFE;

fn epoch(e: u32) -> Epoch {
    Epoch::new(e).unwrap()
}

/// The maximum usable epoch and incarnation encode to the maximum usable key, decode back, and order above every smaller key.
#[test]
fn the_maximum_usable_values_encode_decode_and_compare() {
    let key = Key::new(epoch(FIELD_MAX), Incarnation::new(FIELD_MAX).unwrap());
    assert_eq!(key.encode(), 0xFFFF_FFFE_FFFF_FFFE);
    assert_eq!(Key::decode(key.encode()), Ok(key));
    let smaller = Key::new(epoch(FIELD_MAX - 1), Incarnation::new(FIELD_MAX).unwrap());
    assert!(smaller < key);
    assert!(
        Key::new(epoch(1), Incarnation::new(FIELD_MAX).unwrap())
            < Key::decode(2 << 32 | 1).unwrap()
    );
}

/// The raw-key refusals `decode` must make: each zero or reserved field refuses by its own name, and a key whose epoch
/// and incarnation are both out of range names the epoch.
fn refuses_by_field(decode: impl Fn(u64) -> Result<Key, IdentityError>) {
    assert_eq!(
        decode(1 << 32),
        Err(IdentityError::Zero(Field::Incarnation))
    );
    assert_eq!(decode(0), Err(IdentityError::Zero(Field::Epoch)));
    assert_eq!(decode(7), Err(IdentityError::Zero(Field::Epoch)));
    assert_eq!(
        decode(0xFFFF_FFFF << 32 | 1),
        Err(IdentityError::Reserved(Field::Epoch))
    );
    assert_eq!(
        decode(1 << 32 | 0xFFFF_FFFF),
        Err(IdentityError::Reserved(Field::Incarnation))
    );
    assert_eq!(decode(u64::MAX), Err(IdentityError::Reserved(Field::Epoch)));
}

/// `decode(1 << 32)` names the zero incarnation; a zero or reserved epoch refuses by its field, and the epoch field is checked before the incarnation.
#[test]
fn zero_reserved_and_malformed_keys_refuse_by_field() {
    refuses_by_field(Key::decode);
    assert_eq!(
        Epoch::new(0xFFFF_FFFF),
        Err(IdentityError::Reserved(Field::Epoch))
    );
    assert_eq!(
        Incarnation::new(0),
        Err(IdentityError::Zero(Field::Incarnation))
    );
}

/// The negative control "the incarnation checked first": a decoder that builds the incarnation field before the epoch
/// field refuses the all-zero key as a zero incarnation, so the refusal fixtures reject it at `decode(0)`, which must
/// name the epoch.
#[test]
#[should_panic(expected = "left: Err(Zero(Incarnation))\n right: Err(Zero(Epoch))")]
fn negative_control_a_decode_that_checks_the_incarnation_first_names_the_wrong_field() {
    refuses_by_field(|raw| {
        let incarnation = Incarnation::new(raw as u32)?;
        let epoch = Epoch::new((raw >> 32) as u32)?;
        Ok(Key::new(epoch, incarnation))
    });
}

/// A zero EXHID refuses; any other 16 bytes are kept exactly.
#[test]
fn a_zero_exhid_refuses() {
    assert_eq!(Exhid::new([0; 16]), Err(IdentityError::ExhidZero));
    let mut bytes = [0; 16];
    bytes[15] = 1;
    assert_eq!(Exhid::new(bytes).unwrap().bytes(), bytes);
}

#[test]
fn an_az_name_is_1_to_63_bytes_of_lowercase_letters_digits_and_hyphens() {
    let (longest, too_long) = ("a".repeat(63), "a".repeat(64));
    for name in ["us-east-1a", "us-west-2-lax-1a", "0", "-", &longest] {
        assert!(is_az(name), "{name:?}");
    }
    let refused = [
        "",
        &too_long,
        "US-EAST-1A",
        "us_east_1a",
        "us east",
        "us-east-1a\n",
        "us\u{7f}east",
        "us-east-\u{e9}",
    ];
    for name in refused {
        assert!(!is_az(name), "{name:?}");
    }
}

/// The volume grammar read one byte at a time: `len` in `5..=21`, `vol-`, then lowercase hexadecimal digits up to
/// `len` and zero bytes after it.
fn volume_grammar(len: u8, name: &[u8; MAX_VOLUME_LEN]) -> bool {
    let used = usize::from(len);
    let digit = |c: u8| c.is_ascii_digit() || (b'a'..=b'f').contains(&c);
    (5..=MAX_VOLUME_LEN).contains(&used)
        && name.starts_with(b"vol-")
        && name
            .iter()
            .enumerate()
            .skip(4)
            .all(|(at, &c)| match at < used {
                true => digit(c),
                false => c == 0,
            })
}

/// The lane check of a volume field agrees with the bytewise grammar for every length byte and for every value of
/// every name byte in a valid name of that length, so each lane, the last byte and the prefix are checked on their
/// own; `is_volume` agrees with the grammar on the name each field's first bytes spell and refuses longer names.
#[test]
fn the_volume_field_check_agrees_with_the_bytewise_grammar_at_every_length_and_byte() {
    agrees_with_the_bytewise_grammar(is_volume_field);
    assert!(is_volume("vol-0123456789abcdef0"));
    assert!(!is_volume("vol-0123456789abcdef01"));
}

/// Compares `field` with [`volume_grammar`] at every length byte, for every value of every byte of a field that
/// holds `vol-` and hexadecimal digits up to that length, and compares `is_volume` with the grammar on the first
/// bytes of each field that are UTF-8.
fn agrees_with_the_bytewise_grammar(field: impl Fn(u8, &[u8; MAX_VOLUME_LEN]) -> bool) {
    for len in 0..=u8::MAX {
        let used = usize::from(len);
        let mut name = [0; MAX_VOLUME_LEN];
        name[..4].copy_from_slice(b"vol-");
        for (at, byte) in name.iter_mut().enumerate().skip(4) {
            if at < used {
                *byte = b"0123456789abcdef"[at % 16];
            }
        }
        assert_eq!(
            field(len, &name),
            (5..=MAX_VOLUME_LEN).contains(&used),
            "len {len}"
        );
        for at in 0..MAX_VOLUME_LEN {
            for byte in 0..=u8::MAX {
                let mut changed = name;
                changed[at] = byte;
                assert_eq!(
                    field(len, &changed),
                    volume_grammar(len, &changed),
                    "len {len} byte {at} = {byte:#04x}"
                );
                let mut padded = [0; MAX_VOLUME_LEN];
                let text = &changed[..used.min(MAX_VOLUME_LEN)];
                padded[..text.len()].copy_from_slice(text);
                if let Ok(text) = core::str::from_utf8(text) {
                    let want = volume_grammar(text.len() as u8, &padded);
                    assert_eq!(is_volume(text), want, "name {text:?}");
                }
            }
        }
    }
}

/// A lane check that omits the term clearing a lane whose own bit 7 is set, so a digit byte with bit 7 added
/// counts as a digit. The first such field the comparison reaches is `vol-` followed by `0xb0` at length 5, which
/// the bytewise grammar refuses.
#[test]
#[should_panic(expected = "len 5 byte 4 = 0xb0\n  left: true\n right: false")]
fn negative_control_a_lane_check_that_keeps_a_high_bit_lane_admits_a_non_digit_byte() {
    agrees_with_the_bytewise_grammar(|len, name| {
        const fn lanes(byte: u8) -> u128 {
            u128::from_ne_bytes([byte; 16])
        }
        const HIGH: u128 = lanes(0x80);
        let digits = u32::from(len).wrapping_sub(4);
        let w = u128::from_le_bytes(core::array::from_fn(|at| name[4 + at]));
        let last = name[MAX_VOLUME_LEN - 1];
        let v = w & lanes(0x7F);
        let hex = ((v.wrapping_add(lanes(0x50)) & !v.wrapping_add(lanes(0x46)))
            | (v.wrapping_add(lanes(0x1F)) & !v.wrapping_add(lanes(0x19))))
            & HIGH;
        let used = match digits {
            0..16 => (1 << (8 * digits)) - 1,
            _ => u128::MAX,
        };
        let last_ok = match digits {
            17 => last.wrapping_sub(b'0') < 10 || last.wrapping_sub(b'a') < 6,
            _ => last == 0,
        };
        (1..=17).contains(&digits)
            && name[..4] == *b"vol-"
            && (hex | !used) & HIGH == HIGH
            && w & !used == 0
            && last_ok
    });
}
