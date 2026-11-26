//! Checked identity values of the ownership protocol: extended host identifiers, volume IDs, ownership epochs, attachment incarnations, reservation keys and opaque issuer generations. A volume ID is `vol-` and 1 to 17 lowercase hexadecimal digits; a reservation key packs an epoch and an incarnation.
//!
//! Every instance holds an in-range value, so a zero or reserved field refuses at construction with the field it names. Key order is the order of the encoded `u64`: epoch first, then incarnation.
//!
//! [`is_az`] is the availability-zone name rule that host admission and a zone's reconciler configuration share.

use core::fmt;

/// The 128-bit extended host identifier of one attachment. The fresh path draws it unless a valid local record of the same binding and key incarnation has landed, and every later run and restart of the attachment uses the recorded value. The all-zero value refuses, because the device reports it for a controller with no identifier.
/// `VolumeRecord::enroll` keeps the host IDs of a volume record's enrolled pairs distinct.
/// The 8-byte alignment pads a Report [`Registrant`](super::evidence::Registrant) to 32 bytes, four whole 8-byte words.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(align(8))]
pub struct Exhid([u8; 16]);

impl Exhid {
    pub fn new(bytes: [u8; 16]) -> Result<Self, IdentityError> {
        if bytes == [0; 16] {
            return Err(IdentityError::ExhidZero);
        }
        Ok(Self(bytes))
    }

    pub fn bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for Exhid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Exhid({:02x?})", self.0)
    }
}

/// The key field a refusal names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Field {
    Epoch,
    Incarnation,
}

/// Why an identity value was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityError {
    ExhidZero,
    /// The field is zero.
    Zero(Field),
    /// The field is the reserved `0xFFFF_FFFF`.
    Reserved(Field),
}

fn checked(field: Field, value: u32) -> Result<u32, IdentityError> {
    match value {
        0 => Err(IdentityError::Zero(field)),
        0xFFFF_FFFF => Err(IdentityError::Reserved(field)),
        value => Ok(value),
    }
}

/// A reservation key's epoch in `1..=0xFFFF_FFFE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Epoch(u32);

impl Epoch {
    pub fn new(value: u32) -> Result<Self, IdentityError> {
        checked(Field::Epoch, value).map(Self)
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

/// An attachment incarnation in `1..=0xFFFF_FFFE`; the issuer allocates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Incarnation(u32);

impl Incarnation {
    pub fn new(value: u32) -> Result<Self, IdentityError> {
        checked(Field::Incarnation, value).map(Self)
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

pub const MAX_VOLUME_LEN: usize = 21;

/// Whether `name` is `vol-` and 1 to 17 lowercase hexadecimal digits.
pub fn is_volume(name: &str) -> bool {
    let mut field = [0; MAX_VOLUME_LEN];
    match field.get_mut(..name.len()) {
        Some(head) => {
            head.copy_from_slice(name.as_bytes());
            is_volume_field(name.len() as u8, &field)
        }
        None => false,
    }
}

/// Whether the first `len` bytes of `name` satisfy [`is_volume`] and every later byte is zero. The sixteen bytes
/// after `vol-` are checked as the lanes of one word and the last byte on its own.
pub(crate) fn is_volume_field(len: u8, name: &[u8; MAX_VOLUME_LEN]) -> bool {
    const fn lanes(byte: u8) -> u128 {
        u128::from_ne_bytes([byte; 16])
    }
    const HIGH: u128 = lanes(0x80);
    let digits = u32::from(len).wrapping_sub(4);
    let w = u128::from_le_bytes(core::array::from_fn(|at| name[4 + at]));
    let last = name[MAX_VOLUME_LEN - 1];
    // A lane's high bit is set exactly when its byte is in b'0'..=b'9' or b'a'..=b'f'. On the low seven bits,
    // adding 0x50 or 0x1F sets bit 7 from 0x30 or 0x61 up, and adding 0x46 or 0x19 sets it from 0x3A or 0x67 up.
    // Every sum is at most 0x7F + 0x50 = 0xCF, so each lane's carry stays in its bit 7, and `& !w` clears a lane
    // whose own bit 7 is set.
    let v = w & lanes(0x7F);
    let hex = ((v.wrapping_add(lanes(0x50)) & !v.wrapping_add(lanes(0x46)))
        | (v.wrapping_add(lanes(0x1F)) & !v.wrapping_add(lanes(0x19))))
        & !w
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
}

/// A name may consist entirely of hyphens.
pub fn is_az(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// An opaque generation from the issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Generation(pub u64);

/// A reservation key: the epoch in bits 63..32 and the incarnation in bits 31..0. The derived order compares the epoch first, which is the order of the encoded value. `VolumeRecord::enroll` keeps the keys of a volume record's enrolled pairs distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key {
    epoch: Epoch,
    incarnation: Incarnation,
}

impl Key {
    pub fn new(epoch: Epoch, incarnation: Incarnation) -> Self {
        Self { epoch, incarnation }
    }

    pub fn attachment(incarnation: Incarnation) -> Self {
        Self {
            epoch: Epoch(1),
            incarnation,
        }
    }

    /// Decodes a device key, checking the epoch field before the incarnation field.
    pub fn decode(raw: u64) -> Result<Self, IdentityError> {
        let epoch = Epoch::new((raw >> 32) as u32)?;
        let incarnation = Incarnation::new(raw as u32)?;
        Ok(Self { epoch, incarnation })
    }

    pub fn encode(self) -> u64 {
        (u64::from(self.epoch.0) << 32) | u64::from(self.incarnation.0)
    }

    pub fn epoch(self) -> Epoch {
        self.epoch
    }

    pub fn incarnation(self) -> Incarnation {
        self.incarnation
    }
}

#[cfg(kani)]
mod verification {
    use super::{Field, IdentityError, Key, MAX_VOLUME_LEN, is_volume_field};

    /// Over a symbolic length byte and 21 symbolic name bytes: the lane check admits exactly the fields whose first
    /// `len` bytes, `len` in `5..=21`, are `vol-` and lowercase hexadecimal digits and whose later bytes are zero.
    #[kani::proof]
    #[kani::unwind(22)]
    fn the_volume_field_check_admits_exactly_the_volume_grammar() {
        let (len, name): (u8, [u8; MAX_VOLUME_LEN]) = (kani::any(), kani::any());
        let used = usize::from(len);
        let mut bytewise = (5..=MAX_VOLUME_LEN).contains(&used) && name[..4] == *b"vol-";
        for (at, &c) in name.iter().enumerate().skip(4) {
            bytewise &= match at < used {
                true => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
                false => c == 0,
            };
        }
        kani::cover!(bytewise && used == 5);
        kani::cover!(bytewise && used == MAX_VOLUME_LEN);
        kani::cover!(!bytewise && (5..=MAX_VOLUME_LEN).contains(&used) && name[..4] == *b"vol-");
        assert_eq!(is_volume_field(len, &name), bytewise);
    }

    /// Over two symbolic raw keys: decode admits exactly the keys whose fields both lie in `1..=0xFFFF_FFFE`, round-trips each admitted key, names the epoch field first when both fields are out of range, and orders admitted keys as their raw values.
    #[kani::proof]
    fn the_key_codec_admits_exactly_the_usable_fields_and_keeps_raw_order() {
        let (raw, other): (u64, u64) = (kani::any(), kani::any());
        let (epoch, incarnation) = ((raw >> 32) as u32, raw as u32);
        let refusal = |field, value: u32| match value {
            0 => Some(IdentityError::Zero(field)),
            u32::MAX => Some(IdentityError::Reserved(field)),
            _ => None,
        };
        let expected = refusal(Field::Epoch, epoch).or(refusal(Field::Incarnation, incarnation));
        kani::cover!(expected.is_none());
        kani::cover!(expected == Some(IdentityError::Reserved(Field::Epoch)));
        kani::cover!(expected == Some(IdentityError::Zero(Field::Incarnation)));
        match (Key::decode(raw), expected) {
            (Ok(key), None) => {
                assert_eq!(key.encode(), raw);
                assert_eq!(
                    (key.epoch().get(), key.incarnation().get()),
                    (epoch, incarnation)
                );
                if let Ok(second) = Key::decode(other) {
                    assert_eq!(key.cmp(&second), raw.cmp(&other));
                }
            }
            (Err(error), Some(want)) => assert_eq!(error, want),
            (decoded, _) => panic!("decode returned {decoded:?} against the field rule"),
        }
    }
}
