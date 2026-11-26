//! Body codecs: READY's caps and serving tenure, and the ownership envelope of the six ownership kinds.
//!
//! Every multibyte field is big-endian at a fixed offset, and the codecs allocate nothing.
//!
//! - READY's body is [`ReadyBody::LEN`] bytes: the request-slot cap `u32` at 0 and the window cap `u32` at 4, as in the HELLO, CHALLENGE and CONFIRM body; the shard `u32` at 8; the tenure at 12, which is the shard generation `g` `u64` at 12, the activated epoch `a` `u32` at 20 and the owner's 16-byte host ID at 24.
//! - The ownership envelope is [`OwnershipBody::FIXED_LEN`] bytes followed by the volume name: the volume length `u8` at 0, the validity bits `u8` at 1, the volume state `u8` at 2 and a zero byte at 3; the shard `u32` at 4; the tenure at 8, laid out as READY's (`g` at 8, `a` at 16, host ID at 20); the Report age in microseconds `u64` at 36; the responder's host ID at 44; then the volume name, exactly the declared length.
//! - [`Kind::WhoHolds`] and [`Kind::Probe`] are queries and the other four ownership kinds are replies. A query has a zero responder, zero validity bits and a zero Report age; a reply names its responder.
//! - Absent parts have one encoding each: a volume length of zero with state zero, a tenure of all-zero bytes, and an all-zero responder. A present part is wholly valid: a canonical volume name with state active or retired, a tenure with a [`ShardGeneration`], an [`ActivatedEpoch`] and a nonzero host ID, and a nonzero responder. The Report bit requires a volume, and the Serving and Live bits require a tenure.
//! - READY names an activated tenure, `a >= 2`. An envelope may name a tenure with `a = 0`, a successor whose attempt has not activated.
//! - Decoding checks representation only. The authenticated consumer decides freshness and authority from the decoded values.
//! - A refusal names the first failing check in the documented order, and an encoder that refuses has written no byte of its destination.
//! - Each decoder accepts exactly the bodies its ordered checks accept. [`OwnershipBody::admits`] and [`ReadyBody::admits`] test a whole body from its loaded fields, and the ordered checks run only on a body they refuse, to name the first failure.
//! - [`OwnershipBody::encode`] checks `Volume` and the destination `Length` first, then validates the typed value in decoder order. It returns the first refusal before any write and writes bytes only after all checks pass.

use core::num::{NonZeroU32, NonZeroU64};

use super::frame::{Kind, array, be32, be64};
use super::session::Caps;
use crate::failover::identity::{Exhid, MAX_VOLUME_LEN, is_volume};

const SHARD_LEN: usize = 4;
const TENURE_LEN: usize = 28;
const IDENTITY_LEN: usize = SHARD_LEN + TENURE_LEN;
const READY_IDENTITY_AT: usize = 8;
const VOLUME_LEN_AT: usize = 0;
const VALIDITY_AT: usize = 1;
const STATE_AT: usize = 2;
const RESERVED_AT: usize = 3;
const IDENTITY_AT: usize = 4;
const AGE_AT: usize = IDENTITY_AT + IDENTITY_LEN;
const RESPONDER_AT: usize = AGE_AT + 8;
const VOLUME_AT: usize = RESPONDER_AT + 16;

const _: () = assert!(READY_IDENTITY_AT + IDENTITY_LEN == ReadyBody::LEN);
const _: () = assert!(VOLUME_AT == OwnershipBody::FIXED_LEN);

/// Why a body was refused. Each variant names the part that failed its check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipError {
    /// The kind is not an ownership kind.
    Kind,
    /// The body or the destination differs from the length its layout fixes: a short fixed part, a declared volume past the end, trailing bytes, or a destination of another length.
    Length,
    /// READY's caps are outside [`Caps::in_range`].
    Caps,
    /// The shard is zero.
    Shard,
    /// The tenure's bytes are not all zero and its generation or host ID is zero, its generation or epoch is outside its type's range, or READY's tenure is absent or not activated.
    Tenure,
    /// The volume name is outside the canonical grammar, or its state is not active or retired while the name is present, or nonzero while it is absent.
    Volume,
    /// A validity bit outside [`Validity::ALL`], any bit on a query, the Report bit without a volume, or the Serving or Live bit without a tenure.
    Flags,
    /// A nonzero Report age without [`Validity::REPORT`].
    ReportAge,
    /// A reply without a responder, or a query with one.
    Responder,
    /// The reserved byte is nonzero.
    Reserved,
}

/// Returns whether the last `len` bytes of `body` satisfy [`is_volume`]'s volume-name grammar.
#[inline(always)]
fn volume_bytes(body: &[u8], len: usize) -> bool {
    const WINDOW: usize = 24;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    const LOW: u64 = 0x7F7F_7F7F_7F7F_7F7F;
    const fn lanes(byte: u8) -> u64 {
        u64::from_ne_bytes([byte; 8])
    }
    let Some(window) = body.last_chunk::<WINDOW>() else {
        return false;
    };
    let start = body.len() - len;
    let prefix = body.get(start..start + 4) == Some(b"vol-");
    let mut invalid = 0u32;
    for (at, word) in window.as_chunks::<8>().0.iter().enumerate() {
        let w = u64::from_le_bytes(*word);
        let v = w & LOW;
        let ge30 = v.wrapping_add(lanes(0x50));
        let le39 = !v.wrapping_add(lanes(0x46));
        let ge61 = v.wrapping_add(lanes(0x1F));
        let le66 = !v.wrapping_add(lanes(0x19));
        let bad = !(((ge30 & le39) | (ge61 & le66)) & !w) & HIGH;
        let bits = ((bad >> 7).wrapping_mul(0x0102_0408_1020_4080) >> 56) as u32;
        invalid |= bits << (8 * at);
    }
    let first = (WINDOW + 4).wrapping_sub(len) as u32;
    (5..=MAX_VOLUME_LEN).contains(&len) && prefix && invalid.checked_shr(first).unwrap_or(0) == 0
}

/// A nonzero shard number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Shard(NonZeroU32);

impl Shard {
    pub fn new(value: u32) -> Option<Self> {
        NonZeroU32::new(value).map(Self)
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

/// A shard generation `g` in `1..2^32`, the range the record session `g·2^32 + a` holds; each generation flip raises it by one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShardGeneration(NonZeroU64);

impl ShardGeneration {
    pub fn new(value: u64) -> Option<Self> {
        NonZeroU64::new(value)
            .filter(|value| value.get() <= u64::from(u32::MAX))
            .map(Self)
    }

    pub fn get(self) -> u64 {
        self.0.get()
    }
}

/// The activated epoch `a = 2E` of the shard's attempt counter `E`: even and at most [`ActivatedEpoch::MAX`]. Zero names a tenure whose attempt has not activated; activated attempts have `a >= 2`, and candidate epochs, which are odd, never appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ActivatedEpoch(u32);

impl ActivatedEpoch {
    /// The largest activated epoch, `2E` for the largest attempt counter `E = 2^31 - 2`.
    pub const MAX: u32 = 0xFFFF_FFFC;

    pub fn new(value: u32) -> Option<Self> {
        (value.is_multiple_of(2) && value <= Self::MAX).then_some(Self(value))
    }

    pub fn get(self) -> u32 {
        self.0
    }

    /// Whether an attempt activated this tenure.
    pub fn is_activated(self) -> bool {
        self.0 != 0
    }
}

/// One tenure of a shard: its generation `g`, the activated epoch `a` and the owner's host ID. Consumers order tenures by `(g, a)`; two tenures with equal `(g, a)` and different host IDs conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tenure {
    pub generation: ShardGeneration,
    pub epoch: ActivatedEpoch,
    pub host: Exhid,
}

/// The session `g·2^32 + a` of generation `g` and epoch `a`. Sessions order as their `(g, a)` pairs do, generation
/// first, and distinct pairs have distinct sessions.
pub(crate) fn session_of(generation: u32, epoch: u32) -> u64 {
    (u64::from(generation) << 32) | u64::from(epoch)
}

/// Decodes the shard and the optional tenure at `b[at..at + 32]`.
fn identity(b: &[u8], at: usize) -> Result<(Shard, Option<Tenure>), OwnershipError> {
    let shard = Shard::new(be32(b, at)).ok_or(OwnershipError::Shard)?;
    let t = at + SHARD_LEN;
    if b[t..t + TENURE_LEN].iter().all(|&byte| byte == 0) {
        return Ok((shard, None));
    }
    let tenure = (|| {
        Some(Tenure {
            generation: ShardGeneration::new(be64(b, t))?,
            epoch: ActivatedEpoch::new(be32(b, t + 8))?,
            host: Exhid::new(array(b, t + 12)).ok()?,
        })
    })()
    .ok_or(OwnershipError::Tenure)?;
    Ok((shard, Some(tenure)))
}

fn put_identity(shard: Shard, tenure: Option<Tenure>, b: &mut [u8], at: usize) {
    b[at..at + SHARD_LEN].copy_from_slice(&shard.get().to_be_bytes());
    let t = at + SHARD_LEN;
    if let Some(tenure) = tenure {
        b[t..t + 8].copy_from_slice(&tenure.generation.get().to_be_bytes());
        b[t + 8..t + 12].copy_from_slice(&tenure.epoch.get().to_be_bytes());
        b[t + 12..t + TENURE_LEN].copy_from_slice(&tenure.host.bytes());
    }
}

/// READY's negotiated caps and the activated serving tenure the session binds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadyBody {
    pub caps: Caps,
    pub shard: Shard,
    pub tenure: Tenure,
}

impl ReadyBody {
    /// The exact body length.
    pub const LEN: usize = 40;

    /// # Errors
    ///
    /// `Length` unless `b` holds exactly [`ReadyBody::LEN`] bytes, then `Caps`, `Shard` and `Tenure` in that order.
    #[inline]
    pub fn decode(b: &[u8]) -> Result<Self, OwnershipError> {
        match Self::canonical(b) {
            Some(body) => Ok(body),
            None => Self::ordered(b),
        }
    }

    /// `canonical` builds the body from the fields [`ReadyBody::admits`] validated and returns `None` when validation fails.
    #[inline(always)]
    fn canonical(b: &[u8]) -> Option<Self> {
        if !Self::admits(b) {
            return None;
        }
        let b: &[u8; Self::LEN] = b.try_into().ok()?;
        let t = READY_IDENTITY_AT + SHARD_LEN;
        Some(Self {
            caps: Caps::from_body(array(b, 0)),
            shard: Shard::new(be32(b, READY_IDENTITY_AT))?,
            tenure: Tenure {
                generation: ShardGeneration::new(be64(b, t))?,
                epoch: ActivatedEpoch::new(be32(b, t + 8))?,
                host: Exhid::new(array(b, t + 12)).ok()?,
            },
        })
    }

    /// Whether [`ReadyBody::decode`] accepts `b`.
    #[inline(always)]
    pub(super) fn admits(b: &[u8]) -> bool {
        let Ok(b) = <&[u8; Self::LEN]>::try_from(b) else {
            return false;
        };
        let caps = Caps::from_body(array(b, 0));
        let t = READY_IDENTITY_AT + SHARD_LEN;
        let generation = be64(b, t);
        let epoch = be32(b, t + 8);
        caps.in_range()
            && be32(b, READY_IDENTITY_AT) != 0
            && generation.wrapping_sub(1) < u64::from(u32::MAX)
            && epoch.is_multiple_of(2)
            && epoch.wrapping_sub(2) <= ActivatedEpoch::MAX - 2
            && u128::from_ne_bytes(array(b, t + 12)) != 0
    }

    /// `ordered` applies [`ReadyBody::decode`]'s checks in their documented order and returns the first validation error.
    #[cold]
    #[inline(never)]
    pub(super) fn ordered(b: &[u8]) -> Result<Self, OwnershipError> {
        if b.len() != Self::LEN {
            return Err(OwnershipError::Length);
        }
        let caps = Caps::from_body(array(b, 0));
        if !caps.in_range() {
            return Err(OwnershipError::Caps);
        }
        let (shard, tenure) = identity(b, READY_IDENTITY_AT)?;
        Ok(Self {
            caps,
            shard,
            tenure: tenure
                .filter(|tenure| tenure.epoch.is_activated())
                .ok_or(OwnershipError::Tenure)?,
        })
    }

    /// # Errors
    ///
    /// `Caps` when a cap is out of range, `Tenure` when the tenure is not activated.
    pub fn encode(self) -> Result<[u8; Self::LEN], OwnershipError> {
        if !self.caps.in_range() {
            return Err(OwnershipError::Caps);
        }
        if !self.tenure.epoch.is_activated() {
            return Err(OwnershipError::Tenure);
        }
        let mut b = [0; Self::LEN];
        b[..8].copy_from_slice(&self.caps.body());
        put_identity(self.shard, Some(self.tenure), &mut b, READY_IDENTITY_AT);
        Ok(b)
    }
}

/// Closed validity bits. Each set bit asserts that one input of the responder's claim held when it emitted the body; the authenticated consumer decides what the claim licenses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity(u8);

impl Validity {
    /// The responder holds a certified Report for the named volume, and the Report age measures it.
    pub const REPORT: u8 = 1;
    /// The named tenure was in a Serving turn at the responder.
    pub const SERVING: u8 = 2;
    /// The responder's last observation in which both the shard-record read and the own volume's read returned a
    /// value named the tenure as the shard's current one, and no later returned read contradicted it; a read that
    /// returned no value leaves the bit as it was.
    pub const LIVE: u8 = 4;
    /// Every defined bit.
    pub const ALL: u8 = Self::REPORT | Self::SERVING | Self::LIVE;

    /// # Errors
    ///
    /// `Flags` when `bits` sets a bit outside [`Validity::ALL`].
    pub fn new(bits: u8) -> Result<Self, OwnershipError> {
        if bits & !Self::ALL != 0 {
            return Err(OwnershipError::Flags);
        }
        Ok(Self(bits))
    }

    pub fn bits(self) -> u8 {
        self.0
    }
}

/// A volume's state in the shard's records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VolumeState {
    Active = 1,
    Retired = 2,
}

/// A canonical volume name and its state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Volume<'a> {
    pub name: &'a str,
    pub state: VolumeState,
}

/// The envelope every ownership kind carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnershipBody<'a> {
    pub shard: Shard,
    /// The named volume, absent when the sender knows none, as on a query by shard.
    pub volume: Option<Volume<'a>>,
    /// The tenure the sender names: the shard's owner on a reply, the presented high-water on a query; absent when the sender knows none.
    pub tenure: Option<Tenure>,
    /// Microseconds from the submission of the responder's latest certified Report to the emission of this body, both read from the serving clock; zero unless [`Validity::REPORT`] is set.
    pub report_age_us: u64,
    /// The host that answers; absent on a query.
    pub responder: Option<Exhid>,
    pub validity: Validity,
}

impl<'a> OwnershipBody<'a> {
    /// The length of the fixed part before the volume name.
    pub const FIXED_LEN: usize = 60;

    /// The encoded length: the fixed part and the volume name.
    pub fn encoded_len(&self) -> usize {
        Self::FIXED_LEN + self.volume.map_or(0, |volume| volume.name.len())
    }

    /// Decodes the envelope of a frame of `kind`.
    ///
    /// # Errors
    ///
    /// `Kind` for a kind outside the ownership kinds, then the first failing check in this order: `Length`, `Flags` for the bit set and for a query, `Volume` for the state, `Reserved`, `Shard`, `Tenure`, `Flags` for a bit whose part is absent, `ReportAge`, `Responder`, `Volume` for the name, then `Length` for trailing bytes.
    #[inline]
    pub fn decode(kind: Kind, b: &'a [u8]) -> Result<Self, OwnershipError> {
        match Self::canonical(kind, b) {
            Some(body) => Ok(body),
            None => Self::ordered(kind, b),
        }
    }

    /// `canonical` builds the body from the fields [`OwnershipBody::admits`] validated and returns `None` when validation fails.
    #[inline(always)]
    fn canonical(kind: Kind, b: &'a [u8]) -> Option<Self> {
        if !Self::admits(kind, b) {
            return None;
        }
        let (fixed, name) = b.split_first_chunk::<{ OwnershipBody::FIXED_LEN }>()?;
        let t = IDENTITY_AT + SHARD_LEN;
        let volume = match fixed[STATE_AT] {
            0 => None,
            state => Some(Volume {
                name: core::str::from_utf8(name).ok()?,
                state: if state == VolumeState::Active as u8 {
                    VolumeState::Active
                } else {
                    VolumeState::Retired
                },
            }),
        };
        let tenure = match ShardGeneration::new(be64(fixed, t)) {
            None => None,
            Some(generation) => Some(Tenure {
                generation,
                epoch: ActivatedEpoch::new(be32(fixed, t + 8))?,
                host: Exhid::new(array(fixed, t + 12)).ok()?,
            }),
        };
        Some(Self {
            shard: Shard::new(be32(fixed, IDENTITY_AT))?,
            volume,
            tenure,
            report_age_us: be64(fixed, AGE_AT),
            responder: Exhid::new(array(fixed, RESPONDER_AT)).ok(),
            validity: Validity(fixed[VALIDITY_AT]),
        })
    }

    /// Whether [`OwnershipBody::decode`] accepts `b` for `kind`.
    #[inline(always)]
    pub(super) fn admits(kind: Kind, b: &[u8]) -> bool {
        let Some((fixed, name)) = b.split_first_chunk::<{ OwnershipBody::FIXED_LEN }>() else {
            return false;
        };
        let name_len = usize::from(fixed[VOLUME_LEN_AT]);
        let bits = fixed[VALIDITY_AT];
        let state = fixed[STATE_AT];
        let query = matches!(kind, Kind::WhoHolds | Kind::Probe);
        let t = IDENTITY_AT + SHARD_LEN;
        let generation = be64(fixed, t);
        let epoch = be32(fixed, t + 8);
        let host = u128::from_ne_bytes(array(fixed, t + 12));
        let named = generation | u64::from(epoch) != 0 || host != 0;
        let present = name_len != 0;
        let tenure_holds = !named
            || (generation.wrapping_sub(1) < u64::from(u32::MAX)
                && epoch.is_multiple_of(2)
                && epoch <= ActivatedEpoch::MAX
                && host != 0);
        kind.is_ownership()
            && name.len() == name_len
            && bits & !Validity::ALL == 0
            && !(query && bits != 0)
            && if present {
                state.wrapping_sub(1) < 2
            } else {
                state == 0
            }
            && fixed[RESERVED_AT] == 0
            && be32(fixed, IDENTITY_AT) != 0
            && tenure_holds
            && (present || bits & Validity::REPORT == 0)
            && (named || bits & (Validity::SERVING | Validity::LIVE) == 0)
            && (be64(fixed, AGE_AT) == 0 || bits & Validity::REPORT != 0)
            && (u128::from_ne_bytes(array(fixed, RESPONDER_AT)) != 0) != query
            && (!present || volume_bytes(b, name_len))
    }

    /// `ordered` applies [`OwnershipBody::decode`]'s checks in their documented order and returns the first validation error.
    #[cold]
    #[inline(never)]
    pub(super) fn ordered(kind: Kind, b: &'a [u8]) -> Result<Self, OwnershipError> {
        if !kind.is_ownership() {
            return Err(OwnershipError::Kind);
        }
        if b.len() < Self::FIXED_LEN {
            return Err(OwnershipError::Length);
        }
        let name_len = usize::from(b[VOLUME_LEN_AT]);
        let end = Self::FIXED_LEN + name_len;
        if end > b.len() {
            return Err(OwnershipError::Length);
        }
        let query = matches!(kind, Kind::WhoHolds | Kind::Probe);
        let validity = Validity::new(b[VALIDITY_AT])?;
        if query && validity.bits() != 0 {
            return Err(OwnershipError::Flags);
        }
        let state = match (name_len, b[STATE_AT]) {
            (0, 0) => None,
            (1.., 1) => Some(VolumeState::Active),
            (1.., 2) => Some(VolumeState::Retired),
            _ => return Err(OwnershipError::Volume),
        };
        if b[RESERVED_AT] != 0 {
            return Err(OwnershipError::Reserved);
        }
        let (shard, tenure) = identity(b, IDENTITY_AT)?;
        let bits = validity.bits();
        if (state.is_none() && bits & Validity::REPORT != 0)
            || (tenure.is_none() && bits & (Validity::SERVING | Validity::LIVE) != 0)
        {
            return Err(OwnershipError::Flags);
        }
        let report_age_us = be64(b, AGE_AT);
        if report_age_us != 0 && bits & Validity::REPORT == 0 {
            return Err(OwnershipError::ReportAge);
        }
        let responder = Exhid::new(array(b, RESPONDER_AT)).ok();
        if responder.is_some() == query {
            return Err(OwnershipError::Responder);
        }
        let volume = match state {
            None => None,
            Some(state) => {
                let name = core::str::from_utf8(&b[Self::FIXED_LEN..end])
                    .ok()
                    .filter(|name| is_volume(name))
                    .ok_or(OwnershipError::Volume)?;
                Some(Volume { name, state })
            }
        };
        if end != b.len() {
            return Err(OwnershipError::Length);
        }
        Ok(Self {
            shard,
            volume,
            tenure,
            report_age_us,
            responder,
            validity,
        })
    }

    /// Encodes the envelope of a frame of `kind` into `out`, which must hold exactly [`OwnershipBody::encoded_len`] bytes.
    ///
    /// # Errors
    ///
    /// Before any byte of `out` is written: `Volume` for a noncanonical name, `Length` for a destination of another length, then the refusal [`OwnershipBody::decode`] reports for the encoded bytes.
    pub fn encode(self, kind: Kind, out: &mut [u8]) -> Result<(), OwnershipError> {
        if self.volume.is_some_and(|volume| !is_volume(volume.name)) {
            return Err(OwnershipError::Volume);
        }
        if out.len() != self.encoded_len() {
            return Err(OwnershipError::Length);
        }
        if !kind.is_ownership() {
            return Err(OwnershipError::Kind);
        }
        let query = matches!(kind, Kind::WhoHolds | Kind::Probe);
        let bits = self.validity.bits();
        if (query && bits != 0)
            || (self.volume.is_none() && bits & Validity::REPORT != 0)
            || (self.tenure.is_none() && bits & (Validity::SERVING | Validity::LIVE) != 0)
        {
            return Err(OwnershipError::Flags);
        }
        if self.report_age_us != 0 && bits & Validity::REPORT == 0 {
            return Err(OwnershipError::ReportAge);
        }
        if self.responder.is_some() == query {
            return Err(OwnershipError::Responder);
        }
        let mut fixed = [0; Self::FIXED_LEN];
        if let Some(volume) = self.volume {
            fixed[VOLUME_LEN_AT] = volume.name.len() as u8;
            fixed[STATE_AT] = volume.state as u8;
        }
        fixed[VALIDITY_AT] = bits;
        put_identity(self.shard, self.tenure, &mut fixed, IDENTITY_AT);
        fixed[AGE_AT..RESPONDER_AT].copy_from_slice(&self.report_age_us.to_be_bytes());
        if let Some(responder) = self.responder {
            fixed[RESPONDER_AT..VOLUME_AT].copy_from_slice(&responder.bytes());
        }
        let (head, name) = out.split_at_mut(Self::FIXED_LEN);
        head.copy_from_slice(&fixed);
        name.copy_from_slice(self.volume.map_or(&[][..], |volume| volume.name.as_bytes()));
        Ok(())
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    const HOLDER: u8 = 0x01;
    const RESPONDER: u8 = 0x02;

    fn epoch_in_range(epoch: u32) -> bool {
        epoch % 2 == 0 && epoch <= 0xFFFF_FFFC
    }

    fn generation_in_range(generation: u64) -> bool {
        generation != 0 && generation < 1 << 32
    }

    #[kani::proof]
    #[kani::unwind(41)]
    fn ready_admits_exactly_bounded_caps_and_a_whole_tenure() {
        let b: [u8; ReadyBody::LEN] = kani::any();
        let slots = u32::from_be_bytes(array(&b, 0));
        let window = u32::from_be_bytes(array(&b, 4));
        let shard = u32::from_be_bytes(array(&b, 8));
        let generation = u64::from_be_bytes(array(&b, 12));
        let epoch = u32::from_be_bytes(array(&b, 20));
        let host: [u8; 16] = array(&b, 24);
        let valid = (1..=super::super::frame::MAX_SLOT_CAP).contains(&slots)
            && (1..=super::super::frame::MAX_WINDOW).contains(&window)
            && shard != 0
            && generation_in_range(generation)
            && epoch_in_range(epoch)
            && epoch != 0
            && host != [0; 16];
        let decoded = ReadyBody::decode(&b);
        assert_eq!(decoded.is_ok(), valid);
        if let Ok(body) = decoded {
            assert_eq!((body.caps.slots, body.caps.window), (slots, window));
            assert_eq!(body.shard.get(), shard);
            assert_eq!(body.tenure.generation.get(), generation);
            assert_eq!(body.tenure.epoch.get(), epoch);
            assert_eq!(body.tenure.host.bytes(), host);
            assert_eq!(body.encode().unwrap(), b);
        }
        kani::cover!(valid);
        kani::cover!(epoch == 0 && generation != 0);
        kani::cover!(slots > super::super::frame::MAX_SLOT_CAP);
    }

    #[kani::proof]
    #[kani::unwind(29)]
    fn ownership_fields_round_trip_at_every_byte_and_close_flags_state_and_reserved_bytes() {
        let query: bool = kani::any();
        let kind = if query { Kind::WhoHolds } else { Kind::Holder };
        let flags: u8 = kani::any();
        let state: u8 = kani::any();
        let reserved: u8 = kani::any();
        let shard: u32 = kani::any();
        let named: bool = kani::any();
        let generation: u64 = kani::any();
        let epoch: u32 = kani::any();
        let age: u64 = kani::any();
        let answered: bool = kani::any();
        let mut b = [0; OwnershipBody::FIXED_LEN + 5];
        b[VOLUME_LEN_AT] = 5;
        b[VALIDITY_AT] = flags;
        b[STATE_AT] = state;
        b[RESERVED_AT] = reserved;
        b[4..8].copy_from_slice(&shard.to_be_bytes());
        if named {
            b[8..16].copy_from_slice(&generation.to_be_bytes());
            b[16..20].copy_from_slice(&epoch.to_be_bytes());
            b[20..36].fill(HOLDER);
        }
        b[36..44].copy_from_slice(&age.to_be_bytes());
        if answered {
            b[44..60].fill(RESPONDER);
        }
        b[60..].copy_from_slice(b"vol-a");
        let valid = flags & !Validity::ALL == 0
            && (!query || flags == 0)
            && (state == 1 || state == 2)
            && reserved == 0
            && shard != 0
            && (!named || (generation_in_range(generation) && epoch_in_range(epoch)))
            && (named || flags & (Validity::SERVING | Validity::LIVE) == 0)
            && (age == 0 || flags & Validity::REPORT != 0)
            && answered != query;
        let decoded = OwnershipBody::decode(kind, &b);
        assert_eq!(decoded.is_ok(), valid);
        if let Ok(body) = decoded {
            assert_eq!(body.validity.bits(), flags);
            assert_eq!(body.volume.unwrap().state as u8, state);
            assert_eq!(body.volume.unwrap().name, "vol-a");
            assert_eq!(body.shard.get(), shard);
            assert_eq!(
                body.tenure
                    .map(|t| (t.generation.get(), t.epoch.get(), t.host.bytes())),
                named.then_some((generation, epoch, [HOLDER; 16]))
            );
            assert_eq!(body.report_age_us, age);
            assert_eq!(
                body.responder.map(Exhid::bytes),
                answered.then_some([RESPONDER; 16])
            );
            let mut out = [0; OwnershipBody::FIXED_LEN + 5];
            body.encode(kind, &mut out).unwrap();
            let byte: usize = kani::any();
            kani::assume(byte < b.len());
            assert_eq!(out[byte], b[byte]);
        }
        kani::cover!(valid && query);
        kani::cover!(valid && !named && state == 2);
        kani::cover!(flags & !Validity::ALL != 0);
    }
}
