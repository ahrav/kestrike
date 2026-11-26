//! Actual volume loss, kept apart from host loss. The reconciler names a replacement volume only on the control
//! plane's evidence that the shard's active volume is lost, and holds for an operator's diagnosis when another volume
//! of the AZ shows impairment or loss at the same time. Host loss, a failed Report and delayed metadata damage are
//! inputs of the takeover and restart paths, and this decision reads only volume health.
//!
//! - LOSS-NEEDS-EVIDENCE: [`decide`] returns [`Decision::Provision`] only for [`Health::Lost`] of the shard
//!   record's active volume while no other volume of the AZ is impaired or lost; an available or impaired volume,
//!   and evidence about any other volume, retain it.
//! - CORRELATED-HOLD: a loss beside another impaired or lost volume of the AZ, or at the last generation a session
//!   activates, returns [`Decision::Hold`]. `Reconciler::replacement` latches an unreleased [`Receipt`] of that
//!   replacement held at its [`Phase`], and a create step that reads a held receipt refuses before its provider call,
//!   whatever later evidence for that replacement shows, until
//!   `Reconciler::release_hold`, the operator's write after diagnosis, which clears the hold
//!   and marks it released. [`Receipt::succeeds`] admits a same-generation clear of the hold only in
//!   that write, the one that marks the receipt released. A released receipt stays unheld for every later attempt of
//!   its replacement. `Reconciler::create_replacement` and `Reconciler::abandon` open the next attempt held beside
//!   another impaired or lost volume of the AZ unless the receipt is released. A loss observed alone provisions at
//!   once; the count of other impaired volumes is one observation. `Reconciler::create_replacement` latches the hold
//!   itself when it is passed another impaired or lost volume over an unreleased receipt. `Reconciler::add_spare` and
//!   `Reconciler::flip` refuse while the receipt holds the volume they name or activate; a hold that latches after
//!   their receipt read does not stop the write that follows it. A decision for a later generation starts that
//!   generation's receipt from its own evidence.
//! - CREATE-AFTER-ISSUE: `Reconciler::create_replacement` reads the receipt, refuses a layout below the floor and an
//!   open receipt whose generation the shard record already holds, and commits [`Phase::Issued`] by an exact-version write
//!   before it calls the [`Provider`], so a hold that latched first fails that write's condition and no create
//!   reaches the provider from a read of a held receipt. A hold latched after the issue write moves the receipt off
//!   the read that step writes over, so the step's attempt raise or volume write fails its condition, and after the
//!   release the attempt repeats its token. Within one attempt the phase advances from `Open` to `Issued` to
//!   `Created` and keeps its place across a hold and its release, so an attempt whose create may have reached the
//!   provider stays `Issued` until the receipt records its volume.
//! - IDEMPOTENT-PROVISIONING: the shard's durable [`Receipt`] names the namespace, shard and generation of the
//!   replacement, the layout every attempt creates, and the attempt whose [`Receipt::token`] the create request
//!   carries, all written before the create, and the volume the create returned, written after its provisioned volume
//!   record. A reconciler that restarts reads the receipt: an issued attempt repeats the create under the same token
//!   and layout, which a [`Provider`] answers with the volume that token created, and a receipt that records the volume
//!   calls no provider and returns its volume record. A volume record of another value under the returned name refuses
//!   with the receipt still issued, so every repeat refuses the same way. Two events raise the attempt and so the
//!   token: a create refused for good with no volume made, [`CreateError::Failed`], and `Reconciler::abandon` after the
//!   recorded volume is retired on the caller's evidence of its failure. The provider judges each token alone, so a
//!   reconciler whose receipt read predates another's attempt raise still sends the earlier attempt's token; that
//!   create makes no volume while the provider retains that token's outcome ([`Provider`]). A provider that forgets a
//!   token answers a repeat of it with a new volume, so a first volume whose response was lost before the receipt
//!   recorded it is orphaned, and a stale attempt's repeat makes a volume no receipt records. A token never meets other
//!   parameters, since the receipt fixes the layout. The caller then runs `record_attach`, `add_spare` and `flip`
//!   to `g + 1`, and its owner activates by the fresh path at `E = 0`, a cold start distinct from the takeover of a
//!   retained volume. An issued attempt repeats its token when another volume's flip moved the shard record to its
//!   generation; the step records the returned volume and returns `Stale`. `Reconciler::replacement` starts a later
//!   generation's receipt only over a receipt that is not issued, so the receipt keeps the token until the volume it
//!   made is recorded.
//!   A create over a receipt that records its volume returns `Stale` once the shard record holds its generation.

use crate::failover::records::{
    CodecError, Layout, Namespace, Reader, Record, ShardRecord, SuccessorRule, VOLUME, VolumeId,
    head,
};
use crate::net::ownership::{Shard, ShardGeneration};

/// The control plane's evidence about one volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Available,
    Impaired,
    /// The control plane reports the volume's data lost.
    Lost,
}

/// The replacement volume of one shard generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub namespace: Namespace,
    pub shard: Shard,
    /// The generation the replacement becomes active at, one above the lost volume's.
    pub generation: ShardGeneration,
}

/// What the reconciler does about the shard's active volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Keep the volume active; the takeover and restart paths recover its hosts.
    Retain,
    Provision(Request),
    /// Provision nothing until an operator diagnoses the AZ: the replacement to latch the hold for, `None` at the
    /// last generation a replacement can activate, which admits no replacement.
    Hold(Option<Request>),
}

/// The decision for `record`'s active volume given `evidence`, the health the control plane reports for one volume,
/// while `others` other volumes of the AZ are impaired or lost. A replacement names a generation of at most
/// `2^32 - 2`, the last one a session activates.
pub fn decide(record: &ShardRecord, evidence: (VolumeId, Health), others: usize) -> Decision {
    if evidence != (record.active, Health::Lost) {
        return Decision::Retain;
    }
    let request = ShardGeneration::new(record.generation.get() + 1)
        .filter(|next| next.get() < u64::from(u32::MAX))
        .map(|generation| Request {
            namespace: record.namespace,
            shard: record.shard,
            generation,
        });
    match request {
        Some(request) if others == 0 => Decision::Provision(request),
        request => Decision::Hold(request),
    }
}

/// Why a provider's create returned no volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateError {
    /// The outcome is unknown; a repeat under the same token returns the volume it created, if any.
    Unknown,
    /// The create was refused for good and made no volume.
    Failed,
}

/// The volume provider. A create under a token it has seen returns that token's volume, a volume that failed after
/// its create included, or `Failed` when that attempt was refused and made no volume, and creates no second volume,
/// so the receipt records every volume a token made and only `Reconciler::retire` and `Reconciler::abandon` move past
/// it. The provider retains each token's outcome, a refusal included, while any reconciler can hold a receipt read
/// naming that token's attempt (IDEMPOTENT-PROVISIONING).
pub trait Provider {
    /// Creates a volume of `layout` for the create request `token`.
    ///
    /// # Errors
    ///
    /// [`CreateError`].
    fn create(&mut self, token: &str, layout: Layout) -> Result<VolumeId, CreateError>;
}

const RECEIPT_VERSION: u16 = 1;
/// A receipt's encoded length.
pub const RECEIPT_LEN: usize = 4 + 2 + 16 + 4 + 4 + 4 + 20 + 1 + 1 + 1 + VOLUME;

/// Where one attempt of a replacement stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// The attempt awaits its create's issue.
    Open,
    /// The create was issued under the attempt's token and its volume is not recorded.
    Issued,
    /// The attempt's create returned this volume.
    Created(VolumeId),
}

impl Phase {
    /// The volume the attempt's create returned, recorded in the receipt.
    pub fn volume(self) -> Option<VolumeId> {
        match self {
            Self::Created(volume) => Some(volume),
            Self::Open | Self::Issued => None,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Issued => 1,
            Self::Created(_) => 2,
        }
    }
}

/// One shard's replacement receipt: the replacement it is for, the layout every attempt creates, the attempt, its
/// [`Phase`], and whether the operator released a hold of this replacement. The encoding starts with the magic
/// `RPLC`. The encoding contains the format version, namespace, shard, generation, attempt, layout
/// `(M, K, S, N_max)`, phase byte, held and released flags, and volume field. The volume field stores
/// [`Phase::volume`] when present and zero otherwise. Multi-byte fields use big-endian encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub request: Request,
    pub layout: Layout,
    /// The create attempt, from 1.
    pub attempt: u32,
    pub phase: Phase,
    /// An operator hold keeps the replacement at its phase until release.
    pub held: bool,
    pub released: bool,
}

/// A token's length: the namespace's 32 hex digits, then three fields of a hyphen and 8 hex digits.
const TOKEN_LEN: usize = 32 + 3 * 9;

impl Receipt {
    /// The create request's idempotency token: the namespace, shard, generation and attempt in hex, 59 ASCII bytes.
    pub fn token(&self) -> String {
        let request = &self.request;
        let mut token = Vec::with_capacity(TOKEN_LEN);
        hex(&mut token, &request.namespace.bytes());
        let generation = request.generation.get() as u32;
        for field in [request.shard.get(), generation, self.attempt] {
            token.push(b'-');
            hex(&mut token, &field.to_be_bytes());
        }
        String::from_utf8(token).expect("hex digits and hyphens are ASCII")
    }
}

fn hex(out: &mut Vec<u8>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        out.extend([
            DIGITS[usize::from(byte >> 4)],
            DIGITS[usize::from(byte & 0xf)],
        ]);
    }
}

impl Record for Receipt {
    fn encode(&self) -> Vec<u8> {
        let mut out = head(b"RPLC", RECEIPT_VERSION, RECEIPT_LEN);
        out.extend(self.request.namespace.bytes());
        out.extend(self.request.shard.get().to_be_bytes());
        out.extend((self.request.generation.get() as u32).to_be_bytes());
        out.extend(self.attempt.to_be_bytes());
        out.extend(self.layout.units.to_be_bytes());
        out.extend(self.layout.slots.to_be_bytes());
        out.extend(self.layout.slot_units.to_be_bytes());
        out.extend(self.layout.entries.to_be_bytes());
        let phase = match self.phase {
            Phase::Open => 0,
            Phase::Issued => 1,
            Phase::Created(_) => 2,
        };
        out.push(phase);
        out.push(u8::from(self.held));
        out.push(u8::from(self.released));
        out.extend(self.phase.volume().map_or([0; VOLUME], |v| v.field()));
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() != RECEIPT_LEN {
            return Err(CodecError::Length);
        }
        let mut r = Reader::open(bytes, b"RPLC", RECEIPT_VERSION)?;
        let request = Request {
            namespace: Namespace::new(r.take()?).ok_or(CodecError::Field)?,
            shard: Shard::new(r.u32()?).ok_or(CodecError::Field)?,
            generation: ShardGeneration::new(r.u32()?.into())
                .filter(|g| g.get() < u64::from(u32::MAX))
                .ok_or(CodecError::Field)?,
        };
        let attempt = r.u32()?;
        if attempt == 0 {
            return Err(CodecError::Field);
        }
        let layout = Layout {
            units: r.u64()?,
            slots: r.u32()?,
            slot_units: r.u32()?,
            entries: r.u32()?,
        };
        let (tag, held) = (r.pick(&[0u8, 1, 2])?, r.pick(&[false, true])?);
        let released = r.pick(&[false, true])?;
        if held && released {
            return Err(CodecError::Flag);
        }
        let field = r.take::<VOLUME>()?;
        let volume = (field != [0; VOLUME])
            .then(|| VolumeId::from_field(&field).ok_or(CodecError::Field))
            .transpose()?;
        let phase = match (tag, volume) {
            (0, None) => Phase::Open,
            (1, None) => Phase::Issued,
            (2, Some(volume)) => Phase::Created(volume),
            (2, None) => return Err(CodecError::Field),
            _ => return Err(CodecError::Flag),
        };
        Ok(Self {
            request,
            layout,
            attempt,
            phase,
            held,
            released,
        })
    }

    /// A receipt preserves its namespace and shard; its generation is nondecreasing. Within one generation the layout
    /// and the release stay fixed and the attempt is nondecreasing. Within one attempt the phase is nondecreasing in
    /// the order `Open`, `Issued`, `Created`, and a recorded volume stays fixed. The hold clears exactly in the write
    /// that marks the receipt released.
    fn succeeds(&self, prior: &Self) -> Result<(), SuccessorRule> {
        let (next, old) = (&self.request, &prior.request);
        if next.namespace != old.namespace || next.shard != old.shard {
            return Err(SuccessorRule::Identity);
        }
        if next.generation < old.generation {
            return Err(SuccessorRule::State);
        }
        if next.generation > old.generation {
            return Ok(());
        }
        if self.layout != prior.layout {
            return Err(SuccessorRule::Layout);
        }
        let unheld = prior.held && !self.held;
        let releases = self.released && !prior.released;
        let lowered = self.attempt < prior.attempt;
        let regressed = self.attempt == prior.attempt
            && match prior.phase {
                Phase::Created(_) => self.phase != prior.phase,
                phase => self.phase.rank() < phase.rank(),
            };
        if lowered || regressed || (prior.released && !self.released) || unheld != releases {
            return Err(SuccessorRule::State);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "loss_tests.rs"]
pub(crate) mod tests;
