//! Root blocks and the attach-time choice they decide: the root codec, the probe of one root slot, and the decision over both slots that checks the tenure's session against them and orders its RESET writes.
//!
//! A root's payload, after the block header, holds little-endian the content incarnation, the required journal range as the half-open `[S, D)` with `S` then `D`, the generation's 24-byte clock contract, and the feed's 16-byte authority and `u32` contract reference; the encoder writes zero to the bytes between the feed contract and the block's last eight bytes, and the decoder reads none of them, so a root of this version may hold any bytes there.
//! The header's writer generation and role sequence are the root's generation and root sequence, and roots order by `(generation, root sequence)`.
//! A RESET root under the tenure's session `s` carries generation `s`, root sequence 0, content incarnation `s`, the empty range `[0, 0)`, the clock contract, and the feed contract.
//! The block's last eight bytes hold the root's history generation, the generation of the journal its range names, written as zero when it equals the root's generation; a root whose history generation differs from its generation is a continuation root.
//! The decoder returns the range and the contract bytes as written and admits `S <= D`; `S == D` is empty.

use std::ops::Range;

use super::super::coverage::FEED_LEN;
use super::super::portable::CONTRACT_LEN;
use super::super::record::Crc32c;
use super::MetadataOutcome;
use super::block::{self, FormatId, Header, Layout, PAYLOAD, Role, Undecodable, field};
use super::layout::{Slot, first_slot};
use super::session::Session;

const INCARNATION_AT: usize = PAYLOAD;
const START_AT: usize = PAYLOAD + 8;
const END_AT: usize = PAYLOAD + 16;
const CLOCK_AT: usize = PAYLOAD + 24;
const FEED_AT: usize = CLOCK_AT + CONTRACT_LEN;
const FEED_END: usize = FEED_AT + FEED_LEN;

// `block::seal` writes zero from the head's end to the trailer, so each root field before the history generation ends inside the head.
const _: () = assert!(FEED_END <= block::HEAD);

/// A decoded root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Root {
    pub(crate) generation: u64,
    pub(crate) sequence: u64,
    /// `history` is the generation whose journal blocks the range names: the root's own generation, or an older one for a continuation root.
    pub(crate) history: u64,
    /// The content incarnation: a RESET root writes its generation, [`decode`] refuses one above `history`, and [`decide`] compares it with the other decoded fields when both slots hold one ordinal.
    pub(crate) incarnation: u64,
    /// The required journal range `[S, D)`: `D` is one past the last durable journal block the root requires.
    pub(crate) journal: Range<u64>,
    /// The generation's clock contract, as [`ClockContract::encode`](super::super::portable::ClockContract) wrote it.
    pub(crate) clock: [u8; CONTRACT_LEN],
    /// The feed contract, as [`FeedContract::encode`](super::super::coverage::FeedContract) wrote it.
    pub(crate) feed: [u8; FEED_LEN],
}

impl Root {
    /// The RESET root of generation `generation` under the clock and feed contract bytes: root sequence 0, content incarnation `generation` and the empty journal range.
    pub(crate) fn reset(generation: u64, clock: [u8; CONTRACT_LEN], feed: [u8; FEED_LEN]) -> Self {
        Self {
            generation,
            sequence: 0,
            history: generation,
            incarnation: generation,
            journal: 0..0,
            clock,
            feed,
        }
    }
}

impl Slot {
    /// The slot's block index in the metadata prefix.
    pub(crate) fn block(self) -> u64 {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }

    pub(crate) fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// Encodes `root` of format `format` into `block`, the whole block of `slot` under `layout`.
///
/// # Panics
///
/// When `block.len()` differs from `layout.unit` or is shorter than the head and the trailer together.
pub(crate) fn encode(
    crc: Crc32c,
    layout: Layout,
    format: FormatId,
    root: &Root,
    slot: Slot,
    block: &mut [u8],
) {
    block[PAYLOAD..block::HEAD].fill(0);
    block[INCARNATION_AT..START_AT].copy_from_slice(&root.incarnation.to_le_bytes());
    block[START_AT..END_AT].copy_from_slice(&root.journal.start.to_le_bytes());
    block[END_AT..CLOCK_AT].copy_from_slice(&root.journal.end.to_le_bytes());
    block[CLOCK_AT..FEED_AT].copy_from_slice(&root.clock);
    block[FEED_AT..FEED_END].copy_from_slice(&root.feed);
    let history = if root.history == root.generation {
        0
    } else {
        root.history
    };
    let end = block.len();
    block[end - block::TRAILER..].copy_from_slice(&history.to_le_bytes());
    let header = Header {
        role: Role::Root,
        format,
        generation: root.generation,
        sequence: root.sequence,
        index: slot.block(),
    };
    block::seal(crc, layout, header, block);
}

/// Decodes the root `block` holds at `slot` under `layout`, with its format ID.
///
/// # Errors
///
/// `decode` propagates errors from [`block::open`] and returns `Invalid` when the range's start exceeds its end, the stored history generation is nonzero and either equals or exceeds `generation` or accompanies a nonzero `sequence`, or `incarnation` exceeds `history`. A stored history generation of zero represents `generation`.
pub(crate) fn decode(
    crc: Crc32c,
    layout: Layout,
    block: &[u8],
    slot: Slot,
) -> Result<(FormatId, Root), Undecodable> {
    let (format, generation, sequence) = block::open(crc, layout, block, Role::Root, slot.block())?;
    let journal =
        u64::from_le_bytes(field(block, START_AT))..u64::from_le_bytes(field(block, END_AT));
    let stored = u64::from_le_bytes(field(block, block.len() - block::TRAILER));
    let history = if stored == 0 { generation } else { stored };
    let incarnation = u64::from_le_bytes(field(block, INCARNATION_AT));
    if journal.start > journal.end
        || (stored != 0 && (stored >= generation || sequence != 0))
        || incarnation > history
    {
        return Err(Undecodable::Invalid);
    }
    let root = Root {
        generation,
        sequence,
        history,
        incarnation,
        journal,
        clock: field(block, CLOCK_AT),
        feed: field(block, FEED_AT),
    };
    Ok((format, root))
}

/// What a read of one root slot showed: `None` for a read whose terminal reported a failure or a stop, which shows nothing about the slot's contents, else the slot's decode.
pub(crate) type Probed = Option<Result<(FormatId, Root), Undecodable>>;

fn valid(probed: &Probed) -> Option<&(FormatId, Root)> {
    probed.as_ref()?.as_ref().ok()
}

/// The attach's bootstrap after both root slots were probed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    /// RESET under the tenure's session `session` and format `format`, writing `first` and then its other slot.
    Reset {
        format: FormatId,
        session: u64,
        first: Slot,
    },
    /// Both slots decode `Invalid`: only an explicit format writes to them.
    Unformatted,
    /// The bootstrap ends with this refusal and writes nothing.
    Refused(MetadataOutcome),
}

/// Decides the bootstrap from the probes of slots A and B, refusing in this order: an unreadable slot, A first; an unsupported version, A first; a recorded layout naming another block length or prefix; two format IDs; tied roots; a valid root at or above `session`.
/// With one valid slot or two, the RESET adopts the highest valid root's format ID, writes under `session`, and writes first to the slot without the highest root, or to A when both hold the same root.
pub(crate) fn decide(a: &Probed, b: &Probed, session: &Session) -> Decision {
    let (format, x, y) = match validate(a, b) {
        Err(outcome) => return Decision::Refused(outcome),
        Ok(None) => return Decision::Unformatted,
        Ok(Some(pair)) => pair,
    };
    let (p, q) = (ordinal(x), ordinal(y));
    let session = session.get();
    if p.into_iter().chain(q).any(|(root, _)| root >= session) {
        return Decision::Refused(MetadataOutcome::StaleSession);
    }
    Decision::Reset {
        format,
        session,
        first: first_slot(p, q),
    }
}

/// A root's `(generation, sequence)`, the order that ranks the two slots.
pub(crate) fn ordinal(root: Option<&Root>) -> Option<(u64, u64)> {
    root.map(|root| (root.generation, root.sequence))
}

/// A root pair that passed [`validate`]: the shared format ID and optional valid roots for slots A and B.
pub(crate) type Validated<'p> = (FormatId, Option<&'p Root>, Option<&'p Root>);

/// Validates the probes of slots A and B: returns the shared format ID with each slot's valid root, or `Ok(None)` when both slots decode `Invalid`; [`decide`] then refuses a valid root at or above the session.
///
/// # Errors
///
/// In this order: `SlotUnreadable` for an unreadable slot, A first; `Unsupported` for another version, A first; `FormatMismatch` for a recorded layout naming another block length or prefix, or for two format IDs; `TiedRoots` for two valid roots of equal `(generation, sequence)` that differ in a decoded field.
pub(crate) fn validate<'p>(
    a: &'p Probed,
    b: &'p Probed,
) -> Result<Option<Validated<'p>>, MetadataOutcome> {
    use MetadataOutcome::{FormatMismatch, SlotUnreadable, TiedRoots};
    let slots = [(Slot::A, a), (Slot::B, b)];
    if let Some(&(slot, _)) = slots.iter().find(|(_, probed)| probed.is_none()) {
        return Err(SlotUnreadable { slot });
    }
    for (slot, probed) in slots {
        if let Some(Err(Undecodable::Unsupported { version })) = *probed {
            return Err(MetadataOutcome::Unsupported { slot, version });
        }
    }
    if slots
        .iter()
        .any(|(_, probed)| matches!(probed, Some(Err(Undecodable::ForeignLayout))))
    {
        return Err(FormatMismatch);
    }
    let (x, y) = (valid(a), valid(b));
    let format = match (x, y) {
        (Some((f, _)), Some((g, _))) if f != g => return Err(FormatMismatch),
        (Some((format, _)), _) | (_, Some((format, _))) => *format,
        (None, None) => return Ok(None),
    };
    let (x, y) = (x.map(|(_, root)| root), y.map(|(_, root)| root));
    if let (Some(r), Some(s)) = (x, y)
        && ordinal(x) == ordinal(y)
        && r != s
    {
        return Err(TiedRoots);
    }
    Ok(Some((format, x, y)))
}
