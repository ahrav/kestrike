//! The judge runs `parse` and the fixed-field reference decoder on one datagram and names how their outcomes relate as one [`Verdict`].
//!
//! `OverStrict`, `OverLenient` and `FieldsDiffer` are the failing verdicts. Reference acceptance establishes fixed-field validity only. A `FrameError::Field` refusal reports a field or body rule outside the fixed fields, so [`classify`] returns `Unjudged` when the reference accepts and `parse` returns that error. Any pair of refusals counts as agreement, whatever their reasons.

use crate::storage::Crc32c;

use super::frame::{Frame, FrameError, Header, parse};
use super::frame_reference::{self, BODY_START, Fields, Refusal};

/// How the outcome of `parse` on one datagram relates to the reference decoder's.
#[must_use = "a verdict judges nothing until its caller checks it"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Both accept with equal fields and body bytes when `accepted` is true; both refuse when it is false.
    Agree { accepted: bool },
    /// `parse` refuses, with an error other than [`FrameError::Field`], a datagram the reference accepts. Every error other than `Field`, a new `FrameError` variant included, lands here and fails until `classify` names it.
    OverStrict,
    /// `parse` accepts a datagram the reference refuses.
    OverLenient,
    /// `parse` and the reference decoder accept the input but disagree on a [`Fields`] member or a body byte.
    FieldsDiffer,
    /// `parse` refuses with [`FrameError::Field`] a datagram the reference accepts: the refusal names a field or body rule outside the fixed fields, such as a kind's header constraint, the client boot nonce's nonzero rule or a READY or ownership body.
    Unjudged,
}

/// Returns the [`Verdict`] for `parse`'s outcome beside the reference's. On reference acceptance, `reference` carries the decoded [`Fields`] and the body bytes the reference expects; [`Verdict::Agree`] with `accepted` true requires the frame's fields and the contents of its raw body to equal them.
pub fn classify(
    production: Result<Frame<'_>, FrameError>,
    reference: Result<(Fields, &[u8]), Refusal>,
) -> Verdict {
    match (production, reference) {
        (Ok(frame), Ok((fields, body))) => {
            if read(&frame) == fields && frame.raw_body() == body {
                Verdict::Agree { accepted: true }
            } else {
                Verdict::FieldsDiffer
            }
        }
        (Ok(_), Err(_)) => Verdict::OverLenient,
        (Err(FrameError::Field { .. }), Ok(_)) => Verdict::Unjudged,
        (Err(_), Ok(_)) => Verdict::OverStrict,
        (Err(_), Err(_)) => Verdict::Agree { accepted: false },
    }
}

/// Returns the [`Verdict`] of `parse` beside `reference` on `bytes` and `truncated`. The reference decodes the whole datagram, and the body it expects is the datagram's bytes from offset [`BODY_START`] on, empty for a datagram shorter than that.
pub fn judge_with(
    reference: fn(&[u8], bool) -> Result<Fields, Refusal>,
    crc: Crc32c,
    bytes: &[u8],
    truncated: bool,
) -> Verdict {
    let body = bytes.get(BODY_START..).unwrap_or_default();
    classify(
        parse(crc, bytes, truncated),
        reference(bytes, truncated).map(|fields| (fields, body)),
    )
}

/// [`judge`] uses [`frame_reference::decode`] as the reference decoder for one datagram and its transport-provided `truncated` flag.
pub fn judge(crc: Crc32c, bytes: &[u8], truncated: bool) -> Verdict {
    judge_with(frame_reference::decode, crc, bytes, truncated)
}

// Adding a field to `Header` makes this exhaustive pattern fail to compile.
fn read(frame: &Frame<'_>) -> Fields {
    let Header {
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
    } = frame.header();
    Fields {
        kind: kind as u8,
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
        body_crc: frame.body_crc(),
    }
}
