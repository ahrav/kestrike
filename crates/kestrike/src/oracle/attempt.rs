//! Remote PUT vocabulary: the attempt serial, cumulative receipt, the
//! client's attempt outcome, the facts a pending or `Unknown` row leaves
//! unresolved, and the admissibility rules for PUT rows.
//!
//! The rows of one upload attempt, client and owner side, share one
//! operation identity. A PUT outcome describes that attempt only:
//! `Published` certifies that the attempt published, not that the label is
//! visible now or durable; `Failed` and `NotStarted` forbid the attempt
//! publishing; `Unknown` leaves publication open. A pending attempt, one
//! with no result at the history cut, records the same open publication
//! and its open terminal instead of inventing either. Receipt, grant and
//! write rows carry no PUT or effect outcome, so a full receipt or a write
//! completion alone leaves publication and durability unresolved.

use std::collections::HashSet;
use std::num::NonZeroU64;

use super::action::ActionKind;
use super::custody::Custodian;
use super::ids::{OpId, ResourceKind};
use super::outcome::Outcome;
use super::row::{Field, Row};

/// The custodian a source slot's fragment retention names.
const RETAINED: Option<Custodian> = Some(Custodian::Retransmission);

/// Largest payload one validated fragment row may carry.
pub(crate) const FRAGMENT_BYTES: usize = 8192;

/// Largest number of fragments a grant may admit above the receipt base;
/// a READY's grant counts from base zero.
pub(crate) const MAX_WINDOW: u32 = 4096;

/// Fragments of a manifest: `ceil((metadata + body) / FRAGMENT_BYTES)`,
/// zero for an empty object.
pub(crate) fn fragment_count(metadata_len: u32, body_len: u64) -> u64 {
    (u64::from(metadata_len) + body_len).div_ceil(FRAGMENT_BYTES as u64)
}

/// The wire statuses a PUT ERROR carries. `UNKNOWN_OUTCOME_STATUS` ends an
/// attempt `Unknown`; every other status in the range ends it `Failed`.
pub(crate) const PUT_ERROR_STATUSES: std::ops::RangeInclusive<u16> = 1..=28;
pub(crate) const UNKNOWN_OUTCOME_STATUS: u16 = 24;

/// The fill serial the owner's authority named for one attempt. Authority,
/// READY, fragment, ACK and write-submit rows name it, and a `Published`
/// result names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Serial(pub(crate) NonZeroU64);

impl Serial {
    pub(crate) const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(serial) => Some(Self(serial)),
            None => None,
        }
    }
}

/// A cumulative receipt: every fragment below `base` was received, and bit
/// `i` of `mask` reports fragment `base + 1 + i` received out of order.
///
/// Among receipt fields, only `base` passing a fragment ends its
/// retransmission retention; a mask bit orders hole resends only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Receipt {
    pub(crate) base: u32,
    pub(crate) mask: u64,
}

/// The client's outcome for one upload attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PutOutcome {
    /// The owner reported that this attempt published.
    Published,
    /// The owner reported this typed status; the attempt did not publish.
    /// The status lies in `PUT_ERROR_STATUSES` and is never
    /// `UNKNOWN_OUTCOME_STATUS`, which the client records as `Unknown`.
    Failed(u16),
    /// The owner never saw the attempt's BEGIN.
    NotStarted,
    /// The attempt may have published; only a matching owner terminal
    /// resolves it.
    Unknown,
}

impl PutOutcome {
    pub(crate) const fn publication(self) -> Publication {
        match self {
            Self::Published => Publication::Certain,
            Self::Failed(_) | Self::NotStarted => Publication::Forbidden,
            Self::Unknown => Publication::Open,
        }
    }
}

/// Whether an attempt published, as its rows establish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Publication {
    /// The attempt published once.
    Certain,
    /// The attempt never published.
    Forbidden,
    /// Both owner outcomes remain permitted: the attempt published, or it
    /// did not.
    Open,
}

/// The facts a row declares unresolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Open {
    /// The row leaves nothing open.
    Settled,
    /// A `PutBegin` at the history cut: the attempt's terminal and its
    /// publication are both open.
    Pending,
    /// An `Unknown` result: the terminal is known, the publication is open.
    Publication,
}

impl Open {
    pub(crate) const fn terminal(self) -> bool {
        matches!(self, Self::Pending)
    }

    pub(crate) const fn publication(self) -> bool {
        matches!(self, Self::Pending | Self::Publication)
    }
}

impl ActionKind {
    /// Whether this kind records one step of a remote upload attempt.
    pub(crate) const fn is_remote_put(self) -> bool {
        matches!(
            self,
            Self::PutBegin
                | Self::Authority
                | Self::Ready
                | Self::Fragment
                | Self::Ack
                | Self::WriteSubmit
                | Self::PutResult
                | Self::Retry
                | Self::Abandon
        )
    }

    /// Whether a row of this kind may name the attempt's serial: the
    /// authority, the remote kinds after it except `Abandon`, and the
    /// owner's fill rows for a remote attempt.
    pub(crate) const fn admits_serial(self) -> bool {
        matches!(
            self,
            Self::Authority
                | Self::Ready
                | Self::Fragment
                | Self::Ack
                | Self::WriteSubmit
                | Self::PutResult
                | Self::Retry
                | Self::Fill
                | Self::Receive
                | Self::WriteCompleted
                | Self::Publish
                | Self::Replace
        )
    }
}

impl Row {
    /// Whether the attempt this row describes published, when the row
    /// records an attempt outcome: a pending `PutBegin` leaves it open, and a
    /// `PutResult` states it through its outcome.
    pub(crate) fn publication(&self) -> Option<Publication> {
        match (self.kind, self.outcome) {
            (ActionKind::PutBegin, _) if self.open == Open::Pending => Some(Publication::Open),
            (ActionKind::PutResult, Some(Outcome::Put(outcome))) => Some(outcome.publication()),
            _ => None,
        }
    }

    pub(crate) fn source_slot(&self) -> bool {
        self.resource()
            .is_some_and(|r| r.kind == ResourceKind::SourceSlot)
    }
}

/// The first field of a row that contradicts the PUT vocabulary.
///
/// A serial appears only on kinds `admits_serial` accepts. Retransmission
/// retention holds a source slot. A fragment index names a validated fragment
/// or a source slot's fragment, and every source-slot take and retention
/// release names one. A
/// fragment payload holds one to
/// `FRAGMENT_BYTES` bytes, and the body length of a `PutBegin` or of any row
/// naming a serial fits the wire's `u32`. A receipt appears only on an ACK, and a grant only on READY
/// or an ACK, within the inclusive range from the receipt base to the base
/// plus `MAX_WINDOW`, and a READY's grant within its manifest's fragment
/// count; every set receipt mask bit names a fragment below the grant. A `Published` result names its
/// label and serial, a `NotStarted` one names no serial, and a `Failed` one
/// names a PUT ERROR status other than `UNKNOWN_OUTCOME_STATUS`. Only a
/// `PutBegin` declares `Pending`, and only an `Unknown` result declares
/// `Publication`, which it always does.
pub(crate) fn malformed_put_field(row: &Row) -> Option<Field> {
    if row.serial.is_some() && !row.kind.admits_serial() {
        return Some(Field::Serial);
    }
    let source_slot = row.source_slot();
    if row.custodian == Some(Custodian::Retransmission) && !source_slot {
        return Some(Field::Custodian);
    }
    if source_slot
        && matches!(row.kind, ActionKind::Take | ActionKind::Release)
        && !matches!(
            row.custodian,
            Some(Custodian::Retransmission | Custodian::Nic)
        )
    {
        return Some(Field::Custodian);
    }
    let fragment_kind = row.kind == ActionKind::Fragment
        || (matches!(row.kind, ActionKind::Take | ActionKind::Release) && source_slot);
    match (row.fragment, fragment_kind) {
        (Some(_), false) => return Some(Field::Fragment),
        (None, _) if source_slot && (row.kind == ActionKind::Take || row.custodian == RETAINED) => {
            return Some(Field::Fragment);
        }
        _ => {}
    }
    if row.kind == ActionKind::Fragment
        && row
            .payload
            .as_ref()
            .is_some_and(|bytes| bytes.is_empty() || bytes.len() > FRAGMENT_BYTES)
    {
        return Some(Field::Payload);
    }
    if row.receipt.is_some() && row.kind != ActionKind::Ack {
        return Some(Field::Receipt);
    }
    if (row.kind == ActionKind::PutBegin || row.serial.is_some())
        && row.body_len.is_some_and(|len| len > u64::from(u32::MAX))
    {
        return Some(Field::BodyLength);
    }
    if let Some(grant) = row.grant {
        let base = row.receipt.map_or(0, |receipt| receipt.base);
        if !matches!(row.kind, ActionKind::Ready | ActionKind::Ack)
            || grant < base
            || grant - base > MAX_WINDOW
        {
            return Some(Field::Grant);
        }
        if row.kind == ActionKind::Ready
            && let (Some(metadata_len), Some(body_len)) = (row.metadata_len, row.body_len)
            && u64::from(grant) > fragment_count(metadata_len, body_len)
        {
            return Some(Field::Grant);
        }
        if let Some(receipt) = row.receipt {
            // Bit `i` names fragment `base + 1 + i`; a shift of 64 or more
            // would overflow, and every bit is granted then.
            let granted = grant.saturating_sub(receipt.base.saturating_add(1));
            if granted < u64::BITS && receipt.mask >> granted != 0 {
                return Some(Field::Receipt);
            }
        }
    }
    let result = match (row.kind, row.outcome) {
        (ActionKind::PutResult, Some(Outcome::Put(outcome))) => Some(outcome),
        _ => None,
    };
    match result {
        Some(PutOutcome::Published) if row.label.is_none() => return Some(Field::Label),
        Some(PutOutcome::Unknown) if row.serial.is_none() => return Some(Field::Serial),
        Some(PutOutcome::Published) if row.serial.is_none() => return Some(Field::Serial),
        Some(PutOutcome::NotStarted) if row.serial.is_some() => return Some(Field::Serial),
        Some(PutOutcome::Failed(status))
            if !PUT_ERROR_STATUSES.contains(&status) || status == UNKNOWN_OUTCOME_STATUS =>
        {
            return Some(Field::Outcome);
        }
        _ => {}
    }
    let permitted = match row.kind {
        ActionKind::PutBegin => matches!(row.open, Open::Settled | Open::Pending),
        _ if result == Some(PutOutcome::Unknown) => row.open == Open::Publication,
        _ => row.open == Open::Settled,
    };
    (!permitted).then_some(Field::Open)
}

/// The op of the first `PutResult` that contradicts another result of its
/// attempt. The client decides an attempt once, and a later reply replaces
/// only an `Unknown` outcome, so an attempt holds at most one `Published`,
/// `Failed` or `NotStarted` result. `Unknown` records a handed-off attempt
/// and `NotStarted` one the client never handed off, so the two never share
/// an attempt.
pub(crate) fn contradictory_result(rows: &[Row]) -> Option<OpId> {
    let results = rows.iter().filter_map(|r| match (r.kind, r.outcome) {
        (ActionKind::PutResult, Some(Outcome::Put(outcome))) => Some((r.op, outcome)),
        _ => None,
    });
    let unknown: HashSet<OpId> = results
        .clone()
        .filter(|&(_, outcome)| outcome == PutOutcome::Unknown)
        .map(|(op, _)| op)
        .collect();
    let mut resolved = HashSet::new();
    results
        .filter(|&(_, outcome)| outcome != PutOutcome::Unknown)
        .find(|&(op, outcome)| {
            (outcome == PutOutcome::NotStarted && unknown.contains(&op)) || !resolved.insert(op)
        })
        .map(|(op, _)| op)
}

/// The first PUT row whose declaration disagrees with its attempt's rows in
/// `rows`: a `PutBegin` that declares `Pending` while its attempt has a
/// result, or `Settled` while it has none, or an `Abandon` whose attempt has
/// no `Unknown` result. The client abandons only an `Unknown` attempt, so
/// that result is the row that keeps the abandoned publication open.
pub(crate) fn misstated_cut(rows: &[Row]) -> Option<OpId> {
    let mut ended = HashSet::new();
    let mut unknown = HashSet::new();
    for row in rows.iter().filter(|r| r.kind == ActionKind::PutResult) {
        ended.insert(row.op);
        if row.outcome == Some(Outcome::Put(PutOutcome::Unknown)) {
            unknown.insert(row.op);
        }
    }
    rows.iter()
        .find(|r| match r.kind {
            ActionKind::PutBegin => (r.open == Open::Pending) == ended.contains(&r.op),
            ActionKind::Abandon => !unknown.contains(&r.op),
            _ => false,
        })
        .map(|r| r.op)
}
