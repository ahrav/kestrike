//! Each delivery stays bound to its acquiring operation and the immutable
//! content the catalog records for its label.

use std::collections::HashMap;

use super::action::ActionKind;
use super::bounds::MAX_CONTENT_BYTES;
use super::content::{Geometry, expected_bytes, expected_stream};
use super::ids::{Incarnation, KeyId, Label, OpId, Ordinal, SessionId};
use super::obligation::Obligation;
use super::outcome::{Failure, Outcome};
use super::row::{Field, Row};
use super::verdict::{Activations, Inconclusive, Violation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    metadata_len: u32,
    body_len: u64,
    session: SessionId,
    incarnation: Incarnation,
}

#[derive(Debug, Default)]
pub(crate) struct Catalog {
    entries: HashMap<(KeyId, Label), Entry>,
    /// The invocation ordinal of the earliest acknowledged fill of each
    /// label, whatever order the rows arrive in; a session change that
    /// responds after it supersedes the label's content.
    written_at: HashMap<(KeyId, Label), Option<Ordinal>>,
}

const fn fail(obligation: Obligation, op: OpId, rule: &'static str) -> Violation {
    Violation {
        obligation,
        op,
        rule,
    }
}

impl Catalog {
    pub(crate) fn build(rows: &[&Row]) -> Result<Self, Inconclusive> {
        let mut entries = HashMap::new();
        let mut written_at = HashMap::new();
        // The session a fill runs under: the latest successful session
        // change before it, else the initial session, which the earliest
        // invoked acknowledged fill declared.
        let initial = rows
            .iter()
            .filter(|fill| {
                fill.kind == ActionKind::Fill && fill.outcome == Some(Outcome::Acknowledged)
            })
            .min_by_key(|fill| fill.invoked)
            .and_then(|fill| fill.session);
        let session_at = |invoked: Option<Ordinal>| {
            rows.iter()
                .filter(|change| {
                    change.kind == ActionKind::SessionChange
                        && change.outcome.is_none()
                        && change.responded < invoked
                })
                .max_by_key(|change| change.responded)
                .and_then(|change| change.session)
                .or(initial)
        };
        for row in rows.iter().filter(|r| {
            (r.kind == ActionKind::Fill && r.outcome == Some(Outcome::Acknowledged))
                || matches!(r.kind, ActionKind::Publish | ActionKind::Replace)
        }) {
            let (Some(key), Some(label)) = (row.key(), row.label) else {
                continue;
            };
            let malformed = |field| Inconclusive::Malformed { op: row.op, field };
            if row.kind == ActionKind::Fill {
                if let (Some(current), Some(declared)) = (session_at(row.invoked), row.session)
                    && current != declared
                {
                    return Err(malformed(Field::Session));
                }
                written_at
                    .entry((key, label))
                    .and_modify(|first: &mut Option<Ordinal>| *first = (*first).min(row.invoked))
                    .or_insert(row.invoked);
            }
            let source = if row.kind == ActionKind::Fill {
                row
            } else {
                rows.iter()
                    .find(|fill| {
                        fill.kind == ActionKind::Fill
                            && fill.op == row.op
                            && fill.key() == Some(key)
                            && fill.label == Some(label)
                    })
                    .copied()
                    .ok_or_else(|| malformed(Field::Label))?
            };
            let entry = Entry {
                metadata_len: source
                    .metadata_len
                    .ok_or_else(|| malformed(Field::MetadataLength))?,
                body_len: source
                    .body_len
                    .ok_or_else(|| malformed(Field::BodyLength))?,
                session: source.session.ok_or_else(|| malformed(Field::Session))?,
                incarnation: source
                    .incarnation
                    .ok_or_else(|| malformed(Field::Incarnation))?,
            };
            let total = u64::from(entry.metadata_len).saturating_add(entry.body_len);
            if total > MAX_CONTENT_BYTES as u64 {
                return Err(Inconclusive::DomainBound {
                    dimension: "content bytes",
                    limit: MAX_CONTENT_BYTES,
                    observed: usize::try_from(total).unwrap_or(usize::MAX),
                });
            }
            let completed = rows.iter().any(|done| {
                done.kind == ActionKind::WriteCompleted
                    && done.outcome.is_none()
                    && done.op == row.op
                    && done.key() == Some(key)
                    && done.label == Some(label)
            });
            if row.kind == ActionKind::Fill {
                let mut receives: Vec<&Row> = rows
                    .iter()
                    .copied()
                    .filter(|r| {
                        r.kind == ActionKind::Receive
                            && r.outcome.is_none()
                            && r.op == row.op
                            && r.key() == Some(key)
                            && r.label == Some(label)
                    })
                    .collect();
                receives.sort_by_key(|r| r.invoked);
                // Each fragment is compared against the label's content
                // stream, so the comparison holds no generated bytes, and a
                // run of fragments past the declared total is rejected before
                // any comparison.
                let total = usize::try_from(total).unwrap_or(usize::MAX);
                let declared: usize = receives
                    .iter()
                    .map(|r| r.payload.as_deref().unwrap_or_default().len())
                    .fold(0usize, usize::saturating_add);
                if declared > total || (completed && declared != total) {
                    return Err(malformed(Field::Payload));
                }
                let mut stream = expected_stream(key, label);
                let consistent = receives
                    .iter()
                    .flat_map(|r| r.payload.as_deref().unwrap_or_default())
                    .all(|&byte| stream.next() == Some(byte));
                if !consistent {
                    return Err(malformed(Field::Payload));
                }
            }
            if let Some(previous) = entries.insert((key, label), entry)
                && previous != entry
            {
                return Err(malformed(Field::Label));
            }
        }
        Ok(Self {
            entries,
            written_at,
        })
    }

    /// Whether a successful session change after the label's content was
    /// written and before `invoked` superseded that content.
    fn superseded(
        &self,
        rows: &[&Row],
        key: KeyId,
        label: Label,
        invoked: Option<Ordinal>,
    ) -> bool {
        let Some(&written_at) = self.written_at.get(&(key, label)) else {
            return false;
        };
        rows.iter().any(|change| {
            change.kind == ActionKind::SessionChange
                && change.outcome.is_none()
                && change.responded > written_at
                && change.responded < invoked
        })
    }
}

pub(crate) fn judge_deliveries(
    rows: &[&Row],
    catalog: &Catalog,
    geometry: Geometry,
    activations: &mut Activations,
) -> Result<(), Violation> {
    for delivery in rows.iter().filter(|row| row.kind == ActionKind::Deliver) {
        let (Some(key), Some(label)) = (delivery.key(), delivery.label) else {
            continue;
        };
        // The domain admitted this delivery against the hit lookup on its
        // operation, under that lookup's requested key and acquired label.
        let Some(lookup) = rows
            .iter()
            .find(|lookup| lookup.kind == ActionKind::Lookup && lookup.op == delivery.op)
        else {
            continue;
        };
        let payload = delivery.payload.as_deref().unwrap_or_default();
        let outcome = delivery.outcome.unwrap_or(Outcome::Complete);
        let Some(owner) = lookup.acquired_key() else {
            continue;
        };
        let Some(entry) = catalog.entries.get(&(owner, label)) else {
            return Err(fail(
                Obligation::Bytes,
                delivery.op,
                "delivered label has no content",
            ));
        };
        if delivery.metadata_len != Some(entry.metadata_len)
            || delivery.body_len != Some(entry.body_len)
        {
            return Err(fail(
                Obligation::Bytes,
                delivery.op,
                "delivered lengths differ from the label's content",
            ));
        }
        if delivery.session != Some(entry.session)
            || delivery.incarnation != Some(entry.incarnation)
        {
            return Err(fail(
                Obligation::Bytes,
                delivery.op,
                "delivered identity differs from the acquired content",
            ));
        }
        let examined_header = outcome == Outcome::Complete
            || matches!(outcome, Outcome::Damaged(Failure::ChunkMismatch { .. }));
        if catalog.superseded(rows, owner, label, delivery.invoked)
            && (examined_header || !payload.is_empty())
        {
            return Err(fail(
                Obligation::Bytes,
                delivery.op,
                "a delivery of content from a superseded session",
            ));
        }
        if owner != key {
            if !payload.is_empty() || outcome == Outcome::Complete {
                return Err(fail(
                    Obligation::Bytes,
                    delivery.op,
                    "a colliding candidate delivered another key's bytes",
                ));
            }
            if matches!(outcome, Outcome::Damaged(Failure::ChunkMismatch { .. })) {
                return Err(fail(
                    Obligation::Bytes,
                    delivery.op,
                    "a colliding candidate passed header verification",
                ));
            }
            if outcome.carries_information() {
                activations.activate(Obligation::Bytes);
            }
            if !delivery.refused_read() {
                activations.activate(Obligation::Contain);
            }
            continue;
        }
        // The delivery exposes at most its payload, so only that prefix of
        // the label's content is generated for the comparison.
        let total = entry.metadata_len as usize + entry.body_len as usize;
        let expected = expected_bytes(key, label, payload.len().min(total));
        judge_payload(delivery, outcome, payload, &expected, total, geometry)?;
        if outcome.carries_information() {
            activations.activate(Obligation::Bytes);
        }
        if outcome != Outcome::Complete && !delivery.refused_read() {
            activations.activate(Obligation::Contain);
        }
    }
    Ok(())
}

/// `expected` is the label's content truncated to the payload's length and
/// `total` is the content's full length.
fn judge_payload(
    delivery: &Row,
    outcome: Outcome,
    payload: &[u8],
    expected: &[u8],
    total: usize,
    geometry: Geometry,
) -> Result<(), Violation> {
    let op = delivery.op;
    let refused = delivery.refused_read();
    let prefix = payload.len() <= total && payload == expected;
    let (holds, obligation, rule) = match outcome {
        Outcome::Complete => (
            prefix && payload.len() == total,
            Obligation::Bytes,
            "a complete read returned bytes other than the label's content",
        ),
        Outcome::Damaged(Failure::HeaderMismatch) => (
            payload.is_empty(),
            Obligation::Contain,
            "bytes were exposed before a header mismatch",
        ),
        Outcome::Damaged(Failure::ChunkMismatch { index }) => (
            prefix
                && payload.len() < total
                && payload.len() == geometry.verified_prefix(index, total),
            Obligation::Contain,
            "bytes from a failed chunk or a later one were exposed",
        ),
        Outcome::NoInformation(_) if refused => (
            payload.is_empty(),
            Obligation::Contain,
            "a refused read exposed bytes",
        ),
        _ if !prefix => (
            false,
            Obligation::Contain,
            "a failed read exposed bytes outside the verified prefix",
        ),
        _ => (
            geometry.is_verified_boundary(payload.len(), total),
            Obligation::Contain,
            "a failed read exposed bytes past a verified chunk boundary",
        ),
    };
    if holds {
        Ok(())
    } else {
        Err(fail(obligation, op, rule))
    }
}
