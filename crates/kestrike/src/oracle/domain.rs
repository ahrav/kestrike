//! The per-key judgments accept a history only inside bounded keys, labels
//! and lease holders. The history has one episode, one key per label, one
//! family per operation, one row per operation for the kinds that respond
//! once, and one qualified persistence row per command within a profile,
//! identity and incarnation. The rows of one fill flow share one evidence
//! class. Each hit
//! lookup follows the lease lifecycle through its deliveries and its key
//! release.
//!
//! Every remote PUT row and every row naming a serial shares an operation
//! and evidence with one `PutBegin`, so the attempt judgment sees each
//! attempt whole; the operation belongs to the fill family. An attempt
//! publishes through one owner row, which that judgment checks. A history
//! outside the domain is Inconclusive.

use std::collections::{BTreeSet, HashMap, HashSet};

use super::action::ActionKind;
use super::bounds::{MAX_HOLDERS, MAX_KEYS, MAX_LABELS_PER_KEY};
use super::coverage::Cover;
use super::evidence::Evidence;
use super::history::{History, admit};
use super::ids::{KeyId, Label, OpId, Ordinal};
use super::outcome::Outcome;
use super::row::{Field, Row};
use super::tenure::{ActivationLog, Ordinals};
use super::verdict::Inconclusive;

/// Admits `history` to the per-key domain.
pub(crate) fn admitted(history: &History) -> Result<(), Inconclusive> {
    let admitted = admit(history)?;
    let rows: Vec<&Row> = admitted.rows().iter().collect();
    domain(
        &rows,
        ActivationLog::of(&rows).ok().as_ref(),
        admitted.ordinals(),
    )
}

/// Whether `released`, an outcome-free key release's response on `op`,
/// ended the lease: a refused read returns the lease whole when it responds,
/// so a release that responded while that read was in flight ended nothing.
pub(crate) fn release_ended_lease(rows: &[&Row], op: OpId, released: Ordinal) -> bool {
    rows.iter().all(|r| {
        r.op != op
            || !r.refused_read()
            || !(r.invoked < Some(released) && Some(released) < r.responded)
    })
}

/// The ordinal at which `lookup`'s lease ended: its consuming delivery's
/// custody end, else an outcome-free key release's response.
pub(crate) fn lease_end(rows: &[&Row], lookup: &Row) -> Option<Ordinal> {
    let same_op = rows.iter().filter(|r| r.op == lookup.op);
    let delivered = same_op
        .clone()
        .filter(|r| r.kind == ActionKind::Deliver && !r.refused_read())
        .filter_map(|r| r.custody_end)
        .min();
    delivered.or_else(|| {
        same_op
            .clone()
            .filter(|r| r.kind == ActionKind::Release && r.outcome.is_none())
            .filter_map(|r| {
                r.key()
                    .filter(|&k| Some(k) == lookup.key())
                    .and(r.responded)
            })
            .filter(|&released| release_ended_lease(rows, lookup.op, released))
            .min()
    })
}

/// Admits `rows` to the per-key domain. `log` is the history's activation
/// log, or `None` when the log is malformed, which reads every row as one
/// segment and leaves the log's refusal to the caller.
pub(crate) fn domain(
    rows: &[&Row],
    log: Option<&ActivationLog>,
    ordinals: Ordinals,
) -> Result<(), Inconclusive> {
    domain_within(rows, log, ordinals, Some(MAX_KEYS))
}

/// Admits `rows` under every rule of [`domain`] with no bound on the keys,
/// for a judgment that spans the keys of several per-key histories.
pub(crate) fn domain_across_keys(
    rows: &[&Row],
    log: Option<&ActivationLog>,
    ordinals: Ordinals,
) -> Result<(), Inconclusive> {
    domain_within(rows, log, ordinals, None)
}

/// The rules of [`domain`], with at most `keys` keys when it names a bound.
fn domain_within(
    rows: &[&Row],
    log: Option<&ActivationLog>,
    ordinals: Ordinals,
    keys: Option<usize>,
) -> Result<(), Inconclusive> {
    let begun: HashMap<(OpId, Evidence), Option<Ordinal>> = rows
        .iter()
        .filter(|r| r.kind == ActionKind::PutBegin)
        .map(|r| ((r.op, r.evidence), r.invoked))
        .collect();
    // Every row of an attempt follows the client's BEGIN that opened it.
    if let Some(unopened) = rows.iter().find(|r| {
        (r.kind.is_remote_put()
            || r.serial.is_some()
            || (matches!(
                r.kind,
                ActionKind::Take | ActionKind::Release | ActionKind::Cancel
            ) && r.source_slot()))
            && r.kind != ActionKind::PutBegin
            && begun
                .get(&(r.op, r.evidence))
                .is_none_or(|&opened| r.invoked.or(r.responded) <= opened)
    }) {
        return Err(Inconclusive::Malformed {
            op: unopened.op,
            field: Field::Invocation,
        });
    }
    let named: BTreeSet<_> = rows
        .iter()
        .flat_map(|r| [r.key(), r.candidate_key, r.owner].into_iter().flatten())
        .collect();
    if let Some(limit) = keys.filter(|&limit| named.len() > limit) {
        return Err(Inconclusive::DomainBound {
            dimension: "keys",
            limit,
            observed: named.len(),
        });
    }
    let Some(first) = rows.first() else {
        return Ok(());
    };
    let mut labels: HashMap<_, HashSet<_>> = HashMap::new();
    let mut owners: HashMap<Label, KeyId> = HashMap::new();
    for row in rows {
        if row.episode != first.episode {
            return Err(Inconclusive::Malformed {
                op: row.op,
                field: Field::Episode,
            });
        }
        let acquiring = rows
            .iter()
            .find(|lookup| lookup.kind == ActionKind::Lookup && lookup.op == row.op);
        let key = match (row.kind, acquiring) {
            (ActionKind::Lookup, _) => row.candidate_key.or(row.key()),
            (ActionKind::Take | ActionKind::Release, _) if row.resource().is_some() => row.owner,
            (ActionKind::Deliver | ActionKind::Release, Some(lookup)) => lookup.acquired_key(),
            _ => row.key(),
        };
        if let (Some(key), Some(label)) = (key, row.label) {
            if *owners.entry(label).or_insert(key) != key {
                return Err(Inconclusive::Malformed {
                    op: row.op,
                    field: Field::Label,
                });
            }
            let set = labels.entry(key).or_default();
            set.insert(label);
            if set.len() > MAX_LABELS_PER_KEY {
                return Err(Inconclusive::DomainBound {
                    dimension: "labels per key",
                    limit: MAX_LABELS_PER_KEY,
                    observed: set.len(),
                });
            }
        }
    }
    for kind in [
        ActionKind::Fill,
        ActionKind::Invalidate,
        ActionKind::WriteCompleted,
        ActionKind::Close,
        ActionKind::PutBegin,
    ] {
        let mut ops = HashSet::new();
        for row in rows.iter().filter(|r| r.kind == kind) {
            if !ops.insert(row.op) {
                return Err(Inconclusive::Malformed {
                    op: row.op,
                    field: Field::Invocation,
                });
            }
        }
    }
    let mut commands = HashSet::new();
    for row in rows.iter().filter(|r| r.kind == ActionKind::Persistence) {
        if let Evidence::Qualified(qualified) = row.evidence
            && !commands.insert((
                qualified.profile,
                qualified.identity,
                qualified.incarnation,
                qualified.command,
            ))
        {
            return Err(Inconclusive::Malformed {
                op: row.op,
                field: Field::Evidence,
            });
        }
    }
    // A fill flow's rows share one evidence class: a live receive, write
    // completion or publication follows a live fill, and an abstract one
    // follows a fill under the same hypothesis.
    let admitted_before = |row: &Row, ordinal: Option<Ordinal>| {
        rows.iter().any(|fill| {
            fill.kind == ActionKind::Fill
                && fill.op == row.op
                && fill.key() == row.key()
                && fill.label == row.label
                && fill.evidence == row.evidence
                && fill.outcome == Some(Outcome::Acknowledged)
                && fill.responded < ordinal
        })
    };
    let receives = |op: OpId, evidence: Evidence| {
        rows.iter()
            .filter(move |r| r.kind == ActionKind::Receive && r.op == op && r.evidence == evidence)
    };
    // Every live publication row of an upload attempt reaches the attempt
    // judgment, which rejects a second acknowledged one; any other operation
    // publishes once.
    let mut publications = HashSet::new();
    for publication in rows
        .iter()
        .filter(|r| matches!(r.kind, ActionKind::Publish | ActionKind::Replace))
    {
        let received = receives(publication.op, publication.evidence)
            .all(|r| r.responded < publication.invoked);
        let judged = !publication.evidence.is_recovery()
            && begun.contains_key(&(publication.op, publication.evidence));
        let duplicate = !publications.insert(publication.op) && !judged;
        if duplicate || !admitted_before(publication, publication.invoked) || !received {
            return Err(Inconclusive::Malformed {
                op: publication.op,
                field: Field::Invocation,
            });
        }
    }
    for done in rows.iter().filter(|r| r.kind == ActionKind::WriteCompleted) {
        let header = receives(done.op, done.evidence).any(|r| r.outcome.is_none());
        if !admitted_before(done, done.responded)
            || !header
            || !receives(done.op, done.evidence).all(|r| r.responded < done.responded)
        {
            return Err(Inconclusive::Malformed {
                op: done.op,
                field: Field::Response,
            });
        }
    }
    // A receive after an acknowledged invalidation of its key is malformed
    // only when that invalidation revoked the fill outright in the
    // receive's own segment. An interval invalidation revokes only the
    // versions it covers and another tenure's invalidation leaves this
    // tenure's fill flow running, so a receive after either is admitted and
    // the key model judges the fill's publication. Per-client ordinals
    // order the rows of one client only, so the order holds between rows
    // of one client there.
    let same_segment = |a: &Row, b: &Row| log.is_none_or(|log| log.tag(a) == log.tag(b));
    let ordered = |a: &Row, b: &Row| ordinals == Ordinals::Shared || a.client == b.client;
    for receive in rows.iter().filter(|r| r.kind == ActionKind::Receive) {
        let overlapping = receives(receive.op, receive.evidence)
            .any(|other| other.invoked < receive.invoked && receive.invoked < other.responded);
        let revoked = receive.outcome.is_none()
            && rows.iter().any(|invalidate| {
                invalidate.kind == ActionKind::Invalidate
                    && invalidate.outcome == Some(Outcome::Acknowledged)
                    && !matches!(invalidate.covers, Some(Cover::Range { .. }))
                    && same_segment(invalidate, receive)
                    && ordered(invalidate, receive)
                    && invalidate.evidence == receive.evidence
                    && invalidate.key() == receive.key()
                    && invalidate.responded < receive.invoked
                    && admitted_before(receive, invalidate.invoked)
            });
        if !admitted_before(receive, receive.invoked) || overlapping || revoked {
            return Err(Inconclusive::Malformed {
                op: receive.op,
                field: Field::Invocation,
            });
        }
        if receive.outcome.is_some() && receive.payload.as_ref().is_some_and(|p| !p.is_empty()) {
            return Err(Inconclusive::Malformed {
                op: receive.op,
                field: Field::Payload,
            });
        }
    }
    let mut families: HashMap<OpId, u8> = HashMap::new();
    for row in rows {
        let family = match row.kind {
            ActionKind::Fill
            | ActionKind::Receive
            | ActionKind::WriteCompleted
            | ActionKind::Publish
            | ActionKind::Replace => 0,
            ActionKind::Lookup | ActionKind::Deliver => 1,
            ActionKind::Release if row.key().is_some() => 1,
            ActionKind::Invalidate => 2,
            ActionKind::Close => 3,
            _ if row.kind.is_remote_put() => 0,
            _ => continue,
        };
        if *families.entry(row.op).or_insert(family) != family {
            return Err(Inconclusive::Malformed {
                op: row.op,
                field: Field::Invocation,
            });
        }
    }
    // Lease accounting reads live evidence only; recovery rows are judged
    // within their hypothesis or qualified profile and hold no lease.
    let live: Vec<&Row> = rows
        .iter()
        .copied()
        .filter(|r| !r.evidence.is_recovery())
        .collect();
    let acquiring_lookup = |op: OpId| {
        live.iter().copied().find(|lookup| {
            lookup.kind == ActionKind::Lookup
                && lookup.op == op
                && lookup.outcome == Some(Outcome::Hit)
        })
    };
    let key_releases = |op: OpId| {
        live.iter()
            .copied()
            .filter(move |r| r.kind == ActionKind::Release && r.op == op && r.outcome.is_none())
            .filter(|r| r.key().is_some())
    };
    // A delivery reads the lease a hit lookup returned: it names that
    // lookup's requested key and acquired label, follows the lookup's
    // response and the response of any refused read that held the lease,
    // and precedes any effective release or other consuming delivery of
    // the lease.
    for delivery in live.iter().filter(|r| r.kind == ActionKind::Deliver) {
        let malformed = Inconclusive::Malformed {
            op: delivery.op,
            field: Field::Invocation,
        };
        let Some(lookup) = acquiring_lookup(delivery.op) else {
            return Err(malformed);
        };
        if delivery.invoked <= lookup.responded {
            return Err(malformed);
        }
        if delivery.key() != lookup.key() {
            return Err(Inconclusive::Malformed {
                op: delivery.op,
                field: Field::Key,
            });
        }
        if delivery.label != lookup.label {
            return Err(Inconclusive::Malformed {
                op: delivery.op,
                field: Field::Label,
            });
        }
        let during_refused_read = live.iter().any(|read| {
            read.kind == ActionKind::Deliver
                && read.op == delivery.op
                && read.refused_read()
                && read.invoked < delivery.invoked
                && delivery.invoked < read.responded
        });
        let consumed = live.iter().any(|read| {
            read.kind == ActionKind::Deliver
                && read.op == delivery.op
                && !read.refused_read()
                && read.invoked < delivery.invoked
        });
        let released = key_releases(delivery.op).any(|release| {
            release.responded < delivery.invoked
                && release
                    .responded
                    .is_some_and(|released| release_ended_lease(&live, delivery.op, released))
        });
        if during_refused_read || consumed || released {
            return Err(malformed);
        }
    }
    // A key release names the requested key of the live hit lookup on its
    // operation, once per lookup, after the lookup responded and outside any
    // consuming delivery.
    for release in rows
        .iter()
        .filter(|r| r.kind == ActionKind::Release && r.outcome.is_none())
    {
        let Some(key) = release.key() else {
            continue;
        };
        if release.evidence.is_recovery() {
            continue;
        }
        let Some(lookup) = acquiring_lookup(release.op) else {
            return Err(Inconclusive::Malformed {
                op: release.op,
                field: Field::Response,
            });
        };
        if lookup.key() != Some(key) {
            return Err(Inconclusive::Malformed {
                op: release.op,
                field: Field::Key,
            });
        }
    }
    let mut lookups = HashSet::new();
    let mut events = Vec::new();
    for lookup in rows.iter().filter(|r| r.kind == ActionKind::Lookup) {
        if !lookups.insert(lookup.op) {
            return Err(Inconclusive::Malformed {
                op: lookup.op,
                field: Field::Invocation,
            });
        }
        if lookup.evidence.is_recovery() {
            continue;
        }
        let releases = key_releases(lookup.op).count();
        if releases > 1 {
            return Err(Inconclusive::Malformed {
                op: lookup.op,
                field: Field::Response,
            });
        }
        if lookup.outcome != Some(Outcome::Hit) {
            continue;
        }
        let early_release = key_releases(lookup.op).any(|r| {
            r.responded < lookup.responded
                || live.iter().any(|read| {
                    read.kind == ActionKind::Deliver
                        && read.op == lookup.op
                        && !read.refused_read()
                        && read.invoked < r.responded
                        && r.responded < read.custody_end
                })
        });
        if early_release {
            return Err(Inconclusive::Malformed {
                op: lookup.op,
                field: Field::Response,
            });
        }
        events.push((lookup.responded, true, lookup.op));
        if let Some(end) = lease_end(&live, lookup) {
            events.push((Some(end), false, lookup.op));
        }
    }
    events.sort_by_key(|&(ordinal, _, _)| ordinal);
    let mut holders = HashSet::new();
    for (_, acquired, op) in events {
        if acquired {
            holders.insert(op);
        } else {
            holders.remove(&op);
        }
        if holders.len() > MAX_HOLDERS {
            return Err(Inconclusive::DomainBound {
                dimension: "holders",
                limit: MAX_HOLDERS,
                observed: holders.len(),
            });
        }
    }
    Ok(())
}
