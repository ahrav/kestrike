//! Retained sets across host loss. An activation that names a cut recovers
//! the entries that cut captured before it. A captured entry leaves the
//! retained set when the history places, below the activated tenure, an
//! acknowledged invalidation that covers it or an acknowledged publication
//! of another label of its key that takes effect after the entry's, at any
//! response ordinal, or a recorded expiry or logical eviction of it after
//! its capture and before the activation. An
//! invalidation the activated tenure linearizes before it restores the
//! entry, or anywhere in that tenure when it never restores it, also
//! removes it. An entry such an invalidation or publication
//! leaves in only some legal orders, or that a cancelled or timed-out one
//! that may still land may cover or supersede, is optional. Every required
//! entry is restored in the activated tenure from that cut unless a damage
//! row recorded before the tenure's first lookup names one of its units or
//! the whole volume; an eviction of it recorded in that tenure before any
//! restore is a stale refusal standing in for a recorded eviction. A restore
//! needs its entry captured in the cut it names, whether or not that cut
//! recorded any capture; the key model judges its coverage. Effects are
//! judged from live rows, as the key search reads them. A cancelled or
//! timed-out publication excuses an entry only when it can land: in its
//! fill's segment, among the segments whose close and deadline evidence
//! leave the publication's landing open, and with acknowledgments of its
//! label restricted to that publication. A covering invalidation that real
//! time or a clock sample orders between the fill and the landing closes
//! the publication's landing. Inside one
//! segment a publication supersedes the entry only when real time and that
//! segment's monotonic clock let it take effect after the entry's. An
//! invalidation excuses an entry only in a segment where no hit, expired
//! lookup, restore, expiry or eviction of a label it would cover, in a later
//! tenure or after its landing window in that segment, forces its
//! omission. An
//! invalidation in the activated tenure counts
//! before the entry's first restore there, or anywhere in that tenure when
//! it never restores the entry.
//! An activation that names no cut, or a cut with no recorded capture,
//! after a capture and without whole-volume damage before its first lookup
//! replaced the retained cut with a cold start, even when every later
//! lookup misses. Each judged required entry activates the restart
//! obligation. A row whose outcome carries no information records no
//! removal, restore, capture, damage or activation. A damage row naming one
//! of an entry's units stops excusing the entry once that unit was read
//! whole after it: a later restore of the entry for the row unit, a complete
//! delivery whose lookup began after the damage for the payload unit, each
//! before the judged activation or, for a restore, in its tenure. A row
//! naming the whole volume is never retired.
//! A restore reads the row unit on which the restore's cut captured the
//! entry, so a restore retires row-unit damage only when that cut captured
//! the entry on the damaged unit.

use super::action::ActionKind;
use super::candidates::landings;
use super::coverage::Cover;
use super::ids::{CutId, OpId, Ordinal, Tenure};
use super::obligation::Obligation;
use super::outcome::{Outcome, VisibilityCause};
use super::row::Row;
use super::tenure::{Activation, ActivationLog};
use super::verdict::{Activations, Violation};

const fn fail(op: OpId, rule: &'static str) -> Violation {
    Violation {
        obligation: Obligation::Restart,
        op,
        rule,
    }
}

/// The lowest and highest segments effect `row` may take hold in, or
/// `None` when no legal order lets it take hold. An acknowledged effect
/// takes hold in its own segment. A cancelled or timed-out publication
/// lands only in its fill's segment, among its landings, while that fill is
/// unrevoked; an acknowledged publication causes every other publication
/// with the same label to be refused. A cancelled or timed-out invalidation
/// lands wherever no hit, expired lookup, restore, expiry or eviction of a
/// label it would cover forces its omission, and where an acknowledged
/// publication came from a fill its landing leaves unrevoked.
fn segments(rows: &[&Row], row: &Row, log: &ActivationLog) -> Option<(Tenure, Tenure)> {
    if row.outcome == Some(Outcome::Acknowledged) {
        let own = log.domain(row);
        return Some((own, own));
    }
    let landings = landings(rows, row, log);
    if row.kind == ActionKind::Invalidate {
        let open = open_landings(rows, row, log, None);
        return Some((*open.iter().min()?, *open.iter().max()?));
    }
    let fill = rows
        .iter()
        .find(|fill| fill.kind == ActionKind::Fill && fill.op == row.op)?;
    let filled_in = log.tag(fill);
    let revoked = rows.iter().any(|invalidation| {
        invalidation.kind == ActionKind::Invalidate
            && invalidation.outcome == Some(Outcome::Acknowledged)
            && invalidation.key() == row.key()
            && log.tag(invalidation) == filled_in
            && invalidation
                .covers
                .unwrap_or(Cover::All)
                .contains(row.version)
            && fill.responded < invalidation.invoked
            && precedes(rows, invalidation, row, filled_in, log)
    });
    let duplicated = rows.iter().any(|other| {
        matches!(other.kind, ActionKind::Publish | ActionKind::Replace)
            && other.outcome == Some(Outcome::Acknowledged)
            && other.op != row.op
            && other.key() == row.key()
            && other.label == row.label
    });
    (landings.contains(&filled_in) && !revoked && !duplicated).then_some((filled_in, filled_in))
}

/// Whether every legal order places `first` before `last` when both take
/// effect in `segment`: real time or the segment's clock orders them
/// directly, or orders each around one operation of that clock domain.
fn precedes(rows: &[&Row], first: &Row, last: &Row, segment: Tenure, log: &ActivationLog) -> bool {
    let by_time = |a: &Row, b: &Row| a.interval().1 < b.interval().0;
    let by_clock = |a: &Row, b: &Row| a.sample().zip(b.sample()).is_some_and(|(a, b)| a < b);
    by_time(first, last)
        || by_clock(first, last)
        || rows.iter().any(|between| {
            log.clock_domain(between) == Some(segment)
                && (by_time(first, between) || by_clock(first, between))
                && (by_time(between, last) || by_clock(between, last))
        })
}

/// The landings of cancelled or timed-out invalidation `row` that no later
/// use forces it to omit, with `covered`, and every publication of its
/// segment that precedes `covered`, counted among the publications it
/// covers. An acknowledged publication of a covered version whose fill the
/// landing would revoke closes that landing as well.
fn open_landings(
    rows: &[&Row],
    row: &Row,
    log: &ActivationLog,
    covered: Option<&Row>,
) -> Vec<Tenure> {
    let revokes = |segment: Tenure| {
        rows.iter().any(|publication| {
            matches!(publication.kind, ActionKind::Publish | ActionKind::Replace)
                && publication.outcome == Some(Outcome::Acknowledged)
                && would_revoke(rows, row, publication, segment, log)
        })
    };
    landings(rows, row, log)
        .into_iter()
        .filter(|&segment| !revokes(segment) && !omission_forced(rows, row, segment, log, covered))
        .collect()
}

/// Whether invalidation `row`, landing in `segment`, revokes the fill
/// `publication` came from: the publication is of `row`'s key and a version
/// `row` covers, its fill is tagged `segment` and responded before `row` was
/// invoked, and `row` takes effect before `publication` in every legal
/// order.
fn would_revoke(
    rows: &[&Row],
    row: &Row,
    publication: &Row,
    segment: Tenure,
    log: &ActivationLog,
) -> bool {
    publication.key() == row.key()
        && row
            .covers
            .unwrap_or(Cover::All)
            .contains(publication.version)
        && rows.iter().any(|fill| {
            fill.kind == ActionKind::Fill
                && fill.op == publication.op
                && log.tag(fill) == segment
                && fill.responded < row.invoked
        })
        && precedes(rows, row, publication, segment, log)
}

/// A hit or expired lookup, recorded restore, or recorded expiry or
/// eviction of a label with a publication that may take hold, covered by
/// invalidation `row`, rules out `row` taking effect in `segment` when the
/// use belongs to a later tenure, which coverage survives into, or starts
/// in `segment` after `row`'s landing window ends: each selects its label
/// uncovered. With `covered`, the use rules out `row` covering `covered`
/// in `segment`, where every publication of the segment before `covered`
/// counts as covered.
fn omission_forced(
    rows: &[&Row],
    row: &Row,
    segment: Tenure,
    log: &ActivationLog,
    covered: Option<&Row>,
) -> bool {
    let ended = row.interval().1;
    let covered_in = covered
        .map(|covered| segments(rows, covered, log).map_or(log.domain(covered), |(low, _)| low));
    rows.iter().any(|used| {
        let reads = used.kind == ActionKind::Lookup
            && matches!(used.outcome, Some(Outcome::Hit | Outcome::Expired))
            && used.acquired_key() == row.key();
        let recorded = matches!(
            used.kind,
            ActionKind::Restore | ActionKind::Expire | ActionKind::Evict
        ) && used.records_event()
            && used.key() == row.key();
        if !(reads || recorded) {
            return false;
        }
        let used_in = log.tag(used);
        let later = used_in > segment || (used_in == segment && ended < used.interval().0);
        if !later {
            return false;
        }
        let mut explaining = rows
            .iter()
            .filter(|publication| {
                matches!(publication.kind, ActionKind::Publish | ActionKind::Replace)
                    && publication.key() == row.key()
                    && publication.label == used.label
            })
            .filter_map(|publication| Some((publication, segments(rows, publication, log)?)))
            .filter(|(publication, (low, _))| {
                *low < used_in || (*low == used_in && publication.interval().0 < used.interval().1)
            })
            .peekable();
        explaining.peek().is_some()
            && explaining.all(|(publication, (_, high))| match row.covers {
                Some(cover) => cover.contains(publication.version),
                None => {
                    covered.is_some_and(|covered| {
                        std::ptr::eq(covered, *publication)
                            || (high == segment
                                && covered_in == Some(segment)
                                && precedes(rows, publication, covered, segment, log))
                    }) || high < segment
                        || (high == segment && precedes(rows, publication, row, segment, log))
                        || would_revoke(rows, row, publication, segment, log)
                }
            })
    })
}

/// Whether `row` may take effect after `published` in some legal order
/// when `row` takes effect in `segment`. Tenure order decides across
/// segments; inside one, `row` follows `published` unless real time or the
/// segment's clock places `row` first.
fn after_in(
    rows: &[&Row],
    row: &Row,
    published: &Row,
    segment: Tenure,
    log: &ActivationLog,
) -> bool {
    let publishing = segments(rows, published, log).map_or(log.domain(published), |(low, _)| low);
    if segment != publishing {
        return segment > publishing;
    }
    !precedes(rows, row, published, segment, log)
}

/// Whether `row` may take effect after `published` in some legal order, in
/// the highest segment `row` may take hold in.
fn after(rows: &[&Row], row: &Row, published: &Row, log: &ActivationLog) -> bool {
    segments(rows, row, log)
        .is_some_and(|(_, highest)| after_in(rows, row, published, highest, log))
}

/// Whether invalidation `row` removes the entry `published` published from
/// the retained set of `tenure`'s activation: in some landing later uses
/// leave open with that entry covered, `row` lands below `tenure`, or in
/// it before `first_restore`, and covers the entry there. An interval
/// covers the versions it contains; an unversioned invalidation covers the
/// labels present when it takes effect.
fn invalidated(
    rows: &[&Row],
    row: &Row,
    published: &Row,
    tenure: Tenure,
    first_restore: Option<Ordinal>,
    log: &ActivationLog,
) -> bool {
    let landings = if row.outcome == Some(Outcome::Acknowledged) {
        let own = log.domain(row);
        (!omission_forced(rows, row, own, log, Some(published)))
            .then_some(own)
            .into_iter()
            .collect()
    } else {
        open_landings(rows, row, log, Some(published))
    };
    landings.into_iter().any(|segment| {
        let placed = segment < tenure
            || (segment == tenure && first_restore.is_none_or(|first| row.interval().0 < first.0));
        placed
            && match row.covers {
                Some(cover) => cover.contains(published.version),
                None => after_in(rows, row, published, segment, log),
            }
    })
}

/// Whether the activated tenure must restore captured `entry`: no earlier
/// event removes it in any legal order. `live` holds the history's live
/// rows and the visibility ends its slot releases imply, the evidence the
/// key search reads. Each publication of the entry's label that may take
/// hold is one candidate for the publication the key search lands; the
/// entry stays required while some candidate leaves it in place.
fn required(live: &[&Row], log: &ActivationLog, activation: &Activation, entry: &Row) -> bool {
    let tenure = activation.tenure;
    let (key, label) = (entry.key(), entry.label);
    let effect = |row: &Row, kinds: &[ActionKind]| {
        kinds.contains(&row.kind) && row.key() == key && segments(live, row, log).is_some()
    };
    let publication = |row: &Row| effect(row, &[ActionKind::Publish, ActionKind::Replace]);
    let mut candidates: Vec<&Row> = live
        .iter()
        .copied()
        .filter(|row| row.label == label && publication(row))
        .collect();
    if candidates.is_empty() {
        candidates.push(entry);
    }
    let below = |row: &Row| {
        segments(live, row, log).map_or(log.place(row).tenure(), |(low, _)| low) < tenure
    };
    let first_restore = live
        .iter()
        .filter(|row| {
            row.kind == ActionKind::Restore
                && row.records_event()
                && log.tag(row) == tenure
                && row.key() == key
                && row.label == label
        })
        .filter_map(|row| row.responded)
        .min();
    let removed = |published: &Row| {
        for row in live
            .iter()
            .copied()
            .filter(|row| row.key() == key && below(row))
        {
            if row.label != label && publication(row) {
                if after(live, row, published, log) {
                    return true;
                }
            } else if row.label == label && row.records_event() {
                let removal = row.kind == ActionKind::Expire
                    || (row.kind == ActionKind::VisibilityEnded
                        && row.cause == Some(VisibilityCause::Expiry))
                    || row.is_logical_eviction();
                if removal && entry.responded < row.responded && row.responded < Some(activation.at)
                {
                    return true;
                }
            }
        }
        live.iter().copied().any(|row| {
            row.kind == ActionKind::Invalidate
                && row.key() == key
                && invalidated(live, row, published, tenure, first_restore, log)
        })
    };
    candidates.iter().any(|&published| !removed(published))
}

/// The response ordinal of the latest capture recorded before `activation`.
fn captured_before(rows: &[&Row], activation: &Activation) -> Option<Ordinal> {
    rows.iter()
        .filter(|row| row.kind == ActionKind::Captured && row.records_event())
        .filter_map(|row| row.responded)
        .filter(|&responded| responded < activation.at)
        .max()
}

/// The response ordinal of the first lookup `tenure` answered.
fn first_lookup(rows: &[&Row], log: &ActivationLog, activation: &Activation) -> Option<Ordinal> {
    rows.iter()
        .filter(|row| {
            row.kind == ActionKind::Lookup
                && row.outcome.is_some_and(Outcome::is_answer)
                && log.tag(row) == activation.tenure
        })
        .filter_map(|row| row.responded)
        .min()
}

/// Whether a damage row that `names` accepts was recorded after `captured`,
/// at or below `activation`'s tenure, and before `serving`; a `serving` of
/// `None` sets no upper bound. Retention passes its tenure's first lookup as
/// `serving`, and preservation the first answered lookup of the member's
/// own key.
pub(super) fn damaged_before(
    rows: &[&Row],
    log: &ActivationLog,
    activation: &Activation,
    captured: Option<Ordinal>,
    serving: Option<Ordinal>,
    names: impl Fn(&Row) -> bool,
) -> bool {
    rows.iter().any(|row| {
        row.kind == ActionKind::Damaged
            && row.records_event()
            && row.responded > captured
            && serving.is_none_or(|serving| row.responded < Some(serving))
            && log.tag(row) <= activation.tenure
            && names(row)
    })
}

/// [`damaged_before`] bounded by the first lookup `activation`'s tenure
/// answered.
fn damaged_before_serving(
    rows: &[&Row],
    log: &ActivationLog,
    activation: &Activation,
    captured: Option<Ordinal>,
    names: impl Fn(&Row) -> bool,
) -> bool {
    let serving = first_lookup(rows, log, activation);
    damaged_before(rows, log, activation, captured, serving, names)
}

/// Whether `damage` names `entry`'s row unit or payload unit and still
/// accounts for the entry when `activation` is judged. Evidence that the
/// named unit was read whole after the damage row retires it: for the row
/// unit, a restore of the entry recorded after the row, before the
/// activation or in its tenure; for the payload unit, a complete delivery of
/// the entry's label whose lookup was invoked after the row and that
/// responded before the activation. Evidence from after the activation, in
/// a later tenure, judges only later activations.
/// A restore reads the row unit on which the restore's cut captured the
/// entry, so only a restore from a cut that captured the entry on the
/// damaged unit retires the row.
pub(super) fn damages(
    rows: &[&Row],
    log: &ActivationLog,
    activation: &Activation,
    damage: &Row,
    entry: &Row,
) -> bool {
    let Some(((row_unit, payload), unit)) = entry.captured_units.zip(damage.damaged_unit) else {
        return false;
    };
    let after = |row: &Row| row.responded > damage.responded;
    let of_entry = |row: &Row| row.key() == entry.key() && row.label == entry.label;
    if unit == row_unit {
        let read_unit = |restore: &Row| {
            rows.iter().any(|capture| {
                capture.kind == ActionKind::Captured
                    && capture.records_event()
                    && capture.cut == restore.cut
                    && of_entry(capture)
                    && capture.captured_units.map(|(row_unit, _)| row_unit) == Some(unit)
            })
        };
        return !rows.iter().any(|row| {
            row.kind == ActionKind::Restore
                && row.records_event()
                && of_entry(row)
                && after(row)
                && (row.responded < Some(activation.at) || log.tag(row) == activation.tenure)
                && read_unit(row)
        });
    }
    let invoked_after = |op| {
        rows.iter().any(|lookup| {
            lookup.kind == ActionKind::Lookup
                && lookup.op == op
                && lookup.invoked > damage.responded
        })
    };
    unit == payload
        && !rows.iter().any(|row| {
            row.kind == ActionKind::Deliver
                && row.outcome == Some(Outcome::Complete)
                && of_entry(row)
                && row.responded < Some(activation.at)
                && invoked_after(row.op)
        })
}

/// The entries `cut` captured before `activation`.
fn captured_in<'r>(rows: &[&'r Row], activation: &Activation, cut: CutId) -> Vec<&'r Row> {
    rows.iter()
        .copied()
        .filter(|row| {
            row.kind == ActionKind::Captured
                && row.records_event()
                && row.cut == Some(cut)
                && row.responded < Some(activation.at)
        })
        .collect()
}

/// The retained set of `activation`: the labelled entries its cut captured
/// before it that its tenure must restore. An activation naming no cut
/// retains nothing.
pub(super) fn retained_set<'r>(
    rows: &[&'r Row],
    log: &ActivationLog,
    activation: &Activation,
) -> Vec<&'r Row> {
    let Some(cut) = activation.cut else {
        return Vec::new();
    };
    let live: Vec<&Row> = rows
        .iter()
        .copied()
        .filter(|row| !row.evidence.is_recovery())
        .collect();
    captured_in(rows, activation, cut)
        .into_iter()
        .filter(|entry| entry.label.is_some() && required(&live, log, activation, entry))
        .collect()
}

/// The first labelled entry `activation`'s cut captured that leaves
/// `retained`, the retained set of `activation` over `rows`, only through a
/// publication, replacement or invalidation whose outcome is unknown: with
/// every such cancelled or timed-out row removed, the set keeps it. A
/// history that holds no such row has no such entry.
/// A cancelled or timed-out publication or replacement of a captured entry's
/// own label stays among the rows: the capture shows that a publication of
/// that label landed, and the publication's version decides which interval
/// invalidations cover the entry.
pub(super) fn excluded_by_unknown<'r>(
    rows: &[&'r Row],
    log: &ActivationLog,
    activation: &Activation,
    retained: &[&'r Row],
) -> Option<&'r Row> {
    if !rows.iter().any(|row| row.pending_effect()) {
        return None;
    }
    let captured = captured_in(rows, activation, activation.cut?);
    let own = |row: &Row| {
        matches!(row.kind, ActionKind::Publish | ActionKind::Replace)
            && captured
                .iter()
                .any(|entry| entry.key() == row.key() && entry.label == row.label)
    };
    let known: Vec<&Row> = rows
        .iter()
        .copied()
        .filter(|row| !row.pending_effect() || own(row))
        .collect();
    retained_set(&known, log, activation)
        .into_iter()
        .find(|entry| !retained.iter().any(|kept| std::ptr::eq(*kept, *entry)))
}

pub(crate) fn judge_retention(
    rows: &[&Row],
    log: &ActivationLog,
    activations: &mut Activations,
) -> Result<(), Violation> {
    for activation in log.activations() {
        let Some(op) = activation.op else {
            continue;
        };
        let Some(cut) = activation.cut else {
            judge_cold_start(rows, log, activation, op)?;
            continue;
        };
        let captured = captured_in(rows, activation, cut);
        if captured.is_empty() {
            judge_cold_start(rows, log, activation, op)?;
        }
        judge_cut(rows, log, activation, cut, &captured, activations)?;
    }
    Ok(())
}

/// Judges an activation that recovers no recorded capture, naming no cut
/// or a cut no capture recorded: after a capture with no whole-volume
/// damage before its first lookup, it replaced the retained cut with a
/// cold start.
fn judge_cold_start(
    rows: &[&Row],
    log: &ActivationLog,
    activation: &Activation,
    op: OpId,
) -> Result<(), Violation> {
    let Some(captured) = captured_before(rows, activation) else {
        return Ok(());
    };
    if damaged_before_serving(rows, log, activation, Some(captured), |row| {
        row.damaged_unit.is_none()
    }) {
        return Ok(());
    }
    Err(fail(
        op,
        if activation.cut.is_some() {
            "host loss activated a cut no capture recorded"
        } else {
            "host loss replaced a retained cut with a cold start"
        },
    ))
}

/// Judges `captured`, the entries `cut` captured before `activation`,
/// against the restores of `activation`'s tenure from `cut`.
fn judge_cut(
    rows: &[&Row],
    log: &ActivationLog,
    activation: &Activation,
    cut: CutId,
    captured: &[&Row],
    activations: &mut Activations,
) -> Result<(), Violation> {
    let tenure = activation.tenure;
    let in_tenure = |kind: ActionKind| {
        rows.iter()
            .copied()
            .filter(move |row| row.kind == kind && row.records_event() && log.tag(row) == tenure)
    };
    let restores: Vec<&Row> = in_tenure(ActionKind::Restore)
        .filter(|row| row.cut == Some(cut))
        .collect();
    let first_restore = restores.iter().filter_map(|row| row.responded).min();
    for entry in retained_set(rows, log, activation) {
        let named = |row: &&Row| row.key() == entry.key() && row.label == entry.label;
        let damaged = damaged_before_serving(rows, log, activation, entry.responded, |row| {
            row.damaged_unit.is_none() || damages(rows, log, activation, row, entry)
        });
        if !restores.iter().any(named) && !damaged {
            let stale = in_tenure(ActionKind::Evict)
                .chain(in_tenure(ActionKind::VisibilityEnded))
                .any(|row| {
                    row.is_logical_eviction()
                        && named(&row)
                        && first_restore.is_none_or(|first| row.responded < Some(first))
                });
            return Err(fail(
                entry.op,
                if stale {
                    "a recovery-time stale refusal stood in for a recorded eviction"
                } else {
                    "a retained entry outside every damage set was lost on host loss"
                },
            ));
        }
        activations.activate(Obligation::Restart);
    }
    if let Some(restore) = restores.iter().find(|restore| {
        !captured
            .iter()
            .any(|entry| entry.key() == restore.key() && entry.label == restore.label)
    }) {
        return Err(fail(
            restore.op,
            "a recovery restored an entry its cut never captured",
        ));
    }
    Ok(())
}
