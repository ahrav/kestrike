//! The per-key legal-order search over every key a history touches and the
//! real-time pre-pass it depends on.

use std::collections::BTreeSet;

use super::action::ActionKind;
use super::ids::{ClockSample, KeyId, OpId, Tenure};
use super::key_model::{expired, is_searched};
use super::obligation::Obligation;
use super::outcome::{Outcome, VisibilityCause};
use super::row::Row;
use super::search::{Ceiling, Constraint, Placement};
use super::tenure::{ActivationLog, Place, Reading};
use super::verdict::{Activations, Inconclusive, Violation};

const fn fail(obligation: Obligation, op: OpId, rule: &'static str) -> Violation {
    Violation {
        obligation,
        op,
        rule,
    }
}

/// One tenure's owner samples one monotonic timeline, so a whole-second
/// sample taken by an operation the history orders after another of the
/// same tenure's effect interval is at least the earlier sample, whatever keys the
/// two touch, and a publication invoked after such a sample has a deadline
/// past it. A cancelled or timed-out
/// effect may sample until its custody ends, so its interval ends there. A publication also follows
/// its fill's write completion, since the cache publishes a fill once every
/// write succeeded; a completion carrying device-boundary evidence must name
/// a delivered success terminal for every write command the device accepted
/// for the attempt, covering at least the object's bytes. An acknowledged close is a permanent cutoff: later
/// lookups of its tenure answer nothing informative and later publications
/// of its tenure land nothing.
fn judge_order(rows: &[&Row], log: &ActivationLog) -> Result<(), Violation> {
    let bound = |row: &Row| sample_before(rows, row, log);
    for (later, sample) in rows
        .iter()
        .filter_map(|row| row.sample().map(|sample| (*row, sample)))
    {
        if bound(later).is_some_and(|before| sample < before) {
            return Err(fail(
                Obligation::History,
                later.op,
                "a clock sample regressed behind an earlier one",
            ));
        }
    }
    for publication in rows.iter().filter(|row| {
        matches!(row.kind, ActionKind::Publish | ActionKind::Replace)
            && (row.outcome == Some(Outcome::Acknowledged) || row.pending_effect())
    }) {
        if publication.clock == Some(ClockSample::Unavailable)
            && publication.outcome == Some(Outcome::Acknowledged)
        {
            return Err(fail(
                Obligation::History,
                publication.op,
                "a publication acknowledged without a clock sample",
            ));
        }
        let own = match publication.clock {
            Some(ClockSample::Seconds(seconds)) => Some(seconds),
            _ => None,
        };
        if publication.outcome == Some(Outcome::Acknowledged)
            && let Some(before) = bound(publication).max(own)
            && expired(publication.deadline, Some(ClockSample::Seconds(before)))
        {
            return Err(fail(
                Obligation::History,
                publication.op,
                "a publication at or past its deadline",
            ));
        }
        let completions = || {
            rows.iter().filter(|done| {
                done.kind == ActionKind::WriteCompleted
                    && done.outcome.is_none()
                    && done.op == publication.op
                    && done.key() == publication.key()
                    && done.label == publication.label
                    && done.responded < publication.invoked
            })
        };
        if completions().next().is_none() {
            return Err(fail(
                Obligation::History,
                publication.op,
                "a publication before its writes completed",
            ));
        }
        // Device-boundary evidence: every write command the device accepted
        // for the publishing attempt delivered a success terminal before the
        // publication, and together the commands carry at least the object's
        // bytes. The attempt judgment refuses a completion under another
        // serial, and the census binds each command to the row's serial.
        let object = rows
            .iter()
            .find(|fill| fill.kind == ActionKind::Fill && fill.op == publication.op)
            .map_or(0, |fill| {
                u64::from(fill.metadata_len.unwrap_or(0)) + fill.body_len.unwrap_or(0)
            });
        let eligible = completions().all(|done| match &done.commands {
            None => true,
            Some(commands) => {
                let delivered: u64 = commands.iter().map(|command| u64::from(command.len)).sum();
                !commands.is_empty()
                    && commands.iter().all(|command| command.succeeded())
                    && delivered >= object
            }
        });
        if !eligible {
            return Err(fail(
                Obligation::History,
                publication.op,
                "a publication before every write of its attempt delivered success",
            ));
        }
        // A length sum over overlapping ranges counts the same bytes twice.
        let overlapping = completions().any(|done| {
            let commands = done.commands.as_deref().unwrap_or_default();
            commands.iter().enumerate().any(|(at, a)| {
                commands[..at].iter().any(|b| {
                    a.start < b.start + u64::from(b.len) && b.start < a.start + u64::from(a.len)
                })
            })
        });
        if overlapping {
            return Err(fail(
                Obligation::History,
                publication.op,
                "a publication whose write commands overlap on the device",
            ));
        }
    }
    for row in rows.iter().filter(|row| closed_before(rows, row, log)) {
        let landed = row.outcome == Some(Outcome::Acknowledged);
        let rule = match row.kind {
            ActionKind::Lookup if row.outcome.is_some_and(|o| o.carries_information()) => {
                "a lookup answered after the cache closed"
            }
            ActionKind::Publish | ActionKind::Replace if landed => {
                "a publication after the cache closed"
            }
            ActionKind::Fill if landed => "a fill admitted after the cache closed",
            ActionKind::Invalidate if landed => "an invalidation after the cache closed",
            ActionKind::Receive if row.outcome.is_none() => "a receive after the cache closed",
            _ => continue,
        };
        return Err(fail(Obligation::History, row.op, rule));
    }
    Ok(())
}

/// Rows the per-key searches derive from a history: each expiry-caused
/// visibility end carrying the latest sample any key of its tenure took
/// before it, as the log's reading counts samples as evidence, so the key
/// model judges it against that timeline, and each collision hit as a miss
/// under its requested key, which found nothing there.
pub(crate) struct Derived {
    /// Each expiry-caused visibility end sampled at the latest sample known
    /// to precede it, beside its copy sampled at the latest one an effect
    /// that may land in several segments places before it, when the two
    /// differ.
    expiry_ends: Vec<(Row, Option<Row>)>,
    misses: Vec<Row>,
}

impl Derived {
    pub(crate) fn of(rows: &[&Row], log: &ActivationLog) -> Self {
        // The latest sample known to precede `row`, and the latest one a
        // branch may place before it, from one scan.
        let preceding = |row: &Row| {
            let (mut known, mut branched) = (None, None);
            for earlier in rows {
                let Some(sample) = earlier.sample() else {
                    continue;
                };
                if log.may_sample_before(earlier, row, row.responded) {
                    branched = branched.max(Some(sample));
                    if !log.branch_samples_before(earlier, row, row.responded) {
                        known = known.max(Some(sample));
                    }
                }
            }
            (known, branched)
        };
        let expiry_ends = rows
            .iter()
            .filter(|row| {
                row.kind == ActionKind::VisibilityEnded
                    && row.cause == Some(VisibilityCause::Expiry)
            })
            .map(|row| {
                let (known, branched) = preceding(row);
                let sampled = |clock: Option<u64>| {
                    let mut sampled = (*row).clone();
                    sampled.clock = clock.map(ClockSample::Seconds);
                    sampled
                };
                (
                    sampled(known),
                    (branched != known).then(|| sampled(branched)),
                )
            })
            .collect();
        let misses = rows
            .iter()
            .filter(|row| row.kind == ActionKind::Lookup && row.acquired_key() != row.key())
            .map(|row| {
                let mut miss = (*row).clone();
                miss.candidate_key = None;
                miss.label = None;
                miss.outcome = Some(Outcome::Missing);
                miss
            })
            .collect();
        Self {
            expiry_ends,
            misses,
        }
    }

    /// `ops` with each expiry end replaced by its branched copy, or `None`
    /// when no end among `ops` has one. `ops` holds references
    /// [`key_ops`] drew from this `Derived`, since an end is found by
    /// identity.
    pub(crate) fn branched<'r>(&'r self, ops: &[&'r Row]) -> Option<Vec<&'r Row>> {
        let mut raised = false;
        let branched = ops
            .iter()
            .map(|&op| {
                let branch = self
                    .expiry_ends
                    .iter()
                    .find(|(end, _)| std::ptr::eq(end, op))
                    .and_then(|(_, branched)| branched.as_ref());
                raised |= branch.is_some();
                branch.unwrap_or(op)
            })
            .collect();
        raised.then_some(branched)
    }

    /// `search` over `ops`, and on a definite violation the
    /// [`rejudged`](Self::rejudged) verdict over the branched copy.
    ///
    /// # Errors
    ///
    /// `UnplacedSample`, or the reason `search` stopped.
    pub(crate) fn judged<T>(
        &self,
        ops: &[&Row],
        mut search: impl FnMut(&[&Row]) -> Result<Result<T, Violation>, Inconclusive>,
    ) -> Result<Result<T, Violation>, Inconclusive> {
        match search(ops)? {
            Err(violation) => self.rejudged(ops, violation, search).map(Err),
            judged => Ok(judged),
        }
    }

    /// When an expiry end among `ops` has a branched copy, `again` searches
    /// the branched operations after the search over `ops` failed with
    /// `violation`; its pass makes the verdict `UnplacedSample` and its
    /// failure stays definite. When every expiry end is unbranched,
    /// `violation` stands.
    ///
    /// # Errors
    ///
    /// `UnplacedSample`, or the reason `again` stopped.
    fn rejudged<T>(
        &self,
        ops: &[&Row],
        violation: Violation,
        again: impl FnOnce(&[&Row]) -> Result<Result<T, Violation>, Inconclusive>,
    ) -> Result<Violation, Inconclusive> {
        let Some(branched) = self.branched(ops) else {
            return Ok(violation);
        };
        match again(&branched)? {
            Err(definite) => Ok(definite),
            Ok(_) => Err(Inconclusive::UnplacedSample { op: violation.op }),
        }
    }
}

/// Every key a history's rows name.
pub(crate) fn searched_keys(rows: &[&Row]) -> BTreeSet<KeyId> {
    rows.iter()
        .flat_map(|row| [row.key(), row.candidate_key].into_iter().flatten())
        .collect()
}

/// `key`'s searched rows in row order, then its derived expiry ends and
/// requested-key misses. `derived` comes from `rows`, so every expiry-caused
/// visibility end among `rows` searches as its derived, sampled copy.
pub(crate) fn key_ops<'r>(rows: &[&'r Row], derived: &'r Derived, key: KeyId) -> Vec<&'r Row> {
    rows.iter()
        .copied()
        .filter(|row| {
            is_searched(row.kind)
                && !(row.kind == ActionKind::VisibilityEnded
                    && row.cause == Some(VisibilityCause::Expiry))
                && if row.kind == ActionKind::Lookup {
                    row.acquired_key() == Some(key)
                } else {
                    row.key() == Some(key)
                }
        })
        .chain(
            derived
                .expiry_ends
                .iter()
                .map(|(end, _)| end)
                .filter(|end| end.key() == Some(key)),
        )
        .chain(derived.misses.iter().filter(|miss| miss.key() == Some(key)))
        .collect()
}

/// Whether live `earlier` ended before `row` was invoked on `row`'s
/// timeline, with `earlier` in clock domain `segment`.
fn ended_before_in(earlier: &Row, row: &Row, segment: Tenure, log: &ActivationLog) -> bool {
    !earlier.evidence.is_recovery()
        && log.timeline(earlier) == log.timeline(row)
        && row.invoked.is_some_and(|at| earlier.interval().1 < at.0)
        && log.domain(earlier) == segment
}

/// The latest whole-second sample a live operation of clock domain
/// `segment` took before `row` was invoked on `row`'s timeline.
fn sample_before_in(rows: &[&Row], row: &Row, segment: Tenure, log: &ActivationLog) -> Option<u64> {
    rows.iter()
        .filter_map(|earlier| earlier.sample().map(|sample| (earlier, sample)))
        .filter(|(earlier, _)| {
            log.clock_domain(earlier) == Some(segment)
                && ended_before_in(earlier, row, segment, log)
        })
        .map(|(_, sample)| sample)
        .max()
}

/// The latest whole-second sample a live operation that `log` orders
/// before `row`'s invocation in `row`'s clock domain took.
fn sample_before(rows: &[&Row], row: &Row, log: &ActivationLog) -> Option<u64> {
    rows.iter()
        .filter(|earlier| !earlier.evidence.is_recovery())
        .filter_map(|earlier| earlier.sample().map(|sample| (earlier, sample)))
        .filter(|(earlier, _)| log.samples_before(earlier, row, row.invoked.or(row.responded)))
        .map(|(_, sample)| sample)
        .max()
}

/// Whether a live acknowledged close of `row`'s clock domain responded
/// before `row` was invoked.
fn closed_before(rows: &[&Row], row: &Row, log: &ActivationLog) -> bool {
    rows.iter().any(|close| {
        close.kind == ActionKind::Close
            && close.outcome == Some(Outcome::Acknowledged)
            && !close.evidence.is_recovery()
            && log.precedes(close, row, row.invoked)
    })
}

/// The segments cancelled or timed-out effect `row` may land in: each
/// activated tenure from its place's floor up to its latest whose cache had
/// not closed before it was invoked and, for a publication, whose timeline
/// had not reached its deadline before it was invoked or at its own
/// sample. Empty for every other row. Live rows alone count as evidence,
/// as the key search reads them, so retention and the search agree on
/// every effect's landings.
pub(crate) fn landings(rows: &[&Row], row: &Row, log: &ActivationLog) -> Vec<Tenure> {
    if !row.may_land() {
        return Vec::new();
    }
    let publication = matches!(row.kind, ActionKind::Publish | ActionKind::Replace);
    let lapsed = |sample: Option<u64>| {
        sample.is_some_and(|sample| expired(row.deadline, Some(ClockSample::Seconds(sample))))
    };
    if publication && lapsed(row.sample()) {
        return Vec::new();
    }
    let candidates: Vec<Tenure> = match log.place(row) {
        Place::In(tenure) => vec![tenure],
        Place::AtLeast(floor) => {
            let latest = log.latest(row);
            log.activations()
                .iter()
                .map(|activation| activation.tenure)
                .filter(|&tenure| floor <= tenure && tenure <= latest)
                .collect()
        }
    };
    candidates
        .into_iter()
        .filter(|&segment| {
            let closed = rows.iter().any(|close| {
                close.kind == ActionKind::Close
                    && close.outcome == Some(Outcome::Acknowledged)
                    && ended_before_in(close, row, segment, log)
            });
            !closed && !(publication && lapsed(sample_before_in(rows, row, segment, log)))
        })
        .collect()
}

/// The constraint `rows` and `log` impose on each of `ops`. Each
/// constraint scans `rows`, so a caller passes only the operations it
/// searches.
pub(crate) fn constraints(rows: &[&Row], ops: &[&Row], log: &ActivationLog) -> Vec<Constraint> {
    let published_later = |row: &Row| {
        row.kind == ActionKind::Lookup
            && row.outcome == Some(Outcome::Hit)
            && rows.iter().any(|publication| {
                matches!(publication.kind, ActionKind::Publish | ActionKind::Replace)
                    && publication.outcome == Some(Outcome::Acknowledged)
                    && publication.key() == row.acquired_key()
                    && publication.label == row.label
                    && log.tag(publication) > log.tag(row)
            })
    };
    // An operation linearized before another of its clock domain takes its
    // sample before every sample an operation that other precedes takes,
    // whatever key the later operation touches.
    ops.iter()
        .map(|op| {
            let ceiling = rows
                .iter()
                .filter_map(|later| {
                    let at = later.invoked.or(later.responded)?;
                    let sample = later.sample()?;
                    log.samples_before(op, later, Some(at)).then_some(Ceiling {
                        sample,
                        at,
                        op: later.op,
                    })
                })
                .min();
            let place = log.place(op);
            let latest = log.latest(op);
            Constraint {
                ceiling,
                domain: log.clock_domain(op),
                place,
                timeline: log.timeline(op),
                latest,
                published_later: published_later(op),
                landings: landings(rows, op, log),
                placements: placements(rows, op, place, latest, log),
            }
        })
        .collect()
}

/// The segments where an effect with an unrecorded target may take effect,
/// when there are several, each bounding the effect's sample from below by
/// the non-recovery samples of that segment's clock domain completed before
/// the effect's invocation, and from above by that domain's samples whose
/// invocation, or response when no invocation is recorded, follows the
/// effect's landing window. An effect with one such segment samples that
/// segment's known clock domain, which its constraint's `domain` names.
fn placements(
    rows: &[&Row],
    row: &Row,
    place: Place,
    latest: Tenure,
    log: &ActivationLog,
) -> Vec<Placement> {
    let Place::AtLeast(floor) = place else {
        return Vec::new();
    };
    if floor == latest {
        return Vec::new();
    }
    let mut placements: Vec<Placement> = log
        .activations()
        .iter()
        .filter(|activation| floor <= activation.tenure && activation.tenure <= latest)
        .map(|activation| Placement {
            tenure: activation.tenure,
            floor: None,
            ceiling: None,
        })
        .collect();
    if placements.is_empty() {
        return placements;
    }
    let (invoked, ended) = row.interval();
    let timeline = log.timeline(row);
    for other in rows {
        let Some(sample) = other.sample() else {
            continue;
        };
        if other.op == row.op || log.timeline(other) != timeline {
            continue;
        }
        let Some(placement) = log.clock_domain(other).and_then(|domain| {
            placements
                .iter_mut()
                .find(|placement| placement.tenure == domain)
        }) else {
            continue;
        };
        if !other.evidence.is_recovery() && other.interval().1 < invoked {
            placement.floor = placement.floor.max(Some(sample));
        }
        if let Some(at) = other.invoked.or(other.responded)
            && ended < at.0
        {
            let later = Ceiling {
                sample,
                at,
                op: other.op,
            };
            placement.ceiling = Some(placement.ceiling.map_or(later, |known| known.min(later)));
        }
    }
    placements
}

/// A segment's clock orders samples across keys.
fn unplaced_pair(rows: &[&Row], log: &ActivationLog) -> Option<OpId> {
    let unbound = |row: &Row| {
        let sample = (!row.evidence.is_recovery())
            .then(|| row.sample())
            .flatten()?;
        let Place::AtLeast(floor) = log.place(row) else {
            return None;
        };
        let latest = log.latest(row);
        (floor < latest).then_some((sample, floor, latest))
    };
    rows.iter().find_map(|later| {
        let (low, later_floor, later_latest) = unbound(later)?;
        let timeline = log.timeline(later);
        let invoked = later.interval().0;
        rows.iter()
            .filter_map(|earlier| Some((earlier, unbound(earlier)?)))
            .filter(|(earlier, (high, _, _))| {
                *high > low
                    && earlier.key() != later.key()
                    && log.timeline(earlier) == timeline
                    && earlier.interval().1 < invoked
            })
            .any(|(earlier, (_, earlier_floor, earlier_latest))| {
                let ended = earlier.interval().1;
                log.activations()
                    .iter()
                    .map(|activation| activation.tenure)
                    .filter(|&segment| {
                        earlier_floor.max(later_floor) <= segment
                            && segment <= earlier_latest.min(later_latest)
                    })
                    .any(|segment| {
                        !rows.iter().any(|between| {
                            between.sample().is_some()
                                && !between.evidence.is_recovery()
                                && log.clock_domain(between) == Some(segment)
                                && log.timeline(between) == timeline
                                && ended < between.interval().0
                                && between.interval().1 < invoked
                        })
                    })
            })
            .then_some(later.op)
    })
}

/// Rows whose deadline judgment may compare clocks of two tenures: a hit
/// on a label whose publication carries a deadline and may land in another
/// segment than the hit's, and an `Expired` answer, an `Expire` or an
/// expiry-caused visibility end naming a label such a publication
/// published, with or without a deadline. A publication in one segment
/// lands there; one with an unrecorded target lands in a segment from its
/// floor up to the row's, so below the row's whenever its floor is. The key
/// model leaves each unjudged, so a verdict counts them as a weaker scope.
pub(crate) fn cross_tenure_deadlines(rows: &[&Row], log: &ActivationLog) -> u32 {
    let counted = rows.iter().filter(|row| {
        let hit = row.kind == ActionKind::Lookup && row.outcome == Some(Outcome::Hit);
        let lapsed = (row.kind == ActionKind::Lookup && row.outcome == Some(Outcome::Expired))
            || (row.kind == ActionKind::Expire && row.records_event())
            || (row.kind == ActionKind::VisibilityEnded
                && row.cause == Some(VisibilityCause::Expiry)
                && row.records_event());
        (hit || lapsed)
            && rows.iter().any(|publication| {
                matches!(publication.kind, ActionKind::Publish | ActionKind::Replace)
                    && (publication.outcome == Some(Outcome::Acknowledged)
                        || publication.pending_effect())
                    && publication.key() == row.acquired_key()
                    && publication.label == row.label
                    && (publication.deadline.is_some() || lapsed)
                    && match log.place(publication) {
                        Place::In(tenure) => tenure != log.tag(row),
                        Place::AtLeast(floor) => floor < log.tag(row),
                    }
            })
    });
    u32::try_from(counted.count()).unwrap_or(u32::MAX)
}

/// The count includes pairs of one key's searched rows from different
/// clients, or from a client and the owner, where one row precedes the
/// other under the strict reading. The lenient reading assigns distinct
/// `timeline` values to each pair's rows, and `precedes` requires matching
/// values.
pub(crate) fn cross_timeline_orders(rows: &[&Row], log: &ActivationLog) -> u32 {
    let strict = &log.read(Reading::Strict);
    let searched: Vec<(&Row, KeyId)> = rows
        .iter()
        .filter(|row| !row.evidence.is_recovery() && is_searched(row.kind))
        .filter_map(|row| {
            let key = if row.kind == ActionKind::Lookup {
                row.acquired_key()
            } else {
                row.key()
            };
            Some((*row, key?))
        })
        .collect();
    let searched = &searched;
    let counted = searched.iter().flat_map(|&(earlier, key)| {
        searched.iter().filter(move |&&(later, other)| {
            other == key
                && later.client != earlier.client
                && strict.precedes(earlier, later, later.invoked.or(later.responded))
        })
    });
    u32::try_from(counted.count()).unwrap_or(u32::MAX)
}

/// Builds the constraints the history imposes on the operations a key's
/// search passes it, in their order, so a search that skips operations
/// builds none for them.
pub(crate) type ConstraintsOf<'b> = &'b dyn Fn(&[&Row]) -> Vec<Constraint>;

/// Judges the shared order of `rows`, then each key's operations through
/// `search` in key order, and activates the history obligation per
/// informative lookup. `search` receives the key, the key's operations from
/// [`key_ops`] and the [`ConstraintsOf`] that builds their constraints. When a
/// key's search fails and an expiry end there has a branched sample,
/// `search` runs again over [`Derived::branched`]: a pass makes the verdict
/// `UnplacedSample`, and a failure stays definite. A key whose judgment is
/// inconclusive leaves the other keys searched, and any definite violation
/// among them is the verdict before the first inconclusive reason. After
/// every key passes, [`unplaced_pair`] naming an operation makes the
/// verdict `UnplacedSample`.
pub(crate) fn judge_candidates(
    rows: &[&Row],
    log: &ActivationLog,
    activations: &mut Activations,
    mut search: impl FnMut(
        KeyId,
        &[&Row],
        ConstraintsOf<'_>,
    ) -> Result<Result<(), Violation>, Inconclusive>,
) -> Result<Result<(), Violation>, Inconclusive> {
    if let Err(violation) = judge_order(rows, log) {
        return Ok(Err(violation));
    }
    let derived = Derived::of(rows, log);
    let mut uncertain = None;
    for key in searched_keys(rows) {
        let ops = key_ops(rows, &derived, key);
        let constrain = |ops: &[&Row]| constraints(rows, ops, log);
        let judged = derived.judged(&ops, |ops| search(key, ops, &constrain));
        match judged {
            Ok(Err(violation)) => return Ok(Err(violation)),
            Err(reason) => {
                uncertain.get_or_insert(reason);
            }
            Ok(Ok(())) => {}
        }
    }
    if let Some(reason) = uncertain {
        return Err(reason);
    }
    if let Some(op) = unplaced_pair(rows, log) {
        return Err(Inconclusive::UnplacedSample { op });
    }
    for _ in rows.iter().filter(|row| {
        row.kind == ActionKind::Lookup
            && row
                .outcome
                .is_some_and(|outcome| outcome.carries_information())
    }) {
        activations.activate(Obligation::History);
    }
    Ok(Ok(()))
}
