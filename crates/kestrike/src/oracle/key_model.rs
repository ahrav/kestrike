//! One key's expected mapping and the transition each recorded action makes
//! on it at its linearization point.

use super::action::ActionKind;
use super::coverage::{Cover, Coverage};
use super::ids::{ClientId, ClockSample, Label, OpId, Tenure};
use super::obligation::Obligation;
use super::outcome::{NoInformation, Outcome, VisibilityCause};
use super::row::Row;
use super::rules::{Rule, holds};
use super::verdict::Violation;

/// A hit of a label no linearized publication published.
pub(crate) const UNPUBLISHED_HIT: &str = "a hit of a version no linearized fill published";
/// A hit of a label only a later tenure published.
pub(crate) const LATER_PUBLISHED_HIT: &str =
    "a tenure served a version only a later tenure published";

const fn fail(row: &Row, rule: &'static str) -> Violation {
    Violation {
        obligation: Obligation::History,
        op: row.op,
        rule,
    }
}

/// A linearized publication. `deadline` counts whole seconds of `tenure`'s
/// clock domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Published {
    label: Label,
    version: Option<u64>,
    deadline: Option<u64>,
    tenure: Tenure,
}

/// `published` holds every linearized publication, each eligible for a hit
/// until `covered` covers it, so a hit may return an older uncovered
/// version and a miss is always legal; the abstract residency explains a
/// miss by a hidden eviction and a hit by a hidden restore. `removed_here`
/// holds the labels a recorded expiry, eviction or visibility end removed in
/// the current tenure, which that tenure re-inserts only through a recorded
/// restore. `live` fills may still publish until their one publication
/// attempt responds. `revoked` names each fill an invalidation or a tenure
/// change revoked, with the versions it may no longer publish: an
/// interval invalidation revokes the versions it covers and leaves the
/// fill live for the others, and every other invalidation, like entering a
/// later tenure, revokes the fill outright.
/// `tenure` is the segment being linearized and `clock` the latest
/// whole-second sample a linearized operation of it recorded, since one
/// tenure's owner samples one monotonic timeline. `unbound` holds, per
/// timeline, the latest invocation among the effects with an unrecorded
/// target this segment linearized, so another such effect whose landing
/// window ended before it cannot land after it in the same segment.
///
/// An expiry, eviction or visibility end names a published, uncovered
/// label; eviction waits for the key's current fill, since a commit finds
/// that attempt and returns `Replacing`. `published`, `removed_here`,
/// `live`, `revoked` and `unbound` stay sorted and deduplicated, so equal
/// mappings compare equal in the memo.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub(crate) struct KeyState {
    published: Vec<Published>,
    covered: Coverage,
    removed_here: Vec<Label>,
    live: Vec<(OpId, Label)>,
    revoked: Vec<(OpId, Label, Cover)>,
    tenure: Tenure,
    clock: u64,
    unbound: Vec<(Option<ClientId>, u32)>,
}

/// The mappings one operation may leave at its linearization point. For a
/// cancelled or timed-out `Publish`, `Replace` or `Invalidate` row, `step`
/// returns `Open { refused, landed }` when `effect` succeeds.
#[derive(Debug)]
pub(crate) enum Transition {
    Unchanged,
    Next(KeyState),
    Open { refused: KeyState, landed: KeyState },
}

impl Transition {
    /// This transition with `f` applied to every state it leaves from
    /// `from`, an unchanged state included.
    pub(crate) fn map(self, from: &KeyState, f: impl Fn(KeyState) -> KeyState) -> Self {
        match self {
            Self::Unchanged => Self::Next(f(from.clone())),
            Self::Next(next) => Self::Next(f(next)),
            Self::Open { refused, landed } => Self::Open {
                refused: f(refused),
                landed: f(landed),
            },
        }
    }
}

pub(crate) const fn is_searched(kind: ActionKind) -> bool {
    matches!(
        kind,
        ActionKind::Fill
            | ActionKind::Publish
            | ActionKind::Replace
            | ActionKind::Invalidate
            | ActionKind::Lookup
            | ActionKind::Expire
            | ActionKind::Evict
            | ActionKind::VisibilityEnded
            | ActionKind::Restore
    )
}

/// Deadlines saturate at `u32::MAX` whole seconds, as the stored slot does,
/// and an omitted deadline is that horizon.
pub(crate) fn expired(deadline: Option<u64>, clock: Option<ClockSample>) -> bool {
    let horizon = u64::from(u32::MAX);
    matches!(clock, Some(ClockSample::Seconds(s)) if s >= deadline.map_or(horizon, |d| d.min(horizon)))
}

impl KeyState {
    pub(crate) const fn tenure(&self) -> Tenure {
        self.tenure
    }

    /// The transition `row` makes when it linearizes in tenure `at`'s
    /// segment, at or above the current one. Entering a later tenure starts
    /// its clock domain, its recorded removals and its unbound effects
    /// afresh and revokes every live fill; coverage and publications carry
    /// over.
    pub(crate) fn step(
        &self,
        row: &Row,
        at: Tenure,
        published_later: bool,
    ) -> Result<Transition, Violation> {
        if at <= self.tenure {
            return self.sampled(row, published_later);
        }
        let mut entered = self.clone();
        entered.tenure = at;
        entered.clock = 0;
        entered.removed_here.clear();
        entered.unbound.clear();
        let live = std::mem::take(&mut entered.live);
        entered.revoke(live.into_iter().map(|(op, label)| (op, label, Cover::All)));
        Ok(match entered.sampled(row, published_later)? {
            Transition::Unchanged => Transition::Next(entered),
            stepped => stepped,
        })
    }

    fn sampled(&self, row: &Row, later: bool) -> Result<Transition, Violation> {
        let sampled = match row.clock {
            Some(ClockSample::Seconds(seconds)) if row.samples_clock() => {
                if seconds < self.clock {
                    return Err(fail(row, "a clock sample regressed behind an earlier one"));
                }
                Some(seconds)
            }
            _ => None,
        };
        let transition = self.transition(row, later)?;
        let Some(seconds) = sampled.filter(|&seconds| seconds > self.clock) else {
            return Ok(transition);
        };
        Ok(transition.map(self, |mut state| {
            state.clock = seconds;
            state
        }))
    }

    /// Whether an effect with an unrecorded target, on `timeline` and with
    /// a landing window ending at `ended`, would land in segment `at` after
    /// such an effect of that segment and timeline invoked after `ended`.
    pub(crate) fn overtaken(&self, at: Tenure, timeline: Option<ClientId>, ended: u32) -> bool {
        at == self.tenure
            && self
                .unbound
                .iter()
                .any(|&(seen, invoked)| seen == timeline && invoked > ended)
    }

    /// This state after an effect with an unrecorded target on `timeline`,
    /// invoked at `invoked`, linearized in the current segment.
    pub(crate) fn linearized_unbound(mut self, timeline: Option<ClientId>, invoked: u32) -> Self {
        match self.unbound.iter_mut().find(|(seen, _)| *seen == timeline) {
            Some((_, latest)) => *latest = (*latest).max(invoked),
            None => {
                self.unbound.push((timeline, invoked));
                self.unbound.sort_unstable();
            }
        }
        self
    }

    /// Adds `revoked` to the revocations, kept sorted and deduplicated so
    /// equal revocation sets compare and hash equal.
    fn revoke(&mut self, revoked: impl Iterator<Item = (OpId, Label, Cover)>) {
        self.revoked.extend(revoked);
        self.revoked.sort_unstable_by_key(|&(op, label, cover)| {
            let bounds = match cover {
                Cover::Range { lo, hi } => (0, lo, hi),
                Cover::All => (1, 0, 0),
            };
            (op.0, label.0, bounds)
        });
        self.revoked.dedup();
    }

    fn entry(&self, label: Label) -> Option<&Published> {
        self.published.iter().find(|entry| entry.label == label)
    }

    fn is_covered(&self, entry: &Published) -> bool {
        self.covered.covers(entry.label, entry.version)
    }

    /// Whether `entry`'s deadline counts seconds of the current tenure's
    /// clock domain, the only domain a sample compares against it in.
    fn dated_here(&self, entry: &Published) -> bool {
        entry.tenure == self.tenure
    }

    fn transition(&self, row: &Row, later: bool) -> Result<Transition, Violation> {
        let outcome = row
            .outcome
            .unwrap_or(Outcome::NoInformation(NoInformation::Refused));
        match row.kind {
            ActionKind::Fill => {
                let (Outcome::Acknowledged, Some(label)) = (outcome, row.label) else {
                    return Ok(Transition::Unchanged);
                };
                let mut next = self.clone();
                if !next.live.contains(&(row.op, label)) {
                    next.live.push((row.op, label));
                    next.live
                        .sort_unstable_by_key(|&(op, label)| (op.0, label.0));
                }
                Ok(Transition::Next(next))
            }
            ActionKind::Publish | ActionKind::Replace | ActionKind::Invalidate => {
                if outcome == Outcome::Acknowledged {
                    return Ok(Transition::Next(self.effect(row)?));
                }
                let mut refused = self.clone();
                if let Some(label) = row.label
                    && row.kind != ActionKind::Invalidate
                {
                    refused.live.retain(|fill| *fill != (row.op, label));
                }
                if row.may_land()
                    && let Ok(landed) = self.effect(row)
                {
                    return Ok(Transition::Open { refused, landed });
                }
                Ok(Transition::Next(refused))
            }
            ActionKind::Lookup => {
                self.judge_lookup(row, outcome, later)?;
                Ok(Transition::Unchanged)
            }
            ActionKind::Restore => {
                let (Some(label), true) = (row.label, row.records_event()) else {
                    return Ok(Transition::Unchanged);
                };
                let Some(entry) = self.entry(label) else {
                    return Err(fail(row, "a recorded restore of a version never published"));
                };
                if self.is_covered(entry) {
                    return Err(fail(row, "a recorded restore of a covered version"));
                }
                let mut next = self.clone();
                next.removed_here.retain(|&removed| removed != label);
                Ok(Transition::Next(next))
            }
            ActionKind::Expire | ActionKind::Evict | ActionKind::VisibilityEnded => {
                self.removal(row)
            }
            _ => Ok(Transition::Unchanged),
        }
    }

    fn removal(&self, row: &Row) -> Result<Transition, Violation> {
        let Some(label) = row.label else {
            return Ok(Transition::Unchanged);
        };
        if !row.records_event() {
            return Ok(Transition::Unchanged);
        }
        let Some(entry) = self.entry(label) else {
            return Err(fail(row, "a removal of a label the key never held"));
        };
        let covered = self.is_covered(entry);
        if covered || self.removed_here.contains(&label) {
            // A visibility end observes a removal an invalidation, an expiry
            // or an eviction may already have recorded; those two select a
            // resident, so each one finds the label uncovered and resident.
            if row.kind == ActionKind::VisibilityEnded {
                return Ok(Transition::Unchanged);
            }
            return Err(fail(
                row,
                if covered {
                    "a removal selected a label an invalidation covered"
                } else {
                    "a removal selected a label already removed"
                },
            ));
        }
        if row.is_logical_eviction() && !self.live.is_empty() {
            return Err(fail(row, "an eviction while a fill is current"));
        }
        if self.dated_here(entry) {
            if row.kind == ActionKind::Expire && !expired(entry.deadline, row.clock) {
                return Err(fail(row, "expiry removed a label before its deadline"));
            }
            if row.cause == Some(VisibilityCause::Expiry)
                && !expired(entry.deadline, self.observed(row))
            {
                return Err(fail(row, "a visibility end by expiry before the deadline"));
            }
        }
        let mut next = self.clone();
        next.removed_here.push(label);
        next.removed_here.sort_unstable_by_key(|removed| removed.0);
        Ok(Transition::Next(next))
    }

    fn effect(&self, row: &Row) -> Result<Self, Violation> {
        let mut next = self.clone();
        if row.kind == ActionKind::Invalidate {
            let present = self
                .published
                .iter()
                .map(|entry| (entry.label, entry.version));
            next.covered.add(row.covers, present);
            let revoked = row.covers.unwrap_or(Cover::All);
            next.revoke(self.live.iter().map(|&(op, label)| (op, label, revoked)));
            if revoked == Cover::All {
                next.live.clear();
            }
            return Ok(next);
        }
        let Some(label) = row.label else {
            return Err(fail(row, "publication has no label"));
        };
        if self.revoked.iter().any(|&(op, revoked, cover)| {
            (op, revoked) == (row.op, label) && cover.contains(row.version)
        }) {
            return Err(fail(
                row,
                "a fill revoked by an invalidation or a tenure change published",
            ));
        }
        if !self.live.contains(&(row.op, label)) {
            return Err(fail(row, "a publication without an acknowledged fill"));
        }
        if self.entry(label).is_some() {
            return Err(fail(row, "a publication label was published twice"));
        }
        if expired(row.deadline, self.observed(row)) {
            return Err(fail(row, "a publication at or past its deadline"));
        }
        next.published.push(Published {
            label,
            version: row.version,
            deadline: row.deadline,
            tenure: self.tenure,
        });
        next.published.sort_unstable_by_key(|entry| entry.label.0);
        next.live.retain(|fill| *fill != (row.op, label));
        Ok(next)
    }

    /// The latest sample of the current clock domain at `row`: its own, or
    /// the latest an earlier linearized operation took.
    fn observed(&self, row: &Row) -> Option<ClockSample> {
        Some(ClockSample::Seconds(match row.clock {
            Some(ClockSample::Seconds(seconds)) => seconds.max(self.clock),
            _ => self.clock,
        }))
    }

    /// A miss is always legal. A hit needs a published version, uncovered,
    /// with no recorded removal of its label in the current tenure since
    /// its latest recorded restore, and
    /// before its deadline when that deadline is in the current tenure's
    /// clock domain. `Expired` needs such a version past its deadline, or
    /// one whose deadline is in another tenure's clock domain, which this
    /// tenure's sample leaves unjudged. `later` records that only a later
    /// tenure published the hit's label.
    fn judge_lookup(&self, row: &Row, outcome: Outcome, later: bool) -> Result<(), Violation> {
        match outcome {
            Outcome::Hit => {
                let Some(label) = row.label else {
                    return Err(fail(row, "acquisition has no label"));
                };
                let Some(entry) = self.entry(label) else {
                    return Err(fail(
                        row,
                        if later {
                            LATER_PUBLISHED_HIT
                        } else {
                            UNPUBLISHED_HIT
                        },
                    ));
                };
                if self.is_covered(entry) {
                    return Err(fail(
                        row,
                        "a hit of a version an acknowledged invalidation covered",
                    ));
                }
                if holds(Rule::EvidenceClass) && self.removed_here.contains(&label) {
                    return Err(fail(
                        row,
                        "a hit after a recorded removal of its label in the same tenure",
                    ));
                }
                if self.dated_here(entry) && expired(entry.deadline, row.clock) {
                    return Err(fail(row, "a hit at or past the deadline"));
                }
                Ok(())
            }
            Outcome::Expired => {
                let lapsed = row
                    .label
                    .and_then(|label| self.entry(label))
                    .is_some_and(|entry| {
                        !self.is_covered(entry)
                            && !self.removed_here.contains(&entry.label)
                            && (!self.dated_here(entry) || expired(entry.deadline, row.clock))
                    });
                if lapsed {
                    Ok(())
                } else {
                    Err(fail(
                        row,
                        "Expired without a published label past its deadline",
                    ))
                }
            }
            _ => Ok(()),
        }
    }
}
