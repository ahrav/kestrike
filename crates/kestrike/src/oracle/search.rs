//! Legal-order search for one key. Operations linearize by tenure tag, one
//! tenure's segment after another in lexicographic `(g, a)` order, and in
//! real time inside one segment: an operation may take effect next only when
//! every operation of its segment and timeline that responded before its
//! invocation already has. A pending effect with an unrecorded target lands
//! in the current segment or a later one at or above its floor, and only
//! before every operation of that segment and timeline invoked after its
//! landing window ended, another such effect included; in a segment
//! activated after that window ended it takes effect only as refused. Visited (linearized set, state) pairs
//! are memoized.
//! One tenure's owner samples one monotonic timeline, so an operation that
//! takes effect before another of its tenure responds took its clock sample
//! before every sample an operation of that tenure invoked after that
//! response took.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;

use super::bounds::SearchBudget;
use super::ids::{ClientId, OpId, Ordinal, Tenure};
use super::key_model::{KeyState, Transition};
use super::memo_hash::MemoBuild;
use super::obligation::Obligation;
use super::row::Row;
use super::tenure::Place;
use super::verdict::{Inconclusive, Violation};

/// What the shared timeline, the activation log and the other keys'
/// evidence impose on one operation of a key's search.
#[derive(Debug, Clone)]
pub(crate) struct Constraint {
    /// The least clock sample any operation of this row's clock domain
    /// invoked after this row's effect interval ended took; every sample of
    /// that domain linearized before this row is at most that sample. Equal
    /// samples order by the later row's invocation ordinal.
    pub(crate) ceiling: Option<Ceiling>,
    /// The tenure whose clock domain this row's sample belongs to, `None`
    /// for an effect whose segment the search chooses.
    pub(crate) domain: Option<Tenure>,
    /// The segment this operation linearizes in.
    pub(crate) place: Place,
    /// The timeline whose ordinals order this operation against others of
    /// its segment.
    pub(crate) timeline: Option<ClientId>,
    /// The highest segment a pending effect lands in: the latest tenure
    /// activated before its landing window ended, or under the lenient
    /// per-client reading the latest activated tenure for a client's
    /// effect.
    pub(crate) latest: Tenure,
    /// Whether an acknowledged publication of this hit's label carries a
    /// higher tenure tag than the hit.
    pub(crate) published_later: bool,
    /// The segments a cancelled or timed-out effect may land in; in every
    /// other segment, and when this is empty, the search explores its
    /// refused branch only, over its whole landing window.
    pub(crate) landings: Vec<Tenure>,
    /// For an effect with an unrecorded target that may land in several
    /// segments, each activated segment from its floor up to `latest`, in
    /// tenure order; empty for every other row, whose `domain` names its
    /// one clock domain.
    pub(crate) placements: Vec<Placement>,
}

/// One segment an effect with an unrecorded target may take effect in. An
/// effect that takes effect there samples that segment's clock, so its
/// sample is at least `floor` and at most `ceiling`, the bounds that clock
/// domain's operations ending before its invocation or invoked after its
/// landing window impose.
#[derive(Debug, Clone)]
pub(crate) struct Placement {
    pub(crate) tenure: Tenure,
    /// The latest sample an operation of this clock domain that ended
    /// before the effect's invocation took.
    pub(crate) floor: Option<u64>,
    /// The least sample an operation of this clock domain invoked after
    /// the effect's landing window ended took.
    pub(crate) ceiling: Option<Ceiling>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Ceiling {
    pub(crate) sample: u64,
    pub(crate) at: Ordinal,
    pub(crate) op: OpId,
}

const _: () = assert!(super::bounds::HISTORY_BOUND <= 128);

/// Interning gives each distinct `KeyState` an index, so the visited set
/// hashes `(u128, usize)`; `successor` reuses `from` when the stepped state
/// equals it, and `intern` hashes a `KeyState` once per distinct state.
#[derive(Default)]
struct States {
    by_index: Vec<KeyState>,
    by_state: HashMap<KeyState, usize, MemoBuild>,
}

impl States {
    fn intern(&mut self, state: KeyState) -> usize {
        match self.by_state.entry(state) {
            Entry::Occupied(known) => *known.get(),
            Entry::Vacant(fresh) => {
                let index = self.by_index.len();
                self.by_index.push(fresh.key().clone());
                fresh.insert(index);
                index
            }
        }
    }

    fn successor(&mut self, from: usize, next: KeyState) -> usize {
        if self.by_index[from] == next {
            from
        } else {
            self.intern(next)
        }
    }
}

/// `linearize` finds one legal order, or the failure reached with the most
/// operations already linearized; the first such failure found is kept.
/// `constraints[i]` is what the rest of the history imposes on `ops[i]`.
pub(crate) fn linearize(
    ops: &[&Row],
    constraints: &[Constraint],
    budget: &mut SearchBudget,
) -> Result<Result<(), Violation>, Inconclusive> {
    let Some(first) = ops.first().map(|row| row.op) else {
        return Ok(Ok(()));
    };
    ordered(ops, constraints, &[KeyState::default()], first, budget)
}

/// Whether some legal order of `ops` exists from one of `starts`, tried in
/// order and stopping at the first, as [`linearize`] stops; otherwise the
/// failure reached with the most operations linearized, `first` naming the
/// key's first operation for a failure no step names. `ops` holds at most
/// 128 operations.
///
/// # Errors
///
/// `SearchBound` when `budget` runs out.
pub(crate) fn ordered(
    ops: &[&Row],
    constraints: &[Constraint],
    starts: &[KeyState],
    first: OpId,
    budget: &mut SearchBudget,
) -> Result<Result<(), Violation>, Inconclusive> {
    let mut states = States::default();
    let starts: Vec<usize> = starts
        .iter()
        .map(|state| states.intern(state.clone()))
        .collect();
    let found = explore(ops, constraints, &mut states, &starts, budget, |_| {
        Ok(ControlFlow::Break(()))
    })?;
    Ok(match found {
        Explored::Stopped => Ok(()),
        Explored::Exhausted(best) => Err(fallback(best, first)),
    })
}

/// The states one key's search can leave after linearizing every one of
/// `ops`, starting from each of `starts` in order: the frontier a
/// continuation carries past a cut. Every legal order is explored, so the
/// result holds each admissible state once, in the order the search reaches
/// them; when no legal order exists it is the failure [`linearize`] would
/// report, `first` naming the key's first operation for a failure no step
/// names. `ops` holds at most 128 operations, the width of the linearized
/// mask.
///
/// # Errors
///
/// `SearchBound` when `budget` runs out, or `ContinuationBound` when more
/// than `limit` distinct states remain.
pub(crate) fn frontier(
    ops: &[&Row],
    constraints: &[Constraint],
    starts: &[KeyState],
    first: OpId,
    budget: &mut SearchBudget,
    limit: usize,
) -> Result<Result<Vec<KeyState>, Violation>, Inconclusive> {
    let mut states = States::default();
    let starts: Vec<usize> = starts
        .iter()
        .map(|state| states.intern(state.clone()))
        .collect();
    let mut reached: Vec<usize> = Vec::new();
    let found = explore(ops, constraints, &mut states, &starts, budget, |state| {
        if !reached.contains(&state) {
            if reached.len() == limit {
                return Err(Inconclusive::ContinuationBound {
                    dimension: "frontier",
                    limit,
                });
            }
            reached.push(state);
        }
        Ok(ControlFlow::Continue(()))
    })?;
    if reached.is_empty() {
        let best = match found {
            Explored::Stopped => None,
            Explored::Exhausted(best) => best,
        };
        return Ok(Err(fallback(best, first)));
    }
    Ok(Ok(reached
        .into_iter()
        .map(|state| states.by_index[state].clone())
        .collect()))
}

/// How an exploration ended: `complete` stopped it, or every order was
/// explored, keeping the failure reached with the most operations
/// linearized.
enum Explored {
    Stopped,
    Exhausted(Option<(u32, Violation)>),
}

/// The deepest failure, or the generic one naming `first` when no step
/// failed.
fn fallback(best: Option<(u32, Violation)>, first: OpId) -> Violation {
    best.map_or(
        Violation {
            obligation: Obligation::History,
            op: first,
            rule: "no legal order of the key's operations",
        },
        |(_, failure)| failure,
    )
}

/// Depth-first legal-order search over `ops` from the interned `starts`,
/// the first start explored first, in the order the module states, with
/// visited (linearized set, state) pairs memoized. `complete` sees
/// each state reached with every operation linearized and decides whether
/// the search goes on.
fn explore(
    ops: &[&Row],
    constraints: &[Constraint],
    states: &mut States,
    starts: &[usize],
    budget: &mut SearchBudget,
    mut complete: impl FnMut(usize) -> Result<ControlFlow<()>, Inconclusive>,
) -> Result<Explored, Inconclusive> {
    let intervals: Vec<(u32, u32)> = ops.iter().map(|row| row.interval()).collect();
    let all: u128 = if ops.len() == 128 {
        u128::MAX
    } else {
        (1u128 << ops.len()) - 1
    };
    let mut visited: HashSet<(u128, usize), MemoBuild> = HashSet::default();
    // The stack pops the last push first, so the first start is pushed last.
    let mut stack: Vec<(u128, usize)> = Vec::new();
    for &start in starts.iter().rev() {
        if visited.insert((0, start)) {
            stack.push((0, start));
        }
    }
    let mut best: Option<(u32, Violation)> = None;
    while let Some((done, state)) = stack.pop() {
        if done == all {
            if complete(state)?.is_break() {
                return Ok(Explored::Stopped);
            }
            continue;
        }
        budget.expand()?;
        let current = states.by_index[state].tenure();
        let segments = Segments::of(done, constraints, &intervals);
        let pending = (0..ops.len()).filter(|&i| done & (1 << i) == 0);
        for i in pending.clone() {
            for at in placements(&constraints[i], current) {
                if !segments.admits(i, at, current, constraints, &intervals) {
                    continue;
                }
                let unbound = matches!(constraints[i].place, Place::AtLeast(_));
                if unbound
                    && states.by_index[state].overtaken(at, constraints[i].timeline, intervals[i].1)
                {
                    continue;
                }
                let regressed = ops[i].sample().and_then(|sample| {
                    regression(i, at, sample, pending.clone(), ops, constraints)
                });
                let stepped = match regressed {
                    Some(later) => Err(Violation {
                        obligation: Obligation::History,
                        op: later,
                        rule: "a clock sample regressed behind an earlier one",
                    }),
                    None => states.by_index[state].step(ops[i], at, constraints[i].published_later),
                };
                let stepped = stepped.map(|transition| {
                    if !unbound {
                        return transition;
                    }
                    transition.map(&states.by_index[state], |next| {
                        next.linearized_unbound(constraints[i].timeline, intervals[i].0)
                    })
                });
                match stepped {
                    Ok(transition) => {
                        let linearized = done | (1 << i);
                        let mut visit = |next: usize| {
                            if visited.insert((linearized, next)) {
                                stack.push((linearized, next));
                            }
                        };
                        match transition {
                            Transition::Unchanged => visit(state),
                            Transition::Next(next) => visit(states.successor(state, next)),
                            Transition::Open { refused, landed } => {
                                visit(states.successor(state, refused));
                                if constraints[i].landings.contains(&at)
                                    && at <= constraints[i].latest
                                {
                                    visit(states.successor(state, landed));
                                }
                            }
                        }
                    }
                    Err(failure) => {
                        let depth = done.count_ones();
                        if best.is_none_or(|(deepest, _)| depth > deepest) {
                            best = Some((depth, failure));
                        }
                    }
                }
            }
        }
    }
    Ok(Explored::Exhausted(best))
}

/// What one search state's linearized set imposes on the next step: the
/// lowest segment any remaining operation is bound to and, for each segment
/// and timeline, the earliest end among its remaining bound operations and
/// the latest invocation among its linearized ones.
struct Segments {
    lowest: Option<Tenure>,
    groups: Vec<Group>,
}

struct Group {
    tenure: Tenure,
    timeline: Option<ClientId>,
    earliest_end: u32,
    latest_invocation: Option<u32>,
}

impl Segments {
    fn of(done: u128, constraints: &[Constraint], intervals: &[(u32, u32)]) -> Self {
        let mut segments = Self {
            lowest: None,
            groups: Vec::new(),
        };
        for (i, constraint) in constraints.iter().enumerate() {
            let Place::In(tenure) = constraint.place else {
                continue;
            };
            let at = segments
                .groups
                .iter()
                .position(|group| group.tenure == tenure && group.timeline == constraint.timeline);
            let at = at.unwrap_or_else(|| {
                segments.groups.push(Group {
                    tenure,
                    timeline: constraint.timeline,
                    earliest_end: u32::MAX,
                    latest_invocation: None,
                });
                segments.groups.len() - 1
            });
            let group = &mut segments.groups[at];
            let (invoked, ended) = intervals[i];
            if done & (1 << i) == 0 {
                group.earliest_end = group.earliest_end.min(ended);
                segments.lowest = Some(segments.lowest.map_or(tenure, |low| low.min(tenure)));
            } else {
                group.latest_invocation = group.latest_invocation.max(Some(invoked));
            }
        }
        segments
    }

    fn group(&self, tenure: Tenure, timeline: Option<ClientId>) -> Option<&Group> {
        self.groups
            .iter()
            .find(|group| group.tenure == tenure && group.timeline == timeline)
    }

    /// Whether remaining operation `i` may take effect next in segment `at`
    /// from a state in segment `current`. A remaining operation bound to a
    /// segment below `at`, or an operation in segment `at` on the same
    /// timeline that ended before `i` was invoked, goes first. An effect
    /// with an unrecorded target is overtaken in `at` once an operation
    /// there on its timeline, invoked after the effect's landing window,
    /// has taken effect.
    fn admits(
        &self,
        i: usize,
        at: Tenure,
        current: Tenure,
        constraints: &[Constraint],
        intervals: &[(u32, u32)],
    ) -> bool {
        let constraint = &constraints[i];
        let group = self.group(at, constraint.timeline);
        let (invoked, ended) = intervals[i];
        let blocked = at < current
            || self.lowest.is_some_and(|lowest| lowest < at)
            || group.is_some_and(|group| invoked > group.earliest_end);
        let overtaken = matches!(constraint.place, Place::AtLeast(_))
            && group
                .and_then(|group| group.latest_invocation)
                .is_some_and(|latest| latest > ended);
        !blocked && !overtaken
    }
}

/// The segments an operation may take effect in next from a state in
/// segment `current`, highest first: a bound operation's own segment; for
/// an effect with an unrecorded target, its placements above
/// `max(floor, current)`, then that segment.
fn placements(constraint: &Constraint, current: Tenure) -> impl Iterator<Item = Tenure> + '_ {
    let lowest = match constraint.place {
        Place::In(tenure) => tenure,
        Place::AtLeast(floor) => floor.max(current),
    };
    constraint
        .placements
        .iter()
        .rev()
        .map(|placement| placement.tenure)
        .filter(move |&tenure| tenure > lowest)
        .chain(std::iter::once(lowest))
}

/// Returns a clock-regression witness for `ops[i]` taking effect next in
/// segment `at` with `sample`. A ceiling below `sample`, from a remaining
/// operation of the same clock domain or from `ops[i]`'s placement in
/// `at`, supplies the witness operation; otherwise a placement floor above
/// `sample` makes `ops[i]` the witness. An effect with an unrecorded target
/// samples the clock of the placement it takes effect in.
fn regression(
    i: usize,
    at: Tenure,
    sample: u64,
    pending: impl Iterator<Item = usize>,
    ops: &[&Row],
    constraints: &[Constraint],
) -> Option<OpId> {
    let constraint = &constraints[i];
    let placement = constraint
        .placements
        .iter()
        .find(|placement| placement.tenure == at);
    let domain = constraint
        .domain
        .or(placement.map(|placement| placement.tenure))?;
    let later = pending
        .filter(|&j| j != i && constraints[j].domain == Some(domain))
        .filter_map(|j| constraints[j].ceiling)
        .chain(placement.and_then(|placement| placement.ceiling))
        .filter(|later| later.sample < sample)
        .min();
    match later {
        Some(later) => Some(later.op),
        None => placement
            .and_then(|placement| placement.floor)
            .filter(|&floor| sample < floor)
            .map(|_| ops[i].op),
    }
}
