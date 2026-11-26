//! The continuation entry: it judges a history the harness feeds in
//! segments, each ending at a validated cut, and agrees with judging the
//! whole history at once on the verdict, the first violation and the
//! activations.
//!
//! The continuation keeps every row it admitted, so each judgment that reads
//! across rows (attempts, content, deliveries, custody, the ledger and the
//! shared timeline) runs over the same rows the whole check reads. The per-key
//! legal-order search, whose cost grows with the operations it orders, is the
//! one judgment a cut shortens: operations that ended before the cut's
//! quiescent point, which every later operation follows, collapse into the
//! key's frontier, the set of every state a legal order of them can leave.
//! A tenure cut declares the lowest tenure any later row linearizes in, its
//! tag or, for a pending effect, its target's segment, so every operation
//! of a lower tenure collapses too, since tenure order puts it before every
//! later operation; a later row placed below that floor is `Malformed`.
//! The quiescent point orders operations of every client, so the
//! continuation judges histories under a shared ordinal.
//! A later search starts from each frontier state in the order the whole
//! search reaches them. A collapse knows the clock ceilings of the rows
//! recorded so far only, so a frontier may hold a state a later row's lower
//! sample would rule out; every such row also regresses behind an operation
//! that ended before it was invoked, which the shared timeline check rejects
//! before any key search, so the verdict is the whole check's.
//!
//! The agreement holds within the search bound: each collapse explores
//! every order, and each collapse and judgment spends its own budget, so
//! either may reach `SearchBound` where the whole search does not. A malformed row or declaration stops the
//! continuation where it is found, so it may name another operation than the
//! whole check names.
//! The per-key domain bounds apply over the continuation's life, as they do
//! over a whole history.
//!
//! A cut names its ordinal and declares each operation invoked before it
//! whose row arrives in a later segment, with the ordinal it was invoked
//! at. A row that completes at or past its segment's cut or that arrives at
//! a cut before the previous one, a declaration at or past its cut, a row
//! that starts before the previous cut without a declaration or before its
//! declared invocation, a first declaration invoked before the previous
//! cut, a redeclaration that moves its invocation earlier, one cut declaring
//! an operation twice, a row naming another owner incarnation than its
//! operation's earlier rows, and a declaration no row ever answers, are each
//! `Malformed`.
//! Every limit stops the continuation before any state is dropped: the
//! search budget with `SearchBound`, every other limit with a
//! `ContinuationBound` naming its dimension. A stop raised while admitting
//! or collapsing a segment is sticky; `judge` checks its own key window
//! from the carried state each time.
//!
//! Operations enter by their [`WideOp`] identity, which the caller assigns
//! once per operation and never reuses, so rows sharing one identity judge
//! as one operation; resources enter as (kind, owner incarnation, index),
//! the index unique within its owner incarnation. Both map once to the
//! compact identities the shared judges use, and a write quota and its
//! command keep one compact index.
//! Labels and episodes are `u64` identities in the rows themselves, since a
//! label names its content in the registry. A `Stopped`, `Released` or
//! `Unproven` checkpoint reaches its own owner incarnation's resources only,
//! so another incarnation's retained custody survives it and every later
//! cut. Verdicts name compact operations; [`Continuation::named`] gives the
//! wide identity a verdict names.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::action::ActionKind;
use super::bounds::{HISTORY_BOUND, SEARCH_BOUND, SearchBudget};
use super::candidates::{ConstraintsOf, Derived, constraints, key_ops, searched_keys};
use super::checker::{implied_ends, judge_rows};
use super::content::Geometry;
use super::history::admit_rows;
use super::ids::{KeyId, Label, OpId, Ordinal, Owner, ResourceId, Subject, Tenure, WideOp};
use super::key_model::{KeyState, LATER_PUBLISHED_HIT, UNPUBLISHED_HIT};
use super::outcome::VisibilityCause;
use super::row::{Field, Row};
use super::search::{frontier, ordered};
use super::tenure::{ActivationLog, Ordinals, Place};
use super::verdict::{Inconclusive, Verdict, Violation};

/// One recorded row with its wide operation identity and its owner
/// incarnation.
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    row: Row,
    op: WideOp,
    owner: Owner,
}

impl Entry {
    /// `row` as operation `op` of `owner`; the continuation replaces the
    /// row's own operation and resource index with compact ones.
    pub(crate) fn new(row: Row, op: WideOp, owner: Owner) -> Self {
        Self { row, op, owner }
    }
}

/// An operation invoked before a cut whose row arrives in a later segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pending {
    pub(crate) op: WideOp,
    pub(crate) invoked: Ordinal,
}

/// The continuation's limits, each with its own `ContinuationBound`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// Rows one segment carries, reported as `"window"`, and operations one
    /// key's search orders at once, reported as `"key window"`: at most the
    /// 128 bits of the search mask.
    pub(crate) window: usize,
    /// Rows the continuation keeps over its life.
    pub(crate) rows: usize,
    /// Operations one cut may leave pending, which the harness sizes from
    /// its queue depths.
    pub(crate) pending: usize,
    /// States one key's frontier holds.
    pub(crate) frontier: usize,
    /// Search expansions one key spends per collapse and per judgment.
    pub(crate) search: u32,
}

/// The default windows of rows the continuation keeps over its life; a
/// harness passes its own.
const RETAINED_WINDOWS: usize = 32;

/// The default operations a cut may leave pending; a harness passes its own
/// queue depths.
const PENDING: usize = 64;

/// The default limits: a window of the history bound, the search mask's
/// width; a frontier of `HISTORY_BOUND` states, a collapse that reaches more
/// stopping with `ContinuationBound`; the default retained rows and pending
/// count; and the existing search bound per key.
pub(crate) const LIMITS: Limits = Limits {
    window: HISTORY_BOUND,
    rows: HISTORY_BOUND * RETAINED_WINDOWS,
    pending: PENDING,
    frontier: HISTORY_BOUND,
    search: SEARCH_BOUND,
};

const _: () = assert!(HISTORY_BOUND <= 128, "one window fits the search mask");

/// A searched operation's identity across collapses and judgments: its
/// operation, kind, label and cause, and its ordinals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Searched {
    op: OpId,
    kind: ActionKind,
    label: Option<Label>,
    cause: Option<VisibilityCause>,
    invoked: Option<Ordinal>,
    responded: Option<Ordinal>,
}

fn searched(row: &Row) -> Searched {
    Searched {
        op: row.op,
        kind: row.kind,
        label: row.label,
        cause: row.cause,
        invoked: row.invoked,
        responded: row.responded,
    }
}

/// `violation` as the whole check names it: a hit a collapse found
/// unpublished before a later tenure's publication of its label arrived is
/// a hit of a version only a later tenure published.
fn named_at_judgment(
    violation: Violation,
    ops: &[&Row],
    constrain: ConstraintsOf<'_>,
) -> Violation {
    let later = violation.rule == UNPUBLISHED_HIT
        && ops
            .iter()
            .find(|op| op.op == violation.op && op.kind == ActionKind::Lookup)
            .is_some_and(|&hit| constrain(&[hit])[0].published_later);
    if later {
        Violation {
            rule: LATER_PUBLISHED_HIT,
            ..violation
        }
    } else {
        violation
    }
}

/// One key's collapsed search: the states every legal order of its
/// collapsed operations can leave, those operations, and a failure once no
/// order exists. Operations whose collapse leaves the verdict to an
/// unrecorded landing stay open, so the final judgment searches them with
/// every later operation of their key.
#[derive(Debug, Clone)]
struct Frontier {
    states: Vec<KeyState>,
    collapsed: HashSet<Searched>,
    failed: Option<Violation>,
}

impl Default for Frontier {
    fn default() -> Self {
        Self {
            states: vec![KeyState::default()],
            collapsed: HashSet::new(),
            failed: None,
        }
    }
}

/// A history judged across validated cuts.
#[derive(Debug)]
pub(crate) struct Continuation {
    limits: Limits,
    geometry: Geometry,
    rows: Vec<Row>,
    /// Each compact operation's wide identity and owner incarnation, which
    /// an operation first named by a pending declaration takes from its
    /// first row.
    wide: Vec<(WideOp, Option<Owner>)>,
    ops: HashMap<WideOp, OpId>,
    /// One compact index per (owner, index) pair across kinds, so a write
    /// quota keeps its command's index.
    resources: HashMap<(Owner, u32), u32>,
    /// Each compact resource index's owner incarnation.
    resource_owners: Vec<Owner>,
    /// The latest cut's ordinal.
    cut: Ordinal,
    pending: Vec<(OpId, Ordinal)>,
    keys: BTreeMap<KeyId, Frontier>,
    /// The tenure every row of a later segment is placed at or above, from
    /// the latest cut.
    floor: Tenure,
    /// The floor the next cut adopts.
    declared: Tenure,
    stopped: Option<Inconclusive>,
}

impl Continuation {
    /// A continuation under `geometry`. When `geometry` fails
    /// [`Geometry::defines_windows`], the continuation starts stopped: it
    /// admits no segment and judges `Inconclusive::Geometry`.
    ///
    /// # Panics
    ///
    /// When `limits.window` exceeds the history bound, the search mask's
    /// width.
    pub(crate) fn new(limits: Limits, geometry: Geometry) -> Self {
        assert!(
            limits.window <= HISTORY_BOUND,
            "a window fits the search mask"
        );
        Self {
            limits,
            geometry,
            rows: Vec::new(),
            wide: Vec::new(),
            ops: HashMap::new(),
            resources: HashMap::new(),
            resource_owners: Vec::new(),
            cut: Ordinal(0),
            pending: Vec::new(),
            keys: BTreeMap::new(),
            floor: Tenure::INITIAL,
            declared: Tenure::INITIAL,
            stopped: (!geometry.defines_windows()).then_some(Inconclusive::Geometry {
                chunk: geometry.chunk,
                header: geometry.header,
            }),
        }
    }

    /// The wide identity of compact operation `op`.
    ///
    /// # Panics
    ///
    /// When `op` names no operation the continuation admitted.
    pub(crate) fn wide(&self, op: OpId) -> WideOp {
        self.wide[op.0 as usize].0
    }

    /// The wide identity of the operation `verdict` names, if it names one.
    pub(crate) fn named(&self, verdict: &Verdict) -> Option<WideOp> {
        let op = match *verdict {
            Verdict::Violation(violation) => violation.op,
            Verdict::Inconclusive(
                Inconclusive::Malformed { op, .. }
                | Inconclusive::Unresolved { op, .. }
                | Inconclusive::PoisonedReport { op, .. }
                | Inconclusive::AbsentReport { op, .. }
                | Inconclusive::UnloggedTenure { op, .. }
                | Inconclusive::UnplacedSample { op },
            ) => op,
            _ => return None,
        };
        Some(self.wide(op))
    }

    /// Searched operations collapsed into frontiers, and the most states one
    /// frontier holds.
    pub(crate) fn collapsed(&self) -> (usize, usize) {
        self.keys.values().fold((0, 0), |(ops, widest), frontier| {
            (
                ops + frontier.collapsed.len(),
                widest.max(frontier.states.len()),
            )
        })
    }

    fn bound(&mut self, dimension: &'static str, limit: usize) {
        self.stopped
            .get_or_insert(Inconclusive::ContinuationBound { dimension, limit });
    }

    fn malformed(&mut self, op: OpId, field: Field) {
        self.stopped
            .get_or_insert(Inconclusive::Malformed { op, field });
    }

    fn compact_op(&mut self, wide: WideOp, owner: Option<Owner>) -> Option<OpId> {
        if let Some(&op) = self.ops.get(&wide) {
            return Some(op);
        }
        let Ok(next) = u32::try_from(self.wide.len()) else {
            self.bound("operations", u32::MAX as usize);
            return None;
        };
        self.ops.insert(wide, OpId(next));
        self.wide.push((wide, owner));
        Some(OpId(next))
    }

    fn compact_resource(&mut self, resource: ResourceId, owner: Owner) -> Option<ResourceId> {
        let key = (owner, resource.index);
        if let Some(&index) = self.resources.get(&key) {
            return Some(ResourceId { index, ..resource });
        }
        let Ok(index) = u32::try_from(self.resource_owners.len()) else {
            self.bound("resources", u32::MAX as usize);
            return None;
        };
        self.resources.insert(key, index);
        self.resource_owners.push(owner);
        Some(ResourceId { index, ..resource })
    }

    /// Declares that every row of the segments after the next cut is placed
    /// at or above `floor`. The next cut collapses each operation placed
    /// below the lowest floor any uncollapsed effect may still land at, and
    /// rejects a later row placed below `floor` as `Malformed`.
    pub(crate) fn tenure_cut(&mut self, floor: Tenure) {
        self.declared = self.declared.max(floor);
    }

    /// Admits `entries`, the rows recorded since the previous cut, and cuts
    /// at ordinal `at`, leaving `pending` open.
    pub(crate) fn segment(&mut self, entries: Vec<Entry>, at: Ordinal, pending: &[Pending]) {
        if self.stopped.is_some() {
            return;
        }
        if entries.len() > self.limits.window {
            return self.bound("window", self.limits.window);
        }
        if pending.len() > self.limits.pending {
            return self.bound("pending", self.limits.pending);
        }
        if self.rows.len() + entries.len() > self.limits.rows {
            return self.bound("rows", self.limits.rows);
        }
        let admitted = self.rows.len();
        for Entry { mut row, op, owner } in entries {
            let Some(op) = self.compact_op(op, Some(owner)) else {
                return;
            };
            match self.wide[op.0 as usize].1 {
                Some(recorded) if recorded != owner => {
                    return self.malformed(op, Field::Resource);
                }
                _ => self.wide[op.0 as usize].1 = Some(owner),
            }
            row.op = op;
            if let Some(Subject::Resource(resource)) = row.subject {
                let Some(resource) = self.compact_resource(resource, owner) else {
                    return;
                };
                row.subject = Some(Subject::Resource(resource));
            }
            if at < self.cut || row.ordinals().any(|(_, ordinal)| ordinal >= at) {
                return self.malformed(op, Field::Response);
            }
            let started = row.ordinals().map(|(_, ordinal)| ordinal).min();
            let declared = self
                .pending
                .iter()
                .find(|&&(open, _)| open == op)
                .map(|&(_, invoked)| invoked);
            if started.is_some_and(|start| {
                start < self.cut && declared.is_none_or(|invoked| start < invoked)
            }) {
                return self.malformed(op, Field::Invocation);
            }
            self.rows.push(row);
        }
        let mut open = Vec::with_capacity(pending.len());
        for declared in pending {
            let Some(op) = self.compact_op(declared.op, None) else {
                return;
            };
            let carried = self
                .pending
                .iter()
                .find(|&&(earlier, _)| earlier == op)
                .map(|&(_, invoked)| invoked);
            // A cut's quiescent point trusted the earlier declaration, so an
            // earlier invocation now would have pinned it lower.
            let moved = carried.is_some_and(|invoked| declared.invoked < invoked);
            let late = carried.is_none() && declared.invoked < self.cut;
            let repeated = open.iter().any(|&(declared, _)| declared == op);
            if declared.invoked >= at || moved || late || repeated {
                return self.malformed(op, Field::Invocation);
            }
            open.push((op, declared.invoked));
        }
        let answered = |earlier: OpId| {
            open.iter().any(|&(still, _)| still == earlier)
                || self.rows[admitted..].iter().any(|row| {
                    row.op == earlier && row.ordinals().any(|(_, ordinal)| ordinal >= self.cut)
                })
        };
        if let Some(&(op, _)) = self
            .pending
            .iter()
            .find(|&&(earlier, _)| !answered(earlier))
        {
            return self.malformed(op, Field::Response);
        }
        let log = match self.log() {
            Ok(log) => log,
            Err(reason) => {
                self.stopped.get_or_insert(reason);
                return;
            }
        };
        if let Some(low) = self.rows[admitted..]
            .iter()
            .find(|row| log.place(row).tenure() < self.floor)
        {
            return self.malformed(low.op, Field::Tenure);
        }
        self.floor = self.floor.max(self.declared);
        self.cut = self.cut.max(at);
        self.pending = open;
        self.collapse(&log);
    }

    fn log(&self) -> Result<ActivationLog, Inconclusive> {
        let all: Vec<&Row> = self.rows.iter().collect();
        ActivationLog::of(&all)
    }

    /// Collapses into each key's frontier the operations every later
    /// operation follows in tenure order: each operation tagged below the
    /// collapse tenure, the lowest of the floor and each uncollapsed
    /// effect's landing floor, and each one of the collapse tenure that
    /// ended before the cut's quiescent point. An effect with an unrecorded
    /// target collapses only when every segment it may land in is at or
    /// below the collapse tenure; until then its key's operations of the
    /// collapse tenure stay open beside it. That point is the latest no
    /// later than the cut and every pending invocation, with each searched
    /// operation of the collapse tenure starting at or after it or ending
    /// before it.
    fn collapse(&mut self, log: &ActivationLog) {
        let live: Vec<&Row> = self
            .rows
            .iter()
            .filter(|row| !row.evidence.is_recovery())
            .collect();
        let ended = implied_ends(&live);
        let all: Vec<&Row> = live.iter().copied().chain(ended.iter()).collect();
        let derived = Derived::of(&all, log);
        let searches: Vec<(KeyId, &Row, Vec<&Row>)> = searched_keys(&all)
            .into_iter()
            .filter_map(|key| {
                let ops = key_ops(&all, &derived, key);
                let first = *ops.first()?;
                let collapsed = self.keys.get(&key).map(|carried| &carried.collapsed);
                let open = ops
                    .into_iter()
                    .filter(|op| collapsed.is_none_or(|done| !done.contains(&searched(op))))
                    .collect();
                Some((key, first, open))
            })
            .collect();
        let lowest = searches
            .iter()
            .flat_map(|(_, _, open)| open.iter())
            .filter_map(|op| match log.place(op) {
                Place::AtLeast(floor) => Some(floor),
                Place::In(_) => None,
            })
            .fold(self.floor, Tenure::min);
        let mut quiet = self
            .pending
            .iter()
            .map(|&(_, invoked)| invoked.0)
            .fold(self.cut.0, u32::min);
        while let Some(start) = searches
            .iter()
            .flat_map(|(_, _, open)| open.iter())
            .filter(|op| log.place(op).tenure() >= lowest)
            .map(|op| op.interval())
            .filter(|&(start, end)| start < quiet && quiet <= end)
            .map(|(start, _)| start)
            .min()
        {
            quiet = start;
        }
        for (key, first, open) in &searches {
            let carried = self.keys.entry(*key).or_default();
            if carried.failed.is_some() {
                continue;
            }
            // An effect that may land in the collapse tenure or above it
            // stays open, and so does every operation of the collapse
            // tenure, effects included, that it may still precede or follow.
            let held = open.iter().any(|op| {
                matches!(log.place(op), Place::AtLeast(floor) if floor <= lowest)
                    && log.latest(op) > lowest
            });
            let closing: Vec<&Row> = open
                .iter()
                .copied()
                .filter(|op| match log.place(op) {
                    Place::In(tenure) => {
                        tenure < lowest || (tenure == lowest && !held && op.interval().1 < quiet)
                    }
                    Place::AtLeast(floor) => {
                        floor <= lowest
                            && !held
                            && log.latest(op) <= lowest
                            && op.interval().1 < quiet
                    }
                })
                .collect();
            if closing.is_empty() {
                continue;
            }
            if closing.len() > self.limits.window {
                return self.bound("key window", self.limits.window);
            }
            let bound = constraints(&all, &closing, log);
            let search = |ops: &[&Row]| {
                let mut budget = SearchBudget::new(self.limits.search);
                frontier(
                    ops,
                    &bound,
                    &carried.states,
                    first.op,
                    &mut budget,
                    self.limits.frontier,
                )
            };
            let collapsed = derived.judged(&closing, search);
            match collapsed {
                Ok(Ok(states)) => {
                    carried.states = states;
                    carried
                        .collapsed
                        .extend(closing.iter().map(|op| searched(op)));
                }
                Ok(Err(violation)) => carried.failed = Some(violation),
                Err(Inconclusive::UnplacedSample { .. }) => {}
                Err(reason) => {
                    self.stopped.get_or_insert(reason);
                    return;
                }
            }
        }
    }

    /// The judgment of every row admitted so far, as the whole check judges
    /// the same rows, with each key's search continuing from its frontier.
    pub(crate) fn judge(&self) -> Verdict {
        if let Some(reason) = self.stopped {
            return Verdict::Inconclusive(reason);
        }
        if let Err(reason) = admit_rows(&self.rows) {
            return Verdict::Inconclusive(reason);
        }
        let all: Vec<&Row> = self.rows.iter().collect();
        let initial = Frontier::default();
        let search = |key: KeyId, ops: &[&Row], constrain: ConstraintsOf<'_>| {
            let carried = self.keys.get(&key).unwrap_or(&initial);
            if let Some(violation) = carried.failed {
                return Ok(Err(named_at_judgment(violation, ops, constrain)));
            }
            let Some(first) = ops.first() else {
                return Ok(Ok(()));
            };
            let open: Vec<&Row> = ops
                .iter()
                .copied()
                .filter(|op| !carried.collapsed.contains(&searched(op)))
                .collect();
            if open.is_empty() {
                return Ok(Ok(()));
            }
            if open.len() > self.limits.window {
                return Err(Inconclusive::ContinuationBound {
                    dimension: "key window",
                    limit: self.limits.window,
                });
            }
            let mut budget = SearchBudget::new(self.limits.search);
            ordered(
                &open,
                &constrain(&open),
                &carried.states,
                first.op,
                &mut budget,
            )
        };
        let ends = |checkpoint: &Row, resource: ResourceId| {
            self.wide[checkpoint.op.0 as usize].1
                == self.resource_owners.get(resource.index as usize).copied()
        };
        judge_rows(&all, self.geometry, Ordinals::Shared, search, ends)
    }

    /// The final judgment: [`judge`](Self::judge) once no operation the last
    /// cut left pending is still unanswered.
    pub(crate) fn finish(&self) -> Verdict {
        if self.stopped.is_none()
            && let Some(&(op, _)) = self.pending.first()
        {
            return Verdict::Inconclusive(Inconclusive::Malformed {
                op,
                field: Field::Response,
            });
        }
        self.judge()
    }
}
