//! Tenure order. The activation log names every tenure a history activates:
//! the initial tenure from ordinal zero, then one per `Restart` row that
//! records its event, in response order, each strictly above the previous. A row's tag is its
//! recorded tenure, or for an owner row the tenure active at its invocation.
//! An operation linearizes in its tag's segment; a pending effect lands in
//! its target's segment, or with an unrecorded target in any segment at or
//! above its floor that was active before its landing window ended.
//!
//! Real-time precedence holds inside one clock domain between rows the
//! history's ordinals order. What the ordinals order is a property of the
//! history's evidence: one counter that stamps every row, as in the
//! simulation, orders rows of every client; per-client ordinals, stamped by
//! each client and by the owner separately, order the rows of one client,
//! or of the owner, only. A per-client history is judged under two
//! readings. The lenient one restricts legal orders by precedence inside
//! one timeline only and counts every sample of another timeline as
//! possibly earlier, so a failure under it holds in every cross-timeline
//! order. The strict one also reads the recorded ordinals across timelines
//! as one order the history admits and counts a sample as earlier only
//! inside the row's timeline, so a pass under it holds with no
//! cross-timeline precedence and in that recorded order too.

use std::collections::HashMap;

use super::action::ActionKind;
use super::ids::{ClientId, CutId, OpId, Ordinal, Tenure};
use super::obligation::Obligation;
use super::row::{Field, Row};
use super::rules::{Rule, holds};
use super::verdict::{Inconclusive, Violation};

/// Where an operation may linearize: inside one tenure's segment, or in any
/// segment at or above a floor. A request records its target as a place:
/// the tenure its session was bound to when it was sent, or, when the
/// binding went unrecorded, the client's high-water at send as a floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Place {
    In(Tenure),
    AtLeast(Tenure),
}

impl Place {
    /// The lowest tenure whose segment the place admits.
    pub(crate) const fn tenure(self) -> Tenure {
        match self {
            Self::In(tenure) | Self::AtLeast(tenure) => tenure,
        }
    }
}

/// What a history's ordinals order inside one tenure: every row, when one
/// counter stamped them all, or the rows of one client, and the owner's
/// rows, when each stamped its own. Per-client ordinals stay distinct
/// across the history, as admission requires, so their merge is one
/// recorded interleaving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Ordinals {
    #[default]
    Shared,
    PerClient,
}

/// How a judgment reads precedence between rows of two timelines: under a
/// shared ordinal, or under per-client ordinals as the module's lenient or
/// strict reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reading {
    Shared,
    Lenient,
    Strict,
}

/// The kinds a per-client history may hold: the per-key search's, the
/// fill flow's and the activation log's. Every other kind is judged by
/// comparisons a shared ordinal orders.
const PER_CLIENT_KINDS: [ActionKind; 12] = [
    ActionKind::Fill,
    ActionKind::Receive,
    ActionKind::WriteCompleted,
    ActionKind::Publish,
    ActionKind::Replace,
    ActionKind::Lookup,
    ActionKind::Invalidate,
    ActionKind::Expire,
    ActionKind::Evict,
    ActionKind::VisibilityEnded,
    ActionKind::Close,
    ActionKind::Restart,
];

/// The first row of a per-client history that only a shared ordinal lets
/// the checker judge: a client row with no recorded tag, which the owner's
/// activation ordinals would decide; a row whose operation another
/// client's row shares; a row naming an upload serial or a cut, or a
/// recovery row other than a restart; a restart a client recorded, since
/// activations sit on the owner's timeline; or a row of a kind outside
/// [`PER_CLIENT_KINDS`].
pub(crate) fn per_client_scope(rows: &[&Row]) -> Option<OpId> {
    let mut clients: HashMap<OpId, Option<ClientId>> = HashMap::new();
    rows.iter()
        .find(|row| {
            let shared = *clients.entry(row.op).or_insert(row.client) != row.client;
            shared
                || (row.client.is_some() && row.tenure.is_none())
                || row.serial.is_some()
                || row.cut.is_some()
                || (row.evidence.is_recovery() && row.kind != ActionKind::Restart)
                || (row.kind == ActionKind::Restart && row.client.is_some())
                || !PER_CLIENT_KINDS.contains(&row.kind)
        })
        .map(|row| row.op)
}

/// One activated tenure, from the response ordinal `at` of the row that
/// activated it, naming the retained cut it recovers from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Activation {
    pub(crate) at: Ordinal,
    pub(crate) tenure: Tenure,
    pub(crate) cut: Option<CutId>,
    /// The activating `Restart` row; `None` for the initial tenure.
    pub(crate) op: Option<OpId>,
}

/// Every activated tenure in response order, each client's high-water by
/// response ordinal, and how judgments read precedence across timelines.
/// `seen` is sorted by client and response ordinal, and each entry holds
/// that client's running high-water at that response: the highest
/// high-water it recorded, or tag it accepted, at or before it.
#[derive(Debug, Clone)]
pub(crate) struct ActivationLog {
    activations: Vec<Activation>,
    seen: Vec<(ClientId, Ordinal, Tenure)>,
    reading: Reading,
}

impl ActivationLog {
    /// The log `rows` record, under a shared ordinal. An untagged `Restart`
    /// activates the next generation's first attachment.
    ///
    /// # Errors
    ///
    /// `Malformed` naming `Tenure` when an activation's tenure is not above
    /// every earlier one, or when an untagged `Restart` follows the last
    /// generation.
    pub(crate) fn of(rows: &[&Row]) -> Result<Self, Inconclusive> {
        let mut restarts: Vec<&Row> = rows
            .iter()
            .copied()
            .filter(|row| row.kind == ActionKind::Restart && row.records_event())
            .collect();
        restarts.sort_by_key(|row| row.responded);
        let mut activations = vec![Activation {
            at: Ordinal(0),
            tenure: Tenure::INITIAL,
            cut: None,
            op: None,
        }];
        for row in restarts {
            let previous = activations[activations.len() - 1].tenure;
            let malformed = Inconclusive::Malformed {
                op: row.op,
                field: Field::Tenure,
            };
            let tenure = match row.tenure {
                Some(tenure) => tenure,
                None => Tenure {
                    g: previous.g.checked_add(1).ok_or(malformed)?,
                    a: 0,
                },
            };
            if tenure <= previous {
                return Err(malformed);
            }
            activations.push(Activation {
                at: row.responded.unwrap_or(Ordinal(0)),
                tenure,
                cut: row.cut,
                op: Some(row.op),
            });
        }
        let mut seen: Vec<(ClientId, Ordinal, Tenure)> = rows
            .iter()
            .filter_map(|row| Some((row, row.client?, row.acceptance?, row.responded?)))
            .flat_map(|(row, client, acceptance, responded)| {
                let accepted = row.tenure.filter(|_| acceptance.accepted);
                [acceptance.high_water, accepted]
                    .into_iter()
                    .flatten()
                    .map(move |tenure| (client, responded, tenure))
            })
            .collect();
        seen.sort_unstable();
        // Each entry becomes its client's running high-water at that response.
        for at in 1..seen.len() {
            if seen[at].0 == seen[at - 1].0 {
                seen[at].2 = seen[at].2.max(seen[at - 1].2);
            }
        }
        Ok(Self {
            activations,
            seen,
            reading: Reading::Shared,
        })
    }

    /// This log with precedence across timelines read as `reading`.
    pub(crate) fn read(&self, reading: Reading) -> Self {
        Self {
            activations: self.activations.clone(),
            seen: self.seen.clone(),
            reading,
        }
    }

    /// `client`'s high-water when it sent a request invoked at `sent`: the
    /// highest high-water it recorded, or tag it accepted, at a response
    /// before `sent`. `seen` holds each client's running maximum in
    /// response order, so the last entry before `sent` is that maximum.
    fn high_water(&self, client: ClientId, sent: Option<Ordinal>) -> Tenure {
        let Some(sent) = sent else {
            return Tenure::INITIAL;
        };
        let end = self
            .seen
            .partition_point(|&(by, at, _)| (by, at) < (client, sent));
        match self.seen[..end].last() {
            Some(&(by, _, tenure)) if by == client => tenure,
            _ => Tenure::INITIAL,
        }
    }

    pub(crate) fn activations(&self) -> &[Activation] {
        &self.activations
    }

    /// The tenure active at `at`: the latest activation at or before it.
    /// Activations are in response order, so a binary search finds it.
    fn active(&self, at: Option<Ordinal>) -> Tenure {
        let at = at.unwrap_or(Ordinal(0));
        let end = self
            .activations
            .partition_point(|activation| activation.at <= at);
        self.activations[..end]
            .last()
            .map_or(Tenure::INITIAL, |activation| activation.tenure)
    }

    /// The tenure whose segment `row` belongs to: its recorded tag, else
    /// the tenure active at its invocation.
    pub(crate) fn tag(&self, row: &Row) -> Tenure {
        if !holds(Rule::TenureOrder) {
            return Tenure::INITIAL;
        }
        row.tenure
            .unwrap_or_else(|| self.active(row.invoked.or(row.responded)))
    }

    /// Where `row` linearizes. A cancelled or timed-out effect lands in its
    /// recorded target's place; with an unrecorded target, a client's effect
    /// lands in any segment at or above both its recorded floor and the
    /// client's high-water when it sent the request, and an owner's in the
    /// tenure active at its invocation.
    pub(crate) fn place(&self, row: &Row) -> Place {
        if !holds(Rule::TenureOrder) {
            return Place::In(Tenure::INITIAL);
        }
        if !row.pending_effect() {
            return Place::In(self.tag(row));
        }
        match (row.target, row.client) {
            (Some(Place::AtLeast(floor)), Some(client)) => {
                Place::AtLeast(floor.max(self.high_water(client, row.invoked)))
            }
            (Some(target), _) => target,
            (None, Some(client)) => Place::AtLeast(self.high_water(client, row.invoked)),
            (None, None) => Place::In(self.tag(row)),
        }
    }

    /// The tenure whose clock domain `row`'s sample belongs to: the one
    /// segment its effect lands in when that segment is known, else its tag.
    pub(crate) fn domain(&self, row: &Row) -> Tenure {
        self.clock_domain(row).unwrap_or_else(|| self.tag(row))
    }

    /// The clock domain of `row`'s sample when its segment is known: the
    /// segment of a bound effect, and the one segment an effect with an
    /// unrecorded target lands in when its floor is the latest tenure
    /// activated before its landing window ended. An effect that may land
    /// in several segments samples the clock of whichever it lands in.
    pub(crate) fn clock_domain(&self, row: &Row) -> Option<Tenure> {
        match self.place(row) {
            Place::In(tenure) => Some(tenure),
            Place::AtLeast(floor) => (floor == self.latest(row)).then_some(floor),
        }
    }

    /// The timeline whose ordinals order `row` against others in the
    /// per-key search: the one shared timeline, or under the lenient
    /// reading the row's client, `None` naming the owner.
    pub(crate) fn timeline(&self, row: &Row) -> Option<ClientId> {
        match self.reading {
            Reading::Shared | Reading::Strict => None,
            Reading::Lenient => row.client,
        }
    }

    /// Whether `earlier` ended before `at`, an ordinal of `row`, in `row`'s
    /// clock domain and, under the lenient reading, on its timeline: the
    /// real-time precedence that restricts legal orders.
    pub(crate) fn precedes(&self, earlier: &Row, row: &Row, at: Option<Ordinal>) -> bool {
        self.domain(earlier) == self.domain(row)
            && self.timeline(earlier) == self.timeline(row)
            && at.is_some_and(|at| earlier.interval().1 < at.0)
    }

    /// Whether `earlier`'s clock sample bounds `row`'s from below: both
    /// belong to one known clock domain and `earlier` precedes `row`.
    pub(crate) fn samples_before(&self, earlier: &Row, row: &Row, at: Option<Ordinal>) -> bool {
        self.clock_domain(earlier).is_some()
            && self.clock_domain(row).is_some()
            && self.precedes(earlier, row, at)
    }

    /// Whether `earlier`'s sample counts as evidence of `row`'s clock.
    pub(crate) fn may_sample_before(&self, earlier: &Row, row: &Row, at: Option<Ordinal>) -> bool {
        match self.reading {
            Reading::Shared => {
                self.samples_before(earlier, row, at)
                    || self.branch_samples_before(earlier, row, at)
            }
            Reading::Strict => {
                earlier.client == row.client && self.samples_before(earlier, row, at)
            }
            Reading::Lenient => {
                let domain = self.clock_domain(row);
                self.clock_domain(earlier)
                    .is_none_or(|earlier| domain.is_none_or(|domain| domain == earlier))
                    && (earlier.client != row.client || self.precedes(earlier, row, at))
            }
        }
    }

    /// Whether, under a shared ordinal, `earlier` is an effect that may
    /// land in several segments, `row`'s known clock domain among them, and
    /// ended before `at`: its sample bounds `row`'s on the branch where it
    /// lands in that domain.
    pub(crate) fn branch_samples_before(
        &self,
        earlier: &Row,
        row: &Row,
        at: Option<Ordinal>,
    ) -> bool {
        let (Reading::Shared, Place::AtLeast(floor), None, Some(domain)) = (
            self.reading,
            self.place(earlier),
            self.clock_domain(earlier),
            self.clock_domain(row),
        ) else {
            return false;
        };
        floor <= domain
            && domain <= self.latest(earlier)
            && at.is_some_and(|at| earlier.interval().1 < at.0)
    }

    /// The highest segment `row`'s effect lands in: the latest tenure
    /// activated before its landing window ended. Under the lenient reading
    /// a client's window and the owner's activations share no timeline, so
    /// every activated tenure stays open to it.
    pub(crate) fn latest(&self, row: &Row) -> Tenure {
        if self.reading == Reading::Lenient && row.client.is_some() {
            return self.active(Some(Ordinal(u32::MAX)));
        }
        self.active(Some(Ordinal(row.interval().1)))
    }

    /// The cut the activation of `tenure` names.
    fn cut(&self, tenure: Tenure) -> Option<CutId> {
        self.activations
            .iter()
            .find(|activation| activation.tenure == tenure)
            .and_then(|activation| activation.cut)
    }

    /// Checks that every recorded tag and recorded high-water names a tenure
    /// activated at or before its row's response, and every recorded target
    /// one activated at or before its request's invocation; under per-client
    /// ordinals a client row's tag, high-water and target need only name an
    /// activated tenure.
    ///
    /// # Errors
    ///
    /// `UnloggedTenure` naming the first row whose tag, recorded high-water
    /// or target the log lacks: a harness failure, never a pass.
    pub(crate) fn reconcile(&self, rows: &[&Row]) -> Result<(), Inconclusive> {
        if !holds(Rule::TagReconciliation) {
            return Ok(());
        }
        for row in rows.iter().filter(|row| row.kind != ActionKind::Restart) {
            // The owner's activation ordinals order a client's rows only
            // under a shared ordinal.
            let ordered = self.reading == Reading::Shared || row.client.is_none();
            let logged = |tenure: Tenure, by: Option<Ordinal>| {
                let by = by.unwrap_or(Ordinal(0));
                self.activations.iter().any(|activation| {
                    activation.tenure == tenure && (!ordered || activation.at <= by)
                })
            };
            let tagged = row.tenure.map(|tenure| (tenure, row.responded));
            let watered = row
                .acceptance
                .and_then(|acceptance| acceptance.high_water)
                .map(|tenure| (tenure, row.responded));
            let targeted = row
                .target
                .map(|target| (target.tenure(), row.invoked.or(row.responded)));
            if let Some((tenure, _)) = tagged
                .into_iter()
                .chain(watered)
                .chain(targeted)
                .find(|&(tenure, by)| !logged(tenure, by))
            {
                return Err(Inconclusive::UnloggedTenure { op: row.op, tenure });
            }
        }
        Ok(())
    }

    /// Checks that each recorded `Restore` names the cut its tenure's
    /// activation named.
    pub(crate) fn judge_restores(&self, rows: &[&Row]) -> Result<(), Violation> {
        for row in rows
            .iter()
            .filter(|row| row.kind == ActionKind::Restore && row.records_event())
        {
            if row.cut.is_none() || row.cut != self.cut(self.tag(row)) {
                return Err(Violation {
                    obligation: Obligation::History,
                    op: row.op,
                    rule: "a recorded restore from a checkpoint the store did not name",
                });
            }
        }
        Ok(())
    }
}
