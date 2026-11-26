//! Resource reuse requires all custodians of the previous incarnation to
//! release custody. A write quota is taken while the command with its index
//! and incarnation is held and returns only after that command's terminal.
//! Client source-slot custody, retransmission retention and NIC references
//! alike, holds the client's buffer and no cache capacity, so qualified and
//! healthy checkpoints proceed while it is held. `judge_custody` also
//! compares reported totals with the held count and checks funded progress
//! at checkpoints.

use std::collections::{HashMap, HashSet};

use super::action::ActionKind;
use super::domain::lease_end;
use super::ids::{Incarnation, KeyId, Label, Ordinal, ResourceId, ResourceKind, Subject};
use super::obligation::Obligation;
use super::outcome::{Outcome, VisibilityCause};
use super::row::{ReportKind, ReportState, Row};
use super::verdict::{Activations, Violation};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Custodian {
    Owner,
    Storage,
    Nic,
    Reader,
    Grace,
    /// A client upload retains a source slot's fragment for resend until
    /// the receipt base passes it or the attempt is decided or cancelled.
    Retransmission,
}

impl Custodian {
    const fn exclusive(self) -> bool {
        matches!(
            self,
            Self::Owner | Self::Storage | Self::Grace | Self::Retransmission
        )
    }

    const fn holder(self) -> bool {
        matches!(self, Self::Nic | Self::Reader | Self::Retransmission)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Checkpoint {
    /// A stopped boundary; it ends any retention.
    Stopped,
    /// Every resource other than a budget charge has returned.
    Released,
    /// A stop without proof: custody held here stays held.
    Unproven,
    /// A funded healthy interval: `funded` actions, at most `limit`, and
    /// before the next checkpoint an exact hit of a label the interval
    /// published.
    Qualified { funded: u32, limit: u32 },
    /// The failed owner's stop retains the row's resource while a healthy
    /// owner serves; one row per resource the failed owner holds.
    Isolated,
    /// A healthy owner's interval of `turns`, at most `bound`, that serves an
    /// exact hit before the next checkpoint.
    Healthy { turns: u32, bound: u32 },
}

const fn fail(obligation: Obligation, row: &Row, rule: &'static str) -> Violation {
    Violation {
        obligation,
        op: row.op,
        rule,
    }
}

const fn command_of(quota: ResourceId) -> ResourceId {
    ResourceId {
        kind: ResourceKind::Command,
        index: quota.index,
    }
}

#[derive(Debug)]
struct Held {
    incarnation: Incarnation,
    custodians: Vec<Custodian>,
    span: Option<(u64, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    Unproven,
    Isolated,
}

#[derive(Debug, Default)]
struct Custody {
    held: HashMap<ResourceId, Held>,
    /// The incarnation each incarnated resource last returned in full; a
    /// later lifetime of the resource names a later one.
    completed: HashMap<ResourceId, Incarnation>,
    /// Incarnations an exclusive custodian has returned; custody of one
    /// incarnation passes between exclusive custodians and never back.
    returned: HashSet<(ResourceId, Incarnation, Custodian)>,
    /// The publication each slot incarnation holds, bound by the take that
    /// named it; a visibility end from that slot names the same publication.
    publications: HashMap<(ResourceId, Incarnation), (KeyId, Label)>,
    /// Slot incarnations whose bound publication received its visibility end.
    ended: HashSet<(ResourceId, Incarnation)>,
    /// Resources a stop retains, each under the stop that retained it; a
    /// released or stopped checkpoint ends the retention of the resources
    /// `judge_custody`'s `ends` names for it, so another owner incarnation's
    /// retention survives the checkpoint.
    retained: HashMap<ResourceId, Stop>,
    mismatched: HashMap<ResourceKind, u64>,
}

impl Custody {
    /// The held count of `kind`, or `None` when the held lengths exceed
    /// `u64::MAX`; overflow makes every reported count disagree with the
    /// independent total.
    fn total(&self, kind: ResourceKind) -> Option<u64> {
        self.held
            .iter()
            .filter(|(resource, _)| resource.kind == kind)
            .map(|(_, held)| held.span.map_or(1, |(_, len)| len))
            .try_fold(0u64, u64::checked_add)
    }

    fn unmatched(&mut self, row: &Row, resource: ResourceId) -> Result<(), Violation> {
        if visibility_end(row).is_some() {
            return Err(fail(
                Obligation::Custody,
                row,
                "a visibility end returned no held custody",
            ));
        }
        *self.mismatched.entry(resource.kind).or_default() += 1;
        Ok(())
    }

    fn take(&mut self, row: &Row) -> Result<(), Violation> {
        let (Some(resource), Some(custodian)) = (row.resource(), row.custodian) else {
            return Ok(());
        };
        let incarnation = row.incarnation.unwrap_or(Incarnation(0));
        if resource.kind == ResourceKind::WriteQuota
            && !self
                .held
                .get(&command_of(resource))
                .is_some_and(|held| held.incarnation == incarnation)
        {
            return Err(fail(
                Obligation::Custody,
                row,
                "a write quota was taken without its command",
            ));
        }
        if let Some(held) = self.held.get(&resource) {
            if !resource.kind.incarnated() {
                return Err(fail(
                    Obligation::Custody,
                    row,
                    "a counted resource was taken while held",
                ));
            }
            if held.incarnation != incarnation {
                return Err(fail(
                    Obligation::Custody,
                    row,
                    "a resource was reused while a custodian held an earlier incarnation",
                ));
            }
            if custodian.exclusive() && held.custodians.contains(&custodian) {
                return Err(fail(
                    Obligation::Custody,
                    row,
                    "an exclusive custodian took a resource it already held",
                ));
            }
            if custodian.exclusive() && held.custodians.iter().any(|c| c.exclusive()) {
                return Err(fail(
                    Obligation::Custody,
                    row,
                    "two exclusive custodians held one incarnation",
                ));
            }
            if let (Some(held_span), Some(span)) = (held.span, row.span)
                && held_span != span
            {
                return Err(fail(
                    Obligation::Custody,
                    row,
                    "a held extent was taken under different geometry",
                ));
            }
        } else {
            if resource.kind.spanned() && row.span.is_none() {
                return Err(fail(
                    Obligation::Custody,
                    row,
                    "a span-measured resource was taken without geometry",
                ));
            }
            if self
                .completed
                .get(&resource)
                .is_some_and(|&done| incarnation < done)
            {
                return Err(fail(
                    Obligation::Custody,
                    row,
                    "a resource was retaken under an earlier incarnation",
                ));
            }
            if custodian.holder()
                && resource.kind.incarnated()
                && self.completed.get(&resource) == Some(&incarnation)
            {
                return Err(fail(
                    Obligation::Custody,
                    row,
                    "a holder took a completed incarnation",
                ));
            }
            if self.open_publication(resource, Some(incarnation)) {
                return Err(fail(
                    Obligation::Custody,
                    row,
                    "a slot was reused before its publication's visibility ended",
                ));
            }
        }
        if custodian.exclusive()
            && resource.kind.incarnated()
            && self.returned.contains(&(resource, incarnation, custodian))
        {
            return Err(fail(
                Obligation::Custody,
                row,
                "an exclusive custodian retook an incarnation it had returned",
            ));
        }
        if let (Some(owner), Some(label)) = (row.owner, row.label)
            && *self
                .publications
                .entry((resource, incarnation))
                .or_insert((owner, label))
                != (owner, label)
        {
            return Err(fail(
                Obligation::Custody,
                row,
                "a slot was taken under another publication",
            ));
        }
        if let Some((start, len)) = row.span
            && resource.kind == ResourceKind::Extent
        {
            let end = start + len;
            let overlaps = self.held.iter().any(|(other, held)| {
                *other != resource
                    && other.kind == resource.kind
                    && held.span.is_some_and(|(s, l)| start < s + l && s < end)
            });
            if overlaps {
                return Err(fail(
                    Obligation::Custody,
                    row,
                    "writable extents overlapped",
                ));
            }
        }
        let held = self.held.entry(resource).or_insert(Held {
            incarnation,
            custodians: Vec::new(),
            span: None,
        });
        held.custodians.push(custodian);
        held.span = held.span.or(row.span);
        Ok(())
    }

    fn release(&mut self, row: &Row, custodian: Custodian) -> Result<(), Violation> {
        let Some(resource) = row.resource() else {
            return Ok(());
        };
        let incarnation = row.incarnation.unwrap_or(Incarnation(0));
        if resource.kind == ResourceKind::WriteQuota
            && self
                .held
                .get(&command_of(resource))
                .is_some_and(|held| held.incarnation == incarnation)
        {
            return Err(fail(
                Obligation::Custody,
                row,
                "a write quota returned before its command's terminal",
            ));
        }
        let retained = self.retained.get(&resource).copied();
        let Some(held) = self
            .held
            .get_mut(&resource)
            .filter(|held| held.incarnation == incarnation)
        else {
            return self.unmatched(row, resource);
        };
        let Some(at) = held.custodians.iter().position(|&c| c == custodian) else {
            return self.unmatched(row, resource);
        };
        if let Some((key, label, _)) = visibility_end(row) {
            if self.publications.get(&(resource, incarnation)) != Some(&(key, label)) {
                return Err(fail(
                    Obligation::Custody,
                    row,
                    "a visibility end named a publication its slot did not hold",
                ));
            }
            self.ended.insert((resource, incarnation));
        }
        match retained {
            Some(Stop::Isolated) => {
                return Err(fail(
                    Obligation::Isolation,
                    row,
                    "a failed owner returned custody its unproven stop retained",
                ));
            }
            Some(Stop::Unproven) => {
                return Err(fail(
                    Obligation::Resources,
                    row,
                    "an unproven stop returned retained custody",
                ));
            }
            None => {}
        }
        held.custodians.swap_remove(at);
        if held.custodians.is_empty() {
            self.held.remove(&resource);
            self.completed.insert(resource, incarnation);
        }
        if custodian.exclusive() {
            self.returned.insert((resource, incarnation, custodian));
        }
        Ok(())
    }

    fn report(&self, row: &Row, activations: &mut Activations) -> Result<(), Violation> {
        if let (Some(resource), Some(report)) = (row.resource(), row.report)
            && let ReportState::Value(reported) = report.state
        {
            let independent = if report.kind == ReportKind::Mismatched {
                Some(self.mismatched.get(&resource.kind).copied().unwrap_or(0))
            } else {
                self.total(resource.kind)
            };
            if Some(reported) != independent {
                return Err(fail(
                    Obligation::Resources,
                    row,
                    "a production report disagreed with the independent count",
                ));
            }
            activations.activate(Obligation::Resources);
        }
        Ok(())
    }

    /// Whether a slot incarnation before `until` (every incarnation when
    /// `None`) still holds a publication whose visibility never ended.
    fn open_publication(&self, resource: ResourceId, until: Option<Incarnation>) -> bool {
        self.publications.keys().any(|&(slot, bound)| {
            slot == resource
                && until.is_none_or(|next| bound < next)
                && !self.ended.contains(&(slot, bound))
        })
    }

    /// Judges a released checkpoint over the resources `owned` names: it
    /// ends their retention and requires their capacity returned and their
    /// publications' visibility ended.
    fn released(
        &mut self,
        row: &Row,
        activations: &mut Activations,
        owned: impl Fn(ResourceId) -> bool,
    ) -> Result<(), Violation> {
        self.retained.retain(|&resource, _| !owned(resource));
        if self
            .held
            .keys()
            .any(|&r| owned(r) && r.kind != ResourceKind::BudgetCharge && !r.kind.client_buffer())
        {
            return Err(fail(
                Obligation::Resources,
                row,
                "a released checkpoint kept capacity its obligations no longer justify",
            ));
        }
        let slots: HashSet<ResourceId> = self
            .publications
            .keys()
            .map(|&(slot, _)| slot)
            .filter(|&slot| owned(slot))
            .collect();
        if slots
            .into_iter()
            .any(|slot| self.open_publication(slot, None))
        {
            return Err(fail(
                Obligation::Resources,
                row,
                "a released checkpoint left a publication's visibility open",
            ));
        }
        activations.activate(Obligation::Resources);
        Ok(())
    }

    fn isolated(&mut self, row: &Row) -> Result<(), Violation> {
        let Some(resource) = row.resource() else {
            return Ok(());
        };
        let incarnation = row.incarnation.unwrap_or(Incarnation(0));
        if self
            .held
            .get(&resource)
            .is_none_or(|held| held.incarnation != incarnation)
        {
            return Err(fail(
                Obligation::Isolation,
                row,
                "an isolated stop retained custody no custodian held",
            ));
        }
        self.retained.insert(resource, Stop::Isolated);
        Ok(())
    }

    fn outstanding_holder(&self, exclude: impl Fn(&ResourceId) -> bool) -> bool {
        self.held.iter().any(|(resource, held)| {
            !exclude(resource) && held.custodians.iter().any(|c| c.holder())
        })
    }

    fn healthy(
        &self,
        row: &Row,
        (turns, bound): (u32, u32),
        interval: &[&Row],
        activations: &mut Activations,
    ) -> Result<(), Violation> {
        let isolated = |resource: &ResourceId| {
            resource.kind.client_buffer() || self.retained.get(resource) == Some(&Stop::Isolated)
        };
        if self.outstanding_holder(isolated) {
            return Err(fail(
                Obligation::Isolation,
                row,
                "a healthy checkpoint began with holders outstanding",
            ));
        }
        if turns > bound {
            return Err(fail(
                Obligation::Isolation,
                row,
                "a healthy owner starved past its fixture bound",
            ));
        }
        if !exact_hit(interval) {
            return Err(fail(
                Obligation::Isolation,
                row,
                "a healthy owner served no exact bytes",
            ));
        }
        activations.activate(Obligation::Isolation);
        Ok(())
    }

    fn qualified(
        &self,
        row: &Row,
        (funded, limit): (u32, u32),
        interval: &[&Row],
        activations: &mut Activations,
    ) -> Result<(), Violation> {
        if self.outstanding_holder(|resource| resource.kind.client_buffer()) {
            return Err(fail(
                Obligation::Progress,
                row,
                "a qualified checkpoint began with holders outstanding",
            ));
        }
        if funded > limit {
            return Err(fail(
                Obligation::Progress,
                row,
                "funded recovery exceeded its action bound",
            ));
        }
        if !published_exact_hit(interval, row.responded) {
            let attempt = interval
                .iter()
                .rev()
                .find(|r| r.kind == ActionKind::Lookup)
                .copied()
                .unwrap_or(row);
            return Err(fail(
                Obligation::Progress,
                attempt,
                "a qualified funded interval produced no exact hit",
            ));
        }
        activations.activate(Obligation::Progress);
        Ok(())
    }
}

fn interval<'r>(ordered: &'r [&'r Row], at: usize) -> &'r [&'r Row] {
    let rest = &ordered[at + 1..];
    let end = rest
        .iter()
        .position(|next| next.kind == ActionKind::Checkpoint && next.outcome.is_none())
        .unwrap_or(rest.len());
    &rest[..end]
}

fn exact_hit(interval: &[&Row]) -> bool {
    interval
        .iter()
        .any(|lookup| delivered_hit(interval, lookup))
}

/// `began` is the qualified checkpoint's response; a publication counts for
/// the interval only when it was invoked after it.
fn published_exact_hit(interval: &[&Row], began: Option<Ordinal>) -> bool {
    interval.iter().any(|lookup| {
        delivered_hit(interval, lookup)
            && interval.iter().any(|publication| {
                matches!(publication.kind, ActionKind::Publish | ActionKind::Replace)
                    && publication.invoked > began
                    && publication.outcome == Some(Outcome::Acknowledged)
                    && publication.key() == lookup.acquired_key()
                    && publication.label == lookup.label
            })
    })
}

fn delivered_hit(interval: &[&Row], lookup: &Row) -> bool {
    lookup.kind == ActionKind::Lookup
        && lookup.outcome == Some(Outcome::Hit)
        && interval.iter().any(|delivery| {
            delivery.kind == ActionKind::Deliver
                && delivery.op == lookup.op
                && delivery.outcome == Some(Outcome::Complete)
        })
}

fn visibility_end(row: &Row) -> Option<(KeyId, Label, VisibilityCause)> {
    if row.kind != ActionKind::Release || row.outcome.is_some() || row.resource().is_none() {
        return None;
    }
    Some((row.owner?, row.label?, row.cause?))
}

/// The visibility end a slot release implies: its key, label and cause,
/// at the release's interval, tenure tag and timeline, so the end
/// linearizes in the release's segment.
pub(crate) fn ended_visibility(row: &Row) -> Option<Row> {
    let (key, label, cause) = visibility_end(row)?;
    let mut ended = Row::new(row.op, ActionKind::VisibilityEnded);
    ended.subject = Some(Subject::Key(key));
    ended.label = Some(label);
    ended.cause = Some(cause);
    ended.invoked = row.invoked;
    ended.responded = row.responded;
    ended.episode = row.episode;
    ended.tenure = row.tenure;
    ended.client = row.client;
    Some(ended)
}

/// Judges resource rows and checkpoints in response order and returns the
/// first violation. Each `Stopped`, `Released` and `Unproven`
/// checkpoint reaches only the resources `ends` names for it: a stop proof
/// or release of one owner incarnation keeps another incarnation's retained
/// custody and judges only its own capacity and publications, and an
/// unproven stop retains only its own incarnation's. `Healthy` and
/// `Qualified` checkpoints judge every incarnation's holders, since a held
/// NIC or reader reference blocks progress whoever owns it.
pub(crate) fn judge_custody(
    rows: &[&Row],
    activations: &mut Activations,
    ends: impl Fn(&Row, ResourceId) -> bool,
) -> Result<(), Violation> {
    let mut ordered: Vec<&Row> = rows.to_vec();
    ordered.sort_by_key(|row| row.responded);
    let mut custody = Custody::default();
    for (at, row) in ordered.iter().enumerate() {
        match (row.kind, row.custodian) {
            (ActionKind::Take, _) if row.outcome.is_none() => {
                custody.take(row)?;
                activations.activate(Obligation::Custody);
            }
            (ActionKind::Release, Some(custodian))
                if row.outcome.is_none() && row.resource().is_some() =>
            {
                custody.release(row, custodian)?;
                activations.activate(Obligation::Custody);
            }
            (ActionKind::Terminal, _) => {
                custody.release(row, Custodian::Storage)?;
                activations.activate(Obligation::Custody);
            }
            (ActionKind::Report, _) if row.outcome.is_none() => {
                custody.report(row, activations)?;
            }
            (ActionKind::Checkpoint, _) if row.outcome.is_none() => match row.checkpoint {
                Some(Checkpoint::Released) => {
                    custody.released(row, activations, |resource| ends(row, resource))?;
                }
                Some(Checkpoint::Unproven) => {
                    for resource in custody
                        .held
                        .keys()
                        .filter(|&&r| !r.kind.client_buffer() && ends(row, r))
                    {
                        custody.retained.entry(*resource).or_insert(Stop::Unproven);
                    }
                    activations.activate(Obligation::Resources);
                }
                Some(Checkpoint::Isolated) => {
                    custody.isolated(row)?;
                    activations.activate(Obligation::Resources);
                    activations.activate(Obligation::Isolation);
                }
                Some(Checkpoint::Healthy { turns, bound }) => {
                    custody.healthy(row, (turns, bound), interval(&ordered, at), activations)?;
                }
                Some(Checkpoint::Qualified { funded, limit }) => {
                    let leased = ordered[..at].iter().any(|lookup| {
                        lookup.kind == ActionKind::Lookup
                            && lookup.outcome == Some(Outcome::Hit)
                            && lease_end(rows, lookup).is_none_or(|end| Some(end) > row.responded)
                    });
                    if leased {
                        return Err(fail(
                            Obligation::Progress,
                            row,
                            "a qualified checkpoint began with a lease outstanding",
                        ));
                    }
                    custody.qualified(row, (funded, limit), interval(&ordered, at), activations)?;
                }
                Some(Checkpoint::Stopped) => {
                    custody.retained.retain(|&resource, _| !ends(row, resource))
                }
                None => {}
            },
            _ => {}
        }
    }
    Ok(())
}
