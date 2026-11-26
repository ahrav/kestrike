//! Each remote upload's client rows agree with the owner rows of the same
//! attempt. Every ACK's receipt base and mask count only distinct fragments
//! the owner validated before it. A source slot's
//! retransmission retention ends only after the receipt base passes the
//! fragment its take named, the client's local outcome (`Unknown` included)
//! or the tenure's cancel. `Unknown` keeps the request identity, not the
//! source bytes.

use std::collections::{HashMap, HashSet};

use super::action::ActionKind;
use super::attempt::{FRAGMENT_BYTES, PutOutcome, Serial, fragment_count};
use super::custody::Custodian;
use super::ids::{OpId, Ordinal};
use super::obligation::Obligation;
use super::outcome::Outcome;
use super::row::Row;
use super::verdict::{Activations, Violation};

const fn fail(op: OpId, rule: &'static str) -> Violation {
    Violation {
        obligation: Obligation::History,
        op,
        rule,
    }
}

const OWNER_FLOW: [ActionKind; 5] = [
    ActionKind::Fill,
    ActionKind::Receive,
    ActionKind::WriteCompleted,
    ActionKind::Publish,
    ActionKind::Replace,
];

/// `response` preserves `Option<Ordinal>` ordering for receipt comparisons:
/// a row without a response precedes every recorded one.
fn response(row: &Row) -> u64 {
    match row.responded {
        Some(at) => u64::from(at.0) + 1,
        None => 0,
    }
}

struct Attempt<'a> {
    begin: &'a Row,
    own: Vec<&'a Row>,
    serial: Option<Serial>,
    results: Vec<(&'a Row, PutOutcome)>,
}

impl<'a> Attempt<'a> {
    fn new(begin: &'a Row, rows: &[&'a Row]) -> Self {
        let own: Vec<&Row> = rows.iter().copied().filter(|r| r.op == begin.op).collect();
        let serial = own
            .iter()
            .filter(|r| r.kind != ActionKind::Retry)
            .find_map(|r| r.serial);
        let mut results: Vec<(&Row, PutOutcome)> = own
            .iter()
            .filter_map(|r| match (r.kind, r.outcome) {
                (ActionKind::PutResult, Some(Outcome::Put(outcome))) => Some((*r, outcome)),
                _ => None,
            })
            .collect();
        results.sort_by_key(|(r, _)| r.responded);
        Self {
            begin,
            own,
            serial,
            results,
        }
    }

    fn op(&self) -> OpId {
        self.begin.op
    }

    fn of(&self, kinds: &'a [ActionKind]) -> impl Iterator<Item = &'a Row> + '_ {
        self.own.iter().copied().filter(|r| kinds.contains(&r.kind))
    }

    fn owner_rows(&self) -> Result<(), Violation> {
        let op = self.op();
        let begin = self.begin;
        let manifest = (begin.key(), begin.label, begin.metadata_len, begin.body_len);
        if self
            .of(&[ActionKind::Fill, ActionKind::Ready])
            .any(|r| (r.key(), r.label, r.metadata_len, r.body_len) != manifest)
        {
            return Err(fail(op, "the owner prepared another manifest"));
        }
        if self
            .own
            .iter()
            .filter(|r| r.kind != ActionKind::Retry)
            .any(|r| r.key().is_some_and(|key| Some(key) != begin.key()))
        {
            return Err(fail(op, "the rows of one attempt name two keys"));
        }
        if self
            .own
            .iter()
            .filter(|r| r.kind != ActionKind::Retry)
            .any(|r| r.serial.is_some_and(|s| Some(s) != self.serial))
        {
            return Err(fail(op, "the rows of one attempt name two serials"));
        }
        if self.of(&OWNER_FLOW).any(|r| r.serial.is_none()) {
            return Err(fail(op, "an owner flow row of the attempt names no serial"));
        }
        if let (Some(metadata_len), Some(body_len)) = (begin.metadata_len, begin.body_len) {
            let total = u64::from(metadata_len) + body_len;
            let count = fragment_count(metadata_len, body_len);
            let beyond = |value: Option<u32>| value.is_some_and(|v| u64::from(v) > count);
            if self
                .of(&[ActionKind::Ack])
                .any(|r| beyond(r.grant) || beyond(r.receipt.map(|receipt| receipt.base)))
                || self
                    .of(&[ActionKind::Fragment])
                    .any(|r| r.fragment.is_some_and(|index| u64::from(index) >= count))
            {
                return Err(fail(op, "an owner row beyond the attempt's manifest"));
            }
            if self
                .own
                .iter()
                .filter(|r| r.source_slot())
                .any(|r| r.fragment.is_some_and(|index| u64::from(index) >= count))
            {
                return Err(fail(
                    op,
                    "a source slot named a fragment beyond the attempt's manifest",
                ));
            }
            // Fragment `index` carries `FRAGMENT_BYTES` bytes except the last,
            // which carries the remainder of the total.
            let fragment_len = |index: u32| {
                (total - u64::from(index) * FRAGMENT_BYTES as u64).min(FRAGMENT_BYTES as u64)
            };
            if self.of(&[ActionKind::Fragment]).any(|r| {
                r.fragment
                    .zip(r.payload.as_ref())
                    .is_some_and(|(index, payload)| payload.len() as u64 != fragment_len(index))
            }) {
                return Err(fail(
                    op,
                    "a fragment's payload disagrees with the attempt's manifest",
                ));
            }
        }
        let mut validated = HashSet::new();
        if self
            .of(&[ActionKind::Fragment])
            .filter_map(|r| r.fragment)
            .any(|index| !validated.insert(index))
        {
            return Err(fail(op, "an attempt validated one fragment twice"));
        }
        let authority = self.first(ActionKind::Authority);
        if let Some(authority) = authority
            && self.results.iter().any(|&(result, outcome)| {
                matches!(outcome, PutOutcome::Failed(_))
                    && result.serial.is_none()
                    && result.responded > Some(authority)
            })
        {
            return Err(fail(
                op,
                "a Failed result after the authority names no serial",
            ));
        }
        if let Some(authority) = authority
            && self
                .of(&[ActionKind::Fill])
                .any(|r| r.responded > Some(authority))
        {
            return Err(fail(op, "the owner filled after the attempt's authority"));
        }
        Ok(())
    }

    fn first(&self, kind: ActionKind) -> Option<Ordinal> {
        self.own
            .iter()
            .filter(|r| r.kind == kind)
            .filter_map(|r| r.responded)
            .min()
    }

    /// The owner's authority precedes READY, which precedes every validated
    /// fragment, ACK, write submission, owner publication and `Published`
    /// result. A `Published` or `Failed` result ends the attempt's owner and
    /// client activity; a later retry is the owner replaying its cached
    /// outcome.
    ///
    /// A source slot's take follows READY.
    fn phases(&self) -> Result<(), Violation> {
        let authority = self.first(ActionKind::Authority);
        let ready = self.first(ActionKind::Ready);
        let follows = |row: &Row, phase: Option<Ordinal>| {
            phase.is_some_and(|at| row.invoked.or(row.responded) > Some(at))
        };
        let known = self
            .results
            .iter()
            .filter(|&&(_, outcome)| outcome != PutOutcome::Unknown)
            .find_map(|&(row, _)| row.responded);
        let source_takes = self
            .of(&[ActionKind::Take])
            .filter(|r| r.outcome.is_none() && r.source_slot());
        if self
            .of(&[
                ActionKind::Authority,
                ActionKind::Ready,
                ActionKind::Fragment,
                ActionKind::Ack,
                ActionKind::WriteSubmit,
                ActionKind::Fill,
                ActionKind::Receive,
                ActionKind::WriteCompleted,
            ])
            .any(|r| follows(r, known))
        {
            return Err(fail(self.op(), "attempt activity after a known result"));
        }
        let published = self
            .results
            .iter()
            .filter(|&&(_, outcome)| outcome == PutOutcome::Published)
            .map(|&(row, _)| row);
        if self
            .of(&[
                ActionKind::Ready,
                ActionKind::Fragment,
                ActionKind::Ack,
                ActionKind::WriteSubmit,
            ])
            .any(|r| !follows(r, authority))
            || self
                .of(&[
                    ActionKind::Fragment,
                    ActionKind::Ack,
                    ActionKind::WriteSubmit,
                    ActionKind::Publish,
                    ActionKind::Replace,
                ])
                .chain(published)
                .chain(source_takes)
                .any(|r| !follows(r, ready))
        {
            return Err(fail(self.op(), "the attempt's phases are out of order"));
        }
        Ok(())
    }

    /// The response of the attempt's publication when acknowledged, and
    /// whether that publication may have landed: it is acknowledged, or
    /// `Row::may_land` returns true for it. The owner publishes an attempt
    /// once, whatever the outcome.
    fn publication(&self) -> Result<(Option<Ordinal>, bool), Violation> {
        let rows: Vec<&Row> = self
            .of(&[ActionKind::Publish, ActionKind::Replace])
            .collect();
        if rows.len() > 1 {
            return Err(fail(self.op(), "an attempt published twice"));
        }
        let acknowledged = rows
            .iter()
            .find(|r| r.outcome == Some(Outcome::Acknowledged));
        let possible = rows
            .iter()
            .any(|r| r.outcome == Some(Outcome::Acknowledged) || r.may_land());
        Ok((acknowledged.and_then(|r| r.responded), possible))
    }

    fn judge_results(&self, activations: &mut Activations) -> Result<(), Violation> {
        let op = self.op();
        let (published_at, possible) = self.publication()?;
        let saw_attempt = self.own.iter().any(|r| {
            matches!(
                r.kind,
                ActionKind::Authority
                    | ActionKind::Ready
                    | ActionKind::Fragment
                    | ActionKind::Ack
                    | ActionKind::WriteSubmit
                    | ActionKind::Fill
            ) || (r.kind == ActionKind::Retry && r.outcome == Some(Outcome::Acknowledged))
        });
        let mut known: Option<PutOutcome> = None;
        for &(result, outcome) in &self.results {
            if known.is_some_and(|previous| previous != PutOutcome::Unknown) {
                return Err(fail(op, "a known attempt result changed"));
            }
            match outcome {
                PutOutcome::Published
                    if published_at.is_none_or(|at| Some(at) > result.responded) =>
                {
                    return Err(fail(op, "Published without the attempt's publication"));
                }
                PutOutcome::Published if result.label != self.begin.label => {
                    return Err(fail(op, "Published names another label"));
                }
                PutOutcome::Failed(_) | PutOutcome::NotStarted if possible => {
                    return Err(fail(op, "an attempt that did not publish published"));
                }
                PutOutcome::NotStarted if saw_attempt => {
                    return Err(fail(op, "NotStarted after the owner saw the attempt"));
                }
                _ => {}
            }
            known = Some(outcome);
            activations.activate(Obligation::History);
        }
        Ok(())
    }

    fn abandonment(&self) -> Result<(), Violation> {
        let unknown_before = |abandoned: Ordinal| {
            self.results
                .iter()
                .rfind(|(r, _)| r.responded < Some(abandoned))
                .is_some_and(|&(_, outcome)| outcome == PutOutcome::Unknown)
        };
        if self
            .of(&[ActionKind::Abandon])
            .filter_map(|r| r.responded)
            .any(|abandoned| !unknown_before(abandoned))
        {
            return Err(fail(
                self.op(),
                "an abandonment of an attempt that was not Unknown",
            ));
        }
        Ok(())
    }

    /// Every ACK's receipt base and mask count only distinct fragments the
    /// owner validated before it; duplicate fragment indices count once. The
    /// admitted history's Fragment rows are the attempt's complete fragment
    /// evidence, so a receipt that names a fragment with no earlier Fragment
    /// row is an impossible ACK, including in a history with no Fragment
    /// rows.
    ///
    /// A passing base counts that many distinct Fragment rows, so it is at
    /// most the count of Fragment rows, which the attempt's row count bounds,
    /// and a mask names indices at most 64 above its base: the indices below
    /// `reach` decide every receipt.
    fn receipts(&self, activations: &mut Activations) -> Result<(), Violation> {
        const UNVALIDATED: u64 = u64::MAX;
        let reach = self.own.len() + u64::BITS as usize + 1;
        let mut earliest = vec![UNVALIDATED; reach];
        let mut fragments = 0;
        for row in &self.own {
            if row.kind != ActionKind::Fragment {
                continue;
            }
            fragments += 1;
            if let Some(index) = row.fragment
                && (index as usize) < reach
            {
                let at = response(row);
                if at < earliest[index as usize] {
                    earliest[index as usize] = at;
                }
            }
        }
        // `leading[n]` is the latest of `earliest[..=n]`, so every index up
        // to `n` was validated before `ack` exactly when
        // `leading[n] < response(ack)`.
        let mut leading = earliest[..fragments].to_vec();
        for index in 1..fragments {
            if leading[index] < leading[index - 1] {
                leading[index] = leading[index - 1];
            }
        }
        for ack in &self.own {
            if ack.kind != ActionKind::Ack {
                continue;
            }
            let Some(receipt) = ack.receipt else {
                continue;
            };
            let at = response(ack);
            let base = receipt.base as usize;
            if base > 0 && (base > fragments || leading[base - 1] >= at) {
                return Err(Violation {
                    obligation: Obligation::Resources,
                    op: self.op(),
                    rule: "a receipt base counted fragments never received",
                });
            }
            let mut named = receipt.mask;
            while named != 0 {
                let index = base + 1 + named.trailing_zeros() as usize;
                if earliest[index] >= at {
                    return Err(Violation {
                        obligation: Obligation::Resources,
                        op: self.op(),
                        rule: "a receipt mask named a fragment never received",
                    });
                }
                named &= named - 1;
            }
            activations.activate(Obligation::Resources);
        }
        Ok(())
    }

    fn take_before(&self, row: &Row, custodian: Custodian) -> Option<&'a Row> {
        self.of(&[ActionKind::Take]).find(|take| {
            take.outcome.is_none()
                && take.custodian == Some(custodian)
                && take.resource() == row.resource()
                && take.incarnation == row.incarnation
                && take.responded < row.responded
        })
    }

    /// The client holds one cumulative receipt per attempt: from READY on,
    /// each ACK's base and grant are at least the previous ones, and the
    /// owner validates a fragment only below the grant it last sent.
    fn receipt_state(&self, activations: &mut Activations) -> Result<(), Violation> {
        let mut rows: Vec<&Row> = self
            .of(&[ActionKind::Ready, ActionKind::Ack, ActionKind::Fragment])
            .collect();
        rows.sort_by_key(|r| r.responded);
        let mut held = (0, 0);
        for row in rows {
            if row.kind == ActionKind::Fragment {
                if row.fragment.is_some_and(|index| index >= held.1) {
                    return Err(fail(
                        self.op(),
                        "a fragment was validated beyond the active grant",
                    ));
                }
                continue;
            }
            let base = row.receipt.map_or(0, |receipt| receipt.base);
            let grant = row.grant.unwrap_or(0);
            if base < held.0 || grant < held.1 {
                return Err(Violation {
                    obligation: Obligation::Resources,
                    op: self.op(),
                    rule: "the attempt's receipt base or grant regressed",
                });
            }
            held = (base, grant);
            if row.kind == ActionKind::Ack {
                activations.activate(Obligation::Resources);
            }
        }
        Ok(())
    }

    /// A client source slot's retransmission retention ends only once the
    /// attempt's receipt base passed the slot's fragment, the client
    /// reported the attempt's result, `Unknown` included, or the slot's
    /// tenure was cancelled; a receipt mask bit alone preserves retention.
    /// Each retention release follows the attempt's own take of that
    /// tenure. A source-slot take, release or cancel with a `NoInformation`
    /// outcome preserves custody.
    ///
    /// A cancel names a tenure the attempt retains.
    ///
    /// Each NIC take follows the attempt's retransmission take of the same
    /// tenure and fragment, and each NIC release the attempt's NIC take of
    /// them, and both precede the attempt's first result or cancel and, for
    /// the NIC, the tenure's retention release; a NIC take names a fragment
    /// below the grant the client holds. The attempt takes each source-slot
    /// tenure for retransmission at most once and each fragment into one
    /// slot, naming a fragment the receipt base has not passed. The NIC
    /// takes a tenure once per send, so releases of a tenure never outnumber
    /// its takes.
    fn retention(&self, activations: &mut Activations) -> Result<(), Violation> {
        let source = |r: &&Row, custodian: Custodian| {
            r.outcome.is_none() && r.source_slot() && r.custodian == Some(custodian)
        };
        for cancel in self
            .of(&[ActionKind::Cancel])
            .filter(|r| r.outcome.is_none() && r.source_slot())
        {
            let ended = self
                .of(&[ActionKind::Release])
                .filter(|r| source(r, Custodian::Retransmission))
                .any(|release| {
                    release.resource() == cancel.resource()
                        && release.incarnation == cancel.incarnation
                        && release.responded < cancel.responded
                });
            if ended
                || self
                    .take_before(cancel, Custodian::Retransmission)
                    .is_none()
            {
                return Err(Violation {
                    obligation: Obligation::Custody,
                    op: self.op(),
                    rule: "a source slot cancel named no retained tenure",
                });
            }
        }
        let decided = self
            .results
            .first()
            .and_then(|(result, _)| result.responded)
            .into_iter()
            .chain(
                self.of(&[ActionKind::Cancel])
                    .filter(|r| r.outcome.is_none() && r.source_slot())
                    .filter_map(|r| r.responded),
            )
            .min();
        if self
            .of(&[ActionKind::Take])
            .filter(|r| r.outcome.is_none() && r.source_slot())
            .any(|take| decided.is_some_and(|at| take.responded > Some(at)))
        {
            return Err(Violation {
                obligation: Obligation::Custody,
                op: self.op(),
                rule: "a source slot was taken after the attempt's result or cancel",
            });
        }
        let mut tenures = HashSet::new();
        let mut fragments = HashSet::new();
        for take in self
            .of(&[ActionKind::Take])
            .filter(|r| source(r, Custodian::Retransmission))
        {
            if !tenures.insert((take.resource(), take.incarnation)) {
                return Err(Violation {
                    obligation: Obligation::Custody,
                    op: self.op(),
                    rule: "a source slot tenure was taken twice",
                });
            }
            if !fragments.insert(take.fragment) {
                return Err(Violation {
                    obligation: Obligation::Custody,
                    op: self.op(),
                    rule: "an attempt took one fragment into two source slots",
                });
            }
            let passed = self
                .of(&[ActionKind::Ack])
                .filter(|ack| ack.responded < take.responded)
                .filter_map(|ack| ack.receipt)
                .map(|receipt| receipt.base)
                .max();
            if passed
                .zip(take.fragment)
                .is_some_and(|(base, fragment)| fragment < base)
            {
                return Err(Violation {
                    obligation: Obligation::Custody,
                    op: self.op(),
                    rule: "a source slot took a fragment the receipt base had passed",
                });
            }
        }
        for nic in self
            .of(&[ActionKind::Take])
            .filter(|r| source(r, Custodian::Nic))
        {
            if self
                .take_before(nic, Custodian::Retransmission)
                .is_none_or(|taken| taken.fragment != nic.fragment)
            {
                return Err(Violation {
                    obligation: Obligation::Custody,
                    op: self.op(),
                    rule: "a NIC take of a source slot followed no retransmission take of its fragment",
                });
            }
            if self
                .of(&[ActionKind::Release])
                .filter(|r| source(r, Custodian::Retransmission))
                .any(|release| {
                    release.resource() == nic.resource()
                        && release.incarnation == nic.incarnation
                        && release.responded < nic.responded
                })
            {
                return Err(Violation {
                    obligation: Obligation::Custody,
                    op: self.op(),
                    rule: "a NIC take of a source slot followed its retention release",
                });
            }
            let granted = self
                .of(&[ActionKind::Ready, ActionKind::Ack])
                .filter(|r| r.responded < nic.responded)
                .filter_map(|r| r.grant)
                .max()
                .unwrap_or(0);
            if nic.fragment.is_some_and(|fragment| fragment >= granted) {
                return Err(Violation {
                    obligation: Obligation::Custody,
                    op: self.op(),
                    rule: "a NIC take of a source slot exceeded the active grant",
                });
            }
        }
        for release in self
            .of(&[ActionKind::Release])
            .filter(|r| source(r, Custodian::Nic))
        {
            if self
                .take_before(release, Custodian::Nic)
                .is_none_or(|taken| taken.fragment != release.fragment)
            {
                return Err(Violation {
                    obligation: Obligation::Custody,
                    op: self.op(),
                    rule: "a NIC release returned a tenure its attempt never took",
                });
            }
        }
        for release in self
            .of(&[ActionKind::Release])
            .filter(|r| source(r, Custodian::Retransmission))
        {
            let Some(fragment) = release.fragment else {
                continue;
            };
            let Some(taken) = self.take_before(release, Custodian::Retransmission) else {
                return Err(Violation {
                    obligation: Obligation::Custody,
                    op: self.op(),
                    rule: "a retention release ended a tenure its attempt never took",
                });
            };
            if taken.fragment != Some(fragment) {
                return Err(Violation {
                    obligation: Obligation::Custody,
                    op: self.op(),
                    rule: "a retention release named another fragment than its take",
                });
            }
            let ended = self
                .of(&[ActionKind::Ack, ActionKind::PutResult, ActionKind::Cancel])
                .filter(|r| taken.responded < r.responded && r.responded < release.responded)
                .any(|r| match r.kind {
                    ActionKind::Ack => r.receipt.is_some_and(|receipt| receipt.base > fragment),
                    ActionKind::Cancel => {
                        r.outcome.is_none()
                            && r.resource() == release.resource()
                            && r.incarnation == release.incarnation
                    }
                    _ => true,
                });
            if !ended {
                return Err(Violation {
                    obligation: Obligation::Custody,
                    op: self.op(),
                    rule: "retransmission retention ended before the receipt base passed its fragment",
                });
            }
            activations.activate(Obligation::Custody);
        }
        let mut custody: Vec<&Row> = self
            .of(&[ActionKind::Take, ActionKind::Release])
            .filter(|r| r.outcome.is_none() && r.source_slot())
            .collect();
        custody.sort_by_key(|r| r.responded);
        let mut outstanding: HashMap<_, u32> = HashMap::new();
        for row in custody {
            let held = outstanding
                .entry((row.custodian, row.resource(), row.incarnation))
                .or_default();
            if row.kind == ActionKind::Take {
                *held += 1;
            } else if *held == 0 {
                return Err(Violation {
                    obligation: Obligation::Custody,
                    op: self.op(),
                    rule: "a source slot tenure was released more often than taken",
                });
            } else {
                *held -= 1;
            }
        }
        Ok(())
    }

    fn retries(&self) -> Result<(), Violation> {
        let begin = self.begin;
        let changed = self
            .of(&[ActionKind::Retry])
            .filter(|r| r.outcome == Some(Outcome::Acknowledged))
            .any(|retry| {
                retry.key() != begin.key()
                    || retry.serial.is_some_and(|named| Some(named) != self.serial)
                    || retry
                        .metadata_len
                        .is_some_and(|len| Some(len) != begin.metadata_len)
                    || retry
                        .body_len
                        .is_some_and(|len| Some(len) != begin.body_len)
                    || retry
                        .deadline
                        .is_some_and(|ttl| Some(ttl) != begin.deadline)
            });
        if changed {
            return Err(fail(self.op(), "a changed retry replayed the attempt"));
        }
        Ok(())
    }
}

pub(crate) fn judge_attempts(
    rows: &[&Row],
    activations: &mut Activations,
) -> Result<(), Violation> {
    let mut serials = HashSet::new();
    for begin in rows
        .iter()
        .copied()
        .filter(|r| r.kind == ActionKind::PutBegin)
    {
        let attempt = Attempt::new(begin, rows);
        attempt.owner_rows()?;
        if let Some(serial) = attempt.serial
            && !serials.insert((begin.key(), serial))
        {
            return Err(fail(begin.op, "two attempts share one serial"));
        }
        attempt.judge_results(activations)?;
        attempt.phases()?;
        attempt.abandonment()?;
        attempt.retries()?;
        attempt.receipts(activations)?;
        attempt.receipt_state(activations)?;
        attempt.retention(activations)?;
    }
    Ok(())
}
