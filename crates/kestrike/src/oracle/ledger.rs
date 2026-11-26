//! The recovery ledger judges recovery claims from evidence rows within
//! each scope, a hypothesis or a qualified profile under one attached
//! identity: admission needs binding, payload, identity and ownership
//! facts, a recovered candidate found as a hit or an expiry needs
//! admission and no recovery-safe exclusion, a recovered expiry needs
//! portable expiry authority, and a recovered acquisition needs freshness,
//! portable expiry, serving authority and invalidation replay. A lookup's
//! cut is the latest restart in its scope that responded before the
//! lookup was invoked, and admission and every fact a recovered candidate
//! relies on were recorded before that cut.
//!
//! An admission of a mapping a recovery-safe exclusion already excluded
//! fails, so no later incarnation readmits it; exclusions are judged on
//! key and label. A qualified fact counts only when its profile is
//! qualified and its evidence observed that profile's boundary, its
//! incarnation is the one every qualified restart so far leaves writing,
//! counted across qualified scopes since the incarnation is the owner's,
//! and a fact for every predecessor command it names already counted in
//! that incarnation. A fact recorded after a lookup's cut adds nothing to
//! that lookup, and a fact that does not count adds nothing to any. An
//! exclusion binds from its record onward: an abstract one within its
//! hypothesis, and a qualified one in every qualified scope whether its
//! evidence counts or not, since it forbids rather than permits.

use std::collections::{HashMap, HashSet};

use super::action::ActionKind;
use super::evidence::{DurableFact, Evidence, Qualified, Scope, fact};
use super::ids::{KeyId, Label, Ordinal};
use super::obligation::Obligation;
use super::outcome::Outcome;
use super::row::Row;
use super::verdict::{Activations, Violation};

const ADMISSION: [DurableFact; 4] = [
    DurableFact::Binding,
    DurableFact::Payload,
    DurableFact::Identity,
    DurableFact::Ownership,
];
const ACQUISITION: [DurableFact; 4] = [
    DurableFact::Freshness,
    DurableFact::PortableExpiry,
    DurableFact::ServingAuthority,
    DurableFact::InvalidationReplayed,
];

#[derive(Debug, Default)]
struct Ledger {
    /// Each fact with the response ordinal that first recorded it.
    facts: HashMap<(KeyId, Label, DurableFact), Option<Ordinal>>,
    /// Each admitted mapping with the response ordinal that admitted it.
    admitted: HashMap<(KeyId, Label), Option<Ordinal>>,
    /// Every restart's response ordinal, in response order.
    restarts: Vec<Ordinal>,
    /// The incarnation and command of every qualified fact that counted.
    commands: HashSet<(u64, u32)>,
}

/// Whether evidence recorded at `recorded` was durable before `cut`.
fn before(recorded: Option<Ordinal>, cut: Option<Ordinal>) -> bool {
    match (recorded, cut) {
        (Some(recorded), Some(cut)) => recorded < cut,
        (_, None) => true,
        (None, Some(_)) => false,
    }
}

/// The mappings recovery-safe exclusions excluded.
type Excluded = HashSet<(KeyId, Label)>;

const fn fail(row: &Row, rule: &'static str) -> Violation {
    Violation {
        obligation: Obligation::Restart,
        op: row.op,
        rule,
    }
}

impl Ledger {
    /// The latest restart that responded before `at`, or `None` before
    /// the first.
    fn cut(&self, at: Option<Ordinal>) -> Option<Ordinal> {
        let at = at?;
        self.restarts.iter().copied().rfind(|&restart| restart < at)
    }

    /// Records `row`'s fact at its first response.
    fn record(&mut self, row: &Row) {
        if let (Some(key), Some(label), Some(fact)) = (row.key(), row.label, row.fact) {
            self.facts
                .entry((key, label, fact))
                .or_insert(row.responded);
        }
    }

    /// Records a qualified fact when it counts, `writer` being the owner
    /// incarnation every qualified restart so far leaves writing.
    fn qualified(&mut self, row: &Row, qualified: Qualified, writer: u64) {
        let counts = qualified.accepted()
            && qualified.incarnation == writer
            && qualified
                .predecessors
                .iter()
                .flatten()
                .all(|&command| self.commands.contains(&(writer, command)));
        if counts {
            self.commands.insert((writer, qualified.command));
            self.record(row);
        }
    }

    /// Whether a recovery-safe exclusion recorded so far excludes the
    /// mapping, in this scope or among the qualified `shared` ones.
    fn excluded(&self, key: KeyId, label: Label, shared: &Excluded) -> bool {
        shared.contains(&(key, label))
            || self.has(key, label, &[DurableFact::RecoveryExclusion], None)
    }

    /// Whether every fact in `facts` was recorded for the mapping before
    /// `cut`; `None` accepts facts recorded at any time.
    fn has(&self, key: KeyId, label: Label, facts: &[DurableFact], cut: Option<Ordinal>) -> bool {
        facts.iter().all(|&fact| {
            self.facts
                .get(&(key, label, fact))
                .is_some_and(|&recorded| before(recorded, cut))
        })
    }

    fn admit(&mut self, row: &Row, rows: &[&Row], shared: &Excluded) -> Result<(), Violation> {
        let (Some(key), Some(label)) = (row.key(), row.label) else {
            return Err(fail(row, "admission has no key or label"));
        };
        if self.excluded(key, label, shared) {
            return Err(fail(row, "a recovery-safe exclusion was readmitted"));
        }
        if !self.has(key, label, &ADMISSION, None) {
            let completed = rows.iter().any(|written| {
                written.kind == ActionKind::WriteCompleted
                    && written.key() == Some(key)
                    && written.label == Some(label)
            });
            let payload_only = ADMISSION
                .iter()
                .all(|&f| f == DurableFact::Payload || self.has(key, label, &[f], None));
            return Err(fail(
                row,
                if completed && payload_only {
                    "a write completion was taken as durable payload evidence"
                } else {
                    "admission lacked binding, payload, identity or ownership evidence"
                },
            ));
        }
        self.admitted.entry((key, label)).or_insert(row.responded);
        Ok(())
    }

    fn lookup(&self, row: &Row, shared: &Excluded) -> Result<(), Violation> {
        let Some(restarted) = self.cut(row.invoked) else {
            return Err(fail(row, "recovered acquisition precedes restart"));
        };
        if !matches!(row.outcome, Some(Outcome::Hit | Outcome::Expired)) {
            return Ok(());
        }
        let (Some(key), Some(label)) = (row.acquired_key(), row.label) else {
            return Err(fail(row, "recovered acquisition has no key or label"));
        };
        if self.excluded(key, label, shared) {
            return Err(fail(
                row,
                "a recovery-safe exclusion was revived after restart",
            ));
        }
        if !self
            .admitted
            .get(&(key, label))
            .is_some_and(|&admitted| before(admitted, Some(restarted)))
        {
            return Err(fail(
                row,
                "a recovered candidate was found without admission",
            ));
        }
        if row.outcome == Some(Outcome::Expired) {
            if !self.has(key, label, &[DurableFact::PortableExpiry], Some(restarted)) {
                return Err(fail(
                    row,
                    "a recovered expiry without portable expiry authority",
                ));
            }
            return Ok(());
        }
        if !self.has(key, label, &ACQUISITION, Some(restarted)) {
            return Err(fail(
                row,
                "a recovered candidate was served without freshness, expiry, serving or replay authority",
            ));
        }
        Ok(())
    }
}

pub(crate) fn judge_ledger(rows: &[&Row], activations: &mut Activations) -> Result<(), Violation> {
    let mut ordered: Vec<(Scope, &Row)> = rows
        .iter()
        .filter_map(|&row| Some((row.evidence.scope()?, row)))
        .collect();
    ordered.sort_by_key(|(_, row)| row.responded);
    let mut ledgers: HashMap<Scope, Ledger> = HashMap::new();
    let mut qualified_exclusions = Excluded::new();
    let none = Excluded::new();
    let mut writer = 0;
    for (scope, row) in ordered {
        if row.kind != ActionKind::Lookup && !row.records_event() {
            continue;
        }
        let shared = match scope {
            Scope::Profile(..) => &qualified_exclusions,
            Scope::Hypothesis(_) => &none,
        };
        let ledger = ledgers.entry(scope).or_default();
        match row.kind {
            ActionKind::Persistence => match row.evidence {
                Evidence::Qualified(qualified) => {
                    if row.fact == Some(DurableFact::RecoveryExclusion) {
                        qualified_exclusions.extend(row.key().zip(row.label));
                    }
                    ledger.qualified(row, qualified, writer);
                }
                _ if fact(row).is_some() => ledger.record(row),
                _ => {}
            },
            ActionKind::Admission => ledger.admit(row, rows, shared)?,
            ActionKind::Restart => {
                ledger.restarts.extend(row.responded);
                writer += u64::from(matches!(scope, Scope::Profile(..)));
            }
            ActionKind::Lookup => {
                ledger.lookup(row, shared)?;
                if row
                    .outcome
                    .is_some_and(|outcome| outcome.carries_information())
                {
                    activations.activate(Obligation::Restart);
                }
            }
            ActionKind::Fill
            | ActionKind::Receive
            | ActionKind::WriteCompleted
            | ActionKind::Publish
            | ActionKind::Replace
            | ActionKind::Invalidate
            | ActionKind::Captured
            | ActionKind::Damaged => {}
            _ => {
                return Err(fail(
                    row,
                    "abstract action lacks declared recovery semantics",
                ));
            }
        }
    }
    Ok(())
}
