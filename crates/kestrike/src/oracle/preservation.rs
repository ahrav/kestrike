//! Positive preservation across host loss. [`check`](super::checker::check)
//! keeps a miss legal, so a recovery that restores its retained set and then
//! answers every lookup with a miss passes it. [`preserved`] judges the
//! stronger claim a retention witness needs: every member of an activation's
//! retained set is served, or is accounted to recorded damage on one of its
//! own units.
//!
//! The retained set is the one [`retention`](super::retention) judges: the
//! entries the activation's cut captured, less those an acknowledged
//! invalidation, a supersession or a recorded expiry or eviction removed.
//! Retention removes an entry for an effect below the activated tenure, an
//! expiry or eviction counting when recorded before the activation, and for
//! an invalidation in the activated tenure before the entry's first restore
//! there, or anywhere in that tenure when it never restores the entry. No
//! other effect removes an entry: a member that an acknowledged
//! invalidation, a publication of another label of its key, an expiry or an
//! eviction ends after its restore and before a lookup serves it stays in
//! the set unserved, and the judgment fails it unless damage excuses it. A
//! history that applies such an effect to a member serves the member first.
//! An entry that leaves the set only through a cancelled or timed-out
//! publication, replacement or invalidation, which may or may not have
//! landed, makes the judgment inconclusive, since the history records no
//! evidence that the entry left. A cancelled or timed-out publication or
//! replacement of a captured entry's own label is a known effect: the
//! capture shows that a publication of that label landed, and the
//! publication's version decides which interval invalidations cover the
//! entry.
//! Acknowledged effects that remove an entry
//! in only some legal orders, such as an invalidation or replacement that
//! overlaps the entry's publication, or an acknowledged invalidation in the
//! activated tenure after a miss of the key of an entry that tenure never
//! restores, remove it from the set here as they do in retention, so the
//! judgment does not report them. A member is served when a lookup tagged
//! with the activated tenure or a later one, answered after the activation,
//! hits its label, and that lookup's delivery completes, with the client
//! accepting both wherever the history records its decision; `check` has
//! judged the delivered bytes against the label's content. A member is
//! excused when a damage row names its row unit or its payload unit, is
//! recorded after its capture, is tagged at or below the activated tenure,
//! and precedes the first lookup of the member's key answered at or above
//! that tenure after the activation, or the tenure's first such lookup when
//! the key was never looked up. The bound is the member's own key's first
//! lookup because damage recorded after that lookup cannot explain what it
//! answered; retention's bound, the tenure's first lookup of any key, is a
//! conservative tenure-wide choice. A damage row stops excusing a member once
//! the unit it names was read whole after it, as the retention module
//! states. A damage row that names
//! no unit states the loss of the whole volume, which a cut-naming
//! activation contradicts, so it excuses nothing. The caller records damage
//! rows from the faults it injected, so recovery's own loss report excuses
//! nothing.
//!
//! A lookup counts as a lookup of the member's key when the lookup asks for
//! that key, or acquires an entry of that key as a colliding candidate. Only
//! live lookups count: a recovery-ledger lookup serves no member and sets no
//! damage bound.

use super::action::ActionKind;
use super::checker::{check, implied_ends};
use super::history::History;
use super::ids::{KeyId, Label, Tenure};
use super::obligation::Obligation;
use super::outcome::Outcome;
use super::retention::{damaged_before, damages, excluded_by_unknown, retained_set};
use super::row::Row;
use super::tenure::{Activation, ActivationLog};
use super::verdict::{Inconclusive, Verdict, Violation};

/// The rule [`preserved`] fails when no GET of an activation served a retained member that no damage excuses.
pub(crate) const NEVER_SERVED: &str =
    "a retained entry outside every damage set was never served after host loss";

/// One activation's retained set, split by what became of each member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Preserved {
    pub(crate) tenure: Tenure,
    /// The members of the retained set.
    pub(crate) members: u32,
    /// The members served, and the bytes each one's first hit with a
    /// complete delivery carried.
    pub(crate) served: u32,
    pub(crate) served_bytes: u64,
    /// The members never served whose loss recorded damage accounts for.
    pub(crate) excused: Vec<(KeyId, Label)>,
}

/// Judges `history` with [`check`], then every activation that names a cut:
/// one [`Preserved`] per such activation, in activation order.
///
/// # Errors
///
/// The verdict of `check` when it is not a pass; then a `Restart` violation
/// naming the first member of a retained set that was neither served nor
/// excused, in any activation; then `UnknownExclusion` naming the first
/// captured entry that only an unknown outcome removes from a retained set.
pub(crate) fn preserved(history: &History) -> Result<Vec<Preserved>, Verdict> {
    let verdict = check(history);
    if !matches!(verdict, Verdict::Pass(_)) {
        return Err(verdict);
    }
    let all: Vec<&Row> = history.rows().iter().collect();
    let live: Vec<&Row> = all
        .iter()
        .copied()
        .filter(|row| !row.evidence.is_recovery())
        .collect();
    let ended = implied_ends(&live);
    let rows: Vec<&Row> = all.iter().copied().chain(ended.iter()).collect();
    let log = ActivationLog::of(&rows).map_err(Verdict::Inconclusive)?;
    let mut judged = Vec::new();
    let mut unknown = None;
    for activation in log.activations().iter().filter(|a| a.cut.is_some()) {
        let retained = retained_set(&rows, &log, activation);
        if let Some(entry) = excluded_by_unknown(&rows, &log, activation, &retained) {
            unknown = unknown.or(Some(entry.op));
        }
        let mut account = Preserved {
            tenure: activation.tenure,
            members: 0,
            served: 0,
            served_bytes: 0,
            excused: Vec::new(),
        };
        for entry in retained {
            account.members += 1;
            let named = entry.key().zip(entry.label);
            let named = named.expect("a member of a retained set names its key and label");
            if let Some(delivery) = served_by(&rows, &log, activation, entry) {
                account.served += 1;
                account.served_bytes += delivery.payload.as_ref().map_or(0, Vec::len) as u64;
            } else if on_damaged_unit(&rows, &log, activation, entry) {
                account.excused.push(named);
            } else {
                return Err(Verdict::Violation(Violation {
                    obligation: Obligation::Restart,
                    op: entry.op,
                    rule: NEVER_SERVED,
                }));
            }
        }
        judged.push(account);
    }
    match unknown {
        Some(op) => Err(Verdict::Inconclusive(Inconclusive::UnknownExclusion { op })),
        None => Ok(judged),
    }
}

/// Whether `lookup` is a live lookup tagged at or above `activation`'s
/// tenure and answered after the activation. A recovery-ledger lookup is
/// evidence about the recovery, so it serves no member and bounds no damage.
fn after_activation(lookup: &Row, log: &ActivationLog, activation: &Activation) -> bool {
    lookup.kind == ActionKind::Lookup
        && !lookup.evidence.is_recovery()
        && log.tag(lookup) >= activation.tenure
        && lookup.responded > Some(activation.at)
}

/// Whether the client accepted `row`, where the history records its
/// decision.
fn admitted(row: &Row) -> bool {
    row.acceptance.is_none_or(|acceptance| acceptance.accepted)
}

/// The complete delivery of the first lookup that serves `entry`: an
/// admitted hit of its key and label after the activation whose delivery
/// completed and was admitted.
fn served_by<'r>(
    rows: &[&'r Row],
    log: &ActivationLog,
    activation: &Activation,
    entry: &Row,
) -> Option<&'r Row> {
    let hits = rows.iter().filter(|lookup| {
        after_activation(lookup, log, activation)
            && lookup.acquired_key() == entry.key()
            && lookup.outcome == Some(Outcome::Hit)
            && lookup.label == entry.label
            && admitted(lookup)
    });
    hits.flat_map(|lookup| {
        rows.iter().copied().filter(|delivery| {
            delivery.kind == ActionKind::Deliver
                && delivery.op == lookup.op
                && delivery.outcome == Some(Outcome::Complete)
                && admitted(delivery)
        })
    })
    .next()
}

/// Whether a damage row excuses unserved `entry`, as the module states.
fn on_damaged_unit(
    rows: &[&Row],
    log: &ActivationLog,
    activation: &Activation,
    entry: &Row,
) -> bool {
    let of_entry = |row: &Row| row.key() == entry.key() || row.acquired_key() == entry.key();
    let first = |of_key: bool| {
        rows.iter()
            .filter(|row| {
                after_activation(row, log, activation)
                    && row.outcome.is_some_and(Outcome::is_answer)
                    && (!of_key || of_entry(row))
            })
            .filter_map(|row| row.responded)
            .min()
    };
    let serving = first(true).or_else(|| first(false));
    damaged_before(rows, log, activation, entry.responded, serving, |row| {
        damages(rows, log, activation, row, entry)
    })
}
