//! The long-run gate: the checked-in manifest beside this module fixes
//! every input and bound of one run, and the run reads nothing else, no
//! environment variable, path or clock.
//!
//! The run drives the storage churn on one engine for the manifest's
//! action count with every per-action oracle and the require-all witness
//! set active, then its recovery and terminal faults on that engine, then
//! the lifecycle and poisoned-gate phases, each on the storage its fault
//! needs, then the mixed GET/PUT phase with its correlated witnesses. Each
//! bounded quantity keeps one high-water mark across the phases that
//! measure it: the storage phases measure the device commands and growth,
//! the lease credits and the unreturned credits, the mixed phase every
//! other mark and its own device's commands and growth, and the frontier
//! comes from the continuation over both the churn's funded recovery and
//! the recorded upload. A mark past its manifest bound fails by name, and
//! a mark no phase measured is unsuccessful. The run is credited only as a
//! complete pass: a failed check, an unfired witness, an inconclusive
//! phase or a mark past its bound earns nothing.
//!
//! The manifest pins churn seed 10 with colliding keys and mixed root 3.
//! A change to either input needs a fresh gate run, since the witnesses
//! and bounds hold for the pinned pair alone.

use crate::net::world_tests::long_run::mixed_phase;
use crate::storage::churn_tests::long_run::{ChurnPlan, storage_phases};

/// The gate's manifest text.
pub(crate) const MANIFEST: &str = include_str!("long_run.manifest");

/// Every manifest key, in order. The first five fix the run's inputs; the
/// rest are the bounds the high-water marks are checked against.
pub(crate) const KEYS: [&str; 19] = [
    VERSION,
    CHURN_SEED,
    CHURN_COLLIDE,
    CHURN_ACTIONS,
    MIXED_ROOT,
    DEVICE_COMMANDS,
    DEVICE_GROWTH,
    LEASE_CREDITS,
    UNRETURNED_CREDITS,
    LIVE_UPLOADS,
    SOURCE_BYTES,
    COPY_BYTES,
    TX_SLOTS,
    CAPTURES,
    AUDIT_RECORDS,
    REGISTRY,
    WITNESS_LOG,
    FRONTIER,
    PARKED,
];

/// The index in [`KEYS`] of the first bound.
const FIRST_BOUND: usize = 5;

/// The schema version; only 1 exists.
pub(crate) const VERSION: &str = "version";
/// The churn's seed.
pub(crate) const CHURN_SEED: &str = "churn_seed";
/// 1 routes the churn's keys through one-fingerprint groups, 0 does not.
pub(crate) const CHURN_COLLIDE: &str = "churn_collide";
/// The churn's action count.
pub(crate) const CHURN_ACTIONS: &str = "churn_actions";
/// The root every mixed scenario runs at.
pub(crate) const MIXED_ROOT: &str = "mixed_root";

// Each bound below is a ceiling the run's structure derives, set apart
// from any fixture limit that refuses the same quantity, so a mark past
// its bound is growth the fixture would still admit. A structural ceiling
// names the constant it comes from; a depth ceiling is the most the
// pinned run holds at once plus one unit, so growth past depth plus one
// fails.

/// Commands one simulated disk held at once, pending and posted. A depth
/// ceiling: the churn holds three and a mixed scene two, so four; each
/// disk's queue depth of eight refuses past it.
pub(crate) const DEVICE_COMMANDS: &str = "device_commands";
/// Bytes of capacity one simulated disk's stores grew past their
/// construction capacity. Structural: every store reserves its capacity
/// at construction, so zero.
pub(crate) const DEVICE_GROWTH: &str = "device_growth";
/// Credits backing live extent leases at once, between actions.
/// Structural: a churn holds at most six leases across actions, and every
/// other lease ends within the action that took it.
pub(crate) const LEASE_CREDITS: &str = "lease_credits";
/// Credits still backing a lease once the churn's recovery released every
/// holder. Structural: zero.
pub(crate) const UNRETURNED_CREDITS: &str = "unreturned_credits";
/// Uploads the uploading client held admitted at once. Structural: the
/// world proposes an upload or a retry only once the client retired the
/// last one, so one.
pub(crate) const LIVE_UPLOADS: &str = "live_uploads";
/// Bytes the uploading client's source slots held at once. Structural:
/// every scenario uploads one object of the mixed world's object length,
/// 24,476 bytes, so that length.
pub(crate) const SOURCE_BYTES: &str = "source_bytes";
/// Bytes one link direction held copied in flight at once. A depth
/// ceiling in datagram headers: the long scenario holds five copied
/// headers of 192 bytes, so six.
pub(crate) const COPY_BYTES: &str = "copy_bytes";
/// Transmit references one link retained at once, queued or awaiting
/// return. A depth ceiling: the long scenario retains eight, so nine.
pub(crate) const TX_SLOTS: &str = "tx_slots";
/// Rule-chain captures one link kept in one run. A depth ceiling: the
/// long scenario keeps 66, so 67; the rule manifest refuses past 4,096.
pub(crate) const CAPTURES: &str = "captures";
/// Audit records one link kept in one run. A depth ceiling: the long
/// scenario keeps 59, so 60; the rule manifest refuses past 65,536.
pub(crate) const AUDIT_RECORDS: &str = "audit_records";
/// Contents the observation registry held. Structural: the resident
/// object and the one key each scenario uploads or publishes locally, so
/// two.
pub(crate) const REGISTRY: &str = "registry";
/// Entries the longest correlated witness log held. A depth ceiling: the
/// longest, the ingredient log, holds 35, so 36; the logs refuse past
/// [`WITNESS_LIMIT`](crate::net::world_tests::long_run::WITNESS_LIMIT).
pub(crate) const WITNESS_LOG: &str = "witness_log";
/// States one key's continuation frontier held, over the churn's funded
/// recovery and the recorded upload. A depth ceiling: one, so two.
pub(crate) const FRONTIER: &str = "frontier";
/// GETs the owner held parked behind a fill at once in one scenario, each
/// scenario ending with none. A depth ceiling: the parked scenario parks
/// one, so two.
pub(crate) const PARKED: &str = "parked";

/// The gate's manifest: one value per key of [`KEYS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gate {
    values: [u64; KEYS.len()],
}

impl Gate {
    /// Parses `text` strictly: one `key = value` line per key of [`KEYS`],
    /// in order, each value a canonical unsigned integer, `version` 1, the
    /// collide flag 0 or 1, and a positive action count and root. A bound
    /// may be zero. The worker manifest parser of [`crate::sim::manifest`]
    /// shares the line form and takes its keys in any order; this schema
    /// fixes the order, so each line has one place.
    ///
    /// # Errors
    ///
    /// The first line or key that breaks the schema.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let mut values = [0; KEYS.len()];
        let mut lines = text.lines();
        for (slot, key) in KEYS.iter().enumerate() {
            let line = lines.next().ok_or(format!("missing key {key}"))?;
            let Some((found, value)) = line.split_once(" = ") else {
                return Err(format!("line {}: not `key = value`", slot + 1));
            };
            if found != *key {
                return Err(format!("line {}: {found} where {key} belongs", slot + 1));
            }
            values[slot] = match value.parse::<u64>() {
                Ok(parsed) if parsed.to_string() == value => parsed,
                _ => return Err(format!("{key}: {value:?} is no count")),
            };
        }
        if let Some(line) = lines.next() {
            return Err(format!("an extra line {line:?}"));
        }
        let gate = Self { values };
        if gate.get(VERSION) != 1 {
            return Err("version: only version 1 exists".into());
        }
        if gate.get(CHURN_COLLIDE) > 1 {
            return Err("churn_collide: a flag is 0 or 1".into());
        }
        if gate.get(CHURN_ACTIONS) == 0 || gate.get(MIXED_ROOT) == 0 {
            return Err("an empty run or a zero root selects nothing to credit".into());
        }
        Ok(gate)
    }

    /// The value of `key`.
    ///
    /// # Panics
    ///
    /// When `key` names no key of the schema.
    pub(crate) fn get(&self, key: &str) -> u64 {
        let slot = KEYS.iter().position(|known| *known == key);
        self.values[slot.expect("a gate manifest key")]
    }

    /// This manifest with `key` set to `value`, for a control that runs
    /// the gate at a smaller action count.
    pub(crate) fn with(mut self, key: &str, value: u64) -> Self {
        let slot = KEYS.iter().position(|known| *known == key);
        self.values[slot.expect("a gate manifest key")] = value;
        self
    }

    /// A fresh mark for every bound of the manifest.
    pub(crate) fn marks(&self) -> Marks {
        Marks {
            marks: KEYS[FIRST_BOUND..]
                .iter()
                .map(|&name| Mark {
                    name,
                    bound: self.get(name),
                    high: None,
                })
                .collect(),
        }
    }
}

/// One bound's manifest value and the highest value the run measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mark {
    name: &'static str,
    bound: u64,
    high: Option<u64>,
}

impl Mark {
    /// A mark past its bound fails by name; one no phase measured is
    /// unsuccessful.
    ///
    /// # Errors
    ///
    /// The failure, naming the mark.
    fn verdict(&self) -> Result<(), String> {
        match self.high {
            None => Err(format!("{} was never measured", self.name)),
            Some(high) if high > self.bound => Err(format!(
                "{} reached {high}, past its bound {}",
                self.name, self.bound
            )),
            Some(_) => Ok(()),
        }
    }
}

/// The run's high-water marks, one per manifest bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Marks {
    marks: Vec<Mark>,
}

impl Marks {
    /// The mark `name`.
    ///
    /// # Panics
    ///
    /// When `name` is no bound of the manifest: a phase naming an
    /// undeclared quantity is a harness defect.
    fn mark(&mut self, name: &str) -> &mut Mark {
        let mark = self.marks.iter_mut().find(|mark| mark.name == name);
        mark.expect("a declared bound")
    }

    /// Raises mark `name` to `value` when `value` is higher.
    ///
    /// # Panics
    ///
    /// As [`mark`](Self::mark).
    pub(crate) fn sample(&mut self, name: &str, value: u64) {
        let mark = self.mark(name);
        mark.high = Some(mark.high.map_or(value, |high| high.max(value)));
    }

    /// The first mark past its bound fails by name; a mark no phase
    /// measured leaves the run unsuccessful.
    ///
    /// # Errors
    ///
    /// The first such mark, named.
    pub(crate) fn verdict(&self) -> Result<(), String> {
        self.marks.iter().try_for_each(Mark::verdict)
    }

    /// Checks mark `name` alone, for a phase whose quantity must be within
    /// its bound at a point the rest of the run cannot restore.
    ///
    /// # Errors
    ///
    /// As [`verdict`](Self::verdict), for that mark.
    ///
    /// # Panics
    ///
    /// As [`mark`](Self::mark).
    pub(crate) fn check(&mut self, name: &str) -> Result<(), String> {
        self.mark(name).verdict()
    }

    /// Every mark as `name high/bound`, one line.
    pub(crate) fn render(&self) -> String {
        let marks = self.marks.iter().map(|mark| match mark.high {
            Some(high) => format!("{} {high}/{}", mark.name, mark.bound),
            None => format!("{} unmeasured/{}", mark.name, mark.bound),
        });
        marks.collect::<Vec<_>>().join(", ")
    }
}

/// What a control plants in a gate run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Plants {
    /// The churn takes one extent lease at or after its midpoint and holds
    /// it through the unreturned-credit check.
    pub(crate) leaked_lease: bool,
}

/// Runs `gate` with `plants` and returns its report lines: each phase's
/// witness counts and the marks.
///
/// # Errors
///
/// The first failed check, unfired witness, inconclusive phase or mark
/// past its bound, named; a panicking check unwinds through here.
pub(crate) fn run(gate: &Gate, plants: Plants) -> Result<Vec<String>, String> {
    let mut marks = gate.marks();
    let churn = ChurnPlan {
        seed: gate.get(CHURN_SEED),
        collide: gate.get(CHURN_COLLIDE) == 1,
        actions: gate.get(CHURN_ACTIONS) as usize,
        leaked_lease: plants.leaked_lease,
    };
    let mut report = storage_phases(churn, &mut marks)?;
    report.extend(mixed_phase(gate.get(MIXED_ROOT), &mut marks)?);
    marks.verdict()?;
    report.push(format!("marks: {}", marks.render()));
    Ok(report)
}

/// The manifest's schema, the marks' verdicts and the leaked-lease control.
#[cfg(test)]
mod tests {
    use super::{CHURN_ACTIONS, Gate, KEYS, MANIFEST, Plants, TX_SLOTS, run};

    /// An edit of the manifest's lines.
    type LineEdit = dyn Fn(&mut Vec<String>);

    /// The checked-in text parses, and a missing, reordered or extra key, a
    /// noncanonical value, another version, an out-of-range flag, an empty
    /// run, a zero root and a malformed line are each refused.
    #[test]
    fn the_manifest_parses_strictly() {
        let gate = Gate::parse(MANIFEST).unwrap();
        assert_eq!(gate.get("churn_actions"), 409_600);
        let lines: Vec<&str> = MANIFEST.lines().collect();
        let edited = |edit: &dyn Fn(&mut Vec<String>)| {
            let mut lines: Vec<String> = lines.iter().map(|line| (*line).to_owned()).collect();
            edit(&mut lines);
            Gate::parse(&lines.join("\n"))
        };
        let refusals: [(&LineEdit, &str); 9] = [
            (&|lines| drop(lines.pop()), "missing key parked"),
            (
                &|lines| lines.swap(1, 2),
                "churn_collide where churn_seed belongs",
            ),
            (&|lines| lines.push("parked = 2".into()), "an extra line"),
            (
                &|lines| lines[3] = "churn_actions = 0409600".into(),
                "is no count",
            ),
            (&|lines| lines[0] = "version = 2".into(), "only version 1"),
            (
                &|lines| lines[2] = "churn_collide = 2".into(),
                "a flag is 0 or 1",
            ),
            (
                &|lines| lines[3] = "churn_actions = 0".into(),
                "selects nothing",
            ),
            (
                &|lines| lines[4] = "mixed_root = 0".into(),
                "selects nothing",
            ),
            (
                &|lines| lines[5] = "device_commands=8".into(),
                "not `key = value`",
            ),
        ];
        for (edit, refusal) in refusals {
            let refused = edited(edit).unwrap_err();
            assert!(refused.contains(refusal), "{refused}");
        }
        assert_eq!(KEYS.len(), lines.len());
    }

    /// Every mark at its bound passes; one past its bound fails by its
    /// name, alone and among the rest, and one no phase measured is
    /// unsuccessful.
    #[test]
    fn a_mark_past_its_bound_or_unmeasured_fails_by_name() {
        let gate = Gate::parse(MANIFEST).unwrap();
        let mut marks = gate.marks();
        for name in &KEYS[super::FIRST_BOUND..] {
            marks.sample(name, gate.get(name));
        }
        assert_eq!(marks.verdict(), Ok(()));
        let bound = gate.get(TX_SLOTS);
        marks.sample(TX_SLOTS, bound + 1);
        let past = format!("tx_slots reached {}, past its bound {bound}", bound + 1);
        assert_eq!(marks.verdict(), Err(past.clone()));
        assert_eq!(marks.check(TX_SLOTS), Err(past));
        let mut unmeasured = gate.marks();
        let never = Err("device_commands was never measured".to_owned());
        assert_eq!(unmeasured.verdict(), never);
        assert_eq!(unmeasured.check("device_commands"), never);
    }

    /// Checking a name the manifest declares no bound for is a harness
    /// defect.
    #[test]
    #[should_panic(expected = "a declared bound")]
    fn checking_an_undeclared_mark_panics() {
        let _ = Gate::parse(MANIFEST).unwrap().marks().check("churn_seed");
    }

    /// The same short gate passes completely without the plant, and fails
    /// by the unreturned-credit mark with one lease taken at the churn's
    /// midpoint and held through the recovery.
    #[test]
    fn a_leaked_lease_fails_the_short_gate_by_name() {
        let gate = Gate::parse(MANIFEST).unwrap().with(CHURN_ACTIONS, 2_000);
        let unreturned = "unreturned_credits reached";
        let clean = run(&gate, Plants::default());
        assert!(clean.is_ok(), "{clean:?}");
        let leaked = Plants { leaked_lease: true };
        let refused = run(&gate, leaked).unwrap_err();
        assert_eq!(refused, format!("{unreturned} 1, past its bound 0"));
    }
}
