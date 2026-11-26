//! Judges the alarm catalog over a fleet run's sealed reports and statuses. Each host agent seals its reports with
//! the production writer, and each reconciler actor seals the status part its `ZoneLoop` tick returns with a status
//! writer opened with that loop; [`AlarmLog`] keeps every sealed report and status in the order the fleet received
//! them, with the round's time as the receive clock. [`judged`] accepts each record with the production readers,
//! converts it to its contract view, evaluates every row of the catalog with the reference evaluator
//! (`failover::report::alarm_tests`) and compares the set of fired rows with the scenario's expected set.
//!
//! - SEALED-ONLY: each evaluated record passed a production reader. A status comes only from a reconciler actor's
//!   seal of its own tick's part, and a report only from a host agent's seal.
//! - EXACT-SET: a scenario with a stated set passes only when the set of fired row ids equals it; otherwise it
//!   fails with [`ALARM_SET`], and the failure's detail lists the missing and the extra rows. The series a row fires
//!   on and the count of its firings are outside the comparison.
//! - NO-CREDIT-WITHOUT-INPUT: a run with no sealed report, or with no sealed status while its reconcilers run,
//!   reads `Unrun(NO_RECORDS)`. A scenario with no stated set reads `Unrun(NOT_JUDGED)`, and [`fleet_verdict`]
//!   reads it as incomplete evidence.
//!
//! The receive clock advances `ROUND_US` a round, so a row whose window counts microseconds (`status-absent` and
//! the two `*-unknown-rate` rows, 60 s and more) sees at most a few hundred milliseconds of a run.

use core::num::NonZeroU64;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::failover::records::Host;
use crate::failover::report::alarm_tests::{Deltas, Fired, Input, catalog, evaluate};
use crate::failover::report::status::{StatusReader, StatusWriter, ZonePart};
use crate::failover::report::{Reader, ReportKey, SealError};

use super::super::cycles::{Verdict, hex};
use super::hosts::{Scenario, host_key};

pub(crate) use super::hosts::SEALED_RECORDS as NO_RECORDS;
pub(crate) use super::oracles::{
    ALARM_INCOMPLETE as INCOMPLETE, ALARM_NOT_JUDGED as NOT_JUDGED, ALARM_PLANTED as PLANTED,
    ALARM_SET, ALARM_UNREAD as UNREAD, ALARM_UNSEALED as UNSEALED,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    Report,
    Status,
}

impl Source {
    /// The source name the catalog's rows use.
    fn name(self) -> &'static str {
        match self {
            Self::Report => "report",
            Self::Status => "status",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Sealed {
    pub(crate) at_us: u64,
    pub(crate) source: Source,
    pub(crate) bytes: Vec<u8>,
}

/// The sealed reports and statuses of a run in receive order, and the count of ticks whose status part a
/// reconciler's writer refused to seal. The `Debug` form prints the counts and one SHA-256 over the records.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct AlarmLog {
    pub(crate) sealed: Vec<Sealed>,
    /// The ticks a status writer refused as early: a second tick of one loop inside its seal period. The
    /// two-reconciler race scripts one; any other fails the verdict of a run that [`verdict`] judges.
    pub(crate) unsealed: u32,
    /// The ticks a status writer refused for any other reason and the due reports a host's writer refused, which
    /// fail the verdict of a run that holds its required records and an expected set.
    pub(crate) unsealable: u32,
    /// A test replaced the run's fault script, so its scenario's expected set does not apply.
    pub(crate) scripted: bool,
}

impl core::fmt::Debug for AlarmLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let count = |source| (self.sealed.iter()).filter(|s| s.source == source).count();
        f.debug_struct("AlarmLog")
            .field("reports", &count(Source::Report))
            .field("statuses", &count(Source::Status))
            .field("unsealed", &self.unsealed)
            .field("unsealable", &self.unsealable)
            .field("scripted", &self.scripted)
            .field("sha256", &hex(&self.digest()))
            .finish()
    }
}

impl AlarmLog {
    pub(crate) fn receive(&mut self, source: Source, at_us: u64, bytes: &[u8]) {
        self.sealed.push(Sealed {
            at_us,
            source,
            bytes: bytes.to_vec(),
        });
    }

    /// The SHA-256 over every record's receive time, source, length and bytes, in order.
    fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        for sealed in &self.sealed {
            hash.update(sealed.at_us.to_le_bytes());
            hash.update([sealed.source as u8]);
            hash.update((sealed.bytes.len() as u64).to_le_bytes());
            hash.update(&sealed.bytes);
        }
        hash.finalize().into()
    }

    fn holds(&self, source: Source) -> bool {
        self.sealed.iter().any(|sealed| sealed.source == source)
    }
}

fn reconciler(r: usize) -> Host {
    Host::new(0xD000 + r as u64).expect("a nonzero reconciler identity")
}

/// A loop's writer seals that loop's ticks under a boot nonce of its own, so a restarted loop's statuses form a new
/// boot whose sequences start at 1.
#[derive(Default)]
pub(crate) struct Sealers {
    writers: BTreeMap<usize, StatusWriter>,
    opened: BTreeMap<usize, u16>,
}

impl Sealers {
    /// Gives reconciler `r`'s new loop a writer that seals at most one status per `tick_us`.
    pub(crate) fn open(&mut self, r: usize, tick_us: u64) {
        let opened = self.opened.entry(r).or_default();
        *opened += 1;
        let mut boot = [0xD5; 16];
        boot[0] = r as u8;
        boot[1..3].copy_from_slice(&opened.to_le_bytes());
        let period = NonZeroU64::new(tick_us).expect("a nonzero tick period");
        let writer = crate::failover::report::status::tests::writer_of(reconciler(r), boot, period);
        self.writers.insert(r, writer);
    }

    /// Seals `part`, reconciler `r`'s tick at `now_us`, into `log` as received at `now_us`. A seal the writer
    /// refuses as early counts in [`AlarmLog::unsealed`], and any other refusal in [`AlarmLog::unsealable`].
    pub(crate) fn seal(&mut self, r: usize, part: &ZonePart, now_us: u64, log: &mut AlarmLog) {
        let writer = self
            .writers
            .get_mut(&r)
            .expect("a writer opened with the loop");
        match writer.seal(std::slice::from_ref(part), now_us, now_us) {
            Ok(bytes) => log.receive(Source::Status, now_us, &bytes),
            Err(SealError::Early) => log.unsealed += 1,
            Err(_) => log.unsealable += 1,
        }
    }
}

/// The contract views of the records the production readers accept from `log`, in receive order, and the count
/// they refused.
pub(crate) fn inputs(log: &AlarmLog) -> (Vec<Input>, u32) {
    use crate::failover::report::status::tests as status;
    let (mut reports, mut statuses) = (Reader::default(), StatusReader::default());
    let mut inputs = Vec::new();
    let mut refused = 0;
    for sealed in &log.sealed {
        let view = match sealed.source {
            Source::Report => {
                let key = |host: Host| Some(ReportKey::derive(&host_key(host)));
                let accepted = reports.accept(&sealed.bytes, key);
                accepted.map(|report| crate::failover::report::tests::view(&report))
            }
            Source::Status => {
                let accepted = statuses.accept(&sealed.bytes, status::key_of);
                accepted.map(|accepted| status::view(&accepted))
            }
        };
        match view {
            Ok(view) => inputs.push(Input::Record {
                at_us: sealed.at_us,
                source: sealed.source.name(),
                view,
            }),
            Err(_) => refused += 1,
        }
    }
    (inputs, refused)
}

/// Every firing of every row of `catalog` over `inputs`, row by row in catalog order.
pub(crate) fn fired(catalog: &Value, inputs: &[Input]) -> Vec<Fired> {
    let rows = catalog["rows"].as_array().expect("the catalog's rows");
    (rows.iter())
        .flat_map(|row| evaluate(row, inputs, Deltas::ResetAware))
        .collect()
}

pub(crate) fn rows(fired: &[Fired]) -> BTreeSet<String> {
    fired.iter().map(|fired| fired.row.clone()).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Expected {
    /// The exact set of rows the scenario's run fires.
    Rows(&'static [&'static str]),
    /// The oracle holds no expected set for the run.
    NotJudged,
}

/// Judges `log` against `expected` under `catalog`: `Unrun(NO_RECORDS)` when the run sealed no report, or no
/// status while `statuses` says its reconcilers run; `Unrun(NOT_JUDGED)` for a run with no expected set, whose
/// records stay unread; `Fail(UNSEALED)` when a writer refused a record for a reason other than its pacing;
/// `Fail(UNREAD)` when a reader refused a record; `Fail(ALARM_SET)` with every missing and every extra row; `Pass`.
pub(crate) fn judged(
    log: &AlarmLog,
    catalog: &Value,
    expected: Expected,
    statuses: bool,
) -> Verdict {
    if !log.holds(Source::Report) || (statuses && !log.holds(Source::Status)) {
        return Verdict::Unrun(NO_RECORDS);
    }
    let Expected::Rows(expected) = expected else {
        return Verdict::Unrun(NOT_JUDGED);
    };
    if log.unsealable > 0 {
        return Verdict::Fail(UNSEALED, format!("{} ticks", log.unsealable));
    }
    let (inputs, refused) = inputs(log);
    if refused > 0 {
        return Verdict::Fail(UNREAD, format!("{refused} records"));
    }
    let fired = rows(&fired(catalog, &inputs));
    let expected: BTreeSet<String> = expected.iter().map(|row| (*row).to_owned()).collect();
    let missing: Vec<&String> = expected.difference(&fired).collect();
    let extra: Vec<&String> = fired.difference(&expected).collect();
    if missing.is_empty() && extra.is_empty() {
        return Verdict::Pass;
    }
    Verdict::Fail(ALARM_SET, format!("missing {missing:?} extra {extra:?}"))
}

/// The run's alarm verdict: a planted run reads `Unrun(PLANTED)`, a run whose fault script a test replaced reads
/// as a run with no expected set, and every other run is [`judged`] under the shipped catalog against [`expected`],
/// with a status required when the scenario runs reconcilers. A run that would pass with more early ticks refused
/// than its scenario scripts fails `UNSEALED`.
pub(crate) fn verdict(log: &AlarmLog, config: &super::Config) -> Verdict {
    static SHIPPED: std::sync::LazyLock<Value> = std::sync::LazyLock::new(catalog);
    if matches!(config.profile, super::Profile::Hostile(..)) {
        return Verdict::Unrun(PLANTED);
    }
    let expected = match log.scripted {
        true => Expected::NotJudged,
        false => expected(config),
    };
    let judged = judged(log, &SHIPPED, expected, config.scenario.repairs());
    // The two-reconciler race takes one more tick of reconciler 1 inside a round, which its writer refuses as early.
    let scripted_early = u32::from(config.scenario == Scenario::Racing);
    match judged {
        Verdict::Pass if log.unsealed > scripted_early => {
            Verdict::Fail(UNSEALED, format!("{} early ticks", log.unsealed))
        }
        judged => judged,
    }
}

/// The fleet's alarm verdict over each scenario's verdict: the first failure; `Unrun(INCOMPLETE)` when any scenario
/// did not pass, a scenario with no expected set or no records included, or when no scenario was judged; `Pass`.
pub(crate) fn fleet_verdict(verdicts: &[Verdict]) -> Verdict {
    if let Some(failed) = verdicts.iter().find(|verdict| verdict.rule().is_some()) {
        return failed.clone();
    }
    match !verdicts.is_empty() && verdicts.iter().all(Verdict::passed) {
        true => Verdict::Pass,
        false => Verdict::Unrun(INCOMPLETE),
    }
}

const SILENT: &[&str] = &["host-silent", "shard-silent"];
const FRESH: &[&str] = &["host-silent", "need-fresh", "shard-silent"];
const ZONE_LOST: &[&str] = &["host-silent", "need-fresh", "shard-silent"];

/// The rows each scenario's run fires on its fixture shape, by the scenario and, for a one-zone settle, the census
/// cap of its shape; a hostile store or registrant profile admits its scenario's own episodes and changes no set.
/// The volume cases and the replacement cells have no expected set here. A one-zone repair scenario other than the
/// settle, the full census and the standby-target scenario has none under a census cap below its shard count, and
/// the full census, the standby-target scenario and every two-zone scenario have none under a cap other than their
/// fixture's.
///
/// The status rows fire only where reconciler actors run and seal a status, so a host scenario's lost host fires
/// none of them. An isolated owner's host, H0, counts its three unreachable probers' partitions suspect and reads
/// its own self-suspicion dwell (`self-suspect-host`).
///
/// A lost host reads silent on the zone's status (`host-silent`) and leaves its shards without a live owner while
/// the loss lasts (`shard-silent`); a shard whose owner and standby are both lost needs a fresh host (`need-fresh`);
/// three lost hosts of one zone bring every survivor to its self-suspicion threshold (`self-suspect-host` on the
/// survivors' reports, `self-suspect-zone` on the status). A census cap below the zone's
/// shard count raises `census-cap-below-shards` and, with the census listing every slot it holds, `census-near-cap`.
/// A shard that the full census leaves with no standby serves past the zone's standby target in the standby-target
/// scenario, which raises `no-standby-past-target` beside its census rows.
/// A standby-enrollment crash cell loses a standby's host alone (`host-silent`); a fresh-host cell loses owner and
/// standby, and where the crash cuts a designation whose write landed the restarted loop reads the volume's attach
/// slots closed on one status before the enrollment settles (`attach-closed`), as the slot-moved case does while the
/// slot's host and the named standby both hold an attach. The foreign registrant withdraws s0's owner, whose entry
/// reads the foreign registrant and the retirement request, and the status rows its shard blocked; a zone loss under
/// impaired evidence rows its shards blocked the same way. The regressed shard-record read puts the store
/// regression watermark on the faulted tenure's entry.
///
/// The isolated owner's takeovers load at once, and the owner's deposed tenures withdraw while its records still name
/// it owner, so its reports list no entry for those roles until the zone's hosts reread the shard records after each
/// load ends (`producer-missing`, which rests on that reread, the harness's stand-in for the agents' record sync).
///
/// Where a lost host's takeovers or a returning zone's restarts load at once, no shard stays without a live owner and
/// no returning host lists an owned role with no entry for the rows' windows: the reenroll, partition-repair, racing
/// and slot-moved cases fire no `shard-silent`, and the zone cases no `producer-missing`.
///
/// A planned handoff to a live, attached standby fires nothing. A handoff to a target whose attach ended parks the
/// target, which publishes no status while it parks, so its host's reports list no entry for that process
/// (`producer-missing`); the zone loop counts the owner with no live attach lost and needs a fresh host
/// (`need-fresh`), and the shard has no live owner until the designated host takes it over once the parked host's
/// health bit drops (`shard-silent`).
pub(crate) fn expected(config: &super::Config) -> Expected {
    use super::reconcile::{Call, Ending};
    use Scenario::*;
    let (root, cap) = (config.root, config.shape.cap);
    let cap_below = config.shape.zones == 1 && u32::from(cap) < config.shape.shards;
    let off_fixture = match config.scenario {
        CensusFull => cap != super::Config::census_full(root).shape.cap,
        PastTarget => cap != super::Config::past_target(root).shape.cap,
        Settle if config.shape.zones == 1 => false,
        scenario if config.shape.zones > 1 => cap != super::Config::az(root, scenario).shape.cap,
        scenario => cap_below && scenario.repairs(),
    };
    if off_fixture {
        return Expected::NotJudged;
    }
    let rows: &'static [&'static str] = match config.scenario {
        Impaired | ImpairedBrief | Stall | LostAlone | Correlated | CorrelatedLate | Replace(_) => {
            return Expected::NotJudged;
        }
        Restarts | HostLoss | PartitionLoss | FalseSuspicion | OwnerPause | StoreUnknown(_)
        | PageRegressed => &[],
        OwnerIsolation => &["producer-missing", "self-suspect-host"],
        PartitionLossAt => &["self-suspect-host"],
        RecordRegressed => &["store-regression"],
        Settle if cap_below => &["census-cap-below-shards", "census-near-cap"],
        Settle => &[],
        StandbyLoss | StandbySilent => &["host-silent"],
        Reenroll => &["host-silent"],
        PartitionRepair | Racing => &["host-silent"],
        AttachSurvivor => SILENT,
        DoubleLoss => FRESH,
        Crash(cell) if !cell.fresh => &["host-silent"],
        Crash(cell) if cell.call == Call::Designate && cell.ending != Ending::Lost => {
            &["attach-closed", "host-silent", "need-fresh", "shard-silent"]
        }
        Crash(_) => FRESH,
        PartitionRepairAt => &[
            "host-silent",
            "self-suspect-host",
            "self-suspect-zone",
            "shard-silent",
        ],
        CensusFull => &[
            "census-cap-below-shards",
            "census-near-cap",
            "census-refused-full",
            "host-silent",
            "need-fresh",
            "shard-silent",
        ],
        AttachClosed => &[
            "attach-closed",
            "host-silent",
            "need-fresh",
            "self-suspect-host",
            "self-suspect-zone",
            "shard-silent",
        ],
        Foreign => &[
            "registrant-foreign",
            "retirement-requested",
            "shard-blocked",
        ],
        SlotMoved => &["attach-closed", "host-silent"],
        Handoff => &[],
        PastTarget => &[
            "census-cap-below-shards",
            "census-near-cap",
            "census-refused-full",
            "no-standby-past-target",
        ],
        HandoffEnded => &["need-fresh", "producer-missing", "shard-silent"],
        ZoneLoss | ZoneDeposed => ZONE_LOST,
        ZoneImpaired => &["host-silent", "need-fresh", "shard-blocked", "shard-silent"],
    };
    Expected::Rows(rows)
}
