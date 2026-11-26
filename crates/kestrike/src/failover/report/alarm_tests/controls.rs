//! Each catalog row's control and clean twin: the shared values that the real deciding code produces on an injected
//! fault and on its matched clean history (`controls::<row>()`), and the sealed histories the table test builds
//! from them with the thresholds and windows the row states.

use core::num::NonZeroU64;
use std::collections::BTreeMap;

use serde_json::Value;

use crate::failover::loss::Health;
use crate::failover::records::Host;
use crate::failover::report::status::{
    self, ATTACHES, AttachOutcome, CLASSES, Class, RECEIPTS, REFUSED, ReceiptCount, Refused,
    STANDBYS, Standby, StatusReader, StoreAlarm, ZonePart,
};
use crate::failover::report::tests::{bare, view};
use crate::failover::report::{
    Damage, Enumeration, Envelope, Exit, ExitOperation, ExitStatus, Gauge, HostState, LoadRefusal,
    Members, Reader, RecordedRole, Recovery, RecoveryCheck, RecoveryKind, RecoveryNext,
    RecoveryOutcome, Registrants, ReportKey, Restart, Retention, StoreClass, VolumeEntry,
    Watermark, Withdrawal, Writer, WriterId,
};
use crate::failover::serving::State;
use crate::failover::sim::host;
use crate::failover::standbys::Need;
use crate::failover::standbys::Zone;
use crate::failover::zone_loop::status::Blocker;
use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration};

use super::Input;

/// A control value and its clean twin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Twin<T> {
    pub(crate) fault: T,
    pub(crate) clean: T,
}

impl<T: Copy> Twin<T> {
    pub(crate) fn pick(self, fault: bool) -> T {
        if fault { self.fault } else { self.clean }
    }
}

const KEY: [u8; 32] = [0x5C; 32];
const PERIOD: NonZeroU64 = NonZeroU64::new(1_000).unwrap();
/// The first record's seal time and the time between records, in microseconds.
const START: u64 = 1_750_000_000_000_000;
const STEP: u64 = 10_000_000;

fn members(used: u64, limit: u64) -> Members {
    Members::Known { used, limit }
}

/// A refused recovery attempt of `kind` with `check`, `next` and `store`.
fn refused(
    kind: RecoveryKind,
    check: RecoveryCheck,
    next: RecoveryNext,
    store: Option<StoreClass>,
) -> Recovery {
    Recovery {
        kind: Some(kind),
        outcome: Some(RecoveryOutcome::Refused),
        check: Some(check),
        next: Some(next),
        store,
        attempts: Some(1),
        age_us: Some(50),
    }
}

/// A completed restart, the clean twin of every refused attempt.
pub(crate) fn completed() -> Recovery {
    Recovery {
        kind: Some(RecoveryKind::Restart),
        outcome: Some(RecoveryOutcome::Completed),
        attempts: Some(1),
        age_us: Some(50),
        ..Recovery::UNAVAILABLE
    }
}

pub(crate) fn store_regression() -> Twin<Watermark> {
    Twin {
        fault: Watermark::Regression,
        clean: Watermark::Clear,
    }
}

pub(crate) fn store_instance_change() -> Twin<Watermark> {
    Twin {
        fault: Watermark::Namespace,
        clean: Watermark::Clear,
    }
}

/// The flip request and withdrawal a recorded force detach leaves, and the serving entry's.
pub(crate) fn retirement_requested() -> Twin<(bool, Option<Withdrawal>)> {
    Twin {
        fault: (true, Some(Withdrawal::ForceDetach)),
        clean: (false, None),
    }
}

pub(crate) fn hold_recorded_holder() -> Twin<Recovery> {
    let fault = refused(
        RecoveryKind::Restart,
        RecoveryCheck::RecordedHolder,
        RecoveryNext::Hold,
        None,
    );
    Twin {
        fault,
        clean: completed(),
    }
}

pub(crate) fn hold_no_holder() -> Twin<Recovery> {
    let fault = refused(
        RecoveryKind::Restart,
        RecoveryCheck::Unheld,
        RecoveryNext::Hold,
        None,
    );
    Twin {
        fault,
        clean: completed(),
    }
}

/// A restart whose ready wait failed holds the volume, as a failure of each of its device commands does.
pub(crate) fn hold_device() -> Twin<Recovery> {
    let fault = refused(
        RecoveryKind::Restart,
        RecoveryCheck::Ready,
        RecoveryNext::Hold,
        None,
    );
    Twin {
        fault,
        clean: completed(),
    }
}

/// A restart whose bump the store refused holds the volume with the refused class.
pub(crate) fn hold_store() -> Twin<Recovery> {
    let store = Some(StoreClass::Refused);
    let fault = refused(
        RecoveryKind::Restart,
        RecoveryCheck::Bump,
        RecoveryNext::Hold,
        store,
    );
    Twin {
        fault,
        clean: completed(),
    }
}

/// A restart whose bump reply was lost holds with the unknown class.
pub(crate) fn unknown_recovery_write() -> Twin<Recovery> {
    let store = Some(StoreClass::Unknown);
    let fault = refused(
        RecoveryKind::Restart,
        RecoveryCheck::Bump,
        RecoveryNext::Hold,
        store,
    );
    Twin {
        fault,
        clean: completed(),
    }
}

/// A restart over a record that names certified suffixes and no checkpoint stops at step 1.
pub(crate) fn suffix_only() -> Twin<Recovery> {
    let fault = refused(
        RecoveryKind::Restart,
        RecoveryCheck::SuffixOnly,
        RecoveryNext::Stop,
        None,
    );
    Twin {
        fault,
        clean: completed(),
    }
}

/// Load limits with an empty payload area refuse the warm load.
pub(crate) fn load_refused() -> Twin<Option<LoadRefusal>> {
    Twin {
        fault: Some(LoadRefusal::Limits),
        clean: None,
    }
}

pub(crate) fn enumeration_foreign() -> Twin<Enumeration> {
    Twin {
        fault: Enumeration::Foreign,
        clean: Enumeration::Matches,
    }
}

pub(crate) fn registrant_foreign() -> Twin<(Option<Registrants>, Option<Withdrawal>)> {
    Twin {
        fault: (Some(Registrants::ForeignHolder), Some(Withdrawal::Report)),
        clean: (Some(Registrants::Sole), None),
    }
}

pub(crate) fn registrant_deferred() -> (Option<Registrants>, Option<Withdrawal>) {
    (Some(Registrants::ForeignRegistrant), None)
}

/// An ended registrant on every report of the window, and one whose reports read the own pair sole from the
/// window's last report on, as a Report with the ended key removed reads.
pub(crate) fn registrant_ended() -> Twin<Option<Registrants>> {
    Twin {
        fault: Some(Registrants::EndedRegistrant),
        clean: Some(Registrants::Sole),
    }
}

/// A warm load with one slot unit whose content check failed, and the same load intact.
pub(crate) fn retention_damage() -> Twin<Option<Retention>> {
    let intact = Retention {
        first_damage: None,
        installed: 12,
        omitted: 0,
        held_units: 48,
        failed_units: 0,
        unread_units: 0,
        suffix_damage: 0,
        suffix_tails: 0,
        suffix_dropped: 0,
        suffix_unread: 0,
        slot_superseded: 0,
        slot_withheld: 0,
    };
    let damaged = Retention {
        first_damage: Some(Damage::Content),
        installed: 11,
        failed_units: 1,
        ..intact
    };
    Twin {
        fault: Some(damaged),
        clean: Some(intact),
    }
}

/// The read-defect counts of two successive reports.
pub(crate) fn read_defect() -> Twin<[u64; 2]> {
    Twin {
        fault: [0, 1],
        clean: [0, 0],
    }
}

pub(crate) fn chain_at_cap() -> Twin<Gauge> {
    Twin {
        fault: Gauge::known(4, 4),
        clean: Gauge::known(1, 4),
    }
}

pub(crate) fn handoff_due() -> Twin<Option<bool>> {
    Twin {
        fault: Some(true),
        clean: Some(false),
    }
}

/// An exit whose planned transfer the store refused restarts, and one whose successor record arrived exits.
pub(crate) fn exit_restarting() -> Twin<ExitStatus> {
    Twin {
        fault: ExitStatus::Restarting(Restart::TransferRefused),
        clean: ExitStatus::Exited,
    }
}

/// An exit that waits on its successor record after the withdrawal, and one that exited. The history starts both at
/// `withdrawn`.
pub(crate) fn exit_stuck() -> Twin<ExitStatus> {
    Twin {
        fault: ExitStatus::Waiting,
        clean: ExitStatus::Exited,
    }
}

/// One saturated coverage page of two, and none.
pub(crate) fn coverage_saturated() -> Twin<Gauge> {
    Twin {
        fault: Gauge::known(1, 2),
        clean: Gauge::known(0, 2),
    }
}

/// Held INVALIDATEs at the owner's hold bound of 64, and none.
pub(crate) fn mutation_backlog_full() -> Twin<Gauge> {
    let bound = 64;
    Twin {
        fault: Gauge::known(bound, bound),
        clean: Gauge::known(0, bound),
    }
}

pub(crate) fn suffix_backlog_full() -> Twin<Gauge> {
    Twin {
        fault: Gauge::known(16, 16),
        clean: Gauge::known(2, 16),
    }
}

pub(crate) fn publication_stuck() -> Twin<Option<bool>> {
    Twin {
        fault: Some(true),
        clean: Some(false),
    }
}

pub(crate) fn enumeration_unlisted() -> Twin<Enumeration> {
    Twin {
        fault: Enumeration::Unlisted,
        clean: Enumeration::Matches,
    }
}

/// The detector's self-suspicion dwell: five seconds left, and none.
pub(crate) fn self_suspect_host() -> Twin<Option<u64>> {
    Twin {
        fault: Some(5_000_000),
        clean: Some(0),
    }
}

/// One of two assigned volumes without a fresh entry, and none.
pub(crate) fn producer_missing() -> Twin<Members> {
    Twin {
        fault: members(1, 2),
        clean: members(0, 2),
    }
}

/// One shard past the standby target with no standby, and none.
pub(crate) fn no_standby_past_target() -> Twin<u32> {
    Twin { fault: 1, clean: 0 }
}

/// One shard the full census leaves without a slot, and none.
pub(crate) fn census_refused_full() -> Twin<u32> {
    Twin { fault: 1, clean: 0 }
}

/// A census cap below the zone's shard count, and a cap at it.
pub(crate) fn census_cap_below_shards() -> Twin<bool> {
    Twin {
        fault: true,
        clean: false,
    }
}

/// One shard whose active volume admits no attach, and none.
pub(crate) fn attach_closed() -> Twin<u32> {
    Twin { fault: 1, clean: 0 }
}

/// One held replacement receipt, and none.
pub(crate) fn replacement_held() -> Twin<u32> {
    Twin { fault: 1, clean: 0 }
}

/// One shard lost at its last generation, and none.
pub(crate) fn replacement_exhausted() -> Twin<u32> {
    Twin { fault: 1, clean: 0 }
}

/// One shard whose lost owner's standby cannot gather a detector quorum, and none.
pub(crate) fn quorum_unreachable() -> Twin<u32> {
    Twin { fault: 1, clean: 0 }
}

/// One lost active volume, and none.
pub(crate) fn volume_lost() -> Twin<u32> {
    Twin { fault: 1, clean: 0 }
}

/// One listed cache volume that reads impaired or lost and that no shard names, and none.
pub(crate) fn volume_unnamed() -> Twin<Option<u64>> {
    Twin {
        fault: Some(1),
        clean: Some(0),
    }
}

/// The tag refusals of two successive statuses: one forged report between them, and none.
pub(crate) fn report_forged() -> Twin<[u32; 2]> {
    Twin {
        fault: [0, 1],
        clean: [0, 0],
    }
}

/// The schema refusals of two successive statuses: one schema-2 report between them, and none.
pub(crate) fn report_schema() -> Twin<[u32; 2]> {
    Twin {
        fault: [0, 1],
        clean: [0, 0],
    }
}

/// One stale serving entry, and none.
pub(crate) fn stale_serving() -> Twin<u32> {
    Twin { fault: 1, clean: 0 }
}

/// One blocked shard, and none.
pub(crate) fn shard_blocked() -> Twin<u32> {
    Twin { fault: 1, clean: 0 }
}

/// One silent shard, and none.
pub(crate) fn shard_silent() -> Twin<u32> {
    Twin { fault: 1, clean: 0 }
}

/// The fault case reports one `StoreUnavailable` blocker at every status; the clean case reports one at the first
/// status and zero thereafter.
pub(crate) fn store_unread() -> Twin<[u32; 2]> {
    Twin {
        fault: [1, 1],
        clean: [1, 0],
    }
}

/// The reports, instances, volumes and store flags of a tick that read none of its sources, and of one that read
/// all four.
pub(crate) fn sources_unread() -> Twin<[bool; 4]> {
    Twin {
        fault: [false; 4],
        clean: [true; 4],
    }
}

/// One shard that needs a fresh host, and none.
pub(crate) fn need_fresh() -> Twin<u32> {
    Twin { fault: 1, clean: 0 }
}

/// A census at 58 of 64 slots, above 0.9 of a cap below the zone's shard count, and one at 57.
pub(crate) fn census_near_cap() -> Twin<Members> {
    Twin {
        fault: members(58, 64),
        clean: members(57, 64),
    }
}

/// The failed attach steps of two successive statuses: one failure between them, and none.
pub(crate) fn attach_failed() -> Twin<[u32; 2]> {
    Twin {
        fault: [0, 1],
        clean: [0, 0],
    }
}

/// One self-suspecting host, and none.
pub(crate) fn self_suspect_zone() -> Twin<u32> {
    Twin { fault: 1, clean: 0 }
}

/// One silent host of three, and none.
pub(crate) fn host_silent() -> Twin<Members> {
    Twin {
        fault: members(1, 3),
        clean: members(0, 3),
    }
}

pub(crate) fn budget_attempts() -> Twin<Members> {
    let limit = u64::from(crate::failover::records::ATTEMPTS_MAX);
    let at = (limit * 9).div_ceil(10);
    Twin {
        fault: members(at, limit),
        clean: members(at - 1, limit),
    }
}

pub(crate) fn budget_generation() -> Twin<Members> {
    let limit = u64::from(u32::MAX) - 1;
    let at = (limit * 9).div_ceil(10);
    Twin {
        fault: members(at, limit),
        clean: members(at - 1, limit),
    }
}

pub(crate) fn store_regression_reconciler() -> Twin<StoreAlarm> {
    Twin {
        fault: StoreAlarm::Regression,
        clean: StoreAlarm::Clear,
    }
}

pub(crate) fn store_instance_change_reconciler() -> Twin<StoreAlarm> {
    Twin {
        fault: StoreAlarm::Namespace,
        clean: StoreAlarm::Clear,
    }
}

/// One record of a history.
#[derive(Debug, Clone)]
pub(crate) enum Step {
    Report {
        host: u64,
        state: Box<HostState>,
        entries: Vec<VolumeEntry>,
    },
    /// The previous report of `host`, delivered again.
    Again {
        host: u64,
    },
    /// Later reports of `host` come from its writer of boot `boot`, which starts at sequence 1 the first time.
    Boot {
        host: u64,
        boot: u8,
    },
    Status(Vec<ZonePart>),
    /// Later statuses come from the status writer of boot `boot`, which starts at sequence 1 the first time.
    StatusBoot(u8),
    /// An evaluation instant with no record.
    Tick,
}

/// The base owner entry: shard 1 at `(1, 2)`, serving, with a clear watermark and matching enumeration.
pub(crate) fn owner() -> VolumeEntry {
    VolumeEntry {
        shard: Shard::new(1).unwrap(),
        tenure: Some((
            ShardGeneration::new(1).unwrap(),
            ActivatedEpoch::new(2).unwrap(),
        )),
        serving: Some(State::Serving),
        enumeration: Enumeration::Matches,
        watermark: Watermark::Clear,
        ..bare("vol-0a", RecordedRole::Owner)
    }
}

pub(crate) use crate::failover::zone_loop::tests::observe::host_state;

/// `n` reports of host 1, each holding the owner entry `edit` changes at its index.
fn entries(n: u64, edit: impl Fn(u64, &mut VolumeEntry)) -> Vec<Step> {
    (0..n)
        .map(|at| {
            let mut entry = owner();
            edit(at, &mut entry);
            Step::Report {
                host: 1,
                state: Box::new(host_state()),
                entries: vec![entry],
            }
        })
        .collect()
}

/// `n` reports of host 1 with no entry and the host part `edit` changes.
fn hosts(n: u64, edit: impl Fn(&mut HostState)) -> Vec<Step> {
    (0..n)
        .map(|_| {
            let mut state = host_state();
            edit(&mut state);
            Step::Report {
                host: 1,
                state: Box::new(state),
                entries: Vec::new(),
            }
        })
        .collect()
}

/// `n` statuses of zone 1 from ticks that read the census and every shard's records, each holding a part `edit`
/// changes at its index.
fn zones(n: u64, edit: impl Fn(u64, &mut ZonePart)) -> Vec<Step> {
    (0..n)
        .map(|at| {
            let mut part = ZonePart {
                tick: at + 1,
                ..ZonePart::blank(Zone(1))
            };
            part.flags.store = true;
            edit(at, &mut part);
            Step::Status(vec![part])
        })
        .collect()
}

/// The records a row needs to meet its window: its report count, or enough records one step apart to span its
/// duration, and at least three.
fn span(row: &Value) -> u64 {
    let reports = row["window"]["reports"].as_u64();
    let us = row["window"]["us"].as_u64();
    reports.or(us.map(|us| us / STEP + 2)).unwrap_or(1).max(3)
}

fn number(row: &Value, key: &str) -> u64 {
    row["condition"][key].as_u64().unwrap()
}

type Build = fn(&Value, bool) -> Vec<Step>;

/// The history builder of each row's control, keyed by the name the row's `control` field holds; its clean twin is
/// the same builder under the name the row's `clean` field holds.
pub(crate) fn builders() -> BTreeMap<&'static str, Build> {
    let rows: [(&'static str, Build); 56] = [
        ("store_regression", |row, f| {
            entries(span(row), |_, e| e.watermark = store_regression().pick(f))
        }),
        ("store_instance_change", |row, f| {
            entries(span(row), |_, e| {
                e.watermark = store_instance_change().pick(f)
            })
        }),
        ("retirement_requested", |row, f| {
            entries(span(row), |_, e| {
                let (flip, withdrawal) = retirement_requested().pick(f);
                if flip {
                    e.serving = Some(State::Withdrawn);
                }
                (e.flip, e.withdrawal) = (flip, withdrawal);
            })
        }),
        ("hold_recorded_holder", |row, f| {
            entries(span(row), |_, e| {
                e.recovery = hold_recorded_holder().pick(f)
            })
        }),
        ("hold_no_holder", |row, f| {
            entries(span(row), |_, e| e.recovery = hold_no_holder().pick(f))
        }),
        ("hold_device", |row, f| {
            entries(span(row), |_, e| e.recovery = hold_device().pick(f))
        }),
        ("hold_store", |row, f| {
            entries(span(row), |_, e| e.recovery = hold_store().pick(f))
        }),
        ("unknown_recovery_write", |row, f| {
            entries(span(row), |_, e| {
                e.recovery = unknown_recovery_write().pick(f)
            })
        }),
        ("suffix_only", |row, f| {
            entries(span(row), |_, e| e.recovery = suffix_only().pick(f))
        }),
        ("load_refused", |row, f| {
            entries(span(row), |_, e| e.load_refusal = load_refused().pick(f))
        }),
        ("enumeration_foreign", |row, f| {
            entries(span(row), |_, e| {
                e.enumeration = enumeration_foreign().pick(f)
            })
        }),
        ("registrant_foreign", |row, f| {
            entries(span(row), |_, e| {
                (e.registrants, e.withdrawal) = registrant_foreign().pick(f);
                if e.withdrawal.is_some() {
                    (e.serving, e.flip) = (Some(State::Withdrawn), true);
                }
            })
        }),
        ("retention_damage", |_, f| {
            entries(6, |_, e| e.retention = retention_damage().pick(f))
        }),
        ("read_defect", |row, f| {
            let counts = read_defect().pick(f);
            entries(span(row), |at, e| {
                e.read_defects = Some(counts[(at as usize).min(1)])
            })
        }),
        ("chain_at_cap", |row, f| {
            entries(span(row), |_, e| {
                e.pressure.ancestry = chain_at_cap().pick(f)
            })
        }),
        ("handoff_due", |row, f| {
            entries(span(row), |_, e| e.roll_due = handoff_due().pick(f))
        }),
        ("exit_restarting", |row, f| {
            let operation = ExitOperation::new([7; 16]).unwrap();
            let status = exit_restarting().pick(f);
            entries(span(row), |_, e| e.exit = Some(Exit { operation, status }))
        }),
        ("exit_stuck", |row, f| {
            let operation = ExitOperation::new([8; 16]).unwrap();
            entries(span(row), |at, e| {
                let status = match at {
                    0 => ExitStatus::Withdrawn,
                    _ => exit_stuck().pick(f),
                };
                e.exit = Some(Exit { operation, status })
            })
        }),
        ("coverage_saturated", |row, f| {
            entries(span(row), |_, e| {
                e.coverage.saturated = coverage_saturated().pick(f)
            })
        }),
        ("first_hit_slow", |row, f| {
            let at = number(row, "value") + u64::from(f);
            entries(6, |_, e| e.times.first_hit_us = Some(at))
        }),
        ("recovery_stuck", |row, f| {
            let age = number(row, "value") + u64::from(f);
            entries(span(row), |_, e| {
                e.recovery = Recovery {
                    kind: Some(RecoveryKind::Takeover),
                    outcome: Some(RecoveryOutcome::Running),
                    attempts: Some(1),
                    age_us: Some(age),
                    ..Recovery::UNAVAILABLE
                }
            })
        }),
        ("store_unknown_rate", |row, f| {
            let rise = number(row, "at_least") - u64::from(!f);
            entries(span(row), |at, e| {
                e.store.unknown = Some(if at == 0 { 0 } else { rise });
            })
        }),
        ("mutation_backlog_full", |row, f| {
            entries(span(row), |_, e| {
                e.invalidations = mutation_backlog_full().pick(f)
            })
        }),
        ("suffix_backlog_full", |row, f| {
            entries(span(row), |_, e| {
                e.suffix.blocks = suffix_backlog_full().pick(f)
            })
        }),
        ("publication_stuck", |row, f| {
            entries(span(row), |_, e| {
                e.publication_due = publication_stuck().pick(f)
            })
        }),
        ("enumeration_unlisted", |row, f| {
            entries(span(row), |_, e| {
                e.enumeration = enumeration_unlisted().pick(f)
            })
        }),
        ("self_suspect_host", |row, f| {
            hosts(span(row), |h| {
                h.detector.self_suspect_us = self_suspect_host().pick(f)
            })
        }),
        ("producer_missing", |row, f| {
            hosts(span(row), |h| {
                h.producer_missing = producer_missing().pick(f)
            })
        }),
        ("no_standby_past_target", |row, f| {
            let past = no_standby_past_target().pick(f);
            zones(span(row), |_, z| {
                z.standby[slot(STANDBYS, Standby::Past)] = past
            })
        }),
        ("census_refused_full", |row, f| {
            let full = census_refused_full().pick(f);
            zones(span(row), |_, z| {
                z.blockers[Blocker::CensusFull.position()] = full
            })
        }),
        ("census_cap_below_shards", |row, f| {
            let below = census_cap_below_shards().pick(f);
            zones(span(row), |_, z| z.flags.cap_below = below)
        }),
        ("attach_closed", |row, f| {
            let closed = attach_closed().pick(f);
            zones(span(row), |_, z| {
                z.blockers[Blocker::AttachClosed.position()] = closed
            })
        }),
        ("replacement_held", |row, f| {
            let held = replacement_held().pick(f);
            zones(span(row), |_, z| {
                z.receipts[slot(RECEIPTS, ReceiptCount::Held)] = held
            })
        }),
        ("replacement_exhausted", |row, f| {
            let exhausted = replacement_exhausted().pick(f);
            let at = Blocker::ReplacementExhausted.position();
            zones(span(row), |_, z| z.blockers[at] = exhausted)
        }),
        ("quorum_unreachable", |row, f| {
            let unreachable = quorum_unreachable().pick(f);
            let at = Blocker::QuorumUnreachable.position();
            // Both twins read every report and the instance listing, so each completeness flag the row guards on
            // is true and a gap tick holds by its own flag alone.
            zones(span(row), |_, z| {
                (z.flags.reports, z.flags.instances) = (true, true);
                z.blockers[at] = unreachable
            })
        }),
        ("volume_lost", |row, f| {
            let lost = volume_lost().pick(f);
            zones(span(row), |_, z| {
                z.volumes[status::health_at(Some(Health::Lost))] = lost
            })
        }),
        ("volume_unnamed", |row, f| {
            let unnamed = volume_unnamed().pick(f);
            zones(span(row), |_, z| {
                (z.flags.volumes, z.unnamed_volumes) = (true, unnamed)
            })
        }),
        ("report_forged", |row, f| {
            let counts = report_forged().pick(f);
            zones(span(row), |at, z| {
                z.events.refused[slot(REFUSED, Refused::Tag)] = counts[(at as usize).min(1)]
            })
        }),
        ("report_schema", |row, f| {
            let counts = report_schema().pick(f);
            zones(span(row), |at, z| {
                z.events.refused[slot(REFUSED, Refused::Schema)] = counts[(at as usize).min(1)]
            })
        }),
        ("stale_serving", |row, f| {
            let stale = stale_serving().pick(f);
            zones(span(row), |_, z| {
                z.stale_serving = stale;
                z.stale_oldest_us = (stale > 0).then_some(1);
            })
        }),
        ("shard_blocked", |row, f| {
            let blocked = shard_blocked().pick(f);
            zones(span(row), |_, z| {
                z.classes[slot(CLASSES, Class::Blocked)] = blocked
            })
        }),
        ("shard_silent", |row, f| {
            let silent = shard_silent().pick(f);
            zones(span(row), |_, z| {
                z.classes[slot(CLASSES, Class::Silent)] = silent
            })
        }),
        ("store_unread", |row, f| {
            let unread = store_unread().pick(f);
            zones(span(row), |at, z| {
                let blocked = unread[(at as usize).min(1)];
                z.blockers[Blocker::StoreUnavailable.position()] = blocked;
                (z.flags.warm_up, z.flags.store) = (true, blocked == 0);
            })
        }),
        ("sources_unread", |row, f| {
            let [reports, instances, volumes, store] = sources_unread().pick(f);
            zones(span(row), |_, z| {
                z.flags.warm_up = true;
                (z.flags.reports, z.flags.instances) = (reports, instances);
                (z.flags.volumes, z.flags.store) = (volumes, store);
            })
        }),
        ("need_fresh", |row, f| {
            let fresh = need_fresh().pick(f);
            zones(span(row), |_, z| {
                z.needs[status::need_at(Need::Fresh)] = fresh
            })
        }),
        ("census_near_cap", |row, f| {
            let census = census_near_cap().pick(f);
            zones(span(row), |_, z| {
                z.census = census;
                z.flags.cap_below = true;
            })
        }),
        ("attach_failed", |row, f| {
            let counts = attach_failed().pick(f);
            zones(span(row), |at, z| {
                z.events.attaches[slot(ATTACHES, AttachOutcome::Failed)] =
                    counts[(at as usize).min(1)]
            })
        }),
        ("self_suspect_zone", |row, f| {
            let suspecting = self_suspect_zone().pick(f);
            zones(span(row), |_, z| z.hosts.self_suspect = suspecting)
        }),
        ("host_silent", |row, f| {
            let silent = host_silent().pick(f);
            zones(span(row), |_, z| z.hosts.silent = silent)
        }),
        ("status_absent", |row, f| {
            let window = row["window"]["us"].as_u64().unwrap();
            let mut steps = zones(2, |_, _| {});
            let ticks = window / STEP + 2;
            for at in 0..ticks {
                steps.push(match f {
                    true => Step::Tick,
                    false => zones(1, |_, z| z.tick = at + 3).remove(0),
                });
            }
            steps
        }),
        ("budget_attempts", |row, f| {
            let attempts = budget_attempts().pick(f);
            zones(span(row), |_, z| z.budgets.attempts = attempts)
        }),
        ("budget_generation", |row, f| {
            let generation = budget_generation().pick(f);
            zones(span(row), |_, z| z.budgets.generation = generation)
        }),
        ("store_regression_reconciler", |row, f| {
            let alarm = store_regression_reconciler().pick(f);
            zones(span(row), |_, z| z.store.alarm = alarm)
        }),
        ("store_instance_change_reconciler", |row, f| {
            let alarm = store_instance_change_reconciler().pick(f);
            zones(span(row), |_, z| z.store.alarm = alarm)
        }),
        ("store_unknown_rate_reconciler", |row, f| {
            let rise = u32::try_from(number(row, "at_least")).unwrap() - u32::from(!f);
            zones(span(row), |at, z| {
                z.store.outcomes[0] = if at == 0 { 0 } else { rise }
            })
        }),
        ("registrant_ended", |row, f| {
            // The clean twin clears one report short of the row's window, whatever the padded length.
            let clears = row["window"]["reports"].as_u64().unwrap() - 1;
            entries(span(row), |at, e| {
                e.registrants = match at >= clears {
                    true => registrant_ended().pick(f),
                    false => registrant_ended().fault,
                }
            })
        }),
    ];
    rows.into_iter().collect()
}

/// The count slot of `value` in `table`.
pub(crate) fn slot<T: PartialEq>(table: &[T], value: T) -> usize {
    table.iter().position(|listed| *listed == value).unwrap()
}

/// The names of every registered history: each builder's control and its clean twin.
pub(crate) fn names() -> std::collections::BTreeSet<String> {
    builders()
        .keys()
        .flat_map(|name| [(*name).to_owned(), format!("{name}.clean")])
        .collect()
}

/// The history a row's `control` or `clean` name selects.
pub(crate) fn history(row: &Value, name: &str) -> Vec<Step> {
    let (base, fault) = match name.strip_suffix(".clean") {
        Some(base) => (base, false),
        None => (name, true),
    };
    (builders()[base])(row, fault)
}

fn report_key(_: Host) -> Option<ReportKey> {
    Some(ReportKey::derive(&KEY))
}

/// A report writer for `host` under boot nonce `boot`.
fn writer(host: Host, boot: u8) -> Writer {
    let boot = [boot; 16];
    Writer {
        key: ReportKey::derive(&KEY),
        envelope: Envelope::new(WriterId { host, boot }, PERIOD),
    }
}

/// What a history's records give the evaluator, and the readers' refusals: each step sealed one `STEP` after the
/// last, a report by its host's writer and a status by the status writer, then accepted, with a repeated delivery
/// refused as a duplicate and dropped.
pub(crate) fn sealed(steps: &[Step]) -> (Vec<Input>, Vec<crate::failover::report::ReportError>) {
    let mut writers: BTreeMap<(u64, u8), Writer> = BTreeMap::new();
    let mut boots: BTreeMap<u64, u8> = BTreeMap::new();
    let mut statuses_by_boot: BTreeMap<u8, status::StatusWriter> = BTreeMap::new();
    let mut status_boot = 0;
    let (mut reports, mut statuses) = (Reader::default(), StatusReader::default());
    let mut last: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let (mut inputs, mut refused) = (Vec::new(), Vec::new());
    for (at, step) in steps.iter().enumerate() {
        let at_us = START + at as u64 * STEP;
        let elapsed = at as u64 * STEP;
        let (source, accepted) = match step {
            Step::Report {
                host: number,
                state,
                entries,
            } => {
                let boot = *boots.get(number).unwrap_or(&(*number as u8));
                let writer = writers
                    .entry((*number, boot))
                    .or_insert_with(|| writer(host(*number), boot));
                let bytes = writer.seal(state, entries, at_us, elapsed).unwrap();
                last.insert(*number, bytes.clone());
                let accepted = reports.accept(&bytes, report_key);
                ("report", accepted.map(|report| view(&report)))
            }
            Step::Again { host } => {
                let accepted = reports.accept(&last[host], report_key);
                ("report", accepted.map(|report| view(&report)))
            }
            Step::Boot { host, boot } => {
                boots.insert(*host, *boot);
                continue;
            }
            Step::StatusBoot(boot) => {
                status_boot = *boot;
                continue;
            }
            Step::Status(parts) => {
                let status =
                    statuses_by_boot
                        .entry(status_boot)
                        .or_insert_with(|| match status_boot {
                            0 => status::tests::writer(),
                            boot => status::tests::writer_at([boot; 16]),
                        });
                let bytes = status.seal(parts, at_us, elapsed).unwrap();
                let accepted = statuses.accept(&bytes, status::tests::key_of);
                ("status", accepted.map(|s| status::tests::view(&s)))
            }
            Step::Tick => {
                inputs.push(Input::Tick { at_us });
                continue;
            }
        };
        match accepted {
            Ok(view) => inputs.push(Input::Record {
                at_us,
                source,
                view,
            }),
            Err(error) => refused.push(error),
        }
    }
    (inputs, refused)
}
