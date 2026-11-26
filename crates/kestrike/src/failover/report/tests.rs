use std::cell::Cell;
use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::*;
use crate::failover::assignment::{self, AssignmentError};
use crate::failover::evidence::{NotSole, Pair};
use crate::failover::records::{Ancestry, EventKind, RecordedPair, Suffix};
use crate::failover::serving::{Denial, ReportTrigger};
use crate::failover::sim::host;
use crate::net::owner_tenure_tests::{observe, serve_at, shard_at, token, volume_record};
use crate::net::put_tests::{Scene, scene};
use crate::storage::device::Operation;
use crate::storage::store::{Key as StoreKey, sim::Shared};
use crate::storage::store_tests::{OWNER, SPARE};

const KEY: [u8; 32] = [0xA5; 32];
const BOOT: [u8; 16] = [0x5A; 16];
const PERIOD: NonZeroU64 = NonZeroU64::new(1_000).unwrap();
/// The fixtures' seal time in wall-clock microseconds since the Unix epoch.
const SEALED: u64 = 1_750_000_000_000_000;
const WRITER_HOST: u64 = 0x0102_0304_0506_0708;
const CONTRACT: &str = include_str!("contract.json");

fn volume(name: &str) -> VolumeId {
    VolumeId::new(name).unwrap()
}

fn known(used: u64, limit: u64) -> Gauge {
    Gauge::Known {
        used,
        limit: NonZeroU64::new(limit).unwrap(),
    }
}

pub(crate) fn unavailable_headroom() -> Headroom {
    Headroom {
        ram: Gauge::Unavailable,
        cpu_load: Gauge::Unavailable,
        iops: Gauge::Unavailable,
        bandwidth: Gauge::Unavailable,
        attachments: Gauge::Unavailable,
        workers: Gauge::Unavailable,
        recovery: Gauge::Unavailable,
    }
}

fn unavailable_pressure() -> Pressure {
    Pressure {
        frontier: Gauge::Unavailable,
        ancestry: Gauge::Unavailable,
        quarantine: Gauge::Unavailable,
        full: Gauge::Unavailable,
    }
}

fn operation(byte: u8) -> ExitOperation {
    ExitOperation::new([byte; 16]).unwrap()
}

pub(crate) fn bare(name: &str, role: RecordedRole) -> VolumeEntry {
    VolumeEntry {
        volume: volume(name),
        shard: Shard::new(7).unwrap(),
        role: Some(role),
        tenure: None,
        volume_state: None,
        serving: None,
        withheld: false,
        quarantine: false,
        flip: false,
        withdrawal: None,
        refusal: None,
        enumeration: Enumeration::Unavailable,
        watermark: Watermark::Unavailable,
        report_age_us: None,
        own_records: None,
        checkpoint: None,
        checkpoint_age_us: None,
        captures: Captures {
            refused: None,
            abandoned: None,
        },
        exit: None,
        pressure: unavailable_pressure(),
        registrants: None,
        hold: None,
        readiness: None,
        metadata: None,
        load_refusal: None,
        recovery: Recovery::UNAVAILABLE,
        phase: None,
        ended: None,
        named: None,
        roll_due: None,
        roll_active: None,
        publication_due: None,
        times: RecoveryTimes::UNAVAILABLE,
        retention: None,
        suffix: Backlog::UNAVAILABLE,
        recovery_io: RecoveryIo::UNAVAILABLE,
        attaches: Gauge::Unavailable,
        store: StoreOutcomes::UNAVAILABLE,
        coverage: Coverage::UNAVAILABLE,
        invalidations: Gauge::Unavailable,
        read_defects: None,
        served: None,
    }
}

/// A host part with the given build and headroom whose health, detector, producer and recovery I/O fields read
/// unavailable.
pub(crate) fn unobserved(build: BuildIdentity, headroom: Headroom) -> HostState {
    HostState {
        build,
        headroom,
        health: None,
        detector: Detector::UNAVAILABLE,
        producer_missing: Members::Unavailable,
        recovery_io: Gauge::Unavailable,
    }
}

fn owner_serving() -> (HostState, Vec<VolumeEntry>) {
    let host = HostState {
        build: BuildIdentity {
            era: records::ERA,
            digest: Some([0x3C; 32]),
        },
        headroom: Headroom {
            ram: known(6 << 30, 16 << 30),
            cpu_load: known(150, 800),
            iops: known(12_000, 64_000),
            bandwidth: known(400 << 20, 1 << 30),
            attachments: known(3, 128),
            workers: known(2, 8),
            recovery: known(1, 2),
        },
        health: Some(Health::Unhealthy),
        detector: Detector {
            peers: Members::Known { used: 1, limit: 12 },
            self_suspect_us: Some(0),
            nominations: Some(2),
        },
        producer_missing: Members::Known { used: 0, limit: 1 },
        recovery_io: known(1 << 20, 128 << 20),
    };
    let entry = VolumeEntry {
        tenure: Some((
            ShardGeneration::new(3).unwrap(),
            ActivatedEpoch::new(4).unwrap(),
        )),
        volume_state: Some(VolumeState::Active),
        serving: Some(serving::State::Serving),
        withheld: false,
        quarantine: false,
        flip: false,
        withdrawal: None,
        refusal: Some(Refusal::ReportTimeout),
        enumeration: Enumeration::Matches,
        watermark: Watermark::Clear,
        report_age_us: Some(1_500),
        own_records: Some(1),
        checkpoint: Some(NamedCheckpoint {
            slot: 1,
            session: (3 << 32) | 4,
            capture: 9,
            units: 40,
        }),
        checkpoint_age_us: Some(600_000_000),
        captures: Captures {
            refused: Some(2),
            abandoned: Some(1),
        },
        exit: Some(Exit {
            operation: operation(0x77),
            status: ExitStatus::Received,
        }),
        pressure: Pressure {
            frontier: known(10, 64),
            ancestry: known(2, 4),
            quarantine: known(1, 32),
            full: known(1, 3),
        },
        registrants: Some(Registrants::Recorded),
        hold: Some(Hold::Clear),
        readiness: Some(Readiness::Live),
        metadata: Some(Metadata::Open),
        load_refusal: None,
        recovery: Recovery {
            kind: Some(RecoveryKind::Takeover),
            outcome: Some(RecoveryOutcome::Completed),
            attempts: Some(3),
            age_us: Some(900_000_000),
            ..Recovery::UNAVAILABLE
        },
        phase: Some(Phase::Serving),
        ended: Some(Ended::Rerun),
        named: Some(false),
        roll_due: Some(true),
        roll_active: Some(false),
        publication_due: Some(true),
        times: RecoveryTimes {
            loaded_us: Some(40_000),
            live_us: Some(90_000),
            first_hit_us: Some(95_000),
            retained_us: Some(90_000),
            fill_us: Some(120_000),
        },
        retention: Some(Retention {
            first_damage: Some(Damage::Chunk),
            installed: 37,
            omitted: 2,
            held_units: 40,
            failed_units: 1,
            unread_units: 0,
            suffix_damage: 0,
            suffix_tails: 4,
            suffix_dropped: 3,
            suffix_unread: 0,
            slot_superseded: 4,
            slot_withheld: 0,
        }),
        suffix: Backlog {
            blocks: known(2, 8),
            flush_lag_us: Some(750),
        },
        recovery_io: RecoveryIo {
            peak: known(1 << 20, 4 << 20),
            saturated: Some(1),
        },
        attaches: known(2, 3),
        store: StoreOutcomes {
            unknown: Some(1),
            unavailable: Some(4),
            refused: Some(3),
            log: Some(2),
        },
        coverage: Coverage {
            saturated: known(1, 16),
            largest: known(3_000, 4_096),
        },
        invalidations: known(5, 64),
        read_defects: Some(1),
        served: Some(12_345),
        ..bare("vol-0a", RecordedRole::Owner)
    };
    (host, vec![entry])
}

fn standby_unavailable() -> (HostState, Vec<VolumeEntry>) {
    let build = BuildIdentity {
        era: records::ERA,
        digest: None,
    };
    let host = unobserved(build, unavailable_headroom());
    let entry = VolumeEntry {
        enumeration: Enumeration::Matches,
        named: Some(false),
        ..bare("vol-0b", RecordedRole::Standby)
    };
    (host, vec![entry])
}

fn replacement_restarting() -> (HostState, Vec<VolumeEntry>) {
    let (host, _) = standby_unavailable();
    let entry = VolumeEntry {
        serving: Some(serving::State::Withdrawn),
        withdrawal: Some(Withdrawal::Flipped),
        enumeration: Enumeration::Duplicate,
        watermark: Watermark::Regression,
        exit: Some(Exit {
            operation: operation(0x42),
            status: ExitStatus::Restarting(Restart::Refused(Stale::Volume)),
        }),
        recovery: Recovery {
            kind: Some(RecoveryKind::Restart),
            outcome: Some(RecoveryOutcome::Refused),
            check: Some(RecoveryCheck::Unheld),
            next: Some(RecoveryNext::Hold),
            attempts: Some(1),
            age_us: Some(10),
            ..Recovery::UNAVAILABLE
        },
        phase: Some(Phase::Parked),
        ended: Some(Ended::Retire),
        named: Some(false),
        ..bare("vol-1c", RecordedRole::Replacement)
    };
    (host, vec![entry])
}

type Case = (&'static str, u64, (HostState, Vec<VolumeEntry>));

fn cases() -> [Case; 3] {
    [
        ("owner-serving", 5, owner_serving()),
        ("standby-unavailable", 1, standby_unavailable()),
        ("replacement-restarting", 9, replacement_restarting()),
    ]
}

/// A writer under the report key of `KEY` whose next report carries `next`.
fn fixed(host: Host, boot: [u8; 16], next: u64) -> Writer {
    let mut envelope = Envelope::new(WriterId { host, boot }, PERIOD);
    envelope.next = next;
    Writer {
        key: ReportKey::derive(&KEY),
        envelope,
    }
}

/// A writer of `host` under the report key of `host_key`, with the boot nonce `boot`.
pub(crate) fn writer_for(
    host: Host,
    host_key: &[u8; 32],
    boot: [u8; 16],
    period_us: core::num::NonZeroU64,
) -> Writer {
    Writer {
        key: ReportKey::derive(host_key),
        envelope: Envelope::new(WriterId { host, boot }, period_us),
    }
}

fn writer(next: u64) -> Writer {
    fixed(host(WRITER_HOST), BOOT, next)
}

fn sealed(next: u64, host: &HostState, entries: &[VolumeEntry]) -> Vec<u8> {
    writer(next).seal(host, entries, SEALED, 0).unwrap()
}

fn key_of(_: Host) -> Option<ReportKey> {
    Some(ReportKey::derive(&KEY))
}

/// The boots `reader` keeps for `host`, in their slots.
fn boots(reader: &Reader, host: Host) -> &[KeptBoot] {
    reader.seen.get(&host).map_or(&[], Vec::as_slice)
}

fn retagged(mut bytes: Vec<u8>) -> Vec<u8> {
    let body = bytes.len() - TAG_LEN;
    let tag = hmac(&ReportKey::derive(&KEY).0, &[DOMAIN, &bytes[..body]]);
    bytes[body..].copy_from_slice(&tag);
    bytes
}

/// The body `writer` encodes for `host` and `entries` at its next sequence, sealed at `sealed_at_us`.
fn body(writer: &Writer, host: &HostState, entries: &[VolumeEntry], sealed_at_us: u64) -> Vec<u8> {
    let slot = Slot {
        sequence: writer.envelope.next,
        sealed_at_us,
        next_due: 0,
    };
    writer.encode(host, entries, slot)
}

/// The body `report` encodes to.
fn encoded(report: &HostReport) -> Vec<u8> {
    let writer = fixed(report.writer.host, report.writer.boot, report.sequence);
    body(&writer, &report.host, &report.entries, report.sealed_at_us)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn role_label(role: RecordedRole) -> &'static str {
    match role {
        RecordedRole::Owner => "owner",
        RecordedRole::Standby => "standby",
        RecordedRole::Replacement => "replacement",
        RecordedRole::Unrecorded => "unrecorded",
    }
}

fn volume_state_label(state: VolumeState) -> &'static str {
    match state {
        VolumeState::Provisioning => "provisioning",
        VolumeState::Fresh => "fresh",
        VolumeState::Active => "active",
        VolumeState::Retired => "retired",
        VolumeState::Deleted => "deleted",
    }
}

fn serving_label(state: serving::State) -> &'static str {
    match state {
        serving::State::PreBoundary => "pre-boundary",
        serving::State::Recovering => "recovering",
        serving::State::Serving => "serving",
        serving::State::Withdrawn => "withdrawn",
        serving::State::Closed => "closed",
    }
}

fn withdrawal_label(cause: Withdrawal) -> &'static str {
    match cause {
        Withdrawal::Report => "report",
        Withdrawal::RecordedHolder => "recorded-holder",
        Withdrawal::Unheld => "unheld",
        Withdrawal::Conflict => "conflict",
        Withdrawal::PreemptAborted => "preempt-aborted",
        Withdrawal::ForceDetach => "force-detach",
        Withdrawal::Attachment => "attachment",
        Withdrawal::Modification => "modification",
        Withdrawal::RestartCheck => "restart-check",
        Withdrawal::ActivationRecord => "activation-record",
        Withdrawal::Exhausted => "exhausted",
        Withdrawal::Planned => "planned",
        Withdrawal::Flipped => "flipped",
        Withdrawal::NewerFence => "newer-fence",
        Withdrawal::LaterTenure => "later-tenure",
        Withdrawal::Regression => "regression",
        Withdrawal::Unverified => "unverified",
    }
}

fn refusal_label(cause: Refusal) -> &'static str {
    match cause {
        Refusal::Admission => "admission",
        Refusal::ReportMalformed => "report-malformed",
        Refusal::ReportTimeout => "report-timeout",
        Refusal::ForeignLower => "foreign-lower",
        Refusal::ForeignEqual => "foreign-equal",
        Refusal::ForeignHigher => "foreign-higher",
        Refusal::Conflict => "conflict",
        Refusal::PreemptAborted => "preempt-aborted",
        Refusal::OwnHostId => "own-host-id",
        Refusal::Clock => "clock",
        Refusal::Boundary => "boundary",
    }
}

fn enumeration_label(result: Enumeration) -> &'static str {
    match result {
        Enumeration::Unavailable => "unavailable",
        Enumeration::Matches => "matches",
        Enumeration::Missing => "missing",
        Enumeration::Foreign => "foreign",
        Enumeration::Duplicate => "duplicate",
        Enumeration::Unlisted => "unlisted",
    }
}

fn watermark_label(alarm: Watermark) -> &'static str {
    match alarm {
        Watermark::Unavailable => "unavailable",
        Watermark::Clear => "clear",
        Watermark::Regression => "regression",
        Watermark::Log => "log",
        Watermark::Checkpoint => "checkpoint",
        Watermark::Namespace => "namespace",
    }
}

fn exit_label(status: ExitStatus) -> &'static str {
    match status {
        ExitStatus::Received => "received",
        ExitStatus::Draining => "draining",
        ExitStatus::Withdrawn => "withdrawn",
        ExitStatus::Waiting => "waiting",
        ExitStatus::Exited => "exited",
        ExitStatus::Resumed(Resume::Deadline) => "resumed-deadline",
        ExitStatus::Resumed(Resume::Cut) => "resumed-cut",
        ExitStatus::Resumed(Resume::Standby) => "resumed-standby",
        ExitStatus::Resumed(Resume::Store) => "resumed-store",
        ExitStatus::Restarting(Restart::Deadline) => "restarting-deadline",
        ExitStatus::Restarting(Restart::Refused(Stale::Target)) => "restarting-refused-target",
        ExitStatus::Restarting(Restart::Refused(Stale::Volume)) => "restarting-refused-volume",
        ExitStatus::Restarting(Restart::Planned) => "restarting-planned",
        ExitStatus::Restarting(Restart::TransferRefused) => "restarting-transfer-refused",
        ExitStatus::Restarting(Restart::TransferUnknown) => "restarting-transfer-unknown",
    }
}

/// The report and status contracts use each fieldless variant's kebab-case name as its label.
pub(crate) fn kebab(value: impl core::fmt::Debug) -> String {
    let name = format!("{value:?}");
    let mut label = String::new();
    for (at, c) in name.char_indices() {
        if c.is_ascii_uppercase() && at > 0 {
            label.push('-');
        }
        label.push(c.to_ascii_lowercase());
    }
    label
}

fn members(members: Members) -> Value {
    match members {
        Members::Unavailable => json!("unavailable"),
        Members::Known { used, limit } => json!({ "used": used, "limit": limit }),
    }
}

fn gauge(gauge: Gauge) -> Value {
    match gauge {
        Gauge::Unavailable => json!("unavailable"),
        Gauge::Known { used, limit } => json!({ "used": used, "limit": limit.get() }),
    }
}

fn entry_view(e: &VolumeEntry) -> Value {
    let authority = json!({
        "volume": e.volume.as_str(),
        "shard": e.shard.get(),
        "role": e.role.map(role_label),
        "tenure": e.tenure.map(|(g, a)| json!({ "g": g.get(), "a": a.get() })),
        "volume_state": e.volume_state.map(volume_state_label),
        "serving": e.serving.map(serving_label),
        "withheld": e.withheld,
        "quarantine": e.quarantine,
        "flip": e.flip,
        "withdrawal": e.withdrawal.map(withdrawal_label),
        "refusal": e.refusal.map(refusal_label),
        "enumeration": enumeration_label(e.enumeration),
        "watermark": watermark_label(e.watermark),
        "report_age_us": e.report_age_us,
        "own_records": e.own_records,
        "checkpoint": e.checkpoint.map(|ck| json!({
            "slot": ck.slot, "session": ck.session, "capture": ck.capture, "units": ck.units,
        })),
        "checkpoint_age_us": e.checkpoint_age_us,
        "captures": { "refused": e.captures.refused, "abandoned": e.captures.abandoned },
        "exit": e.exit.map(|exit| json!({
            "operation": hex(&exit.operation.bytes()),
            "status": exit_label(exit.status),
        })),
        "pressure": {
            "frontier": gauge(e.pressure.frontier),
            "ancestry": gauge(e.pressure.ancestry),
            "quarantine": gauge(e.pressure.quarantine),
            "full": gauge(e.pressure.full),
        },
    });
    let r = e.recovery;
    let t = e.times;
    let recovery = json!({
        "registrants": e.registrants.map(kebab),
        "hold": e.hold.map(kebab),
        "readiness": e.readiness.map(kebab),
        "metadata": e.metadata.map(kebab),
        "load_refusal": e.load_refusal.map(kebab),
        "recovery": {
            "kind": r.kind.map(kebab), "outcome": r.outcome.map(kebab), "check": r.check.map(kebab),
            "next": r.next.map(kebab), "store": r.store.map(kebab), "attempts": r.attempts, "age_us": r.age_us,
        },
        "phase": e.phase.map(kebab),
        "ended": e.ended.map(kebab),
        "named": e.named,
        "roll_due": e.roll_due,
        "roll_active": e.roll_active,
        "publication_due": e.publication_due,
        "times": {
            "loaded_us": t.loaded_us, "live_us": t.live_us, "first_hit_us": t.first_hit_us,
            "retained_us": t.retained_us, "fill_us": t.fill_us,
        },
    });
    let retention = e.retention.map(|k| {
        json!({
            "first_damage": k.first_damage.map(kebab), "installed": k.installed, "omitted": k.omitted,
            "held_units": k.held_units, "failed_units": k.failed_units, "unread_units": k.unread_units,
            "suffix_damage": k.suffix_damage, "suffix_tails": k.suffix_tails,
            "suffix_dropped": k.suffix_dropped, "suffix_unread": k.suffix_unread,
            "slot_superseded": k.slot_superseded, "slot_withheld": k.slot_withheld,
        })
    });
    let s = e.store;
    let counts = json!({
        "retention": retention,
        "suffix": { "blocks": gauge(e.suffix.blocks), "flush_lag_us": e.suffix.flush_lag_us },
        "recovery_io": { "peak": gauge(e.recovery_io.peak), "saturated": e.recovery_io.saturated },
        "attaches": gauge(e.attaches),
        "store": {
            "unknown": s.unknown, "unavailable": s.unavailable, "refused": s.refused, "log": s.log,
        },
        "coverage": { "saturated": gauge(e.coverage.saturated), "largest": gauge(e.coverage.largest) },
        "invalidations": gauge(e.invalidations),
        "read_defects": e.read_defects,
        "served": e.served,
    });
    let mut view = authority;
    for part in [recovery, counts] {
        let Value::Object(part) = part else {
            unreachable!("each part is an object")
        };
        view.as_object_mut().unwrap().extend(part);
    }
    view
}

pub(crate) fn view(report: &HostReport) -> Value {
    let (h, d) = (report.host.headroom, report.host.detector);
    json!({
        "schema": SCHEMA,
        "writer": { "host": report.writer.host.get(), "boot": hex(&report.writer.boot) },
        "sequence": report.sequence,
        "sealed_at_us": report.sealed_at_us,
        "build": {
            "era": report.host.build.era,
            "digest": report.host.build.digest.map(|digest| hex(&digest)),
        },
        "headroom": {
            "ram": gauge(h.ram), "cpu_load": gauge(h.cpu_load), "iops": gauge(h.iops),
            "bandwidth": gauge(h.bandwidth), "attachments": gauge(h.attachments),
            "workers": gauge(h.workers), "recovery": gauge(h.recovery),
        },
        "health": report.host.health.map(kebab),
        "detector": {
            "peers": members(d.peers), "self_suspect_us": d.self_suspect_us, "nominations": d.nominations,
        },
        "producer": { "missing": members(report.host.producer_missing) },
        "recovery_io": gauge(report.host.recovery_io),
        "entries": report.entries.iter().map(entry_view).collect::<Vec<_>>(),
    })
}

pub(crate) fn paths(value: &Value, prefix: &str, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                paths(value, &path, out);
                out.insert(path);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| paths(item, prefix, out)),
        _ => {}
    }
}

/// The paths of `value` whose value is null.
fn nulls(value: &Value, prefix: &str, out: &mut BTreeSet<String>) {
    match value {
        Value::Null => {
            out.insert(prefix.to_owned());
        }
        Value::Object(map) => {
            for (key, value) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                nulls(value, &path, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| nulls(item, prefix, out)),
        _ => {}
    }
}

fn contract() -> Value {
    serde_json::from_str(CONTRACT).unwrap()
}

/// Each label field of the contract with the offset of its byte in a report of one entry: the host part's health
/// label, then the labels of the entry.
const LABEL_BYTES: [(&str, usize); 22] = [
    ("health", HEALTH_AT),
    ("role", ENTRY + 26),
    ("volume_state", ENTRY + 35),
    ("serving", ENTRY + 36),
    ("withdrawal", ENTRY + 38),
    ("refusal", ENTRY + 39),
    ("enumeration", ENTRY + 40),
    ("watermark", ENTRY + 41),
    ("exit", ENTRY + 104),
    ("registrants", ENTRY + 189),
    ("hold", ENTRY + 190),
    ("readiness", ENTRY + 191),
    ("metadata", ENTRY + 192),
    ("load_refusal", ENTRY + 193),
    ("recovery.kind", ENTRY + 194),
    ("recovery.outcome", ENTRY + 195),
    ("recovery.check", ENTRY + 196),
    ("recovery.next", ENTRY + 197),
    ("recovery.store", ENTRY + 198),
    ("phase", ENTRY + 199),
    ("ended", ENTRY + 200),
    ("retention.first_damage", ENTRY + 262),
];

fn label_offset(field: &str) -> usize {
    let listed = LABEL_BYTES.iter().find(|(name, _)| *name == field);
    listed
        .map(|&(_, at)| at)
        .unwrap_or_else(|| panic!("no label {field}"))
}

fn label_of(report: &HostReport, field: &str) -> Option<String> {
    let e = &report.entries[0];
    let r = e.recovery;
    match field {
        "health" => report.host.health.map(kebab),
        "role" => e.role.map(role_label).map(str::to_owned),
        "volume_state" => e.volume_state.map(volume_state_label).map(str::to_owned),
        "serving" => e.serving.map(serving_label).map(str::to_owned),
        "withdrawal" => e.withdrawal.map(withdrawal_label).map(str::to_owned),
        "refusal" => e.refusal.map(refusal_label).map(str::to_owned),
        "enumeration" => Some(enumeration_label(e.enumeration).to_owned()),
        "watermark" => Some(watermark_label(e.watermark).to_owned()),
        "exit" => e.exit.map(|exit| exit_label(exit.status).to_owned()),
        "registrants" => e.registrants.map(kebab),
        "hold" => e.hold.map(kebab),
        "readiness" => e.readiness.map(kebab),
        "metadata" => e.metadata.map(kebab),
        "load_refusal" => e.load_refusal.map(kebab),
        "recovery.kind" => r.kind.map(kebab),
        "recovery.outcome" => r.outcome.map(kebab),
        "recovery.check" => r.check.map(kebab),
        "recovery.next" => r.next.map(kebab),
        "recovery.store" => r.store.map(kebab),
        "phase" => e.phase.map(kebab),
        "ended" => e.ended.map(kebab),
        "retention.first_damage" => e.retention.and_then(|k| k.first_damage).map(kebab),
        other => panic!("no label {other}"),
    }
}

/// Every label byte of the owner-serving fixture decodes to the label at its position in the contract's list,
/// offset by the contract's first code, code 0 naming an absent value for a table whose first code is 1, and every
/// other byte refuses with `Flag`.
fn assert_labels_match(contract: &Value) {
    let base = unhex(
        contract["cases"]["owner-serving"]["bytes"]
            .as_str()
            .unwrap(),
    );
    for (field, labels) in contract["labels"].as_object().unwrap() {
        let labels: Vec<&str> = labels
            .as_array()
            .unwrap()
            .iter()
            .map(|label| label.as_str().unwrap())
            .collect();
        let first = contract["label_first_code"][field].as_u64().unwrap() as usize;
        for code in 0..=255u8 {
            let mut bytes = base.clone();
            bytes[label_offset(field)] = code;
            if field == "exit" && code == 0 {
                bytes[label_offset(field) + 1..][..16].fill(0);
            }
            if field == "serving" && code == 0 {
                bytes[label_offset(field) + 1] = 0;
            }
            if field == "recovery.kind" && code == 0 {
                // The outcome, the three refusal labels and the age need a kind; the attempt count does not.
                bytes[ENTRY + 195..ENTRY + 199].fill(0);
                bytes[ENTRY + 207..ENTRY + 216].fill(0);
            }
            if ["recovery.check", "recovery.next", "recovery.store"].contains(&field.as_str()) {
                // A check, a next step and a store class need a refused or unavailable outcome.
                bytes[ENTRY + 195] = 3;
            }
            if field == "recovery.store" {
                // A store class names the error its refusing check carries.
                bytes[ENTRY + 196] = 24;
            }
            if field == "retention.first_damage" && [0, 5].contains(&code) {
                // No damage reads no failed or unread unit, and an unread first damage reads unread units alone.
                bytes[ENTRY + 287..ENTRY + 295].fill(0);
                bytes[ENTRY + 294] = u8::from(code == 5);
            }
            let decoded = Reader::default().accept(&retagged(bytes), key_of);
            let listed = usize::from(code)
                .checked_sub(first)
                .and_then(|at| labels.get(at).copied());
            match (decoded, listed) {
                (Ok(report), Some(label)) => {
                    assert_eq!(
                        label_of(&report, field).as_deref(),
                        Some(label),
                        "{field} {code}"
                    )
                }
                (Ok(report), None) if code == 0 => assert_eq!(label_of(&report, field), None),
                (Err(ReportError::Flag), None) if code != 0 => {}
                (result, listed) => panic!("{field} {code}: {result:?} against {listed:?}"),
            }
        }
    }
}

/// The count fields of the contract and the reset identity their field documentation gives each: the writer boot for
/// the sequence, the detector's nominations and the recovery attempts, and the tenure for the other entry counts.
const COUNTS: [(&str, &str); 13] = [
    ("sequence", "writer.boot"),
    ("detector.nominations", "writer.boot"),
    ("entries.recovery.attempts", "writer.boot"),
    ("entries.captures.refused", "tenure"),
    ("entries.captures.abandoned", "tenure"),
    ("entries.retention", "tenure"),
    ("entries.recovery_io.saturated", "tenure"),
    ("entries.store.unknown", "tenure"),
    ("entries.store.unavailable", "tenure"),
    ("entries.store.refused", "tenure"),
    ("entries.store.log", "tenure"),
    ("entries.read_defects", "tenure"),
    ("entries.served", "tenure"),
];

/// `base` with each value of each recovery-part table in turn.
fn recovery_labelled(base: VolumeEntry) -> Vec<VolumeEntry> {
    let r = base.recovery;
    let refused = Recovery {
        outcome: Some(RecoveryOutcome::Refused),
        ..r
    };
    let with = |recovery| VolumeEntry { recovery, ..base };
    let retention = base.retention.unwrap();
    let account = |first_damage: Option<Damage>| match first_damage {
        None => Retention {
            failed_units: 0,
            unread_units: 0,
            ..retention
        },
        Some(Damage::Unread) => Retention {
            failed_units: 0,
            unread_units: 1,
            ..retention
        },
        Some(_) => retention,
    };
    let mut out: Vec<VolumeEntry> = Vec::new();
    out.extend(REGISTRANTS.iter().map(|&v| VolumeEntry {
        registrants: Some(v),
        ..base
    }));
    out.extend(HOLDS.iter().map(|&v| VolumeEntry {
        hold: Some(v),
        ..base
    }));
    out.extend(READINESS.iter().map(|&v| VolumeEntry {
        readiness: Some(v),
        ..base
    }));
    out.extend(METADATA.iter().map(|&v| VolumeEntry {
        metadata: Some(v),
        ..base
    }));
    out.extend(LOAD_REFUSALS.iter().map(|&v| VolumeEntry {
        load_refusal: Some(v),
        ..base
    }));
    out.extend(KINDS.iter().map(|&v| with(Recovery { kind: Some(v), ..r })));
    out.extend(OUTCOMES.iter().map(|&v| {
        with(Recovery {
            outcome: Some(v),
            ..r
        })
    }));
    out.extend(CHECKS.iter().map(|&v| {
        with(Recovery {
            check: Some(v),
            ..refused
        })
    }));
    out.extend(NEXTS.iter().map(|&v| {
        with(Recovery {
            next: Some(v),
            ..refused
        })
    }));
    out.extend(STORE_CLASSES.iter().map(|&v| {
        with(Recovery {
            check: Some(RecoveryCheck::TakeOver),
            store: Some(v),
            ..refused
        })
    }));
    out.extend(PHASES.iter().map(|&v| VolumeEntry {
        phase: Some(v),
        ..base
    }));
    out.extend(ENDINGS.iter().map(|&v| VolumeEntry {
        ended: Some(v),
        ..base
    }));
    out.extend(
        DAMAGES
            .iter()
            .map(|&v| Some(v))
            .chain([None])
            .map(|first_damage| VolumeEntry {
                retention: Some(Retention {
                    first_damage,
                    ..account(first_damage)
                }),
                ..base
            }),
    );
    out
}

/// The value the bytes of wire-table `row` read in `scope`, a case's report view or one of its entry views, checked
/// against the view: a row under a null field holds zero bytes, and every other row reads the view's value at its
/// field by the row's encoding.
fn assert_wire_row(contract: &Value, row: &Value, bytes: &[u8], scope: &Value, entries: usize) {
    let field = row["field"].as_str().unwrap();
    let encoding = row["encoding"].as_str().unwrap();
    let width = match encoding {
        "u8" | "count" | "zero" | "label" | "flags" | "known_flags" | "presence" => Some(1),
        "u16" => Some(2),
        "u32" | "magic" => Some(4),
        "u64" => Some(8),
        "flagged_u32" => Some(5),
        "flagged_u64" => Some(9),
        "gauge" | "members" => Some(GAUGE),
        "hmac" => Some(TAG_LEN),
        _ => None,
    };
    assert!(
        width.is_none_or(|width| width == bytes.len()),
        "{field}: {encoding} is {width:?} bytes"
    );
    let at = |path: &str| {
        let path = path.strip_prefix("entries.").unwrap_or(path);
        path.split('.').try_fold(scope, |value, key| value.get(key))
    };
    let parent = field.rsplit_once('.').map(|(parent, _)| parent);
    if parent.is_some_and(|parent| at(parent) == Some(&Value::Null)) {
        assert!(
            bytes.iter().all(|&byte| byte == 0),
            "{field} under a null field"
        );
        return;
    }
    let be = |bytes: &[u8]| bytes.iter().fold(0u64, |n, &byte| n << 8 | u64::from(byte));
    let flagged = |value: Value| match bytes[0] {
        0 if bytes[1..].iter().all(|&byte| byte == 0) => Value::Null,
        1 => value,
        flag => panic!("{field}: flag byte {flag}"),
    };
    let bits = || {
        row["bits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|bit| bit.as_str().unwrap())
    };
    let got = match encoding {
        "magic" => return assert_eq!(bytes, MAGIC),
        "zero" => return assert_eq!(bytes, [0]),
        "count" => return assert_eq!(usize::from(bytes[0]), entries),
        "presence" => {
            return assert_eq!(
                bytes,
                [u8::from(at(field) != Some(&Value::Null))],
                "{field}"
            );
        }
        "flags" => {
            let count = bits().count();
            assert_eq!(bytes[0] >> count, 0, "{field}");
            for (bit, name) in bits().enumerate() {
                assert_eq!(at(name), Some(&json!(bytes[0] >> bit & 1 == 1)), "{name}");
            }
            return;
        }
        "known_flags" => {
            for (bit, name) in bits().enumerate() {
                let value = (bytes[0] >> (bit + 4) & 1 == 1).then_some(bytes[0] >> bit & 1 == 1);
                assert_eq!(at(name), Some(&json!(value)), "{name}");
            }
            return;
        }
        "u16" | "u32" | "u64" => json!(be(bytes)),
        "hex" => json!(hex(bytes)),
        "volume" => {
            let len = usize::from(bytes[0]);
            assert!(bytes[1 + len..].iter().all(|&byte| byte == 0), "{field}");
            json!(std::str::from_utf8(&bytes[1..1 + len]).unwrap())
        }
        "label" => {
            let table = row["table"].as_str().unwrap();
            let first = contract["label_first_code"][table].as_u64().unwrap() as usize;
            let code = usize::from(bytes[0]);
            match code.checked_sub(first) {
                None => Value::Null,
                Some(at) => contract["labels"][table][at].clone(),
            }
        }
        "flagged_u32" | "flagged_u64" => flagged(json!(be(&bytes[1..]))),
        "flagged_hex" => flagged(json!(hex(&bytes[1..]))),
        "gauge" | "members" => match bytes[0] {
            0 => json!("unavailable"),
            _ => json!({ "used": be(&bytes[1..9]), "limit": be(&bytes[9..]) }),
        },
        other => panic!("{field}: no encoding {other}"),
    };
    assert_eq!(at(field), Some(&got), "{field}");
}

/// The decoder refuses a volume field whose length byte counts the digits alone, so the contract's identity rule
/// must give the length with `vol-` included.
fn assert_volume_rule(contract: &Value) {
    let rule = contract["unavailable"]["identities"].as_str().unwrap();
    let admitted: Vec<(usize, [u8; VOLUME])> = (0..VOLUME)
        .filter_map(|digits| {
            let name = format!("vol-{}", "a".repeat(digits));
            VolumeId::new(&name).map(|volume| (digits, volume.field()))
        })
        .collect();
    for &(digits, field) in &admitted {
        assert_eq!(usize::from(field[0]), "vol-".len() + digits);
        let mut counted = field;
        counted[0] = digits as u8;
        assert!(
            VolumeId::from_field(&counted).is_none(),
            "a length byte of {digits} for {digits} digits"
        );
    }
    let (fewest, shortest) = admitted.first().map(|(n, field)| (*n, field[0])).unwrap();
    let (most, longest) = admitted.last().map(|(n, field)| (*n, field[0])).unwrap();
    assert_eq!(admitted.len(), most - fewest + 1);
    for text in [
        format!("vol- followed by {fewest} to {most} lowercase hexadecimal digits"),
        format!(
            "its length byte giving the identifier's length with vol- included, {shortest} to {longest},"
        ),
    ] {
        assert!(rule.contains(&text), "the identity rule states: {text}");
    }
}

/// The contract's wire table: its rows tile the header, the host part, an entry and the tag, each leaf of the
/// contract's fields is a row, a bit of a flags row or a part of a gauge row, and each case's bytes at every row read
/// the case view's value at that row's field, with the tag the HMAC of the body under the fixture's report key.
fn assert_wire_table(contract: &Value) {
    let wire = &contract["wire"];
    let rows = |part: &str| wire[part].as_array().unwrap().clone();
    let width = |part: &str| -> usize {
        rows(part)
            .iter()
            .map(|row| row["bytes"].as_u64().unwrap() as usize)
            .sum()
    };
    for (part, len) in [
        ("header", HEADER_LEN),
        ("host", HOST_LEN),
        ("entry", ENTRY_LEN),
        ("tag", TAG_LEN),
    ] {
        assert_eq!(width(part), len, "the {part} rows tile the {part}");
    }
    let mut named = BTreeSet::new();
    for row in ["header", "host", "entry"].into_iter().flat_map(rows) {
        named.insert(row["field"].as_str().unwrap().to_owned());
        for bit in row["bits"].as_array().into_iter().flatten() {
            named.insert(bit.as_str().unwrap().to_owned());
        }
    }
    for field in contract["fields"].as_array().unwrap() {
        let field = field.as_str().unwrap();
        let gauge_part = field.rsplit_once('.').is_some_and(|(parent, leaf)| {
            matches!(leaf, "used" | "limit") && named.contains(parent)
        });
        let group = named
            .iter()
            .any(|row| row.starts_with(&format!("{field}.")));
        assert!(
            named.contains(field) || gauge_part || group,
            "{field} has no row"
        );
    }
    assert_eq!(
        rows("tag"),
        [json!({ "field": "tag", "bytes": TAG_LEN, "encoding": "hmac" })]
    );
    for (name, case) in contract["cases"].as_object().unwrap() {
        let bytes = unhex(case["bytes"].as_str().unwrap());
        assert_wire_report(contract, &bytes, &case["report"], name);
    }
}

/// The sealed report `bytes` read, through the contract's wire table, the values its view `view` holds at every row,
/// and its tag is the HMAC of its body under the fixture's report key.
fn assert_wire_report(contract: &Value, bytes: &[u8], view: &Value, name: &str) {
    let rows = |part: &str| contract["wire"][part].as_array().unwrap().clone();
    let count = view["entries"].as_array().unwrap().len();
    let mut at = 0;
    let mut read = |part: &str, scope: &Value| {
        for row in rows(part) {
            let len = row["bytes"].as_u64().unwrap() as usize;
            assert_wire_row(contract, &row, &bytes[at..at + len], scope, count);
            at += len;
        }
    };
    read("header", view);
    read("host", view);
    for entry in view["entries"].as_array().unwrap() {
        read("entry", entry);
    }
    assert_eq!(at + TAG_LEN, bytes.len(), "{name}");
    let tag = hmac(&ReportKey::derive(&KEY).0, &[DOMAIN, &bytes[..at]]);
    assert_eq!(tag, bytes[at..], "{name}'s tag");
}

/// An entry whose rows of one encoding hold distinct values: a refused takeover carrying its check, next step and
/// store class, a known `live_us` with no retained time, and distinct counts, gauges and unit counts.
fn distinct() -> VolumeEntry {
    let base = owner_serving().1[0];
    VolumeEntry {
        checkpoint_age_us: Some(600_000_000),
        captures: Captures {
            refused: Some(2),
            abandoned: Some(1),
        },
        recovery: Recovery {
            outcome: Some(RecoveryOutcome::Refused),
            check: Some(RecoveryCheck::TakeOver),
            next: Some(RecoveryNext::Restart),
            store: Some(StoreClass::Unknown),
            ..base.recovery
        },
        times: RecoveryTimes {
            retained_us: None,
            ..base.times
        },
        retention: Some(Retention {
            failed_units: 8,
            unread_units: 2,
            suffix_damage: 5,
            suffix_tails: 6,
            suffix_unread: 5,
            slot_withheld: 6,
            ..base.retention.unwrap()
        }),
        recovery_io: RecoveryIo {
            saturated: Some(7),
            ..base.recovery_io
        },
        store: StoreOutcomes {
            unknown: Some(11),
            unavailable: Some(4),
            refused: Some(3),
            log: Some(9),
        },
        read_defects: Some(13),
        ..base
    }
}

/// CLOSED-LABELS, NO-KEY-MATERIAL and NO-INVENTED-VALUES at the operator contract: each fixture decodes to its Rust
/// value and view and reseals to its bytes, the full case carries every listed field and the contract pins a unit
/// for each, every label byte decodes exactly to the contract's labels, each owner cause converts to its own
/// label, the owner's producer fills each field from its source or marks it unavailable, ages the checkpoint from
/// the first read naming it and derives each recorded role from the last shard and own-volume records, and the
/// headroom sampler reads RAM and the load average from procfs and leaves the other gauges unavailable.
#[test]
fn fields_and_fixtures() {
    let contract = contract();
    let nullable = contract["nullable"].as_array().unwrap();
    assert_eq!(contract["schema"], json!(SCHEMA));
    let layout = &contract["layout"];
    for (name, value) in [
        ("header", HEADER_LEN),
        ("host", HOST_LEN),
        ("entry", ENTRY_LEN),
        ("entry_authority", AUTHORITY_LEN),
        ("entry_recovery", RECOVERY_LEN),
        ("tag", TAG_LEN),
        ("max_entries", MAX_ENTRIES),
        ("max_len", MAX_LEN),
    ] {
        assert_eq!(
            layout[name],
            json!(value),
            "the contract pins the {name} length"
        );
    }
    assert_eq!(contract["key"].as_str().unwrap(), hex(&KEY));
    assert_eq!(
        contract["report_key"].as_str().unwrap(),
        hex(&ReportKey::derive(&KEY).0)
    );
    for (name, next, (host, entries)) in cases() {
        let case = &contract["cases"][name];
        let bytes = unhex(case["bytes"].as_str().unwrap());
        let report = Reader::default().accept(&bytes, key_of).unwrap();
        let expected = HostReport {
            writer: writer(next).envelope.id,
            sequence: next,
            sealed_at_us: SEALED,
            host,
            entries: entries.clone(),
        };
        assert_eq!(report, expected, "{name} decodes to its value");
        assert_eq!(view(&report), case["report"], "{name}'s view");
        assert_eq!(sealed(next, &host, &entries), bytes, "{name} reseals");
        let body = &bytes[..bytes.len() - TAG_LEN];
        let report_key = ReportKey::derive(&KEY).0;
        assert!(
            !body
                .windows(32)
                .any(|window| window == KEY || window == report_key)
        );
        let mut null = BTreeSet::new();
        nulls(&case["report"], "", &mut null);
        for path in null {
            assert!(
                nullable.contains(&json!(path)),
                "{name}: {path} is not nullable"
            );
        }
    }
    let mut fields = BTreeSet::new();
    paths(
        &contract["cases"]["owner-serving"]["report"],
        "",
        &mut fields,
    );
    let listed: BTreeSet<String> = contract["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(fields, listed);
    let units = contract["units"].as_object().unwrap();
    for field in &fields {
        let mut prefixes = std::iter::successors(Some(field.as_str()), |path| {
            path.rsplit_once('.').map(|(parent, _)| parent)
        });
        let leaf = !fields
            .iter()
            .any(|other| other.starts_with(&format!("{field}.")));
        assert!(
            !leaf || prefixes.any(|path| units.contains_key(path)),
            "{field} has no unit"
        );
    }
    assert!(units.keys().all(|path| fields.contains(path)));
    let resets = contract["resets"].as_object().unwrap();
    let counted: BTreeSet<&str> = resets.keys().map(String::as_str).collect();
    assert_eq!(counted, COUNTS.map(|(field, _)| field).into());
    for (field, identity) in COUNTS {
        assert!(fields.contains(field), "{field}");
        assert_eq!(resets[field], json!(identity), "{field}'s reset identity");
        let rule = &contract["reset_identities"][identity];
        assert!(rule["rule"].is_string(), "{identity}");
        let key = rule["key"].as_array().unwrap();
        let pinned = match identity {
            "tenure" => json!(["entries.shard", "entries.tenure.g", "entries.tenure.a"]),
            _ => json!(["writer.host", "writer.boot"]),
        };
        assert_eq!(rule["key"], pinned, "{identity}'s key");
        for path in key {
            assert!(
                fields.contains(path.as_str().unwrap()),
                "{identity}: {path}"
            );
        }
    }
    // Two shards may each activate a tenure `(g, a)`, so the tenure identity's key tells their entries apart.
    let tenure_key = |entry: &VolumeEntry| -> Vec<Value> {
        let key = contract["reset_identities"]["tenure"]["key"]
            .as_array()
            .unwrap();
        key.iter()
            .map(|path| {
                let path = path.as_str().unwrap().strip_prefix("entries.").unwrap();
                path.split('.')
                    .fold(entry_view(entry), |value, name| value[name].clone())
            })
            .collect()
    };
    let entry = owner_serving().1[0];
    let neighbour = VolumeEntry {
        shard: Shard::new(entry.shard.get() + 1).unwrap(),
        ..entry
    };
    assert!(entry.tenure.is_some() && entry.tenure == neighbour.tenure);
    assert_ne!(tenure_key(&entry), tenure_key(&neighbour));
    for listing in ["labels", "label_first_code"] {
        let tables: BTreeSet<&str> = contract[listing]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let fields: BTreeSet<&str> = LABEL_BYTES.iter().map(|&(name, _)| name).collect();
        assert_eq!(tables, fields, "the contract's {listing}");
    }
    assert_wire_table(&contract);
    assert_volume_rule(&contract);
    assert!(!contract["omitted"].as_array().unwrap().is_empty());
    assert!(
        nullable
            .iter()
            .all(|path| fields.contains(path.as_str().unwrap()))
    );
    let debug = format!("{:?}", writer(1));
    for key in [KEY, ReportKey::derive(&KEY).0] {
        let prefix = format!("{:?}", &key[..3]);
        assert!(!debug.contains(&prefix[1..prefix.len() - 1]), "{debug}");
    }
    assert!(!debug.contains("key"));
    assert_labels_match(&contract);
    let (state, entries) = owner_serving();
    let base = entries[0];
    let labelled = STATES
        .iter()
        .map(|&v| VolumeEntry {
            volume_state: Some(v),
            ..base
        })
        .chain(SERVING.iter().map(|&v| VolumeEntry {
            serving: Some(v),
            ..base
        }))
        .chain(EXITS.iter().map(|&status| VolumeEntry {
            exit: Some(Exit {
                operation: operation(0x31),
                status,
            }),
            ..base
        }))
        .chain(ROLES.iter().map(|&v| VolumeEntry {
            role: Some(v),
            ..base
        }))
        .chain(WITHDRAWALS.iter().map(|&v| VolumeEntry {
            withdrawal: Some(v),
            ..base
        }))
        .chain(REFUSALS.iter().map(|&v| VolumeEntry {
            refusal: Some(v),
            ..base
        }))
        .chain(ENUMERATIONS.iter().map(|&v| VolumeEntry {
            enumeration: v,
            ..base
        }))
        .chain(WATERMARKS.iter().map(|&v| VolumeEntry {
            watermark: v,
            ..base
        }))
        .chain(recovery_labelled(base));
    // Every table value and the distinct entries read through the wire table from the bytes the codec seals.
    let probes = [
        distinct(),
        VolumeEntry {
            retention: None,
            ..distinct()
        },
    ];
    for entry in labelled.chain(probes) {
        let bytes = sealed(1, &state, &[entry]);
        let report = Reader::default().accept(&bytes, key_of).unwrap();
        assert_wire_report(&contract, &bytes, &view(&report), "a table value");
        let got = report.entries;
        assert_eq!(got, [entry], "every table value decodes to itself");
        assert_eq!(
            entry.encode().and_then(|bytes| VolumeEntry::decode(&bytes)),
            Ok(entry)
        );
    }
    for health in HEALTH.iter().copied().map(Some).chain([None]) {
        let host = HostState { health, ..state };
        let bytes = sealed(1, &host, &entries);
        assert_eq!(Reader::default().accept(&bytes, key_of).unwrap().host, host);
    }
    for (withheld, quarantine, flip, byte) in [
        (true, false, false, 1u8),
        (false, true, false, 2),
        (false, false, true, 4),
    ] {
        let entry = VolumeEntry {
            withheld,
            quarantine,
            flip,
            ..entries[0]
        };
        let bytes = sealed(1, &state, &[entry]);
        assert_eq!(bytes[ENTRY + 37], byte, "each flag owns its bit");
        let report = Reader::default().accept(&bytes, key_of).unwrap();
        assert_wire_report(&contract, &bytes, &view(&report), "a first-byte flag");
        let got = report.entries[0];
        assert_eq!(
            (got.withheld, got.quarantine, got.flip),
            (withheld, quarantine, flip)
        );
    }
    let causes = [
        (
            Cause::Report(ReportTrigger::new(NotSole::Excess).unwrap()),
            "report",
        ),
        (Cause::RecordedHolder, "recorded-holder"),
        (Cause::Unheld, "unheld"),
        (Cause::Unverified, "unverified"),
        (Cause::Status(Deposing::Conflict), "conflict"),
        (Cause::Status(Deposing::PreemptAborted), "preempt-aborted"),
        (Cause::ForceDetach, "force-detach"),
        (Cause::Attachment, "attachment"),
        (Cause::Modification, "modification"),
        (Cause::RestartCheck, "restart-check"),
        (Cause::ActivationRecord, "activation-record"),
        (Cause::Exhausted, "exhausted"),
        (Cause::Planned, "planned"),
        (Cause::Flipped, "flipped"),
        (Cause::NewerFence { page: 3, fence: 9 }, "newer-fence"),
        (Cause::LaterTenure, "later-tenure"),
        (Cause::Regression, "regression"),
    ];
    let refusals = [
        (
            AuthorityRefusal::Admission(Denial::WindowExpired),
            "admission",
        ),
        (AuthorityRefusal::ReportMalformed, "report-malformed"),
        (AuthorityRefusal::ReportTimeout, "report-timeout"),
        (AuthorityRefusal::ForeignLower, "foreign-lower"),
        (AuthorityRefusal::ForeignEqual, "foreign-equal"),
        (AuthorityRefusal::ForeignHigher, "foreign-higher"),
        (AuthorityRefusal::Conflict, "conflict"),
        (AuthorityRefusal::PreemptAborted, "preempt-aborted"),
        (AuthorityRefusal::OwnHostId, "own-host-id"),
        (AuthorityRefusal::Clock, "clock"),
        (AuthorityRefusal::Boundary, "boundary"),
    ];
    for (cause, label) in causes {
        assert_eq!(withdrawal_label(Withdrawal::from(cause)), label);
    }
    for (refusal, label) in refusals {
        assert_eq!(refusal_label(Refusal::from(refusal)), label);
    }
    let judgments = [
        (NotSole::Excess, "excess"),
        (NotSole::Unreadable, "unreadable"),
        (NotSole::ReservationType, "reservation-type"),
        (NotSole::DuplicateOwnRecord, "duplicate-own-record"),
        (NotSole::ForeignHolder, "foreign-holder"),
        (NotSole::ForeignRegistrant, "foreign-registrant"),
        (NotSole::NotHolder, "not-holder"),
    ];
    for (refusal, label) in judgments {
        assert_eq!(kebab(Registrants::from(refusal)), label);
    }
    let outcomes = [
        (MetadataOutcome::Bootstrapping, "bootstrapping"),
        (MetadataOutcome::Unformatted, "unformatted"),
        (MetadataOutcome::Open, "open"),
        (MetadataOutcome::FormatMismatch, "format-mismatch"),
        (MetadataOutcome::TiedRoots, "tied-roots"),
        (MetadataOutcome::StaleSession, "stale-session"),
        (
            MetadataOutcome::Unfenced(crate::storage::GateRefusal::AuthorityLost),
            "unfenced",
        ),
        (MetadataOutcome::EntropyUnavailable, "entropy-unavailable"),
        (MetadataOutcome::MetadataFailed, "metadata-failed"),
        (
            MetadataOutcome::SlotUnreadable {
                slot: crate::storage::Slot::B,
            },
            "slot-unreadable",
        ),
        (
            MetadataOutcome::Unsupported {
                slot: crate::storage::Slot::A,
                version: 9,
            },
            "unsupported",
        ),
        (MetadataOutcome::Collided, "collided"),
        (
            MetadataOutcome::Unloadable(LoadRefusal::StaleWrite),
            "unloadable",
        ),
    ];
    for (outcome, label) in outcomes {
        assert_eq!(kebab(Metadata::from(&outcome)), label);
    }
    let errors = [
        (StoreError::Unavailable, "unavailable"),
        (
            StoreError::Refused(crate::storage::store::Refusal::Condition),
            "refused",
        ),
        (StoreError::Unknown, "unknown"),
        (StoreError::Absent, "absent"),
        (StoreError::Codec(CodecError::Length), "codec"),
        (
            StoreError::Successor(records::SuccessorRule::Identity),
            "successor",
        ),
        (
            StoreError::Flip(crate::failover::flip::FlipRefusal::NoSpare),
            "flip",
        ),
        (StoreError::Stale(Stale::Target), "stale"),
        (StoreError::AttemptsExhausted, "attempts-exhausted"),
        (
            StoreError::Regression(crate::storage::store::Regression::Value(StoreKey::Shard(
                Shard::new(7).unwrap(),
            ))),
            "regression",
        ),
        (StoreError::Withdrawn, "withdrawn"),
        (StoreError::Namespace, "namespace"),
        (StoreError::Log, "log"),
    ];
    for (error, label) in errors {
        assert_eq!(kebab(StoreClass::from(&error)), label);
    }

    scene(&[], |mut scene| {
        serve_at(&mut scene, 3, 1);
        assert_eq!(
            scene.owner.report_entry(0, &Observed::UNAVAILABLE),
            None,
            "no entry before a view"
        );
        let token = token(&scene);
        let attempts = token.epoch.get() / 2;
        let suffix = |epoch: u64, start, end| Suffix {
            session: (3 << 32) | epoch,
            start,
            certified: end,
            end,
        };
        let checkpoint = NamedCheckpoint {
            slot: 1,
            session: (3 << 32) | 2,
            capture: 4,
            units: 8,
        };
        let record = ShardRecord {
            checkpoint: Some(checkpoint),
            cut: 10,
            ancestry: Ancestry::new(&[suffix(2, 5, 20), suffix(4, 20, 30)]).unwrap(),
            ..shard_at(token, 3, attempts)
        };
        let active = volume_record("vol-0a", VolumeState::Active);
        let observed = scene.turn * 100;
        observe(&mut scene, Some(record), Some(active.clone()), token.exhid);
        scene.turn += 3;
        observe(&mut scene, Some(record), Some(active.clone()), token.exhid);
        let owner = &scene.owner;
        let authority = owner.authority_report();
        let entry = owner
            .report_entry(observed + 800, &Observed::UNAVAILABLE)
            .unwrap();
        let expected = VolumeEntry {
            volume: volume("vol-0a"),
            shard: token.shard,
            role: Some(RecordedRole::Owner),
            tenure: Some(authority.tenure),
            volume_state: Some(VolumeState::Active),
            serving: Some(authority.state),
            withheld: authority.withheld,
            quarantine: false,
            flip: authority.flip.is_some(),
            withdrawal: authority.withdrawal.map(Withdrawal::from),
            refusal: authority.refusal.map(Refusal::from),
            enumeration: Enumeration::Unavailable,
            watermark: Watermark::Unavailable,
            report_age_us: authority.report_age_us,
            own_records: authority.own_records,
            checkpoint: Some(checkpoint),
            checkpoint_age_us: Some(800),
            captures: Captures {
                refused: None,
                abandoned: None,
            },
            exit: None,
            pressure: Pressure {
                ancestry: known(2, 4),
                frontier: known(20, 57),
                full: known(0, 3),
                ..unavailable_pressure()
            },
            named: Some(false),
            // The owner's own state of a cold tenure live at its first tick, with no Report judged, no warm load,
            // no suffix and no coverage fencing. The scene's host share gives its one owner 2^40 bytes a tick, and
            // the bucket capacity clamps to that part.
            hold: Some(Hold::Clear),
            readiness: Some(crate::storage::Readiness::Live),
            metadata: Some(Metadata::Open),
            times: RecoveryTimes {
                loaded_us: Some(0),
                live_us: Some(0),
                fill_us: Some(0),
                ..RecoveryTimes::UNAVAILABLE
            },
            recovery_io: RecoveryIo {
                peak: known(0, 1 << 41),
                saturated: Some(0),
            },
            attaches: known(0, 3),
            invalidations: known(0, 64),
            read_defects: Some(0),
            served: Some(0),
            ..bare("vol-0a", RecordedRole::Owner)
        };
        assert_eq!(
            entry, expected,
            "the driver's fields read unavailable with an empty part and the owner's own state gives the rest"
        );
        assert_eq!(
            entry.encode().and_then(|bytes| VolumeEntry::decode(&bytes)),
            Ok(entry)
        );
        assert_eq!(
            (authority.tenure.0, authority.withdrawal),
            (token.generation, None)
        );
        let (state, _) = owner_serving();
        let bytes = writer(1).seal(&state, &[entry], 0, 0).unwrap();
        let body = &bytes[..bytes.len() - TAG_LEN];
        let decoded = Reader::default().accept(&bytes, key_of).unwrap();
        assert_eq!(
            encoded(&decoded),
            body,
            "the body holds only decoded fields"
        );
        assert!(!body.windows(16).any(|window| window == token.exhid.bytes()));
        let moved = NamedCheckpoint {
            capture: 5,
            ..checkpoint
        };
        scene.turn += 1;
        let renamed = scene.turn * 100;
        let next = ShardRecord {
            checkpoint: Some(moved),
            ..record
        };
        observe(&mut scene, Some(next), Some(active.clone()), token.exhid);
        let entry = scene
            .owner
            .report_entry(renamed + 10, &Observed::UNAVAILABLE)
            .unwrap();
        assert_eq!(
            (entry.checkpoint, entry.checkpoint_age_us),
            (Some(moved), Some(10)),
            "a newly named checkpoint ages from its first read"
        );
        let early = scene
            .owner
            .report_entry(renamed - 1, &Observed::UNAVAILABLE)
            .unwrap();
        assert_eq!(
            (early.checkpoint, early.checkpoint_age_us),
            (Some(moved), None),
            "a clock reading before the first read gives no age"
        );
        let unnamed = shard_at(token, 3, attempts);
        observe(&mut scene, Some(unnamed), Some(active), token.exhid);
        let entry = scene
            .owner
            .report_entry(renamed + 20, &Observed::UNAVAILABLE)
            .unwrap();
        assert_eq!((entry.checkpoint, entry.checkpoint_age_us), (None, None));

        let local = host(OWNER);
        let replacement = ShardRecord {
            owner: host(SPARE),
            active: volume("vol-0b"),
            spare: Some((volume("vol-0a"), local)),
            ..record
        };
        let deposed = ShardRecord {
            spare: None,
            ..replacement
        };
        let standby = ShardRecord {
            owner: host(SPARE),
            spare: None,
            standby: Some(local),
            ..record
        };
        let mut registrant = volume_record("vol-0a", VolumeState::Active);
        let attach = registrant
            .push(EventKind::Attach, local, records::ERA)
            .unwrap();
        registrant.pairs.push(RecordedPair {
            host: local,
            pair: Pair {
                exhid: token.exhid,
                key: token.key,
            },
            attach,
        });
        let unlisted = volume_record("vol-0a", VolumeState::Fresh);
        // The local host's attach ended in place with its pair still recorded (ENDED-GRANTS-NOTHING keeps the pair).
        let mut ended = registrant.clone();
        (ended.events.iter_mut())
            .filter(|event| event.seq == attach)
            .for_each(|event| event.kind = EventKind::Ended);
        let (active, fresh) = (VolumeState::Active, VolumeState::Fresh);
        let remote = ShardRecord {
            standby: Some(host(SPARE + 1)),
            ..standby
        };
        let elsewhere = ShardRecord {
            active: volume("vol-0b"),
            ..standby
        };
        let mut last_active_own = true;
        // The role reads the last accepted shard record and the last own-volume read, so an observation carrying
        // one of the two keeps what the other last gave. Owner and replacement rank above a listed pair, and a
        // listed pair reads as standby only on the volume the shard record names active, a pair that pins the local
        // host's ended entry included. `named` needs the local host named standby on the own volume: a remote standby
        // there and the local standby on another volume read false.
        for (shard, volume, role, state, named) in [
            (
                Some(record),
                Some(registrant.clone()),
                RecordedRole::Owner,
                active,
                false,
            ),
            (
                Some(replacement),
                None,
                RecordedRole::Replacement,
                active,
                false,
            ),
            (Some(deposed), None, RecordedRole::Unrecorded, active, false),
            (Some(standby), None, RecordedRole::Standby, active, true),
            (Some(remote), None, RecordedRole::Standby, active, false),
            (
                Some(elsewhere),
                None,
                RecordedRole::Unrecorded,
                active,
                false,
            ),
            (Some(standby), None, RecordedRole::Standby, active, true),
            (None, Some(unlisted), RecordedRole::Unrecorded, fresh, true),
            (
                Some(standby),
                Some(registrant),
                RecordedRole::Standby,
                active,
                true,
            ),
            (
                Some(standby),
                Some(ended),
                RecordedRole::Standby,
                active,
                true,
            ),
        ] {
            let active_own = shard.map(|record| record.active == VolumeId::new("vol-0a").unwrap());
            last_active_own = active_own.unwrap_or(last_active_own);
            observe(&mut scene, shard, volume, token.exhid);
            let entry = scene.owner.report_entry(0, &Observed::UNAVAILABLE).unwrap();
            assert_eq!((entry.role, entry.volume_state), (Some(role), Some(state)));
            assert_eq!(
                entry.named,
                Some(named),
                "{role:?}: named reads the shard record's standby"
            );
            // The history gauges read the own volume's region only while the record names that volume active.
            assert_eq!(
                entry.pressure.frontier != Gauge::Unavailable,
                last_active_own,
                "{role:?}"
            );
        }
        let entry = scene.owner.report_entry(0, &Observed::UNAVAILABLE).unwrap();
        assert_eq!(entry.withdrawal, Some(Withdrawal::Flipped));
        // A later record whose chain holds `MAX_CHAIN` suffixes reads the ancestry at its bound through the entry.
        let chained = ShardRecord {
            ancestry: Ancestry::new(&[(2, 10, 12), (4, 12, 14), (6, 14, 16), (8, 16, 18)].map(
                |(epoch, start, end)| Suffix {
                    session: (3 << 32) | epoch,
                    start,
                    certified: end,
                    end,
                },
            ))
            .unwrap(),
            attempts: attempts + 4,
            ..record
        };
        observe(&mut scene, Some(chained), None, token.exhid);
        let entry = scene.owner.report_entry(0, &Observed::UNAVAILABLE).unwrap();
        assert_eq!(
            (
                entry.pressure.ancestry,
                entry.pressure.frontier,
                entry.pressure.full
            ),
            (known(4, 4), known(8, 57), known(1, 3)),
            "a full chain reads full through the owner's entry"
        );
        // A refused charge in the share's window open at the report adds the share to `full`; the next window,
        // with no later charge, reads it clear again.
        let at = renamed + 1_000;
        scene.owner.refuse_recovery_io(at);
        let saturated = scene
            .owner
            .report_entry(at, &Observed::UNAVAILABLE)
            .unwrap();
        assert_eq!(
            (entry.recovery_io.saturated, saturated.recovery_io.saturated),
            (Some(0), Some(1)),
            "the refused window counts once"
        );
        assert_eq!(
            saturated.pressure,
            Pressure {
                full: known(2, 3),
                ..entry.pressure
            }
        );
        let later = scene
            .owner
            .report_entry(at + 1, &Observed::UNAVAILABLE)
            .unwrap();
        assert_eq!(later.pressure, entry.pressure, "the share's window closed");
        assert_eq!(
            later.recovery_io.saturated,
            Some(1),
            "the count keeps the closed window"
        );
    });
    // A first observation gives the role and the volume state only from the records it carries: a shard record
    // naming neither the owner nor the replacement role gives no role without an own-volume read, and a volume
    // read alone gives no role, ancestry or checkpoint.
    for (shard, volume, expected) in [
        (true, false, (None, None, known(0, 4))),
        (
            false,
            true,
            (None, Some(VolumeState::Active), Gauge::Unavailable),
        ),
    ] {
        scene(&[], |mut scene| {
            serve_at(&mut scene, 3, 1);
            let token = token(&scene);
            let foreign = ShardRecord {
                owner: host(SPARE),
                ..shard_at(token, 3, token.epoch.get() / 2)
            };
            let volume = volume.then(|| volume_record("vol-0a", VolumeState::Active));
            observe(&mut scene, shard.then_some(foreign), volume, token.exhid);
            let entry = scene.owner.report_entry(0, &Observed::UNAVAILABLE).unwrap();
            let got = (entry.role, entry.volume_state, entry.pressure.ancestry);
            assert_eq!((got, entry.checkpoint), (expected, None));
            // `named` reads an accepted shard record, which the volume-only observation lacks.
            assert_eq!(entry.named, shard.then_some(false));
        });
    }

    let meminfo = "MemTotal:       16000 kB\nMemFree:         1000 kB\nMemAvailable:    4000 kB\n";
    assert_eq!(ram(meminfo), known(12_000 * 1024, 16_000 * 1024));
    assert_eq!(
        ram("MemTotal: 4 kB\nMemAvailable: 8 kB\n"),
        Gauge::Unavailable
    );
    assert_eq!(ram("MemTotal: 4 kB\n"), Gauge::Unavailable);
    assert_eq!(
        ram("MemTotal: 4 kB\nMemAvailable: 0 kB\n"),
        known(4096, 4096)
    );
    assert_eq!(cpu_load("inf 1 1", "0-3"), Gauge::Unavailable);
    assert_eq!(
        cpu_load("1.50 0.80 0.40 2/300 12345\n", "0-3,6,8-10\n"),
        known(150, 800)
    );
    assert_eq!(cpu_load("12.00 1 1 1/1 1", "0-3"), known(400, 400));
    assert_eq!(cpu_load("x 1 1", "0-3"), Gauge::Unavailable);
    for overlapping in ["0-3,2-5", "1,1", "4,0-1"] {
        assert_eq!(
            cpu_load("1.0", overlapping),
            Gauge::Unavailable,
            "{overlapping}"
        );
    }
    assert_eq!(cpu_load("1.0", "3-1"), Gauge::Unavailable);
    assert_eq!(
        cpu_load("1.0", "0-18446744073709551615"),
        Gauge::Unavailable
    );
    let sampled = Headroom::sample(&HeadroomInputs::UNAVAILABLE);
    assert!(matches!(sampled.ram, Gauge::Known { used, limit } if used <= limit.get()));
    assert!(matches!(sampled.cpu_load, Gauge::Known { limit, .. } if limit.get() % 100 == 0));
    let sourceless = Headroom {
        ram: Gauge::Unavailable,
        cpu_load: Gauge::Unavailable,
        ..sampled
    };
    assert_eq!(sourceless, unavailable_headroom());
}

/// The helper applies `edit` to a copy of `bytes` and retags the copy under the fixture key.
fn edited(bytes: &[u8], edit: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    edit(&mut bytes);
    retagged(bytes)
}

type Edit = Box<dyn FnOnce(&mut [u8])>;

/// A decoder that checks the body field by field and returns at the first failing check, the form the entry check
/// mask must agree with on every value and first error.
mod field_by_field {
    use super::*;

    fn optional<T: Copy>(r: &mut Bytes<'_>, table: &[T]) -> Result<Option<T>, ReportError> {
        match usize::from(r.u8()?) {
            0 => Ok(None),
            at => table
                .get(at - 1)
                .copied()
                .map(Some)
                .ok_or(ReportError::Flag),
        }
    }
    fn flagged<T: Default + PartialEq>(present: u8, value: T) -> Result<Option<T>, ReportError> {
        match present {
            1 => Ok(Some(value)),
            0 if value == T::default() => Ok(None),
            _ => Err(ReportError::Flag),
        }
    }
    fn take_u64(r: &mut Bytes<'_>) -> Result<Option<u64>, ReportError> {
        flagged(r.u8()?, r.u64()?)
    }
    fn take_members(r: &mut Bytes<'_>) -> Result<Members, ReportError> {
        match flagged(r.u8()?, (r.u64()?, r.u64()?))? {
            None => Ok(Members::Unavailable),
            Some((used, limit)) if used <= limit => Ok(Members::Known { used, limit }),
            Some(_) => Err(ReportError::Field),
        }
    }
    fn take_gauge(r: &mut Bytes<'_>) -> Result<Gauge, ReportError> {
        match flagged(r.u8()?, (r.u64()?, r.u64()?))? {
            None => Ok(Gauge::Unavailable),
            Some((used, limit)) => match Gauge::known(used, limit) {
                Gauge::Unavailable => Err(ReportError::Field),
                known => Ok(known),
            },
        }
    }
    pub(super) fn decode_body(body: &[u8]) -> Result<HostReport, ReportError> {
        let count = layout(body, 0)?;
        let mut r = Bytes::open(body, MAGIC, SCHEMA)?;
        let writer = take_writer(&mut r)?;
        let sequence = Some(r.u64()?)
            .filter(|sequence| *sequence >= 1)
            .ok_or(ReportError::Field)?;
        let sealed_at_us = r.u64()?;
        if r.take::<2>()?[1] != 0 {
            return Err(ReportError::Flag);
        }
        let build = BuildIdentity {
            era: r.u32()?,
            digest: flagged(r.u8()?, r.take()?)?,
        };
        let mut gauge = || take_gauge(&mut r);
        let headroom = Headroom {
            ram: gauge()?,
            cpu_load: gauge()?,
            iops: gauge()?,
            bandwidth: gauge()?,
            attachments: gauge()?,
            workers: gauge()?,
            recovery: gauge()?,
        };
        let health = optional(&mut r, HEALTH)?;
        let detector = Detector {
            peers: take_members(&mut r)?,
            self_suspect_us: take_u64(&mut r)?,
            nominations: take_u64(&mut r)?,
        };
        let (producer_missing, recovery_io) = (take_members(&mut r)?, take_gauge(&mut r)?);
        let mut entries: Vec<VolumeEntry> = Vec::with_capacity(count);
        for _ in 0..count {
            let entry = take_entry(&mut r)?;
            if entries.iter().any(|seen| seen.volume == entry.volume) {
                return Err(ReportError::Field);
            }
            entries.push(entry);
        }
        Ok(HostReport {
            writer,
            sequence,
            sealed_at_us,
            host: HostState {
                build,
                headroom,
                health,
                detector,
                producer_missing,
                recovery_io,
            },
            entries,
        })
    }
    fn take_entry(r: &mut Bytes<'_>) -> Result<VolumeEntry, ReportError> {
        let volume = VolumeId::from_field(&r.take()?).ok_or(ReportError::Field)?;
        let shard = Shard::new(r.u32()?).ok_or(ReportError::Field)?;
        let role = optional(r, ROLES)?;
        let tenure = match (r.u32()?, r.u32()?) {
            (0, 0) => None,
            (g, a) => Some(
                ShardGeneration::new(g.into())
                    .zip(ActivatedEpoch::new(a))
                    .ok_or(ReportError::Field)?,
            ),
        };
        let (volume_state, serving) = (optional(r, &STATES)?, optional(r, SERVING)?);
        let flags = Some(r.u8()?)
            .filter(|flags| flags >> 3 == 0 && (serving.is_some() || *flags == 0))
            .ok_or(ReportError::Flag)?;
        let (withdrawal, refusal) = (optional(r, WITHDRAWALS)?, optional(r, REFUSALS)?);
        let (enumeration, watermark) = (r.pick(ENUMERATIONS)?, r.pick(WATERMARKS)?);
        let (report_age_us, own_records) = (take_u64(r)?, flagged(r.u8()?, r.u32()?)?);
        let (checkpoint, checkpoint_age_us) = (r.checkpoint()?, take_u64(r)?);
        if checkpoint.is_none() && checkpoint_age_us.is_some() {
            return Err(ReportError::Field);
        }
        let captures = Captures {
            refused: take_u64(r)?,
            abandoned: take_u64(r)?,
        };
        let exit = take_exit(r)?;
        let pressure = Pressure {
            frontier: take_gauge(r)?,
            ancestry: take_gauge(r)?,
            quarantine: take_gauge(r)?,
            full: take_gauge(r)?,
        };
        if matches!(pressure.full, Gauge::Known { limit, .. } if limit.get() != HISTORY_RESOURCES) {
            return Err(ReportError::Field);
        }
        let registrants = optional(r, REGISTRANTS)?;
        let hold = optional(r, HOLDS)?;
        let readiness = optional(r, READINESS)?;
        let metadata = optional(r, METADATA)?;
        let load_refusal = optional(r, LOAD_REFUSALS)?;
        let (kind, outcome) = (optional(r, KINDS)?, optional(r, OUTCOMES)?);
        let (check, next, store) = (
            optional(r, CHECKS)?,
            optional(r, NEXTS)?,
            optional(r, STORE_CLASSES)?,
        );
        let settled = matches!(
            outcome,
            Some(RecoveryOutcome::Running | RecoveryOutcome::Completed)
        );
        if settled && (check, next, store) != (None, None, None) {
            return Err(ReportError::Field);
        }
        if store.is_some() && check.is_none() {
            return Err(ReportError::Field);
        }
        let (phase, ended) = (optional(r, PHASES)?, optional(r, ENDINGS)?);
        let more = r.u8()?;
        let known = |bit: u8| match (more >> (bit + 4) & 1, more >> bit & 1) {
            (0, 0) => Ok(None),
            (0, _) => Err(ReportError::Flag),
            (_, value) => Ok(Some(value == 1)),
        };
        let (named, roll_due, roll_active, publication_due) =
            (known(0)?, known(1)?, known(2)?, known(3)?);
        let attempts = flagged(r.u8()?, r.u32()?)?;
        let age_us = take_u64(r)?;
        let recovery = Recovery {
            kind,
            outcome,
            check,
            next,
            store,
            attempts,
            age_us,
        };
        let labelled = Recovery {
            attempts: None,
            ..recovery
        } != Recovery::UNAVAILABLE;
        if kind.is_none() && labelled {
            return Err(ReportError::Field);
        }
        let times = RecoveryTimes {
            loaded_us: take_u64(r)?,
            live_us: take_u64(r)?,
            first_hit_us: take_u64(r)?,
            retained_us: take_u64(r)?,
            fill_us: take_u64(r)?,
        };
        let live = times.live_us.or(times.retained_us);
        let before = |early: Option<u64>, later: Option<u64>| match (early, later) {
            (Some(early), Some(later)) => early <= later,
            _ => true,
        };
        let retained = match (times.live_us, times.retained_us) {
            (Some(live), Some(retained)) => live == retained,
            _ => true,
        };
        let ordered = before(times.loaded_us, live)
            && before(live, times.first_hit_us)
            && before(live, times.fill_us);
        if !(ordered && retained) {
            return Err(ReportError::Field);
        }
        let retention = match (r.u8()?, r.take::<{ RETENTION - 1 }>()?) {
            (0, rest) if rest == [0; RETENTION - 1] => None,
            (1, rest) => {
                let mut rest = Bytes(&rest);
                let retention = Retention {
                    first_damage: optional(&mut rest, DAMAGES)?,
                    installed: rest.u64()?,
                    omitted: rest.u64()?,
                    held_units: rest.u64()?,
                    failed_units: rest.u32()?,
                    unread_units: rest.u32()?,
                    suffix_damage: rest.u32()?,
                    suffix_tails: rest.u32()?,
                    suffix_dropped: rest.u64()?,
                    suffix_unread: rest.u64()?,
                    slot_superseded: rest.u64()?,
                    slot_withheld: rest.u64()?,
                };
                let (failed, unread) = (retention.failed_units, retention.unread_units);
                let consistent = match retention.first_damage {
                    None => failed == 0 && unread == 0,
                    Some(Damage::Content) => true,
                    Some(Damage::Unread) => failed == 0 && unread != 0,
                    Some(_) => failed != 0,
                };
                if !consistent {
                    return Err(ReportError::Field);
                }
                Some(retention)
            }
            _ => return Err(ReportError::Flag),
        };
        let suffix = Backlog {
            blocks: take_gauge(r)?,
            flush_lag_us: take_u64(r)?,
        };
        let empty = matches!(suffix.blocks, Gauge::Known { used: 0, .. });
        if empty && suffix.flush_lag_us.is_some_and(|lag| lag > 0) {
            return Err(ReportError::Field);
        }
        let recovery_io = RecoveryIo {
            peak: take_gauge(r)?,
            saturated: take_u64(r)?,
        };
        let attaches = take_gauge(r)?;
        let store = StoreOutcomes {
            unknown: take_u64(r)?,
            unavailable: take_u64(r)?,
            refused: take_u64(r)?,
            log: take_u64(r)?,
        };
        let coverage = Coverage {
            saturated: take_gauge(r)?,
            largest: take_gauge(r)?,
        };
        let invalidations = take_gauge(r)?;
        let (read_defects, served) = (take_u64(r)?, take_u64(r)?);
        Ok(VolumeEntry {
            volume,
            shard,
            role,
            tenure,
            volume_state,
            serving,
            withheld: flags & 1 != 0,
            quarantine: flags & 2 != 0,
            flip: flags & 4 != 0,
            withdrawal,
            refusal,
            enumeration,
            watermark,
            report_age_us,
            own_records,
            checkpoint,
            checkpoint_age_us,
            captures,
            exit,
            pressure,
            registrants,
            hold,
            readiness,
            metadata,
            load_refusal,
            recovery,
            phase,
            ended,
            named,
            roll_due,
            roll_active,
            publication_due,
            times,
            retention,
            suffix,
            recovery_io,
            attaches,
            store,
            coverage,
            invalidations,
            read_defects,
            served,
        })
    }
    fn take_exit(r: &mut Bytes<'_>) -> Result<Option<Exit>, ReportError> {
        match (optional(r, EXITS)?, r.take::<16>()?) {
            (None, operation) => (operation == [0; 16])
                .then_some(None)
                .ok_or(ReportError::Flag),
            (Some(status), operation) => {
                let operation = ExitOperation::new(operation).ok_or(ReportError::Field)?;
                Ok(Some(Exit { operation, status }))
            }
        }
    }
}

/// The offset of the first entry.
const ENTRY: usize = HEADER_LEN + HOST_LEN;
/// The offset of the host part's health label.
const HEALTH_AT: usize = 204;
/// The flag and zero bytes of the header and host part: the zero byte, the digest flag and the gauge flags.
const HOST: [usize; 15] = [
    47, 52, 85, 102, 119, 136, 153, 170, 187, 204, 205, 222, 231, 240, 257,
];
/// The label and flag bytes of an entry, from its start: role, the seven label bytes, the flags of the Report age,
/// own-record count, checkpoint, checkpoint age and capture counts, the exit code and the four gauge flags; then the
/// twelve label bytes and the second flags byte of the recovery part, the flags of the attempt count, the age and
/// the five times, the retention flag and its first-damage label, and the flags of the remaining gauges and counts.
const LABELS: [usize; 55] = [
    26, 35, 36, 37, 38, 39, 40, 41, 42, 51, 56, 77, 86, 95, 104, 121, 138, 155, 172, 189, 190, 191,
    192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 207, 216, 225, 234, 243, 252, 261, 262,
    335, 352, 361, 378, 387, 404, 413, 422, 431, 440, 457, 474, 491, 500,
];

/// REPORT-AUTHENTICATED and REPORT-BOUNDED: a flipped bit refuses with `Magic`, `Schema` or `Length` in the header
/// bytes those checks read and with `Tag` everywhere else; a zero writer host or boot refuses with `Writer` before
/// the key lookup; a wrong key, the host key in place of its report key, a length off by one, a count above
/// `MAX_ENTRIES` and an oversized buffer refuse at the reader; a retagged body decodes only to the bytes its
/// encoder produces, and each field rule refuses with its own error; the report key authenticates no assignment;
/// a writer from `Writer::new` seals sequence 1 under a fresh boot; an empty report seals at its minimum length;
/// the writer paces on its elapsed clock, whatever the wall stamp, and refuses too many entries, an early seal, an
/// exhausted sequence or due time without changing state, and any value the decoder would refuse or alter.
#[test]
fn mac_and_bounds() {
    let (state, entries) = owner_serving();
    let bytes = sealed(1, &state, &entries);
    let report_key = ReportKey::derive(&KEY);
    assert_ne!(report_key.0, KEY);
    let mut created = Writer::new(host(WRITER_HOST), &KEY, PERIOD).unwrap();
    assert_eq!(
        created.key.0, report_key.0,
        "the writer holds the derived key"
    );
    let first = created.seal(&state, &entries, SEALED, 0).unwrap();
    let first = Reader::default().accept(&first, key_of).unwrap();
    assert_eq!((first.sequence, first.writer.host), (1, host(WRITER_HOST)));
    let again = Writer::new(host(WRITER_HOST), &KEY, PERIOD).unwrap();
    assert!(first.writer.boot != [0; 16] && again.envelope.id.boot != first.writer.boot);
    let assignment = crate::failover::assignment_tests::sample()
        .sign(&KEY)
        .unwrap();
    assert!(assignment::verify(&assignment, &KEY).is_ok());
    assert_eq!(
        assignment::verify(&assignment, &report_key.0),
        Err(AssignmentError::Tag),
        "a verifier's key authenticates no assignment"
    );
    let host_keyed = Reader::default().accept(&bytes, |_| Some(ReportKey(KEY)));
    assert_eq!(host_keyed, Err(ReportError::Tag));
    for at in 0..bytes.len() {
        let mut flipped = bytes.clone();
        flipped[at] ^= 1;
        let expected = match at {
            0..4 => ReportError::Magic,
            4..6 => ReportError::Schema {
                found: u16::from_be_bytes([flipped[4], flipped[5]]),
            },
            _ if at == HEADER_LEN - 2 => ReportError::Length,
            _ => ReportError::Tag,
        };
        let refused = Reader::default().accept(&flipped, key_of);
        assert_eq!(refused, Err(expected), "offset {at}");
    }
    for (at, len) in [(6, 8), (14, 16)] {
        for retag in [false, true] {
            let mut zeroed = bytes.clone();
            zeroed[at..at + len].fill(0);
            let zeroed = if retag { retagged(zeroed) } else { zeroed };
            let calls = Cell::new(0);
            let refused = Reader::default().accept(&zeroed, |_| {
                calls.set(calls.get() + 1);
                Some(ReportKey::derive(&KEY))
            });
            assert_eq!((refused, calls.get()), (Err(ReportError::Writer), 0));
        }
    }
    let wrong = Reader::default().accept(&bytes, |_| Some(ReportKey([0x5B; 32])));
    assert_eq!(wrong, Err(ReportError::Tag));
    let mut longer = bytes.clone();
    longer.push(0);
    for resized in [&bytes[..bytes.len() - 1], &longer[..]] {
        let refused = Reader::default().accept(resized, key_of);
        assert_eq!(refused, Err(ReportError::Length));
    }
    for count in [2, MAX_ENTRIES as u8 + 1] {
        let mut counted = bytes.clone();
        counted[HEADER_LEN - 2] = count;
        let refused = Reader::default().accept(&retagged(counted), key_of);
        assert_eq!(refused, Err(ReportError::Length));
    }
    let mut oversized = bytes.clone();
    oversized.resize(MAX_LEN + 1, 0xEE);
    let refused = Reader::default().accept(&oversized, key_of);
    assert_eq!(refused, Err(ReportError::Length));

    let full: Vec<VolumeEntry> = (0..=MAX_ENTRIES)
        .map(|at| VolumeEntry {
            volume: volume(&format!("vol-{at:x}")),
            ..entries[0]
        })
        .collect();
    let mut w = writer(1);
    let refused = w.seal(&state, &full, 0, 0);
    assert_eq!(refused, Err(SealError::Entries));
    let mut counted = body(&writer(1), &state, &full, SEALED);
    counted.extend([0; TAG_LEN]);
    assert_eq!(counted.len(), report_len(MAX_ENTRIES + 1));
    let calls = Cell::new(0);
    let refused = Reader::default().accept(&retagged(counted), |host| {
        calls.set(calls.get() + 1);
        key_of(host)
    });
    assert_eq!(
        (refused, calls.get()),
        (Err(ReportError::Length), 0),
        "the reader's entry cap"
    );
    let largest = w.seal(&state, &full[..MAX_ENTRIES], 0, 0).unwrap();
    assert_eq!(largest.len(), MAX_LEN);
    let mut reader = Reader::default();
    assert_eq!(
        reader.accept(&largest, key_of).unwrap().entries.len(),
        MAX_ENTRIES
    );
    let refused = w.seal(&state, &entries, u64::MAX, PERIOD.get() - 1);
    assert_eq!(
        refused,
        Err(SealError::Early),
        "a wall-clock step paces nothing"
    );
    assert_eq!(
        w.seal(&state, &full, 0, PERIOD.get() - 1),
        Err(SealError::Early),
        "an early seal of too many entries refuses as early"
    );
    let next = w.seal(&state, &entries, 0, PERIOD.get()).unwrap();
    assert_eq!(reader.accept(&next, key_of).unwrap().sequence, 2);
    let empty = w.seal(&state, &[], 0, 2 * PERIOD.get()).unwrap();
    assert_eq!(empty.len(), HEADER_LEN + HOST_LEN + TAG_LEN);
    let empty = reader.accept(&empty, key_of).unwrap();
    assert_eq!((empty.sequence, empty.entries.len()), (3, 0));
    let refused = writer(u64::MAX).seal(&state, &entries, 0, 0);
    assert_eq!(refused, Err(SealError::Exhausted));
    let mut late = writer(1);
    let refused = late.seal(&state, &entries, 0, u64::MAX);
    assert_eq!(
        refused,
        Err(SealError::Exhausted),
        "the due time does not fit"
    );
    assert_eq!((late.envelope.next, late.envelope.next_due), (1, 0));

    let over = VolumeEntry {
        pressure: Pressure {
            full: Gauge::Known {
                used: 5,
                limit: NonZeroU64::new(4).unwrap(),
            },
            ..entries[0].pressure
        },
        ..entries[0]
    };
    for refused in [&[over][..], &[entries[0], entries[0]]] {
        let mut refusing = writer(1);
        let sealed = refusing.seal(&state, refused, 7, 0);
        assert_eq!(sealed, Err(SealError::Field(ReportError::Field)));
        let kept = &refusing.envelope;
        assert_eq!(
            (kept.next, kept.next_due, kept.sealed_at_us),
            (1, 0, 0),
            "a body the decoder refuses advances nothing"
        );
    }
    let mut forged = body(&writer(1), &state, &[entries[0], entries[0]], SEALED);
    forged.extend([0; TAG_LEN]);
    let refused = Reader::default().accept(&retagged(forged), key_of);
    assert_eq!(refused, Err(ReportError::Field));

    let contract = contract();
    let fixture = |case: &str| unhex(contract["cases"][case]["bytes"].as_str().unwrap());
    let (full, bare) = (fixture("owner-serving"), fixture("standby-unavailable"));
    for case in [&full, &bare] {
        let body_len = case.len() - TAG_LEN;
        for at in 0..body_len {
            for mask in [0x01, 0x80, 0xFF] {
                let bytes = edited(case, |bytes| bytes[at] ^= mask);
                if let Ok(report) = Reader::default().accept(&bytes, key_of) {
                    assert_eq!(encoded(&report), bytes[..body_len], "{at} {mask}");
                }
            }
        }
    }
    let u64_at = |at: usize, value: u64| {
        move |b: &mut [u8]| b[at..at + 8].copy_from_slice(&value.to_be_bytes())
    };
    let (full, bare) = (&full[..], &bare[..]);
    let rules: [(&[u8], Edit, ReportError); 40] = [
        (full, Box::new(|b| b[HEADER_LEN - 1] = 1), ReportError::Flag),
        (full, Box::new(u64_at(30, 0)), ReportError::Field),
        (full, Box::new(|b| b[52] = 2), ReportError::Flag),
        (bare, Box::new(|b| b[53] = 1), ReportError::Flag),
        (full, Box::new(|b| b[85] = 2), ReportError::Flag),
        (bare, Box::new(|b| b[86] = 1), ReportError::Flag),
        (full, Box::new(u64_at(94, 0)), ReportError::Field),
        (full, Box::new(u64_at(86, u64::MAX)), ReportError::Field),
        (
            full,
            Box::new(|b| b[ENTRY..ENTRY + 22].fill(0xFF)),
            ReportError::Field,
        ),
        (
            full,
            Box::new(|b| b[ENTRY + 22..ENTRY + 26].fill(0)),
            ReportError::Field,
        ),
        (
            full,
            Box::new(|b| b[ENTRY + 27..ENTRY + 31].fill(0)),
            ReportError::Field,
        ),
        (full, Box::new(|b| b[ENTRY + 34] = 1), ReportError::Field),
        (full, Box::new(|b| b[ENTRY + 34] = 5), ReportError::Field),
        (
            full,
            Box::new(|b| b[ENTRY + 31..ENTRY + 35].fill(0xFF)),
            ReportError::Field,
        ),
        (full, Box::new(|b| b[ENTRY + 37] = 0x08), ReportError::Flag),
        (bare, Box::new(|b| b[ENTRY + 37] = 1), ReportError::Flag),
        (bare, Box::new(|b| b[ENTRY + 43] = 1), ReportError::Flag),
        (full, Box::new(|b| b[ENTRY + 51] = 2), ReportError::Flag),
        (bare, Box::new(|b| b[ENTRY + 77] = 1), ReportError::Field),
        (bare, Box::new(|b| b[ENTRY + 105] = 1), ReportError::Flag),
        (
            full,
            Box::new(|b| b[ENTRY + 105..ENTRY + 121].fill(0)),
            ReportError::Field,
        ),
        (full, Box::new(|b| b[ENTRY + 121] = 2), ReportError::Flag),
        (full, Box::new(|b| b[HEALTH_AT] = 3), ReportError::Flag),
        (bare, Box::new(|b| b[223] = 1), ReportError::Flag),
        (full, Box::new(u64_at(241, 2)), ReportError::Field),
        (full, Box::new(u64_at(258, u64::MAX)), ReportError::Field),
        (full, Box::new(|b| b[ENTRY + 201] = 0x01), ReportError::Flag),
        (full, Box::new(|b| b[ENTRY + 202] = 2), ReportError::Flag),
        (bare, Box::new(|b| b[ENTRY + 206] = 1), ReportError::Flag),
        (full, Box::new(|b| b[ENTRY + 194] = 0), ReportError::Field),
        (full, Box::new(|b| b[ENTRY + 196] = 1), ReportError::Field),
        (bare, Box::new(|b| b[ENTRY + 207] = 1), ReportError::Field),
        (full, Box::new(|b| b[ENTRY + 261] = 2), ReportError::Flag),
        (bare, Box::new(|b| b[ENTRY + 270] = 1), ReportError::Flag),
        (bare, Box::new(|b| b[ENTRY + 262] = 1), ReportError::Flag),
        (full, Box::new(|b| b[ENTRY + 262] = 6), ReportError::Flag),
        (full, Box::new(|b| b[ENTRY + 262] = 0), ReportError::Field),
        (
            full,
            Box::new(u64_at(ENTRY + 336, u64::MAX)),
            ReportError::Field,
        ),
        (full, Box::new(|b| b[ENTRY + 500] = 2), ReportError::Flag),
        (bare, Box::new(|b| b[ENTRY + 508] = 1), ReportError::Flag),
    ];
    for (at, (case, edit, error)) in rules.into_iter().enumerate() {
        let refused = Reader::default().accept(&edited(case, edit), key_of);
        assert_eq!(refused, Err(error), "rule {at}");
    }

    // Every pair of edits to the label, flag and checked value bytes of one entry, and random edits of up to three
    // bytes past the magic and schema of sealed bodies: the accepted report or the first error equals the
    // field-by-field decoder's, so the check mask keeps the decoder's order.
    let (state, entries) = owner_serving();
    let kinds = [
        entries[0],
        standby_unavailable().1[0],
        replacement_restarting().1[0],
    ];
    let compare = |bytes: Vec<u8>, case: &str| {
        let bytes = retagged(bytes);
        let expected = field_by_field::decode_body(&bytes[..bytes.len() - TAG_LEN]);
        assert_eq!(Reader::default().accept(&bytes, key_of), expected, "{case}");
    };
    let checked = LABELS.iter().chain(&[
        0, 25, 34, 50, 55, 60, 85, 94, 103, 120, 129, 137, 206, 215, 224, 270, 343, 351, 412, 508,
    ]);
    let edits: Vec<(usize, u8)> = checked
        .flat_map(|&at| [0, 1, 2, u8::MAX].map(|value| (ENTRY + at, value)))
        .collect();
    for (kind, entry) in kinds.iter().enumerate() {
        let body = sealed(1, &state, &[*entry]);
        for (first, &(a, x)) in edits.iter().enumerate() {
            for &(b, y) in &edits[first + 1..] {
                let mut bytes = body.clone();
                (bytes[a], bytes[b]) = (x, y);
                compare(bytes, &format!("kind {kind} {a}={x} {b}={y}"));
            }
        }
    }
    let bodies: Vec<Vec<u8>> = [2usize, 5]
        .iter()
        .map(|&count| {
            let mixed: Vec<VolumeEntry> = (0..count)
                .map(|at| VolumeEntry {
                    volume: volume(&format!("vol-{:x}", 0xa + at)),
                    ..kinds[at % kinds.len()]
                })
                .collect();
            sealed(1, &state, &mixed)
        })
        .collect();
    let mut seed = 0x2545_F491_4F6C_DD1D_u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for case in 0..20_000 {
        let mut bytes = bodies[case % bodies.len()].clone();
        let body_len = bytes.len() - TAG_LEN;
        let count = (body_len - ENTRY) / ENTRY_LEN;
        for _ in 0..=next() % 3 {
            let at = match next() % 3 {
                0 => 6 + next() as usize % (body_len - 6),
                1 => HOST[next() as usize % HOST.len()],
                _ => {
                    ENTRY
                        + next() as usize % count * ENTRY_LEN
                        + LABELS[next() as usize % LABELS.len()]
                }
            };
            bytes[at] = match next() % 4 {
                0 => (next() % 4) as u8,
                1 => u8::MAX,
                2 => bytes[at] ^ 1 << (next() % 8),
                _ => next() as u8,
            };
        }
        compare(bytes, &format!("case {case}"));
    }
}

/// A report checks each entry's own fields before it compares the entry's volume with the earlier entries', so the
/// first failing check in layout order is the one reported. Two entries that name one volume refuse with `Field`
/// at the second entry's volume comparison; when the second entry's role byte is also one past its table, that
/// byte's `Flag` comes first. A reader that compared the volume before decoding the entry would return `Field` for
/// both bodies.
#[test]
fn a_repeated_volume_refuses_after_the_entry_s_own_checks() {
    let (state, entries) = owner_serving();
    let body = body(&writer(1), &state, &[entries[0], entries[0]], SEALED);
    let accept = |body: &[u8]| {
        let mut bytes = body.to_vec();
        bytes.extend([0; TAG_LEN]);
        Reader::default().accept(&retagged(bytes), key_of)
    };
    assert_eq!(accept(&body), Err(ReportError::Field));
    let role = ENTRY + ENTRY_LEN + 26;
    assert_eq!(body[role], body[ENTRY + 26], "the second entry's role byte");
    let mut past = body.clone();
    past[role] = ROLES.len() as u8 + 1;
    assert_eq!(accept(&past), Err(ReportError::Flag));
}

type Snapshot = (
    [usize; 2],
    std::collections::BTreeMap<StoreKey, usize>,
    crate::storage::VolumeReport,
    crate::net::OwnerReport,
    crate::net::PutReport,
    AuthorityReport,
    [u64; 2],
    [usize; 4],
);

fn snapshot(scene: &Scene<'_, '_>, store: &Shared, keys: &[StoreKey; 2]) -> Snapshot {
    let sim = store.0.borrow();
    let control = &scene.control;
    (
        keys.each_ref().map(|key| sim.commit_count(key)),
        sim.replied.clone(),
        scene.owner.volume_report(),
        scene.owner.report(),
        scene.owner.put_report(),
        scene.owner.authority_report(),
        [control.logged(), control.capture().accepted],
        [
            control.driver_calls(),
            control.accepted(Operation::Read),
            control.accepted(Operation::Write),
            control.pending(),
        ],
    )
}

/// REPORTS-CONFER-NO-AUTHORITY: producing, sealing and accepting reports, including foreign reports that name the
/// owner's shard under a later owner or a flipped standby, and a reconciler status that rows the shard as cold,
/// leaves the owner's reports and authority and the device double's command counters unchanged, and the report
/// module's lines other than whole-line comments, its status files included, name no write path. The loop holds no store handle, so the store double's commits and replies stay unchanged with it; one
/// store write and one authority event afterwards each change the snapshot, so the snapshot detects both kinds of
/// change.
#[test]
fn report_grants_no_authority() {
    scene(&[], |mut scene| {
        serve_at(&mut scene, 3, 1);
        let token = token(&scene);
        let store = Shared::new();
        let mut client = crate::storage::store_tests::client(&store);
        let record = shard_at(token, 3, token.epoch.get() / 2);
        let shard = client.create_shard(record).unwrap();
        let key = StoreKey::Volume(volume("vol-0a"));
        let own = client
            .create(key, volume_record("vol-0a", VolumeState::Active))
            .unwrap();
        let binding = Some((record.owner, token.exhid));
        let now = scene.turn * 100;
        let owner = &mut scene.owner;
        owner.observe_shard_view(volume("vol-0a"), Some(&shard), Some(&own), binding, now);
        let keys = [StoreKey::Shard(record.shard), key];
        let before = snapshot(&scene, &store, &keys);
        let (state, _) = owner_serving();
        let mut writer = fixed(host(1), BOOT, 1);
        let mut foreign = fixed(host(2), BOOT, 1);
        let mut reader = Reader::default();
        // A filled driver part on alternate cycles, beside the empty one.
        let filled = Observed {
            enumeration: Enumeration::Matches,
            alarm: Some(crate::storage::store::Alarm::Clear),
            store: Some(crate::storage::store::Tally::default()),
            captures: Captures {
                refused: Some(0),
                abandoned: Some(0),
            },
            quarantine: Gauge::known(0, 3),
            suffix_due: Some(crate::storage::checkpoint::SuffixDue::default()),
            roll_due: Some(false),
            roll_active: Some(false),
            ..Observed::UNAVAILABLE
        };
        for cycle in 0..64 {
            let at = cycle * PERIOD.get();
            let observed = [Observed::UNAVAILABLE, filled][(cycle % 2) as usize];
            let entry = scene.owner.report_entry(at, &observed).unwrap();
            let sealed = writer.seal(&state, &[entry], at, at).unwrap();
            assert_eq!(reader.accept(&sealed, key_of).unwrap().entries, [entry]);
            // Foreign entries for the owner's shard carry every schema-3 field: a completed takeover at a later
            // tenure with a clear watermark, and a named standby on another volume.
            let claimed = VolumeEntry {
                volume: entry.volume,
                shard: entry.shard,
                ..owner_serving().1[0]
            };
            let later = VolumeEntry {
                role: Some(RecordedRole::Owner),
                tenure: Some((
                    ShardGeneration::new(4).unwrap(),
                    ActivatedEpoch::new(2).unwrap(),
                )),
                exit: Some(Exit {
                    operation: operation(9),
                    status: ExitStatus::Exited,
                }),
                watermark: Watermark::Clear,
                recovery: Recovery {
                    kind: Some(RecoveryKind::Takeover),
                    outcome: Some(RecoveryOutcome::Completed),
                    ..claimed.recovery
                },
                named: Some(false),
                ..claimed
            };
            let flipped = VolumeEntry {
                volume: volume("vol-0b"),
                role: Some(RecordedRole::Standby),
                withdrawal: Some(Withdrawal::Flipped),
                named: Some(true),
                ..claimed
            };
            let sealed = foreign.seal(&state, &[later, flipped], at, at).unwrap();
            reader.accept(&sealed, key_of).unwrap();
        }
        // A sealed reconciler status that rows the owner's shard as cold, as if a replacement served it.
        let mut part = status::tests::sample(1, 0);
        part.rows = vec![status::ExceptionRow {
            shard: record.shard,
            class: status::Class::Cold,
            standby: status::Standby::Past,
            age_us: 1,
        }];
        let sealed = status::tests::sealed(&[part.clone()]);
        let accepted = status::StatusReader::default().accept(&sealed, status::tests::key_of);
        assert_eq!(accepted.unwrap().zones, [part]);
        assert_eq!(snapshot(&scene, &store, &keys), before);
        client
            .replace(&own, volume_record("vol-0a", VolumeState::Retired))
            .unwrap();
        let written = snapshot(&scene, &store, &keys);
        assert_ne!(written, before, "a store write changes the snapshot");
        let withdraw = crate::failover::serving::Event::Withdraw(Cause::Planned);
        scene.owner.authority_event(withdraw, now);
        assert_ne!(
            snapshot(&scene, &store, &keys),
            written,
            "an authority event changes it"
        );
    });
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = vec![(
        "failover/report.rs".to_owned(),
        include_str!("../report.rs").to_owned(),
    )];
    crate::oracle::guard_tests::sources(&root, &root.join("failover/report"), &mut sources);
    sources.retain(|(path, _)| !test_source(path));
    let recovery = "failover/report/recovery.rs";
    for child in [recovery, "failover/report/observed.rs"] {
        assert!(
            sources.iter().any(|(path, _)| path == child),
            "{child} is scanned"
        );
    }
    for status in ["mod.rs", "part.rs", "build.rs", "events.rs", "codec.rs"] {
        let path = format!("failover/report/status/{status}");
        assert!(sources.iter().any(|(held, _)| *held == path), "{path}");
    }
    assert_eq!(write_paths(&sources), []);
    let found = PLANTS.map(|plant| {
        let planted: Vec<(String, String)> = sources
            .iter()
            .filter(|(path, _)| path == recovery)
            .map(|(path, text)| (path.clone(), format!("{text}\n{plant}")))
            .collect();
        write_paths(&planted)
    });
    assert_eq!(found, PLANTS.map(|_| vec![(recovery.to_owned(), "Device")]));
}

/// Inside a block comment or string literal, `//` leaves the closing delimiter active, so the guard must report the
/// `Device` use in the following function signature.
const PLANTS: [&str; 3] = [
    "// Device\nfn planted(_: &mut dyn Device) {}\n",
    "/*\n// */\nfn planted(_: &mut dyn Device) {}\n",
    "const PLANTED: &str = \"\n// \";\nfn planted(_: &mut dyn Device) {}\n",
];

fn write_paths(sources: &[(String, String)]) -> Vec<(String, &'static str)> {
    const SPELLINGS: [&str; 16] = [
        "Client",
        "Write::",
        "submit",
        "authority_event",
        "Event::",
        "Retirement",
        "Disk",
        "&mut self.volume",
        "StandbyGate",
        "OperatorRelease",
        "Provider",
        "ControlPlane",
        "take_over",
        "bump(",
        "designate",
        ".run(",
    ];
    const HANDLES: [&str; 3] = ["Device", "LocalRecords", "LocalSource"];
    let mut found = Vec::new();
    for (path, text) in sources {
        let code: Vec<&str> = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect();
        let code = code.join("\n");
        let tokens = crate::oracle::guard_tests::tokens(text);
        for spelling in SPELLINGS
            .into_iter()
            .filter(|spelling| code.contains(spelling))
        {
            found.push((path.clone(), spelling));
        }
        for handle in HANDLES.into_iter().filter(|handle| tokens.contains(handle)) {
            found.push((path.clone(), handle));
        }
    }
    found
}

/// The non-test sources that name `HostReport` or `VolumeEntry`: the report module, the readers that take a candidate
/// host, its headroom or its entries from an accepted report, the owner that builds an entry, the population proofs
/// that build a candidate's report, and the host agent and link that build and carry a host's entries.
const READERS: [&str; 12] = [
    "failover/report.rs",
    "failover/report/status/build.rs",
    "failover/standbys.rs",
    "failover/standbys/population_kani.rs",
    "failover/reconcile.rs",
    "net/owner.rs",
    "failover/zone_loop/evidence.rs",
    "failover/zone_loop/observe.rs",
    "failover/zone_loop/plan.rs",
    "failover/zone_loop/actuate.rs",
    "host/link.rs",
    "host/agent.rs",
];

/// Whether the tokens of `text` include `HostReport` or `VolumeEntry`. A token is a slice of its source, so a source
/// that holds neither name as text skips the tokenizer.
fn names_report(text: &str) -> bool {
    (text.contains("HostReport") || text.contains("VolumeEntry"))
        && crate::oracle::guard_tests::tokens(text)
            .into_iter()
            .any(|token| matches!(token, "HostReport" | "VolumeEntry"))
}

/// The sources of `sources`, given by their path under the crate's `src`, outside [`READERS`] whose tokens include
/// `HostReport` or `VolumeEntry`.
fn unlisted_readers(sources: &[(String, String)]) -> Vec<String> {
    sources
        .iter()
        .filter(|(path, text)| !READERS.contains(&path.as_str()) && names_report(text))
        .map(|(path, _)| path.clone())
        .collect()
}

/// The paths of [`READERS`] that `sources` lacks or holds with no `HostReport` or `VolumeEntry` token.
fn stale_readers(sources: &[(String, String)]) -> Vec<&'static str> {
    let reads = |listed: &str| {
        sources
            .iter()
            .any(|(path, text)| path == listed && names_report(text))
    };
    READERS
        .into_iter()
        .filter(|listed| !reads(listed))
        .collect()
}

/// Whether `path`, under the crate's `src`, is a test source: a `tests.rs`, a `*_tests.rs` or a file under a
/// `*_tests` directory.
fn test_source(path: &str) -> bool {
    let mut parts = path.rsplit('/');
    let name = parts.next().unwrap_or_default();
    name == "tests.rs" || name.ends_with("_tests.rs") || parts.any(|dir| dir.ends_with("_tests"))
}

/// REPORTS-CONFER-NO-AUTHORITY at the readers: no non-test source outside the allowlist names `HostReport` or
/// `VolumeEntry` as a token, so a new source that names a report type joins the list in review, and every listed
/// source names one, so the list holds exactly the sources that do. A comment and a longer identifier name no type,
/// a planted source that names `VolumeEntry` outside the list fails the check, and a listed source that is absent
/// or names a type only in a comment reads as stale. The check reads type names, so a source that holds an accepted
/// report through an inferred type passes it.
#[test]
fn report_types_appear_only_in_the_allowed_readers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    crate::oracle::guard_tests::sources(&root, &root, &mut sources);
    sources.retain(|(path, _)| !test_source(path));
    assert!(sources.iter().any(|(path, _)| path == "failover/report.rs"));
    assert!(
        !sources
            .iter()
            .any(|(path, _)| path == "failover/report/tests.rs")
    );
    assert_eq!(unlisted_readers(&sources), Vec::<String>::new());
    assert_eq!(stale_readers(&sources), Vec::<&str>::new());
    let plant = |text: &str| ("failover/zone_loop/unlisted.rs".to_owned(), text.to_owned());
    for named in [
        "// a VolumeEntry in prose",
        "fn count(entries: VolumeEntryCount) {}",
    ] {
        assert_eq!(
            unlisted_readers(&[plant(named)]),
            Vec::<String>::new(),
            "{named}"
        );
    }
    let unread: Vec<_> = sources
        .iter()
        .filter(|(path, _)| path != "net/owner.rs")
        .map(|(path, text)| match path.as_str() {
            "failover/standbys.rs" => (path.clone(), "// a HostReport in prose".to_owned()),
            _ => (path.clone(), text.clone()),
        })
        .collect();
    assert_eq!(
        stale_readers(&unread),
        ["failover/standbys.rs", "net/owner.rs"],
        "control: a listed source that names no report type, and one that is absent"
    );
    let reader = "fn plan(entry: &VolumeEntry) {}";
    let child = ("failover/report/publish.rs".to_owned(), reader.to_owned());
    assert_eq!(
        unlisted_readers(&[child]),
        ["failover/report/publish.rs"],
        "control: a production child of the report module is outside the allowlist"
    );
    sources.push(plant(reader));
    assert_eq!(
        unlisted_readers(&sources),
        ["failover/zone_loop/unlisted.rs"],
        "control: a reader outside the allowlist"
    );
}

/// The sources of `sources`, given by their path under the crate's `src`, outside the status module's files whose
/// tokens include `StatusReader` or `ReconcilerStatus`.
fn status_readers(sources: &[(String, String)]) -> Vec<String> {
    let names_status = |text: &str| {
        (text.contains("StatusReader") || text.contains("ReconcilerStatus"))
            && crate::oracle::guard_tests::tokens(text)
                .into_iter()
                .any(|token| matches!(token, "StatusReader" | "ReconcilerStatus"))
    };
    sources
        .iter()
        .filter(|(path, text)| !path.starts_with("failover/report/status/") && names_status(text))
        .map(|(path, _)| path.clone())
        .collect()
}

/// REPORTS-CONFER-NO-AUTHORITY at the status's readers: outside the status module's files, no non-test source names
/// `StatusReader` or `ReconcilerStatus` as a token, so production code accepts no status and holds no decoded one.
/// A comment and a longer identifier name neither type, a planted source that accepts a status fails the check, and
/// the status module's own files are outside it. The check reads type names, so a source that holds a decoded
/// status through an inferred type passes it.
#[test]
fn no_production_source_outside_the_status_module_reads_a_status() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    crate::oracle::guard_tests::sources(&root, &root, &mut sources);
    sources.retain(|(path, _)| !test_source(path));
    let codec = "failover/report/status/codec.rs";
    assert!(
        sources
            .iter()
            .any(|(path, text)| path == codec && text.contains("pub struct StatusReader")),
        "the scan reads the file that defines the reader"
    );
    assert_eq!(status_readers(&sources), Vec::<String>::new());
    let plant = |text: &str| ("failover/reconcile.rs".to_owned(), text.to_owned());
    for named in [
        "// a StatusReader in prose",
        "fn count(readers: StatusReaderCount) {}",
    ] {
        assert_eq!(
            status_readers(&[plant(named)]),
            Vec::<String>::new(),
            "{named}"
        );
    }
    for reader in [
        "fn zones(reader: &mut StatusReader, bytes: &[u8]) {}",
        "fn zones(status: &ReconcilerStatus) -> usize { status.zones.len() }",
    ] {
        assert_eq!(
            status_readers(&[plant(reader)]),
            ["failover/reconcile.rs"],
            "control: {reader}"
        );
    }
}

/// The schema gate: the contract's sealed schema-2 report refuses with `Schema { found: 2 }` before the key lookup,
/// and the reader keeps the state it had.
#[test]
fn a_sealed_schema_2_report_refuses_by_schema() {
    let contract = contract();
    let refusal = &contract["refusals"]["schema-2"];
    assert_eq!(refusal["error"], "schema 2");
    let bytes = unhex(refusal["bytes"].as_str().unwrap());
    // The fixture is a sealed schema-2 report of one entry: a 48-byte header, a 156-byte host part and a 189-byte
    // entry, tagged under the fixture's report key.
    assert_eq!(
        (&bytes[..6], bytes.len()),
        (&b"HRPT\0\x02"[..], 48 + 156 + 189 + TAG_LEN)
    );
    let (body, tag) = bytes.split_at(bytes.len() - TAG_LEN);
    assert_eq!(hmac(&ReportKey::derive(&KEY).0, &[DOMAIN, body]), tag);
    let (state, entries) = owner_serving();
    let mut reader = Reader::default();
    reader.accept(&sealed(1, &state, &entries), key_of).unwrap();
    let kept = boots(&reader, host(WRITER_HOST)).to_vec();
    let calls = Cell::new(0);
    let refused = reader.accept(&bytes, |host| {
        calls.set(calls.get() + 1);
        key_of(host)
    });
    assert_eq!(
        (refused, calls.get()),
        (Err(ReportError::Schema { found: 2 }), 0)
    );
    assert_eq!(boots(&reader, host(WRITER_HOST)), kept);
    assert_eq!(reader.seen.len(), 1);
}

/// An entry with every field at its largest encodable value: the last label of each table, every flag set, the
/// largest counts, times and identities, and every gauge at `u64::MAX` of `u64::MAX`.
fn largest(at: usize) -> VolumeEntry {
    fn last<T: Copy>(table: &[T]) -> Option<T> {
        table.last().copied()
    }
    let top = known(u64::MAX, u64::MAX);
    let most = Some(u64::MAX);
    VolumeEntry {
        volume: volume(&format!("vol-{at:017x}")),
        shard: Shard::new(u32::MAX).unwrap(),
        role: last(ROLES),
        tenure: Some((
            ShardGeneration::new(u32::MAX.into()).unwrap(),
            ActivatedEpoch::new(ActivatedEpoch::MAX).unwrap(),
        )),
        volume_state: last(&STATES),
        serving: last(SERVING),
        withheld: true,
        quarantine: true,
        flip: true,
        withdrawal: last(WITHDRAWALS),
        refusal: last(REFUSALS),
        enumeration: last(ENUMERATIONS).unwrap(),
        watermark: last(WATERMARKS).unwrap(),
        report_age_us: most,
        own_records: Some(u32::MAX),
        checkpoint: Some(NamedCheckpoint {
            slot: u32::MAX,
            session: u64::MAX,
            capture: u32::MAX,
            units: u32::MAX,
        }),
        checkpoint_age_us: most,
        captures: Captures {
            refused: most,
            abandoned: most,
        },
        exit: Some(Exit {
            operation: operation(0xFF),
            status: *EXITS.last().unwrap(),
        }),
        pressure: Pressure {
            frontier: top,
            ancestry: top,
            quarantine: top,
            full: known(3, 3),
        },
        registrants: last(REGISTRANTS),
        hold: last(HOLDS),
        readiness: last(READINESS),
        metadata: last(METADATA),
        load_refusal: last(LOAD_REFUSALS),
        recovery: Recovery {
            kind: last(KINDS),
            outcome: last(OUTCOMES),
            check: last(CHECKS),
            next: last(NEXTS),
            store: last(STORE_CLASSES),
            attempts: Some(u32::MAX),
            age_us: most,
        },
        phase: last(PHASES),
        ended: last(ENDINGS),
        named: Some(true),
        roll_due: Some(true),
        roll_active: Some(true),
        publication_due: Some(true),
        times: RecoveryTimes {
            loaded_us: most,
            live_us: most,
            first_hit_us: most,
            retained_us: most,
            fill_us: most,
        },
        retention: Some(Retention {
            first_damage: Some(Damage::Content),
            installed: u64::MAX,
            omitted: u64::MAX,
            held_units: u64::MAX,
            failed_units: u32::MAX,
            unread_units: u32::MAX,
            suffix_damage: u32::MAX,
            suffix_tails: u32::MAX,
            suffix_dropped: u64::MAX,
            suffix_unread: u64::MAX,
            slot_superseded: u64::MAX,
            slot_withheld: u64::MAX,
        }),
        suffix: Backlog {
            blocks: top,
            flush_lag_us: most,
        },
        recovery_io: RecoveryIo {
            peak: top,
            saturated: most,
        },
        attaches: top,
        store: StoreOutcomes {
            unknown: most,
            unavailable: most,
            refused: most,
            log: most,
        },
        coverage: Coverage {
            saturated: top,
            largest: top,
        },
        invalidations: top,
        read_defects: most,
        served: most,
    }
}

/// REPORT-BOUNDED at the bound: a report of `MAX_ENTRIES` entries with every field at its largest value seals to
/// exactly `MAX_LEN` bytes and accepts to the equal report.
#[test]
fn a_maximum_report_seals_and_accepts_at_max_len() {
    let top = known(u64::MAX, u64::MAX);
    let host = HostState {
        build: BuildIdentity {
            era: u32::MAX,
            digest: Some([0xFF; 32]),
        },
        headroom: Headroom {
            ram: top,
            cpu_load: top,
            iops: top,
            bandwidth: top,
            attachments: top,
            workers: top,
            recovery: top,
        },
        health: HEALTH.last().copied(),
        detector: Detector {
            peers: Members::Known {
                used: u64::MAX,
                limit: u64::MAX,
            },
            self_suspect_us: Some(u64::MAX),
            nominations: Some(u64::MAX),
        },
        producer_missing: Members::Known {
            used: u64::MAX,
            limit: u64::MAX,
        },
        recovery_io: top,
    };
    let entries: Vec<VolumeEntry> = (0..MAX_ENTRIES).map(largest).collect();
    let bytes = writer(u64::MAX - 1)
        .seal(&host, &entries, u64::MAX, 0)
        .unwrap();
    assert_eq!(bytes.len(), MAX_LEN);
    let report = Reader::default().accept(&bytes, key_of).unwrap();
    let expected = HostReport {
        writer: writer(1).envelope.id,
        sequence: u64::MAX - 1,
        sealed_at_us: u64::MAX,
        host,
        entries,
    };
    assert_eq!(report, expected);
}

/// The public entry codec: `VolumeEntry::encode` returns only bytes `VolumeEntry::decode` accepts, so an entry with a
/// checkpoint age and no checkpoint, or with a gauge above its limit, refuses at both and at `Writer::seal` with
/// `Field`, and a label byte one past its table refuses at the decoder with `Flag`.
#[test]
fn the_entry_codec_refuses_what_its_decoder_refuses() {
    let (state, entries) = owner_serving();
    let base = entries[0];
    let aged = VolumeEntry {
        checkpoint: None,
        ..base
    };
    let over = VolumeEntry {
        attaches: Gauge::Known {
            used: 4,
            limit: NonZeroU64::new(3).unwrap(),
        },
        ..base
    };
    for invalid in [aged, over] {
        assert_eq!(invalid.encode(), Err(ReportError::Field));
        assert_eq!(
            VolumeEntry::decode(&entry_bytes(&invalid)),
            Err(ReportError::Field)
        );
        let refused = writer(1).seal(&state, &[invalid], 0, 0);
        assert_eq!(refused, Err(SealError::Field(ReportError::Field)));
    }
    let mut past = base.encode().unwrap();
    past[label_offset("role") - ENTRY] = ROLES.len() as u8 + 1;
    assert_eq!(VolumeEntry::decode(&past), Err(ReportError::Flag));
    let unserved = VolumeEntry {
        serving: None,
        withheld: true,
        ..base
    };
    assert_eq!(unserved.encode(), Err(ReportError::Flag));
    let refused = writer(1).seal(&state, &[unserved], 0, 0);
    assert_eq!(refused, Err(SealError::Field(ReportError::Flag)));
}

/// Each second-byte flag owns a value bit and a known bit four above it, so it reads unavailable, false or true
/// through the codec and the contract's wire table, and a value bit without its known bit refuses with `Flag`.
#[test]
fn second_byte_flags_distinguish_unknown_false_and_true() {
    let contract = contract();
    let (state, entries) = owner_serving();
    for at in 0..4 {
        for (value, byte) in [
            (None, 0u8),
            (Some(false), 0x10 << at),
            (Some(true), 0x11 << at),
        ] {
            let flag = |bit: usize| if bit == at { value } else { None };
            let entry = VolumeEntry {
                named: flag(0),
                roll_due: flag(1),
                roll_active: flag(2),
                publication_due: flag(3),
                ..entries[0]
            };
            let bytes = sealed(1, &state, &[entry]);
            assert_eq!(bytes[ENTRY + 201], byte, "flag {at} {value:?}");
            let report = Reader::default().accept(&bytes, key_of).unwrap();
            assert_wire_report(&contract, &bytes, &view(&report), "a second-byte flag");
            assert_eq!(report.entries, [entry]);
            if value == Some(true) {
                let unknown = edited(&bytes, |bytes| bytes[ENTRY + 201] = 1 << at);
                let refused = Reader::default().accept(&unknown, key_of);
                assert_eq!(
                    refused,
                    Err(ReportError::Flag),
                    "flag {at} without its known bit"
                );
            }
        }
    }
}

/// The member counts of the host part read a known empty population as 0 of 0, apart from an unavailable one, and
/// refuse a count above its population with `Field`.
#[test]
fn member_counts_tell_an_empty_population_from_a_missing_one() {
    let (state, entries) = owner_serving();
    let empty = Members::Known { used: 0, limit: 0 };
    for counts in [empty, Members::Unavailable] {
        let host = HostState {
            detector: Detector {
                peers: counts,
                ..state.detector
            },
            producer_missing: counts,
            ..state
        };
        let bytes = sealed(1, &host, &[]);
        assert_eq!(Reader::default().accept(&bytes, key_of).unwrap().host, host);
    }
    let sealed_empty = |counts| {
        let host = HostState {
            producer_missing: counts,
            ..state
        };
        sealed(1, &host, &entries)
    };
    assert_ne!(sealed_empty(empty), sealed_empty(Members::Unavailable));
    let over = HostState {
        producer_missing: Members::Known { used: 1, limit: 0 },
        ..state
    };
    let refused = writer(1).seal(&over, &entries, 0, 0);
    assert_eq!(refused, Err(SealError::Field(ReportError::Field)));
}

/// The recovery part's field rules: a known attempt count of zero with no kind seals, accepts beside other entries
/// and round-trips; with no kind, an outcome, a check, a next step, a store class or an age refuses with `Field`; a
/// check, a next step or a store class beside a running or completed outcome refuses with `Field`, while a refused
/// or unavailable outcome carries all three; and a retention account whose failed or unread units carry no first
/// damage refuses with `Field`, while one with a damage and no failed unit accepts.
#[test]
fn recovery_fields_follow_their_kind_outcome_and_damage() {
    let (state, entries) = owner_serving();
    let blank = standby_unavailable().1[0];
    let unattempted = VolumeEntry {
        recovery: Recovery {
            attempts: Some(0),
            ..Recovery::UNAVAILABLE
        },
        ..blank
    };
    let unavailable = VolumeEntry {
        volume: volume("vol-0c"),
        ..blank
    };
    let report = [unattempted, entries[0], unavailable];
    let bytes = sealed(1, &state, &report);
    assert_eq!(
        Reader::default().accept(&bytes, key_of).unwrap().entries,
        report
    );
    assert_eq!(
        unattempted
            .encode()
            .and_then(|bytes| VolumeEntry::decode(&bytes)),
        Ok(unattempted)
    );
    let refusing = Recovery {
        kind: Some(RecoveryKind::Takeover),
        outcome: Some(RecoveryOutcome::Refused),
        check: Some(RecoveryCheck::TakeOver),
        next: Some(RecoveryNext::Restart),
        store: Some(StoreClass::Unknown),
        attempts: Some(1),
        age_us: Some(5),
    };
    let unkinded = Recovery::UNAVAILABLE;
    let with = |recovery| VolumeEntry { recovery, ..blank };
    let refused = [
        Recovery {
            outcome: Some(RecoveryOutcome::Running),
            ..unkinded
        },
        Recovery {
            check: refusing.check,
            ..unkinded
        },
        Recovery {
            next: refusing.next,
            ..unkinded
        },
        Recovery {
            store: refusing.store,
            ..unkinded
        },
        Recovery {
            age_us: Some(0),
            ..unkinded
        },
    ]
    .into_iter()
    .chain(
        [RecoveryOutcome::Running, RecoveryOutcome::Completed]
            .into_iter()
            .flat_map(|outcome| {
                let settled = Recovery {
                    outcome: Some(outcome),
                    check: None,
                    next: None,
                    store: None,
                    ..refusing
                };
                [
                    Recovery {
                        check: refusing.check,
                        ..settled
                    },
                    Recovery {
                        next: refusing.next,
                        ..settled
                    },
                    Recovery {
                        store: refusing.store,
                        ..settled
                    },
                ]
            }),
    );
    for recovery in refused {
        assert_eq!(
            with(recovery).encode(),
            Err(ReportError::Field),
            "{recovery:?}"
        );
        let sealed = writer(1).seal(&state, &[with(recovery)], 0, 0);
        assert_eq!(sealed, Err(SealError::Field(ReportError::Field)));
    }
    for outcome in [Some(RecoveryOutcome::Refused), None] {
        let entry = with(Recovery {
            outcome,
            ..refusing
        });
        let bytes = sealed(1, &state, &[entry]);
        assert_eq!(
            Reader::default().accept(&bytes, key_of).unwrap().entries,
            [entry]
        );
    }
    let account = entries[0].retention.unwrap();
    for (failed_units, unread_units) in [(1, 0), (0, 1)] {
        let entry = VolumeEntry {
            retention: Some(Retention {
                first_damage: None,
                failed_units,
                unread_units,
                ..account
            }),
            ..blank
        };
        assert_eq!(
            entry.encode(),
            Err(ReportError::Field),
            "{failed_units} {unread_units}"
        );
    }
    let cross = VolumeEntry {
        retention: Some(Retention {
            first_damage: Some(Damage::Content),
            failed_units: 0,
            unread_units: 0,
            ..account
        }),
        ..blank
    };
    assert_eq!(
        cross.encode().and_then(|bytes| VolumeEntry::decode(&bytes)),
        Ok(cross)
    );
    // A first damage matches its unit counts: an unread one has unread units and no failed one, and a header, chunk
    // or unit-count damage has a failed unit.
    for (first_damage, failed_units, unread_units) in [
        (Damage::Unread, 1, 1),
        (Damage::Unread, 0, 0),
        (Damage::Header, 0, 1),
        (Damage::Chunk, 0, 0),
        (Damage::Units, 0, 2),
    ] {
        let entry = VolumeEntry {
            retention: Some(Retention {
                first_damage: Some(first_damage),
                failed_units,
                unread_units,
                ..account
            }),
            ..blank
        };
        assert_eq!(entry.encode(), Err(ReportError::Field), "{first_damage:?}");
    }
    // A store class names the error of a refusing check, so it needs one.
    let unchecked = with(Recovery {
        check: None,
        ..refusing
    });
    assert_eq!(unchecked.encode(), Err(ReportError::Field));
    let sealed_unchecked = writer(1).seal(&state, &[unchecked], 0, 0);
    assert_eq!(sealed_unchecked, Err(SealError::Field(ReportError::Field)));
    // A completed attempt with a check fails before a later malformed phase byte.
    let mut both = with(Recovery {
        outcome: Some(RecoveryOutcome::Completed),
        next: None,
        store: None,
        ..refusing
    })
    .encode()
    .unwrap_err();
    assert_eq!(both, ReportError::Field);
    let mut bytes = with(refusing).encode().unwrap();
    bytes[label_offset("recovery.outcome") - ENTRY] = 2;
    bytes[label_offset("phase") - ENTRY] = u8::MAX;
    both = VolumeEntry::decode(&bytes).unwrap_err();
    assert_eq!(
        both,
        ReportError::Field,
        "the outcome rule sits at the store label"
    );
    // Known milestone times follow the recorder's order, equal ticks included, and the retained time is the live
    // time; a fill or first hit before live, a load after live and a retained time apart from live refuse.
    let timed = |times| VolumeEntry { times, ..blank };
    let ordered = RecoveryTimes {
        loaded_us: Some(40),
        live_us: Some(90),
        first_hit_us: Some(90),
        retained_us: Some(90),
        fill_us: Some(120),
    };
    assert_eq!(
        timed(ordered)
            .encode()
            .and_then(|bytes| VolumeEntry::decode(&bytes)),
        Ok(timed(ordered))
    );
    for times in [
        RecoveryTimes {
            first_hit_us: Some(89),
            ..ordered
        },
        RecoveryTimes {
            fill_us: Some(89),
            ..ordered
        },
        RecoveryTimes {
            loaded_us: Some(91),
            ..ordered
        },
        RecoveryTimes {
            retained_us: Some(91),
            ..ordered
        },
        RecoveryTimes {
            live_us: None,
            first_hit_us: Some(89),
            ..ordered
        },
    ] {
        assert_eq!(timed(times).encode(), Err(ReportError::Field), "{times:?}");
    }
    // A known empty suffix backlog reads no lag, and the history pressure counts three resources.
    let backlog = |blocks, flush_lag_us| VolumeEntry {
        suffix: Backlog {
            blocks,
            flush_lag_us,
        },
        ..blank
    };
    assert!(backlog(known(0, 8), Some(0)).encode().is_ok());
    assert!(backlog(known(1, 8), Some(0)).encode().is_ok());
    assert!(backlog(Gauge::Unavailable, Some(5)).encode().is_ok());
    assert_eq!(
        backlog(known(0, 8), Some(1)).encode(),
        Err(ReportError::Field)
    );
    let full = |gauge| VolumeEntry {
        pressure: Pressure {
            full: gauge,
            ..blank.pressure
        },
        ..blank
    };
    for used in 0..=3 {
        assert!(full(known(used, 3)).encode().is_ok(), "{used} of 3");
    }
    for limit in [1, 4] {
        assert_eq!(
            full(known(1, limit)).encode(),
            Err(ReportError::Field),
            "1 of {limit}"
        );
        let sealed_full = writer(1).seal(&state, &[full(known(1, limit))], 0, 0);
        assert_eq!(sealed_full, Err(SealError::Field(ReportError::Field)));
    }
}

/// CLOSED-LABELS at each table's end: a label byte one past its table refuses with `Flag`, and so does a label byte
/// replaced by each byte of a volume identifier that lies past its table, so such an identity byte passes as no
/// label.
#[test]
fn label_bytes_refuse_past_their_tables_and_identity_bytes() {
    let contract = contract();
    let base = unhex(
        contract["cases"]["owner-serving"]["bytes"]
            .as_str()
            .unwrap(),
    );
    let identity = b"vol-0123456789abcdef";
    for (field, labels) in contract["labels"].as_object().unwrap() {
        let first = contract["label_first_code"][field].as_u64().unwrap() as usize;
        let past = first + labels.as_array().unwrap().len();
        let codes = [u8::try_from(past).unwrap()].into_iter().chain(
            identity
                .iter()
                .copied()
                .filter(|&code| usize::from(code) >= past),
        );
        for code in codes {
            let bytes = edited(&base, |bytes| bytes[label_offset(field)] = code);
            let refused = Reader::default().accept(&bytes, key_of);
            assert_eq!(refused, Err(ReportError::Flag), "{field} {code}");
        }
    }
}

/// The recorded-holder and no-holder holds and the unverified withdrawal read labels of their own beside the Report-triggered causes, and a
/// conversion that folds the recorded-holder hold into `report` fails the check.
#[test]
fn the_hold_causes_read_their_own_withdrawal_labels() {
    let split = |convert: fn(Cause) -> Withdrawal| {
        let causes = [
            Cause::Report(ReportTrigger::new(NotSole::ForeignHolder).unwrap()),
            Cause::RecordedHolder,
            Cause::Unheld,
            Cause::Unverified,
        ];
        causes.map(|cause| withdrawal_label(convert(cause)))
            == ["report", "recorded-holder", "unheld", "unverified"]
    };
    assert!(split(Withdrawal::from));
    let folded: fn(Cause) -> Withdrawal = |cause| match cause {
        Cause::RecordedHolder => Withdrawal::Report,
        cause => Withdrawal::from(cause),
    };
    assert!(
        !split(folded),
        "control: the recorded-holder hold folded into report"
    );
}

/// WRITER-SEQUENCE, the key binding and the schema gate: a sequence at or below its writer's high-water is dropped,
/// a forged report moves no high-water, the key lookup receives the header's host and a report naming another host
/// under this host's key refuses, boots are separate writers, the boot with the lowest highest seal time leaves the
/// window, an evicted boot's replay drops, a full window rejects another boot sealed at or below its lowest kept
/// seal time, and an input under 6 bytes or an unknown schema of any length refuses before the key lookup or any
/// later field, leaving the reader unchanged.
#[test]
fn writer_sequence_and_schema() {
    let (state, entries) = standby_unavailable();
    let report = |boot: [u8; 16], next, at| {
        fixed(host(WRITER_HOST), boot, next)
            .seal(&state, &entries, at, 0)
            .unwrap()
    };
    let writer_host = host(WRITER_HOST);
    let asked = Cell::new(None);
    let bound = |host: Host| {
        asked.set(Some(host));
        let key = if host == writer_host { KEY } else { [0x6C; 32] };
        Some(ReportKey::derive(&key))
    };
    assert!(Reader::default().accept(&report(BOOT, 1, 0), bound).is_ok());
    assert_eq!(asked.get(), Some(writer_host));
    let impostor = fixed(host(2), BOOT, 1)
        .seal(&state, &entries, 0, 0)
        .unwrap();
    assert_eq!(
        Reader::default().accept(&impostor, bound),
        Err(ReportError::Tag),
        "a report naming another host verifies only under that host's key"
    );
    assert_eq!(asked.get(), Some(host(2)));
    let mut reader = Reader::default();
    for (next, accepted) in [(1, true), (2, true), (2, false), (1, false), (3, true)] {
        let result = reader.accept(&report(BOOT, next, 0), key_of);
        match accepted {
            true => assert_eq!(result.unwrap().sequence, next),
            false => assert_eq!(result, Err(ReportError::Duplicate)),
        }
    }
    let mut forged = report(BOOT, 100, 0);
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert_eq!(reader.accept(&forged, key_of), Err(ReportError::Tag));
    assert_eq!(
        reader.accept(&report(BOOT, 4, 0), key_of).unwrap().sequence,
        4
    );
    let keyless = reader.accept(&report(BOOT, 5, 0), |_| None);
    assert_eq!(keyless, Err(ReportError::Writer));
    assert!(reader.accept(&report([0x11; 16], 1, 10), key_of).is_ok());
    assert!(reader.accept(&report(BOOT, 5, 20), key_of).is_ok());
    for (boot, at) in [(0x12, 30), (0x13, 40), (0x14, 50)] {
        assert!(reader.accept(&report([boot; 16], 1, at), key_of).is_ok());
    }
    let kept = |reader: &Reader| -> Vec<[u8; 16]> {
        boots(reader, writer_host)
            .iter()
            .map(|kept| kept.boot)
            .collect()
    };
    let window = [BOOT, [0x14; 16], [0x12; 16], [0x13; 16]];
    assert_eq!(kept(&reader), window, "the lowest seal leaves");
    for (boot, next, at) in [(0x11, 1, 10), (0x11, 2, 10), (0x21, 1, 5), (0x22, 1, 9)] {
        assert_eq!(
            reader.accept(&report([boot; 16], next, at), key_of),
            Err(ReportError::Duplicate),
            "a boot outside the window sealed at or below the lowest kept seal time drops: {boot:x} {next}"
        );
    }
    assert_eq!(kept(&reader), window);
    assert!(reader.accept(&report([0x15; 16], 1, 60), key_of).is_ok());
    let window = [[0x15; 16], [0x14; 16], [0x12; 16], [0x13; 16]];
    assert_eq!(kept(&reader), window);
    assert_eq!(
        reader.accept(&report(BOOT, 5, 20), key_of),
        Err(ReportError::Duplicate),
        "the evicted boot's replay drops"
    );
    // A boot sealed at or before the lowest kept seal time drops and the kept set stays.
    for at in [25, 30] {
        let dropped = reader.accept(&report([0x31; 16], 1, at), key_of);
        assert_eq!(dropped, Err(ReportError::Duplicate), "sealed at {at}");
    }
    assert_eq!(kept(&reader), window);
    // The lowest seal leaves even when its boot reported last, so acceptance order evicts nothing.
    assert!(reader.accept(&report([0x12; 16], 2, 31), key_of).is_ok());
    assert!(reader.accept(&report([0x40; 16], 1, 35), key_of).is_ok());
    assert_eq!(
        kept(&reader),
        [[0x15; 16], [0x14; 16], [0x40; 16], [0x13; 16]]
    );
    let replay = reader.accept(&report([0x12; 16], 3, 31), key_of);
    assert_eq!(replay, Err(ReportError::Duplicate));
    // A kept boot keeps its highest seal time, so after a boot whose clock stepped back leaves, the lowest kept seal
    // time still covers its earlier report.
    let mut stepped = Reader::default();
    let high = report([0x51; 16], 1, 100);
    for bytes in [&high, &report([0x51; 16], 2, 50)] {
        assert!(stepped.accept(bytes, key_of).is_ok());
    }
    for (boot, at) in [(0x52, 200), (0x53, 300), (0x54, 400), (0x55, 500)] {
        assert!(stepped.accept(&report([boot; 16], 1, at), key_of).is_ok());
    }
    assert_eq!(stepped.accept(&high, key_of), Err(ReportError::Duplicate));
    // A boot whose clock stepped back keeps its highest seal time in a full window, so the boot that leaves for a
    // newer one is the boot with the lowest highest seal time.
    let mut full = Reader::default();
    for (boot, next, at) in [
        (0x61, 1, 100),
        (0x61, 2, 50),
        (0x62, 1, 80),
        (0x63, 1, 90),
        (0x64, 1, 95),
        (0x65, 1, 96),
    ] {
        assert!(full.accept(&report([boot; 16], next, at), key_of).is_ok());
    }
    assert_eq!(
        kept(&full),
        [[0x61; 16], [0x65; 16], [0x63; 16], [0x64; 16]],
        "the boot sealed at 80 leaves, and the boot that sealed at 100 and then at 50 stays"
    );
    let kept = boots(&reader, writer_host).to_vec();

    for found in [0, 1, 0xFFFF] {
        let mut garbled = report(BOOT, 6, 0);
        garbled[4..6].copy_from_slice(&u16::to_be_bytes(found));
        garbled[6..].fill(0xEE);
        let mut oversized = garbled.clone();
        oversized.resize(MAX_LEN + 1, 0xEE);
        for bytes in [&garbled[..], &garbled[..6], &oversized[..]] {
            let calls = Cell::new(0);
            let refused = reader.accept(bytes, |_| {
                calls.set(calls.get() + 1);
                Some(ReportKey::derive(&KEY))
            });
            assert_eq!(refused, Err(ReportError::Schema { found }));
            assert_eq!(calls.get(), 0);
        }
    }
    let calls = Cell::new(0);
    for len in [0, 1, 5] {
        let refused = reader.accept(&report(BOOT, 7, 0)[..len], |_| {
            calls.set(calls.get() + 1);
            None
        });
        assert_eq!(refused, Err(ReportError::Length), "{len} bytes");
    }
    assert_eq!(calls.get(), 0);
    assert_eq!(boots(&reader, writer_host), kept);
}

/// WRITER-SEQUENCE for a boot outside a full window: the reader admits it once its seal time exceeds the oldest
/// kept boot's, and a kept boot's lower sequences drop by its high-water.
#[test]
fn a_boot_outside_the_window_drops_until_its_clock_passes_the_oldest_kept_boot() {
    let (state, entries) = standby_unavailable();
    let report = |boot: u8, next, at| {
        fixed(host(WRITER_HOST), [boot; 16], next)
            .seal(&state, &entries, at, 0)
            .unwrap()
    };
    let mut reader = Reader::default();
    for (boot, at) in [(0x52, 200), (0x53, 300), (0x54, 400), (0x55, 500)] {
        assert!(reader.accept(&report(boot, 1, at), key_of).is_ok());
    }
    let kept = boots(&reader, host(WRITER_HOST)).to_vec();
    for (next, at) in [(2, 150), (1, 160), (2, 150)] {
        assert_eq!(
            reader.accept(&report(0x61, next, at), key_of),
            Err(ReportError::Duplicate),
            "sequence {next} sealed at {at} before every kept boot"
        );
    }
    assert_eq!(boots(&reader, host(WRITER_HOST)), kept);
    assert_eq!(
        reader
            .accept(&report(0x61, 3, 250), key_of)
            .unwrap()
            .sequence,
        3
    );
    assert_eq!(
        reader.accept(&report(0x61, 1, 260), key_of),
        Err(ReportError::Duplicate),
        "a kept boot drops a lower sequence sealed later"
    );
    assert_eq!(
        reader.accept(&report(0x52, 2, 210), key_of),
        Err(ReportError::Duplicate),
        "the evicted boot's later seal time is below the new oldest kept boot"
    );
}

/// A boot's `sealed_at_us` stays nondecreasing across wall-clock steps, so a delayed lower sequence of a kept boot
/// drops by its high-water, and after the boot leaves the window its earlier reports, including a replay of an
/// accepted one, drop by the lowest kept seal time.
#[test]
fn an_evicted_boot_s_earlier_reports_drop_after_a_wall_clock_step() {
    let (state, entries) = standby_unavailable();
    let writer_host = host(WRITER_HOST);
    let mut stepped = fixed(writer_host, [0x51; 16], 1);
    let first = stepped.seal(&state, &entries, 1_000, 0).unwrap();
    let second = stepped.seal(&state, &entries, 100, PERIOD.get()).unwrap();
    let report = |boot: u8, at| {
        fixed(writer_host, [boot; 16], 1)
            .seal(&state, &entries, at, 0)
            .unwrap()
    };
    let mut reader = Reader::default();
    let accepted = reader.accept(&second, key_of).unwrap();
    for at in [200, 300, 400, 500] {
        assert!(reader.accept(&report(at as u8, at), key_of).is_ok());
    }
    assert_eq!(
        reader.accept(&first, key_of),
        Err(ReportError::Duplicate),
        "the delayed lower sequence"
    );
    assert_eq!(
        (accepted.sequence, accepted.sealed_at_us),
        (2, 1_000),
        "a backward step repeats the previous stamp"
    );
    for at in [1_100, 1_200, 1_300, 1_400] {
        assert!(reader.accept(&report((at / 100) as u8, at), key_of).is_ok());
    }
    let kept = |reader: &Reader| -> BTreeSet<[u8; 16]> {
        boots(reader, writer_host)
            .iter()
            .map(|kept| kept.boot)
            .collect()
    };
    assert_eq!(
        kept(&reader),
        [[11; 16], [12; 16], [13; 16], [14; 16]].into()
    );
    for replay in [&first, &second] {
        assert_eq!(reader.accept(replay, key_of), Err(ReportError::Duplicate));
    }
    let third = stepped
        .seal(&state, &entries, 1_500, 2 * PERIOD.get())
        .unwrap();
    let accepted = reader.accept(&third, key_of).unwrap();
    assert_eq!((accepted.sequence, accepted.sealed_at_us), (3, 1_500));
    assert_eq!(
        kept(&reader),
        [[0x51; 16], [12; 16], [13; 16], [14; 16]].into()
    );
    assert_eq!(reader.accept(&second, key_of), Err(ReportError::Duplicate));
}

pub(crate) fn authority(
    state: serving::State,
    epoch: u32,
    withdrawal: Option<Cause>,
) -> AuthorityReport {
    AuthorityReport {
        state,
        tenure: (
            ShardGeneration::new(3).unwrap(),
            ActivatedEpoch::new(epoch).unwrap(),
        ),
        report_age_us: None,
        freshness_age_us: None,
        withdrawal,
        flip: None,
        refusal: None,
        withheld: false,
        own_records: None,
        pending: false,
        registrants: None,
        hold: crate::storage::HoldState::Clear,
    }
}

fn shard_record(generation: u64) -> ShardRecord {
    ShardRecord {
        generation: ShardGeneration::new(generation).unwrap(),
        ..crate::storage::store_tests::record()
    }
}

/// The exit status is an observation keyed by operation identity: one request moves through withdrawal, waiting
/// and exit, ignoring records of another shard or a lower generation; another waits at its receipt tenure through
/// repeated views, a restarted authority's included, until a refusal that names it restarts it, and a successor
/// record and a later refusal leave the restart in place; a third restarts on a refusal that
/// names it; a fourth stays received under a later generation while its authority serves,
/// then exits on a withdrawal, since a successor ranks first; a fifth ignores a same-generation record under
/// another owner with no more attempts than the receipt's and exits on one with more; a closed authority withdraws
/// a sixth, which stays withdrawn with no record; a serving authority keeps a seventh received; a refusal restarts
/// an eighth from waiting; a new operation replaces a withdrawn ninth, and a refusal restarts it from withdrawn; a
/// resumed tenth keeps its status through a withdrawal and a refusal; each status, the `restarting-deadline` label
/// included, crosses seal and accept with its identity, and the build identity is the running executable's.
#[test]
fn exit_status_and_build_identity() {
    let (state, entries) = standby_unavailable();
    let mut reader = Reader::default();
    let mut next = 1;
    let mut carried = |exit: Option<Exit>| {
        let entry = VolumeEntry { exit, ..entries[0] };
        let sealed = sealed(next, &state, &[entry]);
        next += 1;
        reader.accept(&sealed, key_of).unwrap().entries[0].exit
    };
    let tracked = shard_record(3);
    let mut tracker = ExitTracker::new(tracked.shard, tracked.owner);
    let other_shard = ShardRecord {
        shard: Shard::new(tracked.shard.get() + 1).unwrap(),
        ..shard_record(9)
    };
    let serving3 = authority(serving::State::Serving, 2, None);
    let planned = authority(serving::State::Withdrawn, 2, Some(Cause::Planned));
    let a = operation(0xA1);
    let status = |tracker: &ExitTracker| tracker.last().map(|exit| exit.status);
    tracker.received(a, &serving3);
    let steps = [
        (serving3, None, ExitStatus::Received),
        (planned, None, ExitStatus::Withdrawn),
        (planned, Some(other_shard), ExitStatus::Withdrawn),
        (planned, Some(shard_record(2)), ExitStatus::Withdrawn),
        (planned, Some(shard_record(3)), ExitStatus::Waiting),
        (planned, Some(shard_record(4)), ExitStatus::Exited),
        (serving3, Some(shard_record(3)), ExitStatus::Exited),
    ];
    for (step, (authority, shard, expected)) in steps.into_iter().enumerate() {
        tracker.observe(&authority, shard.as_ref());
        tracker.received(a, &authority);
        assert_eq!(status(&tracker), Some(expected), "step {step}");
        assert_eq!(carried(tracker.last()), tracker.last());
        assert_eq!(tracker.last().unwrap().operation, a);
    }

    let b = operation(0xB2);
    tracker.received(b, &serving3);
    tracker.observe(&planned, None);
    tracker.observe(&planned, Some(&shard_record(3)));
    assert_eq!(status(&tracker), Some(ExitStatus::Waiting));
    let restarted = authority(serving::State::Serving, 4, None);
    for (authority, shard) in [
        (planned, Some(shard_record(3))),
        (planned, None),
        (restarted, Some(shard_record(3))),
    ] {
        tracker.observe(&authority, shard.as_ref());
        let waiting = Some(ExitStatus::Waiting);
        assert_eq!(status(&tracker), waiting, "a waiting request stays");
    }
    let volume = Some(ExitStatus::Restarting(Restart::Refused(Stale::Volume)));
    tracker.refused(b, Stale::Volume);
    assert_eq!(status(&tracker), volume, "a refusal from waiting");
    tracker.observe(&planned, Some(&shard_record(4)));
    tracker.refused(b, Stale::Target);
    assert_eq!(status(&tracker), volume, "a restart has ended");
    assert_eq!(carried(tracker.last()), tracker.last());
    let reserved = Some(Exit {
        operation: b,
        status: ExitStatus::Restarting(Restart::Deadline),
    });
    assert_eq!(carried(reserved), reserved, "the reserved deadline label");

    let c = operation(0xC3);
    tracker.received(c, &serving3);
    tracker.refused(a, Stale::Target);
    assert_eq!(status(&tracker), Some(ExitStatus::Received));
    tracker.refused(c, Stale::Target);
    tracker.refused(c, Stale::Volume);
    let refused = Some(ExitStatus::Restarting(Restart::Refused(Stale::Target)));
    assert_eq!(status(&tracker), refused);
    assert_eq!(carried(tracker.last()), tracker.last());
    assert_eq!(carried(tracker.last()).unwrap().operation, c);
    let d = operation(0xD4);
    tracker.received(d, &serving3);
    for view in 0..2 {
        tracker.observe(&serving3, Some(&shard_record(4)));
        let received = Some(ExitStatus::Received);
        assert_eq!(
            status(&tracker),
            received,
            "a serving owner has not exited: view {view}"
        );
    }
    tracker.observe(&planned, Some(&shard_record(4)));
    assert_eq!(status(&tracker), Some(ExitStatus::Exited));
    let [predecessor, handed] = [1, 2].map(|attempts| ShardRecord {
        owner: host(SPARE),
        attempts,
        ..shard_record(3)
    });
    tracker.received(operation(0xE5), &serving3);
    tracker.observe(&planned, Some(&predecessor));
    let withdrawn = Some(ExitStatus::Withdrawn);
    assert_eq!(
        status(&tracker),
        withdrawn,
        "no more attempts than the receipt's"
    );
    tracker.observe(&planned, Some(&handed));
    assert_eq!(
        status(&tracker),
        Some(ExitStatus::Exited),
        "a same-generation successor"
    );
    let closed = authority(serving::State::Closed, 2, None);
    tracker.received(operation(0xF6), &serving3);
    for view in 0..2 {
        tracker.observe(&closed, None);
        let withdrawn = Some(ExitStatus::Withdrawn);
        assert_eq!(status(&tracker), withdrawn, "closed, view {view}");
    }
    tracker.received(operation(0x17), &serving3);
    tracker.observe(&serving3, None);
    assert_eq!(
        status(&tracker),
        Some(ExitStatus::Received),
        "a serving authority keeps a received request"
    );
    let h = operation(0x28);
    tracker.received(h, &serving3);
    tracker.observe(&planned, None);
    tracker.observe(&planned, Some(&shard_record(3)));
    tracker.refused(h, Stale::Volume);
    assert_eq!(status(&tracker), volume, "a refusal from waiting");
    let (i, j) = (operation(0x39), operation(0x4A));
    tracker.received(i, &serving3);
    tracker.observe(&planned, None);
    tracker.received(j, &serving3);
    let replaced = Exit {
        operation: j,
        status: ExitStatus::Received,
    };
    assert_eq!(tracker.last(), Some(replaced));
    tracker.observe(&planned, None);
    tracker.refused(j, Stale::Target);
    assert_eq!(status(&tracker), refused, "a refusal from withdrawn");
    // A resumed request has ended, so neither a withdrawal nor a refusal replaces it.
    let k = operation(0x5B);
    tracker.received(k, &serving3);
    let resumed = Exit {
        operation: k,
        status: ExitStatus::Resumed(Resume::Cut),
    };
    tracker.last = tracker.last.map(|(_, receipt)| (resumed, receipt));
    tracker.observe(&planned, None);
    assert_eq!(tracker.last(), Some(resumed), "after a withdrawal");
    tracker.refused(k, Stale::Target);
    assert_eq!(tracker.last(), Some(resumed), "after a refusal");

    let build = BuildIdentity::running();
    let mut exe =
        std::io::BufReader::new(std::fs::File::open(std::env::current_exe().unwrap()).unwrap());
    let mut hash = Sha256::new();
    loop {
        let chunk = std::io::BufRead::fill_buf(&mut exe).unwrap();
        if chunk.is_empty() {
            break;
        }
        hash.update(chunk);
        let read = chunk.len();
        std::io::BufRead::consume(&mut exe, read);
    }
    let digest: [u8; 32] = hash.finalize().into();
    assert_eq!(
        build,
        BuildIdentity {
            era: records::ERA,
            digest: Some(digest)
        }
    );
    let running = HostState { build, ..state };
    let sealed = writer(1).seal(&running, &entries, 0, 0).unwrap();
    assert_eq!(
        Reader::default()
            .accept(&sealed, key_of)
            .unwrap()
            .host
            .build,
        build
    );
}

/// The history pressure counts the record's suffixes of `MAX_CHAIN` and the delta blocks its replay requires, from
/// the floor to the last suffix's end, of the region's `J`; `full` counts how many of the chain, the delta history
/// and the share's open window stand at their bound, of three, so a chain at its cap, a history filling the region
/// and a refused share window each add one, a history past the region reads `J` of `J`, a layout with no delta
/// region reads no frontier and counts its history at bound, and an input the producer lacks leaves its gauges
/// unavailable.
#[test]
fn the_history_pressure_reads_the_chain_and_the_required_delta_history() {
    let layout = crate::failover::records::Layout {
        units: 1 + 3 * 2 + 16,
        slots: 3,
        slot_units: 2,
        entries: 41,
    };
    let suffix = |epoch: u64, start, end| Suffix {
        session: (3 << 32) | epoch,
        start,
        certified: start,
        end,
    };
    let record = |cut, chain: &[Suffix]| ShardRecord {
        cut,
        ancestry: Ancestry::new(chain).unwrap(),
        ..crate::storage::store_tests::record()
    };
    let cases = [
        (
            record(7, &[]),
            (0, 0, 0),
            "no suffix requires nothing above the cut",
        ),
        (
            record(4, &[suffix(2, 2, 9), suffix(4, 9, 12)]),
            (2, 8, 0),
            "the floor is the cut above the first suffix's start",
        ),
        (
            record(3, &[suffix(2, 3, 19)]),
            (1, 16, 1),
            "a history filling the region reads full",
        ),
        (
            record(
                0,
                &[
                    suffix(2, 0, 2),
                    suffix(4, 2, 4),
                    suffix(6, 4, 6),
                    suffix(8, 6, 8),
                ],
            ),
            (4, 8, 1),
            "a chain at its cap reads full",
        ),
        (
            record(
                0,
                &[
                    suffix(2, 0, 4),
                    suffix(4, 4, 8),
                    suffix(6, 8, 12),
                    suffix(8, 12, 16),
                ],
            ),
            (4, 16, 2),
            "both at their bound",
        ),
    ];
    for (record, (chain, history, full), case) in cases {
        let pressure = Pressure::recorded(Some(&record), Some(&layout), false);
        assert_eq!(
            (pressure.ancestry, pressure.frontier, pressure.full),
            (known(chain, 4), known(history, 16), known(full, 3)),
            "{case}"
        );
        assert_eq!(pressure.quarantine, Gauge::Unavailable);
        let saturated = Pressure::recorded(Some(&record), Some(&layout), true);
        assert_eq!(
            saturated.full,
            known(full + 1, 3),
            "{case}: a full share window"
        );
    }
    let record = record(3, &[suffix(2, 3, 19)]);
    let unlaid = Pressure::recorded(Some(&record), None, false);
    assert_eq!(
        (unlaid.ancestry, unlaid.frontier, unlaid.full),
        (known(1, 4), Gauge::Unavailable, Gauge::Unavailable),
        "without the own volume's layout only the chain is known"
    );
    assert_eq!(
        Pressure::recorded(None, Some(&layout), false),
        unavailable_pressure()
    );
    let narrow = crate::failover::records::Layout {
        units: 1 + 3 * 2 + 8,
        ..layout
    };
    let past = Pressure::recorded(Some(&record), Some(&narrow), false);
    assert_eq!(
        (past.frontier, past.full),
        (known(8, 8), known(1, 3)),
        "a history past the region saturates the frontier and counts as full"
    );
    let regionless = crate::failover::records::Layout {
        units: 1 + 3 * 2,
        ..layout
    };
    let at_rest = ShardRecord {
        cut: 7,
        ancestry: Ancestry::new(&[]).unwrap(),
        ..crate::storage::store_tests::record()
    };
    let empty = Pressure::recorded(Some(&at_rest), Some(&regionless), false);
    assert_eq!(
        (empty.frontier, empty.full),
        (Gauge::Unavailable, known(1, 3)),
        "a layout with no delta region reads no frontier and holds its history at bound"
    );
}

/// The unresolved-history gauge counts the slots a tenure's possibly-named set holds quarantined or names for a
/// Publish no success settled: none at the tenure's start over a named slot, then one for each unknown Publish, with
/// a pending write naming the named slot and a second write to a counted slot adding nothing.
#[test]
fn the_unresolved_history_gauge_counts_quarantined_and_unsettled_slots() {
    use crate::storage::checkpoint::PossiblyNamed;
    let layout = crate::failover::records::Layout {
        units: 1 + 3 * 2,
        slots: 3,
        slot_units: 2,
        entries: 41,
    };
    let named = NamedCheckpoint {
        slot: 0,
        session: 2,
        capture: 1,
        units: 1,
    };
    let mut possible = PossiblyNamed::new((Shard::new(7).unwrap(), 2), layout, Some(named));
    assert_eq!(
        Pressure::unresolved(&possible),
        known(0, 3),
        "the named slot is resolved"
    );
    possible.submit(Some(1));
    assert_eq!(
        Pressure::unresolved(&possible),
        known(1, 3),
        "an unknown Publish"
    );
    possible.submit(Some(2));
    assert_eq!(
        Pressure::unresolved(&possible),
        known(2, 3),
        "two unknown Publishes fill the free slots"
    );
    possible.submit(Some(0));
    possible.submit(Some(1));
    assert_eq!(
        Pressure::unresolved(&possible),
        known(2, 3),
        "the named slot and a repeated slot count once at most"
    );
}

#[test]
fn a_draining_exit_withdraws_and_a_resumed_one_keeps_its_reason() {
    let tracked = shard_record(3);
    let serving3 = authority(serving::State::Serving, 2, None);
    let planned = authority(serving::State::Withdrawn, 2, Some(Cause::Planned));
    let status = |tracker: &ExitTracker| tracker.last().map(|exit| exit.status);
    let mut tracker = ExitTracker::new(tracked.shard, tracked.owner);
    tracker.draining();
    assert_eq!(status(&tracker), None, "no request, no status");
    tracker.received(operation(0xA1), &serving3);
    tracker.draining();
    assert_eq!(status(&tracker), Some(ExitStatus::Draining));
    tracker.observe(&serving3, None);
    assert_eq!(status(&tracker), Some(ExitStatus::Draining));
    tracker.observe(&planned, None);
    assert_eq!(status(&tracker), Some(ExitStatus::Withdrawn));
    tracker.resumed(Resume::Cut);
    tracker.draining();
    assert_eq!(
        status(&tracker),
        Some(ExitStatus::Withdrawn),
        "a withdrawn exit stays"
    );
    let mut resumed = ExitTracker::new(tracked.shard, tracked.owner);
    resumed.received(operation(0xB2), &serving3);
    resumed.draining();
    resumed.resumed(Resume::Store);
    let store = Some(ExitStatus::Resumed(Resume::Store));
    assert_eq!(status(&resumed), store);
    resumed.draining();
    resumed.observe(&planned, None);
    assert_eq!(status(&resumed), store, "a resumed exit has ended");
}

/// Under a handoff a record of the tracked shard at the receipt's generation and owner but a later `E` supersedes the
/// withdrawn tenure and exits the request, and only the receipt's own `(g, owner, E)` sets it waiting. Outside a
/// handoff the same later record of this host sets the withdrawn request waiting, as a same-host restart's does.
#[test]
fn a_handoff_exits_on_a_later_tenure_of_the_same_host_and_waits_only_at_the_receipt_tenure() {
    let serving = authority(serving::State::Serving, 2, None);
    let planned = authority(serving::State::Withdrawn, 2, Some(Cause::Planned));
    let at = |attempts| ShardRecord {
        attempts,
        ..shard_record(3)
    };
    let status = |tracker: &ExitTracker| tracker.last().map(|exit| exit.status);
    let receipt = at(1);
    let withdrawn = || {
        let mut tracker = ExitTracker::new(receipt.shard, receipt.owner);
        tracker.received(operation(0xC3), &serving);
        tracker.observe_handoff(&planned, None);
        assert_eq!(status(&tracker), Some(ExitStatus::Withdrawn));
        tracker
    };
    let mut later = withdrawn();
    later.observe_handoff(&planned, Some(&at(2)));
    assert_eq!(
        status(&later),
        Some(ExitStatus::Exited),
        "a later E of the same host"
    );
    let mut own = withdrawn();
    own.observe_handoff(&planned, Some(&receipt));
    assert_eq!(
        status(&own),
        Some(ExitStatus::Waiting),
        "the receipt's own tenure"
    );
    own.restarting(Restart::TransferUnknown);
    assert_eq!(
        status(&own),
        Some(ExitStatus::Restarting(Restart::TransferUnknown))
    );
    let mut ordinary = withdrawn();
    ordinary.observe(&planned, Some(&at(2)));
    assert_eq!(
        status(&ordinary),
        Some(ExitStatus::Waiting),
        "outside a handoff a same-host restart is no successor"
    );
}

/// An observation moves an exit by the authority and the record it reads: from each status that has not ended, a
/// successor record under a withdrawn or closed authority exits it, a withdrawn or closed authority withdraws a
/// received or draining exit, the receipt's record sets a withdrawn exit waiting, and every other pair keeps the
/// status, so no observation sets a `restarting` status: [`ExitTracker::restarting`] and [`ExitTracker::refused`]
/// record one.
#[test]
fn an_observation_moves_an_exit_by_its_authority_and_record() {
    use ExitStatus::{Draining, Exited, Received, Waiting, Withdrawn};
    let tracked = shard_record(3);
    let serving3 = authority(serving::State::Serving, 2, None);
    let planned = authority(serving::State::Withdrawn, 2, Some(Cause::Planned));
    let closed = authority(serving::State::Closed, 2, None);
    let other_shard = ShardRecord {
        shard: Shard::new(tracked.shard.get() + 1).unwrap(),
        ..shard_record(9)
    };
    let records = [
        (None, "none"),
        (Some(tracked), "own"),
        (Some(shard_record(4)), "successor"),
        (Some(other_shard), "other shard"),
    ];
    for start in [Received, Draining, Withdrawn, Waiting] {
        for (authority, stopped) in [(serving3, false), (planned, true), (closed, true)] {
            for (record, name) in &records {
                let mut tracker = ExitTracker::new(tracked.shard, tracked.owner);
                tracker.received(operation(0xA1), &serving3);
                match start {
                    Draining => tracker.draining(),
                    Withdrawn => tracker.withdrawn(),
                    Waiting => {
                        tracker.withdrawn();
                        tracker.observe(&planned, Some(&tracked));
                    }
                    _ => {}
                }
                assert_eq!(tracker.last().unwrap().status, start);
                tracker.observe(&authority, record.as_ref());
                let expected = match (start, stopped, *name) {
                    (_, true, "successor") => Exited,
                    (Received | Draining, true, _) => Withdrawn,
                    (Withdrawn, _, "own") => Waiting,
                    _ => start,
                };
                let after = tracker.last().unwrap().status;
                assert_eq!(after, expected, "{start:?}, stopped {stopped}, {name}");
            }
        }
    }
}
