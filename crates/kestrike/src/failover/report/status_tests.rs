use core::num::NonZeroU64;
use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::codec::tests::fixed;
use super::*;
use crate::failover::records::{ATTEMPTS_MAX, Host};
use crate::failover::report::tests::{hex, kebab, paths, unhex};
use crate::failover::report::{Members, ReportError, ReportKey, SealError};
use crate::failover::sim::host;
use crate::failover::standbys::Zone;
use crate::failover::zone_loop::status::Blocker;
use crate::net::ownership::Shard;

const CONTRACT: &str = include_str!("status_contract.json");
const KEY: [u8; 32] = [0xC3; 32];
const BOOT: [u8; 16] = [0x3C; 16];
const PERIOD: NonZeroU64 = NonZeroU64::new(1_000).unwrap();
const SEALED: u64 = 1_750_000_000_000_000;
const IDENTITY: u64 = 0x0A0B_0C0D_0E0F_1011;

pub(crate) fn status_key() -> StatusKey {
    StatusKey::derive(&KEY)
}

pub(crate) fn key_of(_: Host) -> Option<StatusKey> {
    Some(status_key())
}

pub(crate) fn writer() -> StatusWriter {
    writer_at(BOOT)
}

/// The fixtures' writer under the boot nonce `boot`.
pub(crate) fn writer_at(boot: [u8; 16]) -> StatusWriter {
    fixed(host(IDENTITY), boot, status_key(), PERIOD)
}

fn shard(number: u32) -> Shard {
    Shard::new(number).unwrap()
}

fn known(used: u64, limit: u64) -> Members {
    Members::Known { used, limit }
}

/// A part of `zone` whose count slots hold values that differ within each table, and `rows` exception rows aged
/// 10,000 s, 9,999 s and so on.
pub(crate) fn sample(zone: u16, rows: usize) -> ZonePart {
    let from = |base: u32| move |at: usize| base + at as u32;
    let events = Events {
        refused: core::array::from_fn(from(100)),
        reservations: core::array::from_fn(from(110)),
        enrollments: core::array::from_fn(from(120)),
        decisions: core::array::from_fn(from(130)),
        errors: core::array::from_fn(from(140)),
        creates: core::array::from_fn(from(160)),
        attaches: core::array::from_fn(from(170)),
        reclaims: core::array::from_fn(from(180)),
    };
    let classes = [
        Class::Recovering,
        Class::Withdrawn,
        Class::Blocked,
        Class::Silent,
        Class::Cold,
    ];
    let standbys = [
        Standby::Within,
        Standby::Past,
        Standby::Enrolling,
        Standby::Unknown,
    ];
    ZonePart {
        zone: Zone(zone),
        tick: 77,
        flags: Flags {
            reports: true,
            instances: true,
            volumes: false,
            store: true,
            warm_up: false,
            zone_host: false,
            operator: true,
            cap_below: true,
        },
        classes: core::array::from_fn(from(1)),
        stale_serving: 2,
        stale_oldest_us: Some(45_000_000),
        standby: core::array::from_fn(from(10)),
        needs: [3, 4],
        blockers: core::array::from_fn(from(20)),
        census: known(40, 64),
        attaches: Attaches {
            live: 5,
            ended_paired: 6,
            ended_unpaired: 7,
            gone: 8,
            pairs: known(9, 64),
            closed: [1, 2, 3, 4, 5],
        },
        receipts: [11, 12, 13, 14],
        volumes: [15, 16, 17, 18],
        unnamed_volumes: Some(28),
        hosts: Hosts {
            verdicts: [19, 20, 21, 22],
            silent: known(2, 61),
            self_suspect: 23,
        },
        budgets: Budgets {
            attempts: known(9, u64::from(ATTEMPTS_MAX)),
            generation: known(4, u64::from(u32::MAX) - 1),
        },
        store: StoreState {
            alarm: StoreAlarm::Namespace,
            outcomes: [24, 25, 26, 27],
        },
        events,
        omitted: if rows == MAX_ROWS { 3 } else { 0 },
        rows: (0..rows)
            .map(|at| ExceptionRow {
                shard: shard(1_000 + at as u32),
                class: classes[at % classes.len()],
                standby: standbys[at % standbys.len()],
                age_us: 10_000_000_000 - 1_000_000 * at as u64,
            })
            .collect(),
    }
}

fn members(members: Members) -> Value {
    match members {
        Members::Unavailable => Value::Null,
        Members::Known { used, limit } => json!({"used": used, "limit": limit}),
    }
}

fn of<T: core::fmt::Debug>(table: &[T]) -> Vec<String> {
    table.iter().map(kebab).collect()
}

/// Per count table and label field, its label names: name `k` labels slot `k` or wire code `k`.
pub(crate) fn tables() -> Value {
    let blockers = Blocker::ALL;
    use crate::failover::loss::Health;
    use crate::failover::standbys::{Closed, Need};
    use crate::failover::zone_loop::evidence::HostEvidence;
    let positions = [
        [need_at(Need::Standby), need_at(Need::Fresh)].to_vec(),
        [
            HostEvidence::Live,
            HostEvidence::Lost,
            HostEvidence::Conflict,
            HostEvidence::Unknown,
        ]
        .map(verdict_at)
        .to_vec(),
        [
            Some(Health::Available),
            Some(Health::Impaired),
            Some(Health::Lost),
            None,
        ]
        .map(health_at)
        .to_vec(),
        [
            Closed::LiveCap,
            Closed::EntryCap,
            Closed::PairCap,
            Closed::OwnEntry,
            Closed::KeyTaken,
        ]
        .map(closed_at)
        .to_vec(),
    ];
    for listed in positions {
        assert_eq!(
            listed,
            (0..listed.len()).collect::<Vec<_>>(),
            "each value has its own slot"
        );
    }
    json!({
        "class": of(CLASSES),
        "standby": of(STANDBYS),
        "standby.counts": of(&STANDBYS[..STANDBYS.len() - 1]),
        "blockers": of(&blockers),
        "needs": ["standby", "fresh"],
        "receipts": of(RECEIPTS),
        "volumes": ["available", "impaired", "lost", "unknown"],
        "verdicts": ["live", "lost", "conflict", "unknown"],
        "closed": ["live-cap", "entry-cap", "pair-cap", "own-entry", "key-taken"],
        "store.alarm": of(STORE_ALARMS),
        "store.outcomes": ["unknown", "unavailable", "refused", "log"],
        "events.refused": of(REFUSED),
        "events.reservations": of(RESERVATIONS),
        "events.enrollments": of(ENROLLMENTS),
        "events.decisions": of(DECISIONS),
        "events.errors": of(STEP_ERRORS),
        "events.creates": of(CREATES),
        "events.attaches": of(ATTACHES),
        "events.reclaims": of(RECLAIMS),
        "flags": [
            "reports", "instances", "volumes", "store", "warm-up", "zone-host", "operator", "cap-below",
        ],
    })
}

fn named(tables: &Value, table: &str, counts: &[u32]) -> Value {
    let listed = tables[table].as_array().unwrap();
    assert_eq!(listed.len(), counts.len(), "{table}");
    let names = listed.iter().map(|name| name.as_str().unwrap().to_owned());
    Value::Object(names.zip(counts.iter().map(|&n| json!(n))).collect())
}

/// The contract view of one part.
pub(crate) fn part_view(p: &ZonePart) -> Value {
    let t = tables();
    let f = p.flags;
    let flags = [
        f.reports,
        f.instances,
        f.volumes,
        f.store,
        f.warm_up,
        f.zone_host,
        f.operator,
        f.cap_below,
    ];
    let flag_names = t["flags"].as_array().unwrap().iter();
    let flag_names = flag_names.map(|name| name.as_str().unwrap().to_owned());
    let e = &p.events;
    json!({
        "zone": p.zone.0,
        "tick": p.tick,
        "flags": Value::Object(flag_names.zip(flags.map(Value::Bool)).collect()),
        "classes": named(&t, "class", &p.classes),
        "stale_serving": p.stale_serving,
        "stale_oldest_us": p.stale_oldest_us,
        "standby": named(&t, "standby.counts", &p.standby),
        "needs": named(&t, "needs", &p.needs),
        "blockers": named(&t, "blockers", &p.blockers),
        "census": members(p.census),
        "attaches": {
            "live": p.attaches.live,
            "ended_paired": p.attaches.ended_paired,
            "ended_unpaired": p.attaches.ended_unpaired,
            "gone": p.attaches.gone,
            "pairs": members(p.attaches.pairs),
            "closed": named(&t, "closed", &p.attaches.closed),
        },
        "receipts": named(&t, "receipts", &p.receipts),
        "volumes": named(&t, "volumes", &p.volumes),
        "unnamed_volumes": p.unnamed_volumes,
        "hosts": {
            "verdicts": named(&t, "verdicts", &p.hosts.verdicts),
            "silent": members(p.hosts.silent),
            "self_suspect": p.hosts.self_suspect,
        },
        "budgets": {
            "attempts": members(p.budgets.attempts),
            "generation": members(p.budgets.generation),
        },
        "store": {
            "alarm": kebab(p.store.alarm),
            "outcomes": named(&t, "store.outcomes", &p.store.outcomes),
        },
        "events": {
            "refused": named(&t, "events.refused", &e.refused),
            "reservations": named(&t, "events.reservations", &e.reservations),
            "enrollments": named(&t, "events.enrollments", &e.enrollments),
            "decisions": named(&t, "events.decisions", &e.decisions),
            "errors": named(&t, "events.errors", &e.errors),
            "creates": named(&t, "events.creates", &e.creates),
            "attaches": named(&t, "events.attaches", &e.attaches),
            "reclaims": named(&t, "events.reclaims", &e.reclaims),
        },
        "omitted": p.omitted,
        "rows": p.rows.iter().map(|row| json!({
            "shard": row.shard.get(),
            "class": kebab(row.class),
            "standby": kebab(row.standby),
            "age_us": row.age_us,
        })).collect::<Vec<_>>(),
    })
}

/// The contract view of a status.
pub(crate) fn view(status: &ReconcilerStatus) -> Value {
    json!({
        "writer": {"host": status.writer.host.get(), "boot": hex(&status.writer.boot)},
        "sequence": status.sequence,
        "sealed_at_us": status.sealed_at_us,
        "zones": status.zones.iter().map(part_view).collect::<Vec<_>>(),
    })
}

/// The fixture cases: an empty status, one quiet zone without rows, and two zones with rows.
fn cases() -> Vec<(&'static str, Vec<ZonePart>)> {
    let mut quiet = sample(1, 0);
    quiet.census = Members::Unavailable;
    quiet.stale_serving = 0;
    quiet.stale_oldest_us = None;
    quiet.unnamed_volumes = None;
    quiet.store.alarm = StoreAlarm::Clear;
    vec![
        ("empty", Vec::new()),
        ("one-zone", vec![quiet]),
        ("two-zones", vec![sample(1, 3), sample(2, MAX_ROWS)]),
    ]
}

pub(crate) fn sealed(zones: &[ZonePart]) -> Vec<u8> {
    writer().seal(zones, SEALED, 0).unwrap()
}

fn at_code<T: PartialEq>(table: &[T], value: T) -> usize {
    table.iter().position(|listed| *listed == value).unwrap()
}

/// The contract pins the layout, the label tables, the view's field paths and sealed fixtures: each case seals to
/// its bytes and accepts to its view, the widths of each wire table add to its part's length, every field has a
/// unit, and each refusal fixture refuses with its error.
#[test]
fn status_fields_and_fixtures() {
    let contract: Value = serde_json::from_str(CONTRACT).unwrap();
    assert_eq!(contract["schema"], SCHEMA);
    assert_eq!(contract["key"], hex(&KEY));
    assert_eq!(contract["status_key"], hex(&status_key().0));
    let layout = &contract["layout"];
    for (name, value) in [
        ("header", 48),
        ("part", PART_LEN),
        ("row", ROW_LEN),
        ("tag", 32),
        ("max_zones", MAX_ZONES),
        ("max_rows", MAX_ROWS),
        ("max_len", MAX_LEN),
    ] {
        assert_eq!(layout[name], value, "{name}");
    }
    assert_eq!(contract["labels"], tables());
    let widths = |part: &str| -> usize {
        let rows = contract["wire"][part].as_array().unwrap();
        rows.iter()
            .map(|row| row[1].as_u64().unwrap() as usize)
            .sum()
    };
    assert_eq!(
        (widths("header"), widths("part"), widths("row")),
        (48, PART_LEN, ROW_LEN)
    );
    let mut fields = BTreeSet::new();
    for (name, zones) in cases() {
        let case = &contract["cases"][name];
        let bytes = sealed(&zones);
        assert_eq!(case["bytes"], hex(&bytes), "{name}");
        let accepted = StatusReader::default().accept(&bytes, key_of).unwrap();
        assert_eq!(accepted.zones, zones, "{name}");
        assert_eq!(case["view"], view(&accepted), "{name}");
        paths(&view(&accepted), "", &mut fields);
    }
    let listed: BTreeSet<String> = (contract["fields"].as_array().unwrap().iter())
        .map(|path| path.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(listed, fields);
    let units = contract["units"].as_object().unwrap();
    let missing: Vec<&String> = (fields.iter())
        .filter(|path| !units.contains_key(*path))
        .collect();
    assert!(missing.is_empty(), "fields without a unit: {missing:?}");
    for (name, refusal) in contract["refusals"].as_object().unwrap() {
        let bytes = unhex(refusal["bytes"].as_str().unwrap());
        let error = StatusReader::default().accept(&bytes, key_of).unwrap_err();
        assert_eq!(format!("{error:?}"), refusal["error"], "{name}");
    }
    let mut forged = sealed(&[sample(1, 3)]);
    forged[60] ^= 1;
    assert_eq!(
        contract["refusals"]["forged-tag"]["bytes"],
        hex(&forged),
        "the forged tag is a sealed status of the current layout with one body bit flipped"
    );
    assert_eq!(
        StatusReader::default().accept(&forged, key_of),
        Err(ReportError::Tag)
    );
}

/// The field at the dotted `path` of `scope`, `None` when a key is missing.
fn at_path<'a>(scope: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(scope, |value, key| value.get(key))
}

/// Reads `bytes` through the contract's wire tables alone, with no use of the codec, and compares every field with
/// `view` by the encoding its width names: 2, 4 and 8 bytes an integer, 9 a flagged value, 17 a flag, `used` and
/// `limit`, and 1 the flags bitfield, the row count or a label of the table of the same name. The tag follows the
/// last part.
fn walk(contract: &Value, bytes: &[u8], view: &Value) -> Result<(), String> {
    let mut at = 0;
    let mut take = |width: usize| -> Result<&[u8], String> {
        let field = bytes
            .get(at..at + width)
            .ok_or("the bytes end inside a field")?;
        at += width;
        Ok(field)
    };
    let int = |field: &[u8]| field.iter().fold(0u64, |n, &b| (n << 8) | u64::from(b));
    let labels = &contract["labels"];
    let mut zones = 0;
    for entry in contract["wire"]["header"].as_array().unwrap() {
        let (name, width) = (
            entry[0].as_str().unwrap(),
            entry[1].as_u64().unwrap() as usize,
        );
        let field = take(width)?;
        let held = match name {
            "magic" => json!(String::from_utf8_lossy(field)),
            "writer.boot" => json!(hex(field)),
            _ => json!(int(field)),
        };
        let expected = match name {
            "magic" => json!("RSTS"),
            "schema" => json!(SCHEMA),
            "zones" => json!(view["zones"].as_array().map_or(0, Vec::len)),
            "zero" => json!(0),
            _ => at_path(view, name)
                .cloned()
                .ok_or(format!("no view field {name}"))?,
        };
        if name == "zones" {
            zones = int(field) as usize;
        }
        if held != expected {
            return Err(format!("header {name}: bytes {held}, view {expected}"));
        }
    }
    for zone in 0..zones {
        let part = &view["zones"][zone];
        for entry in contract["wire"]["part"].as_array().unwrap() {
            let (name, width) = (
                entry[0].as_str().unwrap(),
                entry[1].as_u64().unwrap() as usize,
            );
            let field = take(width)?;
            let expected = at_path(part, name).ok_or(format!("no view field zones.{name}"))?;
            let held = match (name, width) {
                ("flags", 1) => {
                    let names = labels["flags"].as_array().unwrap();
                    let bits = (names.iter().enumerate()).map(|(bit, flag)| {
                        (
                            flag.as_str().unwrap().to_owned(),
                            json!(field[0] & (1 << bit) != 0),
                        )
                    });
                    Value::Object(bits.collect())
                }
                ("rows", 1) => json!(int(field)),
                (_, 1) => labels[name][usize::from(field[0])].clone(),
                (_, 9) => match field[0] {
                    1 => json!(int(&field[1..])),
                    _ => Value::Null,
                },
                (_, 17) => match field[0] {
                    1 => json!({"used": int(&field[1..9]), "limit": int(&field[9..])}),
                    _ => Value::Null,
                },
                _ => json!(int(field)),
            };
            let expected = match name {
                "rows" => json!(expected.as_array().map_or(0, Vec::len)),
                _ => expected.clone(),
            };
            if held != expected {
                return Err(format!(
                    "zones[{zone}].{name}: bytes {held}, view {expected}"
                ));
            }
        }
        for (index, row) in part["rows"].as_array().unwrap().iter().enumerate() {
            for entry in contract["wire"]["row"].as_array().unwrap() {
                let (name, width) = (
                    entry[0].as_str().unwrap(),
                    entry[1].as_u64().unwrap() as usize,
                );
                let field = take(width)?;
                let held = match width {
                    1 => labels[name][usize::from(field[0])].clone(),
                    _ => json!(int(field)),
                };
                if held != row[name] {
                    return Err(format!(
                        "zones[{zone}].rows[{index}].{name}: bytes {held}, view {}",
                        row[name]
                    ));
                }
            }
        }
    }
    match bytes.len() - at {
        32 => Ok(()),
        left => Err(format!(
            "{left} bytes after the last part, where the tag's 32 belong"
        )),
    }
}

/// Each fixture's bytes, read through the contract's wire tables by name and width alone, give the fixture's
/// view field by field. Swapping two equal-width wire entries whose values differ fails the walk.
#[test]
fn each_fixture_reads_its_view_through_the_wire_tables() {
    let contract: Value = serde_json::from_str(CONTRACT).unwrap();
    for (name, case) in contract["cases"].as_object().unwrap() {
        let bytes = unhex(case["bytes"].as_str().unwrap());
        assert_eq!(walk(&contract, &bytes, &case["view"]), Ok(()), "{name}");
    }
    let mut swapped = contract.clone();
    let part = swapped["wire"]["part"].as_array_mut().unwrap();
    let position =
        |part: &[Value], name: &str| part.iter().position(|entry| entry[0] == name).unwrap();
    let unknown = position(part, "store.outcomes.unknown");
    let unavailable = position(part, "store.outcomes.unavailable");
    part.swap(unknown, unavailable);
    let case = &contract["cases"]["two-zones"];
    let bytes = unhex(case["bytes"].as_str().unwrap());
    assert!(
        walk(&swapped, &bytes, &case["view"]).is_err(),
        "a swapped wire entry fails"
    );
}

fn retagged(mut bytes: Vec<u8>) -> Vec<u8> {
    let body = bytes.len() - 32;
    let label: &[u8] = b"ebs-recon-status";
    let tag = crate::failover::assignment::hmac(&status_key().0, &[label, &bytes[..body]]);
    bytes[body..].copy_from_slice(&tag);
    bytes
}

/// STATUS-BOUNDED: sixteen zones of thirty-two rows each seal and accept at exactly `MAX_LEN` bytes, within 16 KiB;
/// a seventeenth zone and a thirty-third row refuse before any byte is encoded.
#[test]
fn a_status_at_sixteen_zones_of_thirty_two_rows_round_trips_within_16_kib() {
    let zones: Vec<ZonePart> = (1..=MAX_ZONES as u16)
        .map(|zone| sample(zone, MAX_ROWS))
        .collect();
    let bytes = sealed(&zones);
    assert_eq!(bytes.len(), MAX_LEN);
    assert!(bytes.len() <= 16 * 1024);
    let accepted = StatusReader::default().accept(&bytes, key_of).unwrap();
    assert_eq!(accepted.zones, zones);
    assert_eq!((accepted.sequence, accepted.sealed_at_us), (1, SEALED));
    let mut more = zones.clone();
    more.push(sample(17, 0));
    assert_eq!(writer().seal(&more, SEALED, 0), Err(SealError::Entries));
    let mut long = zones;
    long[3].rows.push(ExceptionRow {
        shard: shard(9),
        class: Class::Cold,
        standby: Standby::Past,
        age_us: 0,
    });
    assert_eq!(writer().seal(&long, SEALED, 0), Err(SealError::Entries));
}

/// STATUS-AUTHENTICATED: a flipped bit refuses with `Magic` or `Schema` in the bytes those checks read and with
/// `Tag` in every other byte, the bytes whose decoder rules the flip breaks included, so the tag verifies before the
/// decoder reads a field.
///
/// CLOSED-LABELS and the decoder's rules: a label byte one past its table refuses as a flag, an unknown schema
/// refuses by name before any later field is read, a host report key refuses as a tag, a replay
/// refuses as a duplicate, and the writer refuses as fields a served row within its standby target, unordered or
/// repeated rows, unordered or repeated zones, a stale count without its age and an omitted count beside fewer than
/// 32 rows. Rows are ordered by descending age and, within one age, ascending shard. A census longer than a cap
/// lowered below it seals and accepts.
#[test]
fn label_bytes_past_their_tables_and_unknown_schemas_refuse() {
    let bytes = sealed(&[sample(1, 3)]);
    let alarm_at = 48 + PART_LEN - 1 - 4 - 4 * 49 - 16 - 1;
    assert_eq!(
        usize::from(bytes[alarm_at]),
        at_code(STORE_ALARMS, StoreAlarm::Namespace)
    );
    let edited = |at: usize, code: u8| {
        let mut edited = bytes.clone();
        edited[at] = code;
        StatusReader::default().accept(&retagged(edited), key_of)
    };
    let alarms = STORE_ALARMS.len() as u8;
    assert_eq!(edited(alarm_at, alarms), Err(ReportError::Flag));
    assert!(edited(alarm_at, alarms - 1).is_ok());
    let row = 48 + PART_LEN;
    assert_eq!(edited(row + 4, CLASSES.len() as u8), Err(ReportError::Flag));
    assert_eq!(edited(row + 4, 0), Err(ReportError::Field), "a served row");
    assert_eq!(sample(1, 3).rows[1].standby, Standby::Past);
    assert!(
        edited(row + ROW_LEN + 4, 0).is_ok(),
        "a served row past its standby target"
    );
    assert_eq!(
        edited(row + 5, STANDBYS.len() as u8),
        Err(ReportError::Flag)
    );
    let mut schema = bytes.clone();
    schema[5] = 2;
    schema.truncate(8);
    assert_eq!(
        StatusReader::default().accept(&schema, key_of),
        Err(ReportError::Schema { found: 2 })
    );
    for at in 0..bytes.len() {
        let mut flipped = bytes.clone();
        flipped[at] ^= 1;
        let expected = match at {
            0..4 => ReportError::Magic,
            4..6 => ReportError::Schema {
                found: u16::from_be_bytes([flipped[4], flipped[5]]),
            },
            _ => ReportError::Tag,
        };
        assert_eq!(
            StatusReader::default().accept(&flipped, key_of),
            Err(expected),
            "offset {at}"
        );
    }
    let host_key = |_: Host| Some(StatusKey(ReportKey::derive(&KEY).0));
    assert_eq!(
        StatusReader::default().accept(&bytes, host_key),
        Err(ReportError::Tag)
    );
    let mut reader = StatusReader::default();
    reader.accept(&bytes, key_of).unwrap();
    assert_eq!(reader.accept(&bytes, key_of), Err(ReportError::Duplicate));
    let refused = |change: fn(&mut Vec<ZonePart>)| {
        let mut zones = vec![sample(1, 3), sample(2, 2)];
        change(&mut zones);
        writer().seal(&zones, SEALED, 0)
    };
    let field = Err(SealError::Field(ReportError::Field));
    assert_eq!(refused(|z| z[0].rows[0].class = Class::Served), field);
    assert!(refused(|z| z[0].rows[1].class = Class::Served).is_ok());
    assert_eq!(refused(|z| z[0].rows.swap(0, 1)), field);
    assert_eq!(refused(|z| z[0].rows[1].shard = z[0].rows[0].shard), field);
    assert_eq!(
        refused(|z| {
            let rows = &mut z[0].rows;
            (rows[0].age_us, rows[1].age_us) = (rows[1].age_us, rows[0].age_us);
        }),
        field,
        "a younger row before an older one, their shards ascending"
    );
    assert_eq!(
        refused(|z| {
            let rows = &mut z[0].rows;
            rows[1].age_us = rows[0].age_us;
            (rows[0].shard, rows[1].shard) = (rows[1].shard, rows[0].shard);
        }),
        field,
        "two rows of one age, their shards descending"
    );
    let tied = refused(|z| z[0].rows[1].age_us = z[0].rows[0].age_us);
    assert!(tied.is_ok(), "two rows of one age, their shards ascending");
    assert_eq!(refused(|z| z.swap(0, 1)), field);
    assert_eq!(refused(|z| z[1].zone = z[0].zone), field);
    assert_eq!(refused(|z| z[0].stale_serving = 0), field);
    assert_eq!(refused(|z| z[0].omitted = 1), field);
    assert!(refused(|_| {}).is_ok());
    assert_eq!(
        refused(|z| z[0].budgets.attempts = known(9, 10)),
        field,
        "an attempt budget whose limit is not ATTEMPTS_MAX"
    );
    assert_eq!(
        refused(|z| z[0].budgets.generation = known(4, 5)),
        field,
        "a generation budget whose limit is not GENERATION_MAX"
    );
    assert_eq!(
        refused(|z| z[0].census = known(4097, 64)),
        field,
        "a census past MAX_SLOTS"
    );
    assert_eq!(
        refused(|z| z[0].hosts.silent = known(2, 4097)),
        field,
        "a host population past MAX_HOSTS"
    );
    let pairs = refused(|z| z[0].attaches.pairs = known(3, 1)).expect("pairs past the cap seal");
    let accepted = StatusReader::default().accept(&pairs, key_of).unwrap();
    assert_eq!(accepted.zones[0].attaches.pairs, known(3, 1));
    let over = refused(|z| z[0].census = known(65, 64)).expect("a census past a lowered cap seals");
    let accepted = StatusReader::default().accept(&over, key_of).unwrap();
    assert_eq!(accepted.zones[0].census, known(65, 64));
}

/// The decoder accepts exactly the encodings its encoder produces: each byte edit below, retagged so the tag
/// verifies, refuses with the error its rule names, at the first field it breaks. A flag byte of 2, a clear flag with
/// a value, a gauge flag of 2 beside zero values, a clear gauge flag beside one nonzero value, silent hosts above
/// their population, a census or a host population past its bound, a budget whose limit
/// is not its maximum, a nonzero header pad, a zero sequence, a zone count past the bound, bytes after the last part,
/// a zero row shard and an omitted count beside fewer than 32 rows each refuse. Recorded pairs above the summed pair
/// cap accept.
#[test]
fn each_non_canonical_byte_refuses_with_its_rule() {
    let bytes = sealed(&[sample(1, 3)]);
    let part = 48;
    // The stale age's flag, then the census pair's flag and value, then the pairs, the flagged count of unnamed
    // volumes, the silent hosts and the budgets, each pair a flag byte, `used` and `limit`.
    let stale = part + 2 + 8 + 1 + 4 * CLASSES.len() + 4;
    let census = stale + 9 + 4 * (STANDBYS.len() - 1) + 4 * 2 + 4 * BLOCKERS;
    let pairs = census + 17 + 4 * 4;
    let unnamed = pairs + 17 + 4 * (super::part::CLOSED + RECEIPTS.len() + 4);
    let silent = unnamed + 9 + 4 * 4;
    let attempts = silent + 17 + 4;
    let generation = attempts + 17;
    let row = part + PART_LEN;
    let omitted = row - 5;
    let edited = |edits: &[(usize, u8)], cut: usize| {
        let mut edited = bytes.clone();
        for &(at, byte) in edits {
            edited[at] = byte;
        }
        let body = edited.len() - 32 - cut;
        edited.drain(body..body + cut);
        StatusReader::default().accept(&retagged(edited), key_of)
    };
    type Edit<'a> = (&'a str, &'a [(usize, u8)], usize, ReportError);
    let cases: [Edit<'_>; 17] = [
        ("a flag byte of 2", &[(stale, 2)], 0, ReportError::Flag),
        (
            "an unnamed-volumes flag byte of 2",
            &[(unnamed, 2)],
            0,
            ReportError::Flag,
        ),
        (
            "a clear unnamed-volumes flag with a value",
            &[(unnamed, 0)],
            0,
            ReportError::Flag,
        ),
        (
            "a clear census flag with a value",
            &[(census, 0)],
            0,
            ReportError::Flag,
        ),
        (
            "a census flag byte of 2 beside a zero length and cap",
            &[(census, 2), (census + 8, 0), (census + 16, 0)],
            0,
            ReportError::Flag,
        ),
        (
            "a clear pairs flag beside a count and a zero cap",
            &[(pairs, 0), (pairs + 16, 0)],
            0,
            ReportError::Flag,
        ),
        (
            "silent hosts above their population",
            &[(silent + 8, 0xFF)],
            0,
            ReportError::Field,
        ),
        (
            "a census past the census bound",
            &[(census + 7, 0x10), (census + 8, 0x01)],
            0,
            ReportError::Field,
        ),
        (
            "a host population past the directory bound",
            &[(silent + 15, 0x10), (silent + 16, 0x01)],
            0,
            ReportError::Field,
        ),
        (
            "an attempt budget below its maximum",
            &[(attempts + 16, 0xFD)],
            0,
            ReportError::Field,
        ),
        (
            "a generation budget below its maximum",
            &[(generation + 16, 0xFD)],
            0,
            ReportError::Field,
        ),
        ("a nonzero header pad", &[(47, 1)], 0, ReportError::Flag),
        ("a zero sequence", &[(37, 0)], 0, ReportError::Field),
        (
            "a zone count past the bound",
            &[(46, 17)],
            0,
            ReportError::Length,
        ),
        (
            "a zero row shard",
            &[(row, 0), (row + 1, 0), (row + 2, 0), (row + 3, 0)],
            0,
            ReportError::Field,
        ),
        (
            "an omitted count beside three rows",
            &[(omitted + 3, 1)],
            0,
            ReportError::Field,
        ),
        ("a row cut short", &[], 1, ReportError::Length),
    ];
    assert_eq!(bytes[37], 1, "the sequence's low byte");
    assert_eq!(
        (bytes[census], bytes[census + 8], bytes[census + 16]),
        (1, 40, 64),
        "the census gauge's flag and the low bytes of its length and cap"
    );
    assert_eq!(
        (bytes[pairs], bytes[pairs + 8], bytes[pairs + 16]),
        (1, 9, 64),
        "the pair gauge's flag and the low bytes of its count and cap"
    );
    for (name, edits, cut, error) in cases {
        assert_eq!(edited(edits, cut), Err(error), "{name}");
    }
    let mut longer = bytes.clone();
    let body = longer.len() - 32;
    longer.insert(body, 0);
    assert_eq!(
        StatusReader::default().accept(&retagged(longer), key_of),
        Err(ReportError::Length),
        "bytes after the last part"
    );
    assert!(edited(&[], 0).is_ok());
    let over = edited(&[(pairs + 8, 0xFF)], 0).expect("pairs above the summed pair cap accept");
    assert_eq!(over.zones[0].attaches.pairs, known(0xFF, 64));
}

/// WRITER-SEQUENCE: a seal the decoder refuses advances nothing. The writer's next status carries sequence 1, the
/// stamp of its own seal and no pacing delay, and the status after it is early by the period. An early seal of too
/// many zones refuses as early, and the same zones at the due time refuse as entries.
#[test]
fn a_refused_seal_leaves_the_writer_s_sequence_stamp_and_pacing() {
    let mut writer = writer();
    let mut unordered = sample(1, 3);
    unordered.rows.swap(0, 1);
    assert_eq!(
        writer.seal(&[unordered], SEALED + 5, 0),
        Err(SealError::Field(ReportError::Field))
    );
    let first = writer
        .seal(&[sample(1, 3)], SEALED, 0)
        .expect("the refused seal set no due time");
    let accepted = StatusReader::default().accept(&first, key_of).unwrap();
    assert_eq!((accepted.sequence, accepted.sealed_at_us), (1, SEALED));
    assert_eq!(
        writer.seal(&[sample(1, 3)], SEALED, PERIOD.get() - 1),
        Err(SealError::Early)
    );
    let seventeen: Vec<ZonePart> = (1..=MAX_ZONES as u16 + 1)
        .map(|zone| sample(zone, 0))
        .collect();
    assert_eq!(
        writer.seal(&seventeen, SEALED, PERIOD.get() - 1),
        Err(SealError::Early),
        "an early seal of too many zones refuses as early"
    );
    assert_eq!(
        writer.seal(&seventeen, SEALED, PERIOD.get()),
        Err(SealError::Entries)
    );
    let second = writer.seal(&[sample(1, 3)], SEALED, PERIOD.get()).unwrap();
    let mut reader = StatusReader::default();
    reader.accept(&first, key_of).unwrap();
    assert_eq!(reader.accept(&second, key_of).unwrap().sequence, 2);
}

/// The writers' `Debug` text names the envelope and holds no key: the status writer's and the report writer's each
/// open with the type and its envelope's fields and end as a struct with a field left out.
#[test]
fn a_writer_s_debug_text_shows_its_envelope_and_no_key() {
    let status = format!("{:?}", writer());
    let report_writer = crate::failover::report::Writer::new(host(IDENTITY), &KEY, PERIOD).unwrap();
    let report = format!("{report_writer:?}");
    for (text, name) in [(status, "StatusWriter"), (report, "Writer")] {
        let open = format!("{name} {{ envelope: Envelope {{ id: WriterId {{ host: ");
        assert!(text.starts_with(&open), "{text}");
        assert!(
            text.contains("next: 1, next_due: 0, sealed_at_us: 0"),
            "{text}"
        );
        assert!(text.ends_with("}, .. }"), "{text}");
        assert!(!text.contains("key"), "{text}");
    }
}

/// Each flag of the contract's table travels in its own bit: a part with only flag `k` set seals a flags byte of
/// `1 << k` at the part's third byte past the zone and tick.
#[test]
fn each_flag_seals_its_own_wire_bit() {
    let contract: Value = serde_json::from_str(CONTRACT).unwrap();
    let names = contract["labels"]["flags"].as_array().unwrap();
    assert_eq!(names.len(), 8);
    for (k, name) in names.iter().enumerate() {
        let mut part = sample(1, 0);
        part.flags = Flags::default();
        let flags = &mut part.flags;
        let bit = match name.as_str().unwrap() {
            "reports" => &mut flags.reports,
            "instances" => &mut flags.instances,
            "volumes" => &mut flags.volumes,
            "store" => &mut flags.store,
            "warm-up" => &mut flags.warm_up,
            "zone-host" => &mut flags.zone_host,
            "operator" => &mut flags.operator,
            "cap-below" => &mut flags.cap_below,
            other => panic!("flag {other} has no field"),
        };
        *bit = true;
        let bytes = sealed(&[part]);
        assert_eq!(bytes[48 + 2 + 8], 1 << k, "{name}");
    }
}

/// Each gauge bound is inclusive: a census and its cap at 4096 and a silent-host population of 4096 seal and accept,
/// and a census cap of 4097 refuses at seal and, retagged, at accept.
#[test]
fn each_gauge_bound_is_inclusive() {
    let mut part = sample(1, 0);
    part.census = known(4096, 4096);
    part.hosts.silent = known(4096, 4096);
    let bytes = sealed(std::slice::from_ref(&part));
    let accepted = StatusReader::default().accept(&bytes, key_of).unwrap();
    assert_eq!(
        (accepted.zones[0].census, accepted.zones[0].hosts.silent),
        (part.census, part.hosts.silent)
    );
    part.census = known(40, 4097);
    assert_eq!(
        writer().seal(std::slice::from_ref(&part), SEALED, 0),
        Err(SealError::Field(ReportError::Field))
    );
    let mut edited = sealed(&[sample(1, 0)]);
    let census = 48
        + 2
        + 8
        + 1
        + 4 * CLASSES.len()
        + 4
        + 9
        + 4 * (STANDBYS.len() - 1)
        + 4 * 2
        + 4 * BLOCKERS;
    edited[census + 15] = 0x10;
    edited[census + 16] = 0x01;
    assert_eq!(
        StatusReader::default()
            .accept(&retagged(edited), key_of)
            .unwrap_err(),
        ReportError::Field
    );
}

/// A status shorter than its header and tag, or longer than [`MAX_LEN`], refuses as a length before the reader looks
/// up a key: each prefix of a sealed empty status from 6 bytes up to one byte short, and an input one byte past the
/// bound with a valid writer header.
#[test]
fn a_status_outside_its_length_bounds_refuses_before_the_key() {
    let bytes = sealed(&[]);
    assert_eq!(bytes.len(), 80, "an empty status is its header and tag");
    let no_key =
        |_: Host| -> Option<StatusKey> { panic!("the length check runs before the key lookup") };
    for len in 6..bytes.len() {
        assert_eq!(
            StatusReader::default().accept(&bytes[..len], no_key),
            Err(ReportError::Length),
            "a {len}-byte prefix"
        );
    }
    let mut long = bytes.clone();
    long.resize(MAX_LEN + 1, 0);
    assert_eq!(
        StatusReader::default().accept(&long, no_key),
        Err(ReportError::Length),
        "one byte past MAX_LEN"
    );
    assert!(StatusReader::default().accept(&bytes, key_of).is_ok());
}
