//! Tests that `scripts/gameday-judge.py` judges the evidence directory [`export`] writes from the simulated fleet's
//! host loss: held on two roots and disproven on controls planted before the export.
//!
//! [`export`] maps one [`Report`] of `Config::host_loss` to the directory's files and reads only the report, so
//! repeated exports of one report are byte-equal. Before it writes a file it asserts that file's premises in the
//! report: the scenario is `Scenario::HostLoss`; exactly one host loss and one crash; an empty exempt set and a zero
//! refused count before the standbys read healthy; one seeded owner for every shard the loss took; and, for each
//! successor, a sweep that requested the shape's objects outside its shard's `invalidated` set and counted as
//! exact each of those objects outside the shard's `unserved` entries at the successor's tenure.
//!
//! The export uses host rounds as its clock, and `hosts.fired[0]` is the loss round. The boot precedes the first
//! host round and stands at round -1: the seeded roles, every version of a shard record before the shard's first
//! owner change, and each activation of a tenure that one of those versions names for its host. The export assigns
//! the loss round to each version from the shard's first owner change onward and to every other activation. Every
//! row of a successor's sweep stands at the loss round plus its recovery's `rounds`, the round the successor's
//! client session opened. The report carries one round for each recovery: the sweep sends its first GET in that
//! round and every later GET in that round or a later one, so the stamp is a lower bound of a row's send round.
//! The run window ends one round after the latest of the loss and those stamps. The export seals its collected files
//! and `coverage.json` at that end in `injection/collected.json`, the SHA-256 of each file's bytes, as the stop
//! controller's `seal` does.
//!
//! The package is of kind `simulation`, so the judge's record reads mode `simulation`. Its revision is forty zeros
//! and its date is [`DATE`]. A host scenario runs the fleet's hosts alone, so the package marks the origin,
//! provider and re-enrollment observations as outside its world, and four of the judge's eleven rules read
//! `outside`.
//!
//! The package pins one witness key for each object of a taken shard outside the shard's `invalidated` set. For
//! a successor's sweep the export writes one row for each of its shard's keys: a miss for each object the shard's
//! `unserved` list names at the successor's tenure, and for every other object a hit carrying the reference
//! digest, the SHA-256 of `content(n, first(n))`, the generator that seeded the volume before the fault. The rows
//! hold the sweeps' GETs alone, in ascending object number within each sweep.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::cycles::{Verdict, hex};
use super::fleet::hosts::Scenario;
use super::fleet::{Config, Evidence, Plant, Report, ShardReport, run};
use super::{content, first};
use crate::failover::loss::Receipt;
use crate::failover::loss::Request;
use crate::failover::loss::tests::receipt;
use crate::failover::records::{Host, ShardRecord};
use crate::failover::standbys::MAX_SLOTS;
use crate::failover::zone_loop::directory::MAX_HOSTS;
use crate::net::ownership::ShardGeneration;
use crate::storage::store_tests::fresh_directory;

/// The round of the boot, before the first host round.
const BOOT: i64 = -1;
/// The placeholder date of a simulated package. The judge's layout requires a date, and the readiness grader
/// refuses a `simulation` record under a staging item whatever its date.
const DATE: &str = "1970-01-01";
const PRINCIPAL: &str = "reconciler";
/// The stop request identifies the fleet fault script as the host-loss injector.
const INJECTOR: &str = "fleet-fault-script";
/// The judge classifies these rules as `outside` for a host simulation.
const OUTSIDE: [&str; 4] = [
    "no-origin-before-hit",
    "no-volume-created",
    "origin-load",
    "standby-again",
];

/// The evidence directory's files by their path under it.
type Files = BTreeMap<String, Vec<u8>>;

fn host_name(host: Host) -> String {
    format!("h{}", host.get())
}

fn instance(host: Host) -> String {
    format!("i-h{}", host.get())
}

fn shard_name(shard: u32) -> String {
    format!("s{shard}")
}

fn key(shard: u32, n: u8) -> String {
    format!("s{shard}/object-{n}")
}

/// The SHA-256 of object `n`'s bytes as the generator seeded them before the fault.
fn reference(n: u8) -> String {
    hex(&Sha256::digest(content(n, first(n))))
}

fn json_file(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("a JSON value encodes");
    bytes.push(b'\n');
    bytes
}

fn json_lines(rows: impl IntoIterator<Item = Value>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for row in rows {
        bytes.extend(serde_json::to_vec(&row).expect("a JSON value encodes"));
        bytes.push(b'\n');
    }
    bytes
}

fn version(record: &ShardRecord) -> Value {
    json!({
        "owner": host_name(record.owner),
        "standby": record.standby.map(host_name),
        "generation": record.generation.get(),
        "volume": record.active.as_str(),
        "attempts": record.attempts,
    })
}

/// One shard's record before the loss: the last record in the initial owner's run of its history, and the length
/// of that run.
struct Seed {
    shard: u32,
    record: ShardRecord,
    change: usize,
}

fn seeded(shard: u32, versions: &[ShardRecord]) -> Seed {
    let first = versions.first().expect("a seeded shard record");
    let change = (versions.iter())
        .position(|record| record.owner != first.owner)
        .unwrap_or(versions.len());
    let kept = |record: &ShardRecord| {
        (record.generation, record.active, record.standby)
            == (first.generation, first.active, first.standby)
    };
    assert!(
        versions[..change].iter().all(kept),
        "shard {shard} keeps its generation, volume and standby before its first owner change, which the export stamps at the boot"
    );
    Seed {
        shard,
        record: versions[change - 1],
        change,
    }
}

fn fleet_shard(shards: &[ShardReport], shard: u32) -> &ShardReport {
    (shards.iter())
        .find(|of| of.placement.shard.get() == shard)
        .unwrap_or_else(|| panic!("shard {shard} is a shard of the fleet"))
}

/// `witness` returns the package's witness keys in `taken` order, the witness rows by ascending sweep round with
/// ties in `taken` order, and the latest sweep round; within each shard the keys and rows follow ascending object
/// number.
fn witness(
    shards: &[ShardReport],
    objects: u8,
    taken: &[u32],
    loss: i64,
) -> (Vec<Value>, Vec<Value>, i64) {
    let (mut keys, mut rows, mut latest) = (Vec::new(), Vec::new(), loss);
    for &shard in taken {
        let roles = fleet_shard(shards, shard);
        let objects: Vec<u8> = (1..=objects)
            .filter(|n| !roles.invalidated.contains(n))
            .collect();
        keys.extend(objects.iter().map(
            |&n| json!({"key": key(shard, n), "shard": shard_name(shard), "sha256": reference(n)}),
        ));
        let swept = (roles.recoveries.last())
            .filter(|recovered| recovered.after_crash)
            .and_then(|recovered| recovered.sweep.map(|sweep| (recovered, sweep)));
        let Some((recovered, (requested, exact))) = swept else {
            continue;
        };
        let requested = usize::try_from(requested).expect("a sweep's count fits a usize");
        let exact = usize::try_from(exact).expect("a sweep's count fits a usize");
        assert_eq!(
            objects.len(),
            requested,
            "shard {shard}'s sweep requested each object outside its invalidations"
        );
        let unserved: BTreeSet<u8> = (roles.unserved.iter())
            .filter(|(tenure, _)| *tenure == recovered.tenure)
            .map(|&(_, n)| n)
            .collect();
        let served = |n: &u8| !unserved.contains(n);
        assert_eq!(
            (
                unserved.len() + exact,
                objects.iter().filter(|n| served(n)).count()
            ),
            (requested, exact),
            "shard {shard}'s sweep counts exact each requested object outside its unserved ones {unserved:?}"
        );
        let rounds = i64::try_from(recovered.rounds).expect("a recovery's rounds fit an i64");
        let time = loss
            .checked_add(rounds)
            .expect("the sweep's round fits an i64");
        latest = latest.max(time);
        for &n in &objects {
            let hit = served(&n);
            let row = json!({
                "key": key(shard, n),
                "host": host_name(recovered.host),
                "time": time,
                "outcome": if hit { "hit" } else { "miss" },
                "sha256": hit.then(|| reference(n)),
            });
            rows.push((time, row));
        }
    }
    rows.sort_by_key(|(time, _)| *time);
    let rows = rows.into_iter().map(|(_, row)| row).collect();
    (keys, rows, latest)
}

/// `export` returns the evidence files for `report`'s host loss. It requires `report` to come from
/// `Scenario::HostLoss`, to record exactly one host loss and one crash, and the same host must own every shard
/// taken by the loss.
fn export(report: &Report) -> Files {
    let Report {
        config,
        crashes,
        planted,
        shards,
        hosts: log,
        evidence,
        ..
    } = report;
    let Evidence {
        histories,
        activations,
        receipts,
        losses,
        ..
    } = evidence;
    assert_eq!(
        config.scenario,
        Scenario::HostLoss,
        "the report is of a host loss"
    );
    let fired = log
        .fired
        .first()
        .copied()
        .flatten()
        .expect("the host loss fired");
    let loss = i64::try_from(fired).expect("the loss round fits an i64");
    assert_eq!(
        (log.host_losses, *crashes),
        (1, 1),
        "the run loses one host and counts one crash"
    );
    let count = shards.len();
    assert_eq!((histories.len(), receipts.len()), (count, count));
    let mut seeds = Vec::new();
    for ((shard, versions), roles) in histories.iter().zip(shards) {
        assert_eq!(
            roles.placement.shard, *shard,
            "histories follow shard order"
        );
        let seed = seeded(shard.get(), versions);
        assert_eq!(
            (seed.record.owner, seed.record.standby, seed.record.active),
            (roles.owner, Some(roles.standby), roles.placement.volume),
            "shard {}'s record before the loss names its seeded roles",
            shard.get()
        );
        seeds.push(seed);
    }
    let taken = &losses.hosts;
    let owners: BTreeSet<Host> = (taken.iter())
        .map(|&shard| fleet_shard(shards, shard).owner)
        .collect();
    assert_eq!(owners.len(), 1, "one host owned every shard the loss took");
    let target = *owners.first().expect("one owner");
    let hosts: BTreeSet<Host> = (shards.iter())
        .flat_map(|roles| [roles.owner, roles.standby])
        .collect();
    assert_eq!(
        hosts.len(),
        usize::try_from(config.shape.hosts).expect("a host count fits a usize"),
        "every host of the zone holds a seeded role"
    );
    let (keys, rows, latest) = witness(shards, config.shape.objects, taken, loss);
    let end = latest.checked_add(1).expect("the run's end fits an i64");
    let plant = if *planted {
        ", under a plant that changed the run"
    } else {
        ""
    };
    let package = json_file(&json!({
        "id": "GD-2",
        "kind": "simulation",
        "revision": "0".repeat(40),
        "date": DATE,
        "clock": "host rounds of the simulated fleet, the boot at round -1, one round before the first; every witness \
                  row of a sweep stands at the round its successor's client session opened, which is the send round \
                  of the sweep's first GET and a lower bound of the send round of each later GET, since the report \
                  carries one round for each recovery; the run window ends one round after the latest of those \
                  stamps, so a later GET of a sweep may be sent at or after that end",
        "note": format!(
            "exported from the simulated fleet's host loss of root {}{plant}, and made by no staging run. A record \
             version or an activation stands at the boot or at the loss round, and the witness rows restate each \
             successor's sweep in ascending object number: a miss for each object the fleet reports unserved, and \
             a hit with the reference digest for every other object outside the shard's invalidations. The rows \
             hold the sweeps' GETs alone; a GET the fleet sends a taken shard outside a sweep stays outside the \
             file. The date is a placeholder",
            config.root
        ),
        "target": {"host": host_name(target), "instance": instance(target)},
        "hosts": hosts.iter().map(|&host| host_name(host)).collect::<Vec<_>>(),
        "shards": seeds.iter().map(|seed| shard_name(seed.shard)).collect::<Vec<_>>(),
        "witness": keys,
        "baseline": {"start": BOOT, "end": loss},
        "run": {"start": loss, "end": end},
        "interval": end - loss,
        "reconciler_principal": PRINCIPAL,
        "working_budgets": {},
        "clock_error_seconds": 0,
        "outside": {
            "origin": "the fleet has no origin",
            "provider": "no provider and no reconciler principal run in a host scenario",
            "re-enrollment": "no reconciler runs, so no standby is enrolled again and no blocker is named",
        },
    }));
    assert!(
        log.exempt.is_empty() && log.refused == 0,
        "the standbys read healthy: exempt {:?}, refused {}",
        log.exempt,
        log.refused
    );
    let healthy = |host: Host| {
        let state = json!({"instance": instance(host), "instance_state": "running", "host_report": "healthy"});
        (host_name(host), state)
    };
    let standbys: Map<String, Value> = (seeds.iter())
        .filter(|seed| seed.record.owner == target)
        .filter_map(|seed| seed.record.standby.map(healthy))
        .collect();
    let roles = json!({
        "package_sha256": hex(&Sha256::digest(&package)),
        "time": BOOT,
        "shards": (seeds.iter())
            .map(|seed| (shard_name(seed.shard), version(&seed.record)))
            .collect::<Map<String, Value>>(),
        "standbys": standbys,
    });
    let stop = json!({"instance": instance(target), "time": loss, "identity": INJECTOR});
    let stopped =
        json!({"instance": instance(target), "state": "stopped", "time": loss, "request": stop});
    let mut files = Files::new();
    for ((_, versions), seed) in histories.iter().zip(&seeds) {
        let lines = versions.iter().enumerate().map(|(i, record)| {
            let mut line = version(record);
            line["time"] = json!(if i < seed.change { BOOT } else { loss });
            line
        });
        files.insert(
            format!("records/{}.jsonl", shard_name(seed.shard)),
            json_lines(lines),
        );
    }
    let receipt_rows = (receipts.iter().zip(&seeds))
        .filter_map(|(receipt, seed)| receipt.as_ref().map(|receipt| (receipt, seed)))
        .map(|(receipt, seed)| {
            assert_eq!(
                receipt.request.shard.get(),
                seed.shard,
                "shard {}'s receipt names its shard",
                seed.shard
            );
            json!({"time": loss, "shard": shard_name(seed.shard), "principal": PRINCIPAL})
        });
    files.insert("records/receipts.jsonl".into(), json_lines(receipt_rows));
    let boots: BTreeSet<(u32, u64, u64, Host)> = (histories.iter().zip(&seeds))
        .flat_map(|((_, versions), seed)| {
            (versions[..seed.change].iter()).map(|record| {
                let epoch = u64::from(record.attempts) * 2;
                (seed.shard, record.generation.get(), epoch, record.owner)
            })
        })
        .collect();
    for (shard, _, host) in activations {
        assert!(
            hosts.contains(host),
            "shard {}'s activation names h{}, a host of the zone",
            shard.get(),
            host.get()
        );
    }
    let activated = |host: Host| {
        let listed: Vec<Value> = (activations.iter())
            .filter(|(_, _, of)| *of == host)
            .map(|(shard, tenure, _)| {
                let shard = shard.get();
                assert_eq!(tenure.a % 2, 0, "shard {shard}'s activated epoch {tenure:?} is even");
                let boot = boots.contains(&(shard, tenure.g, tenure.a, host));
                let time = if boot { BOOT } else { loss };
                json!({"shard": shard_name(shard), "generation": tenure.g, "attempt": tenure.a, "time": time})
            })
            .collect();
        json!({"host": host_name(host), "activations": listed})
    };
    files.insert(
        "activations.jsonl".into(),
        json_lines(hosts.iter().map(|&host| activated(host))),
    );
    files.insert("witness.jsonl".into(), json_lines(rows));
    let coverage: Map<String, Value> = (files.iter())
        .filter(|(rel, _)| {
            rel.starts_with("records/") || *rel == "activations.jsonl" || *rel == "witness.jsonl"
        })
        .map(|(rel, bytes)| {
            let lines = bytes.iter().filter(|byte| **byte == b'\n').count();
            (
                rel.clone(),
                json!({"from": BOOT, "to": end, "lines": lines}),
            )
        })
        .collect();
    files.insert("coverage.json".into(), json_file(&Value::Object(coverage)));
    let sealed: Map<String, Value> = (files.iter())
        .map(|(rel, bytes)| (rel.clone(), json!(hex(&Sha256::digest(bytes)))))
        .collect();
    files.insert(
        "injection/collected.json".into(),
        json_file(&json!({"time": end, "files": sealed})),
    );
    files.insert("injection/roles.json".into(), json_file(&roles));
    files.insert("injection/stop.json".into(), json_file(&stop));
    files.insert("injection/stopped.json".into(), json_file(&stopped));
    files.insert("package.json".into(), package);
    files
}

/// `Scratch` recursively removes its directory on drop. Cleanup failure triggers a panic unless the thread is
/// already panicking.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let removed = std::fs::remove_dir_all(&self.0);
        if let Err(error) = removed
            && !std::thread::panicking()
        {
            panic!("{} is removed: {error}", self.0.display());
        }
    }
}

/// `judgment` writes `files` to a fresh evidence directory and runs the judge over it. It returns the judge's exit
/// code, its standard error, and the bytes of the record it wrote, or `None` when no record stands.
fn judgment(files: Files) -> (i32, String, Option<Vec<u8>>) {
    static CASES: AtomicUsize = AtomicUsize::new(0);
    let case = CASES.fetch_add(1, Ordering::Relaxed);
    let scratch = Scratch(fresh_directory(&format!("gameday-export-{case}")));
    let evidence = scratch.0.join("evidence");
    for (rel, bytes) in files {
        let path = evidence.join(rel);
        std::fs::create_dir_all(path.parent().expect("a file under the directory"))
            .expect("a directory is made");
        std::fs::write(&path, bytes).expect("an evidence file is written");
    }
    let record_path = scratch.0.join("record.json");
    let judge = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/gameday-judge.py");
    let output = (Command::new("python3").arg(&judge))
        .arg("--evidence")
        .arg(&evidence)
        .arg("--record")
        .arg(&record_path)
        .output()
        .expect("python3 starts the judge");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let Some(code) = output.status.code() else {
        panic!("the judge ended by {}: {stderr}", output.status);
    };
    // After a refusal the record path is looked up without following a link, so any entry there counts as a record.
    let record = if code == 2 {
        match std::fs::symlink_metadata(&record_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Ok(_) => Some(Vec::new()),
            Err(error) => panic!(
                "the judge exited {code} and {} cannot be looked up: {error}: {stderr}",
                record_path.display()
            ),
        }
    } else {
        Some(std::fs::read(&record_path).unwrap_or_else(|error| {
            panic!(
                "the judge exited {code} and {} reads {error}: {stderr}",
                record_path.display()
            )
        }))
    };
    (code, stderr, record)
}

/// `judged` returns the judge's exit code and parsed run record for the evidence `files`. The judge must exit with
/// code `0` or `1` and write a readable JSON record of the package in `files`.
fn judged(files: Files) -> (i32, Value) {
    let package = hex(&Sha256::digest(&files["package.json"]));
    let (code, stderr, record) = judgment(files);
    assert!(
        code == 0 || code == 1,
        "the judge wrote no record, exit {code}: {stderr}"
    );
    let bytes =
        record.unwrap_or_else(|| panic!("the judge exited {code} and wrote no record: {stderr}"));
    let record: Value = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!("the judge exited {code} and its record is not JSON: {error}: {stderr}")
    });
    assert_eq!(
        record["package_sha256"],
        package.as_str(),
        "the record judges the exported package; the judge exited {code}: {stderr}"
    );
    (code, record)
}

/// `refused` returns the judge's standard error for the evidence `files`, which the judge must refuse with exit 2
/// and no record.
fn refused(files: Files) -> String {
    let (code, stderr, record) = judgment(files);
    assert_eq!(code, 2, "the judge refuses the evidence: {stderr}");
    assert!(record.is_none(), "a refusal leaves no record: {stderr}");
    stderr
}

/// GD-2's eleven rules as the judge names them.
const RULES: [&str; 11] = [
    "changes-hands-once",
    "no-generation-change",
    "no-origin-before-hit",
    "no-replacement-receipt",
    "no-volume-created",
    "one-owner-per-tenure",
    "origin-load",
    "others-keep-owner",
    "standby-again",
    "takeover",
    "witness-first-hit",
];

/// `record["rules"]` must have exactly the keys in [`RULES`]. Each rule's `result` must be `"outside"` for
/// [`OUTSIDE`], `"disproven"` for the remaining rules in `named`, and `"held"` otherwise.
fn assert_results(record: &Value, named: &[&str]) {
    let results = record["rules"].as_object().expect("the record's rules");
    let read: BTreeMap<&str, Option<&str>> = (results.iter())
        .map(|(name, rule)| (name.as_str(), rule["result"].as_str()))
        .collect();
    let expected: BTreeMap<&str, Option<&str>> = (RULES.iter())
        .map(|&name| {
            let result = match name {
                _ if OUTSIDE.contains(&name) => "outside",
                _ if named.contains(&name) => "disproven",
                _ => "held",
            };
            (name, Some(result))
        })
        .collect();
    assert_eq!(read, expected, "{record:#}");
}

fn graded(record: &Value) -> (&str, &str, &str) {
    let word = |key: &str| {
        record[key]
            .as_str()
            .unwrap_or_else(|| panic!("the record's {key}"))
    };
    (word("mode"), word("run_status"), word("verdict"))
}

fn disproven(code: i32, record: &Value, named: &[&str]) -> Vec<Vec<String>> {
    assert_eq!(code, 1, "{record:#}");
    assert_eq!(
        graded(record),
        ("simulation", "COMPLETED", "DISPROVEN"),
        "{record:#}"
    );
    assert_results(record, named);
    (named.iter())
        .map(|name| {
            let detail = record["rules"][name]["detail"].as_array();
            (detail.expect("a detail list").iter())
                .map(|line| line.as_str().expect("a detail line").to_owned())
                .collect()
        })
        .collect()
}

/// Tests judge the same root 1 run, either unchanged or through a modified copy.
fn root_one() -> Report {
    static REPORT: OnceLock<Report> = OnceLock::new();
    let report =
        REPORT.get_or_init(|| run(&Config::host_loss(1)).expect("a run inside the limits"));
    report.clone()
}

fn lines(files: &Files, path: &str) -> Vec<Value> {
    let text = std::str::from_utf8(&files[path]).expect("UTF-8");
    text.lines()
        .map(|line| serde_json::from_str(line).expect("a JSON line"))
        .collect()
}

fn shard_number(name: &str) -> u32 {
    name[1..].parse().expect("a shard name")
}

fn assert_restates(report: &Report, files: &Files) {
    let loss = i64::try_from(report.hosts.fired[0].expect("the loss fired")).expect("a round");
    let seeded_owner = |shard: u32| fleet_shard(&report.shards, shard).owner;
    let name = |host: Host| format!("h{}", host.get());
    for (shard, versions) in &report.evidence.histories {
        let owner = seeded_owner(shard.get());
        let mut changed = false;
        let expected: Vec<Value> = (versions.iter())
            .map(|record| {
                changed |= record.owner != owner;
                json!({
                    "owner": name(record.owner),
                    "standby": record.standby.map(name),
                    "generation": record.generation.get(),
                    "volume": record.active.as_str(),
                    "attempts": record.attempts,
                    "time": if changed { loss } else { BOOT },
                })
            })
            .collect();
        let path = format!("records/s{}.jsonl", shard.get());
        assert_eq!(lines(files, &path), expected, "{path} restates the history");
    }
    let mut exported = Vec::new();
    let activations = lines(files, "activations.jsonl");
    for line in &activations {
        for activation in line["activations"].as_array().expect("a list") {
            let mut row = activation.clone();
            row["host"] = line["host"].clone();
            exported.push(row);
        }
    }
    let mut expected: Vec<Value> = (report.evidence.activations.iter())
        .map(|(shard, tenure, host)| {
            let boot = *host == seeded_owner(shard.get());
            json!({
                "host": name(*host),
                "shard": format!("s{}", shard.get()),
                "generation": tenure.g,
                "attempt": tenure.a,
                "time": if boot { BOOT } else { loss },
            })
        })
        .collect();
    let order = |rows: &mut Vec<Value>| rows.sort_by_key(Value::to_string);
    order(&mut exported);
    order(&mut expected);
    assert_eq!(exported, expected, "every activation is exported");
    let package: Value = serde_json::from_slice(&files["package.json"]).expect("JSON");
    let hosts = package["hosts"].as_array().expect("the package's hosts");
    let listed: Vec<&Value> = activations.iter().map(|line| &line["host"]).collect();
    assert_eq!(
        listed,
        hosts.iter().collect::<Vec<_>>(),
        "one line for every host"
    );
    for row in &exported {
        let shard = row["shard"].as_str().expect("a shard");
        let named = lines(files, &format!("records/{shard}.jsonl"))
            .iter()
            .any(|version| {
                let doubled = version["attempts"].as_u64().and_then(|a| a.checked_mul(2));
                (&version["owner"], &version["generation"], doubled)
                    == (&row["host"], &row["generation"], row["attempt"].as_u64())
            });
        assert!(named, "a record version names the tenure of {row}");
    }
    let mut successors: Vec<u32> = (report.evidence.activations.iter())
        .filter(|(shard, _, host)| *host != seeded_owner(shard.get()))
        .map(|(shard, _, _)| shard.get())
        .collect();
    successors.sort_unstable();
    let mut taken = report.evidence.losses.hosts.clone();
    taken.sort_unstable();
    assert_eq!(
        successors, taken,
        "one successor activates each taken shard"
    );
    let rows = lines(files, "witness.jsonl");
    assert_eq!(rows.len(), 21, "seven objects for each of three successors");
    let mut latest = loss;
    for row in rows {
        let key = row["key"].as_str().expect("a key");
        let shard = shard_number(key.split('/').next().expect("a shard part"));
        let roles = fleet_shard(&report.shards, shard);
        let recovered = roles.recoveries.last().expect("a recovery");
        let rounds = i64::try_from(recovered.rounds).expect("rounds");
        assert!(rounds > 0, "a successor's recovery takes rounds");
        let time = loss.checked_add(rounds).expect("a sweep round");
        latest = latest.max(time);
        assert_eq!(row["time"], time, "{row}");
        assert_eq!(row["host"], name(roles.standby).as_str(), "{row}");
        let object = key.rsplit('-').next().and_then(|n| n.parse::<u8>().ok());
        let n = object.expect("an object number");
        assert!(!roles.invalidated.contains(&n), "{row}");
        let outcome = match roles.unserved.contains(&(recovered.tenure, n)) {
            true => "miss",
            false => "hit",
        };
        assert_eq!(row["outcome"], outcome, "{row}");
    }
    let window = (&package["run"]["start"], &package["run"]["end"]);
    assert_eq!(window, (&json!(loss), &json!(latest + 1)), "the run window");
    assert_eq!(package["interval"], latest + 1 - loss);
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> &str {
    (payload.downcast_ref::<String>().map(String::as_str))
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or_default()
}

/// The simulation exercises `Takeover::nominated` and `Takeover::run`, so a held record is the judge's verdict on
/// the library's takeover sequence.
#[test]
fn the_host_loss_export_is_judged_held_on_two_roots_with_four_rules_outside_its_world() {
    for root in [1, 2] {
        let config = Config::host_loss(root);
        let report = match root {
            1 => root_one(),
            _ => run(&config).expect("a run inside the limits"),
        };
        assert_eq!(report.credit(), Verdict::Pass, "root {root}'s run passes");
        assert!(!report.planted);
        let files = export(&report);
        assert_eq!(
            files,
            export(&report),
            "two exports of one report are byte-equal"
        );
        if root == 1 {
            let again = run(&config).expect("a run inside the limits");
            assert_eq!(
                export(&again),
                files,
                "two runs of root 1 export the same bytes"
            );
        }
        assert_restates(&report, &files);
        if root == 1 {
            let mut shifted = report.clone();
            shifted.hosts.fired[0] = Some(3);
            let moved = export(&shifted);
            assert_restates(&shifted, &moved);
            let stop: Value = serde_json::from_slice(&moved["injection/stop.json"]).expect("JSON");
            assert_eq!(stop["time"], 3);
            let package: Value = serde_json::from_slice(&moved["package.json"]).expect("JSON");
            assert_eq!(package["baseline"], json!({"start": BOOT, "end": 3}));
        }
        let (code, record) = judged(files);
        assert_eq!(code, 0, "{record:#}");
        assert_eq!(
            graded(&record),
            ("simulation", "COMPLETED", "HELD"),
            "{record:#}"
        );
        assert_results(&record, &[]);
        assert_eq!(record["kind"], "simulation");
        let revision = "0000000000000000000000000000000000000000";
        assert_eq!(
            (&record["revision"], &record["date"]),
            (&json!(revision), &json!("1970-01-01"))
        );
        assert_eq!(record["result"], "held on 7 rules, 4 outside its world");
        assert_eq!(record["reach"]["met"], true);
    }
}

#[test]
fn a_restored_entry_miss_planted_in_the_run_is_judged_disproven_on_the_witness_first_hit() {
    let report = run(&Config::host_loss(1).hostile(Plant::RestoredEntryMiss, 1))
        .expect("a run inside the limits");
    assert!(report.planted, "the plant changed the run");
    let two = fleet_shard(&report.shards, 2);
    let successor = two.recoveries.last().expect("shard 2's successor");
    assert_eq!(successor.sweep, Some((7, 6)));
    assert_eq!(two.unserved, [(successor.tenure, 2)]);
    let (code, record) = judged(export(&report));
    let detail = disproven(code, &record, &["witness-first-hit"]);
    assert_eq!(
        detail,
        [["s2/object-2 is requested and never hit before the end of observation"]]
    );
}

#[test]
fn the_witness_names_each_object_outside_its_shards_acknowledged_invalidations() {
    let mut report = root_one();
    let one = (report.shards.iter_mut()).find(|of| of.placement.shard.get() == 1);
    one.expect("shard 1").invalidated = BTreeSet::from([2]);
    let files = export(&report);
    let package: Value = serde_json::from_slice(&files["package.json"]).expect("JSON");
    let pinned = package["witness"].as_array().expect("the witness keys");
    let of_one = |row: &&Value| {
        row["key"]
            .as_str()
            .is_some_and(|key| key.starts_with("s1/"))
    };
    let keys: Vec<&Value> = pinned
        .iter()
        .filter(of_one)
        .map(|row| &row["key"])
        .collect();
    let rows = lines(&files, "witness.jsonl");
    let swept: Vec<&Value> = rows.iter().filter(of_one).map(|row| &row["key"]).collect();
    let expected = [1, 3, 4, 5, 6, 7, 8].map(|n| json!(format!("s1/object-{n}")));
    assert_eq!(keys, expected.iter().collect::<Vec<_>>());
    assert_eq!(swept, keys);
}

/// The report carries one round for each recovery, so the package states where a witness stamp stands before its
/// GET's send and which GETs the rows hold.
#[test]
fn the_package_states_the_limits_of_its_witness_stamps_and_rows() {
    let files = export(&root_one());
    let package: Value = serde_json::from_slice(&files["package.json"]).expect("JSON");
    let clock = package["clock"].as_str().expect("the package's clock");
    for stated in [
        "stands at the round its successor's client session opened",
        "a lower bound of the send round of each later GET",
        "the report carries one round for each recovery",
        "a later GET of a sweep may be sent at or after that end",
    ] {
        assert!(
            clock.contains(stated),
            "the clock states `{stated}`: {clock}"
        );
    }
    let note = package["note"].as_str().expect("the package's note");
    for stated in [
        "in ascending object number",
        "The rows hold the sweeps' GETs alone",
    ] {
        assert!(note.contains(stated), "the note states `{stated}`: {note}");
    }
}

/// The cut history ends shard 1 under the lost owner, which contradicts the takeover. The judge then reads each of
/// shard 1's seven witness hits as standing before its shard's takeover write, which contradicts the
/// witness-first-hit.
#[test]
fn a_history_cut_before_its_takeover_is_judged_disproven_on_the_takeover() {
    let mut report = root_one();
    let (shard, versions) = &mut report.evidence.histories[0];
    assert_eq!(shard.get(), 1);
    let change = seeded(1, versions).change;
    assert!(change < versions.len(), "shard 1 changed owner");
    versions.truncate(change);
    let (code, record) = judged(export(&report));
    let named = ["one-owner-per-tenure", "takeover", "witness-first-hit"];
    let detail = disproven(code, &record, &named);
    let unowned = |line: &String| {
        line.contains(" activates s1 at generation ")
            && line.contains("but no version names it owner")
    };
    assert_eq!((detail[0].len(), detail[0].iter().all(unowned)), (1, true));
    let cut = |line: &String| line.starts_with("s1 ends the run window as ");
    assert_eq!((detail[1].len(), detail[1].iter().all(cut)), (1, true));
    let before = |line: &String| {
        line.starts_with("s1/") && line.ends_with("before its shard's takeover write")
    };
    assert_eq!((detail[2].len(), detail[2].iter().all(before)), (7, true));
}

/// `Plant::TwinStart` records a second activation of a successor's tenure on a host other than the successor.
#[test]
fn a_twin_start_planted_in_the_run_is_judged_disproven_on_one_owner_per_tenure() {
    let report =
        run(&Config::host_loss(1).hostile(Plant::TwinStart, 0)).expect("a run inside the limits");
    assert!(report.planted, "the plant changed the run");
    assert_eq!(report.hosts.twin_started, 1);
    let (code, record) = judged(export(&report));
    let detail = disproven(code, &record, &["one-owner-per-tenure"]);
    let roles = |shard: u32| fleet_shard(&report.shards, shard);
    let twins: Vec<_> = (report.evidence.activations.iter())
        .filter(|(shard, _, host)| {
            ![roles(shard.get()).owner, roles(shard.get()).standby].contains(host)
        })
        .collect();
    let [(shard, tenure, twin)] = twins[..] else {
        panic!("one activation on a host with no role on its shard: {twins:?}");
    };
    let mut pair = [host_name(roles(shard.get()).standby), host_name(*twin)];
    pair.sort();
    let (s, g, epoch) = (shard.get(), tenure.g, tenure.a);
    let expected = [
        format!(
            "{} activates s{s} at generation {g} epoch {epoch}, but no version names it owner at attempts {}",
            host_name(*twin),
            epoch / 2
        ),
        format!(
            "s{s} is activated 2 times at generation {g} epoch {epoch}, by ['{}', '{}']",
            pair[0], pair[1]
        ),
    ];
    assert_eq!(detail[0], expected, "{record:#}");
    let rule = &record["rules"]["one-owner-per-tenure"];
    assert_eq!(
        rule["guardrail"],
        "two hosts activating one tenure of a shard"
    );
    assert_eq!(rule["past_stop_condition"], true);
}

#[test]
fn a_replacement_receipt_in_the_evidence_is_judged_disproven_on_no_replacement_receipt() {
    let mut report = root_one();
    let (shard, versions) = &report.evidence.histories[0];
    assert_eq!(shard.get(), 1);
    let last = versions.last().expect("a version of s1");
    let request = Request {
        namespace: last.namespace,
        shard: last.shard,
        generation: ShardGeneration::new(last.generation.get() + 1).expect("a generation"),
    };
    report.evidence.receipts[0] = Some(Receipt {
        request,
        ..receipt()
    });
    let loss = report.hosts.fired[0].expect("the loss fired");
    let (code, record) = judged(export(&report));
    let detail = disproven(code, &record, &["no-replacement-receipt"]);
    assert_eq!(
        detail,
        [[format!(
            "a replacement receipt of s1 by {PRINCIPAL} at {loss}"
        )]]
    );
    let rule = &record["rules"]["no-replacement-receipt"];
    assert_eq!(
        rule["guardrail"],
        "any replacement receipt written by the reconciler principal"
    );
    assert_eq!(rule["past_stop_condition"], true);
}

#[test]
fn the_export_refuses_a_report_outside_its_premises() {
    let report = root_one();
    let refused = |alter: &dyn Fn(&mut Report), premise: &str| {
        let mut altered = report.clone();
        alter(&mut altered);
        let payload = catch_unwind(AssertUnwindSafe(|| export(&altered))).expect_err(premise);
        let text = panic_text(payload.as_ref());
        assert!(text.contains(premise), "{premise}: {text}");
    };
    refused(
        &|report| report.config.scenario = Scenario::OwnerPause,
        "the report is of a host loss",
    );
    refused(
        &|report| report.hosts.host_losses = 2,
        "the run loses one host and counts one crash",
    );
    refused(
        &|report| report.crashes = 2,
        "the run loses one host and counts one crash",
    );
    refused(
        &|report| report.hosts.refused = 1,
        "the standbys read healthy",
    );
    refused(
        &|report| {
            report.hosts.exempt.insert(4);
        },
        "the standbys read healthy",
    );
    let restored = |report: &mut Report| {
        let versions = &mut report.evidence.histories[0].1;
        let change = seeded(1, versions).change;
        let kept = versions[change - 1];
        let cleared = ShardRecord {
            standby: None,
            ..kept
        };
        versions.splice(change..change, [cleared, kept]);
    };
    refused(
        &restored,
        "shard 1 keeps its generation, volume and standby before its first owner change",
    );
    let swept = |report: &mut Report, sweep: (u32, u32), unserved: &[u8]| {
        let shard = (report.shards.iter_mut()).find(|of| of.placement.shard.get() == 2);
        let shard = shard.expect("shard 2");
        let recovered = shard.recoveries.last_mut().expect("shard 2's successor");
        recovered.sweep = Some(sweep);
        let tenure = recovered.tenure;
        shard.unserved = unserved.iter().map(|&n| (tenure, n)).collect();
    };
    refused(
        &|report| swept(report, (6, 6), &[]),
        "shard 2's sweep requested each object outside its invalidations",
    );
    let counts = "shard 2's sweep counts exact each requested object outside its unserved ones";
    refused(&|report| swept(report, (7, 8), &[]), counts);
    refused(&|report| swept(report, (7, 6), &[]), counts);
    refused(&|report| swept(report, (7, 6), &[1]), counts);
    let moved = |change: fn(&mut ShardRecord, &ShardRecord)| {
        move |report: &mut Report| {
            let other = report.evidence.histories[1].1[0];
            let versions = &mut report.evidence.histories[0].1;
            let change_at = seeded(1, versions).change;
            let kept = versions[change_at - 1];
            let mut changed = kept;
            change(&mut changed, &other);
            versions.splice(change_at..change_at, [changed, kept]);
        }
    };
    let prefix = "shard 1 keeps its generation, volume and standby before its first owner change";
    refused(
        &moved(|record, _| {
            record.generation =
                ShardGeneration::new(record.generation.get() + 1).expect("a generation");
        }),
        prefix,
    );
    refused(&moved(|record, other| record.active = other.active), prefix);
    refused(
        &|report| {
            let target = fleet_shard(&report.shards, report.evidence.losses.hosts[0]).owner;
            let other = (report.shards.iter())
                .find(|of| of.owner != target)
                .expect("a shard of another owner");
            let shard = other.placement.shard.get();
            report.evidence.losses.hosts.push(shard);
        },
        "one host owned every shard the loss took",
    );
    refused(
        &|report| {
            let (shard, tenure, _) = report.evidence.activations[0];
            let stranger = Host::new(99).expect("a host");
            report.evidence.activations.push((shard, tenure, stranger));
        },
        "activation names h99, a host of the zone",
    );
    refused(
        &|report| report.evidence.receipts[0] = Some(receipt()),
        "shard 1's receipt names its shard",
    );
}

#[test]
fn a_skipped_sweep_planted_in_the_run_leaves_the_witness_first_hit_unobserved() {
    let report = run(&Config::host_loss(1).hostile(Plant::SkippedSweep, 1))
        .expect("a run inside the limits");
    assert!(report.planted, "the plant changed the run");
    let recovered = fleet_shard(&report.shards, 2).recoveries.last();
    assert_eq!(recovered.map(|recovered| recovered.sweep), Some(None));
    let (code, record) = judged(export(&report));
    assert_eq!(code, 1, "{record:#}");
    assert_eq!(
        graded(&record),
        ("simulation", "COMPLETED", "INCONCLUSIVE"),
        "{record:#}"
    );
    assert_eq!(
        record["rules"]["witness-first-hit"]["result"], "unobserved",
        "{record:#}"
    );
}

/// The export seals its collections as the stop controller's `seal` does. A witness row removed after the seal, with
/// the file's count in `coverage.json` lowered to match, changes the file's digest, and the judge refuses it.
#[test]
fn a_witness_row_removed_after_the_exports_seal_is_refused() {
    let mut files = export(&root_one());
    let rows = lines(&files, "witness.jsonl");
    assert!(rows.len() > 1, "the export holds witness rows to remove");
    let kept = &rows[..rows.len() - 1];
    files.insert("witness.jsonl".into(), json_lines(kept.iter().cloned()));
    let mut coverage: Value = serde_json::from_slice(&files["coverage.json"]).expect("JSON");
    coverage["witness.jsonl"]["lines"] = json!(kept.len());
    files.insert("coverage.json".into(), json_file(&coverage));
    let stderr = refused(files);
    assert!(
        stderr.contains("witness.jsonl differs from the bytes injection/collected.json seals"),
        "{stderr}"
    );
}

/// A package that lists every host the fleet directory admits, [`MAX_HOSTS`], is judged, and one more host is
/// refused; a shard list one past [`MAX_SLOTS`] is refused too. The judge reads both bounds from their declarations,
/// and the test compares them with the compiled constants.
#[test]
fn a_package_host_list_past_the_fleet_directorys_bound_is_refused() {
    let files = export(&root_one());
    let mut package: Value = serde_json::from_slice(&files["package.json"]).expect("JSON");
    let hosts = package["hosts"].as_array_mut().expect("a host list");
    let spares = MAX_HOSTS - hosts.len();
    hosts.extend((0..spares).map(|n| json!(format!("spare-{n}"))));
    let repackaged = |package: &Value| {
        let mut files = files.clone();
        let bytes = json_file(package);
        let mut roles: Value =
            serde_json::from_slice(&files["injection/roles.json"]).expect("JSON");
        roles["package_sha256"] = json!(hex(&Sha256::digest(&bytes)));
        files.insert("injection/roles.json".into(), json_file(&roles));
        files.insert("package.json".into(), bytes);
        files
    };
    let (code, record) = judged(repackaged(&package));
    assert_eq!(code, 1, "{record:#}");
    assert_eq!(
        record["rules"]["one-owner-per-tenure"]["result"], "unobserved",
        "a spare host has no activation records: {record:#}"
    );
    let hosts = package["hosts"].as_array_mut().expect("a host list");
    hosts.push(json!("spare-past-the-bound"));
    let stderr = refused(repackaged(&package));
    let words = format!(
        "package.json hosts holds {} entries, more than the {MAX_HOSTS}",
        MAX_HOSTS + 1
    );
    assert!(stderr.contains(&words), "{stderr}");
    let mut package: Value = serde_json::from_slice(&files["package.json"]).expect("JSON");
    let shards = package["shards"].as_array_mut().expect("a shard list");
    let spares = MAX_SLOTS + 1 - shards.len();
    shards.extend((0..spares).map(|n| json!(format!("spare-{n}"))));
    let stderr = refused(repackaged(&package));
    let words = format!(
        "package.json shards holds {} entries, more than the {MAX_SLOTS}",
        MAX_SLOTS + 1
    );
    assert!(stderr.contains(&words), "{stderr}");
}
