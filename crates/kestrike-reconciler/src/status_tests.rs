use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use kestrike::failover::loss::Phase;
use kestrike::failover::records::{Host, VolumeId};
use kestrike::failover::report::status::StoreAlarm;
use kestrike::failover::retire::Target;
use kestrike::failover::standbys::{Closed, Need};
use kestrike::failover::zone_loop::config::CapBelowShards;
use kestrike::failover::zone_loop::directory::SuccessionRefusal;
use kestrike::failover::zone_loop::observe::{Completeness, Source};
use kestrike::failover::zone_loop::status::{
    Blocker, EnrollPhase, Holds, ShardState, ShardStatus, VerdictCounts, ZoneStatus,
};
use kestrike::net::ownership::{Shard, ShardGeneration};
use kestrike::storage::store::StoreError;
use serde_json::{Value, json};

use super::{Context, JSON, SEALED, document, line, name, publish};
use crate::fixture::Scratch;

fn row(shard: u32, state: ShardState, blocker: Option<Blocker>) -> ShardStatus {
    ShardStatus {
        shard: Shard::new(shard).unwrap(),
        state,
        blocker,
        target: None,
        closed: None,
        exposure_us: None,
        overdue: false,
    }
}

fn context(alarm: StoreAlarm) -> Context {
    Context {
        zone: 1,
        alarm,
        directory: Some(7),
        now_us: 90,
        ended_us: 140,
        tick_us: 50,
        wall_us: 1_000,
    }
}

/// A zone with a shard in each state whose variant carries fields, and one blocked shard.
fn status() -> ZoneStatus {
    let host = Host::new(12).unwrap();
    let mut enrolling = row(
        2,
        ShardState::Enrolling {
            need: Need::Standby,
            phase: EnrollPhase::Reserved,
            host,
        },
        None,
    );
    enrolling.target = Some(Target {
        generation: ShardGeneration::new(3).unwrap(),
        owner: Host::new(11).unwrap(),
        attempts: 4,
    });
    enrolling.exposure_us = Some(70);
    enrolling.overdue = true;
    ZoneStatus {
        shards: vec![
            row(1, ShardState::NoCandidate, Some(Blocker::CensusFull)),
            enrolling,
            row(
                3,
                ShardState::Replacing {
                    phase: Phase::Created(VolumeId::new("vol-0a").unwrap()),
                },
                None,
            ),
            row(4, ShardState::Unobserved(Source::Directory), None),
            row(
                5,
                ShardState::Unobserved(Source::Store(StoreError::Unavailable)),
                None,
            ),
            row(
                6,
                ShardState::Unobserved(Source::Succession(SuccessionRefusal::Departed(
                    Host::new(13).unwrap(),
                ))),
                None,
            ),
        ],
        census: Some(2),
        cap: 4,
        cap_below: Some(CapBelowShards { cap: 4, shards: 5 }),
        inflight: Some(1),
        holds: Holds {
            warm_up: true,
            zone_host: true,
            operator: false,
        },
        verdicts: Some(VerdictCounts {
            live: 1,
            lost: 3,
            conflict: 0,
            unknown: 2,
        }),
        complete: Completeness {
            reports: false,
            instances: true,
            volumes: false,
            store: true,
        },
        unnamed: None,
        tick: 5,
        started_us: 10,
    }
}

/// The document carries each shard's state and blocker under the zone status's own variant names, with the
/// variant's fields beside the name, and the zone values as the survey reported them.
#[test]
fn the_document_renders_the_zone_status_states_and_blockers_by_name() {
    let status = status();
    let rendered = document(&status, &context(StoreAlarm::Clear));
    let empty = |shard: u32, state: &str| json!({ "shard": shard, "state": state, "blocker": null, "closed": null, "target": null, "exposure_us": null, "overdue": false });
    let mut no_candidate = empty(1, "NoCandidate");
    no_candidate["blocker"] = json!("CensusFull");
    let enrolling = json!({
        "shard": 2, "state": "Enrolling", "need": "Standby", "phase": "Reserved", "host": 12, "blocker": null,
        "closed": null,
        "target": { "generation": 3, "owner": 11, "attempts": 4 }, "exposure_us": 70, "overdue": true,
    });
    let mut replacing = empty(3, "Replacing");
    replacing["phase"] = json!("Created");
    replacing["volume"] = json!("vol-0a");
    let mut directory = empty(4, "Unobserved");
    directory["source"] = json!("Directory");
    directory["error"] = Value::Null;
    let mut store = empty(5, "Unobserved");
    store["source"] = json!("Store");
    store["error"] = json!("Unavailable");
    let mut succession = empty(6, "Unobserved");
    succession["source"] = json!("Succession");
    succession["error"] = json!("Departed(Host(13))");
    assert_eq!(
        rendered,
        json!({
            "format": 2, "zone": 1, "tick": 5, "started_us": 10, "ended_us": 140, "overran": false,
            "observed_us": 90, "observed_at_us": 1_000,
            "directory_version": 7, "client": "Admitted", "store_alarm": "Clear", "census": 2, "cap": 4,
            "cap_below": { "cap": 4, "shards": 5 }, "inflight": 1,
            "holds": { "warm_up": true, "zone_host": true, "operator": false },
            "verdicts": { "live": 1, "lost": 3, "conflict": 0, "unknown": 2 },
            "complete": { "reports": false, "instances": true, "volumes": false, "store": true },
            "unnamed_volumes": null,
            "shards": [no_candidate, enrolling, replacing, directory, store, succession],
        })
    );
    let withdrawn = document(&status, &context(StoreAlarm::Regression));
    assert_eq!(withdrawn["client"], json!("ClientWithdrawn"));
    assert_eq!(withdrawn["store_alarm"], json!("Regression"));
}

/// A tick whose `ZoneStatus` holds no in-flight count and no verdict counts writes `null` for each, so a reader
/// tells a tick that formed no host verdicts from one that counted no host in any class.
#[test]
fn absent_inflight_and_verdicts_are_null_and_zero_counts_are_counts() {
    let mut status = status();
    status.inflight = None;
    status.verdicts = None;
    let absent = document(&status, &context(StoreAlarm::Clear));
    assert_eq!(absent["inflight"], Value::Null);
    assert_eq!(absent["verdicts"], Value::Null);
    status.inflight = Some(0);
    status.verdicts = Some(VerdictCounts::default());
    let zero = document(&status, &context(StoreAlarm::Clear));
    assert_eq!(zero["inflight"], json!(0));
    assert_eq!(
        zero["verdicts"],
        json!({ "live": 0, "lost": 0, "conflict": 0, "unknown": 0 })
    );
}

/// A shard the plan reads closed names the bound its active volume stands at, under the cause's variant name, for
/// each cause; a shard with no cause writes `null`.
#[test]
fn a_closed_shard_names_its_cause_and_a_shard_without_one_writes_null() {
    let causes = [
        (Closed::LiveCap, "LiveCap"),
        (Closed::EntryCap, "EntryCap"),
        (Closed::PairCap, "PairCap"),
        (Closed::OwnEntry, "OwnEntry"),
        (Closed::KeyTaken, "KeyTaken"),
    ];
    for (cause, text) in causes {
        let mut status = status();
        let mut closed = row(1, ShardState::Closed, Some(Blocker::AttachClosed));
        closed.closed = Some(cause);
        status.shards = vec![closed, row(2, ShardState::Protected, None)];
        let rendered = document(&status, &context(StoreAlarm::Clear));
        let shards = &rendered["shards"];
        assert_eq!(
            (&shards[0]["state"], &shards[0]["closed"]),
            (&json!("Closed"), &json!(text))
        );
        assert_eq!(shards[1]["closed"], Value::Null);
    }
}

/// The zone's count of unnamed volumes is the survey's count, zero included, and `null` on a tick whose
/// `ZoneStatus` holds none, so a reader tells a tick that counted no such volume from one whose count did not read.
#[test]
fn the_unnamed_count_is_a_count_and_null_when_the_tick_holds_none() {
    let mut status = status();
    for (unnamed, rendered) in [
        (None, Value::Null),
        (Some(0), json!(0)),
        (Some(2), json!(2)),
    ] {
        status.unnamed = unnamed;
        let document = document(&status, &context(StoreAlarm::Clear));
        assert_eq!(document["unnamed_volumes"], rendered, "{unnamed:?}");
    }
}

/// The refusal of a `Succession` shard is its `SuccessionRefusal` variant with the host it names, for each variant.
#[test]
fn a_succession_shard_names_its_refusal_as_its_error() {
    let host = Host::new(13).unwrap();
    let refusals = [
        (SuccessionRefusal::Zone, "Zone"),
        (SuccessionRefusal::Version, "Version"),
        (SuccessionRefusal::Departed(host), "Departed(Host(13))"),
        (SuccessionRefusal::Unretired(host), "Unretired(Host(13))"),
        (SuccessionRefusal::Reassigned(host), "Reassigned(Host(13))"),
        (SuccessionRefusal::Rezoned(host), "Rezoned(Host(13))"),
    ];
    for (refusal, text) in refusals {
        let mut status = status();
        status.shards = vec![row(
            1,
            ShardState::Unobserved(Source::Succession(refusal)),
            None,
        )];
        let rendered = document(&status, &context(StoreAlarm::Clear));
        let shard = &rendered["shards"][0];
        assert_eq!(
            (&shard["state"], &shard["source"], &shard["error"]),
            (&json!("Unobserved"), &json!("Succession"), &json!(text))
        );
    }
}

/// A `Replacing` shard names its phase, and its volume once the phase holds one: `Open` and `Issued` write a `null`
/// volume.
#[test]
fn a_replacing_shard_names_its_phase_and_a_null_volume_before_one_is_created() {
    let phases = [
        (Phase::Open, "Open", Value::Null),
        (Phase::Issued, "Issued", Value::Null),
        (
            Phase::Created(VolumeId::new("vol-0b").unwrap()),
            "Created",
            json!("vol-0b"),
        ),
    ];
    for (phase, label, volume) in phases {
        let mut status = status();
        status.shards = vec![row(1, ShardState::Replacing { phase }, None)];
        let rendered = document(&status, &context(StoreAlarm::Clear));
        let shard = &rendered["shards"][0];
        assert_eq!(
            (&shard["state"], &shard["phase"], &shard["volume"]),
            (&json!("Replacing"), &json!(label), &volume)
        );
    }
}

/// `overran` is true exactly when the tick's duration, `ended_us - observed_us`, passes `tick_us`: a tick that
/// lasts exactly `tick_us` did not overrun.
#[test]
fn overran_is_true_only_past_the_tick_period() {
    let status = status();
    for (ended_us, overran) in [(90, false), (140, false), (141, true), (1_000, true)] {
        let context = Context {
            ended_us,
            ..context(StoreAlarm::Clear)
        };
        let rendered = document(&status, &context);
        assert_eq!(rendered["ended_us"], json!(ended_us));
        assert_eq!(rendered["overran"], json!(overran), "ended at {ended_us}");
        assert_eq!(context.duration_us(), ended_us - 90);
    }
}

#[test]
fn the_line_counts_states_and_blockers_and_names_the_holds_sources_and_client() {
    let status = status();
    assert_eq!(
        line(&status, &context(StoreAlarm::Clear)),
        "tick=5 zone=1 shards=6 states=Enrolling:1,NoCandidate:1,Replacing:1,Unobserved:3 \
         blockers=CensusFull:1 census=2 cap=4 inflight=1 holds=warm_up,zone_host complete=instances,store \
         client=Admitted"
    );
    let mut empty = status;
    empty.shards.clear();
    empty.census = None;
    empty.inflight = None;
    empty.holds.warm_up = false;
    empty.holds.zone_host = false;
    empty.complete = Completeness::default();
    assert_eq!(
        line(&empty, &context(StoreAlarm::Log)),
        "tick=5 zone=1 shards=0 states=- blockers=- census=- cap=4 inflight=unread holds=- complete=- \
         client=ClientWithdrawn(Log)"
    );
}

/// The line counts every shard a blocker holds and lists the blockers by name, and names the operator hold and the
/// report source when they are set.
#[test]
fn the_line_counts_each_blocker_and_names_every_hold_and_source() {
    let mut status = status();
    status.shards = vec![
        row(1, ShardState::NoCandidate, Some(Blocker::CensusFull)),
        row(2, ShardState::NoCandidate, Some(Blocker::CensusFull)),
        row(3, ShardState::OwnerUnknown, Some(Blocker::OwnerNotReady)),
        row(4, ShardState::Protected, None),
    ];
    status.holds.operator = true;
    status.complete = Completeness {
        reports: true,
        instances: true,
        volumes: true,
        store: true,
    };
    assert_eq!(
        line(&status, &context(StoreAlarm::Clear)),
        "tick=5 zone=1 shards=4 states=NoCandidate:2,OwnerUnknown:1,Protected:1 \
         blockers=CensusFull:2,OwnerNotReady:1 census=2 cap=4 inflight=1 holds=warm_up,zone_host,operator \
         complete=reports,instances,volumes,store client=Admitted"
    );
}

/// Each state's name is its variant's name as `ZoneStatus` spells it, the leading identifier of its `Debug` form.
#[test]
fn every_state_is_named_by_its_variant() {
    let host = Host::new(12).unwrap();
    let states = [
        ShardState::Protected,
        ShardState::Initial,
        ShardState::Enrolling {
            need: Need::Fresh,
            phase: EnrollPhase::Attached,
            host,
        },
        ShardState::NoCandidate,
        ShardState::Closed,
        ShardState::StandbyUnknown,
        ShardState::OwnerUnknown,
        ShardState::VolumeImpaired,
        ShardState::LossUnconfirmed,
        ShardState::Replacing { phase: Phase::Open },
        ShardState::ReplacementHeld,
        ShardState::ReplacementExhausted,
        ShardState::RetirementRequested,
        ShardState::Unobserved(Source::Store(StoreError::Unavailable)),
    ];
    for state in states {
        let debug = format!("{state:?}");
        let variant = debug
            .split(|c: char| !c.is_ascii_alphanumeric())
            .next()
            .unwrap();
        assert_eq!(name(&state), variant, "{debug}");
    }
}

fn open(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(path)
        .unwrap()
}

fn tick_of(path: &Path) -> Value {
    serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap()["tick"].clone()
}

/// A tick whose seal failed removes the previous tick's sealed status, so none outlives its tick's document. A
/// later tick without a seal finds no sealed status to remove and still replaces the document.
#[test]
fn a_failed_seal_removes_the_previous_sealed_status() {
    let scratch = Scratch::new("publish");
    let directory = open(scratch.path());
    let sealed = scratch.path().join(SEALED);
    publish(&directory, &json!({ "tick": 1 }), Some(b"sealed")).unwrap();
    assert_eq!(fs::read(&sealed).unwrap(), b"sealed");
    publish(&directory, &json!({ "tick": 2 }), None).unwrap();
    assert!(!sealed.exists());
    assert_eq!(tick_of(&scratch.path().join(JSON)), json!(2));
    publish(&directory, &json!({ "tick": 3 }), None).unwrap();
    assert!(!sealed.exists());
    assert_eq!(tick_of(&scratch.path().join(JSON)), json!(3));
}

#[test]
fn a_publish_that_fails_to_stage_leaves_the_previous_files() {
    let scratch = Scratch::new("publish-blocked");
    let directory = open(scratch.path());
    publish(&directory, &json!({ "tick": 1 }), Some(b"sealed-1")).unwrap();
    for name in [JSON, SEALED] {
        let staged = scratch.path().join(format!(".{name}.staged"));
        fs::create_dir(&staged).unwrap();
        let error = publish(&directory, &json!({ "tick": 2 }), Some(b"sealed-2")).unwrap_err();
        assert!(
            error.to_string().starts_with(&format!("{name}: ")),
            "{error}"
        );
        assert_eq!(tick_of(&scratch.path().join(JSON)), json!(1));
        assert_eq!(fs::read(scratch.path().join(SEALED)).unwrap(), b"sealed-1");
        fs::remove_dir(&staged).unwrap();
    }
}

/// `publish` installs the sealed status before the document. A directory at `status.sealed` fails the seal's rename
/// and its removal, and each failed publish leaves `status.json` at the previous tick.
#[test]
fn a_publish_that_fails_at_the_sealed_status_leaves_the_previous_document() {
    let scratch = Scratch::new("publish-order");
    let directory = open(scratch.path());
    publish(&directory, &json!({ "tick": 1 }), Some(b"sealed-1")).unwrap();
    let sealed = scratch.path().join(SEALED);
    fs::remove_file(&sealed).unwrap();
    fs::create_dir(&sealed).unwrap();
    for seal in [Some(b"sealed-2".as_slice()), None] {
        let error = publish(&directory, &json!({ "tick": 2 }), seal).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::IsADirectory, "{error}");
        assert!(
            error.to_string().starts_with(&format!("{SEALED}: ")),
            "{error}"
        );
        assert_eq!(tick_of(&scratch.path().join(JSON)), json!(1));
    }
}

#[test]
fn a_link_at_a_staged_name_keeps_its_target_bytes() {
    let scratch = Scratch::new("publish-links");
    let directory = open(scratch.path());
    let sentinel = scratch.write("sentinel", "sentinel");
    let staged = |name: &str| scratch.path().join(format!(".{name}.staged"));
    let links: [fn(&Path, &Path) -> std::io::Result<()>; 2] = [
        |from, to| std::os::unix::fs::symlink(from, to),
        |from, to| fs::hard_link(from, to),
    ];
    for (tick, [json_link, sealed_link]) in [(1, [links[0], links[1]]), (2, [links[1], links[0]])] {
        json_link(&sentinel, &staged(JSON)).unwrap();
        sealed_link(&sentinel, &staged(SEALED)).unwrap();
        let sealed = format!("sealed-{tick}");
        publish(
            &directory,
            &json!({ "tick": tick }),
            Some(sealed.as_bytes()),
        )
        .unwrap();
        assert_eq!(fs::read(&sentinel).unwrap(), b"sentinel");
        for name in [JSON, SEALED] {
            let meta = fs::symlink_metadata(scratch.path().join(name)).unwrap();
            assert!(meta.is_file(), "{name}");
            assert_eq!(meta.permissions().mode() & 0o777, 0o600, "{name}");
        }
        assert_eq!(tick_of(&scratch.path().join(JSON)), json!(tick));
        assert_eq!(
            fs::read(scratch.path().join(SEALED)).unwrap(),
            sealed.as_bytes()
        );
    }
}
