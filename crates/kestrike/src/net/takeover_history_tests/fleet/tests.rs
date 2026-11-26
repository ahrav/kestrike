use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::bounds::{LIMITS, Limits, Refused};
use super::oracles::{self, HostUse, Judged, Retention, Settle, Volumes, Watched};
use super::*;
use crate::sim::choice::ChoiceError;

pub(super) fn passing(config: &Config) -> Report {
    let report = run_shared(config).expect("a run inside the limits");
    assert_eq!(report.credit(), Verdict::Pass, "{}", report.summary());
    report
}

fn assert_two_swept_recoveries(report: &Report, objects: u32) {
    for shard in &report.shards {
        assert!(shard.blockers.is_empty());
        let order: Vec<bool> = shard.recoveries.iter().map(|r| r.after_crash).collect();
        assert_eq!(order, [false, true]);
        let recovered: Vec<(Tenure, Host)> = (shard.recoveries.iter())
            .map(|recovered| (recovered.tenure, shard.owner))
            .collect();
        assert_eq!(shard.activated, recovered, "each recovery activated once");
        for recovered in &shard.recoveries {
            assert!(recovered.peak_bytes > 0);
            assert_eq!(recovered.sweep, Some((objects, objects)));
            assert!(recovered.rounds <= SETTLE_ROUNDS);
        }
    }
}

#[test]
fn six_hosts_restart_six_shards_warm_with_no_takeover_on_three_roots() {
    for root in [1, 2, 3] {
        let report = passing(&Config::six(root));
        assert_eq!((report.takeovers, report.crashes), (0, 6));
        let surveyed = Reconciled {
            ticks: 24,
            unnamed: 0,
        };
        assert_eq!(report.reconciled, surveyed);
        let owners: BTreeSet<u64> = (report.shards.iter())
            .map(|shard| shard.owner.get())
            .collect();
        assert_eq!(owners.len(), 6, "each host owns one shard");
        assert_two_swept_recoveries(&report, 8);
        for shard in &report.shards {
            assert_eq!(shard.attempts, 6, "two restarts from E = 4");
            let tenures: Vec<u64> = shard.recoveries.iter().map(|r| r.tenure.a).collect();
            assert_eq!(tenures, [10, 12]);
        }
        let (offered, served) = (report.shards.iter()).fold((0, 0), |sum, shard| {
            (
                sum.0 + shard.neighbour.offered,
                sum.1 + shard.neighbour.served,
            )
        });
        assert_eq!(
            (offered, served),
            (12, 12),
            "two requests in each of six recoveries"
        );
    }
}

#[test]
fn a_live_owner_renews_its_report_window_while_other_shards_recover() {
    let report = passing(&Config::six(1));
    for shard in &report.shards {
        assert!(
            shard.reports as u64 > SETTLE_ROUNDS,
            "shard {} submitted {} Reports",
            shard.placement.shard.get(),
            shard.reports
        );
    }
}

#[test]
fn hosts_that_own_several_shards_in_two_zones_restart_them_warm() {
    hosts_that_own_several_shards_in_two_zones_restart_them_warm_on(1);
}

pub(super) fn hosts_that_own_several_shards_in_two_zones_restart_them_warm_on(root: u64) {
    let report = passing(&Config::dense(root));
    assert_eq!((report.takeovers, report.crashes), (0, 8));
    let surveyed = Reconciled {
        ticks: 64,
        unnamed: 0,
    };
    assert_eq!(report.reconciled, surveyed, "two stand-ins in each zone");
    assert_two_swept_recoveries(&report, 4);
    for shard in &report.shards {
        assert_ne!(shard.owner, shard.standby);
        assert_eq!(shard.owner.get() / 1000, u64::from(shard.placement.zone.0));
        assert_eq!(
            shard.standby.get() / 1000,
            u64::from(shard.placement.zone.0)
        );
        assert!(shard.recoveries.iter().all(|r| r.share.owners == 4));
    }
}

#[test]
fn a_legal_run_earns_credit_only_when_every_shard_restarted_twice_with_no_blocker() {
    for config in [Config::six(1), Config::dense(1)] {
        let report = passing(&config);
        let at = report.shards.len() - 1;
        let shard = format!("shard {}", report.shards[at].placement.shard.get());
        let incomplete = Verdict::Fail(INCOMPLETE, shard);

        let mut blocked = report.clone();
        blocked.shards[at].blockers.push("Refused".into());
        assert_eq!(blocked.credit(), incomplete);

        let mut down = report.clone();
        down.shards[at].recoveries.pop();
        assert_eq!(down.credit(), incomplete);

        let mut unswept = report.clone();
        unswept.shards[at].recoveries[1].sweep = None;
        assert_eq!(unswept.credit(), incomplete);

        let failed = Verdict::Fail(oracles::LATE, "shard 1".into());
        let mut late = report.clone();
        late.verdicts.settles = failed.clone();
        assert_eq!(late.credit(), failed);

        let unrun = Verdict::Unrun(oracles::NO_NEIGHBOUR);
        let mut alone = report.clone();
        alone.verdicts.untouched = unrun.clone();
        assert_eq!(alone.credit(), unrun);

        let mut both = late.clone();
        both.verdicts.one_owner = Verdict::Unrun(oracles::NO_ACTIVATION);
        assert_eq!(both.credit(), failed, "a failure precedes an earlier Unrun");

        let mut unswept_and_blocked = blocked.clone();
        unswept_and_blocked.verdicts.retained = Verdict::Unrun(oracles::UNSWEPT);
        assert_eq!(unswept_and_blocked.credit(), incomplete);

        let mut taken = report.clone();
        taken.takeovers = 1;
        let took_over = Verdict::Fail(TOOK_OVER, "1 owner changes".into());
        assert_eq!(taken.credit(), took_over);

        let mut hostile = report;
        hostile.config = config.hostile(Plant::TwinTenure, 99);
        assert_eq!(hostile.credit(), Verdict::Unrun(HOSTILE));
    }
}

#[test]
fn one_identity_and_its_recorded_choices_replay_to_an_equal_report() {
    let config = Config::six(7);
    let report = passing(&config);
    assert_eq!(run(&config).as_ref(), Ok(&report));
    let recording = report.recording();
    let replayed = replay(&config, &recording).expect("the recording replays");
    assert_eq!((&replayed, replayed.digest()), (&report, report.digest()));
    let other = passing(&Config::six(8));
    assert_ne!(other.tape, report.tape, "another root decides otherwise");
    assert_ne!(other.digest(), report.digest());
    let mut longer = report.clone();
    longer.tape.push(0);
    assert_ne!(
        longer.digest(),
        report.digest(),
        "the digest covers the tape"
    );
}

#[test]
fn the_digest_changes_with_every_part_of_a_report() {
    let report = passing(&Config::six(1));
    let later = Tenure { g: 3, a: 14 };
    type Edit = fn(&mut Report);
    let edits: [(&str, Edit); 16] = [
        ("the takeovers", |r| r.takeovers += 1),
        ("the crashes", |r| r.crashes += 1),
        ("the rounds", |r| r.rounds += 1),
        ("the reconciler ticks", |r| r.reconciled.ticks += 1),
        ("the unnamed standbys", |r| r.reconciled.unnamed += 1),
        ("the decisions", |r| r.decisions += 1),
        ("a shard's owner", |r| {
            r.shards[5].owner = r.shards[5].standby
        }),
        ("a shard's standby", |r| {
            r.shards[5].standby = r.shards[5].owner;
        }),
        ("a shard's attempts", |r| r.shards[5].attempts += 1),
        ("a shard's served requests", |r| {
            r.shards[5].neighbour.served += 1;
        }),
        ("a shard's requested objects", |r| {
            r.shards[5].requested.push(1);
        }),
        ("a shard's Reports", |r| r.shards[5].reports += 1),
        ("a shard's blockers", |r| {
            r.shards[5].blockers.push("Unheld".into());
        }),
        ("a shard's activations", |r| {
            r.shards[5].activated.pop();
        }),
        ("a recovery's sweep", |r| {
            r.shards[5].recoveries[1].sweep = Some((8, 7));
        }),
        ("a recovery's rounds", |r| {
            r.shards[5].recoveries[1].rounds += 1;
        }),
    ];
    for (part, edit) in edits {
        let mut edited = report.clone();
        edit(&mut edited);
        assert_ne!(edited.digest(), report.digest(), "{part}");
    }
    let mut failing = report.clone();
    failing.verdicts.one_owner = Verdict::Fail(oracles::TWO_OWNERS, "shard 1".into());
    assert_ne!(failing.digest(), report.digest(), "the first verdict");
    let later_verdicts: [Edit; 5] = [
        |r| r.verdicts.keeps_volume = Verdict::Unrun(oracles::NO_CRASH),
        |r| r.verdicts.retained = Verdict::Unrun(oracles::UNSWEPT),
        |r| r.verdicts.settles = Verdict::Unrun(oracles::NO_CRASH),
        |r| r.verdicts.within_share = Verdict::Unrun(oracles::UNCHARGED),
        |r| r.verdicts.untouched = Verdict::Unrun(oracles::NO_NEIGHBOUR),
    ];
    for (at, edit) in later_verdicts.into_iter().enumerate() {
        let mut edited = failing.clone();
        edit(&mut edited);
        assert_eq!(edited.credit(), failing.credit(), "the first failure");
        assert_ne!(edited.digest(), failing.digest(), "verdict {}", at + 2);
    }
    let mut renamed = report.clone();
    renamed.shards[5].recoveries[1].tenure = later;
    assert_ne!(renamed.digest(), report.digest(), "a recovery's tenure");
    let mut charged = report.clone();
    charged.shards[5].recoveries[1].peak_bytes += 1;
    assert_ne!(charged.digest(), report.digest(), "a recovery's peak");
    let mut shared = report.clone();
    shared.shards[5].recoveries[1].share.owners += 1;
    assert_ne!(shared.digest(), report.digest(), "a recovery's share");
}

#[test]
fn a_replay_whose_choices_differ_is_refused_before_the_differing_choice_applies() {
    let config = Config::six(7);
    let recording = passing(&config).recording();
    let refused = |config: &Config, tape: Vec<u8>| {
        let identity = config.identity();
        match replay(config, &Recording { identity, tape }) {
            Err(Stopped::Choice(refusal)) => refusal,
            other => panic!("{other:?}"),
        }
    };

    let other = Config::six(8);
    let stopped = replay(&other, &recording).unwrap_err();
    assert!(matches!(stopped, Stopped::Identity { .. }), "{stopped:?}");
    // A recording of the same configuration under another format tag is refused before its tape is read, an
    // unreadable tape included.
    let earlier = Recording {
        identity: config.identity_tagged(b"fleet-v18"),
        tape: vec![0xff; 3],
    };
    assert_ne!(earlier.identity, config.identity());
    let stopped = replay(&config, &earlier).unwrap_err();
    assert!(matches!(stopped, Stopped::Identity { .. }), "{stopped:?}");

    let mut wider = config;
    wider.shape.hosts = 7;
    let refusal = refused(&wider, recording.tape.clone());
    assert_eq!(
        (refusal.applied, refusal.error),
        (0, ChoiceError::Candidates)
    );

    let mut fuller = config;
    fuller.shape.objects = 9;
    let refusal = refused(&fuller, recording.tape.clone());
    assert_eq!(refusal.error, ChoiceError::Candidates);
    assert_eq!(
        refusal.applied,
        12 + 12 + 2,
        "placement, both orders and one request's shard and round"
    );

    let short = recording.tape[..recording.tape.len() - 32].to_vec();
    assert_eq!(refused(&config, short).error, ChoiceError::Short);
    let long = [&recording.tape[..], &recording.tape[..32]].concat();
    let trailing = refused(&config, long);
    assert_eq!(trailing.error, ChoiceError::Trailing { bytes: 32 });
}

#[test]
fn a_recorded_decision_replayed_among_other_candidates_returns_no_value() {
    let mut recorded = Draws::record(5);
    let picked = recorded.value(draws::NEXT, Tag::Shard, &[1, 2, 3]).unwrap();
    let tape = recorded.finish().unwrap();
    let mut same = Draws::replay(tape.clone());
    assert_eq!(same.value(draws::NEXT, Tag::Shard, &[1, 2, 3]), Ok(picked));
    assert!(same.finish().is_ok());
    let mut other = Draws::replay(tape.clone());
    let refusal = other.value(draws::NEXT, Tag::Shard, &[1, 2]).unwrap_err();
    assert_eq!(
        (refusal.applied, refusal.error),
        (0, ChoiceError::Candidates)
    );
    let mut renamed = Draws::replay(tape.clone());
    let refusal = renamed
        .value(draws::NEXT, Tag::Shard, &[1, 2, 4])
        .unwrap_err();
    assert_eq!(
        (refusal.applied, refusal.error),
        (0, ChoiceError::Candidates),
        "as many candidates with one other value"
    );
    let mut moved = Draws::replay(tape);
    let refusal = moved
        .value(draws::NEIGHBOUR, Tag::Shard, &[1, 2, 3])
        .unwrap_err();
    assert_eq!(refusal.error, ChoiceError::Identity);
}

#[test]
fn a_topology_past_a_limit_is_refused_before_any_draw_or_allocation() {
    let limits = Limits {
        zones: 2,
        partitions: 7,
        hosts: 16,
        shards: 32,
        tenures: 128,
        objects: 50,
        reconcilers: 2,
        requests: 2,
        roles: 64,
    };
    assert_eq!(LIMITS, limits);
    let largest = Shape {
        zones: 2,
        partitions: 7,
        hosts: 16,
        shards: 32,
        objects: 50,
        reconcilers: 2,
        placing: Placing::Drawn,
        cap: 32,
        roles_max: LIMITS.roles,
    };
    assert_eq!(largest.check(), Ok(()));
    type Case = (fn(&mut Shape), Refused);
    let cases: [Case; 19] = [
        (|s| s.zones = 3, Refused::Zones(3)),
        (|s| s.zones = 0, Refused::Zones(0)),
        (|s| s.partitions = 8, Refused::Partitions(8)),
        (|s| s.partitions = 0, Refused::Partitions(0)),
        (|s| (s.partitions, s.hosts) = (7, 6), Refused::Partitions(7)),
        (|s| s.hosts = 17, Refused::Hosts(17)),
        (|s| (s.partitions, s.hosts) = (1, 1), Refused::Hosts(1)),
        (|s| s.shards = 33, Refused::Shards(33)),
        (|s| s.shards = 0, Refused::Shards(0)),
        (|s| s.objects = 51, Refused::Objects(51)),
        (|s| s.objects = 0, Refused::Objects(0)),
        (|s| s.reconcilers = 3, Refused::Reconcilers(3)),
        (|s| s.reconcilers = 0, Refused::Reconcilers(0)),
        (
            |s| s.placing = Placing::Small,
            Refused::Placing(Placing::Small),
        ),
        (|s| s.cap = 0, Refused::Cap(0)),
        (|s| s.cap = 33, Refused::Cap(33)),
        (|s| s.roles_max = 0, Refused::RolesMax(0)),
        (|s| s.roles_max = 65, Refused::RolesMax(65)),
        (
            |s| s.placing = Placing::Tiny,
            Refused::Placing(Placing::Tiny),
        ),
    ];
    for (edit, refused) in cases {
        let mut config = Config::six(1);
        config.shape = largest;
        edit(&mut config.shape);
        let stopped = play(&config, || panic!("a draw preceded the shape check"));
        assert_eq!(stopped, Err(Stopped::Shape(refused)));
    }
}

#[test]
fn a_request_count_past_one_peers_allowance_is_refused_before_any_draw() {
    assert_eq!(bounds::requests(0), Ok(()));
    assert_eq!(bounds::requests(2), Ok(()));
    let mut config = Config::six(1);
    config.requests = 3;
    let refused = Err(Stopped::Shape(Refused::Requests(3)));
    let stopped = play(&config, || panic!("a draw preceded the request check"));
    assert_eq!(stopped, refused);
    let identity = config.identity();
    let tape = Vec::new();
    assert_eq!(replay(&config, &Recording { identity, tape }), refused);

    config.requests = 0;
    let none = run(&config).unwrap();
    let unrun = Verdict::Unrun("no request reached an untouched shard during a recovery");
    assert_eq!(none.verdicts.untouched, unrun);
    assert_eq!(none.credit(), unrun);
}

#[test]
fn fleet_plants_share_the_cycle_table_and_take_codes_13_to_26_40_45_and_50_to_53() {
    let codes: Vec<u8> = Plant::ALL.iter().map(|plant| plant.code()).collect();
    assert_eq!(
        codes,
        [
            13, 14, 2, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 40, 45, 50, 51, 52, 53
        ]
    );
    let identities: BTreeSet<String> = (Plant::ALL.iter())
        .map(|plant| Config::six(1).hostile(*plant, 0).identity())
        .chain([Config::six(1).identity()])
        .collect();
    assert_eq!(identities.len(), 22);
}

#[test]
fn the_identity_changes_with_every_field_of_a_configuration() {
    let base = Config::six(1).hostile(Plant::TwinTenure, 0);
    let edits: [fn(&mut Config); 16] = [
        |c| c.root = 2,
        |c| c.shape.zones = 2,
        |c| c.shape.partitions = 2,
        |c| c.shape.hosts = 7,
        |c| c.shape.shards = 5,
        |c| c.shape.objects = 7,
        |c| c.shape.reconcilers = 1,
        |c| c.requests = 3,
        |c| c.profile = Profile::Hostile(Plant::TwinTenure, 1),
        |c| c.shape.placing = Placing::Small,
        |c| c.scenario = hosts::Scenario::HostLoss,
        |c| c.profile = Profile::Arm(faults::Hostile::Clock),
        |c| c.shape.cap = 5,
        |c| c.shape.roles_max = 5,
        |c| c.scenario = hosts::Scenario::Reenroll,
        |c| {
            let cell = super::reconcile::CrashCell::all()[1];
            c.scenario = hosts::Scenario::Crash(cell);
        },
    ];
    let mut identities = BTreeSet::from([base.identity()]);
    for edit in edits {
        let mut config = base;
        edit(&mut config);
        identities.insert(config.identity());
    }
    assert_eq!(identities.len(), 17);
    let cells = super::reconcile::CrashCell::all().into_iter();
    let crashes: BTreeSet<String> = cells
        .map(|cell| Config::crash(1, cell).identity())
        .collect();
    assert_eq!(
        crashes.len(),
        30,
        "each crash-table cell has its own identity"
    );
}

/// On root 1 of `Config::six`, the shard that receives the first GET sent in shard 3's crash episode.
const FIRST_GET_OF_SHARD_3: u32 = 6;

fn verdict<'r>(report: &'r Report, name: &str) -> &'r Verdict {
    let verdicts = report.verdicts.named();
    let found = verdicts.iter().find(|(of, _)| *of == name);
    found.expect("a named verdict").1
}

#[test]
fn every_hostile_profile_fails_or_reads_unrun_through_its_named_check() {
    let legal = passing(&Config::six(1));
    let shared = (legal.shards.iter())
        .position(|shard| shard.recoveries[0].share.owners > 1)
        .expect("a host with two roles");
    let host = legal.shards[shared].owner.get();
    let roles = legal.shards[shared].recoveries[0].share.owners;
    let failing = [
        (
            Plant::TwinTenure,
            2,
            "one owner per tenure",
            "two hosts own one attempt of a shard",
            "shard 3 attempt (3, 6)".to_string(),
        ),
        (
            Plant::LossEvidence,
            2,
            "volume kept",
            "a generation or an active volume changed with no volume lost",
            "shard 3".to_string(),
        ),
        (
            Plant::RestoredEntryMiss,
            2,
            "retained set",
            "a retained entry was not served its exact bytes at the recovered tenure",
            "shard 3 served 7 of 8".to_string(),
        ),
        (
            Plant::SilentBlocker,
            2,
            "settle or blocker",
            "a shard neither serves with a standby nor reports a blocker",
            "shard 3".to_string(),
        ),
        (
            Plant::WholeShare,
            shared as u32,
            "host share",
            "a host's roles exceed the owners its recovery share divides over",
            format!("host {host} roles {roles} owners 1"),
        ),
    ];
    for (plant, at, name, rule, location) in failing {
        let report = run(&Config::six(1).hostile(plant, at)).unwrap();
        assert!(report.planted, "{plant:?} took effect");
        let failed = Verdict::Fail(rule, location);
        assert_eq!(verdict(&report, name), &failed, "{plant:?}");
        assert_eq!(report.credit(), failed, "{plant:?}");
        let named = format!("; plant {plant:?} at {at}");
        assert!(report.summary().ends_with(&named));
        assert_eq!(report.takeovers, u32::from(plant == Plant::TwinTenure));
        if plant == Plant::RestoredEntryMiss {
            for (index, shard) in report.shards.iter().enumerate() {
                let sweeps: Vec<_> = shard.recoveries.iter().map(|r| r.sweep).collect();
                let after_crash = if index == 2 { (8, 7) } else { (8, 8) };
                assert_eq!(sweeps, [Some((8, 8)), Some(after_crash)], "index {index}");
                let dropped = (index == 2).then(|| (shard.recoveries[1].tenure, 1));
                let unserved: Vec<_> = dropped.into_iter().collect();
                assert_eq!(shard.unserved, unserved, "index {index}");
            }
        }
    }

    let report = run(&Config::six(1).hostile(Plant::NeighborRefusal, 2)).unwrap();
    assert!(report.planted);
    let short: Vec<(u32, u32)> = (report.shards.iter())
        .map(|shard| (shard.neighbour.offered, shard.neighbour.served))
        .collect();
    let offered: Vec<u32> = (legal.shards.iter())
        .map(|shard| shard.neighbour.offered)
        .collect();
    let refused = FIRST_GET_OF_SHARD_3 as usize - 1;
    let expected: Vec<(u32, u32)> = (offered.iter().enumerate())
        .map(|(index, &offered)| (offered, offered - u32::from(index == refused)))
        .collect();
    assert_eq!(short, expected, "one GET refused, by the pinned shard");
    let failed = Verdict::Fail(
        "an untouched shard did not serve a request its object's bytes",
        format!("shard {FIRST_GET_OF_SHARD_3}"),
    );
    assert_eq!(verdict(&report, "untouched shards"), &failed);
    assert_eq!(report.credit(), failed);

    let unrun = [
        (Plant::NoCrashEpisode, "volume kept", "no crash episode ran"),
        (
            Plant::NoCrashEpisode,
            "settle or blocker",
            "no crash episode ran",
        ),
        (
            Plant::NoCrashEpisode,
            "untouched shards",
            "no request reached an untouched shard during a recovery",
        ),
        (
            Plant::SkippedSweep,
            "retained set",
            "the retained-set sweep did not run",
        ),
    ];
    for (plant, name, why) in unrun {
        let report = run(&Config::six(1).hostile(plant, 0)).unwrap();
        assert!(report.planted, "{plant:?} took effect");
        assert_eq!(verdict(&report, name), &Verdict::Unrun(why), "{plant:?}");
        assert!(matches!(report.credit(), Verdict::Unrun(_)));
    }
}

#[test]
fn a_skipped_sweep_leaves_one_tenure_unswept_and_every_other_sweep_whole() {
    let report = run(&Config::six(1).hostile(Plant::SkippedSweep, 4)).unwrap();
    assert!(report.planted);
    for (at, shard) in report.shards.iter().enumerate() {
        let sweeps: Vec<_> = shard.recoveries.iter().map(|r| r.sweep).collect();
        let after_crash = if at == 4 { None } else { Some((8, 8)) };
        assert_eq!(sweeps, [Some((8, 8)), after_crash], "shard index {at}");
    }
    let unrun = Verdict::Unrun("the retained-set sweep did not run");
    assert_eq!(report.verdicts.retained, unrun);

    let past = run(&Config::six(1).hostile(Plant::SkippedSweep, 6)).unwrap();
    assert!(!past.planted, "an index past the last cell plants nothing");
    assert_eq!(past.verdicts.retained, Verdict::Pass);
}

#[test]
fn a_hostile_profile_whose_plant_changes_nothing_earns_no_credit() {
    let report = run(&Config::six(1).hostile(Plant::TwinTenure, 99)).unwrap();
    assert!(!report.planted);
    let verdicts = report.verdicts.named();
    assert!(verdicts.iter().all(|(_, verdict)| verdict.passed()));
    assert_eq!(report.credit(), Verdict::Unrun(HOSTILE));

    let legal = passing(&Config::six(1));
    let alone = (legal.shards.iter())
        .position(|shard| shard.recoveries[0].share.owners == 1)
        .expect("a host with one role") as u32;
    let same = run(&Config::six(1).hostile(Plant::WholeShare, alone)).unwrap();
    assert!(!same.planted, "one role's whole share is its legal share");
    assert_eq!(same.credit(), Verdict::Unrun(HOSTILE));
}

fn failed(rule: Option<&'static str>, at: &str) -> Verdict {
    Verdict::Fail(rule.expect("a rule"), at.into())
}

#[test]
fn each_oracle_fails_each_rule_by_name_and_reads_a_missing_event_unrun() {
    let shard = |n| crate::net::ownership::Shard::new(n).unwrap();
    let host = |n| Host::new(n).unwrap();
    let record = ShardRecord {
        shard: shard(1),
        ..restart_tests::shard_record(5)
    };
    let tenure = Tenure { g: 3, a: 10 };
    let history = vec![(shard(1), vec![record])];
    let once = [(shard(1), tenure, record.owner)];
    assert_eq!(oracles::one_owner(&history, &once), Verdict::Pass);
    let stranger = host(record.owner.get() + 1);
    let twin = [once[0], (shard(1), tenure, stranger)];
    let judged = oracles::one_owner(&history, &twin);
    assert_eq!(judged.rule(), Some("two hosts activated one tenure"));
    let judged = oracles::one_owner(&history, &[once[0], once[0]]);
    assert_eq!(judged.rule(), Some("one tenure activated twice"));
    let unnamed = "a tenure activated that no record version names for its host";
    let unknown = [(shard(1), Tenure { g: 3, a: 12 }, record.owner)];
    assert_eq!(oracles::one_owner(&history, &unknown).rule(), Some(unnamed));
    let wrong = [(shard(1), tenure, stranger)];
    assert_eq!(oracles::one_owner(&history, &wrong).rule(), Some(unnamed));
    let regenerated = [(shard(1), Tenure { g: 4, a: 10 }, record.owner)];
    let judged = oracles::one_owner(&history, &regenerated);
    assert_eq!(judged.rule(), Some(unnamed), "another generation");
    let foreign = vec![(shard(1), vec![restart_tests::shard_record(5)])];
    assert_eq!(oracles::one_owner(&foreign, &once).rule(), Some(unnamed));
    let unrun = Verdict::Unrun("no tenure activated");
    assert_eq!(oracles::one_owner(&history, &[]), unrun);

    let quiet = Volumes::default();
    assert_eq!(
        oracles::keeps_volume(&history, quiet, 1, &oracles::Losses::default()),
        Verdict::Pass
    );
    let unrun = Verdict::Unrun("no crash episode ran");
    assert_eq!(
        oracles::keeps_volume(&history, quiet, 0, &oracles::Losses::default()),
        unrun
    );
    let cases = [
        (
            Volumes { flips: 1, ..quiet },
            "a generation or an active volume changed with no volume lost",
        ),
        (
            Volumes {
                volume_writes: 1,
                ..quiet
            },
            "a volume record or a replacement receipt was written with no volume lost",
        ),
        (
            Volumes {
                receipts: 1,
                ..quiet
            },
            "a volume record or a replacement receipt was written with no volume lost",
        ),
        (
            Volumes {
                flip_requests: 1,
                ..quiet
            },
            "a recovery requested a flip with no volume lost",
        ),
    ];
    for (volumes, rule) in cases {
        let judged = oracles::keeps_volume(&history, volumes, 1, &oracles::Losses::default());
        assert_eq!(judged.rule(), Some(rule));
    }
    let elsewhere = ShardRecord {
        active: crate::failover::records::VolumeId::new("vol-0f000000000000aaa").unwrap(),
        ..record
    };
    let moved = vec![(shard(1), vec![record, elsewhere])];
    let judged = oracles::keeps_volume(&moved, quiet, 1, &oracles::Losses::default());
    assert_eq!(
        judged.rule(),
        Some("a generation or an active volume changed with no volume lost")
    );

    let kept = Retention {
        shard: shard(1),
        activations: 1,
        sweeps: vec![Some((8, 8))],
        judged: Judged::Passed,
    };
    assert_eq!(
        oracles::retained(std::slice::from_ref(&kept)),
        Verdict::Pass
    );
    let unswept = Verdict::Unrun("the retained-set sweep did not run");
    assert_eq!(oracles::retained(&[]), unswept);
    let rule = Some("a rule of the history oracle");
    let violated = Retention {
        judged: Judged::Violated("a rule of the history oracle"),
        ..kept.clone()
    };
    let judged = oracles::retained(std::slice::from_ref(&violated));
    assert_eq!(judged.rule(), rule);
    let undecided = Retention {
        judged: Judged::Undecided,
        ..kept.clone()
    };
    let inconclusive = Verdict::Inconclusive("the history oracle decided nothing");
    assert_eq!(
        oracles::retained(std::slice::from_ref(&undecided)),
        inconclusive
    );
    let unserved = Some("a retained entry was not served its exact bytes at the recovered tenure");
    let short = Retention {
        shard: shard(2),
        sweeps: vec![Some((8, 7))],
        ..kept.clone()
    };
    let never = "a retained entry outside every damage set was never served after host loss";
    let skipped = Retention {
        activations: 2,
        sweeps: vec![Some((8, 8)), None],
        judged: Judged::Unserved(never),
        ..kept.clone()
    };
    let lost = Retention {
        judged: Judged::Unserved(never),
        ..kept.clone()
    };
    let judged = oracles::retained(std::slice::from_ref(&lost));
    assert_eq!(judged, failed(Some(never), "shard 1"));
    let skipped_and_violated = Retention {
        judged: Judged::Violated("a rule of the history oracle"),
        ..skipped.clone()
    };
    let judged = oracles::retained(&[skipped_and_violated]);
    assert_eq!(judged, failed(rule, "shard 1"));
    let later = Retention {
        shard: shard(2),
        ..violated
    };
    for first in [&undecided, &skipped] {
        let judged = oracles::retained(&[first.clone(), short.clone()]);
        assert_eq!(judged, failed(unserved, "shard 2 served 7 of 8"));
        let judged = oracles::retained(&[first.clone(), later.clone()]);
        assert_eq!(judged, failed(rule, "shard 2"));
    }
    assert_eq!(oracles::retained(&[kept.clone(), skipped]), unswept);
    let unreached = Retention {
        activations: 2,
        ..kept.clone()
    };
    assert_eq!(oracles::retained(&[unreached, kept]), unswept);

    let settled = Settle {
        shard: shard(1),
        serving: true,
        standby: true,
        blockers: 0,
        withdrawals: 0,
        rounds: vec![19],
    };
    let one = std::slice::from_ref(&settled);
    assert_eq!(oracles::settles(one, 19, 1), Verdict::Pass);
    assert_eq!(
        oracles::settles(one, 18, 1).rule(),
        Some("a recovery passed the settle bound")
    );
    let blocked = Settle {
        serving: false,
        blockers: 1,
        ..settled.clone()
    };
    assert_eq!(oracles::settles(&[blocked], 19, 1), Verdict::Pass);
    let silent = Some("a shard neither serves with a standby nor reports a blocker");
    let unnamed = Settle {
        standby: false,
        ..settled.clone()
    };
    assert_eq!(oracles::settles(&[unnamed], 19, 1).rule(), silent);
    let dark = Settle {
        serving: false,
        ..settled.clone()
    };
    assert_eq!(oracles::settles(&[dark], 19, 1).rule(), silent);
    let withdrawn = Settle {
        withdrawals: 1,
        ..settled
    };
    assert_eq!(
        oracles::settles(&[withdrawn], 19, 1).rule(),
        Some("a tenure that no fault deposed stopped serving")
    );

    let share = HostShare {
        bytes: 100,
        interval: 10,
        owners: 2,
    };
    let used = HostUse {
        host: host(1),
        roles: 2,
        shares: vec![share],
        peak_bytes: 200,
    };
    let one = std::slice::from_ref(&used);
    assert_eq!(oracles::within_share(one), Verdict::Pass);
    let crowded = HostUse {
        roles: 3,
        ..used.clone()
    };
    assert_eq!(
        oracles::within_share(&[crowded]),
        failed(
            Some("a host's roles exceed the owners its recovery share divides over"),
            "host 1 roles 3 owners 2"
        ),
        "one role past the share's owners"
    );
    let over = HostUse {
        peak_bytes: 201,
        ..used.clone()
    };
    assert_eq!(
        oracles::within_share(&[over]).rule(),
        Some("a host's recovery reads passed twice its share")
    );
    let widest = HostUse {
        shares: vec![HostShare {
            bytes: u64::MAX,
            ..share
        }],
        peak_bytes: u64::MAX,
        ..used.clone()
    };
    assert_eq!(oracles::within_share(&[widest]), Verdict::Pass);
    let idle = HostUse {
        peak_bytes: 0,
        ..used
    };
    let unrun = Verdict::Unrun("no recovery charged its share");
    assert_eq!(oracles::within_share(&[idle]), unrun);

    let watch = Watched {
        shard: shard(1),
        requested: false,
        moved: false,
        views: oracles::Views {
            volume: 3,
            shard: 3,
            other: 0,
            writes: 0,
            rounds: 9,
        },
    };
    let served = [(shard(1), true)];
    assert_eq!(oracles::untouched(&[watch], &served, 1), Verdict::Pass);
    let late = Verdict::Unrun(
        "a request to an untouched shard was not served before the recovering session was active",
    );
    assert_eq!(oracles::untouched(&[watch], &served, 0), late);
    let twice = [served[0], served[0]];
    assert_eq!(oracles::untouched(&[watch], &twice, 2), Verdict::Pass);
    assert_eq!(
        oracles::untouched(&[watch], &twice, 1),
        late,
        "one of two requests served once the recovering session was active"
    );
    let unwatched = Verdict::Unrun("a request reached a shard that no watch covers");
    assert_eq!(oracles::untouched(&[], &served, 1), unwatched);
    let elsewhere = Watched {
        shard: shard(2),
        ..watch
    };
    assert_eq!(oracles::untouched(&[elsewhere], &served, 1), unwatched);
    let requested = Watched {
        requested: true,
        ..watch
    };
    let judged = oracles::untouched(&[requested], &served, 1);
    assert_eq!(
        judged.rule(),
        Some("an untouched shard's records took a store request other than its own record views")
    );
    let reads = "an untouched shard's reads were other than one volume-record and one shard-record read a view period";
    let read_with = |views: oracles::Views| {
        let watch = Watched { views, ..watch };
        oracles::untouched(&[watch], &served, 1)
    };
    let once_more = read_with(oracles::Views {
        shard: 4,
        ..watch.views
    });
    let at = "shard 1 reads volume 3 shard 4 other 0 over 9 rounds".to_owned();
    assert_eq!(
        once_more,
        Verdict::Fail(reads, at),
        "one shard-record read past its volume read"
    );
    let another = read_with(oracles::Views {
        other: 1,
        ..watch.views
    });
    assert_eq!(another.rule(), Some(reads), "a coverage-page read");
    let past = read_with(oracles::Views {
        volume: 4,
        shard: 4,
        ..watch.views
    });
    assert_eq!(
        past.rule(),
        Some(reads),
        "four views over nine rounds of three-round periods"
    );
    let still = read_with(oracles::Views {
        volume: 0,
        shard: 0,
        rounds: 0,
        ..watch.views
    });
    assert_eq!(still, Verdict::Pass, "no view over no round");
    let early = read_with(oracles::Views {
        volume: 1,
        shard: 1,
        rounds: 0,
        ..watch.views
    });
    assert_eq!(early.rule(), Some(reads), "a view over no round");
    let short = read_with(oracles::Views {
        volume: 2,
        shard: 2,
        ..watch.views
    });
    assert_eq!(
        short.rule(),
        Some(reads),
        "two views over nine rounds of three-round periods"
    );
    let none = read_with(oracles::Views {
        volume: 0,
        shard: 0,
        ..watch.views
    });
    let at = "shard 1 reads volume 0 shard 0 other 0 over 9 rounds".to_owned();
    assert_eq!(none, Verdict::Fail(reads, at), "no view over nine rounds");
    let part = read_with(oracles::Views {
        rounds: 11,
        ..watch.views
    });
    assert_eq!(
        part,
        Verdict::Pass,
        "three views over eleven rounds, whose fourth period is not whole"
    );
    let wrote = Watched {
        views: oracles::Views {
            writes: 1,
            ..watch.views
        },
        ..watch
    };
    let judged = oracles::untouched(&[wrote], &served, 1);
    let write = "an untouched shard's serving duties wrote its records";
    assert_eq!(judged, Verdict::Fail(write, "shard 1 1 writes".into()));
    let moved = Watched {
        moved: true,
        ..watch
    };
    let judged = oracles::untouched(&[moved], &served, 1);
    assert_eq!(judged.rule(), Some("an untouched shard changed its tenure"));
}

#[test]
fn an_owner_change_that_returns_counts_twice() {
    let record = restart_tests::shard_record(5);
    let taken = ShardRecord {
        owner: Host::new(record.owner.get() + 1).unwrap(),
        ..record
    };
    assert_eq!(owner_changes(&[record]), 0);
    assert_eq!(owner_changes(&[record, record]), 0);
    assert_eq!(owner_changes(&[record, taken]), 1);
    assert_eq!(owner_changes(&[record, taken, record]), 2);
}

#[test]
fn a_swept_tenure_is_accounted_only_with_every_object_served_and_none_excused() {
    let tenure = Tenure { g: 3, a: 10 };
    let swept = Recovered {
        tenure,
        host: Host::new(1).unwrap(),
        after_crash: false,
        rounds: 19,
        sweep: Some((8, 8)),
        share: HostShare {
            bytes: 100,
            interval: 10,
            owners: 1,
        },
        peak_bytes: 1,
        read_bytes: 0,
    };
    let whole = Preserved {
        tenure,
        members: 8,
        served: 8,
        served_bytes: 8 * 44,
        excused: Vec::new(),
    };
    assert!(accounted(std::slice::from_ref(&whole), &[swept]));
    let unswept = Recovered {
        sweep: None,
        ..swept
    };
    assert!(
        accounted(&[], &[unswept]),
        "a skipped sweep owes no account"
    );
    let excused = (crate::oracle::KeyId(1), crate::oracle::Label(1));
    let short: [(&str, Preserved); 4] = [
        (
            "one member unserved",
            Preserved {
                served: 7,
                ..whole.clone()
            },
        ),
        (
            "one member excused",
            Preserved {
                served: 7,
                excused: vec![excused],
                ..whole.clone()
            },
        ),
        (
            "fewer members than the sweep counted eligible",
            Preserved {
                members: 7,
                served: 7,
                ..whole.clone()
            },
        ),
        (
            "another tenure's account",
            Preserved {
                tenure: Tenure { g: 3, a: 12 },
                ..whole
            },
        ),
    ];
    for (name, account) in short {
        assert!(!accounted(&[account], &[swept]), "{name}");
    }
    assert!(!accounted(&[], &[swept]), "no account");
}

fn seeded(config: &Config) -> Fleet<'_> {
    let mut draws = Draws::record(config.root);
    Fleet::seeded(config, &mut draws, WAIT_ROUNDS).expect("a recorded topology")
}

/// A store class whose every write unwinds.
pub(super) struct Unwinding(pub(super) Shared);

impl Store for Unwinding {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, crate::storage::store::Unavailable> {
        self.0.read(key)
    }

    fn write(&mut self, _: &Key, _: &Write) -> Outcome {
        panic!("a store write that unwinds")
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.0.namespace()
    }
}

/// A restart that unwinds fails the run. `host::recover` contains the unwind of the first cell's owner, whose store
/// unwinds at the restart's first write, and ends `Rerun(Unwound)`; `owners::incarnate` fails the incarnation on
/// that exit, outside that boundary, for each of the fleet's restarts and fresh activations.
#[test]
#[should_panic(expected = "the restart unwound")]
fn a_restart_that_unwinds_inside_recover_fails_the_incarnation() {
    let config = Config::six(1);
    let fleet = seeded(&config);
    let cell = &fleet.cells[0];
    let member = cell.placement.owner;
    let grounds = Grounds::over(storage_shared(1, fleet.share_on(member)));
    let store = Unwinding(fleet.store.clone());
    let log = crate::storage::store::sim::MemLog::default();
    let mut client =
        crate::storage::store::Client::open(store, log).expect("a host's store client");
    let mut local = owners::OwnerLocal(Stored(cell.local.0.clone()));
    let mut plane = crate::failover::fresh::tests::plane();
    let mut refusals = crate::failover::fresh::Refusals::default();
    let _ = owners::incarnate(
        (cell, fleet.topology.members[member], cell.pair),
        fleet.round,
        &grounds,
        &mut client,
        (&mut local, &mut plane, &mut refusals),
    );
}

#[test]
fn a_shards_request_count_covers_its_receipt_and_every_page_and_no_other_shard() {
    let config = Config::dense(1);
    let fleet = seeded(&config);
    let (watched, other) = (&fleet.cells[0], &fleet.cells[1]);
    let shard = watched.placement.shard;
    let mut store = fleet.store.clone();
    let keys = [
        Key::Shard(shard),
        Key::Volume(watched.placement.volume),
        Key::Replacement(shard),
        Key::Page(shard, 0),
        Key::Page(shard, watched.pages - 1),
    ];
    for key in keys {
        let before = (watched.requests(&fleet.store), other.requests(&fleet.store));
        let _ = Store::read(&mut store, &key);
        let after = (watched.requests(&fleet.store), other.requests(&fleet.store));
        assert_eq!(after, (before.0 + 1, before.1), "{key:?}");
    }
    let before = watched.requests(&fleet.store);
    let (history, seen) = (watched.history(&fleet.store), watched.seen(&fleet.store));
    let after = watched.requests(&fleet.store);
    assert_eq!(after, before, "sampling a tenure sends no request");

    let record = history[0];
    assert_eq!(seen.named, (3, 4, record.owner.get()));
    let bumped = ShardRecord {
        attempts: record.attempts + 1,
        ..record
    };
    let item = (fleet.store.0.borrow().current(&Key::Shard(shard))).cloned();
    let write = Write::Exact {
        expect: item.unwrap().version,
        value: bumped.encode(),
    };
    let committed = Store::write(&mut store, &Key::Shard(shard), &write);
    assert!(matches!(committed, Outcome::Committed(_)));
    assert_eq!(watched.seen(&fleet.store).named, (3, 5, record.owner.get()));
    assert_ne!(watched.seen(&fleet.store), seen);
}

#[test]
fn a_hosts_use_takes_each_shards_largest_attach_peak_and_every_share() {
    let config = Config::dense(1);
    let mut fleet = seeded(&config);
    let member = fleet.cells[0].placement.owner;
    let owned: Vec<usize> = (0..fleet.cells.len())
        .filter(|&at| fleet.cells[at].placement.owner == member)
        .collect();
    assert!(owned.len() > 1, "the host owns {} shards", owned.len());
    let share = fleet.share(owned[0]);
    let host = fleet.topology.members[member].host;
    let charge = |load| Charge { host, share, load };
    fleet.cells[owned[0]].charges = vec![charge(900), charge(100)];
    fleet.cells[owned[1]].charges = vec![charge(30)];
    let used = &fleet.host_use()[member];
    assert_eq!((used.peak_bytes, used.shares.len()), (930, 3));
    assert_eq!(used.roles, share.owners);
    let idle = fleet.host_use();
    let others = idle.iter().enumerate().filter(|(at, _)| *at != member);
    assert!(others.into_iter().all(|(_, used)| used.peak_bytes == 0));
}

#[test]
fn a_neighbour_get_counts_inside_the_window_only_while_it_is_open() {
    let config = Config::six(1);
    let mut fleet = seeded(&config);
    fleet.window = true;
    fleet.settle(0, Purpose::Neighbour, true);
    fleet.window = false;
    fleet.settle(1, Purpose::Neighbour, true);
    let inside: Vec<bool> = fleet.neighbours.iter().map(|s| s.inside).collect();
    assert_eq!(inside, [true, false]);
}

#[test]
fn the_survey_counts_an_unnamed_standby_and_panics_on_an_unreadable_record() {
    use crate::storage::store::sim::Arm;
    let config = Config::six(1);
    let fleet = seeded(&config);
    let shards: Vec<_> = fleet
        .cells
        .iter()
        .map(|cell| cell.placement.shard)
        .collect();
    let commits = |fleet: &Fleet<'_>| fleet.commits(|_| true);
    let before = commits(&fleet);
    assert_eq!(actors::reconcile(&fleet.store, &shards), 0);

    let key = Key::Shard(shards[0]);
    let item = (fleet.store.0.borrow().current(&key)).cloned().unwrap();
    let unnamed = ShardRecord {
        standby: None,
        ..ShardRecord::decode(&item.value).unwrap()
    };
    let write = Write::Exact {
        expect: item.version,
        value: unnamed.encode(),
    };
    let committed = Store::write(&mut fleet.store.clone(), &key, &write);
    assert!(matches!(committed, Outcome::Committed(_)));
    assert_eq!(actors::reconcile(&fleet.store, &shards), 1);
    assert_eq!(commits(&fleet), before + 1, "a survey commits nothing");

    fleet.store.0.borrow_mut().schedule(Arm::Unavailable);
    let survey = || actors::reconcile(&fleet.store, &shards);
    let refused = catch_unwind(AssertUnwindSafe(survey)).unwrap_err();
    let message = *refused.downcast::<String>().expect("a formatted panic");
    let named = format!("shard {}:", shards[0].get());
    assert!(message.starts_with(&named), "{message}");
    assert_eq!(commits(&fleet), before + 1);
}

#[test]
fn a_volume_record_or_a_receipt_committed_after_seeding_reads_provisioned() {
    let config = Config::six(1);
    let fleet = seeded(&config);
    assert_eq!(fleet.volumes(), Volumes::default());
    let histories: Vec<_> = (fleet.cells.iter())
        .map(|cell| (cell.placement.shard, cell.history(&fleet.store)))
        .collect();
    let judged = oracles::keeps_volume(&histories, fleet.volumes(), 1, &oracles::Losses::default());
    assert_eq!(judged, Verdict::Pass);
    let provisioned =
        Some("a volume record or a replacement receipt was written with no volume lost");
    let mut store = fleet.store.clone();
    let seeded = Key::Volume(fleet.cells[0].placement.volume);
    let value = (fleet.store.0.borrow().current(&seeded).unwrap())
        .value
        .clone();
    let unseen = crate::failover::records::VolumeId::new("vol-0f000000000000bbb").unwrap();
    let created = Store::write(
        &mut store,
        &Key::Volume(unseen),
        &Write::Create(value.clone()),
    );
    assert!(matches!(created, Outcome::Committed(_)));
    let volumes = fleet.volumes();
    assert_eq!((volumes.volume_writes, volumes.receipts), (1, 0));
    let judged = oracles::keeps_volume(&histories, volumes, 1, &oracles::Losses::default());
    assert_eq!(judged.rule(), provisioned);

    let receipt = Key::Replacement(fleet.cells[1].placement.shard);
    let created = Store::write(&mut store, &receipt, &Write::Create(value));
    assert!(matches!(created, Outcome::Committed(_)));
    let receipts = Volumes {
        volume_writes: 0,
        ..fleet.volumes()
    };
    assert_eq!(receipts.receipts, 1);
    let judged = oracles::keeps_volume(&histories, receipts, 1, &oracles::Losses::default());
    assert_eq!(judged.rule(), provisioned);
}

/// With a reconciler running, a rewrite of a seeded volume record, as an attach record or an enrollment makes,
/// counts no volume write, and a volume record created after seeding counts one and fails the volume check.
#[test]
fn a_volume_record_created_in_a_reconciler_run_reads_provisioned_and_a_rewrite_does_not() {
    let config = Config::settle(1);
    let mut fleet = seeded(&config);
    fleet.reconcilers.push(reconcile::ReconcilerActor::new(
        0,
        crate::failover::standbys::Zone(1),
        6,
    ));
    assert!(fleet.repairs());
    assert_eq!(fleet.volumes(), Volumes::default());
    let histories: Vec<_> = (fleet.cells.iter())
        .map(|cell| (cell.placement.shard, cell.history(&fleet.store)))
        .collect();
    let mut store = fleet.store.clone();
    let seeded = Key::Volume(fleet.cells[0].placement.volume);
    let item = (fleet.store.0.borrow().current(&seeded).cloned()).expect("a seeded volume record");
    let rewrite = Write::Exact {
        expect: item.version,
        value: item.value.clone(),
    };
    let rewritten = Store::write(&mut store, &seeded, &rewrite);
    assert!(matches!(rewritten, Outcome::Committed(_)));
    assert_eq!(fleet.volumes(), Volumes::default());
    assert_eq!(
        oracles::keeps_volume(&histories, fleet.volumes(), 1, &oracles::Losses::default()),
        Verdict::Pass
    );

    let unseen = crate::failover::records::VolumeId::new("vol-0f000000000000bbb").unwrap();
    let created = Store::write(&mut store, &Key::Volume(unseen), &Write::Create(item.value));
    assert!(matches!(created, Outcome::Committed(_)));
    assert_eq!(fleet.volumes().volume_writes, 1);
    let judged = oracles::keeps_volume(&histories, fleet.volumes(), 1, &oracles::Losses::default());
    let provisioned = "a volume record or a replacement receipt was written with no volume lost";
    assert_eq!(judged.rule(), Some(provisioned));
}

#[test]
fn a_shard_record_committed_at_the_next_generation_counts_one_flip() {
    let config = Config::six(1);
    let fleet = seeded(&config);
    let before: Vec<_> = (fleet.cells.iter())
        .map(|cell| (cell.placement.shard, cell.history(&fleet.store)))
        .collect();
    let cell = &fleet.cells[2];
    let key = Key::Shard(cell.placement.shard);
    let item = (fleet.store.0.borrow().current(&key).cloned()).unwrap();
    let record = cell.decoded(&item);
    let next = crate::net::ownership::ShardGeneration::new(record.generation.get() + 1);
    let flipped = ShardRecord {
        generation: next.unwrap(),
        attempts: 0,
        ..record
    };
    let write = Write::Exact {
        expect: item.version,
        value: flipped.encode(),
    };
    let committed = Store::write(&mut fleet.store.clone(), &key, &write);
    assert!(matches!(committed, Outcome::Committed(_)));
    let flips = Volumes {
        flips: 1,
        ..Volumes::default()
    };
    assert_eq!(fleet.volumes(), flips);
    let rule = Some("a generation or an active volume changed with no volume lost");
    let judged = oracles::keeps_volume(&before, fleet.volumes(), 1, &oracles::Losses::default());
    assert_eq!(judged, failed(rule, "1 flips"));
}

#[test]
fn a_fixture_bound_method_refuses_a_fleet_world_before_any_store_request() {
    let config = Config::dense(1);
    let mut fleet = seeded(&config);
    let fixture = crate::storage::store_tests::shard();
    let at = (fleet.cells.iter())
        .position(|cell| cell.placement.shard == fixture)
        .expect("a cell with the fixture's shard number");
    let requests = |fleet: &Fleet<'_>| -> Vec<u64> {
        let cells = fleet.cells.iter();
        cells.map(|cell| cell.requests(&fleet.store)).collect()
    };
    let before = requests(&fleet);
    let world = &mut fleet.cells[at].world;
    let refused = catch_unwind(AssertUnwindSafe(|| world.invalidate(1)));
    let message = *refused.unwrap_err().downcast::<String>().unwrap();
    assert!(
        message.contains("invalidate acts on the single-shard fixture"),
        "{message}"
    );
    let world = &fleet.cells[at].world;
    let calls: [fn(&World); 3] = [
        |world| drop(world.evidence()),
        |world| drop(world.restart_of_a()),
        |world| drop(world.takeover(restart_tests::host())),
    ];
    for call in calls {
        assert!(catch_unwind(AssertUnwindSafe(|| call(world))).is_err());
    }
    assert_eq!(requests(&fleet), before);
}

#[test]
fn a_wait_accepts_its_last_turn_and_a_stall_stops_the_run_with_its_identity() {
    let config = Config::six(1);
    let inline = || crate::storage::INLINE_RECOVERY.with(std::cell::Cell::get);
    let before = inline();
    let within = |wait: u32| play_within(&config, || Draws::record(config.root), wait);
    let stalled = within(1).unwrap_err();
    let Stopped::Stalled(stall) = &stalled else {
        panic!("{stalled:?}");
    };
    assert_eq!(stall.identity, config.identity());
    assert_eq!(stall.waited, "the bootstrap");
    assert!(stall.shard.is_some() && stall.round > DOWN_ROUNDS);
    assert_eq!(inline(), before, "a stalled run restores inline recovery");

    let mut previous = stalled;
    let fitted = (2..200).find_map(|wait| match within(wait) {
        Ok(report) => Some(report),
        Err(stopped) => {
            previous = stopped;
            None
        }
    });
    assert!(matches!(previous, Stopped::Stalled(_)), "{previous:?}");
    assert_eq!(
        fitted,
        run(&config).ok(),
        "the least budget fits its last turn"
    );
    assert_eq!(inline(), before);
}

#[test]
fn a_run_refuses_an_armed_fault_control_by_name_and_restores_inline_recovery() {
    use crate::storage::checkpoint::{PLANT, Plant as Armed};
    let config = Config::six(1);
    let inline = || crate::storage::INLINE_RECOVERY.with(std::cell::Cell::get);
    let before = inline();
    let message = |run: &dyn Fn() -> Result<Report, Stopped>| {
        let refused = catch_unwind(AssertUnwindSafe(run)).unwrap_err();
        *refused.downcast::<String>().expect("a formatted panic")
    };

    PLANT.with(|plant| plant.set(Some(Armed::AllOrNothing)));
    let refused = message(&|| run(&config));
    PLANT.with(|plant| plant.set(None));
    assert!(refused.contains("checkpoint::PLANT is armed"), "{refused}");

    crate::storage::PARK_RECOVERY.with(|park| park.set(true));
    let refused = message(&|| run(&config));
    crate::storage::PARK_RECOVERY.with(|park| park.set(false));
    assert!(refused.contains("PARK is armed"), "{refused}");

    let outer = crate::storage::write_guard::arm(true);
    let refused = message(&|| play(&config, || panic!("a draw preceded the guard check")));
    crate::storage::write_guard::arm(outer);
    assert!(refused.contains("the write guard is armed"), "{refused}");

    for plant in ["unbound", "unrevalidated", "published-only"] {
        let refused = crate::host::agent::tests::planted(plant, || {
            message(&|| play(&config, || panic!("a draw preceded the agent plant check")))
        });
        assert!(
            refused.contains("a host agent plant is armed"),
            "{plant}: {refused}"
        );
        assert!(!crate::host::agent::tests::armed(), "{plant} cleared");
    }
    assert!(run(&config).is_ok(), "an unarmed run is admitted");

    // A shared run refuses the caller's armed control on a warm cache as a cold run does.
    assert!(
        run_shared(&config).is_ok(),
        "an unarmed shared run is admitted"
    );
    PLANT.with(|plant| plant.set(Some(Armed::AllOrNothing)));
    let refused = message(&|| run_shared(&config));
    PLANT.with(|plant| plant.set(None));
    assert!(refused.contains("checkpoint::PLANT is armed"), "{refused}");
    for plant in ["unbound", "unrevalidated", "published-only"] {
        let refused =
            crate::host::agent::tests::planted(plant, || message(&|| run_shared(&config)));
        assert!(
            refused.contains("a host agent plant is armed"),
            "{plant}: {refused}"
        );
    }

    let unwound = catch_unwind(|| play(&config, || panic!("a draw that unwinds")));
    assert!(unwound.is_err());
    assert_eq!(inline(), before, "an unwound run restores inline recovery");
}

#[test]
fn each_placement_takes_a_least_loaded_owner_and_a_standby_outside_its_partition() {
    let shape = Shape {
        zones: 2,
        partitions: 2,
        hosts: 5,
        shards: 14,
        objects: 1,
        reconcilers: 1,
        placing: Placing::Drawn,
        cap: 4,
        roles_max: super::ROLES_MAX,
    };
    for root in [1, 2, 3] {
        let topology = Topology::draw(&shape, &mut Draws::record(root)).unwrap();
        let members = &topology.members;
        let (mut owned, mut stood) = (vec![0; members.len()], vec![0; members.len()]);
        for placement in &topology.placements {
            let (owner, standby) = (&members[placement.owner], &members[placement.standby]);
            assert_eq!((owner.zone, standby.zone), (placement.zone, placement.zone));
            assert_ne!(owner.partition, standby.partition);
            let zone = |at: &usize| members[*at].zone == placement.zone;
            let fewest = (0..members.len()).filter(zone).map(|at| owned[at]).min();
            assert_eq!(Some(owned[placement.owner]), fewest);
            let apart = |at: &usize| zone(at) && members[*at].partition != owner.partition;
            let fewest = (0..members.len()).filter(apart).map(|at| stood[at]).min();
            assert_eq!(Some(stood[placement.standby]), fewest);
            owned[placement.owner] += 1;
            stood[placement.standby] += 1;
        }
        for at in 0..members.len() {
            assert_eq!(topology.roles(at), owned[at] + stood[at]);
        }
    }
    let one = Shape {
        partitions: 1,
        ..shape
    };
    let topology = Topology::draw(&one, &mut Draws::record(1)).unwrap();
    for placement in &topology.placements {
        assert_ne!(placement.owner, placement.standby);
        let standby = &topology.members[placement.standby];
        assert_eq!(
            standby.zone, placement.zone,
            "one partition holds the standby"
        );
    }
}

#[test]
fn the_pinned_runs_pass_and_the_root_sweep_prints_one_line_a_run() {
    let cells = super::reconcile::CrashCell::all();
    pinned_runs_repeat_their_digests(1);
    let table = crash_table(CRASH_TABLE_ROOT, &cells[..1]).expect("a credited crash cell");
    let digest = Sha256::digest(run(&Config::crash(1, cells[0])).unwrap().digest());
    let line = format!(
        "fleet: pinned crash-table root 1: credit pass; digest {}",
        hex(&digest)
    );
    assert_eq!(
        table, line,
        "the crash table's digest hashes its cells' digests in order"
    );
    let lines = roots(1..=2).expect("roots 1 and 2 pass");
    assert_eq!(lines.len(), 5);
    let settle = lines[4]
        .strip_prefix("fleet: roots: 4 runs passed, 0 takeovers, settle at most ")
        .and_then(|rest| rest.strip_suffix(" of 64 rounds"))
        .expect("the closing line");
    let slowest: u64 = settle.parse().expect("a round count");
    assert!(
        (DOWN_ROUNDS..=SETTLE_ROUNDS).contains(&slowest),
        "{slowest}"
    );
}

/// Runs and replays the pinned runs on `root`, then runs each again and asserts the same digest line. The fast tier
/// checks root 1 and the scheduled tier root 2.
pub(super) fn pinned_runs_repeat_their_digests(root: u64) {
    let pinned = pinned_runs(Some(root)).expect("the pinned runs pass and replay");
    let on_root: Vec<_> = PINNED.into_iter().filter(|(.., at)| *at == root).collect();
    assert_eq!(pinned.len(), on_root.len());
    assert!(!pinned.is_empty(), "root {root} holds pinned runs");
    for (line, (name, config, root)) in pinned.iter().zip(on_root) {
        let digest = run(&config(root)).unwrap().digest();
        let again = format!("fleet: pinned {name} root {root}: credit pass; digest {digest}");
        assert_eq!(line, &again, "a second run reports the same digest");
    }
}

#[test]
fn a_run_with_no_credit_or_no_report_stops_the_pinned_case_and_the_root_sweep() {
    let hostile = Config::six(1).hostile(Plant::TwinTenure, 2);
    let lines = run(&hostile).unwrap().lines().join("\n");
    assert!(
        lines.contains("credit FAIL [two hosts own one attempt of a shard]"),
        "{lines}"
    );
    assert_eq!(
        credited_replay("six", &hostile).map(|report| report.digest()),
        Err(lines.clone())
    );
    assert_eq!(sweep([Config::six(1), hostile].into_iter()), Err(lines));

    let mut wide = Config::six(1);
    wide.shape.shards = 33;
    let refused = "root 1: Shape(Shards(33))";
    assert_eq!(
        credited_replay("six", &wide).map(|report| report.digest()),
        Err(format!("six {refused}"))
    );
    assert_eq!(sweep([wide].into_iter()), Err(refused.into()));

    let report = passing(&Config::six(1));
    assert_eq!(alike("six", &report, &Ok(report.clone())), Ok(()));
    let other = Ok(passing(&Config::six(2)));
    let differs = alike("six", &report, &other).unwrap_err();
    assert!(
        differs.starts_with("six root 1 replayed to Ok("),
        "{differs}"
    );
    let stopped = Err(Stopped::Shape(Refused::Shards(33)));
    let refused = "six root 1 replayed to Err(Shape(Shards(33)))";
    assert_eq!(alike("six", &report, &stopped), Err(refused.into()));
}

const INVENTORY: &str = include_str!("../../../../../../scripts/test-inventory.json");

/// The members of row `id` of qualified lane `lane` in the test inventory, in their order; a missing row, a missing
/// member list or a member that is not a string panics.
pub(super) fn inventory_members(lane: &str, id: &str) -> Vec<String> {
    let inventory: serde_json::Value = serde_json::from_str(INVENTORY).expect("the inventory");
    let rows = inventory["qualified"][lane]["rows"].as_array();
    let row = (rows.expect("the lane's rows").iter()).find(|row| row["id"] == id);
    let members = row.expect("the row")["members"].as_array();
    (members.expect("the row's members").iter())
        .map(|member| member.as_str().expect("a member").to_owned())
        .collect()
}

#[test]
fn the_inventory_rows_list_the_pinned_runs_and_the_swept_roots() {
    let members = inventory_members;
    let mut pinned: Vec<String> = (PINNED.iter())
        .map(|(name, _, root)| format!("{name} root {root}"))
        .collect();
    pinned.push(format!("crash-table root {CRASH_TABLE_ROOT}"));
    assert_eq!(members("campaigns", "fleet-replay"), pinned);
    let swept: Vec<String> = [Config::six, Config::dense]
        .into_iter()
        .flat_map(|config| ROOTS.map(config))
        .map(|config| {
            let shape = config.shape;
            let hosts = shape.hosts * u32::from(shape.zones);
            format!("root {} hosts {hosts} shards {}", config.root, shape.shards)
        })
        .collect();
    assert_eq!(members("long-run", "fleet-roots"), swept);
}
