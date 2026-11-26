//! Emitter tests: for each row whose deciding code this tree holds, one injected history through that code produces
//! the row's shared control value and its matched clean history the clean value. The rows read through the owner's
//! entry assert their values in `net::owner_entry_tests`.
//! `handoff-due` and `publication-stuck` read flags that `Owner::report_entry` copies from the driver's `Observed`;
//! `SuffixLog::publication_due` decides the publication flag, and the driver that fills `Observed` lies outside
//! this tree. The `unlisted` enumeration and the failed-attach count come from producers outside this tree, and
//! `status-absent` reads the absence of a record. Those five rows rest on control values and evaluator histories.

use super::controls::{self, Twin};
use crate::failover::attachments::{InstanceId, check};
use crate::failover::evidence::NotSole;
use crate::failover::records::{Ancestry, MAX_CHAIN, ShardRecord, Suffix};
use crate::failover::report::status::{Builder, Memory, ZonePart};
use crate::failover::report::tests::authority;
use crate::failover::report::{
    Backlog, Detector, Enumeration, ExitOperation, ExitStatus, ExitTracker, Pressure, Recovery,
    RecoveryKind, RecoveryRefusal, RecoveryStatus, RecoveryTimes, Registrants, Retention,
    StoreOutcomes, Watermark, Withdrawal, producer_missing,
};
use crate::failover::restart::tests::{self as restart_tests, Card, sample, shard_record};
use crate::failover::restart::{Check, Refused};
use crate::failover::serving;
use crate::storage::store::sim::Arm;
use crate::storage::store::{Alarm, Key, Refusal, StoreError, Tally};
use crate::storage::store_tests::{client, other_namespace, seeded, shard};
use crate::storage::{RecoveryPhase, RecoveryReport, RegistrantJudgment, SuffixBacklog};

/// The recovery part a refused attempt of `kind` reads 50 µs after its start, or the completed attempt's.
fn reported(kind: RecoveryKind, refused: Option<&Refused>) -> Recovery {
    let mut status = RecoveryStatus::NO_ATTEMPT;
    status.start(kind, 100);
    match refused {
        Some(refused) => status.refuse(RecoveryRefusal::from(refused)),
        None => status.complete(),
    }
    status.recovery(150)
}

fn twin<T>(fault: T, clean: T) -> Twin<T> {
    Twin { fault, clean }
}

/// The alarm of a client whose read the store double answers below the client's mark after a bump.
fn regressed() -> Alarm {
    let key = Key::Shard(shard());
    let store = seeded();
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(key).unwrap();
    owner.bump(&read).unwrap();
    owner.read::<ShardRecord>(key).unwrap();
    store.schedule(Arm::StaleCurrentRead);
    assert!(owner.read::<ShardRecord>(key).is_err());
    owner.alarm()
}

/// The alarm of a client whose store instance changes between two reads.
fn moved() -> Alarm {
    let key = Key::Shard(shard());
    let store = seeded();
    let mut reader = client(&store);
    reader.read::<ShardRecord>(key).unwrap();
    store.0.borrow_mut().namespace = other_namespace();
    assert!(reader.read::<ShardRecord>(key).is_err());
    reader.alarm()
}

/// The alarm and the outcomes tally of a client whose `writes` bumps each lose their reply.
fn lost_replies(writes: u64) -> (Alarm, Tally) {
    let store = seeded();
    let mut writer = client(&store);
    let key = Key::Shard(shard());
    for _ in 0..writes {
        let read = writer.read::<ShardRecord>(key).unwrap();
        store.schedule(Arm::Timeout { commit: false });
        assert!(writer.bump(&read).is_err());
    }
    (writer.alarm(), writer.outcomes())
}

/// `store-regression` and `store-instance-change`: a record the store double returns below the client's mark, and
/// a record of another store instance, raise the client alarms the entry's watermark reads; a clean read of the
/// same record reads `clear`.
#[test]
fn the_store_client_alarm_gives_the_watermark_rows() {
    let key = Key::Shard(shard());
    let clean = |store: &crate::storage::store::sim::Shared| {
        let mut reader = client(store);
        reader.read::<ShardRecord>(key).unwrap();
        Watermark::from(reader.alarm())
    };
    assert_eq!(
        twin(Watermark::from(regressed()), clean(&seeded())),
        controls::store_regression()
    );
    assert_eq!(
        twin(Watermark::from(moved()), clean(&seeded())),
        controls::store_instance_change()
    );
}

/// `retirement-requested`: a recorded force detach withdraws the serving owner with a flip request, which the
/// owner's entry reads; the serving entry before it reads no flip and no withdrawal.
#[test]
fn a_force_detach_gives_the_retirement_request() {
    use crate::failover::report::Observed;
    use crate::net::owner_tenure_tests::{observe, serve_at, shard_at, token, volume_record};
    crate::net::put_tests::scene(&[], |mut scene| {
        serve_at(&mut scene, 3, 1);
        let token = token(&scene);
        let record = shard_at(token, 3, token.epoch.get() / 2);
        let active = volume_record("vol-0a", crate::failover::records::VolumeState::Active);
        observe(&mut scene, Some(record), Some(active), token.exhid);
        let now = scene.turn * 100;
        let serving = scene
            .owner
            .report_entry(now, &Observed::UNAVAILABLE)
            .unwrap();
        let detach = serving::Event::Withdraw(serving::Cause::ForceDetach);
        scene.owner.authority_event(detach, now);
        let withdrawn = scene
            .owner
            .report_entry(now, &Observed::UNAVAILABLE)
            .unwrap();
        assert_eq!(
            twin(
                (withdrawn.flip, withdrawn.withdrawal),
                (serving.flip, serving.withdrawal)
            ),
            controls::retirement_requested()
        );
    });
}

/// The hold rows and `unknown-recovery-write`: the restart's refusals, run through the recovery status the entry
/// reads, give each row's recovery part, and a restart that reaches its capability gives the completed part. A
/// restart that stops at each of its six device commands holds the volume with that command's check, and each such
/// recovery part, sealed in an owner entry, fires `hold-device` once; those checks are the row's labels.
/// Truncating Report #1 or #2 or exceeding the registrant bound produces `Hold`; each resulting owner entry fires
/// `hold-device` once. A foreign registrant's refusal requests the flip and leaves `hold-device` silent. The restart
/// holds `recorded-holder` through a failed step of its lineage arm: the enrolled standby holds at Report #1, the arm
/// preempts it after the own bump, and the standby takes the reservation back before Report #2, which refuses the
/// arm inside its hold. It refuses `Unheld` when its preempt leaves nobody
/// registered, the bump with the store's condition refusal when another client bumps the record during Report #1,
/// and `SuffixOnly` over a record that names a certified suffix and no checkpoint.
#[test]
fn the_restart_refusals_give_the_hold_rows() {
    let completed = {
        let store = restart_tests::store(shard_record(4), restart_tests::volume_record());
        restart_tests::restart()
            .run(&mut client(&store), &sample(), &mut Card::new())
            .unwrap();
        reported(RecoveryKind::Restart, None)
    };
    type Setup<'a> = &'a dyn Fn(&crate::storage::store::sim::Shared, &mut Card);
    let refusal = |shard: ShardRecord, volume, setup: Setup| {
        let store = restart_tests::store(shard, volume);
        let mut card = Card::new();
        setup(&store, &mut card);
        restart_tests::restart()
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err()
    };
    let part = |refused: &Refused| reported(RecoveryKind::Restart, Some(refused));
    let run = |setup: Setup| {
        part(&refusal(
            shard_record(4),
            restart_tests::volume_record(),
            setup,
        ))
    };
    let ready = run(&|_, card| card.stop_at = Some(1));
    assert_eq!(twin(ready, completed), controls::hold_device());
    let device = super::row(&super::catalog(), "hold-device");
    let narrow = crate::failover::restart::Restart {
        bounds: crate::failover::bounds::Bounds::new(1, 1, u64::MAX, 100, 100, 0).unwrap(),
        ..restart_tests::restart()
    };
    let unobserved = {
        let store = restart_tests::store(shard_record(4), restart_tests::with_standby());
        let mut card = Card::new();
        card.entries.push(crate::failover::evidence::Registrant {
            holder: false,
            ..restart_tests::holder(restart_tests::standby_pair(), 2)
        });
        let refused = narrow
            .run(&mut client(&store), &sample(), &mut card)
            .unwrap_err();
        assert_eq!(refused.check, Check::Unobserved);
        reported(RecoveryKind::Restart, Some(&refused))
    };
    let stop = |at: usize| run(&|_, card| card.stop_at = Some(at));
    let truncated =
        |nth| run(&|_, card| card.fault = Some(restart_tests::Fault::ReportTruncated(nth)));
    let holds = [
        stop(0),
        stop(1),
        stop(2),
        stop(3),
        truncated(1),
        stop(4),
        stop(5),
        truncated(2),
        unobserved,
    ];
    let mut labels = Vec::new();
    for (at, stopped) in holds.into_iter().enumerate() {
        assert_eq!(
            stopped.next,
            Some(crate::failover::report::RecoveryNext::Hold)
        );
        let entry = crate::failover::report::VolumeEntry {
            recovery: stopped,
            ..controls::owner()
        };
        let steps = [controls::Step::Report {
            host: 1,
            state: Box::new(controls::host_state()),
            entries: vec![entry],
        }];
        let (inputs, refused) = controls::sealed(&steps);
        assert_eq!(refused, []);
        assert_eq!(
            super::evaluate(&device, &inputs, super::Deltas::ResetAware).len(),
            1,
            "hold {at}"
        );
        let super::Input::Record { view, .. } = &inputs[0] else {
            panic!("a report")
        };
        labels.push(view["entries"][0]["recovery"]["check"].clone());
    }
    assert_eq!(&labels, device["condition"]["values"].as_array().unwrap());
    let flipped = run(&|_, card| {
        card.entries.push(crate::failover::evidence::Registrant {
            holder: false,
            ..restart_tests::holder(crate::storage::gate_fixture::foreign(), 2)
        })
    });
    assert_eq!(
        (flipped.check, flipped.next),
        (
            Some(crate::failover::report::RecoveryCheck::NotHolding),
            Some(crate::failover::report::RecoveryNext::Flip)
        )
    );
    let entry = crate::failover::report::VolumeEntry {
        recovery: flipped,
        ..controls::owner()
    };
    assert_eq!(
        super::fired(&device, &[super::report(entry)]),
        [],
        "an observed refusal flips"
    );
    // The volume read, the shard read and the volume reread after Report #1 precede the bump.
    let lost = run(&|store, _| {
        for arm in [
            Arm::Pass,
            Arm::Pass,
            Arm::Pass,
            Arm::Timeout { commit: false },
        ] {
            store.schedule(arm);
        }
    });
    assert_eq!(twin(lost, completed), controls::unknown_recovery_write());
    let holder = refusal(
        shard_record(4),
        restart_tests::with_standby(),
        &|_, card| {
            card.entries = vec![
                crate::failover::evidence::Registrant {
                    holder: false,
                    ..restart_tests::holder(restart_tests::own(), 1)
                },
                restart_tests::holder(restart_tests::standby_pair(), 2),
            ];
            card.after_lineage = Some(Box::new(|entries| {
                for entry in entries.iter_mut() {
                    entry.holder = entry.pair == restart_tests::standby_pair();
                }
                if !entries.iter().any(|entry| entry.holder) {
                    entries.push(restart_tests::holder(restart_tests::standby_pair(), 4));
                }
            }));
        },
    );
    assert_eq!(
        holder.check,
        Check::Lineage(crate::failover::restart::Lineage::Confirm(Box::new(
            Check::RecordedHolder
        )))
    );
    assert_eq!(
        twin(part(&holder), completed),
        controls::hold_recorded_holder()
    );
    let unheld = refusal(
        shard_record(4),
        restart_tests::volume_record(),
        &|_, card| card.fault = Some(restart_tests::Fault::PreemptUnregisters),
    );
    assert_eq!(unheld.check, Check::Unheld);
    assert_eq!(twin(part(&unheld), completed), controls::hold_no_holder());
    let raced = refusal(
        shard_record(4),
        restart_tests::volume_record(),
        &|store, card| {
            let store = store.clone();
            card.before_report = Some(Box::new(move || {
                let mut other = client(&store);
                let read = other.read::<ShardRecord>(Key::Shard(shard())).unwrap();
                other.bump(&read).unwrap();
            }))
        },
    );
    assert_eq!(
        raced.check,
        Check::Bump(StoreError::Refused(Refusal::Condition))
    );
    assert_eq!(twin(part(&raced), completed), controls::hold_store());
    let suffix_only = ShardRecord {
        ancestry: Ancestry::new(&[Suffix {
            session: crate::net::ownership::session_of(shard_record(2).generation.get() as u32, 4),
            start: 0,
            certified: 3,
            end: 3,
        }])
        .unwrap(),
        ..shard_record(2)
    };
    let suffix = refusal(suffix_only, restart_tests::volume_record(), &|_, _| {});
    assert_eq!(suffix.check, Check::SuffixOnly);
    assert_eq!(twin(part(&suffix), completed), controls::suffix_only());
}

/// `recovery-stuck`: a running takeover reads its age from its start, one microsecond past the row's threshold on
/// the control and at the threshold on the clean twin.
#[test]
fn a_running_takeover_reads_its_age() {
    let catalog = super::catalog();
    let row = super::row(&catalog, "recovery-stuck");
    let threshold = row["condition"]["value"].as_u64().unwrap();
    let mut status = RecoveryStatus::NO_ATTEMPT;
    status.start(RecoveryKind::Takeover, 1_000);
    let at = |past: u64| status.recovery(1_000 + threshold + past);
    let history = |fault| {
        controls::history(
            &row,
            if fault {
                "recovery_stuck"
            } else {
                "recovery_stuck.clean"
            },
        )
    };
    for (fault, past) in [(true, 1), (false, 0)] {
        let controls::Step::Report { entries, .. } = &history(fault)[0] else {
            panic!("a report row")
        };
        assert_eq!(entries[0].recovery, at(past), "fault {fault}");
    }
}

/// `load-refused`: the load guard refuses limits whose payload area is empty before it reads an entry, the refusal
/// the owner's entry carries from an unloadable metadata outcome; valid limits over no entry load.
#[test]
fn the_load_guard_gives_the_load_refusal() {
    use crate::storage::{EngineBudget, LoadLimits, load_guard};
    let budget = EngineBudget::unlimited();
    let limits = LoadLimits {
        payload_start: 0,
        payload_end: 100,
        reserve_units: 1,
        slot_count: 8,
        n_max: 8,
        record_chunk_len: 8192,
    };
    let empty = LoadLimits {
        payload_end: 0,
        ..limits
    };
    let refused = load_guard(&[], empty, &budget).err();
    let loaded = load_guard(&[], limits, &budget).err();
    assert_eq!(twin(refused, loaded), controls::load_refused());
}

/// `enumeration-foreign` and `registrant-foreign`: a listing that names an instance outside the admitted set, and
/// a Report whose holder is foreign, give the foreign labels; the listing of the own instance alone and a sole
/// registrant give the clean ones.
#[test]
fn the_listing_check_and_the_registrant_judgment_give_the_foreign_rows() {
    let own = InstanceId::new("i-00000000000000001").unwrap();
    let listed = |ids: &[&str]| -> Vec<String> { ids.iter().map(|id| (*id).to_owned()).collect() };
    let foreign = Enumeration::from(&check(
        &listed(&[own.as_str(), "i-0000000000000000f"]),
        &own,
        [],
    ));
    let matches = Enumeration::from(&check(&listed(&[own.as_str()]), &own, []));
    assert_eq!(twin(foreign, matches), controls::enumeration_foreign());
    let trigger = serving::ReportTrigger::new(NotSole::ForeignHolder).unwrap();
    let holder = (
        Some(Registrants::from(RegistrantJudgment::Refused(
            NotSole::ForeignHolder,
        ))),
        Some(Withdrawal::from(serving::Cause::Report(trigger))),
    );
    let sole = (Some(Registrants::from(RegistrantJudgment::Sole)), None);
    assert_eq!(twin(holder, sole), controls::registrant_foreign());
}

/// `retention-damage` and `first-hit-slow`: a warm load with one slot unit whose content check failed, and a first
/// safe hit one microsecond past the row's threshold from the attach's first tick, give the account and the time
/// the entry reads; the intact load and the hit at the threshold give the clean twins.
#[test]
fn the_recovery_report_gives_the_retention_and_first_hit_rows() {
    use crate::storage::checkpoint::UnitDamage;
    let mut report = RecoveryReport {
        held_units: 48,
        ..RecoveryReport::default()
    };
    report.warm.installed = 12;
    let intact = Retention::of(&report);
    report.warm.installed = 11;
    report.warm.failed_units = 1;
    report.warm.first_damage = Some(UnitDamage::Content { unit: 3 });
    let damaged = Retention::of(&report);
    assert_eq!(
        twin(Some(damaged), Some(intact)),
        controls::retention_damage()
    );
    let catalog = super::catalog();
    let row = super::row(&catalog, "first-hit-slow");
    let threshold = row["condition"]["value"].as_u64().unwrap();
    let hit = |past: u64| {
        let mut report = RecoveryReport::default();
        report.phases[RecoveryPhase::Initialization as usize].start = Some(500);
        report.phases[RecoveryPhase::FirstSafeHit as usize].start = Some(500 + threshold + past);
        RecoveryTimes::of(&report).first_hit_us
    };
    for (fault, past) in [(true, 1), (false, 0)] {
        let name = if fault {
            "first_hit_slow"
        } else {
            "first_hit_slow.clean"
        };
        let controls::Step::Report { entries, .. } = &controls::history(&row, name)[0] else {
            panic!("a report row")
        };
        assert_eq!(entries[0].times.first_hit_us, hit(past), "fault {fault}");
    }
}

/// `chain-at-cap`: a shard record whose ancestry holds `MAX_CHAIN` suffixes reads a full ancestry gauge, and one
/// with one suffix reads one of `MAX_CHAIN`.
#[test]
fn the_recorded_ancestry_gives_the_chain_row() {
    let suffix = |at: u64| Suffix {
        session: crate::net::ownership::session_of(1, 2),
        start: at * 4,
        certified: at * 4 + 3,
        end: at * 4 + 3,
    };
    let with = |n: u64| ShardRecord {
        ancestry: Ancestry::new(&(0..n).map(suffix).collect::<Vec<_>>()).unwrap(),
        ..crate::storage::store_tests::record()
    };
    let gauge = |n: u64| Pressure::recorded(Some(&with(n)), None, false).ancestry;
    assert_eq!(
        twin(gauge(MAX_CHAIN as u64), gauge(1)),
        controls::chain_at_cap()
    );
}

/// `exit-restarting`: an exit request the target refuses as stale restarts, and one whose successor record arrives
/// while the authority is withdrawn exits.
#[test]
fn the_exit_tracker_gives_the_restarting_row() {
    let record = |generation: u64| ShardRecord {
        generation: crate::net::ownership::ShardGeneration::new(generation).unwrap(),
        ..crate::storage::store_tests::record()
    };
    let tracked = record(3);
    let operation = ExitOperation::new([0xA1; 16]).unwrap();
    let serving = authority(serving::State::Serving, 2, None);
    let withdrawn = authority(serving::State::Withdrawn, 2, Some(serving::Cause::Planned));
    let track = || ExitTracker::new(tracked.shard, tracked.owner);
    let mut refused = track();
    refused.received(operation, &serving);
    refused.refused(operation, crate::failover::retire::Stale::Target);
    let mut exited = track();
    exited.received(operation, &serving);
    exited.observe(&withdrawn, Some(&record(4)));
    let status = |tracker: &ExitTracker| tracker.last().unwrap().status;
    assert_eq!(
        twin(status(&refused), status(&exited)),
        controls::exit_restarting()
    );
}

/// `exit-stuck`: an exit request whose authority withdrew, with the shard record still naming the tenure it was
/// received at, stands at `waiting` for as long as no successor record arrives; the successor record exits it.
#[test]
fn the_exit_tracker_gives_the_stuck_row() {
    let record = |generation: u64| ShardRecord {
        generation: crate::net::ownership::ShardGeneration::new(generation).unwrap(),
        ..crate::storage::store_tests::record()
    };
    let tracked = record(3);
    let operation = ExitOperation::new([0xB2; 16]).unwrap();
    let serving = authority(serving::State::Serving, 2, None);
    let withdrawn = authority(serving::State::Withdrawn, 2, Some(serving::Cause::Planned));
    let status = |tracker: &ExitTracker| tracker.last().unwrap().status;
    let withdrawn_exit = || {
        let mut tracker = ExitTracker::new(tracked.shard, tracked.owner);
        tracker.received(operation, &serving);
        tracker.observe(&withdrawn, None);
        assert_eq!(status(&tracker), ExitStatus::Withdrawn);
        tracker
    };
    let mut stuck = withdrawn_exit();
    for _ in 0..3 {
        stuck.observe(&withdrawn, Some(&tracked));
    }
    let mut completed = withdrawn_exit();
    completed.observe(&withdrawn, Some(&tracked));
    completed.observe(&withdrawn, Some(&record(4)));
    assert_eq!(
        twin(status(&stuck), status(&completed)),
        controls::exit_stuck()
    );
}

/// `store-unknown-rate`: three writes whose replies the store double loses raise the client's unknown tally to the
/// row's count, which the entry's store outcomes read; two leave it one short.
#[test]
fn lost_write_replies_give_the_unknown_rate() {
    let catalog = super::catalog();
    let row = super::row(&catalog, "store-unknown-rate");
    let count = row["condition"]["at_least"].as_u64().unwrap();
    let unknown = |writes| StoreOutcomes::from(lost_replies(writes).1).unknown;
    for (fault, writes) in [(true, count), (false, count - 1)] {
        let name = if fault {
            "store_unknown_rate"
        } else {
            "store_unknown_rate.clean"
        };
        let history = controls::history(&row, name);
        let controls::Step::Report { entries, .. } = history.last().unwrap() else {
            panic!("a report row")
        };
        assert_eq!(entries[0].store.unknown, unknown(writes), "fault {fault}");
    }
}

/// `suffix-backlog-full`, `self-suspect-host` and `producer-missing`: a suffix backlog at its queue bound, a
/// detector tick that returned a repair demand, and one of two assigned volumes without a fresh entry give the
/// control values; a short backlog, a tick with no repair demand and every assigned volume fresh give the clean.
#[test]
fn the_backlog_the_detector_and_the_producer_count_give_their_rows() {
    let backlog = |blocks: u64| {
        Backlog::from(SuffixBacklog {
            blocks,
            limit: 16,
            age_ns: Some(5_000),
        })
        .blocks
    };
    assert_eq!(
        twin(backlog(16), backlog(2)),
        controls::suffix_backlog_full()
    );
    let detector = |left: u64| {
        let census = crate::failover::detect::host::WatchCensus {
            tracked: 3,
            suspected: 2,
            suspect_left: Some(left),
            nominations: 0,
        };
        Detector::of(&census).self_suspect_us
    };
    assert_eq!(
        twin(detector(5_000_000), detector(0)),
        controls::self_suspect_host()
    );
    assert_eq!(
        twin(
            producer_missing([true, false]),
            producer_missing([true, true])
        ),
        controls::producer_missing()
    );
}

/// One status part the builder gives from one tick's inputs: the survey's zone-wide status, its host views with
/// each one's silence, its shard rows with their records, the store client's alarm and tally, and the memory the
/// loop carries.
struct Tick<'a> {
    status: crate::failover::zone_loop::status::ZoneStatus,
    hosts: Vec<(crate::failover::zone_loop::observe::HostView, bool)>,
    shards: Vec<(
        crate::failover::zone_loop::status::ShardStatus,
        Option<crate::failover::zone_loop::observe::ShardRecords>,
    )>,
    store: (crate::storage::store::Alarm, crate::storage::store::Tally),
    memory: &'a mut Memory,
    /// The loop time of the tick.
    now_us: u64,
}

/// The fresh window the builder emitters run under.
const FRESH_US: u64 = 1_000;

impl Tick<'_> {
    fn part(self) -> ZonePart {
        let bounds = crate::failover::bounds::Bounds::new(8, 2, 100, 10, 20, 5).unwrap();
        let store = (self.store.0, &self.store.1);
        let zone = crate::failover::standbys::Zone(1);
        let clock = crate::failover::report::status::Clock {
            now_us: self.now_us,
            fresh_us: FRESH_US,
        };
        let hosts = self.hosts.iter().map(|(view, silent)| (view, *silent));
        let mut builder = Builder::new(
            (zone, &self.status),
            hosts,
            self.memory,
            &bounds,
            store,
            clock,
        );
        for (row, records) in &self.shards {
            builder.shard(row, records.as_ref(), false);
        }
        builder.finish()
    }
}

mod survey {
    use crate::failover::loss::{Health, Phase, Receipt, Request};
    use crate::failover::records::ShardRecord;
    use crate::failover::report::HostReport;
    use crate::failover::sim::host;
    use crate::failover::zone_loop::evidence::{HostEvidence, VolumeJudgement};
    use crate::failover::zone_loop::observe::{Completeness, HostView, ShardRecords};
    use crate::failover::zone_loop::status::{
        Holds, ShardState, ShardStatus, VerdictCounts, ZoneStatus,
    };
    use crate::net::ownership::{Shard, ShardGeneration};
    use crate::storage::store_tests::record;

    pub(super) fn zone(census: Option<usize>) -> ZoneStatus {
        ZoneStatus {
            shards: Vec::new(),
            census,
            cap: 64,
            cap_below: None,
            inflight: Some(0),
            holds: Holds::default(),
            verdicts: Some(VerdictCounts::default()),
            complete: Completeness {
                reports: true,
                instances: true,
                volumes: true,
                store: true,
            },
            unnamed: Some(0),
            tick: 1,
            started_us: 0,
        }
    }

    pub(super) fn row(
        state: ShardState,
        blocker: Option<crate::failover::zone_loop::status::Blocker>,
        overdue: bool,
    ) -> ShardStatus {
        ShardStatus {
            shard: Shard::new(1).unwrap(),
            state,
            blocker,
            target: None,
            closed: None,
            exposure_us: Some(1),
            overdue,
        }
    }

    pub(super) fn view(number: u64, verdict: HostEvidence, report: Option<HostReport>) -> HostView {
        HostView {
            entry: crate::failover::zone_loop::tests::directory::entry(number, 0),
            verdict,
            answered: true,
            report: report.map(std::sync::Arc::new),
        }
    }

    /// Shard 1's records owned by host 11 with `change` applied, on the restart fixture's volume.
    pub(super) fn records(change: impl FnOnce(&mut ShardRecords)) -> ShardRecords {
        let mut records = ShardRecords {
            record: ShardRecord {
                shard: Shard::new(1).unwrap(),
                owner: host(11),
                attempts: 1,
                spare: None,
                standby: None,
                ..record()
            },
            active: crate::failover::restart::tests::volume_record(),
            spare: None,
            receipt: None,
            replacement: None,
            entries: Vec::new(),
            judgement: VolumeJudgement {
                health: Some(Health::Available),
                others: 0,
                complete: true,
                streak: 0,
                confirmed: false,
            },
        };
        change(&mut records);
        records
    }

    /// A receipt of the replacement after `record`'s generation, held or not.
    pub(super) fn receipt(record: &ShardRecord, held: bool) -> Receipt {
        Receipt {
            request: Request {
                namespace: record.namespace,
                shard: record.shard,
                generation: ShardGeneration::new(record.generation.get() + 1).unwrap(),
            },
            layout: crate::failover::sim::layout(),
            attempt: 1,
            phase: Phase::Open,
            held,
            released: false,
        }
    }
}

/// The status rows: each control's injected survey row, record, host view or store outcome, through the status
/// builder, gives the row's shared control value, and the matched clean input gives the clean value. The survey's
/// own states reach these inputs in `zone_loop::tests::tick`, which compares its parts with the same controls.
#[test]
fn the_status_builder_gives_the_status_rows() {
    use crate::failover::report::status::{
        CLASSES, Class, RECEIPTS, REFUSED, ReceiptCount, Refused, STANDBYS, Standby, StoreState,
    };
    use crate::failover::zone_loop::evidence::HostEvidence;
    use crate::failover::zone_loop::status::{Blocker, ShardState};
    let slot = |table: &[Standby], value| table.iter().position(|v| *v == value).unwrap();
    let store = (
        crate::storage::store::Alarm::Clear,
        crate::storage::store::Tally::default(),
    );
    let part = |status, hosts, shards| {
        let mut memory = Memory::default();
        Tick {
            status,
            hosts,
            shards,
            store,
            memory: &mut memory,
            now_us: 5,
        }
        .part()
    };
    let owner = || vec![(survey::view(11, HostEvidence::Live, None), false)];
    let one = |row, records| part(survey::zone(Some(0)), owner(), vec![(row, records)]);
    let past = |overdue| {
        one(survey::row(ShardState::NoCandidate, None, overdue), None).standby
            [slot(STANDBYS, Standby::Past)]
    };
    assert_eq!(
        twin(past(true), past(false)),
        controls::no_standby_past_target()
    );
    let blocked_by = |blocker: Blocker, given: Blocker| {
        one(
            survey::row(ShardState::NoCandidate, Some(given), false),
            None,
        )
        .blockers[blocker.position()]
    };
    let full = Blocker::CensusFull;
    assert_eq!(
        twin(blocked_by(full, full), blocked_by(full, Blocker::Headroom)),
        controls::census_refused_full()
    );
    let closed = Blocker::AttachClosed;
    assert_eq!(
        twin(
            blocked_by(closed, closed),
            blocked_by(closed, Blocker::Headroom)
        ),
        controls::attach_closed()
    );
    let exhausted = Blocker::ReplacementExhausted;
    assert_eq!(
        twin(
            blocked_by(exhausted, exhausted),
            blocked_by(exhausted, Blocker::Headroom)
        ),
        controls::replacement_exhausted()
    );
    let below = |below: bool| {
        let mut status = survey::zone(Some(0));
        status.cap_below = below
            .then_some(crate::failover::zone_loop::config::CapBelowShards { cap: 1, shards: 3 });
        part(status, Vec::new(), Vec::new()).flags.cap_below
    };
    assert_eq!(
        twin(below(true), below(false)),
        controls::census_cap_below_shards()
    );
    let protected = survey::row(ShardState::Protected, None, false);
    let held = |held: bool| {
        let records = survey::records(|r| r.receipt = Some(survey::receipt(&r.record, held)));
        one(protected, Some(records)).receipts[RECEIPTS
            .iter()
            .position(|r| *r == ReceiptCount::Held)
            .unwrap()]
    };
    assert_eq!(twin(held(true), held(false)), controls::replacement_held());
    let lost = |health| {
        let records = survey::records(|r| r.judgement.health = Some(health));
        one(protected, Some(records)).volumes
            [crate::failover::report::status::health_at(Some(crate::failover::loss::Health::Lost))]
    };
    use crate::failover::loss::Health;
    assert_eq!(
        twin(lost(Health::Lost), lost(Health::Available)),
        controls::volume_lost()
    );
    let unnamed = |count: u32| {
        let mut status = survey::zone(Some(0));
        status.unnamed = Some(count);
        part(status, Vec::new(), Vec::new()).unnamed_volumes
    };
    assert_eq!(twin(unnamed(1), unnamed(0)), controls::volume_unnamed());
    let mut unread = survey::zone(Some(0));
    unread.unnamed = None;
    assert_eq!(
        part(unread, Vec::new(), Vec::new()).unnamed_volumes,
        None,
        "a tick that could not count reads unavailable"
    );
    let class =
        |part: &ZonePart, class| part.classes[CLASSES.iter().position(|c| *c == class).unwrap()];
    let impaired = one(
        survey::row(ShardState::VolumeImpaired, None, false),
        Some(survey::records(|_| {})),
    );
    let fresh = one(
        survey::row(ShardState::Initial, None, false),
        Some(survey::records(|_| {})),
    );
    assert_eq!(
        twin(
            class(&impaired, Class::Blocked),
            class(&fresh, Class::Blocked)
        ),
        controls::shard_blocked()
    );
    let unread = survey::row(
        ShardState::Unobserved(crate::failover::zone_loop::observe::Source::Directory),
        None,
        false,
    );
    let silent = one(unread, None);
    assert_eq!(
        twin(class(&silent, Class::Silent), class(&fresh, Class::Silent)),
        controls::shard_silent()
    );
    let unavailable = crate::storage::store::StoreError::Unavailable;
    let store_down = ShardState::Unobserved(crate::failover::zone_loop::observe::Source::Store(
        unavailable,
    ));
    let at = Blocker::StoreUnavailable.position();
    let down = one(
        survey::row(store_down, Some(Blocker::StoreUnavailable), false),
        None,
    )
    .blockers[at];
    assert_eq!(
        twin([down, down], [down, fresh.blockers[at]]),
        controls::store_unread()
    );
    let need = |verdict| {
        let hosts = vec![(survey::view(11, verdict, None), false)];
        let shards = vec![(
            survey::row(ShardState::NoCandidate, None, false),
            Some(survey::records(|_| {})),
        )];
        part(survey::zone(Some(0)), hosts, shards).needs
            [crate::failover::report::status::need_at(crate::failover::standbys::Need::Fresh)]
    };
    assert_eq!(
        twin(need(HostEvidence::Lost), need(HostEvidence::Live)),
        controls::need_fresh()
    );
    let census = |len| {
        let mut status = survey::zone(Some(len));
        status.cap_below = Some(crate::failover::zone_loop::config::CapBelowShards {
            cap: 64,
            shards: 70,
        });
        let part = part(status, Vec::new(), Vec::new());
        assert!(part.flags.cap_below);
        part.census
    };
    assert_eq!(twin(census(58), census(57)), controls::census_near_cap());
    let suspect = |left: u64| {
        let mut report = crate::failover::standbys::tests::report_of(
            crate::failover::sim::host(12),
            crate::failover::report::Gauge::Unavailable,
            crate::failover::report::Gauge::Unavailable,
        );
        report.host.detector.self_suspect_us = Some(left);
        let hosts = vec![(survey::view(12, HostEvidence::Live, Some(report)), false)];
        part(survey::zone(Some(0)), hosts, Vec::new())
            .hosts
            .self_suspect
    };
    assert_eq!(
        twin(suspect(5_000_000), suspect(0)),
        controls::self_suspect_zone()
    );
    let silent_hosts = |silent: bool| {
        let hosts = (1..=3)
            .map(|n| (survey::view(n, HostEvidence::Live, None), silent && n == 2))
            .collect();
        part(survey::zone(Some(0)), hosts, Vec::new()).hosts.silent
    };
    assert_eq!(
        twin(silent_hosts(true), silent_hosts(false)),
        controls::host_silent()
    );
    let budgets = |attempts: u32, generation: u64| {
        let records = survey::records(|r| {
            r.record.attempts = attempts;
            r.record.generation = crate::net::ownership::ShardGeneration::new(generation).unwrap();
        });
        one(protected, Some(records)).budgets
    };
    let tenth = |limit: u64| (limit * 9).div_ceil(10);
    let attempts = tenth(u64::from(crate::failover::records::ATTEMPTS_MAX));
    let generation = tenth(u64::from(u32::MAX) - 1);
    let (high, low) = (
        budgets(u32::try_from(attempts).unwrap(), generation),
        budgets(u32::try_from(attempts - 1).unwrap(), generation - 1),
    );
    assert_eq!(
        twin(high.attempts, low.attempts),
        controls::budget_attempts()
    );
    assert_eq!(
        twin(high.generation, low.generation),
        controls::budget_generation()
    );
    let refusals = |error: Option<crate::failover::report::ReportError>, kind: Refused| {
        let mut memory = Memory::default();
        let at = REFUSED.iter().position(|r| *r == kind).unwrap();
        let first = Tick {
            status: survey::zone(Some(0)),
            hosts: Vec::new(),
            shards: Vec::new(),
            store,
            memory: &mut memory,
            now_us: 5,
        }
        .part();
        if let Some(error) = error {
            memory.events.refused(error);
        }
        let second = Tick {
            status: survey::zone(Some(0)),
            hosts: Vec::new(),
            shards: Vec::new(),
            store,
            memory: &mut memory,
            now_us: 5,
        }
        .part();
        [first.events.refused[at], second.events.refused[at]]
    };
    use crate::failover::report::ReportError;
    assert_eq!(
        twin(
            refusals(Some(ReportError::Tag), Refused::Tag),
            refusals(None, Refused::Tag)
        ),
        controls::report_forged()
    );
    let schema = Some(ReportError::Schema { found: 2 });
    assert_eq!(
        twin(
            refusals(schema, Refused::Schema),
            refusals(None, Refused::Schema)
        ),
        controls::report_schema()
    );
    let stale = |serving| {
        let mut entry = super::controls::owner();
        entry.serving = Some(serving);
        let mut report = crate::failover::standbys::tests::report_of(
            crate::failover::sim::host(12),
            crate::failover::report::Gauge::Unavailable,
            crate::failover::report::Gauge::Unavailable,
        );
        report.entries = vec![entry];
        let hosts = vec![
            (survey::view(11, HostEvidence::Live, None), false),
            (survey::view(12, HostEvidence::Live, Some(report)), false),
        ];
        let records = survey::records(|r| r.record.attempts = 2);
        let mut memory = Memory::default();
        let mut tick = |now_us| {
            Tick {
                status: survey::zone(Some(0)),
                hosts: hosts.clone(),
                shards: vec![(protected, Some(records.clone()))],
                store,
                memory: &mut memory,
                now_us,
            }
            .part()
        };
        let first = tick(5).stale_serving;
        assert_eq!(
            first, 0,
            "a stale entry counts once it outlasts the fresh window"
        );
        tick(6 + FRESH_US).stale_serving
    };
    use crate::failover::serving::State;
    assert_eq!(
        twin(stale(State::Serving), stale(State::Withdrawn)),
        controls::stale_serving()
    );
    let alarm = |alarm| StoreState::of(alarm, &crate::storage::store::Tally::default()).alarm;
    let clear = client(&seeded()).alarm();
    assert_eq!(
        twin(alarm(regressed()), alarm(clear)),
        controls::store_regression_reconciler()
    );
    assert_eq!(
        twin(alarm(moved()), alarm(clear)),
        controls::store_instance_change_reconciler()
    );
}

/// `store-unknown-rate-reconciler`: three writes whose replies the store double loses raise the reconciler client's
/// unknown tally, which the status reads, to the row's count; two leave it one short.
#[test]
fn lost_write_replies_give_the_reconciler_unknown_rate() {
    use crate::failover::report::status::StoreState;
    let catalog = super::catalog();
    let row = super::row(&catalog, "store-unknown-rate-reconciler");
    let count = row["condition"]["at_least"].as_u64().unwrap();
    let unknown = |writes| {
        let (alarm, tally) = lost_replies(writes);
        StoreState::of(alarm, &tally).outcomes[0]
    };
    for (fault, writes) in [(true, count), (false, count - 1)] {
        let name = if fault {
            "store_unknown_rate_reconciler"
        } else {
            "store_unknown_rate_reconciler.clean"
        };
        let history = controls::history(&row, name);
        let controls::Step::Status(parts) = history.last().unwrap() else {
            panic!("a status row")
        };
        assert_eq!(parts[0].store.outcomes[0], unknown(writes), "fault {fault}");
    }
}
