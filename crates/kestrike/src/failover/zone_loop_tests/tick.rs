use crate::failover::loss::{Health, Receipt};
use crate::failover::reconcile::{OperatorRelease, Reconciler, StandbyGate};
use crate::failover::records::{ERA, EventKind, ShardRecord, VolumeRecord};
use crate::failover::report::status::tests::{key_of, writer};
use crate::failover::report::status::{CLASSES, Class, Standby, StatusReader, ZonePart};
use crate::failover::sim::{host, layout};
use crate::failover::standbys::Population;
use crate::failover::standbys::tests::roomy;
use crate::failover::zone_loop::Tick;
use crate::failover::zone_loop::config::ZoneBounds;
use crate::failover::zone_loop::status::{Blocker, ShardState};
use crate::net::ownership::Shard;
use crate::storage::store::sim::{AsReconciler, MemLog, Shared};

use super::world::Recording;
use crate::failover::report::alarm_tests::controls::{self, Twin};
use crate::storage::store::{Client, Item, Key};
use crate::storage::store_tests::record;

use super::config::config_of;
use super::observe::{Fixture, S, START, ZONE, volume};
use super::survey::{designate_all, roomy_fixture, warm};
use super::world::Event;

fn class(part: &ZonePart, class: Class) -> u32 {
    let at = CLASSES.iter().position(|listed| *listed == class).unwrap();
    part.classes[at]
}

fn tick(fixture: &mut Fixture, now_us: u64) -> Tick {
    for number in 1..=fixture.hosts {
        fixture.publish(number, &[]);
    }
    fixture
        .zone
        .tick(Ok(fixture.directory()), &mut fixture.world, now_us)
}

fn reconciler(store: &Shared) -> Reconciler<AsReconciler<Shared>, MemLog> {
    Reconciler::new(Client::open(AsReconciler(store.clone()), MemLog::default()).unwrap())
}

fn bounds_with(
    change: impl FnOnce(&mut crate::failover::zone_loop::config::ZoneConfig),
) -> ZoneBounds {
    let mut config = config_of(8);
    change(&mut config);
    config.validate().unwrap()
}

/// Each tick's part equals what that tick's survey rows give: a shard that needs a standby is counted by its
/// state, its need and an exception row, and after its designation the next tick counts it under a named standby,
/// its row reading `named` and the class it keeps with no owner entry. The class counts add up to the survey's shards
/// and the rows list exactly its shards outside the served class. The test feeds the builder only through
/// `ZoneLoop::tick`.
#[test]
fn each_tick_builds_its_part_from_its_own_survey_rows() {
    let mut fixture = roomy_fixture(4, 1);
    warm(&mut fixture, 12);
    let first = tick(&mut fixture, START + 200 * S);
    let row = first.survey.status.shards[0];
    assert!(matches!(row.state, ShardState::Enrolling { .. }), "{row:?}");
    let part = &first.part;
    assert_eq!((part.zone, part.tick), (ZONE, first.survey.status.tick));
    assert_eq!(part.needs, [1, 0]);
    assert_eq!(part.standby, [0, 1, 0, 0, 0]);
    assert_eq!(part.hosts.verdicts, [4, 0, 0, 0]);
    let cap = fixture.zone.bounds.config().population_cap as u64;
    assert_eq!(
        part.census,
        crate::failover::report::Members::Known {
            used: 0,
            limit: cap
        }
    );
    assert_eq!(part.rows.len(), 1);
    assert_eq!(
        (part.rows[0].shard, part.rows[0].standby),
        (row.shard, Standby::Enrolling)
    );
    assert_eq!(
        class(part, Class::Silent),
        1,
        "no owner entry at the record's tenure"
    );
    designate_all(&fixture);
    let second = tick(&mut fixture, START + 210 * S);
    assert_eq!(second.survey.status.shards[0].state, ShardState::Protected);
    assert_eq!(second.part.needs, [0, 0]);
    assert_eq!(second.part.standby, [1, 0, 0, 0, 0]);
    assert_eq!(second.part.tick, first.part.tick + 1);
    for tick in [&first, &second] {
        let shards = tick.survey.status.shards.len() as u32;
        assert_eq!(tick.part.classes.iter().sum::<u32>(), shards);
        let rows: Vec<_> = tick.part.rows.iter().map(|row| row.shard).collect();
        let survey: Vec<_> = tick
            .survey
            .status
            .shards
            .iter()
            .map(|row| row.shard)
            .collect();
        assert_eq!(rows, survey, "no shard of this zone reads served");
    }
    assert_eq!(second.part.rows[0].standby, Standby::Named);
}

/// A shard with no candidate reads `within` while its exposure is inside the standby target and `past` beyond it.
#[test]
fn a_shard_without_a_standby_past_its_target_reads_past() {
    let mut fixture = Fixture::new(3, 1);
    warm(&mut fixture, 12);
    let within = tick(&mut fixture, START + 200 * S).part;
    assert_eq!(within.standby, [0, 0, 1, 0, 0]);
    assert_eq!(within.blockers.iter().sum::<u32>(), 1);
    let target = fixture.zone.bounds.config().standby_target_us;
    let past = tick(&mut fixture, START + 100 * S + target + 10 * S).part;
    assert_eq!(past.standby, [0, 0, 0, 1, 0]);
    assert_eq!(past.rows[0].standby, Standby::Past);
    let at = 3;
    assert_eq!(
        Twin {
            fault: past.standby[at],
            clean: within.standby[at]
        },
        controls::no_standby_past_target(),
        "no-standby-past-target"
    );
}

/// Three expected hosts, one of which stops reporting, read one silent of three; a forged tag delivered once raises
/// `refused.tag` by one, and the genuine report after it raises nothing.
#[test]
fn a_silent_host_and_a_forged_tag_count_once() {
    let mut fixture = Fixture::new(3, 1);
    warm(&mut fixture, 12);
    let quiet = tick(&mut fixture, START + 200 * S).part;
    assert_eq!(
        quiet.hosts.silent,
        crate::failover::report::Members::Known { used: 0, limit: 3 }
    );
    let tag = crate::failover::report::status::REFUSED
        .iter()
        .position(|kind| format!("{kind:?}") == "Tag")
        .unwrap();
    assert_eq!(quiet.events.refused[tag], 0);
    let mut forged = fixture.sealed(2, &[]);
    let last = forged.len() - 1;
    forged[last] ^= 1;
    fixture.publish(1, &[]);
    fixture.publish(3, &[]);
    fixture.world.reports.insert(host(2), forged);
    let refused = fixture
        .zone
        .tick(Ok(fixture.directory()), &mut fixture.world, START + 210 * S)
        .part;
    assert_eq!(refused.events.refused[tag], 1);
    assert_eq!(
        refused.events.refused.iter().sum::<u32>(),
        1,
        "only the tag refusal counts"
    );
    let after = tick(&mut fixture, START + 220 * S).part;
    assert_eq!(after.events.refused[tag], 1);
    let mut now = START + 230 * S;
    let mut part = after;
    for _ in 0..6 {
        fixture.publish(1, &[]);
        fixture.publish(2, &[]);
        part = fixture
            .zone
            .tick(Ok(fixture.directory()), &mut fixture.world, now)
            .part;
        now += 10 * S;
    }
    assert_eq!(
        part.hosts.silent,
        crate::failover::report::Members::Known { used: 1, limit: 3 }
    );
    let silent = Twin {
        fault: part.hosts.silent,
        clean: quiet.hosts.silent,
    };
    assert_eq!(silent, controls::host_silent(), "host-silent");
    let tags = [quiet.events.refused[tag], refused.events.refused[tag]];
    assert_eq!(
        Twin {
            fault: tags,
            clean: genuine(crate::failover::report::status::Refused::Tag)
        },
        controls::report_forged(),
        "report-forged"
    );
}

/// The contract's sealed schema-2 report, delivered as host 2's latest report for one tick, raises `refused.schema`
/// by one through the loop's intake and raises no other refusal; the genuine report on the next tick raises nothing.
#[test]
fn a_schema_2_report_counts_one_schema_refusal() {
    let mut fixture = Fixture::new(3, 1);
    warm(&mut fixture, 12);
    let quiet = tick(&mut fixture, START + 200 * S).part;
    let schema = crate::failover::report::status::REFUSED
        .iter()
        .position(|kind| *kind == crate::failover::report::status::Refused::Schema)
        .unwrap();
    let refusal = &crate::failover::report::alarm_tests::report_contract()["refusals"]["schema-2"];
    let bytes = crate::failover::report::tests::unhex(refusal["bytes"].as_str().unwrap());
    fixture.publish(1, &[]);
    fixture.publish(3, &[]);
    fixture.world.reports.insert(host(2), bytes);
    let refused = fixture
        .zone
        .tick(Ok(fixture.directory()), &mut fixture.world, START + 210 * S)
        .part;
    assert_eq!(
        refused.events.refused.iter().sum::<u32>(),
        1,
        "only the schema refusal counts"
    );
    let after = tick(&mut fixture, START + 220 * S).part;
    assert_eq!(after.events.refused, refused.events.refused);
    let counts = [quiet.events.refused[schema], refused.events.refused[schema]];
    assert_eq!(
        Twin {
            fault: counts,
            clean: genuine(crate::failover::report::status::Refused::Schema)
        },
        controls::report_schema(),
        "report-schema"
    );
}

fn genuine(kind: crate::failover::report::status::Refused) -> [u32; 2] {
    let mut fixture = Fixture::new(3, 1);
    warm(&mut fixture, 12);
    let at = crate::failover::report::status::REFUSED
        .iter()
        .position(|listed| *listed == kind)
        .unwrap();
    let mut counts = [0; 2];
    let mut sequences = [0; 2];
    for (slot, now) in [200, 210].into_iter().enumerate() {
        let tick = tick(&mut fixture, START + now * S);
        assert_eq!(tick.part.events.refused.iter().sum::<u32>(), 0);
        counts[slot] = tick.part.events.refused[at];
        let zone = tick.survey.observation.zone.as_ref().unwrap();
        let view = zone.hosts.iter().find(|view| view.entry.host == host(2));
        sequences[slot] = view.unwrap().report.as_ref().unwrap().sequence;
    }
    assert!(
        sequences[1] > sequences[0],
        "host 2's genuine report is accepted"
    );
    counts
}

/// A census that lists `cap` shards and a shard that needs a slot read a full census, one `census-full` blocker
/// and a cap below the zone's shard count; the clean twin, one free slot, plans a reservation, counts no blocker
/// and reads its cap at the shard count.
#[test]
fn a_full_census_reads_full_and_one_free_slot_reserves() {
    let part = |cap: usize| {
        let mut fixture = roomy_fixture(4, 2);
        fixture.zone.bounds = bounds_with(|config| config.population_cap = cap);
        let gate = StandbyGate::qualified();
        let mut reconciler = reconciler(&fixture.store);
        let shard = Shard::new(1).unwrap();
        let candidate = roomy(host(4));
        let population = Population { cap };
        let bounds = *fixture.zone.bounds.bounds();
        reconciler
            .reserve(&gate, &population, &bounds, ZONE, shard, &candidate, |_| {
                false
            })
            .unwrap();
        warm(&mut fixture, 12);
        let tick = tick(&mut fixture, START + 200 * S);
        let reserved = tick.survey.plan.steps.iter().any(|step| {
            matches!(step, crate::failover::zone_loop::plan::Step::Reserve { shard, .. } if shard.get() == 2)
        });
        (tick.part, reserved)
    };
    let (full, reserved) = part(1);
    assert_eq!(
        full.census,
        crate::failover::report::Members::Known { used: 1, limit: 1 }
    );
    assert_eq!(full.blockers[Blocker::CensusFull.position()], 1);
    assert!(!reserved && full.flags.cap_below);
    let (free, reserved) = part(2);
    assert_eq!(
        free.census,
        crate::failover::report::Members::Known { used: 1, limit: 2 }
    );
    assert_eq!(free.blockers.iter().sum::<u32>(), 0);
    assert!(reserved);
    let at = Blocker::CensusFull.position();
    let refused = Twin {
        fault: full.blockers[at],
        clean: free.blockers[at],
    };
    assert_eq!(
        refused,
        controls::census_refused_full(),
        "census-refused-full"
    );
    let below = Twin {
        fault: full.flags.cap_below,
        clean: free.flags.cap_below,
    };
    assert_eq!(
        below,
        controls::census_cap_below_shards(),
        "census-cap-below-shards"
    );
}

/// One tick of a two-host, one-shard fixture whose active volume record the owner first rewrites with `edit`: the
/// shard's state, the part's attach counts and its `attach-closed` blocker count.
fn closed_tick(
    edit: impl FnOnce(&mut VolumeRecord),
) -> (ShardState, crate::failover::report::status::Attaches, u32) {
    let mut fixture = roomy_fixture(2, 1);
    let mut owner = Client::open(fixture.store.clone(), MemLog::default()).unwrap();
    let read = owner.read::<VolumeRecord>(Key::Volume(volume(1))).unwrap();
    let mut next = read.value().clone();
    edit(&mut next);
    owner.replace(&read, next).unwrap();
    warm(&mut fixture, 12);
    let tick = tick(&mut fixture, START + 200 * S);
    let blockers = tick.part.blockers[Blocker::AttachClosed.position()];
    (
        tick.survey.status.shards[0].state,
        tick.part.attaches,
        blockers,
    )
}

/// The owner and two hosts outside the directory hold the active volume's three live attaches, so the one
/// unattached candidate finds it closed at the live cap; the clean twin, two live attaches, counts no closed shard.
#[test]
fn a_volume_at_its_live_attach_cap_counts_one_closed_shard() {
    let closed = |outside: &[u64]| {
        closed_tick(|next| {
            for &number in outside {
                next.push(EventKind::Attach, host(number), ERA).unwrap();
            }
        })
    };
    let (state, attaches, blockers) = closed(&[50, 51]);
    assert_eq!(
        (state, attaches.closed, attaches.live, blockers),
        (ShardState::Closed, [1, 0, 0, 0, 0], 3, 1)
    );
    let (state, attaches, blockers) = closed(&[50]);
    assert_ne!(state, ShardState::Closed);
    assert_eq!((attaches.closed, attaches.live, blockers), ([0; 5], 2, 0));
}

/// The tick counts the cause the survey names for the one unattached candidate, host 1: its latest event on the
/// active volume is a detach, which closes the shard under `own-entry` while the record's one live attach and its
/// pairs stay below every cap. The clean twin, with no entry of host 1, counts no closed shard and no blocker.
#[test]
fn a_candidate_s_latest_detach_counts_one_own_entry_shard() {
    let (state, attaches, blockers) = closed_tick(|next| {
        next.push(EventKind::Attach, host(1), ERA).unwrap();
        next.push(EventKind::Detach, host(1), ERA).unwrap();
    });
    assert_eq!(
        (state, attaches.closed, blockers),
        (ShardState::Closed, [0, 0, 0, 1, 0], 1)
    );
    let (state, attaches, blockers) = closed_tick(|_| {});
    assert_ne!(state, ShardState::Closed);
    assert_eq!((attaches.closed, blockers), ([0; 5], 0));
}

fn receipt(store: &Shared, shard: Shard) -> Receipt {
    let mut client = Client::open(store.clone(), MemLog::default()).unwrap();
    client
        .read::<Receipt>(Key::Replacement(shard))
        .unwrap()
        .into_value()
}

/// A held replacement receipt reads `held` 1; sealing and accepting the status, then another tick, leave the stored
/// receipt held and the part reading 1, and only the operator's release under `OperatorRelease` makes the next tick
/// read 0. Control: a sealing step that
/// also releases the hold leaves the receipt released, which the check reports.
#[test]
fn a_held_receipt_stays_held_through_sealing_until_the_operator_releases_it() {
    let held_at = |seal: &dyn Fn(&ZonePart, &Shared)| {
        let mut fixture = Fixture::new(3, 2);
        let shard = Shard::new(1).unwrap();
        let mut reconciler = reconciler(&fixture.store);
        let lost = (volume(1), Health::Lost);
        reconciler
            .replacement(&StandbyGate::qualified(), shard, lost, 1, layout())
            .unwrap();
        warm(&mut fixture, 12);
        let part = tick(&mut fixture, START + 200 * S).part;
        assert_eq!(part.receipts, [1, 0, 0, 1]);
        assert_eq!(class(&part, Class::Cold), 1);
        seal(&part, &fixture.store);
        let again = tick(&mut fixture, START + 205 * S).part;
        let held = receipt(&fixture.store, shard).held;
        let count = again.receipts[3];
        (
            held && again.receipts == [1, 0, 0, 1],
            fixture,
            reconciler,
            count,
        )
    };
    let sealing = |part: &ZonePart, _: &Shared| {
        let bytes = writer().seal(std::slice::from_ref(part), 1, 0).unwrap();
        let accepted = StatusReader::default().accept(&bytes, key_of).unwrap();
        assert_eq!(accepted.zones, std::slice::from_ref(part));
    };
    let (held, mut fixture, mut operator, count) = held_at(&sealing);
    assert!(held, "sealing leaves the receipt held");
    let request = receipt(&fixture.store, Shard::new(1).unwrap()).request;
    operator
        .release_hold(&OperatorRelease::diagnosed(), request)
        .unwrap();
    let released = tick(&mut fixture, START + 215 * S).part;
    assert_eq!(released.receipts, [1, 0, 0, 0]);
    let held = Twin {
        fault: count,
        clean: released.receipts[3],
    };
    assert_eq!(held, controls::replacement_held(), "replacement-held");
    let planted = |part: &ZonePart, store: &Shared| {
        sealing(part, store);
        let request = receipt(store, Shard::new(1).unwrap()).request;
        reconciler(store)
            .release_hold(&OperatorRelease::diagnosed(), request)
            .unwrap();
    };
    assert!(
        !held_at(&planted).0,
        "the check sees a seal that releases the hold"
    );
}

type Keys = Vec<(Key, usize, Option<Item>)>;

/// Every store key the history names, with its commit count and its current item.
fn store_state(fixture: &Fixture) -> Keys {
    let mut keys = vec![Key::Standbys(ZONE)];
    for number in 1..=fixture.shards {
        let shard = Shard::new(number).unwrap();
        keys.extend([
            Key::Shard(shard),
            Key::Volume(volume(number)),
            Key::Replacement(shard),
        ]);
        keys.extend((0..record().pages.get()).map(|page| Key::Page(shard, page)));
    }
    let held = fixture.store.0.borrow();
    keys.into_iter()
        .map(|key| (key, held.commit_count(&key), held.current(&key).cloned()))
        .collect()
}

/// How one history's ticks run: the survey alone, the tick with its status sealed and accepted, or the tick with
/// one planted store write through the loop's request log, as a status step that wrote would issue it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Arm {
    Survey,
    Sealed,
    Planted,
}

/// One history of ticks over the zone double under `arm`: the store's items and commit counts, and every request
/// the loop logged, reads included.
fn history(arm: Arm) -> (Keys, Vec<Event>) {
    let mut fixture = roomy_fixture(4, 3);
    for at in 0..30 {
        let now = START + at * 10 * S;
        for number in 1..=fixture.hosts {
            fixture.publish(number, &[]);
        }
        let directory = Ok(fixture.directory());
        if arm == Arm::Survey {
            fixture.zone.survey(directory, &mut fixture.world, now);
        } else {
            let part = fixture.zone.tick(directory, &mut fixture.world, now).part;
            let bytes = writer().seal(std::slice::from_ref(&part), 1, 0).unwrap();
            StatusReader::default().accept(&bytes, key_of).unwrap();
            if arm == Arm::Planted && at == 25 {
                let recording = Recording {
                    inner: AsReconciler(fixture.store.clone()),
                    log: fixture.world.log.clone(),
                };
                let mut client = Client::open(recording, MemLog::default()).unwrap();
                let shard = Shard::new(1).unwrap();
                let read = client.read::<ShardRecord>(Key::Shard(shard)).unwrap();
                client.replace(&read, *read.value()).unwrap();
            }
        }
        if at == 20 {
            designate_all(&fixture);
        }
    }
    (store_state(&fixture), fixture.world.events())
}

/// REPORTS-CONFER-NO-AUTHORITY: one history run twice, once surveying alone and once building, sealing and
/// accepting each tick's status, leaves byte-equal store items, commit counts and request logs, reads included, with
/// no write in either. Control: a status step that issues one store write makes them differ.
#[test]
fn sealing_the_status_changes_no_store_commit() {
    let surveyed = history(Arm::Survey);
    let sealed = history(Arm::Sealed);
    assert_eq!(sealed, surveyed);
    let writes = |events: &[Event]| {
        events
            .iter()
            .filter(|e| matches!(e, Event::Write(_)))
            .count()
    };
    assert_eq!(writes(&sealed.1), 0);
    let planted = history(Arm::Planted);
    assert_ne!(planted, surveyed, "the comparison sees one store write");
    assert_eq!(writes(&planted.1), 1);
}

/// The loop's own store client carries its tally and alarm into the part: a clean tick reads a clear alarm and no
/// outcome, a tick whose census read finds the store unavailable counts one unavailable outcome and reads the store
/// incomplete, and a shard record of another store instance withdraws the client under the namespace alarm.
#[test]
fn the_loop_s_store_alarm_and_tally_reach_its_part() {
    use crate::failover::report::status::StoreAlarm;
    use crate::storage::store::sim::Arm as StoreArm;
    let mut fixture = Fixture::new(3, 1);
    warm(&mut fixture, 12);
    let clean = tick(&mut fixture, START + 200 * S).part;
    assert_eq!(
        (clean.store.alarm, clean.store.outcomes),
        (StoreAlarm::Clear, [0; 4])
    );
    fixture.store.schedule(StoreArm::Unavailable);
    let unavailable = tick(&mut fixture, START + 210 * S).part;
    assert_eq!(unavailable.store.alarm, StoreAlarm::Clear);
    assert_eq!(unavailable.store.outcomes, [0, 1, 0, 0]);
    assert!(!unavailable.flags.store);
    let mut owner = Client::open(
        fixture.store.clone(),
        crate::storage::store::sim::MemLog::default(),
    )
    .unwrap();
    let key = Key::Shard(Shard::new(1).unwrap());
    let read = owner.read::<ShardRecord>(key).unwrap();
    owner.bump(&read).unwrap();
    fixture.store.0.borrow_mut().namespace = crate::storage::store_tests::other_namespace();
    let withdrawn = tick(&mut fixture, START + 220 * S).part;
    assert_eq!(withdrawn.store.alarm, StoreAlarm::Namespace);
    assert_eq!(withdrawn.store.outcomes, [0, 1, 0, 0]);
}

/// The two ways a tick leaves every shard unread, as the status contract's `zones.flags.store` and `zones.hosts`
/// state them. A tick whose census read finds the store unavailable reads each shard silent with its standby unknown
/// and one store-unavailable blocker, and still lists the zone's hosts. A tick whose directory read fails reads every
/// source flag false, no census and no host, and each shard of the directory the loop last admitted silent with its
/// standby unknown and no blocker.
#[test]
fn a_tick_without_its_directory_reads_each_shard_silent_with_no_blocker() {
    use crate::failover::report::Members;
    use crate::failover::report::status::{BLOCKERS, Flags, Hosts};
    use crate::failover::zone_loop::sources::Unreachable;
    use crate::storage::store::sim::Arm as StoreArm;
    let mut fixture = Fixture::new(3, 2);
    warm(&mut fixture, 12);
    let unknown = [0, 0, 0, 0, 2];
    fixture.store.schedule(StoreArm::Unavailable);
    let unavailable = tick(&mut fixture, START + 200 * S).part;
    assert!(!unavailable.flags.store && unavailable.flags.reports);
    assert_eq!(class(&unavailable, Class::Silent), 2);
    assert_eq!(unavailable.standby, unknown);
    assert_eq!(unavailable.blockers.iter().sum::<u32>(), 2);
    assert_eq!(
        unavailable.blockers[Blocker::StoreUnavailable.position()],
        2
    );
    assert_eq!(unavailable.census, Members::Unavailable);
    assert_eq!(
        unavailable.hosts.silent,
        Members::Known { used: 0, limit: 3 }
    );
    let part = (fixture.zone)
        .tick(Err(Unreachable), &mut fixture.world, START + 210 * S)
        .part;
    assert_eq!(part.flags, Flags::default());
    assert_eq!(class(&part, Class::Silent), 2);
    assert_eq!(part.standby, unknown);
    assert_eq!(part.blockers, [0; BLOCKERS]);
    assert_eq!(part.census, Members::Unavailable);
    let unlisted = Hosts {
        verdicts: [0; 4],
        silent: Members::Unavailable,
        self_suspect: 0,
    };
    assert_eq!(part.hosts, unlisted);
}

/// `sources-unread`: a loop that has admitted no directory and whose directory read fails reads its four source
/// flags false on every tick, with warm-up held, no shard in any class and no blocker; a loop whose directory read
/// succeeds reads all four true on its first tick.
#[test]
fn a_loop_that_starts_without_its_directory_reads_no_source() {
    use crate::failover::report::status::BLOCKERS;
    use crate::failover::zone_loop::sources::Unreachable;
    let sources = |part: &ZonePart| {
        let flags = part.flags;
        [flags.reports, flags.instances, flags.volumes, flags.store]
    };
    let mut unread = Fixture::new(3, 2);
    let mut read = Fixture::new(3, 2);
    let listed = tick(&mut read, START).part;
    for at in 0..8 {
        let part = (unread.zone)
            .tick(Err(Unreachable), &mut unread.world, START + at * 10 * S)
            .part;
        assert!(part.flags.warm_up, "tick {at}");
        assert_eq!(part.classes, [0; CLASSES.len()], "tick {at}");
        assert_eq!(part.blockers, [0; BLOCKERS], "tick {at}");
        let twin = Twin {
            fault: sources(&part),
            clean: sources(&listed),
        };
        assert_eq!(twin, controls::sources_unread(), "tick {at}");
    }
}

/// A forged report left in place counts once however many ticks poll it, and a different forged report of the same
/// host counts again.
#[test]
fn an_unchanged_refused_report_counts_once() {
    let mut fixture = Fixture::new(3, 1);
    warm(&mut fixture, 12);
    let tag = crate::failover::report::status::REFUSED
        .iter()
        .position(|kind| format!("{kind:?}") == "Tag")
        .unwrap();
    let mut forged = fixture.sealed(2, &[]);
    let last = forged.len() - 1;
    forged[last] ^= 1;
    fixture.world.reports.insert(host(2), forged);
    let mut counts = Vec::new();
    for at in 0..3 {
        fixture.publish(1, &[]);
        fixture.publish(3, &[]);
        let part = (fixture.zone)
            .tick(
                Ok(fixture.directory()),
                &mut fixture.world,
                START + (200 + 10 * at) * S,
            )
            .part;
        counts.push(part.events.refused[tag]);
    }
    let mut again = fixture.world.reports[&host(2)].clone();
    let middle = again.len() / 2;
    again[middle] ^= 1;
    fixture.world.reports.insert(host(2), again.clone());
    let part = (fixture.zone)
        .tick(Ok(fixture.directory()), &mut fixture.world, START + 230 * S)
        .part;
    counts.push(part.events.refused[tag]);
    fixture.publish(2, &[]);
    tick(&mut fixture, START + 240 * S);
    fixture.world.reports.insert(host(2), again);
    fixture.publish(1, &[]);
    fixture.publish(3, &[]);
    let part = (fixture.zone)
        .tick(Ok(fixture.directory()), &mut fixture.world, START + 250 * S)
        .part;
    counts.push(part.events.refused[tag]);
    assert_eq!(
        counts,
        [1, 1, 1, 2, 3],
        "a body edit under the old tag counts, and an accepted report clears the digest"
    );
}

/// An instance listing with two differing rows for one tracked instance, and a volume listing with two differing
/// rows for one volume, each read as incomplete in the part, as the memories that drop them read them; a listing
/// with an identical repeated row reads complete.
#[test]
fn a_listing_the_memory_drops_reads_incomplete() {
    use crate::failover::zone_loop::evidence::{InstanceState, ListedVolumeState};
    let flags = |change: fn(&mut Fixture)| {
        let mut fixture = Fixture::new(3, 1);
        warm(&mut fixture, 12);
        change(&mut fixture);
        tick(&mut fixture, START + 200 * S).part.flags
    };
    let repeated = flags(|fixture| {
        let row = fixture.world.instances[0];
        fixture.world.instances.push(row);
    });
    assert!(repeated.instances && repeated.volumes);
    let instances = flags(|fixture| {
        let mut row = fixture.world.instances[0];
        row.state = InstanceState::Stopped;
        fixture.world.instances.push(row);
    });
    assert!(!instances.instances && instances.volumes);
    let volumes = flags(|fixture| {
        let mut row = fixture.world.volumes[0].clone();
        row.condition.state = ListedVolumeState::Error;
        fixture.world.volumes.push(row);
    });
    assert!(volumes.instances && !volumes.volumes);
    let attachments = flags(|fixture| {
        let mut row = fixture.world.volumes[0].clone();
        row.attachments.push("i-0000000000000fff".to_owned());
        fixture.world.volumes.push(row);
    });
    assert!(
        attachments.instances && !attachments.volumes,
        "rows that list other attachments conflict"
    );
    let reordered = flags(|fixture| {
        let mut row = fixture.world.volumes[0].clone();
        row.attachments.reverse();
        fixture.world.volumes.push(row);
    });
    assert!(
        reordered.volumes,
        "attachment order aside, a repeated row is the same row"
    );
}

/// The owner's serving entry decides its shard's class only on the shard's active volume: on the active volume
/// the shard reads served with no row, and the same entry naming another volume leaves it silent with a row.
#[test]
fn an_owner_entry_decides_only_on_the_active_volume() {
    use super::observe::{entry, owner_of};
    use crate::failover::serving::State;
    let class = |name: &str| {
        let mut fixture = Fixture::new(3, 1);
        warm(&mut fixture, 12);
        let owner = owner_of(1, 3).get();
        let mut client = Client::open(fixture.store.clone(), MemLog::default()).unwrap();
        let read = client
            .read::<ShardRecord>(Key::Shard(Shard::new(1).unwrap()))
            .unwrap();
        let serving = crate::failover::report::VolumeEntry {
            serving: Some(State::Serving),
            ..entry(
                name,
                1,
                read.value().generation.get(),
                read.value().attempts,
            )
        };
        let mut part = None;
        for at in 0..2 {
            for number in (1..=3).filter(|&n| n != owner) {
                fixture.publish(number, &[]);
            }
            fixture.publish(owner, &[serving]);
            let now = START + (200 + 10 * at) * S;
            part = Some(
                (fixture.zone)
                    .tick(Ok(fixture.directory()), &mut fixture.world, now)
                    .part,
            );
        }
        let part = part.unwrap();
        (
            class(&part, Class::Served),
            class(&part, Class::Silent),
            part.rows.len(),
        )
    };
    assert_eq!(class(volume(1).as_str()), (1, 0, 0));
    assert_eq!(class("vol-0a"), (0, 1, 1));
}

/// The status counts its store client's outcomes from the loop's construction: a client that tallied an
/// unavailable read before the loop took it reads no outcome on the loop's first ticks.
#[test]
fn store_outcomes_count_from_the_loop_s_construction() {
    use super::world::Recording;
    use crate::storage::store::sim::Arm as StoreArm;
    let mut fixture = Fixture::new(3, 1);
    let recording = Recording {
        inner: AsReconciler(fixture.store.clone()),
        log: fixture.world.log.clone(),
    };
    let mut prior = Reconciler::new(Client::open(recording, MemLog::default()).unwrap());
    fixture.store.schedule(StoreArm::Unavailable);
    assert!(
        prior
            .read::<ShardRecord>(Key::Shard(Shard::new(1).unwrap()))
            .is_err()
    );
    assert_eq!(
        prior
            .store_state()
            .1
            .total(crate::storage::store::Tallied::Unavailable),
        1
    );
    fixture.zone = crate::failover::zone_loop::ZoneLoop::new(prior, fixture.zone.bounds.clone());
    let part = tick(&mut fixture, START).part;
    assert_eq!(part.store.outcomes, [0; 4]);
}

/// The survey's warm-up hold reaches the part's flags: the first tick reads warm-up, and a tick after warm-up reads
/// every source complete and every hold clear.
#[test]
fn the_warm_up_hold_reaches_the_part_flags() {
    use crate::failover::report::status::Flags;
    let mut fixture = Fixture::new(3, 1);
    let first = tick(&mut fixture, START).part.flags;
    warm(&mut fixture, 12);
    let after = tick(&mut fixture, START + 200 * S).part.flags;
    let complete = Flags {
        reports: true,
        instances: true,
        volumes: true,
        store: true,
        ..Flags::default()
    };
    assert_eq!(after, complete);
    assert!(first.warm_up, "the first tick holds for warm-up");
    assert_eq!(first.store, complete.store);
}

/// STALE-SERVING through the tick: after a takeover raises the shard record's tenure, the predecessor's last serving
/// report, held unchanged, ages out before it counts, so every tick reads no stale entry; the same entry in reports
/// that keep advancing counts once it has been observed stale for longer than the fresh window.
/// A tick whose directory read fails adds zero to the stale count and preserves each stale entry's dwell: the ticks
/// after the failed read count one stale entry, matching the uninterrupted run.
#[test]
fn a_predecessor_s_last_serving_report_ages_out_before_it_counts() {
    use super::observe::{entry, owner_of};
    use crate::failover::serving::State;
    use crate::failover::zone_loop::sources::Unreachable;
    let stale = |advancing: bool, outage: Option<usize>| {
        let mut fixture = Fixture::new(3, 1);
        warm(&mut fixture, 12);
        let owner = owner_of(1, 3).get();
        let key = Key::Shard(Shard::new(1).unwrap());
        let mut client = Client::open(
            fixture.store.clone(),
            crate::storage::store::sim::MemLog::default(),
        )
        .unwrap();
        let read = client.read::<ShardRecord>(key).unwrap();
        let generation = read.value().generation.get();
        let serving = crate::failover::report::VolumeEntry {
            serving: Some(State::Serving),
            ..entry(volume(1).as_str(), 1, generation, read.value().attempts)
        };
        fixture.publish(owner, &[serving]);
        tick(&mut fixture, START + 200 * S);
        fixture.publish(owner, &[serving]);
        let mut counts = Vec::new();
        let mut now = START + 210 * S;
        let _ = (fixture.zone).tick(Ok(fixture.directory()), &mut fixture.world, now);
        let read = client.read::<ShardRecord>(key).unwrap();
        client.bump(&read).unwrap();
        for tick in 0..8 {
            now += 10 * S;
            for number in (1..=3).filter(|&n| n != owner) {
                fixture.publish(number, &[]);
            }
            if advancing {
                fixture.publish(owner, &[serving]);
            }
            let directory = match outage == Some(tick) {
                true => Err(Unreachable),
                false => Ok(fixture.directory()),
            };
            let part = (fixture.zone).tick(directory, &mut fixture.world, now).part;
            counts.push(part.stale_serving);
        }
        counts
    };
    assert_eq!(stale(false, None), [0; 8], "a held report ages out");
    let advancing = stale(true, None);
    assert_eq!(&advancing[..3], [0, 0, 0], "within the fresh window");
    assert_eq!(
        advancing[5..],
        [1, 1, 1],
        "a report that keeps claiming the lower tenure counts"
    );
    let interrupted = stale(true, Some(4));
    assert_eq!(
        interrupted[4], 0,
        "a tick without its directory counts nothing"
    );
    assert_eq!(
        interrupted[5..],
        advancing[5..],
        "the dwell continues across the failed directory read"
    );
}

/// The silent gauge at its bounds. A host reads silent while its one accepted report sets its baseline, and not
/// silent from the report after it. A host whose last report advance lies exactly the fresh window back still
/// reads fresh, and one microsecond later it reads silent.
#[test]
fn a_host_reads_silent_before_its_second_report_and_past_the_fresh_window() {
    use crate::failover::report::Members;
    let mut fixture = Fixture::new(3, 1);
    let silent = |fixture: &mut Fixture, publishing: &[u64], now_us: u64| {
        for &number in publishing {
            fixture.publish(number, &[]);
        }
        let directory = Ok(fixture.directory());
        let part = fixture
            .zone
            .tick(directory, &mut fixture.world, now_us)
            .part;
        part.hosts.silent
    };
    let of_three = |used| Members::Known { used, limit: 3 };
    assert_eq!(
        silent(&mut fixture, &[1, 2, 3], START),
        of_three(3),
        "each host's first report is its baseline"
    );
    assert_eq!(
        silent(&mut fixture, &[1, 2, 3], START + 10 * S),
        of_three(0)
    );
    let fresh = fixture.zone.bounds.fresh_us();
    let last = START + 10 * S;
    assert_eq!(
        silent(&mut fixture, &[1, 3], last + fresh),
        of_three(0),
        "an advance exactly the fresh window back is fresh"
    );
    assert_eq!(silent(&mut fixture, &[1, 3], last + fresh + 1), of_three(1));
}
