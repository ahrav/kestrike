use super::*;
use crate::failover::bounds::Bounds;
use crate::failover::loss::{Health, Receipt};
use crate::failover::records::{EventKind, Host, Record, ShardRecord, VolumeRecord};
use crate::failover::report::status::{
    ATTACHES, AttachOutcome, CLASSES, CREATES, Class, Create, DECISIONS, Decided, ENROLLMENTS,
    Enrollment, RECLAIMS, REFUSED, RESERVATIONS, Reclaim, Refused, Reservation, STANDBYS,
    STEP_ERRORS, Standby, StepError, ZonePart,
};
use crate::failover::report::tests::bare;
use crate::failover::report::{
    Gauge, Hold, HostReport, Members, Metadata, Phase, RecordedRole, ReportError, VolumeEntry,
};
use crate::failover::serving::State;
use crate::failover::sim::host;
use crate::failover::standbys::tests::report_of;
use crate::failover::standbys::{Closed, Need, Zone};
use crate::failover::zone_loop::evidence::{HostEvidence, VolumeJudgement};
use crate::failover::zone_loop::observe::{Completeness, HostView, ShardRecords, Source};
use crate::failover::zone_loop::status::{
    Blocker, EnrollPhase, Holds, ShardState, ShardStatus, VerdictCounts, ZoneStatus,
};
use crate::failover::zone_loop::tests::directory::entry;
use crate::net::ownership::{ActivatedEpoch, Shard};
use crate::storage::store::{Alarm, StoreError, Tally};
use crate::storage::store_tests::record;

const VOLUME_V3: &[u8] = include_bytes!("../fixtures/volume-v3.rec");

fn shard(number: u32) -> Shard {
    Shard::new(number).unwrap()
}

fn known(used: u64, limit: u64) -> Members {
    Members::Known { used, limit }
}

fn at_code<T: PartialEq>(table: &[T], value: T) -> usize {
    table.iter().position(|listed| *listed == value).unwrap()
}

pub(crate) fn zone_status(shards: Vec<ShardStatus>) -> ZoneStatus {
    ZoneStatus {
        shards,
        census: Some(3),
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

fn row(number: u32, state: ShardState, exposure_us: Option<u64>) -> ShardStatus {
    ShardStatus {
        shard: shard(number),
        state,
        blocker: None,
        target: None,
        closed: None,
        exposure_us,
        overdue: false,
    }
}

fn host_view(number: u64, verdict: HostEvidence, report: Option<HostReport>) -> HostView {
    HostView {
        entry: entry(number, 0),
        verdict,
        answered: true,
        report: report.map(std::sync::Arc::new),
    }
}

fn reported(number: u64, entries: Vec<VolumeEntry>) -> HostReport {
    let mut report = report_of(host(number), Gauge::Unavailable, Gauge::Unavailable);
    report.entries = entries;
    report
}

/// The records of shard `number`, owned by host 11 at `E = 1` on `active`, with `entries` as the accepted entries at
/// the record's tenure.
fn records(number: u32, active: VolumeRecord, entries: Vec<(Host, VolumeEntry)>) -> ShardRecords {
    ShardRecords {
        record: ShardRecord {
            shard: shard(number),
            owner: host(11),
            attempts: 1,
            spare: None,
            standby: None,
            ..record()
        },
        active,
        spare: None,
        receipt: None::<Receipt>,
        replacement: None,
        entries,
        held: None,
        judgement: VolumeJudgement {
            health: Some(Health::Available),
            others: 0,
            complete: true,
            streak: 0,
            confirmed: false,
        },
    }
}

/// Host 11's serving entry for shard `number` at `(g, 2)`, changed by `change`.
fn owner_entry(number: u32, change: impl FnOnce(&mut VolumeEntry)) -> (Host, VolumeEntry) {
    let mut entry = VolumeEntry {
        shard: shard(number),
        tenure: Some((record().generation, ActivatedEpoch::new(2).unwrap())),
        serving: Some(State::Serving),
        phase: Some(Phase::Serving),
        ..bare("vol-0a", RecordedRole::Owner)
    };
    change(&mut entry);
    (host(11), entry)
}

/// The stored format-3 volume fixture: live attaches of hosts 12 and 15, host 12's enrolled pair, host 13's ended
/// entry that its pair pins, and host 14's gone entry.
fn v3() -> VolumeRecord {
    <VolumeRecord as Record>::decode(VOLUME_V3).unwrap()
}

/// The fresh window the builder tests run under.
const FRESH_US: u64 = 1_000;

fn build(
    hosts: &[HostView],
    shards: &[(ShardStatus, Option<ShardRecords>)],
    memory: &mut Memory,
    bounds: &Bounds,
    now_us: u64,
) -> ZonePart {
    let fed: Vec<(&HostView, bool)> = hosts.iter().map(|view| (view, false)).collect();
    build_fed(&fed, shards, memory, bounds, now_us)
}

/// Builds one part from `hosts`, each beside whether its report is silent, and `shards`, none of whose
/// reservations the plan admitted.
fn build_fed(
    hosts: &[(&HostView, bool)],
    shards: &[(ShardStatus, Option<ShardRecords>)],
    memory: &mut Memory,
    bounds: &Bounds,
    now_us: u64,
) -> ZonePart {
    let mut status = zone_status(shards.iter().map(|(row, _)| *row).collect());
    let views: Vec<HostView> = hosts.iter().map(|(view, _)| (*view).clone()).collect();
    status.verdicts = Some(VerdictCounts::of(&views));
    let tally = Tally::default();
    let store = (Alarm::Clear, &tally);
    let clock = Clock {
        now_us,
        fresh_us: FRESH_US,
    };
    let fed = hosts.iter().copied();
    let mut builder = Builder::new((Zone(1), &status), fed, memory, bounds, store, clock);
    for (row, records) in shards {
        builder.shard(row, records.as_ref(), false);
    }
    builder.finish()
}

fn wide() -> Bounds {
    Bounds::new(8, 2, 100, 10, 20, 5).unwrap()
}

/// ONE-CLASSIFICATION: each survey state and owner entry gives its class. An owner entry that reads `unloadable`
/// is `blocked`, counted once and named by an exception row; its clean twin, a serving entry, is `served` with no
/// row.
#[test]
fn the_survey_and_the_owner_entry_give_each_serving_class() {
    let hosts = [host_view(
        11,
        HostEvidence::Live,
        Some(reported(11, vec![])),
    )];
    let class = |state: ShardState, entries: Vec<(Host, VolumeEntry)>| {
        let shards = [(row(1, state, None), Some(records(1, v3(), entries)))];
        let part = build(&hosts, &shards, &mut Memory::default(), &wide(), 5);
        assert_eq!(part.classes.iter().sum::<u32>(), 1);
        let at = part.classes.iter().position(|&n| n == 1).unwrap();
        let rows: Vec<Shard> = part.rows.iter().map(|row| row.shard).collect();
        (CLASSES[at], rows)
    };
    let unloadable = owner_entry(1, |e| e.metadata = Some(Metadata::Unloadable));
    assert_eq!(
        class(ShardState::Protected, vec![unloadable]),
        (Class::Blocked, vec![shard(1)])
    );
    assert_eq!(
        class(ShardState::Protected, vec![owner_entry(1, |_| {})]),
        (Class::Served, vec![])
    );
    let withdrawn = owner_entry(1, |e| e.serving = Some(State::Withdrawn));
    let recovering = owner_entry(1, |e| {
        e.serving = None;
        e.phase = Some(Phase::Recovering);
    });
    let held = owner_entry(1, |e| e.phase = Some(Phase::Held));
    let serving = owner_entry(1, |_| {});
    for (state, entries, expected) in [
        (ShardState::Protected, vec![withdrawn], Class::Withdrawn),
        (ShardState::Protected, vec![recovering], Class::Recovering),
        (ShardState::Protected, vec![held], Class::Blocked),
        (ShardState::Protected, vec![], Class::Silent),
        (ShardState::Initial, vec![], Class::Fresh),
        (ShardState::ReplacementHeld, vec![], Class::Cold),
        (ShardState::VolumeImpaired, vec![serving], Class::Blocked),
    ] {
        assert_eq!(class(state, entries).0, expected, "{state:?}");
    }
    let unread = ShardState::Unobserved(Source::Store(StoreError::Unavailable));
    let shards = [(row(1, unread, None), None)];
    let part = build(&hosts, &shards, &mut Memory::default(), &wide(), 5);
    assert_eq!(part.classes[at_code(CLASSES, Class::Silent)], 1);
    let lost = [host_view(11, HostEvidence::Lost, None)];
    let shards = [(
        row(1, ShardState::NoCandidate, Some(0)),
        Some(records(1, v3(), vec![])),
    )];
    let part = build(&lost, &shards, &mut Memory::default(), &wide(), 5);
    assert_eq!(part.classes[at_code(CLASSES, Class::Fresh)], 1);
    assert_eq!(part.needs, [0, 1], "a lost owner needs a fresh host");
    let held_tenure = owner_entry(1, |e| {
        e.serving = Some(State::Withdrawn);
        e.phase = None;
        e.hold = Some(Hold::Held);
    });
    let released = owner_entry(1, |e| {
        e.serving = Some(State::Withdrawn);
        e.phase = None;
        e.hold = Some(Hold::Clear);
    });
    for (entries, expected) in [
        (vec![held_tenure], Class::Blocked),
        (vec![released], Class::Withdrawn),
    ] {
        assert_eq!(class(ShardState::Protected, entries).0, expected);
    }
}

/// RECORD-LOSS in the need counts: the part counts the need the plan schedules, which `standbys::need_of` judges
/// over the active volume's record. With hosts 12, 13 and 15 live, an owner whose attach ended needs a fresh host
/// and a named standby whose attach ended needs a standby; with both attaches live the shard counts in neither slot,
/// and a record of another volume leaves the count to the hosts' verdicts.
#[test]
fn an_ended_attach_of_the_active_volume_counts_as_the_need_the_plan_schedules() {
    let live = |number| host_view(number, HostEvidence::Live, Some(reported(number, vec![])));
    let hosts = [live(12), live(13), live(15)];
    let needs = |owner: u64, standby: Option<u64>, active: VolumeRecord| {
        let mut held = records(1, active, vec![]);
        held.record.owner = host(owner);
        held.record.standby = standby.map(host);
        let shards = [(row(1, ShardState::Protected, None), Some(held))];
        build(&hosts, &shards, &mut Memory::default(), &wide(), 5).needs
    };
    let active = || VolumeRecord {
        volume: record().active,
        ..v3()
    };
    assert_eq!(needs(12, Some(15), active()), [0, 0], "both attaches live");
    assert_eq!(needs(12, Some(13), active()), [1, 0], "the standby's ended");
    assert_eq!(needs(13, None, active()), [0, 1], "the owner's ended");
    assert_eq!(
        needs(13, Some(15), active()),
        [0, 0],
        "a live standby covers"
    );
    assert_ne!(v3().volume, record().active);
    assert_eq!(needs(13, None, v3()), [1, 0], "another volume's record");
}

/// A lost owner outranks its cached serving entry and reads `fresh`; an owner whose report is silent reads `silent`
/// beside its cached serving entry; the same entry from a fresh report reads `served`, with the owner's verdict
/// unknown, as a failed instance listing leaves it.
#[test]
fn an_owner_entry_decides_only_while_the_owner_report_is_fresh() {
    let class = |verdict: HostEvidence, silent: bool| {
        let owner = host_view(11, verdict, Some(reported(11, vec![])));
        let records = records(1, v3(), vec![owner_entry(1, |_| {})]);
        let shards = [(row(1, ShardState::Protected, None), Some(records))];
        let part = build_fed(
            &[(&owner, silent)],
            &shards,
            &mut Memory::default(),
            &wide(),
            5,
        );
        let at = part.classes.iter().position(|&n| n == 1).unwrap();
        let rows: Vec<Class> = part.rows.iter().map(|row| row.class).collect();
        (CLASSES[at], rows)
    };
    assert_eq!(
        class(HostEvidence::Lost, false),
        (Class::Fresh, vec![Class::Fresh])
    );
    assert_eq!(
        class(HostEvidence::Live, true),
        (Class::Silent, vec![Class::Silent])
    );
    assert_eq!(class(HostEvidence::Live, false), (Class::Served, vec![]));
    assert_eq!(class(HostEvidence::Unknown, false), (Class::Served, vec![]));
}

/// A held restart's diagnostic entry in the owner's fresh report reads `blocked` at the record's tenure and one
/// attempt above the read, with the owner live, in conflict or unknown, as a failed instance listing leaves it; the
/// survey's match, which needs a live owner, is absent in the last two. A silent report reads `silent`, a lost owner
/// `fresh`, and an entry two attempts below the record or for another volume decides nothing.
#[test]
fn a_held_restart_entry_in_the_owner_s_fresh_report_reads_blocked_under_each_verdict_but_lost() {
    let read = records(1, v3(), vec![]).record;
    let entry = crate::host::agent::tests::held_final(&read, 7)
        .entry
        .unwrap();
    assert!(entry.held_restart());
    let class = |verdict: HostEvidence, silent: bool, bumps: u32, entry: VolumeEntry| {
        let owner = host_view(11, verdict, Some(reported(11, vec![entry])));
        let mut records = records(1, v3(), vec![]);
        records.record.attempts += bumps;
        let matched = verdict == HostEvidence::Live && bumps < 2 && entry.volume == read.active;
        records.held = matched.then_some((host(11), entry));
        let shards = [(row(1, ShardState::Protected, None), Some(records))];
        let fed = [(&owner, silent)];
        let part = build_fed(&fed, &shards, &mut Memory::default(), &wide(), 5);
        CLASSES[part.classes.iter().position(|&n| n == 1).unwrap()]
    };
    for verdict in [
        HostEvidence::Live,
        HostEvidence::Conflict,
        HostEvidence::Unknown,
    ] {
        for bumps in [0, 1] {
            assert_eq!(
                class(verdict, false, bumps, entry),
                Class::Blocked,
                "{verdict:?}, {bumps} bumps"
            );
        }
        assert_eq!(class(verdict, true, 0, entry), Class::Silent, "{verdict:?}");
        assert_eq!(
            class(verdict, false, 2, entry),
            Class::Silent,
            "{verdict:?}"
        );
        let elsewhere = VolumeEntry {
            volume: v3().volume,
            ..entry
        };
        assert_ne!(elsewhere.volume, read.active);
        assert_eq!(
            class(verdict, false, 0, elsewhere),
            Class::Silent,
            "{verdict:?}"
        );
    }
    assert_eq!(class(HostEvidence::Lost, false, 0, entry), Class::Fresh);
}

/// Every survey state that fixes a class gives it, and every other state leaves the class to the owner's entry.
#[test]
fn each_survey_state_fixes_its_class_or_defers_to_the_entry() {
    use crate::failover::loss::Phase as ReceiptPhase;
    let enrolling = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Reserved,
        host: host(12),
    };
    let unread = ShardState::Unobserved(Source::Store(StoreError::Unavailable));
    for (state, class) in [
        (ShardState::Protected, None),
        (ShardState::Initial, Some(Class::Fresh)),
        (enrolling, None),
        (ShardState::NoCandidate, None),
        (ShardState::Closed, None),
        (ShardState::StandbyUnknown, None),
        (ShardState::OwnerUnknown, None),
        (ShardState::VolumeImpaired, Some(Class::Blocked)),
        (ShardState::LossUnconfirmed, Some(Class::Blocked)),
        (
            ShardState::Replacing {
                phase: ReceiptPhase::Open,
            },
            Some(Class::Cold),
        ),
        (ShardState::ReplacementHeld, Some(Class::Cold)),
        (ShardState::ReplacementExhausted, Some(Class::Cold)),
        (ShardState::RetirementRequested, Some(Class::Blocked)),
        (unread, Some(Class::Silent)),
    ] {
        assert_eq!(state.class(), class, "{state:?}");
    }
}

fn silent_shards(
    numbers: core::ops::RangeInclusive<u32>,
) -> Vec<(ShardStatus, Option<ShardRecords>)> {
    let silent = |n| {
        let records = records(n, v3(), vec![]);
        (row(n, ShardState::Protected, None), Some(records))
    };
    numbers.map(silent).collect()
}

/// Forty shards outside the served class in one zone keep thirty-two rows, oldest first and then by shard, and
/// count eight omitted; a row's age counts from the first tick that observed the shard in its class and restarts
/// when the class changes.
#[test]
fn forty_shards_outside_the_served_class_keep_thirty_two_rows_oldest_first() {
    let hosts = [host_view(
        11,
        HostEvidence::Live,
        Some(reported(11, vec![])),
    )];
    let mut memory = Memory::default();
    build(&hosts, &silent_shards(1..=20), &mut memory, &wide(), 100);
    let all = silent_shards(1..=40);
    let part = build(&hosts, &all, &mut memory, &wide(), 300);
    assert_eq!((part.rows.len(), part.omitted), (MAX_ROWS, 8));
    assert_eq!(part.classes[at_code(CLASSES, Class::Silent)], 40);
    let order: Vec<(u64, u32)> = (part.rows.iter())
        .map(|row| (row.age_us, row.shard.get()))
        .collect();
    let expected: Vec<(u64, u32)> = (1..=20)
        .map(|n| (200, n))
        .chain((21..=32).map(|n| (0, n)))
        .collect();
    assert_eq!(order, expected);
    let mut changed = all;
    let held = owner_entry(1, |e| e.phase = Some(Phase::Held));
    changed[0].1 = Some(records(1, v3(), vec![held]));
    let part = build(&hosts, &changed, &mut memory, &wide(), 400);
    let blocked = part.rows.iter().find(|row| row.shard == shard(1));
    assert_eq!(blocked, None, "a new class restarts the age");
    assert_eq!(part.classes[at_code(CLASSES, Class::Blocked)], 1);
    assert_eq!(part.omitted, 8);
}

/// The volume-record gauges, a reclaim outcome and a `Closed` cause each count once under their own name: the v3
/// fixture's ended entry that a pair pins and its gone entry, the same record with that pair dropped (an end
/// awaiting its detach), a `detach-unknown` reclaim step, and a closed shard's cause. The builder counts the cause
/// the survey's row carries and keeps the record and bounds fixed: over the v3 fixture under wide bounds a closed row
/// counts `own-entry` or `key-taken` as the row names it; a closed row with no cause, over the record at the pair
/// cap, counts in no cell; and a row in another state counts its cause in no cell. Each row's `attach-closed`
/// blocker counts once beside it.
#[test]
fn volume_gauges_reclaim_outcomes_and_closed_causes_count_once_each() {
    let hosts: Vec<HostView> = (11..=15)
        .map(|n| host_view(n, HostEvidence::Live, None))
        .collect();
    let mut unpaired = v3();
    unpaired.pairs.retain(|held| held.host != host(13));
    let mut memory = Memory::default();
    memory.events.reclaimed(Reclaim::DetachUnknown);
    let narrow = Bounds::new(2, 2, 100, 10, 20, 5).unwrap();
    let closed = ShardStatus {
        closed: Some(Closed::PairCap),
        blocker: Some(Blocker::AttachClosed),
        ..row(2, ShardState::Closed, Some(0))
    };
    let shards = [
        (
            row(1, ShardState::Protected, None),
            Some(records(1, v3(), vec![])),
        ),
        (closed, Some(records(2, unpaired, vec![]))),
    ];
    let part = build(&hosts, &shards, &mut memory, &narrow, 5);
    let a = part.attaches;
    assert_eq!(
        (a.live, a.ended_paired, a.ended_unpaired, a.gone),
        (4, 1, 1, 2)
    );
    assert_eq!(a.pairs, known(3, 4));
    assert_eq!(a.closed, [0, 0, 1, 0, 0]);
    assert_eq!(part.blockers[Blocker::AttachClosed.position()], 1);
    let reclaims = part.events.reclaims;
    assert_eq!(reclaims[at_code(RECLAIMS, Reclaim::DetachUnknown)], 1);
    assert_eq!(reclaims.iter().sum::<u32>(), 1);
    let mut at_cap = v3();
    at_cap.pairs.retain(|held| held.host != host(13));
    for (state, cause, volume, bounds, cells) in [
        (
            ShardState::Closed,
            Some(Closed::OwnEntry),
            v3(),
            wide(),
            [0, 0, 0, 1, 0],
        ),
        (
            ShardState::Closed,
            Some(Closed::KeyTaken),
            v3(),
            wide(),
            [0, 0, 0, 0, 1],
        ),
        (ShardState::Closed, None, at_cap, narrow, [0; 5]),
        (
            ShardState::NoCandidate,
            Some(Closed::OwnEntry),
            v3(),
            wide(),
            [0; 5],
        ),
    ] {
        let fed = ShardStatus {
            state,
            closed: cause,
            ..closed
        };
        let shards = [(fed, Some(records(2, volume, vec![])))];
        let part = build(&hosts, &shards, &mut memory, &bounds, 5);
        assert_eq!(part.attaches.closed, cells, "{state:?} {cause:?}");
        assert_eq!(
            part.blockers[Blocker::AttachClosed.position()],
            1,
            "{state:?} {cause:?}"
        );
    }
    let mut detached = v3();
    detached.push(EventKind::Detach, host(12), 0).unwrap();
    let shards = [(
        row(1, ShardState::Protected, None),
        Some(records(1, detached, vec![])),
    )];
    let part = build(&hosts, &shards, &mut Memory::default(), &wide(), 5);
    assert_eq!(
        part.attaches.ended_paired, 1,
        "a pair pinning an attach that a detach ended is no ended entry"
    );
    // Host 13 attaches again and that attach ends: its pair still pins the earlier ended entry, and the later one
    // awaits its detach. The counts are independent of which hosts `build` receives.
    let mut again = v3();
    again.push(EventKind::Attach, host(13), 0).unwrap();
    again.push(EventKind::Ended, host(13), 0).unwrap();
    let shards = [(
        row(1, ShardState::Protected, None),
        Some(records(1, again, vec![])),
    )];
    let listed = build(&hosts, &shards, &mut Memory::default(), &wide(), 5).attaches;
    let others: Vec<HostView> = (hosts.iter().filter(|view| view.entry.host != host(13)))
        .cloned()
        .collect();
    let paired = build(&others, &shards, &mut Memory::default(), &wide(), 5).attaches;
    let unlisted = build(&[], &shards, &mut Memory::default(), &wide(), 5).attaches;
    for (fed, attaches) in [(5, listed), (4, paired), (0, unlisted)] {
        assert_eq!(
            (
                attaches.ended_paired,
                attaches.ended_unpaired,
                attaches.gone
            ),
            (1, 1, 1),
            "{fed} hosts fed"
        );
    }
}

/// A volume holding more recorded pairs than the pair cap reads its pairs beside the cap, and the part seals and
/// accepts with both values unchanged.
#[test]
fn pairs_above_the_pair_cap_read_beside_the_cap() {
    let hosts = [host_view(11, HostEvidence::Live, None)];
    let tight = Bounds::new(1, 2, 100, 10, 20, 5).unwrap();
    let shards = [(
        row(1, ShardState::Protected, None),
        Some(records(1, v3(), vec![])),
    )];
    let part = build(&hosts, &shards, &mut Memory::default(), &tight, 5);
    let cap = tight.pair_cap() as u64;
    assert_eq!(part.attaches.pairs, known(2, cap));
    assert!(cap < 2, "the fixture's two pairs exceed the cap");
    let bytes = crate::failover::report::status::tests::sealed(std::slice::from_ref(&part));
    let accepted = crate::failover::report::status::StatusReader::default()
        .accept(&bytes, crate::failover::report::status::tests::key_of)
        .unwrap();
    assert_eq!(accepted.zones[0].attaches.pairs, known(2, cap));
}

/// STALE-SERVING: a fresh entry of host 12 that reads serving at `(g, 2)` while the shard record stands at `(g, 4)`
/// is stale from the first tick and counts once it has been stale for longer than the fresh window, its age growing
/// across ticks, whatever the host's verdict. Its clean twins count nothing: the same entry withdrawn, the same entry
/// from a silent report, the same entry at the record's own tenure, and an entry of another shard.
#[test]
fn a_serving_entry_below_the_record_s_tenure_reads_stale() {
    let stale =
        |change: fn(&mut VolumeEntry), verdict: HostEvidence, silent: bool, attempts: u32| {
            let (_, entry) = owner_entry(1, change);
            let owner = host_view(11, HostEvidence::Live, Some(reported(11, vec![])));
            let other = host_view(12, verdict, Some(reported(12, vec![entry])));
            let mut records = records(1, v3(), vec![]);
            records.record.attempts = attempts;
            let shards = [(row(1, ShardState::Protected, None), Some(records))];
            let mut memory = Memory::default();
            let fed = [(&owner, false), (&other, silent)];
            let first = build_fed(&fed, &shards, &mut memory, &wide(), 1_000);
            let at_window = build_fed(&fed, &shards, &mut memory, &wide(), 1_000 + FRESH_US);
            let later = build_fed(&fed, &shards, &mut memory, &wide(), 4_000);
            let counts = [
                first.stale_serving,
                at_window.stale_serving,
                later.stale_serving,
            ];
            (counts, later.stale_oldest_us)
        };
    let live = HostEvidence::Live;
    assert_eq!(stale(|_| {}, live, false, 2), ([0, 0, 1], Some(3_000)));
    for verdict in [HostEvidence::Conflict, HostEvidence::Unknown] {
        assert_eq!(
            stale(|_| {}, verdict, false, 2),
            ([0, 0, 1], Some(3_000)),
            "{verdict:?}"
        );
    }
    let withdrawn: fn(&mut VolumeEntry) = |e| e.serving = Some(State::Withdrawn);
    assert_eq!(stale(withdrawn, live, false, 2), ([0; 3], None));
    assert_eq!(
        stale(|_| {}, live, true, 2),
        ([0; 3], None),
        "a silent report"
    );
    assert_eq!(
        stale(|_| {}, live, false, 1),
        ([0; 3], None),
        "the record's own tenure"
    );
    let other_shard: fn(&mut VolumeEntry) = |e| e.shard = Shard::new(2).unwrap();
    assert_eq!(
        stale(other_shard, live, false, 2),
        ([0; 3], None),
        "another shard"
    );
}

/// A shard the tick could not read reads `silent` and keeps the class and first-observed time it held when last read,
/// so its row's age resumes when a later tick reads it in that class; its stale entry stays uncounted on the unread
/// tick and keeps its first-observed time.
/// The stale entry keeps that time whether the unread tick feeds the builder both hosts or no host.
#[test]
fn an_unread_shard_keeps_its_class_age_and_stale_entry() {
    let (_, stale_entry) = owner_entry(1, |_| {});
    let owner = host_view(11, HostEvidence::Live, Some(reported(11, vec![])));
    let other = host_view(
        12,
        HostEvidence::Live,
        Some(reported(12, vec![stale_entry])),
    );
    let fed = [(&owner, false), (&other, false)];
    let mut blocked = records(
        1,
        v3(),
        vec![owner_entry(1, |e| e.phase = Some(Phase::Held))],
    );
    blocked.record.attempts = 2;
    let read = [(row(1, ShardState::Protected, None), Some(blocked))];
    let unread = ShardState::Unobserved(Source::Store(StoreError::Unavailable));
    let gap = [(row(1, unread, None), None)];
    for viewed in [&fed[..], &[]] {
        let mut memory = Memory::default();
        let first = build_fed(&fed, &read, &mut memory, &wide(), 1_000);
        assert_eq!(
            (first.rows[0].class, first.rows[0].age_us),
            (Class::Blocked, 0)
        );
        let missed = build_fed(viewed, &gap, &mut memory, &wide(), 2_500);
        assert_eq!(missed.rows[0].class, Class::Silent);
        assert_eq!(
            missed.stale_serving, 0,
            "an unread shard counts no stale entry"
        );
        let back = build_fed(&fed, &read, &mut memory, &wide(), 4_000);
        assert_eq!(
            (back.rows[0].class, back.rows[0].age_us),
            (Class::Blocked, 3_000)
        );
        assert_eq!(
            (back.stale_serving, back.stale_oldest_us),
            (1, Some(3_000)),
            "{} hosts fed on the unread tick",
            viewed.len()
        );
    }
}

/// A stale claim's dwell belongs to its claimed tenure: a host that claims `(g, 2)` against the record's `(g, 4)`,
/// then serves `(g, 4)` through a tick that cannot read the shard, starts a new dwell when the record reads `(g, 6)`
/// and counts nothing more than the fresh window after its first claim; its twin keeps claiming `(g, 2)` and counts.
/// A claim carried across two unread ticks keeps its first-observed time, and so does the shard's class age.
#[test]
fn a_stale_dwell_belongs_to_its_claimed_tenure() {
    let at = |attempts: u32| {
        owner_entry(1, |e| {
            e.tenure = Some((
                record().generation,
                ActivatedEpoch::new(2 * attempts).unwrap(),
            ))
        })
        .1
    };
    let dwell = |claims: [u32; 3]| {
        let owner = host_view(11, HostEvidence::Live, Some(reported(11, vec![])));
        let mut memory = Memory::default();
        let unread = ShardState::Unobserved(Source::Store(StoreError::Unavailable));
        let mut counts = Vec::new();
        for (tick, (claim, attempts)) in claims.into_iter().zip([2, 0, 3]).enumerate() {
            let other = host_view(12, HostEvidence::Live, Some(reported(12, vec![at(claim)])));
            let fed = [(&owner, false), (&other, false)];
            let shards = if attempts == 0 {
                vec![(row(1, unread, None), None)]
            } else {
                let mut records = records(
                    1,
                    v3(),
                    vec![owner_entry(1, |e| e.phase = Some(Phase::Held))],
                );
                records.record.attempts = attempts;
                vec![(row(1, ShardState::Protected, None), Some(records))]
            };
            let now = [1_000, 1_500, 1_000 + 2 * FRESH_US][tick];
            counts.push(build_fed(&fed, &shards, &mut memory, &wide(), now).stale_serving);
        }
        counts
    };
    assert_eq!(
        dwell([1, 2, 2]),
        [0, 0, 0],
        "a new claimed tenure starts a new dwell"
    );
    assert_eq!(
        dwell([1, 1, 1]),
        [0, 0, 1],
        "the same claim carried across the unread tick counts"
    );
    let owner = host_view(11, HostEvidence::Live, Some(reported(11, vec![])));
    let fed = [(&owner, false)];
    let mut blocked = records(
        1,
        v3(),
        vec![owner_entry(1, |e| e.phase = Some(Phase::Held))],
    );
    blocked.record.attempts = 1;
    let read = [(row(1, ShardState::Protected, None), Some(blocked))];
    let unread = ShardState::Unobserved(Source::Store(StoreError::Unavailable));
    let gap = [(row(1, unread, None), None)];
    let mut memory = Memory::default();
    build_fed(&fed, &read, &mut memory, &wide(), 100);
    build_fed(&fed, &gap, &mut memory, &wide(), 200);
    build_fed(&fed, &gap, &mut memory, &wide(), 300);
    let back = build_fed(&fed, &read, &mut memory, &wide(), 400);
    assert_eq!(
        (back.rows[0].class, back.rows[0].age_us),
        (Class::Blocked, 300)
    );
}

/// A self-suspecting host counts while its report is fresh, whatever its verdict, and stops counting once its
/// report is silent.
#[test]
fn a_self_suspecting_host_counts_while_its_report_is_fresh() {
    let mut report = reported(12, vec![]);
    report.host.detector.self_suspect_us = Some(5);
    let count = |verdict: HostEvidence, silent: bool| {
        let view = host_view(12, verdict, Some(report.clone()));
        build_fed(&[(&view, silent)], &[], &mut Memory::default(), &wide(), 5)
            .hosts
            .self_suspect
    };
    for verdict in [
        HostEvidence::Live,
        HostEvidence::Conflict,
        HostEvidence::Unknown,
    ] {
        assert_eq!(count(verdict, false), 1, "{verdict:?}");
        assert_eq!(count(verdict, true), 0, "{verdict:?} silent");
    }
}

/// Each owner entry cell gives its class: parked reads blocked, a closed serving state or a closing or withdrawn
/// phase reads withdrawn, a serving phase with no serving state reads served, and any other phase reads recovering.
#[test]
fn each_owner_entry_cell_gives_its_class() {
    let hosts = [host_view(
        11,
        HostEvidence::Live,
        Some(reported(11, vec![])),
    )];
    let class = |change: fn(&mut VolumeEntry)| {
        let shards = [(
            row(1, ShardState::Protected, None),
            Some(records(1, v3(), vec![owner_entry(1, change)])),
        )];
        let part = build(&hosts, &shards, &mut Memory::default(), &wide(), 5);
        CLASSES[part.classes.iter().position(|&n| n == 1).unwrap()]
    };
    type Change = fn(&mut VolumeEntry);
    let cells: [(Change, Class); 6] = [
        (|e| e.phase = Some(Phase::Parked), Class::Blocked),
        (|e| e.serving = Some(State::Closed), Class::Withdrawn),
        (
            |e| {
                e.serving = None;
                e.phase = Some(Phase::Closing)
            },
            Class::Withdrawn,
        ),
        (
            |e| {
                e.serving = None;
                e.phase = Some(Phase::Withdrawn)
            },
            Class::Withdrawn,
        ),
        (
            |e| {
                e.serving = None;
                e.phase = Some(Phase::Serving)
            },
            Class::Served,
        ),
        (
            |e| {
                e.serving = None;
                e.phase = Some(Phase::Starting)
            },
            Class::Recovering,
        ),
    ];
    for (change, expected) in cells {
        assert_eq!(class(change), expected);
    }
}

/// A host the directory retires adds to neither the silent hosts nor their population; a silent host that it does
/// not retire adds to both.
#[test]
fn a_retired_host_is_outside_the_silent_gauge() {
    let mut retired = host_view(13, HostEvidence::Lost, None);
    retired.entry = entry(13, 0);
    retired.entry.state = crate::failover::zone_loop::directory::DirectoryState::Retired;
    let silent = host_view(14, HostEvidence::Unknown, None);
    let live = host_view(11, HostEvidence::Live, Some(reported(11, vec![])));
    let fed = [(&live, false), (&retired, true), (&silent, true)];
    let part = build_fed(&fed, &[], &mut Memory::default(), &wide(), 5);
    assert_eq!(part.hosts.silent, known(1, 2));
    assert_eq!(part.hosts.verdicts, [1, 1, 0, 1]);
}

/// Each standby state counts under its name: a live named standby, an enrollment, an exposure within and past the
/// target, and an unknown standby; a shard that needs none counts in no standby slot and its row reads `unneeded`.
#[test]
fn each_standby_state_counts_under_its_name() {
    let hosts = [host_view(11, HostEvidence::Live, None)];
    let enrolling = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Reserved,
        host: host(12),
    };
    let mut past = row(4, ShardState::NoCandidate, Some(9));
    past.overdue = true;
    past.blocker = Some(Blocker::CensusFull);
    let impaired = |number: u32, attempts: u32| {
        let mut status = row(number, ShardState::VolumeImpaired, Some(9));
        status.overdue = true;
        let mut records = records(number, v3(), vec![]);
        records.record.attempts = attempts;
        (status, Some(records))
    };
    let shards = [
        (row(1, ShardState::Protected, None), None),
        (row(2, enrolling, Some(1)), None),
        (row(3, ShardState::NoCandidate, Some(1)), None),
        (past, None),
        (row(5, ShardState::StandbyUnknown, Some(1)), None),
        (row(6, ShardState::Initial, None), None),
        impaired(7, 0),
        impaired(8, 1),
    ];
    let part = build(&hosts, &shards, &mut Memory::default(), &wide(), 5);
    assert_eq!(part.standby, [1, 1, 1, 2, 1]);
    assert_eq!(part.blockers[Blocker::CensusFull.position()], 1);
    let standbys: Vec<(u32, Standby)> = (part.rows.iter())
        .map(|row| (row.shard.get(), row.standby))
        .collect();
    assert!(standbys.contains(&(4, Standby::Past)));
    assert!(standbys.contains(&(6, Standby::Unneeded)));
    assert!(
        standbys.contains(&(7, Standby::Unneeded)),
        "an overdue impaired shard at E = 0: {standbys:?}"
    );
    assert!(
        standbys.contains(&(8, Standby::Past)),
        "an overdue impaired shard at E = 1: {standbys:?}"
    );
}

/// A served shard with no standby past its target takes an exception row that reads `served` and `past`, aged from
/// the first tick that observed it past; its control, the same shard within its target, counts as served with no
/// row, and a shard that falls back within its target and past it again starts a new age. The survey's blocker of
/// the served shard counts on every tick.
#[test]
fn a_served_shard_past_its_standby_target_takes_a_row() {
    let hosts = [host_view(
        11,
        HostEvidence::Live,
        Some(reported(11, vec![])),
    )];
    let tick = |overdue: bool, memory: &mut Memory, now_us: u64| {
        let mut status = row(1, ShardState::NoCandidate, Some(9));
        status.overdue = overdue;
        status.blocker = Some(Blocker::NoEligibleHost);
        let records = records(1, v3(), vec![owner_entry(1, |_| {})]);
        let part = build(&hosts, &[(status, Some(records))], memory, &wide(), now_us);
        assert_eq!(part.classes[at_code(CLASSES, Class::Served)], 1);
        assert_eq!(
            (
                part.blockers[Blocker::NoEligibleHost.position()],
                part.blockers.iter().sum::<u32>()
            ),
            (1, 1),
            "a served shard's blocker counts"
        );
        let expected = if overdue {
            Standby::Past
        } else {
            Standby::Within
        };
        assert_eq!(part.standby[at_code(STANDBYS, expected)], 1);
        part.rows
    };
    let past = |age_us| ExceptionRow {
        shard: shard(1),
        class: Class::Served,
        standby: Standby::Past,
        age_us,
    };
    let mut memory = Memory::default();
    assert_eq!(tick(false, &mut memory, 5), vec![], "within its target");
    assert_eq!(tick(true, &mut memory, 7), vec![past(0)]);
    assert_eq!(tick(true, &mut memory, 12), vec![past(5)]);
    assert_eq!(
        tick(false, &mut memory, 13),
        vec![],
        "back within its target"
    );
    assert_eq!(tick(true, &mut memory, 20), vec![past(0)]);
    let enrolling = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Reserved,
        host: host(12),
    };
    let mut status = row(1, enrolling, Some(9));
    status.overdue = true;
    let records = records(1, v3(), vec![owner_entry(1, |_| {})]);
    let shards = [(status, Some(records))];
    let part = build(&hosts, &shards, &mut Memory::default(), &wide(), 5);
    assert_eq!(part.classes[at_code(CLASSES, Class::Served)], 1);
    assert_eq!(part.standby[at_code(STANDBYS, Standby::Enrolling)], 1);
    assert_eq!(
        (part.rows.len(), part.omitted),
        (0, 0),
        "an enrollment that holds the census slot reads enrolling past the target"
    );
}

/// A replacement receipt counts under its phase, open, issued or created, and as held while an operator hold stands,
/// only at a later generation than its shard record's; its clean twin at the record's own generation, a replacement
/// the record already holds, counts in no receipt slot.
#[test]
fn a_receipt_counts_only_at_a_later_generation_than_its_record() {
    let counted = |later: bool, held: bool| {
        let mut records = records(1, v3(), vec![]);
        let mut receipt = crate::failover::loss::tests::receipt();
        assert!(receipt.request.generation > records.record.generation);
        if !later {
            receipt.request.generation = records.record.generation;
        }
        receipt.held = held;
        records.receipt = Some(receipt);
        let shards = [(row(1, ShardState::Protected, None), Some(records))];
        build(&[], &shards, &mut Memory::default(), &wide(), 5).receipts
    };
    assert_eq!(counted(true, false), [1, 0, 0, 0]);
    assert_eq!(counted(true, true), [1, 0, 0, 1]);
    assert_eq!(counted(false, false), [0, 0, 0, 0]);
    assert_eq!(counted(false, true), [0, 0, 0, 0]);
    let in_phase = |phase: crate::failover::loss::Phase| {
        let mut records = records(1, v3(), vec![]);
        let mut receipt = crate::failover::loss::tests::receipt();
        receipt.phase = phase;
        records.receipt = Some(receipt);
        let shards = [(row(1, ShardState::Protected, None), Some(records))];
        build(&[], &shards, &mut Memory::default(), &wide(), 5).receipts
    };
    use crate::failover::loss::Phase as ReceiptPhase;
    assert_eq!(in_phase(ReceiptPhase::Issued), [0, 1, 0, 0]);
    let created = ReceiptPhase::Created(v3().volume);
    assert_eq!(in_phase(created), [0, 0, 1, 0]);
}

/// An enrollment that holds no census slot reads `enrolling` only on a tick whose plan admitted its reservation;
/// withheld past the standby target it reads `past`, and within it `within`.
#[test]
fn a_withheld_reservation_reads_by_its_exposure() {
    let unreserved = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Unreserved,
        host: host(12),
    };
    let mut overdue = row(1, unreserved, Some(9));
    overdue.overdue = true;
    let within = row(1, unreserved, Some(1));
    let standby = |status: ShardStatus, reserved: bool| {
        let tally = Tally::default();
        let zone = zone_status(vec![status]);
        let mut memory = Memory::default();
        let bounds = wide();
        let clock = Clock {
            now_us: 5,
            fresh_us: FRESH_US,
        };
        let store = (Alarm::Clear, &tally);
        let mut builder = Builder::new((Zone(1), &zone), [], &mut memory, &bounds, store, clock);
        builder.shard(&status, None, reserved);
        builder.finish().standby
    };
    assert_eq!(standby(overdue, false), [0, 0, 0, 1, 0]);
    assert_eq!(standby(within, false), [0, 0, 1, 0, 0]);
    assert_eq!(standby(overdue, true), [0, 1, 0, 0, 0]);
}

/// Each fed step result counts once under its label, a duplicate report and a retained volume count nothing, and
/// the part carries the memory's counts.
#[test]
fn each_step_result_counts_once_under_its_label() {
    use crate::failover::loss::{CreateError, Decision};
    use crate::failover::reconcile::{ReconcileError, StandbyRefusal};
    use crate::failover::standbys::Refusal;
    let mut memory = Memory::default();
    let e = &mut memory.events;
    e.refused(ReportError::Tag);
    e.refused(ReportError::Duplicate);
    e.refused(ReportError::Schema { found: 2 });
    e.foreign();
    e.reserved(Ok(()));
    e.reserved(Err(Refusal::Full));
    e.enrollment_refused(&StandbyRefusal::Tenure);
    e.decided(Decision::Retain);
    e.decided(Decision::Hold(None));
    e.failed(ReconcileError::Held);
    e.created(&Err::<(), _>(CreateError::Unknown));
    e.attached(AttachOutcome::Failed);
    let part = build(&[], &[], &mut memory, &wide(), 5);
    let e = part.events;
    let one = |table: &[u32], at: usize| table[at] == 1 && table.iter().sum::<u32>() == 1;
    assert_eq!(e.refused.iter().sum::<u32>(), 3);
    for kind in [Refused::Tag, Refused::Schema, Refused::Foreign] {
        assert_eq!(e.refused[at_code(REFUSED, kind)], 1, "{kind:?}");
    }
    assert_eq!(e.reservations.iter().sum::<u32>(), 2);
    assert_eq!(
        e.reservations[at_code(RESERVATIONS, Reservation::Reserved)],
        1
    );
    assert_eq!(e.reservations[at_code(RESERVATIONS, Reservation::Full)], 1);
    assert!(one(
        &e.enrollments,
        at_code(ENROLLMENTS, Enrollment::Tenure)
    ));
    assert!(one(&e.decisions, at_code(DECISIONS, Decided::Exhausted)));
    assert!(one(&e.errors, at_code(STEP_ERRORS, StepError::Held)));
    assert!(one(&e.creates, at_code(CREATES, Create::Unknown)));
    assert!(one(&e.attaches, at_code(ATTACHES, AttachOutcome::Failed)));
}

/// A census longer than a cap lowered below it reads its length beside the cap, and the part seals and accepts, so
/// the status keeps sealing when `census-near-cap` reads past its limit. A cap above the census slots reads as the
/// slots, which the codec's census bound admits.
#[test]
fn a_census_past_a_lowered_cap_seals() {
    let mut status = zone_status(Vec::new());
    (status.census, status.cap) = (Some(70), 64);
    let tally = Tally::default();
    let mut memory = Memory::default();
    let bounds = wide();
    let clock = Clock {
        now_us: 5,
        fresh_us: FRESH_US,
    };
    let part = Builder::new(
        (Zone(1), &status),
        [],
        &mut memory,
        &bounds,
        (Alarm::Clear, &tally),
        clock,
    )
    .finish();
    assert_eq!(part.census, known(70, 64));
    assert_eq!(
        (part.attaches.pairs, part.budgets.attempts),
        (Members::Unavailable, Members::Unavailable),
        "a tick that read no shard records reads no pair gauge and no budget"
    );
    let bytes = crate::failover::report::status::tests::sealed(std::slice::from_ref(&part));
    let accepted = crate::failover::report::status::StatusReader::default()
        .accept(&bytes, crate::failover::report::status::tests::key_of)
        .unwrap();
    assert_eq!(accepted.zones, [part]);
    status.cap = standbys::MAX_SLOTS + 1;
    let builder = Builder::new(
        (Zone(1), &status),
        [],
        &mut memory,
        &bounds,
        (Alarm::Clear, &tally),
        clock,
    );
    let part = builder.finish();
    assert_eq!(part.census, known(70, standbys::MAX_SLOTS as u64));
    crate::failover::report::status::tests::sealed(std::slice::from_ref(&part));
}

/// The variant name of `value`: its `Debug` text up to its first payload.
fn variant(value: &impl core::fmt::Debug) -> String {
    let text = format!("{value:?}");
    text.split(['(', '{', ' ']).next().unwrap().to_owned()
}

/// The name of the one label of `table` whose count is 1, every other count being 0.
fn counted<T: core::fmt::Debug>(table: &[T], counts: &[u32]) -> String {
    assert_eq!(counts.iter().sum::<u32>(), 1, "{counts:?}");
    variant(&table[counts.iter().position(|&n| n == 1).unwrap()])
}

/// CLOSED-LABELS at the conversions: every variant of each step type counts once, under the label of its own name.
/// Four results take another label and count under it: an admitted reservation as `Reserved`, a hold with a
/// replacement as `Hold`, a hold at the last generation as `Exhausted` and a returned volume as `Created`. Each
/// store alarm reads the status label of its name.
#[test]
fn every_step_variant_counts_under_the_label_of_its_name() {
    use crate::failover::admission::AdmissionError;
    use crate::failover::loss::{CreateError, Decision};
    use crate::failover::reconcile::{ReconcileError, StandbyRefusal};
    use crate::failover::records::{Enrollment as Enroll, LayoutRefusal};
    use crate::failover::report::status::{STORE_ALARMS, StoreState};
    use crate::failover::standbys::Refusal;
    let fed = |feed: &dyn Fn(&mut Events)| {
        let mut events = Events::default();
        feed(&mut events);
        events
    };
    for error in [
        ReportError::Length,
        ReportError::Magic,
        ReportError::Schema { found: 2 },
        ReportError::Writer,
        ReportError::Tag,
        ReportError::Flag,
        ReportError::Field,
    ] {
        let events = fed(&|e| e.refused(error));
        assert_eq!(counted(REFUSED, &events.refused), variant(&error));
    }
    assert_eq!(counted(REFUSED, &fed(&|e| e.foreign()).refused), "Foreign");
    for refusal in [
        Refusal::Headroom,
        Refusal::Full,
        Refusal::Taken,
        Refusal::Ineligible,
        Refusal::Closed,
    ] {
        let events = fed(&|e| e.reserved(Err(refusal)));
        assert_eq!(
            counted(RESERVATIONS, &events.reservations),
            variant(&refusal)
        );
    }
    let reserved = fed(&|e| e.reserved(Ok(())));
    assert_eq!(counted(RESERVATIONS, &reserved.reservations), "Reserved");
    let unavailable = StoreError::Unavailable;
    for refusal in [
        StandbyRefusal::Records(unavailable),
        StandbyRefusal::Tenure,
        StandbyRefusal::Persist(AdmissionError::Record),
        StandbyRefusal::Binding,
        StandbyRefusal::Enrollment(Enroll::Unattached),
        StandbyRefusal::Write(unavailable),
    ] {
        let events = fed(&|e| e.enrollment_refused(&refusal));
        assert_eq!(counted(ENROLLMENTS, &events.enrollments), variant(&refusal));
    }
    let request = crate::failover::loss::tests::receipt().request;
    for (decision, label) in [
        (Decision::Provision(request), "Provision"),
        (Decision::Hold(Some(request)), "Hold"),
        (Decision::Hold(None), "Exhausted"),
    ] {
        let events = fed(&|e| e.decided(decision));
        assert_eq!(counted(DECISIONS, &events.decisions), label);
    }
    for error in [
        ReconcileError::Store(unavailable),
        ReconcileError::Conflict,
        ReconcileError::Stale,
        ReconcileError::Retry,
        ReconcileError::Named,
        ReconcileError::Unclean,
        ReconcileError::Layout(LayoutRefusal::TooFewSlots { slots: 1 }),
        ReconcileError::Population(Refusal::Full),
        ReconcileError::Held,
        ReconcileError::Exhausted,
        ReconcileError::Create(CreateError::Failed),
    ] {
        let events = fed(&|e| e.failed(error));
        assert_eq!(counted(STEP_ERRORS, &events.errors), variant(&error));
    }
    for error in [CreateError::Unknown, CreateError::Failed] {
        let events = fed(&|e| e.created(&Err::<(), _>(error)));
        assert_eq!(counted(CREATES, &events.creates), variant(&error));
    }
    let created = fed(&|e| e.created(&Ok::<_, CreateError>(())));
    assert_eq!(counted(CREATES, &created.creates), "Created");
    for &outcome in ATTACHES {
        let events = fed(&|e| e.attached(outcome));
        assert_eq!(counted(ATTACHES, &events.attaches), variant(&outcome));
    }
    for &outcome in RECLAIMS {
        let events = fed(&|e| e.reclaimed(outcome));
        assert_eq!(counted(RECLAIMS, &events.reclaims), variant(&outcome));
    }
    for (events, quiet) in [
        (fed(&|e| e.refused(ReportError::Duplicate)), "a duplicate"),
        (fed(&|e| e.decided(Decision::Retain)), "a retained volume"),
    ] {
        assert_eq!(events, Events::default(), "{quiet} counts nothing");
    }
    let alarms = [
        Alarm::Clear,
        Alarm::Regression,
        Alarm::Checkpoint,
        Alarm::Log,
        Alarm::Namespace,
    ];
    assert_eq!(alarms.len(), STORE_ALARMS.len());
    for alarm in alarms {
        let state = StoreState::of(alarm, &Tally::default());
        assert_eq!(variant(&state.alarm), variant(&alarm));
    }
}

/// ONE-CLASSIFICATION reads the owner's entry only: another host's serving entry at the record's tenure, listed
/// before the owner's withdrawn entry, leaves the shard `withdrawn`, and with no owner entry the shard reads
/// `silent` beside it.
#[test]
fn another_host_s_entry_at_the_record_s_tenure_decides_nothing() {
    let hosts = [
        host_view(11, HostEvidence::Live, Some(reported(11, vec![]))),
        host_view(12, HostEvidence::Live, Some(reported(12, vec![]))),
    ];
    let class = |entries: Vec<(Host, VolumeEntry)>| {
        let shards = [(
            row(1, ShardState::Protected, None),
            Some(records(1, v3(), entries)),
        )];
        let part = build(&hosts, &shards, &mut Memory::default(), &wide(), 5);
        CLASSES[part.classes.iter().position(|&n| n == 1).unwrap()]
    };
    let other = (host(12), owner_entry(1, |_| {}).1);
    let withdrawn = owner_entry(1, |e| e.serving = Some(State::Withdrawn));
    assert_eq!(class(vec![other, withdrawn]), Class::Withdrawn);
    assert_eq!(class(vec![other]), Class::Silent);
}

/// The budgets read the highest attempt counter and the highest generation among the zone's shard records, in either
/// order of the shards, and a record at the last generation reads the generation budget at its limit, which seals.
#[test]
fn the_budgets_read_the_highest_attempt_and_generation() {
    use crate::net::ownership::ShardGeneration;
    let generation = record().generation.get();
    let shard_at = |number: u32, attempts: u32, generation: u64| {
        let mut records = records(number, v3(), vec![]);
        records.record.attempts = attempts;
        records.record.generation = ShardGeneration::new(generation).unwrap();
        (row(number, ShardState::Protected, None), Some(records))
    };
    let budgets = |shards: &[(ShardStatus, Option<ShardRecords>)]| {
        build(&[], shards, &mut Memory::default(), &wide(), 5).budgets
    };
    let (low, high) = (shard_at(1, 1, generation + 7), shard_at(2, 3, generation));
    let limit = u64::from(ATTEMPTS_MAX);
    for shards in [[low.clone(), high.clone()], [high, low]] {
        let read = budgets(&shards);
        assert_eq!(read.attempts, known(3, limit));
        assert_eq!(read.generation, known(generation + 7, GENERATION_MAX));
    }
    let last = [shard_at(1, 1, u64::from(u32::MAX))];
    let part = build(&[], &last, &mut Memory::default(), &wide(), 5);
    assert_eq!(
        part.budgets.generation,
        known(GENERATION_MAX, GENERATION_MAX)
    );
    crate::failover::report::status::tests::sealed(std::slice::from_ref(&part));
}

/// Each source's completeness, each hold and the cap warning reaches its own flag of the part and no other.
#[test]
fn each_source_and_hold_sets_its_own_flag() {
    use crate::failover::zone_loop::config::CapBelowShards;
    type Set = fn(&mut ZoneStatus);
    type Read = fn(&Flags) -> bool;
    let cases: [(Set, Read); 8] = [
        (|s| s.complete.reports = true, |f| f.reports),
        (|s| s.complete.instances = true, |f| f.instances),
        (|s| s.complete.volumes = true, |f| f.volumes),
        (|s| s.complete.store = true, |f| f.store),
        (|s| s.holds.warm_up = true, |f| f.warm_up),
        (|s| s.holds.zone_host = true, |f| f.zone_host),
        (|s| s.holds.operator = true, |f| f.operator),
        (
            |s| s.cap_below = Some(CapBelowShards { cap: 1, shards: 2 }),
            |f| f.cap_below,
        ),
    ];
    let flags = |set: Option<Set>| {
        let mut status = zone_status(Vec::new());
        status.complete = Completeness {
            reports: false,
            instances: false,
            volumes: false,
            store: false,
        };
        if let Some(set) = set {
            set(&mut status);
        }
        let tally = Tally::default();
        let (mut memory, bounds) = (Memory::default(), wide());
        let clock = Clock {
            now_us: 5,
            fresh_us: FRESH_US,
        };
        let store = (Alarm::Clear, &tally);
        Builder::new((Zone(1), &status), [], &mut memory, &bounds, store, clock)
            .finish()
            .flags
    };
    assert_eq!(flags(None), Flags::default());
    for (at, (set, _)) in cases.iter().enumerate() {
        let read = flags(Some(*set));
        let lit: Vec<usize> = (0..cases.len())
            .filter(|&other| (cases[other].1)(&read))
            .collect();
        assert_eq!(lit, [at], "flag {at}");
    }
}

/// `Memory::track` keeps the refused digests of the hosts the zone's listing holds and drops the others: a refused
/// report counts once while its host stays listed, counts again after the listing dropped the host and its digest,
/// and the digest of a host still listed stays, so its unchanged report counts nothing.
#[test]
fn a_refused_report_counts_again_after_its_host_leaves_the_listing() {
    let mut memory = Memory::default();
    let (bytes, kept) = ([7u8; 40], [9u8; 40]);
    let tag = at_code(REFUSED, Refused::Tag);
    memory.refused(host(11), &kept, ReportError::Tag);
    memory.refused(host(12), &bytes, ReportError::Tag);
    memory.track(&[host(11), host(12)]);
    memory.refused(host(12), &bytes, ReportError::Tag);
    assert_eq!(memory.events.refused[tag], 2);
    memory.track(&[host(11)]);
    assert_eq!(
        memory.refused.keys().copied().collect::<Vec<_>>(),
        [host(11)]
    );
    memory.refused(host(12), &bytes, ReportError::Tag);
    memory.refused(host(11), &kept, ReportError::Tag);
    assert_eq!(memory.events.refused[tag], 3);
}

/// STALE-SERVING over several claims. Two hosts' claims count once each and the age reported is the oldest's. A
/// host that moves its claim to another tenure below the record's starts a new dwell. Of one host's two claims for
/// a shard the older stands, whichever its report lists first, and of two first observed on one tick the one its
/// report lists first.
#[test]
fn the_oldest_stale_claim_stands_and_a_new_tenure_starts_a_new_dwell() {
    let claim = |attempts: u32| {
        owner_entry(1, |e| {
            e.tenure = Some((
                record().generation,
                ActivatedEpoch::new(2 * attempts).unwrap(),
            ))
        })
        .1
    };
    let owner = host_view(11, HostEvidence::Live, Some(reported(11, vec![])));
    let shards = || {
        let mut records = records(1, v3(), vec![]);
        records.record.attempts = 3;
        [(row(1, ShardState::Protected, None), Some(records))]
    };
    // Each tick: the claimed attempts of hosts 12 and 13, and the loop time.
    let run = |ticks: &[(&[u32], &[u32], u64)]| {
        let mut memory = Memory::default();
        let mut last = None;
        for &(first, second, now) in ticks {
            let claims = |attempts: &[u32]| attempts.iter().map(|&a| claim(a)).collect();
            let twelve = host_view(12, HostEvidence::Live, Some(reported(12, claims(first))));
            let thirteen = host_view(13, HostEvidence::Live, Some(reported(13, claims(second))));
            let fed = [(&owner, false), (&twelve, false), (&thirteen, false)];
            let part = build_fed(&fed, &shards(), &mut memory, &wide(), now);
            last = Some((part.stale_serving, part.stale_oldest_us));
        }
        last.unwrap()
    };
    let past = 1_000 + FRESH_US + 1;
    assert_eq!(
        run(&[(&[1], &[], 1_000), (&[1], &[1], 1_500), (&[1], &[1], 2_600)]),
        (2, Some(1_600)),
        "two hosts' claims, the older first observed at 1,000"
    );
    assert_eq!(
        run(&[(&[1], &[], 1_000), (&[2], &[], 1_500), (&[2], &[], past)]),
        (0, None),
        "a claim moved to another tenure starts a new dwell"
    );
    assert_eq!(
        run(&[(&[1], &[], 1_000), (&[1], &[], 1_500), (&[1], &[], past)]),
        (1, Some(FRESH_US + 1)),
        "the same claim keeps its dwell"
    );
    for both in [&[2, 1][..], &[1, 2]] {
        assert_eq!(
            run(&[(&[1], &[], 1_000), (both, &[], 1_500), (both, &[], past)]),
            (1, Some(FRESH_US + 1)),
            "the older of one host's two claims stands: {both:?}"
        );
    }
    assert_eq!(
        run(&[(&[1, 2], &[], 1_000), (&[1], &[], past)]),
        (1, Some(FRESH_US + 1)),
        "of two claims first observed on one tick, the first listed stands"
    );
}
