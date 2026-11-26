//! Five single-shard histories judged by the alarm catalog: a clean warm takeover, a takeover stopped after its
//! compare-and-swap and rerun by its host's restart, a takeover whose compare-and-swap reply is unknown, a takeover
//! over one damaged row unit, and a takeover of a shard whose suffix chain stands at its cap.
//!
//! The test plays the successor's driver. It runs each recovery step through one store client of the successor's
//! process and keeps one `RecoveryStatus` for the volume across the process's attempts. Each served tenure observes
//! its shard view from the store and yields its entry through `Owner::report_entry`, with the driver's part built
//! from that client's alarm and tally and the recovery status; the entry is read once the tenure opens its client
//! session and once after it has read every object. An attempt that refuses before any tenure publishes one entry
//! of the driver's own: the volume, the shard, the role the record names and the refused attempt's recovery part.
//! It shares the volume, the shard and the recovery part's source with the entry the fleet harness publishes for a
//! held process (`fleet::hosts`), and reads phase `Recovering` with no ended mark, since the attempt reruns. The world runs no
//! control-plane listing, so every entry's enumeration reads unavailable. Each record is sealed by the host's report
//! writer and accepted by the production reader (`alarm_tests::controls::sealed`), and every row of the catalog is
//! evaluated over the accepted views (`fleet::alarms::fired`).
//!
//! Each history's firings must equal its expected list, one entry per firing, so a missing row, an extra row and a
//! second firing of a row each fail it, and its published records must be the ones its script names.

use super::*;
use crate::failover::records::{ShardRecord, VolumeRecord};
use crate::failover::report::alarm_tests::controls::{Step as Sealing, host_state, sealed};
use crate::failover::report::alarm_tests::{Fired, catalog};
use crate::failover::report::{
    Captures, Gauge, Observed, Phase, RecordedRole, RecoveryKind, RecoveryOutcome, RecoveryRefusal,
    RecoveryStatus, VolumeEntry,
};
use crate::failover::takeover::Next;
use crate::storage::store::Key;
use crate::storage::store::sim::Arm;

use super::fleet::alarms;

/// The successor's process: its store client, its volume's recovery status and the records it published.
struct Driver {
    client: StoreClient<Shared, crate::storage::store::sim::MemLog>,
    recovery: RecoveryStatus,
    sealed: Vec<Sealing>,
}

impl Driver {
    fn new(world: &World) -> Self {
        Self {
            client: store_client(&world.records),
            recovery: RecoveryStatus::NO_ATTEMPT,
            sealed: Vec::new(),
        }
    }

    /// The driver's part of an entry: the client's alarm and tally and the volume's recovery status.
    fn observed(&self) -> Observed {
        Observed {
            alarm: Some(self.client.alarm()),
            store: Some(self.client.outcomes()),
            recovery: Some(self.recovery),
            captures: Captures {
                refused: Some(0),
                abandoned: Some(0),
            },
            quarantine: Gauge::known(0, 3),
            suffix_due: Some(crate::storage::checkpoint::SuffixDue::default()),
            roll_due: Some(false),
            roll_active: Some(false),
            ..Observed::UNAVAILABLE
        }
    }

    fn publish(&mut self, host: Host, entry: VolumeEntry) {
        self.sealed.push(Sealing::Report {
            host: host.get(),
            state: Box::new(host_state()),
            entries: vec![entry],
        });
    }

    /// Observes the shard view the store holds now and publishes `serving`'s entry through `Owner::report_entry`.
    fn served(&mut self, world: &World, host: Host, serving: &mut Serving<'_>) {
        let mut reads = store_client(&world.records);
        let shard = reads.read::<ShardRecord>(Key::Shard(world.shard));
        let shard = shard.expect("the shard record");
        let active = shard.value().active;
        let volume = reads.read::<VolumeRecord>(Key::Volume(active)).ok();
        let now = serving.time();
        (serving.owner).observe_shard_view(active, Some(&shard), volume.as_ref(), None, now);
        let entry = serving.owner.report_entry(now, &self.observed());
        self.publish(
            host,
            entry.expect("an entry once the view names the volume"),
        );
    }

    /// Publishes the entry of an attempt that refused before any tenure: the record's active volume and shard, the
    /// role the record names for `host`, and the refused attempt's recovery part.
    fn refused(&mut self, world: &World, host: Host, refusal: RecoveryRefusal) {
        self.recovery.refuse(refusal);
        let record = restart_tests::shard_now_of(&world.records, world.shard);
        let role = match record.owner == host {
            true => RecordedRole::Owner,
            false => RecordedRole::Standby,
        };
        let entry = VolumeEntry {
            volume: record.active,
            shard: world.shard,
            phase: Some(Phase::Recovering),
            recovery: self.recovery.recovery(0),
            ..crate::failover::report::tests::bare(record.active.as_str(), role)
        };
        self.publish(host, entry);
    }

    /// Completes the driver's running attempt, serves `taken` warm and publishes the tenure's entry once its client
    /// session is active and once after it read every object.
    fn serve(&mut self, world: &mut World, host: Host, taken: Restarted) {
        self.recovery.complete();
        serve(world, taken, Source::Named, |world, serving, outcome| {
            assert_eq!(outcome, MetadataOutcome::Open, "a warm load");
            self.served(world, host, serving);
            serving.read_all(world);
            self.served(world, host, serving);
        });
    }

    /// Every firing of every catalog row over the published records.
    fn fired(&self, catalog: &serde_json::Value) -> Vec<Fired> {
        let (inputs, refused) = sealed(&self.sealed);
        assert_eq!(refused, [], "the reader accepts every published record");
        alarms::fired(catalog, &inputs)
    }
}

/// Starts a takeover attempt on the driver's recovery status and runs `host`'s standby takeover through `driver`'s
/// client, as [`World::takeover`] runs it, with the card stopping at `stop_at` and the store answering the
/// takeover's own calls by `arms`. A takeover that succeeds is fenced; the path returns beside the result.
fn take_over(
    world: &World,
    driver: &mut Driver,
    host: Host,
    (stop_at, arms): (Option<usize>, &[Arm]),
) -> (
    Result<Restarted, Refused>,
    crate::failover::takeover::Takeover<'static>,
) {
    let (mut card, local) = world.host(host);
    card.stop_at = stop_at;
    driver.recovery.start(RecoveryKind::Takeover, 0);
    let path = takeover_of(&world.records, host);
    for &arm in arms {
        world.records.schedule(arm);
    }
    let taken = path.run(&mut driver.client, &local, &mut card);
    if let Ok(taken) = &taken {
        world.fence(taken);
    }
    (taken, path)
}

/// Starts a restart attempt, runs the same-host restart `refused`'s next step names through `driver`'s client, marks the driver's recovery
/// status as the lineage arm's when the restart took that arm, fences the tenure and returns it.
fn rerun(
    world: &World,
    driver: &mut Driver,
    host: Host,
    path: &crate::failover::takeover::Takeover<'static>,
    refused: &Refused,
) -> Restarted {
    let Next::Restart(restart) = path.next(refused) else {
        panic!("the refusal continues by the same-host restart: {refused:?}");
    };
    driver.recovery.start(RecoveryKind::Restart, 0);
    let (mut card, local) = world.host(host);
    let restarted = restart
        .run(&mut driver.client, &local, &mut card)
        .expect("the same-host restart");
    if restarted.lineage() {
        driver.recovery.lineage();
    }
    world.fence(&restarted);
    restarted
}

/// Runs the history `name` and returns the rows it must fire, one entry per firing, whether it first publishes a
/// refused attempt's record, and the driver that ran it.
fn history(name: &str) -> (Vec<&'static str>, bool, Driver) {
    let host = c_host();
    match name {
        "clean" => {
            let mut world = World::new(4, false);
            let mut driver = Driver::new(&world);
            let (taken, _) = take_over(&world, &mut driver, host, (None, &[]));
            driver.serve(&mut world, host, taken.expect("the takeover"));
            (Vec::new(), false, driver)
        }
        "stopped after its compare-and-swap" => {
            let mut world = World::new(4, false);
            let mut driver = Driver::new(&world);
            let (refused, path) = take_over(&world, &mut driver, host, (Some(3), &[]));
            let refused = refused.expect_err("the takeover stops at its first Report");
            let record = restart_tests::shard_now(&world.records);
            assert_eq!(record.owner, host, "the compare-and-swap committed");
            driver.refused(&world, host, RecoveryRefusal::from(&refused));
            let restarted = rerun(&world, &mut driver, host, &path, &refused);
            assert!(restarted.lineage(), "the rerun takes the lineage arm");
            driver.serve(&mut world, host, restarted);
            (Vec::new(), true, driver)
        }
        "unknown compare-and-swap" => {
            let mut world = World::new(4, false);
            let mut driver = Driver::new(&world);
            let arms = [Arm::Pass, Arm::Pass, Arm::Timeout { commit: true }];
            let (refused, path) = take_over(&world, &mut driver, host, (None, &arms));
            let refused = refused.expect_err("an unknown reply refuses the takeover");
            let unknown = crate::storage::store::StoreError::Unknown;
            assert_eq!(
                refused.check,
                crate::failover::takeover::Check::TakeOver(unknown)
            );
            driver.refused(&world, host, RecoveryRefusal::from(&refused));
            let restarted = rerun(&world, &mut driver, host, &path, &refused);
            driver.serve(&mut world, host, restarted);
            (vec!["unknown-recovery-write"], true, driver)
        }
        "one damaged row unit" => {
            let mut world = World::new(50, false);
            let last = world.objects.last().expect("an object").n;
            let (row, _) = world.units(last);
            let lost = world.on_unit(row);
            assert!(
                !lost.is_empty() && lost.len() < 50,
                "the row unit holds some objects"
            );
            world.corrupt(row);
            let mut driver = Driver::new(&world);
            let (taken, _) = take_over(&world, &mut driver, host, (None, &[]));
            driver.serve(&mut world, host, taken.expect("the takeover"));
            (vec!["retention-damage"], false, driver)
        }
        "a chain at its cap" => {
            let (mut world, _) = suffixed(1, Suffix::Certified, Chain::Full);
            let mut driver = Driver::new(&world);
            let (taken, _) = take_over(&world, &mut driver, host, (None, &[]));
            driver.serve(&mut world, host, taken.expect("the takeover"));
            (vec!["chain-at-cap"], false, driver)
        }
        _ => unreachable!("a named history"),
    }
}

const HISTORIES: [&str; 5] = [
    "clean",
    "stopped after its compare-and-swap",
    "unknown compare-and-swap",
    "one damaged row unit",
    "a chain at its cap",
];

/// The rows of `fired`, one entry per firing, sorted.
fn listed(fired: &[Fired]) -> Vec<String> {
    let mut rows: Vec<String> = fired.iter().map(|fired| fired.row.clone()).collect();
    rows.sort_unstable();
    rows
}

/// Each history's sealed entries fire exactly its expected rows, once each: a clean takeover and a takeover stopped
/// after its compare-and-swap, whose host's restart takes the lineage arm and serves, fire none; an unknown
/// compare-and-swap reply fires `unknown-recovery-write` on the refused attempt's record, a damaged row unit
/// `retention-damage` once for the tenure across its two entries, and a suffix chain at its cap `chain-at-cap`. A
/// rerun history seals the refused attempt's entry, with no tenure, and then two completed entries of one served
/// tenure, and every other history those two.
#[test]
fn each_single_shard_history_fires_exactly_its_expected_alarm_rows() {
    let shipped = catalog();
    for name in HISTORIES {
        let (expected, rerun, driver) = history(name);
        let fired = listed(&driver.fired(&shipped));
        // Each record holds one entry: a refused attempt's with no tenure, then two completed ones of one tenure.
        let published: Vec<_> = (driver.sealed.iter())
            .map(|record| match record {
                Sealing::Report { entries, .. } if entries.len() == 1 => {
                    (entries[0].recovery.outcome, entries[0].tenure)
                }
                other => panic!("{name}: a record other than a one-entry report: {other:?}"),
            })
            .collect();
        let (attempt, served) = published.split_at(usize::from(rerun));
        assert_eq!(
            attempt,
            vec![(Some(RecoveryOutcome::Refused), None); usize::from(rerun)],
            "{name}"
        );
        let tenure = served.first().and_then(|(_, tenure)| *tenure);
        assert!(tenure.is_some(), "{name}: the served tenure");
        assert_eq!(
            served,
            [(Some(RecoveryOutcome::Completed), tenure); 2],
            "{name}"
        );
        assert_eq!(fired, expected, "{name}: the fired rows");
        if rerun && !expected.is_empty() {
            let (inputs, _) = sealed(&driver.sealed[..1]);
            let first = listed(&alarms::fired(&shipped, &inputs));
            assert_eq!(
                first, expected,
                "{name}: the refused attempt's record fires the row"
            );
        }
    }
}
