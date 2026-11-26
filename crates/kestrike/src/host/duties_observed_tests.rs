//! The driver's part of the published status: the store tally from the tenure open on, the store client's alarm and
//! the listing result of the last poll each read unavailable until the duties hold their source, and their known
//! value after.

use std::cell::Cell;
use std::rc::Rc;

use super::status::{ZEROED, Zeroed};
use super::tests::{periods, records};
use super::view_tests::{Events, Listing, clean_listing};
use super::{Duties, Linked, Open};
use crate::failover::attachments::Unlisted;
use crate::failover::fresh::tests::holder;
use crate::failover::report::{
    Enumeration, Phase, RecoveryStatus, StoreOutcomes, VolumeEntry, Watermark,
};
use crate::host::lane::tests::bounds;
use crate::host::lane::{Lane, Plane};
use crate::host::link::Link;
use crate::host::serve::loop_tests::{Stage, TestOwner, observe, staged};
use crate::host::{Exit, HostGate};
use crate::storage::store::sim::{Arm, MemLog, Shared};
use crate::storage::store::{
    Alarm, Client, Item, Key, Outcome, Store, StoreError, Tallied, Unavailable, Write,
};
use crate::storage::store_tests::shard;
use crate::storage::test_platform::TestPlatform;

/// A store over [`Shared`] that schedules an armed [`Arm`] on the next shard-record read or write, and answers
/// every volume-record read unavailable while `volume_down` is set.
#[derive(Clone)]
struct Armed {
    inner: Shared,
    read: Rc<Cell<Option<Arm>>>,
    write: Rc<Cell<Option<Arm>>>,
    volume_down: Rc<Cell<bool>>,
}

impl Armed {
    fn new(inner: &Shared) -> Self {
        Self {
            inner: inner.clone(),
            read: Rc::default(),
            write: Rc::default(),
            volume_down: Rc::default(),
        }
    }
}

impl Store for Armed {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        if let Key::Volume(_) = key
            && self.volume_down.get()
        {
            return Err(Unavailable);
        }
        if let Key::Shard(_) = key
            && let Some(arm) = self.read.take()
        {
            self.inner.schedule(arm);
        }
        self.inner.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        if let Key::Shard(_) = key
            && let Some(arm) = self.write.take()
        {
            self.inner.schedule(arm);
        }
        self.inner.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

type ObservedDuties<'w> = Duties<'w, Armed, MemLog, TestPlatform>;

fn observed_duties<'w>(
    stage: &Stage<'w>,
    client: Client<Armed, MemLog>,
    plane: Option<Listing>,
    link: &'w Link,
) -> ObservedDuties<'w> {
    Duties::new(
        (
            &HostGate::qualified(),
            crate::failover::reconcile::StandbyGate::qualified(),
        ),
        Lane::inline(client, stage.storage),
        records(),
        plane.map(|plane| Plane(Box::new(plane))),
        bounds(),
        periods(),
    )
    .linked(Linked {
        link,
        pid: 7,
        status_us: super::tests::TEST_VIEW_US,
        recovery: Some(RecoveryStatus::NO_ATTEMPT),
    })
}

/// Serves `duties` until `done` holds for the entries of the statuses published so far, or the duties exit. `each`
/// runs before every turn. Returns the exit and each published entry, in order; a status before the owner observed a
/// shard view carries no entry and is left out.
fn serve<'w>(
    stage: &mut Stage<'w>,
    duties: &mut ObservedDuties<'w>,
    link: &'w Link,
    mut each: impl FnMut(&mut ObservedDuties<'w>, &mut TestOwner<'w>, u64),
    done: impl Fn(&[VolumeEntry]) -> bool,
) -> (Exit, Vec<VolumeEntry>) {
    let mut entries = Vec::new();
    let (served, _) = stage.serve_until(
        |_, _, _| {},
        |owner, now| {
            if done(&entries) {
                return Some(Exit::Stopped);
            }
            each(duties, owner, now);
            let exit = duties.turn(owner, now);
            if let Some(entry) = link.status.take().and_then(|status| status.entry) {
                entries.push(entry);
            }
            exit
        },
    );
    (served.exit, entries)
}

fn leaked() -> &'static Link {
    Box::leak(Box::default())
}

/// Whether `entry` reads `part` unavailable.
fn unavailable(entry: &VolumeEntry, part: Zeroed) -> bool {
    match part {
        Zeroed::Store => entry.store == StoreOutcomes::UNAVAILABLE,
        Zeroed::Alarm => entry.watermark == Watermark::Unavailable,
        Zeroed::Enumeration => entry.enumeration == Enumeration::Unavailable,
    }
}

const PARTS: [Zeroed; 3] = [Zeroed::Store, Zeroed::Alarm, Zeroed::Enumeration];

/// The entries of a tenure whose owner observed a shard view before its first turn, so the first status carries an
/// entry before the duties adopted a lane completion, served until a status carries a judged listing. With `zeroed`,
/// the duties publish that part as zero or clear while they hold none.
fn until_listed(zeroed: Option<Zeroed>) -> Vec<VolumeEntry> {
    ZEROED.with(|plant| plant.set(zeroed));
    let entries = staged(|mut stage| {
        let link = leaked();
        let client = Client::open(Armed::new(&stage.store), MemLog::default()).unwrap();
        let listing = Listing::new(&Events::default());
        let mut duties = observed_duties(&stage, client, Some(listing), link);
        let store = stage.store.clone();
        let first = Cell::new(true);
        let (exit, entries) = serve(
            &mut stage,
            &mut duties,
            link,
            |_, owner, now| {
                if first.replace(false) {
                    observe(&store, owner, now);
                }
            },
            |entries| {
                (entries.iter()).any(|entry| entry.enumeration == Enumeration::Matches)
                    && entries.len() >= 3
            },
        );
        assert_eq!(exit, Exit::Stopped);
        entries
    });
    ZEROED.with(|plant| plant.set(None));
    entries
}

/// NO-INVENTED-VALUES: the first status, published before the duties adopted a lane completion or judged a listing,
/// reads the store counts, the alarm and the enumeration unavailable, never zero or clear; once the duties hold each
/// source, every later status reads it known.
#[test]
fn the_driver_parts_read_unavailable_until_the_duties_hold_their_sources() {
    let entries = until_listed(None);
    let first = entries.first().unwrap();
    for part in PARTS {
        assert!(unavailable(first, part), "{part:?} in {first:?}");
    }
    let known = |part| {
        entries
            .iter()
            .position(|entry| !unavailable(entry, part))
            .unwrap()
    };
    for part in PARTS {
        let from = known(part);
        assert!(
            entries[from..]
                .iter()
                .all(|entry| !unavailable(entry, part)),
            "{part:?} stays known once held"
        );
        assert!(entries[..from].iter().all(|entry| unavailable(entry, part)));
    }
    let second = &entries[1];
    assert_eq!(second.watermark, Watermark::Clear);
    assert_eq!(
        second.store,
        StoreOutcomes {
            unknown: Some(0),
            unavailable: Some(0),
            refused: Some(0),
            log: Some(0)
        }
    );
    assert!(
        known(Zeroed::Enumeration) > 1,
        "the first listing is judged at the second view"
    );
}

/// Controls for NO-INVENTED-VALUES, planted: duties that publish zero counts, a clear alarm or a matching listing for
/// a part they hold none of fail the first-status case for that part.
#[test]
fn the_controls_that_publish_zero_or_clear_for_a_missing_part_fail_the_first_status() {
    for part in PARTS {
        let entries = until_listed(Some(part));
        let first = entries.first().unwrap();
        assert!(
            !unavailable(first, part),
            "the planted {part:?} reads known: {first:?}"
        );
        for other in PARTS.into_iter().filter(|other| *other != part) {
            assert!(
                unavailable(first, other),
                "{other:?} under the {part:?} plant"
            );
        }
    }
}

/// The tenure's store counts start at the tenure open: a shard-record write whose reply is unknown, the open's own
/// confirmation, reads one unknown in every later status, and an unavailable read the client made before the lane
/// started stays out of the counts while the client's own tally holds it.
#[test]
fn an_unknown_write_reads_once_in_the_tenure_counts_and_earlier_calls_stay_out() {
    staged(|mut stage| {
        let link = leaked();
        let store = Armed::new(&stage.store);
        let mut client = Client::open(store.clone(), MemLog::default()).unwrap();
        store.read.set(Some(Arm::Unavailable));
        assert_eq!(
            client
                .read::<crate::failover::records::ShardRecord>(Key::Shard(shard()))
                .map(drop),
            Err(StoreError::Unavailable)
        );
        store.write.set(Some(Arm::Timeout { commit: false }));
        let mut duties = observed_duties(&stage, client, None, link);
        let (exit, entries) = serve(
            &mut stage,
            &mut duties,
            link,
            |_, _, _| {},
            |entries| {
                let counted = (entries.iter()).position(|entry| entry.store.unknown == Some(1));
                counted.is_some_and(|at| entries.len() >= at + 3)
            },
        );
        assert_eq!(exit, Exit::Stopped);
        assert!(store.write.get().is_none(), "the armed write ran");
        assert_eq!(
            duties.open(),
            Open::Opened,
            "the open retried past the unknown write"
        );
        let at = entries
            .iter()
            .position(|entry| entry.store.unknown == Some(1))
            .unwrap();
        assert!(
            entries[..at]
                .iter()
                .all(|entry| entry.store.unknown == Some(0))
        );
        for entry in &entries[at..] {
            assert_eq!(
                entry.store,
                StoreOutcomes {
                    unknown: Some(1),
                    unavailable: Some(0),
                    refused: Some(0),
                    log: Some(0)
                },
                "the unknown write counted once, the earlier unavailable read left out"
            );
        }
        let client = duties.lane.monitors().unwrap().outcomes;
        assert_eq!(
            client.total(Tallied::Unavailable),
            1,
            "the client counted the earlier read"
        );
        assert_eq!(client.total(Tallied::Unknown), 1);
    });
}

/// A shard read below the client's watermark withdraws the client; the next status reads the regression alarm, and
/// every later status keeps it while the withdrawn client refuses each later view.
#[test]
fn a_regression_reaches_the_status_and_a_withdrawn_client_keeps_its_first_cause() {
    staged(|mut stage| {
        let link = leaked();
        let store = Armed::new(&stage.store);
        let client = Client::open(store.clone(), MemLog::default()).unwrap();
        let mut duties = observed_duties(&stage, client, None, link);
        let armed = Cell::new(false);
        let (_, entries) = serve(
            &mut stage,
            &mut duties,
            link,
            |duties, _, _| {
                if duties.open() == Open::Opened && !armed.replace(true) {
                    store.read.set(Some(Arm::StaleCurrentRead));
                }
            },
            |entries| {
                let raised =
                    (entries.iter()).position(|entry| entry.watermark == Watermark::Regression);
                raised.is_some_and(|at| entries.len() >= at + 6)
            },
        );
        assert!(store.read.get().is_none(), "the armed read ran");
        let at = (entries.iter())
            .position(|entry| entry.watermark == Watermark::Regression)
            .unwrap();
        assert!(
            entries[..at]
                .iter()
                .all(|entry| entry.watermark == Watermark::Clear)
        );
        assert!(
            entries[at..]
                .iter()
                .all(|entry| entry.watermark == Watermark::Regression),
            "the first cause stays"
        );
        assert_eq!(duties.lane.monitors().unwrap().alarm, Alarm::Regression);
        let mut client = duties.end();
        crate::storage::store_tests::withdrawn(&mut client);
        assert_eq!(client.alarm(), Alarm::Regression);
    });
}

/// The status carries the listing result of the last poll: a clean listing reads `Matches`, a refused listing call
/// `Unlisted`, and a foreign listing `Foreign` in the status the retirement's exit turn publishes.
#[test]
fn the_status_carries_the_listing_result_of_the_last_poll() {
    staged(|mut stage| {
        let link = leaked();
        let client = Client::open(Armed::new(&stage.store), MemLog::default()).unwrap();
        let listing = Listing::new(&Events::default());
        let mut duties = observed_duties(&stage, client, Some(listing.clone()), link);
        let phase = Cell::new(0);
        let (exit, entries) = serve(
            &mut stage,
            &mut duties,
            link,
            |duties, _, now| {
                let next = match (phase.get(), duties.enumeration) {
                    (0, Enumeration::Matches) => Some(Err(Unlisted)),
                    (1, Enumeration::Unlisted) => {
                        let mut foreign = clean_listing();
                        foreign.push("i-0fffffffffffffff0".to_owned());
                        Some(Ok(foreign))
                    }
                    _ => None,
                };
                if let Some(listed) = next {
                    listing.set(listed);
                    duties.listing_at = now;
                    phase.set(phase.get() + 1);
                }
            },
            |_| false,
        );
        assert!(matches!(exit, Exit::Retire(_)), "{exit:?}");
        let mut judged: Vec<Enumeration> = entries.iter().map(|entry| entry.enumeration).collect();
        judged.dedup();
        assert_eq!(
            judged,
            [
                Enumeration::Unavailable,
                Enumeration::Matches,
                Enumeration::Unlisted,
                Enumeration::Foreign
            ]
        );
        assert_eq!(entries.last().unwrap().enumeration, Enumeration::Foreign);
    });
}

/// NO-INVENTED-VALUES: a view whose volume read failed polls with the last binding only for a listing adopted before
/// that binding's view, so over the listing adopted after the volume reads began to fail its poll judges the listing
/// without the records a standby binding could admit. A clean result over the rest says nothing about the records
/// left out, so the status reads the enumeration unavailable while the full listing still holds C's record. A duplicate own
/// record retires whatever the records left out hold, so it reads `Duplicate`.
#[test]
fn a_listing_with_a_record_the_view_left_unjudged_reads_unavailable_until_a_duplicate_retires() {
    staged(|mut stage| {
        let link = leaked();
        let store = Armed::new(&stage.store);
        let client = Client::open(store.clone(), MemLog::default()).unwrap();
        let listing = Listing::new(&Events::default());
        let mut duties = observed_duties(&stage, client, Some(listing.clone()), link);
        let phase = Cell::new(0);
        let (exit, entries) = serve(
            &mut stage,
            &mut duties,
            link,
            |duties, _, now| match (phase.get(), duties.enumeration) {
                (0, Enumeration::Matches) if duties.open() == Open::Opened => {
                    store.volume_down.set(true);
                    duties.listing_at = now;
                    phase.set(1);
                }
                (1, Enumeration::Unavailable) => {
                    let mut twice = clean_listing();
                    twice.push(holder().instance.as_str().to_owned());
                    listing.set(Ok(twice));
                    duties.listing_at = now;
                    phase.set(2);
                }
                _ => {}
            },
            |entries| entries.len() >= 30,
        );
        let mut judged: Vec<Enumeration> = entries.iter().map(|entry| entry.enumeration).collect();
        judged.dedup();
        assert_eq!(
            judged,
            [
                Enumeration::Unavailable,
                Enumeration::Matches,
                Enumeration::Unavailable,
                Enumeration::Duplicate
            ]
        );
        assert!(matches!(exit, Exit::Retire(_)), "{exit:?}");
    });
}

/// The turn that ends the tenure has no successor to publish its status. While the link side holds the cell on that
/// turn, the cell takes nothing and the duties keep the status for the caller, which takes it after the serving
/// loop: the status of the retiring turn, with the foreign listing and the withdrawn phase.
#[test]
fn a_cell_held_on_the_exit_turn_leaves_the_final_status_with_the_duties() {
    staged(|mut stage| {
        let link = leaked();
        let client = Client::open(Armed::new(&stage.store), MemLog::default()).unwrap();
        let listing = Listing::new(&Events::default());
        let mut duties = observed_duties(&stage, client, Some(listing.clone()), link);
        let mut foreign = false;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if !foreign {
                    let exit = duties.turn(owner, now);
                    link.status.take();
                    if duties.enumeration == Enumeration::Matches {
                        let mut listed = clean_listing();
                        listed.push("i-0fffffffffffffff0".to_owned());
                        listing.set(Ok(listed));
                        duties.listing_at = now;
                        foreign = true;
                    }
                    return exit;
                }
                let held = link.status.hold();
                let exit = duties.turn(owner, now);
                assert!(held.is_none(), "the held cell took no status");
                drop(held);
                exit
            },
        );
        assert!(matches!(served.exit, Exit::Retire(_)), "{:?}", served.exit);
        assert_eq!(link.status.take(), None);
        let last = duties
            .take_unpublished()
            .expect("the exit turn's status stays with the duties");
        assert_eq!(last.phase, Phase::Withdrawn);
        assert_eq!(
            last.entry.map(|entry| entry.enumeration),
            Some(Enumeration::Foreign)
        );
        assert_eq!(duties.take_unpublished(), None, "taken once");
    });
}

/// NO-INVENTED-VALUES: duties with no control plane judge no listing, and every status reads the enumeration
/// unavailable.
#[test]
fn with_no_control_plane_every_status_reads_the_enumeration_unavailable() {
    staged(|mut stage| {
        let link = leaked();
        let client = Client::open(Armed::new(&stage.store), MemLog::default()).unwrap();
        let mut duties = observed_duties(&stage, client, None, link);
        let (exit, entries) = serve(
            &mut stage,
            &mut duties,
            link,
            |_, _, _| {},
            |entries| entries.len() >= 6,
        );
        assert_eq!(exit, Exit::Stopped);
        assert!(
            (entries.iter()).all(|entry| entry.enumeration == Enumeration::Unavailable),
            "{entries:?}"
        );
    });
}
