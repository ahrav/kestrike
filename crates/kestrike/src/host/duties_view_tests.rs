use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use super::tests::{SNAPSHOT_AFTER_READS, TEST_VIEW_US, UNBOUNDED_BINDING, periods, records};
use super::{Duties, LISTING_US, Open, PeriodRefusal, Periods, VIEW_US as VIEW_MAX};
use crate::failover::attachments::InstanceId;
use crate::failover::attachments::{ControlPlane, Unlisted};
use crate::failover::bounds::Bounds;
use crate::failover::evidence::NotSole;
use crate::failover::fresh::tests::{holder, registrant};
use crate::failover::reconcile::LISTING_HOLD_US;
use crate::failover::records::{ERA, EventKind, Host, Record, ShardRecord, VolumeId, VolumeRecord};
use crate::failover::report::Enumeration;
use crate::failover::restart::tests::{own, shard_now, volume_id};
use crate::failover::retire::Target;
use crate::failover::serving::{Cause, Event, State};
use crate::failover::takeover::tests::{
    b_host, b_pair, c_host, c_pair, designate, instance_of, stored_c, takeover_of, volume_now,
    with_c_and_b,
};
use crate::failover::withhold::{W_US, Withhold};
use crate::host::fencer_tests::fencer_of;
use crate::host::lane::tests::bounds;
use crate::host::lane::{Lane, Plane};
use crate::host::serve::loop_tests::{Stage, staged, staged_ahead, staged_over};
use crate::host::serve::tests::{host_over, warm_volume_certified};
use crate::host::{Exit, HostGate, Rerun};
use crate::storage::gate_fixture::Ticking;
use crate::storage::gate_fixture::{arena_with, bounds_of, bounds_with, limits};
use crate::storage::store::sim::{Arm, MemLog, Shared};
use crate::storage::store::{Client, Item, Key, Outcome, Store, Unavailable, Write};
use crate::storage::store_tests::{client as store_client, shard};
use crate::storage::test_platform::TestPlatform;
use crate::storage::warm_sim::layout;

#[derive(Clone)]
struct Logged {
    inner: Shared,
    now: Rc<Cell<u64>>,
    fail: Rc<Cell<bool>>,
    fail_volume: Rc<Cell<bool>>,
    /// Reads of existing records of the selected kind return malformed bytes at the next version.
    undecodable: Rc<Cell<Option<Undecodable>>>,
    shard_reads: Rc<RefCell<Vec<(u64, bool)>>>,
    /// The shard-record write requests the store received, refused ones included.
    shard_writes: Rc<Cell<usize>>,
    before_shard_write: Rc<RefCell<Option<Step>>>,
    events: Events,
}

/// A step the store runs once, before it forwards the shard-record write request of this number.
type Step = (usize, Box<dyn FnOnce()>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Undecodable {
    Volume,
    Shard,
}

impl Store for Logged {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        let fail = self.fail.get();
        if let Key::Volume(_) = key
            && self.fail_volume.get()
        {
            return Err(Unavailable);
        }
        if let Key::Shard(_) = key {
            self.shard_reads.borrow_mut().push((self.now.get(), !fail));
            self.events.lock().unwrap().push("view");
        }
        if fail {
            return Err(Unavailable);
        }
        let undecodable = matches!(
            (key, self.undecodable.get()),
            (Key::Volume(_), Some(Undecodable::Volume)) | (Key::Shard(_), Some(Undecodable::Shard))
        );
        let item = self.inner.read(key)?;
        Ok(match item {
            Some(item) if undecodable => Some(Item {
                version: item.version.next().expect("a version below the maximum"),
                value: vec![0; 3],
            }),
            item => item,
        })
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        if let Key::Shard(_) = key {
            self.shard_writes.set(self.shard_writes.get() + 1);
            let due = (self.before_shard_write.borrow().as_ref())
                .is_some_and(|(at, _)| *at == self.shard_writes.get());
            if due && let Some((_, step)) = self.before_shard_write.borrow_mut().take() {
                step();
            }
        }
        self.inner.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

#[derive(Clone)]
pub(super) struct Listing(Arc<Mutex<Listed>>, Events);

type Listed = (Result<Vec<String>, Unlisted>, usize);

pub(super) type Events = Arc<Mutex<Vec<&'static str>>>;

impl Listing {
    pub(super) fn new(events: &Events) -> Self {
        Self(
            Arc::new(Mutex::new((Ok(clean_listing()), 0))),
            Arc::clone(events),
        )
    }

    pub(super) fn set(&self, listed: Result<Vec<String>, Unlisted>) {
        self.0.lock().unwrap().0 = listed;
    }

    fn calls(&self) -> usize {
        self.0.lock().unwrap().1
    }
}

impl ControlPlane for Listing {
    fn attachments(&mut self, volume: &VolumeId) -> Result<Vec<String>, Unlisted> {
        assert_eq!(*volume, volume_id(), "the listing names the own volume");
        self.1.lock().unwrap().push("listing");
        let mut held = self.0.lock().unwrap();
        held.1 += 1;
        held.0.clone()
    }
}

const FOREIGN: &str = "i-0eeeeeeeeeeeeeee0";

fn foreign_listing() -> Vec<String> {
    let mut listed = clean_listing();
    listed.push(FOREIGN.to_owned());
    listed
}

pub(super) fn clean_listing() -> Vec<String> {
    [holder().instance, instance_of(c_host())]
        .iter()
        .map(|instance| instance.as_str().to_owned())
        .collect()
}

type ViewDuties<'w> = Duties<'w, Logged, MemLog, TestPlatform>;

fn view_duties<'w>(stage: &Stage<'w>, plane: Option<Listing>) -> (ViewDuties<'w>, Logged) {
    let events = plane
        .as_ref()
        .map_or_else(Events::default, |plane| Arc::clone(&plane.1));
    let store = Logged {
        inner: stage.store.clone(),
        now: Rc::clone(&stage.rounds.now),
        fail: Rc::default(),
        fail_volume: Rc::default(),
        undecodable: Rc::default(),
        shard_reads: Rc::default(),
        shard_writes: Rc::default(),
        before_shard_write: Rc::default(),
        events,
    };
    let lane = Lane::inline(
        Client::open(store.clone(), MemLog::default()).unwrap(),
        stage.storage,
    );
    let plane = plane.map(|plane| Plane(Box::new(plane)));
    let duties = Duties::new(
        (
            &HostGate::qualified(),
            crate::failover::reconcile::StandbyGate::qualified(),
        ),
        lane,
        records(),
        plane,
        bounds(),
        periods(),
    );
    (duties, store)
}

fn enroll_b(store: &Shared) {
    let mut client = store_client(store);
    let read = client
        .read::<VolumeRecord>(Key::Volume(volume_id()))
        .unwrap();
    let next = VolumeRecord {
        layout: layout(),
        ..with_c_and_b()
    };
    client.replace(&read, next).unwrap();
}

#[test]
fn reads_feed_the_freshness_clock_at_their_send_times() {
    staged(|mut stage| {
        let (mut duties, store) = view_duties(&stage, None);
        let (fail, reads) = (Rc::clone(&store.fail), Rc::clone(&store.shard_reads));
        let mut model = Withhold::default();
        let mut adopted = 0;
        let mut withheld = Vec::new();
        let peer = Cell::new(None::<u64>);
        let (served, _) = stage.serve_until(
            |rounds, turn, stop| {
                if turn % 30 == 0 {
                    rounds.skip.set(rounds.skip.get() + 400_000);
                }
                let views = reads.borrow().len();
                fail.set(views >= 6);
                if views >= 40 {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                if fail.get() {
                    peer.set(Some(now));
                    owner.authority_event(
                        Event::Peer {
                            read_at: peer.get(),
                        },
                        now,
                    );
                    model.peer(peer.get());
                }
                let exit = duties.turn(owner, now);
                let logged = reads.borrow();
                let landed = logged.len() - usize::from(duties.viewing.is_some());
                for &(at, ok) in &logged[adopted..landed] {
                    if ok {
                        model.refresh(at);
                    } else {
                        model.failed(at);
                    }
                }
                adopted = landed;
                if duties.viewing.is_none() {
                    assert_eq!(owner.withhold(), model, "the freshness inputs at {now}");
                    withheld.push((model.withholds(now), owner.withhold().withholds(now)));
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(withheld.iter().all(|(model, owner)| model == owner));
        assert!(!withheld.first().unwrap().0, "fresh reads withhold nothing");
        assert!(
            withheld.last().unwrap().0,
            "failed reads past W_US beside peer reads withhold hits"
        );
        assert!(reads.borrow().iter().filter(|(_, ok)| !ok).count() as u64 * 400_000 > W_US);
    });
}

fn deferral(planted: bool) -> (Exit, bool, bool) {
    SNAPSHOT_AFTER_READS.with(|plant| plant.set(planted));
    let outcome = staged(|mut stage| {
        let (mut duties, _) = view_duties(&stage, None);
        let (store, registry) = (stage.store.clone(), stage.registry.clone());
        let mut phase = 0;
        let (mut deferred, mut cleared) = (false, false);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let turned = duties.turn(owner, now);
                let inline = duties.lane.inline_mut();
                match phase {
                    0 if duties.open == Open::Opened && duties.viewing.is_none() => {
                        inline.hold();
                        phase = 1;
                    }
                    1 if duties.viewing.is_some() => {
                        enroll_b(&store);
                        registry.borrow_mut().entries = vec![
                            registrant(own(), 1, true),
                            registrant(c_pair(), 2, false),
                            registrant(b_pair(), 3, false),
                        ];
                        phase = 2;
                    }
                    2 if owner.authority_report().pending => {
                        deferred = true;
                        inline.release();
                        phase = 3;
                    }
                    3 => {
                        inline.release();
                        cleared = !owner.authority_report().pending;
                    }
                    _ => {}
                }
                turned.or_else(|| cleared.then_some(Exit::Stopped))
            },
        );
        assert!(served.teardown.is_ok());
        (served.exit, deferred, cleared)
    });
    SNAPSHOT_AFTER_READS.with(|plant| plant.set(false));
    outcome
}

#[test]
fn a_pair_enrolled_after_the_last_view_clears_its_deferral_with_no_retirement() {
    let (exit, deferred, cleared) = deferral(false);
    assert!(deferred, "B's Report listing was deferred");
    assert!(cleared, "the next view's volume record enrolled B");
    assert_eq!(exit, Exit::Stopped, "no retirement request");
}

#[test]
fn a_report_snapshot_taken_after_the_reads_retires_the_volume() {
    let (exit, deferred, _) = deferral(true);
    assert!(deferred);
    assert!(matches!(exit, Exit::Retire(_)), "{exit:?}");
}

/// A standby registers only after its takeover write on the shard record commits, and every write of the open
/// conditions on the shard record's version. B's enrollment, takeover write and registration land before the Open's
/// first write: the Open issues that write, which the store refuses, and no reservation. The next view's volume
/// record enrolls B and its shard record shows B's tenure, so the tenure ends deposed with no retirement request.
#[test]
fn a_takeover_ends_a_running_open_at_its_next_write_and_the_next_view_deposes() {
    staged_over(warm_volume_certified(0), |mut stage| {
        designate(&stage.store, Some(b_host()));
        let (mut duties, logged) = view_duties(&stage, None);
        let (store, registry) = (stage.store.clone(), stage.registry.clone());
        let (writes, reads) = (
            Rc::clone(&logged.shard_writes),
            Rc::clone(&logged.shard_reads),
        );
        let taken = Rc::new(Cell::new(None::<usize>));
        let at_takeover = Rc::clone(&taken);
        let viewed = Rc::clone(&reads);
        // The Confirm is the tenure's first shard-record write and the Open's certification its second.
        let takeover = move || {
            enroll_b(&store);
            let mut b = store_client(&store);
            let read = b.read::<ShardRecord>(Key::Shard(shard())).unwrap();
            b.take_over(&read, Target::of(read.value()), b_host())
                .expect("B's takeover write");
            registry.borrow_mut().entries = vec![
                registrant(own(), 1, true),
                registrant(c_pair(), 2, false),
                registrant(b_pair(), 3, false),
            ];
            at_takeover.set(Some(viewed.borrow().len()));
        };
        *logged.before_shard_write.borrow_mut() = Some((2, Box::new(takeover)));
        duties.lane.inline_mut().hold();
        let (mut deferred, mut ended) = (false, None);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let exit = duties.turn(owner, now);
                // The Open's completion waits until a Report listed B's registration.
                deferred |= taken.get().is_some() && owner.authority_report().pending;
                if taken.get().is_none() || deferred {
                    duties.lane.inline_mut().release();
                }
                if exit.is_some() {
                    ended = Some(owner.authority_report());
                }
                exit
            },
        );
        assert!(deferred, "the authority deferred B's registration");
        assert_eq!(served.exit, Exit::Deposed, "no retirement request");
        let ended = ended.expect("the duty returned the exit");
        assert_eq!(
            (ended.state, ended.withdrawal, ended.flip),
            (State::Withdrawn, Some(Cause::Flipped), None)
        );
        assert_eq!(shard_now(&stage.store).owner, b_host());
        assert_eq!(
            writes.get(),
            2,
            "the Confirm, and the one write the Open issued after the takeover"
        );
        let views_before = taken.get().expect("the takeover ran inside the Open");
        assert_eq!(
            reads.borrow().len(),
            views_before + 1,
            "the first view after the takeover ended the tenure"
        );
    });
}

#[test]
fn a_later_tenure_in_the_view_ends_the_incarnation_deposed() {
    staged(|mut stage| {
        let (mut duties, _) = view_duties(&stage, None);
        let (store, registry) = (stage.store.clone(), stage.registry.clone());
        let start = stage.rounds.now.get();
        let mut taken = false;
        let mut deposed = None;
        let disks = stage.media.clone();
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if !taken && duties.open == Open::Opened && now >= start + 40 * TEST_VIEW_US {
                    let (disk, _control) = host_over(&registry, &disks, c_pair());
                    let arena = arena_with(16, 9);
                    let clock = Ticking::default();
                    let mut fencer = fencer_of(disk, c_pair(), &arena, &clock);
                    takeover_of(&store, c_host())
                        .run(&mut store_client(&store), &stored_c(), &mut fencer)
                        .expect("C's takeover");
                    taken = true;
                }
                let exit = duties.turn(owner, now);
                if exit.is_some() {
                    deposed = Some(owner.authority_report());
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Deposed);
        assert!(served.teardown.is_ok());
        assert_eq!(shard_now(&stage.store).owner, c_host());
        let deposed = deposed.expect("the duty returned the exit");
        assert_eq!((deposed.state, deposed.flip), (State::Withdrawn, None));
    });
}

#[test]
fn a_foreign_listing_parks_the_tenure_retired_with_no_write() {
    staged(|mut stage| {
        let listing = Listing::new(&Events::default());
        let (mut duties, _) = view_duties(&stage, Some(listing.clone()));
        let store = stage.store.clone();
        let mut commits = None;
        let mut retiring = None;
        for known in [
            holder().instance,
            instance_of(b_host()),
            instance_of(c_host()),
        ] {
            assert_ne!(known.as_str(), FOREIGN);
        }
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if duties.open == Open::Opened && commits.is_none() {
                    listing.set(Ok(foreign_listing()));
                    duties.listing_at = now;
                    commits = Some(store.0.borrow().commit_count(&Key::Shard(shard())));
                }
                let exit = duties.turn(owner, now);
                if exit.is_some() {
                    retiring = Some(owner.authority_report());
                }
                exit
            },
        );
        let target = Target::of(&shard_now(&stage.store));
        assert_eq!(served.exit, Exit::Retire(target));
        let retiring = retiring.expect("the duty returned the exit");
        assert_eq!(
            (retiring.state, retiring.withdrawal, retiring.flip),
            (State::Withdrawn, Some(Cause::Attachment), Some(target)),
            "the duty withdrew with the attachment cause and the flip"
        );
        assert!(served.exit.parks());
        let after = stage.store.0.borrow().commit_count(&Key::Shard(shard()));
        assert_eq!(Some(after), commits, "a retirement writes nothing");
        assert!(listing.calls() >= 2);
    });
}

#[test]
fn a_foreign_listing_after_a_planned_withdrawal_ends_the_tenure_withdrawn_with_no_write() {
    staged(|mut stage| {
        let listing = Listing::new(&Events::default());
        let (mut duties, _) = view_duties(&stage, Some(listing.clone()));
        let store = stage.store.clone();
        let mut commits = None;
        let mut adopted = None;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if commits.is_none() {
                    if duties.open == Open::Opened && duties.viewing.is_none() {
                        listing.set(Ok(foreign_listing()));
                        duties.listing_at = now;
                        commits = Some(store.0.borrow().commit_count(&Key::Shard(shard())));
                        duties.lane.inline_mut().hold();
                    }
                    return duties.turn(owner, now);
                }
                let captured = (duties.viewing.as_ref()).is_some_and(|(_, listed, _)| {
                    listed
                        .as_ref()
                        .is_some_and(|(listed, _)| listed.iter().any(|i| i == FOREIGN))
                });
                let inline = duties.lane.inline_mut();
                if !captured || adopted.is_some() {
                    while inline.release() {}
                    return duties.turn(owner, now);
                }
                if inline.held() == 0 {
                    return duties.turn(owner, now);
                }
                owner.authority_event(Event::Withdraw(Cause::Planned), now);
                while inline.release() {}
                let mut exit = None;
                for _ in 0..8 {
                    exit = duties.turn(owner, now);
                    if exit.is_some() || duties.viewing.is_none() {
                        break;
                    }
                }
                let report = owner.authority_report();
                let landed = duties.viewing.is_none();
                adopted = Some((landed, report.withdrawal, report.flip, exit.clone()));
                exit
            },
        );
        assert_eq!(
            adopted,
            Some((true, Some(Cause::Planned), None, None)),
            "the view with the foreign listing landed after the planned withdrawal, and its turn returned no exit"
        );
        assert_eq!(served.exit, Exit::Rerun(Rerun::Planned));
        assert!(!served.exit.parks());
        let after = stage.store.0.borrow().commit_count(&Key::Shard(shard()));
        assert_eq!(Some(after), commits, "the planned tenure writes nothing");
    });
}

#[test]
fn a_withdrawal_with_nobody_holding_keeps_viewing_each_period() {
    staged(|mut stage| {
        let (mut duties, store) = view_duties(&stage, None);
        let registry = stage.registry.clone();
        let reads = Rc::clone(&store.shard_reads);
        let mut withdrawn_at = None;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if withdrawn_at.is_some_and(|at| reads.borrow().len() >= at + 5) {
                    return Some(Exit::Stopped);
                }
                if duties.open == Open::Opened && withdrawn_at.is_none() {
                    for entry in &mut registry.borrow_mut().entries {
                        entry.holder = false;
                    }
                }
                if withdrawn_at.is_none() && owner.authority_report().state == State::Withdrawn {
                    assert_eq!(owner.authority_report().withdrawal, Some(Cause::Unheld));
                    withdrawn_at = Some(reads.borrow().len());
                }
                duties.turn(owner, now)
            },
        );
        assert_eq!(served.exit, Exit::Stopped, "five more views raised no exit");
    });
}

#[test]
fn with_no_control_plane_the_poll_is_unobserved_and_the_tenure_serves() {
    staged(|mut stage| {
        let (mut duties, store) = view_duties(&stage, None);
        let reads = Rc::clone(&store.shard_reads);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if reads.borrow().len() >= 8 {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                assert_eq!(owner.authority_report().state, State::Serving);
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(duties.unobserved() >= 6, "{}", duties.unobserved());
    });
}

#[test]
fn a_listing_past_its_deadline_counts_as_unread() {
    staged(|mut stage| {
        let listing = Listing::new(&Events::default());
        let (mut duties, _) = view_duties(&stage, Some(listing.clone()));
        let mut held_at = None;
        let mut late = None;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if late.is_some() {
                    return Some(Exit::Stopped);
                }
                let exit = duties.turn(owner, now);
                if duties.open == Open::Opened && held_at.is_none() && duties.plane.is_some() {
                    assert!(duties.listed.is_some(), "a prompt listing is read");
                    duties.lane.inline_mut().hold();
                    duties.listing_at = now;
                    held_at = Some(now);
                } else if let Some(at) = held_at {
                    let inline = duties.lane.inline_mut();
                    if now > at + 2 * 1_000 && late.is_none() {
                        while inline.release() {}
                    }
                    if duties.plane.is_some() && now > at + 2 * 1_000 {
                        late = Some(duties.listed.is_none());
                    }
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(late, Some(true), "the late listing counts as unread");
    });
}

#[test]
fn a_listing_due_with_a_view_runs_after_the_view() {
    staged(|mut stage| {
        let events = Events::default();
        let listing = Listing::new(&events);
        let (mut duties, _) = view_duties(&stage, Some(listing.clone()));
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if listing.calls() >= 2 {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| duties.turn(owner, now),
        );
        assert_eq!(served.exit, Exit::Stopped);
        let events = events.lock().unwrap();
        let first = events.iter().position(|event| *event == "listing").unwrap();
        assert_eq!(
            events[..first],
            ["view"],
            "the first listing ran after the first view"
        );
    });
}

/// A view is two store calls and can wait behind a running listing or a running drop, and the three complete
/// within the view period.
#[test]
fn periods_refuse_deadlines_that_reach_the_view_period() {
    let bounds = bounds_of(limits());
    // A drop ahead of the view: three store calls of 834 outlast the view period.
    assert_eq!(
        Periods::new(&bounds, 2_500, 60_000, (834, 500)),
        Err(PeriodRefusal::Deadlines)
    );
    let admitted = Periods::new(&bounds, 2_500, 60_000, (833, 500)).unwrap();
    assert_eq!(
        (admitted.store_deadline_us(), admitted.listing_deadline_us()),
        (833, 500),
        "the deadlines the store class and the control-plane class are built with"
    );
    assert_eq!(
        Periods::new(&bounds, 2_100, 60_000, (700, 100)),
        Err(PeriodRefusal::Deadlines)
    );
    assert!(Periods::new(&bounds, 2_101, 60_000, (700, 100)).is_ok());
    assert_eq!(
        Periods::new(&bounds, 2_500, 60_000, (u64::MAX, 500)),
        Err(PeriodRefusal::Deadlines)
    );
    assert_eq!(
        Periods::new(&bounds, 2_500, 60_000, (0, 500)),
        Err(PeriodRefusal::Deadlines)
    );
    assert_eq!(
        Periods::new(&bounds, 0, 60_000, (100, 100)),
        Err(PeriodRefusal::View)
    );
    assert_eq!(
        Periods::new(&bounds, 2_500, 60_000, (100, 0)),
        Err(PeriodRefusal::ListingDeadline)
    );
    for listing_us in [0, 2_499] {
        assert_eq!(
            Periods::new(&bounds, 2_500, listing_us, (100, 100)),
            Err(PeriodRefusal::Listing)
        );
    }
    assert!(Periods::new(&bounds, 2_500, 2_500, (100, 100)).is_ok());
    assert_eq!(
        Periods::new(&bounds, VIEW_MAX + 1, 60_000, (100, 100)),
        Err(PeriodRefusal::View)
    );
    assert_eq!(
        Periods::new(&bounds, VIEW_MAX, 60_000_000, (1_000_000, 1_000_001)),
        Err(PeriodRefusal::ListingDeadline)
    );
    assert_eq!(
        Periods::new(&bounds, VIEW_MAX, LISTING_US, (750_000, 1_000_000)),
        Err(PeriodRefusal::Deadlines)
    );
    assert!(Periods::new(&bounds, VIEW_MAX, LISTING_US, (749_999, 1_000_000)).is_ok());
    // Two reads of 1.4 s each and a listing of 1 s outlast the view period, under a window that would admit them.
    assert_eq!(
        Periods::new(
            &bounds_with(limits(), 6_000_000, 0),
            VIEW_MAX,
            LISTING_US,
            (1_400_000, 1_000_000)
        ),
        Err(PeriodRefusal::Deadlines)
    );
}

/// A poll's volume read follows the request of the listing it judges by at most the listing's deadline, the listing
/// period, one lane job ahead of the view and the view's volume read. `Periods::new` admits only periods whose sum
/// of those terms stays below `LISTING_HOLD_US`. A detach settle time must exceed that constant, and `Periods::new`
/// does not check the settle time.
#[test]
fn periods_refuse_a_listing_held_for_the_settle_floor() {
    let bounds = bounds_of(limits());
    // A store call ahead of the view: the listing's 100, the store call's 700 and the volume read's 700.
    let behind_a_store_call = LISTING_HOLD_US - 100 - 700 - 700;
    assert_eq!(
        Periods::new(&bounds, 2_500, behind_a_store_call, (700, 100)),
        Err(PeriodRefusal::Listing)
    );
    assert!(Periods::new(&bounds, 2_500, behind_a_store_call - 1, (700, 100)).is_ok());
    // A listing ahead of the view: the cached listing's 1_000, the running listing's 1_000 and the read's 500.
    let behind_a_listing = LISTING_HOLD_US - 1_000 - 1_000 - 500;
    assert_eq!(
        Periods::new(&bounds, 2_500, behind_a_listing, (500, 1_000)),
        Err(PeriodRefusal::Listing)
    );
    assert!(Periods::new(&bounds, 2_500, behind_a_listing - 1, (500, 1_000)).is_ok());
    assert_eq!(
        Periods::new(&bounds, 2_500, u64::MAX, (500, 1_000)),
        Err(PeriodRefusal::Listing)
    );
}

/// The poll that enrolls a standby completes within one serving window of the first Report that lists it. That
/// Report can be submitted its deadline before the registration, the next view is due one view period after the
/// last, a listing or the open's store call and the drop queued behind it run ahead of it, and it makes two store
/// calls.
#[test]
fn periods_refuse_a_view_that_outlasts_the_serving_window() {
    let report_us = limits().report_timeout();
    let windowed = |window| bounds_with(limits(), window, 0);
    let behind_a_listing = report_us + 2_500 + 1_000 + 2 * 500;
    assert_eq!(
        Periods::new(&windowed(behind_a_listing), 2_500, 60_000, (500, 1_000)),
        Err(PeriodRefusal::Window)
    );
    assert!(Periods::new(&windowed(behind_a_listing + 1), 2_500, 60_000, (500, 1_000)).is_ok());
    let behind_a_write_and_a_drop = report_us + 2_500 + 2 * 700 + 2 * 700;
    assert_eq!(
        Periods::new(
            &windowed(behind_a_write_and_a_drop),
            2_500,
            60_000,
            (700, 100)
        ),
        Err(PeriodRefusal::Window)
    );
    assert!(
        Periods::new(
            &windowed(behind_a_write_and_a_drop + 1),
            2_500,
            60_000,
            (700, 100)
        )
        .is_ok()
    );
    // A Report deadline of 1_800: a Report submitted at 0 lists a pair registered at 1_720, and its deferral
    // lapses at 3_800, before a view due 2_500 after one submitted at 1_600.
    let late_report = Bounds::new(8, 1, 3_800, 1_800, 1_900, 0).unwrap();
    assert_eq!(
        Periods::new(&late_report, 2_500, 60_000, (100, 1_000)),
        Err(PeriodRefusal::Window)
    );
    assert_eq!(
        Periods::new(&windowed(1_000_000), VIEW_MAX, LISTING_US, (1_000, 1_000)),
        Err(PeriodRefusal::Window)
    );
}

#[test]
fn a_failed_volume_read_admits_a_standby_the_last_volume_record_bound() {
    staged(serves_through_failed_volume_reads);
}

/// BIND-AT-ATTACH: C's attach entry binds C's instance, so the binding of the last volume record read holds no peer
/// for C. A view whose volume read fails still admits C's listed instance from that record, and each such view is
/// unobserved while the tenure serves.
#[test]
fn a_failed_volume_read_admits_a_standby_whose_entry_binds_its_instance() {
    let (store, media) = warm_volume_certified(1);
    bind_c(&store, EventKind::Attach);
    staged_over((store, media), serves_through_failed_volume_reads);
}

/// READ-ORDER with BIND-AT-ATTACH: a view that read the volume record after the listing was adopted produced the
/// last binding, and every later volume read fails, so each later view judges that older listing, which names C,
/// against the binding alone. The binding admits C's instance when the caller's lookup binds C, when C's attach
/// entry binds it and when C's ended entry binds it (ENDED-NEVER-RETIRES), so no view retires the volume, the
/// tenure serves and the listing result reads as matching.
#[test]
fn a_failed_volume_read_admits_an_older_listing_of_a_standby_whose_entry_binds_its_instance() {
    for entry in [None, Some(EventKind::Attach), Some(EventKind::Ended)] {
        let (store, media) = warm_volume_certified(1);
        if let Some(kind) = entry {
            bind_c(&store, kind);
        }
        serves_an_older_listing_through_failed_volume_reads((store, media), entry);
    }
}

/// Serves the stage of `volume` until a view that read the volume record after the listing's adoption produced the
/// binding, fails every later volume read, and requires that the views judging that listing, which names C, retire
/// nothing while the tenure serves. `entry` is the kind of C's entry when it binds C's instance.
fn serves_an_older_listing_through_failed_volume_reads(
    volume: (Shared, crate::storage::device::sim::Media),
    entry: Option<EventKind>,
) {
    staged_over(volume, |mut stage| {
        let listing = Listing::new(&Events::default());
        let (mut duties, store) = view_duties(&stage, Some(listing));
        let (fail, reads) = (Rc::clone(&store.fail_volume), Rc::clone(&store.shard_reads));
        let c = instance_of(c_host()).as_str().to_owned();
        let (mut failed_from, mut seen, mut judged) = (None, 0, 0);
        let mut withdrawal = None;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if failed_from.is_some_and(|from| reads.borrow().len() >= from + 6) {
                    return Some(Exit::Stopped);
                }
                let older = match (&duties.listed, &duties.peers) {
                    (Some((_, _, adopted)), Some((_, bound))) => adopted < bound,
                    _ => false,
                };
                let idle = duties.open == Open::Opened && duties.viewing.is_none();
                if failed_from.is_none() && idle && older {
                    fail.set(true);
                    duties.listing_at = u64::MAX;
                    failed_from = Some(reads.borrow().len());
                }
                let exit = duties.turn(owner, now);
                if let Some((_, listed, stamp)) = &duties.viewing
                    && failed_from.is_some()
                    && *stamp != seen
                {
                    seen = *stamp;
                    judged += usize::from(listed.as_ref().is_some_and(|(l, _)| l.contains(&c)));
                }
                withdrawal = withdrawal.or(owner.authority_report().withdrawal);
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped, "{entry:?}: no retirement");
        assert_eq!(withdrawal, None, "{entry:?}");
        assert!(
            judged >= 2,
            "{entry:?}: {judged} failed views judged the listing that names C"
        );
        assert_eq!(
            duties.enumeration,
            Enumeration::Matches,
            "{entry:?}: the failed views judged every listed record"
        );
        let (binding, _) = duties.peers.as_ref().expect("the binding");
        assert_eq!(
            binding.iter().map(|peer| peer.host).collect::<Vec<_>>(),
            [c_host()],
            "{entry:?}: the binding holds C once"
        );
    });
}

/// OWNER-EVENTS at a view that read its volume record: host B, which the caller's lookup does not bind, holds a
/// retained ended entry that binds B's instance and a later live attach that binds none and has no pair. The
/// binding for a later view without the record holds B through the ended entry. The view that read the record
/// judges the attach events by the peers its lookup bound, so B's unbound attach retires the volume.
#[test]
fn a_view_that_read_its_volume_record_judges_attach_events_by_the_lookup_bound_peers() {
    fn without_b(host: Host) -> Option<InstanceId> {
        (host != b_host()).then(|| instance_of(host))
    }
    staged(|mut stage| {
        let listing = Listing::new(&Events::default());
        let (mut duties, _) = view_duties(&stage, Some(listing));
        duties.records.instance = &without_b;
        let shared = stage.store.clone();
        let (mut planted, mut retiring) = (false, None);
        let (served, _) = stage.serve_until(
            |_, turn, stop| {
                if turn >= 2_000 {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let idle = duties.open == Open::Opened && duties.viewing.is_none();
                if !planted && idle && duties.peers.is_some() {
                    rewrite_volume(&shared, |record| {
                        let ended = record.push(EventKind::Attach, b_host(), ERA).unwrap();
                        let entry = (record.events.iter_mut())
                            .find(|event| event.seq == ended)
                            .unwrap();
                        entry.kind = EventKind::Ended;
                        entry.instance = Some(instance_of(b_host()));
                        record.push(EventKind::Attach, b_host(), ERA).unwrap();
                    });
                    planted = true;
                }
                let exit = duties.turn(owner, now);
                if exit.is_some() {
                    retiring = Some((owner.authority_report(), duties.peers.clone()));
                }
                exit
            },
        );
        let target = Target::of(&shard_now(&stage.store));
        assert_eq!(served.exit, Exit::Retire(target));
        let (retiring, binding) = retiring.expect("the duty returned the exit");
        assert_eq!(retiring.withdrawal, Some(Cause::Attachment));
        let (binding, _) = binding.expect("the retiring view bound the standbys");
        assert_eq!(
            binding.iter().map(|peer| peer.host).collect::<Vec<_>>(),
            [c_host(), b_host()],
            "the binding holds C by the lookup and B by its ended entry"
        );
    });
}

/// Binds C's instance in C's entry of the stored volume record and moves the entry to `kind`, as the reconciler's
/// standby attach binds it and its end of the attach marks it.
fn bind_c(store: &Shared, kind: EventKind) {
    rewrite_volume(store, |record| {
        let entry = (record.events.iter_mut())
            .rfind(|event| event.host == c_host())
            .unwrap();
        entry.kind = kind;
        entry.instance = Some(instance_of(c_host()));
    });
    assert!(!volume_now(store).bound_by_lookup(c_host()));
}

/// Replaces the stored volume record with `edit` of it by a raw exact-version write, as a writer outside this host
/// makes it, and requires that the decoder reads the result.
fn rewrite_volume(store: &Shared, edit: impl FnOnce(&mut VolumeRecord)) {
    let key = Key::Volume(volume_id());
    let item = store.0.borrow().current(&key).cloned().unwrap();
    let mut record = VolumeRecord::decode(&item.value).unwrap();
    edit(&mut record);
    assert_eq!(VolumeRecord::decode(&record.encode()), Ok(record.clone()));
    let write = Write::Exact {
        expect: item.version,
        value: record.encode(),
    };
    let mut raw = store.clone();
    assert!(matches!(
        Store::write(&mut raw, &key, &write),
        Outcome::Committed(_)
    ));
}

/// Serves `stage` under the clean listing of the owner and C, fails every volume read once the tenure is open and
/// the listing adopted, and requires five further views, each unobserved, with the tenure serving throughout.
fn serves_through_failed_volume_reads(mut stage: Stage<'_>) {
    {
        let listing = Listing::new(&Events::default());
        let (mut duties, store) = view_duties(&stage, Some(listing));
        let (fail, reads) = (Rc::clone(&store.fail_volume), Rc::clone(&store.shard_reads));
        let failed_from = Cell::new(None::<(usize, u64)>);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if failed_from
                    .get()
                    .is_some_and(|(from, _)| reads.borrow().len() >= from + 6)
                {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let listed = duties.listed.is_some() && duties.viewing.is_none();
                if duties.open == Open::Opened && listed && failed_from.get().is_none() {
                    fail.set(true);
                    failed_from.set(Some((reads.borrow().len(), duties.unobserved())));
                }
                assert_eq!(owner.authority_report().state, State::Serving);
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let (_, before) = failed_from.get().expect("the reads failed");
        assert!(
            duties.unobserved() >= before + 5,
            "each failed view is unobserved"
        );
        assert!(
            reads.borrow().iter().all(|(_, ok)| *ok),
            "the shard reads passed"
        );
    }
}

/// A view whose volume read fails still judges the listed records no standby binding could admit: the own
/// instance listed twice, or a standby listed twice, retires the volume with no write.
#[test]
fn a_failed_volume_read_still_retires_a_duplicate_own_attachment() {
    for twice in [holder().instance, instance_of(c_host())] {
        staged(|mut stage| {
            let listing = Listing::new(&Events::default());
            let (mut duties, store) = view_duties(&stage, Some(listing.clone()));
            let fail = Rc::clone(&store.fail_volume);
            let mut commits = None;
            let mut retiring = None;
            let (served, _) = stage.serve_until(
                |_, turn, stop| {
                    if turn >= 2_000 {
                        stop.store(true, Ordering::Release);
                    }
                },
                |owner, now| {
                    if duties.open == Open::Opened && commits.is_none() && duties.viewing.is_none()
                    {
                        let mut listed = clean_listing();
                        listed.push(twice.as_str().to_owned());
                        listing.set(Ok(listed));
                        fail.set(true);
                        duties.listing_at = now;
                        commits = Some(stage_commits(&store.inner));
                    }
                    let exit = duties.turn(owner, now);
                    if exit.is_some() {
                        retiring = Some(owner.authority_report());
                    }
                    exit
                },
            );
            let target = Target::of(&shard_now(&stage.store));
            let twice = twice.as_str();
            assert_eq!(served.exit, Exit::Retire(target), "{twice} listed twice");
            let retiring = retiring.expect("the duty returned the exit");
            assert_eq!(retiring.withdrawal, Some(Cause::Attachment));
            assert_eq!(
                Some(stage_commits(&stage.store)),
                commits,
                "a retirement writes nothing"
            );
        });
    }
}

fn stage_commits(store: &Shared) -> usize {
    store.0.borrow().commit_count(&Key::Shard(shard()))
}

/// A view adopted at or after the next view's due time leaves its adopting turn to the open's write and the listing,
/// so slow views still let the tenure open its suffix and list its attachments.
#[test]
fn views_adopted_late_leave_turns_for_the_open_and_the_listing() {
    staged(|mut stage| {
        let listing = Listing::new(&Events::default());
        let (mut duties, store) = view_duties(&stage, Some(listing.clone()));
        let reads = Rc::clone(&store.shard_reads);
        duties.lane.inline_mut().hold();
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if reads.borrow().len() >= 40 {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                if duties.open == Open::Opened && listing.calls() > 0 {
                    return Some(Exit::Stopped);
                }
                if duties.viewing.is_none() || now >= duties.view_at {
                    let inline = duties.lane.inline_mut();
                    while inline.release() {}
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(duties.open, Open::Opened, "the open reached its log");
        assert!(listing.calls() > 0, "a listing ran");
        assert!(reads.borrow().len() < 40);
    });
}

/// POST-WITHDRAWAL-POLL: under C's recorded hold, views whose shard reads fail keep the tenure withdrawn
/// with no exit, and the first view whose shard read names the tenure ends it `Rerun(RecordedHolder)`.
#[test]
fn a_recorded_holder_reruns_only_on_a_view_whose_shard_read_names_the_tenure() {
    staged(|mut stage| {
        let (mut duties, store) = view_duties(&stage, None);
        let registry = stage.registry.clone();
        let (fail, reads) = (Rc::clone(&store.fail), Rc::clone(&store.shard_reads));
        let (mut held, mut withdrawn_at) = (false, None);
        let mut exits = Vec::new();
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if !held && duties.open == Open::Opened && duties.viewing.is_none() {
                    fail.set(true);
                    registry.borrow_mut().entries =
                        vec![registrant(own(), 1, false), registrant(c_pair(), 2, true)];
                    held = true;
                }
                let withdrawal = owner.authority_report().withdrawal;
                if withdrawn_at.is_none() && withdrawal == Some(Cause::RecordedHolder) {
                    withdrawn_at = Some(reads.borrow().len());
                }
                if withdrawn_at.is_some_and(|at| reads.borrow().len() >= at + 3) {
                    fail.set(false);
                }
                let exit = duties.turn(owner, now);
                if let Some(exit) = &exit {
                    exits.push((exit.clone(), fail.get(), withdrawal));
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Rerun(Rerun::RecordedHolder));
        assert_eq!(
            exits,
            [(
                Exit::Rerun(Rerun::RecordedHolder),
                false,
                Some(Cause::RecordedHolder)
            )],
            "the failed views under the hold returned no exit"
        );
        let logged = reads.borrow();
        let at = withdrawn_at.expect("the tenure withdrew under the recorded holder");
        assert!(logged[at..].iter().filter(|(_, ok)| !ok).count() >= 2);
    });
}

/// A listing call that fails replaces the foreign listing before it: the next view's poll is unobserved and
/// retires nothing.
#[test]
fn an_unlisted_reply_after_a_foreign_listing_leaves_the_next_poll_unobserved() {
    staged(|mut stage| {
        let listing = Listing::new(&Events::default());
        let (mut duties, _) = view_duties(&stage, Some(listing.clone()));
        let (mut phase, mut calls, mut unobserved) = (0, 0, 0);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let exit = duties.turn(owner, now);
                let idle = duties.plane.is_some() && duties.viewing.is_none();
                match phase {
                    0 if duties.open == Open::Opened && idle => {
                        listing.set(Ok(foreign_listing()));
                        (duties.listing_at, duties.view_at) = (now, u64::MAX);
                        (calls, phase) = (listing.calls(), 1);
                    }
                    1 if idle && listing.calls() == calls + 1 => {
                        assert!(duties.listed.is_some(), "the foreign listing was read");
                        listing.set(Err(Unlisted));
                        duties.listing_at = now;
                        phase = 2;
                    }
                    2 if idle && listing.calls() == calls + 2 => {
                        assert!(duties.listed.is_none());
                        duties.view_at = now;
                        unobserved = duties.unobserved();
                        phase = 3;
                    }
                    3 if duties.unobserved() > unobserved => return Some(Exit::Stopped),
                    _ => {}
                }
                exit
            },
        );
        assert_eq!(
            served.exit,
            Exit::Stopped,
            "the failed listing retired nothing"
        );
    });
}

/// A shard read below the client's watermark withdraws the tenure under `Cause::Regression`, which reruns.
#[test]
fn a_regressed_view_read_withdraws_the_tenure() {
    staged(|mut stage| {
        let (mut duties, store) = view_duties(&stage, None);
        let reads = Rc::clone(&store.shard_reads);
        let (scheduled, mut withdrawal) = (Cell::new(None::<usize>), None);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if scheduled
                    .get()
                    .is_some_and(|at| reads.borrow().len() >= at + 3)
                {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let idle = duties.open == Open::Opened && duties.viewing.is_none();
                if scheduled.get().is_none() && idle {
                    store.inner.schedule(Arm::Pass);
                    store.inner.schedule(Arm::StaleCurrentRead);
                    scheduled.set(Some(reads.borrow().len()));
                }
                let exit = duties.turn(owner, now);
                withdrawal = withdrawal.or(owner.authority_report().withdrawal);
                exit
            },
        );
        assert_eq!(withdrawal, Some(Cause::Regression));
        assert_eq!(served.exit, Exit::Rerun(Rerun::Withdrawn));
    });
}

/// READ-ORDER: a view whose volume read fails judges a listing adopted before the view that produced the last binding
/// against that binding, so a duplicate standby or an instance outside the binding retires the volume with
/// `Cause::Attachment`. The test holds views back until the listing is adopted, then drops the listing from the
/// binding view's snapshot, so the failed read's view is the first poll to judge it.
#[test]
fn a_failed_volume_read_retires_an_older_listing_the_last_binding_refuses() {
    for (case, entry_binds) in [
        ("duplicate standby", false),
        ("foreign instance", false),
        ("duplicate standby whose entry binds it", true),
        (
            "foreign instance beside a standby whose entry binds it",
            true,
        ),
    ] {
        let (store, media) = warm_volume_certified(1);
        if entry_binds {
            bind_c(&store, EventKind::Attach);
        }
        staged_over((store, media), |mut stage| {
            let listing = Listing::new(&Events::default());
            let (mut duties, store) = view_duties(&stage, Some(listing.clone()));
            let fail = Rc::clone(&store.fail_volume);
            let (mut phase, mut calls) = (0, 0);
            let mut retiring = None;
            let (served, _) = stage.serve_until(
                |_, _, _| {},
                |owner, now| {
                    let exit = duties.turn(owner, now);
                    if exit.is_some() {
                        retiring = Some((owner.authority_report(), duties.peers.clone()));
                        return exit;
                    }
                    let idle = duties.plane.is_some() && duties.viewing.is_none();
                    match phase {
                        0 if duties.open == Open::Opened && idle => {
                            let mut listed = clean_listing();
                            listed.push(match case {
                                _ if case.starts_with("duplicate") => {
                                    instance_of(c_host()).as_str().to_owned()
                                }
                                _ => FOREIGN.to_owned(),
                            });
                            listing.set(Ok(listed));
                            (duties.listing_at, duties.view_at) = (now, u64::MAX);
                            (calls, phase) = (listing.calls(), 1);
                        }
                        1 if idle && listing.calls() == calls + 1 => {
                            assert!(duties.listed.is_some(), "{case}: the listing was adopted");
                            (duties.listing_at, duties.view_at) = (u64::MAX, now);
                            phase = 2;
                        }
                        2 if duties.viewing.is_some() => {
                            let snapshot = duties.viewing.as_mut().expect("the binding view");
                            assert!(snapshot.1.is_some(), "{case}: the view took the listing");
                            snapshot.1 = None;
                            fail.set(true);
                            phase = 3;
                        }
                        _ => {}
                    }
                    exit
                },
            );
            let target = Target::of(&shard_now(&stage.store));
            assert_eq!(phase, 3, "{case}");
            assert_eq!(served.exit, Exit::Retire(target), "{case}");
            let (retiring, peers) = retiring.expect("the duty returned the exit");
            assert_eq!(retiring.withdrawal, Some(Cause::Attachment), "{case}");
            let (peers, _) = peers.expect("the binding view bound the standbys");
            assert_eq!(peers.len(), 1, "{case}: the binding holds C alone");
        });
    }
}

/// READ-ORDER: B enrolls in the volume record and attaches after the last view that read the record, and every volume
/// read after it fails. The listing that names B is later than the last binding, so each poll judges only the listed
/// records no binding admits and retires nothing, while the device reservation fences B's writes.
#[test]
fn a_standby_attached_after_the_last_volume_read_retires_nothing_while_the_reads_fail() {
    let (exit, withdrawal, judged) = attached_after_the_binding(false);
    assert_eq!(exit, Exit::Stopped, "no retirement");
    assert_eq!(withdrawal, None, "the tenure kept serving");
    assert!(
        judged >= 2,
        "{judged} failed views judged a listing that names B"
    );
}

/// The planted control: with the last binding admitted for every listing, the same history retires the volume as an
/// attachment outside the binding.
#[test]
fn the_unbounded_binding_retires_a_standby_attached_after_the_last_volume_read() {
    let (exit, withdrawal, judged) = attached_after_the_binding(true);
    assert!(matches!(exit, Exit::Retire(_)), "{exit:?}");
    assert_eq!(withdrawal, Some(Cause::Attachment));
    assert!(judged >= 1);
}

/// Runs the history of B attached after the last volume read, returns the exit, the authority's withdrawal and the
/// number of views with a failed volume read whose snapshot listing named B.
fn attached_after_the_binding(unbounded: bool) -> (Exit, Option<Cause>, usize) {
    UNBOUNDED_BINDING.with(|plant| plant.set(unbounded));
    let outcome = staged(|mut stage| {
        let listing = Listing::new(&Events::default());
        let (mut duties, store) = view_duties(&stage, Some(listing.clone()));
        let (fail, reads) = (Rc::clone(&store.fail_volume), Rc::clone(&store.shard_reads));
        let shared = stage.store.clone();
        let b = instance_of(b_host()).as_str().to_owned();
        let (mut failed_from, mut seen, mut judged) = (None, 0, 0);
        let mut withdrawal = None;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if failed_from.is_some_and(|from| reads.borrow().len() >= from + 6) {
                    return Some(Exit::Stopped);
                }
                let bound = duties.peers.is_some();
                let idle = duties.open == Open::Opened && duties.viewing.is_none();
                if failed_from.is_none() && idle && bound {
                    enroll_b(&shared);
                    let mut listed = clean_listing();
                    listed.push(b.clone());
                    listing.set(Ok(listed));
                    fail.set(true);
                    duties.listing_at = now;
                    failed_from = Some(reads.borrow().len());
                }
                let exit = duties.turn(owner, now);
                if let Some((_, listed, stamp)) = &duties.viewing
                    && failed_from.is_some()
                    && *stamp != seen
                {
                    seen = *stamp;
                    judged += usize::from(listed.as_ref().is_some_and(|(l, _)| l.contains(&b)));
                }
                withdrawal = withdrawal.or(owner.authority_report().withdrawal);
                exit
            },
        );
        (served.exit, withdrawal, judged)
    });
    UNBOUNDED_BINDING.with(|plant| plant.set(false));
    outcome
}

#[test]
fn a_view_record_that_does_not_decode_ends_the_tenure() {
    for record in [Undecodable::Volume, Undecodable::Shard] {
        staged(|mut stage| {
            let (mut duties, store) = view_duties(&stage, None);
            let (undecodable, reads) =
                (Rc::clone(&store.undecodable), Rc::clone(&store.shard_reads));
            let mut from = None;
            let (served, _) = stage.serve_until(
                |_, _, _| {},
                |owner, now| {
                    if from.is_some_and(|from| reads.borrow().len() >= from + 4) {
                        return Some(Exit::Stopped);
                    }
                    let idle = duties.open == Open::Opened && duties.viewing.is_none();
                    if from.is_none() && idle {
                        undecodable.set(Some(record));
                        from = Some(reads.borrow().len());
                    }
                    duties.turn(owner, now)
                },
            );
            assert_eq!(served.exit, Exit::Rerun(Rerun::Withdrawn), "{record:?}");
            let from = from.expect("the record stopped decoding");
            assert_eq!(
                reads.borrow().len(),
                from + 1,
                "{record:?}: the first such view ended the tenure"
            );
        });
    }
}

#[test]
fn a_recorded_holder_reruns_on_a_naming_view_whose_snapshot_holds_no_report() {
    staged(|mut stage| {
        let (mut duties, store) = view_duties(&stage, None);
        let registry = stage.registry.clone();
        let (fail, reads) = (Rc::clone(&store.fail), Rc::clone(&store.shard_reads));
        let (mut phase, mut replaced_at) = (0, 0);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let exit = duties.turn(owner, now);
                let withdrawal = owner.authority_report().withdrawal;
                match phase {
                    0 if duties.open == Open::Opened && duties.viewing.is_none() => {
                        fail.set(true);
                        registry.borrow_mut().entries =
                            vec![registrant(own(), 1, false), registrant(c_pair(), 2, true)];
                        phase = 1;
                    }
                    1 if withdrawal == Some(Cause::RecordedHolder) && duties.viewing.is_none() => {
                        fail.set(false);
                        duties.lane.inline_mut().hold();
                        phase = 2;
                    }
                    2 if duties.viewing.is_some() => {
                        duties.viewing = Some((Err(NotSole::Unreadable), None, duties.stamp));
                        replaced_at = reads.borrow().len();
                        phase = 3;
                    }
                    3 if reads.borrow().len() >= replaced_at + 4 => return Some(Exit::Stopped),
                    _ => {}
                }
                if phase == 3 {
                    while duties.lane.inline_mut().release() {}
                }
                exit
            },
        );
        assert_eq!(phase, 3, "a view ran over a snapshot with no Report");
        assert_eq!(served.exit, Exit::Rerun(Rerun::RecordedHolder));
        assert_eq!(
            reads.borrow().len(),
            replaced_at,
            "the view over that snapshot ended the tenure"
        );
    });
}

#[test]
fn a_view_refreshes_the_freshness_clock_on_the_serving_clock() {
    const AHEAD_US: u64 = 3_600_000_000;
    staged_ahead(AHEAD_US, |mut stage| {
        let (mut duties, store) = view_duties(&stage, None);
        let reads = Rc::clone(&store.shard_reads);
        let mut ages = Vec::new();
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if reads.borrow().len() >= 8 {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                if reads.borrow().len() >= 4 && duties.viewing.is_none() {
                    ages.push(owner.authority_report().freshness_age_us);
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(!ages.is_empty(), "views were adopted");
        for age in ages {
            assert!(
                age.is_some_and(|age| age <= 2 * TEST_VIEW_US),
                "the read age {age:?} counts from the view's send on a serving clock {AHEAD_US} ahead"
            );
        }
    });
}
