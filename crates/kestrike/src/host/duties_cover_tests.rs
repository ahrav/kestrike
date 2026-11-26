use std::cell::RefCell;
use std::collections::VecDeque;
use std::num::NonZeroU16;
use std::rc::Rc;

use super::tests::{TEST_VIEW_US, periods, records};
use super::view_tests::{Events, Listing};
use super::{Duties, Open};
use crate::failover::records::CoveragePage;
use crate::failover::report::Resume;
use crate::failover::serving::{Cause, Event};
use crate::host::lane::tests::bounds;
use crate::host::lane::{Lane, Plane};
use crate::host::serve::loop_tests::{ROUND_US, Stage, TestOwner, staged};
use crate::host::{Exit, HostGate, Rerun};
use crate::net::DrainStage;
use crate::net::ownership::session_of;
use crate::storage::page_coverage::{
    Cover, Entry, Interval, PageRequest, Withdraw, decode_entries, page_len, page_of,
};
use crate::storage::store::sim::{Arm, MemLog, Shared};
use crate::storage::store::{Client, Item, Key, Outcome, Read, Store, Unavailable, Write};
use crate::storage::store_tests::{client as store_client, page as stored, shard};
use crate::storage::test_platform::TestPlatform;
use crate::storage::{CacheVersion, WorkBudget};

/// The page requests [`Paged`] arms: a write, or a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum On {
    PageWrite,
    PageRead,
}

/// The stage's store, logging each coverage page request as `(write, page)` and arming the next page request of a
/// kind with the arm queued for it; record views and record writes pass through unlogged and unarmed. Clones share
/// the log and the queue, so the test's handle sees the lane's requests.
#[derive(Clone)]
pub(super) struct Paged {
    inner: Shared,
    log: Rc<RefCell<Vec<(bool, u16)>>>,
    faults: Rc<RefCell<VecDeque<(On, Arm)>>>,
}

impl Paged {
    /// A paged store over `inner` with an empty log and no armed fault.
    pub(super) fn over(inner: &Shared) -> Self {
        Self {
            inner: inner.clone(),
            log: Rc::default(),
            faults: Rc::default(),
        }
    }

    fn arm(&self, on: On) {
        let mut faults = self.faults.borrow_mut();
        if faults.front().is_some_and(|(kind, _)| *kind == on) {
            let (_, arm) = faults.pop_front().unwrap();
            self.inner.0.borrow_mut().schedule(arm);
        }
    }

    fn requests(&self) -> usize {
        self.log.borrow().len()
    }

    fn on(&self, page: u16) -> Vec<bool> {
        let log = self.log.borrow();
        (log.iter())
            .filter(|(_, on)| *on == page)
            .map(|(write, _)| *write)
            .collect()
    }

    pub(super) fn fault(&self, on: On, arm: Arm) {
        self.faults.borrow_mut().push_back((on, arm));
    }
}

impl Store for Paged {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        if let Key::Page(_, page) = key {
            self.log.borrow_mut().push((false, *page));
            self.arm(On::PageRead);
        }
        self.inner.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        if let Key::Page(_, page) = key {
            self.log.borrow_mut().push((true, *page));
            self.arm(On::PageWrite);
        }
        self.inner.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

type PageDuties<'w> = Duties<'w, Paged, MemLog, TestPlatform>;

fn page_duties<'w>(stage: &Stage<'w>) -> (PageDuties<'w>, Paged) {
    page_duties_over(stage, None)
}

fn page_duties_over<'w>(stage: &Stage<'w>, plane: Option<Plane>) -> (PageDuties<'w>, Paged) {
    let store = Paged::over(&stage.store);
    let lane = Lane::inline(
        Client::open(store.clone(), MemLog::default()).unwrap(),
        stage.storage,
    );
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

pub(super) fn exclusive<S: Store>(duties: &Duties<'_, S, MemLog, TestPlatform>) {
    assert!(
        !duties.paging || duties.lane.outstanding() == 1,
        "a page job beside another unadopted job"
    );
}

pub(super) fn key_on(page: u16, pages: NonZeroU16, skip: usize) -> [u8; 32] {
    (0_u64..)
        .map(|n| {
            let mut key = [0x5a; 32];
            key[..8].copy_from_slice(&n.to_le_bytes());
            key
        })
        .filter(|key| page_of(key, pages) == page)
        .nth(skip)
        .unwrap()
}

pub(super) fn entry(key: [u8; 32]) -> Entry {
    (
        key,
        Interval::new(CacheVersion(3), CacheVersion(5)).unwrap(),
    )
}

pub(super) fn hold(owner: &mut TestOwner<'_>, entry: Entry) {
    let mut budget = WorkBudget::new(1024);
    owner
        .invalidate_interval(&entry.0, entry.1, 2, &mut budget)
        .expect("a held INVALIDATE");
}

pub(super) fn refused(owner: &mut TestOwner<'_>, key: &[u8; 32]) -> bool {
    !owner.coverage_mut().unwrap().admits(key, CacheVersion(4))
}

pub(super) fn commits(store: &Shared, page: u16) -> usize {
    store.0.borrow().commit_count(&Key::Page(shard(), page))
}

/// Whether the stored value of `page` blocks every version of `entry`: saturated, or holding an interval of its key
/// that contains the entry's, both bounds inclusive. A stored page whose entries do not decode fails the test.
pub(super) fn stored_covers(store: &Shared, page: u16, (key, interval): Entry) -> bool {
    let value = stored(store, page);
    let entries = decode_entries(&value.entries).expect("the stored page's entries decode");
    value.saturated
        || (entries.iter()).any(|(held, stored)| {
            *held == key && stored.low() <= interval.low() && interval.high() <= stored.high()
        })
}

pub(super) fn pages(owner: &mut TestOwner<'_>) -> NonZeroU16 {
    owner.coverage_mut().expect("the fencing").pages()
}

/// ACK-ON-COMMIT through the lane: three INVALIDATEs on one page and one on another, and a fifth held on the first
/// page while its write is in flight. While a page job's completion is held, no page request runs, every held entry
/// stays refused for FILL (COVER-BEFORE-SUBMIT) and counted held; each entry is acknowledged only once the stored
/// page covers it after a commit later than its hold, so the fifth waits for the first page's second write.
#[test]
fn each_page_is_acknowledged_only_after_its_write_committed() {
    staged(|mut stage| {
        let (mut duties, probe) = page_duties(&stage);
        let store = stage.store.clone();
        let mut held: Vec<(u16, Entry, usize)> = Vec::new();
        let mut acked: Vec<Entry> = Vec::new();
        let mut frozen = None;
        let (mut windows, mut opened_at) = (0, 0);
        let mut late = None;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if duties.open == Open::Opened && held.is_empty() {
                    let pages = pages(owner);
                    let (p, q) = (0, pages.get() - 1);
                    for (page, skip) in [(p, 0), (p, 1), (p, 2), (q, 0)] {
                        let entry = entry(key_on(page, pages, skip));
                        hold(owner, entry);
                        assert!(refused(owner, &entry.0), "COVER-BEFORE-SUBMIT");
                        held.push((page, entry, commits(&store, page)));
                    }
                    duties.lane.inline_mut().hold();
                }
                let exit = duties.turn(owner, now);
                exclusive(&duties);
                if held.is_empty() {
                    return exit;
                }
                let inline = duties.lane.inline_mut();
                if duties.paging
                    && inline.held() > 0
                    && frozen.is_none()
                    && probe.requests() > opened_at
                {
                    frozen = Some((now, probe.requests()));
                    (windows, opened_at) = (windows + 1, probe.requests());
                }
                if let Some((at, count)) = frozen {
                    if now < at + 20 * ROUND_US {
                        assert_eq!(
                            probe.requests(),
                            count,
                            "no page request while its completion is held"
                        );
                        assert_eq!(owner.held_invalidations(), held.len() - acked.len());
                        for (_, entry, _) in &held {
                            if !acked.contains(entry) {
                                assert!(refused(owner, &entry.0), "COVER-BEFORE-SUBMIT");
                            }
                        }
                        if late.is_none() {
                            let pages = pages(owner);
                            let entry = entry(key_on(0, pages, 3));
                            hold(owner, entry);
                            held.push((0, entry, commits(&store, 0)));
                            late = Some(entry);
                        }
                    } else {
                        while duties.lane.inline_mut().release() {}
                        frozen = None;
                    }
                } else {
                    while inline.release() {}
                }
                for entry in duties.acknowledged() {
                    assert!(!acked.contains(entry), "each entry is acknowledged once");
                    let (page, _, was) = held.iter().find(|(_, held, _)| held == entry).unwrap();
                    assert!(
                        commits(&store, *page) > *was && stored_covers(&store, *page, *entry),
                        "page {page} acknowledged before a write covering the entry committed"
                    );
                    acked.push(*entry);
                }
                if acked.len() == held.len() && late.is_some() {
                    return Some(Exit::Stopped);
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(acked.len(), 5);
        assert!(
            windows >= 2,
            "each page's write waited held, {windows} windows"
        );
        let late = late.unwrap();
        let first = acked.iter().position(|entry| *entry == late).unwrap();
        assert!(
            first == 4,
            "the late entry waits for its own write: {acked:?}"
        );
    });
}

fn bump_page(store: &Shared, page: u16) {
    let mut client = store_client(store);
    let read: Read<CoveragePage> = client.read(Key::Page(shard(), page)).unwrap();
    let same = read.value().clone();
    client.replace(&read, same).unwrap();
}

/// A size rejection of page 0's merged write re-reads the page and writes it saturated: the saturation refuses a
/// FILL of another key of the page before the saturated write is submitted, a key of another page stays admitted,
/// and the entry is acknowledged only after the saturated write committed. Page `B - 1`, whose version moved under
/// the tenure's basis, fails its condition, is re-read and written again without a view-period wait, and its entry
/// is acknowledged only after that write committed.
#[test]
fn a_size_rejection_saturates_and_a_failed_condition_rereads_before_any_acknowledgment() {
    staged(|mut stage| {
        let (mut duties, probe) = page_duties(&stage);
        let store = stage.store.clone();
        let mut phase = 0;
        let mut pending: Option<(u16, Entry, usize)> = None;
        let mut saturating = false;
        let mut reread_at = None;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let pages = pages(owner);
                let (probe_key, other) = (key_on(0, pages, 1), key_on(pages.get() - 1, pages, 1));
                if duties.open == Open::Opened && pending.is_none() {
                    let page = if phase == 0 { 0 } else { pages.get() - 1 };
                    let entry = entry(key_on(page, pages, 0));
                    if phase == 0 {
                        let current = store.0.borrow().current(&Key::Page(shard(), page)).cloned();
                        store.0.borrow_mut().limit = current.unwrap().value.len() + 8;
                        assert!(!refused(owner, &probe_key), "admitted before the rejection");
                    } else {
                        store.0.borrow_mut().limit = usize::MAX;
                        bump_page(&store, page);
                    }
                    pending = Some((page, entry, commits(&store, page)));
                    hold(owner, entry);
                }
                let exit = duties.turn(owner, now);
                let Some((page, entry, was)) = pending else {
                    return exit;
                };
                if phase == 0 && probe.on(0) == [true, false] && !duties.paging {
                    assert!(
                        duties.page_next.is_some(),
                        "the saturated write waits a turn"
                    );
                    assert!(
                        refused(owner, &probe_key),
                        "the saturation precedes its write"
                    );
                    assert!(!refused(owner, &other), "another page stays admitted");
                    saturating = true;
                }
                if phase == 1 && probe.on(page) == [true, false] && reread_at.is_none() {
                    reread_at = Some(now);
                }
                if duties.acknowledged().contains(&entry) {
                    assert!(commits(&store, page) > was, "acknowledged after a commit");
                    assert!(stored_covers(&store, page, entry));
                    assert_eq!(probe.on(page), [true, false, true], "write, re-read, write");
                    match phase {
                        0 => {
                            assert!(saturating, "the pre-submit window was reached");
                            assert!(stored(&store, page).saturated);
                            store.0.borrow_mut().limit = usize::MAX;
                            (phase, pending) = (1, None);
                        }
                        _ => {
                            let waited = now - reread_at.unwrap();
                            assert!(waited < 10 * ROUND_US, "no view-period wait: {waited}");
                            return Some(Exit::Stopped);
                        }
                    }
                } else {
                    assert_eq!(owner.held_invalidations(), 1, "held until a commit");
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(phase, 1);
    });
}

/// Serves a tenure whose page 0 the store replaces with one fenced at `fence(own)`, above the tenure's session, with
/// one INVALIDATE held on it. The turn that adopts the page's re-read returns `exit`, the incarnation's exit, with
/// the held entry dropped unacknowledged and the authority withdrawn on the planted fence.
fn a_newer_fence_ends_the_tenure(fence: impl Fn(u64) -> u64, exit: &Exit) {
    staged(|mut stage| {
        let (mut duties, _) = page_duties(&stage);
        let store = stage.store.clone();
        let (mut held, mut observed) = (false, false);
        let mut planted = 0;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if duties.open == Open::Opened && !held {
                    let pages = pages(owner);
                    let mut client = store_client(&store);
                    let read: Read<CoveragePage> = client.read(Key::Page(shard(), 0)).unwrap();
                    planted = fence(read.value().fence);
                    let newer = CoveragePage {
                        fence: planted,
                        ..read.value().clone()
                    };
                    client.replace(&read, newer).unwrap();
                    hold(owner, entry(key_on(0, pages, 0)));
                    assert_eq!(owner.held_invalidations(), 1);
                    held = true;
                }
                let turn = duties.turn(owner, now);
                assert!(duties.acknowledged().is_empty(), "nothing is acknowledged");
                if let Some(turn) = &turn {
                    assert_eq!(turn, exit, "the turn names the incarnation's exit");
                    assert_eq!(owner.held_invalidations(), 0, "the held entry drops");
                    assert_eq!(
                        owner.authority_report().withdrawal,
                        Some(Cause::NewerFence {
                            page: 0,
                            fence: planted
                        })
                    );
                    observed = true;
                }
                turn
            },
        );
        assert!(observed, "the turn returned the exit");
        assert_eq!(&served.exit, exit);
        assert!(served.teardown.is_ok());
    });
}

/// A page fenced by a later activated session withdraws the tenure on the page's re-read: the held entry drops
/// unacknowledged, the authority withdraws on the newer fence, and the turn returns `Deposed` before teardown.
#[test]
fn a_newer_fence_on_the_page_withdraws_and_drops_the_held_entries() {
    a_newer_fence_ends_the_tenure(|own| own + (1 << 33), &Exit::Deposed);
}

/// A page fence above the tenure's session that is no activated session shows no later tenure, here generation
/// `u32::MAX`, which `Session::activate` refuses: the turn returns `Rerun(Withdrawn)`, the exit the authority names.
#[test]
fn a_newer_fence_of_no_activated_session_reruns() {
    a_newer_fence_ends_the_tenure(
        |own| session_of(u32::MAX, own as u32),
        &Exit::Rerun(Rerun::Withdrawn),
    );
}

/// An unknown outcome of a write that committed acknowledges nothing and holds every page job one view period from
/// its completion. The retry fails its condition on the committed write, the re-read answers, and the write after it
/// goes out on a later turn with no second wait; the entry is acknowledged only after that write committed.
#[test]
fn an_unknown_outcome_waits_one_view_period_and_acknowledges_only_a_later_commit() {
    staged(|mut stage| {
        let (mut duties, probe) = page_duties(&stage);
        let store = stage.store.clone();
        let mut pending: Option<Entry> = None;
        let mut issued: Vec<u64> = Vec::new();
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if duties.open == Open::Opened && pending.is_none() {
                    let entry = entry(key_on(0, pages(owner), 0));
                    probe.fault(On::PageWrite, Arm::Timeout { commit: true });
                    hold(owner, entry);
                    pending = Some(entry);
                }
                let before = probe.requests();
                let exit = duties.turn(owner, now);
                let Some(entry) = pending else {
                    return exit;
                };
                issued.extend((before..probe.requests()).map(|_| now));
                if duties.acknowledged().contains(&entry) {
                    assert_eq!(probe.on(0), [true, true, false, true]);
                    assert!(stored_covers(&store, 0, entry));
                    return Some(Exit::Stopped);
                }
                assert!(duties.acknowledged().is_empty());
                assert_eq!(owner.held_invalidations(), 1, "held until a later commit");
                assert!(refused(owner, &entry.0));
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let [unknown, retry, reread, rewrite] = issued[..] else {
            panic!("four page requests: {issued:?}");
        };
        assert!(
            retry - unknown >= TEST_VIEW_US,
            "the retry waits a view period"
        );
        assert!(
            retry - unknown <= TEST_VIEW_US + 5 * ROUND_US,
            "and resumes"
        );
        assert!(
            rewrite - reread < 5 * ROUND_US,
            "an answered re-read adds no wait"
        );
    });
}

/// A withdrawal or a close that lands while a page write is in flight: the committed write is adopted as the page's
/// known value, nothing is acknowledged, and every held entry, the one on another page included, drops at once.
#[test]
fn an_authority_change_during_a_page_write_acknowledges_nothing() {
    for event in [Event::Withdraw(Cause::Unheld), Event::Close] {
        staged(|mut stage| {
            let (mut duties, probe) = page_duties(&stage);
            let store = stage.store.clone();
            let (mut held, mut changed, mut adopted) = (false, false, false);
            let (served, _) = stage.serve_until(
                |_, _, _| {},
                |owner, now| {
                    if duties.open == Open::Opened && !held {
                        let pages = pages(owner);
                        hold(owner, entry(key_on(0, pages, 0)));
                        hold(owner, entry(key_on(pages.get() - 1, pages, 0)));
                        duties.lane.inline_mut().hold();
                        held = true;
                    }
                    let exit = duties.turn(owner, now);
                    if !held {
                        return exit;
                    }
                    if duties.paging && !changed {
                        owner.authority_event(event, now);
                        changed = true;
                    } else if changed && !duties.paging && !adopted {
                        assert!(duties.acknowledged().is_empty(), "{event:?}");
                        assert_eq!(owner.held_invalidations(), 0, "{event:?}");
                        let current = store.0.borrow().current(&Key::Page(shard(), 0)).cloned();
                        let known = owner.coverage_mut().unwrap().known(0).map(Read::version);
                        assert_eq!(known, current.map(|item| item.version), "{event:?}");
                        adopted = true;
                    } else if adopted {
                        assert_eq!(probe.on(0), [true], "{event:?}: no later page request");
                        return Some(Exit::Stopped);
                    }
                    if changed {
                        while duties.lane.inline_mut().release() {}
                    }
                    exit
                },
            );
            match event {
                // A closed authority ends the tenure at the turn of the close, ahead of the duty's adoption.
                Event::Close => {
                    assert_eq!(served.exit, Exit::Rerun(Rerun::Withdrawn));
                    assert!(duties.acknowledged().is_empty());
                    assert_eq!(probe.on(0), [true], "no later page request");
                }
                _ => {
                    assert!(adopted, "{event:?}");
                    assert_eq!(served.exit, Exit::Stopped);
                }
            }
        });
    }
}

/// A withdrawal after a size rejection's re-read, while the saturated write waits for its turn, drops the write:
/// no further page request reaches the store and nothing is acknowledged.
#[test]
fn a_withdrawal_drops_a_waiting_follow_up_request() {
    staged(|mut stage| {
        let (mut duties, probe) = page_duties(&stage);
        let store = stage.store.clone();
        let (mut held, mut withdrawn_at) = (false, None);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if duties.open == Open::Opened && !held {
                    let current = store.0.borrow().current(&Key::Page(shard(), 0)).cloned();
                    store.0.borrow_mut().limit = current.unwrap().value.len() + 8;
                    let entry = entry(key_on(0, pages(owner), 0));
                    hold(owner, entry);
                    held = true;
                }
                let exit = duties.turn(owner, now);
                assert!(duties.acknowledged().is_empty());
                if held
                    && withdrawn_at.is_none()
                    && duties.page_next.is_some()
                    && probe.on(0).len() == 2
                {
                    owner.authority_event(Event::Withdraw(Cause::Unheld), now);
                    withdrawn_at = Some(now);
                }
                if let Some(at) = withdrawn_at {
                    assert_eq!(probe.on(0), [true, false], "the saturated write is dropped");
                    if now > at + 30 * ROUND_US {
                        assert!(duties.page_next.is_none());
                        return Some(Exit::Stopped);
                    }
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(withdrawn_at.is_some());
    });
}

/// Store capacity returns before the next `duties.turn`. Draining mutations and resuming with `Resume::Cut` in that
/// interval discards the pending saturated write. An owner that stays open issues it.
#[test]
fn a_drain_and_a_resume_drop_a_waiting_follow_up_request() {
    for drained in [true, false] {
        staged(|mut stage| {
            let (mut duties, probe) = page_duties(&stage);
            let store = stage.store.clone();
            let (mut held, mut waiting_at) = (false, None);
            let (served, _) = stage.serve_until(
                |_, _, _| {},
                |owner, now| {
                    if duties.open == Open::Opened && !held {
                        let current = store.0.borrow().current(&Key::Page(shard(), 0)).cloned();
                        store.0.borrow_mut().limit = current.unwrap().value.len() + 8;
                        let entry = entry(key_on(0, pages(owner), 0));
                        hold(owner, entry);
                        held = true;
                    }
                    let exit = duties.turn(owner, now);
                    if held
                        && waiting_at.is_none()
                        && duties.page_next.is_some()
                        && probe.on(0).len() == 2
                    {
                        store.0.borrow_mut().limit = usize::MAX;
                        if drained {
                            owner.drain(DrainStage::Mutations, now);
                            assert!(owner.resume(Resume::Cut), "the resume reopens admission");
                        }
                        waiting_at = Some((now, commits(&store, 0)));
                    }
                    let Some((at, before)) = waiting_at else {
                        return exit;
                    };
                    if !drained {
                        return (probe.on(0).len() == 3).then_some(Exit::Stopped).or(exit);
                    }
                    assert_eq!(probe.on(0), [true, false], "the saturated write is dropped");
                    assert!(duties.acknowledged().is_empty());
                    if now > at + 30 * ROUND_US {
                        assert!(duties.page_next.is_none());
                        assert_eq!(commits(&store, 0), before, "no page commit");
                        assert!(!stored(&store, 0).saturated);
                        return Some(Exit::Stopped);
                    }
                    exit
                },
            );
            assert_eq!(served.exit, Exit::Stopped, "{drained}");
            assert!(waiting_at.is_some(), "{drained}");
            if !drained {
                assert_eq!(probe.on(0), [true, false, true], "the saturated write");
                assert!(stored(&store, 0).saturated);
            }
        });
    }
}

/// A store rejection of the saturated write withdraws the fencing with no authority event: the turn that adopts it
/// ends the incarnation with `Rerun::Withdrawn`, with the held entry dropped, no authority withdrawal and the
/// fencing's coverage closed, and nothing is acknowledged.
#[test]
fn a_rejected_saturated_write_ends_the_tenure() {
    staged(|mut stage| {
        let (mut duties, probe) = page_duties(&stage);
        let store = stage.store.clone();
        let (mut held, mut observed) = (false, false);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if duties.open == Open::Opened && !held {
                    store.0.borrow_mut().limit = page_len(0) - 1;
                    let entry = entry(key_on(0, pages(owner), 0));
                    hold(owner, entry);
                    held = true;
                }
                let exit = duties.turn(owner, now);
                assert!(duties.acknowledged().is_empty(), "nothing is acknowledged");
                if exit.is_some() {
                    assert_eq!(owner.held_invalidations(), 0);
                    assert_eq!(owner.authority_report().withdrawal, None);
                    assert!(owner.coverage_mut().unwrap().coverage().is_none());
                    observed = true;
                }
                exit
            },
        );
        assert!(observed, "the turn returned the exit");
        assert_eq!(served.exit, Exit::Rerun(Rerun::Withdrawn));
        assert_eq!(
            probe.on(0),
            [true, false, true],
            "write, re-read, saturated write"
        );
    });
}

/// A coverage step that fails after the authority withdrew takes the authority's exit: on a flip the adopting turn
/// itself returns `Deposed`, and under `Unheld`, which names no exit, the turn returns none and the post-withdrawal
/// view keeps running with no further page request.
#[test]
fn a_failed_page_step_takes_the_withdrawn_authoritys_exit() {
    for (cause, expected) in [(Cause::Flipped, Some(Exit::Deposed)), (Cause::Unheld, None)] {
        staged(|mut stage| {
            let (mut duties, probe) = page_duties(&stage);
            let store = stage.store.clone();
            let (mut held, mut adopted, mut views) = (false, None, 0);
            let (served, _) = stage.serve_until(
                |_, _, _| {},
                |owner, now| {
                    if duties.open == Open::Opened && !held {
                        store.0.borrow_mut().limit = page_len(0) - 1;
                        let entry = entry(key_on(0, pages(owner), 0));
                        hold(owner, entry);
                        held = true;
                    }
                    let saturated_held = duties.lane.inline_mut().held() > 0;
                    if saturated_held && adopted.is_none() {
                        duties.lane.inline_mut().release();
                        owner.authority_event(Event::Withdraw(cause), now);
                        let exit = duties.turn(owner, now);
                        assert_eq!(exit, expected, "{cause:?}");
                        adopted = Some(now);
                        return exit;
                    }
                    let viewing = duties.viewing.is_some();
                    let exit = duties.turn(owner, now);
                    if held && probe.on(0) == [true, false] && duties.page_next.is_some() {
                        duties.lane.inline_mut().hold();
                    }
                    if let Some(at) = adopted {
                        while duties.lane.inline_mut().release() {}
                        assert_eq!(probe.on(0), [true, false, true], "{cause:?}");
                        views += usize::from(!viewing && duties.viewing.is_some());
                        if now > at + 10 * TEST_VIEW_US {
                            return Some(Exit::Stopped);
                        }
                    }
                    exit
                },
            );
            assert!(adopted.is_some(), "{cause:?}");
            match expected {
                Some(exit) => assert_eq!(served.exit, exit),
                None => {
                    assert_eq!(served.exit, Exit::Stopped);
                    assert!(views >= 2, "the view keeps running: {views}");
                }
            }
        });
    }
}

/// An unavailable re-read after a failed condition carries no value of the page: nothing is acknowledged, every
/// held entry stays held and refused for FILL, and no page request of either held page goes out until one view period
/// after the re-read; then each page is acknowledged after its own commit.
#[test]
fn an_unavailable_reread_waits_one_view_period_for_every_page() {
    staged(|mut stage| {
        let (mut duties, probe) = page_duties(&stage);
        let store = stage.store.clone();
        let mut held: Vec<(u16, Entry, usize)> = Vec::new();
        let mut issued: Vec<(u64, bool, u16)> = Vec::new();
        let mut acked: Vec<Entry> = Vec::new();
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if duties.open == Open::Opened && held.is_empty() {
                    let pages = pages(owner);
                    bump_page(&store, 0);
                    probe.fault(On::PageRead, Arm::Unavailable);
                    for page in [0, pages.get() - 1] {
                        let entry = entry(key_on(page, pages, 0));
                        hold(owner, entry);
                        held.push((page, entry, commits(&store, page)));
                    }
                }
                let before = probe.requests();
                let exit = duties.turn(owner, now);
                exclusive(&duties);
                let log = probe.log.borrow().clone();
                issued.extend(
                    log[before..]
                        .iter()
                        .map(|&(write, page)| (now, write, page)),
                );
                for entry in duties.acknowledged() {
                    let (page, _, was) = held.iter().find(|(_, held, _)| held == entry).unwrap();
                    assert!(commits(&store, *page) > *was && stored_covers(&store, *page, *entry));
                    acked.push(*entry);
                }
                if !held.is_empty() && acked.is_empty() {
                    assert_eq!(owner.held_invalidations(), 2);
                    for (_, entry, _) in &held {
                        assert!(refused(owner, &entry.0));
                    }
                }
                if !held.is_empty() && acked.len() == held.len() {
                    return Some(Exit::Stopped);
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let [(_, true, 0), (reread, false, 0), (resumed, _, _), ..] = issued[..] else {
            panic!("a failed write, then its re-read: {issued:?}");
        };
        assert!(
            resumed - reread >= TEST_VIEW_US,
            "no page request during the wait"
        );
        assert!(
            resumed - reread <= TEST_VIEW_US + 5 * ROUND_US,
            "and resumes"
        );
    });
}

/// The owner's split halves keep one write in flight: a second `cover_begin` starts nothing, an unpaired reply
/// leaves the write in flight, and a continuation that arrives after the authority closed is dropped as
/// unresolved, with no further store request and nothing acknowledged.
#[test]
fn the_owner_drops_a_continuation_once_its_authority_closed() {
    staged(|mut stage| {
        let (mut duties, _) = page_duties(&stage);
        let store = stage.store.clone();
        let mut ran = false;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if duties.open != Open::Opened {
                    return duties.turn(owner, now);
                }
                let current = store.0.borrow().current(&Key::Page(shard(), 0)).cloned();
                store.0.borrow_mut().limit = current.unwrap().value.len() + 8;
                let entry = entry(key_on(0, pages(owner), 0));
                hold(owner, entry);
                let mut client = store_client(&store);
                let request = owner.cover_begin(None, now).unwrap().expect("a page write");
                assert!(
                    owner.cover_begin(None, now).unwrap().is_none(),
                    "one write in flight"
                );
                let stray = PageRequest::reread(shard(), 0).run(&mut client);
                let mut acknowledged = Vec::new();
                assert_eq!(
                    owner.cover_end(stray, &mut acknowledged, now).err(),
                    Some(Withdraw::Unpaired)
                );
                assert!(
                    owner.cover_begin(None, now).unwrap().is_none(),
                    "still in flight"
                );
                let rejected = request.run(&mut client);
                let committed = commits(&store, 0);
                owner.authority_event(Event::Close, now);
                let ended = owner.cover_end(rejected, &mut acknowledged, now);
                assert!(matches!(ended, Ok(Cover::Unresolved)), "{ended:?}");
                assert!(acknowledged.is_empty());
                assert_eq!(owner.held_invalidations(), 0);
                assert_eq!(commits(&store, 0), committed);
                ran = true;
                Some(Exit::Stopped)
            },
        );
        assert!(ran);
        assert_eq!(
            served.exit,
            Exit::Rerun(Rerun::Withdrawn),
            "the closed authority's exit outranks the duty's"
        );
    });
}

/// `Duties::acknowledged` names a turn's acknowledgments: an entry held again after its acknowledgment is
/// acknowledged a second time by its second write, and no turn between repeats either acknowledgment.
#[test]
fn an_entry_held_twice_is_acknowledged_once_per_write() {
    staged(|mut stage| {
        let (mut duties, _) = page_duties(&stage);
        let store = stage.store.clone();
        let mut pending: Option<(Entry, usize)> = None;
        let (mut turns, mut holds) = (0, 0);
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                if duties.open == Open::Opened && pending.is_none() {
                    let entry = entry(key_on(0, pages(owner), 0));
                    hold(owner, entry);
                    holds += 1;
                    pending = Some((entry, commits(&store, 0)));
                }
                let exit = duties.turn(owner, now);
                let Some((entry, was)) = pending else {
                    return exit;
                };
                if duties.acknowledged().contains(&entry) {
                    assert!(commits(&store, 0) > was);
                    turns += 1;
                    if holds == 2 {
                        return Some(Exit::Stopped);
                    }
                    pending = None;
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(turns, 2, "one acknowledging turn per write");
    });
}

/// The page rotation restarts while the lane is idle: once the write of the last page is acknowledged and a turn
/// passed with nothing held, an entry held on the first page has its write issued by the next turn, and a turn with
/// nothing held and no write in flight issues no request.
#[test]
fn an_entry_held_after_an_idle_turn_is_written_on_the_next_turn() {
    staged(|mut stage| {
        let (mut duties, probe) = page_duties(&stage);
        let mut step = 0;
        let mut issued = 0;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let pages = pages(owner);
                let last = pages.get() - 1;
                if duties.open == Open::Opened && step == 0 {
                    hold(owner, entry(key_on(last, pages, 0)));
                    step = 1;
                }
                if step == 3 {
                    hold(owner, entry(key_on(0, pages, 0)));
                    issued = probe.requests();
                }
                let exit = duties.turn(owner, now);
                match step {
                    1 if !duties.acknowledged().is_empty() => {
                        assert_eq!(probe.on(last), [true], "the last page's write");
                        (step, issued) = (2, probe.requests());
                    }
                    2 => {
                        assert_eq!(probe.requests(), issued, "an idle turn issues nothing");
                        assert_eq!(owner.held_invalidations(), 0);
                        step = 3;
                    }
                    3 => {
                        assert_eq!(probe.on(0), [true], "the first page's write, this turn");
                        return Some(Exit::Stopped);
                    }
                    _ => {}
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(step, 3);
    });
}

/// When a listing and an INVALIDATE share a turn, the pending listing completion keeps the invalidation held. The
/// page write acknowledges the invalidation after listing adoption. Releasing the listing completion before the
/// next view is due isolates the listing's effect.
#[test]
fn a_page_write_waits_for_the_adoption_of_a_listing() {
    const WINDOW_US: u64 = 8 * ROUND_US;
    staged(|mut stage| {
        let plane = Plane(Box::new(Listing::new(&Events::default())));
        let (mut duties, probe) = page_duties_over(&stage, Some(plane));
        let mut listing = None;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let idle = duties.plane.is_some() && duties.lane.outstanding() == 0;
                if duties.open == Open::Opened
                    && listing.is_none()
                    && idle
                    && now + 2 * WINDOW_US < duties.view_at
                {
                    let held = entry(key_on(0, pages(owner), 0));
                    hold(owner, held);
                    duties.listing_at = now;
                    duties.lane.inline_mut().hold();
                    listing = Some((now, probe.requests()));
                }
                let exit = duties.turn(owner, now);
                exclusive(&duties);
                let Some((at, issued)) = listing else {
                    return exit;
                };
                if now < at + WINDOW_US {
                    assert!(duties.plane.is_none(), "the listing is unadopted");
                    assert_eq!(
                        probe.requests(),
                        issued,
                        "a page request beside an unadopted listing"
                    );
                    assert_eq!(owner.held_invalidations(), 1);
                } else {
                    while duties.lane.inline_mut().release() {}
                }
                if !duties.acknowledged().is_empty() {
                    assert!(duties.plane.is_some(), "the listing was adopted first");
                    return Some(Exit::Stopped);
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(listing.is_some(), "the listing and the hold shared a turn");
        assert_eq!(probe.on(0), [true], "one write of the page");
    });
}
