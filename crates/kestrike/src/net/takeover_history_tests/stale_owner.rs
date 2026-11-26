//! Five hand-written histories of a deposed owner and its successor, each under the three owner clock strategies.
//!
//! C takes the volume over, serves, and holds an INVALIDATE of one object. The successor is the reconciler's
//! designation of a fresh host D and D's `Takeover::run`, placed by the shared store hook inside C's store requests,
//! or, in `so4`, while C is paused. D then serves and reads every object. Every fault is a field of [`Case`]: the
//! placement names the history row, which fixes its store arm and its pause, and the world draws nothing, so a case
//! replays from its name.
//!
//! | Placement | Fault | Required |
//! | --- | --- | --- |
//! | `so0` | none | C acknowledges and keeps serving |
//! | `so1` | D after the store commits and acknowledges C's page write, before C receives the reply | C acknowledges; D misses the covered object; C's next GET surfaces no byte |
//! | `so2` | C's page write commits with an unknown reply; D after the retry | the retry's coverage call returns `NewerFence` and acknowledges nothing |
//! | `so3` | as `so2`; D after the reread | C acknowledges nothing and withdraws at its next page write or Report |
//! | `so4` | C paused across D's takeover with a client GET waiting | no byte from C is surfaced |
//!
//! The agreed properties the histories judge:
//!
//! - Safety is the same under every clock strategy: WINDOW-IS-AVAILABILITY of the serving machine. The Report window
//!   admits work and never fences it, so `Slow` and `Frozen`, which break the serving clock's elapsed-time contract,
//!   change when C observes its deposition and never a verdict.
//! - [`quiet_after`]: after C observes its deposition it sends no frame, its device accepts no write, the media keeps
//!   its bytes, and C makes no store request and no commit of the shard record, a coverage page or the active
//!   volume's record. The history offers C one client GET and, while that GET is outstanding, one coverage call.
//!   [`reached`] requires the GET to reach C before the client decides it. The coverage call encounters a held entry
//!   unless a `NewerFence` withdrawal already cleared it. `DetectedLossWithdraws` of `quint/tenure.qnt`, and the
//!   obligation records `same-generation-deposition-withdraws-without-retirement` and
//!   `serving-table-token-and-metadata-admission`.
//! - No byte of C is surfaced after D's takeover: each history asserts it on the outcome of every GET C's client
//!   ends after the takeover. Each of those GETs ends before D's READY raises the client's route, so the oracle's
//!   rule "a client accepted a response tagged below its high-water" is judged by the route control
//!   `control_a_client_that_checks_no_route_accepts_a_deposed_tenures_reply_and_fails`, under each strategy.
//!   In `so1` and `so4`, [`run_to_observation`] takes the waiting GET's fragments from the client after each round
//!   through the round C withdraws, and the history asserts that [`run_to_observation`] collected zero bytes.
//! - [`fences_hold`]: every coverage page ends with the successor's session as its fence. `CoverageNeverDecreases`
//!   and `FencedCoverageComplete` of `quint/coverage.qnt`.
//! - An unknown page write is never acknowledged: each coverage call after it acknowledges no entry.
//!   `NoAckBeforeAuthoritative` of `quint/coverage.qnt`, and the record
//!   `a-latched-coverage-withdrawal-issues-no-further-store-request`.
//! - When C's withdrawal carries a flip request, the request is valid for the shard record C served under. Applying
//!   it after D's takeover returns `Stale` and preserves the record's generation and active volume
//!   (`InterruptedTakeoverRetainsVolume` in `quint/tenure.qnt`).
//!
//! In `so2` and `so3` the INVALIDATE C never acknowledges names an object an acknowledged INVALIDATE removed from D's
//! retained set before the host loss, and the history records no row for it, so the positive-preservation judgment
//! stays conclusive. Those two histories witness C's side and leave D's handling of an object that only an
//! unknown-outcome write covers unwitnessed.
//!
//! The histories are outcome witnesses through the implementation under scripted faults, with no model replay. The
//! contract is observation-based: a transmission the link accepted before the observation may finish, and the
//! histories check no bound on when a deposed tenure withdraws. A `Frozen` tenure observes its deposition only
//! through a medium command or a page write. The histories rely on NEW-EXCLUSION for a command issued after the
//! preempt, and each asserts that C's device held no waiting command at the preempt. In `so4` C's device must accept
//! the waiting GET's read after D's fence under `Frozen` and none under `Honest`, whose window the pause closes;
//! under `Slow` the history prints which happened, and in the recorded run the pause of 2,000 µs closes that window
//! too. In these histories the store evaluates every write of C inside the call that issued it, so a write parked
//! before D's takeover and evaluated after it is outside them.

use std::cell::RefCell;
use std::rc::Rc;

use crate::failover::record::LocalRecord;
use crate::failover::records::ShardRecord;
use crate::failover::restart::Restarted;
use crate::failover::retire::{Admitted, Retirement, Role, Stale, Target, Trigger};
use crate::failover::serving::{Cause, State};
use crate::failover::takeover::Refused;
use crate::failover::takeover::tests::{Card, d_host, designate_fresh_host, takeover_of};
use crate::oracle::Tenure;
use crate::oracle::ownership::Step;
use crate::storage::gate_fixture::Strategy;
use crate::storage::page_coverage::Withdraw;
use crate::storage::store::sim::{Arm, Counting, Point, Requests, Shared, hooked};
use crate::storage::store::{Client, Key, Store, StoreError};
use crate::storage::store_tests::{client as store_client, shard};
use crate::storage::warm_sim::object_key;
use crate::storage::{MetadataOutcome, Operation};

use super::{
    Answer, Event, Fetched, STRATEGIES, Serving, Source, Status, World, hold, publish, reports,
    restart_tests, serve, serve_taken,
};

/// The named string of [`quiet_after`].
const QUIET: &str = "a deposed tenure sent a frame after it observed its deposition";
/// The named string of [`fences_hold`].
const FENCED: &str = "a coverage page write committed under a superseded fence";
const FLIP: &str = "a flip request names a tenure its owner never held";
const SURFACED: &str =
    "a client surfaced a byte of a deposed tenure after its successor's takeover";
/// The rounds `so4` pauses C: 2,000 µs, twice the window.
const PAUSE: u64 = 20;
/// The deadline of a GET by C's client, in microseconds, which ends inside the wait helper's 8,000 rounds.
const GET_WAIT: u64 = 100_000;
/// The objects each history publishes and captures before the host loss.
const OBJECTS: u8 = 4;

/// The history row: where the successor is placed and which store arm and pause the row fixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    So0,
    So1,
    So2,
    So3,
    So4,
}

/// One case's recorded choices. A case's result depends on nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Case {
    strategy: Strategy,
    placement: Placement,
    pause: u64,
}

/// The whole case product: five placements by three strategies, `so4` alone with a pause.
fn cases() -> Vec<Case> {
    let placements = [
        Placement::So0,
        Placement::So1,
        Placement::So2,
        Placement::So3,
        Placement::So4,
    ];
    let mut cases = Vec::new();
    for placement in placements {
        for strategy in STRATEGIES {
            let pause = if placement == Placement::So4 {
                PAUSE
            } else {
                0
            };
            cases.push(Case {
                strategy,
                placement,
                pause,
            });
        }
    }
    cases
}

/// A store client over `inner` whose requests add to `requests`, C's request count.
fn counted<S: Store>(
    inner: S,
    requests: &Requests,
) -> Client<Counting<S>, crate::storage::store::sim::MemLog> {
    let store = Counting {
        store: inner,
        requests: requests.clone(),
    };
    Client::open(store, Default::default()).expect("a client")
}

/// What [`quiet_after`] compares: C's sent frames, the writes C's device accepted, the media, the commits of the
/// shard record, the coverage pages and the active volume's record other than the successor's, and C's store
/// requests.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Quiet {
    sent: u64,
    writes: usize,
    media: Vec<u8>,
    commits: usize,
    requests: usize,
}

/// Requires `end` to equal `first`, the snapshot taken after the turn or coverage call that left C `Withdrawn`.
///
/// # Errors
///
/// "a deposed tenure sent a frame after it observed its deposition" when any of the five differs.
fn quiet_after(first: &Quiet, end: &Quiet) -> Result<(), &'static str> {
    if first == end { Ok(()) } else { Err(QUIET) }
}

/// Requires every coverage page's fence to be `successor`, the successor's session.
///
/// # Errors
///
/// "a coverage page write committed under a superseded fence" when a page holds another fence.
fn fences_hold(records: &Shared, successor: u64) -> Result<(), &'static str> {
    let record = restart_tests::shard_now(records);
    let mut client = store_client(records);
    for page in 0..record.pages.get() {
        let read = client
            .read::<crate::failover::records::CoveragePage>(Key::Page(shard(), page))
            .expect("a coverage page");
        if read.value().fence != successor {
            return Err(FENCED);
        }
    }
    Ok(())
}

/// The store's commits of the shard record, every coverage page and the active volume's record.
fn commits(records: &Shared) -> usize {
    let record = restart_tests::shard_now(records);
    let store = records.0.borrow();
    let mut keys = vec![Key::Shard(shard()), Key::Volume(record.active)];
    keys.extend((0..record.pages.get()).map(|page| Key::Page(shard(), page)));
    keys.iter().map(|key| store.commit_count(key)).sum()
}

/// The page's commit and acknowledged-reply counts.
fn counts(records: &Shared, key: Key) -> (usize, usize) {
    let store = records.0.borrow();
    (
        store.commit_count(&key),
        store.replied.get(&key).copied().unwrap_or(0),
    )
}

/// What a successor step leaves: D's local record, its takeover's result, the page's commit and reply counts when
/// the step began, and how many commands waited on C's device at the preempt.
struct Installed {
    record: LocalRecord,
    taken: Result<Restarted, Refused>,
    page_at: (usize, usize),
    /// The page's commit count when the step ended, D's fence included.
    page_fenced: usize,
    waiting: usize,
}

/// Designates D and runs D's takeover over `records` and `reservation`.
fn install(
    records: &Shared,
    reservation: &Rc<RefCell<super::Reservation>>,
    page: Key,
    control: &crate::storage::device::sim::SimControl,
) -> Installed {
    let (page_at, waiting) = (counts(records, page), control.pending());
    let record = designate_fresh_host(records);
    let mut card = Card::new(record.pair(), reservation);
    let local = restart_tests::Stored(Ok(record.clone()));
    let taken = takeover_of(records, d_host()).run(&mut store_client(records), &local, &mut card);
    Installed {
        record,
        taken,
        page_at,
        page_fenced: counts(records, page).0,
        waiting,
    }
}

/// C's quiet snapshot now, with `d_commits`, the commits D made since the first snapshot, taken out of the store's
/// commits.
fn snapshot(world: &World, c: &Serving<'_>, requests: &Requests, d_commits: usize) -> Quiet {
    let (reads, writes) = requests.seen();
    Quiet {
        sent: c.owner.report().sent,
        writes: c.control.accepted(Operation::Write),
        media: world.a.media.borrow().clone(),
        commits: commits(&world.records) - d_commits,
        requests: reads + writes,
    }
}

/// C's serving authority state.
fn state(c: &Serving<'_>) -> State {
    c.owner.authority_report().state
}

/// One `cover_pending` call of C through `client`: its result and how many entries it acknowledged.
fn cover<S: Store>(
    c: &mut Serving<'_>,
    client: &mut Client<S, crate::storage::store::sim::MemLog>,
) -> (Result<(), Withdraw>, usize) {
    let mut acknowledged = Vec::new();
    let now = c.time();
    let covered = c.owner.cover_pending(client, &mut acknowledged, now);
    (covered, acknowledged.len())
}

/// C counts both GET and CANCEL datagrams. An increase of one counts as delivery of GET `id` only when the client
/// poll sends one datagram and leaves `id` undecided. The client queues a CANCEL only for a request it has decided.
fn reached(c: &mut Serving<'_>, id: super::RequestId) -> bool {
    let polled = c.poll_client();
    let sent_get = polled.sent == 1 && c.client.outcome(id).is_none();
    let received = c.owner.report().received;
    c.step_without_client();
    sent_get && c.owner.report().received == received + 1
}

/// Collecting after each step preserves fragments the client received before a deadline or owner error ends GET
/// `waiting`.
fn run_to_observation(c: &mut Serving<'_>, waiting: Option<super::RequestId>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..400 {
        if state(c) == State::Withdrawn {
            break;
        }
        c.step();
        if let Some(id) = waiting {
            super::collect(&mut c.client, id, &mut bytes);
        }
    }
    bytes
}

fn surfaced_none(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(SURFACED)
    }
}

/// Whether the last recorded GET of object `n` in `tenure` was answered with a miss.
fn missed_last(world: &World, n: u8, tenure: Tenure) -> bool {
    let last = world.events.iter().rev().find_map(|event| match event {
        Event::Read {
            n: of,
            tenure: by,
            answer,
            ..
        } if *of == n && *by == tenure => Some(answer),
        _ => None,
    });
    matches!(last, Some(Answer::Missing))
}

/// What one case recorded: the observation that withdrew C, the oracle history and the ownership steps.
#[derive(Debug, PartialEq, Eq)]
struct Ran {
    observed: String,
    /// Whether C's withdrawal carried a flip request, which the store client's `retire` then refused.
    flip_refused: bool,
    history: String,
    steps: String,
}

/// C's first page write of its held INVALIDATE of object `n` commits with an unknown reply. Asserts the premise that
/// the scheduled arm met that write: the page's commit count grew by one and its acknowledged replies by none.
/// Returns the page's counts afterwards.
fn unknown_write(
    world: &World,
    c: &mut Serving<'_>,
    page: Key,
    requests: &Requests,
    name: &str,
) -> (usize, usize) {
    let before = counts(&world.records, page);
    c.step();
    world.records.schedule(Arm::Timeout { commit: true });
    let mut client = counted(world.records.clone(), requests);
    let (covered, acknowledged) = cover(c, &mut client);
    assert_eq!(
        (covered, acknowledged),
        (Ok(()), 0),
        "{name}: the unknown write"
    );
    let met = (before.0 + 1, before.1);
    assert_eq!(
        counts(&world.records, page),
        met,
        "{name}: the arm met C's page write"
    );
    met
}

/// The hook step that installs D, and the cell it leaves the result in.
fn successor_step(
    world: &World,
    c: &Serving<'_>,
    page: Key,
) -> (impl FnOnce() + 'static, Rc<RefCell<Option<Installed>>>) {
    let cell: Rc<RefCell<Option<Installed>>> = Rc::default();
    let (records, reservation) = (world.records.clone(), Rc::clone(&world.reservation));
    let (out, control) = (Rc::clone(&cell), c.control.clone());
    let step = move || *out.borrow_mut() = Some(install(&records, &reservation, page, &control));
    (step, cell)
}

/// Runs one case and returns what it recorded. `so0` ends with C serving. Every other placement asserts its
/// premises, runs C to its observation, offers C one client frame and one coverage call, serves D, and then
/// requires [`quiet_after`], [`fences_hold`], the refused flip request and `World::judged`.
fn run(case: Case) -> Ran {
    let name = format!("{:?} under {:?}", case.placement, case.strategy);
    let mut world = World::new(OBJECTS, false);
    world.set_moving_clock(case.strategy);
    let unknown = matches!(case.placement, Placement::So2 | Placement::So3);
    // The INVALIDATE C never acknowledges names object 2, which an acknowledged INVALIDATE removed from D's retained
    // set before the host loss.
    let n = if unknown {
        world.invalidate(2);
        2
    } else {
        1
    };
    let page = world.page_key(n);
    let (observed, flip_refused) = serve_taken(&mut world, super::c_host(), |world, c, outcome| {
        assert_eq!(outcome, MetadataOutcome::Open, "{name}");
        c.read_all(world);
        assert!(c.open_suffix(&world.records), "{name}: C's suffix opens");
        let requests = Requests::default();
        let commits_at_start = commits(&world.records);
        let own = restart_tests::shard_now(&world.records);
        hold(c, n).expect("C holds the INVALIDATE");
        let observation = |c: &Serving<'_>| {
            let report = c.owner.authority_report();
            format!(
                "{:?} cause {:?} refusal {:?} flip {:?}",
                report.state, report.withdrawal, report.refusal, report.flip
            )
        };
        let periodic = |c: &Serving<'_>| match case.strategy {
            Strategy::Frozen => assert_eq!(reports(c), 1, "{name}: a frozen clock reports once"),
            _ => assert!(
                reports(c) > 1,
                "{name}: a moving clock reports periodically"
            ),
        };
        let before = counts(&world.records, page);
        let mut waiting: Option<super::RequestId> = None;
        // The reads C's device had accepted when `so4` emitted D's `Fenced` step.
        let mut reads_at_fence: Option<usize> = None;
        // The premises of D's takeover, then D's `Fenced` step. Each placement calls this before C's next turn, so
        // the step list shows every command C's device accepts from then on as accepted after the fence.
        let fence = |world: &World, c: &Serving<'_>, installed: &Installed| {
            assert_eq!(
                installed.waiting, 0,
                "{name}: C's device held no waiting command at the preempt"
            );
            let taken = installed.taken.as_ref().expect("D's takeover succeeded");
            assert!(c.deposed(), "{name}: C was deposed");
            world.fence(taken);
        };
        let installed = match case.placement {
            Placement::So0 => {
                let mut client = counted(world.records.clone(), &requests);
                assert!(publish(world, c, n, &mut client), "{name}: C acknowledges");
                for _ in 0..30 {
                    c.step();
                }
                assert_eq!(state(c), State::Serving, "{name}: C keeps serving");
                let served = c.read_all(world).len();
                assert_eq!(served, usize::from(OBJECTS) - 1, "{name}");
                assert!(
                    missed_last(world, n, c.tenure),
                    "{name}: C answered the covered object's GET with a miss"
                );
                periodic(c);
                return (observation(c), false);
            }
            Placement::So1 => {
                let (step, cell) = successor_step(world, c, page);
                let hook = hooked(&world.records, page, Point::AfterWrite, step);
                let mut client = counted(hook, &requests);
                assert!(publish(world, c, n, &mut client), "{name}: C acknowledges");
                let installed = cell.take().expect("the hook ran D's takeover");
                fence(world, c, &installed);
                let grown = (before.0 + 1, before.1 + 1);
                assert_eq!(
                    installed.page_at, grown,
                    "{name}: the store committed and acknowledged C's page write before D's fence"
                );
                hold(c, n).expect("C holds a second INVALIDATE for the offered coverage call");
                installed
            }
            Placement::So2 | Placement::So3 => {
                let met = unknown_write(world, c, page, &requests, &name);
                let point = if case.placement == Placement::So2 {
                    Point::AfterWrite
                } else {
                    Point::AfterRead
                };
                let (step, cell) = successor_step(world, c, page);
                let hook = hooked(&world.records, page, point, step);
                let mut client = counted(hook, &requests);
                let (covered, acknowledged) = cover(c, &mut client);
                let installed = cell.take().expect("the hook ran D's takeover");
                fence(world, c, &installed);
                assert_eq!(
                    installed.page_at, met,
                    "{name}: nothing committed between C's unknown write and D's fence"
                );
                assert_eq!(acknowledged, 0, "{name}: C acknowledges nothing");
                if case.placement == Placement::So2 {
                    let newer = matches!(covered, Err(Withdraw::NewerFence { .. }));
                    assert!(newer, "{name}: the retry's call withdraws: {covered:?}");
                    assert_eq!(
                        state(c),
                        State::Withdrawn,
                        "{name}: the retry's call left C withdrawn"
                    );
                    // C's `Withdrawn` step follows D's `Fenced` step and precedes C's next `Commands` step.
                    c.note_withdrawal();
                    let last = world.steps.borrow().list.last().cloned();
                    assert_eq!(
                        last,
                        Some(Step::Withdrawn { tenure: c.tenure }),
                        "{name}: C's withdrawal is recorded at the retry's call"
                    );
                } else {
                    assert_eq!(covered, Ok(()), "{name}: the reread saw C's own fence");
                    assert_eq!(state(c), State::Serving, "{name}: C serves on");
                }
                installed
            }
            Placement::So4 => {
                let mut client = counted(world.records.clone(), &requests);
                assert!(publish(world, c, n, &mut client), "{name}: C acknowledges");
                hold(c, n).expect("C holds a second INVALIDATE for the offered coverage call");
                waiting = Some(c.send_within(object_key(3), GET_WAIT));
                // The client's next poll puts the GET on the link, where it waits across the pause.
                c.poll_client();
                let turns = |c: &Serving<'_>, world: &World| {
                    let steps = world.steps.borrow();
                    let own = (steps.list.iter())
                        .filter(|step| matches!(step, Step::Commands { tenure, .. } if *tenure == c.tenure))
                        .count();
                    let report = c.owner.report();
                    (report.sent, report.received, own, reports(c))
                };
                let untouched = turns(c, world);
                c.pause(case.pause / 2);
                let installed = install(&world.records, &world.reservation, page, &c.control);
                fence(world, c, &installed);
                c.pause(case.pause - case.pause / 2);
                assert_eq!(
                    turns(c, world),
                    untouched,
                    "{name}: C took no turn and sent nothing across the pause"
                );
                assert!(
                    matches!(world.steps.borrow().list.last(), Some(Step::Fenced { .. })),
                    "{name}: D's fence is the last step before C's first turn after the pause"
                );
                reads_at_fence = Some(c.control.accepted(Operation::Read));
                // The GET waited on the link: C's first turn receives it with no client poll in between.
                let received = c.owner.report().received;
                c.step_without_client();
                assert!(
                    c.owner.report().received > received,
                    "{name}: the waiting GET reached C at its first turn after the pause"
                );
                installed
            }
        };
        let taken = installed.taken.expect("D's takeover succeeded");
        // The takeover ran outside `World::designate_fresh`, which keeps D's local record once D is enrolled.
        world.fresh = Some(installed.record);
        if case.placement == Placement::So3 {
            // C's first observation is a Report in its next turn, which a moving clock may bring, or else its next
            // page write, whose result shows D's fence. The history starts no GET before it, so no device status
            // of C's can withdraw it first.
            c.step();
            if state(c) != State::Withdrawn {
                let mut client = counted(world.records.clone(), &requests);
                let (covered, acknowledged) = cover(c, &mut client);
                assert_eq!(acknowledged, 0, "{name}: C acknowledges nothing");
                let newer = matches!(covered, Err(Withdraw::NewerFence { .. }));
                assert!(
                    newer,
                    "{name}: C's next page write shows D's fence: {covered:?}"
                );
                c.note_withdrawal();
            }
            let cause = c.owner.authority_report().withdrawal;
            let by_page = matches!(cause, Some(Cause::NewerFence { .. }));
            let by_report = case.strategy != Strategy::Frozen
                && matches!(
                    cause,
                    Some(Cause::Report(_) | Cause::RecordedHolder | Cause::Unheld)
                );
            assert!(
                by_page || by_report,
                "{name}: a page write or a Report withdrew C: {cause:?}"
            );
        } else {
            // C runs until it observes its deposition: by a Report its clock brings or by the conflict its next
            // GET's device read meets.
            if state(c) != State::Withdrawn && waiting.is_none() {
                waiting = Some(c.send_within(object_key(3), GET_WAIT));
            }
            let early = run_to_observation(c, waiting);
            surfaced_none(&early).unwrap_or_else(|violated| panic!("{name}: {violated}"));
        }
        periodic(c);
        if let Some(at_fence) = reads_at_fence {
            let read = c.control.accepted(Operation::Read) > at_fence;
            match case.strategy {
                Strategy::Frozen => assert!(
                    read,
                    "{name}: C's device accepted the waiting GET's read after D's fence"
                ),
                Strategy::Honest { .. } => assert!(
                    !read,
                    "{name}: the pause closed C's window, so its device accepted no read after D's fence"
                ),
                Strategy::Slow { .. } => {
                    println!("{name}: C's device accepted a read after D's fence: {read}");
                }
            }
        }
        assert_eq!(
            state(c),
            State::Withdrawn,
            "{name}: C observed its deposition"
        );
        if case.placement == Placement::So4 && case.strategy == Strategy::Frozen {
            let refusal = c.owner.authority_report().refusal;
            let conflict = Some(crate::storage::AuthorityRefusal::Conflict);
            assert_eq!(
                refusal, conflict,
                "{name}: C's device read ended in conflict"
            );
        }
        let observed = observation(c);
        let carried = c.owner.authority_report().flip;
        let first = snapshot(world, c, &requests, 0);
        assert!(
            first.requests > 0 && first.commits > commits_at_start,
            "{name}: the first snapshot counts a store request of C and a commit made since C began serving"
        );
        let ended = |world: &mut World, c: &mut Serving<'_>, id, object: u8| {
            let got = c.finish(id);
            surfaced_none(&got.1).unwrap_or_else(|violated| panic!("{name}: {violated}"));
            println!("{name}: C's GET of object {object} ended {:?}", got.0);
            c.record(world, object, &[super::first(object)], got);
        };
        if let Some(id) = waiting {
            ended(world, c, id, 3);
        }
        // After the observation C is offered one client frame and one coverage call. A held entry meets the call
        // unless the withdrawal was a `NewerFence`, which clears the held entries.
        let offered = c.send_within(object_key(4), GET_WAIT);
        assert!(reached(c, offered), "{name}: the offered GET reached C");
        let newer = matches!(
            c.owner.authority_report().withdrawal,
            Some(Cause::NewerFence { .. })
        );
        let held = c.owner.held_invalidations();
        assert_eq!(
            held,
            usize::from(!newer),
            "{name}: the entry the offered call meets"
        );
        let mut client = counted(world.records.clone(), &requests);
        let (_, acknowledged) = cover(c, &mut client);
        assert_eq!(
            acknowledged, 0,
            "{name}: a withdrawn tenure acknowledges nothing"
        );
        ended(world, c, offered, 4);
        let (before_d, session) = (commits(&world.records), taken.session().get());
        let served = serve(world, taken, Source::Named, |world, d, outcome| {
            assert_eq!(outcome, MetadataOutcome::Open, "{name}: D's load opens");
            let served = d.read_all(world);
            assert!(
                missed_last(world, n, d.tenure),
                "{name}: D answered the covered object's GET with a miss"
            );
            served
        });
        let kept: Vec<u8> = (1..=OBJECTS).filter(|&object| object != n).collect();
        assert_eq!(served, kept, "{name}: D misses the covered object alone");
        let d_commits = commits(&world.records) - before_d;
        let end = snapshot(world, c, &requests, d_commits);
        quiet_after(&first, &end).unwrap_or_else(|violated| panic!("{name}: {violated}"));
        fences_hold(&world.records, session)
            .unwrap_or_else(|violated| panic!("{name}: {violated}"));
        let flip = c.owner.authority_report().flip;
        if let Some(target) = flip {
            refused_flip(&world.records, &own, target, &name)
                .unwrap_or_else(|violated| panic!("{name}: {violated}"));
        }
        (observed, carried.is_some() && carried == flip)
    });
    println!("{name}: C's observation: {observed}");
    let judged = world.judged();
    let accounts = judged.unwrap_or_else(|verdict| panic!("{name}: {verdict:?}"));
    let tenures = if case.placement == Placement::So0 {
        1
    } else {
        2
    };
    assert_eq!(accounts.len(), tenures, "{name}");
    Ran {
        observed,
        flip_refused,
        history: format!("{:?}", world.history(None)),
        steps: format!("{:?}", world.steps.borrow().list),
    }
}

/// C's request for `target` must qualify as `Admitted::Flip` against `own`, the record C served under. After D's
/// takeover, `retire` must return `Stale::Target` for C's `target` and preserve the shard record's generation and
/// active volume.
fn refused_flip(
    records: &Shared,
    own: &ShardRecord,
    target: Target,
    name: &str,
) -> Result<(), &'static str> {
    let request = |volume| {
        Retirement::new(volume, Role::Active, target, Trigger::Activation)
            .expect("a retiring trigger")
    };
    if request(own.active).admit(own) != Ok(Admitted::Flip) {
        return Err(FLIP);
    }
    let mut client = store_client(records);
    let read = client
        .read::<ShardRecord>(Key::Shard(shard()))
        .expect("the shard record");
    let before = *read.value();
    let retired = client.retire(&read, &request(before.active)).map(drop);
    assert!(
        matches!(retired, Err(StoreError::Stale(Stale::Target))),
        "{name}: the flip request is refused: {retired:?}"
    );
    let after = restart_tests::shard_now(records);
    assert_eq!(
        (after.generation, after.active),
        (before.generation, before.active),
        "{name}: the record keeps its generation and active volume"
    );
    Ok(())
}

/// Runs the three cases of `placement`.
fn family(placement: Placement) -> Vec<Ran> {
    let of = cases()
        .into_iter()
        .filter(|case| case.placement == placement);
    of.map(run).collect()
}

/// The family is the whole product, and each case's fields name it uniquely.
#[test]
fn the_family_lists_five_placements_under_three_strategies() {
    let cases = cases();
    assert_eq!(cases.len(), 15);
    let mut names: Vec<String> = cases.iter().map(|case| format!("{case:?}")).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 15, "each case is named by its fields");
}

/// The sibling without the fault: with no successor, C acknowledges its INVALIDATE and keeps serving under each
/// strategy, and the history passes. Property: WINDOW-IS-AVAILABILITY.
#[test]
fn so0_with_no_fault_c_acknowledges_and_keeps_serving() {
    assert_eq!(family(Placement::So0).len(), 3);
}

/// D is installed after the store commits and acknowledges C's page write and before C receives that reply, so C
/// acknowledges its INVALIDATE after D's fence. The coverage model's run `ackBeforeSuccessorFence`, in which the
/// owner acknowledges before the fence, is the nearest run: in both, the successor's fence carries the entry
/// forward on the page. In this history D then misses the covered object and C's next GET surfaces no byte. One
/// case's withdrawal carries a flip request, which the store client's `retire` refuses on a record read after D's
/// takeover. Properties: `CoverageNeverDecreases`, `DetectedLossWithdraws`.
#[test]
fn so1_a_successor_after_the_acknowledged_page_write_misses_the_covered_object() {
    let ran = family(Placement::So1);
    assert!(
        ran.iter().any(|case| case.flip_refused),
        "one case's withdrawal carried a flip request, which the store client's retire refused"
    );
}

/// C's page write commits with an unknown reply, and D is installed after C's retry, which the store refuses. The
/// retry's reread shows D's fence: that coverage call returns `NewerFence`, acknowledges nothing and withdraws C.
/// Properties: `NoAckBeforeAuthoritative`, `FencedCoverageComplete`, `DetectedLossWithdraws`.
#[test]
fn so2_a_successor_after_the_retry_of_an_unknown_page_write_withdraws_c_unacknowledged() {
    assert_eq!(family(Placement::So2).len(), 3);
}

/// As `so2`, with D installed after the reread that follows C's refused retry. The reread shows C's own fence, so
/// the call returns unresolved. C acknowledges nothing and withdraws at a Report in its next turn or else at its
/// next page write, whichever its clock brings first; the history starts no GET before that observation.
/// Properties: `NoAckBeforeAuthoritative`, `DetectedLossWithdraws`.
#[test]
fn so3_a_successor_after_the_reread_of_an_unknown_page_write_withdraws_c_unacknowledged() {
    assert_eq!(family(Placement::So3).len(), 3);
}

/// C is paused across D's takeover with a client GET waiting on the link. After the pause no byte from C is
/// surfaced and C ends `Withdrawn`. Under `Frozen` C's device accepts the GET's read after D's fence and the read
/// ends in Reservation Conflict. Under `Honest` the device accepts no read after the fence, and under `Slow` the
/// history prints whether it did; under both the history prints the withdrawal's cause. One case's withdrawal
/// carries a flip request, which the store client's `retire` refuses on a record read after D's takeover.
/// Properties: WINDOW-IS-AVAILABILITY, NEW-EXCLUSION.
#[test]
fn so4_a_tenure_paused_across_its_successors_takeover_surfaces_no_byte() {
    let ran = family(Placement::So4);
    assert!(
        ran.iter().any(|case| case.flip_refused),
        "one case's withdrawal carried a flip request, which the store client's retire refused"
    );
}

/// One case with a successor, run twice, records equal observations, oracle histories and ownership steps.
#[test]
fn one_case_replays_from_its_name_to_equal_events() {
    let case = Case {
        strategy: STRATEGIES[0],
        placement: Placement::So2,
        pause: 0,
    };
    assert_eq!(run(case), run(case));
}

/// Plant: the hook installs D before C's retry is forwarded and then schedules `Arm::DoubleWin`, a reply outside
/// the store contract, so the store applies C's stale write over D's fence. `fences_hold`, called before any other
/// judgment, fails "a coverage page write committed under a superseded fence"; C's store client reports the
/// unexpected version and C withdraws, acknowledging nothing. Unplanted, the store refuses the retry, the page's
/// commit count stays as D's fence left it, and the call ends in `NewerFence`.
#[test]
fn control_a_store_that_applies_a_stale_page_write_fails_the_fence_check() {
    for planted in [false, true] {
        let name = format!("planted {planted}");
        let mut world = World::new(OBJECTS, false);
        world.invalidate(2);
        let page = world.page_key(2);
        serve_taken(&mut world, super::c_host(), |world, c, _| {
            c.read_all(world);
            assert!(c.open_suffix(&world.records), "{name}: C's suffix opens");
            let requests = Requests::default();
            hold(c, 2).expect("C holds the INVALIDATE");
            let met = unknown_write(world, c, page, &requests, &name);
            let (install, cell) = successor_step(world, c, page);
            let records = world.records.clone();
            let step = move || {
                install();
                if planted {
                    records.schedule(Arm::DoubleWin);
                }
            };
            let hook = hooked(&world.records, page, Point::BeforeWrite, step);
            let mut client = counted(hook, &requests);
            let (covered, acknowledged) = cover(c, &mut client);
            let installed = cell.take().expect("the hook ran D's takeover");
            assert_eq!(
                installed.page_at, met,
                "{name}: nothing committed between C's unknown write and D's fence"
            );
            let taken = installed.taken.expect("D's takeover succeeded");
            assert!(c.deposed(), "{name}: C was deposed");
            assert_eq!(
                installed.page_fenced,
                met.0 + 1,
                "{name}: D fenced the page"
            );
            let forced = counts(&world.records, page).0 - installed.page_fenced;
            let held = fences_hold(&world.records, taken.session().get());
            if planted {
                let violated = "a coverage page write committed under a superseded fence";
                assert_eq!(held, Err(violated), "{name}");
                assert_eq!(forced, 1, "{name}: the store applied C's stale write");
                assert_eq!(acknowledged, 0, "{name}: C acknowledges nothing");
                assert_eq!(state(c), State::Withdrawn, "{name}: {covered:?}");
            } else {
                assert_eq!(held, Ok(()), "{name}");
                assert_eq!(forced, 0, "{name}: the commit count is unchanged");
                let newer = matches!(covered, Err(Withdraw::NewerFence { .. }));
                assert!(newer && acknowledged == 0, "{name}: {covered:?}");
                assert_eq!(state(c), State::Withdrawn, "{name}: {covered:?}");
            }
        });
    }
}

/// Each of the five quantities alone fails the quiet check under its one string.
#[test]
fn each_quantity_of_the_quiet_check_fails_it_alone() {
    let first = Quiet {
        sent: 3,
        writes: 1,
        media: vec![7; 4],
        commits: 5,
        requests: 2,
    };
    assert_eq!(quiet_after(&first, &first.clone()), Ok(()));
    let changed: [fn(&mut Quiet); 5] = [
        |quiet| quiet.sent += 1,
        |quiet| quiet.writes += 1,
        |quiet| quiet.media[0] ^= 1,
        |quiet| quiet.commits += 1,
        |quiet| quiet.requests += 1,
    ];
    for change in changed {
        let mut end = first.clone();
        change(&mut end);
        assert_eq!(quiet_after(&first, &end), Err(QUIET), "{end:?}");
    }
}

/// Plant: the first snapshot is taken while C still serves, a planted observation, and C then answers one GET, so
/// the end snapshot counts more sent frames and equals the first in every other field. `quiet_after` fails "a
/// deposed tenure sent a frame after it observed its deposition". Unplanted, C runs idle rounds and the check
/// passes.
#[test]
fn control_a_frame_counted_after_the_observation_fails_the_quiet_check() {
    for planted in [false, true] {
        let mut world = World::new(OBJECTS, false);
        serve_taken(&mut world, super::c_host(), |world, c, _| {
            c.read_all(world);
            let requests = Requests::default();
            let first = snapshot(world, c, &requests, 0);
            if planted {
                assert!(
                    c.read(world, 1, &[super::first(1)]),
                    "C serves one more GET"
                );
            } else {
                for _ in 0..30 {
                    c.step();
                }
            }
            let end = snapshot(world, c, &requests, 0);
            let rest = |quiet: &Quiet| (quiet.writes, quiet.commits, quiet.requests);
            assert_eq!(rest(&first), rest(&end), "only the frame count may differ");
            assert!(first.media == end.media, "the media keeps its bytes");
            let judged = quiet_after(&first, &end);
            if planted {
                assert!(end.sent > first.sent, "the GET's reply was sent");
                let violated = "a deposed tenure sent a frame after it observed its deposition";
                assert_eq!(judged, Err(violated));
            } else {
                assert_eq!(judged, Ok(()));
            }
        });
    }
}

/// The planted GET starts before D takes over. The client receives C's held reply in the round C withdraws.
/// The GET times out one round later, but `surfaced_none` still detects the byte received after takeover.
#[test]
fn control_a_reply_received_before_the_observation_fails_the_no_byte_check() {
    // Skipping client polls keeps the planted reply on the link until D takes over.
    const HELD: u64 = 200;
    for planted in [false, true] {
        let mut world = World::new(OBJECTS, false);
        world.set_moving_clock(STRATEGIES[0]);
        serve_taken(&mut world, super::c_host(), |world, c, _| {
            assert_eq!(c.read_all(world).len(), usize::from(OBJECTS));
            let mut id = None;
            if planted {
                let wait = (HELD + 3) * super::ROUND_US;
                id = Some(c.send_within(object_key(1), wait));
                c.step();
                for _ in 0..HELD {
                    c.step_without_client();
                }
            }
            world.designate_fresh();
            c.idle_device();
            let (taken, log) = world.takeover(d_host());
            assert!(taken.is_ok() && c.deposed(), "{log:?}");
            let id = id.unwrap_or_else(|| c.send_within(object_key(1), GET_WAIT));
            let turn = c.turn;
            let early = run_to_observation(c, Some(id));
            assert_eq!(state(c), State::Withdrawn, "planted {planted}");
            let observed = c.turn;
            let got = c.finish(id);
            assert_eq!(surfaced_none(&got.1), Ok(()), "the GET's end holds no byte");
            let judged = surfaced_none(&early);
            if planted {
                assert_eq!(
                    observed,
                    turn + 1,
                    "C withdrew in the round the reply arrived"
                );
                assert_eq!(
                    c.turn,
                    observed + 1,
                    "the deadline ended the GET a round later"
                );
                assert_eq!(got.0, Fetched::Incomplete(Status::TimedOut));
                assert_eq!(early, super::content(1, super::first(1)));
                let violated =
                    "a client surfaced a byte of a deposed tenure after its successor's takeover";
                assert_eq!(judged, Err(violated));
            } else {
                assert_eq!(judged, Ok(()));
                assert_eq!(got.0, Fetched::Failed(Status::TimedOut));
            }
        });
    }
}

/// A zero deadline makes the client send only the CANCEL. C's receive count increases, but [`reached`] returns
/// false: C counted the CANCEL, while [`reached`] checks delivery of the GET.
#[test]
fn control_a_get_that_sends_only_its_cancel_fails_the_delivery_premise() {
    for planted in [false, true] {
        let mut world = World::new(OBJECTS, false);
        serve_taken(&mut world, super::c_host(), |world, c, _| {
            assert_eq!(c.read_all(world).len(), usize::from(OBJECTS));
            let wait = if planted { 0 } else { GET_WAIT };
            let offered = c.send_within(object_key(4), wait);
            let received = c.owner.report().received;
            let reached = reached(c, offered);
            assert_eq!(
                c.owner.report().received,
                received + 1,
                "planted {planted}: C received one datagram"
            );
            assert_eq!(reached, !planted, "planted {planted}");
            let got = c.finish(offered);
            if planted {
                assert_eq!(got.0, Fetched::Failed(Status::TimedOut));
                assert!(got.1.is_empty(), "no byte of a GET C never received");
            } else {
                assert_eq!(got.0, Fetched::Complete);
                assert_eq!(got.1, super::content(4, super::first(4)));
            }
        });
    }
}

/// Both calls use the same post-takeover records. Changing only the target's `attempts` field isolates the tenure
/// check.
#[test]
fn control_a_flip_target_c_never_held_fails_the_refusal_check() {
    let mut world = World::new(OBJECTS, false);
    serve_taken(&mut world, super::c_host(), |world, c, _| {
        let own = restart_tests::shard_now(&world.records);
        world.designate_fresh();
        c.idle_device();
        let (taken, log) = world.takeover(d_host());
        assert!(taken.is_ok() && c.deposed(), "{log:?}");
        let held = Target::of(&own);
        let never = Target {
            attempts: held.attempts + 1,
            ..held
        };
        assert_eq!(refused_flip(&world.records, &own, held, "held"), Ok(()));
        let violated = "a flip request names a tenure its owner never held";
        assert_eq!(
            refused_flip(&world.records, &own, never, "never held"),
            Err(violated)
        );
    });
}
