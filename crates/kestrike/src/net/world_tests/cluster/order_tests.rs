//! The ordering plants' selection rule under each event order, and each
//! ordering control from a pinned root: the drawn run forms the premise
//! and is caught, and the same root with the selection that issued the
//! selected GET given to another event ends with no effect. Both runs
//! replay from their tapes. The directed cases of the selection rule carry
//! the reversal of each pair of a premise, and one partition driven step
//! by step forces each pair both ways through its sessions.
//!
//! The chooser picks each GET's issue, I, and with it the order of two
//! issues offered together; it picks among CANCELs and among the events
//! ready at one instant, a GET's issue and the collection of an upload's
//! outcome included. Link draws and the clock decide when a read or a
//! publication becomes ready; the clock stands still while an event is
//! runnable.

use std::cell::RefCell;

use crate::oracle::Obligation;
use crate::sim::choice::{Candidate, Chooser, Domain};
use crate::sim::trace::{Event, Outcome, Terminal};
use crate::sim::turn::{End, Hook, Turn};

use super::super::bundle::FAILURE;
use super::order::Order;
use super::tests::{RAISED, checker, drawn_at, driven, fresh, profile_at, published};
use super::{
    APPLIED, CLIENT_POLL, CLIENTS, Checker, Failure, GET, NO_EFFECT, OUTCOME, PROBE, Plant, READ,
    Ran, SOUND, Shape, content, decoded, misread, run, shape,
};
use crate::net::link::{Faults, TxRelease};

/// A hook that keeps the run's tape, finds the turn that issued the GET
/// whose read first failed a check, and, given a turn count, forces that
/// turn's selection to the first runnable event that is no GET of the hot
/// key.
struct Witness {
    /// The hot key's owner.
    cell: u8,
    key: u8,
    /// The turn count whose selection is forced away from the hot key's
    /// GETs.
    divert: Option<u64>,
    /// Whether the diverted selection offered a GET of the hot key and
    /// another event.
    diverted: bool,
    /// The key and issue turn of each undecided GET the hot key's owner
    /// holds, by client, in issue order, until the owner's first probe.
    gets: [Vec<(u8, u64)>; CLIENTS],
    probed: bool,
    /// The client and issue turn of each decided GET of the hot key, in
    /// the order decided, up to the first read that failed a check.
    decided: Vec<(usize, u64)>,
    /// The read that first failed a check.
    failed: Option<Failed>,
    /// The turn that first collected an outcome of the hot key's upload,
    /// and whether that outcome was published: P when it was.
    reported: Option<(u64, bool)>,
    turns: u64,
    tape: Vec<u8>,
}

/// A read the hook saw fail a check, at the hot key's owner.
#[derive(Clone, Copy, Debug)]
struct Failed {
    /// The key the read's GET asked for, from the hook's own record of
    /// the owner's GETs.
    key: u8,
    client: usize,
    /// The turn that issued the read's GET.
    issue: u64,
    /// The turn that collected the read.
    read: u64,
    /// The read completed.
    complete: bool,
}

impl Witness {
    fn new(cell: u8, key: u8, divert: Option<u64>) -> Self {
        Self {
            cell,
            key,
            divert,
            diverted: false,
            gets: [Vec::new(), Vec::new()],
            probed: false,
            decided: Vec::new(),
            failed: None,
            reported: None,
            turns: 0,
            tape: Vec::new(),
        }
    }

    fn hot_get(&self, candidate: &Candidate) -> bool {
        let bytes = &candidate.0;
        bytes[0] == Domain::Workload as u8
            && bytes[1] == GET
            && bytes[2] == self.cell
            && bytes[8] == self.key
    }
}

impl Hook for Witness {
    fn begin(&mut self, _record: &[u8], choices: &[u8]) {
        self.tape.extend_from_slice(choices);
    }

    fn clock(&mut self, choices: &[u8], _now: u64, _events: &[Event]) {
        self.tape.extend_from_slice(choices);
    }

    fn turn(&mut self, choices: &[u8], turn: &Turn, events: &[Event]) {
        self.tape.extend_from_slice(choices);
        let bytes = turn.event.0;
        let here = bytes[0] == Domain::Workload as u8 && bytes[2] == self.cell;
        let client = usize::from(bytes[3]);
        // A turn's observation starts with 1 to 5 when it collected a
        // GET's outcome.
        let got = (1..=5).contains(&turn.observation[0]);
        match bytes[1] {
            GET if here && turn.outcome == APPLIED => {
                self.gets[client].push((bytes[8], self.turns));
            }
            READ if here && got && !self.probed => {
                let at = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                let (key, issued) = self.gets[client].remove(at as usize);
                if self.failed.is_some() {
                    // The first failed read stands.
                } else if events.iter().any(|event| event.kind == FAILURE) {
                    self.failed = Some(Failed {
                        key,
                        client,
                        issue: issued,
                        read: self.turns,
                        complete: turn.observation[0] == 1,
                    });
                } else if key == self.key {
                    self.decided.push((client, issued));
                }
            }
            // An observation of 6 to 9 is an upload's collected outcome,
            // 6 the published one.
            OUTCOME if here && bytes[8] == self.key && (6..=9).contains(&turn.observation[0]) => {
                self.reported
                    .get_or_insert((self.turns, turn.observation[0] == 6));
            }
            // A probe issues a GET that `gets` leaves out.
            PROBE if here => self.probed = true,
            _ => {}
        }
        self.turns += 1;
    }

    fn select(&mut self, runnable: &[Candidate], chooser: &RefCell<Chooser>) {
        if self.divert != Some(self.turns) {
            return;
        }
        let other = runnable
            .iter()
            .position(|candidate| !self.hot_get(candidate));
        if let Some(other) = other
            && runnable.iter().any(|candidate| self.hot_get(candidate))
        {
            chooser.borrow_mut().force(other);
            self.diverted = true;
        }
    }

    fn end(&mut self, choices: &[u8]) {
        self.tape.extend_from_slice(choices);
    }
}

const FOREIGN: Failure = Failure::Violation(
    Obligation::Bytes,
    "a GET returned bytes no upload of its key wrote",
);

const LIMITS: (
    crate::sim::turn::Limits,
    usize,
    crate::net::link::LinkLimits,
) = (RAISED, 4096, crate::net::link::UNBOUNDED);

const PLANTS: [Plant; 3] = [Plant::Depth1, Plant::Depth2, Plant::Depth3];

/// The control of `depth`, which carries that depth's plant.
fn control(depth: u8) -> &'static Shape {
    let shape = shape(&format!("cluster-order-{depth}")).expect("an ordering control");
    assert_eq!(shape.plant, PLANTS[usize::from(depth) - 1]);
    shape
}

/// Runs the control of `depth` from `root`, with the selection at turn
/// count `divert` forced away from the hot key's GETs.
fn witnessed(depth: u8, root: u64, divert: Option<u64>) -> (Ran, Witness) {
    let shape = control(depth);
    let (_, topology, _) = drawn_at(shape, root);
    let cell = topology.hot % topology.owners;
    let mut witness = Witness::new(cell, topology.hot, divert);
    let profile = profile_at(shape, root);
    let chooser = profile.recorder(&super::sites());
    let ran = run(chooser, &profile, shape, LIMITS, &mut witness);
    (ran, witness)
}

/// Replays `tape` as the control of `depth` from `root` with no hook, and
/// requires the replay to read the whole tape.
fn replayed(depth: u8, root: u64, tape: Vec<u8>) -> Ran {
    let shape = control(depth);
    let profile = profile_at(shape, root);
    let length = tape.len();
    let chooser = Chooser::replay(&super::sites(), tape);
    let ran = run(chooser, &profile, shape, LIMITS, &mut ());
    assert_eq!(ran.draws.borrow().recorded().len(), length);
    ran
}

/// The plant of `depth` over hot key 2, told that version 0 was reported
/// published after the owner's GETs up to `before_report`, then each
/// decided GET of `decided` in turn as its client, its issue number and
/// the version a complete read returned. Returns what each decision
/// selected.
fn selections(depth: u8, before_report: u64, decided: &[(usize, u64, Option<u32>)]) -> Vec<bool> {
    let mut order = Order::new(PLANTS[usize::from(depth) - 1], 2);
    order.published(2, 0, before_report);
    decided
        .iter()
        .map(|&(client, issued, read)| order.decided(client, issued, 2, || read))
        .collect()
}

/// Each plant selects the read that completes its orders, and selects none
/// when any one of them holds the other way: at depth 1, I before P; at
/// depth 2, also R(1) before R(0); at depth 3, also I(0) before I(1).
#[test]
fn a_plant_selects_a_read_only_under_every_one_of_its_orders() {
    // GET 1 was accepted before P and GET 2 after it.
    assert_eq!(selections(1, 1, &[(1, 1, Some(0))]), [true]);
    assert_eq!(selections(1, 1, &[(1, 2, Some(0))]), [false]);
    // Client 0's GET 1 and client 1's GET 2, both accepted before P.
    let (zero, one) = ((0, 1, Some(0)), (1, 2, None));
    for depth in [2, 3] {
        assert_eq!(selections(depth, 2, &[one, zero]), [false, true]);
        assert_eq!(selections(depth, 2, &[zero, one]), [false, false]);
        assert_eq!(selections(depth, 0, &[one, zero]), [false, false]);
    }
    // Client 1's GET was accepted first: depth 2 selects, depth 3 does not.
    let (zero, one) = ((0, 2, Some(0)), (1, 1, None));
    assert_eq!(selections(2, 2, &[one, zero]), [false, true]);
    assert_eq!(selections(3, 2, &[one, zero]), [false, false]);
    // At depths 2 and 3 the selected read is client 0's: client 1's
    // complete read after its own earlier decision selects nothing.
    assert_eq!(
        selections(2, 3, &[(1, 1, None), (1, 2, Some(0))]),
        [false, false]
    );
    assert_eq!(
        selections(3, 3, &[(1, 2, None), (1, 1, Some(0))]),
        [false, false]
    );
    // Depth 3 holds client 0's GET 2 against the latest GET client 1 had
    // decided, GET 3, whichever of client 1's was decided last.
    assert_eq!(
        selections(3, 3, &[(1, 3, None), (1, 1, None), (0, 2, Some(0))]),
        [false, false, true]
    );
}

/// A plant selects one read at most, of version 0 of the hot key alone,
/// holds P to the first report of version 0, and a profile's other plants
/// select none.
#[test]
fn a_plant_selects_one_read_of_the_hot_keys_first_version() {
    let read = [
        (0, 1, Some(1)),
        (0, 2, None),
        (0, 3, Some(0)),
        (1, 1, Some(0)),
    ];
    assert_eq!(selections(1, 3, &read), [false, false, true, false]);
    let mut order = Order::new(Plant::Depth1, 2);
    order.published(1, 0, 5);
    order.published(2, 1, 5);
    assert!(
        !order.decided(0, 1, 2, || Some(0)),
        "no report of the hot key's version 0: a read decided before P"
    );
    order.published(2, 0, 1);
    order.published(2, 0, 5);
    assert!(!order.decided(0, 1, 1, || Some(0)), "another key");
    assert!(
        !order.decided(0, 2, 2, || Some(0)),
        "accepted after the first report"
    );
    assert!(order.decided(0, 1, 2, || Some(0)));
    let mut unplanted = Order::new(Plant::Misread, 2);
    unplanted.published(2, 0, 5);
    assert!(!unplanted.decided(0, 1, 2, || Some(0)));
}

/// The conditions on R(1) at depths 2 and 3, and the one selection of a
/// run. R(1) is a decision by client 1 of a GET of the hot key, decided
/// before or after P and accepted before or after it.
#[test]
fn a_plant_counts_as_r1_any_decision_of_the_hot_key_by_client_1() {
    for depth in [2, 3] {
        let plant = PLANTS[usize::from(depth) - 1];
        // Client 0's own earlier decision is no R(1).
        assert_eq!(
            selections(depth, 3, &[(0, 2, None), (0, 1, Some(0))]),
            [false, false]
        );
        // Client 1's GET 2 was accepted after P, and its read missed or
        // completed with version 0.
        for peer in [None, Some(0)] {
            assert_eq!(
                selections(depth, 1, &[(1, 2, peer), (0, 1, Some(0))]),
                [false, true],
                "depth {depth}, {peer:?}"
            );
        }
        // Client 1's decision of another key is no R(1).
        let mut order = Order::new(plant, 2);
        order.published(2, 0, 2);
        assert!(!order.decided(1, 2, 1, || None));
        assert!(!order.decided(0, 1, 2, || Some(0)), "depth {depth}");
        // Client 1's GET was decided before P.
        let mut order = Order::new(plant, 2);
        assert!(!order.decided(1, 2, 2, || None));
        order.published(2, 0, 2);
        assert!(order.decided(0, 1, 2, || Some(0)), "depth {depth}");
    }
    // A plant that selected a read selects none after a later refusal.
    assert_eq!(
        selections(1, 3, &[(0, 1, Some(0)), (0, 2, None), (0, 3, Some(0))]),
        [true, false, false]
    );
}

/// The read a plant consults is the version of a GET that completed with
/// exactly the bytes an upload of its key wrote: an incomplete result, a
/// complete prefix of the upload, and another key's GET give none.
#[test]
fn a_plant_consults_only_a_complete_read_of_a_whole_upload() {
    let mut checker = fresh();
    let version = published(&mut checker, 0, 2000);
    let object = content(0, version, 0, 2000);
    assert_eq!(checker.complete_read(true, 0, &object), Some(version));
    assert_eq!(checker.complete_read(false, 0, &object), None);
    let prefix = &object[..1000];
    assert_eq!(
        decoded(prefix),
        Some((0, 0, version)),
        "a prefix names the upload"
    );
    assert_eq!(checker.complete_read(true, 0, prefix), None);
    assert_eq!(checker.complete_read(true, 1, &object), None);
}

/// A plant's effect changes the last byte of a read and no other: the
/// changed read keeps the upload's header and length, and the checker
/// finds no upload that wrote it.
#[test]
fn the_effect_changes_the_last_byte_of_a_read_alone() {
    let mut checker = fresh();
    let version = published(&mut checker, 0, 2000);
    let object = content(0, version, 0, 2000);
    let mut read = object.clone();
    assert!(misread(&mut read));
    assert_eq!(read[..1999], object[..1999]);
    assert_ne!(read[1999], object[1999]);
    assert_eq!(checker.complete_read(true, 0, &read), None);
    assert!(!misread(&mut []));
}

/// Through one partition's own GET numbering and publication report, a
/// depth 1 plant over key 0 leaves unchanged the read of the first GET
/// the partition accepts after P, which completes with version 0.
#[test]
fn a_get_accepted_after_p_reads_version_0_unchanged() {
    let (draws, _, setups) = drawn_at(shape("cluster-broad").unwrap(), 1);
    let plant = Plant::Depth1;
    let mut judged = false;
    super::nest(
        0,
        (&setups[..1], &draws, true),
        (4096, crate::net::link::UNBOUNDED),
        Vec::new(),
        &mut |mut cells| {
            let cell = &mut cells[0];
            let mut checker = checker(1, 1);
            checker.order = Order::new(plant, 0);
            let start = cell.start();
            let now = driven(
                cell,
                &mut checker,
                (plant, start),
                |_| true,
                |cell, _| cell.active(0),
            );
            assert_eq!(cell.put(0, 0, content(0, 0, 0, 2000), false, now), APPLIED);
            checker.invoked(0, 0, 2000);
            let now = driven(
                cell,
                &mut checker,
                (plant, now),
                |_| true,
                |cell, _| !cell.uploading(),
            );
            assert!(checker.keys[0].uploads[&0].published, "P happened");
            assert_eq!(cell.get(0, 0, (0, 0), false, now), APPLIED);
            driven(
                cell,
                &mut checker,
                (plant, now),
                |_| true,
                |_, checker| checker.reached.hits == 1,
            );
            assert_eq!(checker.reached.hits, 1, "the GET read version 0");
            assert_eq!((checker.first.get(), checker.acted), (None, false));
            judged = true;
        },
    );
    assert!(judged);
}

/// One step of a forced order at one partition.
#[derive(Clone, Copy, Debug)]
enum Step {
    /// I(c): client c's session accepts a GET of key 0.
    Issue(usize),
    /// R(c): client c's undecided GETs of key 0 are decided.
    Read(usize),
    /// Client c's session cancels its undecided GET of key 0, which the
    /// client's next read step decides.
    Cancel(usize),
    /// Client 0's session accepts an upload of key 0 at this version.
    Upload(u32),
    /// Client 0's session reports the outcome of its upload, published or
    /// not. Client 1 polls nothing while the step runs, so a GET it issued
    /// just before reaches the owner after the report.
    Outcome,
    /// [`Step::Outcome`] that reports the upload of this version
    /// published: P for version 0.
    Report(u32),
    /// Client 0 issues GETs until one reads version 0, each decided
    /// before the next: the owner binds the version.
    Bind,
    /// The partition takes this many steps of the drive, an event or a
    /// move of the clock each.
    Advance(u32),
    /// The links lose every datagram sent from here on.
    Lose,
    /// The links deliver every datagram sent from here on.
    Heal,
}

/// Whether `event` collects a read of `client`.
fn collects(event: &Candidate, client: usize) -> bool {
    event.0[1] == READ && usize::from(event.0[3]) == client
}

/// Applies `step` to the partition under `plant` from time `now` and
/// returns the time reached. A read holds back the collection of the
/// upload's outcome and of the other client's reads; an outcome holds
/// back the collection of every read and client 1's polls; an advance
/// holds back both collections.
fn stepped(
    cell: &mut Box<dyn super::Cell + '_>,
    checker: &mut Checker,
    (plant, mut now): (Plant, u64),
    step: Step,
) -> u64 {
    match step {
        Step::Issue(client) => {
            assert_eq!(cell.get(client, 0, (0, 0), false, now), APPLIED);
        }
        Step::Cancel(client) => assert_eq!(cell.cancel(client, 0), APPLIED),
        Step::Upload(version) => {
            let object = content(0, version, 0, 2000);
            assert_eq!(cell.put(0, version, object, false, now), APPLIED);
            checker.invoked(0, 0, 2000);
        }
        Step::Read(client) => {
            now = driven(
                cell,
                checker,
                (plant, now),
                |event| event.0[1] != OUTCOME && !collects(event, 1 - client),
                |cell, _| cell.pending(client) == 0,
            );
            assert_eq!(cell.pending(client), 0, "{step:?}");
        }
        Step::Outcome => {
            now = driven(
                cell,
                checker,
                (plant, now),
                |event| event.0[1] != READ && !(event.0[1] == CLIENT_POLL && event.0[3] == 1),
                |cell, _| !cell.uploading(),
            );
            assert!(!cell.uploading(), "{step:?}");
        }
        Step::Report(version) => {
            let reported = checker.reached.published;
            now = stepped(cell, checker, (plant, now), Step::Outcome);
            assert_eq!(
                checker.reached.published,
                reported + 1,
                "{step:?} collects one publication report"
            );
            assert!(checker.keys[0].uploads[&version].published, "{step:?}");
        }
        Step::Bind => {
            for _ in 0..64 {
                if checker.reached.hits == 1 {
                    break;
                }
                now = stepped(cell, checker, (plant, now), Step::Issue(0));
                now = stepped(cell, checker, (plant, now), Step::Read(0));
            }
            assert_eq!(checker.reached.hits, 1, "{step:?}");
        }
        Step::Advance(steps) => {
            let taken = std::cell::Cell::new(0);
            now = driven(
                cell,
                checker,
                (plant, now),
                |event| !matches!(event.0[1], OUTCOME | READ),
                |_, _| taken.replace(taken.get() + 1) >= steps,
            );
        }
        Step::Lose | Step::Heal => {
            let loss = if matches!(step, Step::Lose) { 100 } else { 0 };
            let links = Faults {
                loss,
                ..Faults::default()
            };
            cell.set_faults(links, SOUND, TxRelease::AtDelivery);
        }
    }
    now
}

/// Drives one partition under `plant` over key 0 through `steps`, from
/// the time client 0's session is active, and returns its checker.
fn partition(plant: Plant, steps: &[Step]) -> Checker {
    let (draws, _, setups) = drawn_at(shape("cluster-broad").unwrap(), 1);
    let mut ended = None;
    super::nest(
        0,
        (&setups[..1], &draws, true),
        (4096, crate::net::link::UNBOUNDED),
        Vec::new(),
        &mut |mut cells| {
            let cell = &mut cells[0];
            let mut checker = checker(1, 1);
            checker.order = Order::new(plant, 0);
            let subject = (plant, cell.start());
            let mut now = driven(
                cell,
                &mut checker,
                subject,
                |_| true,
                |cell, _| cell.active(0),
            );
            for &step in steps {
                now = stepped(cell, &mut checker, (plant, now), step);
            }
            ended = Some(checker);
        },
    );
    ended.expect("the partition ran")
}

/// Drives one partition under `plant` over key 0 through `steps`, and
/// returns the first failure and whether the plant acted. The partition
/// first accepts the upload of version 0 and serves client 0 a read of
/// it, so the owner binds the version before the first step and P is
/// still to come. The reads and the reports then happen in the order of
/// `steps`. When the plant stays idle, every GET the steps issued passed
/// the checks as a complete read of one upload.
fn forced(plant: Plant, steps: &[Step]) -> (Option<Failure>, bool) {
    let checker = partition(plant, &[&[Step::Upload(0), Step::Bind], steps].concat());
    let failure = checker.first.get();
    let issued = steps
        .iter()
        .filter(|step| matches!(step, Step::Issue(_)))
        .count() as u64;
    assert!(
        failure.is_some() || checker.reached.hits == 1 + issued,
        "{steps:?}: {:?}",
        checker.reached
    );
    (failure, checker.acted)
}

/// Through one partition's sessions, with the reads and the report forced
/// into each order: a plant changes the read that completes its premise
/// and the run fails under the foreign-bytes rule, and with one order of
/// the premise forced the other way every read passes unchanged.
#[test]
fn a_forced_order_is_caught_and_its_reverse_changes_no_read() {
    use Step::{Cancel, Issue, Read, Report, Upload};
    let cases: [(&[Step], [bool; 3]); 9] = [
        // I(0) before P, and the read after P with no R(1) before it.
        (&[Issue(0), Report(0), Read(0)], [true, false, false]),
        // The same orders for client 1, whose read depths 2 and 3 pass by.
        (&[Issue(1), Report(0), Read(1)], [true, false, false]),
        // R(1) before R(0), for a GET accepted before client 0's.
        (
            &[Issue(1), Issue(0), Report(0), Read(1), Read(0)],
            [true, true, false],
        ),
        // The same with R(1) decided before P.
        (
            &[Issue(1), Issue(0), Read(1), Report(0), Read(0)],
            [true, true, false],
        ),
        // I(0) before I(1), and R(1) before R(0).
        (
            &[Issue(0), Issue(1), Report(0), Read(1), Read(0)],
            [true, true, true],
        ),
        // The same with R(1) the outcome of a cancelled GET.
        (
            &[Issue(0), Issue(1), Report(0), Cancel(1), Read(1), Read(0)],
            [true, true, true],
        ),
        // R(0) before R(1).
        (
            &[Issue(0), Issue(1), Report(0), Read(0), Read(1)],
            [true, false, false],
        ),
        // P before I(0), after an R(1) decided before P.
        (
            &[Issue(1), Read(1), Report(0), Issue(0), Read(0)],
            [false, false, false],
        ),
        // I(1) before P, and the read completes with version 1.
        (
            &[Issue(1), Report(0), Upload(1), Report(1), Read(1)],
            [false, false, false],
        ),
    ];
    for (steps, acts) in cases {
        for (plant, acts) in PLANTS.into_iter().zip(acts) {
            let expected = if acts {
                (Some(FOREIGN), true)
            } else {
                (None, false)
            };
            assert_eq!(forced(plant, steps), expected, "{plant:?}: {steps:?}");
        }
    }
}

/// `Report(0)` must collect its own publication report even when
/// `Outcome` has already marked version 0 published.
#[test]
#[should_panic(expected = "Report(0) collects one publication report")]
fn a_report_step_fails_when_it_collects_no_publication_report() {
    use Step::{Bind, Outcome, Report, Upload};
    partition(Plant::Depth1, &[Upload(0), Bind, Outcome, Report(0)]);
}

/// A report of the first upload that is no publication is no P. The
/// links lose every datagram from some step of the upload until client
/// 0's session reports its outcome, and client 1's session accepts a GET
/// just before the loss. At the first such step where that report is no
/// publication and the GET, sent once the links heal, is neither a miss
/// nor a refusal, the owner bound version 0 and its reply was lost: the
/// depth 1 plant leaves that complete read unchanged. From the same step
/// it also leaves the read unchanged when the owner serves it before the
/// upload of version 1 and the client collects it after the report that
/// version 1 published.
#[test]
fn a_report_that_is_no_publication_is_no_p() {
    use Step::{Advance, Heal, Issue, Lose, Outcome, Read, Upload};
    let lost = |cut, after: &[Step]| {
        let reply = [Upload(0), Advance(cut), Issue(1), Lose, Outcome, Heal];
        partition(Plant::Depth1, &[&reply[..], after].concat())
    };
    let cut = (0..64).find(|&cut| {
        let reached = lost(cut, &[Read(1)]).reached;
        reached.published + reached.misses + reached.refused == 0
    });
    let cut = cut.expect("a step that loses the reply of a bound upload");
    let later = [Advance(200), Upload(1), Outcome, Read(1)];
    for (after, published) in [(&[Read(1)][..], 0), (&later[..], 1)] {
        let checker = lost(cut, after);
        let reached = checker.reached;
        assert_eq!(
            (checker.first.get(), checker.acted),
            (None, false),
            "{after:?}"
        );
        assert_eq!(
            (reached.hits, reached.published, checker.last),
            (1, published, Some((0, 0, 0))),
            "{after:?}"
        );
    }
}

/// What a run and its replay must agree on.
fn ending(ran: &Ran) -> (Option<Failure>, bool, End, Terminal, [u64; 3]) {
    let report = &ran.report;
    (
        ran.failure.clone(),
        ran.acted,
        report.end,
        ran.judged(),
        [report.turn_count, report.progress, report.virtual_us],
    )
}

/// The control of `depth` from `root`. The drawn run forms the premise:
/// the plant acts on a complete read of the hot key the hook saw fall in
/// the depth's orders, and the run fails under the foreign-bytes rule with
/// a terminal a sweep credits as a violation. The same root with the
/// selection that issued the selected GET given to another event ends
/// with the control's no-effect ending, which a sweep judges complete and
/// unsuccessful. The forced selection is on the tape as a decision, so
/// each run's tape replays to the same ending with no hook.
fn caught_as_drawn_and_idle_once_diverted(depth: u8, root: u64) {
    let (drawn, witness) = witnessed(depth, root, None);
    assert!(drawn.acted, "root {root}");
    assert_eq!(drawn.failure, Some(FOREIGN), "root {root}");
    assert!(
        matches!(
            drawn.judged(),
            Terminal::Complete {
                outcome: Outcome::Violation,
                ..
            }
        ),
        "root {root}: {:?}",
        drawn.judged()
    );
    assert_eq!(witness.turns, drawn.report.turn_count, "root {root}");
    let Failed {
        key,
        client,
        issue,
        read,
        complete,
    } = witness.failed.expect("the failed read");
    assert!(key == witness.key && complete, "root {root}");
    // I before P, and the read after P.
    let (report, published) = witness.reported.expect("the first upload's outcome");
    assert!(published && issue < report && report < read, "root {root}");
    // R(1) before R(0), and at depth 3 for a GET accepted after I(0).
    let earlier = witness
        .decided
        .iter()
        .filter(|&&(by, issued)| by == 1 && (depth < 3 || issued > issue));
    assert!(
        depth == 1 || client == 0 && earlier.count() > 0,
        "root {root}"
    );
    assert_eq!(ending(&replayed(depth, root, witness.tape)), ending(&drawn));
    let (diverted, witness) = witnessed(depth, root, Some(issue));
    assert!(
        witness.diverted,
        "root {root}: turn {issue} offered no other event"
    );
    assert_eq!(
        (
            diverted.acted,
            diverted.report.end,
            diverted.failure.clone()
        ),
        (false, End::Done, Some(Failure::Unsuccessful(NO_EFFECT))),
        "root {root}"
    );
    assert!(
        matches!(
            diverted.judged(),
            Terminal::Complete {
                outcome: Outcome::Unsuccessful,
                ..
            }
        ),
        "root {root}: {:?}",
        diverted.judged()
    );
    assert_eq!(
        ending(&replayed(depth, root, witness.tape)),
        ending(&diverted)
    );
}

#[test]
fn the_depth_1_control_is_caught_as_drawn_and_idle_once_its_get_is_diverted() {
    caught_as_drawn_and_idle_once_diverted(1, 18);
}

#[test]
fn the_depth_2_control_is_caught_as_drawn_and_idle_once_its_get_is_diverted() {
    caught_as_drawn_and_idle_once_diverted(2, 141);
}

#[test]
fn the_depth_3_control_is_caught_as_drawn_and_idle_once_its_get_is_diverted() {
    caught_as_drawn_and_idle_once_diverted(3, 7);
}
