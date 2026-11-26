//! Each armed reach of a chaos point makes one bounded decision at the
//! point's site and fires on 0, a refused decision latches and fires
//! nothing, and a tape's census counts each point's reaches and fires.

use std::cell::RefCell;
use std::rc::Rc;

use super::{
    CATALOG, Census, EXCHANGE_LOST_LEASE_LIMIT, MARK, Point, Row, acting, arm, census, fire, odds,
    odds_within, refusal, silence, sites,
};
use crate::net::world_tests::{files_holding, scratch};
use crate::sim::choice::{ChoiceError, Chooser, Defect, Domain, Identity, Site, bounded_decisions};
use crate::storage::seeded::SplitMix64;

const ROOT: u64 = 0x5EED_CA05;

const ACTOR: u16 = 4;

const OTHER: Site = Site {
    domain: Domain::Workload,
    actor: 0,
    site: 1,
};

const GOLDEN: [(u16, &str, Point); 3] = [
    (1, "gate-busy", Point::GateBusy),
    (2, "capture-busy", Point::CaptureBusy),
    (3, "exchange-lost", Point::ExchangeLost),
];

fn chooser() -> (Rc<RefCell<Chooser>>, u32) {
    let mut registered = sites(ACTOR);
    registered.push(OTHER);
    let mut chooser = Chooser::record(ROOT, &registered);
    chooser.launch(OTHER.actor);
    let incarnation = chooser.launch(ACTOR);
    (Rc::new(RefCell::new(chooser)), incarnation)
}

/// A reach of `point` inside a production action.
fn reach(point: Point) -> bool {
    acting(|| fire(point))
}

fn finish(chooser: Rc<RefCell<Chooser>>) -> Vec<u8> {
    Rc::try_unwrap(chooser)
        .expect("disarming released the chooser")
        .into_inner()
        .finish()
        .unwrap()
}

#[test]
fn the_codes_match_their_golden_table() {
    assert_eq!(Point::ALL.len(), GOLDEN.len());
    assert_eq!(CATALOG.len(), GOLDEN.len());
    for ((code, name, point), row) in GOLDEN.into_iter().zip(&CATALOG) {
        assert_eq!((row.point, row.name), (point, name));
        assert_eq!(point as u16, code);
        assert_eq!(point.row().name, name);
        assert_eq!(point.site(ACTOR).site, code);
    }
    assert_eq!(Domain::Chaos as u8, 8);
    assert_eq!(Domain::from_code(8), Some(Domain::Chaos));
}

#[test]
fn an_unarmed_point_fires_nothing_and_draws_nothing() {
    let (chooser, incarnation) = chooser();
    for _ in 0..64 {
        assert!(Point::ALL.into_iter().all(|point| !reach(point)));
    }
    assert_eq!(chooser.borrow().decisions(), 0);
    let armed = arm(&chooser, (ACTOR, incarnation), [1, 1, 1]);
    assert!(reach(Point::GateBusy));
    assert_eq!(armed.disarm(), None);
    let decided = chooser.borrow().decisions();
    for _ in 0..64 {
        assert!(Point::ALL.into_iter().all(|point| !reach(point)));
    }
    assert_eq!(chooser.borrow().decisions(), decided);
    assert_eq!(finish(chooser).len(), 2 * crate::sim::choice::RECORD_LEN);
}

#[test]
fn an_armed_point_is_one_bounded_decision_that_fires_on_zero() {
    let (recording, incarnation) = chooser();
    let bounds = [4, 3, 2];
    let armed = arm(&recording, (ACTOR, incarnation), bounds);
    let reaches: Vec<Point> = (0..96).map(|at| Point::ALL[at % 5 % 3]).collect();
    let fired: Vec<bool> = reaches.iter().map(|&point| reach(point)).collect();
    assert_eq!(armed.disarm(), None);
    let decisions = bounded_decisions(&finish(recording)).unwrap();
    assert_eq!(decisions.len(), reaches.len(), "one decision per reach");
    let mut occurrences = [0; Point::ALL.len()];
    for ((&point, &fired), &(site, value)) in reaches.iter().zip(&fired).zip(&decisions) {
        assert_eq!(site, point.site(ACTOR));
        let occurrence = &mut occurrences[point.at()];
        let identity = Identity {
            site,
            incarnation,
            occurrence: *occurrence,
        };
        *occurrence += 1;
        let bound = bounds[point.at()];
        assert_eq!(value, SplitMix64::new(identity.seed(ROOT)).below(bound));
        assert_eq!(fired, value == 0, "{point:?} at occurrence {occurrence}");
    }
    assert!(fired.contains(&true) && fired.contains(&false));

    let (always, incarnation) = chooser();
    let armed = arm(&always, (ACTOR, incarnation), [1, 0, 0]);
    assert!((0..16).all(|_| reach(Point::GateBusy)));
    assert!((0..16).all(|_| !reach(Point::CaptureBusy)));
    assert_eq!(armed.disarm(), None);
    assert_eq!(always.borrow().decisions(), 16);
}

/// An armed point reached outside every production action, as a harness
/// check between turns reaches it, decides nothing and fires nothing.
#[test]
fn an_armed_point_outside_an_action_decides_nothing() {
    let (chooser, incarnation) = chooser();
    let armed = arm(&chooser, (ACTOR, incarnation), [1, 1, 1]);
    assert!(Point::ALL.into_iter().all(|point| !fire(point)));
    assert!(acting(
        || fire(Point::GateBusy) && acting(|| fire(Point::CaptureBusy))
    ));
    assert!(
        !fire(Point::GateBusy),
        "the action's end restores the state"
    );
    assert_eq!(armed.disarm(), None);
    assert_eq!(chooser.borrow().decisions(), 2);
}

#[test]
fn a_replayed_tape_fires_the_same_points_and_a_changed_selection_another_set() {
    let fires = |chooser: &Rc<RefCell<Chooser>>, incarnation| {
        let armed = arm(chooser, (ACTOR, incarnation), [4, 4, 4]);
        let fired: Vec<bool> = (0..33).map(|at| reach(Point::ALL[at % 3])).collect();
        assert_eq!(armed.disarm(), None);
        fired
    };
    let (recording, incarnation) = chooser();
    let recorded = fires(&recording, incarnation);
    let tape = finish(recording);
    let replaying = |tape: Vec<u8>| {
        let mut registered = sites(ACTOR);
        registered.push(OTHER);
        let mut chooser = Chooser::replay(&registered, tape);
        chooser.launch(OTHER.actor);
        let incarnation = chooser.launch(ACTOR);
        (Rc::new(RefCell::new(chooser)), incarnation)
    };
    let (replay, incarnation) = replaying(tape.clone());
    assert_eq!(fires(&replay, incarnation), recorded);
    assert_eq!(finish(replay), tape);

    let first = recorded.iter().position(|&fired| fired).expect("a fire");
    let mut changed = tape;
    let selection = (2 * first + 1) * crate::sim::choice::RECORD_LEN + 1;
    changed[selection] = 1;
    let (replay, incarnation) = replaying(changed);
    let refired = fires(&replay, incarnation);
    assert_ne!(refired, recorded);
    assert!(!refired[first]);
}

#[test]
fn a_point_changes_no_other_sites_values() {
    let (armed_chooser, incarnation) = chooser();
    let mut plain = Chooser::record(ROOT, &[OTHER]);
    plain.launch(OTHER.actor);
    let armed = arm(&armed_chooser, (ACTOR, incarnation), [2, 2, 2]);
    let mut fired = Vec::new();
    for at in 0..64 {
        fired.push(reach(Point::ALL[at % 3]));
        let beside = armed_chooser.borrow_mut().bounded(OTHER, 0, 1 << 20);
        assert!(beside.is_ok(), "decision {at}: {beside:?}");
        assert_eq!(beside, plain.bounded(OTHER, 0, 1 << 20), "decision {at}");
    }
    assert_eq!(armed.disarm(), None);
    assert_eq!(armed_chooser.borrow().decisions(), 128);
    assert!(fired.contains(&true) && fired.contains(&false));
}

#[test]
fn a_refused_draw_latches_and_fires_nothing() {
    let unregistered = Rc::new(RefCell::new(Chooser::record(ROOT, &[OTHER])));
    let incarnation = unregistered.borrow_mut().launch(ACTOR);
    let armed = arm(&unregistered, (ACTOR, incarnation), [1, 1, 1]);
    let site = Point::GateBusy.site(ACTOR);
    assert!(!reach(Point::GateBusy));
    let expected = ChoiceError::HarnessDefect(Defect::Unregistered(site));
    assert_eq!(refusal(), Some(expected));
    assert!(!reach(Point::CaptureBusy));
    assert_eq!(armed.disarm(), Some(expected));
    assert_eq!(refusal(), None);

    let (stale, incarnation) = chooser();
    let armed = arm(&stale, (ACTOR, incarnation + 1), [1, 1, 1]);
    assert!(!reach(Point::CaptureBusy));
    assert_eq!(
        armed.disarm(),
        Some(ChoiceError::HarnessDefect(Defect::Incarnation {
            actor: ACTOR,
            incarnation: incarnation + 1,
        }))
    );
    assert_eq!(stale.borrow().decisions(), 0);

    let (held, incarnation) = chooser();
    let armed = arm(&held, (ACTOR, incarnation), [1, 1, 1]);
    let borrow = held.borrow_mut();
    assert!(!reach(Point::CaptureBusy));
    drop(borrow);
    assert!(!reach(Point::GateBusy), "a latched refusal fires nothing");
    let site = Point::CaptureBusy.site(ACTOR);
    assert_eq!(
        armed.disarm(),
        Some(ChoiceError::HarnessDefect(Defect::Borrowed(site)))
    );
    assert_eq!(held.borrow().decisions(), 0);
}

#[test]
fn a_fed_chooser_feeds_the_points_in_reach_order() {
    let mut registered = sites(ACTOR);
    registered.push(OTHER);
    let mut fed = Chooser::fed(&registered, vec![4, 1, 7, 8]);
    fed.launch(OTHER.actor);
    let incarnation = fed.launch(ACTOR);
    let chooser = Rc::new(RefCell::new(fed));
    let armed = arm(&chooser, (ACTOR, incarnation), [4, 4, 4]);
    assert!(reach(Point::GateBusy), "4 below 4 is 0");
    assert!(!reach(Point::CaptureBusy), "1 below 4 is 1");
    assert_eq!(chooser.borrow_mut().bounded(OTHER, 0, 16), Ok(7));
    assert!(reach(Point::CaptureBusy), "8 below 4 is 0");
    assert!(!reach(Point::GateBusy), "the input is spent");
    assert_eq!(armed.disarm(), Some(ChoiceError::Short));
    assert_eq!(chooser.borrow().decisions(), 4);
}

#[test]
fn unwinding_disarms_the_points() {
    let (chooser, incarnation) = chooser();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _armed = arm(&chooser, (ACTOR, incarnation), [1, 1, 1]);
        assert!(reach(Point::GateBusy));
        panic!("unwind while armed");
    }));
    assert!(unwound.is_err());
    assert_eq!(Rc::strong_count(&chooser), 1);
    assert!(!reach(Point::GateBusy));
    let armed = arm(&chooser, (ACTOR, incarnation), [1, 1, 1]);
    let decided = chooser.borrow().decisions();
    let unwound = std::panic::catch_unwind(|| acting(|| panic!("unwind inside an action")));
    assert!(unwound.is_err());
    assert!(
        !fire(Point::GateBusy),
        "an action that unwinds restores the state"
    );
    assert_eq!(chooser.borrow().decisions(), decided);
    assert!(reach(Point::GateBusy));
    assert_eq!(armed.disarm(), None);
}

#[test]
fn silenced_points_decide_nothing_and_keep_the_latch() {
    let (stale, incarnation) = chooser();
    let armed = arm(&stale, (ACTOR, incarnation + 1), [1, 1, 1]);
    assert!(!reach(Point::GateBusy));
    silence();
    assert!(!reach(Point::GateBusy));
    assert!(refusal().is_some());
    assert!(armed.disarm().is_some());

    let (quiet, incarnation) = chooser();
    let armed = arm(&quiet, (ACTOR, incarnation), [1, 1, 1]);
    silence();
    assert!(Point::ALL.into_iter().all(|point| !reach(point)));
    assert_eq!(armed.disarm(), None);
    assert_eq!(quiet.borrow().decisions(), 0);
}

#[test]
fn the_census_counts_reaches_and_fires_from_the_tape() {
    assert_eq!(census(&[]), Some([Census::default(); Point::ALL.len()]));
    let (recording, incarnation) = chooser();
    let armed = arm(&recording, (ACTOR, incarnation), [3, 2, 2]);
    let mut expected = [Census::default(); Point::ALL.len()];
    let candidates = [
        crate::sim::choice::Candidate([1; 16]),
        crate::sim::choice::Candidate([2; 16]),
    ];
    for at in 0..42 {
        let point = Point::ALL[at % 3];
        let fired = reach(point);
        let counts = &mut expected[point.at()];
        counts.reached += 1;
        counts.fired += u64::from(fired);
        let mut chooser = recording.borrow_mut();
        let picked = chooser.index(point.site(ACTOR), incarnation, &candidates[..1]);
        assert_eq!(picked, Ok(0));
        chooser.bounded(OTHER, 0, 1).unwrap();
        chooser.index(OTHER, 0, &candidates).unwrap();
        chooser.bytes(OTHER, 0, &mut [0; 40]).unwrap();
    }
    assert_eq!(armed.disarm(), None);
    let tape = finish(recording);
    let counted = census(&tape).unwrap();
    assert_eq!(counted, expected);
    assert!(counted.iter().all(|point| point.fired <= point.reached));
    assert!(counted.iter().all(|point| point.fired > 0));

    let mut plain = Chooser::record(ROOT, &[OTHER]);
    plain.launch(OTHER.actor);
    plain.bounded(OTHER, 0, 1).unwrap();
    assert_eq!(
        census(&plain.finish().unwrap()),
        Some([Census::default(); Point::ALL.len()])
    );
    assert_eq!(census(&tape[..tape.len() - 1]), None);
}

#[test]
fn a_lease_limit_below_two_leaves_exchange_lost_unarmed() {
    assert_eq!(odds(), [4; Point::ALL.len()]);
    assert_eq!(EXCHANGE_LOST_LEASE_LIMIT, 2);
    for limit in [2, 3, 16, usize::MAX] {
        assert_eq!(odds_within(limit), odds(), "a limit of {limit}");
    }
    for limit in [0, 1] {
        let within = odds_within(limit);
        for point in Point::ALL {
            let expected = match point {
                Point::ExchangeLost => 0,
                _ => point.row().odds,
            };
            assert_eq!(
                within[point.at()],
                expected,
                "{point:?} at a limit of {limit}"
            );
        }
        let mut registered = sites(ACTOR);
        registered.push(OTHER);
        let mut fed = Chooser::fed(&registered, vec![0, 0]);
        fed.launch(OTHER.actor);
        let incarnation = fed.launch(ACTOR);
        let chooser = Rc::new(RefCell::new(fed));
        let armed = arm(&chooser, (ACTOR, incarnation), within);
        assert!((0..8).all(|_| !reach(Point::ExchangeLost)));
        assert_eq!(chooser.borrow().decisions(), 0);
        assert!(reach(Point::GateBusy) && reach(Point::CaptureBusy));
        assert_eq!(armed.disarm(), None);
        assert_eq!(chooser.borrow().decisions(), 2);
    }
}

#[test]
fn every_row_is_complete() {
    for row in &CATALOG {
        assert_eq!(gaps(row), [""; 0], "{}", row.name);
        for (gap, broken) in [
            ("odds below one", Row { odds: 0, ..*row }),
            (
                "an empty function",
                Row {
                    function: " ",
                    ..*row
                },
            ),
            (
                "a function in a trait impl",
                Row {
                    function: "Gate::drop (trait impl)",
                    ..*row
                },
            ),
            (
                "an empty outcome",
                Row {
                    outcome: " ",
                    ..*row
                },
            ),
            (
                "an empty permitting text",
                Row {
                    permits: " ",
                    ..*row
                },
            ),
            ("an empty cause", Row { cause: " ", ..*row }),
        ] {
            assert_eq!(gaps(&broken), [gap], "{}", row.name);
        }
    }
}

/// What `row` leaves unstated or misplaces: odds below one, an empty
/// function or one in a trait impl, or an empty outcome, permitting text
/// or cause.
fn gaps(row: &Row) -> Vec<&'static str> {
    [
        (row.odds < 1, "odds below one"),
        (row.function.trim().is_empty(), "an empty function"),
        (
            row.function.contains("(trait impl)"),
            "a function in a trait impl",
        ),
        (row.outcome.trim().is_empty(), "an empty outcome"),
        (row.permits.trim().is_empty(), "an empty permitting text"),
        (row.cause.trim().is_empty(), "an empty cause"),
    ]
    .into_iter()
    .filter_map(|(gap, text)| gap.then_some(text))
    .collect()
}

pub(crate) const REVERSED_MARK: &str = "golatac tniop soahc ekirtsek";

/// The compiler checks that reversing `REVERSED_MARK` yields `MARK`.
const _: () = {
    let (mark, reversed) = (MARK.as_bytes(), REVERSED_MARK.as_bytes());
    assert!(mark.len() == reversed.len());
    let mut at = 0;
    while at < mark.len() {
        assert!(mark[at] == reversed[mark.len() - 1 - at]);
        at += 1;
    }
};

/// A file under the walked tree that holds the mark next to bytes that are
/// not UTF-8 is found, and one whose bytes are not UTF-8 and hold no mark
/// is not. A symlink to either file, a symlink to a directory and a root
/// that is a symlink are each an error that names the link.
#[test]
fn the_mark_walk_reads_every_file_and_refuses_a_symlink() {
    let needle: Vec<u8> = REVERSED_MARK.bytes().rev().collect();
    let dir = scratch("mark-walk").unwrap();
    std::fs::create_dir(dir.join("nested")).unwrap();
    let marked = dir.join("nested").join("fixture.bin");
    std::fs::write(&marked, [&[0xFF][..], &needle, &[0xFE]].concat()).unwrap();
    std::fs::write(dir.join("clean.rs"), "").unwrap();
    let unmarked = dir.join("clean.bin");
    std::fs::write(&unmarked, [0xFF, 0xFE]).unwrap();
    assert_eq!(files_holding(&dir, &needle), Ok(vec![marked.clone()]));
    let link = dir.join("link");
    for target in [marked.clone(), unmarked, dir.join("nested")] {
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let refusal = files_holding(&dir, &needle);
        assert!(
            refusal
                .as_ref()
                .is_err_and(|error| error.contains(&link.display().to_string())),
            "the walk follows a symlink to {}: {refusal:?}",
            target.display()
        );
        std::fs::remove_file(&link).unwrap();
    }
    let root = scratch("mark-walk-root").unwrap().join("root");
    std::os::unix::fs::symlink(&dir, &root).unwrap();
    let refusal = files_holding(&root, &needle);
    assert!(
        refusal
            .as_ref()
            .is_err_and(|error| error.contains(&root.display().to_string())),
        "the walk follows a root that is a symlink: {refusal:?}"
    );
    std::fs::remove_dir_all(root.parent().unwrap()).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A FIFO with no writer in the walked tree is an error that names it. The
/// case runs in a fresh child of the test executable under a deadline, so
/// a walk that opens the FIFO and waits fails the case.
#[test]
fn the_mark_walk_refuses_a_fifo_by_name() {
    crate::exact_child::run(
        "sim::chaos::tests::the_mark_walk_refuses_a_fifo_by_name",
        std::time::Duration::from_secs(60),
        || {
            let dir = scratch("mark-walk-fifo").unwrap();
            let fifo = dir.join("fifo");
            let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: `name` is a NUL-terminated path that outlives the call.
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            let refusal = files_holding(&dir, b"mark");
            assert!(
                refusal
                    .as_ref()
                    .is_err_and(|error| error.contains(&fifo.display().to_string())),
                "{refusal:?}"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        },
    );
}

/// No file under `src` holds the chaos mark whole, so a copy of one that a
/// test embeds holds none, and the forward mark in the test executable is
/// the linked `MARK` or a copy embedded from outside `src`, which the walk
/// does not read.
#[test]
fn the_test_executable_links_the_mark() {
    let needle: String = REVERSED_MARK.chars().rev().collect();
    // The executable embeds `REVERSED_MARK`, so a match establishes linkage
    // only when the scan uses the forward mark.
    assert!(
        needle.starts_with("kestrike ") && needle.ends_with(" catalog"),
        "the scan searches for the forward mark, not for {needle:?}"
    );
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert_eq!(files_holding(&src, needle.as_bytes()), Ok(Vec::new()));
    let executable = std::fs::read("/proc/self/exe").unwrap();
    assert!(
        memchr::memmem::find(&executable, needle.as_bytes()).is_some(),
        "the test executable holds the chaos mark"
    );
}
