//! Cluster runs: multi-owner generated workloads on one retained world,
//! their controls, their topology draws and their replay.

use crate::sim::manifest::Manifest;
use crate::sim::trace::{Outcome, Terminal, load};
use crate::sim::turn::World;

use super::super::bundle::{admit, observed, run_into, traced, unsuccessful_rule};
use super::super::replay::{Replayed, replay_recording};
use super::{
    CLIENTS, Checker, Judged, KeyState, PROFILES, Plant, Reached, Shape, Topology, content,
    decoded, run, shape,
};
use crate::net::audit::{Class, Verdict};
use crate::net::fetch::Outcome as Fetched;
use crate::net::frame::Status;
use crate::net::observe::FirstFailure;
use crate::net::upload::UploadOutcome;
use crate::oracle::Obligation;
use crate::storage::{AllocationId, SlotIndex};

fn manifest(profile: &str, root: u64) -> Manifest {
    let text = crate::sim::manifest_tests::sample(profile, &"a".repeat(64), "x86_64-linux")
        .replace("root = 3", &format!("root = {root}"));
    Manifest::parse(&text).unwrap()
}

/// A checker over `owners` owners and `keys` keys with no upload recorded.
pub(super) fn checker(owners: u8, keys: usize) -> Checker {
    Checker {
        owners,
        keys: vec![
            KeyState {
                next: Some(0),
                ..KeyState::default()
            };
            keys
        ],
        served: [0; CLIENTS].map(|_| vec![false; usize::from(owners)]),
        reached: Reached::default(),
        last: None,
        first: FirstFailure::default(),
        carried: 0,
        windows: 0,
        planted: false,
        leaked: None,
        acted: false,
        order: super::order::Order::new(super::Plant::None, 0),
    }
}

/// A checker over two owners and two keys with no upload recorded.
pub(super) fn fresh() -> Checker {
    checker(2, 2)
}

/// A cluster world of `shape` over `topology` and `cells`, judged by
/// `checker`, at `phase` with nothing yet run.
fn world<'c>(
    shape: &'static Shape,
    topology: Topology,
    cells: Vec<Box<dyn super::Cell + 'c>>,
    checker: Checker,
    phase: super::Phase,
) -> super::Cluster<'c> {
    super::Cluster {
        shape,
        topology,
        conserved: vec![0; cells.len()],
        cells,
        checker,
        phase,
        progress: 0,
        start: 0,
        acts: Vec::new(),
        failure_emitted: false,
        boundaries: 0,
        draw_refusal: None,
        puts: 0,
        stalled: false,
        now: 0,
        window_events: Vec::new(),
        marks: super::Marks::default(),
        corrupted: false,
        rested_us: 0,
        resume_at: 0,
    }
}

/// Generated GET `client`'s read of `key` at its contract owner, issued at
/// `floor`.
fn get(client: usize, key: u8, floor: u32) -> Judged {
    Judged {
        client,
        owner: key % 2,
        key,
        floor,
        probe: false,
    }
}

/// Records and publishes an upload of `key` of `len` bytes at its contract
/// owner; returns its version.
pub(super) fn published(checker: &mut Checker, key: u8, len: u32) -> u32 {
    let version = checker.next_version(key).unwrap();
    checker.invoked(key, key % 2, len);
    checker.published(key, version, false);
    version
}

/// Turn limits that let every drawn topology finish, four owners included;
/// the sample manifest's `same_time` of 400 stops some four-owner draws.
pub(super) const RAISED: crate::sim::turn::Limits = crate::sim::turn::Limits {
    total: 200_000,
    same_time: 4_000,
    no_progress: 50_000,
};

/// `manifest` with the [`RAISED`] turn limits.
fn raised(manifest: Manifest) -> Manifest {
    manifest
        .with("turns", RAISED.total)
        .with("same_time", RAISED.same_time)
        .with("no_progress", RAISED.no_progress)
}

/// `shape`'s profile at `root`.
pub(super) fn profile_at(shape: &'static Shape, root: u64) -> crate::sim::action::Profile {
    crate::sim::action::Profile {
        name: shape.name,
        declared: super::DECLARED.to_vec(),
        root,
    }
}

/// The draws of `shape`'s run at `root` past its topology and setup
/// draws, with the topology and every partition's setup.
pub(super) fn drawn_at(
    shape: &'static Shape,
    root: u64,
) -> (crate::net::link::Draws, Topology, Vec<super::Setup>) {
    let profile = profile_at(shape, root);
    let draws = std::rc::Rc::new(std::cell::RefCell::new(profile.recorder(&super::sites())));
    let (topology, setups) = super::drawn_setup(&draws, shape).unwrap();
    (draws, topology, setups)
}

/// Runs `shape` from `root` directly within `total` turns and the raised
/// same-time and no-progress limits, through `hook`.
fn run_for(
    shape: &'static Shape,
    root: u64,
    total: u64,
    hook: &mut impl crate::sim::turn::Hook,
) -> super::Ran {
    let profile = profile_at(shape, root);
    let chooser = profile.recorder(&super::sites());
    let limits = crate::sim::turn::Limits { total, ..RAISED };
    run(
        chooser,
        &profile,
        shape,
        (limits, 4096, crate::net::link::UNBOUNDED),
        hook,
    )
}

/// Runs `shape` from `root` directly within the [`RAISED`] limits.
fn run_root(shape: &'static Shape, root: u64) -> super::Ran {
    run_for(shape, root, RAISED.total, &mut ())
}

/// Runs `shape` from `root` directly and returns what it reached, its
/// first failure, its topology and whether it ended done.
fn ran(shape: &'static Shape, root: u64) -> (Reached, Option<super::Failure>, Topology, bool) {
    let ran = run_root(shape, root);
    let done = ran.report.end == crate::sim::turn::End::Done;
    (
        ran.reached,
        ran.failure,
        ran.topology.expect("the root drew a topology"),
        done,
    )
}

/// An object's bytes name its key, version and owner, and bytes changed in
/// any position decode to nothing.
#[test]
fn objects_name_their_key_version_and_owner() {
    let bytes = content(3, 7, 1, 2000);
    assert_eq!(decoded(&bytes), Some((3, 1, 7)));
    for at in [0, 3, 1999] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert_eq!(decoded(&changed), None, "byte {at}");
    }
}

/// The broad profile on one retained world: several owners, faults
/// delivered, a logical client reading across owners, every healthy phase's
/// probes passing, and the bundle counting as a pass; at root 4 a passing
/// run collects failed upload outcomes within `upload_attempts`.
#[test]
fn a_broad_cluster_run_crosses_owners_and_heals_on_one_world() {
    let broad = shape("cluster-broad").unwrap();
    let run = run_root(broad, 7);
    let (reached, failure, topology) = (run.reached, run.failure, run.topology);
    assert_eq!(failure, None, "{reached:?}");
    assert_eq!(run.report.end, crate::sim::turn::End::Done, "{reached:?}");
    let topology = topology.expect("the root drew a topology");
    assert!(topology.owners >= 2);
    assert!(
        reached.cross > 0 && reached.faults > 0 && reached.hits > 0,
        "{reached:?}"
    );
    assert!(
        reached.invalidated > 0 && reached.cancelled > 0,
        "the broad profile exercises its invalidate and cancel dimensions: {reached:?}"
    );
    assert_eq!(
        reached.healthy, 3,
        "every healthy phase ran on the same world"
    );
    assert!(run.puts <= broad.upload_attempts());
    let mut failed = FailedUploads(0);
    let run = run_for(broad, 4, 200_000, &mut failed);
    assert_eq!(run.failure, None, "root 4: {:?}", run.reached);
    assert_eq!(run.report.end, crate::sim::turn::End::Done, "root 4");
    assert!(run.puts <= broad.upload_attempts());
    assert!(
        failed.0 > 0,
        "the run collects failed upload outcomes, so the failed-upload checks run"
    );
    let manifest = manifest("cluster-broad", 7);
    let closed = traced(admit(&manifest).unwrap(), Vec::new());
    let loaded = load(&closed.sink, manifest.capacity().records()).unwrap();
    assert!(loaded.terminal.counts(), "{:?}", loaded.terminal);
    assert!(loaded.work.turns > 0, "{:?}", loaded.work);
    let seen = observed(&loaded.events);
    let composed = seen.composed.unwrap();
    assert_eq!(composed.owners, u16::from(topology.owners));
    assert_eq!(composed.clients, CLIENTS as u16);
    assert!(seen.faults > 0 && seen.operations > 0);
    let (drawn, counts) = seen.coverage.unwrap();
    assert_eq!(drawn, topology);
    assert_eq!(
        counts.map(u64::from),
        reached.counts(),
        "the bundle records what the run reached"
    );
}

/// The pressure profile publishes more objects than its owners hold, so
/// storage reuses slots, its healthy phases still pass with uploads within
/// the declared `upload_attempts`, and the bundle counts.
#[test]
fn a_pressure_run_reuses_storage_and_heals() {
    let pressure = shape("cluster-pressure").unwrap();
    let run = run_root(pressure, 11);
    assert!(run.puts <= pressure.upload_attempts());
    let (reached, failure, done) = (
        run.reached,
        run.failure,
        run.report.end == crate::sim::turn::End::Done,
    );
    assert_eq!(failure, None, "{reached:?}");
    assert!(done);
    assert!(reached.reused > 0, "{reached:?}");
    assert_eq!(reached.healthy, 2);
    let manifest = raised(manifest("cluster-pressure", 11));
    let closed = traced(admit(&manifest).unwrap(), Vec::new());
    assert!(closed.terminal.counts(), "{:?}", closed.terminal);
}

/// The swarm profile at three pinned roots, through the admission of its
/// manifest: one owner on quiet links, two owners on faulted links and
/// four owners. Each run has the owner and key counts of the member its
/// root selects, heals every phase of that member, and counts as a pass.
#[test]
fn swarm_roots_run_the_members_they_select_to_a_counted_pass() {
    for (root, owners, quiet) in [(9, 1, true), (8, 2, false), (17, 4, false)] {
        let member = super::swarm::member(root);
        assert_eq!(member.owners, (owners, owners), "root {root}");
        assert_eq!(
            member.faults == super::link_faults(0, 0, 0, 0),
            quiet,
            "root {root}"
        );
        let manifest = manifest(super::swarm::NAME, root);
        let closed = traced(admit(&manifest).unwrap(), Vec::new());
        assert!(
            closed.terminal.counts(),
            "root {root}: {:?}",
            closed.terminal
        );
        let loaded = load(&closed.sink, manifest.capacity().records()).unwrap();
        let (drawn, counts) = observed(&loaded.events).coverage.unwrap();
        assert_eq!(
            (drawn.owners, drawn.keys),
            (member.owners.0, member.keys.0),
            "root {root}"
        );
        let [.., healthy, _] = counts;
        assert_eq!(healthy, member.phases, "root {root}");
    }
}

/// The wrong-owner and stale-read controls fail the cluster checker's
/// named checks.
#[test]
fn wrong_owner_and_stale_read_controls_fail_their_checks() {
    for (name, rule) in [
        (
            "cluster-wrong-owner",
            "a key was served from an owner its routing contract does not name",
        ),
        (
            "cluster-stale-read",
            "a GET returned a version older than one collected or removed before it",
        ),
    ] {
        let shape = shape(name).unwrap();
        assert_ne!(shape.plant, Plant::None);
        let failed = (1..=8).find_map(|root| {
            ran(shape, root)
                .1
                .filter(|failure| matches!(failure, super::Failure::Violation(..)))
        });
        assert_eq!(
            failed,
            Some(super::Failure::Violation(
                crate::oracle::Obligation::History,
                rule
            )),
            "{name}"
        );
    }
}

/// One owner's run is no cluster: no client reads from two owners, so a
/// profile requiring cross-owner reads ends unsuccessful.
#[test]
fn a_single_owner_world_earns_no_cross_owner_coverage() {
    static SINGLE: Shape = Shape {
        name: "cluster-broad",
        owners: (1, 1),
        minima: super::Minima {
            cross: 1,
            ..super::NO_MINIMA
        },
        ..PROFILES[0]
    };
    let (reached, failure, topology, _) = ran(&SINGLE, 7);
    assert_eq!(topology.owners, 1);
    assert_eq!(reached.cross, 0);
    assert_eq!(
        failure,
        Some(super::Failure::Unsuccessful(
            "no logical client read from two owners"
        ))
    );
}

/// Every profile's ranges stay inside the cluster's bounds, and its names
/// are unique and listed.
#[test]
fn every_profile_fits_the_cluster_bounds() {
    for shape in &PROFILES {
        assert!(1 <= shape.owners.0 && shape.owners.0 <= shape.owners.1);
        assert!(shape.keys.0 <= shape.keys.1, "{}", shape.name);
        assert!(
            shape.owners.1 <= shape.keys.1,
            "{}: raising the key count to the owner count stays in range",
            shape.name
        );
        assert!(
            shape.minima.healthy <= u64::from(shape.phases),
            "{}",
            shape.name
        );
        assert!(shape.owners.1 <= super::MAX_OWNERS && shape.keys.1 <= super::MAX_KEYS);
        assert!(!shape.sizes.is_empty() && shape.concurrency > 0 && shape.hot > 0);
        assert!(super::super::catalog::listed(shape.name), "{}", shape.name);
    }
    let names: std::collections::BTreeSet<_> = PROFILES.iter().map(|shape| shape.name).collect();
    assert_eq!(names.len(), PROFILES.len(), "names are unique");
}

/// Roots vary the drawn topology inside the profile's ranges.
#[test]
fn roots_vary_the_topology_inside_its_ranges() {
    let shape = shape("cluster-broad").unwrap();
    let topologies: std::collections::BTreeSet<(u8, u8)> = (1..=12)
        .map(|root| {
            let (_, topology, _) = drawn_at(shape, root);
            assert!((2..=4).contains(&topology.owners));
            assert!((topology.owners.max(3)..=6).contains(&topology.keys));
            assert!(topology.hot < topology.keys);
            (topology.owners, topology.keys)
        })
        .collect();
    assert!(topologies.len() > 1, "{topologies:?}");
}

/// A recorded cluster bundle replays in this process to its digest and
/// passing terminal.
#[test]
fn a_cluster_bundle_replays_to_its_digest() {
    let manifest = manifest("cluster-broad", 5);
    replays_to_its_digest(admit(&manifest).unwrap());
}

/// Records the run `admitted` names, requires its recording to replay in
/// this process to the recorded digest and a passing terminal, and
/// returns the loaded replay.
fn replays_to_its_digest(
    admitted: super::super::bundle::Admitted<'_>,
) -> crate::sim::trace::Loaded {
    let closed = traced(admitted, Vec::new());
    let mut again = Vec::new();
    assert!(matches!(
        replay_recording(&closed.sink, &mut again),
        Ok(Replayed::Reproduced)
    ));
    let loaded = load(&again, u64::MAX).unwrap();
    assert_eq!(loaded.digest, closed.digest);
    assert!(matches!(
        loaded.terminal,
        Terminal::Complete {
            outcome: Outcome::Pass,
            ..
        }
    ));
    loaded
}

/// The failure a control run's check recorded; `None` for a run whose
/// plant took no effect or met no check, which a search over roots passes
/// by.
fn checked(failure: Option<super::Failure>) -> Option<super::Failure> {
    failure.filter(|failure| {
        !matches!(
            failure,
            super::Failure::Unsuccessful(super::UNSEEN | super::NO_EFFECT)
        )
    })
}

/// Runs `shape` from `root` to its end and returns the whole run.
fn whole(shape: &'static Shape, root: u64) -> super::Ran {
    run_for(shape, root, u64::MAX, &mut ())
}

/// Two virtual years on one retained world: 731 daily fault phases, each
/// followed by a healed phase, the world resting idle between them. Every
/// minimum is met while the checker's carried history, the registry, the
/// outstanding GETs and the links' kept audit records stay bounded, the
/// audits pass and the run counts, and the 730 days of rest are reported
/// apart from the phase time. The 24 windows of 30 phases and the final
/// window of the last 11 all cut and pass, each in its last fault phase,
/// and a GET is outstanding at the final cut.
#[test]
fn two_virtual_years_stay_bounded_on_one_world() {
    let shape = shape("cluster-long").unwrap();
    let mut cuts = Cuts(Vec::new());
    let ran = run_for(shape, 1, u64::MAX, &mut cuts);
    assert_eq!(ran.failure, None, "{:?}", ran.reached);
    assert_eq!(ran.report.end, crate::sim::turn::End::Done);
    assert_eq!(ran.audit, super::Verdict::Pass);
    assert!(ran.judged().counts(), "{:?}", ran.judged());
    const YEARS: u64 = 2 * 365 * super::DAY_US;
    assert!(ran.report.skipped_us > YEARS, "{}", ran.report.skipped_us);
    assert_eq!(ran.rested_us, 730 * super::DAY_US);
    let active = ran.report.skipped_us - ran.rested_us;
    assert!(active > 0 && ran.rested_us > active, "{active}");
    assert!(super::short_of(&shape.minima, &ran.reached).is_none());
    assert_eq!(ran.reached.healthy, 731);
    assert_eq!(ran.windows, 25);
    let cut_at: Vec<(bool, u32)> = (1..=24)
        .map(|n| (true, 30 * n - 1))
        .chain([(true, 730)])
        .collect();
    assert_eq!(cuts.healed(), cut_at);
    assert!(cuts.final_outstanding() > 0, "{:?}", cuts.0.last());
    assert!(ran.report.turns.is_empty() && ran.report.turn_count > 4_096);
    assert!(ran.marks.carried < 400, "{:?}", ran.marks);
    assert!(ran.marks.registry < 128, "{:?}", ran.marks);
    assert!(
        ran.marks.outstanding <= 16 && ran.marks.kept < 64,
        "{:?}",
        ran.marks
    );
}

/// Asserts that `cut`, a run whose window cuts compact, judges as `whole`,
/// the same shape's run without compaction, from `root`: the same counts,
/// failure, audit verdict, judgment, windows and turns, and both runs end
/// `Done`.
fn agrees(cut: &super::Ran, whole: &super::Ran, root: u64) {
    assert_eq!(cut.reached, whole.reached, "root {root}");
    assert_eq!(cut.failure, whole.failure, "root {root}");
    assert_eq!(cut.audit, whole.audit, "root {root}");
    assert_eq!(cut.judged(), whole.judged(), "root {root}");
    assert_eq!(cut.windows, whole.windows, "root {root}");
    assert_eq!(
        cut.report.turn_count, whole.report.turn_count,
        "root {root}"
    );
    assert_eq!(cut.report.end, whole.report.end, "root {root}");
    assert_eq!(cut.report.end, crate::sim::turn::End::Done, "root {root}");
}

/// The number of keys in `ran`'s drawn topology.
fn keys(ran: &super::Ran) -> usize {
    usize::from(ran.topology.expect("a drawn topology").keys)
}

/// Window cuts that retire discharged history judge as the whole history
/// does: one shape with and without compaction reaches the same counts,
/// failure, audit verdict, terminal, windows and turns, while compaction
/// carries less.
#[test]
fn segmented_and_whole_history_checks_agree() {
    static SEGMENTED: Shape = Shape {
        name: "cluster-broad",
        phases: 40,
        window: 4,
        gap_us: super::DAY_US,
        minima: super::NO_MINIMA,
        ..PROFILES[0]
    };
    static WHOLE: Shape = Shape {
        compact: false,
        ..SEGMENTED
    };
    for root in [3, 7] {
        let (segmented, whole) = (whole(&SEGMENTED, root), whole(&WHOLE, root));
        agrees(&segmented, &whole, root);
        assert_eq!(
            segmented.windows,
            SEGMENTED.phases.div_ceil(SEGMENTED.window)
        );
        assert!(
            segmented.marks.carried < whole.marks.carried,
            "{:?} {:?}",
            segmented.marks,
            whole.marks
        );
    }
}

/// A phase count the window does not divide ends in a shorter final window
/// that cuts and passes as every full window does. Under each root the
/// ten-phase run with compaction judges as the run without it, its three
/// passing cuts land in fault phases 4, 8 and 10, a GET is outstanding at
/// the final cut, and its first two cuts match the eight-phase run's, so
/// that run ends where the final window begins. Each run retains one entry
/// per drawn key. At the end each key's floor and next version equal the
/// whole history's, its retired cut lies at or below its floor, and it
/// carries exactly the whole history's versions at or above that cut; some
/// key's cut lies past the eight-phase run's, so the final window retired
/// history.
#[test]
fn a_final_partial_window_retires_as_the_whole_history_judges() {
    static TAILED: Shape = Shape {
        name: "cluster-broad",
        phases: 10,
        window: 4,
        gap_us: super::DAY_US,
        minima: super::NO_MINIMA,
        ..PROFILES[0]
    };
    static UNTAILED: Shape = Shape {
        phases: TAILED.phases - TAILED.phases % TAILED.window,
        ..TAILED
    };
    static WHOLE: Shape = Shape {
        compact: false,
        ..TAILED
    };
    assert_ne!(TAILED.phases % TAILED.window, 0, "the run has a tail");
    for root in [3, 5, 7] {
        let mut cuts = Cuts(Vec::new());
        let tailed = run_for(&TAILED, root, u64::MAX, &mut cuts);
        let mut prefix = Cuts(Vec::new());
        let untailed = run_for(&UNTAILED, root, u64::MAX, &mut prefix);
        let whole = whole(&WHOLE, root);
        assert_eq!(tailed.failure, None, "root {root}");
        agrees(&tailed, &whole, root);
        assert_eq!(
            cuts.healed(),
            [(true, 3), (true, 7), (true, 9)],
            "root {root}"
        );
        let full = (TAILED.phases / TAILED.window) as usize;
        assert_eq!(prefix.0, cuts.0[..full], "root {root}");
        assert!(
            cuts.final_outstanding() > 0,
            "root {root}: {:?}",
            cuts.0.last()
        );
        for ran in [&tailed, &untailed, &whole] {
            assert_eq!(ran.retained.len(), keys(ran), "root {root}");
        }
        for (key, (cut, kept)) in tailed.retained.iter().zip(&whole.retained).enumerate() {
            assert_eq!(cut.floor, kept.floor, "root {root} key {key}");
            assert_eq!(cut.next, kept.next, "root {root} key {key}");
            assert!(cut.retired_below <= cut.floor, "root {root} key {key}");
            let above: std::collections::BTreeMap<_, _> = kept
                .uploads
                .range(cut.retired_below..)
                .map(|(&version, &upload)| (version, upload))
                .collect();
            assert_eq!(cut.uploads, above, "root {root} key {key}");
        }
        assert!(
            tailed
                .retained
                .iter()
                .zip(&untailed.retained)
                .any(|(cut, before)| cut.retired_below > before.retired_below),
            "root {root}: the final window retired history"
        );
    }
}

/// A key's version counter reaching its end after a window cut compacted
/// that key refuses the next upload and ends the run unsuccessful before
/// its last healthy phase completes. In the chosen run that key is the only
/// one whose counter ended, so the refusal is its own, and its retired cut
/// when the counter ended already lay past the counter's first version.
/// Its newest version is the counter's last, and every key's carried
/// versions lie at or above the first version, so no version wrapped.
#[test]
fn a_version_counter_end_after_a_window_cut_refuses_without_wrapping() {
    const FIRST: u32 = u32::MAX - 6;
    static ENDING: Shape = Shape {
        name: "cluster-version-end",
        phases: 4,
        window: 1,
        first_version: FIRST,
        minima: super::NO_MINIMA,
        ..PROFILES[0]
    };
    /// The one key of `ran` whose counter ended, when a window cut
    /// compacted it before the end.
    fn compacted_end(ran: &super::Ran) -> Option<&KeyState> {
        let mut ended = ran.retained.iter().filter(|key| key.next.is_none());
        let key = ended.next()?;
        let compacted = key.ended_retired.is_some_and(|retired| retired > FIRST);
        (compacted && ended.next().is_none()).then_some(key)
    }
    let refused = Some(super::Failure::Unsuccessful(
        "a key's version counter reached its end",
    ));
    let ran = (1..=8)
        .map(|root| whole(&ENDING, root))
        .find(|ran| ran.failure == refused && compacted_end(ran).is_some())
        .expect("a root whose counter ends on a key a window cut compacted");
    assert!(ran.reached.healthy < u64::from(ENDING.phases));
    let ended = compacted_end(&ran).expect("an ended counter");
    assert_eq!(
        ended.uploads.keys().next_back(),
        Some(&u32::MAX),
        "{ended:?}"
    );
    assert_eq!(ran.retained.len(), keys(&ran));
    for key in &ran.retained {
        assert!(
            key.uploads.keys().all(|&version| version >= FIRST),
            "{key:?}"
        );
    }
}

/// The window events a run's hook saw, in order: whether each window
/// passed through its closing action, and its [`super::window_words`].
/// Only a passing entry implies that its cut passed and compacted.
struct Cuts(Vec<(bool, [u32; 10])>);

impl Cuts {
    fn note(&mut self, events: &[crate::sim::trace::Event]) {
        self.0.extend(
            events
                .iter()
                .filter(|event| event.kind == super::WINDOW)
                .map(|event| {
                    (
                        event.payload[super::WINDOW_VERDICT] == 1,
                        super::window_words(&event.payload),
                    )
                }),
        );
    }

    /// Each window's verdict and the healed phases reached when it cut;
    /// a cut in fault phase `n` follows `n - 1` healed phases.
    fn healed(&self) -> Vec<(bool, u32)> {
        self.0
            .iter()
            .map(|&(passing, words)| (passing, words[9]))
            .collect()
    }

    /// The outstanding GETs the final window event counts.
    fn final_outstanding(&self) -> u32 {
        self.0.last().expect("a window cut").1[3]
    }
}

impl crate::sim::turn::Hook for Cuts {
    fn clock(&mut self, _: &[u8], _: u64, events: &[crate::sim::trace::Event]) {
        self.note(events);
    }
    fn turn(&mut self, _: &[u8], _: &crate::sim::turn::Turn, events: &[crate::sim::trace::Event]) {
        self.note(events);
    }
}

/// Runs the late control `shape` from `root` to its end and returns the
/// failure its check recorded, after asserting that the `plant_after`
/// cuts before the plant armed passed and so retired history.
fn late(shape: &'static Shape, root: u64) -> Option<super::Failure> {
    assert!(shape.compact && shape.plant_after >= 2, "{}", shape.name);
    let mut cuts = Cuts(Vec::new());
    let failure = checked(run_for(shape, root, u64::MAX, &mut cuts).failure)?;
    let passed = cuts.0.iter().take_while(|(passing, _)| *passing).count();
    assert!(
        passed >= shape.plant_after as usize,
        "{} root {root}: {:?}",
        shape.name,
        cuts.0
    );
    Some(failure)
}

/// Each control planted once two windows cut and retired history still
/// fails its check: a stale completion crossing a cut, a leaked upload's
/// held source slots, and a changed payload byte on a device. Every cut
/// before the plant armed passed, so each failure follows compaction.
#[test]
fn controls_planted_after_cuts_still_fail() {
    for (name, expected) in [
        (
            "cluster-late-stale",
            super::Failure::Violation(
                crate::oracle::Obligation::History,
                "a GET returned a version older than one collected or removed before it",
            ),
        ),
        (
            "cluster-late-leak",
            super::Failure::Unsuccessful("a healed owner kept the resources of finished work"),
        ),
    ] {
        let failed = (1..=6).find_map(|root| late(shape(name).unwrap(), root));
        assert_eq!(failed, Some(expected), "{name}");
    }
    let corrupt = (1..=6)
        .find_map(|root| late(shape("cluster-late-corrupt").unwrap(), root))
        .expect("the changed byte fails");
    let stale = late(shape("cluster-late-stale").unwrap(), 12);
    assert_eq!(
        stale,
        Some(super::Failure::Violation(
            crate::oracle::Obligation::History,
            "a GET returned a version older than one collected or removed before it",
        )),
        "at the pinned root the version the plant returns fails the freshness rule"
    );
    assert_eq!(
        corrupt,
        super::Failure::Violation(
            Obligation::Bytes,
            "a bound slot's record fails its header or chunk checks",
        )
    );
}

/// Each swarm control's plant fails a check in a member some root selects:
/// the leak fails the healed owner's resource check, the changed byte a
/// Bytes check, a stale read a History check, and a wrong owner or an
/// acknowledged invalidation that removed nothing a Bytes or History
/// check. A root whose plant took no effect is passed by.
#[test]
fn every_swarm_control_fails_a_check_in_a_drawn_member() {
    for (name, plant, _) in super::swarm::CONTROLS {
        let failed = (1..=24).find_map(|root| {
            let shape = super::swarm::planted(name, root).expect("a swarm control");
            assert_eq!((shape.name, shape.plant), (name, plant));
            checked(whole(shape, root).failure)
        });
        let caught = match (plant, &failed) {
            (Plant::Leak, Some(super::Failure::Unsuccessful(rule))) => {
                *rule == "a healed owner kept the resources of finished work"
            }
            (Plant::Corrupt, Some(super::Failure::Violation(found, _))) => {
                *found == Obligation::Bytes
            }
            (Plant::Misread, Some(super::Failure::Violation(found, rule))) => {
                *found == Obligation::Bytes
                    && *rule == "a GET returned bytes no upload of its key wrote"
            }
            (Plant::StaleRead | Plant::LateStale, Some(super::Failure::Violation(found, _))) => {
                *found == Obligation::History
            }
            (Plant::WrongOwner | Plant::Unremoved, Some(super::Failure::Violation(found, _))) => {
                matches!(found, Obligation::Bytes | Obligation::History)
            }
            _ => false,
        };
        assert!(caught, "{name}: {failed:?}");
    }
}

/// A leak plant armed before any window closes takes effect: its run
/// fails the healed owner's resource check.
#[test]
fn a_leak_planted_from_the_start_fails() {
    static EARLY: Shape = Shape {
        name: "cluster-late-leak",
        plant_after: 0,
        ..PROFILES[6]
    };
    assert_eq!(EARLY.plant, Plant::Leak);
    let failed = (1..=6).find_map(|root| checked(whole(&EARLY, root).failure));
    assert_eq!(
        failed,
        Some(super::Failure::Unsuccessful(
            "a healed owner kept the resources of finished work"
        ))
    );
}

/// The resource check judges a leaked request at the healed probe of the
/// owner that holds it. A turn limit that stops the leak control before
/// that probe, at whichever turn, leaves the run inconclusive with no
/// failure: no check was due, so the plant has not acted.
#[test]
fn a_leak_stopped_before_its_owners_healed_probe_is_inconclusive() {
    use crate::sim::turn::{End, Limit};
    static EARLY: Shape = Shape {
        name: "cluster-late-leak",
        plant_after: 0,
        ..PROFILES[6]
    };
    let kept = super::Failure::Unsuccessful(super::KEPT_RESOURCES);
    let (root, turns) = (1..=6)
        .find_map(|root| {
            let ran = whole(&EARLY, root);
            (ran.failure == Some(kept.clone())).then_some((root, ran.report.turn_count))
        })
        .expect("a root whose leak fails the resource check");
    for total in 1..turns {
        let stopped = run_for(&EARLY, root, total, &mut ());
        assert_eq!(
            (stopped.report.end, stopped.failure),
            (End::Inconclusive(Limit::Total), None),
            "a turn limit of {total}"
        );
    }
}

/// A GET returning a version a window cut retired is a stale read of
/// history: the checker no longer carries the upload, and its retired
/// frontier names the read a History violation where a missing upload
/// would otherwise fail as bytes no upload wrote.
#[test]
fn a_retired_version_reads_as_stale_history() {
    let mut checker = fresh();
    let versions: Vec<u32> = (0..4).map(|_| published(&mut checker, 0, 2000)).collect();
    checker.compact(&[]);
    assert_eq!(checker.keys[0].retired_below, versions[3]);
    assert!(!checker.keys[0].uploads.contains_key(&versions[2]));
    checker.decided(
        get(0, 0, versions[3]),
        Fetched::Complete,
        &content(0, versions[2], 0, 2000),
    );
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::History,
            "a GET returned a version older than one collected or removed before it"
        ))
    );
}

/// The last version a counter holds is used once, and the next upload
/// finds no version, leaving the uploads unchanged; invalidating that last
/// version cannot raise the floor past it and ends the run unsuccessful.
/// The key's retired cut is captured when the last version is invoked and
/// stays as captured when a later compaction raises the retired cut.
#[test]
fn the_version_counter_end_is_used_once_and_never_wraps() {
    let mut checker = fresh();
    checker.keys[0].next = Some(u32::MAX);
    assert_eq!(checker.keys[0].ended_retired, None);
    assert_eq!(published(&mut checker, 0, 2000), u32::MAX);
    assert_eq!(checker.keys[0].ended_retired, Some(0));
    assert_eq!(checker.first.get(), None);
    let uploads = checker.keys[0].uploads.clone();
    assert_eq!(checker.next_version(0), None);
    checker.invoked(0, 0, 2000);
    assert_eq!(checker.keys[0].uploads, uploads);
    checker.invalidated(0, u32::MAX, false);
    assert_eq!(checker.floor(0), u32::MAX);
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Unsuccessful(
            "an invalidation's floor passed the version counter's end"
        ))
    );
    checker.compact(&[]);
    assert_eq!(checker.keys[0].retired_below, u32::MAX);
    assert_eq!(checker.keys[0].ended_retired, Some(0));
}

/// A key's version counter at its end refuses the next upload and ends the
/// run unsuccessful before its last healthy phase completes; no version is
/// reused.
#[test]
fn a_version_counter_at_its_end_refuses_without_wrapping() {
    let shape = shape("cluster-version-end").unwrap();
    let ran = whole(shape, 7);
    assert!(ran.puts >= 1);
    assert!(ran.reached.healthy < u64::from(shape.phases));
    assert_eq!(
        ran.failure,
        Some(super::Failure::Unsuccessful(
            "a key's version counter reached its end"
        ))
    );
}

/// A run that its turn limit ends after the first healthy phase has rested
/// less than the first rest's gap: the rest is credited as the clock passes
/// through it, so the rested time never exceeds the clock's advance.
#[test]
fn rest_is_credited_as_virtual_time_passes() {
    let shape = shape("cluster-long").unwrap();
    let ran = run_for(shape, 7, 250, &mut ());
    assert_eq!(ran.reached.healthy, 1, "{:?}", ran.report.end);
    assert!(
        ran.rested_us < shape.gap_us,
        "rested {} of the first rest's {}",
        ran.rested_us,
        shape.gap_us
    );
    assert!(
        ran.rested_us <= ran.report.skipped_us,
        "rested {} of skipped {}",
        ran.rested_us,
        ran.report.skipped_us
    );
}

#[test]
fn a_refused_setup_draw_leaves_the_topology_unavailable() {
    let manifest = manifest("cluster-broad", 3);
    let admitted = admit(&manifest).unwrap();
    let chooser = admitted.fed(Vec::new());
    let (closed, end, _) = run_into(admitted, Vec::new(), chooser);
    assert!(
        matches!(
            end,
            crate::sim::turn::End::Defect(crate::sim::turn::Defect::Entropy(_))
        ),
        "{end:?}"
    );
    let loaded = load(&closed.sink, u64::MAX).unwrap();
    assert!(matches!(loaded.terminal, Terminal::Infrastructure(_)));
    let seen = observed(&loaded.events);
    assert_eq!(
        seen.stop,
        Some((3, 2)),
        "the stop event names the entropy defect"
    );
    assert_eq!(
        seen.composed, None,
        "the stop event names a drawn world only"
    );
    assert_eq!(
        seen.coverage, None,
        "the coverage event follows a drawn topology only"
    );
}

/// Each coverage name labels the count in its own position.
#[test]
fn coverage_names_follow_their_counts() {
    let reached = Reached {
        published: 1,
        hits: 2,
        misses: 3,
        refused: 4,
        invalidated: 5,
        cancelled: 6,
        cross: 7,
        reused: 8,
        healthy: 9,
        faults: 10,
    };
    let named: Vec<(&str, u64)> = Reached::NAMES.into_iter().zip(reached.counts()).collect();
    assert_eq!(
        named,
        [
            ("published", 1),
            ("hits", 2),
            ("misses", 3),
            ("refused", 4),
            ("invalidated", 5),
            ("cancelled", 6),
            ("cross", 7),
            ("reused", 8),
            ("healthy", 9),
            ("faults", 10)
        ]
    );
}

/// A complete GET of exactly one published upload passes, counts as a hit
/// and raises its key's floor, so a later GET of an older version fails.
#[test]
fn an_exact_read_raises_the_floor_of_later_reads() {
    let mut checker = fresh();
    let older = published(&mut checker, 1, 2000);
    let newer = checker.next_version(1).unwrap();
    checker.invoked(1, 1, 2000);
    let floor = checker.floor(1);
    checker.decided(
        get(0, 1, floor),
        Fetched::Complete,
        &content(1, newer, 1, 2000),
    );
    assert_eq!(checker.last, Some((1, 1, newer)));
    assert_eq!(checker.reached.hits, 1);
    assert_eq!(checker.first.get(), None);
    let floor = checker.floor(1);
    checker.decided(
        get(1, 1, floor),
        Fetched::Complete,
        &content(1, older, 1, 2000),
    );
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::History,
            "a GET returned a version older than one collected or removed before it"
        ))
    );
}

/// A read is evidence of publication even when the PUT's outcome was lost
/// as unknown, and that evidence must survive the cut that retires the
/// read upload.
#[test]
fn a_read_proves_its_key_published_past_the_cut_that_retires_it() {
    let mut checker = fresh();
    let version = checker.next_version(1).unwrap();
    checker.invoked(1, 1, 2000);
    assert!(!checker.keys[1].published);
    checker.decided(
        get(0, 1, 0),
        Fetched::Complete,
        &content(1, version, 1, 2000),
    );
    assert_eq!(checker.first.get(), None);
    assert!(checker.keys[1].published);
    assert_eq!((checker.reached.hits, checker.reached.published), (1, 0));
    checker.invalidated(1, version, false);
    checker.compact(&[]);
    assert!(checker.keys[1].uploads.is_empty());
    assert!(checker.keys[1].published);
}

/// Another key's bytes, a truncated object and an incomplete GET's spliced
/// prefix each fail the bytes check.
#[test]
fn the_checker_fails_foreign_truncated_and_spliced_bytes() {
    let foreign = "a GET returned bytes no upload of its key wrote";
    let spliced = "an incomplete GET exposed bytes no one upload of its key wrote";
    type Bytes = fn(u32, u32) -> Vec<u8>;
    let cases: [(Fetched, Bytes, &str); 3] = [
        (Fetched::Complete, |_, _| content(0, 0, 0, 2000), foreign),
        (
            Fetched::Complete,
            |version, _| content(1, version, 1, 2000)[..1500].to_vec(),
            foreign,
        ),
        (
            Fetched::Incomplete(Status::OwnerUnavailable),
            |first, second| {
                let mut bytes = content(1, first, 1, 2000)[..1000].to_vec();
                bytes.extend(&content(1, second, 1, 2000)[1000..1500]);
                bytes
            },
            spliced,
        ),
    ];
    for (outcome, bytes, rule) in cases {
        let mut checker = fresh();
        let first = published(&mut checker, 1, 2000);
        let second = published(&mut checker, 1, 2000);
        checker.decided(get(0, 1, 0), outcome, &bytes(first, second));
        assert_eq!(
            checker.first.get(),
            Some(super::Failure::Violation(Obligation::Bytes, rule)),
            "{outcome:?}"
        );
        assert_eq!(checker.last, None);
    }
    let mut checker = fresh();
    let version = published(&mut checker, 1, 2000);
    checker.decided(
        get(0, 1, 0),
        Fetched::Incomplete(Status::OwnerUnavailable),
        &content(1, version, 1, 2000)[..1500],
    );
    assert_eq!(checker.first.get(), None, "a prefix of one version passes");
    assert_eq!(checker.reached.refused, 1);
}

/// An incomplete GET handed bytes out, so an empty buffer under that
/// outcome fails the bytes check, and the exposed prefix must belong to an
/// upload the GET could have read complete: one sent to the owner the GET
/// went to and the contract names, at or above the GET's floor.
#[test]
fn an_incomplete_read_is_held_to_the_bytes_a_complete_read_could_return() {
    let incomplete = Fetched::Incomplete(Status::OwnerUnavailable);
    let mut checker = fresh();
    published(&mut checker, 1, 2000);
    checker.decided(get(0, 1, 0), incomplete, &[]);
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::Bytes,
            "an incomplete GET exposed no bytes"
        ))
    );
    let excluded = "an incomplete GET exposed bytes of a version or owner it could not read";
    let mut checker = fresh();
    let older = published(&mut checker, 1, 2000);
    let newer = published(&mut checker, 1, 2000);
    checker.decided(
        get(0, 1, newer),
        incomplete,
        &content(1, older, 1, 2000)[..1500],
    );
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(Obligation::History, excluded)),
        "a prefix of a version below the floor"
    );
    let mut checker = fresh();
    checker.invoked(1, 0, 2000);
    checker.published(1, 0, false);
    let wrong = Judged {
        owner: 0,
        ..get(0, 1, 0)
    };
    checker.decided(wrong, incomplete, &content(1, 0, 0, 2000)[..1500]);
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(Obligation::History, excluded)),
        "a prefix from the owner the contract does not name"
    );
    let mut checker = fresh();
    let older = published(&mut checker, 1, 2000);
    let newer = published(&mut checker, 1, 2000);
    let short = &content(1, older, 1, 2000)[..3];
    assert_eq!(short, &content(1, newer, 1, 2000)[..3]);
    checker.decided(get(0, 1, newer), incomplete, short);
    assert_eq!(
        checker.first.get(),
        None,
        "a prefix shared with a readable version passes"
    );
    assert_eq!(checker.reached.refused, 1);
}

/// An incomplete GET whose prefix only one readable upload starts, as every
/// prefix holding the object header does, is a read of that upload: the
/// owner served its bytes, so a later no-effect report for it contradicts
/// the read, and a later GET of an older version is stale. A prefix two
/// readable uploads share reads neither.
#[test]
fn an_incomplete_read_that_names_a_version_records_the_read() {
    let incomplete = Fetched::Incomplete(Status::OwnerUnavailable);
    let mut checker = fresh();
    let version = checker.next_version(1).unwrap();
    checker.invoked(1, 1, 2000);
    checker.decided(
        get(1, 1, 0),
        incomplete,
        &content(1, version, 1, 2000)[..1500],
    );
    assert_eq!(checker.first.get(), None);
    assert_eq!(checker.floor(1), version);
    checker.unpublished(1, version, None);
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::History,
            "an owner reported a version a GET read as not published"
        ))
    );
    let mut checker = fresh();
    let older = published(&mut checker, 1, 2000);
    let newer = checker.next_version(1).unwrap();
    checker.invoked(1, 1, 2000);
    checker.decided(
        get(1, 1, older),
        incomplete,
        &content(1, newer, 1, 2000)[..1500],
    );
    assert_eq!(
        checker.floor(1),
        newer,
        "the incomplete read raised the floor"
    );
    checker.decided(
        get(0, 1, checker.floor(1)),
        Fetched::Complete,
        &content(1, older, 1, 2000),
    );
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::History,
            "a GET returned a version older than one collected or removed before it"
        ))
    );
    let mut checker = fresh();
    let version = checker.next_version(1).unwrap();
    checker.invoked(1, 1, 2000);
    checker.decided(get(1, 1, 0), incomplete, &content(1, version, 1, 2000)[..3]);
    assert!(
        checker.keys[1].uploads[&0].published,
        "three bytes of the only readable upload read it"
    );
    checker.unpublished(1, version, None);
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::History,
            "an owner reported a version a GET read as not published"
        ))
    );
    let mut checker = fresh();
    let first = checker.next_version(1).unwrap();
    checker.invoked(1, 1, 2000);
    checker.invoked(1, 1, 2000);
    checker.decided(get(1, 1, 0), incomplete, &content(1, first, 1, 2000)[..3]);
    assert_eq!(checker.first.get(), None);
    assert!(
        checker.keys[1]
            .uploads
            .values()
            .all(|upload| !upload.published),
        "three bytes two readable uploads share read neither"
    );
    assert_eq!(checker.floor(1), 0);
    let mut checker = fresh();
    let older = published(&mut checker, 1, 2000);
    let newer = checker.next_version(1).unwrap();
    checker.invoked(1, 1, 2000);
    checker.decided(
        get(1, 1, newer),
        incomplete,
        &content(1, older, 1, 2000)[..3],
    );
    assert!(
        checker.keys[1].uploads[&newer].published,
        "the readable upload, not the one below the floor, is read"
    );
    checker.unpublished(1, newer, None);
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::History,
            "an owner reported a version a GET read as not published"
        ))
    );
}

/// `Failed`, `Pressure` and `Missing` GETs hand out no bytes: with none they
/// pass and count as refused or missed, and with bytes they fail the bytes
/// check and count nothing.
#[test]
fn a_read_that_exposed_bytes_without_completing_fails_the_bytes_check() {
    let outcomes = [
        Fetched::Failed(Status::TimedOut),
        Fetched::Pressure(Status::ReadOpsPressure),
        Fetched::Missing,
    ];
    for outcome in outcomes {
        let mut checker = fresh();
        let version = published(&mut checker, 1, 2000);
        checker.decided(get(0, 1, 0), outcome, &[]);
        assert_eq!(checker.first.get(), None, "{outcome:?}");
        assert_eq!(
            (checker.reached.misses, checker.reached.refused),
            if outcome == Fetched::Missing {
                (1, 0)
            } else {
                (0, 1)
            },
            "{outcome:?}"
        );
        checker.decided(get(0, 1, 0), outcome, &content(1, version, 1, 2000)[..1000]);
        assert_eq!(
            checker.first.get(),
            Some(super::Failure::Violation(
                Obligation::Bytes,
                "a GET exposed bytes under an outcome that hands none out"
            )),
            "{outcome:?}"
        );
        assert_eq!(
            checker.reached.misses + checker.reached.refused,
            1,
            "{outcome:?}"
        );
        assert_eq!(checker.last, None);
    }
}

/// A read of an upload its owner reported as not published records a
/// history violation regardless of the order of the GET and the owner's
/// outcome report, since one client collects the outcome while the other
/// client's GET may already have read the bytes. A GET that reads a version
/// removed by an invalidation before the GET was issued records a history
/// violation regardless of whether an outcome reported that version's
/// publication.
#[test]
fn the_checker_fails_unpublished_and_invalidated_versions() {
    let mut checker = fresh();
    let version = checker.next_version(1).unwrap();
    checker.invoked(1, 1, 2000);
    checker.unpublished(1, version, None);
    checker.decided(
        get(0, 1, 0),
        Fetched::Complete,
        &content(1, version, 1, 2000),
    );
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::History,
            "a GET returned a version its owner reported as not published"
        ))
    );
    let mut checker = fresh();
    let version = checker.next_version(1).unwrap();
    checker.invoked(1, 1, 2000);
    checker.decided(
        get(1, 1, 0),
        Fetched::Complete,
        &content(1, version, 1, 2000),
    );
    assert_eq!(checker.last, Some((1, 1, version)));
    assert_eq!(checker.first.get(), None, "the read precedes any report");
    checker.unpublished(1, version, None);
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::History,
            "an owner reported a version a GET read as not published"
        ))
    );
    for bind_older in [false, true] {
        let mut checker = fresh();
        let older = published(&mut checker, 1, 2000);
        let version = checker.next_version(1).unwrap();
        checker.invoked(1, 1, 2000);
        checker.unpublished(1, version, bind_older.then_some(older));
        assert_eq!(checker.first.get(), None, "bind_older {bind_older}");
    }
    let mut checker = fresh();
    let version = checker.next_version(1).unwrap();
    checker.invoked(1, 1, 2000);
    checker.unpublished(1, version, Some(version));
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::History,
            "an owner reported a version it binds as not published"
        ))
    );
    for reported in [false, true] {
        let mut checker = fresh();
        let version = checker.next_version(1).unwrap();
        checker.invoked(1, 1, 2000);
        if reported {
            checker.published(1, version, false);
        }
        checker.invalidated(1, version, false);
        let floor = checker.floor(1);
        assert_eq!(floor, version + 1, "reported {reported}");
        checker.decided(
            get(0, 1, floor),
            Fetched::Complete,
            &content(1, version, 1, 2000),
        );
        assert_eq!(
            checker.first.get(),
            Some(super::Failure::Violation(
                Obligation::History,
                "a GET returned a version older than one collected or removed before it"
            )),
            "reported {reported}"
        );
    }
    let mut checker = fresh();
    let version = published(&mut checker, 1, 2000);
    checker.invalidated(1, version, true);
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::History,
            "an owner reported a removal while its index binds the key"
        ))
    );
    assert_eq!(checker.floor(1), version + 1);
    let mut checker = fresh();
    checker.unremoved(false);
    assert_eq!(checker.first.get(), None, "an absent key removes nothing");
    checker.unremoved(true);
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::History,
            "an owner reported no removal while its index bound the key"
        ))
    );
}

/// Over roots 1 to 24, no run of `cluster-wrong-owner`,
/// `cluster-stale-read` or a swarm control ends under [`UNSEEN`](super::UNSEEN),
/// and each of those nine controls fails a check on some root.
#[test]
fn a_plant_that_takes_effect_fails_a_check() {
    let swarm = super::swarm::CONTROLS.map(|(name, _, _)| name);
    let fixed = PROFILES
        .iter()
        .filter(|shape| shape.plant != Plant::None && !swarm.contains(&shape.name))
        .filter(|shape| !matches!(shape.plant, Plant::Depth1 | Plant::Depth2 | Plant::Depth3))
        .filter(|shape| shape.phases <= 3);
    let runs = fixed
        .map(|shape| (shape.name, (1..=24).map(|root| (shape, root)).collect()))
        .chain(swarm.map(|name| {
            let planted = |root| (super::swarm::planted(name, root).unwrap(), root);
            (name, (1..=24).map(planted).collect::<Vec<_>>())
        }));
    let mut controls = 0;
    for (name, runs) in runs {
        let failures: Vec<_> = runs
            .into_iter()
            .filter_map(|(shape, root)| run_root(shape, root).failure)
            .collect();
        assert!(
            !failures.contains(&super::Failure::Unsuccessful(super::UNSEEN)),
            "{name}: a plant took effect and met no check"
        );
        assert!(
            failures
                .iter()
                .any(|failure| checked(Some(failure.clone())).is_some()),
            "{name}: no root fails a check"
        );
        controls += 1;
    }
    assert_eq!(controls, 9);
}

/// A control's run that recorded no failure ends unsuccessful under the
/// rule its plant's effect selects: one that finished or stopped at a
/// limit after its plant acted met no check, one that finished before its
/// plant acted took no effect, and one a limit stopped before its plant
/// acted, or a defect or a hook ended, names neither.
#[test]
fn a_control_with_no_failure_names_whether_its_plant_acted() {
    use crate::sim::turn::{Defect, End, Limit};
    let unseen = Some(super::Failure::Unsuccessful(super::UNSEEN));
    let idle = Some(super::Failure::Unsuccessful(super::NO_EFFECT));
    let limit = End::Inconclusive(Limit::NoProgress);
    assert_eq!(super::unmet(End::Done, true), unseen);
    assert_eq!(super::unmet(limit, true), unseen);
    assert_eq!(super::unmet(End::Done, false), idle);
    assert_eq!(super::unmet(limit, false), None);
    for acted in [false, true] {
        assert_eq!(super::unmet(End::Halted, acted), None);
        assert_eq!(
            super::unmet(End::Defect(Defect::Due { now: 1, due: 1 }), acted),
            None
        );
    }
}

/// A control whose run issues no generated operation finishes with no
/// failure and ends unsuccessful under [`NO_EFFECT`](super::NO_EFFECT),
/// whether it plants a wrong owner or starts the version counter at its
/// end: its run never counts as a pass.
#[test]
fn a_control_whose_plant_takes_no_effect_is_unsuccessful() {
    static NO_WORK: Shape = Shape {
        phase_ops: 0,
        ..PROFILES[2]
    };
    static NO_SECOND_VERSION: Shape = Shape {
        phase_ops: 0,
        ..PROFILES[8]
    };
    assert_eq!(NO_WORK.plant, Plant::WrongOwner);
    assert_eq!(NO_SECOND_VERSION.first_version, u32::MAX);
    assert_eq!(NO_SECOND_VERSION.plant, Plant::None);
    for shape in [&NO_WORK, &NO_SECOND_VERSION] {
        let (_, failure, _, done) = ran(shape, 1);
        assert!(done, "{}", shape.name);
        assert_eq!(
            failure,
            Some(super::Failure::Unsuccessful(super::NO_EFFECT)),
            "{}",
            shape.name
        );
    }
}

/// A cluster world of `shape` over `cells`, at root 1's topology, judged
/// by a fresh checker, with every phase done.
fn bare_world(
    shape: &'static Shape,
    cells: Vec<Box<dyn super::Cell + 'static>>,
) -> super::Cluster<'static> {
    let (_, topology, _) = drawn_at(shape, 1);
    world(shape, topology, cells, fresh(), super::Phase::Done)
}

/// A cell with audit verdict `.0` that holds the upload `.1` names and
/// reports the entries in `.2` through `outstanding`. With `.3` set, each
/// conservation judgment records the free-run violation.
struct Audited(Verdict, Option<(u8, u32)>, Vec<(u8, u32)>, bool);

impl super::Cell for Audited {
    fn runnable(&self, _: u64, _: &mut Vec<crate::sim::choice::Candidate>) {}
    fn next_due(&self, _: u64) -> Option<u64> {
        None
    }
    fn advance(&mut self, _: u64, _: &Checker) {}
    fn check(&mut self, _: &Checker) {}
    fn conserve(&mut self, checker: &Checker) -> bool {
        if self.3 {
            checker.first.record(super::Failure::Violation(
                Obligation::Resources,
                crate::net::observe::FREE_RUNS,
            ));
        }
        self.3
    }
    fn apply(
        &mut self,
        _: &crate::sim::choice::Candidate,
        _: u64,
        _: &mut Checker,
        _: Plant,
    ) -> u64 {
        unimplemented!()
    }
    fn get(&mut self, _: usize, _: u8, _: (u32, u32), _: bool, _: u64) -> u64 {
        unimplemented!()
    }
    fn put(&mut self, _: u8, _: u32, _: Vec<u8>, _: bool, _: u64) -> u64 {
        unimplemented!()
    }
    fn invalidate(&mut self, _: u8, _: u64, _: &mut Checker, _: Plant) -> u64 {
        unimplemented!()
    }
    fn cancellable(&self, _: usize, _: u8) -> bool {
        false
    }
    fn cancel(&mut self, _: usize, _: u8) -> u64 {
        unimplemented!()
    }
    fn set_faults(
        &mut self,
        _: crate::net::link::Faults,
        _: super::DeviceFaults,
        _: crate::net::link::TxRelease,
    ) {
    }
    fn returning(&self) -> bool {
        false
    }
    fn active(&self, _: usize) -> bool {
        false
    }
    fn pending(&self, _: usize) -> usize {
        0
    }
    fn uploading(&self) -> bool {
        false
    }
    fn idle(&self) -> bool {
        true
    }
    fn retired(&mut self) -> bool {
        true
    }
    fn reclaimed(&self) -> bool {
        true
    }
    fn take_probe(&mut self) -> Option<crate::net::upload::UploadOutcome> {
        None
    }
    fn take_collected(&mut self) -> super::Collected {
        super::Collected::Absent
    }
    fn audits(&mut self, _: &mut Vec<crate::sim::trace::Event>) {}
    fn absorb(&mut self) {}
    fn verdict(&self) -> Verdict {
        self.0
    }
    fn take_draw_errors(&mut self) {}
    fn defect(&self) -> Option<crate::sim::turn::Defect> {
        None
    }
    fn set_clocks(&self, _: u64) {}
    fn start(&self) -> u64 {
        0
    }
    fn injected(&self) -> u64 {
        0
    }
    fn applied(&self) -> super::Applied {
        super::Applied::default()
    }
    fn rest(&mut self, _: u64) {}
    fn outstanding(&self, out: &mut Vec<(u8, u32)>) {
        out.extend_from_slice(&self.2);
    }
    fn uploading_version(&self) -> Option<(u8, u32)> {
        self.1
    }
    fn compact(&mut self, _: &Checker) -> usize {
        0
    }
    fn kept(&self) -> usize {
        0
    }
    fn peaks(&self) -> (usize, usize) {
        (0, 0)
    }
    fn leak(&mut self) {}
    fn corrupt(&mut self, _: u8) -> bool {
        false
    }
}

/// A hook counting the turns that collect a failed upload outcome.
struct FailedUploads(u64);

impl crate::sim::turn::Hook for FailedUploads {
    fn turn(&mut self, _: &[u8], turn: &crate::sim::turn::Turn, _: &[crate::sim::trace::Event]) {
        let event = turn.event.0;
        if event[0] == crate::sim::choice::Domain::Workload as u8
            && event[1] == super::OUTCOME
            && turn.outcome == super::super::upload_code(UploadOutcome::Failed(Status::Contended))
        {
            self.0 += 1;
        }
    }
}

/// A hook counting the accepted probe steps.
struct Probes(u64);

impl crate::sim::turn::Hook for Probes {
    fn turn(&mut self, _: &[u8], turn: &crate::sim::turn::Turn, _: &[crate::sim::trace::Event]) {
        let event = turn.event.0;
        if event[0] == crate::sim::choice::Domain::Workload as u8
            && event[1] == super::PROBE
            && turn.outcome != super::REFUSED
        {
            self.0 += 1;
        }
    }
}

/// `ServeCore::cancel` settles a fresh identity.
/// The owner then drops or refuses the GET that arrives behind that CANCEL.
/// At root 2021 an owner that admits that GET makes a probe retry.
/// The retry raises the accepted probe steps above `first_attempts`.
#[test]
fn a_get_behind_its_cancel_leaves_the_probes_their_first_attempts() {
    let shape = shape("cluster-broad").unwrap();
    let root = 2021;
    let mut probes = Probes(0);
    let ran = run_for(shape, root, 200_000, &mut probes);
    assert_eq!(ran.failure, None, "root {root}: {:?}", ran.reached);
    assert_eq!(ran.report.end, crate::sim::turn::End::Done, "root {root}");
    assert_eq!(ran.reached.healthy, 3, "root {root}");
    assert!(ran.puts <= shape.upload_attempts(), "root {root}");
    let steps = probes.0;
    let topology = ran.topology.expect("the root drew a topology");
    let first_attempts = 2 * u64::from(topology.owners) * u64::from(shape.phases);
    assert_eq!(steps, first_attempts, "root {root}");
}

/// A cut passes, and so compacts, only when every partition audit passes
/// and no check failed: a failed audit or a recorded checker failure
/// writes verdict byte 0 and retires nothing. The window's words hold its
/// index, the carried uploads and the publications in their places.
#[test]
fn a_cut_fails_once_a_partition_audit_failed() {
    let record = crate::net::audit::Record {
        class: Class::Production,
        reason: crate::net::audit::Reason::Unattributed,
        source: crate::net::audit::Source::Device(0),
    };
    for (verdict, failed_check, passes) in [
        (Verdict::Pass, false, true),
        (Verdict::Fail(record), false, false),
        (Verdict::Pass, true, false),
    ] {
        let shape = shape("cluster-broad").unwrap();
        assert!(shape.compact);
        let mut world = bare_world(
            shape,
            vec![Box::new(Audited(verdict, None, Vec::new(), false))],
        );
        published(&mut world.checker, 1, 2000);
        published(&mut world.checker, 1, 2000);
        if failed_check {
            world.checker.violation("a planted checker failure");
        }
        assert_eq!(world.checker.carried_now(), 2);
        world.cut();
        let event = world.window_events.last().unwrap();
        assert_eq!(
            event.payload[super::WINDOW_VERDICT] == 1,
            passes,
            "{verdict:?} {failed_check}"
        );
        let carried: u32 = if passes { 1 } else { 2 };
        assert_eq!(
            world.checker.carried_now(),
            carried as usize,
            "{verdict:?} {failed_check}"
        );
        assert_eq!(
            super::window_words(&event.payload),
            [0, carried, 0, 0, 0, 2, 0, 0, 0, 0],
            "{verdict:?} {failed_check}"
        );
    }
}

/// A compaction keeps every upload at or above the floor of a GET still
/// outstanding, though the key's floor passed it, across later cuts while
/// newer versions publish: that GET's read of the older version passes,
/// and the version retires once the GET has left the frontier.
#[test]
fn an_outstanding_get_keeps_the_versions_it_may_read() {
    let mut checker = fresh();
    let mut versions: Vec<u32> = (0..4).map(|_| published(&mut checker, 0, 2000)).collect();
    checker.compact(&[(0, versions[1])]);
    assert_eq!(checker.keys[0].retired_below, versions[1]);
    assert!(!checker.keys[0].uploads.contains_key(&versions[0]));
    assert!(checker.keys[0].uploads.contains_key(&versions[1]));
    versions.push(published(&mut checker, 0, 2000));
    checker.compact(&[(0, versions[1])]);
    assert_eq!(checker.keys[0].retired_below, versions[1]);
    assert!(checker.keys[0].uploads.contains_key(&versions[1]));
    checker.decided(
        get(0, 0, versions[1]),
        Fetched::Complete,
        &content(0, versions[1], 0, 2000),
    );
    assert_eq!(checker.first.get(), None);
    checker.compact(&[]);
    assert_eq!(checker.keys[0].retired_below, versions[4]);
    assert!(!checker.keys[0].uploads.contains_key(&versions[1]));
}

/// A passing cut puts each cell's outstanding GET on the compaction
/// frontier: the versions below the GET's floor retire, the versions at
/// or above it stay carried though the key's floor passed them, and the
/// window counts the GET in its outstanding word.
#[test]
fn a_cut_keeps_what_an_outstanding_get_may_read() {
    let shape = shape("cluster-broad").unwrap();
    let mut world = bare_world(
        shape,
        vec![Box::new(Audited(Verdict::Pass, None, vec![(1, 1)], false))],
    );
    let versions: Vec<u32> = (0..3)
        .map(|_| published(&mut world.checker, 1, 2000))
        .collect();
    assert_eq!(versions, [0, 1, 2]);
    assert_eq!(world.checker.floor(1), 2);
    world.cut();
    assert_eq!(world.checker.keys[1].retired_below, 1);
    assert!(!world.checker.keys[1].uploads.contains_key(&0));
    assert_eq!(world.checker.carried_now(), 2);
    let event = world.window_events.last().unwrap();
    assert_eq!(event.payload[super::WINDOW_VERDICT], 1);
    assert_eq!(
        super::window_words(&event.payload),
        [0, 2, 0, 1, 0, 3, 0, 0, 0, 0]
    );
}

/// A check failure, a failing audit or an inconclusive audit that the
/// window's closing action records after a passing cut makes the window
/// event it emits non-passing, so a committed window never names a pass
/// over a record that holds a failure; a closing action that records none
/// keeps the pass.
#[test]
fn a_failure_in_the_closing_action_fails_its_window() {
    let record = crate::net::audit::Record {
        class: Class::Production,
        reason: crate::net::audit::Reason::Unattributed,
        source: crate::net::audit::Source::Device(0),
    };
    let shape = shape("cluster-broad").unwrap();
    for (name, audit, failed_check, conserving, verdict) in [
        ("none", Verdict::Pass, false, false, 1),
        ("check", Verdict::Pass, true, false, 0),
        ("audit", Verdict::Fail(record), false, false, 0),
        (
            "inconclusive",
            Verdict::Inconclusive(crate::net::rules::Bound::Records),
            false,
            false,
            0,
        ),
        ("conservation", Verdict::Pass, false, true, 0),
    ] {
        let mut world = bare_world(
            shape,
            vec![Box::new(Audited(Verdict::Pass, None, Vec::new(), false))],
        );
        world.cut();
        assert_eq!(world.window_events[0].payload[super::WINDOW_VERDICT], 1);
        if failed_check {
            world.checker.violation("a failure in the closing action");
        }
        world.cells[0] = Box::new(Audited(audit, None, Vec::new(), conserving));
        assert_eq!(world.checker.first.get().is_some(), failed_check, "{name}");
        let mut out = Vec::new();
        crate::sim::turn::World::emit(&mut world, &mut out);
        if conserving {
            assert!(
                out.iter()
                    .any(|event| event.kind == super::super::bundle::FAILURE),
                "{name}: the emission carries the rule's failure"
            );
        }
        let windows: Vec<_> = out
            .iter()
            .filter(|event| event.kind == super::WINDOW)
            .collect();
        assert_eq!(windows.len(), 1, "{name}");
        assert_eq!(windows[0].payload[super::WINDOW_VERDICT], verdict, "{name}");
    }
}

/// A healthy phase whose probe never reads its fresh version ends the run
/// unsuccessful after `PROBES` attempts. Each earlier retry's wait deadline
/// becomes the world's next due time, to which the turn controller advances
/// the clock.
#[test]
fn a_probe_that_never_succeeds_ends_the_run_unsuccessful() {
    let shape = shape("cluster-broad").unwrap();
    let (_, topology, _) = drawn_at(shape, 1);
    let mut world = world(shape, topology, Vec::new(), fresh(), super::Phase::Done);
    let now = 5_000;
    for attempt in 0..super::PROBES {
        assert_eq!(world.checker.first.get(), None, "attempt {attempt}");
        world.retry(0, attempt, now);
        if world.phase != super::Phase::Done {
            assert!(world.runnable(now).is_empty(), "attempt {attempt}");
            assert_eq!(world.next_due(now), Some(now + super::RETRY_WAIT_US));
        }
    }
    assert_eq!(world.phase, super::Phase::Done);
    assert_eq!(
        world.checker.first.get(),
        Some(super::Failure::Unsuccessful(
            "healthy work made no progress after the faults healed"
        ))
    );
}

/// A leak caught after two window cuts names its unsuccessful check in its
/// bundle, so a reader tells the leak's detection apart from a plant that
/// took no effect. A shorter rule ends at its recorded length, not at the
/// payload's zero padding. A check raised during the run reaches the bundle
/// as one `OBSERVED` event: settlement records only a failure the run did
/// not emit. A passing bundle names none, and so does one
/// whose only `OBSERVED` event is an inconclusive oracle verdict, or an
/// unsuccessful check whose rule is unprintable or longer than the payload.
#[test]
fn a_detected_leak_names_its_unsuccessful_check_in_its_bundle() {
    const LEAK: &str = "a healed owner kept the resources of finished work";
    let root = (1..=6)
        .find(|&root| {
            whole(shape("cluster-late-leak").unwrap(), root).failure
                == Some(super::Failure::Unsuccessful(LEAK))
        })
        .expect("the leak fails a root");
    let cut = crate::sim::trace::PAYLOAD - 3;
    for (profile, root, rule) in [
        ("cluster-late-leak", root, &LEAK[..cut]),
        (
            "cluster-version-end",
            7,
            "a key's version counter reached its end",
        ),
    ] {
        let closed = traced(admit(&manifest(profile, root)).unwrap(), Vec::new());
        let loaded = load(&closed.sink, u64::MAX).unwrap();
        assert_eq!(
            unsuccessful_rule(&loaded).as_deref(),
            Some(rule),
            "{profile}"
        );
        let observed = loaded
            .events
            .iter()
            .filter(|event| event.kind == super::super::bundle::OBSERVED)
            .count();
        assert_eq!(observed, 1, "{profile}");
    }
    let passing_bytes = traced(admit(&manifest("cluster-broad", 5)).unwrap(), Vec::new()).sink;
    assert_eq!(
        unsuccessful_rule(&load(&passing_bytes, u64::MAX).unwrap()),
        None
    );
    // An inconclusive oracle verdict is no unsuccessful check, and an
    // unsuccessful check whose rule holds a byte outside printable ASCII,
    // or whose recorded length passes the payload, names no rule.
    let mut inconclusive = [0; crate::sim::trace::PAYLOAD];
    inconclusive[..3].copy_from_slice(&[2, 0, 12]);
    inconclusive[3..15].copy_from_slice(b"inconclusive");
    let mut unprintable = [0; crate::sim::trace::PAYLOAD];
    unprintable[..5].copy_from_slice(&[3, 0, 2, b'a', b'\n']);
    let mut overlong = [0; crate::sim::trace::PAYLOAD];
    overlong[..3].copy_from_slice(&[3, 0, 42]);
    for payload in [inconclusive, unprintable, overlong] {
        let mut loaded = load(&passing_bytes, u64::MAX).unwrap();
        loaded.events.push(crate::sim::trace::Event {
            kind: super::super::bundle::OBSERVED,
            payload,
        });
        assert_eq!(unsuccessful_rule(&loaded), None, "{payload:?}");
    }
}

#[test]
fn a_run_short_of_its_minima_names_the_minimum_in_its_bundle() {
    use super::super::bundle::{OBSERVED, STOP};
    const RULE: &str = "fewer exact reads than the profile requires";
    let closed = traced(admit(&manifest("cluster-broad", 11)).unwrap(), Vec::new());
    let loaded = load(&closed.sink, u64::MAX).unwrap();
    assert!(
        matches!(
            loaded.terminal,
            Terminal::Complete {
                outcome: Outcome::Unsuccessful,
                ..
            }
        ),
        "{:?}",
        loaded.terminal
    );
    let cut = crate::sim::trace::PAYLOAD - 3;
    assert_eq!(unsuccessful_rule(&loaded).as_deref(), Some(&RULE[..cut]));
    let at = |kind| loaded.events.iter().position(|event| event.kind == kind);
    let observed = loaded
        .events
        .iter()
        .filter(|event| event.kind == OBSERVED)
        .count();
    assert_eq!(observed, 1);
    assert!(at(super::COVERAGE) < at(OBSERVED), "{:?}", loaded.events);
    assert!(at(OBSERVED) < at(STOP), "{:?}", loaded.events);
}

/// A GET that misses counts as a miss, reads nothing and raises no
/// failure, so a run whose every GET misses reaches no exact read and no
/// cross-owner read. A profile whose minima require exact reads then ends
/// unsuccessful and never counts as a pass.
#[test]
fn an_always_miss_run_falls_short_of_the_hits_minimum() {
    let mut checker = fresh();
    published(&mut checker, 0, 2000);
    let floor = checker.floor(0);
    checker.decided(get(0, 0, floor), Fetched::Missing, &[]);
    assert_eq!((checker.reached.hits, checker.reached.misses), (0, 1));
    assert_eq!((checker.last, checker.first.get()), (None, None));
    for name in ["cluster-broad", "cluster-pressure", "cluster-long"] {
        let minima = shape(name).unwrap().minima;
        assert!(minima.hits > 0, "{name}");
        let reached = Reached {
            published: minima.published,
            hits: 0,
            misses: minima.hits,
            cross: 0,
            reused: minima.reused,
            healthy: minima.healthy,
            faults: minima.faults,
            ..Reached::default()
        };
        assert_eq!(
            super::short_of(&minima, &reached),
            Some("fewer exact reads than the profile requires"),
            "{name}"
        );
    }
}

/// A run whose fault phases issue no operation ends unsuccessful under the
/// broad minima: the healthy phases' probes publish and read at every
/// owner, and those reach no minimum.
#[test]
fn probes_alone_reach_no_minimum() {
    static PROBES_ONLY: Shape = Shape {
        name: "cluster-broad",
        owners: (2, 2),
        phase_ops: 0,
        faults: super::link_faults(0, 0, 0, 0),
        device: super::SOUND,
        sustained: false,
        minima: super::Minima {
            faults: 0,
            ..PROFILES[0].minima
        },
        ..PROFILES[0]
    };
    let (reached, failure, topology, done) = ran(&PROBES_ONLY, 7);
    assert_eq!(topology.owners, 2);
    assert!(done);
    assert_eq!(reached.healthy, 3);
    assert_eq!((reached.published, reached.hits, reached.cross), (0, 0, 0));
    assert_eq!(
        failure,
        Some(super::Failure::Unsuccessful(
            "fewer publications than the profile requires"
        ))
    );
}

/// Client 0 at one partition can hold a retiring upload's device-held
/// source slots beside the next upload's, so the `source_bytes` hold
/// covers the source slot pool the scene gives it.
#[test]
fn the_source_bytes_hold_covers_the_source_slot_pool() {
    for shape in &PROFILES {
        let held = super::super::bundle::held_by(shape.name).unwrap();
        let (_, source_bytes) = held
            .iter()
            .find(|(key, _)| *key == "source_bytes")
            .copied()
            .unwrap();
        let pool = u64::from(crate::net::put_tests::SOURCES)
            * u64::from(crate::net::geometry::FRAGMENT_LEN);
        assert!(
            source_bytes >= pool,
            "{}: {source_bytes} < {pool}",
            shape.name
        );
        assert!(source_bytes >= u64::from(shape.largest()), "{}", shape.name);
    }
}

/// A four-owner draw of the broad profile, the top of its owner range,
/// finishes every phase with no failure on one world.
#[test]
fn a_four_owner_broad_run_heals_every_phase() {
    let shape = shape("cluster-broad").unwrap();
    let ran = run_root(shape, 14);
    assert_eq!(ran.topology.map(|topology| topology.owners), Some(4));
    assert_eq!(ran.failure, None, "{:?}", ran.reached);
    assert_eq!(ran.report.end, crate::sim::turn::End::Done);
    assert_eq!(ran.reached.healthy, u64::from(shape.phases));
    assert!(ran.puts <= shape.upload_attempts());
}

/// The stale-read control's violation reaches the bundle as a violating
/// terminal whose violation record names the freshness rule, and a
/// wrong-owner run reaches it as an unsuccessful terminal; neither counts.
#[test]
fn control_bundles_record_their_violation_or_unsuccessful_terminal() {
    let traced_at = |name: &str, root: u64| {
        let manifest = raised(manifest(name, root));
        let closed = traced(admit(&manifest).unwrap(), Vec::new());
        load(&closed.sink, manifest.capacity().records()).unwrap()
    };
    let outcome = |loaded: &crate::sim::trace::Loaded| match loaded.terminal {
        Terminal::Complete { outcome, .. } => Some(outcome),
        Terminal::Infrastructure(_) => None,
    };
    let violated = (1..=8)
        .map(|root| traced_at("cluster-stale-read", root))
        .find(|loaded| outcome(loaded) == Some(Outcome::Violation))
        .expect("a stale-read root violates");
    assert!(!violated.terminal.counts());
    assert_eq!(
        violated.violation,
        Some(super::super::bundle::failure_code(
            &super::Failure::Violation(
                Obligation::History,
                "a GET returned a version older than one collected or removed before it"
            )
        )),
        "the bundle names the freshness rule"
    );
    let unsuccessful = (1..=8)
        .map(|root| traced_at("cluster-wrong-owner", root))
        .find(|loaded| outcome(loaded) == Some(Outcome::Unsuccessful))
        .expect("a wrong-owner root misses its plant");
    assert!(!unsuccessful.terminal.counts());
}

/// Admission accepts a cluster profile only with its base scenario: an
/// encoded edit of its plan is refused.
#[test]
fn a_cluster_manifest_with_an_edited_scenario_is_refused() {
    let (profile, plan, _) = super::named("cluster-broad", 3).unwrap();
    let edit = super::super::replay::Edit::of(&profile, &plan);
    let base = manifest("cluster-broad", 3);
    assert!(admit(&base).is_ok());
    assert_eq!(
        admit(&base.with_scenario(edit.encode())).err(),
        Some(super::super::bundle::Refusal::Scenario)
    );
}

/// Each minimum fails a run that falls one short of it, under its own
/// rule, exactly as calibration and the summary read it, and keeps that
/// rule when every later minimum is short too, so the rules apply in the
/// order published, hits, cross, faults, healthy, reused; a run that meets
/// every minimum exactly passes.
#[test]
fn each_minimum_fails_a_run_one_short_of_it() {
    let minima = super::Minima {
        published: 2,
        hits: 2,
        cross: 2,
        faults: 2,
        healthy: 2,
        reused: 2,
    };
    let met = Reached {
        published: 2,
        hits: 2,
        cross: 2,
        faults: 2,
        healthy: 2,
        reused: 2,
        ..Reached::default()
    };
    assert_eq!(super::short_of(&minima, &met), None);
    type Lower = fn(&mut Reached);
    let cases: [(Lower, &str); 6] = [
        (
            |reached| reached.published -= 1,
            "fewer publications than the profile requires",
        ),
        (
            |reached| reached.hits -= 1,
            "fewer exact reads than the profile requires",
        ),
        (
            |reached| reached.cross -= 1,
            "no logical client read from two owners",
        ),
        (
            |reached| reached.faults -= 1,
            "fewer delivered faults than the profile requires",
        ),
        (
            |reached| reached.healthy -= 1,
            "fewer healed phases than the profile requires",
        ),
        (
            |reached| reached.reused -= 1,
            "fewer reused slots than the profile requires",
        ),
    ];
    for (at, (lower, rule)) in cases.iter().enumerate() {
        let mut short = met;
        lower(&mut short);
        assert_eq!(super::short_of(&minima, &short), Some(*rule));
        for (later, _) in &cases[at + 1..] {
            later(&mut short);
        }
        assert_eq!(
            super::short_of(&minima, &short),
            Some(*rule),
            "minimum {at}"
        );
    }
}

/// A complete read of bytes that name an owner the contract does not route
/// the key to, and one of bytes from the routed owner that reached the GET
/// through another owner, each fail the routing check.
#[test]
fn a_read_served_off_the_routing_contract_fails_the_routing_check() {
    let rule = "a key was served from an owner its routing contract does not name";
    let mut checker = fresh();
    let version = checker.next_version(1).unwrap();
    checker.invoked(1, 0, 2000);
    checker.published(1, version, false);
    let off_route = Judged {
        owner: 0,
        ..get(0, 1, 0)
    };
    checker.decided(off_route, Fetched::Complete, &content(1, version, 0, 2000));
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(Obligation::History, rule)),
        "bytes written at an owner the contract does not name"
    );
    let mut checker = fresh();
    let version = published(&mut checker, 1, 2000);
    checker.decided(off_route, Fetched::Complete, &content(1, version, 1, 2000));
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(Obligation::History, rule)),
        "the routed owner's bytes returned by another owner"
    );
}

/// An invalidation that removed a version its owner reported as not
/// published contradicts the report, whichever comes first.
#[test]
fn a_removed_version_reported_as_not_published_fails_the_history_check() {
    let rule = "an owner reported a version an invalidation removed as not published";
    for report_first in [false, true] {
        let mut checker = fresh();
        let version = checker.next_version(1).unwrap();
        checker.invoked(1, 1, 2000);
        if report_first {
            checker.unpublished(1, version, None);
            assert_eq!(checker.first.get(), None);
        }
        checker.invalidated(1, version, false);
        if !report_first {
            assert_eq!(checker.first.get(), None);
            checker.unpublished(1, version, None);
        }
        assert_eq!(
            checker.first.get(),
            Some(super::Failure::Violation(Obligation::History, rule)),
            "report first {report_first}"
        );
    }
}

/// A passing window cut keeps an upload whose outcome is still to be
/// reported, though an invalidation raised the floor past it, and retires
/// the older upload below it: the held upload's later report as not
/// published still contradicts the removal, and a cut without it on the
/// frontier retires it too.
#[test]
fn a_cut_keeps_a_held_upload_checkable() {
    let rule = "an owner reported a version an invalidation removed as not published";
    let shape = shape("cluster-broad").unwrap();
    for held in [true, false] {
        let uploading = held.then_some((1, 1));
        let mut world = bare_world(
            shape,
            vec![Box::new(Audited(
                Verdict::Pass,
                uploading,
                Vec::new(),
                false,
            ))],
        );
        assert_eq!(published(&mut world.checker, 1, 2000), 0);
        let version = world.checker.next_version(1).unwrap();
        assert_eq!(version, 1);
        world.checker.invoked(1, 1, 2000);
        world.checker.invalidated(1, version, false);
        assert_eq!(world.checker.floor(1), version + 1);
        world.cut();
        let event = world.window_events.last().unwrap();
        assert_eq!(event.payload[super::WINDOW_VERDICT], 1, "held {held}");
        assert!(
            !world.checker.keys[1].uploads.contains_key(&0),
            "held {held}"
        );
        assert_eq!(
            world.checker.keys[1].retired_below,
            if held { 1 } else { 2 },
            "held {held}"
        );
        assert_eq!(
            world.checker.keys[1].uploads.contains_key(&version),
            held,
            "held {held}"
        );
        if held {
            world.checker.unpublished(1, version, None);
            assert_eq!(
                world.checker.first.get(),
                Some(super::Failure::Violation(Obligation::History, rule))
            );
        }
    }
}

/// An incomplete GET whose bytes are a prefix of an object of a version a
/// window cut retired fails as a read the GET could not make, as the whole
/// history fails it; the same prefix with a changed payload byte fails the
/// bytes check.
#[test]
fn an_incomplete_read_of_a_retired_version_fails_as_the_whole_history_does() {
    let mut checker = fresh();
    let versions: Vec<u32> = (0..3).map(|_| published(&mut checker, 1, 2000)).collect();
    checker.compact(&[]);
    assert!(!checker.keys[1].uploads.contains_key(&versions[0]));
    checker.decided(
        get(1, 1, versions[2]),
        Fetched::Incomplete(Status::OwnerUnavailable),
        &content(1, versions[0], 1, 2000)[..100],
    );
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::History,
            "an incomplete GET exposed bytes of a version or owner it could not read"
        ))
    );
    let mut checker = fresh();
    let versions: Vec<u32> = (0..3).map(|_| published(&mut checker, 1, 2000)).collect();
    checker.compact(&[]);
    let mut changed = content(1, versions[0], 1, 2000)[..100].to_vec();
    changed[50] ^= 1;
    checker.decided(
        get(1, 1, versions[2]),
        Fetched::Incomplete(Status::OwnerUnavailable),
        &changed,
    );
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::Bytes,
            "an incomplete GET exposed bytes no one upload of its key wrote"
        ))
    );
}

/// An incomplete GET whose bytes start only an upload its owner reported
/// as not published fails the history check, as a complete read of it
/// does.
#[test]
fn an_incomplete_read_of_a_version_reported_as_not_published_fails_the_history_check() {
    let mut checker = fresh();
    let version = checker.next_version(1).unwrap();
    checker.invoked(1, 1, 2000);
    checker.unpublished(1, version, None);
    checker.decided(
        get(0, 1, 0),
        Fetched::Incomplete(Status::OwnerUnavailable),
        &content(1, version, 1, 2000)[..1500],
    );
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::History,
            "a GET returned a version its owner reported as not published"
        ))
    );
}

/// The stale-read plant swaps a complete read of a recorded upload for the
/// newest older publication of its key, and leaves bytes naming a key or
/// version the checker never recorded, or a recorded version at another
/// length, as they are.
#[test]
fn the_stale_read_plant_swaps_only_recorded_versions() {
    let mut checker = fresh();
    let older = published(&mut checker, 1, 2000);
    let newer = published(&mut checker, 1, 3000);
    assert_eq!(
        checker.older_publication(&content(1, newer, 1, 3000)),
        Some(content(1, older, 1, 2000))
    );
    assert_eq!(checker.older_publication(&content(1, older, 1, 2000)), None);
    assert_eq!(checker.older_publication(&content(9, 1, 1, 2000)), None);
    assert_eq!(checker.older_publication(&content(1, 7, 1, 2000)), None);
    assert_eq!(
        checker.older_publication(&content(1, 2, 1, 2000)),
        None,
        "the first version no upload took"
    );
    assert_eq!(
        checker.older_publication(&content(1, newer, 1, 2000)),
        None,
        "a recorded version at another length"
    );
    assert_eq!(
        checker.older_publication(&content(1, newer, 0, 3000)),
        None,
        "a recorded version as sent to another owner"
    );
    let failed = checker.next_version(1).unwrap();
    checker.invoked(1, 1, 2000);
    checker.unpublished(1, failed, None);
    assert_eq!(
        checker.older_publication(&content(1, failed, 1, 2000)),
        None,
        "a version its owner reported as not published"
    );
}

/// A cell whose probe passes but whose finished work keeps its resources,
/// while its links hold a device reference or after they hold none.
struct Held {
    retired: bool,
    reclaimed: bool,
    returning: bool,
    /// What [`super::Cell::late`] reports.
    late: bool,
}

impl super::Cell for Held {
    fn late(&self) -> bool {
        self.late
    }
    fn runnable(&self, _: u64, _: &mut Vec<crate::sim::choice::Candidate>) {}
    fn next_due(&self, _: u64) -> Option<u64> {
        None
    }
    fn advance(&mut self, _: u64, _: &Checker) {}
    fn check(&mut self, _: &Checker) {}
    fn apply(
        &mut self,
        _: &crate::sim::choice::Candidate,
        _: u64,
        _: &mut Checker,
        _: Plant,
    ) -> u64 {
        super::REFUSED
    }
    fn get(&mut self, _: usize, _: u8, _: (u32, u32), _: bool, _: u64) -> u64 {
        super::REFUSED
    }
    fn put(&mut self, _: u8, _: u32, _: Vec<u8>, _: bool, _: u64) -> u64 {
        super::REFUSED
    }
    fn invalidate(&mut self, _: u8, _: u64, _: &mut Checker, _: Plant) -> u64 {
        super::REFUSED
    }
    fn cancellable(&self, _: usize, _: u8) -> bool {
        false
    }
    fn cancel(&mut self, _: usize, _: u8) -> u64 {
        super::REFUSED
    }
    fn set_faults(
        &mut self,
        _: crate::net::link::Faults,
        _: super::DeviceFaults,
        _: crate::net::link::TxRelease,
    ) {
    }
    fn returning(&self) -> bool {
        self.returning
    }
    fn active(&self, _: usize) -> bool {
        true
    }
    fn pending(&self, _: usize) -> usize {
        0
    }
    fn uploading(&self) -> bool {
        false
    }
    fn idle(&self) -> bool {
        true
    }
    fn retired(&mut self) -> bool {
        self.retired
    }
    fn reclaimed(&self) -> bool {
        self.reclaimed
    }
    fn take_probe(&mut self) -> Option<UploadOutcome> {
        None
    }
    fn take_collected(&mut self) -> super::Collected {
        super::Collected::Absent
    }
    fn audits(&mut self, _: &mut Vec<crate::sim::trace::Event>) {}
    fn absorb(&mut self) {}
    fn verdict(&self) -> crate::net::audit::Verdict {
        crate::net::audit::Verdict::Pass
    }
    fn take_draw_errors(&mut self) {}
    fn defect(&self) -> Option<crate::sim::turn::Defect> {
        None
    }
    fn set_clocks(&self, _: u64) {}
    fn start(&self) -> u64 {
        0
    }
    fn injected(&self) -> u64 {
        0
    }
    fn applied(&self) -> super::Applied {
        super::Applied::default()
    }
    fn rest(&mut self, _: u64) {}
    fn outstanding(&self, _: &mut Vec<(u8, u32)>) {}
    fn uploading_version(&self) -> Option<(u8, u32)> {
        None
    }
    fn compact(&mut self, _: &Checker) -> usize {
        0
    }
    fn kept(&self) -> usize {
        0
    }
    fn peaks(&self) -> (usize, usize) {
        (0, 0)
    }
    fn leak(&mut self) {}
    fn corrupt(&mut self, _: u8) -> bool {
        false
    }
}

/// A healed owner whose probe read its fresh version but that keeps a
/// decided request unretired, or a source slot or upload held, once its
/// links hold no device reference, ends the run unsuccessful.
#[test]
fn a_healed_owner_that_keeps_finished_work_ends_the_run_unsuccessful() {
    for (retired, reclaimed) in [(false, true), (true, false)] {
        let mut world = held_world(Held {
            retired,
            reclaimed,
            returning: false,
            late: false,
        });
        world.settle(0);
        assert_eq!(world.phase, super::Phase::Done);
        assert_eq!(
            world.checker.first.get(),
            Some(super::Failure::Unsuccessful(
                "a healed owner kept the resources of finished work"
            )),
            "retired {retired}, reclaimed {reclaimed}"
        );
    }
}

/// A client keeps an upload's source slot while a link holds a device
/// reference to it. A healed owner in that state stays at its probe read
/// with no failure, so the resource judgment runs once the links hold no
/// reference.
#[test]
fn a_healed_owner_waits_for_its_links_before_the_resource_judgment() {
    for (retired, reclaimed) in [(false, true), (true, false)] {
        let mut world = held_world(Held {
            retired,
            reclaimed,
            returning: true,
            late: false,
        });
        let reading = world.phase;
        world.settle(0);
        assert_eq!(world.phase, reading);
        assert_eq!(
            world.checker.first.get(),
            None,
            "retired {retired}, reclaimed {reclaimed}"
        );
    }
}

/// The leak plant acts at the healed probe that judges the resources of
/// the owner holding the leaked request, whether or not that judgment
/// fails: a probe that finds nothing kept still counts the plant as
/// acted, so a resource check that misses the leak ends the run under
/// [`UNSEEN`](super::UNSEEN). A probe that waits for its links, and one
/// of an owner that holds no leaked request, leave the plant idle.
#[test]
fn a_leak_acts_at_the_resource_judgment_of_its_owner() {
    for (leaked, kept, returning, acted) in [
        (Some(0), false, false, true),
        (Some(0), true, false, true),
        (Some(0), true, true, false),
        (Some(1), false, false, false),
        (None, false, false, false),
    ] {
        let mut world = held_world(Held {
            retired: !kept,
            reclaimed: true,
            returning,
            late: false,
        });
        world.checker.leaked = leaked;
        world.settle(0);
        assert_eq!(
            world.checker.acted, acted,
            "leaked {leaked:?}, kept {kept}, returning {returning}"
        );
    }
}

/// The control that starts the version counter at its end takes effect
/// when the counter refuses an upload. A probe upload of a key whose
/// counter ended is refused, ends the run under the counter's rule and
/// counts the plant as acted, so a refusal that recorded no failure would
/// end the run under [`UNSEEN`](super::UNSEEN).
#[test]
fn a_refused_upload_at_the_counters_end_counts_the_plant_as_acted() {
    let mut world = held_world(Held {
        retired: true,
        reclaimed: true,
        returning: false,
        late: false,
    });
    world.phase = super::Phase::Probing {
        owner: 0,
        attempt: 0,
        probe: super::Probe::Start,
    };
    world.checker.keys[0].next = None;
    assert_eq!(world.probe_step(0), super::REFUSED);
    assert_eq!(
        world.checker.first.get(),
        Some(super::Failure::Unsuccessful(
            "a key's version counter reached its end"
        ))
    );
    assert_eq!(world.phase, super::Phase::Done);
    assert!(world.checker.acted, "the counter refused an upload");
}

/// A one-owner world at its probe read of version 0, which the checker
/// recorded as read, over `cell`.
fn held_world(cell: Held) -> super::Cluster<'static> {
    let topology = Topology {
        owners: 1,
        keys: 1,
        hot: 0,
    };
    let probing = super::Phase::Probing {
        owner: 0,
        attempt: 0,
        probe: super::Probe::Reading(0),
    };
    let cells: Vec<Box<dyn super::Cell>> = vec![Box::new(cell)];
    let mut world = world(
        shape("cluster-broad").unwrap(),
        topology,
        cells,
        checker(1, 1),
        probing,
    );
    world.checker.last = Some((0, 0, 0));
    world
}

/// An owner whose index binds a version it reported as not published, one
/// an invalidation removed, or one its own acknowledged INVALIDATE covers,
/// fails its next stopped boundary, with no GET of the key.
#[test]
fn a_binding_of_a_version_reported_as_not_published_fails_the_boundary_check() {
    let (draws, _, setups) = drawn_at(shape("cluster-broad").unwrap(), 1);
    let mut bound = false;
    super::nest(
        0,
        (&setups[..1], &draws, false),
        (4096, crate::net::link::UNBOUNDED),
        Vec::new(),
        &mut |mut cells| {
            let cell = &mut cells[0];
            let mut checker = checker(1, 1);
            let mut now = cell.start();
            let mut put = false;
            for step in 0..20_000 {
                if put && !cell.uploading() {
                    break;
                }
                if !put && cell.active(0) {
                    let object = content(0, 0, 0, 2000);
                    assert_eq!(cell.put(0, 0, object, false, now), super::APPLIED);
                    checker.invoked(0, 0, 2000);
                    put = true;
                }
                cell.set_clocks(now);
                let mut out = Vec::new();
                cell.runnable(now, &mut out);
                out.sort();
                if out.is_empty() {
                    now = cell.next_due(now).expect("a due time");
                    cell.advance(now, &checker);
                } else {
                    cell.apply(&out[step % out.len()], now, &mut checker, Plant::None);
                    cell.absorb();
                }
            }
            assert!(
                checker.keys[0].uploads[&0].published,
                "the upload published"
            );
            cell.advance(now, &checker);
            assert_eq!(checker.first.get(), None);
            let rules = [
                "an owner binds a version it reported as not published",
                "an owner binds a version an invalidation removed",
            ];
            for (removed, rule) in [false, true].into_iter().zip(rules) {
                let mut judged = self::checker(1, 1);
                judged.keys = checker.keys.clone();
                let upload = judged.keys[0].uploads.get_mut(&0).unwrap();
                upload.no_effect = !removed;
                upload.removed = removed;
                cell.advance(now, &judged);
                assert_eq!(
                    judged.first.get(),
                    Some(super::Failure::Violation(Obligation::History, rule))
                );
            }
            // The bound version covered by its owner's acknowledged
            // INVALIDATE fails the boundary; another owner's leaves it.
            let mut judged = self::checker(1, 1);
            judged.keys = checker.keys.clone();
            judged.acknowledged(0, 0, 1);
            cell.advance(now, &judged);
            assert_eq!(judged.first.get(), None, "another owner's acknowledgment");
            judged.acknowledged(0, 0, 0);
            cell.advance(now, &judged);
            assert_eq!(
                judged.first.get(),
                Some(super::Failure::Violation(
                    Obligation::History,
                    "an owner binds a version an acknowledged invalidation covered"
                ))
            );
            bound = true;
        },
    );
    assert!(bound);
}

/// An invalidation that removed bytes naming a version no upload of the
/// key took fails the bytes check, and leaves the floor and the
/// invalidation count as they were.
#[test]
fn a_removal_of_an_unrecorded_version_fails_the_bytes_check() {
    let mut checker = fresh();
    published(&mut checker, 1, 2000);
    let floor = checker.floor(1);
    checker.invalidated(1, 5, false);
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::Bytes,
            "an invalidation removed bytes no upload of its key wrote"
        ))
    );
    assert_eq!(checker.floor(1), floor);
    assert_eq!(checker.reached.invalidated, 0);
}

/// `recorded` names an upload's version for exactly the object [`content`]
/// builds for its key, version, owner and length, and `None` for a
/// mismatch in any of the four.
#[test]
fn recorded_bytes_name_their_upload_exactly() {
    let mut checker = fresh();
    let version = published(&mut checker, 1, 2000);
    let owner = 1;
    assert_eq!(
        checker.recorded(1, &content(1, version, owner, 2000)),
        Some(version)
    );
    assert_eq!(checker.recorded(0, &content(1, version, owner, 2000)), None);
    assert_eq!(
        checker.recorded(1, &content(1, version, owner + 1, 2000)),
        None
    );
    assert_eq!(checker.recorded(1, &content(1, version, owner, 1999)), None);
    assert_eq!(
        checker.recorded(1, &content(1, version + 1, owner, 2000)),
        None
    );
}

/// A removal report agrees with the index only when it names the exact
/// allocation, slot and incarnation, that the index bound when the call
/// began; a removal while the index bound the key to none passes, as one
/// of another key sharing its fingerprint.
#[test]
fn a_removal_must_name_the_allocation_the_index_bound() {
    let bound = AllocationId::new(SlotIndex(3), 7);
    let checker = fresh();
    checker.removal(Some(bound), bound);
    assert_eq!(checker.first.get(), None);
    checker.removal(None, bound);
    assert_eq!(checker.first.get(), None, "no binding");
    for (before, case) in [
        (Some(AllocationId::new(SlotIndex(4), 7)), "another slot"),
        (
            Some(AllocationId::new(SlotIndex(3), 8)),
            "another incarnation",
        ),
    ] {
        let checker = fresh();
        checker.removal(before, bound);
        assert_eq!(
            checker.first.get(),
            Some(super::Failure::Violation(
                Obligation::History,
                "an owner reported removing an allocation its index did not bind"
            )),
            "{case}"
        );
    }
}

/// An index may bind neither an upload its owner reported as not published,
/// nor one an invalidation removed, nor one older than a publication of the
/// key at the same owner; an older upload of the key at another owner, and
/// the newest publication, pass.
#[test]
fn the_binding_rule_refuses_unpublished_removed_and_superseded_versions() {
    let mut checker = fresh();
    let older = published(&mut checker, 1, 2000);
    let newer = published(&mut checker, 1, 2000);
    assert_eq!(checker.binding_rule(1, newer, 1), None);
    assert_eq!(
        checker.binding_rule(1, older, 1),
        Some("an owner binds a version older than one it published")
    );
    assert_eq!(
        checker.binding_rule(1, older, 0),
        None,
        "another owner's upload"
    );
    assert_eq!(
        checker.binding_rule(1, 9, 1),
        None,
        "a version no upload took"
    );
    let failed = checker.next_version(1).unwrap();
    checker.invoked(1, 1, 2000);
    checker.unpublished(1, failed, None);
    assert_eq!(
        checker.binding_rule(1, failed, 1),
        Some("an owner binds a version it reported as not published")
    );
    checker.keys[1].uploads.get_mut(&newer).unwrap().removed = true;
    assert_eq!(
        checker.binding_rule(1, newer, 1),
        Some("an owner binds a version an invalidation removed")
    );
    checker.keys[1].uploads.get_mut(&newer).unwrap().covered = true;
    assert_eq!(
        checker.binding_rule(1, newer, 1),
        Some("an owner binds a version an invalidation removed"),
        "a removed version an acknowledgment also covers"
    );
}

/// An INVALIDATE an owner acknowledged covers each upload of its key to
/// that owner up to the version it names, published or still running, so
/// the owner's index may bind none of them. An upload above that version,
/// taken before or after the acknowledgment, stays bindable, and so does
/// every upload after another owner's acknowledgment. A covered upload
/// that was running may end as not published with no failure.
#[test]
fn the_binding_rule_refuses_versions_an_acknowledged_invalidate_covers() {
    let covered = Some("an owner binds a version an acknowledged invalidation covered");
    let mut checker = fresh();
    let first = published(&mut checker, 1, 2000);
    let running = checker.next_version(1).unwrap();
    checker.invoked(1, 1, 2000);
    let above = checker.next_version(1).unwrap();
    checker.invoked(1, 1, 2000);
    assert_eq!(checker.binding_rule(1, running, 1), None);
    checker.acknowledged(1, running, 0);
    assert_eq!(
        checker.binding_rule(1, running, 1),
        None,
        "another owner's acknowledgment"
    );
    checker.acknowledged(1, running, 1);
    for version in [first, running] {
        assert_eq!(
            checker.binding_rule(1, version, 1),
            covered,
            "version {version}"
        );
    }
    assert_eq!(
        checker.binding_rule(1, above, 1),
        None,
        "a version above the one the INVALIDATE named"
    );
    let later = published(&mut checker, 1, 2000);
    assert_eq!(checker.binding_rule(1, later, 1), None);
    checker.unpublished(1, running, None);
    assert_eq!(checker.first.get(), None);
}

/// A publication collected while the index binds its own version passes
/// and names the binding as the upload's; one collected while the index
/// binds another version or bytes no upload of the key wrote fails, and an
/// index that binds none passes.
#[test]
fn a_collected_publication_must_be_the_version_its_index_binds() {
    let rule = "an owner reported a publication while its index binds another version";
    let mut checker = fresh();
    let older = published(&mut checker, 1, 2000);
    let version = published(&mut checker, 1, 2000);
    assert!(checker.collected(1, version, 1, Some(Some(version))));
    assert!(!checker.collected(1, version, 1, None));
    assert_eq!(checker.first.get(), None);
    for bound in [Some(older), None] {
        let mut checker = fresh();
        published(&mut checker, 1, 2000);
        let version = published(&mut checker, 1, 2000);
        assert!(!checker.collected(1, version, 1, Some(bound)));
        assert_eq!(
            checker.first.get(),
            Some(super::Failure::Violation(Obligation::History, rule)),
            "bound {bound:?}"
        );
    }
}

/// An invalidation that removes a version an earlier invalidation already
/// removed shows the index bound it again, a violation.
#[test]
fn a_second_removal_of_one_version_fails_the_history_check() {
    let mut checker = fresh();
    let version = published(&mut checker, 1, 2000);
    checker.invalidated(1, version, false);
    assert_eq!(checker.first.get(), None);
    checker.invalidated(1, version, false);
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::History,
            "an owner binds a version an invalidation removed"
        ))
    );
}

/// An incomplete GET at the key's routed owner whose prefix names only an
/// upload sent to another owner fails the readability check.
#[test]
fn a_routed_incomplete_read_of_another_owners_upload_fails_the_history_check() {
    let mut checker = fresh();
    let version = checker.next_version(1).unwrap();
    checker.invoked(1, 0, 2000);
    checker.published(1, version, false);
    checker.decided(
        get(0, 1, 0),
        Fetched::Incomplete(Status::OwnerUnavailable),
        &content(1, version, 0, 2000)[..1500],
    );
    assert_eq!(
        checker.first.get(),
        Some(super::Failure::Violation(
            Obligation::History,
            "an incomplete GET exposed bytes of a version or owner it could not read"
        ))
    );
}

/// Every workload code a cluster candidate carries names its operation
/// in the narrative's cluster world, beside the candidate's cell, client,
/// argument, key and slot.
#[test]
fn every_cluster_candidate_names_its_operation() {
    use super::{
        CANCEL, CLIENT_POLL, COVER, GET, INVALIDATE, OUTCOME, OWNER_POLL, PREPARE, PROBE, PUT,
        READ, SERVICE, SUPPLY, candidate,
    };
    use crate::net::world_tests::narrate::{World, tests::turn_line};
    for (code, name) in [
        (OWNER_POLL, "owner-poll"),
        (CLIENT_POLL, "client-poll"),
        (SERVICE, "service"),
        (READ, "read"),
        (PREPARE, "prepare"),
        (SUPPLY, "supply"),
        (OUTCOME, "outcome"),
        (PROBE, "probe"),
        (COVER, "cover"),
        (GET, "get"),
        (PUT, "put"),
        (INVALIDATE, "invalidate"),
        (CANCEL, "cancel"),
    ] {
        let line = turn_line(World::Cluster, candidate(code, 1, 1, 0x0102, 3, 2).0, 1);
        let fields = format!("domain=Workload code={name} cell=1 client=1 arg=258 key=3 slot=2 ");
        assert!(line.contains(&fields), "{line}");
    }
}

/// Each turn of a recorded cluster run records the result its action
/// collected from a client: a READ turn's decided GET at that turn's
/// client and owner, an OUTCOME turn's upload at client 0 and that owner,
/// the very upload result its outcome word names, a status exactly for a
/// result that carries one, and nothing at any other turn, so no turn
/// carries an earlier turn's result. The misses and refused GETs the
/// coverage event counts equal the missing and refused results the turns
/// record, and its hits and publications are among the complete reads and
/// published uploads. Roots 1 and 2 record GETs refused under pressure or
/// failed and failed uploads, so those results occur in the cluster world.
#[test]
fn cluster_turns_record_the_results_their_reads_and_outcomes_collected() {
    let seen = cluster_observations("cluster-broad", 5);
    assert!(seen[1] > 0 && seen[6] > 0, "{seen:?}");
    let refused = cluster_observations("cluster-broad", 1);
    assert!(refused[3] > 0 && refused[4] > 0, "{refused:?}");
    let failed = cluster_observations("cluster-broad", 2);
    assert!(failed[7] > 0, "{failed:?}");
}

/// The count of each observation variant the turns of `profile`'s run at
/// `root` record, after checking each turn's observation against its
/// candidate and outcome word and the coverage event against the counts.
fn cluster_observations(profile: &str, root: u64) -> [u64; 11] {
    use crate::sim::choice::Domain;
    use crate::sim::trace::Tag;
    let closed = traced(admit(&manifest(profile, root)).unwrap(), Vec::new());
    let loaded = load(&closed.sink, u64::MAX).unwrap();
    let mut seen = [0u64; 11];
    let turns = closed.sink.as_chunks::<48>().0.iter();
    for record in turns.filter(|record| record[0] == Tag::Turn as u8) {
        let (candidate, observation) = (&record[12..28], &record[36..48]);
        let workload = candidate[0] == Domain::Workload as u8;
        let named = [
            observation[3],
            observation[4],
            observation[5],
            observation[6],
        ];
        let (code, client, cell) = (candidate[1], candidate[3], candidate[2]);
        match observation[0] {
            0 => {}
            1..=5 => assert!(workload && code == super::READ && named == [client, 0, cell, 0]),
            6..=9 => assert!(workload && code == super::OUTCOME && named == [0, 0, cell, 0]),
            other => panic!("turn variant {other}: {observation:?}"),
        }
        let word = u64::from_le_bytes(record[28..36].try_into().unwrap());
        if workload && code == super::OUTCOME {
            let expected = if word == super::REFUSED { 0 } else { 5 + word };
            assert_eq!(u64::from(observation[0]), expected, "{record:?}");
        }
        let status = u16::from_le_bytes([observation[1], observation[2]]);
        match observation[0] {
            3..=5 | 7 => assert!(Status::from_wire(status).is_some(), "{observation:?}"),
            _ => assert_eq!(status, 0, "{observation:?}"),
        }
        assert!(observation[7..].iter().all(|&byte| byte == 0));
        seen[usize::from(observation[0])] += 1;
    }
    let coverage = loaded
        .events
        .iter()
        .rfind(|event| event.kind == super::COVERAGE);
    let (_, counts) = super::coverage_of(coverage.unwrap());
    let count = |name: &str| {
        u64::from(
            counts[super::Reached::NAMES
                .iter()
                .position(|known| *known == name)
                .unwrap()],
        )
    };
    assert_eq!(count("misses"), seen[2], "{seen:?}");
    assert_eq!(count("refused"), seen[3] + seen[4] + seen[5], "{seen:?}");
    assert!(count("hits") <= seen[1], "{seen:?}");
    assert!(count("published") <= seen[6], "{seen:?}");
    seen
}

/// A cluster turn's outcome names what the cluster's producer records: a
/// refusal for each operation `acted` counts as refused at 0, a count for
/// owner polls, service and coverage writes, a client poll's packed
/// received and sent counts, and a collected upload outcome as its number.
#[test]
fn every_cluster_outcome_names_its_producers_meaning() {
    use super::{
        APPLIED, CANCEL, CLIENT_POLL, COVER, GET, INVALIDATE, OUTCOME, OWNER_POLL, PREPARE, PROBE,
        PUT, READ, REFUSED, SERVICE, SUPPLY, candidate,
    };
    use crate::net::world_tests::narrate::{World, tests::turn_line};
    let line = |code, outcome| turn_line(World::Cluster, candidate(code, 1, 0, 0, 3, 2).0, outcome);
    for code in [
        READ, PREPARE, SUPPLY, OUTCOME, PROBE, GET, PUT, INVALIDATE, CANCEL,
    ] {
        assert!(
            line(code, REFUSED).ends_with(" outcome=refused"),
            "{}",
            line(code, REFUSED)
        );
        assert!(
            line(code, APPLIED).ends_with(" outcome=1"),
            "{}",
            line(code, APPLIED)
        );
    }
    for code in [OWNER_POLL, SERVICE, COVER] {
        assert!(line(code, 0).ends_with(" outcome=0"), "{}", line(code, 0));
    }
    let polled = line(CLIENT_POLL, 3 | 5 << 32);
    assert!(polled.ends_with(" received=3 sent=5"), "{polled}");
}

/// Each cluster profile's minima hold the values its recorded bundles were
/// judged under. The configuration record leaves the minima out, and a
/// narrative derives a recorded run's shortfall from this build's minima
/// for the profile the record names, so changing a profile's minima also
/// takes a new `GENERATOR`, and this table with it.
#[test]
fn every_profiles_minima_stay_pinned_to_its_generator() {
    let minima: Vec<(&str, [u64; 6])> = PROFILES
        .iter()
        .map(|shape| {
            let m = shape.minima;
            let values = [m.published, m.hits, m.cross, m.faults, m.healthy, m.reused];
            (shape.name, values)
        })
        .collect();
    assert_eq!(super::GENERATOR, 4, "a new generator pins its minima here");
    assert_eq!(
        minima, PINNED_MINIMA,
        "a changed minimum takes a new GENERATOR"
    );
}
/// Each cluster profile's published, hits, cross, faults, healthy and
/// reused minima under `GENERATOR` 4.
const PINNED_MINIMA: [(&str, [u64; 6]); 20] = [
    ("cluster-broad", [4, 1, 0, 1, 3, 0]),
    ("cluster-pressure", [10, 4, 1, 1, 2, 1]),
    ("cluster-wrong-owner", [0; 6]),
    ("cluster-stale-read", [0; 6]),
    ("cluster-long", [1000, 100, 1, 500, 731, 1]),
    ("cluster-late-stale", [0; 6]),
    ("cluster-late-leak", [0; 6]),
    ("cluster-late-corrupt", [0; 6]),
    ("cluster-version-end", [0; 6]),
    ("cluster-swarm", [0; 6]),
    ("cluster-swarm-wrong-owner", [0; 6]),
    ("cluster-swarm-stale-read", [0; 6]),
    ("cluster-swarm-late-stale", [0; 6]),
    ("cluster-swarm-leak", [0; 6]),
    ("cluster-swarm-corrupt", [0; 6]),
    ("cluster-swarm-misread", [0; 6]),
    ("cluster-swarm-unremoved", [0; 6]),
    ("cluster-order-1", [0; 6]),
    ("cluster-order-2", [0; 6]),
    ("cluster-order-3", [0; 6]),
];

/// The broad profile with sound links, no invalidations, no cancels and
/// no minima, over `device`, its fault phases sustained or not.
const fn on_device(device: super::DeviceFaults, sustained: bool) -> Shape {
    Shape {
        name: "cluster-broad",
        faults: super::link_faults(0, 0, 0, 0),
        device,
        sustained,
        invalidate: false,
        cancel: false,
        minima: super::NO_MINIMA,
        ..PROFILES[0]
    }
}

/// The run of `shape` from `root`, which must pass every check and audit
/// and heal after each of its phases.
fn healed(shape: &'static Shape, root: u64) -> Reached {
    healed_run(shape, root).reached
}

/// [`healed`], returning the whole run.
fn healed_run(shape: &'static Shape, root: u64) -> super::Ran {
    let ran = run_root(shape, root);
    assert_eq!(ran.failure, None, "root {root}: {:?}", ran.reached);
    assert_eq!(ran.report.end, crate::sim::turn::End::Done, "root {root}");
    assert_eq!(ran.audit, super::Verdict::Pass, "root {root}");
    assert_eq!(ran.reached.healthy, u64::from(shape.phases), "root {root}");
    ran
}

/// Under a device whose every write reports an I/O error through sustained
/// fault phases, no generated upload's collected outcome is published,
/// every check passes and every owner heals. The same run over a sound
/// device publishes. With phases that heal as their last operation is
/// issued, the failing device publishes too: an upload whose writes all
/// execute after the heal meets a sound device.
#[test]
fn a_failing_device_write_publishes_nothing_and_the_owners_heal() {
    const FAILING: super::DeviceFaults = super::DeviceFaults {
        write_error: 100,
        ..super::SOUND
    };
    static SOUND: Shape = on_device(super::SOUND, true);
    static SUSTAINED: Shape = on_device(FAILING, true);
    static BRIEF: Shape = on_device(FAILING, false);
    for root in [3, 7] {
        let sound = healed(&SOUND, root);
        assert!(sound.published > 0, "{sound:?}");
        let sustained = healed(&SUSTAINED, root);
        assert_eq!(sustained.published, 0, "{sustained:?}");
        let brief = healed(&BRIEF, root);
        assert!(brief.published > 0, "{brief:?}");
    }
}

/// Under a device whose every read reports an I/O error through sustained
/// fault phases, no generated GET reads an object exactly, more generated
/// GETs end with no complete object than over a sound device, every check
/// passes and every owner heals. The same run over a sound device reads
/// objects exactly.
#[test]
fn a_failing_device_read_serves_nothing_and_the_owners_heal() {
    static SOUND: Shape = on_device(super::SOUND, true);
    static FAILING: Shape = on_device(
        super::DeviceFaults {
            read_error: 100,
            ..super::SOUND
        },
        true,
    );
    for root in [3, 7] {
        let sound = healed(&SOUND, root);
        assert!(sound.hits > 0, "{sound:?}");
        let failing = healed(&FAILING, root);
        assert_eq!(failing.hits, 0, "{failing:?}");
        assert!(failing.refused > sound.refused, "{failing:?} {sound:?}");
    }
}

/// Under a device whose every write that executes through sustained fault
/// phases draws a torn write, no generated upload's collected outcome is
/// published, every check passes and every owner heals, and the same run
/// over a sound device publishes. Each run admits torn writes on ranges
/// the fixture's persistence profile leaves unqualified, which land a
/// prefix of whole sectors and report an I/O error, and carries the
/// no-byte error on hits the device refuses on qualified ones, so both
/// paths of a torn hit are reached. At least one admitted torn write
/// lands a prefix longer than one sector and shorter than its command.
/// The sound run, whose rates are all zero, counts no device fault.
#[test]
fn a_torn_device_write_publishes_nothing_and_the_owners_heal() {
    static SOUND: Shape = on_device(super::SOUND, true);
    static TORN: Shape = on_device(
        super::DeviceFaults {
            write_torn: 100,
            ..super::SOUND
        },
        true,
    );
    for root in [3, 7] {
        let sound = healed_run(&SOUND, root);
        assert!(sound.reached.published > 0, "{:?}", sound.reached);
        assert_eq!(sound.applied, super::Applied::default(), "root {root}");
        let torn = healed_run(&TORN, root);
        assert_eq!(torn.reached.published, 0, "{:?}", torn.reached);
        let applied = torn.applied;
        assert!(applied.write_torn > 0, "root {root}: {applied:?}");
        assert!(applied.torn_refused > 0, "root {root}: {applied:?}");
        assert!(applied.interior > 0, "root {root}: {applied:?}");
        assert_eq!(
            (
                applied.write_error,
                applied.read_error,
                applied.read_partial
            ),
            (0, 0, 0),
            "root {root}: {applied:?}"
        );
    }
}

/// Under a device whose every write that executes through sustained fault
/// phases draws a torn write, over 100-byte objects whose every write is
/// one 4096-byte block the fixture's persistence profile qualifies, the
/// device refuses every torn hit and each refused command carries the
/// no-byte error: no generated upload's collected outcome is published,
/// no torn write is admitted, every check passes and every owner heals.
/// The same run over a sound device publishes, so only the failed
/// commands keep the uploads unpublished.
#[test]
fn a_refused_torn_write_fails_its_command_and_the_owners_heal() {
    const SMALL: &[u32] = &[100];
    static SOUND: Shape = Shape {
        sizes: SMALL,
        ..on_device(super::SOUND, true)
    };
    static TORN: Shape = Shape {
        sizes: SMALL,
        ..on_device(
            super::DeviceFaults {
                write_torn: 100,
                ..super::SOUND
            },
            true,
        )
    };
    for root in [3, 7] {
        let sound = healed(&SOUND, root);
        assert!(sound.published > 0, "{sound:?}");
        let torn = healed_run(&TORN, root);
        assert_eq!(torn.reached.published, 0, "{:?}", torn.reached);
        let applied = torn.applied;
        assert!(applied.torn_refused > 0, "root {root}: {applied:?}");
        assert_eq!(
            super::Applied {
                torn_refused: 0,
                ..applied
            },
            super::Applied::default(),
            "root {root}"
        );
    }
}

/// Under a device whose every read writes a prefix of whole sectors into
/// its buffer and reports an I/O error, through sustained fault phases, no
/// generated GET reads an object exactly, more generated GETs end with no
/// complete object than over a sound device, every check passes and every
/// owner heals, and the same run over a sound device reads objects
/// exactly. Each run applies partial reads, at least one of them with a
/// prefix longer than one sector and shorter than its command.
#[test]
fn a_partial_device_read_serves_nothing_and_the_owners_heal() {
    static SOUND: Shape = on_device(super::SOUND, true);
    static PARTIAL: Shape = on_device(
        super::DeviceFaults {
            read_partial: 100,
            ..super::SOUND
        },
        true,
    );
    for root in [3, 7] {
        let sound = healed(&SOUND, root);
        assert!(sound.hits > 0, "{sound:?}");
        let partial = healed_run(&PARTIAL, root);
        assert_eq!(partial.reached.hits, 0, "{:?}", partial.reached);
        assert!(
            partial.reached.refused > sound.refused,
            "{:?} {sound:?}",
            partial.reached
        );
        let applied = partial.applied;
        assert!(applied.read_partial > 0, "root {root}: {applied:?}");
        assert!(applied.interior > 0, "root {root}: {applied:?}");
        assert_eq!(
            (
                applied.write_error,
                applied.read_error,
                applied.write_torn,
                applied.torn_refused
            ),
            (0, 0, 0, 0),
            "root {root}: {applied:?}"
        );
    }
}

/// Swarm roots 30 to 49 each pass every check and audit and heal every
/// phase of the member they select, while across them the devices admit
/// torn writes, refuse torn hits on qualified ranges and apply partial
/// reads. A zero rate counts zero, among them a zero rate beside an
/// applied kind of the same operation for each of the four kinds, and a
/// run over a member whose device rates are all zero counts no device
/// fault, as does the sound run of
/// `a_torn_device_write_publishes_nothing_and_the_owners_heal`.
#[test]
fn swarm_roots_apply_torn_writes_and_partial_reads_and_pass() {
    let mut applied = super::Applied::default();
    let mut split = [false; 4];
    for root in 30..50 {
        let member = super::swarm::member(root);
        let ran = healed_run(member, root);
        assert!(ran.judged().counts(), "root {root}: {:?}", ran.judged());
        let (device, got) = (member.device, ran.applied);
        let torn = got.write_torn + got.torn_refused;
        // Each kind's rate, its applied count and the applied count of the
        // other kind of the same operation.
        let kinds = [
            (device.write_error, got.write_error, torn),
            (device.read_error, got.read_error, got.read_partial),
            (device.write_torn, torn, got.write_error),
            (device.read_partial, got.read_partial, got.read_error),
        ];
        for (at, (rate, count, partner)) in kinds.into_iter().enumerate() {
            assert!(
                rate > 0 || count == 0,
                "root {root}: {device:?} applied {got:?}"
            );
            // A zero rate beside a kind of the same operation that this
            // root applied drew at that operation's commands, so its zero
            // count judges the selection's split.
            split[at] |= rate == 0 && partner > 0;
        }
        applied = applied.plus(got);
    }
    assert_eq!(
        split, [true; 4],
        "each kind's zero rate beside a drawing one"
    );
    assert!(applied.write_torn > 0, "{applied:?}");
    assert!(applied.torn_refused > 0, "{applied:?}");
    assert!(applied.read_partial > 0, "{applied:?}");
}

/// Every fault the world can attach is honest for every command length a
/// generated profile submits: the no-byte error, built with the zero
/// length every drawn error and every refused torn hit pass, and the
/// prefix kind of each operation at each prefix length. The match over
/// the kinds has no wildcard arm, so a kind added to the draw fails to
/// compile here until it has a range of prefixes; the array the loop
/// visits must list it too. The assertion's helper refuses a lying fault,
/// so the check can fail.
#[test]
fn every_drawn_device_fault_is_honest() {
    use crate::storage::device::sim::{Fault, Report};
    use crate::storage::{Operation, SECTOR};
    let honest = |fault: Fault, len: u32| fault.report(len) == Report::Honest;
    assert!(!honest(Fault::CorruptSuccess, SECTOR as u32));
    // A cluster owner's device transfers at most one buffer per command.
    let most = crate::storage::owner_fixture::BUFFER / SECTOR as u32;
    for sectors in 1..=most {
        let len = sectors * SECTOR as u32;
        for op in [Operation::Read, Operation::Write] {
            for kind in [super::DeviceKind::Error, super::DeviceKind::Prefix] {
                let prefixes = match kind {
                    super::DeviceKind::Error => 0..=0,
                    super::DeviceKind::Prefix => 1..=sectors,
                };
                for prefix in prefixes {
                    let fault = super::device_fault(op, kind, prefix);
                    assert!(honest(fault, len), "{fault:?} on {len} bytes");
                }
            }
        }
    }
}

/// The building function maps each operation and kind to its fault: the
/// no-byte error status for either operation, built with the zero length
/// every drawn error and every refused torn hit pass, a torn write of the drawn
/// prefix for a write and a partial read of it for a read.
#[test]
fn each_drawn_kind_builds_its_fault() {
    use crate::storage::device::sim::Fault;
    use crate::storage::{DeviceStatus, Operation};
    for op in [Operation::Read, Operation::Write] {
        assert_eq!(
            super::device_fault(op, super::DeviceKind::Error, 0),
            Fault::Status(DeviceStatus::Kernel(-libc::EIO))
        );
    }
    for sectors in [1, 7, 32] {
        assert_eq!(
            super::device_fault(Operation::Write, super::DeviceKind::Prefix, sectors),
            Fault::TornWrite { sectors }
        );
        assert_eq!(
            super::device_fault(Operation::Read, super::DeviceKind::Prefix, sectors),
            Fault::PartialReadFailure { sectors }
        );
    }
}

/// The configuration record carries each device rate: shapes that differ
/// only in one of the four rates write different records.
#[test]
fn the_configuration_record_carries_every_device_rate() {
    const fn with(device: super::DeviceFaults) -> Shape {
        on_device(device, true)
    }
    static SHAPES: [Shape; 5] = [
        with(super::SOUND),
        with(super::DeviceFaults {
            write_error: 1,
            ..super::SOUND
        }),
        with(super::DeviceFaults {
            read_error: 1,
            ..super::SOUND
        }),
        with(super::DeviceFaults {
            write_torn: 1,
            ..super::SOUND
        }),
        with(super::DeviceFaults {
            read_partial: 1,
            ..super::SOUND
        }),
    ];
    let records: std::collections::BTreeSet<Vec<u8>> = SHAPES
        .iter()
        .map(|shape| bare_world(shape, Vec::new()).config())
        .collect();
    assert_eq!(records.len(), SHAPES.len());
}

/// An operation whose two rates are zero draws nothing: each run passes on
/// a chooser that omits the device fault site of every operation whose
/// rates are zero, where a draw there would be refused and end the run
/// with a choice defect. A device with all four rates zero runs with no
/// disk site; a device whose write_torn rate is 100 runs with its write
/// site alone and one whose read_partial rate is 100 with its read site
/// alone, each applying its own kind. A companion run of each one-sided
/// device gives its silent operation an error rate of 100 on every site.
/// The companion draws nothing for that operation until its first command
/// executes under the rates, so the two runs agree up to that command, and
/// the companion's positive error count shows that the one-sided run
/// executes a command of its silent operation while the rates are in
/// force. The write_torn device on a chooser with no disk site ends in the
/// defect at a write site, so the check can fail.
#[test]
fn an_operation_with_zero_rates_draws_nothing() {
    use crate::sim::choice::{ChoiceError, Defect as Harness, Domain};
    use crate::sim::turn::{Defect, End};
    use crate::storage::Operation;
    const TORN: super::DeviceFaults = super::DeviceFaults {
        write_torn: 100,
        ..super::SOUND
    };
    const PARTIAL: super::DeviceFaults = super::DeviceFaults {
        read_partial: 100,
        ..super::SOUND
    };
    static SOUND: Shape = on_device(super::SOUND, true);
    static TEARS: Shape = on_device(TORN, true);
    static READS: Shape = on_device(PARTIAL, true);
    static TEARS_FAILING_READS: Shape = on_device(
        super::DeviceFaults {
            read_error: 100,
            ..TORN
        },
        true,
    );
    static READS_FAILING_WRITES: Shape = on_device(
        super::DeviceFaults {
            write_error: 100,
            ..PARTIAL
        },
        true,
    );
    // The chooser keeps every site outside the disk domain and, of the
    // disk sites, only the device fault sites of `kept`.
    let on = |shape: &'static Shape, root: u64, kept: &[Operation]| {
        let profile = profile_at(shape, root);
        let sites: Vec<_> = super::sites()
            .into_iter()
            .filter(|site| {
                site.domain != Domain::Disk
                    || kept
                        .iter()
                        .any(|&op| *site == super::device_site(site.actor, op))
            })
            .collect();
        run(
            profile.recorder(&sites),
            &profile,
            shape,
            (RAISED, 4096, crate::net::link::UNBOUNDED),
            &mut (),
        )
    };
    let both = [Operation::Read, Operation::Write];
    for root in [3, 7] {
        for (shape, kept) in [
            (&SOUND, &[][..]),
            (&TEARS, &[Operation::Write]),
            (&READS, &[Operation::Read]),
        ] {
            let ran = on(shape, root, kept);
            assert_eq!(ran.failure, None, "root {root}: {:?}", shape.device);
            assert_eq!(ran.report.end, End::Done, "root {root}: {:?}", shape.device);
            let applied = ran.applied;
            assert_eq!(
                applied.write_torn > 0,
                shape.device.write_torn > 0,
                "root {root}: {applied:?}"
            );
            assert_eq!(
                applied.read_partial > 0,
                shape.device.read_partial > 0,
                "root {root}: {applied:?}"
            );
        }
        let reads = on(&TEARS_FAILING_READS, root, &both).applied;
        assert!(reads.read_error > 0, "root {root}: {reads:?}");
        let writes = on(&READS_FAILING_WRITES, root, &both).applied;
        assert!(writes.write_error > 0, "root {root}: {writes:?}");
        let refused = on(&TEARS, root, &[]);
        assert!(
            matches!(
                refused.report.end,
                End::Defect(Defect::Choice(ChoiceError::HarnessDefect(Harness::Unregistered(site))))
                    if site.domain == Domain::Disk
                        && site == super::device_site(site.actor, Operation::Write)
            ),
            "root {root}: {:?}",
            refused.report.end
        );
    }
}

/// A run whose shape gives one operation two device rates that sum past
/// 100 panics before its first draw, though each rate alone is at most
/// 100.
#[test]
#[should_panic(expected = "an operation's device rates 1 and 100 sum past 100")]
fn device_rates_that_sum_past_100_are_refused() {
    static OVER: Shape = on_device(
        super::DeviceFaults {
            write_error: 1,
            write_torn: 100,
            ..super::SOUND
        },
        true,
    );
    run_root(&OVER, 3);
}

/// One draw below 100 selects the no-byte error for exactly the values
/// below the error rate, the prefix kind for exactly the next `prefix`
/// values and no fault for the rest, for rate pairs at both ends and
/// between.
#[test]
fn one_draw_selects_each_kind_for_exactly_its_rate() {
    for (error, prefix) in [
        (0, 0),
        (0, 100),
        (100, 0),
        (10, 10),
        (3, 7),
        (50, 50),
        (0, 5),
    ] {
        let expected: Vec<_> = std::iter::repeat_n(Some(super::DeviceKind::Error), error as usize)
            .chain(std::iter::repeat_n(
                Some(super::DeviceKind::Prefix),
                prefix as usize,
            ))
            .chain(std::iter::repeat_n(None, (100 - error - prefix) as usize))
            .collect();
        let chosen: Vec<_> = (0..100)
            .map(|drawn| super::device_kind(drawn, error, prefix))
            .collect();
        assert_eq!(chosen, expected, "({error}, {prefix})");
    }
}

/// A recorded swarm root whose member draws the torn-write and
/// partial-read rates positive, and whose direct run admits torn writes
/// and applies partial reads under the manifest's own bounds, replays in
/// this process to its digest and passing terminal. The recording
/// reaches the same coverage counts as the direct run whose applied
/// counts the test read.
#[test]
fn a_swarm_bundle_with_torn_writes_and_partial_reads_replays_to_its_digest() {
    const ROOT: u64 = 25;
    let member = super::swarm::member(ROOT);
    assert!(member.device.write_torn > 0 && member.device.read_partial > 0);
    let manifest = manifest(super::swarm::NAME, ROOT);
    let admitted = admit(&manifest).unwrap();
    let direct = super::session(&admitted, &mut ()).unwrap();
    let applied = direct.applied;
    assert!(
        applied.write_torn > 0 && applied.read_partial > 0,
        "{applied:?}"
    );
    let loaded = replays_to_its_digest(admitted);
    let (_, counts) = observed(&loaded.events).coverage.unwrap();
    assert_eq!(counts, direct.reached.counts().map(|count| count as u32));
}

/// Each of the links' stale replay, truncation, would-block and failing
/// call faults, alone through sustained fault phases over a sound device,
/// is delivered, and the run passes every check and audit and heals after
/// each phase.
#[test]
fn each_call_and_frame_fault_is_delivered_and_the_owners_heal() {
    use crate::net::link::Faults;
    const fn on_links(faults: Faults) -> Shape {
        Shape {
            name: "cluster-broad",
            faults,
            sustained: true,
            minima: super::NO_MINIMA,
            ..PROFILES[0]
        }
    }
    const NONE: Faults = super::link_faults(0, 0, 0, 0);
    static SHAPES: [Shape; 4] = [
        on_links(Faults { stale: 20, ..NONE }),
        on_links(Faults {
            truncate: 20,
            ..NONE
        }),
        on_links(Faults {
            would_block: 20,
            ..NONE
        }),
        on_links(Faults { error: 20, ..NONE }),
    ];
    for shape in &SHAPES {
        for root in [3, 7] {
            let ran = healed_run(shape, root);
            let (reached, truncated) = (ran.reached, ran.truncated);
            assert!(reached.faults > 0, "{:?}: {reached:?}", shape.faults);
            // The truncation shape delivers truncated datagrams to owners,
            // and each owner drops every one of them as truncated.
            if shape.faults.truncate > 0 {
                assert!(truncated.delivered > 0, "root {root}: {reached:?}");
                assert_eq!(truncated.delivered, truncated.dropped, "root {root}");
            }
        }
    }
}

/// An acknowledged INVALIDATE of a key over every version up to its
/// newest raises the key's floor past that version: a GET issued before
/// the acknowledgment may still return the version, and one issued after
/// it fails as a stale read. A key that took no version has none to name.
#[test]
fn an_acknowledged_invalidation_fails_a_later_read_of_its_versions() {
    let stale = super::Failure::Violation(
        Obligation::History,
        "a GET returned a version older than one collected or removed before it",
    );
    let mut checker = fresh();
    assert_eq!(checker.taken(1), None);
    checker.invoked(1, 1, 2000);
    checker.invoked(1, 1, 2000);
    assert_eq!(checker.taken(1), Some(1));
    checker.published(1, 1, false);
    let before = get(0, 1, checker.floor(1));
    checker.acknowledged(1, 1, 1);
    assert_eq!((checker.floor(1), checker.reached.invalidated), (2, 1));
    let bytes = content(1, 1, 1, 2000);
    checker.decided(before, Fetched::Complete, &bytes);
    assert_eq!(checker.first.get(), None);
    checker.decided(get(0, 1, checker.floor(1)), Fetched::Complete, &bytes);
    assert_eq!(checker.first.get(), Some(stale));
}

/// An INVALIDATE's acknowledgment raises its key's floor however many
/// INVALIDATEs client 0 sent after it. Client 0 sends the INVALIDATE of
/// key 0 and then 64 of key 1 before the owner's first coverage write,
/// which acknowledges both entries, and the client poll that takes the
/// first INVALIDATE's acknowledgment raises key 0's floor past the version
/// it named.
#[test]
fn an_acknowledgment_raises_its_floor_after_64_later_invalidates() {
    let (draws, _, setups) = drawn_at(shape("cluster-broad").unwrap(), 1);
    let cover = super::candidate(super::COVER, 0, 0, 0, 0, 0);
    let mut raised = false;
    super::nest(
        0,
        (&setups[..1], &draws, true),
        (4096, crate::net::link::UNBOUNDED),
        Vec::new(),
        &mut |mut cells| {
            let cell = &mut cells[0];
            let mut checker = checker(1, 2);
            checker.invoked(0, 0, 2000);
            checker.invoked(1, 0, 2000);
            let mut now = cell.start();
            let (mut first, mut later) = (false, 0);
            for step in 0..20_000 {
                if checker.floor(0) == 1 {
                    break;
                }
                if !first && cell.active(0) {
                    let sent = cell.invalidate(0, now, &mut checker, Plant::None);
                    assert_eq!(sent, super::APPLIED);
                    first = true;
                } else if first && later < 64 {
                    let sent = cell.invalidate(1, now, &mut checker, Plant::None);
                    later += u32::from(sent == super::APPLIED);
                }
                cell.set_clocks(now);
                let mut out = Vec::new();
                cell.runnable(now, &mut out);
                out.retain(|event| later == 64 || *event != cover);
                out.sort();
                if out.is_empty() {
                    let Some(due) = cell.next_due(now) else {
                        break;
                    };
                    now = due;
                    cell.advance(now, &checker);
                } else {
                    cell.apply(&out[step % out.len()], now, &mut checker, Plant::None);
                    cell.absorb();
                }
            }
            assert_eq!(later, 64, "client 0 sent every later INVALIDATE");
            assert_eq!(checker.first.get(), None);
            assert_eq!(
                (checker.floor(0), checker.floor(1)),
                (1, 1),
                "each acknowledged INVALIDATE raised its key's floor"
            );
            raised = true;
        },
    );
    assert!(raised);
}

/// An acknowledgment names a version of its own key up to the newest one
/// it was sent with, that version included, and no version of another
/// key or above it. A GET reads the acknowledgments taken before it was
/// issued, a prefix of the list.
#[test]
fn an_acknowledgment_names_its_keys_versions_up_to_its_newest() {
    let acknowledged = [(0, 1), (1, 3)];
    for (key, version, named) in [
        (0, 0, true),
        (0, 1, true),
        (0, 2, false),
        (1, 3, true),
        (1, 4, false),
        (2, 0, false),
    ] {
        assert_eq!(
            super::names(&acknowledged, key, version),
            named,
            "key {key} version {version}"
        );
    }
    assert!(
        !super::names(&acknowledged[..1], 1, 3),
        "a later acknowledgment"
    );
    assert!(!super::names(&[], 0, 0));
}

/// A control's plant counts as having acted when the checker recorded it
/// or a partition observed it late, so a run with either and no failure
/// ends as a missed control, and a run with neither as no effect.
#[test]
fn a_partitions_late_effect_counts_as_the_plants() {
    use crate::sim::turn::End;
    for (acted, late) in [(false, false), (true, false), (false, true)] {
        let mut world = held_world(Held {
            retired: true,
            reclaimed: true,
            returning: false,
            late,
        });
        world.checker.acted = acted;
        assert_eq!(world.planted(), acted || late);
        let unmet = super::unmet(End::Done, world.planted());
        let expected = if acted || late {
            super::UNSEEN
        } else {
            super::NO_EFFECT
        };
        assert_eq!(unmet, Some(super::Failure::Unsuccessful(expected)));
    }
}

/// Drives one partition under `plant`: applies the runnable events
/// `allowed` admits, in sorted order by step, and advances the clock when
/// none is runnable. It stops when `done` holds, when no event is
/// runnable and none is due, or when the steps run out, and returns the
/// time reached.
pub(super) fn driven(
    cell: &mut Box<dyn super::Cell + '_>,
    checker: &mut Checker,
    (plant, mut now): (Plant, u64),
    allowed: impl Fn(&super::Candidate) -> bool,
    done: impl Fn(&dyn super::Cell, &Checker) -> bool,
) -> u64 {
    for step in 0..20_000 {
        if done(&**cell, checker) {
            break;
        }
        cell.set_clocks(now);
        let mut out = Vec::new();
        cell.runnable(now, &mut out);
        out.retain(|event| allowed(event));
        out.sort();
        if out.is_empty() {
            let Some(due) = cell.next_due(now) else {
                break;
            };
            now = due;
            cell.advance(now, checker);
        } else {
            cell.apply(&out[step % out.len()], now, checker, plant);
            cell.absorb();
        }
    }
    now
}

/// Whether `event` moves the partition's upload: a prepare, a supply or
/// an outcome collection.
fn moves_upload(event: &super::Candidate) -> bool {
    matches!(event.0[1], super::PREPARE | super::SUPPLY | super::OUTCOME)
}

/// The client poll that takes an INVALIDATE's acknowledgment judges the
/// owner's binding at once, with no clock move after it. Under the
/// unremoved plant the owner still binds the version the INVALIDATE
/// named: that poll records the binding violation and the plant's
/// effect. With no plant the owner removed the object, and the same poll
/// records no failure and no effect.
#[test]
fn an_acknowledgment_judges_its_owners_binding_when_it_arrives() {
    let rebound = super::Failure::Violation(
        Obligation::History,
        "an owner binds a version an acknowledged invalidation covered",
    );
    for plant in [Plant::Unremoved, Plant::None] {
        let (draws, _, setups) = drawn_at(shape("cluster-broad").unwrap(), 1);
        let mut judged = false;
        super::nest(
            0,
            (&setups[..1], &draws, true),
            (4096, crate::net::link::UNBOUNDED),
            Vec::new(),
            &mut |mut cells| {
                let cell = &mut cells[0];
                let mut checker = checker(1, 1);
                let start = cell.start();
                let now = driven(
                    cell,
                    &mut checker,
                    (plant, start),
                    |_| true,
                    |cell, _| cell.active(0),
                );
                assert_eq!(
                    cell.put(0, 0, content(0, 0, 0, 2000), false, now),
                    super::APPLIED
                );
                checker.invoked(0, 0, 2000);
                let now = driven(
                    cell,
                    &mut checker,
                    (plant, now),
                    |_| true,
                    |cell, _| !cell.uploading(),
                );
                assert!(
                    checker.keys[0].uploads[&0].published,
                    "the upload published"
                );
                assert_eq!(cell.invalidate(0, now, &mut checker, plant), super::APPLIED);
                // A clock move before the acknowledgment judges an upload no
                // acknowledgment covers, so the failure below is the poll's.
                driven(
                    cell,
                    &mut checker,
                    (plant, now),
                    |_| true,
                    |_, checker| {
                        if checker.reached.invalidated == 1 {
                            return true;
                        }
                        assert_eq!((checker.first.get(), checker.acted), (None, false));
                        false
                    },
                );
                assert_eq!(checker.reached.invalidated, 1, "the acknowledgment arrived");
                let planted = plant == Plant::Unremoved;
                assert_eq!(checker.first.get(), planted.then(|| rebound.clone()));
                assert_eq!(checker.acted, planted);
                assert!(!cell.late());
                judged = true;
            },
        );
        assert!(judged, "{plant:?}");
    }
}

/// Runs `after` on partition `owner` of a versioned cluster under the
/// unremoved plant, once the acknowledgment of an INVALIDATE of the key
/// that owner serves arrived while that key's first upload was held
/// before its first frame. The upload took version 0 before the
/// INVALIDATE, so the acknowledgment covers it; nothing is bound when it
/// arrives, so that poll records no failure and no effect. `after` takes
/// the partition, the checker, the key and the time reached.
fn held_past_its_acknowledgment(
    owner: u8,
    mut after: impl FnMut(&mut Box<dyn super::Cell + '_>, &mut Checker, u8, u64),
) {
    let (draws, _, setups) = drawn_at(shape("cluster-broad").unwrap(), 1);
    let partitions = usize::from(owner) + 1;
    let mut ran = false;
    super::nest(
        0,
        (&setups[..partitions], &draws, true),
        (4096, crate::net::link::UNBOUNDED),
        Vec::new(),
        &mut |mut cells| {
            let cell = &mut cells[usize::from(owner)];
            let plant = Plant::Unremoved;
            let key = owner;
            let mut checker = checker(partitions as u8, partitions);
            assert_eq!(checker.route(key), owner);
            let start = cell.start();
            let now = driven(
                cell,
                &mut checker,
                (plant, start),
                |_| true,
                |cell, _| cell.active(0),
            );
            let object = content(key, 0, owner, 2000);
            assert_eq!(cell.put(key, 0, object, false, now), super::APPLIED);
            checker.invoked(key, owner, 2000);
            assert_eq!(
                cell.invalidate(key, now, &mut checker, plant),
                super::APPLIED
            );
            let held = |event: &super::Candidate| !moves_upload(event);
            let now = driven(cell, &mut checker, (plant, now), held, |_, checker| {
                checker.reached.invalidated == 1
            });
            assert_eq!(checker.reached.invalidated, 1, "the acknowledgment arrived");
            assert!(
                checker.keys[usize::from(key)].uploads[&0].covered,
                "the acknowledging owner's upload is covered"
            );
            assert_eq!((checker.first.get(), checker.acted), (None, false));
            assert!(!cell.late());
            after(cell, &mut checker, key, now);
            ran = true;
        },
    );
    assert!(ran);
}

/// Under the unremoved plant, an upload that takes its version before the
/// INVALIDATE and publishes after the acknowledgment binds a version the
/// acknowledgment covers. The acknowledgment covers the upload at the
/// owner that acknowledged, on partition 0 and on partition 1. The
/// upload's outcome collection then fails the binding and the partition
/// records the plant's late effect, with no GET issued.
#[test]
fn an_upload_that_publishes_after_its_keys_acknowledgment_fails_its_binding() {
    for owner in [0, 1] {
        held_past_its_acknowledgment(owner, |cell, checker, key, now| {
            let plant = Plant::Unremoved;
            driven(
                cell,
                checker,
                (plant, now),
                |_| true,
                |cell, _| !cell.uploading(),
            );
            assert!(
                checker.keys[usize::from(key)].uploads[&0].published,
                "the upload published"
            );
            assert_eq!(
                checker.first.get(),
                Some(super::Failure::Violation(
                    Obligation::History,
                    "an owner binds a version an acknowledged invalidation covered",
                )),
                "owner {owner}"
            );
            assert!(cell.late(), "the plant's late effect");
        });
    }
}

/// A stopped boundary observes the same late binding with the upload's
/// outcome uncollected and no GET issued: it fails the binding and the
/// partition records the plant's late effect. With the upload's covered
/// mark cleared, the boundary fails nothing and the partition still
/// records the effect, from its own acknowledgments, so the run would end
/// as a missed control.
#[test]
fn a_stopped_boundary_records_a_late_binding_with_its_outcome_uncollected() {
    for judged in [true, false] {
        held_past_its_acknowledgment(0, |cell, checker, key, now| {
            if !judged {
                let upload = checker.keys[usize::from(key)].uploads.get_mut(&0);
                upload.expect("the held upload").covered = false;
            }
            let uncollected = |event: &super::Candidate| event.0[1] != super::OUTCOME;
            driven(
                cell,
                checker,
                (Plant::Unremoved, now),
                uncollected,
                |cell, _| cell.late(),
            );
            assert!(cell.late(), "a stopped boundary saw the binding");
            assert!(cell.uploading(), "the outcome is uncollected");
            let failure = judged.then_some(super::Failure::Violation(
                Obligation::History,
                "an owner binds a version an acknowledged invalidation covered",
            ));
            assert_eq!((checker.first.get(), checker.acted), (failure, false));
        });
    }
}

/// The broad profile with sound links and devices, no cancels and no
/// minima, over versioned sessions, with or without the unremoved plant.
const fn versioned(plant: Plant) -> Shape {
    Shape {
        name: "cluster-broad",
        faults: super::link_faults(0, 0, 0, 0),
        versioned: true,
        cancel: false,
        plant,
        minima: super::NO_MINIMA,
        ..PROFILES[0]
    }
}

/// Over versioned sessions on sound links, on roots 3 and 7, at least one
/// of client 0's INVALIDATEs is acknowledged, one upload that names its
/// version publishes and one GET reads an object exactly, every check
/// passes and every owner heals.
#[test]
fn a_versioned_run_acknowledges_its_invalidations_and_heals() {
    static VERSIONED: Shape = versioned(Plant::None);
    for root in [3, 7] {
        let reached = healed(&VERSIONED, root);
        assert!(
            reached.invalidated > 0 && reached.published > 0 && reached.hits > 0,
            "root {root}: {reached:?}"
        );
    }
}

/// An INVALIDATE that names a key no upload takes is acknowledged and
/// removes nothing of the key the run tracks it under, so the owner still
/// binds a version the acknowledgment covers: on each of roots 1 to 8
/// the run fails as a binding of a covered version.
#[test]
fn an_acknowledged_invalidation_that_removed_nothing_fails_its_owners_binding() {
    static UNREMOVED: Shape = versioned(Plant::Unremoved);
    for root in 1..=8 {
        assert_eq!(
            run_root(&UNREMOVED, root).failure,
            Some(super::Failure::Violation(
                Obligation::History,
                "an owner binds a version an acknowledged invalidation covered",
            )),
            "root {root}"
        );
    }
}

/// A unit leaked through owner 0's partition at its first poll fails the
/// conservation rule's free-run text in a turn's emission. The same shape
/// without the plant passes.
#[test]
fn a_unit_leaked_through_a_partition_fails_the_free_runs() {
    static LEAKED: Shape = Shape {
        name: "cluster-leaked-unit",
        phases: 1,
        plant: Plant::LeakedUnit,
        minima: super::NO_MINIMA,
        ..super::BROAD
    };
    static PLAIN: Shape = Shape {
        plant: Plant::None,
        ..LEAKED
    };
    for root in [1, 2] {
        let mut batches = super::super::Batches::default();
        let ran = run_for(&LEAKED, root, RAISED.total, &mut batches);
        assert_eq!(
            ran.failure,
            Some(super::Failure::Violation(
                Obligation::Resources,
                crate::net::observe::FREE_RUNS
            )),
            "root {root}"
        );
        let emitted = batches.0.iter().find(|(_, events)| {
            events
                .iter()
                .any(|event| event.kind == super::super::bundle::FAILURE)
        });
        assert!(
            emitted.is_some_and(|(clock, _)| !clock),
            "root {root}: a turn emitted the failure"
        );
        let plain = run_root(&PLAIN, root);
        assert_eq!(plain.failure, None, "root {root}");
        assert_eq!(
            plain.report.end,
            crate::sim::turn::End::Done,
            "root {root}: the sibling finished"
        );
        assert_eq!(plain.audit, Verdict::Pass, "root {root}");
    }
}

/// Every partition judges conservation once per emission: once after each
/// applied turn and once after each clock move.
#[test]
fn every_partition_judges_conservation_after_every_turn_and_clock_move() {
    let ran = run_root(shape("cluster-broad").unwrap(), 1);
    assert_eq!(ran.failure, None);
    assert_eq!(ran.report.end, crate::sim::turn::End::Done);
    let topology = ran.topology.expect("the root drew a topology");
    assert_eq!(ran.conserved.len(), usize::from(topology.owners));
    let emissions = ran.report.turn_count + ran.boundaries;
    assert!(ran.report.turn_count > 0 && ran.boundaries > 0);
    for (partition, judged) in ran.conserved.iter().enumerate() {
        assert_eq!(*judged, emissions, "partition {partition}");
    }
}

#[test]
fn a_lease_a_partitions_multiplexer_swallows_fails_the_datagram_accounts() {
    static UNCOUNTED: Shape = Shape {
        name: "cluster-uncounted",
        phases: 1,
        plant: Plant::Uncounted,
        minima: super::NO_MINIMA,
        ..super::BROAD
    };
    static PLAIN: Shape = Shape {
        plant: Plant::None,
        ..UNCOUNTED
    };
    let mut seed = None;
    for root in [1, 2] {
        let ran = run_root(&UNCOUNTED, root);
        assert!(
            ran.acted,
            "root {root}: premise: owner 0's multiplexer dropped a lease"
        );
        assert_eq!(
            ran.failure,
            Some(super::Failure::Violation(
                Obligation::Contain,
                crate::net::observe::UNACCOUNTED
            )),
            "root {root}"
        );
        assert!(
            ran.failure_emitted,
            "root {root}: a stopped boundary's emission caught it"
        );
        let plain = run_root(&PLAIN, root);
        assert_eq!(plain.failure, None, "root {root}");
        assert_eq!(
            plain.report.end,
            crate::sim::turn::End::Done,
            "root {root}: the sibling finished"
        );
        assert_eq!(plain.audit, Verdict::Pass, "root {root}");
        seed = seed.or(Some(ran));
    }
    // The smallest turn limit whose run drops the lease ends on that
    // turn, before any stopped boundary judges it.
    let seed = seed.expect("root 1 ran");
    let (mut low, mut high) = ((0, None), (seed.report.turn_count, seed));
    while high.0 - low.0 > 1 {
        let middle = low.0 + (high.0 - low.0) / 2;
        let ran = run_for(&UNCOUNTED, 1, middle, &mut ());
        if ran.acted {
            high = (middle, ran);
        } else {
            low = (middle, Some(ran));
        }
    }
    let (last, shorter) = (high.1, low.1.expect("a positive shorter limit"));
    assert_eq!(
        last.failure,
        Some(super::Failure::Violation(
            Obligation::Contain,
            crate::net::observe::UNACCOUNTED
        )),
        "the teardown's accounts check caught the dropped lease"
    );
    assert!(
        !last.failure_emitted,
        "no emission judged the dropped lease"
    );
    assert!(!shorter.acted, "the run one turn shorter dropped no lease");
    assert_eq!(
        shorter.failure, None,
        "the run one turn shorter has no failure"
    );
}
