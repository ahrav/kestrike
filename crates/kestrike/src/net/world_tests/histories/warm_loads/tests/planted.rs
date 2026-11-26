//! Warm-load scripts with planted steps. From `run`, `Ok(None)` certifies a completed pass and `Ok(Some(failure))`
//! carries the first recorded failure, whatever the terminal. A run that records no failure and ends in any other
//! terminal returns `Err(terminal)`.

use std::cell::Cell;

use super::super::super::tests::ended;
use super::super::*;
use super::ROOTS;
use crate::storage::warm_sim::release_capture;

thread_local! {
    static PLANTED: Cell<bool> = const { Cell::new(false) };
    static FINGERPRINTS: Cell<(Option<u64>, Option<u64>)> = const { Cell::new((None, None)) };
    static SESSIONS: Cell<[u64; 4]> = const { Cell::new([0; 4]) };
    static DRAWN: Cell<u64> = const { Cell::new(u64::MAX) };
}

fn run(
    name: &'static str,
    script: &'static [Step],
    expect: Expect,
    premise: &'static [&'static str],
    relaunches: u32,
    root: u64,
) -> Result<Option<Failure>, Terminal> {
    PLANTED.with(|planted| planted.set(false));
    let built = history(name, script, WL2_KEPT_WITNESSES, JUDGED, expect);
    let built = control(warm(relaunching(built, relaunches)), premise);
    let (terminal, first) = ended(Box::leak(Box::new(built)), root);
    let passed = matches!(
        terminal,
        Terminal::Complete {
            outcome: Ending::Pass,
            ..
        }
    );
    if first.is_none() && !passed {
        return Err(terminal);
    }
    Ok(first)
}

fn plant_once(world: &mut Mixed<'_, '_, '_>, change: impl FnOnce(&mut Mixed<'_, '_, '_>) -> bool) {
    if !PLANTED.with(Cell::get) && change(world) {
        PLANTED.with(|planted| planted.set(true));
    }
}

fn look_up_cancelled(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let ran = look_up(world, now);
    if let (_, Some(id)) = warm_state(world).looking
        && world.scene.clients[0].outcome(id).is_none()
    {
        plant_once(world, |world| {
            world.scene.clients[0].cancel(id);
            true
        });
    }
    ran
}

fn drop_served(world: &mut Mixed<'_, '_, '_>, key: u8) {
    plant_once(world, |world| {
        let served = &mut warm_state(world).served;
        let held = served.len();
        served.retain(|&n| n != key);
        served.len() < held
    });
}

fn judge_withheld_unserved(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    drop_served(world, 2);
    restored_judged(world, Some(1))
}

fn judge_unserved(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    drop_served(world, 2);
    restored_judged(world, None)
}

fn judge_unserved_1(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    drop_served(world, 1);
    restored_judged(world, None)
}

fn judge_unserved_3(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    drop_served(world, 3);
    restored_judged(world, None)
}

fn attempt_misnumbered(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    plant_once(world, |world| {
        let pass = warm_state(world).pass.as_mut();
        pass.map(|pass| pass.counter = pass.counter.wrapping_add(1 << 20))
            .is_some()
    });
    publish_attempted(world, now)
}

fn publish_unit_lost(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    plant_once(world, |world| {
        let warm = world.history.warm.as_mut().expect("the warm-load state");
        let Some(pass) = warm.pass.as_mut() else {
            return false;
        };
        let Some(stage) = pass.staged.as_mut() else {
            return false;
        };
        pass.submitted && world.scene.owner.take_unit_for(stage).is_some()
    });
    publish_pass(world, now)
}

fn publish_released(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    plant_once(world, |world| {
        let original = warm_state(world)
            .pass
            .as_ref()
            .is_some_and(|pass| !pass.replacement);
        original && release_capture(world.storage())
    });
    publish_raced(world, now)
}

fn relaunch_stale(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    plant_once(world, |world| {
        let warm = warm_state(world);
        let read = warm.read.as_ref().expect("the shard record");
        warm.host.bump(read).is_ok()
    });
    relaunch_warm(world, now)
}

fn key_2_fingerprint(world: &Mixed<'_, '_, '_>) -> Option<u64> {
    world
        .storage()
        .fingerprint_of(&key(2))
        .map(|(_, _, fingerprint)| fingerprint)
}

fn relaunch_sampled(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let before = key_2_fingerprint(world);
    let first = warm_state(world).session;
    let drawn = crate::storage::Session::fixture_draws();
    let ran = relaunch_warm(world, now);
    DRAWN.with(|during| during.set(crate::storage::Session::fixture_draws() - drawn));
    let after = key_2_fingerprint(world);
    FINGERPRINTS.with(|sampled| sampled.set((before, after)));
    let successor = warm_state(world).successor;
    let warm = world.scene.owner.tenure().get();
    SESSIONS.with(|sessions| sessions.set([first, successor, warm, 0]));
    ran
}

fn judge_reversed_unserved_1(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    drop_served(world, 1);
    judge_reversed(world, now)
}

fn hold_burst_on_one_page(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let pages = record_under(world.scene.owner.tenure()).pages;
    let mut burst = burst_of(pages);
    burst.retain(|(k, _)| page_of(k, pages) == page_of(&key(2), pages));
    plant_once(world, |_| burst.len() == ALONGSIDE + 2);
    burst_held(world, burst)
}

fn judge_after_hold(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    plant_once(world, |world| {
        hold(world, (key(3), one(1))) && world.scene.owner.held_invalidations() == 1
    });
    judge_warm(world, now)
}

fn relaunch_cold(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.relaunch(now);
    let cold = world.scene.owner.tenure().get();
    SESSIONS.with(|sessions| {
        let [first, successor, warm, _] = sessions.get();
        sessions.set([first, successor, warm, cold]);
    });
    1
}

static GET_CANCELLED: [Step; 12] = replaced(
    WL2_KEPT,
    "look-up",
    step("look-up", look_ready, look_up_cancelled),
);

static UNSERVED_WITHHELD: [Step; 12] = replaced(
    WL2_KEPT_UNRESTORED,
    "judge-withheld",
    step("judge-withheld", always, judge_withheld_unserved),
);

static UNSERVED: [Step; 12] = replaced(
    WL2_KEPT,
    "judge-warm",
    step("judge-warm", always, judge_unserved),
);

static ONLY_1_UNSERVED: [Step; 12] = replaced(
    WL2_KEPT,
    "judge-warm",
    step("judge-warm", always, judge_unserved_1),
);

static ONLY_3_UNSERVED: [Step; 18] = replaced(
    WL1_KEPT,
    "judge-warm",
    step("judge-warm", always, judge_unserved_3),
);

static ATTEMPT_MISNUMBERED: [Step; 18] = replaced(
    WL1_LOST,
    "publish-attempt",
    step("publish-attempt", pass_ready, attempt_misnumbered),
);

fn unit_lost(script: &[Step]) -> &'static [Step] {
    let planted = script.iter().map(|&registered| match registered.name {
        "publish-pass" => Step {
            run: publish_unit_lost,
            ..registered
        },
        _ => registered,
    });
    Box::leak(planted.collect())
}

static RELEASED: [Step; 12] = replaced(
    WL2_LOST,
    "publish-pass",
    step("publish-pass", pass_ready, publish_released),
);

fn stay(_: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    STAY
}

static STALLED: [Step; 12] = replaced(
    replaced(
        WL2_LOST,
        "publish-pass",
        step("publish-pass", pass_ready, publish_released),
    ),
    "suffix-landed",
    step("suffix-landed", always, stay),
);

static STALE_RECORD: [Step; 12] = replaced(
    WL2_KEPT,
    "relaunch",
    step("relaunch", relaunchable, relaunch_stale),
);

static SAMPLED: [Step; 12] = replaced(
    WL2_KEPT,
    "relaunch",
    step("relaunch", relaunchable, relaunch_sampled),
);

static KEY_1_UNSERVED: [Step; 15] = replaced(
    WL5_REVERSED,
    "judge-reversed",
    step("judge-reversed", always, judge_reversed_unserved_1),
);

static ONE_PAGE_BURST: [Step; 15] = replaced(
    WL5_IN_ORDER,
    "hold-burst",
    step("hold-burst", always, hold_burst_on_one_page),
);

static SUCCESSOR_HOLDS: [Step; 15] = replaced(
    WL5_IN_ORDER,
    "judge-warm",
    step("judge-warm", always, judge_after_hold),
);

static COLD_AFTER_WARM: [Step; 14] = [
    step("arm", always, arm_warm),
    step("fill-2", always, fill_2),
    step("publish-2", fill_written, publish_2),
    step("start-pass", always, start_pass),
    step("publish-pass", pass_ready, publish_pass),
    step("open-suffix", always, open_tenure_suffix),
    step("suffix-landed", suffix_landed, mark_landed),
    step("close-owner", always, close_first),
    step("relaunch", relaunchable, relaunch_sampled),
    step("look-up", look_ready, look_up),
    step("judge-warm", always, judge_warm),
    step("close-warm-owner", always, close_first),
    step("relaunch-cold", relaunchable, relaunch_cold),
    JUDGE,
];

/// Each planted change ends the run under the premise or rule its step
/// names: a cancelled GET under `LOOKED_UP`, a published key whose served
/// evidence is dropped under `RESTORED` for a withholding control and under
/// the loss rule for the ordinary judgment, a post-drain pass whose walk
/// names another counter under `ATTEMPT_ENDED`, a checkpoint unit whose
/// result is taken before the step reads it under `PASS_PUBLISHED` once
/// the wait passes `BOUND_US`, and a relaunch over a record a planted bump
/// moved under `RELAUNCHED`.
/// A `wl5` burst containing only entries from key 2's page ends under
/// `BURST_HELD`.
#[test]
fn each_planted_change_ends_under_its_named_premise_or_rule() {
    let lost = Expect::Violation(Obligation::Restart, LOST);
    let looked: &[&str] = &[LOADED_OPEN, LOOKED_UP];
    let cases: [(&str, &'static [Step], Expect, &'static [&str]); 7] = [
        (
            "get-cancelled",
            &GET_CANCELLED,
            Expect::Unsuccessful(LOOKED_UP),
            &[],
        ),
        (
            "unserved-withheld",
            &UNSERVED_WITHHELD,
            Expect::Unsuccessful(RESTORED),
            UNRESTORED_PREMISE,
        ),
        ("unserved", &UNSERVED, lost, looked),
        (
            "attempt-misnumbered",
            &ATTEMPT_MISNUMBERED,
            Expect::Unsuccessful(ATTEMPT_ENDED),
            &[],
        ),
        (
            "unit-lost",
            unit_lost(&WL2_KEPT),
            Expect::Unsuccessful(PASS_PUBLISHED),
            &[],
        ),
        (
            "stale-record",
            &STALE_RECORD,
            Expect::Unsuccessful(RELAUNCHED),
            &[],
        ),
        (
            "one-page-burst",
            &ONE_PAGE_BURST,
            Expect::Unsuccessful(BURST_HELD),
            &[],
        ),
    ];
    for (name, script, expect, premise) in cases {
        for root in ROOTS {
            let first = run(name, script, expect, premise, 1, root);
            assert!(
                PLANTED.with(Cell::get),
                "{name} at {root}: the change was planted"
            );
            assert_eq!(first, Ok(expect.failure()), "{name} at {root}");
        }
    }
}

#[test]
fn a_lost_unit_result_ends_the_wl3_and_wl4_scripts_under_pass_published() {
    let scripts: [(&str, &[Step]); 2] =
        [("wl3-unit-lost", &WL3_CAPPED), ("wl4-unit-lost", &WL4_KEPT)];
    let expect = Expect::Unsuccessful(PASS_PUBLISHED);
    for (name, script) in scripts {
        let script = unit_lost(script);
        for root in ROOTS {
            let first = run(name, script, expect, &[], 1, root);
            assert!(
                PLANTED.with(Cell::get),
                "{name} at {root}: the change was planted"
            );
            assert_eq!(
                first,
                Ok(expect.failure()),
                "{name} at {root}: the script's own guard on publish-pass lets the wait pass the bound"
            );
        }
    }
}

/// A capture pass released after key 2 is acknowledged is ended, and the
/// one replacement pass `publish_raced` starts publishes: the load ends
/// `Open`, both keys serve their exact bytes and the judgment keeps them.
#[test]
fn a_released_pass_is_replaced_by_one_that_publishes() {
    for root in ROOTS {
        let first = run("released", &RELEASED, Expect::Pass, &[], 1, root);
        assert!(PLANTED.with(Cell::get), "released at {root}");
        assert_eq!(first, Ok(None), "released at {root}");
    }
}

/// A loss pin counts as a catch only when the unrestored keys satisfy its declared premise.
#[test]
fn a_loss_of_other_keys_than_a_pins_is_no_catch() {
    let cases: [(&str, &str, &'static [Step], &str); 2] = [
        (
            "only-key-1-lost",
            "wl2-fill-in-pass-lost",
            &ONLY_1_UNSERVED,
            "key 2 was not restored",
        ),
        (
            "only-key-3-lost",
            "wl1-closed-pass-lost",
            &ONLY_3_UNSERVED,
            "key 1 was not restored",
        ),
    ];
    for (name, pin, script, witness) in cases {
        let pin = WARM_LOADS.iter().find(|history| history.name == pin);
        let pin = pin.expect("a registered pin");
        for root in ROOTS {
            let first = run(name, script, pin.expect, pin.premise, 1, root);
            assert!(PLANTED.with(Cell::get), "{name} at {root}");
            assert_eq!(
                first,
                Ok(Some(Failure::Unsuccessful(witness))),
                "{name} at {root}"
            );
        }
    }
}

/// A script whose `suffix-landed` step returns `STAY` on every turn ends at a run limit, and `run`
/// returns `Err` with an `Inconclusive` terminal. A passing case requires `Ok(None)`.
#[test]
fn a_run_that_stalls_before_its_judgment_is_no_pass() {
    for root in ROOTS {
        let ended = run("stalled", &STALLED, Expect::Pass, &[], 1, root);
        assert!(PLANTED.with(Cell::get), "stalled at {root}");
        assert!(
            matches!(
                ended,
                Err(Terminal::Complete {
                    outcome: Ending::Inconclusive,
                    ..
                })
            ),
            "{ended:?} at {root}"
        );
    }
}

/// The warm successor fingerprints key 2 under its own key pair: the
/// fingerprint differs from the first tenure's, and the run passes, so the
/// load ended `Open` and key 2 served its exact bytes.
#[test]
fn a_warm_successor_fingerprints_a_restored_key_under_its_own_pair() {
    for root in ROOTS {
        let first = run("sampled", &SAMPLED, Expect::Pass, &[], 1, root);
        assert_eq!(first, Ok(None), "sampled at {root}");
        let (before, after) = FINGERPRINTS.with(Cell::get);
        assert!(
            before.is_some() && after.is_some(),
            "{before:?} {after:?} at {root}"
        );
        assert_ne!(before, after, "at {root}");
    }
}

/// A cold, a warm and a cold attach on one media take strictly rising
/// sessions, the warm owner's session is its record bump's, and the warm
/// relaunch draws no fixture session.
#[test]
fn a_cold_attach_after_a_warm_one_takes_a_higher_session() {
    for root in ROOTS {
        let first = run(
            "cold-after-warm",
            &COLD_AFTER_WARM,
            Expect::Pass,
            &[],
            2,
            root,
        );
        assert_eq!(first, Ok(None), "cold-after-warm at {root}");
        let [cold, bumped, warm, later] = SESSIONS.with(Cell::get);
        assert_eq!(warm, bumped, "at {root}");
        assert_eq!(DRAWN.with(Cell::get), 0, "at {root}");
        assert!(
            cold < warm && warm < later,
            "{cold} {warm} {later} at {root}"
        );
    }
}

#[test]
fn a_reversed_burst_without_key_1_served_ends_unsuccessful() {
    for root in ROOTS {
        let expect = Expect::Unsuccessful(KEY_2_ALONE);
        let first = run("key-1-unserved", &KEY_1_UNSERVED, expect, &[], 1, root);
        assert!(PLANTED.with(Cell::get), "key-1-unserved at {root}");
        assert_eq!(first, Ok(expect.failure()), "key-1-unserved at {root}");
    }
}

#[test]
fn a_covered_warm_successor_holds_a_fresh_invalidate() {
    for root in ROOTS {
        PLANTED.with(|planted| planted.set(false));
        let built = warm_load("holds", &SUCCESSOR_HOLDS, WL5_WITNESSES, Expect::Pass);
        let (terminal, first) = ended(Box::leak(Box::new(built)), root);
        assert!(PLANTED.with(Cell::get), "holds at {root}");
        assert_eq!(first, None, "holds at {root}");
        let passed = matches!(
            terminal,
            Terminal::Complete {
                outcome: Ending::Pass,
                ..
            }
        );
        assert!(passed, "holds at {root}: {terminal:?}");
    }
}
