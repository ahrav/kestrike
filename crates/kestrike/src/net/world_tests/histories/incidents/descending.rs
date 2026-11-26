//! Descending-refusal histories: two successor GETs refused on a wire slot
//! that still binds a cancelled GET, the later generation first.
//!
//! They judge the rule text "a settled GET's row held an admitted request",
//! which the I7 and I9 histories raise, for the clause "stale frames change
//! nothing" of the obligation record `wire-identity-bounds-every-effect`
//! in `verification/obligations.json`: a generation the
//! owner answered while a request held the wire slot's binding is never
//! admitted once the binding frees.
//!
//! I24 in descending order realizes one schedule of `quint/settle.qnt`,
//! its directed run `settle-run-refused-order` (`RUNS` in
//! `quint/settle_check.py`): a higher and then a lower generation are
//! answered under a held binding, the lower is ignored, and both are stale
//! once the binding frees. The simulator runs that one schedule against
//! the owner; it does not check the model.
//!
//! A GET is cancelled with its read held, so its request keeps the slot
//! bound. The first successor takes the slot at the next generation; the
//! link withholds every frame of it toward the owner, so it ends at its
//! own deadline and its client retires it. The second
//! successor takes the slot at a later generation and its GET reaches the
//! owner, which refuses it on the bound slot; the link drops every ERROR
//! toward the client. The history then delivers one withheld GET of the
//! first successor, a genuine client frame under the same session, which
//! the owner refuses on the bound slot after the later generation. The held
//! read releases, the cancelled request drains and the slot frees while the
//! second successor still retransmits. The owner must admit no GET since
//! the first successor was issued, and the slot's row must bind no request
//! and cover both generations.
//!
//! The sibling, I24 in ascending order, runs the same steps over a link
//! that withholds nothing: the first successor's GETs reach the owner
//! before the second's, so the refusals arrive in generation order.
//!
//! The premises are the cancelled GET's binding at each refusal, the first
//! successor's end at its deadline with a GET of it in flight and no
//! generation refused, the second successor's later generation on the same
//! slot, and the delivered GET leaving the link with no stale or duplicate
//! count added at the owner and a busy refusal counted; each is read from
//! state that exists with and without a defect. The control hands the
//! judge a planted observation, one GET admitted since the first successor
//! was issued, so it shows the judge fails through its named rule, not
//! that a defective namespace is caught.
//!
//! Scope: GETs only, two successors, one delivered copy of the first
//! successor's GET; PUT BEGINs refused in descending order are not driven.
//! Simulated devices and network.

use super::*;

use std::cell::Cell;

/// The rule every history of the family judges.
const ADMITTED: &str = "a settled GET's row held an admitted request";

/// Link turns the first successor's frames are withheld for: past any run.
const WITHHELD: u64 = 1 << 40;

thread_local! {
    /// The owner's busy refusals and its stale and duplicate session drops
    /// when the history delivered the withheld GET.
    static DELIVERED: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
}

/// The wire identities of the first and the second successor, once both
/// were issued.
fn successors(world: &Mixed<'_, '_, '_>) -> (RequestId, RequestId) {
    let ids = &world.history.ids;
    let (first, second) = (ids[ids.len() - 2], ids[ids.len() - 1]);
    (
        kept_attempt(world, 1, first),
        kept_attempt(world, 1, second),
    )
}

/// The wire slot row of the GET client's request `wire`.
fn row_of(
    world: &Mixed<'_, '_, '_>,
    wire: RequestId,
) -> crate::net::namespace::WireSlot<crate::net::served::Outcome> {
    world
        .scene
        .owner
        .request_slot(PeerId(1), wire.slot())
        .unwrap_or_default()
}

/// The GET frames of `wire` in flight toward the owner.
fn in_flight(world: &Mixed<'_, '_, '_>, wire: RequestId) -> usize {
    let crc = crate::storage::Crc32c::detect();
    let mut found = 0;
    world.scene.nets[1]
        .borrow_mut()
        .retain(OWNER_SIDE, |bytes| {
            if let Ok(frame) = crate::net::frame::parse(crc, bytes, false)
                && frame.header().kind == Kind::Get
                && frame.header().request == wire.wire()
            {
                found += 1;
            }
            true
        });
    found
}

/// The owner's stale and duplicate session drops.
fn session_drops(world: &Mixed<'_, '_, '_>) -> u64 {
    let report = world.scene.owner.session_report();
    report.stale + report.duplicate
}

/// The owner's GETs refused on a bound wire slot.
fn busy(world: &Mixed<'_, '_, '_>) -> u64 {
    world.scene.owner.serve_report().refused_pressure.busy
}

/// The first successor GET on the cancelled GET's wire slot, issued while
/// the slot's row still binds the cancelled GET at its generation, over a
/// link that drops every ERROR toward the client and, when `withheld`,
/// withholds every frame of the first successor toward the owner. The step
/// keeps the owner's count of admitted GETs, which the judgment requires
/// unchanged.
fn first_successor(world: &mut Mixed<'_, '_, '_>, now: u64, withheld: bool) -> u64 {
    let old = world.gets[1].as_ref().expect("the cancelled GET").id;
    let old_wire = RequestId::from_wire(attempt(world, 1, old));
    let row = row_of(world, old_wire);
    if row.active.is_none() || row.watermark != Some(old_wire.generation()) {
        world.first.record(Failure::Unsuccessful(
            "the cancelled GET kept its wire slot bound",
        ));
        return 0;
    }
    let issued = successor_get_named(world, now, i9_wait_us(), |id, _| id);
    if issued == STAY || issued == 0 {
        return issued;
    }
    if !world
        .history
        .marks
        .contains(&"successor reused the slot at a higher generation")
    {
        world.first.record(Failure::Unsuccessful(
            "successor reused the slot at a higher generation",
        ));
        return 0;
    }
    let (_, first) = i9_wires(world);
    let mut rules = Vec::new();
    if withheld {
        let frames = Selector::All(vec![
            Selector::Toward(OWNER_SIDE),
            Selector::Request(first.wire()),
        ]);
        rules.push(Rule::new(frames, Effect::Delay(WITHHELD)));
    }
    rules.push(Rule::new(toward_client(Kind::Error), Effect::Drop));
    i7_rules_on(world, 1, rules);
    world.history.admitted = world.scene.owner.serve_report().requests;
    mark(world, "the cancelled GET kept its wire slot bound")
}

fn first_withheld(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    first_successor(world, now, true)
}

fn first_prompt(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    first_successor(world, now, false)
}

/// The first successor ended at its own deadline while the cancelled GET
/// still bound the slot, and its client retires it. With `refused`, the
/// owner recorded its generation as refused; otherwise the owner recorded
/// none and a GET of it is in flight, withheld.
fn first_ended(world: &mut Mixed<'_, '_, '_>, refused: bool, witness: &'static str) -> u64 {
    let id = *world.history.ids.last().expect("the first successor");
    let outcome = world.collect_get(1, id);
    let _ = world.scene.clients[1].retire(id);
    let (old, first) = i9_wires(world);
    let row = row_of(world, first);
    let bound = row.active.is_some() && row.watermark == Some(old.generation());
    let seen = if refused {
        row.refused == Some(first.generation())
    } else {
        row.refused.is_none() && in_flight(world, first) >= 1
    };
    if outcome != Some(Outcome::Failed(Status::TimedOut)) || !bound || !seen {
        world.first.record(Failure::Unsuccessful(witness));
        return 0;
    }
    mark(world, witness)
}

fn first_ended_withheld(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    first_ended(
        world,
        false,
        "the first successor ended with its GET withheld",
    )
}

fn first_ended_refused(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    first_ended(
        world,
        true,
        "the bound slot refused the first successor's generation",
    )
}

/// The second successor GET, on the first successor's wire slot at a later
/// generation.
fn second_successor(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let (_, first) = i9_wires(world);
    let Ok(started) = world.scene.clients[1].get(key(1), 0, 1 << 20, now, i9_wait_us()) else {
        return STAY;
    };
    world.history.ids.push(started);
    let second = RequestId::from_wire(attempt(world, 1, started));
    if second.slot() != first.slot() || second.generation() <= first.generation() {
        world.first.record(Failure::Unsuccessful(
            "the second successor took the slot at a later generation",
        ));
        return 0;
    }
    mark(
        world,
        "the second successor took the slot at a later generation",
    )
}

/// Takes the first successor's withheld frames off the link and queues one
/// of its GETs toward the owner, due now.
fn deliver_first(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (first, _) = successors(world);
    let crc = crate::storage::Crc32c::detect();
    let mut taken = None;
    let mut net = world.scene.nets[1].borrow_mut();
    net.retain(OWNER_SIDE, |bytes| {
        let Ok(frame) = crate::net::frame::parse(crc, bytes, false) else {
            return true;
        };
        if frame.header().request != first.wire() {
            return true;
        }
        if frame.header().kind == Kind::Get && taken.is_none() {
            taken = Some(bytes.to_vec());
        }
        false
    });
    let Some(bytes) = taken else {
        drop(net);
        world.first.record(Failure::Unsuccessful(
            "the first successor's withheld GET delivered after the second's refusal",
        ));
        return 0;
    };
    net.inject(OWNER_SIDE, &bytes);
    drop(net);
    DELIVERED.set((busy(world), session_drops(world)));
    mark(
        world,
        "the first successor's withheld GET delivered after the second's refusal",
    )
}

/// The delivered GET left the link and the owner counted a busy refusal
/// since its delivery.
fn first_taken(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    let (first, _) = successors(world);
    in_flight(world, first) == 0 && busy(world) > DELIVERED.get().0
}

/// The owner's session layer took the delivered GET, counting no stale or
/// duplicate datagram since its delivery, while the cancelled GET still
/// bound the slot.
fn first_refused_late(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let witness = "the bound slot answered the first successor after the second";
    let (old, _) = i9_wires(world);
    let (first, _) = successors(world);
    let row = row_of(world, first);
    let bound = row.active.is_some() && row.watermark == Some(old.generation());
    if session_drops(world) != DELIVERED.get().1 || !bound {
        world.first.record(Failure::Unsuccessful(witness));
        return 0;
    }
    mark(world, witness)
}

/// The cancelled GET drained with the second successor still undecided and
/// no ERROR delivered to its client, so every later retransmission meets
/// the freed slot. The GET frames the link carried toward the owner so far
/// are the baseline the judge counts retransmissions from.
fn freed_unanswered(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = *world.history.ids.last().expect("the second successor");
    if world.collect_get(1, id).is_some() || i9_captured(world, Kind::Error, CLIENT, false) != 0 {
        world.first.record(Failure::Unsuccessful(
            "the successor was unanswered when its slot freed",
        ));
        return 0;
    }
    world.history.carried = i9_captured(world, Kind::Get, OWNER_SIDE, false) as u64;
    mark(world, "the successor was unanswered when its slot freed")
}

/// A control: the judge reads one GET admitted since the first successor
/// was issued, as an owner that admitted a refused generation would count.
fn judge_planted(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.admitted = world.history.admitted.wrapping_sub(1);
    i9_judge_lost(world, now)
}

/// Both successors' rows: each generation is at or below the slot's
/// watermark and the slot binds no request once their client retired them.
fn rows(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let ids = &world.history.ids;
    let (first_id, second_id) = (ids[ids.len() - 2], ids[ids.len() - 1]);
    let (first, second) = successors(world);
    let held = world.scene.clients[1].get_wire(second_id).is_some();
    if i7_row(
        world,
        PeerId(1),
        second,
        held,
        ADMITTED,
        "the settled GET left no admitted request",
    ) == 0
    {
        return 0;
    }
    let held = world.scene.clients[1].get_wire(first_id).is_some();
    i7_row(
        world,
        PeerId(1),
        first,
        held,
        ADMITTED,
        "the first successor left no admitted request",
    )
}

const I24_DESCENDING: [Step; 17] = [
    step("hold-reads", i9_refresh_ended, i7_hold_reads),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held, mark_read_held),
    step("cancel", always, cancel_old),
    step("cancel-kept", cancel_received, cancel_kept),
    step("first-successor", active_get, first_withheld),
    step("first-ended", successor_decided, first_ended_withheld),
    step("second-successor", active_get, second_successor),
    step("refused", i9_refusal_lost, i9_mark_lost),
    step("late-first", always, deliver_first),
    step("late-refused", first_taken, first_refused_late),
    step("release-old-read", always, release_reads),
    step("drained", drained, mark_drained),
    step("freed", always, freed_unanswered),
    step("successor-decided", successor_decided, i9_judge_lost),
    step("rows", always, rows),
    JUDGE,
];

/// I24 in ascending order: nothing is withheld, so the first successor's
/// GETs reach the owner before the second's.
const I24_ASCENDING: [Step; 17] = replaced(
    replaced(
        replaced(
            replaced(
                I24_DESCENDING,
                "first-successor",
                step("first-successor-prompt", active_get, first_prompt),
            ),
            "first-ended",
            step("first-refused", successor_decided, first_ended_refused),
        ),
        "late-first",
        step("late-first-removed", always, removed_step),
    ),
    "late-refused",
    step("late-refused-removed", always, removed_step),
);

const I24_PLANTED: [Step; 17] = replaced(
    I24_DESCENDING,
    "successor-decided",
    step("successor-planted", successor_decided, judge_planted),
);

const DESCENDING_WITNESSES: &[&str] = &[
    "old read held",
    "held read cancelled",
    "the owner ended the cancelled request",
    "cancel kept custody",
    "successor reused the slot at a higher generation",
    "the cancelled GET kept its wire slot bound",
    "the first successor ended with its GET withheld",
    "the second successor took the slot at a later generation",
    "the link lost the successor's first ERROR",
    "the bound slot refused the successor's generation",
    "the first successor's withheld GET delivered after the second's refusal",
    "the bound slot answered the first successor after the second",
    "the cancelled request drained after its terminal",
    "the successor was unanswered when its slot freed",
    "the successor's retransmissions reached the owner",
    "the refused successor ended unadmitted",
    "the settled GET left no admitted request",
    "the first successor left no admitted request",
];

const ASCENDING_WITNESSES: &[&str] = &[
    "old read held",
    "held read cancelled",
    "the owner ended the cancelled request",
    "cancel kept custody",
    "successor reused the slot at a higher generation",
    "the cancelled GET kept its wire slot bound",
    "the bound slot refused the first successor's generation",
    "the second successor took the slot at a later generation",
    "the link lost the successor's first ERROR",
    "the bound slot refused the successor's generation",
    "the cancelled request drained after its terminal",
    "the successor was unanswered when its slot freed",
    "the successor's retransmissions reached the owner",
    "the refused successor ended unadmitted",
    "the settled GET left no admitted request",
    "the first successor left no admitted request",
];

/// The marks the control's run holds before its planted step.
const PREMISE: &[&str] = &[
    "the first successor ended with its GET withheld",
    "the second successor took the slot at a later generation",
    "the bound slot refused the successor's generation",
    "the first successor's withheld GET delivered after the second's refusal",
    "the bound slot answered the first successor after the second",
    "the successor was unanswered when its slot freed",
];

/// The descending-refusal histories and their control.
pub(crate) const DESCENDING: [History; 3] = [
    history(
        "i24-refusals-in-descending-order",
        &I24_DESCENDING,
        DESCENDING_WITNESSES,
        I9,
        Expect::Pass,
    ),
    history(
        "i24-refusals-in-ascending-order",
        &I24_ASCENDING,
        ASCENDING_WITNESSES,
        I9,
        Expect::Pass,
    ),
    control(
        history(
            "i24-descending-refusal-admitted",
            &I24_PLANTED,
            DESCENDING_WITNESSES,
            I9,
            Expect::Violation(Obligation::Resources, ADMITTED),
        ),
        PREMISE,
    ),
];

#[cfg(test)]
mod tests {
    use crate::net::observe::Failure;
    use crate::oracle::Obligation;
    use crate::sim::trace::{Outcome, PAYLOAD, Terminal, load};

    use super::super::super::super::bundle::{admit, failure_code, traced};
    use super::super::super::super::replay::{Replayed, replay};
    use super::super::super::tests::manifest;
    use super::{ADMITTED, DESCENDING, Expect};

    /// The roots the seeded test pins: a small one and two drawn from the
    /// 64-bit range.
    const ROOTS: [u64; 3] = [3, 7_677_221_855_602_090_617, 10_289_227_118_843_548_305];

    /// History `name` recorded under `root`: its ending, its violation
    /// record and whether the bundle replayed to an equal digest.
    fn ran_at(name: &str, root: u64) -> (Outcome, Option<[u8; PAYLOAD]>, bool) {
        let mut manifest = manifest(name);
        manifest.root = root;
        let closed = traced(admit(&manifest).expect("admitted"), Vec::new());
        let loaded = load(&closed.sink, manifest.capacity().records()).expect("a loadable bundle");
        let Terminal::Complete { outcome, .. } = loaded.terminal else {
            panic!("{name} at {root}: {:?}", loaded.terminal);
        };
        let reproduced = replay(&closed.sink).expect("a replay").0 == Replayed::Reproduced;
        (outcome, loaded.violation, reproduced)
    }

    /// Two successors refused on a bound wire slot, the later generation
    /// first, are never admitted once the slot frees under each pinned
    /// root, as the same successors refused in generation order are not.
    #[test]
    fn refusals_in_descending_order_leave_both_generations_unadmitted() {
        for name in [
            "i24-refusals-in-descending-order",
            "i24-refusals-in-ascending-order",
        ] {
            for root in ROOTS {
                assert_eq!(
                    ran_at(name, root),
                    (Outcome::Pass, None, true),
                    "{name} at {root}"
                );
            }
        }
    }

    /// Each passing history activates the obligations it declares.
    #[test]
    fn every_passing_descending_history_activates_the_obligations_it_declares() {
        for history in DESCENDING.iter().filter(|h| h.expect == Expect::Pass) {
            let activated = super::super::super::activated(history.witnesses);
            for obligation in history.obligations {
                assert!(
                    activated.contains(obligation),
                    "{}: {obligation:?} has no witnessed check",
                    history.name
                );
            }
        }
    }

    /// The control fails through its named rule once its premise is marked,
    /// and replays to an equal digest.
    #[test]
    fn every_descending_control_fails_through_its_named_check() {
        let killed = [(
            "i24-descending-refusal-admitted",
            Obligation::Resources,
            ADMITTED,
        )];
        for (name, obligation, rule) in killed {
            let declared = DESCENDING.iter().find(|h| h.name == name).expect(name);
            assert_eq!(
                declared.expect,
                Expect::Violation(obligation, rule),
                "{name}"
            );
            assert!(!declared.premise.is_empty(), "{name} declares its premise");
            for root in ROOTS {
                assert_eq!(
                    ran_at(name, root),
                    (
                        Outcome::Violation,
                        Some(failure_code(&Failure::Violation(obligation, rule))),
                        true
                    ),
                    "{name} at {root}"
                );
            }
        }
        let controls = DESCENDING
            .iter()
            .filter(|h| h.expect != Expect::Pass)
            .count();
        assert_eq!(controls, killed.len());
    }
}
