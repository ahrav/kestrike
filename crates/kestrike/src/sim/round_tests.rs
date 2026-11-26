//! Round tests: the legacy schedule runs a round's actions in their listed
//! order, a generated schedule runs each exactly once in an order its root
//! repeats, and a schedule ends with the body that set it.

use std::cell::RefCell;

use super::round::{Act, Actor, Schedule, afresh, generated, legacy, round, rounds, with_schedule};

/// The order four actions of `rounds` rounds ran in, one vector per round.
fn orders(rounds: usize) -> Vec<Vec<u8>> {
    let log = RefCell::new(Vec::new());
    let mut all = Vec::new();
    for _ in 0..rounds {
        log.borrow_mut().clear();
        let (mut a, mut b, mut c, mut d) = (
            || log.borrow_mut().push(0),
            || log.borrow_mut().push(1),
            || log.borrow_mut().push(2),
            || log.borrow_mut().push(3),
        );
        round(&mut [
            Act::new(Actor::Link(0), &mut a),
            Act::new(Actor::Client(0), &mut b),
            Act::new(Actor::Disk(0), &mut c),
            Act::new(Actor::Owner(0), &mut d),
        ]);
        all.push(log.borrow().clone());
    }
    all
}

#[test]
fn the_legacy_schedule_keeps_the_listed_order() {
    assert!(legacy());
    assert!(orders(8).iter().all(|order| order == &[0, 1, 2, 3]));
}

#[test]
fn a_generated_schedule_runs_each_action_once_in_orders_its_root_repeats() {
    let first = with_schedule(Schedule::Generated { root: 7 }, || {
        assert!(!legacy());
        orders(32)
    });
    for order in &first {
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, [0, 1, 2, 3], "each action once: {order:?}");
    }
    assert!(
        first.iter().any(|order| order != &[0, 1, 2, 3]),
        "some round leaves the listed order"
    );
    let again = with_schedule(Schedule::Generated { root: 7 }, || orders(32));
    assert_eq!(first, again, "one root repeats its orders");
    let other = with_schedule(Schedule::Generated { root: 8 }, || orders(32));
    assert_ne!(first, other, "another root picks other orders");
}

#[test]
fn a_schedule_ends_with_its_body_even_when_it_unwinds() {
    let unwound = std::panic::catch_unwind(|| {
        with_schedule(Schedule::Generated { root: 1 }, || panic!("inside"))
    });
    assert!(unwound.is_err());
    assert!(legacy());
}

#[test]
fn an_empty_round_runs_nothing() {
    round(&mut []);
}

#[test]
fn a_generated_round_runs_its_link_advances_first() {
    let log = RefCell::new(Vec::new());
    let lists = with_schedule(Schedule::Generated { root: 5 }, || {
        (0..32)
            .map(|_| {
                log.borrow_mut().clear();
                let (mut client, mut owner, mut link) = (
                    || log.borrow_mut().push(1),
                    || log.borrow_mut().push(2),
                    || log.borrow_mut().push(0),
                );
                round(&mut [
                    Act::new(Actor::Client(0), &mut client),
                    Act::new(Actor::Owner(0), &mut owner),
                    Act::new(Actor::Link(0), &mut link),
                ]);
                log.borrow().clone()
            })
            .collect::<Vec<_>>()
    });
    assert!(lists.iter().all(|order| order[0] == 0), "{lists:?}");
    assert!(
        lists.iter().any(|order| order[1] == 2),
        "both other orders occur"
    );
    assert!(
        lists.iter().any(|order| order[1] == 1),
        "both other orders occur"
    );
}

#[test]
fn afresh_restarts_the_orders_and_keeps_the_round_count() {
    with_schedule(Schedule::Generated { root: 9 }, || {
        let first = afresh(|| orders(8));
        let second = afresh(|| orders(8));
        assert_eq!(first, second, "each run starts from ordinal zero");
        assert_eq!(rounds(), 16, "both runs' rounds count");
    });
}

#[test]
fn a_generated_body_must_run_a_round() {
    fn idle() {}
    let refused = std::panic::catch_unwind(|| generated(3, "idle", idle));
    assert!(refused.is_err());
    generated(3, "orders", || drop(orders(1)));
}

#[test]
fn a_generated_body_whose_rounds_force_their_order_is_refused() {
    fn forced() {
        let (mut link, mut owner, mut client) = (|| {}, || {}, || {});
        round(&mut [
            Act::new(Actor::Link(0), &mut link),
            Act::new(Actor::Owner(0), &mut owner),
        ]);
        round(&mut [Act::new(Actor::Client(0), &mut client)]);
    }
    let refused = std::panic::catch_unwind(|| generated(3, "forced", forced));
    assert!(refused.is_err(), "no round offered a choice of order");
}
