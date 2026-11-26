//! The charge a header pool and a receive pool stage before they claim their arena pool is exactly
//! `size_of::<OpsState>()`, and a budget that cannot hold it refuses before the claim does.
//!
//! `PacketMempool::arena_pool` stages the charge before it claims the arena pool, and the claim
//! refuses with `MempoolError::Kind` while a buffer of the kind is out of the arena. Each history
//! asks for a pool while one buffer is out and reads the staged charge from the refusal a bounded
//! budget meets: a budget that holds the charge reaches the claim and is refused with `Kind`, and a
//! budget that does not hold it is refused with `Budget` first. Every history ends at the claim's
//! refusal or before it.

use super::mock;
use super::registration_tests::ready;
use super::{Environment, MempoolError, OpsState, PacketMempool};
use crate::net::PacketPool;
use crate::storage::{EngineBudget, EngineBudgetExceeded, PoolKind};

/// Which arena pool the history asks for.
#[derive(Clone, Copy, Debug)]
enum Asked {
    Header,
    Receive,
}

/// What one history observed.
#[derive(Debug)]
struct Seen {
    /// Free buffers of the kind when the pool was asked for, of `mock::COUNT`.
    free_at_ask: u32,
    /// The refusal the pool request met, `None` when it built a pool.
    refusal: Option<MempoolError>,
    /// The budget after the request.
    budget: EngineBudget,
}

/// Asks for `asked` over a verified registration and its own device lease with a budget of
/// `limit` bytes, while one buffer of the pool's kind is out of the arena, so the step after
/// the charge refuses with `Kind`.
fn ask(asked: Asked, limit: usize) -> Seen {
    let (env, arena) = (Environment::detached(), mock::arena());
    let mut registration = ready(&env, arena);
    let lease = registration.device_attached();
    let mut budget = EngineBudget::new(limit);
    let seen = match asked {
        Asked::Header => {
            let held = arena
                .acquire(PoolKind::PacketHeader)
                .expect("premise: the arena lends a header buffer");
            let free_at_ask = arena.report(PoolKind::PacketHeader).free;
            let refusal =
                PacketMempool::header(arena, &registration, &lease, c"test-hdr", &mut budget).err();
            drop(held);
            Seen {
                free_at_ask,
                refusal,
                budget,
            }
        }
        Asked::Receive => {
            let view = PacketPool::new(arena, PoolKind::PacketReceive, 1)
                .expect("premise: the receive view forms");
            let _posted = view
                .post()
                .expect("premise: the view posts a receive buffer");
            let free_at_ask = arena.report(PoolKind::PacketReceive).free;
            let refusal =
                PacketMempool::receive(&view, &registration, &lease, c"test-rx", &mut budget).err();
            Seen {
                free_at_ask,
                refusal,
                budget,
            }
        }
    };
    registration
        .device_stopped(lease.stopped())
        .expect("premise: the registration takes its device's stop");
    seen
}

/// The premises of a history: one buffer of the kind was out when the pool was asked for, and
/// the request built no pool.
fn premises(asked: Asked, seen: &Seen) {
    assert_eq!(
        seen.free_at_ask,
        mock::COUNT - 1,
        "premise ({asked:?}): one buffer of the kind is out of the arena"
    );
    assert!(
        seen.refusal.is_some(),
        "premise ({asked:?}): a library test builds no native pool"
    );
}

/// The size of an arena pool's ops state, which the histories measure the staged charge against.
const STATE: usize = size_of::<OpsState>();

/// A budget whose limit is exactly `size_of::<OpsState>()` holds the charge a header pool and a
/// receive pool stage before the claim: the request passes the budget and is refused by the claim
/// with `Kind`, and the budget is the fresh budget of that limit.
#[test]
fn a_budget_of_exactly_the_boxed_ops_state_holds_an_arena_pools_charge() {
    for asked in [Asked::Header, Asked::Receive] {
        let seen = ask(asked, STATE);
        premises(asked, &seen);
        assert_eq!(
            seen.refusal,
            Some(MempoolError::Kind),
            "{asked:?}: a budget of the ops state's size ({STATE} bytes) holds the charge staged \
             before the claim, so the refusal is the claim's and not the budget's; a `Budget` \
             refusal means the pool staged more than that size"
        );
        assert_eq!(
            seen.budget,
            EngineBudget::new(STATE),
            "{asked:?}: the refused request leaves the budget unchanged"
        );
    }
}

/// One byte short of `size_of::<OpsState>()` the budget refuses with `Budget` before the claim
/// refuses, and the refusal names the budget's limit: the charge staged before the claim is no less
/// than the ops state's size.
#[test]
fn a_budget_one_byte_short_of_the_ops_state_refuses_with_budget() {
    for asked in [Asked::Header, Asked::Receive] {
        let seen = ask(asked, STATE - 1);
        premises(asked, &seen);
        match seen.refusal {
            Some(MempoolError::Budget(EngineBudgetExceeded { limit, .. })) => assert_eq!(
                limit,
                STATE - 1,
                "{asked:?}: the refusal names the budget's limit"
            ),
            other => panic!(
                "{asked:?}: a budget one byte short of the ops state refuses with \
                 `Budget`, got {other:?}"
            ),
        }
        assert_eq!(
            seen.budget,
            EngineBudget::new(STATE - 1),
            "{asked:?}: the refused request leaves the budget unchanged"
        );
    }
}

/// The control: the same steps with a budget a mebibyte above the ops state's size end in the same
/// `Kind` refusal, so `Kind` in the first test is the claim's answer to the held buffer and the
/// budget plays no part in it.
#[test]
fn the_same_steps_with_an_ample_budget_meet_the_same_kind_refusal() {
    let limit = STATE + (1 << 20);
    for asked in [Asked::Header, Asked::Receive] {
        let seen = ask(asked, limit);
        premises(asked, &seen);
        assert_eq!(
            seen.refusal,
            Some(MempoolError::Kind),
            "({asked:?}) the held buffer refuses the claim"
        );
        assert_eq!(
            seen.budget,
            EngineBudget::new(limit),
            "({asked:?}) the refused request leaves the budget unchanged"
        );
    }
}
