//! A recovery stage whose watchdog expired before it begins stays unrun:
//! `staged` returns `None` without calling its step and leaves the expiry on
//! the last stage begun, and `restore` loses the link without a port call.

use std::sync::Arc;

use super::super::burst_tests::{
    Containment, LOCAL, PEERS, RECOVERY_DEADLINE, StallClock, watch_on,
};
use super::super::mempool::Role;
use super::super::mock::{self, Forged, MockPort, iova};
use super::super::recovery::{RecoveryEpisode, RecoveryStage};
use super::super::wire::Wire;
use super::{Burst, Link};
use crate::storage::{EngineBudget, PoolKind};

/// A burst over a mock port whose watch is armed and already expired, on a
/// clock this fixture moved past the deadline, and the supervisor that
/// counts the expiry's containment request.
fn expired_burst() -> (Burst<'static, MockPort>, Arc<Containment>) {
    let (clock, containment) = (StallClock::default(), Arc::new(Containment::default()));
    let arena = mock::arena();
    let header = mock::arena_pool(arena, PoolKind::PacketHeader, Role::Header);
    let payload = mock::payload_pool(arena, 8);
    let receive = mock::arena_pool(arena, PoolKind::PacketReceive, Role::Receive);
    let port = MockPort {
        receive: Some(receive.state),
        ..MockPort::open()
    };
    let translate: Box<dyn Fn(usize, usize) -> Option<u64>> = Box::new(iova);
    let recheck: Box<dyn Fn() -> bool> = Box::new(|| true);
    let burst = Burst::new(
        port,
        Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap(),
        [header.state, payload.state, receive.state],
        Box::leak(Box::new(Forged(translate, recheck))),
        watch_on(&clock, &containment),
        8,
        &mut EngineBudget::unlimited(),
    )
    .unwrap();

    assert!(burst.watch.arm(), "the episode's watchdog arms");
    assert!(!burst.watch.expired(), "the clock has not moved");
    clock.expire(RECOVERY_DEADLINE);
    containment.wait_requested();
    assert!(
        burst.watch.expired(),
        "the worker records the expiry before it asks to contain"
    );
    (burst, containment)
}

/// `staged` under a watchdog that has already expired returns `None`,
/// leaves its step unrun and its stage unrecorded, and puts the expiry on
/// the last stage the episode had begun, whether none, the stop or the
/// recheck: an expired episode skips every later step, so every buffer the
/// device may hold stays held.
#[test]
fn a_stage_whose_watchdog_already_expired_stays_unrun_and_the_expiry_falls_on_the_last_stage_begun()
{
    let (mut burst, _containment) = expired_burst();
    for reached in [
        None,
        Some(RecoveryStage::Stop),
        Some(RecoveryStage::Recheck),
    ] {
        let mut episode = RecoveryEpisode {
            reached,
            ..RecoveryEpisode::default()
        };
        let mut runs = 0;
        let outcome = burst.staged(&mut episode, RecoveryStage::Reset, |_| runs += 1);
        assert_eq!(outcome, None, "{reached:?}: the stage ends the attempt");
        assert_eq!(runs, 0, "{reached:?}: the step stays unrun");
        assert_eq!(
            episode,
            RecoveryEpisode {
                reached,
                expired_at: reached,
                ..RecoveryEpisode::default()
            },
            "{reached:?}: the stage is not begun and the expiry falls on the last stage begun"
        );
    }
    assert!(burst.watch.disarm(), "the watchdog had expired");
}

/// `restore` under a watchdog that expired before its first stage loses the
/// link and leaves the episode as it was, with no stage begun and no expiry
/// stage, and the port's call count stays zero: the device is left as the
/// expiry found it. The expiry asked to contain once.
#[test]
fn restore_under_an_already_expired_watchdog_loses_the_link_without_a_port_call() {
    let (mut burst, containment) = expired_burst();
    let mut episode = RecoveryEpisode::default();
    assert_eq!(burst.restore(&mut episode), Link::Lost);
    assert_eq!(
        episode,
        RecoveryEpisode::default(),
        "no stage began, so the expiry falls on none"
    );
    assert_eq!(
        (burst.port().calls, burst.port().stages.as_slice()),
        (0, &[][..]),
        "the port is not called"
    );
    assert!(burst.watch.disarm(), "the watchdog had expired");
    assert_eq!(containment.count(), 1, "the expiry asked to contain once");
}
